// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! AArch64（A64）ユーザーモード実行の run loop。fetch/decode/dispatch を回す。
//!
//! A64 は固定 32 ビット長で遅延スロットを持たない。分岐は意味論が
//! `Ctrl::Jump` を残し、素通しは実行ループが pc を 4 進める。
//! `svc` は OS パーソナリティの `TrapHandler` へ委ねる。
//! CPU 状態・メモリの用意（ELF 配置、初期スタック）は呼び出し側の仕事である。
//!
//! モデルの解決はデコード時に `decode_model_ex` で行う（ADR-0006）。
//! データアクセスのエンディアンは現在 LE 固定（BE は FEAT_BE と ELF の
//! エンディアン確認が揃ってから足す）。

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::Ctrl;
use polyisa_engine::run::{Outcome, TrapHandler, TrapOutcome};
use polyisa_guest_aarch64::sem::{self, Gpr};
use polyisa_guest_aarch64::{Insn, decode_model_ex};
use polyisa_mem::{Access, AccessKind, Align, Endian, PAGE_SIZE, PageNo, Perms, VirtAddr};
use polyisa_sem::Backend as _;

/// 1命令の実行上限。無限ループの検出用。
pub const STEP_LIMIT: u64 = 5_000_000;

/// ページフォルト駆動のスタック成長の設定。
/// `top` はスタック上端、`limit` は下向き成長の下限（RLIMIT_STACK 相当）。
/// 窓 `[limit, top)` 内の未写像ページへのフォルトで写像を伸ばす。
#[derive(Clone, Copy)]
pub struct StackGrowth {
    pub top: u64,
    pub limit: u64,
}

fn acc_fetch() -> Access {
    Access {
        endian: Endian::Le,
        align: Align::Natural,
        kind: AccessKind::Fetch,
    }
}

/// エントリから実行する。`feats` は生成した `FEAT_*` のビット和で、
/// `decode_model_ex` に渡る。CPU モデルの選択からの変換は
/// `polyisa_isadl::select::resolve` が行う。
/// `endian` はデータアクセスのエンディアン（命令フェッチは常に LE）。
/// `stack` はスタック成長の設定。`None` ならフォルトは従来どおり失敗。
pub fn run_ex(
    env: &mut BareEnv,
    entry: u64,
    feats: u64,
    endian: Endian,
    stack: Option<StackGrowth>,
    sys: &mut impl TrapHandler,
) -> Outcome {
    env.pc = entry;
    polyisa_engine::run::run(
        env,
        sys,
        STEP_LIMIT,
        |env| env.pc,
        |env, sys| step_a64(env, sys, feats, endian, stack),
    )
}

/// `run_ex` に機能集合 0・LE・成長なしを渡す既定の入口。
pub fn run(env: &mut BareEnv, entry: u64, sys: &mut impl TrapHandler) -> Outcome {
    run_ex(env, entry, 0, Endian::Le, None, sys)
}

/// 即値の符号拡張。`v` の下位 `bits` を符号付きで取る。
fn sext(v: u32, bits: u32) -> i64 {
    (((v << (32 - bits)) as i32) >> (32 - bits)) as i64
}

/// `svc` の imm16 によるトラップ委譲。`TrapOutcome` を `Outcome` へ写す。
fn svc<H: ?Sized + TrapHandler>(
    env: &mut BareEnv,
    sys: &mut H,
    imm: u32,
    pc: u64,
    word: u32,
) -> Result<(), Outcome> {
    match sys.handle_trap(env, imm) {
        TrapOutcome::Handled => {
            env.pc += 4;
            Ok(())
        }
        TrapOutcome::Exit(code) => {
            if sys.take_exit(env, code) {
                Ok(())
            } else {
                Err(Outcome::Exit(u64::from(code)))
            }
        }
        TrapOutcome::Blocked => {
            if sys.on_block(env) {
                Ok(())
            } else {
                Err(Outcome::Deadlock)
            }
        }
        TrapOutcome::Unimplemented => Err(Outcome::Unimplemented {
            pc,
            word: u128::from(word),
        }),
    }
}

/// 1 命令ぶんのフェッチ・解読・意味論と svc 境界の解決。
/// 継続なら `Ok(())`、退出なら退出理由を返す。
/// `endian` はデータアクセスのエンディアン。フェッチは AArch64 の
/// 規約どおり常にリトルエンディアン（BE でも命令は LE）。
// Ref: SPEC-ARM-ARM-A (Armv9-A ARM ARM 2024-09), SRC-LINUX (7.3).
#[allow(clippy::too_many_lines)]
fn step_a64(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    feats: u64,
    endian: Endian,
    stack: Option<StackGrowth>,
) -> Result<(), Outcome> {
    let pc = env.pc;
    let mut b4 = [0u8; 4];
    if env
        .backend
        .mem
        .read(VirtAddr(pc), &mut b4, acc_fetch())
        .is_err()
    {
        return Err(Outcome::Unimplemented {
            pc,
            word: 0xffff_ffff,
        });
    }
    let word = u32::from_le_bytes(b4);
    let unimpl = |env: &BareEnv| Outcome::Unimplemented {
        pc: env.pc,
        word: u128::from(word),
    };
    let Some(insn) = decode_model_ex(u128::from(word), 32, true, feats) else {
        return Err(unimpl(env));
    };
    if insn == Insn::Svc {
        let imm = (word >> 5) & 0xffff;
        return svc(env, sys, imm, pc, word);
    }
    // フィールドの切り出し。
    let sf = word >> 31 != 0;
    let le = endian;
    let rd = Gpr((word & 31) as u8);
    let rn = Gpr(((word >> 5) & 31) as u8);
    let rm = Gpr(((word >> 16) & 31) as u8);
    let rt = rd;
    let rt2 = Gpr(((word >> 10) & 31) as u8);
    let ra = rt2;
    let rs = rm;
    let imm16 = (word >> 5) & 0xffff;
    let imm12 = (word >> 10) & 0xfff;
    let imm9 = sext((word >> 12) & 0x1ff, 9);
    let imm7 = sext((word >> 15) & 0x7f, 7);
    let imm19 = sext((word >> 5) & 0x7_ffff, 19);
    let imm26 = sext(word & 0x3ff_ffff, 26);
    let imm14 = sext((word >> 5) & 0x3fff, 14);
    let b_tgt = pc.wrapping_add((imm26 << 2) as u64);
    let c_tgt = pc.wrapping_add((imm19 << 2) as u64);
    let t_tgt = pc.wrapping_add((imm14 << 2) as u64);
    let cond = word & 0xf;
    let cond_hi = (word >> 12) & 0xf;
    let sh = (word >> 22) & 1;
    let imm_s = u64::from(imm12) << (sh * 12);
    let hw = (word >> 21) & 3;
    let nzcv_in = word & 0xf;
    let n_bit = (word >> 22) & 1;
    let immr = (word >> 16) & 0x3f;
    let imms = (word >> 10) & 0x3f;
    let shift = (word >> 22) & 3;
    let imm6 = (word >> 10) & 0x3f;
    let option = (word >> 13) & 7;
    let imm3 = (word >> 10) & 7;
    let s_bit = (word >> 12) & 1;
    let sysop = (word >> 5) & 0xffff;
    // TBZ/TBNZ のビット番号は b5(bit31)<<5 | b40(bits[23:19])。
    let bit_no = ((word >> 31) & 1) << 5 | ((word >> 19) & 31);
    let ok = match insn {
        Insn::B => env.step(|b| sem::b_(b, b_tgt)),
        Insn::Bl => env.step(|b| sem::bl(b, pc, b_tgt)),
        Insn::BCond => env.step(|b| sem::b_cond(b, c_tgt, cond)),
        Insn::Cbz => env.step(|b| sem::cbz(b, rt, c_tgt, sf, false)),
        Insn::Cbnz => env.step(|b| sem::cbz(b, rt, c_tgt, sf, true)),
        Insn::Tbz => env.step(|b| sem::tbz(b, rt, t_tgt, bit_no, false)),
        Insn::Tbnz => env.step(|b| sem::tbz(b, rt, t_tgt, bit_no, true)),
        Insn::Br => env.step(|b| sem::br(b, rn)),
        Insn::Blr => env.step(|b| sem::blr(b, rn, pc)),
        Insn::Ret => env.step(|b| sem::ret(b, rn)),
        Insn::Hvc | Insn::Smc | Insn::Brk | Insn::Hlt | Insn::Sysl => {
            return Err(unimpl(env));
        }
        Insn::Msr => env.step(|b| sem::msr(b, rt, sysop)),
        Insn::Mrs => env.step(|b| sem::mrs(b, rt, sysop)),
        Insn::Sys | Insn::PrfmLit => env.step(sem::sys_op),
        Insn::AddImm => env.step(|b| sem::add_imm(b, rd, rn, imm_s, sf, false, false)),
        Insn::AddsImm => env.step(|b| sem::add_imm(b, rd, rn, imm_s, sf, false, true)),
        Insn::SubImm => env.step(|b| sem::add_imm(b, rd, rn, imm_s, sf, true, false)),
        Insn::SubsImm => env.step(|b| sem::add_imm(b, rd, rn, imm_s, sf, true, true)),
        Insn::AndImm | Insn::OrrImm | Insn::EorImm | Insn::AndsImm => {
            let op = match insn {
                Insn::AndImm => 0,
                Insn::OrrImm => 1,
                Insn::EorImm => 2,
                _ => 3,
            };
            let Some(mask) = sem::decode_bit_masks(n_bit, imms, immr, sf) else {
                return Err(unimpl(env));
            };
            env.step(|b| sem::log_imm(b, rd, rn, mask, op, sf))
        }
        Insn::Movn => env.step(|b| sem::movn(b, rd, u64::from(imm16) << (16 * hw), sf)),
        Insn::Movz => env.step(|b| sem::movz(b, rd, u64::from(imm16) << (16 * hw), sf)),
        Insn::Movk => env.step(|b| sem::movk(b, rd, u64::from(imm16), hw, sf)),
        Insn::Adr => {
            // immhi(bits[23:5])<<2 | immlo(bits[30:29]) の 21 ビット符号付き。
            let imm21 = (((word >> 5) & 0x7_ffff) << 2) | ((word >> 29) & 3);
            env.step(|b| sem::adr(b, rd, pc, sext(imm21, 21)))
        }
        Insn::Adrp => {
            let imm21 = (((word >> 5) & 0x7ffff) << 2) | ((word >> 29) & 3);
            env.step(|b| sem::adr(b, rd, pc & !0xfff, sext(imm21, 21) << 12))
        }
        Insn::Sbfm => env.step(|b| sem::bitfield(b, rd, rn, immr, imms, 0, sf)),
        Insn::Bfm => env.step(|b| sem::bitfield(b, rd, rn, immr, imms, 1, sf)),
        Insn::Ubfm => env.step(|b| sem::bitfield(b, rd, rn, immr, imms, 2, sf)),
        Insn::Extr => env.step(|b| sem::extr(b, rd, rn, rm, imms, sf)),
        Insn::AndSh => env.step(|b| sem::log_sh(b, rd, rn, rm, shift, imm6, 0, false, sf)),
        Insn::BicSh => env.step(|b| sem::log_sh(b, rd, rn, rm, shift, imm6, 0, true, sf)),
        Insn::OrrSh => env.step(|b| sem::log_sh(b, rd, rn, rm, shift, imm6, 1, false, sf)),
        Insn::OrnSh => env.step(|b| sem::log_sh(b, rd, rn, rm, shift, imm6, 1, true, sf)),
        Insn::EorSh => env.step(|b| sem::log_sh(b, rd, rn, rm, shift, imm6, 2, false, sf)),
        Insn::EonSh => env.step(|b| sem::log_sh(b, rd, rn, rm, shift, imm6, 2, true, sf)),
        Insn::AndsSh => env.step(|b| sem::log_sh(b, rd, rn, rm, shift, imm6, 3, false, sf)),
        Insn::BicsSh => env.step(|b| sem::log_sh(b, rd, rn, rm, shift, imm6, 3, true, sf)),
        Insn::AddSh => env.step(|b| sem::add_sh(b, rd, rn, rm, shift, imm6, sf, false, false)),
        Insn::AddsSh => env.step(|b| sem::add_sh(b, rd, rn, rm, shift, imm6, sf, false, true)),
        Insn::SubSh => env.step(|b| sem::add_sh(b, rd, rn, rm, shift, imm6, sf, true, false)),
        Insn::SubsSh => env.step(|b| sem::add_sh(b, rd, rn, rm, shift, imm6, sf, true, true)),
        Insn::AddExt => env.step(|b| sem::add_ext(b, rd, rn, rm, option, imm3, sf, false, false)),
        Insn::AddsExt => env.step(|b| sem::add_ext(b, rd, rn, rm, option, imm3, sf, false, true)),
        Insn::SubExt => env.step(|b| sem::add_ext(b, rd, rn, rm, option, imm3, sf, true, false)),
        Insn::SubsExt => env.step(|b| sem::add_ext(b, rd, rn, rm, option, imm3, sf, true, true)),
        Insn::Csel => env.step(|b| sem::csel(b, rd, rn, rm, cond_hi, 0, sf)),
        Insn::Csinc => env.step(|b| sem::csel(b, rd, rn, rm, cond_hi, 1, sf)),
        Insn::Csinv => env.step(|b| sem::csel(b, rd, rn, rm, cond_hi, 2, sf)),
        Insn::Csneg => env.step(|b| sem::csel(b, rd, rn, rm, cond_hi, 3, sf)),
        Insn::CcmnReg => {
            let c = (word >> 12) & 0xf;
            env.step(|b| sem::ccmp(b, rn, rm, 0, nzcv_in, c, sf, false, false))
        }
        Insn::CcmpReg => {
            let c = (word >> 12) & 0xf;
            env.step(|b| sem::ccmp(b, rn, rm, 0, nzcv_in, c, sf, false, true))
        }
        Insn::CcmnImm => {
            let c = (word >> 12) & 0xf;
            let imm5 = u64::from((word >> 16) & 31);
            env.step(|b| sem::ccmp(b, rn, rm, imm5, nzcv_in, c, sf, true, false))
        }
        Insn::CcmpImm => {
            let c = (word >> 12) & 0xf;
            let imm5 = u64::from((word >> 16) & 31);
            env.step(|b| sem::ccmp(b, rn, rm, imm5, nzcv_in, c, sf, true, true))
        }
        Insn::Udiv => env.step(|b| sem::dp2(b, rd, rn, rm, 0, sf)),
        Insn::Sdiv => env.step(|b| sem::dp2(b, rd, rn, rm, 1, sf)),
        Insn::Lslv => env.step(|b| sem::dp2(b, rd, rn, rm, 2, sf)),
        Insn::Lsrv => env.step(|b| sem::dp2(b, rd, rn, rm, 3, sf)),
        Insn::Asrv => env.step(|b| sem::dp2(b, rd, rn, rm, 4, sf)),
        Insn::Rorv => env.step(|b| sem::dp2(b, rd, rn, rm, 5, sf)),
        Insn::Rbit => env.step(|b| sem::dp1(b, rd, rn, 0, sf)),
        Insn::Rev16 => env.step(|b| sem::dp1(b, rd, rn, 1, sf)),
        Insn::Rev32 => env.step(|b| sem::dp1(b, rd, rn, 2, true)),
        Insn::Rev => env.step(|b| sem::dp1(b, rd, rn, 2, false)),
        Insn::Rev64 => env.step(|b| sem::dp1(b, rd, rn, 3, true)),
        Insn::Clz => env.step(|b| sem::dp1(b, rd, rn, 4, sf)),
        Insn::Cls => env.step(|b| sem::dp1(b, rd, rn, 5, sf)),
        Insn::Madd => env.step(|b| sem::madd(b, rd, rn, rm, ra, false, sf)),
        Insn::Msub => env.step(|b| sem::madd(b, rd, rn, rm, ra, true, sf)),
        Insn::Smaddl => env.step(|b| sem::maddl(b, rd, rn, rm, ra, 0)),
        Insn::Smsubl => env.step(|b| sem::maddl(b, rd, rn, rm, ra, 1)),
        Insn::Umaddl => env.step(|b| sem::maddl(b, rd, rn, rm, ra, 2)),
        Insn::Umsubl => env.step(|b| sem::maddl(b, rd, rn, rm, ra, 3)),
        Insn::Smulh => env.step(|b| sem::mulh(b, rd, rn, rm, true)),
        Insn::Umulh => env.step(|b| sem::mulh(b, rd, rn, rm, false)),
        Insn::StrbU => {
            env.step(|b| sem::ls_unsigned(b, rt, rn, imm12 as i64, 1, true, false, false, le))
        }
        Insn::LdrbU => {
            env.step(|b| sem::ls_unsigned(b, rt, rn, imm12 as i64, 1, false, false, false, le))
        }
        Insn::LdrsbUX => {
            env.step(|b| sem::ls_unsigned(b, rt, rn, imm12 as i64, 1, false, true, true, le))
        }
        Insn::LdrsbUW => {
            env.step(|b| sem::ls_unsigned(b, rt, rn, imm12 as i64, 1, false, true, false, le))
        }
        Insn::StrhU => env
            .step(|b| sem::ls_unsigned(b, rt, rn, (imm12 as i64) << 1, 2, true, false, false, le)),
        Insn::LdrhU => env
            .step(|b| sem::ls_unsigned(b, rt, rn, (imm12 as i64) << 1, 2, false, false, false, le)),
        Insn::LdrshUX => {
            env.step(|b| sem::ls_unsigned(b, rt, rn, (imm12 as i64) << 1, 2, false, true, true, le))
        }
        Insn::LdrshUW => env
            .step(|b| sem::ls_unsigned(b, rt, rn, (imm12 as i64) << 1, 2, false, true, false, le)),
        Insn::StrUW => env
            .step(|b| sem::ls_unsigned(b, rt, rn, (imm12 as i64) << 2, 4, true, false, false, le)),
        Insn::LdrUW => env
            .step(|b| sem::ls_unsigned(b, rt, rn, (imm12 as i64) << 2, 4, false, false, false, le)),
        Insn::LdrswU => {
            env.step(|b| sem::ls_unsigned(b, rt, rn, (imm12 as i64) << 2, 4, false, true, true, le))
        }
        Insn::StrUX => env
            .step(|b| sem::ls_unsigned(b, rt, rn, (imm12 as i64) << 3, 8, true, false, false, le)),
        Insn::LdrUX => env
            .step(|b| sem::ls_unsigned(b, rt, rn, (imm12 as i64) << 3, 8, false, false, false, le)),
        Insn::Sturb => env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 1, true, false, false, 0, le)),
        Insn::Ldurb => env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 1, false, false, false, 0, le)),
        Insn::LdursbX => env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 1, false, true, true, 0, le)),
        Insn::LdursbW => env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 1, false, true, false, 0, le)),
        Insn::Sturh => env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 2, true, false, false, 0, le)),
        Insn::Ldurh => env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 2, false, false, false, 0, le)),
        Insn::LdurshX => env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 2, false, true, true, 0, le)),
        Insn::LdurshW => env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 2, false, true, false, 0, le)),
        Insn::SturW => env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 4, true, false, false, 0, le)),
        Insn::LdurW => env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 4, false, false, false, 0, le)),
        Insn::Ldursw => env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 4, false, true, true, 0, le)),
        Insn::SturX => env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 8, true, false, false, 0, le)),
        Insn::LdurX => env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 8, false, false, false, 0, le)),
        Insn::StrbPost => env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 1, true, false, false, 1, le)),
        Insn::LdrbPost => {
            env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 1, false, false, false, 1, le))
        }
        Insn::LdrsbPostX => {
            env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 1, false, true, true, 1, le))
        }
        Insn::LdrsbPostW => {
            env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 1, false, true, false, 1, le))
        }
        Insn::StrhPost => env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 2, true, false, false, 1, le)),
        Insn::LdrhPost => {
            env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 2, false, false, false, 1, le))
        }
        Insn::LdrshPostX => {
            env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 2, false, true, true, 1, le))
        }
        Insn::LdrshPostW => {
            env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 2, false, true, false, 1, le))
        }
        Insn::StrPostW => env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 4, true, false, false, 1, le)),
        Insn::LdrPostW => {
            env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 4, false, false, false, 1, le))
        }
        Insn::LdrswPost => env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 4, false, true, true, 1, le)),
        Insn::StrPostX => env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 8, true, false, false, 1, le)),
        Insn::LdrPostX => {
            env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 8, false, false, false, 1, le))
        }
        Insn::StrbPre => env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 1, true, false, false, 3, le)),
        Insn::LdrbPre => env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 1, false, false, false, 3, le)),
        Insn::LdrsbPreX => env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 1, false, true, true, 3, le)),
        Insn::LdrsbPreW => {
            env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 1, false, true, false, 3, le))
        }
        Insn::StrhPre => env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 2, true, false, false, 3, le)),
        Insn::LdrhPre => env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 2, false, false, false, 3, le)),
        Insn::LdrshPreX => env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 2, false, true, true, 3, le)),
        Insn::LdrshPreW => {
            env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 2, false, true, false, 3, le))
        }
        Insn::StrPreW => env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 4, true, false, false, 3, le)),
        Insn::LdrPreW => env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 4, false, false, false, 3, le)),
        Insn::LdrswPre => env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 4, false, true, true, 3, le)),
        Insn::StrPreX => env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 8, true, false, false, 3, le)),
        Insn::LdrPreX => env.step(|b| sem::ls_imm9(b, rt, rn, imm9, 8, false, false, false, 3, le)),
        Insn::StrbReg => {
            env.step(|b| sem::ls_regoff(b, rt, rn, rm, option, 0, 1, true, false, false, le))
        }
        Insn::LdrbReg => {
            env.step(|b| sem::ls_regoff(b, rt, rn, rm, option, 0, 1, false, false, false, le))
        }
        Insn::LdrsbRegX => {
            env.step(|b| sem::ls_regoff(b, rt, rn, rm, option, 0, 1, false, true, true, le))
        }
        Insn::LdrsbRegW => {
            env.step(|b| sem::ls_regoff(b, rt, rn, rm, option, 0, 1, false, true, false, le))
        }
        Insn::StrhReg => {
            env.step(|b| sem::ls_regoff(b, rt, rn, rm, option, s_bit, 2, true, false, false, le))
        }
        Insn::LdrhReg => {
            env.step(|b| sem::ls_regoff(b, rt, rn, rm, option, s_bit, 2, false, false, false, le))
        }
        Insn::LdrshRegX => {
            env.step(|b| sem::ls_regoff(b, rt, rn, rm, option, s_bit, 2, false, true, true, le))
        }
        Insn::LdrshRegW => {
            env.step(|b| sem::ls_regoff(b, rt, rn, rm, option, s_bit, 2, false, true, false, le))
        }
        Insn::StrRegW => env
            .step(|b| sem::ls_regoff(b, rt, rn, rm, option, s_bit * 2, 4, true, false, false, le)),
        Insn::LdrRegW => env
            .step(|b| sem::ls_regoff(b, rt, rn, rm, option, s_bit * 2, 4, false, false, false, le)),
        Insn::LdrswReg => {
            env.step(|b| sem::ls_regoff(b, rt, rn, rm, option, s_bit * 2, 4, false, true, true, le))
        }
        Insn::StrRegX => env
            .step(|b| sem::ls_regoff(b, rt, rn, rm, option, s_bit * 3, 8, true, false, false, le)),
        Insn::LdrRegX => env
            .step(|b| sem::ls_regoff(b, rt, rn, rm, option, s_bit * 3, 8, false, false, false, le)),
        Insn::LdrWLit => env.step(|b| sem::ls_lit(b, rt, c_tgt, 4, false, false, le)),
        Insn::LdrXLit => env.step(|b| sem::ls_lit(b, rt, c_tgt, 8, false, false, le)),
        Insn::LdrswLit => env.step(|b| sem::ls_lit(b, rt, c_tgt, 4, true, true, le)),
        Insn::StpWOff => env.step(|b| sem::ls_pair(b, rt, rt2, rn, imm7 << 2, 4, true, 2, le)),
        Insn::LdpWOff => env.step(|b| sem::ls_pair(b, rt, rt2, rn, imm7 << 2, 4, false, 2, le)),
        Insn::StpXOff => env.step(|b| sem::ls_pair(b, rt, rt2, rn, imm7 << 3, 8, true, 2, le)),
        Insn::LdpXOff => env.step(|b| sem::ls_pair(b, rt, rt2, rn, imm7 << 3, 8, false, 2, le)),
        Insn::StpWPost => env.step(|b| sem::ls_pair(b, rt, rt2, rn, imm7 << 2, 4, true, 1, le)),
        Insn::LdpWPost => env.step(|b| sem::ls_pair(b, rt, rt2, rn, imm7 << 2, 4, false, 1, le)),
        Insn::StpXPost => env.step(|b| sem::ls_pair(b, rt, rt2, rn, imm7 << 3, 8, true, 1, le)),
        Insn::LdpXPost => env.step(|b| sem::ls_pair(b, rt, rt2, rn, imm7 << 3, 8, false, 1, le)),
        Insn::StpWPre => env.step(|b| sem::ls_pair(b, rt, rt2, rn, imm7 << 2, 4, true, 3, le)),
        Insn::LdpWPre => env.step(|b| sem::ls_pair(b, rt, rt2, rn, imm7 << 2, 4, false, 3, le)),
        Insn::StpXPre => env.step(|b| sem::ls_pair(b, rt, rt2, rn, imm7 << 3, 8, true, 3, le)),
        Insn::LdpXPre => env.step(|b| sem::ls_pair(b, rt, rt2, rn, imm7 << 3, 8, false, 3, le)),
        Insn::LdxrW | Insn::LdaxrW => env.step(|b| sem::ldxr(b, rt, rn, 4, le)),
        Insn::StxrW | Insn::StlxrW => env.step(|b| sem::stxr(b, rs, rt, rn, 4, le)),
        Insn::LdxrX | Insn::LdaxrX => env.step(|b| sem::ldxr(b, rt, rn, 8, le)),
        Insn::StxrX | Insn::StlxrX => env.step(|b| sem::stxr(b, rs, rt, rn, 8, le)),
        Insn::Ldxrb | Insn::Ldaxrb => env.step(|b| sem::ldxr(b, rt, rn, 1, le)),
        Insn::Stxrb | Insn::Stlxrb => env.step(|b| sem::stxr(b, rs, rt, rn, 1, le)),
        Insn::Ldxrh | Insn::Ldaxrh => env.step(|b| sem::ldxr(b, rt, rn, 2, le)),
        Insn::Stxrh | Insn::Stlxrh => env.step(|b| sem::stxr(b, rs, rt, rn, 2, le)),
        // ---- FP/SIMD ----
        Insn::StpSOff => env.step(|b| sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 2, 4, true, 2, le)),
        Insn::LdpSOff => {
            env.step(|b| sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 2, 4, false, 2, le))
        }
        Insn::StpDOff => env.step(|b| sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 3, 8, true, 2, le)),
        Insn::LdpDOff => {
            env.step(|b| sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 3, 8, false, 2, le))
        }
        Insn::StpQOff => {
            env.step(|b| sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 4, 16, true, 2, le))
        }
        Insn::LdpQOff => {
            env.step(|b| sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 4, 16, false, 2, le))
        }
        Insn::StpSPost => {
            env.step(|b| sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 2, 4, true, 1, le))
        }
        Insn::LdpSPost => {
            env.step(|b| sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 2, 4, false, 1, le))
        }
        Insn::StpDPost => {
            env.step(|b| sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 3, 8, true, 1, le))
        }
        Insn::LdpDPost => {
            env.step(|b| sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 3, 8, false, 1, le))
        }
        Insn::StpQPost => {
            env.step(|b| sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 4, 16, true, 1, le))
        }
        Insn::LdpQPost => {
            env.step(|b| sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 4, 16, false, 1, le))
        }
        Insn::StpSPre => env.step(|b| sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 2, 4, true, 3, le)),
        Insn::LdpSPre => {
            env.step(|b| sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 2, 4, false, 3, le))
        }
        Insn::StpDPre => env.step(|b| sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 3, 8, true, 3, le)),
        Insn::LdpDPre => {
            env.step(|b| sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 3, 8, false, 3, le))
        }
        Insn::StpQPre => {
            env.step(|b| sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 4, 16, true, 3, le))
        }
        Insn::LdpQPre => {
            env.step(|b| sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 4, 16, false, 3, le))
        }
        Insn::StrBVu => env.step(|b| sem::vls_unsigned(b, rt.0, rn, imm12 as i64, 1, true, le)),
        Insn::LdrBVu => env.step(|b| sem::vls_unsigned(b, rt.0, rn, imm12 as i64, 1, false, le)),
        Insn::StrHVu => {
            env.step(|b| sem::vls_unsigned(b, rt.0, rn, (imm12 * 2) as i64, 2, true, le))
        }
        Insn::LdrHVu => {
            env.step(|b| sem::vls_unsigned(b, rt.0, rn, (imm12 * 2) as i64, 2, false, le))
        }
        Insn::StrSVu => {
            env.step(|b| sem::vls_unsigned(b, rt.0, rn, (imm12 * 4) as i64, 4, true, le))
        }
        Insn::LdrSVu => {
            env.step(|b| sem::vls_unsigned(b, rt.0, rn, (imm12 * 4) as i64, 4, false, le))
        }
        Insn::StrDVu => {
            env.step(|b| sem::vls_unsigned(b, rt.0, rn, (imm12 * 8) as i64, 8, true, le))
        }
        Insn::LdrDVu => {
            env.step(|b| sem::vls_unsigned(b, rt.0, rn, (imm12 * 8) as i64, 8, false, le))
        }
        Insn::StrQVu => {
            env.step(|b| sem::vls_unsigned(b, rt.0, rn, (imm12 * 16) as i64, 16, true, le))
        }
        Insn::LdrQVu => {
            env.step(|b| sem::vls_unsigned(b, rt.0, rn, (imm12 * 16) as i64, 16, false, le))
        }
        Insn::SturB => env.step(|b| sem::vls_imm9(b, rt.0, rn, imm9, 1, true, 0, le)),
        Insn::LdurB => env.step(|b| sem::vls_imm9(b, rt.0, rn, imm9, 1, false, 0, le)),
        Insn::SturH => env.step(|b| sem::vls_imm9(b, rt.0, rn, imm9, 2, true, 0, le)),
        Insn::LdurH => env.step(|b| sem::vls_imm9(b, rt.0, rn, imm9, 2, false, 0, le)),
        Insn::SturS => env.step(|b| sem::vls_imm9(b, rt.0, rn, imm9, 4, true, 0, le)),
        Insn::LdurS => env.step(|b| sem::vls_imm9(b, rt.0, rn, imm9, 4, false, 0, le)),
        Insn::SturD => env.step(|b| sem::vls_imm9(b, rt.0, rn, imm9, 8, true, 0, le)),
        Insn::LdurD => env.step(|b| sem::vls_imm9(b, rt.0, rn, imm9, 8, false, 0, le)),
        Insn::SturQ => env.step(|b| sem::vls_imm9(b, rt.0, rn, imm9, 16, true, 0, le)),
        Insn::LdurQ => env.step(|b| sem::vls_imm9(b, rt.0, rn, imm9, 16, false, 0, le)),
        Insn::StrBPostV => env.step(|b| sem::vls_imm9(b, rt.0, rn, imm9, 1, true, 1, le)),
        Insn::LdrBPostV => env.step(|b| sem::vls_imm9(b, rt.0, rn, imm9, 1, false, 1, le)),
        Insn::StrHPostV => env.step(|b| sem::vls_imm9(b, rt.0, rn, imm9, 2, true, 1, le)),
        Insn::LdrHPostV => env.step(|b| sem::vls_imm9(b, rt.0, rn, imm9, 2, false, 1, le)),
        Insn::StrSPostV => env.step(|b| sem::vls_imm9(b, rt.0, rn, imm9, 4, true, 1, le)),
        Insn::LdrSPostV => env.step(|b| sem::vls_imm9(b, rt.0, rn, imm9, 4, false, 1, le)),
        Insn::StrDPostV => env.step(|b| sem::vls_imm9(b, rt.0, rn, imm9, 8, true, 1, le)),
        Insn::LdrDPostV => env.step(|b| sem::vls_imm9(b, rt.0, rn, imm9, 8, false, 1, le)),
        Insn::StrQPostV => env.step(|b| sem::vls_imm9(b, rt.0, rn, imm9, 16, true, 1, le)),
        Insn::LdrQPostV => env.step(|b| sem::vls_imm9(b, rt.0, rn, imm9, 16, false, 1, le)),
        Insn::StrBPreV => env.step(|b| sem::vls_imm9(b, rt.0, rn, imm9, 1, true, 3, le)),
        Insn::LdrBPreV => env.step(|b| sem::vls_imm9(b, rt.0, rn, imm9, 1, false, 3, le)),
        Insn::StrHPreV => env.step(|b| sem::vls_imm9(b, rt.0, rn, imm9, 2, true, 3, le)),
        Insn::LdrHPreV => env.step(|b| sem::vls_imm9(b, rt.0, rn, imm9, 2, false, 3, le)),
        Insn::StrSPreV => env.step(|b| sem::vls_imm9(b, rt.0, rn, imm9, 4, true, 3, le)),
        Insn::LdrSPreV => env.step(|b| sem::vls_imm9(b, rt.0, rn, imm9, 4, false, 3, le)),
        Insn::StrDPreV => env.step(|b| sem::vls_imm9(b, rt.0, rn, imm9, 8, true, 3, le)),
        Insn::LdrDPreV => env.step(|b| sem::vls_imm9(b, rt.0, rn, imm9, 8, false, 3, le)),
        Insn::StrQPreV => env.step(|b| sem::vls_imm9(b, rt.0, rn, imm9, 16, true, 3, le)),
        Insn::LdrQPreV => env.step(|b| sem::vls_imm9(b, rt.0, rn, imm9, 16, false, 3, le)),
        Insn::DupGen => {
            let imm5 = (word >> 16) & 0x1f;
            let esz = imm5.trailing_zeros();
            let q = (word >> 30) & 1 != 0;
            env.step(|b| sem::vdup_gpr(b, rd.0, rn, esz, q))
        }
        Insn::InsGen => {
            let imm5 = (word >> 16) & 0x1f;
            let esz = imm5.trailing_zeros();
            let idx = imm5 >> (esz + 1);
            env.step(|b| sem::vins_gpr(b, rd.0, rn, esz, idx))
        }
        Insn::Umov => {
            let imm5 = (word >> 16) & 0x1f;
            let esz = imm5.trailing_zeros();
            let idx = imm5 >> (esz + 1);
            env.step(|b| sem::vext_gpr(b, rd, rn.0, esz, idx))
        }
        Insn::FmovWS => env.step(|b| sem::fmov_to_g(b, rd, rn.0, false, false)),
        Insn::FmovSW => env.step(|b| sem::fmov_to_v(b, rd.0, rn, 32, false)),
        Insn::FmovXD => env.step(|b| sem::fmov_to_g(b, rd, rn.0, true, false)),
        Insn::FmovDX => env.step(|b| sem::fmov_to_v(b, rd.0, rn, 64, false)),
        Insn::FmovXDhi => env.step(|b| sem::fmov_to_g(b, rd, rn.0, true, true)),
        Insn::FmovDhiX => env.step(|b| sem::fmov_to_v(b, rd.0, rn, 64, true)),
        Insn::ModImm => {
            let q = (word >> 30) & 1 != 0;
            let op = (word >> 29) & 1 != 0;
            let cmode = (word >> 12) & 0xf;
            let imm8 = u64::from((((word >> 16) & 7) << 5) | ((word >> 5) & 0x1f));
            env.step(|b| sem::mod_imm(b, rd.0, q, op, cmode, imm8))
        }
        Insn::Svc => unreachable!("svc は先に振り分け済み"),
    };
    if let Err(e) = ok {
        // スタック窓内の未写像フォルトは写像を伸ばして同じ命令をやり直す
        // （カーネルのスタック VMA 成長に相当）。pc は変えずに戻る。
        if let polyisa_engine::interp::InterpExit::Exception(ref g) = e
            && stack_grow(env, stack, g).is_some()
        {
            return Ok(());
        }
        return Err(unimpl(env));
    }
    // 分岐なしは次へ進める（分岐成立は step が pc を置き換える）。
    if env.backend.ctrl == Ctrl::Fallthrough {
        env.pc += 4;
    }
    Ok(())
}

/// ページフォルトをスタック成長として処理する。窓 `[limit, top)` 内の
/// 未写像ページへのフォルトなら、フォルトしたページから最初に写像済みの
/// ページの手前までを R/W で写像する。処理したなら `Some` を返す。
// Ref: SRC-LINUX (7.3) — expand_stack の規約（RLIMIT 内の下方成長）。
fn stack_grow(
    env: &mut BareEnv,
    stack: Option<StackGrowth>,
    e: &polyisa_sem::GuestException,
) -> Option<()> {
    let s = stack?;
    if e.kind != polyisa_sem::ExceptionKind::PageFault {
        return None;
    }
    let a = e.addr?;
    if a >= s.top || a < s.limit {
        return None;
    }
    let lo = a & !(PAGE_SIZE - 1);
    // フォルトしたページから上向きに、現状の写像の下端を探す。
    let mut hi = lo;
    while hi < s.top && !env.backend.mem.is_mapped(PageNo(hi / PAGE_SIZE)) {
        hi += PAGE_SIZE;
    }
    let pages = (hi - lo) / PAGE_SIZE;
    if pages == 0 {
        return None;
    }
    env.backend
        .mem
        .map(VirtAddr(lo), pages, Perms(Perms::R.0 | Perms::W.0))
        .ok()
}

/// 静的な AArch64 ELF を実行する。機械番号 183（EM_AARCH64）。
/// `sys` は `os_linux::aarch64::sys::Linux` が処理する（未実装は ENOSYS）。
/// 動的リンクは `run_elf_aarch64_root` が `--root` でゲストルートを受けて扱う。
/// Ref: SPEC-AARCH64-ELF（AAELF64）。
pub fn run_elf_aarch64(path: &str, argv: &[String]) -> Result<u64, String> {
    run_elf_aarch64_sel(path, argv, None)
}

/// `run_elf_aarch64` に CPU モデルの選択を渡す（`--cpu` の配線）。
/// `sel` の `feats` が `decode_model_ex` に届く。
pub fn run_elf_aarch64_sel(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
) -> Result<u64, String> {
    let mut sys = polyisa_os_linux::aarch64::sys::Linux::default();
    run_elf_aarch64_sys(path, argv, sel, &mut sys)
}

/// `run_elf_aarch64_sel` にゲストルートを渡す形（`--root` の配線）。
/// `root` は PT_INTERP の指す動的ローダと、syscall 経路のパス解決の両方で使う。
pub fn run_elf_aarch64_root(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    root: Option<&str>,
) -> Result<u64, String> {
    let mut sys = polyisa_os_linux::aarch64::sys::Linux::default();
    run_elf_aarch64_impl(path, argv, sel, &mut sys, root)
}

/// `run_elf_aarch64_sel` に OS パーソナリティを差し込む形。
/// テストが syscall の結果（`sys.io` 等）を検査する用途に使う。
pub fn run_elf_aarch64_sys(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    sys: &mut polyisa_os_linux::aarch64::sys::Linux,
) -> Result<u64, String> {
    run_elf_aarch64_impl(path, argv, sel, sys, None)
}

/// `run_elf_aarch64_sys` にゲストルートを添える形。
/// PT_INTERP 経路の動的リンクと root 内のファイル参照を試すテストに使う。
pub fn run_elf_aarch64_sys_root(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    sys: &mut polyisa_os_linux::aarch64::sys::Linux,
    root: Option<&str>,
) -> Result<u64, String> {
    run_elf_aarch64_impl(path, argv, sel, sys, root)
}

/// `run_elf_aarch64_sys` にゲストルートを添えた実体。
/// `root` は PT_INTERP の動的ローダ解決と `sys` のパス閉じ込めに使う。
fn run_elf_aarch64_impl(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    sys: &mut polyisa_os_linux::aarch64::sys::Linux,
    root: Option<&str>,
) -> Result<u64, String> {
    use polyisa_guest_aarch64::sem;
    use polyisa_mem::{PAGE_SIZE, Perms};

    // root 指定時は ELF のパスもゲストの名前空間（chroot と同じ規則）。
    // `/bin/sh` のような絶対リンクは root 内で解決される。
    let host_elf = match root {
        Some(root) => polyisa_os_linux::guest_path::resolve_guest_path_links(root, "/", path)
            .ok_or_else(|| format!("{path}: ゲストルートの外を指す"))?,
        None => path.to_string(),
    };
    let bytes = std::fs::read(&host_elf).map_err(|e| format!("read {path}: {e}"))?;
    if !matches!(bytes.get(4), Some(2)) {
        return Err("AArch64 は ELFCLASS64 のみ対応".to_string());
    }
    let ehdr = polyisa_loader::elf::parse_ehdr(&bytes).map_err(|e| format!("ehdr: {e:?}"))?;
    // EM_AARCH64=183。Ref: SPEC-AARCH64-ELF（AAELF64）§4.2。
    const EM_AARCH64: u16 = 183;
    // EI_DATA でデータアクセスのエンディアンを決める。AArch64 BE は
    // 「命令は LE・データのみ BE」なのでフェッチ経路は変えない。
    let data_endian = if ehdr.little { Endian::Le } else { Endian::Be };
    if ehdr.machine != EM_AARCH64 {
        return Err(format!("未対応の e_machine: {}", ehdr.machine));
    }
    let phdrs =
        polyisa_loader::elf::parse_phdrs(&bytes, &ehdr).map_err(|e| format!("phdrs: {e:?}"))?;
    let interp_path = polyisa_loader::elf::parse_interp(&bytes, &phdrs);
    if let Some(r) = root {
        sys.set_guest_root(r);
    } else if interp_path.is_some() {
        return Err("PT_INTERP のある ELF には --root が必要".to_string());
    }
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_aarch64::CpuState>());
    // ET_DYN の主像は固定基盤へ寄せる（PIE）。ET_EXEC は p_vaddr どおり。
    const MAIN_DYN_BASE: u64 = 0x0000_5500_0000_0000;
    const ET_DYN: u16 = 3;
    let min_vaddr = phdrs
        .iter()
        .filter(|p| p.seg_type == 1)
        .map(|p| p.vaddr & !(PAGE_SIZE - 1))
        .min()
        .unwrap_or(0);
    let main_bias = if ehdr.file_type == ET_DYN {
        MAIN_DYN_BASE - min_vaddr
    } else {
        0
    };
    let image_end = phdrs
        .iter()
        .filter(|p| p.seg_type == 1)
        .map(|p| p.vaddr + p.memsz)
        .max()
        .unwrap_or(0)
        + main_bias;
    polyisa_loader::elf::load_segments_bias(&bytes, &phdrs, &mut env.backend.mem, main_bias)
        .map_err(|e| format!("load: {e:?}"))?;
    // 主像の phdr 表のゲスト内番地（AT_PHDR）。表は先頭の PT_LOAD が覆うのが
    // 普通だが、覆わない最小像は像の直後へ表だけ別置きする。
    // Ref: SPEC-ELF-GABI (Edition 4.1＋2001-04-24 DRAFT).
    let phdr_addr = match phdrs
        .iter()
        .find(|p| p.seg_type == 1 && p.offset <= ehdr.phoff && ehdr.phoff < p.offset + p.filesz)
    {
        Some(p) => main_bias + p.vaddr + (ehdr.phoff - p.offset),
        None => {
            // brk/mmap の割当と衝突しないよう像の直下のページに置く。
            let at = (main_bias + min_vaddr)
                .checked_sub(PAGE_SIZE)
                .ok_or_else(|| "phdr 表の置き場がない".to_string())?;
            let lo = ehdr.phoff as usize;
            let hi = lo + ehdr.phnum as usize * 56;
            env.backend
                .mem
                .map(VirtAddr(at), 1, Perms::RW)
                .map_err(|_| "phdr 表の写像に失敗".to_string())?;
            env.backend
                .mem
                .write(VirtAddr(at), &bytes[lo..hi])
                .map_err(|_| "phdr 表の書き込みに失敗".to_string())?;
            let _ = env.backend.mem.protect(VirtAddr(at), 1, Perms::R);
            at
        }
    };
    // PT_INTERP の動的ローダを像として読み、その入口から始める。
    // Ref: SPEC-ELF-GABI (Edition 4.1＋2001-04-24 DRAFT).
    const INTERP_BASE: u64 = 0x0000_6f00_0000_0000;
    let (entry, interp_bias) = if let Some(gpath) = interp_path {
        let host =
            polyisa_os_linux::guest_path::resolve_guest_path(root.unwrap_or(""), "/", &gpath)
                .ok_or_else(|| format!("interp {gpath} が root 外を指す"))?;
        let ibytes = std::fs::read(&host).map_err(|e| format!("read interp {host}: {e}"))?;
        if !matches!(ibytes.get(4), Some(2)) {
            return Err(format!("interp {host} は ELFCLASS64 ではない"));
        }
        let iehdr =
            polyisa_loader::elf::parse_ehdr(&ibytes).map_err(|e| format!("interp ehdr: {e:?}"))?;
        if !iehdr.little || iehdr.machine != EM_AARCH64 {
            return Err(format!("interp {host} は aarch64 の ELF ではない"));
        }
        let iphdrs = polyisa_loader::elf::parse_phdrs(&ibytes, &iehdr)
            .map_err(|e| format!("interp phdrs: {e:?}"))?;
        let imin = iphdrs
            .iter()
            .filter(|p| p.seg_type == 1)
            .map(|p| p.vaddr & !(PAGE_SIZE - 1))
            .min()
            .unwrap_or(0);
        let ibias = if iehdr.file_type == ET_DYN {
            INTERP_BASE - imin
        } else {
            0
        };
        polyisa_loader::elf::load_segments_bias(&ibytes, &iphdrs, &mut env.backend.mem, ibias)
            .map_err(|e| format!("interp load: {e:?}"))?;
        (ibias + iehdr.entry, ibias)
    } else {
        (main_bias + ehdr.entry, 0)
    };
    // 初期スタック。像を載せる分だけ先に写像し、下方向の成長は
    // ページフォルト駆動で伸ばす（limit は RLIMIT_STACK 既定値の 8 MiB
    // 相当）。像の直上はゲストが sp より上へ書く領域（呼出し側
    // フレーム）として空ける。
    // Ref: SRC-LINUX (7.3) — expand_stack。
    let top = 0x0000_7fff_fff0_0000u64;
    const STACK_LIMIT: u64 = 8 << 20;
    let mut arg_bytes = vec![path.as_bytes().to_vec()];
    for a in argv {
        arg_bytes.push(a.as_bytes().to_vec());
    }
    let img_top = top - 0x1_0000;
    // auxv。AT_RANDOM (25) が指す 16 バイトは像の末尾の文字列領域に置く。
    // sp 直下はゲストのローカル領域になり上書きされるため使えない。
    // Ref: SPEC-AARCH64-ELF（AAELF64）§6、SRC-LINUX (7.3)。
    let mut auxv: Vec<(u64, u64)> = vec![
        (3, phdr_addr),              // AT_PHDR
        (4, 56),                     // AT_PHENT
        (5, u64::from(ehdr.phnum)),  // AT_PHNUM
        (6, 0x1000),                 // AT_PAGESZ
        (8, 0),                      // AT_FLAGS
        (9, main_bias + ehdr.entry), // AT_ENTRY
        (11, 0),                     // AT_UID
        (12, 0),                     // AT_EUID
        (13, 0),                     // AT_GID
        (14, 0),                     // AT_EGID
        (16, 0),                     // AT_HWCAP
        (17, 100),                   // AT_CLKTCK
        (23, 0),                     // AT_SECURE
        (25, 0),                     // AT_RANDOM（後で実番地に差し替え）
    ];
    if interp_bias != 0 {
        auxv.push((7, interp_bias)); // AT_BASE
    }
    let rand_addr = top - 16;
    for (k, v) in auxv.iter_mut() {
        if *k == 25 {
            *v = rand_addr;
        }
    }
    let (img, sp) =
        polyisa_os_linux::build_initial_stack_endian(img_top, &arg_bytes, &[], &auxv, data_endian);
    // 像の置かれる [sp, img_top) と、像の直上の呼出し側スクラッチ
    // （rand_addr を含む top まで）を先に写像する。sp より下は
    // ページフォルト駆動の成長で埋まる。
    let stack_base = sp & !(PAGE_SIZE - 1);
    let stack_pages = (top - stack_base) / PAGE_SIZE;
    env.backend
        .mem
        .map(
            VirtAddr(stack_base),
            stack_pages,
            Perms(Perms::R.0 | Perms::W.0),
        )
        .map_err(|e| format!("stack map: {e:?}"))?;
    env.backend
        .mem
        .write(VirtAddr(sp), &img)
        .map_err(|e| format!("stack write: {e:?}"))?;
    env.backend
        .mem
        .write(
            VirtAddr(rand_addr),
            &[
                0x70, 0x6f, 0x6c, 0x79, 0x69, 0x73, 0x61, 0x2d, 0x61, 0x61, 0x72, 0x63, 0x68, 0x36,
                0x34, 0x21,
            ],
        )
        .map_err(|e| format!("stack write: {e:?}"))?;
    env.backend.set(sem::sp_ref(), sp);
    sys.exe_path = path.to_string();
    sys.set_endian(data_endian);
    sys.init_brk(image_end);
    let feats = sel.map_or(0, |s| s.feats);
    let growth = Some(StackGrowth {
        top,
        limit: top - STACK_LIMIT,
    });
    match run_ex(&mut env, entry, feats, data_endian, growth, sys) {
        Outcome::Exit(code) => Ok(code),
        Outcome::Unimplemented { pc, word } => Err(format!("unimplemented at {pc:#x}: {word:#x}")),
        Outcome::StepLimit { pc } => Err(format!("step limit at {pc:#x}")),
        Outcome::Deadlock => Err("deadlock".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_mem::Perms;

    fn env_at(base: u64) -> BareEnv {
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_aarch64::CpuState>());
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(base), 2, rwx).unwrap();
        env
    }

    fn poke(env: &mut BareEnv, addr: u64, word: u32) {
        env.backend
            .mem
            .write(VirtAddr(addr), &word.to_le_bytes())
            .unwrap();
    }

    fn xreg(env: &mut BareEnv, i: u8) -> u64 {
        env.backend.get(Gpr(i).state())
    }

    /// 何もしないハンドラ。svc なしの裸実行に使う。
    struct NoSys;

    impl TrapHandler for NoSys {
        fn handle_trap(&mut self, _env: &mut BareEnv, _code: u32) -> TrapOutcome {
            TrapOutcome::Unimplemented
        }
    }

    #[test]
    fn movz_add_svc_exit() {
        // movz x8, #94      ; exit_group
        // movz x0, #7
        // svc #0
        let mut env = env_at(0x1_0000);
        poke(&mut env, 0x1_0000, 0xd280_0ba8); // movz x8, #93
        poke(&mut env, 0x1_0004, 0xd280_00e0); // movz x0, #7
        poke(&mut env, 0x1_0008, 0xd400_0001); // svc #0
        let mut sys = polyisa_os_linux::aarch64::sys::Linux::default();
        let out = run(&mut env, 0x1_0000, &mut sys);
        assert_eq!(out, Outcome::Exit(7));
    }

    #[test]
    fn b_cond_uses_nzcv() {
        // x0=1: subs xzr, x0, #1 で Z=1。b.eq で +8 先の movz x1,#3 へ飛ぶ。
        let mut env = env_at(0x1_0000);
        env.backend.set(Gpr(0).state(), 1);
        poke(&mut env, 0x1_0000, 0xf100_041f); // subs xzr, x0, #1
        poke(&mut env, 0x1_0004, 0x5400_0040); // b.eq +8
        poke(&mut env, 0x1_0008, 0xd280_0121); // movz x1, #9（飛ばす）
        poke(&mut env, 0x1_000c, 0xd280_0061); // movz x1, #3（分岐先）
        let mut sys = NoSys;
        env.pc = 0x1_0000;
        let _ = polyisa_engine::run::run(
            &mut env,
            &mut sys,
            3,
            |e| e.pc,
            |e, s| step_a64(e, s, 0, Endian::Le, None),
        );
        assert_eq!(xreg(&mut env, 1), 3);
    }

    #[test]
    fn sp_and_zr_distinguished() {
        // add sp, sp, #16 → SP 文脈; orr x5, xzr, x5 → ZR 文脈
        let mut env = env_at(0x1_0000);
        env.backend.set(sem::sp_ref(), 0x7000);
        poke(&mut env, 0x1_0000, 0x9100_43ff); // add sp, sp, #16
        let mut sys = NoSys;
        env.pc = 0x1_0000;
        let _ = polyisa_engine::run::run(
            &mut env,
            &mut sys,
            1,
            |e| e.pc,
            |e, s| step_a64(e, s, 0, Endian::Le, None),
        );
        assert_eq!(env.backend.get(sem::sp_ref()), 0x7010);
    }

    #[test]
    fn subs_ext_rn31_reads_sp_not_zr() {
        // cmp sp, x2（subs 拡張形式）: Rn=31 は S ビットに関わらず常に SP。
        // SP==x2 なら Z=1。ZR として読むと不一致になる。
        let mut env = env_at(0x1_0000);
        env.backend.set(sem::sp_ref(), 0x9000);
        env.backend.set(Gpr(2).state(), 0x9000);
        poke(&mut env, 0x1_0000, 0xeb22_63ff); // cmp sp, x2
        let mut sys = NoSys;
        env.pc = 0x1_0000;
        let _ = polyisa_engine::run::run(
            &mut env,
            &mut sys,
            1,
            |e| e.pc,
            |e, s| step_a64(e, s, 0, Endian::Le, None),
        );
        assert_eq!(env.backend.get(sem::nzcv_ref()) & 4, 4, "Z=1 で一致");
    }

    #[test]
    fn csel_reads_cond_from_bits_15_12() {
        // csel x3, x4, x5, hs: cond は bits[15:12]。rd=3 の下位ビット（=3、lo 条件）
        // と取り違えると C=1 のとき rm を選んでしまう。
        let mut env = env_at(0x1_0000);
        env.backend.set(sem::nzcv_ref(), 0x2); // C=1
        env.backend.set(Gpr(4).state(), 111);
        env.backend.set(Gpr(5).state(), 222);
        poke(&mut env, 0x1_0000, 0x9a85_2083); // csel x3, x4, x5, hs
        let mut sys = NoSys;
        env.pc = 0x1_0000;
        let _ = polyisa_engine::run::run(
            &mut env,
            &mut sys,
            1,
            |e| e.pc,
            |e, s| step_a64(e, s, 0, Endian::Le, None),
        );
        assert_eq!(xreg(&mut env, 3), 111, "hs 成立で rn を選択");
    }

    #[test]
    fn clz_counts_leading_zeros() {
        // clz w2, w1 / clz x3, x1。w1=1 → 31、x1=1 → 63。
        let mut env = env_at(0x1_0000);
        env.backend.set(Gpr(1).state(), 1);
        poke(&mut env, 0x1_0000, 0x5ac0_1022); // clz w2, w1
        poke(&mut env, 0x1_0004, 0xdac0_1023); // clz x3, x1
        let mut sys = NoSys;
        env.pc = 0x1_0000;
        let _ = polyisa_engine::run::run(
            &mut env,
            &mut sys,
            2,
            |e| e.pc,
            |e, s| step_a64(e, s, 0, Endian::Le, None),
        );
        assert_eq!(xreg(&mut env, 2), 31);
        assert_eq!(xreg(&mut env, 3), 63);
    }

    #[test]
    fn ldp_post_index_writes_back_sp() {
        // ldp x25, x26, [sp], #0x40: 読み出し後に base を更新する。
        let mut env = env_at(0x1_0000);
        env.backend.set(sem::sp_ref(), 0x1_0080);
        env.backend
            .mem
            .write(VirtAddr(0x1_0080), &0x1111u64.to_le_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x1_0088), &0x2222u64.to_le_bytes())
            .unwrap();
        poke(&mut env, 0x1_0000, 0xa8c4_6bf9); // ldp x25, x26, [sp], #0x40
        let mut sys = NoSys;
        env.pc = 0x1_0000;
        let _ = polyisa_engine::run::run(
            &mut env,
            &mut sys,
            1,
            |e| e.pc,
            |e, s| step_a64(e, s, 0, Endian::Le, None),
        );
        assert_eq!(xreg(&mut env, 25), 0x1111);
        assert_eq!(xreg(&mut env, 26), 0x2222);
        assert_eq!(env.backend.get(sem::sp_ref()), 0x1_00c0, "SP += 0x40");
    }

    #[test]
    fn ldr_reg_lsl_scales_index() {
        // ldr x5, [x0, x2, lsl #3]: オフセットは x2<<3。
        let mut env = env_at(0x1_0000);
        env.backend.set(Gpr(0).state(), 0x1_0100);
        env.backend.set(Gpr(2).state(), 2);
        env.backend
            .mem
            .write(VirtAddr(0x1_0110), &0xbeefu64.to_le_bytes())
            .unwrap();
        poke(&mut env, 0x1_0000, 0xf862_7805); // ldr x5, [x0, x2, lsl #3]
        let mut sys = NoSys;
        env.pc = 0x1_0000;
        let _ = polyisa_engine::run::run(
            &mut env,
            &mut sys,
            1,
            |e| e.pc,
            |e, s| step_a64(e, s, 0, Endian::Le, None),
        );
        assert_eq!(xreg(&mut env, 5), 0xbeef);
    }

    #[test]
    fn mrs_returns_id_registers() {
        // mrs x0, midr_el1 / mrs x1, id_aa64pfr0_el1 / mrs x2, mvfr0_el1。
        // ID 値は実装済み機能に整合させる（FP/AdvSIMD=実装済み、EL0 は A64 のみ）。
        let mut env = env_at(0x1_0000);
        poke(&mut env, 0x1_0000, 0xd538_0000); // mrs x0, midr_el1
        poke(&mut env, 0x1_0004, 0xd538_0401); // mrs x1, id_aa64pfr0_el1
        poke(&mut env, 0x1_0008, 0xd538_0302); // mrs x2, mvfr0_el1
        let mut sys = NoSys;
        env.pc = 0x1_0000;
        let _ = polyisa_engine::run::run(
            &mut env,
            &mut sys,
            3,
            |e| e.pc,
            |e, s| step_a64(e, s, 0, Endian::Le, None),
        );
        assert_eq!(xreg(&mut env, 0), 0x410f_d034);
        assert_eq!(xreg(&mut env, 1), 0x2);
        assert_eq!(xreg(&mut env, 2), 0x1011_0112);
    }

    #[test]
    fn stack_grows_on_fault() {
        // stp で現在の写像の下端を越えて書き、ページフォルト駆動の
        // スタック成長で継続できるかを確かめる。
        let mut env = env_at(0x1_0000);
        let top = 0x1_0000u64;
        let growth = Some(StackGrowth {
            top,
            limit: top - 0x8000,
        });
        // sp の指すページのみ写像済みにして、その下への stp をフォルトさせる。
        env.backend
            .mem
            .map(VirtAddr(top - PAGE_SIZE), 1, Perms(Perms::R.0 | Perms::W.0))
            .unwrap();
        env.backend.set(sem::sp_ref(), top - PAGE_SIZE);
        env.backend.set(Gpr(0).state(), 0xaaaa);
        env.backend.set(Gpr(1).state(), 0xbbbb);
        // stp x0, x1, [sp, #-0x200]!: 窓内の未写像アドレスへの書き込み。
        poke(&mut env, 0x1_0000, 0xa9a0_07e0); // stp x0, x1, [sp, #-0x200]!
        let mut sys = NoSys;
        env.pc = 0x1_0000;
        let _ = polyisa_engine::run::run(
            &mut env,
            &mut sys,
            2,
            |e| e.pc,
            |e, s| step_a64(e, s, 0, Endian::Le, growth),
        );
        // 成長して書き込みが完了し、sp が書き戻されている。
        assert_eq!(env.backend.get(sem::sp_ref()), top - PAGE_SIZE - 0x200);
        let mut buf = [0u8; 16];
        env.backend
            .mem
            .read(VirtAddr(top - PAGE_SIZE - 0x200), &mut buf, Access::DATA_LE)
            .unwrap();
        assert_eq!(&buf[..8], &0xaaaau64.to_le_bytes());
        assert_eq!(&buf[8..], &0xbbbbu64.to_le_bytes());
    }
}
