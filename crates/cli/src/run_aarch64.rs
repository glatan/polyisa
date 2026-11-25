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
use polyisa_guest_aarch64::{DEFAULT_FEATS, Insn, decode_model_ex};
use polyisa_mem::{Access, AccessKind, Align, Endian, PAGE_SIZE, PageNo, Perms, VirtAddr};
use polyisa_sem::Backend;

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
    feats: u128,
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

/// `run_ex` に既定モデルの機能集合・LE・成長なしを渡す既定の入口。
pub fn run(env: &mut BareEnv, entry: u64, sys: &mut impl TrapHandler) -> Outcome {
    run_ex(env, entry, DEFAULT_FEATS, Endian::Le, None, sys)
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
    feats: u128,
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
    // semihosting の入口は `hlt #0xf000`。OS パーソナリティへ
    // 委ねる点は svc と同じ（imm が番号として渡る）。
    if insn == Insn::Hlt && (word >> 5) & 0xffff == 0xf000 {
        return svc(env, sys, 0xf000, pc, word);
    }
    let le = endian;
    let ok = env.step(|b| dispatch_a64(b, insn, word, pc, le));
    match ok {
        Err(e) => {
            // スタック窓内の未写像フォルトは写像を伸ばして同じ命令をやり直す
            // （カーネルのスタック VMA 成長に相当）。pc は変えずに戻る。
            if let polyisa_engine::interp::InterpExit::Exception(ref g) = e
                && stack_grow(env, stack, g).is_some()
            {
                return Ok(());
            }
            return Err(unimpl(env));
        }
        Ok(false) => return Err(unimpl(env)),
        Ok(true) => {}
    }
    // 分岐なしは次へ進める（分岐成立は step が pc を置き換える）。
    if env.backend.ctrl == Ctrl::Fallthrough {
        env.pc += 4;
    }
    Ok(())
}

/// `insn`/`word` の意味論に振り分ける。`Ok(false)` は境界
///（`hvc` やデコード不能など、未実装として扱う）。
/// フェッチと `svc` の前処理は `step_a64` / 記録側が行う。
/// `B: Backend` なので記録バックエンドにも同じ表が使える。
// Ref: SPEC-ARM-ARM-A (Armv9-A ARM ARM 2024-09).
#[allow(clippy::too_many_lines)]
fn dispatch_a64<B: Backend>(
    b: &mut B,
    insn: Insn,
    word: u32,
    pc: u64,
    le: Endian,
) -> Result<bool, B::Exit> {
    // フィールドの切り出し。
    let sf = word >> 31 != 0;
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
    let dbl = n_bit != 0;
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
    match insn {
        Insn::B => sem::b_(b, b_tgt),
        Insn::Bl => sem::bl(b, pc, b_tgt),
        Insn::BCond => sem::b_cond(b, c_tgt, cond),
        Insn::Cbz => sem::cbz(b, rt, c_tgt, sf, false),
        Insn::Cbnz => sem::cbz(b, rt, c_tgt, sf, true),
        Insn::Tbz => sem::tbz(b, rt, t_tgt, bit_no, false),
        Insn::Tbnz => sem::tbz(b, rt, t_tgt, bit_no, true),
        Insn::Br => sem::br(b, rn),
        Insn::Blr => sem::blr(b, rn, pc),
        Insn::Ret => sem::ret(b, rn),
        Insn::Hvc | Insn::Smc | Insn::Brk | Insn::Hlt | Insn::Sysl => {
            return Ok(false);
        }
        Insn::Msr => sem::msr(b, rt, sysop),
        Insn::Mrs => sem::mrs(b, rt, sysop),
        Insn::Sys | Insn::PrfmLit => sem::sys_op(b),
        Insn::AddImm => sem::add_imm(b, rd, rn, imm_s, sf, false, false),
        Insn::AddsImm => sem::add_imm(b, rd, rn, imm_s, sf, false, true),
        Insn::SubImm => sem::add_imm(b, rd, rn, imm_s, sf, true, false),
        Insn::SubsImm => sem::add_imm(b, rd, rn, imm_s, sf, true, true),
        Insn::AndImm | Insn::OrrImm | Insn::EorImm | Insn::AndsImm => {
            let op = match insn {
                Insn::AndImm => 0,
                Insn::OrrImm => 1,
                Insn::EorImm => 2,
                _ => 3,
            };
            let Some(mask) = sem::decode_bit_masks(n_bit, imms, immr, sf) else {
                return Ok(false);
            };
            sem::log_imm(b, rd, rn, mask, op, sf)
        }
        Insn::Movn => sem::movn(b, rd, u64::from(imm16) << (16 * hw), sf),
        Insn::Movz => sem::movz(b, rd, u64::from(imm16) << (16 * hw), sf),
        Insn::Movk => sem::movk(b, rd, u64::from(imm16), hw, sf),
        Insn::Adr => {
            // immhi(bits[23:5])<<2 | immlo(bits[30:29]) の 21 ビット符号付き。
            let imm21 = (((word >> 5) & 0x7_ffff) << 2) | ((word >> 29) & 3);
            sem::adr(b, rd, pc, sext(imm21, 21))
        }
        Insn::Adrp => {
            let imm21 = (((word >> 5) & 0x7ffff) << 2) | ((word >> 29) & 3);
            sem::adr(b, rd, pc & !0xfff, sext(imm21, 21) << 12)
        }
        Insn::Sbfm => sem::bitfield(b, rd, rn, immr, imms, 0, sf),
        Insn::Bfm => sem::bitfield(b, rd, rn, immr, imms, 1, sf),
        Insn::Ubfm => sem::bitfield(b, rd, rn, immr, imms, 2, sf),
        Insn::Extr => sem::extr(b, rd, rn, rm, imms, sf),
        Insn::AndSh => sem::log_sh(b, rd, rn, rm, shift, imm6, 0, false, sf),
        Insn::BicSh => sem::log_sh(b, rd, rn, rm, shift, imm6, 0, true, sf),
        Insn::OrrSh => sem::log_sh(b, rd, rn, rm, shift, imm6, 1, false, sf),
        Insn::OrnSh => sem::log_sh(b, rd, rn, rm, shift, imm6, 1, true, sf),
        Insn::EorSh => sem::log_sh(b, rd, rn, rm, shift, imm6, 2, false, sf),
        Insn::EonSh => sem::log_sh(b, rd, rn, rm, shift, imm6, 2, true, sf),
        Insn::AndsSh => sem::log_sh(b, rd, rn, rm, shift, imm6, 3, false, sf),
        Insn::BicsSh => sem::log_sh(b, rd, rn, rm, shift, imm6, 3, true, sf),
        Insn::AddSh => sem::add_sh(b, rd, rn, rm, shift, imm6, sf, false, false),
        Insn::AddsSh => sem::add_sh(b, rd, rn, rm, shift, imm6, sf, false, true),
        Insn::SubSh => sem::add_sh(b, rd, rn, rm, shift, imm6, sf, true, false),
        Insn::SubsSh => sem::add_sh(b, rd, rn, rm, shift, imm6, sf, true, true),
        Insn::AddExt => sem::add_ext(b, rd, rn, rm, option, imm3, sf, false, false),
        Insn::AddsExt => sem::add_ext(b, rd, rn, rm, option, imm3, sf, false, true),
        Insn::SubExt => sem::add_ext(b, rd, rn, rm, option, imm3, sf, true, false),
        Insn::SubsExt => sem::add_ext(b, rd, rn, rm, option, imm3, sf, true, true),
        Insn::Csel => sem::csel(b, rd, rn, rm, cond_hi, 0, sf),
        Insn::Csinc => sem::csel(b, rd, rn, rm, cond_hi, 1, sf),
        Insn::Csinv => sem::csel(b, rd, rn, rm, cond_hi, 2, sf),
        Insn::Csneg => sem::csel(b, rd, rn, rm, cond_hi, 3, sf),
        Insn::CcmnReg => {
            let c = (word >> 12) & 0xf;
            sem::ccmp(b, rn, rm, 0, nzcv_in, c, sf, false, false)
        }
        Insn::CcmpReg => {
            let c = (word >> 12) & 0xf;
            sem::ccmp(b, rn, rm, 0, nzcv_in, c, sf, false, true)
        }
        Insn::CcmnImm => {
            let c = (word >> 12) & 0xf;
            let imm5 = u64::from((word >> 16) & 31);
            sem::ccmp(b, rn, rm, imm5, nzcv_in, c, sf, true, false)
        }
        Insn::CcmpImm => {
            let c = (word >> 12) & 0xf;
            let imm5 = u64::from((word >> 16) & 31);
            sem::ccmp(b, rn, rm, imm5, nzcv_in, c, sf, true, true)
        }
        Insn::Udiv => sem::dp2(b, rd, rn, rm, 0, sf),
        Insn::Sdiv => sem::dp2(b, rd, rn, rm, 1, sf),
        Insn::Lslv => sem::dp2(b, rd, rn, rm, 2, sf),
        Insn::Lsrv => sem::dp2(b, rd, rn, rm, 3, sf),
        Insn::Asrv => sem::dp2(b, rd, rn, rm, 4, sf),
        Insn::Rorv => sem::dp2(b, rd, rn, rm, 5, sf),
        Insn::Rbit => sem::dp1(b, rd, rn, 0, sf),
        Insn::Rev16 => sem::dp1(b, rd, rn, 1, sf),
        Insn::Rev32 => sem::dp1(b, rd, rn, 2, true),
        Insn::Rev => sem::dp1(b, rd, rn, 2, false),
        Insn::Rev64 => sem::dp1(b, rd, rn, 3, true),
        Insn::Clz => sem::dp1(b, rd, rn, 4, sf),
        Insn::Cls => sem::dp1(b, rd, rn, 5, sf),
        Insn::Madd => sem::madd(b, rd, rn, rm, ra, false, sf),
        Insn::Msub => sem::madd(b, rd, rn, rm, ra, true, sf),
        Insn::Smaddl => sem::maddl(b, rd, rn, rm, ra, 0),
        Insn::Smsubl => sem::maddl(b, rd, rn, rm, ra, 1),
        Insn::Umaddl => sem::maddl(b, rd, rn, rm, ra, 2),
        Insn::Umsubl => sem::maddl(b, rd, rn, rm, ra, 3),
        Insn::Smulh => sem::mulh(b, rd, rn, rm, true),
        Insn::Umulh => sem::mulh(b, rd, rn, rm, false),
        Insn::StrbU => sem::ls_unsigned(b, rt, rn, imm12 as i64, 1, true, false, false, le),
        Insn::LdrbU => sem::ls_unsigned(b, rt, rn, imm12 as i64, 1, false, false, false, le),
        Insn::LdrsbUX => sem::ls_unsigned(b, rt, rn, imm12 as i64, 1, false, true, true, le),
        Insn::LdrsbUW => sem::ls_unsigned(b, rt, rn, imm12 as i64, 1, false, true, false, le),
        Insn::StrhU => sem::ls_unsigned(b, rt, rn, (imm12 as i64) << 1, 2, true, false, false, le),
        Insn::LdrhU => sem::ls_unsigned(b, rt, rn, (imm12 as i64) << 1, 2, false, false, false, le),
        Insn::LdrshUX => sem::ls_unsigned(b, rt, rn, (imm12 as i64) << 1, 2, false, true, true, le),
        Insn::LdrshUW => {
            sem::ls_unsigned(b, rt, rn, (imm12 as i64) << 1, 2, false, true, false, le)
        }
        Insn::StrUW => sem::ls_unsigned(b, rt, rn, (imm12 as i64) << 2, 4, true, false, false, le),
        Insn::LdrUW => sem::ls_unsigned(b, rt, rn, (imm12 as i64) << 2, 4, false, false, false, le),
        Insn::LdrswU => sem::ls_unsigned(b, rt, rn, (imm12 as i64) << 2, 4, false, true, true, le),
        Insn::StrUX => sem::ls_unsigned(b, rt, rn, (imm12 as i64) << 3, 8, true, false, false, le),
        Insn::LdrUX => sem::ls_unsigned(b, rt, rn, (imm12 as i64) << 3, 8, false, false, false, le),
        Insn::Sturb => sem::ls_imm9(b, rt, rn, imm9, 1, true, false, false, 0, le),
        Insn::Ldurb => sem::ls_imm9(b, rt, rn, imm9, 1, false, false, false, 0, le),
        Insn::LdursbX => sem::ls_imm9(b, rt, rn, imm9, 1, false, true, true, 0, le),
        Insn::LdursbW => sem::ls_imm9(b, rt, rn, imm9, 1, false, true, false, 0, le),
        Insn::Sturh => sem::ls_imm9(b, rt, rn, imm9, 2, true, false, false, 0, le),
        Insn::Ldurh => sem::ls_imm9(b, rt, rn, imm9, 2, false, false, false, 0, le),
        Insn::LdurshX => sem::ls_imm9(b, rt, rn, imm9, 2, false, true, true, 0, le),
        Insn::LdurshW => sem::ls_imm9(b, rt, rn, imm9, 2, false, true, false, 0, le),
        Insn::SturW => sem::ls_imm9(b, rt, rn, imm9, 4, true, false, false, 0, le),
        Insn::LdurW => sem::ls_imm9(b, rt, rn, imm9, 4, false, false, false, 0, le),
        Insn::Ldursw => sem::ls_imm9(b, rt, rn, imm9, 4, false, true, true, 0, le),
        Insn::SturX => sem::ls_imm9(b, rt, rn, imm9, 8, true, false, false, 0, le),
        Insn::LdurX => sem::ls_imm9(b, rt, rn, imm9, 8, false, false, false, 0, le),
        Insn::StrbPost => sem::ls_imm9(b, rt, rn, imm9, 1, true, false, false, 1, le),
        Insn::LdrbPost => sem::ls_imm9(b, rt, rn, imm9, 1, false, false, false, 1, le),
        Insn::LdrsbPostX => sem::ls_imm9(b, rt, rn, imm9, 1, false, true, true, 1, le),
        Insn::LdrsbPostW => sem::ls_imm9(b, rt, rn, imm9, 1, false, true, false, 1, le),
        Insn::StrhPost => sem::ls_imm9(b, rt, rn, imm9, 2, true, false, false, 1, le),
        Insn::LdrhPost => sem::ls_imm9(b, rt, rn, imm9, 2, false, false, false, 1, le),
        Insn::LdrshPostX => sem::ls_imm9(b, rt, rn, imm9, 2, false, true, true, 1, le),
        Insn::LdrshPostW => sem::ls_imm9(b, rt, rn, imm9, 2, false, true, false, 1, le),
        Insn::StrPostW => sem::ls_imm9(b, rt, rn, imm9, 4, true, false, false, 1, le),
        Insn::LdrPostW => sem::ls_imm9(b, rt, rn, imm9, 4, false, false, false, 1, le),
        Insn::LdrswPost => sem::ls_imm9(b, rt, rn, imm9, 4, false, true, true, 1, le),
        Insn::StrPostX => sem::ls_imm9(b, rt, rn, imm9, 8, true, false, false, 1, le),
        Insn::LdrPostX => sem::ls_imm9(b, rt, rn, imm9, 8, false, false, false, 1, le),
        Insn::StrbPre => sem::ls_imm9(b, rt, rn, imm9, 1, true, false, false, 3, le),
        Insn::LdrbPre => sem::ls_imm9(b, rt, rn, imm9, 1, false, false, false, 3, le),
        Insn::LdrsbPreX => sem::ls_imm9(b, rt, rn, imm9, 1, false, true, true, 3, le),
        Insn::LdrsbPreW => sem::ls_imm9(b, rt, rn, imm9, 1, false, true, false, 3, le),
        Insn::StrhPre => sem::ls_imm9(b, rt, rn, imm9, 2, true, false, false, 3, le),
        Insn::LdrhPre => sem::ls_imm9(b, rt, rn, imm9, 2, false, false, false, 3, le),
        Insn::LdrshPreX => sem::ls_imm9(b, rt, rn, imm9, 2, false, true, true, 3, le),
        Insn::LdrshPreW => sem::ls_imm9(b, rt, rn, imm9, 2, false, true, false, 3, le),
        Insn::StrPreW => sem::ls_imm9(b, rt, rn, imm9, 4, true, false, false, 3, le),
        Insn::LdrPreW => sem::ls_imm9(b, rt, rn, imm9, 4, false, false, false, 3, le),
        Insn::LdrswPre => sem::ls_imm9(b, rt, rn, imm9, 4, false, true, true, 3, le),
        Insn::StrPreX => sem::ls_imm9(b, rt, rn, imm9, 8, true, false, false, 3, le),
        Insn::LdrPreX => sem::ls_imm9(b, rt, rn, imm9, 8, false, false, false, 3, le),
        Insn::StrbReg => sem::ls_regoff(b, rt, rn, rm, option, 0, 1, true, false, false, le),
        Insn::LdrbReg => sem::ls_regoff(b, rt, rn, rm, option, 0, 1, false, false, false, le),
        Insn::LdrsbRegX => sem::ls_regoff(b, rt, rn, rm, option, 0, 1, false, true, true, le),
        Insn::LdrsbRegW => sem::ls_regoff(b, rt, rn, rm, option, 0, 1, false, true, false, le),
        Insn::StrhReg => sem::ls_regoff(b, rt, rn, rm, option, s_bit, 2, true, false, false, le),
        Insn::LdrhReg => sem::ls_regoff(b, rt, rn, rm, option, s_bit, 2, false, false, false, le),
        Insn::LdrshRegX => sem::ls_regoff(b, rt, rn, rm, option, s_bit, 2, false, true, true, le),
        Insn::LdrshRegW => sem::ls_regoff(b, rt, rn, rm, option, s_bit, 2, false, true, false, le),
        Insn::StrRegW => {
            sem::ls_regoff(b, rt, rn, rm, option, s_bit * 2, 4, true, false, false, le)
        }
        Insn::LdrRegW => {
            sem::ls_regoff(b, rt, rn, rm, option, s_bit * 2, 4, false, false, false, le)
        }
        Insn::LdrswReg => {
            sem::ls_regoff(b, rt, rn, rm, option, s_bit * 2, 4, false, true, true, le)
        }
        Insn::StrRegX => {
            sem::ls_regoff(b, rt, rn, rm, option, s_bit * 3, 8, true, false, false, le)
        }
        Insn::LdrRegX => {
            sem::ls_regoff(b, rt, rn, rm, option, s_bit * 3, 8, false, false, false, le)
        }
        Insn::LdrWLit => sem::ls_lit(b, rt, c_tgt, 4, false, false, le),
        Insn::LdrXLit => sem::ls_lit(b, rt, c_tgt, 8, false, false, le),
        Insn::LdrswLit => sem::ls_lit(b, rt, c_tgt, 4, true, true, le),
        Insn::StpWOff => sem::ls_pair(b, rt, rt2, rn, imm7 << 2, 4, true, 2, le),
        Insn::LdpWOff => sem::ls_pair(b, rt, rt2, rn, imm7 << 2, 4, false, 2, le),
        Insn::StpXOff => sem::ls_pair(b, rt, rt2, rn, imm7 << 3, 8, true, 2, le),
        Insn::LdpXOff => sem::ls_pair(b, rt, rt2, rn, imm7 << 3, 8, false, 2, le),
        Insn::StpWPost => sem::ls_pair(b, rt, rt2, rn, imm7 << 2, 4, true, 1, le),
        Insn::LdpWPost => sem::ls_pair(b, rt, rt2, rn, imm7 << 2, 4, false, 1, le),
        Insn::StpXPost => sem::ls_pair(b, rt, rt2, rn, imm7 << 3, 8, true, 1, le),
        Insn::LdpXPost => sem::ls_pair(b, rt, rt2, rn, imm7 << 3, 8, false, 1, le),
        Insn::StpWPre => sem::ls_pair(b, rt, rt2, rn, imm7 << 2, 4, true, 3, le),
        Insn::LdpWPre => sem::ls_pair(b, rt, rt2, rn, imm7 << 2, 4, false, 3, le),
        Insn::StpXPre => sem::ls_pair(b, rt, rt2, rn, imm7 << 3, 8, true, 3, le),
        Insn::LdpXPre => sem::ls_pair(b, rt, rt2, rn, imm7 << 3, 8, false, 3, le),
        Insn::LdxrW | Insn::LdaxrW => sem::ldxr(b, rt, rn, 4, le),
        Insn::StxrW | Insn::StlxrW => sem::stxr(b, rs, rt, rn, 4, le),
        Insn::LdxrX | Insn::LdaxrX => sem::ldxr(b, rt, rn, 8, le),
        Insn::StxrX | Insn::StlxrX => sem::stxr(b, rs, rt, rn, 8, le),
        Insn::Ldxrb | Insn::Ldaxrb => sem::ldxr(b, rt, rn, 1, le),
        Insn::Stxrb | Insn::Stlxrb => sem::stxr(b, rs, rt, rn, 1, le),
        Insn::Ldxrh | Insn::Ldaxrh => sem::ldxr(b, rt, rn, 2, le),
        Insn::Stxrh | Insn::Stlxrh => sem::stxr(b, rs, rt, rn, 2, le),
        // ---- FP/SIMD ----
        Insn::StpSOff => sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 2, 4, true, 2, le),
        Insn::LdpSOff => sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 2, 4, false, 2, le),
        Insn::StpDOff => sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 3, 8, true, 2, le),
        Insn::LdpDOff => sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 3, 8, false, 2, le),
        Insn::StpQOff => sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 4, 16, true, 2, le),
        Insn::LdpQOff => sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 4, 16, false, 2, le),
        Insn::StpSPost => sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 2, 4, true, 1, le),
        Insn::LdpSPost => sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 2, 4, false, 1, le),
        Insn::StpDPost => sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 3, 8, true, 1, le),
        Insn::LdpDPost => sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 3, 8, false, 1, le),
        Insn::StpQPost => sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 4, 16, true, 1, le),
        Insn::LdpQPost => sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 4, 16, false, 1, le),
        Insn::StpSPre => sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 2, 4, true, 3, le),
        Insn::LdpSPre => sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 2, 4, false, 3, le),
        Insn::StpDPre => sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 3, 8, true, 3, le),
        Insn::LdpDPre => sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 3, 8, false, 3, le),
        Insn::StpQPre => sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 4, 16, true, 3, le),
        Insn::LdpQPre => sem::vls_pair(b, rt.0, rt2.0, rn, imm7 << 4, 16, false, 3, le),
        Insn::StrBVu => sem::vls_unsigned(b, rt.0, rn, imm12 as i64, 1, true, le),
        Insn::LdrBVu => sem::vls_unsigned(b, rt.0, rn, imm12 as i64, 1, false, le),
        Insn::StrHVu => sem::vls_unsigned(b, rt.0, rn, (imm12 * 2) as i64, 2, true, le),
        Insn::LdrHVu => sem::vls_unsigned(b, rt.0, rn, (imm12 * 2) as i64, 2, false, le),
        Insn::StrSVu => sem::vls_unsigned(b, rt.0, rn, (imm12 * 4) as i64, 4, true, le),
        Insn::LdrSVu => sem::vls_unsigned(b, rt.0, rn, (imm12 * 4) as i64, 4, false, le),
        Insn::StrDVu => sem::vls_unsigned(b, rt.0, rn, (imm12 * 8) as i64, 8, true, le),
        Insn::LdrDVu => sem::vls_unsigned(b, rt.0, rn, (imm12 * 8) as i64, 8, false, le),
        Insn::StrQVu => sem::vls_unsigned(b, rt.0, rn, (imm12 * 16) as i64, 16, true, le),
        Insn::LdrQVu => sem::vls_unsigned(b, rt.0, rn, (imm12 * 16) as i64, 16, false, le),
        Insn::SturB => sem::vls_imm9(b, rt.0, rn, imm9, 1, true, 0, le),
        Insn::LdurB => sem::vls_imm9(b, rt.0, rn, imm9, 1, false, 0, le),
        Insn::SturH => sem::vls_imm9(b, rt.0, rn, imm9, 2, true, 0, le),
        Insn::LdurH => sem::vls_imm9(b, rt.0, rn, imm9, 2, false, 0, le),
        Insn::SturS => sem::vls_imm9(b, rt.0, rn, imm9, 4, true, 0, le),
        Insn::LdurS => sem::vls_imm9(b, rt.0, rn, imm9, 4, false, 0, le),
        Insn::SturD => sem::vls_imm9(b, rt.0, rn, imm9, 8, true, 0, le),
        Insn::LdurD => sem::vls_imm9(b, rt.0, rn, imm9, 8, false, 0, le),
        Insn::SturQ => sem::vls_imm9(b, rt.0, rn, imm9, 16, true, 0, le),
        Insn::LdurQ => sem::vls_imm9(b, rt.0, rn, imm9, 16, false, 0, le),
        Insn::StrBPostV => sem::vls_imm9(b, rt.0, rn, imm9, 1, true, 1, le),
        Insn::LdrBPostV => sem::vls_imm9(b, rt.0, rn, imm9, 1, false, 1, le),
        Insn::StrHPostV => sem::vls_imm9(b, rt.0, rn, imm9, 2, true, 1, le),
        Insn::LdrHPostV => sem::vls_imm9(b, rt.0, rn, imm9, 2, false, 1, le),
        Insn::StrSPostV => sem::vls_imm9(b, rt.0, rn, imm9, 4, true, 1, le),
        Insn::LdrSPostV => sem::vls_imm9(b, rt.0, rn, imm9, 4, false, 1, le),
        Insn::StrDPostV => sem::vls_imm9(b, rt.0, rn, imm9, 8, true, 1, le),
        Insn::LdrDPostV => sem::vls_imm9(b, rt.0, rn, imm9, 8, false, 1, le),
        Insn::StrQPostV => sem::vls_imm9(b, rt.0, rn, imm9, 16, true, 1, le),
        Insn::LdrQPostV => sem::vls_imm9(b, rt.0, rn, imm9, 16, false, 1, le),
        Insn::StrBPreV => sem::vls_imm9(b, rt.0, rn, imm9, 1, true, 3, le),
        Insn::LdrBPreV => sem::vls_imm9(b, rt.0, rn, imm9, 1, false, 3, le),
        Insn::StrHPreV => sem::vls_imm9(b, rt.0, rn, imm9, 2, true, 3, le),
        Insn::LdrHPreV => sem::vls_imm9(b, rt.0, rn, imm9, 2, false, 3, le),
        Insn::StrSPreV => sem::vls_imm9(b, rt.0, rn, imm9, 4, true, 3, le),
        Insn::LdrSPreV => sem::vls_imm9(b, rt.0, rn, imm9, 4, false, 3, le),
        Insn::StrDPreV => sem::vls_imm9(b, rt.0, rn, imm9, 8, true, 3, le),
        Insn::LdrDPreV => sem::vls_imm9(b, rt.0, rn, imm9, 8, false, 3, le),
        Insn::StrQPreV => sem::vls_imm9(b, rt.0, rn, imm9, 16, true, 3, le),
        Insn::LdrQPreV => sem::vls_imm9(b, rt.0, rn, imm9, 16, false, 3, le),
        Insn::DupGen => {
            let imm5 = (word >> 16) & 0x1f;
            let esz = imm5.trailing_zeros();
            let q = (word >> 30) & 1 != 0;
            sem::vdup_gpr(b, rd.0, rn, esz, q)
        }
        Insn::InsGen => {
            let imm5 = (word >> 16) & 0x1f;
            let esz = imm5.trailing_zeros();
            let idx = imm5 >> (esz + 1);
            sem::vins_gpr(b, rd.0, rn, esz, idx)
        }
        Insn::Umov => {
            let imm5 = (word >> 16) & 0x1f;
            let esz = imm5.trailing_zeros();
            let idx = imm5 >> (esz + 1);
            sem::vext_gpr(b, rd, rn.0, esz, idx)
        }
        Insn::FmovWS => sem::fmov_to_g(b, rd, rn.0, false, false),
        Insn::FmovSW => sem::fmov_to_v(b, rd.0, rn, 32, false),
        Insn::FmovXD => sem::fmov_to_g(b, rd, rn.0, true, false),
        Insn::FmovDX => sem::fmov_to_v(b, rd.0, rn, 64, false),
        Insn::FmovXDhi => sem::fmov_to_g(b, rd, rn.0, true, true),
        Insn::FmovDhiX => sem::fmov_to_v(b, rd.0, rn, 64, true),
        // スカラー FP。dbl は ptype[22]（0=S,1=D）。
        Insn::Fp3 => sem::fp3(b, rd.0, rn.0, rm.0, cond_hi, dbl),
        Insn::Fp1 => {
            let opc = (word >> 15) & 0x3f;
            if opc == 4 || opc == 5 {
                sem::fp1_cvt(b, rd.0, rn.0, opc)
            } else {
                sem::fp1(b, rd.0, rn.0, opc, dbl)
            }
        }
        Insn::Fma => {
            let neg_p = (word >> 21) & 1 != 0;
            let neg_a = (word >> 15) & 1 != 0;
            sem::fma(b, rd.0, rn.0, rm.0, ra.0, neg_p, neg_a, dbl)
        }
        Insn::Fcvt | Insn::FcvtA => {
            let op = (word >> 16) & 7;
            if op == 2 || op == 3 {
                // scvtf/ucvtf: 汎用レジスタ → FP。
                sem::int2fp(b, rd.0, rn, dbl, op == 3, sf)
            } else {
                // fcvt{*,a}{s,u}: FP → 汎用レジスタ。
                {
                    sem::fp2int(
                        b,
                        rd,
                        rn.0,
                        (word >> 19) & 3,
                        op & 1 != 0,
                        insn == Insn::FcvtA,
                        dbl,
                        sf,
                    )
                }
            }
        }
        Insn::Fcmp => sem::fcmp(b, rn.0, rm.0, word & 0x1f, dbl),
        Insn::Fccmp => sem::fccmp(b, rn.0, rm.0, cond_hi, u64::from(word & 0xf), dbl),
        Insn::Fcsel => sem::fcsel(b, rd.0, rn.0, rm.0, cond_hi, dbl),
        Insn::FmovImm => sem::fmov_imm(b, rd.0, (word >> 13) & 0xff, dbl),
        Insn::ModImm => {
            let q = (word >> 30) & 1 != 0;
            let op = (word >> 29) & 1 != 0;
            let cmode = (word >> 12) & 0xf;
            let imm8 = u64::from((((word >> 16) & 7) << 5) | ((word >> 5) & 0x1f));
            sem::mod_imm(b, rd.0, q, op, cmode, imm8)
        }
        Insn::Svc => return Ok(false),
    }?;
    Ok(true)
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
    // JIT は `POLYISA_JIT` 指定時のみ opt-in。既定はインタプリタ。
    let mut jit_owned = polyisa_jit::Jit::new();
    let jit = std::env::var_os("POLYISA_JIT").map(|_| &mut jit_owned);
    run_elf_aarch64_impl(path, argv, sel, &mut sys, root, jit)
}

/// `run_elf_aarch64_sel` に OS パーソナリティを差し込む形。
/// テストが syscall の結果（`sys.io` 等）を検査する用途に使う。
pub fn run_elf_aarch64_sys(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    sys: &mut polyisa_os_linux::aarch64::sys::Linux,
) -> Result<u64, String> {
    run_elf_aarch64_impl(path, argv, sel, sys, None, None)
}

/// `run_elf_aarch64_sys` の JIT 版。差分テストが `sys.io` 等を比べるのに使う。
/// `jit` は呼び出し側が用意し、コンパイル済みブロックはテスト間で使い回せる。
pub fn run_elf_aarch64_sys_jit(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    sys: &mut polyisa_os_linux::aarch64::sys::Linux,
    jit: &mut polyisa_jit::Jit,
) -> Result<u64, String> {
    run_elf_aarch64_impl(path, argv, sel, sys, None, Some(jit))
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
    run_elf_aarch64_impl(path, argv, sel, sys, root, None)
}

/// `run_elf_aarch64_impl` の semihosting 版（`--os semihost`）。
/// `hlt #0xf000` が `semi` の SYS_* 演算へ届く。
pub fn run_elf_aarch64_semi(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    semi: &mut polyisa_os_semihost::SemiA64,
    root: Option<&str>,
) -> Result<u64, String> {
    // JIT は `POLYISA_JIT` 指定時のみ opt-in（linux 経路と同じ）。
    let mut jit_owned = polyisa_jit::Jit::new();
    let jit = std::env::var_os("POLYISA_JIT").map(|_| &mut jit_owned);
    run_elf_aarch64_impl(path, argv, sel, semi, root, jit)
}

/// `run_elf_aarch64_semi` に JIT を差し込む形。差分テストが
/// `semi.io` 等を比べるのに使う。
pub fn run_elf_aarch64_semi_jit(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    semi: &mut polyisa_os_semihost::SemiA64,
    root: Option<&str>,
    jit: &mut polyisa_jit::Jit,
) -> Result<u64, String> {
    run_elf_aarch64_impl(path, argv, sel, semi, root, Some(jit))
}

/// `run_elf_aarch64_sys` にゲストルートを添えた実体。
/// `root` は PT_INTERP の動的ローダ解決と `sys` のパス閉じ込めに使う。
fn run_elf_aarch64_impl(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    sys: &mut impl crate::ElfSys,
    root: Option<&str>,
    jit: Option<&mut polyisa_jit::Jit>,
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
    ];
    if interp_bias != 0 {
        auxv.push((7, interp_bias)); // AT_BASE
    }
    let (img, sp) =
        polyisa_os_linux::build_initial_stack_endian(img_top, &arg_bytes, &[], &auxv, data_endian);
    // 像の置かれる [sp, img_top) と、像の直上の呼出し側スクラッチを
    // 先に写像する。sp より下はページフォルト駆動の成長で埋まる。
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
    env.backend.set(sem::sp_ref(), sp);
    sys.set_exe_path(path);
    sys.set_endian(data_endian);
    sys.init_brk(image_end);
    let feats = sel.map_or(DEFAULT_FEATS, |s| s.feats);
    let growth = Some(StackGrowth {
        top,
        limit: top - STACK_LIMIT,
    });
    let out = match jit {
        Some(jit) => run_ex_jit(&mut env, entry, feats, data_endian, growth, sys, jit),
        None => run_ex(&mut env, entry, feats, data_endian, growth, sys),
    };
    match out {
        Outcome::Exit(code) => Ok(code),
        Outcome::Unimplemented { pc, word } => Err(format!("unimplemented at {pc:#x}: {word:#x}")),
        Outcome::StepLimit { pc } => Err(format!("step limit at {pc:#x}")),
        Outcome::Deadlock => Err("deadlock".to_string()),
        Outcome::Breakpoint { pc } => Err(format!("breakpoint at {pc:#x}")),
    }
}

// ---- JIT（段階 9）----

/// 1 ブロックに記録する命令数の上限。
const MAX_BLOCK_INSNS: usize = 32;

/// A64 の翻訳器。`feats`/`endian` は実行と同じ設定で固定する。
pub struct A64Tx {
    pub feats: u128,
    pub endian: Endian,
}

impl polyisa_jit::Translate for A64Tx {
    fn key(&self, _b: &polyisa_engine::interp::InterpBackend, pc: u64) -> u64 {
        pc
    }

    fn record(
        &self,
        b: &mut polyisa_engine::interp::InterpBackend,
        entry: u64,
    ) -> Option<polyisa_ir::Recorded> {
        let mut irb = polyisa_ir::IrBackend::new();
        let mut pc = entry;
        for _ in 0..MAX_BLOCK_INSNS {
            let mut b4 = [0u8; 4];
            if b.mem.read(VirtAddr(pc), &mut b4, acc_fetch()).is_err() {
                break;
            }
            b.mem.mark_code(VirtAddr(pc));
            let word = u32::from_le_bytes(b4);
            let Some(insn) = decode_model_ex(u128::from(word), 32, true, self.feats) else {
                break;
            };
            // `svc`・`hlt`・未実装の命令はブロックの境界。
            // インタプリタが処理する（semihost の hlt #0xf000 も
            // ここで切って svc 経路へ戻す）。
            if insn == Insn::Svc || insn == Insn::Hlt {
                break;
            }
            irb.cur_pc = pc;
            irb.cur_next = pc + 4;
            match dispatch_a64(&mut irb, insn, word, pc, self.endian) {
                Ok(true) => {}
                Ok(false) => break,
                Err(e) => {
                    irb.abort(e);
                    break;
                }
            }
            // 制御を動かす命令（分岐・ジャンプ）でブロックを閉じる。
            // その命令自体がブロックの最後の命令になる。
            if irb.ir.has_flow() {
                pc += 4;
                break;
            }
            pc += 4;
        }
        if irb.ir.ops.is_empty() {
            return None;
        }
        polyisa_ir::optimize(&mut irb.ir);
        Some(polyisa_ir::Recorded {
            entry,
            fall: pc,
            ir: irb.ir,
        })
    }
}

/// `pc` の命令語を読んで未実装報告を作る（JIT 経路の `unimpl` 相当）。
fn unimpl_at(env: &BareEnv, pc: u64) -> Outcome {
    let mut b4 = [0u8; 4];
    let word = env
        .backend
        .mem
        .read(VirtAddr(pc), &mut b4, acc_fetch())
        .map(|()| u128::from(u32::from_le_bytes(b4)))
        .unwrap_or(0xffff_ffff);
    Outcome::Unimplemented { pc, word }
}

/// `step_a64` の JIT 版。記録できない入口・例外はインタプリタと同じ解決をする。
pub fn step_a64_jit(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    jit: &mut polyisa_jit::Jit,
    feats: u128,
    endian: Endian,
    stack: Option<StackGrowth>,
) -> Result<(), Outcome> {
    let pc = env.pc;
    let tx = A64Tx { feats, endian };
    match jit.exec_block(&mut env.backend, &tx, pc) {
        Some(polyisa_jit::BlockExit::Next(next)) => {
            env.pc = next;
            env.steps += 1;
            Ok(())
        }
        Some(polyisa_jit::BlockExit::Raise { e, pc, next: _ }) => {
            env.pc = pc;
            // インタプリタと同じく、スタック窓内のフォルトは写像を伸ばす。
            if stack_grow(env, stack, &e).is_some() {
                return Ok(());
            }
            Err(unimpl_at(env, pc))
        }
        Some(polyisa_jit::BlockExit::Unimpl { pc }) => {
            env.pc = pc;
            Err(unimpl_at(env, pc))
        }
        // 記録できない入口（svc・境界から始まる命令）は 1 命令ぶん
        // インタプリタで進める。
        None => step_a64(env, sys, feats, endian, stack),
    }
}

/// `run_ex` の JIT 版。ブロックを IR に記録して機械語で実行する。
/// 記録できない入口・トラップはインタプリタと同じ解決に落ちる。
pub fn run_ex_jit(
    env: &mut BareEnv,
    entry: u64,
    feats: u128,
    endian: Endian,
    stack: Option<StackGrowth>,
    sys: &mut impl TrapHandler,
    jit: &mut polyisa_jit::Jit,
) -> Outcome {
    env.pc = entry;
    polyisa_engine::run::run(
        env,
        sys,
        STEP_LIMIT,
        |env| env.pc,
        |env, sys| step_a64_jit(env, sys, jit, feats, endian, stack),
    )
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
            |e, s| step_a64(e, s, DEFAULT_FEATS, Endian::Le, None),
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
            |e, s| step_a64(e, s, DEFAULT_FEATS, Endian::Le, None),
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
            |e, s| step_a64(e, s, DEFAULT_FEATS, Endian::Le, None),
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
            |e, s| step_a64(e, s, DEFAULT_FEATS, Endian::Le, None),
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
            |e, s| step_a64(e, s, DEFAULT_FEATS, Endian::Le, None),
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
            |e, s| step_a64(e, s, DEFAULT_FEATS, Endian::Le, None),
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
            |e, s| step_a64(e, s, DEFAULT_FEATS, Endian::Le, None),
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
            |e, s| step_a64(e, s, DEFAULT_FEATS, Endian::Le, None),
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
            |e, s| step_a64(e, s, DEFAULT_FEATS, Endian::Le, growth),
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

    // ---- スカラー FP ----

    fn vref_of(i: u8) -> polyisa_sem::StateRef<polyisa_sem::W128> {
        polyisa_sem::StateRef::from_offset(
            core::mem::offset_of!(polyisa_guest_aarch64::CpuState, v) + usize::from(i) * 16,
        )
    }

    fn vget(env: &mut BareEnv, i: u8) -> u128 {
        env.backend.get(vref_of(i))
    }

    fn vset(env: &mut BareEnv, i: u8, v: u128) {
        env.backend.set(vref_of(i), v);
    }

    fn run_n(env: &mut BareEnv, n: u64) {
        let mut sys = NoSys;
        let _ = polyisa_engine::run::run(
            env,
            &mut sys,
            n,
            |e| e.pc,
            |e, s| step_a64(e, s, DEFAULT_FEATS, Endian::Le, None),
        );
    }

    #[test]
    fn fp_scalar_arith() {
        // s0=1.5, s1=2.25。演算結果は f32 ビット列で検査する。
        let mut env = env_at(0x1_0000);
        vset(&mut env, 0, 0x3fc0_0000);
        vset(&mut env, 1, 0x4010_0000);
        poke(&mut env, 0x1_0000, 0x1e21_2802); // fadd s2,s0,s1 = 3.75
        poke(&mut env, 0x1_0004, 0x1e21_3803); // fsub s3,s0,s1 = -0.75
        poke(&mut env, 0x1_0008, 0x1e21_0804); // fmul s4,s0,s1 = 3.375
        poke(&mut env, 0x1_000c, 0x1e21_1805); // fdiv s5,s0,s1 = 2/3
        poke(&mut env, 0x1_0010, 0x1e21_4806); // fmax s6 = 2.25
        poke(&mut env, 0x1_0014, 0x1e21_5807); // fmin s7 = 1.5
        poke(&mut env, 0x1_0018, 0x1e21_680d); // fmaxnm s13 = 2.25
        poke(&mut env, 0x1_001c, 0x1e21_880e); // fnmul s14 = -3.375
        env.pc = 0x1_0000;
        run_n(&mut env, 8);
        assert_eq!(vget(&mut env, 2) as u32, 0x4070_0000);
        assert_eq!(vget(&mut env, 3) as u32, 0xbf40_0000);
        assert_eq!(vget(&mut env, 4) as u32, 0x4058_0000);
        assert_eq!(vget(&mut env, 5) as u32, 0x3f2a_aaab);
        assert_eq!(vget(&mut env, 6) as u32, 0x4010_0000);
        assert_eq!(vget(&mut env, 7) as u32, 0x3fc0_0000);
        assert_eq!(vget(&mut env, 13) as u32, 0x4010_0000);
        assert_eq!(vget(&mut env, 14) as u32, 0xc058_0000);
        // スカラー結果は上位レーンを 0 にする。
        assert_eq!(vget(&mut env, 2) >> 32, 0);
    }

    #[test]
    fn fp_scalar_fma_unary_imm() {
        let mut env = env_at(0x1_0000);
        vset(&mut env, 0, 0x3fc0_0000); // 1.5
        vset(&mut env, 1, 0x4010_0000); // 2.25
        vset(&mut env, 3, 0x3f20_0000); // 0.625
        vset(&mut env, 15, 0xc000_0000); // -2.0
        vset(&mut env, 16, 0x4006_0000_0000_0000); // 2.75 (d)
        poke(&mut env, 0x1_0000, 0x1f01_0c02); // fmadd s2,s0,s1,s3 = 4.0
        poke(&mut env, 0x1_0004, 0x1f01_880b); // fmsub s11,s0,s1,s2 = -0.625
        poke(&mut env, 0x1_0008, 0x1f21_0c0c); // fnmadd s12,s0,s1,s3 = -2.75
        poke(&mut env, 0x1_000c, 0x1e21_c029); // fsqrt s9,s1 = 1.5
        poke(&mut env, 0x1_0010, 0x1e20_c1e7); // fabs s7,s15 = 2.0
        poke(&mut env, 0x1_0014, 0x1e21_41e8); // fneg s8,s15 = 2.0
        poke(&mut env, 0x1_0018, 0x1e65_c206); // frintz d6,d16 = 2.0
        poke(&mut env, 0x1_001c, 0x1e2f_1004); // fmov s4,#1.5
        poke(&mut env, 0x1_0020, 0x1e70_9005); // fmov d5,#-2.5
        env.pc = 0x1_0000;
        run_n(&mut env, 9);
        assert_eq!(vget(&mut env, 2) as u32, 0x4080_0000);
        assert_eq!(vget(&mut env, 11) as u32, 0xbf20_0000);
        assert_eq!(vget(&mut env, 12) as u32, 0xc030_0000);
        assert_eq!(vget(&mut env, 9) as u32, 0x3fc0_0000);
        assert_eq!(vget(&mut env, 7) as u32, 0x4000_0000);
        assert_eq!(vget(&mut env, 8) as u32, 0x4000_0000);
        assert_eq!(vget(&mut env, 6), 0x4000_0000_0000_0000);
        assert_eq!(vget(&mut env, 4) as u32, 0x3fc0_0000);
        assert_eq!(vget(&mut env, 5), 0xc004_0000_0000_0000);
    }

    #[test]
    fn fp_scalar_cvt_cmp() {
        let mut env = env_at(0x1_0000);
        env.backend.set(Gpr(0).state(), 42);
        vset(&mut env, 1, 0x3fc0_0000); // 1.5
        vset(&mut env, 16, 0x4002_0000_0000_0000); // 2.25 (d)
        poke(&mut env, 0x1_0000, 0x1e22_0000); // scvtf s0,w0 = 42.0
        poke(&mut env, 0x1_0004, 0x9e62_0009); // scvtf d9,x0 = 42.0
        poke(&mut env, 0x1_0008, 0x1e38_0021); // fcvtzs w1,s1 = 1
        poke(&mut env, 0x1_000c, 0x1e20_0023); // fcvtns w3,s1 = 2 (RNE)
        poke(&mut env, 0x1_0010, 0x1e24_0024); // fcvtas w4,s1 = 2 (away)
        poke(&mut env, 0x1_0014, 0x1e22_c022); // fcvt d2,s1 = 1.5
        poke(&mut env, 0x1_0018, 0x1e62_4203); // fcvt s3,d16 = 2.25
        poke(&mut env, 0x1_001c, 0x9e79_0042); // fcvtzu x2,d2 = 1
        env.pc = 0x1_0000;
        run_n(&mut env, 8);
        assert_eq!(vget(&mut env, 0) as u32, 0x4228_0000);
        assert_eq!(vget(&mut env, 9) as u64, 0x4045_0000_0000_0000);
        assert_eq!(xreg(&mut env, 1), 1);
        assert_eq!(xreg(&mut env, 3), 2);
        assert_eq!(xreg(&mut env, 4), 2);
        assert_eq!(vget(&mut env, 2), 0x3ff8_0000_0000_0000);
        assert_eq!(vget(&mut env, 3) as u32, 0x4010_0000);
        assert_eq!(xreg(&mut env, 2), 1);
    }

    #[test]
    fn fp_scalar_cmp_sel() {
        let mut env = env_at(0x1_0000);
        vset(&mut env, 0, 0x3fc0_0000); // 1.5
        vset(&mut env, 1, 0x4010_0000); // 2.25
        vset(&mut env, 15, 0x7fc0_0000); // qNaN
        poke(&mut env, 0x1_0000, 0x1e21_2000); // fcmp s0,s1 → lt: N=1 → 0b1000
        poke(&mut env, 0x1_0004, 0x1e20_2000); // fcmp s0,s0 → eq: ZC → 0b0110
        poke(&mut env, 0x1_0008, 0x1e20_2008); // fcmp s0,#0.0 → gt: C → 0b0010
        poke(&mut env, 0x1_000c, 0x1e20_21e0); // fcmp s15,s0 → un: CV → 0b0011
        poke(&mut env, 0x1_0010, 0x1e21_140a); // fccmp s0,s1,#0xa,ne（cond 成立→比較）
        poke(&mut env, 0x1_0014, 0x1e21_0c0a); // fcsel s10,s0,s1,eq（直前は lt → s1）
        env.pc = 0x1_0000;
        run_n(&mut env, 6);
        // 直前の fccmp: ne が成立して比較実行 → lt: N=1。
        assert_eq!(env.backend.get(sem::nzcv_ref()) & 0xf, 0x8);
        assert_eq!(vget(&mut env, 10) as u32, 0x4010_0000);
        // 個別フラグの再検査: eq なら fcsel は s0 側を取る。
        poke(&mut env, 0x1_0018, 0x1e20_2000); // fcmp s0,s0
        poke(&mut env, 0x1_001c, 0x1e21_0c0a); // fcsel s10,s0,s1,eq
        env.pc = 0x1_0018;
        run_n(&mut env, 2);
        assert_eq!(env.backend.get(sem::nzcv_ref()) & 0xf, 0x6);
        assert_eq!(vget(&mut env, 10) as u32, 0x3fc0_0000);
    }
}
