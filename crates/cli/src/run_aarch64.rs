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
use polyisa_mem::{Access, AccessKind, Align, Endian, VirtAddr};
use polyisa_sem::Backend as _;

/// 1命令の実行上限。無限ループの検出用。
pub const STEP_LIMIT: u64 = 5_000_000;

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
pub fn run_ex(env: &mut BareEnv, entry: u64, feats: u64, sys: &mut impl TrapHandler) -> Outcome {
    env.pc = entry;
    polyisa_engine::run::run(
        env,
        sys,
        STEP_LIMIT,
        |env| env.pc,
        |env, sys| step_a64(env, sys, feats),
    )
}

/// `run_ex` に機能集合 0 を渡す既定の入口。
pub fn run(env: &mut BareEnv, entry: u64, sys: &mut impl TrapHandler) -> Outcome {
    run_ex(env, entry, 0, sys)
}

/// 即値の符号拡張。`v` の下位 `bits` を符号付きで取る。
fn sext(v: u32, bits: u32) -> i64 {
    (((v << (32 - bits)) as i32) >> (32 - bits)) as i64
}

/// Arm ARM `DecodeBitMasks`（wmask のみ使う）。`len` は N:~imms の最上位セット
/// ビット。即値論理では imms==levels は予約。
/// Ref: SPEC-ARM-ARM-A (Armv9-A ARM ARM 2024-09) shared/functions。
pub fn decode_bit_masks(n: u32, imms: u32, immr: u32, is64: bool) -> Option<u64> {
    let m: u32 = if is64 { 64 } else { 32 };
    let concat = ((n << 6) | (!imms & 0x3f)) & 0x7f;
    if concat == 0 {
        return None;
    }
    let len = 31 - concat.leading_zeros();
    if len < 1 || m < (1u32 << len) {
        return None;
    }
    let levels = (1u32 << len) - 1;
    if (imms & levels) == levels {
        return None;
    }
    let s = imms & levels;
    let r = immr & levels;
    let esize = 1u64 << len;
    let emask = esize - 1;
    let welem = if s >= 63 {
        u64::MAX
    } else {
        (1u64 << (s + 1)) - 1
    };
    let wrot = if r == 0 {
        welem
    } else {
        ((welem >> r) | (welem << (esize as u32 - r))) & emask
    };
    let mut out = 0u64;
    let mut pos = 0u32;
    while pos < m {
        out |= wrot << pos;
        pos += esize as u32;
    }
    Some(out)
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
#[allow(clippy::too_many_lines)]
fn step_a64(env: &mut BareEnv, sys: &mut impl TrapHandler, feats: u64) -> Result<(), Outcome> {
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
    let le = Endian::Le;
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
            let Some(mask) = decode_bit_masks(n_bit, imms, immr, sf) else {
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
        Insn::Csel => env.step(|b| sem::csel(b, rd, rn, rm, cond, 0, sf)),
        Insn::Csinc => env.step(|b| sem::csel(b, rd, rn, rm, cond, 1, sf)),
        Insn::Csinv => env.step(|b| sem::csel(b, rd, rn, rm, cond, 2, sf)),
        Insn::Csneg => env.step(|b| sem::csel(b, rd, rn, rm, cond, 3, sf)),
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
            env.step(|b| sem::ls_unsigned(b, rt, rn, i64::from(imm12), 1, true, false, false, le))
        }
        Insn::LdrbU => {
            env.step(|b| sem::ls_unsigned(b, rt, rn, i64::from(imm12), 1, false, false, false, le))
        }
        Insn::LdrsbUX => {
            env.step(|b| sem::ls_unsigned(b, rt, rn, i64::from(imm12), 1, false, true, true, le))
        }
        Insn::LdrsbUW => {
            env.step(|b| sem::ls_unsigned(b, rt, rn, i64::from(imm12), 1, false, true, false, le))
        }
        Insn::StrhU => env.step(|b| {
            sem::ls_unsigned(b, rt, rn, i64::from(imm12) << 1, 2, true, false, false, le)
        }),
        Insn::LdrhU => env.step(|b| {
            sem::ls_unsigned(b, rt, rn, i64::from(imm12) << 1, 2, false, false, false, le)
        }),
        Insn::LdrshUX => env
            .step(|b| sem::ls_unsigned(b, rt, rn, i64::from(imm12) << 1, 2, false, true, true, le)),
        Insn::LdrshUW => env.step(|b| {
            sem::ls_unsigned(b, rt, rn, i64::from(imm12) << 1, 2, false, true, false, le)
        }),
        Insn::StrUW => env.step(|b| {
            sem::ls_unsigned(b, rt, rn, i64::from(imm12) << 2, 4, true, false, false, le)
        }),
        Insn::LdrUW => env.step(|b| {
            sem::ls_unsigned(b, rt, rn, i64::from(imm12) << 2, 4, false, false, false, le)
        }),
        Insn::LdrswU => env
            .step(|b| sem::ls_unsigned(b, rt, rn, i64::from(imm12) << 2, 4, false, true, true, le)),
        Insn::StrUX => env.step(|b| {
            sem::ls_unsigned(b, rt, rn, i64::from(imm12) << 3, 8, true, false, false, le)
        }),
        Insn::LdrUX => env.step(|b| {
            sem::ls_unsigned(b, rt, rn, i64::from(imm12) << 3, 8, false, false, false, le)
        }),
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
            env.step(|b| sem::ls_regoff(b, rt, rn, rm, option, s_bit, 1, true, false, false, le))
        }
        Insn::LdrbReg => {
            env.step(|b| sem::ls_regoff(b, rt, rn, rm, option, s_bit, 1, false, false, false, le))
        }
        Insn::LdrsbRegX => {
            env.step(|b| sem::ls_regoff(b, rt, rn, rm, option, s_bit, 1, false, true, true, le))
        }
        Insn::LdrsbRegW => {
            env.step(|b| sem::ls_regoff(b, rt, rn, rm, option, s_bit, 1, false, true, false, le))
        }
        Insn::StrhReg => env
            .step(|b| sem::ls_regoff(b, rt, rn, rm, option, s_bit << 1, 2, true, false, false, le)),
        Insn::LdrhReg => env.step(|b| {
            sem::ls_regoff(
                b,
                rt,
                rn,
                rm,
                option,
                s_bit << 1,
                2,
                false,
                false,
                false,
                le,
            )
        }),
        Insn::LdrshRegX => env
            .step(|b| sem::ls_regoff(b, rt, rn, rm, option, s_bit << 1, 2, false, true, true, le)),
        Insn::LdrshRegW => env
            .step(|b| sem::ls_regoff(b, rt, rn, rm, option, s_bit << 1, 2, false, true, false, le)),
        Insn::StrRegW => env
            .step(|b| sem::ls_regoff(b, rt, rn, rm, option, s_bit << 2, 4, true, false, false, le)),
        Insn::LdrRegW => env.step(|b| {
            sem::ls_regoff(
                b,
                rt,
                rn,
                rm,
                option,
                s_bit << 2,
                4,
                false,
                false,
                false,
                le,
            )
        }),
        Insn::LdrswReg => env
            .step(|b| sem::ls_regoff(b, rt, rn, rm, option, s_bit << 2, 4, false, true, true, le)),
        Insn::StrRegX => env
            .step(|b| sem::ls_regoff(b, rt, rn, rm, option, s_bit << 3, 8, true, false, false, le)),
        Insn::LdrRegX => env.step(|b| {
            sem::ls_regoff(
                b,
                rt,
                rn,
                rm,
                option,
                s_bit << 3,
                8,
                false,
                false,
                false,
                le,
            )
        }),
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
        Insn::Svc => unreachable!("svc は先に振り分け済み"),
    };
    if ok.is_err() {
        return Err(unimpl(env));
    }
    // 分岐なしは次へ進める（分岐成立は step が pc を置き換える）。
    if env.backend.ctrl == Ctrl::Fallthrough {
        env.pc += 4;
    }
    Ok(())
}

/// 静的な AArch64 ELF を実行する。機械番号 183（EM_AARCH64）。
/// `sys` は `os_linux::aarch64::sys::Linux` が処理する（未実装は ENOSYS）。
/// 動的リンク・VFS・シグナルは後の段階。
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

/// `run_elf_aarch64_sel` に OS パーソナリティを差し込む形。
/// テストが syscall の結果（`sys.io` 等）を検査する用途に使う。
pub fn run_elf_aarch64_sys(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    sys: &mut polyisa_os_linux::aarch64::sys::Linux,
) -> Result<u64, String> {
    use polyisa_guest_aarch64::sem;
    use polyisa_mem::{PAGE_SIZE, Perms};

    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    if !matches!(bytes.get(4), Some(2)) {
        return Err("AArch64 は ELFCLASS64 のみ対応".to_string());
    }
    let ehdr = polyisa_loader::elf::parse_ehdr(&bytes).map_err(|e| format!("ehdr: {e:?}"))?;
    // EM_AARCH64=183。Ref: SPEC-AARCH64-ELF（AAELF64）§4.2。
    const EM_AARCH64: u16 = 183;
    if !ehdr.little {
        return Err("big-endian ELF は未対応（FEAT_BE は後の段階）".to_string());
    }
    if ehdr.machine != EM_AARCH64 {
        return Err(format!("未対応の e_machine: {}", ehdr.machine));
    }
    let phdrs =
        polyisa_loader::elf::parse_phdrs(&bytes, &ehdr).map_err(|e| format!("phdrs: {e:?}"))?;
    if polyisa_loader::elf::parse_interp(&bytes, &phdrs).is_some() {
        return Err("動的リンクは未対応".to_string());
    }
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_aarch64::CpuState>());
    let image_end = phdrs
        .iter()
        .filter(|p| p.seg_type == 1)
        .map(|p| p.vaddr + p.memsz)
        .max()
        .unwrap_or(0);
    polyisa_loader::elf::load_segments(&bytes, &phdrs, &mut env.backend.mem)
        .map_err(|e| format!("load: {e:?}"))?;
    // 初期スタックを写像する。`build_initial_stack` の返す像を置く。
    // 下方向の成長分は固定で先に確保する（ページフォルト駆動の成長は
    // 未実装。大きさはメモの保留事項を参照）。
    let top = 0x0000_7fff_fff0_0000u64;
    let mut arg_bytes = vec![path.as_bytes().to_vec()];
    for a in argv {
        arg_bytes.push(a.as_bytes().to_vec());
    }
    let (img, sp) = polyisa_os_linux::build_initial_stack(top, &arg_bytes, &[], &[(6, 0x1000)]);
    let stack_pages = 256u64;
    let base = top - stack_pages * PAGE_SIZE;
    env.backend
        .mem
        .map(VirtAddr(base), stack_pages, Perms(Perms::R.0 | Perms::W.0))
        .map_err(|e| format!("stack map: {e:?}"))?;
    env.backend
        .mem
        .write(VirtAddr(sp), &img)
        .map_err(|e| format!("stack write: {e:?}"))?;
    env.backend.set(sem::sp_ref(), sp);
    sys.exe_path = path.to_string();
    sys.init_brk(image_end);
    let feats = sel.map_or(0, |s| s.feats);
    match run_ex(&mut env, ehdr.entry, feats, sys) {
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
        let _ = polyisa_engine::run::run(&mut env, &mut sys, 3, |e| e.pc, |e, s| step_a64(e, s, 0));
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
        let _ = polyisa_engine::run::run(&mut env, &mut sys, 1, |e| e.pc, |e, s| step_a64(e, s, 0));
        assert_eq!(env.backend.get(sem::sp_ref()), 0x7010);
    }
}
