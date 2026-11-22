// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! OpenRISC の命令意味論（段階20 OR5-OR8）。
//!
//! 具体値インタプリタ（`InterpBackend`）上で動く。全命令は固定
//! 32 ビット・ビッグエンディアン。遅延スロットは `exec` の外側
//! （実行ループ）が管理し、制御転送の成立は `npc` 状態面への
//! 書き込みと戻り値 `true` で伝える（実行ループが着地点を消費する）。
//!
//! - r0 は常に 0（読み出し 0・書き込み破棄の実装選択）。
//! - `l.sys` は例外ベクタ 0xc00、`l.trap` は 0xe00 の
//!   `ExceptionKind::Trap` を上げ、OS パーソナリティに委ねる。
//! - 予約カスタム命令（l.cust1-8・lf.cust1.*）と特権専用の
//!   l.rfe は未実装として止める（Gap）。
//! - l.ld/l.sd（ORBIS64）は宣言のみの機能で、実行時は未実装。
//! Ref: SPEC-OPENRISC-1000 §5.3（ORBIS32）, §5.4（ORFPX32/64）,
//! §5.5（ORFPX64A32）, §6（例外）.

use polyisa_engine::interp::{InterpBackend, InterpExit};
use polyisa_mem::{Access, AccessKind, Align, Endian};
use polyisa_sem::{Backend, ExceptionKind, GuestException, StateRef, W8, W16, W32, W64};
use polyisa_softfloat::{F32, F64, Rm};

use crate::{CpuState, Insn, extract_ops, fpcsr_bit, spr, sr_bit};

/// l.sys の例外ベクタ。OS パーソナリティが syscall 発行点として拾う。
/// Ref: SPEC-OPENRISC-1000 §6.1 表 6-2.
pub const TRAP_SYS: u64 = 0xc00;
/// l.trap の例外ベクタ（デバッガ向けトラップ）。
pub const TRAP_TRAP: u64 = 0xe00;
/// 不正命令の例外ベクタ（報告用）。
pub const TRAP_ILL: u64 = 0x700;

const DATA_R: Access = Access {
    endian: Endian::Be,
    align: Align::Natural,
    kind: AccessKind::DataRead,
};
const DATA_W: Access = Access {
    endian: Endian::Be,
    align: Align::Natural,
    kind: AccessKind::DataWrite,
};
const ATOMIC: Access = Access {
    endian: Endian::Be,
    align: Align::Natural,
    kind: AccessKind::AtomicRw,
};

/// CPU 状態の位置たち。
#[must_use]
pub fn r_ref(i: u32) -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, r) + (i as usize) * 8)
}
#[must_use]
pub fn pc_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, pc))
}
#[must_use]
pub fn npc_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, npc))
}
#[must_use]
pub fn ppc_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, ppc))
}
#[must_use]
pub fn sr_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, sr))
}
#[must_use]
pub fn maclo_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, maclo))
}
#[must_use]
pub fn machi_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, machi))
}
#[must_use]
pub fn fpmaddlo_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, fpmaddlo))
}
#[must_use]
pub fn fpmaddhi_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, fpmaddhi))
}
#[must_use]
pub fn fpcsr_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, fpcsr))
}
#[must_use]
pub fn evbar_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, evbar))
}
#[must_use]
pub fn ttcr_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, ttcr))
}
#[must_use]
pub fn ttmr_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, ttmr))
}
#[must_use]
pub fn aecr_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, aecr))
}
#[must_use]
pub fn aesr_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, aesr))
}
#[must_use]
pub fn picmr_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, picmr))
}
#[must_use]
pub fn vr_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, vr))
}
#[must_use]
pub fn upr_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, upr))
}
#[must_use]
pub fn cpucfgr_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, cpucfgr))
}
/// 例外レジスタ拡張（EPCR:0-15, EEAR:16-31, ESR:32-47）。
#[must_use]
pub fn ex_ref(i: u32) -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, ex) + (i as usize) * 8)
}

// ---- 小さなヘルパ ----

fn rget(b: &InterpBackend, i: u64) -> u64 {
    if i == 0 {
        0
    } else {
        get_u64(b, r_ref(i as u32))
    }
}

fn rset(b: &mut InterpBackend, i: u64, v: u64) {
    if i != 0 {
        b.set(r_ref(i as u32), v & 0xffff_ffff);
    }
}

/// 状態バイト列から 64 ビット面を読む（不変借用で使える読み筋）。
fn get_u64(b: &InterpBackend, r: StateRef<W64>) -> u64 {
    let off = r.offset();
    u64::from_le_bytes(b.state[off..off + 8].try_into().expect("w64"))
}

/// SR の観測値。FO（bit15）は常に 1。
/// Ref: SPEC-OPENRISC-1000 §4.6 表 4-9.
fn sr(b: &InterpBackend) -> u64 {
    get_u64(b, sr_ref()) | (1 << sr_bit::FO)
}

fn sr_bit_set(b: &mut InterpBackend, bit: u32, v: bool) {
    let mut s = sr(b);
    if v {
        s |= 1 << bit;
    } else {
        s &= !(1 << bit);
    }
    b.set(sr_ref(), s);
}

fn flag(b: &InterpBackend) -> bool {
    sr(b) & (1 << sr_bit::F) != 0
}

/// 符号拡張（bits は元の幅）。
fn sext(v: u64, bits: u32) -> u64 {
    let sh = 64 - bits;
    (((v << sh) as i64) >> sh) as u64
}

fn trap(code: u64) -> InterpExit {
    InterpExit::Exception(GuestException {
        kind: ExceptionKind::Trap,
        code,
        addr: None,
        in_delay_slot: false,
    })
}

fn unimpl(what: &str) -> InterpExit {
    InterpExit::Unimplemented(what.to_string())
}

fn l8(b: &mut InterpBackend, a: u64) -> Result<u64, InterpExit> {
    Ok(u64::from(b.load::<W8>(a, DATA_R)?))
}
fn l16(b: &mut InterpBackend, a: u64) -> Result<u64, InterpExit> {
    Ok(u64::from(b.load::<W16>(a, DATA_R)?))
}
fn l32(b: &mut InterpBackend, a: u64) -> Result<u64, InterpExit> {
    Ok(u64::from(b.load::<W32>(a, DATA_R)?))
}
fn s8(b: &mut InterpBackend, a: u64, v: u64) -> Result<(), InterpExit> {
    b.store::<W8>(a, v as u8, DATA_W)
}
fn s16(b: &mut InterpBackend, a: u64, v: u64) -> Result<(), InterpExit> {
    b.store::<W16>(a, v as u16, DATA_W)
}
fn s32(b: &mut InterpBackend, a: u64, v: u64) -> Result<(), InterpExit> {
    b.store::<W32>(a, v as u32, DATA_W)
}

/// SPR の読み出し。未実装グループは 0 を返す（Gap）。
/// Ref: SPEC-OPENRISC-1000 §4.3 表 4-1, §4.4 表 4-2.
pub fn spr_read(b: &InterpBackend, adr: u16) -> u64 {
    use spr::*;
    match adr {
        VR => get_u64(b, vr_ref()),
        UPR => get_u64(b, upr_ref()),
        CPUCFGR => get_u64(b, cpucfgr_ref()),
        EVBAR => get_u64(b, evbar_ref()),
        AECR => get_u64(b, aecr_ref()),
        AESR => get_u64(b, aesr_ref()),
        NPC => get_u64(b, npc_ref()),
        SR => sr(b),
        PPC => get_u64(b, ppc_ref()),
        FPCSR => get_u64(b, fpcsr_ref()),
        COREID => 0,
        NUMCORES => 1,
        MACLO => get_u64(b, maclo_ref()),
        MACHI => get_u64(b, machi_ref()),
        FPMADDLO => get_u64(b, fpmaddlo_ref()),
        FPMADDHI => get_u64(b, fpmaddhi_ref()),
        TTMR => get_u64(b, ttmr_ref()),
        TTCR => get_u64(b, ttcr_ref()),
        PICMR => get_u64(b, picmr_ref()),
        PICSR => 0,
        a if (EPCR0..EPCR0 + 16).contains(&a) => get_u64(b, ex_ref((a - EPCR0) as u32)),
        a if (EEAR0..EEAR0 + 16).contains(&a) => get_u64(b, ex_ref(16 + (a - EEAR0) as u32)),
        a if (ESR0..ESR0 + 16).contains(&a) => get_u64(b, ex_ref(32 + (a - ESR0) as u32)),
        a if (GPR0..GPR0 + 32).contains(&a) => get_u64(b, r_ref((a - GPR0) as u32)),
        _ => 0,
    }
}

/// SPR の書き込み。SR はユーザ可書ビットのみ、FPCSR は全ビット、
/// 読み取り専用の構成レジスタ（VR/UPR/CPUCFGR 等）は無視する。
/// 特権 SPR への書き込み制限はユーザモデルの近似（Gap）。
pub fn spr_write(b: &mut InterpBackend, adr: u16, v: u64) {
    use spr::*;
    let v = v & 0xffff_ffff;
    match adr {
        EVBAR => b.set(evbar_ref(), v),
        AECR => b.set(aecr_ref(), v),
        AESR => b.set(aesr_ref(), v),
        NPC => b.set(npc_ref(), v),
        SR => {
            // ユーザ可書ビットのみ従う。FO は常に 1。
            let keep = sr(b) & !u64::from(sr_bit::USER_WRITABLE);
            let user = v & u64::from(sr_bit::USER_WRITABLE);
            b.set(sr_ref(), keep | user);
        }
        PPC => b.set(ppc_ref(), v),
        FPCSR => b.set(fpcsr_ref(), v),
        MACLO => b.set(maclo_ref(), v),
        MACHI => b.set(machi_ref(), v),
        FPMADDLO => b.set(fpmaddlo_ref(), v),
        FPMADDHI => b.set(fpmaddhi_ref(), v),
        TTMR => b.set(ttmr_ref(), v),
        TTCR => b.set(ttcr_ref(), v),
        PICMR => b.set(picmr_ref(), v),
        a if (EPCR0..EPCR0 + 16).contains(&a) => b.set(ex_ref((a - EPCR0) as u32), v),
        a if (EEAR0..EEAR0 + 16).contains(&a) => b.set(ex_ref(16 + (a - EEAR0) as u32), v),
        a if (ESR0..ESR0 + 16).contains(&a) => b.set(ex_ref(32 + (a - ESR0) as u32), v),
        a if (GPR0..GPR0 + 32).contains(&a) => rset(b, u64::from(a - GPR0), v),
        _ => {}
    }
}

/// 加算と CY/OV 旗（l.add/l.addc/l.addi/l.addic）。
/// Ref: SPEC-OPENRISC-1000 §5.3（l.add）.
fn add_flags(b: &mut InterpBackend, x: u64, y: u64, c: bool) -> u64 {
    let (sum, cout) = if c {
        let (s, c1) = (x as u32).overflowing_add(y as u32);
        let (s, c2) = s.overflowing_add(1);
        (s, c1 || c2)
    } else {
        (x as u32).overflowing_add(y as u32)
    };
    let xs = x as u32 as i32;
    let ys = y as u32 as i32;
    let (s0, ov0) = xs.overflowing_add(ys);
    let (ss, ov1) = if c { s0.overflowing_add(1) } else { (s0, ov0) };
    let _ = ss;
    sr_bit_set(b, sr_bit::CY, cout);
    sr_bit_set(b, sr_bit::OV, ov0 || ov1);
    u64::from(sum)
}

/// 減算と CY/OV 旗（l.sub）。CY は借り入れ。
/// Ref: SPEC-OPENRISC-1000 §5.3（l.sub）.
fn sub_flags(b: &mut InterpBackend, x: u64, y: u64) -> u64 {
    let (d, borrow) = (x as u32).overflowing_sub(y as u32);
    let ov = (x as u32 as i32).overflowing_sub(y as u32 as i32).1;
    sr_bit_set(b, sr_bit::CY, borrow);
    sr_bit_set(b, sr_bit::OV, ov);
    u64::from(d)
}

fn set_f(b: &mut InterpBackend, v: bool) {
    sr_bit_set(b, sr_bit::F, v);
}

/// 制御転送の成立を実行ループへ伝える（npc 状態面に着地点を書く）。
fn take(b: &mut InterpBackend, target: u64) -> Result<bool, InterpExit> {
    b.set(npc_ref(), target & 0xffff_ffff);
    Ok(true)
}

/// リンク先。遅延スロット構成では遅延命令 +4（=pc+8）、
/// 無遅延構成ではジャンプ命令 +4（=pc+4）。
/// Ref: SPEC-OPENRISC-1000 §5.3（l.jal/l.jalr）.
fn link(pc: u64, dslot: bool) -> u64 {
    if dslot {
        pc.wrapping_add(8) & 0xffff_ffff
    } else {
        pc.wrapping_add(4) & 0xffff_ffff
    }
}

// ---- FP ----

/// softfloat の例外フラグを FPCSR に積む。
/// FP_NX→IXF, FP_UF→UNF, FP_OF→OVF, FP_DZ→DZF, FP_NV→IVF。
/// Ref: SPEC-OPENRISC-1000 §4.12 表 4-8; SPEC-IEEE754.
fn fp_merge_flags(b: &mut InterpBackend, flags: u8) {
    if flags == 0 {
        return;
    }
    let mut c = get_u64(b, fpcsr_ref()) as u32;
    if flags & polyisa_softfloat::FP_NX != 0 {
        c |= 1 << fpcsr_bit::IXF;
    }
    if flags & polyisa_softfloat::FP_UF != 0 {
        c |= 1 << fpcsr_bit::UNF;
    }
    if flags & polyisa_softfloat::FP_OF != 0 {
        c |= 1 << fpcsr_bit::OVF;
    }
    if flags & polyisa_softfloat::FP_DZ != 0 {
        c |= 1 << fpcsr_bit::DZF;
    }
    if flags & polyisa_softfloat::FP_NV != 0 {
        c |= 1 << fpcsr_bit::IVF;
    }
    b.set(fpcsr_ref(), u64::from(c));
}

/// FPCSR[RM] を softfloat の Rm に写す。
/// 0=RNE,1=RTZ,2=RUP(+∞),3=RDN(-∞)。spec 表 4-8 の
/// 順序（to +/-inf）に注意: softfloat の Rdn/Rup と入れ替わる。
/// Ref: SPEC-OPENRISC-1000 §4.12 表 4-8.
fn fp_rm(b: &InterpBackend) -> Rm {
    match (get_u64(b, fpcsr_ref()) as u32 >> fpcsr_bit::RM_SHIFT) & 3 {
        1 => Rm::Rtz,
        2 => Rm::Rup,
        3 => Rm::Rdn,
        _ => Rm::Rne,
    }
}

fn f32_of(v: u64) -> F32 {
    F32::from_bits(v)
}

fn f64_of(hi: u64, lo: u64) -> F64 {
    F64::from_bits((hi << 32) | (lo & 0xffff_ffff))
}

/// 比較の結果フラグ。unordered（NaN を含む）か、通常比較か。
/// sfu* は unordered でも立つ。lf.sf*.s/.d 共通。
fn fp_cmp(cond: FpCond, unord: bool, eq: bool, lt: bool) -> bool {
    match cond {
        FpCond::Ueq => unord || eq,
        FpCond::Une => unord || !eq,
        FpCond::Ugt => unord || (!eq && !lt),
        FpCond::Uge => unord || !lt,
        FpCond::Ult => unord || lt,
        FpCond::Ule => unord || (lt || eq),
        FpCond::Un => unord,
        FpCond::Eq => !unord && eq,
        FpCond::Ne => !unord && !eq,
        FpCond::Gt => !unord && !eq && !lt,
        FpCond::Ge => !unord && !lt,
        FpCond::Lt => !unord && lt,
        FpCond::Le => !unord && (lt || eq),
    }
}

#[derive(Clone, Copy)]
enum FpCond {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    Ueq,
    Une,
    Ugt,
    Uge,
    Ult,
    Ule,
    Un,
}

/// lf.sf*.s: rA,rB を単精度として比較し SR[F] を書く。
fn fpcmp_s(b: &mut InterpBackend, a: u64, c: u64, cond: FpCond) {
    let (x, y) = (f32_of(a), f32_of(c));
    let unord = x.is_nan() || y.is_nan();
    let (eq, fe) = x.eq(y);
    let (lt, fl) = x.lt(y);
    fp_merge_flags(b, fe | fl);
    set_f(b, fp_cmp(cond, unord, eq, lt));
}

/// lf.sf*.d: ペア {a,a2} {c,c2} の倍精度比較。
fn fpcmp_d(b: &mut InterpBackend, a: u64, a2: u64, c: u64, c2: u64, cond: FpCond) {
    let (x, y) = (
        f64_of(rget(b, a), rget(b, a2)),
        f64_of(rget(b, c), rget(b, c2)),
    );
    let unord = x.is_nan() || y.is_nan();
    let (eq, fe) = x.eq(y);
    let (lt, fl) = x.lt(y);
    fp_merge_flags(b, fe | fl);
    set_f(b, fp_cmp(cond, unord, eq, lt));
}

/// MAC アキュムレータの 64 ビット加減算。
/// Ref: SPEC-OPENRISC-1000 §5.3（l.mac/l.msb/l.macrc）.
fn mac_add(b: &mut InterpBackend, prod: u64, sub: bool, cy_on_add: bool) {
    let acc = (get_u64(b, machi_ref()) << 32) | get_u64(b, maclo_ref());
    let acc = if sub {
        acc.wrapping_sub(prod)
    } else {
        acc.wrapping_add(prod)
    };
    b.set(maclo_ref(), acc & 0xffff_ffff);
    b.set(machi_ref(), (acc >> 32) & 0xffff_ffff);
    if cy_on_add && !sub && acc < prod {
        sr_bit_set(b, sr_bit::CY, true);
    }
}

/// 1 命令ぶんの意味論。`pc` はこの命令の番地、`dslot` は
/// CPUCFGR[ND]=0 の遅延スロット構成か。戻り値 `Ok(true)` は
/// 制御転送が成立し `npc` 状態面に着地点を書いたこと。
// Ref: SPEC-OPENRISC-1000 §5.3-5.5.
#[allow(clippy::too_many_lines)]
pub fn exec(
    b: &mut InterpBackend,
    insn: Insn,
    word: u32,
    pc: u64,
    dslot: bool,
) -> Result<bool, InterpExit> {
    let ops = extract_ops(insn, u128::from(word));
    let g = |i: usize| ops.get(i).copied().unwrap_or(0);
    match insn {
        // ---- 制御転送 ----
        Insn::LJ | Insn::LJal => {
            // EA = exts(N << 2) + JumpInsnAddr。Ref: §5.3.
            let t = pc.wrapping_add(sext(g(0), 26) << 2) & 0xffff_ffff;
            if insn == Insn::LJal {
                rset(b, 9, link(pc, dslot));
            }
            take(b, t)
        }
        Insn::LBnf => {
            if !flag(b) {
                take(b, pc.wrapping_add(sext(g(0), 26) << 2) & 0xffff_ffff)
            } else {
                Ok(false)
            }
        }
        Insn::LBf => {
            if flag(b) {
                take(b, pc.wrapping_add(sext(g(0), 26) << 2) & 0xffff_ffff)
            } else {
                Ok(false)
            }
        }
        Insn::LJr => {
            let t = rget(b, g(0));
            take(b, t)
        }
        Insn::LJalr => {
            let t = rget(b, g(0));
            rset(b, 9, link(pc, dslot));
            take(b, t)
        }
        Insn::LAdrp => {
            // rD = exts(Imm[18:0] << 13) + (InstAddr & -8192)。§5.2.
            let t = (pc & !0x1fff_u64).wrapping_add(sext(g(1) & 0x7ffff, 19) << 13);
            rset(b, g(0), t & 0xffff_ffff);
            Ok(false)
        }

        // ---- 定数形成 ----
        Insn::LNop => Ok(false),
        Insn::LMovhi => {
            rset(b, g(0), g(1) << 16);
            Ok(false)
        }
        Insn::LMacrc => {
            // rD = MACHI:MACLO の下位 32 ビット（実装は OR1K の
            // 慣例に従い MACLO を返す）しアキュムレータを 0 に。
            // Ref: SPEC-OPENRISC-1000 §5.3（l.macrc）.
            let v = get_u64(b, maclo_ref());
            rset(b, g(0), v);
            b.set(maclo_ref(), 0);
            b.set(machi_ref(), 0);
            Ok(false)
        }

        // ---- システム・同期 ----
        Insn::LSys => Err(trap(TRAP_SYS)),
        Insn::LTrap => Err(trap(TRAP_TRAP)),
        Insn::LMsync | Insn::LPsync | Insn::LCsync => Ok(false),
        Insn::LRfe => Err(unimpl("l.rfe（特権復帰。ユーザモデルでは未実装）")),
        Insn::LCust1
        | Insn::LCust2
        | Insn::LCust3
        | Insn::LCust4
        | Insn::LCust5
        | Insn::LCust6
        | Insn::LCust7
        | Insn::LCust8
        | Insn::LfCust1S
        | Insn::LfCust1D => Err(unimpl("カスタム命令（実装定義の予約）")),

        // ---- ロード ----
        Insn::LLf | Insn::LLwz => {
            let a = rget(b, g(1)).wrapping_add(sext(g(2), 16)) & 0xffff_ffff;
            let v = l32(b, a)?;
            rset(b, g(0), v);
            Ok(false)
        }
        Insn::LLws => {
            let a = rget(b, g(1)).wrapping_add(sext(g(2), 16)) & 0xffff_ffff;
            let v = l32(b, a)?;
            rset(b, g(0), sext(v, 32));
            Ok(false)
        }
        Insn::LLbz => {
            let a = rget(b, g(1)).wrapping_add(sext(g(2), 16)) & 0xffff_ffff;
            let v = l8(b, a)?;
            rset(b, g(0), v);
            Ok(false)
        }
        Insn::LLbs => {
            let a = rget(b, g(1)).wrapping_add(sext(g(2), 16)) & 0xffff_ffff;
            let v = l8(b, a)?;
            rset(b, g(0), sext(v, 8));
            Ok(false)
        }
        Insn::LLhz => {
            let a = rget(b, g(1)).wrapping_add(sext(g(2), 16)) & 0xffff_ffff;
            let v = l16(b, a)?;
            rset(b, g(0), v);
            Ok(false)
        }
        Insn::LLhs => {
            let a = rget(b, g(1)).wrapping_add(sext(g(2), 16)) & 0xffff_ffff;
            let v = l16(b, a)?;
            rset(b, g(0), sext(v, 16));
            Ok(false)
        }
        Insn::LLwa => {
            let a = rget(b, g(1)).wrapping_add(sext(g(2), 16)) & 0xffff_ffff;
            let v = u64::from(b.load_reserved::<W32>(a, ATOMIC)?);
            rset(b, g(0), v);
            Ok(false)
        }
        Insn::LLd => Err(unimpl("l.ld（ORBIS64。対象 ABI は 32 ビット）")),

        // ---- ストア ----
        Insn::LSw => {
            let a = rget(b, g(1)).wrapping_add(sext(g(0), 16)) & 0xffff_ffff;
            let v = rget(b, g(2));
            s32(b, a, v)?;
            Ok(false)
        }
        Insn::LSb => {
            let a = rget(b, g(1)).wrapping_add(sext(g(0), 16)) & 0xffff_ffff;
            let v = rget(b, g(2));
            s8(b, a, v)?;
            Ok(false)
        }
        Insn::LSh => {
            let a = rget(b, g(1)).wrapping_add(sext(g(0), 16)) & 0xffff_ffff;
            let v = rget(b, g(2));
            s16(b, a, v)?;
            Ok(false)
        }
        Insn::LSwa => {
            let a = rget(b, g(1)).wrapping_add(sext(g(0), 16)) & 0xffff_ffff;
            let v = rget(b, g(2)) as u32;
            let ok = b.store_conditional::<W32>(a, v, ATOMIC)?;
            set_f(b, ok);
            Ok(false)
        }
        Insn::LSd => Err(unimpl("l.sd（ORBIS64。対象 ABI は 32 ビット）")),

        // ---- 即値演算 ----
        Insn::LAddi | Insn::LAddic => {
            let x = rget(b, g(1));
            let y = sext(g(2), 16);
            let v = add_flags(
                b,
                x,
                y,
                insn == Insn::LAddic && sr(b) & (1 << sr_bit::CY) != 0,
            );
            rset(b, g(0), v);
            Ok(false)
        }
        Insn::LAndi => {
            rset(b, g(0), rget(b, g(1)) & (g(2) & 0xffff));
            Ok(false)
        }
        Insn::LOri => {
            rset(b, g(0), rget(b, g(1)) | (g(2) & 0xffff));
            Ok(false)
        }
        Insn::LXori => {
            rset(b, g(0), rget(b, g(1)) ^ sext(g(2), 16));
            Ok(false)
        }
        Insn::LMuli => {
            let x = rget(b, g(1)) as u32 as i32 as i64;
            let y = sext(g(2), 16) as i64;
            let p = x.wrapping_mul(y);
            // OV は 32 ビット符号積の桁溢れ。Ref: §5.3（l.muli）.
            sr_bit_set(b, sr_bit::OV, p != (p as i32) as i64);
            rset(b, g(0), p as u64 & 0xffff_ffff);
            Ok(false)
        }
        Insn::LMfspr => {
            let a = rget(b, g(1)) as u16;
            let k = (g(2) & 0xffff) as u16;
            let v = spr_read(b, a | k);
            rset(b, g(0), v);
            Ok(false)
        }
        Insn::LMtspr => {
            let a = rget(b, g(0)) as u16;
            let k = (g(2) & 0xffff) as u16;
            let v = rget(b, g(1));
            spr_write(b, a | k, v);
            Ok(false)
        }

        // ---- 即値シフト ----
        Insn::LSlli => {
            rset(
                b,
                g(0),
                (rget(b, g(1)) as u32).wrapping_shl(g(2) as u32) as u64,
            );
            Ok(false)
        }
        Insn::LSrli => {
            rset(
                b,
                g(0),
                (rget(b, g(1)) as u32).wrapping_shr(g(2) as u32) as u64,
            );
            Ok(false)
        }
        Insn::LSrai => {
            rset(
                b,
                g(0),
                (((rget(b, g(1)) as u32) as i32).wrapping_shr(g(2) as u32)) as u32 as u64,
            );
            Ok(false)
        }
        Insn::LRori => {
            rset(
                b,
                g(0),
                (rget(b, g(1)) as u32).rotate_right(g(2) as u32 & 31) as u64,
            );
            Ok(false)
        }

        // ---- 即値比較 ----
        Insn::LSfeqi
        | Insn::LSfnei
        | Insn::LSfgtui
        | Insn::LSfgeui
        | Insn::LSfltui
        | Insn::LSfleui
        | Insn::LSfgtsi
        | Insn::LSfgesi
        | Insn::LSfltsi
        | Insn::LSflesi => {
            let x = rget(b, g(0));
            let y = sext(g(1), 16);
            set_f(b, int_cmp(insn, x, y));
            Ok(false)
        }

        // ---- MAC ----
        Insn::LMac | Insn::LMsb | Insn::LMacu | Insn::LMsbu => {
            let x = rget(b, g(0));
            let y = rget(b, g(1));
            let signed = matches!(insn, Insn::LMac | Insn::LMsb);
            let prod = if signed {
                ((x as u32 as i32 as i64) * (y as u32 as i32 as i64)) as u64
            } else {
                (x as u32 as u64) * (y as u32 as u64)
            };
            let sub = matches!(insn, Insn::LMsb | Insn::LMsbu);
            // l.macu は加算桁溢れで SR[CY]。符号付きは OV を
            // 立てない実装選択（spec 本文は曖昧。Gap）。
            mac_add(b, prod, sub, insn == Insn::LMacu);
            Ok(false)
        }
        Insn::LMaci => {
            let x = rget(b, g(0));
            let y = sext(g(1), 16);
            let prod = ((x as u32 as i32 as i64) * (y as i64)) as u64;
            mac_add(b, prod, false, false);
            Ok(false)
        }
        Insn::LMuld | Insn::LMuldu => {
            let x = rget(b, g(0));
            let y = rget(b, g(1));
            let prod = if insn == Insn::LMuld {
                ((x as u32 as i32 as i64) * (y as u32 as i32 as i64)) as u64
            } else {
                (x as u32 as u64) * (y as u32 as u64)
            };
            b.set(maclo_ref(), prod & 0xffff_ffff);
            b.set(machi_ref(), (prod >> 32) & 0xffff_ffff);
            Ok(false)
        }

        // ---- 0x38 主演算群 ----
        Insn::LExths => {
            rset(b, g(0), sext(rget(b, g(1)) & 0xffff, 16));
            Ok(false)
        }
        Insn::LExtws => {
            rset(b, g(0), rget(b, g(1)) & 0xffff_ffff);
            Ok(false)
        }
        Insn::LExtbs => {
            rset(b, g(0), sext(rget(b, g(1)) & 0xff, 8));
            Ok(false)
        }
        Insn::LExtwz => {
            rset(b, g(0), rget(b, g(1)) & 0xffff_ffff);
            Ok(false)
        }
        Insn::LExthz => {
            rset(b, g(0), rget(b, g(1)) & 0xffff);
            Ok(false)
        }
        Insn::LExtbz => {
            rset(b, g(0), rget(b, g(1)) & 0xff);
            Ok(false)
        }
        Insn::LFf1 | Insn::LFl1 => {
            let v = rget(b, g(1)) as u32;
            // ff1 は最下位の 1 の位置（1 起算、なければ 0）、
            // fl1 は最上位の 1 の位置。Ref: §5.3.
            let r = if insn == Insn::LFf1 {
                if v == 0 { 0 } else { v.trailing_zeros() + 1 }
            } else if v == 0 {
                0
            } else {
                32 - v.leading_zeros()
            };
            rset(b, g(0), u64::from(r));
            Ok(false)
        }
        Insn::LAdd | Insn::LAddc => {
            let c = insn == Insn::LAddc && sr(b) & (1 << sr_bit::CY) != 0;
            let v = add_flags(b, rget(b, g(1)), rget(b, g(2)), c);
            rset(b, g(0), v);
            Ok(false)
        }
        Insn::LSub => {
            let v = sub_flags(b, rget(b, g(1)), rget(b, g(2)));
            rset(b, g(0), v);
            Ok(false)
        }
        Insn::LAnd => {
            rset(b, g(0), rget(b, g(1)) & rget(b, g(2)));
            Ok(false)
        }
        Insn::LOr => {
            rset(b, g(0), rget(b, g(1)) | rget(b, g(2)));
            Ok(false)
        }
        Insn::LXor => {
            rset(b, g(0), rget(b, g(1)) ^ rget(b, g(2)));
            Ok(false)
        }
        Insn::LCmov => {
            let v = if flag(b) {
                rget(b, g(1))
            } else {
                rget(b, g(2))
            };
            rset(b, g(0), v);
            Ok(false)
        }
        Insn::LSll => {
            let n = rget(b, g(2)) as u32 & 31;
            rset(b, g(0), (rget(b, g(1)) as u32).wrapping_shl(n) as u64);
            Ok(false)
        }
        Insn::LSrl => {
            let n = rget(b, g(2)) as u32 & 31;
            rset(b, g(0), (rget(b, g(1)) as u32).wrapping_shr(n) as u64);
            Ok(false)
        }
        Insn::LSra => {
            let n = rget(b, g(2)) as u32 & 31;
            rset(
                b,
                g(0),
                (((rget(b, g(1)) as u32) as i32).wrapping_shr(n)) as u32 as u64,
            );
            Ok(false)
        }
        Insn::LRor => {
            let n = rget(b, g(2)) as u32 & 31;
            rset(b, g(0), (rget(b, g(1)) as u32).rotate_right(n) as u64);
            Ok(false)
        }
        Insn::LMul => {
            let x = rget(b, g(1)) as u32 as i32 as i64;
            let y = rget(b, g(2)) as u32 as i32 as i64;
            let p = x.wrapping_mul(y);
            // 32 ビット符号積の桁溢れで OV。Ref: §5.3（l.mul）.
            sr_bit_set(b, sr_bit::OV, p != (p as i32) as i64);
            rset(b, g(0), p as u64 & 0xffff_ffff);
            Ok(false)
        }
        Insn::LDiv => {
            let x = rget(b, g(1)) as u32 as i32;
            let y = rget(b, g(2)) as u32 as i32;
            if y == 0 {
                // 0 除算: OV を立て宛先は不定（ここでは据え置き）。
                // Ref: §5.3（l.div）.
                sr_bit_set(b, sr_bit::OV, true);
            } else {
                let (q, ov) = x.overflowing_div(y);
                sr_bit_set(b, sr_bit::OV, ov);
                sr_bit_set(b, sr_bit::CY, false);
                if !ov {
                    rset(b, g(0), q as u32 as u64);
                }
            }
            Ok(false)
        }
        Insn::LDivu => {
            let x = rget(b, g(1)) as u32;
            let y = rget(b, g(2)) as u32;
            match x.checked_div(y) {
                Some(q) => {
                    sr_bit_set(b, sr_bit::CY, false);
                    rset(b, g(0), u64::from(q));
                }
                None => sr_bit_set(b, sr_bit::CY, true),
            }
            Ok(false)
        }
        Insn::LMulu => {
            let p = (rget(b, g(1)) as u32 as u64) * (rget(b, g(2)) as u32 as u64);
            sr_bit_set(b, sr_bit::CY, p >> 32 != 0);
            rset(b, g(0), p & 0xffff_ffff);
            Ok(false)
        }

        // ---- レジスタ比較 ----
        Insn::LSfeq
        | Insn::LSfne
        | Insn::LSfgtu
        | Insn::LSfgeu
        | Insn::LSfltu
        | Insn::LSfleu
        | Insn::LSfgts
        | Insn::LSfges
        | Insn::LSflts
        | Insn::LSfles => {
            let x = rget(b, g(0));
            let y = rget(b, g(1));
            set_f(b, int_cmp(insn, x, y));
            Ok(false)
        }

        // ---- ORFPX32 ----
        Insn::LfAddS | Insn::LfSubS | Insn::LfMulS | Insn::LfDivS => {
            let (x, y) = (f32_of(rget(b, g(1))), f32_of(rget(b, g(2))));
            let rm = fp_rm(b);
            let (v, f) = match insn {
                Insn::LfAddS => x.add_rm(y, rm),
                Insn::LfSubS => x.sub_rm(y, rm),
                Insn::LfMulS => x.mul_rm(y, rm),
                _ => x.div_rm(y, rm),
            };
            fp_merge_flags(b, f);
            rset(b, g(0), v.bits());
            Ok(false)
        }
        Insn::LfItofS => {
            let (v, f) = F32::from_i64(rget(b, g(1)) as u32 as i32 as i64, fp_rm(b));
            fp_merge_flags(b, f);
            rset(b, g(0), v.bits());
            Ok(false)
        }
        Insn::LfFtoiS => {
            let (v, f) = f32_of(rget(b, g(1))).to_i32(fp_rm(b));
            fp_merge_flags(b, f);
            rset(b, g(0), v as u32 as u64);
            Ok(false)
        }
        Insn::LfMaddS => {
            let (x, y) = (f32_of(rget(b, g(0))), f32_of(rget(b, g(1))));
            let acc = f64_of(get_u64(b, fpmaddhi_ref()), get_u64(b, fpmaddlo_ref()));
            let (p, f0) = x.mul_rm(y, fp_rm(b));
            let (v, f1) = p.to_f64(Rm::Rne).0.add_rm(acc, fp_rm(b));
            fp_merge_flags(b, f0 | f1);
            let bits = v.bits();
            b.set(fpmaddhi_ref(), bits >> 32);
            b.set(fpmaddlo_ref(), bits & 0xffff_ffff);
            Ok(false)
        }
        Insn::LfSfeqS => {
            fpcmp_s(b, rget(b, g(0)), rget(b, g(1)), FpCond::Eq);
            Ok(false)
        }
        Insn::LfSfneS => {
            fpcmp_s(b, rget(b, g(0)), rget(b, g(1)), FpCond::Ne);
            Ok(false)
        }
        Insn::LfSfgtS => {
            fpcmp_s(b, rget(b, g(0)), rget(b, g(1)), FpCond::Gt);
            Ok(false)
        }
        Insn::LfSfgeS => {
            fpcmp_s(b, rget(b, g(0)), rget(b, g(1)), FpCond::Ge);
            Ok(false)
        }
        Insn::LfSfltS => {
            fpcmp_s(b, rget(b, g(0)), rget(b, g(1)), FpCond::Lt);
            Ok(false)
        }
        Insn::LfSfleS => {
            fpcmp_s(b, rget(b, g(0)), rget(b, g(1)), FpCond::Le);
            Ok(false)
        }
        Insn::LfSfueqS => {
            fpcmp_s(b, rget(b, g(0)), rget(b, g(1)), FpCond::Ueq);
            Ok(false)
        }
        Insn::LfSfuneS => {
            fpcmp_s(b, rget(b, g(0)), rget(b, g(1)), FpCond::Une);
            Ok(false)
        }
        Insn::LfSfugtS => {
            fpcmp_s(b, rget(b, g(0)), rget(b, g(1)), FpCond::Ugt);
            Ok(false)
        }
        Insn::LfSfugeS => {
            fpcmp_s(b, rget(b, g(0)), rget(b, g(1)), FpCond::Uge);
            Ok(false)
        }
        Insn::LfSfultS => {
            fpcmp_s(b, rget(b, g(0)), rget(b, g(1)), FpCond::Ult);
            Ok(false)
        }
        Insn::LfSfuleS => {
            fpcmp_s(b, rget(b, g(0)), rget(b, g(1)), FpCond::Ule);
            Ok(false)
        }
        Insn::LfSfunS => {
            fpcmp_s(b, rget(b, g(0)), rget(b, g(1)), FpCond::Un);
            Ok(false)
        }

        // ---- ORFPX64A32 ----
        Insn::LfAddD | Insn::LfSubD | Insn::LfMulD | Insn::LfDivD => {
            let oo = g(3);
            let (a2, b2, d2) = pair_offs(oo);
            let x = f64_of(rget(b, g(1)), rget(b, g(1) + a2));
            let y = f64_of(rget(b, g(2)), rget(b, g(2) + b2));
            let rm = fp_rm(b);
            let (v, f) = match insn {
                Insn::LfAddD => x.add_rm(y, rm),
                Insn::LfSubD => x.sub_rm(y, rm),
                Insn::LfMulD => x.mul_rm(y, rm),
                _ => x.div_rm(y, rm),
            };
            fp_merge_flags(b, f);
            let bits = v.bits();
            rset(b, g(0), bits >> 32);
            rset(b, g(0) + d2, bits & 0xffff_ffff);
            Ok(false)
        }
        Insn::LfItofD => {
            // {rD1,rD2} ← itof64({rA1,rA2})。
            let oo = g(2);
            let a2 = if oo & 2 != 0 { 2 } else { 1 };
            let d2 = if oo & 4 != 0 { 2 } else { 1 };
            let i = (rget(b, g(1)) << 32) | rget(b, g(1) + a2);
            let (v, f) = F64::from_i64(i as i64, fp_rm(b));
            fp_merge_flags(b, f);
            let bits = v.bits();
            rset(b, g(0), bits >> 32);
            rset(b, g(0) + d2, bits & 0xffff_ffff);
            Ok(false)
        }
        Insn::LfFtoiD => {
            let oo = g(2);
            let a2 = if oo & 2 != 0 { 2 } else { 1 };
            let d2 = if oo & 4 != 0 { 2 } else { 1 };
            let x = f64_of(rget(b, g(1)), rget(b, g(1) + a2));
            let (v, f) = x.to_i64(fp_rm(b));
            fp_merge_flags(b, f);
            let u = v as u64;
            rset(b, g(0), u >> 32);
            rset(b, g(0) + d2, u & 0xffff_ffff);
            Ok(false)
        }
        Insn::LfMaddD => {
            let oo = g(2);
            let (a2, b2, _) = pair_offs(oo);
            let x = f64_of(rget(b, g(0)), rget(b, g(0) + a2));
            let y = f64_of(rget(b, g(1)), rget(b, g(1) + b2));
            let acc = f64_of(get_u64(b, fpmaddhi_ref()), get_u64(b, fpmaddlo_ref()));
            let (p, f0) = x.mul_rm(y, fp_rm(b));
            let (v, f1) = p.add_rm(acc, fp_rm(b));
            fp_merge_flags(b, f0 | f1);
            let bits = v.bits();
            b.set(fpmaddhi_ref(), bits >> 32);
            b.set(fpmaddlo_ref(), bits & 0xffff_ffff);
            Ok(false)
        }
        Insn::LfSfeqD
        | Insn::LfSfneD
        | Insn::LfSfgtD
        | Insn::LfSfgeD
        | Insn::LfSfltD
        | Insn::LfSfleD
        | Insn::LfSfueqD
        | Insn::LfSfuneD
        | Insn::LfSfugtD
        | Insn::LfSfugeD
        | Insn::LfSfultD
        | Insn::LfSfuleD
        | Insn::LfSfunD => {
            let oo = g(2);
            let a2 = if oo & 2 != 0 { 2 } else { 1 };
            let b2 = if oo & 1 != 0 { 2 } else { 1 };
            let cond = match insn {
                Insn::LfSfeqD => FpCond::Eq,
                Insn::LfSfneD => FpCond::Ne,
                Insn::LfSfgtD => FpCond::Gt,
                Insn::LfSfgeD => FpCond::Ge,
                Insn::LfSfltD => FpCond::Lt,
                Insn::LfSfleD => FpCond::Le,
                Insn::LfSfueqD => FpCond::Ueq,
                Insn::LfSfuneD => FpCond::Une,
                Insn::LfSfugtD => FpCond::Ugt,
                Insn::LfSfugeD => FpCond::Uge,
                Insn::LfSfultD => FpCond::Ult,
                Insn::LfSfuleD => FpCond::Ule,
                _ => FpCond::Un,
            };
            fpcmp_d(b, g(0), g(0) + a2, g(1), g(1) + b2, cond);
            Ok(false)
        }
        Insn::LfStodD => {
            // {rD1,rD2} ← stod(rA)。oo bit10 が D2 オフセット。
            let d2 = if g(2) & 4 != 0 { 2 } else { 1 };
            let (v, f) = f32_of(rget(b, g(1))).to_f64(fp_rm(b));
            fp_merge_flags(b, f);
            let bits = v.bits();
            rset(b, g(0), bits >> 32);
            rset(b, g(0) + d2, bits & 0xffff_ffff);
            Ok(false)
        }
        Insn::LfDtosD => {
            // rD ← dtos({rA1,rA2})。oo bit9 が A2 オフセット。
            let a2 = if g(2) & 2 != 0 { 2 } else { 1 };
            let x = f64_of(rget(b, g(1)), rget(b, g(1) + a2));
            let (v, f) = x.to_f32(fp_rm(b));
            fp_merge_flags(b, f);
            rset(b, g(0), v.bits());
            Ok(false)
        }
    }
}

/// oo3 の [10]=D2,[9]=A2,[8]=B2 から +2/+1 のオフセットを作る。
/// 戻り値は (a2, b2, d2)。Ref: SPEC-OPENRISC-1000 §5.5.
fn pair_offs(oo: u64) -> (u64, u64, u64) {
    let a2 = if oo & 2 != 0 { 2 } else { 1 };
    let b2 = if oo & 1 != 0 { 2 } else { 1 };
    let d2 = if oo & 4 != 0 { 2 } else { 1 };
    (a2, b2, d2)
}

/// l.sf*/l.sf*i の条件評価。x,y は 32 ビット値。
fn int_cmp(insn: Insn, x: u64, y: u64) -> bool {
    use Insn::*;
    let (xu, yu) = (x as u32, y as u32);
    let (xs, ys) = (xu as i32, yu as i32);
    match insn {
        LSfeq | LSfeqi => xu == yu,
        LSfne | LSfnei => xu != yu,
        LSfgtu | LSfgtui => xu > yu,
        LSfgeu | LSfgeui => xu >= yu,
        LSfltu | LSfltui => xu < yu,
        LSfleu | LSfleui => xu <= yu,
        LSfgts | LSfgtsi => xs > ys,
        LSfges | LSfgesi => xs >= ys,
        LSflts | LSfltsi => xs < ys,
        LSfles | LSflesi => xs <= ys,
        _ => false,
    }
}
