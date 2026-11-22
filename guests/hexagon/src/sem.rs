// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Hexagon の命令意味論。
//!
//! 具体値インタプリタ（`InterpBackend`）上で動く。HX4 は代表語彙
//! （nop・add/mov・load/store・jump/call/jumpr/callr・制御レジスタ
//! 転送・cmp 系・trap0）と全 duplex subinsn の意味論を持つ
//! （frame 系の deallocframe/dealloc_return/allocframe は HX7）。
//! 書き込みはパケット未確定域（pkt_*）に溜め、フェッチ層が
//! パケット終端で `commit` する（`.new` オペランドはこの一時値を
//! `r_new`/`p_new` で読む）。
//! Ref: SPEC-HEXAGON-PRM (V79).

use polyisa_engine::interp::{Ctrl, InterpBackend, InterpExit};
use polyisa_mem::{Access, AccessKind, Align, Endian};
use polyisa_sem::{Backend as _, StateRef, W8, W16, W32, W64};

use crate::{CpuState, Insn, cnum, extract_ops, packet};

/// `handle_trap` に渡る内部番号。trap0 の即値は 0-63 なので、
/// ぶつからない値を不正命令用に取る。
pub const TRAP_ILL: u64 = u64::MAX;

fn trap(code: u64) -> InterpExit {
    InterpExit::Exception(polyisa_sem::GuestException {
        kind: polyisa_sem::ExceptionKind::Trap,
        code,
        addr: None,
        in_delay_slot: false,
    })
}

/// 符号拡張（`bits` は元の幅）。
fn sext(v: u64, bits: u32) -> u32 {
    let sh = 64 - bits;
    (((v << sh) as i64) >> sh) as u32
}

/// データアクセス属性。整数の load/store は自然整列を要求する
/// （違反は例外）。
/// Ref: SPEC-HEXAGON-PRM (V79) memory access.
const DRD: Access = Access {
    endian: Endian::Le,
    align: Align::Natural,
    kind: AccessKind::DataRead,
};
const DWR: Access = Access {
    endian: Endian::Le,
    align: Align::Natural,
    kind: AccessKind::DataWrite,
};

fn get32(b: &InterpBackend, r: StateRef<W32>) -> u32 {
    let off = r.offset();
    u32::from_le_bytes(b.state[off..off + 4].try_into().expect("w32"))
}

fn set32(b: &mut InterpBackend, r: StateRef<W32>, v: u32) {
    let off = r.offset();
    b.state[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// 汎用レジスタ r_i の状態面。
#[must_use]
pub fn r_ref(i: u32) -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, r) + (i as usize) * 4)
}

/// 汎用レジスタ r_i の値（確定済み）。
#[must_use]
pub fn r_get(b: &InterpBackend, i: u32) -> u32 {
    get32(b, r_ref(i))
}

/// 汎用レジスタ r_i への代入（確定済み値の書き込み）。
pub fn r_set(b: &mut InterpBackend, i: u32, v: u32) {
    set32(b, r_ref(i), v);
}

/// 述語レジスタ P3:0 の面。
#[must_use]
pub fn p_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, p))
}

/// 述語レジスタ p_i の 8 ビット値。
#[must_use]
pub fn p_get(b: &InterpBackend, i: u32) -> u8 {
    (get32(b, p_ref()) >> (i * 8)) as u8
}

/// 述語 p_i への 8 ビット値の代入。
pub fn p_set(b: &mut InterpBackend, i: u32, v: u8) {
    let p = (get32(b, p_ref()) & !(0xff << (i * 8))) | (u32::from(v) << (i * 8));
    set32(b, p_ref(), p);
}

/// 述語 p_i の条件判定（LSB を見る。0xff/0x00 の比較結果と
/// バイト単位の値の両方で成り立つ）。
#[must_use]
pub fn pred(b: &InterpBackend, i: u32) -> bool {
    p_get(b, i) & 1 != 0
}

/// プログラムカウンタの面。
#[must_use]
pub fn pc_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, pc))
}

/// USR の面。
#[must_use]
pub fn usr_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, usr))
}

/// 制御レジスタ番号 → CpuState 面。ユーザ可視分だけを持つ
/// （UPCYCLE/FRAMELIMIT/FRAMEKEY/PKTCOUNT/UTIMER 等の残りは
/// 後段の段階で拡張する）。
fn c_ref(i: u64) -> Option<StateRef<W32>> {
    use core::mem::offset_of as off;
    let a = u8::try_from(i).ok()?;
    let off = match a {
        cnum::SA0 => off!(CpuState, sa0),
        cnum::LC0 => off!(CpuState, lc0),
        cnum::SA1 => off!(CpuState, sa1),
        cnum::LC1 => off!(CpuState, lc1),
        cnum::P3_0 => off!(CpuState, p),
        cnum::M0 => off!(CpuState, m0),
        cnum::M1 => off!(CpuState, m1),
        cnum::USR => off!(CpuState, usr),
        cnum::PC => off!(CpuState, pc),
        cnum::UGP => off!(CpuState, ugp),
        cnum::GP => off!(CpuState, gp),
        cnum::CS0 => off!(CpuState, cs0),
        cnum::CS1 => off!(CpuState, cs1),
        _ => return None,
    };
    Some(StateRef::<W32>::from_offset(off))
}

/// 制御レジスタ c_i の値。未収録の番号は不正。
pub fn c_get(b: &InterpBackend, i: u64) -> Result<u32, InterpExit> {
    match c_ref(i) {
        Some(r) => Ok(get32(b, r)),
        None => Err(trap(TRAP_ILL)),
    }
}

/// 制御レジスタ c_i への代入。PC は書き込み不可（読み取り専用）。
pub fn c_set(b: &mut InterpBackend, i: u64, v: u32) -> Result<(), InterpExit> {
    if i == u64::from(cnum::PC) {
        return Err(trap(TRAP_ILL));
    }
    match c_ref(i) {
        Some(r) => {
            set32(b, r, v);
            Ok(())
        }
        None => Err(trap(TRAP_ILL)),
    }
}

// ---- パケットの未確定域（pkt_*） ----

fn pkt_r_ref(i: u32) -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, pkt_r) + (i as usize) * 4)
}

fn pkt_r_ok_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, pkt_r_ok))
}

fn pkt_p_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, pkt_p))
}

fn pkt_p_ok_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, pkt_p_ok))
}

/// スロット命令の r_i への書き込み。パケット終端の commit まで
/// 確定値（r）には反映されない。
pub fn pkt_w(b: &mut InterpBackend, i: u32, v: u32) {
    set32(b, pkt_r_ref(i), v);
    set32(b, pkt_r_ok_ref(), get32(b, pkt_r_ok_ref()) | (1 << i));
}

/// スロット命令の p_i への書き込み（8 ビット値）。
pub fn pkt_pw(b: &mut InterpBackend, i: u32, v: u8) {
    let p = (get32(b, pkt_p_ref()) & !(0xff << (i * 8))) | (u32::from(v) << (i * 8));
    set32(b, pkt_p_ref(), p);
    set32(b, pkt_p_ok_ref(), get32(b, pkt_p_ok_ref()) | (1 << i));
}

/// `.new` オペランドが読むパケット内の一時値。パケット内で
/// 生産済みならその値、なければ None。
#[must_use]
pub fn r_new(b: &InterpBackend, i: u32) -> Option<u32> {
    if get32(b, pkt_r_ok_ref()) >> i & 1 != 0 {
        Some(get32(b, pkt_r_ref(i)))
    } else {
        None
    }
}

/// `.new` 述語（pX.new）。パケット内で生産済みならその値。
#[must_use]
pub fn p_new(b: &InterpBackend, i: u32) -> Option<bool> {
    if get32(b, pkt_p_ok_ref()) >> i & 1 != 0 {
        Some(((get32(b, pkt_p_ref()) >> (i * 8)) as u8) & 1 != 0)
    } else {
        None
    }
}

/// 現在のパケットがハードウェアループの終端かを保持する面
/// （bit0 = endloop0、bit1 = endloop1）。commit での LC 減算と
/// SA 復帰は HX8 が足す。
#[must_use]
pub fn endloop_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, endloop))
}

/// 未確定域を捨てる（命令の失敗・illegal パケットで残った
/// 一時値を消す）。
pub fn pkt_clear(b: &mut InterpBackend) {
    set32(b, pkt_r_ok_ref(), 0);
    set32(b, pkt_p_ok_ref(), 0);
}

/// パケットの終わりで書き込みをまとめて反映する。pkt_*_ok の
/// ビットが立つ器だけ確定値へコピーし、未確定域をクリアする。
/// ループ終端の LC/SA 処理は HX8 が足す。
pub fn commit(b: &mut InterpBackend) -> Result<(), InterpExit> {
    let ok = get32(b, pkt_r_ok_ref());
    for i in 0..32 {
        if ok >> i & 1 != 0 {
            r_set(b, i, get32(b, pkt_r_ref(i)));
        }
    }
    set32(b, pkt_r_ok_ref(), 0);
    let pok = get32(b, pkt_p_ok_ref());
    if pok != 0 {
        let mut p = get32(b, p_ref());
        let pn = get32(b, pkt_p_ref());
        for i in 0..4 {
            if pok >> i & 1 != 0 {
                p = (p & !(0xff << (i * 8))) | (pn & 0xff << (i * 8));
            }
        }
        set32(b, p_ref(), p);
    }
    set32(b, pkt_p_ok_ref(), 0);
    Ok(())
}

/// dot-if 修飾の述語条件。呼び出し側（フェッチ層）が命令語の
/// 述語選択桁から解釈して渡す。条件が偽なら意味論を実行しない
/// （qp 抑制に相当）。
#[derive(Clone, Copy, Debug)]
pub struct DotIf {
    /// 述語番号（p0-p3）。
    pub p: u8,
    /// 否定形（`if (!pX)`）。
    pub neg: bool,
    /// `.new` 条件（同一パケット内の一時値を読む）。
    pub new: bool,
}

/// 1 命令ぶんの実行文脈。フェッチ層がパケットから組み立てる。
#[derive(Clone, Copy, Debug, Default)]
pub struct Ctx {
    /// dot-if 修飾（なければ無条件）。
    pub cond: Option<DotIf>,
    /// 直前の constant extender が供給した 26 ビット即値。
    pub ext: Option<u32>,
    /// 現在のパケットの先頭アドレス（PC 相対の基底。extender 語を
    /// 含むパケット先頭）。
    pub pc: u32,
    /// 次のパケットのアドレス（call 系のリンク値）。
    pub next: u32,
}

/// extender 併合済みの即値。`raw` は extract_ops の値（zfill
/// 済みなら `shift` で生の桁値へ戻す）、`bits` は非拡張時の
/// 符号拡張幅。
/// Ref: SPEC-HEXAGON-PRM (V79) Section 10.9.
fn ximm(ext: Option<u32>, raw: u64, shift: u32, bits: u32) -> u32 {
    match ext {
        Some(e) => packet::apply_ext(e, (raw >> shift) as u32 & 0x3f),
        None => sext(raw, bits),
    }
}

/// duplex subinsn の 4 ビット部分集合符号 → 汎用レジスタ番号
/// （r0-7→0-7、r16-23→8-15）。
/// Ref: SPEC-HEXAGON-PRM (V79) sub-instructions.
fn dxr(c: u64) -> u32 {
    let c = c as u32;
    if c < 8 { c } else { c + 8 }
}

/// duplex subinsn の 3 ビット対レジスタ符号 → 偶数側の番号
/// （R1:0..R7:6→0-3、R17:16..R23:22→4-7）。
fn dxp(c: u64) -> u32 {
    let c = c as u32;
    if c < 4 { 2 * c } else { 2 * c + 8 }
}

/// subinsn のレジスタ符号 `i` の値（確定済み）。
fn dxr_get(b: &InterpBackend, i: u64) -> u32 {
    r_get(b, dxr(i))
}

/// 制御転送を記録する。パケット内の先勝ちはフェッチ層が裁く。
fn jump(b: &mut InterpBackend, target: u32) {
    b.ctrl = Ctrl::Jump(u64::from(target));
}

/// 1 命令ぶんの意味論。`word` は命令語（32 ビット語か 13 ビット
/// subinsn 語）。戻り値は意味論を実行したか（dot-if で抑制された
/// とき false）。
pub fn exec(b: &mut InterpBackend, insn: Insn, word: u128, cx: Ctx) -> Result<bool, InterpExit> {
    if let Some(c) = cx.cond {
        let v = if c.new {
            p_new(b, u32::from(c.p)).unwrap_or_else(|| pred(b, u32::from(c.p)))
        } else {
            pred(b, u32::from(c.p))
        };
        if v == c.neg {
            return Ok(false);
        }
    }
    let ops = extract_ops(insn, word);
    let jump_off = |raw: u64, shift: u32, bits: u32| -> u32 { ximm(cx.ext, raw, shift, bits) };
    match insn {
        // ---- 32 ビット命令 ----
        Insn::Nop => {}
        Insn::AddRi => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[1] as u32).wrapping_add(ximm(cx.ext, ops[2], 0, 16)),
        ),
        Insn::AddRr => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[1] as u32).wrapping_add(r_get(b, ops[2] as u32)),
        ),
        Insn::EqS16 => pkt_w(b, ops[0] as u32, ximm(cx.ext, ops[1], 0, 16)),
        Insn::MovRr => pkt_w(b, ops[0] as u32, r_get(b, ops[1] as u32)),
        Insn::Immlo => {
            let x = ops[0] as u32;
            let v = (r_get(b, x) & 0xffff_0000) | (ximm(cx.ext, ops[1], 0, 16) & 0xffff);
            pkt_w(b, x, v);
        }
        Insn::Immhi => {
            let x = ops[0] as u32;
            let v = (r_get(b, x) & 0xffff) | (ximm(cx.ext, ops[1], 0, 16) << 16);
            pkt_w(b, x, v);
        }
        Insn::LdwRi => {
            let ea = r_get(b, ops[1] as u32).wrapping_add(jump_off(ops[2], 2, 13));
            let v = b.load::<W32>(u64::from(ea), DRD)?;
            pkt_w(b, ops[0] as u32, v);
        }
        Insn::StwRi => {
            let ea = r_get(b, ops[0] as u32).wrapping_add(jump_off(ops[2], 2, 13));
            let v = r_get(b, ops[1] as u32);
            b.store::<W32>(u64::from(ea), v, DWR)?;
        }
        Insn::JumpPcrel => {
            let off = jump_off(ops[0], 2, 24);
            jump(b, cx.pc.wrapping_add(off));
        }
        Insn::CallPcrel => {
            pkt_w(b, 31, cx.next);
            let off = jump_off(ops[0], 2, 24);
            jump(b, cx.pc.wrapping_add(off));
        }
        Insn::Jumpr => jump(b, r_get(b, ops[0] as u32)),
        Insn::Callr => {
            pkt_w(b, 31, cx.next);
            jump(b, r_get(b, ops[0] as u32));
        }
        Insn::Trap0 => return Err(trap(ops[0])),
        Insn::Rdcr => pkt_w(b, ops[0] as u32, c_get(b, ops[1])?),
        Insn::Wrcr => c_set(b, ops[0], r_get(b, ops[1] as u32))?,
        Insn::CmpeqRr => {
            let v = r_get(b, ops[1] as u32) == r_get(b, ops[2] as u32);
            pkt_pw(b, ops[0] as u32, if v { 0xff } else { 0 });
        }
        Insn::CmpgtRr => {
            let v = (r_get(b, ops[1] as u32) as i32) > (r_get(b, ops[2] as u32) as i32);
            pkt_pw(b, ops[0] as u32, if v { 0xff } else { 0 });
        }
        // extender はフェッチ層で対結合済み。単独では来ない。
        Insn::Immext => return Err(trap(TRAP_ILL)),
        // ---- duplex subinsn（13 ビット語）----
        Insn::DxL1Memw => {
            let ea = dxr_get(b, ops[1]).wrapping_add((ops[2] as u32) << 2);
            let v = b.load::<W32>(u64::from(ea), DRD)?;
            pkt_w(b, dxr(ops[0]), v);
        }
        Insn::DxL1Memub => {
            let ea = dxr_get(b, ops[1]).wrapping_add(ops[2] as u32);
            let v = b.load::<W8>(u64::from(ea), DRD)?;
            pkt_w(b, dxr(ops[0]), u32::from(v));
        }
        Insn::DxL2Memh => {
            let ea = dxr_get(b, ops[1]).wrapping_add((ops[2] as u32) << 1);
            let v = b.load::<W16>(u64::from(ea), DRD)?;
            pkt_w(b, dxr(ops[0]), sext(u64::from(v), 16));
        }
        Insn::DxL2Memuh => {
            let ea = dxr_get(b, ops[1]).wrapping_add((ops[2] as u32) << 1);
            let v = b.load::<W16>(u64::from(ea), DRD)?;
            pkt_w(b, dxr(ops[0]), u32::from(v));
        }
        Insn::DxL2Memb => {
            let ea = dxr_get(b, ops[1]).wrapping_add(ops[2] as u32);
            let v = b.load::<W8>(u64::from(ea), DRD)?;
            pkt_w(b, dxr(ops[0]), sext(u64::from(v), 8));
        }
        Insn::DxL2Ldwsp => {
            let ea = r_get(b, 29).wrapping_add((ops[1] as u32) << 2);
            let v = b.load::<W32>(u64::from(ea), DRD)?;
            pkt_w(b, dxr(ops[0]), v);
        }
        Insn::DxL2Lddsp => {
            let ea = r_get(b, 29).wrapping_add((ops[1] as u32) << 3);
            let v = b.load::<W64>(u64::from(ea), DRD)?;
            let lo = dxp(ops[0]);
            pkt_w(b, lo, v as u32);
            pkt_w(b, lo + 1, (v >> 32) as u32);
        }
        Insn::DxL2Jumpr => jump(b, r_get(b, 31)),
        // frame 系は HX7（allocframe/deallocframe/dealloc_return）。
        Insn::DxL2Deallocframe | Insn::DxL2Deallocret | Insn::DxS2Allocframe => {
            return Err(InterpExit::Unimplemented(format!("{insn:?}")));
        }
        Insn::DxS1Memw => {
            let ea = dxr_get(b, ops[0]).wrapping_add((ops[2] as u32) << 2);
            b.store::<W32>(u64::from(ea), dxr_get(b, ops[1]), DWR)?;
        }
        Insn::DxS1Memb => {
            let ea = dxr_get(b, ops[0]).wrapping_add(ops[2] as u32);
            b.store::<W8>(u64::from(ea), dxr_get(b, ops[1]) as u8, DWR)?;
        }
        Insn::DxS2Memh => {
            let ea = dxr_get(b, ops[0]).wrapping_add((ops[2] as u32) << 1);
            b.store::<W16>(u64::from(ea), dxr_get(b, ops[1]) as u16, DWR)?;
        }
        Insn::DxS2Stwsp => {
            let ea = r_get(b, 29).wrapping_add((ops[1] as u32) << 2);
            b.store::<W32>(u64::from(ea), dxr_get(b, ops[0]), DWR)?;
        }
        Insn::DxS2Stdsp => {
            let ea = r_get(b, 29).wrapping_add(sext(ops[1], 6) << 3);
            let lo = dxp(ops[0]);
            let v = u64::from(r_get(b, lo)) | (u64::from(r_get(b, lo + 1)) << 32);
            b.store::<W64>(u64::from(ea), v, DWR)?;
        }
        Insn::DxS2Stwi => {
            let ea = dxr_get(b, ops[0]).wrapping_add((ops[1] as u32) << 2);
            b.store::<W32>(u64::from(ea), ops[2] as u32, DWR)?;
        }
        Insn::DxS2Stbi => {
            let ea = dxr_get(b, ops[0]).wrapping_add(ops[1] as u32);
            b.store::<W8>(u64::from(ea), ops[2] as u8, DWR)?;
        }
        Insn::DxAAddi => {
            let x = dxr(ops[0]);
            pkt_w(b, x, r_get(b, x).wrapping_add(ximm(cx.ext, ops[1], 0, 7)));
        }
        Insn::DxAUimm => {
            let v = match cx.ext {
                Some(e) => packet::apply_ext(e, ops[1] as u32 & 0x3f),
                None => ops[1] as u32,
            };
            pkt_w(b, dxr(ops[0]), v);
        }
        Insn::DxASpadd => pkt_w(
            b,
            dxr(ops[0]),
            r_get(b, 29).wrapping_add((ops[1] as u32) << 2),
        ),
        Insn::DxAMov => pkt_w(b, dxr(ops[0]), dxr_get(b, ops[1])),
        Insn::DxAAdd1 => pkt_w(b, dxr(ops[0]), dxr_get(b, ops[1]).wrapping_add(1)),
        Insn::DxAAnd1 => pkt_w(b, dxr(ops[0]), dxr_get(b, ops[1]) & 1),
        Insn::DxASub1 => pkt_w(b, dxr(ops[0]), dxr_get(b, ops[1]).wrapping_sub(1)),
        Insn::DxASxth => pkt_w(b, dxr(ops[0]), sext(dxr_get(b, ops[1]) as u64, 16)),
        Insn::DxASxtb => pkt_w(b, dxr(ops[0]), sext(dxr_get(b, ops[1]) as u64, 8)),
        Insn::DxAZxth => pkt_w(b, dxr(ops[0]), dxr_get(b, ops[1]) & 0xffff),
        Insn::DxAZxtb => pkt_w(b, dxr(ops[0]), dxr_get(b, ops[1]) & 0xff),
        Insn::DxAAddr => {
            let d = dxr(ops[0]);
            pkt_w(b, d, r_get(b, d).wrapping_add(dxr_get(b, ops[1])));
        }
        Insn::DxACmpeq => {
            let v = dxr_get(b, ops[0]) == ops[1] as u32;
            pkt_pw(b, 0, if v { 0xff } else { 0 });
        }
        Insn::DxAClr => {
            // dprd=0 は無条件の `Rd=#-1`、述語選択形は条件クリア
            // （dot-if の判定は冒頭で済み）。
            let v = if ops[1] == 0 { u32::MAX } else { 0 };
            pkt_w(b, dxr(ops[0]), v);
        }
        Insn::DxACombi => {
            let lo = dxp(ops[0]);
            pkt_w(b, lo, ops[2] as u32);
            pkt_w(b, lo + 1, ops[1] as u32);
        }
        Insn::DxAComb0 => {
            let lo = dxp(ops[0]);
            pkt_w(b, lo, dxr_get(b, ops[1]));
            pkt_w(b, lo + 1, 0);
        }
        Insn::DxAComb1 => {
            let lo = dxp(ops[0]);
            pkt_w(b, lo, 0);
            pkt_w(b, lo + 1, dxr_get(b, ops[1]));
        }
    }
    Ok(true)
}
