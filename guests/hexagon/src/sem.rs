// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Hexagon の命令意味論（段階22 の骨格）。
//!
//! 具体値インタプリタ（`InterpBackend`）上で動く。命令の実装は
//! HX5 以降で足し、この骨格では dot-if（`if (pX)`）修飾の抑制
//! 入口と、パケット未確定域（pkt_*）の読み書き・commit の器を
//! 置き、全命令を `Unimplemented` で落とす。
//! Ref: SPEC-HEXAGON-PRM (V79).

use polyisa_engine::interp::{InterpBackend, InterpExit};
use polyisa_sem::{StateRef, W32};

use crate::{CpuState, Insn, cnum};

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

/// パケットの終わりで書き込みをまとめて反映する。pkt_*_ok の
/// ビットが立つ器だけ確定値へコピーし、未確定域をクリアする。
/// ループ終端の LC/SA 処理は HX8、メモリ系の保留は HX4 が足す。
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
/// P/PS/DN 桁から解釈して渡す。条件が偽なら意味論を実行しない
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

/// 1 命令ぶんの意味論。`word` は命令語（32 ビット）、`cond` は
/// dot-if 修飾（なければ無条件）。戻り値は意味論を実行したか
/// （抑制されたとき false）。骨格では全命令を Unimplemented
/// で落とす。
pub fn exec(
    b: &mut InterpBackend,
    insn: Insn,
    word: u32,
    cond: Option<DotIf>,
) -> Result<bool, InterpExit> {
    if let Some(c) = cond {
        let v = if c.new {
            p_new(b, u32::from(c.p)).unwrap_or_else(|| pred(b, u32::from(c.p)))
        } else {
            pred(b, u32::from(c.p))
        };
        if v == c.neg {
            return Ok(false);
        }
    }
    let _ = word;
    Err(InterpExit::Unimplemented(format!("{insn:?}")))
}
