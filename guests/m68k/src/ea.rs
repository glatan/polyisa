// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! m68k の実効アドレス（EA）の評価。
//!
//! 命令は16ビットの先頭ワードと、EA が要求する拡張語からなる
//! （1つの EA は最大2語、MOVE は両 EA で最大4語。68020+ の
//! full 形式拡張語は未対応）。
//! 先頭ワードは生成デコーダが Insn に解き、ここでは先頭ワード中の
//! EA フィールド（mode[5:3]・reg[2:0]）をオペランドに解釈する。
//! 拡張語は命令フェッチとして `ext` 以降の偶数アドレスから backend
//! 経由で読み、消費した語数を返す。命令長は 2 + 拡張語数×2 となる。
//!
//! 出典は SPEC-M68K-PRM (M68000PM/AD Rev 1) §Effective Addressing。
//! Ref: SPEC-M68K-PRM (Rev 1).

use polyisa_mem::{Access, AccessKind, Align, Endian};
use polyisa_sem::{Backend, Cmp, ExceptionKind, GuestException, StateArray, W8, W16, W32, W64};

use super::sem::{self, Ssp, Usp};

/// 拡張語の読み出しに使うアクセス属性（BE・命令フェッチ）。
const FETCH: Access = Access {
    endian: Endian::Be,
    align: Align::Natural,
    kind: AccessKind::Fetch,
};

/// `konst` の短い包み（他ゲストの `k`/`k32` と同じ形）。
fn k16<B: Backend>(b: &mut B, v: u16) -> B::V<W16> {
    b.konst::<W16>(v)
}

fn k32<B: Backend>(b: &mut B, v: u32) -> B::V<W32> {
    b.konst::<W32>(v)
}

fn k64<B: Backend>(b: &mut B, v: u64) -> B::V<W64> {
    b.konst::<W64>(v)
}

/// EA の評価結果。レジスタ直接は番号、メモリは実効アドレスを持つ。
pub enum Ea<B: Backend> {
    /// データレジスタ直接（mode 0）。番号は 0〜7。
    D(u8),
    /// アドレスレジスタ直接（mode 1）。番号は 0〜7 で、7 は
    /// 実行時の SR.S に応じた USP/SSP を指す。
    A(u8),
    /// メモリ実効アドレス（indirect・ディスプレイスメント・
    /// 絶対・PC 相対）。
    Addr(B::V<W64>),
    /// 即値（mode 7 reg 4 のみ）。書き込み先には使えない。
    Imm(B::V<W32>),
}

/// EA が消費する拡張語数を、先頭ワードの情報だけから求める。
/// `size` はオペランドのバイト数（1/2/4、無検証・それ以外は
/// 呼び出し側の前提違反）。mode 7 reg 5〜7 のような未定義の
/// 組み合わせは拡張語を消費しないので 0 —— illegal の判定は
/// `eval`/`mode7` 側の責任で、ここでは語数の契約だけ扱う。
// Ref: SPEC-M68K-PRM (Rev 1).
#[must_use]
pub const fn ext_words(mode: u8, reg: u8, size: u32) -> Option<u32> {
    match mode {
        5 | 6 => Some(1),
        7 => match reg {
            0 | 2 | 3 => Some(1),
            1 => Some(2),
            4 => Some(if size > 2 { 2 } else { 1 }),
            _ => Some(0),
        },
        _ => Some(0),
    }
}

/// 先頭ワードの source EA フィールド（mode[5:3]）。
#[must_use]
pub const fn ea_mode(w: u64) -> u8 {
    ((w >> 3) & 7) as u8
}

/// 先頭ワードの source EA フィールド（reg[2:0]）。
#[must_use]
pub const fn ea_reg(w: u64) -> u8 {
    (w & 7) as u8
}

/// 先頭ワードの destination EA フィールド（mode[8:6]）。
#[must_use]
pub const fn dest_mode(w: u64) -> u8 {
    ((w >> 6) & 7) as u8
}

/// 先頭ワードの destination EA フィールド（reg[11:9]）。
#[must_use]
pub const fn dest_reg(w: u64) -> u8 {
    ((w >> 9) & 7) as u8
}

/// 命令全体が消費する拡張語数。命令長は 2 + 戻り値×2。
///
/// EA フィールドの位置とサイズは命令の仕様ごとに違うので、ここが
/// Insn から `ext_words` への振り分けの契約点になる。F0 形式の
/// 固定ワード命令は EA を持たないので 0。
// Ref: SPEC-M68K-PRM (Rev 1).
#[must_use]
pub const fn insn_ext_words(insn: super::Insn, w: u64) -> Option<u32> {
    match insn {
        // move.<b|w|l>: source と destination の EA がそれぞれ語を
        // 消費しうる。
        super::Insn::MoveB | super::Insn::MoveW | super::Insn::MoveL => {
            let size = move_size(insn);
            let Some(s) = ext_words(ea_mode(w), ea_reg(w), size) else {
                return None;
            };
            let Some(d) = ext_words(dest_mode(w), dest_reg(w), size) else {
                return None;
            };
            Some(s + d)
        }
        // movea: destination は An 直なので source だけが語を消費する。
        super::Insn::MoveaW | super::Insn::MoveaL => {
            let size = move_size(insn);
            ext_words(ea_mode(w), ea_reg(w), size)
        }
        // add/sub/cmp 系: EA は一つ。オペランドサイズは opm
        // （bits[8:6]）で決まる（0,4→b、1,3,5→w、2,6,7→l）。
        super::Insn::Add
        | super::Insn::AddDn
        | super::Insn::AddaL
        | super::Insn::Sub
        | super::Insn::SubDn
        | super::Insn::SubaL
        | super::Insn::Cmp
        | super::Insn::CmpaL => {
            let opm = dest_mode(w);
            let size = match opm {
                0 | 4 => 1,
                1 | 3 | 5 => 2,
                _ => 4,
            };
            ext_words(ea_mode(w), ea_reg(w), size)
        }
        // addq/subq: EA は一つ。サイズは qsz（bits[7:6]）。
        super::Insn::Addq | super::Insn::Subq => {
            let size = 1u32 << qsz(w);
            ext_words(ea_mode(w), ea_reg(w), size)
        }
        // addi/subi/cmpi: 即値の拡張語 + EA の拡張語。
        super::Insn::Addi | super::Insn::Subi | super::Insn::Cmpi => {
            let size = 1u32 << qsz(w);
            let iw = if qsz(w) == 2 { 2 } else { 1 };
            let Some(e) = ext_words(ea_mode(w), ea_reg(w), size) else {
                return None;
            };
            Some(e + iw)
        }
        // or/and/eor 系: EA は一つ。サイズは opm で add/sub と同じ写像。
        super::Insn::Or
        | super::Insn::OrBDn
        | super::Insn::OrWDn
        | super::Insn::OrLDn
        | super::Insn::And
        | super::Insn::AndBDn
        | super::Insn::AndWDn
        | super::Insn::AndLDn
        | super::Insn::Eor => {
            let opm = dest_mode(w);
            let size = match opm {
                0 | 4 => 1,
                1 | 3 | 5 => 2,
                _ => 4,
            };
            ext_words(ea_mode(w), ea_reg(w), size)
        }
        // not/clr/tst: qsz サイズの EA は一つ。
        super::Insn::Not | super::Insn::Clr | super::Insn::Tst => {
            let size = 1u32 << qsz(w);
            ext_words(ea_mode(w), ea_reg(w), size)
        }
        // 分岐: disp8=0 のみ 16bit 変位語を消費。
        super::Insn::Bra | super::Insn::Bsr | super::Insn::Bcc => {
            if w & 0xFF == 0 {
                Some(1)
            } else {
                Some(0)
            }
        }
        // jmp/jsr: 制御 EA の語数。
        super::Insn::Jmp | super::Insn::Jsr => ext_words(ea_mode(w), ea_reg(w), 4),
        // rts/rtr: 拡張語なし（F0 表に含めずここで扱う）。
        super::Insn::Rts | super::Insn::Rtr => Some(0),
        // scc: EA のみ。dbcc: 変位語1つ。
        super::Insn::Scc => ext_words(ea_mode(w), ea_reg(w), 1),
        super::Insn::Dbcc | super::Insn::Link => Some(1),
        // EA・即値語を持たない命令は明示的に 0。
        super::Insn::ExgDd
        | super::Insn::ExgAa
        | super::Insn::ExgDa
        | super::Insn::Swap
        | super::Insn::ExtW
        | super::Insn::ExtL => Some(0),
        super::Insn::Lea | super::Insn::Pea => ext_words(ea_mode(w), ea_reg(w), 4),
        super::Insn::Mulu | super::Insn::Muls | super::Insn::Divu | super::Insn::Divs => {
            ext_words(ea_mode(w), ea_reg(w), 2)
        }
        // movem はマスク語（pc+2）+ EA 拡張語、movep は変位語1つ。
        super::Insn::MovrmW | super::Insn::MovrmL | super::Insn::MrmemW | super::Insn::MrmemL => {
            match ext_words(ea_mode(w), ea_reg(w), 4) {
                Some(n) => Some(n + 1),
                None => None,
            }
        }
        super::Insn::MovepWm
        | super::Insn::MovepLm
        | super::Insn::MovepWr
        | super::Insn::MovepLr => Some(1),
        // レジスタビット操作: EA のみ（Dn なら拡張語なし）。
        super::Insn::Btst | super::Insn::Bchg | super::Insn::Bclr | super::Insn::Bset => {
            ext_words(ea_mode(w), ea_reg(w), 1)
        }
        // 即値ビット操作: ビット番号語 + EA 語。
        super::Insn::BtstI | super::Insn::BchgI | super::Insn::BclrI | super::Insn::BsetI => {
            match ext_words(ea_mode(w), ea_reg(w), 1) {
                Some(n) => Some(1 + n),
                None => None,
            }
        }
        // メモリシフト: word サイズの EA は一つ。
        super::Insn::AsrM
        | super::Insn::AslM
        | super::Insn::LsrM
        | super::Insn::LslM
        | super::Insn::RoxrM
        | super::Insn::RoxlM
        | super::Insn::RorM
        | super::Insn::RolM => ext_words(ea_mode(w), ea_reg(w), 2),
        // ori/andi/eori: EA フィールドが #imm（to CCR/to SR の特殊
        // 符号化）なら即値語のみ。通常は即値語 + EA 語。
        super::Insn::Ori | super::Insn::Andi | super::Insn::Eori => {
            let size = 1u32 << qsz(w);
            let iw = if qsz(w) == 2 { 2 } else { 1 };
            if ea_mode(w) == 7 && ea_reg(w) == 4 {
                return Some(iw);
            }
            let Some(e) = ext_words(ea_mode(w), ea_reg(w), size) else {
                return None;
            };
            Some(e + iw)
        }
        _ => Some(0),
    }
}

/// 先頭ワードのサイズフィールド（bits[7:6]）。
#[must_use]
pub const fn qsz(w: u64) -> u8 {
    ((w >> 6) & 3) as u8
}

/// move 系命令のオペランドサイズ（バイト）。
/// move/movea 以外の呼び出しは前提違反。
#[must_use]
pub const fn move_size(insn: super::Insn) -> u32 {
    match insn {
        super::Insn::MoveB => 1,
        super::Insn::MoveW | super::Insn::MoveaW => 2,
        super::Insn::MoveL | super::Insn::MoveaL => 4,
        _ => panic!("move_size: not a move"),
    }
}

/// EA を評価し、オペランドと消費した拡張語数を返す。
///
/// `mode`/`reg` は先頭ワードの EA フィールド、`size` はオペランドの
/// バイト数（1/2/4）、`ext` はこの EA の最初の拡張語の仮想アドレス
/// （命令先頭 + 2 + 先行する EA の消費分）。`(An)+`/`-(An)` はここで
/// An を更新する。
///
/// 合法性のうち文脈依存のものは呼び出し側の責任。具体的には
/// mode 1 の byte サイズ（illegal）、宛先としての PC 相対・即値
/// （不可）、An 直接の alterability などは命令の仕様から呼び出し側が
/// 弾く。
// Ref: SPEC-M68K-PRM (Rev 1).
pub fn eval<B: Backend>(
    b: &mut B,
    mode: u8,
    reg: u8,
    size: u32,
    ext: u64,
) -> Result<(Ea<B>, u32), B::Exit> {
    debug_assert!(matches!(size, 1 | 2 | 4));
    match mode {
        0 => Ok((Ea::D(reg), 0)),
        1 => Ok((Ea::A(reg), 0)),
        2 => {
            let v = sem::areg(b, reg);
            Ok((Ea::Addr(b.zext::<W32, W64>(v)), 0))
        }
        // (An)+: 読み出し後に An を size 分進める。A7 の byte だけ
        // 2 語境界を保つため 2 進める。
        3 => {
            let old = sem::areg(b, reg);
            let step = k32(b, an_step(reg, size));
            let new = b.add(old, step);
            sem::set_areg(b, reg, new)?;
            Ok((Ea::Addr(b.zext::<W32, W64>(old)), 0))
        }
        // -(An): An を size 分下げてから読み出す。
        4 => {
            let old = sem::areg(b, reg);
            let step = k32(b, an_step(reg, size));
            let new = b.sub(old, step);
            sem::set_areg(b, reg, new)?;
            Ok((Ea::Addr(b.zext::<W32, W64>(new)), 0))
        }
        // d16(An): 拡張語の16ビット変位を符号拡張して An に足す。
        5 => {
            let d = ext_w16(b, ext)?;
            let disp = b.sext::<W16, W32>(d);
            let base = sem::areg(b, reg);
            let addr = b.add(base, disp);
            Ok((Ea::Addr(b.zext::<W32, W64>(addr)), 1))
        }
        // d8(An,Xn): 簡易拡張語。
        6 => {
            let w = ext_w16(b, ext)?;
            let (index, disp) = brief_index(b, w);
            let d32 = b.sext::<W8, W32>(disp);
            let off = b.add(index, d32);
            let base = sem::areg(b, reg);
            let addr = b.add(base, off);
            Ok((Ea::Addr(b.zext::<W32, W64>(addr)), 1))
        }
        7 => mode7(b, reg, size, ext),
        _ => Err(illegal(b)),
    }
}

/// mode 7（絶対・PC 相対・即値）の reg 細分。
fn mode7<B: Backend>(b: &mut B, reg: u8, size: u32, ext: u64) -> Result<(Ea<B>, u32), B::Exit> {
    match reg {
        // (xxx).W: 16ビット絶対アドレスを32ビットに符号拡張。
        0 => {
            let w = ext_w16(b, ext)?;
            let a32 = b.sext::<W16, W32>(w);
            Ok((Ea::Addr(b.zext::<W32, W64>(a32)), 1))
        }
        // (xxx).L: 32ビット絶対アドレス（2語）。
        1 => {
            let hi = ext_w16(b, ext)?;
            let lo = ext_w16(b, ext + 2)?;
            let hi_ext = b.zext::<W16, W64>(hi);
            let shift = k64(b, 16);
            let hi64 = b.shl(hi_ext, shift);
            let lo64 = b.zext::<W16, W64>(lo);
            Ok((Ea::Addr(b.or(hi64, lo64)), 2))
        }
        // d16(PC): 拡張語自身のアドレスに16ビット変位を足す。
        // アドレス空間は32ビットなので W32 で加算して折り返す。
        2 => {
            let w = ext_w16(b, ext)?;
            let base = k32(b, ext as u32);
            let disp = b.sext::<W16, W32>(w);
            let addr = b.add(base, disp);
            Ok((Ea::Addr(b.zext::<W32, W64>(addr)), 1))
        }
        // d8(PC,Xn): 拡張語自身のアドレスに8ビット変位と索引を足す。
        3 => {
            let w = ext_w16(b, ext)?;
            let (index, disp) = brief_index(b, w);
            let d32 = b.sext::<W8, W32>(disp);
            let off = b.add(index, d32);
            let base = k32(b, ext as u32);
            let addr = b.add(base, off);
            Ok((Ea::Addr(b.zext::<W32, W64>(addr)), 1))
        }
        // #imm: byte/word は1語（下位に値）、long は2語。
        // byte は拡張語の下位バイトなので上位を捨てる。
        4 => {
            let w0 = ext_w16(b, ext)?;
            if size > 2 {
                let w1 = ext_w16(b, ext + 2)?;
                let hi_ext = b.zext::<W16, W32>(w0);
                let shift = k32(b, 16);
                let hi = b.shl(hi_ext, shift);
                let lo = b.zext::<W16, W32>(w1);
                Ok((Ea::Imm(b.or(hi, lo)), 2))
            } else {
                let v = b.zext::<W16, W32>(w0);
                let mask = k32(b, (1u32 << (size * 8)) - 1);
                Ok((Ea::Imm(b.and(v, mask)), 1))
            }
        }
        _ => Err(illegal(b)),
    }
}

/// (An)+ / -(An) の増減量。A7 は byte でも語境界を保つため 2。
// Ref: SPEC-M68K-PRM (Rev 1) §Address Register Indirect.
const fn an_step(reg: u8, size: u32) -> u32 {
    if reg == 7 && size == 1 { 2 } else { size }
}

/// 拡張語を `addr` から命令フェッチとして読む。
fn ext_w16<B: Backend>(b: &mut B, addr: u64) -> Result<B::V<W16>, B::Exit> {
    let a = k64(b, addr);
    b.load::<W16>(a, FETCH)
}

/// 簡易拡張語から索引の値と8ビット変位を取り出す。
/// bit15=D/A、14-12=番号、11=W/L、7-0=8ビット変位。
/// bits 10-8 は 68000 では使われず無視する（68020+ のスケール・
/// full 形式の判別はここでは扱わない）。
fn brief_index<B: Backend>(b: &mut B, w: B::V<W16>) -> (B::V<W32>, B::V<W8>) {
    let hi_bit = k16(b, 0x8000);
    let masked = b.and(w, hi_bit);
    let zero = k16(b, 0);
    let is_a = b.cmp(Cmp::Ne, masked, zero);
    let n12 = k16(b, 12);
    let shifted = b.shr_l(w, n12);
    let m7 = k16(b, 7);
    let num16 = b.and(shifted, m7);
    let num = b.zext::<W16, W32>(num16);
    let n11 = k16(b, 11);
    let l_sh = b.shr_l(w, n11);
    let one = k16(b, 1);
    let l_bit = b.and(l_sh, one);
    let is_l = b.cmp(Cmp::Ne, l_bit, zero);
    // 索引の値。D はデータレジスタ、A はアドレスレジスタ（A7 は SP）。
    let dv = b.get_indexed(d_array(), num);
    let av = areg_dyn(b, num);
    let idx_val = b.select(is_a, av, dv);
    // W/L: W なら下位16ビットを符号拡張、L ならそのまま。
    let w_part = b.trunc::<W32, W16>(idx_val);
    let sign_ext = b.sext::<W16, W32>(w_part);
    let index = b.select(is_l, idx_val, sign_ext);
    let disp = b.trunc::<W16, W8>(w);
    (index, disp)
}

/// データレジスタ配列を指す。
fn d_array() -> StateArray<W32> {
    StateArray::<W32>::from_layout(core::mem::offset_of!(super::CpuState, d), 4)
}

/// アドレスレジスタを実行時の番号で読む（7 なら SR.S で USP/SSP）。
/// 番号が実行時に決まるので配列参照と条件選択で組み立てる。
fn areg_dyn<B: Backend>(b: &mut B, num: B::V<W32>) -> B::V<W32> {
    let seven = k32(b, 7);
    let is7 = b.cmp(Cmp::Eq, num, seven);
    let a = StateArray::<W32>::from_layout(core::mem::offset_of!(super::CpuState, a), 4);
    // num=7 のときは索引を a[0] に丸めて a の範囲内だけを読み、
    // 結果は下の select で SP に差し替える。
    let z0 = k32(b, 0);
    let idx = b.select(is7, z0, num);
    let low = b.get_indexed(a, idx);
    let s = b.get(sem::sr_ref());
    let mask = k32(b, 1 << sem::sr_bit::S);
    let masked_s = b.and(s, mask);
    let z32 = k32(b, 0);
    let sup = b.cmp(Cmp::Ne, masked_s, z32);
    let ssp = b.get(Ssp.state());
    let usp = b.get(Usp.state());
    let sp = b.select(sup, ssp, usp);
    b.select(is7, sp, low)
}

/// 未定義の EA 組み合わせを illegal instruction（ベクタ 4）にする。
fn illegal<B: Backend>(b: &mut B) -> B::Exit {
    b.raise(GuestException {
        kind: ExceptionKind::Trap,
        code: 4,
        addr: None,
        in_delay_slot: false,
    })
}
