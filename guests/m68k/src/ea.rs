// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! m68k の実効アドレス（EA）の評価。
//!
//! 命令は16ビットの先頭ワードと、EA が要求する0〜2語の拡張語からなる
//! （68020+ の full 形式拡張語は未対応）。
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
/// 組み合わせは None を返す。
// Ref: SPEC-M68K-PRM (Rev 1).
#[must_use]
pub const fn ext_words(mode: u8, reg: u8, size: u32) -> Option<u32> {
    match mode {
        5 | 6 => Some(1),
        7 => match reg {
            0 | 2 | 3 => Some(1),
            1 => Some(2),
            4 => Some(if size > 2 { 2 } else { 1 }),
            _ => None,
        },
        _ => Some(0),
    }
}

/// 命令全体が消費する拡張語数。命令長は 2 + 戻り値×2。
///
/// EA フィールドの位置とサイズは命令の仕様ごとに違うので、ここが
/// Insn から `ext_words` への振り分けの契約点になる。F0 形式の
/// 固定ワード命令は EA を持たないので 0。
// Ref: SPEC-M68K-PRM (Rev 1).
#[must_use]
pub const fn insn_ext_words(insn: super::Insn, w: u64) -> Option<u32> {
    // F0 形式の固定ワード命令は拡張語を持たない。EA を持つ命令の追加で
    // Insn → ext_words の振り分けに育つ。
    let _ = insn;
    let _ = w;
    Some(0)
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
            let step = k32(b, post_adj(reg, size));
            let new = b.add(old, step);
            sem::set_areg(b, reg, new)?;
            Ok((Ea::Addr(b.zext::<W32, W64>(old)), 0))
        }
        // -(An): An を size 分下げてから読み出す。
        4 => {
            let old = sem::areg(b, reg);
            let step = k32(b, post_adj(reg, size));
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
const fn post_adj(reg: u8, size: u32) -> u32 {
    if reg == 7 && size == 1 { 2 } else { size }
}

/// 拡張語を `addr` から命令フェッチとして読む。
fn ext_w16<B: Backend>(b: &mut B, addr: u64) -> Result<B::V<W16>, B::Exit> {
    let a = k64(b, addr);
    b.load::<W16>(a, FETCH)
}

/// 簡易拡張語から索引の値と8ビット変位を取り出す。
/// bit15=D/A、14-12=番号、11=W/L、10-9=スケール（68000 では 0=1倍）、
/// 7-0=8ビット変位。68020+ の full 形式（bit8=1）はここでは扱わない。
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
    let idx32 = b.select(is_l, idx_val, sign_ext);
    let n9 = k16(b, 9);
    let s_sh = b.shr_l(w, n9);
    let m3 = k16(b, 3);
    let scale16 = b.and(s_sh, m3);
    let scale = b.zext::<W16, W32>(scale16);
    let index = b.shl(idx32, scale);
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
