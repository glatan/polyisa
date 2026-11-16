// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! オペコード表デコーダ（`MapDec`）の結果から被演算子の置き場所を
//! 解決する。ModRM/SIB/変位・REX・アドレスサイズをまとめて扱い、
//! 意味論側は `Rm`（レジスタ直接 or 実効アドレス）だけを見る。
//!
//! Ref: SPEC-X86-INTEL-SDM (v093) Vol.2A 2.1.3-2.1.5.

use polyisa_sem::{Backend, W8, W16, W32, W64};

use crate::MapDec;
use crate::sem::{Gpr, clear_hi, read64, write64};

/// ModRM の r/m が指す被演算子。
pub enum Rm<V> {
    /// レジスタ直接（mod=11）。
    Reg(Gpr),
    /// メモリ。`a` は実効アドレス（セグメントベース加算済み）。
    /// `wseg` が `Some` のとき 16 ビットアドレッシング由来で、
    /// 8 ビットを超えるアクセスはオフセットを 64K で折り返す
    /// （実モードの `mov word [bx+0ffffh]` 等）。
    Mem { a: V, wseg: Option<u64> },
}

/// ModRM reg フィールドのレジスタ（REX.R 込み）。
pub fn reg(d: &MapDec) -> Gpr {
    Gpr(((d.modrm >> 3) & 7) | (((d.rex >> 2) & 1) << 3))
}

/// ModRM r/m がレジスタ直接のときのレジスタ（REX.B 込み）。
pub fn rm_reg(d: &MapDec) -> Gpr {
    Gpr((d.modrm & 7) | ((d.rex & 1) << 3))
}

/// +r 形式のレジスタ（オペコード下位3ビット + REX.B）。
pub fn op_reg(d: &MapDec) -> Gpr {
    Gpr((d.opcode & 7) | ((d.rex & 1) << 3))
}

/// グループ選択の reg フィールド値（REX.R なし）。
pub fn group(d: &MapDec) -> u8 {
    (d.modrm >> 3) & 7
}

/// 8ビット被演算子で上位バイト（AH..BH）を指すか。REX があると
/// SPL/BPL/SIL/DIL/R8B-R15B になるので、REX なしの 4-7 のみ。
pub fn high8(d: &MapDec, g: Gpr) -> bool {
    d.rex == 0 && g.0 >= 4
}

/// 8ビット被演算子のエンコーディングを実レジスタと上位バイト選択に写像する。
/// REX なしで 4-7 は AH-DH、つまりベースレジスタ 0-3 の上位バイト。
/// `sem::read8`/`write8` は「そのレジスタの上位バイト」を扱うので、
/// ここで Gpr(4..8) を Gpr(0..4)+high に解決してから渡す。
pub fn reg8(d: &MapDec, g: Gpr) -> (Gpr, bool) {
    if high8(d, g) {
        (Gpr(g.0 - 4), true)
    } else {
        (g, false)
    }
}

/// ModRM/SIB/変位から実効アドレスを求める。mod=11 は `Rm::Reg`。
/// `seg` はセグメントベース（上書き接頭辞由来、なければ 0）。
pub fn rm_of<B: Backend>(b: &mut B, d: &MapDec, next_rip: u64, seg: u64) -> Rm<B::V<W64>> {
    let m = d.modrm;
    if m >> 6 == 3 {
        return Rm::Reg(rm_reg(d));
    }
    let rm = m & 7;
    let mut a: B::V<W64> = if d.asize == 16 {
        ea16(b, m, d.disp)
    } else if rm == 4 {
        ea_sib(b, m, d, next_rip)
    } else if m >> 6 == 0 && rm == 5 {
        // mod=00 r/m=101：RIP 相対（64）か絶対 disp32（32）。
        let base = if d.asize == 64 { next_rip } else { 0 };
        b.konst::<W64>((base as i64).wrapping_add(d.disp) as u64)
    } else {
        ea_base_disp(b, d.asize, rm, d.rex, d.disp)
    };
    if seg != 0 {
        let s = b.konst::<W64>(seg);
        a = b.add::<W64>(a, s);
    }
    let wseg = (d.asize == 16).then_some(seg);
    Rm::Mem { a, wseg }
}

/// 16ビットアドレッシング（実モード・286）。BX+SI 等の固定表。
fn ea16<B: Backend>(b: &mut B, m: u8, disp: i64) -> B::V<W64> {
    let rm = m & 7;
    // (base, index) のレジスタ番号。None はなし。
    let (base, idx): (Option<u8>, Option<u8>) = match rm {
        0 => (Some(3), Some(6)),          // BX+SI
        1 => (Some(3), Some(7)),          // BX+DI
        2 => (Some(5), Some(6)),          // BP+SI
        3 => (Some(5), Some(7)),          // BP+DI
        4 => (None, Some(6)),             // SI
        5 => (None, Some(7)),             // DI
        6 if m >> 6 == 0 => (None, None), // disp16 のみ
        6 => (Some(5), None),             // BP
        _ => (Some(3), None),             // BX
    };
    let r16 = |b: &mut B, i: u8| -> B::V<W16> {
        let v: B::V<W32> = b.get(Gpr(i).state());
        b.trunc::<W32, W16>(v)
    };
    let mut v = b.konst::<W16>(0);
    if let Some(i) = base {
        let t = r16(b, i);
        v = b.add::<W16>(v, t);
    }
    if let Some(i) = idx {
        let t = r16(b, i);
        v = b.add::<W16>(v, t);
    }
    let dv = b.konst::<W16>(disp as u16);
    v = b.add::<W16>(v, dv);
    b.zext::<W16, W64>(v)
}

/// SIB 付き実効アドレス（32/64）。mod=00 base=101 は disp32 のみ。
fn ea_sib<B: Backend>(b: &mut B, m: u8, d: &MapDec, _next_rip: u64) -> B::V<W64> {
    let s = d.sib;
    let idx_raw = (s >> 3) & 7;
    let no_index = idx_raw == 4 && (d.rex >> 1) & 1 == 0;
    let idx = idx_raw | (((d.rex >> 1) & 1) << 3);
    let base_raw = s & 7;
    let base_reg = Gpr(base_raw | ((d.rex & 1) << 3));
    let scale = s >> 6;
    let wide = d.asize == 64;
    let mut a = if m >> 6 == 0 && base_raw == 5 {
        b.konst::<W64>(d.disp as u64)
    } else {
        ea_base(b, wide, base_reg)
    };
    if !no_index {
        let iv = ea_base(b, wide, Gpr(idx));
        let sh = b.konst::<W64>(u64::from(scale));
        let iv = if wide {
            b.shl::<W64>(iv, sh)
        } else {
            let v: B::V<W32> = b.trunc::<W64, W32>(iv);
            let sh32: B::V<W32> = b.trunc::<W64, W32>(sh);
            let t = b.shl::<W32>(v, sh32);
            b.zext::<W32, W64>(t)
        };
        a = b.add::<W64>(a, iv);
    }
    if !(m >> 6 == 0 && base_raw == 5) {
        let dv = b.konst::<W64>(d.disp as u64);
        a = b.add::<W64>(a, dv);
    }
    a
}

/// base+disp の実効アドレス（32/64、非 SIB・非 RIP 相対）。
fn ea_base_disp<B: Backend>(b: &mut B, asize: u8, rm: u8, rex: u8, disp: i64) -> B::V<W64> {
    let base = Gpr(rm | ((rex & 1) << 3));
    let mut a = ea_base(b, asize == 64, base);
    let dv = b.konst::<W64>(disp as u64);
    a = b.add::<W64>(a, dv);
    a
}

/// レジスタ値をアドレス幅で読む。32 幅は下位のみで上位はゼロ。
fn ea_base<B: Backend>(b: &mut B, wide: bool, g: Gpr) -> B::V<W64> {
    if wide {
        read64(b, g)
    } else {
        let v: B::V<W32> = b.get(g.state());
        b.zext::<W32, W64>(v)
    }
}

// ---- レジスタ・メモリの読み書き ----

/// 実モードの 64K オフセット折り返しを考慮してメモリを読む。
/// `wseg` が `Some` なら `off = a - seg` を 16 ビットオフセットとみなし、
/// i バイト目は `seg + ((off + i) & 0xffff)` から読む。
pub fn mem_load<B: Backend, W: Hw>(
    b: &mut B,
    a: B::V<W64>,
    wseg: Option<u64>,
) -> Result<B::V<W>, B::Exit> {
    let Some(seg) = wseg.filter(|_| W::BITS > 8) else {
        return b.load::<W>(a, crate::sem::DATA_READ);
    };
    let sv = b.konst::<W64>(seg);
    let lim = b.konst::<W64>(0xFFFF);
    let aoff = b.sub::<W64>(a, sv);
    let off = b.and::<W64>(aoff, lim);
    let addr0 = b.add::<W64>(off, sv);
    let byte0 = b.load::<W8>(addr0, crate::sem::DATA_READ)?;
    let mut acc: B::V<W> = b.zext::<W8, W>(byte0);
    for i in 1..W::BITS / 8 {
        let iv = b.konst::<W64>(u64::from(i));
        let t = b.add::<W64>(off, iv);
        let oi = b.and::<W64>(t, lim);
        let addr = b.add::<W64>(oi, sv);
        let byte = b.load::<W8>(addr, crate::sem::DATA_READ)?;
        let bw: B::V<W> = b.zext::<W8, W>(byte);
        let sh = b.konst::<W>(W::from_u128(u128::from(i * 8)));
        let part = b.shl::<W>(bw, sh);
        acc = b.or::<W>(acc, part);
    }
    Ok(acc)
}

/// `mem_load` と同じ折り返し規則でメモリに書く。
pub fn mem_store<B: Backend, W: Hw>(
    b: &mut B,
    a: B::V<W64>,
    wseg: Option<u64>,
    v: B::V<W>,
) -> Result<(), B::Exit> {
    let Some(seg) = wseg.filter(|_| W::BITS > 8) else {
        return b.store::<W>(a, v, crate::sem::DATA_WRITE);
    };
    let sv = b.konst::<W64>(seg);
    let lim = b.konst::<W64>(0xFFFF);
    let aoff = b.sub::<W64>(a, sv);
    let off = b.and::<W64>(aoff, lim);
    {
        let addr = b.add::<W64>(off, sv);
        let byte = b.trunc::<W, W8>(v);
        b.store::<W8>(addr, byte, crate::sem::DATA_WRITE)?;
    }
    for i in 1..W::BITS / 8 {
        let iv = b.konst::<W64>(u64::from(i));
        let t = b.add::<W64>(off, iv);
        let oi = b.and::<W64>(t, lim);
        let addr = b.add::<W64>(oi, sv);
        let sh = b.konst::<W>(W::from_u128(u128::from(i * 8)));
        let t = b.shr_l::<W>(v, sh);
        let byte = b.trunc::<W, W8>(t);
        b.store::<W8>(addr, byte, crate::sem::DATA_WRITE)?;
    }
    Ok(())
}

/// 8ビットを読む。
pub fn rd8<B: Backend>(b: &mut B, rm: &Rm<B::V<W64>>, d: &MapDec) -> Result<B::V<W8>, B::Exit> {
    match rm {
        Rm::Reg(g) => {
            let (r8, hi) = reg8(d, *g);
            Ok(crate::sem::read8(b, r8, hi))
        }
        Rm::Mem { a, .. } => b.load::<W8>(*a, crate::sem::DATA_READ),
    }
}

/// 16ビットを読む。
pub fn rd16<B: Backend>(b: &mut B, rm: &Rm<B::V<W64>>) -> Result<B::V<W16>, B::Exit> {
    match rm {
        Rm::Reg(g) => {
            let v: B::V<W32> = b.get(g.state());
            Ok(b.trunc::<W32, W16>(v))
        }
        Rm::Mem { a, wseg } => mem_load::<B, W16>(b, *a, *wseg),
    }
}

/// 32ビットを読む。
pub fn rd32<B: Backend>(b: &mut B, rm: &Rm<B::V<W64>>) -> Result<B::V<W32>, B::Exit> {
    match rm {
        Rm::Reg(g) => Ok(b.get(g.state())),
        Rm::Mem { a, wseg } => mem_load::<B, W32>(b, *a, *wseg),
    }
}

/// 64ビットを読む。
pub fn rd64<B: Backend>(b: &mut B, rm: &Rm<B::V<W64>>) -> Result<B::V<W64>, B::Exit> {
    match rm {
        Rm::Reg(g) => Ok(read64(b, *g)),
        Rm::Mem { a, wseg } => mem_load::<B, W64>(b, *a, *wseg),
    }
}

/// 8ビットを書く。
pub fn wr8<B: Backend>(
    b: &mut B,
    rm: &Rm<B::V<W64>>,
    d: &MapDec,
    v: B::V<W8>,
) -> Result<(), B::Exit> {
    match rm {
        Rm::Reg(g) => {
            let (r8, hi) = reg8(d, *g);
            crate::sem::write8(b, r8, hi, v);
            Ok(())
        }
        Rm::Mem { a, .. } => b.store::<W8>(*a, v, crate::sem::DATA_WRITE),
    }
}

/// 16ビットを書く（上位は保存）。
pub fn wr16<B: Backend>(b: &mut B, rm: &Rm<B::V<W64>>, v: B::V<W16>) -> Result<(), B::Exit> {
    match rm {
        Rm::Reg(g) => {
            let cur: B::V<W32> = b.get(g.state());
            let mask = b.konst::<W32>(0xffff_0000);
            let kept = b.and::<W32>(cur, mask);
            let v32 = b.zext::<W16, W32>(v);
            let merged = b.or::<W32>(kept, v32);
            b.set(g.state(), merged);
            Ok(())
        }
        Rm::Mem { a, wseg } => mem_store::<B, W16>(b, *a, *wseg, v),
    }
}

/// 32ビットを書く（x86-64 では上位を消す）。
pub fn wr32<B: Backend>(b: &mut B, rm: &Rm<B::V<W64>>, v: B::V<W32>) -> Result<(), B::Exit> {
    match rm {
        Rm::Reg(g) => {
            b.set(g.state(), v);
            clear_hi(b, *g);
            Ok(())
        }
        Rm::Mem { a, wseg } => mem_store::<B, W32>(b, *a, *wseg, v),
    }
}

/// 64ビットを書く。
pub fn wr64<B: Backend>(b: &mut B, rm: &Rm<B::V<W64>>, v: B::V<W64>) -> Result<(), B::Exit> {
    match rm {
        Rm::Reg(g) => {
            write64(b, *g, v);
            Ok(())
        }
        Rm::Mem { a, wseg } => mem_store::<B, W64>(b, *a, *wseg, v),
    }
}

// ---- レジスタ直接の読み書き ----

/// 32ビットレジスタを読む。
pub fn grd32<B: Backend>(b: &mut B, g: Gpr) -> B::V<W32> {
    b.get(g.state())
}

/// 64ビットレジスタを読む。
pub fn grd64<B: Backend>(b: &mut B, g: Gpr) -> B::V<W64> {
    read64(b, g)
}

/// 8ビットレジスタを読む。
pub fn grd8<B: Backend>(b: &mut B, g: Gpr, d: &MapDec) -> B::V<W8> {
    let (r8, hi) = reg8(d, g);
    crate::sem::read8(b, r8, hi)
}

/// 16ビットレジスタを読む。
pub fn grd16<B: Backend>(b: &mut B, g: Gpr) -> B::V<W16> {
    let v: B::V<W32> = b.get(g.state());
    b.trunc::<W32, W16>(v)
}

/// 32ビットレジスタを書く（上位を消す）。
pub fn gwr32<B: Backend>(b: &mut B, g: Gpr, v: B::V<W32>) {
    b.set(g.state(), v);
    clear_hi(b, g);
}

/// 64ビットレジスタを書く。
pub fn gwr64<B: Backend>(b: &mut B, g: Gpr, v: B::V<W64>) {
    write64(b, g, v);
}

/// 16ビットレジスタを書く（上位は保存）。
pub fn gwr16<B: Backend>(b: &mut B, g: Gpr, v: B::V<W16>) {
    let cur: B::V<W32> = b.get(g.state());
    let mask = b.konst::<W32>(0xffff_0000);
    let kept = b.and::<W32>(cur, mask);
    let v32 = b.zext::<W16, W32>(v);
    let merged = b.or::<W32>(kept, v32);
    b.set(g.state(), merged);
}

/// 8ビットレジスタを書く。
pub fn gwr8<B: Backend>(b: &mut B, g: Gpr, d: &MapDec, v: B::V<W8>) {
    let (r8, hi) = reg8(d, g);
    crate::sem::write8(b, r8, hi, v);
}

/// 幅ごとのレジスタ読み書きを型で振り分ける。
pub trait Hw: polyisa_sem::Width {
    /// レジスタをこの幅で読む。
    fn get<B: Backend>(b: &mut B, g: Gpr, d: &MapDec) -> B::V<Self>;
    /// レジスタにこの幅で書く（部分幅の規則どおり上位を処理する）。
    fn put<B: Backend>(b: &mut B, g: Gpr, d: &MapDec, v: B::V<Self>);
}

impl Hw for W8 {
    fn get<B: Backend>(b: &mut B, g: Gpr, d: &MapDec) -> B::V<W8> {
        let (r8, hi) = reg8(d, g);
        crate::sem::read8(b, r8, hi)
    }
    fn put<B: Backend>(b: &mut B, g: Gpr, d: &MapDec, v: B::V<W8>) {
        let (r8, hi) = reg8(d, g);
        crate::sem::write8(b, r8, hi, v);
    }
}

impl Hw for W16 {
    fn get<B: Backend>(b: &mut B, g: Gpr, _d: &MapDec) -> B::V<W16> {
        let v: B::V<W32> = b.get(g.state());
        b.trunc::<W32, W16>(v)
    }
    fn put<B: Backend>(b: &mut B, g: Gpr, _d: &MapDec, v: B::V<W16>) {
        let cur: B::V<W32> = b.get(g.state());
        let mask = b.konst::<W32>(0xffff_0000);
        let kept = b.and::<W32>(cur, mask);
        let v32 = b.zext::<W16, W32>(v);
        let merged = b.or::<W32>(kept, v32);
        b.set(g.state(), merged);
    }
}

impl Hw for W32 {
    fn get<B: Backend>(b: &mut B, g: Gpr, _d: &MapDec) -> B::V<W32> {
        b.get(g.state())
    }
    fn put<B: Backend>(b: &mut B, g: Gpr, _d: &MapDec, v: B::V<W32>) {
        b.set(g.state(), v);
        clear_hi(b, g);
    }
}

impl Hw for W64 {
    fn get<B: Backend>(b: &mut B, g: Gpr, _d: &MapDec) -> B::V<W64> {
        read64(b, g)
    }
    fn put<B: Backend>(b: &mut B, g: Gpr, _d: &MapDec, v: B::V<W64>) {
        write64(b, g, v);
    }
}

/// `Rm` を幅 `W` で読む。
pub fn rd<B: Backend, W: Hw>(
    b: &mut B,
    rm: &Rm<B::V<W64>>,
    d: &MapDec,
) -> Result<B::V<W>, B::Exit> {
    match rm {
        Rm::Reg(g) => Ok(W::get(b, *g, d)),
        Rm::Mem { a, wseg } => mem_load::<B, W>(b, *a, *wseg),
    }
}

/// `Rm` に幅 `W` で書く。
pub fn wr<B: Backend, W: Hw>(
    b: &mut B,
    rm: &Rm<B::V<W64>>,
    d: &MapDec,
    v: B::V<W>,
) -> Result<(), B::Exit> {
    match rm {
        Rm::Reg(g) => {
            W::put(b, *g, d, v);
            Ok(())
        }
        Rm::Mem { a, wseg } => mem_store::<B, W>(b, *a, *wseg, v),
    }
}

/// ModRM/SIB の EA が既定で SS を使うか（BP/SP ベースか）。
/// 実モードの既定セグメント解決に使う。
pub fn ea_uses_ss(d: &MapDec) -> bool {
    if d.modrm >= 0xC0 {
        return false;
    }
    let md = d.modrm >> 6;
    let rm = d.modrm & 7;
    if d.asize == 16 {
        // BP+SI / BP+DI / [BP+disp]
        matches!(rm, 2 | 3) || (rm == 6 && md != 0)
    } else if rm == 4 {
        // SIB: base=EBP/RBP/R13(mod!=00) または base=ESP/RSP/R12
        let base = d.sib & 7;
        (base == 5 && md != 0) || base == 4
    } else {
        // mod!=00 の r/m=101 は BP ベース（mod=00 は disp32/RIP）
        rm == 5 && md != 0
    }
}
