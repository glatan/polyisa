// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! オペコード表経路の意味論。被演算子を `Rm`（レジスタ直接 or
//! 実効アドレス）と幅で受け、アドレス形ごとの直積を避ける。
//!
//! Ref: SPEC-X86-INTEL-SDM (v093) Vol.2.

use polyisa_sem::{Backend, Cmp, Flow, W8, W16, W32, W64, W128, Width};

use crate::MapDec;
use crate::decode::{self, Hw, Rm};
use crate::sem::{
    self, FLAG_CF, FLAG_OF, Gpr, eflags_ref, eip_ref, read_cf, read_of, read_pf, read_sf, read_zf,
    update_add_flags, update_addc_flags, update_logic_flags, update_sub_flags, update_subb_flags,
};
use crate::sem::{pick, szp_bits};

/// 二項演算の種別。
#[derive(Clone, Copy)]
pub enum Alu {
    Add,
    Or,
    Adc,
    Sbb,
    And,
    Sub,
    Xor,
    Cmp,
}

fn alu_op<B: Backend, W: Hw>(b: &mut B, op: Alu, x: B::V<W>, y: B::V<W>) -> B::V<W> {
    match op {
        Alu::Add | Alu::Adc => b.add::<W>(x, y),
        Alu::Or => b.or::<W>(x, y),
        Alu::And => b.and::<W>(x, y),
        Alu::Sub | Alu::Sbb | Alu::Cmp => b.sub::<W>(x, y),
        Alu::Xor => b.xor::<W>(x, y),
    }
}

fn alu_flags<B: Backend, W: Hw>(
    b: &mut B,
    op: Alu,
    x: B::V<W>,
    y: B::V<W>,
    c: B::V<W>,
    v: B::V<W>,
) {
    match op {
        Alu::Add | Alu::Adc => update_addc_flags(b, x, y, c, v),
        Alu::Or | Alu::And | Alu::Xor => update_logic_flags(b, v),
        Alu::Sub | Alu::Sbb | Alu::Cmp => update_subb_flags(b, x, y, c, v),
    }
}

/// ADC/SBB のキャリー入力 `c`（0/1）と、それを足した被演算子 `y+c`。
fn alu_carry<B: Backend, W: Hw>(b: &mut B, op: Alu, y: B::V<W>) -> (B::V<W>, B::V<W>) {
    if matches!(op, Alu::Adc | Alu::Sbb) {
        let cf = read_cf(b);
        let one = b.konst::<W>(W::from_u128(1));
        let zero = b.konst::<W>(W::from_u128(0));
        let c = b.select::<W>(cf, one, zero);
        (b.add::<W>(y, c), c)
    } else {
        let zero = b.konst::<W>(W::from_u128(0));
        (y, zero)
    }
}

/// TEST：AND して旗だけ更新する（書き戻さない）。
pub fn test<'a, B: Backend>(
    b: &mut B,
    w: u8,
    rm: &Rm<B::V<W64>>,
    d: &MapDec,
    src: Src<'a, B::V<W64>>,
) -> Flow<B> {
    match w {
        8 => test_w::<B, W8>(b, rm, d, src),
        16 => test_w::<B, W16>(b, rm, d, src),
        32 => test_w::<B, W32>(b, rm, d, src),
        _ => test_w::<B, W64>(b, rm, d, src),
    }
}

fn test_w<'a, B: Backend, W: Hw>(
    b: &mut B,
    rm: &Rm<B::V<W64>>,
    d: &MapDec,
    src: Src<'a, B::V<W64>>,
) -> Flow<B> {
    let x = rd_w::<B, W>(b, rm, d)?;
    let y = match src {
        Src::Reg(g) => grd_w::<B, W>(b, g, d),
        Src::Imm(i) => b.konst::<W>(W::from_u128(u128::from(i))),
        Src::Ea(e) => rd_w::<B, W>(b, e, d)?,
    };
    let v = b.and::<W>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// `dst op= src`（E←G / E←imm / A←imm）。`imm` は既に値化した即値。
/// CMP は書き戻さない。
pub fn alu<'a, B: Backend>(
    b: &mut B,
    op: Alu,
    w: u8,
    rm: &Rm<B::V<W64>>,
    d: &MapDec,
    src: Src<'a, B::V<W64>>,
) -> Flow<B> {
    match w {
        8 => alu_w::<B, W8>(b, op, rm, d, src),
        16 => alu_w::<B, W16>(b, op, rm, d, src),
        32 => alu_w::<B, W32>(b, op, rm, d, src),
        _ => alu_w::<B, W64>(b, op, rm, d, src),
    }
}

/// 右被演算子：レジスタか即値か、もう一方の被演算子（r/m）。
pub enum Src<'a, V> {
    Reg(Gpr),
    Imm(u64),
    Ea(&'a Rm<V>),
}

fn alu_w<'a, B: Backend, W: Hw>(
    b: &mut B,
    op: Alu,
    rm: &Rm<B::V<W64>>,
    d: &MapDec,
    src: Src<'a, B::V<W64>>,
) -> Flow<B> {
    let x = rd_w::<B, W>(b, rm, d)?;
    let y = match src {
        Src::Reg(g) => grd_w::<B, W>(b, g, d),
        Src::Imm(i) => b.konst::<W>(W::from_u128(u128::from(i))),
        Src::Ea(e) => rd_w::<B, W>(b, e, d)?,
    };
    let (y2, c) = alu_carry::<B, W>(b, op, y);
    let v = alu_op::<B, W>(b, op, x, y2);
    alu_flags::<B, W>(b, op, x, y, c, v);
    if !matches!(op, Alu::Cmp) {
        wr_w::<B, W>(b, rm, d, v)?;
    }
    Ok(())
}

fn rd_w<B: Backend, W: Hw>(b: &mut B, rm: &Rm<B::V<W64>>, d: &MapDec) -> Result<B::V<W>, B::Exit> {
    decode::rd::<B, W>(b, rm, d)
}

fn wr_w<B: Backend, W: Hw>(
    b: &mut B,
    rm: &Rm<B::V<W64>>,
    d: &MapDec,
    v: B::V<W>,
) -> Result<(), B::Exit> {
    decode::wr::<B, W>(b, rm, d, v)
}

fn grd_w<B: Backend, W: Hw>(b: &mut B, g: Gpr, d: &MapDec) -> B::V<W> {
    W::get(b, g, d)
}

fn gwr_w<B: Backend, W: Hw>(b: &mut B, g: Gpr, d: &MapDec, v: B::V<W>) {
    W::put(b, g, d, v)
}

// ---- 条件コード ----

/// B の否定（真偽値は select/cmp で組み立てる）。
fn bnot<B: Backend>(b: &mut B, c: B::B) -> B::B {
    let one = b.konst::<W32>(1);
    let zero = b.konst::<W32>(0);
    let n = b.select::<W32>(c, one, zero);
    b.cmp::<W32>(Cmp::Eq, n, zero)
}

/// B の和。
fn bor<B: Backend>(b: &mut B, x: B::B, y: B::B) -> B::B {
    let one = b.konst::<W32>(1);
    let zero = b.konst::<W32>(0);
    let a = b.select::<W32>(x, one, zero);
    let c = b.select::<W32>(y, one, zero);
    let s = b.or::<W32>(a, c);
    b.cmp::<W32>(Cmp::Ne, s, zero)
}

/// B の積。
fn band<B: Backend>(b: &mut B, x: B::B, y: B::B) -> B::B {
    let one = b.konst::<W32>(1);
    let zero = b.konst::<W32>(0);
    let a = b.select::<W32>(x, one, zero);
    let c = b.select::<W32>(y, one, zero);
    let s = b.and::<W32>(a, c);
    b.cmp::<W32>(Cmp::Ne, s, zero)
}

/// cc 番号（0-F）の条件値。
fn cc<B: Backend>(b: &mut B, n: u8) -> B::B {
    match n {
        0x0 => read_of(b),
        0x1 => {
            let v = read_of(b);
            bnot(b, v)
        }
        0x2 => read_cf(b),
        0x3 => {
            let v = read_cf(b);
            bnot(b, v)
        }
        0x4 => read_zf(b),
        0x5 => {
            let v = read_zf(b);
            bnot(b, v)
        }
        0x6 => {
            let x = read_cf(b);
            let y = read_zf(b);
            bor(b, x, y)
        }
        0x7 => {
            let x = read_cf(b);
            let y = read_zf(b);
            let e = bor(b, x, y);
            bnot(b, e)
        }
        0x8 => read_sf(b),
        0x9 => {
            let v = read_sf(b);
            bnot(b, v)
        }
        0xA => read_pf(b),
        0xB => {
            let v = read_pf(b);
            bnot(b, v)
        }
        0xC => {
            let (sf, of) = (sf_num(b), of_num(b));
            b.cmp::<W32>(Cmp::Ne, sf, of)
        }
        0xD => {
            let (sf, of) = (sf_num(b), of_num(b));
            b.cmp::<W32>(Cmp::Eq, sf, of)
        }
        0xE => {
            let (sf, of) = (sf_num(b), of_num(b));
            let s_o = b.cmp::<W32>(Cmp::Ne, sf, of);
            let z = read_zf(b);
            bor(b, z, s_o)
        }
        _ => {
            let (sf, of) = (sf_num(b), of_num(b));
            let s_o = b.cmp::<W32>(Cmp::Eq, sf, of);
            let z = read_zf(b);
            let nz = bnot(b, z);
            band(b, nz, s_o)
        }
    }
}

fn sf_num<B: Backend>(b: &mut B) -> B::V<W32> {
    sem::sf_num(b)
}
fn of_num<B: Backend>(b: &mut B) -> B::V<W32> {
    sem::of_num(b)
}

// ---- 転送・交換 ----

/// MOV/XCHG の E←G / G←E / E←imm。xchg は両方に書く。
pub fn mov_e<'a, B: Backend>(
    b: &mut B,
    w: u8,
    rm: &Rm<B::V<W64>>,
    d: &MapDec,
    src: Src<'a, B::V<W64>>,
) -> Flow<B> {
    match w {
        8 => {
            let v = match src {
                Src::Reg(g) => grd_w::<B, W8>(b, g, d),
                Src::Imm(i) => b.konst::<W8>(i as u8),
                Src::Ea(e) => rd_w::<B, W8>(b, e, d)?,
            };
            wr_w::<B, W8>(b, rm, d, v)
        }
        16 => {
            let v = match src {
                Src::Reg(g) => grd_w::<B, W16>(b, g, d),
                Src::Imm(i) => b.konst::<W16>(i as u16),
                Src::Ea(e) => rd_w::<B, W16>(b, e, d)?,
            };
            wr_w::<B, W16>(b, rm, d, v)
        }
        32 => {
            let v = match src {
                Src::Reg(g) => grd_w::<B, W32>(b, g, d),
                Src::Imm(i) => b.konst::<W32>(i as u32),
                Src::Ea(e) => rd_w::<B, W32>(b, e, d)?,
            };
            wr_w::<B, W32>(b, rm, d, v)
        }
        _ => {
            let v = match src {
                Src::Reg(g) => grd_w::<B, W64>(b, g, d),
                Src::Imm(i) => b.konst::<W64>(i),
                Src::Ea(e) => rd_w::<B, W64>(b, e, d)?,
            };
            wr_w::<B, W64>(b, rm, d, v)
        }
    }
}

/// MOV G←E。
pub fn mov_r<B: Backend>(b: &mut B, w: u8, dst: Gpr, rm: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    match w {
        8 => {
            let v = rd_w::<B, W8>(b, rm, d)?;
            let (r8, hi) = decode::reg8(d, dst);
            sem::write8(b, r8, hi, v);
            Ok(())
        }
        16 => {
            let v = rd_w::<B, W16>(b, rm, d)?;
            gwr_w::<B, W16>(b, dst, d, v);
            Ok(())
        }
        32 => {
            let v = rd_w::<B, W32>(b, rm, d)?;
            gwr_w::<B, W32>(b, dst, d, v);
            Ok(())
        }
        _ => {
            let v = rd_w::<B, W64>(b, rm, d)?;
            gwr_w::<B, W64>(b, dst, d, v);
            Ok(())
        }
    }
}

/// XCHG E,G。
pub fn xchg<B: Backend>(b: &mut B, w: u8, rm: &Rm<B::V<W64>>, d: &MapDec, g: Gpr) -> Flow<B> {
    match w {
        8 => {
            let a = rd_w::<B, W8>(b, rm, d)?;
            let c = grd_w::<B, W8>(b, g, d);
            wr_w::<B, W8>(b, rm, d, c)?;
            let (r8, hi) = decode::reg8(d, g);
            sem::write8(b, r8, hi, a);
            Ok(())
        }
        16 => {
            let a = rd_w::<B, W16>(b, rm, d)?;
            let c = grd_w::<B, W16>(b, g, d);
            wr_w::<B, W16>(b, rm, d, c)?;
            gwr_w::<B, W16>(b, g, d, a);
            Ok(())
        }
        32 => {
            let a = rd_w::<B, W32>(b, rm, d)?;
            let c = grd_w::<B, W32>(b, g, d);
            wr_w::<B, W32>(b, rm, d, c)?;
            gwr_w::<B, W32>(b, g, d, a);
            Ok(())
        }
        _ => {
            let a = rd_w::<B, W64>(b, rm, d)?;
            let c = grd_w::<B, W64>(b, g, d);
            wr_w::<B, W64>(b, rm, d, c)?;
            gwr_w::<B, W64>(b, g, d, a);
            Ok(())
        }
    }
}

/// MOVZX/MOVSX/MOVSXD G←E。src_w はソース幅（8/16/32）。
pub fn movzx<B: Backend>(
    b: &mut B,
    dst_w: u8,
    src_w: u8,
    dst: Gpr,
    rm: &Rm<B::V<W64>>,
    d: &MapDec,
    signed: bool,
) -> Flow<B> {
    let v64: B::V<W64> = match (src_w, signed) {
        (8, false) => {
            let v = rd_w::<B, W8>(b, rm, d)?;
            b.zext::<W8, W64>(v)
        }
        (8, true) => {
            let v = rd_w::<B, W8>(b, rm, d)?;
            b.sext::<W8, W64>(v)
        }
        (16, false) => {
            let v = rd_w::<B, W16>(b, rm, d)?;
            b.zext::<W16, W64>(v)
        }
        (16, true) => {
            let v = rd_w::<B, W16>(b, rm, d)?;
            b.sext::<W16, W64>(v)
        }
        (_, false) => {
            let v = rd_w::<B, W32>(b, rm, d)?;
            b.zext::<W32, W64>(v)
        }
        (_, true) => {
            let v = rd_w::<B, W32>(b, rm, d)?;
            b.sext::<W32, W64>(v)
        }
    };
    match dst_w {
        16 => {
            let v: B::V<W16> = b.trunc::<W64, W16>(v64);
            gwr_w::<B, W16>(b, dst, d, v);
        }
        32 => {
            let v: B::V<W32> = b.trunc::<W64, W32>(v64);
            gwr_w::<B, W32>(b, dst, d, v);
        }
        _ => sem::write64(b, dst, v64),
    }
    Ok(())
}

/// LEA。実効アドレスをレジスタに入れる（メモリアクセスしない）。
/// `rm` の番地はセグメント基底込みなので、`seg` を差し戻してオフセットにする。
pub fn lea<B: Backend>(
    b: &mut B,
    w: u8,
    dst: Gpr,
    rm: &Rm<B::V<W64>>,
    asize: u8,
    seg: u64,
    d: &MapDec,
) -> Flow<B> {
    let Rm::Mem { a, .. } = rm else {
        return Ok(()); // #UD（mod=11）は呼び出し側で排除済み想定
    };
    let s = b.konst::<W64>(seg);
    let a = b.sub::<W64>(*a, s);
    match (w, asize) {
        (16, _) => {
            let v: B::V<W16> = b.trunc::<W64, W16>(a);
            gwr_w::<B, W16>(b, dst, d, v);
        }
        (32, _) => {
            let v: B::V<W32> = b.trunc::<W64, W32>(a);
            gwr_w::<B, W32>(b, dst, d, v);
        }
        (_, 64) => sem::write64(b, dst, a),
        _ => {
            let v: B::V<W32> = b.trunc::<W64, W32>(a);
            let v = b.zext::<W32, W64>(v);
            sem::write64(b, dst, v);
        }
    }
    Ok(())
}

// ---- INC/DEC/NOT/NEG ----

/// INC/DEC。CF は保存される。
pub fn incdec<B: Backend>(b: &mut B, inc: bool, w: u8, rm: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    match w {
        8 => incdec_w::<B, W8>(b, inc, rm, d),
        16 => incdec_w::<B, W16>(b, inc, rm, d),
        32 => incdec_w::<B, W32>(b, inc, rm, d),
        _ => incdec_w::<B, W64>(b, inc, rm, d),
    }
}

fn incdec_w<B: Backend, W: Hw>(b: &mut B, inc: bool, rm: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    let cf_mask = b.konst::<W32>(sem::FLAG_CF);
    let all = b.get(eflags_ref());
    let saved = b.and::<W32>(all, cf_mask);
    let x = rd_w::<B, W>(b, rm, d)?;
    let one = b.konst::<W>(W::from_u128(1));
    let v = if inc {
        b.add::<W>(x, one)
    } else {
        b.sub::<W>(x, one)
    };
    wr_w::<B, W>(b, rm, d, v)?;
    if inc {
        update_add_flags(b, x, one, v);
    } else {
        update_sub_flags(b, x, one, v);
    }
    let f = b.get(eflags_ref());
    let not_cf = b.konst::<W32>(!sem::FLAG_CF);
    let cleared = b.and::<W32>(f, not_cf);
    let merged = b.or::<W32>(cleared, saved);
    b.set(eflags_ref(), merged);
    Ok(())
}

/// NOT。旗は変えない。
pub fn not<B: Backend>(b: &mut B, w: u8, rm: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    match w {
        8 => {
            let x = rd_w::<B, W8>(b, rm, d)?;
            {
                let v = b.not::<W8>(x);
                wr_w::<B, W8>(b, rm, d, v)
            }
        }
        16 => {
            let x = rd_w::<B, W16>(b, rm, d)?;
            {
                let v = b.not::<W16>(x);
                wr_w::<B, W16>(b, rm, d, v)
            }
        }
        32 => {
            let x = rd_w::<B, W32>(b, rm, d)?;
            {
                let v = b.not::<W32>(x);
                wr_w::<B, W32>(b, rm, d, v)
            }
        }
        _ => {
            let x = rd_w::<B, W64>(b, rm, d)?;
            {
                let v = b.not::<W64>(x);
                wr_w::<B, W64>(b, rm, d, v)
            }
        }
    }
}

/// NEG。CF は被演算子が 0 以外で立つ。
pub fn neg<B: Backend>(b: &mut B, w: u8, rm: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    match w {
        8 => neg_w::<B, W8>(b, rm, d),
        16 => neg_w::<B, W16>(b, rm, d),
        32 => neg_w::<B, W32>(b, rm, d),
        _ => neg_w::<B, W64>(b, rm, d),
    }
}

fn neg_w<B: Backend, W: Hw>(b: &mut B, rm: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    let x = rd_w::<B, W>(b, rm, d)?;
    let z = b.konst::<W>(W::from_u128(0));
    let v = b.sub::<W>(z, x);
    wr_w::<B, W>(b, rm, d, v)?;
    // NEG は 0-x の減算と同じ旗。CF は x!=0 のとき立つ（0 からの
    // 借りがちょうどその条件）。
    update_sub_flags(b, z, x, v);
    Ok(())
}

// ---- シフト ----

/// シフト量の由来。
#[derive(Clone, Copy)]
pub enum ShiftCnt {
    /// 即値（マスクは実装側）。
    Imm(u32),
    /// 定数 1。
    One,
    /// CL の値。
    Cl,
}

/// シフトの種別。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Sh {
    Rol,
    Ror,
    Rcl,
    Rcr,
    Shl,
    Shr,
    /// 8086/8088 のシフト群 /6。全ビット 1 を書く undocumented 命令。
    Setmo,
    Sar,
}

/// SHL/SHR/SAR/ROL/ROR/RCL/RCR。量は 5/6 ビットにマスクし、0 なら
/// 結果・旗とも不変とする。
pub fn shift<B: Backend>(
    b: &mut B,
    op: Sh,
    w: u8,
    rm: &Rm<B::V<W64>>,
    d: &MapDec,
    cnt: ShiftCnt,
    m16: bool,
) -> Flow<B> {
    match w {
        8 => shift_w::<B, W8>(b, op, rm, d, cnt, m16),
        16 => shift_w::<B, W16>(b, op, rm, d, cnt, m16),
        32 => shift_w::<B, W32>(b, op, rm, d, cnt, m16),
        _ => shift_w::<B, W64>(b, op, rm, d, cnt, m16),
    }
}

#[allow(clippy::too_many_lines)]
fn shift_w<B: Backend, W: Hw>(
    b: &mut B,
    op: Sh,
    rm: &Rm<B::V<W64>>,
    d: &MapDec,
    cnt: ShiftCnt,
    m16: bool,
) -> Flow<B> {
    // 8088 は CL をマスクしない（回数をそのまま反復）。286 以降は 31/63。
    let mask: u64 = if W::BITS == 64 { 63 } else { 31 };
    let n = match cnt {
        ShiftCnt::Imm(i) => b.konst::<W>(W::from_u128(u128::from(i & mask as u32))),
        ShiftCnt::One => b.konst::<W>(W::from_u128(1)),
        ShiftCnt::Cl => {
            let cl = sem::read8(b, Gpr(1), false);
            let cl: B::V<W32> = b.zext::<W8, W32>(cl);
            let m = b.konst::<W32>(if m16 { 0xFF } else { mask as u32 });
            let v = b.and::<W32>(cl, m);
            b.trunc::<W32, W>(v)
        }
    };
    // SETMO: 8086/8088 のシフト群 /6。回数 0 以外では全ビット 1 を書き、
    // 論理演算と同じ旗（SZP 更新、CF/OF/AF=0）。回数 0 は結果・旗とも不変。
    if op == Sh::Setmo {
        let x = rd_w::<B, W>(b, rm, d)?;
        let all = b.konst::<W>(W::from_u128((1u128 << W::BITS) - 1));
        let z = b.konst::<W>(W::from_u128(0));
        let nz = b.cmp::<W>(Cmp::Ne, n, z);
        let v = b.select::<W>(nz, all, x);
        wr_w::<B, W>(b, rm, d, v)?;
        let old: B::V<W32> = b.get(eflags_ref());
        let keep = b.konst::<W32>(!sem::FLAG_OSZPCA);
        let cleared = b.and::<W32>(old, keep);
        let szp = szp_bits(b, all);
        let nf = b.or::<W32>(cleared, szp);
        let n32: B::V<W32> = b.trunc::<W, W32>(n);
        let z32 = b.konst::<W32>(0);
        let active = b.cmp::<W32>(Cmp::Ne, n32, z32);
        let assembled = b.select::<W32>(active, nf, old);
        b.set(eflags_ref(), assembled);
        return Ok(());
    }
    let x = rd_w::<B, W>(b, rm, d)?;
    let bits = W::BITS;
    let zw = b.konst::<W>(W::from_u128(0));
    let ow = b.konst::<W>(W::from_u128(1));
    let bw = b.konst::<W>(W::from_u128(u128::from(bits)));
    // 大きい回数への安全なシフト量。bits シフトはバックエンドで 0 を返す。
    let over = b.cmp::<W>(Cmp::LtU, bw, n);
    let nc = b.select::<W>(over, bw, n);
    // RCL/RCR の回数は bits+1 の環。mod は繰り返し減算で求める。
    let b1w = b.konst::<W>(W::from_u128(u128::from(bits + 1)));
    let mut ne = n;
    for _ in 0..28 {
        let lt = b.cmp::<W>(Cmp::LtU, ne, b1w);
        let d1 = b.sub::<W>(ne, b1w);
        ne = b.select::<W>(lt, ne, d1);
    }
    // CF 込みの bits+1 回転に必要な CF の値化。
    let cf0 = read_cf(b);
    let cfv = b.select::<W>(cf0, ow, zw);
    let rot = matches!(op, Sh::Rol | Sh::Ror | Sh::Rcl | Sh::Rcr);
    let v = match op {
        Sh::Shl => b.shl::<W>(x, nc),
        Sh::Shr => b.shr_l::<W>(x, nc),
        Sh::Sar => {
            // 回数が幅を超えるときは全ビット符号になる。
            let bm1 = b.konst::<W>(W::from_u128(u128::from(bits - 1)));
            let ge = b.cmp::<W>(Cmp::LtU, bm1, n);
            let sc = b.select::<W>(ge, bm1, n);
            b.shr_a::<W>(x, sc)
        }
        Sh::Rol | Sh::Ror => {
            let bm = b.konst::<W>(W::from_u128(u128::from(bits - 1)));
            let n_mod = b.and::<W>(n, bm);
            let m = b.sub::<W>(bw, n_mod);
            let l = b.shl::<W>(x, if matches!(op, Sh::Rol) { n_mod } else { m });
            let r = b.shr_l::<W>(x, if matches!(op, Sh::Rol) { m } else { n_mod });
            b.or::<W>(l, r)
        }
        Sh::Rcl => {
            // (v<<ne) | (cf<<(ne-1)) | (v>>(bits+1-ne))。ne=0 なら v。
            let t1 = b.shl::<W>(x, ne);
            let nz = b.cmp::<W>(Cmp::Ne, ne, zw);
            let ne1 = b.sub::<W>(ne, ow);
            let t2s = b.shl::<W>(cfv, ne1);
            let t2 = b.select::<W>(nz, t2s, zw);
            let gt1 = b.cmp::<W>(Cmp::LtU, ow, ne);
            let rr = b.sub::<W>(b1w, ne);
            let t3s = b.shr_l::<W>(x, rr);
            let t3 = b.select::<W>(gt1, t3s, zw);
            let t = b.or::<W>(t1, t2);
            b.or::<W>(t, t3)
        }
        Sh::Rcr => {
            // (v>>ne) | (cf<<(bits-ne)) | (v<<(bits+1-ne))。ne=0 なら v。
            let t1 = b.shr_l::<W>(x, ne);
            let nz = b.cmp::<W>(Cmp::Ne, ne, zw);
            let sm = b.sub::<W>(bw, ne);
            let t2s = b.shl::<W>(cfv, sm);
            let t2 = b.select::<W>(nz, t2s, zw);
            let gt1 = b.cmp::<W>(Cmp::LtU, ow, ne);
            let rr = b.sub::<W>(b1w, ne);
            let t3s = b.shl::<W>(x, rr);
            let t3 = b.select::<W>(gt1, t3s, zw);
            let t = b.or::<W>(t1, t2);
            b.or::<W>(t, t3)
        }
        Sh::Setmo => unreachable!(),
    };
    wr_w::<B, W>(b, rm, d, v)?;
    // 旗: 回数が 0 なら据え置き。8088 の実測（SST）に基づく:
    //   CF = 最後に追い出されたビット（RCL/RCR は CF 込みの環から計算）
    //   OF = SHL/ROL/RCL: msb(v)^CF、ROR/RCR: msb(v)^msb-1(v)、
    //        SHR: 回数 1 のとき msb(x)、2 以上で 0、SAR: 0
    //   AF = SHL: v[4]、回転系: 不変、SHR/SAR: 0
    let old: B::V<W32> = b.get(eflags_ref());
    let active = b.cmp::<W>(Cmp::Ne, n, zw);
    let c1 = b.sub::<W>(n, ow);
    let safe_c1 = b.select::<W>(active, c1, zw);
    let topk = b.konst::<W>(W::from_u128(u128::from(bits - 1)));
    let cf_take: B::B = match op {
        Sh::Shl => {
            let s = b.shl::<W>(x, safe_c1);
            let t = b.shr_l::<W>(s, topk);
            let m = b.and::<W>(t, ow);
            b.cmp::<W>(Cmp::Ne, m, zw)
        }
        Sh::Shr => {
            let s = b.shr_l::<W>(x, safe_c1);
            let m = b.and::<W>(s, ow);
            b.cmp::<W>(Cmp::Ne, m, zw)
        }
        Sh::Sar => {
            // 回数が幅を超えるとき最後に出るビットは符号。
            let s = b.shr_l::<W>(x, safe_c1);
            let m = b.and::<W>(s, ow);
            let lt = b.cmp::<W>(Cmp::Ne, m, zw);
            let sg = b.shr_l::<W>(x, topk);
            let sgn = b.and::<W>(sg, ow);
            let sgb = b.cmp::<W>(Cmp::Ne, sgn, zw);
            // n <= bits: n-1 ビット目が最後に出る（n=bits でも msb=符号で一致）。
            let g1 = b.cmp::<W>(Cmp::LtU, n, b1w);
            let t1 = band(b, g1, lt);
            let g2 = b.cmp::<W>(Cmp::LtU, bw, n);
            let t2 = band(b, g2, sgb);
            bor(b, t1, t2)
        }
        Sh::Rol => {
            let m = b.and::<W>(v, ow);
            b.cmp::<W>(Cmp::Ne, m, zw)
        }
        Sh::Ror => {
            let t = b.shr_l::<W>(v, topk);
            let m = b.and::<W>(t, ow);
            b.cmp::<W>(Cmp::Ne, m, zw)
        }
        Sh::Rcl | Sh::Rcr => {
            // bits+1 環の位置 bits に来たビット。
            // rcl: idx = bits-ne（ne<=bits なので負にならない）。
            // rcr: idx = ne==0 ? bits : ne-1。
            let idx = if op == Sh::Rcl {
                b.sub::<W>(bw, ne)
            } else {
                let nz = b.cmp::<W>(Cmp::Ne, ne, zw);
                let d1 = b.sub::<W>(ne, ow);
                b.select::<W>(nz, d1, bw)
            };
            // idx == bits なら CF_in、それ以外は x[idx]。
            let is_t = b.cmp::<W>(Cmp::Eq, idx, bw);
            let s = b.shr_l::<W>(x, idx);
            let m = b.and::<W>(s, ow);
            let xb = b.cmp::<W>(Cmp::Ne, m, zw);
            let nt = bnot(b, is_t);
            let t1 = band(b, nt, xb);
            let t2 = band(b, is_t, cf0);
            bor(b, t1, t2)
        }
        Sh::Setmo => unreachable!(),
    };
    let cf = pick(b, cf_take, sem::FLAG_CF);
    let v_top = b.shr_l::<W>(v, topk);
    let v_msb = b.and::<W>(v_top, ow);
    let of_take: B::B = match op {
        Sh::Shl | Sh::Rol | Sh::Rcl => {
            let cfvv = b.select::<W>(cf_take, ow, zw);
            let t = b.xor::<W>(v_msb, cfvv);
            b.cmp::<W>(Cmp::Ne, t, zw)
        }
        Sh::Shr => {
            // 実測: 回数 1 のときのみ msb(x)、2 以上は 0。
            let t = b.shr_l::<W>(x, topk);
            let m = b.and::<W>(t, ow);
            let msb_x = b.cmp::<W>(Cmp::Ne, m, zw);
            let is1 = b.cmp::<W>(Cmp::Eq, n, ow);
            band(b, is1, msb_x)
        }
        Sh::Sar => {
            let m = b.and::<W>(v_msb, zw);
            b.cmp::<W>(Cmp::Ne, m, zw)
        }
        Sh::Ror | Sh::Rcr => {
            let k2 = b.konst::<W>(W::from_u128(u128::from(bits - 2)));
            let t2 = b.shr_l::<W>(v, k2);
            let t = b.xor::<W>(v_top, t2);
            let m = b.and::<W>(t, ow);
            b.cmp::<W>(Cmp::Ne, m, zw)
        }
        Sh::Setmo => unreachable!(),
    };
    let of = pick(b, of_take, sem::FLAG_OF);
    // AF: SHL は結果 bit4、SHR/SAR は 0、回転系は不変。
    let af = match op {
        Sh::Shl => {
            let four = b.konst::<W>(W::from_u128(4));
            let t = b.shr_l::<W>(v, four);
            let m = b.and::<W>(t, ow);
            let take = b.cmp::<W>(Cmp::Ne, m, zw);
            pick(b, take, sem::FLAG_AF)
        }
        Sh::Rol | Sh::Ror | Sh::Rcl | Sh::Rcr => {
            let m = b.konst::<W32>(sem::FLAG_AF);
            b.and::<W32>(old, m)
        }
        _ => b.konst::<W32>(0),
    };
    // シフト系は SZP を更新するが、回転系（ROL/ROR/RCL/RCR）は
    // SF/ZF/PF を変えない（SDM: CF と OF のみ）。
    let szp = if rot {
        let m = b.konst::<W32>(sem::FLAG_SF | sem::FLAG_ZF | sem::FLAG_PF);
        b.and::<W32>(old, m)
    } else {
        szp_bits(b, v)
    };
    let clear = b.konst::<W32>(!sem::FLAG_OSZPCA);
    let mut nf = b.and::<W32>(old, clear);
    nf = b.or::<W32>(nf, cf);
    nf = b.or::<W32>(nf, of);
    nf = b.or::<W32>(nf, af);
    nf = b.or::<W32>(nf, szp);
    let n32: B::V<W32> = b.trunc::<W, W32>(n);
    let zero32 = b.konst::<W32>(0);
    let active32 = b.cmp::<W32>(Cmp::Ne, n32, zero32);
    let assembled = b.select::<W32>(active32, nf, old);
    b.set(eflags_ref(), assembled);
    Ok(())
}

// ---- PUSH/POP ----

/// PUSH r/m（v は値幅。スタックは osize 幅）。
/// PUSH。被演算子は w 幅、スタックポインタの演算は `sa` 幅（16=SP/32=ESP/64=RSP）。
/// `sseg` は SS の基底（実モードではセレクタ<<4、フラットでは 0）。
pub fn push_v<B: Backend>(b: &mut B, w: u8, v64: B::V<W64>, sa: u8, sseg: u64) -> Flow<B> {
    let sp = Gpr(4);
    let sz = u64::from(w / 8);
    let sg = b.konst::<W64>(sseg);
    let a = match sa {
        16 => {
            let k = b.konst::<W32>(sz as u32);
            let cur: B::V<W32> = b.get(sp.state());
            let np32 = b.sub::<W32>(cur, k);
            // SP は下位 16 ビットだけ。上位は保持する。
            let m16 = b.konst::<W32>(0xFFFF);
            let lo = b.and::<W32>(np32, m16);
            let nm = b.konst::<W32>(0xFFFF_0000);
            let hi = b.and::<W32>(cur, nm);
            let np = b.or::<W32>(hi, lo);
            b.set(sp.state(), np);
            let off = b.zext::<W32, W64>(lo);
            b.add::<W64>(off, sg)
        }
        64 => {
            let k = b.konst::<W64>(sz);
            let cur = sem::read64(b, sp);
            let np = b.sub::<W64>(cur, k);
            sem::write64(b, sp, np);
            b.add::<W64>(np, sg)
        }
        _ => {
            let k = b.konst::<W32>(sz as u32);
            let cur: B::V<W32> = b.get(sp.state());
            let np = b.sub::<W32>(cur, k);
            b.set(sp.state(), np);
            let off = b.zext::<W32, W64>(np);
            b.add::<W64>(off, sg)
        }
    };
    // 実モードでは SP が 64K で折り返す（SP=0xffff への push は
    // 上位バイトがオフセット 0 に書かれる）。
    let wseg = (sa == 16).then_some(sseg);
    match w {
        16 => {
            let v: B::V<W16> = b.trunc::<W64, W16>(v64);
            decode::mem_store(b, a, wseg, v)
        }
        64 => decode::mem_store::<B, W64>(b, a, wseg, v64),
        _ => {
            let v: B::V<W32> = b.trunc::<W64, W32>(v64);
            decode::mem_store(b, a, wseg, v)
        }
    }
}

/// POP → 値幅 w で返す。ポインタ演算は `sa` 幅、読み込み番地は `sseg`+SP。
pub fn pop_v<B: Backend>(b: &mut B, w: u8, sa: u8, sseg: u64) -> Result<B::V<W64>, B::Exit> {
    let sp = Gpr(4);
    let sz = u64::from(w / 8);
    let sg = b.konst::<W64>(sseg);
    let (a, np_done) = match sa {
        16 => {
            let cur: B::V<W32> = b.get(sp.state());
            let m16 = b.konst::<W32>(0xFFFF);
            let lo = b.and::<W32>(cur, m16);
            let off = b.zext::<W32, W64>(lo);
            let a = b.add::<W64>(off, sg);
            let k = b.konst::<W32>(sz as u32);
            let nlo = b.add::<W32>(lo, k);
            let nm = b.konst::<W32>(0xFFFF_0000);
            let hi = b.and::<W32>(cur, nm);
            let np = b.or::<W32>(hi, nlo);
            (a, np)
        }
        64 => {
            let cur = sem::read64(b, sp);
            let a = b.add::<W64>(cur, sg);
            let k = b.konst::<W64>(sz);
            let np = b.add::<W64>(cur, k);
            let np64 = np;
            sem::write64(b, sp, np64);
            (a, b.trunc::<W64, W32>(np))
        }
        _ => {
            let cur: B::V<W32> = b.get(sp.state());
            let off = b.zext::<W32, W64>(cur);
            let a = b.add::<W64>(off, sg);
            let k = b.konst::<W32>(sz as u32);
            let np = b.add::<W32>(cur, k);
            (a, np)
        }
    };
    if sa != 64 {
        b.set(sp.state(), np_done);
    }
    let wseg = (sa == 16).then_some(sseg);
    match w {
        16 => {
            let v: B::V<W16> = decode::mem_load(b, a, wseg)?;
            Ok(b.zext::<W16, W64>(v))
        }
        64 => decode::mem_load::<B, W64>(b, a, wseg),
        _ => {
            let v: B::V<W32> = decode::mem_load(b, a, wseg)?;
            Ok(b.zext::<W32, W64>(v))
        }
    }
}

// ---- 分岐 ----

/// 条件付き相対分岐（eip は命令先頭、len は命令長）。
pub fn jcc<B: Backend>(b: &mut B, n: u8, eip: u32, len: u32, rel: i64) -> Flow<B> {
    let take = cc(b, n);
    jcc_take(b, eip, len, rel, take)
}

fn jcc_take<B: Backend>(b: &mut B, eip: u32, len: u32, rel: i64, take: B::B) -> Flow<B> {
    let target = eip.wrapping_add(len).wrapping_add(rel as i32 as u32);
    let t = b.konst::<W32>(target);
    let tj = b.konst::<W64>(u64::from(target));
    b.if_then(take, |b| {
        b.set(eip_ref(), t);
        b.jump(tj);
        Ok(())
    })?;
    Ok(())
}

/// 無条件相対分岐。
pub fn jmp_rel<B: Backend>(b: &mut B, eip: u32, len: u32, rel: i64) -> Flow<B> {
    let target = eip.wrapping_add(len).wrapping_add(rel as i32 as u32);
    let t32 = b.konst::<W32>(target);
    b.set(eip_ref(), t32);
    let t64 = b.konst::<W64>(u64::from(target));
    b.jump(t64);
    Ok(())
}

/// 幅 w の被演算子を 64 ビット値として読む。
fn rd_any<B: Backend>(
    b: &mut B,
    w: u8,
    rm: &Rm<B::V<W64>>,
    d: &MapDec,
) -> Result<B::V<W64>, B::Exit> {
    match w {
        16 => {
            let v = rd_w::<B, W16>(b, rm, d)?;
            Ok(b.zext::<W16, W64>(v))
        }
        64 => rd_w::<B, W64>(b, rm, d),
        _ => {
            let v = rd_w::<B, W32>(b, rm, d)?;
            Ok(b.zext::<W32, W64>(v))
        }
    }
}

/// 間接分岐（r/m の値へ）。
pub fn jmp_rm<B: Backend>(b: &mut B, w: u8, rm: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    let t = rd_any::<B>(b, w, rm, d)?;
    let t32: B::V<W32> = b.trunc::<W64, W32>(t);
    b.set(eip_ref(), t32);
    b.jump(t);
    Ok(())
}

/// CALL rel。戻り番地（次の命令）を積んで分岐。
pub fn call_rel<B: Backend>(
    b: &mut B,
    eip: u32,
    len: u32,
    rel: i64,
    stack_w: u8,
    sa: u8,
    sseg: u64,
) -> Flow<B> {
    let next = eip.wrapping_add(len);
    let nv = b.konst::<W64>(u64::from(next));
    push_v(b, stack_w, nv, sa, sseg)?;
    jmp_rel(b, eip, len, rel)
}

/// CALL r/m。
#[allow(clippy::too_many_arguments)]
pub fn call_rm<B: Backend>(
    b: &mut B,
    w: u8,
    rm: &Rm<B::V<W64>>,
    d: &MapDec,
    eip: u32,
    len: u32,
    sa: u8,
    sseg: u64,
) -> Flow<B> {
    let next = eip.wrapping_add(len);
    let t = rd_any::<B>(b, w, rm, d)?;
    let nv = b.konst::<W64>(u64::from(next));
    push_v(b, w, nv, sa, sseg)?;
    let t32: B::V<W32> = b.trunc::<W64, W32>(t);
    b.set(eip_ref(), t32);
    b.jump(t);
    Ok(())
}

/// SP に iw を積み増しする。ポインタ更新はスタックアドレス幅 sa に従う。
fn sp_add_iw<B: Backend>(b: &mut B, iw: u16, sa: u8) {
    let sp = Gpr(4);
    match sa {
        64 => {
            let cur = sem::read64(b, sp);
            let k = b.konst::<W64>(u64::from(iw));
            let np = b.add::<W64>(cur, k);
            sem::write64(b, sp, np);
        }
        16 => {
            let cur: B::V<W32> = b.get(sp.state());
            let k = b.konst::<W32>(u32::from(iw));
            let np32 = b.add::<W32>(cur, k);
            let m16 = b.konst::<W32>(0xFFFF);
            let lo = b.and::<W32>(np32, m16);
            let nm = b.konst::<W32>(0xFFFF_0000);
            let hi = b.and::<W32>(cur, nm);
            let np = b.or::<W32>(hi, lo);
            b.set(sp.state(), np);
        }
        _ => {
            let cur: B::V<W32> = b.get(sp.state());
            let k = b.konst::<W32>(u32::from(iw));
            let np = b.add::<W32>(cur, k);
            b.set(sp.state(), np);
        }
    }
}

/// RET。pop で戻る。iw は積み増し。
pub fn ret<B: Backend>(b: &mut B, w: u8, iw: u16, sa: u8, sseg: u64) -> Flow<B> {
    let v = pop_v(b, w, sa, sseg)?;
    if iw != 0 {
        sp_add_iw(b, iw, sa);
    }
    let t32: B::V<W32> = b.trunc::<W64, W32>(v);
    b.set(eip_ref(), t32);
    b.jump(v);
    Ok(())
}

// ---- 実モードの far 転移・割り込み ----

/// far 分岐先 (off, sel) へ CS:IP を設定し、実モードの物理番地
/// `sel<<4 + off` へ分岐する。
fn jmp_far<B: Backend>(b: &mut B, off: B::V<W64>, sel: B::V<W16>) -> Flow<B> {
    b.set(sem::sreg_ref(1), sel);
    let ip: B::V<W32> = b.trunc::<W64, W32>(off);
    b.set(eip_ref(), ip);
    let sel64 = b.zext::<W16, W64>(sel);
    let sh = b.konst::<W64>(4);
    let base = b.shl::<W64>(sel64, sh);
    let target = b.add::<W64>(base, off);
    b.jump(target);
    Ok(())
}

/// JMPF ptr16:v（直値 far ポインタ）。
pub fn jmpf_ptr<B: Backend>(b: &mut B, off: u64, sel: u64) -> Flow<B> {
    let o = b.konst::<W64>(off);
    let s = b.konst::<W16>(sel as u16);
    jmp_far(b, o, s)
}

/// CALLF ptr16:v。CS、次の IP の順に積んで far 分岐する。
pub fn callf_ptr<B: Backend>(
    b: &mut B,
    off: u64,
    sel: u64,
    eip: u32,
    len: u32,
    sa: u8,
    sseg: u64,
) -> Flow<B> {
    let cs: B::V<W16> = b.get(sem::sreg_ref(1));
    let cs64 = b.zext::<W16, W64>(cs);
    push_v(b, 16, cs64, sa, sseg)?;
    let next = eip.wrapping_add(len) & 0xFFFF;
    let nv = b.konst::<W64>(u64::from(next));
    push_v(b, 16, nv, sa, sseg)?;
    jmpf_ptr(b, off, sel)
}

/// RETF。IP、CS の順に戻す。iw は積み増し。
pub fn retf<B: Backend>(b: &mut B, iw: u16, sa: u8, sseg: u64) -> Flow<B> {
    let ip = pop_v(b, 16, sa, sseg)?;
    let cs64 = pop_v(b, 16, sa, sseg)?;
    if iw != 0 {
        sp_add_iw(b, iw, sa);
    }
    let sel: B::V<W16> = b.trunc::<W64, W16>(cs64);
    jmp_far(b, ip, sel)
}

/// far ポインタ（オフセット、セレクタ）。
type FarPtr<B> = (<B as Backend>::V<W64>, <B as Backend>::V<W16>);

/// m16:v の far ポインタ（off は v 幅、seg は 16 ビット）を読む。
/// レジスタ形は far ポインタを構成できないので None。
fn load_far_ptr<B: Backend>(
    b: &mut B,
    w: u8,
    rm: &Rm<B::V<W64>>,
) -> Result<Option<FarPtr<B>>, B::Exit> {
    let Rm::Mem { a, wseg } = rm else {
        return Ok(None);
    };
    let off: B::V<W64> = match w {
        16 => {
            let v: B::V<W16> = decode::mem_load(b, *a, *wseg)?;
            b.zext::<W16, W64>(v)
        }
        _ => {
            let v: B::V<W32> = decode::mem_load(b, *a, *wseg)?;
            b.zext::<W32, W64>(v)
        }
    };
    let adv = b.konst::<W64>(u64::from(w / 8));
    let a2 = b.add::<W64>(*a, adv);
    let seg: B::V<W16> = decode::mem_load(b, a2, *wseg)?;
    Ok(Some((off, seg)))
}

/// CALLF/JMPF m16:v。far ポインタを読み、`is_call` なら CS と
/// 次の IP を積んでから分岐する。
#[allow(clippy::too_many_arguments)]
pub fn far_rm<B: Backend>(
    b: &mut B,
    w: u8,
    rm: &Rm<B::V<W64>>,
    is_call: bool,
    eip: u32,
    len: u32,
    sa: u8,
    sseg: u64,
) -> Flow<B> {
    let Some((off, sel)) = load_far_ptr(b, w, rm)? else {
        return Ok(());
    };
    if is_call {
        let cs: B::V<W16> = b.get(sem::sreg_ref(1));
        let cs64 = b.zext::<W16, W64>(cs);
        push_v(b, 16, cs64, sa, sseg)?;
        let next = eip.wrapping_add(len) & 0xFFFF;
        let nv = b.konst::<W64>(u64::from(next));
        push_v(b, 16, nv, sa, sseg)?;
    }
    jmp_far(b, off, sel)
}

/// 実モード割り込み。FLAGS、CS、次の IP の順に積み、IF=TF=0 に
/// して IVT[vec] へ far 分岐する。divide error もこの経路で、
/// 積まれる IP は除算命令の次を指す（8088 の実動作）。
pub fn int_real<B: Backend>(b: &mut B, eip: u32, len: u32, vec: u8, sa: u8, sseg: u64) -> Flow<B> {
    let fl: B::V<W32> = b.get(eflags_ref());
    let fl64 = b.zext::<W32, W64>(fl);
    push_v(b, 16, fl64, sa, sseg)?;
    // IF(bit9) と TF(bit8) を落とす。
    let m = b.konst::<W32>(!0x300u32);
    let n = b.and::<W32>(fl, m);
    b.set(eflags_ref(), n);
    let cs: B::V<W16> = b.get(sem::sreg_ref(1));
    let cs64 = b.zext::<W16, W64>(cs);
    push_v(b, 16, cs64, sa, sseg)?;
    let next = eip.wrapping_add(len) & 0xFFFF;
    let nv = b.konst::<W64>(u64::from(next));
    push_v(b, 16, nv, sa, sseg)?;
    // IVT の物理番地は vec*4（+2 がセレクタ）。
    let va = b.konst::<W64>(u64::from(vec) * 4);
    let ip: B::V<W16> = decode::mem_load(b, va, None)?;
    let adv = b.konst::<W64>(2);
    let ca = b.add::<W64>(va, adv);
    let cs2: B::V<W16> = decode::mem_load(b, ca, None)?;
    let off = b.zext::<W16, W64>(ip);
    jmp_far(b, off, cs2)
}

/// INTO。OF が立っていれば割り込み 4。
pub fn into_real<B: Backend>(b: &mut B, eip: u32, len: u32, sa: u8, sseg: u64) -> Flow<B> {
    let of = read_of(b);
    b.if_then(of, |b| int_real(b, eip, len, 4, sa, sseg))
}

/// IRET（実モード）。IP、CS、FLAGS を pop する。
pub fn iret_real<B: Backend>(b: &mut B, sa: u8, sseg: u64) -> Flow<B> {
    let ip = pop_v(b, 16, sa, sseg)?;
    let cs64 = pop_v(b, 16, sa, sseg)?;
    let fl64 = pop_v(b, 16, sa, sseg)?;
    let fl32: B::V<W32> = b.trunc::<W64, W32>(fl64);
    // POPF と同じ強制ビット（bit1=1、bit3/5=0、bit12-15 は常に 1）。
    let m = b.konst::<W32>(0x0FD5);
    let low = b.and::<W32>(fl32, m);
    let forced = b.konst::<W32>(0xF002);
    let low = b.or::<W32>(low, forced);
    let cur = b.get(eflags_ref());
    let him = b.konst::<W32>(0xFFFF_0000);
    let hi = b.and::<W32>(cur, him);
    let merged = b.or::<W32>(hi, low);
    b.set(eflags_ref(), merged);
    let sel: B::V<W16> = b.trunc::<W64, W16>(cs64);
    jmp_far(b, ip, sel)
}

/// IN AL/AX/EAX, port。ポート番号は 16 ビットで、読み出した
/// 値はアキュムレータへ入る。フラグは変わらない。
pub fn io_in<B: Backend>(b: &mut B, w: u8, port: B::V<W64>, d: &MapDec) -> Flow<B> {
    match w {
        8 => {
            let v = b.port_in::<W8>(port)?;
            W8::put(b, Gpr(0), d, v);
        }
        16 => {
            let v = b.port_in::<W16>(port)?;
            W16::put(b, Gpr(0), d, v);
        }
        _ => {
            let v = b.port_in::<W32>(port)?;
            W32::put(b, Gpr(0), d, v);
        }
    }
    Ok(())
}

/// OUT port, AL/AX/EAX。アキュムレータの値をポートへ書く。
/// フラグは変わらない。
pub fn io_out<B: Backend>(b: &mut B, w: u8, port: B::V<W64>, d: &MapDec) -> Flow<B> {
    match w {
        8 => {
            let v = W8::get(b, Gpr(0), d);
            b.port_out::<W8>(port, v)
        }
        16 => {
            let v = W16::get(b, Gpr(0), d);
            b.port_out::<W16>(port, v)
        }
        _ => {
            let v = W32::get(b, Gpr(0), d);
            b.port_out::<W32>(port, v)
        }
    }
}

// ---- SETcc/CMOVcc ----

/// SETcc r/m8。
pub fn setcc<B: Backend>(b: &mut B, n: u8, rm: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    let take = cc(b, n);
    let one = b.konst::<W8>(1);
    let zero = b.konst::<W8>(0);
    let v = b.select::<W8>(take, one, zero);
    wr_w::<B, W8>(b, rm, d, v)
}

/// CMOVcc G,E（取らなければ何もしない）。
pub fn cmov<B: Backend>(
    b: &mut B,
    n: u8,
    w: u8,
    dst: Gpr,
    rm: &Rm<B::V<W64>>,
    d: &MapDec,
) -> Flow<B> {
    let take = cc(b, n);
    match w {
        16 => {
            let v = rd_w::<B, W16>(b, rm, d)?;
            let cur = grd_w::<B, W16>(b, dst, d);
            let sv = b.select::<W16>(take, v, cur);
            gwr_w::<B, W16>(b, dst, d, sv);
        }
        32 => {
            let v = rd_w::<B, W32>(b, rm, d)?;
            let cur = grd_w::<B, W32>(b, dst, d);
            let sv = b.select::<W32>(take, v, cur);
            gwr_w::<B, W32>(b, dst, d, sv);
        }
        _ => {
            let v = rd_w::<B, W64>(b, rm, d)?;
            let cur = grd_w::<B, W64>(b, dst, d);
            let sv = b.select::<W64>(take, v, cur);
            sem::write64(b, dst, sv);
        }
    }
    Ok(())
}

// ---- その他の単機能 ----

/// BSWAP。
pub fn bswap<B: Backend>(b: &mut B, w: u8, g: Gpr) -> Flow<B> {
    if w == 64 {
        return sem::bswap_r64(b, g);
    }
    if w == 32 {
        return sem::bswap_r32(b, g);
    }
    Ok(())
}

/// CBW/CWDE/CDQE（98）：AL→AX / AX→EAX / EAX→RAX の符号拡張。
/// ソースはターゲット幅の半分。
pub fn cwde<B: Backend>(b: &mut B, w: u8, d: &MapDec) -> Flow<B> {
    match w {
        16 => {
            let al = sem::read8(b, Gpr(0), false);
            let v = b.sext::<W8, W16>(al);
            gwr_w::<B, W16>(b, Gpr(0), d, v);
        }
        32 => {
            let ax = grd_w::<B, W16>(b, Gpr(0), d);
            let v = b.sext::<W16, W32>(ax);
            gwr_w::<B, W32>(b, Gpr(0), d, v);
        }
        _ => {
            let eax = grd_w::<B, W32>(b, Gpr(0), d);
            let v = b.sext::<W32, W64>(eax);
            sem::write64(b, Gpr(0), v);
        }
    }
    Ok(())
}

/// CDQ 系（99）：AX→DX:AX / EAX→EDX:EAX / RAX→RDX:RAX。
pub fn cdq<B: Backend>(b: &mut B, w: u8) -> Flow<B> {
    match w {
        16 => {
            let ax = {
                let v: B::V<W32> = b.get(Gpr(0).state());
                b.trunc::<W32, W16>(v)
            };
            let neg = {
                let s = b.konst::<W16>(15);
                b.shr_a::<W16>(ax, s)
            };
            let cur: B::V<W32> = b.get(Gpr(2).state());
            let mask = b.konst::<W32>(0xffff_0000);
            let kept = b.and::<W32>(cur, mask);
            let v32 = b.zext::<W16, W32>(neg);
            let merged = b.or::<W32>(kept, v32);
            b.set(Gpr(2).state(), merged);
        }
        32 => {
            let ax: B::V<W32> = b.get(Gpr(0).state());
            let s = b.konst::<W32>(31);
            let v = b.shr_a::<W32>(ax, s);
            b.set(Gpr(2).state(), v);
            sem::clear_hi(b, Gpr(2));
        }
        _ => {
            let ax = sem::read64(b, Gpr(0));
            let s = b.konst::<W64>(63);
            let v = b.shr_a::<W64>(ax, s);
            sem::write64(b, Gpr(2), v);
        }
    }
    Ok(())
}

/// SAHF：AH を旗の低8ビット（SF/ZF/AF/PF/CF）に入れる。
pub fn sahf<B: Backend>(b: &mut B) -> Flow<B> {
    let ah = sem::read8(b, Gpr(0), true);
    let mask = b.konst::<W8>(0xd5); // SF|ZF|AF|PF|CF
    let bits = b.and::<W8>(ah, mask);
    let f = b.get(eflags_ref());
    let kmask = b.konst::<W32>(!0xd5u32 | 0x2);
    let keep = b.and::<W32>(f, kmask);
    let v = b.zext::<W8, W32>(bits);
    let two = b.konst::<W32>(0x2);
    let fixed = b.or::<W32>(v, two);
    let merged = b.or::<W32>(keep, fixed);
    b.set(eflags_ref(), merged);
    Ok(())
}

/// LAHF：旗の低8ビットを AH に入れる。
pub fn lahf<B: Backend>(b: &mut B) -> Flow<B> {
    let f = b.get(eflags_ref());
    let v = b.trunc::<W32, W8>(f);
    sem::write8(b, Gpr(0), true, v);
    Ok(())
}

/// フラグ操作（CLC/STC/CMC/CLD/STD）。
pub fn flagop<B: Backend>(b: &mut B, bit: u32, op: u8) -> Flow<B> {
    let f = b.get(eflags_ref());
    let m = b.konst::<W32>(bit);
    let nm = b.not::<W32>(m);
    let v = match op {
        0 => b.and::<W32>(f, nm), // clear
        1 => b.or::<W32>(f, m),   // set
        _ => b.xor::<W32>(f, m),  // complement
    };
    b.set(eflags_ref(), v);
    Ok(())
}

/// NOP。
pub fn nop<B: Backend>(_b: &mut B) -> Flow<B> {
    Ok(())
}

/// UD2 / HLT 等のトラップ（ユーザーモードは #UD/#GP）。
pub fn trap<B: Backend>(b: &mut B, eip: u32, code: u64) -> Flow<B> {
    use polyisa_sem::{ExceptionKind, GuestException};
    Err(b.raise(GuestException {
        kind: ExceptionKind::Trap,
        code,
        addr: Some(u64::from(eip)),
        in_delay_slot: false,
    }))
}

/// INT n（OS パーソナリティが処理する退出）。
pub fn int_n<B: Backend>(b: &mut B, eip: u32, n: u8) -> Flow<B> {
    use polyisa_sem::{ExceptionKind, GuestException};
    Err(b.raise(GuestException {
        kind: ExceptionKind::Trap,
        code: u64::from(n),
        addr: Some(u64::from(eip)),
        in_delay_slot: false,
    }))
}

// ---- 追加の幅汎用命令 ----

/// CF/OF を同じ値に更新し、他のフラグは保存する（IMUL: SZPA は未定義）。
fn set_cf_of<B: Backend>(b: &mut B, ovf: B::B) {
    let old: B::V<W32> = b.get(eflags_ref());
    let m = sem::FLAG_CF | sem::FLAG_OF;
    let nm = b.konst::<W32>(!m);
    let cleared = b.and::<W32>(old, nm);
    let mv = b.konst::<W32>(m);
    let z0 = b.konst::<W32>(0);
    let on = b.select::<W32>(ovf, mv, z0);
    let efl = b.or::<W32>(cleared, on);
    b.set(eflags_ref(), efl);
}

fn imul3_w<B: Backend, W: Hw>(
    b: &mut B,
    g: Gpr,
    ea: &Rm<B::V<W64>>,
    d: &MapDec,
    imm: i64,
) -> Flow<B> {
    let x = rd_w::<B, W>(b, ea, d)?;
    let y = b.konst::<W>(W::from_u128(imm as u64 as u128));
    let lo = b.mul::<W>(x, y);
    let hi = b.mulh::<W>(x, y);
    let sh = b.konst::<W>(W::from_u128(u128::from(W::BITS - 1)));
    let expect = b.shr_a::<W>(lo, sh);
    let ovf = b.cmp::<W>(Cmp::Ne, hi, expect);
    W::put(b, g, d, lo);
    set_cf_of(b, ovf);
    Ok(())
}

fn imul2_w<B: Backend, W: Hw>(b: &mut B, g: Gpr, ea: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    let x = W::get(b, g, d);
    let y = rd_w::<B, W>(b, ea, d)?;
    let lo = b.mul::<W>(x, y);
    let hi = b.mulh::<W>(x, y);
    let sh = b.konst::<W>(W::from_u128(u128::from(W::BITS - 1)));
    let expect = b.shr_a::<W>(lo, sh);
    let ovf = b.cmp::<W>(Cmp::Ne, hi, expect);
    W::put(b, g, d, lo);
    set_cf_of(b, ovf);
    Ok(())
}

/// IMUL Gv, Ev（2 被演算子形）。
pub fn imul2<B: Backend>(b: &mut B, w: u8, g: Gpr, ea: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    match w {
        16 => imul2_w::<B, W16>(b, g, ea, d),
        64 => imul2_w::<B, W64>(b, g, ea, d),
        _ => imul2_w::<B, W32>(b, g, ea, d),
    }
}

/// IMUL Gv, Ev, Iz/Ib（3 被演算子形）。CF/OF=積が幅に収まらないとき 1。
pub fn imul3<B: Backend>(
    b: &mut B,
    w: u8,
    g: Gpr,
    ea: &Rm<B::V<W64>>,
    d: &MapDec,
    imm: i64,
) -> Flow<B> {
    match w {
        16 => imul3_w::<B, W16>(b, g, ea, d, imm),
        64 => imul3_w::<B, W64>(b, g, ea, d, imm),
        _ => imul3_w::<B, W32>(b, g, ea, d, imm),
    }
}

fn cmpxchg_w<B: Backend, W: Hw>(b: &mut B, ea: &Rm<B::V<W64>>, d: &MapDec, src: Gpr) -> Flow<B> {
    let t = rd_w::<B, W>(b, ea, d)?;
    let acc = W::get(b, Gpr(0), d);
    let v = b.sub::<W>(acc, t);
    update_sub_flags(b, acc, t, v);
    let zero = b.konst::<W>(W::from_u128(0));
    let eq = b.cmp::<W>(Cmp::Eq, v, zero);
    let new_acc = b.select::<W>(eq, acc, t);
    W::put(b, Gpr(0), d, new_acc);
    let sv = W::get(b, src, d);
    b.if_then(eq, |b| wr_w::<B, W>(b, ea, d, sv))?;
    Ok(())
}

/// CMPXCHG r/m, r（AL/AX/EAX/RAX と比較）。
pub fn cmpxchg<B: Backend>(b: &mut B, w: u8, ea: &Rm<B::V<W64>>, d: &MapDec, src: Gpr) -> Flow<B> {
    match w {
        8 => cmpxchg_w::<B, W8>(b, ea, d, src),
        16 => cmpxchg_w::<B, W16>(b, ea, d, src),
        64 => cmpxchg_w::<B, W64>(b, ea, d, src),
        _ => cmpxchg_w::<B, W32>(b, ea, d, src),
    }
}

fn xadd_w<B: Backend, W: Hw>(b: &mut B, ea: &Rm<B::V<W64>>, d: &MapDec, src: Gpr) -> Flow<B> {
    let t = rd_w::<B, W>(b, ea, d)?;
    let s = W::get(b, src, d);
    let v = b.add::<W>(t, s);
    update_add_flags(b, t, s, v);
    wr_w::<B, W>(b, ea, d, v)?;
    W::put(b, src, d, t);
    Ok(())
}

/// XADD r/m, r（交換しつつ加算）。
pub fn xadd<B: Backend>(b: &mut B, w: u8, ea: &Rm<B::V<W64>>, d: &MapDec, src: Gpr) -> Flow<B> {
    match w {
        8 => xadd_w::<B, W8>(b, ea, d, src),
        16 => xadd_w::<B, W16>(b, ea, d, src),
        64 => xadd_w::<B, W64>(b, ea, d, src),
        _ => xadd_w::<B, W32>(b, ea, d, src),
    }
}

fn bsfx_w<B: Backend, W: Hw>(
    b: &mut B,
    msb: bool,
    g: Gpr,
    ea: &Rm<B::V<W64>>,
    d: &MapDec,
) -> Flow<B> {
    let v = rd_w::<B, W>(b, ea, d)?;
    let zero = b.konst::<W>(W::from_u128(0));
    let one = b.konst::<W>(W::from_u128(1));
    let is_zero = b.cmp::<W>(Cmp::Eq, v, zero);
    let sentinel = b.konst::<W>(W::from_u128(u128::from(W::BITS)));
    let mut acc = sentinel;
    for i in 0..W::BITS {
        let bit = b.konst::<W>(W::from_u128(1u128 << i));
        let t = b.and::<W>(v, bit);
        let set = b.cmp::<W>(Cmp::Ne, t, zero);
        let idx = b.konst::<W>(W::from_u128(u128::from(i)));
        acc = if msb {
            b.select::<W>(set, idx, acc)
        } else {
            let undecided = b.cmp::<W>(Cmp::Eq, acc, sentinel);
            let s_n = b.select::<W>(set, one, zero);
            let u_n = b.select::<W>(undecided, one, zero);
            let both = b.and::<W>(s_n, u_n);
            let take = b.cmp::<W>(Cmp::Ne, both, zero);
            b.select::<W>(take, idx, acc)
        };
    }
    let dst = b.select::<W>(is_zero, zero, acc);
    W::put(b, g, d, dst);
    let old: B::V<W32> = b.get(eflags_ref());
    let nzf = b.konst::<W32>(!sem::FLAG_ZF);
    let cleared = b.and::<W32>(old, nzf);
    let zon = b.konst::<W32>(sem::FLAG_ZF);
    let zoff = b.konst::<W32>(0);
    let zf = b.select::<W32>(is_zero, zon, zoff);
    let efl = b.or::<W32>(cleared, zf);
    b.set(eflags_ref(), efl);
    Ok(())
}

/// BSF/BSR r, r/m（msb=true で BSR）。
pub fn bsfx<B: Backend>(
    b: &mut B,
    w: u8,
    msb: bool,
    g: Gpr,
    ea: &Rm<B::V<W64>>,
    d: &MapDec,
) -> Flow<B> {
    match w {
        16 => bsfx_w::<B, W16>(b, msb, g, ea, d),
        64 => bsfx_w::<B, W64>(b, msb, g, ea, d),
        _ => bsfx_w::<B, W32>(b, msb, g, ea, d),
    }
}

/// LOOPNE/LOOPE/LOOP/JcXZ。カウンタ幅はアドレスサイズ（CX/ECX/RCX）に従う。
/// kind: 0=LOOPNE 1=LOOPE 2=LOOP 3=JcXZ。
pub fn loopcc<B: Backend>(
    b: &mut B,
    kind: u8,
    eip: u32,
    len: u32,
    rel: i64,
    d: &MapDec,
) -> Flow<B> {
    let m: u64 = match d.asize {
        16 => 0xffff,
        32 => 0xffff_ffff,
        _ => u64::MAX,
    };
    let c0 = sem::read64(b, Gpr(1));
    let mm = b.konst::<W64>(m);
    let c0m = b.and::<W64>(c0, mm);
    let one = b.konst::<W64>(1);
    let zero64 = b.konst::<W64>(0);
    let dec = b.sub::<W64>(c0m, one);
    let c1 = b.and::<W64>(dec, mm);
    if kind != 3 {
        let nmm = b.konst::<W64>(!m);
        let rest = b.and::<W64>(c0, nmm);
        let nv2 = b.or::<W64>(rest, c1);
        sem::write64(b, Gpr(1), nv2);
    }
    let nz = b.cmp::<W64>(Cmp::Ne, c1, zero64);
    let zf = read_zf(b);
    let zv = b.select::<W64>(zf, one, zero64);
    let nv = b.select::<W64>(nz, one, zero64);
    let take_v = match kind {
        0 => {
            let zinv = b.xor::<W64>(zv, one);
            b.and::<W64>(nv, zinv)
        }
        1 => b.and::<W64>(nv, zv),
        2 => nv,
        _ => {
            let is_z = b.cmp::<W64>(Cmp::Eq, c0m, zero64);
            b.select::<W64>(is_z, one, zero64)
        }
    };
    let take = b.cmp::<W64>(Cmp::Ne, take_v, zero64);
    jcc_take(b, eip, len, rel, take)
}

/// ENTER imm16, imm8（レベルは下位 5 ビット）。非 64 ビットモードのみ。
pub fn enter<B: Backend>(b: &mut B, w: u8, frame: u64, level: u64, sa: u8, sseg: u64) -> Flow<B> {
    let lvl = level & 31;
    let m: u64 = if w == 16 { 0xffff } else { 0xffff_ffff };
    let mm = b.konst::<W64>(m);
    let bp = sem::read64(b, Gpr(5));
    let bp = b.and::<W64>(bp, mm);
    push_v(b, w, bp, sa, sseg)?;
    let sp0 = sem::read64(b, Gpr(4));
    let sp0 = b.and::<W64>(sp0, mm);
    let bytes = b.konst::<W64>(u64::from(w / 8));
    let sg = b.konst::<W64>(sseg);
    if lvl > 0 {
        let mut p = sp0;
        for _ in 1..lvl {
            let pv = b.sub::<W64>(p, bytes);
            p = b.and::<W64>(pv, mm);
            let pa = b.add::<W64>(p, sg);
            let v = b.load::<W64>(pa, sem::DATA_READ)?;
            let vm = b.and::<W64>(v, mm);
            push_v(b, w, vm, sa, sseg)?;
        }
        push_v(b, w, sp0, sa, sseg)?;
    }
    let nmm = b.konst::<W64>(!m);
    let rbp = sem::read64(b, Gpr(5));
    let bhi = b.and::<W64>(rbp, nmm);
    let nbp = b.or::<W64>(bhi, sp0);
    sem::write64(b, Gpr(5), nbp);
    let cur = sem::read64(b, Gpr(4));
    let fv = b.konst::<W64>(frame & m);
    let sub = b.sub::<W64>(cur, fv);
    let lo = b.and::<W64>(sub, mm);
    let shi = b.and::<W64>(cur, nmm);
    let nsp = b.or::<W64>(shi, lo);
    sem::write64(b, Gpr(4), nsp);
    Ok(())
}

/// XLAT: AL = [seg:BX/EBX/RBX + AL]（asize 幅のベース）。
pub fn xlat<B: Backend>(b: &mut B, d: &MapDec, seg: u64) -> Flow<B> {
    let bx = sem::read64(b, Gpr(3));
    let base = match d.asize {
        16 => {
            let m16 = b.konst::<W64>(0xffff);
            b.and::<W64>(bx, m16)
        }
        32 => {
            let m32 = b.konst::<W64>(0xffff_ffff);
            b.and::<W64>(bx, m32)
        }
        _ => bx,
    };
    let al = sem::read8(b, Gpr(0), false);
    let al64 = b.zext::<W8, W64>(al);
    let addr = b.add::<W64>(base, al64);
    // オフセットはアドレスサイズに折り返す（8088 の XLAT は
    // BX+AL が 0xFFFF を越えるとセグメント内で巻き戻る）。
    let addr = match d.asize {
        16 => {
            let m16 = b.konst::<W64>(0xffff);
            b.and::<W64>(addr, m16)
        }
        32 => {
            let m32 = b.konst::<W64>(0xffff_ffff);
            b.and::<W64>(addr, m32)
        }
        _ => addr,
    };
    let sb = b.konst::<W64>(seg);
    let addr = b.add::<W64>(addr, sb);
    let v = b.load::<W8>(addr, sem::DATA_READ)?;
    sem::write8(b, Gpr(0), false, v);
    Ok(())
}

/// RDTSC: EDX:EAX = 仮想タイムスタンプ。現段階は決定論的な 0（時間モデル未実装）。
pub fn rdtsc<B: Backend>(b: &mut B) -> Flow<B> {
    let z = b.konst::<W32>(0);
    decode::gwr32(b, Gpr(0), z);
    decode::gwr32(b, Gpr(2), z);
    Ok(())
}

/// RDTSCP。RDTSC に加えて ECX に TSC_AUX を返す（0 固定）。
pub fn rdtscp<B: Backend>(b: &mut B) -> Flow<B> {
    rdtsc(b)?;
    let z = b.konst::<W32>(0);
    decode::gwr32(b, Gpr(1), z);
    Ok(())
}

// ---- 文字列命令 ----

/// 文字列命令の種別。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Str {
    Movs,
    Stos,
    Lods,
    Scas,
    Cmps,
}

fn asize_mask(asize: u8) -> u64 {
    match asize {
        16 => 0xffff,
        32 => 0xffff_ffff,
        _ => u64::MAX,
    }
}

/// 文字列ポインタ（ESI/EDI 系）を asize 幅で読む。
fn sptr<B: Backend>(b: &mut B, g: Gpr, asize: u8) -> B::V<W64> {
    let v = sem::read64(b, g);
    let m = b.konst::<W64>(asize_mask(asize));
    b.and::<W64>(v, m)
}

fn sptr_put<B: Backend>(b: &mut B, g: Gpr, asize: u8, v: B::V<W64>) {
    let m = asize_mask(asize);
    let cur = sem::read64(b, g);
    let nm = b.konst::<W64>(!m);
    let hi = b.and::<W64>(cur, nm);
    let mm = b.konst::<W64>(m);
    let lo = b.and::<W64>(v, mm);
    let nv = b.or::<W64>(hi, lo);
    sem::write64(b, g, nv);
}

/// DF を見て文字列ポインタを ±sz 進める。
fn str_bump<B: Backend>(b: &mut B, g: Gpr, asize: u8, sz: u64) {
    let flags: B::V<W32> = b.get(eflags_ref());
    let dfm = b.konst::<W32>(0x400);
    let bit = b.and::<W32>(flags, dfm);
    let z = b.konst::<W32>(0);
    let down = b.cmp::<W32>(Cmp::Ne, bit, z);
    let pos = b.konst::<W64>(sz);
    let neg = b.konst::<W64>((sz as i64).wrapping_neg() as u64);
    let d = b.select::<W64>(down, neg, pos);
    let v = sptr(b, g, asize);
    let nv = b.add::<W64>(v, d);
    sptr_put(b, g, asize, nv);
}

/// 繰り返し判定とカウンタ減算。cond_zf: 0=なし, 1=ZF==1(REPE), 2=ZF==0(REPNE)。
fn rep_tail<B: Backend>(b: &mut B, d: &MapDec, eip: u32, cond_zf: u8) -> Flow<B> {
    let m = asize_mask(d.asize);
    let mm = b.konst::<W64>(m);
    let c0 = sem::read64(b, Gpr(1));
    let c0m = b.and::<W64>(c0, mm);
    let one = b.konst::<W64>(1);
    let zero = b.konst::<W64>(0);
    let dec = b.sub::<W64>(c0m, one);
    let c1 = b.and::<W64>(dec, mm);
    let nm = b.konst::<W64>(!m);
    let hi = b.and::<W64>(c0, nm);
    let nv = b.or::<W64>(hi, c1);
    sem::write64(b, Gpr(1), nv);
    let nz = b.cmp::<W64>(Cmp::Ne, c1, zero);
    let nzv = b.select::<W64>(nz, one, zero);
    let again_v = match cond_zf {
        1 => {
            let zf = read_zf(b);
            let zv = b.select::<W64>(zf, one, zero);
            b.and::<W64>(nzv, zv)
        }
        2 => {
            let zf = read_zf(b);
            let zv = b.select::<W64>(zf, one, zero);
            let zinv = b.xor::<W64>(zv, one);
            b.and::<W64>(nzv, zinv)
        }
        _ => nzv,
    };
    let again = b.cmp::<W64>(Cmp::Ne, again_v, zero);
    let t = b.konst::<W32>(eip);
    let tj = b.konst::<W64>(u64::from(eip));
    b.if_then(again, |b| {
        b.set(eip_ref(), t);
        b.jump(tj);
        Ok(())
    })?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn str_w<B: Backend, W: Hw>(
    b: &mut B,
    kind: Str,
    d: &MapDec,
    eip: u32,
    seg: u64,
    es: u64,
    rep: bool,
    zf_cond: u8,
) -> Flow<B> {
    let asize = d.asize;
    // 実モードの文字列アクセスはオフセット（SI/DI）を 64K で折り返す。
    let wseg_s = (asize == 16).then_some(seg);
    let wseg_d = (asize == 16).then_some(es);
    let mut si = sptr(b, Gpr(6), asize);
    let sg = b.konst::<W64>(seg);
    si = b.add::<W64>(si, sg);
    let mut di = sptr(b, Gpr(7), asize);
    let eg = b.konst::<W64>(es);
    di = b.add::<W64>(di, eg);
    let sz = u64::from(W::BITS / 8);
    match kind {
        Str::Movs => {
            let v: B::V<W> = decode::mem_load(b, si, wseg_s)?;
            decode::mem_store(b, di, wseg_d, v)?;
            str_bump(b, Gpr(6), asize, sz);
            str_bump(b, Gpr(7), asize, sz);
        }
        Str::Stos => {
            let acc = W::get(b, Gpr(0), d);
            decode::mem_store(b, di, wseg_d, acc)?;
            str_bump(b, Gpr(7), asize, sz);
        }
        Str::Lods => {
            let v: B::V<W> = decode::mem_load(b, si, wseg_s)?;
            W::put(b, Gpr(0), d, v);
            str_bump(b, Gpr(6), asize, sz);
        }
        Str::Scas => {
            let acc = W::get(b, Gpr(0), d);
            let t: B::V<W> = decode::mem_load(b, di, wseg_d)?;
            let v = b.sub::<W>(acc, t);
            update_sub_flags(b, acc, t, v);
            str_bump(b, Gpr(7), asize, sz);
        }
        Str::Cmps => {
            let x: B::V<W> = decode::mem_load(b, si, wseg_s)?;
            let t: B::V<W> = decode::mem_load(b, di, wseg_d)?;
            let v = b.sub::<W>(x, t);
            update_sub_flags(b, x, t, v);
            str_bump(b, Gpr(6), asize, sz);
            str_bump(b, Gpr(7), asize, sz);
        }
    }
    if rep {
        rep_tail(b, d, eip, zf_cond)
    } else {
        Ok(())
    }
}

/// 文字列命令（MOVS/STOS/LODS/SCAS/CMPS）。rep≠0 で要素ごとの繰り返し。
pub fn str_op<B: Backend>(
    b: &mut B,
    kind: Str,
    w: u8,
    d: &MapDec,
    eip: u32,
    seg: u64,
    es: u64,
) -> Flow<B> {
    let rep = d.rep != 0;
    // REPE/REPNE の ZF 条件は SCAS/CMPS にだけ効く。
    let zf_cond = match kind {
        Str::Scas | Str::Cmps if d.rep == 0xF3 => 1,
        Str::Scas | Str::Cmps if d.rep == 0xF2 => 2,
        _ => 0,
    };
    let iter = |b: &mut B| -> Flow<B> {
        match w {
            16 => str_w::<B, W16>(b, kind, d, eip, seg, es, rep, zf_cond),
            64 => str_w::<B, W64>(b, kind, d, eip, seg, es, rep, zf_cond),
            8 => str_w::<B, W8>(b, kind, d, eip, seg, es, rep, zf_cond),
            _ => str_w::<B, W32>(b, kind, d, eip, seg, es, rep, zf_cond),
        }
    };
    if rep {
        // カウンタが 0 なら何もせず次へ進む。
        let c = sptr(b, Gpr(1), d.asize);
        let z = b.konst::<W64>(0);
        let active = b.cmp::<W64>(Cmp::Ne, c, z);
        b.if_then(active, |b| iter(b))
    } else {
        iter(b)
    }
}

// ---- moffs MOV ----

/// MOV AL/eAX, [moffs]（A0/A1）。
pub fn mov_moffs_ld<B: Backend>(b: &mut B, w: u8, moffs: u64, seg: u64, d: &MapDec) -> Flow<B> {
    let a = b.konst::<W64>(moffs);
    let sg = b.konst::<W64>(seg);
    let addr = b.add::<W64>(a, sg);
    let wseg = (d.asize == 16).then_some(seg);
    match w {
        8 => {
            let v: B::V<W8> = b.load::<W8>(addr, sem::DATA_READ)?;
            W8::put(b, Gpr(0), d, v);
        }
        16 => {
            let v: B::V<W16> = decode::mem_load(b, addr, wseg)?;
            W16::put(b, Gpr(0), d, v);
        }
        64 => {
            let v: B::V<W64> = decode::mem_load(b, addr, wseg)?;
            W64::put(b, Gpr(0), d, v);
        }
        _ => {
            let v: B::V<W32> = decode::mem_load(b, addr, wseg)?;
            W32::put(b, Gpr(0), d, v);
        }
    }
    Ok(())
}

/// MOV [moffs], AL/eAX（A2/A3）。
pub fn mov_moffs_st<B: Backend>(b: &mut B, w: u8, moffs: u64, seg: u64, d: &MapDec) -> Flow<B> {
    let a = b.konst::<W64>(moffs);
    let sg = b.konst::<W64>(seg);
    let addr = b.add::<W64>(a, sg);
    let wseg = (d.asize == 16).then_some(seg);
    match w {
        8 => {
            let v = W8::get(b, Gpr(0), d);
            b.store::<W8>(addr, v, sem::DATA_WRITE)?;
        }
        16 => {
            let v = W16::get(b, Gpr(0), d);
            decode::mem_store(b, addr, wseg, v)?;
        }
        64 => {
            let v = W64::get(b, Gpr(0), d);
            decode::mem_store(b, addr, wseg, v)?;
        }
        _ => {
            let v = W32::get(b, Gpr(0), d);
            decode::mem_store(b, addr, wseg, v)?;
        }
    }
    Ok(())
}

// ---- BT/BTS/BTR/BTC ----

fn bt_flags<B: Backend>(b: &mut B, bit: B::B) {
    let old: B::V<W32> = b.get(eflags_ref());
    let ncf = b.konst::<W32>(!sem::FLAG_CF);
    let cleared = b.and::<W32>(old, ncf);
    let cf = b.konst::<W32>(sem::FLAG_CF);
    let z = b.konst::<W32>(0);
    let on = b.select::<W32>(bit, cf, z);
    let nv = b.or::<W32>(cleared, on);
    b.set(eflags_ref(), nv);
}

fn bt_w<B: Backend, W: Hw>(
    b: &mut B,
    op: u8,
    ea: &Rm<B::V<W64>>,
    d: &MapDec,
    n: B::V<W64>,
) -> Flow<B> {
    // r/m のビット列：メモリなら n/W::BITS 要素分アドレスを進める（負も可）。
    let lg_bits = W::BITS.trailing_zeros();
    let lg_bytes = (W::BITS / 8).trailing_zeros();
    let sh = b.konst::<W64>(u64::from(lg_bits));
    let off = b.shr_a::<W64>(n, sh);
    let bm = b.konst::<W64>(u64::from(W::BITS - 1));
    let idx = b.and::<W64>(n, bm);
    let bs = b.konst::<W64>(u64::from(lg_bytes));
    let e2;
    let target = if let Rm::Mem { a, wseg } = ea {
        let ob = b.shl::<W64>(off, bs);
        let na = b.add::<W64>(*a, ob);
        e2 = Rm::Mem { a: na, wseg: *wseg };
        &e2
    } else {
        ea
    };
    let t = rd_w::<B, W>(b, target, d)?;
    let k: B::V<W> = b.trunc::<W64, W>(idx);
    let one = b.konst::<W>(W::from_u128(1));
    let bit = b.shl::<W>(one, k);
    let got = b.and::<W>(t, bit);
    let zero = b.konst::<W>(W::from_u128(0));
    let is_set = b.cmp::<W>(Cmp::Ne, got, zero);
    bt_flags(b, is_set);
    let nv = match op {
        1 => b.or::<W>(t, bit),
        2 => {
            let all = b.konst::<W>(W::from_u128(u128::MAX));
            let nb = b.xor::<W>(bit, all);
            b.and::<W>(t, nb)
        }
        3 => b.xor::<W>(t, bit),
        _ => t,
    };
    if op != 0 {
        wr_w::<B, W>(b, target, d, nv)?;
    }
    Ok(())
}

/// BT/BTS/BTR/BTC。op: 0=BT 1=BTS 2=BTR 3=BTC。n は符号付きビット番号（64bit 値）。
pub fn bt_op<B: Backend>(
    b: &mut B,
    op: u8,
    w: u8,
    ea: &Rm<B::V<W64>>,
    d: &MapDec,
    n: B::V<W64>,
) -> Flow<B> {
    match w {
        16 => bt_w::<B, W16>(b, op, ea, d, n),
        64 => bt_w::<B, W64>(b, op, ea, d, n),
        _ => bt_w::<B, W32>(b, op, ea, d, n),
    }
}

// ---- SHLD/SHRD ----

fn shxd_w<B: Backend, W: Hw>(
    b: &mut B,
    left: bool,
    ea: &Rm<B::V<W64>>,
    d: &MapDec,
    src: Gpr,
    cnt: B::V<W>,
) -> Flow<B> {
    let msk = if W::BITS == 64 { 63u64 } else { 31 };
    let mk = b.konst::<W>(W::from_u128(u128::from(msk)));
    let n = b.and::<W>(cnt, mk);
    let zero = b.konst::<W>(W::from_u128(0));
    let nz = b.cmp::<W>(Cmp::Ne, n, zero);
    b.if_then(nz, |b| {
        let t = rd_w::<B, W>(b, ea, d)?;
        let s = W::get(b, src, d);
        let bits_k = b.konst::<W>(W::from_u128(u128::from(W::BITS)));
        let wm = b.sub::<W>(bits_k, n);
        let v = if left {
            let a = b.shl::<W>(t, n);
            let x = b.shr_l::<W>(s, wm);
            b.or::<W>(a, x)
        } else {
            let a = b.shr_l::<W>(t, n);
            let x = b.shl::<W>(s, wm);
            b.or::<W>(a, x)
        };
        wr_w::<B, W>(b, ea, d, v)?;
        // CF: SHLD は元の w-n ビット、SHRD は n-1 ビット。
        let cf_idx = if left { wm } else { n };
        let one = b.konst::<W>(W::from_u128(1));
        let cf_idx = if left {
            cf_idx
        } else {
            b.sub::<W>(cf_idx, one)
        };
        let cfv = b.shr_l::<W>(t, cf_idx);
        let cf_and = b.and::<W>(cfv, one);
        let cf = b.cmp::<W>(Cmp::Ne, cf_and, zero);
        let old: B::V<W32> = b.get(eflags_ref());
        let ncf = b.konst::<W32>(!sem::FLAG_CF);
        let cleared = b.and::<W32>(old, ncf);
        let cfm = b.konst::<W32>(sem::FLAG_CF);
        let z32 = b.konst::<W32>(0);
        let on = b.select::<W32>(cf, cfm, z32);
        let efl = b.or::<W32>(cleared, on);
        b.set(eflags_ref(), efl);
        // SZP と OF（n==1 のとき符号変化）。
        let szp = szp_bits::<B, W>(b, v);
        let one_w = b.konst::<W>(W::from_u128(1));
        let n1 = b.cmp::<W>(Cmp::Eq, n, one_w);
        let msb = b.konst::<W>(W::from_u128(u128::from(W::BITS - 1)));
        let so = b.shr_l::<W>(t, msb);
        let sv = b.shr_l::<W>(v, msb);
        let so1 = b.and::<W>(so, one);
        let sv1 = b.and::<W>(sv, one);
        let chg = b.cmp::<W>(Cmp::Ne, so1, sv1);
        let ofm = b.konst::<W32>(sem::FLAG_OF);
        let ones32 = b.konst::<W32>(0xffff_ffff);
        let o1 = b.select::<W32>(n1, ofm, z32);
        let o2 = b.select::<W32>(chg, ones32, z32);
        let of = b.and::<W32>(o1, o2);
        let old2: B::V<W32> = b.get(eflags_ref());
        let mask = sem::FLAG_OF | sem::FLAG_SF | sem::FLAG_ZF | sem::FLAG_PF;
        let nm = b.konst::<W32>(!mask);
        let keep = b.and::<W32>(old2, nm);
        let efl2 = b.or::<W32>(keep, szp);
        let efl3 = b.or::<W32>(efl2, of);
        b.set(eflags_ref(), efl3);
        Ok(())
    })?;
    Ok(())
}

/// SHLD/SHRD。left=true で SHLD。cnt は幅 W の値（CL または即値）。
pub fn shxd<B: Backend>(
    b: &mut B,
    left: bool,
    w: u8,
    ea: &Rm<B::V<W64>>,
    d: &MapDec,
    src: Gpr,
    cnt: u8,
) -> Flow<B> {
    // 即値/CL を幅 W の値として供給。CL は上位を切る。
    match w {
        16 => {
            let c = cnt_v::<B, W16>(b, cnt, d);
            shxd_w::<B, W16>(b, left, ea, d, src, c)
        }
        64 => {
            let c = cnt_v::<B, W64>(b, cnt, d);
            shxd_w::<B, W64>(b, left, ea, d, src, c)
        }
        _ => {
            let c = cnt_v::<B, W32>(b, cnt, d);
            shxd_w::<B, W32>(b, left, ea, d, src, c)
        }
    }
}

fn cnt_v<B: Backend, W: Hw>(b: &mut B, cnt: u8, d: &MapDec) -> B::V<W> {
    if cnt == u8::MAX {
        // CL。
        let cl = W8::get(b, Gpr(1), d);
        b.zext::<W8, W>(cl)
    } else {
        b.konst::<W>(W::from_u128(u128::from(cnt)))
    }
}

// ===== XMM（オペコード表経路の SSE/SSE2）=====
//
// 被演算子は `Rm` のまま受け、`Rm::Reg` を XMM 番号として読み替える。
// メモリは命令ごとの幅（128/64/32）で読み、上位はゼロ拡張する。

use crate::sem::Xmm;

/// ModRM.reg の XMM。
fn reg_x(d: &MapDec) -> Xmm {
    Xmm(decode::reg(d).0)
}

/// ModRM.r/m の XMM（mod=11 のみで使う）。
fn rm_x(d: &MapDec) -> Xmm {
    Xmm(decode::rm_reg(d).0)
}

/// xmm/m64 の下位 64 ビット（パックシフトのカウント被演算子）。
pub fn xm_lo64<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>) -> Result<B::V<W64>, B::Exit> {
    let v = rx(b, ea, 64)?;
    Ok(b.trunc::<W128, W64>(v))
}

/// xmm/m を読む。メモリは `bits` 幅で読み、上位はゼロ拡張。
fn rx<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>, bits: u32) -> Result<B::V<W128>, B::Exit> {
    match ea {
        Rm::Reg(g) => Ok(b.get(sem::xmm_ref(Xmm(g.0)))),
        Rm::Mem { a, .. } => {
            let a = *a;
            match bits {
                32 => {
                    let v: B::V<W32> = b.load::<W32>(a, sem::DATA_READ)?;
                    Ok(b.zext::<W32, W128>(v))
                }
                64 => {
                    let v: B::V<W64> = b.load::<W64>(a, sem::DATA_READ)?;
                    Ok(b.zext::<W64, W128>(v))
                }
                _ => b.load::<W128>(a, sem::DATA_READ),
            }
        }
    }
}

/// xmm/m に `v` の下位 `bits` を書く。レジスタ直接は 128 ビット全体を
/// `v`（呼び出し側が上位を合成済み）で上書きする。
fn wx<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>, bits: u32, v: B::V<W128>) -> Result<(), B::Exit> {
    match ea {
        Rm::Reg(g) => {
            b.set(sem::xmm_ref(Xmm(g.0)), v);
            Ok(())
        }
        Rm::Mem { a, .. } => {
            let a = *a;
            match bits {
                32 => {
                    let v32: B::V<W32> = b.trunc::<W128, W32>(v);
                    b.store::<W32>(a, v32, sem::DATA_WRITE)
                }
                64 => {
                    let v64: B::V<W64> = b.trunc::<W128, W64>(v);
                    b.store::<W64>(a, v64, sem::DATA_WRITE)
                }
                _ => b.store::<W128>(a, v, sem::DATA_WRITE),
            }
        }
    }
}

/// 128 ビット値の `at` ビットから `bits` 幅を取り出してゼロ拡張する。
fn lane128<B: Backend>(b: &mut B, v: B::V<W128>, at: u32, bits: u32) -> B::V<W128> {
    let sh = b.konst::<W128>(u128::from(at));
    let shifted = b.shr_l::<W128>(v, sh);
    let mask = b.konst::<W128>((1u128 << bits) - 1);
    b.and::<W128>(shifted, mask)
}

/// `dst` の `at` ビットから `bits` 幅を `v` の下位で置き換える。
fn put_lane128<B: Backend>(
    b: &mut B,
    dst: B::V<W128>,
    v: B::V<W128>,
    at: u32,
    bits: u32,
) -> B::V<W128> {
    let mask = b.konst::<W128>((1u128 << bits) - 1);
    let lo = b.and::<W128>(v, mask);
    let sh = b.konst::<W128>(u128::from(at));
    let part = b.shl::<W128>(lo, sh);
    let hole = b.shl::<W128>(mask, sh);
    let nhole = b.not::<W128>(hole);
    let keep = b.and::<W128>(dst, nhole);
    b.or::<W128>(keep, part)
}

/// 128 ビット移動の読み込み（movups/movupd/movaps/movapd/movdqa/movdqu）。
pub fn mov_x_w<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let v = rx(b, ea, 128)?;
    b.set(sem::xmm_ref(reg_x(d)), v);
    Ok(())
}

/// 128 ビット移動の書き込み。
pub fn mov_w_x<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let v: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    wx(b, ea, 128, v)
}

/// MOVSS/MOVSD の読み込み。mod=11 は下位のみ書き換えて上位を保持、
/// メモリは 32/64 ビットを読んで上位をゼロクリア。
pub fn movs_ld<B: Backend>(
    b: &mut B,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
    bits: u32,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    if d.modrm >= 0xC0 {
        let s = rx(b, ea, 128)?;
        let old: B::V<W128> = b.get(sem::xmm_ref(dst));
        let v = put_lane128(b, old, s, 0, bits);
        b.set(sem::xmm_ref(dst), v);
    } else {
        let v = rx(b, ea, bits)?;
        b.set(sem::xmm_ref(dst), v);
    }
    Ok(())
}

/// MOVSS/MOVSD の書き込み。mod=11 は下位のみコピー（上位は dst のまま）。
pub fn movs_st<B: Backend>(
    b: &mut B,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
    bits: u32,
) -> Result<(), B::Exit> {
    let s: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    if d.modrm >= 0xC0 {
        let old = rx(b, ea, 128)?;
        let v = put_lane128(b, old, s, 0, bits);
        wx(b, ea, 128, v)
    } else {
        wx(b, ea, bits, s)
    }
}

/// MOVQ xmm, xmm/m64（F3 0F 7E）。下位 64 をコピーし上位はゼロ。
pub fn movq_x_w<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let v = rx(b, ea, 64)?;
    b.set(sem::xmm_ref(reg_x(d)), v);
    Ok(())
}

/// MOVQ xmm/m64, xmm（66 0F D6）。mod=11 は下位 64 のみ書き換え上位はゼロ。
pub fn movq_w_x<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let s: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    let lo = lane128(b, s, 0, 64);
    wx(b, ea, if d.modrm >= 0xC0 { 128 } else { 64 }, lo)
}

/// MOVD/MOVQ xmm, r/m（66 0F 6E）。REX.W で 64 ビット。
pub fn movd_x_e<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let v = if d.rex & 8 != 0 {
        let v: B::V<W64> = decode::rd64(b, ea)?;
        b.zext::<W64, W128>(v)
    } else {
        let v: B::V<W32> = decode::rd32(b, ea)?;
        b.zext::<W32, W128>(v)
    };
    b.set(sem::xmm_ref(reg_x(d)), v);
    Ok(())
}

/// MOVD/MOVQ r/m, xmm（66 0F 7E）。REX.W で 64 ビット。
pub fn movd_e_x<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let s: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    if d.rex & 8 != 0 {
        let v: B::V<W64> = b.trunc::<W128, W64>(s);
        decode::wr64(b, ea, v)
    } else {
        let v: B::V<W32> = b.trunc::<W128, W32>(s);
        decode::wr32(b, ea, v)
    }
}

/// MOVLPS/MOVLPD の読み込み（0F 12、メモリ形のみ）。下位 64 を
/// 読み込む。F3 は MOVSLDUP、F2 は MOVDDUP。mod=11 は
/// MOVHLPS/MOVLHPS（別宣言）。
pub fn movl_d<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    if d.rep == 0xF3 {
        // MOVSLDUP: 偶数の 32 ビット要素を複製。
        let s = rx(b, ea, 128)?;
        let l0 = lane128(b, s, 0, 32);
        let l2 = lane128(b, s, 64, 32);
        let mut v = put_lane128(b, s, l0, 32, 32);
        v = put_lane128(b, v, l2, 96, 32);
        b.set(sem::xmm_ref(dst), v);
        return Ok(());
    }
    if d.rep == 0xF2 {
        // MOVDDUP: 下位 64 を両方に複製。
        let s = rx(b, ea, 64)?;
        let lo = lane128(b, s, 0, 64);
        let v = put_lane128(b, s, lo, 64, 64);
        b.set(sem::xmm_ref(dst), v);
        return Ok(());
    }
    let s = rx(b, ea, 64)?;
    let old: B::V<W128> = b.get(sem::xmm_ref(dst));
    let v = put_lane128(b, old, s, 0, 64);
    b.set(sem::xmm_ref(dst), v);
    Ok(())
}

/// MOVHLPS（0F 12 mod=11、0x66 は無視される）。dst.lo = src.hi。
pub fn movhlps_d<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let s = rx(b, ea, 128)?;
    let hi = lane128(b, s, 64, 64);
    let old: B::V<W128> = b.get(sem::xmm_ref(dst));
    let v = put_lane128(b, old, hi, 0, 64);
    b.set(sem::xmm_ref(dst), v);
    Ok(())
}

/// MOVLHPS（0F 16 mod=11、0x66 は無視される）。dst.hi = src.lo。
pub fn movlhps_d<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let s = rx(b, ea, 128)?;
    let old: B::V<W128> = b.get(sem::xmm_ref(dst));
    let v = put_lane128(b, old, s, 64, 64);
    b.set(sem::xmm_ref(dst), v);
    Ok(())
}

/// MOVLPS/MOVLPD の書き込み（0F 13）。下位 64 を書く。
pub fn movl_st<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let s: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    let lo = lane128(b, s, 0, 64);
    wx(b, ea, 64, lo)
}

/// MOVHPS/MOVHPD の読み込み（0F 16、メモリ形のみ）。上位 64 を
/// 読み込む。F3 は MOVSHDUP。mod=11 は MOVLHPS（別宣言）。
pub fn movh_d<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    if d.rep == 0xF3 {
        // MOVSHDUP: 奇数の 32 ビット要素を複製。
        let s = rx(b, ea, 128)?;
        let l1 = lane128(b, s, 32, 32);
        let l3 = lane128(b, s, 96, 32);
        let mut v = put_lane128(b, s, l1, 0, 32);
        v = put_lane128(b, v, l3, 64, 32);
        b.set(sem::xmm_ref(dst), v);
        return Ok(());
    }
    let s = rx(b, ea, 64)?;
    let old: B::V<W128> = b.get(sem::xmm_ref(dst));
    let v = put_lane128(b, old, s, 64, 64);
    b.set(sem::xmm_ref(dst), v);
    Ok(())
}

/// MOVHPS/MOVHPD の書き込み（0F 17）。上位 64 を書く。
pub fn movh_st<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let s: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    let hi = lane128(b, s, 64, 64);
    wx(b, ea, 64, hi)
}

/// 128 ビットの論理演算（ANDPS/ANDPD/ANDNPS/ANDNPD/ORPS/ORPD/XORPS/XORPD
/// と PAND/PANDN/POR/PXOR はすべて同じビット演算）。
#[derive(Clone, Copy)]
pub enum Lop {
    And,
    Andn,
    Or,
    Xor,
}

pub fn logic128<B: Backend>(
    b: &mut B,
    op: Lop,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let c = rx(b, ea, 128)?;
    let v = match op {
        Lop::And => b.and::<W128>(a, c),
        Lop::Andn => {
            let na = b.not::<W128>(a);
            b.and::<W128>(na, c)
        }
        Lop::Or => b.or::<W128>(a, c),
        Lop::Xor => b.xor::<W128>(a, c),
    };
    b.set(sem::xmm_ref(dst), v);
    Ok(())
}

/// 浮動小数点演算の種別。
#[derive(Clone, Copy)]
pub enum Fop {
    Add,
    Sub,
    Mul,
    Div,
    Min,
    Max,
    Sqrt,
    Cmp(u8),
}

fn fop64<B: Backend>(
    b: &mut B,
    op: Fop,
    a: B::V<polyisa_sem::F64>,
    c: B::V<polyisa_sem::F64>,
) -> B::V<polyisa_sem::F64> {
    use polyisa_sem::F64;
    match op {
        Fop::Add => b.fadd::<F64>(a, c),
        Fop::Sub => b.fsub::<F64>(a, c),
        Fop::Mul => b.fmul::<F64>(a, c),
        Fop::Div => b.fdiv::<F64>(a, c),
        Fop::Min => b.fmin::<F64>(a, c),
        Fop::Max => b.fmax::<F64>(a, c),
        Fop::Sqrt => b.fsqrt::<F64>(a),
        Fop::Cmp(_) => a,
    }
}

fn fop32<B: Backend>(
    b: &mut B,
    op: Fop,
    a: B::V<polyisa_sem::F32>,
    c: B::V<polyisa_sem::F32>,
) -> B::V<polyisa_sem::F32> {
    use polyisa_sem::F32;
    match op {
        Fop::Add => b.fadd::<F32>(a, c),
        Fop::Sub => b.fsub::<F32>(a, c),
        Fop::Mul => b.fmul::<F32>(a, c),
        Fop::Div => b.fdiv::<F32>(a, c),
        Fop::Min => b.fmin::<F32>(a, c),
        Fop::Max => b.fmax::<F32>(a, c),
        Fop::Sqrt => b.fsqrt::<F32>(a),
        Fop::Cmp(_) => a,
    }
}

/// スカラ浮動小数点（addsd/subsd/mulsd/divsd/minsd/maxsd/sqrtsd と
/// 単精度形）。`fbits` は 32 または 64。上位は dst のまま。
pub fn sfloat<B: Backend>(
    b: &mut B,
    op: Fop,
    fbits: u32,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a128: B::V<W128> = b.get(sem::xmm_ref(dst));
    let c128 = rx(b, ea, fbits)?;
    let res = if fbits == 64 {
        let a64: B::V<W64> = b.trunc::<W128, W64>(a128);
        let c64: B::V<W64> = b.trunc::<W128, W64>(c128);
        let af = b.trunc::<W64, polyisa_sem::F64>(a64);
        let cf = b.trunc::<W64, polyisa_sem::F64>(c64);
        let v = fop64(b, op, af, cf);
        let v64 = b.trunc::<polyisa_sem::F64, W64>(v);
        b.zext::<W64, W128>(v64)
    } else {
        let a32: B::V<W32> = b.trunc::<W128, W32>(a128);
        let c32: B::V<W32> = b.trunc::<W128, W32>(c128);
        let af = b.trunc::<W32, polyisa_sem::F32>(a32);
        let cf = b.trunc::<W32, polyisa_sem::F32>(c32);
        let v = fop32(b, op, af, cf);
        let v32 = b.trunc::<polyisa_sem::F32, W32>(v);
        b.zext::<W32, W128>(v32)
    };
    let out = put_lane128(b, a128, res, 0, fbits);
    b.set(sem::xmm_ref(dst), out);
    Ok(())
}

/// パック浮動小数点（addps/addpd 等の 4×f32 / 2×f64 の全要素）。
pub fn pfloat<B: Backend>(
    b: &mut B,
    op: Fop,
    fbits: u32,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a128: B::V<W128> = b.get(sem::xmm_ref(dst));
    let c128 = rx(b, ea, 128)?;
    let mut acc = b.konst::<W128>(0);
    let n = 128 / fbits;
    for i in 0..n {
        let al = lane128(b, a128, i * fbits, fbits);
        let cl = lane128(b, c128, i * fbits, fbits);
        let res = if fbits == 64 {
            let a64: B::V<W64> = b.trunc::<W128, W64>(al);
            let c64: B::V<W64> = b.trunc::<W128, W64>(cl);
            let af = b.trunc::<W64, polyisa_sem::F64>(a64);
            let cf = b.trunc::<W64, polyisa_sem::F64>(c64);
            let v = match op {
                Fop::Cmp(p) => {
                    let m = fcmp_pred::<B, polyisa_sem::F64>(b, p, af, cf);
                    let ones = b.konst::<W64>(u64::MAX);
                    let zero = b.konst::<W64>(0);
                    b.select::<W64>(m, ones, zero)
                }
                _ => {
                    let v = fop64(b, op, af, cf);
                    b.trunc::<polyisa_sem::F64, W64>(v)
                }
            };
            b.zext::<W64, W128>(v)
        } else {
            let a32: B::V<W32> = b.trunc::<W128, W32>(al);
            let c32: B::V<W32> = b.trunc::<W128, W32>(cl);
            let af = b.trunc::<W32, polyisa_sem::F32>(a32);
            let cf = b.trunc::<W32, polyisa_sem::F32>(c32);
            let v = match op {
                Fop::Cmp(p) => {
                    let m = fcmp_pred::<B, polyisa_sem::F32>(b, p, af, cf);
                    let ones = b.konst::<W32>(u32::MAX);
                    let zero = b.konst::<W32>(0);
                    b.select::<W32>(m, ones, zero)
                }
                _ => {
                    let v = fop32(b, op, af, cf);
                    b.trunc::<polyisa_sem::F32, W32>(v)
                }
            };
            b.zext::<W32, W128>(v)
        };
        acc = put_lane128(b, acc, res, i * fbits, fbits);
    }
    b.set(sem::xmm_ref(dst), acc);
    Ok(())
}

/// CMPPS/CMPPD の判定。cond に該当するかを返す。
fn fcmp_pred<B: Backend, F: polyisa_sem::Width>(
    b: &mut B,
    pred: u8,
    a: B::V<F>,
    c: B::V<F>,
) -> B::B {
    let nan_a = {
        let eq = b.feq::<F>(a, a);
        sem::bit_not(b, eq)
    };
    let nan_c = {
        let eq = b.feq::<F>(c, c);
        sem::bit_not(b, eq)
    };
    let unord = sem::bit_or(b, nan_a, nan_c);
    let ord = sem::bit_not(b, unord);
    let eq = b.feq::<F>(a, c);
    let lt = b.flt::<F>(a, c);
    let le = b.fle::<F>(a, c);
    let neq = sem::bit_not(b, eq);
    let lt_o = sem::bit_not(b, lt);
    let nlt = sem::bit_or(b, unord, lt_o);
    let le_o = sem::bit_not(b, le);
    let nle = sem::bit_or(b, unord, le_o);
    let neq_u = sem::bit_or(b, unord, neq);
    match pred & 7 {
        0 => eq,
        1 => lt,
        2 => le,
        3 => unord,
        4 => neq_u,
        5 => nlt,
        6 => nle,
        _ => ord,
    }
}

/// CMPSS/CMPSD。下位のみ判定マスク、上位は dst のまま。
pub fn scmp<B: Backend>(
    b: &mut B,
    fbits: u32,
    pred: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a128: B::V<W128> = b.get(sem::xmm_ref(dst));
    let c128 = rx(b, ea, fbits)?;
    let res = if fbits == 64 {
        let a64: B::V<W64> = b.trunc::<W128, W64>(a128);
        let c64: B::V<W64> = b.trunc::<W128, W64>(c128);
        let af = b.trunc::<W64, polyisa_sem::F64>(a64);
        let cf = b.trunc::<W64, polyisa_sem::F64>(c64);
        let m = fcmp_pred::<B, polyisa_sem::F64>(b, pred, af, cf);
        let ones = b.konst::<W64>(u64::MAX);
        let zero = b.konst::<W64>(0);
        let m64 = b.select::<W64>(m, ones, zero);
        b.zext::<W64, W128>(m64)
    } else {
        let a32: B::V<W32> = b.trunc::<W128, W32>(a128);
        let c32: B::V<W32> = b.trunc::<W128, W32>(c128);
        let af = b.trunc::<W32, polyisa_sem::F32>(a32);
        let cf = b.trunc::<W32, polyisa_sem::F32>(c32);
        let m = fcmp_pred::<B, polyisa_sem::F32>(b, pred, af, cf);
        let ones = b.konst::<W32>(u32::MAX);
        let zero = b.konst::<W32>(0);
        let m32 = b.select::<W32>(m, ones, zero);
        b.zext::<W32, W128>(m32)
    };
    let out = put_lane128(b, a128, res, 0, fbits);
    b.set(sem::xmm_ref(dst), out);
    Ok(())
}

/// UCOMISS/UCOMISD（COMISS/COMISD も同じ旗の規則）。
/// 結果は ZF/PF/CF に書き、OF/SF/AF は 0。
pub fn ucomis<B: Backend>(
    b: &mut B,
    fbits: u32,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let a128: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    let c128 = rx(b, ea, fbits)?;
    let (unord, eq, lt) = if fbits == 64 {
        let a64: B::V<W64> = b.trunc::<W128, W64>(a128);
        let c64: B::V<W64> = b.trunc::<W128, W64>(c128);
        let af = b.trunc::<W64, polyisa_sem::F64>(a64);
        let cf = b.trunc::<W64, polyisa_sem::F64>(c64);
        let na = {
            let e = b.feq::<polyisa_sem::F64>(af, af);
            sem::bit_not(b, e)
        };
        let nc = {
            let e = b.feq::<polyisa_sem::F64>(cf, cf);
            sem::bit_not(b, e)
        };
        (
            sem::bit_or(b, na, nc),
            b.feq::<polyisa_sem::F64>(af, cf),
            b.flt::<polyisa_sem::F64>(af, cf),
        )
    } else {
        let a32: B::V<W32> = b.trunc::<W128, W32>(a128);
        let c32: B::V<W32> = b.trunc::<W128, W32>(c128);
        let af = b.trunc::<W32, polyisa_sem::F32>(a32);
        let cf = b.trunc::<W32, polyisa_sem::F32>(c32);
        let na = {
            let e = b.feq::<polyisa_sem::F32>(af, af);
            sem::bit_not(b, e)
        };
        let nc = {
            let e = b.feq::<polyisa_sem::F32>(cf, cf);
            sem::bit_not(b, e)
        };
        (
            sem::bit_or(b, na, nc),
            b.feq::<polyisa_sem::F32>(af, cf),
            b.flt::<polyisa_sem::F32>(af, cf),
        )
    };
    let zf = sem::bit_or(b, unord, eq);
    let cf_out = sem::bit_or(b, unord, lt);
    let f: B::V<W32> = b.get(eflags_ref());
    let mask = b.konst::<W32>(
        sem::FLAG_ZF | sem::FLAG_PF | sem::FLAG_CF | sem::FLAG_OF | sem::FLAG_SF | sem::FLAG_AF,
    );
    let nmask = b.not::<W32>(mask);
    let kept = b.and::<W32>(f, nmask);
    let zf_v = pick(b, zf, sem::FLAG_ZF);
    let pf_v = pick(b, unord, sem::FLAG_PF);
    let cf_v = pick(b, cf_out, sem::FLAG_CF);
    let mut v = b.or::<W32>(kept, zf_v);
    v = b.or::<W32>(v, pf_v);
    v = b.or::<W32>(v, cf_v);
    b.set(eflags_ref(), v);
    Ok(())
}

/// CVTSI2SD/CVTSI2SS。整数を浮動小数点にして下位に書く。上位は dst のまま。
pub fn cvtsi<B: Backend>(
    b: &mut B,
    fbits: u32,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a128: B::V<W128> = b.get(sem::xmm_ref(dst));
    let res = if d.rex & 8 != 0 {
        let i64v = decode::rd64(b, ea)?;
        let f = if fbits == 64 {
            let f = b.fcvt_from_s64::<polyisa_sem::F64>(i64v, 0);
            b.trunc::<polyisa_sem::F64, W64>(f)
        } else {
            let f = b.fcvt_from_s64::<polyisa_sem::F32>(i64v, 0);
            let f32 = b.trunc::<polyisa_sem::F32, W32>(f);
            b.zext::<W32, W64>(f32)
        };
        b.zext::<W64, W128>(f)
    } else {
        let i32v = decode::rd32(b, ea)?;
        if fbits == 64 {
            let f = b.fcvt_from_s32::<polyisa_sem::F64>(i32v, 0);
            let f64 = b.trunc::<polyisa_sem::F64, W64>(f);
            b.zext::<W64, W128>(f64)
        } else {
            let f = b.fcvt_from_s32::<polyisa_sem::F32>(i32v, 0);
            let f32 = b.trunc::<polyisa_sem::F32, W32>(f);
            b.zext::<W32, W128>(f32)
        }
    };
    let out = put_lane128(b, a128, res, 0, fbits);
    b.set(sem::xmm_ref(dst), out);
    Ok(())
}

/// CVTTSD2SI/CVTTSS2SI（rm=1 切り捨て）と CVTSD2SI/CVTSS2SI（rm=0 最近接）。
/// dst は GPR（V 幅）。`trunc_rm` が真で切り捨て。
pub fn cvtf2i<B: Backend>(
    b: &mut B,
    fbits: u32,
    trunc_rm: bool,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
    dst: Gpr,
) -> Result<(), B::Exit> {
    let s = rx(b, ea, fbits)?;
    let rm = if trunc_rm { 1 } else { 0 };
    let v = if fbits == 64 {
        let s64: B::V<W64> = b.trunc::<W128, W64>(s);
        let f = b.trunc::<W64, polyisa_sem::F64>(s64);
        if d.rex & 8 != 0 {
            b.fcvt_s64::<polyisa_sem::F64>(f, rm)
        } else {
            let v32 = b.fcvt_s32::<polyisa_sem::F64>(f, rm);
            b.sext::<W32, W64>(v32)
        }
    } else {
        let s32: B::V<W32> = b.trunc::<W128, W32>(s);
        let f = b.trunc::<W32, polyisa_sem::F32>(s32);
        if d.rex & 8 != 0 {
            b.fcvt_s64::<polyisa_sem::F32>(f, rm)
        } else {
            let v32 = b.fcvt_s32::<polyisa_sem::F32>(f, rm);
            b.sext::<W32, W64>(v32)
        }
    };
    if d.rex & 8 != 0 {
        sem::write64(b, dst, v);
    } else {
        let v32: B::V<W32> = b.trunc::<W64, W32>(v);
        let cleared = b.zext::<W32, W64>(v32);
        sem::write64(b, dst, cleared);
    }
    Ok(())
}

/// CVTPS2PD / CVTPD2PS / CVTSS2SD / CVTSD2SS。
/// `to64` で F32→F64、`keep_hi` でスカラ形（上位を dst のまま）。
pub fn cvtff<B: Backend>(
    b: &mut B,
    to64: bool,
    keep_hi: bool,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    use polyisa_sem::{F32, F64};
    let dst = reg_x(d);
    let a128: B::V<W128> = b.get(sem::xmm_ref(dst));
    let src_bits = if to64 { 64 } else { 128 };
    let s = rx(b, ea, src_bits)?;
    let out = if to64 {
        if keep_hi {
            // CVTSS2SD: lo32 → lo64
            let s32: B::V<W32> = b.trunc::<W128, W32>(s);
            let f = b.trunc::<W32, F32>(s32);
            let v = b.fcvt_ff::<F32, F64>(f, 0);
            let v64 = b.trunc::<F64, W64>(v);
            let v128 = b.zext::<W64, W128>(v64);
            put_lane128(b, a128, v128, 0, 64)
        } else {
            // CVTPS2PD: lo/hi の f32 → 2 つの f64
            let lo32: B::V<W32> = b.trunc::<W128, W32>(s);
            let s64k = b.konst::<W128>(64);
            let s_hi = b.shr_l::<W128>(s, s64k);
            let hi64: B::V<W64> = b.trunc::<W128, W64>(s_hi);
            let hi32: B::V<W32> = b.trunc::<W64, W32>(hi64);
            let fl = b.trunc::<W32, F32>(lo32);
            let fh = b.trunc::<W32, F32>(hi32);
            let vl = b.fcvt_ff::<F32, F64>(fl, 0);
            let vh = b.fcvt_ff::<F32, F64>(fh, 0);
            let vl64 = b.trunc::<F64, W64>(vl);
            let vh64 = b.trunc::<F64, W64>(vh);
            let lo = b.zext::<W64, W128>(vl64);
            let vh128 = b.zext::<W64, W128>(vh64);
            put_lane128(b, lo, vh128, 64, 64)
        }
    } else if keep_hi {
        // CVTSD2SS: lo64 → lo32
        let s64: B::V<W64> = b.trunc::<W128, W64>(s);
        let f = b.trunc::<W64, F64>(s64);
        let v = b.fcvt_ff::<F64, F32>(f, 0);
        let v32 = b.trunc::<F32, W32>(v);
        let v128 = b.zext::<W32, W128>(v32);
        put_lane128(b, a128, v128, 0, 32)
    } else {
        // CVTPD2PS: 2 つの f64 → lo64 の 2 つの f32、hi64 は 0
        let lo64: B::V<W64> = b.trunc::<W128, W64>(s);
        let k64c = b.konst::<W128>(64);
        let hi64v = b.shr_l::<W128>(s, k64c);
        let hi64: B::V<W64> = b.trunc::<W128, W64>(hi64v);
        let fl = b.trunc::<W64, F64>(lo64);
        let fh = b.trunc::<W64, F64>(hi64);
        let vl = b.fcvt_ff::<F64, F32>(fl, 0);
        let vh = b.fcvt_ff::<F64, F32>(fh, 0);
        let vl32 = b.trunc::<F32, W32>(vl);
        let vh32 = b.trunc::<F32, W32>(vh);
        let lo = b.zext::<W32, W128>(vl32);
        let vh128 = b.zext::<W32, W128>(vh32);
        put_lane128(b, lo, vh128, 32, 32)
    };
    b.set(sem::xmm_ref(dst), out);
    Ok(())
}

/// PSHUFD（66）/PSHUFHW（F3）/PSHUFLW（F2）。
pub fn pshuf<B: Backend>(
    b: &mut B,
    kind: u8,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let s = rx(b, ea, 128)?;
    let v = match kind {
        // 全 4 dword を imm で並べ替え。
        0 => {
            let mut acc = b.konst::<W128>(0);
            for i in 0..4u32 {
                let sel = u32::from((imm >> (2 * i)) & 3);
                let l = lane128(b, s, sel * 32, 32);
                acc = put_lane128(b, acc, l, i * 32, 32);
            }
            acc
        }
        // 上位 4 word を並べ替え。下位 64 は src のまま。
        1 => {
            let mut acc = s;
            for i in 0..4u32 {
                let sel = u32::from((imm >> (2 * i)) & 3);
                let l = lane128(b, s, 64 + sel * 16, 16);
                acc = put_lane128(b, acc, l, 64 + i * 16, 16);
            }
            acc
        }
        // 下位 4 word を並べ替え。上位 64 は src のまま。
        _ => {
            let mut acc = s;
            for i in 0..4u32 {
                let sel = u32::from((imm >> (2 * i)) & 3);
                let l = lane128(b, s, sel * 16, 16);
                acc = put_lane128(b, acc, l, i * 16, 16);
            }
            acc
        }
    };
    b.set(sem::xmm_ref(dst), v);
    Ok(())
}

/// SHUFPS/SHUFPD。
pub fn shufp<B: Backend>(
    b: &mut B,
    pd: bool,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let c = rx(b, ea, 128)?;
    let v = if pd {
        let al = lane128(b, a, u32::from(imm & 1) * 64, 64);
        let cl = lane128(b, c, u32::from((imm >> 1) & 1) * 64, 64);
        put_lane128(b, al, cl, 64, 64)
    } else {
        let a0 = lane128(b, a, u32::from(imm & 3) * 32, 32);
        let a1 = lane128(b, a, u32::from((imm >> 2) & 3) * 32, 32);
        let c0 = lane128(b, c, u32::from((imm >> 4) & 3) * 32, 32);
        let c1 = lane128(b, c, u32::from((imm >> 6) & 3) * 32, 32);
        let mut acc = put_lane128(b, a0, a1, 32, 32);
        acc = put_lane128(b, acc, c0, 64, 32);
        put_lane128(b, acc, c1, 96, 32)
    };
    b.set(sem::xmm_ref(dst), v);
    Ok(())
}

/// PUNPCKL*/PUNPCKH* と UNPCKLPS/PD・UNPCKHPS/PD。
/// `bits` は要素幅（8/16/32/64）、`high` で上半分を取る。
pub fn punpck<B: Backend>(
    b: &mut B,
    bits: u32,
    high: bool,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let c = rx(b, ea, 128)?;
    let half = 64 / bits;
    let base = if high { half } else { 0 };
    let mut acc = b.konst::<W128>(0);
    for i in 0..half {
        let al = lane128(b, a, (base + i) * bits, bits);
        let cl = lane128(b, c, (base + i) * bits, bits);
        acc = put_lane128(b, acc, al, (2 * i) * bits, bits);
        acc = put_lane128(b, acc, cl, (2 * i + 1) * bits, bits);
    }
    b.set(sem::xmm_ref(dst), acc);
    Ok(())
}

/// PINSRW。imm の下位 3 ビットの word を 16 ビットで置き換える。
pub fn pinsrw<B: Backend>(
    b: &mut B,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let w16: B::V<W16> = decode::rd16(b, ea)?;
    let w128 = b.zext::<W16, W128>(w16);
    let v = put_lane128(b, a, w128, u32::from(imm & 7) * 16, 16);
    b.set(sem::xmm_ref(dst), v);
    Ok(())
}

/// PEXTRW。imm の下位 3 ビットの word を GPR に書く。
pub fn pextrw<B: Backend>(
    b: &mut B,
    imm: u8,
    _d: &MapDec,
    ea: &Rm<B::V<W64>>,
    dst: Gpr,
) -> Result<(), B::Exit> {
    let s = rx(b, ea, 128)?;
    let l = lane128(b, s, u32::from(imm & 7) * 16, 16);
    let l16: B::V<W16> = b.trunc::<W128, W16>(l);
    let v = b.zext::<W16, W64>(l16);
    sem::write64(b, dst, v);
    Ok(())
}

/// PMOVMSKB（16 バイトの符号ビット）と MOVMSKPS/MOVMSKPD
/// （要素の符号ビットを 4/2 個取る）。
pub fn movmsk<B: Backend>(
    b: &mut B,
    bits: u32,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let s = rx(b, ea, 128)?;
    let mut acc = b.konst::<W64>(0);
    let n = 128 / bits;
    for i in 0..n {
        let l = lane128(b, s, i * bits + bits - 1, 1);
        let l64: B::V<W64> = b.trunc::<W128, W64>(l);
        let sh = b.konst::<W64>(u64::from(i));
        let placed = b.shl::<W64>(l64, sh);
        acc = b.or::<W64>(acc, placed);
    }
    // dst は 32/64 ビット GPR。下位 32 ビットを書き上位はクリア。
    let v32: B::V<W32> = b.trunc::<W64, W32>(acc);
    let v = b.zext::<W32, W64>(v32);
    sem::write64(b, decode::reg(d), v);
    Ok(())
}

/// パック整数の要素ごとの演算。`f` は要素同士の演算。
fn lane_bin<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
    mut f: impl FnMut(&mut B, B::V<W>, B::V<W>) -> B::V<W>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let c = rx(b, ea, 128)?;
    let mut acc = b.konst::<W128>(0);
    let n = 128 / W::BITS;
    for i in 0..n {
        let al = lane128(b, a, i * W::BITS, W::BITS);
        let cl = lane128(b, c, i * W::BITS, W::BITS);
        let a_w: B::V<W> = b.trunc::<W128, W>(al);
        let c_w: B::V<W> = b.trunc::<W128, W>(cl);
        let r = f(b, a_w, c_w);
        let r128 = b.zext::<W, W128>(r);
        acc = put_lane128(b, acc, r128, i * W::BITS, W::BITS);
    }
    b.set(sem::xmm_ref(dst), acc);
    Ok(())
}

/// 符号なし飽和加算（a+b が溢れたら全 1）。
fn sat_add_u<B: Backend, W: polyisa_sem::Width>(b: &mut B, a: B::V<W>, c: B::V<W>) -> B::V<W> {
    let s = b.add::<W>(a, c);
    let ovf = b.cmp::<W>(Cmp::LtU, s, a);
    let max = b.konst::<W>(W::from_u128((1u128 << W::BITS) - 1));
    b.select::<W>(ovf, max, s)
}

/// 符号付き飽和加算。
fn sat_add_s<B: Backend, W: polyisa_sem::Width>(b: &mut B, a: B::V<W>, c: B::V<W>) -> B::V<W> {
    let s = b.add::<W>(a, c);
    let sign = b.konst::<W>(W::from_u128(1u128 << (W::BITS - 1)));
    let sa = b.and::<W>(a, sign);
    let sc = b.and::<W>(c, sign);
    let ss = b.and::<W>(s, sign);
    let same = b.cmp::<W>(Cmp::Eq, sa, sc);
    let diff = b.cmp::<W>(Cmp::Ne, ss, sa);
    let ovf = sem::bit_and(b, same, diff);
    let wzero = b.konst::<W>(W::from_u128(0));
    let neg = b.cmp::<W>(Cmp::Ne, sa, wzero);
    let min = sign;
    let max = b.konst::<W>(W::from_u128((1u128 << (W::BITS - 1)) - 1));
    let sat = b.select::<W>(neg, min, max);
    b.select::<W>(ovf, sat, s)
}

/// 符号なし飽和減算（a<b なら 0）。
fn sat_sub_u<B: Backend, W: polyisa_sem::Width>(b: &mut B, a: B::V<W>, c: B::V<W>) -> B::V<W> {
    let lt = b.cmp::<W>(Cmp::LtU, a, c);
    let s = b.sub::<W>(a, c);
    let z = b.konst::<W>(W::from_u128(0));
    b.select::<W>(lt, z, s)
}

/// 符号付き飽和減算。
fn sat_sub_s<B: Backend, W: polyisa_sem::Width>(b: &mut B, a: B::V<W>, c: B::V<W>) -> B::V<W> {
    let s = b.sub::<W>(a, c);
    let sign = b.konst::<W>(W::from_u128(1u128 << (W::BITS - 1)));
    let sa = b.and::<W>(a, sign);
    let sc = b.and::<W>(c, sign);
    let ss = b.and::<W>(s, sign);
    let diff = b.cmp::<W>(Cmp::Ne, sa, sc);
    let wrong = b.cmp::<W>(Cmp::Ne, ss, sa);
    let ovf = sem::bit_and(b, diff, wrong);
    let wzero = b.konst::<W>(W::from_u128(0));
    let neg = b.cmp::<W>(Cmp::Ne, sa, wzero);
    let min = sign;
    let max = b.konst::<W>(W::from_u128((1u128 << (W::BITS - 1)) - 1));
    let sat = b.select::<W>(neg, min, max);
    b.select::<W>(ovf, sat, s)
}

/// 全 1 マスクの生成（要素比較用）。
fn lane_mask<B: Backend, W: polyisa_sem::Width>(b: &mut B, cond: B::B) -> B::V<W> {
    let ones = b.konst::<W>(W::from_u128((1u128 << W::BITS) - 1));
    let z = b.konst::<W>(W::from_u128(0));
    b.select::<W>(cond, ones, z)
}

/// パック整数の算術・比較。`kind` で演算を選ぶ。
#[derive(Clone, Copy)]
pub enum Iop {
    Add,
    Sub,
    MulLo,
    AddSatU,
    AddSatS,
    SubSatU,
    SubSatS,
    Avg,
    MinU,
    MaxU,
    MinS,
    MaxS,
    CmpEq,
    CmpGtS,
}

/// `Iop` のレーン演算本体。xmm の `pint` と mm の `mint` で共有する。
fn iop_op<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    kind: Iop,
    a: B::V<W>,
    c: B::V<W>,
) -> B::V<W> {
    match kind {
        Iop::Add => b.add::<W>(a, c),
        Iop::Sub => b.sub::<W>(a, c),
        Iop::MulLo => b.mul::<W>(a, c),
        Iop::AddSatU => sat_add_u::<B, W>(b, a, c),
        Iop::AddSatS => sat_add_s::<B, W>(b, a, c),
        Iop::SubSatU => sat_sub_u::<B, W>(b, a, c),
        Iop::SubSatS => sat_sub_s::<B, W>(b, a, c),
        Iop::Avg => {
            // (a + b + 1) >> 1 をオーバーフローなしで: (a>>1)+(b>>1)+((a|b)&1)
            let one = b.konst::<W>(W::from_u128(1));
            let ah = b.shr_l::<W>(a, one);
            let ch = b.shr_l::<W>(c, one);
            let sum = b.add::<W>(ah, ch);
            let ab = b.or::<W>(a, c);
            let lsb = b.and::<W>(ab, one);
            b.add::<W>(sum, lsb)
        }
        Iop::MinU => {
            let lt = b.cmp::<W>(Cmp::LtU, a, c);
            b.select::<W>(lt, a, c)
        }
        Iop::MaxU => {
            let gt = b.cmp::<W>(Cmp::GtU, a, c);
            b.select::<W>(gt, a, c)
        }
        Iop::MinS => {
            let lt = b.cmp::<W>(Cmp::LtS, a, c);
            b.select::<W>(lt, a, c)
        }
        Iop::MaxS => {
            let gt = b.cmp::<W>(Cmp::GtS, a, c);
            b.select::<W>(gt, a, c)
        }
        Iop::CmpEq => {
            let eq = b.cmp::<W>(Cmp::Eq, a, c);
            lane_mask::<B, W>(b, eq)
        }
        Iop::CmpGtS => {
            let gt = b.cmp::<W>(Cmp::GtS, a, c);
            lane_mask::<B, W>(b, gt)
        }
    }
}

pub fn pint<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    kind: Iop,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    lane_bin::<B, W>(b, d, ea, |b, a, c| iop_op::<B, W>(b, kind, a, c))
}

/// PSRL/PSRA/PSLL のパックシフト。カウントは xmm/m128 の下位 64 または即値。
#[derive(Clone, Copy)]
pub enum Psh {
    L,
    A,
    R,
}

fn pshift_impl<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    dir: Psh,
    cnt: B::V<W64>,
    dst: Xmm,
) -> Flow<B> {
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    // カウントが幅以上なら結果は 0（PSRA は符号拡張）。
    let bits_k = b.konst::<W64>(u64::from(W::BITS));
    let over = b.cmp::<W64>(Cmp::GeU, cnt, bits_k);
    let cnt_w: B::V<W> = b.trunc::<W64, W>(cnt);
    let mut acc = b.konst::<W128>(0);
    let n = 128 / W::BITS;
    for i in 0..n {
        let al = lane128(b, a, i * W::BITS, W::BITS);
        let a_w: B::V<W> = b.trunc::<W128, W>(al);
        let r = match dir {
            Psh::L => b.shl::<W>(a_w, cnt_w),
            Psh::A => b.shr_a::<W>(a_w, cnt_w),
            Psh::R => b.shr_l::<W>(a_w, cnt_w),
        };
        // オーバーシフト: L/R は 0、A は符号ビットの繰り返し。
        let r = if matches!(dir, Psh::A) {
            let sign_sh = b.konst::<W>(W::from_u128((W::BITS - 1) as u128));
            let sg = b.shr_l::<W>(a_w, sign_sh);
            let wz2 = b.konst::<W>(W::from_u128(0));
            let neg = b.cmp::<W>(Cmp::Ne, sg, wz2);
            let ones = b.konst::<W>(W::from_u128((1u128 << W::BITS) - 1));
            let z = b.konst::<W>(W::from_u128(0));
            let ext = b.select::<W>(neg, ones, z);
            b.select::<W>(over, ext, r)
        } else {
            let z = b.konst::<W>(W::from_u128(0));
            b.select::<W>(over, z, r)
        };
        let r128 = b.zext::<W, W128>(r);
        acc = put_lane128(b, acc, r128, i * W::BITS, W::BITS);
    }
    b.set(sem::xmm_ref(dst), acc);
    Ok(())
}

/// 2 被演算子形（xmm, xmm/m64）：dst は ModRM.reg。
pub fn pshift<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    dir: Psh,
    cnt: B::V<W64>,
    d: &MapDec,
) -> Flow<B> {
    pshift_impl::<B, W>(b, dir, cnt, reg_x(d))
}

/// グループ即値形（xmm, imm8）：dst は ModRM.r/m。
pub fn pshift_i<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    dir: Psh,
    imm: u8,
    d: &MapDec,
) -> Flow<B> {
    let c = b.konst::<W64>(u64::from(imm));
    pshift_impl::<B, W>(b, dir, c, rm_x(d))
}

/// PSRLDQ/PSLLDQ。128 ビット全体を imm バイトずらす。
pub fn byteshift<B: Backend>(b: &mut B, left: bool, imm: u8, d: &MapDec) -> Flow<B> {
    let dst = rm_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let bits = u32::from(imm).min(16) * 8;
    let sh = b.konst::<W128>(u128::from(bits));
    let v = if imm >= 16 {
        b.konst::<W128>(0)
    } else if left {
        b.shl::<W128>(a, sh)
    } else {
        b.shr_l::<W128>(a, sh)
    };
    b.set(sem::xmm_ref(dst), v);
    Ok(())
}

// ===== MMX（0F 接頭辞なし。P/Q オペランド）=====
//
// mm レジスタは st_sig（x87 仮数部の物理スロット）が実機の
// エイリアス先。タグワードはモデル化していないので EMMS は
// 建築状態を変えない。

/// ModRM.reg の MMX 番号。
fn reg_m(d: &MapDec) -> usize {
    (decode::reg(d).0 & 7) as usize
}

/// ModRM.r/m がレジスタ形のときの MMX 番号（mod=11 でのみ使う）。
fn rm_m(d: &MapDec) -> usize {
    (decode::rm_reg(d).0 & 7) as usize
}

/// mm/m64 を読む。
fn rq<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>) -> Result<B::V<W64>, B::Exit> {
    match ea {
        Rm::Reg(g) => Ok(b.get(sem::st_sig_ref((g.0 & 7) as usize))),
        Rm::Mem { a, .. } => b.load::<W64>(*a, sem::DATA_READ),
    }
}

/// 64 ビット値の `at` ビットから `bits` 幅を取り出してゼロ拡張する。
fn lane64<B: Backend>(b: &mut B, v: B::V<W64>, at: u32, bits: u32) -> B::V<W64> {
    let sh = b.konst::<W64>(u64::from(at));
    let shifted = b.shr_l::<W64>(v, sh);
    let mask = b.konst::<W64>((1u64 << bits) - 1);
    b.and::<W64>(shifted, mask)
}

/// `dst` の `at` ビットから `bits` 幅を `v` の下位で置き換える。
fn put_lane64<B: Backend>(
    b: &mut B,
    dst: B::V<W64>,
    v: B::V<W64>,
    at: u32,
    bits: u32,
) -> B::V<W64> {
    let mask = b.konst::<W64>((1u64 << bits) - 1);
    let lo = b.and::<W64>(v, mask);
    let sh = b.konst::<W64>(u64::from(at));
    let part = b.shl::<W64>(lo, sh);
    let hole = b.shl::<W64>(mask, sh);
    let nhole = b.not::<W64>(hole);
    let keep = b.and::<W64>(dst, nhole);
    b.or::<W64>(keep, part)
}

/// パック整数の要素ごとの演算の MMX 形（`lane_bin` の 64 ビット版）。
fn lane_bin64<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
    mut f: impl FnMut(&mut B, B::V<W>, B::V<W>) -> B::V<W>,
) -> Result<(), B::Exit> {
    let dst = reg_m(d);
    let a: B::V<W64> = b.get(sem::st_sig_ref(dst));
    let c = rq(b, ea)?;
    let mut acc = b.konst::<W64>(0);
    let n = 64 / W::BITS;
    for i in 0..n {
        let al = lane64(b, a, i * W::BITS, W::BITS);
        let cl = lane64(b, c, i * W::BITS, W::BITS);
        let a_w: B::V<W> = b.trunc::<W64, W>(al);
        let c_w: B::V<W> = b.trunc::<W64, W>(cl);
        let r = f(b, a_w, c_w);
        let r64 = b.zext::<W, W64>(r);
        acc = put_lane64(b, acc, r64, i * W::BITS, W::BITS);
    }
    b.set(sem::st_sig_ref(dst), acc);
    Ok(())
}

/// `pint` の MMX 形。PADD/PSUB/PMULLW/飽和/平均/min/max/PCMPEQ/PCMPGT。
pub fn mint<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    kind: Iop,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    lane_bin64::<B, W>(b, d, ea, |b, a, c| iop_op::<B, W>(b, kind, a, c))
}

/// PAND/PANDN/POR/PXOR の MMX 形（64 ビット全体の論理）。
pub fn mlogic<B: Backend>(
    b: &mut B,
    kind: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_m(d);
    let a: B::V<W64> = b.get(sem::st_sig_ref(dst));
    let c = rq(b, ea)?;
    let v = match kind {
        0 => b.and::<W64>(a, c),
        1 => {
            let na = b.not::<W64>(a);
            b.and::<W64>(na, c)
        }
        2 => b.or::<W64>(a, c),
        _ => b.xor::<W64>(a, c),
    };
    b.set(sem::st_sig_ref(dst), v);
    Ok(())
}

/// PUNPCKL*/PUNPCKH* の MMX 形。`bits` は要素幅（8/16/32）。
/// 64 ビットの下半分（high なら上半分）を交互に詰める。
pub fn mpunpck<B: Backend>(
    b: &mut B,
    bits: u32,
    high: bool,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_m(d);
    let a: B::V<W64> = b.get(sem::st_sig_ref(dst));
    let c = rq(b, ea)?;
    let half = 32 / bits;
    let base = if high { half } else { 0 };
    let mut acc = b.konst::<W64>(0);
    for i in 0..half {
        let al = lane64(b, a, (base + i) * bits, bits);
        let cl = lane64(b, c, (base + i) * bits, bits);
        acc = put_lane64(b, acc, al, (2 * i) * bits, bits);
        acc = put_lane64(b, acc, cl, (2 * i + 1) * bits, bits);
    }
    b.set(sem::st_sig_ref(dst), acc);
    Ok(())
}

/// PACKSSWB/W の MMX 形。`W` 要素を半分の幅に飽和変換して詰める
/// （dst が下位、src が上位）。`unsig` は packuswb（出力が符号なし飽和、
/// 入力は符号付き読み）。
pub fn mpack<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    unsig: bool,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_m(d);
    let a: B::V<W64> = b.get(sem::st_sig_ref(dst));
    let c = rq(b, ea)?;
    let mut acc = b.konst::<W64>(0);
    let n = 64 / W::BITS;
    let (lo, hi) = if unsig {
        (0u128, (1u128 << (W::BITS / 2)) - 1)
    } else {
        let h = W::BITS / 2;
        let mag = 1u128 << (h - 1);
        ((1u128 << W::BITS) - mag, mag - 1)
    };
    for (src_i, s) in [a, c].into_iter().enumerate() {
        for i in 0..n {
            let l = lane64(b, s, i * W::BITS, W::BITS);
            let v: B::V<W> = b.trunc::<W64, W>(l);
            let klo = b.konst::<W>(W::from_u128(lo));
            let khi = b.konst::<W>(W::from_u128(hi));
            let under = b.cmp::<W>(Cmp::LtS, v, klo);
            let over = b.cmp::<W>(Cmp::GtS, v, khi);
            let r = b.select::<W>(under, klo, v);
            let r = b.select::<W>(over, khi, r);
            let r64 = b.zext::<W, W64>(r);
            acc = put_lane64(
                b,
                acc,
                r64,
                (src_i as u32 * n + i) * (W::BITS / 2),
                W::BITS / 2,
            );
        }
    }
    b.set(sem::st_sig_ref(dst), acc);
    Ok(())
}

/// PSRL/PSRA/PSLL の MMX 形。
fn mshift_impl<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    dir: Psh,
    cnt: B::V<W64>,
    dst: usize,
) -> Flow<B> {
    let a: B::V<W64> = b.get(sem::st_sig_ref(dst));
    // カウントが幅以上なら結果は 0（PSRA は符号拡張）。
    let bits_k = b.konst::<W64>(u64::from(W::BITS));
    let over = b.cmp::<W64>(Cmp::GeU, cnt, bits_k);
    let cnt_w: B::V<W> = b.trunc::<W64, W>(cnt);
    let mut acc = b.konst::<W64>(0);
    let n = 64 / W::BITS;
    for i in 0..n {
        let al = lane64(b, a, i * W::BITS, W::BITS);
        let a_w: B::V<W> = b.trunc::<W64, W>(al);
        let r = match dir {
            Psh::L => b.shl::<W>(a_w, cnt_w),
            Psh::A => b.shr_a::<W>(a_w, cnt_w),
            Psh::R => b.shr_l::<W>(a_w, cnt_w),
        };
        let r = if matches!(dir, Psh::A) {
            let sign_sh = b.konst::<W>(W::from_u128((W::BITS - 1) as u128));
            let sg = b.shr_l::<W>(a_w, sign_sh);
            let wz2 = b.konst::<W>(W::from_u128(0));
            let neg = b.cmp::<W>(Cmp::Ne, sg, wz2);
            let ones = b.konst::<W>(W::from_u128((1u128 << W::BITS) - 1));
            let z = b.konst::<W>(W::from_u128(0));
            let ext = b.select::<W>(neg, ones, z);
            b.select::<W>(over, ext, r)
        } else {
            let z = b.konst::<W>(W::from_u128(0));
            b.select::<W>(over, z, r)
        };
        let r64 = b.zext::<W, W64>(r);
        acc = put_lane64(b, acc, r64, i * W::BITS, W::BITS);
    }
    b.set(sem::st_sig_ref(dst), acc);
    Ok(())
}

/// 2 被演算子形（mm, mm/m64）：dst は ModRM.reg、カウントは被演算子全体。
pub fn mshift<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    dir: Psh,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Flow<B> {
    let cnt = rq(b, ea)?;
    mshift_impl::<B, W>(b, dir, cnt, reg_m(d))
}

/// グループ即値形（mm, imm8）：dst は ModRM.r/m。
pub fn mshift_i<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    dir: Psh,
    imm: u8,
    d: &MapDec,
) -> Flow<B> {
    let c = b.konst::<W64>(u64::from(imm));
    mshift_impl::<B, W>(b, dir, c, rm_m(d))
}

/// PSHUFW。4 つの word を imm の 2 ビットずつで並べ替える。
pub fn mshufw<B: Backend>(
    b: &mut B,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let s = rq(b, ea)?;
    let mut acc = b.konst::<W64>(0);
    for i in 0..4u32 {
        let sel = u32::from((imm >> (2 * i)) & 3);
        let l = lane64(b, s, sel * 16, 16);
        acc = put_lane64(b, acc, l, i * 16, 16);
    }
    b.set(sem::st_sig_ref(reg_m(d)), acc);
    Ok(())
}

/// PMULHW/PMULHUW。16×16→32 の上位 16（`unsigned` は符号なし掛け）。
pub fn mmulh<B: Backend>(
    b: &mut B,
    unsigned: bool,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_m(d);
    let a: B::V<W64> = b.get(sem::st_sig_ref(dst));
    let c = rq(b, ea)?;
    let mut acc = b.konst::<W64>(0);
    for i in 0..4u32 {
        let al = lane64(b, a, i * 16, 16);
        let cl = lane64(b, c, i * 16, 16);
        let a16: B::V<W16> = b.trunc::<W64, W16>(al);
        let c16: B::V<W16> = b.trunc::<W64, W16>(cl);
        let av = if unsigned {
            b.zext::<W16, W32>(a16)
        } else {
            b.sext::<W16, W32>(a16)
        };
        let cv = if unsigned {
            b.zext::<W16, W32>(c16)
        } else {
            b.sext::<W16, W32>(c16)
        };
        let p = b.mul::<W32>(av, cv);
        let sh = b.konst::<W32>(16);
        let hi = b.shr_l::<W32>(p, sh);
        let hi64 = b.zext::<W32, W64>(hi);
        acc = put_lane64(b, acc, hi64, i * 16, 16);
    }
    b.set(sem::st_sig_ref(dst), acc);
    Ok(())
}

/// PMADDWD。隣接 s16 ペア同士の積の和を s32 にする。
pub fn mmaddwd<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let dst = reg_m(d);
    let a: B::V<W64> = b.get(sem::st_sig_ref(dst));
    let c = rq(b, ea)?;
    let mut acc = b.konst::<W64>(0);
    for i in 0..2u32 {
        let mut sum = b.konst::<W32>(0);
        for j in 0..2u32 {
            let al = lane64(b, a, (2 * i + j) * 16, 16);
            let cl = lane64(b, c, (2 * i + j) * 16, 16);
            let a16: B::V<W16> = b.trunc::<W64, W16>(al);
            let c16: B::V<W16> = b.trunc::<W64, W16>(cl);
            let av = b.sext::<W16, W32>(a16);
            let cv = b.sext::<W16, W32>(c16);
            let p = b.mul::<W32>(av, cv);
            sum = b.add::<W32>(sum, p);
        }
        let s64 = b.zext::<W32, W64>(sum);
        acc = put_lane64(b, acc, s64, i * 32, 32);
    }
    b.set(sem::st_sig_ref(dst), acc);
    Ok(())
}

/// PMULUDQ（MMX 形）。下位 u32 同士の積がそのまま 64 ビットの結果。
pub fn mmuludq<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let a: B::V<W64> = b.get(sem::st_sig_ref(reg_m(d)));
    let c = rq(b, ea)?;
    let a32: B::V<W32> = b.trunc::<W64, W32>(a);
    let c32: B::V<W32> = b.trunc::<W64, W32>(c);
    let av = b.zext::<W32, W64>(a32);
    let cv = b.zext::<W32, W64>(c32);
    let p = b.mul::<W64>(av, cv);
    b.set(sem::st_sig_ref(reg_m(d)), p);
    Ok(())
}

/// PSADBW。8 バイトの絶対差の和を下位 16 ビットへ（上位は 0）。
pub fn msadbw<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let a: B::V<W64> = b.get(sem::st_sig_ref(reg_m(d)));
    let c = rq(b, ea)?;
    let mut acc = b.konst::<W64>(0);
    for i in 0..8u32 {
        let al = lane64(b, a, i * 8, 8);
        let cl = lane64(b, c, i * 8, 8);
        let lt = b.cmp::<W64>(Cmp::LtU, al, cl);
        let d1 = b.sub::<W64>(al, cl);
        let d2 = b.sub::<W64>(cl, al);
        let diff = b.select::<W64>(lt, d2, d1);
        acc = b.add::<W64>(acc, diff);
    }
    b.set(sem::st_sig_ref(reg_m(d)), acc);
    Ok(())
}

/// MOVD/MOVQ mm, r/m。`w` が 64 なら movq、さもなくば movd（ゼロ拡張）。
pub fn movd_pv_ev<B: Backend>(
    b: &mut B,
    w: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let v = if w == 64 {
        decode::rd::<B, W64>(b, ea, d)?
    } else {
        let v32: B::V<W32> = decode::rd::<B, W32>(b, ea, d)?;
        b.zext::<W32, W64>(v32)
    };
    b.set(sem::st_sig_ref(reg_m(d)), v);
    Ok(())
}

/// MOVD/MOVQ r/m, mm。`w` が 64 なら 64 ビット、さもなくば下位 32。
pub fn movd_ev_pv<B: Backend>(
    b: &mut B,
    w: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let v: B::V<W64> = b.get(sem::st_sig_ref(reg_m(d)));
    if w == 64 {
        decode::wr::<B, W64>(b, ea, d, v)
    } else {
        let v32: B::V<W32> = b.trunc::<W64, W32>(v);
        decode::wr::<B, W32>(b, ea, d, v32)
    }
}

/// MOVQ mm, mm/m64。
pub fn movq_pv_qv<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let v = rq(b, ea)?;
    b.set(sem::st_sig_ref(reg_m(d)), v);
    Ok(())
}

/// MOVQ mm/m64, mm（MOVNTQ も同じ経路。nt ヒントは効果なし）。
pub fn movq_qv_pv<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let v: B::V<W64> = b.get(sem::st_sig_ref(reg_m(d)));
    match ea {
        Rm::Reg(g) => {
            b.set(sem::st_sig_ref((g.0 & 7) as usize), v);
            Ok(())
        }
        Rm::Mem { a, .. } => b.store::<W64>(*a, v, sem::DATA_WRITE),
    }
}

/// PINSRW mm, r32/m16, imm8。imm の下位 2 ビットの word を置き換える。
pub fn mpinsrw<B: Backend>(
    b: &mut B,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_m(d);
    let a: B::V<W64> = b.get(sem::st_sig_ref(dst));
    let w16: B::V<W16> = decode::rd16(b, ea)?;
    let w64 = b.zext::<W16, W64>(w16);
    let v = put_lane64(b, a, w64, u32::from(imm & 3) * 16, 16);
    b.set(sem::st_sig_ref(dst), v);
    Ok(())
}

/// PEXTRW r, mm, imm8。imm の下位 2 ビットの word を GPR に書く。
pub fn mpextrw<B: Backend>(
    b: &mut B,
    imm: u8,
    ea: &Rm<B::V<W64>>,
    dst: Gpr,
) -> Result<(), B::Exit> {
    let s = rq(b, ea)?;
    let l = lane64(b, s, u32::from(imm & 3) * 16, 16);
    let l16: B::V<W16> = b.trunc::<W64, W16>(l);
    let v = b.zext::<W16, W64>(l16);
    sem::write64(b, dst, v);
    Ok(())
}

/// PMOVMSKB（MMX 形）。8 バイトの符号ビットを 8 ビットに集める。
pub fn mmovmskb<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>, dst: Gpr) -> Result<(), B::Exit> {
    let s = rq(b, ea)?;
    let mut acc = b.konst::<W64>(0);
    for i in 0..8u32 {
        let l = lane64(b, s, i * 8 + 7, 1);
        let sh = b.konst::<W64>(u64::from(i));
        let placed = b.shl::<W64>(l, sh);
        acc = b.or::<W64>(acc, placed);
    }
    sem::write64(b, dst, acc);
    Ok(())
}

/// MASKMOVQ。マスク mm の各バイトの MSB が立つ要素だけ
/// データ mm を DS:(E)DI へ書く。
pub fn maskmovq<B: Backend>(
    b: &mut B,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
    seg: u64,
) -> Result<(), B::Exit> {
    let src: B::V<W64> = b.get(sem::st_sig_ref(reg_m(d)));
    let mask = rq(b, ea)?;
    let src128: B::V<W128> = b.zext::<W64, W128>(src);
    let mask128: B::V<W128> = b.zext::<W64, W128>(mask);
    maskmov_store(b, d, seg, src128, mask128, 8)
}

/// MASKMOVDQU（66 0F F7）。xmm のマスク上位ビットで選択した
/// バイトを DS:(E)DI に書き込む（16 バイト）。
pub fn maskmovdqu<B: Backend>(
    b: &mut B,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
    seg: u64,
) -> Result<(), B::Exit> {
    let src: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    let mask = rx(b, ea, 128)?;
    maskmov_store(b, d, seg, src, mask, 16)
}

/// マスク付きバイト列を DS:(E)DI に書き込む共有部。
fn maskmov_store<B: Backend>(
    b: &mut B,
    d: &MapDec,
    seg: u64,
    src: B::V<W128>,
    mask: B::V<W128>,
    n: u32,
) -> Result<(), B::Exit> {
    let di = sem::read64(b, Gpr(7));
    // (E)DI はアドレスサイズで折り返してから DS 基底を足す。
    let off = match d.asize {
        16 => {
            let m16 = b.konst::<W64>(0xffff);
            b.and::<W64>(di, m16)
        }
        32 => {
            let m32 = b.konst::<W64>(0xffff_ffff);
            b.and::<W64>(di, m32)
        }
        _ => di,
    };
    let sb = b.konst::<W64>(seg);
    let base = b.add::<W64>(off, sb);
    for i in 0..n {
        let m = lane128(b, mask, i * 8 + 7, 1);
        let m8: B::V<W8> = b.trunc::<W128, W8>(m);
        let z8 = b.konst::<W8>(0);
        let en = b.cmp::<W8>(Cmp::Ne, m8, z8);
        let byte = lane128(b, src, i * 8, 8);
        let b8: B::V<W8> = b.trunc::<W128, W8>(byte);
        let koff = b.konst::<W64>(u64::from(i));
        let a = b.add::<W64>(base, koff);
        b.if_then(en, |b| b.store::<W8>(a, b8, sem::DATA_WRITE))?;
    }
    Ok(())
}

/// EMMS。タグワードはモデル化していないので状態変化なし。
pub fn emms<B: Backend>(_b: &mut B) -> Flow<B> {
    Ok(())
}

// ===== 0F 38 / 0F 3A サブマップ（SSSE3/SSE4.1/MOVBE）=====

/// PSHUFB。制御バイトの MSB が立つ要素は 0、下位 4 ビットが選ぶバイト。
pub fn pshufb<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let c = rx(b, ea, 128)?;
    let mut acc = b.konst::<W128>(0);
    for i in 0..16u32 {
        let ctrl = lane128(b, c, i * 8, 8);
        let c8: B::V<W8> = b.trunc::<W128, W8>(ctrl);
        let k0f = b.konst::<W8>(0x0F);
        let idx = b.and::<W8>(c8, k0f);
        let idx128 = b.zext::<W8, W128>(idx);
        let k3 = b.konst::<W128>(3);
        let sh = b.shl::<W128>(idx128, k3);
        let kff = b.konst::<W128>(0xFF);
        let shifted = b.shr_l::<W128>(a, sh);
        let byte = b.and::<W128>(shifted, kff);
        let k80 = b.konst::<W8>(0x80);
        let m = b.and::<W8>(c8, k80);
        let z8 = b.konst::<W8>(0);
        let msb = b.cmp::<W8>(Cmp::Ne, m, z8);
        let z128 = b.konst::<W128>(0);
        let v = b.select::<W128>(msb, z128, byte);
        acc = put_lane128(b, acc, v, i * 8, 8);
    }
    b.set(sem::xmm_ref(dst), acc);
    Ok(())
}

/// PHADDW/PHADDD/PHADDSW/PHSUBW/PHSUBD/PHSUBSW。
/// 隣接ペアを加減算し、dst 側ペアを下位 64・src 側ペアを上位 64 に詰める。
pub fn phaddsub<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    sub: bool,
    sat: bool,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let c = rx(b, ea, 128)?;
    let bits = W::BITS;
    let half = 64 / bits;
    let mut acc = b.konst::<W128>(0);
    for (src_i, s) in [a, c].into_iter().enumerate() {
        for i in 0..half {
            let l0 = lane128(b, s, 2 * i * bits, bits);
            let l1 = lane128(b, s, (2 * i + 1) * bits, bits);
            let w0: B::V<W> = b.trunc::<W128, W>(l0);
            let w1: B::V<W> = b.trunc::<W128, W>(l1);
            let r = match (sub, sat) {
                (true, true) => sat_sub_s::<B, W>(b, w0, w1),
                (true, false) => b.sub::<W>(w0, w1),
                (false, true) => sat_add_s::<B, W>(b, w0, w1),
                (false, false) => b.add::<W>(w0, w1),
            };
            let r128 = b.zext::<W, W128>(r);
            acc = put_lane128(b, acc, r128, (src_i as u32 * half + i) * bits, bits);
        }
    }
    b.set(sem::xmm_ref(dst), acc);
    Ok(())
}

/// PSIGNB/W/D。`c < 0` なら `-a`、`c == 0` なら 0、それ以外は `a`。
pub fn psign<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    lane_bin::<B, W>(b, d, ea, |b, a, c| {
        let z = b.konst::<W>(W::from_u128(0));
        let neg = b.cmp::<W>(Cmp::LtS, c, z);
        let zero = b.cmp::<W>(Cmp::Eq, c, z);
        let nega = b.sub::<W>(z, a);
        let inner = b.select::<W>(zero, z, a);
        b.select::<W>(neg, nega, inner)
    })
}

/// PMADDUBSW。符号なし a バイトと符号付き c バイトの積を、隣接ペアで
/// s16 飽和の和にする。
pub fn pmaddubsw<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let c = rx(b, ea, 128)?;
    let mut acc = b.konst::<W128>(0);
    for i in 0..8u32 {
        let mut sum = b.konst::<W32>(0);
        for j in 0..2u32 {
            let at = i * 16 + j * 8;
            let al = lane128(b, a, at, 8);
            let cl = lane128(b, c, at, 8);
            let a8: B::V<W8> = b.trunc::<W128, W8>(al);
            let c8: B::V<W8> = b.trunc::<W128, W8>(cl);
            let ab = b.zext::<W8, W32>(a8);
            let cb = b.sext::<W8, W32>(c8);
            let p = b.mul::<W32>(ab, cb);
            sum = b.add::<W32>(sum, p);
        }
        // s16 飽和。
        let kmin = b.konst::<W32>(0xFFFF_8000);
        let kmax = b.konst::<W32>(0x7FFF);
        let lo = b.cmp::<W32>(Cmp::LtS, sum, kmin);
        let hi = b.cmp::<W32>(Cmp::GtS, sum, kmax);
        let r = b.select::<W32>(lo, kmin, sum);
        let r = b.select::<W32>(hi, kmax, r);
        let r128 = b.zext::<W32, W128>(r);
        acc = put_lane128(b, acc, r128, i * 16, 16);
    }
    b.set(sem::xmm_ref(dst), acc);
    Ok(())
}

/// PMULHRSW。`((a*c*2) + 0x8000) >> 16` を s16 飽和にする。
pub fn pmulhrsw<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let c = rx(b, ea, 128)?;
    let mut acc = b.konst::<W128>(0);
    for i in 0..8u32 {
        let al = lane128(b, a, i * 16, 16);
        let cl = lane128(b, c, i * 16, 16);
        let a16: B::V<W16> = b.trunc::<W128, W16>(al);
        let c16: B::V<W16> = b.trunc::<W128, W16>(cl);
        let av = b.sext::<W16, W32>(a16);
        let cv = b.sext::<W16, W32>(c16);
        let p = b.mul::<W32>(av, cv);
        let k1 = b.konst::<W32>(1);
        let k8000 = b.konst::<W32>(0x8000);
        let p2 = b.shl::<W32>(p, k1);
        let t = b.add::<W32>(p2, k8000);
        let k16 = b.konst::<W32>(16);
        let r = b.shr_a::<W32>(t, k16);
        let r128 = b.zext::<W32, W128>(r);
        acc = put_lane128(b, acc, r128, i * 16, 16);
    }
    b.set(sem::xmm_ref(dst), acc);
    Ok(())
}

/// PABSB/W/D。`|src[i]|`。
pub fn pabs<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let s = rx(b, ea, 128)?;
    let bits = W::BITS;
    let mut acc = b.konst::<W128>(0);
    for i in 0..(128 / bits) {
        let l = lane128(b, s, i * bits, bits);
        let v: B::V<W> = b.trunc::<W128, W>(l);
        let z = b.konst::<W>(W::from_u128(0));
        let neg = b.cmp::<W>(Cmp::LtS, v, z);
        let nega = b.sub::<W>(z, v);
        let r = b.select::<W>(neg, nega, v);
        let r128 = b.zext::<W, W128>(r);
        acc = put_lane128(b, acc, r128, i * bits, bits);
    }
    b.set(sem::xmm_ref(dst), acc);
    Ok(())
}

/// PTEST。ZF = (a & c) == 0、CF = (c & !a) == 0。他の状況旗はクリア。
pub fn ptest<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Flow<B> {
    let a: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    let c = rx(b, ea, 128)?;
    let z = b.konst::<W128>(0);
    let t1 = b.and::<W128>(a, c);
    let na = b.not::<W128>(a);
    let t2 = b.and::<W128>(na, c);
    let zf = b.cmp::<W128>(Cmp::Eq, t1, z);
    let cf = b.cmp::<W128>(Cmp::Eq, t2, z);
    let f: B::V<W32> = b.get(eflags_ref());
    let mask = b.konst::<W32>(
        sem::FLAG_ZF | sem::FLAG_PF | sem::FLAG_CF | sem::FLAG_OF | sem::FLAG_SF | sem::FLAG_AF,
    );
    let nmask = b.not::<W32>(mask);
    let kept = b.and::<W32>(f, nmask);
    let zf_v = pick(b, zf, sem::FLAG_ZF);
    let cf_v = pick(b, cf, sem::FLAG_CF);
    let v = b.or::<W32>(kept, zf_v);
    let v = b.or::<W32>(v, cf_v);
    b.set(eflags_ref(), v);
    Ok(())
}

/// `from` ビット整数を `to` ビットへ拡張する（`signed` で符号拡張）。
fn ext_int<B: Backend>(b: &mut B, v: B::V<W128>, from: u32, to: u32, signed: bool) -> B::V<W128> {
    macro_rules! e {
        ($f:ty, $t:ty) => {{
            let x: B::V<$f> = b.trunc::<W128, $f>(v);
            let r = if signed {
                b.sext::<$f, $t>(x)
            } else {
                b.zext::<$f, $t>(x)
            };
            b.zext::<$t, W128>(r)
        }};
    }
    match (from, to) {
        (8, 16) => e!(W8, W16),
        (8, 32) => e!(W8, W32),
        (8, 64) => e!(W8, W64),
        (16, 32) => e!(W16, W32),
        (16, 64) => e!(W16, W64),
        (32, 64) => e!(W32, W64),
        _ => v,
    }
}

/// PMOVSX*/PMOVZX*。下位要素を `to` ビット幅へ拡張して詰める。
/// m16/m32 形は `rx` が 128 ビット読みするためページ端で実機より
/// 広く読み得る。Gap: GAP-0036
pub fn pmovx<B: Backend>(
    b: &mut B,
    from: u32,
    to: u32,
    signed: bool,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let n = 128 / to;
    let s = rx(b, ea, n * from)?;
    let mut acc = b.konst::<W128>(0);
    for i in 0..n {
        let l = lane128(b, s, i * from, from);
        let e = ext_int(b, l, from, to, signed);
        acc = put_lane128(b, acc, e, i * to, to);
    }
    b.set(sem::xmm_ref(reg_x(d)), acc);
    Ok(())
}

/// PMULDQ。偶数 i32 レーンの符号付き積を i64 で 2 本得る。
pub fn pmuldq<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let a: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    let c = rx(b, ea, 128)?;
    let mut acc = b.konst::<W128>(0);
    for i in 0..2u32 {
        let al = lane128(b, a, i * 64, 32);
        let cl = lane128(b, c, i * 64, 32);
        let a32: B::V<W32> = b.trunc::<W128, W32>(al);
        let c32: B::V<W32> = b.trunc::<W128, W32>(cl);
        let av = b.sext::<W32, W64>(a32);
        let cv = b.sext::<W32, W64>(c32);
        let p = b.mul::<W64>(av, cv);
        let p128 = b.zext::<W64, W128>(p);
        acc = put_lane128(b, acc, p128, i * 64, 64);
    }
    b.set(sem::xmm_ref(reg_x(d)), acc);
    Ok(())
}

/// PACKUSDW。i32 を u16 飽和に変換して詰める（dst が下位、src が上位）。
pub fn packusdw<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let a: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    let c = rx(b, ea, 128)?;
    let mut acc = b.konst::<W128>(0);
    for (src_i, s) in [a, c].into_iter().enumerate() {
        for i in 0..4u32 {
            let l = lane128(b, s, i * 32, 32);
            let v: B::V<W32> = b.trunc::<W128, W32>(l);
            let kz = b.konst::<W32>(0);
            let kmax = b.konst::<W32>(0xFFFF);
            let neg = b.cmp::<W32>(Cmp::LtS, v, kz);
            let over = b.cmp::<W32>(Cmp::GtS, v, kmax);
            let kz = b.konst::<W32>(0);
            let r = b.select::<W32>(neg, kz, v);
            let kmax = b.konst::<W32>(0xFFFF);
            let r = b.select::<W32>(over, kmax, r);
            let r128 = b.zext::<W32, W128>(r);
            acc = put_lane128(b, acc, r128, (src_i as u32 * 4 + i) * 16, 16);
        }
    }
    b.set(sem::xmm_ref(reg_x(d)), acc);
    Ok(())
}

/// PALIGNR。`(dst:src)` の 256 ビット連結を imm バイト右にずらし下位
/// 128 ビットを取る。
pub fn palignr<B: Backend>(
    b: &mut B,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let c = rx(b, ea, 128)?;
    let sh = u32::from(imm) * 8;
    let v = if sh == 0 {
        c
    } else if sh < 128 {
        let ksh = b.konst::<W128>(u128::from(sh));
        let lo = b.shr_l::<W128>(c, ksh);
        let ksh2 = b.konst::<W128>(u128::from(128 - sh));
        let hi = b.shl::<W128>(a, ksh2);
        b.or::<W128>(lo, hi)
    } else if sh < 256 {
        let ksh = b.konst::<W128>(u128::from(sh - 128));
        b.shr_l::<W128>(a, ksh)
    } else {
        b.konst::<W128>(0)
    };
    b.set(sem::xmm_ref(dst), v);
    Ok(())
}

/// BLENDPS/BLENDPD/PBLENDW。imm の各ビットで `c` のレーンを選ぶ
/// （0 は `a` を維持）。`bits` は 16/32/64。
pub fn blendp<B: Backend>(
    b: &mut B,
    bits: u32,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let c = rx(b, ea, 128)?;
    let mut acc = b.konst::<W128>(0);
    for i in 0..(128 / bits) {
        let l = if imm >> i & 1 == 1 {
            lane128(b, c, i * bits, bits)
        } else {
            lane128(b, a, i * bits, bits)
        };
        acc = put_lane128(b, acc, l, i * bits, bits);
    }
    b.set(sem::xmm_ref(dst), acc);
    Ok(())
}

/// PEXTRB/PEXTRW/PEXTRD/PEXTRQ/EXTRACTPS。`bits` 幅のレーンを取り出して
/// Ea 先へ書く。mod=11（GPR）はゼロ拡張して 32/64 ビットに書く。
pub fn pextrx<B: Backend>(
    b: &mut B,
    bits: u32,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let s: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    let n = 128 / bits;
    let sel = u32::from(imm) & (n - 1);
    let l = lane128(b, s, sel * bits, bits);
    match ea {
        Rm::Reg(g) => {
            let v: B::V<W64> = b.trunc::<W128, W64>(l);
            sem::write64(b, *g, v);
            Ok(())
        }
        Rm::Mem { a, .. } => {
            let a = *a;
            match bits {
                8 => {
                    let v: B::V<W8> = b.trunc::<W128, W8>(l);
                    b.store::<W8>(a, v, sem::DATA_WRITE)
                }
                16 => {
                    let v: B::V<W16> = b.trunc::<W128, W16>(l);
                    b.store::<W16>(a, v, sem::DATA_WRITE)
                }
                32 => {
                    let v: B::V<W32> = b.trunc::<W128, W32>(l);
                    b.store::<W32>(a, v, sem::DATA_WRITE)
                }
                _ => {
                    let v: B::V<W64> = b.trunc::<W128, W64>(l);
                    b.store::<W64>(a, v, sem::DATA_WRITE)
                }
            }
        }
    }
}

/// PINSRB/PINSRD/PINSRQ。Ea の `bits` 幅を `sel` のレーンへ挿入する。
pub fn pinsrx<B: Backend>(
    b: &mut B,
    bits: u32,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let a: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    let v: B::V<W64> = match bits {
        8 => {
            let x: B::V<W8> = decode::rd8(b, ea, d)?;
            b.zext::<W8, W64>(x)
        }
        16 => {
            let x: B::V<W16> = decode::rd16(b, ea)?;
            b.zext::<W16, W64>(x)
        }
        32 => {
            let x: B::V<W32> = decode::rd32(b, ea)?;
            b.zext::<W32, W64>(x)
        }
        _ => decode::rd64(b, ea)?,
    };
    let v128: B::V<W128> = b.zext::<W64, W128>(v);
    let n = 128 / bits;
    let sel = u32::from(imm) & (n - 1);
    let r = put_lane128(b, a, v128, sel * bits, bits);
    b.set(sem::xmm_ref(reg_x(d)), r);
    Ok(())
}

/// INSERTPS。mod=11 は src xmm の `count_s` レーン、メモリは m32 を、
/// `count_d` レーンへ挿入する。`zmask` のビットが立つレーンは 0 にする。
pub fn insertps<B: Backend>(
    b: &mut B,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let a: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    let s = if d.modrm >= 0xC0 {
        let src: B::V<W128> = b.get(sem::xmm_ref(rm_x(d)));
        lane128(b, src, u32::from(imm >> 6 & 3) * 32, 32)
    } else {
        rx(b, ea, 32)?
    };
    let mut v = put_lane128(b, a, s, u32::from(imm >> 4 & 3) * 32, 32);
    for i in 0..4u32 {
        if imm >> i & 1 == 1 {
            let z = b.konst::<W128>(0);
            v = put_lane128(b, v, z, i * 32, 32);
        }
    }
    b.set(sem::xmm_ref(reg_x(d)), v);
    Ok(())
}

/// `bits` 幅（16/32/64）のバイト順反転。
fn bswap_bits<B: Backend>(b: &mut B, v: B::V<W64>, bits: u32) -> B::V<W64> {
    let n = bits / 8;
    let mut acc = b.konst::<W64>(0);
    for i in 0..n {
        let sh = b.konst::<W64>(u64::from(i * 8));
        let kff = b.konst::<W64>(0xFF);
        let shv = b.shr_l::<W64>(v, sh);
        let byte = b.and::<W64>(shv, kff);
        let to = b.konst::<W64>(u64::from((n - 1 - i) * 8));
        let placed = b.shl::<W64>(byte, to);
        acc = b.or::<W64>(acc, placed);
    }
    acc
}

/// MOVBE load。`w` ビットのメモリを読み、バイト順を反転して GPR に書く。
pub fn movbe_ld<B: Backend>(b: &mut B, w: u8, reg: Gpr, d: &MapDec, ea: &Rm<B::V<W64>>) -> Flow<B> {
    let v: B::V<W64> = match w {
        16 => {
            let x: B::V<W16> = decode::rd16(b, ea)?;
            b.zext::<W16, W64>(x)
        }
        64 => decode::rd64(b, ea)?,
        _ => {
            let x: B::V<W32> = decode::rd32(b, ea)?;
            b.zext::<W32, W64>(x)
        }
    };
    let r = bswap_bits(b, v, u32::from(w));
    match w {
        64 => sem::write64(b, reg, r),
        16 => {
            let r16: B::V<W16> = b.trunc::<W64, W16>(r);
            gwr_w::<B, W16>(b, reg, d, r16);
        }
        _ => {
            let r32: B::V<W32> = b.trunc::<W64, W32>(r);
            gwr_w::<B, W32>(b, reg, d, r32);
        }
    }
    Ok(())
}

/// MOVBE store。GPR の `w` ビットをバイト順反転してメモリに書く。
pub fn movbe_st<B: Backend>(b: &mut B, w: u8, reg: Gpr, d: &MapDec, ea: &Rm<B::V<W64>>) -> Flow<B> {
    let v: B::V<W64> = match w {
        16 => {
            let x: B::V<W16> = grd_w::<B, W16>(b, reg, d);
            b.zext::<W16, W64>(x)
        }
        64 => grd_w::<B, W64>(b, reg, d),
        _ => {
            let x: B::V<W32> = grd_w::<B, W32>(b, reg, d);
            b.zext::<W32, W64>(x)
        }
    };
    let r = bswap_bits(b, v, u32::from(w));
    match w {
        16 => {
            let r16: B::V<W16> = b.trunc::<W64, W16>(r);
            decode::wr16(b, ea, r16)
        }
        64 => {
            let r64: B::V<W64> = r;
            decode::wr64(b, ea, r64)
        }
        _ => {
            let r32: B::V<W32> = b.trunc::<W64, W32>(r);
            decode::wr32(b, ea, r32)
        }
    }
}

// ===== x87（オペコード表経路）=====
//
// ST(i) は物理スロット (top + i) & 7。mod=11 の r/m フィールドが i。
// 状態は sig/exp/top で持つ（タグ・ステータスワードは未モデル）。

/// ST(i) のスロット番号を値ドメインで返す。i はホスト既知。
fn st_slot<B: Backend>(b: &mut B, i: u8) -> B::V<W16> {
    let top = b.get(sem::top_ref());
    let ii = b.konst::<W16>(u16::from(i));
    let summed = b.add::<W16>(top, ii);
    let seven = b.konst::<W16>(7);
    b.and::<W16>(summed, seven)
}

/// FLD m32/m64/m80。m80 は仮数 8 バイト + 指数 2 バイト。
pub fn fld_m<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>, bits: u32) -> Result<(), B::Exit> {
    match ea {
        Rm::Reg(_) => Ok(()),
        Rm::Mem { a, .. } => {
            let a = *a;
            match bits {
                32 => {
                    let v: B::V<W32> = b.load::<W32>(a, sem::DATA_READ)?;
                    sem::push_f32(b, v)
                }
                80 => {
                    let sig: B::V<W64> = b.load::<W64>(a, sem::DATA_READ)?;
                    let a8 = b.konst::<W64>(8);
                    let a2 = b.add::<W64>(a, a8);
                    let exp: B::V<W16> = b.load::<W16>(a2, sem::DATA_READ)?;
                    sem::push_ext(b, sig, exp)
                }
                _ => {
                    let v: B::V<W64> = b.load::<W64>(a, sem::DATA_READ)?;
                    sem::push_f64(b, v)
                }
            }
        }
    }
}

/// FST/FSTP m32/m64/m80。pop でスタックを一つ捨てる。
pub fn fst_m<B: Backend>(
    b: &mut B,
    ea: &Rm<B::V<W64>>,
    bits: u32,
    pop: bool,
) -> Result<(), B::Exit> {
    let top = b.get(sem::top_ref());
    let (sig, exp) = sem::read_st(b, top);
    if let Rm::Mem { a, .. } = ea {
        let a = *a;
        match bits {
            32 => {
                let v64 = sem::f80_to_f64(b, sig, exp);
                let f = b.trunc::<W64, polyisa_sem::F64>(v64);
                let v32 = b.fcvt_ff::<polyisa_sem::F64, polyisa_sem::F32>(f, 0);
                let bits32 = b.trunc::<polyisa_sem::F32, W32>(v32);
                b.store::<W32>(a, bits32, sem::DATA_WRITE)?;
            }
            80 => {
                b.store::<W64>(a, sig, sem::DATA_WRITE)?;
                let a8 = b.konst::<W64>(8);
                let a2 = b.add::<W64>(a, a8);
                b.store::<W16>(a2, exp, sem::DATA_WRITE)?;
            }
            _ => {
                let v = sem::f80_to_f64(b, sig, exp);
                b.store::<W64>(a, v, sem::DATA_WRITE)?;
            }
        }
    }
    if pop {
        sem::pop_st(b, top)?;
    }
    Ok(())
}

/// FST/FSTP ST(i)（DD D0/D8+i）。
pub fn fst_sti<B: Backend>(b: &mut B, i: u8, pop: bool) -> Flow<B> {
    let top = b.get(sem::top_ref());
    let (sig, exp) = sem::read_st(b, top);
    let dst = st_slot(b, i);
    sem::write_st(b, dst, sig, exp);
    if pop {
        sem::pop_st(b, top)?;
    }
    Ok(())
}

/// FILD m16/m32/m64。
pub fn fild_m<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>, bits: u32) -> Result<(), B::Exit> {
    if let Rm::Mem { a, .. } = ea {
        let a = *a;
        match bits {
            16 => {
                let v: B::V<W16> = b.load::<W16>(a, sem::DATA_READ)?;
                let v32 = b.sext::<W16, W32>(v);
                sem::push_i32(b, v32)
            }
            32 => {
                let v: B::V<W32> = b.load::<W32>(a, sem::DATA_READ)?;
                sem::push_i32(b, v)
            }
            _ => {
                let v: B::V<W64> = b.load::<W64>(a, sem::DATA_READ)?;
                sem::push_i64(b, v)
            }
        }
    } else {
        Ok(())
    }
}

/// FIST/FISTP m16/m32/m64。
pub fn fist_m<B: Backend>(
    b: &mut B,
    ea: &Rm<B::V<W64>>,
    bits: u32,
    pop: bool,
) -> Result<(), B::Exit> {
    let top = b.get(sem::top_ref());
    let (sig, exp) = sem::read_st(b, top);
    let v = sem::f80_to_i64(b, sig, exp);
    if let Rm::Mem { a, .. } = ea {
        let a = *a;
        match bits {
            16 => {
                let v16: B::V<W16> = b.trunc::<W64, W16>(v);
                b.store::<W16>(a, v16, sem::DATA_WRITE)?;
            }
            32 => {
                let v32: B::V<W32> = b.trunc::<W64, W32>(v);
                b.store::<W32>(a, v32, sem::DATA_WRITE)?;
            }
            _ => {
                b.store::<W64>(a, v, sem::DATA_WRITE)?;
            }
        }
    }
    if pop {
        sem::pop_st(b, top)?;
    }
    Ok(())
}

/// x87 のメモリ二項演算（fadd/fmul/fsub/fsubr/fdiv/fdivr）。
/// `rev` で被演算子の順序を反転（fsubr/fdivr）。
#[derive(Clone, Copy)]
pub enum FAr {
    Add,
    Sub,
    SubR,
    Mul,
    Div,
    DivR,
}

fn ext_arith<B: Backend>(
    b: &mut B,
    op: FAr,
    s0: B::V<W64>,
    e0: B::V<W16>,
    s1: B::V<W64>,
    e1: B::V<W16>,
) -> (B::V<W64>, B::V<W16>) {
    let sign_mask = b.konst::<W16>(0x8000);
    match op {
        FAr::Add => sem::add_ext(b, s0, e0, s1, e1),
        FAr::Sub => {
            let ne = b.xor::<W16>(e1, sign_mask);
            sem::add_ext(b, s0, e0, s1, ne)
        }
        FAr::SubR => {
            let ne = b.xor::<W16>(e0, sign_mask);
            sem::add_ext(b, s1, e1, s0, ne)
        }
        FAr::Mul => sem::mul_ext(b, s0, e0, s1, e1),
        FAr::Div => sem::div_ext(b, s0, e0, s1, e1),
        FAr::DivR => sem::div_ext(b, s1, e1, s0, e0),
    }
}

/// x87 の m32/m64 二項演算。ST(0) = ST(0) op m。
pub fn farith_m<B: Backend>(
    b: &mut B,
    op: FAr,
    ea: &Rm<B::V<W64>>,
    fbits: u32,
) -> Result<(), B::Exit> {
    if let Rm::Mem { a, .. } = ea {
        let a = *a;
        let (sm, em) = if fbits == 32 {
            let v: B::V<W32> = b.load::<W32>(a, sem::DATA_READ)?;
            sem::f32_to_ext(b, v)
        } else {
            let v: B::V<W64> = b.load::<W64>(a, sem::DATA_READ)?;
            sem::f64_to_ext(b, v)
        };
        let top = b.get(sem::top_ref());
        let (s0, e0) = sem::read_st(b, top);
        let (sr, er) = ext_arith(b, op, s0, e0, sm, em);
        sem::write_st(b, top, sr, er);
    }
    Ok(())
}

/// x87 の整数二項演算（fiadd/fimul/fisub/fisubr/fidiv/fidivr）m16/m32。
pub fn fiarith_m<B: Backend>(
    b: &mut B,
    op: FAr,
    ea: &Rm<B::V<W64>>,
    bits: u32,
) -> Result<(), B::Exit> {
    if let Rm::Mem { a, .. } = ea {
        let a = *a;
        let v64 = if bits == 16 {
            let v: B::V<W16> = b.load::<W16>(a, sem::DATA_READ)?;
            b.sext::<W16, W64>(v)
        } else {
            let v: B::V<W32> = b.load::<W32>(a, sem::DATA_READ)?;
            b.sext::<W32, W64>(v)
        };
        let (sm, em) = sem::i64_to_ext(b, v64);
        let top = b.get(sem::top_ref());
        let (s0, e0) = sem::read_st(b, top);
        let (sr, er) = ext_arith(b, op, s0, e0, sm, em);
        sem::write_st(b, top, sr, er);
    }
    Ok(())
}

/// x87 の ST(i) 二項演算。`rev` は ST(i) 側を結果の書き先にする
/// DC 形（st(i) = st(i) op st(0) の順、sub/div は反転済みの FAr を渡す）。
/// `pop` で ST(0) を捨てる（DE 形）。
pub fn farith_st<B: Backend>(b: &mut B, op: FAr, i: u8, rev: bool, pop: bool) -> Flow<B> {
    let top = b.get(sem::top_ref());
    let (s0, e0) = sem::read_st(b, top);
    let slot = st_slot(b, i);
    let (s1, e1) = sem::read_st(b, slot);
    let (sr, er) = if rev {
        ext_arith(b, op, s1, e1, s0, e0)
    } else {
        ext_arith(b, op, s0, e0, s1, e1)
    };
    let dst = if rev { slot } else { top };
    sem::write_st(b, dst, sr, er);
    if pop {
        sem::pop_st(b, top)?;
    }
    Ok(())
}

/// FCMOVcc。cond が真なら ST(0) = ST(i)。
/// code: 0=B 1=E 2=BE 3=U 4=NB 5=NE 6=NBE 7=NU（DA/DB のグループ順）。
pub fn fcmov_cc<B: Backend>(b: &mut B, code: u8, i: u8) -> Flow<B> {
    let f: B::V<W32> = b.get(eflags_ref());
    let bit = |b: &mut B, m: u32| {
        let mk = b.konst::<W32>(m);
        let masked = b.and::<W32>(f, mk);
        let z = b.konst::<W32>(0);
        b.cmp::<W32>(Cmp::Ne, masked, z)
    };
    let cond = match code & 7 {
        0 => bit(b, 0x1),
        1 => bit(b, 0x40),
        2 => {
            let cf = bit(b, 0x1);
            let zf = bit(b, 0x40);
            sem::bit_or(b, cf, zf)
        }
        3 => bit(b, 0x4),
        4 => {
            let cf = bit(b, 0x1);
            sem::bit_not(b, cf)
        }
        5 => {
            let zf = bit(b, 0x40);
            sem::bit_not(b, zf)
        }
        6 => {
            let cf = bit(b, 0x1);
            let zf = bit(b, 0x40);
            let be = sem::bit_or(b, cf, zf);
            sem::bit_not(b, be)
        }
        _ => {
            let pf = bit(b, 0x4);
            sem::bit_not(b, pf)
        }
    };
    fcmov(b, cond, i)
}

/// FCMOVcc。cond が真なら ST(0) = ST(i)。
pub fn fcmov<B: Backend>(b: &mut B, cond: B::B, i: u8) -> Flow<B> {
    let top = b.get(sem::top_ref());
    let (s0, e0) = sem::read_st(b, top);
    let slot = st_slot(b, i);
    let (s1, e1) = sem::read_st(b, slot);
    let sig = b.select::<W64>(cond, s1, s0);
    let exp = b.select::<W16>(cond, e1, e0);
    sem::write_st(b, top, sig, exp);
    Ok(())
}

/// FCHS（符号反転）/FABS（符号クリア）。
pub fn fchs_abs<B: Backend>(b: &mut B, abs: bool) -> Flow<B> {
    let top = b.get(sem::top_ref());
    let (sig, exp) = sem::read_st(b, top);
    let new_exp = if abs {
        let m = b.konst::<W16>(0x7fff);
        b.and::<W16>(exp, m)
    } else {
        let m = b.konst::<W16>(0x8000);
        b.xor::<W16>(exp, m)
    };
    sem::write_st(b, top, sig, new_exp);
    Ok(())
}

/// FLD1/FLDZ/FLDPI/FLDL2T/FLDL2E/FLDLG2/FLDLN2。
pub fn fld_const<B: Backend>(b: &mut B, which: u8) -> Flow<B> {
    let (sig, exp): (u64, u16) = match which {
        0 => (0x8000_0000_0000_0000, 0x3fff), // 1.0
        1 => (0xD49A_784B_CD1B_8AFE, 0x4000), // log2(10)
        2 => (0xB8AA_3B29_5C17_F0BC, 0x3fff), // log2(e)
        3 => (0xC90F_DAA2_2168_C235, 0x4000), // pi
        4 => (0x9A20_9A84_FBCF_F799, 0x3ffd), // log10(2)
        5 => (0xB172_17F7_D1CF_79AC, 0x3ffe), // ln(2)
        _ => (0, 0),                          // 0.0
    };
    let s = b.konst::<W64>(sig);
    let e = b.konst::<W16>(exp);
    sem::push_ext(b, s, e)
}

/// FSQRT。80 ビットを倍精度に落として平方根し戻す（精度は倍精度近似）。
pub fn fsqrt_st<B: Backend>(b: &mut B) -> Flow<B> {
    let top = b.get(sem::top_ref());
    let (sig, exp) = sem::read_st(b, top);
    let v = sem::f80_to_f64(b, sig, exp);
    let f = b.trunc::<W64, polyisa_sem::F64>(v);
    let r = b.fsqrt::<polyisa_sem::F64>(f);
    let r64 = b.trunc::<polyisa_sem::F64, W64>(r);
    let (sr, er) = sem::f64_to_ext(b, r64);
    sem::write_st(b, top, sr, er);
    Ok(())
}

/// FRNDINT。倍精度経由で整数値へ丸める（RC は RNE 近似、|x|>2^63 は不正確）。
pub fn frndint_st<B: Backend>(b: &mut B) -> Flow<B> {
    let top = b.get(sem::top_ref());
    let (sig, exp) = sem::read_st(b, top);
    let v = sem::f80_to_f64(b, sig, exp);
    let f = b.trunc::<W64, polyisa_sem::F64>(v);
    let i = b.fcvt_s64::<polyisa_sem::F64>(f, 0);
    let r = b.fcvt_from_s64::<polyisa_sem::F64>(i, 0);
    let r64 = b.trunc::<polyisa_sem::F64, W64>(r);
    let (sr, er) = sem::f64_to_ext(b, r64);
    sem::write_st(b, top, sr, er);
    Ok(())
}

/// FFREE。タグ未モデルのためスロットをゼロにする。
pub fn ffree<B: Backend>(b: &mut B, i: u8) -> Flow<B> {
    let slot = st_slot(b, i);
    let z64 = b.konst::<W64>(0);
    let z16 = b.konst::<W16>(0);
    sem::write_st(b, slot, z64, z16);
    Ok(())
}

/// FFREEP（DF C0+i）。FFREE に続けてスタックを一つ捨てる。
pub fn ffreep<B: Backend>(b: &mut B, i: u8) -> Flow<B> {
    ffree(b, i)?;
    let top = b.get(sem::top_ref());
    sem::pop_st(b, top)
}

/// FDECSTP/FINCSTP。TOP を -1/+1 する。
pub fn fdecstp<B: Backend>(b: &mut B, inc: bool) -> Flow<B> {
    let top = b.get(sem::top_ref());
    let one = b.konst::<W16>(1);
    let seven = b.konst::<W16>(7);
    let moved = if inc {
        b.add::<W16>(top, one)
    } else {
        b.sub::<W16>(top, one)
    };
    let new_top = b.and::<W16>(moved, seven);
    b.set(sem::top_ref(), new_top);
    Ok(())
}

/// FINIT。FCW=0x037f、TOP=0、スタックを空にする。
pub fn finit<B: Backend>(b: &mut B) -> Flow<B> {
    let fcw = b.konst::<W16>(0x037f);
    b.set(sem::fcw_ref(), fcw);
    let z16 = b.konst::<W16>(0);
    let z64 = b.konst::<W64>(0);
    b.set(sem::top_ref(), z16);
    for slot in 0..8 {
        b.set(sem::st_sig_ref(slot), z64);
        b.set(sem::st_exp_ref(slot), z16);
    }
    Ok(())
}

/// FLDCW m16。
pub fn fldcw_m<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    if let Rm::Mem { a, .. } = ea {
        let v: B::V<W16> = b.load::<W16>(*a, sem::DATA_READ)?;
        b.set(sem::fcw_ref(), v);
    }
    Ok(())
}

/// FNSTCW m16。
pub fn fnstcw_m<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    if let Rm::Mem { a, .. } = ea {
        let v: B::V<W16> = b.get(sem::fcw_ref());
        b.store::<W16>(*a, v, sem::DATA_WRITE)?;
    }
    Ok(())
}

// ---- セグメント・特権 ----

/// MOV Sreg, r/m16。セレクタをロードする。実機ではディスクリプタ
/// キャッシュの再解決が起きるが、ユーザモードのエミュレーションでは
/// FS/GS ベースは OS の仕掛け（arch_prctl / set_thread_area）で別途
/// 決まるため、ここではセレクタ値の観測だけをモデルにする。
pub fn mov_sr_ld<B: Backend>(b: &mut B, s: u8, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let v = decode::rd16(b, ea)?;
    b.set(sem::sreg_ref(s), v);
    Ok(())
}

/// MOV r/m16, Sreg。
pub fn mov_sr_st<B: Backend>(b: &mut B, s: u8, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let v: B::V<W16> = b.get(sem::sreg_ref(s));
    decode::wr16(b, ea, v)
}

/// PUSH sreg。ゼロ拡張したセレクタをスタック幅で積む
/// （64bit モードは 8 バイトスロット、32bit は 4 バイト）。
pub fn push_sr<B: Backend>(b: &mut B, s: u8, sw: u8, sa: u8, sseg: u64) -> Flow<B> {
    let v: B::V<W16> = b.get(sem::sreg_ref(s));
    let v64 = b.zext::<W16, W64>(v);
    push_v(b, sw, v64, sa, sseg)
}

/// POP sreg。スタック幅で取り出し下位 16 ビットをセレクタへ書く
/// （ベースは変えない。`mov_sr_ld` の注記を参照）。
pub fn pop_sr<B: Backend>(b: &mut B, s: u8, sw: u8, sa: u8, sseg: u64) -> Flow<B> {
    let v = pop_v(b, sw, sa, sseg)?;
    let v16: B::V<W16> = b.trunc::<W64, W16>(v);
    b.set(sem::sreg_ref(s), v16);
    Ok(())
}

/// ARPL r/m16, r16。dst の RPL（下位 2 ビット）が src より小さければ
/// src の RPL に揃えて ZF=1、そうでなければ ZF=0。
pub fn arpl<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let dst = decode::rd16(b, ea)?;
    let src = decode::grd16(b, decode::reg(d));
    let m = b.konst::<W16>(3);
    let dr = b.and::<W16>(dst, m);
    let sr = b.and::<W16>(src, m);
    let lt = b.cmp::<W16>(Cmp::LtU, dr, sr);
    let dr_new = b.select::<W16>(lt, sr, dr);
    let keep = b.konst::<W16>(0xFFFC);
    let upper = b.and::<W16>(dst, keep);
    let nv = b.or::<W16>(upper, dr_new);
    decode::wr16(b, ea, nv)?;
    let old: B::V<W32> = b.get(eflags_ref());
    let nzf = b.konst::<W32>(!sem::FLAG_ZF);
    let cleared = b.and::<W32>(old, nzf);
    let zf = pick(b, lt, sem::FLAG_ZF);
    let efl = b.or::<W32>(cleared, zf);
    b.set(eflags_ref(), efl);
    Ok(())
}

/// SYSENTER。i386 のシステムコール ABI（eax=番号、ebx,ecx,edx,esi,
/// edi,ebp=引数）は INT 0x80 と同じなので同じトラップで表す。
/// vdso の __kernel_vsyscall は sysenter の次の命令が sysexit の
/// 戻り先になるよう構成されるため、継続位置の扱いも一致する。
pub fn sysenter<B: Backend>(b: &mut B, eip: u32) -> Flow<B> {
    sem::int80(b, eip)
}

/// SYSEXIT。REX.W なしは edx→eip・ecx→esp、REX.W ありは
/// rdx→rip・rcx→rsp に機械的に従う（特権遷移はモデル外）。
pub fn sysexit<B: Backend>(b: &mut B, w: u8) -> Flow<B> {
    let (tgt, nsp) = if w == 64 {
        (decode::grd64(b, Gpr(2)), decode::grd64(b, Gpr(1)))
    } else {
        let t = decode::grd32(b, Gpr(2));
        let s = decode::grd32(b, Gpr(1));
        (b.zext::<W32, W64>(t), b.zext::<W32, W64>(s))
    };
    let e: B::V<W32> = b.trunc::<W64, W32>(tgt);
    b.set(eip_ref(), e);
    sem::write64(b, Gpr(4), nsp);
    b.jump(tgt);
    Ok(())
}

// ---- MUL/IMUL/DIV/IDIV（F6/F7 /4-/7）----

/// MUL/IMUL r/m（1被演算子形）。積は DX:AX 系に倍幅で入る。
/// CF/OF は上位半分が意味を持つとき 1。フラグのソースは MUL が上位半分
/// そのもの、IMUL が `hi - sext(lo)`（収まり検査の減算）になる（8088 実測）。
pub fn mulx<B: Backend>(b: &mut B, w: u8, d: &MapDec, ea: &Rm<B::V<W64>>, signed: bool) -> Flow<B> {
    match w {
        8 => mulx8(b, d, ea, signed),
        16 => mulx_w::<B, W16, W32>(b, d, ea, signed),
        64 => mulx_w::<B, W64, W128>(b, d, ea, signed),
        _ => mulx_w::<B, W32, W64>(b, d, ea, signed),
    }
}

/// MUL/IMUL のフラグ更新。MUL は `src=hi`・AF=0。IMUL は `src = hi - sext(lo)`
/// で、SZP を `src` から、CF=OF=`src != 0`、AF は `lo` が負かつ `hi` の
/// 下位ニブルが 0xF のとき 1（sext の否定を 2 の補数で加えたときの
/// ニブルキャリーに相当。8088 実測）。
fn mul_flags<B: Backend, W: Hw>(b: &mut B, hi: B::V<W>, lo: B::V<W>, signed: bool) {
    let zro = b.konst::<W>(W::from_u128(0));
    let old: B::V<W32> = b.get(eflags_ref());
    let mask = b.konst::<W32>(!sem::FLAG_OSZPCA);
    let cleared = b.and::<W32>(old, mask);
    let (src, af) = if signed {
        let msb = b.konst::<W>(W::from_u128(1u128 << (W::BITS - 1)));
        let loand = b.and::<W>(lo, msb);
        let negl = b.cmp::<W>(Cmp::Ne, loand, zro);
        let all = b.konst::<W>(W::from_u128((1u128 << W::BITS) - 1));
        let se = b.select::<W>(negl, all, zro);
        let chk = b.sub::<W>(hi, se);
        let hf = b.konst::<W>(W::from_u128(0xF));
        let hiand = b.and::<W>(hi, hf);
        let hif = b.cmp::<W>(Cmp::Eq, hiand, hf);
        let an = pick(b, negl, sem::FLAG_AF);
        let ah = pick(b, hif, sem::FLAG_AF);
        let af = b.and::<W32>(an, ah);
        (chk, af)
    } else {
        (hi, b.konst::<W32>(0))
    };
    let cof = b.cmp::<W>(Cmp::Ne, src, zro);
    let cf = pick(b, cof, sem::FLAG_CF);
    let of = pick(b, cof, sem::FLAG_OF);
    let szp = szp_bits(b, src);
    let mut efl = b.or::<W32>(cleared, cf);
    efl = b.or::<W32>(efl, of);
    efl = b.or::<W32>(efl, szp);
    efl = b.or::<W32>(efl, af);
    b.set(eflags_ref(), efl);
}

/// MUL r/m8 → AX。IMUL では符号拡張してから掛ける。
fn mulx8<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>, signed: bool) -> Flow<B> {
    let al = sem::read8(b, Gpr(0), false);
    let y = rd_w::<B, W8>(b, ea, d)?;
    let (xw, yw) = if signed {
        (b.sext::<W8, W16>(al), b.sext::<W8, W16>(y))
    } else {
        (b.zext::<W8, W16>(al), b.zext::<W8, W16>(y))
    };
    let p = b.mul::<W16>(xw, yw);
    decode::gwr16(b, Gpr(0), p);
    let eight = b.konst::<W16>(8);
    let hi = b.shr_l::<W16>(p, eight);
    let hi8: B::V<W8> = b.trunc::<W16, W8>(hi);
    let lo8: B::V<W8> = b.trunc::<W16, W8>(p);
    mul_flags::<B, W8>(b, hi8, lo8, signed);
    Ok(())
}

fn mulx_w<B: Backend, W: Hw, W2: polyisa_sem::Width>(
    b: &mut B,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
    signed: bool,
) -> Flow<B> {
    let x = W::get(b, Gpr(0), d);
    let y = rd_w::<B, W>(b, ea, d)?;
    let (xw, yw) = if signed {
        (b.sext::<W, W2>(x), b.sext::<W, W2>(y))
    } else {
        (b.zext::<W, W2>(x), b.zext::<W, W2>(y))
    };
    let p = b.mul::<W2>(xw, yw);
    let lo: B::V<W> = b.trunc::<W2, W>(p);
    let sh = b.konst::<W2>(W2::from_u128(u128::from(W::BITS)));
    let hiw = b.shr_l::<W2>(p, sh);
    let hi: B::V<W> = b.trunc::<W2, W>(hiw);
    W::put(b, Gpr(0), d, lo);
    W::put(b, Gpr(2), d, hi);
    mul_flags::<B, W>(b, hi, lo, signed);
    Ok(())
}

/// DIV/IDIV r/m。実モードでは 0 除算・商あふれを IVT 0 番へ送る
/// （積まれる IP は命令の次を指す）。それ以外のモードでは DivZero
/// 例外で退出する。8088 がフォールト時に残すフラグは
/// CORD 先頭の `tmpA - tmpB` 比較減算のもの。
#[allow(clippy::too_many_arguments)]
pub fn divx<B: Backend>(
    b: &mut B,
    w: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
    eip: u32,
    len: u32,
    sa: u8,
    sseg: u64,
    mode: u8,
    signed: bool,
) -> Flow<B> {
    match w {
        8 => divx8(b, d, ea, eip, len, sa, sseg, mode, signed),
        16 => divx_w::<B, W16, W32>(b, d, ea, eip, len, sa, sseg, mode, signed),
        64 => divx_w::<B, W64, W128>(b, d, ea, eip, len, sa, sseg, mode, signed),
        _ => divx_w::<B, W32, W64>(b, d, ea, eip, len, sa, sseg, mode, signed),
    }
}

/// #DE。実モードでは実機の割り込み 0（FLAGS/CS/次の IP を積んで
/// IVT[0] へ far 分岐）。他モードは divide error 例外。
/// `hi`/`dv` はオペランド幅の（符号付きなら絶対値化後の）被除数
/// 上位半分と除数。8088 では CORD 先頭の `hi - dv` 比較減算の
/// フラグがフォールト時に残る（SST 8088 実測）。
#[allow(clippy::too_many_arguments)]
fn div_fault<B: Backend, W: Width>(
    b: &mut B,
    hi: B::V<W>,
    dv: B::V<W>,
    eip: u32,
    len: u32,
    sa: u8,
    sseg: u64,
    mode: u8,
) -> Flow<B> {
    if mode == 16 {
        let r = b.sub::<W>(hi, dv);
        update_sub_flags::<B, W>(b, hi, dv, r);
        int_real(b, eip, len, 0, sa, sseg)
    } else {
        Err(sem::div0(b, eip))
    }
}

/// mode==16（8088）の DIV/IDIV。CORD 除算マイクロコードを再現する。
///
/// フラグはループ内で最後に実行された F 比較（シフト後 tmpA - 除数）
/// が残す。ただし CF は除算完了時に捨てられる RCL tmpC が ¬商 の
/// 最上位を残すため ¬q_msb に置き換わる。IDIV 成功時は POSTIDIV の
/// CCOF で CF/OF=0。フォールトは 2 種: 入口比較の |hi| ≥ |d|
/// （ゼロ除算を含む）と IDIV 専用の POSTIDIV 商オーバーフロー
/// （商マグニチュードの msb=1。表現可能な -2^(W-1) もフォールト
/// するのが実機動作）。いずれもフラグ更新のあと INT 0 を起こし、
/// 商・剰余は書かない。
#[allow(clippy::too_many_arguments)]
fn div_cord<B: Backend, W: Hw, W2: Width, F: Fn(&mut B, B::V<W>, B::V<W>)>(
    b: &mut B,
    hi: B::V<W>,
    lo: B::V<W>,
    d: B::V<W>,
    dvd: B::V<W2>,
    neg_q: B::B,
    neg_r: B::B,
    signed: bool,
    eip: u32,
    len: u32,
    sa: u8,
    sseg: u64,
    wr: F,
) -> Flow<B> {
    let zero = b.konst::<W>(W::from_u128(0));
    let one = b.konst::<W>(W::from_u128(1));
    let top = b.konst::<W>(W::from_u128(1u128 << (W::BITS - 1)));
    // 入口フォールト: |hi| ≥ |d|。d=0 もここで捕捉される。
    let ef = b.cmp::<W>(Cmp::GeU, hi, d);
    // 商・剰余はマグニチュード除算。ゼロ除算は結果を使わないので 1 に退避。
    let dz = b.cmp::<W>(Cmp::Eq, d, zero);
    let d_safe = b.select::<W>(dz, one, d);
    let d_ext = b.zext::<W, W2>(d_safe);
    let q2 = b.udiv::<W2>(dvd, d_ext);
    let r2 = b.urem::<W2>(dvd, d_ext);
    let q = b.trunc::<W2, W>(q2);
    let r = b.trunc::<W2, W>(r2);
    let qb = b.and::<W>(q, top);
    let q_msb = b.cmp::<W>(Cmp::Ne, qb, zero);
    // POSTIDIV 商オーバーフロー（IDIV のみ）。
    let mut fault = ef;
    if signed {
        fault = bor(b, ef, q_msb);
    }
    // CORD ループ。比較の桁供給ビットは元の下位被除数の bit (W-1-i)。
    // fl_a は最後にフラグを書いた比較の被演算値。全反復が top-bit
    // パスなら入口比較の hi が残るので hi で初期化する。
    let mut fl_a = hi;
    let mut tmp_a = hi;
    for i in 0..W::BITS {
        let shn = b.konst::<W>(W::from_u128((W::BITS - 1 - i) as u128));
        let c1s = b.shr_l::<W>(lo, shn);
        let c1 = b.and::<W>(c1s, one);
        let tb = b.and::<W>(tmp_a, top);
        let c2 = b.cmp::<W>(Cmp::Ne, tb, zero);
        let a_sl = b.shl::<W>(tmp_a, one);
        let a_sh = b.or::<W>(a_sl, c1);
        fl_a = b.select::<W>(c2, fl_a, a_sh);
        let subr = b.sub::<W>(a_sh, d);
        let ge = b.cmp::<W>(Cmp::GeU, a_sh, d);
        let take = bor(b, c2, ge);
        tmp_a = b.select::<W>(take, subr, a_sh);
    }
    // フラグ = 入口フォールト時は hi - d、それ以外は最後の比較。
    let fx = b.select::<W>(ef, hi, fl_a);
    let fr = b.sub::<W>(fx, d);
    update_sub_flags::<B, W>(b, fx, d, fr);
    // CF/OF を比較結果から実機の値に直す。
    //   入口フォールト: 比較のまま（hi≥d なので CF=0・OF は減算値）。
    //   DIV 成功: CF = ¬q_msb。
    //   IDIV 成功: CF=0, OF=0（CCOF）。
    //   POSTIDIV フォールト: CF=0（=¬q_msb は q_msb=1 で自動的に 0）。
    let nq = bnot(b, q_msb);
    let cf_t = if signed {
        b.konst::<W32>(0)
    } else {
        pick(b, nq, FLAG_CF)
    };
    let z32 = b.konst::<W32>(0);
    let cf_v = b.select::<W32>(ef, z32, cf_t);
    let a1 = b.xor::<W>(fx, d);
    let a2 = b.xor::<W>(fx, fr);
    let sof = b.and::<W>(a1, a2);
    let sof_n = b.konst::<W>(W::from_u128((W::BITS - 1) as u128));
    let sof_s = b.shr_l::<W>(sof, sof_n);
    let sof_t = b.and::<W>(sof_s, one);
    let of_c = b.cmp::<W>(Cmp::Ne, sof_t, zero);
    let mut of_v = pick(b, of_c, FLAG_OF);
    if signed {
        let succ = bnot(b, fault);
        of_v = b.select::<W32>(succ, z32, of_v);
    }
    let clr = b.konst::<W32>(!(FLAG_CF | FLAG_OF));
    let mut f: B::V<W32> = b.get(eflags_ref());
    f = b.and::<W32>(f, clr);
    f = b.or::<W32>(f, cf_v);
    f = b.or::<W32>(f, of_v);
    b.set(eflags_ref(), f);
    // フォールトは商・剰余を書かずに割り込み 0 を起こす。
    let nf = bnot(b, fault);
    b.if_then(nf, |b| {
        let q_neg = b.sub::<W>(zero, q);
        let r_neg = b.sub::<W>(zero, r);
        let qs = b.select::<W>(neg_q, q_neg, q);
        let rs = b.select::<W>(neg_r, r_neg, r);
        wr(b, qs, rs);
        Ok(())
    })?;
    b.if_then(fault, |b| int_real(b, eip, len, 0, sa, sseg))?;
    Ok(())
}

/// DIV/IDIV r/m8。被除数は AX、商を AL・剰余を AH に置く。
#[allow(clippy::too_many_arguments)]
fn divx8<B: Backend>(
    b: &mut B,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
    eip: u32,
    len: u32,
    sa: u8,
    sseg: u64,
    mode: u8,
    signed: bool,
) -> Flow<B> {
    let ax32: B::V<W32> = b.get(Gpr(0).state());
    let ax: B::V<W16> = b.trunc::<W32, W16>(ax32);
    let y = rd_w::<B, W8>(b, ea, d)?;
    if mode == 16 {
        // PREIDIV 相当の絶対値化（IDIV のみ）。
        let z16 = b.konst::<W16>(0);
        let z8 = b.konst::<W8>(0);
        let zero32 = b.konst::<W32>(0);
        let one32 = b.konst::<W32>(1);
        let (m_a, m_d, neg_q, neg_r) = if signed {
            let neg_a = b.sub::<W16>(z16, ax);
            let sa16 = b.cmp::<W16>(Cmp::LtS, ax, z16);
            let m_a = b.select::<W16>(sa16, neg_a, ax);
            let neg_d = b.sub::<W8>(z8, y);
            let sd8 = b.cmp::<W8>(Cmp::LtS, y, z8);
            let m_d = b.select::<W8>(sd8, neg_d, y);
            let s1 = b.select::<W32>(sa16, one32, zero32);
            let s2 = b.select::<W32>(sd8, one32, zero32);
            let mut neg_q = b.cmp::<W32>(Cmp::Ne, s1, s2);
            // F1 は REP 接頭辞でも立つ（8088 実機の quirk。`rep idiv`
            // は商の符号が反転する）。
            if d.rep != 0 {
                neg_q = bnot(b, neg_q);
            }
            (m_a, m_d, neg_q, sa16)
        } else {
            let f0 = b.cmp::<W32>(Cmp::Ne, zero32, zero32);
            (ax, y, f0, f0)
        };
        let sh8 = b.konst::<W16>(8);
        let hi16 = b.shr_l::<W16>(m_a, sh8);
        let hi = b.trunc::<W16, W8>(hi16);
        let lo = b.trunc::<W16, W8>(m_a);
        return div_cord::<B, W8, W16, _>(
            b,
            hi,
            lo,
            m_d,
            m_a,
            neg_q,
            neg_r,
            signed,
            eip,
            len,
            sa,
            sseg,
            |b, q, r| {
                sem::write8(b, Gpr(0), false, q);
                sem::write8(b, Gpr(0), true, r);
            },
        );
    }
    // PREIDIV 相当の絶対値化（IDIV のみ）。CORD のフォールト検査
    // は |上位半分| - |除数| の減算を行い、そのフラグが残る。
    let (m_dvd, m_d) = if signed {
        let z16 = b.konst::<W16>(0);
        let neg_a = b.sub::<W16>(z16, ax);
        let sa16 = b.cmp::<W16>(Cmp::LtS, ax, z16);
        let m_a = b.select::<W16>(sa16, neg_a, ax);
        let z8 = b.konst::<W8>(0);
        let neg_d = b.sub::<W8>(z8, y);
        let sd8 = b.cmp::<W8>(Cmp::LtS, y, z8);
        (m_a, b.select::<W8>(sd8, neg_d, y))
    } else {
        (ax, y)
    };
    let (dvd, dvs) = if signed {
        (b.sext::<W16, W32>(ax), b.sext::<W8, W32>(y))
    } else {
        (b.zext::<W16, W32>(ax), b.zext::<W8, W32>(y))
    };
    let sh8 = b.konst::<W16>(8);
    let hi16 = b.shr_l::<W16>(m_dvd, sh8);
    let hi8 = b.trunc::<W16, W8>(hi16);
    let zero = b.konst::<W32>(0);
    let is_zero = b.cmp::<W32>(Cmp::Eq, dvs, zero);
    b.if_then(is_zero, |b| {
        div_fault::<B, W8>(b, hi8, m_d, eip, len, sa, sseg, mode)
    })?;
    let q = if signed {
        b.sdiv::<W32>(dvd, dvs)
    } else {
        b.udiv::<W32>(dvd, dvs)
    };
    let q8: B::V<W8> = b.trunc::<W32, W8>(q);
    let q_back = if signed {
        b.sext::<W8, W32>(q8)
    } else {
        b.zext::<W8, W32>(q8)
    };
    let over = b.cmp::<W32>(Cmp::Ne, q_back, q);
    b.if_then(over, |b| {
        div_fault::<B, W8>(b, hi8, m_d, eip, len, sa, sseg, mode)
    })?;
    let r = if signed {
        b.srem::<W32>(dvd, dvs)
    } else {
        b.urem::<W32>(dvd, dvs)
    };
    let r8: B::V<W8> = b.trunc::<W32, W8>(r);
    sem::write8(b, Gpr(0), false, q8);
    sem::write8(b, Gpr(0), true, r8);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn divx_w<B: Backend, W: Hw, W2: polyisa_sem::Width>(
    b: &mut B,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
    eip: u32,
    len: u32,
    sa: u8,
    sseg: u64,
    mode: u8,
    signed: bool,
) -> Flow<B> {
    let lo = W::get(b, Gpr(0), d);
    let hi = W::get(b, Gpr(2), d);
    let y = rd_w::<B, W>(b, ea, d)?;
    if mode == 16 {
        // PREIDIV 相当の絶対値化（IDIV のみ）。
        let zw = b.konst::<W>(W::from_u128(0));
        let zero32 = b.konst::<W32>(0);
        let one32 = b.konst::<W32>(1);
        let sh16 = b.konst::<W2>(W2::from_u128(u128::from(W::BITS)));
        let hi_z = b.zext::<W, W2>(hi);
        let lo_z = b.zext::<W, W2>(lo);
        let hi_sh = b.shl::<W2>(hi_z, sh16);
        let dvd = b.or::<W2>(hi_sh, lo_z);
        let z2 = b.konst::<W2>(W2::from_u128(0));
        let (m_dvd, m_d, neg_q, neg_r) = if signed {
            let neg = b.sub::<W2>(z2, dvd);
            let sdvd = b.cmp::<W>(Cmp::LtS, hi, zw);
            let m_dvd = b.select::<W2>(sdvd, neg, dvd);
            let neg_d = b.sub::<W>(zw, y);
            let sd = b.cmp::<W>(Cmp::LtS, y, zw);
            let m_d = b.select::<W>(sd, neg_d, y);
            let s1 = b.select::<W32>(sdvd, one32, zero32);
            let s2 = b.select::<W32>(sd, one32, zero32);
            let mut neg_q = b.cmp::<W32>(Cmp::Ne, s1, s2);
            if d.rep != 0 {
                neg_q = bnot(b, neg_q);
            }
            (m_dvd, m_d, neg_q, sdvd)
        } else {
            let f0 = b.cmp::<W32>(Cmp::Ne, zero32, zero32);
            (dvd, y, f0, f0)
        };
        let m_hi2 = b.shr_l::<W2>(m_dvd, sh16);
        let m_hi = b.trunc::<W2, W>(m_hi2);
        let m_lo = b.trunc::<W2, W>(m_dvd);
        return div_cord::<B, W, W2, _>(
            b,
            m_hi,
            m_lo,
            m_d,
            m_dvd,
            neg_q,
            neg_r,
            signed,
            eip,
            len,
            sa,
            sseg,
            |b, q, r| {
                W::put(b, Gpr(0), d, q);
                W::put(b, Gpr(2), d, r);
            },
        );
    }
    let hiw = if signed {
        b.sext::<W, W2>(hi)
    } else {
        b.zext::<W, W2>(hi)
    };
    let sh = b.konst::<W2>(W2::from_u128(u128::from(W::BITS)));
    let hi_sh = b.shl::<W2>(hiw, sh);
    let low = b.zext::<W, W2>(lo);
    let dvd = b.or::<W2>(hi_sh, low);
    let yw = if signed {
        b.sext::<W, W2>(y)
    } else {
        b.zext::<W, W2>(y)
    };
    // PREIDIV 相当の絶対値化（IDIV のみ）。CORD のフォールト検査
    // は |上位半分| - |除数| の減算を行い、そのフラグが残る。
    let (m_hi, m_d) = if signed {
        let z2 = b.konst::<W2>(W2::from_u128(0));
        let neg = b.sub::<W2>(z2, dvd);
        let sd2 = b.cmp::<W2>(Cmp::LtS, dvd, z2);
        let m2 = b.select::<W2>(sd2, neg, dvd);
        let m_h2 = b.shr_l::<W2>(m2, sh);
        let m_hi = b.trunc::<W2, W>(m_h2);
        let zw = b.konst::<W>(W::from_u128(0));
        let neg_d = b.sub::<W>(zw, y);
        let sdw = b.cmp::<W>(Cmp::LtS, y, zw);
        (m_hi, b.select::<W>(sdw, neg_d, y))
    } else {
        (hi, y)
    };
    let zero = b.konst::<W2>(W2::from_u128(0));
    let is_zero = b.cmp::<W2>(Cmp::Eq, yw, zero);
    b.if_then(is_zero, |b| {
        div_fault::<B, W>(b, m_hi, m_d, eip, len, sa, sseg, mode)
    })?;
    let q = if signed {
        b.sdiv::<W2>(dvd, yw)
    } else {
        b.udiv::<W2>(dvd, yw)
    };
    let q_t: B::V<W> = b.trunc::<W2, W>(q);
    let q_back = if signed {
        b.sext::<W, W2>(q_t)
    } else {
        b.zext::<W, W2>(q_t)
    };
    let over = b.cmp::<W2>(Cmp::Ne, q_back, q);
    b.if_then(over, |b| {
        div_fault::<B, W>(b, m_hi, m_d, eip, len, sa, sseg, mode)
    })?;
    let r = if signed {
        b.srem::<W2>(dvd, yw)
    } else {
        b.urem::<W2>(dvd, yw)
    };
    let r_t: B::V<W> = b.trunc::<W2, W>(r);
    W::put(b, Gpr(0), d, q_t);
    W::put(b, Gpr(2), d, r_t);
    Ok(())
}

// ---- BCD 調整・SALC ----

/// DAA（27）。AL をパック BCD 加算の結果に補正する。
/// CF/AF は補正の有無、SZP は結果、OF は元値+補正合計の符号あふれ
/// （8088 実測）。
pub fn daa<B: Backend>(b: &mut B) -> Flow<B> {
    let old_al = sem::read8(b, Gpr(0), false);
    let old_cf = read_cf(b);
    let af_in = sem::read_af(b);
    let z8 = b.konst::<W8>(0);
    let nine = b.konst::<W8>(9);
    let f = b.konst::<W8>(0xF);
    let low = b.and::<W8>(old_al, f);
    let gt9 = b.cmp::<W8>(Cmp::LtU, nine, low);
    let adj1 = bor(b, gt9, af_in);
    let six = b.konst::<W8>(6);
    let add1 = b.select::<W8>(adj1, six, z8);
    let al1 = b.add::<W8>(old_al, add1);
    // 第2補正の条件: CF | (AL + (AF ? 0 : 6)) > 0x9F（8088 実測）。
    // AL=0x9A..0x9F で AF=0 のときだけ補正がかかる点が SDM と異なる。
    // 比較は 8 ビットに折れない幅で行う（0xFA+6=0x100 も補正対象）。
    let add6 = b.select::<W8>(af_in, z8, six);
    let al16: B::V<W16> = b.zext::<W8, W16>(old_al);
    let a16: B::V<W16> = b.zext::<W8, W16>(add6);
    let chk = b.add::<W16>(al16, a16);
    let n9f = b.konst::<W16>(0x9F);
    let gt9f = b.cmp::<W16>(Cmp::LtU, n9f, chk);
    let adj2 = bor(b, gt9f, old_cf);
    let c60 = b.konst::<W8>(0x60);
    let add2 = b.select::<W8>(adj2, c60, z8);
    let v = b.add::<W8>(al1, add2);
    sem::write8(b, Gpr(0), false, v);
    // OF は元値 + 補正合計の符号あふれ（8088 実測）。
    let adj_total = b.add::<W8>(add1, add2);
    let t1 = b.xor::<W8>(old_al, v);
    let t2 = b.xor::<W8>(adj_total, v);
    let s = b.and::<W8>(t1, t2);
    let k80 = b.konst::<W8>(0x80);
    let sm = b.and::<W8>(s, k80);
    let of_take = b.cmp::<W8>(Cmp::Ne, sm, z8);
    let old: B::V<W32> = b.get(eflags_ref());
    let cf = pick(b, adj2, sem::FLAG_CF);
    let af = pick(b, adj1, sem::FLAG_AF);
    let of = pick(b, of_take, sem::FLAG_OF);
    let szp = szp_bits(b, v);
    let keep = b.konst::<W32>(!sem::FLAG_OSZPCA);
    let mut nf = b.and::<W32>(old, keep);
    nf = b.or::<W32>(nf, cf);
    nf = b.or::<W32>(nf, af);
    nf = b.or::<W32>(nf, of);
    nf = b.or::<W32>(nf, szp);
    b.set(eflags_ref(), nf);
    Ok(())
}

/// DAS（2F）。AL をパック BCD 減算の結果に補正する。
/// CF/AF は補正の有無、SZP は結果、OF は元値-補正合計の借りあふれ。
pub fn das<B: Backend>(b: &mut B) -> Flow<B> {
    let old_al = sem::read8(b, Gpr(0), false);
    let old_cf = read_cf(b);
    let af_in = sem::read_af(b);
    let z8 = b.konst::<W8>(0);
    let nine = b.konst::<W8>(9);
    let f = b.konst::<W8>(0xF);
    let low = b.and::<W8>(old_al, f);
    let gt9 = b.cmp::<W8>(Cmp::LtU, nine, low);
    let adj1 = bor(b, gt9, af_in);
    let six = b.konst::<W8>(6);
    let sub1 = b.select::<W8>(adj1, six, z8);
    let al1 = b.sub::<W8>(old_al, sub1);
    // 第2補正の条件: CF | (AL + (AF ? 0 : 6)) > 0x9F（8088 実測）。
    // 比較は 8 ビットに折れない幅で行う。
    let add6 = b.select::<W8>(af_in, z8, six);
    let al16: B::V<W16> = b.zext::<W8, W16>(old_al);
    let a16: B::V<W16> = b.zext::<W8, W16>(add6);
    let chk = b.add::<W16>(al16, a16);
    let n9f = b.konst::<W16>(0x9F);
    let gt9f = b.cmp::<W16>(Cmp::LtU, n9f, chk);
    let adj2 = bor(b, gt9f, old_cf);
    let c60 = b.konst::<W8>(0x60);
    let sub2 = b.select::<W8>(adj2, c60, z8);
    let v = b.sub::<W8>(al1, sub2);
    sem::write8(b, Gpr(0), false, v);
    // OF は元値 - 補正合計の借りあふれ（8088 実測）。
    let adj_total = b.add::<W8>(sub1, sub2);
    let t1 = b.xor::<W8>(old_al, adj_total);
    let t2 = b.xor::<W8>(old_al, v);
    let s = b.and::<W8>(t1, t2);
    let k80 = b.konst::<W8>(0x80);
    let sm = b.and::<W8>(s, k80);
    let of_take = b.cmp::<W8>(Cmp::Ne, sm, z8);
    let old: B::V<W32> = b.get(eflags_ref());
    let cf = pick(b, adj2, sem::FLAG_CF);
    let af = pick(b, adj1, sem::FLAG_AF);
    let of = pick(b, of_take, sem::FLAG_OF);
    let szp = szp_bits(b, v);
    let keep = b.konst::<W32>(!sem::FLAG_OSZPCA);
    let mut nf = b.and::<W32>(old, keep);
    nf = b.or::<W32>(nf, cf);
    nf = b.or::<W32>(nf, af);
    nf = b.or::<W32>(nf, of);
    nf = b.or::<W32>(nf, szp);
    b.set(eflags_ref(), nf);
    Ok(())
}

/// AAA/AAS（37/3F）。AL をアンパック BCD に補正し、必要なら AH を
/// ±1 する。AH±1 と AL±6 は独立に計算する（AL の桁上げは AH に伝搬しない）。
/// 旗ソースは補正時 `AL±6`、非補正時は `AL`。CF/AF は補正の有無、
/// SZP は旗ソースから、OF は補正時だけ `AL±6` の符号あふれ（8088 実測）。
pub fn aaa_aas<B: Backend>(b: &mut B, sub: bool) -> Flow<B> {
    let al = sem::read8(b, Gpr(0), false);
    let ah = sem::read8(b, Gpr(0), true);
    let af_in = sem::read_af(b);
    let z8 = b.konst::<W8>(0);
    let nine = b.konst::<W8>(9);
    let f = b.konst::<W8>(0xF);
    let low = b.and::<W8>(al, f);
    let gt9 = b.cmp::<W8>(Cmp::LtU, nine, low);
    let adj = bor(b, gt9, af_in);
    let six = b.konst::<W8>(6);
    let t = if sub {
        b.sub::<W8>(al, six)
    } else {
        b.add::<W8>(al, six)
    };
    // 旗ソース: 補正時は al±6、非補正時は al（8088 実測）。
    let src = b.select::<W8>(adj, t, al);
    // AL = src & 0xF（非補正でも下位ニブルへマスク）。AH は独立に ±1。
    let al_v = b.and::<W8>(src, f);
    let one = b.konst::<W8>(1);
    let d1 = b.select::<W8>(adj, one, z8);
    let ah_v = if sub {
        b.sub::<W8>(ah, d1)
    } else {
        b.add::<W8>(ah, d1)
    };
    sem::write8(b, Gpr(0), false, al_v);
    sem::write8(b, Gpr(0), true, ah_v);
    // OF: 補正時は al±6 の符号あふれ、非補正時は 0。
    let t1 = if sub {
        b.xor::<W8>(al, six)
    } else {
        let nt = b.not::<W8>(al);
        b.xor::<W8>(nt, six)
    };
    let t2 = b.xor::<W8>(al, t);
    let s = b.and::<W8>(t1, t2);
    let k80 = b.konst::<W8>(0x80);
    let sm = b.and::<W8>(s, k80);
    let ovf = b.cmp::<W8>(Cmp::Ne, sm, z8);
    let of_take = band(b, ovf, adj);
    let old: B::V<W32> = b.get(eflags_ref());
    let cf = pick(b, adj, sem::FLAG_CF);
    let af = pick(b, adj, sem::FLAG_AF);
    let of = pick(b, of_take, sem::FLAG_OF);
    let szp = szp_bits(b, src);
    let keep = b.konst::<W32>(!sem::FLAG_OSZPCA);
    let mut nf = b.and::<W32>(old, keep);
    nf = b.or::<W32>(nf, cf);
    nf = b.or::<W32>(nf, af);
    nf = b.or::<W32>(nf, of);
    nf = b.or::<W32>(nf, szp);
    b.set(eflags_ref(), nf);
    Ok(())
}

/// AAM（D4 ib）。AL を base で割り商を AH・剰余を AL に置く。
/// SZP は剰余、CF/OF/AF=0（8088 実測）。base=0 は #DE。
pub fn aam<B: Backend>(
    b: &mut B,
    base: u8,
    eip: u32,
    len: u32,
    sa: u8,
    sseg: u64,
    mode: u8,
) -> Flow<B> {
    if base == 0 {
        // 8088 の AAM は被除数上位 = 0 の CORD 経路。除数 0 は
        // 入口比較 0 - 0 のフラグを残して #DE（IVT 0 番）になる。
        let z = b.konst::<W8>(0);
        return div_fault::<B, W8>(b, z, z, eip, len, sa, sseg, mode);
    }
    let al = sem::read8(b, Gpr(0), false);
    let bb = b.konst::<W8>(base);
    let q = b.udiv::<W8>(al, bb);
    let r = b.urem::<W8>(al, bb);
    let q16: B::V<W16> = b.zext::<W8, W16>(q);
    let r16: B::V<W16> = b.zext::<W8, W16>(r);
    let eight = b.konst::<W16>(8);
    let hi = b.shl::<W16>(q16, eight);
    let ax = b.or::<W16>(hi, r16);
    decode::gwr16(b, Gpr(0), ax);
    // SZP は剰余（新 AL）から。CF/OF/AF=0（8088 実測）= 論理演算型。
    update_logic_flags(b, r);
    Ok(())
}

/// AAD（D5 ib）。AL = AL + AH*base、AH = 0。
/// 8088 ではこの 8 ビット加算として全旗が更新される。
pub fn aad<B: Backend>(b: &mut B, base: u8) -> Flow<B> {
    let al = sem::read8(b, Gpr(0), false);
    let ah = sem::read8(b, Gpr(0), true);
    let bb = b.konst::<W8>(base);
    let p = b.mul::<W8>(ah, bb);
    let v = b.add::<W8>(al, p);
    sem::write8(b, Gpr(0), false, v);
    let z8 = b.konst::<W8>(0);
    sem::write8(b, Gpr(0), true, z8);
    // 8088 では AL + (AH*base) の 8 ビット加算として全旗が更新される。
    update_add_flags(b, al, p, v);
    Ok(())
}

/// SALC（D6）。CF=1 なら AL=0xFF、0 なら 0x00。旗は不変。
pub fn salc<B: Backend>(b: &mut B) -> Flow<B> {
    let cf = read_cf(b);
    let ff = b.konst::<W8>(0xFF);
    let z8 = b.konst::<W8>(0);
    let v = b.select::<W8>(cf, ff, z8);
    sem::write8(b, Gpr(0), false, v);
    Ok(())
}

/// LES/LDS（C4/C5）。m16:16 の far ポインタを読み、オフセットを
/// 汎用レジスタ、セレクタをセグメントレジスタ `s`（ES=0,DS=3）へ書く。
/// mod=11 は #UD 相当なので何もしない。
pub fn load_far<B: Backend>(b: &mut B, d: &MapDec, rm: &Rm<B::V<W64>>, s: u8) -> Flow<B> {
    let Rm::Mem { a, wseg } = rm else {
        return Ok(());
    };
    let off: B::V<W16> = decode::mem_load(b, *a, *wseg)?;
    let two = b.konst::<W64>(2);
    let a2 = b.add::<W64>(*a, two);
    let seg: B::V<W16> = decode::mem_load(b, a2, *wseg)?;
    decode::gwr16(b, decode::reg(d), off);
    b.set(sem::sreg_ref(s), seg);
    Ok(())
}

// ---- x87 比較・環境 ----

/// FCOM 系の C ビット位置（fsw の bit8,10,14）。
const X87_C0: u16 = 0x0100;
const X87_C2: u16 = 0x0400;
const X87_C3: u16 = 0x4000;
const X87_C_MASK: u16 = X87_C0 | X87_C2 | X87_C3;

/// ST(0) と (sig,exp) を比較して fsw の C0/C2/C3 を更新する。
/// `pop` で 1 段捨てる（FCOMP/FICOMP）。
fn fcom_ext<B: Backend>(b: &mut B, sig: B::V<W64>, exp: B::V<W16>, pop: bool) -> Flow<B> {
    let top = b.get(sem::top_ref());
    let (s0, e0) = sem::read_st(b, top);
    let (zf, unord, cf) = sem::cmp_f80(b, s0, e0, sig, exp);
    let old: B::V<W16> = b.get(sem::fsw_ref());
    let keep = b.konst::<W16>(!X87_C_MASK);
    let cleared = b.and::<W16>(old, keep);
    let k0 = b.konst::<W16>(0);
    let kc0 = b.konst::<W16>(X87_C0);
    let kc2 = b.konst::<W16>(X87_C2);
    let kc3 = b.konst::<W16>(X87_C3);
    let c0 = b.select::<W16>(cf, kc0, k0);
    let c2 = b.select::<W16>(unord, kc2, k0);
    let c3 = b.select::<W16>(zf, kc3, k0);
    let c02 = b.or::<W16>(c0, c2);
    let cbits = b.or::<W16>(c02, c3);
    let nv = b.or::<W16>(cleared, cbits);
    b.set(sem::fsw_ref(), nv);
    if pop {
        sem::pop_st(b, top)?;
    }
    Ok(())
}

/// FCOM/FCOMP m32/m64（bits で読み幅）。mod=11 では ST(i) との比較。
pub fn fcom_m<B: Backend>(
    b: &mut B,
    bits: u32,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
    pop: bool,
) -> Flow<B> {
    if d.modrm >= 0xC0 {
        let i = (d.modrm & 7) as u32;
        let top = b.get(sem::top_ref());
        let ii = b.konst::<W16>(i as u16);
        let summed = b.add::<W16>(top, ii);
        let seven = b.konst::<W16>(7);
        let slot = b.and::<W16>(summed, seven);
        let (s1, e1) = sem::read_st(b, slot);
        return fcom_ext(b, s1, e1, pop);
    }
    let (sig, exp) = match ea {
        Rm::Mem { a, .. } => {
            let a = *a;
            if bits == 64 {
                let v = b.load::<W64>(a, sem::DATA_READ)?;
                sem::f64_to_ext(b, v)
            } else {
                let v = b.load::<W32>(a, sem::DATA_READ)?;
                sem::f32_to_ext(b, v)
            }
        }
        Rm::Reg(_) => return Ok(()),
    };
    fcom_ext(b, sig, exp, pop)
}

/// FICOM/FICOMP m16int。
pub fn ficom_m16<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>, pop: bool) -> Flow<B> {
    let v = decode::rd16(b, ea)?;
    let v64 = b.sext::<W16, W64>(v);
    let (sig, exp) = sem::i64_to_ext(b, v64);
    fcom_ext(b, sig, exp, pop)
}

/// FCOM/FUCOM 系の st(i) 形。ST(0) と ST(i) を比較して C ビットを更新する。
pub fn fcom_sti<B: Backend>(b: &mut B, i: u8, pop: bool) -> Flow<B> {
    let top = b.get(sem::top_ref());
    let ii = b.konst::<W16>(u16::from(i & 7));
    let summed = b.add::<W16>(top, ii);
    let seven = b.konst::<W16>(7);
    let slot = b.and::<W16>(summed, seven);
    let (s1, e1) = sem::read_st(b, slot);
    fcom_ext(b, s1, e1, pop)
}

/// FNSTSW m16。fsw の C ビットに TOP を合成して書き込む。
pub fn fnstsw_m16<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let fsw: B::V<W16> = b.get(sem::fsw_ref());
    let top = b.get(sem::top_ref());
    let seven = b.konst::<W16>(7);
    let t3 = b.and::<W16>(top, seven);
    let sh = b.konst::<W16>(11);
    let tbits = b.shl::<W16>(t3, sh);
    let v = b.or::<W16>(fsw, tbits);
    decode::wr16(b, ea, v)
}

/// FNSAVE m108。28 バイトの環境 + 8×10 バイトの ST を書き、
/// 書き終わると FPU を初期化する（FCW=0x037F、スタックは空）。
/// FIP/FCS/FOP/FDP/FDS はモデル外のため 0 を書く。
pub fn fnsave_m<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>) -> Flow<B> {
    let Rm::Mem { a, .. } = ea else {
        return Ok(());
    };
    let a = *a;
    let fcw: B::V<W16> = b.get(sem::fcw_ref());
    b.store::<W16>(a, fcw, sem::DATA_WRITE)?;
    let fsw: B::V<W16> = b.get(sem::fsw_ref());
    let top = b.get(sem::top_ref());
    let seven = b.konst::<W16>(7);
    let t3 = b.and::<W16>(top, seven);
    let sh = b.konst::<W16>(11);
    let tbits = b.shl::<W16>(t3, sh);
    let fswv = b.or::<W16>(fsw, tbits);
    let a2 = b.konst::<W64>(2);
    let afs = b.add::<W64>(a, a2);
    b.store::<W16>(afs, fswv, sem::DATA_WRITE)?;
    // FTW（簡約形）: ST(i) が空でなければ bit i = 1。
    let mut ftag = b.konst::<W16>(0);
    for i in 0..8u32 {
        let ii = b.konst::<W16>(i as u16);
        let summed = b.add::<W16>(top, ii);
        let slot = b.and::<W16>(summed, seven);
        let (sig, exp) = sem::read_st(b, slot);
        let e64 = b.zext::<W16, W64>(exp);
        let mask = b.konst::<W64>(0x7fff);
        let em = b.and::<W64>(e64, mask);
        let zro = b.konst::<W64>(0);
        let e_nz = b.cmp::<W64>(Cmp::Ne, em, zro);
        let s_nz = b.cmp::<W64>(Cmp::Ne, sig, zro);
        let nonempty = sem::bit_or(b, e_nz, s_nz);
        let bit = b.konst::<W16>(1u16 << i);
        let z16 = b.konst::<W16>(0);
        let sel = b.select::<W16>(nonempty, bit, z16);
        ftag = b.or::<W16>(ftag, sel);
    }
    let a4 = b.konst::<W64>(4);
    let aft = b.add::<W64>(a, a4);
    b.store::<W16>(aft, ftag, sem::DATA_WRITE)?;
    // 予約 + FIP/FCS/FOP/FDP/FDS（オフセット 6-27）は 0。
    let a6 = b.konst::<W64>(6);
    let az = b.add::<W64>(a, a6);
    let z64 = b.konst::<W64>(0);
    for i in 0..3u64 {
        let ki = b.konst::<W64>(i * 8);
        let addr = b.add::<W64>(az, ki);
        b.store::<W64>(addr, z64, sem::DATA_WRITE)?;
    }
    // ST レジスタ: 論理順（ST(0) から）で sig(8B)+exp(2B)。
    let a28 = b.konst::<W64>(28);
    for i in 0..8u32 {
        let ii = b.konst::<W16>(i as u16);
        let summed = b.add::<W16>(top, ii);
        let slot = b.and::<W16>(summed, seven);
        let (sig, exp) = sem::read_st(b, slot);
        let off = b.konst::<W64>(u64::from(i) * 10);
        let base = b.add::<W64>(a, a28);
        let addr = b.add::<W64>(base, off);
        b.store::<W64>(addr, sig, sem::DATA_WRITE)?;
        let off8 = b.konst::<W64>(u64::from(i) * 10 + 8);
        let addr8 = b.add::<W64>(base, off8);
        b.store::<W16>(addr8, exp, sem::DATA_WRITE)?;
    }
    // 初期化: FCW=0x037F、FSW/TOP=0、レジスタは空。
    let kcw = b.konst::<W16>(0x037F);
    b.set(sem::fcw_ref(), kcw);
    let z16 = b.konst::<W16>(0);
    b.set(sem::fsw_ref(), z16);
    b.set(sem::top_ref(), z16);
    for i in 0..8u32 {
        let ii = b.konst::<W16>(i as u16);
        let z = b.konst::<W64>(0);
        sem::write_st(b, ii, z, z16);
    }
    Ok(())
}

/// FRSTOR m108。FNSAVE が書いた形式から環境と ST を戻す。
/// FSW から TOP を `top` へ、C ビットを `fsw` へ反映する。
pub fn frstor_m<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>) -> Flow<B> {
    let Rm::Mem { a, .. } = ea else {
        return Ok(());
    };
    let a = *a;
    let fcw = b.load::<W16>(a, sem::DATA_READ)?;
    b.set(sem::fcw_ref(), fcw);
    let a2 = b.konst::<W64>(2);
    let afs = b.add::<W64>(a, a2);
    let fsw = b.load::<W16>(afs, sem::DATA_READ)?;
    b.set(sem::fsw_ref(), fsw);
    let sh = b.konst::<W16>(11);
    let t = b.shr_l::<W16>(fsw, sh);
    let seven = b.konst::<W16>(7);
    let top = b.and::<W16>(t, seven);
    b.set(sem::top_ref(), top);
    let a28 = b.konst::<W64>(28);
    for i in 0..8u32 {
        let off = b.konst::<W64>(u64::from(i) * 10);
        let base = b.add::<W64>(a, a28);
        let addr = b.add::<W64>(base, off);
        let sig = b.load::<W64>(addr, sem::DATA_READ)?;
        let off8 = b.konst::<W64>(u64::from(i) * 10 + 8);
        let addr8 = b.add::<W64>(base, off8);
        let exp = b.load::<W16>(addr8, sem::DATA_READ)?;
        // 論理 ST(i) は物理スロット (top+i)&7。
        let ii = b.konst::<W16>(i as u16);
        let summed = b.add::<W16>(top, ii);
        let slot = b.and::<W16>(summed, seven);
        sem::write_st(b, slot, sig, exp);
    }
    Ok(())
}

/// FBLD m80。9 バイトのパック十進 18 桁 + 符号バイトを読み、
/// 整数として拡張精度に変換して積む。符号付き 0 は -0.0 になる。
/// 数字でないニブルは値としてそのまま扱う（SDM の規定する無効動作は未対応）。
pub fn fbld_m<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>) -> Flow<B> {
    let Rm::Mem { a, .. } = ea else {
        return Ok(());
    };
    let a = *a;
    let mut acc = b.konst::<W64>(0);
    let mut mul = b.konst::<W64>(1);
    let ten = b.konst::<W64>(10);
    let m0f = b.konst::<W8>(0x0F);
    let s4 = b.konst::<W8>(4);
    for i in 0..18u64 {
        let off = b.konst::<W64>(i / 2);
        let addr = b.add::<W64>(a, off);
        let byte = b.load::<W8>(addr, sem::DATA_READ)?;
        let nib = if i % 2 == 0 {
            b.and::<W8>(byte, m0f)
        } else {
            b.shr_l::<W8>(byte, s4)
        };
        let nib64 = b.zext::<W8, W64>(nib);
        let term = b.mul::<W64>(nib64, mul);
        acc = b.add::<W64>(acc, term);
        mul = b.mul::<W64>(mul, ten);
    }
    let off9 = b.konst::<W64>(9);
    let addr9 = b.add::<W64>(a, off9);
    let sbyte = b.load::<W8>(addr9, sem::DATA_READ)?;
    let s80 = b.konst::<W8>(0x80);
    let sbits = b.and::<W8>(sbyte, s80);
    let is_neg = b.cmp::<W8>(Cmp::Eq, sbits, s80);
    let zero = b.konst::<W64>(0);
    let negv = b.sub::<W64>(zero, acc);
    let v = b.select::<W64>(is_neg, negv, acc);
    let (sig, exp0) = sem::i64_to_ext(b, v);
    // i64_to_ext は -0 を作れないので、負の 0 には符号ビットを足す。
    let kb = b.konst::<W16>(0x8000);
    let k0 = b.konst::<W16>(0);
    let sbit = b.select::<W16>(is_neg, kb, k0);
    let exp = b.or::<W16>(exp0, sbit);
    sem::push_ext(b, sig, exp)
}

/// FBSTP m80。ST(0) を FCW の丸めで整数にしてパック十進へ書き、pop する。
/// 18 桁に入らない値・非数は不定（全バイト 0xFF）を書く。
pub fn fbstp_m<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>) -> Flow<B> {
    let Rm::Mem { a, .. } = ea else {
        return Ok(());
    };
    let a = *a;
    let top = b.get(sem::top_ref());
    let (sig, exp) = sem::read_st(b, top);
    let v = sem::f80_to_i64(b, sig, exp);
    let indef = b.konst::<W64>(1u64 << 63);
    let raw_indef = b.cmp::<W64>(Cmp::Eq, v, indef);
    let exp64 = b.zext::<W16, W64>(exp);
    let s15 = b.konst::<W64>(15);
    let sgn = b.shr_l::<W64>(exp64, s15);
    let one = b.konst::<W64>(1);
    let neg = b.cmp::<W64>(Cmp::Eq, sgn, one);
    let zero = b.konst::<W64>(0);
    let negv = b.sub::<W64>(zero, v);
    let mag = b.select::<W64>(neg, negv, v);
    // 18 桁（< 10^18）に収まる範囲だけを書く。
    let lim = b.konst::<W64>(1_000_000_000_000_000_000);
    let big = b.cmp::<W64>(Cmp::GeU, mag, lim);
    let is_indef = sem::bit_or(b, raw_indef, big);
    let ten = b.konst::<W64>(10);
    let s4 = b.konst::<W64>(4);
    let ff8 = b.konst::<W8>(0xFF);
    let mut m = mag;
    for i in 0..9u64 {
        let off = b.konst::<W64>(i);
        let addr = b.add::<W64>(a, off);
        let d0 = b.urem::<W64>(m, ten);
        let m1 = b.udiv::<W64>(m, ten);
        let d1 = b.urem::<W64>(m1, ten);
        let m2 = b.udiv::<W64>(m1, ten);
        let d1s = b.shl::<W64>(d1, s4);
        let pair = b.or::<W64>(d0, d1s);
        let pair8: B::V<W8> = b.trunc::<W64, W8>(pair);
        let byte = b.select::<W8>(is_indef, ff8, pair8);
        b.store::<W8>(addr, byte, sem::DATA_WRITE)?;
        m = m2;
    }
    let off9 = b.konst::<W64>(9);
    let addr9 = b.add::<W64>(a, off9);
    let s8 = b.konst::<W8>(0x80);
    let z8 = b.konst::<W8>(0);
    let sval = b.select::<W8>(neg, s8, z8);
    let sbyte = b.select::<W8>(is_indef, ff8, sval);
    b.store::<W8>(addr9, sbyte, sem::DATA_WRITE)?;
    sem::pop_st(b, top)
}

/// FNSTSW AX（DF E0）。fsw に TOP を合成して AX へ書く。
pub fn fnstsw_ax<B: Backend>(b: &mut B) {
    let fsw: B::V<W16> = b.get(sem::fsw_ref());
    let top = b.get(sem::top_ref());
    let seven = b.konst::<W16>(7);
    let t3 = b.and::<W16>(top, seven);
    let sh = b.konst::<W16>(11);
    let tbits = b.shl::<W16>(t3, sh);
    let v = b.or::<W16>(fsw, tbits);
    decode::gwr16(b, Gpr(0), v);
}

// ===========================================================================
// SSE3-4.2・POPCNT/CRC32・MXCSR・0F AE 群
// ===========================================================================

use polyisa_sem::{F32, F64};

/// fcvt の丸めモード（aarch64 sem と同じ値域）。
const RM_RNE: u8 = 0;
const RM_RTZ: u8 = 1;
const RM_RDN: u8 = 2;
const RM_RUP: u8 = 3;

/// 定数 0。
fn k0<B: Backend, W: Width>(b: &mut B) -> B::V<W> {
    b.konst::<W>(W::from_u128(0))
}

/// v != 0。
fn nez<B: Backend, W: Width>(b: &mut B, v: B::V<W>) -> B::B {
    let z = b.konst::<W>(W::from_u128(0));
    b.cmp::<W>(Cmp::Ne, v, z)
}

/// v == 0。
fn eqz<B: Backend, W: Width>(b: &mut B, v: B::V<W>) -> B::B {
    let z = b.konst::<W>(W::from_u128(0));
    b.cmp::<W>(Cmp::Eq, v, z)
}

/// v < k（符号なし、定数比較）。
fn ltu_k<B: Backend, W: Width>(b: &mut B, v: B::V<W>, k: u128) -> B::B {
    let kk = b.konst::<W>(W::from_u128(k));
    b.cmp::<W>(Cmp::LtU, v, kk)
}

/// Backend の真偽値を 0/1 の整数へ。
fn zext_b<B: Backend, W: Width>(b: &mut B, v: B::B) -> B::V<W> {
    let one = b.konst::<W>(W::from_u128(1));
    let zero = b.konst::<W>(W::from_u128(0));
    b.select::<W>(v, one, zero)
}

/// 2つの 0/1 整数の AND。
fn band32<B: Backend>(b: &mut B, x: B::V<W32>, y: B::V<W32>) -> B::V<W32> {
    b.and::<W32>(x, y)
}

/// 2つの 0/1 整数の OR。
fn bor32<B: Backend>(b: &mut B, x: B::V<W32>, y: B::V<W32>) -> B::V<W32> {
    b.or::<W32>(x, y)
}

/// 32 ビット浮動小数点レーンを取り出す。
fn flane32<B: Backend>(b: &mut B, v: B::V<W128>, i: u32) -> B::V<F32> {
    let l = lane128(b, v, i * 32, 32);
    let w: B::V<W32> = b.trunc::<W128, W32>(l);
    b.trunc::<W32, F32>(w)
}

/// 64 ビット浮動小数点レーンを取り出す。
fn flane64<B: Backend>(b: &mut B, v: B::V<W128>, i: u32) -> B::V<F64> {
    let l = lane128(b, v, i * 64, 64);
    let w: B::V<W64> = b.trunc::<W128, W64>(l);
    b.trunc::<W64, F64>(w)
}

/// 浮動小数点値を `dst` のレーン `i` へ書く。
fn put_flane32<B: Backend>(b: &mut B, dst: B::V<W128>, v: B::V<F32>, i: u32) -> B::V<W128> {
    let w: B::V<W32> = b.trunc::<F32, W32>(v);
    let w128 = b.zext::<W32, W128>(w);
    put_lane128(b, dst, w128, i * 32, 32)
}

fn put_flane64<B: Backend>(b: &mut B, dst: B::V<W128>, v: B::V<F64>, i: u32) -> B::V<W128> {
    let w: B::V<W64> = b.trunc::<F64, W64>(v);
    let w128 = b.zext::<W64, W128>(w);
    put_lane128(b, dst, w128, i * 64, 64)
}

/// 浮動小数点値を整数丸めする。|a| >= 2^63 や NaN/Inf はそのまま返す
/// （aarch64 の frint と同じ近似）。
fn frint_f32<B: Backend>(b: &mut B, a: B::V<F32>, rm: u8) -> B::V<F32> {
    let lim = b.konst::<F32>(0x5f00_0000);
    let kz = b.konst::<F32>(0);
    // |a| = a から符号ビットを除いた値。fsgnjx は符号ビットを XOR する。
    let abs = b.fsgnjx::<F32>(a, kz);
    let small = b.flt::<F32>(abs, lim);
    let i = b.fcvt_s64::<F32>(a, rm);
    let r = b.fcvt_from_s64::<F32>(i, RM_RNE);
    let via_int = b.select::<F32>(small, r, a);
    let ordered = b.feq::<F32>(a, a);
    b.select::<F32>(ordered, via_int, a)
}

fn frint_f64<B: Backend>(b: &mut B, a: B::V<F64>, rm: u8) -> B::V<F64> {
    let lim = b.konst::<F64>(0x43e0_0000_0000_0000);
    let kz = b.konst::<F64>(0);
    let abs = b.fsgnjx::<F64>(a, kz);
    let small = b.flt::<F64>(abs, lim);
    let i = b.fcvt_s64::<F64>(a, rm);
    let r = b.fcvt_from_s64::<F64>(i, RM_RNE);
    let via_int = b.select::<F64>(small, r, a);
    let ordered = b.feq::<F64>(a, a);
    b.select::<F64>(ordered, via_int, a)
}

/// HADDPD/HADDPS/HSUBPD/HSUBPS。隣接ペアを加減算し、dst 側ペアを
/// 下位、src 側ペアを上位に詰める（phaddsub の浮動小数点版）。
pub fn phaddsub_f<B: Backend>(
    b: &mut B,
    sub: bool,
    fbits: u32,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let c = rx(b, ea, 128)?;
    let mut acc = b.konst::<W128>(0);
    let n = 64 / fbits;
    for (src_i, s) in [a, c].into_iter().enumerate() {
        for i in 0..n {
            let at = (src_i as u32 * n + i) * fbits;
            if fbits == 64 {
                let x = flane64(b, s, 2 * i);
                let y = flane64(b, s, 2 * i + 1);
                let r = if sub {
                    b.fsub::<F64>(x, y)
                } else {
                    b.fadd::<F64>(x, y)
                };
                acc = put_flane64(b, acc, r, at / 64);
            } else {
                let x = flane32(b, s, 2 * i);
                let y = flane32(b, s, 2 * i + 1);
                let r = if sub {
                    b.fsub::<F32>(x, y)
                } else {
                    b.fadd::<F32>(x, y)
                };
                acc = put_flane32(b, acc, r, at / 32);
            }
        }
    }
    b.set(sem::xmm_ref(dst), acc);
    Ok(())
}

/// ADDSUBPD/ADDSUBPS。偶数レーンは減算、奇数レーンは加算。
pub fn addsub<B: Backend>(
    b: &mut B,
    fbits: u32,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let c = rx(b, ea, 128)?;
    let mut acc = b.konst::<W128>(0);
    for i in 0..(128 / fbits) {
        let sub = i % 2 == 0;
        if fbits == 64 {
            let x = flane64(b, a, i);
            let y = flane64(b, c, i);
            let r = if sub {
                b.fsub::<F64>(x, y)
            } else {
                b.fadd::<F64>(x, y)
            };
            acc = put_flane64(b, acc, r, i);
        } else {
            let x = flane32(b, a, i);
            let y = flane32(b, c, i);
            let r = if sub {
                b.fsub::<F32>(x, y)
            } else {
                b.fadd::<F32>(x, y)
            };
            acc = put_flane32(b, acc, r, i);
        }
    }
    b.set(sem::xmm_ref(dst), acc);
    Ok(())
}

/// PBLENDVB。XMM0 の各バイトの MSB で `c` のバイトを選ぶ（0 は `a`）。
pub fn pblendvb<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let c = rx(b, ea, 128)?;
    let mask: B::V<W128> = b.get(sem::xmm_ref(sem::Xmm(0)));
    let mut acc = b.konst::<W128>(0);
    for i in 0..16u32 {
        let m = lane128(b, mask, i * 8 + 7, 1);
        let al = lane128(b, a, i * 8, 8);
        let cl = lane128(b, c, i * 8, 8);
        let m8: B::V<W8> = b.trunc::<W128, W8>(m);
        let sel = nez::<B, W8>(b, m8);
        let l = b.select::<W128>(sel, cl, al);
        acc = put_lane128(b, acc, l, i * 8, 8);
    }
    b.set(sem::xmm_ref(dst), acc);
    Ok(())
}

/// BLENDVPS/BLENDVPD。XMM0 の各要素の MSB で `c` の要素を選ぶ。
/// `elt` は要素のビット幅（32/64）。
pub fn blendv<B: Backend>(
    b: &mut B,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
    elt: u32,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let c = rx(b, ea, 128)?;
    let mask: B::V<W128> = b.get(sem::xmm_ref(sem::Xmm(0)));
    let mut acc = b.konst::<W128>(0);
    for i in 0..128u32 / elt {
        let m = lane128(b, mask, i * elt + elt - 1, 1);
        let al = lane128(b, a, i * elt, elt);
        let cl = lane128(b, c, i * elt, elt);
        let m8: B::V<W8> = b.trunc::<W128, W8>(m);
        let sel = nez::<B, W8>(b, m8);
        let l = b.select::<W128>(sel, cl, al);
        acc = put_lane128(b, acc, l, i * elt, elt);
    }
    b.set(sem::xmm_ref(dst), acc);
    Ok(())
}

/// DPPS/DPPD。imm[7:4] が掛けるレーン、imm[3:0] が結果を書くレーン。
pub fn dpp<B: Backend>(
    b: &mut B,
    fbits: u32,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let c = rx(b, ea, 128)?;
    let lanes = 128 / fbits;
    let mut acc = b.konst::<W128>(0);
    if fbits == 64 {
        let mut sum = b.konst::<F64>(0);
        for i in 0..lanes {
            if imm >> (4 + i) & 1 == 1 {
                let x = flane64(b, a, i);
                let y = flane64(b, c, i);
                let p = b.fmul::<F64>(x, y);
                sum = b.fadd::<F64>(sum, p);
            }
        }
        for i in 0..lanes {
            if imm >> i & 1 == 1 {
                acc = put_flane64(b, acc, sum, i);
            }
        }
    } else {
        let mut sum = b.konst::<F32>(0);
        for i in 0..lanes {
            if imm >> (4 + i) & 1 == 1 {
                let x = flane32(b, a, i);
                let y = flane32(b, c, i);
                let p = b.fmul::<F32>(x, y);
                sum = b.fadd::<F32>(sum, p);
            }
        }
        for i in 0..lanes {
            if imm >> i & 1 == 1 {
                acc = put_flane32(b, acc, sum, i);
            }
        }
    }
    b.set(sem::xmm_ref(dst), acc);
    Ok(())
}

/// ROUNDPS/ROUNDPD。全レーンを imm[1:0] の丸めモードで整数丸めする。
/// MXCSR の例外マスク・フラグ反映と imm[3] の MXCSR 参照は未対応。
/// Gap: GAP-0036
pub fn round_p<B: Backend>(
    b: &mut B,
    fbits: u32,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let rm = match imm & 3 {
        1 => RM_RDN,
        2 => RM_RUP,
        3 => RM_RTZ,
        _ => RM_RNE,
    };
    let dst = reg_x(d);
    let c = rx(b, ea, 128)?;
    let mut acc = b.konst::<W128>(0);
    for i in 0..(128 / fbits) {
        if fbits == 64 {
            let __h0 = flane64(b, c, i);
            let r = frint_f64(b, __h0, rm);
            acc = put_flane64(b, acc, r, i);
        } else {
            let __h1 = flane32(b, c, i);
            let r = frint_f32(b, __h1, rm);
            acc = put_flane32(b, acc, r, i);
        }
    }
    b.set(sem::xmm_ref(dst), acc);
    Ok(())
}

/// ROUNDSS/ROUNDSD。下位レーンのみ丸め、上位は dst のまま。
pub fn round_s<B: Backend>(
    b: &mut B,
    fbits: u32,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let rm = match imm & 3 {
        1 => RM_RDN,
        2 => RM_RUP,
        3 => RM_RTZ,
        _ => RM_RNE,
    };
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let c = rx(b, ea, fbits)?;
    let acc = if fbits == 64 {
        let __h2 = flane64(b, c, 0);
        let r = frint_f64(b, __h2, rm);
        put_flane64(b, a, r, 0)
    } else {
        let __h3 = flane32(b, c, 0);
        let r = frint_f32(b, __h3, rm);
        put_flane32(b, a, r, 0)
    };
    b.set(sem::xmm_ref(dst), acc);
    Ok(())
}

/// MPSADBW。a（第1被演算子）の imm[2] ブロックと、c（第2被演算子）の imm[1:0] ブロックから
/// 選んだ位置からずらした 4 バイト列の絶対差和を 8 本の u16 で返す。
pub fn mpsadbw<B: Backend>(
    b: &mut B,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let c = rx(b, ea, 128)?;
    let a_off = u32::from(imm >> 2 & 1) * 4;
    let c_off = u32::from(imm & 3) * 4;
    let mut acc = b.konst::<W128>(0);
    for i in 0..8u32 {
        let mut sum = k0::<B, W32>(b);
        for j in 0..4u32 {
            let al = lane128(b, a, (a_off + i + j) * 8, 8);
            let cl = lane128(b, c, (c_off + j) * 8, 8);
            let a8: B::V<W8> = b.trunc::<W128, W8>(al);
            let c8: B::V<W8> = b.trunc::<W128, W8>(cl);
            let a32 = b.zext::<W8, W32>(a8);
            let c32 = b.zext::<W8, W32>(c8);
            let diff = b.sub::<W32>(a32, c32);
            let __h4 = k0::<B, W32>(b);
            let neg = b.cmp::<W32>(Cmp::LtS, diff, __h4);
            let z = k0::<B, W32>(b);
            let negd = b.sub::<W32>(z, diff);
            let adiff = b.select::<W32>(neg, negd, diff);
            sum = b.add::<W32>(sum, adiff);
        }
        let s128 = b.zext::<W32, W128>(sum);
        acc = put_lane128(b, acc, s128, i * 16, 16);
    }
    b.set(sem::xmm_ref(dst), acc);
    Ok(())
}

/// PHMINPOSUW。8 本の u16 の最小値とその添え字を下位ワードに書く。
pub fn phminposuw<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let c = rx(b, ea, 128)?;
    let mut min = lane128(b, c, 0, 16);
    let mut idx = b.konst::<W128>(0);
    for i in 1..8u32 {
        let v = lane128(b, c, i * 16, 16);
        let v16: B::V<W16> = b.trunc::<W128, W16>(v);
        let m16: B::V<W16> = b.trunc::<W128, W16>(min);
        let smaller = b.cmp::<W16>(Cmp::LtU, v16, m16);
        let i128 = b.konst::<W128>(u128::from(i));
        idx = b.select::<W128>(smaller, i128, idx);
        min = b.select::<W128>(smaller, v, min);
    }
    let __h0 = b.konst::<W128>(0);
    let res = put_lane128(b, __h0, idx, 16, 16);
    let res = put_lane128(b, res, min, 0, 16);
    b.set(sem::xmm_ref(dst), res);
    Ok(())
}

/// バイト列の長を求める。`explicit` なら `len`（EAX/EDX 由来、16 で
/// 頭打ち）、さもなくば先頭の NUL まで（16 以下）。
fn xstrlen<B: Backend>(b: &mut B, v: B::V<W128>, explicit: bool, len: B::V<W32>) -> B::V<W32> {
    if explicit {
        // EAX/EDX は符号付きの絶対値として読み、16 で頭打ちにする。
        let k31 = b.konst::<W32>(31);
        let mask = b.shr_a::<W32>(len, k31);
        let x = b.xor::<W32>(len, mask);
        let abs = b.sub::<W32>(x, mask);
        let k16 = b.konst::<W32>(16);
        let over = b.cmp::<W32>(Cmp::GtU, abs, k16);
        b.select::<W32>(over, k16, abs)
    } else {
        let mut out = b.konst::<W32>(16);
        let mut seen = k0::<B, W32>(b);
        for i in 0..16u32 {
            let l = lane128(b, v, i * 8, 8);
            let b8: B::V<W8> = b.trunc::<W128, W8>(l);
            let isz = eqz::<B, W8>(b, b8);
            let isz32 = zext_b::<B, W32>(b, isz);
            let not_seen = eqz::<B, W32>(b, seen);
            let __h5 = zext_b::<B, W32>(b, not_seen);
            let take = b.and::<W32>(__h5, isz32);
            let take_it = nez::<B, W32>(b, take);
            let iv = b.konst::<W32>(i);
            out = b.select::<W32>(take_it, iv, out);
            seen = b.or::<W32>(seen, isz32);
        }
        out
    }
}

/// PCMPxSTRy 系の集約結果を IntRes1 として 16 ビットへ畳む。
/// `agg` は imm[3:2]（equal any / ranges / equal each / equal ordered）。
fn str_agg<B: Backend>(
    b: &mut B,
    agg: u8,
    i: u32,
    a: B::V<W128>,
    c: B::V<W128>,
    len_a: B::V<W32>,
    len_c: B::V<W32>,
) -> B::V<W32> {
    let ci = lane128(b, c, i * 8, 8);
    let ci8: B::V<W8> = b.trunc::<W128, W8>(ci);
    match agg {
        // equal any。c[i] が a のどれかの有効バイトと等しい。
        0 => {
            let mut any = k0::<B, W32>(b);
            for j in 0..16u32 {
                let aj = lane128(b, a, j * 8, 8);
                let aj8: B::V<W8> = b.trunc::<W128, W8>(aj);
                let jvalid = str_valid(b, len_a, j);
                let eq = b.cmp::<W8>(Cmp::Eq, ci8, aj8);
                let __h6 = zext_b::<B, W32>(b, eq);
                let __h7 = band32(b, __h6, jvalid);
                any = bor32(b, any, __h7);
            }
            let __h8 = str_valid(b, len_c, i);
            band32(b, any, __h8)
        }
        // ranges。a の偶奇ペア [a[2j], a[2j+1]] の範囲に c[i] が入る。
        1 => {
            let mut any = k0::<B, W32>(b);
            for j in 0..8u32 {
                let lo = lane128(b, a, 2 * j * 8, 8);
                let hi = lane128(b, a, (2 * j + 1) * 8, 8);
                let lo8: B::V<W8> = b.trunc::<W128, W8>(lo);
                let hi8: B::V<W8> = b.trunc::<W128, W8>(hi);
                let lv = str_valid(b, len_a, 2 * j);
                let hv = str_valid(b, len_a, 2 * j + 1);
                let __h1 = b.cmp::<W8>(Cmp::GeU, ci8, lo8);
                let ge = zext_b::<B, W32>(b, __h1);
                let __h2 = b.cmp::<W8>(Cmp::LeU, ci8, hi8);
                let le = zext_b::<B, W32>(b, __h2);
                let inr = band32(b, ge, le);
                let __h9 = band32(b, lv, hv);
                let __h10 = band32(b, inr, __h9);
                any = bor32(b, any, __h10);
            }
            let __h11 = str_valid(b, len_c, i);
            band32(b, any, __h11)
        }
        // equal each。両方無効なら強制的に真（SDM のオーバーライド表）。
        2 => {
            let ai = lane128(b, a, i * 8, 8);
            let ai8: B::V<W8> = b.trunc::<W128, W8>(ai);
            let __h3 = b.cmp::<W8>(Cmp::Eq, ci8, ai8);
            let eq = zext_b::<B, W32>(b, __h3);
            let iv = str_valid(b, len_a, i);
            let cv_i = str_valid(b, len_c, i);
            let iv_cv = band32(b, iv, cv_i);
            let hit = band32(b, eq, iv_cv);
            let one = b.konst::<W32>(1);
            let niv = b.xor::<W32>(iv, one);
            let ncv = b.xor::<W32>(cv_i, one);
            let both_invalid = band32(b, niv, ncv);
            bor32(b, hit, both_invalid)
        }
        // equal ordered。第1被演算子 a が needle（len_a バイトの
        // パターン）、第2被演算子 c が haystack。res1[i] は c の位置
        // i に a[0..len_a) が現れるとき 1。i+j >= 16 のパターン
        // バイトは比較しない（パターンが haystack の終端を
        // 越えても一致する建築上の仕様）。
        _ => {
            let mut all = b.konst::<W32>(1);
            for j in 0..16u32 {
                let ij = i + j;
                // パターンの j バイト目が haystack の範囲内にある
                // 時だけ比較する。j >= len_a ならスキップ。
                let jge = ltu_k::<B, W32>(b, len_a, u128::from(j + 1));
                let skip = zext_b::<B, W32>(b, jge);
                let ok = if in_range16(ij) {
                    let cij = lane128(b, c, ij * 8, 8);
                    let cij8: B::V<W8> = b.trunc::<W128, W8>(cij);
                    let aj = lane128(b, a, j * 8, 8);
                    let aj8: B::V<W8> = b.trunc::<W128, W8>(aj);
                    let e = b.cmp::<W8>(Cmp::Eq, cij8, aj8);
                    let eq = zext_b::<B, W32>(b, e);
                    bor32(b, eq, skip)
                } else {
                    // レジスタ端を越えるバイトは比較しない。
                    b.konst::<W32>(1)
                };
                all = band32(b, all, ok);
            }
            // ForceFalseIfInvalid: i >= len_c（haystack の長）なら 0。
            let cv = str_valid(b, len_c, i);
            band32(b, all, cv)
        }
    }
}

const fn in_range16(i: u32) -> bool {
    i < 16
}

/// `i < len`（i が有効バイト範囲内）を 0/1 整数で返す。
fn str_valid<B: Backend>(b: &mut B, len: B::V<W32>, i: u32) -> B::V<W32> {
    let ki = b.konst::<W32>(i);
    let gt = b.cmp::<W32>(Cmp::GtU, len, ki);
    zext_b::<B, W32>(b, gt)
}

/// PCMPxSTRy。集約（imm[3:2]）→極性（imm[5:4]）→出力（imm[6]）の
/// 三段で IntRes2 を求め、index 形は ECX、mask 形は XMM0 に書く。
/// フラグは CF/ZF/SF/OF を更新し AF/PF は 0 にする。
pub fn pxstr<B: Backend>(
    b: &mut B,
    explicit: bool,
    index: bool,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let a: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    let c = rx(b, ea, 128)?;
    let len_a = if explicit {
        let eax32 = grd_w::<B, W32>(b, Gpr(0), d);
        xstrlen(b, a, true, eax32)
    } else {
        let __h17 = k0::<B, W32>(b);
        xstrlen(b, a, false, __h17)
    };
    let len_c = if explicit {
        let edx32 = grd_w::<B, W32>(b, Gpr(2), d);
        xstrlen(b, c, true, edx32)
    } else {
        let __h18 = k0::<B, W32>(b);
        xstrlen(b, c, false, __h18)
    };
    // IntRes1 を 16 ビットへ畳む。
    let mut res1 = k0::<B, W32>(b);
    for i in 0..16u32 {
        // imm[1:0]（要素の幅と符号）はバイト・符号なしのみを仮定する。
        // Gap: GAP-0036
        let r = str_agg(b, (imm >> 2) & 3, i, a, c, len_a, len_c);
        let __h5 = b.konst::<W32>(i);
        let sh = b.shl::<W32>(r, __h5);
        res1 = b.or::<W32>(res1, sh);
    }
    // 極性。imm[5:4]: 00/10 正、01 反転、11 有効バイトで反転。
    let res2 = match (imm >> 4) & 3 {
        1 => {
            let inv = b.not::<W32>(res1);
            let __h6 = b.konst::<W32>(0xFFFF);
            b.and::<W32>(inv, __h6)
        }
        3 => {
            let mut m = k0::<B, W32>(b);
            for i in 0..16u32 {
                let valid = str_valid(b, len_c, i);
                let __h7 = b.konst::<W32>(i);
                let sh = b.shl::<W32>(valid, __h7);
                m = b.or::<W32>(m, sh);
            }
            b.xor::<W32>(res1, m)
        }
        _ => res1,
    };
    // 出力とフラグ。
    let cf = nez::<B, W32>(b, res2);
    if index {
        // ECX に添え字。imm[6]=0 は最小、=1 は最大の立ちビット。
        let mut out = b.konst::<W32>(16);
        let range: &[u32] = if imm & 0x40 == 0 {
            &[15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
        } else {
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        };
        for &i in range {
            let bit = str_bit(b, res2, i);
            let iv = b.konst::<W32>(i);
            out = b.select::<W32>(bit, iv, out);
        }
        gwr_w::<B, W32>(b, Gpr(1), d, out);
    } else {
        // XMM0 にマスク。imm[6]=0 は 16 ビットマスク、=1 はバイトマスク。
        let res: B::V<W128> = if imm & 0x40 == 0 {
            b.zext::<W32, W128>(res2)
        } else {
            let mut m = b.konst::<W128>(0);
            for i in 0..16u32 {
                let bit = str_bit(b, res2, i);
                let ff = b.konst::<W128>(0xFF);
                let zz = b.konst::<W128>(0);
                let fb = b.select::<W128>(bit, ff, zz);
                m = put_lane128(b, m, fb, i * 8, 8);
            }
            m
        };
        b.set(sem::xmm_ref(sem::Xmm(0)), res);
    }
    // フラグ: CF=res2!=0、ZF=len_c<16、SF=len_a<16、OF=res2 bit0。
    // AF/PF は 0。
    let zf = ltu_k::<B, W32>(b, len_c, 16);
    let sf = ltu_k::<B, W32>(b, len_a, 16);
    let __h8 = b.konst::<W32>(1);
    let bit0 = b.and::<W32>(res2, __h8);
    let of = nez::<B, W32>(b, bit0);
    let f: B::V<W32> = b.get(eflags_ref());
    let mask = b.konst::<W32>(
        sem::FLAG_CF | sem::FLAG_ZF | sem::FLAG_SF | sem::FLAG_OF | sem::FLAG_AF | sem::FLAG_PF,
    );
    let __h9 = b.not::<W32>(mask);
    let kept = b.and::<W32>(f, __h9);
    let mut v = kept;
    let __h19 = pick(b, cf, sem::FLAG_CF);
    v = b.or::<W32>(v, __h19);
    let __h20 = pick(b, zf, sem::FLAG_ZF);
    v = b.or::<W32>(v, __h20);
    let __h21 = pick(b, sf, sem::FLAG_SF);
    v = b.or::<W32>(v, __h21);
    let __h22 = pick(b, of, sem::FLAG_OF);
    v = b.or::<W32>(v, __h22);
    b.set(eflags_ref(), v);
    Ok(())
}

/// `v` のビット `i`。
fn str_bit<B: Backend>(b: &mut B, v: B::V<W32>, i: u32) -> B::B {
    let __h10 = b.konst::<W32>(i);
    let sh = b.shr_l::<W32>(v, __h10);
    let __h11 = b.konst::<W32>(1);
    let bit = b.and::<W32>(sh, __h11);
    nez::<B, W32>(b, bit)
}

/// CRC32（CRC32C、反射多項式 0x82F63B78）。`ebits` は被演算子幅
/// （8/16/32/64）。初期値は dst の下位 32 ビット。
pub fn crc32<B: Backend>(
    b: &mut B,
    ebits: u32,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = decode::reg(d);
    let src: B::V<W64> = match ebits {
        8 => {
            let v: B::V<W8> = decode::rd8(b, ea, d)?;
            b.zext::<W8, W64>(v)
        }
        16 => {
            let v: B::V<W16> = decode::rd16(b, ea)?;
            b.zext::<W16, W64>(v)
        }
        32 => {
            let v: B::V<W32> = decode::rd32(b, ea)?;
            b.zext::<W32, W64>(v)
        }
        _ => decode::rd64(b, ea)?,
    };
    let dst64 = grd_w::<B, W64>(b, dst, d);
    let init: B::V<W32> = b.trunc::<W64, W32>(dst64);
    let poly = b.konst::<W32>(0x82F6_3B78);
    let mut crc = init;
    let nbytes = ebits / 8;
    for i in 0..nbytes {
        let sh = b.konst::<W64>(u64::from(i * 8));
        let __h13 = b.shr_l::<W64>(src, sh);
        let __h12 = b.konst::<W64>(0xFF);
        let byte = b.and::<W64>(__h13, __h12);
        let b32: B::V<W32> = b.trunc::<W64, W32>(byte);
        crc = b.xor::<W32>(crc, b32);
        for _ in 0..8 {
            let __h14 = b.konst::<W32>(1);
            let lsb = b.and::<W32>(crc, __h14);
            let __h15 = b.konst::<W32>(1);
            let shifted = b.shr_l::<W32>(crc, __h15);
            let x = b.xor::<W32>(shifted, poly);
            let has = nez::<B, W32>(b, lsb);
            crc = b.select::<W32>(has, x, shifted);
        }
    }
    let r = b.zext::<W32, W64>(crc);
    gwr_w::<B, W64>(b, dst, d, r);
    Ok(())
}

/// POPCNT。`w` 幅の被演算子の立ちビット数を dst へ書く。
/// 結果が 0 なら ZF、他の状態旗は 0。
pub fn popcnt<B: Backend>(
    b: &mut B,
    w: u8,
    reg: Gpr,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let v: B::V<W64> = match w {
        16 => {
            let x: B::V<W16> = decode::rd16(b, ea)?;
            b.zext::<W16, W64>(x)
        }
        64 => decode::rd64(b, ea)?,
        _ => {
            let x: B::V<W32> = decode::rd32(b, ea)?;
            b.zext::<W32, W64>(x)
        }
    };
    let mut acc = b.konst::<W64>(0);
    for i in 0..u32::from(w) {
        let ksh = b.konst::<W64>(u64::from(i));
        let sh = b.shr_l::<W64>(v, ksh);
        let __h16 = b.konst::<W64>(1);
        let bit = b.and::<W64>(sh, __h16);
        acc = b.add::<W64>(acc, bit);
    }
    match w {
        64 => gwr_w::<B, W64>(b, reg, d, acc),
        16 => {
            let a16: B::V<W16> = b.trunc::<W64, W16>(acc);
            gwr_w::<B, W16>(b, reg, d, a16);
        }
        _ => {
            let a32: B::V<W32> = b.trunc::<W64, W32>(acc);
            gwr_w::<B, W32>(b, reg, d, a32);
        }
    }
    // ZF=結果 0、他の状態旗は 0。
    let zf = eqz::<B, W64>(b, acc);
    let f: B::V<W32> = b.get(eflags_ref());
    let mask = b.konst::<W32>(
        sem::FLAG_CF | sem::FLAG_ZF | sem::FLAG_SF | sem::FLAG_OF | sem::FLAG_AF | sem::FLAG_PF,
    );
    let __h17 = b.not::<W32>(mask);
    let kept = b.and::<W32>(f, __h17);
    let __h23 = pick(b, zf, sem::FLAG_ZF);
    let v = b.or::<W32>(kept, __h23);
    b.set(eflags_ref(), v);
    Ok(())
}

/// LDMXCSR。m32 を MXCSR へ読み込む。
pub fn ldmxcsr<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    if let Rm::Mem { a, .. } = ea {
        let v: B::V<W32> = b.load::<W32>(*a, sem::DATA_READ)?;
        b.set(sem::mxcsr_ref(), v);
    }
    Ok(())
}

/// STMXCSR。MXCSR を m32 へ書く。
pub fn stmxcsr<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    if let Rm::Mem { a, .. } = ea {
        let a = *a;
        let v: B::V<W32> = b.get(sem::mxcsr_ref());
        b.store::<W32>(a, v, sem::DATA_WRITE)?;
    }
    Ok(())
}

/// SFENCE/MFENCE/LFENCE/CLFLUSH。機能シミュレーションでは順序・
/// キャッシュの効果はないので何もしない。
pub fn mem_hint<B: Backend>(b: &mut B) -> Result<(), B::Exit> {
    let _ = b;
    Ok(())
}

/// CMPXCHG8B/CMPXCHG16B。EDX:EAX（または RDX:RAX）とメモリを比較し、
/// 等しければ ECX:EBX（RCX:RBX）を書き込み、違えばメモリ値を
/// EDX:EAX（RDX:RAX）へ読む。ZF に結果を書く。
pub fn cmpxchg_m<B: Backend>(
    b: &mut B,
    wide: bool,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let Rm::Mem { a, .. } = ea else {
        return Ok(());
    };
    let a = *a;
    if wide {
        // 128 ビット形（REX.W）。RDX:RAX を期待値、RCX:RBX を新値。
        let acc_lo = sem::read64(b, Gpr(0));
        let acc_hi = sem::read64(b, Gpr(2));
        let new_lo = sem::read64(b, Gpr(3));
        let new_hi = sem::read64(b, Gpr(1));
        let old = b.load::<W128>(a, sem::DATA_READ)?;
        let acc = cat64(b, acc_lo, acc_hi);
        let new = cat64(b, new_lo, new_hi);
        let eq = b.cmp::<W128>(Cmp::Eq, old, acc);
        let to_mem = b.select::<W128>(eq, new, old);
        b.store::<W128>(a, to_mem, sem::DATA_WRITE)?;
        let old_lo = lane128(b, old, 0, 64);
        let old_hi = lane128(b, old, 64, 64);
        let olo: B::V<W64> = b.trunc::<W128, W64>(old_lo);
        let ohi: B::V<W64> = b.trunc::<W128, W64>(old_hi);
        let r_lo = b.select::<W64>(eq, acc_lo, olo);
        let r_hi = b.select::<W64>(eq, acc_hi, ohi);
        sem::write64(b, Gpr(0), r_lo);
        sem::write64(b, Gpr(2), r_hi);
        set_zf(b, eq);
    } else {
        let acc_lo: B::V<W32> = b.get(sem::Gpr(0).state());
        let acc_hi: B::V<W32> = b.get(sem::Gpr(2).state());
        let new_lo: B::V<W32> = b.get(sem::Gpr(3).state());
        let new_hi: B::V<W32> = b.get(sem::Gpr(1).state());
        let old = b.load::<W64>(a, sem::DATA_READ)?;
        let acc = cat32(b, acc_lo, acc_hi);
        let new = cat32(b, new_lo, new_hi);
        let eq = b.cmp::<W64>(Cmp::Eq, old, acc);
        let to_mem = b.select::<W64>(eq, new, old);
        b.store::<W64>(a, to_mem, sem::DATA_WRITE)?;
        let olo: B::V<W32> = b.trunc::<W64, W32>(old);
        let __h18 = b.konst::<W64>(32);
        let ohi64 = b.shr_l::<W64>(old, __h18);
        let ohi: B::V<W32> = b.trunc::<W64, W32>(ohi64);
        let r_lo = b.select::<W32>(eq, acc_lo, olo);
        let r_hi = b.select::<W32>(eq, acc_hi, ohi);
        gwr_w::<B, W32>(b, Gpr(0), d, r_lo);
        gwr_w::<B, W32>(b, Gpr(2), d, r_hi);
        set_zf(b, eq);
    }
    Ok(())
}

fn cat64<B: Backend>(b: &mut B, lo: B::V<W64>, hi: B::V<W64>) -> B::V<W128> {
    let lo128 = b.zext::<W64, W128>(lo);
    let hi128 = b.zext::<W64, W128>(hi);
    let __h19 = b.konst::<W128>(64);
    let hi_sh = b.shl::<W128>(hi128, __h19);
    b.or::<W128>(lo128, hi_sh)
}

fn cat32<B: Backend>(b: &mut B, lo: B::V<W32>, hi: B::V<W32>) -> B::V<W64> {
    let lo64 = b.zext::<W32, W64>(lo);
    let hi64 = b.zext::<W32, W64>(hi);
    let __h20 = b.konst::<W64>(32);
    let hi_sh = b.shl::<W64>(hi64, __h20);
    b.or::<W64>(lo64, hi_sh)
}

/// ZF を `eq` で置き換える。
fn set_zf<B: Backend>(b: &mut B, eq: B::B) {
    let f: B::V<W32> = b.get(eflags_ref());
    let __h21 = b.konst::<W32>(!sem::FLAG_ZF);
    let kept = b.and::<W32>(f, __h21);
    let __h24 = pick(b, eq, sem::FLAG_ZF);
    let v = b.or::<W32>(kept, __h24);
    b.set(eflags_ref(), v);
}

// ---------------------------------------------------------------------------
// SSSE3 の MMX 形（64 ビット）。XMM 形と同じ演算を st_sig 上で行う。
// ---------------------------------------------------------------------------

/// PSHUFB の MMX 形。制御バイトの MSB が立つ位置は 0、下位 3 ビットで
/// シャッフルする。
pub fn pshufb64<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let dst = reg_m(d);
    let a: B::V<W64> = b.get(sem::st_sig_ref(dst));
    let c = rq(b, ea)?;
    let mut acc = b.konst::<W64>(0);
    for i in 0..8u32 {
        let ctrl = lane64(b, c, i * 8, 8);
        let c8: B::V<W8> = b.trunc::<W64, W8>(ctrl);
        let __h22 = b.konst::<W8>(0x07);
        let idx = b.and::<W8>(c8, __h22);
        let idx64 = b.zext::<W8, W64>(idx);
        let __h23 = b.konst::<W64>(3);
        let sh = b.shl::<W64>(idx64, __h23);
        let __h25 = b.shr_l::<W64>(a, sh);
        let __h24 = b.konst::<W64>(0xFF);
        let byte = b.and::<W64>(__h25, __h24);
        let __h26 = b.konst::<W8>(0x80);
        let msb = b.and::<W8>(c8, __h26);
        let kill = nez::<B, W8>(b, msb);
        let __h27 = b.konst::<W64>(0);
        let v = b.select::<W64>(kill, __h27, byte);
        acc = put_lane64(b, acc, v, i * 8, 8);
    }
    b.set(sem::st_sig_ref(dst), acc);
    Ok(())
}

/// PHADD/PHSUB の MMX 形。
pub fn phaddsub64<B: Backend, W: Width>(
    b: &mut B,
    sub: bool,
    sat: bool,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_m(d);
    let a: B::V<W64> = b.get(sem::st_sig_ref(dst));
    let c = rq(b, ea)?;
    let bits = W::BITS;
    let half = 32 / bits;
    let mut acc = b.konst::<W64>(0);
    for (src_i, s) in [a, c].into_iter().enumerate() {
        for i in 0..half {
            let l0 = lane64(b, s, 2 * i * bits, bits);
            let l1 = lane64(b, s, (2 * i + 1) * bits, bits);
            let w0: B::V<W> = b.trunc::<W64, W>(l0);
            let w1: B::V<W> = b.trunc::<W64, W>(l1);
            let r = match (sub, sat) {
                (true, true) => sat_sub_s::<B, W>(b, w0, w1),
                (true, false) => b.sub::<W>(w0, w1),
                (false, true) => sat_add_s::<B, W>(b, w0, w1),
                (false, false) => b.add::<W>(w0, w1),
            };
            let r64 = b.zext::<W, W64>(r);
            acc = put_lane64(b, acc, r64, (src_i as u32 * half + i) * bits, bits);
        }
    }
    b.set(sem::st_sig_ref(dst), acc);
    Ok(())
}

/// PMADDUBSW の MMX 形。
pub fn pmaddubsw64<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let dst = reg_m(d);
    let a: B::V<W64> = b.get(sem::st_sig_ref(dst));
    let c = rq(b, ea)?;
    let mut acc = b.konst::<W64>(0);
    for i in 0..4u32 {
        let mut sum = k0::<B, W32>(b);
        for j in 0..2u32 {
            let at = i * 16 + j * 8;
            let al = lane64(b, a, at, 8);
            let cl = lane64(b, c, at, 8);
            let a8: B::V<W8> = b.trunc::<W64, W8>(al);
            let c8: B::V<W8> = b.trunc::<W64, W8>(cl);
            let ab = b.zext::<W8, W32>(a8);
            let cb = b.sext::<W8, W32>(c8);
            let p = b.mul::<W32>(ab, cb);
            sum = b.add::<W32>(sum, p);
        }
        let s16 = sat_s32_s16(b, sum);
        let s64 = b.zext::<W16, W64>(s16);
        acc = put_lane64(b, acc, s64, i * 16, 16);
    }
    b.set(sem::st_sig_ref(dst), acc);
    Ok(())
}

/// i32 を i16 飽和する。
fn sat_s32_s16<B: Backend>(b: &mut B, v: B::V<W32>) -> B::V<W16> {
    let kmax = b.konst::<W32>(0x7FFF);
    let kmin = b.konst::<W32>(0xFFFF_8000);
    let k16max = b.konst::<W32>(0x7FFF);
    let k16min = b.konst::<W32>(0x8000);
    let hi = b.cmp::<W32>(Cmp::GtS, v, kmax);
    let v = b.select::<W32>(hi, k16max, v);
    let lo = b.cmp::<W32>(Cmp::LtS, v, kmin);
    let v = b.select::<W32>(lo, k16min, v);
    b.trunc::<W32, W16>(v)
}

/// PMULHRSW の MMX 形。(a*c*2 + 0x8000) >> 16。
pub fn pmulhrsw64<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let dst = reg_m(d);
    let a: B::V<W64> = b.get(sem::st_sig_ref(dst));
    let c = rq(b, ea)?;
    let mut acc = b.konst::<W64>(0);
    for i in 0..4u32 {
        let al = lane64(b, a, i * 16, 16);
        let cl = lane64(b, c, i * 16, 16);
        let a16: B::V<W16> = b.trunc::<W64, W16>(al);
        let c16: B::V<W16> = b.trunc::<W64, W16>(cl);
        let a32 = b.sext::<W16, W32>(a16);
        let c32 = b.sext::<W16, W32>(c16);
        let p = b.mul::<W32>(a32, c32);
        let __h28 = b.konst::<W32>(1);
        let p2 = b.shl::<W32>(p, __h28);
        let __h29 = b.konst::<W32>(0x8000);
        let r = b.add::<W32>(p2, __h29);
        let __h30 = b.konst::<W32>(16);
        let r = b.shr_a::<W32>(r, __h30);
        let r16: B::V<W16> = b.trunc::<W32, W16>(r);
        let r64 = b.zext::<W16, W64>(r16);
        acc = put_lane64(b, acc, r64, i * 16, 16);
    }
    b.set(sem::st_sig_ref(dst), acc);
    Ok(())
}

/// PSIGN の MMX 形。c の符号で a を正・零・負にする。
pub fn psign64<B: Backend, W: Width>(
    b: &mut B,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    lane_bin64::<B, W>(b, d, ea, |b, a, c| {
        let z = k0::<B, W>(b);
        let neg = b.cmp::<W>(Cmp::LtS, c, z);
        let zero = b.cmp::<W>(Cmp::Eq, c, z);
        let nega = b.sub::<W>(z, a);
        let inner = b.select::<W>(zero, z, a);
        b.select::<W>(neg, nega, inner)
    })
}

/// PABS の MMX 形。
pub fn pabs64<B: Backend, W: Width>(
    b: &mut B,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    lane_bin64::<B, W>(b, d, ea, |b, _a, c| {
        let z = k0::<B, W>(b);
        let neg = b.cmp::<W>(Cmp::LtS, c, z);
        let negc = b.sub::<W>(z, c);
        b.select::<W>(neg, negc, c)
    })
}

/// PALIGNR の MMX 形。128 ビット連結の右シフトを 64 ビットで行う。
pub fn palignr64<B: Backend>(
    b: &mut B,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_m(d);
    let a: B::V<W64> = b.get(sem::st_sig_ref(dst));
    let c = rq(b, ea)?;
    let sh = u32::from(imm) * 8;
    let v = if sh == 0 {
        c
    } else if sh < 64 {
        let klo = b.konst::<W64>(u64::from(sh));
        let lo = b.shr_l::<W64>(c, klo);
        let khi = b.konst::<W64>(u64::from(64 - sh));
        let hi = b.shl::<W64>(a, khi);
        b.or::<W64>(lo, hi)
    } else if sh < 128 {
        let ksh = b.konst::<W64>(u64::from(sh - 64));
        b.shr_l::<W64>(a, ksh)
    } else {
        b.konst::<W64>(0)
    };
    b.set(sem::st_sig_ref(dst), v);
    Ok(())
}
