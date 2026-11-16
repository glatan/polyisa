// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! オペコード表経路の意味論。被演算子を `Rm`（レジスタ直接 or
//! 実効アドレス）と幅で受け、アドレス形ごとの直積を避ける。
//!
//! Ref: SPEC-X86-INTEL-SDM (v093) Vol.2.

use polyisa_sem::{Backend, Cmp, Flow, W8, W16, W32, W64};

use crate::MapDec;
use crate::decode::{self, Hw, Rm};
use crate::sem::{
    self, Gpr, eflags_ref, eip_ref, read_cf, read_of, read_pf, read_sf, read_zf, update_add_flags,
    update_logic_flags, update_sub_flags,
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

fn alu_flags<B: Backend, W: Hw>(b: &mut B, op: Alu, x: B::V<W>, y: B::V<W>, v: B::V<W>) {
    match op {
        Alu::Add | Alu::Adc => update_add_flags(b, x, y, v),
        Alu::Or | Alu::And | Alu::Xor => update_logic_flags(b, v),
        Alu::Sub | Alu::Sbb | Alu::Cmp => update_sub_flags(b, x, y, v),
    }
}

/// ADC/SBB のキャリー分を被演算子に足す。
fn alu_carry<B: Backend, W: Hw>(b: &mut B, op: Alu, y: B::V<W>) -> B::V<W> {
    if matches!(op, Alu::Adc | Alu::Sbb) {
        let cf = read_cf(b);
        let one = b.konst::<W>(W::from_u128(1));
        let zero = b.konst::<W>(W::from_u128(0));
        let c = b.select::<W>(cf, one, zero);
        b.add::<W>(y, c)
    } else {
        y
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
    let y = alu_carry::<B, W>(b, op, y);
    let v = alu_op::<B, W>(b, op, x, y);
    alu_flags::<B, W>(b, op, x, y, v);
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
/// `addr` はセグメントを含まないリニアの数値。
pub fn lea<B: Backend>(
    b: &mut B,
    w: u8,
    dst: Gpr,
    rm: &Rm<B::V<W64>>,
    asize: u8,
    d: &MapDec,
) -> Flow<B> {
    let Rm::Mem(a) = rm else {
        return Ok(()); // #UD（mod=11）は呼び出し側で排除済み想定
    };
    match (w, asize) {
        (16, _) => {
            let v: B::V<W16> = b.trunc::<W64, W16>(*a);
            gwr_w::<B, W16>(b, dst, d, v);
        }
        (32, _) => {
            let v: B::V<W32> = b.trunc::<W64, W32>(*a);
            gwr_w::<B, W32>(b, dst, d, v);
        }
        (_, 64) => sem::write64(b, dst, *a),
        _ => {
            let v: B::V<W32> = b.trunc::<W64, W32>(*a);
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
#[derive(Clone, Copy)]
pub enum Sh {
    Rol,
    Ror,
    Rcl,
    Rcr,
    Shl,
    Shr,
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
) -> Flow<B> {
    match w {
        8 => shift_w::<B, W8>(b, op, rm, d, cnt),
        16 => shift_w::<B, W16>(b, op, rm, d, cnt),
        32 => shift_w::<B, W32>(b, op, rm, d, cnt),
        _ => shift_w::<B, W64>(b, op, rm, d, cnt),
    }
}

fn shift_w<B: Backend, W: Hw>(
    b: &mut B,
    op: Sh,
    rm: &Rm<B::V<W64>>,
    d: &MapDec,
    cnt: ShiftCnt,
) -> Flow<B> {
    let mask: u64 = if W::BITS == 64 { 63 } else { 31 };
    let n = match cnt {
        ShiftCnt::Imm(i) => b.konst::<W>(W::from_u128(u128::from(i & mask as u32))),
        ShiftCnt::One => b.konst::<W>(W::from_u128(1)),
        ShiftCnt::Cl => {
            let cl = sem::read8(b, Gpr(1), false);
            let cl: B::V<W32> = b.zext::<W8, W32>(cl);
            let m = b.konst::<W32>(mask as u32);
            let v = b.and::<W32>(cl, m);
            b.trunc::<W32, W>(v)
        }
    };
    let x = rd_w::<B, W>(b, rm, d)?;
    let bits = W::BITS;
    // bits-n は n=0 で bits になるため mod しておく。
    let v = match op {
        Sh::Shl => b.shl::<W>(x, n),
        Sh::Shr => b.shr_l::<W>(x, n),
        Sh::Sar => b.shr_a::<W>(x, n),
        Sh::Rol | Sh::Ror | Sh::Rcl | Sh::Rcr => {
            // 循環は (x<<n)|(x>>(bits-n)) 型。RCL/RCR は CF 込みの
            // bits+1 循環だが、単一スレッド試作では算術近似に留める。
            let bm = b.konst::<W>(W::from_u128(u128::from(bits - 1)));
            let n_mod = b.and::<W>(n, bm);
            let bmc = b.konst::<W>(W::from_u128(u128::from(bits)));
            let m = b.sub::<W>(bmc, n_mod);
            let l = b.shl::<W>(
                x,
                if matches!(op, Sh::Rol | Sh::Rcl) {
                    n_mod
                } else {
                    m
                },
            );
            let r = b.shr_l::<W>(
                x,
                if matches!(op, Sh::Rol | Sh::Rcl) {
                    m
                } else {
                    n_mod
                },
            );
            b.or::<W>(l, r)
        }
    };
    wr_w::<B, W>(b, rm, d, v)?;
    // 旗: 量が 0 なら据え置き。CF は最後に追い出されたビット、OF は
    // n=1 のときだけ更新される（SDM Vol.2 各命令の Flags Affected）。
    let old: B::V<W32> = b.get(eflags_ref());
    let zw = b.konst::<W>(W::from_u128(0));
    let ow = b.konst::<W>(W::from_u128(1));
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
        Sh::Shr | Sh::Sar => {
            let s = b.shr_l::<W>(x, safe_c1);
            let m = b.and::<W>(s, ow);
            b.cmp::<W>(Cmp::Ne, m, zw)
        }
        Sh::Rol | Sh::Rcl => {
            let m = b.and::<W>(v, ow);
            b.cmp::<W>(Cmp::Ne, m, zw)
        }
        Sh::Ror | Sh::Rcr => {
            let t = b.shr_l::<W>(v, topk);
            let m = b.and::<W>(t, ow);
            b.cmp::<W>(Cmp::Ne, m, zw)
        }
    };
    let cf = pick(b, cf_take, sem::FLAG_CF);
    let v_top = b.shr_l::<W>(v, topk);
    let v_msb = b.and::<W>(v_top, ow);
    let of_take: B::B = match op {
        Sh::Shl | Sh::Rol | Sh::Rcl => {
            let cfv = b.select::<W>(cf_take, ow, zw);
            let x = b.xor::<W>(v_msb, cfv);
            b.cmp::<W>(Cmp::Ne, x, zw)
        }
        Sh::Shr => {
            let t = b.shr_l::<W>(x, topk);
            let m = b.and::<W>(t, ow);
            b.cmp::<W>(Cmp::Ne, m, zw)
        }
        Sh::Sar => {
            let m = b.and::<W>(v_msb, zw);
            b.cmp::<W>(Cmp::Ne, m, zw)
        }
        Sh::Ror | Sh::Rcr => {
            let k2 = b.konst::<W>(W::from_u128(u128::from(bits - 2)));
            let t2 = b.shr_l::<W>(v, k2);
            let x = b.xor::<W>(v_top, t2);
            let m = b.and::<W>(x, ow);
            b.cmp::<W>(Cmp::Ne, m, zw)
        }
    };
    let of_new = pick(b, of_take, sem::FLAG_OF);
    let of_mask = b.konst::<W32>(sem::FLAG_OF);
    let old_of = b.and::<W32>(old, of_mask);
    let n32: B::V<W32> = b.trunc::<W, W32>(n);
    let one32 = b.konst::<W32>(1);
    let is_one = b.cmp::<W32>(Cmp::Eq, n32, one32);
    let of = b.select::<W32>(is_one, of_new, old_of);
    // シフト系は SZP を更新するが、回転系（ROL/ROR/RCL/RCR）は
    // SF/ZF/PF を変えない（SDM: CF と OF のみ）。
    let szp = if matches!(op, Sh::Rol | Sh::Ror | Sh::Rcl | Sh::Rcr) {
        let m = b.konst::<W32>(sem::FLAG_SF | sem::FLAG_ZF | sem::FLAG_PF);
        b.and::<W32>(old, m)
    } else {
        szp_bits(b, v)
    };
    let clear = b.konst::<W32>(!sem::FLAG_OSZPC);
    let mut nf = b.and::<W32>(old, clear);
    nf = b.or::<W32>(nf, cf);
    nf = b.or::<W32>(nf, of);
    nf = b.or::<W32>(nf, szp);
    let zero32 = b.konst::<W32>(0);
    let active32 = b.cmp::<W32>(Cmp::Ne, n32, zero32);
    let assembled = b.select::<W32>(active32, nf, old);
    b.set(eflags_ref(), assembled);
    Ok(())
}

// ---- PUSH/POP ----

/// PUSH r/m（v は値幅。スタックは osize 幅）。
pub fn push_v<B: Backend>(b: &mut B, w: u8, v64: B::V<W64>) -> Flow<B> {
    let sp = Gpr(4);
    match w {
        16 => {
            let sz = b.konst::<W32>(2);
            let cur: B::V<W32> = b.get(sp.state());
            let np = b.sub::<W32>(cur, sz);
            b.set(sp.state(), np);
            let a = b.zext::<W32, W64>(np);
            let v: B::V<W16> = b.trunc::<W64, W16>(v64);
            b.store::<W16>(a, v, sem::DATA_WRITE)
        }
        64 => {
            let sz = b.konst::<W64>(8);
            let cur = sem::read64(b, sp);
            let np = b.sub::<W64>(cur, sz);
            sem::write64(b, sp, np);
            b.store::<W64>(np, v64, sem::DATA_WRITE)
        }
        _ => {
            let sz = b.konst::<W32>(4);
            let cur: B::V<W32> = b.get(sp.state());
            let np = b.sub::<W32>(cur, sz);
            b.set(sp.state(), np);
            let a = b.zext::<W32, W64>(np);
            let v: B::V<W32> = b.trunc::<W64, W32>(v64);
            b.store::<W32>(a, v, sem::DATA_WRITE)
        }
    }
}

/// POP → 値幅 w で返す。
pub fn pop_v<B: Backend>(b: &mut B, w: u8) -> Result<B::V<W64>, B::Exit> {
    let sp = Gpr(4);
    match w {
        16 => {
            let cur: B::V<W32> = b.get(sp.state());
            let a = b.zext::<W32, W64>(cur);
            let v = b.load::<W16>(a, sem::DATA_READ)?;
            let sz = b.konst::<W32>(2);
            let np = b.add::<W32>(cur, sz);
            b.set(sp.state(), np);
            Ok(b.zext::<W16, W64>(v))
        }
        64 => {
            let cur = sem::read64(b, sp);
            let v = b.load::<W64>(cur, sem::DATA_READ)?;
            let sz = b.konst::<W64>(8);
            let np = b.add::<W64>(cur, sz);
            sem::write64(b, sp, np);
            Ok(v)
        }
        _ => {
            let cur: B::V<W32> = b.get(sp.state());
            let a = b.zext::<W32, W64>(cur);
            let v = b.load::<W32>(a, sem::DATA_READ)?;
            let sz = b.konst::<W32>(4);
            let np = b.add::<W32>(cur, sz);
            b.set(sp.state(), np);
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
pub fn call_rel<B: Backend>(b: &mut B, eip: u32, len: u32, rel: i64, stack_w: u8) -> Flow<B> {
    let next = eip.wrapping_add(len);
    let nv = b.konst::<W64>(u64::from(next));
    push_v(b, stack_w, nv)?;
    jmp_rel(b, eip, len, rel)
}

/// CALL r/m。
pub fn call_rm<B: Backend>(
    b: &mut B,
    w: u8,
    rm: &Rm<B::V<W64>>,
    d: &MapDec,
    eip: u32,
    len: u32,
) -> Flow<B> {
    let next = eip.wrapping_add(len);
    let t = rd_any::<B>(b, w, rm, d)?;
    let nv = b.konst::<W64>(u64::from(next));
    push_v(b, w, nv)?;
    let t32: B::V<W32> = b.trunc::<W64, W32>(t);
    b.set(eip_ref(), t32);
    b.jump(t);
    Ok(())
}

/// RET。pop で戻る。iw は積み増し。
pub fn ret<B: Backend>(b: &mut B, w: u8, iw: u16) -> Flow<B> {
    let v = pop_v(b, w)?;
    if iw != 0 {
        let sp = Gpr(4);
        match w {
            64 => {
                let cur = sem::read64(b, sp);
                let k = b.konst::<W64>(u64::from(iw));
                let np = b.add::<W64>(cur, k);
                sem::write64(b, sp, np);
            }
            _ => {
                let cur: B::V<W32> = b.get(sp.state());
                let k = b.konst::<W32>(u32::from(iw));
                let np = b.add::<W32>(cur, k);
                b.set(sp.state(), np);
            }
        }
    }
    let t32: B::V<W32> = b.trunc::<W64, W32>(v);
    b.set(eip_ref(), t32);
    b.jump(v);
    Ok(())
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
    let ah = sem::read8(b, Gpr(4), true);
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
    sem::write8(b, Gpr(4), true, v);
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
pub fn enter<B: Backend>(b: &mut B, w: u8, frame: u64, level: u64) -> Flow<B> {
    let lvl = level & 31;
    let m: u64 = if w == 16 { 0xffff } else { 0xffff_ffff };
    let mm = b.konst::<W64>(m);
    let bp = sem::read64(b, Gpr(5));
    let bp = b.and::<W64>(bp, mm);
    push_v(b, w, bp)?;
    let sp0 = sem::read64(b, Gpr(4));
    let sp0 = b.and::<W64>(sp0, mm);
    let bytes = b.konst::<W64>(u64::from(w / 8));
    if lvl > 0 {
        let mut p = sp0;
        for _ in 1..lvl {
            let pv = b.sub::<W64>(p, bytes);
            p = b.and::<W64>(pv, mm);
            let v = b.load::<W64>(p, sem::DATA_READ)?;
            let vm = b.and::<W64>(v, mm);
            push_v(b, w, vm)?;
        }
        push_v(b, w, sp0)?;
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
