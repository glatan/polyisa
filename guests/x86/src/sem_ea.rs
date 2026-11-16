// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! オペコード表経路の意味論。被演算子を `Rm`（レジスタ直接 or
//! 実効アドレス）と幅で受け、アドレス形ごとの直積を避ける。
//!
//! Ref: SPEC-X86-INTEL-SDM (v093) Vol.2.

use polyisa_sem::{Backend, Cmp, Flow, W8, W16, W32, W64, W128};

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

fn str_w<B: Backend, W: Hw>(
    b: &mut B,
    kind: Str,
    d: &MapDec,
    eip: u32,
    seg: u64,
    rep: bool,
    zf_cond: u8,
) -> Flow<B> {
    let asize = d.asize;
    let mut si = sptr(b, Gpr(6), asize);
    let sg = b.konst::<W64>(seg);
    si = b.add::<W64>(si, sg);
    let di = sptr(b, Gpr(7), asize);
    let sz = u64::from(W::BITS / 8);
    match kind {
        Str::Movs => {
            let v: B::V<W> = b.load::<W>(si, sem::DATA_READ)?;
            b.store::<W>(di, v, sem::DATA_WRITE)?;
            str_bump(b, Gpr(6), asize, sz);
            str_bump(b, Gpr(7), asize, sz);
        }
        Str::Stos => {
            let acc = W::get(b, Gpr(0), d);
            b.store::<W>(di, acc, sem::DATA_WRITE)?;
            str_bump(b, Gpr(7), asize, sz);
        }
        Str::Lods => {
            let v: B::V<W> = b.load::<W>(si, sem::DATA_READ)?;
            W::put(b, Gpr(0), d, v);
            str_bump(b, Gpr(6), asize, sz);
        }
        Str::Scas => {
            let acc = W::get(b, Gpr(0), d);
            let t: B::V<W> = b.load::<W>(di, sem::DATA_READ)?;
            let v = b.sub::<W>(acc, t);
            update_sub_flags(b, acc, t, v);
            str_bump(b, Gpr(7), asize, sz);
        }
        Str::Cmps => {
            let x: B::V<W> = b.load::<W>(si, sem::DATA_READ)?;
            let t: B::V<W> = b.load::<W>(di, sem::DATA_READ)?;
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
pub fn str_op<B: Backend>(b: &mut B, kind: Str, w: u8, d: &MapDec, eip: u32, seg: u64) -> Flow<B> {
    let rep = d.rep != 0;
    // REPE/REPNE の ZF 条件は SCAS/CMPS にだけ効く。
    let zf_cond = match kind {
        Str::Scas | Str::Cmps if d.rep == 0xF3 => 1,
        Str::Scas | Str::Cmps if d.rep == 0xF2 => 2,
        _ => 0,
    };
    let iter = |b: &mut B| -> Flow<B> {
        match w {
            16 => str_w::<B, W16>(b, kind, d, eip, seg, rep, zf_cond),
            64 => str_w::<B, W64>(b, kind, d, eip, seg, rep, zf_cond),
            8 => str_w::<B, W8>(b, kind, d, eip, seg, rep, zf_cond),
            _ => str_w::<B, W32>(b, kind, d, eip, seg, rep, zf_cond),
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
    match w {
        8 => {
            let v: B::V<W8> = b.load::<W8>(addr, sem::DATA_READ)?;
            W8::put(b, Gpr(0), d, v);
        }
        16 => {
            let v: B::V<W16> = b.load::<W16>(addr, sem::DATA_READ)?;
            W16::put(b, Gpr(0), d, v);
        }
        64 => {
            let v: B::V<W64> = b.load::<W64>(addr, sem::DATA_READ)?;
            W64::put(b, Gpr(0), d, v);
        }
        _ => {
            let v: B::V<W32> = b.load::<W32>(addr, sem::DATA_READ)?;
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
    match w {
        8 => {
            let v = W8::get(b, Gpr(0), d);
            b.store::<W8>(addr, v, sem::DATA_WRITE)?;
        }
        16 => {
            let v = W16::get(b, Gpr(0), d);
            b.store::<W16>(addr, v, sem::DATA_WRITE)?;
        }
        64 => {
            let v = W64::get(b, Gpr(0), d);
            b.store::<W64>(addr, v, sem::DATA_WRITE)?;
        }
        _ => {
            let v = W32::get(b, Gpr(0), d);
            b.store::<W32>(addr, v, sem::DATA_WRITE)?;
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
    let target = if let Rm::Mem(a) = ea {
        let ob = b.shl::<W64>(off, bs);
        let na = b.add::<W64>(*a, ob);
        e2 = Rm::Mem(na);
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
        Rm::Mem(a) => {
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
        Rm::Mem(a) => {
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

/// MOVLPS/MOVLPD の読み込み（0F 12）。mem は下位 64 を読み込み、
/// mod=11 は MOVLHPS（0x66 なし）または MOVHLPS（0x66 あり）。
/// F3 は MOVSLDUP、F2 は MOVDDUP。
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
    if d.modrm >= 0xC0 {
        let s = rx(b, ea, 128)?;
        let old: B::V<W128> = b.get(sem::xmm_ref(dst));
        let v = if d.p66 {
            // MOVHLPS: dst.lo = src.hi
            let hi = lane128(b, s, 64, 64);
            put_lane128(b, old, hi, 0, 64)
        } else {
            // MOVLHPS: dst.hi = src.lo
            put_lane128(b, old, s, 64, 64)
        };
        b.set(sem::xmm_ref(dst), v);
    } else {
        let s = rx(b, ea, 64)?;
        let old: B::V<W128> = b.get(sem::xmm_ref(dst));
        let v = put_lane128(b, old, s, 0, 64);
        b.set(sem::xmm_ref(dst), v);
    }
    Ok(())
}

/// MOVLPS/MOVLPD の書き込み（0F 13）。下位 64 を書く。
pub fn movl_st<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let s: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    let lo = lane128(b, s, 0, 64);
    wx(b, ea, 64, lo)
}

/// MOVHPS/MOVHPD の読み込み（0F 16）。mem は上位 64 を読み込み、
/// mod=11 は MOVHLPS（dst.lo = src.hi）。F3 は MOVSHDUP。
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
    if d.modrm >= 0xC0 {
        // MOVHLPS: dst.lo = src.hi
        let s = rx(b, ea, 128)?;
        let hi = lane128(b, s, 64, 64);
        let old: B::V<W128> = b.get(sem::xmm_ref(dst));
        let v = put_lane128(b, old, hi, 0, 64);
        b.set(sem::xmm_ref(dst), v);
    } else {
        let s = rx(b, ea, 64)?;
        let old: B::V<W128> = b.get(sem::xmm_ref(dst));
        let v = put_lane128(b, old, s, 64, 64);
        b.set(sem::xmm_ref(dst), v);
    }
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

pub fn pint<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    kind: Iop,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    lane_bin::<B, W>(b, d, ea, |b, a, c| match kind {
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
    })
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
        Rm::Mem(a) => {
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
        Rm::Mem(a) => {
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
    if let Rm::Mem(a) = ea {
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
    if let Rm::Mem(a) = ea {
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
    if let Rm::Mem(a) = ea {
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
    if let Rm::Mem(a) = ea {
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
    if let Rm::Mem(a) = ea {
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
    if let Rm::Mem(a) = ea {
        let v: B::V<W16> = b.load::<W16>(*a, sem::DATA_READ)?;
        b.set(sem::fcw_ref(), v);
    }
    Ok(())
}

/// FNSTCW m16。
pub fn fnstcw_m<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    if let Rm::Mem(a) = ea {
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
pub fn push_sr<B: Backend>(b: &mut B, s: u8, sw: u8) -> Flow<B> {
    let v: B::V<W16> = b.get(sem::sreg_ref(s));
    let v64 = b.zext::<W16, W64>(v);
    push_v(b, sw, v64)
}

/// POP sreg。スタック幅で取り出し下位 16 ビットをセレクタへ書く
/// （ベースは変えない。`mov_sr_ld` の注記を参照）。
pub fn pop_sr<B: Backend>(b: &mut B, s: u8, sw: u8) -> Flow<B> {
    let v = pop_v(b, sw)?;
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
/// CF/OF は上位半分が意味を持つとき 1（他旗は不定のため保存）。
pub fn mulx<B: Backend>(b: &mut B, w: u8, d: &MapDec, ea: &Rm<B::V<W64>>, signed: bool) -> Flow<B> {
    match w {
        8 => mulx8(b, d, ea, signed),
        16 => mulx_w::<B, W16, W32>(b, d, ea, signed),
        64 => mulx_w::<B, W64, W128>(b, d, ea, signed),
        _ => mulx_w::<B, W32, W64>(b, d, ea, signed),
    }
}

/// CF/OF を `c` で更新する。
fn set_cof<B: Backend>(b: &mut B, c: B::B) {
    let old: B::V<W32> = b.get(eflags_ref());
    let mask = b.konst::<W32>(!(sem::FLAG_CF | sem::FLAG_OF));
    let cleared = b.and::<W32>(old, mask);
    let cf = pick(b, c, sem::FLAG_CF);
    let of = pick(b, c, sem::FLAG_OF);
    let both = b.or::<W32>(cf, of);
    let efl = b.or::<W32>(cleared, both);
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
    let zro = b.konst::<W16>(0);
    let cof = if signed {
        // hi が lo（AL）の符号拡張と一致するか。
        let lo: B::V<W8> = b.trunc::<W16, W8>(p);
        let z8 = b.konst::<W8>(0);
        let neg = b.cmp::<W8>(Cmp::LtS, lo, z8);
        let all = b.konst::<W16>(0xFF);
        let exp = b.select::<W16>(neg, all, zro);
        b.cmp::<W16>(Cmp::Ne, hi, exp)
    } else {
        b.cmp::<W16>(Cmp::Ne, hi, zro)
    };
    set_cof(b, cof);
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
    let zro = b.konst::<W>(W::from_u128(0));
    let cof = if signed {
        let neg = b.cmp::<W>(Cmp::LtS, lo, zro);
        let all = b.konst::<W>(W::from_u128((1u128 << W::BITS) - 1));
        let exp = b.select::<W>(neg, all, zro);
        b.cmp::<W>(Cmp::Ne, hi, exp)
    } else {
        b.cmp::<W>(Cmp::Ne, hi, zro)
    };
    set_cof(b, cof);
    Ok(())
}

/// DIV/IDIV r/m。0 除算・商あふれは #DE 相当の DivZero で退出する。
/// フラグは不定なので変えない。
pub fn divx<B: Backend>(
    b: &mut B,
    w: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
    eip: u32,
    signed: bool,
) -> Flow<B> {
    match w {
        8 => divx8(b, d, ea, eip, signed),
        16 => divx_w::<B, W16, W32>(b, d, ea, eip, signed),
        64 => divx_w::<B, W64, W128>(b, d, ea, eip, signed),
        _ => divx_w::<B, W32, W64>(b, d, ea, eip, signed),
    }
}

/// DIV/IDIV r/m8。被除数は AX、商を AL・剰余を AH に置く。
fn divx8<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>, eip: u32, signed: bool) -> Flow<B> {
    let ax32: B::V<W32> = b.get(Gpr(0).state());
    let ax: B::V<W16> = b.trunc::<W32, W16>(ax32);
    let y = rd_w::<B, W8>(b, ea, d)?;
    let (dvd, dvs) = if signed {
        (b.sext::<W16, W32>(ax), b.sext::<W8, W32>(y))
    } else {
        (b.zext::<W16, W32>(ax), b.zext::<W8, W32>(y))
    };
    let zero = b.konst::<W32>(0);
    let is_zero = b.cmp::<W32>(Cmp::Eq, dvs, zero);
    b.if_then(is_zero, |b| Err(sem::div0(b, eip)))?;
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
    b.if_then(over, |b| Err(sem::div0(b, eip)))?;
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

fn divx_w<B: Backend, W: Hw, W2: polyisa_sem::Width>(
    b: &mut B,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
    eip: u32,
    signed: bool,
) -> Flow<B> {
    let lo = W::get(b, Gpr(0), d);
    let hi = W::get(b, Gpr(2), d);
    let y = rd_w::<B, W>(b, ea, d)?;
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
    let zero = b.konst::<W2>(W2::from_u128(0));
    let is_zero = b.cmp::<W2>(Cmp::Eq, yw, zero);
    b.if_then(is_zero, |b| Err(sem::div0(b, eip)))?;
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
    b.if_then(over, |b| Err(sem::div0(b, eip)))?;
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
        Rm::Mem(a) => {
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
    let Rm::Mem(a) = ea else {
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
    let Rm::Mem(a) = ea else {
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
    let Rm::Mem(a) = ea else {
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
    let Rm::Mem(a) = ea else {
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
