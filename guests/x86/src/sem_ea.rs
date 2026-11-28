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
    self, FLAG_CF, FLAG_OF, FLAG_PF, FLAG_SF, FLAG_ZF, Gpr, eflags_ref, eip_ref, read_cf, read_of,
    read_pf, read_sf, read_zf, update_add_flags, update_addc_flags, update_logic_flags,
    update_sub_flags, update_subb_flags,
};
use crate::sem::{pf_bit, pick, szp_bits};

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
    if !d.nf {
        alu_flags::<B, W>(b, op, x, y, c, v);
    }
    if !matches!(op, Alu::Cmp) {
        wr_dst::<B, W>(b, rm, d, v)?;
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

/// NDD/ZU 宛先への書き込み。幅にかかわらずレジスタ全体へ書く
/// （8/16 ビット形でも上位はゼロ拡張。APX の NDD は常に
/// zero-upper）。
fn put_ndd<B: Backend, W: Hw>(b: &mut B, g: Gpr, v: B::V<W>) {
    let v64 = b.zext::<W, W64>(v);
    sem::write64(b, g, v64);
}

/// 宛先オペランドへの書き戻し。APX の NDD では vvvv レジスタへ
/// 書き、通常形は被演算子自身へ書く。
fn wr_dst<B: Backend, W: Hw>(
    b: &mut B,
    rm: &Rm<B::V<W64>>,
    d: &MapDec,
    v: B::V<W>,
) -> Result<(), B::Exit> {
    if d.ndd {
        put_ndd::<B, W>(b, Gpr(d.vex_v), v);
        Ok(())
    } else {
        wr_w::<B, W>(b, rm, d, v)
    }
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

/// CCMPscc/CTESTscc の source condition。1010/1011 は PF/NP ではなく
/// 常に真/偽になる。
fn cc_nci<B: Backend>(b: &mut B, n: u8) -> B::B {
    match n {
        0xA => bool_k(b, true),
        0xB => bool_k(b, false),
        _ => cc(b, n),
    }
}

/// NCI エンコードの dfv（物理 vvvv ビット）と scc（物理 V'/aaa ビット）。
/// `MapDec::vex_v` はレジスタ番号用に反転済みなので、ここでは元の
/// ペイロード値へ戻す。
fn nci_fields(d: &MapDec) -> (u8, u8) {
    let dfv = (!d.vex_v) & 0xF;
    let sc3 = (!((d.vex_v >> 4) & 1)) & 1;
    let scc = (sc3 << 3) | (d.evex_aaa & 7);
    (dfv, scc)
}

fn dfv_flags(dfv: u8) -> u32 {
    let cf = u32::from(dfv & 1);
    let zf = u32::from((dfv >> 1) & 1);
    let sf = u32::from((dfv >> 2) & 1);
    let of = u32::from((dfv >> 3) & 1);
    cf * FLAG_CF + zf * FLAG_ZF + sf * FLAG_SF + of * FLAG_OF + cf * FLAG_PF
}

/// 条件が真なら通常の CMP/TEST の旗、偽なら dfv の旗を選ぶ。
/// 被演算子は条件に関係なく先に読む（メモリは偽でも読み、フォールトする）。
fn nci_select_flags<B: Backend>(b: &mut B, old: B::V<W32>, cond: B::B, dfv: u8) {
    let new = b.get(eflags_ref());
    let ones = b.konst::<W32>(u32::MAX);
    let zero = b.konst::<W32>(0);
    let cm = b.select::<W32>(cond, ones, zero);
    let ncm = b.not::<W32>(cm);
    let mask = b.konst::<W32>(sem::FLAG_OSZPCA);
    let def = b.konst::<W32>(dfv_flags(dfv));
    let cm_mask = b.and::<W32>(cm, mask);
    let new_part = b.and::<W32>(new, cm_mask);
    let ncm_mask = b.and::<W32>(ncm, mask);
    let def_part = b.and::<W32>(def, ncm_mask);
    let nmask = b.not::<W32>(mask);
    let rest = b.and::<W32>(old, nmask);
    let chosen = b.or::<W32>(new_part, def_part);
    let merged = b.or::<W32>(chosen, rest);
    b.set(eflags_ref(), merged);
}

/// CCMPscc。条件が真なら CMP、偽なら dfv を旗へ写す。
pub fn ccmp<'a, B: Backend>(
    b: &mut B,
    w: u8,
    rm: &Rm<B::V<W64>>,
    d: &MapDec,
    src: Src<'a, B::V<W64>>,
) -> Flow<B> {
    match w {
        8 => ccmp_w::<B, W8>(b, rm, d, src),
        16 => ccmp_w::<B, W16>(b, rm, d, src),
        32 => ccmp_w::<B, W32>(b, rm, d, src),
        _ => ccmp_w::<B, W64>(b, rm, d, src),
    }
}

fn ccmp_w<'a, B: Backend, W: Hw>(
    b: &mut B,
    rm: &Rm<B::V<W64>>,
    d: &MapDec,
    src: Src<'a, B::V<W64>>,
) -> Flow<B> {
    let (dfv, scc) = nci_fields(d);
    let cond = cc_nci(b, scc);
    let old = b.get(eflags_ref());
    let x = rd_w::<B, W>(b, rm, d)?;
    let y = match src {
        Src::Reg(g) => grd_w::<B, W>(b, g, d),
        Src::Imm(i) => b.konst::<W>(W::from_u128(u128::from(i))),
        Src::Ea(e) => rd_w::<B, W>(b, e, d)?,
    };
    let v = b.sub::<W>(x, y);
    update_sub_flags(b, x, y, v);
    nci_select_flags(b, old, cond, dfv);
    Ok(())
}

/// CTESTscc。条件が真なら TEST、偽なら dfv を旗へ写す。
pub fn ctest<'a, B: Backend>(
    b: &mut B,
    w: u8,
    rm: &Rm<B::V<W64>>,
    d: &MapDec,
    src: Src<'a, B::V<W64>>,
) -> Flow<B> {
    match w {
        8 => ctest_w::<B, W8>(b, rm, d, src),
        16 => ctest_w::<B, W16>(b, rm, d, src),
        32 => ctest_w::<B, W32>(b, rm, d, src),
        _ => ctest_w::<B, W64>(b, rm, d, src),
    }
}

fn ctest_w<'a, B: Backend, W: Hw>(
    b: &mut B,
    rm: &Rm<B::V<W64>>,
    d: &MapDec,
    src: Src<'a, B::V<W64>>,
) -> Flow<B> {
    let (dfv, scc) = nci_fields(d);
    let cond = cc_nci(b, scc);
    let old = b.get(eflags_ref());
    let x = rd_w::<B, W>(b, rm, d)?;
    let y = match src {
        Src::Reg(g) => grd_w::<B, W>(b, g, d),
        Src::Imm(i) => b.konst::<W>(W::from_u128(u128::from(i))),
        Src::Ea(e) => rd_w::<B, W>(b, e, d)?,
    };
    let v = b.and::<W>(x, y);
    update_logic_flags(b, v);
    nci_select_flags(b, old, cond, dfv);
    Ok(())
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
    wr_dst::<B, W>(b, rm, d, v)?;
    if d.nf {
        return Ok(());
    }
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
                wr_dst::<B, W8>(b, rm, d, v)
            }
        }
        16 => {
            let x = rd_w::<B, W16>(b, rm, d)?;
            {
                let v = b.not::<W16>(x);
                wr_dst::<B, W16>(b, rm, d, v)
            }
        }
        32 => {
            let x = rd_w::<B, W32>(b, rm, d)?;
            {
                let v = b.not::<W32>(x);
                wr_dst::<B, W32>(b, rm, d, v)
            }
        }
        _ => {
            let x = rd_w::<B, W64>(b, rm, d)?;
            {
                let v = b.not::<W64>(x);
                wr_dst::<B, W64>(b, rm, d, v)
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
    wr_dst::<B, W>(b, rm, d, v)?;
    // NEG は 0-x の減算と同じ旗。CF は x!=0 のとき立つ（0 からの
    // 借りがちょうどその条件）。
    if !d.nf {
        update_sub_flags(b, z, x, v);
    }
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
    _m16: bool,
) -> Flow<B> {
    // CL のマスクは挙動パラメータ `shift_count`。full は 8086/8088
    // （回数をそのまま反復）、masked は 286 以降の 31/63。
    let mask: u64 = if W::BITS == 64 { 63 } else { 31 };
    let full = b.param::<crate::ShiftCountParam>() == crate::SHIFT_COUNT_FULL;
    let n = match cnt {
        ShiftCnt::Imm(i) => b.konst::<W>(W::from_u128(u128::from(i & mask as u32))),
        ShiftCnt::One => b.konst::<W>(W::from_u128(1)),
        ShiftCnt::Cl => {
            let cl = sem::read8(b, Gpr(1), false);
            let cl: B::V<W32> = b.zext::<W8, W32>(cl);
            let m = b.konst::<W32>(if full { 0xFF } else { mask as u32 });
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
    wr_dst::<B, W>(b, rm, d, v)?;
    if d.nf {
        return Ok(());
    }
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
    // 80386: バイトシフトで回数が 8 を超えるとき、回数が 8 の倍数
    //（16/24）なら CF に被演算子バイトの端ビットが残る。メモリ
    // 被演算子はアライメント済みワードで読まれるが、端ビットは
    // 被演算子バイト自身から取られる（SST 80386 実測）。
    let cf_take = if W::BITS == 8
        && matches!(op, Sh::Shl | Sh::Shr)
        && b.param::<crate::Shift8OverParam>() == crate::SHIFT8_OVER_EDGE
    {
        let ebit = if matches!(op, Sh::Shl) {
            b.and::<W>(x, ow)
        } else {
            let s = b.shr_l::<W>(x, topk);
            b.and::<W>(s, ow)
        };
        let edgeb = b.cmp::<W>(Cmp::Ne, ebit, zw);
        let eight = b.konst::<W>(W::from_u128(8));
        let gt8 = b.cmp::<W>(Cmp::LtU, eight, n);
        let seven = b.konst::<W>(W::from_u128(7));
        let m8 = b.and::<W>(n, seven);
        let m8z = b.cmp::<W>(Cmp::Ne, m8, zw);
        let m8z = bnot(b, m8z);
        let apply = band(b, gt8, m8z);
        let napp = bnot(b, apply);
        let keep = band(b, napp, cf_take);
        let take = band(b, apply, edgeb);
        bor(b, keep, take)
    } else {
        cf_take
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
    // sa==16 では SP の更新をストアの後に遅らせる（限界例外で SP が
    // 変わらないようにするため）。
    let (a, np16, off) = match sa {
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
            let off = b.zext::<W32, W64>(lo);
            (b.add::<W64>(off, sg), Some(np), off)
        }
        64 => {
            let k = b.konst::<W64>(sz);
            let cur = sem::read64(b, sp);
            let np = b.sub::<W64>(cur, k);
            sem::write64(b, sp, np);
            (b.add::<W64>(np, sg), None, np)
        }
        _ => {
            let k = b.konst::<W32>(sz as u32);
            let cur: B::V<W32> = b.get(sp.state());
            let np = b.sub::<W32>(cur, k);
            b.set(sp.state(), np);
            let off = b.zext::<W32, W64>(np);
            (b.add::<W64>(off, sg), None, off)
        }
    };
    // 80386 のスタック書き込みも折り返したオフセットの跨ぎで
    // #SS になる（PUSHAD の逐次 push が 0xFFFE の双語で例外になる
    // SST 80386 実測）。折り返しそのものはアクセス側が行う。
    // 第 2 要素はオフセットの生値（SP は 16 ビット幅なので
    // 桁上げは起きない）。
    let wseg = (sa == 16).then_some((sseg | decode::WSEG_SS, off));
    match w {
        16 => {
            let v: B::V<W16> = b.trunc::<W64, W16>(v64);
            decode::mem_store(b, a, wseg, v)?
        }
        64 => decode::mem_store::<B, W64>(b, a, wseg, v64)?,
        _ => {
            let v: B::V<W32> = b.trunc::<W64, W32>(v64);
            decode::mem_store(b, a, wseg, v)?
        }
    }
    if let Some(np) = np16 {
        b.set(sp.state(), np);
    }
    Ok(())
}

/// PUSHA/POPA のようにスタックへ `n` 語連続アクセスする命令の限界
/// 事前検査。80286 実測では系列中のいずれかのアクセスが限界に触れる
/// とアクセス前の部分副作用は残らない（ENTER のように push を
/// 逐次コミットする命令とは異なり不可分）。`pop` なら SP から
/// +2k 目（k=0..n-1）、そうでなければ -2k 目（k=1..n）のオフセットを
/// 検査する。
pub fn stack_span_chk<B: Backend>(
    b: &mut B,
    w: u8,
    n: u32,
    pop: bool,
    sa: u8,
    sseg: u64,
) -> Flow<B> {
    // 80386 系（`fault_atomic` = ATOMIC）の PUSHA は各書き込みを
    // 個別に検査しながら逐次コミットするのでここでは検査しない
    // （POPA 側はこの関数を呼ばず、読み込みを個別に検査する）。
    if sa != 16 || (!pop && b.param::<crate::FaultAtomicParam>() == crate::FAULT_ATOMIC_ATOMIC) {
        return Ok(());
    }
    let sp = Gpr(4);
    let cur: B::V<W32> = b.get(sp.state());
    let m16 = b.konst::<W32>(0xFFFF);
    let lo = b.and::<W32>(cur, m16);
    let lo64 = b.zext::<W32, W64>(lo);
    let lim = b.konst::<W64>(0xFFFF);
    let wseg = sseg | decode::WSEG_SS;
    let sz = u64::from(w / 8);
    for k in 0..n {
        let kk = b.konst::<W64>(u64::from(if pop { k } else { k + 1 }) * sz);
        let o = if pop {
            b.add::<W64>(lo64, kk)
        } else {
            b.sub::<W64>(lo64, kk)
        };
        // SP は 16 ビット幅なのでオフセットは 64K で折る。
        let off = b.and::<W64>(o, lim);
        match w {
            16 => decode::seg_limit_chk::<B, W16>(b, off, wseg)?,
            64 => decode::seg_limit_chk::<B, W64>(b, off, wseg)?,
            _ => decode::seg_limit_chk::<B, W32>(b, off, wseg)?,
        }
    }
    Ok(())
}

/// PUSHA/PUSHAD。`w` はオペランドサイズ。80286 系では系列中の
/// いずれかの限界違反で全書き込みが無効になる不可分検査
/// （`stack_span_chk`）。80386 系では書き込みは低位番地
/// （EDI 側）から昇順に行われ、各書き込みは個別に限界検査
/// される。違反時はそこまでの書き込みが残り、SP は命令前の
/// 値のままになる（SST 80386 実測）。
pub fn pusha<B: Backend>(b: &mut B, w: u8, sa: u8, sseg: u64) -> Flow<B> {
    if sa == 16 && b.param::<crate::FaultAtomicParam>() == crate::FAULT_ATOMIC_ATOMIC {
        let sz = u64::from(w / 8);
        let m = b.konst::<W64>(0xFFFF);
        let nm = b.konst::<W64>(!0xFFFFu64);
        let sg = b.konst::<W64>(sseg);
        let wseg = sseg | decode::WSEG_SS;
        let cur = sem::read64(b, Gpr(4));
        let total = b.konst::<W64>(sz * 8);
        let base0 = b.sub::<W64>(cur, total);
        let base = b.and::<W64>(base0, m);
        // 格納順は EDI, ESI, EBP, 元の ESP, EBX, EDX, ECX, EAX。
        for (k, g) in [7u8, 6, 5, 4, 3, 2, 1, 0].iter().enumerate() {
            let kk = b.konst::<W64>(k as u64 * sz);
            let o = b.add::<W64>(base, kk);
            let off = b.and::<W64>(o, m);
            let a = b.add::<W64>(off, sg);
            let ws = Some((wseg, off));
            let v64 = if *g == 4 {
                cur
            } else {
                sem::read64(b, Gpr(*g))
            };
            match w {
                16 => {
                    let v: B::V<W16> = b.trunc::<W64, W16>(v64);
                    decode::mem_store(b, a, ws, v)?;
                }
                _ => {
                    let v: B::V<W32> = b.trunc::<W64, W32>(v64);
                    decode::mem_store(b, a, ws, v)?;
                }
            }
        }
        // 全書き込みの成功後に SP の下位 16 ビットだけを更新する。
        let nsp = b.sub::<W64>(cur, total);
        let lo = b.and::<W64>(nsp, m);
        let hi = b.and::<W64>(cur, nm);
        let np = b.or::<W64>(hi, lo);
        sem::write64(b, Gpr(4), np);
        return Ok(());
    }
    // EAX, ECX, EDX, EBX, 元の ESP, EBP, ESI, EDI の順。
    // ESP 枠は命令実行前の値なので push 前に採取する。
    stack_span_chk(b, w, 8, false, sa, sseg)?;
    let sp0 = sem::read64(b, Gpr(4));
    for g in 0..4u8 {
        let v = sem::read64(b, Gpr(g));
        push_v(b, w, v, sa, sseg)?;
    }
    push_v(b, w, sp0, sa, sseg)?;
    for g in 5..8u8 {
        let v = sem::read64(b, Gpr(g));
        push_v(b, w, v, sa, sseg)?;
    }
    Ok(())
}

/// POPA/POPAD。`w` はオペランドサイズ。80286 系では読み込み系列を
/// 不可分に事前検査する（違反時はレジスタ・SP を一切更新しない）。
/// 80386 系では各 pop の読み込みが個別に限界検査され、成功した
/// 分のレジスタはコミットされるが SP は最後の pop が成功するまで
/// 更新されない（SST 80386 実測）。
pub fn popa<B: Backend>(b: &mut B, w: u8, sa: u8, sseg: u64) -> Flow<B> {
    if sa == 16 && b.param::<crate::FaultAtomicParam>() == crate::FAULT_ATOMIC_ATOMIC {
        let sz = u64::from(w / 8);
        let m = b.konst::<W64>(0xFFFF);
        let nm = b.konst::<W64>(!0xFFFFu64);
        let sg = b.konst::<W64>(sseg);
        let wseg = sseg | decode::WSEG_SS;
        let cur = sem::read64(b, Gpr(4));
        // 読み出し順は EDI, ESI, EBP, ESP(捨てる), EBX, EDX, ECX, EAX。
        let mut esp_hi: Option<B::V<W64>> = None;
        for (k, g) in [7u8, 6, 5, 4, 3, 2, 1, 0].iter().enumerate() {
            let kk = b.konst::<W64>(k as u64 * sz);
            let lo = b.and::<W64>(cur, m);
            let o = b.add::<W64>(lo, kk);
            let off = b.and::<W64>(o, m);
            let a = b.add::<W64>(off, sg);
            let ws = Some((wseg, off));
            let v = match w {
                16 => {
                    let v: B::V<W16> = decode::mem_load(b, a, ws)?;
                    b.zext::<W16, W64>(v)
                }
                _ => {
                    let v: B::V<W32> = decode::mem_load(b, a, ws)?;
                    b.zext::<W32, W64>(v)
                }
            };
            if *g == 4 {
                esp_hi = Some(v);
                continue;
            }
            match w {
                16 => {
                    let old = sem::read64(b, Gpr(*g));
                    let hi = b.and::<W64>(old, nm);
                    let nv = b.or::<W64>(hi, v);
                    sem::write64(b, Gpr(*g), nv);
                }
                _ => {
                    let v32: B::V<W32> = b.trunc::<W64, W32>(v);
                    b.set(Gpr(*g).state(), v32);
                }
            }
        }
        // 全読み出しの成功後に SP の下位 16 ビットだけを進める。
        // POPAD では ESP スロットの双語の上位 16 ビットが ESP の
        // 上位に載る（下位は SP+32 のまま。SST 80386 実測）。
        let total = b.konst::<W64>(sz * 8);
        let nsp = b.add::<W64>(cur, total);
        let lo = b.and::<W64>(nsp, m);
        let hi = match (w, esp_hi) {
            (32, Some(v)) => b.and::<W64>(v, nm),
            _ => b.and::<W64>(cur, nm),
        };
        let np = b.or::<W64>(hi, lo);
        sem::write64(b, Gpr(4), np);
        return Ok(());
    }
    // EDI, ESI, EBP, (ESP は捨てる), EBX, EDX, ECX, EAX。
    stack_span_chk(b, w, 8, true, sa, sseg)?;
    for g in [7u8, 6, 5, 4, 3, 2, 1, 0] {
        let v = pop_v(b, w, sa, sseg)?;
        if g == 4 {
            continue;
        }
        match w {
            16 => {
                let m = b.konst::<W64>(0xFFFF_0000);
                let old = sem::read64(b, Gpr(g));
                let hi = b.and::<W64>(old, m);
                let nv = b.or::<W64>(hi, v);
                sem::write64(b, Gpr(g), nv);
            }
            64 => {
                let v64: B::V<W64> = v;
                sem::write64(b, Gpr(g), v64);
            }
            _ => {
                let v32: B::V<W32> = b.trunc::<W64, W32>(v);
                b.set(Gpr(g).state(), v32);
            }
        }
    }
    Ok(())
}

/// POP → 値幅 w で返す。ポインタ演算は `sa` 幅、読み込み番地は `sseg`+SP。
pub fn pop_v<B: Backend>(b: &mut B, w: u8, sa: u8, sseg: u64) -> Result<B::V<W64>, B::Exit> {
    let sp = Gpr(4);
    let sz = u64::from(w / 8);
    let sg = b.konst::<W64>(sseg);
    // sa==16 では SP の更新をロードの後に遅らせる（限界例外で SP が
    // 変わらないようにするため）。
    let (a, np_done, off) = match sa {
        16 => {
            let cur: B::V<W32> = b.get(sp.state());
            let m16 = b.konst::<W32>(0xFFFF);
            let lo = b.and::<W32>(cur, m16);
            let off = b.zext::<W32, W64>(lo);
            let a = b.add::<W64>(off, sg);
            let k = b.konst::<W32>(sz as u32);
            let nlo0 = b.add::<W32>(lo, k);
            // SP は下位 16 ビットで折り返す（加算の桁上りは捨てる）。
            let nlo = b.and::<W32>(nlo0, m16);
            let nm = b.konst::<W32>(0xFFFF_0000);
            let hi = b.and::<W32>(cur, nm);
            let np = b.or::<W32>(hi, nlo);
            (a, np, off)
        }
        64 => {
            let cur = sem::read64(b, sp);
            let a = b.add::<W64>(cur, sg);
            let k = b.konst::<W64>(sz);
            let np = b.add::<W64>(cur, k);
            let np64 = np;
            sem::write64(b, sp, np64);
            (a, b.trunc::<W64, W32>(np), a)
        }
        _ => {
            let cur: B::V<W32> = b.get(sp.state());
            let off = b.zext::<W32, W64>(cur);
            let a = b.add::<W64>(off, sg);
            let k = b.konst::<W32>(sz as u32);
            let np = b.add::<W32>(cur, k);
            (a, np, off)
        }
    };
    if sa != 64 && sa != 16 {
        b.set(sp.state(), np_done);
    }
    let wseg = (sa == 16).then_some((sseg | decode::WSEG_SS, off));
    let v = match w {
        16 => {
            let v: B::V<W16> = decode::mem_load(b, a, wseg)?;
            b.zext::<W16, W64>(v)
        }
        64 => decode::mem_load::<B, W64>(b, a, wseg)?,
        _ => {
            let v: B::V<W32> = decode::mem_load(b, a, wseg)?;
            b.zext::<W32, W64>(v)
        }
    };
    if sa == 16 {
        b.set(sp.state(), np_done);
    }
    Ok(v)
}

/// PUSH2 Ev, vvvv（APX）。第1被演算子（vvvv）→第2被演算子（rm）の順に
/// 64 ビット値を push する。push2p の p はペアリング性能ヒントで、
/// 結果の順序は変わらない。例外条件（APX 仕様書 Table 3.4 と
/// exception class APX-EVEX-PP2）:
/// - B/V のいずれかのレジスタ id が 4（RSP）なら #UD
/// - エントリ時の RSP が 16 バイト整列でなければ #GP（書き込む
///   16 バイトがスタック上で整列する必要がある）
/// - fault 時は 2 つの書き込みのどちらもコミットされない。
///   ここでは両番地を読み probe してから書き込むことで不可分性を
///   近似し、RSP の更新は最後に一度だけ行う。
pub fn push2<B: Backend>(
    b: &mut B,
    rm: &Rm<B::V<W64>>,
    d: &MapDec,
    sa: u8,
    sseg: u64,
    pp: bool,
) -> Flow<B> {
    use polyisa_sem::{ExceptionKind, GuestException};
    // RSP 被演算子の禁止は encoding 条件なので無条件に #UD。
    if d.vex_v == 4 || matches!(rm, Rm::Reg(g) if g.0 == 4) {
        return Err(b.raise(GuestException {
            kind: ExceptionKind::Undefined,
            code: 0x06,
            addr: None,
            in_delay_slot: false,
        }));
    }
    let v_rm = rd_w::<B, W64>(b, rm, d)?;
    let v_nd = sem::read64(b, Gpr(d.vex_v));
    let _ = pp;
    if sa != 64 {
        push_v(b, 64, v_nd, sa, sseg)?;
        return push_v(b, 64, v_rm, sa, sseg);
    }
    let rsp = sem::read64(b, Gpr(4));
    // 16 バイト整列の検査。違反なら #GP で、何もコミットしない。
    let align_mask = b.konst::<W64>(15);
    let low = b.and::<W64>(rsp, align_mask);
    let z64 = b.konst::<W64>(0);
    let misaligned = b.cmp::<W64>(Cmp::Ne, low, z64);
    b.if_then(misaligned, |b| {
        Err(b.raise(GuestException {
            kind: ExceptionKind::Protection,
            code: 0x0D,
            addr: None,
            in_delay_slot: false,
        }))
    })?;
    let sixteen = b.konst::<W64>(16);
    let np = b.sub::<W64>(rsp, sixteen);
    let sg = b.konst::<W64>(sseg);
    let a_lo = b.add::<W64>(np, sg);
    let eight = b.konst::<W64>(8);
    let np8 = b.add::<W64>(np, eight);
    let a_hi = b.add::<W64>(np8, sg);
    // 書き込み不可分性の近似: 両番地を先に読み probe し、
    // fault はどの書き込みより前に起こす。
    let _p1 = b.load::<W64>(a_lo, sem::DATA_READ)?;
    let _p2 = b.load::<W64>(a_hi, sem::DATA_READ)?;
    b.store::<W64>(a_hi, v_nd, sem::DATA_WRITE)?;
    b.store::<W64>(a_lo, v_rm, sem::DATA_WRITE)?;
    sem::write64(b, Gpr(4), np);
    Ok(())
}

/// POP2 Ev, vvvv（APX）。スタックトップから第1被演算子（vvvv）→
/// 第2被演算子（rm）の順に pop する。pop2p の p はペアリング性能
/// ヒントで、結果の順序は変わらない。
pub fn pop2<B: Backend>(
    b: &mut B,
    rm: &Rm<B::V<W64>>,
    d: &MapDec,
    sa: u8,
    sseg: u64,
    pp: bool,
) -> Flow<B> {
    use polyisa_sem::{ExceptionKind, GuestException};
    // RSP 被演算子の禁止と、POP2 では B/V が同一でないこと。
    // 違反は encoding 条件なので無条件に #UD。
    let dup = matches!(rm, Rm::Reg(g) if g.0 == d.vex_v);
    if d.vex_v == 4 || matches!(rm, Rm::Reg(g) if g.0 == 4) || dup {
        return Err(b.raise(GuestException {
            kind: ExceptionKind::Undefined,
            code: 0x06,
            addr: None,
            in_delay_slot: false,
        }));
    }
    let _ = pp;
    if sa != 64 {
        let v_nd = pop_v(b, 64, sa, sseg)?;
        let v_rm = pop_v(b, 64, sa, sseg)?;
        wr_w::<B, W64>(b, rm, d, v_rm)?;
        W64::put(b, Gpr(d.vex_v), d, v_nd);
        return Ok(());
    }
    let rsp = sem::read64(b, Gpr(4));
    // 16 バイト整列の検査。違反なら #GP で、何もコミットしない。
    let align_mask = b.konst::<W64>(15);
    let low = b.and::<W64>(rsp, align_mask);
    let z64 = b.konst::<W64>(0);
    let misaligned = b.cmp::<W64>(Cmp::Ne, low, z64);
    b.if_then(misaligned, |b| {
        Err(b.raise(GuestException {
            kind: ExceptionKind::Protection,
            code: 0x0D,
            addr: None,
            in_delay_slot: false,
        }))
    })?;
    let sg = b.konst::<W64>(sseg);
    let a0 = b.add::<W64>(rsp, sg);
    let eight = b.konst::<W64>(8);
    let rsp8 = b.add::<W64>(rsp, eight);
    let a1 = b.add::<W64>(rsp8, sg);
    // 両方の値を先に読み、レジスタと RSP の更新はすべての
    // 読み込みが成功した後に一度だけ行う（fault 非 commit）。
    let v_nd = b.load::<W64>(a0, sem::DATA_READ)?;
    let v_rm = b.load::<W64>(a1, sem::DATA_READ)?;
    wr_w::<B, W64>(b, rm, d, v_rm)?;
    W64::put(b, Gpr(d.vex_v), d, v_nd);
    let sixteen = b.konst::<W64>(16);
    let np = b.add::<W64>(rsp, sixteen);
    sem::write64(b, Gpr(4), np);
    Ok(())
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

/// RAO-INT の AADD/AAND/AOR/AXOR。返り値とフラグ更新はない。
/// op は 0:add, 1:and, 2:or, 3:xor。
pub fn rao_op<B: Backend>(
    b: &mut B,
    op: u8,
    w: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let reg = decode::reg(d);
    let src64 = sem::read64(b, reg);
    if w == 64 {
        let x = rd_w::<B, W64>(b, ea, d)?;
        let y: B::V<W64> = src64;
        let r = match op {
            0 => b.add::<W64>(x, y),
            1 => b.and::<W64>(x, y),
            2 => b.or::<W64>(x, y),
            _ => b.xor::<W64>(x, y),
        };
        wr_w::<B, W64>(b, ea, d, r)
    } else {
        let x = rd_w::<B, W32>(b, ea, d)?;
        let y: B::V<W32> = b.trunc::<W64, W32>(src64);
        let r = match op {
            0 => b.add::<W32>(x, y),
            1 => b.and::<W32>(x, y),
            2 => b.or::<W32>(x, y),
            _ => b.xor::<W32>(x, y),
        };
        wr_w::<B, W32>(b, ea, d, r)
    }
}

/// CMPccXADD。old=mem として cmp old,r1 の旗を立て、cc 成立なら
/// mem=old+r2(vvvv)、r1=old とする。幅は 32 または 64。
pub fn cmpccxadd<B: Backend>(
    b: &mut B,
    ccnum: u8,
    w: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let r1g = decode::reg(d);
    let r1all = sem::read64(b, r1g);
    let r2all = sem::read64(b, Gpr(d.vex_v));
    if w == 64 {
        let old = rd_w::<B, W64>(b, ea, d)?;
        let r1: B::V<W64> = r1all;
        let diff = b.sub::<W64>(old, r1);
        sem::update_sub_flags(b, old, r1, diff);
        let r2: B::V<W64> = r2all;
        let sum = b.add::<W64>(old, r2);
        let take = cc(b, ccnum);
        let out = b.select::<W64>(take, sum, old);
        wr_w::<B, W64>(b, ea, d, out)?;
        sem::write64(b, r1g, old);
    } else {
        let old = rd_w::<B, W32>(b, ea, d)?;
        let r1: B::V<W32> = b.trunc::<W64, W32>(r1all);
        let diff = b.sub::<W32>(old, r1);
        sem::update_sub_flags(b, old, r1, diff);
        let r2: B::V<W32> = b.trunc::<W64, W32>(r2all);
        let sum = b.add::<W32>(old, r2);
        let take = cc(b, ccnum);
        let out = b.select::<W32>(take, sum, old);
        wr_w::<B, W32>(b, ea, d, out)?;
        let z = b.zext::<W32, W64>(old);
        sem::write64(b, r1g, z);
    }
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
pub fn jmp_rm<B: Backend>(b: &mut B, w: u8, rm: &Rm<B::V<W64>>, d: &MapDec, sa: u8) -> Flow<B> {
    let t = rd_any::<B>(b, w, rm, d)?;
    xfer_eip_chk(b, t, sa, w)?;
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
    xfer_eip_chk(b, t, sa, w)?;
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

/// sa==16 のスタック読み込み（SP は更新しない）。`plus` は SP
/// からのオフセット（ワード境界で 64K 折り返し）。ret 系の
/// 移転先検査で値だけ先に読むために使う。
fn stack_peek<B: Backend>(b: &mut B, w: u8, plus: u64, sseg: u64) -> Result<B::V<W64>, B::Exit> {
    let sp = Gpr(4);
    let cur: B::V<W32> = b.get(sp.state());
    let m16 = b.konst::<W32>(0xFFFF);
    let lo = b.and::<W32>(cur, m16);
    let k = b.konst::<W32>(plus as u32);
    let o = b.add::<W32>(lo, k);
    let o16 = b.and::<W32>(o, m16);
    let off = b.zext::<W32, W64>(o16);
    let sg = b.konst::<W64>(sseg);
    let a = b.add::<W64>(off, sg);
    let wseg = Some((sseg | decode::WSEG_SS, off));
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

/// 80386 実モードでは、制御移転でロードした EIP が CS 限界を
/// 越えると移転自体が #GP になる（積まれる IP は移転命令の
/// 番地。SST 80386 実測）。16 ビットの移転先は常に範囲内。
fn xfer_eip_chk<B: Backend>(b: &mut B, eip: B::V<W64>, sa: u8, w: u8) -> Flow<B> {
    use polyisa_sem::{ExceptionKind, GuestException};
    if sa != 16 || w != 32 || b.param::<crate::StackWrapParam>() != crate::STACK_WRAP_WRAP {
        return Ok(());
    }
    let lim = b.konst::<W64>(0xFFFF);
    let over = b.cmp::<W64>(Cmp::GtU, eip, lim);
    b.if_then(over, |b| {
        Err(b.raise(GuestException {
            kind: ExceptionKind::Trap,
            code: 13,
            addr: None,
            in_delay_slot: false,
        }))
    })
}

/// RET。pop で戻る。iw は積み増し。
pub fn ret<B: Backend>(b: &mut B, w: u8, iw: u16, sa: u8, sseg: u64) -> Flow<B> {
    // 80386 実モード: 移転先が限界を越えれば RET 自体が #GP
    // になり、SP の更新はコミットされない（SST 80386 実測）。
    if sa == 16 && b.param::<crate::StackWrapParam>() == crate::STACK_WRAP_WRAP {
        let v = stack_peek(b, w, 0, sseg)?;
        xfer_eip_chk(b, v, sa, w)?;
        let bump = (u64::from(w / 8) + u64::from(iw)) as u16;
        sp_add_iw(b, bump, sa);
        let t32: B::V<W32> = b.trunc::<W64, W32>(v);
        b.set(eip_ref(), t32);
        b.jump(v);
        return Ok(());
    }
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

/// JMPF ptr16:v（直値 far ポインタ）。実モードでは移転先が
/// CS 限界を越えると JMPF 自体が #GP（SST 80386 実測）。
pub fn jmpf_ptr<B: Backend>(b: &mut B, off: u64, sel: u64) -> Flow<B> {
    let o = b.konst::<W64>(off);
    xfer_eip_chk(b, o, 16, 32)?;
    let s = b.konst::<W16>(sel as u16);
    jmp_far(b, o, s)
}

/// CALLF ptr16:v。CS、次の IP の順に積んで far 分岐する。`w` は
/// オペランドサイズ（積む CS/EIP の幅とターゲットオフセット幅）。
#[allow(clippy::too_many_arguments)]
pub fn callf_ptr<B: Backend>(
    b: &mut B,
    w: u8,
    off: u64,
    sel: u64,
    eip: u32,
    len: u32,
    sa: u8,
    sseg: u64,
) -> Flow<B> {
    let o = b.konst::<W64>(off);
    xfer_eip_chk(b, o, sa, w)?;
    let cs: B::V<W16> = b.get(sem::sreg_ref(1));
    let cs64 = b.zext::<W16, W64>(cs);
    push_v(b, w, cs64, sa, sseg)?;
    let next = if w == 16 {
        eip.wrapping_add(len) & 0xFFFF
    } else {
        eip.wrapping_add(len)
    };
    let nv = b.konst::<W64>(u64::from(next));
    push_v(b, w, nv, sa, sseg)?;
    let s = b.konst::<W16>(sel as u16);
    jmp_far(b, o, s)
}

/// RETF。IP、CS の順に戻す。`w` はオペランドサイズ、iw は積み増し。
pub fn retf<B: Backend>(b: &mut B, w: u8, iw: u16, sa: u8, sseg: u64) -> Flow<B> {
    // 80386 実モード: 移転先 EIP が限界を越えれば RETF 自体が
    // #GP で、どちらのポップもコミットされない（SST 80386 実測）。
    if sa == 16 && b.param::<crate::StackWrapParam>() == crate::STACK_WRAP_WRAP {
        let sz = u64::from(w / 8);
        let ip = stack_peek(b, w, 0, sseg)?;
        let cs64 = stack_peek(b, w, sz, sseg)?;
        xfer_eip_chk(b, ip, sa, w)?;
        let bump = (sz * 2 + u64::from(iw)) as u16;
        sp_add_iw(b, bump, sa);
        let sel: B::V<W16> = b.trunc::<W64, W16>(cs64);
        return jmp_far(b, ip, sel);
    }
    let ip = pop_v(b, w, sa, sseg)?;
    let cs64 = pop_v(b, w, sa, sseg)?;
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
    xfer_eip_chk(b, off, sa, w)?;
    if is_call {
        let cs: B::V<W16> = b.get(sem::sreg_ref(1));
        let cs64 = b.zext::<W16, W64>(cs);
        push_v(b, w, cs64, sa, sseg)?;
        let next = if w == 16 {
            eip.wrapping_add(len) & 0xFFFF
        } else {
            eip.wrapping_add(len)
        };
        let nv = b.konst::<W64>(u64::from(next));
        push_v(b, w, nv, sa, sseg)?;
    }
    jmp_far(b, off, sel)
}

/// 実モード割り込み。FLAGS、CS、次の IP の順に積み、IF=TF=0 に
/// して IVT[vec] へ far 分岐する。divide error もこの経路で、
/// 積まれる IP は除算命令の次を指す（8088 の実動作）。
pub fn int_real<B: Backend>(b: &mut B, eip: u32, len: u32, vec: u8, sa: u8, sseg: u64) -> Flow<B> {
    // IVT エントリはフレームを積む前に読む。SS と IVT が重なる
    // とき、フレームの書き込みがベクタを上書きしても配送先は
    // 元のエントリになる（SST 80386 実測）。
    let va = b.konst::<W64>(u64::from(vec) * 4);
    let ip: B::V<W16> = decode::mem_load(b, va, None)?;
    let adv = b.konst::<W64>(2);
    let ca = b.add::<W64>(va, adv);
    let cs2: B::V<W16> = decode::mem_load(b, ca, None)?;
    let fl: B::V<W32> = b.get(eflags_ref());
    // `flags_top` = ones（8086/80186）では積まれる FLAGS の bit12-15 が 1。
    let mut fl64 = b.zext::<W32, W64>(fl);
    if b.param::<crate::FlagsTopParam>() == crate::FLAGS_TOP_ONES {
        let hi = b.konst::<W64>(0xF000);
        fl64 = b.or::<W64>(fl64, hi);
    }
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
    let off = b.zext::<W16, W64>(ip);
    jmp_far(b, off, cs2)
}

/// INTO。OF が立っていれば割り込み 4。
pub fn into_real<B: Backend>(b: &mut B, eip: u32, len: u32, sa: u8, sseg: u64) -> Flow<B> {
    let of = read_of(b);
    b.if_then(of, |b| int_real(b, eip, len, 4, sa, sseg))
}

/// IRET（実モード）。IP、CS、FLAGS を pop する。`w` は
/// オペランドサイズ（iretd では 32 ビット双語を pop する）。
pub fn iret_real<B: Backend>(b: &mut B, w: u8, sa: u8, sseg: u64) -> Flow<B> {
    // 80386 実モード: 移転先 EIP が限界を越えれば IRET 自体が
    // #GP で、どのポップもコミットされない（SST 80386 実測）。
    let (ip, cs64, fl64) =
        if sa == 16 && b.param::<crate::StackWrapParam>() == crate::STACK_WRAP_WRAP {
            let sz = u64::from(w / 8);
            let ip = stack_peek(b, w, 0, sseg)?;
            let cs = stack_peek(b, w, sz, sseg)?;
            let fl = stack_peek(b, w, sz * 2, sseg)?;
            xfer_eip_chk(b, ip, sa, w)?;
            sp_add_iw(b, (sz * 3) as u16, sa);
            (ip, cs, fl)
        } else {
            let ip = pop_v(b, w, sa, sseg)?;
            let cs = pop_v(b, w, sa, sseg)?;
            let fl = pop_v(b, w, sa, sseg)?;
            (ip, cs, fl)
        };
    let fl32: B::V<W32> = b.trunc::<W64, W32>(fl64);
    // POPF と同じ強制ビット（bit1=1、bit3/5=0）。bit12-15 は
    // `flags_top` = ones（8086/80186）で常に 1、zero（80286 以降）では
    // 積まれた値をそのまま採用する。
    let m = b.konst::<W32>(0x0FD5);
    let low = b.and::<W32>(fl32, m);
    let top = if b.param::<crate::FlagsTopParam>() == crate::FLAGS_TOP_ONES {
        0xF002
    } else {
        0x0002
    };
    let forced = b.konst::<W32>(top);
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
    // APX ZU ではレジスタ宛先の上位をゼロにする。vvvv は使わず、
    // ND ビットが ZU の選択子。メモリ宛先は byte 書きのまま。
    if d.ndd
        && let Rm::Reg(g) = rm
    {
        put_ndd::<B, W8>(b, *g, v);
        return Ok(());
    }
    wr_w::<B, W8>(b, rm, d, v)
}

/// APX の CMOVcc/CFCMOVcc。NDD 形は `ndd = cc ? r/m : reg`。
/// NF は新宛先ではなくフォールト抑制・条件付きストアの選択子。
fn cmov_apx<B: Backend>(
    b: &mut B,
    n: u8,
    w: u8,
    dst: Gpr,
    rm: &Rm<B::V<W64>>,
    d: &MapDec,
) -> Flow<B> {
    match w {
        16 => cmov_apx_w::<B, W16>(b, n, dst, rm, d),
        32 => cmov_apx_w::<B, W32>(b, n, dst, rm, d),
        _ => cmov_apx_w::<B, W64>(b, n, dst, rm, d),
    }
}

fn cmov_apx_w<B: Backend, W: Hw>(
    b: &mut B,
    n: u8,
    dst: Gpr,
    rm: &Rm<B::V<W64>>,
    d: &MapDec,
) -> Flow<B> {
    let take = cc(b, n);
    if d.ndd {
        let ndd = Gpr(d.vex_v);
        let src1 = grd_w::<B, W>(b, dst, d);
        if d.nf {
            // CFCMOV ndd,reg,r/m。偽では reg を返し、メモリは読まない。
            return b.if_then_else(
                take,
                |b| {
                    let v = rd_w::<B, W>(b, rm, d)?;
                    put_ndd::<B, W>(b, ndd, v);
                    Ok(())
                },
                |b| {
                    // CFCMOV の偽側で r/m がメモリのときは reg
                    // ソースを全幅コピーする。レジスタ直形では通常
                    // どおり結果幅へゼロ拡張する（SDE 10.13 との
                    // 差分で確認した非対称）。
                    if matches!(rm, Rm::Mem { .. }) {
                        let v = sem::read64(b, dst);
                        sem::write64(b, ndd, v);
                    } else {
                        put_ndd::<B, W>(b, ndd, src1);
                    }
                    Ok(())
                },
            );
        }
        // NDD CMOV。メモリは条件が偽でも読む。
        let src2 = rd_w::<B, W>(b, rm, d)?;
        let v = b.select::<W>(take, src2, src1);
        put_ndd::<B, W>(b, ndd, v);
        return Ok(());
    }
    if !d.nf {
        // CFCMOV reg,r/m。真なら r/m、偽なら 0。メモリは真のときだけ読む。
        return b.if_then_else(
            take,
            |b| {
                let v = rd_w::<B, W>(b, rm, d)?;
                put_ndd::<B, W>(b, dst, v);
                Ok(())
            },
            |b| {
                let z = b.konst::<W>(W::from_u128(0));
                put_ndd::<B, W>(b, dst, z);
                Ok(())
            },
        );
    }
    // CFCMOV r/m,reg（条件付きストア）。真なら r/m へ reg を書き、
    // 偽ではレジスタ宛先を 0 にし、メモリ宛先は触れない。
    let src = grd_w::<B, W>(b, dst, d);
    b.if_then_else(
        take,
        |b| match rm {
            Rm::Reg(g) => {
                put_ndd::<B, W>(b, *g, src);
                Ok(())
            }
            Rm::Mem { .. } => wr_w::<B, W>(b, rm, d, src),
        },
        |b| {
            if let Rm::Reg(g) = rm {
                let z = b.konst::<W>(W::from_u128(0));
                put_ndd::<B, W>(b, *g, z);
            }
            Ok(())
        },
    )
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
    if d.evex && d.vex_map == 4 {
        return cmov_apx(b, n, w, dst, rm, d);
    }
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

/// 無効命令例外（#UD）。ユーザーモードでは OS パーソナリティが
/// シグナルへ変換する退出として表す。
pub fn undefined<B: Backend>(b: &mut B, eip: u32) -> Flow<B> {
    use polyisa_sem::{ExceptionKind, GuestException};
    Err(b.raise(GuestException {
        kind: ExceptionKind::Undefined,
        code: 0x06,
        addr: Some(u64::from(eip)),
        in_delay_slot: false,
    }))
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
    // map4 の即値形は NDD ではなく ZU。宛先は reg のまま、
    // ND=1 で上位をゼロにする（16 ビット幅でだけ意味を持つ）。
    if d.ndd {
        put_ndd::<B, W>(b, g, lo);
    } else {
        W::put(b, g, d, lo);
    }
    if d.nf {
        return Ok(());
    }
    if b.param::<crate::ImulFlagsParam>() == crate::IMUL_FLAGS_SZP {
        // 80286 の実測フラグ（SST 80286）：SF は積の符号（上位語の
        // 符号ビット）、ZF は上位語 == 0、PF は `hi ^ sext(lo)` の
        // 下位バイトの偶数性、CF/OF は溢れ。AF は未定義で残す。
        let z = b.konst::<W>(W::from_u128(0));
        let sf = b.cmp::<W>(Cmp::LtS, hi, z);
        let zf = b.cmp::<W>(Cmp::Eq, hi, z);
        let xw = b.xor::<W>(hi, expect);
        let old: B::V<W32> = b.get(eflags_ref());
        let keep = b.konst::<W32>(
            !(sem::FLAG_CF | sem::FLAG_ZF | sem::FLAG_SF | sem::FLAG_PF | sem::FLAG_OF),
        );
        let cf = pick(b, ovf, sem::FLAG_CF);
        let zfb = pick(b, zf, sem::FLAG_ZF);
        let sfb = pick(b, sf, sem::FLAG_SF);
        let pfb = pf_bit(b, xw);
        let ofb = pick(b, ovf, sem::FLAG_OF);
        let mut nf = b.and::<W32>(old, keep);
        nf = b.or::<W32>(nf, cf);
        nf = b.or::<W32>(nf, zfb);
        nf = b.or::<W32>(nf, sfb);
        nf = b.or::<W32>(nf, pfb);
        nf = b.or::<W32>(nf, ofb);
        b.set(eflags_ref(), nf);
    } else {
        set_cf_of(b, ovf);
    }
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
    if d.ndd {
        put_ndd::<B, W>(b, Gpr(d.vex_v), lo);
    } else {
        W::put(b, g, d, lo);
    }
    if !d.nf {
        set_cf_of(b, ovf);
    }
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
    // 等価時は宛先のみ、非等価時はアキュムレータのみ書く。等価時に
    // acc を「同じ値」で書き戻すと 32 ビット形が上位を消してしまう。
    let sv = W::get(b, src, d);
    b.if_then_else(
        eq,
        |b| wr_w::<B, W>(b, ea, d, sv),
        |b| {
            W::put(b, Gpr(0), d, t);
            Ok(())
        },
    )?;
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
    // dst と src が同じレジスタでは被演算子への書き戻しを
    // しない（xadd r,r は r=2*r で確定する）。
    let same = matches!(ea, Rm::Reg(g) if *g == src);
    wr_w::<B, W>(b, ea, d, v)?;
    if !same {
        W::put(b, src, d, t);
    }
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
    // 入力 0 のときの宛先は挙動パラメータ。dest_zero=0 に、
    // dest_unchanged=保つ。IR 経路では `param` が定数になり枝が畳まれる。
    let zero_dst = b.param::<crate::BsfZeroInputParam>() == crate::BSF_ZERO_INPUT_DEST_ZERO;
    let dst = if zero_dst {
        b.select::<W>(is_zero, zero, acc)
    } else {
        let old = W::get(b, g, d);
        b.select::<W>(is_zero, old, acc)
    };
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

/// LZCNT r, r/m。上位から連続する 0 の個数。入力 0 は幅を返して
/// CF=1、結果 0（MSB が立つ）で ZF=1。その他のフラグは保つ。
fn lzcnt_w<B: Backend, W: Hw>(b: &mut B, g: Gpr, ea: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    let v = rd_w::<B, W>(b, ea, d)?;
    let zero = b.konst::<W>(W::from_u128(0));
    // 最上位に立つビットの添字（入力 0 のときは使わない）。
    let mut idx = zero;
    for i in 0..W::BITS {
        let bit = b.konst::<W>(W::from_u128(1u128 << i));
        let t = b.and::<W>(v, bit);
        let set = b.cmp::<W>(Cmp::Ne, t, zero);
        let iv = b.konst::<W>(W::from_u128(u128::from(i)));
        idx = b.select::<W>(set, iv, idx);
    }
    let is_zero = b.cmp::<W>(Cmp::Eq, v, zero);
    let bits = b.konst::<W>(W::from_u128(u128::from(W::BITS)));
    let one = b.konst::<W>(W::from_u128(1));
    let t = b.add::<W>(idx, one);
    let cnt = b.sub::<W>(bits, t);
    let dst = b.select::<W>(is_zero, bits, cnt);
    W::put(b, g, d, dst);
    let is_dst_zero = b.cmp::<W>(Cmp::Eq, dst, zero);
    let old: B::V<W32> = b.get(eflags_ref());
    let mask = b.konst::<W32>(!(sem::FLAG_CF | sem::FLAG_ZF));
    let f = b.and::<W32>(old, mask);
    let cf = pick(b, is_zero, sem::FLAG_CF);
    let zf = pick(b, is_dst_zero, sem::FLAG_ZF);
    let f = b.or::<W32>(f, cf);
    let f = b.or::<W32>(f, zf);
    b.set(eflags_ref(), f);
    Ok(())
}

/// LZCNT r, r/m。
pub fn lzcnt<B: Backend>(b: &mut B, w: u8, g: Gpr, ea: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    match w {
        16 => lzcnt_w::<B, W16>(b, g, ea, d),
        64 => lzcnt_w::<B, W64>(b, g, ea, d),
        _ => lzcnt_w::<B, W32>(b, g, ea, d),
    }
}

// ---- BMI1/BMI2（VEX エンコードの GPR ビット操作）----

/// VEX.vvvv が指す GPR（BMI の By オペランド）。
fn vvv_g(d: &MapDec) -> Gpr {
    Gpr(d.vex_v)
}

/// BMI の SF/ZF/CF/OF 更新。SF/ZF は結果から、CF は `cf`、
/// OF は常に 0。AF/PF は不定（実値のまま残す）。
fn bmi_flags<B: Backend, W: Hw>(b: &mut B, dst: B::V<W>, cf: B::B) {
    let zero = b.konst::<W>(W::from_u128(0));
    let is_z = b.cmp::<W>(Cmp::Eq, dst, zero);
    let top = b.konst::<W>(W::from_u128(1u128 << (W::BITS - 1)));
    let t = b.and::<W>(dst, top);
    let is_s = b.cmp::<W>(Cmp::Ne, t, zero);
    let old: B::V<W32> = b.get(eflags_ref());
    let mask = b.konst::<W32>(!(sem::FLAG_SF | sem::FLAG_ZF | sem::FLAG_OF | sem::FLAG_CF));
    let f = b.and::<W32>(old, mask);
    let sf = pick(b, is_s, sem::FLAG_SF);
    let f = b.or::<W32>(f, sf);
    let zf = pick(b, is_z, sem::FLAG_ZF);
    let f = b.or::<W32>(f, zf);
    let cfb = pick(b, cf, sem::FLAG_CF);
    let f = b.or::<W32>(f, cfb);
    b.set(eflags_ref(), f);
}

/// 偽の条件値（フラグを必ず 0 にする用途）。
fn fals<B: Backend, W: Hw>(b: &mut B) -> B::B {
    let z = b.konst::<W>(W::from_u128(0));
    b.cmp::<W>(Cmp::Ne, z, z)
}

/// ANDN Gv, By, Ev。`dst = ~src1 & src2`。CF/OF=0。
fn andn_w<B: Backend, W: Hw>(b: &mut B, g: Gpr, ea: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    let s1 = W::get(b, vvv_g(d), d);
    let s2 = rd_w::<B, W>(b, ea, d)?;
    let n = b.not::<W>(s1);
    let r = b.and::<W>(n, s2);
    W::put(b, g, d, r);
    let f = fals::<B, W>(b);
    bmi_flags::<B, W>(b, r, f);
    Ok(())
}

/// ANDN。VEX.W で 32/64。
pub fn andn<B: Backend>(b: &mut B, w: u8, g: Gpr, ea: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    if w == 64 {
        andn_w::<B, W64>(b, g, ea, d)
    } else {
        andn_w::<B, W32>(b, g, ea, d)
    }
}

/// BEXTR Gv, Ev, By。src2 の [7:0]=開始・[15:8]=長さの
/// ビットフィールドを src1 から取り出す。ZF のみ意味を持ち、
/// CF/OF=0。開始が幅以上なら結果 0、長さがあふれる分は無視。
fn bextr_w<B: Backend, W: Hw>(b: &mut B, g: Gpr, ea: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    let s = rd_w::<B, W>(b, ea, d)?;
    let c = W::get(b, vvv_g(d), d);
    let m8 = b.konst::<W>(W::from_u128(0xFF));
    let start = b.and::<W>(c, m8);
    let c8 = b.konst::<W>(W::from_u128(8));
    let t = b.shr_l::<W>(c, c8);
    let len = b.and::<W>(t, m8);
    // shr_l/shl は幅以上を 0 とする全域関数なので、開始・長さの
    // 範囲外は select せずにそのまま扱える。
    let sh = b.shr_l::<W>(s, start);
    let one = b.konst::<W>(W::from_u128(1));
    let ml = b.shl::<W>(one, len);
    let one2 = b.konst::<W>(W::from_u128(1));
    let mk = b.sub::<W>(ml, one2);
    let r = b.and::<W>(sh, mk);
    W::put(b, g, d, r);
    let f = fals::<B, W>(b);
    bmi_flags::<B, W>(b, r, f);
    Ok(())
}

/// BEXTR。
pub fn bextr<B: Backend>(b: &mut B, w: u8, g: Gpr, ea: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    if w == 64 {
        bextr_w::<B, W64>(b, g, ea, d)
    } else {
        bextr_w::<B, W32>(b, g, ea, d)
    }
}

/// BLSR(/1)・BLSMSK(/2)・BLSI(/3)。宛先は vvvv。
/// CF は BLSI だけ src!=0、他は src==0。
fn bls_w<B: Backend, W: Hw>(b: &mut B, kind: u8, ea: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    let s = rd_w::<B, W>(b, ea, d)?;
    let one = b.konst::<W>(W::from_u128(1));
    let m1 = b.sub::<W>(s, one);
    let r = match kind {
        1 => b.and::<W>(s, m1),
        2 => b.xor::<W>(s, m1),
        _ => {
            let zero = b.konst::<W>(W::from_u128(0));
            let n = b.sub::<W>(zero, s);
            b.and::<W>(s, n)
        }
    };
    W::put(b, vvv_g(d), d, r);
    let zero = b.konst::<W>(W::from_u128(0));
    let cf = if kind == 3 {
        b.cmp::<W>(Cmp::Ne, s, zero)
    } else {
        b.cmp::<W>(Cmp::Eq, s, zero)
    };
    bmi_flags::<B, W>(b, r, cf);
    Ok(())
}

/// BLSR/BLSMSK/BLSI。`kind` は ModRM.reg のグループ番号。
pub fn bls<B: Backend>(b: &mut B, w: u8, kind: u8, ea: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    if w == 64 {
        bls_w::<B, W64>(b, kind, ea, d)
    } else {
        bls_w::<B, W32>(b, kind, ea, d)
    }
}

/// BZHI Gv, Ev, By。index（src2 の下位 8 ビット）以上の
/// ビットをクリアする。index>=幅 で CF=1、結果は src のまま。
fn bzhi_w<B: Backend, W: Hw>(b: &mut B, g: Gpr, ea: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    let s = rd_w::<B, W>(b, ea, d)?;
    let c = W::get(b, vvv_g(d), d);
    let m8 = b.konst::<W>(W::from_u128(0xFF));
    let n = b.and::<W>(c, m8);
    let one = b.konst::<W>(W::from_u128(1));
    let ml = b.shl::<W>(one, n);
    let one2 = b.konst::<W>(W::from_u128(1));
    let mk = b.sub::<W>(ml, one2);
    let r = b.and::<W>(s, mk);
    W::put(b, g, d, r);
    let bits = b.konst::<W>(W::from_u128(u128::from(W::BITS)));
    let cf = b.cmp::<W>(Cmp::GeU, n, bits);
    bmi_flags::<B, W>(b, r, cf);
    Ok(())
}

/// BZHI。
pub fn bzhi<B: Backend>(b: &mut B, w: u8, g: Gpr, ea: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    if w == 64 {
        bzhi_w::<B, W64>(b, g, ea, d)
    } else {
        bzhi_w::<B, W32>(b, g, ea, d)
    }
}

/// MULX By, Gv, Ev。暗黙の EDX/RDX と src の符号なし乗算で、
/// 下位を vvvv、上位を ModRM.reg へ書く。フラグ不変。
fn vmulx_w<B: Backend, W: Hw>(b: &mut B, g: Gpr, ea: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    let s = rd_w::<B, W>(b, ea, d)?;
    let m = W::get(b, Gpr(2), d);
    let lo = b.mul::<W>(m, s);
    let hi = b.mulhu::<W>(m, s);
    W::put(b, vvv_g(d), d, lo);
    W::put(b, g, d, hi);
    Ok(())
}

/// MULX。
pub fn vmulx<B: Backend>(b: &mut B, w: u8, g: Gpr, ea: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    if w == 64 {
        vmulx_w::<B, W64>(b, g, ea, d)
    } else {
        vmulx_w::<B, W32>(b, g, ea, d)
    }
}

/// PDEP Gv, By, Ev。src1 の下位ビットを src2 マスクの立ち
/// 位置へ並列配置する。フラグ不変。
fn pdep_w<B: Backend, W: Hw>(b: &mut B, g: Gpr, ea: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    let s = W::get(b, vvv_g(d), d);
    let mk = rd_w::<B, W>(b, ea, d)?;
    let zero = b.konst::<W>(W::from_u128(0));
    let one = b.konst::<W>(W::from_u128(1));
    let mut r = zero;
    let mut si = zero;
    for i in 0..W::BITS {
        let bit = b.konst::<W>(W::from_u128(1u128 << i));
        let m = b.and::<W>(mk, bit);
        let has = b.cmp::<W>(Cmp::Ne, m, zero);
        // マスクの i 番目が立つなら src の si 番目を i に置く。
        let sbit = b.shl::<W>(one, si);
        let sv = b.and::<W>(s, sbit);
        let nz = b.cmp::<W>(Cmp::Ne, sv, zero);
        let place = b.select::<W>(nz, bit, zero);
        let nr = b.or::<W>(r, place);
        r = b.select::<W>(has, nr, r);
        let si1 = b.add::<W>(si, one);
        si = b.select::<W>(has, si1, si);
    }
    W::put(b, g, d, r);
    Ok(())
}

/// PDEP。
pub fn pdep<B: Backend>(b: &mut B, w: u8, g: Gpr, ea: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    if w == 64 {
        pdep_w::<B, W64>(b, g, ea, d)
    } else {
        pdep_w::<B, W32>(b, g, ea, d)
    }
}

/// PEXT Gv, By, Ev。src1 のうち src2 マスクの立つ位置の
/// ビットを下位へ並列圧縮する。フラグ不変。
fn pext_w<B: Backend, W: Hw>(b: &mut B, g: Gpr, ea: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    let s = W::get(b, vvv_g(d), d);
    let mk = rd_w::<B, W>(b, ea, d)?;
    let zero = b.konst::<W>(W::from_u128(0));
    let one = b.konst::<W>(W::from_u128(1));
    let mut r = zero;
    let mut di = zero;
    for i in 0..W::BITS {
        let bit = b.konst::<W>(W::from_u128(1u128 << i));
        let m = b.and::<W>(mk, bit);
        let has = b.cmp::<W>(Cmp::Ne, m, zero);
        // マスクの i 番目が立つなら src の i 番目を di に置く。
        let sv = b.and::<W>(s, bit);
        let nz = b.cmp::<W>(Cmp::Ne, sv, zero);
        let dbit = b.shl::<W>(one, di);
        let place = b.select::<W>(nz, dbit, zero);
        let nr = b.or::<W>(r, place);
        r = b.select::<W>(has, nr, r);
        let di1 = b.add::<W>(di, one);
        di = b.select::<W>(has, di1, di);
    }
    W::put(b, g, d, r);
    Ok(())
}

/// PEXT。
pub fn pext<B: Backend>(b: &mut B, w: u8, g: Gpr, ea: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    if w == 64 {
        pext_w::<B, W64>(b, g, ea, d)
    } else {
        pext_w::<B, W32>(b, g, ea, d)
    }
}

/// RORX Gv, Ev, Ib。フラグ不変の右ローテート。
fn rorx_w<B: Backend, W: Hw>(b: &mut B, g: Gpr, ea: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    let s = rd_w::<B, W>(b, ea, d)?;
    let c = (d.imm as u32) % W::BITS;
    let ck = b.konst::<W>(W::from_u128(u128::from(c)));
    let lo = b.shr_l::<W>(s, ck);
    let bits = b.konst::<W>(W::from_u128(u128::from(W::BITS - c)));
    let hi = b.shl::<W>(s, bits);
    let r = b.or::<W>(lo, hi);
    W::put(b, g, d, r);
    Ok(())
}

/// RORX。
pub fn rorx<B: Backend>(b: &mut B, w: u8, g: Gpr, ea: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    if w == 64 {
        rorx_w::<B, W64>(b, g, ea, d)
    } else {
        rorx_w::<B, W32>(b, g, ea, d)
    }
}

/// SHLX/SHRX/SARX Gv, Ev, By。カウントは src2 を幅で
/// マスクしたもの。フラグ不変。`kind`: 0=shl, 1=shr_l, 2=shr_a。
fn vshiftx_w<B: Backend, W: Hw>(
    b: &mut B,
    kind: u8,
    g: Gpr,
    ea: &Rm<B::V<W64>>,
    d: &MapDec,
) -> Flow<B> {
    let s = rd_w::<B, W>(b, ea, d)?;
    let c = W::get(b, vvv_g(d), d);
    let m = b.konst::<W>(W::from_u128(u128::from(W::BITS - 1)));
    let cnt = b.and::<W>(c, m);
    let r = match kind {
        0 => b.shl::<W>(s, cnt),
        1 => b.shr_l::<W>(s, cnt),
        _ => b.shr_a::<W>(s, cnt),
    };
    W::put(b, g, d, r);
    Ok(())
}

/// SHLX/SHRX/SARX。
pub fn vshiftx<B: Backend>(
    b: &mut B,
    w: u8,
    kind: u8,
    g: Gpr,
    ea: &Rm<B::V<W64>>,
    d: &MapDec,
) -> Flow<B> {
    if w == 64 {
        vshiftx_w::<B, W64>(b, kind, g, ea, d)
    } else {
        vshiftx_w::<B, W32>(b, kind, g, ea, d)
    }
}

/// TZCNT r, r/m（F3 0F BC）。下位から連続する 0 の個数。
/// 入力 0 は幅を返して CF=1、結果 0（LSB が立つ）で ZF=1。
/// その他のフラグは保つ。
fn tzcnt_w<B: Backend, W: Hw>(b: &mut B, g: Gpr, ea: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    let v = rd_w::<B, W>(b, ea, d)?;
    let zero = b.konst::<W>(W::from_u128(0));
    // 最下位に立つビットの添字（入力 0 のときは使わない）。
    let mut idx = zero;
    for i in (0..W::BITS).rev() {
        let bit = b.konst::<W>(W::from_u128(1u128 << i));
        let t = b.and::<W>(v, bit);
        let set = b.cmp::<W>(Cmp::Ne, t, zero);
        let iv = b.konst::<W>(W::from_u128(u128::from(i)));
        idx = b.select::<W>(set, iv, idx);
    }
    let is_zero = b.cmp::<W>(Cmp::Eq, v, zero);
    let bits = b.konst::<W>(W::from_u128(u128::from(W::BITS)));
    let dst = b.select::<W>(is_zero, bits, idx);
    W::put(b, g, d, dst);
    let is_dst_zero = b.cmp::<W>(Cmp::Eq, dst, zero);
    let old: B::V<W32> = b.get(eflags_ref());
    let mask = b.konst::<W32>(!(sem::FLAG_CF | sem::FLAG_ZF));
    let f = b.and::<W32>(old, mask);
    let cf = pick(b, is_zero, sem::FLAG_CF);
    let zf = pick(b, is_dst_zero, sem::FLAG_ZF);
    let f = b.or::<W32>(f, cf);
    let f = b.or::<W32>(f, zf);
    b.set(eflags_ref(), f);
    Ok(())
}

/// TZCNT r, r/m。
pub fn tzcnt<B: Backend>(b: &mut B, w: u8, g: Gpr, ea: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    match w {
        16 => tzcnt_w::<B, W16>(b, g, ea, d),
        64 => tzcnt_w::<B, W64>(b, g, ea, d),
        _ => tzcnt_w::<B, W32>(b, g, ea, d),
    }
}

// ---- TBM（XOP.9 グループと XOP.A の AMD ビット操作）----

/// TBM 群（XOP.9）。宛先は vvvv、ソースは r/m。`kind` は式:
///   0=BLCFILL s&(s+1)  1=BLSFILL s|(s-1)  2=BLCS s|(s+1)
///   3=TZMSK  ~s&(s-1)  4=BLCIC   ~s&(s+1)  5=BLSIC ~s|(s-1)
///   6=T1MSKC ~s|(s+1)  7=BLCI    s|~(s+1)  8=BLCMSK s^(s+1)
/// CF は内部の加減算の桁上がり/借り（+1 形は s+1==0、
/// -1 形は s==0）。SF/ZF は結果、OF=0。
fn tbm_w<B: Backend, W: Hw>(b: &mut B, kind: u8, ea: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    let s = rd_w::<B, W>(b, ea, d)?;
    let one = b.konst::<W>(W::from_u128(1));
    let minus = matches!(kind, 1 | 3 | 5);
    let t = if minus {
        b.sub::<W>(s, one)
    } else {
        b.add::<W>(s, one)
    };
    let ns = b.not::<W>(s);
    let nt = b.not::<W>(t);
    let r = match kind {
        0 => b.and::<W>(s, t),
        1 | 2 => b.or::<W>(s, t),
        3 | 4 => b.and::<W>(ns, t),
        5 | 6 => b.or::<W>(ns, t),
        7 => b.or::<W>(s, nt),
        _ => b.xor::<W>(s, t),
    };
    W::put(b, vvv_g(d), d, r);
    let zero = b.konst::<W>(W::from_u128(0));
    let cf = if minus {
        b.cmp::<W>(Cmp::Eq, s, zero)
    } else {
        b.cmp::<W>(Cmp::Eq, t, zero)
    };
    bmi_flags::<B, W>(b, r, cf);
    Ok(())
}

/// TBM グループ命令（BLCFILL/BLSFILL/BLCS/TZMSK/BLCIC/BLSIC/
/// T1MSKC/BLCI/BLCMSK）。`kind` は上の式番号。
pub fn tbm<B: Backend>(b: &mut B, w: u8, kind: u8, ea: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    if w == 64 {
        tbm_w::<B, W64>(b, kind, ea, d)
    } else {
        tbm_w::<B, W32>(b, kind, ea, d)
    }
}

/// TBM BEXTR Gv, Ev, id（XOP.A 0x10）。imm32 の [7:0]=開始
/// ビット・[15:8]=長さのフィールドを src から取り出す。
/// フラグは BMI BEXTR と同じく ZF 意味あり・CF/OF=0。
fn tbextr_w<B: Backend, W: Hw>(b: &mut B, g: Gpr, ea: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    let s = rd_w::<B, W>(b, ea, d)?;
    let c = b.konst::<W>(W::from_u128(d.imm as u128));
    let m8 = b.konst::<W>(W::from_u128(0xFF));
    let start = b.and::<W>(c, m8);
    let c8 = b.konst::<W>(W::from_u128(8));
    let t = b.shr_l::<W>(c, c8);
    let len = b.and::<W>(t, m8);
    // shr_l/shl は幅以上を 0 とする全域関数なので、開始・長さの
    // 範囲外はそのまま扱える。
    let sh = b.shr_l::<W>(s, start);
    let one = b.konst::<W>(W::from_u128(1));
    let ml = b.shl::<W>(one, len);
    let one2 = b.konst::<W>(W::from_u128(1));
    let mk = b.sub::<W>(ml, one2);
    let r = b.and::<W>(sh, mk);
    W::put(b, g, d, r);
    let f = fals::<B, W>(b);
    bmi_flags::<B, W>(b, r, f);
    Ok(())
}

/// TBM BEXTR（imm32 制御形）。
pub fn tbextr<B: Backend>(b: &mut B, w: u8, g: Gpr, ea: &Rm<B::V<W64>>, d: &MapDec) -> Flow<B> {
    if w == 64 {
        tbextr_w::<B, W64>(b, g, ea, d)
    } else {
        tbextr_w::<B, W32>(b, g, ea, d)
    }
}

/// パック浮動小数点レーンの取り出し/書き戻しの関数型。
type FLaneGet<B, F> = fn(&mut B, <B as Backend>::V<W128>, u32) -> <B as Backend>::V<F>;
type FLanePut<B, F> =
    fn(&mut B, <B as Backend>::V<W128>, <B as Backend>::V<F>, u32) -> <B as Backend>::V<W128>;

/// 128 ビットチャンクのレーンごと FMA。`ord` は積和へのオペランド
/// 割り当て（0=132: dst·src+vvvv、1=213: vvvv·dst+src、
/// 2=231: vvvv·src+dst）。`op`: 0=fmadd 1=fmsub 2=fnmadd
/// 3=fnmsub 4=fmaddsub（偶数レーン引き算）5=fmsubadd（偶数レーン足し算）。
#[allow(clippy::too_many_arguments)]
fn vfma128<B: Backend, F: Width>(
    b: &mut B,
    op: u8,
    ord: u8,
    lanes: u32,
    dv: B::V<W128>,
    hv: B::V<W128>,
    sv: B::V<W128>,
    get: FLaneGet<B, F>,
    put: FLanePut<B, F>,
) -> B::V<W128> {
    let sign = b.konst::<F>(F::from_u128(1u128 << (F::BITS - 1)));
    let neg = |b: &mut B, v: B::V<F>| b.xor::<F>(v, sign);
    let mut acc = b.konst::<W128>(0);
    for i in 0..lanes {
        let dl = get(b, dv, i);
        let hl = get(b, hv, i);
        let sl = get(b, sv, i);
        let (a, m, c) = match ord {
            0 => (dl, sl, hl),
            1 => (hl, dl, sl),
            _ => (hl, sl, dl),
        };
        let (a, c) = match op {
            1 => (a, neg(b, c)),
            2 => (neg(b, a), c),
            3 => {
                let na = neg(b, a);
                (na, neg(b, c))
            }
            4 if i % 2 == 0 => (a, neg(b, c)),
            5 if i % 2 == 1 => (a, neg(b, c)),
            _ => (a, c),
        };
        let r = b.fmadd::<F>(a, m, c);
        acc = put(b, acc, r, i);
    }
    acc
}

/// VEX FMA（VFMADD/VFMSUB/VFNMADD/VFNMSUB/VFMADDSUB/VFMSUBADD の
/// 132・213・231 形）。`pd` は倍精度、`scalar` は SS/SD。スカラ形
/// の上位ビットは vvvv（SRC1）由来で、VEX.128 のみ。
pub fn vfma<B: Backend>(
    b: &mut B,
    pd: bool,
    scalar: bool,
    op: u8,
    ord: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    use polyisa_sem::{F32, F64};
    let dst = reg_x(d);
    let fbits = if pd { 64 } else { 32 };
    let dv: B::V<W128> = b.get(sem::xmm_ref(dst));
    let hv: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    let sv = rx(b, ea, if scalar { fbits } else { 128 })?;
    let lo = if pd {
        let lanes = if scalar { 1 } else { 2 };
        vfma128::<B, F64>(b, op, ord, lanes, dv, hv, sv, flane64, put_flane64)
    } else {
        let lanes = if scalar { 1 } else { 4 };
        vfma128::<B, F32>(b, op, ord, lanes, dv, hv, sv, flane32, put_flane32)
    };
    if scalar {
        let out = put_lane128(b, hv, lo, 0, fbits);
        b.set(sem::xmm_ref(dst), out);
        let z = b.konst::<W128>(0);
        b.set(sem::ymm_hi_ref(dst), z);
        return Ok(());
    }
    b.set(sem::xmm_ref(dst), lo);
    let hi = if d.vex_l {
        let dhi: B::V<W128> = b.get(sem::ymm_hi_ref(dst));
        let hhi: B::V<W128> = b.get(sem::ymm_hi_ref(vvv_x(d)));
        let shi = rx_hi(b, ea)?;
        if pd {
            vfma128::<B, F64>(b, op, ord, 2, dhi, hhi, shi, flane64, put_flane64)
        } else {
            vfma128::<B, F32>(b, op, ord, 4, dhi, hhi, shi, flane32, put_flane32)
        }
    } else {
        b.konst::<W128>(0)
    };
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

// ---- AMD XOP（FMA4・VPCMOV・VFRCZ・パックシフト）----

/// imm8[7:4] が選ぶ XMM（is4 オペランド）。
fn is4_x(d: &MapDec) -> Xmm {
    Xmm(((d.imm >> 4) & 0xF) as u8)
}

/// FMA4（XOP.8 / 66 0F 3A + is4）。`dest = src1·src2 + src3`
/// で src1=vvvv。W=0 は src2=r/m・src3=is4、W=1 は逆。
/// `op` は vfma128 と同じ（0=fmadd 1=fmsub 2=fnmadd 3=fnmsub
/// 4=fmaddsub 5=fmsubadd）。スカラ形の上位は src1（vvvv）由来。
pub fn vfma4<B: Backend>(
    b: &mut B,
    pd: bool,
    scalar: bool,
    op: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    use polyisa_sem::{F32, F64};
    let dst = reg_x(d);
    let fbits = if pd { 64 } else { 32 };
    let hv: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    let rmv = rx(b, ea, if scalar { fbits } else { 128 })?;
    let iv: B::V<W128> = b.get(sem::xmm_ref(is4_x(d)));
    // ord=1 は (hv·dv)+sv を計算するので、dv=s2・sv=s3 を渡す。
    let (s2, s3) = if d.vex_w { (iv, rmv) } else { (rmv, iv) };
    let lo = if pd {
        let lanes = if scalar { 1 } else { 2 };
        vfma128::<B, F64>(b, op, 1, lanes, s2, hv, s3, flane64, put_flane64)
    } else {
        let lanes = if scalar { 1 } else { 4 };
        vfma128::<B, F32>(b, op, 1, lanes, s2, hv, s3, flane32, put_flane32)
    };
    if scalar {
        // FMA4 スカラ形は dest のレーン 0 以外を 0 クリアする
        // （src1 上位の継承はしない。APM vol.6 各命令ページ）。
        b.set(sem::xmm_ref(dst), lo);
        let z = b.konst::<W128>(0);
        b.set(sem::ymm_hi_ref(dst), z);
        return Ok(());
    }
    b.set(sem::xmm_ref(dst), lo);
    let hi = if d.vex_l {
        let hhi: B::V<W128> = b.get(sem::ymm_hi_ref(vvv_x(d)));
        let rhi = rx_hi(b, ea)?;
        let ihi: B::V<W128> = b.get(sem::ymm_hi_ref(is4_x(d)));
        let (s2h, s3h) = if d.vex_w { (ihi, rhi) } else { (rhi, ihi) };
        if pd {
            vfma128::<B, F64>(b, op, 1, 2, s2h, hhi, s3h, flane64, put_flane64)
        } else {
            vfma128::<B, F32>(b, op, 1, 4, s2h, hhi, s3h, flane32, put_flane32)
        }
    } else {
        b.konst::<W128>(0)
    };
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

/// VPCMOV dest, src1(vvvv), src2, src3:
/// dest = (src1 & src3) | (src2 & ~src3)。W=0 は src2=r/m・
/// src3=is4、W=1 は逆。L=1 は ymm 上位も同じ処理。
pub fn vpcmov<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let s1: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    let rmv = rx(b, ea, 128)?;
    let iv: B::V<W128> = b.get(sem::xmm_ref(is4_x(d)));
    let (s2, s3) = if d.vex_w { (iv, rmv) } else { (rmv, iv) };
    let t = b.and::<W128>(s1, s3);
    let n = b.not::<W128>(s3);
    let o = b.and::<W128>(s2, n);
    let lo = b.or::<W128>(t, o);
    b.set(sem::xmm_ref(dst), lo);
    let hi = if d.vex_l {
        let h1: B::V<W128> = b.get(sem::ymm_hi_ref(vvv_x(d)));
        let rh = rx_hi(b, ea)?;
        let ih: B::V<W128> = b.get(sem::ymm_hi_ref(is4_x(d)));
        let (h2, h3) = if d.vex_w { (ih, rh) } else { (rh, ih) };
        let t = b.and::<W128>(h1, h3);
        let n = b.not::<W128>(h3);
        let o = b.and::<W128>(h2, n);
        b.or::<W128>(t, o)
    } else {
        b.konst::<W128>(0)
    };
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

/// VPERMIL2PS/PD の 128 ビットレーン内演算。`s1`/`s2` がデータ
/// ソース、`ctrl` が選択子。選択はレーン内に閉じ、M2Z で 0 を
/// 選べる。
fn vpermil2_val<B: Backend>(
    b: &mut B,
    fbits: u32,
    m2z: u8,
    s1: B::V<W128>,
    s2: B::V<W128>,
    ctrl: B::V<W128>,
) -> B::V<W128> {
    let idx_bits = if fbits == 32 { 2 } else { 1 };
    let idx_at = if fbits == 32 { 0 } else { 1 };
    let shmul = b.konst::<W128>(u128::from(fbits.trailing_zeros()));
    let maskv = b.konst::<W128>((1u128 << fbits) - 1);
    let zv = b.konst::<W128>(0);
    let mut acc = b.konst::<W128>(0);
    for i in 0..(128 / fbits) {
        let base = i * fbits;
        let idx = lane128(b, ctrl, base + idx_at, idx_bits);
        let sh = b.shl::<W128>(idx, shmul);
        let ashift = b.shr_l::<W128>(s1, sh);
        let a = b.and::<W128>(ashift, maskv);
        let cshift = b.shr_l::<W128>(s2, sh);
        let c = b.and::<W128>(cshift, maskv);
        let sb = lane128(b, ctrl, base + 2, 1);
        let use_s2 = nez::<B, W128>(b, sb);
        let mut v = b.select::<W128>(use_s2, c, a);
        let mb = lane128(b, ctrl, base + 3, 1);
        let zero = match m2z & 3 {
            2 => nez::<B, W128>(b, mb),
            3 => eqz::<B, W128>(b, mb),
            _ => bool_k(b, false),
        };
        v = b.select::<W128>(zero, zv, v);
        acc = put_lane128(b, acc, v, base, fbits);
    }
    acc
}

/// VPERMIL2PS/PD。src1=vvvv。W=0 は src2=r/m・選択子=is4、
/// W=1 は逆。
pub fn vpermil2<B: Backend>(
    b: &mut B,
    fbits: u32,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let m2z = (d.imm & 3) as u8;
    let s1: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    let rmv = rx(b, ea, 128)?;
    let iv: B::V<W128> = b.get(sem::xmm_ref(is4_x(d)));
    let (s2, ctrl) = if d.vex_w { (iv, rmv) } else { (rmv, iv) };
    let lo = vpermil2_val(b, fbits, m2z, s1, s2, ctrl);
    b.set(sem::xmm_ref(dst), lo);
    let hi = if d.vex_l {
        let h1: B::V<W128> = b.get(sem::ymm_hi_ref(vvv_x(d)));
        let rh = rx_hi(b, ea)?;
        let ih: B::V<W128> = b.get(sem::ymm_hi_ref(is4_x(d)));
        let (h2, hc) = if d.vex_w { (ih, rh) } else { (rh, ih) };
        vpermil2_val(b, fbits, m2z, h1, h2, hc)
    } else {
        b.konst::<W128>(0)
    };
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

/// 丸めのなじまない大きい値はそのまま返す frint のジェネリック版
/// （frint_f32/frint_f64 と同じ近似）。rm は softfloat 値
/// （0=RNE 1=RTZ 2=RDN 3=RUP 4=RMM）。
fn frint_g<B: Backend, F: Width>(b: &mut B, a: B::V<F>, rm: u8) -> B::V<F> {
    let lim = b.konst::<F>(F::from_u128(if F::BITS == 32 {
        0x5f00_0000
    } else {
        0x43e0_0000_0000_0000
    }));
    let kz = b.konst::<F>(F::from_u128(0));
    let abs = b.fsgnjx::<F>(a, kz);
    let small = b.flt::<F>(abs, lim);
    let i = b.fcvt_s64::<F>(a, rm);
    let r = b.fcvt_from_s64::<F>(i, RM_RNE);
    let via_int = b.select::<F>(small, r, a);
    let ordered = b.feq::<F>(a, a);
    b.select::<F>(ordered, via_int, a)
}

/// VFRCZ の 128 ビットチャンク — 各レーン `v - trunc(v)`。
fn vfrcz128<B: Backend, F: Width>(
    b: &mut B,
    lanes: u32,
    sv: B::V<W128>,
    get: FLaneGet<B, F>,
    put: FLanePut<B, F>,
) -> B::V<W128> {
    let mut acc = b.konst::<W128>(0);
    for i in 0..lanes {
        let f = get(b, sv, i);
        let t = frint_g::<B, F>(b, f, 1); // RTZ = ゼロ方向
        let r = b.fsub::<F>(f, t);
        acc = put(b, acc, r, i);
    }
    acc
}

/// VFRCZPD/PS/SD/SS。dst = v - trunc(v)（小数部抽出）。
/// スカラ形はレーン 0 のみ計算して上位は 0 クリア。L=1 は
/// ymm も処理する（パック形のみ）。
pub fn vfrcz<B: Backend>(
    b: &mut B,
    pd: bool,
    scalar: bool,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    use polyisa_sem::{F32, F64};
    let dst = reg_x(d);
    let fbits = if pd { 64 } else { 32 };
    let sv = rx(b, ea, if scalar { fbits } else { 128 })?;
    let lo = if pd {
        vfrcz128::<B, F64>(b, if scalar { 1 } else { 2 }, sv, flane64, put_flane64)
    } else {
        vfrcz128::<B, F32>(b, if scalar { 1 } else { 4 }, sv, flane32, put_flane32)
    };
    if scalar {
        b.set(sem::xmm_ref(dst), lo);
        let z = b.konst::<W128>(0);
        b.set(sem::ymm_hi_ref(dst), z);
        return Ok(());
    }
    b.set(sem::xmm_ref(dst), lo);
    let hi = if d.vex_l {
        let sh = rx_hi(b, ea)?;
        if pd {
            vfrcz128::<B, F64>(b, 2, sh, flane64, put_flane64)
        } else {
            vfrcz128::<B, F32>(b, 4, sh, flane32, put_flane32)
        }
    } else {
        b.konst::<W128>(0)
    };
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

/// XOP パックシフト/ローテートの 128 ビットチャンク。カウントは
/// vvvv の対応レーン下位 8 ビット（符号付き: 正=左/左ローテート、
/// 負=右）。kind: 0=算術(vpsha)、1=論理(vpshl)、2=ローテート(vprot)。
fn vpsh_chunk<B: Backend>(
    b: &mut B,
    kind: u8,
    ebits: u32,
    sv: B::V<W128>,
    cv: B::V<W128>,
) -> B::V<W128> {
    let mut acc = b.konst::<W128>(0);
    let lanes = 128 / ebits;
    for i in 0..lanes {
        let off = i * ebits;
        let sh = b.konst::<W128>(off as u128);
        let lm = b.konst::<W128>((1u128 << ebits) - 1);
        let sl = b.shr_l::<W128>(sv, sh);
        let lane = b.and::<W128>(sl, lm);
        let csh = b.konst::<W128>(off as u128);
        let cl = b.shr_l::<W128>(cv, csh);
        let mff = b.konst::<W128>(0xFF);
        let cb = b.and::<W128>(cl, mff);
        let zero = b.konst::<W128>(0);
        let r = if kind == 2 {
            // ローテート量 = raw byte & (w-1)。負カウントの右回転は
            // (byte & mask) の左回転と同値（w が 256 を割るため）。
            let wk = b.konst::<W128>((ebits - 1) as u128);
            let n = b.and::<W128>(cb, wk);
            let wl = b.konst::<W128>(ebits as u128);
            let nr = b.sub::<W128>(wl, n);
            let lo = b.shl::<W128>(lane, n);
            let hi = b.shr_l::<W128>(lane, nr);
            let both = b.or::<W128>(lo, hi);
            b.and::<W128>(both, lm)
        } else {
            // 符号付きシフト: >=128 は負（右シフト）。
            let half = b.konst::<W128>(128);
            let neg = b.cmp::<W128>(Cmp::GeU, cb, half);
            let bk = b.konst::<W128>(256);
            let mag = b.sub::<W128>(bk, cb);
            let cmag = b.select::<W128>(neg, mag, cb);
            let sl2 = b.shl::<W128>(lane, cmag);
            let left = b.and::<W128>(sl2, lm);
            let base = b.shr_l::<W128>(lane, cmag);
            // 算術右シフトの符号繰り返し。cmag>=w では全 1。
            let top = b.konst::<W128>(1u128 << (ebits - 1));
            let tb = b.and::<W128>(lane, top);
            let sbit = b.cmp::<W128>(Cmp::Ne, tb, zero);
            let wv = b.konst::<W128>(ebits as u128);
            let big = b.cmp::<W128>(Cmp::GeU, cmag, wv);
            let sc = b.select::<W128>(big, wv, cmag);
            let rem = b.sub::<W128>(wv, sc);
            let fsh = b.shl::<W128>(lm, rem);
            let fill = b.and::<W128>(fsh, lm);
            let right = if kind == 0 {
                let f = b.select::<W128>(sbit, fill, zero);
                b.or::<W128>(base, f)
            } else {
                base
            };
            b.select::<W128>(neg, right, left)
        };
        let pos = b.konst::<W128>(off as u128);
        let pr = b.shl::<W128>(r, pos);
        acc = b.or::<W128>(acc, pr);
    }
    acc
}

/// VPSHA*/VPSHL*/VPROT*。dest=reg。W=0 は src=r/m・cnt=vvvv、
/// W=1 は src=vvvv・cnt=r/m（APM vol.6 Table 1-4 の 3 オペランド
/// 配置）。kind: 0=算術右(vpsha)、1=論理(vpshl)、2=ローテート(vprot)。
pub fn vpsh<B: Backend>(
    b: &mut B,
    kind: u8,
    ebits: u32,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let rmv = rx(b, ea, 128)?;
    let hv: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    let (sv, cv) = if d.vex_w { (hv, rmv) } else { (rmv, hv) };
    let lo = vpsh_chunk::<B>(b, kind, ebits, sv, cv);
    b.set(sem::xmm_ref(dst), lo);
    let z = b.konst::<W128>(0);
    b.set(sem::ymm_hi_ref(dst), z);
    Ok(())
}

/// VPCOM* — 各レーン src1(vvvv) と src2(r/m) を imm8[2:0] の述語で
/// 比較し、真なら全 1・偽なら全 0 を書く。`ebits` は要素幅、
/// `sgn` は符号付き比較か。述語: 0=lt 1=le 2=gt 3=ge 4=eq 5=ne
/// 6=false 7=true。
pub fn vpcom<B: Backend>(
    b: &mut B,
    ebits: u32,
    sgn: bool,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let hv: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    let sv = rx(b, ea, 128)?;
    let pred = (d.imm & 7) as u8;
    let mut acc = b.konst::<W128>(0);
    let lanes = 128 / ebits;
    for i in 0..lanes {
        let off = i * ebits;
        let sh = b.konst::<W128>(off as u128);
        let lm = b.konst::<W128>((1u128 << ebits) - 1);
        let a1 = b.shr_l::<W128>(hv, sh);
        let a = b.and::<W128>(a1, lm);
        let s1 = b.shr_l::<W128>(sv, sh);
        let c = b.and::<W128>(s1, lm);
        // 符号比較は符号ビットを反転した上で符号なし比較に帰着する。
        let (a, c) = if sgn {
            let sign = b.konst::<W128>(1u128 << (ebits - 1));
            (b.xor::<W128>(a, sign), b.xor::<W128>(c, sign))
        } else {
            (a, c)
        };
        let lz = b.konst::<W128>(0);
        let lane = match pred {
            0 => {
                let t = b.cmp::<W128>(Cmp::LtU, a, c);
                b.select::<W128>(t, lm, lz)
            }
            1 => {
                let t = b.cmp::<W128>(Cmp::GtU, a, c);
                b.select::<W128>(t, lz, lm)
            }
            2 => {
                let t = b.cmp::<W128>(Cmp::GtU, a, c);
                b.select::<W128>(t, lm, lz)
            }
            3 => {
                let t = b.cmp::<W128>(Cmp::LtU, a, c);
                b.select::<W128>(t, lz, lm)
            }
            4 => {
                let t = b.cmp::<W128>(Cmp::Eq, a, c);
                b.select::<W128>(t, lm, lz)
            }
            5 => {
                let t = b.cmp::<W128>(Cmp::Ne, a, c);
                b.select::<W128>(t, lm, lz)
            }
            6 => lz,
            _ => lm,
        };
        let pos = b.konst::<W128>(off as u128);
        let pr = b.shl::<W128>(lane, pos);
        acc = b.or::<W128>(acc, pr);
    }
    b.set(sem::xmm_ref(dst), acc);
    let z = b.konst::<W128>(0);
    b.set(sem::ymm_hi_ref(dst), z);
    Ok(())
}

/// x86 の RC フィールド（0=RNE 1=RDN 2=RUP 3=RTZ）を softfloat
/// の丸め値（0=RNE 1=RTZ 2=RDN 3=RUP 4=RMM）へ写す。
fn x86_rm(rc: u64) -> u8 {
    [0u8, 2, 3, 1, 0, 0, 0, 0][(rc & 7) as usize]
}

/// F32 値を F16 へ変換する。`mx` が Some なら MXCSR の全値で、
/// RC（bits 14:13）に従って 4 候補を選ぶ。None なら `rm` 固定。
fn cvtps2ph_one<B: Backend>(
    b: &mut B,
    f: B::V<polyisa_sem::F32>,
    mx: Option<B::V<W32>>,
    rm: u8,
) -> B::V<polyisa_sem::F16> {
    use polyisa_sem::{F16, F32};
    let Some(mx) = mx else {
        return b.fcvt_ff::<F32, F16>(f, rm);
    };
    let sh = b.konst::<W32>(13);
    let m = b.konst::<W32>(3);
    let shr = b.shr_l::<W32>(mx, sh);
    let rc = b.and::<W32>(shr, m);
    // x86 RC 順（RNE/RDN/RUP/RTZ）に候補を並べて select する。
    let rms = [0u8, 2, 3, 1];
    let mut g = b.fcvt_ff::<F32, F16>(f, rms[0]);
    for (k, r) in rms.iter().enumerate().skip(1) {
        let cand = b.fcvt_ff::<F32, F16>(f, *r);
        let kk = b.konst::<W32>(k as u32);
        let is = b.cmp::<W32>(Cmp::Eq, rc, kk);
        g = b.select::<F16>(is, cand, g);
    }
    g
}

/// VCVTPH2PS xmm/ymm, xmm/m64|m128。半精度を単精度へ展開する。
/// VEX.128 は下位 64 ビットの 4 要素、VEX.256 は全 128 ビットの
/// 8 要素を変換する。
pub fn vcvtph2ps<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    use polyisa_sem::{F16, F32};
    let dst = reg_x(d);
    let s = rx(b, ea, if d.vex_l { 128 } else { 64 })?;
    let n = if d.vex_l { 8 } else { 4 };
    let mut lo = b.konst::<W128>(0);
    let mut hi = b.konst::<W128>(0);
    for i in 0..n {
        let l = lane128(b, s, i * 16, 16);
        let h: B::V<W16> = b.trunc::<W128, W16>(l);
        let f = b.trunc::<W16, F16>(h);
        let g = b.fcvt_ff::<F16, F32>(f, 0);
        let w = b.trunc::<F32, W32>(g);
        let w128 = b.zext::<W32, W128>(w);
        if i < 4 {
            lo = put_lane128(b, lo, w128, i * 32, 32);
        } else {
            hi = put_lane128(b, hi, w128, (i - 4) * 32, 32);
        }
    }
    b.set(sem::xmm_ref(dst), lo);
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

/// VCVTPS2PH xmm/m64|m128, xmm/ymm, imm8。単精度を半精度へ縮める。
/// 丸めは imm8[1:0]（x86 RC）、imm8[2]=1 なら MXCSR.RC を使う。
/// 宛先は Ev（VEX.128 では xmm/m64、VEX.256 では xmm/m128）。
pub fn vcvtps2ph<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    use polyisa_sem::{F16, F32};
    // SDM Table 5-12: imm8[1:0]=RC、imm8[2]=1 で MXCSR.RC を使う。
    // imm8[7:3] は無視。
    let (mx, rm) = if d.imm & 0x04 != 0 {
        (Some(b.get::<W32>(sem::mxcsr_ref())), 0)
    } else {
        (None, x86_rm(d.imm & 3))
    };
    let src = reg_x(d);
    let n = if d.vex_l { 8 } else { 4 };
    let mut out = b.konst::<W128>(0);
    for i in 0..n {
        let chunk: B::V<W128> = if i < 4 {
            b.get(sem::xmm_ref(src))
        } else {
            b.get(sem::ymm_hi_ref(src))
        };
        let l = lane128(b, chunk, (i % 4) * 32, 32);
        let w: B::V<W32> = b.trunc::<W128, W32>(l);
        let f = b.trunc::<W32, F32>(w);
        let g = cvtps2ph_one(b, f, mx, rm);
        let h = b.trunc::<F16, W16>(g);
        let h128 = b.zext::<W16, W128>(h);
        out = put_lane128(b, out, h128, i * 16, 16);
    }
    wx(b, ea, if d.vex_l { 128 } else { 64 }, out)?;
    if let Rm::Reg(g) = ea {
        let z = b.konst::<W128>(0);
        b.set(sem::ymm_hi_ref(Xmm(g.0)), z);
    }
    Ok(())
}

/// ADCX/ADOX r, r/m。`of` が真なら ADOX（OF を桁上げ入力・出力に
/// 使う）、偽なら ADCX（CF）。結果は dst = dst + src + carry。
/// 更新するのは対応する旗だけで、他のフラグは保つ。
fn adcx_w<B: Backend, W: Hw, W2: Width>(
    b: &mut B,
    of: bool,
    g: Gpr,
    ea: &Rm<B::V<W64>>,
    d: &MapDec,
) -> Flow<B> {
    let src = rd_w::<B, W>(b, ea, d)?;
    let dst = W::get(b, g, d);
    let c = if of { read_of(b) } else { read_cf(b) };
    let zero = b.konst::<W>(W::from_u128(0));
    let one = b.konst::<W>(W::from_u128(1));
    let cin = b.select::<W>(c, one, zero);
    let d2 = b.zext::<W, W2>(dst);
    let s2 = b.zext::<W, W2>(src);
    let c2 = b.zext::<W, W2>(cin);
    let t = b.add::<W2>(d2, s2);
    let t = b.add::<W2>(t, c2);
    let v: B::V<W> = b.trunc::<W2, W>(t);
    let top = b.konst::<W2>(W2::from_u128(1u128 << W::BITS));
    let co = b.and::<W2>(t, top);
    let zero2 = b.konst::<W2>(W2::from_u128(0));
    let cout = b.cmp::<W2>(Cmp::Ne, co, zero2);
    W::put(b, g, d, v);
    let bit = if of { sem::FLAG_OF } else { sem::FLAG_CF };
    let old: B::V<W32> = b.get(eflags_ref());
    let mask = b.konst::<W32>(!bit);
    let f = b.and::<W32>(old, mask);
    let nv = pick(b, cout, bit);
    let f = b.or::<W32>(f, nv);
    b.set(eflags_ref(), f);
    Ok(())
}

/// ADCX/ADOX r, r/m。
pub fn adcx<B: Backend>(
    b: &mut B,
    w: u8,
    of: bool,
    g: Gpr,
    ea: &Rm<B::V<W64>>,
    d: &MapDec,
) -> Flow<B> {
    match w {
        16 => adcx_w::<B, W16, W32>(b, of, g, ea, d),
        64 => adcx_w::<B, W64, W128>(b, of, g, ea, d),
        _ => adcx_w::<B, W32, W64>(b, of, g, ea, d),
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
/// ENTER の仮想 SP プッシュ。ss:off に値を書き込むだけで SP
/// レジスタは更新しない。80286 は ENTER 全体を仮想 SP で処理し、
/// SP へのコミットは最後に行う（SST 実測。限界例外では SP が
/// 初期値のまま残り、例外フレームは元の SP-6 に積まれる。ただし
/// コミット済みの push のメモリ書き込みは残る）。
fn enter_store<B: Backend>(
    b: &mut B,
    w: u8,
    sg: B::V<W64>,
    off: B::V<W64>,
    wseg: Option<u64>,
    v64: B::V<W64>,
) -> Flow<B> {
    let a = b.add::<W64>(off, sg);
    let ws = wseg.map(|s| (s, off));
    match w {
        16 => {
            let v: B::V<W16> = b.trunc::<W64, W16>(v64);
            decode::mem_store(b, a, ws, v)?
        }
        64 => decode::mem_store::<B, W64>(b, a, ws, v64)?,
        _ => {
            let v: B::V<W32> = b.trunc::<W64, W32>(v64);
            decode::mem_store(b, a, ws, v)?
        }
    }
    Ok(())
}

pub fn enter<B: Backend>(b: &mut B, w: u8, frame: u64, level: u64, sa: u8, sseg: u64) -> Flow<B> {
    let lvl = level & 31;
    // ポインタ演算（SP/フレーム）はスタックアドレスサイズ `sa` 幅、
    // push する値の幅は `w`（オペランドサイズ）。
    let m: u64 = match sa {
        16 => 0xffff,
        64 => u64::MAX,
        _ => 0xffff_ffff,
    };
    let mm = b.konst::<W64>(m);
    let nmm = b.konst::<W64>(!m);
    let sz = u64::from(w / 8);
    let bytes = b.konst::<W64>(sz);
    let sg = b.konst::<W64>(sseg);
    // push する BP は被演算子幅の全値（o32 では EBP の上位語も
    // 積まれる。SST 80386 実測）。鎖の番地は `sa` 幅に潰す。
    let rbp = sem::read64(b, Gpr(5));
    let bp = b.and::<W64>(rbp, mm);
    let sp0 = sem::read64(b, Gpr(4));
    let sp0 = b.and::<W64>(sp0, mm);
    // sa==16 では読み書きとも SS の限界例外が効く（80286/80386
    // 実測。コミット済みの push は例外後も残る）。
    let wseg = (sa == 16).then_some(sseg | decode::WSEG_SS);
    let wseg_r = wseg;
    let mut vsp = b.sub::<W64>(sp0, bytes);
    vsp = b.and::<W64>(vsp, mm);
    enter_store(b, w, sg, vsp, wseg, rbp)?;
    let framep = vsp;
    if lvl > 0 {
        let mut p = bp;
        for _ in 1..lvl {
            let pv = b.sub::<W64>(p, bytes);
            p = b.and::<W64>(pv, mm);
            let pa = b.add::<W64>(p, sg);
            let ws = wseg_r.map(|s| (s, p));
            let v = match w {
                16 => {
                    let v: B::V<W16> = decode::mem_load(b, pa, ws)?;
                    b.zext::<W16, W64>(v)
                }
                64 => decode::mem_load::<B, W64>(b, pa, ws)?,
                _ => {
                    let v: B::V<W32> = decode::mem_load(b, pa, ws)?;
                    b.zext::<W32, W64>(v)
                }
            };
            // 鎖要素は値幅 `w` のまま積む。`mm`（スタック番地幅）
            // を被演算子に掛けると o32 の双語要素の上位が消える
            // （SST 80386 実測）。
            let sub = b.sub::<W64>(vsp, bytes);
            vsp = b.and::<W64>(sub, mm);
            enter_store(b, w, sg, vsp, wseg, v)?;
        }
        let sub = b.sub::<W64>(vsp, bytes);
        vsp = b.and::<W64>(sub, mm);
        enter_store(b, w, sg, vsp, wseg, framep)?;
    }
    // フレームポインタは被演算子幅で書く。sa==16 の 386 実測では
    // o32 enter の EBP に折り返した SP が零拡張で入る。
    let nbp = if w == 16 {
        let rbp = sem::read64(b, Gpr(5));
        let bhi = b.and::<W64>(rbp, nmm);
        b.or::<W64>(bhi, framep)
    } else {
        framep
    };
    sem::write64(b, Gpr(5), nbp);
    let cur = sem::read64(b, Gpr(4));
    let fv = b.konst::<W64>(frame & m);
    let sub = b.sub::<W64>(vsp, fv);
    let lo = b.and::<W64>(sub, mm);
    let shi = b.and::<W64>(cur, nmm);
    let nsp = b.or::<W64>(shi, lo);
    sem::write64(b, Gpr(4), nsp);
    Ok(())
}

/// LEAVE（16 ビットスタックアドレッシング）。SP:=BP のコミットは
/// pop の読み込み成功後に行う（80286 実測。pop が限界例外を起こすと
/// SP は元値のまま残り、例外フレームは元の SP-6 に積まれる）。
/// 戻り値は新しい BP（値幅 `w`）。
pub fn leave16<B: Backend>(b: &mut B, w: u8, sseg: u64) -> Result<B::V<W64>, B::Exit> {
    let m16 = b.konst::<W64>(0xffff);
    let rbp = sem::read64(b, Gpr(5));
    let off = b.and::<W64>(rbp, m16);
    let sg = b.konst::<W64>(sseg);
    let a = b.add::<W64>(off, sg);
    let wseg = Some((sseg | decode::WSEG_SS, off));
    let v: B::V<W64> = if w == 16 {
        let v: B::V<W16> = decode::mem_load(b, a, wseg)?;
        b.zext::<W16, W64>(v)
    } else {
        let v: B::V<W32> = decode::mem_load(b, a, wseg)?;
        b.zext::<W32, W64>(v)
    };
    // SP = BP + w/8（16 ビット折り返し、上位保持）。
    let sz = b.konst::<W64>(u64::from(w / 8));
    let add = b.add::<W64>(off, sz);
    let nlo = b.and::<W64>(add, m16);
    let rsp = sem::read64(b, Gpr(4));
    let hm = b.konst::<W64>(!0xffffu64);
    let hi = b.and::<W64>(rsp, hm);
    let nsp = b.or::<W64>(hi, nlo);
    sem::write64(b, Gpr(4), nsp);
    Ok(v)
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
    Ins,
    Outs,
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
/// REP の CX デクリメント。イテレーションの先頭で行う（80286
/// 実測。アクセスが限界例外を起こしてもデクリメントは残る）。
fn rep_dec<B: Backend>(b: &mut B, d: &MapDec) {
    let m = asize_mask(d.asize);
    let mm = b.konst::<W64>(m);
    let c0 = sem::read64(b, Gpr(1));
    let c0m = b.and::<W64>(c0, mm);
    let one = b.konst::<W64>(1);
    let dec = b.sub::<W64>(c0m, one);
    let c1 = b.and::<W64>(dec, mm);
    let nm = b.konst::<W64>(!m);
    let hi = b.and::<W64>(c0, nm);
    let nv = b.or::<W64>(hi, c1);
    sem::write64(b, Gpr(1), nv);
}

/// REP イテレーション末尾の分岐。`cond_zf` は REPE/REPNE の ZF 条件。
fn rep_tail<B: Backend>(b: &mut B, d: &MapDec, eip: u32, cond_zf: u8) -> Flow<B> {
    let m = asize_mask(d.asize);
    let mm = b.konst::<W64>(m);
    let c0 = sem::read64(b, Gpr(1));
    let c1 = b.and::<W64>(c0, mm);
    let one = b.konst::<W64>(1);
    let zero = b.konst::<W64>(0);
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
    seg_ss: bool,
    es: u64,
    rep: bool,
    zf_cond: u8,
    real16: bool,
    atomic: bool,
) -> Flow<B> {
    let asize = d.asize;
    // 実モードの文字列アクセスはオフセット（SI/DI）を 64K で折り返す
    // か限界例外（`seg_limit`）。DS 上書き側は SS のとき例外が #SS。
    // `d.asize` は保護モードの 0x67 でも 16 になるので実モードを
    // 併せて要求する。
    let mut si = sptr(b, Gpr(6), asize);
    let mut di = sptr(b, Gpr(7), asize);
    let wseg_at = |seg: u64, off: B::V<W64>| {
        if !real16 {
            return None;
        }
        match asize {
            16 => Some((seg, off)),
            32 => Some((seg | decode::WSEG_32, off)),
            _ => None,
        }
    };
    let sf = seg | if seg_ss { decode::WSEG_SS } else { 0 };
    let wseg_s = wseg_at(sf, si);
    let wseg_d = wseg_at(es, di);
    let sg = b.konst::<W64>(seg);
    si = b.add::<W64>(si, sg);
    let eg = b.konst::<W64>(es);
    di = b.add::<W64>(di, eg);
    let sz = u64::from(W::BITS / 8);
    // 80286 系は要素ごとのポインタ更新をアクセスより先にコミット
    // する（アクセスが限界例外を起こしても更新が残る。SST 実測）。
    // 80386 系は全アクセスの限界を事前検査するので違反時は更新も
    // デクリメントも起きない（str_op 側で検査済み）。
    // REP 実行中のストアが限界例外を起こすと、80286 はイテレーション
    // の後始末として CX をもう一度デクリメントしてから例外を取る
    // （合計 -2。ロード系の失敗ではイテレーション先頭の -1 のみ。
    // SST 実測）。最終アクセスになるストアにだけ適用する。
    let done = |b: &mut B, r: Flow<B>| -> Flow<B> {
        if rep && !atomic && r.is_err() {
            rep_dec(b, d);
        }
        r
    };
    match kind {
        Str::Movs => {
            str_bump(b, Gpr(6), asize, sz);
            let v: B::V<W> = decode::mem_load(b, si, wseg_s)?;
            str_bump(b, Gpr(7), asize, sz);
            let r = decode::mem_store(b, di, wseg_d, v);
            done(b, r)?;
        }
        Str::Stos => {
            str_bump(b, Gpr(7), asize, sz);
            let acc = W::get(b, Gpr(0), d);
            let r = decode::mem_store(b, di, wseg_d, acc);
            done(b, r)?;
        }
        Str::Lods => {
            str_bump(b, Gpr(6), asize, sz);
            let v: B::V<W> = decode::mem_load(b, si, wseg_s)?;
            W::put(b, Gpr(0), d, v);
        }
        Str::Scas => {
            str_bump(b, Gpr(7), asize, sz);
            let acc = W::get(b, Gpr(0), d);
            let t: B::V<W> = decode::mem_load(b, di, wseg_d)?;
            let v = b.sub::<W>(acc, t);
            update_sub_flags(b, acc, t, v);
        }
        Str::Cmps => {
            // 80286 実測: CMPS は DI 側（ES）の更新とロードが先、
            // SI 側の更新とロードが後（DI ロードが限界例外でも SI は
            // 未更新、SI ロードの例外では両方更新済み）。また REP の
            // CX デクリメントは DI ロードの後に置かれる（DI ロードの
            // 例外ではデクリメントされない）。
            str_bump(b, Gpr(7), asize, sz);
            let t: B::V<W> = decode::mem_load(b, di, wseg_d)?;
            if rep && !atomic {
                rep_dec(b, d);
            }
            str_bump(b, Gpr(6), asize, sz);
            let x: B::V<W> = decode::mem_load(b, si, wseg_s)?;
            let v = b.sub::<W>(x, t);
            update_sub_flags(b, x, t, v);
        }
        Str::Ins => {
            // INS: DX のポートから読み ES:(E)DI へ書く（80186）。
            str_bump(b, Gpr(7), asize, sz);
            let dx = decode::grd16(b, Gpr(2));
            let port: B::V<W64> = b.zext::<W16, W64>(dx);
            let v = b.port_in::<W>(port)?;
            let r = decode::mem_store(b, di, wseg_d, v);
            done(b, r)?;
        }
        Str::Outs => {
            // OUTS: DS:(E)SI から読み DX のポートへ書く（80186）。
            str_bump(b, Gpr(6), asize, sz);
            let dx = decode::grd16(b, Gpr(2));
            let port: B::V<W64> = b.zext::<W16, W64>(dx);
            let v: B::V<W> = decode::mem_load(b, si, wseg_s)?;
            b.port_out::<W>(port, v)?;
        }
    }
    if rep {
        rep_tail(b, d, eip, zf_cond)
    } else {
        Ok(())
    }
}

/// 文字列命令（MOVS/STOS/LODS/SCAS/CMPS）。rep≠0 で要素ごとの繰り返し。
#[allow(clippy::too_many_arguments)]
pub fn str_op<B: Backend>(
    b: &mut B,
    kind: Str,
    w: u8,
    d: &MapDec,
    eip: u32,
    seg: u64,
    seg_ss: bool,
    es: u64,
    real16: bool,
) -> Flow<B> {
    let rep = d.rep != 0;
    // REPE/REPNE の ZF 条件は SCAS/CMPS にだけ効く。
    let zf_cond = match kind {
        Str::Scas | Str::Cmps if d.rep == 0xF3 => 1,
        Str::Scas | Str::Cmps if d.rep == 0xF2 => 2,
        _ => 0,
    };
    // 80386 系は全アクセスのセグメント限界を事前検査し、違反では
    // CX デクリメントも SI/DI 更新も起きない（SST 80386 実測）。
    let atomic = real16
        && matches!(d.asize, 16 | 32)
        && b.param::<crate::FaultAtomicParam>() == crate::FAULT_ATOMIC_ATOMIC;
    let precheck = |b: &mut B| -> Flow<B> {
        if !atomic {
            return Ok(());
        }
        let sz = u64::from(w / 8);
        let w32 = if d.asize == 32 { decode::WSEG_32 } else { 0 };
        let sf = seg | if seg_ss { decode::WSEG_SS } else { 0 } | w32;
        let esw = es | w32;
        let si_hit = matches!(kind, Str::Movs | Str::Lods | Str::Cmps | Str::Outs);
        let di_hit = matches!(
            kind,
            Str::Movs | Str::Stos | Str::Scas | Str::Cmps | Str::Ins
        );
        // 検査順はアクセス順（CMPS は DI 側が先）。
        if matches!(kind, Str::Cmps) && di_hit {
            let di = sptr(b, Gpr(7), d.asize);
            decode::seg_limit_chk_n(b, di, esw, sz)?;
        }
        if si_hit {
            let si = sptr(b, Gpr(6), d.asize);
            decode::seg_limit_chk_n(b, si, sf, sz)?;
        }
        if di_hit && !matches!(kind, Str::Cmps) {
            let di = sptr(b, Gpr(7), d.asize);
            decode::seg_limit_chk_n(b, di, esw, sz)?;
        }
        Ok(())
    };
    let iter = |b: &mut B| -> Flow<B> {
        match w {
            16 => str_w::<B, W16>(
                b, kind, d, eip, seg, seg_ss, es, rep, zf_cond, real16, atomic,
            ),
            64 => str_w::<B, W64>(
                b, kind, d, eip, seg, seg_ss, es, rep, zf_cond, real16, atomic,
            ),
            8 => str_w::<B, W8>(
                b, kind, d, eip, seg, seg_ss, es, rep, zf_cond, real16, atomic,
            ),
            _ => str_w::<B, W32>(
                b, kind, d, eip, seg, seg_ss, es, rep, zf_cond, real16, atomic,
            ),
        }
    };
    if rep {
        // カウンタが 0 なら何もせず次へ進む。
        let c = sptr(b, Gpr(1), d.asize);
        let z = b.konst::<W64>(0);
        let active = b.cmp::<W64>(Cmp::Ne, c, z);
        b.if_then(active, |b| {
            if atomic {
                // 限界違反では CX も SI/DI も変わらない（80386 実測）。
                precheck(b)?;
                rep_dec(b, d);
            } else if !matches!(kind, Str::Cmps) {
                // CMPS だけは CX デクリメントが DI ロードの後に置かれる
                // （80286 実測。DI ロードの限界例外では減らない）。
                rep_dec(b, d);
            }
            iter(b)
        })
    } else {
        precheck(b)?;
        iter(b)
    }
}

// ---- moffs MOV ----

/// MOV AL/eAX, [moffs]（A0/A1）。
pub fn mov_moffs_ld<B: Backend>(
    b: &mut B,
    w: u8,
    moffs: u64,
    seg: u64,
    seg_ss: bool,
    d: &MapDec,
    real16: bool,
) -> Flow<B> {
    let mraw = b.konst::<W64>(moffs & asize_mask(d.asize));
    let sg = b.konst::<W64>(seg);
    let addr = b.add::<W64>(mraw, sg);
    let sf = seg | if seg_ss { decode::WSEG_SS } else { 0 };
    let wseg = if real16 {
        match d.asize {
            16 => Some((sf, mraw)),
            32 => Some((sf | decode::WSEG_32, mraw)),
            _ => None,
        }
    } else {
        None
    };
    match w {
        8 => {
            let v: B::V<W8> = decode::mem_load(b, addr, wseg)?;
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
pub fn mov_moffs_st<B: Backend>(
    b: &mut B,
    w: u8,
    moffs: u64,
    seg: u64,
    seg_ss: bool,
    d: &MapDec,
    real16: bool,
) -> Flow<B> {
    let mraw = b.konst::<W64>(moffs & asize_mask(d.asize));
    let sg = b.konst::<W64>(seg);
    let addr = b.add::<W64>(mraw, sg);
    let sf = seg | if seg_ss { decode::WSEG_SS } else { 0 };
    let wseg = if real16 {
        match d.asize {
            16 => Some((sf, mraw)),
            32 => Some((sf | decode::WSEG_32, mraw)),
            _ => None,
        }
    } else {
        None
    };
    match w {
        8 => {
            let v = W8::get(b, Gpr(0), d);
            decode::mem_store(b, addr, wseg, v)?;
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
    // CF はビット値、OF は未定義（386EX 実測では 0 に落ちる）。
    let clr = b.konst::<W32>(!(sem::FLAG_CF | sem::FLAG_OF));
    let cleared = b.and::<W32>(old, clr);
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
    mod_at_ea: bool,
) -> Flow<B> {
    // r/m のビット列：メモリなら n/W::BITS 要素分アドレスを進める（負も可）。
    let lg_bits = W::BITS.trailing_zeros();
    let lg_bytes = (W::BITS / 8).trailing_zeros();
    let sh = b.konst::<W64>(u64::from(lg_bits));
    let off = b.shr_a::<W64>(n, sh);
    let bm = b.konst::<W64>(u64::from(W::BITS - 1));
    let idx = b.and::<W64>(n, bm);
    let e2;
    let target = if let Rm::Mem { a, wseg } = ea {
        if mod_at_ea {
            // 386 実モード実測: Ib 形のメモリオペランドはビット列
            // オフセットでアドレスをずらさず、EA 上のオペランドに
            // mod 幅で作用する。
            ea
        } else {
            let bs = b.konst::<W64>(u64::from(lg_bytes));
            let ob = b.shl::<W64>(off, bs);
            match decode::wseg_off(b, *a, *wseg) {
                // 実モード: ずらしたオフセットを折り返して限界検査する。
                Some((off_raw, sv)) => {
                    let (seg, _) = wseg.unwrap();
                    let no = b.add::<W64>(off_raw, ob);
                    let m = if seg & decode::WSEG_32 != 0 {
                        b.konst::<W64>(0xFFFF_FFFF)
                    } else {
                        b.konst::<W64>(0xFFFF)
                    };
                    let a2 = b.and::<W64>(no, m);
                    let na = b.add::<W64>(a2, sv);
                    e2 = Rm::Mem {
                        a: na,
                        wseg: Some((seg, no)),
                    };
                }
                None => {
                    let na = b.add::<W64>(*a, ob);
                    e2 = Rm::Mem { a: na, wseg: *wseg };
                }
            }
            &e2
        }
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
    mod_at_ea: bool,
) -> Flow<B> {
    match w {
        16 => bt_w::<B, W16>(b, op, ea, d, n, mod_at_ea),
        64 => bt_w::<B, W64>(b, op, ea, d, n, mod_at_ea),
        _ => bt_w::<B, W32>(b, op, ea, d, n, mod_at_ea),
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
    // 読み出しは count=0 でも行う: 386 は n==0 でもデストの EA を
    // 検証し、限界違反なら例外になる（SST 80386 実測）。
    let t = rd_w::<B, W>(b, ea, d)?;
    {
        let s = W::get(b, src, d);
        let bits_k = b.konst::<W>(W::from_u128(u128::from(W::BITS)));
        let wm = b.sub::<W>(bits_k, n);
        let one = b.konst::<W>(W::from_u128(1));
        // n > オペランド幅（W16 で 17-31）: 386 実測ではデストが
        // 押し出されて残るのは src の n-16 回転だけになる。
        let (v_norm, cf_norm, v_wide, cf_wide) = if left {
            let a = b.shl::<W>(t, n);
            let x = b.shr_l::<W>(s, wm);
            let vn = b.or::<W>(a, x);
            let cfv = b.shr_l::<W>(t, wm);
            let cf_n = b.and::<W>(cfv, one);
            // rol(src, n-16)
            let k = b.sub::<W>(n, bits_k);
            let bk = b.add::<W>(bits_k, bits_k);
            let k2 = b.sub::<W>(bk, n);
            let sa = b.shl::<W>(s, k);
            let sb = b.shr_l::<W>(s, k2);
            let vw = b.or::<W>(sa, sb);
            // CF は連結値 (t:s) の 2W-n ビット = src の 2W-n ビット。
            let bk2 = b.add::<W>(bits_k, bits_k);
            let cf_i2 = b.sub::<W>(bk2, n);
            let cfv2 = b.shr_l::<W>(s, cf_i2);
            let cf_w = b.and::<W>(cfv2, one);
            (vn, cf_n, vw, cf_w)
        } else {
            let a = b.shr_l::<W>(t, n);
            let x = b.shl::<W>(s, wm);
            let vn = b.or::<W>(a, x);
            let cf_idx = b.sub::<W>(n, one);
            let cfv = b.shr_l::<W>(t, cf_idx);
            let cf_n = b.and::<W>(cfv, one);
            // ror(src, n-16)
            let k = b.sub::<W>(n, bits_k);
            let bk = b.add::<W>(bits_k, bits_k);
            let k2 = b.sub::<W>(bk, n);
            let sa = b.shr_l::<W>(s, k);
            let sb = b.shl::<W>(s, k2);
            let vw = b.or::<W>(sa, sb);
            let cf_idx2 = b.sub::<W>(n, bits_k);
            let cf_idx2 = b.sub::<W>(cf_idx2, one);
            let cfv2 = b.shr_l::<W>(s, cf_idx2);
            let cf_w = b.and::<W>(cfv2, one);
            (vn, cf_n, vw, cf_w)
        };
        let over = b.cmp::<W>(Cmp::GtU, n, bits_k);
        let v0 = b.select::<W>(over, v_wide, v_norm);
        let cf_and = b.select::<W>(over, cf_wide, cf_norm);
        // count=0 でも宛先は書き戻される（値は不変）。32 ビット形では
        // この書き戻しが上位 32 ビットを消す（ホスト CPU 実測）。
        let v = b.select::<W>(nz, v0, t);
        wr_w::<B, W>(b, ea, d, v)?;
        // フラグは count!=0 のときだけ変わる（CF は追い出しビット）。
        b.if_then(nz, |b| {
            // CF: SHLD は元の w-n ビット、SHRD は n-1 ビット。
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
    }
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
    cnt: ShiftCnt,
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

fn cnt_v<B: Backend, W: Hw>(b: &mut B, cnt: ShiftCnt, d: &MapDec) -> B::V<W> {
    match cnt {
        ShiftCnt::Cl => {
            // CL。
            let cl = W8::get(b, Gpr(1), d);
            b.zext::<W8, W>(cl)
        }
        ShiftCnt::One => b.konst::<W>(W::from_u128(1)),
        ShiftCnt::Imm(i) => b.konst::<W>(W::from_u128(u128::from(i))),
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
                8 => {
                    let v: B::V<W8> = b.load::<W8>(a, sem::DATA_READ)?;
                    Ok(b.zext::<W8, W128>(v))
                }
                16 => {
                    let v: B::V<W16> = b.load::<W16>(a, sem::DATA_READ)?;
                    Ok(b.zext::<W16, W128>(v))
                }
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
    let v = lop_lane(b, op, a, c);
    b.set(sem::xmm_ref(dst), v);
    Ok(())
}

/// 128 ビットレーンの論理演算（レガシー形の `logic128` と
/// VEX 形の `vlogic` が共有する要素演算）。
fn lop_lane<B: Backend>(b: &mut B, op: Lop, a: B::V<W128>, c: B::V<W128>) -> B::V<W128> {
    match op {
        Lop::And => b.and::<W128>(a, c),
        Lop::Andn => {
            let na = b.not::<W128>(a);
            b.and::<W128>(na, c)
        }
        Lop::Or => b.or::<W128>(a, c),
        Lop::Xor => b.xor::<W128>(a, c),
    }
}

/// VEX.vvvv が指す XMM。
fn vvv_x(d: &MapDec) -> Xmm {
    Xmm(d.vex_v)
}

/// `ea` が指す YMM の上位 128 ビットを読む。レジスタ直接は
/// `ymm_hi`、メモリは `a + 16` からの 128 ビットロード。
fn rx_hi<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>) -> Result<B::V<W128>, B::Exit> {
    match ea {
        Rm::Reg(g) => Ok(b.get(sem::ymm_hi_ref(Xmm(g.0)))),
        Rm::Mem { a, .. } => {
            let a16 = madd(b, *a, 16);
            b.load::<W128>(a16, sem::DATA_READ)
        }
    }
}

/// `ea` が指す YMM の上位 128 ビットへ書く。
fn wx_hi<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>, v: B::V<W128>) -> Result<(), B::Exit> {
    match ea {
        Rm::Reg(g) => {
            b.set(sem::ymm_hi_ref(Xmm(g.0)), v);
            Ok(())
        }
        Rm::Mem { a, .. } => {
            let a16 = madd(b, *a, 16);
            b.store::<W128>(a16, v, sem::DATA_WRITE)
        }
    }
}

/// VEX の 128/256 ビット移動ロード（VMOVUPS/VMOVUPD/VMOVDQA/
/// VMOVDQU）。VEX.128 形は YMM 上位をゼロクリアする
/// （VEX 命令共通の不動点規則）。
pub fn vmov_x_w<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let v = rx(b, ea, 128)?;
    b.set(sem::xmm_ref(dst), v);
    let hi = if d.vex_l {
        rx_hi(b, ea)?
    } else {
        b.konst::<W128>(0)
    };
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

/// VEX の 128/256 ビット移動ストア。
pub fn vmov_w_x<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let v: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    wx(b, ea, 128, v)?;
    if d.vex_l {
        let hi: B::V<W128> = b.get(sem::ymm_hi_ref(reg_x(d)));
        wx_hi(b, ea, hi)?;
    } else if d.modrm >= 0xC0 {
        // L=0 の xmm→xmm ストアは宛先の上位 128 ビットをゼロにする。
        let z = b.konst::<W128>(0);
        b.set(sem::ymm_hi_ref(rm_x(d)), z);
    }
    Ok(())
}

/// VMOVSS/VMOVSD の読み込み。メモリ形は下位 `fbits` のみ読んで
/// 残りはゼロ。レジスタ形は下位 `fbits` を第 2 ソース（r/m）から、
/// 128 ビット内の残りを第 1 ソース（vvvv）から合成する。
/// YMM 上位は常にゼロクリア。
pub fn vmovs_ld<B: Backend>(
    b: &mut B,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
    fbits: u32,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    // レジスタ形もメモリ形も、下位 `fbits` に r/m ソースを置き、
    // 128 ビット内の残りは src1（vvvv）とマージする。
    // メモリ形の上位マージはレガシーの MOVSS/MOVSD（0 クリア）と違う
    // VEX 固有の動作。
    let s1: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    let s2 = if d.modrm >= 0xC0 {
        rx(b, ea, 128)?
    } else {
        rx(b, ea, fbits)?
    };
    let v = put_lane128(b, s1, s2, 0, fbits);
    b.set(sem::xmm_ref(dst), v);
    let z = b.konst::<W128>(0);
    b.set(sem::ymm_hi_ref(dst), z);
    Ok(())
}

/// VMOVSS/VMOVSD の書き込み。メモリ形は下位 `fbits` のみ書く。
/// レジスタ形は r/m のレジスタが第 3 オペランドで、下位を
/// 第 2 ソース（reg）、残りを第 1 ソース（vvvv）から合成する。
pub fn vmovs_st<B: Backend>(
    b: &mut B,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
    fbits: u32,
) -> Result<(), B::Exit> {
    let s2: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    if d.modrm >= 0xC0 {
        let dst = rm_x(d);
        let s1: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
        let v = put_lane128(b, s1, s2, 0, fbits);
        b.set(sem::xmm_ref(dst), v);
        let z = b.konst::<W128>(0);
        b.set(sem::ymm_hi_ref(dst), z);
        Ok(())
    } else {
        wx(b, ea, fbits, s2)
    }
}

/// VEX のスカラ浮動小数点（VADDSS 等）。下位 `fbits` を
/// src1(vvvv) と src2(r/m) で演算し、128 ビット内の残りは
/// src1 からコピー。YMM 上位はゼロクリア。
pub fn vsfloat<B: Backend>(
    b: &mut B,
    op: Fop,
    fbits: u32,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let s1: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    let s2 = rx(b, ea, fbits)?;
    let res = if fbits == 64 {
        let a64: B::V<W64> = b.trunc::<W128, W64>(s1);
        let c64: B::V<W64> = b.trunc::<W128, W64>(s2);
        let af = b.trunc::<W64, polyisa_sem::F64>(a64);
        let cf = b.trunc::<W64, polyisa_sem::F64>(c64);
        let v64 = match op {
            Fop::Cmp(p) => {
                let m = fcmp_pred::<B, polyisa_sem::F64>(b, p, true, af, cf);
                let ones = b.konst::<W64>(u64::MAX);
                let zero = b.konst::<W64>(0);
                b.select::<W64>(m, ones, zero)
            }
            _ => {
                let v = fop64(b, op, af, cf);
                b.trunc::<polyisa_sem::F64, W64>(v)
            }
        };
        b.zext::<W64, W128>(v64)
    } else {
        let a32: B::V<W32> = b.trunc::<W128, W32>(s1);
        let c32: B::V<W32> = b.trunc::<W128, W32>(s2);
        let af = b.trunc::<W32, polyisa_sem::F32>(a32);
        let cf = b.trunc::<W32, polyisa_sem::F32>(c32);
        let v32 = match op {
            Fop::Cmp(p) => {
                let m = fcmp_pred::<B, polyisa_sem::F32>(b, p, true, af, cf);
                let ones = b.konst::<W32>(u32::MAX);
                let zero = b.konst::<W32>(0);
                b.select::<W32>(m, ones, zero)
            }
            _ => {
                let v = fop32(b, op, af, cf);
                b.trunc::<polyisa_sem::F32, W32>(v)
            }
        };
        b.zext::<W32, W128>(v32)
    };
    let out = put_lane128(b, s1, res, 0, fbits);
    b.set(sem::xmm_ref(dst), out);
    let z = b.konst::<W128>(0);
    b.set(sem::ymm_hi_ref(dst), z);
    Ok(())
}

/// VEX のパック浮動小数点。レーンごとに src1(vvvv) と src2(r/m)
/// を演算する。VEX.256 形は上位 128 ビットにも同じ演算を適用し、
/// VEX.128 形は上位をゼロクリアする。
pub fn vpfloat<B: Backend>(
    b: &mut B,
    op: Fop,
    fbits: u32,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let s1: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    let s2 = rx(b, ea, 128)?;
    let lo = pfloat_lane(b, op, fbits, true, s1, s2);
    b.set(sem::xmm_ref(dst), lo);
    let hi = if d.vex_l {
        let h1: B::V<W128> = b.get(sem::ymm_hi_ref(vvv_x(d)));
        let h2 = rx_hi(b, ea)?;
        pfloat_lane(b, op, fbits, true, h1, h2)
    } else {
        b.konst::<W128>(0)
    };
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

/// VEX のパック論理（VANDPS/VPXOR 等）。`vpfloat` と同じ
/// 128/256 のレーン構造。
pub fn vlogic<B: Backend>(
    b: &mut B,
    op: Lop,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let s1: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    let s2 = rx(b, ea, 128)?;
    let lo = lop_lane(b, op, s1, s2);
    b.set(sem::xmm_ref(dst), lo);
    let hi = if d.vex_l {
        let h1: B::V<W128> = b.get(sem::ymm_hi_ref(vvv_x(d)));
        let h2 = rx_hi(b, ea)?;
        lop_lane(b, op, h1, h2)
    } else {
        b.konst::<W128>(0)
    };
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

/// VZEROUPPER（`all=false`、YMM 上位だけを消す）と
/// VZEROALL（`all=true`、XMM 全体も消す）。
pub fn vzero<B: Backend>(b: &mut B, all: bool) -> Result<(), B::Exit> {
    let z = b.konst::<W128>(0);
    for i in 0..16u8 {
        b.set(sem::ymm_hi_ref(Xmm(i)), z);
        if all {
            b.set(sem::xmm_ref(Xmm(i)), z);
        }
    }
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
        // SQRT 系は 2 オペランド（dst = sqrt(src)）なので
        // src1（`a`）ではなく r/m 側の `c` を取る。
        Fop::Sqrt => b.fsqrt::<F64>(c),
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
        Fop::Sqrt => b.fsqrt::<F32>(c),
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
    let acc = pfloat_lane(b, op, fbits, false, a128, c128);
    b.set(sem::xmm_ref(dst), acc);
    Ok(())
}

/// 128 ビットレーンのパック浮動小数点（レガシー形の `pfloat` と
/// VEX 形の `vpfloat` が共有する要素演算）。
fn pfloat_lane<B: Backend>(
    b: &mut B,
    op: Fop,
    fbits: u32,
    wide: bool,
    a128: B::V<W128>,
    c128: B::V<W128>,
) -> B::V<W128> {
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
                    let m = fcmp_pred::<B, polyisa_sem::F64>(b, p, wide, af, cf);
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
                    let m = fcmp_pred::<B, polyisa_sem::F32>(b, p, wide, af, cf);
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
    acc
}

/// RCP/RSQRT の 1 要素。近似命令だが、正確な商/逆平方根も
/// 許容される近似として計算する。
fn rcp_rs_elem<B: Backend>(b: &mut B, rsqrt: bool, x: B::V<W32>) -> B::V<W32> {
    use polyisa_sem::F32;
    let onebits = b.konst::<W32>(0x3f80_0000);
    let one = b.trunc::<W32, F32>(onebits);
    let f = b.trunc::<W32, F32>(x);
    let den = if rsqrt { b.fsqrt::<F32>(f) } else { f };
    let q = b.fdiv::<F32>(one, den);
    b.trunc::<F32, W32>(q)
}

/// RCPPS/RSQRTPS の 128 ビット処理。
fn rcp_rs_val<B: Backend>(b: &mut B, rsqrt: bool, v: B::V<W128>) -> B::V<W128> {
    let mut r = b.konst::<W128>(0);
    for i in 0..4u32 {
        let x128 = lane128(b, v, i * 32, 32);
        let x = b.trunc::<W128, W32>(x128);
        let q = rcp_rs_elem(b, rsqrt, x);
        let q128 = b.zext::<W32, W128>(q);
        r = put_lane128(b, r, q128, i * 32, 32);
    }
    r
}

/// RCPPS/RSQRTPS（レガシー）。
pub fn rcp_rs<B: Backend>(
    b: &mut B,
    rsqrt: bool,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let v = rx(b, ea, 128)?;
    let r = rcp_rs_val(b, rsqrt, v);
    b.set(sem::xmm_ref(reg_x(d)), r);
    Ok(())
}

/// RCPSS/RSQRTSS（レガシー）。下位だけを更新する。
pub fn rcp_rs_s<B: Backend>(
    b: &mut B,
    rsqrt: bool,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let old: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    let v = rx(b, ea, 32)?;
    let x = b.trunc::<W128, W32>(v);
    let q = rcp_rs_elem(b, rsqrt, x);
    let q128 = b.zext::<W32, W128>(q);
    let r = put_lane128(b, old, q128, 0, 32);
    b.set(sem::xmm_ref(reg_x(d)), r);
    Ok(())
}

/// VRCPPS/VRSQRTPS。
pub fn vrcp_rs<B: Backend>(
    b: &mut B,
    rsqrt: bool,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    vun2(b, d, ea, |b, x| rcp_rs_val(b, rsqrt, x))
}

/// VRCPSS/VRSQRTSS。下位は src2 から計算し、128 ビット内の
/// 残りは src1（vvvv）を継承する。
pub fn vrcp_rs_s<B: Backend>(
    b: &mut B,
    rsqrt: bool,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let old: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    let v = rx(b, ea, 32)?;
    let x = b.trunc::<W128, W32>(v);
    let q = rcp_rs_elem(b, rsqrt, x);
    let q128 = b.zext::<W32, W128>(q);
    let r = put_lane128(b, old, q128, 0, 32);
    b.set(sem::xmm_ref(dst), r);
    let z = b.konst::<W128>(0);
    b.set(sem::ymm_hi_ref(dst), z);
    Ok(())
}

/// CMPPS/CMPPD と VEX の VCMPPS/VCMPPD の判定。`wide` が真なら
/// VEX の 32 述語（pred&0x1F）、偽ならレガシーの 8 述語（pred&7）。
/// _S/_Q の signal 差は例外をモデル化しないので同一視する。
fn fcmp_pred<B: Backend, F: polyisa_sem::Width>(
    b: &mut B,
    pred: u8,
    wide: bool,
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
    let ge = b.fle::<F>(c, a);
    let gt = b.flt::<F>(c, a);
    let neq = sem::bit_not(b, eq);
    let lt_o = sem::bit_not(b, lt);
    let nlt = sem::bit_or(b, unord, lt_o);
    let le_o = sem::bit_not(b, le);
    let nle = sem::bit_or(b, unord, le_o);
    let neq_u = sem::bit_or(b, unord, neq);
    if !wide {
        return match pred & 7 {
            0 => eq,
            1 => lt,
            2 => le,
            3 => unord,
            4 => neq_u,
            5 => nlt,
            6 => nle,
            _ => ord,
        };
    }
    let ueq = sem::bit_or(b, unord, eq);
    let nge = sem::bit_or(b, unord, lt);
    let ngt = sem::bit_or(b, unord, le);
    let neq_o = sem::bit_and(b, ord, neq);
    // ordered ∧ unordered は常に偽、∨ は常に真。
    let f = sem::bit_and(b, ord, unord);
    let t = sem::bit_or(b, unord, ord);
    match pred & 0x1F {
        0x00 | 0x10 => eq,
        0x01 | 0x11 => lt,
        0x02 | 0x12 => le,
        0x03 | 0x13 => unord,
        0x04 | 0x14 => neq_u,
        0x05 | 0x15 => nlt,
        0x06 | 0x16 => nle,
        0x07 | 0x17 => ord,
        0x08 | 0x18 => ueq,
        0x09 | 0x19 => nge,
        0x0A | 0x1A => ngt,
        0x0B | 0x1B => f,
        0x0C | 0x1C => neq_o,
        0x0D | 0x1D => ge,
        0x0E | 0x1E => gt,
        _ => t,
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
        let m = fcmp_pred::<B, polyisa_sem::F64>(b, pred, false, af, cf);
        let ones = b.konst::<W64>(u64::MAX);
        let zero = b.konst::<W64>(0);
        let m64 = b.select::<W64>(m, ones, zero);
        b.zext::<W64, W128>(m64)
    } else {
        let a32: B::V<W32> = b.trunc::<W128, W32>(a128);
        let c32: B::V<W32> = b.trunc::<W128, W32>(c128);
        let af = b.trunc::<W32, polyisa_sem::F32>(a32);
        let cf = b.trunc::<W32, polyisa_sem::F32>(c32);
        let m = fcmp_pred::<B, polyisa_sem::F32>(b, pred, false, af, cf);
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

/// AVX10.2 の enhanced scalar compare。OF/SF/ZF/PF/CF を関係ごとの
/// 5 ビットパターンへ置き、AF を 0 にする。comx/ucomx の invalid
/// 例外強度差は MXCSR 例外生成の未モデルとして残る。
fn comx_parts<B: Backend, F: Width>(b: &mut B, a: B::V<F>, c: B::V<F>) -> (B::B, B::B, B::B) {
    let na = {
        let e = b.feq::<F>(a, a);
        sem::bit_not(b, e)
    };
    let nc = {
        let e = b.feq::<F>(c, c);
        sem::bit_not(b, e)
    };
    (sem::bit_or(b, na, nc), b.feq::<F>(a, c), b.flt::<F>(a, c))
}

/// VCOMXSS/SD/SH と VUCOMXSS/SD/SH。
pub fn vcomx<B: Backend>(
    b: &mut B,
    fbits: u32,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let a128: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    let c128 = rx(b, ea, fbits)?;
    let (unord, eq, lt) = if fbits == 64 {
        let aw: B::V<W64> = b.trunc::<W128, W64>(a128);
        let cw: B::V<W64> = b.trunc::<W128, W64>(c128);
        let af = b.trunc::<W64, polyisa_sem::F64>(aw);
        let cf = b.trunc::<W64, polyisa_sem::F64>(cw);
        comx_parts::<B, polyisa_sem::F64>(b, af, cf)
    } else if fbits == 32 {
        let aw: B::V<W32> = b.trunc::<W128, W32>(a128);
        let cw: B::V<W32> = b.trunc::<W128, W32>(c128);
        let af = b.trunc::<W32, polyisa_sem::F32>(aw);
        let cf = b.trunc::<W32, polyisa_sem::F32>(cw);
        comx_parts::<B, polyisa_sem::F32>(b, af, cf)
    } else {
        let aw: B::V<W16> = b.trunc::<W128, W16>(a128);
        let cw: B::V<W16> = b.trunc::<W128, W16>(c128);
        let af = b.trunc::<W16, polyisa_sem::F16>(aw);
        let cf = b.trunc::<W16, polyisa_sem::F16>(cw);
        comx_parts::<B, polyisa_sem::F16>(b, af, cf)
    };
    let eq_or_lt = sem::bit_or(b, eq, lt);
    let not_gt = sem::bit_or(b, unord, eq_or_lt);
    let gt = sem::bit_not(b, not_gt);
    // OF,SF,ZF,PF,CF は unordered=11011、greater=00000、
    // less=10001、equal=11100。AF=0。他旗は保存する。
    let of_v = sem::bit_not(b, gt);
    let sf_v = sem::bit_or(b, unord, eq);
    let zf_v = eq;
    let pf_v = unord;
    let cf_v = sem::bit_or(b, unord, lt);
    let f: B::V<W32> = b.get(eflags_ref());
    let mask = b.konst::<W32>(
        sem::FLAG_ZF | sem::FLAG_PF | sem::FLAG_CF | sem::FLAG_OF | sem::FLAG_SF | sem::FLAG_AF,
    );
    let nmask = b.not::<W32>(mask);
    let kept = b.and::<W32>(f, nmask);
    let of_b = pick(b, of_v, sem::FLAG_OF);
    let sf_b = pick(b, sf_v, sem::FLAG_SF);
    let zf_b = pick(b, zf_v, sem::FLAG_ZF);
    let pf_b = pick(b, pf_v, sem::FLAG_PF);
    let cf_b = pick(b, cf_v, sem::FLAG_CF);
    let mut v = b.or::<W32>(kept, of_b);
    v = b.or::<W32>(v, sf_b);
    v = b.or::<W32>(v, zf_b);
    v = b.or::<W32>(v, pf_b);
    v = b.or::<W32>(v, cf_b);
    b.set(eflags_ref(), v);
    Ok(())
}

/// CVTSI2SD/CVTSI2SS の変換値（ゼロ拡張された 128 ビット）。
fn cvtsi_val<B: Backend>(
    b: &mut B,
    fbits: u32,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<B::V<W128>, B::Exit> {
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
    Ok(res)
}

/// `base` の下位 `fbits` を `res` で置き換える。
fn cvt_merge<B: Backend>(b: &mut B, base: B::V<W128>, res: B::V<W128>, fbits: u32) -> B::V<W128> {
    put_lane128(b, base, res, 0, fbits)
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
    let res = cvtsi_val(b, fbits, d, ea)?;
    let out = cvt_merge(b, a128, res, fbits);
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

/// PSHUFD/PSHUFHW/PSHUFLW の 128 ビット処理（値関数）。
fn pshuf_val<B: Backend>(b: &mut B, kind: u8, imm: u8, s: B::V<W128>) -> B::V<W128> {
    match kind {
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
    }
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
    let v = pshuf_val(b, kind, imm, s);
    b.set(sem::xmm_ref(dst), v);
    Ok(())
}

/// SHUFPS/SHUFPD の 128 ビット処理（値関数）。a が下位、
/// c が上位の要素ソース。
fn shufp_val<B: Backend>(b: &mut B, pd: bool, imm: u8, a: B::V<W128>, c: B::V<W128>) -> B::V<W128> {
    if pd {
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
    }
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
    let v = shufp_val(b, pd, imm, a, c);
    b.set(sem::xmm_ref(dst), v);
    Ok(())
}

/// PUNPCKL*/PUNPCKH* と UNPCKLPS/PD・UNPCKHPS/PD の 128 ビット
/// 処理（値関数）。`bits` は要素幅（8/16/32/64）、`high` で上半分。
fn punpck_val<B: Backend>(
    b: &mut B,
    bits: u32,
    high: bool,
    a: B::V<W128>,
    c: B::V<W128>,
) -> B::V<W128> {
    let half = 64 / bits;
    let base = if high { half } else { 0 };
    let mut acc = b.konst::<W128>(0);
    for i in 0..half {
        let al = lane128(b, a, (base + i) * bits, bits);
        let cl = lane128(b, c, (base + i) * bits, bits);
        acc = put_lane128(b, acc, al, (2 * i) * bits, bits);
        acc = put_lane128(b, acc, cl, (2 * i + 1) * bits, bits);
    }
    acc
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
    let acc = punpck_val(b, bits, high, a, c);
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

/// 2 つの 128 ビット値のレーンごとに `f` を適用する。
fn plane_bin<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    a: B::V<W128>,
    c: B::V<W128>,
    mut f: impl FnMut(&mut B, B::V<W>, B::V<W>) -> B::V<W>,
) -> B::V<W128> {
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
    acc
}

fn lane_bin<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
    f: impl FnMut(&mut B, B::V<W>, B::V<W>) -> B::V<W>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let c = rx(b, ea, 128)?;
    let acc = plane_bin::<B, W>(b, a, c, f);
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
    MulHiU,
    MulHiS,
    Sign,
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
        Iop::MulHiU => mul_hi::<B, W>(b, true, a, c),
        Iop::MulHiS => mul_hi::<B, W>(b, false, a, c),
        // PSIGN: c<0 なら -a、c=0 なら 0、それ以外は a。
        Iop::Sign => {
            let z = b.konst::<W>(W::from_u128(0));
            let eq0 = b.cmp::<W>(Cmp::Eq, c, z);
            let neg = b.cmp::<W>(Cmp::LtS, c, z);
            let na = b.sub::<W>(z, a);
            let r = b.select::<W>(neg, na, a);
            b.select::<W>(eq0, z, r)
        }
    }
}

/// 拡幅乗算の上位 `W` ビット（PMULHUW/PMULHW のレーン本体）。
fn mul_hi<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    unsigned: bool,
    a: B::V<W>,
    c: B::V<W>,
) -> B::V<W> {
    let a128 = if unsigned {
        b.zext::<W, W128>(a)
    } else {
        b.sext::<W, W128>(a)
    };
    let c128 = if unsigned {
        b.zext::<W, W128>(c)
    } else {
        b.sext::<W, W128>(c)
    };
    let p = b.mul::<W128>(a128, c128);
    let sh = b.konst::<W128>(u128::from(W::BITS));
    let hi = b.shr_l::<W128>(p, sh);
    b.trunc::<W128, W>(hi)
}

pub fn pint<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    kind: Iop,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    lane_bin::<B, W>(b, d, ea, |b, a, c| iop_op::<B, W>(b, kind, a, c))
}

/// VEX の 3 オペランド・パック整数演算。第 1 ソースは vvvv、
/// 第 2 ソースは xmm/m128（L=0）または ymm/m256（L=1）。
/// L=0 では YMM 上位をゼロクリアする。
pub fn vpint<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    kind: Iop,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let s1: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    let s2 = rx(b, ea, 128)?;
    let lo = plane_bin::<B, W>(b, s1, s2, |b, a, c| iop_op::<B, W>(b, kind, a, c));
    b.set(sem::xmm_ref(dst), lo);
    let hi = if d.vex_l {
        let h1: B::V<W128> = b.get(sem::ymm_hi_ref(vvv_x(d)));
        let h2 = rx_hi(b, ea)?;
        plane_bin::<B, W>(b, h1, h2, |b, a, c| iop_op::<B, W>(b, kind, a, c))
    } else {
        b.konst::<W128>(0)
    };
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

/// PSRL/PSRA/PSLL のパックシフト。カウントは xmm/m128 の下位 64 または即値。
#[derive(Clone, Copy)]
pub enum Psh {
    L,
    A,
    R,
}

/// 128 ビット値 `a` の各 `W` レーンを `cnt` でシフトする。
fn pshift_val<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    dir: Psh,
    cnt: B::V<W64>,
    a: B::V<W128>,
) -> B::V<W128> {
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
    acc
}

fn pshift_impl<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    dir: Psh,
    cnt: B::V<W64>,
    dst: Xmm,
) -> Flow<B> {
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let r = pshift_val::<B, W>(b, dir, cnt, a);
    b.set(sem::xmm_ref(dst), r);
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

/// VEX の 3 オペランド・パックシフト（カウントは xmm/m128 の
/// 下位 64 ビット）。第 1 ソースは vvvv、L=1 では上位 128 も
/// 同じカウントでシフトする。
pub fn vpshift<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    dir: Psh,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let s2 = rx(b, ea, 128)?;
    let lo64 = lane128(b, s2, 0, 64);
    let cnt = b.trunc::<W128, W64>(lo64);
    let dst = reg_x(d);
    let s1: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    let lo = pshift_val::<B, W>(b, dir, cnt, s1);
    b.set(sem::xmm_ref(dst), lo);
    let hi = if d.vex_l {
        let h1: B::V<W128> = b.get(sem::ymm_hi_ref(vvv_x(d)));
        pshift_val::<B, W>(b, dir, cnt, h1)
    } else {
        b.konst::<W128>(0)
    };
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

/// VPSLLV/VPSRLV/VPSRAV の 128 ビットレーン内演算。各要素を
/// 同じ位置のカウント要素でシフトする。Backend のシフトは幅
/// 以上を全域化しているので、VPSLLV/VPSRLV は 0、VPSRAV は
/// 符号埋めとそのまま一致する。
fn pvshift_val<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    dir: Psh,
    a: B::V<W128>,
    c: B::V<W128>,
) -> B::V<W128> {
    let mut acc = b.konst::<W128>(0);
    for i in 0..(128 / W::BITS) {
        let at = i * W::BITS;
        let al = lane128(b, a, at, W::BITS);
        let cl = lane128(b, c, at, W::BITS);
        let a_w: B::V<W> = b.trunc::<W128, W>(al);
        let c_w: B::V<W> = b.trunc::<W128, W>(cl);
        let r = match dir {
            Psh::L => b.shl::<W>(a_w, c_w),
            Psh::A => b.shr_a::<W>(a_w, c_w),
            Psh::R => b.shr_l::<W>(a_w, c_w),
        };
        let r128 = b.zext::<W, W128>(r);
        acc = put_lane128(b, acc, r128, at, W::BITS);
    }
    acc
}

/// VPSLLVD/VPSLLVQ/VPSRLVD/VPSRLVQ/VPSRAVD。
pub fn vpshiftv<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    dir: Psh,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    vbin2(b, d, ea, |b, a, c| pvshift_val::<B, W>(b, dir, a, c))
}

/// VEX のグループ即値シフト（Op/En B：vvvv が宛先）。
/// ソースは r/m。L=1 では r/m の YMM 上位も処理する。
pub fn vpshift_i<B: Backend, W: polyisa_sem::Width>(b: &mut B, dir: Psh, d: &MapDec) -> Flow<B> {
    let cnt = b.konst::<W64>(u64::from(d.imm as u8));
    let src = rm_x(d);
    let dst = vvv_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(src));
    let lo = pshift_val::<B, W>(b, dir, cnt, a);
    b.set(sem::xmm_ref(dst), lo);
    let hi = if d.vex_l {
        let h: B::V<W128> = b.get(sem::ymm_hi_ref(src));
        pshift_val::<B, W>(b, dir, cnt, h)
    } else {
        b.konst::<W128>(0)
    };
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

/// 128 ビット値 `a` を `imm` バイトずらす。
fn byteshift_val<B: Backend>(b: &mut B, left: bool, imm: u8, a: B::V<W128>) -> B::V<W128> {
    let bits = u32::from(imm).min(16) * 8;
    let sh = b.konst::<W128>(u128::from(bits));
    if imm >= 16 {
        b.konst::<W128>(0)
    } else if left {
        b.shl::<W128>(a, sh)
    } else {
        b.shr_l::<W128>(a, sh)
    }
}

/// PSRLDQ/PSLLDQ。128 ビット全体を imm バイトずらす。
pub fn byteshift<B: Backend>(b: &mut B, left: bool, imm: u8, d: &MapDec) -> Flow<B> {
    let dst = rm_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let v = byteshift_val(b, left, imm, a);
    b.set(sem::xmm_ref(dst), v);
    Ok(())
}

/// VEX の VPSRLDQ/VPSLLDQ（Op/En B：vvvv が宛先）。
/// L=1 では 128 ビットレーンごとに独立にずらす。
pub fn vbyteshift<B: Backend>(b: &mut B, left: bool, d: &MapDec) -> Flow<B> {
    let imm = d.imm as u8;
    let src = rm_x(d);
    let dst = vvv_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(src));
    let lo = byteshift_val(b, left, imm, a);
    b.set(sem::xmm_ref(dst), lo);
    let hi = if d.vex_l {
        let h: B::V<W128> = b.get(sem::ymm_hi_ref(src));
        byteshift_val(b, left, imm, h)
    } else {
        b.konst::<W128>(0)
    };
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

/// VMOVLPS/VMOVLPD xmm, xmm, m64（VEX.128 のメモリロード形）。
/// 下位 64 に r/m、上位 64 に src1（vvvv）の上位を残す。
pub fn vmovl_ld<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let s1: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    let s = rx(b, ea, 64)?;
    let v = put_lane128(b, s1, s, 0, 64);
    b.set(sem::xmm_ref(dst), v);
    let z = b.konst::<W128>(0);
    b.set(sem::ymm_hi_ref(dst), z);
    Ok(())
}

/// VMOVHPS/VMOVHPD xmm, xmm, m64（VEX.128 のメモリロード形）。
/// 上位 64 に r/m、下位 64 に src1（vvvv）の下位を残す。
pub fn vmovh_ld<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let s1: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    let s = rx(b, ea, 64)?;
    let v = put_lane128(b, s1, s, 64, 64);
    b.set(sem::xmm_ref(dst), v);
    let z = b.konst::<W128>(0);
    b.set(sem::ymm_hi_ref(dst), z);
    Ok(())
}

/// VMOVLHPS xmm, xmm, xmm（0F 16 mod=11）。dst.hi = src2.lo、
/// dst.lo = src1.lo。
pub fn vmovlhps<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let s1: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    let s2 = rx(b, ea, 128)?;
    let lo = lane128(b, s2, 0, 64);
    let v = put_lane128(b, s1, lo, 64, 64);
    b.set(sem::xmm_ref(dst), v);
    let z = b.konst::<W128>(0);
    b.set(sem::ymm_hi_ref(dst), z);
    Ok(())
}

/// VMOVHLPS xmm, xmm, xmm（0F 12 mod=11）。dst.lo = src2.hi、
/// dst.hi = src1.hi。
pub fn vmovhlps<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let s1: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    let s2 = rx(b, ea, 128)?;
    let hi = lane128(b, s2, 64, 64);
    let v = put_lane128(b, s1, hi, 0, 64);
    b.set(sem::xmm_ref(dst), v);
    let z = b.konst::<W128>(0);
    b.set(sem::ymm_hi_ref(dst), z);
    Ok(())
}

/// VMOVSLDUP/VMOVSHDUP の 128 ビット処理。`odd` が真なら奇数
/// （SHDUP）、偽なら偶数（SLDUP）の 32 ビット要素を複製する。
fn vdupps_val<B: Backend>(b: &mut B, odd: bool, s: B::V<W128>) -> B::V<W128> {
    let b0 = if odd { 32 } else { 0 };
    let b2 = if odd { 96 } else { 64 };
    let l0 = lane128(b, s, b0, 32);
    let l2 = lane128(b, s, b2, 32);
    let mut v = b.konst::<W128>(0);
    v = put_lane128(b, v, l0, 0, 32);
    v = put_lane128(b, v, l0, 32, 32);
    v = put_lane128(b, v, l2, 64, 32);
    put_lane128(b, v, l2, 96, 32)
}

/// VMOVSLDUP/VMOVSHDUP。L=1 は上位 128 ビットにも同じ変形を適用。
pub fn vdupps<B: Backend>(
    b: &mut B,
    odd: bool,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let s2 = rx(b, ea, 128)?;
    let lo = vdupps_val(b, odd, s2);
    b.set(sem::xmm_ref(dst), lo);
    let hi = if d.vex_l {
        let h2 = rx_hi(b, ea)?;
        vdupps_val(b, odd, h2)
    } else {
        b.konst::<W128>(0)
    };
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

/// VMOVDDUP の 128 ビット処理。下位 64 を上下に複製する。
fn vddup_val<B: Backend>(b: &mut B, s: B::V<W128>) -> B::V<W128> {
    let lo = lane128(b, s, 0, 64);
    put_lane128(b, s, lo, 64, 64)
}

/// VMOVDDUP。L=1 は上位 128 ビットにも同じ変形を適用。L=0 は
/// メモリから 64 ビットのみ読む（ページ境界のフォルト差分）。
pub fn vmovddup<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let s2 = rx(b, ea, if d.vex_l { 128 } else { 64 })?;
    let lo = vddup_val(b, s2);
    b.set(sem::xmm_ref(dst), lo);
    let hi = if d.vex_l {
        let h2 = rx_hi(b, ea)?;
        vddup_val(b, h2)
    } else {
        b.konst::<W128>(0)
    };
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

/// VMOVMSKPS/VMOVMSKPD/VPMOVMSKB。src の各 `bits` 要素の符号
/// ビットを集めて GPR に書く。L=1 は YMM 上位の要素も続けて集める。
pub fn vmovmsk<B: Backend>(
    b: &mut B,
    bits: u32,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let n = 128 / bits;
    let s = rx(b, ea, 128)?;
    let mut acc = b.konst::<W64>(0);
    for i in 0..n {
        let l = lane128(b, s, i * bits + bits - 1, 1);
        let l64: B::V<W64> = b.trunc::<W128, W64>(l);
        let sh = b.konst::<W64>(u64::from(i));
        let placed = b.shl::<W64>(l64, sh);
        acc = b.or::<W64>(acc, placed);
    }
    if d.vex_l {
        let h = rx_hi(b, ea)?;
        for i in 0..n {
            let l = lane128(b, h, i * bits + bits - 1, 1);
            let l64: B::V<W64> = b.trunc::<W128, W64>(l);
            let sh = b.konst::<W64>(u64::from(n + i));
            let placed = b.shl::<W64>(l64, sh);
            acc = b.or::<W64>(acc, placed);
        }
    }
    let v32: B::V<W32> = b.trunc::<W64, W32>(acc);
    let v = b.zext::<W32, W64>(v32);
    sem::write64(b, decode::reg(d), v);
    Ok(())
}

/// VMOVD/VMOVQ xmm, r/m（VEX 66 0F 6E）。レガシーと同じ読み込みに
/// YMM 上位のゼロクリアを足す。
pub fn vmovd_x_e<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    movd_x_e(b, d, ea)?;
    let z = b.konst::<W128>(0);
    let r = reg_x(d);
    b.set(sem::ymm_hi_ref(r), z);
    // VEX/EVEX 形は 128 ビット書き込みで最大ベクトル幅まで上位を
    // ゼロクリアする。zmm 対応状態では part2/3 も残さない。
    b.set(sem::zreg_ref(r.0, 2), z);
    b.set(sem::zreg_ref(r.0, 3), z);
    Ok(())
}

/// VMOVQ xmm, xmm/m64（VEX F3 0F 7E）。レガシーと同じ読み込みに
/// YMM 上位のゼロクリアを足す。
pub fn vmovq_x_w<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    movq_x_w(b, d, ea)?;
    let z = b.konst::<W128>(0);
    b.set(sem::ymm_hi_ref(reg_x(d)), z);
    Ok(())
}

/// VMOVQ xmm/m64, xmm（VEX 66 0F D6）。レジスタ形は YMM 上位も
/// ゼロクリアする。
pub fn vmovq_w_x<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    movq_w_x(b, d, ea)?;
    if d.modrm >= 0xC0 {
        let z = b.konst::<W128>(0);
        b.set(sem::ymm_hi_ref(rm_x(d)), z);
    }
    Ok(())
}

/// 2 オペランド値関数 `f` を src1（vvvv）と src2（r/m）に適用する
/// VEX ラッパー。L=1 は上位 128 ビットにも同じ関数を適用する。
fn vbin2<B: Backend>(
    b: &mut B,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
    f: impl Fn(&mut B, B::V<W128>, B::V<W128>) -> B::V<W128>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let s1: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    let s2 = rx(b, ea, 128)?;
    let lo = f(b, s1, s2);
    b.set(sem::xmm_ref(dst), lo);
    let hi = if d.vex_l {
        let h1: B::V<W128> = b.get(sem::ymm_hi_ref(vvv_x(d)));
        let h2 = rx_hi(b, ea)?;
        f(b, h1, h2)
    } else {
        b.konst::<W128>(0)
    };
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

/// VPMADD52LUQ/HUQ の 128 ビットレーン内演算。qword ごとに
/// 下位 52 ビット同士の 104 ビット積を作り、下位/上位 52 ビットを
/// 既存の dest へ足す。
fn vpmadd52_val<B: Backend>(
    b: &mut B,
    high: bool,
    acc: B::V<W128>,
    s1: B::V<W128>,
    s2: B::V<W128>,
) -> B::V<W128> {
    let m52 = b.konst::<W128>((1u128 << 52) - 1);
    let k52 = b.konst::<W128>(52);
    let mut r = b.konst::<W128>(0);
    for i in 0..2u32 {
        let x0 = lane128(b, s1, i * 64, 64);
        let y0 = lane128(b, s2, i * 64, 64);
        let x = b.and::<W128>(x0, m52);
        let y = b.and::<W128>(y0, m52);
        let prod = b.mul::<W128>(x, y);
        let part = if high {
            let h = b.shr_l::<W128>(prod, k52);
            b.and::<W128>(h, m52)
        } else {
            b.and::<W128>(prod, m52)
        };
        let a = lane128(b, acc, i * 64, 64);
        let sum = b.add::<W128>(a, part);
        r = put_lane128(b, r, sum, i * 64, 64);
    }
    r
}

/// VPMADD52LUQ/HUQ。dest は入力の累算器でもある。
pub fn vpmadd52<B: Backend>(
    b: &mut B,
    high: bool,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let acc: B::V<W128> = b.get(sem::xmm_ref(dst));
    let s1: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    let s2 = rx(b, ea, 128)?;
    let lo = vpmadd52_val(b, high, acc, s1, s2);
    b.set(sem::xmm_ref(dst), lo);
    let hi = if d.vex_l {
        let ah: B::V<W128> = b.get(sem::ymm_hi_ref(dst));
        let h1: B::V<W128> = b.get(sem::ymm_hi_ref(vvv_x(d)));
        let h2 = rx_hi(b, ea)?;
        vpmadd52_val(b, high, ah, h1, h2)
    } else {
        b.konst::<W128>(0)
    };
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

/// 8/16 ビット要素を必要に応じて符号拡張する。`v` は lane128 で
/// 下位へ取り出した値。
fn vnni_elem<B: Backend>(b: &mut B, bits: u32, signed: bool, v: B::V<W128>) -> B::V<W128> {
    if !signed {
        return v;
    }
    if bits == 8 {
        let x = b.trunc::<W128, W8>(v);
        b.sext::<W8, W128>(x)
    } else {
        let x = b.trunc::<W128, W16>(v);
        b.sext::<W16, W128>(x)
    }
}

#[derive(Clone, Copy)]
struct VnniOp {
    bits: u32,
    s1signed: bool,
    s2signed: bool,
    sat: bool,
}

/// AVX-VNNI のドット積の 128 ビットレーン内演算。`bits` は 8 か 16。
/// 積とそのグループ内合計は常に正確に計算し、dest への加算だけを
/// 32 ビットで折り返すか符号飽和する。
fn vpdp_val<B: Backend>(
    b: &mut B,
    op: VnniOp,
    acc: B::V<W128>,
    s1: B::V<W128>,
    s2: B::V<W128>,
) -> B::V<W128> {
    let VnniOp {
        bits,
        s1signed,
        s2signed,
        sat,
    } = op;
    let max = b.konst::<W128>(0x7fff_ffff);
    let min = b.konst::<W128>(u128::MAX - ((1u128 << 31) - 1));
    let mut r = b.konst::<W128>(0);
    for dword in 0..4u32 {
        let mut sum = b.konst::<W128>(0);
        for j in 0..(32 / bits) {
            let at = dword * 32 + j * bits;
            let x0 = lane128(b, s1, at, bits);
            let y0 = lane128(b, s2, at, bits);
            let x = vnni_elem(b, bits, s1signed, x0);
            let y = vnni_elem(b, bits, s2signed, y0);
            let p = b.mul::<W128>(x, y);
            sum = b.add::<W128>(sum, p);
        }
        let a0 = lane128(b, acc, dword * 32, 32);
        let a32 = b.trunc::<W128, W32>(a0);
        let a = b.sext::<W32, W128>(a32);
        let mut total = b.add::<W128>(a, sum);
        if sat {
            let hi = b.cmp::<W128>(Cmp::GtS, total, max);
            total = b.select::<W128>(hi, max, total);
            let lo = b.cmp::<W128>(Cmp::LtS, total, min);
            total = b.select::<W128>(lo, min, total);
        }
        r = put_lane128(b, r, total, dword * 32, 32);
    }
    r
}

/// AVX-VNNI のドット積。dest は入力の累算器でもある。
pub fn vpdp<B: Backend>(
    b: &mut B,
    bits: u32,
    s1signed: bool,
    s2signed: bool,
    sat: bool,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let acc: B::V<W128> = b.get(sem::xmm_ref(dst));
    let s1: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    let s2 = rx(b, ea, 128)?;
    let op = VnniOp {
        bits,
        s1signed,
        s2signed,
        sat,
    };
    let lo = vpdp_val(b, op, acc, s1, s2);
    b.set(sem::xmm_ref(dst), lo);
    let hi = if d.vex_l {
        let ah: B::V<W128> = b.get(sem::ymm_hi_ref(dst));
        let h1: B::V<W128> = b.get(sem::ymm_hi_ref(vvv_x(d)));
        let h2 = rx_hi(b, ea)?;
        vpdp_val(b, op, ah, h1, h2)
    } else {
        b.konst::<W128>(0)
    };
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

/// 単項値関数 `f` を r/m に適用する VEX ラッパー（VPABS 等）。
fn vun2<B: Backend>(
    b: &mut B,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
    f: impl Fn(&mut B, B::V<W128>) -> B::V<W128>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let s2 = rx(b, ea, 128)?;
    let lo = f(b, s2);
    b.set(sem::xmm_ref(dst), lo);
    let hi = if d.vex_l {
        let h2 = rx_hi(b, ea)?;
        f(b, h2)
    } else {
        b.konst::<W128>(0)
    };
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

/// VPHADDW/D/SW・VPHSUBW/D/SW。
pub fn vphaddsub<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    sub: bool,
    sat: bool,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    vbin2(b, d, ea, |b, a, c| phaddsub_val::<B, W>(b, sub, sat, a, c))
}

/// VPMADDUBSW。
pub fn vpmaddubsw<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    vbin2(b, d, ea, pmaddubsw_val)
}

/// VPMULHRSW。
pub fn vpmulhrsw<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    vbin2(b, d, ea, pmulhrsw_val)
}

/// VPABSB/W/D。
pub fn vpabs<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    vun2(b, d, ea, |b, s| pabs_val::<B, W>(b, s))
}

/// PMADDWD。s16 の隣接ペア積和を s32 にする（値関数）。
fn pmaddwd_val<B: Backend>(b: &mut B, a: B::V<W128>, c: B::V<W128>) -> B::V<W128> {
    let mut acc = b.konst::<W128>(0);
    for i in 0..4u32 {
        let l0 = lane128(b, a, i * 32, 16);
        let l1 = lane128(b, a, i * 32 + 16, 16);
        let m0 = lane128(b, c, i * 32, 16);
        let m1 = lane128(b, c, i * 32 + 16, 16);
        let a0: B::V<W16> = b.trunc::<W128, W16>(l0);
        let a1: B::V<W16> = b.trunc::<W128, W16>(l1);
        let c0: B::V<W16> = b.trunc::<W128, W16>(m0);
        let c1: B::V<W16> = b.trunc::<W128, W16>(m1);
        let a0w = b.sext::<W16, W32>(a0);
        let a1w = b.sext::<W16, W32>(a1);
        let c0w = b.sext::<W16, W32>(c0);
        let c1w = b.sext::<W16, W32>(c1);
        let p0 = b.mul::<W32>(a0w, c0w);
        let p1 = b.mul::<W32>(a1w, c1w);
        let sum = b.add::<W32>(p0, p1);
        let r128 = b.zext::<W32, W128>(sum);
        acc = put_lane128(b, acc, r128, i * 32, 32);
    }
    acc
}

/// PMULUDQ。偶数 u32 レーンの積を u64 にする（値関数）。
fn pmuludq_val<B: Backend>(b: &mut B, a: B::V<W128>, c: B::V<W128>) -> B::V<W128> {
    let mut acc = b.konst::<W128>(0);
    for i in 0..2u32 {
        let l = lane128(b, a, i * 64, 32);
        let m = lane128(b, c, i * 64, 32);
        let a32: B::V<W32> = b.trunc::<W128, W32>(l);
        let c32: B::V<W32> = b.trunc::<W128, W32>(m);
        let aw = b.zext::<W32, W64>(a32);
        let cw = b.zext::<W32, W64>(c32);
        let p = b.mul::<W64>(aw, cw);
        let r128 = b.zext::<W64, W128>(p);
        acc = put_lane128(b, acc, r128, i * 64, 64);
    }
    acc
}

/// PSADBW。各 qword 内の 8 バイトの絶対差分和を u16 にする（値関数）。
fn psadbw_val<B: Backend>(b: &mut B, a: B::V<W128>, c: B::V<W128>) -> B::V<W128> {
    let mut acc = b.konst::<W128>(0);
    for i in 0..2u32 {
        let mut sum = b.konst::<W32>(0);
        for j in 0..8u32 {
            let l = lane128(b, a, i * 64 + j * 8, 8);
            let m = lane128(b, c, i * 64 + j * 8, 8);
            let a8: B::V<W8> = b.trunc::<W128, W8>(l);
            let c8: B::V<W8> = b.trunc::<W128, W8>(m);
            let av = b.zext::<W8, W32>(a8);
            let cv = b.zext::<W8, W32>(c8);
            let gt = b.cmp::<W32>(Cmp::GtU, av, cv);
            let d1 = b.sub::<W32>(av, cv);
            let d2 = b.sub::<W32>(cv, av);
            let dv = b.select::<W32>(gt, d1, d2);
            sum = b.add::<W32>(sum, dv);
        }
        let r128 = b.zext::<W32, W128>(sum);
        acc = put_lane128(b, acc, r128, i * 64, 16);
    }
    acc
}

/// `dst = f(dst, rm)` 形の 128 ビット演算（レガシー xmm 形）。
fn pdst_val<B: Backend>(
    b: &mut B,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
    mut f: impl FnMut(&mut B, B::V<W128>, B::V<W128>) -> B::V<W128>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let c = rx(b, ea, 128)?;
    let v = f(b, a, c);
    b.set(sem::xmm_ref(dst), v);
    Ok(())
}

/// PMADDWD / PMULUDQ / PSADBW のレガシー xmm 形。
pub fn pmaddwd<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    pdst_val(b, d, ea, pmaddwd_val)
}
pub fn pmuludq<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    pdst_val(b, d, ea, pmuludq_val)
}
pub fn psadbw<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    pdst_val(b, d, ea, psadbw_val)
}

/// VPMADDWD / VPMULUDQ / VPSADBW。
pub fn vpmaddwd<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    vbin2(b, d, ea, pmaddwd_val)
}
pub fn vpmuludq<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    vbin2(b, d, ea, pmuludq_val)
}
pub fn vpsadbw<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    vbin2(b, d, ea, psadbw_val)
}

/// VPTEST。L=1 は YMM 上位も判定に含める。
pub fn vptest<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Flow<B> {
    let a: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    let c = rx(b, ea, 128)?;
    let mut t1 = b.and::<W128>(a, c);
    let na = b.not::<W128>(a);
    let mut t2 = b.and::<W128>(na, c);
    if d.vex_l {
        let ah: B::V<W128> = b.get(sem::ymm_hi_ref(reg_x(d)));
        let ch = rx_hi(b, ea)?;
        let nah = b.not::<W128>(ah);
        let t1h = b.and::<W128>(ah, ch);
        let t2h = b.and::<W128>(nah, ch);
        t1 = b.or::<W128>(t1, t1h);
        t2 = b.or::<W128>(t2, t2h);
    }
    ptest_flags(b, t1, t2)
}

/// VTESTPS/VTESTPD。VPTEST と違い各浮動要素の符号ビットだけを
/// AND して ZF/CF を判定する（SDM: sign bits のみ検査）。
pub fn vtestf<B: Backend>(
    b: &mut B,
    d: &MapDec,
    esz: u32,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let a: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    let c = rx(b, ea, 128)?;
    let na = b.not::<W128>(a);
    let mut t1 = b.and::<W128>(a, c);
    let mut t2 = b.and::<W128>(na, c);
    if d.vex_l {
        let ah: B::V<W128> = b.get(sem::ymm_hi_ref(reg_x(d)));
        let ch = rx_hi(b, ea)?;
        let nah = b.not::<W128>(ah);
        let t1h = b.and::<W128>(ah, ch);
        let t2h = b.and::<W128>(nah, ch);
        t1 = b.or::<W128>(t1, t1h);
        t2 = b.or::<W128>(t2, t2h);
    }
    let smask = b.konst::<W128>(if esz == 64 {
        0x8000_0000_0000_0000_8000_0000_0000_0000
    } else {
        0x8000_0000_8000_0000_8000_0000_8000_0000
    });
    let t1s = b.and::<W128>(t1, smask);
    let t2s = b.and::<W128>(t2, smask);
    ptest_flags(b, t1s, t2s)
}

/// VPHMINPOSUW。レガシーと同じ変換に YMM 上位のゼロクリアを足す。
pub fn vphminposuw<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    phminposuw(b, d, ea)?;
    let z = b.konst::<W128>(0);
    b.set(sem::ymm_hi_ref(reg_x(d)), z);
    Ok(())
}

/// VSHUFPS/VSHUFPD。L=1 は各 128 レーンで独立に変形する
/// （VSHUFPS は同じ imm8 フィールド、VSHUFPD は上位レーンが
/// imm8[3:2]）。
pub fn vshufp<B: Backend>(
    b: &mut B,
    pd: bool,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    if !pd {
        return vbin2(b, d, ea, |b, a, c| shufp_val(b, false, imm, a, c));
    }
    // VSHUFPD ymm はレーンごとに別の imm8 ビットを使う
    // （L0 は 1:0、L1 は 3:2）。
    let dst = reg_x(d);
    let s1: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    let s2 = rx(b, ea, 128)?;
    let lo = shufp_val(b, true, imm, s1, s2);
    b.set(sem::xmm_ref(dst), lo);
    let hi = if d.vex_l {
        let h1: B::V<W128> = b.get(sem::ymm_hi_ref(vvv_x(d)));
        let h2 = rx_hi(b, ea)?;
        shufp_val(b, true, imm >> 2, h1, h2)
    } else {
        b.konst::<W128>(0)
    };
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

/// VPUNPCKL*/VPUNPCKH* と VUNPCKLPS/PD・VUNPCKHPS/PD。
pub fn vpunpck<B: Backend>(
    b: &mut B,
    bits: u32,
    high: bool,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    vbin2(b, d, ea, |b, a, c| punpck_val(b, bits, high, a, c))
}

/// VPSHUFD/VPSHUFHW/VPSHUFLW。
pub fn vpshuf<B: Backend>(
    b: &mut B,
    kind: u8,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    vun2(b, d, ea, |b, s| pshuf_val(b, kind, imm, s))
}

/// VPACKSSWB/W・VPACKUSWB/DW。
pub fn vpack<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    unsig: bool,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    vbin2(b, d, ea, |b, a, c| pack_val::<B, W>(b, unsig, a, c))
}

/// VPSHUFB。各 128 レーンの制御バイトで同レーンをシャッフル。
pub fn vpshufb<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    vbin2(b, d, ea, pshufb_val)
}

/// VEX パック CVT の変換方向。
#[derive(Clone, Copy)]
pub enum CvtK {
    /// VCVTPS2PD。f32 → f64（拡大）。
    Ps2Pd,
    /// VCVTPD2PS。f64 → f32（縮小、dst は常に xmm）。
    Pd2Ps,
    /// VCVTPD2DQ。f64 → s32（最近接丸め、dst は常に xmm）。
    Pd2Dq,
    /// VCVTTPD2DQ。f64 → s32（切り捨て、dst は常に xmm）。
    TPd2Dq,
    /// VCVTPS2DQ。f32 → s32（最近接丸め、同幅）。
    Ps2Dq,
    /// VCVTTPS2DQ。f32 → s32（切り捨て、同幅）。
    TPs2Dq,
    /// VCVTDQ2PD。s32 → f64（拡大）。
    Dq2Pd,
    /// VCVTDQ2PS。s32 → f32（同幅）。
    Dq2Ps,
}

/// s の `base` から 2 つの 32 ビット要素を f64 に変換して
/// 0/64 ビットに置く（ps2pd/dq2pd の各 128 ビット出力）。
fn cvt_widen_lane<B: Backend>(b: &mut B, int: bool, s: B::V<W128>, base: u32) -> B::V<W128> {
    let mut acc = b.konst::<W128>(0);
    for i in 0..2u32 {
        let l = lane128(b, s, (base + i) * 32, 32);
        let v32: B::V<W32> = b.trunc::<W128, W32>(l);
        let v64: B::V<W64> = if int {
            let f = b.fcvt_from_s32::<polyisa_sem::F64>(v32, 0);
            b.trunc::<polyisa_sem::F64, W64>(f)
        } else {
            let f = b.trunc::<W32, polyisa_sem::F32>(v32);
            let g = b.fcvt_ff::<polyisa_sem::F32, polyisa_sem::F64>(f, 0);
            b.trunc::<polyisa_sem::F64, W64>(g)
        };
        let v128 = b.zext::<W64, W128>(v64);
        acc = put_lane128(b, acc, v128, i * 64, 64);
    }
    acc
}

/// s の 2 つの f64 を 32 ビット要素に変換して下位 64 ビットに置く
/// （pd2ps/pd2dq の各 128 ビットソース）。
fn cvt_narrow_lane<B: Backend>(b: &mut B, kind: CvtK, s: B::V<W128>) -> B::V<W128> {
    let mut acc = b.konst::<W128>(0);
    for i in 0..2u32 {
        let l = lane128(b, s, i * 64, 64);
        let v64: B::V<W64> = b.trunc::<W128, W64>(l);
        let f = b.trunc::<W64, polyisa_sem::F64>(v64);
        let r32: B::V<W32> = match kind {
            CvtK::Pd2Ps => {
                let g = b.fcvt_ff::<polyisa_sem::F64, polyisa_sem::F32>(f, 0);
                b.trunc::<polyisa_sem::F32, W32>(g)
            }
            CvtK::Pd2Dq => b.fcvt_s32::<polyisa_sem::F64>(f, 0),
            _ => b.fcvt_s32::<polyisa_sem::F64>(f, 1),
        };
        let r128 = b.zext::<W32, W128>(r32);
        acc = put_lane128(b, acc, r128, i * 32, 32);
    }
    acc
}

/// s の 4 つの 32 ビット要素を同幅で相互変換する
/// （dq2ps/ps2dq/tps2dq の各 128 ビットレーン）。
fn cvt_same_lane<B: Backend>(b: &mut B, kind: CvtK, s: B::V<W128>) -> B::V<W128> {
    let mut acc = b.konst::<W128>(0);
    for i in 0..4u32 {
        let l = lane128(b, s, i * 32, 32);
        let v32: B::V<W32> = b.trunc::<W128, W32>(l);
        let r32: B::V<W32> = match kind {
            CvtK::Dq2Ps => {
                let f = b.fcvt_from_s32::<polyisa_sem::F32>(v32, 0);
                b.trunc::<polyisa_sem::F32, W32>(f)
            }
            CvtK::Ps2Dq => {
                let f = b.trunc::<W32, polyisa_sem::F32>(v32);
                b.fcvt_s32::<polyisa_sem::F32>(f, 0)
            }
            _ => {
                let f = b.trunc::<W32, polyisa_sem::F32>(v32);
                b.fcvt_s32::<polyisa_sem::F32>(f, 1)
            }
        };
        let r128 = b.zext::<W32, W128>(r32);
        acc = put_lane128(b, acc, r128, i * 32, 32);
    }
    acc
}

/// VEX のパック変換。L=1 での読み・書き幅は `kind` ごとに決まる。
pub fn vcvtp<B: Backend>(
    b: &mut B,
    kind: CvtK,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    match kind {
        CvtK::Dq2Ps | CvtK::Ps2Dq | CvtK::TPs2Dq => {
            let s = rx(b, ea, 128)?;
            let lo = cvt_same_lane(b, kind, s);
            b.set(sem::xmm_ref(dst), lo);
            let hi = if d.vex_l {
                let h = rx_hi(b, ea)?;
                cvt_same_lane(b, kind, h)
            } else {
                b.konst::<W128>(0)
            };
            b.set(sem::ymm_hi_ref(dst), hi);
        }
        CvtK::Ps2Pd | CvtK::Dq2Pd => {
            // 読み幅 = dst/2（L=0 は 64、L=1 は 128）。
            let s = rx(b, ea, if d.vex_l { 128 } else { 64 })?;
            let int = matches!(kind, CvtK::Dq2Pd);
            let lo = cvt_widen_lane(b, int, s, 0);
            b.set(sem::xmm_ref(dst), lo);
            let hi = if d.vex_l {
                cvt_widen_lane(b, int, s, 2)
            } else {
                b.konst::<W128>(0)
            };
            b.set(sem::ymm_hi_ref(dst), hi);
        }
        CvtK::Pd2Ps | CvtK::Pd2Dq | CvtK::TPd2Dq => {
            // 出力は常に xmm。L=1 は上位 128 ソースの変換結果を
            // 下位の結果の後ろに並べる。
            let s = rx(b, ea, 128)?;
            let mut out = cvt_narrow_lane(b, kind, s);
            if d.vex_l {
                let h = rx_hi(b, ea)?;
                let h2 = cvt_narrow_lane(b, kind, h);
                out = put_lane128(b, out, h2, 64, 64);
            }
            b.set(sem::xmm_ref(dst), out);
            let z = b.konst::<W128>(0);
            b.set(sem::ymm_hi_ref(dst), z);
        }
    }
    Ok(())
}

/// レガシー xmm 形のパック CVT（0F 5B/E6）。dst を丸ごと上書きする。
pub fn pcvtp<B: Backend>(
    b: &mut B,
    kind: CvtK,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let v = match kind {
        CvtK::Dq2Ps | CvtK::Ps2Dq | CvtK::TPs2Dq => {
            let s = rx(b, ea, 128)?;
            cvt_same_lane(b, kind, s)
        }
        CvtK::Ps2Pd | CvtK::Dq2Pd => {
            let s = rx(b, ea, 64)?;
            cvt_widen_lane(b, matches!(kind, CvtK::Dq2Pd), s, 0)
        }
        CvtK::Pd2Ps | CvtK::Pd2Dq | CvtK::TPd2Dq => {
            let s = rx(b, ea, 128)?;
            cvt_narrow_lane(b, kind, s)
        }
    };
    b.set(sem::xmm_ref(dst), v);
    Ok(())
}

/// VCVTSS2SD/VCVTSD2SS。下位のみ変換し、残りは vvvv ソースとマージ。
pub fn vcvtsf<B: Backend>(
    b: &mut B,
    to64: bool,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let s1: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    // ソースは m32（ss2sd）または m64（sd2ss）のみを読む。
    let s = rx(b, ea, if to64 { 32 } else { 64 })?;
    let res = if to64 {
        let l = lane128(b, s, 0, 32);
        let v32: B::V<W32> = b.trunc::<W128, W32>(l);
        let f = b.trunc::<W32, polyisa_sem::F32>(v32);
        let g = b.fcvt_ff::<polyisa_sem::F32, polyisa_sem::F64>(f, 0);
        let v64 = b.trunc::<polyisa_sem::F64, W64>(g);
        b.zext::<W64, W128>(v64)
    } else {
        let l = lane128(b, s, 0, 64);
        let v64: B::V<W64> = b.trunc::<W128, W64>(l);
        let f = b.trunc::<W64, polyisa_sem::F64>(v64);
        let g = b.fcvt_ff::<polyisa_sem::F64, polyisa_sem::F32>(f, 0);
        let v32 = b.trunc::<polyisa_sem::F32, W32>(g);
        b.zext::<W32, W128>(v32)
    };
    let out = cvt_merge(b, s1, res, if to64 { 64 } else { 32 });
    b.set(sem::xmm_ref(dst), out);
    let z = b.konst::<W128>(0);
    b.set(sem::ymm_hi_ref(dst), z);
    Ok(())
}

/// VCVTSI2SS/SD。レガシーと同じ変換を vvvv ソースへマージする。
pub fn vcvtsi<B: Backend>(
    b: &mut B,
    fbits: u32,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let s1: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    let res = cvtsi_val(b, fbits, d, ea)?;
    let out = cvt_merge(b, s1, res, fbits);
    b.set(sem::xmm_ref(dst), out);
    let z = b.konst::<W128>(0);
    b.set(sem::ymm_hi_ref(dst), z);
    Ok(())
}

/// VBLENDPS/VBLENDPD/VPBLENDW。256 ビット形で要素数が 8 以下
/// （bits >= 32）のとき上位レーンは imm の上位フィールドを使う。
/// VPBLENDW（bits=16）は imm8 を両レーンで再利用する。
pub fn vblendp<B: Backend>(
    b: &mut B,
    bits: u32,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let s1: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    let s2 = rx(b, ea, 128)?;
    let lo = blendp_val(b, bits, imm, s1, s2);
    b.set(sem::xmm_ref(dst), lo);
    let hi = if d.vex_l {
        let h1: B::V<W128> = b.get(sem::ymm_hi_ref(vvv_x(d)));
        let h2 = rx_hi(b, ea)?;
        let himm = if bits >= 32 { imm >> (128 / bits) } else { imm };
        blendp_val(b, bits, himm, h1, h2)
    } else {
        b.konst::<W128>(0)
    };
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

/// VBLENDVPS/VBLENDVPD/VPBLENDVB。マスクは imm8[7:4] の x/ymm レジスタ
/// （VEX 拡張なしの 4 ビット番号）。
pub fn vblendv<B: Backend>(
    b: &mut B,
    elt: u32,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let mx = sem::Xmm((d.imm >> 4 & 0xF) as u8);
    let s1: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    let s2 = rx(b, ea, 128)?;
    let m: B::V<W128> = b.get(sem::xmm_ref(mx));
    let lo = blendv_val(b, elt, s1, s2, m);
    b.set(sem::xmm_ref(dst), lo);
    let hi = if d.vex_l {
        let h1: B::V<W128> = b.get(sem::ymm_hi_ref(vvv_x(d)));
        let h2 = rx_hi(b, ea)?;
        let mh: B::V<W128> = b.get(sem::ymm_hi_ref(mx));
        blendv_val(b, elt, h1, h2, mh)
    } else {
        b.konst::<W128>(0)
    };
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

/// VDPPS（レーン単位）/VDPPD。
pub fn vdpp<B: Backend>(
    b: &mut B,
    fbits: u32,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    vbin2(b, d, ea, |b, a, c| dpp_val(b, fbits, imm, a, c))
}

/// VROUNDPS/VROUNDPD。
pub fn vroundp<B: Backend>(
    b: &mut B,
    fbits: u32,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    vun2(b, d, ea, |b, s| round_p_val(b, fbits, round_rm(imm), s))
}

/// VROUNDSS/VROUNDSD。下位のみ丸め、残りは vvvv ソースとマージ。
pub fn vrounds<B: Backend>(
    b: &mut B,
    fbits: u32,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let s1: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    let c = rx(b, ea, fbits)?;
    let z128 = b.konst::<W128>(0);
    let res = if fbits == 64 {
        let __h0 = flane64(b, c, 0);
        let r = frint_f64(b, __h0, round_rm(imm));
        put_flane64(b, z128, r, 0)
    } else {
        let __h1 = flane32(b, c, 0);
        let r = frint_f32(b, __h1, round_rm(imm));
        put_flane32(b, z128, r, 0)
    };
    let out = cvt_merge(b, s1, res, fbits);
    b.set(sem::xmm_ref(dst), out);
    let z = b.konst::<W128>(0);
    b.set(sem::ymm_hi_ref(dst), z);
    Ok(())
}

/// VINSERTPS。vvvv ソースへ下位レーンを挿入する。
pub fn vinsertps<B: Backend>(
    b: &mut B,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    let s = if d.modrm >= 0xC0 {
        let src: B::V<W128> = b.get(sem::xmm_ref(rm_x(d)));
        lane128(b, src, u32::from(imm >> 6 & 3) * 32, 32)
    } else {
        rx(b, ea, 32)?
    };
    let r = insertps_val(b, imm, a, s);
    b.set(sem::xmm_ref(dst), r);
    let z = b.konst::<W128>(0);
    b.set(sem::ymm_hi_ref(dst), z);
    Ok(())
}

/// VPINSRB/VPINSRW/VPINSRD/VPINSRQ。vvvv ソースへ `bits` 幅を挿入。
pub fn vpinsrx<B: Backend>(
    b: &mut B,
    bits: u32,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
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
    b.set(sem::xmm_ref(dst), r);
    let z = b.konst::<W128>(0);
    b.set(sem::ymm_hi_ref(dst), z);
    Ok(())
}

/// VPMOVSX*/VPMOVZX*。L=1 は 128 ビットソースの後半を上位レーンに拡張。
pub fn vpmovx<B: Backend>(
    b: &mut B,
    from: u32,
    to: u32,
    signed: bool,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let n = 128 / to;
    let s = rx(b, ea, if d.vex_l { 128 } else { n * from })?;
    let lo = pmovx_val(b, from, to, signed, s, 0);
    b.set(sem::xmm_ref(dst), lo);
    let hi = if d.vex_l {
        pmovx_val(b, from, to, signed, s, n)
    } else {
        b.konst::<W128>(0)
    };
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

/// VMPSADBW。ymm 形は上位レーンが imm8[5:3]（下位は imm8[2:0]）。
pub fn vmpsadbw<B: Backend>(
    b: &mut B,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let s1: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    let s2 = rx(b, ea, 128)?;
    let lo = mpsadbw_val(b, imm, s1, s2);
    b.set(sem::xmm_ref(dst), lo);
    let hi = if d.vex_l {
        let h1: B::V<W128> = b.get(sem::ymm_hi_ref(vvv_x(d)));
        let h2 = rx_hi(b, ea)?;
        mpsadbw_val(b, imm >> 3, h1, h2)
    } else {
        b.konst::<W128>(0)
    };
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

/// VMOVNTDQA。L=1 は 256 ビットロード。
pub fn vmovntdqa<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let v = rx(b, ea, 128)?;
    b.set(sem::xmm_ref(dst), v);
    let hi = if d.vex_l {
        rx_hi(b, ea)?
    } else {
        b.konst::<W128>(0)
    };
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

/// VPERMILPS/VPERMILPD のレーン内即値並べ替え。
fn permilp_val<B: Backend>(b: &mut B, fbits: u32, imm: u8, s: B::V<W128>) -> B::V<W128> {
    let n = 128 / fbits;
    let mut acc = b.konst::<W128>(0);
    for i in 0..n {
        let sel = if fbits == 32 {
            u32::from(imm >> (2 * i) & 3)
        } else {
            u32::from(imm >> i & 1)
        };
        let l = lane128(b, s, sel * fbits, fbits);
        acc = put_lane128(b, acc, l, i * fbits, fbits);
    }
    acc
}

/// VPERMILPS/VPERMILPD の即値形。PD の ymm 形は上位レーンが imm8[3:2]。
pub fn vpermilp_i<B: Backend>(
    b: &mut B,
    fbits: u32,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    if fbits == 32 {
        return vun2(b, d, ea, |b, s| permilp_val(b, 32, imm, s));
    }
    let dst = reg_x(d);
    let s = rx(b, ea, 128)?;
    let lo = permilp_val(b, 64, imm, s);
    b.set(sem::xmm_ref(dst), lo);
    let hi = if d.vex_l {
        let h = rx_hi(b, ea)?;
        permilp_val(b, 64, imm >> 2, h)
    } else {
        b.konst::<W128>(0)
    };
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

/// VPERMILPS/VPERMILPD の可変形。制御は第2ソースの要素
/// （ps: dword [1:0]、pd: qword bit1）。
pub fn vpermilp_v<B: Backend>(
    b: &mut B,
    fbits: u32,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    vbin2(b, d, ea, |b, a, c| {
        let n = 128 / fbits;
        let shmul = b.konst::<W128>(u128::from(fbits.trailing_zeros()));
        let maskv = b.konst::<W128>((1u128 << fbits) - 1);
        let mut acc = b.konst::<W128>(0);
        for i in 0..n {
            // 制御値（ps: dword[1:0]、pd: qword bit1）を動的シフト量にする。
            let cb = if fbits == 32 {
                lane128(b, c, i * 32, 2)
            } else {
                lane128(b, c, i * 64 + 1, 1)
            };
            let sh = b.shl::<W128>(cb, shmul);
            let sf = b.shr_l::<W128>(a, sh);
            let l = b.and::<W128>(sf, maskv);
            acc = put_lane128(b, acc, l, i * fbits, fbits);
        }
        acc
    })
}

/// VPERM2F128/VPERM2I128。imm で両ソースの 128 半分を選ぶ
/// （imm[1:0]+zero[3] → 下位、imm[5:4]+zero[7] → 上位）。L=1 専用。
pub fn vperm2x128<B: Backend>(
    b: &mut B,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let alo: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    let ahi: B::V<W128> = b.get(sem::ymm_hi_ref(vvv_x(d)));
    let clo = rx(b, ea, 128)?;
    let chi = rx_hi(b, ea)?;
    let pick = |b: &mut B, sel: u8, zero: u8| -> B::V<W128> {
        if zero != 0 {
            return b.konst::<W128>(0);
        }
        match sel & 3 {
            0 => alo,
            1 => ahi,
            2 => clo,
            _ => chi,
        }
    };
    let lo = pick(b, imm & 3, imm >> 3 & 1);
    b.set(sem::xmm_ref(dst), lo);
    let hi = pick(b, imm >> 4 & 3, imm >> 7 & 1);
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

/// 256 ビット中の `idx` 番要素をシフト+マスク+選択で取る。
/// `idx` は 0..(256/bits-1) の範囲を仮定（呼び出し側でマスク済み）。
fn perm_elem_dyn<B: Backend>(
    b: &mut B,
    lo: B::V<W128>,
    hi: B::V<W128>,
    bits: u32,
    idx: B::V<W128>,
) -> B::V<W128> {
    let n = 256 / bits;
    // 半分内の位置（idx % (n/2)）で各半分をシフトする（シフト量は < 128）。
    let kloc = b.konst::<W128>(u128::from(n / 2 - 1));
    let local = b.and::<W128>(idx, kloc);
    let shc = b.konst::<W128>(u128::from(bits.trailing_zeros()));
    let sh = b.shl::<W128>(local, shc);
    let maskv = b.konst::<W128>((1u128 << bits) - 1);
    let slo = b.shr_l::<W128>(lo, sh);
    let el = b.and::<W128>(slo, maskv);
    let shi = b.shr_l::<W128>(hi, sh);
    let eh = b.and::<W128>(shi, maskv);
    // idx の上位半分ビットが立っていれば hi 側を選ぶ。
    let khb = b.konst::<W128>(u128::from(n / 2));
    let hib = b.and::<W128>(idx, khb);
    let k0 = b.konst::<W128>(0);
    let pick_hi = b.cmp::<W128>(Cmp::Ne, hib, k0);
    b.select::<W128>(pick_hi, eh, el)
}

/// VPERMD/VPERMPS。dst.d[i] = src2.d[ctrl.d[i] & 7]（256 全域選択）。L=1 専用。
pub fn vpermd<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let clo = rx(b, ea, 128)?;
    let chi = rx_hi(b, ea)?;
    let alo: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    let ahi: B::V<W128> = b.get(sem::ymm_hi_ref(vvv_x(d)));
    let k7 = b.konst::<W128>(7);
    let mut lo = b.konst::<W128>(0);
    let mut hi = b.konst::<W128>(0);
    for i in 0..4u32 {
        let cl = lane128(b, alo, i * 32, 32);
        let cv: B::V<W32> = b.trunc::<W128, W32>(cl);
        let cv128 = b.zext::<W32, W128>(cv);
        let idx = b.and::<W128>(cv128, k7);
        let e = perm_elem_dyn::<B>(b, clo, chi, 32, idx);
        lo = put_lane128(b, lo, e, i * 32, 32);
        let ch = lane128(b, ahi, i * 32, 32);
        let cvh: B::V<W32> = b.trunc::<W128, W32>(ch);
        let cvh128 = b.zext::<W32, W128>(cvh);
        let idxh = b.and::<W128>(cvh128, k7);
        let eh = perm_elem_dyn::<B>(b, clo, chi, 32, idxh);
        hi = put_lane128(b, hi, eh, i * 32, 32);
    }
    b.set(sem::xmm_ref(dst), lo);
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

/// VPERMQ（即値形）。dst.q[i] = src.q[imm フィールド]（256 全域選択）。L=1 専用。
pub fn vpermq<B: Backend>(
    b: &mut B,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let slo = rx(b, ea, 128)?;
    let shi = rx_hi(b, ea)?;
    for half in 0..2u32 {
        let mut acc = b.konst::<W128>(0);
        for i in 0..2u32 {
            let sel = u32::from(imm >> (2 * (half * 2 + i)) & 3);
            let s = if sel < 2 { slo } else { shi };
            let l = lane128(b, s, (sel & 1) * 64, 64);
            acc = put_lane128(b, acc, l, i * 64, 64);
        }
        if half == 0 {
            b.set(sem::xmm_ref(dst), acc);
        } else {
            b.set(sem::ymm_hi_ref(dst), acc);
        }
    }
    Ok(())
}

/// VBROADCASTSS。ソースの下位 32 ビットを全 dword に複製。
pub fn vbcastss<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let e: B::V<W32> = match ea {
        Rm::Reg(g) => {
            let s: B::V<W128> = b.get(sem::xmm_ref(Xmm(g.0)));
            b.trunc::<W128, W32>(s)
        }
        _ => decode::rd32(b, ea)?,
    };
    let e128 = b.zext::<W32, W128>(e);
    let mut v = b.konst::<W128>(0);
    for i in 0..4u32 {
        v = put_lane128(b, v, e128, i * 32, 32);
    }
    b.set(sem::xmm_ref(dst), v);
    let hi = if d.vex_l { v } else { b.konst::<W128>(0) };
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

/// VBROADCASTSD。ソースの下位 64 ビットを全 qword に複製（L=1 専用）。
pub fn vbcastsd<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let e: B::V<W64> = match ea {
        Rm::Reg(g) => {
            let s: B::V<W128> = b.get(sem::xmm_ref(Xmm(g.0)));
            b.trunc::<W128, W64>(s)
        }
        _ => decode::rd64(b, ea)?,
    };
    let e128 = b.zext::<W64, W128>(e);
    let mut v = b.konst::<W128>(0);
    for i in 0..2u32 {
        v = put_lane128(b, v, e128, i * 64, 64);
    }
    b.set(sem::xmm_ref(dst), v);
    b.set(sem::ymm_hi_ref(dst), v);
    Ok(())
}

/// VBROADCASTF128/VBROADCASTI128。m128 を両半分に複製（L=1・メモリのみ）。
pub fn vbcastx128<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let s = rx(b, ea, 128)?;
    b.set(sem::xmm_ref(dst), s);
    b.set(sem::ymm_hi_ref(dst), s);
    Ok(())
}

/// VPBROADCASTB/W/D/Q。ソースの下位要素を全要素に複製（AVX2）。
pub fn vpbroadcast<B: Backend>(
    b: &mut B,
    bits: u32,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let e: B::V<W64> = match ea {
        Rm::Reg(g) => {
            let s: B::V<W128> = b.get(sem::xmm_ref(Xmm(g.0)));
            b.trunc::<W128, W64>(s)
        }
        _ => match bits {
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
        },
    };
    let e128 = b.zext::<W64, W128>(e);
    let mut v = b.konst::<W128>(0);
    for i in 0..128 / bits {
        v = put_lane128(b, v, e128, i * bits, bits);
    }
    b.set(sem::xmm_ref(dst), v);
    let hi = if d.vex_l { v } else { b.konst::<W128>(0) };
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

/// VINSERTF128/VINSERTI128。vvvv の imm[0] で選んだ 128 半分を
/// r/m の 128 ビットで置き換える。L=1 専用。
pub fn vinsertx128<B: Backend>(
    b: &mut B,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let s = rx(b, ea, 128)?;
    if imm & 1 == 1 {
        let keep: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
        b.set(sem::xmm_ref(dst), keep);
        b.set(sem::ymm_hi_ref(dst), s);
    } else {
        let keep: B::V<W128> = b.get(sem::ymm_hi_ref(vvv_x(d)));
        b.set(sem::xmm_ref(dst), s);
        b.set(sem::ymm_hi_ref(dst), keep);
    }
    Ok(())
}

/// VEXTRACTF128/VEXTRACTI128。ymm の imm[0] で選んだ 128 半分を書く。
pub fn vextractx128<B: Backend>(
    b: &mut B,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let v: B::V<W128> = if imm & 1 == 1 {
        b.get(sem::ymm_hi_ref(reg_x(d)))
    } else {
        b.get(sem::xmm_ref(reg_x(d)))
    };
    wx(b, ea, 128, v)?;
    if let Rm::Reg(g) = ea {
        let z = b.konst::<W128>(0);
        b.set(sem::ymm_hi_ref(Xmm(g.0)), z);
    }
    Ok(())
}

/// マスクベクトルの要素 `i`（`elt` ビット幅）の MSB が立つか。
fn vmask_bit<B: Backend>(b: &mut B, m: B::V<W128>, i: u32, elt: u32) -> B::B {
    let e = lane128(b, m, i * elt, elt);
    let sh = b.konst::<W128>(u128::from(elt - 1));
    let t = b.shr_l::<W128>(e, sh);
    let z = b.konst::<W128>(0);
    b.cmp::<W128>(Cmp::Ne, t, z)
}

/// `elt` 幅の条件付きロード。`pos` は出力レーン位置。
fn vmask_load<B: Backend>(
    b: &mut B,
    ad: B::V<W64>,
    cur: B::V<W128>,
    pos: u32,
    elt: u32,
) -> Result<B::V<W128>, B::Exit> {
    if elt == 32 {
        let v: B::V<W32> = b.load::<W32>(ad, sem::DATA_READ)?;
        let e = b.zext::<W32, W128>(v);
        Ok(put_lane128(b, cur, e, pos, 32))
    } else {
        let v: B::V<W64> = b.load::<W64>(ad, sem::DATA_READ)?;
        let e = b.zext::<W64, W128>(v);
        Ok(put_lane128(b, cur, e, pos, 64))
    }
}

/// VMASKMOVPS/PD・VPMASKMOVD/Q のロード形。マスク MSB の立つ
/// 要素だけ読み、残りはゼロ（フォールト抑制）。メモリ形のみ。
pub fn vmaskmov_ld<B: Backend>(
    b: &mut B,
    elt: u32,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let mx = vvv_x(d);
    let a = match ea {
        Rm::Mem { a, .. } => *a,
        Rm::Reg(_) => return Ok(()),
    };
    let per = 128 / elt;
    let n = if d.vex_l { per * 2 } else { per };
    // dst とマスクが同じレジスタでも正しく動くよう、
    // dst のゼロ化前にマスクを両半分読んでおく。
    let mlo: B::V<W128> = b.get(sem::xmm_ref(mx));
    let mhi: B::V<W128> = if d.vex_l {
        b.get(sem::ymm_hi_ref(mx))
    } else {
        mlo
    };
    let z = b.konst::<W128>(0);
    b.set(sem::xmm_ref(dst), z);
    let z = b.konst::<W128>(0);
    b.set(sem::ymm_hi_ref(dst), z);
    for i in 0..n {
        let (m, li) = if i < per { (mlo, i) } else { (mhi, i - per) };
        let on = vmask_bit(b, m, li, elt);
        b.if_then(on, |b| {
            let off = b.konst::<W64>(u64::from(i * (elt / 8)));
            let ad = b.add::<W64>(a, off);
            let cur: B::V<W128> = if i < per {
                b.get(sem::xmm_ref(dst))
            } else {
                b.get(sem::ymm_hi_ref(dst))
            };
            let r = vmask_load(b, ad, cur, li * elt, elt)?;
            if i < per {
                b.set(sem::xmm_ref(dst), r);
            } else {
                b.set(sem::ymm_hi_ref(dst), r);
            }
            Ok(())
        })?;
    }
    Ok(())
}

/// VMASKMOVPS/PD・VPMASKMOVD/Q のストア形。マスク MSB の立つ
/// 要素だけ書く（フォールト抑制）。メモリ形のみ。
pub fn vmaskmov_st<B: Backend>(
    b: &mut B,
    elt: u32,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let src = reg_x(d);
    let mx = vvv_x(d);
    let a = match ea {
        Rm::Mem { a, .. } => *a,
        Rm::Reg(_) => return Ok(()),
    };
    let per = 128 / elt;
    let n = if d.vex_l { per * 2 } else { per };
    let mlo: B::V<W128> = b.get(sem::xmm_ref(mx));
    let mhi: B::V<W128> = if d.vex_l {
        b.get(sem::ymm_hi_ref(mx))
    } else {
        mlo
    };
    let shi: B::V<W128> = if d.vex_l {
        b.get(sem::ymm_hi_ref(src))
    } else {
        mlo
    };
    for i in 0..n {
        let (m, li) = if i < per { (mlo, i) } else { (mhi, i - per) };
        let on = vmask_bit(b, m, li, elt);
        b.if_then(on, |b| {
            let s = if i < per {
                b.get(sem::xmm_ref(src))
            } else {
                shi
            };
            let off = b.konst::<W64>(u64::from(i * (elt / 8)));
            let ad = b.add::<W64>(a, off);
            let l = lane128(b, s, li * elt, elt);
            if elt == 32 {
                let v: B::V<W32> = b.trunc::<W128, W32>(l);
                b.store::<W32>(ad, v, sem::DATA_WRITE)
            } else {
                let v: B::V<W64> = b.trunc::<W128, W64>(l);
                b.store::<W64>(ad, v, sem::DATA_WRITE)
            }
        })?;
    }
    Ok(())
}

/// VGATHER*/VPGATHER*。VSIB（SIB.index のベクトル）の要素ごとに
/// base + sext(index)*scale + disp を計算して条件ロードする。
/// マスクされなかった要素は dst の旧値を残し、マスクレジスタは
/// 最後に全要素クリアされる。`idx_q` は index 要素が 64 ビットか
/// （オペコード bit0）。収集幅は VEX.W（`d.vex_w`）で 32/64。
/// 実機では dst/index/mask が重なるエンコードは #UD だが、ここでは
/// 検査せず事前に読んだ値で処理する（合法コードには影響しない）。
pub fn vgather<B: Backend>(b: &mut B, idx_q: bool, d: &MapDec, seg: u64) -> Result<(), B::Exit> {
    // VSIB は SIB 必須。rm!=4 のメモリ形は非合法エンコードなので
    // 何もしない（フォールトはモデル化しない）。
    if !d.has_sib {
        return Ok(());
    }
    let dbits = if d.vex_w { 64 } else { 32 };
    let dst = reg_x(d);
    let mx = vvv_x(d);
    let (base, scale, disp, iv) = decode::vsib(b, d);
    let ibits = if idx_q { 64 } else { 32 };
    let per = 128 / dbits;
    let iper = 128 / ibits;
    // 収集要素数。qword index・dword 収集（QPS/QD）は 128 ビット
    // 形のみで 2 要素。dword index・dword 収集は全幅。qword 収集は半幅。
    let n = if dbits == 32 && idx_q {
        2
    } else if dbits == 32 {
        if d.vex_l { 8 } else { 4 }
    } else if d.vex_l {
        4
    } else {
        2
    };
    let mlo: B::V<W128> = b.get(sem::xmm_ref(mx));
    let mhi: B::V<W128> = if d.vex_l {
        b.get(sem::ymm_hi_ref(mx))
    } else {
        mlo
    };
    let ilo: B::V<W128> = b.get(sem::xmm_ref(Xmm(iv)));
    let ihi: B::V<W128> = if d.vex_l {
        b.get(sem::ymm_hi_ref(Xmm(iv)))
    } else {
        ilo
    };
    for i in 0..n {
        let (m, li) = if i < per { (mlo, i) } else { (mhi, i - per) };
        let on = vmask_bit(b, m, li, dbits);
        let (ivv, ii) = if i < iper { (ilo, i) } else { (ihi, i - iper) };
        b.if_then(on, |b| {
            let iev = lane128(b, ivv, ii * ibits, ibits);
            let i64v: B::V<W64> = if idx_q {
                b.trunc::<W128, W64>(iev)
            } else {
                let t: B::V<W32> = b.trunc::<W128, W32>(iev);
                b.sext::<W32, W64>(t)
            };
            let sc = b.konst::<W64>(u64::from(scale));
            let sh = b.shl::<W64>(i64v, sc);
            let mut ad = b.add::<W64>(base, sh);
            let dv = b.konst::<W64>(disp as u64);
            ad = b.add::<W64>(ad, dv);
            if d.asize == 32 {
                let m32 = b.konst::<W64>(0xFFFF_FFFF);
                ad = b.and::<W64>(ad, m32);
            }
            if seg != 0 {
                let s = b.konst::<W64>(seg);
                ad = b.add::<W64>(ad, s);
            }
            let cur: B::V<W128> = if i < per {
                b.get(sem::xmm_ref(dst))
            } else {
                b.get(sem::ymm_hi_ref(dst))
            };
            let pos = (i - if i < per { 0 } else { per }) * dbits;
            let r = vmask_load(b, ad, cur, pos, dbits)?;
            if i < per {
                b.set(sem::xmm_ref(dst), r);
            } else {
                b.set(sem::ymm_hi_ref(dst), r);
            }
            Ok(())
        })?;
    }
    // 収集対象外の残り要素はゼロ（QPS/QD は 2 要素のみ）。
    // 128 ビット形では上位半分もゼロ。
    let full = if d.vex_l { per * 2 } else { per };
    for i in n..full {
        let z = b.konst::<W128>(0);
        if i < per {
            let cur: B::V<W128> = b.get(sem::xmm_ref(dst));
            let r = put_lane128(b, cur, z, i * dbits, dbits);
            b.set(sem::xmm_ref(dst), r);
        } else {
            let cur: B::V<W128> = b.get(sem::ymm_hi_ref(dst));
            let r = put_lane128(b, cur, z, (i - per) * dbits, dbits);
            b.set(sem::ymm_hi_ref(dst), r);
        }
    }
    if !d.vex_l {
        let z = b.konst::<W128>(0);
        b.set(sem::ymm_hi_ref(dst), z);
    }
    // 終了時にマスクは全要素クリアされる。
    let z = b.konst::<W128>(0);
    b.set(sem::xmm_ref(mx), z);
    let z = b.konst::<W128>(0);
    b.set(sem::ymm_hi_ref(mx), z);
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

/// CVTPI2PS xmm, mm/m64。2 個の s32 を f32 にして下位 64 へ
/// 書く。上位 64 は従来値のまま。
pub fn cvtpi2ps<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let v = rq(b, ea)?;
    let mut conv = b.konst::<W64>(0);
    for i in 0..2u32 {
        let l = lane64(b, v, i * 32, 32);
        let x = b.trunc::<W64, W32>(l);
        let f = b.fcvt_from_s32::<polyisa_sem::F32>(x, RM_RNE);
        let bits = b.trunc::<polyisa_sem::F32, W32>(f);
        let z = b.zext::<W32, W64>(bits);
        conv = put_lane64(b, conv, z, i * 32, 32);
    }
    let old: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    let conv128 = b.zext::<W64, W128>(conv);
    let out = put_lane128(b, old, conv128, 0, 64);
    b.set(sem::xmm_ref(reg_x(d)), out);
    Ok(())
}

/// CVTPI2PD xmm, mm/m64。2 個の s32 を f64 にして xmm 全体へ書く。
pub fn cvtpi2pd<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let v = rq(b, ea)?;
    let mut out = b.konst::<W128>(0);
    for i in 0..2u32 {
        let l = lane64(b, v, i * 32, 32);
        let x = b.trunc::<W64, W32>(l);
        let f = b.fcvt_from_s32::<polyisa_sem::F64>(x, RM_RNE);
        let bits = b.trunc::<polyisa_sem::F64, W64>(f);
        let z = b.zext::<W64, W128>(bits);
        out = put_lane128(b, out, z, i * 64, 64);
    }
    b.set(sem::xmm_ref(reg_x(d)), out);
    Ok(())
}

/// CVTPS2PI/CVTTPS2PI mm, xmm/m64。下位 2 個の f32 を s32 にする。
pub fn cvtps2pi<B: Backend>(
    b: &mut B,
    trunc: bool,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let v128 = rx(b, ea, 64)?;
    let mut out = b.konst::<W64>(0);
    let rm = if trunc { RM_RTZ } else { RM_RNE };
    for i in 0..2u32 {
        let l = lane128(b, v128, i * 32, 32);
        let bits = b.trunc::<W128, W32>(l);
        let f = b.trunc::<W32, polyisa_sem::F32>(bits);
        let x = b.fcvt_s32::<polyisa_sem::F32>(f, rm);
        let z = b.zext::<W32, W64>(x);
        out = put_lane64(b, out, z, i * 32, 32);
    }
    b.set(sem::st_sig_ref(reg_m(d)), out);
    Ok(())
}

/// CVTPD2PI/CVTTPD2PI mm, xmm/m128。2 個の f64 を s32 にする。
pub fn cvtpd2pi<B: Backend>(
    b: &mut B,
    trunc: bool,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let v128 = rx(b, ea, 128)?;
    let mut out = b.konst::<W64>(0);
    let rm = if trunc { RM_RTZ } else { RM_RNE };
    for i in 0..2u32 {
        let l = lane128(b, v128, i * 64, 64);
        let bits = b.trunc::<W128, W64>(l);
        let f = b.trunc::<W64, polyisa_sem::F64>(bits);
        let x = b.fcvt_s32::<polyisa_sem::F64>(f, rm);
        let z = b.zext::<W32, W64>(x);
        out = put_lane64(b, out, z, i * 32, 32);
    }
    b.set(sem::st_sig_ref(reg_m(d)), out);
    Ok(())
}

/// MOVDQ2Q mm, xmm。xmm の下位 64 ビットを mm へ写す。
pub fn movdq2q<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let x = rx(b, ea, 128)?;
    let v = lane128(b, x, 0, 64);
    let v64 = b.trunc::<W128, W64>(v);
    b.set(sem::st_sig_ref(reg_m(d)), v64);
    Ok(())
}

/// MOVQ2DQ xmm, mm。mm を下位 64 ビットへ写し上位を 0 にする。
pub fn movq2dq<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let v = rq(b, ea)?;
    let out = b.zext::<W64, W128>(v);
    b.set(sem::xmm_ref(reg_x(d)), out);
    Ok(())
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

/// EMMS。全 x87 タグを empty にする。
pub fn emms<B: Backend>(b: &mut B) -> Flow<B> {
    let empty_tags = b.konst::<W16>(0xffff);
    b.set(sem::ftw_ref(), empty_tags);
    Ok(())
}

// ===== 3DNow!（0F 0F /r imm8、MMX 上のパック単精度）=====
// 2 レーンの f32 を mm レジスタ（x87 仮数スロット）に詰める。
// PFRCP/PFRSQRT の近似テーブルや PFRCPIT2 の捨てビット復元は
// モデル化せず、近似命令は正確な除算/平方根で代用する。

/// W64 中の `i` 番目の 32 ビットを f32 として取り出す。
fn flane32_64<B: Backend>(b: &mut B, v: B::V<W64>, i: u32) -> B::V<F32> {
    let l = lane64(b, v, i * 32, 32);
    let w: B::V<W32> = b.trunc::<W64, W32>(l);
    b.trunc::<W32, F32>(w)
}

/// f32 を `dst`（W64）のレーン `i` へ書く。
fn put_flane32_64<B: Backend>(b: &mut B, dst: B::V<W64>, v: B::V<F32>, i: u32) -> B::V<W64> {
    let w: B::V<W32> = b.trunc::<F32, W32>(v);
    let w64 = b.zext::<W32, W64>(w);
    put_lane64(b, dst, w64, i * 32, 32)
}

/// W32 の符号比較で `lo`/`hi` に飽和させる。
fn clamp_w32<B: Backend>(b: &mut B, v: B::V<W32>, lo: u32, hi: u32) -> B::V<W32> {
    let hv = b.konst::<W32>(hi);
    let ge_hi = b.cmp::<W32>(Cmp::GtS, v, hv);
    let lv = b.konst::<W32>(lo);
    let lt_lo = b.cmp::<W32>(Cmp::LtS, v, lv);
    let t = b.select::<W32>(ge_hi, hv, v);
    b.select::<W32>(lt_lo, lv, t)
}

/// 3DNow! の操作種別。
#[derive(Clone, Copy)]
pub enum Dop {
    /// レーンごとの二項演算。Subr は c-a。
    Add,
    Sub,
    Subr,
    Mul,
    Min,
    Max,
    /// 比較（成立で全 1、さもなければ 0）。
    CmpEq,
    CmpGe,
    CmpGt,
    /// 横方向の累積。dst 側を畳んで下位、src 側を畳んで
    /// 上位に置く。Acc は両側が加算、Nacc は両側が
    /// lo-hi、Pnacc は dst 側が lo-hi・src 側が加算。
    Acc,
    Nacc,
    Pnacc,
    /// レーン交換（src のみ）。
    Swap,
    /// 逆数系。近似命令は正確値で代用。
    Rcp,
    Rsqrt,
    /// Newton-Raphson の第 1 補正。RcpIt1 は 2-a*c、
    /// RsqrtIt1 は (3-a*c)/2、RcpIt2 は最終乗算 a*c。
    RcpIt1,
    RsqrtIt1,
    RcpIt2,
    /// 変換。F2* は f32→符号付き整数（切り捨て・飽和）、
    /// I2* は符号付き整数→f32。
    F2Id,
    F2Iw,
    I2Fd,
    I2Fw,
    /// PAVGUSB（バイトの丸め付き平均）と PMULHRW
    /// （符号付きワード乗算の上位+丸め）。
    AvgUsb,
    MulHrw,
}

/// 3DNow! の共通実装。dst = mm（ModRM.reg）、src = mm/m64。
pub fn dnow<B: Backend>(b: &mut B, op: Dop, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    use polyisa_sem::F32;
    let dst = reg_m(d);
    let a: B::V<W64> = b.get(sem::st_sig_ref(dst));
    let c = rq(b, ea)?;
    let mut acc = b.konst::<W64>(0);
    match op {
        Dop::Acc | Dop::Nacc | Dop::Pnacc => {
            let a0 = flane32_64(b, a, 0);
            let a1 = flane32_64(b, a, 1);
            let c0 = flane32_64(b, c, 0);
            let c1 = flane32_64(b, c, 1);
            // dst（第 1 オペランド）側を畳んで下位に置く:
            // Acc は加算、Nacc/Pnacc は lo-hi。
            let lo = if matches!(op, Dop::Acc) {
                b.fadd::<F32>(a0, a1)
            } else {
                b.fsub::<F32>(a0, a1)
            };
            // src（第 2 オペランド）側を畳んで上位に置く:
            // Nacc は lo-hi、Acc/Pnacc は加算。
            let hi = if matches!(op, Dop::Nacc) {
                b.fsub::<F32>(c0, c1)
            } else {
                b.fadd::<F32>(c0, c1)
            };
            acc = put_flane32_64(b, acc, lo, 0);
            acc = put_flane32_64(b, acc, hi, 1);
        }
        Dop::Swap => {
            let c0 = flane32_64(b, c, 0);
            let c1 = flane32_64(b, c, 1);
            acc = put_flane32_64(b, acc, c1, 0);
            acc = put_flane32_64(b, acc, c0, 1);
        }
        Dop::CmpEq | Dop::CmpGe | Dop::CmpGt => {
            let ones = b.konst::<W32>(0xffff_ffff);
            let zero = b.konst::<W32>(0);
            for i in 0..2 {
                let af = flane32_64(b, a, i);
                let cf = flane32_64(b, c, i);
                let hit = match op {
                    Dop::CmpEq => b.feq::<F32>(af, cf),
                    Dop::CmpGe => b.fle::<F32>(cf, af),
                    _ => b.flt::<F32>(cf, af),
                };
                let w = b.select::<W32>(hit, ones, zero);
                let w64 = b.zext::<W32, W64>(w);
                acc = put_lane64(b, acc, w64, i * 32, 32);
            }
        }
        Dop::F2Id => {
            for i in 0..2 {
                let af = flane32_64(b, c, i);
                let w: B::V<W32> = b.fcvt_s32::<F32>(af, RM_RTZ);
                let w64 = b.zext::<W32, W64>(w);
                acc = put_lane64(b, acc, w64, i * 32, 32);
            }
        }
        Dop::F2Iw => {
            for i in 0..2 {
                let af = flane32_64(b, c, i);
                let w: B::V<W32> = b.fcvt_s32::<F32>(af, RM_RTZ);
                let w = clamp_w32(b, w, 0xffff_8000, 0x0000_7fff);
                let w64 = b.zext::<W32, W64>(w);
                acc = put_lane64(b, acc, w64, i * 32, 32);
            }
        }
        Dop::I2Fd => {
            for i in 0..2 {
                let l = lane64(b, c, i * 32, 32);
                let w: B::V<W32> = b.trunc::<W64, W32>(l);
                let f = b.fcvt_from_s32::<F32>(w, RM_RNE);
                acc = put_flane32_64(b, acc, f, i);
            }
        }
        Dop::I2Fw => {
            for i in 0..2 {
                let l = lane64(b, c, i * 32, 16);
                let w16: B::V<W16> = b.trunc::<W64, W16>(l);
                let w: B::V<W32> = b.sext::<W16, W32>(w16);
                let f = b.fcvt_from_s32::<F32>(w, RM_RNE);
                acc = put_flane32_64(b, acc, f, i);
            }
        }
        Dop::AvgUsb => {
            for i in 0..8 {
                let al64 = lane64(b, a, i * 8, 8);
                let cl64 = lane64(b, c, i * 8, 8);
                let al = b.trunc::<W64, W32>(al64);
                let cl = b.trunc::<W64, W32>(cl64);
                let one = b.konst::<W32>(1);
                let s = b.add::<W32>(al, cl);
                let s = b.add::<W32>(s, one);
                let r = b.shr_l::<W32>(s, one);
                let r64 = b.zext::<W32, W64>(r);
                acc = put_lane64(b, acc, r64, i * 8, 8);
            }
        }
        Dop::MulHrw => {
            for i in 0..4 {
                let al64 = lane64(b, a, i * 16, 16);
                let cl64 = lane64(b, c, i * 16, 16);
                let al: B::V<W16> = b.trunc::<W64, W16>(al64);
                let cl: B::V<W16> = b.trunc::<W64, W16>(cl64);
                let a32 = b.sext::<W16, W32>(al);
                let c32 = b.sext::<W16, W32>(cl);
                let p = b.mul::<W32>(a32, c32);
                let rnd = b.konst::<W32>(0x8000);
                let p = b.add::<W32>(p, rnd);
                let sh = b.konst::<W32>(16);
                let r = b.shr_a::<W32>(p, sh);
                let r64 = b.zext::<W32, W64>(r);
                acc = put_lane64(b, acc, r64, i * 16, 16);
            }
        }
        // 残りは全てレーンごとの f32 演算。
        _ => {
            for i in 0..2 {
                let af = flane32_64(b, a, i);
                let cf = flane32_64(b, c, i);
                let rf = match op {
                    Dop::Add => b.fadd::<F32>(af, cf),
                    Dop::Sub => b.fsub::<F32>(af, cf),
                    Dop::Subr => b.fsub::<F32>(cf, af),
                    Dop::Mul => b.fmul::<F32>(af, cf),
                    Dop::Min => b.fmin::<F32>(af, cf),
                    Dop::Max => b.fmax::<F32>(af, cf),
                    Dop::Rcp => {
                        let one = b.konst::<F32>(0x3f80_0000);
                        b.fdiv::<F32>(one, cf)
                    }
                    Dop::Rsqrt => {
                        let one = b.konst::<F32>(0x3f80_0000);
                        let sq = b.fsqrt::<F32>(cf);
                        b.fdiv::<F32>(one, sq)
                    }
                    Dop::RcpIt1 => {
                        let two = b.konst::<F32>(0x4000_0000);
                        let p = b.fmul::<F32>(af, cf);
                        b.fsub::<F32>(two, p)
                    }
                    Dop::RsqrtIt1 => {
                        let three = b.konst::<F32>(0x4040_0000);
                        let two = b.konst::<F32>(0x4000_0000);
                        let p = b.fmul::<F32>(af, cf);
                        let s = b.fsub::<F32>(three, p);
                        b.fdiv::<F32>(s, two)
                    }
                    // RcpIt2 は近似値と補正係数の最終乗算。
                    _ => b.fmul::<F32>(af, cf),
                };
                acc = put_flane32_64(b, acc, rf, i);
            }
        }
    }
    b.set(sem::st_sig_ref(dst), acc);
    Ok(())
}

/// FEMMS。MMX 状態の解放（EMMS と同じく全 x87 tag を empty にする）。
pub fn femms<B: Backend>(b: &mut B) -> Flow<B> {
    emms(b)
}

/// EMMS 以外の MMX 命令が成功したときの x87 状態遷移。
/// SDM Vol.1 Chapter 9/10: TOP=0、全 tag は valid。MMX レジスタへの
/// 書き込みでは、対応する x87 80 ビットレジスタの上位 16 ビットが
/// 全 1 になる。
pub fn mmx_entry<B: Backend>(b: &mut B) {
    let z16 = b.konst::<W16>(0);
    b.set(sem::top_ref(), z16);
    b.set(sem::ftw_ref(), z16);
}

/// MMX レジスタ write に伴う exponent/sign 部の更新。
pub fn mmx_written<B: Backend>(b: &mut B, slot: usize) {
    let ones = b.konst::<W16>(0xffff);
    b.set(sem::st_exp_ref(slot), ones);
}

// ===== SSE4a（AMD 拡張）=====

/// EXTRQ/INSERTQ のフィールドマスク（値）。length が 0 のとき
/// 64（全ビット）を意味する。
fn extrq_mask<B: Backend>(b: &mut B, len: B::V<W64>) -> B::V<W64> {
    let zero = b.konst::<W64>(0);
    let is0 = b.cmp::<W64>(Cmp::Eq, len, zero);
    let one = b.konst::<W64>(1);
    let sh = b.shl::<W64>(one, len);
    let m = b.sub::<W64>(sh, one);
    let all = b.konst::<W64>(u64::MAX);
    b.select::<W64>(is0, all, m)
}

/// EXTRQ（imm 形）。r/m 宛先の下位 64 ビットから index 位置・
/// length 幅のフィールドを抽出して下位に置く。index+length が
/// 64 を超えるとき結果は不定（Zen では単純な右シフト結果に
/// なった観測値）だが、ここでは `(src >> idx) & mask(len)` で
/// 求める。上位 64 ビットは不定 → 0。
pub fn extrqi<B: Backend>(b: &mut B, len: u8, idx: u8, d: &MapDec) -> Flow<B> {
    let dst = rm_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let lo: B::V<W64> = b.trunc::<W128, W64>(a);
    let n = u64::from(len & 0x3F);
    let p = u64::from(idx & 0x3F);
    let mask = if n == 0 { u64::MAX } else { (1u64 << n) - 1 };
    let kp = b.konst::<W64>(p);
    let sh = b.shr_l::<W64>(lo, kp);
    let km = b.konst::<W64>(mask);
    let v = b.and::<W64>(sh, km);
    let v128 = b.zext::<W64, W128>(v);
    b.set(sem::xmm_ref(dst), v128);
    Ok(())
}

/// EXTRQ（reg 形）。reg 宛先の下位 64 ビットから、r/m ソースの
/// b[0]=length・b[1]=index で指定されるフィールドを抽出。
pub fn extrqr<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Flow<B> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let lo: B::V<W64> = b.trunc::<W128, W64>(a);
    let c = rx(b, ea, 128)?;
    let c64: B::V<W64> = b.trunc::<W128, W64>(c);
    let k63 = b.konst::<W64>(0x3F);
    let len = b.and::<W64>(c64, k63);
    let k8 = b.konst::<W64>(8);
    let idxb = b.shr_l::<W64>(c64, k8);
    let idx = b.and::<W64>(idxb, k63);
    let mask = extrq_mask(b, len);
    let sh = b.shr_l::<W64>(lo, idx);
    let v = b.and::<W64>(sh, mask);
    let v128 = b.zext::<W64, W128>(v);
    b.set(sem::xmm_ref(dst), v128);
    Ok(())
}

/// INSERTQ の挿入合成（値）。`dlo` の index 位置に `slo` の
/// 下位 length ビットを挿入する。index+length が 64 を超えて
/// はみ出る上位ビットは失われる（Zen 観測値と同じ単純シフト）。
fn insertq_val<B: Backend>(
    b: &mut B,
    dlo: B::V<W64>,
    slo: B::V<W64>,
    len: B::V<W64>,
    idx: B::V<W64>,
) -> B::V<W64> {
    let mask = extrq_mask(b, len);
    let msh = b.shl::<W64>(mask, idx);
    let nm = b.not::<W64>(msh);
    let keep = b.and::<W64>(dlo, nm);
    let bits = b.and::<W64>(slo, mask);
    let ins = b.shl::<W64>(bits, idx);
    b.or::<W64>(keep, ins)
}

/// INSERTQ（imm 形）。reg 宛先に r/m ソースの下位 length ビットを
/// index 位置へ挿入。ib は（length, index）の順。上位 64 ビットは
/// 不定 → 0。
pub fn insertqi<B: Backend>(
    b: &mut B,
    len: u8,
    idx: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let dlo: B::V<W64> = b.trunc::<W128, W64>(a);
    let c = rx(b, ea, 64)?;
    let slo: B::V<W64> = b.trunc::<W128, W64>(c);
    let lenc = b.konst::<W64>(u64::from(len & 0x3F));
    let idxc = b.konst::<W64>(u64::from(idx & 0x3F));
    let v = insertq_val(b, dlo, slo, lenc, idxc);
    let v128 = b.zext::<W64, W128>(v);
    b.set(sem::xmm_ref(dst), v128);
    Ok(())
}

/// INSERTQ（reg 形）。r/m ソースの下位 64 ビットを reg 宛先へ
/// 挿入。制御はソース xmm の b[8]=length・b[9]=index。
pub fn insertqr<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Flow<B> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let dlo: B::V<W64> = b.trunc::<W128, W64>(a);
    let c = rx(b, ea, 128)?;
    let k64 = b.konst::<W128>(64);
    let hi128 = b.shr_l::<W128>(c, k64);
    let hi: B::V<W64> = b.trunc::<W128, W64>(hi128);
    let k63 = b.konst::<W64>(0x3F);
    let len = b.and::<W64>(hi, k63);
    let k8 = b.konst::<W64>(8);
    let idxb = b.shr_l::<W64>(hi, k8);
    let idx = b.and::<W64>(idxb, k63);
    let slo: B::V<W64> = b.trunc::<W128, W64>(c);
    let v = insertq_val(b, dlo, slo, len, idx);
    let v128 = b.zext::<W64, W128>(v);
    b.set(sem::xmm_ref(dst), v128);
    Ok(())
}

/// MOVNTSS/MOVNTSD。reg ソースの下位 32/64 ビットをメモリへ
/// ノンテンポラルに書き出す（NT ヒントはメモリモデルに現れない
/// ので通常ストアと同じ）。
pub fn movnts<B: Backend>(
    b: &mut B,
    dword: bool,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let src = reg_x(d);
    let v: B::V<W128> = b.get(sem::xmm_ref(src));
    match ea {
        Rm::Mem { a, .. } => {
            let a = *a;
            if dword {
                let v32: B::V<W32> = b.trunc::<W128, W32>(v);
                b.store::<W32>(a, v32, sem::DATA_WRITE)
            } else {
                let v64: B::V<W64> = b.trunc::<W128, W64>(v);
                b.store::<W64>(a, v64, sem::DATA_WRITE)
            }
        }
        Rm::Reg(_) => Ok(()),
    }
}

/// CLZERO。rAX が指す 64 バイト領域を 0 で埋める。アドレスは
/// アドレスサイズに折り返す。
pub fn clzero<B: Backend>(b: &mut B, d: &MapDec) -> Flow<B> {
    let base = sem::read64(b, Gpr(0));
    let m = b.konst::<W64>(asize_mask(d.asize));
    let a = b.and::<W64>(base, m);
    let z = b.konst::<W64>(0);
    for i in 0..8u64 {
        let off = b.konst::<W64>(i * 8);
        let ad = b.add::<W64>(a, off);
        b.store::<W64>(ad, z, sem::DATA_WRITE)?;
    }
    Ok(())
}

/// RDPRU。ECX が選ぶ AMD プロセッサレジスタ（0=MPERF, 1=APERF）
/// を EDX:EAX に返す。時間モデル未実装のため RDTSC と同じく
/// 決定論的な 0（選択子が無効でも #GP はモデル化せず 0）。
pub fn rdpru<B: Backend>(b: &mut B) -> Flow<B> {
    let z = b.konst::<W32>(0);
    decode::gwr32(b, Gpr(0), z);
    decode::gwr32(b, Gpr(2), z);
    Ok(())
}

// ===== 0F 38 / 0F 3A サブマップ（SSSE3/SSE4.1/MOVBE）=====

/// PSHUFB の 128 ビット処理（値関数）。制御バイトの MSB が立つ要素は
/// 0、下位 4 ビットが選ぶバイト。a がデータ、c が制御。
fn pshufb_val<B: Backend>(b: &mut B, a: B::V<W128>, c: B::V<W128>) -> B::V<W128> {
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
    acc
}

/// PSHUFB。
pub fn pshufb<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let c = rx(b, ea, 128)?;
    let acc = pshufb_val(b, a, c);
    b.set(sem::xmm_ref(dst), acc);
    Ok(())
}

/// PHADDW/PHADDD/PHADDSW/PHSUBW/PHSUBD/PHSUBSW。
/// 隣接ペアを加減算し、dst 側ペアを下位 64・src 側ペアを上位 64 に詰める。
fn phaddsub_val<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    sub: bool,
    sat: bool,
    a: B::V<W128>,
    c: B::V<W128>,
) -> B::V<W128> {
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
    acc
}

/// レガシーの PHADD/PHSUB。dst レジスタが第 1 ソース。
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
    let acc = phaddsub_val::<B, W>(b, sub, sat, a, c);
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
fn pmaddubsw_val<B: Backend>(b: &mut B, a: B::V<W128>, c: B::V<W128>) -> B::V<W128> {
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
    acc
}

/// レガシーの PMADDUBSW。dst レジスタが第 1 ソース。
pub fn pmaddubsw<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let c = rx(b, ea, 128)?;
    let acc = pmaddubsw_val(b, a, c);
    b.set(sem::xmm_ref(dst), acc);
    Ok(())
}

/// PMULHRSW。`((a*c*2) + 0x8000) >> 16` を s16 飽和にする。
fn pmulhrsw_val<B: Backend>(b: &mut B, a: B::V<W128>, c: B::V<W128>) -> B::V<W128> {
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
    acc
}

/// レガシーの PMULHRSW。dst レジスタが第 1 ソース。
pub fn pmulhrsw<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let c = rx(b, ea, 128)?;
    let acc = pmulhrsw_val(b, a, c);
    b.set(sem::xmm_ref(dst), acc);
    Ok(())
}

/// PABSB/W/D。`|src[i]|`。
fn pabs_val<B: Backend, W: polyisa_sem::Width>(b: &mut B, s: B::V<W128>) -> B::V<W128> {
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
    acc
}

/// レガシーの PABS。2 オペランドの単項形。
pub fn pabs<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let s = rx(b, ea, 128)?;
    let acc = pabs_val::<B, W>(b, s);
    b.set(sem::xmm_ref(dst), acc);
    Ok(())
}

/// PTEST 系の状況旗書き込み。ZF = `t1` が 0、CF = `t2` が 0。
/// 他の状況旗はクリア。
fn ptest_flags<B: Backend>(b: &mut B, t1: B::V<W128>, t2: B::V<W128>) -> Flow<B> {
    let z = b.konst::<W128>(0);
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

/// PTEST。ZF = (a & c) == 0、CF = (c & !a) == 0。
pub fn ptest<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Flow<B> {
    let a: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    let c = rx(b, ea, 128)?;
    let t1 = b.and::<W128>(a, c);
    let na = b.not::<W128>(a);
    let t2 = b.and::<W128>(na, c);
    ptest_flags(b, t1, t2)
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

/// PMOVSX/PMOVZX の拡張。`s` の `base` から `from` ビット要素を
/// `to` ビットへ拡張する。
fn pmovx_val<B: Backend>(
    b: &mut B,
    from: u32,
    to: u32,
    signed: bool,
    s: B::V<W128>,
    base: u32,
) -> B::V<W128> {
    let n = 128 / to;
    let mut acc = b.konst::<W128>(0);
    for i in 0..n {
        let l = lane128(b, s, (base + i) * from, from);
        let e = ext_int(b, l, from, to, signed);
        acc = put_lane128(b, acc, e, i * to, to);
    }
    acc
}

/// PMOVSX/PMOVZX。
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
    let r = pmovx_val(b, from, to, signed, s, 0);
    b.set(sem::xmm_ref(reg_x(d)), r);
    Ok(())
}

/// PMULDQ の 128 ビットレーン内演算。偶数 i32 レーンの符号付き
/// 積を i64 で 2 本得る。
fn pmuldq_val<B: Backend>(b: &mut B, a: B::V<W128>, c: B::V<W128>) -> B::V<W128> {
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
    acc
}

/// PMULDQ。
pub fn pmuldq<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    pdst_val(b, d, ea, pmuldq_val)
}

/// VPMULDQ。
pub fn vpmuldq<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    vbin2(b, d, ea, pmuldq_val)
}

/// PACKSS*/PACKUS* の 128 ビット処理（値関数）。`W` 要素を半分の
/// 幅に飽和変換して詰める（a が下位、c が上位）。`unsig` なら出力は
/// 符号なし飽和（入力は符号付き読み）。
fn pack_val<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    unsig: bool,
    a: B::V<W128>,
    c: B::V<W128>,
) -> B::V<W128> {
    let mut acc = b.konst::<W128>(0);
    let n = 128 / W::BITS;
    let (lo, hi) = if unsig {
        (0u128, (1u128 << (W::BITS / 2)) - 1)
    } else {
        let h = W::BITS / 2;
        let mag = 1u128 << (h - 1);
        ((1u128 << W::BITS) - mag, mag - 1)
    };
    for (src_i, s) in [a, c].into_iter().enumerate() {
        for i in 0..n {
            let l = lane128(b, s, i * W::BITS, W::BITS);
            let v: B::V<W> = b.trunc::<W128, W>(l);
            let klo = b.konst::<W>(W::from_u128(lo));
            let khi = b.konst::<W>(W::from_u128(hi));
            let under = b.cmp::<W>(Cmp::LtS, v, klo);
            let over = b.cmp::<W>(Cmp::GtS, v, khi);
            let r = b.select::<W>(under, klo, v);
            let r = b.select::<W>(over, khi, r);
            let r128 = b.zext::<W, W128>(r);
            acc = put_lane128(
                b,
                acc,
                r128,
                (src_i as u32 * n + i) * (W::BITS / 2),
                W::BITS / 2,
            );
        }
    }
    acc
}

/// PACKSSWB/W・PACKUSWB/DW のレガシー xmm 形。
pub fn ppack<B: Backend, W: polyisa_sem::Width>(
    b: &mut B,
    unsig: bool,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    pdst_val(b, d, ea, |b, a, c| pack_val::<B, W>(b, unsig, a, c))
}

/// PACKUSDW（SSE4.1、0F38 2B）。
pub fn packusdw<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    ppack::<B, W32>(b, true, d, ea)
}

/// PALIGNR の 128 ビットレーン内演算。`(a:c)` の 256 ビット連結を
/// imm バイト右にずらし下位 128 ビットを取る。
fn palignr_val<B: Backend>(b: &mut B, imm: u8, a: B::V<W128>, c: B::V<W128>) -> B::V<W128> {
    let sh = u32::from(imm) * 8;
    if sh == 0 {
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
    }
}

/// PALIGNR。
pub fn palignr<B: Backend>(
    b: &mut B,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let c = rx(b, ea, 128)?;
    let v = palignr_val(b, imm, a, c);
    b.set(sem::xmm_ref(dst), v);
    Ok(())
}

/// VPALIGNR。VEX.256 でも連結は 128 ビットレーンごとに閉じる。
pub fn vpalignr<B: Backend>(
    b: &mut B,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    vbin2(b, d, ea, |b, a, c| palignr_val(b, imm, a, c))
}

/// VPBLENDD。imm のビットは ymm 全体の dword レーンに対応する
/// ため、上位 128 ビットでは imm[7:4] を使う。
pub fn vpblendd<B: Backend>(
    b: &mut B,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let s1: B::V<W128> = b.get(sem::xmm_ref(vvv_x(d)));
    let s2 = rx(b, ea, 128)?;
    let lo = blendp_val(b, 32, imm, s1, s2);
    b.set(sem::xmm_ref(dst), lo);
    let hi = if d.vex_l {
        let h1: B::V<W128> = b.get(sem::ymm_hi_ref(vvv_x(d)));
        let h2 = rx_hi(b, ea)?;
        blendp_val(b, 32, imm >> 4, h1, h2)
    } else {
        b.konst::<W128>(0)
    };
    b.set(sem::ymm_hi_ref(dst), hi);
    Ok(())
}

/// BLENDPS/BLENDPD/PBLENDW。imm の各ビットで `c` のレーンを選ぶ
/// （0 は `a` を維持）。`bits` は 16/32/64。
/// BLENDPS/BLENDPD/PBLENDW の選択マージ（imm の各ビットで a/c を選ぶ）。
fn blendp_val<B: Backend>(
    b: &mut B,
    bits: u32,
    imm: u8,
    a: B::V<W128>,
    c: B::V<W128>,
) -> B::V<W128> {
    let mut acc = b.konst::<W128>(0);
    for i in 0..(128 / bits) {
        let l = if imm >> i & 1 == 1 {
            lane128(b, c, i * bits, bits)
        } else {
            lane128(b, a, i * bits, bits)
        };
        acc = put_lane128(b, acc, l, i * bits, bits);
    }
    acc
}

/// BLENDPS/BLENDPD/PBLENDW。imm の各ビットで a/c を選ぶ。
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
    let r = blendp_val(b, bits, imm, a, c);
    b.set(sem::xmm_ref(dst), r);
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
    let r = insertps_val(b, imm, a, s);
    b.set(sem::xmm_ref(reg_x(d)), r);
    Ok(())
}

/// INSERTPS のマージ。`a` の imm[5:4] レーンを `s` で置き換え、
/// imm[3:0] のレーンを 0 にする。
fn insertps_val<B: Backend>(b: &mut B, imm: u8, a: B::V<W128>, s: B::V<W128>) -> B::V<W128> {
    let mut v = put_lane128(b, a, s, u32::from(imm >> 4 & 3) * 32, 32);
    for i in 0..4u32 {
        if imm >> i & 1 == 1 {
            let z = b.konst::<W128>(0);
            v = put_lane128(b, v, z, i * 32, 32);
        }
    }
    v
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
        Rm::Mem { a, wseg } => {
            let a = *a;
            match bits {
                32 => {
                    let v: B::V<W32> = decode::mem_load::<B, W32>(b, a, *wseg)?;
                    sem::push_f32(b, v)
                }
                80 => {
                    let sig: B::V<W64> = decode::mem_load::<B, W64>(b, a, *wseg)?;
                    let a8 = b.konst::<W64>(8);
                    let a2 = b.add::<W64>(a, a8);
                    let exp: B::V<W16> = decode::mem_load::<B, W16>(b, a2, *wseg)?;
                    sem::push_ext(b, sig, exp)
                }
                _ => {
                    let v: B::V<W64> = decode::mem_load::<B, W64>(b, a, *wseg)?;
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
    let (sig, exp, fault) = sem::read_st_source(b, top);
    let commit0 = sem::x87_commit_after_fault(b, fault);
    // m32/m64 への store は整数 bit 演算で target precision へ丸める。
    // unmasked overflow/underflow では memory と TOP を変えない。m80 は
    // 変換を伴わないので numeric fault 応答を持たない。
    let zero64 = b.konst::<W64>(0);
    let no_numeric_block = sem::bool_false(b);
    let (converted, numeric_block) = if bits == 32 {
        sem::x87_ext_to_ieee_bits(b, sig, exp, 24, 23, 127, 0xff)
    } else if bits == 64 {
        sem::x87_ext_to_ieee_bits(b, sig, exp, 53, 52, 1023, 0x7ff)
    } else {
        (zero64, no_numeric_block)
    };
    let not_numeric_block = sem::bit_not(b, numeric_block);
    let commit = sem::bit_and(b, commit0, not_numeric_block);
    if let Rm::Mem { a, wseg } = ea {
        let a = *a;
        let wseg = *wseg;
        b.if_then(commit, |b| {
            match bits {
                32 => {
                    let store32 = b.trunc::<W64, W32>(converted);
                    decode::mem_store::<B, W32>(b, a, wseg, store32)?;
                }
                80 => {
                    decode::mem_store::<B, W64>(b, a, wseg, sig)?;
                    let a8 = b.konst::<W64>(8);
                    let a2 = b.add::<W64>(a, a8);
                    decode::mem_store::<B, W16>(b, a2, wseg, exp)?;
                }
                _ => {
                    decode::mem_store::<B, W64>(b, a, wseg, converted)?;
                }
            }
            if pop {
                sem::pop_st(b, top)?;
            }
            Ok(())
        })?;
    }
    Ok(())
}

/// FST/FSTP ST(i)（DD D0/D8+i）。
pub fn fst_sti<B: Backend>(b: &mut B, i: u8, pop: bool) -> Flow<B> {
    let top = b.get(sem::top_ref());
    let (sig, exp, fault) = sem::read_st_source(b, top);
    let commit = sem::x87_commit_after_fault(b, fault);
    let dst = st_slot(b, i);
    b.if_then(commit, |b| {
        sem::write_st(b, dst, sig, exp);
        if pop {
            sem::pop_st(b, top)?;
        }
        Ok(())
    })
}

/// FILD m16/m32/m64。
pub fn fild_m<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>, bits: u32) -> Result<(), B::Exit> {
    if let Rm::Mem { a, wseg } = ea {
        let a = *a;
        match bits {
            16 => {
                let v: B::V<W16> = decode::mem_load::<B, W16>(b, a, *wseg)?;
                let v32 = b.sext::<W16, W32>(v);
                sem::push_i32(b, v32)
            }
            32 => {
                let v: B::V<W32> = decode::mem_load::<B, W32>(b, a, *wseg)?;
                sem::push_i32(b, v)
            }
            _ => {
                let v: B::V<W64> = decode::mem_load::<B, W64>(b, a, *wseg)?;
                sem::push_i64(b, v)
            }
        }
    } else {
        Ok(())
    }
}

/// FIST 系の整数化。丸めで値が変われば PE、NaN/無限大や
/// 出力幅に入らない値なら IE を立てる。denormal 入力では DE も立てる。
fn fist_apply_exceptions<B: Backend>(
    b: &mut B,
    sig: B::V<W64>,
    exp: B::V<W16>,
    bits: u32,
    v: B::V<W64>,
    inexact: B::B,
    bad64: B::B,
) -> (B::V<W64>, B::B) {
    use polyisa_sem::{Cmp, W16, W64};
    let z64 = b.konst::<W64>(0);
    let one64 = b.konst::<W64>(1);
    let false0 = b.cmp::<W64>(Cmp::Eq, z64, one64);
    let mut width_bad = false0;
    if bits == 16 {
        let max = b.konst::<W64>(0x7fff);
        let min = b.konst::<W64>(0xffff_ffff_ffff_8000);
        let pos = b.cmp::<W64>(Cmp::GtS, v, max);
        let neg = b.cmp::<W64>(Cmp::LtS, v, min);
        width_bad = sem::bit_or(b, pos, neg);
    } else if bits == 32 {
        let max = b.konst::<W64>(0x7fff_ffff);
        let min = b.konst::<W64>(0xffff_ffff_8000_0000);
        let pos = b.cmp::<W64>(Cmp::GtS, v, max);
        let neg = b.cmp::<W64>(Cmp::LtS, v, min);
        width_bad = sem::bit_or(b, pos, neg);
    }
    let invalid = sem::bit_or(b, bad64, width_bad);
    sem::x87_exception_flag(b, invalid, 1);
    sem::x87_exception_flag(b, inexact, 1 << 5);

    let exp64 = b.zext::<W16, W64>(exp);
    let mask15 = b.konst::<W64>(0x7fff);
    let ea = b.and::<W64>(exp64, mask15);
    let exp_zero = b.cmp::<W64>(Cmp::Eq, ea, z64);
    let sig_nz = b.cmp::<W64>(Cmp::Ne, sig, z64);
    let denormal = sem::bit_and(b, exp_zero, sig_nz);
    sem::x87_exception_flag(b, denormal, 1 << 1);
    let indef = match bits {
        16 => b.konst::<W64>(0x8000),
        32 => b.konst::<W64>(0x8000_0000),
        _ => b.konst::<W64>(1u64 << 63),
    };
    (b.select::<W64>(invalid, indef, v), invalid)
}

fn fist_convert<B: Backend>(
    b: &mut B,
    sig: B::V<W64>,
    exp: B::V<W16>,
    bits: u32,
) -> (B::V<W64>, B::B) {
    let (v, inexact, bad64) = sem::f80_to_i64_occ(b, sig, exp);
    fist_apply_exceptions(b, sig, exp, bits, v, inexact, bad64)
}

/// FIST 系の整数値を出力幅でメモリへ書く。
fn fist_store_at<B: Backend>(
    b: &mut B,
    a: B::V<W64>,
    wseg: Option<(u64, B::V<W64>)>,
    bits: u32,
    v: B::V<W64>,
) -> Result<(), B::Exit> {
    match bits {
        16 => {
            let v16: B::V<W16> = b.trunc::<W64, W16>(v);
            decode::mem_store::<B, W16>(b, a, wseg, v16)
        }
        32 => {
            let v32: B::V<W32> = b.trunc::<W64, W32>(v);
            decode::mem_store::<B, W32>(b, a, wseg, v32)
        }
        _ => decode::mem_store::<B, W64>(b, a, wseg, v),
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
    let (sig, exp, fault) = sem::read_st_source(b, top);
    let commit = sem::x87_commit_after_fault(b, fault);
    if let Rm::Mem { a, wseg } = ea {
        let a = *a;
        let wseg = *wseg;
        b.if_then(commit, |b| {
            b.if_then_else(
                fault,
                |b| {
                    let indef = match bits {
                        16 => b.konst::<W64>(0x8000),
                        32 => b.konst::<W64>(0x8000_0000),
                        _ => b.konst::<W64>(1u64 << 63),
                    };
                    fist_store_at(b, a, wseg, bits, indef)?;
                    if pop {
                        sem::pop_st(b, top)?;
                    }
                    Ok(())
                },
                |b| {
                    let (v, invalid) = fist_convert(b, sig, exp, bits);
                    let ie_masked = sem::x87_ie_masked(b);
                    let no_invalid = sem::bit_not(b, invalid);
                    let write_ok = sem::bit_or(b, no_invalid, ie_masked);
                    b.if_then(write_ok, |b| {
                        fist_store_at(b, a, wseg, bits, v)?;
                        if pop {
                            sem::pop_st(b, top)?;
                        }
                        Ok(())
                    })
                },
            )
        })?;
    }
    Ok(())
}

/// FISTTP 用の切り捨て変換。FISTTP は FCW の RC に関係なく
/// 常に truncation なので、丸め制御だけを一時的に切り捨てへ
/// 合わせて共通変換を使う。
fn f80_to_i64_trunc_occ<B: Backend>(
    b: &mut B,
    sig: B::V<W64>,
    exp: B::V<W16>,
) -> (B::V<W64>, B::B, B::B) {
    let old = b.get(sem::fcw_ref());
    let keep = b.konst::<W16>(!0x0c00u16);
    let base = b.and::<W16>(old, keep);
    let trunc = b.konst::<W16>(0x0c00);
    let cw = b.or::<W16>(base, trunc);
    b.set(sem::fcw_ref(), cw);
    let r = sem::f80_to_i64_occ(b, sig, exp);
    b.set(sem::fcw_ref(), old);
    r
}

/// FISTTP m16/m32/m64。常に切り捨てで整数化し、pop する。
pub fn fisttp_m<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>, bits: u32) -> Result<(), B::Exit> {
    let top = b.get(sem::top_ref());
    let (sig, exp, fault) = sem::read_st_source(b, top);
    let commit = sem::x87_commit_after_fault(b, fault);
    if let Rm::Mem { a, wseg } = ea {
        let a = *a;
        let wseg = *wseg;
        b.if_then(commit, |b| {
            b.if_then_else(
                fault,
                |b| {
                    let indef = match bits {
                        16 => b.konst::<W64>(0x8000),
                        32 => b.konst::<W64>(0x8000_0000),
                        _ => b.konst::<W64>(1u64 << 63),
                    };
                    fist_store_at(b, a, wseg, bits, indef)?;
                    sem::pop_st(b, top)
                },
                |b| {
                    let (v, inexact, bad64) = f80_to_i64_trunc_occ(b, sig, exp);
                    let (v, invalid) = fist_apply_exceptions(b, sig, exp, bits, v, inexact, bad64);
                    let ie_masked = sem::x87_ie_masked(b);
                    let no_invalid = sem::bit_not(b, invalid);
                    let write_ok = sem::bit_or(b, no_invalid, ie_masked);
                    b.if_then(write_ok, |b| {
                        fist_store_at(b, a, wseg, bits, v)?;
                        sem::pop_st(b, top)
                    })
                },
            )
        })?;
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
) -> (B::V<W64>, B::V<W16>, B::B) {
    let sign_mask = b.konst::<W16>(0x8000);
    match op {
        FAr::Add => sem::add_ext(b, s0, e0, s1, e1),
        FAr::Sub => {
            let ne = b.xor::<W16>(e1, sign_mask);
            sem::add_ext_nan(b, s0, e0, s1, ne, e0, e1)
        }
        FAr::SubR => {
            let ne = b.xor::<W16>(e0, sign_mask);
            sem::add_ext_nan(b, s1, e1, s0, ne, e1, e0)
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
    if let Rm::Mem { a, wseg } = ea {
        let a = *a;
        let wseg = *wseg;
        let top = b.get(sem::top_ref());
        let (s0, e0, fault) = sem::read_st_source(b, top);
        let commit = sem::x87_commit_after_fault(b, fault);
        b.if_then(commit, |b| {
            let indef_sig = b.konst::<W64>(0xC000_0000_0000_0000);
            let indef_exp = b.konst::<W16>(0xffff);
            b.if_then_else(
                fault,
                |b| {
                    sem::write_st(b, top, indef_sig, indef_exp);
                    Ok(())
                },
                |b| {
                    let (sm, em) = if fbits == 32 {
                        let v: B::V<W32> = decode::mem_load::<B, W32>(b, a, wseg)?;
                        let denormal = sem::f32_denormal(b, v);
                        sem::x87_exception_flag(b, denormal, 1 << 1);
                        sem::f32_to_ext(b, v)
                    } else {
                        let v: B::V<W64> = decode::mem_load::<B, W64>(b, a, wseg)?;
                        let denormal = sem::f64_denormal(b, v);
                        sem::x87_exception_flag(b, denormal, 1 << 1);
                        sem::f64_to_ext(b, v)
                    };
                    let (sr, er, invalid) = ext_arith(b, op, s0, e0, sm, em);
                    let commit = sem::x87_arith_result_commit(b, invalid);
                    b.if_then(commit, |b| {
                        sem::write_st(b, top, sr, er);
                        Ok(())
                    })
                },
            )
        })?;
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
    if let Rm::Mem { a, wseg } = ea {
        let a = *a;
        let wseg = *wseg;
        let top = b.get(sem::top_ref());
        let (s0, e0, fault) = sem::read_st_source(b, top);
        let commit = sem::x87_commit_after_fault(b, fault);
        b.if_then(commit, |b| {
            let indef_sig = b.konst::<W64>(0xC000_0000_0000_0000);
            let indef_exp = b.konst::<W16>(0xffff);
            b.if_then_else(
                fault,
                |b| {
                    sem::write_st(b, top, indef_sig, indef_exp);
                    Ok(())
                },
                |b| {
                    let v64 = if bits == 16 {
                        let v: B::V<W16> = decode::mem_load::<B, W16>(b, a, wseg)?;
                        b.sext::<W16, W64>(v)
                    } else {
                        let v: B::V<W32> = decode::mem_load::<B, W32>(b, a, wseg)?;
                        b.sext::<W32, W64>(v)
                    };
                    let (sm, em) = sem::i64_to_ext(b, v64);
                    let (sr, er, invalid) = ext_arith(b, op, s0, e0, sm, em);
                    let commit = sem::x87_arith_result_commit(b, invalid);
                    b.if_then(commit, |b| {
                        sem::write_st(b, top, sr, er);
                        Ok(())
                    })
                },
            )
        })?;
    }
    Ok(())
}

/// x87 の ST(i) 二項演算。`rev` は ST(i) 側を結果の書き先にする
/// DC 形（st(i) = st(i) op st(0) の順、sub/div は反転済みの FAr を渡す）。
/// `pop` で ST(0) を捨てる（DE 形）。
pub fn farith_st<B: Backend>(b: &mut B, op: FAr, i: u8, rev: bool, pop: bool) -> Flow<B> {
    let top = b.get(sem::top_ref());
    let (s0, e0, fault0) = sem::read_st_source(b, top);
    let slot = st_slot(b, i);
    let (s1, e1, fault1) = sem::read_st_source(b, slot);
    let fault = sem::bit_or(b, fault0, fault1);
    let commit = sem::x87_commit_after_fault(b, fault);
    let dst = if rev { slot } else { top };
    b.if_then(commit, |b| {
        let indef_sig = b.konst::<W64>(0xC000_0000_0000_0000);
        let indef_exp = b.konst::<W16>(0xffff);
        b.if_then_else(
            fault,
            |b| {
                sem::write_st(b, dst, indef_sig, indef_exp);
                if pop {
                    sem::pop_st(b, top)?;
                }
                Ok(())
            },
            |b| {
                let (sr, er, invalid) = if rev {
                    ext_arith(b, op, s1, e1, s0, e0)
                } else {
                    ext_arith(b, op, s0, e0, s1, e1)
                };
                let commit = sem::x87_arith_result_commit(b, invalid);
                b.if_then(commit, |b| {
                    sem::write_st(b, dst, sr, er);
                    if pop {
                        sem::pop_st(b, top)?;
                    }
                    Ok(())
                })
            },
        )
    })
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
    let (_s0, _e0, fault0) = sem::read_st_source(b, top);
    let slot = st_slot(b, i);
    let (s1, e1, fault1) = sem::read_st_source(b, slot);
    let fault = sem::bit_or(b, fault0, fault1);
    let commit = sem::x87_commit_after_fault(b, fault);
    b.if_then(commit, |b| {
        let indef_sig = b.konst::<W64>(0xC000_0000_0000_0000);
        let indef_exp = b.konst::<W16>(0xffff);
        b.if_then_else(
            fault,
            |b| {
                sem::write_st(b, top, indef_sig, indef_exp);
                Ok(())
            },
            |b| {
                b.if_then(cond, |b| {
                    sem::write_st(b, top, s1, e1);
                    Ok(())
                })
            },
        )
    })
}

/// FCHS（符号反転）/FABS（符号クリア）。
pub fn fchs_abs<B: Backend>(b: &mut B, abs: bool) -> Flow<B> {
    let top = b.get(sem::top_ref());
    let (sig, exp, fault) = sem::read_st_source(b, top);
    let commit = sem::x87_commit_after_fault(b, fault);
    b.if_then(commit, |b| {
        let new_exp = if abs {
            let m = b.konst::<W16>(0x7fff);
            b.and::<W16>(exp, m)
        } else {
            let m = b.konst::<W16>(0x8000);
            b.xor::<W16>(exp, m)
        };
        let indef_sig = b.konst::<W64>(0xC000_0000_0000_0000);
        let indef_exp = b.konst::<W16>(0xffff);
        let sig_out = b.select::<W64>(fault, indef_sig, sig);
        let exp_out = b.select::<W16>(fault, indef_exp, new_exp);
        sem::write_st(b, top, sig_out, exp_out);
        Ok(())
    })
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

/// FSQRT。有限正数は 128 ビット整数平方根から 64 ビット仮数へ丸める。
/// denormal 入力は正規化して扱い、NaN・無限大・符号付き零と負数の
/// invalid operation を x87 の規則にそろえる。
pub fn fsqrt_st<B: Backend>(b: &mut B) -> Flow<B> {
    let top = b.get(sem::top_ref());
    let (sig, exp, fault) = sem::read_st_source(b, top);
    let commit = sem::x87_commit_after_fault(b, fault);
    b.if_then(commit, |b| {
        let indef_sig = b.konst::<W64>(0xC000_0000_0000_0000);
        let indef_exp = b.konst::<W16>(0xffff);
        b.if_then_else(
            fault,
            |b| {
                sem::write_st(b, top, indef_sig, indef_exp);
                Ok(())
            },
            |b| {
                let zero = b.konst::<W64>(0);
                let one = b.konst::<W64>(1);
                let mask15 = b.konst::<W64>(0x7fff);
                let special = mask15;
                let s15 = b.konst::<W64>(15);
                let bias = b.konst::<W64>(16383);
                let int_bit = b.konst::<W64>(1u64 << 63);
                let exp64 = b.zext::<W16, W64>(exp);
                let ea = b.and::<W64>(exp64, mask15);
                let sign = b.shr_l::<W64>(exp64, s15);
                let neg = b.cmp::<W64>(Cmp::Eq, sign, one);
                let exp_zero = b.cmp::<W64>(Cmp::Eq, ea, zero);
                let sig_zero = b.cmp::<W64>(Cmp::Eq, sig, zero);
                let sig_nz = b.cmp::<W64>(Cmp::Ne, sig, zero);
                let is_zero = sem::bit_and(b, exp_zero, sig_zero);
                let denormal = sem::bit_and(b, exp_zero, sig_nz);
                let sp = b.cmp::<W64>(Cmp::Eq, ea, special);
                let frac_mask = b.konst::<W64>((1u64 << 63) - 1);
                let frac = b.and::<W64>(sig, frac_mask);
                let frac_nz = b.cmp::<W64>(Cmp::Ne, frac, zero);
                let frac_z = sem::bit_not(b, frac_nz);
                let is_nan = sem::bit_and(b, sp, frac_nz);
                let is_inf = sem::bit_and(b, sp, frac_z);
                let qbit = b.konst::<W64>(1u64 << 62);
                let qbits = b.and::<W64>(sig, qbit);
                let qbit_set = b.cmp::<W64>(Cmp::Ne, qbits, zero);
                let qbit_clear = sem::bit_not(b, qbit_set);
                let snan = sem::bit_and(b, is_nan, qbit_clear);
                let nonzero = sem::bit_not(b, is_zero);
                let not_nan = sem::bit_not(b, is_nan);
                let neg_nonzero = sem::bit_and(b, neg, nonzero);
                let invalid_neg = sem::bit_and(b, neg_nonzero, not_nan);
                let unsupported = sem::x87_unsupported_format(b, sig, exp);
                let invalid0 = sem::bit_or(b, invalid_neg, unsupported);
                let invalid = sem::bit_or(b, invalid0, snan);
                sem::x87_exception_flag(b, invalid, 1);
                let higher_den0 = sem::bit_or(b, is_nan, invalid);
                let higher_den = sem::bit_not(b, higher_den0);
                let denormal_report = sem::bit_and(b, denormal, higher_den);
                sem::x87_exception_flag(b, denormal_report, 1 << 1);

                // sqrt(sig * 2^u) を整数平方根で求める。u が偶数なら
                // sqrt(sig << 63)、奇数なら sqrt(sig << 64) が目的の
                // 64 ビット仮数になる。指数は floor(u/2)+bias。
                let (sig_norm, ea_eff) = sem::x87_normalize_denormal_operand(b, sig, ea);
                let unb = b.sub::<W64>(ea_eff, bias);
                let odd_bit = b.and::<W64>(unb, one);
                let odd = b.cmp::<W64>(Cmp::Eq, odd_bit, one);
                let k63 = b.konst::<W64>(63);
                let k64 = b.konst::<W64>(64);
                let nshift = b.select::<W64>(odd, k64, k63);
                let sig128 = b.zext::<W64, W128>(sig_norm);
                let nshift128 = b.zext::<W64, W128>(nshift);
                let n = b.shl::<W128>(sig128, nshift128);
                let root = sem::isqrt128_floor(b, n);
                let root128 = b.zext::<W64, W128>(root);
                let root_sq = b.mul::<W128>(root128, root128);
                let low_diff = b.sub::<W128>(n, root_sq);
                let z128 = b.konst::<W128>(0);
                let inexact128 = b.cmp::<W128>(Cmp::Ne, low_diff, z128);
                let root_plus = b.add::<W64>(root, one);
                let root_plus128 = b.zext::<W64, W128>(root_plus);
                let plus_sq = b.mul::<W128>(root_plus128, root_plus128);
                let high_diff = b.sub::<W128>(plus_sq, n);
                let high_closer = b.cmp::<W128>(Cmp::LtU, high_diff, low_diff);
                let tie = b.cmp::<W128>(Cmp::Eq, high_diff, low_diff);
                let lsb = b.and::<W64>(root, one);
                let lsb_set = b.cmp::<W64>(Cmp::Eq, lsb, one);
                let tie_up = sem::bit_and(b, tie, lsb_set);
                let nearest_up0 = sem::bit_or(b, high_closer, tie_up);
                let nearest_up_pre = sem::bit_and(b, nearest_up0, inexact128);

                let fcw = b.get(sem::fcw_ref());
                let fcw64 = b.zext::<W16, W64>(fcw);
                let ten = b.konst::<W64>(10);
                let three = b.konst::<W64>(3);
                let rc0 = b.shr_l::<W64>(fcw64, ten);
                let rc = b.and::<W64>(rc0, three);
                let two = b.konst::<W64>(2);
                let nearest_mode = b.cmp::<W64>(Cmp::Eq, rc, zero);
                let nearest_up = sem::bit_and(b, nearest_up_pre, nearest_mode);
                let ceil = b.cmp::<W64>(Cmp::Eq, rc, two);
                let ceil_up = sem::bit_and(b, ceil, inexact128);
                let do_up = sem::bit_or(b, nearest_up, ceil_up);
                let numeric0 = sem::bit_not(b, sp);
                let numeric1 = sem::bit_not(b, invalid);
                let numeric = sem::bit_and(b, numeric0, numeric1);
                let inexact_numeric = sem::bit_and(b, inexact128, numeric);
                sem::x87_exception_flag(b, inexact_numeric, 1 << 5);

                let root_inc = b.select::<W64>(do_up, root_plus, root);
                let root_carry = b.cmp::<W64>(Cmp::Eq, root_inc, zero);
                let root_fin = b.select::<W64>(root_carry, int_bit, root_inc);
                let half = b.shr_a::<W64>(unb, one);
                let out_e0 = b.add::<W64>(half, bias);
                let carry_v = b.select::<W64>(root_carry, one, zero);
                let out_e = b.add::<W64>(out_e0, carry_v);
                // 特殊値と zero を優先し、有限正数だけ整数平方根の結果を使う。
                let inf_sig = b.select::<W64>(is_inf, int_bit, root_fin);
                let inf_exp = b.select::<W64>(is_inf, special, out_e);
                let zero_sig = b.select::<W64>(is_zero, sig, inf_sig);
                let zero_exp64 = b.select::<W64>(is_zero, exp64, inf_exp);
                let bad_nan0 = sem::bit_or(b, is_nan, invalid_neg);
                let bad_nan = sem::bit_or(b, bad_nan0, unsupported);
                let nan_prop_sig = b.or::<W64>(sig, qbit);
                let nan_or_indef = b.select::<W64>(is_nan, nan_prop_sig, indef_sig);
                let final_sig = b.select::<W64>(bad_nan, nan_or_indef, zero_sig);
                let indef_exp64 = b.konst::<W64>(0xffff);
                let nan_exp64 = b.select::<W64>(is_nan, exp64, indef_exp64);
                let exp_word64 = b.select::<W64>(bad_nan, nan_exp64, zero_exp64);
                let exp_word = b.trunc::<W64, W16>(exp_word64);
                let (sr, er) = sem::x87_apply_precision(b, final_sig, exp_word);
                let invalid_um = sem::x87_unmasked_exception(b, invalid, 1);
                let denormal_um = sem::x87_unmasked_exception(b, denormal_report, 1 << 1);
                let suppress = sem::bit_or(b, invalid_um, denormal_um);
                let commit_result = sem::x87_arith_result_commit(b, suppress);
                b.if_then(commit_result, |b| {
                    sem::write_st(b, top, sr, er);
                    Ok(())
                })
            },
        )
    })
}

/// FRNDINT。80 ビット整数変換を使い FCW の RC に従う。
/// |x| >= 2^63・無限大・NaN は整数化しても値が変わらないので入力を保つ。
pub fn frndint_st<B: Backend>(b: &mut B) -> Flow<B> {
    let top = b.get(sem::top_ref());
    let (sig, exp, fault) = sem::read_st_source(b, top);
    let commit = sem::x87_commit_after_fault(b, fault);
    b.if_then(commit, |b| {
        let indef_sig = b.konst::<W64>(0xC000_0000_0000_0000);
        let indef_exp = b.konst::<W16>(0xffff);
        b.if_then_else(
            fault,
            |b| {
                sem::write_st(b, top, indef_sig, indef_exp);
                Ok(())
            },
            |b| {
                let (iv, inexact, _bad) = sem::f80_to_i64_occ(b, sig, exp);
                sem::x87_exception_flag(b, inexact, 1 << 5);
                let (isig, mut iexp) = sem::i64_to_ext(b, iv);
                // 入力が負で結果整数が 0 のときは -0 を保つ。
                let z64 = b.konst::<W64>(0);
                let zero_i = b.cmp::<W64>(Cmp::Eq, iv, z64);
                let e64 = b.zext::<W16, W64>(exp);
                let s15 = b.konst::<W64>(15);
                let sign = b.shr_l::<W64>(e64, s15);
                let one64 = b.konst::<W64>(1);
                let neg = b.cmp::<W64>(Cmp::Eq, sign, one64);
                let neg_zero = sem::bit_and(b, zero_i, neg);
                let signbit = b.konst::<W16>(0x8000);
                let iexp_signed = b.or::<W16>(iexp, signbit);
                iexp = b.select::<W16>(neg_zero, iexp_signed, iexp);
                // 指数が 63 以上なら整数化で値は変わらない。NaN/Inf の
                // 0x7fff もこの条件に含まれる。
                let exp64 = b.zext::<W16, W64>(exp);
                let mask15 = b.konst::<W64>(0x7fff);
                let ea = b.and::<W64>(exp64, mask15);
                let lim = b.konst::<W64>(16383 + 63);
                let small = b.cmp::<W64>(Cmp::LtU, ea, lim);
                let sr0 = b.select::<W64>(small, isig, sig);
                let er0 = b.select::<W16>(small, iexp, exp);
                let zero64 = b.konst::<W64>(0);
                let exp_is_zero = b.cmp::<W64>(Cmp::Eq, ea, zero64);
                let sig_nz = b.cmp::<W64>(Cmp::Ne, sig, zero64);
                let denormal = sem::bit_and(b, exp_is_zero, sig_nz);
                sem::x87_exception_flag(b, denormal, 1 << 1);
                let special = b.konst::<W64>(0x7fff);
                let is_special = b.cmp::<W64>(Cmp::Eq, ea, special);
                let frac_mask = b.konst::<W64>((1u64 << 63) - 1);
                let frac = b.and::<W64>(sig, frac_mask);
                let frac_nz = b.cmp::<W64>(Cmp::Ne, frac, zero64);
                let int_bit64 = b.konst::<W64>(1u64 << 63);
                let ib = b.and::<W64>(sig, int_bit64);
                let ib_set = b.cmp::<W64>(Cmp::Ne, ib, zero64);
                let nan0 = sem::bit_and(b, is_special, frac_nz);
                let is_nan = sem::bit_and(b, nan0, ib_set);
                let qbit = b.konst::<W64>(1u64 << 62);
                let qbits = b.and::<W64>(sig, qbit);
                let qbit_set = b.cmp::<W64>(Cmp::Ne, qbits, zero64);
                let qbit_clear = sem::bit_not(b, qbit_set);
                let snan = sem::bit_and(b, is_nan, qbit_clear);
                let unsupported = sem::x87_unsupported_format(b, sig, exp);
                let invalid = sem::bit_or(b, unsupported, snan);
                sem::x87_exception_flag(b, invalid, 1);
                let nan_sig = b.or::<W64>(sig, qbit);
                let sr_nan = b.select::<W64>(is_nan, nan_sig, sr0);
                let er_nan = b.select::<W16>(is_nan, exp, er0);
                let sr = b.select::<W64>(unsupported, indef_sig, sr_nan);
                let er = b.select::<W16>(unsupported, indef_exp, er_nan);
                let invalid_um = sem::x87_unmasked_exception(b, invalid, 1);
                let commit_result = sem::x87_arith_result_commit(b, invalid_um);
                b.if_then(commit_result, |b| {
                    sem::write_st(b, top, sr, er);
                    Ok(())
                })
            },
        )
    })
}

/// FFREE。データビットは残し、タグだけ empty にする。
pub fn ffree<B: Backend>(b: &mut B, i: u8) -> Flow<B> {
    let slot = st_slot(b, i);
    let empty = b.konst::<W16>(3);
    sem::x87_write_tag(b, slot, empty);
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

/// FCLEX/FNCLEX。例外フラグ・SF・ES・B をクリアする。
/// 条件コードと TOP は保持する。
pub fn fclex<B: Backend>(b: &mut B) -> Flow<B> {
    let old = b.get(sem::fsw_ref());
    let keep = b.konst::<W16>(!0x80FFu16);
    let nv = b.and::<W16>(old, keep);
    b.set(sem::fsw_ref(), nv);
    Ok(())
}

/// FINIT。FCW=0x037f、TOP=0、全タグを empty にする。
pub fn finit<B: Backend>(b: &mut B) -> Flow<B> {
    let fcw = b.konst::<W16>(0x037f);
    b.set(sem::fcw_ref(), fcw);
    let z16 = b.konst::<W16>(0);
    b.set(sem::top_ref(), z16);
    b.set(sem::fsw_ref(), z16);
    let empty_tags = b.konst::<W16>(0xffff);
    b.set(sem::ftw_ref(), empty_tags);
    let z64 = b.konst::<W64>(0);
    b.set(sem::fip_ref(), z64);
    b.set(sem::fdp_ref(), z64);
    b.set(sem::fcs_ref(), z16);
    b.set(sem::fds_ref(), z16);
    b.set(sem::fop_ref(), z16);
    Ok(())
}

/// FLDCW m16。
pub fn fldcw_m<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    if let Rm::Mem { a, wseg } = ea {
        let v: B::V<W16> = decode::mem_load::<B, W16>(b, *a, *wseg)?;
        b.set(sem::fcw_ref(), v);
    }
    Ok(())
}

/// FNSTCW m16。
pub fn fnstcw_m<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    if let Rm::Mem { a, wseg } = ea {
        let v: B::V<W16> = b.get(sem::fcw_ref());
        decode::mem_store::<B, W16>(b, *a, *wseg, v)?;
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
/// 80386 実モードの o32 形では SP をオペランド幅（4）で引き、
/// word だけを新しい SP に書く（SST 80386 実測）。
pub fn push_sr<B: Backend>(b: &mut B, s: u8, sw: u8, sa: u8, sseg: u64) -> Flow<B> {
    let v: B::V<W16> = b.get(sem::sreg_ref(s));
    if sa == 16 && b.param::<crate::StackWrapParam>() == crate::STACK_WRAP_WRAP {
        let sp = Gpr(4);
        let delta = u64::from(sw / 8);
        let cur: B::V<W32> = b.get(sp.state());
        let m16 = b.konst::<W32>(0xFFFF);
        let k = b.konst::<W32>(delta as u32);
        let np32 = b.sub::<W32>(cur, k);
        let lo = b.and::<W32>(np32, m16);
        let nm = b.konst::<W32>(0xFFFF_0000);
        let hi = b.and::<W32>(cur, nm);
        let np = b.or::<W32>(hi, lo);
        let off = b.zext::<W32, W64>(lo);
        let sg = b.konst::<W64>(sseg);
        let a = b.add::<W64>(off, sg);
        let ws = Some((sseg | decode::WSEG_SS, off));
        decode::mem_store::<B, W16>(b, a, ws, v)?;
        b.set(sp.state(), np);
        return Ok(());
    }
    let v64 = b.zext::<W16, W64>(v);
    push_v(b, sw, v64, sa, sseg)
}

/// POP sreg。スタック幅で取り出し下位 16 ビットをセレクタへ書く
/// （ベースは変えない。`mov_sr_ld` の注記を参照）。
/// 80386 実モードの o32 形では word だけを読み、SP は
/// オペランド幅（4）で進む（SST 80386 実測）。
pub fn pop_sr<B: Backend>(b: &mut B, s: u8, sw: u8, sa: u8, sseg: u64) -> Flow<B> {
    let v = if sa == 16 && b.param::<crate::StackWrapParam>() == crate::STACK_WRAP_WRAP {
        let v = pop_v(b, 16, sa, sseg)?;
        if sw > 16 {
            sp_add_iw(b, u16::from(sw / 8) - 2, sa);
        }
        v
    } else {
        pop_v(b, sw, sa, sseg)?
    };
    let v16: B::V<W16> = b.trunc::<W64, W16>(v);
    b.set(sem::sreg_ref(s), v16);
    Ok(())
}

/// ARPL r/m16, r16。dst の RPL（下位 2 ビット）が src より小さければ
/// src の RPL に揃えて ZF=1、そうでなければ ZF=0。
pub fn arpl<B: Backend>(
    b: &mut B,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
    eip: u32,
    mode: u8,
    sa: u8,
    sseg: u64,
) -> Result<(), B::Exit> {
    // ARPL は保護モード専用。実モードで実行すると #UD（割り込み 6）。
    if mode == 16 {
        return int_real(b, eip, 0, 6, sa, sseg);
    }
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
        // 8086/8088 は次命令、286 以降はフォールトした命令の先頭を積む
        // （`div_fault_ip` パラメータで選択）。
        let flen = if b.param::<crate::DivFaultIpParam>() == crate::DIV_FAULT_IP_AT_INSN {
            0
        } else {
            len
        };
        int_real(b, eip, flen, 0, sa, sseg)
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
    // POSTIDIV 商オーバーフロー（IDIV のみ）。80286 以降は符号付きの
    // -2^(W-1) を許容するので、q==top かつ商が負になるケースでは
    // q_msb をフォールトに数えない（SST 80286/80386 実測）。
    let q_ovf = if signed && b.param::<crate::Idiv8Param>() == crate::IDIV8_I286 {
        let is_top = b.cmp::<W>(Cmp::Eq, q, top);
        let allow = band(b, is_top, neg_q);
        let nallow = bnot(b, allow);
        band(b, q_msb, nallow)
    } else {
        q_msb
    };
    let mut fault = ef;
    if signed {
        fault = bor(b, ef, q_ovf);
    }
    // 80386: 商が -2^(W-1) を下回る IDIV でも、|被除数| - 2^(2W-2) が
    // [2^(W-1)·|除数|, (2^(W-1)+1)·|除数|) に収まるときは例外にならず、
    // 商を -2^(W-1) に飽和させ剰余は |被除数| - 2^(W-1)|除数| を残す
    // （SST 80386 実測）。80286 では同条件でも #DE になり、8086/80186
    // では商マグニチュード自体が #DE なので、idiv8=i286 かつ
    // fault_atomic=atomic のモデル（= i386 系）に限る。
    let mut q_w = q;
    let mut r_w = r;
    if signed
        && b.param::<crate::Idiv8Param>() == crate::IDIV8_I286
        && b.param::<crate::FaultAtomicParam>() == crate::FAULT_ATOMIC_ATOMIC
    {
        let s = W2::from_u128(1u128 << (W::BITS - 1));
        let s2 = b.konst::<W2>(W2::from_u128(1u128 << (2 * W::BITS - 2)));
        let s_w2 = b.konst::<W2>(s);
        let d2 = b.zext::<W, W2>(d_safe);
        let ge_s2 = b.cmp::<W2>(Cmp::GeU, dvd, s2);
        let c = b.sub::<W2>(dvd, s2);
        let qw = b.udiv::<W2>(c, d2);
        let is_s = b.cmp::<W2>(Cmp::Eq, qw, s_w2);
        let ndz = bnot(b, dz);
        let win0 = band(b, ge_s2, is_s);
        let win1 = band(b, win0, neg_q);
        let win = band(b, win1, ndz);
        let nwin = bnot(b, win);
        fault = band(b, fault, nwin);
        let shs = b.konst::<W2>(W2::from_u128(u128::from(W::BITS - 1)));
        let smd = b.shl::<W2>(d2, shs);
        let r_sat = b.sub::<W2>(dvd, smd);
        let r_sat_w = b.trunc::<W2, W>(r_sat);
        q_w = b.select::<W>(win, top, q);
        r_w = b.select::<W>(win, r_sat_w, r);
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
        let q_neg = b.sub::<W>(zero, q_w);
        let r_neg = b.sub::<W>(zero, r_w);
        let qs = b.select::<W>(neg_q, q_neg, q_w);
        let rs = b.select::<W>(neg_r, r_neg, r_w);
        wr(b, qs, rs);
        Ok(())
    })?;
    let flen = if b.param::<crate::DivFaultIpParam>() == crate::DIV_FAULT_IP_AT_INSN {
        0
    } else {
        len
    };
    b.if_then(fault, |b| int_real(b, eip, flen, 0, sa, sseg))?;
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
    // 第2補正の条件は世代差。8086/8088 は CF | (AL+(AF?0:6)) > 0x9F、
    // 80286 以降は CF | AL > 0x99（SDM 記載どおり。SST 80286 実測）。
    // 8 ビットに折れない幅で比較する（0xFA+6=0x100 も補正対象）。
    let al16: B::V<W16> = b.zext::<W8, W16>(old_al);
    let adj2 = if b.param::<crate::BcdParam>() == crate::BCD_I8088 {
        let add6 = b.select::<W8>(af_in, z8, six);
        let a16: B::V<W16> = b.zext::<W8, W16>(add6);
        let chk = b.add::<W16>(al16, a16);
        let n9f = b.konst::<W16>(0x9F);
        let gt9f = b.cmp::<W16>(Cmp::LtU, n9f, chk);
        bor(b, gt9f, old_cf)
    } else {
        let n99 = b.konst::<W16>(0x99);
        let gt99 = b.cmp::<W16>(Cmp::LtU, n99, al16);
        bor(b, gt99, old_cf)
    };
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
    // 第2補正の条件は DAA と同じ世代差（80286 実測）。
    let al16: B::V<W16> = b.zext::<W8, W16>(old_al);
    let adj2 = if b.param::<crate::BcdParam>() == crate::BCD_I8088 {
        let add6 = b.select::<W8>(af_in, z8, six);
        let a16: B::V<W16> = b.zext::<W8, W16>(add6);
        let chk = b.add::<W16>(al16, a16);
        let n9f = b.konst::<W16>(0x9F);
        let gt9f = b.cmp::<W16>(Cmp::LtU, n9f, chk);
        bor(b, gt9f, old_cf)
    } else {
        let n99 = b.konst::<W16>(0x99);
        let gt99 = b.cmp::<W16>(Cmp::LtU, n99, al16);
        bor(b, gt99, old_cf)
    };
    let c60 = b.konst::<W8>(0x60);
    let sub2 = b.select::<W8>(adj2, c60, z8);
    let v = b.sub::<W8>(al1, sub2);
    sem::write8(b, Gpr(0), false, v);
    // 80286 では第1補正の引き算のボローも CF に残る（SST 実測:
    // AL=0x00 かつ AF=1 → AL=0xFA, CF=1）。
    let cf_v = if b.param::<crate::BcdParam>() == crate::BCD_I286 {
        let bw = b.cmp::<W8>(Cmp::LtU, old_al, sub1);
        bor(b, adj2, bw)
    } else {
        adj2
    };
    // OF は元値 - 補正合計の借りあふれ（8088 実測）。
    let adj_total = b.add::<W8>(sub1, sub2);
    let t1 = b.xor::<W8>(old_al, adj_total);
    let t2 = b.xor::<W8>(old_al, v);
    let s = b.and::<W8>(t1, t2);
    let k80 = b.konst::<W8>(0x80);
    let sm = b.and::<W8>(s, k80);
    let of_take = b.cmp::<W8>(Cmp::Ne, sm, z8);
    let old: B::V<W32> = b.get(eflags_ref());
    let cf = pick(b, cf_v, sem::FLAG_CF);
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
    // 旗ソース: 補正時は al±6、非補正時は al（8088・80286 実測）。
    let src = b.select::<W8>(adj, t, al);
    let al_v = b.and::<W8>(src, f);
    if b.param::<crate::BcdParam>() == crate::BCD_I286 {
        // 80286 以降は AX ± 0x106：AL±6 の桁上りが AH に伝搬する
        // （SST 80286 実測）。AL は最後に下位ニブルへマスク。
        let ax = decode::grd16(b, Gpr(0));
        let k = b.konst::<W16>(0x106);
        let adj_ax = if sub {
            b.sub::<W16>(ax, k)
        } else {
            b.add::<W16>(ax, k)
        };
        let ax_v = b.select::<W16>(adj, adj_ax, ax);
        let msk = b.konst::<W16>(0xFF0F);
        let ax_v = b.and::<W16>(ax_v, msk);
        let lo8: B::V<W8> = b.trunc::<W16, W8>(ax_v);
        sem::write8(b, Gpr(0), false, lo8);
        let sh8 = b.konst::<W16>(8);
        let hi: B::V<W16> = b.shr_l::<W16>(ax_v, sh8);
        let hi8: B::V<W8> = b.trunc::<W16, W8>(hi);
        sem::write8(b, Gpr(0), true, hi8);
    } else {
        // AL = src & 0xF。AH は独立に ±1（桁上りは伝搬しない）。
        let one = b.konst::<W8>(1);
        let d1 = b.select::<W8>(adj, one, z8);
        let ah_v = if sub {
            b.sub::<W8>(ah, d1)
        } else {
            b.add::<W8>(ah, d1)
        };
        sem::write8(b, Gpr(0), false, al_v);
        sem::write8(b, Gpr(0), true, ah_v);
    }
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
        if mode == 16
            && b.param::<crate::Idiv8Param>() == crate::IDIV8_I286
            && b.param::<crate::FaultAtomicParam>() == crate::FAULT_ATOMIC_ATOMIC
        {
            // i386 系のみ（上の複合条件は世代プロキシ。div_cord 参照）。
            // 80386 の AAM 0 は #DE。全ステータスフラグをクリアして
            // PF=被除数 AL>>1 の偶パリティになる（SST 80386 実測）。
            let al = sem::read8(b, Gpr(0), false);
            let one = b.konst::<W8>(1);
            let sh = b.shr_l::<W8>(al, one);
            let old: B::V<W32> = b.get(eflags_ref());
            let clr = b.konst::<W32>(!sem::FLAG_OSZPCA);
            let f = b.and::<W32>(old, clr);
            let pf = pf_bit::<B, W8>(b, sh);
            let f = b.or::<W32>(f, pf);
            b.set(eflags_ref(), f);
            return int_real(b, eip, 0, 0, sa, sseg);
        }
        if b.param::<crate::BcdParam>() == crate::BCD_I286 && mode == 16 {
            // 80286 の AAM 0 は #DE だが、積まれるフラグは全ステータス
            // クリア + PF=被除数 AL の偶パリティになる（SST 80286 実測）。
            let al = sem::read8(b, Gpr(0), false);
            let old: B::V<W32> = b.get(eflags_ref());
            let clr = b.konst::<W32>(!sem::FLAG_OSZPCA);
            let f = b.and::<W32>(old, clr);
            let pf = pf_bit::<B, W8>(b, al);
            let f = b.or::<W32>(f, pf);
            b.set(eflags_ref(), f);
            return int_real(b, eip, 0, 0, sa, sseg);
        }
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
pub fn load_far<B: Backend>(b: &mut B, w: u8, d: &MapDec, rm: &Rm<B::V<W64>>, s: u8) -> Flow<B> {
    let Some((off, seg)) = load_far_ptr(b, w, rm)? else {
        return Ok(());
    };
    match w {
        16 => {
            let off16: B::V<W16> = b.trunc::<W64, W16>(off);
            decode::gwr16(b, decode::reg(d), off16);
        }
        64 => decode::gwr64(b, decode::reg(d), off),
        _ => {
            let off32: B::V<W32> = b.trunc::<W64, W32>(off);
            decode::gwr32(b, decode::reg(d), off32);
        }
    }
    b.set(sem::sreg_ref(s), seg);
    Ok(())
}

/// BOUND Gv, Mp（80186）。添字レジスタが [lo, hi]（符号付き）の外なら
/// 実モードでは割り込み 5。フォールト時に積む IP は命令先頭（len=0）。
#[allow(clippy::too_many_arguments)]
pub fn bound<B: Backend>(
    b: &mut B,
    w: u8,
    d: &MapDec,
    rm: &Rm<B::V<W64>>,
    eip: u32,
    mode: u8,
    sa: u8,
    sseg: u64,
) -> Flow<B> {
    let Rm::Mem { a, wseg } = rm else {
        return Ok(());
    };
    let sz = b.konst::<W64>(u64::from(w / 8));
    let a2 = b.add::<W64>(*a, sz);
    if w == 16 {
        let lo: B::V<W16> = decode::mem_load(b, *a, *wseg)?;
        let hi: B::V<W16> = decode::mem_load(b, a2, *wseg)?;
        let idx = decode::grd16(b, decode::reg(d));
        bound_chk::<B, W16>(b, idx, lo, hi, eip, mode, sa, sseg)
    } else {
        let lo: B::V<W32> = decode::mem_load(b, *a, *wseg)?;
        let hi: B::V<W32> = decode::mem_load(b, a2, *wseg)?;
        let idx = decode::grd32(b, decode::reg(d));
        bound_chk::<B, W32>(b, idx, lo, hi, eip, mode, sa, sseg)
    }
}

#[allow(clippy::too_many_arguments)]
fn bound_chk<B: Backend, W: Width>(
    b: &mut B,
    idx: B::V<W>,
    lo: B::V<W>,
    hi: B::V<W>,
    eip: u32,
    mode: u8,
    sa: u8,
    sseg: u64,
) -> Flow<B> {
    let under = b.cmp::<W>(Cmp::LtS, idx, lo);
    let over = b.cmp::<W>(Cmp::GtS, idx, hi);
    let bad = bor(b, under, over);
    if mode == 16 {
        b.if_then(bad, |b| int_real(b, eip, 0, 5, sa, sseg))
    } else {
        // 保護モードの #BR ハンドラは本格実装で足す。
        use polyisa_sem::{ExceptionKind, GuestException};
        b.if_then(bad, |b| {
            Err(b.raise(GuestException {
                kind: ExceptionKind::Break,
                code: 5,
                addr: Some(eip as u64),
                in_delay_slot: false,
            }))
        })
    }
}

/// SMSW r/m16（80286 実モード）。`msw` 挙動パラメータの値を書く。
/// `reg` 形では機種依存の上位ビットは書かない（`msw` は 16 ビット値）。
pub fn smsw<B: Backend>(b: &mut B, rm: &Rm<B::V<W64>>) -> Flow<B> {
    let m = u64::from(b.param::<crate::MswParam>()) as u16;
    let v = b.konst::<W16>(m);
    decode::wr16(b, rm, v)
}

/// LMSW r/m16。PE ビットを立てる書き込みはどのモードでも例外と
/// する（CR0 を持たないモデルの近似）。PE=0 の書き込みは MSW を
/// 変えない。
pub fn lmsw<B: Backend>(b: &mut B, rm: &Rm<B::V<W64>>, eip: u32) -> Flow<B> {
    let v: B::V<W16> = decode::rd16(b, rm)?;
    let one = b.konst::<W16>(1);
    let pe = b.and::<W16>(v, one);
    let zero = b.konst::<W16>(0);
    let on = b.cmp::<W16>(Cmp::Ne, pe, zero);
    use polyisa_sem::{ExceptionKind, GuestException};
    b.if_then(on, |b| {
        Err(b.raise(GuestException {
            kind: ExceptionKind::Undefined,
            code: 0x000F_0106,
            addr: Some(eip as u64),
            in_delay_slot: false,
        }))
    })
}

// ---- システム状態（0F 00/01 グループ） ----

/// SGDT/SIDT。limit(16) + base(32 または 64) をメモリに書く。
/// `idt` で対象レジスタを選ぶ。80286 ではベースが 24 ビットだが
/// 32 ビット幅で書く近似（上位バイトは実機では不定）。
fn sdtr<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>, mode: u8, idt: bool) -> Result<(), B::Exit> {
    let Rm::Mem { a, wseg } = ea else {
        return Ok(());
    };
    let (base_r, lim_r) = if idt {
        (sem::idtr_base_ref(), sem::idtr_limit_ref())
    } else {
        (sem::gdtr_base_ref(), sem::gdtr_limit_ref())
    };
    // 6/10 バイトのアクセスをまとめて限界検査してから書く
    // （分割書き込みだと前半だけコミットされ得る）。
    if let Some((seg, _)) = wseg {
        let (off, _) = decode::wseg_off(b, *a, *wseg).unwrap();
        let n = if mode == 64 { 10 } else { 6 };
        decode::seg_limit_chk_n(b, off, *seg, n)?;
    }
    let lim: B::V<W16> = b.get(lim_r);
    decode::mem_store::<B, W16>(b, *a, *wseg, lim)?;
    let k2 = b.konst::<W64>(2);
    let a2 = b.add::<W64>(*a, k2);
    let base: B::V<W64> = b.get(base_r);
    if mode == 64 {
        decode::mem_store::<B, W64>(b, a2, *wseg, base)
    } else {
        let base32 = b.trunc::<W64, W32>(base);
        decode::mem_store::<B, W32>(b, a2, *wseg, base32)
    }
}

/// LGDT/LIDT。limit(16) + base(32 または 64) をメモリから読む。
/// 80286 のベースは 24 ビットだが 32 ビット読む近似。
fn ldtr_load<B: Backend>(
    b: &mut B,
    ea: &Rm<B::V<W64>>,
    mode: u8,
    idt: bool,
) -> Result<(), B::Exit> {
    let Rm::Mem { a, wseg } = ea else {
        return Ok(());
    };
    let lim: B::V<W16> = decode::mem_load(b, *a, *wseg)?;
    let k2 = b.konst::<W64>(2);
    let a2 = b.add::<W64>(*a, k2);
    let base: B::V<W64> = if mode == 64 {
        decode::mem_load::<B, W64>(b, a2, *wseg)?
    } else {
        let v: B::V<W32> = decode::mem_load(b, a2, *wseg)?;
        b.zext::<W32, W64>(v)
    };
    let (base_r, lim_r) = if idt {
        (sem::idtr_base_ref(), sem::idtr_limit_ref())
    } else {
        (sem::gdtr_base_ref(), sem::gdtr_limit_ref())
    };
    b.set(base_r, base);
    b.set(lim_r, lim);
    Ok(())
}

/// SLDT/STR。セレクタを格納する。実モードでは全世代で #UD
/// （Intel 80386 PRM: "not recognized in Real Address Mode"）。
/// r/m32 以上の格納先では上位ビットは不定のはずだが、W16 の
/// まま書く近似。
pub fn sldt<B: Backend>(
    b: &mut B,
    is_str: bool,
    rm: &Rm<B::V<W64>>,
    mode: u8,
    eip: u32,
    sa: u8,
    sseg: u64,
) -> Flow<B> {
    if mode == 16 {
        return int_real(b, eip, 0, 6, sa, sseg);
    }
    let sel: B::V<W16> = b.get(if is_str {
        sem::tr_ref()
    } else {
        sem::ldtr_ref()
    });
    decode::wr16(b, rm, sel)
}

/// LLDT/LTR。実モードでは #UD。ディスクリプタ検査を持たないので
/// セレクタをそのまま格納する。
pub fn lldt<B: Backend>(
    b: &mut B,
    is_ltr: bool,
    rm: &Rm<B::V<W64>>,
    mode: u8,
    eip: u32,
    sa: u8,
    sseg: u64,
) -> Flow<B> {
    if mode == 16 {
        return int_real(b, eip, 0, 6, sa, sseg);
    }
    let sel: B::V<W16> = decode::rd16(b, rm)?;
    b.set(
        if is_ltr {
            sem::tr_ref()
        } else {
            sem::ldtr_ref()
        },
        sel,
    );
    Ok(())
}

/// VERR/VERW。実モードでは #UD。ディスクリプタを持たないモデル
/// では全セレクタの検査が失敗するので ZF=0 とする。セレクタ
/// 自体は読まない（読んでも検査結果は変わらない近似）。
pub fn verrw<B: Backend>(b: &mut B, mode: u8, eip: u32, sa: u8, sseg: u64) -> Flow<B> {
    if mode == 16 {
        return int_real(b, eip, 0, 6, sa, sseg);
    }
    let f: B::V<W32> = b.get(eflags_ref());
    let nzf = b.konst::<W32>(!sem::FLAG_ZF);
    let v = b.and::<W32>(f, nzf);
    b.set(eflags_ref(), v);
    Ok(())
}

/// LAR/LSL。実モードでは #UD。ディスクリプタを持たないモデルでは
/// 全セレクタが無効なので ZF=0・dest 不変とする。
pub fn lar_lsl<B: Backend>(b: &mut B, mode: u8, eip: u32, sa: u8, sseg: u64) -> Flow<B> {
    verrw(b, mode, eip, sa, sseg)
}

/// RDRAND/RDSEED。真のエントロピー源は持たないので
/// `rand_seed` パラメータを混ぜた splitmix64 の決定的列を
/// 返す。常に成功（CF=1、他のフラグは 0）。
fn rand_next<B: Backend>(b: &mut B) -> B::V<W64> {
    let s: B::V<W64> = b.get(sem::rand_state_ref());
    let g = b.konst::<W64>(0x9E37_79B9_7F4A_7C15);
    let ns = b.add::<W64>(s, g);
    b.set(sem::rand_state_ref(), ns);
    let p = u64::from(b.param::<crate::RandSeedParam>());
    let seed = b.konst::<W64>(p);
    let mut z = b.add::<W64>(ns, seed);
    let k30 = b.konst::<W64>(30);
    let sh = b.shr_l::<W64>(z, k30);
    z = b.xor::<W64>(z, sh);
    let m1 = b.konst::<W64>(0xBF58_476D_1CE4_E5B9);
    z = b.mul::<W64>(z, m1);
    let k27 = b.konst::<W64>(27);
    let sh = b.shr_l::<W64>(z, k27);
    z = b.xor::<W64>(z, sh);
    let m2 = b.konst::<W64>(0x94D0_49BB_1331_11EB);
    z = b.mul::<W64>(z, m2);
    let k31 = b.konst::<W64>(31);
    let sh = b.shr_l::<W64>(z, k31);
    b.xor::<W64>(z, sh)
}

/// RDFSBASE/RDGSBASE/WRFSBASE/WRGSBASE（F3 0F AE /0-/3）。
/// FS/GS base を GPR とやり取りする。16 ビット形は無いので
/// o64 以外は 32 ビットで扱う。
pub fn fsgsbase<B: Backend>(
    b: &mut B,
    w: u8,
    rm: &Rm<B::V<W64>>,
    gs: bool,
    wr: bool,
    _d: &MapDec,
) -> Flow<B> {
    let Rm::Reg(g) = rm else {
        return Ok(());
    };
    let base = if gs {
        sem::gs_base_ref()
    } else {
        sem::fs_base_ref()
    };
    if wr {
        let v: B::V<W64> = if w == 64 {
            decode::grd64(b, *g)
        } else {
            let v = decode::grd32(b, *g);
            b.zext::<W32, W64>(v)
        };
        b.set(base, v);
    } else {
        let cur: B::V<W64> = b.get(base);
        if w == 64 {
            decode::gwr64(b, *g, cur);
        } else {
            let v = b.trunc::<W64, W32>(cur);
            decode::gwr32(b, *g, v);
        }
    }
    Ok(())
}

/// RDSSPD/RDSSPQ（F3 0F 1E /1）。影響スタックはモデル化
/// しないので dest は 0 固定。
pub fn rdssp<B: Backend>(b: &mut B, w: u8, rm: &Rm<B::V<W64>>, _d: &MapDec) -> Flow<B> {
    let Rm::Reg(g) = rm else {
        return Ok(());
    };
    if w == 64 {
        let z = b.konst::<W64>(0);
        decode::gwr64(b, *g, z);
    } else {
        let z = b.konst::<W32>(0);
        decode::gwr32(b, *g, z);
    }
    Ok(())
}

/// マスクされていない x87 例外が残っているか。FCW/FSW の
/// 下位 6 ビットを見る。ES/B は派生表示なので判定には使わない。
pub fn x87_has_unmasked_pending<B: Backend>(b: &mut B) -> B::B {
    let fsw: B::V<W16> = b.get(sem::fsw_ref());
    let fcw: B::V<W16> = b.get(sem::fcw_ref());
    let exc_mask = b.konst::<W16>(0x3f);
    let fbits = b.and::<W16>(fsw, exc_mask);
    let cbits = b.and::<W16>(fcw, exc_mask);
    let not_c = b.not::<W16>(cbits);
    let pending = b.and::<W16>(fbits, not_c);
    let z16 = b.konst::<W16>(0);
    b.cmp::<W16>(Cmp::Ne, pending, z16)
}

/// x87 浮動小数点例外（#MF 相当）。実際の配送は先行する
/// unmasked exception が残った状態で次の x87 命令/FWAIT を
/// 実行しようとしたときに起こる。
pub fn fp_exception<B: Backend>(b: &mut B, eip: u32) -> Flow<B> {
    use polyisa_sem::{ExceptionKind, GuestException};
    Err(b.raise(GuestException {
        kind: ExceptionKind::Fp,
        code: 16,
        addr: Some(u64::from(eip)),
        in_delay_slot: false,
    }))
}

/// 実モード側の #MF 通知。実行を例外 exit で打ち切り、呼び出し側が
/// IVT vector 16 へ配送する。`int_real` を直接呼ぶと jump だけでは
/// 命令本体の残りを打ち切れないため、この例外を使う。
pub fn fp_exception_real<B: Backend>(b: &mut B) -> Flow<B> {
    use polyisa_sem::{ExceptionKind, GuestException};
    Err(b.raise(GuestException {
        kind: ExceptionKind::Trap,
        code: 16,
        addr: None,
        in_delay_slot: false,
    }))
}

/// 特権違反・保護違反（#GP(0)相当）。
pub fn protection<B: Backend>(b: &mut B, eip: u32) -> Flow<B> {
    use polyisa_sem::{ExceptionKind, GuestException};
    Err(b.raise(GuestException {
        kind: ExceptionKind::Protection,
        code: 0x0D,
        addr: Some(u64::from(eip)),
        in_delay_slot: false,
    }))
}

/// システムモード側の RDMSR。IA32_MISC_ENABLE (0x1a0) だけを
/// モデル化し、その他の MSR は 0 を返す最小近似にする。
pub fn rdmsr<B: Backend>(b: &mut B) -> Flow<B> {
    let ecx = decode::grd32(b, Gpr(1));
    let ia32_misc = b.konst::<W32>(0x1a0);
    let is_misc = b.cmp::<W32>(Cmp::Eq, ecx, ia32_misc);
    let v: B::V<W64> = b.get(crate::sem::misc_enable_ref());
    let lo = b.trunc::<W64, W32>(v);
    let sh = b.konst::<W64>(32);
    let hi64 = b.shr_l::<W64>(v, sh);
    let hi = b.trunc::<W64, W32>(hi64);
    let z = b.konst::<W32>(0);
    let eax = b.select::<W32>(is_misc, lo, z);
    let edx = b.select::<W32>(is_misc, hi, z);
    decode::gwr32(b, Gpr(0), eax);
    decode::gwr32(b, Gpr(2), edx);
    Ok(())
}

/// システムモード側の WRMSR。IA32_MISC_ENABLE だけを保持し、
/// その他の MSR への書き込みは無視する最小近似にする。
pub fn wrmsr<B: Backend>(b: &mut B) -> Flow<B> {
    let ecx = decode::grd32(b, Gpr(1));
    let ia32_misc = b.konst::<W32>(0x1a0);
    let is_misc = b.cmp::<W32>(Cmp::Eq, ecx, ia32_misc);
    let lo32 = decode::grd32(b, Gpr(0));
    let hi32 = decode::grd32(b, Gpr(2));
    let lo = b.zext::<W32, W64>(lo32);
    let hi0 = b.zext::<W32, W64>(hi32);
    let sh = b.konst::<W64>(32);
    let hi = b.shl::<W64>(hi0, sh);
    let v = b.or::<W64>(lo, hi);
    let old: B::V<W64> = b.get(crate::sem::misc_enable_ref());
    let new = b.select::<W64>(is_misc, v, old);
    b.set(crate::sem::misc_enable_ref(), new);
    Ok(())
}

/// RDPID r。TSC_AUX の内容を返す命令だが、エミュレータは
/// TSC_AUX を 0 に固定する。
pub fn rdpid<B: Backend>(b: &mut B, w: u8, rm: &Rm<B::V<W64>>, _d: &MapDec) -> Flow<B> {
    let Rm::Reg(g) = rm else {
        return Ok(());
    };
    if w == 64 {
        let z = b.konst::<W64>(0);
        decode::gwr64(b, *g, z);
    } else {
        let z = b.konst::<W32>(0);
        decode::gwr32(b, *g, z);
    }
    Ok(())
}

/// URDMSR/UWRMSR の最小ユーザーモデル。公開された user MSR は
/// IA32_UARCH_MISC_CTL だけで、ここではマイクロアーキテクチャ
/// 制御なので値を 0 固定・書き込み無視にする。
pub fn urdmsr<B: Backend>(b: &mut B, rm: &Rm<B::V<W64>>) -> Flow<B> {
    if let Rm::Reg(g) = rm {
        let z = b.konst::<W64>(0);
        decode::gwr64(b, *g, z);
    }
    Ok(())
}

/// RDPMC。PMU をモデル化しないのでカウンタは 0。ECX の選択子は
/// そのまま残し、EDX:EAX を 0 にする。
pub fn rdpmc<B: Backend>(b: &mut B) -> Flow<B> {
    let z = b.konst::<W32>(0);
    decode::gwr32(b, Gpr(0), z);
    decode::gwr32(b, Gpr(2), z);
    Ok(())
}

/// RDRAND/RDSEED r。決定的列を書き込み、CF=1・他のフラグは 0。
pub fn rdrand<B: Backend>(b: &mut B, w: u8, rm: &Rm<B::V<W64>>, _d: &MapDec) -> Flow<B> {
    let z = rand_next(b);
    let Rm::Reg(g) = rm else {
        return Ok(());
    };
    match w {
        16 => {
            let v = b.trunc::<W64, W16>(z);
            decode::gwr16(b, *g, v);
        }
        64 => decode::gwr64(b, *g, z),
        _ => {
            let v = b.trunc::<W64, W32>(z);
            decode::gwr32(b, *g, v);
        }
    }
    // CF=1、OF/SF/ZF/AF/PF=0。
    let f: B::V<W32> = b.get(eflags_ref());
    let keep = b.konst::<W32>(
        !(sem::FLAG_CF | sem::FLAG_PF | sem::FLAG_AF | sem::FLAG_ZF | sem::FLAG_SF | sem::FLAG_OF),
    );
    let clr = b.and::<W32>(f, keep);
    let cf = b.konst::<W32>(sem::FLAG_CF);
    let v = b.or::<W32>(clr, cf);
    b.set(eflags_ref(), v);
    Ok(())
}

/// RDPKRU。EAX=PKRU、EDX=0。ECX は入力（0 以外で #GP）で
/// 出力ではないが、#GP はモデル化しないので ECX は触れない。
pub fn rdpkru<B: Backend>(b: &mut B) -> Flow<B> {
    let p: B::V<W64> = b.get(sem::pkru_ref());
    let v = b.trunc::<W64, W32>(p);
    decode::gwr32(b, Gpr(0), v);
    let z = b.konst::<W32>(0);
    decode::gwr32(b, Gpr(2), z);
    Ok(())
}

/// WRPKRU。PKRU=EAX。ECX/EDX が 0 でない場合の #GP は
/// モデル化しない。
pub fn wrpkru<B: Backend>(b: &mut B) -> Flow<B> {
    let v = decode::grd32(b, Gpr(0));
    let w64 = b.zext::<W32, W64>(v);
    b.set(sem::pkru_ref(), w64);
    Ok(())
}

/// XBEGIN。トランザクション実行はモデル化しないので常に
/// アボートし、EAX=`tsx_abort` パラメータを書いて
/// フォールバックアドレスへ分岐する。アボート時の状態復元は
/// XBEGIN 直前の値なので、実質「EAX を書いて分岐」と等価。
pub fn xbegin<B: Backend>(b: &mut B, eip: u32, len: u32, rel: i64) -> Flow<B> {
    let code = u64::from(b.param::<crate::TsxAbortParam>()) as u32;
    let v = b.konst::<W32>(code);
    decode::gwr32(b, Gpr(0), v);
    jmp_rel(b, eip, len, rel)
}

/// XTEST。トランザクションはモデル化しないので実行中は
/// 常に外 = ZF=1。他のフラグは不変。
pub fn xtest<B: Backend>(b: &mut B) -> Flow<B> {
    let f: B::V<W32> = b.get(eflags_ref());
    let zf = b.konst::<W32>(sem::FLAG_ZF);
    let v = b.or::<W32>(f, zf);
    b.set(eflags_ref(), v);
    Ok(())
}

/// TESTUI/UMWAIT。UIF は 0 固定、ウェイクは即時と近似する
/// ので CF=0。他のフラグは不変。
pub fn cf_clear<B: Backend>(b: &mut B) -> Flow<B> {
    let f: B::V<W32> = b.get(eflags_ref());
    let keep = b.konst::<W32>(!FLAG_CF);
    let v = b.and::<W32>(f, keep);
    b.set(eflags_ref(), v);
    Ok(())
}

/// MOVDIR64B/ENQCMD/ENQCMDS。reg が指す宛先へ src の
/// 64 バイトをコピーする。ダイレクトストアやキュー投入の
/// デバイス側振る舞いは持たないので通常のメモリ書き込み
/// として近似する。
pub fn movdir64b<B: Backend>(b: &mut B, dst: Gpr, src: &Rm<B::V<W64>>, m64: bool) -> Flow<B> {
    let Rm::Mem { a, .. } = src else {
        return Ok(());
    };
    // 宛先アドレスを持つレジスタはアドレス幅ではなく
    // レジスタ幅（m64 なら r64）で読む。
    let da: B::V<W64> = if m64 {
        decode::grd64(b, dst)
    } else {
        let v = decode::grd32(b, dst);
        b.zext::<W32, W64>(v)
    };
    for k in 0..8u64 {
        let ka = b.konst::<W64>(k * 8);
        let sa = b.add::<W64>(*a, ka);
        let v: B::V<W64> = b.load::<W64>(sa, sem::DATA_READ)?;
        let dd = b.add::<W64>(da, ka);
        b.store::<W64>(dd, v, sem::DATA_WRITE)?;
    }
    Ok(())
}

/// SGDT。
pub fn sgdt<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>, mode: u8) -> Flow<B> {
    sdtr(b, ea, mode, false)
}
/// SIDT。
pub fn sidt<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>, mode: u8) -> Flow<B> {
    sdtr(b, ea, mode, true)
}
/// LGDT。
pub fn lgdt<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>, mode: u8) -> Flow<B> {
    ldtr_load(b, ea, mode, false)
}
/// LIDT。
pub fn lidt<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>, mode: u8) -> Flow<B> {
    ldtr_load(b, ea, mode, true)
}

// ---- x87 比較・環境 ----

/// FCOM 系の C ビット位置（fsw の bit8,9,10,14）。
const X87_C0: u16 = 0x0100;
const X87_C1: u16 = 0x0200;
const X87_C2: u16 = 0x0400;
const X87_C3: u16 = 0x4000;
const X87_C_MASK: u16 = X87_C0 | X87_C2 | X87_C3;
const X87_CC_MASK: u16 = X87_C_MASK | X87_C1;

/// ST(0) と (sig,exp) を比較して fsw の C0/C2/C3 を更新する。
/// `pop` で 1 段捨てる（FCOMP/FICOMP）。
fn fcom_ext<B: Backend>(b: &mut B, sig: B::V<W64>, exp: B::V<W16>, pop: bool) -> Flow<B> {
    let no_fault = sem::bool_false(b);
    fcom_ext_with_fault(b, sig, exp, pop, no_fault, true)
}

/// `src_fault` は ST(i) source operand の empty 検査。ST(0) と合わせ、
/// unmasked では C ビットとスタックを変えない。masked response は
/// indefinite による unordered 比較となり、pop 形では pop する。
fn fcom_ext_with_fault<B: Backend>(
    b: &mut B,
    sig: B::V<W64>,
    exp: B::V<W16>,
    pop: bool,
    src_fault: B::B,
    ordered: bool,
) -> Flow<B> {
    let top = b.get(sem::top_ref());
    let (s0, e0, fault0) = sem::read_st_source(b, top);
    let fault = sem::bit_or(b, fault0, src_fault);
    let invalid = sem::x87_cmp_invalid(b, s0, e0, sig, exp, ordered);
    let invalid_commit = sem::x87_compare_commit(b, invalid);
    let fault_commit = sem::x87_commit_after_fault(b, fault);
    let commit = sem::bit_and(b, fault_commit, invalid_commit);
    b.if_then(commit, |b| {
        let (zf0, unord0, cf0) = sem::cmp_f80(b, s0, e0, sig, exp);
        let zf = sem::bit_or(b, zf0, invalid);
        let unord = sem::bit_or(b, unord0, invalid);
        let cf = sem::bit_or(b, cf0, invalid);
        let old: B::V<W16> = b.get(sem::fsw_ref());
        // FCOM 系は C1 も 0 にする（C1=1 はスタックフォルト時のみ）。
        let keep = b.konst::<W16>(!X87_CC_MASK);
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
    })
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
        let (s1, e1, fault) = sem::read_st_source(b, slot);
        return fcom_ext_with_fault(b, s1, e1, pop, fault, true);
    }
    let (sig, exp) = match ea {
        Rm::Mem { a, wseg } => {
            let a = *a;
            if bits == 64 {
                let v = decode::mem_load::<B, W64>(b, a, *wseg)?;
                let denormal = sem::f64_denormal(b, v);
                sem::x87_exception_flag(b, denormal, 1 << 1);
                sem::f64_to_ext(b, v)
            } else {
                let v = decode::mem_load::<B, W32>(b, a, *wseg)?;
                let denormal = sem::f32_denormal(b, v);
                sem::x87_exception_flag(b, denormal, 1 << 1);
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
    let (s1, e1, fault) = sem::read_st_source(b, slot);
    fcom_ext_with_fault(b, s1, e1, pop, fault, true)
}

/// FUCOM/FUCOMP st(i)。QNaN では #IA を立てず、SNaN だけを invalid とする。
pub fn fucom_sti<B: Backend>(b: &mut B, i: u8, pop: bool) -> Flow<B> {
    let top = b.get(sem::top_ref());
    let ii = b.konst::<W16>(u16::from(i & 7));
    let summed = b.add::<W16>(top, ii);
    let seven = b.konst::<W16>(7);
    let slot = b.and::<W16>(summed, seven);
    let (s1, e1, fault) = sem::read_st_source(b, slot);
    fcom_ext_with_fault(b, s1, e1, pop, fault, false)
}

/// FCOMPP。ST(0) と ST(1) を比較して C ビットを更新し、2 段ポップする。
pub fn fcompp_st<B: Backend>(b: &mut B) -> Flow<B> {
    fcompp_impl(b, true)
}

/// FUCOMPP。QNaN では #IA を立てず、SNaN だけを invalid とする。
pub fn fucompp_st<B: Backend>(b: &mut B) -> Flow<B> {
    fcompp_impl(b, false)
}

fn fcompp_impl<B: Backend>(b: &mut B, ordered: bool) -> Flow<B> {
    let top = b.get(sem::top_ref());
    let (s0, e0, fault0) = sem::read_st_source(b, top);
    let slot = st_slot(b, 1);
    let (s1, e1, fault1) = sem::read_st_source(b, slot);
    let fault = sem::bit_or(b, fault0, fault1);
    let invalid = sem::x87_cmp_invalid(b, s0, e0, s1, e1, ordered);
    let invalid_commit = sem::x87_compare_commit(b, invalid);
    let fault_commit = sem::x87_commit_after_fault(b, fault);
    let commit = sem::bit_and(b, fault_commit, invalid_commit);
    b.if_then(commit, |b| {
        let (zf0, unord0, cf0) = sem::cmp_f80(b, s0, e0, s1, e1);
        let zf = sem::bit_or(b, zf0, invalid);
        let unord = sem::bit_or(b, unord0, invalid);
        let cf = sem::bit_or(b, cf0, invalid);
        let old: B::V<W16> = b.get(sem::fsw_ref());
        let keep = b.konst::<W16>(!X87_CC_MASK);
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
        let one = b.konst::<W16>(1);
        let inc = b.add::<W16>(top, one);
        let seven = b.konst::<W16>(7);
        let top1 = b.and::<W16>(inc, seven);
        sem::pop_st(b, top)?;
        sem::pop_st(b, top1)?;
        Ok(())
    })
}

/// FTST。ST(0) と +0.0 を比較して C ビットを更新する（ポップなし）。
pub fn ftst_st<B: Backend>(b: &mut B) -> Flow<B> {
    let zs = b.konst::<W64>(0);
    let ze = b.konst::<W16>(0);
    fcom_ext(b, zs, ze, false)
}

/// FXAM。ST(0) を分類して C1=符号、C3/C2/C0=クラスを書く。
/// クラス: 0=未対応(unnormal) 1=NaN 2=正規 3=無限 4=ゼロ 5=空 6=非正規。
/// タグが empty のスロットは値ビットに関係なく Empty(5) に分類する。
pub fn fxam_st<B: Backend>(b: &mut B) -> Flow<B> {
    let top = b.get(sem::top_ref());
    let (sig, exp) = sem::read_st(b, top);
    let e64 = b.zext::<W16, W64>(exp);
    let m7fff = b.konst::<W64>(0x7fff);
    let eb = b.and::<W64>(e64, m7fff);
    let z64 = b.konst::<W64>(0);
    let ibit = b.konst::<W64>(1u64 << 63);
    let ez = b.cmp::<W64>(Cmp::Eq, eb, z64);
    let ef = b.cmp::<W64>(Cmp::Eq, eb, m7fff);
    let sz = b.cmp::<W64>(Cmp::Eq, sig, z64);
    let snz = b.cmp::<W64>(Cmp::Ne, sig, z64);
    let sib = b.cmp::<W64>(Cmp::Eq, sig, ibit);
    let s63 = b.konst::<W64>(63);
    let topbit = b.shr_l::<W64>(sig, s63);
    let one64 = b.konst::<W64>(1);
    let int_set = b.cmp::<W64>(Cmp::Eq, topbit, one64);
    let not_int = sem::bit_not(b, int_set);
    let not_ez = sem::bit_not(b, ez);
    let not_ef = sem::bit_not(b, ef);
    let range = sem::bit_and(b, not_ez, not_ef);
    let not_sib = sem::bit_not(b, sib);
    let nan_shape = sem::bit_and(b, not_sib, int_set);
    let is_nan = sem::bit_and(b, ef, nan_shape);
    let is_inf = sem::bit_and(b, ef, sib);
    let is_zero = sem::bit_and(b, ez, sz);
    let is_den = sem::bit_and(b, ez, snz);
    let nonzero_exp = sem::bit_or(b, range, ef);
    let is_unn = sem::bit_and(b, nonzero_exp, not_int);
    let mut class = b.konst::<W16>(2);
    let z16 = b.konst::<W16>(0);
    let k0 = b.konst::<W16>(0);
    let k1 = b.konst::<W16>(1);
    let k3 = b.konst::<W16>(3);
    let k4 = b.konst::<W16>(4);
    let k6 = b.konst::<W16>(6);
    class = b.select::<W16>(is_unn, k0, class);
    class = b.select::<W16>(is_nan, k1, class);
    class = b.select::<W16>(is_inf, k3, class);
    class = b.select::<W16>(is_zero, k4, class);
    class = b.select::<W16>(is_den, k6, class);
    let tag = sem::x87_read_tag(b, top);
    let empty_tag = b.konst::<W16>(3);
    let is_empty = b.cmp::<W16>(Cmp::Eq, tag, empty_tag);
    let k5 = b.konst::<W16>(5);
    class = b.select::<W16>(is_empty, k5, class);
    let four = b.konst::<W16>(4);
    let two = b.konst::<W16>(2);
    let c3f = b.cmp::<W16>(Cmp::GeU, class, four);
    let c2v = b.and::<W16>(class, two);
    let c2f = b.cmp::<W16>(Cmp::Ne, c2v, z16);
    let c0v = b.and::<W16>(class, k1);
    let c0f = b.cmp::<W16>(Cmp::Ne, c0v, z16);
    let s15 = b.konst::<W64>(15);
    let sgn = b.shr_l::<W64>(e64, s15);
    let c1f = b.cmp::<W64>(Cmp::Eq, sgn, one64);
    let old: B::V<W16> = b.get(sem::fsw_ref());
    let keep = b.konst::<W16>(!X87_CC_MASK);
    let cleared = b.and::<W16>(old, keep);
    let kc0 = b.konst::<W16>(X87_C0);
    let kc1 = b.konst::<W16>(X87_C1);
    let kc2 = b.konst::<W16>(X87_C2);
    let kc3 = b.konst::<W16>(X87_C3);
    let c0 = b.select::<W16>(c0f, kc0, z16);
    let c1 = b.select::<W16>(c1f, kc1, z16);
    let c2 = b.select::<W16>(c2f, kc2, z16);
    let c3 = b.select::<W16>(c3f, kc3, z16);
    let c01 = b.or::<W16>(c0, c1);
    let c23 = b.or::<W16>(c2, c3);
    let cbits = b.or::<W16>(c01, c23);
    let nv = b.or::<W16>(cleared, cbits);
    b.set(sem::fsw_ref(), nv);
    Ok(())
}

/// FPREM/FPREM1。指数差が 64 未満なら剰余を完全に求め、
/// 64 以上なら上位 63 ビット分だけ正確に減算して C2=1 とする。
/// FPREM は商を trunc、FPREM1 は最近接偶数へ丸める。結果は exact。
pub fn fprem_st<B: Backend>(b: &mut B, prem1: bool) -> Flow<B> {
    let top = b.get(sem::top_ref());
    let (s0, e0, fault0) = sem::read_st_source(b, top);
    let slot = st_slot(b, 1);
    let (s1, e1, fault1) = sem::read_st_source(b, slot);
    let fault = sem::bit_or(b, fault0, fault1);
    let commit = sem::x87_commit_after_fault(b, fault);
    let nofault = sem::bit_not(b, fault);

    // 非正規入力や特殊値に対する既存の倍精度近似。通常の有限入力では
    // 下の整数経路が優先される。
    let b0 = sem::f80_to_f64(b, s0, e0);
    let b1 = sem::f80_to_f64(b, s1, e1);
    let f0 = b.trunc::<W64, polyisa_sem::F64>(b0);
    let f1 = b.trunc::<W64, polyisa_sem::F64>(b1);
    let qf64 = b.fdiv::<polyisa_sem::F64>(f0, f1);
    let rm: u8 = if prem1 { 0 } else { 1 };
    let qi_f = b.fcvt_s64::<polyisa_sem::F64>(qf64, rm);
    let qff = b.fcvt_from_s64::<polyisa_sem::F64>(qi_f, 0);
    let prod = b.fmul::<polyisa_sem::F64>(qff, f1);
    let rf = b.fsub::<polyisa_sem::F64>(f0, prod);
    let r64 = b.trunc::<polyisa_sem::F64, W64>(rf);
    let (sr_f, er_f) = sem::f64_to_ext(b, r64);

    let zero = b.konst::<W64>(0);
    let one = b.konst::<W64>(1);
    let mask15 = b.konst::<W64>(0x7fff);
    let special = b.konst::<W64>(0x7fff);
    let s15 = b.konst::<W64>(15);
    let e064 = b.zext::<W16, W64>(e0);
    let e164 = b.zext::<W16, W64>(e1);
    let ea = b.and::<W64>(e064, mask15);
    let eb = b.and::<W64>(e164, mask15);
    let sign0 = b.shr_l::<W64>(e064, s15);
    let sign1 = b.shr_l::<W64>(e164, s15);
    let sp0 = b.cmp::<W64>(Cmp::Eq, ea, special);
    let sp1 = b.cmp::<W64>(Cmp::Eq, eb, special);
    let ez0 = b.cmp::<W64>(Cmp::Eq, ea, zero);
    let ez1 = b.cmp::<W64>(Cmp::Eq, eb, zero);
    let sz0 = b.cmp::<W64>(Cmp::Eq, s0, zero);
    let sz1 = b.cmp::<W64>(Cmp::Eq, s1, zero);
    let snz0 = sem::bit_not(b, sz0);
    let snz1 = sem::bit_not(b, sz1);
    let den0 = sem::bit_and(b, ez0, snz0);
    let den1 = sem::bit_and(b, ez1, snz1);
    let denormal_in0 = sem::bit_or(b, den0, den1);

    let frac_mask = b.konst::<W64>((1u64 << 63) - 1);
    let frac0 = b.and::<W64>(s0, frac_mask);
    let frac1 = b.and::<W64>(s1, frac_mask);
    let f0nz = b.cmp::<W64>(Cmp::Ne, frac0, zero);
    let f1nz = b.cmp::<W64>(Cmp::Ne, frac1, zero);
    let f0zero = sem::bit_not(b, f0nz);
    let f1zero = sem::bit_not(b, f1nz);
    let inf0 = sem::bit_and(b, sp0, f0zero);
    let inf1 = sem::bit_and(b, sp1, f1zero);
    let zero0 = sem::bit_and(b, ez0, sz0);
    let zero1 = sem::bit_and(b, ez1, sz1);
    let nan_sel = sem::x87_nan_select2(b, s0, e0, s1, e1);
    let nan_input = nan_sel.any;
    let snan_invalid = nan_sel.snan_invalid;
    let nan_prop_sig = nan_sel.sig;
    let nan_prop_sign = nan_sel.sign;
    let uns0 = sem::x87_unsupported_format(b, s0, e0);
    let uns1 = sem::x87_unsupported_format(b, s1, e1);
    let unsupported = sem::bit_or(b, uns0, uns1);
    let invalid_zi0 = sem::bit_or(b, inf0, zero1);
    let not_nan_zi = sem::bit_not(b, nan_input);
    let invalid_zi = sem::bit_and(b, invalid_zi0, not_nan_zi);
    let invalid_nan = sem::bit_or(b, invalid_zi, snan_invalid);
    let invalid_raw = sem::bit_or(b, invalid_nan, unsupported);
    let invalid0 = sem::bit_and(b, invalid_raw, nofault);
    sem::x87_exception_flag(b, invalid0, 1);
    // invalid は denormal より優先される。invalid 側だけを処理するときは
    // DE を立てず、unmasked DE による停止ともしない。
    let no_invalid0 = sem::bit_not(b, invalid_raw);
    let no_nan_den = sem::bit_not(b, nan_input);
    let no_invalid_raw = sem::bit_and(b, no_invalid0, no_nan_den);
    let denormal_report0 = sem::bit_and(b, denormal_in0, no_invalid_raw);
    let denormal_in = sem::bit_and(b, denormal_report0, nofault);
    sem::x87_exception_flag(b, denormal_in, 1 << 1);

    // 有限入力では、denormal も正規化した実効指数で整数の筆算だけを行う。
    let z0n = sem::bit_not(b, zero0);
    let z1n = sem::bit_not(b, zero1);
    let sp0n = sem::bit_not(b, sp0);
    let sp1n = sem::bit_not(b, sp1);
    let n0a = sem::bit_and(b, z0n, sp0n);
    let n1a = sem::bit_and(b, z1n, sp1n);
    let normal_inputs = sem::bit_and(b, n0a, n1a);
    let (sn0, ea_eff) = sem::x87_normalize_denormal_operand(b, s0, ea);
    let (sn1, eb_eff) = sem::x87_normalize_denormal_operand(b, s1, eb);

    let diff = b.sub::<W64>(ea_eff, eb_eff);
    let dneg = b.cmp::<W64>(Cmp::LtS, diff, zero);
    let k64lim = b.konst::<W64>(64);
    let partial = b.cmp::<W64>(Cmp::GeS, diff, k64lim);
    let partial_n = sem::bit_not(b, partial);
    let dneg_n = sem::bit_not(b, dneg);
    let dpos = sem::bit_and(b, partial_n, dneg_n);
    let shift_c = b.select::<W64>(dpos, diff, zero);

    // 完全減算: floor((sig0 << D) / sig1)。FPREM1 は剰余と
    // 半分の比較から商を最近接偶数へ丸める。
    let sig0z = b.zext::<W64, W128>(sn0);
    let sig1z = b.zext::<W64, W128>(sn1);
    let one128 = b.konst::<W128>(1);
    let den_safe = b.select::<W128>(sz1, one128, sig1z);
    let shift_c128 = b.zext::<W64, W128>(shift_c);
    let num_c = b.shl::<W128>(sig0z, shift_c128);
    let quot_c128 = b.udiv::<W128>(num_c, den_safe);
    let rem_c128 = b.urem::<W128>(num_c, den_safe);
    let quot_floor = b.trunc::<W128, W64>(quot_c128);
    let rem_floor = b.trunc::<W128, W64>(rem_c128);
    let false_b = b.cmp::<W64>(Cmp::Ne, zero, zero);
    // exponent 差 -1 では筆算の桁合わせ上 0.5 倍ちょうどになる。
    // FPREM1 の quotient は最近接偶数なので、sig0 > sig1 のときだけ
    // quotient 1 へ丸まる。このとき剰余の大きさは
    // (2*sig1-sig0)/2 で、sig0 > sig1 なら桁あふれ前に
    // sig1-(sig0-sig1) として 64 ビットで求められる。
    let minus_one = b.konst::<W64>(u64::MAX);
    let diff_m1 = b.cmp::<W64>(Cmp::Eq, diff, minus_one);
    let sig0_gt_sig1 = b.cmp::<W64>(Cmp::GtU, sn0, sn1);
    let special_half_up0 = sem::bit_and(b, diff_m1, sig0_gt_sig1);
    let special_half_up = if prem1 { special_half_up0 } else { false_b };
    let (qmag_c, rem_mag_c, signflip) = if prem1 {
        let rem2 = b.shl::<W128>(rem_c128, one128);
        let gt_half = b.cmp::<W128>(Cmp::GtU, rem2, den_safe);
        let eq_half = b.cmp::<W128>(Cmp::Eq, rem2, den_safe);
        let qlow = b.and::<W64>(quot_floor, one);
        let floor_odd = b.cmp::<W64>(Cmp::Eq, qlow, one);
        let tie_up = sem::bit_and(b, eq_half, floor_odd);
        let roundup_pos = sem::bit_or(b, gt_half, tie_up);
        let dneg_n = sem::bit_not(b, dneg);
        let roundup_normal = sem::bit_and(b, roundup_pos, dneg_n);
        let roundup = sem::bit_or(b, roundup_normal, special_half_up);
        let upv = b.select::<W64>(roundup, one, zero);
        let qround = b.add::<W64>(quot_floor, upv);
        let deficit = b.sub::<W64>(sn1, rem_floor);
        let sig_delta = b.sub::<W64>(sn0, sn1);
        let deficit_m1 = b.sub::<W64>(sn1, sig_delta);
        let roundup_deficit = b.select::<W64>(special_half_up, deficit_m1, deficit);
        let remmag = b.select::<W64>(roundup, roundup_deficit, rem_floor);
        (qround, remmag, roundup)
    } else {
        (quot_floor, rem_floor, false_b)
    };

    // 部分減算。一回で落とせる exponent は n=(D&31)|32 で、
    // 32..63 の範囲に抑える。これは実機が一度に消費する商桁数の
    // 上限を真似るためで、固定 63 ビットでは部分剰余の指数がずれる。
    let k31 = b.konst::<W64>(31);
    let k32 = b.konst::<W64>(32);
    let diff_low = b.and::<W64>(diff, k31);
    let partial_n = b.or::<W64>(diff_low, k32);
    let partial_n128 = b.zext::<W64, W128>(partial_n);
    let num_p = b.shl::<W128>(sig0z, partial_n128);
    let quot_p128 = b.udiv::<W128>(num_p, den_safe);
    let rem_p128 = b.urem::<W128>(num_p, den_safe);
    let qmag_p = b.trunc::<W128, W64>(quot_p128);
    let rem_mag_p = b.trunc::<W128, W64>(rem_p128);

    // 完全経路の正規化。remainder = rem * 2^(eb-bias-63)。
    let lz_c = sem::clz64(b, rem_mag_c);
    let sig_c_norm = b.shl::<W64>(rem_mag_c, lz_c);
    let eb_eff_m1 = b.sub::<W64>(eb_eff, one);
    let eb_rem_base = b.select::<W64>(special_half_up, eb_eff_m1, eb_eff);
    let eraw_c = b.sub::<W64>(eb_rem_base, lz_c);
    let rem_c_zero = b.cmp::<W64>(Cmp::Eq, rem_mag_c, zero);
    let sig_c_nonzero = b.select::<W64>(rem_c_zero, zero, sig_c_norm);
    let er_c_nonzero = b.select::<W64>(rem_c_zero, zero, eraw_c);
    // D<0 で quotient が 0 に留まるときは被除数がそのまま残る。
    // exponent 差 -1 から FPREM1 の quotient 1 へ丸まったときは、
    // 上で求めた符号反転済み剰余を使う。
    let signflip_n = sem::bit_not(b, signflip);
    let dneg_keep = sem::bit_and(b, dneg, signflip_n);
    let sig_c = b.select::<W64>(dneg_keep, sn0, sig_c_nonzero);
    let er_c_mag = b.select::<W64>(dneg_keep, ea_eff, er_c_nonzero);

    // 部分経路では rem_p が n 桁だけ進んだ商に対応する剰余なので、
    // 正規化 exponent は ea-n-lz。
    let lz_p = sem::clz64(b, rem_mag_p);
    let sig_p_norm = b.shl::<W64>(rem_mag_p, lz_p);
    let eraw_p0 = b.sub::<W64>(ea_eff, partial_n);
    let eraw_p = b.sub::<W64>(eraw_p0, lz_p);
    let rem_p_zero = b.cmp::<W64>(Cmp::Eq, rem_mag_p, zero);
    let sig_p = b.select::<W64>(rem_p_zero, zero, sig_p_norm);
    let er_p_mag = b.select::<W64>(rem_p_zero, zero, eraw_p);

    let sig_exact_mag = b.select::<W64>(partial, sig_p, sig_c);
    let er_exact = b.select::<W64>(partial, er_p_mag, er_c_mag);
    // FPREM1 で商を上げたときだけ剰余の符号が被除数と反転する。
    // 零の剰余は被除数の符号を保つ。
    let flipv = b.select::<W64>(signflip, one, zero);
    let sign_flip = b.xor::<W64>(sign0, flipv);
    let sign_exact = b.select::<W64>(rem_c_zero, sign0, sign_flip);
    let sign_exact = b.select::<W64>(partial, sign0, sign_exact);
    let sign_exact = b.select::<W64>(dneg_keep, sign0, sign_exact);
    let (sig_exact_enc, er_exact16) =
        sem::x87_encode_normalized(b, sig_exact_mag, er_exact, sign_exact);

    // 特殊値の優先順位: NaN/invalid、無限 divisor または零 dividend では
    // ST0 不変、通常有限では整数経路、残りは倍精度近似。
    let any_nan = nan_input;
    let unchanged0 = sem::bit_or(b, inf1, zero0);
    let use_nan0 = sem::bit_or(b, any_nan, invalid0);
    let use_nan = sem::bit_or(b, use_nan0, unsupported);
    let nan_sig = b.konst::<W64>(0xC000_0000_0000_0000);
    let nan_mag64 = b.konst::<W64>(0x7fff);
    let indef_exp64 = b.konst::<W64>(0xffff);
    let not_unsupported = sem::bit_not(b, unsupported);
    let propagate_nan = sem::bit_and(b, nan_input, not_unsupported);
    let nan_out_sig = b.select::<W64>(propagate_nan, nan_prop_sig, nan_sig);
    let nan_sign = b.shl::<W64>(nan_prop_sign, s15);
    let nan_prop_exp = b.or::<W64>(nan_mag64, nan_sign);
    let nan_exp_sel64 = b.select::<W64>(propagate_nan, nan_prop_exp, indef_exp64);
    let nan_exp = b.trunc::<W64, W16>(nan_exp_sel64);
    let sig_sel0 = b.select::<W64>(normal_inputs, sig_exact_enc, sr_f);
    let er_sel0 = b.select::<W16>(normal_inputs, er_exact16, er_f);
    let (den_norm_sig, den_norm_exp) = sem::x87_encode_normalized(b, sn0, ea_eff, sign0);
    let inf_denorm0 = sem::bit_and(b, inf1, den0);
    let unchanged_sig = b.select::<W64>(inf_denorm0, den_norm_sig, s0);
    let unchanged_exp = b.select::<W16>(inf_denorm0, den_norm_exp, e0);
    let sig_sel1 = b.select::<W64>(unchanged0, unchanged_sig, sig_sel0);
    let er_sel1 = b.select::<W16>(unchanged0, unchanged_exp, er_sel0);
    let sig_out0 = b.select::<W64>(use_nan, nan_out_sig, sig_sel1);
    let er_out0 = b.select::<W16>(use_nan, nan_exp, er_sel1);
    let indef_sig = b.konst::<W64>(0xC000_0000_0000_0000);
    let indef_exp = b.konst::<W16>(0xffff);
    let sig_out = b.select::<W64>(fault, indef_sig, sig_out0);
    let er_out = b.select::<W16>(fault, indef_exp, er_out0);

    // 商の符号を反映した低 3 ビット。完全時は C0=Q2/C3=Q1/C1=Q0、
    // 部分時は C2=1、C0=C3=0 で C1 だけ商の bit0。
    let qmag_cp = b.select::<W64>(partial, qmag_p, qmag_c);
    let qmag_all = b.select::<W64>(dneg_keep, zero, qmag_cp);
    let qxor = b.xor::<W64>(sign0, sign1);
    let qnegf = b.cmp::<W64>(Cmp::Ne, qxor, zero);
    let qneg = b.sub::<W64>(zero, qmag_all);
    let qsigned = b.select::<W64>(qnegf, qneg, qmag_all);
    let qi16 = b.trunc::<W64, W16>(qsigned);
    let z16 = b.konst::<W16>(0);
    let one16 = b.konst::<W16>(1);
    let two16 = b.konst::<W16>(2);
    let four16 = b.konst::<W16>(4);
    let q0v = b.and::<W16>(qi16, one16);
    let q1v = b.and::<W16>(qi16, two16);
    let q2v = b.and::<W16>(qi16, four16);
    let q0f = b.cmp::<W16>(Cmp::Ne, q0v, z16);
    let q1f0 = b.cmp::<W16>(Cmp::Ne, q1v, z16);
    let q2f0 = b.cmp::<W16>(Cmp::Ne, q2v, z16);
    let complete = sem::bit_not(b, partial);
    let q1f = sem::bit_and(b, q1f0, complete);
    let q2f = sem::bit_and(b, q2f0, complete);
    let old: B::V<W16> = b.get(sem::fsw_ref());
    let keep = b.konst::<W16>(!X87_CC_MASK);
    let cleared = b.and::<W16>(old, keep);
    let kc0 = b.konst::<W16>(X87_C0);
    let kc1 = b.konst::<W16>(X87_C1);
    let kc2 = b.konst::<W16>(X87_C2);
    let kc3 = b.konst::<W16>(X87_C3);
    let c0 = b.select::<W16>(q2f, kc0, z16);
    let c1 = b.select::<W16>(q0f, kc1, z16);
    let c2 = b.select::<W16>(partial, kc2, z16);
    let c3 = b.select::<W16>(q1f, kc3, z16);
    let c01 = b.or::<W16>(c0, c1);
    let c23 = b.or::<W16>(c2, c3);
    let cbits = b.or::<W16>(c01, c23);
    let exact_cc = b.or::<W16>(cleared, cbits);
    let nv_normal = b.select::<W16>(normal_inputs, exact_cc, old);
    // stack fault の masked response では indefinite を置き、C ビットは
    // 不定なので 0 側へ揃える。unmasked ではこのブロック自体が走らない。
    let nv = b.select::<W16>(fault, cleared, nv_normal);
    let invalid_um = sem::x87_unmasked_exception(b, invalid0, 1);
    let denormal_um = sem::x87_unmasked_exception(b, denormal_in, 1 << 1);
    let suppress0 = sem::bit_or(b, invalid_um, denormal_um);
    let result_commit = sem::x87_arith_result_commit(b, suppress0);
    let commit_result = sem::bit_and(b, commit, result_commit);
    b.if_then(commit_result, |b| {
        sem::write_st(b, top, sig_out, er_out);
        b.set(sem::fsw_ref(), nv);
        Ok(())
    })
}

/// FSCALE。ST(0) = ST(0) * 2^trunc(ST(1))。整数化は 80 ビットから直接行い、
/// 仮数は変えず指数に整数を加える。denormal 入力は正規化し、結果の
/// gradual underflow では FCW.RC に従って丸める。
pub fn fscale_st<B: Backend>(b: &mut B) -> Flow<B> {
    let top = b.get(sem::top_ref());
    let (s0, e0, fault0) = sem::read_st_source(b, top);
    let slot = st_slot(b, 1);
    let (s1, e1, fault1) = sem::read_st_source(b, slot);
    let fault = sem::bit_or(b, fault0, fault1);
    let commit = sem::x87_commit_after_fault(b, fault);
    let nofault = sem::bit_not(b, fault);
    let n = f80_to_i64_trunc_occ(b, s1, e1).0;
    // ±50000 までは正確な scale を保つ。これを超えると、最小/最大の
    // finite exponent を考えても最終的な overflow/underflow 側だけが
    // 残るので、飽和させても結果は変わらない。
    let hi = b.konst::<W64>(0xc350);
    let lo = b.konst::<W64>(0xffff_ffff_ffff_3cb0);
    let nhi = b.cmp::<W64>(Cmp::GtS, n, hi);
    let nlo = b.cmp::<W64>(Cmp::LtS, n, lo);
    let n1 = b.select::<W64>(nhi, hi, n);
    let n2 = b.select::<W64>(nlo, lo, n1);

    let zero = b.konst::<W64>(0);
    let one = b.konst::<W64>(1);
    let mask15 = b.konst::<W64>(0x7fff);
    let special = mask15;
    let s15 = b.konst::<W64>(15);
    let e64 = b.zext::<W16, W64>(e0);
    let eb = b.and::<W64>(e64, mask15);
    let sign = b.shr_l::<W64>(e64, s15);
    let ez0 = b.cmp::<W64>(Cmp::Eq, eb, zero);
    let sz0 = b.cmp::<W64>(Cmp::Eq, s0, zero);
    let snz0 = sem::bit_not(b, sz0);
    let is_zero = sem::bit_and(b, ez0, sz0);
    let denormal0 = sem::bit_and(b, ez0, snz0);
    let sp = b.cmp::<W64>(Cmp::Eq, eb, special);
    let e1_64 = b.zext::<W16, W64>(e1);
    let eb1 = b.and::<W64>(e1_64, mask15);
    let ez1 = b.cmp::<W64>(Cmp::Eq, eb1, zero);
    let sz1 = b.cmp::<W64>(Cmp::Eq, s1, zero);
    let snz1 = sem::bit_not(b, sz1);
    let denormal1 = sem::bit_and(b, ez1, snz1);
    let denormal_in0 = sem::bit_or(b, denormal0, denormal1);
    let denormal_in = sem::bit_and(b, denormal_in0, nofault);
    let sp1 = b.cmp::<W64>(Cmp::Eq, eb1, special);
    let frac_mask = b.konst::<W64>((1u64 << 63) - 1);
    let frac1 = b.and::<W64>(s1, frac_mask);
    let frac1_nz = b.cmp::<W64>(Cmp::Ne, frac1, zero);
    let frac1_z = sem::bit_not(b, frac1_nz);
    let is_inf1 = sem::bit_and(b, sp1, frac1_z);
    let sign1 = b.shr_l::<W64>(e1_64, s15);
    let sign1_set = b.cmp::<W64>(Cmp::Eq, sign1, one);
    let neg_inf1 = sem::bit_and(b, is_inf1, sign1_set);
    let not_sign1 = sem::bit_not(b, sign1_set);
    let pos_inf1 = sem::bit_and(b, is_inf1, not_sign1);
    let pass = sem::bit_or(b, sp, is_zero);

    let nan_sel = sem::x87_nan_select2(b, s0, e0, s1, e1);
    let nan_input = nan_sel.any;
    let snan_invalid = nan_sel.snan_invalid;
    let uns0 = sem::x87_unsupported_format(b, s0, e0);
    let uns1 = sem::x87_unsupported_format(b, s1, e1);
    let unsupported = sem::bit_or(b, uns0, uns1);
    // zero × 2^-inf は zero × 0 なので zero のまま有効だが、
    // zero × 2^+inf は zero × infinity で invalid である。
    let zero_times_infscale = sem::bit_and(b, pos_inf1, is_zero);
    let inf_times_zero_scale0 = sem::bit_and(b, neg_inf1, sp);
    let not_nan_scale = sem::bit_not(b, nan_input);
    let inf_times_zero_scale = sem::bit_and(b, inf_times_zero_scale0, not_nan_scale);
    let invalid_scale0 = sem::bit_or(b, zero_times_infscale, inf_times_zero_scale);
    let invalid_scale = sem::bit_and(b, invalid_scale0, nofault);
    let invalid_pre = sem::bit_or(b, snan_invalid, unsupported);
    let invalid = sem::bit_or(b, invalid_pre, invalid_scale);
    sem::x87_exception_flag(b, invalid, 1);
    let higher_den0 = sem::bit_or(b, nan_input, invalid);
    let higher_den = sem::bit_not(b, higher_den0);
    let denormal = sem::bit_and(b, denormal_in, higher_den);
    sem::x87_exception_flag(b, denormal, 1 << 1);
    let not_nan_input = sem::bit_not(b, nan_input);
    let not_invalid = sem::bit_not(b, invalid);
    let numeric_input0 = sem::bit_and(b, not_nan_input, not_invalid);
    let numeric_input = sem::bit_and(b, numeric_input0, nofault);
    // 整数化が i64 indefinite へ潰れる ±2^63 以上の scale は、
    // 符号だけを保存して結果が変わらない ±50000 へ飽和させる。
    let scale_lim = b.konst::<W64>(16383 + 63);
    let scale_large = b.cmp::<W64>(Cmp::GeU, eb1, scale_lim);
    let scale_neg = b.cmp::<W64>(Cmp::Eq, sign1, one);
    let huge_pos = b.konst::<W64>(0xc350);
    let huge_neg = b.konst::<W64>(0xffff_ffff_ffff_3cb0);
    let huge_signed = b.select::<W64>(scale_neg, huge_neg, huge_pos);
    let n3 = b.select::<W64>(scale_large, huge_signed, n2);

    let (sig_norm, ea_eff) = sem::x87_normalize_denormal_operand(b, s0, eb);
    let sum = b.add::<W64>(ea_eff, n3);
    let over_raw = b.cmp::<W64>(Cmp::GeS, sum, special);
    let under_raw = b.cmp::<W64>(Cmp::LeS, sum, zero);
    let not_pass = sem::bit_not(b, pass);
    let not_inf1 = sem::bit_not(b, is_inf1);
    let scale_active00 = sem::bit_and(b, not_pass, numeric_input);
    let scale_active0 = sem::bit_and(b, scale_active00, not_inf1);
    let over = sem::bit_and(b, over_raw, scale_active0);
    let under = sem::bit_and(b, under_raw, scale_active0);

    // exponent 0 以下では、正規化 significand を FCW.RC で丸めながら
    // denormal へ落とす。shift が 64 以上なら結果は零だが、shift=64
    // では元の integer bit が round bit になる。
    let shift0 = b.sub::<W64>(one, sum);
    let tail_any = sem::bool_false(b);
    let (sig_den, inexact0) = sem::x87_round_shift64_tail(b, sig_norm, shift0, sign, tail_any);
    let int_bit = b.konst::<W64>(1u64 << 63);
    let den_to_normal = b.cmp::<W64>(Cmp::Eq, sig_den, int_bit);
    let denormal_exp0 = b.select::<W64>(den_to_normal, one, zero);
    let sig_under = b.select::<W64>(under, sig_den, sig_norm);
    let exp_under = b.select::<W64>(under, denormal_exp0, sum);
    let inexact = sem::bit_and(b, inexact0, under);
    sem::x87_exception_flag(b, inexact, 1 << 5);

    let (sig_ovm, exp_ovm) = sem::x87_overflow_masked_response(b, sign);
    let sig_scaled = b.select::<W64>(over, sig_ovm, sig_under);
    let exp_scaled = b.select::<W64>(over, exp_ovm, exp_under);
    sem::x87_exception_flag(b, over, 1 << 3);
    sem::x87_exception_flag(b, over, 1 << 5);

    let fcw = b.get(sem::fcw_ref());
    let umask_bit = b.konst::<W16>(1 << 4);
    let umask = b.and::<W16>(fcw, umask_bit);
    let z16 = b.konst::<W16>(0);
    let umasked = b.cmp::<W16>(Cmp::Ne, umask, z16);
    let uunmasked = sem::bit_not(b, umasked);
    let unf_tiny = sem::bit_or(b, inexact, uunmasked);
    let unf = sem::bit_and(b, under, unf_tiny);
    sem::x87_exception_flag(b, unf, 1 << 4);

    let sig_p = b.select::<W64>(pass, s0, sig_scaled);
    let exp_p = b.select::<W64>(pass, e64, exp_scaled);
    let sign_bit = b.shl::<W64>(sign, s15);
    let exp_signed = b.or::<W64>(exp_p, sign_bit);
    // pass した NaN/Inf/zero は入力の符号・指数をそのまま使う。
    let exp_sel = b.select::<W64>(pass, e64, exp_signed);
    let exp16 = b.trunc::<W64, W16>(exp_sel);
    let indef_sig = b.konst::<W64>(0xC000_0000_0000_0000);
    let indef_exp = b.konst::<W16>(0xffff);
    // ST(1) が ±inf のとき、有限非零の ST(0) は例外なしで
    // 符号付き ±inf/+0 になる。NaN は payload と符号を伝播し、
    // unsupported format は負の indefinite になる。
    let int_bit64 = b.konst::<W64>(1u64 << 63);
    let not_sp0 = sem::bit_not(b, sp);
    let nonzero0 = sem::bit_not(b, is_zero);
    let finite0 = sem::bit_and(b, not_sp0, nonzero0);
    let inf_scale0 = sem::bit_and(b, is_inf1, finite0);
    let inf_scale = sem::bit_and(b, inf_scale0, numeric_input);
    let zero_sig64 = b.konst::<W64>(0);
    let infscale_sig = b.select::<W64>(neg_inf1, zero_sig64, int_bit64);
    let infscale_mag = b.select::<W64>(neg_inf1, zero, special);
    let infscale_exp64 = b.or::<W64>(infscale_mag, sign_bit);
    let infscale_exp = b.trunc::<W64, W16>(infscale_exp64);
    let sig_inf = b.select::<W64>(inf_scale, infscale_sig, sig_p);
    let exp_inf = b.select::<W16>(inf_scale, infscale_exp, exp16);
    let not_unsupported = sem::bit_not(b, unsupported);
    let propagate_nan = sem::bit_and(b, nan_input, not_unsupported);
    let nan_sig64 = b.select::<W64>(propagate_nan, nan_sel.sig, indef_sig);
    let nan_sign_bit = b.shl::<W64>(nan_sel.sign, s15);
    let nan_mag = b.or::<W64>(special, nan_sign_bit);
    let nan_prop_exp = b.trunc::<W64, W16>(nan_mag);
    let nan_exp = b.select::<W16>(propagate_nan, nan_prop_exp, indef_exp);
    let sig_nan = b.select::<W64>(nan_input, nan_sig64, sig_inf);
    let exp_nan = b.select::<W16>(nan_input, nan_exp, exp_inf);
    let invalid_response = sem::bit_or(b, unsupported, invalid_scale);
    let sig_uns = b.select::<W64>(invalid_response, indef_sig, sig_nan);
    let exp_uns = b.select::<W16>(invalid_response, indef_exp, exp_nan);
    let sig_out0 = b.select::<W64>(fault, indef_sig, sig_uns);
    let exp_out0 = b.select::<W16>(fault, indef_exp, exp_uns);
    let (sig_out, exp_out) = (sig_out0, exp_out0);
    let invalid_um = sem::x87_unmasked_exception(b, invalid, 1);
    let result_commit = sem::x87_arith_result_commit(b, invalid_um);
    let commit = sem::bit_and(b, commit, result_commit);
    b.if_then(commit, |b| {
        sem::write_st(b, top, sig_out, exp_out);
        Ok(())
    })
}

/// FXTRACT。ST(0) を指数・仮数に分け、結果は ST(0)=仮数（指数 0x3fff、
/// 符号保持）、ST(1)=指数（実数化）。±0/±inf/NaN の各クラス結果は近似。
pub fn fxtract_st<B: Backend>(b: &mut B) -> Flow<B> {
    let top = b.get(sem::top_ref());
    let fsw0 = b.get(sem::fsw_ref());
    let keep_c1 = b.konst::<W16>(!(1u16 << 9));
    let fsw_c1c = b.and::<W16>(fsw0, keep_c1);
    b.set(sem::fsw_ref(), fsw_c1c);
    let (sig, exp, underflow) = sem::read_st_source(b, top);
    let e64 = b.zext::<W16, W64>(exp);
    let m7fff = b.konst::<W64>(0x7fff);
    let eb = b.and::<W64>(e64, m7fff);
    let bias = b.konst::<W64>(0x3fff);
    let zero64 = b.konst::<W64>(0);
    let sig_zero = b.cmp::<W64>(Cmp::Eq, sig, zero64);
    let exp_zero = b.cmp::<W64>(Cmp::Eq, eb, zero64);
    let sig_nz = sem::bit_not(b, sig_zero);
    let is_zero = sem::bit_and(b, exp_zero, sig_zero);
    let denormal0 = sem::bit_and(b, exp_zero, sig_nz);
    let sp = b.cmp::<W64>(Cmp::Eq, eb, m7fff);
    let frac_mask = b.konst::<W64>((1u64 << 63) - 1);
    let frac = b.and::<W64>(sig, frac_mask);
    let frac_nz = b.cmp::<W64>(Cmp::Ne, frac, zero64);
    let is_nan = sem::bit_and(b, sp, frac_nz);
    let frac_z = sem::bit_not(b, frac_nz);
    let is_inf = sem::bit_and(b, sp, frac_z);
    let (sig_norm, ea_eff) = sem::x87_normalize_denormal_operand(b, sig, eb);
    let t = b.sub::<W64>(ea_eff, bias);
    let (es_finite, ee_finite) = sem::i64_to_ext(b, t);
    let m8000 = b.konst::<W16>(0x8000);
    let sgn = b.and::<W16>(exp, m8000);
    let k3fff = b.konst::<W16>(0x3fff);
    let finite_mant_e = b.or::<W16>(sgn, k3fff);
    let int_bit = b.konst::<W64>(1u64 << 63);
    let pinf_e = b.konst::<W16>(0x7fff);
    let ninf_e = b.konst::<W16>(0xffff);
    let zero_mant_e = b.and::<W16>(exp, m8000);
    // zero は ZE で exponent=-inf/significand=signed zero、infinity は
    // exponent=+inf/significand=signed infinity。NaN は両方へ同じ値を置く。
    sem::x87_exception_flag(b, is_zero, 1 << 2);
    let nan_sel = sem::x87_nan_select2(b, sig, exp, sig, exp);
    let snan_invalid = nan_sel.snan_invalid;
    let unsupported = sem::x87_unsupported_format(b, sig, exp);
    let invalid = sem::bit_or(b, snan_invalid, unsupported);
    sem::x87_exception_flag(b, invalid, 1);
    // invalid と zero-divide は denormal より優先される。
    let high0 = sem::bit_or(b, invalid, is_zero);
    let no_high = sem::bit_not(b, high0);
    let denormal = sem::bit_and(b, denormal0, no_high);
    sem::x87_exception_flag(b, denormal, 1 << 1);
    let es_inf = b.select::<W64>(is_inf, int_bit, es_finite);
    let ee_inf = b.select::<W16>(is_inf, pinf_e, ee_finite);
    let es_zero = b.select::<W64>(is_zero, int_bit, es_inf);
    let ee_zero = b.select::<W16>(is_zero, ninf_e, ee_inf);
    let es0 = b.select::<W64>(is_nan, sig, es_zero);
    let ee0 = b.select::<W16>(is_nan, exp, ee_zero);
    let mant_sig_inf = b.select::<W64>(is_inf, int_bit, sig_norm);
    let mant_exp_inf = b.select::<W16>(is_inf, exp, finite_mant_e);
    let mant_sig_zero = b.select::<W64>(is_zero, sig, mant_sig_inf);
    let mant_exp_zero = b.select::<W16>(is_zero, zero_mant_e, mant_exp_inf);
    let new_e0 = b.select::<W16>(is_nan, exp, mant_exp_zero);
    let sig0 = b.select::<W64>(is_nan, sig, mant_sig_zero);
    let indef_sig0 = b.konst::<W64>(0xC000_0000_0000_0000);
    let indef_exp0 = b.konst::<W16>(0xffff);
    let es = b.select::<W64>(invalid, indef_sig0, es0);
    let ee = b.select::<W16>(invalid, indef_exp0, ee0);
    let new_e = b.select::<W16>(invalid, indef_exp0, new_e0);
    let sig = b.select::<W64>(invalid, indef_sig0, sig0);

    let one16 = b.konst::<W16>(1);
    let dec = b.sub::<W16>(top, one16);
    let seven = b.konst::<W16>(7);
    let new_top = b.and::<W16>(dec, seven);
    let target_tag = sem::x87_read_tag(b, new_top);
    let empty_tag = b.konst::<W16>(3);
    let target_empty = b.cmp::<W16>(Cmp::Eq, target_tag, empty_tag);
    let target_occupied = sem::bit_not(b, target_empty);
    let no_underflow = sem::bit_not(b, underflow);
    let overflow = sem::bit_and(b, target_occupied, no_underflow);
    sem::x87_stack_fault(b, overflow, true);

    let fault = sem::bit_or(b, underflow, overflow);
    let fault_commit = sem::x87_commit_after_fault(b, fault);
    let invalid_um = sem::x87_unmasked_exception(b, invalid, 1);
    let zero_um = sem::x87_unmasked_exception(b, is_zero, 1 << 2);
    let denormal_um = sem::x87_unmasked_exception(b, denormal, 1 << 1);
    let suppress0 = sem::bit_or(b, invalid_um, zero_um);
    let suppress = sem::bit_or(b, suppress0, denormal_um);
    let result_commit = sem::x87_arith_result_commit(b, suppress);
    let commit = sem::bit_and(b, fault_commit, result_commit);
    let indef_sig = b.konst::<W64>(0xC000_0000_0000_0000);
    let indef_exp = b.konst::<W16>(0xffff);
    let exp_sig_w = b.select::<W64>(fault, indef_sig, es);
    let exp_exp_w = b.select::<W16>(fault, indef_exp, ee);
    let mant_sig_w = b.select::<W64>(fault, indef_sig, sig);
    let mant_exp_w = b.select::<W16>(fault, indef_exp, new_e);
    b.if_then(commit, |b| {
        sem::write_st(b, top, exp_sig_w, exp_exp_w);
        b.set(sem::top_ref(), new_top);
        sem::write_st(b, new_top, mant_sig_w, mant_exp_w);
        Ok(())
    })
}

/// 環境イメージ内の 16 ビット値を書く。
fn env_st16<B: Backend>(
    b: &mut B,
    a: B::V<W64>,
    wseg: Option<(u64, B::V<W64>)>,
    off: u64,
    v: B::V<W16>,
) -> Flow<B> {
    let k = b.konst::<W64>(off);
    let ad = b.add::<W64>(a, k);
    decode::mem_store::<B, W16>(b, ad, wseg, v)
}

/// 環境イメージ内の 16 ビット値を読む。
fn env_ld16<B: Backend>(
    b: &mut B,
    a: B::V<W64>,
    wseg: Option<(u64, B::V<W64>)>,
    off: u64,
) -> Result<B::V<W16>, B::Exit> {
    let k = b.konst::<W64>(off);
    let ad = b.add::<W64>(a, k);
    decode::mem_load::<B, W16>(b, ad, wseg)
}

/// 16 ビット保護モード形式（Figure 8-11）を書く。FOP はこの形式に無い。
fn x87_env_store_prot16<B: Backend>(
    b: &mut B,
    a: B::V<W64>,
    wseg: Option<(u64, B::V<W64>)>,
) -> Flow<B> {
    let fcw: B::V<W16> = b.get(sem::fcw_ref());
    env_st16(b, a, wseg, 0, fcw)?;
    let fsw: B::V<W16> = b.get(sem::fsw_ref());
    let top = b.get(sem::top_ref());
    let seven = b.konst::<W16>(7);
    let t3 = b.and::<W16>(top, seven);
    let sh = b.konst::<W16>(11);
    let tbits = b.shl::<W16>(t3, sh);
    let fswv = b.or::<W16>(fsw, tbits);
    env_st16(b, a, wseg, 2, fswv)?;
    let ftw: B::V<W16> = b.get(sem::ftw_ref());
    env_st16(b, a, wseg, 4, ftw)?;
    let fip64: B::V<W64> = b.get(sem::fip_ref());
    let fip: B::V<W16> = b.trunc::<W64, W16>(fip64);
    env_st16(b, a, wseg, 6, fip)?;
    let fcs: B::V<W16> = b.get(sem::fcs_ref());
    env_st16(b, a, wseg, 8, fcs)?;
    let fdp64: B::V<W64> = b.get(sem::fdp_ref());
    let fdp: B::V<W16> = b.trunc::<W64, W16>(fdp64);
    env_st16(b, a, wseg, 10, fdp)?;
    let fds: B::V<W16> = b.get(sem::fds_ref());
    env_st16(b, a, wseg, 12, fds)
}

/// 16 ビット保護モード形式を読む。FOP は形式に無いので 0 にする。
fn x87_env_load_prot16<B: Backend>(
    b: &mut B,
    a: B::V<W64>,
    wseg: Option<(u64, B::V<W64>)>,
) -> Flow<B> {
    let fcw = env_ld16(b, a, wseg, 0)?;
    b.set(sem::fcw_ref(), fcw);
    let fsw = env_ld16(b, a, wseg, 2)?;
    let sh = b.konst::<W16>(11);
    let t = b.shr_l::<W16>(fsw, sh);
    let seven = b.konst::<W16>(7);
    let top = b.and::<W16>(t, seven);
    let keep = b.konst::<W16>(!0x3800u16);
    let fsw_n = b.and::<W16>(fsw, keep);
    b.set(sem::fsw_ref(), fsw_n);
    b.set(sem::top_ref(), top);
    let ftw = env_ld16(b, a, wseg, 4)?;
    b.set(sem::ftw_ref(), ftw);
    let fip = env_ld16(b, a, wseg, 6)?;
    let fip64 = b.zext::<W16, W64>(fip);
    b.set(sem::fip_ref(), fip64);
    let fcs = env_ld16(b, a, wseg, 8)?;
    b.set(sem::fcs_ref(), fcs);
    let fdp = env_ld16(b, a, wseg, 10)?;
    let fdp64 = b.zext::<W16, W64>(fdp);
    b.set(sem::fdp_ref(), fdp64);
    let fds = env_ld16(b, a, wseg, 12)?;
    b.set(sem::fds_ref(), fds);
    let z16 = b.konst::<W16>(0);
    b.set(sem::fop_ref(), z16);
    Ok(())
}

/// real-address mode 32-bit format（Figure 8-10）を書く。
/// 図の上位 4 ビットは 0 で、FIP/FDP の上位側は 12 ビットだけを保持する。
fn x87_env_store_real32<B: Backend>(
    b: &mut B,
    a: B::V<W64>,
    wseg: Option<(u64, B::V<W64>)>,
) -> Flow<B> {
    let z16 = b.konst::<W16>(0);
    let fcw: B::V<W16> = b.get(sem::fcw_ref());
    env_st16(b, a, wseg, 0, fcw)?;
    env_st16(b, a, wseg, 2, z16)?;
    let fsw: B::V<W16> = b.get(sem::fsw_ref());
    let top = b.get(sem::top_ref());
    let seven = b.konst::<W16>(7);
    let t3 = b.and::<W16>(top, seven);
    let sh11 = b.konst::<W16>(11);
    let tbits = b.shl::<W16>(t3, sh11);
    let fswv = b.or::<W16>(fsw, tbits);
    env_st16(b, a, wseg, 4, fswv)?;
    env_st16(b, a, wseg, 6, z16)?;
    let ftw: B::V<W16> = b.get(sem::ftw_ref());
    env_st16(b, a, wseg, 8, ftw)?;
    env_st16(b, a, wseg, 10, z16)?;
    let fip64: B::V<W64> = b.get(sem::fip_ref());
    let fip32: B::V<W32> = b.trunc::<W64, W32>(fip64);
    let fipl: B::V<W16> = b.trunc::<W32, W16>(fip32);
    env_st16(b, a, wseg, 12, fipl)?;
    env_st16(b, a, wseg, 14, z16)?;
    let fop: B::V<W16> = b.get(sem::fop_ref());
    let opmask = b.konst::<W16>(0x7ff);
    let fop11 = b.and::<W16>(fop, opmask);
    // +16 dword の bits27:12 に FIP[31:16] が連続して入る。
    // したがって +16 は FIP[19:16]<<12|FOP、+18 は FIP[31:20]。
    let sh16w = b.konst::<W32>(16);
    let fiph32 = b.shr_l::<W32>(fip32, sh16w);
    let maskfw = b.konst::<W32>(0xf);
    let fipln = b.and::<W32>(fiph32, maskfw);
    let sh12w32 = b.konst::<W32>(12);
    let fipln_pos = b.shl::<W32>(fipln, sh12w32);
    let fop32 = b.zext::<W16, W32>(fop11);
    let lowmix = b.or::<W32>(fipln_pos, fop32);
    let lowmix16: B::V<W16> = b.trunc::<W32, W16>(lowmix);
    env_st16(b, a, wseg, 16, lowmix16)?;
    let sh20w = b.konst::<W32>(20);
    let fiph32 = b.shr_l::<W32>(fip32, sh20w);
    let mask12w = b.konst::<W32>(0xfff);
    let fiph12 = b.and::<W32>(fiph32, mask12w);
    let fiph: B::V<W16> = b.trunc::<W32, W16>(fiph12);
    env_st16(b, a, wseg, 18, fiph)?;
    let fdp64: B::V<W64> = b.get(sem::fdp_ref());
    let fdp32: B::V<W32> = b.trunc::<W64, W32>(fdp64);
    let fdpl: B::V<W16> = b.trunc::<W32, W16>(fdp32);
    env_st16(b, a, wseg, 20, fdpl)?;
    env_st16(b, a, wseg, 22, z16)?;
    let fdph32 = b.shr_l::<W32>(fdp32, sh16w);
    let fdpln = b.and::<W32>(fdph32, maskfw);
    let fdpln_pos = b.shl::<W32>(fdpln, sh12w32);
    let fdplow16: B::V<W16> = b.trunc::<W32, W16>(fdpln_pos);
    env_st16(b, a, wseg, 24, fdplow16)?;
    let fdph32 = b.shr_l::<W32>(fdp32, sh20w);
    let fdph12 = b.and::<W32>(fdph32, mask12w);
    let fdph: B::V<W16> = b.trunc::<W32, W16>(fdph12);
    env_st16(b, a, wseg, 26, fdph)
}

/// real-address mode 32-bit format を読む。selector は real mode なので clear。
fn x87_env_load_real32<B: Backend>(
    b: &mut B,
    a: B::V<W64>,
    wseg: Option<(u64, B::V<W64>)>,
) -> Flow<B> {
    let fcw = env_ld16(b, a, wseg, 0)?;
    b.set(sem::fcw_ref(), fcw);
    let fsw = env_ld16(b, a, wseg, 4)?;
    let sh = b.konst::<W16>(11);
    let t = b.shr_l::<W16>(fsw, sh);
    let seven = b.konst::<W16>(7);
    let top = b.and::<W16>(t, seven);
    let keep = b.konst::<W16>(!0x3800u16);
    let fsw_n = b.and::<W16>(fsw, keep);
    b.set(sem::fsw_ref(), fsw_n);
    b.set(sem::top_ref(), top);
    let ftw = env_ld16(b, a, wseg, 8)?;
    b.set(sem::ftw_ref(), ftw);
    let lo16 = env_ld16(b, a, wseg, 12)?;
    let hi16 = env_ld16(b, a, wseg, 18)?;
    let lo32 = b.zext::<W16, W32>(lo16);
    let hi32 = b.zext::<W16, W32>(hi16);
    let sh16 = b.konst::<W32>(16);
    let mix = env_ld16(b, a, wseg, 16)?;
    let mix32 = b.zext::<W16, W32>(mix);
    let sh12 = b.konst::<W32>(12);
    let ip_ln0 = b.shr_l::<W32>(mix32, sh12);
    let mask4 = b.konst::<W32>(0xf);
    let ip_ln = b.and::<W32>(ip_ln0, mask4);
    let ip_ln_pos = b.shl::<W32>(ip_ln, sh16);
    let mask12 = b.konst::<W32>(0xfff);
    let ip_hi12 = b.and::<W32>(hi32, mask12);
    let sh20 = b.konst::<W32>(20);
    let ip_hi_pos = b.shl::<W32>(ip_hi12, sh20);
    let fip_lo = b.or::<W32>(lo32, ip_ln_pos);
    let fip32 = b.or::<W32>(fip_lo, ip_hi_pos);
    let fip64 = b.zext::<W32, W64>(fip32);
    b.set(sem::fip_ref(), fip64);
    let fop = env_ld16(b, a, wseg, 16)?;
    let opmask = b.konst::<W16>(0x7ff);
    let fop11 = b.and::<W16>(fop, opmask);
    b.set(sem::fop_ref(), fop11);
    let dlo16 = env_ld16(b, a, wseg, 20)?;
    let dhi16 = env_ld16(b, a, wseg, 26)?;
    let dlo32 = b.zext::<W16, W32>(dlo16);
    let dhi32 = b.zext::<W16, W32>(dhi16);
    let dmix = env_ld16(b, a, wseg, 24)?;
    let dmix32 = b.zext::<W16, W32>(dmix);
    let dp_ln0 = b.shr_l::<W32>(dmix32, sh12);
    let dp_ln = b.and::<W32>(dp_ln0, mask4);
    let dp_ln_pos = b.shl::<W32>(dp_ln, sh16);
    let dp_hi12 = b.and::<W32>(dhi32, mask12);
    let dp_hi_pos = b.shl::<W32>(dp_hi12, sh20);
    let fdp_lo = b.or::<W32>(dlo32, dp_ln_pos);
    let fdp32 = b.or::<W32>(fdp_lo, dp_hi_pos);
    let fdp64 = b.zext::<W32, W64>(fdp32);
    b.set(sem::fdp_ref(), fdp64);
    let z16 = b.konst::<W16>(0);
    b.set(sem::fcs_ref(), z16);
    b.set(sem::fds_ref(), z16);
    Ok(())
}

/// real-address mode 16-bit format（Figure 8-12）を書く。
fn x87_env_store_real16<B: Backend>(
    b: &mut B,
    a: B::V<W64>,
    wseg: Option<(u64, B::V<W64>)>,
) -> Flow<B> {
    let fcw: B::V<W16> = b.get(sem::fcw_ref());
    env_st16(b, a, wseg, 0, fcw)?;
    let fsw: B::V<W16> = b.get(sem::fsw_ref());
    let top = b.get(sem::top_ref());
    let seven = b.konst::<W16>(7);
    let t3 = b.and::<W16>(top, seven);
    let sh11 = b.konst::<W16>(11);
    let tbits = b.shl::<W16>(t3, sh11);
    let fswv = b.or::<W16>(fsw, tbits);
    env_st16(b, a, wseg, 2, fswv)?;
    let ftw: B::V<W16> = b.get(sem::ftw_ref());
    env_st16(b, a, wseg, 4, ftw)?;
    let fip64: B::V<W64> = b.get(sem::fip_ref());
    let fip32: B::V<W32> = b.trunc::<W64, W32>(fip64);
    let fipl: B::V<W16> = b.trunc::<W32, W16>(fip32);
    env_st16(b, a, wseg, 6, fipl)?;
    let sh16w = b.konst::<W32>(16);
    let fiph = b.shr_l::<W32>(fip32, sh16w);
    let mask4w = b.konst::<W32>(0xf);
    let fiph4 = b.and::<W32>(fiph, mask4w);
    let sh12w = b.konst::<W32>(12);
    let fiph_pos = b.shl::<W32>(fiph4, sh12w);
    let fop: B::V<W16> = b.get(sem::fop_ref());
    let fop32 = b.zext::<W16, W32>(fop);
    let maskop = b.konst::<W32>(0x7ff);
    let fop11 = b.and::<W32>(fop32, maskop);
    let mixed = b.or::<W32>(fiph_pos, fop11);
    let mixed16: B::V<W16> = b.trunc::<W32, W16>(mixed);
    env_st16(b, a, wseg, 8, mixed16)?;
    let fdp64: B::V<W64> = b.get(sem::fdp_ref());
    let fdp32: B::V<W32> = b.trunc::<W64, W32>(fdp64);
    let fdpl: B::V<W16> = b.trunc::<W32, W16>(fdp32);
    env_st16(b, a, wseg, 10, fdpl)?;
    let fdph = b.shr_l::<W32>(fdp32, sh16w);
    let fdph4 = b.and::<W32>(fdph, mask4w);
    let fdph_pos = b.shl::<W32>(fdph4, sh12w);
    let fdph16: B::V<W16> = b.trunc::<W32, W16>(fdph_pos);
    env_st16(b, a, wseg, 12, fdph16)
}

/// real-address mode 16-bit format を読む。selector は real mode なので clear。
fn x87_env_load_real16<B: Backend>(
    b: &mut B,
    a: B::V<W64>,
    wseg: Option<(u64, B::V<W64>)>,
) -> Flow<B> {
    let fcw = env_ld16(b, a, wseg, 0)?;
    b.set(sem::fcw_ref(), fcw);
    let fsw = env_ld16(b, a, wseg, 2)?;
    let sh = b.konst::<W16>(11);
    let t = b.shr_l::<W16>(fsw, sh);
    let seven = b.konst::<W16>(7);
    let top = b.and::<W16>(t, seven);
    let keep = b.konst::<W16>(!0x3800u16);
    let fsw_n = b.and::<W16>(fsw, keep);
    b.set(sem::fsw_ref(), fsw_n);
    b.set(sem::top_ref(), top);
    let ftw = env_ld16(b, a, wseg, 4)?;
    b.set(sem::ftw_ref(), ftw);
    let lo = env_ld16(b, a, wseg, 6)?;
    let mixed = env_ld16(b, a, wseg, 8)?;
    let lo32 = b.zext::<W16, W32>(lo);
    let mixed32 = b.zext::<W16, W32>(mixed);
    let sh12 = b.konst::<W32>(12);
    let hi_nib0 = b.shr_l::<W32>(mixed32, sh12);
    let mask4 = b.konst::<W32>(0xf);
    let hi_nib = b.and::<W32>(hi_nib0, mask4);
    let sh16 = b.konst::<W32>(16);
    let hi20 = b.shl::<W32>(hi_nib, sh16);
    let fip32 = b.or::<W32>(lo32, hi20);
    let fip64 = b.zext::<W32, W64>(fip32);
    b.set(sem::fip_ref(), fip64);
    let opmask = b.konst::<W16>(0x7ff);
    let fop = b.and::<W16>(mixed, opmask);
    b.set(sem::fop_ref(), fop);
    let dlo = env_ld16(b, a, wseg, 10)?;
    let dhi = env_ld16(b, a, wseg, 12)?;
    let dlo32 = b.zext::<W16, W32>(dlo);
    let dhi32 = b.zext::<W16, W32>(dhi);
    let dhi_nib0 = b.shr_l::<W32>(dhi32, sh12);
    let dhi_nib = b.and::<W32>(dhi_nib0, mask4);
    let dhi20 = b.shl::<W32>(dhi_nib, sh16);
    let fdp32 = b.or::<W32>(dlo32, dhi20);
    let fdp64 = b.zext::<W32, W64>(fdp32);
    b.set(sem::fdp_ref(), fdp64);
    let z16 = b.konst::<W16>(0);
    b.set(sem::fcs_ref(), z16);
    b.set(sem::fds_ref(), z16);
    Ok(())
}

/// 環境形式を選んで書く。戻り値の size は後続 ST image の開始 offset。
fn x87_env_store<B: Backend>(
    b: &mut B,
    a: B::V<W64>,
    wseg: Option<(u64, B::V<W64>)>,
    mode: u8,
    osize: u8,
) -> Result<u64, B::Exit> {
    if mode == 16 {
        if osize == 16 {
            x87_env_store_real16(b, a, wseg)?;
            Ok(14)
        } else {
            x87_env_store_real32(b, a, wseg)?;
            Ok(28)
        }
    } else if osize == 16 {
        x87_env_store_prot16(b, a, wseg)?;
        Ok(14)
    } else {
        x87_env_store_prot32(b, a, wseg)?;
        Ok(28)
    }
}

/// 環境形式を選んで読む。戻り値の size は後続 ST image の開始 offset。
fn x87_env_load<B: Backend>(
    b: &mut B,
    a: B::V<W64>,
    wseg: Option<(u64, B::V<W64>)>,
    mode: u8,
    osize: u8,
) -> Result<u64, B::Exit> {
    if mode == 16 {
        if osize == 16 {
            x87_env_load_real16(b, a, wseg)?;
            Ok(14)
        } else {
            x87_env_load_real32(b, a, wseg)?;
            Ok(28)
        }
    } else if osize == 16 {
        x87_env_load_prot16(b, a, wseg)?;
        Ok(14)
    } else {
        x87_env_load_prot32(b, a, wseg)?;
        Ok(28)
    }
}

/// FNSAVE/FNSTENV 共通の環境 28 バイト書き込み。
/// 32 ビット保護モード形式。/// FNSAVE/FNSTENV 共通の環境 28 バイト書き込み。
/// 32 ビット保護モード形式。各 32 ビット語の下位に FCW/FSW/FTW を置き、
/// 上位は 0。FIP/FCS/FOP/FDP/FDS は追跡未実装なので 0 を書く。
fn x87_env_store_prot32<B: Backend>(
    b: &mut B,
    a: B::V<W64>,
    wseg: Option<(u64, B::V<W64>)>,
) -> Flow<B> {
    let fcw: B::V<W16> = b.get(sem::fcw_ref());
    decode::mem_store::<B, W16>(b, a, wseg, fcw)?;
    let z16 = b.konst::<W16>(0);
    let a2 = b.konst::<W64>(2);
    let aw = b.add::<W64>(a, a2);
    decode::mem_store::<B, W16>(b, aw, wseg, z16)?;
    let fsw: B::V<W16> = b.get(sem::fsw_ref());
    let top = b.get(sem::top_ref());
    let seven = b.konst::<W16>(7);
    let t3 = b.and::<W16>(top, seven);
    let sh = b.konst::<W16>(11);
    let tbits = b.shl::<W16>(t3, sh);
    let fswv = b.or::<W16>(fsw, tbits);
    let a4 = b.konst::<W64>(4);
    let afs = b.add::<W64>(a, a4);
    decode::mem_store::<B, W16>(b, afs, wseg, fswv)?;
    let a6 = b.konst::<W64>(6);
    let aw = b.add::<W64>(a, a6);
    decode::mem_store::<B, W16>(b, aw, wseg, z16)?;
    let ftag: B::V<W16> = b.get(sem::ftw_ref());
    let a8 = b.konst::<W64>(8);
    let aft = b.add::<W64>(a, a8);
    decode::mem_store::<B, W16>(b, aft, wseg, ftag)?;
    let a10 = b.konst::<W64>(10);
    let aw = b.add::<W64>(a, a10);
    decode::mem_store::<B, W16>(b, aw, wseg, z16)?;
    let a12 = b.konst::<W64>(12);
    let aw = b.add::<W64>(a, a12);
    let fip: B::V<W64> = b.get(sem::fip_ref());
    let fip32: B::V<W32> = b.trunc::<W64, W32>(fip);
    decode::mem_store::<B, W32>(b, aw, wseg, fip32)?;
    let a16 = b.konst::<W64>(16);
    let aw = b.add::<W64>(a, a16);
    let fcs: B::V<W16> = b.get(sem::fcs_ref());
    decode::mem_store::<B, W16>(b, aw, wseg, fcs)?;
    let a18 = b.konst::<W64>(18);
    let aw = b.add::<W64>(a, a18);
    let fop: B::V<W16> = b.get(sem::fop_ref());
    let opmask = b.konst::<W16>(0x7ff);
    let fop11 = b.and::<W16>(fop, opmask);
    decode::mem_store::<B, W16>(b, aw, wseg, fop11)?;
    let a20 = b.konst::<W64>(20);
    let aw = b.add::<W64>(a, a20);
    let fdp: B::V<W64> = b.get(sem::fdp_ref());
    let fdp32: B::V<W32> = b.trunc::<W64, W32>(fdp);
    decode::mem_store::<B, W32>(b, aw, wseg, fdp32)?;
    let a24 = b.konst::<W64>(24);
    let aw = b.add::<W64>(a, a24);
    let fds: B::V<W16> = b.get(sem::fds_ref());
    decode::mem_store::<B, W16>(b, aw, wseg, fds)?;
    let a26 = b.konst::<W64>(26);
    let aw = b.add::<W64>(a, a26);
    decode::mem_store::<B, W16>(b, aw, wseg, z16)?;
    Ok(())
}

/// FRSTOR/FLDENV 共通の環境読み出し。32 ビット保護モード形式の
/// FCW・FSW（C ビット+TOP）・FTW を戻す。FRSTOR 側はこの FTW の
/// empty/non-empty だけを使い、非空タグをデータから再計算する。
fn x87_env_load_prot32<B: Backend>(
    b: &mut B,
    a: B::V<W64>,
    wseg: Option<(u64, B::V<W64>)>,
) -> Flow<B> {
    let fcw = decode::mem_load::<B, W16>(b, a, wseg)?;
    b.set(sem::fcw_ref(), fcw);
    let a4 = b.konst::<W64>(4);
    let afs = b.add::<W64>(a, a4);
    let fsw = decode::mem_load::<B, W16>(b, afs, wseg)?;
    let sh = b.konst::<W16>(11);
    let t = b.shr_l::<W16>(fsw, sh);
    let seven = b.konst::<W16>(7);
    let top = b.and::<W16>(t, seven);
    // TOP は専用の top 状態が持つ。fsw からは TOP ビットを除いて格納する。
    let keep = b.konst::<W16>(!0x3800u16);
    let fsw_n = b.and::<W16>(fsw, keep);
    b.set(sem::fsw_ref(), fsw_n);
    b.set(sem::top_ref(), top);
    let a8 = b.konst::<W64>(8);
    let aft = b.add::<W64>(a, a8);
    let ftw = decode::mem_load::<B, W16>(b, aft, wseg)?;
    b.set(sem::ftw_ref(), ftw);
    let a12 = b.konst::<W64>(12);
    let aw = b.add::<W64>(a, a12);
    let fip32: B::V<W32> = decode::mem_load::<B, W32>(b, aw, wseg)?;
    let fip = b.zext::<W32, W64>(fip32);
    b.set(sem::fip_ref(), fip);
    let a16 = b.konst::<W64>(16);
    let aw = b.add::<W64>(a, a16);
    let fcs = decode::mem_load::<B, W16>(b, aw, wseg)?;
    b.set(sem::fcs_ref(), fcs);
    let a18 = b.konst::<W64>(18);
    let aw = b.add::<W64>(a, a18);
    let fop = decode::mem_load::<B, W16>(b, aw, wseg)?;
    let opmask = b.konst::<W16>(0x7ff);
    let fop11 = b.and::<W16>(fop, opmask);
    b.set(sem::fop_ref(), fop11);
    let a20 = b.konst::<W64>(20);
    let aw = b.add::<W64>(a, a20);
    let fdp32: B::V<W32> = decode::mem_load::<B, W32>(b, aw, wseg)?;
    let fdp = b.zext::<W32, W64>(fdp32);
    b.set(sem::fdp_ref(), fdp);
    let a24 = b.konst::<W64>(24);
    let aw = b.add::<W64>(a, a24);
    let fds = decode::mem_load::<B, W16>(b, aw, wseg)?;
    b.set(sem::fds_ref(), fds);
    Ok(())
}

/// FTW image の empty/non-empty を保ち、非空スロットの
/// valid/zero/special を現在のデータビットから再計算する。
fn x87_recompute_tags_from_data<B: Backend>(b: &mut B) {
    for i in 0..8u16 {
        let slot = b.konst::<W16>(i);
        let image_tag = sem::x87_read_tag(b, slot);
        let empty_tag = b.konst::<W16>(3);
        let is_empty = b.cmp::<W16>(Cmp::Eq, image_tag, empty_tag);
        let (sig, exp) = sem::read_st(b, slot);
        let value_tag = sem::x87_tag_from_value(b, sig, exp);
        let tag = b.select::<W16>(is_empty, empty_tag, value_tag);
        sem::x87_write_tag(b, slot, tag);
    }
}

/// FLDENV m14/28byte。現在の mode/osize に応じた環境形式を読み戻す。
pub fn fldenv_m<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>, mode: u8, osize: u8) -> Flow<B> {
    let Rm::Mem { a, wseg } = ea else {
        return Ok(());
    };
    x87_env_load(b, *a, *wseg, mode, osize)?;
    x87_recompute_tags_from_data(b);
    Ok(())
}

/// FNSTENV m14/28byte。環境を書き出し、全浮動小数点例外をマスクする（FCW|=0x3f）。
pub fn fnstenv_m<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>, mode: u8, osize: u8) -> Flow<B> {
    let Rm::Mem { a, wseg } = ea else {
        return Ok(());
    };
    let a = *a;
    x87_env_store(b, a, *wseg, mode, osize)?;
    let fcw: B::V<W16> = b.get(sem::fcw_ref());
    let mask = b.konst::<W16>(0x3f);
    let m = b.or::<W16>(fcw, mask);
    b.set(sem::fcw_ref(), m);
    Ok(())
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

/// FNSAVE m94/108byte。14/28 バイトの環境 + 8×10 バイトの ST を書き、
/// 書き終わると FPU を初期化する（FCW=0x037F、スタックは空）。
pub fn fnsave_m<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>, mode: u8, osize: u8) -> Flow<B> {
    let Rm::Mem { a, wseg } = ea else {
        return Ok(());
    };
    let a = *a;
    let env_size = x87_env_store(b, a, *wseg, mode, osize)?;
    // ST レジスタ: 論理順（ST(0) から）で sig(8B)+exp(2B)。
    let top = b.get(sem::top_ref());
    let seven = b.konst::<W16>(7);
    let a28 = b.konst::<W64>(env_size);
    for i in 0..8u32 {
        let ii = b.konst::<W16>(i as u16);
        let summed = b.add::<W16>(top, ii);
        let slot = b.and::<W16>(summed, seven);
        let (sig, exp) = sem::read_st(b, slot);
        let off = b.konst::<W64>(u64::from(i) * 10);
        let base = b.add::<W64>(a, a28);
        let addr = b.add::<W64>(base, off);
        decode::mem_store::<B, W64>(b, addr, *wseg, sig)?;
        let off8 = b.konst::<W64>(u64::from(i) * 10 + 8);
        let addr8 = b.add::<W64>(base, off8);
        decode::mem_store::<B, W16>(b, addr8, *wseg, exp)?;
    }
    // 初期化: FCW=0x037F、FSW/TOP=0、レジスタは空。
    let kcw = b.konst::<W16>(0x037F);
    b.set(sem::fcw_ref(), kcw);
    let z16 = b.konst::<W16>(0);
    b.set(sem::fsw_ref(), z16);
    b.set(sem::top_ref(), z16);
    let empty_tags = b.konst::<W16>(0xffff);
    b.set(sem::ftw_ref(), empty_tags);
    let z64 = b.konst::<W64>(0);
    b.set(sem::fip_ref(), z64);
    b.set(sem::fdp_ref(), z64);
    b.set(sem::fcs_ref(), z16);
    b.set(sem::fds_ref(), z16);
    b.set(sem::fop_ref(), z16);
    Ok(())
}

/// FRSTOR m94/108byte。FSAVE/FNSAVE が書いた形式から環境と ST を戻す。
/// FSW から TOP を `top` へ、C ビットを `fsw` へ反映する。
pub fn frstor_m<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>, mode: u8, osize: u8) -> Flow<B> {
    let Rm::Mem { a, wseg } = ea else {
        return Ok(());
    };
    let a = *a;
    let env_size = x87_env_load(b, a, *wseg, mode, osize)?;
    let top = b.get(sem::top_ref());
    let seven = b.konst::<W16>(7);
    let a28 = b.konst::<W64>(env_size);
    for i in 0..8u32 {
        let off = b.konst::<W64>(u64::from(i) * 10);
        let base = b.add::<W64>(a, a28);
        let addr = b.add::<W64>(base, off);
        let sig = decode::mem_load::<B, W64>(b, addr, *wseg)?;
        let off8 = b.konst::<W64>(u64::from(i) * 10 + 8);
        let addr8 = b.add::<W64>(base, off8);
        let exp = decode::mem_load::<B, W16>(b, addr8, *wseg)?;
        // 論理 ST(i) は物理スロット (top+i)&7。
        let ii = b.konst::<W16>(i as u16);
        let summed = b.add::<W16>(top, ii);
        let slot = b.and::<W16>(summed, seven);
        sem::write_st_data(b, slot, sig, exp);
        let image_tag = sem::x87_read_tag(b, slot);
        let empty_tag = b.konst::<W16>(3);
        let is_empty = b.cmp::<W16>(Cmp::Eq, image_tag, empty_tag);
        let value_tag = sem::x87_tag_from_value(b, sig, exp);
        let tag = b.select::<W16>(is_empty, empty_tag, value_tag);
        sem::x87_write_tag(b, slot, tag);
    }
    Ok(())
}

/// FBLD m80。9 バイトのパック十進 18 桁 + 符号バイトを読み、
/// 整数として拡張精度に変換して積む。符号付き 0 は -0.0 になる。
/// 数字でないニブルは値としてそのまま扱う（SDM の規定する無効動作は未対応）。
pub fn fbld_m<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>) -> Flow<B> {
    let Rm::Mem { a, wseg } = ea else {
        return Ok(());
    };
    let a = *a;
    // m80 の 10 バイトアクセスも実モードの 64K 折り返し・限界検査の
    // 対象（他のメモリ形と同じ規則。SST 80286 には m80 の境界テストが
    // ない）。
    let woff = decode::wseg_off(b, a, *wseg);
    if let (Some((seg, _)), Some((off, _))) = (*wseg, woff) {
        decode::seg_limit_chk_n(b, off, seg, 10)?;
    }
    let mut acc = b.konst::<W64>(0);
    let mut mul = b.konst::<W64>(1);
    let ten = b.konst::<W64>(10);
    let m0f = b.konst::<W8>(0x0F);
    let s4 = b.konst::<W8>(4);
    for i in 0..18u64 {
        let addr = decode::wseg_byte_addr(b, a, woff, i / 2);
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
    let addr9 = decode::wseg_byte_addr(b, a, woff, 9);
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
    let Rm::Mem { a, wseg } = ea else {
        return Ok(());
    };
    let a = *a;
    // fbld_m と同じ m80 の折り返し・限界規則。検査は書き込みに先行する。
    let woff = decode::wseg_off(b, a, *wseg);
    if let (Some((seg, _)), Some((off, _))) = (*wseg, woff) {
        decode::seg_limit_chk_n(b, off, seg, 10)?;
    }
    let top = b.get(sem::top_ref());
    let (sig, exp, fault) = sem::read_st_source(b, top);
    let commit = sem::x87_commit_after_fault(b, fault);
    // fist と同じく occ 形で例外発生を拾う。inexact は PE、
    // NaN/Inf/int64 範囲外と 18 桁に収まらない値は IE。
    let (v, inexact, bad64) = sem::f80_to_i64_occ(b, sig, exp);
    let lim = b.konst::<W64>(1_000_000_000_000_000_000);
    let nlim = b.konst::<W64>(1_000_000_000_000_000_000u64.wrapping_neg());
    let pos_big = b.cmp::<W64>(Cmp::GeS, v, lim);
    let neg_big = b.cmp::<W64>(Cmp::LeS, v, nlim);
    let width_bad = sem::bit_or(b, pos_big, neg_big);
    let invalid = sem::bit_or(b, bad64, width_bad);
    sem::x87_exception_flag(b, invalid, 1);
    sem::x87_exception_flag(b, inexact, 1 << 5);
    // denormal 入力の DE。fist と同じ判定。
    let z64 = b.konst::<W64>(0);
    let exp64 = b.zext::<W16, W64>(exp);
    let mask15 = b.konst::<W64>(0x7fff);
    let ea = b.and::<W64>(exp64, mask15);
    let exp_zero = b.cmp::<W64>(Cmp::Eq, ea, z64);
    let sig_nz = b.cmp::<W64>(Cmp::Ne, sig, z64);
    let denormal = sem::bit_and(b, exp_zero, sig_nz);
    sem::x87_exception_flag(b, denormal, 1 << 1);
    let is_indef = sem::bit_or(b, invalid, fault);
    let s15 = b.konst::<W64>(15);
    let sgn = b.shr_l::<W64>(exp64, s15);
    let one = b.konst::<W64>(1);
    let neg = b.cmp::<W64>(Cmp::Eq, sgn, one);
    let zero = z64;
    let negv = b.sub::<W64>(zero, v);
    let mag = b.select::<W64>(neg, negv, v);
    let ten = b.konst::<W64>(10);
    let s4 = b.konst::<W64>(4);
    let ff8 = b.konst::<W8>(0xFF);
    let mut m = mag;
    // unmasked invalid では store/pop を抑止する。masked なら
    // indefinite を書いて pop する（fist と同じ規則）。
    let ie_masked = sem::x87_ie_masked(b);
    let no_invalid = sem::bit_not(b, invalid);
    let write_ok = sem::bit_or(b, no_invalid, ie_masked);
    let do_write = sem::bit_and(b, commit, write_ok);
    b.if_then(do_write, |b| {
        for i in 0..9u64 {
            let addr = decode::wseg_byte_addr(b, a, woff, i);
            let d0 = b.urem::<W64>(m, ten);
            let m1 = b.udiv::<W64>(m, ten);
            let d1 = b.urem::<W64>(m1, ten);
            let m2 = b.udiv::<W64>(m1, ten);
            let d1s = b.shl::<W64>(d1, s4);
            let pair = b.or::<W64>(d0, d1s);
            let pair8: B::V<W8> = b.trunc::<W64, W8>(pair);
            let indef_digit = if i == 7 {
                b.konst::<W8>(0xC0)
            } else if i == 8 {
                b.konst::<W8>(0xFF)
            } else {
                b.konst::<W8>(0)
            };
            let byte = b.select::<W8>(is_indef, indef_digit, pair8);
            b.store::<W8>(addr, byte, sem::DATA_WRITE)?;
            m = m2;
        }
        let addr9 = decode::wseg_byte_addr(b, a, woff, 9);
        let s8 = b.konst::<W8>(0x80);
        let z8 = b.konst::<W8>(0);
        let sval = b.select::<W8>(neg, s8, z8);
        let sbyte = b.select::<W8>(is_indef, ff8, sval);
        b.store::<W8>(addr9, sbyte, sem::DATA_WRITE)?;
        sem::pop_st(b, top)
    })
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

/// HADDPD/HADDPS/HSUBPD/HSUBPS の 128 ビットレーン内演算。
/// 隣接ペアを加減算し、src1 側ペアを下位、src2 側ペアを上位に
/// 詰める（phaddsub の浮動小数点版）。
fn phaddsub_f_val<B: Backend>(
    b: &mut B,
    sub: bool,
    fbits: u32,
    a: B::V<W128>,
    c: B::V<W128>,
) -> B::V<W128> {
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
    acc
}

/// HADDPD/HADDPS/HSUBPD/HSUBPS。
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
    let acc = phaddsub_f_val(b, sub, fbits, a, c);
    b.set(sem::xmm_ref(dst), acc);
    Ok(())
}

/// VHADDPD/VHADDPS/VHSUBPD/VHSUBPS。VEX.256 も 128 ビット
/// レーンごとの独立演算なので `vbin2` で上下に展開する。
pub fn vphaddsub_f<B: Backend>(
    b: &mut B,
    sub: bool,
    fbits: u32,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    vbin2(b, d, ea, |b, a, c| phaddsub_f_val(b, sub, fbits, a, c))
}

/// ADDSUBPD/ADDSUBPS の 128 ビットレーン内演算。偶数レーンは
/// 減算、奇数レーンは加算。
fn addsub_val<B: Backend>(b: &mut B, fbits: u32, a: B::V<W128>, c: B::V<W128>) -> B::V<W128> {
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
    acc
}

/// ADDSUBPD/ADDSUBPS。
pub fn addsub<B: Backend>(
    b: &mut B,
    fbits: u32,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let c = rx(b, ea, 128)?;
    let acc = addsub_val(b, fbits, a, c);
    b.set(sem::xmm_ref(dst), acc);
    Ok(())
}

/// VADDSUBPD/VADDSUBPS。
pub fn vaddsub<B: Backend>(
    b: &mut B,
    fbits: u32,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    vbin2(b, d, ea, |b, a, c| addsub_val(b, fbits, a, c))
}

/// PBLENDVB。XMM0 の各バイトの MSB で `c` のバイトを選ぶ（0 は `a`）。
/// マスク `m` の各要素 MSB で `a`/`c` を選ぶ（PBLENDVB/BLENDVPS/PD 共通）。
/// `elt` は要素のビット幅（8/32/64）。
fn blendv_val<B: Backend>(
    b: &mut B,
    elt: u32,
    a: B::V<W128>,
    c: B::V<W128>,
    m: B::V<W128>,
) -> B::V<W128> {
    let mut acc = b.konst::<W128>(0);
    for i in 0..128u32 / elt {
        let mb = lane128(b, m, i * elt + elt - 1, 1);
        let al = lane128(b, a, i * elt, elt);
        let cl = lane128(b, c, i * elt, elt);
        let m8: B::V<W8> = b.trunc::<W128, W8>(mb);
        let sel = nez::<B, W8>(b, m8);
        let l = b.select::<W128>(sel, cl, al);
        acc = put_lane128(b, acc, l, i * elt, elt);
    }
    acc
}

/// PBLENDVB。XMM0 の各バイトの MSB で `c` のバイトを選ぶ。
pub fn pblendvb<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let c = rx(b, ea, 128)?;
    let mask: B::V<W128> = b.get(sem::xmm_ref(sem::Xmm(0)));
    let r = blendv_val(b, 8, a, c, mask);
    b.set(sem::xmm_ref(dst), r);
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
    let r = blendv_val(b, elt, a, c, mask);
    b.set(sem::xmm_ref(dst), r);
    Ok(())
}

/// DPPS/DPPD のレーン計算。imm[7:4] が掛けるレーン、imm[3:0] が結果を書くレーン。
fn dpp_val<B: Backend>(b: &mut B, fbits: u32, imm: u8, a: B::V<W128>, c: B::V<W128>) -> B::V<W128> {
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
    acc
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
    let r = dpp_val(b, fbits, imm, a, c);
    b.set(sem::xmm_ref(dst), r);
    Ok(())
}

/// ROUNDPS/ROUNDPD。全レーンを imm[1:0] の丸めモードで整数丸めする。
/// MXCSR の例外マスク・フラグ反映と imm[3] の MXCSR 参照は未対応。
fn round_rm(imm: u8) -> u8 {
    match imm & 3 {
        1 => RM_RDN,
        2 => RM_RUP,
        3 => RM_RTZ,
        _ => RM_RNE,
    }
}

/// ROUNDPS/ROUNDPD の全レーン丸め。
fn round_p_val<B: Backend>(b: &mut B, fbits: u32, rm: u8, c: B::V<W128>) -> B::V<W128> {
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
    acc
}

/// ROUNDPS/ROUNDPD。全レーンを imm[1:0] の丸めモードで整数丸めする。
pub fn round_p<B: Backend>(
    b: &mut B,
    fbits: u32,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let c = rx(b, ea, 128)?;
    let r = round_p_val(b, fbits, round_rm(imm), c);
    b.set(sem::xmm_ref(dst), r);
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
fn mpsadbw_val<B: Backend>(b: &mut B, imm: u8, a: B::V<W128>, c: B::V<W128>) -> B::V<W128> {
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
    acc
}

/// MPSADBW。a（dst 側）と c（src 側）の絶対差和を 8 本の u16 で返す。
pub fn mpsadbw<B: Backend>(
    b: &mut B,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let a: B::V<W128> = b.get(sem::xmm_ref(dst));
    let c = rx(b, ea, 128)?;
    let r = mpsadbw_val(b, imm, a, c);
    b.set(sem::xmm_ref(dst), r);
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

// ---- XCR0 / XSAVE 系 ----

/// XGETBV。EAX=XCR0[31:0]、EDX=XCR0[63:32]。ECX≠0 の #GP は
/// モデル化しない。
pub fn xgetbv<B: Backend>(b: &mut B) -> Flow<B> {
    use polyisa_sem::{ExceptionKind, GuestException};
    // ECX が 0 でなければ #GP（唯一の XCR 番号は 0）。
    let ecx = decode::grd32(b, Gpr(1));
    let z32 = b.konst::<W32>(0);
    let bad = b.cmp::<W32>(Cmp::Ne, ecx, z32);
    b.if_then(bad, |b| {
        Err(b.raise(GuestException {
            kind: ExceptionKind::Protection,
            code: 0x0D,
            addr: None,
            in_delay_slot: false,
        }))
    })?;
    let x: B::V<W64> = b.get(sem::xcr0_ref());
    let lo = b.trunc::<W64, W32>(x);
    decode::gwr32(b, Gpr(0), lo);
    let k32 = b.konst::<W64>(32);
    let hi64 = b.shr_l::<W64>(x, k32);
    let hi = b.trunc::<W64, W32>(hi64);
    decode::gwr32(b, Gpr(2), hi);
    Ok(())
}

/// XSETBV。XCR0=EDX:EAX。bit0（x87）はハードウェアで常時 1 な
/// ので OR して保持する。未対応成分、TILECFG/TILEDATA の片方だけの
/// 設定、SCALEDATA を AMX 状態なしで設定する要求は #GP。
pub fn xsetbv<B: Backend>(b: &mut B, eip: u32) -> Flow<B> {
    let lo = decode::grd32(b, Gpr(0));
    let hi = decode::grd32(b, Gpr(2));
    let lo64 = b.zext::<W32, W64>(lo);
    let hi64 = b.zext::<W32, W64>(hi);
    let k32 = b.konst::<W64>(32);
    let his = b.shl::<W64>(hi64, k32);
    let raw = b.or::<W64>(lo64, his);
    let k1 = b.konst::<W64>(1);
    let v = b.or::<W64>(raw, k1);
    let supp: B::V<W64> = b.get(sem::xcomp_supp_ref());
    let nsupp = b.not::<W64>(supp);
    let unsupported = b.and::<W64>(v, nsupp);
    let z64 = b.konst::<W64>(0);
    let bad_supp = b.cmp::<W64>(Cmp::Ne, unsupported, z64);
    let amx_mask = b.konst::<W64>(0x6_0000);
    let amx = b.and::<W64>(v, amx_mask);
    let amx_full = b.cmp::<W64>(Cmp::Eq, amx, amx_mask);
    let amx_partial = b.cmp::<W64>(Cmp::Ne, amx, z64);
    let amx_not_full = bnot(b, amx_full);
    let amx_partial = band(b, amx_partial, amx_not_full);
    let scale_mask = b.konst::<W64>(0x10_0000);
    let scale = b.and::<W64>(v, scale_mask);
    let has_scale = b.cmp::<W64>(Cmp::Ne, scale, z64);
    let amx_not_full2 = bnot(b, amx_full);
    let scale_without_amx = band(b, has_scale, amx_not_full2);
    let bad_amx = bor(b, amx_partial, scale_without_amx);
    let bad = bor(b, bad_supp, bad_amx);
    use polyisa_sem::{ExceptionKind, GuestException};
    b.if_then(bad, |b| {
        Err(b.raise(GuestException {
            kind: ExceptionKind::Protection,
            code: 13,
            addr: Some(u64::from(eip)),
            in_delay_slot: false,
        }))
    })?;
    b.set(sem::xcr0_ref(), v);
    Ok(())
}

/// `a` に定数オフセットを足したアドレス。
fn madd<B: Backend>(b: &mut B, a: B::V<W64>, off: u64) -> B::V<W64> {
    let k = b.konst::<W64>(off);
    b.add::<W64>(a, k)
}

/// `c` が真なら `v` を書き、偽なら既存値を読み戻して書き戻す
/// 条件付きストア。XSAVE が RFBM 外の成分を書かない振る舞いの
/// 近似で、偽でもアクセス自体は行われる（限界検査・ライト
/// ペーパーの副作用は残る）。
fn cstore<B: Backend, W: decode::Hw>(
    b: &mut B,
    a: B::V<W64>,
    wseg: Option<(u64, B::V<W64>)>,
    v: B::V<W>,
    c: B::B,
) -> Result<(), B::Exit> {
    let old: B::V<W> = decode::mem_load(b, a, wseg)?;
    let nv = b.select::<W>(c, v, old);
    decode::mem_store::<B, W>(b, a, wseg, nv)
}

/// FXSAVE/XSAVE 共通の先行 512 バイトを書く。`w87`/`wsse` が
/// 偽の成分は `cstore` 経由で既存値を書き戻す（XSAVE の
/// RFBM ∩ XCR0 反映）。
/// レイアウト: FCW(0)+FSW|TOP(2)+FTW(4)+FOP(6)+FIP(8)+FDP(16)
/// +MXCSR(24)+MASK(28)+ST0-7(32-,16B毎: sig@0,exp@8)
/// +XMM(160-,16B毎。m64 は XMM8-15 が +288 以降)。
/// 64 バイト境界整列の #GP はモデル化しない。
/// 公開の理由: Linux のシグナルフレームの fpstate もこの
/// 配置なので、os-linux が `wseg=None` で呼び直す。
pub fn fxsave_area<B: Backend>(
    b: &mut B,
    a: B::V<W64>,
    wseg: Option<(u64, B::V<W64>)>,
    mode: u8,
    w87: B::B,
    wsse: B::B,
) -> Flow<B> {
    let fcw: B::V<W16> = b.get(sem::fcw_ref());
    cstore::<B, W16>(b, a, wseg, fcw, w87)?;
    let a2 = madd(b, a, 2);
    let fsw: B::V<W16> = b.get(sem::fsw_ref());
    let top: B::V<W16> = b.get(sem::top_ref());
    let k7 = b.konst::<W16>(7);
    let t3 = b.and::<W16>(top, k7);
    let k11 = b.konst::<W16>(11);
    let tbits = b.shl::<W16>(t3, k11);
    let fswv = b.or::<W16>(fsw, tbits);
    cstore::<B, W16>(b, a2, wseg, fswv, w87)?;
    // FTW（簡約形、1 ビット/物理スロット）: empty だけが 0。
    let ftw_full: B::V<W16> = b.get(sem::ftw_ref());
    let mut ftw = b.konst::<W8>(0);
    for i in 0..8u16 {
        let sh = b.konst::<W16>(i * 2);
        let shifted = b.shr_l::<W16>(ftw_full, sh);
        let three16 = b.konst::<W16>(3);
        let tag = b.and::<W16>(shifted, three16);
        let empty = b.cmp::<W16>(Cmp::Eq, tag, three16);
        let non = sem::bit_not(b, empty);
        let bit = b.konst::<W8>(1u8 << i);
        let z8 = b.konst::<W8>(0);
        let sel = b.select::<W8>(non, bit, z8);
        ftw = b.or::<W8>(ftw, sel);
    }
    let a4 = madd(b, a, 4);
    let ftw16 = b.zext::<W8, W16>(ftw);
    cstore::<B, W16>(b, a4, wseg, ftw16, w87)?;
    let a6 = madd(b, a, 6);
    let fop: B::V<W16> = b.get(sem::fop_ref());
    cstore::<B, W16>(b, a6, wseg, fop, w87)?;
    let a8 = madd(b, a, 8);
    let fip: B::V<W64> = b.get(sem::fip_ref());
    let a16 = madd(b, a, 16);
    let fdp: B::V<W64> = b.get(sem::fdp_ref());
    if mode == 64 {
        cstore::<B, W64>(b, a8, wseg, fip, w87)?;
        cstore::<B, W64>(b, a16, wseg, fdp, w87)?;
    } else {
        let fip32: B::V<W32> = b.trunc::<W64, W32>(fip);
        cstore::<B, W32>(b, a8, wseg, fip32, w87)?;
        let a12 = madd(b, a, 12);
        let fcs: B::V<W16> = b.get(sem::fcs_ref());
        let fcs32 = b.zext::<W16, W32>(fcs);
        cstore::<B, W32>(b, a12, wseg, fcs32, w87)?;
        let fdp32: B::V<W32> = b.trunc::<W64, W32>(fdp);
        cstore::<B, W32>(b, a16, wseg, fdp32, w87)?;
        let a20 = madd(b, a, 20);
        let fds: B::V<W16> = b.get(sem::fds_ref());
        let fds32 = b.zext::<W16, W32>(fds);
        cstore::<B, W32>(b, a20, wseg, fds32, w87)?;
    }
    let mx: B::V<W32> = b.get(sem::mxcsr_ref());
    let a24 = madd(b, a, 24);
    cstore::<B, W32>(b, a24, wseg, mx, wsse)?;
    let a28 = madd(b, a, 28);
    let mm = b.konst::<W32>(0xFFBF);
    cstore::<B, W32>(b, a28, wseg, mm, wsse)?;
    // ST0-7 のデータ領域は論理順（ST(0) から）。簡約 FTW のビット順だけが物理順。
    for i in 0..8u64 {
        let ii = b.konst::<W16>(i as u16);
        let summed = b.add::<W16>(top, ii);
        let slot = b.and::<W16>(summed, k7);
        let (sig, exp) = sem::read_st(b, slot);
        let asig = madd(b, a, 32 + 16 * i);
        cstore::<B, W64>(b, asig, wseg, sig, w87)?;
        let aexp = madd(b, a, 40 + 16 * i);
        cstore::<B, W16>(b, aexp, wseg, exp, w87)?;
    }
    // XMM のストアは 128 ビット幅なので `cstore`（Hw 制約）では
    // なく読み戻し+生ストアで実装する。XMM の map 経路メモリ
    // アクセスは既存と同じく wseg の限界検査を行わない。
    let nx = if mode == 64 { 16u64 } else { 8 };
    for i in 0..nx {
        let xv: B::V<W128> = b.get(sem::xmm_ref(Xmm(i as u8)));
        let ax = madd(b, a, 160 + 16 * i);
        let old: B::V<W128> = b.load::<W128>(ax, sem::DATA_READ)?;
        let nv = b.select::<W128>(wsse, xv, old);
        b.store::<W128>(ax, nv, sem::DATA_WRITE)?;
    }
    Ok(())
}

/// FXRSTOR/XRSTOR 共通の先行 512 バイトからの復元。成分ごとに
/// 「領域の値で復元 (`r*`)」「初期値に戻す (`i*`)」を選び、
/// 両方偽なら現状を保つ（XRSTOR の RFBM 外成分）。
/// `cstore` と同様の近似で、RFBM 外の成分も値は読み込む
/// （読み出し側の副作用は残るが状態には反映しない）。
/// 公開の理由: rt_sigreturn が fpstate（同じ配置）から
/// 復元するとき os-linux 側から呼ぶ。
pub fn fxrstor_area<B: Backend>(
    b: &mut B,
    a: B::V<W64>,
    wseg: Option<(u64, B::V<W64>)>,
    mode: u8,
    rst: B::V<W64>,
    ini: B::V<W64>,
) -> Flow<B> {
    let r87 = mask_bit(b, rst, 0);
    let rsse = mask_bit(b, rst, 1);
    let i87 = mask_bit(b, ini, 0);
    let isse = mask_bit(b, ini, 1);
    let fcw_m: B::V<W16> = decode::mem_load(b, a, wseg)?;
    let fcw_i = b.konst::<W16>(0x037F);
    let fcw_c = b.get(sem::fcw_ref());
    let t1 = b.select::<W16>(i87, fcw_i, fcw_c);
    let fcw_n = b.select::<W16>(r87, fcw_m, t1);
    b.set(sem::fcw_ref(), fcw_n);
    // FSW の bit11-13 は TOP。復元値から取り出して別フィールドへ。
    let a2 = madd(b, a, 2);
    let fsw_m: B::V<W16> = decode::mem_load(b, a2, wseg)?;
    let k7 = b.konst::<W16>(7);
    let k11 = b.konst::<W16>(11);
    let fsw_sh = b.shr_l::<W16>(fsw_m, k11);
    let top_m = b.and::<W16>(fsw_sh, k7);
    let top_c = b.get(sem::top_ref());
    let top_i = b.konst::<W16>(0);
    let t2 = b.select::<W16>(i87, top_i, top_c);
    let top_n = b.select::<W16>(r87, top_m, t2);
    b.set(sem::top_ref(), top_n);
    let fsw_c = b.get(sem::fsw_ref());
    let ktop = b.konst::<W16>(0xC7FF);
    let fsw_keep = b.and::<W16>(fsw_m, ktop);
    let fsw_i = b.konst::<W16>(0);
    let t3 = b.select::<W16>(i87, fsw_i, fsw_c);
    let fsw_n = b.select::<W16>(r87, fsw_keep, t3);
    b.set(sem::fsw_ref(), fsw_n);
    let a6 = madd(b, a, 6);
    let fop_m: B::V<W16> = decode::mem_load(b, a6, wseg)?;
    let fop_i = b.konst::<W16>(0);
    let fop_c = b.get(sem::fop_ref());
    let tfop = b.select::<W16>(i87, fop_i, fop_c);
    let fop_n = b.select::<W16>(r87, fop_m, tfop);
    b.set(sem::fop_ref(), fop_n);
    let a8 = madd(b, a, 8);
    let a16 = madd(b, a, 16);
    let z64i = b.konst::<W64>(0);
    let z64j = b.konst::<W64>(0);
    let z16i = b.konst::<W16>(0);
    if mode == 64 {
        let fip_m: B::V<W64> = decode::mem_load(b, a8, wseg)?;
        let fip_c = b.get(sem::fip_ref());
        let tfip = b.select::<W64>(i87, z64i, fip_c);
        let fip_n = b.select::<W64>(r87, fip_m, tfip);
        b.set(sem::fip_ref(), fip_n);
        let fdp_m: B::V<W64> = decode::mem_load(b, a16, wseg)?;
        let fdp_c = b.get(sem::fdp_ref());
        let tfdp = b.select::<W64>(i87, z64j, fdp_c);
        let fdp_n = b.select::<W64>(r87, fdp_m, tfdp);
        b.set(sem::fdp_ref(), fdp_n);
    } else {
        let fip32: B::V<W32> = decode::mem_load(b, a8, wseg)?;
        let fip_m = b.zext::<W32, W64>(fip32);
        let fip_c = b.get(sem::fip_ref());
        let tfip = b.select::<W64>(i87, z64i, fip_c);
        let fip_n = b.select::<W64>(r87, fip_m, tfip);
        b.set(sem::fip_ref(), fip_n);
        let a12 = madd(b, a, 12);
        let fcs32: B::V<W32> = decode::mem_load(b, a12, wseg)?;
        let fcs_m = b.trunc::<W32, W16>(fcs32);
        let fcs_c = b.get(sem::fcs_ref());
        let tfcs = b.select::<W16>(i87, z16i, fcs_c);
        let fcs_n = b.select::<W16>(r87, fcs_m, tfcs);
        b.set(sem::fcs_ref(), fcs_n);
        let fdp32: B::V<W32> = decode::mem_load(b, a16, wseg)?;
        let fdp_m = b.zext::<W32, W64>(fdp32);
        let fdp_c = b.get(sem::fdp_ref());
        let tfdp = b.select::<W64>(i87, z64j, fdp_c);
        let fdp_n = b.select::<W64>(r87, fdp_m, tfdp);
        b.set(sem::fdp_ref(), fdp_n);
        let a20 = madd(b, a, 20);
        let fds32: B::V<W32> = decode::mem_load(b, a20, wseg)?;
        let fds_m = b.trunc::<W32, W16>(fds32);
        let fds_c = b.get(sem::fds_ref());
        let tfds = b.select::<W16>(i87, z16i, fds_c);
        let fds_n = b.select::<W16>(r87, fds_m, tfds);
        b.set(sem::fds_ref(), fds_n);
    }
    let a4 = madd(b, a, 4);
    let ftw_m8: B::V<W8> = decode::mem_load(b, a4, wseg)?;
    let ftw_m = b.zext::<W8, W16>(ftw_m8);
    for i in 0..8u16 {
        let asig = madd(b, a, 32 + 16 * u64::from(i));
        let sig_m: B::V<W64> = decode::mem_load(b, asig, wseg)?;
        let aexp = madd(b, a, 40 + 16 * u64::from(i));
        let exp_m: B::V<W16> = decode::mem_load(b, aexp, wseg)?;
        // メモリ上の論理 ST(i) は、復元後 TOP を使って物理スロット
        // (TOP+i)&7 へ戻る。
        let ii = b.konst::<W16>(i);
        let summed = b.add::<W16>(top_n, ii);
        let phys = b.and::<W16>(summed, k7);
        let (s_c, e_c) = sem::read_st(b, phys);
        let z64 = b.konst::<W64>(0);
        let z16 = b.konst::<W16>(0);
        let s_t = b.select::<W64>(i87, z64, s_c);
        let e_t = b.select::<W16>(i87, z16, e_c);
        let s_n = b.select::<W64>(r87, sig_m, s_t);
        let e_n = b.select::<W16>(r87, exp_m, e_t);
        sem::write_st_data(b, phys, s_n, e_n);
        // 簡約 FTW は物理ビット順。0 なら empty、1 なら値から full tag を再計算する。
        let ftw_sh = b.shr_l::<W16>(ftw_m, phys);
        let one16 = b.konst::<W16>(1);
        let nonbit = b.and::<W16>(ftw_sh, one16);
        let z16b = b.konst::<W16>(0);
        let nonempty = b.cmp::<W16>(Cmp::Ne, nonbit, z16b);
        let empty_tag = b.konst::<W16>(3);
        let value_tag = sem::x87_tag_from_value(b, s_n, e_n);
        let mem_tag = b.select::<W16>(nonempty, value_tag, empty_tag);
        let old_tag = sem::x87_read_tag(b, phys);
        let init_tag = b.select::<W16>(i87, empty_tag, old_tag);
        let tag_n = b.select::<W16>(r87, mem_tag, init_tag);
        sem::x87_write_tag(b, phys, tag_n);
    }
    let a24 = madd(b, a, 24);
    let mx_m: B::V<W32> = decode::mem_load(b, a24, wseg)?;
    let mx_i = b.konst::<W32>(0x1F80);
    let mx_c = b.get(sem::mxcsr_ref());
    let t4 = b.select::<W32>(isse, mx_i, mx_c);
    let mx_n = b.select::<W32>(rsse, mx_m, t4);
    b.set(sem::mxcsr_ref(), mx_n);
    let nx = if mode == 64 { 16 } else { 8 };
    for i in 0..nx {
        let ax = madd(b, a, 160 + 16 * i as u64);
        let x_m: B::V<W128> = b.load::<W128>(ax, sem::DATA_READ)?;
        let x_c = b.get(sem::xmm_ref(Xmm(i as u8)));
        let z128 = b.konst::<W128>(0);
        let t5 = b.select::<W128>(isse, z128, x_c);
        let x_n = b.select::<W128>(rsse, x_m, t5);
        b.set(sem::xmm_ref(Xmm(i as u8)), x_n);
    }
    Ok(())
}

/// XSAVE 系の成分マスク。RFBM（EDX:EAX）∩ XCR0。
fn xsave_mask<B: Backend>(b: &mut B) -> B::V<W64> {
    let lo = decode::grd32(b, Gpr(0));
    let hi = decode::grd32(b, Gpr(2));
    let lo64 = b.zext::<W32, W64>(lo);
    let hi64 = b.zext::<W32, W64>(hi);
    let k32 = b.konst::<W64>(32);
    let his = b.shl::<W64>(hi64, k32);
    let rfbm = b.or::<W64>(lo64, his);
    let x0 = b.get(sem::xcr0_ref());
    b.and::<W64>(rfbm, x0)
}

/// マスク `m` の `bit` が立っていれば真。
fn mask_bit<B: Backend>(b: &mut B, m: B::V<W64>, bit: u64) -> B::B {
    let k = b.konst::<W64>(1u64 << bit);
    let v = b.and::<W64>(m, k);
    let z = b.konst::<W64>(0);
    b.cmp::<W64>(Cmp::Ne, v, z)
}

/// 定数真偽値。
fn bool_k<B: Backend>(b: &mut B, v: bool) -> B::B {
    let z = b.konst::<W8>(0);
    let op = if v { Cmp::Eq } else { Cmp::Ne };
    b.cmp::<W8>(op, z, z)
}

/// FXSAVE。512 バイトの x87+SSE イメージを書く。
pub fn fxsave<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>, mode: u8) -> Flow<B> {
    let Rm::Mem { a, wseg } = ea else {
        return Ok(());
    };
    let a = *a;
    let wseg = *wseg;
    let t = bool_k::<B>(b, true);
    fxsave_area(b, a, wseg, mode, t, t)
}

/// FXRSTOR。512 バイトの x87+SSE イメージで全成分を復元する。
/// 初期化は起きない。
pub fn fxrstor<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>, mode: u8) -> Flow<B> {
    let Rm::Mem { a, wseg } = ea else {
        return Ok(());
    };
    let a = *a;
    let wseg = *wseg;
    let rst = b.konst::<W64>(3);
    let ini = b.konst::<W64>(0);
    fxrstor_area(b, a, wseg, mode, rst, ini)
}

/// XSAVE 領域への 128 ビット store。`wseg` 経路が W128 を
/// 持たないので、既存の YMMH と同じく 2 本の W64 に分解する。
fn xsave_store128<B: Backend>(
    b: &mut B,
    a: B::V<W64>,
    wseg: Option<(u64, B::V<W64>)>,
    v: B::V<W128>,
) -> Result<(), B::Exit> {
    let lo: B::V<W64> = b.trunc::<W128, W64>(v);
    let sh = b.konst::<W128>(64);
    let vs = b.shr_l::<W128>(v, sh);
    let hi: B::V<W64> = b.trunc::<W128, W64>(vs);
    decode::mem_store::<B, W64>(b, a, wseg, lo)?;
    let ah = madd(b, a, 8);
    decode::mem_store::<B, W64>(b, ah, wseg, hi)
}

/// `xsave_store128` と対になる 128 ビット load。
fn xsave_load128<B: Backend>(
    b: &mut B,
    a: B::V<W64>,
    wseg: Option<(u64, B::V<W64>)>,
) -> Result<B::V<W128>, B::Exit> {
    let lo: B::V<W64> = decode::mem_load(b, a, wseg)?;
    let ah = madd(b, a, 8);
    let hi: B::V<W64> = decode::mem_load(b, ah, wseg)?;
    let sh = b.konst::<W128>(64);
    let hiz = b.zext::<W64, W128>(hi);
    let hi128 = b.shl::<W128>(hiz, sh);
    let loz = b.zext::<W64, W128>(lo);
    Ok(b.or::<W128>(loz, hi128))
}

/// XSAVE/XSAVEOPT。先行 512 バイトは RFBM ∩ XCR0 の成分だけ
/// 書き、+512 の XSTATE_BV では RFBM 内のビットを立て、RFBM 外の
/// 既存ビットを残す。XINUSE は全成分使用中と近似する。
/// XSAVEOPT の省略最適化と監査値はモデル化しない。XSAVEC の
/// 圧縮レイアウトはインタプリタ層の具体値実行で扱う。
pub fn xsave<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>, mode: u8) -> Flow<B> {
    let Rm::Mem { a, wseg } = ea else {
        return Ok(());
    };
    xsave_align_chk(b, *a)?;
    let m = xsave_mask(b);
    xsave_area_mask(b, *a, *wseg, mode, m)
}

/// XSAVE/XRSTOR/FXSAVE 系の 64 バイト整列検査。違反は #GP。
pub fn xsave_align_chk<B: Backend>(b: &mut B, a: B::V<W64>) -> Flow<B> {
    use polyisa_sem::{ExceptionKind, GuestException};
    let m63 = b.konst::<W64>(63);
    let low = b.and::<W64>(a, m63);
    let z64 = b.konst::<W64>(0);
    let bad = b.cmp::<W64>(Cmp::Ne, low, z64);
    b.if_then(bad, |b| {
        Err(b.raise(GuestException {
            kind: ExceptionKind::Protection,
            code: 0x0D,
            addr: None,
            in_delay_slot: false,
        }))
    })
}

/// XSAVE の標準レイアウトを、明示した成分マスクで書く。
/// Linux のシグナルフレームはゲストレジスタ EDX:EAX を経由せず、
/// OS が許可した user xfeatures を使うため公開する。
pub fn xsave_area_mask<B: Backend>(
    b: &mut B,
    a: B::V<W64>,
    wseg: Option<(u64, B::V<W64>)>,
    mode: u8,
    m: B::V<W64>,
) -> Flow<B> {
    let w87 = mask_bit(b, m, 0);
    let wsse = mask_bit(b, m, 1);
    let wymm = mask_bit(b, m, 2);
    fxsave_area(b, a, wseg, mode, w87, wsse)?;
    // XSTATE_BV だけを更新し、RFBM 外のビットは既存値から残す。
    // XCOMP_BV と予約域は XSAVE が書き換えない。
    let a512 = madd(b, a, 512);
    let old_xbv: B::V<W64> = decode::mem_load(b, a512, wseg)?;
    let nm = b.not::<W64>(m);
    let keep = b.and::<W64>(old_xbv, nm);
    let xbv = b.or::<W64>(keep, m);
    decode::mem_store::<B, W64>(b, a512, wseg, xbv)?;
    // YMMH 成分（+576、YMM0-15 の上位 128 ビット）。W128 の
    // メモリアクセスは wseg 経路がないので 2 本の W64 に分解する。
    // 成分が RFBM∩XCR0 から外れるモデルでは領域外を触らないよう
    // 条件領域にする（AVX 非対応モデルの回帰防止）。
    b.if_then(wymm, |b| {
        for i in 0..16u8 {
            let v: B::V<W128> = b.get(sem::ymm_hi_ref(Xmm(i)));
            let ah = madd(b, a, 576 + u64::from(i) * 16);
            xsave_store128(b, ah, wseg, v)?;
        }
        Ok(())
    })?;
    // AVX-512 の標準レイアウト。MPX/APX 領域を避けた実機どおりの
    // 固定オフセットを使う。opmask=0x440、ZMM_Hi256=0x480、
    // Hi16_ZMM=0x680。
    let wopmask = mask_bit(b, m, 5);
    b.if_then(wopmask, |b| {
        for i in 0..8u8 {
            let v: B::V<W64> = b.get(sem::kref(i));
            let ah = madd(b, a, 0x440 + u64::from(i) * 8);
            decode::mem_store::<B, W64>(b, ah, wseg, v)?;
        }
        Ok(())
    })?;
    let wzmmhi = mask_bit(b, m, 6);
    b.if_then(wzmmhi, |b| {
        for r in 0..16u8 {
            for part in 2..4usize {
                let v: B::V<W128> = b.get(sem::zreg_ref(r, part));
                let ah = madd(b, a, 0x480 + u64::from(r) * 32 + (part as u64 - 2) * 16);
                xsave_store128(b, ah, wseg, v)?;
            }
        }
        Ok(())
    })?;
    let whi16 = mask_bit(b, m, 7);
    b.if_then(whi16, |b| {
        for r in 16..32u8 {
            for part in 0..4usize {
                let v: B::V<W128> = b.get(sem::zreg_ref(r, part));
                let ah = madd(b, a, 0x680 + u64::from(r - 16) * 64 + part as u64 * 16);
                xsave_store128(b, ah, wseg, v)?;
            }
        }
        Ok(())
    })?;
    // APX EGPR 成分（0x3c0、r16-r31）。MPX が使っていた
    // 128 バイトを再利用する。
    let wapx = mask_bit(b, m, 19);
    b.if_then(wapx, |b| {
        for i in 0..16u8 {
            let v: B::V<W64> = b.get(sem::x_ref(Gpr(16 + i)));
            let ah = madd(b, a, 0x3c0 + u64::from(i) * 8);
            decode::mem_store::<B, W64>(b, ah, wseg, v)?;
        }
        Ok(())
    })?;
    // PKRU 成分（bit9、0xA80、8 バイト）。0x680 から始まる
    // Hi16_ZMM の終端 0xa80 直後の空きを使う。
    let wpkru = mask_bit(b, m, 9);
    b.if_then(wpkru, |b| {
        let v: B::V<W64> = b.get(sem::pkru_ref());
        let ah = madd(b, a, 0xa80);
        decode::mem_store::<B, W64>(b, ah, wseg, v)?;
        Ok(())
    })?;
    // AMX。実機の標準レイアウトでは XTILECFG=0xac0（64
    // バイト）、XTILEDATA=0xb00（8192 バイト）。この配置は
    // CPUID leaf D の成分情報と対にする。
    let wtilecfg = mask_bit(b, m, 17);
    b.if_then(wtilecfg, |b| {
        for i in 0..8usize {
            let v: B::V<W64> = b.get(sem::tilecfg_qref(i));
            let ah = madd(b, a, 0xac0 + i as u64 * 8);
            decode::mem_store::<B, W64>(b, ah, wseg, v)?;
        }
        Ok(())
    })?;
    let wtiledata = mask_bit(b, m, 18);
    b.if_then(wtiledata, |b| {
        for i in 0..1024usize {
            let v: B::V<W64> = b.get(sem::tmm_qref(i));
            let ah = madd(b, a, 0xb00 + i as u64 * 8);
            decode::mem_store::<B, W64>(b, ah, wseg, v)?;
        }
        Ok(())
    })?;
    // ACE SCALEDATA（0x2b00、128 バイト）。
    let wscale = mask_bit(b, m, 20);
    b.if_then(wscale, |b| {
        for i in 0..16usize {
            let v: B::V<W64> = b.get(sem::scaledata_qref(i));
            let ah = madd(b, a, 0x2b00 + i as u64 * 8);
            decode::mem_store::<B, W64>(b, ah, wseg, v)?;
        }
        Ok(())
    })
}

/// XSAVE 成分のうち `m` に含まれるものを初期値へ戻す。
/// Linux の sigreturn がフレームにない user xfeature を初期化するために使う。
pub fn xrstor_init_mask<B: Backend>(b: &mut B, m: B::V<W64>) -> Flow<B> {
    let i87 = mask_bit(b, m, 0);
    b.if_then(i87, |b| {
        let cw = b.konst::<W16>(0x037F);
        b.set(sem::fcw_ref(), cw);
        let z16 = b.konst::<W16>(0);
        b.set(sem::fsw_ref(), z16);
        b.set(sem::top_ref(), z16);
        let empty = b.konst::<W16>(0xffff);
        b.set(sem::ftw_ref(), empty);
        let z64 = b.konst::<W64>(0);
        b.set(sem::fip_ref(), z64);
        b.set(sem::fdp_ref(), z64);
        b.set(sem::fcs_ref(), z16);
        b.set(sem::fds_ref(), z16);
        b.set(sem::fop_ref(), z16);
        for i in 0..8usize {
            b.set(sem::st_sig_ref(i), z64);
            b.set(sem::st_exp_ref(i), z16);
        }
        Ok(())
    })?;
    let isse = mask_bit(b, m, 1);
    b.if_then(isse, |b| {
        let mx = b.konst::<W32>(0x1F80);
        b.set(sem::mxcsr_ref(), mx);
        let z: B::V<W128> = b.konst::<W128>(0);
        for i in 0..16u8 {
            b.set(sem::xmm_ref(Xmm(i)), z);
        }
        Ok(())
    })?;
    let iymm = mask_bit(b, m, 2);
    b.if_then(iymm, |b| {
        let z: B::V<W128> = b.konst::<W128>(0);
        for i in 0..16u8 {
            b.set(sem::ymm_hi_ref(Xmm(i)), z);
        }
        Ok(())
    })?;
    let iopm = mask_bit(b, m, 5);
    b.if_then(iopm, |b| {
        let z = b.konst::<W64>(0);
        for i in 0..8u8 {
            b.set(sem::kref(i), z);
        }
        Ok(())
    })?;
    for (bit, parts, first, last) in [(6u64, 2..4usize, 0u8, 16u8), (7, 0..4usize, 16, 32)] {
        let iz = mask_bit(b, m, bit);
        b.if_then(iz, |b| {
            let z: B::V<W128> = b.konst::<W128>(0);
            for r in first..last {
                for part in parts.clone() {
                    b.set(sem::zreg_ref(r, part), z);
                }
            }
            Ok(())
        })?;
    }
    let itcfg = mask_bit(b, m, 17);
    b.if_then(itcfg, |b| {
        let z = b.konst::<W64>(0);
        for i in 0..8usize {
            b.set(sem::tilecfg_qref(i), z);
        }
        Ok(())
    })?;
    let itdata = mask_bit(b, m, 18);
    b.if_then(itdata, |b| {
        let z = b.konst::<W64>(0);
        for i in 0..1024usize {
            b.set(sem::tmm_qref(i), z);
        }
        Ok(())
    })?;
    let iscale = mask_bit(b, m, 20);
    b.if_then(iscale, |b| {
        let v = b.konst::<W64>(0x7f7f_7f7f_7f7f_7f7f);
        for i in 0..16usize {
            b.set(sem::scaledata_qref(i), v);
        }
        Ok(())
    })?;
    let iapx = mask_bit(b, m, 19);
    b.if_then(iapx, |b| {
        let z = b.konst::<W64>(0);
        for i in 0..16u8 {
            b.set(sem::x_ref(Gpr(16 + i)), z);
        }
        Ok(())
    })
}

/// XRSTOR。成分 i∈RFBM∩XCR0 は領域の XSTATE_BV ビットが立てば
/// 復元、立たなければ初期値に戻す。RFBM 外の成分は手付かず。
/// MXCSR 予約ビット・XSTATE_BV 不整合の #GP はモデル化しない。
pub fn xrstor<B: Backend>(b: &mut B, ea: &Rm<B::V<W64>>, mode: u8) -> Flow<B> {
    let Rm::Mem { a, wseg } = ea else {
        return Ok(());
    };
    xsave_align_chk(b, *a)?;
    let m = xsave_mask(b);
    xrstor_area_mask(b, *a, *wseg, mode, m)
}

/// XRSTOR の標準レイアウトを、明示した成分マスクで読む。
/// Linux の rt_sigreturn はゲストレジスタ EDX:EAX を経由せず、
/// sigframe の user xfeatures と OS 許可成分の交差を使う。
pub fn xrstor_area_mask<B: Backend>(
    b: &mut B,
    a: B::V<W64>,
    wseg: Option<(u64, B::V<W64>)>,
    mode: u8,
    m: B::V<W64>,
) -> Flow<B> {
    let a512 = madd(b, a, 512);
    let xbv: B::V<W64> = decode::mem_load(b, a512, wseg)?;
    let rst = b.and::<W64>(m, xbv);
    let nxbv = b.not::<W64>(xbv);
    let ini = b.and::<W64>(m, nxbv);
    fxrstor_area(b, a, wseg, mode, rst, ini)?;
    // 標準形式の XRSTOR では、RFBM[1] と RFBM[2] のどちらかが
    // 立っていれば XSTATE_BV[1] の有無に関係なく MXCSR を legacy
    // 領域から読む。XMM の初期化は fxrstor_area 側の規則のまま。
    let sse_or_avx = b.konst::<W64>(0x6);
    let mxreq = b.and::<W64>(m, sse_or_avx);
    let z64mx = b.konst::<W64>(0);
    let load_mx = b.cmp::<W64>(Cmp::Ne, mxreq, z64mx);
    b.if_then(load_mx, |b| {
        let a24 = madd(b, a, 24);
        let mx: B::V<W32> = decode::mem_load(b, a24, wseg)?;
        b.set(sem::mxcsr_ref(), mx);
        Ok(())
    })?;
    // YMMH 成分（+576）。`rst` が立つときだけ領域を読み、`ini`
    // なら読まずに 0 を書く。両方偽なら領域も状態も触らない
    // （xsave 側と同じ回帰防止）。`rst`/`ini` は排他。
    let rymm = mask_bit(b, rst, 2);
    let iymm = mask_bit(b, ini, 2);
    b.if_then(rymm, |b| {
        for i in 0..16u8 {
            let ah = madd(b, a, 576 + u64::from(i) * 16);
            let ah8 = madd(b, ah, 8);
            let lo: B::V<W64> = decode::mem_load(b, ah, wseg)?;
            let hi: B::V<W64> = decode::mem_load(b, ah8, wseg)?;
            let sh = b.konst::<W128>(64);
            let hiz = b.zext::<W64, W128>(hi);
            let hi128 = b.shl::<W128>(hiz, sh);
            let loz = b.zext::<W64, W128>(lo);
            let vm = b.or::<W128>(loz, hi128);
            b.set(sem::ymm_hi_ref(Xmm(i)), vm);
        }
        Ok(())
    })?;
    b.if_then(iymm, |b| {
        let z: B::V<W128> = b.konst::<W128>(0);
        for i in 0..16u8 {
            b.set(sem::ymm_hi_ref(Xmm(i)), z);
        }
        Ok(())
    })?;
    // AVX-512 成分。bit が XSTATE_BV にあれば領域から復元し、
    // なければ RFBM∩XCR0 の成分は初期値（0）に戻す。
    for (bit, off, parts, first, last) in [
        (6u64, 0x480u64, 2..4usize, 0u8, 16u8),
        (7, 0x680, 0..4usize, 16, 32),
    ] {
        let rstz = mask_bit(b, rst, bit);
        b.if_then(rstz, |b| {
            for r in first..last {
                for part in parts.clone() {
                    let stride = if bit == 6 { 32 } else { 64 };
                    let row = if bit == 6 {
                        u64::from(r)
                    } else {
                        u64::from(r - 16)
                    };
                    let poff = if bit == 6 {
                        part as u64 - 2
                    } else {
                        part as u64
                    };
                    let ah = madd(b, a, off + row * stride + poff * 16);
                    let v = xsave_load128(b, ah, wseg)?;
                    b.set(sem::zreg_ref(r, part), v);
                }
            }
            Ok(())
        })?;
        let iniz = mask_bit(b, ini, bit);
        b.if_then(iniz, |b| {
            let z: B::V<W128> = b.konst::<W128>(0);
            for r in first..last {
                for part in parts.clone() {
                    b.set(sem::zreg_ref(r, part), z);
                }
            }
            Ok(())
        })?;
    }
    // APX EGPR。bit19 が XSTATE_BV にあれば復元し、なければ
    // RFBM∩XCR0 の成分は 0 に戻す。
    let rapx = mask_bit(b, rst, 19);
    b.if_then(rapx, |b| {
        for i in 0..16u8 {
            let ah = madd(b, a, 0x3c0 + u64::from(i) * 8);
            let v: B::V<W64> = decode::mem_load(b, ah, wseg)?;
            b.set(sem::x_ref(Gpr(16 + i)), v);
        }
        Ok(())
    })?;
    let iapx = mask_bit(b, ini, 19);
    b.if_then(iapx, |b| {
        let z = b.konst::<W64>(0);
        for i in 0..16u8 {
            b.set(sem::x_ref(Gpr(16 + i)), z);
        }
        Ok(())
    })?;
    // PKRU。bit9 が XSTATE_BV にあれば 0xa80 から復元し、
    // なければ RFBM∩XCR0 の成分は初期値 0 に戻す。
    let rpkru = mask_bit(b, rst, 9);
    b.if_then(rpkru, |b| {
        let ah = madd(b, a, 0xa80);
        let v: B::V<W64> = decode::mem_load(b, ah, wseg)?;
        b.set(sem::pkru_ref(), v);
        Ok(())
    })?;
    let ipkru = mask_bit(b, ini, 9);
    b.if_then(ipkru, |b| {
        let z = b.konst::<W64>(0);
        b.set(sem::pkru_ref(), z);
        Ok(())
    })?;
    // AMX。XTILECFG と XTILEDATA は独立した成分として扱うが、
    // 実機では XCR0[18:17] は常に同時に立つ。
    let rtcfg = mask_bit(b, rst, 17);
    b.if_then(rtcfg, |b| {
        for i in 0..8usize {
            let ah = madd(b, a, 0xac0 + i as u64 * 8);
            let v: B::V<W64> = decode::mem_load(b, ah, wseg)?;
            b.set(sem::tilecfg_qref(i), v);
        }
        Ok(())
    })?;
    let itcfg = mask_bit(b, ini, 17);
    b.if_then(itcfg, |b| {
        let z = b.konst::<W64>(0);
        for i in 0..8usize {
            b.set(sem::tilecfg_qref(i), z);
        }
        Ok(())
    })?;
    let rtdata = mask_bit(b, rst, 18);
    b.if_then(rtdata, |b| {
        for i in 0..1024usize {
            let ah = madd(b, a, 0xb00 + i as u64 * 8);
            let v: B::V<W64> = decode::mem_load(b, ah, wseg)?;
            b.set(sem::tmm_qref(i), v);
        }
        Ok(())
    })?;
    let itdata = mask_bit(b, ini, 18);
    b.if_then(itdata, |b| {
        let z = b.konst::<W64>(0);
        for i in 0..1024usize {
            b.set(sem::tmm_qref(i), z);
        }
        Ok(())
    })?;
    // ACE SCALEDATA。初期値は 0 ではなく全バイト 0x7f。
    let rscale = mask_bit(b, rst, 20);
    b.if_then(rscale, |b| {
        for i in 0..16usize {
            let ah = madd(b, a, 0x2b00 + i as u64 * 8);
            let v: B::V<W64> = decode::mem_load(b, ah, wseg)?;
            b.set(sem::scaledata_qref(i), v);
        }
        Ok(())
    })?;
    let iscale = mask_bit(b, ini, 20);
    b.if_then(iscale, |b| {
        let v = b.konst::<W64>(0x7f7f_7f7f_7f7f_7f7f);
        for i in 0..16usize {
            b.set(sem::scaledata_qref(i), v);
        }
        Ok(())
    })?;
    let ropm = mask_bit(b, rst, 5);
    b.if_then(ropm, |b| {
        for i in 0..8u8 {
            let ah = madd(b, a, 0x440 + u64::from(i) * 8);
            let v: B::V<W64> = decode::mem_load(b, ah, wseg)?;
            b.set(sem::kref(i), v);
        }
        Ok(())
    })?;
    let iopm = mask_bit(b, ini, 5);
    b.if_then(iopm, |b| {
        let z = b.konst::<W64>(0);
        for i in 0..8u8 {
            b.set(sem::kref(i), z);
        }
        Ok(())
    })
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

// ---- AES-NI / PCLMULQDQ ----

/// AES の S-box。
const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// AES の逆 S-box。
const AES_INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

/// 8 ビットの値で 256 エントリの表を引く。select の二分木で構成する
/// （ヘルパー機構は未配線なので素の演算で表す）。
fn lut8<B: Backend>(
    b: &mut B,
    idx: B::V<W128>,
    t: &[u8; 256],
    bit: u32,
    base: usize,
) -> B::V<W128> {
    if bit == 8 {
        return b.konst::<W128>(u128::from(t[base]));
    }
    let lo = lut8(b, idx, t, bit + 1, base);
    let hi = lut8(b, idx, t, bit + 1, base | (1usize << bit));
    let mask = b.konst::<W128>(1u128 << bit);
    let v = b.and::<W128>(idx, mask);
    let c = nez::<B, W128>(b, v);
    b.select::<W128>(c, hi, lo)
}

/// GF(2^8) の xtime（×2）。`x` は下位 8 ビットに値を持つ。
fn aes_xtime<B: Backend>(b: &mut B, x: B::V<W128>) -> B::V<W128> {
    let one = b.konst::<W128>(1);
    let t0 = b.shl::<W128>(x, one);
    let ff = b.konst::<W128>(0xff);
    let t = b.and::<W128>(t0, ff);
    let h80 = b.konst::<W128>(0x80);
    let h = b.and::<W128>(x, h80);
    let hp = nez::<B, W128>(b, h);
    let k1b = b.konst::<W128>(0x1b);
    let red = b.xor::<W128>(t, k1b);
    b.select::<W128>(hp, red, t)
}

/// GF(2^8) の定数乗算。`x` は下位 8 ビットに値を持つ。
fn aes_mul<B: Backend>(b: &mut B, x: B::V<W128>, c: u8) -> B::V<W128> {
    let mut r = b.konst::<W128>(0);
    let mut t = x;
    for i in 0..8 {
        if c >> i & 1 != 0 {
            r = b.xor::<W128>(r, t);
        }
        t = aes_xtime(b, t);
    }
    r
}

/// SubBytes/InvSubBytes。16 バイトすべてに S-box を適用する。
fn aes_sub_bytes<B: Backend>(b: &mut B, v: B::V<W128>, inv: bool) -> B::V<W128> {
    let t = if inv { &AES_INV_SBOX } else { &AES_SBOX };
    let mut r = b.konst::<W128>(0);
    for i in 0..16u32 {
        let byte = lane128(b, v, i * 8, 8);
        let s = lut8(b, byte, t, 0, 0);
        r = put_lane128(b, r, s, i * 8, 8);
    }
    r
}

/// ShiftRows/InvShiftRows。バイト `4c+r`（列 c・行 r）を行 r の
/// ローテートで並べ替える。順変換は左、逆変換は右に r 列回す。
fn aes_shift_rows<B: Backend>(b: &mut B, v: B::V<W128>, inv: bool) -> B::V<W128> {
    let mut r = b.konst::<W128>(0);
    for c in 0..4u32 {
        for row in 0..4u32 {
            let sc = if inv {
                (c + 4 - row) % 4
            } else {
                (c + row) % 4
            };
            let byte = lane128(b, v, (4 * sc + row) * 8, 8);
            r = put_lane128(b, r, byte, (4 * c + row) * 8, 8);
        }
    }
    r
}

/// MixColumns/InvMixColumns。各列（dword）に GF(2^8) の行列を掛ける。
fn aes_mix_columns<B: Backend>(b: &mut B, v: B::V<W128>, inv: bool) -> B::V<W128> {
    const M: [[u8; 4]; 4] = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];
    const MI: [[u8; 4]; 4] = [
        [14, 11, 13, 9],
        [9, 14, 11, 13],
        [13, 9, 14, 11],
        [11, 13, 9, 14],
    ];
    let m = if inv { &MI } else { &M };
    let mut r = b.konst::<W128>(0);
    for c in 0..4u32 {
        let a: Vec<B::V<W128>> = (0..4u32)
            .map(|i| lane128(b, v, (4 * c + i) * 8, 8))
            .collect();
        for (row, coef) in m.iter().enumerate() {
            let mut o = b.konst::<W128>(0);
            for i in 0..4usize {
                let p = aes_mul(b, a[i], coef[i]);
                o = b.xor::<W128>(o, p);
            }
            r = put_lane128(b, r, o, (4 * c + row as u32) * 8, 8);
        }
    }
    r
}

/// AES-NI のラウンド変換の値計算。`kind`: 0=ENC 1=ENCLAST
/// 2=DEC 3=DECLAST。IMC は逆 MixColumns だけなので別扱い。
fn aesround_val<B: Backend>(b: &mut B, kind: u8, mut v: B::V<W128>, key: B::V<W128>) -> B::V<W128> {
    match kind {
        0 | 1 => {
            v = aes_sub_bytes(b, v, false);
            v = aes_shift_rows(b, v, false);
            if kind == 0 {
                v = aes_mix_columns(b, v, false);
            }
        }
        _ => {
            v = aes_shift_rows(b, v, true);
            v = aes_sub_bytes(b, v, true);
            if kind == 2 {
                v = b.xor::<W128>(v, key);
                return aes_mix_columns(b, v, true);
            }
        }
    }
    b.xor::<W128>(v, key)
}

/// AES-NI のラウンド変換。`kind`: 0=ENC 1=ENCLAST 2=DEC 3=DECLAST 4=IMC。
pub fn aesround<B: Backend>(
    b: &mut B,
    kind: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let dst = reg_x(d);
    let key = rx(b, ea, 128)?;
    let v = if kind == 4 {
        aes_mix_columns(b, key, true)
    } else {
        let x: B::V<W128> = b.get(sem::xmm_ref(dst));
        aesround_val(b, kind, x, key)
    };
    b.set(sem::xmm_ref(dst), v);
    Ok(())
}

/// VAESENC/VAESDEC 系。VEX.256 でも各 128 ビットレーン独立。
pub fn vaesround<B: Backend>(
    b: &mut B,
    kind: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    vbin2(b, d, ea, |b, a, c| aesround_val(b, kind, a, c))
}

/// VAESIMC。入力は第2オペランドだけ。
pub fn vaesimc<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    vun2(b, d, ea, |b, x| aes_mix_columns(b, x, true))
}

/// AESKEYGENASSIST。各 64 ビット半区画について、下位 dword に
/// SubWord(Xi)、上位 dword に RotWord(SubWord(Xi))^rcon を置く
/// （X1=SRC[63:32]、X3=SRC[127:96]）。
pub fn aeskeygenassist<B: Backend>(
    b: &mut B,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let src = rx(b, ea, 128)?;
    let r = aeskeygenassist_val(b, imm, src);
    b.set(sem::xmm_ref(reg_x(d)), r);
    Ok(())
}

/// AESKEYGENASSIST の 128 ビットレーン内演算。
fn aeskeygenassist_val<B: Backend>(b: &mut B, imm: u8, src: B::V<W128>) -> B::V<W128> {
    let subw = |b: &mut B, w: B::V<W128>| {
        let mut r = b.konst::<W128>(0);
        for i in 0..4u32 {
            let byte = lane128(b, w, i * 8, 8);
            let s = lut8(b, byte, &AES_SBOX, 0, 0);
            r = put_lane128(b, r, s, i * 8, 8);
        }
        r
    };
    let rotw = |b: &mut B, w: B::V<W128>| {
        let k8 = b.konst::<W128>(8);
        let k24 = b.konst::<W128>(24);
        let kff = b.konst::<W128>(0xffff_ffff);
        let lo = b.shr_l::<W128>(w, k8);
        let hi0 = b.shl::<W128>(w, k24);
        let hi = b.and::<W128>(hi0, kff);
        b.or::<W128>(lo, hi)
    };
    let krcon = b.konst::<W128>(u128::from(imm));
    let mut r = b.konst::<W128>(0);
    for (q, at, rot) in [
        (32u32, 0u32, false),
        (32, 32, true),
        (96, 64, false),
        (96, 96, true),
    ] {
        let w = lane128(b, src, q, 32);
        let w = if rot { rotw(b, w) } else { w };
        let mut s = subw(b, w);
        if rot {
            s = b.xor::<W128>(s, krcon);
        }
        r = put_lane128(b, r, s, at, 32);
    }
    r
}

/// VAESKEYGENASSIST。
pub fn vaeskeygenassist<B: Backend>(
    b: &mut B,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    vun2(b, d, ea, |b, x| aeskeygenassist_val(b, imm, x))
}

/// PCLMULQDQ の 128 ビットレーン内演算。imm[0]・imm[4] で両
/// オペランドの qword を選び、64×64 のキャリーレス乗算を返す。
fn pclmulqdq_val<B: Backend>(b: &mut B, imm: u8, a: B::V<W128>, c: B::V<W128>) -> B::V<W128> {
    let x = lane128(b, a, if imm & 1 == 0 { 0 } else { 64 }, 64);
    let y = lane128(b, c, if imm & 0x10 == 0 { 0 } else { 64 }, 64);
    let mut r = b.konst::<W128>(0);
    for i in 0..64u32 {
        let ki = b.konst::<W128>(u128::from(i));
        let sh = b.shr_l::<W128>(y, ki);
        let k1 = b.konst::<W128>(1);
        let bit = b.and::<W128>(sh, k1);
        let has = nez::<B, W128>(b, bit);
        let xs = b.shl::<W128>(x, ki);
        let xr = b.xor::<W128>(r, xs);
        r = b.select::<W128>(has, xr, r);
    }
    r
}

/// PCLMULQDQ。
pub fn pclmulqdq<B: Backend>(
    b: &mut B,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let a: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    let c = rx(b, ea, 128)?;
    let r = pclmulqdq_val(b, imm, a, c);
    b.set(sem::xmm_ref(reg_x(d)), r);
    Ok(())
}

/// VPCLMULQDQ。VEX.256 でも 128 ビットレーンごとに独立。
pub fn vpclmulqdq<B: Backend>(
    b: &mut B,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    vbin2(b, d, ea, |b, a, c| pclmulqdq_val(b, imm, a, c))
}

// ---- SHA-NI / GFNI ----

/// dword レーンの 32 ビットローテート。`x` は下位 32 ビットを持つ。
fn rol32<B: Backend>(b: &mut B, x: B::V<W128>, n: u32) -> B::V<W128> {
    let kl = b.konst::<W128>(u128::from(n));
    let kr = b.konst::<W128>(u128::from(32 - n));
    let l = b.shl::<W128>(x, kl);
    let r = b.shr_l::<W128>(x, kr);
    let t = b.or::<W128>(l, r);
    let m = b.konst::<W128>(0xffff_ffff);
    b.and::<W128>(t, m)
}

/// dword レーンの右ローテート。
fn ror32<B: Backend>(b: &mut B, x: B::V<W128>, n: u32) -> B::V<W128> {
    let kr = b.konst::<W128>(u128::from(n));
    let kl = b.konst::<W128>(u128::from(32 - n));
    let r = b.shr_l::<W128>(x, kr);
    let l = b.shl::<W128>(x, kl);
    let t = b.or::<W128>(l, r);
    let m = b.konst::<W128>(0xffff_ffff);
    b.and::<W128>(t, m)
}

/// 下位 32 ビットに丸める。
fn m32<B: Backend>(b: &mut B, x: B::V<W128>) -> B::V<W128> {
    let m = b.konst::<W128>(0xffff_ffff);
    b.and::<W128>(x, m)
}

/// dword レーン i（0 が最下位）を取り出す。
fn dw<B: Backend>(b: &mut B, v: B::V<W128>, i: u32) -> B::V<W128> {
    lane128(b, v, i * 32, 32)
}

/// dst の dword レーン i を v の下位で置き換える。
fn put_dw<B: Backend>(b: &mut B, dst: B::V<W128>, v: B::V<W128>, i: u32) -> B::V<W128> {
    put_lane128(b, dst, v, i * 32, 32)
}

/// SHA1RNDS4。imm[1:0] が論理関数と定数を選ぶ。SRC1 = (A,B,C,D)、
/// SRC2 = (W0+E, W1, W2, W3)。4 ラウンド分をまとめて計算する。
pub fn sha1rnds4<B: Backend>(
    b: &mut B,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    const K: [u64; 4] = [0x5A82_7999, 0x6ED9_EBA1, 0x8F1B_BCDC, 0xCA62_C1D6];
    let s1: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    let s2 = rx(b, ea, 128)?;
    let kk = b.konst::<W128>(u128::from(K[usize::from(imm & 3)]));
    let fsel = imm & 3;
    let (mut a, mut bb, mut c, mut dd) = (dw(b, s1, 3), dw(b, s1, 2), dw(b, s1, 1), dw(b, s1, 0));
    // 0 ラウンド目は SRC2[127:96]（W0+E の和）をそのまま使う。
    let mut e = dw(b, s2, 3);
    for i in 0..4u32 {
        let f = match fsel {
            0 => {
                let t0 = b.and::<W128>(bb, c);
                let nb = b.not::<W128>(bb);
                let t1 = b.and::<W128>(nb, dd);
                b.xor::<W128>(t0, t1)
            }
            2 => {
                let t0 = b.and::<W128>(bb, c);
                let t1 = b.and::<W128>(bb, dd);
                let t2 = b.and::<W128>(c, dd);
                let t3 = b.xor::<W128>(t0, t1);
                b.xor::<W128>(t3, t2)
            }
            _ => {
                let t = b.xor::<W128>(bb, c);
                b.xor::<W128>(t, dd)
            }
        };
        let addend = if i == 0 {
            e
        } else {
            let w = dw(b, s2, 3 - i);
            b.add::<W128>(e, w)
        };
        let r5 = rol32(b, a, 5);
        let t0 = b.add::<W128>(f, r5);
        let t1 = b.add::<W128>(t0, addend);
        let t2 = b.add::<W128>(t1, kk);
        let na = m32(b, t2);
        e = dd;
        dd = c;
        c = rol32(b, bb, 30);
        bb = a;
        a = na;
    }
    let mut r = b.konst::<W128>(0);
    r = put_dw(b, r, a, 3);
    r = put_dw(b, r, bb, 2);
    r = put_dw(b, r, c, 1);
    r = put_dw(b, r, dd, 0);
    b.set(sem::xmm_ref(reg_x(d)), r);
    Ok(())
}

/// SHA1NEXTE。DEST[127:96] = SRC2[127:96] + rol30(SRC1[127:96])、
/// 残りは SRC2 そのまま。
pub fn sha1nexte<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let s1: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    let s2 = rx(b, ea, 128)?;
    let a = dw(b, s1, 3);
    let t = rol32(b, a, 30);
    let s2top = dw(b, s2, 3);
    let top = b.add::<W128>(s2top, t);
    let top = m32(b, top);
    let r = put_dw(b, s2, top, 3);
    b.set(sem::xmm_ref(reg_x(d)), r);
    Ok(())
}

/// SHA1MSG1。DEST = [W2^W0, W3^W1, W4^W2, W5^W3]（dword 順に
/// 上から）。W4/W5 は SRC2 の上位 2 dword。
pub fn sha1msg1<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let s1: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    let s2 = rx(b, ea, 128)?;
    let mut r = b.konst::<W128>(0);
    for (a1, a2, oi) in [
        (dw(b, s1, 1), dw(b, s1, 3), 3u32),
        (dw(b, s1, 0), dw(b, s1, 2), 2),
        (dw(b, s2, 3), dw(b, s1, 1), 1),
        (dw(b, s2, 2), dw(b, s1, 0), 0),
    ] {
        let t = b.xor::<W128>(a1, a2);
        r = put_dw(b, r, t, oi);
    }
    b.set(sem::xmm_ref(reg_x(d)), r);
    Ok(())
}

/// SHA1MSG2。W16-W19 を順に (SRC1^W13..)^rol1 で作る
/// （W19 は W16 に依存する逐次形）。
pub fn sha1msg2<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let s1: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    let s2 = rx(b, ea, 128)?;
    let w13 = dw(b, s2, 2);
    let w14 = dw(b, s2, 1);
    let w15 = dw(b, s2, 0);
    let __dw0 = dw(b, s1, 3);
    let t13 = b.xor::<W128>(__dw0, w13);
    let w16 = rol32(b, t13, 1);
    let __dw1 = dw(b, s1, 2);
    let t14 = b.xor::<W128>(__dw1, w14);
    let w17 = rol32(b, t14, 1);
    let __dw2 = dw(b, s1, 1);
    let t15 = b.xor::<W128>(__dw2, w15);
    let w18 = rol32(b, t15, 1);
    let __dw3 = dw(b, s1, 0);
    let t16 = b.xor::<W128>(__dw3, w16);
    let w19 = rol32(b, t16, 1);
    let mut r = b.konst::<W128>(0);
    r = put_dw(b, r, w16, 3);
    r = put_dw(b, r, w17, 2);
    r = put_dw(b, r, w18, 1);
    r = put_dw(b, r, w19, 0);
    b.set(sem::xmm_ref(reg_x(d)), r);
    Ok(())
}

/// SHA-256 の補助関数。
fn sha256_ch<B: Backend>(b: &mut B, e: B::V<W128>, f: B::V<W128>, g: B::V<W128>) -> B::V<W128> {
    let t0 = b.and::<W128>(e, f);
    let ne = b.not::<W128>(e);
    let t1 = b.and::<W128>(ne, g);
    b.xor::<W128>(t0, t1)
}
fn sha256_maj<B: Backend>(b: &mut B, a: B::V<W128>, bb: B::V<W128>, c: B::V<W128>) -> B::V<W128> {
    let t0 = b.and::<W128>(a, bb);
    let t1 = b.and::<W128>(a, c);
    let t2 = b.and::<W128>(bb, c);
    let t3 = b.xor::<W128>(t0, t1);
    b.xor::<W128>(t3, t2)
}
fn sha256_sig0<B: Backend>(b: &mut B, x: B::V<W128>) -> B::V<W128> {
    let t0 = ror32(b, x, 2);
    let t1 = ror32(b, x, 13);
    let t2 = ror32(b, x, 22);
    let t3 = b.xor::<W128>(t0, t1);
    b.xor::<W128>(t3, t2)
}
fn sha256_sig1<B: Backend>(b: &mut B, x: B::V<W128>) -> B::V<W128> {
    let t0 = ror32(b, x, 6);
    let t1 = ror32(b, x, 11);
    let t2 = ror32(b, x, 25);
    let t3 = b.xor::<W128>(t0, t1);
    b.xor::<W128>(t3, t2)
}
fn sha256_s0<B: Backend>(b: &mut B, x: B::V<W128>) -> B::V<W128> {
    let t0 = ror32(b, x, 7);
    let t1 = ror32(b, x, 18);
    let k3 = b.konst::<W128>(3);
    let t2 = b.shr_l::<W128>(x, k3);
    let t3 = b.xor::<W128>(t0, t1);
    let t4 = b.xor::<W128>(t3, t2);
    m32(b, t4)
}
fn sha256_s1<B: Backend>(b: &mut B, x: B::V<W128>) -> B::V<W128> {
    let t0 = ror32(b, x, 17);
    let t1 = ror32(b, x, 19);
    let k10 = b.konst::<W128>(10);
    let t2 = b.shr_l::<W128>(x, k10);
    let t3 = b.xor::<W128>(t0, t1);
    let t4 = b.xor::<W128>(t3, t2);
    m32(b, t4)
}

/// SHA256RNDS2。SRC1 = (C,D,G,H)、SRC2 = (A,B,E,F)、暗黙の XMM0 の
/// 下位 2 dword が W+K の和。2 ラウンドで (A,B,E,F) を更新する。
pub fn sha256rnds2<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let s1: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    let s2 = rx(b, ea, 128)?;
    let x0: B::V<W128> = b.get(sem::xmm_ref(Xmm(0)));
    let wk = [dw(b, x0, 0), dw(b, x0, 1)];
    let (mut a, mut bb) = (dw(b, s2, 3), dw(b, s2, 2));
    let (mut c, mut dd) = (dw(b, s1, 3), dw(b, s1, 2));
    let (mut e, mut f) = (dw(b, s2, 1), dw(b, s2, 0));
    let (mut g, mut h) = (dw(b, s1, 1), dw(b, s1, 0));
    for w in wk {
        let ch = sha256_ch(b, e, f, g);
        let s1_ = sha256_sig1(b, e);
        let t0 = b.add::<W128>(ch, s1_);
        let t1 = b.add::<W128>(t0, w);
        let t1 = b.add::<W128>(t1, h);
        let t1 = m32(b, t1);
        let maj = sha256_maj(b, a, bb, c);
        let s0_ = sha256_sig0(b, a);
        let t2 = b.add::<W128>(maj, s0_);
        let t3 = b.add::<W128>(t1, t2);
        let na = m32(b, t3);
        let ne0 = b.add::<W128>(t1, dd);
        let ne = m32(b, ne0);
        h = g;
        g = f;
        f = e;
        e = ne;
        dd = c;
        c = bb;
        bb = a;
        a = na;
    }
    let mut r = b.konst::<W128>(0);
    r = put_dw(b, r, a, 3);
    r = put_dw(b, r, bb, 2);
    r = put_dw(b, r, e, 1);
    r = put_dw(b, r, f, 0);
    b.set(sem::xmm_ref(reg_x(d)), r);
    Ok(())
}

/// SHA256MSG1。DEST.d_i = SRC1.d_i + σ0(d_{i+1})（最上位だけ
/// SRC2[31:0] を σ0 入力に使う）。
pub fn sha256msg1<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let s1: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    let s2 = rx(b, ea, 128)?;
    let w4 = dw(b, s2, 0);
    let mut r = b.konst::<W128>(0);
    for i in 0..4u32 {
        let w = dw(b, s1, i);
        let x = if i == 3 { w4 } else { dw(b, s1, i + 1) };
        let s = sha256_s0(b, x);
        let t0 = b.add::<W128>(w, s);
        let t = m32(b, t0);
        r = put_dw(b, r, t, i);
    }
    b.set(sem::xmm_ref(reg_x(d)), r);
    Ok(())
}

/// SHA256MSG2。W16-W19 を逐次に作る（W18/W19 は直前の結果に依存）。
pub fn sha256msg2<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let s1: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    let s2 = rx(b, ea, 128)?;
    let w14 = dw(b, s2, 2);
    let w15 = dw(b, s2, 3);
    let s14 = sha256_s1(b, w14);
    let __dw4 = dw(b, s1, 0);
    let t0 = b.add::<W128>(__dw4, s14);
    let w16 = m32(b, t0);
    let s15 = sha256_s1(b, w15);
    let __dw5 = dw(b, s1, 1);
    let t1 = b.add::<W128>(__dw5, s15);
    let w17 = m32(b, t1);
    let s16 = sha256_s1(b, w16);
    let __dw6 = dw(b, s1, 2);
    let t2 = b.add::<W128>(__dw6, s16);
    let w18 = m32(b, t2);
    let s17 = sha256_s1(b, w17);
    let __dw7 = dw(b, s1, 3);
    let t3 = b.add::<W128>(__dw7, s17);
    let w19 = m32(b, t3);
    let mut r = b.konst::<W128>(0);
    r = put_dw(b, r, w19, 3);
    r = put_dw(b, r, w18, 2);
    r = put_dw(b, r, w17, 1);
    r = put_dw(b, r, w16, 0);
    b.set(sem::xmm_ref(reg_x(d)), r);
    Ok(())
}

// ---- GFNI ----

/// GF(2^8) の乗算（還元多項式 x^8+x^4+x^3+x+1 = 0x11B）。
/// 両オペランドは下位 8 ビットを持つ。
fn gf8mul<B: Backend>(b: &mut B, x: B::V<W128>, y: B::V<W128>) -> B::V<W128> {
    let mut t = b.konst::<W128>(0);
    for i in 0..8u32 {
        let ki = b.konst::<W128>(u128::from(i));
        let sh = b.shr_l::<W128>(y, ki);
        let k1 = b.konst::<W128>(1);
        let bit = b.and::<W128>(sh, k1);
        let c = nez::<B, W128>(b, bit);
        let xs = b.shl::<W128>(x, ki);
        let xt = b.xor::<W128>(t, xs);
        t = b.select::<W128>(c, xt, t);
    }
    for i in (8..15u32).rev() {
        let ki = b.konst::<W128>(u128::from(i));
        let sh = b.shr_l::<W128>(t, ki);
        let k1 = b.konst::<W128>(1);
        let bit = b.and::<W128>(sh, k1);
        let c = nez::<B, W128>(b, bit);
        let p = b.konst::<W128>(0x11bu128 << (i - 8));
        let tp = b.xor::<W128>(t, p);
        t = b.select::<W128>(c, tp, t);
    }
    t
}

/// GF(2^8) の逆元 x^254（x=0 では 0）。
fn gf8inv<B: Backend>(b: &mut B, x: B::V<W128>) -> B::V<W128> {
    // 254 = 2+4+8+16+32+64+128 なので x^{2^i}（i=1..7）を掛け合わせる。
    let mut r = b.konst::<W128>(1);
    let mut t = x;
    for _ in 0..7 {
        t = gf8mul(b, t, t);
        r = gf8mul(b, r, t);
    }
    m32(b, r)
}

/// GF2P8MULB。各バイトを GF(2^8) で乗算する。
pub fn gf2p8mulb<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let s1: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    let s2 = rx(b, ea, 128)?;
    let r = gf2p8mulb_val(b, s1, s2);
    b.set(sem::xmm_ref(reg_x(d)), r);
    Ok(())
}

/// GF2P8MULB の 128 ビットレーン内演算。
fn gf2p8mulb_val<B: Backend>(b: &mut B, s1: B::V<W128>, s2: B::V<W128>) -> B::V<W128> {
    let mut r = b.konst::<W128>(0);
    for i in 0..16u32 {
        let x = lane128(b, s1, i * 8, 8);
        let y = lane128(b, s2, i * 8, 8);
        let p = gf8mul(b, x, y);
        r = put_lane128(b, r, p, i * 8, 8);
    }
    r
}

/// VGF2P8MULB。
pub fn vgf2p8mulb<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    vbin2(b, d, ea, |b, a, c| gf2p8mulb_val(b, a, c))
}

/// バイト値（下位 8 ビット）のパリティを 0/1 の値で返す。
fn parity8<B: Backend>(b: &mut B, x: B::V<W128>) -> B::V<W128> {
    let k4 = b.konst::<W128>(4);
    let t0 = b.shr_l::<W128>(x, k4);
    let t = b.xor::<W128>(x, t0);
    let k2 = b.konst::<W128>(2);
    let t1 = b.shr_l::<W128>(t, k2);
    let t = b.xor::<W128>(t, t1);
    let k1 = b.konst::<W128>(1);
    let t2 = b.shr_l::<W128>(t, k1);
    let t = b.xor::<W128>(t, t2);
    b.and::<W128>(t, k1)
}

/// GF2P8AFFINEQB/AFFINEINVQB。qword ごとに 8x8 ビット行列を
/// 各バイトに掛け、imm8 を XOR する。inv=true は入力バイトを
/// GF(2^8) で逆元にしてから掛ける。
pub fn gf2p8affine<B: Backend>(
    b: &mut B,
    inv: bool,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let s1: B::V<W128> = b.get(sem::xmm_ref(reg_x(d)));
    let s2 = rx(b, ea, 128)?;
    let r = gf2p8affine_val(b, inv, imm, s1, s2);
    b.set(sem::xmm_ref(reg_x(d)), r);
    Ok(())
}

/// GF2P8AFFINEQB/AFFINEINVQB の 128 ビットレーン内演算。
fn gf2p8affine_val<B: Backend>(
    b: &mut B,
    inv: bool,
    imm: u8,
    s1: B::V<W128>,
    s2: B::V<W128>,
) -> B::V<W128> {
    let mut r = b.konst::<W128>(0);
    for q in 0..2u32 {
        let mat = lane128(b, s2, q * 64, 64);
        for i in 0..8u32 {
            let mut x = lane128(b, s1, (q * 8 + i) * 8, 8);
            if inv {
                x = gf8inv(b, x);
            }
            let mut ob = b.konst::<W128>(0);
            for k in 0..8u32 {
                let row = lane128(b, mat, (7 - k) * 8, 8);
                let prod = b.and::<W128>(row, x);
                let mut bit = parity8(b, prod);
                if imm >> k & 1 != 0 {
                    let k1 = b.konst::<W128>(1);
                    bit = b.xor::<W128>(bit, k1);
                }
                let kk = b.konst::<W128>(u128::from(k));
                let sh = b.shl::<W128>(bit, kk);
                ob = b.or::<W128>(ob, sh);
            }
            r = put_lane128(b, r, ob, (q * 8 + i) * 8, 8);
        }
    }
    r
}

/// VGF2P8AFFINEQB/AFFINEINVQB。
pub fn vgf2p8affine<B: Backend>(
    b: &mut B,
    inv: bool,
    imm: u8,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    vbin2(b, d, ea, |b, a, c| gf2p8affine_val(b, inv, imm, a, c))
}

// ===== EVEX（AVX-512）

/// EVEX のベクタ長（128 ビット部分の個数。ll=0→1、1→2、2→4）。
fn ev_n(d: &MapDec) -> usize {
    1usize << d.evex_ll
}

/// aaa が選ぶ k マスクを読む（0 はマスクなし＝全 1）。
fn ev_k<B: Backend>(b: &mut B, d: &MapDec) -> B::V<W64> {
    if d.evex_aaa == 0 {
        b.konst::<W64>(W64::from_u128(u64::MAX as u128))
    } else {
        b.get(sem::kref(d.evex_aaa))
    }
}

/// k マスクの `idx` ビット目（0/1 の値）。
fn ev_kbit<B: Backend>(b: &mut B, k: B::V<W64>, idx: usize) -> B::V<W64> {
    let sh = b.konst::<W64>(W64::from_u128(idx as u128));
    let s = b.shr_l::<W64>(k, sh);
    let one = b.konst::<W64>(W64::from_u128(1));
    b.and::<W64>(s, one)
}

/// part `p`（128 ビット）に対応する要素マスクを 0/全 1 で展開する。
/// `w64` なら 64 ビット要素×2、偽なら 32 ビット要素×4。
fn ev_kmask128<B: Backend>(b: &mut B, k: B::V<W64>, p: usize, w64: bool) -> B::V<W128> {
    let (nelem, ebits) = if w64 { (2usize, 64u32) } else { (4, 32) };
    let z64 = b.konst::<W64>(W64::from_u128(0));
    let eones = b.konst::<W64>(W64::from_u128(if w64 {
        u64::MAX as u128
    } else {
        0xFFFF_FFFF
    }));
    let mut m = b.konst::<W128>(W128::from_u128(0));
    for e in 0..nelem {
        let bit = ev_kbit(b, k, p * nelem + e);
        // 0 → 0、1 → 要素幅の全 1（0-1 の桁借りを要素幅に絞る。
        // 64 ビット幅のままだと隣接要素へはみ出す）。
        let m64 = b.sub::<W64>(z64, bit);
        let m64 = b.and::<W64>(m64, eones);
        let m128 = b.zext::<W64, W128>(m64);
        let sh = b.konst::<W128>(W128::from_u128((e as u32 * ebits) as u128));
        let m128 = b.shl::<W128>(m128, sh);
        m = b.or::<W128>(m, m128);
    }
    m
}

/// {k}/{z} マージ。`src` の part 値を、`dst` の現在値（{z} なら
/// 0）と要素マスクで合成する。`w64` は要素幅。
fn ev_merge<B: Backend>(
    b: &mut B,
    d: &MapDec,
    k: B::V<W64>,
    dst: u8,
    src: B::V<W128>,
    p: usize,
    w64: bool,
) -> B::V<W128> {
    let m = ev_kmask128(b, k, p, w64);
    let keep = if d.evex_z {
        b.konst::<W128>(W128::from_u128(0))
    } else {
        b.get(sem::zreg_ref(dst, p))
    };
    let masked = b.and::<W128>(src, m);
    let nm = b.not::<W128>(m);
    let kept = b.and::<W128>(keep, nm);
    b.or::<W128>(masked, kept)
}

/// VMOVDQU32/64（EVEX.0F 6F/7F）。`store` が真なら r/m 宛ての 7F、
/// `w64` は要素幅（dqu64）。{k} マージと {z} ゼロイングに対応する。
/// メモリ読みは部分幅で行うため、非アクティブ要素のフォールト抑制は
/// 128 ビット単位の近似（ストアは要素単位に書かないので厳密）。
/// `ea` の実モード限界検査（wseg）は落とす。EVEX は 64 ビット
/// モード専用で wseg は常に無いため到達しない。
pub fn emovdqu<B: Backend>(
    b: &mut B,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
    store: bool,
    w64: bool,
) -> Result<(), B::Exit> {
    let n = ev_n(d);
    let k = ev_k(b, d);
    let zero = b.konst::<W128>(W128::from_u128(0));
    let merge = |b: &mut B, dst: u8, src: B::V<W128>, p: usize| ev_merge(b, d, k, dst, src, p, w64);
    if !store {
        let dst = decode::reg_x5(d);
        for p in 0..4 {
            let v = if p < n {
                let src = match ea {
                    Rm::Reg(_) => b.get(sem::zreg_ref(decode::rm_reg_x5(d), p)),
                    Rm::Mem { a, .. } => {
                        let off = b.konst::<W64>(W64::from_u128((p * 16) as u128));
                        let a = b.add::<W64>(*a, off);
                        b.load::<W128>(a, sem::DATA_READ)?
                    }
                };
                merge(b, dst, src, p)
            } else {
                // ベクタ長より上は常に 0。
                zero
            };
            b.set(sem::zreg_ref(dst, p), v);
        }
        return Ok(());
    }
    let src_r = decode::reg_x5(d);
    match ea {
        Rm::Reg(_) => {
            let dst = decode::rm_reg_x5(d);
            for p in 0..4 {
                let v = if p < n {
                    let src = b.get(sem::zreg_ref(src_r, p));
                    merge(b, dst, src, p)
                } else {
                    zero
                };
                b.set(sem::zreg_ref(dst, p), v);
            }
        }
        Rm::Mem { a, .. } => {
            let a = *a;
            let (nelem, ebytes) = if w64 { (2usize, 8u32) } else { (4, 4) };
            let z64 = b.konst::<W64>(W64::from_u128(0));
            for p in 0..n {
                let part = b.get(sem::zreg_ref(src_r, p));
                for e in 0..nelem {
                    let bit = ev_kbit(b, k, p * nelem + e);
                    let on = b.cmp::<W64>(Cmp::Ne, bit, z64);
                    let off = (p * 16 + e * ebytes as usize) as u128;
                    let elem = lane128(b, part, (e as u32) * ebytes * 8, ebytes * 8);
                    b.if_then(on, |b| {
                        let off = b.konst::<W64>(W64::from_u128(off));
                        let ad = b.add::<W64>(a, off);
                        if w64 {
                            let v64 = b.trunc::<W128, W64>(elem);
                            b.store::<W64>(ad, v64, sem::DATA_WRITE)
                        } else {
                            let v32 = b.trunc::<W128, W32>(elem);
                            b.store::<W32>(ad, v32, sem::DATA_WRITE)
                        }
                    })?;
                }
            }
        }
    }
    Ok(())
}

/// {er} エンコード（b=1 のレジスタ形）なら L'L は丸め指定。
/// softfloat の `Rm` 番号で返し、それ以外は 0（RNE。
/// MXCSR.RC の反映と {sae} の例外抑制は未モデル化の近似）。
fn ev_rc(d: &MapDec, reg_form: bool) -> u8 {
    if d.evex_b && reg_form {
        x86_rm(u64::from(d.evex_ll))
    } else {
        0
    }
}

/// {er} 形を含めたベクタの part 数。{er} は 512 ビット固定で、
/// レジスタ形の b=1 では L'L が丸め指定になるため `ev_n` は
/// 使えない。
fn ev_parts(d: &MapDec, reg_form: bool) -> usize {
    if d.evex_b && reg_form { 4 } else { ev_n(d) }
}

/// 要素を 128 ビット全幅に複製する（埋め込み broadcast 用）。
/// `v` は下位 `ebits`（32 または 64）に要素値を持つ W128。
fn ev_splat128<B: Backend>(b: &mut B, v: B::V<W128>, ebits: u32) -> B::V<W128> {
    assert!(ebits == 32 || ebits == 64, "ev_splat128: ebits={ebits}");
    let sh = b.konst::<W128>(W128::from_u128(u128::from(ebits)));
    let hi = b.shl::<W128>(v, sh);
    let v = b.or::<W128>(v, hi);
    if ebits == 32 {
        let sh = b.konst::<W128>(W128::from_u128(64));
        let hi = b.shl::<W128>(v, sh);
        b.or::<W128>(v, hi)
    } else {
        v
    }
}

/// EVEX r/m ソースの part `p`（128 ビット単位）を読む。
/// メモリ形で b=1 なら埋め込み broadcast：要素（`edisp` バイト）
/// を読んで全レーンに複製する。`w64` は要素幅。
///
/// 近似：実機では opmask で全要素が無効のときメモリ読み出し
/// 自体が抑制される（フォールトしない）が、本実装は
/// アクティブな part を無条件で読む。
fn ev_src<B: Backend>(
    b: &mut B,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
    p: usize,
    w64: bool,
) -> Result<B::V<W128>, B::Exit> {
    match ea {
        Rm::Reg(_) => Ok(b.get(sem::zreg_ref(decode::rm_reg_x5(d), p))),
        Rm::Mem { a, .. } => {
            if d.evex_b {
                // 埋め込み broadcast。要素を読んで全レーンへ複製
                // する。ベクタ長に依らず要素アクセスは 1 回だけ。
                let v = if w64 {
                    let v = b.load::<W64>(*a, sem::DATA_READ)?;
                    b.zext::<W64, W128>(v)
                } else {
                    let v = b.load::<W32>(*a, sem::DATA_READ)?;
                    b.zext::<W32, W128>(v)
                };
                Ok(ev_splat128(b, v, if w64 { 64 } else { 32 }))
            } else {
                let off = b.konst::<W64>(W64::from_u128((p * 16) as u128));
                let a = b.add::<W64>(*a, off);
                b.load::<W128>(a, sem::DATA_READ)
            }
        }
    }
}

/// EVEX の FVM パック浮動小数点演算（VADD/VSUB/VMUL/VDIV/
/// VMIN/VMAX/VSQRT の ps/pd）。dst{zk} = src1 op src2 で、
/// `d.vex_w` が要素幅（W=0 は f32、W=1 は f64）。メモリ形の
/// b=1 は m32bcst/m64bcst、レジスタ形の b=1 は {er}/{sae}
/// （L'L=丸め指定、512 固定）。Sqrt は Vv 未使用の単項で
/// r/m 側を取る。{k} マージと {z} ゼロイングは要素単位。
pub fn efloat<B: Backend>(
    b: &mut B,
    op: Fop,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    use polyisa_sem::{F32, F64};
    let reg_form = matches!(ea, Rm::Reg(_));
    let n = ev_parts(d, reg_form);
    let w64 = d.vex_w;
    let rc = ev_rc(d, reg_form);
    let k = ev_k(b, d);
    let dst = decode::reg_x5(d);
    let src1 = d.vex_v;
    let zero = b.konst::<W128>(W128::from_u128(0));
    let una = matches!(op, Fop::Sqrt);
    for p in 0..4 {
        let v = if p < n {
            let y = ev_src(b, d, ea, p, w64)?;
            let x = if una {
                zero
            } else {
                b.get(sem::zreg_ref(src1, p))
            };
            let mut r = zero;
            if w64 {
                for e in 0..2 {
                    let xf = flane64(b, x, e);
                    let yf = flane64(b, y, e);
                    let g = efl_bin::<B, F64>(b, op, xf, yf, rc);
                    r = put_flane64(b, r, g, e);
                }
            } else {
                for e in 0..4 {
                    let xf = flane32(b, x, e);
                    let yf = flane32(b, y, e);
                    let g = efl_bin::<B, F32>(b, op, xf, yf, rc);
                    r = put_flane32(b, r, g, e);
                }
            }
            ev_merge(b, d, k, dst, r, p, w64)
        } else {
            zero
        };
        b.set(sem::zreg_ref(dst, p), v);
    }
    Ok(())
}

/// `efloat` のレーン演算本体。{er} の丸め指定 `rc` は丸めの
/// 効く演算（四則・sqrt）にだけ渡し、min/max は丸め無し。
/// Sqrt は単項なので r/m 側の `c` を取る（`fop64` と同じ）。
fn efl_bin<B: Backend, F: polyisa_sem::Width>(
    b: &mut B,
    op: Fop,
    a: B::V<F>,
    c: B::V<F>,
    rc: u8,
) -> B::V<F> {
    match op {
        Fop::Add => b.fadd_r::<F>(a, c, rc),
        Fop::Sub => b.fsub_r::<F>(a, c, rc),
        Fop::Mul => b.fmul_r::<F>(a, c, rc),
        Fop::Div => b.fdiv_r::<F>(a, c, rc),
        Fop::Min => b.fmin::<F>(a, c),
        Fop::Max => b.fmax::<F>(a, c),
        Fop::Sqrt => b.fsqrt_r::<F>(c, rc),
        Fop::Cmp(_) => a,
    }
}

/// EVEX のパック整数演算（VPADD/VPSUB/VPMIN/VPMAX 等の
/// dword/qword 形）。`d.vex_w` が要素幅、メモリ形の b=1 は
/// m32bcst/m64bcst。整数形なので {er} はない。
pub fn eint<B: Backend>(
    b: &mut B,
    kind: Iop,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let reg_form = matches!(ea, Rm::Reg(_));
    let n = ev_parts(d, reg_form);
    let w64 = d.vex_w;
    let k = ev_k(b, d);
    let dst = decode::reg_x5(d);
    let src1 = d.vex_v;
    let zero = b.konst::<W128>(W128::from_u128(0));
    for p in 0..4 {
        let v = if p < n {
            let x = b.get(sem::zreg_ref(src1, p));
            let y = ev_src(b, d, ea, p, w64)?;
            let r = if w64 {
                let mut r = zero;
                for e in 0..2 {
                    let xl = lane128(b, x, e * 64, 64);
                    let yl = lane128(b, y, e * 64, 64);
                    let x64 = b.trunc::<W128, W64>(xl);
                    let y64 = b.trunc::<W128, W64>(yl);
                    let g = iop_op::<B, W64>(b, kind, x64, y64);
                    let g128 = b.zext::<W64, W128>(g);
                    r = put_lane128(b, r, g128, e * 64, 64);
                }
                r
            } else {
                let mut r = zero;
                for e in 0..4 {
                    let xl = lane128(b, x, e * 32, 32);
                    let yl = lane128(b, y, e * 32, 32);
                    let x32 = b.trunc::<W128, W32>(xl);
                    let y32 = b.trunc::<W128, W32>(yl);
                    let g = iop_op::<B, W32>(b, kind, x32, y32);
                    let g128 = b.zext::<W32, W128>(g);
                    r = put_lane128(b, r, g128, e * 32, 32);
                }
                r
            };
            ev_merge(b, d, k, dst, r, p, w64)
        } else {
            zero
        };
        b.set(sem::zreg_ref(dst, p), v);
    }
    Ok(())
}

/// EVEX のパック論理（VPAND/VPANDN/VPOR/VPXOR の d/q 形）。
/// レーン演算は 128 ビット単位、マスク粒度は `d.vex_w` の
/// 要素幅。メモリ形の b=1 は m32bcst/m64bcst。
pub fn elogic<B: Backend>(
    b: &mut B,
    op: Lop,
    d: &MapDec,
    ea: &Rm<B::V<W64>>,
) -> Result<(), B::Exit> {
    let reg_form = matches!(ea, Rm::Reg(_));
    let n = ev_parts(d, reg_form);
    let w64 = d.vex_w;
    let k = ev_k(b, d);
    let dst = decode::reg_x5(d);
    let src1 = d.vex_v;
    let zero = b.konst::<W128>(W128::from_u128(0));
    for p in 0..4 {
        let v = if p < n {
            let x = b.get(sem::zreg_ref(src1, p));
            let y = ev_src(b, d, ea, p, w64)?;
            let r = lop_lane(b, op, x, y);
            ev_merge(b, d, k, dst, r, p, w64)
        } else {
            zero
        };
        b.set(sem::zreg_ref(dst, p), v);
    }
    Ok(())
}

/// EVEX の PABS（VPABSD/VPABSQ）。Vv 未使用の単項で、
/// 要素幅は `d.vex_w`（VPABSQ は avx512dq）。
pub fn eabs<B: Backend>(b: &mut B, d: &MapDec, ea: &Rm<B::V<W64>>) -> Result<(), B::Exit> {
    let reg_form = matches!(ea, Rm::Reg(_));
    let n = ev_parts(d, reg_form);
    let w64 = d.vex_w;
    let k = ev_k(b, d);
    let dst = decode::reg_x5(d);
    let zero = b.konst::<W128>(W128::from_u128(0));
    for p in 0..4 {
        let v = if p < n {
            let y = ev_src(b, d, ea, p, w64)?;
            let r = if w64 {
                pabs_val::<B, W64>(b, y)
            } else {
                pabs_val::<B, W32>(b, y)
            };
            ev_merge(b, d, k, dst, r, p, w64)
        } else {
            zero
        };
        b.set(sem::zreg_ref(dst, p), v);
    }
    Ok(())
}
