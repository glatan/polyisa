// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Power（ppc64・ユーザーモード）の意味論。`polyisa_sem` のバックエンド
//! 上に命令ごとの作用を書く。
//!
//! XO フィールドの細かい振り分けは `x31`・`x19`・`x63` 等の入口が
//! 行う（ARM 試作と同じ粗分類＋意味論振り分け）。出典は
//! SPEC-POWER-ISA（Power ISA v3.1C）である。XO の数値は llvm-mc の
//! 符号化（TOOL-LLVM）で確認した。
// Ref: SPEC-POWER-ISA (v3.1C), SPEC-POWER-ABI (ELFv2 r1.5), TOOL-LLVM.

use polyisa_mem::{Access, AccessKind, Align, Endian};
use polyisa_sem::{
    Backend, Cmp, ExceptionKind, Flow, GuestException, StateRef, W8, W16, W32, W64, W128,
};

use crate::CpuState;

/// 汎用レジスタ番号。`r0` の「値 0」規約は各エントリ側で扱う。
pub struct Gpr(pub u8);
/// VSR 番号（0–63）。FPR・VR の別名もこの指し方で書く。
pub struct Vsr(pub u8);

impl Gpr {
    #[must_use]
    pub const fn state(self) -> StateRef<W64> {
        StateRef::from_offset(core::mem::offset_of!(CpuState, r) + self.0 as usize * 8)
    }
}

impl Vsr {
    #[must_use]
    pub const fn state(self) -> StateRef<W128> {
        StateRef::from_offset(core::mem::offset_of!(CpuState, vsr) + self.0 as usize * 16)
    }
}

/// 条件レジスタ。
#[must_use]
pub const fn cr_ref() -> StateRef<W64> {
    StateRef::from_offset(core::mem::offset_of!(CpuState, cr))
}
/// XER（SO/OV/CA）。
#[must_use]
pub const fn xer_ref() -> StateRef<W64> {
    StateRef::from_offset(core::mem::offset_of!(CpuState, xer))
}
/// リンクレジスタ。
#[must_use]
pub const fn lr_ref() -> StateRef<W64> {
    StateRef::from_offset(core::mem::offset_of!(CpuState, lr))
}
/// カウントレジスタ。
#[must_use]
pub const fn ctr_ref() -> StateRef<W64> {
    StateRef::from_offset(core::mem::offset_of!(CpuState, ctr))
}
/// FPSCR。
#[must_use]
pub const fn fpscr_ref() -> StateRef<W64> {
    StateRef::from_offset(core::mem::offset_of!(CpuState, fpscr))
}
/// PVR（SPR 287）。
#[must_use]
pub const fn pvr_ref() -> StateRef<W64> {
    StateRef::from_offset(core::mem::offset_of!(CpuState, pvr))
}
/// タイムベース相当のカウンタ。
#[must_use]
pub const fn tb_ref() -> StateRef<W64> {
    StateRef::from_offset(core::mem::offset_of!(CpuState, tb))
}
/// スタックポインタ（r1）。
#[must_use]
pub const fn sp_ref() -> StateRef<W64> {
    Gpr(1).state()
}

const XER_SO: u64 = 1 << 31;
const XER_OV: u64 = 1 << 30;
const XER_CA: u64 = 1 << 29;

const CR_LT: u64 = 0x8;
const CR_GT: u64 = 0x4;
const CR_EQ: u64 = 0x2;
const CR_SO: u64 = 0x1;

const fn data_acc(le: bool, read: bool) -> Access {
    Access {
        endian: if le { Endian::Le } else { Endian::Be },
        align: Align::Unaligned,
        kind: if read {
            AccessKind::DataRead
        } else {
            AccessKind::DataWrite
        },
    }
}

fn unimp<B: Backend>(b: &mut B, code: u64) -> Flow<B> {
    Err(b.raise(GuestException {
        kind: ExceptionKind::Undefined,
        code,
        addr: None,
        in_delay_slot: false,
    }))
}

fn g<B: Backend>(b: &mut B, i: u8) -> B::V<W64> {
    b.get(Gpr(i).state())
}

/// r0 はコンテキストによって値 0 を読む。
fn ra<B: Backend>(b: &mut B, i: u8) -> B::V<W64> {
    if i == 0 { k(b, 0) } else { g(b, i) }
}

fn s<B: Backend>(b: &mut B, i: u8, v: B::V<W64>) {
    b.set(Gpr(i).state(), v);
}

fn k<B: Backend>(b: &mut B, v: u64) -> B::V<W64> {
    b.konst::<W64>(v)
}

fn k32<B: Backend>(b: &mut B, v: u32) -> B::V<W32> {
    b.konst::<W32>(v)
}

fn k128<B: Backend>(b: &mut B, v: u128) -> B::V<W128> {
    b.konst::<W128>(v)
}

fn zero_b<B: Backend>(b: &mut B) -> B::B {
    let t = k(b, 0);
    let z = k(b, 0);
    b.cmp(Cmp::Ne, t, z)
}

fn bnot<B: Backend>(b: &mut B, c: B::B) -> B::B {
    let t = k(b, 1);
    let z = k(b, 0);
    let v = b.select(c, z, t);
    b.cmp(Cmp::Ne, v, z)
}

fn band<B: Backend>(b: &mut B, x: B::B, y: B::B) -> B::B {
    let t = k(b, 1);
    let z = k(b, 0);
    let sy = b.select(y, t, z);
    let v = b.select(x, sy, z);
    b.cmp(Cmp::Ne, v, z)
}

fn bor<B: Backend>(b: &mut B, x: B::B, y: B::B) -> B::B {
    let t = k(b, 1);
    let z = k(b, 0);
    let sy = b.select(y, t, z);
    let v = b.select(x, t, sy);
    b.cmp(Cmp::Ne, v, z)
}

fn bsel64<B: Backend>(b: &mut B, c: B::B, t: u64, f: u64) -> B::V<W64> {
    let tv = k(b, t);
    let fv = k(b, f);
    b.select(c, tv, fv)
}

// ---------------- CR/XER ----------------

/// CR フィールド i（0–7）の 4 ビット。
fn crf<B: Backend>(b: &mut B, i: u8) -> B::V<W64> {
    let sh = k(b, 28 - 4 * u64::from(i.min(7)));
    let cr = b.get(cr_ref());
    let v = b.shr_l(cr, sh);
    let __h0 = k(b, 0xf);
    b.and(v, __h0)
}

fn set_crf<B: Backend>(b: &mut B, i: u8, v: B::V<W64>) {
    let sh = 28 - 4 * u64::from(i.min(7));
    let cr = b.get(cr_ref());
    let __h1 = k(b, !(0xfu64 << sh));
    let keep = b.and(cr, __h1);
    let __h2 = k(b, 0xf);
    let bits = b.and(v, __h2);
    let __h3 = k(b, sh);
    let put = b.shl(bits, __h3);
    let __h4 = b.or(keep, put);
    b.set(cr_ref(), __h4);
}

/// CR ビット bi（IBM 0–31）を B 値で読む。
fn cr_bit<B: Backend>(b: &mut B, bi: u8) -> B::B {
    let sh = k(b, 31 - u64::from(bi.min(31)));
    let cr = b.get(cr_ref());
    let v = b.shr_l(cr, sh);
    let __h5 = k(b, 1);
    let bit = b.and(v, __h5);
    let __h6 = k(b, 0);
    b.cmp(Cmp::Ne, bit, __h6)
}

fn set_cr_bit<B: Backend>(b: &mut B, bi: u8, v: B::V<W64>) {
    let sh = 31 - u64::from(bi.min(31));
    let cr = b.get(cr_ref());
    let __h7 = k(b, !(1u64 << sh));
    let keep = b.and(cr, __h7);
    let __h8 = k(b, 1);
    let bit = b.and(v, __h8);
    let __h9 = k(b, sh);
    let put = b.shl(bit, __h9);
    let __h10 = b.or(keep, put);
    b.set(cr_ref(), __h10);
}

fn xer_so<B: Backend>(b: &mut B) -> B::V<W64> {
    let x = b.get(xer_ref());
    let __h11 = k(b, 31);
    let v = b.shr_l(x, __h11);
    let __h12 = k(b, 1);
    b.and(v, __h12)
}

/// 結果の符号で CR0 を記録（Rc 命令）。SO は XER.SO。
fn record_cr0<B: Backend>(b: &mut B, v: B::V<W64>) {
    let zero = k(b, 0);
    let lt = b.cmp(Cmp::LtS, v, zero);
    let eq = b.cmp(Cmp::Eq, v, zero);
    let ltf = bsel64(b, lt, CR_LT, 0);
    let __h14 = k(b, CR_GT);
    let __h13 = k(b, CR_EQ);
    let eqf = b.select(eq, __h13, __h14);
    let f1 = b.or(ltf, eqf);
    let __h15 = xer_so(b);
    let f = b.or(f1, __h15);
    set_crf(b, 0, f);
}

/// 比較。l=false は 32 ビット（符号なし比較は zext、符号ありは sext で
/// 揃えてから 64 ビットの演算に乗せる）。
fn do_cmp<B: Backend>(b: &mut B, bf: u8, l: bool, logical: bool, a: B::V<W64>, x: B::V<W64>) {
    let (a, x) = if l {
        (a, x)
    } else {
        let a32 = b.trunc::<W64, W32>(a);
        let x32 = b.trunc::<W64, W32>(x);
        if logical {
            (b.zext::<W32, W64>(a32), b.zext::<W32, W64>(x32))
        } else {
            (b.sext::<W32, W64>(a32), b.sext::<W32, W64>(x32))
        }
    };
    let lt_op = if logical { Cmp::LtU } else { Cmp::LtS };
    let gt_op = if logical { Cmp::GtU } else { Cmp::GtS };
    let lt = b.cmp(lt_op, a, x);
    let gt = b.cmp(gt_op, a, x);
    let eq = b.cmp(Cmp::Eq, a, x);
    let ltf = bsel64(b, lt, CR_LT, 0);
    let gtf = bsel64(b, gt, CR_GT, 0);
    let eqf = bsel64(b, eq, CR_EQ, 0);
    let f1 = b.or(ltf, gtf);
    let __h16 = xer_so(b);
    let f2 = b.or(eqf, __h16);
    let f = b.or(f1, f2);
    set_crf(b, bf, f);
}

fn set_ca<B: Backend>(b: &mut B, c: B::B) {
    let x = b.get(xer_ref());
    let __h17 = k(b, XER_CA);
    let set = b.or(x, __h17);
    let __h18 = k(b, !XER_CA);
    let clr = b.and(x, __h18);
    let __h19 = b.select(c, set, clr);
    b.set(xer_ref(), __h19);
}

fn ca<B: Backend>(b: &mut B) -> B::V<W64> {
    let x = b.get(xer_ref());
    let __h20 = k(b, 29);
    let v = b.shr_l(x, __h20);
    let __h21 = k(b, 1);
    b.and(v, __h21)
}

/// OV を書く。セット時は SO も立つ。
fn set_ov<B: Backend>(b: &mut B, ov: B::B) {
    let x = b.get(xer_ref());
    let __h22 = k(b, XER_OV | XER_SO);
    let set = b.or(x, __h22);
    let __h23 = k(b, !XER_OV);
    let clr = b.and(x, __h23);
    let __h24 = b.select(ov, set, clr);
    b.set(xer_ref(), __h24);
}

/// a+x の符号オーバーフロー。
fn ov_add<B: Backend>(b: &mut B, a: B::V<W64>, x: B::V<W64>, r: B::V<W64>) -> B::B {
    let ax = b.xor(a, x);
    let __h25 = k(b, 0);
    let same = b.cmp(Cmp::GeS, ax, __h25);
    let ar = b.xor(a, r);
    let __h26 = k(b, 0);
    let diff = b.cmp(Cmp::LtS, ar, __h26);
    band(b, same, diff)
}

/// a-x の符号オーバーフロー（= a+~x+1）。
fn ov_sub<B: Backend>(b: &mut B, a: B::V<W64>, x: B::V<W64>, r: B::V<W64>) -> B::B {
    let ax = b.xor(a, x);
    let __h27 = k(b, 0);
    let diff = b.cmp(Cmp::LtS, ax, __h27);
    let ar = b.xor(a, r);
    let __h28 = k(b, 0);
    let same = b.cmp(Cmp::LtS, ar, __h28);
    let __h29 = bnot(b, same);
    band(b, diff, __h29)
}

/// BO/BI の条件判定。成立なら B 値 true。
/// BO は 5 ビットで IBM 番号 BO0（値の bit4=0x10）から BO4（bit0）。
/// BO2=0 で CTR デクリメント、BO0=0 で条件検査。
fn bo_ok<B: Backend>(b: &mut B, bo: u8, bi: u8) -> B::B {
    let mut ok = k(b, 1u64);
    let __h31 = k(b, 0);
    if bo & 4 == 0 {
        let one = k(b, 1);
        let c0 = b.get(ctr_ref());
        let c = b.sub(c0, one);
        b.set(ctr_ref(), c);
        let __h30 = k(b, 0);
        let nz = b.cmp(Cmp::Ne, c, __h30);
        let t = if bo & 2 != 0 { bnot(b, nz) } else { nz };
        let tv = bsel64(b, t, 1, 0);
        ok = b.and(ok, tv);
    }
    if bo & 0x10 == 0 {
        let cb = cr_bit(b, bi);
        let t = if bo & 8 != 0 { cb } else { bnot(b, cb) };
        let tv = bsel64(b, t, 1, 0);
        ok = b.and(ok, tv);
    }
    b.cmp(Cmp::Ne, ok, __h31)
}

// ---------------- 即値演算 ----------------

/// addi/addis/li/lis。
fn addi_i<B: Backend>(b: &mut B, rt: u8, r: u8, imm: i64, shifted: bool) -> Flow<B> {
    let v = if shifted { imm << 16 } else { imm };
    let a = ra(b, r);
    let x = k(b, v as u64);
    let res = b.add(a, x);
    s(b, rt, res);
    Ok(())
}

/// addic/addic.。CA 記録、Rc で CR0 も。
fn addic_i<B: Backend>(b: &mut B, rt: u8, r: u8, imm: i64, rc: bool) -> Flow<B> {
    let a = g(b, r);
    let x = k(b, imm as u64);
    let res = b.add(a, x);
    let cry = b.cmp(Cmp::LtU, res, a);
    set_ca(b, cry);
    s(b, rt, res);
    if rc {
        record_cr0(b, res);
    }
    Ok(())
}

/// subfic: rT = imm - rA。CA は imm >=u rA。
fn subfic_i<B: Backend>(b: &mut B, rt: u8, r: u8, imm: i64) -> Flow<B> {
    let a = g(b, r);
    let x = k(b, imm as u64);
    let res = b.sub(x, a);
    let cry = b.cmp(Cmp::LeU, a, x);
    set_ca(b, cry);
    s(b, rt, res);
    Ok(())
}

/// mulli。
fn mulli_i<B: Backend>(b: &mut B, rt: u8, r: u8, imm: i64) -> Flow<B> {
    let a = g(b, r);
    let x = k(b, imm as u64);
    let res = b.mul(a, x);
    s(b, rt, res);
    Ok(())
}

/// ori/oris/xori/xoris（op: 1=or, 2=xor。imm は既シフト済みで渡す）。
fn log_imm<B: Backend>(b: &mut B, ra_d: u8, rs: u8, imm: u64, op: u8) -> Flow<B> {
    let a = g(b, rs);
    let x = k(b, imm);
    let v = if op == 1 { b.or(a, x) } else { b.xor(a, x) };
    s(b, ra_d, v);
    Ok(())
}

/// andi./andis.。
fn andi_rc_i<B: Backend>(b: &mut B, ra_d: u8, rs: u8, imm: u64) -> Flow<B> {
    let a = g(b, rs);
    let x = k(b, imm);
    let v = b.and(a, x);
    s(b, ra_d, v);
    record_cr0(b, v);
    Ok(())
}

/// cmpwi/cmpdi。
fn cmp_imm<B: Backend>(b: &mut B, bf: u8, l: bool, r: u8, imm: i64) -> Flow<B> {
    let a = g(b, r);
    let x = k(b, imm as u64);
    do_cmp(b, bf, l, false, a, x);
    Ok(())
}

/// cmplwi/cmpldi。
fn cmpl_imm<B: Backend>(b: &mut B, bf: u8, l: bool, r: u8, imm: u64) -> Flow<B> {
    let a = g(b, r);
    let x = k(b, imm);
    do_cmp(b, bf, l, true, a, x);
    Ok(())
}

/// TO 条件が成立すれば Trap 例外を上げる。
fn trap_if<B: Backend>(b: &mut B, to: u8, l: bool, a: B::V<W64>, x: B::V<W64>) -> Flow<B> {
    let (as_, au) = if l {
        (a, a)
    } else {
        let a32 = b.trunc::<W64, W32>(a);
        (b.sext::<W32, W64>(a32), b.zext::<W32, W64>(a32))
    };
    let (xs, xu) = if l {
        (x, x)
    } else {
        let x32 = b.trunc::<W64, W32>(x);
        (b.sext::<W32, W64>(x32), b.zext::<W32, W64>(x32))
    };
    let ff = zero_b(b);
    let c1 = if to & 16 != 0 {
        b.cmp(Cmp::LtS, as_, xs)
    } else {
        ff
    };
    let c2 = if to & 8 != 0 {
        b.cmp(Cmp::GtS, as_, xs)
    } else {
        ff
    };
    let c3 = if to & 4 != 0 {
        b.cmp(Cmp::Eq, au, xu)
    } else {
        ff
    };
    let c4 = if to & 2 != 0 {
        b.cmp(Cmp::LtU, au, xu)
    } else {
        ff
    };
    let c5 = if to & 1 != 0 {
        b.cmp(Cmp::GtU, au, xu)
    } else {
        ff
    };
    let o1 = bor(b, c1, c2);
    let o2 = bor(b, c3, c4);
    let o3 = bor(b, o1, o2);
    let hit = bor(b, o3, c5);
    b.if_then(hit, |b| {
        Err(b.raise(GuestException {
            kind: ExceptionKind::Trap,
            code: 0,
            addr: None,
            in_delay_slot: false,
        }))
    })
}

/// tdi/twi。
fn trap_imm<B: Backend>(b: &mut B, to: u8, l: bool, r: u8, imm: i64) -> Flow<B> {
    let a = g(b, r);
    let x = k(b, imm as u64);
    trap_if(b, to, l, a, x)
}

// ---------------- 分岐 ----------------

/// b/bl。
fn branch_i<B: Backend>(b: &mut B, pc: u64, li: i64, aa: bool, lk: bool) -> Flow<B> {
    if lk {
        let ret = k(b, pc + 4);
        b.set(lr_ref(), ret);
    }
    let t = if aa {
        (li << 2) as u64
    } else {
        pc.wrapping_add((li << 2) as u64)
    };
    let tv = k(b, t);
    b.jump(tv);
    Ok(())
}

/// bc/bcl。
fn branch_cond_i<B: Backend>(
    b: &mut B,
    pc: u64,
    bo: u8,
    bi: u8,
    bd: i64,
    aa: bool,
    lk: bool,
) -> Flow<B> {
    let t = if aa {
        (bd << 2) as u64
    } else {
        pc.wrapping_add((bd << 2) as u64)
    };
    let ok = bo_ok(b, bo, bi);
    if lk {
        let ret = k(b, pc + 4);
        b.set(lr_ref(), ret);
    }
    b.branch(ok, t);
    Ok(())
}

/// op19（XL 形式）。bclr/bcctr/CR 論理/mcrf/isync。
fn xl19<B: Backend>(b: &mut B, pc: u64, word: u32) -> Flow<B> {
    let xo = (word >> 1) & 0x3ff;
    let bo = ((word >> 21) & 31) as u8;
    let bi = ((word >> 16) & 31) as u8;
    let lk = word & 1 != 0;
    match xo {
        // bclr/bclrl。
        16 => {
            let ok = bo_ok(b, bo, bi);
            if lk {
                let ret = k(b, pc + 4);
                b.set(lr_ref(), ret);
            }
            let t0 = b.get(lr_ref());
            let __h32 = k(b, !3u64);
            let t = b.and(t0, __h32);
            b.if_then(ok, |b| {
                b.jump(t);
                Ok(())
            })
        }
        // bcctr/bcctrl。
        528 => {
            // CTR デクリメントは行わない（BO0 を立てる）。CTR 検査は
            // 生の CTR に対して行われる。
            let ok = bo_ok(b, bo | 0x10, bi);
            if lk {
                let ret = k(b, pc + 4);
                b.set(lr_ref(), ret);
            }
            let t0 = b.get(ctr_ref());
            let __h33 = k(b, !3u64);
            let t = b.and(t0, __h33);
            b.if_then(ok, |b| {
                b.jump(t);
                Ok(())
            })
        }
        // isync。
        150 => Ok(()),
        // mcrf。
        0 => {
            let dst = ((word >> 23) & 7) as u8;
            let src = ((word >> 18) & 7) as u8;
            let v = crf(b, src);
            set_crf(b, dst, v);
            Ok(())
        }
        // CR 論理（crnor=33,crandc=129,crxor=193,crnand=225,
        // crand=257,creqv=289,crorc=417,cror=449）。
        33 | 129 | 193 | 225 | 257 | 289 | 417 | 449 => {
            let bt = ((word >> 21) & 31) as u8;
            let ba = ((word >> 16) & 31) as u8;
            let bb = ((word >> 11) & 31) as u8;
            let __h34 = cr_bit(b, ba);
            let av = bsel64(b, __h34, 1, 0);
            let __h35 = cr_bit(b, bb);
            let bv = bsel64(b, __h35, 1, 0);
            let r = match xo {
                33 => {
                    let __h36 = b.or(av, bv);
                    b.not(__h36)
                }
                129 => {
                    let __h37 = b.not(bv);
                    b.and(av, __h37)
                }
                193 => b.xor(av, bv),
                225 => {
                    let __h38 = b.and(av, bv);
                    b.not(__h38)
                }
                257 => b.and(av, bv),
                289 => {
                    let __h39 = b.xor(av, bv);
                    b.not(__h39)
                }
                417 => {
                    let __h40 = b.not(bv);
                    b.or(av, __h40)
                }
                _ => b.or(av, bv),
            };
            set_cr_bit(b, bt, r);
            Ok(())
        }
        _ => unimp(b, u64::from(xo)),
    }
}

// ---------------- ロード・ストア ----------------

/// D 形式ロード。
#[allow(clippy::too_many_arguments)]
fn ld_d<B: Backend>(
    b: &mut B,
    rt: u8,
    r: u8,
    imm: i64,
    size: u32,
    sign: bool,
    upd: bool,
    le: bool,
) -> Flow<B> {
    let a = ra(b, r);
    let off = k(b, imm as u64);
    let ea = b.add(a, off);
    let acc = data_acc(le, true);
    let v: B::V<W64> = match size {
        1 => {
            let w = b.load::<W8>(ea, acc)?;
            b.zext::<W8, W64>(w)
        }
        2 => {
            let w = b.load::<W16>(ea, acc)?;
            if sign {
                b.sext::<W16, W64>(w)
            } else {
                b.zext::<W16, W64>(w)
            }
        }
        4 => {
            let w = b.load::<W32>(ea, acc)?;
            if sign {
                b.sext::<W32, W64>(w)
            } else {
                b.zext::<W32, W64>(w)
            }
        }
        _ => b.load::<W64>(ea, acc)?,
    };
    s(b, rt, v);
    if upd {
        s(b, r, ea);
    }
    Ok(())
}

/// D 形式ストア。
fn st_d<B: Backend>(b: &mut B, rs: u8, r: u8, imm: i64, size: u32, upd: bool, le: bool) -> Flow<B> {
    let a = ra(b, r);
    let off = k(b, imm as u64);
    let ea = b.add(a, off);
    let acc = data_acc(le, false);
    let v = g(b, rs);
    match size {
        1 => {
            let w = b.trunc::<W64, W8>(v);
            b.store::<W8>(ea, w, acc)?;
        }
        2 => {
            let w = b.trunc::<W64, W16>(v);
            b.store::<W16>(ea, w, acc)?;
        }
        4 => {
            let w = b.trunc::<W64, W32>(v);
            b.store::<W32>(ea, w, acc)?;
        }
        _ => b.store::<W64>(ea, v, acc)?,
    }
    if upd {
        s(b, r, ea);
    }
    Ok(())
}

/// lmw。rT から r31 まで連続した 4 バイトを転送。
fn lmw_i<B: Backend>(b: &mut B, rt: u8, r: u8, imm: i64, le: bool) -> Flow<B> {
    let base = ra(b, r);
    let off = k(b, imm as u64);
    let ea0 = b.add(base, off);
    let acc = data_acc(le, true);
    for (n, i) in (rt..32).enumerate() {
        let __h41 = k(b, (n as u64) * 4);
        let a = b.add(ea0, __h41);
        let w = b.load::<W32>(a, acc)?;
        let v = b.zext::<W32, W64>(w);
        s(b, i, v);
    }
    Ok(())
}

/// stmw。
fn stmw_i<B: Backend>(b: &mut B, rs: u8, r: u8, imm: i64, le: bool) -> Flow<B> {
    let base = ra(b, r);
    let off = k(b, imm as u64);
    let ea0 = b.add(base, off);
    let acc = data_acc(le, false);
    for (n, i) in (rs..32).enumerate() {
        let __h42 = k(b, (n as u64) * 4);
        let a = b.add(ea0, __h42);
        let v = g(b, i);
        let w = b.trunc::<W64, W32>(v);
        b.store::<W32>(a, w, acc)?;
    }
    Ok(())
}

// ---------------- 回転・マスク ----------------

fn mask32(begin: u8, end: u8) -> u64 {
    let (x, y) = (u64::from(begin & 31), u64::from(end & 31));
    let all = 0xffff_ffffu64;
    if x <= y {
        (all >> x) & (all << (31 - y))
    } else {
        (all >> x) | (all << (31 - y))
    }
}

fn mask64(begin: u8, end: u8) -> u64 {
    let (x, y) = (u64::from(begin & 63), u64::from(end & 63));
    if x <= y {
        (u64::MAX >> x) & (u64::MAX << (63 - y))
    } else {
        (u64::MAX >> x) | (u64::MAX << (63 - y))
    }
}

/// 32 ビットの左回転（W64 の中の下位 32 ビットを回転）。
fn rotl32<B: Backend>(b: &mut B, v: B::V<W64>, n: B::V<W64>) -> B::V<W64> {
    let __h43 = k(b, 0xffff_ffff);
    let w = b.and(v, __h43);
    let __h44 = k(b, 32);
    let hi = b.shl(w, __h44);
    let w2 = b.or(w, hi);
    let __h45 = k(b, 31);
    let n32 = b.and(n, __h45);
    let l = b.shl(w2, n32);
    let __h46 = k(b, 0xffff_ffff);
    let lm = b.and(l, __h46);
    let __h47 = k(b, 32);
    let inv = b.sub(__h47, n32);
    let r = b.shr_l(w2, inv);
    b.or(lm, r)
}

/// rlwinm/rlwimi/rlwnm。`insert` ならマスク外は RA を残す。
fn rlm<B: Backend>(
    b: &mut B,
    ra_d: u8,
    rs: u8,
    n: B::V<W64>,
    mbe: (u8, u8),
    insert: bool,
    rc: bool,
) -> Flow<B> {
    let (mb, me) = mbe;
    let src = g(b, rs);
    let r = rotl32(b, src, n);
    let m = k(b, mask32(mb, me));
    let __h49 = b.not(m);
    let __h48 = g(b, ra_d);
    let v = if insert {
        let keep = b.and(__h48, __h49);
        let ins = b.and(r, m);
        b.or(ins, keep)
    } else {
        b.and(r, m)
    };
    s(b, ra_d, v);
    if rc {
        record_cr0(b, v);
    }
    Ok(())
}

/// rlwinm（sldi/clrlwi/clrrwi/rotlwi 等の別名を含む）。
fn rlwinm_i<B: Backend>(b: &mut B, ra_d: u8, rs: u8, sh: u8, mb: u8, me: u8, rc: bool) -> Flow<B> {
    let n = k(b, u64::from(sh));
    rlm(b, ra_d, rs, n, (mb, me), false, rc)
}

/// rlwimi。
fn rlwimi_i<B: Backend>(b: &mut B, ra_d: u8, rs: u8, sh: u8, mb: u8, me: u8, rc: bool) -> Flow<B> {
    let n = k(b, u64::from(sh));
    rlm(b, ra_d, rs, n, (mb, me), true, rc)
}

/// rlwnm。
fn rlwnm_i<B: Backend>(b: &mut B, ra_d: u8, rs: u8, rb: u8, mb: u8, me: u8, rc: bool) -> Flow<B> {
    let n = g(b, rb);
    rlm(b, ra_d, rs, n, (mb, me), false, rc)
}

/// 64 ビットの左回転（シンボリック n）。n=0 は素通し。
/// n=0 のとき `v >> (64-n)` が 64 ビットシフトになるので 1 に詰める。
fn rotl64<B: Backend>(b: &mut B, v: B::V<W64>, n: B::V<W64>) -> B::V<W64> {
    let __h50 = k(b, 63);
    let n6 = b.and(n, __h50);
    let lo = b.shl(v, n6);
    let __h51 = k(b, 0);
    let nz = b.cmp(Cmp::Eq, n6, __h51);
    let __h52 = k(b, 64);
    let inv0 = b.sub(__h52, n6);
    let __h53 = k(b, 1);
    let inv = b.select(nz, __h53, inv0);
    let hi = b.shr_l(v, inv);
    let rot = b.or(lo, hi);
    b.select(nz, v, rot)
}

/// op30（MD 形式）。rldicl/rldicr/rldic/rldimi。
fn rld<B: Backend>(b: &mut B, ra_d: u8, rs: u8, word: u32, rc: bool) -> Flow<B> {
    let sh = (((word >> 11) & 31) | (((word >> 1) & 1) << 5)) as u8;
    let m6 = (((word >> 6) & 31) | (((word >> 5) & 1) << 5)) as u8;
    let xo3 = (word >> 2) & 7;
    let src = g(b, rs);
    // MDS 形式（rldcl/rldcr、xo3=4|5）はシフト量を RB レジスタから取る。
    // sh フィールドの位置が RB 番号になる。
    let n = if xo3 >= 4 {
        let rb = ((word >> 11) & 31) as u8;
        g(b, rb)
    } else {
        k(b, u64::from(sh))
    };
    let r = rotl64(b, src, n);
    let v = match xo3 {
        // rldicl/rldcl: rotl(n) & mask(mb,63)。
        0 | 4 => {
            let m = k(b, mask64(m6, 63));
            b.and(r, m)
        }
        // rldicr/rldcr: rotl(n) & mask(0,me)。
        1 | 5 => {
            let m = k(b, mask64(0, m6));
            b.and(r, m)
        }
        // rldic: rotl(sh) & mask(mb,63-sh)。sh=0 は mask(mb,63)。
        2 => {
            let end = (63u8).wrapping_sub(sh) & 63;
            let m = k(b, mask64(m6, end));
            b.and(r, m)
        }
        // rldimi: マスク内は回転値、外は RA を残す。mask(mb,63-sh)。
        3 => {
            let end = (63u8).wrapping_sub(sh) & 63;
            let mm = k(b, mask64(m6, end));
            let __h55 = b.not(mm);
            let __h54 = g(b, ra_d);
            let keep = b.and(__h54, __h55);
            let ins = b.and(r, mm);
            b.or(ins, keep)
        }
        _ => return unimp(b, u64::from(xo3)),
    };
    s(b, ra_d, v);
    if rc {
        record_cr0(b, v);
    }
    Ok(())
}

// ---------------- FPR/VSR の読み書き ----------------

/// FPR i（=VSR[i] の IBM 上位 64 ビット）を読む。
fn fpr<B: Backend>(b: &mut B, i: u8) -> B::V<W64> {
    let v = b.get(Vsr(i).state());
    let sh = k128(b, 64);
    let hi = b.shr_l(v, sh);
    b.trunc::<W128, W64>(hi)
}

/// FPR i に書く。下位 64 ビットは 0 にする。
fn set_fpr<B: Backend>(b: &mut B, i: u8, v: B::V<W64>) {
    let w = b.zext::<W64, W128>(v);
    let __h56 = k128(b, 64);
    let wide = b.shl(w, __h56);
    b.set(Vsr(i).state(), wide);
}

fn vsr<B: Backend>(b: &mut B, i: u8) -> B::V<W128> {
    b.get(Vsr(i).state())
}

fn set_vsr<B: Backend>(b: &mut B, i: u8, v: B::V<W128>) {
    b.set(Vsr(i).state(), v);
}

/// VSR の IBM 上位 64 ビット（dw0）。
fn vsr_hi<B: Backend>(b: &mut B, i: u8) -> B::V<W64> {
    let v = vsr(b, i);
    let __h57 = k128(b, 64);
    let hi = b.shr_l(v, __h57);
    b.trunc::<W128, W64>(hi)
}

/// VSR の IBM 下位 64 ビット（dw1）。
fn vsr_lo<B: Backend>(b: &mut B, i: u8) -> B::V<W64> {
    let v = vsr(b, i);
    b.trunc::<W128, W64>(v)
}

fn vsr_pack<B: Backend>(b: &mut B, hi: B::V<W64>, lo: B::V<W64>) -> B::V<W128> {
    let h = b.zext::<W64, W128>(hi);
    let __h58 = k128(b, 64);
    let hs = b.shl(h, __h58);
    let l = b.zext::<W64, W128>(lo);
    b.or(hs, l)
}

/// 64 ビット値を VSR の dw0（IBM 上位）に置く。
fn put_dw0<B: Backend>(b: &mut B, v: B::V<W64>) -> B::V<W128> {
    let w = b.zext::<W64, W128>(v);
    let __h59 = k128(b, 64);
    b.shl(w, __h59)
}

// ---------------- op31（X 形式） ----------------

/// 加減算（op1 + op2 + cin の形に正規化し、128 ビットで桁上がりを取る）。
fn x31_arith<B: Backend>(
    b: &mut B,
    _word: u32,
    xo: u32,
    t: u8,
    a: u8,
    bb: u8,
    rc_oe: (bool, bool),
) -> Flow<B> {
    let (rc, oe) = rc_oe;
    let x = g(b, a);
    let y = g(b, bb);
    let (op1, op2, cin): (B::V<W64>, B::V<W64>, B::V<W64>) = match xo {
        // subfc/subf: y + ~x + 1。
        8 | 40 => {
            let nx = b.not(x);
            (y, nx, k(b, 1))
        }
        // subfe: ~x + y + CA（RT = RA - RB + CA - 1 …… 実際は x + ~y + CA ではなく
        // rA - rB = rA + ~rB + 1 なので subfe は ~x + y + CA）。
        136 => {
            let nx = b.not(x);
            let c = ca(b);
            (nx, y, c)
        }
        // subfze: ~x + CA。
        200 => {
            let nx = b.not(x);
            let c = ca(b);
            (nx, k(b, 0), c)
        }
        // subfme: ~x + ~0 + CA = ~x - 1 + CA。
        232 => {
            let nx = b.not(x);
            let c = ca(b);
            (nx, k(b, !0u64), c)
        }
        // adde。
        138 => {
            let c = ca(b);
            (x, y, c)
        }
        // addze。
        202 => {
            let c = ca(b);
            (x, k(b, 0), c)
        }
        // addme。
        234 => {
            let c = ca(b);
            (x, k(b, !0u64), c)
        }
        // add/addc。
        266 | 10 => (x, y, k(b, 0)),
        // neg: 0 - x。
        _ => {
            let nx = b.not(x);
            (k(b, 0), nx, k(b, 1))
        }
    };
    let w1 = b.zext::<W64, W128>(op1);
    let w2 = b.zext::<W64, W128>(op2);
    let w3 = b.zext::<W64, W128>(cin);
    let s12 = b.add(w1, w2);
    let wide = b.add(s12, w3);
    let r = b.trunc::<W128, W64>(wide);
    let __h60 = k128(b, 64);
    let cy = b.shr_l(wide, __h60);
    let cy64 = b.trunc::<W128, W64>(cy);
    let __h61 = k(b, 0);
    let carry = b.cmp(Cmp::Ne, cy64, __h61);
    s(b, t, r);
    // CA を更新するのはキャリアウトを定義する形式だけ。
    // subf(40)・add(266) は CA を触らない（subfc/addc/e 系だけが書く）。
    if matches!(xo, 8 | 10 | 104 | 136 | 138 | 200 | 202 | 232 | 234) {
        set_ca(b, carry);
    }
    if oe {
        // subf 系は減算のオーバーフロー。
        let ov = if xo == 8 || xo == 40 {
            ov_sub(b, y, x, r)
        } else if matches!(xo, 104 | 200 | 202 | 232 | 234) {
            // 単項＋CA。ov はエッジ値と CA の組み合わせ。
            // neg: x=MIN / subfze: x=MIN&&CA / addze: x=MAX&&CA /
            // subfme: x=MAX&&!CA / addme: x=MIN&&!CA。
            let (v, edge, want_ca) = match xo {
                200 => (x, i64::MIN as u64, true),
                202 => (x, i64::MAX as u64, true),
                232 => (x, i64::MAX as u64, false),
                234 => (x, i64::MIN as u64, false),
                _ => (x, i64::MIN as u64, true),
            };
            let __h62 = k(b, edge);
            let at = b.cmp(Cmp::Eq, v, __h62);
            if xo == 104 {
                at
            } else {
                let __h64 = k(b, 0);
                let __h63 = ca(b);
                let cb = b.cmp(Cmp::Ne, __h63, __h64);
                let cb = if want_ca { cb } else { bnot(b, cb) };
                band(b, at, cb)
            }
        } else {
            // add/addc/adde/subfe: op2+cin を一つの項として近似。
            let c2 = b.add(op2, cin);
            ov_add(b, op1, c2, r)
        };
        set_ov(b, ov);
    }
    if rc {
        record_cr0(b, r);
    }
    Ok(())
}

/// 乗算（mulhw/mulhwu/mulhd/mulhdu/mulld/mullw）。OE は積が幅に
/// 収まらないことで判定する。
fn x31_mul<B: Backend>(b: &mut B, xo: u32, t: u8, a: u8, bb: u8, rc: bool, oe: bool) -> Flow<B> {
    let x = g(b, a);
    let y = g(b, bb);
    let r = match xo {
        75 => {
            // mulhw: 上位 32 ビット（符号付き）。
            let x32 = b.trunc::<W64, W32>(x);
            let y32 = b.trunc::<W64, W32>(y);
            let sx = b.sext::<W32, W64>(x32);
            let sy = b.sext::<W32, W64>(y32);
            let p = b.mul(sx, sy);
            let __h65 = k(b, 32);
            b.shr_a(p, __h65)
        }
        11 => {
            // mulhwu: 上位 32 ビット（符号なし）。
            let x32 = b.trunc::<W64, W32>(x);
            let y32 = b.trunc::<W64, W32>(y);
            let ux = b.zext::<W32, W64>(x32);
            let uy = b.zext::<W32, W64>(y32);
            let p = b.mul(ux, uy);
            let __h66 = k(b, 32);
            b.shr_l(p, __h66)
        }
        73 => b.mulh(x, y),
        9 => b.mulhu(x, y),
        233 => b.mul(x, y),
        _ => {
            // mullw: 下位 32 ビット積の符号拡張。
            let x32 = b.trunc::<W64, W32>(x);
            let y32 = b.trunc::<W64, W32>(y);
            let z = b.mul::<W32>(x32, y32);
            b.sext::<W32, W64>(z)
        }
    };
    s(b, t, r);
    if oe {
        let ov = match xo {
            // mulld: 128 ビット積の上位が下位の符号反復でなければ OV。
            233 => {
                let hi = b.mulh(x, y);
                let lo = b.mul(x, y);
                let __h67 = k(b, 63);
                let se = b.shr_a(lo, __h67);
                b.cmp(Cmp::Ne, hi, se)
            }
            // mullw: 32 ビット積に収まらなければ OV。
            235 => {
                let x32 = b.trunc::<W64, W32>(x);
                let y32 = b.trunc::<W64, W32>(y);
                let sx = b.sext::<W32, W64>(x32);
                let sy = b.sext::<W32, W64>(y32);
                let p = b.mul(sx, sy);
                let p32 = b.trunc::<W64, W32>(p);
                let back = b.sext::<W32, W64>(p32);
                b.cmp(Cmp::Ne, p, back)
            }
            _ => zero_b(b),
        };
        set_ov(b, ov);
    }
    if rc {
        record_cr0(b, r);
    }
    Ok(())
}

/// 除算・剰余（divd/divdu/divde/divdeu/divw/divwu/divwe/divweu/mod*）。
fn x31_div<B: Backend>(b: &mut B, xo: u32, t: u8, a: u8, bb: u8, rc: bool) -> Flow<B> {
    let x = g(b, a);
    let y = g(b, bb);
    let w = matches!(xo, 491 | 459 | 427 | 395 | 267 | 779);
    let signed = matches!(xo, 489 | 491 | 425 | 427 | 777 | 779);
    let rem = matches!(xo, 265 | 267 | 777 | 779);
    let (xa, xb) = if w {
        if signed {
            let a32 = b.trunc::<W64, W32>(x);
            let b32 = b.trunc::<W64, W32>(y);
            (b.sext::<W32, W64>(a32), b.sext::<W32, W64>(b32))
        } else {
            let a32 = b.trunc::<W64, W32>(x);
            let b32 = b.trunc::<W64, W32>(y);
            (b.zext::<W32, W64>(a32), b.zext::<W32, W64>(b32))
        }
    } else {
        (x, y)
    };
    let zero = k(b, 0);
    let dz = b.cmp(Cmp::Eq, xb, zero);
    let q = if rem {
        if signed {
            b.srem(xa, xb)
        } else {
            b.urem(xa, xb)
        }
    } else if signed {
        b.sdiv(xa, xb)
    } else {
        b.udiv(xa, xb)
    };
    // 0 除算・INT_MIN/-1 は未定義。0/値に寄せる。
    let q = b.select(dz, zero, q);
    let r = if w {
        let q32 = b.trunc::<W64, W32>(q);
        b.sext::<W32, W64>(q32)
    } else {
        q
    };
    s(b, t, r);
    if rc {
        record_cr0(b, r);
    }
    Ok(())
}

/// シフト・拡張・数え上げ系（XO の中の一群）。
#[allow(clippy::too_many_lines)]
fn x31_shift<B: Backend>(b: &mut B, word: u32, xo: u32, t: u8, a: u8, bb: u8, rc: bool) -> Flow<B> {
    let x = g(b, t);
    let y = g(b, bb);
    let __h68 = k(b, 63);
    let n6 = b.and(y, __h68);
    let r = match xo {
        24 => {
            let __h69 = k(b, 31);
            // slw: n>=32 は 0。32 ビット結果はゼロ拡張で置く。
            let n = b.and(y, __h69);
            let __h70 = k(b, 31);
            let big = b.cmp(Cmp::GtU, n6, __h70);
            let x32 = b.trunc::<W64, W32>(x);
            let __h71 = b.trunc::<W64, W32>(n);
            let z = b.shl::<W32>(x32, __h71);
            let res = b.zext::<W32, W64>(z);
            let __h72 = k(b, 0);
            b.select(big, __h72, res)
        }
        27 => {
            let big = {
                let __h73 = k(b, 64);
                let h = b.and(y, __h73);
                let __h74 = k(b, 0);
                b.cmp(Cmp::Ne, h, __h74)
            };
            let z = b.shl(x, n6);
            let __h75 = k(b, 0);
            b.select(big, __h75, z)
        }
        536 => {
            let __h76 = k(b, 31);
            // srw。
            let n = b.and(y, __h76);
            let __h77 = k(b, 31);
            let big = b.cmp(Cmp::GtU, n6, __h77);
            let x32 = b.trunc::<W64, W32>(x);
            let __h78 = b.trunc::<W64, W32>(n);
            let z = b.shr_l::<W32>(x32, __h78);
            let res = b.zext::<W32, W64>(z);
            let __h79 = k(b, 0);
            b.select(big, __h79, res)
        }
        539 => {
            // srd。
            let big = {
                let __h80 = k(b, 64);
                let h = b.and(y, __h80);
                let __h81 = k(b, 0);
                b.cmp(Cmp::Ne, h, __h81)
            };
            let z = b.shr_l(x, n6);
            let __h82 = k(b, 0);
            b.select(big, __h82, z)
        }
        792 => {
            let __h83 = k(b, 31);
            // sraw: 算術右シフト＋CA（負数で 1 が出たか）。
            let n = b.and(y, __h83);
            let __h84 = k(b, 31);
            let big = b.cmp(Cmp::GtU, n6, __h84);
            let x32 = b.trunc::<W64, W32>(x);
            let sa = b.sext::<W32, W64>(x32);
            let n32 = b.trunc::<W64, W32>(n);
            let sh = b.shr_a::<W32>(x32, n32);
            let one = k(b, 1);
            let shifted_one = b.shl(one, n6);
            let lost_mask = b.sub(shifted_one, one);
            let lost_bits = b.and(x, lost_mask);
            let __h85 = k(b, 0xffff_ffff);
            let lost_low = b.and(lost_bits, __h85);
            let __h86 = k(b, 0);
            let lost = b.cmp(Cmp::Ne, lost_low, __h86);
            let __h87 = k(b, 0);
            let neg = b.cmp(Cmp::LtS, sa, __h87);
            let lo = bor(b, lost, big);
            let c = band(b, neg, lo);
            set_ca(b, c);
            let __h88 = k(b, 31);
            let sat = b.shr_a(sa, __h88);
            let res = b.sext::<W32, W64>(sh);
            b.select(big, sat, res)
        }
        794 => {
            // srad。
            let big = {
                let __h89 = k(b, 64);
                let h = b.and(y, __h89);
                let __h90 = k(b, 0);
                b.cmp(Cmp::Ne, h, __h90)
            };
            let __h91 = k(b, 63);
            let sh = b.select(big, __h91, n6);
            let __h92 = k(b, 0);
            let neg = b.cmp(Cmp::LtS, x, __h92);
            let one = k(b, 1);
            let shifted_one = b.shl(one, n6);
            let lost_mask = b.sub(shifted_one, one);
            let lost_bits = b.and(x, lost_mask);
            let __h93 = k(b, 0);
            let lost = b.cmp(Cmp::Ne, lost_bits, __h93);
            let lo = bor(b, lost, big);
            let c = band(b, neg, lo);
            set_ca(b, c);
            b.shr_a(x, sh)
        }
        824 => {
            // srawi: 即値シフト（sh は bits11-15）。
            let n = u64::from((word >> 11) & 31);
            let x32 = b.trunc::<W64, W32>(x);
            let sa = b.sext::<W32, W64>(x32);
            let __h94 = k32(b, n as u32);
            let sh = b.shr_a::<W32>(x32, __h94);
            let lost_mask = (1u64 << n) - 1;
            let __h95 = k(b, lost_mask);
            let lost_bits = b.and(x, __h95);
            let __h96 = k(b, 0);
            let lost = b.cmp(Cmp::Ne, lost_bits, __h96);
            let __h97 = k(b, 0);
            let neg = b.cmp(Cmp::LtS, sa, __h97);
            let c = band(b, neg, lost);
            set_ca(b, c);
            b.sext::<W32, W64>(sh)
        }
        826 | 827 => {
            // sradi: sh = SH | (bit1 << 5)。bit1 が立つと XO10 は 827。
            let n = u64::from(((word >> 11) & 31) | (((word >> 1) & 1) << 5));
            let lost_mask = if n == 0 { 0 } else { (1u64 << n) - 1 };
            let __h98 = k(b, lost_mask);
            let lost_bits = b.and(x, __h98);
            let __h99 = k(b, 0);
            let lost = b.cmp(Cmp::Ne, lost_bits, __h99);
            let __h100 = k(b, 0);
            let neg = b.cmp(Cmp::LtS, x, __h100);
            let c = band(b, neg, lost);
            set_ca(b, c);
            let __h101 = k(b, n);
            b.shr_a(x, __h101)
        }
        26 => {
            let __h102 = k(b, 0xffff_ffff);
            // cntlzw: 32 ビット値の先頭ゼロ。
            let w = b.and(x, __h102);
            let __h103 = k(b, 32);
            let w2 = b.shl(w, __h103);
            let c = clz64(b, w2);
            let __h104 = k(b, 64);
            let is64 = b.cmp(Cmp::Eq, c, __h104);
            let __h105 = k(b, 32);
            b.select(is64, __h105, c)
        }
        58 => clz64(b, x),
        922 => {
            let w = b.trunc::<W64, W16>(x);
            b.sext::<W16, W64>(w)
        }
        954 => {
            let w = b.trunc::<W64, W8>(x);
            b.sext::<W8, W64>(w)
        }
        986 => {
            let w = b.trunc::<W64, W32>(x);
            b.sext::<W32, W64>(w)
        }
        122 => {
            // popcntb: 各バイトのポップカウント。
            let mut v = k(b, 0);
            for i in 0..8u64 {
                let __h106 = k(b, i * 8);
                let byte0 = b.shr_l(x, __h106);
                let __h107 = k(b, 0xff);
                let byte = b.and(byte0, __h107);
                let c = popcnt8(b, byte);
                let __h108 = k(b, i * 8);
                let put = b.shl(c, __h108);
                v = b.or(v, put);
            }
            v
        }
        378 => {
            let __h109 = k(b, 0xffff_ffff);
            // popcntw: 各ワードのポップカウント。
            let lo = b.and(x, __h109);
            let w0 = popcnt8x4(b, lo);
            let __h110 = k(b, 32);
            let hi0 = b.shr_l(x, __h110);
            let w1 = popcnt8x4(b, hi0);
            let __h111 = k(b, 32);
            let hi = b.shl(w1, __h111);
            b.or(w0, hi)
        }
        506 => popcnt8x8(b, x),
        508 => {
            // cmpb: バイトごとの等価比較。
            let mut v = k(b, 0);
            for i in 0..8u64 {
                let __h112 = k(b, i * 8);
                let bx0 = b.shr_l(x, __h112);
                let __h113 = k(b, 0xff);
                let bx = b.and(bx0, __h113);
                let __h114 = k(b, i * 8);
                let by0 = b.shr_l(y, __h114);
                let __h115 = k(b, 0xff);
                let by = b.and(by0, __h115);
                let eq = b.cmp(Cmp::Eq, bx, by);
                let ff = bsel64(b, eq, 0xff, 0);
                let __h116 = k(b, i * 8);
                let put = b.shl(ff, __h116);
                v = b.or(v, put);
            }
            v
        }
        224 => {
            // cmpeqb: RA の最下位バイトが RB のいずれかのバイトに一致すれば
            // CR[bf] の GT ビットを立てる。SO は XER.SO から。
            let ra_v = g(b, a);
            let rb_v = g(b, bb);
            let __h117 = k(b, 0xff);
            let bx = b.and(ra_v, __h117);
            let mut any = k(b, 0u64);
            let __h120 = k(b, 0);
            for i in 0..8u64 {
                let __h118 = k(b, i * 8);
                let by0 = b.shr_l(rb_v, __h118);
                let __h119 = k(b, 0xff);
                let by = b.and(by0, __h119);
                let hit = b.cmp(Cmp::Eq, bx, by);
                let hv = bsel64(b, hit, 1, 0);
                any = b.or(any, hv);
            }
            let found = b.cmp(Cmp::Ne, any, __h120);
            let f1 = bsel64(b, found, CR_GT, 0);
            let __h121 = xer_so(b);
            let f = b.or(f1, __h121);
            set_crf(b, ((word >> 23) & 7) as u8, f);
            return Ok(());
        }
        128 => {
            // setb: LT→-1、GT→1、他→0。
            let f = crf(b, ((word >> 23) & 7) as u8);
            let lt = {
                let __h122 = k(b, CR_LT);
                let m = b.and(f, __h122);
                let __h123 = k(b, 0);
                b.cmp(Cmp::Ne, m, __h123)
            };
            let gt = {
                let __h124 = k(b, CR_GT);
                let m = b.and(f, __h124);
                let __h125 = k(b, 0);
                b.cmp(Cmp::Ne, m, __h125)
            };
            let __h127 = bsel64(b, gt, 1, 0);
            let __h126 = k(b, !0u64);
            let v = b.select(lt, __h126, __h127);
            s(b, t, v);
            return Ok(());
        }
        156 | 188 => {
            // pdepd: RS の下位ビットを RB マスクの立った位置へ展開。
            // pextd: RB マスク位置のビットを下位へ集める。
            // 64 回の逐語展開で書く。
            let mut v = k(b, 0);
            let mut pos = k(b, 0);
            for i in 0..64u64 {
                let __h128 = k(b, i);
                let m0 = b.shr_l(y, __h128);
                let __h129 = k(b, 1);
                let sel = b.and(m0, __h129);
                let __h130 = k(b, 63);
                let bit = if xo == 156 {
                    // pdep: 次の入力ビットを mask 位置 i へ。
                    let safe = b.and(pos, __h130);
                    let s0 = b.shr_l(x, safe);
                    let __h131 = k(b, 1);
                    let sb = b.and(s0, __h131);
                    b.and(sb, sel)
                } else {
                    let __h132 = k(b, i);
                    // pext: mask 位置 i のビットを次の出力位置へ。
                    let s0 = b.shr_l(x, __h132);
                    let __h133 = k(b, 1);
                    let sb = b.and(s0, __h133);
                    b.and(sb, sel)
                };
                let sh = if xo == 156 {
                    k(b, i)
                } else {
                    let __h134 = k(b, 63);
                    b.and(pos, __h134)
                };
                let put = b.shl(bit, sh);
                v = b.or(v, put);
                pos = b.add(pos, sel);
            }
            v
        }
        252 => {
            // bpermd: RS の各バイトを添字として RB のビットを拾う。
            // byte[i] が 0–63 なら RB の当該ビット、64–127 なら 0。
            let mut v = k(b, 0);
            for i in 0..8u64 {
                let __h135 = k(b, i * 8);
                let idx0 = b.shr_l(x, __h135);
                let __h136 = k(b, 0x7f);
                let idx = b.and(idx0, __h136);
                let __h137 = k(b, 64);
                let inr = b.cmp(Cmp::LtU, idx, __h137);
                let __h138 = k(b, 63);
                let inv = b.sub(__h138, idx);
                let __h139 = k(b, 63);
                // inv は負の場合がある（idx>63）が inr で後から捨てる。
                let safe = b.and(inv, __h139);
                let bit0 = b.shr_l(y, safe);
                let __h140 = k(b, 1);
                let bit = b.and(bit0, __h140);
                let __h141 = k(b, 0);
                let got = b.select(inr, bit, __h141);
                let __h142 = k(b, i * 8);
                let put = b.shl(got, __h142);
                v = b.or(v, put);
            }
            v
        }
        538 => {
            let __h143 = k(b, 0xffff_ffff);
            // cnttzw: 32 ビット値の後続ゼロ。
            let w = b.and(x, __h143);
            let c = ctz64(b, w);
            let __h144 = k(b, 64);
            let is64 = b.cmp(Cmp::Eq, c, __h144);
            let __h145 = k(b, 32);
            b.select(is64, __h145, c)
        }
        570 => ctz64(b, x),
        _ => return unimp(b, u64::from(xo)),
    };
    s(b, a, r);
    if rc {
        record_cr0(b, r);
    }
    Ok(())
}

/// X-indexed ロード。
fn x31_ldx<B: Backend>(b: &mut B, xo: u32, t: u8, a: u8, bb: u8, le: bool) -> Flow<B> {
    let base = ra(b, a);
    let idx = g(b, bb);
    let ea = b.add(base, idx);
    let acc = data_acc(le, true);
    let v: B::V<W64> = match xo {
        87 | 119 => {
            let w = b.load::<W8>(ea, acc)?;
            b.zext::<W8, W64>(w)
        }
        279 | 311 => {
            let w = b.load::<W16>(ea, acc)?;
            b.zext::<W16, W64>(w)
        }
        343 | 375 => {
            let w = b.load::<W16>(ea, acc)?;
            b.sext::<W16, W64>(w)
        }
        23 | 55 => {
            let w = b.load::<W32>(ea, acc)?;
            b.zext::<W32, W64>(w)
        }
        341 | 373 => {
            let w = b.load::<W32>(ea, acc)?;
            b.sext::<W32, W64>(w)
        }
        _ => b.load::<W64>(ea, acc)?,
    };
    s(b, t, v);
    if matches!(xo, 119 | 311 | 375 | 55 | 373 | 53) {
        s(b, a, ea);
    }
    Ok(())
}

/// X-indexed ストア。
fn x31_stx<B: Backend>(b: &mut B, xo: u32, t: u8, a: u8, bb: u8, le: bool) -> Flow<B> {
    let base = ra(b, a);
    let idx = g(b, bb);
    let ea = b.add(base, idx);
    let acc = data_acc(le, false);
    let v = g(b, t);
    match xo {
        215 | 247 => {
            let w = b.trunc::<W64, W8>(v);
            b.store::<W8>(ea, w, acc)?;
        }
        407 | 439 => {
            let w = b.trunc::<W64, W16>(v);
            b.store::<W16>(ea, w, acc)?;
        }
        151 | 183 => {
            let w = b.trunc::<W64, W32>(v);
            b.store::<W32>(ea, w, acc)?;
        }
        _ => b.store::<W64>(ea, v, acc)?,
    }
    if matches!(xo, 247 | 439 | 183 | 181) {
        s(b, a, ea);
    }
    Ok(())
}

/// バイト反転ロード・ストア。
fn x31_bswap_ls<B: Backend>(b: &mut B, xo: u32, t: u8, a: u8, bb: u8, le: bool) -> Flow<B> {
    let base = ra(b, a);
    let idx = g(b, bb);
    let ea = b.add(base, idx);
    let acc = data_acc(le, true);
    let accw = data_acc(le, false);
    match xo {
        534 => {
            let v = b.load::<W32>(ea, acc)?;
            let w = bswap32(b, v);
            let v2 = b.zext::<W32, W64>(w);
            s(b, t, v2);
        }
        790 => {
            let v = b.load::<W16>(ea, acc)?;
            let w = bswap16(b, v);
            let v2 = b.zext::<W16, W64>(w);
            s(b, t, v2);
        }
        532 => {
            let v = b.load::<W64>(ea, acc)?;
            let w = bswap64(b, v);
            s(b, t, w);
        }
        662 => {
            let v = g(b, t);
            let w = b.trunc::<W64, W32>(v);
            let r = bswap32(b, w);
            b.store::<W32>(ea, r, accw)?;
        }
        918 => {
            let v = g(b, t);
            let w = b.trunc::<W64, W16>(v);
            let r = bswap16(b, w);
            b.store::<W16>(ea, r, accw)?;
        }
        _ => {
            let v = g(b, t);
            let r = bswap64(b, v);
            b.store::<W64>(ea, r, accw)?;
        }
    }
    Ok(())
}

/// 予約ロード。
fn x31_larx<B: Backend>(b: &mut B, xo: u32, t: u8, a: u8, bb: u8, le: bool) -> Flow<B> {
    let base = ra(b, a);
    let idx = g(b, bb);
    let ea = b.add(base, idx);
    let acc = data_acc(le, true);
    let v: B::V<W64> = match xo {
        20 => {
            let w = b.load_reserved::<W32>(ea, acc)?;
            b.zext::<W32, W64>(w)
        }
        84 => b.load_reserved::<W64>(ea, acc)?,
        52 => {
            let w = b.load_reserved::<W8>(ea, acc)?;
            b.zext::<W8, W64>(w)
        }
        _ => {
            let w = b.load_reserved::<W16>(ea, acc)?;
            b.zext::<W16, W64>(w)
        }
    };
    s(b, t, v);
    Ok(())
}

/// 条件付きストア。成功で CR0.EQ。
fn x31_stcx<B: Backend>(b: &mut B, xo: u32, t: u8, a: u8, bb: u8, le: bool) -> Flow<B> {
    let base = ra(b, a);
    let idx = g(b, bb);
    let ea = b.add(base, idx);
    let acc = data_acc(le, false);
    let v = g(b, t);
    let ok = match xo {
        150 => {
            let w = b.trunc::<W64, W32>(v);
            b.store_conditional::<W32>(ea, w, acc)?
        }
        214 => b.store_conditional::<W64>(ea, v, acc)?,
        694 => {
            let w = b.trunc::<W64, W8>(v);
            b.store_conditional::<W8>(ea, w, acc)?
        }
        _ => {
            let w = b.trunc::<W64, W16>(v);
            b.store_conditional::<W16>(ea, w, acc)?
        }
    };
    let f1 = bsel64(b, ok, CR_EQ, 0);
    let __h146 = xer_so(b);
    let f = b.or(f1, __h146);
    set_crf(b, 0, f);
    Ok(())
}

/// FP ロード・ストア（X-indexed）。
fn x31_fls<B: Backend>(b: &mut B, xo: u32, t: u8, a: u8, bb: u8, le: bool) -> Flow<B> {
    let base = ra(b, a);
    let idx = g(b, bb);
    let ea = b.add(base, idx);
    let acc = data_acc(le, true);
    let accw = data_acc(le, false);
    match xo {
        535 | 567 => {
            // lfsx/lfsux: f32→f64 変換して FPR へ。
            let w = b.load::<W32>(ea, acc)?;
            let v = b.fcvt_ff::<W32, W64>(w, 0);
            set_fpr(b, t, v);
            if xo == 567 {
                s(b, a, ea);
            }
        }
        599 | 631 => {
            let v = b.load::<W64>(ea, acc)?;
            set_fpr(b, t, v);
            if xo == 631 {
                s(b, a, ea);
            }
        }
        663 | 695 => {
            let v = fpr(b, t);
            let w = b.fcvt_ff::<W64, W32>(v, 0);
            b.store::<W32>(ea, w, accw)?;
            if xo == 695 {
                s(b, a, ea);
            }
        }
        727 | 759 => {
            let v = fpr(b, t);
            b.store::<W64>(ea, v, accw)?;
            if xo == 759 {
                s(b, a, ea);
            }
        }
        855 => {
            // lfiwax: 符号付きワードをロードして FPR へ（整数のまま）。
            let w = b.load::<W32>(ea, acc)?;
            let v = b.sext::<W32, W64>(w);
            set_fpr(b, t, v);
        }
        887 => {
            // lfiwzx。
            let w = b.load::<W32>(ea, acc)?;
            let v = b.zext::<W32, W64>(w);
            set_fpr(b, t, v);
        }
        _ => {
            // stfiwx。
            let v = fpr(b, t);
            let w = b.trunc::<W64, W32>(v);
            b.store::<W32>(ea, w, accw)?;
        }
    }
    Ok(())
}

/// VSX/AltiVec ロード・ストア（X-indexed、VX 形式）。
#[allow(clippy::too_many_lines)]
fn x31_vsx_ls<B: Backend>(
    b: &mut B,
    word: u32,
    xo: u32,
    t: u8,
    a: u8,
    bb: u8,
    le: bool,
) -> Flow<B> {
    let base = ra(b, a);
    let idx = g(b, bb);
    let ea = b.add(base, idx);
    let acc = data_acc(le, true);
    let accw = data_acc(le, false);
    // VX 形式の拡張ビット。T = RT(5) | TX(bit0)。
    let xt = (u64::from(t) | (u64::from(word & 1) << 5)) as u8;
    match xo {
        588 => {
            // lxsdx: 8B を VSR[dw0] へ。
            let v = b.load::<W64>(ea, acc)?;
            let w = put_dw0(b, v);
            set_vsr(b, xt, w);
        }
        716 => {
            // stxsdx。
            let v = vsr_hi(b, xt);
            b.store::<W64>(ea, v, accw)?;
        }
        844 => {
            // lxvd2x: LE は各 dw が LE ロード。dw0=mem[ea], dw1=mem[ea+8]。
            let hi = b.load::<W64>(ea, acc)?;
            let __h147 = k(b, 8);
            let ea2 = b.add(ea, __h147);
            let lo = b.load::<W64>(ea2, acc)?;
            let v = vsr_pack(b, hi, lo);
            set_vsr(b, xt, v);
        }
        972 => {
            // stxvd2x。
            let hi = vsr_hi(b, xt);
            let lo = vsr_lo(b, xt);
            b.store::<W64>(ea, hi, accw)?;
            let __h148 = k(b, 8);
            let ea2 = b.add(ea, __h148);
            b.store::<W64>(ea2, lo, accw)?;
        }
        332 => {
            // lxvdsx: 8B を両 dw に複製。
            let v = b.load::<W64>(ea, acc)?;
            let w = vsr_pack(b, v, v);
            set_vsr(b, xt, w);
        }
        364 => {
            // lxvwsx: 4B を全ワードに複製。
            let w = b.load::<W32>(ea, acc)?;
            let wz = b.zext::<W32, W128>(w);
            let __h500 = k128(b, 32);
            let s1 = b.shl(wz, __h500);
            let __h501 = k128(b, 64);
            let s2 = b.shl(wz, __h501);
            let __h502 = k128(b, 96);
            let s3 = b.shl(wz, __h502);
            let m01 = b.or(wz, s1);
            let m23 = b.or(s2, s3);
            let v = b.or(m01, m23);
            set_vsr(b, xt, v);
        }
        103 => {
            // lvx: 16B。LE モードは要素順が IBM 逆。全バイト反転で近似。
            let v = b.load::<W128>(ea, acc)?;
            let w = bswap128(b, v);
            set_vsr(b, xt, w);
        }
        231 => {
            let v = vsr(b, xt);
            let w = bswap128(b, v);
            b.store::<W128>(ea, w, accw)?;
        }
        268 => {
            // lxvx: 16B をそのまま（VSX は LE の要素順のまま）。
            let v = b.load::<W128>(ea, acc)?;
            set_vsr(b, xt, v);
        }
        396 => {
            let v = vsr(b, xt);
            b.store::<W128>(ea, v, accw)?;
        }
        780 => {
            // lxvw4x: 4 ワード。各ワードは LE ロード、IBM word0 が最上位。
            let mut vv = k128(b, 0);
            for i in 0..4u128 {
                let __h149 = k(b, i as u64 * 4);
                let ea2 = b.add(ea, __h149);
                let w = b.load::<W32>(ea2, acc)?;
                let wz = b.zext::<W32, W128>(w);
                let sh = k128(b, 96 - i * 32);
                let put = b.shl(wz, sh);
                vv = b.or(vv, put);
            }
            set_vsr(b, xt, vv);
        }
        908 => {
            for i in 0..4u128 {
                let v = vsr(b, xt);
                let sh = k128(b, 96 - i * 32);
                let w = b.shr_l(v, sh);
                let w32 = b.trunc::<W128, W32>(w);
                let __h150 = k(b, i as u64 * 4);
                let ea2 = b.add(ea, __h150);
                b.store::<W32>(ea2, w32, accw)?;
            }
        }
        812 => {
            // lxvh8x: 8 ハーフ。要素 i を IBM 位置 i へ。
            let mut vv = k128(b, 0);
            for i in 0..8u128 {
                let __h151 = k(b, i as u64 * 2);
                let ea2 = b.add(ea, __h151);
                let w = b.load::<W16>(ea2, acc)?;
                let wz = b.zext::<W16, W128>(w);
                let sh = k128(b, 112 - i * 16);
                let put = b.shl(wz, sh);
                vv = b.or(vv, put);
            }
            set_vsr(b, xt, vv);
        }
        940 => {
            // stxvh8x。
            let v = vsr(b, xt);
            for i in 0..8u128 {
                let sh = k128(b, 112 - i * 16);
                let w0 = b.shr_l(v, sh);
                let w = b.trunc::<W128, W16>(w0);
                let __h152 = k(b, i as u64 * 2);
                let ea2 = b.add(ea, __h152);
                b.store::<W16>(ea2, w, accw)?;
            }
        }
        876 => {
            // lxvb16x: バイト i を IBM 位置 i へ（要素は反転しない）。
            let mut vv = k128(b, 0);
            for i in 0..16u128 {
                let __h153 = k(b, i as u64);
                let ea2 = b.add(ea, __h153);
                let w = b.load::<W8>(ea2, acc)?;
                let wz = b.zext::<W8, W128>(w);
                let sh = k128(b, 120 - i * 8);
                let put = b.shl(wz, sh);
                vv = b.or(vv, put);
            }
            set_vsr(b, xt, vv);
        }
        1004 => {
            // stxvb16x。
            let v = vsr(b, xt);
            for i in 0..16u128 {
                let sh = k128(b, 120 - i * 8);
                let w0 = b.shr_l(v, sh);
                let w = b.trunc::<W128, W8>(w0);
                let __h154 = k(b, i as u64);
                let ea2 = b.add(ea, __h154);
                b.store::<W8>(ea2, w, accw)?;
            }
        }
        269 | 301 => {
            // lxvl/lxvll: EA = ra(A)、長 = g(bb) を 16 バイトに丸める。
            // IBM バイト i へ mem[EA+i] を置く（条件付きロード）。
            let n0 = g(b, bb);
            let __h155 = k(b, 0xff);
            let n = b.and(n0, __h155);
            let accb = data_acc(le, true);
            let __h156 = k128(b, 0);
            set_vsr(b, xt, __h156);
            for i in 0..16u128 {
                let __h157 = k(b, i as u64);
                let ea2 = b.add(base, __h157);
                let __h158 = k(b, i as u64);
                let have = b.cmp(Cmp::LtU, __h158, n);
                b.if_then(have, |b| {
                    let w = b.load::<W8>(ea2, accb)?;
                    let wz = b.zext::<W8, W128>(w);
                    let __h159 = k128(b, 120 - i * 8);
                    let put = b.shl(wz, __h159);
                    let cur = vsr(b, xt);
                    let nv = b.or(cur, put);
                    set_vsr(b, xt, nv);
                    Ok(())
                })?;
            }
        }
        397 | 429 => {
            // stxvl/stxvll: 左詰め nb バイトを書く（条件付きストア）。
            let n0 = g(b, bb);
            let __h160 = k(b, 0xff);
            let n = b.and(n0, __h160);
            let accb = data_acc(le, false);
            let v = vsr(b, xt);
            for i in 0..16u128 {
                let sh = k128(b, 120 - i * 8);
                let w0 = b.shr_l(v, sh);
                let w = b.trunc::<W128, W8>(w0);
                let __h161 = k(b, i as u64);
                let ea2 = b.add(base, __h161);
                let __h162 = k(b, i as u64);
                let have = b.cmp(Cmp::LtU, __h162, n);
                b.if_then(have, |b| b.store::<W8>(ea2, w, accb))?;
            }
        }
        13 | 45 | 77 | 109 => {
            // lxvr*x: 要素を右端（IBM 最終要素=LSB 側）へ。残りは 0。
            let v: B::V<W128> = match xo {
                13 => {
                    let w = b.load::<W8>(ea, acc)?;
                    b.zext::<W8, W128>(w)
                }
                45 => {
                    let w = b.load::<W16>(ea, acc)?;
                    b.zext::<W16, W128>(w)
                }
                77 => {
                    let w = b.load::<W32>(ea, acc)?;
                    b.zext::<W32, W128>(w)
                }
                _ => {
                    let w = b.load::<W64>(ea, acc)?;
                    b.zext::<W64, W128>(w)
                }
            };
            set_vsr(b, xt, v);
        }
        141 | 173 | 205 | 237 => {
            // stxvr*x: 右端の要素を書く。
            let v = vsr(b, xt);
            match xo {
                141 => {
                    let w = b.trunc::<W128, W8>(v);
                    b.store::<W8>(ea, w, accw)?;
                }
                173 => {
                    let w = b.trunc::<W128, W16>(v);
                    b.store::<W16>(ea, w, accw)?;
                }
                205 => {
                    let w = b.trunc::<W128, W32>(v);
                    b.store::<W32>(ea, w, accw)?;
                }
                _ => {
                    let w = b.trunc::<W128, W64>(v);
                    b.store::<W64>(ea, w, accw)?;
                }
            }
        }
        524 => {
            // lxsspx: 4B を VSR 先頭ワードへ。
            let w = b.load::<W32>(ea, acc)?;
            let wz = b.zext::<W32, W128>(w);
            let __h163 = k128(b, 96);
            let put = b.shl(wz, __h163);
            set_vsr(b, xt, put);
        }
        652 => {
            let v = vsr(b, xt);
            let sh = k128(b, 96);
            let w = b.shr_l(v, sh);
            let w32 = b.trunc::<W128, W32>(w);
            b.store::<W32>(ea, w32, accw)?;
        }
        140 => {
            // stxsiwx: VSR 先頭ワードを 4B ストア。
            let v = vsr(b, xt);
            let sh = k128(b, 96);
            let w = b.shr_l(v, sh);
            let w32 = b.trunc::<W128, W32>(w);
            b.store::<W32>(ea, w32, accw)?;
        }
        76 => {
            // lxsiwax: 符号付きワードを dw0 へ。
            let w = b.load::<W32>(ea, acc)?;
            let v = b.sext::<W32, W64>(w);
            let wide = put_dw0(b, v);
            set_vsr(b, xt, wide);
        }
        12 => {
            // lxsiwzx。
            let w = b.load::<W32>(ea, acc)?;
            let v = b.zext::<W32, W64>(w);
            let wide = put_dw0(b, v);
            set_vsr(b, xt, wide);
        }
        _ => return unimp(b, u64::from(xo)),
    }
    Ok(())
}

/// VSR ↔ GPR（VX 形式。mtvsrd/mfvsrd/mtvsrwa/mfvsrwz/mtvsrwz/mtvsrdd/mfvsrld）。
/// mt/mf 系の拡張ビットはともに命令の最下位ビット（IBM bit31。TX/SX）。
/// GPR 側は常に RA 欄。
fn x31_vsr_gpr<B: Backend>(b: &mut B, word: u32, xo: u32, t: u8, a: u8) -> Flow<B> {
    let xt = (u64::from(t) | (u64::from(word & 1) << 5)) as u8;
    // mf 系の拡張ビット SX も TX と同じく命令の最下位ビット（IBM bit31）。
    let xs = (u64::from(t) | (u64::from(word & 1) << 5)) as u8;
    match xo {
        179 => {
            // mtvsrd: GPR[ra] → VSR[xt].dw0。
            let v = g(b, a);
            let w = put_dw0(b, v);
            set_vsr(b, xt, w);
        }
        51 => {
            // mfvsrd: VSR[xs].dw0 → GPR[ra]。
            let hi = vsr_hi(b, xs);
            s(b, a, hi);
        }
        211 => {
            // mtvsrwa: GPR[ra].w0 を符号拡張で VSR[xt].dw0 へ。
            let v = g(b, a);
            let w32 = b.trunc::<W64, W32>(v);
            let s = b.sext::<W32, W64>(w32);
            let w = put_dw0(b, s);
            set_vsr(b, xt, w);
        }
        115 => {
            // mfvsrwz: VSR[xs].w1（dw0 下位ワード）をゼロ拡張で GPR[ra] へ。
            let hi = vsr_hi(b, xs);
            let __h164 = k(b, 0xffff_ffff);
            let v = b.and(hi, __h164);
            s(b, a, v);
        }
        243 => {
            // mtvsrwz: GPR[ra].w0 をゼロ拡張で VSR[xt].dw0 へ。
            let v = g(b, a);
            let __h165 = k(b, 0xffff_ffff);
            let w = b.and(v, __h165);
            let w2 = put_dw0(b, w);
            set_vsr(b, xt, w2);
        }
        435 => {
            // mtvsrdd: GPR[ra]+GPR[rb] → 両 dw。
            let hi = g(b, a);
            let lo = g(b, ((word >> 11) & 31) as u8);
            let v = vsr_pack(b, hi, lo);
            set_vsr(b, xt, v);
        }
        307 => {
            // mfvsrld: VSR[xs].dw1 → GPR[ra]。
            let lo = vsr_lo(b, xs);
            s(b, a, lo);
        }
        _ => return unimp(b, u64::from(xo)),
    }
    Ok(())
}

/// SPR・CR の移動（mfspr/mtspr/mfcr/mtcrf/mcrxr/mcrxrx）。
fn x31_spr<B: Backend>(b: &mut B, word: u32, xo: u32, t: u8) -> Flow<B> {
    match xo {
        339 => {
            // mfspr。sprn は bits15-11 が上位 5、bits20-16 が下位 5。
            let sprn = ((word >> 11) & 0x1f) << 5 | ((word >> 16) & 0x1f);
            let v = match sprn {
                8 => b.get(lr_ref()),
                9 => b.get(ctr_ref()),
                1 => b.get(xer_ref()),
                287 => b.get(pvr_ref()),
                268 | 269 => {
                    // TB/TBU。実行ごとに増える単調値を返す。
                    let tb0 = b.get(tb_ref());
                    let __h166 = k(b, 16);
                    let tb = b.add(tb0, __h166);
                    b.set(tb_ref(), tb);
                    if sprn == 269 {
                        let __h167 = k(b, 32);
                        b.shr_l(tb, __h167)
                    } else {
                        tb
                    }
                }
                _ => k(b, 0),
            };
            s(b, t, v);
            Ok(())
        }
        467 => {
            // mtspr（sprn の並びは mfspr と同じ）。
            let sprn = ((word >> 11) & 0x1f) << 5 | ((word >> 16) & 0x1f);
            let v = g(b, t);
            match sprn {
                8 => b.set(lr_ref(), v),
                9 => b.set(ctr_ref(), v),
                1 => b.set(xer_ref(), v),
                _ => {}
            }
            Ok(())
        }
        19 => {
            // mfcr / mfocrf（bit20=1 で単一フィールド）。
            // mfocrf は FXM(bits12-19) の単一セットビットが選択する
            // CR フィールド i を Rt の同じフィールド位置にコピーする
            // （残りビットは 0）。FXM の bit(0x80>>i) がフィールド i。
            let cr = b.get(cr_ref());
            let v = if word & 0x10_0000 != 0 {
                let fxm = (word >> 12) & 0xff;
                let bf = if fxm == 0 {
                    0
                } else {
                    7 - fxm.trailing_zeros()
                };
                let sh = 28 - 4 * u64::from(bf);
                let __h168 = k(b, sh);
                let f = b.shr_l(cr, __h168);
                let __h169 = k(b, 0xf);
                let f4 = b.and(f, __h169);
                let __h170 = k(b, sh);
                b.shl(f4, __h170)
            } else {
                cr
            };
            s(b, t, v);
            Ok(())
        }
        144 => {
            // mtcrf/mtocrf: FXM(8bit) で指定したフィールドを rs で上書き。
            let fxm = ((word >> 12) & 0xff) as u64;
            let mut mask = 0u64;
            for i in 0..8u64 {
                if fxm & (0x80 >> i) != 0 {
                    mask |= 0xf << (28 - 4 * i);
                }
            }
            let rv = g(b, t);
            let __h171 = k(b, mask);
            let ins = b.and(rv, __h171);
            let cr = b.get(cr_ref());
            let __h172 = k(b, !mask);
            let keep = b.and(cr, __h172);
            let v = b.or(ins, keep);
            b.set(cr_ref(), v);
            Ok(())
        }
        512 => {
            // mcrxr: CR[bf] = XER[31:28]、XER[31:28] = 0。
            let x = b.get(xer_ref());
            let __h173 = k(b, 28);
            let f = b.shr_l(x, __h173);
            set_crf(b, ((word >> 23) & 7) as u8, f);
            let __h174 = k(b, 0x0fff_ffff);
            let nx = b.and(x, __h174);
            b.set(xer_ref(), nx);
            Ok(())
        }
        576 => Ok(()), // mcrxrx: 近似 NOP。
        _ => unimp(b, u64::from(xo)),
    }
}

/// isel（XO = 15 + 32*BC）。
fn x31_isel<B: Backend>(b: &mut B, word: u32, t: u8, a: u8, bb: u8) -> Flow<B> {
    let bc = (((word >> 1) & 0x3ff) >> 5) as u8;
    let c = cr_bit(b, bc);
    let x = ra(b, a);
    let y = g(b, bb);
    let v = b.select(c, y, x);
    s(b, t, v);
    Ok(())
}

/// op31（X 形式）の振り分け。`le` はデータアクセスのエンディアン。
#[allow(clippy::too_many_lines)]
pub fn x31<B: Backend>(b: &mut B, word: u32, _pc: u64, le: bool) -> Flow<B> {
    let xo = (word >> 1) & 0x3ff;
    let t = ((word >> 21) & 31) as u8;
    let a = ((word >> 16) & 31) as u8;
    let bb = ((word >> 11) & 31) as u8;
    let rc = word & 1 != 0;
    let oe = word & 0x400 != 0;
    match xo {
        // ---- 比較 ----
        0 => {
            let bf = ((word >> 23) & 7) as u8;
            let l = word & 0x20_0000 != 0;
            let x = g(b, a);
            let y = g(b, bb);
            do_cmp(b, bf, l, false, x, y);
            return Ok(());
        }
        32 => {
            let bf = ((word >> 23) & 7) as u8;
            let l = word & 0x20_0000 != 0;
            let x = g(b, a);
            let y = g(b, bb);
            do_cmp(b, bf, l, true, x, y);
            return Ok(());
        }
        // ---- 論理（RS→RA）----
        28 | 60 | 316 | 284 | 476 | 124 | 444 | 412 => {
            let x = g(b, t);
            let y = g(b, bb);
            let v = match xo {
                28 => b.and(x, y),
                60 => {
                    let ny = b.not(y);
                    b.and(x, ny)
                }
                316 => b.xor(x, y),
                284 => {
                    let z = b.xor(x, y);
                    b.not(z)
                }
                476 => {
                    let z = b.and(x, y);
                    b.not(z)
                }
                124 => {
                    let z = b.or(x, y);
                    b.not(z)
                }
                444 => b.or(x, y),
                _ => {
                    let ny = b.not(y);
                    b.or(x, ny)
                }
            };
            s(b, a, v);
            if rc {
                record_cr0(b, v);
            }
            return Ok(());
        }
        // ---- 加減算 ----
        8 | 10 | 40 | 136 | 138 | 200 | 202 | 232 | 234 | 266 | 104 => {
            return x31_arith(b, word, xo, t, a, bb, (rc, oe));
        }
        // ---- 乗算 ----
        11 | 75 | 9 | 73 | 233 | 235 => return x31_mul(b, xo, t, a, bb, rc, oe),
        // ---- 除算・剰余 ----
        393 | 395 | 425 | 427 | 457 | 459 | 489 | 491 | 265 | 267 | 777 | 779 => {
            return x31_div(b, xo, t, a, bb, rc);
        }
        // ---- シフト・拡張・数え上げ ----
        24 | 27 | 536 | 539 | 792 | 824 | 826 | 827 | 26 | 58 | 922 | 954 | 986 | 122 | 378
        | 506 | 508 | 224 | 128 | 252 | 538 | 570 | 156 | 188 => {
            return x31_shift(b, word, xo, t, a, bb, rc);
        }
        // ---- isel ----
        15 | 47 | 79 | 111 | 143 | 175 | 207 | 239 | 271 | 303 | 335 | 367 | 399 | 431 | 463
        | 495 | 527 | 559 | 591 | 623 | 655 | 687 | 719 | 751 | 783 | 815 | 847 | 879 | 911
        | 943 | 975 | 1007 => return x31_isel(b, word, t, a, bb),
        // ---- トラップ ----
        4 | 68 => {
            // tw/td。TO は bits25-21。
            let to = t;
            let x = g(b, a);
            let y = g(b, bb);
            return trap_if(b, to, xo == 68, x, y);
        }
        _ => {}
    }

    match xo {
        // ---- 整数 X-indexed ロード ----
        87 | 119 | 279 | 311 | 343 | 375 | 23 | 55 | 341 | 373 | 21 | 53 => {
            x31_ldx(b, xo, t, a, bb, le)
        }
        // ---- 整数 X-indexed ストア ----
        215 | 247 | 407 | 439 | 151 | 183 | 149 | 181 => x31_stx(b, xo, t, a, bb, le),
        // ---- バイト反転 ----
        534 | 790 | 662 | 918 | 532 | 660 => x31_bswap_ls(b, xo, t, a, bb, le),
        // ---- 予約 ----
        20 | 84 | 52 | 116 => x31_larx(b, xo, t, a, bb, le),
        150 | 214 | 694 | 726 => x31_stcx(b, xo, t, a, bb, le),
        // ---- SPR/CR ----
        339 | 467 | 19 | 144 | 512 | 576 => x31_spr(b, word, xo, t),
        // ---- FP ロード・ストア ----
        535 | 567 | 599 | 631 | 663 | 695 | 727 | 759 | 855 | 887 | 983 => {
            x31_fls(b, xo, t, a, bb, le)
        }
        // ---- VSX/AltiVec ロード・ストア ----
        588 | 716 | 844 | 972 | 332 | 103 | 231 | 268 | 396 | 780 | 908 | 812 | 876 | 524 | 652
        | 140 | 76 | 12 | 269 | 301 | 397 | 429 | 940 | 1004 | 13 | 45 | 77 | 109 | 141 | 173
        | 205 | 237 | 364 => x31_vsx_ls(b, word, xo, t, a, bb, le),
        // ---- VSR ↔ GPR ----
        179 | 51 | 211 | 115 | 243 | 435 | 307 => x31_vsr_gpr(b, word, xo, t, a),
        // ---- ベクタ要素ロード・ストア（lvebx/lvehx/lvewx/stvebx/…） ----
        7 | 39 | 71 | 135 | 167 | 199 | 6 | 38 => Ok(()),
        // ---- 文字列転送（lswi/stswi/lswx/stswx） ----
        597 | 725 | 533 | 661 => x31_string_ls(b, word, xo, t, a, bb, le),
        // ---- システム ----
        598 => Ok(()), // sync/lwsync/ptesync。
        854 => Ok(()), // eieio。
        982 => Ok(()), // icbi。
        86 => Ok(()),  // dcbf。
        54 => Ok(()),  // dcbst。
        1014 => {
            // dcbz/dcbzl: キャッシュライン 128 バイトをゼロクリア。
            let accw = data_acc(le, false);
            let base = ra(b, a);
            let __h175 = g(b, bb);
            let ea = b.add(base, __h175);
            let __h176 = k(b, !127u64);
            let ea0 = b.and(ea, __h176);
            let z = k(b, 0);
            for i in 0..16u64 {
                let __h177 = k(b, i * 8);
                let a2 = b.add(ea0, __h177);
                b.store::<W64>(a2, z, accw)?;
            }
            Ok(())
        }
        278 => Ok(()), // dcbt。
        246 => Ok(()), // dcbtst。
        30 => Ok(()),  // wait（共有終了待ち。単実行なので素通し）。
        338 => Ok(()), // slbsync。
        230 => Ok(()), // icblc。
        302 => {
            let __h178 = k(b, 0);
            // mfbhrbe: 分岐履歴は持たないので 0 を返す。
            s(b, t, __h178);
            Ok(())
        }
        430 => Ok(()), // clrbhrb。
        755 => {
            // darn: 擬似乱数。l=bits20:16 の 0/1/2 で 32/16/8 ビット。
            // TB とアドレスを混ぜた決定的な値で返す。
            let l = (word >> 16) & 3;
            let tb0 = b.get(tb_ref());
            let __h179 = g(b, t);
            let x0 = b.xor(tb0, __h179);
            let __h180 = k(b, 0x9e37_79b9_7f4a_7c15);
            let x1 = b.xor(x0, __h180);
            let __h181 = k(b, 0x2545_f491_4f6c_dd1d);
            let x2 = b.mul(x1, __h181);
            let v = match l {
                0 => {
                    let __h182 = k(b, 0xffff_ffff);
                    b.and(x2, __h182)
                }
                1 => {
                    let __h183 = k(b, 0xffff);
                    b.and(x2, __h183)
                }
                _ => {
                    let __h184 = k(b, 0xff);
                    b.and(x2, __h184)
                }
            };
            s(b, t, v);
            Ok(())
        }
        _ => unimp(b, u64::from(xo)),
    }
}

/// lswi/stswi（NB フィールド）と lswx/stswx（XER のバイト数）の
/// 文字列転送。バイト列をレジスタ列（低 32 ビット・MSB ファースト）へ
/// 転送する。i 番目のバイトは `r[(t + i/4) & 31]` の位置 `3 - (i%4)`
/// に置かれる。lswx/stswx の個数は実行時の XER[0:6]（0–127）なので、
/// 全バイトを個数との比較で条件実行する（lxvl と同じ形）。
// Ref: SPEC-POWER-ISA (v3.1C) — lswi/stswi/lswx/stswx。
fn x31_string_ls<B: Backend>(
    b: &mut B,
    word: u32,
    xo: u32,
    t: u8,
    a: u8,
    bb: u8,
    le: bool,
) -> Flow<B> {
    let indexed = matches!(xo, 533 | 661);
    let load = matches!(xo, 597 | 533);
    let ea = if indexed {
        let base = ra(b, a);
        let idx = g(b, bb);
        b.add(base, idx)
    } else {
        ra(b, a)
    };
    let accr = data_acc(le, true);
    let accw = data_acc(le, false);
    // lswx/stswx の個数は XER バイト数（値 bits 0–6 = 0–127）。
    let n_dyn: Option<B::V<W64>> = if indexed {
        let x = b.get(xer_ref());
        let __h = k(b, 0x7f);
        Some(b.and(x, __h))
    } else {
        None
    };
    let nb = (word >> 11) & 31;
    let total: u64 = if indexed {
        128
    } else if nb == 0 {
        32
    } else {
        u64::from(nb)
    };
    for i in 0..total {
        let r = (t.wrapping_add((i / 4) as u8)) & 31;
        let shift = (3 - (i % 4)) * 8;
        if let Some(nd) = &n_dyn {
            let __i = k(b, i);
            let have = b.cmp(Cmp::LtU, __i, *nd);
            if load {
                b.if_then(have, |b| {
                    let off = k(b, i);
                    let ad = b.add(ea, off);
                    let w = b.load::<W8>(ad, accr)?;
                    let wz = b.zext::<W8, W64>(w);
                    let sh = k(b, shift);
                    let put = b.shl(wz, sh);
                    let cur = g(b, r);
                    let mk = k(b, !(0xffu64 << shift));
                    let keep = b.and(cur, mk);
                    let nv = b.or(keep, put);
                    s(b, r, nv);
                    Ok(())
                })?;
            } else {
                b.if_then(have, |b| {
                    let cur = g(b, r);
                    let sh = k(b, shift);
                    let v0 = b.shr_l(cur, sh);
                    let w = b.trunc::<W64, W8>(v0);
                    let off = k(b, i);
                    let ad = b.add(ea, off);
                    b.store::<W8>(ad, w, accw)
                })?;
            }
        } else if load {
            let off = k(b, i);
            let ad = b.add(ea, off);
            let w = b.load::<W8>(ad, accr)?;
            let wz = b.zext::<W8, W64>(w);
            let sh = k(b, shift);
            let put = b.shl(wz, sh);
            let cur = g(b, r);
            let mk = k(b, !(0xffu64 << shift));
            let keep = b.and(cur, mk);
            let nv = b.or(keep, put);
            s(b, r, nv);
        } else {
            let cur = g(b, r);
            let sh = k(b, shift);
            let v0 = b.shr_l(cur, sh);
            let w = b.trunc::<W64, W8>(v0);
            let off = k(b, i);
            let ad = b.add(ea, off);
            b.store::<W8>(ad, w, accw)?;
        }
    }
    Ok(())
}

fn bswap16<B: Backend>(b: &mut B, v: B::V<W16>) -> B::V<W16> {
    let w = b.zext::<W16, W32>(v);
    let __h185 = k32(b, 0xff00);
    let hi = b.and(w, __h185);
    let __h186 = k32(b, 8);
    let hi8 = b.shr_l::<W32>(hi, __h186);
    let __h187 = k32(b, 0xff);
    let lo = b.and(w, __h187);
    let __h188 = k32(b, 8);
    let lo8 = b.shl::<W32>(lo, __h188);
    let r = b.or(hi8, lo8);
    b.trunc::<W32, W16>(r)
}

fn bswap32<B: Backend>(b: &mut B, v: B::V<W32>) -> B::V<W32> {
    let w = b.zext::<W32, W64>(v);
    let __h189 = k(b, 0xff00_0000);
    let b3 = b.and(w, __h189);
    let __h190 = k(b, 24);
    let b3s = b.shr_l(b3, __h190);
    let __h191 = k(b, 0x00ff_0000);
    let b2 = b.and(w, __h191);
    let __h192 = k(b, 8);
    let b2s = b.shr_l(b2, __h192);
    let __h193 = k(b, 0x0000_ff00);
    let b1 = b.and(w, __h193);
    let __h194 = k(b, 8);
    let b1s = b.shl(b1, __h194);
    let __h195 = k(b, 0x0000_00ff);
    let b0 = b.and(w, __h195);
    let __h196 = k(b, 24);
    let b0s = b.shl(b0, __h196);
    let t0 = b.or(b3s, b2s);
    let t1 = b.or(b1s, b0s);
    let r = b.or(t0, t1);
    b.trunc::<W64, W32>(r)
}

fn bswap64<B: Backend>(b: &mut B, v: B::V<W64>) -> B::V<W64> {
    let mut r = k(b, 0);
    for i in 0..8u64 {
        let __h197 = k(b, i * 8);
        let byte0 = b.shr_l(v, __h197);
        let __h198 = k(b, 0xff);
        let byte = b.and(byte0, __h198);
        let __h199 = k(b, (7 - i) * 8);
        let put = b.shl(byte, __h199);
        r = b.or(r, put);
    }
    r
}

fn bswap128<B: Backend>(b: &mut B, v: B::V<W128>) -> B::V<W128> {
    let mut r = k128(b, 0);
    for i in 0..16u128 {
        let __h200 = k128(b, i * 8);
        let byte0 = b.shr_l(v, __h200);
        let __h201 = k128(b, 0xff);
        let byte = b.and(byte0, __h201);
        let __h202 = k128(b, (15 - i) * 8);
        let put = b.shl(byte, __h202);
        r = b.or(r, put);
    }
    r
}

fn popcnt8<B: Backend>(b: &mut B, v: B::V<W64>) -> B::V<W64> {
    let __h203 = k(b, 1);
    let v1h = b.shr_l(v, __h203);
    let __h204 = k(b, 0x55);
    let v1m = b.and(v1h, __h204);
    let v1 = b.sub(v, v1m);
    let __h205 = k(b, 2);
    let v2h = b.shr_l(v1, __h205);
    let __h206 = k(b, 0x33);
    let v2a = b.and(v1, __h206);
    let __h207 = k(b, 0x33);
    let v2b = b.and(v2h, __h207);
    let v2 = b.add(v2a, v2b);
    let __h208 = k(b, 4);
    let v3h = b.shr_l(v2, __h208);
    let v3 = b.add(v2, v3h);
    let __h209 = k(b, 0x0f);
    b.and(v3, __h209)
}

fn popcnt8x4<B: Backend>(b: &mut B, w: B::V<W64>) -> B::V<W64> {
    let m1 = k(b, 0x5555_5555);
    let m2 = k(b, 0x3333_3333);
    let m4 = k(b, 0x0f0f_0f0f);
    let __h210 = k(b, 0xffff_ffff);
    let v = b.and(w, __h210);
    let __h211 = k(b, 1);
    let v1h = b.shr_l(v, __h211);
    let v1m = b.and(v1h, m1);
    let v = b.sub(v, v1m);
    let __h212 = k(b, 2);
    let v2h = b.shr_l(v, __h212);
    let v2a = b.and(v, m2);
    let v2b = b.and(v2h, m2);
    let v = b.add(v2a, v2b);
    let __h213 = k(b, 4);
    let v3h = b.shr_l(v, __h213);
    let v3 = b.add(v, v3h);
    let v = b.and(v3, m4);
    let __h214 = k(b, 8);
    let s1 = b.shr_l(v, __h214);
    let v = b.add(v, s1);
    let __h215 = k(b, 16);
    let s2 = b.shr_l(v, __h215);
    let v = b.add(v, s2);
    let __h216 = k(b, 0x3f);
    b.and(v, __h216)
}

fn popcnt8x8<B: Backend>(b: &mut B, v: B::V<W64>) -> B::V<W64> {
    let m1 = k(b, 0x5555_5555_5555_5555);
    let m2 = k(b, 0x3333_3333_3333_3333);
    let m4 = k(b, 0x0f0f_0f0f_0f0f_0f0f);
    let __h217 = k(b, 1);
    let v1h = b.shr_l(v, __h217);
    let v1m = b.and(v1h, m1);
    let v = b.sub(v, v1m);
    let __h218 = k(b, 2);
    let v2h = b.shr_l(v, __h218);
    let v2a = b.and(v, m2);
    let v2b = b.and(v2h, m2);
    let v = b.add(v2a, v2b);
    let __h219 = k(b, 4);
    let v3h = b.shr_l(v, __h219);
    let v3 = b.add(v, v3h);
    let v = b.and(v3, m4);
    let h = k(b, 0x0101_0101_0101_0101);
    let v = b.mul(v, h);
    let __h220 = k(b, 56);
    b.shr_l(v, __h220)
}

/// 先頭ゼロの数（0→64）。
fn clz64<B: Backend>(b: &mut B, v: B::V<W64>) -> B::V<W64> {
    let mut n = k(b, 0);
    let mut v = v;
    let __h223 = k(b, 0);
    for bits in [32u64, 16, 8, 4, 2, 1] {
        let __h221 = k(b, bits);
        let hi = b.shr_l(v, __h221);
        let __h222 = k(b, 0);
        let zero = b.cmp(Cmp::Eq, hi, __h222);
        let add = bsel64(b, zero, bits, 0);
        n = b.add(n, add);
        v = b.select(zero, v, hi);
    }
    // 入力が全ゼロなら 64。
    let z = b.cmp(Cmp::Eq, v, __h223);
    let __h224 = k(b, 64);
    b.select(z, __h224, n)
}

// ---------------- FP（op59/63） ----------------

/// FP 比較。bf フィールドに [lt,gt,eq,un] を書く。
/// unordered は「どちら側にも fle が立たない」で取る（NaN 検出）。
fn do_fcmp<B: Backend>(b: &mut B, bf: u8, a: B::V<W64>, x: B::V<W64>) {
    let lt = b.flt::<W64>(a, x);
    let gt = b.flt::<W64>(x, a);
    let eq = b.feq::<W64>(a, x);
    let le_ab = b.fle::<W64>(a, x);
    let le_ba = b.fle::<W64>(x, a);
    let ordered = bor(b, le_ab, le_ba);
    let un = bnot(b, ordered);
    let ltf = bsel64(b, lt, CR_LT, 0);
    let gtf = bsel64(b, gt, CR_GT, 0);
    let eqf = bsel64(b, eq, CR_EQ, 0);
    let unf = bsel64(b, un, CR_SO, 0);
    let f1 = b.or(ltf, gtf);
    let f2 = b.or(eqf, unf);
    let f = b.or(f1, f2);
    set_crf(b, bf, f);
}

/// CR1 = FP 例外フラグ（近似: 何もしない）。
fn record_cr1<B: Backend>(_b: &mut B) {}

/// FP の単項（frsp/fcti*/fcfi*/fneg/fmr/fnabs/fabs/fsqrt/fri*/fcpsgn/ftdiv/ftsqrt）。
fn fp_xo10<B: Backend>(b: &mut B, word: u32, xo10: u32, t: u8, a: u8, bb: u8) -> Option<B::V<W64>> {
    let _ = t;
    let _ = word;
    let _ = a;
    let v: B::V<W64> = match xo10 {
        // frsp: f32 精度に丸める。
        12 => {
            let x = fpr(b, bb);
            let w = b.fcvt_ff::<W64, W32>(x, 0);
            b.fcvt_ff::<W32, W64>(w, 0)
        }
        // fctiw/fctiwz/fctiwu/fctiwuz。
        14 => {
            let x = fpr(b, bb);
            let w = b.fcvt_s32::<W64>(x, 0);
            b.sext::<W32, W64>(w)
        }
        15 => {
            let x = fpr(b, bb);
            let w = b.fcvt_s32::<W64>(x, 1);
            b.sext::<W32, W64>(w)
        }
        142 => {
            let x = fpr(b, bb);
            let w = b.fcvt_u32::<W64>(x, 0);
            b.zext::<W32, W64>(w)
        }
        143 => {
            let x = fpr(b, bb);
            let w = b.fcvt_u32::<W64>(x, 1);
            b.zext::<W32, W64>(w)
        }
        // fctid/fctidz/fctidu/fctiduz。
        814 => {
            let x = fpr(b, bb);
            b.fcvt_s64::<W64>(x, 0)
        }
        815 => {
            let x = fpr(b, bb);
            b.fcvt_s64::<W64>(x, 1)
        }
        942 => {
            let x = fpr(b, bb);
            b.fcvt_u64::<W64>(x, 0)
        }
        943 => {
            let x = fpr(b, bb);
            b.fcvt_u64::<W64>(x, 1)
        }
        // fcfid/fcfidu。
        846 => {
            let x = fpr(b, bb);
            b.fcvt_from_s64::<W64>(x, 0)
        }
        974 => {
            let x = fpr(b, bb);
            b.fcvt_from_u64::<W64>(x, 0)
        }
        // fneg/fmr/fnabs/fabs。
        40 => {
            let x = fpr(b, bb);
            let __h225 = k(b, 1 << 63);
            b.xor(x, __h225)
        }
        72 => fpr(b, bb),
        136 => {
            let x = fpr(b, bb);
            let __h226 = k(b, 1 << 63);
            b.or(x, __h226)
        }
        264 => {
            let x = fpr(b, bb);
            let __h227 = k(b, !(1u64 << 63));
            b.and(x, __h227)
        }
        // fsqrt（A 形式でも見えるが XO10 で先に見る）。
        22 => {
            let x = fpr(b, bb);
            b.fsqrt::<W64>(x)
        }
        // frin/friz/frip/frim: 整数値に丸める。s64 往復で近似。
        392 | 424 | 456 | 488 => {
            let x = fpr(b, bb);
            let rm = match xo10 {
                424 => 1,
                _ => 0,
            };
            let i = b.fcvt_s64::<W64>(x, rm);
            b.fcvt_from_s64::<W64>(i, 0)
        }
        // fcpsgn: 符号を x から y へ。
        8 => {
            let x = fpr(b, a);
            let y = fpr(b, bb);
            let __h228 = k(b, 1 << 63);
            let sign = b.and(x, __h228);
            let __h229 = k(b, !(1u64 << 63));
            let mag = b.and(y, __h229);
            b.or(sign, mag)
        }
        _ => return None,
    };
    Some(v)
}

/// op63: 倍精度 FP と FPSCR 系。
#[allow(clippy::too_many_lines)]
pub fn x63<B: Backend>(b: &mut B, word: u32, _pc: u64, _le: bool) -> Flow<B> {
    let xo10 = (word >> 1) & 0x3ff;
    let xo5 = (word >> 1) & 0x1f;
    let t = ((word >> 21) & 31) as u8;
    let a = ((word >> 16) & 31) as u8;
    let bb = ((word >> 11) & 31) as u8;
    let c = ((word >> 6) & 31) as u8;
    let rc = word & 1 != 0;
    // X 形式（XO10）の一致を先に見る。
    if let Some(v) = fp_xo10(b, word, xo10, t, a, bb) {
        set_fpr(b, t, v);
        if rc {
            record_cr1(b);
        }
        return Ok(());
    }
    match xo10 {
        0 | 32 => {
            // fcmpu/fcmpo。
            let x = fpr(b, a);
            let y = fpr(b, bb);
            do_fcmp(b, ((word >> 23) & 7) as u8, x, y);
            Ok(())
        }
        128 => {
            // ftdiv: 除算可能性検査。近似で LT=0,GT=1,EQ=0,SO=0。
            let f = k(b, CR_GT);
            set_crf(b, ((word >> 23) & 7) as u8, f);
            Ok(())
        }
        160 => {
            // ftsqrt。
            let f = k(b, CR_GT);
            set_crf(b, ((word >> 23) & 7) as u8, f);
            Ok(())
        }
        583 => {
            // mffs: FPSCR を FPR に写す。
            let v = b.get(fpscr_ref());
            set_fpr(b, t, v);
            Ok(())
        }
        711 => {
            // mtfsf: FLM で指定したフィールドを FPRB で上書き。
            let flm = ((word >> 17) & 0xff) as u64;
            let mut mask = 0u64;
            for i in 0..8u64 {
                if flm & (0x80 >> i) != 0 {
                    mask |= 0xf << (28 - 4 * i);
                }
            }
            let fv = fpr(b, bb);
            let __h230 = k(b, mask);
            let ins = b.and(fv, __h230);
            let cur = b.get(fpscr_ref());
            let __h231 = k(b, !mask);
            let keep = b.and(cur, __h231);
            let v = b.or(ins, keep);
            b.set(fpscr_ref(), v);
            Ok(())
        }
        38 | 70 => {
            // mtfsb1/mtfsb0。FPSCR の bit BT（IBM 0–31、LE では 31–BT）。
            let bf = ((word >> 21) & 31) as u64;
            let cur = b.get(fpscr_ref());
            let __h232 = k(b, 1 << (31 - bf));
            let v = if xo10 == 38 {
                b.or(cur, __h232)
            } else {
                let __h233 = k(b, !(1u64 << (31 - bf)));
                b.and(cur, __h233)
            };
            b.set(fpscr_ref(), v);
            Ok(())
        }
        134 => {
            // mtfsfi: フィールド BF（bits25:23）に IMM（bits15:12）を書く。
            let bf = ((word >> 23) & 7) as u64;
            let imm = ((word >> 12) & 0xf) as u64;
            let sh = 28 - 4 * bf;
            let cur = b.get(fpscr_ref());
            let __h234 = k(b, !(0xfu64 << sh));
            let keep = b.and(cur, __h234);
            let put = k(b, imm << sh);
            let v = b.or(keep, put);
            b.set(fpscr_ref(), v);
            Ok(())
        }
        64 => {
            // mcrfs: CR[bf] = FPSCR フィールド（クリアは近似で省略）。
            let bf = ((word >> 23) & 7) as u8;
            let cur = b.get(fpscr_ref());
            let sh = 28 - 4 * u64::from(bf);
            let __h236 = k(b, 0xf);
            let __h421 = k(b, sh);
            let __h235 = b.shr_l(cur, __h421);
            let f = b.and(__h235, __h236);
            set_crf(b, bf, f);
            Ok(())
        }
        _ => {
            // A 形式（XO5）。
            let v: B::V<W64> = match xo5 {
                21 => {
                    let x = fpr(b, a);
                    let y = fpr(b, bb);
                    b.fadd::<W64>(x, y)
                }
                20 => {
                    let x = fpr(b, a);
                    let y = fpr(b, bb);
                    b.fsub::<W64>(x, y)
                }
                25 => {
                    let x = fpr(b, a);
                    let y = fpr(b, c);
                    b.fmul::<W64>(x, y)
                }
                18 => {
                    let x = fpr(b, a);
                    let y = fpr(b, bb);
                    b.fdiv::<W64>(x, y)
                }
                29 => {
                    let x = fpr(b, a);
                    let y = fpr(b, c);
                    let z = fpr(b, bb);
                    b.fmadd::<W64>(x, y, z)
                }
                28 => {
                    let x = fpr(b, a);
                    let y = fpr(b, c);
                    let z = fpr(b, bb);
                    let __h237 = k(b, 0);
                    let nz = b.fsub::<W64>(__h237, z);
                    b.fmadd::<W64>(x, y, nz)
                }
                31 => {
                    let x = fpr(b, a);
                    let y = fpr(b, c);
                    let z = fpr(b, bb);
                    let p = b.fmadd::<W64>(x, y, z);
                    let __h238 = k(b, 0);
                    b.fsub::<W64>(__h238, p)
                }
                30 => {
                    let x = fpr(b, a);
                    let y = fpr(b, c);
                    let z = fpr(b, bb);
                    let __h239 = k(b, 0);
                    let nz = b.fsub::<W64>(__h239, z);
                    let p = b.fmadd::<W64>(x, y, nz);
                    let __h240 = k(b, 0);
                    b.fsub::<W64>(__h240, p)
                }
                23 => {
                    // fsel: A>=+0.0 ? C : B（符号ビットが 0 で非 NaN）。
                    let a0 = fpr(b, a);
                    let __h241 = k(b, 1 << 63);
                    let sm = b.and(a0, __h241);
                    let __h242 = k(b, 0);
                    let pos = b.cmp(Cmp::Eq, sm, __h242);
                    let le1 = b.fle::<W64>(a0, a0); // NaN でない
                    let ok = band(b, pos, le1);
                    let cx = fpr(b, c);
                    let bx = fpr(b, bb);
                    b.select(ok, cx, bx)
                }
                22 => {
                    let x = fpr(b, bb);
                    b.fsqrt::<W64>(x)
                }
                26 => {
                    // frsqrte: 1/sqrt の近似を正確な計算で返す。
                    let x = fpr(b, bb);
                    let sq = b.fsqrt::<W64>(x);
                    let __h243 = k(b, 0x3ff0_0000_0000_0000);
                    b.fdiv::<W64>(__h243, sq)
                }
                _ => return unimp(b, u64::from(xo10)),
            };
            set_fpr(b, t, v);
            if rc {
                record_cr1(b);
            }
            Ok(())
        }
    }
}

/// op59: 単精度 FP（A 形式）と fcfids/fcfidus/dtstsfi。
pub fn x59<B: Backend>(b: &mut B, word: u32, _pc: u64, _le: bool) -> Flow<B> {
    let xo10 = (word >> 1) & 0x3ff;
    let xo5 = (word >> 1) & 0x1f;
    let t = ((word >> 21) & 31) as u8;
    let a = ((word >> 16) & 31) as u8;
    let bb = ((word >> 11) & 31) as u8;
    let c = ((word >> 6) & 31) as u8;
    let rc = word & 1 != 0;
    // XO10 の単項（fcfids/fcfidus/dtstsfi 系）。
    match xo10 {
        334 => {
            // fcfids: s64 → f32。
            let x = fpr(b, bb);
            let v = b.fcvt_from_s64::<W64>(x, 0);
            let w = b.fcvt_ff::<W64, W32>(v, 0);
            let d = b.fcvt_ff::<W32, W64>(w, 0);
            set_fpr(b, t, d);
            if rc {
                record_cr1(b);
            }
            return Ok(());
        }
        462 => {
            // fcfidus。
            let x = fpr(b, bb);
            let v = b.fcvt_from_u64::<W64>(x, 0);
            let w = b.fcvt_ff::<W64, W32>(v, 0);
            let d = b.fcvt_ff::<W32, W64>(w, 0);
            set_fpr(b, t, d);
            if rc {
                record_cr1(b);
            }
            return Ok(());
        }
        675 | 739 | 803 | 867 | 931 | 995 => return Ok(()), // dtstsfi/dtstex 系: NOP 近似。
        _ => {}
    }
    let v32: B::V<W32> = match xo5 {
        21 => {
            let __h244 = fpr(b, a);
            let x = b.fcvt_ff::<W64, W32>(__h244, 0);
            let __h245 = fpr(b, bb);
            let y = b.fcvt_ff::<W64, W32>(__h245, 0);
            b.fadd::<W32>(x, y)
        }
        20 => {
            let __h246 = fpr(b, a);
            let x = b.fcvt_ff::<W64, W32>(__h246, 0);
            let __h247 = fpr(b, bb);
            let y = b.fcvt_ff::<W64, W32>(__h247, 0);
            b.fsub::<W32>(x, y)
        }
        25 => {
            let __h248 = fpr(b, a);
            let x = b.fcvt_ff::<W64, W32>(__h248, 0);
            let __h249 = fpr(b, c);
            let y = b.fcvt_ff::<W64, W32>(__h249, 0);
            b.fmul::<W32>(x, y)
        }
        18 => {
            let __h250 = fpr(b, a);
            let x = b.fcvt_ff::<W64, W32>(__h250, 0);
            let __h251 = fpr(b, bb);
            let y = b.fcvt_ff::<W64, W32>(__h251, 0);
            b.fdiv::<W32>(x, y)
        }
        29 => {
            let __h252 = fpr(b, a);
            let x = b.fcvt_ff::<W64, W32>(__h252, 0);
            let __h253 = fpr(b, c);
            let y = b.fcvt_ff::<W64, W32>(__h253, 0);
            let __h254 = fpr(b, bb);
            let z = b.fcvt_ff::<W64, W32>(__h254, 0);
            b.fmadd::<W32>(x, y, z)
        }
        28 => {
            let __h255 = fpr(b, a);
            let x = b.fcvt_ff::<W64, W32>(__h255, 0);
            let __h256 = fpr(b, c);
            let y = b.fcvt_ff::<W64, W32>(__h256, 0);
            let __h257 = fpr(b, bb);
            let z = b.fcvt_ff::<W64, W32>(__h257, 0);
            let __h258 = k32(b, 0);
            let nz = b.fsub::<W32>(__h258, z);
            b.fmadd::<W32>(x, y, nz)
        }
        31 => {
            let __h259 = fpr(b, a);
            let x = b.fcvt_ff::<W64, W32>(__h259, 0);
            let __h260 = fpr(b, c);
            let y = b.fcvt_ff::<W64, W32>(__h260, 0);
            let __h261 = fpr(b, bb);
            let z = b.fcvt_ff::<W64, W32>(__h261, 0);
            let p = b.fmadd::<W32>(x, y, z);
            let __h262 = k32(b, 0);
            b.fsub::<W32>(__h262, p)
        }
        30 => {
            let __h263 = fpr(b, a);
            let x = b.fcvt_ff::<W64, W32>(__h263, 0);
            let __h264 = fpr(b, c);
            let y = b.fcvt_ff::<W64, W32>(__h264, 0);
            let __h265 = fpr(b, bb);
            let z = b.fcvt_ff::<W64, W32>(__h265, 0);
            let __h266 = k32(b, 0);
            let nz = b.fsub::<W32>(__h266, z);
            let p = b.fmadd::<W32>(x, y, nz);
            let __h267 = k32(b, 0);
            b.fsub::<W32>(__h267, p)
        }
        24 => {
            let __h268 = fpr(b, bb);
            // fres: 1/a の近似。
            let x = b.fcvt_ff::<W64, W32>(__h268, 0);
            let __h269 = k32(b, 0x3f80_0000);
            b.fdiv::<W32>(__h269, x)
        }
        26 => {
            let __h270 = fpr(b, bb);
            // frsqrtes: 1/sqrt の近似。
            let x = b.fcvt_ff::<W64, W32>(__h270, 0);
            let sq = b.fsqrt::<W32>(x);
            let __h271 = k32(b, 0x3f80_0000);
            b.fdiv::<W32>(__h271, sq)
        }
        22 => {
            let __h272 = fpr(b, bb);
            let x = b.fcvt_ff::<W64, W32>(__h272, 0);
            b.fsqrt::<W32>(x)
        }
        _ => return unimp(b, u64::from(xo10)),
    };
    let d = b.fcvt_ff::<W32, W64>(v32, 0);
    set_fpr(b, t, d);
    if rc {
        record_cr1(b);
    }
    Ok(())
}

// ---------------- DS 形式（op58/62） ----------------

/// ld/ldu/lwa（op58）と std/stdu（op62）。DS 形式の即値は
/// imm14 << 2（下位 2 ビットが XO）。
fn ds_i<B: Backend>(b: &mut B, word: u32, load: bool, le: bool) -> Flow<B> {
    let xo = word & 3;
    let t = ((word >> 21) & 31) as u8;
    let r = ((word >> 16) & 31) as u8;
    let imm = (((word >> 2) & 0x3fff) as i32) << 18 >> 18;
    let d = i64::from(imm) << 2;
    if load {
        match xo {
            0 | 1 => ld_d(b, t, r, d, 8, false, xo == 1, le),
            2 => ld_d(b, t, r, d, 4, true, false, le),
            _ => unimp(b, u64::from(xo)),
        }
    } else {
        match xo {
            0 | 1 => st_d(b, t, r, d, 8, xo == 1, le),
            _ => unimp(b, u64::from(xo)),
        }
    }
}

/// op61: lxv/stxv（DQ 形式）。即値は DQ(12bit)<<4、TX は bit3。
fn dq_i<B: Backend>(b: &mut B, word: u32, le: bool) -> Flow<B> {
    let xo3 = word & 7;
    let tx = ((word >> 3) & 1) as u64;
    let t = ((word >> 21) & 31) as u8;
    let r = ((word >> 16) & 31) as u8;
    let xt = (u64::from(t) | (tx << 5)) as u8;
    let imm = (((word >> 4) & 0xfff) as i32) << 20 >> 20;
    let a = ra(b, r);
    let off = k(b, ((i64::from(imm)) << 4) as u64);
    let ea = b.add(a, off);
    match xo3 {
        1 => {
            let acc = data_acc(le, true);
            let v = b.load::<W128>(ea, acc)?;
            set_vsr(b, xt, v);
        }
        5 => {
            let accw = data_acc(le, false);
            let v = vsr(b, xt);
            b.store::<W128>(ea, v, accw)?;
        }
        _ => return unimp(b, u64::from(xo3)),
    }
    Ok(())
}

/// op0: attn（XO=256）。ヒントなので通過する。
pub fn x0<B: Backend>(b: &mut B, word: u32, _pc: u64, _le: bool) -> Flow<B> {
    let xo = (word >> 1) & 0x3ff;
    if xo == 256 {
        Ok(())
    } else {
        unimp(b, u64::from(xo))
    }
}

// ---------------- op60（XX 形式） ----------------

/// XX 形式の VSR 番号の拡張ビットを畳む。
/// T(25:21)+TX(bit0), A(20:16)+AX(bit2), B(15:11)+BX(bit1)。
fn xx_regs(word: u32) -> (u8, u8, u8) {
    let t = (((word >> 21) & 31) | ((word & 1) << 5)) as u8;
    let a = (((word >> 16) & 31) | (((word >> 2) & 1) << 5)) as u8;
    let bb = (((word >> 11) & 31) | (((word >> 1) & 1) << 5)) as u8;
    (t, a, bb)
}

/// FMA の (m0, m1, ad, mode) 選択の戻り。
type FmaSel<V> = (V, V, V, u8);

/// XX3 の madd 系。variant: 0=madd-ad,1=madd-md,2=msub-ad,3=msub-md,
/// 4=nmadd-ad,5=nmadd-md,6=nmsub-ad,7=nmsub-md。
/// ad 形は a*b+t、md 形は t*a+b、sub は加数を引く、n は結果を反転。
#[allow(clippy::too_many_arguments)]
fn xvmadd<B: Backend>(
    b: &mut B,
    t: u8,
    a: u8,
    bb: u8,
    variant: u8,
    mode_sel: u8, // 0=dp ベクタ、1=sp スカラー、2=sp ベクタ、3=dp スカラー
) -> B::V<W128> {
    // (m0, m1, ad, mode) mode: 0=+、1=sub、2=neg-add、3=neg-sub。
    let pick = |x: B::V<W64>, y: B::V<W64>, z: B::V<W64>| -> FmaSel<B::V<W64>> {
        match variant {
            0 => (x, y, z, 0),
            1 => (z, x, y, 0),
            2 => (x, y, z, 1),
            3 => (z, x, y, 1),
            4 => (x, y, z, 2),
            5 => (z, x, y, 2),
            6 => (x, y, z, 3),
            _ => (z, x, y, 3),
        }
    };
    let one = |b: &mut B, m0: B::V<W64>, m1: B::V<W64>, ad: B::V<W64>, mode: u8| -> B::V<W64> {
        let z0 = k(b, 0);
        let p = b.fmadd::<W64>(m0, m1, z0);
        match mode {
            0 => b.fadd::<W64>(p, ad),
            1 => b.fsub::<W64>(p, ad),
            2 => {
                let s = b.fadd::<W64>(p, ad);
                b.fsub::<W64>(z0, s)
            }
            _ => b.fsub::<W64>(ad, p),
        }
    };
    if mode_sel == 1 {
        // f32 先頭ワードのスカラー演算。結果は dw0 の両ワードに複製。
        let f = |b: &mut B, i: u8| -> B::V<W64> {
            let v = vsr(b, i);
            let __h273 = k128(b, 96);
            let hi = b.shr_l(v, __h273);
            let w = b.trunc::<W128, W32>(hi);
            // f32 値を f64 に変換して共通ルートへ。
            b.fcvt_ff::<W32, W64>(w, 0)
        };
        let x = f(b, a);
        let y = f(b, bb);
        let z = f(b, t);
        let (m0, m1, ad, mode) = pick(x, y, z);
        let r = one(b, m0, m1, ad, mode);
        let rw = b.fcvt_ff::<W64, W32>(r, 0);
        let r64 = b.zext::<W32, W64>(rw);
        let __h422 = k(b, 32);
        let __h274 = b.shl(r64, __h422);
        let d = b.or(r64, __h274);
        put_dw0(b, d)
    } else if mode_sel == 2 {
        // f32 4 要素のベクタ演算。
        let f = |b: &mut B, i: u8, j: u128| -> B::V<W64> {
            let v = vsr(b, i);
            let __h275 = k128(b, 96 - j * 32);
            let w0 = b.shr_l(v, __h275);
            let w = b.trunc::<W128, W32>(w0);
            b.fcvt_ff::<W32, W64>(w, 0)
        };
        let mut v = k128(b, 0);
        for j in 0..4u128 {
            let x = f(b, a, j);
            let y = f(b, bb, j);
            let z = f(b, t, j);
            let (m0, m1, ad, mode) = pick(x, y, z);
            let r = one(b, m0, m1, ad, mode);
            let rw = b.fcvt_ff::<W64, W32>(r, 0);
            let rz = b.zext::<W32, W128>(rw);
            let __h276 = k128(b, 96 - j * 32);
            let put = b.shl(rz, __h276);
            v = b.or(v, put);
        }
        v
    } else if mode_sel == 3 {
        // f64 スカラー（dw0 のみ）。
        let (x, y, z) = (vsr_hi(b, a), vsr_hi(b, bb), vsr_hi(b, t));
        let (m0, m1, ad, mode) = pick(x, y, z);
        let r = one(b, m0, m1, ad, mode);
        put_dw0(b, r)
    } else {
        let (x0, y0, z0) = (vsr_hi(b, a), vsr_hi(b, bb), vsr_hi(b, t));
        let (x1, y1, z1) = (vsr_lo(b, a), vsr_lo(b, bb), vsr_lo(b, t));
        let (m0a, m1a, ada, ma) = pick(x0, y0, z0);
        let (m0b, m1b, adb, mb) = pick(x1, y1, z1);
        let ra = one(b, m0a, m1a, ada, ma);
        let rb_ = one(b, m0b, m1b, adb, mb);
        vsr_pack(b, ra, rb_)
    }
}

/// op60。XX3（XO8 = bits10:3）と XX2（XO9 = bits10:2）を振り分ける。
#[allow(clippy::too_many_lines)]
pub fn x60<B: Backend>(b: &mut B, word: u32, _pc: u64, _le: bool) -> Flow<B> {
    let (t, a, bb) = xx_regs(word);
    let xo9 = (word >> 2) & 0x1ff;
    let xo8 = (word >> 3) & 0xff;
    // ---- XX2（XO9）----
    let unary: Option<B::V<W128>> = match xo9 {
        345 => {
            // xsabsdp。
            let v = vsr(b, bb);
            let m = k128(b, !(1u128 << 127));
            Some(b.and(v, m))
        }
        361 => {
            // xsnabsdp。
            let v = vsr(b, bb);
            let m = k128(b, 1u128 << 127);
            Some(b.or(v, m))
        }
        377 => {
            // xsnegdp。
            let v = vsr(b, bb);
            let m = k128(b, 1u128 << 127);
            Some(b.xor(v, m))
        }
        473 => {
            // xvabsdp: 両 dw の符号ビットを消す。
            let m = k128(
                b,
                !(0x8000_0000_0000_0000u128 << 64 | 0x8000_0000_0000_0000),
            );
            let v = vsr(b, bb);
            Some(b.and(v, m))
        }
        489 => {
            // xvnabsdp。
            let m = k128(b, 0x8000_0000_0000_0000u128 << 64 | 0x8000_0000_0000_0000);
            let v = vsr(b, bb);
            Some(b.or(v, m))
        }
        505 => {
            // xvnegdp。
            let m = k128(b, 0x8000_0000_0000_0000u128 << 64 | 0x8000_0000_0000_0000);
            let v = vsr(b, bb);
            Some(b.xor(v, m))
        }
        75 => {
            // xssqrtdp: dw0 のスカラー sqrt。
            let x = vsr_hi(b, bb);
            let v = b.fsqrt::<W64>(x);
            Some(put_dw0(b, v))
        }
        11 => {
            // xssqrtsp: 先頭ワードの f32 sqrt を両ワードに複製。
            let v = vsr(b, bb);
            let __h277 = k128(b, 96);
            let hi = b.shr_l(v, __h277);
            let x = b.trunc::<W128, W32>(hi);
            let sq = b.fsqrt::<W32>(x);
            let r64 = b.zext::<W32, W64>(sq);
            let __h423 = k(b, 32);
            let __h278 = b.shl(r64, __h423);
            let d = b.or(r64, __h278);
            Some(put_dw0(b, d))
        }
        90 => {
            // xsredp: 1/x の近似。除算で計算。
            let x = vsr_hi(b, bb);
            let __h279 = k(b, 0x3ff0_0000_0000_0000);
            let v = b.fdiv::<W64>(__h279, x);
            Some(put_dw0(b, v))
        }
        74 => {
            // xsrsqrtedp: 1/sqrt の近似。
            let x = vsr_hi(b, bb);
            let sq = b.fsqrt::<W64>(x);
            let __h280 = k(b, 0x3ff0_0000_0000_0000);
            let v = b.fdiv::<W64>(__h280, sq);
            Some(put_dw0(b, v))
        }
        26 => {
            // xsresp。
            let v = vsr(b, bb);
            let __h281 = k128(b, 96);
            let hi = b.shr_l(v, __h281);
            let x = b.trunc::<W128, W32>(hi);
            let __h282 = k32(b, 0x3f80_0000);
            let r = b.fdiv::<W32>(__h282, x);
            let r64 = b.zext::<W32, W64>(r);
            let __h424 = k(b, 32);
            let __h283 = b.shl(r64, __h424);
            let d = b.or(r64, __h283);
            Some(put_dw0(b, d))
        }
        10 => {
            // xsrsqrtesp。
            let v = vsr(b, bb);
            let __h284 = k128(b, 96);
            let hi = b.shr_l(v, __h284);
            let x = b.trunc::<W128, W32>(hi);
            let sq = b.fsqrt::<W32>(x);
            let __h285 = k32(b, 0x3f80_0000);
            let r = b.fdiv::<W32>(__h285, sq);
            let r64 = b.zext::<W32, W64>(r);
            let __h425 = k(b, 32);
            let __h286 = b.shl(r64, __h425);
            let d = b.or(r64, __h286);
            Some(put_dw0(b, d))
        }
        // ---- 丸め（xsrdpi 系）。s64 往復で近似。----
        73 | 89 | 105 | 107 | 121 => {
            let x = vsr_hi(b, bb);
            let i = b.fcvt_s64::<W64>(x, 0);
            let v = b.fcvt_from_s64::<W64>(i, 0);
            Some(put_dw0(b, v))
        }
        // ---- 変換 ----
        267 => {
            // xscvdpspn: dw0 の f64 を f32 ビット列へ（先頭ワード）。
            let x = vsr_hi(b, bb);
            let w = b.fcvt_ff::<W64, W32>(x, 0);
            let wz = b.zext::<W32, W128>(w);
            let __h287 = k128(b, 96);
            Some(b.shl(wz, __h287))
        }
        331 => {
            // xscvspdpn: 先頭ワードの f32 ビット列を f64 へ。
            let v = vsr(b, bb);
            let __h288 = k128(b, 96);
            let hi = b.shr_l(v, __h288);
            let w = b.trunc::<W128, W32>(hi);
            let x = b.fcvt_ff::<W32, W64>(w, 0);
            Some(put_dw0(b, x))
        }
        265 => {
            // xscvdpsp: dw0 f64 → f32→f64 へ丸める。
            let x = vsr_hi(b, bb);
            let w = b.fcvt_ff::<W64, W32>(x, 0);
            let v = b.fcvt_ff::<W32, W64>(w, 0);
            Some(put_dw0(b, v))
        }
        281 => {
            // xsrsp: 同上（f32 精度への丸め）。
            let x = vsr_hi(b, bb);
            let w = b.fcvt_ff::<W64, W32>(x, 0);
            let v = b.fcvt_ff::<W32, W64>(w, 0);
            Some(put_dw0(b, v))
        }
        344 => {
            // xscvdpsxds: dw0 f64 → s64。
            let x = vsr_hi(b, bb);
            let v = b.fcvt_s64::<W64>(x, 1);
            Some(put_dw0(b, v))
        }
        88 => {
            // xscvdpsxws: dw0 f64 → s32。結果は dw0 の両ワードに複製。
            let x = vsr_hi(b, bb);
            let w = b.fcvt_s32::<W64>(x, 1);
            let v = b.sext::<W32, W64>(w);
            let __h426 = k(b, 32);
            let __h289 = b.shl(v, __h426);
            let d = b.or(v, __h289);
            Some(put_dw0(b, d))
        }
        328 => {
            // xscvdpuxds。
            let x = vsr_hi(b, bb);
            let v = b.fcvt_u64::<W64>(x, 1);
            Some(put_dw0(b, v))
        }
        72 => {
            // xscvdpuxws。
            let x = vsr_hi(b, bb);
            let w = b.fcvt_u32::<W64>(x, 1);
            let v = b.zext::<W32, W64>(w);
            let __h427 = k(b, 32);
            let __h290 = b.shl(v, __h427);
            let d = b.or(v, __h290);
            Some(put_dw0(b, d))
        }
        296 => {
            // xscvuxdsp: dw0 u64 → f32（先頭ワードの f32 ビット）。
            let x = vsr_hi(b, bb);
            let v = b.fcvt_from_u64::<W64>(x, 0);
            let w = b.fcvt_ff::<W64, W32>(v, 0);
            let wz = b.zext::<W32, W128>(w);
            let __h291 = k128(b, 96);
            Some(b.shl(wz, __h291))
        }
        376 => {
            // xscvsxddp。
            let x = vsr_hi(b, bb);
            let v = b.fcvt_from_s64::<W64>(x, 0);
            Some(put_dw0(b, v))
        }
        360 => {
            // xscvuxddp。
            let x = vsr_hi(b, bb);
            let v = b.fcvt_from_u64::<W64>(x, 0);
            Some(put_dw0(b, v))
        }
        312 => {
            // xscvsxdsp。
            let x = vsr_hi(b, bb);
            let v = b.fcvt_from_s64::<W64>(x, 0);
            let w = b.fcvt_ff::<W64, W32>(v, 0);
            let wz = b.zext::<W32, W128>(w);
            let __h292 = k128(b, 96);
            Some(b.shl(wz, __h292))
        }
        // ---- XX2 の混ぜ・抜き出し ----
        164 => {
            // xxspltw: ワード複製。UIM=bits17:16。
            let uim = u128::from((word >> 16) & 3);
            let v0 = vsr(b, bb);
            let sh = k128(b, 96 - uim * 32);
            let w0 = b.shr_l(v0, sh);
            let w = b.trunc::<W128, W32>(w0);
            let w128 = b.zext::<W32, W128>(w);
            let __h293 = k128(b, 32);
            let s1 = b.shl(w128, __h293);
            let __h294 = k128(b, 64);
            let s2 = b.shl(w128, __h294);
            let __h295 = k128(b, 96);
            let s3 = b.shl(w128, __h295);
            let m01 = b.or(w128, s1);
            let m23 = b.or(s2, s3);
            Some(b.or(m01, m23))
        }
        165 => {
            // xxextractuw: ワード UIM を右端（IBM word3=LSB 側）へ。
            let uim = u128::from((word >> 16) & 3);
            let v0 = vsr(b, bb);
            let sh = k128(b, 96 - uim * 32);
            let w0 = b.shr_l(v0, sh);
            let w = b.trunc::<W128, W32>(w0);
            Some(b.zext::<W32, W128>(w))
        }
        // ---- ベクタの sp↔dp・int↔fp 変換 ----
        393 => {
            // xvcvdpsp: dw0=[f32(hi),f32(lo)]、dw1=0。
            let x0 = vsr_hi(b, bb);
            let x1 = vsr_lo(b, bb);
            let f0 = b.fcvt_ff::<W64, W32>(x0, 0);
            let f1 = b.fcvt_ff::<W64, W32>(x1, 0);
            let z0 = b.zext::<W32, W64>(f0);
            let z1 = b.zext::<W32, W64>(f1);
            let __h296 = k(b, 32);
            let sh = b.shl(z0, __h296);
            let hi = b.or(sh, z1);
            let __h297 = k(b, 0);
            Some(vsr_pack(b, hi, __h297))
        }
        457 => {
            // xvcvspdp: dw[i] = f64(偶数ワード i*2)。
            let v = vsr(b, bb);
            let __h428 = k128(b, 96);
            let __h298 = b.shr_l(v, __h428);
            let w0 = b.trunc::<W128, W32>(__h298);
            let __h429 = k128(b, 32);
            let __h299 = b.shr_l(v, __h429);
            let w1 = b.trunc::<W128, W32>(__h299);
            let f0 = b.fcvt_ff::<W32, W64>(w0, 0);
            let f1 = b.fcvt_ff::<W32, W64>(w1, 0);
            Some(vsr_pack(b, f0, f1))
        }
        248 | 232 => {
            // xvcvsxwdp/xvcvuxwdp: 偶数ワードの符号(なし)付き→f64。
            let v = vsr(b, bb);
            let __h430 = k128(b, 96);
            let __h300 = b.shr_l(v, __h430);
            let w0 = b.trunc::<W128, W32>(__h300);
            let __h431 = k128(b, 32);
            let __h301 = b.shr_l(v, __h431);
            let w1 = b.trunc::<W128, W32>(__h301);
            let (f0, f1) = if xo9 == 248 {
                let i0 = b.sext::<W32, W64>(w0);
                let i1 = b.sext::<W32, W64>(w1);
                (b.fcvt_from_s64::<W64>(i0, 0), b.fcvt_from_s64::<W64>(i1, 0))
            } else {
                let i0 = b.zext::<W32, W64>(w0);
                let i1 = b.zext::<W32, W64>(w1);
                (b.fcvt_from_u64::<W64>(i0, 0), b.fcvt_from_u64::<W64>(i1, 0))
            };
            Some(vsr_pack(b, f0, f1))
        }
        216 | 200 => {
            // xvcvdpsxws/xvcvdpuxws: dw→s32/u32。偶数ワードに結果、
            // 奇数ワードは 0。
            let x0 = vsr_hi(b, bb);
            let x1 = vsr_lo(b, bb);
            let (w0, w1) = if xo9 == 216 {
                (b.fcvt_s32::<W64>(x0, 1), b.fcvt_s32::<W64>(x1, 1))
            } else {
                (b.fcvt_u32::<W64>(x0, 1), b.fcvt_u32::<W64>(x1, 1))
            };
            let z0 = b.zext::<W32, W128>(w0);
            let z1 = b.zext::<W32, W128>(w1);
            let __h302 = k128(b, 96);
            let p0 = b.shl(z0, __h302);
            let __h303 = k128(b, 32);
            let p1 = b.shl(z1, __h303);
            Some(b.or(p0, p1))
        }
        408 | 392 => {
            // xvcvspsxds/xvcvspuxds: ワードの f32 → s64/u64。
            let v = vsr(b, bb);
            let __h432 = k128(b, 96);
            let __h304 = b.shr_l(v, __h432);
            let w0 = b.trunc::<W128, W32>(__h304);
            let __h433 = k128(b, 32);
            let __h305 = b.shr_l(v, __h433);
            let w1 = b.trunc::<W128, W32>(__h305);
            let (i0, i1) = if xo9 == 408 {
                (b.fcvt_s64::<W32>(w0, 1), b.fcvt_s64::<W32>(w1, 1))
            } else {
                (b.fcvt_u64::<W32>(w0, 1), b.fcvt_u64::<W32>(w1, 1))
            };
            Some(vsr_pack(b, i0, i1))
        }
        184 | 168 => {
            // xvcvsxwsp/xvcvuxwsp: ワード整数→f32（そのまま）。
            let v = vsr(b, bb);
            let mut vv = k128(b, 0);
            for i in 0..4u128 {
                let __h434 = k128(b, 96 - i * 32);
                let __h306 = b.shr_l(v, __h434);
                let w = b.trunc::<W128, W32>(__h306);
                let f = if xo9 == 184 {
                    let s = b.sext::<W32, W64>(w);
                    let f64 = b.fcvt_from_s64::<W64>(s, 0);
                    b.fcvt_ff::<W64, W32>(f64, 0)
                } else {
                    let u = b.zext::<W32, W64>(w);
                    let f64 = b.fcvt_from_u64::<W64>(u, 0);
                    b.fcvt_ff::<W64, W32>(f64, 0)
                };
                let fz = b.zext::<W32, W128>(f);
                let __h307 = k128(b, 96 - i * 32);
                let put = b.shl(fz, __h307);
                vv = b.or(vv, put);
            }
            Some(vv)
        }
        440 | 424 => {
            // xvcvsxdsp/xvcvuxdsp: dw 整数→f32 を先頭ワードへ。
            let x0 = vsr_hi(b, bb);
            let x1 = vsr_lo(b, bb);
            let (f0, f1) = if xo9 == 440 {
                (b.fcvt_from_s64::<W64>(x0, 0), b.fcvt_from_s64::<W64>(x1, 0))
            } else {
                (b.fcvt_from_u64::<W64>(x0, 0), b.fcvt_from_u64::<W64>(x1, 0))
            };
            let w0 = b.fcvt_ff::<W64, W32>(f0, 0);
            let w1 = b.fcvt_ff::<W64, W32>(f1, 0);
            let z0 = b.zext::<W32, W128>(w0);
            let z1 = b.zext::<W32, W128>(w1);
            let __h308 = k128(b, 96);
            let p0 = b.shl(z0, __h308);
            let __h309 = k128(b, 64);
            let p1 = b.shl(z1, __h309);
            Some(b.or(p0, p1))
        }
        // ---- ベクタ変換（両 dw）----
        472 => {
            // xvcvdpsxds。
            let x0 = vsr_hi(b, bb);
            let x1 = vsr_lo(b, bb);
            let v0 = b.fcvt_s64::<W64>(x0, 1);
            let v1 = b.fcvt_s64::<W64>(x1, 1);
            Some(vsr_pack(b, v0, v1))
        }
        456 => {
            // xvcvdpuxds。
            let x0 = vsr_hi(b, bb);
            let x1 = vsr_lo(b, bb);
            let v0 = b.fcvt_u64::<W64>(x0, 1);
            let v1 = b.fcvt_u64::<W64>(x1, 1);
            Some(vsr_pack(b, v0, v1))
        }
        504 => {
            // xvcvsxddp。
            let x0 = vsr_hi(b, bb);
            let x1 = vsr_lo(b, bb);
            let v0 = b.fcvt_from_s64::<W64>(x0, 0);
            let v1 = b.fcvt_from_s64::<W64>(x1, 0);
            Some(vsr_pack(b, v0, v1))
        }
        488 => {
            // xvcvuxddp。
            let x0 = vsr_hi(b, bb);
            let x1 = vsr_lo(b, bb);
            let v0 = b.fcvt_from_u64::<W64>(x0, 0);
            let v1 = b.fcvt_from_u64::<W64>(x1, 0);
            Some(vsr_pack(b, v0, v1))
        }
        475 => {
            // xxbrd/xxbrw/xxbrh: 要素幅は a フィールド（7=hw,15=w,23=dw）。
            let sz = match a {
                7 => 16u128,
                15 => 32,
                _ => 64,
            };
            let v = vsr(b, bb);
            let elems = 128 / sz;
            let mut r = k128(b, 0);
            for i in 0..elems {
                let e = lane(b, v, sz, i);
                let e64 = b.trunc::<W128, W64>(e);
                let sw = match sz {
                    16 => {
                        let w = b.trunc::<W64, W16>(e64);
                        let r = bswap16(b, w);
                        b.zext::<W16, W64>(r)
                    }
                    32 => {
                        let w = b.trunc::<W64, W32>(e64);
                        let r = bswap32(b, w);
                        b.zext::<W32, W64>(r)
                    }
                    _ => bswap64(b, e64),
                };
                let sw128 = b.zext::<W64, W128>(sw);
                r = put_lane(b, r, sz, i, sw128);
            }
            Some(r)
        }
        _ => None,
    };
    if let Some(v) = unary {
        set_vsr(b, t, v);
        return Ok(());
    }
    // ---- XX4（xxsel: XO8 の下位 3 ビットが 6）----
    if xo8 & 7 == 6 {
        let c = (((word >> 6) & 31) | (((word >> 3) & 1) << 5)) as u8;
        let x = vsr(b, a);
        let y = vsr(b, bb);
        let cc = vsr(b, c);
        let nc = b.not(cc);
        let lhs = b.and(x, nc);
        let rhs = b.and(y, cc);
        let v = b.or(lhs, rhs);
        set_vsr(b, t, v);
        return Ok(());
    }
    // ---- XX3（XO8）----
    // スカラー dp 演算。
    let scalar: Option<B::V<W64>> = match xo8 {
        32 => {
            let x = vsr_hi(b, a);
            let y = vsr_hi(b, bb);
            Some(b.fadd::<W64>(x, y))
        }
        40 => {
            let x = vsr_hi(b, a);
            let y = vsr_hi(b, bb);
            Some(b.fsub::<W64>(x, y))
        }
        48 => {
            let x = vsr_hi(b, a);
            let y = vsr_hi(b, bb);
            Some(b.fmul::<W64>(x, y))
        }
        56 => {
            let x = vsr_hi(b, a);
            let y = vsr_hi(b, bb);
            Some(b.fdiv::<W64>(x, y))
        }
        160 | 144 => {
            // xsmaxdp/xsmaxjdp（NaN 規則の差は近似で無視）。
            let x = vsr_hi(b, a);
            let y = vsr_hi(b, bb);
            Some(b.fmax::<W64>(x, y))
        }
        168 | 152 => {
            // xsmindp/xsminjdp。
            let x = vsr_hi(b, a);
            let y = vsr_hi(b, bb);
            Some(b.fmin::<W64>(x, y))
        }
        _ => None,
    };
    if let Some(v) = scalar {
        set_fpr(b, t, v);
        return Ok(());
    }
    // 単精度スカラー（xsaddsp/xssubsp/xsmulsp/xsdivsp）。
    if matches!(xo8, 0 | 8 | 16 | 24) {
        let f = |b: &mut B, i: u8| -> B::V<W32> {
            let v = vsr(b, i);
            let __h310 = k128(b, 96);
            let hi = b.shr_l(v, __h310);
            b.trunc::<W128, W32>(hi)
        };
        let (x, y) = (f(b, a), f(b, bb));
        let r = match xo8 {
            0 => b.fadd::<W32>(x, y),
            8 => b.fsub::<W32>(x, y),
            16 => b.fmul::<W32>(x, y),
            24 => b.fdiv::<W32>(x, y),
            144 => b.fmax::<W32>(x, y),
            _ => b.fmin::<W32>(x, y),
        };
        let r64 = b.zext::<W32, W64>(r);
        let __h435 = k(b, 32);
        let __h311 = b.shl(r64, __h435);
        let d = b.or(r64, __h311);
        set_fpr(b, t, d);
        return Ok(());
    }
    // madd 系（dp=XX3 xo8、sp=さらに -32）。
    match xo8 {
        33 | 41 | 49 | 57 | 161 | 169 | 177 | 185 => {
            let variant = match xo8 {
                33 => 0,
                41 => 1,
                49 => 2,
                57 => 3,
                161 => 4,
                169 => 5,
                177 => 6,
                _ => 7,
            };
            let v = xvmadd(b, t, a, bb, variant, 3);
            set_vsr(b, t, v);
            return Ok(());
        }
        1 | 9 | 17 | 25 | 129 | 137 | 145 | 153 => {
            let variant = match xo8 {
                1 => 0,
                9 => 1,
                17 => 2,
                25 => 3,
                129 => 4,
                137 => 5,
                145 => 6,
                _ => 7,
            };
            let v = xvmadd(b, t, a, bb, variant, 1);
            set_vsr(b, t, v);
            return Ok(());
        }
        _ => {}
    }
    // xxpermdi/xxspltd/xxswapd（DM は bits9:8）。
    if matches!(xo8, 10 | 42 | 74 | 106) {
        let dm = (word >> 8) & 3;
        let s0 = if dm & 2 != 0 {
            vsr_lo(b, a)
        } else {
            vsr_hi(b, a)
        };
        let s1 = if dm & 1 != 0 {
            vsr_lo(b, bb)
        } else {
            vsr_hi(b, bb)
        };
        let v = vsr_pack(b, s0, s1);
        set_vsr(b, t, v);
        return Ok(());
    }
    // xxsldwi（SHW は bits9:8）。
    if matches!(xo8, 2 | 34 | 66 | 98) {
        let shw = u128::from((word >> 8) & 3) * 32;
        let x = vsr(b, a);
        let y = vsr(b, bb);
        let v = if shw == 0 {
            x
        } else {
            let sh = k128(b, shw);
            let lo = b.shl(x, sh);
            let inv = k128(b, 128 - shw);
            let hi = b.shr_l(y, inv);
            b.or(lo, hi)
        };
        set_vsr(b, t, v);
        return Ok(());
    }
    match xo8 {
        // ベクタ dw 演算。
        96 | 104 | 112 | 120 | 224 | 232 => {
            let a0 = vsr_hi(b, a);
            let a1 = vsr_lo(b, a);
            let b0 = vsr_hi(b, bb);
            let b1 = vsr_lo(b, bb);
            let (r0, r1) = match xo8 {
                96 => (b.fadd::<W64>(a0, b0), b.fadd::<W64>(a1, b1)),
                104 => (b.fsub::<W64>(a0, b0), b.fsub::<W64>(a1, b1)),
                112 => (b.fmul::<W64>(a0, b0), b.fmul::<W64>(a1, b1)),
                120 => (b.fdiv::<W64>(a0, b0), b.fdiv::<W64>(a1, b1)),
                224 => (b.fmax::<W64>(a0, b0), b.fmax::<W64>(a1, b1)),
                _ => (b.fmin::<W64>(a0, b0), b.fmin::<W64>(a1, b1)),
            };
            let v = vsr_pack(b, r0, r1);
            set_vsr(b, t, v);
            Ok(())
        }
        // ベクタ単精度（xvaddsp 等）。各ワードの f32 同士。
        64 | 72 | 80 | 88 | 192 | 200 => {
            let x = vsr(b, a);
            let y = vsr(b, bb);
            let mut v = k128(b, 0);
            for i in 0..4u128 {
                let sh = k128(b, 96 - i * 32);
                let xw0 = b.shr_l(x, sh);
                let xw = b.trunc::<W128, W32>(xw0);
                let yw0 = b.shr_l(y, sh);
                let yw = b.trunc::<W128, W32>(yw0);
                let r = match xo8 {
                    64 => b.fadd::<W32>(xw, yw),
                    72 => b.fsub::<W32>(xw, yw),
                    80 => b.fmul::<W32>(xw, yw),
                    88 => b.fdiv::<W32>(xw, yw),
                    192 => b.fmax::<W32>(xw, yw),
                    _ => b.fmin::<W32>(xw, yw),
                };
                let rz = b.zext::<W32, W128>(r);
                let put = b.shl(rz, sh);
                v = b.or(v, put);
            }
            set_vsr(b, t, v);
            Ok(())
        }
        // 論理（XX3 ビット演算）。
        130 | 138 | 146 | 154 | 162 | 170 | 178 | 186 => {
            let x = vsr(b, a);
            let y = vsr(b, bb);
            let v = match xo8 {
                130 => b.and(x, y),
                138 => {
                    let ny = b.not(y);
                    b.and(x, ny)
                }
                146 => b.or(x, y),
                154 => b.xor(x, y),
                162 => {
                    let z = b.or(x, y);
                    b.not(z)
                }
                170 => {
                    let ny = b.not(y);
                    b.or(x, ny)
                }
                178 => {
                    let z = b.and(x, y);
                    b.not(z)
                }
                _ => {
                    let z = b.xor(x, y);
                    b.not(z)
                }
            };
            set_vsr(b, t, v);
            Ok(())
        }
        // xvcpsgndp（xvmovdp は a==b の別名）。
        240 => {
            let x = vsr(b, a);
            let y = vsr(b, bb);
            let smask = k128(b, 0x8000_0000_0000_0000u128 << 64 | 0x8000_0000_0000_0000);
            let nmask = k128(
                b,
                !(0x8000_0000_0000_0000u128 << 64 | 0x8000_0000_0000_0000),
            );
            let sign = b.and(x, smask);
            let mag = b.and(y, nmask);
            let v = b.or(sign, mag);
            set_vsr(b, t, v);
            Ok(())
        }
        // xxmrghw/xxmrglw: ワードの交差。
        18 | 50 => {
            let x = vsr(b, a);
            let y = vsr(b, bb);
            let mut v = k128(b, 0);
            for i in 0..4u128 {
                let sel = if xo8 == 18 { i / 2 } else { i / 2 + 2 };
                let src = if i % 2 == 0 { x } else { y };
                let sh = k128(b, 96 - sel * 32);
                let w0 = b.shr_l(src, sh);
                let w = b.trunc::<W128, W32>(w0);
                let wz = b.zext::<W32, W128>(w);
                let __h312 = k128(b, 96 - i * 32);
                let put = b.shl(wz, __h312);
                v = b.or(v, put);
            }
            set_vsr(b, t, v);
            Ok(())
        }
        // xxinsertw: VSR[A] の word UIM を B の右端ワードで置く。
        90 => {
            let uim = u128::from((word >> 16) & 3);
            let av = vsr(b, a);
            let bv = vsr(b, bb);
            let __h313 = k128(b, 0xffff_ffff);
            let e = b.and(bv, __h313);
            let mask = 0xffff_ffffu128;
            let off = 96 - uim * 32;
            let __h314 = k128(b, !(mask << off));
            let clr = b.and(av, __h314);
            let __h315 = k128(b, off);
            let put = b.shl(e, __h315);
            let v = b.or(clr, put);
            set_vsr(b, t, v);
            Ok(())
        }
        // xscmpudp/xscmpeqdp/xscmpgtdp/xscmpgedp（CR bf への FP 比較）。
        3 | 11 | 19 | 35 => {
            let bf = ((word >> 23) & 7) as u8;
            let x = vsr_hi(b, a);
            let y = vsr_hi(b, bb);
            do_fcmp(b, bf, x, y);
            Ok(())
        }
        // xvsqrtdp（近似: 各 dw の sqrt）。
        101 => {
            let __h316 = vsr_hi(b, bb);
            let v0 = b.fsqrt::<W64>(__h316);
            let __h317 = vsr_lo(b, bb);
            let v1 = b.fsqrt::<W64>(__h317);
            let v = vsr_pack(b, v0, v1);
            set_vsr(b, t, v);
            Ok(())
        }
        // xvmadd*dp（xvmaddadp=97, xvmaddmdp=105 等）。
        97 | 105 | 113 | 121 | 225 | 233 | 241 | 249 => {
            let variant = match xo8 {
                97 => 0,
                105 => 1,
                113 => 2,
                121 => 3,
                225 => 4,
                233 => 5,
                241 => 6,
                _ => 7,
            };
            let v = xvmadd(b, t, a, bb, variant, 0);
            set_vsr(b, t, v);
            Ok(())
        }
        // xvmadd*sp。
        65 | 73 | 81 | 89 | 193 | 201 | 209 | 217 => {
            let variant = match xo8 {
                65 => 0,
                73 => 1,
                81 => 2,
                89 => 3,
                193 => 4,
                201 => 5,
                209 => 6,
                _ => 7,
            };
            let v = xvmadd(b, t, a, bb, variant, 2);
            set_vsr(b, t, v);
            Ok(())
        }
        _ => unimp(b, u64::from(xo8)),
    }
}

// ---------------- op4（AltiVec/VMX） ----------------

/// VSR の IBM 要素 i（0 が最上位）を取り出す。sz はビット幅。
fn lane<B: Backend>(b: &mut B, v: B::V<W128>, sz: u128, i: u128) -> B::V<W128> {
    let elems = 128 / sz;
    let off = (elems - 1 - i) * sz;
    let mask = if sz == 128 {
        u128::MAX
    } else {
        (1u128 << sz) - 1
    };
    let sh = k128(b, off);
    let e = b.shr_l(v, sh);
    let __h318 = k128(b, mask);
    b.and(e, __h318)
}

/// IBM 要素 i に値を置く。
fn put_lane<B: Backend>(
    b: &mut B,
    acc: B::V<W128>,
    sz: u128,
    i: u128,
    e: B::V<W128>,
) -> B::V<W128> {
    let elems = 128 / sz;
    let off = (elems - 1 - i) * sz;
    let mask = if sz == 128 {
        u128::MAX
    } else {
        (1u128 << sz) - 1
    };
    let __h319 = k128(b, mask);
    let em = b.and(e, __h319);
    let __h320 = k128(b, off);
    let put = b.shl(em, __h320);
    b.or(acc, put)
}

/// 要素幅別の加減算（mod 演算、幅内で折り返す）。
fn lane_addsub<B: Backend>(
    b: &mut B,
    x: B::V<W128>,
    y: B::V<W128>,
    sz: u128,
    sub: bool,
) -> B::V<W128> {
    let elems = 128 / sz;
    let mask = if sz == 128 {
        u128::MAX
    } else {
        (1u128 << sz) - 1
    };
    let mut v = k128(b, 0);
    for i in 0..elems {
        let a = lane(b, x, sz, i);
        let c = lane(b, y, sz, i);
        let r = if sub { b.sub(a, c) } else { b.add(a, c) };
        let __h321 = k128(b, mask);
        let rm = b.and(r, __h321);
        v = put_lane(b, v, sz, i, rm);
    }
    v
}

/// 要素幅別の飽和加減算。signed で符号あり飽和。
fn lane_sat_addsub<B: Backend>(
    b: &mut B,
    x: B::V<W128>,
    y: B::V<W128>,
    sz: u128,
    sub: bool,
    signed: bool,
) -> B::V<W128> {
    let elems = 128 / sz;
    let mask = if sz == 128 {
        u128::MAX
    } else {
        (1u128 << sz) - 1
    };
    let (smax, smin): (u64, i64) = match sz {
        8 => (0x7f, -128),
        16 => (0x7fff, -32768),
        _ => (0x7fff_ffff, -0x8000_0000),
    };
    let mut v = k128(b, 0);
    for i in 0..elems {
        let a = lane(b, x, sz, i);
        let c = lane(b, y, sz, i);
        let a64 = b.trunc::<W128, W64>(a);
        let c64 = b.trunc::<W128, W64>(c);
        let (se, ce) = if sz == 8 {
            let as8 = b.trunc::<W64, W8>(a64);
            let cs8 = b.trunc::<W64, W8>(c64);
            (b.sext::<W8, W64>(as8), b.sext::<W8, W64>(cs8))
        } else if sz == 16 {
            let as16 = b.trunc::<W64, W16>(a64);
            let cs16 = b.trunc::<W64, W16>(c64);
            (b.sext::<W16, W64>(as16), b.sext::<W16, W64>(cs16))
        } else {
            let as32 = b.trunc::<W64, W32>(a64);
            let cs32 = b.trunc::<W64, W32>(c64);
            (b.sext::<W32, W64>(as32), b.sext::<W32, W64>(cs32))
        };
        let (ae, ce) = if signed { (se, ce) } else { (a64, c64) };
        let r = if sub { b.sub(ae, ce) } else { b.add(ae, ce) };
        let (hi_lim, lo_lim) = if signed {
            (smax as i64, smin)
        } else {
            ((1i64 << sz.min(63)) - 1, 0)
        };
        let __h322 = k(b, hi_lim as u64);
        let over = if signed {
            b.cmp(Cmp::GtS, r, __h322)
        } else {
            let __h323 = k(b, hi_lim as u64);
            b.cmp(Cmp::GtU, r, __h323)
        };
        let __h324 = k(b, lo_lim as u64);
        let under = if signed {
            b.cmp(Cmp::LtS, r, __h324)
        } else {
            // 符号なしの引き算での underflow: r の 64 ビットの負値。
            if sub {
                let __h325 = k(b, mask as u64);
                b.cmp(Cmp::GtU, r, __h325)
            } else {
                zero_b(b)
            }
        };
        let __h436 = k(b, lo_lim as u64 & mask as u64);
        let __h327 = b.select(under, __h436, r);
        let __h326 = k(b, hi_lim as u64 & mask as u64);
        let clipped = b.select(over, __h326, __h327);
        let c128 = b.zext::<W64, W128>(clipped);
        let __h328 = k128(b, mask);
        let cm = b.and(c128, __h328);
        v = put_lane(b, v, sz, i, cm);
    }
    v
}

/// 要素幅別の比較。戻り値は（結果ベクタ, 全要素成立, 全要素不成立）。
fn lane_cmp<B: Backend>(
    b: &mut B,
    x: B::V<W128>,
    y: B::V<W128>,
    sz: u128,
    mode: u8,
) -> (B::V<W128>, B::B, B::B) {
    let elems = 128 / sz;
    let mask = if sz == 128 {
        u128::MAX
    } else {
        (1u128 << sz) - 1
    };
    let mut v = k128(b, 0);
    let mut all_t = k(b, 1u64);
    let mut all_f = k(b, 1u64);
    let __h331 = k(b, 0);
    for i in 0..elems {
        let a = lane(b, x, sz, i);
        let c = lane(b, y, sz, i);
        let a64 = b.trunc::<W128, W64>(a);
        let c64 = b.trunc::<W128, W64>(c);
        // 符号付きは上位を埋めて比較する。
        let (as_, cs) = if sz == 8 {
            let as8 = b.trunc::<W64, W8>(a64);
            let cs8 = b.trunc::<W64, W8>(c64);
            (b.sext::<W8, W64>(as8), b.sext::<W8, W64>(cs8))
        } else if sz == 16 {
            let as16 = b.trunc::<W64, W16>(a64);
            let cs16 = b.trunc::<W64, W16>(c64);
            (b.sext::<W16, W64>(as16), b.sext::<W16, W64>(cs16))
        } else if sz == 32 {
            let as32 = b.trunc::<W64, W32>(a64);
            let cs32 = b.trunc::<W64, W32>(c64);
            (b.sext::<W32, W64>(as32), b.sext::<W32, W64>(cs32))
        } else {
            (a64, c64)
        };
        let hit = match mode {
            0 => b.cmp(Cmp::Eq, a64, c64),
            1 => b.cmp(Cmp::GtS, as_, cs),
            _ => b.cmp(Cmp::GtU, a64, c64),
        };
        let __h330 = k128(b, 0);
        let __h329 = k128(b, mask);
        let hitv = b.select(hit, __h329, __h330);
        v = put_lane(b, v, sz, i, hitv);
        let hv = bsel64(b, hit, 1, 0);
        all_t = b.and(all_t, hv);
        let nh = bnot(b, hit);
        let nhf = bsel64(b, nh, 1, 0);
        all_f = b.and(all_f, nhf);
    }
    let at = b.cmp(Cmp::Ne, all_t, __h331);
    let __h332 = k(b, 0);
    let af = b.cmp(Cmp::Ne, all_f, __h332);
    (v, at, af)
}

/// 要素幅別のシフト。右シフトは論理、arith で算術。量は各要素の下位 log2(sz) ビット。
fn lane_shift<B: Backend>(
    b: &mut B,
    x: B::V<W128>,
    y: B::V<W128>,
    sz: u128,
    left: bool,
    arith: bool,
) -> B::V<W128> {
    let elems = 128 / sz;
    let mask = if sz == 128 {
        u128::MAX
    } else {
        (1u128 << sz) - 1
    };
    let lgsz = sz - 1;
    let mut v = k128(b, 0);
    for i in 0..elems {
        let e = lane(b, x, sz, i);
        let s0 = lane(b, y, sz, i);
        let __h333 = k128(b, lgsz);
        let s = b.and(s0, __h333);
        let r = if left {
            b.shl(e, s)
        } else if arith {
            // 符号拡張して算術シフト（sz<64 のみ）。
            let e64 = b.trunc::<W128, W64>(e);
            let se = if sz == 8 {
                let w = b.trunc::<W64, W8>(e64);
                b.sext::<W8, W64>(w)
            } else if sz == 16 {
                let w = b.trunc::<W64, W16>(e64);
                b.sext::<W16, W64>(w)
            } else {
                let w = b.trunc::<W64, W32>(e64);
                b.sext::<W32, W64>(w)
            };
            let s64 = b.trunc::<W128, W64>(s);
            let sh = b.shr_a(se, s64);
            b.zext::<W64, W128>(sh)
        } else {
            b.shr_l(e, s)
        };
        let __h334 = k128(b, mask);
        let rm = b.and(r, __h334);
        v = put_lane(b, v, sz, i, rm);
    }
    v
}

/// 要素幅別の回転（vrlb/vrlh/vrlw）。
fn lane_rotl<B: Backend>(b: &mut B, x: B::V<W128>, y: B::V<W128>, sz: u128) -> B::V<W128> {
    let elems = 128 / sz;
    let mask = if sz == 128 {
        u128::MAX
    } else {
        (1u128 << sz) - 1
    };
    let lgsz = sz - 1;
    let mut v = k128(b, 0);
    for i in 0..elems {
        let e = lane(b, x, sz, i);
        let s0 = lane(b, y, sz, i);
        let __h335 = k128(b, lgsz);
        let n = b.and(s0, __h335);
        let l = b.shl(e, n);
        let __h336 = k128(b, sz);
        let inv = b.sub(__h336, n);
        let r = b.shr_l(e, inv);
        let rot = b.or(l, r);
        let __h337 = k128(b, mask);
        let rm = b.and(rot, __h337);
        v = put_lane(b, v, sz, i, rm);
    }
    v
}

/// 要素幅別の交差。`hi` なら各元の前半の要素（IBM 0..elems/2）。
fn lane_merge<B: Backend>(
    b: &mut B,
    x: B::V<W128>,
    y: B::V<W128>,
    sz: u128,
    hi: bool,
) -> B::V<W128> {
    let elems = 128 / sz;
    let half = elems / 2;
    let mut v = k128(b, 0);
    for i in 0..half {
        let src = if hi { i } else { i + half };
        let ex = lane(b, x, sz, src);
        let ey = lane(b, y, sz, src);
        v = put_lane(b, v, sz, 2 * i, ex);
        v = put_lane(b, v, sz, 2 * i + 1, ey);
    }
    v
}

/// 要素幅別の乗算（vmulo*/vmule*）。`sz` は結果の要素幅、奇偶は `odd`、
/// 符号は `signed`。
fn lane_mul<B: Backend>(
    b: &mut B,
    x: B::V<W128>,
    y: B::V<W128>,
    sz: u128,
    odd: bool,
    signed: bool,
) -> B::V<W128> {
    let src_sz = sz / 2;
    let n = 128 / sz;
    let mut v = k128(b, 0);
    for i in 0..n {
        let src = if odd { 2 * i + 1 } else { 2 * i };
        let ae = lane(b, x, src_sz, src);
        let ce = lane(b, y, src_sz, src);
        let a64 = b.trunc::<W128, W64>(ae);
        let c64 = b.trunc::<W128, W64>(ce);
        let (aa, cc) = match (src_sz, signed) {
            (8, true) => {
                let a8 = b.trunc::<W64, W8>(a64);
                let c8 = b.trunc::<W64, W8>(c64);
                (b.sext::<W8, W64>(a8), b.sext::<W8, W64>(c8))
            }
            (8, false) => (a64, c64),
            (16, true) => {
                let a16 = b.trunc::<W64, W16>(a64);
                let c16 = b.trunc::<W64, W16>(c64);
                (b.sext::<W16, W64>(a16), b.sext::<W16, W64>(c16))
            }
            (16, false) => (a64, c64),
            (32, true) => {
                let a32 = b.trunc::<W64, W32>(a64);
                let c32 = b.trunc::<W64, W32>(c64);
                (b.sext::<W32, W64>(a32), b.sext::<W32, W64>(c32))
            }
            _ => (a64, c64),
        };
        let p = b.mul(aa, cc);
        let __h338 = k(b, (1u64 << sz.min(63)) - 1);
        let pm = b.and(p, __h338);
        let p128 = b.zext::<W64, W128>(pm);
        v = put_lane(b, v, sz, i, p128);
    }
    v
}

/// vspltis* の即値複製を定数で返す。
fn splat_simm(kind: u32, simm: i32) -> u128 {
    let s = simm as i64 as u64;
    match kind {
        908 => {
            let w = (s & 0xffff_ffff) as u128;
            w << 96 | w << 64 | w << 32 | w
        }
        844 => {
            let h = (s & 0xffff) as u128;
            let mut v = 0u128;
            for i in 0..8u128 {
                v |= h << (i * 16);
            }
            v
        }
        _ => {
            let by = (s & 0xff) as u128;
            let mut v = 0u128;
            for i in 0..16u128 {
                v |= by << (i * 8);
            }
            v
        }
    }
}

/// 飽和パック（vpk*）。
fn lane_pack<B: Backend>(
    b: &mut B,
    x: B::V<W128>,
    y: B::V<W128>,
    ssz: u128,
    dsz: u128,
    src_unsigned: bool,
    dst_unsigned: bool,
) -> B::V<W128> {
    let n = 128 / ssz;
    let dmask = (1u64 << dsz) - 1;
    let smax_u = dmask;
    let smax_s = ((1i64 << (dsz - 1)) - 1) as u64;
    let smin_s = -((1i64) << (dsz - 1));
    let mut v = k128(b, 0);
    for (si, src) in [x, y].iter().enumerate() {
        for i in 0..n {
            let e = lane(b, *src, ssz, i);
            let e64 = b.trunc::<W128, W64>(e);
            let (se, ue) = if ssz == 16 {
                let e16 = b.trunc::<W64, W16>(e64);
                let __h339 = k(b, 0xffff);
                (b.sext::<W16, W64>(e16), b.and(e64, __h339))
            } else {
                let e32 = b.trunc::<W64, W32>(e64);
                let __h340 = k(b, 0xffff_ffff);
                (b.sext::<W32, W64>(e32), b.and(e64, __h340))
            };
            let __h341 = k(b, smax_u);
            let val = if src_unsigned {
                // u→u: min(ue, smax_u)。
                let big = b.cmp(Cmp::GtU, ue, __h341);
                let __h342 = k(b, smax_u);
                b.select(big, __h342, ue)
            } else if dst_unsigned {
                let __h343 = k(b, 0);
                // s→u: 負→0、>max→max。
                let neg = b.cmp(Cmp::LtS, se, __h343);
                let __h344 = k(b, smax_u);
                let big = b.cmp(Cmp::GtS, se, __h344);
                let m1 = bsel64(b, big, smax_u, 0);
                let __h345 = k(b, dmask);
                let m0 = b.and(ue, __h345);
                let __h437 = bnot_m(b, big);
                let __h346 = b.and(__h437, m0);
                let mid = b.or(m1, __h346);
                let __h347 = k(b, 0);
                b.select(neg, __h347, mid)
            } else {
                let __h348 = k(b, smin_s as u64);
                // s→s: [smin_s, smax_s] に飽和。
                let lo = b.cmp(Cmp::LtS, se, __h348);
                let __h349 = k(b, smax_s);
                let hi = b.cmp(Cmp::GtS, se, __h349);
                let mid = {
                    let __h350 = k(b, dmask);
                    let um = b.and(ue, __h350);
                    let __h351 = k(b, smax_s);
                    b.select(hi, __h351, um)
                };
                let __h352 = k(b, (smin_s as u64) & dmask);
                b.select(lo, __h352, mid)
            };
            let v128 = b.zext::<W64, W128>(val);
            v = put_lane(b, v, dsz, si as u128 * n + i, v128);
        }
    }
    v
}

/// 否定の補助（sel に使うだけの薄いもの）。
fn bnot_m<B: Backend>(b: &mut B, c: B::B) -> B::V<W64> {
    let __h353 = bnot(b, c);
    bsel64(b, __h353, 0xffff_ffff_ffff_ffff, 0)
}

/// op4。VX 形式（XO11 = bits10:0）と VA 形式（XO6 = bits5:0）。
#[allow(clippy::too_many_lines)]
pub fn x4<B: Backend>(b: &mut B, word: u32, _pc: u64, _le: bool) -> Flow<B> {
    let t = ((word >> 21) & 31) as u8;
    let a = ((word >> 16) & 31) as u8;
    let bb = ((word >> 11) & 31) as u8;
    let xo11 = word & 0x7ff;
    // ---- VA 形式（XO6 = bits5:0）----
    match word & 0x3f {
        // vperm: T.byte[i] = C[i]&31<16 ? A[C[i]&31] : B[C[i]&31-16]。
        0x2b => {
            let c = ((word >> 6) & 31) as u8;
            let av = vsr(b, a);
            let bv = vsr(b, bb);
            let cv = vsr(b, c);
            let mut v = k128(b, 0);
            for i in 0..16u128 {
                let idx0 = lane(b, cv, 8, i);
                let __h354 = k128(b, 31);
                let idx = b.and(idx0, __h354);
                let __h355 = k128(b, 16);
                let is_a = b.cmp::<W128>(Cmp::LtU, idx, __h355);
                let src = b.select(is_a, av, bv);
                let __h356 = k128(b, 15);
                let inv = b.sub(__h356, idx);
                let __h357 = k128(b, 31);
                let inv31 = b.sub(__h357, idx);
                let __h358 = k128(b, 8);
                let sh_a = b.mul(inv, __h358);
                let __h359 = k128(b, 8);
                let sh_b = b.mul(inv31, __h359);
                let sh = b.select(is_a, sh_a, sh_b);
                let byte0 = b.shr_l(src, sh);
                let __h360 = k128(b, 0xff);
                let byte = b.and(byte0, __h360);
                v = put_lane(b, v, 8, i, byte);
            }
            set_vsr(b, t, v);
            return Ok(());
        }
        // vsel: T = (A & ~C) | (B & C)。
        0x2a => {
            let c = ((word >> 6) & 31) as u8;
            let x = vsr(b, a);
            let y = vsr(b, bb);
            let cc = vsr(b, c);
            let nc = b.not(cc);
            let lhs = b.and(x, nc);
            let rhs = b.and(y, cc);
            let v = b.or(lhs, rhs);
            set_vsr(b, t, v);
            return Ok(());
        }
        // vsldoi: concat(A,B) を SHB バイト左シフトして上位を取る。
        0x2c => {
            let shb = u128::from((word >> 6) & 0xf);
            let x = vsr(b, a);
            let y = vsr(b, bb);
            let sh = shb * 8;
            let v = if sh == 0 {
                x
            } else {
                let __h361 = k128(b, sh);
                let lo = b.shl(x, __h361);
                let __h362 = k128(b, 128 - sh);
                let hi = b.shr_l(y, __h362);
                b.or(lo, hi)
            };
            set_vsr(b, t, v);
            return Ok(());
        }
        _ => {}
    }
    match xo11 {
        // ---- 加減算（要素幅別、折り返し） ----
        0 | 64 | 128 | 192 | 256 => {
            let sz = match xo11 {
                0 => 8,
                64 => 16,
                128 => 32,
                192 => 64,
                _ => 128,
            };
            let __h364 = vsr(b, bb);
            let __h363 = vsr(b, a);
            let v = lane_addsub(b, __h363, __h364, sz, false);
            set_vsr(b, t, v);
            Ok(())
        }
        1024 | 1088 | 1152 | 1216 | 1280 => {
            let sz = match xo11 {
                1024 => 8,
                1088 => 16,
                1152 => 32,
                1216 => 64,
                _ => 128,
            };
            let __h366 = vsr(b, bb);
            let __h365 = vsr(b, a);
            let v = lane_addsub(b, __h365, __h366, sz, true);
            set_vsr(b, t, v);
            Ok(())
        }
        // ---- 飽和加減算 ----
        512 | 576 | 640 | 768 | 832 | 896 | 1536 | 1600 | 1664 | 1792 | 1856 | 1920 => {
            let (sz, sub, signed) = match xo11 {
                512 => (8, false, false),
                576 => (16, false, false),
                640 => (32, false, false),
                768 => (8, false, true),
                832 => (16, false, true),
                896 => (32, false, true),
                1536 => (8, true, false),
                1600 => (16, true, false),
                1664 => (32, true, false),
                1792 => (8, true, true),
                1856 => (16, true, true),
                _ => (32, true, true),
            };
            let __h368 = vsr(b, bb);
            let __h367 = vsr(b, a);
            let v = lane_sat_addsub(b, __h367, __h368, sz, sub, signed);
            set_vsr(b, t, v);
            Ok(())
        }
        // ---- 論理 ----
        1028 => {
            let __h370 = vsr(b, bb);
            let __h369 = vsr(b, a);
            let v = b.and(__h369, __h370);
            set_vsr(b, t, v);
            Ok(())
        }
        1092 => {
            let __h371 = vsr(b, bb);
            let ny = b.not(__h371);
            let __h372 = vsr(b, a);
            let v = b.and(__h372, ny);
            set_vsr(b, t, v);
            Ok(())
        }
        1156 => {
            let __h374 = vsr(b, bb);
            let __h373 = vsr(b, a);
            let v = b.or(__h373, __h374);
            set_vsr(b, t, v);
            Ok(())
        }
        1220 => {
            let __h376 = vsr(b, bb);
            let __h375 = vsr(b, a);
            let v = b.xor(__h375, __h376);
            set_vsr(b, t, v);
            Ok(())
        }
        1284 => {
            let __h378 = vsr(b, bb);
            let __h377 = vsr(b, a);
            let z = b.or(__h377, __h378);
            let v = b.not(z);
            set_vsr(b, t, v);
            Ok(())
        }
        // ---- 要素シフト（vslb/vslh/vslw/vsrb/vsrh/vsrw/vsrab/vsrah/vsraw） ----
        260 | 324 | 388 | 516 | 580 | 644 | 772 | 836 | 900 => {
            let (sz, left, arith) = match xo11 {
                260 => (8, true, false),
                324 => (16, true, false),
                388 => (32, true, false),
                516 => (8, false, false),
                580 => (16, false, false),
                644 => (32, false, false),
                772 => (8, false, true),
                836 => (16, false, true),
                _ => (32, false, true),
            };
            let __h380 = vsr(b, bb);
            let __h379 = vsr(b, a);
            let v = lane_shift(b, __h379, __h380, sz, left, arith);
            set_vsr(b, t, v);
            Ok(())
        }
        // ---- 要素回転（vrlb/vrlh/vrlw） ----
        4 | 68 | 132 => {
            let sz = if xo11 == 4 {
                8
            } else if xo11 == 68 {
                16
            } else {
                32
            };
            let __h382 = vsr(b, bb);
            let __h381 = vsr(b, a);
            let v = lane_rotl(b, __h381, __h382, sz);
            set_vsr(b, t, v);
            Ok(())
        }
        // ---- 全体シフト（vsl=452, vsr=708。量は VRB 最後のバイトの下位 3 ビット） ----
        452 | 708 => {
            let y = vsr(b, bb);
            let __h383 = k128(b, 7);
            let s0 = b.and(y, __h383);
            let __h384 = vsr(b, a);
            let v = if xo11 == 452 {
                b.shl(__h384, s0)
            } else {
                let __h385 = vsr(b, a);
                b.shr_l(__h385, s0)
            };
            set_vsr(b, t, v);
            Ok(())
        }
        // ---- オクテットシフト（vslo=1036, vsro=1100） ----
        1036 | 1100 => {
            let y = vsr(b, bb);
            let __h386 = k128(b, 127);
            let s0 = b.and(y, __h386);
            let __h387 = k128(b, 0x78);
            let s = b.and(s0, __h387);
            let __h388 = k128(b, 3);
            let bits = b.shl(s, __h388);
            let __h389 = vsr(b, a);
            let v = if xo11 == 1036 {
                b.shl(__h389, bits)
            } else {
                let __h390 = vsr(b, a);
                b.shr_l(__h390, bits)
            };
            set_vsr(b, t, v);
            Ok(())
        }
        // ---- 即値複製（vspltisb=780, vspltish=844, vspltisw=908） ----
        780 | 844 | 908 => {
            let simm = ((word >> 16) & 31) as i32;
            let simm = (simm << 27) >> 27; // 5 ビット符号拡張
            let v = k128(b, splat_simm(xo11, simm));
            set_vsr(b, t, v);
            Ok(())
        }
        // ---- レジスタ複製（vspltb=524, vsplth=588, vspltw=652） ----
        524 | 588 | 652 => {
            let sz = if xo11 == 524 {
                8
            } else if xo11 == 588 {
                16
            } else {
                32
            };
            let uim = u128::from((word >> 16) & 31) & (128 / sz - 1);
            let src = vsr(b, bb);
            let e = lane(b, src, sz, uim);
            let mut v = k128(b, 0);
            for i in 0..128 / sz {
                v = put_lane(b, v, sz, i, e);
            }
            set_vsr(b, t, v);
            Ok(())
        }
        // ---- 符号拡張アンパック（vupkh*/vupkl*/vupkhsw/vupklsw） ----
        526 | 654 | 590 | 718 | 1614 | 1742 => {
            let (sz, hi) = match xo11 {
                526 => (8u128, true),
                654 => (8, false),
                590 => (16, true),
                718 => (16, false),
                1614 => (32, true),
                _ => (32, false),
            };
            let src_elems = 128 / sz;
            let half = src_elems / 2;
            let base = if hi { 0u128 } else { half };
            let mut v = k128(b, 0);
            for i in 0..half {
                let src = vsr(b, bb);
                let e = lane(b, src, sz, base + i);
                let e64 = b.trunc::<W128, W64>(e);
                let se = if sz == 8 {
                    let w = b.trunc::<W64, W8>(e64);
                    b.sext::<W8, W64>(w)
                } else if sz == 16 {
                    let w = b.trunc::<W64, W16>(e64);
                    b.sext::<W16, W64>(w)
                } else {
                    let w = b.trunc::<W64, W32>(e64);
                    b.sext::<W32, W64>(w)
                };
                let se128 = b.zext::<W64, W128>(se);
                v = put_lane(b, v, sz * 2, i, se128);
            }
            set_vsr(b, t, v);
            Ok(())
        }
        // ---- ゼロ拡張アンパックは vpk* 系に含まず（vexts* は a フィールド別） ----
        // ---- 交差（vmrgh*/vmrgl*） ----
        12 | 76 | 140 | 268 | 332 | 396 => {
            let (sz, hi) = match xo11 {
                12 => (8u128, true),
                76 => (16, true),
                140 => (32, true),
                268 => (8, false),
                332 => (16, false),
                _ => (32, false),
            };
            let __h392 = vsr(b, bb);
            let __h391 = vsr(b, a);
            let v = lane_merge(b, __h391, __h392, sz, hi);
            set_vsr(b, t, v);
            Ok(())
        }
        // ---- 語交差（vmrgew=1932, vmrgow=1676） ----
        1932 | 1676 => {
            let x = vsr(b, a);
            let y = vsr(b, bb);
            let base = if xo11 == 1932 { 0u128 } else { 1 };
            let mut v = k128(b, 0);
            for i in 0..2u128 {
                let src = base + 2 * i;
                let ex = lane(b, x, 32, src);
                let ey = lane(b, y, 32, src);
                v = put_lane(b, v, 32, 2 * i, ex);
                v = put_lane(b, v, 32, 2 * i + 1, ey);
            }
            set_vsr(b, t, v);
            Ok(())
        }
        // ---- 乗算（奇・偶要素）----
        // vmuloub=8,vmulouh=72,vmulosb=264,vmulosh=328,
        // vmuleub=520,vmuleuh=584,vmulesb=776,vmulesh=840。
        8 | 72 | 264 | 328 | 520 | 584 | 776 | 840 => {
            let (sz, odd, signed) = match xo11 {
                8 => (16u128, true, false),
                72 => (32, true, false),
                264 => (16, true, true),
                328 => (32, true, true),
                520 => (16, false, false),
                584 => (32, false, false),
                776 => (16, false, true),
                _ => (32, false, true),
            };
            let __h394 = vsr(b, bb);
            let __h393 = vsr(b, a);
            let v = lane_mul(b, __h393, __h394, sz, odd, signed);
            set_vsr(b, t, v);
            Ok(())
        }
        // ---- 乗算（vmuluwm=137, vmuluhs=73 等の同幅積） ----
        137 => {
            let x = vsr(b, a);
            let y = vsr(b, bb);
            let mut v = k128(b, 0);
            for i in 0..4u128 {
                let ex = lane(b, x, 32, i);
                let ey = lane(b, y, 32, i);
                let x64 = b.trunc::<W128, W64>(ex);
                let y64 = b.trunc::<W128, W64>(ey);
                let x32 = b.trunc::<W64, W32>(x64);
                let y32 = b.trunc::<W64, W32>(y64);
                let p = b.mul::<W32>(x32, y32);
                let p128 = b.zext::<W32, W128>(p);
                v = put_lane(b, v, 32, i, p128);
            }
            set_vsr(b, t, v);
            Ok(())
        }
        // ---- 比較（eq=6,70,134,199 / ugt=518,582,646,711 / sgt=774,838,902,967。
        // fp=198,710。Rc 形は bit10=0x400 立ち） ----
        6 | 70 | 134 | 199 | 518 | 582 | 646 | 711 | 774 | 838 | 902 | 967 | 198 | 710 | 0x406
        | 0x446 | 0x486 | 0x4c7 | 0x606 | 0x646 | 0x686 | 0x6c7 | 0x706 | 0x746 | 0x786 | 0x7c7
        | 0x4c6 | 0x6c6 => {
            let base = xo11 & 0x3ff;
            let (sz, mode) = match base {
                6 => (8u128, 0u8),
                70 => (16, 0),
                134 => (32, 0),
                199 => (64, 0),
                198 => (32, 3),
                518 => (8, 2),
                582 => (16, 2),
                646 => (32, 2),
                711 => (64, 2),
                710 => (32, 4),
                774 => (8, 1),
                838 => (16, 1),
                902 => (32, 1),
                _ => (64, 1),
            };
            let __h396 = vsr(b, bb);
            let __h395 = vsr(b, a);
            let (v, all_t, all_f) = if mode < 3 {
                lane_cmp(b, __h395, __h396, sz, mode)
            } else {
                // FP 比較。32 ビット要素の f32 比較。
                let x = vsr(b, a);
                let y = vsr(b, bb);
                let mut vv = k128(b, 0);
                let mut at = k(b, 1u64);
                let mut af = k(b, 1u64);
                let __h400 = k(b, 0);
                let __h399 = k(b, 0);
                for i in 0..4u128 {
                    let sh = k128(b, 96 - i * 32);
                    let xw0 = b.shr_l(x, sh);
                    let xw = b.trunc::<W128, W32>(xw0);
                    let yw0 = b.shr_l(y, sh);
                    let yw = b.trunc::<W128, W32>(yw0);
                    let hit = if mode == 3 {
                        b.feq::<W32>(xw, yw)
                    } else {
                        b.flt::<W32>(yw, xw)
                    };
                    let __h398 = k128(b, 0);
                    let __h397 = k128(b, 0xffff_ffff);
                    let hv = b.select(hit, __h397, __h398);
                    vv = put_lane(b, vv, 32, i, hv);
                    let hf = bsel64(b, hit, 1, 0);
                    at = b.and(at, hf);
                    let nh = bnot(b, hit);
                    let nhf = bsel64(b, nh, 1, 0);
                    af = b.and(af, nhf);
                }
                (vv, b.cmp(Cmp::Ne, at, __h399), b.cmp(Cmp::Ne, af, __h400))
            };
            set_vsr(b, t, v);
            if xo11 & 0x400 != 0 {
                let lt = bsel64(b, all_t, CR_LT, 0);
                let eq = bsel64(b, all_f, CR_EQ, 0);
                let f = b.or(lt, eq);
                set_crf(b, 6, f);
            }
            Ok(())
        }
        // ---- 飽和パック（vpkuwum=78 は mod、vpkuwus=206/vpkswus=334/vpkswss=462
        // は w→hw。vpkuhus=142/vpkshus=270/vpkshss=398 は hw→b） ----
        142 | 270 | 398 | 206 | 334 | 462 | 78 => {
            let (ssz, dsz, src_unsigned, dst_unsigned, modulo) = match xo11 {
                142 => (16u128, 8u128, true, true, false),
                270 => (16, 8, false, true, false),
                398 => (16, 8, false, false, false),
                78 => (32, 16, true, true, true),
                206 => (32, 16, true, true, false),
                334 => (32, 16, false, true, false),
                _ => (32, 16, false, false, false),
            };
            if modulo {
                // vpkuwum: マスクで切るだけ。
                let mut v = k128(b, 0);
                for (si, src) in [vsr(b, a), vsr(b, bb)].iter().enumerate() {
                    for i in 0..4u128 {
                        let e = lane(b, *src, 32, i);
                        let e64 = b.trunc::<W128, W64>(e);
                        let __h401 = k(b, 0xffff);
                        let um = b.and(e64, __h401);
                        let e128 = b.zext::<W64, W128>(um);
                        v = put_lane(b, v, 16, si as u128 * 4 + i, e128);
                    }
                }
                set_vsr(b, t, v);
            } else {
                let __h403 = vsr(b, bb);
                let __h402 = vsr(b, a);
                let v = lane_pack(b, __h402, __h403, ssz, dsz, src_unsigned, dst_unsigned);
                set_vsr(b, t, v);
            }
            Ok(())
        }
        // ---- 平均（vavg*） ----
        1026 | 1090 | 1154 | 1282 | 1346 | 1410 => {
            let (sz, signed) = match xo11 {
                1026 => (8u128, false),
                1090 => (16, false),
                1154 => (32, false),
                1282 => (8, true),
                1346 => (16, true),
                _ => (32, true),
            };
            let x = vsr(b, a);
            let y = vsr(b, bb);
            let mut v = k128(b, 0);
            for i in 0..128 / sz {
                let ex = lane(b, x, sz, i);
                let ey = lane(b, y, sz, i);
                let x64 = b.trunc::<W128, W64>(ex);
                let y64 = b.trunc::<W128, W64>(ey);
                let (xs, ys) = if signed {
                    if sz == 8 {
                        let xs8 = b.trunc::<W64, W8>(x64);
                        let ys8 = b.trunc::<W64, W8>(y64);
                        (b.sext::<W8, W64>(xs8), b.sext::<W8, W64>(ys8))
                    } else if sz == 16 {
                        let xs16 = b.trunc::<W64, W16>(x64);
                        let ys16 = b.trunc::<W64, W16>(y64);
                        (b.sext::<W16, W64>(xs16), b.sext::<W16, W64>(ys16))
                    } else {
                        let xs32 = b.trunc::<W64, W32>(x64);
                        let ys32 = b.trunc::<W64, W32>(y64);
                        (b.sext::<W32, W64>(xs32), b.sext::<W32, W64>(ys32))
                    }
                } else {
                    (x64, y64)
                };
                let sum = b.add(xs, ys);
                let one = k(b, 1);
                let sum1 = b.add(sum, one);
                let avg = b.shr_l(sum1, one);
                let mask = (1u64 << sz) - 1;
                let __h404 = k(b, mask);
                let am = b.and(avg, __h404);
                let am128 = b.zext::<W64, W128>(am);
                v = put_lane(b, v, sz, i, am128);
            }
            set_vsr(b, t, v);
            Ok(())
        }
        // ---- 最小・最大 ----
        2 | 66 | 130 | 258 | 322 | 386 | 514 | 578 | 642 | 770 | 834 | 898 => {
            let (sz, signed, max) = match xo11 {
                2 => (8u128, false, true),
                66 => (16, false, true),
                130 => (32, false, true),
                258 => (8, true, true),
                322 => (16, true, true),
                386 => (32, true, true),
                514 => (8, false, false),
                578 => (16, false, false),
                642 => (32, false, false),
                770 => (8, true, false),
                834 => (16, true, false),
                _ => (32, true, false),
            };
            let x = vsr(b, a);
            let y = vsr(b, bb);
            let mut v = k128(b, 0);
            for i in 0..128 / sz {
                let ex = lane(b, x, sz, i);
                let ey = lane(b, y, sz, i);
                let x64 = b.trunc::<W128, W64>(ex);
                let y64 = b.trunc::<W128, W64>(ey);
                let (xs, ys) = if signed {
                    if sz == 8 {
                        let xs8 = b.trunc::<W64, W8>(x64);
                        let ys8 = b.trunc::<W64, W8>(y64);
                        (b.sext::<W8, W64>(xs8), b.sext::<W8, W64>(ys8))
                    } else if sz == 16 {
                        let xs16 = b.trunc::<W64, W16>(x64);
                        let ys16 = b.trunc::<W64, W16>(y64);
                        (b.sext::<W16, W64>(xs16), b.sext::<W16, W64>(ys16))
                    } else {
                        let xs32 = b.trunc::<W64, W32>(x64);
                        let ys32 = b.trunc::<W64, W32>(y64);
                        (b.sext::<W32, W64>(xs32), b.sext::<W32, W64>(ys32))
                    }
                } else {
                    (x64, y64)
                };
                let gt = if signed {
                    b.cmp(Cmp::GtS, xs, ys)
                } else {
                    b.cmp(Cmp::GtU, x64, y64)
                };
                let pick = if max {
                    b.select(gt, ex, ey)
                } else {
                    b.select(gt, ey, ex)
                };
                v = put_lane(b, v, sz, i, pick);
            }
            set_vsr(b, t, v);
            Ok(())
        }
        // ---- 単項・拡張（a フィールドで要素種別を分ける） ----
        // vextsb2w(a=16)/vextsh2w(a=17)/vextsw2d(a=26)/vctzd(a=31)/
        // vnegw(a=6)/vprtybw(a=8)。
        1538 => {
            let src = vsr(b, bb);
            let mut v = k128(b, 0);
            match a {
                16 | 17 => {
                    // vextsb2w/vextsh2w: 各要素を w へ符号拡張。
                    let (ssz, n) = if a == 16 { (8u128, 4u128) } else { (16, 4) };
                    let base = 128 / ssz - n;
                    for i in 0..n {
                        let e = lane(b, src, ssz, base + i);
                        let e64 = b.trunc::<W128, W64>(e);
                        let se = if ssz == 8 {
                            let w = b.trunc::<W64, W8>(e64);
                            b.sext::<W8, W64>(w)
                        } else {
                            let w = b.trunc::<W64, W16>(e64);
                            b.sext::<W16, W64>(w)
                        };
                        let se128 = b.zext::<W64, W128>(se);
                        v = put_lane(b, v, 32, i, se128);
                    }
                }
                26 => {
                    // vextsw2d。
                    let e = lane(b, src, 32, 3);
                    let e64 = b.trunc::<W128, W64>(e);
                    let e32 = b.trunc::<W64, W32>(e64);
                    let se = b.sext::<W32, W64>(e32);
                    let se128 = b.zext::<W64, W128>(se);
                    v = put_lane(b, v, 64, 1, se128);
                    let e = lane(b, src, 32, 2);
                    let e64 = b.trunc::<W128, W64>(e);
                    let e32 = b.trunc::<W64, W32>(e64);
                    let se = b.sext::<W32, W64>(e32);
                    let se128 = b.zext::<W64, W128>(se);
                    v = put_lane(b, v, 64, 0, se128);
                }
                31 => {
                    // vctzd: 各 dw の後続ゼロ数。
                    let lo = vsr_lo(b, bb);
                    let hi = vsr_hi(b, bb);
                    let c0 = ctz64(b, hi);
                    let c1 = ctz64(b, lo);
                    let c0w = b.zext::<W64, W128>(c0);
                    let c1w = b.zext::<W64, W128>(c1);
                    v = put_lane(b, v, 64, 0, c0w);
                    v = put_lane(b, v, 64, 1, c1w);
                }
                6 => {
                    // vnegw。
                    for i in 0..4u128 {
                        let e = lane(b, src, 32, i);
                        let e64 = b.trunc::<W128, W64>(e);
                        let __h405 = k(b, 0);
                        let n = b.sub(__h405, e64);
                        let __h406 = k(b, 0xffff_ffff);
                        let nm = b.and(n, __h406);
                        let n128 = b.zext::<W64, W128>(nm);
                        v = put_lane(b, v, 32, i, n128);
                    }
                }
                _ => {
                    // その他の単項は近似として素通し。
                    v = src;
                }
            }
            set_vsr(b, t, v);
            Ok(())
        }
        // ---- カウント系（vclzb=1794,vclzh=1858,vclzw=1922,vpopcntw=1923,
        // vpopcntb=1795,vpopcnth=1859,vpopcntd=1987） ----
        1794 | 1858 | 1922 | 1795 | 1859 | 1923 | 1987 => {
            let (sz, pop) = match xo11 {
                1794 => (8u128, false),
                1858 => (16, false),
                1922 => (32, false),
                1795 => (8, true),
                1859 => (16, true),
                1923 => (32, true),
                _ => (64, true),
            };
            let src = vsr(b, bb);
            let mut v = k128(b, 0);
            for i in 0..128 / sz {
                let e = lane(b, src, sz, i);
                let e64 = b.trunc::<W128, W64>(e);
                let r = if pop {
                    popcnt8(b, e64)
                } else {
                    let __h407 = k(b, 64 - sz as u64);
                    // 先頭ゼロ（幅内）。
                    let w = b.shl(e64, __h407);
                    let c = clz64(b, w);
                    let __h408 = k(b, 64);
                    let is64 = b.cmp(Cmp::Eq, c, __h408);
                    let __h409 = k(b, sz as u64);
                    b.select(is64, __h409, c)
                };
                let __h410 = k(b, (1u64 << sz.min(63)) - 1);
                let rm = b.and(r, __h410);
                let r128 = b.zext::<W64, W128>(rm);
                v = put_lane(b, v, sz, i, r128);
            }
            set_vsr(b, t, v);
            Ok(())
        }
        // ---- 要素の出し入れ（vextract*=525/653/781? / vinsert*=781/909/…）
        // vextractub=525,vextractuh=589,vextractuw=653,vextractd=717。
        525 | 589 | 653 | 717 => {
            let sz = match xo11 {
                525 => 8u128,
                589 => 16,
                653 => 32,
                _ => 64,
            };
            let uim = u128::from((word >> 16) & 31) & (128 / sz - 1);
            let src = vsr(b, bb);
            let e = lane(b, src, sz, uim);
            set_vsr(b, t, e);
            Ok(())
        }
        // vinsertb=781,vinserth=845,vinsertw=909,vinsertd=973。
        781 | 845 | 909 | 973 => {
            let sz = match xo11 {
                781 => 8u128,
                845 => 16,
                909 => 32,
                _ => 64,
            };
            let uim = u128::from((word >> 16) & 31) & (128 / sz - 1);
            let src = vsr(b, a);
            let dst = vsr(b, t);
            let e = lane(b, src, sz, 0);
            let mask = if sz == 128 {
                u128::MAX
            } else {
                (1u128 << sz) - 1
            };
            let elems = 128 / sz;
            let off = (elems - 1 - uim) * sz;
            let __h411 = k128(b, !(mask << off));
            let clr = b.and(dst, __h411);
            let __h413 = k128(b, off);
            let __h438 = k128(b, mask);
            let __h412 = b.and(e, __h438);
            let put = b.shl(__h412, __h413);
            let v = b.or(clr, put);
            set_vsr(b, t, v);
            Ok(())
        }
        // ---- FP ベクタ（vrfin=522,vrfiz=650,vrfip=714,vrfim=778,
        // vrefp=266,vrsqrtefp=330,vmaxfp?） ----
        522 | 650 | 714 | 778 | 266 | 330 => {
            let src = vsr(b, bb);
            let mut v = k128(b, 0);
            for i in 0..4u128 {
                let sh = k128(b, 96 - i * 32);
                let xw0 = b.shr_l(src, sh);
                let xw = b.trunc::<W128, W32>(xw0);
                let r = match xo11 {
                    266 => {
                        let __h414 = k32(b, 0x3f80_0000);
                        b.fdiv::<W32>(__h414, xw)
                    }
                    330 => {
                        let sq = b.fsqrt::<W32>(xw);
                        let __h415 = k32(b, 0x3f80_0000);
                        b.fdiv::<W32>(__h415, sq)
                    }
                    _ => {
                        // 丸めは s32 往復で近似。
                        let i64v = b.fcvt_s32::<W32>(xw, 0);
                        b.fcvt_from_s32::<W32>(i64v, 0)
                    }
                };
                let rz = b.zext::<W32, W128>(r);
                let put = b.shl(rz, sh);
                v = b.or(v, put);
            }
            set_vsr(b, t, v);
            Ok(())
        }
        _ => unimp(b, u64::from(xo11)),
    }
}

/// 後続ゼロの数（0→64）。
fn ctz64<B: Backend>(b: &mut B, v: B::V<W64>) -> B::V<W64> {
    // v & -v の位置。全ゼロは 64。
    let nv = b.not(v);
    let __h416 = k(b, 1);
    let neg = b.add(nv, __h416);
    let iso = b.and(v, neg);
    let __h417 = k(b, 0);
    // iso = 最下位の 1 ビット。1<<n の log2 を取る。
    let is0 = b.cmp(Cmp::Eq, iso, __h417);
    let mut n = k(b, 0);
    let mut p = iso;
    let __h420 = k(b, 64);
    for bits in [32u64, 16, 8, 4, 2, 1] {
        let __h418 = k(b, bits);
        let hi = b.shr_l(p, __h418);
        let __h419 = k(b, 0);
        let nz = b.cmp(Cmp::Ne, hi, __h419);
        let add = bsel64(b, nz, bits, 0);
        n = b.add(n, add);
        p = b.select(nz, hi, p);
    }
    b.select(is0, __h420, n)
}

// ---------------- Insn → 各形式の入口 ----------------

/// D 形式の符号つき 16 ビット即値。
fn simm16(word: u32) -> i64 {
    i64::from((word as i32) << 16 >> 16)
}

/// D 形式の (rt, ra, d)。
fn d_fields(word: u32) -> (u8, u8, i64) {
    let t = ((word >> 21) & 31) as u8;
    let r = ((word >> 16) & 31) as u8;
    (t, r, simm16(word))
}

/// M 形式の (ra_d, rs, rb/sh, mb, me, rc)。
fn m_fields(word: u32) -> (u8, u8, u8, u8, u8, bool) {
    let ra_d = ((word >> 16) & 31) as u8;
    let rs = ((word >> 21) & 31) as u8;
    let rb = ((word >> 11) & 31) as u8;
    let mb = ((word >> 6) & 31) as u8;
    let me = ((word >> 1) & 31) as u8;
    (ra_d, rs, rb, mb, me, word & 1 != 0)
}

/// op2: tdi（64 ビット罠）。
pub fn tdi<B: Backend>(b: &mut B, word: u32, _pc: u64, _le: bool) -> Flow<B> {
    let to = ((word >> 21) & 31) as u8;
    let r = ((word >> 16) & 31) as u8;
    trap_imm(b, to, true, r, simm16(word))
}

/// op3: twi（32 ビット罠）。
pub fn twi<B: Backend>(b: &mut B, word: u32, _pc: u64, _le: bool) -> Flow<B> {
    let to = ((word >> 21) & 31) as u8;
    let r = ((word >> 16) & 31) as u8;
    trap_imm(b, to, false, r, simm16(word))
}

/// op7: mulli。
pub fn mulli<B: Backend>(b: &mut B, word: u32, _pc: u64, _le: bool) -> Flow<B> {
    let (t, r, d) = d_fields(word);
    mulli_i(b, t, r, d)
}

/// op8: subfic。
pub fn subfic<B: Backend>(b: &mut B, word: u32, _pc: u64, _le: bool) -> Flow<B> {
    let (t, r, d) = d_fields(word);
    subfic_i(b, t, r, d)
}

/// op10: cmpli。L は bit21。
pub fn cmpli<B: Backend>(b: &mut B, word: u32, _pc: u64, _le: bool) -> Flow<B> {
    let bf = ((word >> 23) & 7) as u8;
    let l = word & 0x20_0000 != 0;
    let r = ((word >> 16) & 31) as u8;
    cmpl_imm(b, bf, l, r, (word & 0xffff) as u64)
}

/// op11: cmpwi。
pub fn cmpwi<B: Backend>(b: &mut B, word: u32, _pc: u64, _le: bool) -> Flow<B> {
    let bf = ((word >> 23) & 7) as u8;
    let l = word & 0x20_0000 != 0;
    let r = ((word >> 16) & 31) as u8;
    cmp_imm(b, bf, l, r, simm16(word))
}

/// op12/13: addic/addic.。
pub fn addic<B: Backend>(b: &mut B, word: u32, _pc: u64, _le: bool) -> Flow<B> {
    let (t, r, d) = d_fields(word);
    addic_i(b, t, r, d, false)
}

/// addic.（CR0 を記録）。
pub fn addic_rc<B: Backend>(b: &mut B, word: u32, _pc: u64, _le: bool) -> Flow<B> {
    let (t, r, d) = d_fields(word);
    addic_i(b, t, r, d, true)
}

/// op14: addi。rA=0 は値 0。
pub fn addi<B: Backend>(b: &mut B, word: u32, _pc: u64, _le: bool) -> Flow<B> {
    let (t, r, d) = d_fields(word);
    addi_i(b, t, r, d, false)
}

/// op15: addis（即値を 16 左シフト）。
pub fn addis<B: Backend>(b: &mut B, word: u32, _pc: u64, _le: bool) -> Flow<B> {
    let (t, r, d) = d_fields(word);
    addi_i(b, t, r, d, true)
}

/// op16: bc/bcl（B 形式）。bd は 14 ビット符号つき <<2。
pub fn bc<B: Backend>(b: &mut B, word: u32, pc: u64, _le: bool) -> Flow<B> {
    let bo = ((word >> 21) & 31) as u8;
    let bi = ((word >> 16) & 31) as u8;
    // BD は bits[15:2] の 14 ビット符号つき。バイトオフセットへの <<2 は
    // branch_cond_i が行う。
    let bd = i64::from(((word >> 2) as i32) << 18 >> 18);
    branch_cond_i(b, pc, bo, bi, bd, word & 2 != 0, word & 1 != 0)
}

/// op18: b/bl（I 形式）。li は 24 ビット符号つき <<2。
pub fn b_<B: Backend>(b: &mut B, word: u32, pc: u64, _le: bool) -> Flow<B> {
    // LI は bits[25:2] の 24 ビット符号つき。バイトオフセットへの <<2 は
    // branch_i が行う。
    let li = i64::from(((word >> 2) as i32) << 8 >> 8);
    branch_i(b, pc, li, word & 2 != 0, word & 1 != 0)
}

/// op19: XL 形式（bclr/bcctr/CR 論理/isync）。
pub fn x19<B: Backend>(b: &mut B, word: u32, pc: u64, _le: bool) -> Flow<B> {
    xl19(b, pc, word)
}

/// op20: rlwimi。
pub fn rlwimi<B: Backend>(b: &mut B, word: u32, _pc: u64, _le: bool) -> Flow<B> {
    let (ra_d, rs, sh, mb, me, rc) = m_fields(word);
    rlwimi_i(b, ra_d, rs, sh, mb, me, rc)
}

/// op21: rlwinm。
pub fn rlwinm<B: Backend>(b: &mut B, word: u32, _pc: u64, _le: bool) -> Flow<B> {
    let (ra_d, rs, sh, mb, me, rc) = m_fields(word);
    rlwinm_i(b, ra_d, rs, sh, mb, me, rc)
}

/// op23: rlwnm。
pub fn rlwnm<B: Backend>(b: &mut B, word: u32, _pc: u64, _le: bool) -> Flow<B> {
    let (ra_d, rs, rb, mb, me, rc) = m_fields(word);
    rlwnm_i(b, ra_d, rs, rb, mb, me, rc)
}

/// op24/25: ori/oris。op は log_imm の 1=or。
pub fn ori<B: Backend>(b: &mut B, word: u32, _pc: u64, _le: bool) -> Flow<B> {
    let (s_, r, _) = d_fields(word);
    log_imm(b, r, s_, u64::from(word & 0xffff), 1)
}

/// oris（即値 <<16）。
pub fn oris<B: Backend>(b: &mut B, word: u32, _pc: u64, _le: bool) -> Flow<B> {
    let (s_, r, _) = d_fields(word);
    log_imm(b, r, s_, u64::from(word & 0xffff) << 16, 1)
}

/// op26/27: xori/xoris。
pub fn xori<B: Backend>(b: &mut B, word: u32, _pc: u64, _le: bool) -> Flow<B> {
    let (s_, r, _) = d_fields(word);
    log_imm(b, r, s_, u64::from(word & 0xffff), 2)
}

/// xoris（即値 <<16）。
pub fn xoris<B: Backend>(b: &mut B, word: u32, _pc: u64, _le: bool) -> Flow<B> {
    let (s_, r, _) = d_fields(word);
    log_imm(b, r, s_, u64::from(word & 0xffff) << 16, 2)
}

/// op28/29: andi./andis.（CR0 を記録）。
pub fn andi_rc<B: Backend>(b: &mut B, word: u32, _pc: u64, _le: bool) -> Flow<B> {
    let (s_, r, _) = d_fields(word);
    andi_rc_i(b, r, s_, u64::from(word & 0xffff))
}

/// andis.（即値 <<16、CR0 を記録）。
pub fn andis_rc<B: Backend>(b: &mut B, word: u32, _pc: u64, _le: bool) -> Flow<B> {
    let (s_, r, _) = d_fields(word);
    andi_rc_i(b, r, s_, u64::from(word & 0xffff) << 16)
}

/// op30: rldicl/rldicr/rldic/rldimi/rldcl/rldcr（MD/MDS）。
pub fn x30<B: Backend>(b: &mut B, word: u32, _pc: u64, _le: bool) -> Flow<B> {
    let ra_d = ((word >> 16) & 31) as u8;
    let rs = ((word >> 21) & 31) as u8;
    let rc = word & 1 != 0;
    rld(b, ra_d, rs, word, rc)
}

/// op32/33: lwz/lwzu（4 バイトゼロ拡張）。
pub fn lwz<B: Backend>(b: &mut B, word: u32, _pc: u64, le: bool) -> Flow<B> {
    let (t, r, d) = d_fields(word);
    ld_d(b, t, r, d, 4, false, false, le)
}

/// lwzu（更新あり）。
pub fn lwzu<B: Backend>(b: &mut B, word: u32, _pc: u64, le: bool) -> Flow<B> {
    let (t, r, d) = d_fields(word);
    ld_d(b, t, r, d, 4, false, true, le)
}

/// op34/35: lbz/lbzu。
pub fn lbz<B: Backend>(b: &mut B, word: u32, _pc: u64, le: bool) -> Flow<B> {
    let (t, r, d) = d_fields(word);
    ld_d(b, t, r, d, 1, false, false, le)
}

/// lbzu。
pub fn lbzu<B: Backend>(b: &mut B, word: u32, _pc: u64, le: bool) -> Flow<B> {
    let (t, r, d) = d_fields(word);
    ld_d(b, t, r, d, 1, false, true, le)
}

/// op36/37: stw/stwu。
pub fn stw<B: Backend>(b: &mut B, word: u32, _pc: u64, le: bool) -> Flow<B> {
    let (t, r, d) = d_fields(word);
    st_d(b, t, r, d, 4, false, le)
}

/// stwu。
pub fn stwu<B: Backend>(b: &mut B, word: u32, _pc: u64, le: bool) -> Flow<B> {
    let (t, r, d) = d_fields(word);
    st_d(b, t, r, d, 4, true, le)
}

/// op38/39: stb/stbu。
pub fn stb<B: Backend>(b: &mut B, word: u32, _pc: u64, le: bool) -> Flow<B> {
    let (t, r, d) = d_fields(word);
    st_d(b, t, r, d, 1, false, le)
}

/// stbu。
pub fn stbu<B: Backend>(b: &mut B, word: u32, _pc: u64, le: bool) -> Flow<B> {
    let (t, r, d) = d_fields(word);
    st_d(b, t, r, d, 1, true, le)
}

/// op40/41: lhz/lhzu。
pub fn lhz<B: Backend>(b: &mut B, word: u32, _pc: u64, le: bool) -> Flow<B> {
    let (t, r, d) = d_fields(word);
    ld_d(b, t, r, d, 2, false, false, le)
}

/// lhzu。
pub fn lhzu<B: Backend>(b: &mut B, word: u32, _pc: u64, le: bool) -> Flow<B> {
    let (t, r, d) = d_fields(word);
    ld_d(b, t, r, d, 2, false, true, le)
}

/// op42/43: lha/lhau（2 バイト符号拡張）。
pub fn lha<B: Backend>(b: &mut B, word: u32, _pc: u64, le: bool) -> Flow<B> {
    let (t, r, d) = d_fields(word);
    ld_d(b, t, r, d, 2, true, false, le)
}

/// lhau。
pub fn lhau<B: Backend>(b: &mut B, word: u32, _pc: u64, le: bool) -> Flow<B> {
    let (t, r, d) = d_fields(word);
    ld_d(b, t, r, d, 2, true, true, le)
}

/// op44/45: sth/sthu。
pub fn sth<B: Backend>(b: &mut B, word: u32, _pc: u64, le: bool) -> Flow<B> {
    let (t, r, d) = d_fields(word);
    st_d(b, t, r, d, 2, false, le)
}

/// sthu。
pub fn sthu<B: Backend>(b: &mut B, word: u32, _pc: u64, le: bool) -> Flow<B> {
    let (t, r, d) = d_fields(word);
    st_d(b, t, r, d, 2, true, le)
}

/// op46/47: lmw/stmw。
pub fn lmw<B: Backend>(b: &mut B, word: u32, _pc: u64, le: bool) -> Flow<B> {
    let (t, r, d) = d_fields(word);
    lmw_i(b, t, r, d, le)
}

/// stmw。
pub fn stmw<B: Backend>(b: &mut B, word: u32, _pc: u64, le: bool) -> Flow<B> {
    let (t, r, d) = d_fields(word);
    stmw_i(b, t, r, d, le)
}

/// FP 単精度ロード: f32 → f64 に変換して dw0 へ。
fn fp_ld32<B: Backend>(b: &mut B, t: u8, ea: B::V<W64>, acc: Access) -> Flow<B> {
    let w = b.load::<W32>(ea, acc)?;
    let d = b.fcvt_ff::<W32, W64>(w, 0);
    set_fpr(b, t, d);
    Ok(())
}

/// FP 倍精度ロード。
fn fp_ld64<B: Backend>(b: &mut B, t: u8, ea: B::V<W64>, acc: Access) -> Flow<B> {
    let v = b.load::<W64>(ea, acc)?;
    set_fpr(b, t, v);
    Ok(())
}

/// lfs/lfsu の共通（upd で rA 更新）。
fn lfs_i<B: Backend>(b: &mut B, word: u32, upd: bool, le: bool) -> Flow<B> {
    let (t, r, d) = d_fields(word);
    let a = ra(b, r);
    let off = k(b, d as u64);
    let ea = b.add(a, off);
    fp_ld32(b, t, ea, data_acc(le, true))?;
    if upd {
        s(b, r, ea);
    }
    Ok(())
}

/// lfd/lfdu の共通。
fn lfd_i<B: Backend>(b: &mut B, word: u32, upd: bool, le: bool) -> Flow<B> {
    let (t, r, d) = d_fields(word);
    let a = ra(b, r);
    let off = k(b, d as u64);
    let ea = b.add(a, off);
    fp_ld64(b, t, ea, data_acc(le, true))?;
    if upd {
        s(b, r, ea);
    }
    Ok(())
}

/// stfs/stfsu の共通（dw0 の f64 を f32 に変換して 4B 書き）。
fn stfs_i<B: Backend>(b: &mut B, word: u32, upd: bool, le: bool) -> Flow<B> {
    let (t, r, d) = d_fields(word);
    let a = ra(b, r);
    let off = k(b, d as u64);
    let ea = b.add(a, off);
    let v = fpr(b, t);
    let w = b.fcvt_ff::<W64, W32>(v, 0);
    b.store::<W32>(ea, w, data_acc(le, false))?;
    if upd {
        s(b, r, ea);
    }
    Ok(())
}

/// stfd/stfdu の共通。
fn stfd_i<B: Backend>(b: &mut B, word: u32, upd: bool, le: bool) -> Flow<B> {
    let (t, r, d) = d_fields(word);
    let a = ra(b, r);
    let off = k(b, d as u64);
    let ea = b.add(a, off);
    let v = fpr(b, t);
    b.store::<W64>(ea, v, data_acc(le, false))?;
    if upd {
        s(b, r, ea);
    }
    Ok(())
}

/// op48/49: lfs/lfsu。
pub fn lfs<B: Backend>(b: &mut B, word: u32, _pc: u64, le: bool) -> Flow<B> {
    lfs_i(b, word, false, le)
}

/// lfsu。
pub fn lfsu<B: Backend>(b: &mut B, word: u32, _pc: u64, le: bool) -> Flow<B> {
    lfs_i(b, word, true, le)
}

/// op50/51: lfd/lfdu。
pub fn lfd<B: Backend>(b: &mut B, word: u32, _pc: u64, le: bool) -> Flow<B> {
    lfd_i(b, word, false, le)
}

/// lfdu。
pub fn lfdu<B: Backend>(b: &mut B, word: u32, _pc: u64, le: bool) -> Flow<B> {
    lfd_i(b, word, true, le)
}

/// op52/53: stfs/stfsu。
pub fn stfs<B: Backend>(b: &mut B, word: u32, _pc: u64, le: bool) -> Flow<B> {
    stfs_i(b, word, false, le)
}

/// stfsu。
pub fn stfsu<B: Backend>(b: &mut B, word: u32, _pc: u64, le: bool) -> Flow<B> {
    stfs_i(b, word, true, le)
}

/// op54/55: stfd/stfdu。
pub fn stfd<B: Backend>(b: &mut B, word: u32, _pc: u64, le: bool) -> Flow<B> {
    stfd_i(b, word, false, le)
}

/// stfdu。
pub fn stfdu<B: Backend>(b: &mut B, word: u32, _pc: u64, le: bool) -> Flow<B> {
    stfd_i(b, word, true, le)
}

/// op56: lq（128 ビットロード。rT=下位側、rT+1=上位側、rT は偶数）。
pub fn x56<B: Backend>(b: &mut B, word: u32, _pc: u64, le: bool) -> Flow<B> {
    let t = ((word >> 21) & 31) as u8;
    let r = ((word >> 16) & 31) as u8;
    let dq = i64::from(((word >> 4) & 0xfff) as i32) << 20 >> 16;
    let a = ra(b, r);
    let off = k(b, dq as u64);
    let ea = b.add(a, off);
    let acc = data_acc(le, true);
    let lo = b.load::<W64>(ea, acc)?;
    let __h503 = k(b, 8);
    let ea2 = b.add(ea, __h503);
    let hi = b.load::<W64>(ea2, acc)?;
    let tt = t & !1;
    s(b, tt, lo);
    s(b, tt + 1, hi);
    Ok(())
}

/// op58: ld/ldu/lwa（DS 形式、xo = bits1:0）。
pub fn x58<B: Backend>(b: &mut B, word: u32, _pc: u64, le: bool) -> Flow<B> {
    ds_i(b, word, true, le)
}

/// op61: lxv/stxv（DQ 形式）。
pub fn x61<B: Backend>(b: &mut B, word: u32, _pc: u64, le: bool) -> Flow<B> {
    dq_i(b, word, le)
}

/// op62: std/stdu（DS 形式）。
pub fn x62<B: Backend>(b: &mut B, word: u32, _pc: u64, le: bool) -> Flow<B> {
    ds_i(b, word, false, le)
}
