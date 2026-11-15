// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! s390/zArchitecture（ユーザーモード）の意味論。`polyisa_sem` の
//! バックエンド上に命令ごとの作用を書く。
//!
//! 生成デコーダが Insn へ振り分けたあと、0xB2/0xB9/0xB3/0xE3/0xEB/0xEC/
//! 0xED/0xE5 の 2 バイトオペコード空間はここで機能フィールドを読んで
//! さらに振り分ける。CC（条件コード）は `CpuState.cc` に格納する。
//!
//! 文字列命令（MVCL/MVCLE/CLCL/CLCLE/MVST/CLST 等）は 1 ステップに
//! 一定バイト数だけ進め、未完なら `jump(pc)` で再実行する。これは
//! docs/design/semantics.md の反復命令の規約に従う。
//!
//! 出典は SPEC-S390-ZARCH-POP（SA22-7832）と SPEC-S390-ESA390-POP。
//! DFP・HFP・10 進演算は範囲外で Unimplemented に落とす（GAP。
//! lib.rs の説明を参照）。
// Ref: SPEC-S390-ZARCH-POP (SA22-7832-13), SPEC-S390-ESA390-POP (SA22-7201-08).

use polyisa_mem::{Access, AccessKind, Align, Endian};
use polyisa_sem::{Backend, Cmp, ExceptionKind, Flow, GuestException, StateRef, W8, W16, W32, W64};

use crate::CpuState;

/// 汎用レジスタ番号。
pub struct Gpr(pub u8);
/// 浮動小数点レジスタ番号。
pub struct Fpr(pub u8);
/// アクセスレジスタ番号。
pub struct Acr(pub u8);

impl Gpr {
    #[must_use]
    pub const fn state(self) -> StateRef<W64> {
        StateRef::from_offset(core::mem::offset_of!(CpuState, r) + self.0 as usize * 8)
    }
}

impl Fpr {
    #[must_use]
    pub const fn state(self) -> StateRef<W64> {
        StateRef::from_offset(core::mem::offset_of!(CpuState, f) + self.0 as usize * 8)
    }
}

impl Acr {
    #[must_use]
    pub const fn state(self) -> StateRef<W64> {
        StateRef::from_offset(core::mem::offset_of!(CpuState, ar) + self.0 as usize * 8)
    }
}

/// 条件コード。
#[must_use]
pub const fn cc_ref() -> StateRef<W64> {
    StateRef::from_offset(core::mem::offset_of!(CpuState, cc))
}

/// FPC レジスタ。
#[must_use]
pub const fn fpc_ref() -> StateRef<W64> {
    StateRef::from_offset(core::mem::offset_of!(CpuState, fpc))
}

/// プログラムマスク。
#[must_use]
pub const fn pm_ref() -> StateRef<W64> {
    StateRef::from_offset(core::mem::offset_of!(CpuState, pm))
}

/// アドレスマスク（64 ビット = !0、31 ビット = 0x7fffffff）。
#[must_use]
pub const fn amask_ref() -> StateRef<W64> {
    StateRef::from_offset(core::mem::offset_of!(CpuState, amask))
}

/// STCK 系の簡易時計。
#[must_use]
pub const fn clk_ref() -> StateRef<W64> {
    StateRef::from_offset(core::mem::offset_of!(CpuState, clk))
}

/// データ読み出し。
const RD: Access = Access {
    endian: Endian::Be,
    align: Align::Natural,
    kind: AccessKind::DataRead,
};
/// データ書き込み。
const WR: Access = Access {
    endian: Endian::Be,
    align: Align::Natural,
    kind: AccessKind::DataWrite,
};

/// 文字列命令が 1 ステップに進める上限バイト数。
const CHUNK: u64 = 256;

fn unimp<B: Backend>(b: &mut B, code: u64) -> Flow<B> {
    Err(b.raise(GuestException {
        kind: ExceptionKind::Undefined,
        code,
        addr: None,
        in_delay_slot: false,
    }))
}

fn g<B: Backend>(b: &mut B, i: u8) -> B::V<W64> {
    b.get(Gpr(i & 15).state())
}

fn set_g<B: Backend>(b: &mut B, i: u8, v: B::V<W64>) {
    b.set(Gpr(i & 15).state(), v);
}

/// 下位 32 ビットだけを書き戻す（32 ビット命令の規約）。
fn set_g32<B: Backend>(b: &mut B, i: u8, v: B::V<W32>) {
    let old = g(b, i);
    let __h0 = b.konst::<W64>(0xffff_ffff_0000_0000);

    let hi = b.and(old, __h0);
    let lo = b.zext::<W32, W64>(v);
    let __h1 = b.or(hi, lo);

    set_g(b, i, __h1);
}

fn k<B: Backend>(b: &mut B, v: u64) -> B::V<W64> {
    b.konst::<W64>(v)
}

fn btrue<B: Backend>(b: &mut B) -> B::B {
    let z = k(b, 0);
    b.cmp(Cmp::Eq, z, z)
}

fn bfalse<B: Backend>(b: &mut B) -> B::B {
    let z = k(b, 0);
    let o = k(b, 1);
    b.cmp(Cmp::Eq, z, o)
}

/// ブール AND（select を使う）。
fn band<B: Backend>(b: &mut B, x: B::B, y: B::B) -> B::B {
    let t = k(b, 1);
    let z = k(b, 0);
    let sy = b.select(y, t, z);
    let v = b.select(x, sy, z);
    b.cmp(Cmp::Ne, v, z)
}

fn set_cc<B: Backend>(b: &mut B, v: u64) {
    let __h2 = b.konst::<W64>(v);

    b.set(cc_ref(), __h2);
}

/// 符号あり演算の CC: 0=ゼロ、1=負、2=正、3=オーバーフロー。
fn cc_signed<B: Backend>(b: &mut B, res: B::V<W64>, ovf: B::B) {
    let zero = k(b, 0);
    let eq = b.cmp(Cmp::Eq, res, zero);
    let lt = b.cmp(Cmp::LtS, res, zero);
    let __h3 = k(b, 0);
    let __h5 = k(b, 1);
    let __h6 = k(b, 2);

    let __h4 = b.select(lt, __h5, __h6);

    let base = b.select(eq, __h3, __h4);
    let __h8 = k(b, 3);
    let __h7 = b.select(ovf, __h8, base);

    b.set(cc_ref(), __h7);
}

/// 論理加減算の CC: 0=ゼロ・桁なし、1=非ゼロ・桁なし、2=ゼロ・桁あり、
/// 3=非ゼロ・桁あり。
fn cc_logical<B: Backend>(b: &mut B, res: B::V<W64>, carry: B::B) {
    let zero = k(b, 0);
    let is0 = b.cmp(Cmp::Eq, res, zero);
    let __h9 = k(b, 2);
    let __h10 = k(b, 3);

    let zc = b.select(is0, __h9, __h10);
    let __h11 = k(b, 0);
    let __h12 = k(b, 1);

    let zn = b.select(is0, __h11, __h12);
    let __h13 = b.select(carry, zc, zn);

    b.set(cc_ref(), __h13);
}

/// 比較の CC: 0=等しい、1=op1<op2、2=op1>op2。
fn cc_cmp<B: Backend>(b: &mut B, a: B::V<W64>, x: B::V<W64>, signed: bool) {
    let eq = b.cmp(Cmp::Eq, a, x);
    let lt = b.cmp(if signed { Cmp::LtS } else { Cmp::LtU }, a, x);
    let __h14 = k(b, 0);
    let __h16 = k(b, 1);
    let __h17 = k(b, 2);

    let __h15 = b.select(lt, __h16, __h17);

    let v = b.select(eq, __h14, __h15);
    b.set(cc_ref(), v);
}

/// テストの CC: 0=ゼロ、1=負、2=正。
fn cc_test<B: Backend>(b: &mut B, res: B::V<W64>) {
    let zero = k(b, 0);
    let eq = b.cmp(Cmp::Eq, res, zero);
    let lt = b.cmp(Cmp::LtS, res, zero);
    let __h18 = k(b, 0);
    let __h20 = k(b, 1);
    let __h21 = k(b, 2);

    let __h19 = b.select(lt, __h20, __h21);

    let v = b.select(eq, __h18, __h19);
    b.set(cc_ref(), v);
}

/// 有効アドレス。x2/b2 のフィールド値 0 は「レジスタを足さない」。
fn ea<B: Backend>(b: &mut B, x2: u8, b2: u8, disp: i64) -> B::V<W64> {
    let mut a = k(b, disp as u64);
    if x2 != 0 {
        let __h22 = g(b, x2);

        a = b.add(a, __h22);
    }
    if b2 != 0 {
        let __h23 = g(b, b2);

        a = b.add(a, __h23);
    }
    let m = b.get(amask_ref());
    b.and(a, m)
}

/// 分岐マスクの評価。CC=c はマスクビット (3-c) で選ぶ。
fn btaken<B: Backend>(b: &mut B, m: u8) -> B::B {
    let cc = b.get(cc_ref());
    let __h24 = k(b, 3);

    let sh = b.sub(__h24, cc);
    let __h25 = k(b, u64::from(m & 0xf));
    let __h23 = b.shr_l::<W64>(__h25, sh);
    let __h26 = k(b, 1);

    let bit = b.and(__h23, __h26);
    let __h27 = k(b, 0);

    b.cmp(Cmp::Ne, bit, __h27)
}

/// 条件付きジャンプ。
fn cjump<B: Backend>(b: &mut B, m: u8, target: B::V<W64>) -> Flow<B> {
    let c = btaken(b, m);
    b.if_then_else(
        c,
        |bb| {
            bb.jump(target);
            Ok(())
        },
        |_| Ok(()),
    )
}

// ---- フィールド切り出し ----

fn r1(w: u64) -> u8 {
    ((w >> 20) & 0xf) as u8
}
fn f3(w: u64) -> u8 {
    ((w >> 16) & 0xf) as u8
}
fn b2f(w: u64) -> u8 {
    ((w >> 12) & 0xf) as u8
}
fn d2(w: u64) -> u64 {
    w & 0xfff
}
fn i16f(w: u64) -> i64 {
    (w as u16) as i16 as i64
}
fn rr1(w: u64) -> u8 {
    ((w >> 4) & 0xf) as u8
}
fn rr2(w: u64) -> u8 {
    (w & 0xf) as u8
}
fn r1_48(w: u64) -> u8 {
    ((w >> 36) & 0xf) as u8
}
fn f3_48(w: u64) -> u8 {
    ((w >> 32) & 0xf) as u8
}
fn disp20(w: u64) -> i64 {
    let v = (((w >> 8) & 0xff) << 12) | ((w >> 16) & 0xfff);
    ((v << 44) as i64) >> 44
}
fn func(w: u64) -> u8 {
    (w & 0xff) as u8
}
fn ril_i2(w: u64) -> i64 {
    (w as u32) as i32 as i64
}
/// 48 ビット命令の b1/d1 フィールド（SS: bytes 4-5）。
fn b1_48(w: u64) -> u8 {
    ((w >> 28) & 0xf) as u8
}
fn d1_48(w: u64) -> u64 {
    (w >> 16) & 0xfff
}
/// 48 ビット命令の b2/d2 フィールド（SS: bytes 6-7）。
fn b2_48(w: u64) -> u8 {
    ((w >> 12) & 0xf) as u8
}
fn d2_48(w: u64) -> u64 {
    w & 0xfff
}
fn ril_u2(w: u64) -> u64 {
    w & 0xffff_ffff
}

/// 32 ビット符号あり加減算。
fn arith32<B: Backend>(b: &mut B, r: u8, x: B::V<W32>, sub: bool) -> Flow<B> {
    let __h28 = g(b, r);

    let a = b.trunc::<W64, W32>(__h28);
    let (v, _c, o) = if sub {
        let nx = b.not(x);
        let __h29 = btrue(b);

        b.add_with_carry(a, nx, __h29)
    } else {
        let __h30 = bfalse(b);

        b.add_with_carry(a, x, __h30)
    };
    set_g32(b, r, v);
    let s = b.sext::<W32, W64>(v);
    cc_signed(b, s, o);
    Ok(())
}

/// 64 ビット符号あり加減算。
fn arith64<B: Backend>(b: &mut B, r: u8, x: B::V<W64>, sub: bool) -> Flow<B> {
    let a = g(b, r);
    let (v, _c, o) = if sub {
        let nx = b.not(x);
        let __h31 = btrue(b);

        b.add_with_carry(a, nx, __h31)
    } else {
        let __h32 = bfalse(b);

        b.add_with_carry(a, x, __h32)
    };
    set_g(b, r, v);
    cc_signed(b, v, o);
    Ok(())
}

/// 32 ビット論理加減算。sub は a + ~x + 1（桁上がり=借りなし）。
fn arith32l<B: Backend>(b: &mut B, r: u8, x: B::V<W32>, sub: bool) -> Flow<B> {
    let __h33 = g(b, r);

    let a = b.trunc::<W64, W32>(__h33);
    let (v, c, _o) = if sub {
        let nx = b.not(x);
        let __h34 = btrue(b);

        b.add_with_carry(a, nx, __h34)
    } else {
        let __h35 = bfalse(b);

        b.add_with_carry(a, x, __h35)
    };
    set_g32(b, r, v);
    let z = b.zext::<W32, W64>(v);
    cc_logical(b, z, c);
    Ok(())
}

/// 64 ビット論理加減算。
fn arith64l<B: Backend>(b: &mut B, r: u8, x: B::V<W64>, sub: bool) -> Flow<B> {
    let a = g(b, r);
    let (v, c, _o) = if sub {
        let nx = b.not(x);
        let __h36 = btrue(b);

        b.add_with_carry(a, nx, __h36)
    } else {
        let __h37 = bfalse(b);

        b.add_with_carry(a, x, __h37)
    };
    set_g(b, r, v);
    cc_logical(b, v, c);
    Ok(())
}

/// 32 ビット論理演算（N=0/O=1/X=2）。
fn log32<B: Backend>(b: &mut B, r: u8, x: B::V<W32>, op: u8) -> Flow<B> {
    let __h38 = g(b, r);

    let a = b.trunc::<W64, W32>(__h38);
    let v = match op {
        0 => b.and(a, x),
        1 => b.or(a, x),
        _ => b.xor(a, x),
    };
    set_g32(b, r, v);
    let s = b.sext::<W32, W64>(v);
    cc_test(b, s);
    Ok(())
}

fn log64<B: Backend>(b: &mut B, r: u8, x: B::V<W64>, op: u8) -> Flow<B> {
    let a = g(b, r);
    let v = match op {
        0 => b.and(a, x),
        1 => b.or(a, x),
        _ => b.xor(a, x),
    };
    set_g(b, r, v);
    cc_test(b, v);
    Ok(())
}

/// メモリロード（サイズ・符号拡張）。
fn ldx<B: Backend>(
    b: &mut B,
    addr: B::V<W64>,
    bytes: u32,
    signed: bool,
) -> Result<B::V<W64>, B::Exit> {
    Ok(match (bytes, signed) {
        (1, false) => {
            let __h39 = b.load::<W8>(addr, RD)?;
            b.zext::<W8, W64>(__h39)
        }
        (1, true) => {
            let __h40 = b.load::<W8>(addr, RD)?;
            b.sext::<W8, W64>(__h40)
        }
        (2, false) => {
            let __h41 = b.load::<W16>(addr, RD)?;
            b.zext::<W16, W64>(__h41)
        }
        (2, true) => {
            let __h42 = b.load::<W16>(addr, RD)?;
            b.sext::<W16, W64>(__h42)
        }
        (4, false) => {
            let __h43 = b.load::<W32>(addr, RD)?;
            b.zext::<W32, W64>(__h43)
        }
        (4, true) => {
            let __h44 = b.load::<W32>(addr, RD)?;
            b.sext::<W32, W64>(__h44)
        }
        _ => b.load::<W64>(addr, RD)?,
    })
}

fn store_r<B: Backend>(b: &mut B, r: u8, addr: B::V<W64>, bytes: u32) -> Flow<B> {
    let v = g(b, r);
    match bytes {
        1 => {
            let __h45 = b.trunc::<W64, W8>(v);
            b.store::<W8>(addr, __h45, WR)?
        }
        2 => {
            let __h46 = b.trunc::<W64, W16>(v);
            b.store::<W16>(addr, __h46, WR)?
        }
        4 => {
            let __h47 = b.trunc::<W64, W32>(v);
            b.store::<W32>(addr, __h47, WR)?
        }
        _ => b.store::<W64>(addr, v, WR)?,
    }
    Ok(())
}

/// 32 ビット比較。
fn cmp32<B: Backend>(b: &mut B, r: u8, x: B::V<W32>, signed: bool) -> Flow<B> {
    let __h48 = g(b, r);

    let a32 = b.trunc::<W64, W32>(__h48);
    let (a, y) = if signed {
        (b.sext::<W32, W64>(a32), b.sext::<W32, W64>(x))
    } else {
        (b.zext::<W32, W64>(a32), b.zext::<W32, W64>(x))
    };
    cc_cmp(b, a, y, signed);
    Ok(())
}

fn cmp64<B: Backend>(b: &mut B, r: u8, x: B::V<W64>, signed: bool) -> Flow<B> {
    let __h49 = g(b, r);

    cc_cmp(b, __h49, x, signed);
    Ok(())
}

// ======================== 入口 ========================

/// `Insn` と命令語（下位 len ビット）から 1 命令を実行する。`pc` は命令
/// アドレス（分岐・再実行の基準）。
pub fn exec<B: Backend>(b: &mut B, insn: crate::Insn, w: u64, pc: u64) -> Flow<B> {
    use crate::Insn::*;
    match insn {
        EMisc => e_misc(b, w),
        Spm => {
            let a = g(b, rr1(w));
            let __h51 = k(b, 24);
            let __h50 = b.shr_l::<W64>(a, __h51);
            let __h52 = k(b, 0x7f);

            let ccpm = b.and(__h50, __h52);
            let __h55 = k(b, 4);
            let __h54 = b.shr_l::<W64>(ccpm, __h55);
            let __h56 = k(b, 3);

            let __h53 = b.and(__h54, __h56);

            b.set(cc_ref(), __h53);
            let __h58 = k(b, 0xf);
            let __h57 = b.and(ccpm, __h58);

            b.set(pm_ref(), __h57);
            Ok(())
        }
        Balr | Basr => {
            let (r, x) = (rr1(w), rr2(w));
            let ret = k(b, pc.wrapping_add(2));
            let t = g(b, x);
            set_g(b, r, ret);
            if x != 0 {
                b.jump(t);
            }
            Ok(())
        }
        Bsm | Bassm => {
            let (r, x) = (rr1(w), rr2(w));
            let ret = k(b, pc.wrapping_add(2));
            let t = g(b, x);
            set_g(b, r, ret);
            if x != 0 {
                b.jump(t);
            }
            Ok(())
        }
        Bctr => {
            let (r, x) = (rr1(w), rr2(w));
            let __h59 = g(b, r);
            let __h60 = k(b, 1);

            let v = b.sub(__h59, __h60);
            let __h61 = b.trunc::<W64, W32>(v);

            set_g32(b, r, __h61);
            let __h63 = k(b, 0xffff_ffff);
            let __h62 = b.and(v, __h63);
            let __h64 = k(b, 0);

            let nz = b.cmp(Cmp::Ne, __h62, __h64);
            if x == 0 {
                // BCTR r1,0: デクリメントのみで分岐しない。
                return Ok(());
            }
            let t = g(b, x);
            b.if_then_else(
                nz,
                |bb| {
                    bb.jump(t);
                    Ok(())
                },
                |_| Ok(()),
            )
        }
        Bcr => {
            let x = rr2(w);
            if x == 0 {
                // BCR m,0: r2=0 は分岐せず nop 相当（ホットパッチ埋めに使う）。
                return Ok(());
            }
            let __h65 = g(b, x);
            cjump(b, rr1(w), __h65)
        }
        Svc => unimp(b, 0x0a),
        Mvcl => mvcl(b, w, pc),
        Clcl => clcl(b, w, pc),
        Lpr | Lnr | Ltr | Lcr => {
            let (r, x) = (rr1(w), rr2(w));
            let v2 = g(b, x);
            // 絶対値・負の絶対値は 32 ビット領域で max/min として計算する。
            // `x | sign` では 0 が INT_MIN になる誤りが起きる。
            let x32 = b.trunc::<W64, W32>(v2);
            let z32 = b.konst::<W32>(0);
            let neg = b.sub(z32, x32);
            let lt = b.cmp(Cmp::LtS, x32, z32);
            let v = match insn {
                Lpr => b.select(lt, neg, x32),
                Lnr => b.select(lt, x32, neg),
                Ltr => x32,
                _ => neg,
            };
            set_g32(b, r, v);
            let s = b.sext::<W32, W64>(v);
            if insn == Lcr {
                let __h69 = k(b, 0xffff_ffff_8000_0000);

                let min = b.cmp(Cmp::Eq, s, __h69);
                cc_signed(b, s, min);
            } else {
                cc_test(b, s);
            }
            Ok(())
        }
        Nr | Or | Xr => {
            let op = match insn {
                Nr => 0,
                Or => 1,
                _ => 2,
            };
            let __h70 = g(b, rr2(w));

            let xv = b.trunc::<W64, W32>(__h70);
            log32(b, rr1(w), xv, op)
        }
        Lr => {
            let __h71 = g(b, rr2(w));

            let v = b.trunc::<W64, W32>(__h71);
            set_g32(b, rr1(w), v);
            Ok(())
        }
        Cr => {
            let __h73 = g(b, rr2(w));

            let __h72 = b.trunc::<W64, W32>(__h73);
            cmp32(b, rr1(w), __h72, true)
        }
        Clr => {
            let __h75 = g(b, rr2(w));

            let __h74 = b.trunc::<W64, W32>(__h75);
            cmp32(b, rr1(w), __h74, false)
        }
        Ar => {
            let __h77 = g(b, rr2(w));

            let __h76 = b.trunc::<W64, W32>(__h77);
            arith32(b, rr1(w), __h76, false)
        }
        Sr => {
            let __h79 = g(b, rr2(w));

            let __h78 = b.trunc::<W64, W32>(__h79);
            arith32(b, rr1(w), __h78, true)
        }
        Alr => {
            let __h81 = g(b, rr2(w));

            let __h80 = b.trunc::<W64, W32>(__h81);
            arith32l(b, rr1(w), __h80, false)
        }
        Slr => {
            let __h83 = g(b, rr2(w));

            let __h82 = b.trunc::<W64, W32>(__h83);
            arith32l(b, rr1(w), __h82, true)
        }
        Mr => mr(b, w),
        Dr => dr(b, w),
        Lpdr | Lndr | Ltdr | Lcdr | Lper | Lner | Lter | Lcer => fp_ltest(b, insn, w),
        Ldr | Ler => {
            let v = b.get(Fpr(rr2(w) & 15).state());
            if insn == Ler {
                let __h84 = b.get(Fpr(rr1(w) & 15).state());
                let __h85 = k(b, 0xffff_ffff);

                let hi = b.and(__h84, __h85);
                let __h86 = k(b, 0xffff_ffff_0000_0000);

                let nv = b.and(v, __h86);
                let __h87 = b.or(nv, hi);

                b.set(Fpr(rr1(w) & 15).state(), __h87);
            } else {
                b.set(Fpr(rr1(w) & 15).state(), v);
            }
            Ok(())
        }
        Ldxr | Ledr => {
            // LDXR/LEDR: 拡張→長、長→短。試作は f64 近似。
            let v = b.get(Fpr(rr2(w) & 15).state());
            let s = b.fcvt_ff::<W64, W32>(v, 0);
            let out = if insn == Ledr {
                b.zext::<W32, W64>(s)
            } else {
                v
            };
            b.set(Fpr(rr1(w) & 15).state(), out);
            Ok(())
        }
        // 32/48 ビット命令は第 2 段へ。
        _ => exec2(b, insn, w, pc),
    }
}

fn e_misc<B: Backend>(b: &mut B, w: u64) -> Flow<B> {
    match w & 0xffff {
        0x010a => unimp(b, 0x010a), // PFPO（10 進変換）は範囲外。
        0x01ff => unimp(b, 0x01ff), // TRAP2。
        _ => unimp(b, w & 0xffff),
    }
}

/// MR: 偶奇ペア下位 32 × 下位 32 → 64 ビット積をペアに置く。
fn mr<B: Backend>(b: &mut B, w: u64) -> Flow<B> {
    let (r, x) = (rr1(w), rr2(w));
    if r & 1 != 0 {
        return unimp(b, 0x5ec1);
    }
    let __h89 = g(b, r + 1);
    let __h88 = b.trunc::<W64, W32>(__h89);

    let a = b.sext::<W32, W64>(__h88);
    let __h91 = g(b, x);
    let __h90 = b.trunc::<W64, W32>(__h91);

    let y = b.sext::<W32, W64>(__h90);
    let p = b.mul::<W64>(a, y);
    set_g(b, r + 1, p);
    let __h93 = k(b, 32);
    let __h92 = b.shr_a::<W64>(p, __h93);

    set_g(b, r, __h92);
    Ok(())
}

/// DR: 偶奇ペア 64 / r2 下位 32 → 商を r1+1、余りを r1 の下位 32。
fn dr<B: Backend>(b: &mut B, w: u64) -> Flow<B> {
    let (r, x) = (rr1(w), rr2(w));
    let __h96 = g(b, x);
    let __h95 = b.trunc::<W64, W32>(__h96);
    let __h94 = b.sext::<W32, W64>(__h95);

    dr_body(b, r, __h94)
}

fn dr_body<B: Backend>(b: &mut B, r: u8, dvs: B::V<W64>) -> Flow<B> {
    if r & 1 != 0 {
        return unimp(b, 0x5ec1);
    }
    let __h98 = g(b, r);
    let __h97 = b.trunc::<W64, W32>(__h98);

    let hi = b.zext::<W32, W64>(__h97);
    let __h100 = g(b, r + 1);
    let __h99 = b.trunc::<W64, W32>(__h100);

    let lo = b.zext::<W32, W64>(__h99);
    let __h102 = k(b, 32);
    let __h101 = b.shl::<W64>(hi, __h102);

    let dvd = b.or(__h101, lo);
    let __h103 = k(b, 0);

    let dz = b.cmp(Cmp::Eq, dvs, __h103);
    b.if_then_else(
        dz,
        |bb| {
            Err(bb.raise(GuestException {
                kind: ExceptionKind::DivZero,
                code: 0x1d,
                addr: None,
                in_delay_slot: false,
            }))
        },
        |bb| {
            let q = bb.sdiv::<W64>(dvd, dvs);
            let rem = bb.srem::<W64>(dvd, dvs);
            let keep = bb.konst::<W64>(0xffff_ffff_0000_0000);
            let __h105 = bb.trunc::<W64, W32>(q);
            let __h104 = bb.sext::<W32, W64>(__h105);
            let __h106 = bb.konst::<W64>(0xffff_ffff);

            let q32 = bb.and(__h104, __h106);
            let __h108 = bb.trunc::<W64, W32>(rem);
            let __h107 = bb.sext::<W32, W64>(__h108);
            let __h109 = bb.konst::<W64>(0xffff_ffff);

            let r32 = bb.and(__h107, __h109);
            let __h112 = g(bb, r + 1);
            let __h111 = bb.and(__h112, keep);
            let __h110 = bb.or(__h111, q32);

            bb.set(Gpr(r + 1).state(), __h110);
            let __h115 = g(bb, r);
            let __h114 = bb.and(__h115, keep);
            let __h113 = bb.or(__h114, r32);

            bb.set(Gpr(r).state(), __h113);
            Ok(())
        },
    )
}

/// LPDR 系の符号操作と LT 系の CC。f0 近似の整数ビット操作。
fn fp_ltest<B: Backend>(b: &mut B, insn: crate::Insn, w: u64) -> Flow<B> {
    use crate::Insn::*;
    let (r, x) = (rr1(w), rr2(w));
    let v = b.get(Fpr(x).state());
    let sign = k(b, 0x8000_0000_0000_0000);
    let short = matches!(insn, Lper | Lner | Lter | Lcer);
    let out = match insn {
        Lpdr | Lper => {
            let __h116 = b.not(sign);
            b.and(v, __h116)
        }
        Lndr | Lner => b.or(v, sign),
        Lcdr | Lcer => b.xor(v, sign),
        _ => v,
    };
    let out = if short {
        let __h117 = k(b, 0xffff_ffff_0000_0000);

        b.and(out, __h117)
    } else {
        out
    };
    b.set(Fpr(r).state(), out);
    if matches!(insn, Ltdr | Lter) {
        let __h118 = b.and(out, sign);
        let __h119 = k(b, 0);

        // テスト: 0/負/正。近似はビットの符号（NaN/-0.0 の厳密さは GAP）。
        let neg = b.cmp(Cmp::Ne, __h118, __h119);
        let __h121 = b.not(sign);
        let __h120 = b.and(out, __h121);
        let __h122 = k(b, 0);

        let is0 = b.cmp(Cmp::Eq, __h120, __h122);
        let __h124 = k(b, 0);
        let __h126 = k(b, 1);
        let __h127 = k(b, 2);

        let __h125 = b.select(neg, __h126, __h127);

        let __h123 = b.select(is0, __h124, __h125);

        b.set(cc_ref(), __h123);
    }
    Ok(())
}

// ======================== MVCL/CLCL 系 ========================

/// MVCL: 1 ステップに CHUNK バイトまで進め、未完は jump(pc) で再実行。
/// r1/r1+1 = 宛先アドレス/長さ、r2/r2+1 = 元アドレス/長さ（上位バイトが
/// 埋めバイト）。
fn mvcl<B: Backend>(b: &mut B, w: u64, pc: u64) -> Flow<B> {
    let (r, x) = (rr1(w), rr2(w));
    if r & 1 != 0 || x & 1 != 0 {
        return unimp(b, 0x5ec1);
    }
    let __h129 = g(b, x + 1);
    let __h130 = k(b, 56);

    let __h128 = b.shr_l::<W64>(__h129, __h130);
    let __h131 = k(b, 0xff);

    let pad = b.and(__h128, __h131);
    let __h132 = g(b, x + 1);
    let __h133 = k(b, 0x00ff_ffff_ffff_ffff);

    let slen = b.and(__h132, __h133);
    let __h134 = g(b, r);
    let __h135 = g(b, r + 1);
    let __h136 = g(b, x);

    mvcl_body(b, r, x, __h134, __h135, __h136, slen, pad, pc)
}

/// MVCLE（RS 形式）: 元ペアが r3、埋めバイトは d2(b2) のメモリ内容。
fn mvcle<B: Backend>(b: &mut B, w: u64, pc: u64) -> Flow<B> {
    let (r, s, b2, d) = (r1(w), f3(w), b2f(w), d2(w));
    if r & 1 != 0 || s & 1 != 0 {
        return unimp(b, 0x5ec1);
    }
    let paddr = ea(b, 0, b2, d as i64);
    let __h137 = b.load::<W8>(paddr, RD)?;

    let pad = b.zext::<W8, W64>(__h137);
    let __h138 = g(b, r);
    let __h139 = g(b, r + 1);
    let __h140 = g(b, s);
    let __h141 = g(b, s + 1);

    mvcl_body(b, r, s, __h138, __h139, __h140, __h141, pad, pc)
}

#[allow(clippy::too_many_arguments)]
fn mvcl_body<B: Backend>(
    b: &mut B,
    r: u8,
    s: u8,
    mut dst: B::V<W64>,
    mut dlen: B::V<W64>,
    mut src: B::V<W64>,
    mut slen: B::V<W64>,
    pad: B::V<W64>,
    pc: u64,
) -> Flow<B> {
    let __h142 = b.cmp(Cmp::LtU, dlen, slen);

    // 破壊的重複チェック（dst が (src, src+len) に入る場合は CC3）。
    let span = b.select(__h142, dlen, slen);
    {
        let gt = b.cmp(Cmp::GtU, dst, src);
        let end = b.add(src, span);
        let lt = b.cmp(Cmp::LtU, dst, end);
        let __h143 = k(b, 0);

        let nz = b.cmp(Cmp::Ne, span, __h143);
        let __h144 = band(b, gt, lt);

        let ov = band(b, __h144, nz);
        let mut skip = false;
        b.if_then_else(
            ov,
            |bb| {
                skip = true;
                let __h145 = bb.konst::<W64>(3);

                bb.set(cc_ref(), __h145);
                Ok(())
            },
            |_| Ok(()),
        )?;
        if skip {
            return Ok(());
        }
    }
    let __h146 = k(b, CHUNK);

    // 最終ステップの CC は処理前の len 関係から決める。
    let last = b.cmp(Cmp::LeU, dlen, __h146);
    let ccv = {
        let eq = b.cmp(Cmp::Eq, dlen, slen);
        let lt = b.cmp(Cmp::LtU, dlen, slen);
        let __h147 = k(b, 0);
        let __h149 = k(b, 2);
        let __h150 = k(b, 1);

        let __h148 = b.select(lt, __h149, __h150);

        b.select(eq, __h147, __h148)
    };
    for _ in 0..CHUNK {
        let __h151 = k(b, 0);

        let active = b.cmp(Cmp::Ne, dlen, __h151);
        b.if_then_else(
            active,
            |bb| {
                let __h152 = bb.konst::<W64>(0);

                let has_src = bb.cmp(Cmp::Ne, slen, __h152);
                // 元が尽きたら読み先を dst に向ける（常に写像済み）。値は
                // 使わず pad を選ぶので、0 番地読みのフォルトを避ける。
                let raddr = bb.select(has_src, src, dst);
                let __h153 = bb.load::<W8>(raddr, RD)?;

                let sb = bb.zext::<W8, W64>(__h153);
                let byte = bb.select(has_src, sb, pad);
                let __h154 = bb.trunc::<W64, W8>(byte);

                bb.store::<W8>(dst, __h154, WR)?;
                let __h155 = bb.konst::<W64>(1);

                dst = bb.add(dst, __h155);
                let __h156 = bb.konst::<W64>(1);

                dlen = bb.sub(dlen, __h156);
                let __h157 = bb.konst::<W64>(1);
                let __h158 = bb.konst::<W64>(0);

                let adv = bb.select(has_src, __h157, __h158);
                src = bb.add(src, adv);
                slen = bb.sub(slen, adv);
                Ok(())
            },
            |_| Ok(()),
        )?;
    }
    set_g(b, r, dst);
    set_g(b, r + 1, dlen);
    set_g(b, s, src);
    let __h159 = g(b, s + 1);
    let __h160 = k(b, 0xff00_0000_0000_0000);

    let kp = b.and(__h159, __h160);
    let __h161 = b.or(kp, slen);

    set_g(b, s + 1, __h161);
    b.if_then_else(
        last,
        |bb| {
            bb.set(cc_ref(), ccv);
            Ok(())
        },
        |bb| {
            let __h162 = bb.konst::<W64>(pc);

            bb.jump(__h162);
            Ok(())
        },
    )
}

/// CLCL: メモリ比較。短い側は埋めバイトで延長して比較する。
fn clcl<B: Backend>(b: &mut B, w: u64, pc: u64) -> Flow<B> {
    let (r, x) = (rr1(w), rr2(w));
    if r & 1 != 0 || x & 1 != 0 {
        return unimp(b, 0x5ec1);
    }
    let __h164 = g(b, x + 1);
    let __h165 = k(b, 56);

    let __h163 = b.shr_l::<W64>(__h164, __h165);
    let __h166 = k(b, 0xff);

    let pad = b.and(__h163, __h166);
    let __h167 = g(b, x + 1);
    let __h168 = k(b, 0x00ff_ffff_ffff_ffff);

    let blen = b.and(__h167, __h168);
    let __h169 = g(b, r);
    let __h170 = g(b, r + 1);
    let __h171 = g(b, x);

    clcl_body(b, r, x, __h169, __h170, __h171, blen, pad, pc)
}

fn clcle<B: Backend>(b: &mut B, w: u64, pc: u64) -> Flow<B> {
    let (r, s, b2, d) = (r1(w), f3(w), b2f(w), d2(w));
    if r & 1 != 0 || s & 1 != 0 {
        return unimp(b, 0x5ec1);
    }
    let paddr = ea(b, 0, b2, d as i64);
    let __h172 = b.load::<W8>(paddr, RD)?;

    let pad = b.zext::<W8, W64>(__h172);
    let __h173 = g(b, r);
    let __h174 = g(b, r + 1);
    let __h175 = g(b, s);
    let __h176 = g(b, s + 1);

    clcl_body(b, r, s, __h173, __h174, __h175, __h176, pad, pc)
}

#[allow(clippy::too_many_arguments)]
fn clcl_body<B: Backend>(
    b: &mut B,
    r: u8,
    s: u8,
    mut a: B::V<W64>,
    mut alen: B::V<W64>,
    mut x: B::V<W64>,
    mut blen: B::V<W64>,
    pad: B::V<W64>,
    pc: u64,
) -> Flow<B> {
    let mut hit = false;
    let mut done = false;
    for _ in 0..CHUNK {
        if hit {
            break;
        }
        let rem = b.or(alen, blen);
        let __h177 = k(b, 0);

        let active = b.cmp(Cmp::Ne, rem, __h177);
        b.if_then_else(
            active,
            |bb| {
                let __h179 = bb.konst::<W64>(0);
                let __h178 = bb.cmp(Cmp::Ne, alen, __h179);
                let __h181 = bb.load::<W8>(a, RD)?;
                let __h180 = bb.zext::<W8, W64>(__h181);

                let ab = bb.select(__h178, __h180, pad);
                let __h183 = bb.konst::<W64>(0);
                let __h182 = bb.cmp(Cmp::Ne, blen, __h183);
                let __h185 = bb.load::<W8>(x, RD)?;
                let __h184 = bb.zext::<W8, W64>(__h185);

                let cb = bb.select(__h182, __h184, pad);
                let ne = bb.cmp(Cmp::Ne, ab, cb);
                bb.if_then_else(
                    ne,
                    |b2| {
                        hit = true;
                        let lt = b2.cmp(Cmp::LtU, ab, cb);
                        let __h187 = b2.konst::<W64>(1);
                        let __h188 = b2.konst::<W64>(2);

                        let __h186 = b2.select(lt, __h187, __h188);

                        b2.set(cc_ref(), __h186);
                        Ok(())
                    },
                    |b2| {
                        let __h190 = b2.konst::<W64>(0);
                        let __h189 = b2.cmp(Cmp::Ne, alen, __h190);
                        let __h191 = b2.konst::<W64>(1);
                        let __h192 = b2.konst::<W64>(0);

                        let ad = b2.select(__h189, __h191, __h192);
                        let __h194 = b2.konst::<W64>(0);
                        let __h193 = b2.cmp(Cmp::Ne, blen, __h194);
                        let __h195 = b2.konst::<W64>(1);
                        let __h196 = b2.konst::<W64>(0);

                        let bd = b2.select(__h193, __h195, __h196);
                        a = b2.add(a, ad);
                        alen = b2.sub(alen, ad);
                        x = b2.add(x, bd);
                        blen = b2.sub(blen, bd);
                        Ok(())
                    },
                )?;
                Ok(())
            },
            |_| {
                done = true;
                Ok(())
            },
        )?;
        if hit || done {
            break;
        }
    }
    set_g(b, r, a);
    set_g(b, r + 1, alen);
    set_g(b, s, x);
    let __h197 = g(b, s + 1);
    let __h198 = k(b, 0xff00_0000_0000_0000);

    let kp = b.and(__h197, __h198);
    let __h199 = b.or(kp, blen);

    set_g(b, s + 1, __h199);
    if hit {
        return Ok(());
    }
    // 全バイト一致なら CC0 で終了、まだ残るなら再実行。
    let rem = b.or(alen, blen);
    let __h200 = k(b, 0);

    let fin = b.cmp(Cmp::Eq, rem, __h200);
    b.if_then_else(
        fin,
        |bb| {
            let __h201 = bb.konst::<W64>(0);

            bb.set(cc_ref(), __h201);
            Ok(())
        },
        |bb| {
            let __h202 = bb.konst::<W64>(pc);

            bb.jump(__h202);
            Ok(())
        },
    )
}

// ======================== RX/RS/SI/RI ========================

/// RX 形式のロード・演算・分岐。`w` は 32 ビット。
pub fn rx<B: Backend>(b: &mut B, insn: crate::Insn, w: u64, pc: u64) -> Flow<B> {
    use crate::Insn::*;
    let (r, x2, b2, d) = (r1(w), f3(w), b2f(w), d2(w));
    let a = ea(b, x2, b2, d as i64);
    match insn {
        La | Lae => {
            // 64 ビットアドレス指定モードでは実効アドレスを 64 ビット全部
            // 書く。ESA（31 ビット）では下位 32 ビットの書き換え。
            let m = b.get(amask_ref());
            let __h202 = k(b, u64::MAX);

            let is64 = b.cmp(Cmp::Eq, m, __h202);
            let __h205 = g(b, r);
            let __h206 = k(b, 0xffff_ffff_0000_0000);

            let hi = b.and(__h205, __h206);
            let __h207 = b.trunc::<W64, W32>(a);

            let lo = b.zext::<W32, W64>(__h207);
            let __h204 = b.or(hi, lo);

            let v = b.select(is64, a, __h204);
            set_g(b, r, v);
            Ok(())
        }
        Ic => {
            let __h204 = b.load::<W8>(a, RD)?;

            let v = b.zext::<W8, W64>(__h204);
            let __h205 = b.trunc::<W64, W32>(v);

            set_g32(b, r, __h205);
            Ok(())
        }
        Stc => {
            let __h206 = g(b, r);

            let v = b.trunc::<W64, W8>(__h206);
            b.store::<W8>(a, v, WR)?;
            Ok(())
        }
        Sth => store_r(b, r, a, 2),
        St => store_r(b, r, a, 4),
        Lh => {
            let v = ldx(b, a, 2, true)?;
            let __h207 = b.trunc::<W64, W32>(v);

            set_g32(b, r, __h207);
            Ok(())
        }
        L => {
            let v = ldx(b, a, 4, false)?;
            let __h208 = b.trunc::<W64, W32>(v);

            set_g32(b, r, __h208);
            Ok(())
        }
        Bal | Bas => {
            let ret = k(b, pc.wrapping_add(4));
            set_g(b, r, ret);
            b.jump(a);
            Ok(())
        }
        Bct => {
            let __h209 = g(b, r);
            let __h210 = k(b, 1);

            let v = b.sub(__h209, __h210);
            let __h211 = b.trunc::<W64, W32>(v);

            set_g32(b, r, __h211);
            let __h213 = k(b, 0xffff_ffff);
            let __h212 = b.and(v, __h213);
            let __h214 = k(b, 0);

            let nz = b.cmp(Cmp::Ne, __h212, __h214);
            b.if_then_else(
                nz,
                |bb| {
                    bb.jump(a);
                    Ok(())
                },
                |_| Ok(()),
            )
        }
        Bc => cjump(b, r, a),
        Ch => {
            let __h215 = ldx(b, a, 2, true)?;

            let v = b.trunc::<W64, W32>(__h215);
            cmp32(b, r, v, true)
        }
        C => {
            let __h216 = ldx(b, a, 4, false)?;

            let v = b.trunc::<W64, W32>(__h216);
            cmp32(b, r, v, true)
        }
        Cl => {
            let __h217 = ldx(b, a, 4, false)?;

            let v = b.trunc::<W64, W32>(__h217);
            cmp32(b, r, v, false)
        }
        Ah | Sh => {
            let __h218 = ldx(b, a, 2, true)?;

            let v = b.trunc::<W64, W32>(__h218);
            arith32(b, r, v, insn == Sh)
        }
        A | S => {
            let __h219 = ldx(b, a, 4, false)?;

            let v = b.trunc::<W64, W32>(__h219);
            arith32(b, r, v, insn == S)
        }
        Al | Sl => {
            let __h220 = ldx(b, a, 4, false)?;

            let v = b.trunc::<W64, W32>(__h220);
            arith32l(b, r, v, insn == Sl)
        }
        N | O | X => {
            let __h221 = ldx(b, a, 4, false)?;

            let v = b.trunc::<W64, W32>(__h221);
            let op = match insn {
                N => 0,
                O => 1,
                _ => 2,
            };
            log32(b, r, v, op)
        }
        Mh => {
            let m = ldx(b, a, 2, true)?;
            let __h223 = g(b, r);
            let __h222 = b.trunc::<W64, W32>(__h223);

            let v = b.sext::<W32, W64>(__h222);
            let p = b.mul::<W64>(v, m);
            let __h224 = b.trunc::<W64, W32>(p);

            set_g32(b, r, __h224);
            Ok(())
        }
        Mulw => {
            // M: 偶奇ペア × mem32。
            if r & 1 != 0 {
                return unimp(b, 0x5ec1);
            }
            let m = ldx(b, a, 4, true)?;
            let __h226 = g(b, r + 1);
            let __h225 = b.trunc::<W64, W32>(__h226);

            let v = b.sext::<W32, W64>(__h225);
            let p = b.mul::<W64>(v, m);
            set_g(b, r + 1, p);
            let __h228 = k(b, 32);
            let __h227 = b.shr_a::<W64>(p, __h228);

            set_g(b, r, __h227);
            Ok(())
        }
        Ms => {
            let m = ldx(b, a, 4, true)?;
            let __h230 = g(b, r);
            let __h229 = b.trunc::<W64, W32>(__h230);

            let v = b.sext::<W32, W64>(__h229);
            let p = b.mul::<W64>(v, m);
            let __h231 = b.trunc::<W64, W32>(p);

            set_g32(b, r, __h231);
            Ok(())
        }
        D => {
            let m = ldx(b, a, 4, true)?;
            dr_body(b, r, m)
        }
        Cvb => unimp(b, 0x4f), // CVB（10 進変換）は範囲外。
        Cvd => unimp(b, 0x4e), // CVD も同じ。
        Ex => unimp(b, 0x44),  // EX（ execute ）は範囲外。
        // BFP メモリ形式（HFP ロード・ストアはレジスタのビットをそのまま運ぶ）。
        Le => {
            let __h232 = b.load::<W32>(a, RD)?;

            let v = b.zext::<W32, W64>(__h232);
            let cur = b.get(Fpr(r & 15).state());
            let __h235 = k(b, 0);
            let __h234 = b.and(v, __h235);
            let __h238 = k(b, 32);
            let __h237 = b.shl::<W64>(v, __h238);
            let __h240 = k(b, 0xffff_ffff);
            let __h239 = b.and(cur, __h240);

            let __h236 = b.or(__h237, __h239);

            let __h233 = b.or(__h234, __h236);

            b.set(Fpr(r & 15).state(), __h233);
            Ok(())
        }
        Ld => {
            let v = b.load::<W64>(a, RD)?;
            b.set(Fpr(r & 15).state(), v);
            Ok(())
        }
        Ste => {
            let v = b.get(Fpr(r & 15).state());
            let __h243 = k(b, 32);
            let __h242 = b.shr_l::<W64>(v, __h243);
            let __h241 = b.trunc::<W64, W32>(__h242);

            b.store::<W32>(a, __h241, WR)?;
            Ok(())
        }
        Std => {
            let v = b.get(Fpr(r & 15).state());
            b.store::<W64>(a, v, WR)?;
            Ok(())
        }
        // HFP の算術・比較（AD/SD/MD/DD/CD/MXD/AW/SW/AU/SU/AE/SE/MDE/DE/CE）は範囲外。
        _ => unimp(b, w & 0xffff_ffff),
    }
}

/// RS/SI 形式（stm/lm/シフト/tm/mvi/ni/cli/oi/xi/mvcle/clcle/bx 等）。
pub fn rs<B: Backend>(b: &mut B, insn: crate::Insn, w: u64, pc: u64) -> Flow<B> {
    use crate::Insn::*;
    let (r, f3v, b2, d) = (r1(w), f3(w), b2f(w), d2(w));
    match insn {
        Stm | Lm | Lam | Stam => {
            // r3–r1 を連続ワードとして書く/読む（wrap-around）。
            let base = ea(b, 0, b2, d as i64);
            let r3 = f3v;
            let mut i = r;
            loop {
                let off = k(b, u64::from((i.wrapping_sub(r)) & 15) * 4);
                let a = b.add(base, off);
                if insn == Stm || insn == Stam {
                    let v = if insn == Stam {
                        b.get(Acr(i).state())
                    } else {
                        g(b, i)
                    };
                    let __h244 = b.trunc::<W64, W32>(v);

                    b.store::<W32>(a, __h244, WR)?;
                } else {
                    let __h245 = b.load::<W32>(a, RD)?;

                    let v = b.zext::<W32, W64>(__h245);
                    if insn == Lam {
                        b.set(Acr(i).state(), v);
                    } else {
                        let __h246 = b.trunc::<W64, W32>(v);

                        set_g32(b, i, __h246);
                    }
                }
                if i == r3 {
                    break;
                }
                i = (i + 1) & 15;
            }
            Ok(())
        }
        Srl | Sll | Sra | Sla | Srdl | Sldl | Srda | Slda => shift_r(b, insn, w),
        Tm | Ni | Cli | Oi | Xi | Mvi => si_op(b, insn, w),
        Ts => {
            // TS: 読んで CC、0xff を書く。
            let a = ea(b, 0, b2, d as i64);
            let __h247 = b.load::<W8>(a, RD)?;

            let v = b.zext::<W8, W64>(__h247);
            let __h248 = k(b, 0);

            let nz = b.cmp(Cmp::Ne, v, __h248);
            let __h250 = k(b, 1);
            let __h251 = k(b, 0);

            let __h249 = b.select(nz, __h250, __h251);

            b.set(cc_ref(), __h249);
            let __h252 = b.konst::<W8>(0xff);

            b.store::<W8>(a, __h252, WR)?;
            Ok(())
        }
        Brxh | Brxle | Bxh | Bxle => bx(b, insn, w),
        Diag => unimp(b, 0x83),
        Stnsm | Stosm => {
            // STNSM/STOSM: アクセスレジスタ操作（ユーザーモードでは実質 no-op）。
            let a = ea(b, 0, b2, d as i64);
            let v = g(b, r);
            let __h253 = b.trunc::<W64, W8>(v);

            b.store::<W8>(a, __h253, WR)?;
            Ok(())
        }
        Mvcle => mvcle(b, w, pc),
        Clcle => clcle(b, w, pc),
        Icm => {
            // ICM: 下位 32 ビット（バイト 4–7）へマスク選択で挿入。
            let a = ea(b, 0, b2, d as i64);
            icm_body(b, r, f3v, a, 4, false)
        }
        Stcm => {
            let a = ea(b, 0, b2, d as i64);
            stcm_body(b, r, f3v, a, 4, false)
        }
        Clm => {
            // CLM: 下位 32 ビットのマスク選択バイトとメモリ比較。
            let a = ea(b, 0, b2, d as i64);
            clm_body(b, r, f3v, a, 4, false)
        }
        Cs => {
            // CS: 32 ビット CAS（r1 下位=期待値、r3 下位=新値）。
            let a = ea(b, 0, b2, d as i64);
            let __h400 = g(b, r);
            let old = b.trunc::<W64, W32>(__h400);
            let __h401 = g(b, f3v);
            let new = b.trunc::<W64, W32>(__h401);
            let got = b.cmpxchg::<W32>(a, old, new, WR)?;
            let eq = b.cmp(Cmp::Eq, got, old);
            b.if_then_else(
                eq,
                |bb| {
                    let __h402 = bb.konst::<W64>(0);
                    bb.set(cc_ref(), __h402);
                    Ok(())
                },
                |bb| {
                    set_g32(bb, r, got);
                    let __h403 = bb.konst::<W64>(1);
                    bb.set(cc_ref(), __h403);
                    Ok(())
                },
            )
        }
        Cds => {
            // CDS: 64 ビット CAS（r1 ペア=期待値、r3 ペア=新値）。
            if r & 1 != 0 || f3v & 1 != 0 {
                return unimp(b, 0x5ec1);
            }
            let a = ea(b, 0, b2, d as i64);
            let old0 = g(b, r);
            let old1 = g(b, r + 1);
            let m0 = b.load::<W64>(a, RD)?;
            let same = {
                let e0 = b.cmp(Cmp::Eq, m0, old0);
                let __h404 = k(b, 8);
                let a1 = b.add(a, __h404);
                let m1 = b.load::<W64>(a1, RD)?;
                let e1 = b.cmp(Cmp::Eq, m1, old1);
                band(b, e0, e1)
            };
            b.if_then_else(
                same,
                |bb| {
                    let n0 = g(bb, f3v);
                    bb.store::<W64>(a, n0, WR)?;
                    let __h405 = bb.konst::<W64>(8);
                    let a1 = bb.add(a, __h405);
                    let n1 = g(bb, f3v + 1);
                    bb.store::<W64>(a1, n1, WR)?;
                    let __h406 = bb.konst::<W64>(0);
                    bb.set(cc_ref(), __h406);
                    Ok(())
                },
                |bb| {
                    let __h407 = bb.konst::<W64>(8);
                    let a1 = bb.add(a, __h407);
                    let m1 = bb.load::<W64>(a1, RD)?;
                    bb.set(Gpr(r).state(), m0);
                    bb.set(Gpr(r + 1).state(), m1);
                    let __h408 = bb.konst::<W64>(1);
                    bb.set(cc_ref(), __h408);
                    Ok(())
                },
            )
        }
        X08 | X09 => unimp(b, w & 0xffff),
        _ => unimp(b, w & 0xffff_ffff),
    }
}

/// RS のシフト群。アドレスは変位+b2（x2 フィールドなし）で下位 6 ビット。
fn shift_r<B: Backend>(b: &mut B, insn: crate::Insn, w: u64) -> Flow<B> {
    use crate::Insn::*;
    let (r, _r3, b2, d) = (r1(w), f3(w), b2f(w), d2(w));
    let a = ea(b, 0, b2, d as i64);
    let __h254 = k(b, 63);

    let n = b.and(a, __h254);
    match insn {
        Srl | Sra | Sll | Sla => {
            let __h256 = g(b, r);
            let __h255 = b.trunc::<W64, W32>(__h256);

            let v = b.zext::<W32, W64>(__h255);
            let (out, ovf) = match insn {
                Srl => (b.shr_l::<W64>(v, n), bfalse(b)),
                Sll => {
                    let __h257 = b.shl::<W64>(v, n);
                    let __h258 = k(b, 0xffff_ffff);

                    (b.and(__h257, __h258), bfalse(b))
                }
                Sra => {
                    let __h260 = b.trunc::<W64, W32>(v);

                    let __h259 = b.sext::<W32, W64>(__h260);
                    (b.shr_a::<W64>(__h259, n), bfalse(b))
                }
                _ => {
                    let __h261 = b.trunc::<W64, W32>(v);

                    // SLA: 符号左シフト。オーバーフローで CC3（近似: シフト後の
                    // 32 ビットが元の符号と違う/上位に食い込んだら）。
                    let sv = b.sext::<W32, W64>(__h261);
                    let sh = b.shl::<W64>(sv, n);
                    let back = b.shr_a::<W64>(sh, n);
                    let neq = b.cmp(Cmp::Ne, back, sv);
                    let __h262 = k(b, 0xffff_ffff);

                    (b.and(sh, __h262), neq)
                }
            };
            let o32 = b.trunc::<W64, W32>(out);
            set_g32(b, r, o32);
            let s = b.sext::<W32, W64>(o32);
            if insn == Sla {
                cc_signed(b, s, ovf);
            } else if insn == Sra || insn == Sll {
                cc_test(b, s);
            }
            Ok(())
        }
        Srdl | Sldl | Srda | Slda => {
            // 偶奇ペアの 64 ビットシフト。
            if r & 1 != 0 {
                return unimp(b, 0x5ec1);
            }
            let __h264 = g(b, r);
            let __h263 = b.trunc::<W64, W32>(__h264);

            let hi = b.zext::<W32, W64>(__h263);
            let __h266 = g(b, r + 1);
            let __h265 = b.trunc::<W64, W32>(__h266);

            let lo = b.zext::<W32, W64>(__h265);
            let __h268 = k(b, 32);
            let __h267 = b.shl::<W64>(hi, __h268);

            let v = b.or(__h267, lo);
            let (out, ovf) = match insn {
                Srdl => (b.shr_l::<W64>(v, n), bfalse(b)),
                Sldl => (b.shl::<W64>(v, n), bfalse(b)),
                Srda => (b.shr_a::<W64>(v, n), bfalse(b)),
                _ => {
                    let sh = b.shl::<W64>(v, n);
                    let back = b.shr_a::<W64>(sh, n);
                    let neq = b.cmp(Cmp::Ne, back, v);
                    (sh, neq)
                }
            };
            let __h271 = k(b, 32);
            let __h270 = b.shr_l::<W64>(out, __h271);
            let __h269 = b.trunc::<W64, W32>(__h270);

            set_g32(b, r, __h269);
            let __h272 = b.trunc::<W64, W32>(out);

            set_g32(b, r + 1, __h272);
            if insn == Slda {
                cc_signed(b, out, ovf);
            } else if insn == Srda {
                cc_test(b, out);
            }
            Ok(())
        }
        _ => unimp(b, w & 0xffff_ffff),
    }
}

/// SI 形式の即値演算（ni/oi/xi/cli/mvi/tm）。
fn si_op<B: Backend>(b: &mut B, insn: crate::Insn, w: u64) -> Flow<B> {
    use crate::Insn::*;
    let i2 = (w >> 16) & 0xff;
    let a = ea(b, 0, b2f(w), d2(w) as i64);
    let __h273 = b.load::<W8>(a, RD)?;

    let v = b.zext::<W8, W64>(__h273);
    let iv = k(b, i2);
    match insn {
        Mvi => {
            let __h274 = b.konst::<W8>(i2 as u8);

            b.store::<W8>(a, __h274, WR)?;
            Ok(())
        }
        Ni | Oi | Xi => {
            let r = match insn {
                Ni => b.and(v, iv),
                Oi => b.or(v, iv),
                _ => b.xor(v, iv),
            };
            let __h275 = b.trunc::<W64, W8>(r);

            b.store::<W8>(a, __h275, WR)?;
            let __h276 = k(b, 0);

            let nz = b.cmp(Cmp::Ne, r, __h276);
            let __h278 = k(b, 1);
            let __h279 = k(b, 0);

            let __h277 = b.select(nz, __h278, __h279);

            b.set(cc_ref(), __h277);
            Ok(())
        }
        Cli => {
            cc_cmp(b, v, iv, false);
            Ok(())
        }
        Tm => {
            let r = b.and(v, iv);
            let __h280 = k(b, 0);

            let is0 = b.cmp(Cmp::Eq, r, __h280);
            let all = b.cmp(Cmp::Eq, r, iv);
            let __h281 = k(b, 0);
            let __h283 = k(b, 3);
            let __h284 = k(b, 1);

            let __h282 = b.select(all, __h283, __h284);

            // CC: 0=全部 0、1=混在、3=全部 1。
            let cc = b.select(is0, __h281, __h282);
            b.set(cc_ref(), cc);
            Ok(())
        }
        _ => unimp(b, w & 0xffff_ffff),
    }
}

/// BXH/BXLE/BRXH/BRXLE。r3（偶数なら r3+1 が増分、r3 が比較値;奇数なら
/// r3 が両方）の規約に従う。
fn bx<B: Backend>(b: &mut B, insn: crate::Insn, w: u64) -> Flow<B> {
    use crate::Insn::*;
    let (r, r3, b2, d) = (r1(w), f3(w), b2f(w), d2(w));
    let target = ea(b, 0, b2, d as i64);
    let (inc, lim) = if r3 & 1 != 0 { (r3, r3) } else { (r3 + 1, r3) };
    let is64 = matches!(insn, Brxh | Brxle);
    let one = k(b, 1);
    if is64 {
        let __h285 = g(b, r);
        let __h286 = g(b, inc);

        let v = b.add(__h285, __h286);
        set_g(b, r, v);
        let c = if insn == Brxh {
            let __h287 = g(b, lim);

            b.cmp(Cmp::GtS, v, __h287)
        } else {
            let __h288 = g(b, lim);

            b.cmp(Cmp::LeS, v, __h288)
        };
        b.if_then_else(
            c,
            |bb| {
                bb.jump(target);
                Ok(())
            },
            |_| Ok(()),
        )
    } else {
        let __h289 = g(b, r);
        let __h290 = g(b, inc);

        let v = b.add(__h289, __h290);
        let __h291 = b.trunc::<W64, W32>(v);

        set_g32(b, r, __h291);
        let __h292 = b.trunc::<W64, W32>(v);

        let vs = b.sext::<W32, W64>(__h292);
        let __h294 = g(b, lim);
        let __h293 = b.trunc::<W64, W32>(__h294);

        let l = b.sext::<W32, W64>(__h293);
        let c = if insn == Bxh {
            b.cmp(Cmp::GtS, vs, l)
        } else {
            b.cmp(Cmp::LeS, vs, l)
        };
        let _ = one;
        b.if_then_else(
            c,
            |bb| {
                bb.jump(target);
                Ok(())
            },
            |_| Ok(()),
        )
    }
}

// ======================== RI/RIL ========================

/// RI 形式（A5/A7。下位ニブルが機能）。
pub fn ri<B: Backend>(b: &mut B, insn: crate::Insn, w: u64, pc: u64) -> Flow<B> {
    use crate::Insn::*;
    let r = r1(w);
    let imm = i16f(w);
    match insn {
        Lhi | Lghi => {
            let v = k(b, imm as u64);
            if insn == Lhi {
                let __h295 = b.trunc::<W64, W32>(v);

                set_g32(b, r, __h295);
            } else {
                set_g(b, r, v);
            }
            Ok(())
        }
        Ahi | Aghi => {
            let v = k(b, imm as u64);
            if insn == Ahi {
                let __h296 = b.trunc::<W64, W32>(v);

                arith32(b, r, __h296, false)
            } else {
                arith64(b, r, v, false)
            }
        }
        Mhi | Mghi => {
            let a = if insn == Mhi {
                let __h298 = g(b, r);
                let __h297 = b.trunc::<W64, W32>(__h298);

                b.sext::<W32, W64>(__h297)
            } else {
                g(b, r)
            };
            let __h299 = k(b, imm as u64);

            let p = b.mul::<W64>(a, __h299);
            if insn == Mhi {
                let __h300 = b.trunc::<W64, W32>(p);

                set_g32(b, r, __h300);
            } else {
                set_g(b, r, p);
            }
            Ok(())
        }
        Chi | Cghi => {
            let v = k(b, imm as u64);
            if insn == Chi {
                let __h301 = b.trunc::<W64, W32>(v);

                cmp32(b, r, __h301, true)
            } else {
                cmp64(b, r, v, true)
            }
        }
        Tmlh | Tmll | Tmhh | Tmhl => {
            let shift = match insn {
                Tmhh => 48,
                Tmhl => 32,
                Tmlh => 16,
                _ => 0,
            };
            let __h303 = g(b, r);
            let __h304 = k(b, shift);

            let __h302 = b.shr_l::<W64>(__h303, __h304);
            let __h305 = k(b, 0xffff);

            let v = b.and(__h302, __h305);
            let __h306 = k(b, (imm as u64) & 0xffff);

            let t = b.and(v, __h306);
            let __h307 = k(b, 0);

            let is0 = b.cmp(Cmp::Eq, t, __h307);
            let __h309 = k(b, 0xffff);
            let __h308 = b.and(v, __h309);

            let all = b.cmp(Cmp::Eq, t, __h308);
            let __h311 = k(b, 0);
            let __h313 = k(b, 3);
            let __h314 = k(b, 1);

            let __h312 = b.select(all, __h313, __h314);

            let __h310 = b.select(is0, __h311, __h312);

            b.set(cc_ref(), __h310);
            Ok(())
        }
        Brc => {
            let t = k(b, pc.wrapping_add((imm << 1) as u64));
            cjump(b, r, t)
        }
        Bras => {
            let t = k(b, pc.wrapping_add((imm << 1) as u64));
            let ret = k(b, pc.wrapping_add(4));
            set_g(b, r, ret);
            b.jump(t);
            Ok(())
        }
        Brct | Brctg => {
            let __h315 = g(b, r);
            let __h316 = k(b, 1);

            let v = b.sub(__h315, __h316);
            if insn == Brct {
                let __h317 = b.trunc::<W64, W32>(v);

                set_g32(b, r, __h317);
            } else {
                set_g(b, r, v);
            }
            let m = if insn == Brct {
                k(b, 0xffff_ffff)
            } else {
                k(b, u64::MAX)
            };
            let __h318 = b.and(v, m);
            let __h319 = k(b, 0);

            let nz = b.cmp(Cmp::Ne, __h318, __h319);
            let t = k(b, pc.wrapping_add((imm << 1) as u64));
            b.if_then_else(
                nz,
                |bb| {
                    bb.jump(t);
                    Ok(())
                },
                |_| Ok(()),
            )
        }
        // A5: 16 ビット即値を上半・下半の各 16 ビットに挿入/論理。
        Llihh | Llihl | Llilh | Llill | Nihh | Nihl | Nilh | Nill | Oihh | Oihl | Oilh | Oill => {
            ri_imm(b, insn, r, imm as u64)
        }
        _ => unimp(b, w & 0xffff_ffff),
    }
}

/// A5 系の 16 ビット即値操作。挿入位置は命令の種類で決まる。
fn ri_imm<B: Backend>(b: &mut B, insn: crate::Insn, r: u8, imm: u64) -> Flow<B> {
    use crate::Insn::*;
    let (shift, op) = match insn {
        Llihh => (48, 0),
        Llihl => (32, 0),
        Llilh => (16, 0),
        Llill => (0, 0),
        Nihh => (48, 1),
        Nihl => (32, 1),
        Nilh => (16, 1),
        Nill => (0, 1),
        Oihh => (48, 2),
        Oihl => (32, 2),
        Oilh => (16, 2),
        _ => (0, 2), // Oill
    };
    let sh = k(b, shift);
    let __h320 = k(b, 0xffff);

    let fmask = b.shl::<W64>(__h320, sh);
    let __h321 = k(b, imm);

    let fv = b.shl::<W64>(__h321, sh);
    let old = g(b, r);
    let v = match op {
        0 => {
            let __h324 = b.not(fmask);
            let __h323 = b.and(old, __h324);

            let __h322 = b.or(fv, __h323);
            let __h325 = k(b, u64::MAX);

            b.and(__h322, __h325)
        }
        1 => {
            let t = b.and(old, fmask);
            let nv = b.and(t, fv);
            let __h327 = b.not(fmask);
            let __h326 = b.and(old, __h327);

            b.or(__h326, nv)
        }
        _ => {
            let t = b.and(old, fmask);
            let nv = b.or(t, fv);
            let __h329 = b.not(fmask);
            let __h328 = b.and(old, __h329);

            b.or(__h328, nv)
        }
    };
    set_g(b, r, v);
    Ok(())
}

/// RIL 形式（C0/C2/C4/C5/C6。下位ニブルが機能）。
pub fn ril<B: Backend>(b: &mut B, insn: crate::Insn, w: u64, pc: u64) -> Flow<B> {
    use crate::Insn::*;
    let r = r1_48(w);
    let imm32 = ril_i2(w);
    match insn {
        Larl => {
            let t = k(b, pc.wrapping_add((imm32 << 1) as u64));
            set_g(b, r, t);
            Ok(())
        }
        Brcl | Brul | Brh => {
            let m = if insn == Brul {
                0xf
            } else if insn == Brh {
                0x2
            } else {
                r & 0xf
            };
            let t = k(b, pc.wrapping_add((imm32 << 1) as u64));
            cjump(b, m, t)
        }
        Brasl => {
            let t = k(b, pc.wrapping_add((imm32 << 1) as u64));
            let ret = k(b, pc.wrapping_add(6));
            set_g(b, r, ret);
            b.jump(t);
            Ok(())
        }
        Iihf | Iilf | Nihf | Nilf | Oihf | Oilf | Llihf | Llilf | Xihf | Xilf => {
            ril_imm(b, insn, r, ril_u2(w))
        }
        Lgfi => {
            let __h330 = k(b, imm32 as u64);

            set_g(b, r, __h330);
            Ok(())
        }
        Agfi | Afi => arith64_or32(b, insn, r, imm32, false, true),
        Algfi | Alfi => arith64_or32(b, insn, r, imm32, false, false),
        Slgfi | Slfi => arith64_or32(b, insn, r, imm32, true, false),
        Cgfi | Cfi => {
            let v = k(b, imm32 as u64);
            if insn == Cgfi {
                cmp64(b, r, v, true)
            } else {
                let __h331 = b.trunc::<W64, W32>(v);

                cmp32(b, r, __h331, true)
            }
        }
        Clgfi | Clfi => {
            let v = k(b, imm32 as u64);
            if insn == Clgfi {
                cmp64(b, r, v, false)
            } else {
                let __h332 = b.trunc::<W64, W32>(v);

                cmp32(b, r, __h332, false)
            }
        }
        Msgfi | Msfi => {
            let a = if insn == Msfi {
                let __h334 = g(b, r);
                let __h333 = b.trunc::<W64, W32>(__h334);

                b.sext::<W32, W64>(__h333)
            } else {
                g(b, r)
            };
            let __h335 = k(b, imm32 as u64);

            let p = b.mul::<W64>(a, __h335);
            if insn == Msfi {
                let __h336 = b.trunc::<W64, W32>(p);

                set_g32(b, r, __h336);
            } else {
                set_g(b, r, p);
            }
            Ok(())
        }
        // C4: 相対ロード/ストア。
        Lgrl | Lgfrl | Lghrl | Lhrl | Llhrl | Llghrl | Lrl | Llgfrl | Stgrl | Strl | Sthrl => {
            let a = k(b, pc.wrapping_add((imm32 << 1) as u64));
            let __h337 = b.get(amask_ref());

            let ea_v = b.and(a, __h337);
            match insn {
                Stgrl => store_r(b, r, ea_v, 8),
                Strl => store_r(b, r, ea_v, 4),
                Sthrl => store_r(b, r, ea_v, 2),
                Lgrl => {
                    let v = b.load::<W64>(ea_v, RD)?;
                    set_g(b, r, v);
                    Ok(())
                }
                Lgfrl => {
                    let __h338 = b.load::<W32>(ea_v, RD)?;

                    let v = b.sext::<W32, W64>(__h338);
                    set_g(b, r, v);
                    Ok(())
                }
                Lghrl => {
                    let __h339 = b.load::<W16>(ea_v, RD)?;

                    let v = b.sext::<W16, W64>(__h339);
                    set_g(b, r, v);
                    Ok(())
                }
                Lhrl => {
                    let __h340 = b.load::<W16>(ea_v, RD)?;

                    let v = b.sext::<W16, W64>(__h340);
                    let __h341 = b.trunc::<W64, W32>(v);

                    set_g32(b, r, __h341);
                    Ok(())
                }
                Llhrl => {
                    let __h342 = b.load::<W16>(ea_v, RD)?;

                    let v = b.zext::<W16, W64>(__h342);
                    let __h343 = b.trunc::<W64, W32>(v);

                    set_g32(b, r, __h343);
                    Ok(())
                }
                Llghrl => {
                    let __h344 = b.load::<W16>(ea_v, RD)?;

                    let v = b.zext::<W16, W64>(__h344);
                    set_g(b, r, v);
                    Ok(())
                }
                Lrl => {
                    let __h345 = b.load::<W32>(ea_v, RD)?;

                    let v = b.zext::<W32, W64>(__h345);
                    let __h346 = b.trunc::<W64, W32>(v);

                    set_g32(b, r, __h346);
                    Ok(())
                }
                Llgfrl => {
                    let __h347 = b.load::<W32>(ea_v, RD)?;

                    let v = b.zext::<W32, W64>(__h347);
                    set_g(b, r, v);
                    Ok(())
                }
                _ => unimp(b, w),
            }
        }
        // C6: 相対比較と EXRL。
        Exrl => {
            // EXRL: ターゲット命令を実行する。試作では 1 命令ぶん実行する
            // 複雑なので未対応（GAP）。
            unimp(b, 0xc600)
        }
        Crl | Cgrl | Cghrl | Chrl | Clrl | Clgrl | Clghrl | Clhrl | Cgfrl | Clgfrl => {
            let a = k(b, pc.wrapping_add((imm32 << 1) as u64));
            let __h348 = b.get(amask_ref());

            let ea_v = b.and(a, __h348);
            let signed = !matches!(insn, Clrl | Clgrl | Clghrl | Clhrl | Clgfrl);
            let v = match insn {
                Cghrl | Clghrl => {
                    let __h349 = b.load::<W16>(ea_v, RD)?;
                    b.sext::<W16, W64>(__h349)
                }
                Chrl | Clhrl => {
                    let __h350 = b.load::<W16>(ea_v, RD)?;
                    b.sext::<W16, W64>(__h350)
                }
                Cgfrl | Clgfrl => {
                    if signed {
                        let __h351 = b.load::<W32>(ea_v, RD)?;

                        b.sext::<W32, W64>(__h351)
                    } else {
                        let __h352 = b.load::<W32>(ea_v, RD)?;

                        b.zext::<W32, W64>(__h352)
                    }
                }
                Crl | Clrl => {
                    let __h353 = b.load::<W32>(ea_v, RD)?;
                    b.zext::<W32, W64>(__h353)
                }
                _ => b.load::<W64>(ea_v, RD)?,
            };
            match insn {
                Crl | Chrl => {
                    let m = b.trunc::<W64, W32>(v);
                    cmp32(b, r, m, true)
                }
                Clrl | Clhrl => {
                    let m = b.trunc::<W64, W32>(v);
                    cmp32(b, r, m, false)
                }
                _ => cmp64(b, r, v, signed),
            }
        }
        _ => unimp(b, w),
    }
}

/// AGFI/AFI/ALGFI/ALFI/SLGFI/SLFI の共通処理。
fn arith64_or32<B: Backend>(
    b: &mut B,
    insn: crate::Insn,
    r: u8,
    imm: i64,
    sub: bool,
    signed_arith: bool,
) -> Flow<B> {
    use crate::Insn::*;
    let v = k(b, imm as u64);
    match insn {
        Agfi | Algfi | Slgfi => {
            if signed_arith {
                arith64(b, r, v, sub)
            } else {
                arith64l(b, r, v, sub)
            }
        }
        _ => {
            if signed_arith {
                let __h354 = b.trunc::<W64, W32>(v);

                arith32(b, r, __h354, sub)
            } else {
                let __h355 = b.trunc::<W64, W32>(v);

                arith32l(b, r, __h355, sub)
            }
        }
    }
}

/// C0 系の 32 ビット即値挿入/論理。対象は上位 32 または下位 32。
fn ril_imm<B: Backend>(b: &mut B, insn: crate::Insn, r: u8, imm: u64) -> Flow<B> {
    use crate::Insn::*;
    let (hi, op) = match insn {
        Iihf => (true, 0),
        Iilf => (false, 0),
        Nihf => (true, 1),
        Nilf => (false, 1),
        Oihf => (true, 2),
        Oilf => (false, 2),
        Llihf => (true, 3),
        Llilf => (false, 3),
        Xihf => (true, 4),
        _ => (false, 4), // Xilf
    };
    let sh = if hi { 32 } else { 0 };
    let __h356 = k(b, 0xffff_ffff);
    let __h357 = k(b, sh);

    let fmask = b.shl::<W64>(__h356, __h357);
    let __h358 = k(b, imm);
    let __h359 = k(b, sh);

    let fv = b.shl::<W64>(__h358, __h359);
    let old = g(b, r);
    let v = match op {
        0 | 3 => {
            // II/LLI は対象 32 ビットを置き換える（LLI は他を保持しない）。
            if op == 3 {
                fv
            } else {
                let __h361 = b.not(fmask);
                let __h360 = b.and(old, __h361);

                b.or(__h360, fv)
            }
        }
        1 => {
            let t = b.and(old, fmask);
            let __h363 = b.not(fmask);
            let __h362 = b.and(old, __h363);
            let __h364 = b.and(t, fv);

            b.or(__h362, __h364)
        }
        2 => {
            let t = b.and(old, fmask);
            let __h366 = b.not(fmask);
            let __h365 = b.and(old, __h366);
            let __h367 = b.or(t, fv);

            b.or(__h365, __h367)
        }
        _ => {
            let t = b.and(old, fmask);
            let __h369 = b.not(fmask);
            let __h368 = b.and(old, __h369);
            let __h370 = b.xor(t, fv);

            b.or(__h368, __h370)
        }
    };
    set_g(b, r, v);
    Ok(())
}

// ======================== SS 形式 ========================

/// SS 形式（l8 + b1d1 + b2d2）。`w` は 48 ビット。
pub fn ss<B: Backend>(b: &mut B, insn: crate::Insn, w: u64, _pc: u64) -> Flow<B> {
    use crate::Insn::*;
    // SS の長さフィールドは byte 1（l-1 なので 0 でも 1 バイト処理）。
    let l = (w >> 32) & 0xff;
    let a1 = ea(b, 0, b1_48(w), d1_48(w) as i64);
    let a2 = ea(b, 0, b2_48(w), d2_48(w) as i64);
    match insn {
        Mvc | Mvn | Mvz | Nc | Oc | Xc => {
            for i in 0..=l {
                let off = k(b, i);
                let __h371 = b.add(a2, off);

                let s = b.load::<W8>(__h371, RD)?;
                let d_addr = b.add(a1, off);
                let v = match insn {
                    Mvc | Mvn | Mvz => {
                        if insn == Mvn {
                            // MVN は数字部（下位ニブル）のみ運ぶ。
                            let d = b.zext::<W8, W64>(s);
                            let __h372 = b.load::<W8>(d_addr, RD)?;

                            let cur = b.zext::<W8, W64>(__h372);
                            let __h374 = k(b, 0xf0);
                            let __h373 = b.and(cur, __h374);
                            let __h376 = k(b, 0x0f);
                            let __h375 = b.and(d, __h376);

                            b.or(__h373, __h375)
                        } else if insn == Mvz {
                            let d = b.zext::<W8, W64>(s);
                            let __h377 = b.load::<W8>(d_addr, RD)?;

                            let cur = b.zext::<W8, W64>(__h377);
                            let __h379 = k(b, 0x0f);
                            let __h378 = b.and(cur, __h379);
                            let __h381 = k(b, 0xf0);
                            let __h380 = b.and(d, __h381);

                            b.or(__h378, __h380)
                        } else {
                            b.zext::<W8, W64>(s)
                        }
                    }
                    Nc => {
                        let __h382 = b.load::<W8>(d_addr, RD)?;

                        let dv = b.zext::<W8, W64>(__h382);
                        let __h383 = b.zext::<W8, W64>(s);

                        b.and(dv, __h383)
                    }
                    Oc => {
                        let __h384 = b.load::<W8>(d_addr, RD)?;

                        let dv = b.zext::<W8, W64>(__h384);
                        let __h385 = b.zext::<W8, W64>(s);

                        b.or(dv, __h385)
                    }
                    _ => {
                        let __h386 = b.load::<W8>(d_addr, RD)?;

                        let dv = b.zext::<W8, W64>(__h386);
                        let __h387 = b.zext::<W8, W64>(s);

                        b.xor(dv, __h387)
                    }
                };
                let __h388 = b.trunc::<W64, W8>(v);

                b.store::<W8>(d_addr, __h388, WR)?;
            }
            // NC/OC/XC は結果が全部ゼロかで CC。バイトを OR 畳み込みで検査する。
            if matches!(insn, Nc | Oc | Xc) {
                let mut acc = k(b, 0);
                for i in 0..=l {
                    let __h391 = k(b, i);
                    let __h390 = b.add(a1, __h391);
                    let __h389 = b.load::<W8>(__h390, RD)?;

                    let v = b.zext::<W8, W64>(__h389);
                    acc = b.or(acc, v);
                }
                let __h392 = k(b, 0);

                let is0 = b.cmp(Cmp::Eq, acc, __h392);
                let __h394 = k(b, 0);
                let __h395 = k(b, 1);

                let __h393 = b.select(is0, __h394, __h395);

                b.set(cc_ref(), __h393);
            }
            Ok(())
        }
        Clc => {
            for i in 0..=l {
                let off = k(b, i);
                let __h397 = b.add(a2, off);
                let __h396 = b.load::<W8>(__h397, RD)?;

                let s = b.zext::<W8, W64>(__h396);
                let __h399 = b.add(a1, off);
                let __h398 = b.load::<W8>(__h399, RD)?;

                let d = b.zext::<W8, W64>(__h398);
                let ne = b.cmp(Cmp::Ne, d, s);
                let mut hit = false;
                b.if_then_else(
                    ne,
                    |bb| {
                        hit = true;
                        let lt = bb.cmp(Cmp::LtU, d, s);
                        let __h401 = bb.konst::<W64>(1);
                        let __h402 = bb.konst::<W64>(2);

                        let __h400 = bb.select(lt, __h401, __h402);

                        bb.set(cc_ref(), __h400);
                        Ok(())
                    },
                    |_| Ok(()),
                )?;
                if hit {
                    return Ok(());
                }
            }
            set_cc(b, 0);
            Ok(())
        }
        Tr => {
            // TR: l+1 バイトを a2 の 256 バイト表で写像する。
            for i in 0..=l {
                let off = k(b, i);
                let __h404 = b.add(a1, off);
                let __h403 = b.load::<W8>(__h404, RD)?;

                let idx = b.zext::<W8, W64>(__h403);
                let __h405 = b.add(a2, idx);

                let tv = b.load::<W8>(__h405, RD)?;
                let __h406 = b.add(a1, off);

                b.store::<W8>(__h406, tv, WR)?;
            }
            Ok(())
        }
        Trt | Ed | Edmk => unimp(b, w >> 40), // 変換・編集は範囲外。
        // 10 進演算（SRP/MVO/PACK/UNPK/ZAP/CP/AP/SP/MP/DP）は範囲外（GAP）。
        _ => unimp(b, w >> 40),
    }
}

// ======================== MVST/CLST ========================

/// MVST（B255）: NUL までバイトコピー。r1=宛先、r2=元。CC1 で終了。
fn mvst<B: Backend>(b: &mut B, r: u8, x: u8, pc: u64) -> Flow<B> {
    let mut dst = g(b, r);
    let mut src = g(b, x);
    let mut hit = false;
    for _ in 0..CHUNK {
        if hit {
            break;
        }
        let byte = b.load::<W8>(src, RD)?;
        let zb = b.zext::<W8, W64>(byte);
        let __h407 = k(b, 0);

        let is0 = b.cmp(Cmp::Eq, zb, __h407);
        b.store::<W8>(dst, byte, WR)?;
        b.if_then_else(
            is0,
            |bb| {
                hit = true;
                let __h408 = bb.konst::<W64>(1);

                bb.set(cc_ref(), __h408);
                Ok(())
            },
            |_| Ok(()),
        )?;
        if hit {
            // 終端バイトを指したまま終了（呼び出し側が ' ' や '\n' で
            // 上書きする規約。PoP の MVST は最終格納位置を返す）。
            break;
        }
        let __h409 = k(b, 1);

        dst = b.add(dst, __h409);
        let __h410 = k(b, 1);

        src = b.add(src, __h410);
    }
    set_g(b, r, dst);
    set_g(b, x, src);
    if !hit {
        let __h411 = k(b, pc);

        b.jump(__h411);
    }
    Ok(())
}

/// CLST（B25D）: NUL までバイト比較。不一致で CC1/2、一致で CC0。
/// r1/r2 は最終比較位置に更新される。
fn clst<B: Backend>(b: &mut B, r: u8, x: u8, pc: u64) -> Flow<B> {
    let mut a = g(b, r);
    let mut c = g(b, x);
    let mut done = false;
    for _ in 0..CHUNK {
        if done {
            break;
        }
        let __h412 = b.load::<W8>(a, RD)?;

        let ab = b.zext::<W8, W64>(__h412);
        let __h413 = b.load::<W8>(c, RD)?;

        let cb = b.zext::<W8, W64>(__h413);
        let ne = b.cmp(Cmp::Ne, ab, cb);
        // ネストしたクロージャでの多重借用を避けるため、ゼロ一致の判定は
        // 別変数 `donez` に書く。
        let mut donez = false;
        b.if_then_else(
            ne,
            |bb| {
                done = true;
                let lt = bb.cmp(Cmp::LtU, ab, cb);
                let __h415 = bb.konst::<W64>(1);
                let __h416 = bb.konst::<W64>(2);

                let __h414 = bb.select(lt, __h415, __h416);

                bb.set(cc_ref(), __h414);
                Ok(())
            },
            |bb| {
                let __h417 = bb.konst::<W64>(0);

                let both0 = bb.cmp(Cmp::Eq, ab, __h417);
                bb.if_then_else(
                    both0,
                    |b2| {
                        donez = true;
                        let __h418 = b2.konst::<W64>(0);

                        b2.set(cc_ref(), __h418);
                        Ok(())
                    },
                    |_| Ok(()),
                )?;
                Ok(())
            },
        )?;
        done = done || donez;
        if done {
            break;
        }
        let __h419 = k(b, 1);

        a = b.add(a, __h419);
        let __h420 = k(b, 1);

        c = b.add(c, __h420);
    }
    set_g(b, r, a);
    set_g(b, x, c);
    if !done {
        let __h421 = k(b, pc);

        b.jump(__h421);
    }
    Ok(())
}

// ======================== S 形式（0xB2） ========================

/// 0xB2 系（S 形式 + 拡張 RRE）。byte1 が機能。
pub fn s_b2<B: Backend>(b: &mut B, w: u64, pc: u64) -> Flow<B> {
    let f = ((w >> 16) & 0xff) as u8;
    let r1f = ((w >> 4) & 0xf) as u8;
    let r2f = (w & 0xf) as u8;
    match f {
        0x05 | 0x78 | 0x7c => {
            // STCK/STCKE/STCKF: 時計をメモリへ。clk フィールドを単調に進める。
            let a = ea(b, 0, b2f(w), d2(w) as i64);
            let cur = b.get(clk_ref());
            let __h422 = k(b, 0x1000);

            let v = b.add(cur, __h422);
            b.set(clk_ref(), v);
            b.store::<W64>(a, v, WR)?;
            Ok(())
        }
        0x22 => {
            // IPM: CC と PM を r1 の bits 24-31 に挿入する。
            let cc = b.get(cc_ref());
            let pm = b.get(pm_ref());
            let __h424 = k(b, 4);
            let __h423 = b.shl::<W64>(cc, __h424);

            let field = b.or(__h423, pm);
            let old = g(b, r1f);
            let __h426 = k(b, 0xffff_ffff_00ff_ffff);
            let __h425 = b.and(old, __h426);
            let __h429 = k(b, 0xff);
            let __h428 = b.and(field, __h429);
            let __h430 = k(b, 24);

            let __h427 = b.shl::<W64>(__h428, __h430);

            let v = b.or(__h425, __h427);
            set_g(b, r1f, v);
            Ok(())
        }
        0x4e => {
            let __h432 = g(b, r2f);
            let __h431 = b.trunc::<W64, W32>(__h432);

            // SAR: ar[r1] = r2 の下位 32。
            let v = b.zext::<W32, W64>(__h431);
            b.set(Acr(r1f).state(), v);
            Ok(())
        }
        0x4f => {
            // EAR: r1 の下位 32 = ar[r2]。
            let v = b.get(Acr(r2f).state());
            let __h433 = b.trunc::<W64, W32>(v);

            set_g32(b, r1f, __h433);
            Ok(())
        }
        0x99 => {
            // SRNM: 丸めモードを d2(b2) の下位 2 ビットから FPC にセット。
            let a = ea(b, 0, b2f(w), d2(w) as i64);
            let cur = b.get(fpc_ref());
            let __h434 = k(b, 3);

            let rm = b.and(a, __h434);
            let __h437 = k(b, !3u64);
            let __h436 = b.and(cur, __h437);
            let __h435 = b.or(__h436, rm);

            b.set(fpc_ref(), __h435);
            Ok(())
        }
        0xb9 => unimp(b, 0xb2b9), // SRNMT（DFP 丸め）は範囲外。
        0x9c => {
            // STFPC: FPC をメモリへ。
            let a = ea(b, 0, b2f(w), d2(w) as i64);
            let v = b.get(fpc_ref());
            let __h438 = b.trunc::<W64, W32>(v);

            b.store::<W32>(a, __h438, WR)?;
            Ok(())
        }
        0x9d => {
            // LFPC: メモリから FPC へ。
            let a = ea(b, 0, b2f(w), d2(w) as i64);
            let __h439 = b.load::<W32>(a, RD)?;

            let v = b.zext::<W32, W64>(__h439);
            b.set(fpc_ref(), v);
            Ok(())
        }
        0x52 => {
            // MSR: 32×32 → 64 符号付き積。
            let __ha = g(b, r1f);
            let a32 = b.trunc::<W64, W32>(__ha);
            let av = b.sext::<W32, W64>(a32);
            let __hb = g(b, r2f);
            let b32 = b.trunc::<W64, W32>(__hb);
            let bv = b.sext::<W32, W64>(b32);
            let p = b.mul::<W64>(av, bv);
            set_g(b, r1f, p);
            Ok(())
        }
        0x55 => mvst(b, r1f, r2f, pc),
        0x5d => clst(b, r1f, r2f, pc),
        0x5e => {
            // SRST: r2 から始まるバイト列を走査し、r0 の bits 56-63 と
            // 一致するバイトを探す。発見 → r1=一致アドレス、r2=次アドレス、
            // CC1。CHUNK 打ち切り → 継続位置に更新して CC3（再実行）。
            let mut cur = g(b, r2f);
            let needle = {
                let __h434 = g(b, 0);
                let __h435 = k(b, 0xff);
                b.and(__h434, __h435)
            };
            let mut hit = false;
            for _ in 0..CHUNK {
                if hit {
                    break;
                }
                let byte = b.load::<W8>(cur, RD)?;
                let zb = b.zext::<W8, W64>(byte);
                let eq = b.cmp(Cmp::Eq, zb, needle);
                b.if_then_else(
                    eq,
                    |bb| {
                        hit = true;
                        let __h436 = bb.konst::<W64>(1);
                        bb.set(cc_ref(), __h436);
                        Ok(())
                    },
                    |_| Ok(()),
                )?;
                if hit {
                    // cur は一致バイトのアドレス。r1=cur、r2=cur+1。
                    set_g(b, r1f, cur);
                    let __h437 = k(b, 1);
                    let nx = b.add(cur, __h437);
                    set_g(b, r2f, nx);
                    return Ok(());
                }
                let __h438 = k(b, 1);
                cur = b.add(cur, __h438);
            }
            // 打ち切り: 継続位置に更新して CC3、命令を再実行。
            set_g(b, r1f, cur);
            set_g(b, r2f, cur);
            let __h439 = k(b, 3);
            b.set(cc_ref(), __h439);
            let __h440 = k(b, pc);
            b.jump(__h440);
            Ok(())
        }
        0x2d => {
            // DXR（HFP 拡張除算）は範囲外。
            unimp(b, 0xb22d)
        }
        _ => unimp(b, 0xb200 + u64::from(f)),
    }
}

// ======================== B9/B3（RRE/RRF） ========================

/// 0xB9 系の整数 RRE/RRF。byte1 が機能。
pub fn b9<B: Backend>(b: &mut B, w: u64, _pc: u64) -> Flow<B> {
    let f = ((w >> 16) & 0xff) as u8;
    let m3 = ((w >> 12) & 0xf) as u8;
    let r = ((w >> 4) & 0xf) as u8;
    let x = (w & 0xf) as u8;
    let v2 = g(b, x);
    match f {
        // 符号・テスト系。
        0x00 | 0x01 | 0x02 | 0x03 | 0x10 | 0x11 | 0x12 | 0x13 => {
            // 絶対値・負の絶対値は符号付き max/min として計算する。
            // `x | sign` では 0 が INT_MIN になる誤りが起きる
            // （LNGR(0) = 0 が正しい）。
            let v = if f >= 0x10 {
                // F 系は下位 32 ビットを符号付きで扱い、結果を符号拡張する。
                let x32 = b.trunc::<W64, W32>(v2);
                let z32 = b.konst::<W32>(0);
                let neg = b.sub(z32, x32);
                let lt = b.cmp(Cmp::LtS, x32, z32);
                let v32 = match f {
                    0x10 => b.select(lt, neg, x32),
                    0x11 => b.select(lt, x32, neg),
                    0x12 => x32,
                    _ => neg,
                };
                b.sext::<W32, W64>(v32)
            } else {
                let z = k(b, 0);
                let neg = b.sub(z, v2);
                let lt = b.cmp(Cmp::LtS, v2, z);
                match f {
                    0x00 => b.select(lt, neg, v2),
                    0x01 => b.select(lt, v2, neg),
                    0x02 => v2,
                    _ => neg,
                }
            };
            set_g(b, r, v);
            if matches!(f, 0x02 | 0x12) {
                cc_test(b, v);
            } else if matches!(f, 0x03 | 0x13) {
                let __h444 = k(
                    b,
                    if f == 0x13 {
                        0xffff_ffff_8000_0000
                    } else {
                        0x8000_0000_0000_0000
                    },
                );

                let min = b.cmp(Cmp::Eq, v, __h444);
                cc_signed(b, v, min);
            }
            Ok(())
        }
        // ロード系。
        0x04 | 0x14 => {
            // LGR / LGFR。
            let v = if f == 0x14 {
                let __h445 = b.trunc::<W64, W32>(v2);

                b.sext::<W32, W64>(__h445)
            } else {
                v2
            };
            set_g(b, r, v);
            Ok(())
        }
        0x06 | 0x07 | 0x26 | 0x27 | 0x16 | 0x17 | 0x84 | 0x85 | 0x94 | 0x95 => {
            // LGBR/LGHR/LBR/LHR/LLGFR/LLGTR/LLGCR/LLGHR/LLCR/LLHR。
            let (bits, sign) = match f {
                0x06 | 0x26 => (1, true),
                0x07 | 0x27 => (2, true),
                0x84 => (1, false),
                0x85 => (2, false),
                0x94 => (1, false),
                0x95 => (2, false),
                0x16 => (4, false),
                _ => (4, false),
            };
            let v = match (bits, sign) {
                (1, true) => {
                    let __h446 = b.trunc::<W64, W8>(v2);
                    b.sext::<W8, W64>(__h446)
                }
                (2, true) => {
                    let __h447 = b.trunc::<W64, W16>(v2);
                    b.sext::<W16, W64>(__h447)
                }
                (1, false) => {
                    let __h448 = b.trunc::<W64, W8>(v2);
                    b.zext::<W8, W64>(__h448)
                }
                (2, false) => {
                    let __h449 = b.trunc::<W64, W16>(v2);
                    b.zext::<W16, W64>(__h449)
                }
                (4, true) => {
                    let __h450 = b.trunc::<W64, W32>(v2);
                    b.sext::<W32, W64>(__h450)
                }
                _ => {
                    let __h451 = b.trunc::<W64, W32>(v2);
                    b.zext::<W32, W64>(__h451)
                }
            };
            if f == 0x17 {
                let __h453 = k(b, 0x7fff_ffff);
                let __h452 = b.and(v, __h453);

                // LLGTR は上位 31 ビットクリア。
                set_g(b, r, __h452);
            } else {
                set_g(b, r, v);
            }
            Ok(())
        }
        0x0f | 0x1f => {
            // LRVGR/LRVR: バイト反転ロード。
            let v = if f == 0x1f {
                let __h454 = b.trunc::<W64, W32>(v2);

                b.zext::<W32, W64>(__h454)
            } else {
                v2
            };
            let __h455 = bswap(b, v, if f == 0x1f { 4 } else { 8 });

            set_g(b, r, __h455);
            Ok(())
        }
        0x08 => arith64(b, r, v2, false),
        0x09 => arith64(b, r, v2, true),
        0x0a => arith64l(b, r, v2, false),
        0x0b => arith64l(b, r, v2, true),
        0x0c => {
            let __h457 = g(b, r);
            let __h456 = b.trunc::<W64, W32>(__h457);

            // MSGR。
            let a = b.sext::<W32, W64>(__h456);
            let __h458 = b.trunc::<W64, W32>(v2);

            let y = b.sext::<W32, W64>(__h458);
            let p = b.mul::<W64>(a, y);
            let __h460 = b.trunc::<W64, W32>(p);
            let __h459 = b.sext::<W32, W64>(__h460);

            set_g(b, r, __h459);
            Ok(())
        }
        0x0d => dsg_body(b, r, v2),
        0x1c => {
            let __h462 = g(b, r);
            let __h461 = b.trunc::<W64, W32>(__h462);

            // MSGFR。
            let a = b.sext::<W32, W64>(__h461);
            let __h463 = b.trunc::<W64, W32>(v2);

            let y = b.sext::<W32, W64>(__h463);
            let p = b.mul::<W64>(a, y);
            let __h465 = b.trunc::<W64, W32>(p);
            let __h464 = b.sext::<W32, W64>(__h465);

            set_g(b, r, __h464);
            Ok(())
        }
        0x1d => {
            // DSGFR: ペアの下位 64/32。
            if r & 1 != 0 {
                return unimp(b, 0x5ec1);
            }
            let dvd = g(b, r + 1);
            let __h466 = b.trunc::<W64, W32>(v2);

            let dvs = b.sext::<W32, W64>(__h466);
            div_step(b, r, dvd, dvs, false)
        }
        0x88 | 0x89 => {
            // ALCGR/SLBGR: 論理加減算＋直前 CC のキャリー/ボロー伝搬。
            let cc = b.get(cc_ref());
            let __hc = k(b, 2);
            let cin = b.cmp(Cmp::GeU, cc, __hc);
            let a0 = g(b, r);
            let m2 = if f == 0x88 { v2 } else { b.not(v2) };
            let (v, c, _o) = b.add_with_carry(a0, m2, cin);
            set_g(b, r, v);
            cc_logical(b, v, c);
            Ok(())
        }
        0x18..=0x1b => {
            // AGFR/SGFR/ALGFR/SLGFR: 32 ビット符号拡張して 64 ビット演算。
            let __h4 = b.trunc::<W64, W32>(v2);
            let x32 = b.sext::<W32, W64>(__h4);
            if matches!(f, 0x1a | 0x1b) {
                arith64l(b, r, x32, f == 0x1b)
            } else {
                arith64(b, r, x32, f == 0x19)
            }
        }
        0x20 | 0x21 => cmp64(b, r, v2, f == 0x20),
        0x30 | 0x31 => {
            let y = b.trunc::<W64, W32>(v2);
            if f == 0x30 {
                cmp32(b, r, y, true)
            } else {
                cmp32(b, r, y, false)
            }
        }
        0x60 | 0x61 | 0x72 | 0x73 => {
            // CGRT/CLGRT/CRT/CLRT: 条件コードが m3 に合えば trap（ユーザーモード
            // では条件が合わない限り no-op）。
            let c = btaken(b, m3);
            b.if_then_else(
                c,
                |bb| {
                    Err(bb.raise(GuestException {
                        kind: ExceptionKind::Trap,
                        code: 0xb900 + u64::from(f),
                        addr: None,
                        in_delay_slot: false,
                    }))
                },
                |_| Ok(()),
            )
        }
        0x80 => log64(b, r, v2, 0),
        0x81 => log64(b, r, v2, 1),
        0x82 => log64(b, r, v2, 2),
        0x83 => {
            // FLOGR: r（偶数ペア）= 元のままのレジスタ、r+1 = 先頭 1 ビット位置。
            if r & 1 != 0 {
                return unimp(b, 0x5ec1);
            }
            let __h467 = k(b, 0);

            // ゼロなら位置 64、CC0。
            let is0 = b.cmp(Cmp::Eq, v2, __h467);
            let mut bit = k(b, 0);
            for i in 0..64 {
                let __h469 = k(b, 63 - i);
                let __h468 = b.shr_l::<W64>(v2, __h469);
                let __h470 = k(b, 1);

                let top = b.and(__h468, __h470);
                let __h471 = k(b, 0);

                let one = b.cmp(Cmp::Ne, top, __h471);
                let __h472 = k(b, 0);

                let cur = b.cmp(Cmp::Eq, bit, __h472);
                let upd = band(b, one, cur);
                let __h473 = k(b, i);

                bit = b.select(upd, __h473, bit);
            }
            let __h474 = k(b, 64);

            let idx = b.select(is0, __h474, bit);
            set_g(b, r, v2);
            set_g(b, r + 1, idx);
            let __h475 = k(b, 0);

            let _ = b.cmp(Cmp::Eq, v2, __h475);
            let __h477 = k(b, 0);
            let __h478 = k(b, 2);

            let __h476 = b.select(is0, __h477, __h478);

            b.set(cc_ref(), __h476);
            Ok(())
        }
        0x86 | 0x87 | 0x96 | 0x97 => {
            // MLGR/DLGR/MLR/DLR。
            if r & 1 != 0 {
                return unimp(b, 0x5ec1);
            }
            match f {
                0x86 => {
                    let __h479 = g(b, r + 1);

                    // MLGR: 64×64 → 128。
                    let hi = b.mulhu::<W64>(__h479, v2);
                    let __h480 = g(b, r + 1);

                    let lo = b.mul::<W64>(__h480, v2);
                    set_g(b, r, hi);
                    set_g(b, r + 1, lo);
                    Ok(())
                }
                0x96 => {
                    let __h482 = g(b, r + 1);
                    let __h481 = b.trunc::<W64, W32>(__h482);

                    // MLR: 32×32 → 64。
                    let a = b.zext::<W32, W64>(__h481);
                    let __h483 = b.trunc::<W64, W32>(v2);

                    let y = b.zext::<W32, W64>(__h483);
                    let p = b.mul::<W64>(a, y);
                    set_g(b, r + 1, p);
                    let __h486 = k(b, 32);
                    let __h485 = b.shr_l::<W64>(p, __h486);
                    let __h484 = b.trunc::<W64, W32>(__h485);

                    set_g32(b, r, __h484);
                    Ok(())
                }
                0x87 => {
                    // DLGR: 128 / 64 → 商 r+1、余り r。
                    let (hi, lo) = (g(b, r), g(b, r + 1));
                    let __h487 = k(b, 0);

                    let dz = b.cmp(Cmp::Eq, v2, __h487);
                    b.if_then_else(
                        dz,
                        |bb| {
                            Err(bb.raise(GuestException {
                                kind: ExceptionKind::DivZero,
                                code: 0xb987,
                                addr: None,
                                in_delay_slot: false,
                            }))
                        },
                        |bb| {
                            let __h488 = bb.konst::<W64>(0);

                            // 128/64 除算の近似: hi==0 なら 64/64、hi!=0 は未対応。
                            let h0 = bb.cmp(Cmp::Eq, hi, __h488);
                            bb.if_then_else(
                                h0,
                                |b2| {
                                    let q = b2.udiv::<W64>(lo, v2);
                                    let rm = b2.urem::<W64>(lo, v2);
                                    b2.set(Gpr(r + 1).state(), q);
                                    b2.set(Gpr(r).state(), rm);
                                    Ok(())
                                },
                                |b2| {
                                    // 逐次引き算で 64 回回す。
                                    let mut rem = lo;
                                    let mut hi_r = hi;
                                    for i in 0..64 {
                                        let __h489 = b2.konst::<W64>(63);

                                        let msb = b2.shr_l::<W64>(hi_r, __h489);
                                        let __h491 = b2.konst::<W64>(1);
                                        let __h490 = b2.shl::<W64>(hi_r, __h491);
                                        let __h493 = b2.konst::<W64>(63);
                                        let __h492 = b2.shr_l::<W64>(rem, __h493);

                                        hi_r = b2.or(__h490, __h492);
                                        let __h494 = b2.konst::<W64>(1);

                                        rem = b2.shl::<W64>(rem, __h494);
                                        let ge = b2.cmp(Cmp::GeU, hi_r, v2);
                                        let __h495 = b2.sub(hi_r, v2);

                                        hi_r = b2.select(ge, __h495, hi_r);
                                        let __h497 = b2.konst::<W64>(1);
                                        let __h498 = b2.konst::<W64>(0);

                                        let __h496 = b2.select(ge, __h497, __h498);

                                        rem = b2.or(rem, __h496);
                                        let _ = msb;
                                        let _ = i;
                                    }
                                    b2.set(Gpr(r + 1).state(), rem);
                                    b2.set(Gpr(r).state(), hi_r);
                                    Ok(())
                                },
                            )
                        },
                    )
                }
                _ => {
                    let __h502 = g(b, r);
                    let __h501 = b.trunc::<W64, W32>(__h502);
                    let __h500 = b.zext::<W32, W64>(__h501);
                    let __h503 = k(b, 32);

                    let __h499 = b.shl::<W64>(__h500, __h503);
                    let __h506 = g(b, r + 1);
                    let __h505 = b.trunc::<W64, W32>(__h506);
                    let __h504 = b.zext::<W32, W64>(__h505);

                    // DLR: ペア下位 64/32。
                    let dvd = b.or(__h499, __h504);
                    let __h507 = b.trunc::<W64, W32>(v2);

                    let dvs = b.zext::<W32, W64>(__h507);
                    div_step(b, r, dvd, dvs, true)
                }
            }
        }
        0xe1 => {
            // POPCNT: 各バイトの 1 ビット数を各バイトに書く。
            let mut acc = k(b, 0);
            for i in 0..8 {
                let __h509 = k(b, i * 8);
                let __h508 = b.shr_l::<W64>(v2, __h509);
                let __h510 = k(b, 0xff);

                let byte = b.and(__h508, __h510);
                let mut cnt = k(b, 0);
                for j in 0..8 {
                    let __h512 = k(b, j);
                    let __h511 = b.shr_l::<W64>(byte, __h512);
                    let __h513 = k(b, 1);

                    let one = b.and(__h511, __h513);
                    cnt = b.add(cnt, one);
                }
                let __h515 = k(b, i * 8);
                let __h514 = b.shl::<W64>(cnt, __h515);

                acc = b.or(acc, __h514);
            }
            set_g(b, r, acc);
            Ok(())
        }
        _ => unimp(b, 0xb900 + u64::from(f)),
    }
}

/// バイト反転。`bytes` 分だけ見る。
fn bswap<B: Backend>(b: &mut B, v: B::V<W64>, bytes: u64) -> B::V<W64> {
    let mut acc = k(b, 0);
    for i in 0..bytes {
        let __h517 = k(b, i * 8);
        let __h516 = b.shr_l::<W64>(v, __h517);
        let __h518 = k(b, 0xff);

        let byte = b.and(__h516, __h518);
        let __h520 = k(b, (bytes - 1 - i) * 8);
        let __h519 = b.shl::<W64>(byte, __h520);

        acc = b.or(acc, __h519);
    }
    acc
}

/// DSG（64÷64）の共通処理。
fn dsg_body<B: Backend>(b: &mut B, r: u8, dvs: B::V<W64>) -> Flow<B> {
    if r & 1 != 0 {
        return unimp(b, 0x5ec1);
    }
    let dvd = g(b, r + 1);
    div_step(b, r, dvd, dvs, false)
}

/// 除算ステップ。商→r+1、余り→r（DSG は 64、DLR は 32）。
fn div_step<B: Backend>(b: &mut B, r: u8, dvd: B::V<W64>, dvs: B::V<W64>, narrow: bool) -> Flow<B> {
    let __h521 = k(b, 0);

    let dz = b.cmp(Cmp::Eq, dvs, __h521);
    b.if_then_else(
        dz,
        |bb| {
            Err(bb.raise(GuestException {
                kind: ExceptionKind::DivZero,
                code: 0xd500,
                addr: None,
                in_delay_slot: false,
            }))
        },
        |bb| {
            let q = bb.sdiv::<W64>(dvd, dvs);
            let rm = bb.srem::<W64>(dvd, dvs);
            if narrow {
                let keep = bb.konst::<W64>(0xffff_ffff_0000_0000);
                let __h524 = g(bb, r + 1);
                let __h523 = bb.and(__h524, keep);
                let __h527 = bb.trunc::<W64, W32>(q);
                let __h526 = bb.sext::<W32, W64>(__h527);
                let __h528 = bb.konst::<W64>(0xffff_ffff);

                let __h525 = bb.and(__h526, __h528);

                let __h522 = bb.or(__h523, __h525);

                bb.set(Gpr(r + 1).state(), __h522);
                let __h531 = g(bb, r);
                let __h530 = bb.and(__h531, keep);
                let __h534 = bb.trunc::<W64, W32>(rm);
                let __h533 = bb.sext::<W32, W64>(__h534);
                let __h535 = bb.konst::<W64>(0xffff_ffff);

                let __h532 = bb.and(__h533, __h535);

                let __h529 = bb.or(__h530, __h532);

                bb.set(Gpr(r).state(), __h529);
            } else {
                bb.set(Gpr(r + 1).state(), q);
                bb.set(Gpr(r).state(), rm);
            }
            Ok(())
        },
    )
}

// ======================== B3（BFP RRE/RRF） ========================

/// 0xB3 系の BFP（2 値・3 値・変換・テスト）。byte1 が機能。
/// レイアウト: `B3 func | m3 または // | r1 r2`（RRF は r3 が byte3 下位）。
/// fp128（拡張）系は f64 近似で、片方のレジスタだけを読み書きする（GAP）。
pub fn b3<B: Backend>(b: &mut B, w: u64, _pc: u64) -> Flow<B> {
    let f = ((w >> 16) & 0xff) as u8;
    let m3 = ((w >> 12) & 0xf) as u8;
    let r1 = ((w >> 4) & 0xf) as u8;
    let r2 = (w & 0xf) as u8;
    let fr = |i: u8| Fpr(i & 15).state();
    let fg = |b: &mut B, i: u8| b.get(fr(i));
    match f {
        // 非負/負/テスト/反転（短・長・拡張）。
        0x00 | 0x01 | 0x02 | 0x03 | 0x10 | 0x11 | 0x12 | 0x13 | 0x40 | 0x41 | 0x42 | 0x43 => {
            let short = f < 0x10;
            let v = fg(b, r2);
            let sign = k(b, 0x8000_0000_0000_0000);
            let out = match f & 0x0f {
                0 => {
                    let __h536 = b.not(sign);
                    b.and(v, __h536)
                }
                1 => b.or(v, sign),
                3 => b.xor(v, sign),
                _ => v,
            };
            let out = if short {
                let __h537 = k(b, 0xffff_ffff_0000_0000);

                b.and(out, __h537)
            } else {
                out
            };
            b.set(fr(r1), out);
            if matches!(f, 0x02 | 0x12 | 0x42) {
                fp_test_cc(b, out, short);
            }
            Ok(())
        }
        // 変換: LDEBR(f32→f64) / LEXBR(f32→拡張 f64 近似) / LDXBR(f64→拡張) /
        // LDBR / LEBR / LXBR（コピー/丸め）。
        0x04 => {
            let v = fg(b, r2);
            let __h540 = k(b, 32);
            let __h539 = b.shr_l::<W64>(v, __h540);
            let __h538 = b.trunc::<W64, W32>(__h539);

            let d = b.fcvt_ff::<W32, W64>(__h538, 0);
            b.set(fr(r1), d);
            Ok(())
        }
        0x05 | 0x06 | 0x45 | 0x46 => {
            // LEXBR/LDXBR/LEDBR 等: 拡張宛ても f64 近似。
            let v = fg(b, r2);
            b.set(fr(r1), v);
            let __h541 = k(b, 0);

            b.set(fr((r1 + 2) & 15), __h541);
            Ok(())
        }
        0x07 => {
            // MXDBR: f32 → f64。
            let v = fg(b, r2);
            let __h544 = k(b, 32);
            let __h543 = b.shr_l::<W64>(v, __h544);
            let __h542 = b.trunc::<W64, W32>(__h543);

            let d = b.fcvt_ff::<W32, W64>(__h542, 0);
            b.set(fr(r1), d);
            Ok(())
        }
        // 2 値演算。0x0e/0x0f/0x1e/0x1f は RRF-a の MAE/MAD/MSE/MSD で別途処理。
        0x08..=0x0d | 0x14 | 0x15 | 0x17 | 0x18..=0x1d | 0x48..=0x4d => fp_bin(b, f, r1, r2),
        0x16 => {
            // SQXBR: 拡張平方根は f64 近似。
            let v = fg(b, r2);
            let __h545 = b.fsqrt::<W64>(v);

            b.set(fr(r1), __h545);
            Ok(())
        }
        // 3 値演算（RRF-a: byte2 上位 nibble が r1、byte3 上位が r2、下位が r3）。
        // MAEBR/MADBR: f1 = f3*f2 + f1、MSEBR/MSDBR: f1 = f3*f2 - f1。
        // フィールド配置は 2 値 RRE と異なる: `B3 ff | r1 0 | r2 r3`。
        0x0e | 0x1e | 0x0f | 0x1f => {
            let (dr, mr2, r3) = (m3, r1, r2);
            let short = matches!(f, 0x0e | 0x0f);
            let a64 = fg64(b, r3, short);
            let y64 = fg64(b, mr2, short);
            let acc = fg64(b, dr, short);
            let addend = if matches!(f, 0x0f | 0x1f) {
                let __hs = k(b, 0x8000_0000_0000_0000);
                b.xor(acc, __hs)
            } else {
                acc
            };
            let d = b.fmadd::<W64>(a64, y64, addend);
            put_f(b, dr, d, short);
            Ok(())
        }
        // GPR → FP（cdfbr 等）と FP → GPR（cfdbr 等）。
        0x94 | 0x95 | 0xa4 | 0xa5 => {
            // CEFBR/CDFBR/CEGBR/CDGBR: r2(GPR)→ f1。
            let v = g(b, r2);
            let v32 = b.trunc::<W64, W32>(v);
            let d = if f == 0x94 || f == 0xa4 {
                // E 形式（f32）: 32/64 ビット入力を f32 化して上位に置く。
                let t = if f == 0x94 {
                    b.fcvt_from_s32::<W32>(v32, 0)
                } else {
                    b.fcvt_from_s64::<W32>(v, 0)
                };
                let __h558 = b.zext::<W32, W64>(t);
                let __h559 = k(b, 32);

                b.shl::<W64>(__h558, __h559)
            } else {
                if f == 0x95 {
                    b.fcvt_from_s32::<W64>(v32, 0)
                } else {
                    b.fcvt_from_s64::<W64>(v, 0)
                }
            };
            b.set(fr(r1), d);
            Ok(())
        }
        0xcd | 0xc1 => {
            // LGDR(0xcd): r1 = f2 のビット / LDGR(0xc1): f1 = r2 のビット。
            if f == 0xcd {
                let v = fg(b, r2);
                set_g(b, r1, v);
            } else {
                let v = g(b, r2);
                b.set(fr(r1), v);
            }
            Ok(())
        }
        0x96 | 0xa6 => {
            // CXFBR/CXGBR: 拡張宛ても f64 近似。
            let v = g(b, r2);
            let t = if f == 0x96 {
                let __h560 = b.trunc::<W64, W32>(v);

                b.fcvt_from_s32::<W64>(__h560, 0)
            } else {
                b.fcvt_from_s64::<W64>(v, 0)
            };
            b.set(fr(r1), t);
            let __h561 = k(b, 0);

            b.set(fr((r1 + 2) & 15), __h561);
            Ok(())
        }
        0x98 | 0x99 | 0xa8 | 0xa9 | 0x9a | 0xaa => {
            // CFEBR/CFDBR/CGEBR/CGDBR/CFXBR/CGXBR: f2 → r1。m3 が丸め。
            let src = fg(b, r2);
            let d = if matches!(f, 0x99 | 0xa9 | 0x9a | 0xaa) {
                src
            } else {
                let __h563 = k(b, 32);
                let __h562 = b.shr_l::<W64>(src, __h563);

                // f32 → f64 正規化してから整数化。
                let s = b.trunc::<W64, W32>(__h562);
                b.fcvt_ff::<W32, W64>(s, 0)
            };
            let long = matches!(f, 0xa8..=0xaa);
            if long {
                let v = b.fcvt_s64::<W64>(d, m3_to_rm(m3));
                set_g(b, r1, v);
            } else {
                let v = b.fcvt_s32::<W64>(d, m3_to_rm(m3));
                set_g32(b, r1, v);
            }
            set_cc(b, 0);
            Ok(())
        }
        0x47 | 0x57 | 0x5f => {
            // FIXBR/FIEBR/FIDBR: 整数部に丸める（m3 が丸めモード）。
            let v = fg(b, r2);
            let i = b.fcvt_s64::<W64>(v, m3_to_rm(m3));
            let d = b.fcvt_from_s64::<W64>(i, 0);
            if f == 0x57 {
                let s = b.fcvt_ff::<W64, W32>(d, 0);
                let __h565 = b.zext::<W32, W64>(s);
                let __h566 = k(b, 32);

                let __h564 = b.shl::<W64>(__h565, __h566);

                b.set(fr(r1), __h564);
            } else {
                b.set(fr(r1), d);
            }
            Ok(())
        }
        0x50 | 0x51 => {
            // TBEDR/TBDR: HFP→BFP 変換は範囲外。
            unimp(b, 0xb300 + u64::from(f))
        }
        0x53 | 0x5b => {
            // DIEBR/DIDBR: 商と余りの同時計算。byte2 = r2|m4、byte3 = r1|r3。
            let r3 = (w & 0xf) as u8;
            let r2i = ((w >> 12) & 0xf) as u8;
            let n = fg(b, r2i);
            let dv = fg(b, r3);
            let q = b.fdiv::<W64>(n, dv);
            // PoP: 商は 0 方向への丸め。
            let qi = b.fcvt_s64::<W64>(q, 1);
            let qf = b.fcvt_from_s64::<W64>(qi, 0);
            let __h567 = b.fmul::<W64>(qf, dv);

            let rem = b.fsub::<W64>(n, __h567);
            b.set(fr(r1), qf);
            b.set(fr(r3), rem);
            Ok(())
        }
        0x62 | 0x69 => {
            // LTXR/CXR（HFP）は範囲外。
            unimp(b, 0xb300 + u64::from(f))
        }
        0x84 => {
            let __h568 = g(b, r1);

            // SFPC: FPC = r1 下位 32。
            let v = b.trunc::<W64, W32>(__h568);
            let __h569 = b.zext::<W32, W64>(v);

            b.set(fpc_ref(), __h569);
            Ok(())
        }
        0x8c => {
            // EFPC: r1 下位 32 = FPC。
            let v = b.get(fpc_ref());
            let __h570 = b.trunc::<W64, W32>(v);

            set_g32(b, r1, __h570);
            Ok(())
        }
        _ => unimp(b, 0xb300 + u64::from(f)),
    }
}

/// s390 の M3 丸めモードを softfloat Rm へ写す。
/// s390: 0=FPC 指定, 1=RNA, 4=RNE, 5=RTZ, 6=RUP(+∞), 7=RDN(-∞)。
/// softfloat: 0=Rne, 1=Rtz, 2=Rdn, 3=Rup, 4=Rmm。
// Ref: SPEC-S390-ZARCH-POP — 変換系命令の丸めモード指定子。
fn m3_to_rm(m3: u8) -> u8 {
    match m3 & 7 {
        1 => 4, // RNA（最遠方向）→ Rmm
        4 => 0, // RNE → Rne
        5 => 1, // RTZ → Rtz
        6 => 3, // +∞ → Rup
        7 => 2, // -∞ → Rdn
        // 0（FPC 現行）と未規定値は既定の最近接偶数に倒す。
        _ => 0,
    }
}

/// LPTE/LTC 系のテスト CC（0/負/正）。近似はビット符号。
fn fp_test_cc<B: Backend>(b: &mut B, v: B::V<W64>, _short: bool) {
    let sign = k(b, 0x8000_0000_0000_0000);
    let __h571 = b.and(v, sign);
    let __h572 = k(b, 0);

    let neg = b.cmp(Cmp::Ne, __h571, __h572);
    let __h574 = b.not(sign);
    let __h573 = b.and(v, __h574);
    let __h575 = k(b, 0);

    let is0 = b.cmp(Cmp::Eq, __h573, __h575);
    let __h577 = k(b, 0);
    let __h579 = k(b, 1);
    let __h580 = k(b, 2);

    let __h578 = b.select(neg, __h579, __h580);

    let __h576 = b.select(is0, __h577, __h578);

    b.set(cc_ref(), __h576);
}

/// 2 値 BFP 演算。f32/f64 を選び、結果はレジスタの対応する半分に置く。
fn fp_bin<B: Backend>(b: &mut B, f: u8, r1: u8, r2: u8) -> Flow<B> {
    let _fr = |i: u8| Fpr(i & 15).state();
    // 拡張（0x48-0x4d）も f64 近似。
    let short = matches!(f, 0x08..=0x0f | 0x14 | 0x17);
    let a64 = fg64(b, r1, short);
    let y64 = fg64(b, r2, short);
    let (d, cc_v) = match f & 0x0f {
        0x8 => {
            // 比較（KEB/KDB/KXB）。
            let eq = b.feq::<W64>(a64, y64);
            let lt = b.flt::<W64>(a64, y64);
            let __h581 = k(b, 0);
            let __h583 = k(b, 1);
            let __h584 = k(b, 2);

            let __h582 = b.select(lt, __h583, __h584);

            let cc = b.select(eq, __h581, __h582);
            b.set(cc_ref(), cc);
            return Ok(());
        }
        0x9 => {
            let eq = b.feq::<W64>(a64, y64);
            let lt = b.flt::<W64>(a64, y64);
            let __h585 = k(b, 0);
            let __h587 = k(b, 1);
            let __h588 = k(b, 2);

            let __h586 = b.select(lt, __h587, __h588);

            let cc = b.select(eq, __h585, __h586);
            b.set(cc_ref(), cc);
            return Ok(());
        }
        0xa => (b.fadd::<W64>(a64, y64), 0),
        0xb => (b.fsub::<W64>(a64, y64), 0),
        0xc | 0x7 => (b.fmul::<W64>(a64, y64), 0),
        0xd => (b.fdiv::<W64>(a64, y64), 0),
        0x4 => (b.fsqrt::<W64>(y64), 0),
        0x5 => (b.fsqrt::<W64>(y64), 0),
        _ => return unimp(b, 0xb300 + u64::from(f)),
    };
    let _ = cc_v;
    put_f(b, r1, d, short);
    Ok(())
}

fn fg64<B: Backend>(b: &mut B, i: u8, short: bool) -> B::V<W64> {
    let v = b.get(Fpr(i & 15).state());
    if short {
        let __h590 = k(b, 32);
        let __h589 = b.shr_l::<W64>(v, __h590);

        let s = b.trunc::<W64, W32>(__h589);
        b.fcvt_ff::<W32, W64>(s, 0)
    } else {
        v
    }
}

fn put_f<B: Backend>(b: &mut B, i: u8, d: B::V<W64>, short: bool) {
    if short {
        let s = b.fcvt_ff::<W64, W32>(d, 0);
        let cur = b.get(Fpr(i & 15).state());
        let __h592 = b.zext::<W32, W64>(s);
        let __h593 = k(b, 32);

        let __h591 = b.shl::<W64>(__h592, __h593);
        let __h595 = k(b, 0xffff_ffff);
        let __h594 = b.and(cur, __h595);

        let nv = b.or(__h591, __h594);
        b.set(Fpr(i & 15).state(), nv);
    } else {
        b.set(Fpr(i & 15).state(), d);
    }
}

// ======================== E3/EB/EC/ED/E5 ========================

/// RXY 形式（0xE3）。func が下位バイト。
pub fn e3<B: Backend>(b: &mut B, w: u64, _pc: u64) -> Flow<B> {
    let f = func(w);
    let r = r1_48(w);
    let x2 = f3_48(w);
    let b2 = ((w >> 28) & 0xf) as u8;
    let a = ea(b, x2, b2, disp20(w));
    match f {
        // ロード。
        0x04 | 0x14 | 0x15 | 0x77 | 0x76 | 0x16 | 0x17 | 0x90 | 0x91 | 0x94 | 0x95 | 0x58
        | 0x78 | 0x1e | 0x1f | 0x0f | 0x02 | 0x12 | 0x06 | 0x26 => {
            let (bytes, sign, g64) = match f {
                0x04 => (8, false, true),  // LG
                0x14 => (4, true, true),   // LGF
                0x15 => (2, true, true),   // LGH
                0x77 => (1, true, true),   // LGB
                0x76 => (1, true, false),  // LB
                0x16 => (4, false, true),  // LLGF
                0x17 => (4, false, true),  // LLGT
                0x90 => (1, false, true),  // LLGC
                0x91 => (2, false, true),  // LLGH
                0x94 => (1, false, false), // LLC
                0x95 => (2, false, false), // LLH
                0x58 => (4, false, false), // LY
                0x78 => (2, true, false),  // LHY
                0x1e => (4, false, false), // LRV
                0x1f => (2, false, false), // LRVH
                0x0f => (8, false, true),  // LRVG
                0x02 => (8, false, true),  // LTG
                0x12 => (4, false, false), // LT
                0x06 => (4, false, false), // CVBY
                _ => (8, false, true),     // CVDY は別扱い
            };
            match f {
                0x1e => {
                    let __h596 = b.load::<W32>(a, RD)?;

                    let v = b.zext::<W32, W64>(__h596);
                    let __h597 = bswap(b, v, 4);

                    set_g(b, r, __h597);
                    return Ok(());
                }
                0x1f => {
                    let __h598 = b.load::<W16>(a, RD)?;

                    let v = b.zext::<W16, W64>(__h598);
                    let __h599 = bswap(b, v, 2);

                    set_g(b, r, __h599);
                    return Ok(());
                }
                0x0f => {
                    let v = b.load::<W64>(a, RD)?;
                    let __h600 = bswap(b, v, 8);

                    set_g(b, r, __h600);
                    return Ok(());
                }
                0x06 | 0x0e | 0x26 | 0x2e => {
                    // CVB/CVD の Y 形式は 10 進変換で範囲外。
                    return unimp(b, 0xe300 + u64::from(f));
                }
                _ => {}
            }
            let v = ldx(b, a, bytes, sign)?;
            let v = if f == 0x17 {
                let __h601 = k(b, 0x7fff_ffff);

                b.and(v, __h601)
            } else {
                v
            };
            if g64 {
                set_g(b, r, v);
            } else {
                let __h602 = b.trunc::<W64, W32>(v);

                set_g32(b, r, __h602);
            }
            if f == 0x02 || f == 0x12 {
                cc_test(b, v);
            }
            Ok(())
        }
        // ストア。
        0x24 | 0x50 | 0x70 | 0x72 | 0x2f | 0x3e | 0x3f => {
            let bytes = match f {
                0x24 => 8, // STG
                0x50 => 4, // STY
                0x70 => 2, // STHY
                0x72 => 1, // STCY
                0x2f => 8, // STRVG
                0x3e => 4, // STRV
                _ => 2,    // STRVH
            };
            let v = g(b, r);
            match f {
                0x2f => {
                    let __h603 = bswap(b, v, 8);

                    b.store::<W64>(a, __h603, WR)?;
                }
                0x3e => {
                    let __h605 = bswap(b, v, 4);
                    let __h604 = b.trunc::<W64, W32>(__h605);

                    b.store::<W32>(a, __h604, WR)?;
                }
                0x3f => {
                    let __h607 = bswap(b, v, 2);
                    let __h606 = b.trunc::<W64, W16>(__h607);

                    b.store::<W16>(a, __h606, WR)?;
                }
                _ => {
                    store_r(b, r, a, bytes)?;
                    return Ok(());
                }
            }
            Ok(())
        }
        0x73 => {
            let __h608 = b.load::<W8>(a, RD)?;

            // ICY。
            let v = b.zext::<W8, W64>(__h608);
            let __h609 = b.trunc::<W64, W32>(v);

            set_g32(b, r, __h609);
            Ok(())
        }
        0x71 => {
            // LAY。
            set_g(b, r, a);
            Ok(())
        }
        // 算術。
        0x08 | 0x09 | 0x0a | 0x0b | 0x18 | 0x19 | 0x1a | 0x1b => {
            let m = match f {
                0x08..=0x0b => b.load::<W64>(a, RD)?,
                _ => {
                    let __h610 = b.load::<W32>(a, RD)?;
                    b.sext::<W32, W64>(__h610)
                }
            };
            let sub = matches!(f, 0x09 | 0x19);
            let logical = matches!(f, 0x0a | 0x0b | 0x1a | 0x1b);
            if matches!(f, 0x18..=0x1b) {
                let x32 = b.trunc::<W64, W32>(m);
                if logical {
                    arith32l(b, r, x32, sub)
                } else {
                    arith32(b, r, x32, sub)
                }
            } else if logical {
                arith64l(b, r, m, sub)
            } else {
                arith64(b, r, m, sub)
            }
        }
        0x0c | 0x1c => {
            // MSG/MSGF。
            let m = if f == 0x0c {
                b.load::<W64>(a, RD)?
            } else {
                let __h611 = b.load::<W32>(a, RD)?;

                b.sext::<W32, W64>(__h611)
            };
            let v = g(b, r);
            let __h612 = b.mul::<W64>(v, m);

            set_g(b, r, __h612);
            Ok(())
        }
        0x0d => {
            // DSG。
            let m = b.load::<W64>(a, RD)?;
            dsg_body(b, r, m)
        }
        0x1d => {
            // DSGF。
            if r & 1 != 0 {
                return unimp(b, 0x5ec1);
            }
            let __h613 = b.load::<W32>(a, RD)?;

            let m = b.sext::<W32, W64>(__h613);
            let dvd = g(b, r + 1);
            div_step(b, r, dvd, m, false)
        }
        0x86 => {
            // MLG: 64×64 → 128。
            if r & 1 != 0 {
                return unimp(b, 0x5ec1);
            }
            let m = b.load::<W64>(a, RD)?;
            let __h614 = g(b, r + 1);

            let hi = b.mulhu::<W64>(__h614, m);
            let __h615 = g(b, r + 1);

            let lo = b.mul::<W64>(__h615, m);
            set_g(b, r, hi);
            set_g(b, r + 1, lo);
            Ok(())
        }
        0x96 => {
            // ML: 32×32 → 64 ペア。
            if r & 1 != 0 {
                return unimp(b, 0x5ec1);
            }
            let __h616 = b.load::<W32>(a, RD)?;

            let m = b.zext::<W32, W64>(__h616);
            let __h618 = g(b, r + 1);
            let __h617 = b.trunc::<W64, W32>(__h618);

            let v = b.zext::<W32, W64>(__h617);
            let p = b.mul::<W64>(v, m);
            set_g(b, r + 1, p);
            let __h621 = k(b, 32);
            let __h620 = b.shr_l::<W64>(p, __h621);
            let __h619 = b.trunc::<W64, W32>(__h620);

            set_g32(b, r, __h619);
            Ok(())
        }
        0x87 => {
            // DLG: 128/64。
            if r & 1 != 0 {
                return unimp(b, 0x5ec1);
            }
            let m = b.load::<W64>(a, RD)?;
            let (hi, lo) = (g(b, r), g(b, r + 1));
            dl128(b, r, hi, lo, m)
        }
        0x97 => {
            // DL: ペア 64/32。
            if r & 1 != 0 {
                return unimp(b, 0x5ec1);
            }
            let __h622 = b.load::<W32>(a, RD)?;

            let m = b.zext::<W32, W64>(__h622);
            let __h626 = g(b, r);
            let __h625 = b.trunc::<W64, W32>(__h626);
            let __h624 = b.zext::<W32, W64>(__h625);
            let __h627 = k(b, 32);

            let __h623 = b.shl::<W64>(__h624, __h627);
            let __h630 = g(b, r + 1);
            let __h629 = b.trunc::<W64, W32>(__h630);
            let __h628 = b.zext::<W32, W64>(__h629);

            let dvd = b.or(__h623, __h628);
            div_step(b, r, dvd, m, true)
        }
        // 比較。
        0x20 => {
            let m = b.load::<W64>(a, RD)?;
            cmp64(b, r, m, true)
        }
        0x21 => {
            let m = b.load::<W64>(a, RD)?;
            cmp64(b, r, m, false)
        }
        0x30 => {
            let __h631 = b.load::<W32>(a, RD)?;

            let m = b.sext::<W32, W64>(__h631);
            cmp64(b, r, m, true)
        }
        0x31 => {
            let __h632 = b.load::<W32>(a, RD)?;

            let m = b.zext::<W32, W64>(__h632);
            cmp64(b, r, m, false)
        }
        // 論理 Y 形式。
        0x54..=0x57 => {
            let m = b.load::<W64>(a, RD)?;
            match f {
                0x55 => {
                    // CLY。
                    let m32 = b.trunc::<W64, W32>(m);
                    cmp32(b, r, m32, false)
                }
                _ => {
                    let op = match f {
                        0x54 => 0,
                        0x56 => 1,
                        _ => 2,
                    };
                    let __h633 = b.trunc::<W64, W32>(m);

                    log32(b, r, __h633, op)
                }
            }
        }
        0x80..=0x82 => {
            let m = b.load::<W64>(a, RD)?;
            let op = f - 0x80;
            log64(b, r, m, op)
        }
        0x98 | 0x99 => {
            // ALG/SLG: 64 ビット論理加減算（メモリ 8 バイト）。
            let m = b.load::<W64>(a, RD)?;
            arith64l(b, r, m, f == 0x99)
        }
        0x88 | 0x89 => {
            // ALCG/SLBG: 論理加減算＋キャリー/ボロー伝搬。
            // 直前 CC の bit1 が carry/borrow を運ぶ（cc>=2 で有り）。
            let m = b.load::<W64>(a, RD)?;
            let cc = b.get(cc_ref());
            let __hc = k(b, 2);
            let cin = b.cmp(Cmp::GeU, cc, __hc);
            let a0 = g(b, r);
            let m2 = if f == 0x88 { m } else { b.not(m) };
            let (v, c, _o) = b.add_with_carry(a0, m2, cin);
            set_g(b, r, v);
            cc_logical(b, v, c);
            Ok(())
        }
        0x46 => {
            let __h634 = g(b, r);
            let __h635 = k(b, 1);

            // BCTG。
            let v = b.sub(__h634, __h635);
            set_g(b, r, v);
            let __h636 = k(b, 0);

            let nz = b.cmp(Cmp::Ne, v, __h636);
            b.if_then_else(
                nz,
                |bb| {
                    bb.jump(a);
                    Ok(())
                },
                |_| Ok(()),
            )
        }
        0x8e | 0x8f => {
            // STPQ/LPQ（ペア）。
            if r & 1 != 0 {
                return unimp(b, 0x5ec1);
            }
            if f == 0x8f {
                let hi = b.load::<W64>(a, RD)?;
                let __h638 = k(b, 8);
                let __h637 = b.add(a, __h638);

                let lo = b.load::<W64>(__h637, RD)?;
                set_g(b, r, hi);
                set_g(b, r + 1, lo);
            } else {
                let __h639 = g(b, r);

                b.store::<W64>(a, __h639, WR)?;
                let __h641 = k(b, 8);
                let __h640 = b.add(a, __h641);
                let __h642 = g(b, r + 1);

                b.store::<W64>(__h640, __h642, WR)?;
            }
            Ok(())
        }
        _ => unimp(b, 0xe300 + u64::from(f)),
    }
}

/// 128/64 の符号なし除算（DLG/DLGR）。hi,lo が 128 ビット被除数。
fn dl128<B: Backend>(b: &mut B, r: u8, hi: B::V<W64>, lo: B::V<W64>, dvs: B::V<W64>) -> Flow<B> {
    let __h643 = k(b, 0);

    let dz = b.cmp(Cmp::Eq, dvs, __h643);
    b.if_then_else(
        dz,
        |bb| {
            Err(bb.raise(GuestException {
                kind: ExceptionKind::DivZero,
                code: 0xe387,
                addr: None,
                in_delay_slot: false,
            }))
        },
        |bb| {
            // 1 ビットずつの復元除算（64 回）。
            let mut rem = lo;
            let mut hi_r = hi;
            for _ in 0..64 {
                let __h645 = bb.konst::<W64>(1);
                let __h644 = bb.shl::<W64>(hi_r, __h645);
                let __h647 = bb.konst::<W64>(63);
                let __h646 = bb.shr_l::<W64>(rem, __h647);

                hi_r = bb.or(__h644, __h646);
                let __h648 = bb.konst::<W64>(1);

                rem = bb.shl::<W64>(rem, __h648);
                let ge = bb.cmp(Cmp::GeU, hi_r, dvs);
                let __h649 = bb.sub(hi_r, dvs);

                hi_r = bb.select(ge, __h649, hi_r);
                let __h651 = bb.konst::<W64>(1);
                let __h652 = bb.konst::<W64>(0);

                let __h650 = bb.select(ge, __h651, __h652);

                rem = bb.or(rem, __h650);
            }
            bb.set(Gpr(r + 1).state(), rem);
            bb.set(Gpr(r).state(), hi_r);
            Ok(())
        },
    )
}

/// RSY/SIY 形式（0xEB）。func が下位バイト。
pub fn eb<B: Backend>(b: &mut B, w: u64, _pc: u64) -> Flow<B> {
    let f = func(w);
    let r = r1_48(w);
    let r3 = f3_48(w);
    let b2 = ((w >> 28) & 0xf) as u8;
    let a = ea(b, 0, b2, disp20(w));
    match f {
        0x04 | 0x24 => {
            // LMG/STMG: r3–r1 を 8 バイトずつ。
            let mut i = r;
            loop {
                let off = k(b, u64::from((i.wrapping_sub(r)) & 15) * 8);
                let aa = b.add(a, off);
                if f == 0x24 {
                    let __h653 = g(b, i);

                    b.store::<W64>(aa, __h653, WR)?;
                } else {
                    let v = b.load::<W64>(aa, RD)?;
                    set_g(b, i, v);
                }
                if i == r3 {
                    break;
                }
                i = (i + 1) & 15;
            }
            Ok(())
        }
        0x26 => {
            // STMH: r3–r1 の上位 32 を 4 バイトずつ。
            let mut i = r;
            loop {
                let off = k(b, u64::from((i.wrapping_sub(r)) & 15) * 4);
                let aa = b.add(a, off);
                let __h656 = g(b, i);
                let __h657 = k(b, 32);

                let __h655 = b.shr_l::<W64>(__h656, __h657);
                let __h654 = b.trunc::<W64, W32>(__h655);

                b.store::<W32>(aa, __h654, WR)?;
                if i == r3 {
                    break;
                }
                i = (i + 1) & 15;
            }
            Ok(())
        }
        0x0a | 0x0b | 0x0c | 0x0d | 0x1c | 0x1d => {
            let __h658 = k(b, 63);

            // SRAG/SLAG/SRLG/SLLG/RLLG/RLL。元は r3 ではなく第 2 オペランド
            // レジスタは byte1 上位（r 側）。シフト量は addr&63。
            let n = b.and(a, __h658);
            let v = g(b, r1_48_src(w));
            match f {
                0x1c => {
                    // RLLG: 左回転。
                    let out = rotl(b, v, n, 64);
                    set_g(b, r, out);
                }
                0x1d => {
                    let __h659 = b.trunc::<W64, W32>(v);

                    // RLL: 下位 32 の左回転。
                    let v32 = b.zext::<W32, W64>(__h659);
                    let out = rotl(b, v32, n, 32);
                    let __h660 = b.trunc::<W64, W32>(out);

                    set_g32(b, r, __h660);
                }
                0x0c => {
                    let __h661 = b.shr_l::<W64>(v, n);

                    set_g(b, r, __h661);
                }
                0x0d => {
                    let __h662 = b.shl::<W64>(v, n);

                    set_g(b, r, __h662);
                }
                0x0a => {
                    let __h663 = b.shr_a::<W64>(v, n);

                    set_g(b, r, __h663);
                }
                _ => {
                    // SLAG。
                    let sh = b.shl::<W64>(v, n);
                    let back = b.shr_a::<W64>(sh, n);
                    let neq = b.cmp(Cmp::Ne, back, v);
                    set_g(b, r, sh);
                    cc_signed(b, sh, neq);
                }
            }
            Ok(())
        }
        0x51 => {
            // TMY。
            let i2 = (w >> 16) & 0xfff;
            let _ = i2;
            unimp(b, 0xeb51)
        }
        0x52 => {
            // MVIY。
            let i2 = ((w >> 16) & 0xff) as u8;
            let __h664 = b.konst::<W8>(i2);

            b.store::<W8>(a, __h664, WR)?;
            Ok(())
        }
        0x54 | 0x56 | 0x57 => {
            // NIY/OIY/XIY。
            let i2 = k(b, ((w >> 40) & 0xff00) >> 8 | ((w >> 16) & 0xff));
            let _ = i2;
            unimp(b, 0xeb00 + u64::from(f))
        }
        0x55 => {
            // CLIY。
            let i2 = k(b, (w >> 16) & 0xff);
            let __h665 = b.load::<W8>(a, RD)?;

            let v = b.zext::<W8, W64>(__h665);
            cc_cmp(b, v, i2, false);
            Ok(())
        }
        0x6e | 0x7e => {
            // ALSI/ALGSI: メモリ += 即値。
            let i2 = k(
                b,
                ((w >> 40) & 0xff) << 56 | (((w >> 40) & 0xff) as i8 as i64 as u64) >> 8,
            );
            let _ = i2;
            unimp(b, 0xeb00 + u64::from(f))
        }
        0x20 | 0x21 => {
            // CLMH（上位 32 ビット）/CLMY（下位 32 ビット）。マスクは 4 ビット。
            let m3 = r3;
            clm_body(b, r, m3, a, 4, f == 0x20)
        }
        0x80 | 0x81 => {
            // ICMH/ICMY（マスクは 4 ビット固定）。
            let m3 = r3;
            icm_body(b, r, m3, a, 4, f == 0x80)
        }
        0x2c | 0x2d => {
            // STCMH/STCMY（マスクは 4 ビット固定）。
            let m3 = r3;
            stcm_body(b, r, m3, a, 4, f == 0x2c)
        }
        0x30 | 0x31 | 0x3e | 0x14 => {
            // CSG/CDSY/CDSG/CSY。
            cs_op(b, w, a)
        }
        0x4c => {
            // ECAG: 抽出＋計算（アドレス生成専用）。r1 = r2 + (r3 << i3)。
            let i3 = (w >> 16) & 0x3f;
            let __h666 = g(b, f3_48(w));
            let __h668 = g(b, b1_48(w));
            let __h669 = k(b, i3);

            let __h667 = b.shl::<W64>(__h668, __h669);

            let v = b.add(__h666, __h667);
            set_g(b, r, v);
            let _ = a;
            Ok(())
        }
        _ => unimp(b, 0xeb00 + u64::from(f)),
    }
}

/// EB 系の「第 2 レジスタ」は byte1 上位ニブル（r1 フィールドと同じ位置、
/// シフト系では r3 に値、r1 に結果）。PoP: SRLG r1,r3,d2(b2)。
fn r1_48_src(w: u64) -> u8 {
    ((w >> 32) & 0xf) as u8
}

fn rotl<B: Backend>(b: &mut B, v: B::V<W64>, n: B::V<W64>, width: u64) -> B::V<W64> {
    let w = k(b, width);
    let nn = if width == 32 {
        let __h670 = k(b, 31);

        b.and(n, __h670)
    } else {
        n
    };
    let l = b.shl::<W64>(v, nn);
    let __h671 = b.sub(w, nn);

    let rr = b.shr_l::<W64>(v, __h671);
    b.or(l, rr)
}

/// CS 系（CS/CSY/CSG/CDS/CDSY/CDSG）。CS: r1==mem → mem=r3、CC0;
/// そうでなければ r1=mem、CC1。
fn cs_op<B: Backend>(b: &mut B, w: u64, a: B::V<W64>) -> Flow<B> {
    let f = func(w);
    let r = r1_48(w);
    let r3 = f3_48(w);
    match f {
        0x30 => {
            // CSG: 64 ビット CAS。
            let old = g(b, r);
            let new = g(b, r3);
            let got = b.cmpxchg::<W64>(a, old, new, WR)?;
            let eq = b.cmp(Cmp::Eq, got, old);
            b.if_then_else(
                eq,
                |bb| {
                    let __h672 = bb.konst::<W64>(0);

                    bb.set(cc_ref(), __h672);
                    Ok(())
                },
                |bb| {
                    bb.set(Gpr(r).state(), got);
                    let __h673 = bb.konst::<W64>(1);

                    bb.set(cc_ref(), __h673);
                    Ok(())
                },
            )
        }
        0x14 => {
            let __h674 = g(b, r);

            // CSY: 32 ビット CAS。
            let old = b.trunc::<W64, W32>(__h674);
            let __h675 = g(b, r3);

            let new = b.trunc::<W64, W32>(__h675);
            let got = b.cmpxchg::<W32>(a, old, new, WR)?;
            let eq = b.cmp(Cmp::Eq, got, old);
            b.if_then_else(
                eq,
                |bb| {
                    let __h676 = bb.konst::<W64>(0);

                    bb.set(cc_ref(), __h676);
                    Ok(())
                },
                |bb| {
                    set_g32(bb, r, got);
                    let __h677 = bb.konst::<W64>(1);

                    bb.set(cc_ref(), __h677);
                    Ok(())
                },
            )
        }
        // CDS/CDSY/CDSG（ペア CAS）は近似で未対応でもよいが、よく使われるので
        // 順次版で実装する。z/Architecture では CDS/CDSY も 16 バイト CAS
        // （レジスタペア = 128 ビット）。
        0x31 | 0x3e => {
            if r & 1 != 0 || r3 & 1 != 0 {
                return unimp(b, 0x5ec1);
            }
            // 旧値の一致を確認してから新値 2 語を書く（cmpxchg は 1 語単位）。
            if false {
                let __h678 = g(b, r);

                let old0 = b.trunc::<W64, W32>(__h678);
                let __h679 = g(b, r + 1);

                let old1 = b.trunc::<W64, W32>(__h679);
                let m0 = b.load::<W32>(a, RD)?;
                let __h681 = k(b, 4);
                let __h680 = b.add(a, __h681);

                let m1 = b.load::<W32>(__h680, RD)?;
                let same = {
                    let e0 = b.cmp(Cmp::Eq, m0, old0);
                    let e1 = b.cmp(Cmp::Eq, m1, old1);
                    band(b, e0, e1)
                };
                b.if_then_else(
                    same,
                    |bb| {
                        let __h683 = g(bb, r3);
                        let __h682 = bb.trunc::<W64, W32>(__h683);

                        bb.store::<W32>(a, __h682, WR)?;
                        let __h685 = bb.konst::<W64>(4);
                        let __h684 = bb.add(a, __h685);
                        let __h687 = g(bb, r3 + 1);
                        let __h686 = bb.trunc::<W64, W32>(__h687);

                        bb.store::<W32>(__h684, __h686, WR)?;
                        let __h688 = bb.konst::<W64>(0);

                        bb.set(cc_ref(), __h688);
                        Ok(())
                    },
                    |bb| {
                        set_g32(bb, r, m0);
                        set_g32(bb, r + 1, m1);
                        let __h689 = bb.konst::<W64>(1);

                        bb.set(cc_ref(), __h689);
                        Ok(())
                    },
                )
            } else {
                let old0 = g(b, r);
                let old1 = g(b, r + 1);
                let m0 = b.load::<W64>(a, RD)?;
                let __h691 = k(b, 8);
                let __h690 = b.add(a, __h691);

                let m1 = b.load::<W64>(__h690, RD)?;
                let same = {
                    let e0 = b.cmp(Cmp::Eq, m0, old0);
                    let e1 = b.cmp(Cmp::Eq, m1, old1);
                    band(b, e0, e1)
                };
                b.if_then_else(
                    same,
                    |bb| {
                        let __h692 = g(bb, r3);

                        bb.store::<W64>(a, __h692, WR)?;
                        let __h694 = bb.konst::<W64>(8);
                        let __h693 = bb.add(a, __h694);
                        let __h695 = g(bb, r3 + 1);

                        bb.store::<W64>(__h693, __h695, WR)?;
                        let __h696 = bb.konst::<W64>(0);

                        bb.set(cc_ref(), __h696);
                        Ok(())
                    },
                    |bb| {
                        bb.set(Gpr(r).state(), m0);
                        bb.set(Gpr(r + 1).state(), m1);
                        let __h697 = bb.konst::<W64>(1);

                        bb.set(cc_ref(), __h697);
                        Ok(())
                    },
                )
            }
        }
        _ => unimp(b, 0xeb00 + u64::from(f)),
    }
}

/// CLM/CLMH/CLMY: マスクで選んだバイト列をメモリと比較。
/// `hi` なら上位 32 ビット（バイト 0–3）、なら下位 32 ビット（4–7）。
fn clm_body<B: Backend>(b: &mut B, r: u8, m3: u8, a: B::V<W64>, n: u8, hi: bool) -> Flow<B> {
    // マスクビット m0 は対象の左端バイト。メモリ側は選択バイトを
    // 詰めた連続領域（選択順の番号 j）。
    let mut res = k(b, 0);
    let mut j = 0u64;
    for i in 0..n {
        if (m3 >> (3 - i)) & 1 != 0 {
            let idx = if hi { i } else { i + 4 };
            let __h699 = g(b, r);
            let __h700 = k(b, (7 - u64::from(idx)) * 8);

            let __h698 = b.shr_l::<W64>(__h699, __h700);
            let __h701 = k(b, 0xff);

            let rb = b.and(__h698, __h701);
            let __h704 = k(b, j);
            j += 1;
            let __h703 = b.add(a, __h704);
            let __h702 = b.load::<W8>(__h703, RD)?;

            let mb = b.zext::<W8, W64>(__h702);
            let lt = b.cmp(Cmp::LtU, rb, mb);
            let gt = b.cmp(Cmp::GtU, rb, mb);
            let __h705 = k(b, 1);
            let __h707 = k(b, 2);
            let __h706 = b.select(gt, __h707, res);

            res = b.select(lt, __h705, __h706);
        }
    }
    b.set(cc_ref(), res);
    Ok(())
}

/// ICM/ICMH/ICMY: マスクビットごとにレジスタの該当バイトへロード。
/// `hi` なら上位 32 ビット（バイト 0–3）、なら下位 32 ビット（4–7）。
fn icm_body<B: Backend>(b: &mut B, r: u8, m3: u8, a: B::V<W64>, n: u8, hi: bool) -> Flow<B> {
    let mut v = g(b, r);
    let mut acc = k(b, 0);
    // メモリ側は選択バイトを詰めた連続領域。選択順の番号 j で読む。
    let mut j = 0u64;
    for i in 0..n {
        if (m3 >> (3 - i)) & 1 != 0 {
            let base: u64 = if hi { 0 } else { 4 };
            let pos = base + u64::from(i);
            let __h710 = k(b, j);
            j += 1;
            let __h709 = b.add(a, __h710);
            let __h708 = b.load::<W8>(__h709, RD)?;

            let mv = b.zext::<W8, W64>(__h708);
            let sh = k(b, (7 - pos) * 8);
            let __h714 = k(b, 0xff);
            let __h713 = b.shl::<W64>(__h714, sh);
            let __h712 = b.not(__h713);
            let __h711 = b.and(v, __h712);
            let __h715 = b.shl::<W64>(mv, sh);

            v = b.or(__h711, __h715);
            acc = b.or(acc, mv);
        }
    }
    set_g(b, r, v);
    cc_test(b, acc);
    Ok(())
}

/// STCM/STCMH/STCMY。`hi` なら上位 32 ビット（バイト 0–3）。
fn stcm_body<B: Backend>(b: &mut B, r: u8, m3: u8, a: B::V<W64>, n: u8, hi: bool) -> Flow<B> {
    let v = g(b, r);
    let mut j = 0u64;
    for i in 0..n {
        if (m3 >> (3 - i)) & 1 != 0 {
            let base: u64 = if hi { 0 } else { 4 };
            let pos = base + u64::from(i);
            let __h717 = k(b, (7 - pos) * 8);
            let __h716 = b.shr_l::<W64>(v, __h717);
            let __h718 = k(b, 0xff);

            let byte = b.and(__h716, __h718);
            let __h720 = k(b, j);
            j += 1;
            let __h719 = b.add(a, __h720);
            let __h721 = b.trunc::<W64, W8>(byte);

            b.store::<W8>(__h719, __h721, WR)?;
        }
    }
    Ok(())
}

/// RIE 形式（0xEC）。func が下位バイト。
pub fn ec<B: Backend>(b: &mut B, w: u64, pc: u64) -> Flow<B> {
    let f = func(w);
    let r = r1_48(w);
    let r2 = f3_48(w);
    let i2 = ((w >> 16) & 0xffff) as i16 as i64;
    let m3 = ((w >> 12) & 0xf) as u8;
    match f {
        0x64 | 0x65 | 0x76 | 0x77 | 0xe4 | 0xe5 | 0xf6 | 0xf7 => {
            // CGRJ/CLGRJ/CRJ/CLRJ と BRB 系（cgrb 等）。
            let target = k(b, pc.wrapping_add((i2 << 1) as u64));
            let signed = matches!(f, 0x64 | 0x76 | 0xe4 | 0xf6);
            let wide = matches!(f, 0x64 | 0x65 | 0xe4 | 0xe5);
            let (a, x) = if wide {
                (g(b, r), g(b, r2))
            } else {
                let __h723 = g(b, r);
                let __h722 = b.trunc::<W64, W32>(__h723);
                let __h725 = g(b, r2);
                let __h724 = b.trunc::<W64, W32>(__h725);

                (b.sext::<W32, W64>(__h722), b.sext::<W32, W64>(__h724))
            };
            let (a, x) = if !signed && !wide {
                let __h726 = b.trunc::<W64, W32>(a);
                let __h727 = b.trunc::<W64, W32>(x);

                (b.zext::<W32, W64>(__h726), b.zext::<W32, W64>(__h727))
            } else {
                (a, x)
            };
            cc_cmp(b, a, x, signed);
            cjump(b, m3, target)
        }
        0x7c | 0x7d | 0x7e | 0x7f | 0xfc | 0xfd | 0xfe | 0xff => {
            // CGIJ/CLGIJ/CIJ/CLIJ と CIB 系。
            // マスクは byte1 下位 nibble（r1|m3）。byte4 の i2 が比較即値。
            let m3i = f3_48(w);
            let target = k(b, pc.wrapping_add((i2 << 1) as u64));
            let i3 = ((w >> 8) & 0xff) as i8 as i64;
            let signed = matches!(f, 0x7c | 0x7e | 0xfc | 0xfe);
            let wide = matches!(f, 0x7c | 0x7d | 0xfc | 0xfd);
            let (a, x) = if wide {
                (g(b, r), k(b, i3 as u64))
            } else {
                let __h729 = g(b, r);
                let __h728 = b.trunc::<W64, W32>(__h729);

                (b.sext::<W32, W64>(__h728), k(b, i3 as u64))
            };
            cc_cmp(b, a, x, signed);
            cjump(b, m3i, target)
        }
        0x44 | 0x45 => {
            // BRXHG/BRXLG: r1 += r(r1+1)。BRXHG は r1 > r(r2) で分岐、
            // BRXLG は r1 <= r(r2) で分岐。busybox のループで使われる。
            let incr = g(b, r + 1);
            let lim = g(b, r2);
            let cur = g(b, r);
            let nv = b.add(cur, incr);
            set_g(b, r, nv);
            let target = k(b, pc.wrapping_add((i2 << 1) as u64));
            let c = if f == 0x44 {
                b.cmp(Cmp::GtS, nv, lim)
            } else {
                b.cmp(Cmp::LeS, nv, lim)
            };
            b.if_then_else(
                c,
                |bb| {
                    bb.jump(target);
                    Ok(())
                },
                |_| Ok(()),
            )
        }
        0x70..=0x73 => {
            // CGIT/CLGIT/CIT/CLIT: 条件が合えば trap、合わなければ no-op。
            let c = btaken(b, m3);
            b.if_then_else(
                c,
                |bb| {
                    Err(bb.raise(GuestException {
                        kind: ExceptionKind::Trap,
                        code: 0xec00 + u64::from(f),
                        addr: None,
                        in_delay_slot: false,
                    }))
                },
                |_| Ok(()),
            )
        }
        0x54..=0x57 => {
            // RNSBG/ROSBG/RXSBG/RISBG 系（回転＋選択挿入）。
            risb(b, f, r, w)
        }
        0x59 | 0x5d | 0x51 => {
            // RISBLG/RISBHG/RISBMZ は低・高位グラフトで別形式。未対応。
            unimp(b, 0xec00 + u64::from(f))
        }
        _ => unimp(b, 0xec00 + u64::from(f)),
    }
}

/// RISB 系（回転＋選択挿入）。
/// i3[5:0]=開始ビット（PoP の左からの番号）、i4[5:0]=終了ビット、
/// i4[7]=ゼロ化フラグ、i5[5:0]=回転量。
/// 0x54=RNSBG(AND), 0x55=RISBG(挿入), 0x56=ROSBG(OR), 0x57=RXSBG(XOR)。
// Ref: SPEC-S390-ZARCH-POP — RNSBG/ROSBG/RXSBG/RISBG の選択回転挿入。
fn risb<B: Backend>(b: &mut B, f: u8, r: u8, w: u64) -> Flow<B> {
    let r2 = f3_48(w);
    let i3 = (w >> 24) & 0xff;
    let i4 = (w >> 16) & 0xff;
    let i5 = (w >> 8) & 0xff;
    let v2 = g(b, r2);
    let __h730 = k(b, i5 & 0x3f);
    let rot = rotl(b, v2, __h730, 64);
    let lo = i3 & 0x3f;
    let hi_i = i4 & 0x3f;
    let zeroed = i4 & 0x80 != 0;
    // PoP ビット i は u64 の LSB 側 (63-i)。範囲 lo..hi の選択マスク。
    // hi_i < lo はビット 63→0 を跨ぐ折返し選択。
    let mask: u64 = if hi_i >= lo {
        let width = hi_i - lo + 1;
        if width >= 64 {
            u64::MAX
        } else {
            ((1u64 << width) - 1) << (63 - hi_i)
        }
    } else {
        (u64::MAX >> lo) | (u64::MAX << (63 - hi_i))
    };
    let __h731 = k(b, mask);
    let sel = b.and(rot, __h731);
    let old = g(b, r);
    // 選択ビットでの演算結果。
    let ins = match f {
        0x54 => b.and(old, sel),
        0x56 => b.or(old, sel),
        0x57 => b.xor(old, sel),
        _ => sel,
    };
    let out = if zeroed {
        ins
    } else {
        let __h732 = b.not(__h731);
        let __h733 = b.and(old, __h732);
        b.or(__h733, ins)
    };
    set_g(b, r, out);
    cc_test(b, out);
    Ok(())
}

/// RXE/RXF 形式（0xED）。BFP メモリ演算。
pub fn ed<B: Backend>(b: &mut B, w: u64, _pc: u64) -> Flow<B> {
    let f = func(w);
    let r = r1_48(w);
    let x2 = f3_48(w);
    let b2 = ((w >> 28) & 0xf) as u8;
    let a = ea(b, x2, b2, disp20(w));
    match f {
        0x64..=0x67 => {
            // LEY/LDY/STEY/STDY。
            match f {
                0x64 => {
                    let __h743 = b.load::<W32>(a, RD)?;

                    let v = b.zext::<W32, W64>(__h743);
                    let cur = b.get(Fpr(r & 15).state());
                    let __h746 = k(b, 32);
                    let __h745 = b.shl::<W64>(v, __h746);
                    let __h748 = k(b, 0xffff_ffff);
                    let __h747 = b.and(cur, __h748);

                    let __h744 = b.or(__h745, __h747);

                    b.set(Fpr(r & 15).state(), __h744);
                }
                0x65 => {
                    let v = b.load::<W64>(a, RD)?;
                    b.set(Fpr(r & 15).state(), v);
                }
                0x66 => {
                    let v = b.get(Fpr(r & 15).state());
                    let __h751 = k(b, 32);
                    let __h750 = b.shr_l::<W64>(v, __h751);
                    let __h749 = b.trunc::<W64, W32>(__h750);

                    b.store::<W32>(a, __h749, WR)?;
                }
                _ => {
                    let v = b.get(Fpr(r & 15).state());
                    b.store::<W64>(a, v, WR)?;
                }
            }
            Ok(())
        }
        0x04 => {
            let __h752 = b.load::<W32>(a, RD)?;

            // LDEB: f32 → f64。
            let s = b.zext::<W32, W64>(__h752);
            let __h753 = b.trunc::<W64, W32>(s);

            let d = b.fcvt_ff::<W32, W64>(__h753, 0);
            b.set(Fpr(r & 15).state(), d);
            Ok(())
        }
        // メモリ対 BFP 2 値演算（0x0e/0x0f/0x1e/0x1f は RXF の MAD/MSD 系）。
        0x08..=0x0d | 0x14 | 0x15 | 0x18..=0x1d => {
            let short = matches!(f, 0x08..=0x0d | 0x14);
            let m = if short {
                let __h754 = b.load::<W32>(a, RD)?;

                let s = b.zext::<W32, W64>(__h754);
                let __h755 = b.trunc::<W64, W32>(s);

                b.fcvt_ff::<W32, W64>(__h755, 0)
            } else {
                b.load::<W64>(a, RD)?
            };
            let a64 = fg64(b, r, short);
            let d = match f & 0x0f {
                0x8 | 0x9 => {
                    // KEB/KEB? f==8=KEB,9=CEB。
                    let eq = b.feq::<W64>(a64, m);
                    let lt = b.flt::<W64>(a64, m);
                    let __h756 = k(b, 0);
                    let __h758 = k(b, 1);
                    let __h759 = k(b, 2);

                    let __h757 = b.select(lt, __h758, __h759);

                    let cc = b.select(eq, __h756, __h757);
                    b.set(cc_ref(), cc);
                    return Ok(());
                }
                0xa => b.fadd::<W64>(a64, m),
                0xb => b.fsub::<W64>(a64, m),
                0xc => b.fmul::<W64>(a64, m),
                0xd => b.fdiv::<W64>(a64, m),
                0x4 => b.fsqrt::<W64>(m),
                0x5 => b.fsqrt::<W64>(m),
                _ => return unimp(b, 0xed00 + u64::from(f)),
            };
            put_f(b, r, d, short);
            Ok(())
        }
        0x0e | 0x0f | 0x1e | 0x1f => {
            // MAEB/MSEB/MADB/MSDB（RXF: byte4 上位が r1、byte1 上位が r3）。
            let r3 = ((w >> 36) & 0xf) as u8;
            let r1f = ((w >> 12) & 0xf) as u8;
            let short = f == 0x0e || f == 0x0f;
            let m = if short {
                let __h760 = b.load::<W32>(a, RD)?;

                let s = b.zext::<W32, W64>(__h760);
                let __h761 = b.trunc::<W64, W32>(s);

                b.fcvt_ff::<W32, W64>(__h761, 0)
            } else {
                b.load::<W64>(a, RD)?
            };
            let a64 = fg64(b, r3, short);
            let acc = fg64(b, r1f, short);
            let prod = b.fmul::<W64>(a64, m);
            let d = if f == 0x0e || f == 0x1e {
                b.fadd::<W64>(acc, prod)
            } else {
                b.fsub::<W64>(acc, prod)
            };
            put_f(b, r1f, d, short);
            Ok(())
        }
        _ => unimp(b, 0xed00 + u64::from(f)),
    }
}

/// SIL/SSE 形式（0xE5）。`E5 f | b1 d1 | i2`: byte1 が機能、
/// b1/d1 が被演算数アドレス、後半 16 ビットが即値。
pub fn e5<B: Backend>(b: &mut B, w: u64, _pc: u64) -> Flow<B> {
    let f = ((w >> 32) & 0xff) as u8;
    let b1 = ((w >> 28) & 0xf) as u8;
    let d1 = ((w >> 16) & 0xfff) as i64;
    let i2 = (w & 0xffff) as i16 as i64;
    match f {
        0x44 | 0x48 | 0x4c => {
            // MVHHI/MVGHI/MVHI: メモリに 16 ビット即値を書く。
            let a = ea(b, 0, b1, d1);
            let v = k(b, i2 as u64);
            match f {
                0x44 => {
                    let __h762 = b.trunc::<W64, W16>(v);

                    b.store::<W16>(a, __h762, WR)?;
                }
                0x4c => {
                    let __h763 = b.trunc::<W64, W32>(v);

                    b.store::<W32>(a, __h763, WR)?;
                }
                _ => {
                    b.store::<W64>(a, v, WR)?;
                }
            }
            Ok(())
        }
        _ => unimp(b, 0xe500 + u64::from(f)),
    }
}

/// 生成 Insn → 意味論の第 2 段ディスパッチ（32/48 ビット側）。
pub fn exec2<B: Backend>(b: &mut B, insn: crate::Insn, w: u64, pc: u64) -> Flow<B> {
    use crate::Insn::*;
    match insn {
        // RX。
        Sth | La | Stc | Ic | Ex | Bal | Bct | Bc | Lh | Ch | Ah | Sh | Mh | Bas | Cvd | Cvb
        | St | Lae | N | Cl | O | X | L | C | A | S | Mulw | D | Al | Sl | Std | Mxd | Ld | Cd
        | Ad | Sd | Md | Dd | Aw | Sw | Ste | Ms | Le | Ce | Ae | Se | Mde | De | Au | Su => {
            rx(b, insn, w, pc)
        }
        // RS/SI/RI。
        Diag | Brxh | Brxle | Bxh | Bxle | Srl | Sll | Sra | Sla | Srdl | Sldl | Srda | Slda
        | Stm | Tm | Mvi | Ts | Ni | Cli | Oi | Xi | Lm | Lam | Stam | Mvcle | Clcle | Stnsm
        | Stosm | Icm | Stcm | Clm | Cs | Cds | Nihh | Nihl | Nilh | Nill | Oihh | Oihl | Oilh
        | Oill | Llihh | Llihl | Llilh | Llill | Tmlh | Tmll | Tmhh | Tmhl | Brc | Bras | Brct
        | Brctg | Lhi | Lghi | Ahi | Aghi | Mhi | Mghi | Chi | Cghi => rs_ri(b, insn, w, pc),
        // B2/B9/B3。
        SB2 => s_b2(b, w, pc),
        B3 => b3(b, w, pc),
        B9 => b9(b, w, pc),
        // RIL。
        Larl | Lgfi | Brcl | Brasl | Xihf | Xilf | Iihf | Iilf | Nihf | Nilf | Oihf | Oilf
        | Llihf | Llilf | Msgfi | Msfi | Slgfi | Slfi | Agfi | Afi | Algfi | Alfi | Cgfi | Cfi
        | Clgfi | Clfi | Llhrl | Lghrl | Lhrl | Llghrl | Sthrl | Lgrl | Stgrl | Lgfrl | Lrl
        | Llgfrl | Strl | Brul | Brh | Exrl | Cghrl | Chrl | Clghrl | Clhrl | Cgrl | Clgrl
        | Cgfrl | Crl | Clgfrl | Clrl => ril(b, insn, w, pc),
        // SS。
        Mvn | Mvc | Mvz | Nc | Clc | Oc | Xc | Tr | Trt | Ed | Edmk | Srp | Mvo | Pack | Unpk
        | Zap | Cp | Ap | Sp | Mp | Dp => ss(b, insn, w, pc),
        // RXY/RSY/RIE/RXE/SIL。
        E3 => e3(b, w, pc),
        Eb => eb(b, w, pc),
        Ec => ec(b, w, pc),
        Rxe => ed(b, w, pc),
        E5 => e5(b, w, pc),
        _ => unimp(b, w & 0xffff_ffff_ffff),
    }
}

/// RS/SI/RI のうち RI（A5/A7）を RI 側へ振り分ける。
fn rs_ri<B: Backend>(b: &mut B, insn: crate::Insn, w: u64, pc: u64) -> Flow<B> {
    use crate::Insn::*;
    match insn {
        Nihh | Nihl | Nilh | Nill | Oihh | Oihl | Oilh | Oill | Llihh | Llihl | Llilh | Llill
        | Tmlh | Tmll | Tmhh | Tmhl | Brc | Bras | Brct | Brctg | Lhi | Lghi | Ahi | Aghi | Mhi
        | Mghi | Chi | Cghi => ri(b, insn, w, pc),
        _ => rs(b, insn, w, pc),
    }
}
