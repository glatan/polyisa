// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! IA-64 の 82 ビット形式（`ia64ext`）の振る舞いを例で確認する。
//! 値の読みは `{符号1, 指数17（バイアス 0xFFFF）, 仮数64（整数ビット
//! 込み）}`。`fma` 系は `Fmt` で精度と指数範囲を選ぶ。

use polyisa_softfloat::ia64ext::{EXP_INT, FClass, FMT_REG, FMT_S, Ia64Ext};
use polyisa_softfloat::{FP_NV, FP_NX, FP_UF, Rm};

fn f64(v: f64) -> Ia64Ext {
    Ia64Ext::from_bin::<11, 52>(v.to_bits())
}

fn f32(v: f32) -> Ia64Ext {
    Ia64Ext::from_bin::<8, 23>(v.to_bits() as u64)
}

#[test]
fn decode_constants() {
    // FR0/FR1 の定数と NaTVal のエンコーディング。
    assert_eq!(Ia64Ext::ZERO.class(), FClass::Zero);
    assert_eq!(Ia64Ext::ONE.class(), FClass::Norm);
    assert_eq!(Ia64Ext::ONE.bits(), (0xffffu128 << 64) | (1u128 << 63));
    assert!(Ia64Ext::NATVAL.is_natval());
    assert_eq!(Ia64Ext::NATVAL.class(), FClass::NatVal);
}

#[test]
fn fmadd_basic() {
    // 1*1+1 = 2、1*2+0.5 = 2.5。
    let (r, fl) = Ia64Ext::ONE.fmadd(Ia64Ext::ONE, Ia64Ext::ONE, Rm::Rne, FMT_REG, false);
    assert_eq!(fl, 0);
    assert_eq!(r.bits() >> 64, 0x10000);
    assert_eq!(r.bits() as u64, 1u64 << 63);
    let (r, _) = f64(1.0).fmadd(f64(2.0), f64(0.5), Rm::Rne, FMT_REG, false);
    assert_eq!(r.to_bin::<11, 52>(Rm::Rne).0, 2.5f64.to_bits());
}

#[test]
fn fmadd_single_precision_output() {
    // .s 完了子相当: FMT_S で 24 ビットに丸める。1/3 の f32 丸め。
    let third = Ia64Ext::from_parts(false, 0xffff - 2, 0xaaaa_aaaa_aaaa_aaaa);
    let (r, fl) = Ia64Ext::ONE.fmadd(Ia64Ext::ZERO, third, Rm::Rne, FMT_S, false);
    assert_ne!(fl & FP_NX, 0);
    assert_eq!(
        r.to_bin::<8, 23>(Rm::Rne).0,
        (1.0f32 / 3.0).to_bits() as u64
    );
}

#[test]
fn fmadd_cancel() {
    // a*b - a*b = +0（Rdn では -0）。
    let (r, _) = f64(1.5).fmadd(f64(2.0), f64(-3.0), Rm::Rne, FMT_REG, false);
    assert_eq!(r.bits(), 0);
    let (r, _) = f64(1.5).fmadd(f64(2.0), f64(-3.0), Rm::Rdn, FMT_REG, false);
    assert_eq!(r.bits(), 1u128 << 81);
}

#[test]
fn special_arithmetic() {
    // inf * 0 + c → invalid → QNaN + NV。
    let (r, fl) = Ia64Ext::inf(false).fmadd(Ia64Ext::ZERO, f64(1.0), Rm::Rne, FMT_REG, false);
    assert_eq!(r, Ia64Ext::QNAN);
    assert_ne!(fl & FP_NV, 0);
    // NaTVal は伝播。
    let (r, _) = Ia64Ext::NATVAL.fmadd(Ia64Ext::ONE, Ia64Ext::ONE, Rm::Rne, FMT_REG, false);
    assert!(r.is_natval());
}

#[test]
fn int_roundtrip() {
    // fcvt.xf ↔ fcvt.fx。
    let v = Ia64Ext::from_i64(42);
    assert_eq!(v.class(), FClass::Norm);
    assert_eq!(v.to_int(false, Rm::Rne).0, 42);
    assert_eq!(
        Ia64Ext::from_i64(-7).to_int(false, Rm::Rne).0,
        (-7i64) as u64
    );
    // 3.6 → Rne 4、Rtz 3。
    let x = f64(3.6);
    assert_eq!(x.to_int(false, Rm::Rne).0, 4);
    assert_eq!(x.to_int(false, Rm::Rtz).0, 3);
    // NaN → 整数不定値 + NV。
    let (v, fl) = Ia64Ext::QNAN.to_int(false, Rm::Rne);
    assert_eq!(v, 0x8000_0000_0000_0000);
    assert_ne!(fl & FP_NV, 0);
}

#[test]
fn narrow_and_widen() {
    // f32 → reg → f32 は厳密。f64 → f32 は丸める。
    let x = f32(1.5);
    assert_eq!(x.to_bin::<8, 23>(Rm::Rne).0, 1.5f32.to_bits() as u64);
    let (bits, _) = f64(1.1).to_bin::<8, 23>(Rm::Rne);
    assert_eq!(bits, (1.1f64 as f32).to_bits() as u64);
    // 最小 f64 非正規化 → f32 では零 + U|I。
    let (_, fl) = f64(f64::from_bits(1)).to_bin::<8, 23>(Rm::Rne);
    assert_eq!(fl & (FP_UF | FP_NX), FP_UF | FP_NX);
}

#[test]
fn compare_and_class() {
    use core::cmp::Ordering;
    assert_eq!(f64(-1.0).compare(f64(2.0)), Some(Ordering::Less));
    // -0 == +0。
    assert_eq!(
        Ia64Ext::ZERO.compare(Ia64Ext::zero_signed(true)),
        Some(Ordering::Equal)
    );
    // unnormalized {exp=5, int=0} も大小比較できる。
    let u = Ia64Ext::from_parts(false, 5, 1);
    assert_eq!(u.class(), FClass::Unnorm);
    assert_eq!(u.compare(Ia64Ext::ZERO), Some(Ordering::Greater));
    // fclass: {pos|norm} = 0x11 に norm 正値が合う。
    assert!(f64(3.0).fclass_hit(0x011));
    assert!(Ia64Ext::NATVAL.fclass_hit(0x100));
    assert!(Ia64Ext::QNAN.fclass_hit(0x080));
}

#[test]
fn approximations() {
    // frcpa(1,2) = 0.5・述語 1。frsqrta(4) ≈ 0.5。
    let (p, r) = Ia64Ext::ONE.frcpa(f64(2.0));
    assert!(p);
    assert_eq!(r.to_bin::<11, 52>(Rm::Rne).0, 0.5f64.to_bits());
    let (p, r) = f64(4.0).frsqrta();
    assert!(p);
    let got = r.to_bin::<11, 52>(Rm::Rne).0;
    assert!((f64::from_bits(got) - 0.5).abs() < 1e-12);
    // 0/0・負の平方根は述語 0。
    assert!(!Ia64Ext::ZERO.frcpa(Ia64Ext::ZERO).0);
    assert!(!f64(-4.0).frsqrta().0);
}

#[test]
fn ext80_roundtrip() {
    // 拡張精度メモリ形式。{符号1,指数15} の再バイアス + 仮数そのまま。
    let v = f64(2.0);
    let (se, sig) = v.to_ext80();
    assert_eq!(se, 16383 + 1);
    assert_eq!(sig, 1u64 << 63);
    assert_eq!(Ia64Ext::from_ext80(se, sig), v);
    // NaTVal は符号 0・指数 0x1FFFE・仮数 0。
    assert_eq!(Ia64Ext::NATVAL.bits(), 0x1fffeu128 << 64);
}

#[test]
fn integer_form() {
    // getf/setf.sig・ldf8 の「整数形式」は {0, EXP_INT, sig}。
    let v = Ia64Ext::int_form(0xdead_beef);
    assert_eq!(v.bits() >> 64, EXP_INT as u128);
}
