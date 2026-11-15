// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 非 IEEE 浮動小数点の仕様値と往復の例（層4・examples）。
//!
//! IBM 十六進浮動小数点（HFP）・DEC F/D/G/H・Motorola 68881 拡張
//! 精度について、マニュアル記載の既知ビットパターンと、演算の
//! 自明な往復を検査する。値はすべて整数演算で決定的に得られる。

use polyisa_softfloat::decfp::{VaxDF, VaxFF, VaxGF};
use polyisa_softfloat::ibmhex::{Hf32, Hf64, Hf128};
use polyisa_softfloat::m68kext::M68kExt;
use polyisa_softfloat::{FP_DZ, FP_NV, FP_OF, FP_UF, Rm};

// ---- IBM HFP ----
// 既知パターン（S/360 PoO の例）:
//   1.0   = 0x41100000        （特性 0x41、仮数 0x100000）
//   0.5   = 0x40800000
//   1.5   = 0x41180000
//   2.0   = 0x41200000
//   16.0  = 0x42100000
//   -16.0 = 0xC2100000
//   31.0  = 0x421F0000        （16.0 + 15.0）
//   最大  = 0x7FFFFFFF
//   最小正規化 = 0x00100000   （16^-65）

#[test]
fn hfp_known_patterns() {
    // 1.0 + 0.5 = 1.5
    let (r, f) = Hf32::from_bits(0x41100000).add(Hf32::from_bits(0x40800000), Rm::Rne);
    assert_eq!((r.bits() as u64, f), (0x41180000, 0));
    // 16.0 + 15.0 = 31.0
    let (r, f) = Hf32::from_bits(0x42100000).add(Hf32::from_bits(0x41F00000), Rm::Rne);
    assert_eq!((r.bits() as u64, f), (0x421F0000, 0));
    // 1.0 * 1.5 = 1.5
    let (r, f) = Hf32::from_bits(0x41100000).mul(Hf32::from_bits(0x41180000), Rm::Rne);
    assert_eq!((r.bits() as u64, f), (0x41180000, 0));
    // 3.0 / 2.0 = 1.5
    let (r, f) = Hf32::from_bits(0x41300000).div(Hf32::from_bits(0x41200000), Rm::Rne);
    assert_eq!((r.bits() as u64, f), (0x41180000, 0));
    // 1.5 - 0.5 = 1.0
    let (r, f) = Hf32::from_bits(0x41180000).sub(Hf32::from_bits(0x40800000), Rm::Rne);
    assert_eq!((r.bits() as u64, f), (0x41100000, 0));
}

#[test]
fn hfp_long_and_extended() {
    // 64 ビット版 1.0 = 0x4110000000000000
    let one = Hf64::from_bits(0x4110000000000000);
    let half = Hf64::from_bits(0x4080000000000000);
    let (r, f) = one.add(half, Rm::Rne);
    assert_eq!((r.bits() as u64, f), (0x4118000000000000, 0));
    // 128 ビット版 1.0：符号 0、特性 0x41、仮数 0x1 の後に 0 が 27 桁。
    let e1 = Hf128::from_bits(0x411000000000000000000000000000u128);
    let (r, f) = e1.add(e1, Rm::Rne);
    assert_eq!(r.bits(), 0x412000000000000000000000000000u128);
    assert_eq!(f, 0);
    // 往復：encode → decode は一致する。
    let v = Hf64::from_bits(0xC210000000000000);
    assert!(v.negative());
    assert!(!v.is_zero());
}

#[test]
fn hfp_exceptions() {
    let max = Hf32::from_bits(0x7FFF_FFFF);
    // 最大 + 最大 → オーバーフロー。s390 流儀では特性指数が mod 128
    // で包まれ、仮数は正しい結果のまま残る（0x200000）。
    let (r, f) = max.add(max, Rm::Rne);
    assert_eq!(f & FP_OF, FP_OF);
    assert_eq!(r.bits() as u64, 0x0020_0000);
    // 最小正規化数 / 16.0 → 16^-66 でアンダーフローし零。
    let (r, f) = Hf32::from_bits(0x0010_0000).div(Hf32::from_bits(0x4210_0000), Rm::Rne);
    assert_eq!(f & FP_UF, FP_UF);
    assert!(r.is_zero());
    // 1.0 / 0 → FP_DZ（HFP に無限大はない）。
    let (_, f) = Hf32::from_bits(0x4110_0000).div(Hf32::from_bits(0), Rm::Rne);
    assert_eq!(f & FP_DZ, FP_DZ);
}

#[test]
fn hfp_compare() {
    let one = Hf32::from_bits(0x4110_0000);
    let neg = Hf32::from_bits(0xC110_0000);
    assert!(neg.lt(one));
    assert!(!one.lt(neg));
    assert_eq!(one.cmp(one), 0);
    // ゼロは符号に関係なく等しい（0x00000000 と 0x80000000）。
    assert_eq!(Hf32::from_bits(0).cmp(Hf32::from_bits(0x8000_0000)), 0);
    // -16.0 < 1.0 < 16.0
    let m16 = Hf32::from_bits(0xC210_0000);
    let p16 = Hf32::from_bits(0x4210_0000);
    assert!(m16.lt(one) && one.lt(p16));
}

// ---- DEC ----
// 既知パターン（VAX アーキテクチャの値、符号|指数|仮数の線形配置）:
//   F 1.0 = 0x40800000、F 0.5 = 0x40000000、F 2.0 = 0x41000000
//   F -1.0 = 0xC0800000、予約オペランド = 0x80000000
//   D 1.0 = 0x4080000000000000
//   G 1.0 = 0x4010000000000000

#[test]
fn vax_known_patterns() {
    // 1.0 + 0.5 = 1.5（f = 0.75 → 仮数 0x400000、指数 129）
    let (r, f) = VaxFF::from_bits(0x40800000).add(VaxFF::from_bits(0x40000000), Rm::Rne);
    assert_eq!((r.bits() as u64, f), (0x40C00000, 0));
    // 1.5 * 2.0 = 3.0（f = 0.75、指数 130 → 0x41400000）
    let (r, f) = VaxFF::from_bits(0x40C00000).mul(VaxFF::from_bits(0x41000000), Rm::Rne);
    assert_eq!((r.bits() as u64, f), (0x41400000, 0));
    // 3.0 - 1.0 = 2.0
    let (r, f) = VaxFF::from_bits(0x41400000).sub(VaxFF::from_bits(0x40800000), Rm::Rne);
    assert_eq!((r.bits() as u64, f), (0x41000000, 0));
    // 3.0 / 2.0 = 1.5
    let (r, f) = VaxFF::from_bits(0x41400000).div(VaxFF::from_bits(0x41000000), Rm::Rne);
    assert_eq!((r.bits() as u64, f), (0x40C00000, 0));
}

#[test]
fn vax_reserved_and_zero() {
    // 予約オペランドは FP_NV。
    let (r, f) = VaxFF::from_bits(0x8000_0000).add(VaxFF::from_bits(0x4080_0000), Rm::Rne);
    assert_eq!(f & FP_NV, FP_NV);
    assert!(r.is_zero());
    // dirty zero（指数 0 で仮数があっても零）は零として扱う。
    assert!(VaxFF::from_bits(0x0000_0001).is_zero());
    assert!(VaxFF::from_bits(0x8000_0000).is_reserved());
    // 零 + 値 = 値。
    let (r, f) = VaxFF::zero().add(VaxFF::from_bits(0x4100_0000), Rm::Rne);
    assert_eq!((r.bits() as u64, f), (0x4100_0000, 0));
}

#[test]
fn vax_widen() {
    // F の 1.0 → D：指数は同じ、仮数を伸ばす。
    let (d, f) = VaxFF::from_bits(0x4080_0000).widen::<8, 55>();
    assert_eq!((d.bits() as u64, f), (0x4080_0000_0000_0000, 0));
    // F の 1.0 → G：値は同じで指数幅が広がる。
    let (g, f) = VaxFF::from_bits(0x4080_0000).widen::<11, 52>();
    assert_eq!((g.bits() as u64, f), (0x4010_0000_0000_0000, 0));
    // D の 1.0 → G → 往復しても値は保存される。
    let d1 = VaxDF::from_bits(0x4080_0000_0000_0000);
    let (g, _) = d1.widen::<11, 52>();
    assert!(g.eq(VaxGF::from_bits(0x4010_0000_0000_0000)));
}

// ---- Motorola 68881 拡張 ----
// 既知パターン（96 ビット格納、符号|指数15|未使用16|仮数64）:
//   1.0   = 0x3FFF0000_8000000000000000 の分解表現
//   2.0   = 指数 0x4000、仮数 0x8000000000000000
//   -1.0  = 符号 1、指数 0x3FFF、仮数 0x8000000000000000
//   +inf  = 指数 0x7FFF、仮数 0
//   NaN   = 指数 0x7FFF、仮数非 0

#[test]
fn m68k_known_patterns() {
    let one = M68kExt::from_parts(false, 0x3FFF, 0x8000_0000_0000_0000);
    let two = M68kExt::from_parts(false, 0x4000, 0x8000_0000_0000_0000);
    let neg_one = M68kExt::from_parts(true, 0x3FFF, 0x8000_0000_0000_0000);
    // 1.0 + 1.0 = 2.0
    let (r, f) = one.add(one, Rm::Rne);
    assert_eq!((r, f), (two, 0));
    // 2.0 - 1.0 = 1.0
    let (r, f) = two.sub(one, Rm::Rne);
    assert_eq!((r, f), (one, 0));
    // 1.5 = 指数 0x3FFF、仮数 0xC000000000000000
    let three_half = M68kExt::from_parts(false, 0x3FFF, 0xC000_0000_0000_0000);
    let (r, f) = one.add(
        M68kExt::from_parts(false, 0x3FFE, 0x8000_0000_0000_0000),
        Rm::Rne,
    );
    assert_eq!((r, f), (three_half, 0));
    // 1.5 * 2.0 = 3.0（指数 0x4000、仮数 0xC000…）
    let three = M68kExt::from_parts(false, 0x4000, 0xC000_0000_0000_0000);
    let (r, f) = three_half.mul(two, Rm::Rne);
    assert_eq!((r, f), (three, 0));
    // 3.0 / 2.0 = 1.5
    let (r, f) = three.div(two, Rm::Rne);
    assert_eq!((r, f), (three_half, 0));
    // 比較：-1 < 1 < 2
    assert!(neg_one.lt(one) && one.lt(two));
    assert!(one.eq(one));
}

#[test]
fn m68k_exceptions() {
    let one = M68kExt::from_parts(false, 0x3FFF, 0x8000_0000_0000_0000);
    let inf = M68kExt::inf(false);
    let nan = M68kExt::canonical_nan();
    // 0 / 0 → NaN + FP_NV
    let (r, f) = M68kExt::zero().div(M68kExt::zero(), Rm::Rne);
    assert!(r.is_nan());
    assert_eq!(f & FP_NV, FP_NV);
    // 1 / 0 → inf + FP_DZ
    let (r, f) = one.div(M68kExt::zero(), Rm::Rne);
    assert_eq!((r, f), (inf, FP_DZ));
    // inf - inf → NaN + FP_NV
    let (r, f) = inf.sub(inf, Rm::Rne);
    assert!(r.is_nan());
    assert_eq!(f & FP_NV, FP_NV);
    // inf * 0 → NaN + FP_NV
    let (r, f) = inf.mul(M68kExt::zero(), Rm::Rne);
    assert!(r.is_nan());
    assert_eq!(f & FP_NV, FP_NV);
    // NaN + 1 → NaN
    let (r, _) = nan.add(one, Rm::Rne);
    assert!(r.is_nan());
    // 非正規化数はそのまま読める。
    let d = M68kExt::from_parts(false, 0, 1);
    assert!(d.is_denormal());
}

#[test]
fn m68k_bits_roundtrip() {
    let v = M68kExt::from_parts(true, 0x1234, 0xDEAD_BEEF_CAFE_F00D);
    let b = v.bits();
    assert_eq!(M68kExt::from_bits(b), v);
    // 未使用 16 ビットは from_bits で保持されるが、from_parts では 0。
    assert_eq!(b >> 64 & 0xFFFF, 0);
    assert!(v.negative());
}
