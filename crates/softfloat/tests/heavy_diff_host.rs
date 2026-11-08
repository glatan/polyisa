// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! ホスト FPU との差分比較（層8・diff の浮動小数点版）。
//!
//! TestFloat ベクタ実行までのつなぎとして、ホストの RNE 演算（IEEE 754）と
//! 値を突き合わせる。NaN はペイロード不問（正準化の差を許す）、
//! それ以外はビット一致を要求する。ゼロの符号も区別する。
//! 外部道具も取得データも要らない。

use polyisa_softfloat::{F32, F64};

fn next_u64(s: &mut u64) -> u64 {
    // xorshift64*。決定的にするため固定種から始める。
    let mut x = *s;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *s = x;
    x.wrapping_mul(0x2545_F491_4F6C_DD1D)
}

/// 境界値に偏らせた 32 ビットパターン。
fn pat32(rng: &mut u64, i: u64) -> u32 {
    match i % 16 {
        0 => {
            if next_u64(rng) & 1 == 0 {
                0x0000_0000
            } else {
                0x8000_0000
            }
        }
        1 => {
            if next_u64(rng) & 1 == 0 {
                0x7F80_0000
            } else {
                0xFF80_0000
            }
        }
        2 => 0x7F80_0000 | (next_u64(rng) as u32 & 0x7F_FFFF) | 1,
        3 => (next_u64(rng) as u32 & 0x7F_FFFF) | 1,
        4 => {
            if next_u64(rng) & 1 == 0 {
                0x0080_0000
            } else {
                0x7F7F_FFFF
            }
        }
        _ => next_u64(rng) as u32,
    }
}

/// 境界値に偏らせた 64 ビットパターン。
fn pat64(rng: &mut u64, i: u64) -> u64 {
    match i % 16 {
        0 => {
            if next_u64(rng) & 1 == 0 {
                0x0000_0000_0000_0000
            } else {
                0x8000_0000_0000_0000
            }
        }
        1 => {
            if next_u64(rng) & 1 == 0 {
                0x7FF0_0000_0000_0000
            } else {
                0xFFF0_0000_0000_0000
            }
        }
        2 => 0x7FF0_0000_0000_0000 | (next_u64(rng) & 0xF_FFFF_FFFF_FFFF) | 1,
        3 => (next_u64(rng) & 0xF_FFFF_FFFF_FFFF) | 1,
        4 => {
            if next_u64(rng) & 1 == 0 {
                0x0010_0000_0000_0000
            } else {
                0x7FEF_FFFF_FFFF_FFFF
            }
        }
        _ => next_u64(rng),
    }
}

fn same_f32_3(got: u64, want: u64, op: &str, a: u32, b: u32, c: u32, i: u64) {
    let gn = F32::from_bits(got).is_nan();
    let wn = f32::from_bits(want as u32).is_nan();
    if gn || wn {
        assert!(
            gn && wn,
            "{op} f32 NaN不一致 i={i} a={a:#x} b={b:#x} c={c:#x} got={got:#x} want={want:#x}"
        );
        return;
    }
    assert_eq!(
        got as u32, want as u32,
        "{op} f32 不一致 i={i} a={a:#x} b={b:#x} c={c:#x}"
    );
}

fn same_f64_3(got: u64, want: u64, op: &str, a: u64, b: u64, c: u64, i: u64) {
    let gn = F64::from_bits(got).is_nan();
    let wn = f64::from_bits(want).is_nan();
    if gn || wn {
        assert!(
            gn && wn,
            "{op} f64 NaN不一致 i={i} a={a:#x} b={b:#x} c={c:#x} got={got:#x} want={want:#x}"
        );
        return;
    }
    assert_eq!(
        got, want,
        "{op} f64 不一致 i={i} a={a:#x} b={b:#x} c={c:#x}"
    );
}

fn same_f32(got: u64, want: u64, op: &str, a: u32, b: u32, i: u64) {
    let gn = F32::from_bits(got).is_nan();
    let wn = f32::from_bits(want as u32).is_nan();
    if gn || wn {
        assert!(
            gn && wn,
            "{op} f32 NaN不一致 i={i} a={a:#x} b={b:#x} got={got:#x} want={want:#x}"
        );
        return;
    }
    assert_eq!(
        got as u32, want as u32,
        "{op} f32 不一致 i={i} a={a:#x} b={b:#x}"
    );
}

fn same_f64(got: u64, want: u64, op: &str, a: u64, b: u64, i: u64) {
    let gn = F64::from_bits(got).is_nan();
    let wn = f64::from_bits(want).is_nan();
    if gn || wn {
        assert!(
            gn && wn,
            "{op} f64 NaN不一致 i={i} a={a:#x} b={b:#x} got={got:#x} want={want:#x}"
        );
        return;
    }
    assert_eq!(got, want, "{op} f64 不一致 i={i} a={a:#x} b={b:#x}");
}

const N: u64 = 30_000;

#[test]
fn host_diff_f32() {
    let mut rng = 0x1234_5678_9ABC_DEF0u64;
    for i in 0..N {
        let a = pat32(&mut rng, i);
        let b = pat32(&mut rng, i.wrapping_mul(0x9E37_79B9).wrapping_add(1));
        let fa = f32::from_bits(a);
        let fb = f32::from_bits(b);
        same_f32(
            F32::from_bits(a as u64)
                .add(F32::from_bits(b as u64))
                .0
                .bits(),
            (fa + fb).to_bits() as u64,
            "add",
            a,
            b,
            i,
        );
        same_f32(
            F32::from_bits(a as u64)
                .sub(F32::from_bits(b as u64))
                .0
                .bits(),
            (fa - fb).to_bits() as u64,
            "sub",
            a,
            b,
            i,
        );
        same_f32(
            F32::from_bits(a as u64)
                .mul(F32::from_bits(b as u64))
                .0
                .bits(),
            (fa * fb).to_bits() as u64,
            "mul",
            a,
            b,
            i,
        );
        same_f32(
            F32::from_bits(a as u64)
                .div(F32::from_bits(b as u64))
                .0
                .bits(),
            (fa / fb).to_bits() as u64,
            "div",
            a,
            b,
            i,
        );
        same_f32(
            F32::from_bits(a as u64).sqrt().0.bits(),
            fa.sqrt().to_bits() as u64,
            "sqrt",
            a,
            0,
            i,
        );
        let c = pat32(&mut rng, i.wrapping_mul(0x9E37_79B9).wrapping_add(2));
        same_f32_3(
            F32::from_bits(a as u64)
                .fmadd(F32::from_bits(b as u64), F32::from_bits(c as u64))
                .0
                .bits(),
            fa.mul_add(fb, f32::from_bits(c)).to_bits() as u64,
            "fmadd",
            a,
            b,
            c,
            i,
        );
    }
}

#[test]
fn host_diff_f64() {
    let mut rng = 0xFEDC_BA98_7654_3210u64;
    for i in 0..N {
        let a = pat64(&mut rng, i);
        let b = pat64(&mut rng, i.wrapping_mul(0x9E37_79B9).wrapping_add(1));
        let fa = f64::from_bits(a);
        let fb = f64::from_bits(b);
        same_f64(
            F64::from_bits(a).add(F64::from_bits(b)).0.bits(),
            (fa + fb).to_bits(),
            "add",
            a,
            b,
            i,
        );
        same_f64(
            F64::from_bits(a).sub(F64::from_bits(b)).0.bits(),
            (fa - fb).to_bits(),
            "sub",
            a,
            b,
            i,
        );
        same_f64(
            F64::from_bits(a).mul(F64::from_bits(b)).0.bits(),
            (fa * fb).to_bits(),
            "mul",
            a,
            b,
            i,
        );
        same_f64(
            F64::from_bits(a).div(F64::from_bits(b)).0.bits(),
            (fa / fb).to_bits(),
            "div",
            a,
            b,
            i,
        );
        same_f64(
            F64::from_bits(a).sqrt().0.bits(),
            fa.sqrt().to_bits(),
            "sqrt",
            a,
            0,
            i,
        );
        let c = pat64(&mut rng, i.wrapping_mul(0x9E37_79B9).wrapping_add(2));
        same_f64_3(
            F64::from_bits(a)
                .fmadd(F64::from_bits(b), F64::from_bits(c))
                .0
                .bits(),
            fa.mul_add(fb, f64::from_bits(c)).to_bits(),
            "fmadd",
            a,
            b,
            c,
            i,
        );
    }
}
