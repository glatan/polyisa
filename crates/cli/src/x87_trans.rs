// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! x87 transcendental evaluation support.
//!
//! The first evaluation layer is double-double arithmetic.  It keeps about
//! 106 significant bits so that a result can be rounded once to the x87
//! 64-bit significand without the 53-bit truncation of the legacy host-f64
//! implementation.

#![allow(dead_code)]

#[derive(Clone, Copy, Debug)]
pub(crate) struct Dd {
    pub hi: f64,
    pub lo: f64,
}

impl Dd {
    pub fn new(hi: f64, lo: f64) -> Self {
        Self { hi, lo }
    }

    pub fn from_f64(x: f64) -> Self {
        Self::new(x, 0.0)
    }

    fn quick_two_sum(a: f64, b: f64) -> (f64, f64) {
        let s = a + b;
        let e = b - (s - a);
        (s, e)
    }

    fn two_sum(a: f64, b: f64) -> (f64, f64) {
        let s = a + b;
        let bp = s - a;
        let ap = s - bp;
        let be = b - bp;
        let ae = a - ap;
        (s, ae + be)
    }

    pub fn add(self, rhs: Self) -> Self {
        let (s, e) = Self::two_sum(self.hi, rhs.hi);
        let lo = self.lo + rhs.lo + e;
        let (hi, lo) = Self::quick_two_sum(s, lo);
        Self::new(hi, lo)
    }

    pub fn sub(self, rhs: Self) -> Self {
        self.add(Self::new(-rhs.hi, -rhs.lo))
    }

    pub fn mul(self, rhs: Self) -> Self {
        let p = self.hi * rhs.hi;
        let e = self.hi.mul_add(rhs.hi, -p);
        let lo = self.hi.mul_add(rhs.lo, self.lo * rhs.hi) + e;
        let (hi, lo) = Self::quick_two_sum(p, lo);
        Self::new(hi, lo)
    }

    pub fn div(self, rhs: Self) -> Self {
        let q1 = self.hi / rhs.hi;
        let r = self.sub(rhs.mul(Self::from_f64(q1)));
        let q2 = r.hi / rhs.hi;
        let (hi, lo) = Self::quick_two_sum(q1, q2);
        Self::new(hi, lo)
    }

    pub fn neg(self) -> Self {
        Self::new(-self.hi, -self.lo)
    }
}

/// Exact 80-bit finite input as a double-double value.  The 64-bit
/// significand is split at its f64-significand boundary so no low bit is
/// discarded before the transcendental evaluation.
pub(crate) fn ext_to_dd(sig: u64, exp_word: u16) -> Dd {
    let ef = i32::from(exp_word & 0x7fff);
    let hi_part = sig >> 11;
    let lo_part = sig & 0x7ff;
    let scale_hi = (ef - 16383 - 52) as f64;
    let scale_lo = (ef - 16383 - 63) as f64;
    let hi = (hi_part as f64) * scale_hi.exp2();
    let lo = (lo_part as f64) * scale_lo.exp2();
    let out = Dd::new(hi, lo);
    if exp_word & 0x8000 != 0 {
        out.neg()
    } else {
        out
    }
}

/// ln(2) split into a double-double constant.
pub(crate) const LN2: Dd = Dd {
    hi: std::f64::consts::LN_2,
    lo: 2.3190468138462996e-17,
};

pub(crate) fn expm1_small(x: Dd) -> Dd {
    // expm1(x ln2) の Taylor 級数。oracle の valid-range 入力は
    // |x| < 1 なので、106 bit の double-double では数十項で収束する。
    let t = x.mul(LN2);
    let mut sum = t;
    let mut term = t;
    for n in 2u32..48 {
        term = term.mul(t).div(Dd::from_f64(f64::from(n)));
        let next = sum.add(term);
        if next.hi == sum.hi && next.lo == sum.lo {
            break;
        }
        sum = next;
    }
    sum
}

fn f64_parts(x: f64) -> (u64, i32) {
    let bits = x.to_bits();
    let raw = ((bits >> 52) & 0x7ff) as i32;
    let frac = bits & ((1u64 << 52) - 1);
    if raw == 0 {
        // ここで扱う transcendental の有限結果は zero か正規数なので、
        // subnormal は zero 側へ潰す。入力拡張自体は exact に扱っている。
        (frac, -1074)
    } else {
        ((1u64 << 52) | frac, raw - 1023)
    }
}

/// double-double の positive finite 値を 80 bit extended へ丸める。
/// nearest のほか、FCW の truncation/floor/ceil に対応する。DD 自身の
/// 誤差は残るが、53 bit 変換とは違って下位 11 bit も使う。
pub(crate) fn dd_to_ext(value: Dd, rc: u16) -> (u64, u16) {
    if value.hi == 0.0 && value.lo == 0.0 {
        return (
            0,
            if value.hi.is_sign_negative() {
                0x8000
            } else {
                0
            },
        );
    }
    let neg = value.hi.is_sign_negative();
    let v = if neg { value.neg() } else { value };
    let (hf, eh) = f64_parts(v.hi);
    // hi を 64 bit significand の上位 53 bit へ置き、lo を同じ quantum
    // へ換算して足す。lo_units の小数部が round/sticky を兼ねる。
    let hi_units = hf << 11;
    let scale = (63 - eh) as f64;
    let lo_scaled = v.lo * scale.exp2();
    let nearest = lo_scaled.round() as i64;
    let units = match rc {
        // extended の magnitude を丸めているので、負数の floor と
        // 正数の ceil だけ magnitude を大きくする。truncation は
        // 符号に関係なく magnitude を小さくする。
        1 if neg => lo_scaled.ceil() as i64,
        1 => lo_scaled.floor() as i64,
        2 if neg => lo_scaled.floor() as i64,
        2 => lo_scaled.ceil() as i64,
        3 => lo_scaled.floor() as i64,
        _ => nearest,
    };
    let sig64 = hi_units as i128 + i128::from(units);
    let mut sig = sig64 as u64;
    let mut exp = eh + 16383;
    if sig == 0 {
        return (0, if neg { 0x8000 } else { 0 });
    }
    if sig64 >= 1i128 << 64 {
        sig >>= 1;
        exp += 1;
    }
    (sig, (exp as u16) | if neg { 0x8000 } else { 0 })
}

pub(crate) fn sin_small(x: Dd) -> Dd {
    let x2 = x.mul(x);
    let mut sum = x;
    let mut term = x;
    for n in 1u32..32 {
        let den = f64::from((2 * n) * (2 * n + 1));
        term = term.mul(x2).div(Dd::from_f64(den)).neg();
        let next = sum.add(term);
        if next.hi == sum.hi && next.lo == sum.lo {
            break;
        }
        sum = next;
    }
    sum
}

pub(crate) fn cos_small(x: Dd) -> Dd {
    let x2 = x.mul(x);
    let mut sum = Dd::from_f64(1.0);
    let mut term = Dd::from_f64(1.0);
    for n in 1u32..32 {
        let den = f64::from((2 * n - 1) * (2 * n));
        term = term.mul(x2).div(Dd::from_f64(den)).neg();
        let next = sum.add(term);
        if next.hi == sum.hi && next.lo == sum.lo {
            break;
        }
        sum = next;
    }
    sum
}
