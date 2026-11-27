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
