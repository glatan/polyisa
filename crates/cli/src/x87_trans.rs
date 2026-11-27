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
    let mut ef = i32::from(exp_word & 0x7fff);
    let mut sig = sig;
    if ef == 0 && sig != 0 {
        let lz = sig.leading_zeros() as i32;
        sig <<= lz;
        ef = 1 - lz;
    }
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

pub(crate) fn log2_near_one(x: Dd) -> Dd {
    // ln(x)=2*(z+z^3/3+...), z=(x-1)/(x+1)。oracle の binary
    // corpus は x を 1 の近傍に寄せている。収束が遅い場合でも
    // double-double の精度内へ入るまで項を進める。
    let z = x.sub(Dd::from_f64(1.0)).div(x.add(Dd::from_f64(1.0)));
    let z2 = z.mul(z);
    let mut sum = z;
    let mut term = z;
    for n in 1u32..512 {
        term = term.mul(z2);
        let add = term.div(Dd::from_f64(f64::from(2 * n + 1)));
        let next = sum.add(add);
        if next.hi == sum.hi && next.lo == sum.lo {
            break;
        }
        sum = next;
    }
    sum.mul(Dd::from_f64(2.0)).div(LN2)
}

pub(crate) fn ext_mantissa_exp_dd(sig: u64, exp_word: u16) -> (Dd, i32) {
    let lz = sig.leading_zeros() as i32;
    let nsig = sig << lz;
    let raw_exp = i32::from(exp_word & 0x7fff);
    let exp = if raw_exp == 0 {
        1 - lz - 16383
    } else {
        raw_exp - lz - 16383
    };
    let hi_part = nsig >> 11;
    let lo_part = nsig & 0x7ff;
    let hi = (hi_part as f64) * 2f64.powi(-52);
    let lo = (lo_part as f64) * 2f64.powi(-63);
    let out = Dd::new(hi, lo);
    (
        if exp_word & 0x8000 != 0 {
            out.neg()
        } else {
            out
        },
        exp,
    )
}

pub(crate) fn log2_positive_ext(sig: u64, exp_word: u16) -> Dd {
    let (m, e) = ext_mantissa_exp_dd(sig, exp_word);
    log2_near_one(m).add(Dd::from_f64(f64::from(e)))
}

pub(crate) const PI: Dd = Dd {
    hi: std::f64::consts::PI,
    lo: 1.2246467991473532e-16,
};
pub(crate) const PI2: Dd = Dd {
    hi: std::f64::consts::FRAC_PI_2,
    lo: 6.123233995736766e-17,
};

pub(crate) fn sqrt_positive(x: Dd) -> Dd {
    let mut y = Dd::from_f64((x.hi + x.lo).sqrt());
    for _ in 0..5 {
        y = y.add(x.div(y)).div(Dd::from_f64(2.0));
    }
    y
}

pub(crate) fn atan_core(r: Dd) -> Dd {
    let neg = r.hi < 0.0 || (r.hi == 0.0 && r.lo < 0.0);
    let mut z = if neg { r.neg() } else { r };
    let mut steps = 0u32;
    while z.hi.abs() > 0.25 && steps < 8 {
        let one = Dd::from_f64(1.0);
        z = z.div(one.add(sqrt_positive(one.add(z.mul(z)))));
        steps += 1;
    }
    let z2 = z.mul(z);
    let mut sum = z;
    let mut term = z;
    for n in 1u32..128 {
        term = term.mul(z2).neg();
        let next = sum.add(term.div(Dd::from_f64(f64::from(2 * n + 1))));
        if next.hi == sum.hi && next.lo == sum.lo {
            break;
        }
        sum = next;
    }
    for _ in 0..steps {
        sum = sum.mul(Dd::from_f64(2.0));
    }
    if neg { sum.neg() } else { sum }
}

pub(crate) fn atan2_dd(y: Dd, x: Dd) -> Dd {
    let xneg = x.hi < 0.0 || (x.hi == 0.0 && x.lo < 0.0);
    let yneg = y.hi < 0.0 || (y.hi == 0.0 && y.lo < 0.0);
    let base = atan_core(y.div(x));
    if !xneg {
        base
    } else if yneg {
        base.sub(PI)
    } else {
        base.add(PI)
    }
}

pub(crate) const INV_PI2: Dd = Dd {
    hi: std::f64::consts::FRAC_2_PI,
    lo: -3.935735687792394e-17,
};

fn nearby_int(x: f64) -> i64 {
    x.round() as i64
}

// x87 が内部で使う 66 bit の π/2 近似。Intel が示す
// π のビット列 C90FDAA2 2168C234 C を有限値として保持する。
const HW_PI2_P68: u128 = 0xC90FDAA2_2168C234C;
pub(crate) fn hw_pi2() -> Dd {
    let hi_int = HW_PI2_P68 >> 15;
    let lo_int = HW_PI2_P68 & ((1u128 << 15) - 1);
    Dd::new(
        (hi_int as f64) * 2f64.powi(-52),
        (lo_int as f64) * 2f64.powi(-67),
    )
}

/// trig 用の π/2 単位の引数削減。x87 と同じ 66 bit の π/2
/// 近似を使い、戻り値は残余と象限。
pub(crate) fn reduce_pi2(x: Dd) -> (Dd, i64) {
    let qf = x.mul(INV_PI2).hi;
    let q = nearby_int(qf);
    if q == 0 {
        return (x, 0);
    }
    let qd = Dd::from_f64(q as f64);
    let r = x.sub(qd.mul(hw_pi2()));
    (r, q)
}

pub(crate) fn sin_reduced(x: Dd) -> Dd {
    let (r, q) = reduce_pi2(x);
    match q.rem_euclid(4) {
        0 => sin_small(r),
        1 => cos_small(r),
        2 => sin_small(r).neg(),
        _ => cos_small(r).neg(),
    }
}

pub(crate) fn cos_reduced(x: Dd) -> Dd {
    let (r, q) = reduce_pi2(x);
    match q.rem_euclid(4) {
        0 => cos_small(r),
        1 => sin_small(r).neg(),
        2 => cos_small(r).neg(),
        _ => sin_small(r),
    }
}
