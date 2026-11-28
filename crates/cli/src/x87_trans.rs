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
pub(crate) struct ExtRounded {
    pub sig: u64,
    pub exp: u16,
    pub normal_sig: u64,
    pub normal_exp: i32,
    pub tiny: bool,
}

pub(crate) fn dd_to_ext(value: Dd, rc: u16) -> (u64, u16) {
    let r = dd_to_ext_scaled_meta(value, 0, rc);
    (r.sig, r.exp)
}

pub(crate) fn dd_to_ext_scaled(value: Dd, scale_exp: i32, rc: u16) -> (u64, u16) {
    let r = dd_to_ext_scaled_meta(value, scale_exp, rc);
    (r.sig, r.exp)
}

fn round_units(units: i128, frac: f64, shift: u32, rc: u16, neg: bool) -> u128 {
    if units <= 0 {
        return 0;
    }
    let (q, rem, half) = if shift >= 128 {
        (0u128, 0u128, 0u128)
    } else {
        let u = units as u128;
        (
            u >> shift,
            if shift == 0 {
                0
            } else {
                u & ((1u128 << shift) - 1)
            },
            if shift == 0 { 0 } else { 1u128 << (shift - 1) },
        )
    };
    let any = rem != 0 || frac != 0.0;
    // shift=0 では rem/half がともに 0 に潰れるので、frac を量子の半分
    // 0.5 と直接比較する。shift>=1 では rem+frac と half の比較は
    // `rem > half || (rem == half && frac > 0)` で正確（frac < 1 より
    // rem < half なら rem+frac < half、rem==half では frac が決め手）。
    let (over_half, at_half) = if shift == 0 {
        (frac > 0.5, frac == 0.5)
    } else {
        (
            rem > half || (rem == half && frac > 0.0),
            rem == half && frac == 0.0,
        )
    };
    let up = match rc {
        1 => neg && any,
        2 => !neg && any,
        3 => false,
        _ => over_half || (at_half && q & 1 != 0),
    };
    q + u128::from(up)
}

pub(crate) fn dd_to_ext_scaled_meta(value: Dd, scale_exp: i32, rc: u16) -> ExtRounded {
    if value.hi == 0.0 && value.lo == 0.0 {
        let exp = if value.hi.is_sign_negative() {
            0x8000
        } else {
            0
        };
        return ExtRounded {
            sig: 0,
            exp,
            normal_sig: 0,
            normal_exp: 0,
            tiny: false,
        };
    }
    let neg = value.hi.is_sign_negative();
    let v = if neg { value.neg() } else { value };
    let (hf, eh) = f64_parts(v.hi);
    // hi を 64 bit significand の整数単位へ置き、lo を同じ量子へ換算する。
    // そのままでは extended 全 exponent を f64 が表せないので、符号・
    // 指数を分離したまま最終 quantum へ一度だけ丸める。
    let hi_units = u128::from(hf) << 11;
    let scale = (63 - eh) as f64;
    let lo_scaled = v.lo * scale.exp2();
    let lo_floor = lo_scaled.floor() as i128;
    let frac = lo_scaled - lo_floor as f64;
    let units = hi_units as i128 + lo_floor;
    let unbiased = eh + scale_exp;
    let normal_rounded = round_units(units, frac, 0, rc, neg);
    let mut normal_sig = normal_rounded as u64;
    let mut normal_exp = unbiased + 16383;
    if normal_rounded >= 1u128 << 64 {
        normal_sig = (normal_rounded >> 1) as u64;
        normal_exp += 1;
    } else if normal_rounded != 0 && normal_rounded < 1u128 << 63 {
        // hi がちょうど 2^n で lo が負の微小量だと、units は 2^63 を
        // わずかに割り、整数 bit の落ちた非正規形になる。extended の
        // normal は bit63 を立てる必要があるので 1 bit 左へそろえて
        // exponent を下げる。dd の lo は hi の 2^-53 級までなので、
        // ずれは 1 bit を超えない。cos の微小入力で 1.0 直前の値が
        // この経路を通る。
        normal_sig = (normal_rounded << 1) as u64;
        normal_exp -= 1;
    }
    if unbiased >= -16382 {
        return ExtRounded {
            sig: normal_sig,
            exp: (normal_exp.clamp(0, 0x7fff) as u16) | if neg { 0x8000 } else { 0 },
            normal_sig,
            normal_exp,
            tiny: false,
        };
    }
    let shift = (-(unbiased + 16382)) as u32;
    let rounded = round_units(units, frac, shift, rc, neg);
    if rounded == 0 {
        return ExtRounded {
            sig: 0,
            exp: if neg { 0x8000 } else { 0 },
            normal_sig,
            normal_exp,
            tiny: true,
        };
    }
    // denormal quantum と exponent 1 の quantum は連続している。bit63
    // まで丸め上がれば最小正規数側の encoding になる。
    let exp = if rounded >= 1u128 << 63 { 1u16 } else { 0u16 };
    ExtRounded {
        sig: rounded as u64,
        exp: exp | if neg { 0x8000 } else { 0 },
        normal_sig,
        normal_exp,
        tiny: true,
    }
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
    if sig == 0 {
        return (Dd::from_f64(0.0), 0);
    }
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

/// denormal quantum を単位とした significand に、64 bit significand の
/// 正係数を掛けて一度だけ丸める。`coeff_scale` は係数の binary scaling。
/// 返り値は同じ quantum を単位とする整数で、bit63 が立てば exponent 1
/// の最小正規数側へ連続的に移る。
pub(crate) fn mul_denormal_units(
    sig: u64,
    coeff_sig: u64,
    coeff_scale: u32,
    rc: u16,
    neg: bool,
) -> u128 {
    let n = u128::from(sig) * u128::from(coeff_sig);
    let q = n >> coeff_scale;
    let rem = n & ((1u128 << coeff_scale) - 1);
    let half = 1u128 << (coeff_scale - 1);
    let up = match rc {
        1 => neg && rem != 0,
        2 => !neg && rem != 0,
        3 => false,
        _ => rem > half || (rem == half && q & 1 != 0),
    };
    q + u128::from(up)
}

pub(crate) fn denormal_units_to_ext(units: u128, neg: bool) -> (u64, u16) {
    if units == 0 {
        return (0, if neg { 0x8000 } else { 0 });
    }
    let exp = if units >= 1u128 << 63 { 1u16 } else { 0u16 };
    (units as u64, exp | if neg { 0x8000 } else { 0 })
}

fn scale_pow2(x: Dd, scale: i32) -> Dd {
    if x.hi == 0.0 && x.lo == 0.0 {
        return x;
    }
    let clamped = scale.clamp(-2047, 2047);
    let f = 2f64.powi(clamped);
    Dd::new(x.hi * f, x.lo * f)
}

/// exponent 分離した extended 入力の atan2。比值そのものを f64 経路で
/// オーバーフローさせず、大きな比では逆数側へ落として atan を評価する。
pub(crate) fn atan2_ext(ysig: u64, yexp_word: u16, xsig: u64, xexp_word: u16) -> Dd {
    let yneg = yexp_word & 0x8000 != 0;
    let xneg = xexp_word & 0x8000 != 0;
    let (ym, ye) = ext_mantissa_exp_dd(ysig, yexp_word & 0x7fff);
    let (xm, xe) = ext_mantissa_exp_dd(xsig, xexp_word & 0x7fff);
    let scale = ye - xe;
    let magnitude = if scale >= 0 {
        // |y/x| が大きいときは atan(r)=pi/2-atan(1/r)。
        let inv = scale_pow2(xm.div(ym), -scale);
        PI2.sub(atan_core(inv))
    } else {
        atan_core(scale_pow2(ym.div(xm), scale))
    };
    let angle = if !xneg { magnitude } else { PI.sub(magnitude) };
    if yneg { angle.neg() } else { angle }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct U256([u64; 4]);

impl U256 {
    fn zero() -> Self {
        Self([0; 4])
    }

    fn shl64(x: u64, shift: u32) -> Self {
        let mut out = Self::zero();
        let limb = (shift / 64) as usize;
        let bits = shift % 64;
        if limb < 4 {
            out.0[limb] = x << bits;
            if bits != 0 && limb + 1 < 4 {
                out.0[limb + 1] = x >> (64 - bits);
            }
        }
        out
    }

    fn mul_u64_u128(x: u64, y: u128) -> Self {
        let y0 = y as u64;
        let y1 = (y >> 64) as u64;
        let a = u128::from(x) * u128::from(y0);
        let b = u128::from(x) * u128::from(y1) + (a >> 64);
        Self([a as u64, b as u64, (b >> 64) as u64, 0])
    }

    fn cmp(self, rhs: Self) -> core::cmp::Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&rhs.0[i]) {
                core::cmp::Ordering::Equal => {}
                ord => return ord,
            }
        }
        core::cmp::Ordering::Equal
    }

    fn sub(self, rhs: Self) -> Self {
        let mut out = [0u64; 4];
        let mut borrow = false;
        for i in 0..4 {
            let (v, b1) = self.0[i].overflowing_sub(rhs.0[i]);
            let (v, b2) = v.overflowing_sub(u64::from(borrow));
            out[i] = v;
            borrow = b1 || b2;
        }
        Self(out)
    }

    fn is_zero(self) -> bool {
        self.0.iter().all(|v| *v == 0)
    }

    fn bit(self, pos: u32) -> bool {
        let limb = (pos / 64) as usize;
        limb < 4 && self.0[limb] >> (pos % 64) & 1 != 0
    }

    fn highest(self) -> Option<u32> {
        for i in (0..4).rev() {
            if self.0[i] != 0 {
                return Some(i as u32 * 64 + (63 - self.0[i].leading_zeros()));
            }
        }
        None
    }

    fn extract_low(self, bits: u32) -> u64 {
        let mut out = 0u64;
        for pos in 0..bits.min(64) {
            if self.bit(pos) {
                out |= 1u64 << pos;
            }
        }
        out
    }

    fn extract_high53(self, top: u32) -> u64 {
        let low = top.saturating_sub(52);
        let mut out = 0u64;
        for bit in 0..53u32 {
            if self.bit(low + bit) {
                out |= 1u64 << bit;
            }
        }
        out
    }
}

fn nearest_integer_dd(x: Dd) -> i64 {
    let base_floor = x.hi.floor();
    let base = base_floor as i64;
    let frac = (x.hi - base_floor) + x.lo;
    base + frac.round() as i64
}

fn exact_residue_pi2(sig: u64, exp_word: u16, q: u64) -> Dd {
    // 入力は sig*2^(E-63)、x87 の π/2 近似は P68*2^-67。
    // 両者を 2^-67 quantum の整数へそろえ、qP を正確に引く。
    let lz = sig.leading_zeros() as i32;
    let nsig = sig << lz;
    let raw_exp = i32::from(exp_word & 0x7fff);
    let effective = if raw_exp == 0 { 1 - lz } else { raw_exp - lz };
    let unbiased = effective - 16383;
    let shift = unbiased - 63 + 67;
    if !(0..=96).contains(&shift) {
        // trig の valid domain では正規入力はここへ来る。denormal や
        // 小さい入力は q=0 側で処理する。
        return ext_to_dd(sig, exp_word);
    }
    let xu = U256::shl64(nsig, shift as u32);
    let pu = U256::mul_u64_u128(q, HW_PI2_P68);
    let negative = xu.cmp(pu) == core::cmp::Ordering::Less;
    let mag = if negative { pu.sub(xu) } else { xu.sub(pu) };
    if mag.is_zero() {
        return Dd::from_f64(0.0);
    }
    let Some(top) = mag.highest() else {
        return Dd::from_f64(0.0);
    };
    let high_bits = top.min(52);
    let hi_int = mag.extract_high53(top);
    let low_pos = top - high_bits;
    let hi = (hi_int as f64) * 2f64.powi(low_pos as i32 - 67);
    let low_bits = top.saturating_sub(52);
    let lo_int = mag.extract_low(low_bits);
    let lo = (lo_int as f64) * 2f64.powi(-67);
    let out = Dd::new(hi, lo);
    if negative { out.neg() } else { out }
}

/// positive finite extended 入力を x87 の有限 π/2 で正確に引数削減する。
/// 商は double-double で十分な精度で求め、剰余は整数 bit 列で計算する。
pub(crate) fn reduce_pi2_positive_ext(sig: u64, exp_word: u16) -> (Dd, i64) {
    let x = ext_to_dd(sig, exp_word & 0x7fff);
    let qf = x.mul(Dd::from_f64(1.0).div(hw_pi2()));
    let qi = nearest_integer_dd(qf);
    if qi == 0 {
        return (x, 0);
    }
    (exact_residue_pi2(sig, exp_word & 0x7fff, qi as u64), qi)
}

pub(crate) fn sin_reduced_ext(sig: u64, exp_word: u16) -> Dd {
    let neg = exp_word & 0x8000 != 0;
    let (r, q) = reduce_pi2_positive_ext(sig, exp_word);
    let mag = match q.rem_euclid(4) {
        0 => sin_small(r),
        1 => cos_small(r),
        2 => sin_small(r).neg(),
        _ => cos_small(r).neg(),
    };
    if neg { mag.neg() } else { mag }
}

pub(crate) fn cos_reduced_ext(sig: u64, exp_word: u16) -> Dd {
    let (r, q) = reduce_pi2_positive_ext(sig, exp_word);
    match q.rem_euclid(4) {
        0 => cos_small(r),
        1 => sin_small(r).neg(),
        2 => cos_small(r).neg(),
        _ => sin_small(r),
    }
}
