//! ソフトウェア浮動小数点。ホストの FPU を使わず、整数演算で実装する。
//!
//! 出典は SPEC-IEEE754 の版 2019 である。数値・丸め規則の事実のみを自前の表現で使う。
//! 条文・図表の複製はしない。丸めは最近接偶数（RNE）のみであり、
//! 動的丸めと例外フラグは `FpEnv` の導入時に足す。
//!
//! 形式はビット幅で汎化する。`F32` は `Binary<8, 23>`、`F64` は `Binary<11, 52>` である。
// Ref: SPEC-IEEE754 (2019).

#![forbid(unsafe_code)]

/// 指数 E ビット、仮数 M ビットの二進浮動小数点。符号 1 ビットを含め `1 + E + M <= 64` とする。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Binary<const E: u32, const M: u32> {
    bits: u64,
}

/// 32 ビット形式。
pub type F32 = Binary<8, 23>;
/// 64 ビット形式。
pub type F64 = Binary<11, 52>;

// 演算名は `Backend` の語彙に合わせる。`std::ops` は実装しない。
#[allow(clippy::should_implement_trait)]
impl<const E: u32, const M: u32> Binary<E, M> {
    /// ビット列から作る。幅より上は切り捨てる。
    #[must_use]
    pub const fn from_bits(bits: u64) -> Self {
        Self {
            bits: bits & Self::mask(),
        }
    }

    /// ビット列を取り出す。
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.bits
    }

    const fn width() -> u32 {
        1 + E + M
    }

    const fn mask() -> u64 {
        if Self::width() >= 64 {
            u64::MAX
        } else {
            (1u64 << Self::width()) - 1
        }
    }

    const fn bias() -> i64 {
        ((1u64 << (E - 1)) - 1) as i64
    }

    const fn exp_max() -> u64 {
        (1u64 << E) - 1
    }

    /// 正のゼロ。
    #[must_use]
    pub const fn zero() -> Self {
        Self { bits: 0 }
    }

    /// 正の無限大。
    #[must_use]
    pub const fn inf(neg: bool) -> Self {
        Self {
            bits: ((neg as u64) << (E + M)) | (Self::exp_max() << M),
        }
    }

    /// 正準 NaN。RISC-V が伝搬に使う決定値である。
    #[must_use]
    pub const fn canonical_nan() -> Self {
        Self {
            bits: (Self::exp_max() << M) | (1u64 << (M - 1)),
        }
    }

    fn decode(self) -> (bool, u32, u64) {
        let neg = (self.bits >> (E + M)) & 1 == 1;
        let exp = ((self.bits >> M) & ((1u64 << E) - 1)) as u32;
        let frac = self.bits & ((1u64 << M) - 1);
        (neg, exp, frac)
    }

    /// NaN かどうか。ペイロードは問わない。
    #[must_use]
    pub fn is_nan(self) -> bool {
        let (_, exp, frac) = self.decode();
        exp == Self::exp_max() as u32 && frac != 0
    }

    /// 無限大かどうか。
    #[must_use]
    pub fn is_inf(self) -> bool {
        let (_, exp, frac) = self.decode();
        exp == Self::exp_max() as u32 && frac == 0
    }

    /// ゼロかどうか。符号は問わない。
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.bits & Self::mask() & ((1u64 << (E + M)) - 1) == 0
    }

    /// 加算。RNE。
    #[must_use]
    pub fn add(self, other: Self) -> Self {
        add_sub(self, other, false)
    }

    /// 減算。`a - b` は `a + (-b)` である。
    #[must_use]
    pub fn sub(self, other: Self) -> Self {
        add_sub(self, other, true)
    }

    /// 乗算。RNE。
    #[must_use]
    pub fn mul(self, other: Self) -> Self {
        let (s1, e1, f1) = self.decode();
        let (s2, e2, f2) = other.decode();
        let neg = s1 ^ s2;
        if self.is_nan() || other.is_nan() {
            return Self::canonical_nan();
        }
        let inf1 = self.is_inf();
        let inf2 = other.is_inf();
        let zero1 = self.is_zero();
        let zero2 = other.is_zero();
        if (inf1 && zero2) || (zero1 && inf2) {
            return Self::canonical_nan();
        }
        if inf1 || inf2 {
            return Self::inf(neg);
        }
        if zero1 || zero2 {
            return Self::zero_signed(neg);
        }
        let bias = Self::bias();
        let (ue1, m1) = expand(e1, f1, M, bias);
        let (ue2, m2) = expand(e2, f2, M, bias);
        // 積は最大で 2M+2 ビット。窓 [2^P, 2^(P+1))（P = M+3）に寄せる。
        // 不変条件：値は m * 2^(e-M-3) である。
        let p = m1 * m2;
        let bitlen = 128 - p.leading_zeros() as i64;
        let shift = (bitlen - 1) - (M as i64 + 3);
        let mut e = ue1 + ue2 - M as i64 + 3 + shift;
        let mut m: u128;
        let mut sticky: i8 = 0;
        if shift >= 0 {
            let s = shift as u32;
            if s >= 128 {
                sticky = (p != 0) as i8;
                m = 0;
            } else {
                sticky = (s > 0 && (p & ((1u128 << s) - 1)) != 0) as i8;
                m = p >> s;
            }
        } else {
            m = p << (-shift as u32);
        }
        // m == 0 にはならない（入力が非ゼロのため）。正規化と丸めは共通化する。
        sticky = normalize_window::<E, M>(&mut e, &mut m, sticky);
        finish::<E, M>(neg, &mut e, &mut m, sticky)
    }

    /// 除算。RNE。
    #[must_use]
    pub fn div(self, other: Self) -> Self {
        let (s1, e1, f1) = self.decode();
        let (s2, e2, f2) = other.decode();
        let neg = s1 ^ s2;
        if self.is_nan() || other.is_nan() {
            return Self::canonical_nan();
        }
        let inf1 = self.is_inf();
        let inf2 = other.is_inf();
        let zero1 = self.is_zero();
        let zero2 = other.is_zero();
        if (inf1 && inf2) || (zero1 && zero2) {
            return Self::canonical_nan();
        }
        if inf1 || zero2 {
            return Self::inf(neg);
        }
        if zero1 || inf2 {
            return Self::zero_signed(neg);
        }
        let bias = Self::bias();
        let (ue1, m1) = expand(e1, f1, M, bias);
        let (ue2, m2) = expand(e2, f2, M, bias);
        // 商を M+3 ビットの窓に寄せる。余りは sticky に畳む。
        // m1 は最大 M+1 ビット、m2 は最小 1 ビットなので shift >= 3 が常に成り立つ。
        let shift = M as i64 + 3 + (bitlen_u128(m2) - bitlen_u128(m1));
        debug_assert!(shift >= 0);
        let num = m1 << shift as u32;
        let m = num / m2;
        let sticky = u8::from(!num.is_multiple_of(m2)) as i8;
        let mut e = ue1 - ue2 - shift + M as i64 + 3;
        let mut m = m;
        let sticky = normalize_window::<E, M>(&mut e, &mut m, sticky);
        finish::<E, M>(neg, &mut e, &mut m, sticky)
    }

    fn zero_signed(neg: bool) -> Self {
        Self {
            bits: (neg as u64) << (E + M),
        }
    }
}

/// 指数部と仮数部を、符号なし指数と整数の仮数（隠れビット付き）にほどく。
/// 非正規数は指数を emin、隠れビットなしとして扱う。
fn expand(exp: u32, frac: u64, m_bits: u32, bias: i64) -> (i64, u128) {
    if exp == 0 {
        (1 - bias, u128::from(frac))
    } else {
        (i64::from(exp) - bias, u128::from(frac) | (1u128 << m_bits))
    }
}

fn bitlen_u128(mut v: u128) -> i64 {
    let mut n = 0;
    while v != 0 {
        v >>= 1;
        n += 1;
    }
    n
}

/// 加減算の中核。`flip` が真のとき第 2 引数の符号を反転する。
fn add_sub<const E: u32, const M: u32>(
    a: Binary<E, M>,
    b: Binary<E, M>,
    flip: bool,
) -> Binary<E, M> {
    let (s1, e1, f1) = a.decode();
    let (mut s2, e2, f2) = b.decode();
    if flip {
        s2 = !s2;
    }
    if a.is_nan() || b.is_nan() {
        return Binary::canonical_nan();
    }
    let inf1 = a.is_inf();
    let inf2 = b.is_inf();
    if inf1 && inf2 {
        if s1 == s2 {
            return Binary::inf(s1);
        }
        return Binary::canonical_nan();
    }
    if inf1 {
        return Binary::inf(s1);
    }
    if inf2 {
        return Binary::inf(s2);
    }
    let zero1 = a.is_zero();
    let zero2 = b.is_zero();
    if zero1 && zero2 {
        // RNE では +0。-0 + -0 のみ -0 になる。
        return Binary::zero_signed(s1 && s2);
    }
    if zero1 {
        return Binary::from_bits(b.bits & Binary::<E, M>::mask() | ((s2 as u64) << (E + M)));
    }
    if zero2 {
        return Binary::from_bits(a.bits);
    }
    let bias = Binary::<E, M>::bias();
    let (ue1, f1e) = expand(e1, f1, M, bias);
    let (ue2, f2e) = expand(e2, f2, M, bias);
    // 3 ビットの余裕を持たせ、大きい指数に寄せる。
    // sticky は i8 で、0=正確、1=切り捨てた正の端数、-1=切り捨てた負の端数（減算時）を表す。
    let mut m1 = f1e << 3;
    let mut m2 = f2e << 3;
    let mut dropped = false;
    // 切り捨てた側のオペランドの符号。端数の符号はこれで決まる。
    let mut s_shifted: i8 = 0;
    let mut e = ue1;
    if ue1 > ue2 {
        let d = (ue1 - ue2) as u32;
        dropped = shr_jam(&mut m2, d);
        s_shifted = if s2 { -1 } else { 1 };
    } else if ue2 > ue1 {
        let d = (ue2 - ue1) as u32;
        dropped = shr_jam(&mut m1, d);
        s_shifted = if s1 { -1 } else { 1 };
        e = ue2;
    }
    // 丸めの判定に要るのは端数の有無と符号だけである（大きさは問わない）。
    // 符号は結果の符号と切り捨てた側の符号の積で決まる。
    let (mut m, neg) = if s1 == s2 {
        (m1 + m2, s1)
    } else if m1 >= m2 {
        (m1 - m2, s1)
    } else {
        (m2 - m1, s2)
    };
    if m == 0 {
        // exact zero は +0。切り捨てで残っただけなら切り捨てた側の符号になる。
        return Binary::zero_signed(dropped && s_shifted < 0);
    }
    let r_sign: i8 = if neg { -1 } else { 1 };
    let sticky: i8 = if dropped { r_sign * s_shifted } else { 0 };
    // 正規化。e は emin を下回りうる。下回り分は jam で寄せる。
    let sticky = normalize_window::<E, M>(&mut e, &mut m, sticky);
    finish::<E, M>(neg, &mut e, &mut m, sticky)
}

/// 正規化。窓 [2^(M+3), 2^(M+4)) に寄せ、emin を下回る分は jam で寄せる。
/// 戻り値は更新後の sticky である。`m == 0` では何もしない。
fn normalize_window<const E: u32, const M: u32>(e: &mut i64, m: &mut u128, sticky: i8) -> i8 {
    let emin = 1 - Binary::<E, M>::bias();
    let mut s = sticky;
    while *m >= (1u128 << (M + 4)) {
        if *m & 1 == 1 {
            s = 1;
        }
        *m >>= 1;
        *e += 1;
    }
    while *m != 0 && *m < (1u128 << (M + 3)) {
        *m <<= 1;
        *e -= 1;
    }
    if *m != 0 && *e < emin {
        let d = (emin - *e) as u32;
        // 落ちたビットがあれば正の端数になる。なければ符号を引き継ぐ。
        s = if shr_jam(m, d) { 1 } else { s };
        *e = emin;
    }
    s
}

/// 丸め（RNE）と符号化。`m` は下位 3 ビットを GRS とし、`sticky` を S に畳む。
/// 不変条件：値は `m * 2^(e-M-3)` である（丸めで下位 3 ビットを落とす）。
fn finish<const E: u32, const M: u32>(
    neg: bool,
    e: &mut i64,
    m: &mut u128,
    sticky: i8,
) -> Binary<E, M> {
    let bias = Binary::<E, M>::bias();
    // tie（下位 3 ビットが 100）のときだけ端数の符号が要る。
    // 正の端数は切り上げ、負の端数は切り捨て、なければ偶数丸めである。
    let r0 = *m & 0b111;
    let up = (r0 > 4) || (r0 == 4 && (sticky > 0 || (sticky == 0 && ((*m >> 3) & 1 == 1))));
    let mut sig = (*m >> 3) + u128::from(up);
    let mut exp = *e;
    if sig >= (1u128 << (M + 1)) {
        sig >>= 1;
        exp += 1;
    }
    let biased = exp + bias;
    let exp_max = (1i64 << E) - 1;
    if biased >= exp_max {
        return Binary::inf(neg);
    }
    // 隠れビットがなければ非正規数であり、指数部は 0 とする。
    // 正規化の保証により、この場合は exp == emin である。
    if sig >= (1u128 << M) {
        debug_assert!(biased >= 1);
        let frac = (sig & ((1u128 << M) - 1)) as u64;
        Binary::from_bits(((neg as u64) << (E + M)) | ((biased as u64) << M) | frac)
    } else {
        debug_assert!(exp == 1 - bias);
        Binary::from_bits(((neg as u64) << (E + M)) | sig as u64)
    }
}

/// 右に `d` ビット寄せ、落ちたビットを戻り値（sticky）に畳む。
fn shr_jam(m: &mut u128, d: u32) -> bool {
    if d == 0 {
        return false;
    }
    if d >= 128 {
        let s = *m != 0;
        *m = 0;
        return s;
    }
    let dropped = *m & ((1u128 << d) - 1);
    *m >>= d;
    dropped != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basics() {
        assert!(F64::canonical_nan().is_nan());
        assert!(F64::inf(false).is_inf());
        assert!(F32::zero().is_zero());
        assert_eq!(
            F64::from_bits(0x3ff0_0000_0000_0000).bits(),
            0x3ff0_0000_0000_0000
        );
    }

    #[test]
    fn one_plus_two() {
        let one = F64::from_bits(0x3ff0_0000_0000_0000);
        let two = F64::from_bits(0x4000_0000_0000_0000);
        assert_eq!(one.add(two).bits(), 0x4008_0000_0000_0000);
        assert_eq!(two.sub(one).bits(), one.bits());
        assert_eq!(one.mul(two).bits(), two.bits());
        assert_eq!(two.div(one).bits(), two.bits());
    }

    #[test]
    fn special_values() {
        let inf = F64::inf(false);
        let ninf = F64::inf(true);
        let zero = F64::zero();
        // inf + -inf は NaN。
        assert!(inf.add(ninf).is_nan());
        // 0/0 は NaN。
        assert!(zero.div(zero).is_nan());
        // 有限/0 は無限大。
        let one = F64::from_bits(0x3ff0_0000_0000_0000);
        assert_eq!(one.div(zero).bits(), inf.bits());
        // 0 * inf は NaN。
        assert!(zero.mul(inf).is_nan());
        // -0 + -0 は -0、それ以外は +0。
        let nzero = F64::from_bits(0x8000_0000_0000_0000);
        assert_eq!(nzero.add(nzero).bits(), nzero.bits());
        assert_eq!(nzero.add(zero).bits(), zero.bits());
    }

    #[test]
    fn f32_basic() {
        let one = F32::from_bits(0x3f80_0000);
        let two = F32::from_bits(0x4000_0000);
        assert_eq!(one.add(two).bits(), 0x4040_0000);
        assert_eq!(one.mul(two).bits(), two.bits());
    }

    /// ホストの演算との差分検査。NaN はビット比較せず、NaN 同士で一致とみなす。
    fn diff_f64<F>(mut f: F, n: u32)
    where
        F: FnMut(u64, u64) -> (u64, f64),
    {
        let mut s = 0x1234_5678_9abc_def1u64;
        let mut next = move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for _ in 0..n {
            // 非正規数も混ぜるためビット列から作る（指数部が 0 のものを間引かない）。
            let a = next();
            let b = next();
            let (got, want) = f(a, b);
            let want_bits = want.to_bits();
            if want.is_nan() {
                assert!(
                    (got & 0x7ff0_0000_0000_0000) == 0x7ff0_0000_0000_0000
                        && got & 0x000f_ffff_ffff_ffff != 0,
                    "want NaN, got {got:#x}"
                );
            } else {
                assert_eq!(got, want_bits, "a={a:#x} b={b:#x}");
            }
        }
    }

    #[test]
    fn diff_add() {
        diff_f64(
            |a, b| {
                let r = F64::from_bits(a).add(F64::from_bits(b));
                (r.bits(), f64::from_bits(a) + f64::from_bits(b))
            },
            20_000,
        );
    }

    #[test]
    fn diff_sub() {
        diff_f64(
            |a, b| {
                let r = F64::from_bits(a).sub(F64::from_bits(b));
                (r.bits(), f64::from_bits(a) - f64::from_bits(b))
            },
            20_000,
        );
    }

    #[test]
    fn diff_mul() {
        diff_f64(
            |a, b| {
                let r = F64::from_bits(a).mul(F64::from_bits(b));
                (r.bits(), f64::from_bits(a) * f64::from_bits(b))
            },
            20_000,
        );
    }

    #[test]
    fn diff_div() {
        diff_f64(
            |a, b| {
                let r = F64::from_bits(a).div(F64::from_bits(b));
                (r.bits(), f64::from_bits(a) / f64::from_bits(b))
            },
            20_000,
        );
    }

    /// f32 の差分検査。
    fn diff_f32<F>(mut f: F, n: u32)
    where
        F: FnMut(u32, u32) -> (u32, f32),
    {
        let mut s = 0x9e37_79b9u64;
        let mut next = move || {
            s = s
                .wrapping_mul(0x5851_f42d_4c95_7f2d)
                .wrapping_add(0x1405_7b7e_f767_814f);
            (s >> 32) as u32
        };
        for _ in 0..n {
            let a = next();
            let b = next();
            let (got, want) = f(a, b);
            if want.is_nan() {
                assert!(
                    (got & 0x7f80_0000) == 0x7f80_0000 && got & 0x007f_ffff != 0,
                    "want NaN, got {got:#x}"
                );
            } else {
                assert_eq!(got, want.to_bits(), "a={a:#x} b={b:#x}");
            }
        }
    }

    /// 打ち消しと非正規数に偏らせた差分検査。指数差が小さく結果が小さい場合を集中的に試す。
    /// 左シフトと sticky の相互作用の検証が目的である。
    fn stress_cancellation() {
        let mut s = 0x243f_6a88_85a3_08d3u64;
        let mut next = move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        // 指数を emin 近傍に偏らせる。
        for _ in 0..200_000 {
            let e1 = 1 + (next() % 30);
            let e2 = 1 + (next() % 30);
            let m1 = next() & ((1 << 52) - 1);
            let m2 = next() & ((1 << 52) - 1);
            let a = (e1 << 52) | m1;
            let b = (e2 << 52) | m2;
            let r = F64::from_bits(a).add(F64::from_bits(b));
            let w = f64::from_bits(a) + f64::from_bits(b);
            assert_eq!(r.bits(), w.to_bits(), "add a={a:#x} b={b:#x}");
            let r = F64::from_bits(a).sub(F64::from_bits(b));
            let w = f64::from_bits(a) - f64::from_bits(b);
            assert_eq!(r.bits(), w.to_bits(), "sub a={a:#x} b={b:#x}");
            let r = F64::from_bits(a).mul(F64::from_bits(b));
            let w = f64::from_bits(a) * f64::from_bits(b);
            assert_eq!(r.bits(), w.to_bits(), "mul a={a:#x} b={b:#x}");
            let r = F64::from_bits(a).div(F64::from_bits(b));
            let w = f64::from_bits(a) / f64::from_bits(b);
            if w.is_nan() {
                assert!(r.is_nan(), "div nan a={a:#x} b={b:#x}");
            } else {
                assert_eq!(r.bits(), w.to_bits(), "div a={a:#x} b={b:#x}");
            }
        }
    }

    #[test]
    fn stress() {
        stress_cancellation();
    }

    #[test]
    fn diff_f32_all() {
        diff_f32(
            |a, b| {
                let r = F32::from_bits(u64::from(a)).add(F32::from_bits(u64::from(b)));
                (r.bits() as u32, f32::from_bits(a) + f32::from_bits(b))
            },
            20_000,
        );
        diff_f32(
            |a, b| {
                let r = F32::from_bits(u64::from(a)).sub(F32::from_bits(u64::from(b)));
                (r.bits() as u32, f32::from_bits(a) - f32::from_bits(b))
            },
            20_000,
        );
        diff_f32(
            |a, b| {
                let r = F32::from_bits(u64::from(a)).mul(F32::from_bits(u64::from(b)));
                (r.bits() as u32, f32::from_bits(a) * f32::from_bits(b))
            },
            20_000,
        );
        diff_f32(
            |a, b| {
                let r = F32::from_bits(u64::from(a)).div(F32::from_bits(u64::from(b)));
                (r.bits() as u32, f32::from_bits(a) / f32::from_bits(b))
            },
            20_000,
        );
    }
}
