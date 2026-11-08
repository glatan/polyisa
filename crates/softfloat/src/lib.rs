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

    /// 符号つき 64 ビット整数に変換する。RNE で丸め、範囲外は飽和する。
    #[must_use]
    pub fn to_i64(self) -> i64 {
        if self.is_nan() {
            return i64::MAX;
        }
        let (neg, exp, frac) = self.decode();
        if self.is_inf() {
            return if neg { i64::MIN } else { i64::MAX };
        }
        if self.is_zero() {
            return 0;
        }
        let (ue, m) = expand(exp, frac, M, Self::bias());
        // 値 = m * 2^(ue-M)。整数部と端数に分ける。
        let e = ue - M as i64;
        to_int_signed(neg, m, e, 64) as i64
    }

    /// 符号なし 64 ビット整数に変換する。RNE で丸め、範囲外は飽和する。負は 0 になる。
    #[must_use]
    pub fn to_u64(self) -> u64 {
        if self.is_nan() {
            return u64::MAX;
        }
        let (neg, exp, frac) = self.decode();
        if self.is_inf() {
            return if neg { 0 } else { u64::MAX };
        }
        if self.is_zero() || neg {
            return 0;
        }
        let (ue, m) = expand(exp, frac, M, Self::bias());
        let e = ue - M as i64;
        to_int_unsigned(m, e, 64)
    }

    /// 符号つき 64 ビット整数から変換する。RNE。
    #[must_use]
    pub fn from_i64(v: i64) -> Self {
        let neg = v < 0;
        from_mag(neg, v.unsigned_abs() as u128)
    }

    /// 符号なし 64 ビット整数から変換する。RNE。
    #[must_use]
    pub fn from_u64(v: u64) -> Self {
        from_mag(false, u128::from(v))
    }

    /// 等しいか。NaN は等しくない。+0 と -0 は等しい。
    #[must_use]
    pub fn eq(self, other: Self) -> bool {
        if self.is_nan() || other.is_nan() {
            return false;
        }
        if self.is_zero() && other.is_zero() {
            return true;
        }
        self.bits == other.bits
    }

    /// 小さいか。NaN があれば偽。
    #[must_use]
    pub fn lt(self, other: Self) -> bool {
        if self.is_nan() || other.is_nan() {
            return false;
        }
        let (s1, e1, f1) = self.decode();
        let (s2, e2, f2) = other.decode();
        match (s1, s2) {
            (true, false) => !self.is_zero() || !other.is_zero(),
            (false, true) => false,
            (false, false) => (e1, f1) < (e2, f2),
            (true, true) => (e1, f1) > (e2, f2),
        }
    }

    /// 以下か。NaN があれば偽。
    #[must_use]
    pub fn le(self, other: Self) -> bool {
        self.lt(other) || self.eq(other)
    }

    /// 最小値。どちらかが NaN ならもう一方。正規 NaN 同士は正規 NaN。
    /// +0 と -0 では -0 を返す。
    #[must_use]
    pub fn fmin(self, other: Self) -> Self {
        if self.is_nan() {
            return other;
        }
        if other.is_nan() {
            return self;
        }
        if self.lt(other) {
            self
        } else if other.lt(self) {
            other
        } else if self.negative() {
            self
        } else {
            other
        }
    }

    /// 最大値。NaN の扱いは `fmin` と同じ。+0 と -0 では +0 を返す。
    #[must_use]
    pub fn fmax(self, other: Self) -> Self {
        if self.is_nan() {
            return other;
        }
        if other.is_nan() {
            return self;
        }
        if self.lt(other) {
            other
        } else if other.lt(self) {
            self
        } else if self.negative() {
            other
        } else {
            self
        }
    }

    fn negative(self) -> bool {
        self.decode().0
    }

    fn zero_signed(neg: bool) -> Self {
        Self {
            bits: (neg as u64) << (E + M),
        }
    }

    /// 平方根。RNE。負の値（負の無限大を含む）は NaN になる。
    #[must_use]
    pub fn sqrt(self) -> Self {
        let (neg, exp, frac) = self.decode();
        if self.is_nan() || (neg && !self.is_zero() && !self.is_inf()) {
            return Self::canonical_nan();
        }
        if neg && self.is_inf() {
            return Self::canonical_nan();
        }
        if self.is_zero() || self.is_inf() {
            return self;
        }
        let bias = Self::bias();
        let (ue, m) = expand(exp, frac, M, bias);
        // E_in = ue - M が奇数のときは m を倍にして偶数に揃える。
        let (mut ein, mut m) = (ue - M as i64, m);
        if ein & 1 != 0 {
            m <<= 1;
            ein -= 1;
        }
        // m を M+1 ビット以上にそろえる。isqrt の商が窓の下限を下回ると、
        // 左シフトで埋めたゼロが GRS に混ざり丸めを誤るためである。
        // 2 ビットずつ動かすので ein の偶奇は保たれる。
        while m < (1u128 << (M + 1)) {
            m <<= 2;
            ein -= 2;
        }
        // 十分な余裕を持って整数平方根を取る。余りは sticky になる。
        const EXTRA: u32 = 64;
        let scaled = m << EXTRA;
        let (mut q, rem) = isqrt_rem(scaled);
        let mut sticky: i8 = i8::from(rem != 0);
        // value = q * 2^(E_in/2 - EXTRA/2)。窓の不変条件に合わせる。
        let mut e = ein / 2 - (EXTRA as i64) / 2 + M as i64 + 3;
        sticky = normalize_window::<E, M>(&mut e, &mut q, sticky);
        finish::<E, M>(neg, &mut e, &mut q, sticky)
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

/// 整数平方根。商と余りを返す。ビット単位の筆算であり、余りは正確である。
fn isqrt_rem(n: u128) -> (u128, u128) {
    let mut op = n;
    let mut res: u128 = 0;
    let mut one: u128 = 1 << 126;
    while one != 0 {
        if op >= res + one {
            op -= res + one;
            res = (res >> 1) + one;
        } else {
            res >>= 1;
        }
        one >>= 2;
    }
    (res, op)
}

/// 符号つき整数への変換。値は `m * 2^e`（m は非負の整数）である。RNE、範囲外は飽和する。
fn to_int_signed(neg: bool, m: u128, e: i64, bits: u32) -> i128 {
    let max = (1i128 << (bits - 1)) - 1;
    // 大きすぎる値は飽和する。
    if e >= 64 {
        return if neg { -max - 1 } else { max };
    }
    let mag: i128 = if e >= 0 {
        let v = m << e as u32;
        v.min(max as u128 + 1) as i128
    } else {
        let d = (-e) as u32;
        // d は最大で 1074 程度になる。u128 を超えるシフトに注意する。
        if d >= 128 {
            return 0;
        }
        let q = m >> d;
        let dropped = m & ((1u128 << d) - 1);
        let half = 1u128 << (d - 1);
        (q + u128::from(dropped > half || (dropped == half && (q & 1) == 1))) as i128
    };
    let signed = if neg { -mag } else { mag };
    signed.clamp(-max - 1, max)
}

/// 符号なし整数への変換。呼び出し側で非負・有限を保証する。
fn to_int_unsigned(m: u128, e: i64, bits: u32) -> u64 {
    let max = (1u128 << bits) - 1;
    if e >= 64 {
        return max as u64;
    }
    let v: u128 = if e >= 0 {
        m << e as u32
    } else {
        let d = (-e) as u32;
        if d >= 128 {
            return 0;
        }
        let q = m >> d;
        let dropped = m & ((1u128 << d) - 1);
        let half = 1u128 << (d - 1);
        q + u128::from(dropped > half || (dropped == half && (q & 1) == 1))
    };
    v.min(max) as u64
}

/// 32 ビット形式と 64 ビット形式の相互変換。RNE。
impl F32 {
    /// 64 ビット形式に変換する。
    #[must_use]
    pub fn to_f64(self) -> F64 {
        convert(self)
    }
}

impl F64 {
    /// 32 ビット形式に変換する。
    #[must_use]
    pub fn to_f32(self) -> F32 {
        convert(self)
    }
}

/// 整数の絶対値から浮動小数点を作る。RNE。
fn from_mag<const E: u32, const M: u32>(neg: bool, mag: u128) -> Binary<E, M> {
    if mag == 0 {
        return Binary::zero_signed(neg);
    }
    let bitlen = 128 - mag.leading_zeros() as i64;
    // 窓 [2^(M+3), 2^(M+4)) に寄せる。余りは sticky になる。
    let shift = (M as i64 + 4) - bitlen;
    let (mut m, sticky): (u128, i8) = if shift >= 0 {
        (mag << shift as u32, 0)
    } else {
        let s = (-shift) as u32;
        (mag >> s, (mag & ((1u128 << s) - 1) != 0) as i8)
    };
    let mut e = bitlen - 1;
    let sticky = normalize_window::<E, M>(&mut e, &mut m, sticky);
    finish::<E, M>(neg, &mut e, &mut m, sticky)
}

/// 形式を変える。RNE。指数範囲の違いは `finish` が扱う。
fn convert<const E1: u32, const M1: u32, const E2: u32, const M2: u32>(
    v: Binary<E1, M1>,
) -> Binary<E2, M2> {
    let (neg, exp, frac) = v.decode();
    if v.is_nan() {
        return Binary::<E2, M2>::canonical_nan();
    }
    if v.is_inf() {
        return Binary::<E2, M2>::inf(neg);
    }
    if v.is_zero() {
        return Binary::<E2, M2>::zero_signed(neg);
    }
    let bias1 = Binary::<E1, M1>::bias();
    let (ue, m) = expand(exp, frac, M1, bias1);
    let mut e = ue;
    // 対象の形式の仮数幅に合わせる。余りは sticky に畳む。
    let mut m = m << 3;
    let mut sticky: i8 = 0;
    if M1 > M2 {
        let d = M1 - M2;
        sticky = shr_jam(&mut m, d) as i8;
    } else if M2 > M1 {
        m <<= M2 - M1;
    }
    let sticky = normalize_window::<E2, M2>(&mut e, &mut m, sticky);
    finish::<E2, M2>(neg, &mut e, &mut m, sticky)
}
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

    #[test]
    fn sqrt_cases() {
        let four = F64::from_bits(0x4010_0000_0000_0000);
        let two = F64::from_bits(0x4000_0000_0000_0000);
        assert_eq!(four.sqrt().bits(), two.bits());
        assert_eq!(F64::zero().sqrt().bits(), F64::zero().bits());
        assert!(F64::from_bits(0xbff0_0000_0000_0000).sqrt().is_nan());
        assert_eq!(F64::inf(false).sqrt().bits(), F64::inf(false).bits());
        // 2 の平方根は丸めで決まる。
        assert_eq!(two.sqrt().bits(), 0x3ff6_a09e_667f_3bcd);
    }

    #[test]
    fn int_conversions() {
        let one5 = F64::from_bits(0x3ff8_0000_0000_0000);
        assert_eq!(one5.to_i64(), 2);
        assert_eq!(one5.to_u64(), 2);
        let neg = F64::from_bits(0xbff8_0000_0000_0000);
        assert_eq!(neg.to_i64(), -2);
        assert_eq!(neg.to_u64(), 0);
        // 範囲外は飽和する。
        assert_eq!(F64::from_bits(0x43e0_0000_0000_0000).to_i64(), i64::MAX);
        assert_eq!(F64::from_bits(0xc3e0_0000_0000_0000).to_i64(), i64::MIN);
        assert_eq!(F64::canonical_nan().to_i64(), i64::MAX);
        assert_eq!(F64::canonical_nan().to_u64(), u64::MAX);
        // 整数からは正確に丸める。u64::MAX は 2^64 に切り上がる。
        assert_eq!(F64::from_i64(-42).bits(), 0xc045_0000_0000_0000);
        assert_eq!(F64::from_u64(u64::MAX).bits(), 0x43f0_0000_0000_0000);
        assert_eq!(F32::from_bits(0x3f80_0000).to_i64(), 1);
    }

    #[test]
    fn f32_f64_convert() {
        let one = F32::from_bits(0x3f80_0000);
        assert_eq!(one.to_f64().bits(), 0x3ff0_0000_0000_0000);
        let back: F32 = one.to_f64().to_f32();
        assert_eq!(back.bits(), one.bits());
        // 狭める方向は丸める。
        let third64 = F64::from_bits(0x3fd5_5555_5555_5555);
        assert_eq!(third64.to_f32().bits(), 0x3eaa_aaab);
    }

    #[test]
    fn comparisons() {
        let one = F64::from_bits(0x3ff0_0000_0000_0000);
        let two = F64::from_bits(0x4000_0000_0000_0000);
        let nan = F64::canonical_nan();
        let pz = F64::zero();
        let nz = F64::from_bits(0x8000_0000_0000_0000);
        assert!(one.lt(two));
        assert!(!two.lt(one));
        assert!(one.le(one));
        assert!(pz.eq(nz));
        assert!(!nan.eq(nan));
        assert!(!nan.lt(one));
        assert!(!one.lt(nan));
        assert_eq!(one.fmin(two).bits(), one.bits());
        assert_eq!(one.fmax(two).bits(), two.bits());
        assert_eq!(nan.fmin(one).bits(), one.bits());
        assert_eq!(one.fmin(nan).bits(), one.bits());
        assert_eq!(pz.fmax(nz).bits(), pz.bits());
        assert_eq!(pz.fmin(nz).bits(), nz.bits());
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
    fn diff_extra() {
        // sqrt、変換、比較、min/max の差分検査。
        let mut s = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for _ in 0..20_000 {
            let a = next();
            let fa = f64::from_bits(a);
            let r = F64::from_bits(a).sqrt();
            let w = fa.sqrt();
            if w.is_nan() {
                assert!(r.is_nan(), "sqrt nan {a:#x}");
            } else {
                assert_eq!(r.bits(), w.to_bits(), "sqrt {a:#x}");
            }
            if fa.is_finite() && fa.abs() < 9.0e18 {
                // `as` は切り捨てなので、RNE の期待値は round_ties_even で作る。
                assert_eq!(
                    F64::from_bits(a).to_i64(),
                    fa.round_ties_even() as i64,
                    "to_i64 {a:#x}"
                );
                if fa >= 0.0 {
                    assert_eq!(
                        F64::from_bits(a).to_u64(),
                        fa.round_ties_even() as u64,
                        "to_u64 {a:#x}"
                    );
                }
                assert_eq!(
                    F64::from_bits(a).to_f32().bits() as u32,
                    (fa as f32).to_bits(),
                    "to_f32 {a:#x}"
                );
            }
            let b = next();
            let fb = f64::from_bits(b);
            assert_eq!(F64::from_bits(a).eq(F64::from_bits(b)), fa == fb, "eq");
            assert_eq!(
                F64::from_bits(a).lt(F64::from_bits(b)),
                fa < fb,
                "lt {a:#x} {b:#x}"
            );
            assert_eq!(
                F64::from_bits(a).fmin(F64::from_bits(b)).bits(),
                fa.min(fb).to_bits(),
                "min {a:#x} {b:#x}"
            );
            assert_eq!(
                F64::from_bits(a).fmax(F64::from_bits(b)).bits(),
                fa.max(fb).to_bits(),
                "max {a:#x} {b:#x}"
            );
            let c = next() as u32;
            // NaN は正規化される（RISC-V の fcvt と同じ）。それ以外は host と一致する。
            let fc = F32::from_bits(u64::from(c));
            if fc.is_nan() {
                assert!(fc.to_f64().is_nan(), "f32 to f64 nan {c:#x}");
            } else {
                assert_eq!(
                    fc.to_f64().bits(),
                    f64::from(f32::from_bits(c)).to_bits(),
                    "f32 to f64"
                );
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
