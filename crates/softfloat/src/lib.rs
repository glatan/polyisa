// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! ソフトウェア浮動小数点。ホストの FPU を使わず、整数演算で実装する。
//!
//! 出典は SPEC-IEEE754 の版 2019 である。数値・丸め規則の事実のみを自前の表現で使う。
//! 条文・図表の複製はしない。丸めは Rm で選び（動的丸めは呼び出し側が解決する）、
//! 例外フラグは戻り値で返す。蓄積は呼び出し側（バックエンド）が行う。
//!
//! 形式はビット幅で汎化する。`F32` は `Binary<8, 23>`、`F64` は `Binary<11, 52>` である。
// Ref: SPEC-IEEE754 (2019).

#![forbid(unsafe_code)]

/// 例外フラグのビット。RISC-V の fflags と同じ配置である。
pub const FP_NX: u8 = 1;
/// アンダーフロー。
pub const FP_UF: u8 = 2;
/// オーバーフロー。
pub const FP_OF: u8 = 4;
/// 0 除算。
pub const FP_DZ: u8 = 8;
/// 不正演算。
pub const FP_NV: u8 = 16;

/// 丸めモード。RISC-V の rm フィールドと同じ値である。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Rm {
    /// 最近接偶数（000）。
    Rne = 0,
    /// 0 方向への丸め（001）。
    Rtz = 1,
    /// 負無限大方向への丸め（010）。
    Rdn = 2,
    /// 正無限大方向への丸め（011）。
    Rup = 3,
    /// 絶対値最大方向への丸め（100）。
    Rmm = 4,
}

impl Rm {
    /// rm フィールド値から作る。未定義値は最近接偶数に倒す。
    #[must_use]
    pub const fn from_bits(v: u8) -> Self {
        match v & 7 {
            1 => Self::Rtz,
            2 => Self::Rdn,
            3 => Self::Rup,
            4 => Self::Rmm,
            _ => Self::Rne,
        }
    }
}

/// 指数 E ビット、仮数 M ビットの二進浮動小数点。符号 1 ビットを含め `1 + E + M <= 64` とする。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Binary<const E: u32, const M: u32> {
    bits: u64,
}

/// 16 ビット形式（binary16・half）。
pub type F16 = Binary<5, 10>;
/// 32 ビット形式。
pub type F32 = Binary<8, 23>;

/// 8 ビット形式（FP8）。E4M3 は OCP FP8 の E4M3、E5M2 は E5M2。
/// AVX10.2/ACE が使う。
///
/// `Binary<E, M>` の機械は IEEE754 の配置（最上段指数 = Inf/NaN）で
/// 組み立てるため、E4M3 と E2M1 の最上段指数行だけは規格とずれる。
/// OCP の実情は:
///
/// - E4M3: exp=15 は有限値の続き（256 〜 448）。0x7F/0xFF だけが
///   NaN で、Inf は存在しない。
/// - E2M1: 特殊値を持たない。0x6 = 4.0、0x7 = 6.0 が最大の有限値。
/// - E5M2 は IEEE の配置と一致するので汎用機械で正しい。
///
/// このため E4M3・E2M1 への変換は専用経路（`to_e4m3`/`to_e2m1` と
/// 各 `to_f32`）を用意し、上位行を OCP の意味で扱う。`is_inf` や
/// `canonical_nan` など IEEE を仮定する補助関数は上位行に対して
/// 当てはまらない点に注意（Ref: SPEC-X86-AVX10-2）。
pub type E4M3 = Binary<4, 3>;

/// 8 ビット形式（E5M2）。IEEE の配置と一致する。
pub type E5M2 = Binary<5, 2>;

/// 4 ビット形式（E2M1、FP4。AVX10.2/ACE が使う）。特殊値なし。
pub type E2M1 = Binary<2, 1>;

/// 16 ビット形式（bfloat16。AVX10.2/AVX512_BF16/AMX が使う）。
/// IEEE の配置と一致するので汎用機械で正しい。
pub type BF16 = Binary<8, 7>;
/// 64 ビット形式。
pub type F64 = Binary<11, 52>;

/// DEC の F/D/G/H 形式（VAX・PDP-11・Alpha）。
pub mod decfp;
/// IA-64 の 82 ビット浮動小数点レジスタファイル形式。
pub mod ia64ext;
/// IBM の十六進浮動小数点（S/360 系 HFP）。
pub mod ibmhex;
/// Motorola 68881/68882 の拡張精度形式。
pub mod m68kext;

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

    /// シグナリング NaN かどうか。仮数部の最上位ビットが 0 の NaN である。
    #[must_use]
    pub fn is_signaling_nan(self) -> bool {
        let (_, exp, frac) = self.decode();
        exp == Self::exp_max() as u32 && frac != 0 && (frac >> (M - 1)) & 1 == 0
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
    pub fn add(self, other: Self) -> (Self, u8) {
        self.add_rm(other, Rm::Rne)
    }

    /// 丸め指定付き加算。
    #[must_use]
    pub fn add_rm(self, other: Self, rm: Rm) -> (Self, u8) {
        add_sub(self, other, false, rm)
    }

    /// 減算。`a - b` は `a + (-b)` である。
    #[must_use]
    pub fn sub(self, other: Self) -> (Self, u8) {
        self.sub_rm(other, Rm::Rne)
    }

    /// 丸め指定付き減算。
    #[must_use]
    pub fn sub_rm(self, other: Self, rm: Rm) -> (Self, u8) {
        add_sub(self, other, true, rm)
    }

    /// 乗算。RNE。
    #[must_use]
    pub fn mul(self, other: Self) -> (Self, u8) {
        self.mul_rm(other, Rm::Rne)
    }

    /// 丸め指定付き乗算。
    #[must_use]
    pub fn mul_rm(self, other: Self, rm: Rm) -> (Self, u8) {
        let (s1, e1, f1) = self.decode();
        let (s2, e2, f2) = other.decode();
        let neg = s1 ^ s2;
        if self.is_nan() || other.is_nan() {
            let mut f = 0;
            if self.is_signaling_nan() || other.is_signaling_nan() {
                f |= FP_NV;
            }
            return (Self::canonical_nan(), f);
        }
        let inf1 = self.is_inf();
        let inf2 = other.is_inf();
        let zero1 = self.is_zero();
        let zero2 = other.is_zero();
        if (inf1 && zero2) || (zero1 && inf2) {
            return (Self::canonical_nan(), FP_NV);
        }
        if inf1 || inf2 {
            return (Self::inf(neg), 0);
        }
        if zero1 || zero2 {
            return (Self::zero_signed(neg), 0);
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
        finish::<E, M>(neg, &mut e, &mut m, sticky, rm)
    }

    /// 除算。RNE。
    #[must_use]
    pub fn div(self, other: Self) -> (Self, u8) {
        self.div_rm(other, Rm::Rne)
    }

    /// 丸め指定付き除算。
    #[must_use]
    pub fn div_rm(self, other: Self, rm: Rm) -> (Self, u8) {
        let (s1, e1, f1) = self.decode();
        let (s2, e2, f2) = other.decode();
        let neg = s1 ^ s2;
        if self.is_nan() || other.is_nan() {
            let mut f = 0;
            if self.is_signaling_nan() || other.is_signaling_nan() {
                f |= FP_NV;
            }
            return (Self::canonical_nan(), f);
        }
        let inf1 = self.is_inf();
        let inf2 = other.is_inf();
        let zero1 = self.is_zero();
        let zero2 = other.is_zero();
        if (inf1 && inf2) || (zero1 && zero2) {
            return (Self::canonical_nan(), FP_NV);
        }
        if inf1 {
            return (Self::inf(neg), 0);
        }
        if zero1 {
            return (Self::zero_signed(neg), 0);
        }
        if zero2 {
            return (Self::inf(neg), FP_DZ);
        }
        if inf2 {
            return (Self::zero_signed(neg), 0);
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
        finish::<E, M>(neg, &mut e, &mut m, sticky, rm)
    }

    /// 符号つき 32 ビット整数に変換する。範囲外は飽和し NV を立てる。
    #[must_use]
    pub fn to_i32(self, rm: Rm) -> (i32, u8) {
        if self.is_nan() {
            return (i32::MAX, FP_NV);
        }
        let (neg, exp, frac) = self.decode();
        if self.is_inf() {
            return (if neg { i32::MIN } else { i32::MAX }, FP_NV);
        }
        if self.is_zero() {
            return (0, 0);
        }
        let (ue, m) = expand(exp, frac, M, Self::bias());
        let e = ue - M as i64;
        let (v, f) = to_int_signed(neg, m, e, 32, rm);
        (v as i32, f)
    }

    /// 符号なし 32 ビット整数に変換する。範囲外は飽和し NV を立てる。
    #[must_use]
    pub fn to_u32(self, rm: Rm) -> (u32, u8) {
        if self.is_nan() {
            return (u32::MAX, FP_NV);
        }
        let (neg, exp, frac) = self.decode();
        if self.is_inf() {
            return (if neg { 0 } else { u32::MAX }, FP_NV);
        }
        if self.is_zero() {
            return (0, 0);
        }
        if neg {
            // 負の有限値：丸めて0になればNX、そうでなければNVで0を返す。
            let (ue, m) = expand(exp, frac, M, Self::bias());
            let e = ue - M as i64;
            let (sv, sf) = to_int_signed(true, m, e, 32, rm);
            if sv == 0 {
                return (0, sf);
            }
            return (0, FP_NV);
        }
        let (ue, m) = expand(exp, frac, M, Self::bias());
        let e = ue - M as i64;
        let (v, f) = to_int_unsigned(m, e, 32, rm);
        (v as u32, f)
    }

    /// 符号つき 64 ビット整数に変換する。範囲外は飽和し NV を立てる。
    /// 丸めで値が変われば NX を立てる。
    #[must_use]
    pub fn to_i64(self, rm: Rm) -> (i64, u8) {
        if self.is_nan() {
            return (i64::MAX, FP_NV);
        }
        let (neg, exp, frac) = self.decode();
        if self.is_inf() {
            return (if neg { i64::MIN } else { i64::MAX }, FP_NV);
        }
        if self.is_zero() {
            return (0, 0);
        }
        let (ue, m) = expand(exp, frac, M, Self::bias());
        // 値 = m * 2^(ue-M)。整数部と端数に分ける。
        let e = ue - M as i64;
        let (v, f) = to_int_signed(neg, m, e, 64, rm);
        (v as i64, f)
    }

    /// 符号なし 64 ビット整数に変換する。範囲外は飽和し NV を立てる。
    /// 負は 0 になる。丸めで値が変われば NX を立てる。
    #[must_use]
    pub fn to_u64(self, rm: Rm) -> (u64, u8) {
        if self.is_nan() {
            return (u64::MAX, FP_NV);
        }
        let (neg, exp, frac) = self.decode();
        if self.is_inf() {
            return (if neg { 0 } else { u64::MAX }, FP_NV);
        }
        if self.is_zero() {
            return (0, 0);
        }
        if neg {
            let (ue, m) = expand(exp, frac, M, Self::bias());
            let e = ue - M as i64;
            let (sv, sf) = to_int_signed(true, m, e, 64, rm);
            if sv == 0 {
                return (0, sf);
            }
            return (0, FP_NV);
        }
        let (ue, m) = expand(exp, frac, M, Self::bias());
        let e = ue - M as i64;
        to_int_unsigned(m, e, 64, rm)
    }

    /// 符号つき 64 ビット整数から変換する。
    #[must_use]
    pub fn from_i64(v: i64, rm: Rm) -> (Self, u8) {
        let neg = v < 0;
        from_mag(neg, v.unsigned_abs() as u128, rm)
    }

    /// 符号なし 64 ビット整数から変換する。
    #[must_use]
    pub fn from_u64(v: u64, rm: Rm) -> (Self, u8) {
        from_mag(false, u128::from(v), rm)
    }

    /// 等しいか。NaN は等しくない。+0 と -0 は等しい。
    /// シグナリング NaN が入力なら NV を立てる。
    #[must_use]
    pub fn eq(self, other: Self) -> (bool, u8) {
        if self.is_nan() || other.is_nan() {
            let f = if self.is_signaling_nan() || other.is_signaling_nan() {
                FP_NV
            } else {
                0
            };
            return (false, f);
        }
        if self.is_zero() && other.is_zero() {
            return (true, 0);
        }
        (self.bits == other.bits, 0)
    }

    /// 小さいか。NaN があれば偽。NaN入力ではNVを立てる（quietでも）。
    /// feqのみsNaNでNV、flt/fleはquietでもNV（SPEC-RISCV-UNPRIV F章）。
    #[must_use]
    pub fn lt(self, other: Self) -> (bool, u8) {
        if self.is_nan() || other.is_nan() {
            return (false, FP_NV);
        }
        let (s1, e1, f1) = self.decode();
        let (s2, e2, f2) = other.decode();
        let r = match (s1, s2) {
            (true, false) => !self.is_zero() || !other.is_zero(),
            (false, true) => false,
            (false, false) => (e1, f1) < (e2, f2),
            (true, true) => (e1, f1) > (e2, f2),
        };
        (r, 0)
    }

    /// 以下か。NaN があれば偽。NaN入力ではNVを立てる。
    #[must_use]
    pub fn le(self, other: Self) -> (bool, u8) {
        if self.is_nan() || other.is_nan() {
            return (false, FP_NV);
        }
        let (lt, f1) = self.lt(other);
        let (eq, f2) = self.eq(other);
        (lt || eq, f1 | f2)
    }

    /// 最小値。NaN がある場合は他方を返し、両方 NaN なら正準 NaN を返す。
    /// シグナリング NaN があれば NV を立てる。+0 と -0 では -0 を返す。
    #[must_use]
    pub fn fmin(self, other: Self) -> (Self, u8) {
        let f = if self.is_signaling_nan() || other.is_signaling_nan() {
            FP_NV
        } else {
            0
        };
        if self.is_nan() {
            return if other.is_nan() {
                (Self::canonical_nan(), f)
            } else {
                (other, f)
            };
        }
        if other.is_nan() {
            return (self, f);
        }
        if self.lt(other).0 {
            (self, 0)
        } else if other.lt(self).0 {
            (other, 0)
        } else if self.negative() {
            (self, 0)
        } else {
            (other, 0)
        }
    }

    /// 最大値。NaN の扱いは `fmin` と同じ。+0 と -0 では +0 を返す。
    #[must_use]
    pub fn fmax(self, other: Self) -> (Self, u8) {
        let f = if self.is_signaling_nan() || other.is_signaling_nan() {
            FP_NV
        } else {
            0
        };
        if self.is_nan() {
            return if other.is_nan() {
                (Self::canonical_nan(), f)
            } else {
                (other, f)
            };
        }
        if other.is_nan() {
            return (self, f);
        }
        if self.lt(other).0 {
            (other, 0)
        } else if other.lt(self).0 {
            (self, 0)
        } else if self.negative() {
            (other, 0)
        } else {
            (self, 0)
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

    /// 積和融合。`self * other + addend` を一回の丸めで求める（RNE）。
    ///
    /// FMSUB・FNMADD・FNMSUB は引数の符号反転（正確）でこの形に直す。
    /// NaN 入力は正準 NaN、inf * 0 と inf - inf は NaN になる。
    #[must_use]
    pub fn fmadd(self, other: Self, addend: Self) -> (Self, u8) {
        self.fmadd_rm(other, addend, Rm::Rne)
    }

    /// 丸め指定付き積和融合。
    #[must_use]
    pub fn fmadd_rm(self, other: Self, addend: Self, rm: Rm) -> (Self, u8) {
        let (s1, e1, f1) = self.decode();
        let (s2, e2, f2) = other.decode();
        let (s3, e3, f3) = addend.decode();
        if self.is_nan() || other.is_nan() || addend.is_nan() {
            let mut f = 0;
            if self.is_signaling_nan() || other.is_signaling_nan() || addend.is_signaling_nan() {
                f |= FP_NV;
            }
            return (Self::canonical_nan(), f);
        }
        let sp = s1 ^ s2;
        let inf1 = self.is_inf();
        let inf2 = other.is_inf();
        let zero1 = self.is_zero();
        let zero2 = other.is_zero();
        let inf3 = addend.is_inf();
        let zero3 = addend.is_zero();
        if (inf1 && zero2) || (zero1 && inf2) {
            return (Self::canonical_nan(), FP_NV);
        }
        if inf1 || inf2 {
            if inf3 && s3 != sp {
                return (Self::canonical_nan(), FP_NV);
            }
            return (Self::inf(sp), 0);
        }
        if inf3 {
            return (Self::inf(s3), 0);
        }
        if zero1 || zero2 {
            if zero3 {
                return (
                    if sp == s3 {
                        Self::zero_signed(sp)
                    } else {
                        Self::zero()
                    },
                    0,
                );
            }
            return (addend, 0);
        }
        let bias = Self::bias();
        let (ue1, m1) = expand(e1, f1, M, bias);
        let (ue2, m2) = expand(e2, f2, M, bias);
        let (ue3, m3) = expand(e3, f3, M, bias);
        // exact product: m_p * 2^(ue_p - 2M)。u128 に収まる。
        let ue_p = ue1 + ue2;
        let m_p = m1 * m2;
        let lsb_p = ue_p - 2 * M as i64;
        let lsb3 = ue3 - M as i64;
        let bl_p = bitlen_u128(m_p);
        let bl3 = bitlen_u128(m3);
        // 両項の上位 121 ビットを残し、下位は jam に畳む。
        // 121 ビットあれば丸め（上位 M+4 ビット＋sticky）は正確であり、
        // 幅は u128 に収まる。m3 == 0（加数がゼロ）のとき bl3 == 0 である。
        let msb_p = lsb_p + bl_p - 1;
        let msb3 = lsb3 + bl3 - 1;
        let top = msb_p.max(msb3);
        let base = top - 120;
        let mut sticky = 0i8;
        let mut s_jam = 0i8;
        let mut acc = 0u128;
        let mut neg = false;
        let mut first = true;
        for (mm, lsb, s) in [(m_p, lsb_p, sp), (m3, lsb3, s3)] {
            let shift = lsb - base;
            let mut v = mm;
            if shift >= 0 {
                v <<= shift as u32;
            } else if shr_jam(&mut v, (-shift) as u32) {
                sticky = 1;
                s_jam += if s { -1 } else { 1 };
            }
            if first {
                acc = v;
                neg = s;
                first = false;
            } else if neg == s {
                acc += v;
            } else if acc >= v {
                acc -= v;
            } else {
                acc = v - acc;
                neg = s;
            }
        }
        if acc == 0 {
            // add_sub と同じく、切り捨てだけ残れば切り捨てた側の符号にする。
            return (Self::zero_signed(sticky != 0 && s_jam < 0), 0);
        }
        // acc は base 刻みにある。
        let mut e = base + M as i64 + 3;
        let mut m_win = acc;
        let s = normalize_window::<E, M>(&mut e, &mut m_win, sticky);
        finish::<E, M>(neg, &mut e, &mut m_win, s, rm)
    }

    /// 平方根。RNE。負の値（負の無限大を含む）は NaN になる。
    #[must_use]
    pub fn sqrt(self) -> (Self, u8) {
        self.sqrt_rm(Rm::Rne)
    }

    /// 丸め指定付き平方根。
    #[must_use]
    pub fn sqrt_rm(self, rm: Rm) -> (Self, u8) {
        let (neg, exp, frac) = self.decode();
        if self.is_nan() {
            let f = if self.is_signaling_nan() { FP_NV } else { 0 };
            return (Self::canonical_nan(), f);
        }
        if neg && !self.is_zero() {
            return (Self::canonical_nan(), FP_NV);
        }
        if self.is_zero() || self.is_inf() {
            return (self, 0);
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
        finish::<E, M>(neg, &mut e, &mut q, sticky, rm)
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
    rm: Rm,
) -> (Binary<E, M>, u8) {
    let (s1, e1, f1) = a.decode();
    let (mut s2, e2, f2) = b.decode();
    if flip {
        s2 = !s2;
    }
    if a.is_nan() || b.is_nan() {
        let mut f = 0;
        if a.is_signaling_nan() || b.is_signaling_nan() {
            f |= FP_NV;
        }
        return (Binary::canonical_nan(), f);
    }
    let inf1 = a.is_inf();
    let inf2 = b.is_inf();
    if inf1 && inf2 {
        if s1 == s2 {
            return (Binary::inf(s1), 0);
        }
        return (Binary::canonical_nan(), FP_NV);
    }
    if inf1 {
        return (Binary::inf(s1), 0);
    }
    if inf2 {
        return (Binary::inf(s2), 0);
    }
    let zero1 = a.is_zero();
    let zero2 = b.is_zero();
    if zero1 && zero2 {
        // RNE では +0。-0 + -0 のみ -0 になる。
        return (Binary::zero_signed(s1 && s2), 0);
    }
    if zero1 {
        return (
            Binary::from_bits(b.bits & Binary::<E, M>::mask() | ((s2 as u64) << (E + M))),
            0,
        );
    }
    if zero2 {
        return (Binary::from_bits(a.bits), 0);
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
        // 切り捨てがあれば微小な非ゼロ値であり、不正確である。
        let f = if dropped { FP_NX } else { 0 };
        return (Binary::zero_signed(dropped && s_shifted < 0), f);
    }
    let r_sign: i8 = if neg { -1 } else { 1 };
    let sticky: i8 = if dropped { r_sign * s_shifted } else { 0 };
    // 正規化。e は emin を下回りうる。下回り分は jam で寄せる。
    let sticky = normalize_window::<E, M>(&mut e, &mut m, sticky);
    finish::<E, M>(neg, &mut e, &mut m, sticky, rm)
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

/// 丸めと符号化。`m` は下位 3 ビットを GRS とし、`sticky` を S に畳む。
/// 不変条件：値は `m * 2^(e-M-3)` である（丸めで下位 3 ビットを落とす）。
/// 戻り値は（値、例外フラグ）である。NX は不正確、UF は微小かつ不正確、
/// OF はオーバーフローを表す。OF のとき NX も立つ。
fn finish<const E: u32, const M: u32>(
    neg: bool,
    e: &mut i64,
    m: &mut u128,
    sticky: i8,
    rm: Rm,
) -> (Binary<E, M>, u8) {
    let bias = Binary::<E, M>::bias();
    // tie（下位 3 ビットが 100）のときだけ端数の符号が要る。
    // 正の端数は切り上げ、負の端数は切り捨て、なければ偶数丸めである。
    let r0 = *m & 0b111;
    let up = match rm {
        Rm::Rne => (r0 > 4) || (r0 == 4 && (sticky > 0 || (sticky == 0 && ((*m >> 3) & 1 == 1)))),
        Rm::Rtz => false,
        Rm::Rdn => neg && (r0 != 0 || sticky != 0),
        Rm::Rup => !neg && (r0 != 0 || sticky != 0),
        Rm::Rmm => r0 >= 4,
    };
    let mut sig = (*m >> 3) + u128::from(up);
    let mut exp = *e;
    if sig >= (1u128 << (M + 1)) {
        sig >>= 1;
        exp += 1;
    }
    let mut flags = if r0 != 0 || sticky != 0 { FP_NX } else { 0 };
    let biased = exp + bias;
    let exp_max = (1i64 << E) - 1;
    if biased >= exp_max {
        // オーバーフロー。丸め方向により inf か最大有限値になる。
        let to_inf = match rm {
            Rm::Rtz => false,
            Rm::Rdn => neg,
            Rm::Rup => !neg,
            Rm::Rne | Rm::Rmm => true,
        };
        if to_inf {
            return (Binary::inf(neg), flags | FP_OF | FP_NX);
        }
        let frac = ((1u128 << M) - 1) as u64;
        let v = Binary::from_bits(((neg as u64) << (E + M)) | (((exp_max - 1) as u64) << M) | frac);
        return (v, flags | FP_OF | FP_NX);
    }
    // 隠れビットがなければ非正規数であり、指数部は 0 とする。
    // 正規化の保証により、この場合は exp == emin である。
    if sig >= (1u128 << M) {
        debug_assert!(biased >= 1);
        let frac = (sig & ((1u128 << M) - 1)) as u64;
        let v = Binary::from_bits(((neg as u64) << (E + M)) | ((biased as u64) << M) | frac);
        (v, flags)
    } else {
        debug_assert!(exp == 1 - bias);
        if flags & FP_NX != 0 {
            flags |= FP_UF;
        }
        (
            Binary::from_bits(((neg as u64) << (E + M)) | sig as u64),
            flags,
        )
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

/// 符号つき整数への変換。値は `m * 2^e`（m は非負の整数）である。
/// 丸めた結果が範囲外なら飽和し NV を立てる。丸めで値が変われば NX を立てる。
fn to_int_signed(neg: bool, m: u128, e: i64, bits: u32, rm: Rm) -> (i128, u8) {
    let max = (1i128 << (bits - 1)) - 1;
    // 大きすぎる値は飽和する。
    if e >= 64 {
        return (if neg { -max - 1 } else { max }, FP_NV);
    }
    let (mut q, dropped_any) = if e >= 0 {
        (m << e as u32, false)
    } else {
        let d = (-e) as u32;
        // d は最大で 1074 程度になる。u128 を超えるシフトに注意する。
        if d >= 128 {
            // 0 への丸め。RDN/RUP では符号方向に 1 になることがある。
            let one = match rm {
                Rm::Rdn => neg,
                Rm::Rup => !neg,
                _ => false,
            };
            return (u128::from(one) as i128 * if neg { -1 } else { 1 }, FP_NX);
        }
        let q = m >> d;
        let dropped = m & ((1u128 << d) - 1);
        (q, dropped != 0)
    };
    // 丸め。d は e<0 のときの小数ビット数、e>=0 のときは端数なしである。
    let up = if e >= 0 {
        false
    } else {
        let d = (-e) as u32;
        let dropped = m & ((1u128 << d) - 1);
        let half = 1u128 << (d - 1);
        match rm {
            Rm::Rne => dropped > half || (dropped == half && (q & 1) == 1),
            Rm::Rtz => false,
            Rm::Rdn => neg && dropped_any,
            Rm::Rup => !neg && dropped_any,
            Rm::Rmm => dropped >= half,
        }
    };
    if up {
        q = q.saturating_add(1);
    }
    let nx = if dropped_any { FP_NX } else { 0 };
    // 範囲検査は丸めた値で行う。
    if neg {
        if q > max as u128 + 1 {
            return (-max - 1, FP_NV);
        }
        if q == max as u128 + 1 {
            return (-max - 1, nx);
        }
        (-(q as i128), nx)
    } else {
        if q > max as u128 {
            return (max, FP_NV);
        }
        (q as i128, nx)
    }
}

/// 符号なし整数への変換。呼び出し側で非負・有限を保証する。
fn to_int_unsigned(m: u128, e: i64, bits: u32, rm: Rm) -> (u64, u8) {
    let max = (1u128 << bits) - 1;
    if e >= 64 {
        return (max as u64, FP_NV);
    }
    let (mut q, dropped_any) = if e >= 0 {
        (m << e as u32, false)
    } else {
        let d = (-e) as u32;
        if d >= 128 {
            let one = matches!(rm, Rm::Rup);
            return (u128::from(one) as u64, FP_NX);
        }
        let q = m >> d;
        let dropped = m & ((1u128 << d) - 1);
        (q, dropped != 0)
    };
    let up = if e >= 0 {
        false
    } else {
        let d = (-e) as u32;
        let dropped = m & ((1u128 << d) - 1);
        let half = 1u128 << (d - 1);
        match rm {
            Rm::Rne => dropped > half || (dropped == half && (q & 1) == 1),
            Rm::Rtz | Rm::Rdn => false,
            Rm::Rup => dropped_any,
            Rm::Rmm => dropped >= half,
        }
    };
    if up {
        q = q.saturating_add(1);
    }
    let nx = if dropped_any { FP_NX } else { 0 };
    if q > max {
        return (max as u64, FP_NV);
    }
    (q as u64, nx)
}

/// 32 ビット形式と 64 ビット形式の相互変換。
impl F16 {
    /// 32 ビット形式に変換する。
    #[must_use]
    pub fn to_f32(self, rm: Rm) -> (F32, u8) {
        convert(self, rm)
    }
}

impl F32 {
    /// 64 ビット形式に変換する。
    #[must_use]
    pub fn to_f64(self, rm: Rm) -> (F64, u8) {
        convert(self, rm)
    }

    /// 16 ビット形式に変換する。
    #[must_use]
    pub fn to_f16(self, rm: Rm) -> (F16, u8) {
        convert(self, rm)
    }

    /// BF16（16 ビット）に変換する。
    #[must_use]
    pub fn to_bf16(self, rm: Rm) -> (BF16, u8) {
        convert(self, rm)
    }

    /// E4M3（8 ビット）に変換する。OCP 仕様: Inf なし・オーバーフローは NaN。
    #[must_use]
    pub fn to_e4m3(self, rm: Rm) -> (E4M3, u8) {
        if self.is_nan() || self.is_inf() {
            return (E4M3::from_bits(0x7f | ((self.decode().0 as u64) << 7)), 0);
        }
        let (r, f) = convert::<8, 23, 4, 3>(self, rm);
        // IEEE モデルで Inf 行に丸め込まれた有限値は OCP では 256〜448。
        if r.bits() & 0x7f != 0x78 {
            return (r, f);
        }
        let (neg, exp, frac) = self.decode();
        let sgn = (neg as u64) << 7;
        let eu = exp as i64 - 127;
        let m24 = (1u64 << 23) | frac;
        // 指数欄 15 の刻みは 32（2^8 の 1/8）。値は 256 + frac3 * 32。
        // eu = 7 の到達範囲は 248 以上なので丸めると frac3 = 0（256）。
        // eu = 8 では frac3 = round((m24 - 2^23) / 2^20)。
        let (q, rem, half) = if eu == 7 {
            (0u64, 1u64, 1u64) // 248 以上 → 0x78 に寄せる。常に非正確。
        } else if eu == 8 {
            let shift = 20u32;
            let num = m24 - (1 << 23);
            (num >> shift, num & ((1 << shift) - 1), 1u64 << (shift - 1))
        } else {
            // 上限超過（eu >= 9）は NaN。
            return (E4M3::from_bits(0x7f | sgn), 0);
        };
        let inc = match rm {
            Rm::Rne => rem > half || (rem == half && q & 1 == 1),
            Rm::Rtz => false,
            Rm::Rdn => neg && rem != 0,
            Rm::Rup => !neg && rem != 0,
            Rm::Rmm => rem >= half,
        };
        let q = q + u64::from(inc);
        // frac3 = 7 は OCP で NaN 行。6（448）までが有限値。
        if q >= 7 {
            return (E4M3::from_bits(0x7f | sgn), 0);
        }
        let nx = if rem != 0 || eu == 7 { FP_NX } else { 0 };
        (E4M3::from_bits(0x78 | q | sgn), nx)
    }

    /// E5M2（8 ビット）に変換する。
    #[must_use]
    pub fn to_e5m2(self, rm: Rm) -> (E5M2, u8) {
        convert(self, rm)
    }

    /// E2M1（4 ビット）に変換する。特殊値なし・上限超過は最大値 6.0。
    #[must_use]
    pub fn to_e2m1(self, rm: Rm) -> (E2M1, u8) {
        if self.is_nan() || self.is_inf() {
            return (E2M1::from_bits(0x7 | ((self.decode().0 as u64) << 3)), 0);
        }
        let (r, f) = convert::<8, 23, 2, 1>(self, rm);
        // IEEE モデルで exp=3 行に丸め込まれた有限値は OCP では 4.0/6.0。
        if r.bits() & 0x7 != 0x6 {
            return (r, f);
        }
        let (neg, exp, frac) = self.decode();
        let sgn = (neg as u64) << 3;
        let eu = exp as i64 - 127;
        let m24 = (1u64 << 23) | frac;
        // 値は 2^2*(1+m)。frac1 = round(m*2)。eu = 2 では (m24-2^23)/2^22。
        let (q, rem, half) = if eu == 2 {
            let shift = 22u32;
            let num = m24 - (1 << 23);
            (num >> shift, num & ((1 << shift) - 1), 1u64 << (shift - 1))
        } else if eu > 2 {
            // 6.0 超は最大値に飽和。
            return (E2M1::from_bits(0x7 | sgn), FP_NX);
        } else {
            // eu = 1 で IEEE モデルが exp=3 行に来るのは 3.5 以上のみ。
            (0, 1, 1)
        };
        let inc = match rm {
            Rm::Rne => rem > half || (rem == half && q & 1 == 1),
            Rm::Rtz => false,
            Rm::Rdn => neg && rem != 0,
            Rm::Rup => !neg && rem != 0,
            Rm::Rmm => rem >= half,
        };
        let q = (q + u64::from(inc)).min(1);
        (
            E2M1::from_bits(0x6 | q | sgn),
            if rem != 0 { FP_NX } else { 0 },
        )
    }
}

impl F64 {
    /// 32 ビット形式に変換する。
    #[must_use]
    pub fn to_f32(self, rm: Rm) -> (F32, u8) {
        convert(self, rm)
    }
}

impl BF16 {
    /// 32 ビット形式に変換する。
    #[must_use]
    pub fn to_f32(self, rm: Rm) -> (F32, u8) {
        convert(self, rm)
    }
}

/// FP8/FP4 の小さい形式から 32 ビットへの変換。
impl E4M3 {
    /// 32 ビット形式に変換する。OCP 仕様: 0x7F/0xFF が NaN。
    #[must_use]
    pub fn to_f32(self, rm: Rm) -> (F32, u8) {
        let v = self.bits() & 0xff;
        if v & 0x7f == 0x7f {
            return (F32::canonical_nan(), 0);
        }
        if v & 0x7f == 0x78 {
            // exp 欄 15・仮数 0 は 256.0。
            return (F32::from_bits((v >> 7) << 31 | 0x4380_0000), 0);
        }
        if v & 0x7f > 0x78 {
            // 0x79〜0x7E: 256 + frac*32。
            let mag = 256 + ((v & 7) * 32) as i64;
            let (r, _) = F32::from_i64(mag, Rm::Rne);
            return (F32::from_bits(r.bits() | (v >> 7) << 31), 0);
        }
        convert(self, rm)
    }
}

impl E5M2 {
    /// 32 ビット形式に変換する。
    #[must_use]
    pub fn to_f32(self, rm: Rm) -> (F32, u8) {
        convert(self, rm)
    }
}

impl E2M1 {
    /// 32 ビット形式に変換する。0x6 = 4.0、0x7 = 6.0。
    #[must_use]
    pub fn to_f32(self, rm: Rm) -> (F32, u8) {
        let v = self.bits() & 0xf;
        if v & 0x7 >= 0x6 {
            let mag = if v & 1 == 1 { 6 } else { 4 };
            let (r, _) = F32::from_i64(mag, Rm::Rne);
            return (F32::from_bits(r.bits() | (v >> 3) << 31), 0);
        }
        convert(self, rm)
    }
}

/// 整数の絶対値から浮動小数点を作る。RNE。
fn from_mag<const E: u32, const M: u32>(neg: bool, mag: u128, rm: Rm) -> (Binary<E, M>, u8) {
    if mag == 0 {
        return (Binary::zero_signed(neg), 0);
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
    finish::<E, M>(neg, &mut e, &mut m, sticky, rm)
}

/// 形式を変える。指数範囲の違いは `finish` が扱う。
fn convert<const E1: u32, const M1: u32, const E2: u32, const M2: u32>(
    v: Binary<E1, M1>,
    rm: Rm,
) -> (Binary<E2, M2>, u8) {
    let (neg, exp, frac) = v.decode();
    if v.is_nan() {
        let f = if v.is_signaling_nan() { FP_NV } else { 0 };
        return (Binary::<E2, M2>::canonical_nan(), f);
    }
    if v.is_inf() {
        return (Binary::<E2, M2>::inf(neg), 0);
    }
    if v.is_zero() {
        return (Binary::<E2, M2>::zero_signed(neg), 0);
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
    finish::<E2, M2>(neg, &mut e, &mut m, sticky, rm)
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
        assert_eq!(one.add(two).0.bits(), 0x4008_0000_0000_0000);
        assert_eq!(two.sub(one).0.bits(), one.bits());
        assert_eq!(one.mul(two).0.bits(), two.bits());
        assert_eq!(two.div(one).0.bits(), two.bits());
    }

    #[test]
    fn special_values() {
        let inf = F64::inf(false);
        let ninf = F64::inf(true);
        let zero = F64::zero();
        // inf + -inf は NaN。
        assert!(inf.add(ninf).0.is_nan());
        // 0/0 は NaN。
        assert!(zero.div(zero).0.is_nan());
        // 有限/0 は無限大。
        let one = F64::from_bits(0x3ff0_0000_0000_0000);
        assert_eq!(one.div(zero).0.bits(), inf.bits());
        // 0 * inf は NaN。
        assert!(zero.mul(inf).0.is_nan());
        // -0 + -0 は -0、それ以外は +0。
        let nzero = F64::from_bits(0x8000_0000_0000_0000);
        assert_eq!(nzero.add(nzero).0.bits(), nzero.bits());
        assert_eq!(nzero.add(zero).0.bits(), zero.bits());
    }

    #[test]
    fn f32_basic() {
        let one = F32::from_bits(0x3f80_0000);
        let two = F32::from_bits(0x4000_0000);
        assert_eq!(one.add(two).0.bits(), 0x4040_0000);
        assert_eq!(one.mul(two).0.bits(), two.bits());
    }

    #[test]
    fn fp8_fp4_basic() {
        let one = F32::from_bits(0x3f80_0000);
        // E4M3: bias 7、1.0 は 0x38。
        let a = one.to_e4m3(Rm::Rne);
        assert_eq!(a.0.bits(), 0x38);
        assert_eq!(a.1, 0);
        assert_eq!(a.0.to_f32(Rm::Rne).0.bits(), one.bits());
        // E5M2: bias 15、1.0 は 0x3c。
        let b = one.to_e5m2(Rm::Rne);
        assert_eq!(b.0.bits(), 0x3c);
        assert_eq!(b.0.to_f32(Rm::Rne).0.bits(), one.bits());
        // E2M1: bias 1、1.0 は 0b0010。
        let c = one.to_e2m1(Rm::Rne);
        assert_eq!(c.0.bits(), 0x2);
        assert_eq!(c.0.to_f32(Rm::Rne).0.bits(), one.bits());
        // 丸め: E4M3 は仮数 3 ビット。1.0625 (0x3f880000) は 0x38 に偶数側で丸まる。
        let m = F32::from_bits(0x3f88_0000).to_e4m3(Rm::Rne);
        assert_eq!(m.0.bits(), 0x38);
        assert_eq!(m.1, FP_NX);
        // E5M2 の無限大は 0x7c。
        assert!(E5M2::from_bits(0x7c).is_inf());
        // NaN は正準 NaN に畳む。
        assert!(F32::from_bits(0x7fc0_0000).to_e4m3(Rm::Rne).0.is_nan());
    }

    #[test]
    fn fp8_fp4_ocp_top_row() {
        // OCP: E4M3 の exp=15 は有限値（256〜448）、0x7F のみ NaN。
        assert_eq!(E4M3::from_bits(0x7e).to_f32(Rm::Rne).0.bits(), 0x43e0_0000); // 448
        assert!(E4M3::from_bits(0x7f).to_f32(Rm::Rne).0.is_nan());
        // f32 256〜448 → 0x78〜0x7E。
        assert_eq!(F32::from_bits(0x4380_0000).to_e4m3(Rm::Rne).0.bits(), 0x78); // 256
        assert_eq!(F32::from_bits(0x43e0_0000).to_e4m3(Rm::Rne).0.bits(), 0x7e); // 448
        // 448 と次の刻み 480 の中点 464 は偶数側 448 へ。超過は NaN。
        assert_eq!(F32::from_bits(0x43e8_0000).to_e4m3(Rm::Rne).0.bits(), 0x7e); // 464
        assert_eq!(F32::from_bits(0x43f0_0000).to_e4m3(Rm::Rne).0.bits(), 0x7f); // 480→NaN
        assert_eq!(F32::inf(false).to_e4m3(Rm::Rne).0.bits(), 0x7f);
        // 248 は 240/256 の中点。偶数側の 256 に寄せる。
        assert_eq!(F32::from_bits(0x4378_0000).to_e4m3(Rm::Rne).0.bits(), 0x78); // 248
        // OCP: E2M1 の 0x6=4.0・0x7=6.0。
        assert_eq!(E2M1::from_bits(0x6).to_f32(Rm::Rne).0.bits(), 0x4080_0000);
        assert_eq!(E2M1::from_bits(0x7).to_f32(Rm::Rne).0.bits(), 0x40c0_0000);
        assert_eq!(F32::from_bits(0x4080_0000).to_e2m1(Rm::Rne).0.bits(), 0x6); // 4.0
        assert_eq!(F32::from_bits(0x40c0_0000).to_e2m1(Rm::Rne).0.bits(), 0x7); // 6.0
        assert_eq!(F32::from_bits(0x40e0_0000).to_e2m1(Rm::Rne).0.bits(), 0x7); // 7.0→飽和
        // NaN は最大値 0x7 に寄せる（OCP の E2M1 に NaN はない）。
        assert_eq!(F32::from_bits(0x7fc0_0000).to_e2m1(Rm::Rne).0.bits(), 0x7);
    }

    #[test]
    fn sqrt_cases() {
        let four = F64::from_bits(0x4010_0000_0000_0000);
        let two = F64::from_bits(0x4000_0000_0000_0000);
        assert_eq!(four.sqrt().0.bits(), two.bits());
        assert_eq!(F64::zero().sqrt().0.bits(), F64::zero().bits());
        assert!(F64::from_bits(0xbff0_0000_0000_0000).sqrt().0.is_nan());
        assert_eq!(F64::inf(false).sqrt().0.bits(), F64::inf(false).bits());
        // 2 の平方根は丸めで決まる。
        assert_eq!(two.sqrt().0.bits(), 0x3ff6_a09e_667f_3bcd);
    }

    #[test]
    fn int_conversions() {
        let one5 = F64::from_bits(0x3ff8_0000_0000_0000);
        assert_eq!(one5.to_i64(Rm::Rne).0, 2);
        assert_eq!(one5.to_u64(Rm::Rne).0, 2);
        let neg = F64::from_bits(0xbff8_0000_0000_0000);
        assert_eq!(neg.to_i64(Rm::Rne).0, -2);
        assert_eq!(neg.to_u64(Rm::Rne).0, 0);
        // 範囲外は飽和する。
        assert_eq!(
            F64::from_bits(0x43e0_0000_0000_0000).to_i64(Rm::Rne).0,
            i64::MAX
        );
        assert_eq!(
            F64::from_bits(0xc3e0_0000_0000_0000).to_i64(Rm::Rne).0,
            i64::MIN
        );
        assert_eq!(F64::canonical_nan().to_i64(Rm::Rne).0, i64::MAX);
        assert_eq!(F64::canonical_nan().to_u64(Rm::Rne).0, u64::MAX);
        // 整数からは正確に丸める。u64::MAX は 2^64 に切り上がる。
        assert_eq!(F64::from_i64(-42, Rm::Rne).0.bits(), 0xc045_0000_0000_0000);
        assert_eq!(
            F64::from_u64(u64::MAX, Rm::Rne).0.bits(),
            0x43f0_0000_0000_0000
        );
        assert_eq!(F32::from_bits(0x3f80_0000).to_i64(Rm::Rne).0, 1);
    }

    #[test]
    fn f32_f64_convert() {
        let one = F32::from_bits(0x3f80_0000);
        assert_eq!(one.to_f64(Rm::Rne).0.bits(), 0x3ff0_0000_0000_0000);
        let back: F32 = one.to_f64(Rm::Rne).0.to_f32(Rm::Rne).0;
        assert_eq!(back.bits(), one.bits());
        // 狭める方向は丸める。
        let third64 = F64::from_bits(0x3fd5_5555_5555_5555);
        assert_eq!(third64.to_f32(Rm::Rne).0.bits(), 0x3eaa_aaab);
    }

    #[test]
    fn comparisons() {
        let one = F64::from_bits(0x3ff0_0000_0000_0000);
        let two = F64::from_bits(0x4000_0000_0000_0000);
        let nan = F64::canonical_nan();
        let pz = F64::zero();
        let nz = F64::from_bits(0x8000_0000_0000_0000);
        assert!(one.lt(two).0);
        assert!(!two.lt(one).0);
        assert!(one.le(one).0);
        assert!(pz.eq(nz).0);
        assert!(!nan.eq(nan).0);
        assert!(!nan.lt(one).0);
        assert!(!one.lt(nan).0);
        assert_eq!(one.fmin(two).0.bits(), one.bits());
        assert_eq!(one.fmax(two).0.bits(), two.bits());
        assert_eq!(nan.fmin(one).0.bits(), one.bits());
        assert_eq!(one.fmin(nan).0.bits(), one.bits());
        assert_eq!(pz.fmax(nz).0.bits(), pz.bits());
        assert_eq!(pz.fmin(nz).0.bits(), nz.bits());
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
                (r.0.bits(), f64::from_bits(a) + f64::from_bits(b))
            },
            20_000,
        );
    }

    #[test]
    fn diff_sub() {
        diff_f64(
            |a, b| {
                let r = F64::from_bits(a).sub(F64::from_bits(b));
                (r.0.bits(), f64::from_bits(a) - f64::from_bits(b))
            },
            20_000,
        );
    }

    #[test]
    fn diff_mul() {
        diff_f64(
            |a, b| {
                let r = F64::from_bits(a).mul(F64::from_bits(b));
                (r.0.bits(), f64::from_bits(a) * f64::from_bits(b))
            },
            20_000,
        );
    }

    #[test]
    fn diff_div() {
        diff_f64(
            |a, b| {
                let r = F64::from_bits(a).div(F64::from_bits(b));
                (r.0.bits(), f64::from_bits(a) / f64::from_bits(b))
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
            assert_eq!(r.0.bits(), w.to_bits(), "add a={a:#x} b={b:#x}");
            let r = F64::from_bits(a).sub(F64::from_bits(b));
            let w = f64::from_bits(a) - f64::from_bits(b);
            assert_eq!(r.0.bits(), w.to_bits(), "sub a={a:#x} b={b:#x}");
            let r = F64::from_bits(a).mul(F64::from_bits(b));
            let w = f64::from_bits(a) * f64::from_bits(b);
            assert_eq!(r.0.bits(), w.to_bits(), "mul a={a:#x} b={b:#x}");
            let r = F64::from_bits(a).div(F64::from_bits(b));
            let w = f64::from_bits(a) / f64::from_bits(b);
            if w.is_nan() {
                assert!(r.0.is_nan(), "div nan a={a:#x} b={b:#x}");
            } else {
                assert_eq!(r.0.bits(), w.to_bits(), "div a={a:#x} b={b:#x}");
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
                assert!(r.0.is_nan(), "sqrt nan {a:#x}");
            } else {
                assert_eq!(r.0.bits(), w.to_bits(), "sqrt {a:#x}");
            }
            if fa.is_finite() && fa.abs() < 9.0e18 {
                // `as` は切り捨てなので、RNE の期待値は round_ties_even で作る。
                assert_eq!(
                    F64::from_bits(a).to_i64(Rm::Rne).0,
                    fa.round_ties_even() as i64,
                    "to_i64 {a:#x}"
                );
                if fa >= 0.0 {
                    assert_eq!(
                        F64::from_bits(a).to_u64(Rm::Rne).0,
                        fa.round_ties_even() as u64,
                        "to_u64 {a:#x}"
                    );
                }
                assert_eq!(
                    F64::from_bits(a).to_f32(Rm::Rne).0.bits() as u32,
                    (fa as f32).to_bits(),
                    "to_f32 {a:#x}"
                );
            }
            let b = next();
            let fb = f64::from_bits(b);
            assert_eq!(F64::from_bits(a).eq(F64::from_bits(b)).0, fa == fb, "eq");
            assert_eq!(
                F64::from_bits(a).lt(F64::from_bits(b)).0,
                fa < fb,
                "lt {a:#x} {b:#x}"
            );
            assert_eq!(
                F64::from_bits(a).fmin(F64::from_bits(b)).0.bits(),
                fa.min(fb).to_bits(),
                "min {a:#x} {b:#x}"
            );
            assert_eq!(
                F64::from_bits(a).fmax(F64::from_bits(b)).0.bits(),
                fa.max(fb).to_bits(),
                "max {a:#x} {b:#x}"
            );
            let c = next() as u32;
            // NaN は正規化される（RISC-V の fcvt と同じ）。それ以外は host と一致する。
            let fc = F32::from_bits(u64::from(c));
            if fc.is_nan() {
                assert!(fc.to_f64(Rm::Rne).0.is_nan(), "f32 to f64 nan {c:#x}");
            } else {
                assert_eq!(
                    fc.to_f64(Rm::Rne).0.bits(),
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
                (r.0.bits() as u32, f32::from_bits(a) + f32::from_bits(b))
            },
            20_000,
        );
        diff_f32(
            |a, b| {
                let r = F32::from_bits(u64::from(a)).sub(F32::from_bits(u64::from(b)));
                (r.0.bits() as u32, f32::from_bits(a) - f32::from_bits(b))
            },
            20_000,
        );
        diff_f32(
            |a, b| {
                let r = F32::from_bits(u64::from(a)).mul(F32::from_bits(u64::from(b)));
                (r.0.bits() as u32, f32::from_bits(a) * f32::from_bits(b))
            },
            20_000,
        );
        diff_f32(
            |a, b| {
                let r = F32::from_bits(u64::from(a)).div(F32::from_bits(u64::from(b)));
                (r.0.bits() as u32, f32::from_bits(a) / f32::from_bits(b))
            },
            20_000,
        );
    }
}
