// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! DEC の浮動小数点（VAX の F/D/G/H、PDP-11 の F/D、Alpha の F/G）を
//! 整数演算で実装する。
//!
//! 形式は IEEE の二進形式と同じフィールド配置（符号・指数・仮数）だが、
//! 解釈が違う。隠れビットを含む仮数は `[0.5, 1)` の範囲を取り、値は
//! `±f * 2^(e - bias)`（f は仮数）。指数部 0 は、符号が 0 なら零
//! （"dirty zero" も零として読む）、符号が 1 なら予約オペランドである。
//! 無限大と NaN は存在しない。指数部の最大値も普通の数である。
//!
//! 例外は `FP_NV`（予約オペランド・0 除算など）、`FP_OF`、
//! `FP_UF` を返す。VAX の規則では、オーバーフローはエラーで結果は
//! 不定、アンダーフローは真の零になる。この実装は決定性のため、
//! オーバーフロー時は符号つきの最大有限値を返す。
//! 丸めは呼び出し側の `Rm` に従う（VAX の演算は 0.5 ulp を足して
//! 切り捨てる規則で、`Rm::Rmm` に近い）。
// Ref: VAX Architecture Reference Manual の F/D/G/H 形式（事実のみ）。

use crate::{FP_DZ, FP_NV, FP_OF, FP_UF, Rm};
use core::cmp::Ordering;

/// DEC の浮動小数点。指数 E ビット（バイアス 2^(E-1)）、仮数 M ビット
/// （隠れビット込みで M+1 ビットの有效数字）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VaxF<const E: u32, const M: u32> {
    bits: u128,
}

/// VAX の F 形式（32 ビット、指数 8、仮数 23+隠れ 1）。
pub type VaxFF = VaxF<8, 23>;
/// VAX の D 形式（64 ビット、指数 8、仮数 55+隠れ 1）。
pub type VaxDF = VaxF<8, 55>;
/// VAX の G 形式（64 ビット、指数 11、仮数 52+隠れ 1）。
pub type VaxGF = VaxF<11, 52>;
/// VAX の H 形式（128 ビット、指数 15、仮数 112+隠れ 1）。
pub type VaxHF = VaxF<15, 112>;

fn bitlen(v: u128) -> i64 {
    128 - v.leading_zeros() as i64
}

#[allow(clippy::should_implement_trait)]
impl<const E: u32, const M: u32> VaxF<E, M> {
    const WIDTH: u32 = 1 + E + M;
    const BIAS: i64 = 1i64 << (E - 1);
    const EMAX: u64 = (1u64 << E) - 1;

    /// ビット列から作る。幅より上は切り捨てる。
    #[must_use]
    pub const fn from_bits(bits: u128) -> Self {
        Self {
            bits: bits & Self::mask(),
        }
    }

    /// ビット列を取り出す。
    #[must_use]
    pub const fn bits(self) -> u128 {
        self.bits
    }

    const fn mask() -> u128 {
        if Self::WIDTH >= 128 {
            u128::MAX
        } else {
            (1u128 << Self::WIDTH) - 1
        }
    }

    const fn fmask() -> u128 {
        (1u128 << M) - 1
    }

    /// 符号・指数・仮数に分解する。
    fn decode(self) -> (bool, u32, u128) {
        let neg = (self.bits >> (E + M)) & 1 == 1;
        let exp = ((self.bits >> M) & Self::EMAX as u128) as u32;
        let frac = self.bits & Self::fmask();
        (neg, exp, frac)
    }

    /// 予約オペランドかどうか（指数 0 で符号が 1）。NaN に相当する。
    #[must_use]
    pub fn is_reserved(self) -> bool {
        let (neg, exp, _) = self.decode();
        exp == 0 && neg
    }

    /// ゼロかどうか。指数 0 で符号が 0（dirty zero を含む）。
    #[must_use]
    pub fn is_zero(self) -> bool {
        let (neg, exp, _) = self.decode();
        exp == 0 && !neg
    }

    /// 値を (符号係数, 指数) にほどく。値 = sig * 2^(e - BIAS - M - 1)。
    /// sig は M+1 ビット（隠れビット込み）。入力の正規化チェックは
    /// 呼び出し側が行い、非正規入力（先頭が 0）は受け付けない
    /// （DEC 形式は常に正規化済みである）。
    fn unpack(self) -> (bool, u128, i64) {
        let (neg, exp, frac) = self.decode();
        // sig = 2^M + frac、値 = sig * 2^(exp - BIAS - M - 1)。
        (
            neg,
            (1u128 << M) | frac,
            i64::from(exp) - Self::BIAS - i64::from(M) - 1,
        )
    }

    /// (係数, 指数) を形式に収める。sig はちょうど M+1 ビットで最上位が 1
    /// （0 も可）。指数範囲を検査し、範囲外はフラグつき。
    fn pack(neg: bool, sig: u128, e2: i64) -> (Self, u8) {
        if sig == 0 {
            return (Self::zero(), 0);
        }
        // sig は M+1 ビット → 指数部 = e2 + BIAS + M + 1。
        let eu = e2 + Self::BIAS + i64::from(M) + 1;
        if eu < 1 {
            // アンダーフロー。VAX は真の零を返す。
            return (Self::zero(), FP_UF);
        }
        if eu > Self::EMAX as i64 {
            // オーバーフロー。VAX はエラーで結果は不定。決定性のため
            // 符号つきの最大有限値を返す。
            let m = Self {
                bits: ((neg as u128) << (E + M)) | ((Self::EMAX as u128) << M) | Self::fmask(),
            };
            return (m, FP_OF);
        }
        (
            Self {
                bits: ((neg as u128) << (E + M))
                    | (((eu as u128) & Self::EMAX as u128) << M)
                    | (sig & Self::fmask()),
            },
            0,
        )
    }

    /// 正のゼロ。
    #[must_use]
    pub const fn zero() -> Self {
        Self { bits: 0 }
    }

    /// 加算。
    #[must_use]
    pub fn add(self, other: Self, rm: Rm) -> (Self, u8) {
        add_sub(self, other, false, rm)
    }

    /// 減算。
    #[must_use]
    pub fn sub(self, other: Self, rm: Rm) -> (Self, u8) {
        add_sub(self, other, true, rm)
    }

    /// 乗算。
    #[must_use]
    pub fn mul(self, other: Self, rm: Rm) -> (Self, u8) {
        let neg = self.decode().0 ^ other.decode().0;
        if self.is_reserved() || other.is_reserved() {
            return (Self::zero(), FP_NV);
        }
        if self.is_zero() || other.is_zero() {
            return (Self::zero(), 0);
        }
        let (_, m1, e1) = self.unpack();
        let (_, m2, e2) = other.unpack();
        // 積は最大 2M+2 ビット。M+2 ビット＋sticky に畳む。
        let mut p = m1 * m2;
        let mut e = e1 + e2;
        let mut sticky = false;
        while bitlen(p) > i64::from(M) + 2 {
            sticky |= (p & 1) != 0;
            p >>= 1;
            e += 1;
        }
        round_pack::<E, M>(neg, p, e, sticky, rm)
    }

    /// 除算。
    #[must_use]
    pub fn div(self, other: Self, rm: Rm) -> (Self, u8) {
        let neg = self.decode().0 ^ other.decode().0;
        if self.is_reserved() || other.is_reserved() {
            return (Self::zero(), FP_NV);
        }
        if other.is_zero() {
            return (Self::zero(), FP_DZ);
        }
        if self.is_zero() {
            return (Self::zero(), 0);
        }
        let (_, m1, e1) = self.unpack();
        let (_, m2, e2) = other.unpack();
        // 商を M+3 ビットほど作る。整数商から始め、余りから 1 ビット
        // ずつ下へ伸ばす（u128 に被除数を伸ばすと溢れるため）。
        let want = i64::from(M) + 2;
        let mut q = m1 / m2;
        let mut r = m1 % m2;
        let mut e = e1 - e2;
        let mut iters = 0;
        while bitlen(q) <= want && r != 0 && iters < 140 {
            let r2 = r << 1;
            q = (q << 1) | (r2 / m2);
            r = r2 % m2;
            e -= 1;
            iters += 1;
        }
        round_pack::<E, M>(neg, q, e, r != 0, rm)
    }

    /// 比較。等しければ 0。予約オペランドは FP_NV 相当として
    /// 呼び出し側に伝えるため `Option` で返す。
    #[must_use]
    pub fn cmp(self, other: Self) -> Option<i8> {
        if self.is_reserved() || other.is_reserved() {
            return None;
        }
        if self.is_zero() && other.is_zero() {
            return Some(0);
        }
        let s1 = self.decode().0;
        let s2 = other.decode().0;
        if s1 != s2 {
            return Some(if s1 { -1 } else { 1 });
        }
        let (_, m1, e1) = self.unpack();
        let (_, m2, e2) = other.unpack();
        let h1 = bitlen(m1) + e1;
        let h2 = bitlen(m2) + e2;
        let ord = if h1 != h2 {
            h1.cmp(&h2)
        } else {
            // 同じ高さ：係数を幅の大きい方に揃えて比較。
            let (mut x, mut y) = (m1, m2);
            let (dx, dy) = (bitlen(x), bitlen(y));
            if dx > dy {
                y <<= (dx - dy) as u32;
            } else if dy > dx {
                x <<= (dy - dx) as u32;
            }
            x.cmp(&y)
        };
        let v = match ord {
            Ordering::Less => -1,
            Ordering::Equal => 0,
            Ordering::Greater => 1,
        };
        Some(if s1 { -v } else { v })
    }

    /// 小さいか。予約オペランドがあれば偽。
    #[must_use]
    pub fn lt(self, other: Self) -> bool {
        self.cmp(other) == Some(-1)
    }

    /// 等しいか。予約オペランドがあれば偽。
    #[must_use]
    pub fn eq(self, other: Self) -> bool {
        self.cmp(other) == Some(0)
    }

    /// 別の形式に変換する。仮数が狭まるとき（D→G など）は RNE で
    /// 丸める。予約オペランドはそのまま写して FP_NV を返す。
    #[must_use]
    pub fn widen<const E2: u32, const M2: u32>(self) -> (VaxF<E2, M2>, u8) {
        if self.is_reserved() {
            return (
                VaxF::<E2, M2> {
                    bits: 1u128 << (E2 + M2),
                },
                FP_NV,
            );
        }
        if self.is_zero() {
            return (VaxF::<E2, M2>::zero(), 0);
        }
        let (neg, mut sig, mut eb) = self.unpack();
        // 係数を M2+1 ビットに揃える。落ちる桁は RNE で丸める。
        if M2 >= M {
            let d = M2 - M;
            sig <<= d;
            eb -= i64::from(d);
        } else {
            let d = M - M2;
            let dropped = sig & ((1u128 << d) - 1);
            sig >>= d;
            eb += i64::from(d);
            let guard = (dropped >> (d - 1)) & 1;
            let sticky = (dropped & ((1u128 << (d - 1)) - 1)) != 0;
            if guard != 0 && (sticky || (sig & 1) == 1) {
                sig += 1;
                if bitlen(sig) > i64::from(M2) + 1 {
                    sig >>= 1;
                    eb += 1;
                }
            }
        }
        VaxF::<E2, M2>::pack(neg, sig, eb)
    }
}

/// M+2 ビットの係数（最下位はガード）と sticky から最終結果を作る。
fn round_pack<const E: u32, const M: u32>(
    neg: bool,
    mut q: u128,
    mut e: i64,
    mut sticky: bool,
    rm: Rm,
) -> (VaxF<E, M>, u8) {
    let want = i64::from(M) + 2;
    while bitlen(q) > want {
        sticky |= (q & 1) != 0;
        q >>= 1;
        e += 1;
    }
    while q != 0 && bitlen(q) < want {
        q <<= 1;
        e -= 1;
    }
    if q == 0 {
        return (VaxF::<E, M>::zero(), 0);
    }
    let guard = (q & 1) as u8;
    q >>= 1;
    e += 1;
    let up = match rm {
        Rm::Rtz => false,
        Rm::Rup => !neg && (guard != 0 || sticky),
        Rm::Rdn => neg && (guard != 0 || sticky),
        Rm::Rmm => guard != 0,
        Rm::Rne => guard != 0 && (sticky || (q & 1) == 1),
    };
    if up {
        q += 1;
        if bitlen(q) > i64::from(M) + 1 {
            q >>= 1;
            e += 1;
        }
    }
    VaxF::pack(neg, q, e)
}

/// 加減算の中核。
fn add_sub<const E: u32, const M: u32>(
    a: VaxF<E, M>,
    b: VaxF<E, M>,
    flip: bool,
    rm: Rm,
) -> (VaxF<E, M>, u8) {
    let s1 = a.decode().0;
    let mut s2 = b.decode().0;
    if flip {
        s2 = !s2;
    }
    if a.is_reserved() || b.is_reserved() {
        return (VaxF::zero(), FP_NV);
    }
    let z1 = a.is_zero();
    let z2 = b.is_zero();
    if z1 && z2 {
        return (VaxF::zero(), 0);
    }
    if z1 {
        // b の符号を flip に応じて変えた零ではない有限値を返す。
        let mut r = b;
        if flip {
            r.bits ^= 1u128 << (E + M);
        }
        return (r, 0);
    }
    if z2 {
        return (a, 0);
    }
    let (_, m1, e1) = a.unpack();
    let (_, m2, e2) = b.unpack();
    let (x, mut y, sx, sy, ex) = if e1 >= e2 {
        (m1, m2, s1, s2, e1)
    } else {
        (m2, m1, s2, s1, e2)
    };
    let diff = (e1 - e2).unsigned_abs().min(127);
    let mut dropped: u128 = 0;
    let r = diff.min(127) as u32;
    if r > 0 {
        dropped = y & ((1u128 << r.min(127)) - 1);
        y >>= r.min(127);
    }
    let dropped_nz = dropped != 0;
    let (mut q, neg) = if sx == sy {
        (x + y, sx)
    } else if x > y || (x == y && !dropped_nz) {
        (x - y, sx)
    } else {
        (y - x, sy)
    };
    if dropped_nz && sx != sy && neg != sy {
        q = q.saturating_sub(1);
    }
    if q == 0 {
        if !dropped_nz {
            return (VaxF::zero(), 0);
        }
        // 粗いスケールでは 0 だが、シフトで落ちた桁を含めると残余は
        // 零ではない。異符号（減算相当）のとき：
        //   neg == sx（x > シフト後 y、借りパス）: 値 = (2^r - dropped)
        //   neg == sy（x == シフト後 y）: 値 = -dropped（符号は sy）
        // 残余は 2^-r 細かいスケールなので指数を ex - r にずらす。
        let q2 = if neg == sx {
            (1u128 << r) - dropped
        } else {
            dropped
        };
        return round_pack::<E, M>(neg, q2, ex - i64::from(r), false, rm);
    }
    round_pack::<E, M>(neg, q, ex, dropped_nz, rm)
}
