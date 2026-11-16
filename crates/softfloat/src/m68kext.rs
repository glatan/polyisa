// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Motorola 68881/68882 の拡張精度（96 ビット格納形式、値は 80 ビット）
//! を整数演算で実装する。
//!
//! 形式は符号 1 ビット、指数 15 ビット（バイアス 16383）、未使用 16
//! ビット、仮数 64 ビットである。仮数は整数ビットを明示的に持ち、
//! `1.m` の m が下位 63 ビット。値は `±(int.m) * 2^(e - 16383)`。
//! 正規化数は整数ビットが 1。指数 0 で仮数が非 0 なら非正規化数、
//! 指数 0 で仮数 0 なら零、指数が全 1 なら無限大（仮数 0）か NaN
//! （仮数非 0）。整数ビットが 0 の正規化範囲の値（unnormalized）も
//! 68881 はオペランドとして受け付ける。
//!
//! 例外は `FP_NV`（0 除算・NaN 生成など IEEE の 5 種）に合わせる。
//! 丸めは `Rm`（68881 の RN/RZ/RM/RP）に従う。
// Ref: MC68881/68882 ユーザーズマニュアルの拡張精度形式（事実のみ）。

use crate::{FP_DZ, FP_NV, FP_NX, FP_OF, FP_UF, Rm};
use core::cmp::Ordering;

/// 68881 の拡張精度（96 ビット）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct M68kExt {
    bits: u128,
}

const BIAS: i64 = 16383;
const EMAX: u32 = 0x7fff;

fn bitlen(v: u128) -> i64 {
    128 - v.leading_zeros() as i64
}

/// ガード・スティッキー・最下位ビットから丸め上げるか決める。
fn round_up(neg: bool, guard: bool, sticky: bool, last: bool, rm: Rm) -> bool {
    match rm {
        Rm::Rtz => false,
        Rm::Rup => !neg && (guard || sticky),
        Rm::Rdn => neg && (guard || sticky),
        Rm::Rmm => guard,
        Rm::Rne => guard && (sticky || last),
    }
}

impl M68kExt {
    /// ビット列から作る。上位 32 ビットは切り捨てる。
    /// レイアウトは格納形式と同じ：bit95 符号、bit94:80 指数、
    /// bit79:64 未使用、bit63:0 仮数（bit63 が整数ビット）。
    #[must_use]
    pub const fn from_bits(bits: u128) -> Self {
        Self {
            bits: bits & ((1u128 << 96) - 1),
        }
    }

    /// 符号・指数・仮数フィールドから組み立てる（未使用部は 0）。
    #[must_use]
    pub const fn from_parts(neg: bool, exp: u32, mant: u64) -> Self {
        Self {
            bits: ((neg as u128) << 95) | (((exp as u128) & 0x7fff) << 80) | (mant as u128),
        }
    }

    /// ビット列を取り出す。
    #[must_use]
    pub const fn bits(self) -> u128 {
        self.bits
    }

    fn decode(self) -> (bool, u32, u64) {
        let neg = (self.bits >> 95) & 1 == 1;
        let exp = ((self.bits >> 80) & 0x7fff) as u32;
        let mant = self.bits as u64;
        (neg, exp, mant)
    }

    /// NaN かどうか（指数全 1、仮数非 0）。
    #[must_use]
    pub fn is_nan(self) -> bool {
        let (_, e, m) = self.decode();
        e == EMAX && m != 0
    }

    /// シグナリング NaN かどうか。quiet ビットは bit62（整数ビット直下）。
    #[must_use]
    pub fn is_signaling_nan(self) -> bool {
        let (_, e, m) = self.decode();
        e == EMAX && m != 0 && (m >> 62) & 1 == 0
    }

    /// 無限大かどうか。
    #[must_use]
    pub fn is_inf(self) -> bool {
        let (_, e, m) = self.decode();
        e == EMAX && m == 0
    }

    /// ゼロかどうか（指数 0、仮数 0）。
    #[must_use]
    pub fn is_zero(self) -> bool {
        let (_, e, m) = self.decode();
        e == 0 && m == 0
    }

    /// 非正規化数かどうか（指数 0 で仮数非 0）。
    #[must_use]
    pub fn is_denormal(self) -> bool {
        let (_, e, m) = self.decode();
        e == 0 && m != 0
    }

    /// 負かどうか。
    #[must_use]
    pub fn negative(self) -> bool {
        self.decode().0
    }

    /// 正の無限大。
    #[must_use]
    pub const fn inf(neg: bool) -> Self {
        Self::from_parts(neg, EMAX, 0)
    }

    /// 正のゼロ。
    #[must_use]
    pub const fn zero() -> Self {
        Self { bits: 0 }
    }

    /// 正準 NaN（68881 が生成する NaN：符号 0、指数全 1、仮数全 1）。
    #[must_use]
    pub const fn canonical_nan() -> Self {
        Self::from_parts(false, EMAX, u64::MAX)
    }

    /// 値を (係数 u128, 2 進指数) にほどく。値 = sig * 2^e2 で、
    /// 正規化数は sig が 64 ビット（bit63=1）。非正規化数と
    /// unnormalized（整数ビット 0 の普通の指数）はそのまま返す。
    fn unpack(self) -> (bool, u128, i64) {
        let (neg, exp, mant) = self.decode();
        if exp == 0 {
            // 非正規化数。値 = mant * 2^(1 - 16383 - 63)。
            (neg, u128::from(mant), 1 - BIAS - 63)
        } else {
            // 正規化・unnormalized 共通。値 = mant * 2^(exp - 16383 - 63)。
            (neg, u128::from(mant), i64::from(exp) - BIAS - 63)
        }
    }

    /// (係数, 指数) を形式に収める。値 = sig * 2^e2。sig は任意の
    /// ビット数でよく、ここで正規化（bit63 が最上位）と非正規化への
    /// 落とし込みを行う。sticky は係数の下にまだ非 0 があるか。
    /// ガードは sig 内の最下位 1 ビットではなく、shift で落ちた
    /// 最上位を sticky とは別に扱うため内部で保持する。
    fn pack(neg: bool, mut sig: u128, mut e2: i64, mut sticky: i8, rm: Rm) -> (Self, u8) {
        if sig == 0 && sticky == 0 {
            return (Self::zero_signed(neg), 0);
        }
        let mut flags = 0u8;
        // 正規化：bit63 が最上位になるよう合わせる。最後に落ちた
        // ビットを guard、残りは sticky に畳む。
        let mut guard = 0i8;
        while bitlen(sig) > 64 {
            sticky |= guard;
            guard = i8::from((sig & 1) != 0);
            sig >>= 1;
            e2 += 1;
        }
        // unnormalized 入力など bit63 が 0 のときは左へ。
        while sig != 0 && (sig >> 63) & 1 == 0 {
            sig <<= 1;
            e2 -= 1;
        }
        if sig == 0 {
            // 全部落ちた：sticky だけが残る。
            return Self::underflow_zero(neg, rm, sticky);
        }
        // 値 = sig * 2^e2、sig の最上位が bit63 → 格納指数 = e2 + 63 + BIAS。
        let eu = e2 + 63 + BIAS;
        if eu >= i64::from(EMAX) {
            // オーバーフロー。丸めモードで無限大か最大有限値。
            let to_inf = match rm {
                Rm::Rtz | Rm::Rmm => false,
                Rm::Rup => !neg,
                Rm::Rdn => neg,
                Rm::Rne => true,
            };
            flags |= FP_OF | FP_NX;
            if to_inf {
                return (Self::inf(neg), flags);
            }
            return (Self::from_parts(neg, EMAX - 1, u64::MAX), flags);
        }
        if eu <= 0 {
            // 非正規化領域。mant = sig >> (1 - eu) で指数 0 に揃える。
            let s = (1 - eu) as u32;
            let (mut mant, g2, s2) = if s >= 65 {
                // すべて落ちる。最上位ビットがガードになるか判定。
                if s == 65 {
                    (
                        0u128,
                        i8::from((sig >> 63) & 1 == 1),
                        sticky | i8::from((sig & ((1u128 << 63) - 1)) != 0),
                    )
                } else {
                    (0u128, 0, sticky | i8::from(sig != 0))
                }
            } else {
                let dropped = sig & ((1u128 << s) - 1);
                let m = sig >> s;
                (
                    m,
                    i8::from(((dropped >> (s - 1)) & 1) == 1),
                    sticky | i8::from((dropped & ((1u128 << (s - 1)) - 1)) != 0),
                )
            };
            let last = (mant & 1) != 0;
            let up = round_up(neg, g2 != 0, s2 != 0, last, rm);
            if g2 != 0 || s2 != 0 {
                flags |= FP_NX | FP_UF;
            }
            if up {
                mant += 1;
                // 丸めで bit63 まで来たら最小の正規化数。
                if (mant >> 63) & 1 == 1 {
                    return (Self::from_parts(neg, 1, mant as u64), flags);
                }
            }
            if mant == 0 {
                return (Self::zero_signed(neg), flags);
            }
            return (Self::from_parts(neg, 0, mant as u64), flags);
        }
        // 正規化数の経路。sig は 64 ビットで最上位が 1。
        // 呼び出し側の丸め済みの値に対し、ここでは畳まれた
        // guard/sticky だけが残る（round_window で丸めた後は 0）。
        if guard != 0 || sticky != 0 {
            flags |= FP_NX;
            let last = (sig & 1) != 0;
            if round_up(neg, guard != 0, sticky != 0, last, rm) {
                sig += 1;
                if bitlen(sig) > 64 {
                    sig >>= 1;
                    e2 += 1;
                    let eu2 = e2 + 63 + BIAS;
                    if eu2 >= i64::from(EMAX) {
                        return (Self::inf(neg), flags | FP_OF);
                    }
                }
            }
        }
        (
            Self::from_parts(neg, (e2 + 63 + BIAS) as u32, sig as u64),
            flags,
        )
    }

    /// アンダーフローで値が零になるときの処理。
    fn underflow_zero(neg: bool, rm: Rm, sticky: i8) -> (Self, u8) {
        // 値は最小非正規化数の半分未満。Rup/Rdn なら最小値に
        // なり得るが、ここまで来るケースは丸め窓側で処理するため
        // 単純に符号つき零を返す。
        let _ = rm;
        (
            Self::zero_signed(neg),
            u8::from(sticky != 0) * (FP_UF | FP_NX),
        )
    }

    fn zero_signed(neg: bool) -> Self {
        Self::from_parts(neg, 0, 0)
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
        if self.is_nan() || other.is_nan() {
            let f = u8::from(self.is_signaling_nan() || other.is_signaling_nan()) * FP_NV;
            return (Self::canonical_nan(), f);
        }
        if (self.is_inf() && other.is_zero()) || (other.is_inf() && self.is_zero()) {
            return (Self::canonical_nan(), FP_NV);
        }
        if self.is_inf() || other.is_inf() {
            return (Self::inf(neg), 0);
        }
        if self.is_zero() || other.is_zero() {
            return (Self::zero_signed(neg), 0);
        }
        let (_, m1, e1) = self.unpack();
        let (_, m2, e2) = other.unpack();
        // 積は最大 128 ビット。上から 64+2 ビットに畳む。
        let mut p = m1 * m2;
        let mut e = e1 + e2;
        let mut sticky = 0i8;
        while bitlen(p) > 66 {
            sticky |= i8::from((p & 1) != 0);
            p >>= 1;
            e += 1;
        }
        round_window(neg, p, e, sticky, rm)
    }

    /// 除算。
    #[must_use]
    pub fn div(self, other: Self, rm: Rm) -> (Self, u8) {
        let neg = self.decode().0 ^ other.decode().0;
        if self.is_nan() || other.is_nan() {
            let f = u8::from(self.is_signaling_nan() || other.is_signaling_nan()) * FP_NV;
            return (Self::canonical_nan(), f);
        }
        if self.is_inf() && other.is_inf() {
            return (Self::canonical_nan(), FP_NV);
        }
        if self.is_inf() {
            return (Self::inf(neg), 0);
        }
        if other.is_inf() {
            return (Self::zero_signed(neg), 0);
        }
        if other.is_zero() {
            if self.is_zero() {
                return (Self::canonical_nan(), FP_NV);
            }
            return (Self::inf(neg), FP_DZ);
        }
        if self.is_zero() {
            return (Self::zero_signed(neg), 0);
        }
        let (_, m1, e1) = self.unpack();
        let (_, m2, e2) = other.unpack();
        // 商を 67 ビットほど作る。整数商から始め、余りから 1 ビット
        // ずつ下へ伸ばす（u128 に被除数を伸ばすと溢れるため）。
        let mut q = m1 / m2;
        let mut r = m1 % m2;
        let mut e = e1 - e2;
        let mut iters = 0;
        while bitlen(q) <= 66 && r != 0 && iters < 140 {
            let r2 = r << 1;
            q = (q << 1) | (r2 / m2);
            r = r2 % m2;
            e -= 1;
            iters += 1;
        }
        round_window(neg, q, e, i8::from(r != 0), rm)
    }

    /// 比較。NaN があれば None。
    #[must_use]
    #[allow(clippy::should_implement_trait)]
    pub fn cmp(self, other: Self) -> Option<i8> {
        if self.is_nan() || other.is_nan() {
            return None;
        }
        if self.is_zero() && other.is_zero() {
            return Some(0);
        }
        let s1 = self.decode().0;
        let s2 = other.decode().0;
        // 無限大は符号で順序づく（-inf < +inf）。
        match (self.is_inf(), other.is_inf()) {
            (true, true) => {
                return Some(if s1 == s2 {
                    0
                } else if s1 {
                    -1
                } else {
                    1
                });
            }
            (true, false) => return Some(if s1 { -1 } else { 1 }),
            (false, true) => return Some(if s2 { 1 } else { -1 }),
            _ => {}
        }
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

    /// 等しいか。
    #[must_use]
    #[allow(clippy::should_implement_trait)]
    pub fn eq(self, other: Self) -> bool {
        self.cmp(other) == Some(0)
    }

    /// 小さいか。
    #[must_use]
    pub fn lt(self, other: Self) -> bool {
        self.cmp(other) == Some(-1)
    }
}

/// 66 ビットの窓（係数の上位 64＋ガード 1＋その下 sticky）から
/// 最終結果を作る。値 = q * 2^e で、最下位 2 ビットがガード相当では
/// なく、bit0 が sticky 合成・bit1 がガードという形ではなく、
/// 呼び出し側が 66 ビットの値を渡す。
fn round_window(neg: bool, mut q: u128, mut e: i64, mut sticky: i8, rm: Rm) -> (M68kExt, u8) {
    // q をちょうど 66 ビットに揃える（下 2 ビットがガードと予備）。
    while bitlen(q) > 66 {
        sticky |= i8::from((q & 1) != 0);
        q >>= 1;
        e += 1;
    }
    while q != 0 && bitlen(q) < 66 {
        q <<= 1;
        e -= 1;
    }
    if q == 0 && sticky == 0 {
        return (M68kExt::zero_signed(neg), 0);
    }
    // 最下位 2 ビットをガード＋ラウンドに使う。
    let round = (q & 2) != 0;
    sticky |= i8::from((q & 1) != 0);
    let mut sig = q >> 2;
    e += 2;
    let last = (sig & 1) != 0;
    let up = match rm {
        Rm::Rtz => false,
        Rm::Rup => !neg && (round || sticky != 0),
        Rm::Rdn => neg && (round || sticky != 0),
        Rm::Rmm => round,
        Rm::Rne => round && (sticky != 0 || last),
    };
    let flags = u8::from(round || sticky != 0) * FP_NX;
    if up {
        sig += 1;
        if bitlen(sig) > 64 {
            sig >>= 1;
            e += 1;
        }
    }
    let (r, f) = M68kExt::pack(neg, sig, e, 0, rm);
    (r, f | flags)
}

/// 加減算の中核。
fn add_sub(a: M68kExt, b: M68kExt, flip: bool, rm: Rm) -> (M68kExt, u8) {
    let s1 = a.decode().0;
    let mut s2 = b.decode().0;
    if flip {
        s2 = !s2;
    }
    if a.is_nan() || b.is_nan() {
        let f = u8::from(a.is_signaling_nan() || b.is_signaling_nan()) * FP_NV;
        return (M68kExt::canonical_nan(), f);
    }
    match (a.is_inf(), b.is_inf()) {
        (true, true) => {
            if s1 == s2 {
                return (M68kExt::inf(s1), 0);
            }
            return (M68kExt::canonical_nan(), FP_NV);
        }
        (true, false) => return (M68kExt::inf(s1), 0),
        (false, true) => return (M68kExt::inf(s2), 0),
        _ => {}
    }
    let z1 = a.is_zero();
    let z2 = b.is_zero();
    if z1 && z2 {
        return (M68kExt::zero_signed(s1 && s2), 0);
    }
    if z1 {
        let mut r = b;
        if flip {
            r.bits ^= 1u128 << 95;
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
    let diff = (e1 - e2).unsigned_abs();
    let r = diff.min(127) as u32;
    let mut dropped: u128 = 0;
    if r > 0 {
        dropped = y & ((1u128 << r) - 1);
        y >>= r;
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
            return (M68kExt::zero_signed(false), 0);
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
        return round_window(neg, q2, ex - i64::from(r), 0, rm);
    }
    round_window(neg, q, ex, i8::from(dropped_nz), rm)
}
