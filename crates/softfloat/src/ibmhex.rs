// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! IBM の 16 進浮動小数点（s390 系の HFP）を整数演算で実装する。
//!
//! 形式は符号 1 ビット、特性指数 7 ビット（バイアス 64、底 16）、仮数 F
//! ビットである。値は `±(0.f 16 進) * 16^(e - 64)` で、仮数は F/4 桁の 16
//! 進数字として読む。正規化数は先頭の 16 進桁が非 0、非正規化数（先頭桁が
//! 0 のもの）もオペランドとして受け付ける。NaN と無限大は存在せず、全ビット
//! パターンが有限の数か零である。
//!
//! 例外は `FP_OF`（指数オーバーフロー）と `FP_UF`（指数アンダーフロー）を
//! 返す。s390 では、オーバーフロー時の結果は特性指数を 128 で包んだ値
//! （mod 128）、アンダーフロー抑制マスク（EUM）があれば真の零が返る。
//! この実装はそれに倣い、オーバーフローは包んだ値＋FP_OF、アンダーフロー
//! は真の零＋FP_UF を返す。丸めは呼び出し側の `Rm` に従う（伝統的な HFP
//! の演算は切り捨て `Rm::Rtz` に相当する）。
// Ref: s390 POP の HFP 形式定義（事実のみ）。

use crate::{FP_OF, FP_UF, Rm};
use core::cmp::Ordering;

/// 16 進浮動小数点。仮数は F ビット（4 の倍数）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HexF<const F: u32> {
    bits: u128,
}

/// 32 ビット形式（仮数 24 ビット＝6 桁）。
pub type Hf32 = HexF<24>;
/// 64 ビット形式（仮数 56 ビット＝14 桁）。
pub type Hf64 = HexF<56>;
/// 128 ビット形式（仮数 112 ビット＝28 桁）。下位語の符号・指数は 0 とする。
pub type Hf128 = HexF<112>;

/// u128 の値の 16 進の桁数を数える。
fn hexdig(c: u128) -> i64 {
    ((128 - c.leading_zeros() as i64) + 3) / 4
}

/// 二つの係数を、16 進の上位桁から順に比較する。桁数が違うときは
/// 短い方の下位を 0 とみなす（呼び出し側で同じ高さに揃える前提）。
fn hex_cmp(c1: u128, c2: u128) -> Ordering {
    let d1 = hexdig(c1);
    let d2 = hexdig(c2);
    let n = d1.max(d2);
    for k in (0..n).rev() {
        let g1 = if k < d1 {
            (c1 >> (k * 4) as u32) & 0xf
        } else {
            0
        };
        let g2 = if k < d2 {
            (c2 >> (k * 4) as u32) & 0xf
        } else {
            0
        };
        if g1 != g2 {
            return g1.cmp(&g2);
        }
    }
    Ordering::Equal
}

#[allow(clippy::should_implement_trait)]
impl<const F: u32> HexF<F> {
    const NDIG: u32 = F / 4;
    const WIDTH: u32 = 1 + 7 + F;

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
        (1u128 << Self::WIDTH) - 1
    }

    const fn fmask() -> u128 {
        (1u128 << F) - 1
    }

    /// 符号・特性指数・仮数に分解する。
    fn decode(self) -> (bool, u32, u128) {
        let neg = (self.bits >> (7 + F)) & 1 == 1;
        let exp = ((self.bits >> F) & 0x7f) as u32;
        let frac = self.bits & Self::fmask();
        (neg, exp, frac)
    }

    /// ゼロかどうか。仮数が全 0 なら指数・符号に関わらず真の零である。
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.bits & Self::fmask() == 0
    }

    /// 負かどうか。
    #[must_use]
    pub fn negative(self) -> bool {
        self.decode().0
    }

    /// 正規化数かどうか（先頭の 16 進桁が非 0）。
    #[must_use]
    pub fn is_normalized(self) -> bool {
        let (_, _, frac) = self.decode();
        frac >> (F - 4) != 0
    }

    /// 値を (係数, 16 進指数) にほどく。値 = coef * 16^e16。
    fn unpack(self) -> (bool, u128, i64) {
        let (neg, exp, frac) = self.decode();
        // frac は 0.frac の 16 進 NDIG 桁 → 整数化して指数を下げる。
        (neg, frac, i64::from(exp) - 64 - i64::from(Self::NDIG))
    }

    /// 正規化した (係数, 16 進指数) を形式に収める。coef はちょうど
    /// NDIG 桁で先頭が非 0（あるいは 0）であること。指数の範囲を
    /// 検査し、オーバーフローは包み（s390 流儀）、アンダーフローは
    /// 真の零にする。
    fn pack(neg: bool, coef: u128, e16: i64) -> (Self, u8) {
        if coef == 0 {
            return (Self::zero_signed(neg), 0);
        }
        let e7 = e16 + i64::from(Self::NDIG) + 64;
        if e7 < 0 {
            // アンダーフロー。s390 の EUM 動作で真の零を返す。
            return (Self::zero_signed(false), FP_UF);
        }
        let mut flags = 0u8;
        let mut e7 = e7;
        if e7 > 127 {
            // オーバーフロー。s390 は特性指数を mod 128 で包む。
            e7 &= 127;
            flags |= FP_OF;
        }
        (
            Self {
                bits: ((neg as u128) << (7 + F))
                    | (((e7 as u128) & 0x7f) << F)
                    | (coef & Self::fmask()),
            },
            flags,
        )
    }

    fn zero_signed(neg: bool) -> Self {
        Self {
            bits: (neg as u128) << (7 + F),
        }
    }

    /// 加算。`a + b`。
    #[must_use]
    pub fn add(self, other: Self, rm: Rm) -> (Self, u8) {
        add_sub(self, other, false, rm)
    }

    /// 減算。`a - b`。
    #[must_use]
    pub fn sub(self, other: Self, rm: Rm) -> (Self, u8) {
        add_sub(self, other, true, rm)
    }

    /// 乗算。
    #[must_use]
    pub fn mul(self, other: Self, rm: Rm) -> (Self, u8) {
        let (s1, _, _) = self.decode();
        let (s2, _, _) = other.decode();
        let neg = s1 ^ s2;
        if self.is_zero() || other.is_zero() {
            return (Self::zero_signed(neg), 0);
        }
        let (_, c1, e1) = self.unpack();
        let (_, c2, e2) = other.unpack();
        // 積の係数は最大 2*NDIG 桁。NDIG+1 桁＋sticky に畳む。
        let mut p = c1 * c2;
        let mut e = e1 + e2;
        let want = i64::from(Self::NDIG) + 1;
        let mut sticky = false;
        while hexdig(p) > want {
            sticky |= (p & 0xf) != 0;
            p >>= 4;
            e += 1;
        }
        round_pack::<F>(neg, p, e, sticky, rm)
    }

    /// 除算。
    #[must_use]
    pub fn div(self, other: Self, rm: Rm) -> (Self, u8) {
        let (s1, _, _) = self.decode();
        let (s2, _, _) = other.decode();
        let neg = s1 ^ s2;
        if other.is_zero() {
            // HFP の 0 除算はプログラム例外。決定的に +0 と DZ を返す。
            return (Self::zero_signed(neg), crate::FP_DZ);
        }
        if self.is_zero() {
            return (Self::zero_signed(neg), 0);
        }
        let (_, c1, e1) = self.unpack();
        let (_, c2, e2) = other.unpack();
        // 商を NDIG+2 桁ほど作る。整数商から始め、余りから 16 進
        // 桁を下へ伸ばす（u128 に被除数を伸ばすと溢れるため）。
        // 伸ばした桁ぶん指数を下げる。
        let mut q = c1 / c2;
        let mut r = c1 % c2;
        let mut e = e1 - e2;
        let mut iters = 0;
        while hexdig(q) <= i64::from(Self::NDIG) + 1 && r != 0 && iters < 64 {
            let r16 = r * 16;
            q = q * 16 + r16 / c2;
            r = r16 % c2;
            e -= 1;
            iters += 1;
        }
        round_pack::<F>(neg, q, e, r != 0, rm)
    }

    /// 比較。等しければ 0、小さければ -1、大きければ 1。
    /// 零は符号に関わらず等しい。
    #[must_use]
    pub fn cmp(self, other: Self) -> i8 {
        let z1 = self.is_zero();
        let z2 = other.is_zero();
        if z1 && z2 {
            return 0;
        }
        let (s1, _, _) = self.decode();
        let (s2, _, _) = other.decode();
        if s1 != s2 {
            return if s1 { -1 } else { 1 };
        }
        let (_, c1, e1) = self.unpack();
        let (_, c2, e2) = other.unpack();
        // 最高 16 進桁の位置（調整済み指数）で比較し、同じなら上位から
        // 桁ごとに比べる。
        let h1 = hexdig(c1) + e1;
        let h2 = hexdig(c2) + e2;
        let ord = if h1 != h2 {
            h1.cmp(&h2)
        } else {
            hex_cmp(c1, c2)
        };
        let v = match ord {
            Ordering::Less => -1,
            Ordering::Equal => 0,
            Ordering::Greater => 1,
        };
        if s1 { -v } else { v }
    }

    /// 小さいか。
    #[must_use]
    pub fn lt(self, other: Self) -> bool {
        self.cmp(other) < 0
    }

    /// 等しいか。
    #[must_use]
    pub fn eq(self, other: Self) -> bool {
        self.cmp(other) == 0
    }

    /// より広い形式に変換する（G > F）。係数の下位に 0 を足すだけ。
    #[must_use]
    pub fn widen<const G: u32>(self) -> HexF<G> {
        debug_assert!(G > F);
        let (neg, exp, frac) = self.decode();
        HexF::<G> {
            bits: ((neg as u128) << (7 + G))
                | (u128::from(exp) << G)
                | ((frac << (G - F)) & ((1u128 << G) - 1)),
        }
    }
}

/// 丸め用に残した NDIG+1 桁の係数と sticky から最終結果を作る。
/// 値は `q * 16^e` で、guard＝最下位桁、その下は sticky が表す。
fn round_pack<const F: u32>(
    neg: bool,
    mut q: u128,
    mut e: i64,
    mut sticky: bool,
    rm: Rm,
) -> (HexF<F>, u8) {
    let ndig = i64::from(HexF::<F>::NDIG);
    // 係数をちょうど NDIG+1 桁に正規化する。
    while hexdig(q) > ndig + 1 {
        sticky |= (q & 0xf) != 0;
        q >>= 4;
        e += 1;
    }
    while q != 0 && hexdig(q) < ndig + 1 {
        q <<= 4;
        e -= 1;
    }
    // 最下位桁がガード、それ以下は sticky。
    let guard = (q & 0xf) as u8;
    q >>= 4;
    e += 1;
    let up = match rm {
        Rm::Rtz => false,
        Rm::Rup => !neg && (guard != 0 || sticky),
        Rm::Rdn => neg && (guard != 0 || sticky),
        Rm::Rmm => guard >= 8,
        Rm::Rne => guard > 8 || (guard == 8 && (sticky || (q & 1) == 1)),
    };
    if up {
        q += 1;
        if hexdig(q) > ndig {
            q >>= 4;
            e += 1;
        }
    }
    HexF::pack(neg, q, e)
}

/// 加減算の中核。小さい指数側の係数を右に寄せて揃える。
fn add_sub<const F: u32>(a: HexF<F>, b: HexF<F>, flip: bool, rm: Rm) -> (HexF<F>, u8) {
    let (s1, _, _) = a.decode();
    let (mut s2, _, _) = b.decode();
    if flip {
        s2 = !s2;
    }
    let z1 = a.is_zero();
    let z2 = b.is_zero();
    if z1 && z2 {
        // 両方零。同符号ならその符号、違えば +0。
        return (HexF::zero_signed(s1 && s2), 0);
    }
    if z1 {
        return (b, 0);
    }
    if z2 {
        return (a, 0);
    }
    let (_, c1, e1) = a.unpack();
    let (_, c2, e2) = b.unpack();
    // 大きい指数の側を x とし、y を右に寄せて指数を揃える。
    // y の落ちた桁は dropped に残す（減算の借りと、ちょうど
    // 打ち消し合う端縁で使う）。
    let (x, mut y, sx, sy, ex) = if e1 >= e2 {
        (c1, c2, s1, s2, e1)
    } else {
        (c2, c1, s2, s1, e2)
    };
    let diff = if e1 >= e2 { e1 - e2 } else { e2 - e1 };
    let r = diff.min(31);
    let mut dropped: u128 = 0;
    if r > 0 {
        dropped = y & ((1u128 << (r * 4)) - 1);
        y >>= (r * 4) as u32;
    }
    if diff > 31 && y != 0 {
        // さらに下に非 0 の桁が残る。dropped は使わない。
        dropped = 1;
        y = 0;
    }
    let dropped_nz = dropped != 0;
    // 同符号なら加、異符号なら大きい方から引く。
    let (mut q, neg) = if sx == sy {
        (x + y, sx)
    } else if x > y {
        (x - y, sx)
    } else if x == y {
        if dropped_nz {
            // ちょうど打ち消し合い、残りは捨てた桁そのもの
            // （符号は y 側に従う）。
            return round_pack::<F>(sy, dropped, ex - r, false, rm);
        }
        return (HexF::zero_signed(false), 0);
    } else {
        (y - x, sy)
    };
    // 寄せた桁の落ちた分は y 側に属する。結果の符号が y と違う
    // （減算で小さい側から借りる）ときは真の残りが負なので 1 借りて
    // 正の残りに直す。
    if dropped_nz && sx != sy && neg != sy {
        q = q.saturating_sub(1);
    }
    round_pack::<F>(neg, q, ex, dropped_nz, rm)
}
