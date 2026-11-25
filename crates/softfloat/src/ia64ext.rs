// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! IA-64 の浮動小数点レジスタファイル形式（82 ビット）を整数演算で
//! 実装する。
//!
//! 形式は符号 1 ビット、指数 17 ビット（バイアス 0xFFFF）、仮数 64
//! ビット（整数ビットを明示的に持つ）。値は `±(int.m) * 2^(e - 0xFFFF)`。
//! IEEE 形式と異なり、仮数が 0 の指数非 0 エンコーディング（pseudo-zero）
//! や整数ビット 0 の指数非 0 値（unnormalized）もオペランドとして許容
//! される。NaTVal は別ビットではなく `{符号0, 指数0x1FFFE, 仮数0}` の
//! エンコーディングとして仮数レジスタ内に保持される。
//!
//! 演算結果は常に最も正規化された表現で書き戻される。`fma` 系は
//! 丸めモードに加えて出力形式（仮数ビット数と指数範囲。sf の pc/wre
//! または .s/.d 完了子が選ぶ）を `Fmt` で受け取る。ftz が立つときは
//! 形式の非正規域に届く結果を符号つき零に畳む。
//! Ref: SPEC-IA64-SDM (Rev 2.3), SPEC-IEEE754 (2019).

use crate::{F64, FP_DZ, FP_NV, FP_NX, FP_OF, FP_UF, Rm};
use core::cmp::Ordering;

/// 指数バイアス。
pub const BIAS: i64 = 0xffff;
/// 特殊値（Inf/NaN）の指数場。
pub const EXP_SPECIAL: u32 = 0x1ffff;
/// 有限値の最大指数場。
pub const EXP_MAX_FINITE: u32 = 0x1fffe;
/// 整数・ペア（並列単精度）形式が使う指数場（2.063 のバイアス指数）。
/// 値は仮数をそのまま符号なし整数として読む `sig * 2^0` になる。
pub const EXP_INT: u32 = 0x1003e;

const SIGN_BIT: u128 = 1 << 81;
const SIG_INF: u64 = 1 << 63;
/// 整数不定値（fcvt.fx の invalid 結果仮数）。
pub const INT_INDEF: u64 = 0x8000_0000_0000_0000;

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

/// 値の分類（fclass の 9 クラスと対応）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FClass {
    /// NaTVal（符号 0・指数 0x1FFFE・仮数 0）。
    NatVal,
    /// quiet NaN（指数全 1、仮数 bit62=1）。
    QNan,
    /// signaling NaN・pseudo-NaN（指数全 1、仮数非 0、bit62=0）。
    SNan,
    /// 無限大（指数全 1、仮数 = 1<<63）。
    Inf,
    /// 零（仮数 0。pseudo-zero を含む）。
    Zero,
    /// 非正規化数（指数 0、仮数非 0）。
    Denorm,
    /// unnormalized（指数非 0、整数ビット 0、pseudo-denormal を含む）。
    Unnorm,
    /// 正規化数（整数ビット 1、有限指数）。
    Norm,
}

/// 出力形式。`sig` は仮数ビット数（整数ビット込み）、`emin`/`emax`
/// は無バイアス指数の範囲（1.m の指数）。
#[derive(Clone, Copy, Debug)]
pub struct Fmt {
    /// 仮数ビット数（24/53/64）。
    pub sig: u32,
    /// 最小正規化指数（無バイアス）。
    pub emin: i64,
    /// 最大指数（無バイアス）。
    pub emax: i64,
}

/// レジスタ形式そのまま（64 ビット仮数・17 ビット指数域）。
pub const FMT_REG: Fmt = Fmt {
    sig: 64,
    emin: 1 - BIAS,
    emax: BIAS,
};
/// 単精度形式（24 ビット仮数・8 ビット指数域）。
pub const FMT_S: Fmt = Fmt {
    sig: 24,
    emin: -126,
    emax: 127,
};
/// 倍精度形式（53 ビット仮数・11 ビット指数域）。
pub const FMT_D: Fmt = Fmt {
    sig: 53,
    emin: -1022,
    emax: 1023,
};
/// 拡張精度メモリ形式（64 ビット仮数・15 ビット指数域）。
pub const FMT_E: Fmt = Fmt {
    sig: 64,
    emin: -16382,
    emax: 16383,
};

/// IA-64 の 82 ビット浮動小数点レジスタ値。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ia64Ext {
    bits: u128,
}

impl Ia64Ext {
    /// 下位 82 ビットの生の並びから作る。
    #[must_use]
    pub const fn from_bits(bits: u128) -> Self {
        Self {
            bits: bits & ((1u128 << 82) - 1),
        }
    }

    /// 符号・指数・仮数から組み立てる。
    #[must_use]
    pub const fn from_parts(neg: bool, exp: u32, sig: u64) -> Self {
        Self {
            bits: ((neg as u128) << 81) | (((exp as u128) & 0x1ffff) << 64) | (sig as u128),
        }
    }

    /// ビット列を取り出す。
    #[must_use]
    pub const fn bits(self) -> u128 {
        self.bits
    }

    fn decode(self) -> (bool, u32, u64) {
        (
            self.bits & SIGN_BIT != 0,
            ((self.bits >> 64) & 0x1ffff) as u32,
            self.bits as u64,
        )
    }

    /// +0.0。
    pub const ZERO: Self = Self { bits: 0 };
    /// +1.0（FR1 の定数）。
    pub const ONE: Self = Self::from_parts(false, 0xffff, SIG_INF);
    /// NaTVal。
    pub const NATVAL: Self = Self::from_parts(false, EXP_MAX_FINITE, 0);
    /// 正準 quiet NaN（符号 0・指数全 1・仮数全 1）。
    pub const QNAN: Self = Self::from_parts(false, EXP_SPECIAL, u64::MAX);
    /// 符号つき無限大。
    #[must_use]
    pub const fn inf(neg: bool) -> Self {
        Self::from_parts(neg, EXP_SPECIAL, SIG_INF)
    }
    /// 符号つき零。
    #[must_use]
    pub const fn zero_signed(neg: bool) -> Self {
        Self::from_parts(neg, 0, 0)
    }
    /// 整数形式（符号 0・指数 EXP_INT・仮数そのまま）。
    #[must_use]
    pub const fn int_form(sig: u64) -> Self {
        Self::from_parts(false, EXP_INT, sig)
    }

    /// 分類。
    #[must_use]
    pub fn class(self) -> FClass {
        let (neg, e, m) = self.decode();
        if e == EXP_SPECIAL {
            if m == SIG_INF {
                FClass::Inf
            } else if (m >> 62) & 1 == 1 {
                FClass::QNan
            } else {
                FClass::SNan
            }
        } else if m == 0 {
            if e == EXP_MAX_FINITE && !neg {
                FClass::NatVal
            } else {
                FClass::Zero
            }
        } else if e == 0 {
            FClass::Denorm
        } else if (m >> 63) & 1 == 0 {
            FClass::Unnorm
        } else {
            FClass::Norm
        }
    }

    /// NaTVal かどうか。
    #[must_use]
    pub fn is_natval(self) -> bool {
        self.class() == FClass::NatVal
    }

    /// NaN かどうか。
    #[must_use]
    pub fn is_nan(self) -> bool {
        matches!(self.class(), FClass::QNan | FClass::SNan)
    }

    /// 無限大かどうか。
    #[must_use]
    pub fn is_inf(self) -> bool {
        self.class() == FClass::Inf
    }

    /// 零かどうか（pseudo-zero を含む）。
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.class() == FClass::Zero
    }

    /// 非正規化・unnormalized な有限オペランドか（FPSR の D 旗用）。
    #[must_use]
    pub fn is_denormal_operand(self) -> bool {
        matches!(self.class(), FClass::Denorm | FClass::Unnorm)
    }

    /// 負かどうか。
    #[must_use]
    pub fn negative(self) -> bool {
        self.decode().0
    }

    /// 符号場（false=正）。
    #[must_use]
    pub fn sign_bit(self) -> bool {
        self.decode().0
    }

    /// 指数場（17 ビットの生値）。
    #[must_use]
    pub fn exp_field(self) -> u32 {
        self.decode().1
    }

    /// 仮数場（64 ビットの生値）。
    #[must_use]
    pub fn sig(self) -> u64 {
        self.decode().2
    }

    /// 符号を反転した値。
    #[must_use]
    pub fn negated(self) -> Self {
        Self::from_bits(self.bits ^ SIGN_BIT)
    }

    /// 有限値を (符号, 係数 u128, LSB 指数) にほどく。
    /// 値 = sig * 2^e2。非正規化（e=0）は e=1 と同じ重み、
    /// unnormalized はそのままの仮数で返す。
    fn unpack(self) -> (bool, u128, i64) {
        let (neg, e, m) = self.decode();
        let e2 = i64::from(e.max(1)) - BIAS - 63;
        (neg, u128::from(m), e2)
    }

    /// (係数, 指数, sticky) を `fmt` の形式に収める。
    /// 値 = sig * 2^e2（sig の最上位は任意）。fmt.sig への丸め・
    /// 指数範囲・ftz・レジスタ非正規化をここで処理する。
    fn pack(
        neg: bool,
        mut sig: u128,
        mut e2: i64,
        mut sticky: i8,
        rm: Rm,
        fmt: Fmt,
        ftz: bool,
    ) -> (Self, u8) {
        if sig == 0 && sticky == 0 {
            return (Self::zero_signed(neg), 0);
        }
        let mut flags = 0u8;
        let mut guard = 0i8;
        while bitlen(sig) > 64 {
            sticky |= guard;
            guard = i8::from((sig & 1) != 0);
            sig >>= 1;
            e2 += 1;
        }
        while sig != 0 && (sig >> 63) & 1 == 0 {
            sig <<= 1;
            e2 -= 1;
        }
        if sig == 0 {
            return (
                Self::zero_signed(neg),
                u8::from(sticky != 0) * (FP_NX | FP_UF),
            );
        }
        // 値 = sig * 2^e2、sig の最上位が bit63。
        let eu = e2 + 63 + BIAS;
        let inexact = guard != 0 || sticky != 0;
        if eu <= 0 {
            // レジスタ非正規領域。ftz なら零へ畳む。
            if ftz {
                return (Self::zero_signed(neg), flags | FP_UF | FP_NX);
            }
            let s = (1 - eu) as u32;
            let (mut mant, g2, s2) = if s >= 65 {
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
                (
                    sig >> s,
                    i8::from(((dropped >> (s - 1)) & 1) == 1),
                    sticky | i8::from((dropped & ((1u128 << (s - 1)) - 1)) != 0),
                )
            };
            if g2 != 0 || s2 != 0 {
                flags |= FP_NX | FP_UF;
            }
            let last = (mant & 1) != 0;
            if round_up(neg, g2 != 0, s2 != 0, last, rm) {
                mant += 1;
                if (mant >> 63) & 1 == 1 {
                    return (Self::from_parts(neg, 1, mant as u64), flags);
                }
            }
            if mant == 0 {
                return (Self::zero_signed(neg), flags);
            }
            return (Self::from_parts(neg, 0, mant as u64), flags);
        }
        // fmt.sig ビットへの丸め。
        let drop = 64 - fmt.sig;
        if drop > 0 {
            let dropped = sig & ((1u128 << drop) - 1);
            let g2 = ((dropped >> (drop - 1)) & 1) as i8;
            sticky |= guard | i8::from((dropped & ((1u128 << (drop - 1)) - 1)) != 0);
            guard = g2;
            sig >>= drop;
        }
        let inexact2 = inexact || guard != 0 || sticky != 0;
        if inexact2 {
            flags |= FP_NX;
        }
        let last = (sig & 1) != 0;
        if round_up(neg, guard != 0, sticky != 0, last, rm) {
            sig += 1;
            if bitlen(sig) > i64::from(fmt.sig) {
                sig >>= 1;
                e2 += 1;
            }
        }
        // 値 = sig * 2^(e2 + drop)、sig の最上位は bit(fmt.sig-1)。
        // よって無バイアス指数は e2 + drop + fmt.sig - 1 = e2 + 63。
        let unb = e2 + 63;
        if unb > fmt.emax {
            // オーバーフロー。
            flags |= FP_OF | FP_NX;
            let to_inf = match rm {
                Rm::Rtz | Rm::Rmm => false,
                Rm::Rup => !neg,
                Rm::Rdn => neg,
                Rm::Rne => true,
            };
            if to_inf {
                return (Self::inf(neg), flags);
            }
            let kept = ((1u128 << fmt.sig) - 1) << drop;
            return (
                Self::from_parts(neg, (fmt.emax + BIAS) as u32, kept as u64),
                flags,
            );
        }
        if unb < fmt.emin {
            // 形式の非正規域に届く値。U は inexact のときだけ立て、
            // ftz なら零へ畳む。
            if inexact2 {
                flags |= FP_UF;
            }
            if ftz {
                return (Self::zero_signed(neg), flags);
            }
        }
        (
            Self::from_parts(neg, (unb + BIAS) as u32, (sig << drop) as u64),
            flags,
        )
    }

    /// 積和融合 `a * b + c`（1 回丸め）。NaTVal はそのまま伝播する。
    #[must_use]
    pub fn fmadd(self, b: Self, c: Self, rm: Rm, fmt: Fmt, ftz: bool) -> (Self, u8) {
        let (a, bb, cc) = (self, b, c);
        if a.is_natval() || bb.is_natval() || cc.is_natval() {
            return (Self::NATVAL, 0);
        }
        if a.is_nan() || bb.is_nan() || cc.is_nan() {
            let f = u8::from(matches!(
                (a.class(), bb.class(), cc.class()),
                (FClass::SNan, _, _) | (_, FClass::SNan, _) | (_, _, FClass::SNan)
            )) * FP_NV;
            return (Self::QNAN, f);
        }
        let (s1, s2, s3) = (a.decode().0, bb.decode().0, cc.decode().0);
        let sp = s1 ^ s2;
        let (i1, i2, i3) = (a.is_inf(), bb.is_inf(), cc.is_inf());
        let (z1, z2, z3) = (a.is_zero(), bb.is_zero(), cc.is_zero());
        if (i1 && z2) || (z1 && i2) {
            return (Self::QNAN, FP_NV);
        }
        if i1 || i2 {
            if i3 && s3 != sp {
                return (Self::QNAN, FP_NV);
            }
            return (Self::inf(sp), 0);
        }
        if i3 {
            return (Self::inf(s3), 0);
        }
        if z1 || z2 {
            if z3 {
                return (
                    if sp == s3 {
                        Self::zero_signed(sp)
                    } else {
                        Self::zero_signed(false)
                    },
                    0,
                );
            }
            // 積が零でも加数は出力形式に丸める（fma.s で +64 ビットの
            // 値を通さない）。
            let (n3, m3, e3) = cc.unpack();
            return Self::pack(n3, m3, e3, 0, rm, fmt, ftz);
        }
        // 厳密な積と加数を 121 ビット窓に揃える（Binary::fmadd_rm と
        // 同じ手法。積は最大 128 ビット、加数は最大 64 ビット）。
        let (neg1, m1, l1) = a.unpack();
        let (neg2, m2, l2) = bb.unpack();
        let (_, m3, l3) = cc.unpack();
        debug_assert_eq!(neg1 ^ neg2, sp);
        let m_p = m1 * m2;
        let l_p = l1 + l2;
        let msb_p = l_p + bitlen(m_p) - 1;
        let msb3 = l3 + bitlen(m3) - 1;
        let top = msb_p.max(msb3);
        let base = top - 120;
        let mut sticky = 0i8;
        let mut s_jam = 0i8;
        let mut acc = 0u128;
        let mut neg = false;
        let mut first = true;
        for (mm, lsb, s) in [(m_p, l_p, sp), (m3, l3, s3)] {
            let shift = lsb - base;
            let mut v = mm;
            if shift >= 0 {
                v <<= shift as u32;
            } else {
                let d = (-shift) as u32;
                if d >= 128 {
                    if v != 0 {
                        sticky = 1;
                        s_jam += if s { -1 } else { 1 };
                    }
                    v = 0;
                } else {
                    let dropped = v & ((1u128 << d) - 1);
                    v >>= d;
                    if dropped != 0 {
                        sticky = 1;
                        s_jam += if s { -1 } else { 1 };
                    }
                }
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
            if sticky != 0 {
                // 切り捨てた端数だけが残れば微小な非零。丸め窓の
                // 最小目盛より 50 桁以上小さいので零に畳む。
                return (Self::zero_signed(s_jam < 0), FP_NX);
            }
            // 厳密な相殺: 零の符号は負丸めのときだけ負。
            return (Self::zero_signed(rm == Rm::Rdn), 0);
        }
        Self::pack(neg, acc, base, sticky, rm, fmt, ftz)
    }

    /// 除算。frcpa の近似値計算にも使う。
    #[must_use]
    pub fn div(self, other: Self, rm: Rm, fmt: Fmt) -> (Self, u8) {
        let (a, b) = (self, other);
        if a.is_natval() || b.is_natval() {
            return (Self::NATVAL, 0);
        }
        let neg = a.decode().0 ^ b.decode().0;
        if a.is_nan() || b.is_nan() {
            let f = u8::from(matches!(
                (a.class(), b.class()),
                (FClass::SNan, _) | (_, FClass::SNan)
            )) * FP_NV;
            return (Self::QNAN, f);
        }
        if a.is_inf() && b.is_inf() {
            return (Self::QNAN, FP_NV);
        }
        if a.is_inf() {
            return (Self::inf(neg), 0);
        }
        if b.is_inf() {
            return (Self::zero_signed(neg), 0);
        }
        if b.is_zero() {
            if a.is_zero() {
                return (Self::QNAN, FP_NV);
            }
            return (Self::inf(neg), FP_DZ);
        }
        if a.is_zero() {
            return (Self::zero_signed(neg), 0);
        }
        let (_, m1, e1) = a.unpack();
        let (_, m2, e2) = b.unpack();
        // 商を 66 ビットほど作り、余りは sticky へ。
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
        Self::pack(neg, q, e, i8::from(r != 0), rm, fmt, false)
    }

    /// 比較。NaN 入力は None。
    #[must_use]
    pub fn compare(self, other: Self) -> Option<Ordering> {
        let (a, b) = (self, other);
        if a.is_nan() || b.is_nan() {
            return None;
        }
        let az = a.is_zero();
        let bz = b.is_zero();
        if az && bz {
            return Some(Ordering::Equal);
        }
        if az {
            return Some(if b.negative() {
                Ordering::Greater
            } else {
                Ordering::Less
            });
        }
        if bz {
            return Some(if a.negative() {
                Ordering::Less
            } else {
                Ordering::Greater
            });
        }
        let s1 = a.decode().0;
        let s2 = b.decode().0;
        if a.is_inf() || b.is_inf() {
            let ia = a.is_inf();
            let ib = b.is_inf();
            return Some(if ia && ib {
                match s1.cmp(&s2) {
                    Ordering::Equal => Ordering::Equal,
                    _ => {
                        if s1 {
                            Ordering::Less
                        } else {
                            Ordering::Greater
                        }
                    }
                }
            } else if ia {
                if s1 {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            } else if s2 {
                Ordering::Greater
            } else {
                Ordering::Less
            });
        }
        if s1 != s2 {
            return Some(if s1 {
                Ordering::Less
            } else {
                Ordering::Greater
            });
        }
        let (_, m1, e1) = a.unpack();
        let (_, m2, e2) = b.unpack();
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
        Some(if s1 { ord.reverse() } else { ord })
    }

    /// fmin/fmax/famin/famax。`abs` 真なら絶対値で比較する。
    /// NaN は正準 QNaN（SNaN 入力で NV）。
    #[must_use]
    pub fn min_max(self, other: Self, max: bool, abs: bool) -> (Self, u8) {
        let (a, b) = (self, other);
        if a.is_natval() || b.is_natval() {
            return (Self::NATVAL, 0);
        }
        let (ca, cb) = (a.class(), b.class());
        if ca == FClass::SNan || cb == FClass::SNan {
            return (Self::QNAN, FP_NV);
        }
        if ca == FClass::QNan || cb == FClass::QNan {
            return (Self::QNAN, 0);
        }
        let ord = if abs {
            let am = Self::from_bits(a.bits & !SIGN_BIT);
            let bm = Self::from_bits(b.bits & !SIGN_BIT);
            am.compare(bm)
        } else {
            a.compare(b)
        };
        let pick_a = match ord {
            Some(Ordering::Less) => !max,
            Some(Ordering::Greater) => max,
            Some(Ordering::Equal) | None => {
                // 等しい（±0 含む）: min は負側、max は正側を選ぶ。
                if max { !a.negative() } else { a.negative() }
            }
        };
        (if pick_a { a } else { b }, 0)
    }

    /// fclass の 9 クラス選択との一致。選択は
    /// {NaTVal(bit8), QNaN(7), SNaN(6)} 直和、または
    /// {pos(0), neg(1)} × {zero(2), unorm(3), norm(4), inf(5)} の積。
    #[must_use]
    pub fn fclass_hit(self, sel: u32) -> bool {
        match self.class() {
            FClass::NatVal => sel & 0x100 != 0,
            FClass::QNan => sel & 0x080 != 0,
            FClass::SNan => sel & 0x040 != 0,
            c => {
                let sign_ok = if self.negative() {
                    sel & 0x002 != 0
                } else {
                    sel & 0x001 != 0
                };
                let t = match c {
                    FClass::Zero => 0x004,
                    FClass::Denorm | FClass::Unnorm => 0x008,
                    FClass::Norm => 0x010,
                    _ => 0x020,
                };
                sign_ok && sel & t != 0
            }
        }
    }

    /// 整数への変換（fcvt.fx/fxu）。結果は 64 ビットの整数
    /// （符号つきは two's complement）。不正入力は整数不定値 + NV。
    #[must_use]
    pub fn to_int(self, unsigned: bool, rm: Rm) -> (u64, u8) {
        match self.class() {
            FClass::NatVal => (0, 0),
            FClass::QNan | FClass::SNan | FClass::Inf => (INT_INDEF, FP_NV),
            FClass::Zero => (0, 0),
            _ => {
                let (neg, m, e2) = self.unpack();
                // 整数 LSB でのガード・スティッキーを作る。
                let (mut q, guard, sticky) = if e2 >= 0 {
                    if e2 + bitlen(m) > 64 {
                        return (INT_INDEF, FP_NV);
                    }
                    (m << e2 as u32, false, false)
                } else {
                    let d = (-e2) as u32;
                    if d >= 128 {
                        (0, false, m != 0)
                    } else {
                        let dropped = m & ((1u128 << d) - 1);
                        (
                            m >> d,
                            ((dropped >> (d - 1)) & 1) != 0,
                            (dropped & ((1u128 << (d - 1)) - 1)) != 0,
                        )
                    }
                };
                let flags = u8::from(guard || sticky) * FP_NX;
                let last = (q & 1) != 0;
                if round_up(neg, guard, sticky, last, rm) {
                    q += 1;
                }
                let (v, ok) = if unsigned {
                    (q as u64, !neg && q <= u64::MAX as u128)
                } else if neg {
                    let lim = 1u128 << 63;
                    (q.wrapping_neg() as u64, q <= lim)
                } else {
                    (q as u64, q <= i64::MAX as u128)
                };
                if !ok {
                    return (INT_INDEF, flags | FP_NV);
                }
                (v, flags)
            }
        }
    }

    /// 64 ビット符号つき整数からの変換（fcvt.xf。常に厳密）。
    #[must_use]
    pub fn from_i64(v: i64) -> Self {
        if v == 0 {
            return Self::ZERO;
        }
        let neg = v < 0;
        let m = v.unsigned_abs();
        let sh = m.leading_zeros();
        let sig = (m as u128) << sh;
        // 値 = sig * 2^-sh。
        Self::from_parts(neg, 63 - sh + BIAS as u32, sig as u64)
    }

    /// 64 ビット符号なし整数からの変換（xma/fcvt.xuf 相当の正規化）。
    #[must_use]
    pub fn from_u64(v: u64) -> (Self, u8) {
        if v == 0 {
            return (Self::ZERO, 0);
        }
        let sh = v.leading_zeros();
        let sig = (v as u128) << sh;
        (
            Self::from_parts(false, 63 - sh + BIAS as u32, sig as u64),
            0,
        )
    }

    /// IEEE 形式（符号 1 + 指数 E + 仮数 M）への変換。
    /// ビット列を返す。丸め・非正規化・オーバーフローは IEEE どおり。
    #[must_use]
    pub fn to_bin<const E: u32, const M: u32>(self, rm: Rm) -> (u64, u8) {
        let bias_e = (1i64 << (E - 1)) - 1;
        let emax_e = (1i64 << E) - 1;
        let (neg, _e, m) = self.decode();
        let cls = self.class();
        let sign_bit = (neg as u64) << (E + M);
        match cls {
            FClass::NatVal => (sign_bit, 0),
            FClass::SNan | FClass::QNan => {
                // 仮数の最上位 M-1 ビットを payload に、quiet ビットを立てる。
                let payload = (m >> (63 - M)) & ((1u64 << M) - 1) & !(1u64 << (M - 1));
                (
                    sign_bit | ((emax_e as u64) << M) | (1u64 << (M - 1)) | payload,
                    if cls == FClass::SNan { FP_NV } else { 0 },
                )
            }
            FClass::Inf => (sign_bit | ((emax_e as u64) << M), 0),
            FClass::Zero => (sign_bit, 0),
            _ => {
                let (neg, mut mm, mut ee) = self.unpack();
                while mm != 0 && (mm >> 63) & 1 == 0 {
                    mm <<= 1;
                    ee -= 1;
                }
                let mut flags = 0u8;
                let sticky = 0i8;
                let unb = ee + 63;
                let be = unb + bias_e;
                if be >= emax_e {
                    let to_inf = match rm {
                        Rm::Rtz | Rm::Rmm => false,
                        Rm::Rup => !neg,
                        Rm::Rdn => neg,
                        Rm::Rne => true,
                    };
                    flags |= FP_OF | FP_NX;
                    if to_inf {
                        return (sign_bit | ((emax_e as u64) << M), flags);
                    }
                    return (
                        sign_bit | (((emax_e - 1) as u64) << M) | ((1u64 << M) - 1),
                        flags,
                    );
                }
                // 非正規化シフト量（対象形式の仮数位置まで右揃え）。
                let s = if be < 1 { (1 - be) as u32 } else { 0 };
                let sh = 63 - M + s;
                let (mut frac, g, st) = if sh >= 64 {
                    // 全部落ちる。MSB がガード。
                    if sh == 64 {
                        (
                            0u128,
                            (mm >> 63) & 1 == 1,
                            sticky | i8::from((mm & ((1u128 << 63) - 1)) != 0),
                        )
                    } else {
                        (0u128, false, sticky | i8::from(mm != 0))
                    }
                } else {
                    let dropped = mm & ((1u128 << sh) - 1);
                    (
                        mm >> sh,
                        ((dropped >> (sh - 1)) & 1) != 0,
                        sticky | i8::from((dropped & ((1u128 << (sh - 1)) - 1)) != 0),
                    )
                };
                if g || st != 0 {
                    flags |= FP_NX;
                    if s > 0 {
                        flags |= FP_UF;
                    }
                }
                let last = (frac & 1) != 0;
                if round_up(neg, g, st != 0, last, rm) {
                    frac += 1;
                }
                if frac >= (1u128 << (M + 1)) {
                    // 丸めのキャリーで正規化数 1 個上がる。
                    frac >>= 1;
                    let be2 = be + 1;
                    if be2 >= emax_e {
                        return (sign_bit | ((emax_e as u64) << M), flags | FP_OF);
                    }
                    return (
                        sign_bit | ((be2 as u64) << M) | (frac as u64 & ((1u64 << M) - 1)),
                        flags,
                    );
                }
                if be >= 1 {
                    // 正規化数。frac は M+1 ビット（隠れビット込み）。
                    // 丸めで M ビットを越えた場合は最小正規化数。
                    if frac >= (1u128 << M) {
                        (
                            sign_bit | ((be as u64) << M) | (frac as u64 & ((1u64 << M) - 1)),
                            flags,
                        )
                    } else {
                        // 非正規化位置で 1 に届かないことは無い（be>=1）。
                        (sign_bit | ((be as u64) << M) | frac as u64, flags)
                    }
                } else if frac >= (1u128 << M) {
                    // 非正規化数の丸めが最小正規化数に届いた。
                    (sign_bit | (1u64 << M), flags)
                } else {
                    (sign_bit | frac as u64, flags)
                }
            }
        }
    }

    /// IEEE 形式のビット列から作る（単精度・倍精度の拡大は厳密）。
    #[must_use]
    pub fn from_bin<const E: u32, const M: u32>(bits: u64) -> Self {
        let bias_e = (1i64 << (E - 1)) - 1;
        let neg = (bits >> (E + M)) & 1 != 0;
        let e = ((bits >> M) & ((1u64 << E) - 1)) as u32;
        let frac = bits & ((1u64 << M) - 1);
        if e == (1u32 << E) - 1 {
            if frac == 0 {
                return Self::inf(neg);
            }
            // NaN。quiet ビットは仮数最上位。
            let sig = SIG_INF | ((frac & ((1u64 << M) - 1)) << (63 - M));
            return Self::from_parts(neg, EXP_SPECIAL, sig);
        }
        if e == 0 {
            if frac == 0 {
                return Self::zero_signed(neg);
            }
            // 非正規化数。値 = frac * 2^(1 - bias - M)。
            let m = u128::from(frac);
            let (r, _) = Self::pack(
                neg,
                m,
                1 - bias_e - i64::from(M),
                0,
                Rm::Rne,
                FMT_REG,
                false,
            );
            return r;
        }
        // 正規化数。値 = (1<<M | frac) * 2^(e - bias - M)。
        let m = u128::from(frac | (1u64 << M)) << (63 - M);
        Self::from_parts(neg, e + (BIAS as u32 - bias_e as u32), m as u64)
    }

    /// 拡張精度メモリ形式（80 ビット。{符号1,指数15} + 仮数 64）
    /// への変換。レジスタ側は場の再バイアスで近似する（範囲外は
    /// 飽和。docs/guests/ia64.md）。
    #[must_use]
    pub fn to_ext80(self) -> (u16, u64) {
        let (neg, e, m) = self.decode();
        let se = if e == 0 {
            0
        } else if e == EXP_SPECIAL {
            0x7fff
        } else {
            (e as i64 - BIAS + 16383).clamp(0, 0x7ffe) as u16
        };
        (((neg as u16) << 15) | se, m)
    }

    /// 拡張精度メモリ形式から作る。各場をそのまま移すので
    /// pseudo-NaN・pseudo-denormal 等のエンコーディングも保存される。
    #[must_use]
    pub fn from_ext80(se: u16, sig: u64) -> Self {
        let neg = (se >> 15) & 1 != 0;
        let e15 = se & 0x7fff;
        let e17 = if e15 == 0 {
            0
        } else if e15 == 0x7fff {
            EXP_SPECIAL
        } else {
            e15 as u32 + (BIAS as u32 - 16383)
        };
        Self::from_parts(neg, e17, sig)
    }

    /// frcpa（1/f3 の逆数近似）の値と条件述語。
    /// 近似の規則に従い、計算不能な組み合わせでは述語 0 を返す。
    /// 逆数自体は正しい丸めで求める（建築の近似誤差の上限を大きく
    /// 下回る。テーブル方式との差は docs/guests/ia64.md）。
    #[must_use]
    pub fn frcpa(self, other: Self) -> (bool, Self) {
        let (a, b) = (self, other);
        if a.is_natval() || b.is_natval() {
            return (false, Self::NATVAL);
        }
        if a.is_nan() || b.is_nan() {
            return (false, Self::QNAN);
        }
        let neg = a.decode().0 ^ b.decode().0;
        match (a.is_inf(), b.is_inf(), a.is_zero(), b.is_zero()) {
            (true, true, _, _) => (false, Self::QNAN),
            (_, _, true, true) => (false, Self::QNAN),
            (_, _, _, true) => (true, Self::inf(neg)),
            (_, true, _, _) => (true, Self::zero_signed(neg)),
            (true, _, _, _) => (true, Self::inf(neg)),
            // 近似対象は f3 の逆数（1/f3）。f2 は述語と特別値
            // 決定だけに使う（SDM FRCPA 表）。正確な商は呼出側が
            // Newton 反復で組み立てる。
            _ => (true, Self::ONE.div(b, Rm::Rne, FMT_REG).0),
        }
    }

    /// frsqrta（1/sqrt(f3) の近似）の値と条件述語。
    /// 平方根・逆数は F64 域で求める（同じく近似誤差の上限以下。
    /// docs/guests/ia64.md）。
    #[must_use]
    pub fn frsqrta(self) -> (bool, Self) {
        let a = self;
        if a.is_natval() {
            return (false, Self::NATVAL);
        }
        if a.is_nan() {
            return (false, Self::QNAN);
        }
        if a.is_inf() {
            return if a.negative() {
                (false, Self::QNAN)
            } else {
                (true, Self::ZERO)
            };
        }
        if a.is_zero() {
            return (true, Self::inf(a.negative()));
        }
        if a.negative() {
            return (false, Self::QNAN);
        }
        // 値 = s * 2^U（s ∈ [1,2)）を s' * 2^2k（s' ∈ [1,4)）に
        // 直し、rsqrt = (1/sqrt(s')) * 2^-k とする。
        let (_, m, e2) = a.unpack();
        let bl = bitlen(m);
        let u = e2 + bl - 1;
        let k = u.div_euclid(2);
        let par = u.rem_euclid(2);
        let (d, _) = F64::from_u64(m as u64, Rm::Rne);
        // s' = m * 2^(par - (bl-1)) を F64 で作る（2 の冪スケールは厳密）。
        let p = F64::from_bits(((1023 + par - (bl - 1)) as u64) << 52);
        let (sp, _) = d.mul_rm(p, Rm::Rne);
        let (rt, _) = sp.sqrt_rm(Rm::Rne);
        let one = F64::from_bits(0x3ff0_0000_0000_0000);
        let (t, _) = one.div_rm(rt, Rm::Rne);
        // t ∈ (0.5, 1] を展開して 2^-k だけ下げる。
        let tb = t.bits();
        let te = ((tb >> 52) & 0x7ff) as i64;
        let mt = u128::from((tb & ((1u64 << 52) - 1)) | (1u64 << 52));
        let lt = te - 1023 - 52 - k;
        (
            true,
            Self::pack(false, mt, lt, 0, Rm::Rne, FMT_REG, false).0,
        )
    }
}
