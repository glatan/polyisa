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
//! 丸めは呼び出し側の `Rm` に従う。VAX の演算の丸めは「0.5 ulp を
//! 足して切り捨てる」規則 —— ガード桁が立っていれば絶対値を丸め
//! 上げる `Rm::Rmm` と一致する（sticky は効かない）。
// Ref: VAX Architecture Reference Manual の F/D/G/H 形式（事実のみ）。

use crate::{FP_DZ, FP_NV, FP_OF, FP_UF, Rm};
use core::cmp::Ordering;

/// 整数オーバーフロー（整数変換・EMOD の整数部が結果の 32 ビット幅に
/// 収まらない。dst には真の結果の下位ビットが置かれる）。
/// `FP_*` の RISC-V 五ビットの外側にある DEC 系だけの拡張ビット。
pub const FP_IOV: u8 = 0x20;

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

/// 丸め済み・未パックの中間形（符号, M+1 ビット係数, 未クランプの
/// バイアス指数）。sig==0 は真の零。DEC の演算の最終段で、形式
/// 固有の格納規則がこの生値から値を組み立てる —— VAX は飽和
/// （`vax_pack`）、FP11 は指数を 400₈ ずらした真の結果
/// （`fp11_pack`）。
struct Rp {
    neg: bool,
    sig: u128,
    eu: i64,
}

/// (係数, 指数) を形式に収める前段。sig はちょうど M+1 ビットで
/// 最上位が 1（0 も可）。フラグは範囲外の指数で立つ。
fn pack_e<const E: u32, const M: u32>(neg: bool, sig: u128, e2: i64) -> (Rp, u8) {
    if sig == 0 {
        return (
            Rp {
                neg: false,
                sig: 0,
                eu: 0,
            },
            0,
        );
    }
    // sig は M+1 ビット → 指数部 = e2 + BIAS + M + 1。
    let eu = e2 + VaxF::<E, M>::BIAS + i64::from(M) + 1;
    let fl = if eu < 1 {
        FP_UF
    } else if eu > VaxF::<E, M>::EMAX as i64 {
        FP_OF
    } else {
        0
    };
    (Rp { neg, sig, eu }, fl)
}

/// 生値の VAX 式の格納形。アンダーフローは真の零、オーバーフローは
/// 「結果は不定」に対する決定的な選択として符号つき最大有限値。
fn vax_pack<const E: u32, const M: u32>(rp: Rp) -> VaxF<E, M> {
    if rp.sig == 0 || rp.eu < 1 {
        return VaxF::<E, M>::zero();
    }
    if rp.eu > VaxF::<E, M>::EMAX as i64 {
        return VaxF::<E, M> {
            bits: ((rp.neg as u128) << (E + M))
                | ((VaxF::<E, M>::EMAX as u128) << M)
                | VaxF::<E, M>::fmask(),
        };
    }
    VaxF::<E, M>::from_bits(
        ((rp.neg as u128) << (E + M))
            | (((rp.eu as u128) & VaxF::<E, M>::EMAX as u128) << M)
            | (rp.sig & VaxF::<E, M>::fmask()),
    )
}

/// 生値の FP11 式の格納形。オーバーフローは指数を -400₈、
/// アンダーフローは +400₈ ずらした真の結果（仮数と符号は正しく
/// 格納される。fl が立たない通常値は eu のまま）。係数が 0 は
/// 真の零。ずらした指数はフィールド幅で折り返す。
// Gap: GAP-0083（折り返し端境は実機との照合なしの決定的選択）
fn fp11_pack<const E: u32, const M: u32>(rp: Rp, fl: u8) -> VaxF<E, M> {
    if rp.sig == 0 {
        return VaxF::<E, M>::zero();
    }
    let d = if fl & FP_OF != 0 {
        -0o400i64
    } else if fl & FP_UF != 0 {
        0o400
    } else {
        0
    };
    let eu = (rp.eu + d) & 0xff;
    VaxF::<E, M>::from_bits(
        ((rp.neg as u128) << (E + M))
            | (((eu as u128) & VaxF::<E, M>::EMAX as u128) << M)
            | (rp.sig & VaxF::<E, M>::fmask()),
    )
}

/// (生値, フラグ) の FP11 式の結果。
fn fp11<const E: u32, const M: u32>(raw: (Rp, u8)) -> (VaxF<E, M>, u8) {
    (fp11_pack::<E, M>(raw.0, raw.1), raw.1)
}

/// u128 同士の積の (上位, 下位)。H 形式の係数乗算（226 ビット）や
/// EMOD の拡張係数（241 ビット）が u128 に収まらないため。
fn mulhilo(a: u128, b: u128) -> (u128, u128) {
    const LOM: u128 = 0xffff_ffff_ffff_ffff;
    let (a0, a1) = (a & LOM, a >> 64);
    let (b0, b1) = (b & LOM, b >> 64);
    let t = a0 * b0;
    let s1 = a0 * b1 + (t >> 64);
    let s2 = a1 * b0 + (s1 & LOM);
    let lo = (t & LOM) | (s2 << 64);
    let hi = a1 * b1 + (s1 >> 64) + (s2 >> 64);
    (hi, lo)
}

/// 256 ビット値 (hi:lo) のビット長。
fn bitlen256(hi: u128, lo: u128) -> i64 {
    if hi == 0 {
        bitlen(lo)
    } else {
        128 + bitlen(hi)
    }
}

/// 256 ビット値 (hi:lo) から下位 `s` ビットを落として u128 に畳む。
/// 落ちた桁は sticky に畳む（結果が u128 に収まることは呼び出し側の
/// 責務 — 使いどころは常に最上位側の切り出し）。
fn shr256(hi: u128, lo: u128, s: u32) -> (u128, bool) {
    if s == 0 {
        return (lo, false);
    }
    if s >= 128 {
        let rest = s - 128;
        let sticky =
            lo != 0 || (rest < 128 && (hi & ((1u128 << rest.min(127)) - 1)) != 0) || rest >= 128;
        let q = if rest >= 128 { 0 } else { hi >> rest };
        return (q, sticky);
    }
    let sticky = (lo & ((1u128 << s) - 1)) != 0;
    ((hi << (128 - s)) | (lo >> s), sticky)
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
        let (rp, fl) = pack_e::<E, M>(neg, sig, e2);
        (vax_pack::<E, M>(rp), fl)
    }

    /// 正のゼロ。
    #[must_use]
    pub const fn zero() -> Self {
        Self { bits: 0 }
    }

    /// 加算。
    #[must_use]
    pub fn add(self, other: Self, rm: Rm) -> (Self, u8) {
        let (rp, fl) = add_sub(self, other, false, rm);
        (vax_pack::<E, M>(rp), fl)
    }

    /// 減算。
    #[must_use]
    pub fn sub(self, other: Self, rm: Rm) -> (Self, u8) {
        let (rp, fl) = add_sub(self, other, true, rm);
        (vax_pack::<E, M>(rp), fl)
    }

    /// FP11 規則の加算。オーバーフロー/アンダーフロー時の戻り値は
    /// 仮数と符号を正しく持ち指数フィールドが真値から 400₈
    /// （オーバーフローは -400₈、アンダーフローは +400₈）ずれた
    /// 真の結果 —— VAX 式の飽和値/零ではない。係数が 0 は真の零。
    /// PDP-11 FP11 用（ARCH83 Chapter 6 の例外時格納規則）。
    #[must_use]
    pub fn add_fp11(self, other: Self, rm: Rm) -> (Self, u8) {
        fp11::<E, M>(add_sub(self, other, false, rm))
    }

    /// FP11 規則の減算。`add_fp11` と同じ格納規則。
    #[must_use]
    pub fn sub_fp11(self, other: Self, rm: Rm) -> (Self, u8) {
        fp11::<E, M>(add_sub(self, other, true, rm))
    }

    /// 乗算。
    #[must_use]
    pub fn mul(self, other: Self, rm: Rm) -> (Self, u8) {
        let (rp, fl) = mul_e::<E, M>(self, other, rm);
        (vax_pack::<E, M>(rp), fl)
    }

    /// FP11 規則の乗算。`add_fp11` と同じ格納規則。
    #[must_use]
    pub fn mul_fp11(self, other: Self, rm: Rm) -> (Self, u8) {
        fp11::<E, M>(mul_e::<E, M>(self, other, rm))
    }

    /// 除算。
    #[must_use]
    pub fn div(self, other: Self, rm: Rm) -> (Self, u8) {
        let (rp, fl) = div_e::<E, M>(self, other, rm);
        (vax_pack::<E, M>(rp), fl)
    }

    /// FP11 規則の除算。`add_fp11` と同じ格納規則。除数が零なら
    /// FP_DZ（FP11 では FEC=4 の中止例外で AC は変化しない）。
    #[must_use]
    pub fn div_fp11(self, other: Self, rm: Rm) -> (Self, u8) {
        fp11::<E, M>(div_e::<E, M>(self, other, rm))
    }

    /// FP11 の MOD（乗算 + 整数部/小数部分離、ARCH83 Chapter 6）。
    /// 返す: (整数部 N, 小数部 g, フラグ)。値は FP11 の格納形 —
    /// FP_OF 時は N だけが有効（指数 -400₈）で g は真の零、
    /// FP_UF 時は N が真の零で g が指数 +400₈ の形。呼び出し側が
    // Gap: GAP-0083（大指数の整数部・小数部下桁の端境は正本
    // マイクロコードとの照合なし）
    /// 割込み可否に応じて ACv1/AC への格納を裁く。
    /// N は係数を L=M+1 ビットに切り詰め（2**L 以上の積では低位が
    /// 失われ、そのとき AC 側は真の零）、g は rm で丸める。
    /// 積の係数生成は形式の全幅（1+E+M ビット）への切り詰め —
    /// emod と同じ近似で、実機が生成する 48/59-64 ビット積とは
    /// 下位桁が違いうる。
    #[must_use]
    pub fn modf_fp11(self, muld: Self, rm: Rm) -> (Self, Self, u8) {
        if self.is_reserved() || muld.is_reserved() {
            return (Self::zero(), Self::zero(), FP_NV);
        }
        if self.is_zero() || muld.is_zero() {
            return (Self::zero(), Self::zero(), 0);
        }
        let neg = self.decode().0 ^ muld.decode().0;
        let (_, m1, e1) = self.unpack();
        let (_, m2, e2) = muld.unpack();
        let (ph, pl) = mulhilo(m1, m2);
        // 正規化前の積を形式の全幅（1+E+M）ビットへ切り詰める
        // （emod と同じ規則）。値 = q * 2^e。
        let drop = (bitlen256(ph, pl) - i64::from(Self::WIDTH)).max(0) as u32;
        let (q, _) = shr256(ph, pl, drop);
        let e = e1 + e2 + i64::from(drop);
        // 整数部のビット長・L ビットに正規化した係数・bit0 の重みと
        // 小数部の (係数, bit0 の重み)。値 = q * 2^e。整数部が係数の
        // 有効幅 L を超えるとき（|PROD| >= 2**L）小数部は捨てられる。
        let l = i64::from(M) + 1;
        let (nsig, ne, bl_i, fsig, fe) = if e >= 0 {
            // 全部整数部。int = q << e — 上位 L ビットが必要なときは
            // 桁落ちしないので q の上位 L ビット（L 未満なら左寄せ）。
            let bl = bitlen(q) + e;
            if bl > l {
                let bq = bitlen(q);
                let ns = if bq >= l {
                    q >> (bq - l)
                } else {
                    q << (l - bq)
                };
                (ns, bl - l, bl, 0u128, 0i64)
            } else {
                // int = q << e は L ビット以内に収まる。
                let int = q << e as u32;
                (int << (l - bl), -(l - bl), bl, 0, 0)
            }
        } else {
            let r = (-e) as u32;
            if r >= 128 {
                (0, 0, 0, q, e)
            } else {
                let int = q >> r;
                let bl = bitlen(int);
                let fs = if bl > l { 0 } else { q & ((1u128 << r) - 1) };
                if bl == 0 {
                    (0, 0, 0, fs, e)
                } else if bl > l {
                    (int >> (bl - l), bl - l, bl, fs, e)
                } else {
                    (int << (l - bl), -(l - bl), bl, fs, e)
                }
            }
        };
        // N は係数を L ビットに切詰めて格納（規則は chop なので
        // pack_e でよい）。
        let n_rp = if bl_i == 0 {
            Rp {
                neg: false,
                sig: 0,
                eu: 0,
            }
        } else {
            pack_e::<E, M>(neg, nsig, ne).0
        };
        // 小数部は M+2 ビット＋sticky に正規化して丸める。
        let g_rp = if fsig == 0 {
            (
                Rp {
                    neg: false,
                    sig: 0,
                    eu: 0,
                },
                0,
            )
        } else {
            let want = l + 1;
            let bl_g = bitlen(fsig);
            let (gq, ge, gs) = if bl_g > want {
                let d = (bl_g - want) as u32;
                (fsig >> d, fe + i64::from(d), fsig & ((1u128 << d) - 1) != 0)
            } else {
                (fsig << (want - bl_g) as u32, fe - (want - bl_g), false)
            };
            round_pack_e::<E, M>(neg, gq, ge, gs, rm)
        };
        let n_fl = if n_rp.sig != 0 && n_rp.eu > Self::EMAX as i64 {
            FP_OF
        } else {
            0
        };
        if n_fl & FP_OF != 0 {
            // PROD 自体のオーバーフローもここに合流する（N の指数が
            // 表現を超えるのは |PROD| >= 2**emax+1 のとき）。
            return (fp11_pack::<E, M>(n_rp, FP_OF), Self::zero(), FP_OF);
        }
        if g_rp.1 & FP_UF != 0 {
            return (Self::zero(), fp11_pack::<E, M>(g_rp.0, FP_UF), FP_UF);
        }
        (
            fp11_pack::<E, M>(n_rp, 0),
            fp11_pack::<E, M>(g_rp.0, g_rp.1),
            0,
        )
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

    /// 別の形式に変換する。仮数が狭まるとき（D→G など）の丸めは
    /// `rm` に従う（VAX の cvt 命令は `Rm::Rmm`、既存の DEC 系経路は
    /// `widen` が RNE を使う）。予約オペランドはそのまま写して
    /// FP_NV を返す。
    #[must_use]
    pub fn widen_rm<const E2: u32, const M2: u32>(self, rm: Rm) -> (VaxF<E2, M2>, u8) {
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
        // 係数を M2+1 ビットに揃える。落ちる桁は rm で丸める。
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
            let up = match rm {
                Rm::Rtz => false,
                Rm::Rup => !neg && (guard != 0 || sticky),
                Rm::Rdn => neg && (guard != 0 || sticky),
                Rm::Rmm => guard != 0,
                Rm::Rne => guard != 0 && (sticky || (sig & 1) == 1),
            };
            if up {
                sig += 1;
                if bitlen(sig) > i64::from(M2) + 1 {
                    sig >>= 1;
                    eb += 1;
                }
            }
        }
        VaxF::<E2, M2>::pack(neg, sig, eb)
    }

    /// 別の形式に変換する。仮数が狭まるときは RNE で丸める
    /// （VAX の cvt は `widen_rm` に `Rm::Rmm` を渡す）。
    #[must_use]
    pub fn widen<const E2: u32, const M2: u32>(self) -> (VaxF<E2, M2>, u8) {
        self.widen_rm(Rm::Rne)
    }

    /// 負の有限値か（条件コード N。指数 0 は真の零・dirty zero で
    /// 負ではない。結果に予約オペランドは生成されないので、
    /// 読み出し側が予約オペランドを弾いた後に使う前提）。
    #[must_use]
    pub fn is_neg(self) -> bool {
        let (neg, exp, _) = self.decode();
        neg && exp != 0
    }

    /// 符号を反転する（mneg）。指数 0（真の零・dirty zero）は真の
    /// 零を返す — 予約オペランドは結果に生成されない。
    #[must_use]
    pub fn neg(self) -> Self {
        if self.decode().1 == 0 {
            Self::zero()
        } else {
            Self::from_bits(self.bits ^ (1u128 << (E + M)))
        }
    }

    /// dirty zero（指数 0・符号 0・仮数非 0）を真の零へ畳む。
    /// その他の値はそのまま。予約オペランドは呼び出し側が先に弾く。
    #[must_use]
    pub fn clean_zero(self) -> Self {
        if self.is_zero() { Self::zero() } else { self }
    }

    /// 整数（i32）からの変換。丸めは `rm`（VAX の cvt は Rmm）。
    /// オーバーフロー・アンダーフローは起きない。
    #[must_use]
    pub fn from_i32(v: i32, rm: Rm) -> Self {
        if v == 0 {
            return Self::zero();
        }
        let neg = v < 0;
        let mag = u128::from(v.unsigned_abs());
        // M+2 ビット（係数＋ガード）へ畳んで round_pack へ。
        let want = i64::from(M) + 2;
        let bl = bitlen(mag);
        let (q, e, sticky) = if bl > want {
            let s = (bl - want) as u32;
            (mag >> s, i64::from(s), (mag & ((1u128 << s) - 1)) != 0)
        } else {
            let s = (want - bl) as u32;
            (mag << s, -i64::from(s), false)
        };
        round_pack::<E, M>(neg, q, e, sticky, rm).0
    }

    /// 整数（i32）への変換。`round` なら VAX の丸め（0.5 ulp を足して
    /// 切り捨て — 絶対値で最も近い方へ）で、なければ 0 方向へ
    /// 切り詰める（符号・絶対値表現の DEC 形式は丸めも符号・絶対値）。
    /// 返すのは (結果の下位 32 ビットの二の補数, フラグ)。フラグは
    /// FP_NV（予約オペランド）と FP_IOV（32 ビットに収まらない —
    /// その場合も下位ビットは真の値のまま）を持ち得る。
    #[must_use]
    pub fn to_i32(self, round: bool) -> (i32, u8) {
        if self.is_reserved() {
            return (0, FP_NV);
        }
        if self.is_zero() {
            return (0, 0);
        }
        let (neg, sig, e) = self.unpack();
        // 絶対値の整数部（下位 32 ビットと「収まるか」の判定だけ
        // 要るので大きい側は飽和する）。
        let (low, iov) = if e >= 0 {
            let mbits = bitlen(sig) + e;
            let low = if e >= 32 {
                0
            } else {
                (sig as u32) << (e as u32)
            };
            (
                low,
                mbits > 32 || (mbits == 32 && !(neg && low == 0x8000_0000)),
            )
        } else {
            let r = (-e) as u32;
            let mut mag = if r >= 128 { 0 } else { sig >> r };
            if round && (1..=128).contains(&r) && (sig >> (r - 1)) & 1 == 1 {
                mag += 1;
            }
            let lim = if neg {
                0x8000_0000u128
            } else {
                0x7fff_ffffu128
            };
            (mag as u32, mag > lim)
        };
        let v = if neg { low.wrapping_neg() } else { low } as i32;
        (v, if iov { FP_IOV } else { 0 })
    }

    /// EMOD。`mulrx` は係数拡張の桁（self 側の係数の下に連結する
    /// ext ビット — EMODF/D は mulrx.rb の 8 ビット、EMODG/H は
    /// mulrx.rw の上位 11/15 ビットを呼び出し側が右詰めで渡す）。
    /// 拡張係数と muld の積を、正規化前の仮数フィールド幅
    /// （形式の全幅 32/64/128 ビット）へ切り詰めてから整数部と
    /// 小数部へ分ける。小数部は VAX 丸めの形式値。
    /// 返すのは (整数部の下位 32 ビットの二の補数, 小数部, フラグ)。
    /// フラグは FP_NV・FP_UF（小数部の下桁）・FP_IOV。
    // Ref: VAX Architecture Reference Manual の emod 命令の節.
    #[must_use]
    pub fn emod(self, mulrx: u32, muld: Self) -> (i32, Self, u8) {
        if self.is_reserved() || muld.is_reserved() {
            return (0, Self::zero(), FP_NV);
        }
        if self.is_zero() || muld.is_zero() {
            return (0, Self::zero(), 0);
        }
        let neg = self.decode().0 ^ muld.decode().0;
        let (_, m1, e1) = self.unpack();
        let (_, m2, e2) = muld.unpack();
        // 拡張桁は EMODF/D が 8（指数 8 の下位に連結）、EMODG が
        // 11、EMODH が 15 — どれも E に一致する。
        let ext = E;
        let sig = (m1 << ext) | u128::from(mulrx & ((1u32 << ext) - 1));
        let (ph, pl) = mulhilo(sig, m2);
        // 正規化前の積を形式の全幅（1+E+M）ビットの仮数フィールドへ
        // 切り詰める（常にフィールド幅を超えるので必ず右へ寄せる）。
        let w2 = i64::from(Self::WIDTH);
        let drop = (bitlen256(ph, pl) - w2).max(0) as u32;
        let (q, _) = shr256(ph, pl, drop);
        let e = e1 - i64::from(ext) + e2 + i64::from(drop);
        // 値 = q * 2^e。q は最大 w2 ビット（先頭が立たないこともある —
        // 正規化前の積のフィールドという建前）。
        let mut flags = 0u8;
        let (low, iov, fsig, fe) = if e >= 0 {
            // 全部整数部。
            let mbits = bitlen(q) + e;
            let low = if e >= 32 { 0 } else { (q as u32) << (e as u32) };
            (
                low,
                mbits > 32 || (mbits == 32 && !(neg && low == 0x8000_0000)),
                0u128,
                0i64,
            )
        } else {
            let r = (-e) as u32;
            if r >= Self::WIDTH {
                // 全部小数部。
                (0, false, q, e)
            } else {
                let imag = q >> r;
                let mbits = bitlen(imag);
                let low = imag as u32;
                (
                    low,
                    mbits > 32 || (mbits == 32 && !(neg && low == 0x8000_0000)),
                    q & ((1u128 << r) - 1),
                    e,
                )
            }
        };
        if iov {
            flags |= FP_IOV;
        }
        // 小数部を正規化・丸め（VAX 規則）。
        let (fract, ff) = if fsig == 0 {
            (Self::zero(), 0)
        } else {
            let want = i64::from(M) + 2;
            let bl = bitlen(fsig);
            let (mut q2, mut e2) = (fsig, fe);
            let mut sticky = false;
            if bl > want {
                let s = (bl - want) as u32;
                sticky = (fsig & ((1u128 << s) - 1)) != 0;
                q2 = fsig >> s;
                e2 += i64::from(s);
            } else if bl < want {
                q2 = fsig << (want - bl) as u32;
                e2 -= want - bl;
            }
            round_pack::<E, M>(neg, q2, e2, sticky, Rm::Rmm)
        };
        (
            if neg { low.wrapping_neg() } else { low } as i32,
            fract,
            flags | ff,
        )
    }

    /// POLY の 1 反復: `arg * self + coeff` を正本の中間精度で
    /// 計算する。作業仮数は上位が立つ幅いっぱいのフィールドで、
    /// 積と和のそれぞれについて上位 `E + M` ビット（作業フィールド
    /// の先頭の「分数部」の先頭側）を残して下位を切り捨てる —
    /// 切り詰めのあと正規化・丸め（VAX 規則）して形式値に畳む。
    /// フラグは FP_NV・FP_OF・FP_UF。
    // Ref: VAX Architecture Reference Manual の poly 命令の節.
    #[must_use]
    pub fn poly_iter(self, arg: Self, coeff: Self) -> (Self, u8) {
        if self.is_reserved() || arg.is_reserved() || coeff.is_reserved() {
            return (Self::zero(), FP_NV);
        }
        // 作業仮数フィールド（FW ビット、正規化入力は最上位が立つ）。
        // 残すのはフィールド上位 W = E+M ビット。
        const FW: i64 = 128;
        let w = i64::from(E + M);
        let mask: u128 = (1u128 << (FW - w)) - 1;
        // （符号, 作業仮数, bit0 の重み）へほどく。
        let unpack_fw = |v: Self| -> (bool, u128, i64) {
            let (neg, sig, e) = v.unpack();
            let sh = FW - bitlen(sig);
            (neg, sig << sh as u32, e - sh)
        };
        // 積: 非正規化のまま作業フィールドの上位を残す。
        let (s_p, f_p, e_p) = if self.is_zero() || arg.is_zero() {
            (false, 0u128, 0i64)
        } else {
            let (na, fa, ea) = unpack_fw(self);
            let (nb, fb, eb) = unpack_fw(arg);
            // 256 ビット積の上位 FW ビットが作業仮数。
            let (ph, _pl) = mulhilo(fa, fb);
            (na ^ nb, ph & !mask, ea + eb + FW)
        };
        let (s_c, f_c, e_c) = if coeff.is_zero() {
            (false, 0u128, 0i64)
        } else {
            unpack_fw(coeff)
        };
        if f_p == 0 && f_c == 0 {
            return (Self::zero(), 0);
        }
        // 和: 指数の大きい側へ揃えて符号・絶対値で畳む。作業
        // フィールドの下へはみ出た桁は借りの規則だけ見る
        // （add_sub と同じ）。
        let (x, mut y, sx, sy, ex) = if e_p >= e_c {
            (f_p, f_c, s_p, s_c, e_p)
        } else {
            (f_c, f_p, s_c, s_p, e_c)
        };
        let diff = (e_p - e_c).unsigned_abs();
        let mut dropped_nz = false;
        if diff >= FW as u64 {
            dropped_nz = y != 0;
            y = 0;
        } else if diff > 0 {
            let r = diff as u32;
            dropped_nz = (y & ((1u128 << r) - 1)) != 0;
            y >>= r;
        }
        let (mut q, neg, carry) = if sx == sy {
            let s = x.wrapping_add(y);
            (s, sx, s < x)
        } else if x > y || (x == y && !dropped_nz) {
            (x - y, sx, false)
        } else {
            (y - x, sy, false)
        };
        if dropped_nz && sx != sy && neg != sy {
            q = q.wrapping_sub(1);
        }
        let mut e = ex;
        if carry {
            // 和がフィールドをはみ出す — 1 桁ずらして MSB を戻す。
            q = (q >> 1) | (1u128 << (FW - 1));
            e += 1;
        }
        // 非正規化の和をフィールド上位 W ビットへ切り詰める。
        q &= !mask;
        if q == 0 {
            return (Self::zero(), 0);
        }
        round_pack::<E, M>(neg, q, e, false, Rm::Rmm)
    }
}

/// M+2 ビットの係数（最下位はガード）と sticky から最終結果を作る。
fn round_pack<const E: u32, const M: u32>(
    neg: bool,
    q: u128,
    e: i64,
    sticky: bool,
    rm: Rm,
) -> (VaxF<E, M>, u8) {
    let (rp, fl) = round_pack_e::<E, M>(neg, q, e, sticky, rm);
    (vax_pack::<E, M>(rp), fl)
}

/// `round_pack` の生値版 — VAX 式の格納前の段階で止める。
fn round_pack_e<const E: u32, const M: u32>(
    neg: bool,
    mut q: u128,
    mut e: i64,
    mut sticky: bool,
    rm: Rm,
) -> (Rp, u8) {
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
        return (
            Rp {
                neg: false,
                sig: 0,
                eu: 0,
            },
            0,
        );
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
    pack_e::<E, M>(neg, q, e)
}

/// 有限値から生値へ（sig==0 は真の零）。
fn rp_of<const E: u32, const M: u32>(v: VaxF<E, M>) -> Rp {
    let (neg, sig, e2) = v.unpack();
    Rp {
        neg,
        sig,
        eu: e2 + VaxF::<E, M>::BIAS + i64::from(M) + 1,
    }
}

/// 乗算の中核 — 生値で返す。
fn mul_e<const E: u32, const M: u32>(a: VaxF<E, M>, b: VaxF<E, M>, rm: Rm) -> (Rp, u8) {
    let neg = a.decode().0 ^ b.decode().0;
    if a.is_reserved() || b.is_reserved() {
        return (
            Rp {
                neg: false,
                sig: 0,
                eu: 0,
            },
            FP_NV,
        );
    }
    if a.is_zero() || b.is_zero() {
        return (
            Rp {
                neg: false,
                sig: 0,
                eu: 0,
            },
            0,
        );
    }
    let (_, m1, e1) = a.unpack();
    let (_, m2, e2) = b.unpack();
    // 積は最大 2M+2 ビット（H は 226 ビットで u128 に収まらない
    // ので 256 ビットに受ける）。M+2 ビット＋sticky に畳む。
    let (ph, pl) = mulhilo(m1, m2);
    let want = i64::from(M) + 2;
    let drop = (bitlen256(ph, pl) - want).max(0) as u32;
    let (q, sticky) = shr256(ph, pl, drop);
    round_pack_e::<E, M>(neg, q, e1 + e2 + i64::from(drop), sticky, rm)
}

/// 除算の中核 — 生値で返す。
fn div_e<const E: u32, const M: u32>(a: VaxF<E, M>, b: VaxF<E, M>, rm: Rm) -> (Rp, u8) {
    let neg = a.decode().0 ^ b.decode().0;
    if a.is_reserved() || b.is_reserved() {
        return (
            Rp {
                neg: false,
                sig: 0,
                eu: 0,
            },
            FP_NV,
        );
    }
    if b.is_zero() {
        return (
            Rp {
                neg: false,
                sig: 0,
                eu: 0,
            },
            FP_DZ,
        );
    }
    if a.is_zero() {
        return (
            Rp {
                neg: false,
                sig: 0,
                eu: 0,
            },
            0,
        );
    }
    let (_, m1, e1) = a.unpack();
    let (_, m2, e2) = b.unpack();
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
    round_pack_e::<E, M>(neg, q, e, r != 0, rm)
}

/// 加減算の中核。
fn add_sub<const E: u32, const M: u32>(
    a: VaxF<E, M>,
    b: VaxF<E, M>,
    flip: bool,
    rm: Rm,
) -> (Rp, u8) {
    let s1 = a.decode().0;
    let mut s2 = b.decode().0;
    if flip {
        s2 = !s2;
    }
    if a.is_reserved() || b.is_reserved() {
        return (
            Rp {
                neg: false,
                sig: 0,
                eu: 0,
            },
            FP_NV,
        );
    }
    let z1 = a.is_zero();
    let z2 = b.is_zero();
    if z1 && z2 {
        return (
            Rp {
                neg: false,
                sig: 0,
                eu: 0,
            },
            0,
        );
    }
    if z1 {
        // b の符号を flip に応じて変えた零ではない有限値を返す。
        let mut r = b;
        if flip {
            r.bits ^= 1u128 << (E + M);
        }
        return (rp_of::<E, M>(r), 0);
    }
    if z2 {
        return (rp_of::<E, M>(a), 0);
    }
    let (_, m1, e1) = a.unpack();
    let (_, m2, e2) = b.unpack();
    let (mut x, mut y, sx, sy, mut ex) = if e1 >= e2 {
        (m1, m2, s1, s2, e1)
    } else {
        (m2, m1, s2, s1, e2)
    };
    // ガード桁方式の揃え: 指数の小さい側を diff-1 ビットずらして
    // 最上位の「ガード候補」を係数の bit0 に残し、大きい側は
    // 1 ビット上げてスケールを ex-1 に合わせる。ずらして落ちた
    // 下位 diff-1 ビットが sticky — 0.5 ulp 規則（Rmm）は正規化
    // 後のガード位置だけを見るので、ここで 1 桁残さないと加算で
    // 半 ulp が常に捨てられてしまう。
    let diff = (e1 - e2).unsigned_abs().min(127);
    let mut dropped: u128 = 0;
    let mut r = 0u32; // sticky へ送った桁数
    if diff > 0 {
        r = (diff - 1).min(126) as u32;
        dropped = y & ((1u128 << r) - 1);
        y >>= r;
        x <<= 1;
        ex -= 1;
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
            return (
                Rp {
                    neg: false,
                    sig: 0,
                    eu: 0,
                },
                0,
            );
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
        return round_pack_e::<E, M>(neg, q2, ex - i64::from(r), false, rm);
    }
    // q の LSB の下に続く残余（tail は r 桁）。減算で借りを
    // 起こした側（x'-y' が係数上 0 より大きく残った側）は
    // 補数 2^r - dropped になる。加算・被減数側は dropped そのまま。
    let tail = if sx != sy && neg == sx && dropped_nz {
        (1u128 << r) - dropped
    } else {
        dropped
    };
    // 正規化が左に寄せるぶんだけ tail の上位桁を係数へ取り込む
    // （残りが sticky）。ガード位置が常に真の桁から来るように
    // するため — 全部を sticky に畳むと Rmm の半 ulp 判定が
    // キャンセレーションで誤る。
    let want = i64::from(M) + 2;
    if bitlen(q) < want && r > 0 {
        let take = ((want - bitlen(q)) as u32).min(r);
        q = (q << take) | (tail >> (r - take));
        ex -= i64::from(take);
        r -= take;
    }
    let sticky = (tail & ((1u128 << r) - 1)) != 0;
    round_pack_e::<E, M>(neg, q, ex, sticky, rm)
}
