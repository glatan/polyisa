// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 十進浮動小数点（IEEE 754 の decimal32/64/128）。
//!
//! 値は符号・種別・係数・指数の組 `(neg, kind, coef, exp)` で、
//! 有限値は `±coef * 10^exp` を表す。係数は最上位桁から並ぶ
//! `Vec<u8>`（各要素 0〜9）で、先頭の 0 は正規化して持たない。
//! 文脈 `Ctx` は precision・指数範囲・丸め・clamp を運び、演算は
//! `finish` で文脈を適用する。例外は条件フラグ `cond` の和で返す。
//! エンコードは DPD 組合せフィールドの規則に従う。
// Ref: SPEC-DECIMAL-ARITH (演算・条件・DPD), SPEC-IEEE754 (2008).

use crate::{PackedDec, dpd};

/// 例外条件フラグのビット。GDA/decTest の並び。
pub mod cond {
    /// 指数を範囲に収めた（パディング・0 化を含む）。
    pub const CLAMPED: u32 = 1;
    /// 入力の文字列が構文として受理できない。
    pub const CONV_SYNTAX: u32 = 2;
    /// 零除算。
    pub const DIV_ZERO: u32 = 4;
    /// 整数除算・剰余の商が precision を超える。
    pub const DIV_IMPOSSIBLE: u32 = 8;
    /// 0/0。
    pub const DIV_UNDEFINED: u32 = 16;
    /// 結果が厳密でない。
    pub const INEXACT: u32 = 32;
    /// 入力の桁が収まらない（extended=0 の環境）。
    pub const INSUFF_STORAGE: u32 = 64;
    /// 不正な演算。
    pub const INVALID: u32 = 128;
    /// 入力で失われた桁。
    pub const LOST_DIGITS: u32 = 256;
    /// オーバーフロー。
    pub const OVERFLOW: u32 = 512;
    /// 桁が捨てられた（0 の桁でも立つ）。
    pub const ROUNDED: u32 = 1024;
    /// 結果がサブノーマル。
    pub const SUBNORMAL: u32 = 2048;
    /// サブノーマルかつ非厳密。
    pub const UNDERFLOW: u32 = 4096;
}

/// 丸めモード。decTest の rounding 指示名に対応する。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Rm {
    /// 0 方向（切り捨て）。
    Down,
    /// 絶対値大きい方向。
    Up,
    /// 最近接（同距離は上）。
    HalfUp,
    /// 最近接（同距離は下）。
    HalfDown,
    /// 最近接（同距離は偶数）。
    HalfEven,
    /// 正の無限大方向。
    Ceiling,
    /// 負の無限大方向。
    Floor,
    /// 残す最終桁が 0/5 のときだけ絶対値大きい方向。
    Up05,
}

/// 値の種別。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// 有限値。
    Finite,
    /// 無限大。
    Inf,
    /// quiet NaN。
    Qnan,
    /// signaling NaN。
    Snan,
}

/// 演算文脈。decTest の precision/maxExponent/minExponent/rounding/clamp
/// に対応する。指数範囲は `emin..=emax`（調整済み指数の閉区間）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ctx {
    /// 係数の最大桁数。
    pub prec: u32,
    /// 調整済み指数の最大。
    pub emax: i32,
    /// 調整済み指数の最小。
    pub emin: i32,
    /// 丸めモード。
    pub rm: Rm,
    /// IEEE 交換形式のクランプ規則を適用する。
    pub clamp: bool,
}

impl Ctx {
    /// decimal64 の既定文脈（テスト用の決定値）。
    pub const DEC64: Self = Self {
        prec: 16,
        emax: 384,
        emin: -383,
        rm: Rm::HalfEven,
        clamp: false,
    };
}

/// 十進浮動小数点の値。`neg` は符号、`kind` は種別、`coef` は
/// 最上位桁から並ぶ係数（各要素 0〜9、空なら [0] として扱う）、
/// `exp` は係数の小数点位置（値は `±coef * 10^exp`）。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Dec {
    /// 符号（NaN を含む全種別で意味を持つ）。
    pub neg: bool,
    /// 種別。
    pub kind: Kind,
    /// 係数の桁（最上位から）。有限値の桁数は `digits()` が返す。
    /// NaN では診断情報の桁として使う。
    pub coef: Vec<u8>,
    /// 指数。
    pub exp: i32,
}

// ---- 基本補助 ----

/// 係数の有効桁数（先頭の 0 を除いた桁数）。
fn dlen(d: &[u8]) -> usize {
    let n = d.iter().take_while(|&&x| x == 0).count();
    d.len() - n
}

/// 先頭の 0 を削る。全 0 なら 1 桁残す。
fn dtrim(d: &mut Vec<u8>) {
    let first = d.iter().position(|&x| x != 0).unwrap_or(d.len() - 1);
    d.drain(0..first);
}

/// 数字列を係数にする。全桁 0〜9 でなければ `None`。
fn parse_digits(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() {
        return Some(Vec::new());
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(s.bytes().map(|b| b - b'0').collect())
}

/// 絶対値の加算（桁列同士）。
fn abs_add(a: &[u8], b: &[u8]) -> Vec<u8> {
    let pa = PackedDec::from_digits(a, false).unwrap();
    let pb = PackedDec::from_digits(b, false).unwrap();
    pa.add(&pb).digits
}

/// 絶対値の減算（|a| >= |b| が前提）。
fn abs_sub(a: &[u8], b: &[u8]) -> Vec<u8> {
    let pa = PackedDec::from_digits(a, false).unwrap();
    let pb = PackedDec::from_digits(b, false).unwrap();
    pa.sub(&pb).digits
}

/// 桁列の絶対値比較（先頭の 0 は無視）。
fn abs_cmp(a: &[u8], b: &[u8]) -> Ordering {
    let pa = PackedDec::from_digits(a, false).unwrap();
    let pb = PackedDec::from_digits(b, false).unwrap();
    pa.cmp(&pb)
}

/// 係数を 10^s 倍する（末尾に 0 を足す）。
fn scale_coef(coef: &[u8], s: i64) -> Vec<u8> {
    let mut v = coef.to_vec();
    v.resize(coef.len() + usize::try_from(s).unwrap_or(0), 0);
    v
}

/// 位置 p の桁。係数は最上位から並ぶので、最下位桁の位置が s なら
/// 位置 p の桁は `coef[len - 1 - (p - s)]`。
fn digit_at(coef: &[u8], s: i64, p: i64) -> u8 {
    let n = dlen(coef) as i64;
    if p < s || p >= s + n {
        0
    } else {
        coef[coef.len() - 1 - (p - s) as usize]
    }
}

/// `a * 10^sa` と `b * 10^sb` の絶対値比較。桁を素材化せず
/// 位置のスキャンで比べる（指数差が巨大でも桁数ぶんで済む）。
fn cmp_sparse(a: &[u8], sa: i64, b: &[u8], sb: i64) -> Ordering {
    let na = dlen(a) as i64;
    let nb = dlen(b) as i64;
    // 0 は位置に関係なく最小。
    match (na == 0, nb == 0) {
        (true, true) => return Ordering::Equal,
        (true, false) => return Ordering::Less,
        (false, true) => return Ordering::Greater,
        _ => {}
    }
    let ta = sa + na;
    let tb = sb + nb;
    if ta != tb {
        return ta.cmp(&tb);
    }
    let mut p = ta - 1;
    let lo = sa.min(sb);
    while p >= lo {
        let da = digit_at(a, sa, p);
        let db = digit_at(b, sb, p);
        if da != db {
            return da.cmp(&db);
        }
        p -= 1;
    }
    Ordering::Equal
}

/// lo 部分（位置 < low）の加算の繰り上がりと sticky。
/// (carry_into_low, sticky_below_low) を返す。
fn lo_add_carry(lo_a: &[u8], sa: i64, lo_b: &[u8], sb: i64, low: i64) -> (bool, bool) {
    // 位置を昇順に走査。両方の係数の非零位置の和集合を集める。
    let mut positions = Vec::new();
    for (coef, s) in [(lo_a, sa), (lo_b, sb)] {
        let n = dlen(coef) as i64;
        let base = coef.len() - n as usize;
        for (k, &d) in coef[base..].iter().enumerate() {
            if d != 0 {
                positions.push(s + n - 1 - k as i64);
            }
        }
    }
    positions.sort_unstable();
    positions.dedup();
    let mut carry = 0u8;
    let mut sticky = false;
    let mut prev: Option<i64> = None;
    for p in positions {
        if p >= low {
            break;
        }
        // 隙間に carry が残っていればその位置の桁は 1 → sticky になり
        // 繰り上がりは死ぬ。
        if let Some(q) = prev
            && p > q + 1
            && carry == 1
        {
            sticky = true;
            carry = 0;
        }
        let s = digit_at(lo_a, sa, p) + digit_at(lo_b, sb, p) + carry;
        if !s.is_multiple_of(10) {
            sticky = true;
        }
        carry = u8::from(s >= 10);
        prev = Some(p);
    }
    let carry_out = if carry == 1 {
        match prev {
            Some(q) if q + 1 == low => true,
            Some(q) if q + 1 < low => {
                sticky = true;
                false
            }
            _ => false,
        }
    } else {
        false
    };
    (carry_out, sticky)
}

/// 桁列の整数を 1 減らす（非零が前提。全零はそのまま）。
fn dec1(v: &mut [u8]) {
    if v.iter().all(|&d| d == 0) {
        return;
    }
    let mut i = v.len();
    loop {
        i -= 1;
        if v[i] > 0 {
            v[i] -= 1;
            break;
        }
        v[i] = 9;
    }
}

/// 丸めの繰り上げ判定。guard は捨てる先頭桁、sticky はそれ以下に
/// 非零があるか、last は残す最終桁。
fn round_up(rm: Rm, neg: bool, guard: u8, sticky: bool, last: u8) -> bool {
    match rm {
        Rm::Down => false,
        Rm::Up => guard != 0 || sticky,
        Rm::HalfUp => guard >= 5,
        Rm::HalfDown => guard > 5 || (guard == 5 && sticky),
        Rm::HalfEven => guard > 5 || (guard == 5 && (sticky || last % 2 == 1)),
        Rm::Ceiling => !neg && (guard != 0 || sticky),
        Rm::Floor => neg && (guard != 0 || sticky),
        // 05up: 0 か 5 のときだけ上げる。
        Rm::Up05 => (guard != 0 || sticky) && (last == 0 || last == 5),
    }
}

/// NaN 伝播。sNaN があれば INVALID を立てて quiet にした最初の sNaN、
/// なければ最初の qNaN を返す。ペイロードは precision に丸め、符号は保持する。
fn propagate_nan(a: &Dec, b: Option<&Dec>, c: Option<&Dec>, ctx: &Ctx) -> Option<(Dec, u32)> {
    let mut flags = 0u32;
    let mut pick: Option<&Dec> = None;
    for d in [a, b.unwrap_or(a), c.unwrap_or(a)] {
        if d.kind == Kind::Snan {
            flags |= cond::INVALID;
            if pick.is_none() {
                pick = Some(d);
            }
        }
    }
    if flags != 0 {
        let src = pick.unwrap();
        let mut n = src.clone();
        n.kind = Kind::Qnan;
        // ペイロードは precision に収める（下位桁を残す）。
        if n.digits() > ctx.prec {
            let drop = n.coef.len() - ctx.prec as usize;
            n.coef.drain(0..drop);
        }
        return Some((n, flags));
    }
    for d in [a, b.unwrap_or(a), c.unwrap_or(a)] {
        if d.is_nan() {
            let mut n = d.clone();
            if n.digits() > ctx.prec {
                let drop = n.coef.len() - ctx.prec as usize;
                n.coef.drain(0..drop);
            }
            return Some((n, flags));
        }
    }
    None
}

/// IEEE minNum/maxNum の NaN 規則。片方だけ NaN なら他方を返す
/// （sNaN は INVALID 付き）。両方 NaN なら伝播。
fn nan_minmax(a: &Dec, b: &Dec, ctx: &Ctx) -> Option<(Dec, u32)> {
    if !a.is_nan() && !b.is_nan() {
        return None;
    }
    // sNaN があれば常に quiet 化した NaN + INVALID。
    if a.kind == Kind::Snan || b.kind == Kind::Snan {
        let (n, f) = propagate_nan(a, Some(b), None, ctx).unwrap();
        return Some((n, f));
    }
    if a.is_nan() && b.is_nan() {
        let (n, f) = propagate_nan(a, Some(b), None, ctx).unwrap();
        return Some((n, f));
    }
    // qNaN だけなら他方のオペランドを返す（符号は保持）。
    let d = if a.is_nan() { b } else { a };
    let (r, fr) = d.clone().finish(ctx);
    Some((r, fr))
}

impl Dec {
    /// 有限値を作る。係数の先頭 0 は削る（全 0 なら [0]）。
    #[must_use]
    pub fn finite(neg: bool, coef: Vec<u8>, exp: i32) -> Self {
        let mut c = coef;
        if c.is_empty() {
            c.push(0);
        }
        dtrim(&mut c);
        Self {
            neg,
            kind: Kind::Finite,
            coef: c,
            exp,
        }
    }

    /// ゼロ。
    #[must_use]
    pub fn zero(neg: bool) -> Self {
        Self {
            neg,
            kind: Kind::Finite,
            coef: vec![0],
            exp: 0,
        }
    }

    /// 無限大。
    #[must_use]
    pub fn inf(neg: bool) -> Self {
        Self {
            neg,
            kind: Kind::Inf,
            coef: vec![0],
            exp: 0,
        }
    }

    /// NaN。signaling なら sNaN。
    #[must_use]
    pub fn nan(signaling: bool) -> Self {
        Self {
            neg: false,
            kind: if signaling { Kind::Snan } else { Kind::Qnan },
            coef: vec![0],
            exp: 0,
        }
    }

    /// NaN かどうか。
    #[must_use]
    pub fn is_nan(&self) -> bool {
        matches!(self.kind, Kind::Qnan | Kind::Snan)
    }

    /// ゼロかどうか（有限で係数が全 0）。
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.kind == Kind::Finite && self.coef.iter().all(|&d| d == 0)
    }

    /// 係数の桁数（先頭の 0 を除く）。
    #[must_use]
    pub fn digits(&self) -> u32 {
        dlen(&self.coef) as u32
    }

    /// 調整済み指数 `exp + digits - 1`。
    #[must_use]
    pub fn adj_exp(&self) -> i64 {
        i64::from(self.exp) + i64::from(self.digits()) - 1
    }

    // ---- 文脈の適用 ----

    /// 文脈を適用する。丸め・サブノーマル・オーバーフロー・クランプを
    /// ここで処理し、条件フラグを返す。
    pub fn finish(self, ctx: &Ctx) -> (Self, u32) {
        self.finish_st(ctx, false)
    }

    /// `finish` に加えて捨てた分の sticky を供給する。商や剰余の
    /// 下位に非零があることを丸め判定に伝えるために使う。
    fn finish_st(mut self, ctx: &Ctx, sticky_in: bool) -> (Self, u32) {
        if self.kind != Kind::Finite {
            return (self, 0);
        }
        let mut flags = 0u32;
        let p = ctx.prec.max(1) as usize;
        let etiny = i64::from(ctx.emin) - i64::from(ctx.prec) + 1;
        let etop = i64::from(ctx.emax) - i64::from(ctx.prec) + 1;
        dtrim(&mut self.coef);
        if self.is_zero() {
            // 零。指数は [etiny, emax]、clamp=1 では [etiny, etop] に収める。
            self.coef.clear();
            self.coef.push(0);
            let hi = if ctx.clamp { etop } else { i64::from(ctx.emax) };
            if i64::from(self.exp) < etiny {
                self.exp = etiny as i32;
                flags |= cond::CLAMPED;
            } else if i64::from(self.exp) > hi {
                self.exp = hi as i32;
                flags |= cond::CLAMPED;
            }
            return (self, flags);
        }
        let n = dlen(&self.coef);
        let keep_from = self.coef.len() - n;
        let sub = self.adj_exp() < i64::from(ctx.emin);
        if sub {
            flags |= cond::SUBNORMAL;
        }
        // 捨てる桁数。precision 超過分と etiny 未満分の大きい方。
        let mut drop = n as i64 - p as i64;
        if sub {
            drop = drop.max(etiny - i64::from(self.exp));
        }
        if drop > 0 {
            let keep = n as i64 - drop; // 残る桁数（<= 0 なら全部落ちる）
            // ガード桁の位置は exp+drop-1。係数がそこまで届かなければ
            // guard=0 で sticky だけ見る。
            let (guard, sticky, last) = if keep < 0 {
                (
                    0u8,
                    self.coef[keep_from..].iter().any(|&d| d != 0) || sticky_in,
                    0u8,
                )
            } else {
                let keep = keep as usize;
                if keep == 0 {
                    (
                        self.coef[keep_from],
                        self.coef[keep_from + 1..].iter().any(|&d| d != 0) || sticky_in,
                        0u8,
                    )
                } else {
                    let split = keep_from + keep;
                    (
                        self.coef[split],
                        self.coef[split + 1..].iter().any(|&d| d != 0) || sticky_in,
                        self.coef[split - 1],
                    )
                }
            };
            let up = round_up(ctx.rm, self.neg, guard, sticky, last);
            self.coef.truncate(keep_from + keep.max(0) as usize);
            self.exp = (i64::from(self.exp) + drop).min(i64::from(i32::MAX)) as i32;
            flags |= cond::ROUNDED;
            if guard != 0 || sticky {
                flags |= cond::INEXACT;
            }
            if keep <= 0 {
                self.coef.clear();
                self.coef.push(u8::from(up));
            } else if up {
                let mut i = self.coef.len();
                loop {
                    if i == keep_from {
                        self.coef.insert(keep_from, 1);
                        break;
                    }
                    i -= 1;
                    if self.coef[i] < 9 {
                        self.coef[i] += 1;
                        break;
                    }
                    self.coef[i] = 0;
                }
                if self.coef.len() - keep_from > p {
                    self.coef.pop();
                    self.exp = self.exp.saturating_add(1);
                }
            }
            if self.is_zero() {
                // 係数が 0 になった。指数は etiny、Clamped を立てる。
                self.exp = etiny as i32;
                flags |= cond::CLAMPED;
            }
        }
        if flags & cond::SUBNORMAL != 0 && flags & cond::INEXACT != 0 {
            flags |= cond::UNDERFLOW;
        }
        if self.is_zero() {
            return (self, flags);
        }
        // オーバーフロー。調整済み指数が emax を超えた。
        if self.adj_exp() > i64::from(ctx.emax) {
            flags |= cond::OVERFLOW | cond::INEXACT | cond::ROUNDED;
            let to_inf = match ctx.rm {
                Rm::Down | Rm::Up05 => false,
                Rm::Ceiling => !self.neg,
                Rm::Floor => self.neg,
                _ => true,
            };
            if to_inf {
                return (Self::inf(self.neg), flags);
            }
            return (Self::finite(self.neg, vec![9; p], etop as i32), flags);
        }
        // クランプ。exp > etop なら係数に 0 を足して etop に合わせる。
        if ctx.clamp && i64::from(self.exp) > etop {
            let pad = (i64::from(self.exp) - etop) as usize;
            if dlen(&self.coef) + pad <= p {
                for _ in 0..pad {
                    self.coef.push(0);
                }
                self.exp = etop as i32;
                flags |= cond::CLAMPED;
            }
        }
        (self, flags)
    }

    // ---- 四則 ----

    /// 加算。
    #[must_use]
    pub fn add(&self, other: &Self, ctx: &Ctx) -> (Self, u32) {
        self.add_sub(other, false, ctx)
    }

    /// 減算。`a - b`。
    #[must_use]
    pub fn sub(&self, other: &Self, ctx: &Ctx) -> (Self, u32) {
        self.add_sub(other, true, ctx)
    }

    fn add_sub(&self, other: &Self, flip: bool, ctx: &Ctx) -> (Self, u32) {
        if let Some(r) = propagate_nan(self, Some(other), None, ctx) {
            return r;
        }
        let (ia, ib) = (self.kind == Kind::Inf, other.kind == Kind::Inf);
        let sb = other.neg ^ flip;
        if ia && ib {
            if self.neg == sb {
                return (Self::inf(self.neg), 0);
            }
            return (Self::nan(false), cond::INVALID);
        }
        if ia {
            return (Self::inf(self.neg), 0);
        }
        if ib {
            return (Self::inf(sb), 0);
        }
        // 有限。
        let za = self.is_zero();
        let zb = other.is_zero();
        if za && zb {
            // +0 + -0 → +0（RDN 系を除く）。指数は小さい方。
            let neg = match ctx.rm {
                Rm::Floor => self.neg || sb,
                _ => self.neg && sb,
            };
            let mut d = Self::zero(neg);
            d.exp = self.exp.min(other.exp);
            return d.finish(ctx);
        }
        if za || zb {
            // 片方が 0 → もう片方を優先指数 min(e1,e2) に寄せる。
            // 係数に 0 を足して指数を下げるが、precision を超える分は
            // 暗黙に捨てたものとして Rounded を立てる。
            let src = if za { (other, sb) } else { (self, self.neg) };
            let mut d = src.0.clone();
            d.neg = src.1;
            let e = self.exp.min(other.exp);
            let mut flags = 0u32;
            let diff = i64::from(d.exp) - i64::from(e);
            if diff > 0 {
                let n0 = dlen(&d.coef);
                let room = (ctx.prec as usize).saturating_sub(n0);
                let pad = (diff as usize).min(room);
                for _ in 0..pad {
                    d.coef.push(0);
                }
                d.exp -= pad as i32;
                if d.exp > e {
                    // 優先指数に届かない → 末尾の 0 を暗黙に捨てた。
                    flags |= cond::ROUNDED;
                }
            }
            let (r, f) = d.finish(ctx);
            return (r, f | flags);
        }
        // 共通指数に寄せて整数加算。指数差が巨大なときは係数を
        // 分けて仮想的に切り捨てる（cap 桁の窓）。
        let e = i64::from(self.exp).min(i64::from(other.exp));
        let la = dlen(&self.coef);
        let lb = dlen(&other.coef);
        let s1 = i64::from(self.exp) - e;
        let s2 = i64::from(other.exp) - e;
        let cap = (ctx.prec as usize + la.max(lb) + 4) as i64;
        let top1 = s1 + la as i64;
        let top2 = s2 + lb as i64;
        let l = top1.max(top2);
        let (res_coef, res_neg, res_exp, sticky) = if l <= cap {
            let a_coef = scale_coef(&self.coef, s1);
            let b_coef = scale_coef(&other.coef, s2);
            if self.neg == sb {
                (abs_add(&a_coef, &b_coef), self.neg, e, false)
            } else {
                match abs_cmp(&a_coef, &b_coef) {
                    Ordering::Greater => (abs_sub(&a_coef, &b_coef), self.neg, e, false),
                    Ordering::Less => (abs_sub(&b_coef, &a_coef), sb, e, false),
                    Ordering::Equal => {
                        let mut d = Self::zero(ctx.rm == Rm::Floor);
                        d.exp = self.exp.min(other.exp);
                        return d.finish(ctx);
                    }
                }
            }
        } else {
            // 切り捨て位置 low（これ未満の位置は窓の外）。
            // 係数の桁は位置 [shift, shift+len) にある。
            let low = l - cap;
            let split = |coef: &[u8], shift: i64| -> (Vec<u8>, Vec<u8>) {
                let n = dlen(coef) as i64;
                let top = shift + n;
                let hi_n = (top - low.max(shift)).max(0) as usize;
                let lo_n = (low.min(top) - shift).max(0) as usize;
                let base = coef.len() - n as usize;
                let hi = coef[base..base + hi_n].to_vec();
                let lo = coef[base + n as usize - lo_n..].to_vec();
                (hi, lo)
            };
            let (hi_a, lo_a) = split(&self.coef, s1);
            let (hi_b, lo_b) = split(&other.coef, s2);
            // hi は位置 low 基準の整数：係数の最下位の位置が s_i なら
            // s_i - low 個の 0 を末尾に足す（shift>low のときのみ正）。
            let eff = |hi: &[u8], shift: i64| -> Vec<u8> {
                let mut v = hi.to_vec();
                v.resize(hi.len() + (shift - low).max(0) as usize, 0);
                v
            };
            let ea = eff(&hi_a, s1);
            let eb = eff(&hi_b, s2);
            if self.neg == sb {
                // 同符号加算：lo 同士の和が窓へ繰り上がることがある。
                let (carry, sticky) = lo_add_carry(&lo_a, s1, &lo_b, s2, low);
                let mut out = abs_add(&ea, &eb);
                if carry {
                    let mut one = vec![0; out.len()];
                    *one.last_mut().unwrap() = 1;
                    out = abs_add(&out, &one);
                }
                (out, self.neg, e + low, sticky)
            } else {
                // 減算：真の大小は桁全体（hi+lo）で決める。
                match cmp_sparse(&self.coef, s1, &other.coef, s2) {
                    Ordering::Equal => {
                        let mut d = Self::zero(ctx.rm == Rm::Floor);
                        d.exp = self.exp.min(other.exp);
                        return d.finish(ctx);
                    }
                    ord => {
                        // 被減数の lo が減数の lo より小さいと借位が窓に入る。
                        let (w_a, w_b, neg) = if ord == Ordering::Greater {
                            ((ea, lo_a, s1), (eb, lo_b, s2), self.neg)
                        } else {
                            ((eb, lo_b, s2), (ea, lo_a, s1), sb)
                        };
                        let borrow = cmp_sparse(&w_a.1, w_a.2, &w_b.1, w_b.2) == Ordering::Less;
                        let sticky = cmp_sparse(&w_a.1, w_a.2, &w_b.1, w_b.2) != Ordering::Equal;
                        let mut out = abs_sub(&w_a.0, &w_b.0);
                        if borrow {
                            dec1(&mut out);
                        }
                        if out.iter().all(|&d| d == 0) {
                            let mut d = Self::zero(ctx.rm == Rm::Floor);
                            d.exp = i32::try_from(e + low).unwrap_or(i32::MIN + 1);
                            return d.finish(ctx);
                        }
                        (out, neg, e + low, sticky)
                    }
                }
            }
        };
        let d = Self {
            neg: res_neg,
            kind: Kind::Finite,
            coef: res_coef,
            exp: res_exp as i32,
        };
        d.finish_st(ctx, sticky)
    }

    /// 乗算。
    #[must_use]
    pub fn mul(&self, other: &Self, ctx: &Ctx) -> (Self, u32) {
        if let Some(r) = propagate_nan(self, Some(other), None, ctx) {
            return r;
        }
        let neg = self.neg ^ other.neg;
        let (ia, ib) = (self.kind == Kind::Inf, other.kind == Kind::Inf);
        if (ia && other.is_zero()) || (ib && self.is_zero()) {
            return (Self::nan(false), cond::INVALID);
        }
        if ia || ib {
            return (Self::inf(neg), 0);
        }
        if self.is_zero() || other.is_zero() {
            let mut d = Self::zero(neg);
            // 0 * x の指数は e1 + e2。
            d.exp = self.exp.saturating_add(other.exp);
            return d.finish(ctx);
        }
        let pa = PackedDec::from_digits(&self.coef, false).unwrap();
        let pb = PackedDec::from_digits(&other.coef, false).unwrap();
        let prod = pa.mul(&pb);
        let d = Self {
            neg,
            kind: Kind::Finite,
            coef: prod.digits,
            exp: self.exp.saturating_add(other.exp),
        };
        d.finish(ctx)
    }

    /// 除算。
    #[must_use]
    pub fn div(&self, other: &Self, ctx: &Ctx) -> (Self, u32) {
        if let Some(r) = propagate_nan(self, Some(other), None, ctx) {
            return r;
        }
        let neg = self.neg ^ other.neg;
        let (ia, ib) = (self.kind == Kind::Inf, other.kind == Kind::Inf);
        if ia && ib {
            return (Self::nan(false), cond::INVALID);
        }
        if ia {
            return (Self::inf(neg), 0);
        }
        let (za, zb) = (self.is_zero(), other.is_zero());
        if zb {
            if za {
                return (Self::nan(false), cond::DIV_UNDEFINED);
            }
            return (Self::inf(neg), cond::DIV_ZERO);
        }
        if ib {
            // GDA: 有限 ÷ Inf は符号付き 0、指数は etiny、Clamped。
            let mut d = Self::zero(neg);
            let etiny = i32::try_from(i64::from(ctx.emin) - i64::from(ctx.prec) + 1)
                .unwrap_or(i32::MIN + 1);
            d.exp = etiny;
            return (d, cond::CLAMPED);
        }
        if za {
            // 0 ÷ 有限：優先指数は e1-e2。クランプ範囲は finish と同じで
            // clamp=0 なら [etiny, emax]、clamp=1 なら [etiny, etop]。
            let mut d = Self::zero(neg);
            let mut flags = 0u32;
            let etiny = i64::from(ctx.emin) - i64::from(ctx.prec) + 1;
            let hi = if ctx.clamp {
                i64::from(ctx.emax) - i64::from(ctx.prec) + 1
            } else {
                i64::from(ctx.emax)
            };
            let mut e = i64::from(self.exp) - i64::from(other.exp);
            if e < etiny {
                e = etiny;
                flags |= cond::CLAMPED;
            } else if e > hi {
                e = hi;
                flags |= cond::CLAMPED;
            }
            d.exp = i32::try_from(e).unwrap_or(i32::MAX);
            return (d, flags);
        }
        // 商の整数部の桁数は la-lb または la-lb+1。余りが尽きるまで
        // 係数を伸ばし、必要なら precision+1 桁で丸める。
        let a = PackedDec::from_digits(&self.coef, false).unwrap();
        let b = PackedDec::from_digits(&other.coef, false).unwrap();
        let la = a.digit_len() as i64;
        let lb = b.digit_len() as i64;
        let p = i64::from(ctx.prec);
        // 商の整数部の桁数の見積もり。
        let q_int = la - lb;
        // まず scale 桁だけ伸ばして商を求める。
        let scale = (p - q_int).max(1);
        let mut num = a.digits.clone();
        num.resize(a.digits.len() + scale.max(0) as usize, 0);
        let num_pd = PackedDec::from_digits(&num, false).unwrap();
        let (mut q, mut r) = num_pd.divmod(&b).unwrap();
        // 余りが残る間は商を 1 桁ずつ伸ばす（ガード桁まで）。
        let mut res_exp = i64::from(self.exp) - i64::from(other.exp) - scale;
        let mut exact = r.is_zero();
        while !exact && q.digit_len() as i64 <= p {
            // もう 1 桁。
            let mut rn = r.digits.clone();
            rn.push(0);
            let r10 = PackedDec::from_digits(&rn, false).unwrap();
            let (g, r2) = r10.divmod(&b).unwrap();
            let mut qd = q.digits.clone();
            qd.push(g.digits.first().copied().unwrap_or(0));
            q = PackedDec::from_digits(&qd, false).unwrap();
            r = r2;
            res_exp -= 1;
            exact = r.is_zero();
        }
        let mut d = Self {
            neg,
            kind: Kind::Finite,
            coef: q.digits.clone(),
            exp: res_exp as i32,
        };
        dtrim(&mut d.coef);
        if exact {
            // 正確な商。優先指数 e1-e2 を上限として末尾 0 は削る
            // （係数が prec 内のままなら削れるところまで）。
            let pref = i64::from(self.exp) - i64::from(other.exp);
            while i64::from(d.exp) < pref && d.coef.last() == Some(&0) {
                d.coef.pop();
                d.exp += 1;
            }
        }
        d.finish_st(ctx, !exact)
    }

    /// 積和。`a*b + c` を一度だけ丸める。
    #[must_use]
    pub fn fma(&self, b: &Self, c: &Self, ctx: &Ctx) -> (Self, u32) {
        // sNaN は即座に伝播。
        if [self, b, c].iter().any(|d| d.kind == Kind::Snan) {
            return propagate_nan(self, Some(b), Some(c), ctx).unwrap();
        }
        let neg_prod = self.neg ^ b.neg;
        let (ia, ib, ic) = (
            self.kind == Kind::Inf,
            b.kind == Kind::Inf,
            c.kind == Kind::Inf,
        );
        if (ia && b.is_zero()) || (ib && self.is_zero()) {
            // Inf*0。加数 c が qNaN でも Invalid_operation は立つ。
            // 結果は伝播した NaN（あれば）。
            if let Some((n, _)) = propagate_nan(self, Some(b), Some(c), ctx) {
                return (n, cond::INVALID);
            }
            return (Self::nan(false), cond::INVALID);
        }
        if let Some(r) = propagate_nan(self, Some(b), Some(c), ctx) {
            return r;
        }
        if (ia || ib) && ic && neg_prod != c.neg {
            // Inf - Inf。
            return (Self::nan(false), cond::INVALID);
        }
        if ia || ib {
            return (Self::inf(neg_prod), 0);
        }
        if ic {
            return (Self::inf(c.neg), 0);
        }
        let pa = PackedDec::from_digits(&self.coef, false).unwrap();
        let pb = PackedDec::from_digits(&b.coef, false).unwrap();
        let prod = pa.mul(&pb);
        let prod_dec = Self {
            neg: neg_prod,
            kind: Kind::Finite,
            coef: prod.digits,
            exp: self.exp.saturating_add(b.exp),
        };
        prod_dec.add_sub(c, false, ctx)
    }

    // ---- 単項 ----

    /// 文脈適用の正値（plus 演算）。`0 + x` の和として扱い、
    /// 零の符号は floor なら -0、それ以外は +0。
    #[must_use]
    pub fn plus(&self, ctx: &Ctx) -> (Self, u32) {
        if let Some(r) = propagate_nan(self, None, None, ctx) {
            return r;
        }
        let (mut d, f) = self.clone().finish(ctx);
        // オペランドが厳密に零なら結果の符号は丸めモード由来
        // （floor→-0、他は+0）。非零が零に丸まった場合は符号保持。
        if d.kind == Kind::Finite && d.is_zero() && self.is_zero() {
            d.neg = ctx.rm == Rm::Floor;
        }
        (d, f)
    }

    /// 符号反転して文脈適用。`0 - x` の差として扱い、
    /// 零の符号は floor なら -0、それ以外は +0。
    #[must_use]
    pub fn minus(&self, ctx: &Ctx) -> (Self, u32) {
        if let Some(r) = propagate_nan(self, None, None, ctx) {
            return r;
        }
        let mut d = self.clone();
        d.neg = !d.neg;
        let (mut d, f) = d.finish(ctx);
        if d.kind == Kind::Finite && d.is_zero() && self.is_zero() {
            d.neg = ctx.rm == Rm::Floor;
        }
        (d, f)
    }

    /// 絶対値にして文脈適用。
    #[must_use]
    pub fn abs(&self, ctx: &Ctx) -> (Self, u32) {
        if let Some(r) = propagate_nan(self, None, None, ctx) {
            return r;
        }
        let mut d = self.clone();
        d.neg = false;
        d.finish(ctx)
    }

    // ---- 比較 ----

    /// quiet 比較。等しければ 0、小さければ -1、大きければ 1。
    /// NaN があれば quiet は qNaN を伝播、sNaN は INVALID。
    #[must_use]
    pub fn compare(&self, other: &Self, ctx: &Ctx) -> (Self, u32) {
        if self.is_nan() || other.is_nan() {
            let (n, f) = propagate_nan(self, Some(other), None, ctx).unwrap();
            return (n, f);
        }
        let ord = self.total_cmp(other);
        let v: i8 = match ord {
            Ordering::Less => -1,
            Ordering::Equal => 0,
            Ordering::Greater => 1,
        };
        (Self::finite(v < 0, vec![v.unsigned_abs()], 0), 0)
    }

    /// signaling 比較。NaN があれば必ず INVALID。
    #[must_use]
    pub fn compare_sig(&self, other: &Self, ctx: &Ctx) -> (Self, u32) {
        if self.is_nan() || other.is_nan() {
            let (n, f) = propagate_nan(self, Some(other), None, ctx).unwrap();
            return (n, f | cond::INVALID);
        }
        self.compare(other, ctx)
    }

    /// 符号込みの大小比較（NaN なしが前提）。
    fn total_cmp(&self, other: &Self) -> Ordering {
        match (self.kind, other.kind) {
            (Kind::Inf, Kind::Inf) => {
                return if self.neg == other.neg {
                    Ordering::Equal
                } else if self.neg {
                    Ordering::Less
                } else {
                    Ordering::Greater
                };
            }
            (Kind::Inf, _) => {
                return if self.neg {
                    Ordering::Less
                } else {
                    Ordering::Greater
                };
            }
            (_, Kind::Inf) => {
                return if other.neg {
                    Ordering::Greater
                } else {
                    Ordering::Less
                };
            }
            _ => {}
        }
        let za = self.is_zero();
        let zb = other.is_zero();
        if za && zb {
            return Ordering::Equal;
        }
        match (self.neg, other.neg) {
            (true, false) => return Ordering::Less,
            (false, true) => return Ordering::Greater,
            _ => {}
        }
        let ord = self.abs_cmp(other);
        if self.neg { ord.reverse() } else { ord }
    }

    /// 絶対値の比較（有限が前提）。
    fn abs_cmp(&self, other: &Self) -> Ordering {
        // 零はコーホートに関わらず等しく、非零は零より大。
        match (self.is_zero(), other.is_zero()) {
            (true, true) => return Ordering::Equal,
            (true, false) => return Ordering::Less,
            (false, true) => return Ordering::Greater,
            _ => {}
        }
        // 調整済み指数で比べ、同じなら係数を位置合わせして比較。
        let n1 = dlen(&self.coef) as i64;
        let n2 = dlen(&other.coef) as i64;
        let adj1 = i64::from(self.exp) + n1 - 1;
        let adj2 = i64::from(other.exp) + n2 - 1;
        if adj1 != adj2 {
            return adj1.cmp(&adj2);
        }
        // 同じ adj。係数を同じ幅に揃えて辞書順比較。
        let w = n1.max(n2) as usize;
        let mut a = self.coef.clone();
        let mut b = other.coef.clone();
        a.resize(a.len() - n1 as usize + w, 0);
        b.resize(b.len() - n2 as usize + w, 0);
        a.cmp(&b)
    }

    /// 最小値（IEEE の minNum。片方だけ NaN なら他方を返す）。
    #[must_use]
    pub fn min_num(&self, other: &Self, ctx: &Ctx) -> (Self, u32) {
        minmax(self, other, false, ctx)
    }

    /// 最大値（IEEE の maxNum）。
    #[must_use]
    pub fn max_num(&self, other: &Self, ctx: &Ctx) -> (Self, u32) {
        minmax(self, other, true, ctx)
    }

    /// 絶対値の最大値。
    #[must_use]
    pub fn max_mag(&self, other: &Self, ctx: &Ctx) -> (Self, u32) {
        minmax_mag(self, other, true, ctx)
    }

    /// 絶対値の最小値。
    #[must_use]
    pub fn min_mag(&self, other: &Self, ctx: &Ctx) -> (Self, u32) {
        minmax_mag(self, other, false, ctx)
    }

    /// 量子化。他方の指数に合わせる。結果の係数が precision を
    /// 超えるときは INVALID。Underflow は立てない規則。
    #[must_use]
    pub fn quantize(&self, other: &Self, ctx: &Ctx) -> (Self, u32) {
        if let Some(r) = propagate_nan(self, Some(other), None, ctx) {
            return r;
        }
        if self.kind == Kind::Inf || other.kind == Kind::Inf {
            if self.kind == other.kind {
                return (Self::inf(self.neg), 0);
            }
            return (Self::nan(false), cond::INVALID);
        }
        let e = i64::from(other.exp);
        // 目標係数は c * 10^(self.exp - e)。shift>0 なら桁を足し、
        // shift<0 なら桁を捨てて丸める。
        let shift = i64::from(self.exp) - e;
        let mut d = self.clone();
        let mut flags = 0u32;
        if shift < 0 {
            // 係数から -shift 桁を捨てる。
            let n = dlen(&d.coef) as i64;
            let kf = d.coef.len() - n as usize;
            let drop = (-shift).min(i64::MAX - 1);
            if n == 0 {
                d.exp = other.exp;
            } else if drop >= n {
                // 全部落ちる。drop > n ならガードは最上位桁の上の
                // 仮想 0 で、係数全体が sticky。drop == n なら
                // ガードは最上位桁そのもの。
                let (guard, sticky) = if drop == n {
                    (d.coef[kf], d.coef[kf + 1..].iter().any(|&x| x != 0))
                } else {
                    (0, d.coef[kf..].iter().any(|&x| x != 0))
                };
                let up = round_up(ctx.rm, d.neg, guard, sticky, 0);
                d.coef = vec![u8::from(up)];
                d.exp = other.exp;
                flags |= cond::ROUNDED;
                if guard != 0 || sticky {
                    flags |= cond::INEXACT;
                }
            } else {
                let keep = (n - drop) as usize;
                let split = kf + keep;
                let guard = d.coef[split];
                let sticky = d.coef[split + 1..].iter().any(|&x| x != 0);
                let last = d.coef[split - 1];
                let up = round_up(ctx.rm, d.neg, guard, sticky, last);
                d.coef.truncate(split);
                d.exp = other.exp;
                flags |= cond::ROUNDED;
                if guard != 0 || sticky {
                    flags |= cond::INEXACT;
                }
                if up {
                    let mut i = d.coef.len();
                    loop {
                        if i == kf {
                            d.coef.insert(kf, 1);
                            break;
                        }
                        i -= 1;
                        if d.coef[i] < 9 {
                            d.coef[i] += 1;
                            break;
                        }
                        d.coef[i] = 0;
                    }
                }
            }
        } else if shift > 0 {
            // 係数に 0 を足して指数を下げる（零係数は桁数を増やさない）。
            let n = dlen(&d.coef);
            let add = shift.min(i64::MAX - 1) as usize;
            if n > 0 && n + add > ctx.prec as usize {
                return (Self::nan(false), cond::INVALID);
            }
            if n > 0 {
                for _ in 0..add {
                    d.coef.push(0);
                }
            }
            d.exp = other.exp;
        } else {
            d.exp = other.exp;
        }
        if d.digits() > ctx.prec {
            return (Self::nan(false), cond::INVALID);
        }
        // 結果が有限範囲内にあること。指数は etiny 以上、
        // 調整済み指数は emax 以下（零も対象）。
        let etiny = i64::from(ctx.emin) - i64::from(ctx.prec) + 1;
        if d.is_zero() {
            if i64::from(d.exp) < etiny || i64::from(d.exp) > i64::from(ctx.emax) {
                return (Self::nan(false), cond::INVALID);
            }
        } else if d.adj_exp() > i64::from(ctx.emax) || i64::from(d.exp) < etiny {
            return (Self::nan(false), cond::INVALID);
        }
        // quantize は非正規結果に Subnormal を立てる（Underflow は立てない）。
        if !d.is_zero() && d.adj_exp() < i64::from(ctx.emin) {
            flags |= cond::SUBNORMAL;
        }
        // なお、書式バインド（IEEE quantize）で結果指数が Etop を
        // 超える場合の Clamped は呼び出し側が付与する。
        (d, flags)
    }

    /// 同じ量子かどうか。真なら 1、偽なら 0、NaN/Inf なら INVALID。
    #[must_use]
    pub fn same_quantum(&self, other: &Self) -> (Self, u32) {
        // 述語なので NaN でも例外を立てない（sNaN でも 0）。
        if self.is_nan() || other.is_nan() {
            let eq = self.is_nan() && other.is_nan();
            return (Self::finite(false, vec![u8::from(eq)], 0), 0);
        }
        if self.kind == Kind::Inf || other.kind == Kind::Inf {
            let eq = self.kind == other.kind;
            return (Self::finite(false, vec![u8::from(eq)], 0), 0);
        }
        (
            Self::finite(false, vec![u8::from(self.exp == other.exp)], 0),
            0,
        )
    }

    /// 指数の再スケール（rescale）。`other` の値が目標指数。
    /// quantize と同じ丸めだが Subnormal を立てる点が異なる。
    #[must_use]
    pub fn rescale(&self, other: &Self, ctx: &Ctx) -> (Self, u32) {
        if let Some(r) = propagate_nan(self, Some(other), None, ctx) {
            return r;
        }
        // Inf は両辺のときだけ許す（結果は self の Inf）。
        // 片方だけなら Invalid_operation。
        if self.kind == Kind::Inf || other.kind == Kind::Inf {
            if self.kind == other.kind {
                return (Self::inf(self.neg), 0);
            }
            return (Self::nan(false), cond::INVALID);
        }
        // other は整数値でなければならない。
        let Some(new_exp) = other.int_value() else {
            return (Self::nan(false), cond::INVALID);
        };
        let t = Dec::finite(false, vec![1], new_exp);
        let (d, f) = self.quantize(&t, ctx);
        // rescale は Subnormal を立てる（quantize は立てない）。
        if f & cond::INVALID == 0
            && d.kind == Kind::Finite
            && !d.is_zero()
            && d.adj_exp() < i64::from(ctx.emin)
        {
            return (d, f | cond::SUBNORMAL);
        }
        (d, f)
    }

    /// 整数値としての値（exp<0 で割り切れないなら None）。
    fn int_value(&self) -> Option<i32> {
        if self.kind != Kind::Finite {
            return None;
        }
        let mut digits = self.coef.clone();
        let mut exp = i64::from(self.exp);
        // 係数末尾の 0 と exp の負分を相殺する。
        while exp < 0 {
            match digits.last() {
                Some(&0) => {
                    digits.pop();
                    exp += 1;
                }
                None => break,
                _ => return None,
            }
        }
        let mut v: i64 = 0;
        for &d in &digits {
            v = v * 10 + i64::from(d);
        }
        v = v.saturating_mul(10i64.saturating_pow(exp.min(18) as u32));
        if self.neg {
            v = -v;
        }
        i32::try_from(v).ok()
    }

    /// 係数の末尾 0 を削る（reduce/normalize）。
    #[must_use]
    pub fn reduce(&self, ctx: &Ctx) -> (Self, u32) {
        if let Some(r) = propagate_nan(self, None, None, ctx) {
            return r;
        }
        if self.kind == Kind::Inf {
            return (Self::inf(self.neg), 0);
        }
        // 先に文脈を適用（非正規の丸め込み）してから末尾 0 を削る。
        let (mut d, flags) = self.clone().finish(ctx);
        if d.is_zero() {
            // 零の reduce は指数 0 の正準形。
            d.exp = 0;
            return (d, flags);
        }
        // 末尾 0 を削る。ただし指数は Etop（emax - prec + 1）を
        // 超えられない。ddReduce の "origami" 例がこの上限を要求する。
        let etop = ctx.emax - ctx.prec as i32 + 1;
        while d.coef.last() == Some(&0) && d.exp < etop {
            d.coef.pop();
            d.exp = d.exp.saturating_add(1);
        }
        (d, flags)
    }

    /// 整数への丸め。exact なら Inexact/Rounded を立てる（tointegralx）。
    #[must_use]
    pub fn to_integral(&self, exact: bool, ctx: &Ctx) -> (Self, u32) {
        if let Some(r) = propagate_nan(self, None, None, ctx) {
            return r;
        }
        if self.kind == Kind::Inf {
            return (Self::inf(self.neg), 0);
        }
        if self.exp >= 0 {
            // すでに整数。指数を展開せずオペランドの量子のまま返す。
            return self.clone().finish(ctx);
        }
        // 小数部を削る。削る桁数 = -exp。
        let mut c = self.clone();
        let need = (-c.exp) as usize;
        let n = dlen(&c.coef);
        if n == 0 {
            // 零。指数は 0 に揃える。
            c.exp = 0;
            return c.finish(ctx);
        }
        let mut flags = 0u32;
        if need >= n {
            let kf = c.coef.len() - n;
            // 全桁が捨てられる。ガード桁は小数第 1 位なので、係数が
            // 小数点に届かない（need > n）ときガードは仮想の 0。
            let (g, st) = if need == n {
                (c.coef[kf], c.coef[kf + 1..].iter().any(|&d| d != 0))
            } else {
                (0, c.coef[kf..].iter().any(|&d| d != 0))
            };
            let up = round_up(ctx.rm, c.neg, g, st, 0);
            c.coef = vec![u8::from(up)];
            c.exp = 0;
            if exact {
                flags |= cond::ROUNDED;
                if g != 0 || st {
                    flags |= cond::INEXACT;
                }
            }
        } else {
            let kf = c.coef.len() - n;
            let split = kf + (n - need);
            let g = c.coef[split];
            let st = c.coef[split + 1..].iter().any(|&d| d != 0);
            let last = c.coef[split - 1];
            let up = round_up(ctx.rm, c.neg, g, st, last);
            c.coef.truncate(split);
            c.exp = 0;
            if exact {
                flags |= cond::ROUNDED;
                if g != 0 || st {
                    flags |= cond::INEXACT;
                }
            }
            if up {
                let mut i = c.coef.len();
                loop {
                    if i == kf {
                        c.coef.insert(kf, 1);
                        break;
                    }
                    i -= 1;
                    if c.coef[i] < 9 {
                        c.coef[i] += 1;
                        break;
                    }
                    c.coef[i] = 0;
                }
            }
        }
        let (r, f2) = c.finish(ctx);
        // tointegral（exact=false）は条件を立てない。
        // tointegralx（exact=true）は Rounded と、非零を捨てれば Inexact。
        (r, flags | f2)
    }

    /// 平方根。
    #[must_use]
    pub fn sqrt(&self, ctx: &Ctx) -> (Self, u32) {
        if let Some(r) = propagate_nan(self, None, None, ctx) {
            return r;
        }
        if self.kind == Kind::Inf {
            if self.neg {
                return (Self::nan(false), cond::INVALID);
            }
            return (Self::inf(false), 0);
        }
        if self.is_zero() {
            let mut d = self.clone();
            d.exp = self.exp.div_euclid(2);
            return d.finish(ctx);
        }
        if self.neg {
            return (Self::nan(false), cond::INVALID);
        }
        // 値 = c * 10^e。結果指数は floor(e/2)。
        let res_exp0 = self.exp.div_euclid(2);
        let odd = self.exp.rem_euclid(2);
        // sqrt(c * 10^odd) を求める。c を 10^(2m) 倍して整数平方根。
        let mut num = self.coef.clone();
        if odd == 1 {
            num.push(0);
        }
        let np = PackedDec::from_digits(&num, false).unwrap();
        // q の桁数 ≈ (nd + 2m)/2。prec+2 桁以上になるよう m を決める。
        let nd = np.digit_len() as i64;
        let m = ((2 * ctx.prec as i64 + 4 - nd + 1) / 2).max(0);
        let mut num2 = np.digits.clone();
        num2.resize(np.digits.len() + (2 * m).max(0) as usize, 0);
        let np2 = PackedDec::from_digits(&num2, false).unwrap();
        let (q, exact) = isqrt(&np2);
        let mut coef = q.digits;
        let mut exp = i64::from(res_exp0) - m;
        if exact {
            // パディング由来の 0 を除き preferred exponent = floor(e/2) へ。
            while m > 0 && coef.last() == Some(&0) && exp < i64::from(res_exp0) {
                coef.pop();
                exp += 1;
            }
        }
        let mut d = Self {
            neg: false,
            kind: Kind::Finite,
            coef,
            exp: i32::try_from(exp).unwrap_or(0),
        };
        dtrim(&mut d.coef);
        d.finish_st(ctx, !exact)
    }

    // ---- 文字列 ----

    /// 科学的記法の文字列（GDA の to-scientific-string）。
    #[must_use]
    pub fn to_sci(&self) -> String {
        let neg = if self.neg { "-" } else { "" };
        match self.kind {
            Kind::Inf => return format!("{neg}Infinity"),
            Kind::Qnan | Kind::Snan => {
                let s = if self.kind == Kind::Snan {
                    "sNaN"
                } else {
                    "NaN"
                };
                if !self.coef.iter().all(|&d| d == 0) {
                    let digs: String = self.coef.iter().map(|&d| (b'0' + d) as char).collect();
                    return format!("{neg}{s}{digs}");
                }
                return format!("{neg}{s}");
            }
            Kind::Finite => {}
        }
        let digs: String = self.coef.iter().map(|&d| (b'0' + d) as char).collect();
        let n = digs.len() as i32;
        let adj = self.exp + n - 1;
        let body = if self.exp <= 0 && adj >= -6 {
            // 科学的記法にしない範囲。
            if self.exp == 0 {
                digs.clone()
            } else if adj >= 0 {
                // 桁の途中に小数点。
                let int_n = (adj + 1) as usize;
                if int_n >= digs.len() {
                    format!("{}{}", digs, "0".repeat(int_n - digs.len()))
                } else {
                    format!("{}.{}", &digs[..int_n], &digs[int_n..])
                }
            } else {
                format!("0.{}{}", "0".repeat((-adj - 1) as usize), digs)
            }
        } else {
            // 科学的記法。d[.ddd]E±adj。
            if digs.len() == 1 {
                format!("{}E{}{}", digs, if adj < 0 { "-" } else { "+" }, adj.abs())
            } else {
                format!(
                    "{}.{}E{}{}",
                    &digs[..1],
                    &digs[1..],
                    if adj < 0 { "-" } else { "+" },
                    adj.abs()
                )
            }
        };
        format!("{neg}{body}")
    }

    /// 工学記法の文字列（指数は 3 の倍数）。
    #[must_use]
    pub fn to_eng(&self) -> String {
        if self.kind != Kind::Finite {
            return self.to_sci();
        }
        let neg = if self.neg { "-" } else { "" };
        let digs: String = self.coef.iter().map(|&d| (b'0' + d) as char).collect();
        let n = digs.len() as i32;
        let adj = self.exp + n - 1;
        if self.is_zero() {
            // 0：指数が -6..=0 なら素直な小数、それ以外は指数を
            // 3 の倍数に切り上げて 0.00..E±e3。
            let e = i64::from(self.exp);
            if (-6..=0).contains(&e) {
                if e == 0 {
                    return format!("{neg}0");
                }
                return format!("{neg}0.{}", "0".repeat((-e) as usize));
            }
            let r = e.rem_euclid(3);
            let e3 = e + if r == 0 { 0 } else { 3 - r };
            let z = (e3 - e) as usize;
            let mant = if z == 0 {
                "0".to_string()
            } else {
                format!("0.{}", "0".repeat(z))
            };
            return if e3 == 0 {
                format!("{neg}{mant}")
            } else {
                format!("{neg}{mant}E{}{}", if e3 < 0 { "-" } else { "+" }, e3.abs())
            };
        }
        if self.exp <= 0 && adj >= -6 {
            // to_sci と同じ非科学記法範囲。
            return self.to_sci();
        }
        // 整数部の桁数: adj mod 3 + 1（1..3）。
        let int_n = (adj.rem_euclid(3) + 1) as usize;
        let e3 = adj - adj.rem_euclid(3);
        let mut coef = digs.clone();
        if coef.len() < int_n {
            coef.push_str(&"0".repeat(int_n - coef.len()));
        }
        // 調整後の指数が 0 なら指数部は出さない（"100" 等）。
        let body = if coef.len() == int_n {
            coef
        } else {
            format!("{}.{}", &coef[..int_n], &coef[int_n..])
        };
        if e3 == 0 {
            return format!("{neg}{body}");
        }
        format!("{neg}{body}E{}{}", if e3 < 0 { "-" } else { "+" }, e3.abs())
    }

    /// 文字列の解析（GDA の to-number 構文）。受理できなければ `None`。
    /// 前後の空白は文法に含まれないので受理しない。
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let t = s;
        if t.is_empty() {
            return None;
        }
        let (neg, rest) = match t.as_bytes()[0] {
            b'-' => (true, &t[1..]),
            b'+' => (false, &t[1..]),
            _ => (false, t),
        };
        let low = rest.to_ascii_lowercase();
        if low == "inf" || low == "infinity" {
            return Some(Self::inf(neg));
        }
        if let Some(p) = low.strip_prefix("snan") {
            let mut d = Self::nan(true);
            d.neg = neg;
            if let Some(c) = parse_digits(p) {
                if !c.is_empty() {
                    d.coef = c;
                    dtrim(&mut d.coef);
                }
            } else if !p.is_empty() {
                return None;
            }
            return Some(d);
        }
        if let Some(p) = low.strip_prefix("nan") {
            let mut d = Self::nan(false);
            d.neg = neg;
            if let Some(c) = parse_digits(p) {
                if !c.is_empty() {
                    d.coef = c;
                    dtrim(&mut d.coef);
                }
            } else if !p.is_empty() {
                return None;
            }
            return Some(d);
        }
        // [digits][.digits][E[+/-]digits]
        let bytes = rest.as_bytes();
        let mut i = 0;
        let mut int_part = Vec::new();
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            int_part.push(bytes[i] - b'0');
            i += 1;
        }
        let mut frac = Vec::new();
        if i < bytes.len() && bytes[i] == b'.' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                frac.push(bytes[i] - b'0');
                i += 1;
            }
        }
        if int_part.is_empty() && frac.is_empty() {
            return None;
        }
        let mut exp: i64 = 0;
        if i < bytes.len() && (bytes[i] == b'e' || bytes[i] == b'E') {
            i += 1;
            let mut esign = 1i64;
            if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
                if bytes[i] == b'-' {
                    esign = -1;
                }
                i += 1;
            }
            if i >= bytes.len() || !bytes[i].is_ascii_digit() {
                return None;
            }
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                exp = exp
                    .checked_mul(10)?
                    .checked_add(i64::from(bytes[i] - b'0'))?;
                if exp > 2_000_000_000 {
                    exp = 2_000_000_000; // i32 に収まる上限（後で Inf/0 に潰す）
                    while i < bytes.len() && bytes[i].is_ascii_digit() {
                        i += 1;
                    }
                    break;
                }
                i += 1;
            }
            exp *= esign;
        }
        if i != bytes.len() {
            return None;
        }
        let mut coef = int_part;
        coef.extend_from_slice(&frac);
        let exp = exp
            .checked_sub(frac.len() as i64)?
            .clamp(i64::from(i32::MIN), i64::from(i32::MAX));
        let mut d = Self::finite(neg, coef, exp as i32);
        // 全桁 0 の -0 は符号を保持する。
        if neg {
            d.neg = true;
        }
        Some(d)
    }
}

// ---- 演算の内部 ----

use core::cmp::Ordering;

/// IEEE minNum/maxNum。
fn minmax(a: &Dec, b: &Dec, want_max: bool, ctx: &Ctx) -> (Dec, u32) {
    if let Some(r) = nan_minmax(a, b, ctx) {
        return r;
    }
    let ord = a.total_cmp(b);
    let take_a = if want_max {
        ord == Ordering::Greater
    } else {
        ord == Ordering::Less
    };
    if ord == Ordering::Equal {
        // 同値。符号が違えば正を優先（max）/負を優先（min）。
        if a.neg != b.neg {
            let sel = if want_max { !a.neg } else { a.neg };
            let (d, f) = if sel {
                a.clone().finish(ctx)
            } else {
                b.clone().finish(ctx)
            };
            return (d, f);
        }
        // 同符号同値：指数が大きい方を max は選ぶ。負値は逆。
        let pick_larger_exp = want_max != a.neg;
        let sel = if a.exp == b.exp {
            true
        } else if pick_larger_exp {
            a.exp > b.exp
        } else {
            a.exp < b.exp
        };
        let (d, f) = if sel {
            a.clone().finish(ctx)
        } else {
            b.clone().finish(ctx)
        };
        return (d, f);
    }
    let (d, f) = if take_a {
        a.clone().finish(ctx)
    } else {
        b.clone().finish(ctx)
    };
    (d, f)
}

/// IEEE maxNumMag/minNumMag。
fn minmax_mag(a: &Dec, b: &Dec, want_max: bool, ctx: &Ctx) -> (Dec, u32) {
    if let Some(r) = nan_minmax(a, b, ctx) {
        return r;
    }
    // |x| の順序。Inf は全有限値より大。
    let ord = match (a.kind == Kind::Inf, b.kind == Kind::Inf) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        (false, false) => a.abs_cmp(b),
    };
    let take_a = if want_max {
        ord == Ordering::Greater
    } else {
        ord == Ordering::Less
    };
    if ord == Ordering::Equal {
        // 同じ絶対値。符号が違えば正を優先（max）/負を優先（min）。
        if a.neg != b.neg {
            let sel = if want_max { !a.neg } else { a.neg };
            let (d, f) = if sel {
                a.clone().finish(ctx)
            } else {
                b.clone().finish(ctx)
            };
            return (d, f);
        }
        // 同符号：指数の規則は max/min と同じ。
        let pick_larger_exp = want_max != a.neg;
        let sel = if a.exp == b.exp {
            true
        } else if pick_larger_exp {
            a.exp > b.exp
        } else {
            a.exp < b.exp
        };
        let (d, f) = if sel {
            a.clone().finish(ctx)
        } else {
            b.clone().finish(ctx)
        };
        return (d, f);
    }
    if take_a {
        a.clone().finish(ctx)
    } else {
        b.clone().finish(ctx)
    }
}

/// 整数平方根（ニュートン法）。戻り値は (商, 厳密か)。
fn isqrt(n: &PackedDec) -> (PackedDec, bool) {
    if n.is_zero() {
        return (PackedDec::from_digits(&[0], false).unwrap(), true);
    }
    // 初期値: 10^ceil(len/2)。
    let l = n.digit_len();
    let mut x = vec![0u8; 1 + l.div_ceil(2)];
    x[0] = 1;
    let mut xp = PackedDec::from_digits(&x, false).unwrap();
    loop {
        // x' = (x + n/x) / 2。
        let (q, _r) = n.divmod(&xp).unwrap();
        let s = xp.add(&q);
        // s / 2（桁列の半分）。
        let half = half_digits(&s.digits);
        let xn = PackedDec::from_digits(&half, false).unwrap();
        if xn.cmp(&xp) != Ordering::Less {
            // 収束。xp*xp <= n < (xp+1)^2 かを確かめる。
            let sq = xp.mul(&xp);
            let exact = sq.cmp(n) == Ordering::Equal;
            return (xp, exact);
        }
        xp = xn;
    }
}

/// 桁列を 2 で割る（繰り下がり処理）。
fn half_digits(d: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(d.len());
    let mut carry = 0u8;
    for &x in d {
        let v = carry * 10 + x;
        out.push(v / 2);
        carry = v % 2;
    }
    out
}

// ---- DPD 符号化 ----

/// 十進浮動小数点の交換形式。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DfpFmt {
    /// 総ビット数（32/64/128）。
    pub bits: u32,
    /// 係数桁数。
    pub prec: u32,
    /// 調整済み指数の最大。
    pub emax: i32,
    /// 指数バイアス（= -etiny）。
    pub bias: i32,
    /// 組合せフィールドに入らない指数ビット数。
    pub exp_cont_bits: u32,
}

impl DfpFmt {
    /// この形式の文脈（IEEE 交換形式は clamp が有効）。
    #[must_use]
    pub const fn ctx(&self) -> Ctx {
        Ctx {
            prec: self.prec,
            emax: self.emax,
            emin: -self.emax + 1,
            rm: Rm::HalfEven,
            clamp: true,
        }
    }

    /// 係数のデクレット数（先頭桁を除く (prec-1)/3）。
    const fn declets(&self) -> u32 {
        (self.prec - 1) / 3
    }
}

/// decimal32。
pub const FMT_D32: DfpFmt = DfpFmt {
    bits: 32,
    prec: 7,
    emax: 96,
    bias: 101,
    exp_cont_bits: 6,
};

/// decimal64。
pub const FMT_D64: DfpFmt = DfpFmt {
    bits: 64,
    prec: 16,
    emax: 384,
    bias: 398,
    exp_cont_bits: 8,
};

/// decimal128。
pub const FMT_D128: DfpFmt = DfpFmt {
    bits: 128,
    prec: 34,
    emax: 6144,
    bias: 6176,
    exp_cont_bits: 12,
};

/// 値を交換形式のビット列に符号化する。
#[must_use]
pub fn encode(f: DfpFmt, d: &Dec) -> u128 {
    let neg_bit = u128::from(d.neg) << (f.bits - 1);
    match d.kind {
        Kind::Inf => {
            // 組合せフィールド 11110。
            neg_bit | (0b11110u128 << (f.bits - 6))
        }
        Kind::Qnan | Kind::Snan => {
            // 組合せフィールド 11111、指数継続の先頭ビットが sNaN 印。
            let mut v = neg_bit | (0b11111u128 << (f.bits - 6));
            if d.kind == Kind::Snan {
                v |= 1u128 << (f.bits - 7);
            }
            // ペイロードは係数フィールドにデクレットで収める。
            let ncoef = f.prec - 1;
            let mut coef = d.coef.clone();
            let nl = coef.len();
            if nl > ncoef as usize {
                coef.drain(0..nl - ncoef as usize);
            }
            let mut pad = vec![0u8; ncoef as usize - coef.len()];
            pad.extend_from_slice(&coef);
            let mut bits: u128 = 0;
            for i in 0..f.declets() {
                let c0 = u16::from(pad[(i * 3) as usize]);
                let c1 = u16::from(pad[(i * 3 + 1) as usize]);
                let c2 = u16::from(pad[(i * 3 + 2) as usize]);
                let dl = dpd::bcd_to_dpd((c0 << 8) | (c1 << 4) | c2);
                bits |= u128::from(dl) << (10 * (f.declets() - 1 - i));
            }
            v | bits
        }
        Kind::Finite => {
            // 係数を prec 桁に揃える（先頭は組合せフィールド）。
            let etop = i64::from(f.emax) - i64::from(f.prec) + 1;
            let mut coef = d.coef.clone();
            let n = coef.len();
            if n > f.prec as usize {
                // 先頭が 0 でない限り収まらない。呼び出し側の規約では
                // encode 前に文脈適用済み。ここでは下位桁を残す。
                coef.drain(0..n - f.prec as usize);
            }
            let mut full = vec![0u8; f.prec as usize - coef.len()];
            full.extend_from_slice(&coef);
            let lead = i64::from(full[0]);
            let mut exp = i64::from(d.exp) + i64::from(f.bias);
            if exp > i64::from(f.emax) + i64::from(f.bias) {
                exp = i64::from(f.emax) + i64::from(f.bias); // clamp 済み前提
            }
            let _ = etop;
            if exp < 0 {
                exp = 0;
            }
            let exp = exp as u128;
            let eb = f.exp_cont_bits;
            let exp_top = (exp >> eb) & 3;
            let exp_lo = exp & ((1 << eb) - 1);
            // 組合せフィールド。
            let comb: u128 = if lead < 8 {
                (exp_top << 3) | lead as u128
            } else {
                0b11000 | (exp_top << 1) | (lead as u128 & 1)
            };
            let mut v = neg_bit | (comb << (f.bits - 6)) | (exp_lo << (f.declets() * 10));
            // 残りの係数桁をデクレットに。
            for i in 0..f.declets() {
                let c0 = u16::from(full[(1 + i * 3) as usize]);
                let c1 = u16::from(full[(2 + i * 3) as usize]);
                let c2 = u16::from(full[(3 + i * 3) as usize]);
                let dl = dpd::bcd_to_dpd((c0 << 8) | (c1 << 4) | c2);
                v |= u128::from(dl) << (10 * (f.declets() - 1 - i));
            }
            v
        }
    }
}

/// 交換形式のビット列を値に復号する。
#[must_use]
pub fn decode(f: DfpFmt, bits: u128) -> Dec {
    let neg = (bits >> (f.bits - 1)) & 1 == 1;
    let comb = ((bits >> (f.bits - 6)) & 0b11111) as u32;
    if comb == 0b11110 {
        return Dec::inf(neg);
    }
    if comb == 0b11111 {
        let sig = (bits >> (f.bits - 7)) & 1 == 1;
        // ペイロードは係数フィールドのデクレット。
        let ncoef = f.prec - 1;
        let mut coef = vec![0u8; ncoef as usize];
        for i in 0..f.declets() {
            let dl = ((bits >> (10 * (f.declets() - 1 - i))) & 0x3ff) as u16;
            let b = dpd::dpd_to_bcd(dl);
            coef[(i * 3) as usize] = (b >> 8) as u8;
            coef[(i * 3 + 1) as usize] = ((b >> 4) & 0xf) as u8;
            coef[(i * 3 + 2) as usize] = (b & 0xf) as u8;
        }
        let mut d = Dec::nan(sig);
        d.neg = neg;
        dtrim(&mut coef);
        d.coef = coef;
        return d;
    }
    // 有限値。
    let eb = f.exp_cont_bits;
    let exp_lo = (bits >> (f.declets() * 10)) & ((1 << eb) - 1);
    let (lead, exp_top): (u8, u128) = if comb >> 3 == 0b11 {
        (8 + (comb & 1) as u8, u128::from((comb >> 1) & 3))
    } else {
        ((comb & 7) as u8, u128::from((comb >> 3) & 3))
    };
    let exp = (exp_top << eb) | exp_lo;
    let mut coef = Vec::with_capacity(f.prec as usize);
    coef.push(lead);
    for i in 0..f.declets() {
        let dl = ((bits >> (10 * (f.declets() - 1 - i))) & 0x3ff) as u16;
        let b = dpd::dpd_to_bcd(dl);
        coef.push((b >> 8) as u8);
        coef.push(((b >> 4) & 0xf) as u8);
        coef.push((b & 0xf) as u8);
    }
    let mut d = Dec {
        neg,
        kind: Kind::Finite,
        coef,
        exp: (exp as i64 - i64::from(f.bias)) as i32,
    };
    dtrim(&mut d.coef);
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_print() {
        let d = Dec::parse("1.50").unwrap();
        assert_eq!(d.to_sci(), "1.50");
        let d = Dec::parse("-0.001").unwrap();
        assert_eq!(d.to_sci(), "-0.001");
        let d = Dec::parse("1E+3").unwrap();
        assert_eq!(d.to_sci(), "1E+3");
        let d = Dec::parse("12.34E-9").unwrap();
        assert_eq!(d.to_sci(), "1.234E-8");
    }

    #[test]
    fn add_basic() {
        let ctx = Ctx::DEC64;
        let a = Dec::parse("5.75").unwrap();
        let b = Dec::parse("3.3").unwrap();
        let (r, f) = a.add(&b, &ctx);
        assert_eq!(r.to_sci(), "9.05");
        assert_eq!(f, 0);
        // ddadd011
        let a = Dec::parse("0.4444444444444446").unwrap();
        let b = Dec::parse("0.5555555555555555").unwrap();
        let (r, f) = a.add(&b, &ctx);
        assert_eq!(r.to_sci(), "1.000000000000000");
        assert_eq!(f, cond::INEXACT | cond::ROUNDED);
    }

    #[test]
    fn div_basic() {
        let ctx = Ctx::DEC64;
        let (r, f) = Dec::parse("1")
            .unwrap()
            .div(&Dec::parse("3").unwrap(), &ctx);
        assert_eq!(r.to_sci(), "0.3333333333333333");
        assert_eq!(f, cond::INEXACT | cond::ROUNDED);
        let (r2, f2) = Dec::parse("2")
            .unwrap()
            .div(&Dec::parse("2").unwrap(), &ctx);
        assert_eq!(r2.to_sci(), "1");
        assert_eq!(f2, 0);
    }

    #[test]
    fn encode_roundtrip() {
        for s in ["0", "1", "-1", "1234567890123456", "1.5", "-Inf", "NaN"] {
            let d = Dec::parse(s).unwrap();
            let bits = encode(FMT_D64, &d);
            let back = decode(FMT_D64, bits);
            assert_eq!(back.to_sci(), d.to_sci(), "{s}");
        }
    }
}
