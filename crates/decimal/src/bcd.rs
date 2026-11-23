// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! パック十進整数（BCD）の演算と符号化。
//!
//! 数字列は最上位桁から並ぶ `Vec<u8>` で、各要素は 0〜9。
//! 符号の規約は `BcdEnv` が運ぶ（優先符号・受理符号・符号なし形式）。
//! s390 系の ZAP/AP と Power の bcdadd. が必要とする規則をここで共通化する。
// Ref: SPEC-S390-ZARCH-POP (十進演算), SPEC-POWER-ISA (bcdadd.).

use crate::PackedDec;

/// パック十進の符号規約（環境）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BcdEnv {
    /// 結果に書く正の符号コード（下位ニブル）。
    pub plus: u8,
    /// 結果に書く負の符号コード。
    pub minus: u8,
    /// 正として受理する符号ニブルのビット集合（bit n がニブル値 n を許す）。
    pub accept_plus: u16,
    /// 負として受理する符号ニブルのビット集合。
    pub accept_minus: u16,
    /// 真なら最終バイトの下位ニブルも数字とする（符号なし形式。
    /// Power の bcdadd. PS=1 が使う）。
    pub unsigned: bool,
}

impl BcdEnv {
    /// s390 系と Power（PS=0）の符号つきパック形式の規約。
    /// 受理する正符号は 0xA/0xC/0xE/0xF、負符号は 0xB/0xD。
    /// 優先符号は 0xC と 0xD。
    #[must_use]
    pub const fn s390() -> Self {
        Self {
            plus: 0xc,
            minus: 0xd,
            accept_plus: (1 << 0xa) | (1 << 0xc) | (1 << 0xe) | (1 << 0xf),
            accept_minus: (1 << 0xb) | (1 << 0xd),
            unsigned: false,
        }
    }

    /// VAX パック十進の符号規約。受理する正符号は 0xA/0xC/0xE/0xF、
    /// 負符号は 0xB/0xD、優先符号は 0xC/0xD —— s390 と同じ集合。
    /// Ref: SPEC-VAX-ARM（十進文字列の符号表）.
    #[must_use]
    pub const fn vax() -> Self {
        Self::s390()
    }

    /// 符号なし形式。全ニブルが数字で、結果の符号ニブルは 0xF。
    #[must_use]
    pub const fn unsigned() -> Self {
        Self {
            plus: 0xf,
            minus: 0xf,
            accept_plus: 0xffff,
            accept_minus: 0,
            unsigned: true,
        }
    }
}

/// パック十進の誤り。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BcdErr {
    /// 数字でないニブル（または符号ニブルの位置の誤り）。
    InvalidDigit,
    /// 符号ニブルが受理集合にない。
    InvalidSign,
    /// 出力領域に結果が収まらない。
    Overflow,
    /// 0 除算。
    DivZero,
}

/// パック十進バイト列を復号する。`bytes` の各バイトは 2 ニブル。
/// `unsigned` の環境では最終バイトの下位ニブルも数字。
/// 符号ニブルの有無は環境で決まる。数字ニブルが 10 以上なら `InvalidDigit`、
/// 符号ニブルが受理集合にないなら `InvalidSign`。
pub fn from_packed(bytes: &[u8], env: BcdEnv) -> Result<PackedDec, BcdErr> {
    let mut digits = Vec::with_capacity(bytes.len() * 2);
    let n = bytes.len();
    for (i, &b) in bytes.iter().enumerate() {
        let hi = b >> 4;
        let lo = b & 0xf;
        if hi > 9 {
            return Err(BcdErr::InvalidDigit);
        }
        digits.push(hi);
        if i == n - 1 && !env.unsigned {
            // 符号ニブル。
            if env.accept_plus >> lo & 1 == 1 {
                return Ok(PackedDec::from_digits(&digits, false).unwrap());
            }
            if env.accept_minus >> lo & 1 == 1 {
                return Ok(PackedDec::from_digits(&digits, true).unwrap());
            }
            return Err(BcdErr::InvalidSign);
        }
        if lo > 9 {
            return Err(BcdErr::InvalidDigit);
        }
        digits.push(lo);
    }
    if bytes.is_empty() {
        return Ok(PackedDec::from_digits(&[0], false).unwrap());
    }
    if env.unsigned {
        return Ok(PackedDec::from_digits(&digits, false).unwrap());
    }
    // 最終バイトを符号として処理済みなのでここには来ない。
    unreachable!()
}

/// `PackedDec` をパック十進バイト列に符号化する。
/// `out` の長さがちょうど結果のバイト数（数字 2 個 + 符号で奇数揃え）。
/// 数字が収まらなければ `Overflow`。
pub fn to_packed(v: &PackedDec, env: BcdEnv, out: &mut [u8]) -> Result<(), BcdErr> {
    let cap = if env.unsigned {
        out.len() * 2
    } else {
        out.len() * 2 - 1
    };
    if v.digits.len() > cap {
        return Err(BcdErr::Overflow);
    }
    let sign = if env.unsigned {
        env.plus
    } else if v.negative {
        env.minus
    } else {
        env.plus
    };
    // 数字を右詰めで並べ、先頭の空きニブルは 0 埋め。
    for b in out.iter_mut() {
        *b = 0;
    }
    let total_nibbles = out.len() * 2;
    // 最後の数字位置。符号つきは最終ニブルが符号なので 1 つ手前。
    let anchor = if env.unsigned {
        total_nibbles - 1
    } else {
        total_nibbles - 2
    };
    for (k, &d) in v.digits.iter().enumerate() {
        if d > 9 {
            return Err(BcdErr::InvalidDigit);
        }
        let pos = anchor - (v.digits.len() - 1 - k);
        let byte = pos / 2;
        if pos.is_multiple_of(2) {
            out[byte] |= d << 4;
        } else {
            out[byte] |= d;
        }
    }
    if !env.unsigned {
        let last = out.len() - 1;
        out[last] = (out[last] & 0xf0) | sign;
    }
    Ok(())
}

// ---- 数字列の演算（PackedDec の内部実装に使う） ----

/// 数字列を正規化する（先頭の 0 を除く。全 0 なら 1 桁の 0）。
fn norm(d: &mut Vec<u8>) {
    if d.is_empty() {
        d.push(0);
        return;
    }
    let first = d.iter().position(|&x| x != 0).unwrap_or(d.len() - 1);
    d.drain(0..first);
}

/// 桁数（先頭 0 を除いた実効桁数）。
fn len(d: &[u8]) -> usize {
    let first = d.iter().position(|&x| x != 0).unwrap_or(d.len());
    d.len() - first
}

/// 絶対値の比較。
fn abs_cmp(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    let (la, lb) = (len(a), len(b));
    match la.cmp(&lb) {
        core::cmp::Ordering::Equal => a[a.len() - la..].cmp(&b[b.len() - lb..]),
        o => o,
    }
}

/// 絶対値の加算。`a` の桁数に `b` を寄せて足す。結果は `a.len()+1` 桁まで。
fn abs_add(a: &[u8], b: &[u8]) -> Vec<u8> {
    let n = a.len().max(b.len()) + 1;
    let mut out = vec![0u8; n];
    let mut c = 0u8;
    for i in 0..n - 1 {
        let da = if i < a.len() { a[a.len() - 1 - i] } else { 0 };
        let db = if i < b.len() { b[b.len() - 1 - i] } else { 0 };
        let s = da + db + c;
        out[n - 1 - i] = s % 10;
        c = s / 10;
    }
    out[0] = c;
    out
}

/// 絶対値の減算（a >= b を要求）。
fn abs_sub(a: &[u8], b: &[u8]) -> Vec<u8> {
    let n = a.len();
    let mut out = vec![0u8; n];
    let mut borrow = 0i8;
    for i in 0..n {
        let da = a[n - 1 - i] as i8;
        let db = if i < b.len() { b[b.len() - 1 - i] } else { 0 } as i8;
        let mut d = da - db - borrow;
        if d < 0 {
            d += 10;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out[n - 1 - i] = d as u8;
    }
    debug_assert!(borrow == 0);
    out
}

impl PackedDec {
    /// 加算。`a + b`（符号つき）。結果の 0 の符号は正（負+負のみ負）。
    #[must_use]
    pub fn add(&self, other: &Self) -> Self {
        let (a, b) = (self, other);
        let (digits, negative) = if a.negative == b.negative {
            (abs_add(&a.digits, &b.digits), a.negative)
        } else {
            match abs_cmp(&a.digits, &b.digits) {
                core::cmp::Ordering::Equal => (vec![0], false),
                core::cmp::Ordering::Greater => (abs_sub(&a.digits, &b.digits), a.negative),
                core::cmp::Ordering::Less => (abs_sub(&b.digits, &a.digits), b.negative),
            }
        };
        let mut d = digits;
        norm(&mut d);
        let negative = negative && !(d.len() == 1 && d[0] == 0);
        Self {
            digits: d,
            negative,
        }
    }

    /// 減算。`a - b`。
    #[must_use]
    pub fn sub(&self, other: &Self) -> Self {
        let mut b = other.clone();
        b.negative = !b.negative;
        self.add(&b)
    }

    /// 乗算。桁数は `a.len()+b.len()` まで。
    #[must_use]
    pub fn mul(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::from_digits(&[0], false).unwrap();
        }
        let (a, b) = (&self.digits, &other.digits);
        let mut out = vec![0u8; a.len() + b.len()];
        for (i, &da) in a.iter().enumerate().rev() {
            let mut c = 0u8;
            for (j, &db) in b.iter().enumerate().rev() {
                let pos = i + j + 1;
                let s = out[pos] + da * db + c;
                out[pos] = s % 10;
                c = s / 10;
            }
            out[i] += c;
        }
        norm(&mut out);
        Self {
            digits: out,
            negative: self.negative ^ other.negative,
        }
    }

    /// 除算の商と余り（切り捨て。`a / b`、`a % b`）。0 除算は `DivZero`。
    pub fn divmod(&self, other: &Self) -> Result<(Self, Self), BcdErr> {
        if other.is_zero() {
            return Err(BcdErr::DivZero);
        }
        let (a, b) = (&self.digits, &other.digits);
        if abs_cmp(a, b) == core::cmp::Ordering::Less {
            return Ok((
                Self::from_digits(&[0], false).unwrap(),
                Self::from_digits(a, self.negative).unwrap(),
            ));
        }
        // 筆算。被除数を 1 桁ずつ降ろす。
        let mut q = vec![0u8; a.len()];
        let mut rem: Vec<u8> = vec![0];
        let mut qi = 0;
        let mut started = false;
        for (i, &dig) in a.iter().enumerate() {
            rem.push(dig);
            norm(&mut rem);
            let mut d = 0u8;
            while abs_cmp(&rem, b) != core::cmp::Ordering::Less {
                rem = abs_sub(&rem, b);
                d += 1;
            }
            if d != 0 || started {
                q[qi] = d;
                qi += 1;
                started = true;
            }
            let _ = i;
        }
        if !started {
            q[0] = 0;
            qi = 1;
        }
        q.truncate(qi);
        let q = Self::from_digits(&q, self.negative ^ other.negative).unwrap();
        let mut r = rem;
        norm(&mut r);
        let r = Self::from_digits(&r, self.negative).unwrap();
        Ok((q, r))
    }

    /// 比較（符号込み）。
    #[must_use]
    #[allow(clippy::should_implement_trait)]
    pub fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        match (self.negative, other.negative) {
            (false, true) => {
                if self.is_zero() && other.is_zero() {
                    core::cmp::Ordering::Equal
                } else {
                    core::cmp::Ordering::Greater
                }
            }
            (true, false) => {
                if self.is_zero() && other.is_zero() {
                    core::cmp::Ordering::Equal
                } else {
                    core::cmp::Ordering::Less
                }
            }
            (false, false) => abs_cmp(&self.digits, &other.digits),
            (true, true) => abs_cmp(&other.digits, &self.digits),
        }
    }

    /// 0 かどうか。
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.digits.iter().all(|&d| d == 0)
    }

    /// 先頭 0 を除いた桁数。
    #[must_use]
    pub fn digit_len(&self) -> usize {
        len(&self.digits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pd(ds: &[u8], neg: bool) -> PackedDec {
        PackedDec::from_digits(ds, neg).unwrap()
    }

    #[test]
    fn packed_roundtrip() {
        let v = pd(&[1, 2, 3, 4, 5], true);
        let mut out = [0u8; 3];
        to_packed(&v, BcdEnv::s390(), &mut out).unwrap();
        assert_eq!(out, [0x12, 0x34, 0x5d]);
        let back = from_packed(&out, BcdEnv::s390()).unwrap();
        assert_eq!(back.digits, vec![1, 2, 3, 4, 5]);
        assert!(back.negative);
    }

    #[test]
    fn packed_unsigned() {
        let v = pd(&[9, 9, 9, 9], false);
        let mut out = [0u8; 2];
        to_packed(&v, BcdEnv::unsigned(), &mut out).unwrap();
        assert_eq!(out, [0x99, 0x99]);
        let back = from_packed(&out, BcdEnv::unsigned()).unwrap();
        assert_eq!(back.digits, vec![9, 9, 9, 9]);
    }

    #[test]
    fn bad_digits() {
        assert_eq!(
            from_packed(&[0x1a, 0x2c], BcdEnv::s390()),
            Err(BcdErr::InvalidDigit)
        );
        assert_eq!(
            from_packed(&[0x12, 0x39], BcdEnv::s390()),
            Err(BcdErr::InvalidSign)
        );
    }

    #[test]
    fn arith() {
        let a = pd(&[1, 2, 3], false);
        let b = pd(&[4, 5, 6], false);
        assert_eq!(a.add(&b).digits, vec![5, 7, 9]);
        assert_eq!(b.sub(&a).digits, vec![3, 3, 3]);
        assert_eq!(a.mul(&b).digits, vec![5, 6, 0, 8, 8]);
        let (q, r) = b.divmod(&a).unwrap();
        assert_eq!(q.digits, vec![3]);
        assert_eq!(r.digits, vec![8, 7]);
        // 符号。
        let na = pd(&[5], true);
        let p = pd(&[3], false);
        assert_eq!(na.add(&p).digits, vec![2]);
        assert!(na.add(&p).negative);
        // -0 は正に正規化する。
        let z = na.add(&pd(&[5], false));
        assert_eq!(z.digits, vec![0]);
        assert!(!z.negative);
    }
}
