// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 十進演算。パック十進整数と十進浮動小数点（DPD 符号化）。
//!
//! - [`bcd`] はニブルに数字を並べるパック形式と、その符号規約
//!   （`BcdEnv`）を扱う。s390 の ZAP/AP と Power の bcdadd. の
//!   規則を共通化する。
//! - [`dpd`] は 10 ビットのデクレットと BCD 3 桁を相互変換する。
//! - [`dfp`] は IEEE 754 の十進浮動小数点（decimal32/64/128）の
//!   値・文脈・演算・形式間変換を提供する。

#![forbid(unsafe_code)]

pub mod bcd;
pub mod dfp;
pub mod dpd;

/// パック十進整数。各バイトが 0〜9 の数字。符号は別に持つ。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PackedDec {
    pub digits: Vec<u8>,
    pub negative: bool,
}

impl PackedDec {
    /// 数字列から作る。0〜9 以外があれば `None`。
    #[must_use]
    pub fn from_digits(digits: &[u8], negative: bool) -> Option<Self> {
        if digits.iter().any(|&d| d > 9) {
            return None;
        }
        Some(Self {
            digits: digits.to_vec(),
            negative,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_digits() {
        assert!(PackedDec::from_digits(&[1, 10], false).is_none());
        assert!(PackedDec::from_digits(&[1, 2], true).is_some());
    }
}
