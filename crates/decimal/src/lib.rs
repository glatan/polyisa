// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 十進演算。パック十進整数と十進浮動小数点。
//!
//! 中身は確認後に実装する。ここでは型だけを提供する。

#![forbid(unsafe_code)]

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
