// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! ビットパターン。`0`、`1`、`.`（任意）からなる。空白と `_` は無視する。
//!
//! 例：RISC-V の `add` の `0000000 ..... ..... 000 ..... 0110011`。

/// ビットパターン。長さは 1〜128 ビット。左端が最上位ビット。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Pattern {
    len: u32,
    mask: u128,
    bits: u128,
}

/// パターンの誤り。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PatternError {
    Empty,
    TooLong,
    BadChar(char),
}

impl core::fmt::Display for PatternError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => write!(f, "empty pattern"),
            Self::TooLong => write!(f, "pattern longer than 128 bits"),
            Self::BadChar(c) => write!(f, "bad pattern char {c:?}"),
        }
    }
}

impl Pattern {
    /// 文字列から作る。`0`、`1`、`.` のみを数える。
    pub fn parse(text: &str) -> Result<Self, PatternError> {
        let mut len = 0u32;
        let mut mask = 0u128;
        let mut bits = 0u128;
        for c in text.chars() {
            match c {
                '0' => {
                    len += 1;
                    mask = (mask << 1) | 1;
                    bits <<= 1;
                }
                '1' => {
                    len += 1;
                    mask = (mask << 1) | 1;
                    bits = (bits << 1) | 1;
                }
                '.' => {
                    len += 1;
                    mask <<= 1;
                    bits <<= 1;
                }
                ' ' | '\t' | '_' => {}
                other => return Err(PatternError::BadChar(other)),
            }
            if len > 128 {
                return Err(PatternError::TooLong);
            }
        }
        if len == 0 {
            return Err(PatternError::Empty);
        }
        Ok(Self { len, mask, bits })
    }

    /// ビット長。
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.len
    }

    /// 空かどうか。構文解析で空を拒むため、常に `false`。
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 固定ビットのマスク。
    #[must_use]
    pub const fn mask(&self) -> u128 {
        self.mask
    }

    /// 固定ビットの値。
    #[must_use]
    pub const fn bits(&self) -> u128 {
        self.bits
    }

    /// 命令語が一致するかどうか。下位余白は無視し、`len` ビットで比べる。
    #[must_use]
    pub const fn matches(&self, word: u128) -> bool {
        // `len == 128` の `1 << 128` を避けるため、マスク済みの比較だけにする。
        (word & self.mask) == self.bits
    }

    /// 二つのパターンに共通して一致する語があるかどうか。
    #[must_use]
    pub const fn overlaps(&self, other: &Self) -> bool {
        if self.len != other.len {
            return false;
        }
        // 両方で固定され、値が食い違う位置がなければ重なる。
        (self.bits ^ other.bits) & self.mask & other.mask == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_add() {
        let p = Pattern::parse("0000000 ..... ..... 000 ..... 0110011").unwrap();
        assert_eq!(p.len(), 32);
        assert!(p.matches(0x0020_8033));
        assert!(!p.matches(0x0020_803b));
    }

    #[test]
    fn overlap_cases() {
        let add = Pattern::parse("0000000 ..... ..... 000 ..... 0110011").unwrap();
        let sub = Pattern::parse("0100000 ..... ..... 000 ..... 0110011").unwrap();
        assert!(!add.overlaps(&sub));
        let any_r = Pattern::parse("....... ..... ..... 000 ..... 0110011").unwrap();
        assert!(add.overlaps(&any_r));
        // 長さが違うものは入口の長さ規則で分かれるため、ここでは重ならないとする。
        let c_addi = Pattern::parse("000 ............ 000 .. 001").unwrap();
        assert!(!add.overlaps(&c_addi));
    }

    #[test]
    fn bad_input() {
        assert_eq!(Pattern::parse(""), Err(PatternError::Empty));
        assert!(Pattern::parse("01x").is_err());
    }
}
