// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 実行ファイル形式の解析。配置の方針は OS パーソナリティが決める。
//!
//! ELF の定数と配置は SPEC-ELF-GABI の確認済みの版に基づく（`// Ref:` は `elf` にある）。

#![forbid(unsafe_code)]

pub mod aout;
pub mod elf;

use elf::MAGIC;

/// ファイルの種別。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FileKind {
    Unknown,
    Elf,
    /// a.out。対象機種は magic だけでは分からない —— 呼び出し側が
    /// 別の手がかり（`--cpu` のファミリなど）で `aout::Arch` を決める。
    Aout,
}

/// 先頭バイトから種別を推定する。ELF の識別子に一致すれば `Elf`、
/// a.out の magic に一致すれば `Aout` とする。
#[must_use]
pub fn probe_kind(bytes: &[u8]) -> FileKind {
    if bytes.len() >= MAGIC.len() && bytes[0..MAGIC.len()] == MAGIC {
        FileKind::Elf
    } else if aout::probe_magic(bytes).is_some() {
        FileKind::Aout
    } else {
        FileKind::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_unknown() {
        assert_eq!(probe_kind(&[]), FileKind::Unknown);
    }

    #[test]
    fn magic_is_elf() {
        let mut bytes = [0u8; 8];
        bytes[0..4].copy_from_slice(&MAGIC);
        assert_eq!(probe_kind(&bytes), FileKind::Elf);
    }

    #[test]
    fn aout_magic_is_aout() {
        let bytes = aout::NMAGIC.to_le_bytes();
        assert_eq!(probe_kind(&bytes), FileKind::Aout);
    }
}
