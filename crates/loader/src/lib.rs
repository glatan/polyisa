//! 実行ファイル形式の解析。配置の方針は OS パーソナリティが決める。
//!
//! 形式ごとの定数表は参照資料の確認後に埋める。ここでは種別の判定の入口だけを提供する。

#![forbid(unsafe_code)]

/// ファイルの種別。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FileKind {
    Unknown,
    Elf,
}

/// 先頭バイトから種別を推定する。詳細の解析は後の段階で足す。
#[must_use]
pub fn probe_kind(bytes: &[u8]) -> FileKind {
    // ELF の識別子などの定数は、台帳の確認後にここで扱う。
    let _ = bytes;
    FileKind::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_unknown() {
        assert_eq!(probe_kind(&[]), FileKind::Unknown);
    }
}
