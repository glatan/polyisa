//! Linux パーソナリティ。仮想カーネルの上で Linux の規約を実装する。
//!
//! 番号表と構造体配置は参照資料の確認後に埋める。

#![forbid(unsafe_code)]

/// 対応するゲスト ABI の名前。表の中身は後の段階で足す。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GuestAbi {
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder() {
        assert_eq!(GuestAbi::Unknown, GuestAbi::Unknown);
    }
}
