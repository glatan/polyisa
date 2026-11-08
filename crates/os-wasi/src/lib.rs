//! WASI パーソナリティ。仮想カーネルの上で WASI を実装する。

#![forbid(unsafe_code)]

/// 対応する版。詳細は後の段階で足す。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WasiVersion {
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder() {
        assert_eq!(WasiVersion::Unknown, WasiVersion::Unknown);
    }
}
