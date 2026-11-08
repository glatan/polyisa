//! 命令トレースとシステムコールトレースの記録形式と出力。

#![forbid(unsafe_code)]

/// 1 件の記録。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Record {
    /// 固定書式の行。
    pub line: String,
}

impl Record {
    #[must_use]
    pub fn new(line: &str) -> Self {
        Self {
            line: line.to_string(),
        }
    }
}

/// 行を組み立てる。書式の確定は観測の実装時に行う。
#[must_use]
pub fn format_step(pc: u64, name: &str) -> Record {
    Record::new(&format!("{pc:#x}: {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_format() {
        assert_eq!(format_step(0x1000, "add").line, "0x1000: add");
    }
}
