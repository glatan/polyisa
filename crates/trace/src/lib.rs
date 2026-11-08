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

/// 行を組み立てる。決定性のため16進小文字・固定書式とする。
#[must_use]
pub fn format_step(pc: u64, name: &str) -> Record {
    Record::new(&format!("{pc:#x}: {name}"))
}

/// システムコールの記録行を組み立てる。番号は10進で書く。
#[must_use]
pub fn format_syscall(nr: u64, name: &str) -> Record {
    Record::new(&format!("syscall {nr} ({name})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_format() {
        assert_eq!(format_step(0x1000, "add").line, "0x1000: add");
    }

    #[test]
    fn syscall_format() {
        assert_eq!(format_syscall(64, "write").line, "syscall 64 (write)");
    }
}
