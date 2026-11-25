// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
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

/// `InsnTrace` に渡す命令名の関数。env（ゲストメモリ）と pc から
/// 名前を引く。env を渡すのは、呼び出し側が命令語を読んで
/// 逆アセンブルするため。
pub type InsnName<'a> = dyn FnMut(&mut polyisa_engine::bare::BareEnv, u64) -> String + 'a;

/// 命令トレース。エンジンの観測点として、実行したステップを 1 行ずつ
/// `lines` に積む。命令名は `engine` がゲスト ISA を知らないので、
/// env（ゲストメモリ）と pc から名前を引く関数を構築時に呼び出し側が
/// 渡す。`pre_step` で pc を退避し、実行が確定する `post_step` で
/// 名前を取って行を積む（未実行の pc は記録しない）。
pub struct InsnTrace<'a> {
    name: Box<InsnName<'a>>,
    pending: Option<u64>,
    lines: Vec<String>,
}

impl<'a> InsnTrace<'a> {
    #[must_use]
    pub fn new(name: impl FnMut(&mut polyisa_engine::bare::BareEnv, u64) -> String + 'a) -> Self {
        Self {
            name: Box::new(name),
            pending: None,
            lines: Vec::new(),
        }
    }

    /// 記録した行。
    #[must_use]
    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    /// 記録した行を取り出し、内部を空にする。
    pub fn take(&mut self) -> Vec<String> {
        std::mem::take(&mut self.lines)
    }

    /// 記録した行を所有権ごと取り出す。
    #[must_use]
    pub fn into_lines(self) -> Vec<String> {
        self.lines
    }
}

impl polyisa_engine::obs::Observer for InsnTrace<'_> {
    fn pre_step(&mut self, _env: &mut polyisa_engine::bare::BareEnv, pc: u64) {
        self.pending = Some(pc);
    }

    fn post_step(&mut self, env: &mut polyisa_engine::bare::BareEnv, _pc: u64) {
        let Some(pc) = self.pending.take() else {
            return;
        };
        let name = (self.name)(env, pc);
        self.lines.push(format_step(pc, &name).line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_engine::bare::BareEnv;
    use polyisa_engine::obs::Observer;

    #[test]
    fn line_format() {
        assert_eq!(format_step(0x1000, "add").line, "0x1000: add");
    }

    #[test]
    fn syscall_format() {
        assert_eq!(format_syscall(64, "write").line, "syscall 64 (write)");
    }

    #[test]
    fn insn_trace_records_executed_steps() {
        let mut env = BareEnv::new(8);
        let mut t = InsnTrace::new(|_env, pc| format!("insn@{pc:x}"));
        t.pre_step(&mut env, 0x1000);
        t.post_step(&mut env, 0x1004);
        t.pre_step(&mut env, 0x1004);
        t.post_step(&mut env, 0x1008);
        assert_eq!(t.lines(), ["0x1000: insn@1000", "0x1004: insn@1004"]);
        let taken = t.take();
        assert_eq!(taken.len(), 2);
        assert!(t.lines().is_empty());
        assert_eq!(t.into_lines(), Vec::<String>::new());
    }

    #[test]
    fn insn_trace_skips_unexecuted_step() {
        // pre のあと post が来ない pc（ブレークポイント停止・退出）は記録しない。
        let mut env = BareEnv::new(8);
        let mut t = InsnTrace::new(|_env, pc| format!("{pc:x}"));
        t.pre_step(&mut env, 0x1000);
        t.post_step(&mut env, 0x1004);
        t.pre_step(&mut env, 0x1004);
        assert_eq!(t.lines(), ["0x1000: 1000"]);
    }

    #[test]
    fn insn_trace_is_observer() {
        fn check(_: &mut impl Observer) {}
        let mut t = InsnTrace::new(|_env, pc| format!("{pc:x}"));
        check(&mut t);
        check(&mut polyisa_engine::obs::NoObserver);
    }
}
