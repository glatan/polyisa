// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 仮想カーネル。ゲストプロセス、ゲストスレッド、スケジューラ。
//!
//! システムコール番号などの ABI 表は OS パーソナリティ側に置く。

#![forbid(unsafe_code)]

/// ゲストプロセスの識別子。ホストのプロセスとは対応しない。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ProcessId(pub u64);

/// ゲストスレッドの識別子。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ThreadId(pub u64);

/// ゲストプロセスの親子と終了コード。アドレス空間は呼び出し側が持つ。
#[derive(Clone, Debug, Default)]
pub struct ProcessTable {
    next: u64,
    procs: Vec<Proc>,
}

#[derive(Clone, Debug)]
struct Proc {
    id: ProcessId,
    parent: Option<ProcessId>,
    exit_code: Option<u32>,
}

/// `wait` の結果。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reap {
    /// 子は終了済みで、表から外した。
    Exited { pid: ProcessId, code: u32 },
    /// 一致する子はいるが、まだ終了していない。
    Pending,
    /// 一致する子がいない。
    NoChild,
}

impl ProcessTable {
    /// 親のないプロセス、または親を指定した子を作る。識別子は 1 から増える。
    pub fn spawn(&mut self, parent: Option<ProcessId>) -> ProcessId {
        self.next += 1;
        let id = ProcessId(self.next);
        self.procs.push(Proc {
            id,
            parent,
            exit_code: None,
        });
        id
    }

    /// `parent` の子を作る。
    pub fn fork(&mut self, parent: ProcessId) -> ProcessId {
        self.spawn(Some(parent))
    }

    /// 終了コードを記録する。既に終了していれば上書きする。
    pub fn exit(&mut self, id: ProcessId, code: u32) {
        if let Some(proc) = self.procs.iter_mut().find(|proc| proc.id == id) {
            proc.exit_code = Some(code);
        }
    }

    /// `parent` の子を回収する。`which` が -1 のときはどの子でもよい。
    /// 0 や正で一致しない識別子は子がいても `NoChild` である。
    pub fn try_reap(&mut self, parent: ProcessId, which: i64) -> Reap {
        let matches =
            |proc: &Proc| proc.parent == Some(parent) && (which == -1 || which as u64 == proc.id.0);
        if let Some(idx) = self
            .procs
            .iter()
            .position(|proc| matches(proc) && proc.exit_code.is_some())
        {
            let proc = self.procs.remove(idx);
            return Reap::Exited {
                pid: proc.id,
                code: proc.exit_code.unwrap_or(0),
            };
        }
        if self.procs.iter().any(matches) {
            Reap::Pending
        } else {
            Reap::NoChild
        }
    }
}

/// 仮想時間が最も小さい vCPU を次に実行する決定的な順序のための待ち行列。
#[derive(Debug, Default)]
pub struct Scheduler {
    ready: std::collections::VecDeque<(ThreadId, u64)>,
}

impl Scheduler {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 実行可能にする。`virtual_time` は順序の決定に使う。
    pub fn push(&mut self, tid: ThreadId, virtual_time: u64) {
        let pos = self
            .ready
            .iter()
            .position(|&(_, t)| virtual_time < t)
            .unwrap_or(self.ready.len());
        self.ready.insert(pos, (tid, virtual_time));
    }

    /// 次に実行するスレッドを取り出す。
    #[must_use]
    pub fn pop(&mut self) -> Option<ThreadId> {
        self.ready.pop_front().map(|(tid, _)| tid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smallest_time_first() {
        let mut s = Scheduler::new();
        s.push(ThreadId(1), 30);
        s.push(ThreadId(2), 10);
        s.push(ThreadId(3), 20);
        assert_eq!(s.pop(), Some(ThreadId(2)));
        assert_eq!(s.pop(), Some(ThreadId(3)));
        assert_eq!(s.pop(), Some(ThreadId(1)));
        assert_eq!(s.pop(), None);
    }

    #[test]
    fn wait_reaps_the_child_exit_code() {
        let mut table = ProcessTable::default();
        let parent = table.spawn(None);
        let child = table.fork(parent);
        assert_eq!(table.try_reap(parent, -1), Reap::Pending);
        assert_eq!(table.try_reap(parent, 99), Reap::NoChild);
        table.exit(child, 42);
        assert_eq!(
            table.try_reap(parent, child.0 as i64),
            Reap::Exited {
                pid: child,
                code: 42,
            }
        );
        assert_eq!(table.try_reap(parent, -1), Reap::NoChild);
    }
}
