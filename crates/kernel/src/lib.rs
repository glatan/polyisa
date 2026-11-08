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
}
