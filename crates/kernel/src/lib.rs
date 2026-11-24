// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 仮想カーネル。ゲストプロセス、ゲストスレッド、スケジューラ。
//!
//! システムコール番号などの ABI 表は OS パーソナリティ側に置く。

#![forbid(unsafe_code)]

pub mod fd;

pub use fd::*;

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
    signal: Option<u32>,
    pgid: u64,
}

/// `wait` の結果。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reap {
    /// 子は終了済みで、表から外した。`signal` があるときはシグナルで死んでいる。
    Exited {
        pid: ProcessId,
        code: u32,
        signal: Option<u32>,
    },
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
            signal: None,
            pgid: id.0,
        });
        id
    }

    /// プロセスグループ。作ったときの値は自分の識別子。
    #[must_use]
    pub fn pgid(&self, id: ProcessId) -> Option<u64> {
        self.procs
            .iter()
            .find(|proc| proc.id == id)
            .map(|proc| proc.pgid)
    }

    /// グループを変える。対象がいなければ偽。
    pub fn set_pgid(&mut self, id: ProcessId, pgid: u64) -> bool {
        let Some(proc) = self.procs.iter_mut().find(|proc| proc.id == id) else {
            return false;
        };
        proc.pgid = pgid;
        true
    }

    /// 自分、または自分の子なら真。
    #[must_use]
    pub fn owns(&self, me: ProcessId, id: ProcessId) -> bool {
        self.procs
            .iter()
            .any(|proc| proc.id == id && (id == me || proc.parent == Some(me)))
    }

    /// `parent` の子を作る。
    pub fn fork(&mut self, parent: ProcessId) -> ProcessId {
        self.spawn(Some(parent))
    }

    /// 終了コードを記録する。シグナルで死んでいれば変えない。
    pub fn exit(&mut self, id: ProcessId, code: u32) {
        if let Some(proc) = self.procs.iter_mut().find(|proc| proc.id == id)
            && proc.signal.is_none()
        {
            proc.exit_code = Some(code);
        }
    }

    /// シグナルの既定動作で止める。対象がいなければ偽。
    pub fn kill(&mut self, id: ProcessId, signal: u32) -> bool {
        let Some(proc) = self.procs.iter_mut().find(|proc| proc.id == id) else {
            return false;
        };
        if proc.exit_code.is_none() && proc.signal.is_none() {
            proc.signal = Some(signal);
        }
        true
    }

    /// 親のないプロセスなら真。表にいなければ偽。
    #[must_use]
    pub fn is_root(&self, id: ProcessId) -> bool {
        self.procs
            .iter()
            .any(|proc| proc.id == id && proc.parent.is_none())
    }

    /// 親の識別子。根や表にいないときは `None`。
    #[must_use]
    pub fn parent_of(&self, id: ProcessId) -> Option<ProcessId> {
        self.procs
            .iter()
            .find(|proc| proc.id == id)
            .and_then(|proc| proc.parent)
    }

    /// `which` がこの子を待っているか。`-1` はどの子でも、`0` は親と同じグループ、
    /// 正は子の識別子、それより小さい値はプロセスグループの識別子である。
    #[must_use]
    pub fn waits_for(&self, parent: ProcessId, which: i64, child: ProcessId) -> bool {
        let parent_pgid = self.pgid(parent);
        let Some(proc) = self.procs.iter().find(|proc| proc.id == child) else {
            return false;
        };
        child_selected(parent, parent_pgid, proc, which)
    }

    /// `parent` の子を回収する。一致する子がいても終了していなければ `Pending`。
    pub fn try_reap(&mut self, parent: ProcessId, which: i64) -> Reap {
        let parent_pgid = self.pgid(parent);
        let matches = |proc: &Proc| child_selected(parent, parent_pgid, proc, which);
        if let Some(idx) = self
            .procs
            .iter()
            .position(|proc| matches(proc) && (proc.exit_code.is_some() || proc.signal.is_some()))
        {
            let proc = self.procs.remove(idx);
            return Reap::Exited {
                pid: proc.id,
                code: proc.exit_code.unwrap_or(0),
                signal: proc.signal,
            };
        }
        if self.procs.iter().any(matches) {
            Reap::Pending
        } else {
            Reap::NoChild
        }
    }
}

fn child_selected(parent: ProcessId, parent_pgid: Option<u64>, proc: &Proc, which: i64) -> bool {
    if proc.parent != Some(parent) {
        return false;
    }
    if which == -1 {
        return true;
    }
    if which > 0 {
        return which as u64 == proc.id.0;
    }
    if which == 0 {
        return parent_pgid == Some(proc.pgid);
    }
    proc.pgid == which.unsigned_abs()
}

/// ゲストスレッドが待っている理由。アドレス空間は呼び出し側が持つ。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ThreadWait {
    /// `wait`。`which` が -1 のときはどの子でもよい。
    Child { which: i64 },
    /// 空のパイプの読み。
    Pipe { id: u64 },
}

#[derive(Debug)]
struct GThread {
    id: ThreadId,
    steps: u64,
    wait: Option<ThreadWait>,
    exited: bool,
}

/// タイミングが無効のときのスケジューラ。ステップ数が最も少ない実行可能なスレッドを選ぶ。
#[derive(Debug, Default)]
pub struct GuestScheduler {
    threads: Vec<GThread>,
}

impl GuestScheduler {
    /// いなければステップ数 0 で加える。既にあれば変えない。
    pub fn insert(&mut self, id: ThreadId) {
        if self.threads.iter().any(|thread| thread.id == id) {
            return;
        }
        self.threads.push(GThread {
            id,
            steps: 0,
            wait: None,
            exited: false,
        });
    }

    /// `to` のステップ数を `from` に合わせる。fork 直後に親が子より先に進むため。
    pub fn copy_steps(&mut self, from: ThreadId, to: ThreadId) {
        let steps = self.steps_of(from);
        if let Some(thread) = self.threads.iter_mut().find(|thread| thread.id == to) {
            thread.steps = steps;
        }
    }

    /// 1 ステップ足して、足したあとの値を返す。
    pub fn add_step(&mut self, id: ThreadId) -> u64 {
        self.insert(id);
        let Some(thread) = self.threads.iter_mut().find(|thread| thread.id == id) else {
            return 0;
        };
        thread.steps += 1;
        thread.steps
    }

    pub fn block(&mut self, id: ThreadId, wait: ThreadWait) {
        if let Some(thread) = self.threads.iter_mut().find(|thread| thread.id == id) {
            thread.wait = Some(wait);
        }
    }

    pub fn unblock(&mut self, id: ThreadId) {
        if let Some(thread) = self.threads.iter_mut().find(|thread| thread.id == id) {
            thread.wait = None;
        }
    }

    /// そのパイプを待っているスレッドを実行可能に戻す。
    pub fn unblock_pipe(&mut self, id: u64) {
        for thread in &mut self.threads {
            if matches!(thread.wait, Some(ThreadWait::Pipe { id: waiting }) if waiting == id) {
                thread.wait = None;
            }
        }
    }

    pub fn mark_exited(&mut self, id: ThreadId) {
        if let Some(thread) = self.threads.iter_mut().find(|thread| thread.id == id) {
            thread.exited = true;
            thread.wait = None;
        }
    }

    #[must_use]
    pub fn is_exited(&self, id: ThreadId) -> bool {
        self.threads
            .iter()
            .any(|thread| thread.id == id && thread.exited)
    }

    /// 待ちに入っているスレッド。実行を止めるときに報告する。
    #[must_use]
    pub fn blocked(&self) -> Vec<(ThreadId, ThreadWait)> {
        self.threads
            .iter()
            .filter_map(|thread| thread.wait.map(|wait| (thread.id, wait)))
            .collect()
    }

    /// `current` の代わりに走らせるスレッド。`current` を続けるなら `None`。
    #[must_use]
    pub fn next(&self, current: ThreadId) -> Option<ThreadId> {
        let me = self.threads.iter().find(|thread| thread.id == current)?;
        let best = self.least_runnable()?;
        if !me.exited && me.wait.is_none() {
            if best != current && self.steps_of(best) < me.steps {
                Some(best)
            } else {
                None
            }
        } else if best == current {
            None
        } else {
            Some(best)
        }
    }

    /// 終了しておらず、待ってもいないスレッドのうち、ステップ数が最小のもの。
    #[must_use]
    pub fn least_runnable(&self) -> Option<ThreadId> {
        self.threads
            .iter()
            .filter(|thread| !thread.exited && thread.wait.is_none())
            .min_by_key(|thread| (thread.steps, thread.id.0))
            .map(|thread| thread.id)
    }

    fn steps_of(&self, id: ThreadId) -> u64 {
        self.threads
            .iter()
            .find(|thread| thread.id == id)
            .map(|thread| thread.steps)
            .unwrap_or(0)
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
        assert!(table.is_root(parent));
        assert!(!table.is_root(child));
        table.exit(child, 42);
        assert_eq!(
            table.try_reap(parent, child.0 as i64),
            Reap::Exited {
                pid: child,
                code: 42,
                signal: None,
            }
        );
        assert_eq!(table.try_reap(parent, -1), Reap::NoChild);
    }

    #[test]
    fn fewer_steps_run_before_a_longer_thread() {
        let mut sched = GuestScheduler::default();
        sched.insert(ThreadId(1));
        sched.insert(ThreadId(2));
        for _ in 0..5 {
            sched.add_step(ThreadId(1));
        }
        assert_eq!(sched.next(ThreadId(1)), Some(ThreadId(2)));
        sched.block(ThreadId(2), ThreadWait::Child { which: -1 });
        assert_eq!(sched.next(ThreadId(1)), None);
        sched.mark_exited(ThreadId(1));
        assert_eq!(sched.least_runnable(), None);
        sched.unblock(ThreadId(2));
        assert_eq!(sched.least_runnable(), Some(ThreadId(2)));
    }

    #[test]
    fn pipe_read_waits_until_write_and_eof_when_writer_closes() {
        let mut pipes = PipeTable::default();
        let id = pipes.open();
        assert_eq!(pipes.read(id, 4), PipeRead::Empty);
        assert_eq!(pipes.write(id, b"ab"), Some(2));
        assert_eq!(pipes.read(id, 1), PipeRead::Bytes(b"a".to_vec()));
        pipes.close(id, false);
        assert_eq!(pipes.read(id, 4), PipeRead::Bytes(b"b".to_vec()));
        assert_eq!(pipes.read(id, 4), PipeRead::Eof);
        pipes.close(id, true);
        assert_eq!(pipes.write(id, b"z"), None);
    }

    #[test]
    fn process_group_starts_as_own_pid() {
        let mut table = ProcessTable::default();
        let parent = table.spawn(None);
        let child = table.fork(parent);
        assert_eq!(table.pgid(parent), Some(parent.0));
        assert_eq!(table.pgid(child), Some(child.0));
        assert!(table.owns(parent, child));
        assert!(table.set_pgid(child, parent.0));
        assert_eq!(table.pgid(child), Some(parent.0));
        assert!(!table.set_pgid(ProcessId(99), 1));
        assert!(!table.owns(parent, ProcessId(99)));
    }

    #[test]
    fn wait_selects_a_process_group() {
        let mut table = ProcessTable::default();
        let parent = table.spawn(None);
        let child = table.fork(parent);
        let other = table.fork(parent);
        assert_eq!(table.try_reap(parent, 0), Reap::NoChild);
        assert_eq!(table.try_reap(parent, -(other.0 as i64)), Reap::Pending);
        assert!(table.set_pgid(child, parent.0));
        assert_eq!(table.try_reap(parent, 0), Reap::Pending);
        table.exit(child, 7);
        assert_eq!(
            table.try_reap(parent, 0),
            Reap::Exited {
                pid: child,
                code: 7,
                signal: None,
            }
        );
        table.exit(other, 1);
        assert_eq!(
            table.try_reap(parent, -(other.0 as i64)),
            Reap::Exited {
                pid: other,
                code: 1,
                signal: None,
            }
        );
    }

    #[test]
    fn kill_reaps_as_a_signal() {
        let mut table = ProcessTable::default();
        let parent = table.spawn(None);
        let child = table.fork(parent);
        assert!(table.kill(child, 9));
        assert_eq!(
            table.try_reap(parent, -1),
            Reap::Exited {
                pid: child,
                code: 0,
                signal: Some(9),
            }
        );
    }
}
