// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! x86 Linux の syscall 処理全体。ゲスト状態機械とプロセス/スケジューラ統合を
//! `kernel` の抽象の上に組み立て、`cli` の `run` ループから SYSCALL/INT 0x80
//! トラップを委譲される。

use super::*;
use crate::{TrapHandler, TrapOutcome};
use polyisa_engine::bare::BareEnv;
use polyisa_guest_x86::sem::Gpr;
use polyisa_mem::VirtAddr;

/// Linux の syscall 処理全体。`cli` の `run` ループからopenat/read/write/close と
/// exit/exit_group をホストに直結して受け、ほかは未対応として報告する。
/// x86-32（`is64=false`）と x86-64（`is64=true`）で番号表と引数レジスタが変わる。
/// x86-64 の引数は RDI/RSI/RDX（Gpr 7/6/2）、番号は RAX（Gpr 0）にある。
///
/// 試作の合意事項：仮想カーネル・VFS・ゲストルートの適用は後の段階である。
/// ここではホストのファイルに直接触る（裸実行の延長）。パスの隔離はしないので、
/// 信頼できないゲストバイナリには使わないこと。絶対パスはホストのパスとして開き、
/// 相対パスはプロセスの作業ディレクトリから開く。1 回の転送は 64 KiB ずつに区切る。
#[derive(Default)]
pub struct Linux {
    reported: Vec<u64>,
    /// 開いたファイルの表（ゲスト fd 3 以降）。仮想カーネルの fd 管理を使う.
    fds: polyisa_kernel::FdTable,
    /// 標準 fd (0/1/2) の付け替え先。close 後に open した対象が入る.
    /// uniq のように stdin をファイルに付け替える applet のため.
    /// ファイル・パイプ端・ソケットなどあらゆる対象を保持する.
    std_targets: [Option<polyisa_kernel::FdTarget>; 3],
    /// dup2(0,n) 後。n からの read は stdin_buf、write は EBADF。
    /// 標準入力は開ファイルを持たないため、付け替え先として覚える.
    std_is_stdin: [bool; 3],
    /// 標準 fd の閉鎖状態。初期 (stdio 接続) は false。close で true になる.
    std_closed: [bool; 3],
    /// ファイル作成マスク。umask で更新する。初期値は 022.
    umask: u32,
    /// personality。初期値は PER_LINUX (0)。実行形式は変えない。
    personality: u64,
    /// ioprio_set で覚えた値。未設定のときは best-effort 4 を返す。
    ioprio: u32,
    ioprio_known: bool,
    is64: bool,
    /// x32 ABI（ILP32）。`is64` と併置: 引数レジスタは 64ビット、
    /// `long`/ポインタを含む構造体は 32ビット幅になる。
    x32: bool,
    /// プログラムブレーク（ヒープ末尾）。0 は未初期化。
    /// `run_image_x86_64` がロード後に像末尾へ進める。
    heap_end: u64,
    /// 匿名 mmap の割り当て基底。0 は未初期化。
    /// brk のヒープとは別の高アドレス領域から昇順に取る（実 Linux で
    /// ヒープと mmap 領域が別空間なのと同じ分離）。heap_end と共有すると
    /// brk の縮小で割り当て起点がヒープ内に戻り、領域が交差する。
    mmap_base: u64,
    /// robust futex リスト先頭。set_robust_list で記録する。
    /// 終了時の書き戻しは未対応のため、値の保持のみ行う。
    robust_head: u64,
    /// rseq 領域先頭。rseq で記録する。終了時の書き戻しは未対応.
    rseq_addr: u64,
    /// ゲスト実行ファイルのホストパス。/proc/self/exe の readlinkat に答える.
    pub exe_path: String,
    /// getdents64 で最後まで読んだ fd。次の呼び出しは 0 (EOF) を返す.
    dir_done: Vec<u32>,
    /// getdents64 の続き。fd と、次に返す名前の添字。
    dir_pos: Vec<(u32, usize)>,
    /// 標準 fd に付け替えたファイルのホストパス。
    std_paths: [Option<String>; 3],
    /// Some のとき、fd 1 の出力をここへ溜める。None のときはホストの stdout。
    /// fork した子と親で同じバッファを使う。
    pub capture_out: Option<std::rc::Rc<std::cell::RefCell<Vec<u8>>>>,
    /// dup2(2,1) 後。fd 1 への write を stderr に流す（time の集計など）。
    stdout_is_stderr: bool,
    /// dup2(1,2) 後。fd 2 への write を fd 1（capture）に流す。
    stderr_is_stdout: bool,
    /// 真の stdin へ供給するバイト。空なら空読み（端末は奪わない）。
    pub stdin_buf: Vec<u8>,
    /// `stdin_buf` の次に読む位置。
    stdin_pos: usize,
    /// シグナルハンドラの表（添字はシグナル番号-1）。空は全て
    /// SIG_DFL。i386 では配送はしないが設定の保持は共通。
    sigacts: Vec<crate::x86::SigAct>,
    /// ブロック中のシグナルのビット集合。
    sig_mask: u64,
    /// 保留中のシグナルのビット集合。配送は `after_step` で行う。
    sig_pending: u64,
    /// 代替シグナルスタック（task の sas_ss_*）。
    sigaltstack: crate::x86::SigAltStack,
    /// ゲストプロセス表。fork した子と共有する。
    procs: std::rc::Rc<std::cell::RefCell<polyisa_kernel::ProcessTable>>,
    /// 0 は未登録。最初のシステムコールか命令で 1 から採番する。
    pid: u64,
    /// このスレッドが実行した命令数。選択の正は `queue` のスケジューラ。
    steps: u64,
    /// `wait4` で待っているときの引数。
    wait: Option<WaitSlot>,
    /// 自分以外のスレッド。スケジューラと環境を共有する。
    queue: SharedQueue,
    /// 空のパイプを読もうとして待っているパイプ。
    pipe_wait: Option<u64>,
    /// fd 準備待ち（ソケット・待ち合わせ系）の中身。
    fd_wait: Option<crate::sock::Wait>,
    /// 解けたばかりの fd 待ち。解除時に退避し、起きて再実行された
    /// syscall へ `prev` として渡す（期限切れ起きの判定用）。
    fd_wait_prev: Option<crate::sock::Wait>,
    /// HostIo 作業スレッド。プロセス系で共有し、初使用で起動する。
    host_io: SharedHostIo,
    /// このプロセスの作業ディレクトリ。空はまだホストの作業ディレクトリを写していない。
    /// 当面ホスト表記のまま持つ。guest_root 設定時はゲスト表記への見直しが要る (follow-up)。
    pub cwd: String,
    /// ゲストのルート。空は隔離なし（従来動作）。WP1 で導入し、設定手段は後の段階で足す。
    /// root 設定時は /proc 合成の比較や exe リダイレクトも解決前後で見直す (follow-up)。
    guest_root: String,
    /// MONOTONIC 時計の起点。ゲスト実行ごとに取り直す。fork した子は親と共有する。
    /// makemime は srand(monotonic_us()) で境界を作るため、起点の共有は出力を揺らす.
    mono_start: Option<std::time::Instant>,
    /// fd 待ちの単調時計起点。初使用で張る。時刻報告（`mono_start`）
    /// とは別系統で、最初の clock_gettime が来る前の待ちにも動く。
    wait_start: std::cell::OnceCell<std::time::Instant>,
}

/// `wait4` を完了するときに使う引数。
struct WaitSlot {
    which: i64,
    status_ptr: u64,
}

/// 今は走っていないスレッドの実行環境。
struct ParkedTask {
    env: BareEnv,
    linux: Linux,
}

/// ステップ数で選ぶスケジューラと、止まっている実行環境。
#[derive(Default)]
struct SchedQueue {
    meta: polyisa_kernel::GuestScheduler,
    parked: Vec<ParkedTask>,
}

#[derive(Clone)]
struct SharedQueue(std::rc::Rc<std::cell::RefCell<SchedQueue>>);

/// HostIo をプロセス系で共有する器。初使用で起動する。
#[derive(Clone)]
struct SharedHostIo(std::rc::Rc<std::cell::RefCell<Option<std::rc::Rc<polyisa_kernel::HostIo>>>>);

impl Default for SharedHostIo {
    fn default() -> Self {
        Self(std::rc::Rc::new(std::cell::RefCell::new(None)))
    }
}

impl Default for SharedQueue {
    fn default() -> Self {
        Self(std::rc::Rc::new(std::cell::RefCell::new(
            SchedQueue::default(),
        )))
    }
}

/// この回数ごとに、ステップ数がより少ない実行可能なスレッドへ切り替える。
pub const SCHED_SLICE: u64 = 64;

impl Linux {
    /// x86-32 用ハンドラ。
    pub fn x86_32() -> Self {
        Self {
            umask: 0o22,
            ..Self::default()
        }
    }

    /// x86-64 用ハンドラ。
    pub fn x86_64() -> Self {
        Self {
            is64: true,
            umask: 0o22,
            ..Self::default()
        }
    }

    /// x32（ILP32）用ハンドラ。引数は x86-64 のレジスタ規則だが、
    /// 構造体内のポインタ・`long` は 32 ビットになる。
    pub fn x86_x32() -> Self {
        Self {
            is64: true,
            x32: true,
            umask: 0o22,
            ..Self::default()
        }
    }

    /// x32（ILP32）のハンドラなら真。実行経路が像とハンドラの
    /// ABI を食い違えて組み合わせていないか検査するために使う。
    pub fn is_x32(&self) -> bool {
        self.x32
    }

    /// プログラムブレークの初期値を置く。像末尾をページ境界に切り上げる。
    /// `run_image_x86_64` がセグメント配置の直後に呼ぶ。
    pub fn init_brk(&mut self, image_end: u64) {
        use polyisa_mem::PAGE_SIZE;
        self.heap_end = image_end.next_multiple_of(PAGE_SIZE);
    }

    /// ゲストパスをホストパスへ解決する。root 空は従来通り。はみ出しは None。
    fn resolve_path(&self, path: &str) -> Option<String> {
        resolve_guest_path(&self.guest_root, &self.cwd, path)
    }

    /// fd の対象。標準 fd の付け替え先も見る。
    fn fd_target(&self, fd: u32) -> Option<&polyisa_kernel::FdTarget> {
        if fd < 3 {
            self.std_targets[fd as usize].as_ref()
        } else {
            self.fds.target(fd)
        }
    }

    /// fd に対応する開ファイルの参照。対象がホストファイルのときだけ。
    fn file_ref(&self, fd: u32) -> Option<&std::fs::File> {
        match self.fd_target(fd) {
            Some(polyisa_kernel::FdTarget::File(f)) => Some(f),
            _ => None,
        }
    }

    /// fd に対応する開ファイルの可変参照。対象がホストファイルのときだけ。
    fn file_mut(&mut self, fd: u32) -> Option<&mut std::fs::File> {
        if fd < 3 {
            match self.std_targets[fd as usize].as_mut() {
                Some(polyisa_kernel::FdTarget::File(f)) => Some(f),
                _ => None,
            }
        } else {
            self.fds.file_mut(fd)
        }
    }

    /// 真の標準入出力に繋がっているか（閉じても付け替えてもいない）。
    fn std_attached(&self, fd: u32) -> bool {
        fd < 3 && !self.std_closed[fd as usize] && self.std_targets[fd as usize].is_none()
    }

    /// fcntl・dup2 の妥当性。接続中・付け替え中の標準 fd と opened fd が真.
    fn fd_valid(&self, fd: u32) -> bool {
        self.fd_target(fd).is_some() || (fd < 3 && !self.std_closed[fd as usize])
    }

    /// パイプ端なら (id, read)。
    fn pipe_end(&self, fd: u32) -> Option<(u64, bool)> {
        match self.fd_target(fd) {
            Some(polyisa_kernel::FdTarget::PipeEnd { id, read }) => Some((*id, *read)),
            _ => None,
        }
    }

    /// 対象を複製する（dup・fork 相当）。パスも返す。
    /// 複製に失敗した対象は None。
    fn dup_open(&self, fd: u32) -> Option<(polyisa_kernel::FdTarget, Option<String>)> {
        let target = self.fd_target(fd)?;
        let dup = self.fds.dup_of(target)?;
        let path = self.path_of(fd).map(str::to_string);
        Some((dup, path))
    }

    /// fd の対象を外して閉じる。パイプ端なら待ちを解除する。
    /// 対象がなければ偽。
    fn remove_fd(&mut self, fd: u32) -> bool {
        let target = if fd < 3 {
            self.std_targets[fd as usize].take()
        } else {
            self.fds.take(fd).map(|ent| ent.target)
        };
        let Some(target) = target else {
            return false;
        };
        for (id, wake_r, wake_w) in self.fds.close_target(&target) {
            if wake_r || wake_w {
                self.wake_pipe(id);
            }
        }
        true
    }

    /// 対象を `newfd` へ置く。先に旧対象を閉じる（dup2 規約）。
    /// 閉じた標準 fd への再配置もここで面倒を見る。
    fn install_target(&mut self, t: polyisa_kernel::FdTarget, newfd: u32) {
        self.close_fd(newfd);
        if newfd < 3 {
            let i = newfd as usize;
            self.std_targets[i] = Some(t);
            self.std_paths[i] = None;
            self.std_closed[i] = false;
            self.std_is_stdin[i] = false;
            return;
        }
        self.fds.place(newfd, t);
    }

    /// そのパイプの読みを待っているスレッドを実行可能に戻す。
    fn wake_pipe(&mut self, id: u64) {
        self.queue.0.borrow_mut().meta.unblock_pipe(id);
        let queue = self.queue.clone();
        for task in &mut queue.0.borrow_mut().parked {
            if task.linux.pipe_wait == Some(id) {
                task.linux.pipe_wait = None;
            }
        }
        if self.pipe_wait == Some(id) {
            self.pipe_wait = None;
        }
    }

    /// 単調時計の今（ナノ秒。fd 待ち専用。初使用の時点を起点）。
    fn mono_ns(&self) -> u64 {
        self.wait_start
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_nanos() as u64
    }

    /// ソケット正準層への ABI 差分。
    fn sock_abi(&self) -> crate::sock::SockAbi {
        let ptr = if self.is64 && !self.x32 { 8 } else { 4 };
        crate::sock::SockAbi::generic(ptr, Endian::Le)
    }

    /// 待ち合わせ正準層への ABI 差分。x86 は epoll_event が
    /// 12 バイト詰め。i386 の select(82) は 5 語ブロックの旧形式。
    /// x32 は ILP32 でも timespec が 64 ビット幅。
    fn wait_abi(&self) -> crate::wait::WaitAbi {
        let ptr = if self.is64 && !self.x32 { 8 } else { 4 };
        let time = if self.is64 { 8 } else { 4 };
        let mut abi = crate::wait::WaitAbi::generic(ptr, time, Endian::Le);
        abi.epoll_ev_size = 12;
        abi.old_select = !self.is64;
        abi
    }

    /// 待ち合わせ系 syscall の正準層呼び出し。`prev` は前回張った
    /// 待ち（起きて再実行された呼び出しの期限切れ判定に使う）。
    fn wait_call(
        &mut self,
        env: &mut BareEnv,
        cx: &SysCtx,
        name: &str,
        prev: Option<&crate::sock::Wait>,
    ) -> Option<TrapOutcome> {
        let abi = self.wait_abi();
        let args: [u64; 6] = [
            get64(env, cx.r_a),
            get64(env, cx.r_b),
            get64(env, cx.r_c),
            get64(env, cx.r_d),
            get64(env, cx.r_e),
            get64(env, cx.r_f),
        ];
        let now = self.mono_ns();
        let pending = self.sig_pending;
        let r = crate::wait::dispatch(&mut self.fds, &abi, env, name, &args, prev, now, pending)?;
        self.sock_finish(env, r)
    }

    /// AF_UNIX のパス写像器を作る（guest_root・cwd を束縛した
    /// closure。`sock` 正準層へ渡す）。
    fn unix_path_map(&self) -> impl Fn(&[u8]) -> Option<Vec<u8>> + use<> {
        crate::sock::unix_path_map(&self.guest_root, &self.cwd)
    }

    /// accept/accept4 の共通処理。`flags` は SOCK_NONBLOCK/CLOEXEC。
    fn accept_impl(&mut self, env: &mut BareEnv, cx: &SysCtx, flags: u64) -> Option<TrapOutcome> {
        let abi = self.sock_abi();
        #[cfg(unix)]
        {
            let (a, b, c) = (get64(env, cx.r_a), get64(env, cx.r_b), get64(env, cx.r_c));
            let r = crate::sock::sys_accept(&mut self.fds, &abi, env, a, b, c, flags);
            self.sock_finish(env, r)
        }
        #[cfg(not(unix))]
        {
            let _ = (abi, env, cx, flags);
            Some(TrapOutcome::Unimplemented)
        }
    }

    /// getsockname/getpeername の共通処理。
    fn getname_impl(&mut self, env: &mut BareEnv, cx: &SysCtx, peer: bool) -> Option<TrapOutcome> {
        let abi = self.sock_abi();
        #[cfg(unix)]
        {
            let (a, b, c) = (get64(env, cx.r_a), get64(env, cx.r_b), get64(env, cx.r_c));
            let r = crate::sock::sys_getname(&mut self.fds, &abi, env, a, b, c, peer)
                .map(crate::sock::Out::Done);
            self.sock_finish(env, r)
        }
        #[cfg(not(unix))]
        {
            let _ = (abi, env, cx, peer);
            Some(TrapOutcome::Unimplemented)
        }
    }

    /// HostIo の共有器（初使用で起動）。
    fn host_io(&self) -> Option<std::rc::Rc<polyisa_kernel::HostIo>> {
        let mut slot = self.host_io.0.borrow_mut();
        if slot.is_none() {
            *slot = polyisa_kernel::HostIo::spawn().map(std::rc::Rc::new);
        }
        slot.clone()
    }

    /// 自分が fd 待ち系で blocked に記録されているか。
    fn self_fd_blocked(&self) -> bool {
        self.queue.0.borrow().meta.blocked().iter().any(|(id, w)| {
            id.0 == self.pid
                && matches!(
                    w,
                    polyisa_kernel::ThreadWait::Fd
                        | polyisa_kernel::ThreadWait::HostFd
                        | polyisa_kernel::ThreadWait::Timer
                )
        })
    }

    /// fd 待ちの駐車種別。ホスト fd を含むなら HostFd、期限だけ
    /// なら Timer、それ以外は Fd。
    fn wait_kind(&self, w: &crate::sock::Wait) -> polyisa_kernel::ThreadWait {
        #[cfg(unix)]
        if w.fds
            .iter()
            .any(|&(fd, ev)| !self.fds.host_watches(fd, ev).is_empty())
        {
            return polyisa_kernel::ThreadWait::HostFd;
        }
        if w.fds.is_empty() && w.deadline.is_some() {
            return polyisa_kernel::ThreadWait::Timer;
        }
        polyisa_kernel::ThreadWait::Fd
    }

    /// ソケット正準層の戻りをゲスト状態へ写す。
    fn sock_finish(
        &mut self,
        env: &mut BareEnv,
        r: Result<crate::sock::Out, u32>,
    ) -> Option<TrapOutcome> {
        match r {
            Ok(crate::sock::Out::Done(v)) => {
                self.fd_wait = None;
                set64(env, Gpr(0), v);
                self.advance_past_syscall(env);
                Some(TrapOutcome::Handled)
            }
            Ok(crate::sock::Out::Wait(w)) => {
                let id = self.ensure_self();
                let kind = self.wait_kind(&w);
                self.fd_wait = Some(w);
                self.queue
                    .0
                    .borrow_mut()
                    .meta
                    .block(polyisa_kernel::ThreadId(id.0), kind);
                Some(TrapOutcome::Blocked)
            }
            Err(e) => {
                self.fd_wait = None;
                self.set_errno(env, e);
                self.advance_past_syscall(env);
                Some(TrapOutcome::Handled)
            }
        }
    }

    /// 一つの待ちの準備評価。期限切れも真。
    fn wait_ready(
        fds: &polyisa_kernel::FdTable,
        w: &crate::sock::Wait,
        now: u64,
        pending: u64,
    ) -> bool {
        if w.deadline.is_some_and(|dl| now >= dl) {
            return true;
        }
        w.fds.iter().any(|&(fd, ev)| {
            let r = fds.ready(fd, now, pending);
            // ERR/HUP は興味ビットに関係なく常に起床条件。
            r.err
                || r.hup
                || (ev & crate::sock::WANT_READ != 0 && r.read)
                || (ev & crate::sock::WANT_WRITE != 0 && r.write)
        })
    }

    /// 駐車中と自分の fd 待ちを再評価し、準備の立ったものを
    /// 実行可能へ戻す。
    fn sweep_fd_waits(&mut self) {
        let now = self.mono_ns();
        let queue = self.queue.clone();
        let mut borrowed = queue.0.borrow_mut();
        let mut ready = Vec::new();
        for task in &mut borrowed.parked {
            let Some(w) = &task.linux.fd_wait else {
                continue;
            };
            if Self::wait_ready(&task.linux.fds, w, now, task.linux.sig_pending) {
                task.linux.fd_wait_prev = task.linux.fd_wait.take();
                ready.push(polyisa_kernel::ThreadId(task.linux.pid));
            }
        }
        for id in ready {
            borrowed.meta.unblock(id);
        }
        drop(borrowed);
        let self_ready = self
            .fd_wait
            .as_ref()
            .is_some_and(|w| Self::wait_ready(&self.fds, w, now, self.sig_pending));
        if self_ready {
            self.fd_wait_prev = self.fd_wait.take();
            let pid = self.pid;
            self.queue
                .0
                .borrow_mut()
                .meta
                .unblock(polyisa_kernel::ThreadId(pid));
        }
    }

    /// 駐車中と自分の待ちから、ホスト fd の監視集合と最速の期限を集める。
    /// 戻り値は（ホスト監視列, 最速期限 ns）。
    fn collect_host_watches(&self) -> (Vec<(polyisa_host::RawFd, i16)>, Option<u64>) {
        // ホスト fd の監視は Unix 系ホストだけが足す。
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut list = Vec::new();
        let mut earliest: Option<u64> = None;
        let mut take = |w: &crate::sock::Wait, fds: &polyisa_kernel::FdTable| {
            for &(fd, ev) in &w.fds {
                #[cfg(unix)]
                list.extend(fds.host_watches(fd, ev));
                // timerfd 等のカーネル対象の期限も起床時刻に畳む。
                if let Some(dl) = fds.wait_deadline(fd) {
                    earliest = Some(earliest.map_or(dl, |e| e.min(dl)));
                }
                #[cfg(not(unix))]
                let _ = ev;
            }
            if let Some(dl) = w.deadline {
                earliest = Some(earliest.map_or(dl, |e| e.min(dl)));
            }
        };
        for task in &self.queue.0.borrow().parked {
            if let Some(w) = &task.linux.fd_wait {
                take(w, &task.linux.fds);
            }
        }
        if let Some(w) = &self.fd_wait {
            take(w, &self.fds);
        }
        (list, earliest)
    }

    /// ホスト fd イベントに対応する待ちを解除する。
    /// `events` は（生 fd, revents）の列。戻るのは誰か解除したか。
    // ホスト監視の照合は Unix 系ホストだけにある。
    #[cfg_attr(not(unix), allow(unused_variables))]
    fn wake_host_waits(&mut self, events: &[(polyisa_host::RawFd, i16)]) -> bool {
        let queue = self.queue.clone();
        let mut borrowed = queue.0.borrow_mut();
        let mut woke = Vec::new();
        for task in &mut borrowed.parked {
            let Some(w) = &task.linux.fd_wait else {
                continue;
            };
            let hit = w.fds.iter().any(|&(fd, ev)| {
                #[cfg(unix)]
                return task
                    .linux
                    .fds
                    .host_watches(fd, ev)
                    .iter()
                    .any(|&(raw, _)| events.iter().any(|&(r, _)| r == raw));
                #[allow(unreachable_code)]
                {
                    let _ = (fd, ev);
                    false
                }
            });
            if hit {
                task.linux.fd_wait_prev = task.linux.fd_wait.take();
                woke.push(polyisa_kernel::ThreadId(task.linux.pid));
            }
        }
        for id in &woke {
            borrowed.meta.unblock(*id);
        }
        let mut woke = !woke.is_empty();
        drop(borrowed);
        let self_hit = self.fd_wait.as_ref().is_some_and(|w| {
            w.fds.iter().any(|&(fd, ev)| {
                #[cfg(unix)]
                return self
                    .fds
                    .host_watches(fd, ev)
                    .iter()
                    .any(|&(raw, _)| events.iter().any(|&(r, _)| r == raw));
                #[allow(unreachable_code)]
                {
                    let _ = (fd, ev);
                    false
                }
            })
        });
        if self_hit {
            self.fd_wait_prev = self.fd_wait.take();
            let pid = self.pid;
            self.queue
                .0
                .borrow_mut()
                .meta
                .unblock(polyisa_kernel::ThreadId(pid));
            woke = true;
        }
        woke
    }

    /// HostFd/Timer 待ちの処理。ホスト fd を poll か HostIo で待ち、
    /// イベントや期限で待ちを解除する。誰か実行可能になったら真、
    /// 処理できる待ちが残らなければ偽（デッドロック）。
    fn drive_io_waits(&mut self) -> bool {
        // ホスト fd の poll は Unix 系ホストだけが行う。
        #[cfg_attr(not(unix), allow(unused_mut))]
        let (mut watches, deadline) = self.collect_host_watches();
        // 待ちが一つも無ければ処理できない。
        let any_wait = self.fd_wait.is_some()
            || self
                .queue
                .0
                .borrow()
                .parked
                .iter()
                .any(|t| t.linux.fd_wait.is_some());
        if !any_wait {
            return false;
        }
        // ホスト監視も期限も無い fd 待ちだけなら、ほかに実行可能な
        // スレッドがいない限り進まない（カーネル対象の変化は他
        // スレッドの実行が要る）— ここに来た時点でいないので不成立。
        if watches.is_empty() && deadline.is_none() {
            return false;
        }
        let now = self.mono_ns();
        let timeout_ms = deadline.map(|dl| {
            let remain = dl.saturating_sub(now);
            i32::try_from(remain / 1_000_000).unwrap_or(i32::MAX)
        });
        // HostIo が使えれば作業スレッド経由、なければ直接 poll。
        let events: Vec<(polyisa_host::RawFd, i16)> = if let Some(io) = self.host_io() {
            io.set_watches(&watches);
            let ms = timeout_ms.map(|t| std::time::Duration::from_millis(t.max(0) as u64));
            io.wait_done(ms).unwrap_or_default()
        } else {
            #[cfg(unix)]
            {
                let t = timeout_ms.unwrap_or(50).min(50);
                let _ = polyisa_host::sock::poll(&mut watches, t);
                watches
                    .iter()
                    .filter(|&&(_, rev)| rev != 0)
                    .copied()
                    .collect()
            }
            #[cfg(not(unix))]
            {
                std::thread::sleep(std::time::Duration::from_millis(
                    timeout_ms.unwrap_or(50).min(50) as u64,
                ));
                Vec::new()
            }
        };
        self.wake_host_waits(&events);
        // イベントが無くても期限切れ・カーネル側の変化を掃討で拾う。
        true
    }

    /// 実行できない理由を一度報告する。
    fn note_deadlock(&self) {
        eprintln!("run: deadlock");
        for (id, wait) in self.queue.0.borrow().meta.blocked() {
            match wait {
                polyisa_kernel::ThreadWait::Child { which } => {
                    eprintln!("run: pid {} waits for child {which}", id.0);
                }
                polyisa_kernel::ThreadWait::Pipe { id: pipe } => {
                    eprintln!("run: pid {} waits for pipe {pipe}", id.0);
                }
                polyisa_kernel::ThreadWait::Fd => {
                    eprintln!("run: pid {} waits for fd readiness", id.0);
                }
                polyisa_kernel::ThreadWait::HostFd => {
                    eprintln!("run: pid {} waits for host fd readiness", id.0);
                }
                polyisa_kernel::ThreadWait::Timer => {
                    eprintln!("run: pid {} waits for timer", id.0);
                }
            }
        }
    }

    /// 止めたスレッドの実行環境を外し、パイプの端を閉じる。
    fn release_parked(&mut self, pid: u64) {
        let queue = self.queue.clone();
        let mut task = {
            let mut borrowed = queue.0.borrow_mut();
            let Some(idx) = borrowed
                .parked
                .iter()
                .position(|task| task.linux.pid == pid)
            else {
                return;
            };
            borrowed.parked.remove(idx)
        };
        let n = task.linux.fds.len();
        for fd in 0..n as u32 {
            task.linux.remove_fd(3 + fd);
        }
        for i in 0..3u32 {
            task.linux.remove_fd(i);
        }
        // 閉じた fd を観ていた他スレッドの待ちを解消する。
        self.sweep_fd_waits();
    }

    /// この子を待っているスレッドを、再び実行できるようにする。
    fn wake_child_waiters(&mut self, child: polyisa_kernel::ProcessId) {
        let queue = self.queue.clone();
        let waiters: Vec<u64> = queue
            .0
            .borrow()
            .parked
            .iter()
            .filter_map(|task| {
                let which = task.linux.wait.as_ref().map(|wait| wait.which)?;
                if self.procs.borrow().waits_for(
                    polyisa_kernel::ProcessId(task.linux.pid),
                    which,
                    child,
                ) {
                    Some(task.linux.pid)
                } else {
                    None
                }
            })
            .collect();
        let mut queue = queue.0.borrow_mut();
        for pid in waiters {
            queue.meta.unblock(polyisa_kernel::ThreadId(pid));
        }
    }

    /// 最下位の空き番号を割り当てる。閉じた標準 fd・空きスロットを再利用する.
    fn alloc_fd(&mut self, f: std::fs::File) -> u32 {
        self.alloc_target(polyisa_kernel::FdTarget::File(f))
    }

    /// 任意の対象を最下位の空き番号へ割り当てる。
    fn alloc_target(&mut self, t: polyisa_kernel::FdTarget) -> u32 {
        for i in 0..3usize {
            if self.std_targets[i].is_none() && self.std_closed[i] {
                self.std_targets[i] = Some(t);
                self.std_closed[i] = false;
                self.std_is_stdin[i] = false;
                return i as u32;
            }
        }
        self.fds.alloc(t)
    }

    /// FD_CLOEXEC を立てる/下ろす。標準 fd の付け替え先は記録しない。
    fn set_cloexec(&mut self, fd: u32, on: bool) {
        if fd >= 3 {
            let _ = self.fds.set_cloexec(fd, on);
        }
    }

    /// ゲスト fd に、openat が開いたホストパスを覚える。
    fn remember_path(&mut self, fd: u32, path: String) {
        if fd < 3 {
            self.std_paths[fd as usize] = Some(path);
            return;
        }
        self.fds.remember_path(fd, path);
    }

    /// ゲスト fd に覚えたホストパス。
    fn path_of(&self, fd: u32) -> Option<&str> {
        if fd < 3 {
            self.std_paths[fd as usize].as_deref()
        } else {
            self.fds.path_of(fd)
        }
    }

    /// ゲスト fd のパスと、getdents64 の読み終わり印を捨てる。
    fn forget_path(&mut self, fd: u32) {
        if fd < 3 {
            self.std_paths[fd as usize] = None;
        } else {
            self.fds.forget_path(fd);
        }
        self.dir_done.retain(|d| *d != fd);
        self.dir_pos.retain(|(id, _)| *id != fd);
    }

    /// 真の stdin から `dst` へ読む。供給が尽きたら 0。
    fn take_stdin(&mut self, dst: &mut [u8]) -> usize {
        let start = self.stdin_pos.min(self.stdin_buf.len());
        let n = (self.stdin_buf.len() - start).min(dst.len());
        dst[..n].copy_from_slice(&self.stdin_buf[start..start + n]);
        self.stdin_pos = start + n;
        n
    }

    /// fd 1 へ書く。capture_out があるときはそこへ溜める。
    fn write_fd1(&mut self, bytes: &[u8]) -> usize {
        if self.stdout_is_stderr {
            return std::io::Write::write(&mut std::io::stderr(), bytes).unwrap_or(0);
        }
        if let Some(buf) = self.capture_out.as_ref() {
            buf.borrow_mut().extend_from_slice(bytes);
            return bytes.len();
        }
        std::io::Write::write(&mut std::io::stdout(), bytes).unwrap_or(0)
    }

    /// 標準 fd 1/2 への write。dup2 による付け替えを反映する。
    fn write_stdio(&mut self, fd: u32, bytes: &[u8]) -> usize {
        match fd {
            1 => self.write_fd1(bytes),
            2 if self.stderr_is_stdout => self.write_fd1(bytes),
            _ => std::io::Write::write(&mut std::io::stderr(), bytes).unwrap_or(0),
        }
    }

    /// fd を閉じる。標準 fd の初回 close も成功させる。閉じたら真.
    fn close_fd(&mut self, fd: u32) -> bool {
        if fd < 3 {
            let i = fd as usize;
            if self.remove_fd(fd) {
                self.std_closed[i] = true;
                self.std_is_stdin[i] = false;
                self.forget_path(fd);
                true
            } else if !self.std_closed[i] {
                self.std_closed[i] = true;
                self.std_is_stdin[i] = false;
                true
            } else {
                false
            }
        } else {
            if self.remove_fd(fd) {
                self.forget_path(fd);
                return true;
            }
            false
        }
    }

    /// 未登録ならプロセス表とスケジューラへ載せる。
    fn ensure_self(&mut self) -> polyisa_kernel::ProcessId {
        if self.pid == 0 {
            let id = self.procs.borrow_mut().spawn(None);
            self.pid = id.0;
            self.queue
                .0
                .borrow_mut()
                .meta
                .insert(polyisa_kernel::ThreadId(id.0));
            id
        } else {
            let id = polyisa_kernel::ProcessId(self.pid);
            self.queue
                .0
                .borrow_mut()
                .meta
                .insert(polyisa_kernel::ThreadId(id.0));
            id
        }
    }

    /// 作業ディレクトリが空なら、ホストの現在位置を写す。
    fn ensure_cwd(&mut self) {
        if !self.cwd.is_empty() {
            return;
        }
        self.cwd = std::env::current_dir()
            .ok()
            .and_then(|path| path.into_os_string().into_string().ok())
            .unwrap_or_else(|| "/".to_string());
    }

    /// ファイル記述子を複製した子の状態。プロセス表は共有し、止めた子は持たない。
    fn duplicate(&self) -> Self {
        Self {
            reported: self.reported.clone(),
            fds: self.fds.try_clone(),
            std_targets: std::array::from_fn(|i| {
                self.std_targets[i]
                    .as_ref()
                    .and_then(|t| self.fds.dup_of(t))
            }),
            std_is_stdin: self.std_is_stdin,
            std_closed: self.std_closed,
            umask: self.umask,
            personality: self.personality,
            ioprio: self.ioprio,
            ioprio_known: self.ioprio_known,
            is64: self.is64,
            x32: self.x32,
            heap_end: self.heap_end,
            mmap_base: self.mmap_base,
            robust_head: self.robust_head,
            rseq_addr: self.rseq_addr,
            exe_path: self.exe_path.clone(),
            dir_done: self.dir_done.clone(),
            dir_pos: self.dir_pos.clone(),
            std_paths: self.std_paths.clone(),
            capture_out: self.capture_out.clone(),
            stdout_is_stderr: self.stdout_is_stderr,
            stderr_is_stdout: self.stderr_is_stdout,
            stdin_buf: self.stdin_buf.clone(),
            stdin_pos: self.stdin_pos,
            // fork: ハンドラ表とマスクは継承、保留は引き継がない。
            sigacts: self.sigacts.clone(),
            sig_mask: self.sig_mask,
            sig_pending: 0,
            sigaltstack: self.sigaltstack,
            procs: std::rc::Rc::clone(&self.procs),
            pid: self.pid,
            steps: 0,
            wait: None,
            queue: self.queue.clone(),
            pipe_wait: None,
            fd_wait: None,
            fd_wait_prev: None,
            host_io: self.host_io.clone(),
            cwd: self.cwd.clone(),
            guest_root: self.guest_root.clone(),
            mono_start: self.mono_start,
            wait_start: {
                self.wait_start.get_or_init(std::time::Instant::now);
                self.wait_start.clone()
            },
        }
    }

    /// 止まっているスレッドの識別子。
    pub fn task_pids(&self) -> Vec<u64> {
        self.queue
            .0
            .borrow()
            .parked
            .iter()
            .map(|task| task.linux.pid)
            .collect()
    }

    /// シグナルの既定動作で現在のプロセスを終える。プロセス表には
    /// 終了コードではなくシグナル死因を残し、wait 側が signal 付きの
    /// status を作れるようにする。
    fn terminate_by_signal(&mut self, sig: u32) -> TrapOutcome {
        let me = self.ensure_self();
        let nfd = self.fds.len();
        for fd in 0..3u32 {
            self.close_fd(fd);
        }
        for idx in 0..nfd {
            self.close_fd(3 + idx as u32);
        }
        self.procs.borrow_mut().kill(me, sig);
        self.queue
            .0
            .borrow_mut()
            .meta
            .mark_exited(polyisa_kernel::ThreadId(me.0));
        self.sweep_fd_waits();
        self.wake_child_waiters(me);
        TrapOutcome::Exit(sig)
    }

    /// 同期 CPU 例外を x86-64/i386 の rt フレームで配送する。
    /// ブロック中の同期例外も実機では再実行や終了に依存するため、
    /// ここでは既定動作へ倒す近似にする。
    fn deliver_exception(
        &mut self,
        env: &mut BareEnv,
        sig: u32,
        si_code: u64,
        si_addr: u64,
    ) -> TrapOutcome {
        let bit = 1u64 << (sig - 1);
        let act = self
            .sigacts
            .get(sig as usize - 1)
            .copied()
            .unwrap_or_default();
        if act.handler <= 1 || self.sig_mask & bit != 0 {
            return self.terminate_by_signal(sig);
        }
        let old = self.sig_mask;
        self.sig_mask = old
            | act.mask
            | if act.flags & crate::x86::SA_NODEFER == 0 {
                bit
            } else {
                0
            };
        if act.flags & crate::x86::SA_RESETHAND != 0 {
            self.sigacts[sig as usize - 1] = crate::x86::SigAct::default();
        }
        let ok = if self.x32 {
            crate::x86::rt_sigframe_x32_write_ex(
                env,
                sig,
                &act,
                old,
                si_code,
                si_addr,
                self.sigaltstack,
            )
        } else if self.is64 {
            crate::x86::rt_sigframe_write_ex(
                env,
                sig,
                &act,
                old,
                si_code,
                si_addr,
                self.sigaltstack,
            )
        } else {
            crate::x86::rt_sigframe32_write_ex(
                env,
                sig,
                &act,
                old,
                si_code,
                si_addr,
                self.sigaltstack,
            )
        };
        if ok {
            crate::x86::signal_init_user_fpstate(env);
            if self.sigaltstack.flags & crate::x86::SS_AUTODISARM != 0 {
                self.sigaltstack = crate::x86::SigAltStack {
                    flags: crate::x86::SS_DISABLE,
                    ..crate::x86::SigAltStack::default()
                };
            }
            return TrapOutcome::Handled;
        }
        self.sig_mask = old;
        self.sigacts[sig as usize - 1] = act;
        self.terminate_by_signal(11)
    }

    /// 保留シグナルのうちブロックされていない最も小さい番号を配送する。
    /// ハンドラが SIG_DFL/SIG_IGN のものは `kill` 側で保留に
    /// しないのでここには来ない。
    // Gap: GAP-0026 — CPU 例外→シグナルの変換、i386 フレーム、
    // 既定動作（SIGKILL 以外）による終了、他プロセス/他スレッド
    // への配送、タイマ由来のシグナル、sigaltstack はない。
    // x32 は rt_sigframe_x32 形式で配送する。syscall 番号ではなく
    // プロセス ABI で戻り形式を選ぶ近似は残る。
    fn deliver_pending(&mut self, env: &mut BareEnv) {
        let deliver = self.sig_pending & !self.sig_mask;
        if deliver == 0 {
            return;
        }
        let sig = deliver.trailing_zeros() + 1;
        let bit = 1u64 << (sig - 1);
        self.sig_pending &= !bit;
        let act = self
            .sigacts
            .get(sig as usize - 1)
            .copied()
            .unwrap_or_default();
        if act.handler <= 1 {
            return;
        }
        let old = self.sig_mask;
        self.sig_mask = old
            | act.mask
            | if act.flags & crate::x86::SA_NODEFER == 0 {
                bit
            } else {
                0
            };
        if act.flags & crate::x86::SA_RESETHAND != 0 {
            self.sigacts[sig as usize - 1] = crate::x86::SigAct::default();
        }
        let pid = self.pid;
        let ok = if self.x32 {
            crate::x86::rt_sigframe_x32_write_ex(env, sig, &act, old, 0, pid, self.sigaltstack)
        } else if self.is64 {
            crate::x86::rt_sigframe_write_ex(env, sig, &act, old, 0, pid, self.sigaltstack)
        } else {
            crate::x86::rt_sigframe32_write_ex(env, sig, &act, old, 0, pid, self.sigaltstack)
        };
        if ok {
            crate::x86::signal_init_user_fpstate(env);
            if self.sigaltstack.flags & crate::x86::SS_AUTODISARM != 0 {
                self.sigaltstack = crate::x86::SigAltStack {
                    flags: crate::x86::SS_DISABLE,
                    ..crate::x86::SigAltStack::default()
                };
            }
        } else {
            // フレームが書けない（未写像スタック等）。実機なら
            // SIGSEGV で死ぬが、ここでは配送を諦めて保留と
            // ハンドラを戻し、再試行できる状態にする。
            self.sig_mask = old;
            self.sig_pending |= bit;
            self.sigacts[sig as usize - 1] = act;
        }
    }

    /// 1 命令を数え、区切りでより短いスレッドへ切り替える。
    fn step_and_maybe_preempt(&mut self, env: &mut BareEnv) {
        let id = self.ensure_self();
        let steps = {
            let mut queue = self.queue.0.borrow_mut();
            queue.meta.add_step(polyisa_kernel::ThreadId(id.0))
        };
        self.steps = steps;
        if steps.is_multiple_of(SCHED_SLICE) {
            let _ = self.preempt(env);
        }
    }

    /// 自分よりステップ数が少ない実行可能なスレッドと入れ替える。
    fn preempt(&mut self, env: &mut BareEnv) -> bool {
        let next = {
            let queue = self.queue.0.borrow();
            queue.meta.next(polyisa_kernel::ThreadId(self.pid))
        };
        let Some(next) = next else {
            return false;
        };
        self.swap_in(env, next.0)
    }

    fn swap_in(&mut self, env: &mut BareEnv, pid: u64) -> bool {
        let queue = self.queue.clone();
        let mut other = {
            let mut borrowed = queue.0.borrow_mut();
            let Some(idx) = borrowed
                .parked
                .iter()
                .position(|task| task.linux.pid == pid)
            else {
                return false;
            };
            borrowed.parked.remove(idx)
        };
        std::mem::swap(self, &mut other.linux);
        std::mem::swap(env, &mut other.env);
        let exited = queue
            .0
            .borrow()
            .meta
            .is_exited(polyisa_kernel::ThreadId(other.linux.pid));
        if !exited {
            queue.0.borrow_mut().parked.push(other);
        }
        true
    }

    /// 子の終了を記録し、親か残りの実行可能なスレッドへ戻る。
    /// 戻る相手がいるときだけ真。初期プロセスの終了は偽で、呼び出し側へ渡す。
    fn yield_on_exit(&mut self, env: &mut BareEnv, code: u32) -> bool {
        let me = self.ensure_self();
        let nfd = self.fds.len();
        for fd in 0..3u32 {
            self.close_fd(fd);
        }
        for idx in 0..nfd {
            self.close_fd(3 + idx as u32);
        }
        self.procs.borrow_mut().exit(me, code);
        let root = self.procs.borrow().is_root(me);
        self.queue
            .0
            .borrow_mut()
            .meta
            .mark_exited(polyisa_kernel::ThreadId(me.0));
        // 閉じた fd を観ていた他スレッドの待ちを解消する。
        self.sweep_fd_waits();
        if root {
            return false;
        }
        let target = {
            let queue = self.queue.0.borrow();
            let waiter = queue.parked.iter().find_map(|task| {
                let which = task.linux.wait.as_ref().map(|wait| wait.which)?;
                if self.procs.borrow().waits_for(
                    polyisa_kernel::ProcessId(task.linux.pid),
                    which,
                    me,
                ) {
                    Some(task.linux.pid)
                } else {
                    None
                }
            });
            waiter.or_else(|| queue.meta.least_runnable().map(|id| id.0))
        };
        let Some(pid) = target else {
            return false;
        };
        if !self.swap_in(env, pid) {
            return false;
        }
        if self.wait.is_some() {
            self.complete_wait(env);
        }
        true
    }

    /// 待っていた `wait4` を、記録済みの終了コードで完了する。
    fn complete_wait(&mut self, env: &mut BareEnv) {
        let Some(wait) = self.wait.take() else {
            return;
        };
        self.queue
            .0
            .borrow_mut()
            .meta
            .unblock(polyisa_kernel::ThreadId(self.pid));
        match self
            .procs
            .borrow_mut()
            .try_reap(polyisa_kernel::ProcessId(self.pid), wait.which)
        {
            polyisa_kernel::Reap::Exited { pid, code, signal } => {
                if wait.status_ptr != 0 {
                    let st = reap_status(code, signal);
                    if env
                        .backend
                        .mem
                        .write(VirtAddr(wait.status_ptr), &st.to_le_bytes())
                        .is_err()
                    {
                        self.set_errno(env, EFAULT);
                        self.advance_past_syscall(env);
                        return;
                    }
                }
                set64(env, Gpr(0), pid.0);
                self.advance_past_syscall(env);
            }
            polyisa_kernel::Reap::NoChild => {
                self.set_errno(env, ECHILD);
                self.advance_past_syscall(env);
            }
            polyisa_kernel::Reap::Pending => {
                let which = wait.which;
                self.wait = Some(wait);
                self.queue.0.borrow_mut().meta.block(
                    polyisa_kernel::ThreadId(self.pid),
                    polyisa_kernel::ThreadWait::Child { which },
                );
            }
        }
    }

    fn set_errno(&self, env: &mut BareEnv, errno: u32) {
        let value = if self.is64 {
            neg_errno64(errno)
        } else {
            u64::from(neg_errno(errno))
        };
        set64(env, Gpr(0), value);
    }

    /// SYSCALL と INT 0x80 は 2 バイト。完了した呼び出しの次へ進める。
    fn advance_past_syscall(&self, env: &mut BareEnv) {
        let eip = eip_of(env);
        env.backend
            .set(polyisa_guest_x86::sem::eip_ref(), eip.wrapping_add(2));
    }
}

/// 1 回の read/write でホストに確保する上限（バイト）。ゲスト指定の
/// 長さが大きくても、この刻みで分割して転送する。
const IO_CHUNK: usize = 65536;

fn reap_status(code: u32, signal: Option<u32>) -> u32 {
    match signal {
        Some(sig) => sig & 0x7f,
        None => crate::exited_wait_status(code),
    }
}

/// ホスト metadata から x86-64 struct stat (144B) を合成する。
/// 種別 (st_mode) と大きさ (st_size) と、パスから決めた st_ino を入れる。
/// 同じパスは同じ inode になり、ディレクトリの再帰判定が分かれる。
/// レイアウトは musl/glibc 共通のカーネル ABI 由来である。
type SysFn = fn(&mut Linux, &mut BareEnv, &SysCtx) -> Option<TrapOutcome>;

const X86_64_SYSCALLS: &[(&str, SysFn)] = &[
    ("openat", sys_openat),
    ("open", sys_open),
    ("read", sys_read),
    ("close", sys_close),
    ("write", sys_write),
    ("writev", sys_writev),
    ("readv", sys_readv),
    ("exit", sys_exit),
    ("exit_group", sys_exit_group),
    ("clone", sys_clone),
    ("fork", sys_fork),
    ("vfork", sys_vfork),
    ("execve", sys_execve),
    ("wait4", sys_wait4),
    ("pipe2", sys_pipe2),
    ("pipe", sys_pipe),
    ("setpgid", sys_setpgid),
    ("setsid", sys_setsid),
    ("getpgid", sys_getpgid),
    ("getpriority", sys_getpriority),
    ("setpriority", sys_setpriority),
    ("personality", sys_personality),
    ("sched_setaffinity", sys_sched_setaffinity),
    ("ioprio_set", sys_ioprio_set),
    ("ioprio_get", sys_ioprio_get),
    ("fsync", sys_fsync),
    ("fdatasync", sys_fdatasync),
    ("unshare", sys_unshare),
    ("sched_setparam", sys_sched_setparam),
    ("sched_getparam", sys_sched_getparam),
    ("sched_setscheduler", sys_sched_setscheduler),
    ("sched_getscheduler", sys_sched_getscheduler),
    ("sched_get_priority_max", sys_sched_get_priority_max),
    ("sched_get_priority_min", sys_sched_get_priority_min),
    ("chdir", sys_chdir),
    ("fchdir", sys_fchdir),
    ("setgroups", sys_setgroups),
    ("chroot", sys_chroot),
    ("kill", sys_kill),
    ("mmap", sys_mmap),
    ("set_tid_address", sys_set_tid_address),
    ("gettid", sys_gettid),
    ("getpid", sys_getpid),
    ("getppid", sys_getppid),
    ("sysinfo", sys_sysinfo),
    ("reboot", sys_reboot),
    ("syslog", sys_syslog),
    ("init_module", sys_init_module),
    ("delete_module", sys_delete_module),
    ("finit_module", sys_finit_module),
    ("swapon", sys_swapon),
    ("swapoff", sys_swapoff),
    ("pivot_root", sys_pivot_root),
    ("umount2", sys_umount2),
    ("flock", sys_flock),
    ("shmget", sys_shmget),
    ("shmctl", sys_shmctl),
    ("semget", sys_semget),
    ("semctl", sys_semctl),
    ("msgget", sys_msgget),
    ("msgctl", sys_msgctl),
    ("getitimer", sys_getitimer),
    ("setitimer", sys_setitimer),
    ("socket", sys_socket),
    ("socketpair", sys_socketpair),
    ("bind", sys_bind),
    ("connect", sys_connect),
    ("listen", sys_listen),
    ("accept", sys_accept),
    ("accept4", sys_accept4),
    ("getpeername", sys_getpeername),
    ("shutdown", sys_shutdown),
    ("setsockopt", sys_setsockopt),
    ("getsockopt", sys_getsockopt),
    ("sendto", sys_sendto),
    ("recvfrom", sys_recvfrom),
    ("sendmsg", sys_sendmsg),
    ("recvmsg", sys_recvmsg),
    ("getsockname", sys_getsockname),
    ("setxattr", sys_setxattr),
    ("lsetxattr", sys_lsetxattr),
    ("fsetxattr", sys_fsetxattr),
    ("mount", sys_mount),
    ("sysfs", sys_sysfs),
    ("tkill", sys_tkill),
    ("inotify_init1", sys_inotify_init1),
    ("inotify_init", sys_inotify_init),
    ("inotify_add_watch", sys_inotify_add_watch),
    ("adjtimex", sys_adjtimex),
    ("setuid", sys_setuid),
    ("setgid", sys_setgid),
    ("setreuid", sys_setreuid),
    ("setregid", sys_setregid),
    ("setresuid", sys_setresuid),
    ("setresgid", sys_setresgid),
    ("uname", sys_uname),
    ("getuid", sys_getuid),
    ("geteuid", sys_geteuid),
    ("getgid", sys_getgid),
    ("getegid", sys_getegid),
    ("getcwd", sys_getcwd),
    ("getdents64", sys_getdents64),
    ("fstat", sys_fstat),
    ("stat", sys_stat),
    ("lstat", sys_lstat),
    ("newfstatat", sys_newfstatat),
    ("sendfile", sys_sendfile),
    ("lseek", sys_lseek),
    ("ftruncate", sys_ftruncate),
    ("fallocate", sys_fallocate),
    ("getgroups", sys_getgroups),
    ("mprotect", sys_mprotect),
    ("munmap", sys_munmap),
    ("sigaltstack", sys_sigaltstack),
    ("rt_sigaction", sys_rt_sigaction),
    ("rt_sigprocmask", sys_rt_sigprocmask),
    ("rt_sigpending", sys_rt_sigpending),
    ("rt_sigreturn", sys_rt_sigreturn),
    ("rt_sigtimedwait", sys_rt_sigtimedwait),
    ("rt_sigsuspend", sys_rt_sigsuspend),
    ("pause", sys_pause),
    ("tgkill", sys_tgkill),
    ("set_robust_list", sys_set_robust_list),
    ("rseq", sys_rseq),
    ("getrandom", sys_getrandom),
    ("prlimit64", sys_prlimit64),
    ("time", sys_time),
    ("gettimeofday", sys_gettimeofday),
    ("getcpu", sys_getcpu),
    ("ioctl", sys_ioctl),
    ("clock_nanosleep", sys_clock_nanosleep),
    ("nanosleep", sys_nanosleep),
    ("sched_getaffinity", sys_sched_getaffinity),
    ("clock_gettime", sys_clock_gettime),
    ("readlinkat", sys_readlinkat),
    ("readlink", sys_readlink),
    ("arch_prctl", sys_arch_prctl),
    ("dup", sys_dup),
    ("dup2", sys_dup2),
    ("dup3", sys_dup3),
    ("mkdir", sys_mkdir),
    ("mkdirat", sys_mkdirat),
    ("mknod", sys_mknod),
    ("rename", sys_rename),
    ("symlink", sys_symlink),
    ("link", sys_link),
    ("sync", sys_sync),
    ("rmdir", sys_rmdir),
    ("unlink", sys_unlink),
    ("unlinkat", sys_unlinkat),
    ("access", sys_access),
    ("faccessat", sys_faccessat),
    ("utimensat", sys_utimensat),
    ("chmod", sys_chmod),
    ("fchmod", sys_fchmod),
    ("chown", sys_chown),
    ("fchown", sys_fchown),
    ("lchown", sys_lchown),
    ("fchmodat", sys_fchmodat),
    ("umask", sys_umask),
    ("fcntl", sys_fcntl),
    ("brk", sys_brk),
];

const X86_32_SYSCALLS: &[(&str, SysFn)] = &[
    ("socketcall", sys_socketcall),
    ("openat", sys_openat),
    ("open", sys_open),
    ("read", sys_read),
    ("close", sys_close),
    ("write", sys_write),
    ("writev", sys_writev),
    ("readv", sys_readv),
    ("exit", sys_exit),
    ("exit_group", sys_exit_group),
    ("gettid", sys_gettid),
    ("getpid", sys_getpid),
    ("getppid", sys_getppid),
    ("uname", sys_uname),
    ("set_thread_area", sys_set_thread_area),
    ("set_tid_address", sys_set_tid_address),
    ("getuid", sys_getuid),
    ("geteuid", sys_geteuid),
    ("getgid", sys_getgid),
    ("getegid", sys_getegid),
    ("setuid", sys_setuid),
    ("setgid", sys_setgid),
    ("getgroups", sys_getgroups),
    ("getgroups32", sys_getgroups32),
    ("setgroups", sys_setgroups),
    ("getcwd", sys_getcwd),
    ("chdir", sys_chdir),
    ("fchdir", sys_fchdir),
    ("ftruncate", sys_ftruncate),
    ("mprotect", sys_mprotect),
    ("munmap", sys_munmap),
    ("sigaltstack", sys_sigaltstack),
    ("rt_sigaction", sys_rt_sigaction),
    ("rt_sigprocmask", sys_rt_sigprocmask),
    ("rt_sigpending", sys_rt_sigpending),
    ("rt_sigreturn", sys_rt_sigreturn),
    ("rt_sigtimedwait", sys_rt_sigtimedwait),
    ("rt_sigsuspend", sys_rt_sigsuspend),
    ("pause", sys_pause),
    ("tgkill", sys_tgkill),
    ("readlinkat", sys_readlinkat),
    ("readlink", sys_readlink),
    ("dup", sys_dup),
    ("dup2", sys_dup2),
    ("dup3", sys_dup3),
    ("mkdir", sys_mkdir),
    ("mkdirat", sys_mkdirat),
    ("rename", sys_rename),
    ("symlink", sys_symlink),
    ("rmdir", sys_rmdir),
    ("unlink", sys_unlink),
    ("unlinkat", sys_unlinkat),
    ("access", sys_access),
    ("faccessat", sys_faccessat),
    ("utimensat", sys_utimensat),
    ("chmod", sys_chmod),
    ("fchmod", sys_fchmod),
    ("fchmodat", sys_fchmodat),
    ("umask", sys_umask),
    ("fcntl", sys_fcntl),
    ("ioctl", sys_ioctl),
    ("getrandom", sys_getrandom),
    ("lseek", sys_lseek),
    ("llseek", sys_llseek),
    ("getdents64", sys_getdents64),
    ("sendfile", sys_sendfile),
    ("time", sys_time),
    ("gettimeofday", sys_gettimeofday),
    ("getcpu", sys_getcpu),
    ("clock_gettime", sys_clock_gettime),
    ("stat", sys_stat),
    ("lstat", sys_lstat),
    ("fstat", sys_fstat),
    ("fstatat64", sys_fstatat64),
    ("sysinfo", sys_sysinfo),
    ("personality", sys_personality),
    ("fork", sys_fork),
    ("vfork", sys_vfork),
    ("clone", sys_clone),
    ("execve", sys_execve),
    ("wait4", sys_wait4),
    ("pipe", sys_pipe),
    ("pipe2", sys_pipe2),
    ("setpgid", sys_setpgid),
    ("getpgid", sys_getpgid),
    ("setsid", sys_setsid),
    ("kill", sys_kill),
    ("brk", sys_brk),
    ("mmap", sys_mmap),
];

fn sys_open(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // open は dirfd を持たない。パスは AT_FDCWD からの相対パスとして開く。
    let path_addr = get64(env, cx.r_a);
    let flags = get64(env, cx.r_b) as u32;
    open_at_cwd(sys, env, cx, path_addr, flags)
}

fn sys_openat(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // Gap: GAP-0002
    let dirfd = get64(env, cx.r_a);
    let path_addr = get64(env, cx.r_b);
    let flags = get64(env, cx.r_c) as u32;
    if !cx.is_at_fdcwd(dirfd) {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    open_at_cwd(sys, env, cx, path_addr, flags)
}

fn open_synth_bytes(
    sys: &mut Linux,
    env: &mut BareEnv,
    cx: &SysCtx,
    tag: &str,
    body: &[u8],
) -> Option<TrapOutcome> {
    let path =
        std::env::temp_dir().join(format!("polyisa-{tag}-{}-{}", std::process::id(), sys.pid));
    if std::fs::write(&path, body).is_err() {
        set64(env, Gpr(0), cx.neg(EACCES));
        return Some(TrapOutcome::Handled);
    }
    match std::fs::File::open(&path) {
        Ok(f) => {
            let fd = sys.alloc_fd(f);
            sys.remember_path(fd, path.to_string_lossy().into_owned());
            set64(env, Gpr(0), fd as u64);
            Some(TrapOutcome::Handled)
        }
        Err(_) => {
            set64(env, Gpr(0), cx.neg(ENOENT));
            Some(TrapOutcome::Handled)
        }
    }
}

fn open_synth_meminfo(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // sysinfo の固定値（1 GiB / 512 MiB）に揃えた kB 表記。
    open_synth_bytes(
        sys,
        env,
        cx,
        "meminfo",
        b"\
MemTotal:        1048576 kB
MemFree:          524288 kB
MemAvailable:     524288 kB
Buffers:               0 kB
Cached:                0 kB
SwapCached:            0 kB
SwapTotal:             0 kB
SwapFree:              0 kB
Shmem:                 0 kB
",
    )
}

fn open_synth_stat(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // iostat 用。CPU 1 個・全カウンタ 0。
    open_synth_bytes(
        sys,
        env,
        cx,
        "stat",
        b"\
cpu  0 0 0 0 0 0 0 0 0 0
cpu0 0 0 0 0 0 0 0 0 0 0
intr 0
ctxt 0
btime 946688400
processes 0
procs_running 1
procs_blocked 0
",
    )
}

fn open_synth_uptime(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    open_synth_bytes(sys, env, cx, "uptime", b"1000.00 1000.00\n")
}

fn open_synth_diskstats(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // major minor name ... 全 0。iostat の Device 行を固定する。
    open_synth_bytes(
        sys,
        env,
        cx,
        "diskstats",
        b"   8       0 sda 1 0 8 0 0 0 0 0 0 0 0 0 0 0 0\n",
    )
}

fn open_at_cwd(
    sys: &mut Linux,
    env: &mut BareEnv,
    cx: &SysCtx,
    path_addr: u64,
    flags: u32,
) -> Option<TrapOutcome> {
    const O_CLOEXEC: u32 = 0o2000000;
    let out = open_at_cwd_run(sys, env, cx, path_addr, flags);
    // O_CLOEXEC を割り当てた fd へ反映する。Handled で小さい返り値は
    // 新しい fd（エラーは負の errno で格納域の上限を越える）。
    if flags & O_CLOEXEC != 0 && matches!(out, Some(TrapOutcome::Handled)) {
        let ret = get64(env, Gpr(0));
        if ret < 1024 {
            sys.set_cloexec(ret as u32, true);
        }
    }
    out
}

fn open_at_cwd_run(
    sys: &mut Linux,
    env: &mut BareEnv,
    cx: &SysCtx,
    path_addr: u64,
    flags: u32,
) -> Option<TrapOutcome> {
    // 書込み・生成・切詰めを受け付ける。O_NONBLOCK/O_DIRECTORY/O_NOFOLLOW 等は無視する。
    // truncate/cp/split が O_WRONLY|O_CREAT 等で開く。Ref: SRC-LINUX (7.3).
    const O_ACCMODE: u32 = 3;
    const O_CREAT: u32 = 0o100;
    const O_EXCL: u32 = 0o200;
    const O_TRUNC: u32 = 0o1000;
    const O_APPEND: u32 = 0o2000;
    let acc = flags & O_ACCMODE;
    if acc > 2 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let path = match guest_c_string(env, path_addr) {
        Some(p) => p,
        None => {
            // NULL や読めないパスは Linux と同様 EFAULT。
            set64(env, Gpr(0), cx.neg(EFAULT));
            return Some(TrapOutcome::Handled);
        }
    };
    sys.ensure_cwd();
    let Some(path) = sys.resolve_path(&path) else {
        set64(env, Gpr(0), cx.neg(EPERM));
        return Some(TrapOutcome::Handled);
    };
    // ホストの /proc を見せると free/iostat の数値が揺らぐ。固定の合成ファイルを開く。
    if path == "/proc/meminfo" {
        return open_synth_meminfo(sys, env, cx);
    }
    if path == "/proc/stat" {
        return open_synth_stat(sys, env, cx);
    }
    if path == "/proc/uptime" {
        return open_synth_uptime(sys, env, cx);
    }
    if path == "/proc/diskstats" {
        return open_synth_diskstats(sys, env, cx);
    }
    if path == "/proc/loadavg" {
        return open_synth_bytes(sys, env, cx, "loadavg", b"0.00 0.00 0.00 1/1 1\n");
    }
    if path == "/proc/modules" {
        // lsmod。モジュール無しの固定表。
        return open_synth_bytes(sys, env, cx, "modules", b"");
    }
    if path == "/proc/sys/kernel/tainted" {
        return open_synth_bytes(sys, env, cx, "tainted", b"0\n");
    }
    if path == "/proc/net/route" {
        // route。宛先無しの見出しだけを出す入力。
        return open_synth_bytes(
            sys,
            env,
            cx,
            "netroute",
            b"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n",
        );
    }
    if path == "/proc/net/tcp"
        || path == "/proc/net/tcp6"
        || path == "/proc/net/udp"
        || path == "/proc/net/udp6"
        || path == "/proc/net/raw"
        || path == "/proc/net/raw6"
    {
        // netstat。接続無しの見出し行のみ。
        return open_synth_bytes(
            sys,
            env,
            cx,
            "nettcp",
            b"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
        );
    }
    if path == "/proc/net/unix" {
        return open_synth_bytes(
            sys,
            env,
            cx,
            "netunix",
            b"Num       RefCount Protocol Flags    Type St Inode Path\n",
        );
    }
    // lsscsi 用。ホストの SCSI 一覧は見せず、1 台だけ固定する。
    if let Some(rest) = path.strip_prefix("/sys/bus/scsi/devices/0:0:0:0/") {
        let body: &[u8] = match rest {
            "vendor" => b"PolyISA\n",
            "model" => b"Disk\n",
            "rev" => b"1.0\n",
            "type" => b"0\n",
            _ => b"",
        };
        if !body.is_empty() {
            return open_synth_bytes(sys, env, cx, "scsi", body);
        }
    }
    // ps / top / pstree 用。ホストの PID 一覧は見せず、pid 1 だけを固定する。
    if path == "/proc/1/stat"
        || path == "/proc/self/stat"
        || path == "/proc/1/task/1/stat"
        || path == "/proc/self/task/1/stat"
    {
        return open_synth_bytes(
            sys,
            env,
            cx,
            "pidstat",
            b"1 (init) S 0 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
        );
    }
    if path == "/proc/1/cmdline" || path == "/proc/self/cmdline" {
        return open_synth_bytes(sys, env, cx, "pidcmd", b"/sbin/init\0");
    }
    if path == "/proc/1/status" || path == "/proc/self/status" {
        return open_synth_bytes(
            sys,
            env,
            cx,
            "pidstatus",
            b"\
Name:\tinit
Uid:\t0\t0\t0\t0
Gid:\t0\t0\t0\t0
PPid:\t0
Threads:\t1
Cpus_allowed:\t1
Cpus_allowed_list:\t0
",
        );
    }
    if path == "/proc/1/comm" || path == "/proc/self/comm" {
        return open_synth_bytes(sys, env, cx, "pidcomm", b"init\n");
    }
    if path == "/proc/1/smaps"
        || path == "/proc/self/smaps"
        || path == "/proc/1/maps"
        || path == "/proc/self/maps"
    {
        // pmap は maps が無いとき見出しだけ出す（ホストの pid 1 も maps を読めない環境がある）。
        set64(env, Gpr(0), cx.neg(ENOENT));
        return Some(TrapOutcome::Handled);
    }
    if path == "/etc/hosts" {
        return open_synth_bytes(
            sys,
            env,
            cx,
            "hosts",
            b"127.0.0.1 localhost.localdomain localhost\n",
        );
    }
    // /proc/self/exe はゲスト実行ファイル自身を開く（ホスト exe ではない）。
    // readlink と同じ合成。書込み付きは Linux と同様に EACCES。
    if let Some(real) = guest_exe_redirect(&sys.exe_path, &path) {
        if acc != 0 || flags & (O_CREAT | O_TRUNC | O_APPEND) != 0 {
            set64(env, Gpr(0), cx.neg(EACCES));
            return Some(TrapOutcome::Handled);
        }
        return Some(match std::fs::File::open(&real) {
            Ok(f) => {
                let fd = sys.alloc_fd(f);
                sys.remember_path(fd, path);
                set64(env, Gpr(0), fd as u64);
                TrapOutcome::Handled
            }
            Err(e) => {
                let no = match e.kind() {
                    std::io::ErrorKind::NotFound => ENOENT,
                    std::io::ErrorKind::PermissionDenied => EACCES,
                    _ => EINVAL,
                };
                set64(env, Gpr(0), cx.neg(no));
                TrapOutcome::Handled
            }
        });
    }
    let want_write = acc != 0 || flags & (O_CREAT | O_TRUNC | O_APPEND) != 0;
    let opened = if want_write {
        let mut opts = std::fs::OpenOptions::new();
        opts.read(acc != 1);
        opts.write(true);
        if flags & O_CREAT != 0 {
            if flags & O_EXCL != 0 {
                opts.create_new(true);
            } else {
                opts.create(true);
            }
        }
        opts.truncate(flags & O_TRUNC != 0);
        opts.append(flags & O_APPEND != 0);
        opts.open(&path)
    } else {
        std::fs::File::open(&path)
    };
    Some(match opened {
        Ok(f) => {
            let fd = sys.alloc_fd(f);
            sys.remember_path(fd, path);
            set64(env, Gpr(0), fd as u64);
            TrapOutcome::Handled
        }
        Err(e) => {
            let no = match e.kind() {
                std::io::ErrorKind::NotFound => ENOENT,
                std::io::ErrorKind::PermissionDenied => EACCES,
                std::io::ErrorKind::AlreadyExists => 17,
                _ => EINVAL,
            };
            set64(env, Gpr(0), cx.neg(no));
            TrapOutcome::Handled
        }
    })
}

fn pipe_read(
    sys: &mut Linux,
    env: &mut BareEnv,
    cx: &SysCtx,
    end: (u64, bool),
    buf: u64,
    left: u64,
) -> Option<TrapOutcome> {
    if !end.1 {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    }
    if left == 0 {
        set64(env, Gpr(0), 0);
        return Some(TrapOutcome::Handled);
    }
    let max = usize::try_from(left.min(4096)).unwrap_or(0);
    let got = sys.fds.pipes().borrow_mut().read(end.0, max);
    match got {
        polyisa_kernel::PipeRead::Bytes(bytes) => {
            if env.backend.mem.write(VirtAddr(buf), &bytes).is_err() {
                return Some(TrapOutcome::Unimplemented);
            }
            set64(env, Gpr(0), bytes.len() as u64);
            Some(TrapOutcome::Handled)
        }
        polyisa_kernel::PipeRead::Eof => {
            set64(env, Gpr(0), 0);
            Some(TrapOutcome::Handled)
        }
        polyisa_kernel::PipeRead::Empty => {
            let id = sys.ensure_self();
            sys.pipe_wait = Some(end.0);
            sys.queue.0.borrow_mut().meta.block(
                polyisa_kernel::ThreadId(id.0),
                polyisa_kernel::ThreadWait::Pipe { id: end.0 },
            );
            Some(TrapOutcome::Blocked)
        }
    }
}

fn pipe_write(
    sys: &mut Linux,
    env: &mut BareEnv,
    cx: &SysCtx,
    end: (u64, bool),
    buf: u64,
    left: u64,
) -> Option<TrapOutcome> {
    if end.1 {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    }
    if left == 0 {
        set64(env, Gpr(0), 0);
        return Some(TrapOutcome::Handled);
    }
    let take = usize::try_from(left.min(4096)).unwrap_or(0);
    let mut chunk = vec![0u8; take];
    if env
        .backend
        .mem
        .read(VirtAddr(buf), &mut chunk, data_access())
        .is_err()
    {
        return Some(TrapOutcome::Unimplemented);
    }
    let wrote = sys.fds.pipes().borrow_mut().write(end.0, &chunk);
    match wrote {
        None => {
            set64(env, Gpr(0), cx.neg(EPIPE));
            Some(TrapOutcome::Handled)
        }
        Some(n) => {
            sys.wake_pipe(end.0);
            set64(env, Gpr(0), n as u64);
            Some(TrapOutcome::Handled)
        }
    }
}

fn sys_pipe(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // pipe(pipefd)。pipe2 の flags=0 と同じ。zcat が使う。
    open_pipe(sys, env, cx, 0)
}

fn sys_pipe2(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let flags = get64(env, cx.r_b);
    open_pipe(sys, env, cx, flags)
}

fn open_pipe(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx, flags: u64) -> Option<TrapOutcome> {
    let addr = get64(env, cx.r_a);
    const O_NONBLOCK: u64 = 0o4000;
    const O_CLOEXEC: u64 = 0o2000000;
    if flags & !(O_NONBLOCK | O_CLOEXEC) != 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let (rd, wr) = sys.fds.pipe_pair();
    let read_fd = sys.alloc_target(rd);
    let write_fd = sys.alloc_target(wr);
    if flags & O_NONBLOCK != 0 {
        let _ = sys.fds.set_nonblock(read_fd, true);
        let _ = sys.fds.set_nonblock(write_fd, true);
    }
    if flags & O_CLOEXEC != 0 {
        sys.set_cloexec(read_fd, true);
        sys.set_cloexec(write_fd, true);
    }
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&read_fd.to_le_bytes());
    bytes[4..].copy_from_slice(&write_fd.to_le_bytes());
    if env.backend.mem.write(VirtAddr(addr), &bytes).is_err() {
        sys.close_fd(read_fd);
        sys.close_fd(write_fd);
        set64(env, Gpr(0), cx.neg(EFAULT));
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

fn sys_read(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let fd = get64(env, cx.r_a) as u32;
    let buf = get64(env, cx.r_b);
    let mut left = get64(env, cx.r_c);
    if let Some(end) = sys.pipe_end(fd) {
        return pipe_read(sys, env, cx, end, buf, left);
    }
    // 付け替えた標準 fd はファイルから読む。真の stdin は供給バッファから読む。
    // dup2(0,n) で stdin を指す fd も同様。
    let stdin_empty =
        (fd == 0 || (fd < 3 && sys.std_is_stdin[fd as usize])) && sys.std_attached(fd);
    if stdin_empty {
        let mut done = 0u64;
        let mut chunk = vec![0u8; IO_CHUNK];
        while left > 0 {
            let take = left.min(IO_CHUNK as u64) as usize;
            let n = sys.take_stdin(&mut chunk[..take]);
            if n == 0 {
                break;
            }
            if env
                .backend
                .mem
                .write(VirtAddr(buf + done), &chunk[..n])
                .is_err()
            {
                return Some(TrapOutcome::Unimplemented);
            }
            done += n as u64;
            left -= n as u64;
            if n < take {
                break;
            }
        }
        set64(env, Gpr(0), done);
        return Some(TrapOutcome::Handled);
    }
    let Some(file) = sys.file_mut(fd) else {
        return fd_read_other(sys, env, cx, fd, buf, left);
    };
    let mut done = 0u64;
    let mut chunk = vec![0u8; IO_CHUNK];
    while left > 0 {
        let take = left.min(IO_CHUNK as u64) as usize;
        let n = match std::io::Read::read(file, &mut chunk[..take]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        if env
            .backend
            .mem
            .write(VirtAddr(buf + done), &chunk[..n])
            .is_err()
        {
            return Some(TrapOutcome::Unimplemented);
        }
        done += n as u64;
        left -= n as u64;
        if n < take {
            break;
        }
    }
    set64(env, Gpr(0), done);
    Some(TrapOutcome::Handled)
}

/// ファイル・パイプ端・stdin 以外の対象の read。fd 表の対象別
/// 実装へ流し、阻止で読めなければ待ちを張る。
fn fd_read_other(
    sys: &mut Linux,
    env: &mut BareEnv,
    cx: &SysCtx,
    fd: u32,
    buf: u64,
    left: u64,
) -> Option<TrapOutcome> {
    use polyisa_kernel::FdRead;
    if sys.fds.target(fd).is_none() {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    }
    let max = usize::try_from(left.min(IO_CHUNK as u64)).unwrap_or(0);
    // TimerFd は ready が catch_up を進める。
    let _ = sys.fds.ready(fd, sys.mono_ns(), sys.sig_pending);
    match sys.fds.read(fd, max) {
        FdRead::Bytes(bytes) => {
            if env.backend.mem.write(VirtAddr(buf), &bytes).is_err() {
                return Some(TrapOutcome::Unimplemented);
            }
            set64(env, Gpr(0), bytes.len() as u64);
            Some(TrapOutcome::Handled)
        }
        FdRead::Count(v) => {
            if env
                .backend
                .mem
                .write(VirtAddr(buf), &v.to_le_bytes())
                .is_err()
            {
                return Some(TrapOutcome::Unimplemented);
            }
            set64(env, Gpr(0), 8);
            Some(TrapOutcome::Handled)
        }
        FdRead::Eof => {
            set64(env, Gpr(0), 0);
            Some(TrapOutcome::Handled)
        }
        FdRead::Empty if sys.fds.nonblock(fd) => {
            set64(env, Gpr(0), cx.neg(EAGAIN));
            Some(TrapOutcome::Handled)
        }
        FdRead::Empty => {
            let r = crate::wait::read_wait(&sys.fds, fd)
                .map(crate::sock::Out::Wait)
                .ok_or(EAGAIN);
            sys.sock_finish(env, r)
        }
        FdRead::IsDir => {
            set64(env, Gpr(0), cx.neg(EISDIR));
            Some(TrapOutcome::Handled)
        }
        FdRead::BadFd => {
            set64(env, Gpr(0), cx.neg(EBADF));
            Some(TrapOutcome::Handled)
        }
        FdRead::Inval => {
            set64(env, Gpr(0), cx.neg(EINVAL));
            Some(TrapOutcome::Handled)
        }
        FdRead::Host(e) => {
            set64(
                env,
                Gpr(0),
                cx.neg(e.raw_os_error().unwrap_or(EIO as i32) as u32),
            );
            Some(TrapOutcome::Handled)
        }
    }
}

/// ファイル・パイプ端・stdio 以外の対象の write。eventfd への
/// カウンタ書き込み（8 バイト）も `fd 表` が裁く。
fn fd_write_other(
    sys: &mut Linux,
    env: &mut BareEnv,
    cx: &SysCtx,
    fd: u32,
    buf: u64,
    left: u64,
) -> Option<TrapOutcome> {
    use polyisa_kernel::FdWrite;
    let is_eventfd = matches!(
        sys.fds.target(fd),
        Some(polyisa_kernel::FdTarget::EventFd(_))
    );
    if sys.fds.target(fd).is_none() {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    }
    let take = usize::try_from(left.min(IO_CHUNK as u64)).unwrap_or(0);
    // eventfd の write は 8 バイトのカウンタ加算（LE 復元）。
    if is_eventfd {
        if take != 8 {
            set64(env, Gpr(0), cx.neg(EINVAL));
            return Some(TrapOutcome::Handled);
        }
        let mut chunk = [0u8; 8];
        if env
            .backend
            .mem
            .read(VirtAddr(buf), &mut chunk, data_access())
            .is_err()
        {
            return Some(TrapOutcome::Unimplemented);
        }
        let v = u64::from_le_bytes(chunk);
        return match sys.fds.write_eventfd(fd, v) {
            FdWrite::Done(n) => {
                set64(env, Gpr(0), n as u64);
                Some(TrapOutcome::Handled)
            }
            FdWrite::Full if sys.fds.nonblock(fd) => {
                set64(env, Gpr(0), cx.neg(EAGAIN));
                Some(TrapOutcome::Handled)
            }
            FdWrite::Full => {
                let r = crate::wait::write_wait(&sys.fds, fd)
                    .map(crate::sock::Out::Wait)
                    .ok_or(EAGAIN);
                sys.sock_finish(env, r)
            }
            FdWrite::BadFd => {
                set64(env, Gpr(0), cx.neg(EBADF));
                Some(TrapOutcome::Handled)
            }
            _ => {
                set64(env, Gpr(0), cx.neg(EIO));
                Some(TrapOutcome::Handled)
            }
        };
    }
    let mut chunk = vec![0u8; take];
    if env
        .backend
        .mem
        .read(VirtAddr(buf), &mut chunk, data_access())
        .is_err()
    {
        return Some(TrapOutcome::Unimplemented);
    }
    match sys.fds.write(fd, &chunk) {
        FdWrite::Done(n) => {
            set64(env, Gpr(0), n as u64);
            Some(TrapOutcome::Handled)
        }
        FdWrite::Pipe => {
            set64(env, Gpr(0), cx.neg(EPIPE));
            Some(TrapOutcome::Handled)
        }
        FdWrite::Full if sys.fds.nonblock(fd) => {
            set64(env, Gpr(0), cx.neg(EAGAIN));
            Some(TrapOutcome::Handled)
        }
        FdWrite::Full => {
            let r = crate::wait::write_wait(&sys.fds, fd)
                .map(crate::sock::Out::Wait)
                .ok_or(EAGAIN);
            sys.sock_finish(env, r)
        }
        FdWrite::BadFd => {
            set64(env, Gpr(0), cx.neg(EBADF));
            Some(TrapOutcome::Handled)
        }
        FdWrite::Inval => {
            set64(env, Gpr(0), cx.neg(EINVAL));
            Some(TrapOutcome::Handled)
        }
        FdWrite::Host(e) => {
            set64(
                env,
                Gpr(0),
                cx.neg(e.raw_os_error().unwrap_or(EIO as i32) as u32),
            );
            Some(TrapOutcome::Handled)
        }
    }
}

fn sys_close(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 標準 fd の close も成功させる。uniq は stdin を閉じて開き直す.
    let fd = get64(env, cx.r_a) as u32;
    Some(if sys.close_fd(fd) {
        set64(env, Gpr(0), 0);
        TrapOutcome::Handled
    } else {
        set64(env, Gpr(0), cx.neg(EBADF));
        TrapOutcome::Handled
    })
}

fn sys_write(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let fd = get64(env, cx.r_a) as u32;
    let buf = get64(env, cx.r_b);
    let mut left = get64(env, cx.r_c);
    if let Some(end) = sys.pipe_end(fd) {
        return pipe_write(sys, env, cx, end, buf, left);
    }
    // dup2(0,n) で stdin を指す fd への write は EBADF（O_RDONLY）。
    if fd < 3 && sys.std_is_stdin[fd as usize] {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    }
    if (fd == 1 || fd == 2) && sys.std_targets[fd as usize].is_none() {
        let mut done = 0u64;
        let mut chunk = vec![0u8; IO_CHUNK];
        while left > 0 {
            let take = left.min(IO_CHUNK as u64) as usize;
            if env
                .backend
                .mem
                .read(VirtAddr(buf + done), &mut chunk[..take], data_access())
                .is_err()
            {
                return Some(TrapOutcome::Unimplemented);
            }
            let n = sys.write_stdio(fd, &chunk[..take]);
            done += n as u64;
            left -= n as u64;
            if n < take {
                break;
            }
        }
        set64(env, Gpr(0), done);
        return Some(TrapOutcome::Handled);
    }
    // 開ファイル (opened fd・付け替え先。dup2 で stdout に置いた出力先を含む)
    // への write はホストに書く。読取り専用で開いた場合は EBADF になる。
    let Some(file) = sys.file_mut(fd) else {
        return fd_write_other(sys, env, cx, fd, buf, left);
    };
    let mut done = 0u64;
    let mut chunk = vec![0u8; IO_CHUNK];
    let mut err_no: Option<u32> = None;
    while left > 0 {
        let take = left.min(IO_CHUNK as u64) as usize;
        if env
            .backend
            .mem
            .read(VirtAddr(buf + done), &mut chunk[..take], data_access())
            .is_err()
        {
            return Some(TrapOutcome::Unimplemented);
        }
        match std::io::Write::write(file, &chunk[..take]) {
            Ok(0) => break,
            Ok(n) => {
                done += n as u64;
                left -= n as u64;
                if n < take {
                    break;
                }
            }
            Err(e) => {
                err_no = Some(match e.raw_os_error() {
                    Some(9) => EBADF,
                    Some(13) => EACCES,
                    _ => EINVAL,
                });
                break;
            }
        }
    }
    if done == 0 {
        if let Some(no) = err_no {
            set64(env, Gpr(0), cx.neg(no));
        } else {
            set64(env, Gpr(0), 0);
        }
    } else {
        set64(env, Gpr(0), done);
    }
    Some(TrapOutcome::Handled)
}

fn writev_opened(
    sys: &mut Linux,
    env: &mut BareEnv,
    cx: &SysCtx,
    fd: u32,
    iov: u64,
    iovcnt: u64,
) -> Option<TrapOutcome> {
    // 開いたファイルへの writev。dos2unix は一時ファイルへ stdio の writev で書く。
    const IOV_MAX: u64 = 1024;
    if sys.file_ref(fd).is_none() {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    }
    if iovcnt > IOV_MAX {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let mut done = 0u64;
    let mut chunk = vec![0u8; IO_CHUNK];
    for idx in 0..iovcnt {
        let (base, len) = if cx.is64 && !cx.x32 {
            let mut ent = [0u8; 16];
            if env
                .backend
                .mem
                .read(VirtAddr(iov + idx * 16), &mut ent, data_access())
                .is_err()
            {
                return Some(TrapOutcome::Unimplemented);
            }
            (
                u64::from_le_bytes(ent[..8].try_into().unwrap()),
                u64::from_le_bytes(ent[8..].try_into().unwrap()),
            )
        } else {
            let mut ent = [0u8; 8];
            if env
                .backend
                .mem
                .read(VirtAddr(iov + idx * 8), &mut ent, data_access())
                .is_err()
            {
                return Some(TrapOutcome::Unimplemented);
            }
            (
                u64::from(u32::from_le_bytes(ent[..4].try_into().unwrap())),
                u64::from(u32::from_le_bytes(ent[4..].try_into().unwrap())),
            )
        };
        let mut left = len;
        let mut off = 0u64;
        while left > 0 {
            let take = left.min(IO_CHUNK as u64) as usize;
            if env
                .backend
                .mem
                .read(VirtAddr(base + off), &mut chunk[..take], data_access())
                .is_err()
            {
                return Some(TrapOutcome::Unimplemented);
            }
            let file = sys.file_mut(fd).expect("opened fd");
            match std::io::Write::write(file, &chunk[..take]) {
                Ok(0) => {
                    set64(env, Gpr(0), done);
                    return Some(TrapOutcome::Handled);
                }
                Ok(n) => {
                    done += n as u64;
                    left -= n as u64;
                    off += n as u64;
                    if n < take {
                        set64(env, Gpr(0), done);
                        return Some(TrapOutcome::Handled);
                    }
                }
                Err(e) => {
                    if done == 0 {
                        let no = match e.raw_os_error() {
                            Some(9) => EBADF,
                            Some(13) => EACCES,
                            _ => EINVAL,
                        };
                        set64(env, Gpr(0), cx.neg(no));
                    } else {
                        set64(env, Gpr(0), done);
                    }
                    return Some(TrapOutcome::Handled);
                }
            }
        }
    }
    set64(env, Gpr(0), done);
    Some(TrapOutcome::Handled)
}

fn sys_writev(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // writev/readv (x86-64: 20/19, x86-32: 146/145)。iovec 配列を辿って転送する.
    // fd 1/2 は標準出力へ、開いたファイルはホストのファイルへ書く。
    let fd = get64(env, cx.r_a) as u32;
    let iov = get64(env, cx.r_b);
    let iovcnt = get64(env, cx.r_c);
    // dup2(0,n) で stdin を指す fd への writev は EBADF（O_RDONLY）。
    if fd < 3 && sys.std_is_stdin[fd as usize] {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    }
    // 付け替えた標準 fd への writev は開ファイルへ書く（sys_write と同じ）。
    // 読取り専用で開いた場合は writev_opened が EBADF を返す。
    if (fd == 1 || fd == 2) && sys.std_targets[fd as usize].is_some() {
        return writev_opened(sys, env, cx, fd, iov, iovcnt);
    }
    if fd != 1 && fd != 2 {
        return writev_opened(sys, env, cx, fd, iov, iovcnt);
    }
    const IOV_MAX: u64 = 1024;
    if iovcnt > IOV_MAX {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let mut done = 0u64;
    let mut chunk = vec![0u8; IO_CHUNK];
    for idx in 0..iovcnt {
        let (base, len) = if cx.is64 && !cx.x32 {
            let mut ent = [0u8; 16];
            if env
                .backend
                .mem
                .read(VirtAddr(iov + idx * 16), &mut ent, data_access())
                .is_err()
            {
                return Some(TrapOutcome::Unimplemented);
            }
            (
                u64::from_le_bytes(ent[..8].try_into().unwrap()),
                u64::from_le_bytes(ent[8..].try_into().unwrap()),
            )
        } else {
            let mut ent = [0u8; 8];
            if env
                .backend
                .mem
                .read(VirtAddr(iov + idx * 8), &mut ent, data_access())
                .is_err()
            {
                return Some(TrapOutcome::Unimplemented);
            }
            (
                u64::from(u32::from_le_bytes(ent[..4].try_into().unwrap())),
                u64::from(u32::from_le_bytes(ent[4..].try_into().unwrap())),
            )
        };
        let mut left = len;
        let mut off = 0u64;
        while left > 0 {
            let take = left.min(IO_CHUNK as u64) as usize;
            if env
                .backend
                .mem
                .read(VirtAddr(base + off), &mut chunk[..take], data_access())
                .is_err()
            {
                return Some(TrapOutcome::Unimplemented);
            }
            let n = sys.write_stdio(fd, &chunk[..take]);
            done += n as u64;
            left -= n as u64;
            off += n as u64;
            if n < take {
                break;
            }
        }
    }
    set64(env, Gpr(0), done);
    Some(TrapOutcome::Handled)
}

fn sys_readv(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let fd = get64(env, cx.r_a) as u32;
    let iov = get64(env, cx.r_b);
    let iovcnt = get64(env, cx.r_c);
    const IOV_MAX: u64 = 1024;
    if iovcnt > IOV_MAX {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    // 付け替えた標準 fd はファイルから読む。真の stdin は空読みのまま.
    // dup2(0,n) で stdin を指す fd も同様。
    let empty_stdin =
        (fd == 0 || (fd < 3 && sys.std_is_stdin[fd as usize])) && sys.std_attached(fd);
    if !empty_stdin && sys.file_ref(fd).is_none() {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    }
    let mut done = 0u64;
    let mut chunk = vec![0u8; IO_CHUNK];
    for idx in 0..iovcnt {
        let (base, len) = if cx.is64 && !cx.x32 {
            let mut ent = [0u8; 16];
            if env
                .backend
                .mem
                .read(VirtAddr(iov + idx * 16), &mut ent, data_access())
                .is_err()
            {
                return Some(TrapOutcome::Unimplemented);
            }
            (
                u64::from_le_bytes(ent[..8].try_into().unwrap()),
                u64::from_le_bytes(ent[8..].try_into().unwrap()),
            )
        } else {
            let mut ent = [0u8; 8];
            if env
                .backend
                .mem
                .read(VirtAddr(iov + idx * 8), &mut ent, data_access())
                .is_err()
            {
                return Some(TrapOutcome::Unimplemented);
            }
            (
                u64::from(u32::from_le_bytes(ent[..4].try_into().unwrap())),
                u64::from(u32::from_le_bytes(ent[4..].try_into().unwrap())),
            )
        };
        let mut left = len;
        let mut off = 0u64;
        while left > 0 {
            let take = left.min(IO_CHUNK as u64) as usize;
            let n = if empty_stdin {
                sys.take_stdin(&mut chunk[..take])
            } else {
                let f = sys.file_mut(fd).unwrap();
                match std::io::Read::read(f, &mut chunk[..take]) {
                    Ok(0) => 0,
                    Ok(n) => n,
                    Err(_) => 0,
                }
            };
            if n == 0 {
                break;
            }
            if env
                .backend
                .mem
                .write(VirtAddr(base + off), &chunk[..n])
                .is_err()
            {
                return Some(TrapOutcome::Unimplemented);
            }
            done += n as u64;
            left -= n as u64;
            off += n as u64;
            if n < take {
                break;
            }
        }
        // 真の stdin は空読みとして次へ進む.
        if empty_stdin {
            continue;
        }
    }
    set64(env, Gpr(0), done);
    Some(TrapOutcome::Handled)
}

fn sys_exit(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let code = get64(env, cx.r_a) as u32;
    if sys.pid != 0 {
        sys.procs
            .borrow_mut()
            .exit(polyisa_kernel::ProcessId(sys.pid), code);
    }
    Some(TrapOutcome::Exit(code))
}

fn sys_exit_group(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_exit(sys, env, cx)
}

fn sys_mmap(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_mmap(&mut sys.mmap_base, env, cx)
}

fn sys_set_tid_address(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    let me = sys.ensure_self().0;
    crate::x86::sys_set_tid_address(me, env, cx)
}

fn sys_set_thread_area(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // set_thread_area(user_desc*)。entry_number=-1 のとき最初の TLS スロット 6 を
    // 割り当てて書き戻し、base_addr を GS ベースとして記憶する。i386 musl の TLS 初期化.
    // Ref: SRC-LINUX (7.3).
    let u = get64(env, cx.r_a);
    let mut desc = [0u8; 8];
    if env
        .backend
        .mem
        .read(VirtAddr(u), &mut desc, data_access())
        .is_err()
    {
        set64(env, Gpr(0), cx.neg(EFAULT));
        return Some(TrapOutcome::Handled);
    }
    if u32::from_le_bytes(desc[0..4].try_into().unwrap()) == u32::MAX
        && env
            .backend
            .mem
            .write(VirtAddr(u), &6u32.to_le_bytes())
            .is_err()
    {
        set64(env, Gpr(0), cx.neg(EFAULT));
        return Some(TrapOutcome::Handled);
    }
    env.backend.set(
        polyisa_guest_x86::sem::gs_base_ref(),
        u64::from(u32::from_le_bytes(desc[4..8].try_into().unwrap())),
    );
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

fn sys_gettid(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    let me = sys.ensure_self().0;
    crate::x86::sys_gettid(me, env, cx)
}

fn sys_getpid(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    let me = sys.ensure_self().0;
    crate::x86::sys_getpid(me, env, cx)
}

fn sys_getppid(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    let me = sys.ensure_self().0;
    let borrowed = sys.procs.borrow();
    crate::x86::sys_getppid(&borrowed, me, env, cx)
}

fn sys_sysinfo(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_sysinfo(env, cx)
}

fn sys_reboot(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_reboot(env, cx)
}

fn sys_init_module(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_init_module(env, cx)
}

fn sys_delete_module(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_delete_module(env, cx)
}

fn sys_finit_module(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_finit_module(env, cx)
}

fn sys_swapon(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_swapon(env, cx)
}

fn sys_swapoff(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_swapoff(env, cx)
}

fn sys_pivot_root(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_pivot_root(env, cx)
}

fn sys_umount2(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    sys.ensure_cwd();
    let root = sys.guest_root.clone();
    let cwd = sys.cwd.clone();
    crate::x86::sys_umount2(&root, &cwd, env, cx)
}

fn sys_flock(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_flock(env, cx)
}

fn sys_shmget(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_shmget(env, cx)
}

fn sys_shmctl(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_shmctl(env, cx)
}

fn sys_semget(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_semget(env, cx)
}

fn sys_semctl(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_semctl(env, cx)
}

fn sys_msgget(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_msgget(env, cx)
}

fn sys_msgctl(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_msgctl(env, cx)
}

fn sys_getitimer(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_getitimer(env, cx)
}

fn sys_setitimer(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_setitimer(env, cx)
}

fn sys_socket(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 正準層は os-linux::sock。引数は rbx/rcx/rdx（i386 は socketcall 経由）。
    let abi = sys.sock_abi();
    let r = crate::sock::sys_socket(
        &mut sys.fds,
        &abi,
        get64(env, cx.r_a),
        get64(env, cx.r_b),
        get64(env, cx.r_c),
    )
    .map(crate::sock::Out::Done);
    sys.sock_finish(env, r)
}

fn sys_socketpair(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let abi = sys.sock_abi();
    let (a, b, c, d) = (
        get64(env, cx.r_a),
        get64(env, cx.r_b),
        get64(env, cx.r_c),
        get64(env, cx.r_d),
    );
    let r = crate::sock::sys_socketpair(&mut sys.fds, &abi, env, a, b, c, d)
        .map(crate::sock::Out::Done);
    sys.sock_finish(env, r)
}

fn sys_bind(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let abi = sys.sock_abi();
    let map = sys.unix_path_map();
    #[cfg(unix)]
    {
        let (a, b, c) = (get64(env, cx.r_a), get64(env, cx.r_b), get64(env, cx.r_c));
        let r = crate::sock::sys_bind(&mut sys.fds, &abi, env, a, b, c, &map)
            .map(crate::sock::Out::Done);
        sys.sock_finish(env, r)
    }
    #[cfg(not(unix))]
    {
        let _ = (abi, map, env, cx);
        Some(TrapOutcome::Unimplemented)
    }
}

fn sys_connect(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let abi = sys.sock_abi();
    let map = sys.unix_path_map();
    #[cfg(unix)]
    {
        let (a, b, c) = (get64(env, cx.r_a), get64(env, cx.r_b), get64(env, cx.r_c));
        let r = crate::sock::sys_connect(&mut sys.fds, &abi, env, a, b, c, &map);
        sys.sock_finish(env, r)
    }
    #[cfg(not(unix))]
    {
        let _ = (abi, map, env, cx);
        Some(TrapOutcome::Unimplemented)
    }
}

fn sys_listen(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let abi = sys.sock_abi();
    #[cfg(unix)]
    {
        let (a, b) = (get64(env, cx.r_a), get64(env, cx.r_b));
        let r = crate::sock::sys_listen(&mut sys.fds, &abi, a, b).map(crate::sock::Out::Done);
        sys.sock_finish(env, r)
    }
    #[cfg(not(unix))]
    {
        let _ = (abi, env, cx);
        Some(TrapOutcome::Unimplemented)
    }
}

fn sys_accept(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys.accept_impl(env, cx, 0)
}

fn sys_accept4(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let flags = get64(env, cx.r_d);
    sys.accept_impl(env, cx, flags)
}

fn sys_getpeername(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys.getname_impl(env, cx, true)
}

fn sys_shutdown(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let abi = sys.sock_abi();
    let (a, b) = (get64(env, cx.r_a), get64(env, cx.r_b));
    let r = crate::sock::sys_shutdown(&mut sys.fds, &abi, a, b).map(crate::sock::Out::Done);
    sys.sock_finish(env, r)
}

fn sys_setsockopt(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let abi = sys.sock_abi();
    #[cfg(unix)]
    {
        let (a, b, c, d, e) = (
            get64(env, cx.r_a),
            get64(env, cx.r_b),
            get64(env, cx.r_c),
            get64(env, cx.r_d),
            get64(env, cx.r_e),
        );
        let r = crate::sock::sys_setsockopt(&mut sys.fds, &abi, env, a, b, c, d, e)
            .map(crate::sock::Out::Done);
        sys.sock_finish(env, r)
    }
    #[cfg(not(unix))]
    {
        let _ = (abi, env, cx);
        Some(TrapOutcome::Unimplemented)
    }
}

fn sys_getsockopt(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let abi = sys.sock_abi();
    #[cfg(unix)]
    {
        let (a, b, c, d, e) = (
            get64(env, cx.r_a),
            get64(env, cx.r_b),
            get64(env, cx.r_c),
            get64(env, cx.r_d),
            get64(env, cx.r_e),
        );
        let r = crate::sock::sys_getsockopt(&mut sys.fds, &abi, env, a, b, c, d, e)
            .map(crate::sock::Out::Done);
        sys.sock_finish(env, r)
    }
    #[cfg(not(unix))]
    {
        let _ = (abi, env, cx);
        Some(TrapOutcome::Unimplemented)
    }
}

fn sys_sendto(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let abi = sys.sock_abi();
    let map = sys.unix_path_map();
    let (a, b, c, d, e, f) = (
        get64(env, cx.r_a),
        get64(env, cx.r_b),
        get64(env, cx.r_c),
        get64(env, cx.r_d),
        get64(env, cx.r_e),
        get64(env, cx.r_f),
    );
    let r = crate::sock::sys_sendto(&mut sys.fds, &abi, env, a, b, c, d, e, f, &map);
    sys.sock_finish(env, r)
}

fn sys_recvfrom(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let abi = sys.sock_abi();
    let (a, b, c, d, e, f) = (
        get64(env, cx.r_a),
        get64(env, cx.r_b),
        get64(env, cx.r_c),
        get64(env, cx.r_d),
        get64(env, cx.r_e),
        get64(env, cx.r_f),
    );
    let r = crate::sock::sys_recvfrom(&mut sys.fds, &abi, env, a, b, c, d, e, f);
    sys.sock_finish(env, r)
}

fn sys_sendmsg(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let abi = sys.sock_abi();
    let map = sys.unix_path_map();
    let (a, b, c) = (get64(env, cx.r_a), get64(env, cx.r_b), get64(env, cx.r_c));
    let r = crate::sock::sys_sendmsg(&mut sys.fds, &abi, env, a, b, c, &map);
    sys.sock_finish(env, r)
}

fn sys_recvmsg(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let abi = sys.sock_abi();
    let (a, b, c) = (get64(env, cx.r_a), get64(env, cx.r_b), get64(env, cx.r_c));
    let r = crate::sock::sys_recvmsg(&mut sys.fds, &abi, env, a, b, c);
    sys.sock_finish(env, r)
}

fn sys_getsockname(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys.getname_impl(env, cx, false)
}

/// i386 系の socketcall(call, args)。副番号は sock::call。
fn sys_socketcall(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let abi = sys.sock_abi();
    let map = sys.unix_path_map();
    let (a, b) = (get64(env, cx.r_a), get64(env, cx.r_b));
    let r = crate::sock::sys_socketcall(&mut sys.fds, &abi, env, a, b, &map);
    sys.sock_finish(env, r)
}

fn sys_setxattr(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    sys.ensure_cwd();
    let root = sys.guest_root.clone();
    let cwd = sys.cwd.clone();
    crate::x86::sys_setxattr(&root, &cwd, env, cx)
}

fn sys_lsetxattr(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層。
    // lsetxattr はシンボリックリンク自体に付けるが、試作では区別しない。
    sys.ensure_cwd();
    let root = sys.guest_root.clone();
    let cwd = sys.cwd.clone();
    crate::x86::sys_lsetxattr(&root, &cwd, env, cx)
}

fn sys_fsetxattr(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_fsetxattr(env, cx)
}

fn sys_mount(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    sys.ensure_cwd();
    let root = sys.guest_root.clone();
    let cwd = sys.cwd.clone();
    crate::x86::sys_mount(&root, &cwd, env, cx)
}

fn sys_sysfs(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_sysfs(env, cx)
}

fn sys_tkill(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // tkill(tid, sig)。tgkill と同様に、自分宛てでハンドラが
    // あれば保留に積む。
    let sig = get64(env, cx.r_b);
    if sig > 64 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    if sig > 0 {
        let me = sys.ensure_self();
        let tid = get64(env, cx.r_a);
        if tid == me.0
            && sys
                .sigacts
                .get(sig as usize - 1)
                .is_some_and(|a| a.handler > 1)
        {
            sys.sig_pending |= 1 << (sig - 1);
        }
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

fn sys_inotify_init1(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_inotify_init1(env, cx)
}

fn sys_inotify_init(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は os-linux に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_inotify_init(env, cx)
}

fn sys_inotify_add_watch(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_inotify_add_watch(env, cx)
}

fn sys_adjtimex(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_adjtimex(env, cx)
}

fn sys_setuid(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_setuid(env, cx)
}

fn sys_setgid(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は os-linux に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_setgid(env, cx)
}

fn sys_setreuid(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は os-linux に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_setreuid(env, cx)
}

fn sys_setregid(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は os-linux に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_setregid(env, cx)
}

fn sys_setresuid(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は os-linux に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_setresuid(env, cx)
}

fn sys_setresgid(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は os-linux に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_setresgid(env, cx)
}

fn sys_syslog(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_syslog(env, cx)
}

fn sys_setpgid(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    let me = sys.ensure_self().0;
    let mut borrowed = sys.procs.borrow_mut();
    crate::x86::sys_setpgid(&mut borrowed, me, env, cx)
}

fn sys_setsid(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    let me = sys.ensure_self().0;
    let mut borrowed = sys.procs.borrow_mut();
    crate::x86::sys_setsid(&mut borrowed, me, env, cx)
}

fn sys_getpriority(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_getpriority(env, cx)
}

fn sys_setpriority(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_setpriority(env, cx)
}

fn sys_personality(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    let mut v = sys.personality;
    let r = crate::x86::sys_personality(&mut v, env, cx);
    sys.personality = v;
    r
}

fn sys_ioprio_set(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // ioprio_set(which, who, ioprio)。実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    let me = sys.ensure_self().0;
    let mut io = crate::x86::IoPriority {
        prio: sys.ioprio,
        known: sys.ioprio_known,
    };
    let r = crate::x86::sys_ioprio_set(&mut io, me, env, cx);
    sys.ioprio = io.prio;
    sys.ioprio_known = io.known;
    r
}

fn sys_ioprio_get(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // ioprio_get(which, who)。実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    let me = sys.ensure_self().0;
    let io = crate::x86::IoPriority {
        prio: sys.ioprio,
        known: sys.ioprio_known,
    };
    crate::x86::sys_ioprio_get(&io, me, env, cx)
}

fn sys_fsync(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    // 有効性判定は状態を束ねる cli 側、実処理は os-linux 側.
    let fd = get64(env, cx.r_a) as u32;
    let valid = sys.fd_valid(fd);
    crate::x86::sys_fsync(valid, env, cx)
}

fn sys_fdatasync(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    // 有効性判定は状態を束ねる cli 側、実処理は os-linux 側.
    let fd = get64(env, cx.r_a) as u32;
    let valid = sys.fd_valid(fd);
    crate::x86::sys_fdatasync(valid, env, cx)
}

fn sys_unshare(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_unshare(env, cx)
}

fn sys_sched_setaffinity(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    let me = sys.ensure_self().0;
    crate::x86::sys_sched_setaffinity(me, env, cx)
}

fn sys_sched_get_priority_max(
    _sys: &mut Linux,
    env: &mut BareEnv,
    cx: &SysCtx,
) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_sched_get_priority_max(env, cx)
}

fn sys_sched_get_priority_min(
    _sys: &mut Linux,
    env: &mut BareEnv,
    cx: &SysCtx,
) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_sched_get_priority_min(env, cx)
}

fn sys_sched_getscheduler(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    let me = sys.ensure_self().0;
    crate::x86::sys_sched_getscheduler(me, env, cx)
}

fn sys_sched_setscheduler(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    let me = sys.ensure_self().0;
    crate::x86::sys_sched_setscheduler(me, env, cx)
}

fn sys_sched_setparam(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    let me = sys.ensure_self().0;
    crate::x86::sys_sched_setparam(me, env, cx)
}

fn sys_sched_getparam(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    let me = sys.ensure_self().0;
    crate::x86::sys_sched_getparam(me, env, cx)
}

fn sys_getpgid(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    let me = sys.ensure_self().0;
    let borrowed = sys.procs.borrow();
    crate::x86::sys_getpgid(&borrowed, me, env, cx)
}

fn sys_kill(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    const SIGKILL: i64 = 9;
    let pid = get64(env, cx.r_a) as i64;
    let sig = get64(env, cx.r_b) as i64;
    // SIGKILL 以外: 自分宛てでハンドラがあれば保留に積む。
    // SIG_IGN/SIG_DFL 宛ては従来どおり成功だけを返す（SIGKILL
    // 以外の既定動作での終了はモデル化しない）。
    if sig != SIGKILL {
        // sig=0 は存在確認のみ。範囲外は EINVAL（tgkill と同じ）。
        if !(0..=64).contains(&sig) {
            set64(env, Gpr(0), cx.neg(EINVAL));
            return Some(TrapOutcome::Handled);
        }
        if sig > 0 {
            let me = sys.ensure_self();
            if pid == me.0 as i64 {
                if sys
                    .sigacts
                    .get(sig as usize - 1)
                    .is_some_and(|a| a.handler > 1)
                {
                    sys.sig_pending |= 1 << (sig - 1);
                }
            } else if pid > 0 {
                let target = polyisa_kernel::ProcessId(pid as u64);
                if sys.procs.borrow().pgid(target).is_none() {
                    set64(env, Gpr(0), cx.neg(ESRCH));
                    return Some(TrapOutcome::Handled);
                }
                // 実行を停めている子プロセスは scheduler に Linux 状態ごと
                // 残っている。プロセス宛てシグナルをその pending 集合へ積み、
                // 次に実行可能になったときの通常配送へ任せる。
                let mut queue = sys.queue.0.borrow_mut();
                if let Some(task) = queue
                    .parked
                    .iter_mut()
                    .find(|task| task.linux.pid == target.0)
                    && task
                        .linux
                        .sigacts
                        .get(sig as usize - 1)
                        .is_some_and(|a| a.handler > 1)
                {
                    task.linux.sig_pending |= 1 << (sig - 1);
                }
            }
        }
        set64(env, Gpr(0), 0);
        return Some(TrapOutcome::Handled);
    }
    if pid <= 0 {
        // kill(-1, SIGKILL) も相手なしで成功にする。
        set64(env, Gpr(0), 0);
        return Some(TrapOutcome::Handled);
    }
    let me = sys.ensure_self();
    let target = polyisa_kernel::ProcessId(pid as u64);
    if sys.procs.borrow().pgid(target).is_none() {
        set64(env, Gpr(0), cx.neg(ESRCH));
        return Some(TrapOutcome::Handled);
    }
    sys.procs.borrow_mut().kill(target, SIGKILL as u32);
    sys.queue
        .0
        .borrow_mut()
        .meta
        .mark_exited(polyisa_kernel::ThreadId(target.0));
    if target != me {
        sys.release_parked(target.0);
    }
    sys.wake_child_waiters(target);
    if target == me {
        return Some(TrapOutcome::Exit(SIGKILL as u32));
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

fn sys_uname(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_uname(env, cx)
}

fn sys_getuid(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_getuid(env, cx)
}

fn sys_geteuid(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は os-linux に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_geteuid(env, cx)
}

fn sys_getgid(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_getgid(env, cx)
}

fn sys_getegid(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は os-linux に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_getegid(env, cx)
}

fn sys_getcwd(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    sys.ensure_cwd();
    let cwd = sys.cwd.clone();
    crate::x86::sys_getcwd(&cwd, env, cx)
}

fn sys_chdir(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    sys.ensure_cwd();
    let root = sys.guest_root.clone();
    crate::x86::sys_chdir(&root, &mut sys.cwd, env, cx)
}

fn sys_fchdir(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    let mut cwd = sys.cwd.clone();
    let r = crate::x86::sys_fchdir(&sys.fds, &sys.std_paths, &mut cwd, env, cx);
    sys.cwd = cwd;
    r
}

fn sys_setgroups(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_setgroups(env, cx)
}

fn sys_chroot(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_chroot(env, cx)
}

fn sys_getdents64(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_getdents64(
        &sys.fds,
        &sys.std_paths,
        &mut sys.dir_pos,
        &mut sys.dir_done,
        env,
        cx,
    )
}

fn sys_fstat(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    let fd = get64(env, cx.r_a) as u32;
    let std = if fd < 3 {
        match sys.std_targets[fd as usize].as_ref() {
            Some(polyisa_kernel::FdTarget::File(f)) => Some(f),
            _ => None,
        }
    } else {
        None
    };
    crate::x86::sys_fstat(&sys.fds, std, &sys.std_paths, env, cx)
}

fn sys_stat(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    sys.ensure_cwd();
    let root = sys.guest_root.clone();
    let cwd = sys.cwd.clone();
    let exe = sys.exe_path.clone();
    crate::x86::sys_stat(&root, &cwd, &exe, env, cx)
}

fn sys_lstat(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    sys.ensure_cwd();
    let root = sys.guest_root.clone();
    let cwd = sys.cwd.clone();
    let exe = sys.exe_path.clone();
    crate::x86::sys_lstat(&root, &cwd, &exe, env, cx)
}

fn sys_newfstatat(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    // AT_FDCWD+絶対パスのみ受ける点も実体側に寄せる。
    sys.ensure_cwd();
    let root = sys.guest_root.clone();
    let cwd = sys.cwd.clone();
    let exe = sys.exe_path.clone();
    crate::x86::sys_newfstatat(&root, &cwd, &exe, env, cx)
}

fn sys_sendfile(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // sendfile(out_fd, in_fd, offset, count)。offset==NULL のみ受け付ける.
    // in_fd から読んで out_fd (1/2) へ書き、転送バイト数を返す.
    // Ref: SRC-LINUX (7.3).
    let out_fd = get64(env, cx.r_a) as u32;
    let in_fd = get64(env, cx.r_b) as u32;
    let offset = get64(env, cx.r_c);
    let mut left = get64(env, cx.r_d);
    if offset != 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    if out_fd != 1 && out_fd != 2 {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    }
    // 付け替えた標準出力は読取り専用のため EBADF。
    if sys.file_ref(out_fd).is_some() {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    }
    if let Some(end) = sys.pipe_end(in_fd) {
        if !end.1 {
            set64(env, Gpr(0), cx.neg(EBADF));
            return Some(TrapOutcome::Handled);
        }
        let mut done = 0u64;
        while left > 0 {
            let max = usize::try_from(left.min(4096)).unwrap_or(0);
            let got = sys.fds.pipes().borrow_mut().read(end.0, max);
            match got {
                polyisa_kernel::PipeRead::Bytes(bytes) => {
                    let n = bytes.len();
                    let w = match out_fd {
                        1 => sys.write_fd1(&bytes),
                        _ => std::io::Write::write(&mut std::io::stderr(), &bytes).unwrap_or(0),
                    };
                    done += n as u64;
                    left -= n as u64;
                    if w < n {
                        break;
                    }
                }
                polyisa_kernel::PipeRead::Eof => break,
                polyisa_kernel::PipeRead::Empty => {
                    if done > 0 {
                        break;
                    }
                    let id = sys.ensure_self();
                    sys.pipe_wait = Some(end.0);
                    sys.queue.0.borrow_mut().meta.block(
                        polyisa_kernel::ThreadId(id.0),
                        polyisa_kernel::ThreadWait::Pipe { id: end.0 },
                    );
                    return Some(TrapOutcome::Blocked);
                }
            }
        }
        set64(env, Gpr(0), done);
        return Some(TrapOutcome::Handled);
    }
    // 付け替えた stdin はファイルから読む。真の stdin は供給バッファから読む。
    let in_empty = in_fd == 0 && sys.std_attached(0);
    if sys.file_ref(in_fd).is_none() {
        if in_empty {
            let mut done = 0u64;
            let mut chunk = vec![0u8; IO_CHUNK];
            while left > 0 {
                let take = left.min(IO_CHUNK as u64) as usize;
                let n = sys.take_stdin(&mut chunk[..take]);
                if n == 0 {
                    break;
                }
                let w = match out_fd {
                    1 => sys.write_fd1(&chunk[..n]),
                    _ => std::io::Write::write(&mut std::io::stderr(), &chunk[..n]).unwrap_or(0),
                };
                done += n as u64;
                left -= n as u64;
                if n < take || w < n {
                    break;
                }
            }
            set64(env, Gpr(0), done);
            return Some(TrapOutcome::Handled);
        }
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    }
    let mut done = 0u64;
    let mut chunk = vec![0u8; IO_CHUNK];
    while left > 0 {
        let take = left.min(IO_CHUNK as u64) as usize;
        let n = {
            let Some(file) = sys.file_mut(in_fd) else {
                break;
            };
            match std::io::Read::read(file, &mut chunk[..take]) {
                Ok(n) => n,
                Err(_) => break,
            }
        };
        if n == 0 {
            break;
        }
        let w = match out_fd {
            1 => sys.write_fd1(&chunk[..n]),
            _ => std::io::Write::write(&mut std::io::stderr(), &chunk[..n]).unwrap_or(0),
        };
        done += n as u64;
        left -= n as u64;
        if n < take || w < n {
            break;
        }
    }
    set64(env, Gpr(0), done);
    Some(TrapOutcome::Handled)
}

fn sys_lseek(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    // 標準 fd かは cx.r_a（第1引数の fd）で判定する。実体側と同じ番号を使う.
    let fd = get64(env, cx.r_a) as u32;
    let std = if fd < 3 {
        match sys.std_targets[fd as usize].as_mut() {
            Some(polyisa_kernel::FdTarget::File(f)) => Some(f),
            _ => None,
        }
    } else {
        None
    };
    crate::x86::sys_lseek(&mut sys.fds, std, env, cx)
}

fn sys_llseek(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // _llseek。標準 fd かは cx.r_a（第1引数の fd）で判定する。実体側と同じ番号を使う.
    let fd = get64(env, cx.r_a) as u32;
    let std = if fd < 3 {
        match sys.std_targets[fd as usize].as_mut() {
            Some(polyisa_kernel::FdTarget::File(f)) => Some(f),
            _ => None,
        }
    } else {
        None
    };
    crate::x86::sys_llseek(&mut sys.fds, std, env, cx)
}

fn sys_ftruncate(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    // 標準 fd かは実体と同じ番号（cx.r_a）で判定する。
    let fd = get64(env, cx.r_a) as u32;
    let std = if fd < 3 {
        match sys.std_targets[fd as usize].as_mut() {
            Some(polyisa_kernel::FdTarget::File(f)) => Some(f),
            _ => None,
        }
    } else {
        None
    };
    crate::x86::sys_ftruncate(&mut sys.fds, std, env, cx)
}

fn sys_fallocate(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    // 標準 fd かは実体と同じ番号（cx.r_a）で判定する。
    let fd = get64(env, cx.r_a) as u32;
    let std = if fd < 3 {
        match sys.std_targets[fd as usize].as_mut() {
            Some(polyisa_kernel::FdTarget::File(f)) => Some(f),
            _ => None,
        }
    } else {
        None
    };
    crate::x86::sys_fallocate(&mut sys.fds, std, env, cx)
}

fn sys_getgroups(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_getgroups(env, cx)
}

fn sys_getgroups32(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // getgroups32。gid リストの型が違うだけで `getgroups` と同じ実体を使う。
    crate::x86::sys_getgroups(env, cx)
}

fn sys_fstatat64(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // fstatat64。i386 の newfstatat。実体は `os-linux` に置く。
    crate::x86::sys_newfstatat(&sys.guest_root, &sys.cwd, &sys.exe_path, env, cx)
}

fn sys_mprotect(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_mprotect(env, cx)
}

fn sys_munmap(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_munmap(env, cx)
}

/// シグナル番号の妥当性（1..=64）。SIGKILL(9)/SIGSTOP(19) は
/// ハンドラを設定できない（Linux の sig_kernel_only 相当）。
fn sig_settable(sig: u64) -> bool {
    (1..=64).contains(&sig) && sig != 9 && sig != 19
}

/// `do_sigaltstack` の更新部。返り値は Linux errno 番号。
fn sigaltstack_update(
    sys: &mut Linux,
    env: &mut BareEnv,
    new: crate::x86::SigAltStack,
    sp: u64,
) -> Result<(), u32> {
    if sys.sigaltstack.on_stack(sp) {
        return Err(EPERM);
    }
    let mode = new.flags & !crate::x86::SS_FLAG_BITS;
    if mode != crate::x86::SS_DISABLE && mode != crate::x86::SS_ONSTACK && mode != 0 {
        return Err(EINVAL);
    }
    if sys.sigaltstack == new {
        return Ok(());
    }
    let mut next = new;
    if mode == crate::x86::SS_DISABLE {
        next.sp = 0;
        next.size = 0;
    } else {
        if next.size < crate::x86::MINSIGSTKSZ {
            return Err(ENOMEM);
        }
        // Linux の既定では strict 検査はしないが、動的 xfeature（AMX）の
        // 許可を取った task では、その user state を含む frame が入る
        // ことを要求する。XTILECFG/XTILEDATA は bit17/18。
        let supp = env.backend.get(polyisa_guest_x86::sem::xcomp_supp_ref());
        let perm = env.backend.get(polyisa_guest_x86::sem::xcomp_perm_ref());
        if supp & 0x6_0000 != 0 && perm & 0x6_0000 != 0 {
            let need =
                crate::x86::min_sigstksz_for_xfeatures(crate::x86::signal_user_xfeatures(env));
            if next.size <= need {
                return Err(ENOMEM);
            }
        }
    }
    sys.sigaltstack = next;
    Ok(())
}

fn sys_sigaltstack(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // sigaltstack(uss, uoss)。x86-64 は 24 バイト stack_t、i386/x32 は
    // 12 バイト compat_stack_t。
    let uss = get64(env, cx.r_a);
    let uoss = get64(env, cx.r_b);
    let wide = sys.is64 && !sys.x32;
    let sp = get64(env, Gpr(4));
    let new = if uss != 0 {
        let Some(ss) = crate::x86::sigaltstack_read(env, uss, wide) else {
            set64(env, Gpr(0), cx.neg(EFAULT));
            return Some(TrapOutcome::Handled);
        };
        Some(ss)
    } else {
        None
    };
    // do_sigaltstack は更新前の状態を oss へ作る。 copy_to_user は
    // 新規設定の検証に成功した後だが、中身は更新前である。
    let cur = sys.sigaltstack;
    let old = crate::x86::SigAltStack {
        sp: cur.sp,
        size: cur.size,
        flags: cur.status_flags(sp) | (cur.flags & crate::x86::SS_FLAG_BITS),
    };
    if let Some(ss) = new
        && let Err(errno) = sigaltstack_update(sys, env, ss, sp)
    {
        set64(env, Gpr(0), cx.neg(errno));
        return Some(TrapOutcome::Handled);
    }
    if uoss != 0 && !crate::x86::sigaltstack_write(env, uoss, old, wide) {
        set64(env, Gpr(0), cx.neg(EFAULT));
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

fn sys_rt_sigaction(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // rt_sigaction(sig, act, oldact, sigsetsize)。kernel_sigaction
    // は x86-64 で 32 バイト、i386 で 20 バイト。x86-64 では
    // SA_RESTORER 必須（glibc が常に設定する）。
    let sig = get64(env, cx.r_a);
    let act_p = get64(env, cx.r_b);
    let old_p = get64(env, cx.r_c);
    let size = get64(env, cx.r_d);
    if !(1..=64).contains(&sig) || size != 8 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let act = if act_p == 0 {
        None
    } else {
        // 設定の拒否は act 指定時のみ。act=NULL の照会は
        // SIGKILL/SIGSTOP に対しても成功する。
        if !sig_settable(sig) {
            set64(env, Gpr(0), cx.neg(EINVAL));
            return Some(TrapOutcome::Handled);
        }
        let Some(a) = crate::x86::sigact_read(env, act_p, sys.is64 && !sys.x32) else {
            set64(env, Gpr(0), cx.neg(EFAULT));
            return Some(TrapOutcome::Handled);
        };
        if sys.is64 && a.flags & crate::x86::SA_RESTORER == 0 {
            set64(env, Gpr(0), cx.neg(EINVAL));
            return Some(TrapOutcome::Handled);
        }
        Some(a)
    };
    if sys.sigacts.len() < 64 {
        sys.sigacts.resize(64, crate::x86::SigAct::default());
    }
    let i = sig as usize - 1;
    let old = sys.sigacts[i];
    if let Some(a) = act {
        sys.sigacts[i] = a;
    }
    if old_p != 0 && !crate::x86::sigact_write(env, old_p, &old, sys.is64 && !sys.x32) {
        set64(env, Gpr(0), cx.neg(EFAULT));
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

/// シグナルマスクの u64 をゲストメモリから読む。
fn mask_read(env: &mut BareEnv, addr: u64) -> Option<u64> {
    let mut b = [0u8; 8];
    env.backend
        .mem
        .read(
            polyisa_mem::VirtAddr(addr),
            &mut b,
            crate::x86::data_access(),
        )
        .ok()?;
    Some(u64::from_le_bytes(b))
}

fn mask_write(env: &mut BareEnv, addr: u64, v: u64) -> bool {
    env.backend
        .mem
        .write(polyisa_mem::VirtAddr(addr), &v.to_le_bytes())
        .is_ok()
}

fn sys_rt_sigprocmask(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // rt_sigprocmask(how, set, oldset, sigsetsize)。
    let how = get64(env, cx.r_a);
    let set_p = get64(env, cx.r_b);
    let old_p = get64(env, cx.r_c);
    let size = get64(env, cx.r_d);
    if size != 8 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    if old_p != 0 && !mask_write(env, old_p, sys.sig_mask) {
        set64(env, Gpr(0), cx.neg(EFAULT));
        return Some(TrapOutcome::Handled);
    }
    if set_p != 0 {
        let Some(v) = mask_read(env, set_p) else {
            set64(env, Gpr(0), cx.neg(EFAULT));
            return Some(TrapOutcome::Handled);
        };
        sys.sig_mask = match how {
            crate::x86::SIG_BLOCK => sys.sig_mask | v,
            crate::x86::SIG_UNBLOCK => sys.sig_mask & !v,
            crate::x86::SIG_SETMASK => v,
            _ => {
                set64(env, Gpr(0), cx.neg(EINVAL));
                return Some(TrapOutcome::Handled);
            }
        } & !(1 << 8 | 1 << 18); // SIGKILL/SIGSTOP は止められない
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

fn sys_rt_sigpending(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // rt_sigpending(set, sigsetsize)。
    let set_p = get64(env, cx.r_a);
    let size = get64(env, cx.r_b);
    if size != 8 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    if !mask_write(env, set_p, sys.sig_pending) {
        set64(env, Gpr(0), cx.neg(EFAULT));
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

fn sys_rt_sigreturn(sys: &mut Linux, env: &mut BareEnv, _cx: &SysCtx) -> Option<TrapOutcome> {
    // x86-64/i386 それぞれの rt フレームから復元する。uc_stack も
    // restore_altstack 相当で戻す。エラーは実機と同じく握り潰す。
    let sp_before = get64(env, Gpr(4));
    let frame_base = sp_before.wrapping_sub(if sys.is64 { 8 } else { 4 });
    let (alt_addr, wide) = if sys.x32 {
        (frame_base + 16, false)
    } else if sys.is64 {
        (frame_base + 24, true)
    } else {
        (frame_base + 152, false)
    };
    let alt = crate::x86::sigaltstack_read(env, alt_addr, wide);
    let frame = if sys.x32 {
        crate::x86::rt_sigframe_x32_read(env)
    } else if sys.is64 {
        crate::x86::rt_sigframe_read(env)
    } else {
        crate::x86::rt_sigframe32_read(env)
    };
    match frame {
        Some(mask) => {
            // set_current_blocked と同じく SIGKILL/SIGSTOP は frame 経由で
            // block できない。
            sys.sig_mask = mask & !(1 << 8 | 1 << 18);
            let Some(ss) = alt else {
                // restore_altstack の copy_from_user 失敗は badframe。
                return Some(TrapOutcome::Exit(11));
            };
            // x86-64 は sigcontext 復元前、i386/x32 は復元後に
            // restore_altstack を呼ぶ。したがって後者の on_sig_stack
            // 判定には復元された interrupted SP を使う。
            let sp_for_altstack = if sys.is64 && !sys.x32 {
                sp_before
            } else {
                get64(env, Gpr(4))
            };
            let _ = sigaltstack_update(sys, env, ss, sp_for_altstack);
            Some(TrapOutcome::Handled)
        }
        // 壊れたフレーム。実機は SIGSEGV で殺す。
        None => Some(TrapOutcome::Exit(11)),
    }
}

fn sys_pause(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // pause。保留シグナルがあれば `after_step` で配送されるので
    // EINTR を返す。ない場合も待たずに EINTR（近似）。
    set64(env, Gpr(0), cx.neg(EINTR));
    Some(TrapOutcome::Handled)
}

fn sys_rt_sigtimedwait(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_rt_sigtimedwait(env, cx)
}

fn sys_rt_sigsuspend(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // rt_sigsuspend(set, sigsetsize)。マスクを一時的に置き換えて
    // シグナルを待つ。配送は `after_step` で起きるので待たずに
    // EINTR を返す（近似）。マスクは次の sigreturn で元に戻る
    // ためここでは退避しない（近似: フレームの uc_sigmask が正）。
    let set_p = get64(env, cx.r_a);
    let size = get64(env, cx.r_b);
    if size != 8 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    if set_p != 0 {
        let Some(v) = mask_read(env, set_p) else {
            set64(env, Gpr(0), cx.neg(EFAULT));
            return Some(TrapOutcome::Handled);
        };
        sys.sig_mask = v;
    }
    set64(env, Gpr(0), cx.neg(EINTR));
    Some(TrapOutcome::Handled)
}

fn sys_tgkill(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // tgkill(tgid, tid, sig)。自分宛てでハンドラがあれば保留に積む。
    let sig = get64(env, cx.r_c);
    if sig > 64 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    if sig > 0 {
        let me = sys.ensure_self();
        let tid = get64(env, cx.r_b);
        if tid == me.0
            && sys
                .sigacts
                .get(sig as usize - 1)
                .is_some_and(|a| a.handler > 1)
        {
            sys.sig_pending |= 1 << (sig - 1);
        }
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

fn sys_set_robust_list(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    let mut v = sys.robust_head;
    let r = crate::x86::sys_set_robust_list(&mut v, env, cx);
    sys.robust_head = v;
    r
}

fn sys_rseq(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    let mut v = sys.rseq_addr;
    let r = crate::x86::sys_rseq(&mut v, env, cx);
    sys.rseq_addr = v;
    r
}

fn sys_getrandom(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_getrandom(env, cx)
}

fn sys_prlimit64(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_prlimit64(env, cx)
}

fn sys_time(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_time(env, cx)
}

fn sys_ioctl(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_ioctl(env, cx)
}

fn sys_nanosleep(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_nanosleep(env, cx)
}

/// `/proc/self/status` の `Cpus_allowed` を、CPU 0 が最下位ビットのバイト列にする。
fn sys_sched_getaffinity(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    let me = sys.ensure_self().0;
    crate::x86::sys_sched_getaffinity(me, env, cx)
}

fn sys_clock_nanosleep(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_clock_nanosleep(env, cx)
}

fn sys_gettimeofday(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    crate::x86::sys_gettimeofday(env, cx)
}

fn sys_getcpu(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_getcpu(env, cx)
}

fn sys_clock_gettime(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_clock_gettime(&mut sys.mono_start, env, cx)
}

fn sys_readlinkat(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    sys.ensure_cwd();
    let root = sys.guest_root.clone();
    let cwd = sys.cwd.clone();
    let exe = sys.exe_path.clone();
    crate::x86::sys_readlinkat(&root, &cwd, &exe, &sys.fds, &sys.std_paths, env, cx)
}

fn sys_readlink(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    sys.ensure_cwd();
    let root = sys.guest_root.clone();
    let cwd = sys.cwd.clone();
    let exe = sys.exe_path.clone();
    crate::x86::sys_readlink(&root, &cwd, &exe, &sys.fds, &sys.std_paths, env, cx)
}

fn sys_arch_prctl(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // FS ベースは CPU 状態に置く。実体は `os-linux` にある.
    crate::x86::sys_arch_prctl(env, cx)
}

fn sys_dup(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // dup(oldfd)。開ファイルは try_clone して最下位空きに置く (freopen 対応)。
    // 真の 1/2 (ファイルなし) は旧来通り oldfd を返す.
    let oldfd = get64(env, cx.r_a) as u32;
    if !sys.fd_valid(oldfd) {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    }
    if let Some((dup, path)) = sys.dup_open(oldfd) {
        let fd = sys.alloc_target(dup);
        if let Some(p) = path {
            sys.remember_path(fd, p);
        }
        set64(env, Gpr(0), fd as u64);
        return Some(TrapOutcome::Handled);
    }
    if oldfd == 1 || oldfd == 2 {
        set64(env, Gpr(0), oldfd as u64);
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), cx.neg(EBADF));
    Some(TrapOutcome::Handled)
}

fn sys_dup2(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // dup2(oldfd, newfd)。1/2 同士の複製は newfd を返して継続する.
    // --list の dup2(1,2) は出力先の付け替えだが、試作では写像せず継続する.
    let oldfd = get64(env, cx.r_a) as u32;
    let newfd = get64(env, cx.r_b) as u32;
    // 閉じた標準 fd は不正。接続中・付け替え中と opened fd が真.
    let valid = |fd: u32| sys.fd_valid(fd);
    if !valid(oldfd) || newfd > 1024 {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    }
    if oldfd == newfd {
        set64(env, Gpr(0), newfd as u64);
        return Some(TrapOutcome::Handled);
    }
    if let Some((dup, path)) = sys.dup_open(oldfd) {
        sys.install_target(dup, newfd);
        if let Some(p) = path {
            sys.remember_path(newfd, p);
        }
        set64(env, Gpr(0), newfd as u64);
        return Some(TrapOutcome::Handled);
    }
    if (oldfd == 1 || oldfd == 2) && (newfd == 1 || newfd == 2) {
        // time は dup2(2,1) のあと printf で集計を出す。--list は dup2(1,2)。
        if oldfd == 2 && newfd == 1 {
            sys.stdout_is_stderr = true;
            sys.stderr_is_stdout = false;
        } else if oldfd == 1 && newfd == 2 {
            sys.stderr_is_stdout = true;
            sys.stdout_is_stderr = false;
        }
        sys.std_is_stdin[newfd as usize] = false;
        set64(env, Gpr(0), newfd as u64);
        return Some(TrapOutcome::Handled);
    }
    // dup2(0,n)。stdin は開ファイルを持たないが有効な fd であり、成功させる。
    // n は stdin を指す。read は stdin_buf、write は EBADF（O_RDONLY）。
    // dup(0) は未対応（開ファイルがないため複製先を作れない）。
    if oldfd == 0 && newfd < 3 {
        if !sys.std_attached(0) {
            set64(env, Gpr(0), cx.neg(EBADF));
            return Some(TrapOutcome::Handled);
        }
        sys.close_fd(newfd);
        sys.std_closed[newfd as usize] = false;
        sys.std_is_stdin[newfd as usize] = true;
        sys.forget_path(newfd);
        set64(env, Gpr(0), newfd as u64);
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), cx.neg(EBADF));
    Some(TrapOutcome::Handled)
}

fn sys_dup3(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // dup3(oldfd, newfd, flags)。hexdump の libbb 準備で使う.
    // flags は O_CLOEXEC のみ。oldfd==newfd は EINVAL.
    let oldfd = get64(env, cx.r_a) as u32;
    let newfd = get64(env, cx.r_b) as u32;
    let flags = get64(env, cx.r_c) as u32;
    const O_CLOEXEC: u32 = 0x80000;
    if flags & !O_CLOEXEC != 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    if oldfd == newfd {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let valid = |fd: u32| sys.fd_valid(fd);
    if !valid(oldfd) || newfd > 1024 {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    }
    if let Some((dup, path)) = sys.dup_open(oldfd) {
        sys.install_target(dup, newfd);
        sys.set_cloexec(newfd, flags & O_CLOEXEC != 0);
        if let Some(p) = path {
            sys.remember_path(newfd, p);
        }
        set64(env, Gpr(0), newfd as u64);
        return Some(TrapOutcome::Handled);
    }
    if (oldfd == 1 || oldfd == 2) && (newfd == 1 || newfd == 2) {
        if oldfd == 2 && newfd == 1 {
            sys.stdout_is_stderr = true;
            sys.stderr_is_stdout = false;
        } else if oldfd == 1 && newfd == 2 {
            sys.stderr_is_stdout = true;
            sys.stdout_is_stderr = false;
        }
        set64(env, Gpr(0), newfd as u64);
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), cx.neg(EBADF));
    Some(TrapOutcome::Handled)
}

fn sys_mkdir(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    sys.ensure_cwd();
    let root = sys.guest_root.clone();
    let cwd = sys.cwd.clone();
    crate::x86::sys_mkdir(&root, &cwd, env, cx)
}

fn sys_mknod(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    sys.ensure_cwd();
    let root = sys.guest_root.clone();
    let cwd = sys.cwd.clone();
    let umask = sys.umask;
    crate::x86::sys_mknod(&root, &cwd, umask, env, cx)
}

fn sys_mkdirat(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    sys.ensure_cwd();
    let root = sys.guest_root.clone();
    let cwd = sys.cwd.clone();
    crate::x86::sys_mkdirat(&root, &cwd, env, cx)
}

fn sys_rename(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    sys.ensure_cwd();
    let root = sys.guest_root.clone();
    let cwd = sys.cwd.clone();
    crate::x86::sys_rename(&root, &cwd, env, cx)
}

fn sys_sync(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_sync(env, cx)
}

fn sys_link(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    sys.ensure_cwd();
    let root = sys.guest_root.clone();
    let cwd = sys.cwd.clone();
    crate::x86::sys_link(&root, &cwd, env, cx)
}

fn sys_symlink(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // symlink(oldpath, newpath)。`ln -s` で使う。
    // 可搬 API がないため実体はクリエート host の helper に置く。
    // host 依存は cli のみに限る設計（workspace.md「依存規則」）のため、
    // 解決済みでも os-linux へは移さずここに残す。
    // 作成先だけ解決し、指し先は verbatim に保つ。
    let old_addr = get64(env, cx.r_a);
    let new_addr = get64(env, cx.r_b);
    let old_path = match guest_c_string(env, old_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    let new_path = match guest_c_string(env, new_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    sys.ensure_cwd();
    let Some(new_path) = sys.resolve_path(&new_path) else {
        set64(env, Gpr(0), cx.neg(EPERM));
        return Some(TrapOutcome::Handled);
    };
    Some(match polyisa_host::symlink(&old_path, &new_path) {
        Ok(()) => {
            set64(env, Gpr(0), 0);
            TrapOutcome::Handled
        }
        Err(e) => {
            let no = match e.kind() {
                std::io::ErrorKind::NotFound => ENOENT,
                std::io::ErrorKind::AlreadyExists => 17,
                std::io::ErrorKind::PermissionDenied => EACCES,
                _ => EINVAL,
            };
            set64(env, Gpr(0), cx.neg(no));
            TrapOutcome::Handled
        }
    })
}

fn sys_rmdir(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    sys.ensure_cwd();
    let root = sys.guest_root.clone();
    let cwd = sys.cwd.clone();
    crate::x86::sys_rmdir(&root, &cwd, env, cx)
}

fn sys_unlink(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    sys.ensure_cwd();
    let root = sys.guest_root.clone();
    let cwd = sys.cwd.clone();
    crate::x86::sys_unlink(&root, &cwd, env, cx)
}

fn sys_unlinkat(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    sys.ensure_cwd();
    let root = sys.guest_root.clone();
    let cwd = sys.cwd.clone();
    crate::x86::sys_unlinkat(&root, &cwd, &sys.fds, &sys.std_paths, env, cx)
}

fn sys_access(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    sys.ensure_cwd();
    let root = sys.guest_root.clone();
    let cwd = sys.cwd.clone();
    crate::x86::sys_access(&root, &cwd, env, cx)
}

fn sys_faccessat(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    sys.ensure_cwd();
    let root = sys.guest_root.clone();
    let cwd = sys.cwd.clone();
    crate::x86::sys_faccessat(&root, &cwd, env, cx)
}

fn sys_utimensat(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    sys.ensure_cwd();
    let root = sys.guest_root.clone();
    let cwd = sys.cwd.clone();
    crate::x86::sys_utimensat(&root, &cwd, env, cx)
}

fn sys_chmod(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_chmod(env, cx)
}

fn sys_fchmod(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_fchmod(env, cx)
}

fn sys_fchmodat(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は os-linux に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_fchmodat(env, cx)
}

fn sys_chown(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_chown(env, cx)
}

fn sys_lchown(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_lchown(env, cx)
}

fn sys_fchown(_sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_fchown(env, cx)
}

fn sys_umask(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    let mut v = sys.umask;
    let r = crate::x86::sys_umask(&mut v, env, cx);
    sys.umask = v;
    r
}

fn sys_fcntl(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let fd = get64(env, cx.r_a) as u32;
    let cmd = get64(env, cx.r_b);
    let arg = get64(env, cx.r_c);
    const F_GETFD: u64 = 1;
    const F_SETFD: u64 = 2;
    const F_GETFL: u64 = 3;
    const F_SETFL: u64 = 4;
    const FD_CLOEXEC: u64 = 1;
    const O_NONBLOCK: u64 = 0o4000;
    // 表に載る fd の旗は仮想カーネルが応える。
    if fd >= 3 && sys.fds.ent(fd).is_some() {
        match cmd {
            F_GETFD => {
                set64(env, Gpr(0), u64::from(sys.fds.cloexec(fd)));
                return Some(TrapOutcome::Handled);
            }
            F_SETFD => {
                let _ = sys.fds.set_cloexec(fd, arg & FD_CLOEXEC != 0);
                set64(env, Gpr(0), 0);
                return Some(TrapOutcome::Handled);
            }
            F_GETFL => {
                // 記録しているのは O_NONBLOCK だけ。
                let fl = if sys.fds.nonblock(fd) { O_NONBLOCK } else { 0 };
                set64(env, Gpr(0), fl);
                return Some(TrapOutcome::Handled);
            }
            F_SETFL => {
                let _ = sys.fds.set_nonblock(fd, arg & O_NONBLOCK != 0);
                set64(env, Gpr(0), 0);
                return Some(TrapOutcome::Handled);
            }
            _ => {}
        }
    }
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    // 有効性判定は状態を束ねる cli 側、実処理は os-linux 側.
    let valid = sys.fd_valid(fd);
    crate::x86::sys_fcntl(valid, env, cx)
}

fn sys_brk(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 実体は `os-linux` に置く。WP2 の移管が終わるまでの適合層.
    crate::x86::sys_brk(&mut sys.heap_end, env, cx)
}

/// プロセスの clone。アドレス空間を共有するフラグは受けない。
/// 子は実行可能なスレッドとして置き、親には子の識別子を返す。
fn sys_fork(sys: &mut Linux, env: &mut BareEnv, _cx: &SysCtx) -> Option<TrapOutcome> {
    // fork()。アドレス空間は複製する。CLONE_VM の vfork は受けない。
    spawn_child(sys, env, 0)
}

fn sys_vfork(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // vfork()。共有アドレス空間は持たず、fork と同じ複製で進める。
    // CLONE_VM 経由の vfork は sys_clone 側で拒む。time / timeout / xargs が呼ぶ。
    sys_fork(sys, env, cx)
}

fn sys_clone(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let flags = get64(env, cx.r_a);
    let stack = get64(env, cx.r_b);
    if flags & (crate::clone_flag::VM | crate::clone_flag::THREAD) != 0 {
        return Some(TrapOutcome::Unimplemented);
    }
    spawn_child(sys, env, stack)
}

fn spawn_child(sys: &mut Linux, env: &mut BareEnv, stack: u64) -> Option<TrapOutcome> {
    let parent = sys.ensure_self();
    let child_pid = sys.procs.borrow_mut().fork(parent);
    let mut child_env = env.clone();
    set64(&mut child_env, Gpr(0), 0);
    if stack != 0 {
        set64(&mut child_env, Gpr(4), stack);
    }
    // SYSCALL と INT 0x80 はどちらも 2 バイト。子は次の命令から始める。
    let eip = eip_of(&mut child_env);
    child_env
        .backend
        .set(polyisa_guest_x86::sem::eip_ref(), eip.wrapping_add(2));
    let mut child_linux = sys.duplicate();
    child_linux.pid = child_pid.0;
    child_linux.steps = 0;
    child_linux.wait = None;
    sys.queue
        .0
        .borrow_mut()
        .meta
        .insert(polyisa_kernel::ThreadId(child_pid.0));
    sys.queue.0.borrow_mut().meta.copy_steps(
        polyisa_kernel::ThreadId(parent.0),
        polyisa_kernel::ThreadId(child_pid.0),
    );
    sys.queue.0.borrow_mut().parked.push(ParkedTask {
        env: child_env,
        linux: child_linux,
    });
    set64(env, Gpr(0), child_pid.0);
    Some(TrapOutcome::Handled)
}

fn sys_execve(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let path_addr = get64(env, cx.r_a);
    let argv_addr = get64(env, cx.r_b);
    let envp_addr = get64(env, cx.r_c);
    let Some(path) = guest_c_string(env, path_addr) else {
        set64(env, Gpr(0), cx.neg(EFAULT));
        return Some(TrapOutcome::Handled);
    };
    // /proc/self/exe はゲスト実行ファイル自身を読む（ホスト exe ではない）。
    let path = guest_exe_redirect(&sys.exe_path, &path).unwrap_or(path);
    let wide = sys.is64 && !sys.x32;
    let argv = match read_cstr_array(env, argv_addr, wide) {
        Ok(v) => v,
        Err(()) => {
            set64(env, Gpr(0), cx.neg(EFAULT));
            return Some(TrapOutcome::Handled);
        }
    };
    sys.ensure_cwd();
    let Some(path) = sys.resolve_path(&path) else {
        set64(env, Gpr(0), cx.neg(EPERM));
        return Some(TrapOutcome::Handled);
    };
    let envp = match read_cstr_array(env, envp_addr, wide) {
        Ok(v) => v,
        Err(()) => {
            set64(env, Gpr(0), cx.neg(EFAULT));
            return Some(TrapOutcome::Handled);
        }
    };
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            set64(env, Gpr(0), cx.neg(ENOENT));
            return Some(TrapOutcome::Handled);
        }
        Err(_) => {
            set64(env, Gpr(0), cx.neg(EACCES));
            return Some(TrapOutcome::Handled);
        }
    };
    match install_exec(sys, env, &bytes, &path, &argv, &envp) {
        Ok(()) => Some(TrapOutcome::Handled),
        Err(errno) => {
            // ホストの動的バイナリ（/sbin/cat 等）は PT_INTERP のため ENOEXEC。
            // ゲスト環境では同名の BusyBox アプレットのはずなので、
            // 同じ argv で実行ファイル（BusyBox 静的）へ読み替える。
            // スクリプト（非 ELF）は ash の解釈へ委ねるため対象外。
            if errno == ENOEXEC && path != sys.exe_path && !sys.exe_path.is_empty() {
                let is_dynamic = if sys.x32 {
                    polyisa_loader::elf::parse_ehdr32(&bytes)
                        .ok()
                        .and_then(|ehdr| {
                            polyisa_loader::elf::parse_phdrs32(&bytes, &ehdr)
                                .ok()
                                .map(|phdrs| phdrs.iter().any(|ph| ph.seg_type == 3))
                        })
                        .unwrap_or(false)
                } else {
                    polyisa_loader::elf::parse_ehdr(&bytes)
                        .ok()
                        .and_then(|ehdr| {
                            polyisa_loader::elf::parse_phdrs(&bytes, &ehdr)
                                .ok()
                                .map(|phdrs| phdrs.iter().any(|ph| ph.seg_type == 3))
                        })
                        .unwrap_or(false)
                };
                if is_dynamic
                    && let Ok(busy) = std::fs::read(sys.exe_path.clone())
                    && install_exec(sys, env, &busy, &sys.exe_path.clone(), &argv, &envp).is_ok()
                {
                    return Some(TrapOutcome::Handled);
                }
            }
            set64(env, Gpr(0), cx.neg(errno));
            Some(TrapOutcome::Handled)
        }
    }
}

fn sys_wait4(sys: &mut Linux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // WNOHANG。子がまだ終了していなければ 0 を返す。
    const WNOHANG: u64 = 1;
    let which = get64(env, cx.r_a) as i64;
    let status_ptr = get64(env, cx.r_b);
    let options = get64(env, cx.r_c);
    let wnohang = options & WNOHANG != 0;
    if sys.pid == 0 {
        set64(env, Gpr(0), cx.neg(ECHILD));
        return Some(TrapOutcome::Handled);
    }
    sys.wait = None;
    sys.queue
        .0
        .borrow_mut()
        .meta
        .unblock(polyisa_kernel::ThreadId(sys.pid));
    let parent = polyisa_kernel::ProcessId(sys.pid);
    match sys.procs.borrow_mut().try_reap(parent, which) {
        polyisa_kernel::Reap::Exited { pid, code, signal } => {
            if status_ptr != 0 {
                let st = reap_status(code, signal);
                if env
                    .backend
                    .mem
                    .write(VirtAddr(status_ptr), &st.to_le_bytes())
                    .is_err()
                {
                    set64(env, Gpr(0), cx.neg(EFAULT));
                    return Some(TrapOutcome::Handled);
                }
            }
            set64(env, Gpr(0), pid.0);
            Some(TrapOutcome::Handled)
        }
        polyisa_kernel::Reap::NoChild => {
            set64(env, Gpr(0), cx.neg(ECHILD));
            Some(TrapOutcome::Handled)
        }
        polyisa_kernel::Reap::Pending => {
            if wnohang {
                set64(env, Gpr(0), 0);
                Some(TrapOutcome::Handled)
            } else {
                sys.wait = Some(WaitSlot { which, status_ptr });
                sys.queue.0.borrow_mut().meta.block(
                    polyisa_kernel::ThreadId(sys.pid),
                    polyisa_kernel::ThreadWait::Child { which },
                );
                Some(TrapOutcome::Blocked)
            }
        }
    }
}

/// ゲストのポインタ配列を NUL 終端まで読む。失敗は `Err(())`。
/// `wide` はポインタ幅が 8 バイトか（x86-64）、4 バイトか
/// （x86-32・x32）を選ぶ。
fn read_cstr_array(env: &mut BareEnv, addr: u64, wide: bool) -> Result<Vec<Vec<u8>>, ()> {
    if addr == 0 {
        return Err(());
    }
    let acc = data_access();
    let step: usize = if wide { 8 } else { 4 };
    let mut out = Vec::new();
    for i in 0..64u64 {
        let mut word = [0u8; 8];
        if env
            .backend
            .mem
            .read(VirtAddr(addr + i * step as u64), &mut word[..step], acc)
            .is_err()
        {
            return Err(());
        }
        let ptr = u64::from_le_bytes(word);
        if ptr == 0 {
            return Ok(out);
        }
        let Some(text) = guest_c_string(env, ptr) else {
            return Err(());
        };
        out.push(text.into_bytes());
    }
    Err(())
}

/// 現在のアドレス空間を静的 ELF で置き換え、入口へ eip を移す。
fn install_exec(
    sys: &mut Linux,
    env: &mut BareEnv,
    bytes: &[u8],
    path: &str,
    argv: &[Vec<u8>],
    envp: &[Vec<u8>],
) -> Result<(), u32> {
    use polyisa_mem::{PAGE_SIZE, Perms};
    // x32 の ELF は ELFCLASS32 + EM_X86_64 なので 32 ビット形式で読む。
    let ehdr = if sys.x32 {
        polyisa_loader::elf::parse_ehdr32(bytes).map_err(|_| ENOEXEC)?
    } else {
        polyisa_loader::elf::parse_ehdr(bytes).map_err(|_| ENOEXEC)?
    };
    const EM_X86_64: u16 = 62;
    if !ehdr.little || ehdr.machine != EM_X86_64 || ehdr.entry > u64::from(u32::MAX) {
        return Err(ENOEXEC);
    }
    let phdrs = if sys.x32 {
        polyisa_loader::elf::parse_phdrs32(bytes, &ehdr).map_err(|_| ENOEXEC)?
    } else {
        polyisa_loader::elf::parse_phdrs(bytes, &ehdr).map_err(|_| ENOEXEC)?
    };
    // 動的リンク（PT_INTERP あり）は実行できない。ENOEXEC で探索を続けさせる。
    if phdrs.iter().any(|ph| ph.seg_type == 3) {
        return Err(ENOEXEC);
    }
    let mut mem = polyisa_mem::AddressSpace::new();
    polyisa_loader::elf::load_segments(bytes, &phdrs, &mut mem).map_err(|_| ENOEXEC)?;
    let mut image_end = 0u64;
    for ph in &phdrs {
        if ph.seg_type == 1 {
            image_end = image_end.max(ph.vaddr.saturating_add(ph.memsz));
        }
    }
    let top = 0x7fff_0000u64;
    let minsigstksz = crate::x86::min_sigstksz_for_xfeatures(
        env.backend.get(polyisa_guest_x86::sem::xcomp_supp_ref()),
    );
    let auxv = [(6, 0x1000), (51, minsigstksz)];
    // x32 は 64 ビットモードで動くが初期スタックのポインタは 32 ビット。
    let (img, sp) = if sys.is64 && !sys.x32 {
        crate::build_initial_stack(top, argv, envp, &auxv)
    } else {
        crate::build_initial_stack32(top, argv, envp, &auxv)
    };
    const STACK_SIZE: u64 = 8 * 1024 * 1024;
    let base = top - STACK_SIZE;
    let end = top.next_multiple_of(PAGE_SIZE);
    let count = (end - base) / PAGE_SIZE;
    mem.map(VirtAddr(base), count, Perms(Perms::R.0 | Perms::W.0))
        .map_err(|_| ENOMEM)?;
    mem.write(VirtAddr(sp), &img).map_err(|_| EFAULT)?;
    // x86-64 の vsyscall ページ。新しい像でも同じ番地が見えるよう
    // ここでも写像する（x32 も 64 ビット実行なので対象に含める）。
    if sys.is64 {
        let _ = crate::x86::map_vsyscall_page(&mut mem);
    }
    env.backend.mem = mem;
    env.backend.reservation = polyisa_mem::Reservation::empty();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(4), sp);
    set64(env, Gpr(0), 0);
    env.backend
        .set(polyisa_guest_x86::sem::eip_ref(), ehdr.entry as u32);
    sys.init_brk(image_end);
    // 成功した exec では代替シグナルスタックを無効化する。
    sys.sigaltstack = crate::x86::SigAltStack {
        flags: crate::x86::SS_DISABLE,
        ..crate::x86::SigAltStack::default()
    };
    // アドレス空間を置き換えたので mmap の割り当て基底も初期に戻す。
    sys.mmap_base = 0;
    sys.exe_path = path.to_string();
    env.backend.set(polyisa_guest_x86::sem::fs_base_ref(), 0);
    // execve は捕捉済みハンドラを SIG_DFL に戻す。SIG_IGN と
    // マスク・保留は維持される。
    for a in &mut sys.sigacts {
        if a.handler > 1 {
            *a = crate::x86::SigAct::default();
        }
    }
    // FD_CLOEXEC の fd を掃討する。パイプ端を閉じた結果の
    // 待ち解除はここで配る。
    let taken = sys.fds.take_cloexec();
    let mut wakes = Vec::new();
    for t in &taken {
        wakes.extend(sys.fds.close_target(t));
    }
    for (id, wake_r, wake_w) in wakes {
        if wake_r || wake_w {
            sys.wake_pipe(id);
        }
    }
    Ok(())
}

impl TrapHandler for Linux {
    fn init_brk(&mut self, image_end: u64) {
        Linux::init_brk(self, image_end);
    }

    fn after_step(&mut self, env: &mut BareEnv) {
        self.deliver_pending(env);
        self.step_and_maybe_preempt(env);
    }

    fn on_block(&mut self, env: &mut BareEnv) -> bool {
        let blocked = self.wait.is_some() || self.pipe_wait.is_some() || self.fd_wait.is_some();
        if self.preempt(env) {
            return true;
        }
        loop {
            self.sweep_fd_waits();
            if self.preempt(env) {
                return true;
            }
            // 自分の待ちが解けて実行可能に戻った。`fd_wait_prev`
            // が置かれるのは掃討/起床が待ちを解いたときだけ。
            if self.fd_wait.is_none() && (self.fd_wait_prev.is_some() || self.self_fd_blocked()) {
                let pid = self.pid;
                self.queue
                    .0
                    .borrow_mut()
                    .meta
                    .unblock(polyisa_kernel::ThreadId(pid));
                return true;
            }
            if !self.drive_io_waits() {
                if blocked {
                    self.note_deadlock();
                }
                return false;
            }
            // HostIo 待ちの間に自分が parked へ移ることはない
            // （swap_in は preempt 経由でのみ起きる）。
        }
    }

    fn take_exit(&mut self, env: &mut BareEnv, code: u32) -> bool {
        self.yield_on_exit(env, code)
    }

    fn handle_exception(
        &mut self,
        env: &mut BareEnv,
        e: polyisa_sem::GuestException,
    ) -> TrapOutcome {
        use polyisa_sem::ExceptionKind;
        let ip = u64::from(env.backend.get(polyisa_guest_x86::sem::eip_ref()));
        // si_code は Linux/uapi の代表値。kill 由来と区別できる
        // ことと、fault アドレスの配置を優先し、細かい x86 固有の
        // 分岐（SEGV_ACCERR 等）は必要になった時点で分ける。
        let (sig, si_code, si_addr) = match e.kind {
            ExceptionKind::Undefined => (4, 2, ip), // SIGILL, ILL_ILLOPN
            ExceptionKind::Protection => (11, 0, e.addr.unwrap_or(ip)), // SIGSEGV
            ExceptionKind::PageFault => (11, 1, e.addr.unwrap_or(ip)), // SEGV_MAPERR
            ExceptionKind::Align => (7, 1, e.addr.unwrap_or(ip)), // SIGBUS, BUS_ADRALN
            ExceptionKind::DivZero => (8, 1, ip),   // SIGFPE, FPE_INTDIV
            ExceptionKind::Fp => (8, 0, e.addr.unwrap_or(ip)),
            ExceptionKind::Break => (5, 1, ip), // SIGTRAP, TRAP_BRKPT
            ExceptionKind::Trap => return TrapOutcome::Unimplemented,
        };
        self.deliver_exception(env, sig, si_code, si_addr)
    }

    fn handle_trap(&mut self, env: &mut BareEnv, code: u32) -> TrapOutcome {
        use polyisa_guest_x86::sem::Gpr;
        // INT 0x80 (code 0x80) と SYSCALL (code 0) のどちらも番号は RAX/EAX にある。
        let _ = code;
        // 引数レジスタ：x86-32 は EBX/ECX/EDX/ESI/EDI/EBP、
        // x86-64 は RDI/RSI/RDX/R10/R8/R9。
        let (r_a, r_b, r_c, r_d, r_e, r_f) = if self.is64 {
            (Gpr(7), Gpr(6), Gpr(2), Gpr(10), Gpr(8), Gpr(9))
        } else {
            (Gpr(3), Gpr(1), Gpr(2), Gpr(6), Gpr(7), Gpr(5))
        };
        let guest_abi = if self.x32 {
            crate::GuestAbi::X32Linux
        } else if self.is64 {
            crate::GuestAbi::X86_64Linux
        } else {
            crate::GuestAbi::X86_32Linux
        };
        // dirfd の AT_FDCWD：x86-32 は 32ビット、x86-64 は 64ビットの -100。
        // 32ビット mov で設定された場合 (RDI=0xffffff9c) も受け付けるため下位32で比較する.
        let at_fdcwd: u64 = if self.is64 {
            0xffff_ffff_ffff_ff9c
        } else {
            u64::from(AT_FDCWD_U32)
        };
        let cx = SysCtx {
            r_a,
            r_b,
            r_c,
            r_d,
            r_e,
            r_f,
            is64: self.is64,
            x32: self.x32,
            at_fdcwd,
        };
        let nr = get64(env, Gpr(0));
        let name = crate::syscall_name(guest_abi, nr);
        let table = if self.is64 {
            X86_64_SYSCALLS
        } else {
            X86_32_SYSCALLS
        };
        let trace = std::env::var_os("POLYISA_X86_SYSCALLS").is_some();
        if trace {
            let args: Vec<u64> = [cx.r_a, cx.r_b, cx.r_c, cx.r_d, cx.r_e, cx.r_f]
                .iter()
                .map(|r| get64(env, *r))
                .collect();
            eprintln!("sys {}({}) args={args:x?}", nr, name.unwrap_or("?"));
        }
        // 前回張った待ちは 1 回限り消費する（起きて再実行された
        // syscall だけが `prev` として使う。他の呼び出しでは捨てる）。
        let fd_wait_prev = self.fd_wait_prev.take();
        if let Some(name) = name
            && crate::wait::NAMES.contains(&name)
            && let Some(out) = self.wait_call(env, &cx, name, fd_wait_prev.as_ref())
        {
            if trace {
                eprintln!("  -> {:#x}", get64(env, Gpr(0)));
            }
            return out;
        }
        if let Some(name) = name
            && let Some((_, handler)) = table.iter().find(|(n, _)| *n == name)
            && let Some(out) = handler(self, env, &cx)
        {
            if trace {
                eprintln!("  -> {:#x}", get64(env, Gpr(0)));
            }
            return out;
        }
        // 未実装は既定で ENOSYS を返して続ける（設計: user-mode.md）。
        if !self.reported.contains(&nr) {
            self.reported.push(nr);
            eprintln!("run: unhandled syscall {nr} ({})", name.unwrap_or("?"));
        }
        set64(env, Gpr(0), cx.neg(crate::ENOSYS));
        TrapOutcome::Handled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_engine::bare::BareEnv;
    use polyisa_guest_x86::sem::Gpr;
    use polyisa_mem::{Perms, VirtAddr};

    fn bare() -> BareEnv {
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_x86::CpuState>());
        env.backend.mem.map(VirtAddr(0), 2, Perms::RW).unwrap();
        env
    }

    fn set_regs(env: &mut BareEnv, nr: u32, a: u32, b: u32, c: u32) {
        env.backend.set(Gpr(0).state(), nr);
        env.backend.set(Gpr(3).state(), a);
        env.backend.set(Gpr(1).state(), b);
        env.backend.set(Gpr(2).state(), c);
    }

    fn assert_syscall_table(table: &[(&str, SysFn)], abi: crate::GuestAbi) {
        let mut seen = std::collections::BTreeSet::new();
        let known = os_linux_names(abi);
        for (name, _) in table {
            assert!(seen.insert(*name), "名前が重複している: {name}");
            assert!(known.contains(name), "{name} は {abi:?} の番号表にない");
        }
    }

    fn os_linux_names(abi: crate::GuestAbi) -> std::collections::BTreeSet<&'static str> {
        let mut names = std::collections::BTreeSet::new();
        for nr in 0..4096 {
            if let Some(name) = crate::syscall_name(abi, nr) {
                names.insert(name);
            }
        }
        if abi == crate::GuestAbi::X32Linux {
            // x32 専用番号（SYSCALL_BIT|512〜547）も列挙する。
            for nr in 0x4000_0200..0x4000_0240 {
                if let Some(name) = crate::syscall_name(abi, nr) {
                    names.insert(name);
                }
            }
        }
        names
    }

    #[test]
    fn write_stdout_and_bad_fd() {
        let mut sys = Linux::default();
        let mut env = bare();
        env.backend.mem.write(VirtAddr(0x100), b"hi").unwrap();
        // write(1, 0x100, 2) は受理し、書いたバイト数を返す。
        set_regs(&mut env, crate::x86_32::WRITE as u32, 1, 0x100, 2);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 2);
        // 存在しない fd への write は EBADF。
        set_regs(&mut env, crate::x86_32::WRITE as u32, 9, 0x100, 2);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), neg_errno(EBADF));
    }

    #[test]
    fn writev_two_iovecs() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        env.backend.mem.write(VirtAddr(0x100), b"hi").unwrap();
        env.backend.mem.write(VirtAddr(0x110), b"!").unwrap();
        // iov[0]={0x100,2}, iov[1]={0x110,1} at 0x200.
        let mut iov = [0u8; 32];
        iov[..8].copy_from_slice(&0x100u64.to_le_bytes());
        iov[8..16].copy_from_slice(&2u64.to_le_bytes());
        iov[16..24].copy_from_slice(&0x110u64.to_le_bytes());
        iov[24..32].copy_from_slice(&1u64.to_le_bytes());
        env.backend.mem.write(VirtAddr(0x200), &iov).unwrap();
        set64(&mut env, Gpr(0), abi::WRITEV);
        set64(&mut env, Gpr(7), 2);
        set64(&mut env, Gpr(6), 0x200);
        set64(&mut env, Gpr(2), 2);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 3);
        // fd=9 は EBADF。
        set64(&mut env, Gpr(0), abi::WRITEV);
        set64(&mut env, Gpr(7), 9);
        set64(&mut env, Gpr(6), 0x200);
        set64(&mut env, Gpr(2), 2);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EBADF));
    }

    #[test]
    fn writev_opened_fd_writes_file() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        let path = std::env::temp_dir().join(format!("polyisa-writev-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        let fd = sys.alloc_fd(file);
        env.backend.mem.write(VirtAddr(0x100), b"hi").unwrap();
        env.backend.mem.write(VirtAddr(0x110), b"!").unwrap();
        let mut iov = [0u8; 32];
        iov[..8].copy_from_slice(&0x100u64.to_le_bytes());
        iov[8..16].copy_from_slice(&2u64.to_le_bytes());
        iov[16..24].copy_from_slice(&0x110u64.to_le_bytes());
        iov[24..32].copy_from_slice(&1u64.to_le_bytes());
        env.backend.mem.write(VirtAddr(0x200), &iov).unwrap();
        set64(&mut env, Gpr(0), abi::WRITEV);
        set64(&mut env, Gpr(7), u64::from(fd));
        set64(&mut env, Gpr(6), 0x200);
        set64(&mut env, Gpr(2), 2);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 3);
        drop(sys);
        assert_eq!(std::fs::read(&path).unwrap(), b"hi!");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn dup2_stdin_marks_and_transfers() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        sys.stdin_buf = b"hi".to_vec();
        let mut env = bare();
        // dup2(0, 2) は成功し、fd 2 を stdin 付けにする。
        set64(&mut env, Gpr(0), abi::DUP2);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 2);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 2);
        // read(2, 0x100, 16) は stdin_buf から読む。
        env.backend
            .mem
            .write(VirtAddr(0x100), b"..........")
            .unwrap();
        set64(&mut env, Gpr(0), abi::READ);
        set64(&mut env, Gpr(7), 2);
        set64(&mut env, Gpr(6), 0x100);
        set64(&mut env, Gpr(2), 16);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 2);
        let mut got = [0u8; 2];
        env.backend
            .mem
            .read(VirtAddr(0x100), &mut got, data_access())
            .unwrap();
        assert_eq!(&got, b"hi");
        // write(2, ...) は EBADF（stdin は O_RDONLY 相当）。
        set64(&mut env, Gpr(0), abi::WRITE);
        set64(&mut env, Gpr(7), 2);
        set64(&mut env, Gpr(6), 0x100);
        set64(&mut env, Gpr(2), 2);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EBADF));
    }

    #[test]
    fn mmap_anonymous_returns_addr() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        sys.mmap_base = 0x6000_0000;
        let mut env = bare();
        // mmap(NULL, 0x1000, PROT_READ|WRITE, MAP_PRIVATE|ANONYMOUS, -1, 0).
        set64(&mut env, Gpr(0), abi::MMAP);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 0x1000);
        set64(&mut env, Gpr(2), 3);
        set64(&mut env, Gpr(10), 0x22);
        set64(&mut env, Gpr(8), 0xffff_ffff_ffff_ffff);
        set64(&mut env, Gpr(9), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let base = get64(&mut env, Gpr(0));
        assert_eq!(base, 0x6000_0000);
        // len=0 は EINVAL。
        set64(&mut env, Gpr(0), abi::MMAP);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
    }

    #[test]
    fn mmap_null_skips_mapped() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        sys.mmap_base = 0x6000_0000;
        let mut env = bare();
        // 先に 0x60000000 を写像して内容を書く（縮小で残った写像を模す）。
        env.backend
            .mem
            .map(VirtAddr(0x6000_0000), 1, Perms::RW)
            .unwrap();
        env.backend.mem.write(VirtAddr(0x6000_0000), b"hi").unwrap();
        // mmap(NULL, 0x1000, ...) は占有を避けて次のページを返す。
        set64(&mut env, Gpr(0), abi::MMAP);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 0x1000);
        set64(&mut env, Gpr(2), 3);
        set64(&mut env, Gpr(10), 0x22);
        set64(&mut env, Gpr(8), 0xffff_ffff_ffff_ffff);
        set64(&mut env, Gpr(9), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0x6000_1000);
        // 既存内容は残っている。
        let mut back = [0u8; 2];
        env.backend
            .mem
            .read(VirtAddr(0x6000_0000), &mut back, data_access())
            .unwrap();
        assert_eq!(&back, b"hi");
    }

    #[test]
    fn mmap_anonymous_stays_clear_of_brk() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        sys.init_brk(0x1234);
        let mut env = bare();
        // brk でヒープを伸ばしても mmap 基底には触れない。
        set64(&mut env, Gpr(0), abi::BRK);
        set64(&mut env, Gpr(7), 0x4000);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(sys.heap_end, 0x4000);
        // mmap(NULL, ...) はヒープ末尾ではなく mmap 領域から取る。
        set64(&mut env, Gpr(0), abi::MMAP);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 0x2000);
        set64(&mut env, Gpr(2), 3);
        set64(&mut env, Gpr(10), 0x22);
        set64(&mut env, Gpr(8), 0xffff_ffff_ffff_ffff);
        set64(&mut env, Gpr(9), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0x4000_0000_0000);
        // 2 回目はその続き。ヒープ領域には割り当てない。
        set64(&mut env, Gpr(0), abi::MMAP);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0x4000_0000_2000);
        // mmap はブレークを動かさない。brk 側も mmap 基底を動かさない。
        assert_eq!(sys.heap_end, 0x4000);
        assert_eq!(sys.mmap_base, 0x4000_0000_4000);
    }

    #[test]
    fn mmap_fixed_and_hint_leave_cursor() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        sys.init_brk(0x1234);
        let mut env = bare();
        // MAP_FIXED は要求番地に写像し、割り当て基底は動かさない。
        set64(&mut env, Gpr(0), abi::MMAP);
        set64(&mut env, Gpr(7), 0x7000_0000);
        set64(&mut env, Gpr(6), 0x1000);
        set64(&mut env, Gpr(2), 3);
        set64(&mut env, Gpr(10), 0x32);
        set64(&mut env, Gpr(8), 0xffff_ffff_ffff_ffff);
        set64(&mut env, Gpr(9), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0x7000_0000);
        assert_eq!(sys.mmap_base, 0);
        // ヒント付き（FIXED なし）も同様。次の mmap(NULL) は基底から取る。
        set64(&mut env, Gpr(0), abi::MMAP);
        set64(&mut env, Gpr(7), 0x8000_0000);
        set64(&mut env, Gpr(10), 0x22);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0x8000_0000);
        assert_eq!(sys.mmap_base, 0);
        set64(&mut env, Gpr(0), abi::MMAP);
        set64(&mut env, Gpr(7), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0x4000_0000_0000);
    }

    #[test]
    fn mmap_anonymous_stays_in_guest_space() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        // 32 ビット空間（i386）では割り当て基底も空間内に取る。
        env.backend.addr_mask = 0xffff_ffff;
        set64(&mut env, Gpr(0), abi::MMAP);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 0x1000);
        set64(&mut env, Gpr(2), 3);
        set64(&mut env, Gpr(10), 0x22);
        set64(&mut env, Gpr(8), 0xffff_ffff_ffff_ffff);
        set64(&mut env, Gpr(9), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0x4000_0000);
        // 空間の末尾を跨ぐ割り当ては ENOMEM。
        sys.mmap_base = 0xffff_f000;
        set64(&mut env, Gpr(0), abi::MMAP);
        set64(&mut env, Gpr(6), 0x2000);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(ENOMEM));
    }

    #[test]
    fn openat_reads_string_near_map_edge() {
        // 写像の末尾近くに置いたパスも読める（まとめて読むと境界で失敗するため）。
        let mut sys = Linux::default();
        let mut env = bare();
        env.backend.mem.write(VirtAddr(0x1FFD), b"/x\0").unwrap();
        set_regs(
            &mut env,
            crate::x86_32::OPENAT as u32,
            0xffff_ff9c,
            0x1FFD,
            0,
        );
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        // /x は存在しないため ENOENT。読めなければ Unimplemented になる。
        assert_eq!(env.backend.get(Gpr(0).state()), neg_errno(ENOENT));
    }

    #[test]
    fn openat_missing_is_enoent() {
        let mut sys = Linux::default();
        let mut env = bare();
        env.backend
            .mem
            .write(VirtAddr(0x100), b"/no/such/file\0")
            .unwrap();
        set_regs(
            &mut env,
            crate::x86_32::OPENAT as u32,
            0xffff_ff9c,
            0x100,
            0,
        );
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), neg_errno(ENOENT));
    }

    #[test]
    fn openat_rejects_bad_dirfd_and_relpath() {
        let mut sys = Linux::default();
        let mut env = bare();
        env.backend.mem.write(VirtAddr(0x100), b"/x\0").unwrap();
        // dirfd が AT_FDCWD ではない。
        set_regs(&mut env, crate::x86_32::OPENAT as u32, 3, 0x100, 0);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), neg_errno(EINVAL));
        // 相対パスは作業ディレクトリから開く。ここには無いので ENOENT。
        env.backend.mem.write(VirtAddr(0x100), b"rel\0").unwrap();
        set_regs(
            &mut env,
            crate::x86_32::OPENAT as u32,
            0xffff_ff9c,
            0x100,
            0,
        );
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), neg_errno(ENOENT));
    }

    #[test]
    fn openat_creat_wronly_write_roundtrip() {
        // truncate/cp/split の前段: O_WRONLY|O_CREAT|O_TRUNC で作り、write して read で戻る.
        // O_EXCL 付きの既存作成は EEXIST(17)。旧実装は書込み系 flags を EINVAL で拒否した.
        let dir = std::env::temp_dir().join(format!("polyisa-unit-open-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let path_s = dir.join("f.txt").to_string_lossy().into_owned();
        let mut sys = Linux::default();
        let mut env = bare();
        env.backend
            .mem
            .write(VirtAddr(0x100), path_s.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x100 + path_s.len() as u64), &[0])
            .unwrap();
        env.backend.mem.write(VirtAddr(0x200), b"abcdef").unwrap();
        // 存在しない path の O_WRONLY のみは ENOENT。
        set_regs(
            &mut env,
            crate::x86_32::OPENAT as u32,
            0xffff_ff9c,
            0x100,
            1,
        );
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), neg_errno(ENOENT));
        // O_WRONLY|O_CREAT|O_TRUNC (1|0o100|0o1000=0o1101) で作成 -> fd 3。
        set_regs(
            &mut env,
            crate::x86_32::OPENAT as u32,
            0xffff_ff9c,
            0x100,
            0o1101,
        );
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 3);
        // write(3, 0x200, 6) -> 6。
        set_regs(&mut env, crate::x86_32::WRITE as u32, 3, 0x200, 6);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 6);
        // close(3) -> 0。
        set_regs(&mut env, crate::x86_32::CLOSE as u32, 3, 0, 0);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 0);
        // O_RDONLY で開き直して read -> "abcdef"。
        set_regs(
            &mut env,
            crate::x86_32::OPENAT as u32,
            0xffff_ff9c,
            0x100,
            0,
        );
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 3);
        set_regs(&mut env, crate::x86_32::READ as u32, 3, 0x300, 6);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 6);
        let mut back = [0u8; 6];
        env.backend
            .mem
            .read(VirtAddr(0x300), &mut back, data_access())
            .unwrap();
        assert_eq!(&back, b"abcdef");
        // O_RDWR で開いて追記位置を読書きできる。
        set_regs(&mut env, crate::x86_32::CLOSE as u32, 3, 0, 0);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        set_regs(
            &mut env,
            crate::x86_32::OPENAT as u32,
            0xffff_ff9c,
            0x100,
            2,
        );
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 3);
        // O_CREAT|O_EXCL の既存作成は EEXIST(17)。
        set_regs(
            &mut env,
            crate::x86_32::OPENAT as u32,
            0xffff_ff9c,
            0x100,
            0o300,
        );
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), neg_errno(17));
        // O_TRUNC で空になる。
        set_regs(&mut env, crate::x86_32::CLOSE as u32, 3, 0, 0);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        set_regs(
            &mut env,
            crate::x86_32::OPENAT as u32,
            0xffff_ff9c,
            0x100,
            0o1101,
        );
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 3);
        set_regs(&mut env, crate::x86_32::READ as u32, 3, 0x300, 6);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 0);
        // 読取り専用 fd への write は EBADF。
        set_regs(&mut env, crate::x86_32::CLOSE as u32, 3, 0, 0);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        set_regs(
            &mut env,
            crate::x86_32::OPENAT as u32,
            0xffff_ff9c,
            0x100,
            0,
        );
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 3);
        set_regs(&mut env, crate::x86_32::WRITE as u32, 3, 0x200, 6);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), neg_errno(EBADF));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn openat_accepts_o_directory() {
        // O_DIRECTORY 付きでも開ける（opendir が付ける旗）。
        let mut sys = Linux::default();
        let mut env = bare();
        env.backend.mem.write(VirtAddr(0x100), b"/\0").unwrap();
        set_regs(
            &mut env,
            crate::x86_32::OPENAT as u32,
            0xffff_ff9c,
            0x100,
            0x4000,
        );
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        // fd (3) が返る。ENOENT/EINVAL ではない。
        assert_eq!(env.backend.get(Gpr(0).state()), 3);
    }

    #[test]
    fn read_write_close_roundtrip() {
        let path = std::env::temp_dir().join(format!("polyisa-unit-{}", std::process::id()));
        std::fs::write(&path, b"abcdef").unwrap();
        let path_s = path.to_string_lossy().into_owned();
        let mut sys = Linux::default();
        let mut env = bare();
        env.backend
            .mem
            .write(VirtAddr(0x100), path_s.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x100 + path_s.len() as u64), &[0])
            .unwrap();
        // openat -> fd 3。
        set_regs(
            &mut env,
            crate::x86_32::OPENAT as u32,
            0xffff_ff9c,
            0x100,
            0,
        );
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 3);
        // read(fd=3, buf=0x200, 64) -> 6。
        set_regs(&mut env, crate::x86_32::READ as u32, 3, 0x200, 64);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 6);
        // close(3) -> 0、もう一度 close(3) -> EBADF。
        set_regs(&mut env, crate::x86_32::CLOSE as u32, 3, 0, 0);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 0);
        set_regs(&mut env, crate::x86_32::CLOSE as u32, 3, 0, 0);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), neg_errno(EBADF));
        // read(closed fd=3) -> EBADF。
        set_regs(&mut env, crate::x86_32::READ as u32, 3, 0x200, 64);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), neg_errno(EBADF));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn stdin_close_open_read_serves_file() {
        // uniq の stdin 付け替え回帰: close(0) -> 0、open -> 0、read(0) で内容が読める.
        // 旧実装は close(0) で EBADF、read(0) で空読み 0 を返した.
        let path = std::env::temp_dir().join(format!("polyisa-unit-stdin-{}", std::process::id()));
        std::fs::write(&path, b"abcdef").unwrap();
        let path_s = path.to_string_lossy().into_owned();
        let mut sys = Linux::default();
        let mut env = bare();
        env.backend
            .mem
            .write(VirtAddr(0x100), path_s.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x100 + path_s.len() as u64), &[0])
            .unwrap();
        // close(0) -> 0。
        set_regs(&mut env, crate::x86_32::CLOSE as u32, 0, 0, 0);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 0);
        // openat -> 最下位の空き 0。
        set_regs(
            &mut env,
            crate::x86_32::OPENAT as u32,
            0xffff_ff9c,
            0x100,
            0,
        );
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 0);
        // read(0) -> 6（付け替えたファイルから読む）。
        set_regs(&mut env, crate::x86_32::READ as u32, 0, 0x200, 64);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 6);
        // fcntl(0) -> 0（付け替え中は妥当）。
        set_regs(&mut env, crate::x86_32::FCNTL as u32, 0, 3, 0);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 0);
        // close(0) -> 0、read(0) -> EBADF、もう一度 close(0) -> EBADF。
        set_regs(&mut env, crate::x86_32::CLOSE as u32, 0, 0, 0);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 0);
        set_regs(&mut env, crate::x86_32::READ as u32, 0, 0x200, 64);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), neg_errno(EBADF));
        set_regs(&mut env, crate::x86_32::CLOSE as u32, 0, 0, 0);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), neg_errno(EBADF));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn open_reuses_freed_slot() {
        // 最下位の空き番号を再利用する: open -> 3、close(3) -> 0、open -> 3.
        // 旧実装は常に末尾へ積み、2回目は 4 を返した.
        let path = std::env::temp_dir().join(format!("polyisa-unit-reuse-{}", std::process::id()));
        std::fs::write(&path, b"abcdef").unwrap();
        let path_s = path.to_string_lossy().into_owned();
        let mut sys = Linux::default();
        let mut env = bare();
        env.backend
            .mem
            .write(VirtAddr(0x100), path_s.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x100 + path_s.len() as u64), &[0])
            .unwrap();
        let openat = (crate::x86_32::OPENAT as u32, 0xffff_ff9c, 0x100, 0);
        set_regs(&mut env, openat.0, openat.1, openat.2, openat.3);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 3);
        set_regs(&mut env, crate::x86_32::CLOSE as u32, 3, 0, 0);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 0);
        set_regs(&mut env, openat.0, openat.1, openat.2, openat.3);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 3);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn brk_query_extend_shrink() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        sys.init_brk(0x1234);
        assert_eq!(sys.heap_end, 0x2000);
        let mut env = bare();
        // brk(0) は問い合わせであり現ブレークを返す。
        set64(&mut env, Gpr(0), abi::BRK);
        set64(&mut env, Gpr(7), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0x2000);
        // brk(0x2100) は 0x3000 まで拡張する。
        set64(&mut env, Gpr(0), abi::BRK);
        set64(&mut env, Gpr(7), 0x2100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0x3000);
        assert_eq!(sys.heap_end, 0x3000);
        // 拡張域は零初期化され、読み書きできる。
        env.backend.mem.write(VirtAddr(0x2FF0), b"hi").unwrap();
        let mut back = [0u8; 2];
        env.backend
            .mem
            .read(VirtAddr(0x2FF0), &mut back, data_access())
            .unwrap();
        assert_eq!(&back, b"hi");
        // 縮小は受け付ける。
        set64(&mut env, Gpr(0), abi::BRK);
        set64(&mut env, Gpr(7), 0x2000);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0x2000);
        // 拡張しすぎは失敗扱い（現ブレークを返す）。
        set64(&mut env, Gpr(0), abi::BRK);
        set64(&mut env, Gpr(7), 0x2000 + 256 * 1024 * 1024 + 1);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0x2000);
        assert_eq!(sys.heap_end, 0x2000);
    }

    #[test]
    fn brk_shrink_regrow_keeps_data() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        sys.init_brk(0x1234);
        let mut env = bare();
        // brk で 0x3000 まで拡張し、書き込んでから縮小・再拡張する。
        set64(&mut env, Gpr(0), abi::BRK);
        set64(&mut env, Gpr(7), 0x3000);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0x3000);
        env.backend.mem.write(VirtAddr(0x2FF0), b"hi").unwrap();
        set64(&mut env, Gpr(0), abi::BRK);
        set64(&mut env, Gpr(7), 0x2000);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0x2000);
        set64(&mut env, Gpr(0), abi::BRK);
        set64(&mut env, Gpr(7), 0x3000);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0x3000);
        // 縮小前の内容が残っている（ゼロ化されない）。
        let mut back = [0u8; 2];
        env.backend
            .mem
            .read(VirtAddr(0x2FF0), &mut back, data_access())
            .unwrap();
        assert_eq!(&back, b"hi");
    }

    #[test]
    fn arch_prctl_set_get_fs() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        // ARCH_SET_FS(0x1002) は base を記録して 0 を返す。
        set64(&mut env, Gpr(0), abi::ARCH_PRCTL);
        set64(&mut env, Gpr(7), 0x1002);
        set64(&mut env, Gpr(6), 0x5000);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        assert_eq!(
            env.backend.get(polyisa_guest_x86::sem::fs_base_ref()),
            0x5000
        );
        // ARCH_GET_FS(0x1003) は記録値を [addr] に書いて 0 を返す。
        set64(&mut env, Gpr(0), abi::ARCH_PRCTL);
        set64(&mut env, Gpr(7), 0x1003);
        set64(&mut env, Gpr(6), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        let mut back = [0u8; 8];
        env.backend
            .mem
            .read(VirtAddr(0x100), &mut back, data_access())
            .unwrap();
        assert_eq!(u64::from_le_bytes(back), 0x5000);
        // 不明な op は EINVAL。
        set64(&mut env, Gpr(0), abi::ARCH_PRCTL);
        set64(&mut env, Gpr(7), 0x9999);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
    }

    fn rd8(env: &mut BareEnv, a: u64) -> u64 {
        let mut b = [0u8; 8];
        env.backend
            .mem
            .read(VirtAddr(a), &mut b, data_access())
            .unwrap();
        u64::from_le_bytes(b)
    }

    #[test]
    fn arch_prctl_xcomp() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        let mut prctl = |env: &mut BareEnv, op: u64, arg: u64| {
            set64(env, Gpr(0), abi::ARCH_PRCTL);
            set64(env, Gpr(7), op);
            set64(env, Gpr(6), arg);
            sys.handle_trap(env, 0);
            get64(env, Gpr(0))
        };
        // 対応=3（x87+SSE。amx_tile なしの既定モデル）、許可=3。
        env.backend.set(polyisa_guest_x86::sem::xcomp_supp_ref(), 3);
        env.backend.set(polyisa_guest_x86::sem::xcomp_perm_ref(), 3);
        assert_eq!(prctl(&mut env, 0x1021, 0x100), 0); // GET_XCOMP_SUPP
        assert_eq!(rd8(&mut env, 0x100), 3);
        assert_eq!(prctl(&mut env, 0x1022, 0x108), 0); // GET_XCOMP_PERM
        assert_eq!(rd8(&mut env, 0x108), 3);
        // 未対応の XTILEDATA(18)/APX(19)/SCALEDATA(20) は EOPNOTSUPP、上限超は EINVAL。
        assert_eq!(prctl(&mut env, 0x1023, 18), neg_errno64(EOPNOTSUPP));
        assert_eq!(prctl(&mut env, 0x1023, 19), neg_errno64(EOPNOTSUPP));
        assert_eq!(prctl(&mut env, 0x1023, 20), neg_errno64(EOPNOTSUPP));
        assert_eq!(prctl(&mut env, 0x1023, 21), neg_errno64(EINVAL));
        // amx_tile 相当の対応マスクにすると要求が通る。
        env.backend
            .set(polyisa_guest_x86::sem::xcomp_supp_ref(), 0x6_0003);
        // XTILEDATA の要求は依存する XTILECFG もまとめて許可する。
        assert_eq!(prctl(&mut env, 0x1023, 18), 0);
        assert_eq!(prctl(&mut env, 0x1023, 17), 0);
        assert_eq!(
            env.backend.get(polyisa_guest_x86::sem::xcomp_perm_ref()),
            0x6_0003
        );
        // 動的成分の許可は XCR0 にも反映される。
        assert_eq!(
            env.backend.get(polyisa_guest_x86::sem::xcr0_ref()),
            0x6_0000
        );
        // 書き込み先が未写像なら EFAULT。
        assert_eq!(prctl(&mut env, 0x1021, 0x1_0000_0000), neg_errno64(EFAULT));
    }

    #[test]
    fn signal_deliver_sigreturn() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        // フレーム用のスタック領域を写像する（0x6000-0x9FFF）。
        env.backend.mem.map(VirtAddr(0x6000), 4, Perms::RW).unwrap();
        // 64 ビットでフルサイズの CPU 状態が要る。
        env.backend.set(polyisa_guest_x86::sem::fcw_ref(), 0x037F);
        env.backend
            .set(polyisa_guest_x86::sem::ftw_ref(), 0xffffu16);
        env.backend.set(polyisa_guest_x86::sem::mxcsr_ref(), 0x1F80);
        env.backend.set(polyisa_guest_x86::sem::xcr0_ref(), 7);
        env.backend.set(polyisa_guest_x86::sem::xcomp_supp_ref(), 7);
        env.backend.set(polyisa_guest_x86::sem::xcomp_perm_ref(), 7);
        env.backend
            .set(polyisa_guest_x86::sem::cpuid_ref(1, 2), 1u32 << 26);
        env.backend.set(
            polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(0)),
            0x1122_3344,
        );
        env.backend.set(
            polyisa_guest_x86::sem::ymm_hi_ref(polyisa_guest_x86::sem::Xmm(0)),
            0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00u128,
        );
        set64(&mut env, Gpr(4), 0x8000); // RSP
        set64(&mut env, Gpr(3), 0xAAAA); // RBX
        env.backend.set(polyisa_guest_x86::sem::eip_ref(), 0x4000);
        // kernel_sigaction {handler, flags=SA_RESTORER, restorer, mask}。
        env.backend
            .mem
            .write(VirtAddr(0x200), &0x9000u64.to_le_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x208), &crate::x86::SA_RESTORER.to_le_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x210), &0x9100u64.to_le_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x218), &(1u64 << 11).to_le_bytes())
            .unwrap();
        // rt_sigaction(SIGUSR1=10, act=0x200, old=0, 8)。
        set64(&mut env, Gpr(0), abi::RT_SIGACTION);
        set64(&mut env, Gpr(7), 10);
        set64(&mut env, Gpr(6), 0x200);
        set64(&mut env, Gpr(2), 0);
        set64(&mut env, Gpr(10), 8);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        // SIGKILL(9) にはハンドラを設定できない。
        set64(&mut env, Gpr(0), abi::RT_SIGACTION);
        set64(&mut env, Gpr(7), 9);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
        // ただし act=NULL の照会は SIGKILL に対しても成功する。
        set64(&mut env, Gpr(0), abi::RT_SIGACTION);
        set64(&mut env, Gpr(7), 9);
        set64(&mut env, Gpr(6), 0);
        set64(&mut env, Gpr(2), 0x220);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        // kill(getpid(), SIGUSR1) で保留に積む。
        set64(&mut env, Gpr(0), abi::GETPID);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let pid = get64(&mut env, Gpr(0));
        set64(&mut env, Gpr(0), abi::KILL);
        set64(&mut env, Gpr(7), pid);
        set64(&mut env, Gpr(6), 10);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        // 次の命令境界で配送される。
        sys.after_step(&mut env);
        let f = get64(&mut env, Gpr(4));
        assert!(f < 0x8000 - 1024);
        // フレーム基底は ≡8 (mod 16)（call 直後の関数入口と同じ）。
        assert_eq!(f % 16, 8);
        assert_eq!(env.backend.get(polyisa_guest_x86::sem::eip_ref()), 0x9000);
        assert_eq!(
            env.backend.get(polyisa_guest_x86::sem::xmm_ref(
                polyisa_guest_x86::sem::Xmm(0)
            )),
            0,
            "ハンドラ開始時の user FP state は初期化される"
        );
        assert_eq!(get64(&mut env, Gpr(7)), 10); // 第1引数=シグナル
        assert_eq!(get64(&mut env, Gpr(6)), f + 312); // &siginfo
        assert_eq!(get64(&mut env, Gpr(2)), f + 8); // &ucontext
        assert_eq!(rd8(&mut env, f), 0x9100); // pretcode=restorer
        assert_eq!(rd8(&mut env, f + 304), 0); // uc_sigmask=旧マスク
        assert_eq!(rd8(&mut env, f + 312) & 0xFFFF_FFFF, 10); // si_signo
        assert_eq!(rd8(&mut env, f + 312 + 16) & 0xFFFF_FFFF, pid); // si_pid
        // gregs: RIP=旧 eip, RBX=0xAAAA。
        assert_eq!(rd8(&mut env, f + 48 + 8 * 16), 0x4000);
        assert_eq!(rd8(&mut env, f + 48 + 8 * 11), 0xAAAA);
        // fpstate はフレームの直上に別置き。fpregs が指す。
        let fp = rd8(&mut env, f + 48 + 184);
        assert_eq!(fp % 64, 0); // 64 整列
        assert_eq!(rd8(&mut env, fp) & 0xFFFF, 0x037F);
        assert_eq!(rd8(&mut env, fp + 24) & 0xFFFF_FFFF, 0x1F80);
        assert_eq!(rd8(&mut env, fp + 160), 0x1122_3344);
        // xsave 拡張: SW 予約域、xstate header、YMMH 成分。
        assert_eq!(rd8(&mut env, fp + 464) & 0xFFFF_FFFF, 0x4650_5853);
        assert_eq!(rd8(&mut env, fp + 468) & 0xFFFF_FFFF, 0x340 + 4);
        assert_eq!(rd8(&mut env, fp + 472), 7);
        assert_eq!(rd8(&mut env, fp + 480) & 0xFFFF_FFFF, 0x340);
        assert_eq!(rd8(&mut env, fp + 0x340) & 0xFFFF_FFFF, 0x4650_5845);
        assert_eq!(rd8(&mut env, fp + 512), 7, "xstate_bv");
        assert_eq!(rd8(&mut env, fp + 0x240), 0x99aa_bbcc_ddee_ff00);
        assert_eq!(rd8(&mut env, fp + 0x248), 0x1122_3344_5566_7788);
        // ハンドラ中はマスクが act.mask|シグナル になる。
        assert_eq!(sys.sig_mask, (1 << 11) | (1 << 9));
        // ハンドラが状態を変えてから ret で pretcode（restorer）
        // をポップ → RSP はフレーム基底+8 で rt_sigreturn へ来る。
        set64(&mut env, Gpr(3), 0xBBBB);
        env.backend.set(
            polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(0)),
            0,
        );
        env.backend.set(
            polyisa_guest_x86::sem::ymm_hi_ref(polyisa_guest_x86::sem::Xmm(0)),
            0,
        );
        set64(&mut env, Gpr(4), f + 8);
        set64(&mut env, Gpr(0), abi::RT_SIGRETURN);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        // コンテキストと FP 状態・マスクが復元される。
        assert_eq!(env.backend.get(polyisa_guest_x86::sem::eip_ref()), 0x4000);
        assert_eq!(get64(&mut env, Gpr(4)), 0x8000);
        assert_eq!(get64(&mut env, Gpr(3)), 0xAAAA);
        assert_eq!(
            env.backend.get(polyisa_guest_x86::sem::xmm_ref(
                polyisa_guest_x86::sem::Xmm(0)
            )),
            0x1122_3344
        );
        assert_eq!(
            env.backend.get(polyisa_guest_x86::sem::ymm_hi_ref(
                polyisa_guest_x86::sem::Xmm(0)
            )),
            0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00u128
        );
        assert_eq!(sys.sig_mask, 0);
    }

    #[test]
    fn sigreturn_null_fpstate_initializes_fp_sse_state() {
        let mut env = bare();
        env.backend.mem.map(VirtAddr(0x6000), 8, Perms::RW).unwrap();
        env.backend
            .set(polyisa_guest_x86::sem::cpuid_ref(1, 2), 1u32 << 26);
        env.backend.set(polyisa_guest_x86::sem::xcomp_supp_ref(), 7);
        env.backend.set(polyisa_guest_x86::sem::xcomp_perm_ref(), 7);
        env.backend.set(polyisa_guest_x86::sem::fcw_ref(), 0x037F);
        env.backend
            .set(polyisa_guest_x86::sem::ftw_ref(), 0xffffu16);
        env.backend.set(polyisa_guest_x86::sem::mxcsr_ref(), 0x1F80);
        set64(&mut env, Gpr(4), 0x9000);
        env.backend.set(polyisa_guest_x86::sem::eip_ref(), 0x4000);
        assert!(crate::x86::rt_sigframe_write(
            &mut env,
            10,
            &crate::x86::SigAct::default(),
            0,
            1234
        ));
        let f = get64(&mut env, Gpr(4));
        // sigcontext.fpregs=NULL。ハンドラ中の値は中断コンテキストへ漏れない。
        env.backend
            .mem
            .write(VirtAddr(f + 48 + 184), &0u64.to_le_bytes())
            .unwrap();
        env.backend.set(
            polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(0)),
            0xffffu128,
        );
        env.backend.set(polyisa_guest_x86::sem::mxcsr_ref(), 0);
        set64(&mut env, Gpr(4), f + 8);
        assert!(crate::x86::rt_sigframe_read(&mut env).is_some());
        assert_eq!(
            env.backend.get(polyisa_guest_x86::sem::xmm_ref(
                polyisa_guest_x86::sem::Xmm(0)
            )),
            0
        );
        assert_eq!(env.backend.get(polyisa_guest_x86::sem::mxcsr_ref()), 0x1F80);
        assert_eq!(env.backend.get(polyisa_guest_x86::sem::fcw_ref()), 0x037F);
    }

    #[test]
    fn sigreturn_initializes_xfeatures_missing_from_frame() {
        let mut env = bare();
        env.backend.mem.map(VirtAddr(0x6000), 8, Perms::RW).unwrap();
        env.backend
            .set(polyisa_guest_x86::sem::cpuid_ref(1, 2), 1u32 << 26);
        env.backend.set(polyisa_guest_x86::sem::xcomp_supp_ref(), 7);
        env.backend.set(polyisa_guest_x86::sem::xcomp_perm_ref(), 7);
        env.backend.set(polyisa_guest_x86::sem::xcr0_ref(), 7);
        env.backend.set(polyisa_guest_x86::sem::fcw_ref(), 0x037F);
        env.backend
            .set(polyisa_guest_x86::sem::ftw_ref(), 0xffffu16);
        env.backend.set(polyisa_guest_x86::sem::mxcsr_ref(), 0x1F80);
        env.backend.set(
            polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(0)),
            0x1122_3344,
        );
        env.backend.set(
            polyisa_guest_x86::sem::ymm_hi_ref(polyisa_guest_x86::sem::Xmm(0)),
            0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00u128,
        );
        set64(&mut env, Gpr(4), 0x9000);
        env.backend.set(polyisa_guest_x86::sem::eip_ref(), 0x4000);
        assert!(crate::x86::rt_sigframe_write(
            &mut env,
            10,
            &crate::x86::SigAct::default(),
            0,
            1234
        ));
        let f = get64(&mut env, Gpr(4));
        let fp = rd8(&mut env, f + 48 + 184);
        // user により xfeatures から AVX(bit2) が削られたフレームを再現する。
        env.backend
            .mem
            .write(VirtAddr(fp + 472), &3u64.to_le_bytes())
            .unwrap();
        env.backend.set(
            polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(0)),
            0,
        );
        env.backend.set(
            polyisa_guest_x86::sem::ymm_hi_ref(polyisa_guest_x86::sem::Xmm(0)),
            0xffffu128,
        );
        set64(&mut env, Gpr(4), f + 8);
        assert!(crate::x86::rt_sigframe_read(&mut env).is_some());
        assert_eq!(
            env.backend.get(polyisa_guest_x86::sem::xmm_ref(
                polyisa_guest_x86::sem::Xmm(0)
            )),
            0x1122_3344
        );
        // AVX は復元対象から外れたので、ハンドラの値を残さず初期状態へ戻る。
        assert_eq!(
            env.backend.get(polyisa_guest_x86::sem::ymm_hi_ref(
                polyisa_guest_x86::sem::Xmm(0)
            )),
            0
        );
    }

    #[test]
    fn exception_delivers_sigsegv_frame() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        env.backend.mem.map(VirtAddr(0x6000), 4, Perms::RW).unwrap();
        env.backend.set(polyisa_guest_x86::sem::fcw_ref(), 0x037F);
        env.backend
            .set(polyisa_guest_x86::sem::ftw_ref(), 0xffffu16);
        env.backend.set(polyisa_guest_x86::sem::mxcsr_ref(), 0x1F80);
        env.backend.set(polyisa_guest_x86::sem::xcr0_ref(), 3);
        set64(&mut env, Gpr(4), 0x8000);
        env.backend.set(polyisa_guest_x86::sem::eip_ref(), 0x4000);
        // SIGSEGV(11) のハンドラを入れる。
        env.backend
            .mem
            .write(VirtAddr(0x200), &0x9000u64.to_le_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x208), &crate::x86::SA_RESTORER.to_le_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x210), &0x9100u64.to_le_bytes())
            .unwrap();
        set64(&mut env, Gpr(0), abi::RT_SIGACTION);
        set64(&mut env, Gpr(7), 11);
        set64(&mut env, Gpr(6), 0x200);
        set64(&mut env, Gpr(2), 0);
        set64(&mut env, Gpr(10), 8);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        // 同期 fault を配送すると、ただちにハンドラへ入る。
        let ex = polyisa_sem::GuestException {
            kind: polyisa_sem::ExceptionKind::PageFault,
            code: 0,
            addr: Some(0xDEAD_0000),
            in_delay_slot: false,
        };
        assert!(matches!(
            sys.handle_exception(&mut env, ex),
            TrapOutcome::Handled
        ));
        let f = get64(&mut env, Gpr(4));
        assert_eq!(env.backend.get(polyisa_guest_x86::sem::eip_ref()), 0x9000);
        assert_eq!(get64(&mut env, Gpr(7)), 11);
        assert_eq!(rd8(&mut env, f + 312) & 0xFFFF_FFFF, 11);
        assert_eq!(rd8(&mut env, f + 312 + 8) & 0xFFFF_FFFF, 1);
        assert_eq!(rd8(&mut env, f + 312 + 16), 0xDEAD_0000);
        assert_eq!(rd8(&mut env, f + 48 + 8 * 16), 0x4000, "faulting rip");
    }

    #[test]
    fn exception_default_action_records_signal_death() {
        let mut sys = Linux::x86_64();
        let mut env = bare();
        env.backend.set(polyisa_guest_x86::sem::eip_ref(), 0x4000);
        let ex = polyisa_sem::GuestException {
            kind: polyisa_sem::ExceptionKind::Undefined,
            code: 6,
            addr: Some(0x4000),
            in_delay_slot: false,
        };
        assert!(matches!(
            sys.handle_exception(&mut env, ex),
            TrapOutcome::Exit(4)
        ));
        let pid = polyisa_kernel::ProcessId(sys.pid);
        assert!(sys.procs.borrow().pgid(pid).is_some());
    }

    #[test]
    fn exception_delivers_i386_sigsegv_frame_and_sigreturn() {
        let mut sys = Linux::x86_32();
        let mut env = bare();
        env.backend.mem.map(VirtAddr(0x6000), 4, Perms::RW).unwrap();
        env.backend
            .set(polyisa_guest_x86::sem::cpuid_ref(1, 3), 1u32 << 24);
        env.backend
            .set(polyisa_guest_x86::sem::cpuid_ref(1, 2), 1u32 << 26);
        env.backend.set(polyisa_guest_x86::sem::xcomp_supp_ref(), 3);
        env.backend.set(polyisa_guest_x86::sem::xcomp_perm_ref(), 3);
        env.backend.set(polyisa_guest_x86::sem::fcw_ref(), 0x037F);
        env.backend
            .set(polyisa_guest_x86::sem::ftw_ref(), 0xffffu16);
        env.backend.set(polyisa_guest_x86::sem::mxcsr_ref(), 0x1F80);
        env.backend.set(
            polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(0)),
            0x1122_3344,
        );
        sys.sigacts.resize(64, crate::x86::SigAct::default());
        sys.sigacts[10] = crate::x86::SigAct {
            handler: 0x9000,
            flags: crate::x86::SA_RESTORER,
            restorer: 0x9100,
            mask: 0,
        };
        set64(&mut env, Gpr(4), 0x8000);
        set64(&mut env, Gpr(3), 0xAAAA);
        env.backend.set(polyisa_guest_x86::sem::eip_ref(), 0x4000);
        let ex = polyisa_sem::GuestException {
            kind: polyisa_sem::ExceptionKind::PageFault,
            code: 0,
            addr: Some(0xDEAD_0000),
            in_delay_slot: false,
        };
        assert!(matches!(
            sys.handle_exception(&mut env, ex),
            TrapOutcome::Handled
        ));
        let f = get64(&mut env, Gpr(4));
        assert_eq!((f + 4) % 16, 0, "i386 ABI stack alignment");
        assert_eq!(env.backend.get(polyisa_guest_x86::sem::eip_ref()), 0x9000);
        assert_eq!(get64(&mut env, Gpr(0)), 11, "EAX=signal");
        assert_eq!(get64(&mut env, Gpr(2)), f + 16, "EDX=&siginfo");
        assert_eq!(get64(&mut env, Gpr(1)), f + 144, "ECX=&ucontext");
        assert_eq!(rd8(&mut env, f) & 0xFFFF_FFFF, 0x9100, "pretcode");
        assert_eq!(rd8(&mut env, f + 16) & 0xFFFF_FFFF, 11, "si_signo");
        assert_eq!(rd8(&mut env, f + 24) & 0xFFFF_FFFF, 1, "si_code");
        assert_eq!(rd8(&mut env, f + 28) & 0xFFFF_FFFF, 0xDEAD_0000, "si_addr");
        // sigcontext: ip=f+164+56、ebx=f+164+32。
        assert_eq!(rd8(&mut env, f + 164 + 56) & 0xFFFF_FFFF, 0x4000);
        assert_eq!(rd8(&mut env, f + 164 + 32) & 0xFFFF_FFFF, 0xAAAA);
        let fp = rd8(&mut env, f + 164 + 76) & 0xFFFF_FFFF;
        assert_ne!(fp, 0);
        assert_eq!((fp + 112) % 64, 0, "ia32 FX 領域は 64 整列");
        assert_eq!(rd8(&mut env, fp) & 0xFFFF, 0x037F);
        assert_eq!(rd8(&mut env, fp + 110) & 0xFFFF, 0, "X86_FXSR_MAGIC");
        assert_eq!(rd8(&mut env, fp + 112) & 0xFFFF, 0x037F);
        assert_eq!(rd8(&mut env, fp + 112 + 160), 0x1122_3344);
        assert_eq!(rd8(&mut env, fp + 112 + 464) & 0xFFFF_FFFF, 0x4650_5853);
        assert_eq!(rd8(&mut env, fp + 112 + 468) & 0xFFFF_FFFF, 0x240 + 4 + 112);
        assert_eq!(rd8(&mut env, fp + 112 + 480) & 0xFFFF_FFFF, 0x240);
        assert_eq!(rd8(&mut env, fp + 112 + 0x240) & 0xFFFF_FFFF, 0x4650_5845);
        // legacy 前置部が x87 の正本。FX 側と異なる値へ書き換えても legacy が勝つ。
        env.backend
            .mem
            .write(VirtAddr(fp), &0x027Fu16.to_le_bytes())
            .unwrap();
        // restorer へ来た状態（ESP=f+4）で rt_sigreturn を呼ぶ。
        set64(&mut env, Gpr(4), f + 4);
        set64(&mut env, Gpr(3), 0xBBBB);
        env.backend.set(
            polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(0)),
            0,
        );
        set64(&mut env, Gpr(0), crate::x86_32::RT_SIGRETURN);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(env.backend.get(polyisa_guest_x86::sem::eip_ref()), 0x4000);
        assert_eq!(get64(&mut env, Gpr(4)), 0x8000);
        assert_eq!(get64(&mut env, Gpr(3)), 0xAAAA);
        assert_eq!(env.backend.get(polyisa_guest_x86::sem::fcw_ref()), 0x027F);
        assert_eq!(
            env.backend.get(polyisa_guest_x86::sem::xmm_ref(
                polyisa_guest_x86::sem::Xmm(0)
            )),
            0x1122_3344
        );
    }

    #[test]
    fn sigaltstack_install_query_and_delivery() {
        let mut sys = Linux::x86_64();
        let mut env = bare();
        env.backend.mem.map(VirtAddr(0x6000), 2, Perms::RW).unwrap();
        // stack_t {ss_sp=0x6000, ss_flags=0, ss_size=0x2000}。
        let mut st = [0u8; 24];
        st[0..8].copy_from_slice(&0x6000u64.to_le_bytes());
        st[16..24].copy_from_slice(&0x2000u64.to_le_bytes());
        // 入力の ss_flags padding は無視する。
        st[12..16].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        env.backend.mem.write(VirtAddr(0x100), &st).unwrap();
        set64(&mut env, Gpr(0), 131); // x86-64 sigaltstack
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x120);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        assert_eq!(rd8(&mut env, 0x120), 0);
        assert_eq!(rd8(&mut env, 0x128) & 0xFFFF_FFFF, crate::x86::SS_DISABLE);
        assert_eq!(
            rd8(&mut env, 0x12C) & 0xFFFF_FFFF,
            0,
            "出力 padding は zero"
        );
        assert_eq!(rd8(&mut env, 0x130), 0, "初期状態の代替スタックは未設定");
        // 小さすぎる代替スタックは ENOMEM。
        st[16..24].copy_from_slice(&100u64.to_le_bytes());
        env.backend.mem.write(VirtAddr(0x100), &st).unwrap();
        set64(&mut env, Gpr(0), 131);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(ENOMEM));

        // SA_ONSTACK の配送は通常スタックではなく代替スタック上へ置く。
        sys.sigacts.resize(64, crate::x86::SigAct::default());
        sys.sigacts[9] = crate::x86::SigAct {
            handler: 0x9000,
            flags: crate::x86::SA_RESTORER | crate::x86::SA_ONSTACK,
            restorer: 0x9100,
            mask: 0,
        };
        // 正しいサイズを再設定する。
        st[16..24].copy_from_slice(&0x2000u64.to_le_bytes());
        env.backend.mem.write(VirtAddr(0x100), &st).unwrap();
        set64(&mut env, Gpr(0), 131);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        set64(&mut env, Gpr(4), 0x1800);
        sys.sig_pending = 1 << 9;
        sys.deliver_pending(&mut env);
        let f = get64(&mut env, Gpr(4));
        assert!(f > 0x6000 && f <= 0x8000, "frame {f:#x} は altstack 内");
        assert_eq!(
            f, 0x7C38,
            "新規 altstack では 128 バイト redzone を引かない"
        );
        assert_eq!(env.backend.get(polyisa_guest_x86::sem::eip_ref()), 0x9000);
        assert_eq!(rd8(&mut env, f + 24), 0x6000, "uc_stack.ss_sp");
        assert_eq!(rd8(&mut env, f + 32), 0, "uc_stack.ss_flags");
        assert_eq!(rd8(&mut env, f + 40), 0x2000, "uc_stack.ss_size");
    }

    #[test]
    fn sigaltstack_i386_uses_compat_stack() {
        let mut sys = Linux::x86_32();
        let mut env = bare();
        let mut st = [0u8; 12];
        st[0..4].copy_from_slice(&0x6000u32.to_le_bytes());
        st[8..12].copy_from_slice(&0x2000u32.to_le_bytes());
        env.backend.mem.write(VirtAddr(0x100), &st).unwrap();
        set64(&mut env, Gpr(0), 186); // i386 sigaltstack
        set64(&mut env, Gpr(3), 0x100);
        set64(&mut env, Gpr(1), 0x120);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        assert_eq!(rd8(&mut env, 0x120) & 0xFFFF_FFFF, 0);
        assert_eq!(rd8(&mut env, 0x124) & 0xFFFF_FFFF, crate::x86::SS_DISABLE);
        assert_eq!(rd8(&mut env, 0x128) & 0xFFFF_FFFF, 0);
    }

    #[test]
    fn exception_delivers_x32_sigsegv_frame_and_sigreturn() {
        let mut sys = Linux::x86_x32();
        let mut env = bare();
        env.backend.mem.map(VirtAddr(0x6000), 6, Perms::RW).unwrap();
        env.backend.set(polyisa_guest_x86::sem::fcw_ref(), 0x037F);
        env.backend
            .set(polyisa_guest_x86::sem::ftw_ref(), 0xffffu16);
        env.backend.set(polyisa_guest_x86::sem::mxcsr_ref(), 0x1F80);
        env.backend.set(
            polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(0)),
            0x1122_3344,
        );
        sys.sigacts.resize(64, crate::x86::SigAct::default());
        sys.sigacts[10] = crate::x86::SigAct {
            handler: 0x9000,
            flags: crate::x86::SA_RESTORER,
            restorer: 0x9100,
            mask: 0,
        };
        set64(&mut env, Gpr(4), 0x8000);
        set64(&mut env, Gpr(3), 0xAAAA);
        env.backend.set(polyisa_guest_x86::sem::eip_ref(), 0x4000);
        let ex = polyisa_sem::GuestException {
            kind: polyisa_sem::ExceptionKind::PageFault,
            code: 0,
            addr: Some(0xDEAD_0000),
            in_delay_slot: false,
        };
        assert!(matches!(
            sys.handle_exception(&mut env, ex),
            TrapOutcome::Handled
        ));
        let f = get64(&mut env, Gpr(4));
        assert_eq!(f % 16, 8, "x32 も関数入口と同じ stack 整列");
        assert_eq!(env.backend.get(polyisa_guest_x86::sem::eip_ref()), 0x9000);
        assert_eq!(get64(&mut env, Gpr(7)), 11);
        assert_eq!(get64(&mut env, Gpr(6)), f + 296);
        assert_eq!(get64(&mut env, Gpr(2)), f + 8);
        assert_eq!(rd8(&mut env, f), 0x9100, "pretcode");
        assert_eq!(rd8(&mut env, f + 8) & 0xFFFF_FFFF, 6, "uc_flags");
        assert_eq!(rd8(&mut env, f + 288), 0, "uc_sigmask");
        assert_eq!(rd8(&mut env, f + 296) & 0xFFFF_FFFF, 11, "si_signo");
        assert_eq!(rd8(&mut env, f + 296 + 8) & 0xFFFF_FFFF, 1, "si_code");
        assert_eq!(
            rd8(&mut env, f + 296 + 12) & 0xFFFF_FFFF,
            0xDEAD_0000,
            "si_addr"
        );
        assert_eq!(rd8(&mut env, f + 32 + 128), 0x4000, "sigcontext rip");
        assert_eq!(rd8(&mut env, f + 32 + 88), 0xAAAA, "sigcontext rbx");
        let fp = rd8(&mut env, f + 32 + 184);
        assert_eq!(fp % 64, 0);
        assert_eq!(rd8(&mut env, fp + 160), 0x1122_3344);
        assert_eq!(
            env.backend.get(polyisa_guest_x86::sem::xmm_ref(
                polyisa_guest_x86::sem::Xmm(0)
            )),
            0,
            "ハンドラ開始時の user FP state は初期化される"
        );
        set64(&mut env, Gpr(3), 0xBBBB);
        // frame 内 mask を書き換えても SIGKILL/SIGSTOP は block できない。
        env.backend
            .mem
            .write(
                VirtAddr(f + 288),
                &(1u64 << 8 | 1 << 18 | 1 << 9).to_le_bytes(),
            )
            .unwrap();
        set64(&mut env, Gpr(4), f + 8);
        set64(&mut env, Gpr(0), crate::x86_x32::RT_SIGRETURN);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(env.backend.get(polyisa_guest_x86::sem::eip_ref()), 0x4000);
        assert_eq!(get64(&mut env, Gpr(4)), 0x8000);
        assert_eq!(get64(&mut env, Gpr(3)), 0xAAAA);
        assert_eq!(sys.sig_mask, 1 << 9);
        assert_eq!(
            env.backend.get(polyisa_guest_x86::sem::xmm_ref(
                polyisa_guest_x86::sem::Xmm(0)
            )),
            0x1122_3344
        );
    }

    #[test]
    fn set_tid_address_returns_tid() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::SET_TID_ADDRESS);
        set64(&mut env, Gpr(7), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 1);
    }

    #[test]
    fn gettid_returns_tid() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::GETTID);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 1);
    }

    #[test]
    fn getdents64_lists_dir() {
        use crate::x86_64 as abi;
        // 一時ディレクトリを作り、openat 経由で開いて列挙する。
        let dir = std::env::temp_dir().join(format!("polyisa-getdents-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"hi").unwrap();
        let mut sys = Linux::x86_64();
        let mut env = bare();
        let path = dir.to_str().unwrap().to_string() + "\0";
        env.backend
            .mem
            .write(VirtAddr(0x100), path.as_bytes())
            .unwrap();
        // openat(AT_FDCWD, dir, O_RDONLY) -> fd 3。
        set64(&mut env, Gpr(0), abi::OPENAT);
        set64(&mut env, Gpr(7), 0xffff_ffff_ffff_ff9c);
        set64(&mut env, Gpr(6), 0x100);
        set64(&mut env, Gpr(2), 0);
        set64(&mut env, Gpr(10), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 3);
        // 1 件も入らない count は EINVAL。読み位置は進めない。
        set64(&mut env, Gpr(0), abi::GETDENTS64);
        set64(&mut env, Gpr(7), 3);
        set64(&mut env, Gpr(6), 0x400);
        set64(&mut env, Gpr(2), 8);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
        // "." 1 件だけ入る。残りは次の呼び出しに残る。
        set64(&mut env, Gpr(0), abi::GETDENTS64);
        set64(&mut env, Gpr(7), 3);
        set64(&mut env, Gpr(6), 0x400);
        set64(&mut env, Gpr(2), 24);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 24);
        // getdents64(3, 0x400, 0x500) は残りの件数を返す。
        set64(&mut env, Gpr(0), abi::GETDENTS64);
        set64(&mut env, Gpr(7), 3);
        set64(&mut env, Gpr(6), 0x400);
        set64(&mut env, Gpr(2), 0x500);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let n = get64(&mut env, Gpr(0));
        assert!(n > 0 && n < 0x1_0000, "getdents64 returned {n:#x}");
        let mut back = vec![0u8; n as usize];
        env.backend
            .mem
            .read(VirtAddr(0x400), &mut back, data_access())
            .unwrap();
        // "a.txt" が含まれること。
        assert!(back.windows(5).any(|w| w == b"a.txt"));
        // 2回目は 0 (EOF)。
        set64(&mut env, Gpr(0), abi::GETDENTS64);
        set64(&mut env, Gpr(7), 3);
        set64(&mut env, Gpr(6), 0x400);
        set64(&mut env, Gpr(2), 0x500);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn getpid_returns_pid() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::GETPID);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 1);
    }

    #[test]
    fn getppid_returns_zero_for_root() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::GETPPID);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
    }

    #[test]
    fn sysinfo_writes_fixed_layout() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::SYSINFO);
        set64(&mut env, Gpr(7), 0x200);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        let mut buf = [0u8; 112];
        env.backend
            .mem
            .read(
                VirtAddr(0x200),
                &mut buf,
                polyisa_mem::Access {
                    endian: polyisa_mem::Endian::Le,
                    align: polyisa_mem::Align::Unaligned,
                    kind: polyisa_mem::AccessKind::DataRead,
                },
            )
            .unwrap();
        assert_eq!(i64::from_le_bytes(buf[0..8].try_into().unwrap()), 3600);
        assert_eq!(
            u64::from_le_bytes(buf[32..40].try_into().unwrap()),
            1024 * 1024 * 1024
        );
        assert_eq!(
            u64::from_le_bytes(buf[40..48].try_into().unwrap()),
            512 * 1024 * 1024
        );
        assert_eq!(u16::from_le_bytes(buf[80..82].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(buf[104..108].try_into().unwrap()), 1);
    }

    #[test]
    fn clone_pid_matches_getpid() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_x86::CpuState>());
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend.set(polyisa_guest_x86::sem::eip_ref(), 0x1000);
        // 子は未実装命令で止まり、wait4 は子を戻す。
        env.backend.mem.write(VirtAddr(0x1002), &[0x06]).unwrap();
        set64(&mut env, Gpr(0), abi::CLONE);
        set64(&mut env, Gpr(7), 17);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let child = get64(&mut env, Gpr(0));
        assert!(child > 1, "child pid {child}");
        set64(&mut env, Gpr(0), abi::GETPID);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), sys.pid);
        assert_ne!(sys.pid, u64::from(std::process::id()));
        set64(&mut env, Gpr(0), abi::GETTID);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), sys.pid);
        // 子は終了しない。wait4 は子を残して待つ。
        set64(&mut env, Gpr(0), abi::WAIT4);
        set64(&mut env, Gpr(7), child);
        set64(&mut env, Gpr(6), 0);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Blocked));
        assert!(sys.task_pids().contains(&child));
    }

    #[test]
    fn fork_returns_child_pid() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_x86::CpuState>());
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend.set(polyisa_guest_x86::sem::eip_ref(), 0x1000);
        env.backend.mem.write(VirtAddr(0x1002), &[0x06]).unwrap();
        set64(&mut env, Gpr(0), abi::FORK);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let child = get64(&mut env, Gpr(0));
        assert!(child > 1, "child pid {child}");
        assert!(sys.task_pids().contains(&child));
    }

    #[test]
    fn uname_writes_utsname() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::UNAME);
        set64(&mut env, Gpr(7), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        let mut back = [0u8; 65 * 6];
        env.backend
            .mem
            .read(VirtAddr(0x100), &mut back, data_access())
            .unwrap();
        assert_eq!(&back[..6], b"Linux\0");
        assert_eq!(&back[65..75], b"localhost\0");
        assert_eq!(&back[65 * 5..65 * 5 + 12], b"localdomain\0");
    }

    #[test]
    fn getuid_gid_return_zero() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        for nr in [abi::GETUID, abi::GETGID, abi::GETEUID, abi::GETEGID] {
            set64(&mut env, Gpr(0), nr);
            assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
            assert_eq!(get64(&mut env, Gpr(0)), 0);
        }
    }

    #[test]
    fn getcwd_returns_host_cwd() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::GETCWD);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let n = get64(&mut env, Gpr(0)) as usize;
        assert!(n > 1);
        let mut back = vec![0u8; n];
        env.backend
            .mem
            .read(
                VirtAddr(0x100),
                &mut back,
                polyisa_mem::Access {
                    endian: polyisa_mem::Endian::Le,
                    align: polyisa_mem::Align::Unaligned,
                    kind: polyisa_mem::AccessKind::DataRead,
                },
            )
            .unwrap();
        assert_eq!(back[n - 1], 0);
        // ERANGE: サイズ不足.
        set64(&mut env, Gpr(0), abi::GETCWD);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 1);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(ERANGE));
    }

    #[test]
    fn chdir_updates_getcwd_and_relative_openat() {
        use crate::x86_64 as abi;
        let dir = std::env::temp_dir().join(format!("polyisa-chdir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("note"), b"Q").unwrap();
        let path = dir.to_str().unwrap();

        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::GETCWD);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let n = get64(&mut env, Gpr(0)) as usize;
        let mut back = vec![0u8; n];
        env.backend
            .mem
            .read(VirtAddr(0x100), &mut back, data_access())
            .unwrap();
        let host = std::env::current_dir().unwrap();
        assert_eq!(&back[..n - 1], host.to_str().unwrap().as_bytes());

        env.backend
            .mem
            .write(VirtAddr(0x300), path.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x300 + path.len() as u64), &[0])
            .unwrap();
        set64(&mut env, Gpr(0), abi::CHDIR);
        set64(&mut env, Gpr(7), 0x300);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);

        set64(&mut env, Gpr(0), abi::GETCWD);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let n = get64(&mut env, Gpr(0)) as usize;
        let mut back = vec![0u8; n];
        env.backend
            .mem
            .read(VirtAddr(0x100), &mut back, data_access())
            .unwrap();
        assert_eq!(&back[..n - 1], path.as_bytes());

        env.backend.mem.write(VirtAddr(0x400), b"note\0").unwrap();
        set64(&mut env, Gpr(0), abi::OPENAT);
        set64(&mut env, Gpr(7), u64::from(AT_FDCWD_U32));
        set64(&mut env, Gpr(6), 0x400);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let fd = get64(&mut env, Gpr(0));
        set64(&mut env, Gpr(0), abi::READ);
        set64(&mut env, Gpr(7), fd);
        set64(&mut env, Gpr(6), 0x500);
        set64(&mut env, Gpr(2), 1);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 1);
        let mut byte = [0u8; 1];
        env.backend
            .mem
            .read(VirtAddr(0x500), &mut byte, data_access())
            .unwrap();
        assert_eq!(byte, *b"Q");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn guest_root_confines_openat_and_chdir() {
        use crate::x86_64 as abi;
        let root = std::env::temp_dir().join(format!("polyisa-jail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let jail = root.join("jail");
        std::fs::create_dir_all(jail.join("sub")).unwrap();
        std::fs::write(jail.join("f"), b"Q").unwrap();
        std::fs::write(root.join("evil"), b"X").unwrap();

        let mut sys = Linux::x86_64();
        sys.guest_root = jail.to_str().unwrap().to_string();
        sys.cwd = "/".to_string();
        let mut env = bare();
        // openat("f") は jail/f を開く。
        env.backend.mem.write(VirtAddr(0x300), b"f\0").unwrap();
        set64(&mut env, Gpr(0), abi::OPENAT);
        set64(&mut env, Gpr(7), u64::from(AT_FDCWD_U32));
        set64(&mut env, Gpr(6), 0x300);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let fd = get64(&mut env, Gpr(0));
        assert!(fd < 0x1000, "openat jail/f: {fd:#x}");
        set64(&mut env, Gpr(0), abi::READ);
        set64(&mut env, Gpr(7), fd);
        set64(&mut env, Gpr(6), 0x500);
        set64(&mut env, Gpr(2), 1);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 1);
        let mut byte = [0u8; 1];
        env.backend
            .mem
            .read(VirtAddr(0x500), &mut byte, data_access())
            .unwrap();
        assert_eq!(byte, *b"Q");
        // jail 外への脱出は EPERM。兄弟の evil は開かない。
        env.backend
            .mem
            .write(VirtAddr(0x300), b"../evil\0")
            .unwrap();
        set64(&mut env, Gpr(0), abi::OPENAT);
        set64(&mut env, Gpr(7), u64::from(AT_FDCWD_U32));
        set64(&mut env, Gpr(6), 0x300);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EPERM));
        // chdir("sub") は成功、"/" からの ".." は EPERM。
        env.backend.mem.write(VirtAddr(0x300), b"sub\0").unwrap();
        set64(&mut env, Gpr(0), abi::CHDIR);
        set64(&mut env, Gpr(7), 0x300);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        sys.cwd = "/".to_string();
        env.backend.mem.write(VirtAddr(0x300), b"..\0").unwrap();
        set64(&mut env, Gpr(0), abi::CHDIR);
        set64(&mut env, Gpr(7), 0x300);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EPERM));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn utimensat_resolves_relative_to_cwd() {
        use crate::x86_64 as abi;
        let dir = std::env::temp_dir().join(format!("polyisa-utime-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut sys = Linux::x86_64();
        sys.cwd = dir.to_str().unwrap().to_string();
        let mut env = bare();
        // times==NULL、存在しない相対パスは cwd 配下に空作成する。カレントには作らない。
        env.backend
            .mem
            .write(VirtAddr(0x300), b"newfile\0")
            .unwrap();
        set64(&mut env, Gpr(0), abi::UTIMENSAT);
        set64(&mut env, Gpr(7), u64::from(AT_FDCWD_U32));
        set64(&mut env, Gpr(6), 0x300);
        set64(&mut env, Gpr(2), 0);
        set64(&mut env, Gpr(1), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        assert!(dir.join("newfile").is_file());
        // guest_root 配下からの脱出は EPERM。
        sys.guest_root = dir.to_str().unwrap().to_string();
        sys.cwd = "/".to_string();
        env.backend
            .mem
            .write(VirtAddr(0x300), b"../evil\0")
            .unwrap();
        set64(&mut env, Gpr(0), abi::UTIMENSAT);
        set64(&mut env, Gpr(7), u64::from(AT_FDCWD_U32));
        set64(&mut env, Gpr(6), 0x300);
        set64(&mut env, Gpr(2), 0);
        set64(&mut env, Gpr(1), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EPERM));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn relative_fs_ops_resolve_under_cwd_and_jail() {
        use crate::x86_64 as abi;
        let root = std::env::temp_dir().join(format!("polyisa-relfs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let jail = root.join("jail");
        std::fs::create_dir_all(&jail).unwrap();
        std::fs::write(jail.join("f"), b"ab\n").unwrap();

        let mut sys = Linux::x86_64();
        sys.guest_root = jail.to_str().unwrap().to_string();
        sys.cwd = "/".to_string();
        let mut env = bare();
        let cstr = |env: &mut BareEnv, addr: u64, s: &[u8]| {
            env.backend.mem.write(VirtAddr(addr), s).unwrap();
            env.backend
                .mem
                .write(VirtAddr(addr + s.len() as u64), &[0])
                .unwrap();
        };
        // access("f") は jail/f を見る。
        cstr(&mut env, 0x300, b"f");
        set64(&mut env, Gpr(0), abi::ACCESS);
        set64(&mut env, Gpr(7), 0x300);
        set64(&mut env, Gpr(6), 4);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        // link("f", "hard") は jail 内で成功する。
        cstr(&mut env, 0x300, b"f");
        cstr(&mut env, 0x310, b"hard");
        set64(&mut env, Gpr(0), abi::LINK);
        set64(&mut env, Gpr(7), 0x300);
        set64(&mut env, Gpr(6), 0x310);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        assert_eq!(std::fs::read(jail.join("hard")).unwrap(), b"ab\n");
        // rename("hard", "g") は jail 内で成功する。
        cstr(&mut env, 0x300, b"hard");
        cstr(&mut env, 0x310, b"g");
        set64(&mut env, Gpr(0), abi::RENAME);
        set64(&mut env, Gpr(7), 0x300);
        set64(&mut env, Gpr(6), 0x310);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        assert!(jail.join("g").is_file());
        // symlink は作成先だけ解決し、指し先は verbatim。
        cstr(&mut env, 0x300, b"g");
        cstr(&mut env, 0x310, b"ln");
        set64(&mut env, Gpr(0), abi::SYMLINK);
        set64(&mut env, Gpr(7), 0x300);
        set64(&mut env, Gpr(6), 0x310);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        assert_eq!(
            std::fs::read_link(jail.join("ln")).unwrap(),
            std::path::PathBuf::from("g")
        );
        // rmdir("..") の脱出は EPERM。
        cstr(&mut env, 0x300, b"..");
        set64(&mut env, Gpr(0), abi::RMDIR);
        set64(&mut env, Gpr(7), 0x300);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EPERM));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn fchdir_sets_cwd_from_dir_fd() {
        use crate::x86_64 as abi;
        let dir = std::env::temp_dir().join(format!("polyisa-fchdir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.to_str().unwrap();
        let mut sys = Linux::x86_64();
        let mut env = bare();
        let mut cpath = path.as_bytes().to_vec();
        cpath.push(0);
        env.backend.mem.write(VirtAddr(0x200), &cpath).unwrap();
        set64(&mut env, Gpr(0), abi::OPENAT);
        set64(&mut env, Gpr(7), u64::from(AT_FDCWD_U32));
        set64(&mut env, Gpr(6), 0x200);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let fd = get64(&mut env, Gpr(0));
        assert!(fd >= 3);
        set64(&mut env, Gpr(0), abi::FCHDIR);
        set64(&mut env, Gpr(7), fd);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        assert_eq!(sys.cwd, path);
        set64(&mut env, Gpr(0), abi::FCHDIR);
        set64(&mut env, Gpr(7), 99);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EBADF));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fstat_stdout_writes_stat() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        // fstat(1, 0x100) は 0 を返し、struct stat (144B) を書く。
        set64(&mut env, Gpr(0), abi::FSTAT);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        let mut back = [0u8; 144];
        env.backend
            .mem
            .read(VirtAddr(0x100), &mut back, data_access())
            .unwrap();
        // st_mode (オフセット 24) は何かしら非0のはず。
        assert_ne!(u32::from_le_bytes(back[24..28].try_into().unwrap()), 0);
        // 不正 fd は EBADF。
        set64(&mut env, Gpr(0), abi::FSTAT);
        set64(&mut env, Gpr(7), 99);
        set64(&mut env, Gpr(6), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EBADF));
    }

    #[test]
    fn sendfile_file_to_stdout() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        // /proc/self/exe を入力に積む（必ず存在する実行ファイル）。
        let f = std::fs::File::open("/proc/self/exe").unwrap();
        assert_eq!(sys.fds.alloc(polyisa_kernel::FdTarget::File(f)), 3);
        let mut env = bare();
        // sendfile(1, 3, NULL, 16) は 16 を返して stdout に書く。
        set64(&mut env, Gpr(0), abi::SENDFILE);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 3);
        set64(&mut env, Gpr(2), 0);
        set64(&mut env, Gpr(10), 16);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 16);
        // offset 非NULL は EINVAL。
        set64(&mut env, Gpr(0), abi::SENDFILE);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 3);
        set64(&mut env, Gpr(2), 0x100);
        set64(&mut env, Gpr(10), 16);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
        // 不正な入力 fd は EBADF。
        set64(&mut env, Gpr(0), abi::SENDFILE);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 99);
        set64(&mut env, Gpr(2), 0);
        set64(&mut env, Gpr(10), 16);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EBADF));
        // stdin (0) は空読みとして 0 を返す。
        set64(&mut env, Gpr(0), abi::SENDFILE);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 0);
        set64(&mut env, Gpr(2), 0);
        set64(&mut env, Gpr(10), 16);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
    }

    #[test]
    fn lseek_moves_position() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let f = std::fs::File::open("/proc/self/exe").unwrap();
        assert_eq!(sys.fds.alloc(polyisa_kernel::FdTarget::File(f)), 3);
        let mut env = bare();
        // lseek(3, 16, SEEK_SET) は 16 を返す。
        set64(&mut env, Gpr(0), abi::LSEEK);
        set64(&mut env, Gpr(7), 3);
        set64(&mut env, Gpr(6), 16);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 16);
        // 不正な whence は EINVAL、不正 fd は EBADF。
        set64(&mut env, Gpr(0), abi::LSEEK);
        set64(&mut env, Gpr(7), 3);
        set64(&mut env, Gpr(6), 0);
        set64(&mut env, Gpr(2), 99);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
        set64(&mut env, Gpr(0), abi::LSEEK);
        set64(&mut env, Gpr(7), 99);
        set64(&mut env, Gpr(6), 0);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EBADF));
    }

    #[test]
    fn time_returns_host_secs() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        // time(NULL) は 0 より大きい秒を返す。
        set64(&mut env, Gpr(0), abi::TIME);
        set64(&mut env, Gpr(7), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let secs = get64(&mut env, Gpr(0));
        assert!(secs > 0);
        // time(0x100) は同じ秒を [0x100] に書く。
        set64(&mut env, Gpr(0), abi::TIME);
        set64(&mut env, Gpr(7), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), secs);
        let mut back = [0u8; 8];
        env.backend
            .mem
            .read(VirtAddr(0x100), &mut back, data_access())
            .unwrap();
        assert_eq!(i64::from_le_bytes(back) as u64, secs);
    }

    #[test]
    fn getgroups_returns_root() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        // getgroups(0, NULL) は必要数 1 を返す。
        set64(&mut env, Gpr(0), abi::GETGROUPS);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 1);
        // getgroups(1, 0x100) は 1 を返し、GID 0 を書く。
        set64(&mut env, Gpr(0), abi::GETGROUPS);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 1);
        let mut back = [0u8; 4];
        env.backend
            .mem
            .read(VirtAddr(0x100), &mut back, data_access())
            .unwrap();
        assert_eq!(u32::from_le_bytes(back), 0);
    }

    #[test]
    fn setsid_returns_pid() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::SETSID);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 1);
    }

    #[test]
    fn getpriority_returns_niceness_plus_twenty() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::GETPRIORITY);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 20);
        set64(&mut env, Gpr(0), abi::SETPRIORITY);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 0);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        set64(&mut env, Gpr(0), abi::SETPRIORITY);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 1);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EPERM));
        set64(&mut env, Gpr(0), abi::GETPRIORITY);
        set64(&mut env, Gpr(7), 3);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
    }

    #[test]
    fn sched_priority_bounds_for_other_and_fifo() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::SCHED_GET_PRIORITY_MAX);
        set64(&mut env, Gpr(7), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        set64(&mut env, Gpr(0), abi::SCHED_GET_PRIORITY_MAX);
        set64(&mut env, Gpr(7), 1);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 99);
        set64(&mut env, Gpr(0), abi::SCHED_GET_PRIORITY_MIN);
        set64(&mut env, Gpr(7), 1);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 1);
        set64(&mut env, Gpr(0), abi::SCHED_GET_PRIORITY_MAX);
        set64(&mut env, Gpr(7), 9);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
        env.backend
            .mem
            .write(VirtAddr(0x200), &0i32.to_le_bytes())
            .unwrap();
        set64(&mut env, Gpr(0), abi::SCHED_SETSCHEDULER);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 0);
        set64(&mut env, Gpr(2), 0x200);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
    }

    #[test]
    fn personality_returns_previous() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::PERSONALITY);
        set64(&mut env, Gpr(7), 8);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        set64(&mut env, Gpr(0), abi::PERSONALITY);
        set64(&mut env, Gpr(7), 0xffff_ffff);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 8);
    }

    #[test]
    fn sched_setaffinity_accepts_cpu0() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        env.backend
            .mem
            .write(VirtAddr(0x200), &1u64.to_le_bytes())
            .unwrap();
        set64(&mut env, Gpr(0), abi::SCHED_SETAFFINITY);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 8);
        set64(&mut env, Gpr(2), 0x200);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        env.backend
            .mem
            .write(VirtAddr(0x200), &0u64.to_le_bytes())
            .unwrap();
        set64(&mut env, Gpr(0), abi::SCHED_SETAFFINITY);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
    }

    #[test]
    fn ioprio_set_and_get_roundtrip() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        // 未設定なら best-effort の 4。
        set64(&mut env, Gpr(0), abi::IOPRIO_GET);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), (2 << 13) | 4);
        // IDLE class 3。
        set64(&mut env, Gpr(0), abi::IOPRIO_SET);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 0);
        set64(&mut env, Gpr(2), 3 << 13);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        set64(&mut env, Gpr(0), abi::IOPRIO_GET);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 3 << 13);
        // 未知のクラスは EINVAL。
        set64(&mut env, Gpr(0), abi::IOPRIO_SET);
        set64(&mut env, Gpr(2), 7 << 13);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
    }

    #[test]
    fn fsync_and_fdatasync_accept_open_fd() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        // 標準出力は開いている。
        set64(&mut env, Gpr(0), abi::FSYNC);
        set64(&mut env, Gpr(7), 1);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        set64(&mut env, Gpr(0), abi::FDATASYNC);
        set64(&mut env, Gpr(7), 1);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        set64(&mut env, Gpr(0), abi::FSYNC);
        set64(&mut env, Gpr(7), 99);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EBADF));
    }

    #[test]
    fn unshare_accepts_zero_flags() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::UNSHARE);
        set64(&mut env, Gpr(7), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        set64(&mut env, Gpr(0), abi::UNSHARE);
        set64(&mut env, Gpr(7), 0x20000);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EPERM));
    }

    #[test]
    fn setgroups_and_chroot_return_eperm() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::SETGROUPS);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EPERM));
        set64(&mut env, Gpr(0), abi::CHROOT);
        set64(&mut env, Gpr(7), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EPERM));
    }

    #[test]
    fn chown_returns_zero() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::CHOWN);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        set64(&mut env, Gpr(0), abi::LCHOWN);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
    }

    #[test]
    fn sync_returns_zero() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::SYNC);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
    }

    #[test]
    fn nanosleep_zero_returns_zero() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        // nanosleep({0, 0}, NULL) は待たずに 0 を返す。sleep 0 が使う。
        env.backend.mem.write(VirtAddr(0x100), &[0u8; 16]).unwrap();
        set64(&mut env, Gpr(0), abi::NANOSLEEP);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        // tv_nsec が範囲外なら EINVAL。
        let bad = 1_000_000_000i64.to_le_bytes();
        env.backend.mem.write(VirtAddr(0x108), &bad).unwrap();
        set64(&mut env, Gpr(0), abi::NANOSLEEP);
        set64(&mut env, Gpr(7), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
        // req が NULL なら EFAULT。
        set64(&mut env, Gpr(0), abi::NANOSLEEP);
        set64(&mut env, Gpr(7), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EFAULT));
    }

    #[test]
    fn sched_getaffinity_copies_host_mask() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        let want = crate::x86::host_affinity_mask();
        // sched_getaffinity(0, 128, 0x200) はホストのマスクを書き、バイト数を返す。
        set64(&mut env, Gpr(0), abi::SCHED_GETAFFINITY);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 128);
        set64(&mut env, Gpr(2), 0x200);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), want.len() as u64);
        let mut back = vec![0u8; want.len()];
        env.backend
            .mem
            .read(VirtAddr(0x200), &mut back, data_access())
            .unwrap();
        assert_eq!(back, want);
        // 長さ 0 は EINVAL。知らない pid は ESRCH。
        set64(&mut env, Gpr(0), abi::SCHED_GETAFFINITY);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
        set64(&mut env, Gpr(0), abi::SCHED_GETAFFINITY);
        set64(&mut env, Gpr(7), 0x1000);
        set64(&mut env, Gpr(6), 128);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(ESRCH));
    }

    #[test]
    fn clock_nanosleep_returns_zero() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        // clock_nanosleep(0, 0, req, rem) は待たずに 0 を返す。
        set64(&mut env, Gpr(0), abi::CLOCK_NANOSLEEP);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 0);
        set64(&mut env, Gpr(2), 0x100);
        set64(&mut env, Gpr(10), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        // 不正な clock_id は EINVAL。
        set64(&mut env, Gpr(0), abi::CLOCK_NANOSLEEP);
        set64(&mut env, Gpr(7), 99);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
    }

    #[test]
    fn ioctl_returns_enotty() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        // ioctl(1, TIOCGWINSZ, ...) は端末なしとして ENOTTY を返す。
        set64(&mut env, Gpr(0), abi::IOCTL);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 0x5413);
        set64(&mut env, Gpr(2), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(ENOTTY));
        // FS_IOC_GETFLAGS は 8 バイトの 0 を書いて成功する。
        env.backend.mem.write(VirtAddr(0x100), &[0xff; 8]).unwrap();
        set64(&mut env, Gpr(0), abi::IOCTL);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 0xffff_ffff_8008_6601);
        set64(&mut env, Gpr(2), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        let mut flags = [0xffu8; 8];
        env.backend
            .mem
            .read(VirtAddr(0x100), &mut flags, data_access())
            .unwrap();
        assert_eq!(flags, [0; 8]);
    }

    #[test]
    fn fcntl_stdout_returns_zero() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        // fcntl(1, F_GETFL) は 0 を返して継続する。printf の stdout 設定で使う.
        set64(&mut env, Gpr(0), abi::FCNTL);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 3);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        // 不正 fd は EBADF。
        set64(&mut env, Gpr(0), abi::FCNTL);
        set64(&mut env, Gpr(7), 99);
        set64(&mut env, Gpr(6), 3);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EBADF));
    }

    #[test]
    fn stat_root_is_dir() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        env.backend.mem.write(VirtAddr(0x100), b"/\0").unwrap();
        // stat("/", 0x200) は 0 を返し、st_mode に S_IFDIR を書く。
        set64(&mut env, Gpr(0), abi::STAT);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x200);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        let mut back = [0u8; 4];
        env.backend
            .mem
            .read(VirtAddr(0x218), &mut back, data_access())
            .unwrap();
        assert_eq!(u32::from_le_bytes(back) & 0o170000, 0o040000);
        let mut ino = [0u8; 8];
        env.backend
            .mem
            .read(VirtAddr(0x208), &mut ino, data_access())
            .unwrap();
        let root_ino = u64::from_le_bytes(ino);
        assert_ne!(root_ino, 0);
        set64(&mut env, Gpr(0), abi::STAT);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x300);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        env.backend
            .mem
            .read(VirtAddr(0x308), &mut ino, data_access())
            .unwrap();
        assert_eq!(u64::from_le_bytes(ino), root_ino);
        env.backend.mem.write(VirtAddr(0x100), b"/..\0").unwrap();
        set64(&mut env, Gpr(0), abi::STAT);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x300);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        env.backend
            .mem
            .read(VirtAddr(0x308), &mut ino, data_access())
            .unwrap();
        assert_eq!(u64::from_le_bytes(ino), root_ino);
        // 存在しないパスは ENOENT。
        env.backend
            .mem
            .write(VirtAddr(0x100), b"/no/such/file\0")
            .unwrap();
        set64(&mut env, Gpr(0), abi::STAT);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x200);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(ENOENT));
    }

    #[test]
    fn lstat_sees_the_link() {
        use crate::x86_64 as abi;
        let dir = std::env::temp_dir().join(format!("polyisa-lstat-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let target = dir.join("file");
        let link = dir.join("link");
        std::fs::write(&target, b"ab").unwrap();
        polyisa_host::symlink(
            target.to_str().expect("utf-8"),
            link.to_str().expect("utf-8"),
        )
        .unwrap();
        let mut path = link.into_os_string().into_encoded_bytes();
        path.push(0);
        let mut sys = Linux::x86_64();
        let mut env = bare();
        env.backend.mem.write(VirtAddr(0x100), &path).unwrap();
        set64(&mut env, Gpr(0), abi::LSTAT);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x200);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        let mut back = [0u8; 4];
        env.backend
            .mem
            .read(VirtAddr(0x218), &mut back, data_access())
            .unwrap();
        assert_eq!(u32::from_le_bytes(back) & 0o170000, 0o120000);
        set64(&mut env, Gpr(0), abi::STAT);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x200);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        env.backend
            .mem
            .read(VirtAddr(0x218), &mut back, data_access())
            .unwrap();
        assert_eq!(u32::from_le_bytes(back) & 0o170000, 0o100000);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn newfstatat_root_is_dir() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        env.backend.mem.write(VirtAddr(0x100), b"/\0").unwrap();
        // newfstatat(AT_FDCWD, "/", 0x200, 0) は 0 を返し、st_mode に S_IFDIR を書く。
        set64(&mut env, Gpr(0), abi::NEWFSTATAT);
        set64(&mut env, Gpr(7), 0xffff_ffff_ffff_ff9c);
        set64(&mut env, Gpr(6), 0x100);
        set64(&mut env, Gpr(2), 0x200);
        set64(&mut env, Gpr(10), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        let mut back = [0u8; 4];
        env.backend
            .mem
            .read(VirtAddr(0x218), &mut back, data_access())
            .unwrap();
        assert_eq!(u32::from_le_bytes(back) & 0o170000, 0o040000);
        // 存在しないパスは ENOENT。
        env.backend
            .mem
            .write(VirtAddr(0x100), b"/no/such/file\0")
            .unwrap();
        set64(&mut env, Gpr(0), abi::NEWFSTATAT);
        set64(&mut env, Gpr(7), 0xffff_ffff_ffff_ff9c);
        set64(&mut env, Gpr(6), 0x100);
        set64(&mut env, Gpr(2), 0x200);
        set64(&mut env, Gpr(10), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(ENOENT));
    }

    #[test]
    fn mprotect_munmap_return_zero() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::MPROTECT);
        set64(&mut env, Gpr(6), 0x1000);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        set64(&mut env, Gpr(0), abi::MPROTECT);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
        set64(&mut env, Gpr(0), abi::MUNMAP);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
    }

    #[test]
    fn rt_sig_returns_zero() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        // sig=10, act=0, old=0, size=8 は受理される。
        set64(&mut env, Gpr(0), abi::RT_SIGACTION);
        set64(&mut env, Gpr(7), 10);
        set64(&mut env, Gpr(10), 8);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        // how=SIG_BLOCK, set=0, old=0, size=8 は受理される。
        set64(&mut env, Gpr(0), abi::RT_SIGPROCMASK);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 0);
        set64(&mut env, Gpr(2), 0);
        set64(&mut env, Gpr(10), 8);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        set64(&mut env, Gpr(0), abi::RT_SIGTIMEDWAIT);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EAGAIN));
        // set=0, size=8 は受理されて EINTR。
        set64(&mut env, Gpr(0), abi::RT_SIGSUSPEND);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 8);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINTR));
    }

    #[test]
    fn tgkill_zero_returns_zero() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::TGKILL);
        set64(&mut env, Gpr(7), 100);
        set64(&mut env, Gpr(6), 100);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        // sig 範囲外は EINVAL。
        set64(&mut env, Gpr(0), abi::TGKILL);
        set64(&mut env, Gpr(2), 100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
    }

    #[test]
    fn rseq_records_addr() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::RSEQ);
        set64(&mut env, Gpr(7), 0x5000);
        set64(&mut env, Gpr(6), 32);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        assert_eq!(sys.rseq_addr, 0x5000);
        // 長さが 32 でなければ EINVAL。
        set64(&mut env, Gpr(0), abi::RSEQ);
        set64(&mut env, Gpr(7), 0x5000);
        set64(&mut env, Gpr(6), 16);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
    }

    #[test]
    fn getrandom_fills_zeros() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::GETRANDOM);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 8);
        set64(&mut env, Gpr(2), 1);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 8);
        let mut back = [0xFFu8; 8];
        env.backend
            .mem
            .read(VirtAddr(0x100), &mut back, data_access())
            .unwrap();
        assert_eq!(back, [0u8; 8]);
        // 不明な flags は EINVAL。
        set64(&mut env, Gpr(0), abi::GETRANDOM);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 8);
        set64(&mut env, Gpr(2), 8);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
    }

    #[test]
    fn mkdir_rmdir_roundtrip() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        let path = format!("/tmp/polyisa_mkdir_{}", std::process::id());
        let _ = std::fs::remove_dir(&path);
        env.backend
            .mem
            .write(VirtAddr(0x100), path.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x100 + path.len() as u64), &[0])
            .unwrap();
        // mkdir(path) は 0 を返す.
        set64(&mut env, Gpr(0), abi::MKDIR);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0o777);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        assert!(std::fs::metadata(&path).is_ok());
        // 二重作成は EEXIST (17).
        set64(&mut env, Gpr(0), abi::MKDIR);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0o777);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(17));
        // rmdir(path) は 0 を返す.
        set64(&mut env, Gpr(0), abi::RMDIR);
        set64(&mut env, Gpr(7), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
    }

    #[test]
    fn mknod_fifo_and_rejects_device() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        let path = format!("/tmp/polyisa_fifo_{}", std::process::id());
        let _ = std::fs::remove_file(&path);
        env.backend
            .mem
            .write(VirtAddr(0x100), path.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x100 + path.len() as u64), &[0])
            .unwrap();
        set64(&mut env, Gpr(0), abi::MKNOD);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0o010000 | 0o666);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        let kind = std::process::Command::new("stat")
            .args(["-c", "%F", &path])
            .output()
            .unwrap();
        assert_eq!(String::from_utf8(kind.stdout).unwrap().trim(), "fifo");
        set64(&mut env, Gpr(0), abi::MKNOD);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0o020000 | 0o666);
        set64(&mut env, Gpr(2), 0x103);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EPERM));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn umask_roundtrip() {
        // umask(mask) は旧マスクを返して更新する。mkdir -p の保存・復元で使う.
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        sys.umask = 0o22;
        // umask(0o77) -> 0o22。
        set64(&mut env, Gpr(0), abi::UMASK);
        set64(&mut env, Gpr(7), 0o77);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0o22);
        // umask(0o22) -> 0o77。
        set64(&mut env, Gpr(0), abi::UMASK);
        set64(&mut env, Gpr(7), 0o22);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0o77);
    }

    #[test]
    fn ftruncate_roundtrip() {
        // ftruncate(fd, len) は長さを変えて 0 を返す。truncate -s で使う.
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        let path = format!("/tmp/polyisa_ftruncate_{}", std::process::id());
        std::fs::write(&path, b"abcdef").unwrap();
        let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        assert_eq!(sys.fds.alloc(polyisa_kernel::FdTarget::File(f)), 3);
        // ftruncate(3, 3) -> 0、大きさ 3.
        set64(&mut env, Gpr(0), abi::FTRUNCATE);
        set64(&mut env, Gpr(7), 3);
        set64(&mut env, Gpr(6), 3);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 3);
        // 不正 fd は EBADF。
        set64(&mut env, Gpr(0), abi::FTRUNCATE);
        set64(&mut env, Gpr(7), 99);
        set64(&mut env, Gpr(6), 3);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EBADF));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn fallocate_extends_file() {
        // fallocate(fd, 0, 0, 8) は長さ 8 にする。mode が 0 以外は EOPNOTSUPP。
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        let path = format!("/tmp/polyisa_fallocate_{}", std::process::id());
        let _ = std::fs::remove_file(&path);
        let f = std::fs::File::create(&path).unwrap();
        assert_eq!(sys.fds.alloc(polyisa_kernel::FdTarget::File(f)), 3);
        set64(&mut env, Gpr(0), abi::FALLOCATE);
        set64(&mut env, Gpr(7), 3);
        set64(&mut env, Gpr(6), 0);
        set64(&mut env, Gpr(2), 0);
        set64(&mut env, Gpr(10), 8);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 8);
        set64(&mut env, Gpr(0), abi::FALLOCATE);
        set64(&mut env, Gpr(7), 3);
        set64(&mut env, Gpr(6), 1);
        set64(&mut env, Gpr(2), 0);
        set64(&mut env, Gpr(10), 8);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(95));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn neg_errno_sign_extends() {
        // 負 errno は符号拡張する。x86-64 の誤り (+errno) を回帰で防ぐ.
        assert_eq!(neg_errno(22), 0xFFFF_FFEAu32);
        assert_eq!(neg_errno64(22), 0xFFFF_FFFF_FFFF_FFEAu64);
        assert_eq!(neg_errno64(0), 0);
    }

    #[test]
    fn rename_roundtrip() {
        // rename(old, new) は移動して 0 を返す。mv で使う.
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        let old = format!("/tmp/polyisa_rename_old_{}", std::process::id());
        let new = format!("/tmp/polyisa_rename_new_{}", std::process::id());
        let _ = std::fs::remove_file(&new);
        std::fs::write(&old, b"data").unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x100), old.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x100 + old.len() as u64), &[0])
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x200), new.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x200 + new.len() as u64), &[0])
            .unwrap();
        // rename(old, new) -> 0、old は消えて new ができる.
        set64(&mut env, Gpr(0), abi::RENAME);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x200);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        assert!(std::fs::metadata(&old).is_err());
        assert_eq!(std::fs::read(&new).unwrap(), b"data");
        // 存在しない old は ENOENT。
        let missing = format!("/tmp/polyisa_rename_missing_{}", std::process::id());
        env.backend
            .mem
            .write(VirtAddr(0x100), missing.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x100 + missing.len() as u64), &[0])
            .unwrap();
        set64(&mut env, Gpr(0), abi::RENAME);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x200);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(ENOENT));
        let _ = std::fs::remove_file(&new);
    }

    #[test]
    fn symlink_roundtrip() {
        // symlink(old, new) はリンクを作って 0 を返す。`ln -s` で使う.
        // 実体は host helper のためここでは番号経路と結果の写像を確かめる.
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        let old = String::from("/tmp/symlink_target_exists");
        let new = format!("/tmp/polyisa_symlink_{}", std::process::id());
        let _ = std::fs::remove_file(&new);
        env.backend
            .mem
            .write(VirtAddr(0x100), old.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x100 + old.len() as u64), &[0])
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x200), new.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x200 + new.len() as u64), &[0])
            .unwrap();
        // symlink(old, new) -> 0、new は old へのリンク.
        set64(&mut env, Gpr(0), abi::SYMLINK);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x200);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        assert_eq!(
            std::fs::read_link(&new).unwrap(),
            std::path::PathBuf::from(old.as_str())
        );
        // 同じ new の再作成は EEXIST(17)。
        set64(&mut env, Gpr(0), abi::SYMLINK);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x200);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(17));
        // 存在しない親の下は ENOENT。
        let bad = format!("/tmp/polyisa_no_dir_{}/link", std::process::id());
        env.backend
            .mem
            .write(VirtAddr(0x200), bad.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x200 + bad.len() as u64), &[0])
            .unwrap();
        set64(&mut env, Gpr(0), abi::SYMLINK);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x200);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(ENOENT));
        let _ = std::fs::remove_file(&new);
    }

    #[test]
    fn link_roundtrip() {
        // link(old, new) はハードリンクを作って 0 を返す。busybox の `link` で使う。
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        let old = format!("/tmp/polyisa_link_old_{}", std::process::id());
        let new = format!("/tmp/polyisa_link_new_{}", std::process::id());
        let _ = std::fs::remove_file(&old);
        let _ = std::fs::remove_file(&new);
        std::fs::write(&old, b"ab").unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x100), old.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x100 + old.len() as u64), &[0])
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x200), new.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x200 + new.len() as u64), &[0])
            .unwrap();
        set64(&mut env, Gpr(0), abi::LINK);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x200);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        assert_eq!(std::fs::read(&new).unwrap(), b"ab");
        set64(&mut env, Gpr(0), abi::LINK);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x200);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(17));
        let _ = std::fs::remove_file(&old);
        assert_eq!(std::fs::read(&new).unwrap(), b"ab");
        let missing = format!("/tmp/polyisa_link_missing_{}", std::process::id());
        env.backend
            .mem
            .write(VirtAddr(0x100), missing.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x100 + missing.len() as u64), &[0])
            .unwrap();
        set64(&mut env, Gpr(0), abi::LINK);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x200);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(ENOENT));
        let _ = std::fs::remove_file(&new);
    }

    #[test]
    fn unlink_access_utimensat_roundtrip() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        let path = format!("/tmp/polyisa_utimens_{}", std::process::id());
        let _ = std::fs::remove_file(&path);
        env.backend
            .mem
            .write(VirtAddr(0x100), path.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x100 + path.len() as u64), &[0])
            .unwrap();
        // utimensat(AT_FDCWD, path) は空作成して 0 を返す.
        set64(&mut env, Gpr(0), abi::UTIMENSAT);
        set64(&mut env, Gpr(7), 0xffff_ffff_ffff_ff9c);
        set64(&mut env, Gpr(6), 0x100);
        set64(&mut env, Gpr(2), 0);
        set64(&mut env, Gpr(10), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        assert!(std::fs::metadata(&path).is_ok());
        // access(path) は 0 を返す.
        set64(&mut env, Gpr(0), abi::ACCESS);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        // unlink(path) は 0 を返す.
        set64(&mut env, Gpr(0), abi::UNLINK);
        set64(&mut env, Gpr(7), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        // 存在しない access は ENOENT.
        set64(&mut env, Gpr(0), abi::ACCESS);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(ENOENT));
    }

    #[test]
    fn dup2_std_alias_returns_newfd() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        // dup2(1, 2) は 2 を返す (--list の画面幅取得の前段).
        set64(&mut env, Gpr(0), abi::DUP2);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 2);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 2);
        // chmod/fchmodat は無視して 0 を返す.
        set64(&mut env, Gpr(0), abi::CHMOD);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0o755);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        // fchown は無視して 0 を返す。dos2unix の所有者の戻し.
        set64(&mut env, Gpr(0), abi::FCHOWN);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), u64::MAX);
        set64(&mut env, Gpr(2), u64::MAX);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
    }

    #[test]
    fn dup3_std_alias_returns_newfd() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        // dup3(1, 2, 0) は 2 を返す (hexdump の前段).
        set64(&mut env, Gpr(0), abi::DUP3);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 2);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 2);
        // oldfd==newfd は EINVAL.
        set64(&mut env, Gpr(0), abi::DUP3);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 1);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
        // 不正 flags は EINVAL.
        set64(&mut env, Gpr(0), abi::DUP3);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 2);
        set64(&mut env, Gpr(2), 0xFFFF);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
    }

    #[test]
    fn dup2_opened_fd_onto_stdin_serves_file() {
        // freopen 相当の付け替え回帰: open -> fd 3、close(0)、dup2(3, 0) -> 0、read(0) で読める.
        // hexdump の Bad file descriptor 対応。旧実装は opened fd の dup2 で EBADF.
        use crate::x86_64 as abi;
        let path = std::env::temp_dir().join(format!("polyisa-unit-dup2-{}", std::process::id()));
        std::fs::write(&path, b"abcdef").unwrap();
        let path_s = path.to_string_lossy().into_owned();
        let mut sys = Linux::x86_64();
        let mut env = bare();
        env.backend
            .mem
            .write(VirtAddr(0x100), path_s.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x100 + path_s.len() as u64), &[0])
            .unwrap();
        // openat(AT_FDCWD, path, O_RDONLY) -> fd 3.
        set64(&mut env, Gpr(0), abi::OPENAT);
        set64(&mut env, Gpr(7), AT_FDCWD_U32 as u64);
        set64(&mut env, Gpr(6), 0x100);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 3);
        // close(0) -> 0。
        set64(&mut env, Gpr(0), abi::CLOSE);
        set64(&mut env, Gpr(7), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        // dup2(3, 0) -> 0。
        set64(&mut env, Gpr(0), abi::DUP2);
        set64(&mut env, Gpr(7), 3);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        // dup(3) -> 最下位空き 4。
        set64(&mut env, Gpr(0), abi::DUP);
        set64(&mut env, Gpr(7), 3);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 4);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn write_to_remapped_stdout_serves_file() {
        // split の出力 pattern: open(WRONLY|CREAT) -> fd、dup2(fd, 1)、write(1) で書ける.
        // 旧実装は付け替え後もホスト stdout に書いたため出力が空になった.
        use crate::x86_64 as abi;
        let dir = std::env::temp_dir().join(format!("polyisa-unit-wstdout-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let path_s = dir.join("o.txt").to_string_lossy().into_owned();
        let mut sys = Linux::x86_64();
        let mut env = bare();
        env.backend
            .mem
            .write(VirtAddr(0x100), path_s.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x100 + path_s.len() as u64), &[0])
            .unwrap();
        env.backend.mem.write(VirtAddr(0x200), b"abcdef").unwrap();
        // openat(AT_FDCWD, path, O_WRONLY|O_CREAT|O_TRUNC) -> fd 3.
        set64(&mut env, Gpr(0), abi::OPENAT);
        set64(&mut env, Gpr(7), AT_FDCWD_U32 as u64);
        set64(&mut env, Gpr(6), 0x100);
        set64(&mut env, Gpr(2), 0o1101);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 3);
        // dup2(3, 1) -> 1。
        set64(&mut env, Gpr(0), abi::DUP2);
        set64(&mut env, Gpr(7), 3);
        set64(&mut env, Gpr(6), 1);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 1);
        // write(1, 0x200, 6) -> 6。ホスト stdout ではなくファイルに書く。
        set64(&mut env, Gpr(0), abi::WRITE);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 0x200);
        set64(&mut env, Gpr(2), 6);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 6);
        assert_eq!(std::fs::read(dir.join("o.txt")).unwrap(), b"abcdef");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prlimit64_writes_infinity() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::PRLIMIT64);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 3);
        set64(&mut env, Gpr(2), 0);
        set64(&mut env, Gpr(10), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        let mut back = [0u8; 16];
        env.backend
            .mem
            .read(VirtAddr(0x100), &mut back, data_access())
            .unwrap();
        assert_eq!(
            u64::from_le_bytes(back[..8].try_into().unwrap()),
            0xFFFF_FFFF_FFFF_FFFF
        );
        assert_eq!(
            u64::from_le_bytes(back[8..].try_into().unwrap()),
            0xFFFF_FFFF_FFFF_FFFF
        );
        // resource 範囲外は EINVAL。
        set64(&mut env, Gpr(0), abi::PRLIMIT64);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 16);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
    }

    #[test]
    fn clock_gettime_realtime_is_fixed() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::CLOCK_GETTIME);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        let mut back = [0xFFu8; 16];
        env.backend
            .mem
            .read(VirtAddr(0x100), &mut back, data_access())
            .unwrap();
        assert_eq!(
            i64::from_le_bytes(back[0..8].try_into().unwrap()),
            946_688_400
        );
        assert_eq!(i64::from_le_bytes(back[8..16].try_into().unwrap()), 0);
    }

    #[test]
    fn reboot_returns_eperm() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::REBOOT);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EPERM));
    }

    #[test]
    fn syslog_read_all_writes_fixed_line() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::SYSLOG);
        set64(&mut env, Gpr(7), 3);
        set64(&mut env, Gpr(6), 0x100);
        set64(&mut env, Gpr(2), 64);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 23);
        let mut back = [0u8; 23];
        env.backend
            .mem
            .read(VirtAddr(0x100), &mut back, data_access())
            .unwrap();
        assert_eq!(&back, b"[    0.000000] polyisa\n");
    }

    #[test]
    fn readlinkat_proc_self_exe() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        env.backend
            .mem
            .write(VirtAddr(0x100), b"/proc/self/exe\0")
            .unwrap();
        set64(&mut env, Gpr(0), abi::READLINKAT);
        set64(&mut env, Gpr(7), 0xffff_ffff_ffff_ff9c);
        set64(&mut env, Gpr(6), 0x100);
        set64(&mut env, Gpr(2), 0x200);
        set64(&mut env, Gpr(10), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let n = get64(&mut env, Gpr(0));
        assert!(n > 0 && n < 0x100);
        let mut back = vec![0u8; n as usize];
        env.backend
            .mem
            .read(VirtAddr(0x200), &mut back, data_access())
            .unwrap();
        assert!(back.starts_with(b"/"));
        // bufsiz=0 は EINVAL。
        set64(&mut env, Gpr(0), abi::READLINKAT);
        set64(&mut env, Gpr(7), 0xffff_ffff_ffff_ff9c);
        set64(&mut env, Gpr(6), 0x100);
        set64(&mut env, Gpr(2), 0x200);
        set64(&mut env, Gpr(10), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
    }

    #[test]
    fn read_stdin_buffer_returns_bytes() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        sys.stdin_buf = b"ab\n".to_vec();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::READ);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 0x200);
        set64(&mut env, Gpr(2), 8);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 3);
        let mut back = [0u8; 3];
        env.backend
            .mem
            .read(VirtAddr(0x200), &mut back, data_access())
            .unwrap();
        assert_eq!(&back, b"ab\n");
        set64(&mut env, Gpr(0), abi::READ);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 0x200);
        set64(&mut env, Gpr(2), 8);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
    }

    #[test]
    fn readlink_proc_self_exe() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        sys.exe_path = "/tmp/opencode/work/busybox-1.37.0/busybox".to_string();
        let mut env = bare();
        env.backend
            .mem
            .write(VirtAddr(0x100), b"/proc/self/exe\0")
            .unwrap();
        set64(&mut env, Gpr(0), abi::READLINK);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x200);
        set64(&mut env, Gpr(2), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let n = get64(&mut env, Gpr(0));
        assert_eq!(n, 0x29);
        let mut back = vec![0u8; n as usize];
        env.backend
            .mem
            .read(VirtAddr(0x200), &mut back, data_access())
            .unwrap();
        assert_eq!(&back, b"/tmp/opencode/work/busybox-1.37.0/busybox");
    }

    #[test]
    fn readlink_proc_self_fd_returns_opened_path() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        let path = std::env::temp_dir().join(format!("polyisa-fdlink-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let file = std::fs::File::create(&path).unwrap();
        let fd = sys.alloc_fd(file);
        let host = path.to_str().unwrap().to_string();
        sys.remember_path(fd, host.clone());
        let proc = format!("/proc/self/fd/{fd}\0");
        env.backend
            .mem
            .write(VirtAddr(0x100), proc.as_bytes())
            .unwrap();
        set64(&mut env, Gpr(0), abi::READLINK);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x200);
        set64(&mut env, Gpr(2), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let n = get64(&mut env, Gpr(0));
        assert_eq!(n, host.len() as u64);
        let mut back = vec![0u8; n as usize];
        env.backend
            .mem
            .read(VirtAddr(0x200), &mut back, data_access())
            .unwrap();
        assert_eq!(back, host.as_bytes());
        drop(sys);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn set_robust_list_records_head() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::SET_ROBUST_LIST);
        set64(&mut env, Gpr(7), 0x5000);
        set64(&mut env, Gpr(6), 24);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        assert_eq!(sys.robust_head, 0x5000);
        // 長さが 24 でなければ EINVAL。
        set64(&mut env, Gpr(0), abi::SET_ROBUST_LIST);
        set64(&mut env, Gpr(7), 0x5000);
        set64(&mut env, Gpr(6), 16);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
    }

    #[test]
    fn pipe2_roundtrip_in_one_process() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::PIPE2);
        set64(&mut env, Gpr(7), 0x200);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        let mut fds = [0u8; 8];
        env.backend
            .mem
            .read(VirtAddr(0x200), &mut fds, data_access())
            .unwrap();
        let read_fd = u32::from_le_bytes(fds[0..4].try_into().unwrap());
        let write_fd = u32::from_le_bytes(fds[4..8].try_into().unwrap());
        env.backend.mem.write(VirtAddr(0x300), b"Z").unwrap();
        set64(&mut env, Gpr(0), abi::WRITE);
        set64(&mut env, Gpr(7), write_fd.into());
        set64(&mut env, Gpr(6), 0x300);
        set64(&mut env, Gpr(2), 1);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 1);
        set64(&mut env, Gpr(0), abi::READ);
        set64(&mut env, Gpr(7), read_fd.into());
        set64(&mut env, Gpr(6), 0x400);
        set64(&mut env, Gpr(2), 1);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 1);
        let mut byte = [0u8; 1];
        env.backend
            .mem
            .read(VirtAddr(0x400), &mut byte, data_access())
            .unwrap();
        assert_eq!(byte, *b"Z");
    }

    #[test]
    fn pipe_returns_two_fds() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::PIPE);
        set64(&mut env, Gpr(7), 0x200);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        let mut fds = [0u8; 8];
        env.backend
            .mem
            .read(VirtAddr(0x200), &mut fds, data_access())
            .unwrap();
        let read_fd = u32::from_le_bytes(fds[0..4].try_into().unwrap());
        let write_fd = u32::from_le_bytes(fds[4..8].try_into().unwrap());
        assert_ne!(read_fd, write_fd);
        assert!(read_fd >= 3 && write_fd >= 3);
        // ファイルが先に開いているとき、両端は別の番号になる。
        let mut sys = Linux::x86_64();
        let mut env = bare();
        assert_eq!(
            sys.fds.alloc(polyisa_kernel::FdTarget::File(
                std::fs::File::open("/dev/null").unwrap()
            )),
            3
        );
        set64(&mut env, Gpr(0), abi::PIPE);
        set64(&mut env, Gpr(7), 0x200);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let mut again = [0u8; 8];
        env.backend
            .mem
            .read(VirtAddr(0x200), &mut again, data_access())
            .unwrap();
        let read2 = u32::from_le_bytes(again[0..4].try_into().unwrap());
        let write2 = u32::from_le_bytes(again[4..8].try_into().unwrap());
        assert_eq!((read2, write2), (4, 5));
    }

    #[test]
    fn dup2_pipe_onto_stdin_reads() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::PIPE);
        set64(&mut env, Gpr(7), 0x200);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let mut fds = [0u8; 8];
        env.backend
            .mem
            .read(VirtAddr(0x200), &mut fds, data_access())
            .unwrap();
        let read_fd = u32::from_le_bytes(fds[0..4].try_into().unwrap());
        let write_fd = u32::from_le_bytes(fds[4..8].try_into().unwrap());
        set64(&mut env, Gpr(0), abi::DUP2);
        set64(&mut env, Gpr(7), read_fd.into());
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        env.backend.mem.write(VirtAddr(0x300), b"Q").unwrap();
        set64(&mut env, Gpr(0), abi::WRITE);
        set64(&mut env, Gpr(7), write_fd.into());
        set64(&mut env, Gpr(6), 0x300);
        set64(&mut env, Gpr(2), 1);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        set64(&mut env, Gpr(0), abi::READ);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 0x400);
        set64(&mut env, Gpr(2), 1);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 1);
        let mut byte = [0u8; 1];
        env.backend
            .mem
            .read(VirtAddr(0x400), &mut byte, data_access())
            .unwrap();
        assert_eq!(byte, *b"Q");
    }

    #[test]
    fn kill_drops_the_parked_child() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::CLONE);
        set64(&mut env, Gpr(7), 17);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let child = get64(&mut env, Gpr(0));
        assert!(sys.task_pids().contains(&child));
        set64(&mut env, Gpr(0), abi::KILL);
        set64(&mut env, Gpr(7), child);
        set64(&mut env, Gpr(6), 9);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        assert!(!sys.task_pids().contains(&child));
        set64(&mut env, Gpr(0), abi::WAIT4);
        set64(&mut env, Gpr(7), child);
        set64(&mut env, Gpr(6), 0x100);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), child);
        let mut status = [0u8; 4];
        env.backend
            .mem
            .read(VirtAddr(0x100), &mut status, data_access())
            .unwrap();
        assert_eq!(u32::from_le_bytes(status), 9);
    }

    #[test]
    fn kill_queues_a_handler_signal_on_the_parked_child() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        sys.sigacts.resize(64, crate::x86::SigAct::default());
        sys.sigacts[9].handler = 0x1000; // SIGUSR1
        set64(&mut env, Gpr(4), 0x1800);
        env.backend.set(polyisa_guest_x86::sem::fcw_ref(), 0x037f);
        env.backend
            .set(polyisa_guest_x86::sem::ftw_ref(), 0xffffu16);
        env.backend.set(polyisa_guest_x86::sem::mxcsr_ref(), 0x1f80);
        env.backend.set(polyisa_guest_x86::sem::xcr0_ref(), 7);
        env.backend.set(polyisa_guest_x86::sem::xcomp_supp_ref(), 7);
        env.backend.set(polyisa_guest_x86::sem::xcomp_perm_ref(), 7);
        env.backend
            .set(polyisa_guest_x86::sem::cpuid_ref(1, 2), 1u32 << 26);
        set64(&mut env, Gpr(0), abi::CLONE);
        set64(&mut env, Gpr(7), 17);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let child = get64(&mut env, Gpr(0));
        set64(&mut env, Gpr(0), abi::KILL);
        set64(&mut env, Gpr(7), child);
        set64(&mut env, Gpr(6), 10);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        let queue = sys.queue.0.borrow();
        let task = queue
            .parked
            .iter()
            .find(|task| task.linux.pid == child)
            .expect("parked child");
        assert_ne!(task.linux.sig_pending & (1 << 9), 0);
        drop(queue);
        assert!(sys.swap_in(&mut env, child));
        sys.after_step(&mut env);
        assert_eq!(env.backend.get(polyisa_guest_x86::sem::eip_ref()), 0x1000);
        assert_eq!(sys.sig_pending & (1 << 9), 0);
    }

    #[test]
    fn wait4_zero_reaps_a_child_in_the_same_group() {
        use crate::x86_64 as abi;
        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::CLONE);
        set64(&mut env, Gpr(7), 17);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let child = get64(&mut env, Gpr(0));
        set64(&mut env, Gpr(0), abi::WAIT4);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 0);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(ECHILD));
        set64(&mut env, Gpr(0), abi::SETPGID);
        set64(&mut env, Gpr(7), child);
        set64(&mut env, Gpr(6), sys.pid);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        sys.procs
            .borrow_mut()
            .exit(polyisa_kernel::ProcessId(child), 4);
        set64(&mut env, Gpr(0), abi::WAIT4);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 0x100);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), child);
        let mut status = [0u8; 4];
        env.backend
            .mem
            .read(VirtAddr(0x100), &mut status, data_access())
            .unwrap();
        assert_eq!(u32::from_le_bytes(status), 4 << 8);
    }

    #[test]
    fn syscall_tables_are_unique_and_named_in_os_linux() {
        assert_syscall_table(X86_64_SYSCALLS, crate::GuestAbi::X86_64Linux);
        assert_syscall_table(X86_32_SYSCALLS, crate::GuestAbi::X86_32Linux);
        // x32 は x86-64 と同じハンドラ表を使う（番号表だけが別）。
        assert_syscall_table(X86_64_SYSCALLS, crate::GuestAbi::X32Linux);
    }
    #[test]
    fn unimplemented_syscall_returns_enosys_and_continues() {
        // 未知番号は一度だけ報告し、ENOSYS を返して実行を続ける（user-mode.md）。
        let mut sys = Linux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), 9999);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(crate::ENOSYS));
    }

    #[test]
    fn unimplemented_syscall_returns_enosys_x86_32() {
        let mut sys = Linux::x86_32();
        let mut env = bare();
        set64(&mut env, Gpr(0), 9999);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), u64::from(neg_errno(crate::ENOSYS)));
    }

    #[test]
    fn x32_table_names() {
        // x32 専用番号（SYSCALL_BIT|512〜）は x32 の表を引く。
        assert_eq!(
            crate::syscall_name(crate::GuestAbi::X32Linux, crate::x86_x32::RT_SIGACTION),
            Some("rt_sigaction")
        );
        assert_eq!(
            crate::syscall_name(crate::GuestAbi::X32Linux, crate::x86_x32::WRITEV),
            Some("writev")
        );
        assert_eq!(
            crate::syscall_name(crate::GuestAbi::X32Linux, crate::x86_x32::EXECVE),
            Some("execve")
        );
        // ビットのない番号は x86-64 と同じ表を使う。
        assert_eq!(
            crate::syscall_name(crate::GuestAbi::X32Linux, crate::x86_64::EXIT_GROUP),
            Some("exit_group")
        );
        assert_eq!(
            crate::syscall_name(crate::GuestAbi::X32Linux, crate::x86_64::MMAP),
            Some("mmap")
        );
        // x32 は全呼び出しでビットを立てる。ベース 0-511 は
        // x86-64 と同じ表を引く（0x40000001 = write）。
        assert_eq!(
            crate::syscall_name(crate::GuestAbi::X32Linux, crate::x86_x32::SYSCALL_BIT | 1),
            Some("write")
        );
        assert_eq!(
            crate::syscall_name(
                crate::GuestAbi::X32Linux,
                crate::x86_x32::SYSCALL_BIT | crate::x86_64::EXIT_GROUP
            ),
            Some("exit_group")
        );
        // ビットありで 512-547 の範囲外は未定義。
        assert!(
            crate::syscall_name(crate::GuestAbi::X32Linux, crate::x86_x32::SYSCALL_BIT | 548)
                .is_none()
        );
    }

    #[test]
    fn x32_common_nr_with_bit_dispatches() {
        // 0x40000001 = x32 の write（ベース 1 → x86-64 表）。
        let mut sys = Linux::x86_x32();
        let mut env = bare();
        env.backend.mem.write(VirtAddr(0x100), b"hi").unwrap();
        set64(&mut env, Gpr(0), crate::x86_x32::SYSCALL_BIT | 1);
        set64(&mut env, Gpr(7), 2);
        set64(&mut env, Gpr(6), 0x100);
        set64(&mut env, Gpr(2), 2);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 2);
    }

    #[test]
    fn x32_writev_uses_8byte_iovec() {
        let mut sys = Linux::x86_x32();
        let mut env = bare();
        env.backend.mem.write(VirtAddr(0x100), b"hi").unwrap();
        env.backend.mem.write(VirtAddr(0x110), b"!").unwrap();
        // x32 の iovec は {u32 base, u32 len} の 8 バイト。
        let mut iov = [0u8; 16];
        iov[..4].copy_from_slice(&0x100u32.to_le_bytes());
        iov[4..8].copy_from_slice(&2u32.to_le_bytes());
        iov[8..12].copy_from_slice(&0x110u32.to_le_bytes());
        iov[12..16].copy_from_slice(&1u32.to_le_bytes());
        env.backend.mem.write(VirtAddr(0x200), &iov).unwrap();
        // writev(2, 0x200, 2) を x32 番号で呼ぶ。
        set64(&mut env, Gpr(0), crate::x86_x32::WRITEV);
        set64(&mut env, Gpr(7), 2);
        set64(&mut env, Gpr(6), 0x200);
        set64(&mut env, Gpr(2), 2);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 3);
    }

    #[test]
    fn x32_rt_sigaction_uses_20byte_act() {
        let mut sys = Linux::x86_x32();
        let mut env = bare();
        // x32 の kernel_sigaction は i386 と同じ 20 バイト
        // {handler u32, flags u32, restorer u32, mask u64}。
        let mut act = [0u8; 20];
        act[0..4].copy_from_slice(&0x1000u32.to_le_bytes());
        act[4..8].copy_from_slice(&(crate::x86::SA_RESTORER as u32).to_le_bytes());
        act[8..12].copy_from_slice(&0x2000u32.to_le_bytes());
        env.backend.mem.write(VirtAddr(0x300), &act).unwrap();
        // rt_sigaction(SIGUSR1=10, 0x300, 0, 8) で設定する。
        set64(&mut env, Gpr(0), crate::x86_x32::RT_SIGACTION);
        set64(&mut env, Gpr(7), 10);
        set64(&mut env, Gpr(6), 0x300);
        set64(&mut env, Gpr(2), 0);
        set64(&mut env, Gpr(10), 8);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        // oldact=0x400 に 20 バイトで書き戻される。
        set64(&mut env, Gpr(0), crate::x86_x32::RT_SIGACTION);
        set64(&mut env, Gpr(7), 10);
        set64(&mut env, Gpr(6), 0);
        set64(&mut env, Gpr(2), 0x400);
        set64(&mut env, Gpr(10), 8);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        let mut out = [0u8; 20];
        env.backend
            .mem
            .read(VirtAddr(0x400), &mut out, crate::x86::data_access())
            .unwrap();
        assert_eq!(u32::from_le_bytes(out[0..4].try_into().unwrap()), 0x1000);
        assert_eq!(u32::from_le_bytes(out[8..12].try_into().unwrap()), 0x2000);
    }
}
