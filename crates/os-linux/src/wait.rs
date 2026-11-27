// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 待ち合わせ系 syscall の正準実装と fd 待ちの消化機構
//! （段階26・NS6）。
//!
//! 対象は select/_newselect/pselect6・poll/ppoll・
//! epoll_create/epoll_create1/epoll_ctl/epoll_wait/epoll_pwait/
//! epoll_pwait2・eventfd/eventfd2・timerfd_*。ソケット系は
//! `sock` モジュールが担う。
//!
//! `Wait`・`Out` はソケット系と共通の待ち語彙（ABI が駐車へ
//! 写す要求と結果）。`serve` は単一スレッド ABI のための
//! 待ち消化（ホスト fd は `host::poll`、カーネル対象は
//! `FdTable::ready` の再評価、`Wait::deadline` 切れは Expired）。
//! `dispatch` は名前駆動。`prev` は前回張った `Wait` で、
//! 期限切れ起きの再実行を正準層が判定するためのもの。
// Ref: SRC-LINUX (7.3)。

use polyisa_engine::bare::BareEnv;
use polyisa_kernel::{FdRead, FdTable, FdTarget, FdWrite};
use polyisa_mem::Endian;

use crate::sock::{errno, rd, rd_u, wr, wr_u};

/// 待ち系の結果。`Done` の語を ABI が結果レジスタへ置く。
/// `Wait` は fd 準備待ちの要求で、ABI が駐車へ写す。
#[derive(Debug)]
pub enum Out {
    /// 完了（結果語）。
    Done(u64),
    /// fd 準備待ち。ABI は待ちを張って syscall を後で再実行する。
    Wait(Wait),
}

/// fd 準備待ちの中身。ABI の `Linux` が `fd_wait` として持つ。
/// `deadline` は「それまでに再評価してほしい」時点（ナノ秒）で、
/// poll 系はタイムアウト、timerfd の read は満了時刻を指す。
#[derive(Clone, Debug)]
pub struct Wait {
    /// （ゲスト fd, 興味ビット）。POLLIN=1・POLLOUT=4。
    pub fds: Vec<(u32, u32)>,
    /// 期限（ナノ秒。ABI の単調時計起点）。None は無期限。
    pub deadline: Option<u64>,
}

/// 興味ビット。poll 規約と同じ値。
pub const WANT_READ: u32 = 1;
/// 興味ビット（POLLOUT）。
pub const WANT_WRITE: u32 = 4;

/// `dispatch` が受ける syscall 名の集合。`*_time64` は 32 ビット
/// ABI の 64 ビット時刻版で、timespec が常に 64 ビット幅。
pub const NAMES: &[&str] = &[
    "select",
    "_newselect",
    "pselect6",
    "pselect6_time64",
    "poll",
    "ppoll",
    "ppoll_time64",
    "epoll_create",
    "epoll_create1",
    "epoll_ctl",
    "epoll_wait",
    "epoll_pwait",
    "epoll_pwait2",
    "eventfd",
    "eventfd2",
    "timerfd",
    "timerfd_create",
    "timerfd_settime",
    "timerfd_gettime",
    "timerfd_settime64",
    "timerfd_gettime64",
    "memfd_create",
    "signalfd",
    "signalfd4",
];

/// ABI ごとの差分。値はゲスト側の定数。
pub struct WaitAbi {
    /// ポインタ語幅（4 or 8 バイト）。
    pub ptr_size: u8,
    /// ゲストのエンディアン。
    pub endian: Endian,
    /// asm-generic errno → ABI errno の写像（同値なら恒等）。
    pub errno: fn(u32) -> u32,
    /// timeval/timespec の語幅（4 or 8 バイト）。
    pub time_size: u8,
    /// epoll_event の 1 項目サイズ（12 詰め or 16 パッド）。
    pub epoll_ev_size: u8,
    /// `select` が旧形式（5 語の引数ブロックを指す）か。
    /// i386 の 82・m68k/powerpc32 の 82 など。
    pub old_select: bool,
    /// O_NONBLOCK（eventfd2・timerfd_create の旗値）。
    pub nonblock: u64,
    /// O_CLOEXEC。
    pub cloexec: u64,
}

impl WaitAbi {
    /// asm-generic 値の ABI（errno 恒等・旧形式なし）。
    pub fn generic(ptr_size: u8, time_size: u8, endian: Endian) -> Self {
        Self {
            ptr_size,
            endian,
            errno: |e| e,
            time_size,
            epoll_ev_size: if ptr_size == 8 { 16 } else { 12 },
            old_select: false,
            nonblock: 0o4000,
            cloexec: 0o2000000,
        }
    }

    /// `name` に合わせて時刻語幅を直したコピー。`*_time64` と
    /// epoll_pwait2 は `__kernel_timespec`（常に 64 ビット幅）。
    #[must_use]
    pub fn for_name(&self, name: &str) -> Self {
        let mut a = Self {
            ptr_size: self.ptr_size,
            endian: self.endian,
            errno: self.errno,
            time_size: self.time_size,
            epoll_ev_size: self.epoll_ev_size,
            old_select: self.old_select,
            nonblock: self.nonblock,
            cloexec: self.cloexec,
        };
        if name.ends_with("_time64") || name == "epoll_pwait2" {
            a.time_size = 8;
        }
        a
    }
}

/// `serve`/`drive` の待ち消化の結果。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Served {
    /// 監視対象の準備が立った。
    Ready,
    /// 待ちの期限が切れた。
    Expired,
    /// 進められる待ちが残っていない（実機のデッドロック相当）。
    Deadlock,
}

/// 単一スレッド ABI の `Wait` の消化。ホスト fd は `host::poll`
/// （epoll 登録の中の HostSock も `host_watches` で拾う）、
/// カーネル対象は `ready` の再評価で待つ。期限は `mono_ns` の
/// 時計（ナノ秒）。
///
/// カーネル対象だけを無期限に待ち、変化の余地がない（待っている
/// スレッドが自分だけ）場合は実機のデッドロック相当として
/// `Deadlock` を返す（ABI はデッドロック報告へ写す）。期限が
/// ある待ちは `Expired` で戻り、ABI は `dispatch` を `prev`
/// つきで再実行する（正準層がタイムアウト結果を組み立てる）。
///
/// `pending` は signalfd 判定用の保留シグナル集合（無い ABI は 0）。
pub fn serve(fds: &FdTable, wait: &Wait, pending: u64, mono_ns: &dyn Fn() -> u64) -> Served {
    // 監視対象を集める。ホストソケットは生 fd を poll へ、
    // それ以外は ready の再評価対象へ。
    #[cfg(unix)]
    let host_list: Vec<(polyisa_host::RawFd, i16)> = wait
        .fds
        .iter()
        .flat_map(|&(fd, ev)| fds.host_watches(fd, ev))
        .collect();
    // どれか一つでも既に準備が立っていれば即終了。
    let check = |now: u64| -> bool {
        wait.fds.iter().any(|&(fd, ev)| {
            let r = fds.ready(fd, now, pending);
            r.err || r.hup || (ev & WANT_READ != 0 && r.read) || (ev & WANT_WRITE != 0 && r.write)
        })
    };
    if check(mono_ns()) {
        return Served::Ready;
    }
    loop {
        let now = mono_ns();
        let remain = match wait.deadline {
            Some(dl) if now >= dl => return Served::Expired,
            Some(dl) => dl - now,
            None => u64::MAX,
        };
        #[cfg(not(unix))]
        let host_list: Vec<()> = Vec::new();
        if host_list.is_empty() && wait.deadline.is_none() {
            // ホスト資源も期限も無い単一スレッドの待ちはデッドロック相当。
            return Served::Deadlock;
        }
        let chunk_ms = remain.min(50_000_000) / 1_000_000; // 50ms ごとにカーネル側も見る
        #[cfg(unix)]
        if !host_list.is_empty() {
            let mut list = host_list.clone();
            let _ =
                polyisa_host::sock::poll(&mut list, i32::try_from(chunk_ms).unwrap_or(i32::MAX));
        } else {
            std::thread::sleep(std::time::Duration::from_millis(chunk_ms));
        }
        #[cfg(not(unix))]
        std::thread::sleep(std::time::Duration::from_millis(chunk_ms));
        if check(mono_ns()) {
            return Served::Ready;
        }
    }
}

/// 前回の待ちが期限切れ起きだったか。
fn expired(prev: Option<&Wait>, now: u64) -> bool {
    prev.is_some_and(|w| w.deadline.is_some_and(|dl| now >= dl))
}

/// 再実行で使う残り時間（ナノ秒）。`prev` があればその期限との
/// 差、なければ `full`（初回評価）を返す。
fn remaining_ns(prev: Option<&Wait>, now: u64, full: u64) -> u64 {
    match prev.and_then(|w| w.deadline) {
        Some(dl) => dl.saturating_sub(now),
        None => full,
    }
}

/// timeval/timespec の 2 語を読みナノ秒へ。addr=0 は None。
/// `usec` が真なら 2 語目はマイクロ秒（select）。負の秒や
/// 範囲外の細部は EINVAL。
fn rd_ts(env: &mut BareEnv, abi: &WaitAbi, addr: u64, usec: bool) -> Result<Option<u64>, u32> {
    if addr == 0 {
        return Ok(None);
    }
    let w = abi.time_size as usize;
    let (Some(s), Some(ns)) = (
        rd_u(env, abi.endian, addr, w),
        rd_u(env, abi.endian, addr + w as u64, w),
    ) else {
        return Err(errno::EFAULT);
    };
    // 語幅で符号拡張する。
    let sign = |v: u64| -> i64 {
        if w == 4 {
            v as u32 as i32 as i64
        } else {
            v as i64
        }
    };
    let (s, f) = (sign(s), sign(ns));
    let (flimit, fmul) = if usec {
        (1_000_000_i64, 1_000_u64)
    } else {
        (1_000_000_000, 1)
    };
    if s < 0 || !(0..flimit).contains(&f) {
        return Err(errno::EINVAL);
    }
    Ok(Some(
        (s as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(f as u64 * fmul),
    ))
}

/// timeval/timespec に残りナノ秒を書き戻す。addr=0 では何もしない。
/// `usec` が真なら 2 語目はマイクロ秒（select）。
fn wr_ts(env: &mut BareEnv, abi: &WaitAbi, addr: u64, ns: u64, usec: bool) -> Result<(), u32> {
    if addr == 0 {
        return Ok(());
    }
    let w = abi.time_size as usize;
    let (s, f) = (ns / 1_000_000_000, ns % 1_000_000_000);
    let f = if usec { f / 1_000 } else { f };
    if !wr_u(env, abi.endian, addr, s, w) || !wr_u(env, abi.endian, addr + w as u64, f, w) {
        return Err(errno::EFAULT);
    }
    Ok(())
}

/// `Ready` を POLL* の revents ビットへ写す。
fn revents_of(r: polyisa_kernel::Ready, events: u32) -> u16 {
    let mut v = 0u16;
    if r.read {
        v |= (events & (1 | 2 | 0x40 | 0x80)) as u16; // IN PRI RDNORM RDBAND
    }
    if r.write {
        v |= (events & (4 | 0x100 | 0x200)) as u16; // OUT WRNORM WRBAND
    }
    if r.err {
        v |= 8; // POLLERR
    }
    if r.hup {
        v |= 0x10; // POLLHUP
    }
    v
}

/// poll(fds, nfds, timeout) 本体。`deadline` は None=無期限・
/// Some(0..=now)=即時・Some(将来)=期限つき。
#[allow(clippy::too_many_arguments)]
fn do_poll(
    fds: &mut FdTable,
    abi: &WaitAbi,
    env: &mut BareEnv,
    addr: u64,
    nfds: u64,
    deadline: Option<u64>,
    prev: Option<&Wait>,
    now: u64,
    pending: u64,
) -> Result<Out, u32> {
    if nfds > 0x10_0000 {
        return Err(errno::EINVAL);
    }
    // pollfd: i32 fd + i16 events + i16 revents = 8 バイト。
    let mut nready = 0u64;
    let mut watches: Vec<(u32, u32)> = Vec::new();
    for i in 0..nfds {
        let base = addr + i * 8;
        let (Some(fd), Some(events)) = (
            rd_u(env, abi.endian, base, 4),
            rd_u(env, abi.endian, base + 4, 2),
        ) else {
            return Err(errno::EFAULT);
        };
        let fd = fd as u32 as i32;
        let events = events as u16;
        let mut rev = 0u16;
        if fd >= 0 {
            if fds.ent(fd as u32).is_none() {
                rev = 0x20; // POLLNVAL
            } else {
                let r = fds.ready(fd as u32, now, pending);
                rev = revents_of(r, u32::from(events));
            }
            if rev != 0 {
                nready += 1;
            }
            // ゲストの興味に応じた方向だけ監視する。ERR/HUP/NVAL は
            // 興味に関係なく起床条件と revents の両方に載る。
            let ev = u32::from(events);
            let mut w = 0u32;
            if ev & 0xC3 != 0 {
                w |= WANT_READ;
            }
            if ev & 0x304 != 0 {
                w |= WANT_WRITE;
            }
            watches.push((fd as u32, w));
        }
        if !wr_u(env, abi.endian, base + 6, u64::from(rev), 2) {
            return Err(errno::EFAULT);
        }
    }
    if nready > 0 || expired(prev, now) || deadline.is_some_and(|dl| dl <= now) {
        return Ok(Out::Done(nready));
    }
    Ok(Out::Wait(Wait {
        fds: watches,
        deadline,
    }))
}

/// fd_set（1024 ビットのビットマップ）を読み、興味のある fd の
/// 集合と監視用の (fd, want) 列を返す。
#[allow(clippy::type_complexity)]
fn rd_fdset(
    env: &mut BareEnv,
    abi: &WaitAbi,
    addr: u64,
    nfds: u32,
    want: u32,
) -> Result<([u64; 16], Vec<(u32, u32)>), u32> {
    // (マスク, 監視リスト) を返す型は読みづらいが局所的。
    let mut mask = [0u64; 16];
    if addr != 0 {
        for (i, w) in mask.iter_mut().enumerate() {
            *w = rd_u(env, abi.endian, addr + i as u64 * 8, 8).ok_or(errno::EFAULT)?;
        }
    }
    let mut list = Vec::new();
    for fd in 0..nfds {
        if mask[fd as usize / 64] >> (fd % 64) & 1 != 0 {
            list.push((fd, want));
        }
    }
    Ok((mask, list))
}

/// 準備の立った fd だけが立った fd_set を書き戻す。
fn wr_fdset(env: &mut BareEnv, abi: &WaitAbi, addr: u64, ready: &[u64; 16]) -> Result<(), u32> {
    if addr == 0 {
        return Ok(());
    }
    for (i, w) in ready.iter().enumerate() {
        if !wr_u(env, abi.endian, addr + i as u64 * 8, *w, 8) {
            return Err(errno::EFAULT);
        }
    }
    Ok(())
}

/// select(nfds, readfds, writefds, exceptfds, tv) /
/// pselect6（timespec と sigmask ペア。mask は読み飛ばす）。
/// `timeout` は None=無期限・Some(ns)。戻るときの tv には残りを
/// 書き戻す。
#[allow(clippy::too_many_arguments)]
fn do_select(
    fds: &mut FdTable,
    abi: &WaitAbi,
    env: &mut BareEnv,
    nfds: u64,
    rd_addr: u64,
    wr_addr: u64,
    ex_addr: u64,
    tv_addr: u64,
    timeout: Option<u64>,
    tv_null: bool,
    tv_usec: bool,
    prev: Option<&Wait>,
    now: u64,
    pending: u64,
) -> Result<Out, u32> {
    if nfds > 1024 {
        return Err(errno::EINVAL);
    }
    let nfds = nfds as u32;
    let (r_mask, r_list) = rd_fdset(env, abi, rd_addr, nfds, WANT_READ)?;
    let (w_mask, w_list) = rd_fdset(env, abi, wr_addr, nfds, WANT_WRITE)?;
    let (x_mask, x_list) = rd_fdset(env, abi, ex_addr, nfds, WANT_READ)?;
    let mut r_out = [0u64; 16];
    let mut w_out = [0u64; 16];
    let mut x_out = [0u64; 16];
    let mut nready = 0u64;
    for fd in 0..nfds.min(1024) {
        let bit = 1u64 << (fd % 64);
        let w = fd as usize / 64;
        let r = fds.ready(fd, now, pending);
        let mut hit = false;
        if r_mask[w] & bit != 0 && (r.read || r.hup || r.err) {
            r_out[w] |= bit;
            hit = true;
        }
        if w_mask[w] & bit != 0 && (r.write || r.err) {
            w_out[w] |= bit;
            hit = true;
        }
        if x_mask[w] & bit != 0 && r.err {
            x_out[w] |= bit;
            hit = true;
        }
        if hit {
            nready += 1;
        }
    }
    wr_fdset(env, abi, rd_addr, &r_out)?;
    wr_fdset(env, abi, wr_addr, &w_out)?;
    wr_fdset(env, abi, ex_addr, &x_out)?;
    let mut watches = r_list;
    watches.extend(w_list);
    watches.extend(x_list);
    if nready > 0 {
        if !tv_null {
            wr_ts(
                env,
                abi,
                tv_addr,
                remaining_ns(prev, now, timeout.unwrap_or(0)),
                tv_usec,
            )?;
        }
        return Ok(Out::Done(nready));
    }
    if expired(prev, now) || timeout == Some(0) {
        wr_ts(env, abi, tv_addr, 0, tv_usec)?;
        return Ok(Out::Done(0));
    }
    Ok(Out::Wait(Wait {
        fds: watches,
        deadline: if tv_null {
            None
        } else {
            timeout.map(|ns| now.saturating_add(ns))
        },
    }))
}

/// select の引数展開。旧形式（`old_select`）は args[0] が
/// 5 語の引数ブロックを指す。
#[allow(clippy::too_many_arguments)]
fn sys_select(
    fds: &mut FdTable,
    abi: &WaitAbi,
    env: &mut BareEnv,
    args: &[u64; 6],
    tv_usec: bool,
    old_block: bool,
    prev: Option<&Wait>,
    now: u64,
    pending: u64,
) -> Result<Out, u32> {
    let (nfds, rd, wr, ex, tv) = if old_block {
        let w = abi.ptr_size as u64;
        let mut a = [0u64; 5];
        for (i, slot) in a.iter_mut().enumerate() {
            *slot =
                rd_u(env, abi.endian, args[0] + i as u64 * w, w as usize).ok_or(errno::EFAULT)?;
        }
        (a[0], a[1], a[2], a[3], a[4])
    } else {
        (args[0], args[1], args[2], args[3], args[4])
    };
    let timeout = rd_ts(env, abi, tv, tv_usec)?;
    if !tv_usec && args[5] != 0 {
        // pselect6 の第6引数は { sigmask, sigsetsize } の組。
        let w = u64::from(abi.ptr_size);
        let mask = rd_u(env, abi.endian, args[5], w as usize).ok_or(errno::EFAULT)?;
        let size = rd_u(env, abi.endian, args[5] + w, w as usize).ok_or(errno::EFAULT)?;
        rd_pwait_mask(env, abi, mask, size)?;
    }
    do_select(
        fds,
        abi,
        env,
        nfds,
        rd,
        wr,
        ex,
        tv,
        timeout,
        tv == 0,
        tv_usec,
        prev,
        now,
        pending,
    )
}

/// epoll_create(size) / epoll_create1(flags)。EPOLL_CLOEXEC だけを
/// 受ける。size は 0 より大きいことだけ要求する。
fn sys_epoll_create(fds: &mut FdTable, abi: &WaitAbi, size: u64, flags: u64) -> Result<u64, u32> {
    if size == 0 {
        return Err(errno::EINVAL);
    }
    if flags & !abi.cloexec != 0 {
        return Err(errno::EINVAL);
    }
    let t = fds.epoll();
    let fd = fds.alloc(t);
    if flags & abi.cloexec != 0 {
        fds.set_cloexec(fd, true);
    }
    Ok(u64::from(fd))
}

/// epoll_ctl(epfd, op, fd, event)。event は {u32 events, u64 data}。
/// op は ADD=1 DEL=2 MOD=3。
fn sys_epoll_ctl(
    fds: &mut FdTable,
    abi: &WaitAbi,
    env: &mut BareEnv,
    epfd: u64,
    op: u64,
    fd: u64,
    ev_addr: u64,
) -> Result<u64, u32> {
    let Some(set) = fds.epoll_of(epfd as u32) else {
        return Err(if fds.ent(epfd as u32).is_none() {
            errno::EBADF
        } else {
            errno::EINVAL
        });
    };
    if epfd == fd {
        return Err(errno::EINVAL);
    }
    let Some(target) = fds.target(fd as u32) else {
        return Err(errno::EBADF);
    };
    // epoll が扱えない対象（通常ファイル・memfd・予約枠）は EPERM。
    if matches!(
        target,
        FdTarget::File(_) | FdTarget::MemFd(_) | FdTarget::Reserved
    ) {
        return Err(errno::EPERM);
    }
    let key = target.epoll_key();
    match op {
        // EPOLL_CTL_DEL
        2 => {
            if fds.epoll_del(&set, key) {
                Ok(0)
            } else {
                Err(errno::ENOENT)
            }
        }
        // EPOLL_CTL_ADD / EPOLL_CTL_MOD
        1 | 3 => {
            let (Some(events), Some(data)) = (
                rd_u(env, abi.endian, ev_addr, 4),
                rd_u(env, abi.endian, ev_addr + abi.epoll_ev_size as u64 - 8, 8),
            ) else {
                return Err(errno::EFAULT);
            };
            let exists = set.borrow().regs.iter().any(|r| r.key == key);
            if op == 1 && exists {
                return Err(errno::EEXIST);
            }
            if op == 3 && !exists {
                return Err(errno::ENOENT);
            }
            let Some(dup) = fds.dup_of(target) else {
                return Err(errno::ENOMEM);
            };
            // 同じ鍵は epoll_add が MOD 相当で置き換える。
            if !fds.epoll_add(&set, key, dup, events as u32, data) {
                return Err(errno::ELOOP);
            }
            Ok(0)
        }
        _ => Err(errno::EINVAL),
    }
}

/// epoll_wait(epfd, events, maxevents, timeout)。`deadline` は
/// None=無期限・Some(0..=now)=即時・Some(将来)=期限つき。
/// pwait 系の sigmask は読み飛ばす。
#[allow(clippy::too_many_arguments)]
fn sys_epoll_wait(
    fds: &mut FdTable,
    abi: &WaitAbi,
    env: &mut BareEnv,
    epfd: u64,
    evs: u64,
    max: u64,
    deadline: Option<u64>,
    prev: Option<&Wait>,
    now: u64,
    pending: u64,
) -> Result<Out, u32> {
    let Some(set) = fds.epoll_of(epfd as u32) else {
        return Err(if fds.ent(epfd as u32).is_none() {
            errno::EBADF
        } else {
            errno::EINVAL
        });
    };
    if max == 0 || max > 0x10_0000 {
        return Err(errno::EINVAL);
    }
    let ev_size = u64::from(abi.epoll_ev_size);
    let ready = fds.epoll_collect(&set, now, pending, max as usize);
    if ready.is_empty() {
        if expired(prev, now) || deadline.is_some_and(|dl| dl <= now) {
            return Ok(Out::Done(0));
        }
        return Ok(Out::Wait(Wait {
            fds: vec![(epfd as u32, WANT_READ)],
            deadline,
        }));
    }
    for (i, (events, data)) in ready.iter().enumerate() {
        let base = evs + i as u64 * ev_size;
        if !wr_u(env, abi.endian, base, u64::from(*events), 4)
            || !wr_u(env, abi.endian, base + ev_size - 8, *data, 8)
        {
            return Err(errno::EFAULT);
        }
    }
    Ok(Out::Done(ready.len() as u64))
}

/// pwait 系の sigmask を入力として検証して読む。
/// Linux の kernel sigset_t は 64 シグナル分の 8 バイト。mask が
/// null のときはサイズ引数を見ない。実際の一時 mask 適用は ABI 層で行う。
fn rd_pwait_mask(
    env: &mut BareEnv,
    abi: &WaitAbi,
    addr: u64,
    size: u64,
) -> Result<Option<u64>, u32> {
    if addr == 0 {
        return Ok(None);
    }
    if size != 8 {
        return Err(errno::EINVAL);
    }
    rd_u(env, abi.endian, addr, 8)
        .map(Some)
        .ok_or(errno::EFAULT)
}

/// eventfd(initval, flags)。EFD_SEMAPHORE=1・EFD_NONBLOCK・
/// EFD_CLOEXEC。eventfd は flags=0 の形。
fn sys_eventfd(fds: &mut FdTable, abi: &WaitAbi, init: u64, flags: u64) -> Result<u64, u32> {
    let known = 1 | abi.nonblock | abi.cloexec;
    if flags & !known != 0 {
        return Err(errno::EINVAL);
    }
    let t = fds.eventfd(init, flags & 1 != 0);
    let fd = fds.alloc(t);
    if flags & abi.nonblock != 0 {
        fds.set_nonblock(fd, true);
    }
    if flags & abi.cloexec != 0 {
        fds.set_cloexec(fd, true);
    }
    Ok(u64::from(fd))
}

/// timerfd_create(clockid, flags)。clockid は REALTIME/MONOTONIC
/// を受理（時計の区別は行わず単調時計に寄せる）。
/// TFD_NONBLOCK/TFD_CLOEXEC（O_* と同値）だけを受ける。
fn sys_timerfd_create(
    fds: &mut FdTable,
    abi: &WaitAbi,
    clockid: u64,
    flags: u64,
) -> Result<u64, u32> {
    if clockid > 1 {
        return Err(errno::EINVAL);
    }
    if flags & !(abi.nonblock | abi.cloexec) != 0 {
        return Err(errno::EINVAL);
    }
    let t = fds.timerfd();
    let fd = fds.alloc(t);
    if flags & abi.nonblock != 0 {
        fds.set_nonblock(fd, true);
    }
    if flags & abi.cloexec != 0 {
        fds.set_cloexec(fd, true);
    }
    Ok(u64::from(fd))
}

/// memfd_create(name, flags)。MFD_CLOEXEC=1・MFD_ALLOW_SEALING=2
/// を受ける（シール機構は未実装）。中身は `FdTarget::MemFd`。
fn sys_memfd_create(
    fds: &mut FdTable,
    abi: &WaitAbi,
    env: &mut BareEnv,
    _name_addr: u64,
    flags: u64,
) -> Result<u64, u32> {
    // MFD_CLOEXEC=1・MFD_ALLOW_SEALING=2・MFD_HUGETLB=4・
    // MFD_NOEXEC_SEAL=8・MFD_EXEC=16 を既知とする（HUGETLB 系と
    // exec 制御は近似として受理のみ）。
    // 名前の正当性は検査しない（読めればよい。読めなくても受理）。
    if flags & !0x1F != 0 {
        return Err(errno::EINVAL);
    }
    let _ = (env, abi); // 名前の読み取りは記録しないので省略。
    let t = fds.memfd();
    let fd = fds.alloc(t);
    if flags & 1 != 0 {
        fds.set_cloexec(fd, true);
    }
    Ok(u64::from(fd))
}

/// signalfd4(fd, mask, flags) / signalfd(fd, mask)。fd == -1 で
/// 新規作成、そうでなければ既存 signalfd のマスク更新。
/// mask はゲストのシグナル番号のビット集合（sigset_t 語を読む）。
fn sys_signalfd(
    fds: &mut FdTable,
    abi: &WaitAbi,
    env: &mut BareEnv,
    fd: u64,
    mask_addr: u64,
    flags: u64,
) -> Result<u64, u32> {
    if flags & !(abi.nonblock | abi.cloexec) != 0 {
        return Err(errno::EINVAL);
    }
    // sigset_t は ptr 幅を持つ（128 ビットの語でも先頭語だけ見る）。
    let w = usize::from(abi.ptr_size).max(8);
    let mask = rd_u(env, abi.endian, mask_addr, w).ok_or(errno::EFAULT)?;
    let fdu = fd as u32 as i32;
    let out = if fdu < 0 {
        let t = fds.signalfd(mask);
        fds.alloc(t)
    } else {
        if !fds.signalfd_mask(fd as u32, mask) {
            return Err(errno::EBADF);
        }
        fd as u32
    };
    if flags & abi.nonblock != 0 {
        fds.set_nonblock(out, true);
    }
    if flags & abi.cloexec != 0 {
        fds.set_cloexec(out, true);
    }
    Ok(u64::from(out))
}

/// itimerspec（it_interval・it_value の timespec 2 個）を読む。
fn rd_itimer(env: &mut BareEnv, abi: &WaitAbi, addr: u64) -> Result<(u64, u64), u32> {
    let w = u64::from(abi.time_size);
    let iv = rd_ts(env, abi, addr, false)?.unwrap_or(0);
    let v = rd_ts(env, abi, addr + w * 2, false)?.unwrap_or(0);
    Ok((iv, v))
}

/// itimerspec を書く。
fn wr_itimer(
    env: &mut BareEnv,
    abi: &WaitAbi,
    addr: u64,
    interval: u64,
    value: u64,
) -> Result<(), u32> {
    let w = u64::from(abi.time_size);
    wr_ts(env, abi, addr, interval, false)?;
    wr_ts(env, abi, addr + w * 2, value, false)?;
    Ok(())
}

/// timerfd の現在値（周期・残り）。
fn timerfd_cur(fds: &FdTable, fd: u32, now: u64) -> Option<(u64, u64)> {
    let Some(FdTarget::TimerFd(st)) = fds.target(fd) else {
        return None;
    };
    let st = st.borrow();
    let remain = st.deadline.map(|dl| dl.saturating_sub(now)).unwrap_or(0);
    Some((st.interval, remain))
}

/// timerfd_settime(fd, flags, new, old)。TFD_TIMER_ABSTIME=1。
#[allow(clippy::too_many_arguments)]
fn sys_timerfd_settime(
    fds: &mut FdTable,
    abi: &WaitAbi,
    env: &mut BareEnv,
    fd: u64,
    flags: u64,
    new_addr: u64,
    old_addr: u64,
    now: u64,
) -> Result<u64, u32> {
    if flags & !1 != 0 {
        return Err(errno::EINVAL);
    }
    let fd = fd as u32;
    if !matches!(fds.target(fd), Some(FdTarget::TimerFd(_))) {
        return Err(errno::EINVAL);
    }
    if old_addr != 0 {
        let (iv, v) = timerfd_cur(fds, fd, now).unwrap_or((0, 0));
        wr_itimer(env, abi, old_addr, iv, v)?;
    }
    let (interval, value) = rd_itimer(env, abi, new_addr)?;
    let Some(FdTarget::TimerFd(st)) = fds.target(fd) else {
        unreachable!()
    };
    let mut st = st.borrow_mut();
    st.interval = interval;
    st.deadline = if value == 0 {
        None
    } else if flags & 1 != 0 {
        Some(value) // 絶対時刻
    } else {
        Some(now.saturating_add(value))
    };
    st.expirations = 0;
    Ok(0)
}

/// timerfd_gettime(fd, cur)。
fn sys_timerfd_gettime(
    fds: &mut FdTable,
    abi: &WaitAbi,
    env: &mut BareEnv,
    fd: u64,
    cur_addr: u64,
    now: u64,
) -> Result<u64, u32> {
    let Some((iv, v)) = timerfd_cur(fds, fd as u32, now) else {
        return Err(errno::EINVAL);
    };
    wr_itimer(env, abi, cur_addr, iv, v)?;
    Ok(0)
}

/// syscall 名による振り分け。待ち系の名前でなければ `None`。
/// `prev` は前回張った `Wait`（再起動の再実行で期限切れを
/// 判定する）。`now`/`pending` は `FdTable::ready` と同じ時計・
/// 保留集合。
#[allow(clippy::too_many_arguments)]
pub fn dispatch(
    fds: &mut FdTable,
    abi: &WaitAbi,
    env: &mut BareEnv,
    name: &str,
    args: &[u64; 6],
    prev: Option<&Wait>,
    now: u64,
    pending: u64,
) -> Option<Result<Out, u32>> {
    // `*_time64`/epoll_pwait2 は __kernel_timespec（64 ビット幅）。
    let abi = &abi.for_name(name);
    let r: Result<Out, u32> = match name {
        "poll" => {
            let ms = args[2] as u32 as i32 as i64;
            let dl = if ms < 0 {
                None
            } else {
                Some(now.saturating_add((ms as u64).saturating_mul(1_000_000)))
            };
            do_poll(fds, abi, env, args[0], args[1], dl, prev, now, pending)
        }
        "ppoll" | "ppoll_time64" => {
            let dl = match rd_ts(env, abi, args[2], false) {
                Ok(t) => t.map(|ns| now.saturating_add(ns)),
                Err(e) => return Some(Err(e)),
            };
            if let Err(e) = rd_pwait_mask(env, abi, args[3], args[4]) {
                return Some(Err(e));
            }
            do_poll(fds, abi, env, args[0], args[1], dl, prev, now, pending)
        }
        "select" | "_newselect" | "pselect6" | "pselect6_time64" => sys_select(
            fds,
            abi,
            env,
            args,
            // select/_newselect は timeval、pselect6 系は timespec。
            matches!(name, "select" | "_newselect"),
            // 旧形式の引数ブロックは select 番号のときだけ。
            abi.old_select && name == "select",
            prev,
            now,
            pending,
        ),
        "epoll_create" => sys_epoll_create(fds, abi, args[0], 0).map(Out::Done),
        "epoll_create1" => sys_epoll_create(fds, abi, 1, args[0]).map(Out::Done),
        "epoll_ctl" => {
            sys_epoll_ctl(fds, abi, env, args[0], args[1], args[2], args[3]).map(Out::Done)
        }
        "epoll_wait" | "epoll_pwait" => {
            let ms = args[3] as u32 as i32 as i64;
            let dl = if ms < 0 {
                None
            } else {
                Some(now.saturating_add((ms as u64).saturating_mul(1_000_000)))
            };
            if name == "epoll_pwait"
                && let Err(e) = rd_pwait_mask(env, abi, args[4], args[5])
            {
                return Some(Err(e));
            }
            sys_epoll_wait(
                fds, abi, env, args[0], args[1], args[2], dl, prev, now, pending,
            )
        }
        "epoll_pwait2" => {
            // (epfd, events, maxevents, ts, sigmask, sigsetsize)。
            let dl = match rd_ts(env, abi, args[3], false) {
                Ok(t) => t.map(|ns| now.saturating_add(ns)),
                Err(e) => return Some(Err(e)),
            };
            if let Err(e) = rd_pwait_mask(env, abi, args[4], args[5]) {
                return Some(Err(e));
            }
            sys_epoll_wait(
                fds, abi, env, args[0], args[1], args[2], dl, prev, now, pending,
            )
        }
        "eventfd" => sys_eventfd(fds, abi, args[0], 0).map(Out::Done),
        "eventfd2" => sys_eventfd(fds, abi, args[0], args[1]).map(Out::Done),
        // 旧形式の timerfd(ufd, clockid, flags, utmr)。ufd が -1
        // なら作成、そうでなければその fd の再武装。
        "timerfd" => {
            if (args[0] as u32 as i32) < 0 {
                sys_timerfd_create(fds, abi, args[1], args[2]).map(Out::Done)
            } else {
                sys_timerfd_settime(fds, abi, env, args[0], args[2], args[3], 0, now).map(Out::Done)
            }
        }
        "timerfd_create" => sys_timerfd_create(fds, abi, args[0], args[1]).map(Out::Done),
        "timerfd_settime" | "timerfd_settime64" => {
            sys_timerfd_settime(fds, abi, env, args[0], args[1], args[2], args[3], now)
                .map(Out::Done)
        }
        "timerfd_gettime" | "timerfd_gettime64" => {
            sys_timerfd_gettime(fds, abi, env, args[0], args[1], now).map(Out::Done)
        }
        "memfd_create" => sys_memfd_create(fds, abi, env, args[0], args[1]).map(Out::Done),
        "signalfd" => sys_signalfd(fds, abi, env, args[0], args[1], 0).map(Out::Done),
        "signalfd4" => sys_signalfd(fds, abi, env, args[0], args[1], args[2]).map(Out::Done),
        _ => return None,
    };
    Some(r)
}

/// 単一スレッド ABI のための `dispatch` 駆動。`Wait` が返ったら
/// `serve` で眠り、成立・期限切れのどちらでも同じ呼び出しを
/// `prev` つきで再実行する（正準層が期限切れ結果を組み立てる）。
/// 進行不能な待ちは `Err(EDEADLK)` で戻す。
#[allow(clippy::too_many_arguments)]
pub fn drive(
    fds: &mut FdTable,
    abi: &WaitAbi,
    env: &mut BareEnv,
    name: &str,
    args: &[u64; 6],
    pending: u64,
    mono_ns: &dyn Fn() -> u64,
) -> Option<Result<u64, u32>> {
    let mut prev: Option<Wait> = None;
    loop {
        let now = mono_ns();
        match dispatch(fds, abi, env, name, args, prev.as_ref(), now, pending)? {
            Ok(Out::Done(v)) => return Some(Ok(v)),
            Err(e) => return Some(Err(e)),
            Ok(Out::Wait(w)) => match serve(fds, &w, pending, mono_ns) {
                Served::Deadlock => return Some(Err(errno::EDEADLK)),
                _ => prev = Some(w),
            },
        }
    }
}

/// `FdTarget::HostSock` か。ホストソケットは Unix 系ホストにしかない。
#[cfg(unix)]
fn is_host_sock(t: Option<&FdTarget>) -> bool {
    matches!(t, Some(FdTarget::HostSock(_)))
}

/// ホストソケットを持てない OS では常に偽。
#[cfg(not(unix))]
fn is_host_sock(_t: Option<&FdTarget>) -> bool {
    false
}

/// read が `FdRead::Empty` だった対象の待ちを組み立てる
/// （阻止 read を ABI の待ち機構へ写すため）。TimerFd は期限も
/// 持つ。待ちを張る意味のない対象・無い fd では None。
#[must_use]
pub fn read_wait(fds: &FdTable, fd: u32) -> Option<Wait> {
    let ok = matches!(
        fds.target(fd),
        Some(
            FdTarget::PipeEnd { read: true, .. }
                | FdTarget::PairSock { .. }
                | FdTarget::EventFd(_)
                | FdTarget::TimerFd(_)
                | FdTarget::Epoll(_)
        )
    ) || is_host_sock(fds.target(fd));
    if !ok {
        return None;
    }
    Some(Wait {
        fds: vec![(fd, WANT_READ)],
        deadline: fds.wait_deadline(fd),
    })
}

/// write が一杯だった対象の待ち（阻止 write 用）。
#[must_use]
pub fn write_wait(fds: &FdTable, fd: u32) -> Option<Wait> {
    let ok = matches!(
        fds.target(fd),
        Some(
            FdTarget::PipeEnd { read: false, .. }
                | FdTarget::PairSock { .. }
                | FdTarget::EventFd(_)
        )
    ) || is_host_sock(fds.target(fd));
    if !ok {
        return None;
    }
    Some(Wait {
        fds: vec![(fd, WANT_WRITE)],
        deadline: None,
    })
}

/// 単一スレッド ABI の「ファイル以外の対象」の read。
/// `Empty` は `serve` で待って再読みし、カウンタ値は ABI の
/// エンディアンで 8 バイトに直列化する。戻りは読んだバイト数
/// か errno（デッドロックは `EDEADLK`）。fd が無ければ `EBADF`。
#[allow(clippy::too_many_arguments)]
pub fn read_other(
    fds: &mut FdTable,
    abi: &WaitAbi,
    env: &mut BareEnv,
    fd: u32,
    buf: u64,
    len: u64,
    pending: u64,
    mono_ns: &dyn Fn() -> u64,
) -> Result<u64, u32> {
    use polyisa_kernel::FdRead;
    if fds.target(fd).is_none() {
        return Err(errno::EBADF);
    }
    let max = usize::try_from(len.min(65536)).unwrap_or(0);
    match drive_read_once(fds, fd, max, pending, mono_ns) {
        FdRead::Bytes(b) => {
            if !wr(env, buf, &b) {
                return Err(errno::EFAULT);
            }
            Ok(b.len() as u64)
        }
        FdRead::Count(v) => {
            if !wr_u(env, abi.endian, buf, v, 8) {
                return Err(errno::EFAULT);
            }
            Ok(8)
        }
        FdRead::Eof => Ok(0),
        FdRead::Empty => Err(errno::EAGAIN),
        FdRead::IsDir => Err(errno::EISDIR),
        FdRead::BadFd => Err(errno::EBADF),
        FdRead::Inval => Err(errno::EINVAL),
        FdRead::Host(e) => Err(e.raw_os_error().map_or(errno::EIO, |c| c as u32)),
    }
}

/// `read_other` の 1 回分。阻止 `Empty` を内部で待つ。
fn drive_read_once(
    fds: &mut FdTable,
    fd: u32,
    max: usize,
    pending: u64,
    mono_ns: &dyn Fn() -> u64,
) -> FdRead {
    use polyisa_kernel::FdRead;
    loop {
        // TimerFd は ready が catch_up を進める。
        let _ = fds.ready(fd, mono_ns(), pending);
        match fds.read(fd, max) {
            FdRead::Empty if !fds.nonblock(fd) => {
                let Some(w) = read_wait(fds, fd) else {
                    return FdRead::Empty;
                };
                if serve(fds, &w, pending, mono_ns) == Served::Deadlock {
                    return FdRead::Empty;
                }
            }
            r => return r,
        }
    }
}

/// `read_other` の write 版。ゲストバッファの内容を対象へ書く。
#[allow(clippy::too_many_arguments)]
pub fn write_other(
    fds: &mut FdTable,
    abi: &WaitAbi,
    env: &mut BareEnv,
    fd: u32,
    buf: u64,
    len: u64,
    pending: u64,
    mono_ns: &dyn Fn() -> u64,
) -> Result<u64, u32> {
    use polyisa_kernel::FdWrite;
    let is_eventfd = matches!(fds.target(fd), Some(FdTarget::EventFd(_)));
    if fds.target(fd).is_none() {
        return Err(errno::EBADF);
    }
    let take = usize::try_from(len.min(65536)).unwrap_or(0);
    // eventfd の write は 8 バイトのカウンタ加算（対象の読み取り語は
    // ゲストのエンディアン）。`FdTarget::EventFd` の `fds.write` は
    // Inval を返す決まりなのでここで復元して `write_eventfd` を呼ぶ。
    if is_eventfd {
        if take != 8 {
            return Err(errno::EINVAL);
        }
        let mut chunk = [0u8; 8];
        if !rd(env, buf, &mut chunk) {
            return Err(errno::EFAULT);
        }
        let v = match abi.endian {
            Endian::Le => u64::from_le_bytes(chunk),
            Endian::Be => u64::from_be_bytes(chunk),
        };
        loop {
            match fds.write_eventfd(fd, v) {
                FdWrite::Done(n) => return Ok(n as u64),
                FdWrite::Full => {
                    if fds.nonblock(fd) {
                        return Err(errno::EAGAIN);
                    }
                    let Some(w) = write_wait(fds, fd) else {
                        return Err(errno::EAGAIN);
                    };
                    if serve(fds, &w, pending, mono_ns) == Served::Deadlock {
                        return Err(errno::EDEADLK);
                    }
                }
                FdWrite::BadFd => return Err(errno::EBADF),
                FdWrite::Pipe => return Err(errno::EPIPE),
                FdWrite::Inval => return Err(errno::EINVAL),
                FdWrite::Host(e) => {
                    return Err(e.raw_os_error().map_or(errno::EIO, |c| c as u32));
                }
            }
        }
    }
    let mut chunk = vec![0u8; take];
    if !rd(env, buf, &mut chunk) {
        return Err(errno::EFAULT);
    }
    loop {
        match fds.write(fd, &chunk) {
            FdWrite::Done(n) => return Ok(n as u64),
            FdWrite::Pipe => return Err(errno::EPIPE),
            FdWrite::Full => {
                if fds.nonblock(fd) {
                    return Err(errno::EAGAIN);
                }
                let Some(w) = write_wait(fds, fd) else {
                    return Err(errno::EAGAIN);
                };
                if serve(fds, &w, pending, mono_ns) == Served::Deadlock {
                    return Err(errno::EDEADLK);
                }
            }
            FdWrite::BadFd => return Err(errno::EBADF),
            FdWrite::Inval => return Err(errno::EINVAL),
            FdWrite::Host(e) => {
                return Err(e.raw_os_error().map_or(errno::EIO, |c| c as u32));
            }
        }
    }
}

/// 単一スレッド ABI の `fds.read` 消化。`Empty` を対象別の待ちへ
/// 写して眠り、起きたら再 read する。非阻止 fd や待てない対象
/// の `Empty`、デッドロックでは `Empty` のまま戻す（ABI は
/// EAGAIN・デッドロック報告へ写す）。
pub fn drive_read(
    fds: &mut FdTable,
    fd: u32,
    max: usize,
    pending: u64,
    mono_ns: &dyn Fn() -> u64,
) -> FdRead {
    loop {
        // TimerFd は ready が catch_up を進める。
        let _ = fds.ready(fd, mono_ns(), pending);
        match fds.read(fd, max) {
            FdRead::Empty if !fds.nonblock(fd) => {
                let Some(w) = read_wait(fds, fd) else {
                    return FdRead::Empty;
                };
                if serve(fds, &w, pending, mono_ns) == Served::Deadlock {
                    return FdRead::Empty;
                }
            }
            r => return r,
        }
    }
}

/// `drive_read` の write 版。
pub fn drive_write(
    fds: &mut FdTable,
    fd: u32,
    bytes: &[u8],
    pending: u64,
    mono_ns: &dyn Fn() -> u64,
) -> FdWrite {
    loop {
        match fds.write(fd, bytes) {
            FdWrite::Full if !fds.nonblock(fd) => {
                let Some(w) = write_wait(fds, fd) else {
                    return FdWrite::Full;
                };
                if serve(fds, &w, pending, mono_ns) == Served::Deadlock {
                    return FdWrite::Full;
                }
            }
            r => return r,
        }
    }
}
