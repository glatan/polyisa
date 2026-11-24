// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! x86 の Linux システムコール。文脈（`SysCtx`）と、状態を持たない
//! 個別の `sys_*` 処理を置く。fd・プロセス・スケジューラの状態機械は
//! `x86::sys`（`Linux`）にあり、実行ループからのトラップはそこが受ける。
//! 分割の軸は ADR-0015（無状態スタブ対状態機械）による。
//!
//! 番号表は ABI 名のモジュール（`x86_64`・`x86_32`）に置く。

// Ref: SRC-LINUX (7.3).

use polyisa_engine::bare::BareEnv;
use polyisa_guest_x86::sem::Gpr;
use polyisa_kernel::{FdTable, ProcessId, ProcessTable};
use polyisa_mem::{Access, AccessKind, Align, Endian, VirtAddr};
use polyisa_sem::Backend;

use super::TrapOutcome;

/// Linux 汎用の errno 番号の一部。負数で返す。
// Ref: SRC-LINUX (7.3).
pub const EPERM: u32 = 1;
pub const ENOENT: u32 = 2;
pub const ESRCH: u32 = 3;
pub const ENOEXEC: u32 = 8;
pub const EBADF: u32 = 9;
pub const ECHILD: u32 = 10;
pub const EAGAIN: u32 = 11;
pub const EINTR: u32 = 4;
pub const EFAULT: u32 = 14;
pub const EACCES: u32 = 13;
pub const ENOMEM: u32 = 12;
pub const ENOTDIR: u32 = 20;
pub const EINVAL: u32 = 22;
pub const EPIPE: u32 = 32;
pub const ERANGE: u32 = 34;
pub const ENOTTY: u32 = 25;
pub const EOPNOTSUPP: u32 = 95;

pub fn get64(env: &mut BareEnv, r: Gpr) -> u64 {
    polyisa_guest_x86::sem::read64(&mut env.backend, r)
}

pub fn set64(env: &mut BareEnv, r: Gpr, v: u64) {
    polyisa_guest_x86::sem::write64(&mut env.backend, r, v)
}

pub fn data_access() -> Access {
    Access {
        endian: Endian::Le,
        align: Align::Unaligned,
        kind: AccessKind::DataRead,
    }
}

/// ゲストの NUL 終端文字列を読む。上限を超えるか読めなければ None。
pub fn guest_c_string(env: &mut BareEnv, addr: u64) -> Option<String> {
    let acc = data_access();
    // 上限は 4096 バイト（NUL がなければ失敗扱い）。未写像ページまで読むと
    // read 全体が失敗するので、ページ境界ごとに読んで NUL を探す。
    const LIMIT: u64 = polyisa_mem::PAGE_SIZE;
    let mut buf = Vec::new();
    let mut cur = addr;
    let end = cur.checked_add(LIMIT)?;
    while cur < end {
        let n = (polyisa_mem::PAGE_SIZE - (cur % polyisa_mem::PAGE_SIZE)).min(end - cur);
        let mut chunk = vec![0u8; n as usize];
        env.backend.mem.read(VirtAddr(cur), &mut chunk, acc).ok()?;
        match chunk.iter().position(|&b| b == 0) {
            Some(i) => {
                buf.extend_from_slice(&chunk[..i]);
                return String::from_utf8(buf).ok();
            }
            None => buf.extend_from_slice(&chunk),
        }
        cur += n;
    }
    None
}

/// dirfd の AT_FDCWD を 32 ビットで比べるときの値。
pub const AT_FDCWD_U32: u32 = 0xffff_ff9c;

/// 32ビットの負 errno。
pub fn neg_errno(n: u32) -> u32 {
    (n as i32).wrapping_neg() as u32
}

/// 64ビットの負 errno（符号拡張する）。
pub fn neg_errno64(n: u32) -> u64 {
    (n as i32).wrapping_neg() as i64 as u64
}

/// 1 回のシステムコールで共通に使う値。
// Gap: GAP-0032
pub struct SysCtx {
    pub r_a: Gpr,
    pub r_b: Gpr,
    pub r_c: Gpr,
    /// 第4〜6引数のレジスタ（x86-64 は R10/R8/R9、x86-32 は ESI/EDI/EBP）。
    /// 3引数までしか使わないハンドラは見なくてよい。
    pub r_d: Gpr,
    pub r_e: Gpr,
    pub r_f: Gpr,
    pub is64: bool,
    /// x32 ABI。構造体内のポインタ・`long` フィールドは 32 ビット幅。
    pub x32: bool,
    pub at_fdcwd: u64,
}

impl SysCtx {
    /// dirfd が AT_FDCWD か。x86-64 は下位 32 ビット、x86-32 は値そのものを比べる.
    pub fn is_at_fdcwd(&self, dirfd: u64) -> bool {
        if self.is64 {
            (dirfd as u32) == AT_FDCWD_U32
        } else {
            dirfd == self.at_fdcwd
        }
    }

    /// 戻り値の負 errno。x86-64 は 64 ビット符号拡張、x86-32 は 32 ビット。
    pub fn neg(&self, n: u32) -> u64 {
        if self.is64 {
            neg_errno64(n)
        } else {
            u64::from(neg_errno(n))
        }
    }
}

/// socket 系。[ユーザーモード](../../../docs/design/user-mode.md) の
/// 「Linux のシステムコールの実装の段階」の段階 5（ネットワークと待ち合わせ）までの
/// 暫定で常に EPERM。失敗形のアプレット合わせに使う。
pub fn sys_socket(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    set64(env, Gpr(0), cx.neg(EPERM));
    Some(TrapOutcome::Handled)
}

/// socketpair。`sys_socket` に委ねる。
pub fn sys_socketpair(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_socket(env, cx)
}

/// bind。`sys_socket` に委ねる。
pub fn sys_bind(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_socket(env, cx)
}

/// connect。`sys_socket` に委ねる。
pub fn sys_connect(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_socket(env, cx)
}

/// sendto。`sys_socket` に委ねる。
pub fn sys_sendto(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_socket(env, cx)
}

/// recvfrom。`sys_socket` に委ねる。
pub fn sys_recvfrom(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_socket(env, cx)
}

/// getsockname。`sys_socket` に委ねる。
pub fn sys_getsockname(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_socket(env, cx)
}

// 状態を持たないシステムコールの実体。`cli` は適合層で呼ぶ。

fn sched_priority_bounds(policy: u64) -> Option<(i32, i32)> {
    match policy {
        0 | 3 | 5 => Some((0, 0)),
        1 | 2 => Some((1, 99)),
        _ => None,
    }
}

pub fn sys_chmod(env: &mut BareEnv, _cx: &SysCtx) -> Option<TrapOutcome> {
    // chmod/fchmod/fchmodat。試作では権限変更を無視して 0 を返す.
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

pub fn sys_fchmod(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_chmod(env, cx)
}

pub fn sys_chown(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_fchown(env, cx)
}

pub fn sys_lchown(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_fchown(env, cx)
}

pub fn sys_fchown(env: &mut BareEnv, _cx: &SysCtx) -> Option<TrapOutcome> {
    // chown/lchown/fchown。所有者変更を無視して 0 を返す。
    // tar の展開が chown を呼ぶ。dos2unix は fchown で所有者を戻す。
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

pub fn sys_chroot(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // chroot(path)。ルートは移さず EPERM。サンドボックスのホストと同じ。
    let _ = get64(env, cx.r_a);
    set64(env, Gpr(0), cx.neg(EPERM));
    Some(TrapOutcome::Handled)
}

pub fn sys_clock_nanosleep(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // clock_nanosleep(clock_id, flags, req, rem)。試作では待たずに 0 を返す.
    // clock_id は CLOCK_REALTIME(0)/MONOTONIC(1) のみ受け付ける.
    let clock_id = get64(env, cx.r_a);
    if clock_id > 1 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

pub fn sys_flock(env: &mut BareEnv, _cx: &SysCtx) -> Option<TrapOutcome> {
    // flock(fd, op)。単一ゲストでは競合がないので常に成功。
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

pub fn sys_getgid(env: &mut BareEnv, _cx: &SysCtx) -> Option<TrapOutcome> {
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

pub fn sys_getpriority(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // getpriority(which, who)。カーネルは nice に 20 を足した値を返す。
    // ここでの nice は 0 なので 20。Ref: SRC-LINUX (7.3).
    let which = get64(env, cx.r_a);
    if which > 2 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), 20);
    Some(TrapOutcome::Handled)
}

pub fn sys_getuid(env: &mut BareEnv, _cx: &SysCtx) -> Option<TrapOutcome> {
    // root として uid 0 を返す.
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

pub fn sys_inotify_add_watch(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    set64(env, Gpr(0), cx.neg(EPERM));
    Some(TrapOutcome::Handled)
}

pub fn sys_inotify_init1(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // inotify。監視は持たず EPERM。inotifyd の失敗形合わせ。
    set64(env, Gpr(0), cx.neg(EPERM));
    Some(TrapOutcome::Handled)
}

pub fn sys_mprotect(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // mprotect(addr, len, prot)。試作では権限変更を無視して 0 を返す.
    // addr/len の検証のみ行う (len==0 は EINVAL).
    let len = if cx.is64 {
        get64(env, Gpr(6))
    } else {
        u64::from(env.backend.get(Gpr(1).state()))
    };
    if len == 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

pub fn sys_msgctl(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    set64(env, Gpr(0), cx.neg(EINVAL));
    Some(TrapOutcome::Handled)
}

pub fn sys_msgget(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    set64(env, Gpr(0), cx.neg(ENOENT));
    Some(TrapOutcome::Handled)
}

pub fn sys_munmap(env: &mut BareEnv, _cx: &SysCtx) -> Option<TrapOutcome> {
    // munmap(addr, len)。試作では写像解除せず 0 を返す.
    // Gap: GAP-0034
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

pub fn sys_pivot_root(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    set64(env, Gpr(0), cx.neg(EPERM));
    Some(TrapOutcome::Handled)
}

pub fn sys_poll(env: &mut BareEnv, _cx: &SysCtx) -> Option<TrapOutcome> {
    // poll。待ちはせずタイムアウトとして 0 を返す。top / powertop の前進用。
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

pub fn sys_reboot(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // reboot。権限がなく常に EPERM。halt / poweroff / reboot アプレットが呼ぶ。
    set64(env, Gpr(0), cx.neg(EPERM));
    Some(TrapOutcome::Handled)
}

pub fn sys_rt_sigtimedwait(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 待ち受けはせず、期限切れとして EAGAIN を返す。init が呼ぶ。本格は GAP-0026。
    set64(env, Gpr(0), cx.neg(EAGAIN));
    Some(TrapOutcome::Handled)
}

pub fn sys_sched_get_priority_max(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // sched_get_priority_max(policy)。chrt が方針の上限を読む。Ref: SRC-LINUX (7.3).
    let Some((_, max)) = sched_priority_bounds(get64(env, cx.r_a)) else {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    };
    set64(env, Gpr(0), max as u64);
    Some(TrapOutcome::Handled)
}

pub fn sys_sched_get_priority_min(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let Some((min, _)) = sched_priority_bounds(get64(env, cx.r_a)) else {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    };
    set64(env, Gpr(0), min as u64);
    Some(TrapOutcome::Handled)
}

pub fn sys_select(env: &mut BareEnv, _cx: &SysCtx) -> Option<TrapOutcome> {
    // select。待ちはせずタイムアウトとして 0 を返す。vi / inetd の前進用。
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

pub fn sys_semctl(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    set64(env, Gpr(0), cx.neg(EINVAL));
    Some(TrapOutcome::Handled)
}

pub fn sys_semget(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    set64(env, Gpr(0), cx.neg(ENOENT));
    Some(TrapOutcome::Handled)
}

pub fn sys_setgroups(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // setgroups(size, list)。権限がないので常に EPERM。setuidgid がここで止まる。
    // Ref: SRC-LINUX (7.3).
    let _ = get64(env, cx.r_a);
    let _ = get64(env, cx.r_b);
    set64(env, Gpr(0), cx.neg(EPERM));
    Some(TrapOutcome::Handled)
}

pub fn sys_setpriority(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // setpriority(which, who, prio)。自プロセス (who=0) は受け、他は EPERM。
    // nice は self、renice <pid> は他プロセス向け。
    let which = get64(env, cx.r_a);
    let who = get64(env, cx.r_b) as i64;
    if which > 2 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    if who != 0 {
        set64(env, Gpr(0), cx.neg(EPERM));
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

pub fn sys_setuid(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // setuid 系。資格は変えず常に EPERM。passwd / chpasswd の失敗形合わせ。
    set64(env, Gpr(0), cx.neg(EPERM));
    Some(TrapOutcome::Handled)
}

pub fn sys_shmctl(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    set64(env, Gpr(0), cx.neg(EINVAL));
    Some(TrapOutcome::Handled)
}

pub fn sys_shmget(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // shmget。セグメントは持たず ENOENT。ipcrm -M が呼ぶ。
    set64(env, Gpr(0), cx.neg(ENOENT));
    Some(TrapOutcome::Handled)
}

pub fn sys_swapoff(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    set64(env, Gpr(0), cx.neg(EPERM));
    Some(TrapOutcome::Handled)
}

pub fn sys_swapon(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    set64(env, Gpr(0), cx.neg(EPERM));
    Some(TrapOutcome::Handled)
}

pub fn sys_sync(env: &mut BareEnv, _cx: &SysCtx) -> Option<TrapOutcome> {
    // sync()。ゲストの書き込みは既にホストのファイルへ届いている。dirty な頁は持たない。
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

pub fn sys_sysfs(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // sysfs（廃止）。常に EINVAL。wall が呼ぶことがある。
    set64(env, Gpr(0), cx.neg(EINVAL));
    Some(TrapOutcome::Handled)
}

pub fn sys_tgkill(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // tgkill(tgid, tid, sig)。単一スレッド試作として sig==0 は 0 を返す.
    // シグナル番号が範囲外なら EINVAL.
    let sig = if cx.is64 {
        get64(env, Gpr(2))
    } else {
        u64::from(env.backend.get(Gpr(2).state()))
    };
    if sig > 64 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    // sig==0 は存在確認であり 0 を返す。他のシグナルは無視して 0 とする.
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

pub fn sys_tkill(env: &mut BareEnv, _cx: &SysCtx) -> Option<TrapOutcome> {
    // tkill。単一ゲストでは対象が自分以外に無く、成功として無視する。
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

pub fn sys_unshare(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // unshare(flags)。flags=0 だけ受理し、名前空間は作らない。
    // 特権が要るフラグは EPERM。Ref: SRC-LINUX (7.3).
    let flags = get64(env, cx.r_a);
    if flags != 0 {
        set64(env, Gpr(0), cx.neg(EPERM));
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}
// ゲストパス解決は feature 非依存のため `guest_path` が正本。
// 既存の呼び出し経路（crate::x86::*）のため再エクスポートする。
pub use crate::guest_path::{join_guest_path, resolve_guest_path};
pub fn sys_access(root: &str, cwd: &str, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // access(path, mode)。存在確認のみ行い、存在すれば 0 を返す.
    // X_OK 等の実行権限の厳密判定はしない（試作の割り切り）。
    let path_addr = get64(env, cx.r_a);
    let path = match guest_c_string(env, path_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    let Some(path) = resolve_guest_path(root, cwd, &path) else {
        set64(env, Gpr(0), cx.neg(EPERM));
        return Some(TrapOutcome::Handled);
    };
    Some(match std::fs::metadata(&path) {
        Ok(_) => {
            set64(env, Gpr(0), 0);
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
    })
}
pub fn sys_faccessat(root: &str, cwd: &str, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // faccessat(dirfd, path, mode)。AT_FDCWD のみ、存在確認のみ行う.
    let (dirfd, path_addr) = if cx.is64 {
        (get64(env, Gpr(7)), get64(env, Gpr(6)))
    } else {
        (
            u64::from(env.backend.get(Gpr(3).state())),
            u64::from(env.backend.get(Gpr(1).state())),
        )
    };
    if !cx.is_at_fdcwd(dirfd) {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let path = match guest_c_string(env, path_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    let Some(path) = resolve_guest_path(root, cwd, &path) else {
        set64(env, Gpr(0), cx.neg(EPERM));
        return Some(TrapOutcome::Handled);
    };
    Some(match std::fs::metadata(&path) {
        Ok(_) => {
            set64(env, Gpr(0), 0);
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
    })
}
pub fn sys_link(root: &str, cwd: &str, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // link(oldpath, newpath)。ハードリンク。busybox の `link` が使う。
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
    let Some(old_path) = resolve_guest_path(root, cwd, &old_path) else {
        set64(env, Gpr(0), cx.neg(EPERM));
        return Some(TrapOutcome::Handled);
    };
    let Some(new_path) = resolve_guest_path(root, cwd, &new_path) else {
        set64(env, Gpr(0), cx.neg(EPERM));
        return Some(TrapOutcome::Handled);
    };
    Some(match std::fs::hard_link(&old_path, &new_path) {
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
pub fn sys_rename(root: &str, cwd: &str, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // rename(oldpath, newpath)。ホストの rename に直結する.
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
    let Some(old_path) = resolve_guest_path(root, cwd, &old_path) else {
        set64(env, Gpr(0), cx.neg(EPERM));
        return Some(TrapOutcome::Handled);
    };
    let Some(new_path) = resolve_guest_path(root, cwd, &new_path) else {
        set64(env, Gpr(0), cx.neg(EPERM));
        return Some(TrapOutcome::Handled);
    };
    Some(match std::fs::rename(&old_path, &new_path) {
        Ok(()) => {
            set64(env, Gpr(0), 0);
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
    })
}
pub fn sys_rmdir(root: &str, cwd: &str, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // rmdir(path)。ホストの remove_dir に直結する.
    let path_addr = get64(env, cx.r_a);
    let path = match guest_c_string(env, path_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    let Some(path) = resolve_guest_path(root, cwd, &path) else {
        set64(env, Gpr(0), cx.neg(EPERM));
        return Some(TrapOutcome::Handled);
    };
    Some(match std::fs::remove_dir(&path) {
        Ok(()) => {
            set64(env, Gpr(0), 0);
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
    })
}
pub fn sys_unlink(root: &str, cwd: &str, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // unlink(path)。chdir 後の相対パスは作業ディレクトリから外す。
    let path_addr = get64(env, cx.r_a);
    let path = match guest_c_string(env, path_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    let Some(path) = resolve_guest_path(root, cwd, &path) else {
        set64(env, Gpr(0), cx.neg(EPERM));
        return Some(TrapOutcome::Handled);
    };
    Some(match std::fs::remove_file(&path) {
        Ok(()) => {
            set64(env, Gpr(0), 0);
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
    })
}
pub fn sys_mkdir(root: &str, cwd: &str, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // mkdir(path, mode)。chdir 後の相対パスは作業ディレクトリから作る。
    let path_addr = get64(env, cx.r_a);
    let path = match guest_c_string(env, path_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    let Some(path) = resolve_guest_path(root, cwd, &path) else {
        set64(env, Gpr(0), cx.neg(EPERM));
        return Some(TrapOutcome::Handled);
    };
    Some(match std::fs::create_dir(&path) {
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
pub fn sys_mkdirat(root: &str, cwd: &str, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // mkdirat(dirfd, path, mode)。AT_FDCWD の相対パスは作業ディレクトリから作る。
    let (dirfd, path_addr) = (get64(env, cx.r_a), get64(env, cx.r_b));
    if !cx.is_at_fdcwd(dirfd) {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let path = match guest_c_string(env, path_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    let Some(path) = resolve_guest_path(root, cwd, &path) else {
        set64(env, Gpr(0), cx.neg(EPERM));
        return Some(TrapOutcome::Handled);
    };
    Some(match std::fs::create_dir(&path) {
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
pub fn sys_mknod(
    root: &str,
    cwd: &str,
    umask: u32,
    env: &mut BareEnv,
    cx: &SysCtx,
) -> Option<TrapOutcome> {
    // mknod(path, mode, dev)。名前付きパイプだけ作る。デバイスノードは EPERM。
    // このクレートは unsafe を使わないので、ホストの mkfifo に委譲する。
    let path_addr = get64(env, cx.r_a);
    let mode = get64(env, cx.r_b) as u32;
    const S_IFMT: u32 = 0o170000;
    const S_IFIFO: u32 = 0o010000;
    if mode & S_IFMT != S_IFIFO {
        set64(env, Gpr(0), cx.neg(EPERM));
        return Some(TrapOutcome::Handled);
    }
    let path = match guest_c_string(env, path_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    let Some(path) = resolve_guest_path(root, cwd, &path) else {
        set64(env, Gpr(0), cx.neg(EPERM));
        return Some(TrapOutcome::Handled);
    };
    let perm = (mode & 0o777) & !umask;
    let status = std::process::Command::new("mkfifo")
        .arg("-m")
        .arg(format!("{perm:03o}"))
        .arg(&path)
        .status();
    let no = match status {
        Ok(st) if st.success() => {
            set64(env, Gpr(0), 0);
            return Some(TrapOutcome::Handled);
        }
        Ok(_) if std::fs::metadata(&path).is_ok() => 17,
        Ok(_)
            if std::fs::metadata(
                std::path::Path::new(&path)
                    .parent()
                    .unwrap_or(std::path::Path::new(".")),
            )
            .is_err() =>
        {
            ENOENT
        }
        _ => EACCES,
    };
    set64(env, Gpr(0), cx.neg(no));
    Some(TrapOutcome::Handled)
}
pub fn sys_utimensat(root: &str, cwd: &str, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // utimensat(dirfd, path, times, flags)。AT_FDCWD のみ受け付ける.
    // times==NULL は現在時刻のつもりで、存在すれば 0、なければ空作成して 0 を返す.
    // times!=NULL は無視して同様に扱う（touch の継続が目的の試作）。
    let (dirfd, path_addr) = if cx.is64 {
        (get64(env, Gpr(7)), get64(env, Gpr(6)))
    } else {
        (
            u64::from(env.backend.get(Gpr(3).state())),
            u64::from(env.backend.get(Gpr(1).state())),
        )
    };
    if !cx.is_at_fdcwd(dirfd) {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let path = match guest_c_string(env, path_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    let Some(path) = resolve_guest_path(root, cwd, &path) else {
        set64(env, Gpr(0), cx.neg(EPERM));
        return Some(TrapOutcome::Handled);
    };
    if std::fs::metadata(&path).is_ok() {
        set64(env, Gpr(0), 0);
        return Some(TrapOutcome::Handled);
    }
    Some(match std::fs::File::create(&path) {
        Ok(_) => {
            set64(env, Gpr(0), 0);
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
    })
}
pub fn sys_adjtimex(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // adjtimex(timex)。時計は動かさず、バッファがあれば 0 埋めして成功する。
    let addr = get64(env, cx.r_a);
    if addr != 0 {
        let zeros = [0u8; 208];
        if env.backend.mem.write(VirtAddr(addr), &zeros).is_err() {
            set64(env, Gpr(0), cx.neg(EFAULT));
            return Some(TrapOutcome::Handled);
        }
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}
pub fn sys_fsetxattr(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // fsetxattr(fd, ...)。fd 経由でも属性は付けず EPERM。
    set64(env, Gpr(0), cx.neg(EPERM));
    Some(TrapOutcome::Handled)
}
pub fn sys_getgroups(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // getgroups(size, list)。所属グループは root (0) のみとみなす.
    // size==0 では必要数を返し、そうでなければ GID 0 を書く.
    // Ref: SRC-LINUX (7.3).
    let size = get64(env, cx.r_a);
    let list = get64(env, cx.r_b);
    if size == 0 {
        set64(env, Gpr(0), 1);
        return Some(TrapOutcome::Handled);
    }
    if list == 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    if env
        .backend
        .mem
        .write(VirtAddr(list), &0u32.to_le_bytes())
        .is_err()
    {
        return Some(TrapOutcome::Unimplemented);
    }
    set64(env, Gpr(0), 1.min(size));
    Some(TrapOutcome::Handled)
}
pub fn sys_getitimer(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // getitimer(which, curr). ゼロの itimerval を書く。
    let curr = get64(env, cx.r_b);
    if curr != 0 {
        let zeros = [0u8; 32];
        if env.backend.mem.write(VirtAddr(curr), &zeros).is_err() {
            return Some(TrapOutcome::Unimplemented);
        }
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}
pub fn sys_getrandom(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // getrandom(buf, len, flags)。試作では 0 埋めして len を返す.
    // flags は GRND_NONBLOCK(1)/GRND_RANDOM(2)/GRND_INSECURE(4) のみ受け付ける.
    let buf = get64(env, cx.r_a);
    let len = get64(env, cx.r_b);
    let flags = get64(env, cx.r_c);
    if flags & !7 != 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    // 拡張しすぎは失敗扱い (0 を返す)。
    const MAX_GETRANDOM: u64 = 256 * 1024;
    if len > MAX_GETRANDOM {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let zeros = vec![0u8; len as usize];
    if len != 0
        && env
            .backend
            .mem
            .write(polyisa_mem::VirtAddr(buf), &zeros)
            .is_err()
    {
        return Some(TrapOutcome::Unimplemented);
    }
    set64(env, Gpr(0), len);
    Some(TrapOutcome::Handled)
}
pub fn sys_ioctl(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // ioctl(fd, request, ...)。端末要求は ENOTTY。
    // FS_IOC_GETFLAGS はフラグなしを返す。lsattr がこれでダッシュを出す。
    // Ref: SRC-LINUX (7.3). linux/fs.h の _IOR('f', 1, long)。
    const FS_IOC_GETFLAGS: u32 = 0x8008_6601;
    // compat（x32）では _IOR の型が 4 バイトになり要求値が変わる。
    const FS_IOC_GETFLAGS32: u32 = 0x8004_6601;
    if cx.is64 && !cx.x32 && get64(env, cx.r_b) as u32 == FS_IOC_GETFLAGS {
        let ptr = get64(env, cx.r_c);
        if env.backend.mem.write(VirtAddr(ptr), &[0u8; 8]).is_err() {
            return Some(TrapOutcome::Unimplemented);
        }
        set64(env, Gpr(0), 0);
        return Some(TrapOutcome::Handled);
    }
    if cx.x32 && get64(env, cx.r_b) as u32 == FS_IOC_GETFLAGS32 {
        let ptr = get64(env, cx.r_c);
        if env.backend.mem.write(VirtAddr(ptr), &[0u8; 4]).is_err() {
            return Some(TrapOutcome::Unimplemented);
        }
        set64(env, Gpr(0), 0);
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), cx.neg(ENOTTY));
    Some(TrapOutcome::Handled)
}
pub fn sys_nanosleep(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // nanosleep(req, rem)。req の timespec を読んで、不正なら EINVAL。
    // 試作では待たずに 0 を返す。sleep 0 はこれで正しい。
    // Ref: SRC-LINUX (7.3).
    let req = get64(env, cx.r_a);
    if req == 0 {
        set64(env, Gpr(0), cx.neg(EFAULT));
        return Some(TrapOutcome::Handled);
    }
    let mut buf = [0u8; 16];
    if env
        .backend
        .mem
        .read(VirtAddr(req), &mut buf, data_access())
        .is_err()
    {
        return Some(TrapOutcome::Unimplemented);
    }
    let sec = i64::from_le_bytes(buf[..8].try_into().unwrap());
    let nsec = i64::from_le_bytes(buf[8..].try_into().unwrap());
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}
pub fn sys_prlimit64(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // prlimit64(pid, resource, new_limit, old_limit)。
    // 試作では new_limit の設定は無視し、old_limit には無制限を書く.
    // resource は 0..16 (RLIM_NLIMITS) のみ受け付ける.
    const RLIM_NLIMITS: u64 = 16;
    const RLIM_INFINITY: u64 = 0xffff_ffff_ffff_ffff;
    let resource = get64(env, cx.r_b);
    if resource >= RLIM_NLIMITS {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let old_limit = get64(env, cx.r_d);
    if old_limit != 0 {
        let buf = RLIM_INFINITY.to_le_bytes();
        // rlim_cur (8B) + rlim_max (8B) = 16B.
        let mut both = [0u8; 16];
        both[..8].copy_from_slice(&buf);
        both[8..].copy_from_slice(&buf);
        if env
            .backend
            .mem
            .write(polyisa_mem::VirtAddr(old_limit), &both)
            .is_err()
        {
            return Some(TrapOutcome::Unimplemented);
        }
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}
pub fn sys_setitimer(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // setitimer(which, new, old)。タイマーは動かさず、old があればゼロを書く。
    let old = get64(env, cx.r_c);
    if old != 0 {
        let zeros = [0u8; 32];
        if env.backend.mem.write(VirtAddr(old), &zeros).is_err() {
            return Some(TrapOutcome::Unimplemented);
        }
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}
pub fn sys_sysinfo(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // sysinfo(info)。メモリと稼働時間はゲストの固定値。free / uptime が読む。
    // 配置は UAPI の struct sysinfo（x86-64 で 112 バイト）。Ref: SRC-LINUX (7.3).
    let buf = get64(env, cx.r_a);
    if buf == 0 {
        set64(env, Gpr(0), cx.neg(EFAULT));
        return Some(TrapOutcome::Handled);
    }
    let mut out = [0u8; 112];
    // uptime = 3600 秒。
    out[0..8].copy_from_slice(&3600i64.to_le_bytes());
    // totalram = 1 GiB、freeram = 512 MiB、mem_unit = 1。
    out[32..40].copy_from_slice(&(1024u64 * 1024 * 1024).to_le_bytes());
    out[40..48].copy_from_slice(&(512u64 * 1024 * 1024).to_le_bytes());
    // procs = 1。
    out[80..82].copy_from_slice(&1u16.to_le_bytes());
    out[104..108].copy_from_slice(&1u32.to_le_bytes());
    if env.backend.mem.write(VirtAddr(buf), &out).is_err() {
        return Some(TrapOutcome::Unimplemented);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}
pub fn sys_syslog(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // syslog / klogctl。リングバッファは固定の 1 行。dmesg が読む。
    // type: 3=READ_ALL, 2=READ, 4=READ_CLEAR, 10=SIZE_BUFFER。Ref: SRC-LINUX (7.3).
    const MSG: &[u8] = b"[    0.000000] polyisa\n";
    let typ = get64(env, cx.r_a) as i32;
    let buf = get64(env, cx.r_b);
    let len = get64(env, cx.r_c) as i64;
    if typ == 10 {
        set64(env, Gpr(0), MSG.len() as u64);
        return Some(TrapOutcome::Handled);
    }
    if matches!(typ, 2..=4) {
        if len < 0 {
            set64(env, Gpr(0), cx.neg(EINVAL));
            return Some(TrapOutcome::Handled);
        }
        if buf == 0 {
            set64(env, Gpr(0), cx.neg(EFAULT));
            return Some(TrapOutcome::Handled);
        }
        let n = core::cmp::min(MSG.len(), len as usize);
        if env.backend.mem.write(VirtAddr(buf), &MSG[..n]).is_err() {
            return Some(TrapOutcome::Unimplemented);
        }
        set64(env, Gpr(0), n as u64);
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), cx.neg(EPERM));
    Some(TrapOutcome::Handled)
}
pub fn sys_time(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // time(tloc)。CLOCK_REALTIME と同じ固定値（2000-01-01 01:00:00 UTC）を返す.
    // 設計（ユーザーモード「時計と乱数」）のとおり既定は仮想時刻であり、
    // ホストの実時間は使わない。tloc!=NULL なら書き込む。
    let tloc = get64(env, cx.r_a);
    let secs = 946_688_400i64;
    if tloc != 0
        && env
            .backend
            .mem
            .write(VirtAddr(tloc), &secs.to_le_bytes())
            .is_err()
    {
        return Some(TrapOutcome::Unimplemented);
    }
    set64(env, Gpr(0), secs as u64);
    Some(TrapOutcome::Handled)
}
pub fn sys_uname(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // uname(buf)。struct utsname (65B x 6、domainname 含む) を固定値で埋めて 0 を返す.
    // Ref: SRC-LINUX (7.3).
    let buf = get64(env, cx.r_a);
    let fields: [&[u8]; 6] = [
        b"Linux",
        b"localhost",
        b"6.0.0",
        b"#1",
        b"x86_64",
        b"localdomain",
    ];
    let mut out = [0u8; 65 * 6];
    for (i, f) in fields.iter().enumerate() {
        let base = i * 65;
        out[base..base + f.len()].copy_from_slice(f);
    }
    if env.backend.mem.write(VirtAddr(buf), &out).is_err() {
        return Some(TrapOutcome::Unimplemented);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}
pub fn stat144(m: &std::fs::Metadata, ino: u64) -> [u8; 144] {
    let mut st = [0u8; 144];
    // S_IFDIR/S_IFREG/S_IFLNK。fifo 等の判別は可搬 API にないため、
    // ディレクトリでもシンボリックリンクでもなければ通常ファイルとみなす.
    // 許可ビットは所有者の読み書き実行を仮定する（試作）。
    const S_IFDIR: u32 = 0o040000;
    const S_IFREG: u32 = 0o100000;
    const S_IFLNK: u32 = 0o120000;
    let ft = m.file_type();
    let kind = if ft.is_dir() {
        S_IFDIR
    } else if ft.is_symlink() {
        S_IFLNK
    } else {
        S_IFREG
    };
    st[8..16].copy_from_slice(&ino.to_le_bytes());
    st[24..28].copy_from_slice(&(kind | 0o700).to_le_bytes());
    st[48..56].copy_from_slice(&(m.len() as i64).to_le_bytes());
    st
}

/// i386 の `struct stat64`（96B）。stat144 と同じ最小限の実値を入れる.
/// レイアウト: dev@0 ino@8 mode@16 nlink@20 uid@24 gid@28 rdev@32 pad@40
/// size@48 blksize@56 pad@60 blocks@64 atime@72/+4 mtime@80/+4 ctime@88/+4.
/// Ref: SRC-LINUX (7.3). arch/x86/include/uapi/asm/stat.h.
pub fn stat64(m: &std::fs::Metadata, ino: u64) -> [u8; 96] {
    let mut st = [0u8; 96];
    const S_IFDIR: u32 = 0o040000;
    const S_IFREG: u32 = 0o100000;
    const S_IFLNK: u32 = 0o120000;
    let ft = m.file_type();
    let kind = if ft.is_dir() {
        S_IFDIR
    } else if ft.is_symlink() {
        S_IFLNK
    } else {
        S_IFREG
    };
    st[8..16].copy_from_slice(&ino.to_le_bytes());
    st[16..20].copy_from_slice(&(kind | 0o700).to_le_bytes());
    st[48..56].copy_from_slice(&(m.len() as i64).to_le_bytes());
    st
}

/// ABI に合う struct stat バイト列を選ぶ。stat64/struct stat のみ対応.
pub fn stat_buf(m: &std::fs::Metadata, ino: u64, is64: bool) -> Vec<u8> {
    if is64 {
        stat144(m, ino).to_vec()
    } else {
        stat64(m, ino).to_vec()
    }
}

/// gettimeofday(tv, tz)。CLOCK_REALTIME と同じ固定値を返す.
/// i386 は {i32 sec, i32 usec} の8B、x86-64 は {i64,i64} の16B を書く.
/// Ref: SRC-LINUX (7.3).
pub fn sys_gettimeofday(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let tv = get64(env, cx.r_a);
    if tv != 0 {
        let secs = 946_688_400i64;
        let buf: Vec<u8> = if cx.is64 {
            let mut v = Vec::with_capacity(16);
            v.extend_from_slice(&secs.to_le_bytes());
            v.extend_from_slice(&0i64.to_le_bytes());
            v
        } else {
            let mut v = Vec::with_capacity(8);
            v.extend_from_slice(&(secs as i32).to_le_bytes());
            v.extend_from_slice(&0i32.to_le_bytes());
            v
        };
        if env.backend.mem.write(VirtAddr(tv), &buf).is_err() {
            return Some(TrapOutcome::Unimplemented);
        }
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

/// getcpu(cpu, node, tcache)。仮想 CPU 0・ノード 0 を書き込む。
/// tcache（第3引数）は未使用。Ref: SRC-LINUX (7.3)。
pub fn sys_getcpu(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    for p in [get64(env, cx.r_a), get64(env, cx.r_b)] {
        if p != 0
            && env
                .backend
                .mem
                .write(VirtAddr(p), &0u32.to_le_bytes())
                .is_err()
        {
            return Some(TrapOutcome::Unimplemented);
        }
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

/// vsyscall ページの配置先。実機は 0xffffffffff600000 台だが、
/// eip を 32 ビットで持つモデルでは下位番地に写像する。
pub const VSYSCALL_ADDR: u64 = 0xff60_0000;

/// x86-64 の vsyscall ページを写像する。gettimeofday(96)・
/// time(201)・getcpu(309) の各入口に `mov eax, nr; syscall; ret`
/// のスタブを置き、call で飛んできた呼び出しを OS パーソナリティへ
/// 回す（i386 の VSYS_ADDR スタブと同じ仕組み）。
/// x32 でも同じページが見えるので同様に写像してよい。
// Ref: SRC-LINUX arch/x86/entry/vsyscall/vsyscall_64.c。
pub fn map_vsyscall_page(mem: &mut polyisa_mem::AddressSpace) -> Result<(), polyisa_mem::MemError> {
    use polyisa_mem::Perms;
    mem.map(
        VirtAddr(VSYSCALL_ADDR),
        1,
        Perms(Perms::R.0 | Perms::W.0 | Perms::X.0),
    )?;
    for (off, nr) in [(0u64, 96u32), (0x400, 201), (0x800, 309)] {
        let mut stub = Vec::with_capacity(8);
        stub.push(0xB8); // mov eax, imm32
        stub.extend_from_slice(&nr.to_le_bytes());
        stub.extend_from_slice(&[0x0F, 0x05, 0xC3]); // syscall; ret
        mem.write(VirtAddr(VSYSCALL_ADDR + off), &stub)?;
    }
    Ok(())
}
pub fn path_ino(path: &str) -> u64 {
    let folded = fold_path(path);
    let mut h = 0xcbf29ce484222325u64;
    for b in folded.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h | 1
}
pub fn fold_path(path: &str) -> String {
    let abs = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            if parts.pop().is_none() && !abs {
                parts.push("..");
            }
            continue;
        }
        parts.push(part);
    }
    if abs {
        if parts.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", parts.join("/"))
        }
    } else if parts.is_empty() {
        ".".to_string()
    } else {
        parts.join("/")
    }
}
pub fn guest_exe_redirect(exe_path: &str, path: &str) -> Option<String> {
    if path == "/proc/self/exe" && !exe_path.is_empty() {
        return Some(exe_path.to_string());
    }
    None
}
pub fn sys_stat(
    root: &str,
    cwd: &str,
    exe_path: &str,
    env: &mut BareEnv,
    cx: &SysCtx,
) -> Option<TrapOutcome> {
    // stat(path, statbuf)。作業ディレクトリから辿り、struct stat (144B) を書く.
    // シンボリックリンクは辿る。Ref: SRC-LINUX (7.3).
    let path_addr = get64(env, cx.r_a);
    let stat_addr = get64(env, cx.r_b);
    let path = match guest_c_string(env, path_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    let Some(path) = resolve_guest_path(root, cwd, &path) else {
        set64(env, Gpr(0), cx.neg(EPERM));
        return Some(TrapOutcome::Handled);
    };
    let path = guest_exe_redirect(exe_path, &path).unwrap_or(path);
    let m = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(e) => {
            let no = match e.kind() {
                std::io::ErrorKind::NotFound => ENOENT,
                std::io::ErrorKind::PermissionDenied => EACCES,
                _ => EINVAL,
            };
            set64(env, Gpr(0), cx.neg(no));
            return Some(TrapOutcome::Handled);
        }
    };
    let st = stat_buf(&m, path_ino(&path), cx.is64);
    if env.backend.mem.write(VirtAddr(stat_addr), &st).is_err() {
        return Some(TrapOutcome::Unimplemented);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}
pub fn sys_lstat(
    root: &str,
    cwd: &str,
    exe_path: &str,
    env: &mut BareEnv,
    cx: &SysCtx,
) -> Option<TrapOutcome> {
    // lstat(path, statbuf)。リンク自体の struct stat (144B) を書く.
    // Ref: SRC-LINUX (7.3).
    let path_addr = get64(env, cx.r_a);
    let stat_addr = get64(env, cx.r_b);
    let path = match guest_c_string(env, path_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    let Some(path) = resolve_guest_path(root, cwd, &path) else {
        set64(env, Gpr(0), cx.neg(EPERM));
        return Some(TrapOutcome::Handled);
    };
    let path = guest_exe_redirect(exe_path, &path).unwrap_or(path);
    let m = match std::fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) => {
            let no = match e.kind() {
                std::io::ErrorKind::NotFound => ENOENT,
                std::io::ErrorKind::PermissionDenied => EACCES,
                _ => EINVAL,
            };
            set64(env, Gpr(0), cx.neg(no));
            return Some(TrapOutcome::Handled);
        }
    };
    let st = stat_buf(&m, path_ino(&path), cx.is64);
    if env.backend.mem.write(VirtAddr(stat_addr), &st).is_err() {
        return Some(TrapOutcome::Unimplemented);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

/// newfstatat(dirfd, path, statbuf, flags)。AT_FDCWD+絶対パスのみ.
/// ホスト metadata から ABI 幅の struct stat を書いて 0 を返す.
/// flags (AT_SYMLINK_NOFOLLOW 等) は無視してたどる.
/// Ref: SRC-LINUX (7.3).
pub fn sys_newfstatat(
    root: &str,
    cwd: &str,
    exe_path: &str,
    env: &mut BareEnv,
    cx: &SysCtx,
) -> Option<TrapOutcome> {
    let dirfd = get64(env, cx.r_a);
    let path_addr = get64(env, cx.r_b);
    let stat_addr = get64(env, cx.r_c);
    if !cx.is_at_fdcwd(dirfd) {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let path = match guest_c_string(env, path_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    if !path.starts_with('/') {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let path = match resolve_guest_path(root, cwd, &path) {
        Some(p) => guest_exe_redirect(exe_path, &p).unwrap_or(p),
        None => {
            set64(env, Gpr(0), cx.neg(EPERM));
            return Some(TrapOutcome::Handled);
        }
    };
    let m = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(e) => {
            let no = match e.kind() {
                std::io::ErrorKind::NotFound => ENOENT,
                std::io::ErrorKind::PermissionDenied => EACCES,
                _ => EINVAL,
            };
            set64(env, Gpr(0), cx.neg(no));
            return Some(TrapOutcome::Handled);
        }
    };
    let st = stat_buf(&m, path_ino(&path), cx.is64);
    if env.backend.mem.write(VirtAddr(stat_addr), &st).is_err() {
        return Some(TrapOutcome::Unimplemented);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}
pub fn sys_mount(root: &str, cwd: &str, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // mount(source, target, ...)。実マウントはせず、無い道は ENOENT、有る道は EPERM。
    let src_addr = get64(env, cx.r_a);
    let tgt_addr = get64(env, cx.r_b);
    let src = match guest_c_string(env, src_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    let tgt = match guest_c_string(env, tgt_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    let Some(src_host) = resolve_guest_path(root, cwd, &src) else {
        set64(env, Gpr(0), cx.neg(EPERM));
        return Some(TrapOutcome::Handled);
    };
    let Some(tgt_host) = resolve_guest_path(root, cwd, &tgt) else {
        set64(env, Gpr(0), cx.neg(EPERM));
        return Some(TrapOutcome::Handled);
    };
    let err =
        if std::path::Path::new(&src_host).exists() && std::path::Path::new(&tgt_host).exists() {
            EPERM
        } else {
            ENOENT
        };
    set64(env, Gpr(0), cx.neg(err));
    Some(TrapOutcome::Handled)
}
pub fn sys_umount2(root: &str, cwd: &str, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // umount2(target, flags)。実アンマウントはせず、無い道は ENOENT、有る道は EPERM。
    let addr = get64(env, cx.r_a);
    let path = match guest_c_string(env, addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    let Some(host) = resolve_guest_path(root, cwd, &path) else {
        set64(env, Gpr(0), cx.neg(EPERM));
        return Some(TrapOutcome::Handled);
    };
    let err = if std::path::Path::new(&host).exists() {
        EPERM
    } else {
        ENOENT
    };
    set64(env, Gpr(0), cx.neg(err));
    Some(TrapOutcome::Handled)
}
pub fn sys_setxattr(root: &str, cwd: &str, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // setxattr(path, ...)。属性は付けず、無い道は ENOENT、有る道は EPERM。
    let addr = get64(env, cx.r_a);
    let path = match guest_c_string(env, addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    let Some(host) = resolve_guest_path(root, cwd, &path) else {
        set64(env, Gpr(0), cx.neg(EPERM));
        return Some(TrapOutcome::Handled);
    };
    let err = if std::path::Path::new(&host).exists() {
        EPERM
    } else {
        ENOENT
    };
    set64(env, Gpr(0), cx.neg(err));
    Some(TrapOutcome::Handled)
}
pub fn sys_chdir(
    root: &str,
    cwd: &mut String,
    env: &mut BareEnv,
    cx: &SysCtx,
) -> Option<TrapOutcome> {
    let path_addr = get64(env, cx.r_a);
    let Some(path) = guest_c_string(env, path_addr) else {
        return Some(TrapOutcome::Unimplemented);
    };
    if path.is_empty() {
        set64(env, Gpr(0), cx.neg(ENOENT));
        return Some(TrapOutcome::Handled);
    }
    let Some(host) = resolve_guest_path(root, cwd, &path) else {
        set64(env, Gpr(0), cx.neg(EPERM));
        return Some(TrapOutcome::Handled);
    };
    let errno = match std::fs::metadata(&host) {
        Ok(meta) if meta.is_dir() => {
            cwd.clear();
            cwd.push_str(&host);
            set64(env, Gpr(0), 0);
            return Some(TrapOutcome::Handled);
        }
        Ok(_) => ENOTDIR,
        Err(err) => match err.kind() {
            std::io::ErrorKind::NotFound => ENOENT,
            std::io::ErrorKind::PermissionDenied => EACCES,
            _ => ENOENT,
        },
    };
    set64(env, Gpr(0), cx.neg(errno));
    Some(TrapOutcome::Handled)
}
pub fn sys_getcwd(cwd: &str, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // getcwd(buf, size)。プロセスの作業ディレクトリを返し、NUL 込み長さを返す.
    let buf = get64(env, cx.r_a);
    let size = get64(env, cx.r_b);
    if buf == 0 || size == 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let bytes = cwd.as_bytes();
    let need = (bytes.len() as u64) + 1;
    if size < need {
        set64(env, Gpr(0), cx.neg(ERANGE));
        return Some(TrapOutcome::Handled);
    }
    if env
        .backend
        .mem
        .write(polyisa_mem::VirtAddr(buf), bytes)
        .is_err()
    {
        return Some(TrapOutcome::Unimplemented);
    }
    if env
        .backend
        .mem
        .write(polyisa_mem::VirtAddr(buf + bytes.len() as u64), &[0u8])
        .is_err()
    {
        return Some(TrapOutcome::Unimplemented);
    }
    set64(env, Gpr(0), need);
    Some(TrapOutcome::Handled)
}
pub fn sys_umask(umask: &mut u32, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // umask(mask)。旧マスクを返して更新する。mkdir -p の保存・復元で使う.
    // ホストの umask は触らない.
    let mask = get64(env, cx.r_a) as u32 & 0o777;
    let old = *umask;
    *umask = mask;
    set64(env, Gpr(0), u64::from(old));
    Some(TrapOutcome::Handled)
}
pub fn sys_personality(state: &mut u64, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // personality(persona)。0xffffffff は現在値を返すだけ。実行形式は変えない。
    // Ref: SRC-LINUX (7.3).
    let persona = get64(env, cx.r_a);
    let old = *state;
    if persona != 0xffff_ffff && persona != u64::MAX {
        *state = persona;
    }
    set64(env, Gpr(0), old);
    Some(TrapOutcome::Handled)
}

/// 入出力優先度の保持値。未設定時は best-effort 4 を返す。
#[derive(Clone, Copy, Debug, Default)]
pub struct IoPriority {
    pub prio: u32,
    pub known: bool,
}

pub fn ioprio_ok(prio: u64) -> bool {
    if prio > 0xffff {
        return false;
    }
    let class = prio >> 13;
    let data = prio & 0x1fff;
    match class {
        0 => data == 0,
        1 | 2 => data <= 7,
        3 => true,
        _ => false,
    }
}

pub fn ioprio_target_ok(which: u64, who: i64, me: u64) -> Result<(), u32> {
    if !(1..=3).contains(&which) {
        return Err(EINVAL);
    }
    let me = me as i64;
    if which == 1 && who != 0 && who != me {
        return Err(ESRCH);
    }
    if which != 1 && who != 0 {
        return Err(ESRCH);
    }
    Ok(())
}

/// ioprio_set(which, who, ioprio)。入出力の優先度は変えず、範囲だけ確かめる。
/// Ref: SRC-LINUX (7.3).
pub fn sys_ioprio_set(
    io: &mut IoPriority,
    me: u64,
    env: &mut BareEnv,
    cx: &SysCtx,
) -> Option<TrapOutcome> {
    let which = get64(env, cx.r_a);
    let who = get64(env, cx.r_b) as i64;
    let prio = get64(env, cx.r_c);
    if let Err(err) = ioprio_target_ok(which, who, me) {
        set64(env, Gpr(0), cx.neg(err));
        return Some(TrapOutcome::Handled);
    }
    if !ioprio_ok(prio) {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    io.prio = prio as u32;
    io.known = true;
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

/// ioprio_get(which, who)。未設定なら best-effort の 4。
pub fn sys_ioprio_get(
    io: &IoPriority,
    me: u64,
    env: &mut BareEnv,
    cx: &SysCtx,
) -> Option<TrapOutcome> {
    let which = get64(env, cx.r_a);
    let who = get64(env, cx.r_b) as i64;
    if let Err(err) = ioprio_target_ok(which, who, me) {
        set64(env, Gpr(0), cx.neg(err));
        return Some(TrapOutcome::Handled);
    }
    let prio = if io.known {
        u64::from(io.prio)
    } else {
        (2 << 13) | 4
    };
    set64(env, Gpr(0), prio);
    Some(TrapOutcome::Handled)
}
pub fn read_sched_priority(env: &mut BareEnv, addr: u64) -> Option<i32> {
    if addr == 0 {
        return None;
    }
    let mut buf = [0u8; 4];
    if env
        .backend
        .mem
        .read(polyisa_mem::VirtAddr(addr), &mut buf, data_access())
        .is_err()
    {
        return None;
    }
    Some(i32::from_le_bytes(buf))
}
pub fn sys_arch_prctl(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // arch_prctl (x86-64 のみ)。TLS の FS ベース設定を受け付ける。
    // FS ベースは CPU 状態（`CpuState::fs_base`）に置く。
    // Ref: SRC-LINUX (7.3) arch/x86/include/uapi/asm/prctl.h.
    const ARCH_SET_FS: u64 = 0x1002;
    const ARCH_GET_FS: u64 = 0x1003;
    let op = get64(env, cx.r_a);
    if op == ARCH_SET_FS {
        let base = get64(env, cx.r_b);
        env.backend.set(polyisa_guest_x86::sem::fs_base_ref(), base);
        set64(env, Gpr(0), 0);
        return Some(TrapOutcome::Handled);
    }
    if op == ARCH_GET_FS {
        let base = env.backend.get(polyisa_guest_x86::sem::fs_base_ref());
        let dst = get64(env, cx.r_b);
        let buf = base.to_le_bytes();
        if env
            .backend
            .mem
            .write(polyisa_mem::VirtAddr(dst), &buf)
            .is_err()
        {
            return Some(TrapOutcome::Unimplemented);
        }
        set64(env, Gpr(0), 0);
        return Some(TrapOutcome::Handled);
    }
    // XCOMP 系（AMX 等の動的拡張状態の許可）。対応マスクと
    // 許可マスクは CpuState の `xcomp_supp`/`xcomp_perm` にある。
    // Ref: SRC-LINUX (7.3) arch/x86/kernel/fpu/xstate.c.
    const ARCH_GET_XCOMP_PERM: u64 = 0x1021;
    const ARCH_REQ_XCOMP_PERM: u64 = 0x1022;
    const ARCH_GET_XCOMP_SUPP: u64 = 0x1031;
    /// 動的に許可が要る成分の先頭（XTILECFG 以降）。これより
    /// 小さい成分は静的で、要求なしに使える。
    const XFEATURE_FIRST_DYNAMIC: u64 = 16;
    /// 成分番号の上限（XFEATURE_MAX）。
    const XFEATURE_MAX: u64 = 18;
    const XFEATURE_XTILECFG: u64 = 17;
    const XFEATURE_XTILEDATA: u64 = 18;
    if op == ARCH_GET_XCOMP_SUPP || op == ARCH_GET_XCOMP_PERM {
        let which = if op == ARCH_GET_XCOMP_SUPP {
            polyisa_guest_x86::sem::xcomp_supp_ref()
        } else {
            polyisa_guest_x86::sem::xcomp_perm_ref()
        };
        let v = env.backend.get(which);
        let dst = get64(env, cx.r_b);
        if env
            .backend
            .mem
            .write(polyisa_mem::VirtAddr(dst), &v.to_le_bytes())
            .is_err()
        {
            set64(env, Gpr(0), cx.neg(EFAULT));
            return Some(TrapOutcome::Handled);
        }
        set64(env, Gpr(0), 0);
        return Some(TrapOutcome::Handled);
    }
    if op == ARCH_REQ_XCOMP_PERM {
        let feature = get64(env, cx.r_b);
        let supp = env.backend.get(polyisa_guest_x86::sem::xcomp_supp_ref());
        let perm = env.backend.get(polyisa_guest_x86::sem::xcomp_perm_ref());
        // Linux の規約: 番号が上限超なら EINVAL、対応外の成分は
        // EOPNOTSUPP。XTILEDATA の要求は先に XTILECFG の許可が要る。
        if feature > XFEATURE_MAX {
            set64(env, Gpr(0), cx.neg(EINVAL));
            return Some(TrapOutcome::Handled);
        }
        let bit = 1u64 << feature;
        if bit & supp == 0 {
            set64(env, Gpr(0), cx.neg(EOPNOTSUPP));
            return Some(TrapOutcome::Handled);
        }
        if feature == XFEATURE_XTILEDATA && perm & (1 << XFEATURE_XTILECFG) == 0 {
            set64(env, Gpr(0), cx.neg(EINVAL));
            return Some(TrapOutcome::Handled);
        }
        env.backend
            .set(polyisa_guest_x86::sem::xcomp_perm_ref(), perm | bit);
        // 動的成分の許可は XCR0 にも反映される（実機では XSAVE
        // 領域が広がる）。成分の保存実装がない bit は名前だけの追跡。
        if feature >= XFEATURE_FIRST_DYNAMIC {
            let xcr0 = env.backend.get(polyisa_guest_x86::sem::xcr0_ref());
            // XTILEDATA の許可はカーネルと同じく XTILECFG にも波及
            // させる（bit18 の要求で bit17|18 が両方立つ）。
            let set = if bit == (1 << XFEATURE_XTILEDATA) {
                bit | (1 << XFEATURE_XTILECFG)
            } else {
                bit
            };
            env.backend
                .set(polyisa_guest_x86::sem::xcr0_ref(), xcr0 | set);
        }
        set64(env, Gpr(0), 0);
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), cx.neg(EINVAL));
    Some(TrapOutcome::Handled)
}
pub fn sys_rseq(rseq_addr: &mut u64, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // rseq 領域を記録して 0 を返す。署名検証はしない.
    // rseq_len は 32 (struct rseq) のはずであり、異なる場合は EINVAL.
    // flags は 0 のみ受け付ける.
    const RSEQ_LEN: u64 = 32;
    if get64(env, cx.r_b) != RSEQ_LEN || get64(env, cx.r_c) != 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    *rseq_addr = get64(env, cx.r_a);
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}
pub fn sys_set_robust_list(
    robust_head: &mut u64,
    env: &mut BareEnv,
    cx: &SysCtx,
) -> Option<TrapOutcome> {
    // robust futex リスト先頭を記録して 0 を返す。
    // 長さは struct robust_list_head のはずで、x86-64 は 24 バイト、
    // x86-32・x32（compat）は 12 バイト。異なる場合は EINVAL.
    let want = if cx.is64 && !cx.x32 { 24 } else { 12 };
    if get64(env, cx.r_b) != want {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    *robust_head = get64(env, cx.r_a);
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}
pub fn sys_sched_getparam(me: u64, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let pid = get64(env, cx.r_a);
    let param = get64(env, cx.r_b);
    if pid != 0 && pid != me {
        set64(env, Gpr(0), cx.neg(ESRCH));
        return Some(TrapOutcome::Handled);
    }
    if env
        .backend
        .mem
        .write(polyisa_mem::VirtAddr(param), &0i32.to_le_bytes())
        .is_err()
    {
        set64(env, Gpr(0), cx.neg(EFAULT));
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}
pub fn sys_sched_setparam(me: u64, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // sched_setparam(pid, param)。現方針 OTHER の優先度 0 だけ受理する。
    let pid = get64(env, cx.r_a);
    let param = get64(env, cx.r_b);
    if pid != 0 && pid != me {
        set64(env, Gpr(0), cx.neg(ESRCH));
        return Some(TrapOutcome::Handled);
    }
    let Some(prio) = read_sched_priority(env, param) else {
        set64(env, Gpr(0), cx.neg(EFAULT));
        return Some(TrapOutcome::Handled);
    };
    if prio != 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}
pub fn sys_sched_getscheduler(me: u64, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // いまの方針は SCHED_OTHER。pid 0 は自分。
    let pid = get64(env, cx.r_a);
    if pid != 0 && pid != me {
        set64(env, Gpr(0), cx.neg(ESRCH));
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}
pub fn sys_sched_setscheduler(me: u64, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // sched_setscheduler(pid, policy, param)。方針は変えず、範囲だけ確かめて 0 を返す。
    let pid = get64(env, cx.r_a);
    let policy = get64(env, cx.r_b);
    let param = get64(env, cx.r_c);
    if pid != 0 && pid != me {
        set64(env, Gpr(0), cx.neg(ESRCH));
        return Some(TrapOutcome::Handled);
    }
    let Some((min, max)) = sched_priority_bounds(policy) else {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    };
    let Some(prio) = read_sched_priority(env, param) else {
        set64(env, Gpr(0), cx.neg(EFAULT));
        return Some(TrapOutcome::Handled);
    };
    if prio < min || prio > max {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}
pub fn guest_readlink_target(
    root: &str,
    cwd: &str,
    exe_path: &str,
    fds: &FdTable,
    std_paths: &[Option<String>; 3],
    path: &str,
) -> Result<String, u32> {
    // /proc/self/exe はゲスト実行ファイルのホストパスへ読み替える。
    if path == "/proc/self/exe" && !exe_path.is_empty() {
        return Ok(exe_path.to_string());
    }
    // musl の realpath は開いた fd を /proc/self/fd/N の readlink で読む。
    // ホストの同じ番号は別物なので、開いたときに覚えたパスを返す。
    // 標準 fd は付け替え先のパスを見る。
    if let Some(rest) = path.strip_prefix("/proc/self/fd/")
        && !rest.is_empty()
        && rest.bytes().all(|b| b.is_ascii_digit())
        && let Ok(fd) = rest.parse::<u32>()
    {
        let found = if fd < 3 {
            std_paths.get(fd as usize).and_then(|p| p.as_deref())
        } else {
            fds.path_of(fd)
        };
        return match found {
            Some(p) => Ok(p.to_string()),
            None => Err(ENOENT),
        };
    }
    // それ以外のパスはゲストルート配下で解決する。はみ出しは EPERM。
    let path = match resolve_guest_path(root, cwd, path) {
        Some(p) => p,
        None => return Err(EPERM),
    };
    match std::fs::read_link(&path) {
        Ok(p) => Ok(p.into_os_string().into_string().unwrap_or_default()),
        Err(e) => Err(match e.kind() {
            std::io::ErrorKind::NotFound => ENOENT,
            std::io::ErrorKind::PermissionDenied => EACCES,
            _ => EINVAL,
        }),
    }
}
pub fn sys_readlink(
    root: &str,
    cwd: &str,
    exe_path: &str,
    fds: &FdTable,
    std_paths: &[Option<String>; 3],
    env: &mut BareEnv,
    cx: &SysCtx,
) -> Option<TrapOutcome> {
    // readlink(pathname, buf, bufsiz)。readlinkat から dirfd 検証を除いた形.
    let (path_addr, buf, bufsiz) = if cx.is64 {
        (get64(env, Gpr(7)), get64(env, Gpr(6)), get64(env, Gpr(2)))
    } else {
        (
            u64::from(env.backend.get(Gpr(3).state())),
            u64::from(env.backend.get(Gpr(1).state())),
            u64::from(env.backend.get(Gpr(2).state())),
        )
    };
    if bufsiz == 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let path = match guest_c_string(env, path_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    const MAX_READLINK: u64 = 4096;
    if bufsiz > MAX_READLINK {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let target = match guest_readlink_target(root, cwd, exe_path, fds, std_paths, &path) {
        Ok(p) => p,
        Err(no) => {
            set64(env, Gpr(0), cx.neg(no));
            return Some(TrapOutcome::Handled);
        }
    };
    let bytes = target.as_bytes();
    let take = (bytes.len() as u64).min(bufsiz) as usize;
    if env
        .backend
        .mem
        .write(polyisa_mem::VirtAddr(buf), &bytes[..take])
        .is_err()
    {
        return Some(TrapOutcome::Unimplemented);
    }
    set64(env, Gpr(0), take as u64);
    Some(TrapOutcome::Handled)
}
pub fn sys_readlinkat(
    root: &str,
    cwd: &str,
    exe_path: &str,
    fds: &FdTable,
    std_paths: &[Option<String>; 3],
    env: &mut BareEnv,
    cx: &SysCtx,
) -> Option<TrapOutcome> {
    // readlinkat(dirfd, pathname, buf, bufsiz)。AT_FDCWD+絶対パスのみ.
    // ホストの read_link に直結し、切詰めて返す（NUL 終端なし）。
    let (dirfd, path_addr, buf, bufsiz) = if cx.is64 {
        (
            get64(env, Gpr(7)),
            get64(env, Gpr(6)),
            get64(env, Gpr(2)),
            get64(env, Gpr(10)),
        )
    } else {
        (
            u64::from(env.backend.get(Gpr(3).state())),
            u64::from(env.backend.get(Gpr(1).state())),
            u64::from(env.backend.get(Gpr(2).state())),
            u64::from(env.backend.get(Gpr(6).state())),
        )
    };
    if !cx.is_at_fdcwd(dirfd) {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    if bufsiz == 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let path = match guest_c_string(env, path_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    if !path.starts_with('/') {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    // 拡張しすぎは失敗扱い.
    const MAX_READLINK: u64 = 4096;
    if bufsiz > MAX_READLINK {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    // /proc/self/exe はゲスト実行ファイル自身を返す (ホスト exe ではない).
    // 空の exe_path (単体テスト) ではホストに直結する.
    let target = match guest_readlink_target(root, cwd, exe_path, fds, std_paths, &path) {
        Ok(p) => p,
        Err(no) => {
            set64(env, Gpr(0), cx.neg(no));
            return Some(TrapOutcome::Handled);
        }
    };
    let bytes = target.as_bytes();
    let take = (bytes.len() as u64).min(bufsiz) as usize;
    if env
        .backend
        .mem
        .write(polyisa_mem::VirtAddr(buf), &bytes[..take])
        .is_err()
    {
        return Some(TrapOutcome::Unimplemented);
    }
    set64(env, Gpr(0), take as u64);
    Some(TrapOutcome::Handled)
}
pub fn sys_unlinkat(
    root: &str,
    cwd: &str,
    fds: &FdTable,
    std_paths: &[Option<String>; 3],
    env: &mut BareEnv,
    cx: &SysCtx,
) -> Option<TrapOutcome> {
    // unlinkat(dirfd, path, flags)。flags は 0/AT_REMOVEDIR(0x200)。
    // AT_FDCWD は作業ディレクトリ、開いたディレクトリは覚えたパスから外す。
    let (dirfd, path_addr, flags) = if cx.is64 {
        (get64(env, Gpr(7)), get64(env, Gpr(6)), get64(env, Gpr(2)))
    } else {
        (
            u64::from(env.backend.get(Gpr(3).state())),
            u64::from(env.backend.get(Gpr(1).state())),
            u64::from(env.backend.get(Gpr(2).state())),
        )
    };
    if flags & !0x200 != 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let path = match guest_c_string(env, path_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    let base = if cx.is_at_fdcwd(dirfd) {
        cwd.to_string()
    } else if dirfd < 3 {
        match std_paths.get(dirfd as usize).and_then(|p| p.as_ref()) {
            Some(p) => p.clone(),
            None => {
                set64(env, Gpr(0), cx.neg(EBADF));
                return Some(TrapOutcome::Handled);
            }
        }
    } else {
        match fds.path_of(dirfd as u32) {
            Some(p) => p.to_string(),
            None => {
                set64(env, Gpr(0), cx.neg(EBADF));
                return Some(TrapOutcome::Handled);
            }
        }
    };
    let Some(path) = resolve_guest_path(root, &base, &path) else {
        set64(env, Gpr(0), cx.neg(EPERM));
        return Some(TrapOutcome::Handled);
    };
    let res = if flags & 0x200 != 0 {
        std::fs::remove_dir(&path)
    } else {
        std::fs::remove_file(&path)
    };
    Some(match res {
        Ok(()) => {
            set64(env, Gpr(0), 0);
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
    })
}
pub fn host_affinity_mask() -> Vec<u8> {
    let fallback = vec![1, 0, 0, 0, 0, 0, 0, 0];
    let Ok(text) = std::fs::read_to_string("/proc/self/status") else {
        return fallback;
    };
    let Some(line) = text
        .lines()
        .find(|l| l.starts_with("Cpus_allowed:") && !l.starts_with("Cpus_allowed_list:"))
    else {
        return fallback;
    };
    let rest = line.split_once(':').map(|(_, r)| r.trim()).unwrap_or("");
    let groups: Vec<&str> = rest
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if groups.is_empty() {
        return fallback;
    }
    let mut bytes = Vec::new();
    let mut bit_at = 0u32;
    for (from_low, group) in groups.iter().rev().enumerate() {
        let Ok(val) = u32::from_str_radix(group, 16) else {
            return fallback;
        };
        let width = if from_low + 1 < groups.len() {
            32
        } else {
            group.len().saturating_mul(4).max(1) as u32
        };
        for b in 0..width {
            if (val >> b) & 1 == 1 {
                let idx = bit_at + b;
                let byte = (idx / 8) as usize;
                if bytes.len() <= byte {
                    bytes.resize(byte + 1, 0);
                }
                bytes[byte] |= 1 << (idx % 8);
            }
        }
        bit_at += width;
    }
    if bytes.is_empty() {
        return fallback;
    }
    while bytes.len() % 8 != 0 {
        bytes.push(0);
    }
    bytes
}
pub fn sys_getpid(me: u64, env: &mut BareEnv, _cx: &SysCtx) -> Option<TrapOutcome> {
    set64(env, Gpr(0), me);
    Some(TrapOutcome::Handled)
}
pub fn sys_gettid(me: u64, env: &mut BareEnv, _cx: &SysCtx) -> Option<TrapOutcome> {
    // 単一スレッドなので tid は pid と同じ値である。
    set64(env, Gpr(0), me);
    Some(TrapOutcome::Handled)
}
pub fn sys_set_tid_address(me: u64, env: &mut BareEnv, _cx: &SysCtx) -> Option<TrapOutcome> {
    // 本物は clear_child_tid を記録し終了時に書き込む。試作は識別子の返却だけを行う。
    // 単一スレッドなので tid は pid と同じ値である。
    set64(env, Gpr(0), me);
    Some(TrapOutcome::Handled)
}
pub fn sys_getppid(
    procs: &ProcessTable,
    me: u64,
    env: &mut BareEnv,
    _cx: &SysCtx,
) -> Option<TrapOutcome> {
    // 根は親がいないので 0。fork 後の子は親の識別子を返す。
    let ppid = procs.parent_of(ProcessId(me)).map(|id| id.0).unwrap_or(0);
    set64(env, Gpr(0), ppid);
    Some(TrapOutcome::Handled)
}
pub fn sys_getpgid(
    procs: &ProcessTable,
    me: u64,
    env: &mut BareEnv,
    cx: &SysCtx,
) -> Option<TrapOutcome> {
    let pid = get64(env, cx.r_a) as i64;
    if pid < 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let target = ProcessId(if pid == 0 { me } else { pid as u64 });
    match procs.pgid(target) {
        Some(pgid) => set64(env, Gpr(0), pgid),
        None => set64(env, Gpr(0), cx.neg(ESRCH)),
    }
    Some(TrapOutcome::Handled)
}
pub fn sys_setpgid(
    procs: &mut ProcessTable,
    me: u64,
    env: &mut BareEnv,
    cx: &SysCtx,
) -> Option<TrapOutcome> {
    let pid = get64(env, cx.r_a) as i64;
    let pgid = get64(env, cx.r_b) as i64;
    if pid < 0 || pgid < 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let target = ProcessId(if pid == 0 { me } else { pid as u64 });
    let group = if pgid == 0 { target.0 } else { pgid as u64 };
    if procs.pgid(target).is_none() {
        set64(env, Gpr(0), cx.neg(ESRCH));
        return Some(TrapOutcome::Handled);
    }
    if !procs.owns(ProcessId(me), target) {
        set64(env, Gpr(0), cx.neg(EPERM));
        return Some(TrapOutcome::Handled);
    }
    procs.set_pgid(target, group);
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}
pub fn sys_setsid(
    procs: &mut ProcessTable,
    me: u64,
    env: &mut BareEnv,
    _cx: &SysCtx,
) -> Option<TrapOutcome> {
    // setsid()。自分をプロセスグループの先頭にし、その番号を返す。
    // setsid echo が先にこれを呼ぶ。Ref: SRC-LINUX (7.3).
    let _ = procs.set_pgid(ProcessId(me), me);
    set64(env, Gpr(0), me);
    Some(TrapOutcome::Handled)
}
pub fn sys_sched_setaffinity(me: u64, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // sched_setaffinity(pid, len, mask)。空集合と、ホストに無い CPU は EINVAL。
    // CPU は実際には固定しない。taskset が続けて exec できるように 0 を返す。
    // Ref: SRC-LINUX (7.3).
    let pid = get64(env, cx.r_a);
    let len = get64(env, cx.r_b);
    let mask = get64(env, cx.r_c);
    if pid != 0 && pid != me {
        set64(env, Gpr(0), cx.neg(ESRCH));
        return Some(TrapOutcome::Handled);
    }
    const MAX_MASK: u64 = 65536;
    if len == 0 || !len.is_multiple_of(8) || len > MAX_MASK || mask == 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let mut buf = vec![0u8; len as usize];
    if env
        .backend
        .mem
        .read(polyisa_mem::VirtAddr(mask), &mut buf, data_access())
        .is_err()
    {
        set64(env, Gpr(0), cx.neg(EFAULT));
        return Some(TrapOutcome::Handled);
    }
    let host = host_affinity_mask();
    let mut any = false;
    for (i, byte) in buf.iter().enumerate() {
        if *byte == 0 {
            continue;
        }
        any = true;
        let allowed = host.get(i).copied().unwrap_or(0);
        if byte & !allowed != 0 {
            set64(env, Gpr(0), cx.neg(EINVAL));
            return Some(TrapOutcome::Handled);
        }
    }
    if !any {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}
pub fn sys_sched_getaffinity(me: u64, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // sched_getaffinity(pid, cpusetsize, mask)。
    // 生の戻り値はコピーしたバイト数。musl は残りを 0 にして利用者へは 0 を返す。
    // 0 を返すとマスク全体が消えるので、バイト数を返す。nproc がビットを数える。
    // Ref: SRC-LINUX (7.3).
    let pid = get64(env, cx.r_a);
    let len = get64(env, cx.r_b);
    let mask = get64(env, cx.r_c);
    if pid != 0 && pid != me {
        set64(env, Gpr(0), cx.neg(ESRCH));
        return Some(TrapOutcome::Handled);
    }
    // nproc は 0x2000 バイトを渡す。それより大きい要求は受けない。
    const MAX_MASK: u64 = 65536;
    if len == 0 || !len.is_multiple_of(8) || len > MAX_MASK || mask == 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let affinity = host_affinity_mask();
    let highest = affinity.iter().rposition(|b| *b != 0).unwrap_or(0) as u64;
    if highest >= len {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    // 戻り値はカーネルと同じくマスクのバイト数。バッファの残りは 0 にする。
    // 呼び出し側が戻り値を見ずに len バイトを数えるため。
    let ret = (affinity.len() as u64).min(len);
    let mut buf = vec![0u8; len as usize];
    let n = affinity.len().min(len as usize);
    buf[..n].copy_from_slice(&affinity[..n]);
    if env.backend.mem.write(VirtAddr(mask), &buf).is_err() {
        return Some(TrapOutcome::Unimplemented);
    }
    set64(env, Gpr(0), ret);
    Some(TrapOutcome::Handled)
}

/// clock_gettime 相当の時刻取得。MONOTONIC の起点は呼び出し側が保持する.
pub fn sys_clock_gettime(
    mono: &mut Option<std::time::Instant>,
    env: &mut BareEnv,
    cx: &SysCtx,
) -> Option<TrapOutcome> {
    // clock_gettime(clk_id, tp)。
    // REALTIME は uptime の表示を安定させるため 2000-01-01 01:00:00 UTC 固定。
    // MONOTONIC は起動からの経過で進め、時刻待ちループが止まらないようにする.
    let clk = get64(env, cx.r_a);
    let tp = get64(env, cx.r_b);
    if tp != 0 {
        let (sec, nsec) = if clk == 0 {
            // CLOCK_REALTIME
            (946_688_400i64, 0i64)
        } else {
            // CLOCK_MONOTONIC ほか。ゲスト実行の起点からの経過。
            let start = *mono.get_or_insert_with(std::time::Instant::now);
            let elapsed = start.elapsed();
            (elapsed.as_secs() as i64, elapsed.subsec_nanos() as i64)
        };
        let mut both = [0u8; 16];
        both[..8].copy_from_slice(&sec.to_le_bytes());
        both[8..].copy_from_slice(&nsec.to_le_bytes());
        if env.backend.mem.write(VirtAddr(tp), &both).is_err() {
            return Some(TrapOutcome::Unimplemented);
        }
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

/// fstat(fd, struct stat *)。x86-64 struct stat (144B) を書く.
/// レイアウトは musl/glibc 共通のカーネル ABI 由来である.
/// ホスト依存の詳細は std の可搬 API だけでは取れないため、
/// 種別 (st_mode) と大きさ (st_size) のみ実値を入れ、残りは 0 とする.
/// Ref: SRC-LINUX (7.3).
pub fn sys_fstat(
    fds: &FdTable,
    std: Option<&std::fs::File>,
    std_paths: &[Option<String>; 3],
    env: &mut BareEnv,
    cx: &SysCtx,
) -> Option<TrapOutcome> {
    let fd = get64(env, cx.r_a) as u32;
    let stat_addr = get64(env, cx.r_b);
    let meta: std::io::Result<std::fs::Metadata> = if fd < 3 {
        // 付け替えた標準 fd はファイルのメタデータを返す。
        match std {
            Some(f) => f.metadata(),
            None => std::fs::metadata(format!("/proc/self/fd/{fd}")),
        }
    } else {
        match fds.file(fd) {
            Some(f) => f.metadata(),
            None => {
                set64(env, Gpr(0), cx.neg(EBADF));
                return Some(TrapOutcome::Handled);
            }
        }
    };
    let m = match meta {
        Ok(m) => m,
        Err(_) => {
            set64(env, Gpr(0), cx.neg(EBADF));
            return Some(TrapOutcome::Handled);
        }
    };
    let ino = if fd < 3 {
        std_paths
            .get(fd as usize)
            .and_then(|p| p.as_deref())
            .map(path_ino)
    } else {
        fds.path_of(fd).map(path_ino)
    }
    .unwrap_or(u64::from(fd) | 1);
    let st = stat_buf(&m, ino, cx.is64);
    if env.backend.mem.write(VirtAddr(stat_addr), &st).is_err() {
        return Some(TrapOutcome::Unimplemented);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

pub fn module_eperm(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // モジュールは扱わず常に EPERM。insmod / rmmod が呼ぶ。
    set64(env, Gpr(0), cx.neg(EPERM));
    Some(TrapOutcome::Handled)
}

pub fn sys_init_module(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    module_eperm(env, cx)
}

pub fn sys_delete_module(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    module_eperm(env, cx)
}

pub fn sys_finit_module(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    module_eperm(env, cx)
}
pub fn dir_cursor(dir_pos: &[(u32, usize)], fd: u32) -> usize {
    dir_pos
        .iter()
        .find(|(id, _)| *id == fd)
        .map(|(_, n)| *n)
        .unwrap_or(0)
}
pub fn set_dir_cursor(dir_pos: &mut Vec<(u32, usize)>, fd: u32, next: usize) {
    if let Some(slot) = dir_pos.iter_mut().find(|(id, _)| *id == fd) {
        slot.1 = next;
    } else {
        dir_pos.push((fd, next));
    }
}
pub fn sys_lsetxattr(root: &str, cwd: &str, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // lsetxattr(path, ...) は setxattr と同じ扱いにする.
    // シンボリックリンク自体への付与は区別しない（試作の割り切り...）。方針は呼び出し側と同じ.
    sys_setxattr(root, cwd, env, cx)
}
pub fn sys_fallocate(
    fds: &mut FdTable,
    std: Option<&mut std::fs::File>,
    env: &mut BareEnv,
    cx: &SysCtx,
) -> Option<TrapOutcome> {
    // fallocate(fd, mode, offset, len)。長さを offset+len まで伸ばす。
    // mode が 0 以外（穴あけ等）は EOPNOTSUPP。
    let fd = get64(env, cx.r_a) as u32;
    let mode = get64(env, cx.r_b);
    let offset = get64(env, cx.r_c);
    let len = get64(env, cx.r_d);
    const EOPNOTSUPP: u32 = 95;
    if mode != 0 {
        set64(env, Gpr(0), cx.neg(EOPNOTSUPP));
        return Some(TrapOutcome::Handled);
    }
    let Some(end) = offset.checked_add(len) else {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    };
    let file = if fd < 3 { std } else { fds.file_mut(fd) };
    let Some(file) = file else {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    };
    let cur = match file.metadata() {
        Ok(m) => m.len(),
        Err(_) => {
            set64(env, Gpr(0), cx.neg(EBADF));
            return Some(TrapOutcome::Handled);
        }
    };
    if end > cur {
        if file.set_len(end).is_err() {
            set64(env, Gpr(0), cx.neg(EINVAL));
            return Some(TrapOutcome::Handled);
        }
        if end > 0 {
            use std::io::{Seek, Write};
            if file.seek(std::io::SeekFrom::Start(end - 1)).is_err()
                || file.write_all(&[0]).is_err()
            {
                set64(env, Gpr(0), cx.neg(EINVAL));
                return Some(TrapOutcome::Handled);
            }
        }
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}
pub fn sys_ftruncate(
    fds: &mut FdTable,
    std: Option<&mut std::fs::File>,
    env: &mut BareEnv,
    cx: &SysCtx,
) -> Option<TrapOutcome> {
    // ftruncate(fd, length)。truncate -s で使う。ホストの set_len に直結する.
    let fd = get64(env, cx.r_a) as u32;
    let len = get64(env, cx.r_b);
    let file = if fd < 3 { std } else { fds.file_mut(fd) };
    let Some(file) = file else {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    };
    Some(match file.set_len(len) {
        Ok(()) => {
            set64(env, Gpr(0), 0);
            TrapOutcome::Handled
        }
        Err(e) if e.raw_os_error() == Some(EBADF as i32) => {
            set64(env, Gpr(0), cx.neg(EBADF));
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
    })
}
pub fn sys_lseek(
    fds: &mut FdTable,
    std: Option<&mut std::fs::File>,
    env: &mut BareEnv,
    cx: &SysCtx,
) -> Option<TrapOutcome> {
    // lseek(fd, offset, whence)。opened fd の位置を動かし、新位置を返す.
    // Ref: SRC-LINUX (7.3).
    use std::io::Seek;
    let fd = get64(env, cx.r_a) as u32;
    let offset = get64(env, cx.r_b) as i64;
    let whence = get64(env, cx.r_c) as u32;
    let file = if fd < 3 { std } else { fds.file_mut(fd) };
    let Some(file) = file else {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    };
    let pos = match whence {
        0 => std::io::SeekFrom::Start(offset as u64),
        1 => std::io::SeekFrom::Current(offset),
        2 => std::io::SeekFrom::End(offset),
        _ => {
            set64(env, Gpr(0), cx.neg(EINVAL));
            return Some(TrapOutcome::Handled);
        }
    };
    match file.seek(pos) {
        Ok(n) => set64(env, Gpr(0), n),
        Err(_) => set64(env, Gpr(0), cx.neg(EINVAL)),
    }
    Some(TrapOutcome::Handled)
}
/// _llseek(fd, offset_hi, offset_lo, result*, whence)。i386 の 64 ビットシーク。
/// 成功時は result に 8 バイトを書き、戻り値は 0。fd 3 未満は標準入出力の付け替え先を見る。
pub fn sys_llseek(
    fds: &mut FdTable,
    std: Option<&mut std::fs::File>,
    env: &mut BareEnv,
    cx: &SysCtx,
) -> Option<TrapOutcome> {
    use std::io::Seek;
    let fd = get64(env, cx.r_a) as u32;
    let off = (get64(env, cx.r_b) << 32) | get64(env, cx.r_c);
    let res = get64(env, cx.r_d);
    let whence = get64(env, cx.r_e) as u32;
    let file = if fd < 3 { std } else { fds.file_mut(fd) };
    let Some(file) = file else {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    };
    let pos = match whence {
        0 => std::io::SeekFrom::Start(off),
        1 => std::io::SeekFrom::Current(off as i64),
        2 => std::io::SeekFrom::End(off as i64),
        _ => {
            set64(env, Gpr(0), cx.neg(EINVAL));
            return Some(TrapOutcome::Handled);
        }
    };
    match file.seek(pos) {
        Ok(n) => {
            if env
                .backend
                .mem
                .write(VirtAddr(res), &n.to_le_bytes())
                .is_err()
            {
                set64(env, Gpr(0), cx.neg(EFAULT));
            } else {
                set64(env, Gpr(0), 0);
            }
        }
        Err(_) => set64(env, Gpr(0), cx.neg(EINVAL)),
    }
    Some(TrapOutcome::Handled)
}
pub fn sys_fchdir(
    fds: &FdTable,
    std_paths: &[Option<String>; 3],
    cwd: &mut String,
    env: &mut BareEnv,
    cx: &SysCtx,
) -> Option<TrapOutcome> {
    // fchdir(fd)。覚えたパスがディレクトリなら cwd にする。envdir が使う。
    // Ref: SRC-LINUX (7.3).
    let fd = get64(env, cx.r_a) as u32;
    let path = if fd < 3 {
        std_paths.get(fd as usize).and_then(|p| p.as_deref())
    } else {
        fds.path_of(fd)
    };
    let Some(path) = path.map(str::to_owned) else {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    };
    let errno = match std::fs::metadata(&path) {
        Ok(meta) if meta.is_dir() => {
            cwd.clear();
            cwd.push_str(&path);
            set64(env, Gpr(0), 0);
            return Some(TrapOutcome::Handled);
        }
        Ok(_) => ENOTDIR,
        Err(err) => match err.kind() {
            std::io::ErrorKind::NotFound => ENOENT,
            std::io::ErrorKind::PermissionDenied => EACCES,
            _ => ENOENT,
        },
    };
    set64(env, Gpr(0), cx.neg(errno));
    Some(TrapOutcome::Handled)
}
pub fn sys_getdents64(
    fds: &FdTable,
    std_paths: &[Option<String>; 3],
    dir_pos: &mut Vec<(u32, usize)>,
    dir_done: &mut Vec<u32>,
    env: &mut BareEnv,
    cx: &SysCtx,
) -> Option<TrapOutcome> {
    // getdents64(fd, dirp, count)。ホストのディレクトリ列挙を
    // linux_dirent64 形式で書く。入り切った分だけ返し、残りは次の呼び出しに残す。
    // 1 件も入らなければ EINVAL で、読み位置は進めない。最後まで読んだあとは 0 を返す。
    // d_ino は 0、d_off は累積オフセット、種別は dir/file/link のみ判別する.
    // Ref: SRC-LINUX (7.3).
    let fd = get64(env, cx.r_a) as u32;
    let dirp = get64(env, cx.r_b);
    let count = get64(env, cx.r_c);
    if dir_done.contains(&fd) {
        set64(env, Gpr(0), 0);
        return Some(TrapOutcome::Handled);
    }
    // opened fd のみ受け付ける。stdin/stdout (0-2) は、パスを覚えていなければ EBADF。
    // ゲスト fd を /proc/self/fd のホスト fd とみなすと、別の記述子を開く。
    let dir_path = if fd < 3 {
        std_paths.get(fd as usize).and_then(|p| p.as_deref())
    } else {
        fds.path_of(fd)
    };
    let Some(dir_path) = dir_path.map(std::path::PathBuf::from) else {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    };
    let rd = match std::fs::read_dir(&dir_path) {
        Ok(rd) => rd,
        Err(e) => {
            let no = match e.kind() {
                std::io::ErrorKind::NotFound => ENOENT,
                std::io::ErrorKind::PermissionDenied => EACCES,
                _ => EINVAL,
            };
            set64(env, Gpr(0), cx.neg(no));
            return Some(TrapOutcome::Handled);
        }
    };
    // "." と ".." を先頭に置く（カーネルと同様）。
    let mut names: Vec<(Vec<u8>, u8)> = vec![(b".".to_vec(), 4), (b"..".to_vec(), 4)];
    let proc_root = dir_path == std::path::Path::new("/proc");
    let proc_one_task = dir_path == std::path::Path::new("/proc/1/task")
        || dir_path == std::path::Path::new("/proc/self/task");
    let scsi_devices = dir_path == std::path::Path::new("/sys/bus/scsi/devices")
        || dir_path == std::path::Path::new("/sys/bus/scsi/devices/.");
    if proc_root {
        // ホストの PID は隠す。ps/top の期待値を固定するため pid 1 と self だけ返す。
        names.push((b"1".to_vec(), 4));
        names.push((b"self".to_vec(), 10));
        names.push((b"diskstats".to_vec(), 8));
        names.push((b"loadavg".to_vec(), 8));
        names.push((b"meminfo".to_vec(), 8));
        names.push((b"stat".to_vec(), 8));
        names.push((b"uptime".to_vec(), 8));
    } else if proc_one_task {
        names.push((b"1".to_vec(), 4));
    } else if scsi_devices {
        names.push((b"0:0:0:0".to_vec(), 4));
    } else {
        for ent in rd.flatten() {
            let name = ent
                .file_name()
                .into_string()
                .unwrap_or_default()
                .into_bytes();
            if name.is_empty() {
                continue;
            }
            let ty = ent
                .file_type()
                .map(|t| {
                    if t.is_dir() {
                        4u8
                    } else if t.is_symlink() {
                        10u8
                    } else {
                        8u8
                    }
                })
                .unwrap_or(0);
            names.push((name, ty));
        }
    }
    // 名前順に並べ替えて決定的にする（カーネルの順序は不定だが、ls は自前で整列する）。
    names[2..].sort_by(|a, b| a.0.cmp(&b.0));
    let start = dir_cursor(dir_pos, fd);
    if start >= names.len() {
        if !dir_done.contains(&fd) {
            dir_done.push(fd);
        }
        set64(env, Gpr(0), 0);
        return Some(TrapOutcome::Handled);
    }
    let mut out = Vec::new();
    let mut off = 0u64;
    let mut taken = 0usize;
    for (name, ty) in names.iter().skip(start) {
        let reclen = ((19 + name.len() + 1) as u64).next_multiple_of(8);
        if out.len() as u64 + reclen > count {
            break;
        }
        off += reclen;
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&off.to_le_bytes());
        out.extend_from_slice(&(reclen as u16).to_le_bytes());
        out.push(*ty);
        out.extend_from_slice(name);
        out.push(0);
        while !(out.len() as u64).is_multiple_of(8) {
            out.push(0);
        }
        taken += 1;
    }
    if taken == 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    if env.backend.mem.write(VirtAddr(dirp), &out).is_err() {
        return Some(TrapOutcome::Unimplemented);
    }
    let next = start + taken;
    if next >= names.len() {
        dir_done.push(fd);
        dir_pos.retain(|(id, _)| *id != fd);
    } else {
        set_dir_cursor(dir_pos, fd, next);
    }
    set64(env, Gpr(0), out.len() as u64);
    Some(TrapOutcome::Handled)
}
pub fn sys_fchmodat(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_chmod(env, cx)
}
pub fn sys_getegid(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_getgid(env, cx)
}
pub fn sys_geteuid(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_getuid(env, cx)
}
pub fn sys_inotify_init(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_inotify_init1(env, cx)
}
pub fn sys_setgid(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_setuid(env, cx)
}
pub fn sys_setregid(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_setuid(env, cx)
}
pub fn sys_setresgid(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_setuid(env, cx)
}
pub fn sys_setreuid(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_setuid(env, cx)
}
pub fn sys_setresuid(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_setuid(env, cx)
}
pub fn sys_pselect6(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_select(env, cx)
}
pub fn sys_fsync(valid: bool, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // fsync(fd)。ホストへは流さず、開いている fd なら 0。
    // Ref: SRC-LINUX (7.3).
    if !valid {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

pub fn sys_fcntl(valid: bool, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // fcntl(fd, cmd, ...)。接続中・付け替え中の標準 fd と opened fd に対して 0 を返す.
    // printf の stdout 設定などで呼ばれる。複製やロックは行わない.
    if !valid {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

pub fn sys_fdatasync(valid: bool, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // fdatasync(fd)。shred が毎回呼ぶ。実体は fsync と同じ.
    sys_fsync(valid, env, cx)
}
/// start 以降で count ページ連続の空きを探す。見つからなければ None.
/// brk 縮小で残った写像や固定写像の上書きを避ける first-fit.
/// MAP_FIXED でない mmap は空きを選ぶ (Ref: SRC-LINUX (7.3)).
pub fn find_free_run(env: &BareEnv, start: u64, count: u64) -> Option<u64> {
    use polyisa_mem::{PAGE_SIZE, PageNo};
    // 走査上限（4GB 分）。通常は先頭で見つかる.
    const SCAN_CAP_PAGES: u64 = 1 << 20;
    let mut base = start.next_multiple_of(PAGE_SIZE);
    let mut scanned = 0u64;
    while scanned < SCAN_CAP_PAGES {
        let mut i = 0u64;
        while i < count {
            let page = (base / PAGE_SIZE).checked_add(i)?;
            if env.backend.mem.is_mapped(PageNo(page)) {
                break;
            }
            i += 1;
        }
        if i == count {
            return Some(base);
        }
        base = base.checked_add((i + 1) * PAGE_SIZE)?;
        scanned += i + 1;
    }
    None
}
pub fn sys_brk(heap_end: &mut u64, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // ブレークは要求値ではなくページ整列した末尾で記録・返却する。
    // Gap: GAP-0034
    use polyisa_mem::{PAGE_SIZE, Perms, VirtAddr};
    let addr = get64(env, cx.r_a);
    // 未初期化の非常口：像末尾を知らないため要求値を切り上げて使う。
    // run_image 経由では init_brk 済みのため通常は通らない。
    if *heap_end == 0 {
        (*heap_end) = addr.next_multiple_of(PAGE_SIZE);
        set64(env, Gpr(0), *heap_end);
        return Some(TrapOutcome::Handled);
    }
    if addr == 0 {
        // brk(0) は問い合わせであり現ブレークを返す。
        set64(env, Gpr(0), *heap_end);
        return Some(TrapOutcome::Handled);
    }
    let aligned = addr.next_multiple_of(PAGE_SIZE);
    if aligned > *heap_end {
        // 拡張しすぎは失敗扱い（現ブレークを返す）。
        const MAX_GROW: u64 = 256 * 1024 * 1024;
        if aligned - *heap_end > MAX_GROW {
            set64(env, Gpr(0), *heap_end);
            return Some(TrapOutcome::Handled);
        }
        // 縮小で残った写像は消さず、欠けたページだけ足す。
        // 実 brk は縮小で内容を捨てないため、再拡張で上書きしない.
        use polyisa_mem::PageNo;
        let mut cur = *heap_end;
        while cur < aligned {
            if !env.backend.mem.is_mapped(PageNo(cur / PAGE_SIZE))
                && env.backend.mem.map(VirtAddr(cur), 1, Perms::RW).is_err()
            {
                set64(env, Gpr(0), *heap_end);
                return Some(TrapOutcome::Handled);
            }
            cur += PAGE_SIZE;
        }
        (*heap_end) = aligned;
    } else {
        // 縮小は受け付ける（写像は残す）。
        (*heap_end) = aligned;
    }
    set64(env, Gpr(0), *heap_end);
    Some(TrapOutcome::Handled)
}
pub fn sys_mmap(mmap_base: &mut u64, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // mmap(addr, len, prot, flags, fd, offset)。匿名のみ受け付ける.
    // ファイル-backed は未対応のため EINVAL.
    // prot は寛容に RW で写像する (PROT_NONE 予約後の mprotect 前でも動くため).
    use polyisa_mem::{PAGE_SIZE, Perms, VirtAddr};
    let addr = get64(env, cx.r_a);
    let len = get64(env, cx.r_b);
    let _prot = get64(env, cx.r_c);
    let flags = get64(env, cx.r_d);
    let fd = get64(env, cx.r_e) as i64;
    let offset = get64(env, cx.r_f);
    const MAP_ANONYMOUS: u64 = 0x20;
    const MAP_FIXED: u64 = 0x10;
    if len == 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    if offset & (PAGE_SIZE - 1) != 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    if flags & MAP_ANONYMOUS == 0 && fd != -1 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    // 拡張しすぎは失敗扱い.
    const MAX_MMAP: u64 = 1024 * 1024 * 1024;
    if len > MAX_MMAP {
        set64(env, Gpr(0), cx.neg(ENOMEM));
        return Some(TrapOutcome::Handled);
    }
    let aligned_len = len.next_multiple_of(PAGE_SIZE);
    let count = aligned_len / PAGE_SIZE;
    if flags & MAP_FIXED != 0 {
        if addr & (PAGE_SIZE - 1) != 0 {
            set64(env, Gpr(0), cx.neg(EINVAL));
            return Some(TrapOutcome::Handled);
        }
        // MAP_FIXED は既存写像を置換する。先に外してから写像する.
        env.backend.mem.unmap(VirtAddr(addr), count);
        if env
            .backend
            .mem
            .map(VirtAddr(addr), count, Perms::RW)
            .is_err()
        {
            set64(env, Gpr(0), cx.neg(ENOMEM));
            return Some(TrapOutcome::Handled);
        }
        // MAP_FIXED は明示番地なので割り当て基底は動かさない。
        // brk のブレークとも独立している。
        set64(env, Gpr(0), addr);
        return Some(TrapOutcome::Handled);
    }
    if addr == 0 {
        let Some(base) = mmap_alloc(mmap_base, env, count, aligned_len) else {
            set64(env, Gpr(0), cx.neg(ENOMEM));
            return Some(TrapOutcome::Handled);
        };
        set64(env, Gpr(0), base);
        return Some(TrapOutcome::Handled);
    }
    // ヒント付き: 範囲全体が空きのときだけ要求番地に写像し、
    // 占有があれば mmap_base から first-fit で取る (上書きしない).
    let hint = addr & !(PAGE_SIZE - 1);
    let hint_free = {
        use polyisa_mem::PageNo;
        let mut i = 0u64;
        while i < count {
            let page = (hint / PAGE_SIZE).checked_add(i);
            match page {
                Some(no) if !env.backend.mem.is_mapped(PageNo(no)) => i += 1,
                _ => break,
            }
        }
        i == count
    };
    if hint_free
        && env
            .backend
            .mem
            .map(VirtAddr(hint), count, Perms::RW)
            .is_ok()
    {
        set64(env, Gpr(0), hint);
        return Some(TrapOutcome::Handled);
    }
    let Some(base) = mmap_alloc(mmap_base, env, count, aligned_len) else {
        set64(env, Gpr(0), cx.neg(ENOMEM));
        return Some(TrapOutcome::Handled);
    };
    set64(env, Gpr(0), base);
    Some(TrapOutcome::Handled)
}

/// 匿名 mmap の割り当て。`mmap_base` から空きを探して写像し、
/// 基底を進めて割り当てた番地を返す。失敗は None.
fn mmap_alloc(mmap_base: &mut u64, env: &mut BareEnv, count: u64, aligned_len: u64) -> Option<u64> {
    use polyisa_mem::{Perms, VirtAddr};
    if *mmap_base == 0 {
        // 実 Linux の TASK_UNMAPPED_BASE 相当。brk ヒープとは別空間から
        // 昇順に取る。空間の幅に応じて番地を選ぶ。
        *mmap_base = if env.backend.addr_mask == u64::MAX {
            0x4000_0000_0000
        } else {
            0x4000_0000
        };
    }
    let base = find_free_run(env, *mmap_base, count)?;
    // ゲストのアドレス空間に収まる割り当てだけを返す。
    // addr_mask の外側は mem 上は空きでもゲストから到達できない。
    let limit = env.backend.addr_mask.wrapping_add(1);
    if limit != 0 && (base >= limit || aligned_len > limit - base) {
        return None;
    }
    env.backend.mem.map(VirtAddr(base), count, Perms::RW).ok()?;
    *mmap_base = base + aligned_len;
    Some(base)
}

/// eip レジスタの読み出し。FS/GS ベースは `CpuState` のレジスタなので、
/// トラップ側からも実行ループ側からも同じ `env.backend` 経由で届く。
pub fn eip_of(env: &mut BareEnv) -> u32 {
    env.backend.get(polyisa_guest_x86::sem::eip_ref())
}

/// `rt_sigaction` で覚えるハンドラの内容。Linux の
/// kernel_sigaction（x86-64 では handler/flags/restorer/mask の
/// 32 バイト、i386 は 20 バイト）に対応する。
// Ref: SRC-LINUX (7.3) arch/x86/kernel/signal.c.
#[derive(Clone, Copy, Default, Debug)]
pub struct SigAct {
    /// ハンドラのアドレス。0=SIG_DFL、1=SIG_IGN。
    pub handler: u64,
    /// SA_* フラグ（SA_NODEFER/SA_RESETHAND/SA_RESTORER を使う）。
    pub flags: u64,
    /// SA_RESTORER が指す復帰コード。rt_sigreturn を呼ぶ。
    pub restorer: u64,
    /// ハンドラ実行中に足すシグナルマスク。
    pub mask: u64,
}

/// ハンドラ実行中に当該シグナル自身を止めない。
pub const SA_NODEFER: u64 = 0x4000_0000;
/// 配送のたびにハンドラを SIG_DFL に戻す。
pub const SA_RESETHAND: u64 = 0x8000_0000;
/// `restorer` が有効（x86-64 の rt_sigaction では必須）。
pub const SA_RESTORER: u64 = 0x0400_0000;
/// 代替スタックなしを表す ss_flags の値。
pub const SS_DISABLE: u64 = 2;
/// rt_sigprocmask の how。現行マスクに加える。
pub const SIG_BLOCK: u64 = 0;
/// rt_sigprocmask の how。現行マスクから外す。
pub const SIG_UNBLOCK: u64 = 1;
/// rt_sigprocmask の how。マスクを置き換える。
pub const SIG_SETMASK: u64 = 2;

/// ゲストメモリから kernel_sigaction を読む。`is64` で配置が変わる。
#[must_use]
pub fn sigact_read(env: &mut BareEnv, addr: u64, is64: bool) -> Option<SigAct> {
    // i386 の構造体は 20 バイト。32 バイト読むとマップ末尾の
    // 構造体で偽の EFAULT になる。
    let mut b = [0u8; 32];
    let n = if is64 { 32 } else { 20 };
    env.backend
        .mem
        .read(polyisa_mem::VirtAddr(addr), &mut b[..n], data_access())
        .ok()?;
    Some(if is64 {
        SigAct {
            handler: u64::from_le_bytes(b[0..8].try_into().unwrap()),
            flags: u64::from_le_bytes(b[8..16].try_into().unwrap()),
            restorer: u64::from_le_bytes(b[16..24].try_into().unwrap()),
            mask: u64::from_le_bytes(b[24..32].try_into().unwrap()),
        }
    } else {
        SigAct {
            handler: u64::from(u32::from_le_bytes(b[0..4].try_into().unwrap())),
            flags: u64::from(u32::from_le_bytes(b[4..8].try_into().unwrap())),
            restorer: u64::from(u32::from_le_bytes(b[8..12].try_into().unwrap())),
            mask: u64::from_le_bytes(b[12..20].try_into().unwrap()),
        }
    })
}

/// ゲストメモリへ kernel_sigaction を書く（oldact の返却用）。
pub fn sigact_write(env: &mut BareEnv, addr: u64, act: &SigAct, is64: bool) -> bool {
    // i386 は 20 バイトだけ書く。32 バイト書くと呼び出し側の
    // バッファの後ろを壊す。
    let mut b = [0u8; 32];
    if is64 {
        b[0..8].copy_from_slice(&act.handler.to_le_bytes());
        b[8..16].copy_from_slice(&act.flags.to_le_bytes());
        b[16..24].copy_from_slice(&act.restorer.to_le_bytes());
        b[24..32].copy_from_slice(&act.mask.to_le_bytes());
    } else {
        b[0..4].copy_from_slice(&(act.handler as u32).to_le_bytes());
        b[4..8].copy_from_slice(&(act.flags as u32).to_le_bytes());
        b[8..12].copy_from_slice(&(act.restorer as u32).to_le_bytes());
        b[12..20].copy_from_slice(&act.mask.to_le_bytes());
    }
    let n = if is64 { 32 } else { 20 };
    env.backend
        .mem
        .write(polyisa_mem::VirtAddr(addr), &b[..n])
        .is_ok()
}

/// ゲストメモリの読み書き。失敗時は None/false。
fn frd64(env: &mut BareEnv, a: u64) -> Option<u64> {
    let mut b = [0u8; 8];
    env.backend
        .mem
        .read(polyisa_mem::VirtAddr(a), &mut b, data_access())
        .ok()?;
    Some(u64::from_le_bytes(b))
}

fn fwr(env: &mut BareEnv, a: u64, v: u64, n: usize) -> bool {
    env.backend
        .mem
        .write(polyisa_mem::VirtAddr(a), &v.to_le_bytes()[..n])
        .is_ok()
}

/// x86-64 の rt シグナルフレームをスタックに作り、RIP を
/// ハンドラ入口に向ける。失敗（未写像など）なら偽を返す。
/// 配置（`struct rt_sigframe` 相当）:
///   +0    pretcode（SA_RESTORER のアドレス）
///   +8    ucontext: flags,link,stack,mcontext{gregs[23],fpregs*,rsvd}
///         ,sigmask（旧マスク）… +311
///   +312  siginfo（128 バイト、si_signo/si_code=SI_USER/si_pid）
///   fpstate（512 バイト、FXSAVE 配置）はフレームの直上に
///   別置きし、uc_mcontext.fpregs が指す（64 整列が要るため）。
/// フレーム基底は ≡8 (mod 16)。call 直後の関数入口と同じ
/// ABI 整列でハンドラへ入る。RDI=sig, RSI=&info, RDX=&uc。
// Ref: SRC-LINUX (7.3) arch/x86/kernel/signal.c setup_rt_frame.
pub fn rt_sigframe_write(
    env: &mut BareEnv,
    sig: u32,
    act: &SigAct,
    old_mask: u64,
    pid: u64,
) -> bool {
    const FRAME: u64 = 1024;
    const GREGB: u64 = 48; // ucontext.mcontext.gregs のフレーム内オフセット
    let rsp = get64(env, Gpr(4));
    // レッドゾーン(128)を避けて、fpstate をフレームより上に
    // 64 整列で取る。フレーム基底は fp の下に ≡8 (mod 16) で
    // 置く（実カーネルの round_down(...,16)-8 と同じ整列）。
    let fp = ((rsp - 128).wrapping_sub(512)) & !63;
    let f = (fp & !15).wrapping_sub(FRAME + 8);
    // ucontext の固定部と siginfo。
    let fields: [(u64, u64); 10] = [
        (f, act.restorer),
        (f + 8, 0),                // uc_flags
        (f + 16, 0),               // uc_link
        (f + 24, 0),               // uc_stack.ss_sp
        (f + 32, SS_DISABLE),      // uc_stack.ss_flags
        (f + 40, 0),               // uc_stack.ss_size
        (f + GREGB + 184, fp),     // uc_mcontext.fpregs
        (f + 304, old_mask),       // uc_sigmask
        (f + 312, u64::from(sig)), // si_signo+si_errno(=0)
        (f + 312 + 8, 0),          // si_code=SI_USER
    ];
    for (a, v) in fields {
        if !fwr(env, a, v, 8) {
            return false;
        }
    }
    if !fwr(env, f + 312 + 16, pid, 8) {
        // _sifields._kill = {si_pid u32, si_uid u32}
        return false;
    }
    // gregs: REG_R8..R15,RDI,RSI,RBP,RBX,RDX,RAX,RCX,RSP,RIP,EFL,
    // CSGSFS,ERR,TRAPNO,OLDMASK,CR2 の順。
    let mut g = [0u64; 23];
    for (i, v) in g.iter_mut().enumerate().take(8) {
        *v = get64(env, Gpr(8 + i as u8));
    }
    for (i, r) in [7u8, 6, 5, 3, 2, 0, 1, 4].iter().enumerate() {
        g[8 + i] = get64(env, Gpr(*r));
    }
    g[16] = u64::from(env.backend.get(polyisa_guest_x86::sem::eip_ref()));
    g[17] = u64::from(env.backend.get(polyisa_guest_x86::sem::eflags_ref()));
    let cs = u64::from(env.backend.get(polyisa_guest_x86::sem::sreg_ref(1)));
    let gs = u64::from(env.backend.get(polyisa_guest_x86::sem::sreg_ref(5)));
    let fs = u64::from(env.backend.get(polyisa_guest_x86::sem::sreg_ref(4)));
    g[18] = cs | (gs << 16) | (fs << 32);
    g[21] = old_mask;
    for (i, v) in g.iter().enumerate() {
        if !fwr(env, f + GREGB + 8 * i as u64, *v, 8) {
            return false;
        }
    }
    // fpstate（FXSAVE 配置）。両成分を無条件で書く。
    let b = &mut env.backend;
    if polyisa_guest_x86::sem_ea::fxsave_area(b, fp, None, 64, true, true).is_err() {
        return false;
    }
    // ハンドラへ入る引数とスタック。
    set64(env, Gpr(4), f);
    set64(env, Gpr(7), u64::from(sig));
    set64(env, Gpr(6), f + 312);
    set64(env, Gpr(2), f + 8);
    set64(env, Gpr(0), 0);
    env.backend
        .set(polyisa_guest_x86::sem::eip_ref(), act.handler as u32);
    true
}

/// rt_sigreturn。RSP が指すフレームからコンテキスト（レジスタ・
/// FP 状態・マスク）を復元し、復元したシグナルマスクを返す。
/// フレームが読めなければ None。
/// ハンドラの ret が pretcode をポップしてから restorer が走る
/// ので、システムコール時点の RSP はフレーム基底+8 になって
/// いる（カーネルも `sp - sizeof(long)` で基底を求める）。
pub fn rt_sigframe_read(env: &mut BareEnv) -> Option<u64> {
    const GREGB: u64 = 48;
    let f = get64(env, Gpr(4)).wrapping_sub(8);
    let mask = frd64(env, f + 304)?;
    let fp = frd64(env, f + GREGB + 184)?;
    let mut g = [0u64; 23];
    for (i, v) in g.iter_mut().enumerate() {
        *v = frd64(env, f + GREGB + 8 * i as u64)?;
    }
    for (i, v) in g.iter().enumerate().take(8) {
        set64(env, Gpr(8 + i as u8), *v);
    }
    for (i, r) in [7u8, 6, 5, 3, 2, 0, 1].iter().enumerate() {
        set64(env, Gpr(*r), g[8 + i]);
    }
    let xcr0 = env.backend.get(polyisa_guest_x86::sem::xcr0_ref());
    let b = &mut env.backend;
    polyisa_guest_x86::sem_ea::fxrstor_area(b, fp, None, 64, xcr0 & 3, 0).ok()?;
    set64(env, Gpr(4), g[15]);
    env.backend
        .set(polyisa_guest_x86::sem::eflags_ref(), g[17] as u32);
    env.backend
        .set(polyisa_guest_x86::sem::eip_ref(), g[16] as u32);
    Some(mask)
}

/// Linux の syscall 処理（`cli` から移管した `Linux` 状態機械）。
pub mod sys;

pub use sys::{Linux, SCHED_SLICE};

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_mem::Perms;

    #[test]
    fn c_string_spans_pages() {
        let mut env = BareEnv::new(8);
        env.backend.mem.map(VirtAddr(0), 2, Perms::RW).unwrap();
        // ページをまたぐ文字列（0x0FF8 から）。
        let s = b"hello-span\0";
        env.backend.mem.write(VirtAddr(0x0FF8), s).unwrap();
        assert_eq!(
            guest_c_string(&mut env, 0x0FF8).as_deref(),
            Some("hello-span")
        );
    }

    #[test]
    fn c_string_stops_at_unmapped_page() {
        let mut env = BareEnv::new(8);
        env.backend.mem.map(VirtAddr(0), 1, Perms::RW).unwrap();
        // NUL なしでページ末尾まで埋めると、次ページは未写像なので None。
        let s = vec![b'a'; polyisa_mem::PAGE_SIZE as usize];
        env.backend.mem.write(VirtAddr(0), &s).unwrap();
        assert_eq!(guest_c_string(&mut env, 0), None);
        // 途中に NUL があればその手前まで読める。
        env.backend.mem.write(VirtAddr(0x0FFE), &[0u8]).unwrap();
        assert_eq!(guest_c_string(&mut env, 0).map(|s| s.len()), Some(4094));
    }
}
