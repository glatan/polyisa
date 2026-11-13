// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! x86 用のシステムコール文脈。`cli` の実行側と共有する。
//!
//! GAP-0001（ADR-0015）の移管の最初の一片として、`run_x86.rs` にあった
//! 定義を移す。番号表は従来どおり `super`（`GuestAbi`）に置く。

// Ref: SRC-LINUX (7.3).

use polyisa_engine::bare::BareEnv;
use polyisa_guest_x86::sem::Gpr;
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
    // 1バイトずつ読む。まとめて読むと写像の境界で失敗するため.
    // 上限は 4096 バイト（NUL がなければ失敗扱い）。
    let mut buf = Vec::new();
    for i in 0..4096u64 {
        let mut b = [0u8; 1];
        env.backend.mem.read(VirtAddr(addr + i), &mut b, acc).ok()?;
        if b[0] == 0 {
            break;
        }
        buf.push(b[0]);
    }
    if buf.len() == 4096 {
        return None;
    }
    String::from_utf8(buf).ok()
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
pub struct SysCtx {
    pub r_a: Gpr,
    pub r_b: Gpr,
    pub r_c: Gpr,
    pub is64: bool,
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

/// socket 系。段階 C までの暫定で常に EPERM。失敗形のアプレット合わせに使う。
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

pub fn sys_rt_sigaction(env: &mut BareEnv, _cx: &SysCtx) -> Option<TrapOutcome> {
    // シグナルハンドラ設定は無視して 0 を返す (試作はシグナルなし).
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

pub fn sys_rt_sigprocmask(env: &mut BareEnv, _cx: &SysCtx) -> Option<TrapOutcome> {
    // シグナルマスク変更は無視して 0 を返す.
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

pub fn sys_rt_sigsuspend(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // シグナル待ちはせず EINTR を返す。本格は段階 B。
    set64(env, Gpr(0), cx.neg(EINTR));
    Some(TrapOutcome::Handled)
}

pub fn sys_rt_sigtimedwait(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 待ち受けはせず、期限切れとして EAGAIN を返す。init が呼ぶ。本格は段階 B。
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
pub fn join_guest_path(cwd: &str, path: &str) -> String {
    if path.starts_with('/') || cwd.is_empty() {
        return path.to_string();
    }
    if cwd == "/" {
        return format!("/{path}");
    }
    format!("{}/{}", cwd.trim_end_matches('/'), path)
}
pub fn resolve_guest_path(root: &str, cwd: &str, path: &str) -> Option<String> {
    if root.is_empty() {
        return Some(join_guest_path(cwd, path));
    }
    let joined = join_guest_path(cwd, path);
    let mut parts: Vec<&str> = Vec::new();
    for comp in joined.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            _ => parts.push(comp),
        }
    }
    let root_trim = root.trim_end_matches('/');
    let mut out = String::from(root_trim);
    for part in parts {
        out.push('/');
        out.push_str(part);
    }
    Some(out)
}
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
    if cx.is64 && get64(env, cx.r_b) as u32 == FS_IOC_GETFLAGS {
        let ptr = get64(env, cx.r_c);
        if env.backend.mem.write(VirtAddr(ptr), &[0u8; 8]).is_err() {
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
    let old_limit = get64(env, Gpr(10));
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
    let st = stat144(&m, path_ino(&path));
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
    let st = stat144(&m, path_ino(&path));
    if env.backend.mem.write(VirtAddr(stat_addr), &st).is_err() {
        return Some(TrapOutcome::Unimplemented);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

/// newfstatat(dirfd, path, statbuf, flags)。AT_FDCWD+絶対パスのみ.
/// ホスト metadata から struct stat (144B) を書いて 0 を返す.
/// flags (AT_SYMLINK_NOFOLLOW 等) は無視してたどる.
/// Ref: SRC-LINUX (7.3).
pub fn sys_newfstatat(
    root: &str,
    cwd: &str,
    exe_path: &str,
    env: &mut BareEnv,
    cx: &SysCtx,
) -> Option<TrapOutcome> {
    let dirfd = get64(env, Gpr(7));
    let path_addr = get64(env, Gpr(6));
    let stat_addr = get64(env, Gpr(2));
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
    let st = stat144(&m, path_ino(&path));
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
pub fn sys_arch_prctl(fs_base: &mut u64, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // arch_prctl (x86-64 のみ)。TLS の FS ベース設定を受け付ける。
    // Ref: SRC-LINUX (7.3) arch/x86/include/uapi/asm/prctl.h.
    const ARCH_SET_FS: u64 = 0x1002;
    const ARCH_GET_FS: u64 = 0x1003;
    let op = get64(env, cx.r_a);
    if op == ARCH_SET_FS {
        *fs_base = get64(env, cx.r_b);
        set64(env, Gpr(0), 0);
        return Some(TrapOutcome::Handled);
    }
    if op == ARCH_GET_FS {
        let base = *fs_base;
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
    // 長さは struct robust_list_head (24バイト) のはずであり、異なる場合は EINVAL.
    const ROBUST_LIST_HEAD_LEN: u64 = 24;
    if get64(env, cx.r_b) != ROBUST_LIST_HEAD_LEN {
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
