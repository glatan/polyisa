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
    /// dirfd が AT_FDCWD か。x86-64 は下位 32 ビット、i386 は値そのものを比べる.
    pub fn is_at_fdcwd(&self, dirfd: u64) -> bool {
        if self.is64 {
            (dirfd as u32) == AT_FDCWD_U32
        } else {
            dirfd == self.at_fdcwd
        }
    }

    /// 戻り値の負 errno。x86-64 は 64 ビット符号拡張、i386 は 32 ビット。
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
