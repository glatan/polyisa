// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! ソケット関連 syscall の正準実装（段階26・NS5）。
//!
//! 各 ABI は番号展開・引数レジスタの読み出し・errno の ABI 値への
//! 写像・待ちの駐車を担い、意味はここへ寄せる。`sys_*` 関数群は
//! 引数語と `BareEnv`・`FdTable`・`SockAbi` を受けて、結果語か
//! 待ち要求 `Out::Wait` を返す。errno は asm-generic 値で返し、
//! `SockAbi::errno` が ABI 値へ写す。
//!
//! ホストのソケットは常に非阻止に保ち、阻止動作は ABI が `Wait` を
//! 自前の待ち機構へ写して実現する。カーネル内対象（socketpair の
//! `PairSock`）は `FdTable` の操作だけで閉じる。
// Ref: SRC-LINUX (7.3)。

use polyisa_engine::bare::BareEnv;
use polyisa_kernel::{FdEnt, FdTable, FdTarget};
use polyisa_mem::{Access, AccessKind, Align, Endian, VirtAddr};

/// asm-generic の errno。ABI 値への写像は `SockAbi::errno`。
// Ref: SRC-LINUX (7.3) — include/uapi/asm-generic/errno.h.
pub mod errno {
    pub const EPERM: u32 = 1;
    pub const ENOENT: u32 = 2;
    pub const EINTR: u32 = 4;
    pub const EIO: u32 = 5;
    pub const EBADF: u32 = 9;
    pub const EAGAIN: u32 = 11;
    pub const ENOMEM: u32 = 12;
    pub const EFAULT: u32 = 14;
    pub const EEXIST: u32 = 17;
    pub const EISDIR: u32 = 21;
    pub const EINVAL: u32 = 22;
    pub const EMFILE: u32 = 24;
    pub const EPIPE: u32 = 32;
    pub const ENOTSOCK: u32 = 88;
    pub const EDESTADDRREQ: u32 = 89;
    pub const EMSGSIZE: u32 = 90;
    pub const EPROTOTYPE: u32 = 91;
    pub const ENOPROTOOPT: u32 = 92;
    pub const EPROTONOSUPPORT: u32 = 93;
    pub const EOPNOTSUPP: u32 = 95;
    pub const EAFNOSUPPORT: u32 = 97;
    pub const EADDRINUSE: u32 = 98;
    pub const EADDRNOTAVAIL: u32 = 99;
    pub const ECONNRESET: u32 = 104;
    pub const ENOBUFS: u32 = 105;
    pub const EISCONN: u32 = 106;
    pub const ENOTCONN: u32 = 107;
    pub const ETIMEDOUT: u32 = 110;
    pub const ECONNREFUSED: u32 = 111;
    pub const EINPROGRESS: u32 = 115;
    /// 単一スレッドの待ちが進行不能だったときのデッドロック報告値。
    pub const EDEADLK: u32 = 35;
    pub const ELOOP: u32 = 40;
}

/// `dispatch` が受ける syscall 名の集合。ABI が「ソケット系か」を
/// 名前だけで判定するときに使う。
pub const NAMES: &[&str] = &[
    "socket",
    "socketpair",
    "bind",
    "connect",
    "listen",
    "accept",
    "accept4",
    "getsockname",
    "getpeername",
    "shutdown",
    "send",
    "sendto",
    "recv",
    "recvfrom",
    "sendmsg",
    "recvmsg",
    "setsockopt",
    "getsockopt",
    "socketcall",
];

// fd 待ちの語彙（`Wait`・`Out`・興味ビット・消化機構）は
// 待ち合わせ系の正準層 `wait` が正本で、ソケット系もそれを使う。
pub use crate::wait::{Out, WANT_READ, WANT_WRITE, Wait};

/// ABI ごとの差分。値はゲスト側の定数。
pub struct SockAbi {
    /// ポインタ語幅（4 or 8 バイト）。
    pub ptr_size: u8,
    /// ゲストのエンディアン。
    pub endian: Endian,
    /// asm-generic errno → ABI errno の写像（同値なら恒等）。
    pub errno: fn(u32) -> u32,
    /// socket の type に混ざる SOCK_NONBLOCK（ABI の O_NONBLOCK 値）。
    pub sock_nonblock: u64,
    /// SOCK_CLOEXEC（ABI の O_CLOEXEC 値）。
    pub sock_cloexec: u64,
    /// MSG_DONTWAIT。
    pub msg_dontwait: u64,
    /// MSG_NOSIGNAL（受理して捨てる）。
    pub msg_nosignal: u64,
    /// SOL_SOCKET の optname をホスト値へ写す。知らない値は -1。
    pub so_to_host: fn(u32) -> i32,
}

impl SockAbi {
    /// asm-generic 値の ABI（ほぼ全ての現行ターゲット）。
    /// `ptr_size` は 4 か 8。
    pub fn generic(ptr_size: u8, endian: Endian) -> Self {
        Self {
            ptr_size,
            endian,
            errno: |e| e,
            sock_nonblock: 0o4000,   // O_NONBLOCK
            sock_cloexec: 0o2000000, // O_CLOEXEC
            msg_dontwait: 0x40,
            msg_nosignal: 0x4000,
            so_to_host: so_generic_to_host,
        }
    }
}

/// generic の SO_* optname → ホスト値（同値）。
fn so_generic_to_host(name: u32) -> i32 {
    match name {
        // DEBUG=1 REUSEADDR=2 TYPE=3 ERROR=4 DONTROUTE=5 BROADCAST=6
        // SNDBUF=7 RCVBUF=8 KEEPALIVE=9 OOBINLINE=10 LINGER=13
        // REUSEPORT=15
        1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 13 | 15 => name as i32,
        _ => -1,
    }
}

/// mips/alpha/sparc/parisc の SO_* optname → ホスト（generic）値。
/// 4 ABI は同じ独自系（REUSEADDR=4・TYPE=0x1008・SNDBUF=0x1001 等）。
// Ref: SRC-LINUX — arch/{mips,alpha,sparc,parisc}/include/uapi/asm/socket.h。
pub fn so_odd_to_host(name: u32) -> i32 {
    match name {
        0x0001 => 1,  // DEBUG
        0x0004 => 2,  // REUSEADDR
        0x0008 => 9,  // KEEPALIVE
        0x0010 => 5,  // DONTROUTE
        0x0020 => 6,  // BROADCAST
        0x0080 => 13, // LINGER
        0x0100 => 10, // OOBINLINE
        0x0200 => 15, // REUSEPORT
        0x1001 => 7,  // SNDBUF
        0x1002 => 8,  // RCVBUF
        0x1007 => 4,  // ERROR
        0x1008 => 3,  // TYPE
        _ => -1,
    }
}

/// データアクセスの既定形。
fn acc(e: Endian) -> Access {
    Access {
        endian: e,
        align: Align::Unaligned,
        kind: AccessKind::DataRead,
    }
}

pub(crate) fn rd(env: &mut BareEnv, addr: u64, buf: &mut [u8]) -> bool {
    // バイト列の読み出しにエンディアンは関係しない。
    env.backend
        .mem
        .read(VirtAddr(addr), buf, acc(Endian::Le))
        .is_ok()
}

/// 値をゲストエンディアンで読む。
pub(crate) fn rd_u(env: &mut BareEnv, endian: Endian, addr: u64, width: usize) -> Option<u64> {
    let mut a = acc(endian);
    a.align = Align::Unaligned;
    env.backend.mem.read_value(VirtAddr(addr), width, a).ok()
}

/// 値をゲストエンディアンで書く。
pub(crate) fn wr_u(env: &mut BareEnv, endian: Endian, addr: u64, v: u64, width: usize) -> bool {
    let mut a = acc(endian);
    a.align = Align::Unaligned;
    env.backend
        .mem
        .write_value(VirtAddr(addr), v, width, a)
        .is_ok()
}

pub(crate) fn wr(env: &mut BareEnv, addr: u64, buf: &[u8]) -> bool {
    env.backend.mem.write(VirtAddr(addr), buf).is_ok()
}

/// ポインタ語を読む（`ptr_size` 幅）。
fn rd_ptr(env: &mut BareEnv, endian: Endian, ptr_size: u8, addr: u64) -> Option<u64> {
    rd_u(env, endian, addr, ptr_size as usize)
}

/// ゲストの sockaddr をホスト形（先頭 family 2 バイト＋本体）へ写す。
/// family フィールドはゲストのエンディアンで読み、ホスト（LE）形に
/// 置き直す。AF_UNIX のパスは `path_map` 経由。
#[cfg(unix)]
fn sockaddr_in(
    env: &mut BareEnv,
    abi: &SockAbi,
    addr: u64,
    len: u64,
    path_map: &dyn Fn(&[u8]) -> Option<Vec<u8>>,
) -> Result<polyisa_host::SockAddr, u32> {
    if !(2..=128).contains(&len) {
        return Err(errno::EINVAL);
    }
    let mut bytes = vec![0u8; len as usize];
    if !rd(env, addr, &mut bytes) {
        return Err(errno::EFAULT);
    }
    // family はゲストエンディアンの u16。
    let fam = match abi.endian {
        Endian::Le => u16::from_le_bytes([bytes[0], bytes[1]]),
        Endian::Be => u16::from_be_bytes([bytes[0], bytes[1]]),
    };
    bytes[0..2].copy_from_slice(&fam.to_le_bytes());
    if fam == 1 {
        // AF_UNIX: パスをゲスト名からホスト名へ写し直す。
        let Some(mapped) = path_map(&bytes[2..]) else {
            return Err(errno::EAFNOSUPPORT);
        };
        let total = 2 + mapped.len();
        if total > 128 {
            return Err(errno::EINVAL);
        }
        let mut out = vec![0u8; total];
        out[0..2].copy_from_slice(&1u16.to_le_bytes());
        out[2..].copy_from_slice(&mapped);
        bytes = out;
    }
    Ok(polyisa_host::SockAddr {
        bytes: {
            let mut b = [0u8; 128];
            b[..bytes.len()].copy_from_slice(&bytes);
            b
        },
        len: bytes.len() as u32,
    })
}

/// ホストの SockAddr をゲストの sockaddr へ書く。`*addrlen` は
/// 値結果（呼び出し時にバッファ幅、返りに実長）。
#[cfg(unix)]
fn sockaddr_out(
    env: &mut BareEnv,
    abi: &SockAbi,
    sa: &polyisa_host::SockAddr,
    addr: u64,
    addrlen: u64,
) -> Result<(), u32> {
    let mut bytes = sa.bytes[..sa.len as usize].to_vec();
    if abi.endian == Endian::Be && bytes.len() >= 2 {
        bytes[0..2].reverse();
    }
    let n = if addrlen != 0 {
        let cap = match rd_u(env, abi.endian, addrlen, 4) {
            Some(c) => c as usize,
            None => return Err(errno::EFAULT),
        };
        bytes.len().min(cap)
    } else {
        bytes.len()
    };
    if addr != 0 && !wr(env, addr, &bytes[..n]) {
        return Err(errno::EFAULT);
    }
    if addrlen != 0 && !wr_u(env, abi.endian, addrlen, sa.len as u64, 4) {
        return Err(errno::EFAULT);
    }
    Ok(())
}

/// ホストエラーを generic errno に粗く写す。
#[cfg(unix)]
fn host_errno(e: &std::io::Error) -> u32 {
    use std::io::ErrorKind as K;
    match e.kind() {
        K::WouldBlock => errno::EAGAIN,
        K::Interrupted => errno::EINTR,
        K::AddrInUse => errno::EADDRINUSE,
        K::AddrNotAvailable => errno::EADDRNOTAVAIL,
        K::ConnectionRefused => errno::ECONNREFUSED,
        K::ConnectionReset | K::ConnectionAborted => errno::ECONNRESET,
        K::NotConnected => errno::ENOTCONN,
        K::BrokenPipe => errno::EPIPE,
        K::TimedOut => errno::ETIMEDOUT,
        K::PermissionDenied => 1,
        K::NotFound => errno::EADDRNOTAVAIL,
        K::InvalidInput => errno::EINVAL,
        _ => match e.raw_os_error() {
            // 生の errno が asm-generic と同じ体系ならそのまま。
            Some(v) if v > 0 => v as u32,
            _ => errno::EINVAL,
        },
    }
}

/// ESOCKTNOSUPPORT（asm-generic 94）。
pub const ESOCKTNOSUPPORT: u32 = 94;

/// socket(domain, type, protocol)。
/// SOCK_NONBLOCK/SOCK_CLOEXEC を type から剥がす。
// ホストソケットを持てない OS ではホスト側だけの引数を使わない。
#[cfg_attr(not(unix), allow(unused_variables))]
pub fn sys_socket(
    fds: &mut FdTable,
    abi: &SockAbi,
    domain: u64,
    ty: u64,
    proto: u64,
) -> Result<u64, u32> {
    let cloexec = ty & abi.sock_cloexec != 0;
    let nonblock = ty & abi.sock_nonblock != 0;
    let base = ty & !(abi.sock_nonblock | abi.sock_cloexec);
    if base != 1 && base != 2 {
        return Err(ESOCKTNOSUPPORT);
    }
    if domain != 1 && domain != 2 && domain != 10 {
        return Err(errno::EAFNOSUPPORT);
    }
    #[cfg(unix)]
    {
        return match polyisa_host::sock::socket(domain as i32, base as i32, proto as i32) {
            Ok(s) => {
                let fd = fds.alloc_ent(FdEnt {
                    target: fds.host_sock(s, nonblock),
                    path: None,
                    cloexec,
                });
                Ok(fd as u64)
            }
            Err(e) => Err(host_errno(&e)),
        };
    }
    #[allow(unreachable_code)]
    Err(errno::EAFNOSUPPORT)
}

/// socketpair(domain, type, protocol, sv)。sv は int[2] のゲスト領域。
/// カーネル内の `PairSock` で実現する（AF_UNIX のみ）。
pub fn sys_socketpair(
    fds: &mut FdTable,
    abi: &SockAbi,
    env: &mut BareEnv,
    domain: u64,
    ty: u64,
    _proto: u64,
    sv: u64,
) -> Result<u64, u32> {
    let cloexec = ty & abi.sock_cloexec != 0;
    let nonblock = ty & abi.sock_nonblock != 0;
    let base = ty & !(abi.sock_nonblock | abi.sock_cloexec);
    if domain != 1 || (base != 1 && base != 2) {
        return Err(errno::EAFNOSUPPORT);
    }
    let (a, b) = fds.socket_pair(base == 2);
    let ent = |target| FdEnt {
        target,
        path: None,
        cloexec,
    };
    let fa = fds.alloc_ent(ent(a));
    let fb = fds.alloc_ent(ent(b));
    if nonblock {
        fds.set_nonblock(fa, true);
        fds.set_nonblock(fb, true);
    }
    let mut buf = [0u8; 8];
    buf[0..4].copy_from_slice(&fa.to_le_bytes());
    buf[4..8].copy_from_slice(&fb.to_le_bytes());
    if abi.endian == Endian::Be {
        buf[0..4].reverse();
        buf[4..8].reverse();
    }
    if !wr(env, sv, &buf) {
        // 書けなければ両方閉じる。
        let ta = fds.take(fa).map(|e| e.target);
        let tb = fds.take(fb).map(|e| e.target);
        for t in [ta, tb].into_iter().flatten() {
            let _ = fds.close_target(&t);
        }
        return Err(errno::EFAULT);
    }
    Ok(0)
}

/// fd が指すものがソケット系対象でなければ ENOTSOCK。
fn want_sock(fds: &FdTable, fd: u32) -> Result<(), u32> {
    match fds.target(fd) {
        None => Err(errno::EBADF),
        Some(FdTarget::PairSock { .. }) => Ok(()),
        #[cfg(unix)]
        Some(FdTarget::HostSock(_)) => Ok(()),
        Some(_) => Err(errno::ENOTSOCK),
    }
}

/// bind(fd, addr, addrlen)。ホストソケットだけが対象。
/// `path_map` は AF_UNIX のゲストパス（NUL 終端か len 指定）を
/// ホスト sockaddr_un のパス部バイト列へ写す。None なら
/// AF_UNIX を受け付けない。
#[cfg(unix)]
pub fn sys_bind(
    fds: &mut FdTable,
    abi: &SockAbi,
    env: &mut BareEnv,
    fd: u64,
    addr: u64,
    addrlen: u64,
    path_map: &dyn Fn(&[u8]) -> Option<Vec<u8>>,
) -> Result<u64, u32> {
    let fd = fd as u32;
    want_sock(fds, fd)?;
    let Some(s) = fds.host_sock_of(fd) else {
        return Err(errno::EOPNOTSUPP);
    };
    let sa = sockaddr_in(env, abi, addr, addrlen, path_map)?;
    polyisa_host::sock::bind(&s.sock, &sa)
        .map(|()| 0)
        .map_err(|e| host_errno(&e))
}

/// listen(fd, backlog)。
#[cfg(unix)]
pub fn sys_listen(fds: &mut FdTable, _abi: &SockAbi, fd: u64, backlog: u64) -> Result<u64, u32> {
    let fd = fd as u32;
    want_sock(fds, fd)?;
    let Some(s) = fds.host_sock_of(fd) else {
        return Err(errno::EOPNOTSUPP);
    };
    polyisa_host::sock::listen(&s.sock, backlog.min(i32::MAX as u64) as i32)
        .map(|()| 0)
        .map_err(|e| host_errno(&e))
}

/// connect(fd, addr, addrlen)。EINPROGRESS は POLLOUT 待ちへ写す。
#[cfg(unix)]
pub fn sys_connect(
    fds: &mut FdTable,
    abi: &SockAbi,
    env: &mut BareEnv,
    fd: u64,
    addr: u64,
    addrlen: u64,
    path_map: &dyn Fn(&[u8]) -> Option<Vec<u8>>,
) -> Result<Out, u32> {
    let fd = fd as u32;
    want_sock(fds, fd)?;
    let Some(s) = fds.host_sock_of(fd) else {
        // カーネル内ソケット対は常に接続済み。
        return Ok(Out::Done(0));
    };
    let sa = sockaddr_in(env, abi, addr, addrlen, path_map)?;
    if s.connecting.get() {
        // 接続中の再入（待ち→再実行）。ホストの connect を呼ばず
        // SO_ERROR で完了を読む（実機では可書き後に読む規約）。
        s.connecting.set(false);
        match s.sock.getopt(1, 4) {
            // SOL_SOCKET=1, SO_ERROR=4（ホスト値）。
            Ok(0) => return Ok(Out::Done(0)),
            Ok(e) => {
                return Err(host_errno(&std::io::Error::from_raw_os_error(
                    i32::try_from(e).unwrap_or(-1),
                )));
            }
            Err(e) => return Err(host_errno(&e)),
        }
    }
    match polyisa_host::sock::connect(&s.sock, &sa) {
        Ok(()) => Ok(Out::Done(0)),
        Err(e) => {
            let raw = e.raw_os_error().unwrap_or(-1);
            if raw == 115 {
                // EINPROGRESS（ホスト errno 値と仮定。unix では asm-generic と同値）。
                s.connecting.set(true);
                // 非阻止なら EINPROGRESS をゲストへ返す。阻止なら
                // POLLOUT まで待ってから SO_ERROR で完了を見る。
                if guest_nonblock(fds, fd) {
                    return Err((abi.errno)(errno::EINPROGRESS));
                }
                return Ok(Out::Wait(Wait {
                    fds: vec![(fd, WANT_WRITE)],
                    deadline: None,
                }));
            }
            Err(host_errno(&e))
        }
    }
}

/// accept/accept4(fd, addr, addrlen, flags)。flags は accept4 のもの
/// （SOCK_NONBLOCK/SOCK_CLOEXEC）。EAGAIN は POLLIN 待ちへ写す。
#[cfg(unix)]
pub fn sys_accept(
    fds: &mut FdTable,
    abi: &SockAbi,
    env: &mut BareEnv,
    fd: u64,
    addr: u64,
    addrlen: u64,
    flags: u64,
) -> Result<Out, u32> {
    let fd = fd as u32;
    want_sock(fds, fd)?;
    if flags & !(abi.sock_nonblock | abi.sock_cloexec) != 0 {
        return Err(errno::EINVAL);
    }
    let Some(s) = fds.host_sock_of(fd) else {
        // ソケット対の端は受付対象ではない。
        return Err(errno::EOPNOTSUPP);
    };
    match polyisa_host::sock::accept(&s.sock) {
        Ok((ns, sa)) => {
            if addr != 0
                && let Some(sa) = &sa
            {
                sockaddr_out(env, abi, sa, addr, addrlen)?;
            }
            let cloexec = flags & abi.sock_cloexec != 0;
            let nonblock = flags & abi.sock_nonblock != 0;
            let nfd = fds.alloc_ent(FdEnt {
                target: fds.host_sock(ns, nonblock),
                path: None,
                cloexec,
            });
            Ok(Out::Done(nfd as u64))
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            if guest_nonblock(fds, fd) {
                Err(errno::EAGAIN)
            } else {
                Ok(Out::Wait(Wait {
                    fds: vec![(fd, WANT_READ)],
                    deadline: None,
                }))
            }
        }
        Err(e) => Err(host_errno(&e)),
    }
}

/// getsockname/getpeername。`peer` が真なら対側。
#[cfg(unix)]
pub fn sys_getname(
    fds: &mut FdTable,
    abi: &SockAbi,
    env: &mut BareEnv,
    fd: u64,
    addr: u64,
    addrlen: u64,
    peer: bool,
) -> Result<u64, u32> {
    let fd = fd as u32;
    want_sock(fds, fd)?;
    match fds.host_sock_of(fd) {
        Some(s) => match s.sock.sockname(peer) {
            Ok(sa) => {
                sockaddr_out(env, abi, &sa, addr, addrlen)?;
                Ok(0)
            }
            Err(e) => Err(host_errno(&e)),
        },
        None => {
            // ソケット対: 名前は持たない（AF_UNIX・無名）。
            if peer {
                return Err(errno::ENOTCONN);
            }
            let sa = polyisa_host::SockAddr {
                bytes: {
                    let mut b = [0u8; 128];
                    b[0..2].copy_from_slice(&1u16.to_le_bytes());
                    b
                },
                len: 2,
            };
            sockaddr_out(env, abi, &sa, addr, addrlen)?;
            Ok(0)
        }
    }
}

/// shutdown(fd, how)。how は SHUT_RD=0・SHUT_WR=1・SHUT_RDWR=2。
pub fn sys_shutdown(fds: &mut FdTable, _abi: &SockAbi, fd: u64, how: u64) -> Result<u64, u32> {
    let fd = fd as u32;
    want_sock(fds, fd)?;
    if how > 2 {
        return Err(errno::EINVAL);
    }
    if let Some((pair, end)) = fds.pair_of(fd) {
        return if pair.borrow_mut().shutdown(end, how as u32) {
            Ok(0)
        } else {
            Err(errno::ENOTCONN)
        };
    }
    #[cfg(unix)]
    if let Some(s) = fds.host_sock_of(fd) {
        return s
            .sock
            .shutdown(how as i32)
            .map(|()| 0)
            .map_err(|e| host_errno(&e));
    }
    Err(errno::ENOTSOCK)
}

/// fd がゲスト側で非阻止と見えるか。
fn guest_nonblock(fds: &FdTable, fd: u32) -> bool {
    fds.nonblock(fd)
}

/// send(fd, buf, len, flags) と sendto（宛先つき）。PairSock/HostSock
/// の両方を扱う。`Wait` は POLLOUT。
// HostSock の経路は Unix 系ホストだけにある。
#[cfg_attr(not(unix), allow(unused_variables))]
#[allow(clippy::too_many_arguments)]
pub fn sys_sendto(
    fds: &mut FdTable,
    abi: &SockAbi,
    env: &mut BareEnv,
    fd: u64,
    buf: u64,
    len: u64,
    flags: u64,
    addr: u64,
    addrlen: u64,
    path_map: &dyn Fn(&[u8]) -> Option<Vec<u8>>,
) -> Result<Out, u32> {
    let fd = fd as u32;
    want_sock(fds, fd)?;
    let data = {
        let n = usize::try_from(len.min(65536)).unwrap_or(0);
        let mut b = vec![0u8; n];
        if n > 0 && !rd(env, buf, &mut b) {
            return Err(errno::EFAULT);
        }
        b
    };
    let again = flags & abi.msg_dontwait != 0;
    let wait = |fd: u32| -> Result<Out, u32> {
        Ok(Out::Wait(Wait {
            fds: vec![(fd, WANT_WRITE)],
            deadline: None,
        }))
    };
    if let Some((pair, end)) = fds.pair_of(fd) {
        match pair.borrow_mut().send(end, &data) {
            Some(n) => return Ok(Out::Done(n as u64)),
            None => return Err(errno::EPIPE),
        }
    }
    #[cfg(unix)]
    if let Some(s) = fds.host_sock_of(fd) {
        let r = if addr != 0 {
            let sa = sockaddr_in(env, abi, addr, addrlen, path_map)?;
            s.sock.sendto(&data, &sa)
        } else {
            s.sock.send(&data)
        };
        return match r {
            Ok(n) => Ok(Out::Done(n as u64)),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if again || guest_nonblock(fds, fd) {
                    Err(errno::EAGAIN)
                } else {
                    wait(fd)
                }
            }
            Err(e) => Err(host_errno(&e)),
        };
    }
    Err(errno::ENOTSOCK)
}

/// recv(fd, buf, len, flags) と recvfrom（出所の返しつき）。
/// `Wait` は POLLIN。msg_peek は未対応（受理して EOPNOTSUPP）。
// HostSock の経路は Unix 系ホストだけにある。
#[cfg_attr(not(unix), allow(unused_variables))]
#[allow(clippy::too_many_arguments)]
pub fn sys_recvfrom(
    fds: &mut FdTable,
    abi: &SockAbi,
    env: &mut BareEnv,
    fd: u64,
    buf: u64,
    len: u64,
    flags: u64,
    addr: u64,
    addrlen: u64,
) -> Result<Out, u32> {
    let fd = fd as u32;
    want_sock(fds, fd)?;
    if flags & 0x2 != 0 {
        // MSG_PEEK（generic 値 2）。
        return Err(errno::EOPNOTSUPP);
    }
    let max = usize::try_from(len.min(65536)).unwrap_or(0);
    let again = flags & abi.msg_dontwait != 0;
    if let Some((pair, end)) = fds.pair_of(fd) {
        use polyisa_kernel::PipeRead;
        return match pair.borrow_mut().recv(end, max) {
            PipeRead::Bytes(b) => {
                if !wr(env, buf, &b) {
                    return Err(errno::EFAULT);
                }
                Ok(Out::Done(b.len() as u64))
            }
            PipeRead::Eof => Ok(Out::Done(0)),
            PipeRead::Empty => {
                if again || guest_nonblock(fds, fd) {
                    Err(errno::EAGAIN)
                } else {
                    Ok(Out::Wait(Wait {
                        fds: vec![(fd, WANT_READ)],
                        deadline: None,
                    }))
                }
            }
        };
    }
    #[cfg(unix)]
    if let Some(s) = fds.host_sock_of(fd) {
        let r = if addr != 0 {
            s.sock.recvfrom(max)
        } else {
            s.sock.recv(max).map(|b| (b, None))
        };
        return match r {
            Ok((b, sa)) => {
                if !wr(env, buf, &b) {
                    return Err(errno::EFAULT);
                }
                if addr != 0
                    && let Some(sa) = &sa
                {
                    sockaddr_out(env, abi, sa, addr, addrlen)?;
                }
                Ok(Out::Done(b.len() as u64))
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if again || guest_nonblock(fds, fd) {
                    Err(errno::EAGAIN)
                } else {
                    Ok(Out::Wait(Wait {
                        fds: vec![(fd, WANT_READ)],
                        deadline: None,
                    }))
                }
            }
            Err(e) => Err(host_errno(&e)),
        };
    }
    Err(errno::ENOTSOCK)
}

/// setsockopt(fd, level, optname, optval, optlen)。ホストソケットだけ
/// が対象。optval は u32 として読む。
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
pub fn sys_setsockopt(
    fds: &mut FdTable,
    abi: &SockAbi,
    env: &mut BareEnv,
    fd: u64,
    level: u64,
    name: u64,
    val: u64,
    len: u64,
) -> Result<u64, u32> {
    let fd = fd as u32;
    want_sock(fds, fd)?;
    let Some(s) = fds.host_sock_of(fd) else {
        return Err(errno::ENOPROTOOPT);
    };
    let host_name = (abi.so_to_host)(name as u32);
    if host_name < 0 {
        return Err(errno::ENOPROTOOPT);
    }
    if len < 4 {
        return Err(errno::EINVAL);
    }
    let v = rd_u(env, abi.endian, val, 4).ok_or(errno::EFAULT)? as u32;
    s.sock
        .setopt(level as i32, host_name, v)
        .map(|()| 0)
        .map_err(|e| host_errno(&e))
}

/// getsockopt(fd, level, optname, optval, optlen)。値は u32 で書く。
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
pub fn sys_getsockopt(
    fds: &mut FdTable,
    abi: &SockAbi,
    env: &mut BareEnv,
    fd: u64,
    level: u64,
    name: u64,
    val: u64,
    len: u64,
) -> Result<u64, u32> {
    let fd = fd as u32;
    want_sock(fds, fd)?;
    let Some(s) = fds.host_sock_of(fd) else {
        return Err(errno::ENOPROTOOPT);
    };
    let host_name = (abi.so_to_host)(name as u32);
    if host_name < 0 {
        return Err(errno::ENOPROTOOPT);
    }
    match s.sock.getopt(level as i32, host_name) {
        Ok(v) => {
            // SO_ERROR の値はホスト errno。generic 経由で ABI の
            // errno 空間へ写してからゲストへ書く。
            let out = if level as i32 == 1 && host_name == 4 {
                let g = host_errno(&std::io::Error::from_raw_os_error(
                    i32::try_from(v).unwrap_or(-1),
                ));
                u64::from((abi.errno)(g))
            } else {
                v as u64
            };
            if !wr_u(env, abi.endian, val, out, 4) {
                return Err(errno::EFAULT);
            }
            if len != 0 && !wr_u(env, abi.endian, len, 4, 4) {
                return Err(errno::EFAULT);
            }
            Ok(0)
        }
        Err(e) => Err(host_errno(&e)),
    }
}

/// iovec を読む。（（base, len）の列）。
fn read_iov(env: &mut BareEnv, abi: &SockAbi, iov: u64, cnt: u64) -> Result<Vec<(u64, u64)>, u32> {
    if cnt == 0 || cnt > 1024 {
        return Err(errno::EINVAL);
    }
    let item = (abi.ptr_size as u64) * 2;
    let mut out = Vec::with_capacity(cnt as usize);
    for i in 0..cnt {
        let base = rd_ptr(env, abi.endian, abi.ptr_size, iov + i * item).ok_or(errno::EFAULT)?;
        let len = rd_ptr(
            env,
            abi.endian,
            abi.ptr_size,
            iov + i * item + abi.ptr_size as u64,
        )
        .ok_or(errno::EFAULT)?;
        out.push((base, len));
    }
    Ok(out)
}

/// sendmsg(fd, msg, flags)。msghdr: {name, namelen(u64/u32), iov, iovlen, control, controllen, flags}。
/// 制御メッセージ（SCM_RIGHTS 等）は読み捨てる近似。
// HostSock の経路は Unix 系ホストだけにある。
#[cfg_attr(not(unix), allow(unused_variables))]
pub fn sys_sendmsg(
    fds: &mut FdTable,
    abi: &SockAbi,
    env: &mut BareEnv,
    fd: u64,
    msg: u64,
    flags: u64,
    path_map: &dyn Fn(&[u8]) -> Option<Vec<u8>>,
) -> Result<Out, u32> {
    let p = abi.ptr_size as u64;
    let name = rd_ptr(env, abi.endian, abi.ptr_size, msg).ok_or(errno::EFAULT)?;
    let namelen = rd_u(env, abi.endian, msg + p, 4).ok_or(errno::EFAULT)?;
    let iov = rd_ptr(env, abi.endian, abi.ptr_size, msg + p * 2).ok_or(errno::EFAULT)?;
    let iovlen = rd_ptr(env, abi.endian, abi.ptr_size, msg + p * 3).ok_or(errno::EFAULT)?;
    let iovs = read_iov(env, abi, iov, iovlen)?;
    // 全部連結して一つの送信にする（dgram の境界維持のため）。
    let total: u64 = iovs.iter().map(|&(_, l)| l).sum();
    if total > 65536 {
        return Err(errno::EMSGSIZE);
    }
    let mut data = Vec::with_capacity(total as usize);
    for (base, len) in iovs {
        let mut b = vec![0u8; len as usize];
        if !rd(env, base, &mut b) {
            return Err(errno::EFAULT);
        }
        data.extend_from_slice(&b);
    }
    // sendto と同じ宛先解釈。
    let fd32 = fd as u32;
    want_sock(fds, fd32)?;
    if let Some((pair, end)) = fds.pair_of(fd32) {
        return match pair.borrow_mut().send(end, &data) {
            Some(n) => Ok(Out::Done(n as u64)),
            None => Err(errno::EPIPE),
        };
    }
    #[cfg(unix)]
    if let Some(s) = fds.host_sock_of(fd32) {
        let r = if name != 0 {
            let sa = sockaddr_in(env, abi, name, namelen, path_map)?;
            s.sock.sendto(&data, &sa)
        } else {
            s.sock.send(&data)
        };
        return match r {
            Ok(n) => Ok(Out::Done(n as u64)),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if flags & abi.msg_dontwait != 0 || guest_nonblock(fds, fd32) {
                    Err(errno::EAGAIN)
                } else {
                    Ok(Out::Wait(Wait {
                        fds: vec![(fd32, WANT_WRITE)],
                        deadline: None,
                    }))
                }
            }
            Err(e) => Err(host_errno(&e)),
        };
    }
    Err(errno::ENOTSOCK)
}

/// recvmsg(fd, msg, flags)。出所と受け取った旗を msg へ書き戻す。
// HostSock の経路は Unix 系ホストだけにある。
#[cfg_attr(not(unix), allow(unused_variables))]
pub fn sys_recvmsg(
    fds: &mut FdTable,
    abi: &SockAbi,
    env: &mut BareEnv,
    fd: u64,
    msg: u64,
    flags: u64,
) -> Result<Out, u32> {
    let p = abi.ptr_size as u64;
    let name = rd_ptr(env, abi.endian, abi.ptr_size, msg).ok_or(errno::EFAULT)?;
    let namelen_addr = msg + p;
    let iov = rd_ptr(env, abi.endian, abi.ptr_size, msg + p * 2).ok_or(errno::EFAULT)?;
    let iovlen = rd_ptr(env, abi.endian, abi.ptr_size, msg + p * 3).ok_or(errno::EFAULT)?;
    // controllen: {name(8/4), namelen(4), iov, iovlen, control, controllen, flags}
    // 構造は p*4 以降に control・p*5 に controllen・p*6 に flags（64bit）。
    // 32bit では u32 並びで同じ配置になる（name,namelen,iov,iovlen,control,controllen,flags の
    // ptr 幅の列）。msg_flags は末尾 u32。
    let fd32 = fd as u32;
    want_sock(fds, fd32)?;
    // msg_flags を末尾に書き戻す（MSG_TRUNC 等の詳細は近似で 0）。
    let flags_addr = msg + p * 6;
    let wr_flags = |env: &mut BareEnv| -> Result<(), u32> {
        if wr_u(env, abi.endian, flags_addr, 0, 4) {
            Ok(())
        } else {
            Err(errno::EFAULT)
        }
    };
    if iovlen == 0 {
        wr_flags(env)?;
        return Ok(Out::Done(0));
    }
    let iovs = read_iov(env, abi, iov, iovlen)?;
    let total: u64 = iovs.iter().map(|&(_, l)| l).sum();
    let max = usize::try_from(total.min(65536)).unwrap_or(0);
    let again = flags & abi.msg_dontwait != 0;

    // 受け取ったバイト列を iovec へ散らす。
    let scatter = |env: &mut BareEnv, b: &[u8]| -> bool {
        let mut off = 0usize;
        for (base, len) in &iovs {
            let take = (*len as usize).min(b.len() - off);
            if take > 0 && !wr(env, *base, &b[off..off + take]) {
                return false;
            }
            off += take;
            if off >= b.len() {
                break;
            }
        }
        true
    };

    if let Some((pair, end)) = fds.pair_of(fd32) {
        use polyisa_kernel::PipeRead;
        return match pair.borrow_mut().recv(end, max) {
            PipeRead::Bytes(b) => {
                if !scatter(env, &b) {
                    return Err(errno::EFAULT);
                }
                wr_flags(env)?;
                Ok(Out::Done(b.len() as u64))
            }
            PipeRead::Eof => {
                wr_flags(env)?;
                Ok(Out::Done(0))
            }
            PipeRead::Empty => {
                if again || guest_nonblock(fds, fd32) {
                    Err(errno::EAGAIN)
                } else {
                    Ok(Out::Wait(Wait {
                        fds: vec![(fd32, WANT_READ)],
                        deadline: None,
                    }))
                }
            }
        };
    }
    #[cfg(unix)]
    if let Some(s) = fds.host_sock_of(fd32) {
        return match s.sock.recvfrom(max) {
            Ok((b, sa)) => {
                if !scatter(env, &b) {
                    return Err(errno::EFAULT);
                }
                if name != 0
                    && let Some(sa) = &sa
                {
                    sockaddr_out(env, abi, sa, name, namelen_addr)?;
                }
                wr_flags(env)?;
                Ok(Out::Done(b.len() as u64))
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if again || guest_nonblock(fds, fd32) {
                    Err(errno::EAGAIN)
                } else {
                    Ok(Out::Wait(Wait {
                        fds: vec![(fd32, WANT_READ)],
                        deadline: None,
                    }))
                }
            }
            Err(e) => Err(host_errno(&e)),
        };
    }
    Err(errno::ENOTSOCK)
}

/// socketcall の副番号（include/linux/net.h）。
pub mod call {
    pub const SOCKET: u64 = 1;
    pub const BIND: u64 = 2;
    pub const CONNECT: u64 = 3;
    pub const LISTEN: u64 = 4;
    pub const ACCEPT: u64 = 5;
    pub const GETSOCKNAME: u64 = 6;
    pub const GETPEERNAME: u64 = 7;
    pub const SOCKETPAIR: u64 = 8;
    pub const SEND: u64 = 9;
    pub const RECV: u64 = 10;
    pub const SENDTO: u64 = 11;
    pub const RECVFROM: u64 = 12;
    pub const SHUTDOWN: u64 = 13;
    pub const SETSOCKOPT: u64 = 14;
    pub const GETSOCKOPT: u64 = 15;
    pub const SENDMSG: u64 = 16;
    pub const RECVMSG: u64 = 17;
    pub const ACCEPT4: u64 = 18;
}

/// socketcall(call, args) の展開。`args` は u32 の列を指す
/// ゲストポインタ。副番号ごとの引数語を読んで本体へ渡す。
/// i386・m68k・power・s390・superh・sparc・mips o32 が使う。
/// socketcall の引数は常に u32 列（32ビット ABI 専用）。
pub fn sys_socketcall(
    fds: &mut FdTable,
    abi: &SockAbi,
    env: &mut BareEnv,
    call: u64,
    argsp: u64,
    path_map: &dyn Fn(&[u8]) -> Option<Vec<u8>>,
) -> Result<Out, u32> {
    // 引数語を先に全部読む（env を closure に貸すと呼び出し側と
    // 借用が衝突するため）。
    let mut a = [0u64; 6];
    for (i, slot) in a.iter_mut().enumerate() {
        *slot = rd_u(env, abi.endian, argsp + i as u64 * 4, 4).ok_or(errno::EFAULT)?;
    }
    match call {
        call::SOCKET => sys_socket(fds, abi, a[0], a[1], a[2]).map(Out::Done),
        #[cfg(unix)]
        call::BIND => sys_bind(fds, abi, env, a[0], a[1], a[2], path_map).map(Out::Done),
        #[cfg(unix)]
        call::CONNECT => sys_connect(fds, abi, env, a[0], a[1], a[2], path_map),
        #[cfg(unix)]
        call::LISTEN => sys_listen(fds, abi, a[0], a[1]).map(Out::Done),
        #[cfg(unix)]
        call::ACCEPT => sys_accept(fds, abi, env, a[0], a[1], a[2], 0),
        #[cfg(unix)]
        call::GETSOCKNAME => sys_getname(fds, abi, env, a[0], a[1], a[2], false).map(Out::Done),
        #[cfg(unix)]
        call::GETPEERNAME => sys_getname(fds, abi, env, a[0], a[1], a[2], true).map(Out::Done),
        call::SOCKETPAIR => sys_socketpair(fds, abi, env, a[0], a[1], a[2], a[3]).map(Out::Done),
        call::SEND => sys_sendto(fds, abi, env, a[0], a[1], a[2], a[3], 0, 0, path_map),
        call::RECV => sys_recvfrom(fds, abi, env, a[0], a[1], a[2], a[3], 0, 0),
        call::SENDTO => sys_sendto(fds, abi, env, a[0], a[1], a[2], a[3], a[4], a[5], path_map),
        call::RECVFROM => sys_recvfrom(fds, abi, env, a[0], a[1], a[2], a[3], a[4], a[5]),
        call::SHUTDOWN => sys_shutdown(fds, abi, a[0], a[1]).map(Out::Done),
        #[cfg(unix)]
        call::SETSOCKOPT => {
            sys_setsockopt(fds, abi, env, a[0], a[1], a[2], a[3], a[4]).map(Out::Done)
        }
        #[cfg(unix)]
        call::GETSOCKOPT => {
            sys_getsockopt(fds, abi, env, a[0], a[1], a[2], a[3], a[4]).map(Out::Done)
        }
        call::SENDMSG => sys_sendmsg(fds, abi, env, a[0], a[1], a[2], path_map),
        call::RECVMSG => sys_recvmsg(fds, abi, env, a[0], a[1], a[2]),
        #[cfg(unix)]
        call::ACCEPT4 => sys_accept(fds, abi, env, a[0], a[1], a[2], a[3]),
        _ => Err(errno::EINVAL),
    }
}

/// syscall 名による振り分け。ソケット系の名前でなければ `None`。
/// `args` は ABI が読み出した 6 個の引数語。`send`/`recv` は
/// 宛先なしの `sendto`/`recvfrom` として処理する（x86-64 のように
/// 個別番号を持たない ABI でも同じ入口を使う）。
#[allow(clippy::too_many_arguments)]
pub fn dispatch(
    fds: &mut FdTable,
    abi: &SockAbi,
    env: &mut BareEnv,
    name: &str,
    args: &[u64; 6],
    path_map: &dyn Fn(&[u8]) -> Option<Vec<u8>>,
) -> Option<Result<Out, u32>> {
    let r: Result<Out, u32> = match name {
        "socket" => sys_socket(fds, abi, args[0], args[1], args[2]).map(Out::Done),
        "socketpair" => {
            sys_socketpair(fds, abi, env, args[0], args[1], args[2], args[3]).map(Out::Done)
        }
        #[cfg(unix)]
        "bind" => sys_bind(fds, abi, env, args[0], args[1], args[2], path_map).map(Out::Done),
        #[cfg(unix)]
        "connect" => sys_connect(fds, abi, env, args[0], args[1], args[2], path_map),
        #[cfg(unix)]
        "listen" => sys_listen(fds, abi, args[0], args[1]).map(Out::Done),
        #[cfg(unix)]
        "accept" => sys_accept(fds, abi, env, args[0], args[1], args[2], 0),
        #[cfg(unix)]
        "accept4" => sys_accept(fds, abi, env, args[0], args[1], args[2], args[3]),
        #[cfg(unix)]
        "getsockname" => {
            sys_getname(fds, abi, env, args[0], args[1], args[2], false).map(Out::Done)
        }
        #[cfg(unix)]
        "getpeername" => sys_getname(fds, abi, env, args[0], args[1], args[2], true).map(Out::Done),
        "shutdown" => sys_shutdown(fds, abi, args[0], args[1]).map(Out::Done),
        "send" | "sendto" => sys_sendto(
            fds, abi, env, args[0], args[1], args[2], args[3], args[4], args[5], path_map,
        ),
        "recv" | "recvfrom" => sys_recvfrom(
            fds, abi, env, args[0], args[1], args[2], args[3], args[4], args[5],
        ),
        "sendmsg" => sys_sendmsg(fds, abi, env, args[0], args[1], args[2], path_map),
        "recvmsg" => sys_recvmsg(fds, abi, env, args[0], args[1], args[2]),
        #[cfg(unix)]
        "setsockopt" => sys_setsockopt(fds, abi, env, args[0], args[1], args[2], args[3], args[4])
            .map(Out::Done),
        #[cfg(unix)]
        "getsockopt" => sys_getsockopt(fds, abi, env, args[0], args[1], args[2], args[3], args[4])
            .map(Out::Done),
        "socketcall" => sys_socketcall(fds, abi, env, args[0], args[1], path_map),
        _ => return None,
    };
    Some(r)
}

/// 単一スレッド ABI のための `dispatch` 駆動。`Wait` が返ったら
/// `serve_wait` で眠り、成立したら同じ呼び出しを最初から再実行
/// する（再起動規約は x86 の駐車と同じ）。進行不能な待ちは
/// `Err(EDEADLK)` で戻す — ABI はデッドロック報告へ写す。
/// 戻り値の `Err` は asm-generic errno（ABI が `SockAbi::errno`
/// で写す）。
#[allow(clippy::too_many_arguments)]
pub fn drive(
    fds: &mut FdTable,
    abi: &SockAbi,
    env: &mut BareEnv,
    name: &str,
    args: &[u64; 6],
    path_map: &dyn Fn(&[u8]) -> Option<Vec<u8>>,
    pending: u64,
    mono_ns: &dyn Fn() -> u64,
) -> Option<Result<u64, u32>> {
    let mut r = dispatch(fds, abi, env, name, args, path_map)?;
    loop {
        match r {
            Ok(Out::Done(v)) => return Some(Ok(v)),
            Err(e) => return Some(Err(e)),
            Ok(Out::Wait(w)) => {
                match crate::wait::serve(fds, &w, pending, mono_ns) {
                    crate::wait::Served::Ready => {
                        r = dispatch(fds, abi, env, name, args, path_map)
                            .unwrap_or(Err(errno::EINVAL));
                    }
                    // ソケットの待ちは期限を持たないので Expired は
                    // 起きえない。Deadlock と同じく進行不能として戻す。
                    _ => return Some(Err(errno::EDEADLK)),
                }
            }
        }
    }
}

/// AF_UNIX のゲストパス（sockaddr のパス部）をホストの sockaddr_un
/// パス部バイト列へ写す。先頭 NUL の抽象名空間は未対応で None。
// 段階26 残件: 抽象名空間・ホスト FS に残るソケットファイルの近似。
pub fn unix_path_bytes(root: &str, cwd: &str, raw: &[u8]) -> Option<Vec<u8>> {
    if raw.first() == Some(&0) {
        return None;
    }
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let path = String::from_utf8_lossy(&raw[..end]).into_owned();
    let host = crate::guest_path::resolve_guest_path(root, cwd, &path)?;
    let mut b = host.into_bytes();
    b.push(0);
    Some(b)
}

/// AF_UNIX パス写像器を `root`/`cwd` で束縛して作る。中身は
/// 複製なので呼び出し側の借用は戻った時点で切れる（`use<>` で
/// ライフタイム捕捉を明示）。
pub fn unix_path_map(root: &str, cwd: &str) -> impl Fn(&[u8]) -> Option<Vec<u8>> + use<> {
    let root = root.to_string();
    let cwd = cwd.to_string();
    move |raw: &[u8]| unix_path_bytes(&root, &cwd, raw)
}
