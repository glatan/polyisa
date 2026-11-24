// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! ホストのソケット。`std::net` と `std::os::unix` が直に足りない分を
//! 自前の FFI で補う。仮想カーネルの `HostSock` fd 対象と、作業用
//! ホストスレッドの待ちが使う。
//!
//! ソケットは常に非阻止（O_NONBLOCK）にして扱う。阻止が要る呼び出しは
//! 仮想カーネル側が待ちへ写す。
//!
//! 現在の FFI は Linux 向けの値（SOCK_NONBLOCK・accept4・O_NONBLOCK
//! 等の定数）を使う。macOS 等では accept4 と型フラグがないので、
//! そのホストを対象にするときは fcntl による段階適用に書き換える。

// unsafe 許可クレート（docs/design/workspace.md「`unsafe` の扱い」）。

use std::io;
#[cfg(unix)]
pub use std::os::fd::RawFd;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// ホストの fd 番号。非 Unix ホストでは番号系がないので i32 で済ませる。
#[cfg(not(unix))]
pub type RawFd = i32;

/// ホストのソケット記述子。閉じると host の fd も閉じる。
#[cfg(unix)]
#[derive(Debug)]
pub struct SockFd(OwnedFd);

/// 非 Unix ホストではソケットを持てない空の対象。
#[cfg(not(unix))]
#[derive(Debug)]
pub struct SockFd;

/// 非 Unix では全操作が unsupported。`HostIo` 等の汎用コードが
/// 条件分岐なしで呼べるよう形だけ揃える。
#[cfg(not(unix))]
impl SockFd {
    /// 常に -1（無効 fd）。
    #[must_use]
    pub fn raw(&self) -> RawFd {
        -1
    }

    /// 常に unsupported。
    pub fn send(&self, _bytes: &[u8]) -> io::Result<usize> {
        Err(unsupported())
    }

    /// 常に unsupported。
    pub fn recv(&self, _max: usize) -> io::Result<Vec<u8>> {
        Err(unsupported())
    }

    /// 常に偽。
    #[must_use]
    pub fn is_nonblock(&self) -> bool {
        false
    }

    /// 常に unsupported。
    pub fn set_nonblock(&self, _on: bool) -> io::Result<()> {
        Err(unsupported())
    }

    /// 常に unsupported。
    pub fn ready(&self) -> io::Result<SockReady> {
        Err(unsupported())
    }

    /// 常に unsupported。
    pub fn shutdown(&self, _how: u32) -> io::Result<()> {
        Err(unsupported())
    }
}

/// poll の結果（準備状態）。呼び出し側が自分の Ready 型に写す。
#[derive(Clone, Copy, Default, Debug)]
pub struct SockReady {
    /// POLLIN。
    pub read: bool,
    /// POLLOUT。
    pub write: bool,
    /// POLLHUP。
    pub hup: bool,
    /// POLLERR/POLLNVAL。
    pub err: bool,
}

#[cfg(unix)]
impl SockFd {
    /// 既存の RawFd から作る。所有権はこちらへ移る。
    ///
    /// # Safety
    /// `fd` は有効なホスト fd で、他の所有者がいないこと。
    pub unsafe fn from_raw(fd: RawFd) -> Self {
        // SAFETY: 呼び出し側が所有権の唯一性を保証する。
        Self(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// ホストの fd 番号。
    #[must_use]
    pub fn raw(&self) -> RawFd {
        self.0.as_raw_fd()
    }

    /// ホスト fd の複製（dup）。記述は共有する。
    pub fn try_clone(&self) -> io::Result<Self> {
        self.0.try_clone().map(Self)
    }

    /// 非阻止か。
    #[must_use]
    pub fn is_nonblock(&self) -> bool {
        imp::getfl(self.raw())
            .map(|fl| fl & imp::O_NONBLOCK != 0)
            .unwrap_or(false)
    }

    /// O_NONBLOCK を変える。
    pub fn set_nonblock(&self, on: bool) -> io::Result<()> {
        imp::setfl_nonblock(self.raw(), on)
    }

    /// 準備状態の即時照合（`poll` timeout 0）。
    #[must_use]
    pub fn ready(&self) -> SockReady {
        let revents = imp::poll_one(self.raw(), imp::POLLIN | imp::POLLOUT, 0);
        SockReady {
            read: revents & imp::POLLIN != 0,
            write: revents & imp::POLLOUT != 0,
            hup: revents & imp::POLLHUP != 0,
            err: revents & (imp::POLLERR | imp::POLLNVAL) != 0,
        }
    }

    /// `recv`。非阻止なので WouldBlock を返しうる。
    pub fn recv(&self, max: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; max];
        let n = imp::recv(self.raw(), &mut buf, 0)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// `send`。
    pub fn send(&self, bytes: &[u8]) -> io::Result<usize> {
        imp::send(self.raw(), bytes, imp::MSG_NOSIGNAL)
    }

    /// `sendto`。宛先は `SockAddr` の生バイト。
    pub fn sendto(&self, bytes: &[u8], addr: &SockAddr) -> io::Result<usize> {
        imp::sendto(self.raw(), bytes, imp::MSG_NOSIGNAL, addr)
    }

    /// `recvfrom`。宛先を `Some` に入れて返す。
    pub fn recvfrom(&self, max: usize) -> io::Result<(Vec<u8>, Option<SockAddr>)> {
        let mut buf = vec![0u8; max];
        let (n, addr) = imp::recvfrom(self.raw(), &mut buf, 0)?;
        buf.truncate(n);
        Ok((buf, addr))
    }

    /// `shutdown(how)`。
    pub fn shutdown(&self, how: i32) -> io::Result<()> {
        imp::shutdown(self.raw(), how)
    }

    /// `getsockname` / `getpeername`。
    pub fn sockname(&self, peer: bool) -> io::Result<SockAddr> {
        imp::xname(self.raw(), peer)
    }

    /// `getsockopt`（4 バイト値）。
    pub fn getopt(&self, level: i32, name: i32) -> io::Result<u32> {
        imp::getopt(self.raw(), level, name)
    }

    /// `setsockopt`（4 バイト値）。
    pub fn setopt(&self, level: i32, name: i32, value: u32) -> io::Result<()> {
        imp::setopt(self.raw(), level, name, value)
    }
}

/// sockaddr の生バイト列（先頭 2 バイトが family）。
#[derive(Clone, Debug)]
pub struct SockAddr {
    /// sockaddr の内容。`len` が有効バイト数。
    pub bytes: [u8; 128],
    /// 有効長。
    pub len: u32,
}

/// `socket(domain, type, protocol)`。作ったら直ちに非阻止にする。
#[cfg(unix)]
pub fn socket(domain: i32, ty: i32, protocol: i32) -> io::Result<SockFd> {
    let fd = imp::socket(
        domain,
        ty | imp::SOCK_NONBLOCK | imp::SOCK_CLOEXEC,
        protocol,
    )?;
    // SAFETY: socket が返した新しい fd で所有者はここだけ。
    Ok(unsafe { SockFd::from_raw(fd) })
}

#[cfg(not(unix))]
pub fn socket(_domain: i32, _ty: i32, _protocol: i32) -> io::Result<SockFd> {
    Err(unsupported())
}

/// `bind`。
#[cfg(unix)]
pub fn bind(s: &SockFd, addr: &SockAddr) -> io::Result<()> {
    imp::bind(s.raw(), addr)
}

#[cfg(not(unix))]
pub fn bind(_s: &SockFd, _addr: &SockAddr) -> io::Result<()> {
    Err(unsupported())
}

/// `connect`。非阻止ソケットでは EINPROGRESS を返しうる
/// （`io::ErrorKind::WouldBlock`/`InProgress` として報告する）。
#[cfg(unix)]
pub fn connect(s: &SockFd, addr: &SockAddr) -> io::Result<()> {
    imp::connect(s.raw(), addr)
}

#[cfg(not(unix))]
pub fn connect(_s: &SockFd, _addr: &SockAddr) -> io::Result<()> {
    Err(unsupported())
}

/// `listen`。
#[cfg(unix)]
pub fn listen(s: &SockFd, backlog: i32) -> io::Result<()> {
    imp::listen(s.raw(), backlog)
}

#[cfg(not(unix))]
pub fn listen(_s: &SockFd, _backlog: i32) -> io::Result<()> {
    Err(unsupported())
}

/// `accept4`。新しいソケットは非阻止で返す。
#[cfg(unix)]
pub fn accept(s: &SockFd) -> io::Result<(SockFd, Option<SockAddr>)> {
    let (fd, addr) = imp::accept4(s.raw())?;
    // SAFETY: accept4 が返した新しい fd。
    Ok((unsafe { SockFd::from_raw(fd) }, addr))
}

#[cfg(not(unix))]
pub fn accept(_s: &SockFd) -> io::Result<(SockFd, Option<SockAddr>)> {
    Err(unsupported())
}

/// `socketpair`。両端とも非阻止で返す。
#[cfg(unix)]
pub fn socketpair(domain: i32, ty: i32, protocol: i32) -> io::Result<(SockFd, SockFd)> {
    let (a, b) = imp::socketpair(
        domain,
        ty | imp::SOCK_NONBLOCK | imp::SOCK_CLOEXEC,
        protocol,
    )?;
    // SAFETY: socketpair が返した新しい fd 二つ。
    Ok((unsafe { SockFd::from_raw(a) }, unsafe {
        SockFd::from_raw(b)
    }))
}

#[cfg(not(unix))]
pub fn socketpair(_domain: i32, _ty: i32, _protocol: i32) -> io::Result<(SockFd, SockFd)> {
    Err(unsupported())
}

/// ホスト fd の集合を `poll` で待つ。`timeout_ms` <0 は無期限。
/// 返り値は各 fd の revents（`fds` と同じ長さ・順序）。
/// EINTR は内部でやり直す。
#[cfg(unix)]
pub fn poll(fds: &mut [(RawFd, i16)], timeout_ms: i32) -> io::Result<()> {
    imp::poll(fds, timeout_ms)
}

#[cfg(not(unix))]
pub fn poll(_fds: &mut [(RawFd, i16)], _timeout_ms: i32) -> io::Result<()> {
    Err(unsupported())
}

#[cfg(not(unix))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "sockets unsupported on this host",
    )
}

#[cfg(unix)]
mod imp {
    use super::*;
    use std::ffi::c_void;

    mod c {
        use std::ffi::c_void;

        unsafe extern "C" {
            pub fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
            pub fn bind(fd: i32, addr: *const c_void, len: u32) -> i32;
            pub fn connect(fd: i32, addr: *const c_void, len: u32) -> i32;
            pub fn listen(fd: i32, backlog: i32) -> i32;
            pub fn accept4(fd: i32, addr: *mut c_void, len: *mut u32, flags: i32) -> i32;
            pub fn socketpair(domain: i32, ty: i32, protocol: i32, sv: *mut i32) -> i32;
            pub fn send(fd: i32, buf: *const c_void, len: usize, flags: i32) -> isize;
            pub fn sendto(
                fd: i32,
                buf: *const c_void,
                len: usize,
                flags: i32,
                addr: *const c_void,
                addrlen: u32,
            ) -> isize;
            pub fn recv(fd: i32, buf: *mut c_void, len: usize, flags: i32) -> isize;
            pub fn recvfrom(
                fd: i32,
                buf: *mut c_void,
                len: usize,
                flags: i32,
                addr: *mut c_void,
                addrlen: *mut u32,
            ) -> isize;
            pub fn shutdown(fd: i32, how: i32) -> i32;
            pub fn getsockname(fd: i32, addr: *mut c_void, len: *mut u32) -> i32;
            pub fn getpeername(fd: i32, addr: *mut c_void, len: *mut u32) -> i32;
            pub fn getsockopt(
                fd: i32,
                level: i32,
                name: i32,
                val: *mut c_void,
                len: *mut u32,
            ) -> i32;
            pub fn setsockopt(fd: i32, level: i32, name: i32, val: *const c_void, len: u32) -> i32;
            pub fn fcntl(fd: i32, cmd: i32, arg: i32) -> i32;
            pub fn poll(fds: *mut super::PollFd, nfds: u64, timeout: i32) -> i32;
        }
    }

    pub const O_NONBLOCK: i32 = 0o4000;
    pub const SOCK_NONBLOCK: i32 = 0o0004000;
    pub const SOCK_CLOEXEC: i32 = 0o2000000;
    pub const MSG_NOSIGNAL: i32 = 0x4000;
    pub const POLLIN: i16 = 0x001;
    pub const POLLOUT: i16 = 0x004;
    pub const POLLERR: i16 = 0x008;
    pub const POLLHUP: i16 = 0x010;
    pub const POLLNVAL: i16 = 0x020;
    const F_GETFL: i32 = 3;
    const F_SETFL: i32 = 4;

    #[repr(C)]
    struct PollFd {
        fd: i32,
        events: i16,
        revents: i16,
    }

    fn last() -> io::Error {
        io::Error::last_os_error()
    }

    fn cvt(r: i32) -> io::Result<i32> {
        if r < 0 { Err(last()) } else { Ok(r) }
    }

    pub fn socket(domain: i32, ty: i32, protocol: i32) -> io::Result<RawFd> {
        // SAFETY: socket の呼び出し。返り値は新しい fd か -1。
        cvt(unsafe { c::socket(domain, ty, protocol) })
    }

    pub fn bind(fd: RawFd, addr: &SockAddr) -> io::Result<()> {
        // SAFETY: addr は len バイト有効なバッファ。
        cvt(unsafe { c::bind(fd, addr.bytes.as_ptr() as *const c_void, addr.len) }).map(|_| ())
    }

    pub fn connect(fd: RawFd, addr: &SockAddr) -> io::Result<()> {
        cvt(unsafe { c::connect(fd, addr.bytes.as_ptr() as *const c_void, addr.len) }).map(|_| ())
    }

    pub fn listen(fd: RawFd, backlog: i32) -> io::Result<()> {
        cvt(unsafe { c::listen(fd, backlog) }).map(|_| ())
    }

    pub fn accept4(fd: RawFd) -> io::Result<(RawFd, Option<SockAddr>)> {
        let mut addr = SockAddr {
            bytes: [0; 128],
            len: 128,
        };
        let mut len: u32 = 128;
        // SAFETY: addr/len は十分なバッファ。
        let r = cvt(unsafe {
            c::accept4(
                fd,
                addr.bytes.as_mut_ptr() as *mut c_void,
                &mut len,
                SOCK_NONBLOCK | SOCK_CLOEXEC,
            )
        })?;
        addr.len = len;
        Ok((r, Some(addr)))
    }

    pub fn socketpair(domain: i32, ty: i32, protocol: i32) -> io::Result<(RawFd, RawFd)> {
        let mut sv = [0i32; 2];
        // SAFETY: sv は 2 要素のバッファ。
        cvt(unsafe { c::socketpair(domain, ty, protocol, sv.as_mut_ptr()) })?;
        Ok((sv[0], sv[1]))
    }

    pub fn send(fd: RawFd, buf: &[u8], flags: i32) -> io::Result<usize> {
        // SAFETY: buf は len バイト有効。
        let r = unsafe { c::send(fd, buf.as_ptr() as *const c_void, buf.len(), flags) };
        if r < 0 { Err(last()) } else { Ok(r as usize) }
    }

    pub fn sendto(fd: RawFd, buf: &[u8], flags: i32, addr: &SockAddr) -> io::Result<usize> {
        let r = unsafe {
            c::sendto(
                fd,
                buf.as_ptr() as *const c_void,
                buf.len(),
                flags,
                addr.bytes.as_ptr() as *const c_void,
                addr.len,
            )
        };
        if r < 0 { Err(last()) } else { Ok(r as usize) }
    }

    pub fn recv(fd: RawFd, buf: &mut [u8], flags: i32) -> io::Result<usize> {
        let r = unsafe { c::recv(fd, buf.as_mut_ptr() as *mut c_void, buf.len(), flags) };
        if r < 0 { Err(last()) } else { Ok(r as usize) }
    }

    pub fn recvfrom(
        fd: RawFd,
        buf: &mut [u8],
        flags: i32,
    ) -> io::Result<(usize, Option<SockAddr>)> {
        let mut addr = SockAddr {
            bytes: [0; 128],
            len: 0,
        };
        let mut len: u32 = 128;
        let r = unsafe {
            c::recvfrom(
                fd,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                flags,
                addr.bytes.as_mut_ptr() as *mut c_void,
                &mut len,
            )
        };
        if r < 0 {
            Err(last())
        } else {
            addr.len = len;
            Ok((r as usize, Some(addr)))
        }
    }

    pub fn shutdown(fd: RawFd, how: i32) -> io::Result<()> {
        cvt(unsafe { c::shutdown(fd, how) }).map(|_| ())
    }

    pub fn xname(fd: RawFd, peer: bool) -> io::Result<SockAddr> {
        let mut addr = SockAddr {
            bytes: [0; 128],
            len: 0,
        };
        let mut len: u32 = 128;
        let f = if peer { c::getpeername } else { c::getsockname };
        // SAFETY: addr/len は十分なバッファ。
        cvt(unsafe { f(fd, addr.bytes.as_mut_ptr() as *mut c_void, &mut len) })?;
        addr.len = len;
        Ok(addr)
    }

    pub fn getopt(fd: RawFd, level: i32, name: i32) -> io::Result<u32> {
        let mut v: u32 = 0;
        let mut len: u32 = 4;
        cvt(unsafe {
            c::getsockopt(fd, level, name, &mut v as *mut u32 as *mut c_void, &mut len)
        })?;
        Ok(v)
    }

    pub fn setopt(fd: RawFd, level: i32, name: i32, value: u32) -> io::Result<()> {
        cvt(unsafe { c::setsockopt(fd, level, name, &value as *const u32 as *const c_void, 4) })
            .map(|_| ())
    }

    pub fn getfl(fd: RawFd) -> io::Result<i32> {
        cvt(unsafe { c::fcntl(fd, F_GETFL, 0) })
    }

    pub fn setfl_nonblock(fd: RawFd, on: bool) -> io::Result<()> {
        let fl = getfl(fd)?;
        let fl = if on {
            fl | O_NONBLOCK
        } else {
            fl & !O_NONBLOCK
        };
        cvt(unsafe { c::fcntl(fd, F_SETFL, fl) }).map(|_| ())
    }

    /// 一つの fd を timeout_ms で poll し revents を返す。
    pub fn poll_one(fd: RawFd, events: i16, timeout_ms: i32) -> i16 {
        let mut p = PollFd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: p は 1 要素のバッファ。
        let r = unsafe { c::poll(&mut p, 1, timeout_ms) };
        if r <= 0 { 0 } else { p.revents }
    }

    pub fn poll(fds: &mut [(RawFd, i16)], timeout_ms: i32) -> io::Result<()> {
        let mut p: Vec<PollFd> = fds
            .iter()
            .map(|&(fd, ev)| PollFd {
                fd,
                events: ev,
                revents: 0,
            })
            .collect();
        // SAFETY: p は nfds 要素のバッファ。EINTR はやり直し
        // （呼び出し側へは成功で返す）。
        let r = loop {
            let r = unsafe { c::poll(p.as_mut_ptr(), p.len() as u64, timeout_ms) };
            if r < 0 && last().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break r;
        };
        if r < 0 {
            return Err(last());
        }
        for (dst, src) in fds.iter_mut().zip(p.iter()) {
            dst.1 = src.revents;
        }
        Ok(())
    }
}
