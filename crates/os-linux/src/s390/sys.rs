// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! s390x Linux の syscall 処理。s390x の単一 ABI。
//!
//! `svc 0` で入り、番号は r1、引数は r2–r7、戻り値は r2。エラーは
//! r2 に負の errno を直接書く（CR0.SO のようなフラグは使わない）。
//! errno は asm-generic 値。
//!
//! 試作の合意事項は他 ABI と同じ: ホストのファイルに直接触る。
//! 信頼できないゲストバイナリには使わないこと。
//! fork/clone/execve/パイプは未対応（ENOSYS）。
// Ref: SRC-LINUX (7.3), SPEC-S390-ABI.

use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

use polyisa_engine::bare::BareEnv;
use polyisa_guest_s390::sem::Gpr;
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};
use polyisa_sem::Backend as _;

use crate::{TrapHandler, TrapOutcome, s390, s390::errno};

/// 標準入出力の capture。テストが読む。
#[derive(Default)]
pub struct S390Io {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// s390x Linux の syscall 状態機械。
pub struct Linux {
    /// 標準入出力の capture。テストが読む。
    pub io: S390Io,
    fds: polyisa_kernel::FdTable,
    heap_end: u64,
    mmap_next: u64,
    umask: u32,
    pid: u64,
    cwd: String,
    guest_root: String,
    pub exe_path: String,
    reported: Vec<u64>,
    pub stdin_buf: Vec<u8>,
    stdin_pos: usize,
    mono_start: Option<std::time::Instant>,
}

impl Default for Linux {
    fn default() -> Self {
        Self::new()
    }
}

fn reg(env: &mut BareEnv, r: u8) -> u64 {
    env.backend.get(Gpr(r).state())
}

/// 引数 i（0–5）は r2–r7。
fn arg(env: &mut BareEnv, i: u8) -> u64 {
    reg(env, i + 2)
}

enum Disp {
    /// r2 に書く値（負値は errno の符号反転として扱う）。
    Ret(u64),
    Exit(u32),
    Unimpl,
}

fn ret(v: u64) -> Disp {
    Disp::Ret(v)
}

const ACC: Access = Access {
    endian: Endian::Be,
    align: Align::Unaligned,
    kind: AccessKind::DataRead,
};

impl Linux {
    /// s390x の Linux 状態機械を作る。
    #[must_use]
    pub fn new() -> Self {
        Self {
            io: S390Io::default(),
            fds: polyisa_kernel::FdTable::default(),
            heap_end: 0,
            mmap_next: 0x0000_0800_0000_0000,
            umask: 0o22,
            pid: 0,
            cwd: String::new(),
            guest_root: String::new(),
            exe_path: String::new(),
            reported: Vec::new(),
            stdin_buf: Vec::new(),
            stdin_pos: 0,
            mono_start: None,
        }
    }

    /// ゲストのルートと cwd を設定する。
    pub fn set_root(&mut self, guest_root: &str, cwd: &str) {
        self.guest_root = guest_root.to_string();
        self.cwd = cwd.to_string();
    }

    fn pid(&mut self) -> u64 {
        if self.pid == 0 {
            self.pid = 1;
        }
        self.pid
    }

    fn fail(errno: u32) -> u64 {
        (-(errno as i64)) as u64
    }

    fn fail_ret(errno: u32) -> Disp {
        Disp::Ret(Self::fail(errno))
    }

    fn fail_ret_host(e: std::io::Error) -> Disp {
        Disp::Ret(Self::fail(
            e.raw_os_error().unwrap_or(errno::EIO as i32).unsigned_abs(),
        ))
    }

    /// 64 ビット値をメモリから読む。読めなければ 0。
    fn mem_u(&self, env: &mut BareEnv, addr: u64) -> u64 {
        let mut b = [0u8; 8];
        env.backend
            .mem
            .read(VirtAddr(addr), &mut b, ACC)
            .map_or(0, |()| u64::from_be_bytes(b))
    }

    /// 32 ビット値を書く。
    fn put_u32(&self, env: &mut BareEnv, addr: u64, v: u32) -> bool {
        env.backend
            .mem
            .write(VirtAddr(addr), &v.to_be_bytes())
            .is_ok()
    }

    /// 64 ビット値を書く。
    fn put_u64(&self, env: &mut BareEnv, addr: u64, v: u64) -> bool {
        env.backend
            .mem
            .write(VirtAddr(addr), &v.to_be_bytes())
            .is_ok()
    }

    /// 64 ビット値を読む。
    fn get_u64(&self, env: &mut BareEnv, addr: u64) -> Option<u64> {
        let mut b = [0u8; 8];
        env.backend.mem.read(VirtAddr(addr), &mut b, ACC).ok()?;
        Some(u64::from_be_bytes(b))
    }

    /// mmap 共用体。`prot` は PROT_*、addr!=0 はヒントとして使う。
    fn do_mmap(&mut self, env: &mut BareEnv, addr: u64, len: u64, prot: u64) -> Disp {
        if len == 0 {
            return Self::fail_ret(errno::EINVAL);
        }
        let pages = len.div_ceil(0x1000);
        let base = if addr != 0 {
            addr & !0xfff
        } else {
            self.mmap_next
        };
        let mut p = 0u8;
        if prot & 1 != 0 {
            p |= Perms::R.0;
        }
        if prot & 2 != 0 {
            p |= Perms::W.0;
        }
        if prot & 4 != 0 {
            p |= Perms::X.0;
        }
        if env
            .backend
            .mem
            .map(VirtAddr(base), pages, Perms(p))
            .is_err()
        {
            return Self::fail_ret(errno::ENOMEM);
        }
        if base >= self.mmap_next {
            self.mmap_next = base + pages * 0x1000;
        }
        ret(base)
    }

    /// NUL 終端文字列を読む。失敗は None。
    fn cstr(&self, env: &mut BareEnv, addr: u64) -> Option<String> {
        let mut out = Vec::new();
        for i in 0..4096u64 {
            let mut b = [0u8; 1];
            env.backend.mem.read(VirtAddr(addr + i), &mut b, ACC).ok()?;
            if b[0] == 0 {
                return Some(String::from_utf8_lossy(&out).into_owned());
            }
            out.push(b[0]);
        }
        None
    }

    fn host_path(&self, p: &str) -> String {
        crate::guest_path::resolve_guest_path(&self.guest_root, &self.cwd, p)
            .unwrap_or_else(|| p.to_string())
    }

    /// `fd` への `tmp` の書き込み。fd 1/2 は capture しつつホストにも流す。
    fn write_to(&mut self, fd: u64, tmp: &[u8]) -> Result<(), Disp> {
        match fd {
            1 => {
                self.io.stdout.extend_from_slice(tmp);
                let _ = std::io::Write::write_all(&mut std::io::stdout(), tmp);
            }
            2 => {
                self.io.stderr.extend_from_slice(tmp);
                let _ = std::io::Write::write_all(&mut std::io::stderr(), tmp);
            }
            _ => {
                let Some(f) = self.fds.file_mut(fd as u32) else {
                    return Err(Self::fail_ret(errno::EBADF));
                };
                if let Err(e) = f.write_all(tmp) {
                    return Err(Self::fail_ret_host(e));
                }
            }
        }
        Ok(())
    }

    /// 簡易 `struct stat`（新形式、144B）をビッグエンディアンで埋める。
    fn put_stat(&self, env: &mut BareEnv, addr: u64, m: &polyisa_host::Stat) -> bool {
        let mut ok = true;
        // s390x `struct stat`（UAPI）。asm-generic とは違い時刻フィールドが
        // st_blksize/st_blocks より先に来る。
        // Ref: SRC-LINUX arch/s390/include/uapi/asm/stat.h。
        ok &= self.put_u64(env, addr, m.dev);
        ok &= self.put_u64(env, addr + 8, m.ino);
        ok &= self.put_u64(env, addr + 16, m.nlink);
        ok &= self.put_u32(env, addr + 24, m.mode);
        ok &= self.put_u32(env, addr + 28, m.uid);
        ok &= self.put_u32(env, addr + 32, m.gid);
        // addr+36 は __pad1。
        ok &= self.put_u64(env, addr + 40, m.rdev);
        ok &= self.put_u64(env, addr + 48, m.size);
        ok &= self.put_u64(env, addr + 56, m.atime as u64);
        ok &= self.put_u64(env, addr + 64, m.atime_nsec as u64);
        ok &= self.put_u64(env, addr + 72, m.mtime as u64);
        ok &= self.put_u64(env, addr + 80, m.mtime_nsec as u64);
        ok &= self.put_u64(env, addr + 88, m.ctime as u64);
        ok &= self.put_u64(env, addr + 96, m.ctime_nsec as u64);
        ok &= self.put_u64(env, addr + 104, m.blksize);
        ok &= self.put_u64(env, addr + 112, m.blocks);
        ok
    }

    /// `newfstatat`/`statx` 共用の stat 書き込み。
    fn stat_at(&mut self, env: &mut BareEnv, dirfd: u64, path: u64, buf: u64) -> Disp {
        let Some(p) = self.cstr(env, path) else {
            return Self::fail_ret(errno::EFAULT);
        };
        let hp = self.host_path(&p);
        let _ = dirfd;
        match polyisa_host::stat(&hp) {
            Ok(m) => {
                if self.put_stat(env, buf, &m) {
                    ret(0)
                } else {
                    Self::fail_ret(errno::EFAULT)
                }
            }
            Err(e) => Self::fail_ret_host(e),
        }
    }

    /// ソケット系 syscall を `sock` 正準層へ委譲する（socketcall
    /// 副番号の展開を含む）。待ち要求は単一スレッド消化で進め、
    /// 進行不能はデッドロックとして報告。
    fn sock_call(&mut self, env: &mut BareEnv, nr: u64) -> Disp {
        let Some(name) = s390::name(nr) else {
            return Self::fail_ret(errno::ENOSYS);
        };
        let abi = crate::sock::SockAbi::generic(8, Endian::Be);
        let map = crate::sock::unix_path_map(&self.guest_root, &self.cwd);
        let args: [u64; 6] = std::array::from_fn(|i| arg(env, i as u8));
        let t0 = std::time::Instant::now();
        let mono = move || t0.elapsed().as_nanos() as u64;
        match crate::sock::drive(&mut self.fds, &abi, env, name, &args, &map, 0, &mono) {
            Some(Ok(v)) => ret(v),
            Some(Err(e)) => {
                if e == crate::sock::errno::EDEADLK {
                    eprintln!("s390: deadlock in fd wait");
                }
                Self::fail_ret((abi.errno)(e))
            }
            None => Self::fail_ret(errno::ENOSYS),
        }
    }

    /// 待ち合わせ系 syscall を `wait` 正準層へ委譲する。
    fn wait_call(&mut self, env: &mut BareEnv, nr: u64) -> Disp {
        let Some(name) = s390::name(nr) else {
            return Self::fail_ret(errno::ENOSYS);
        };
        let abi = crate::wait::WaitAbi::generic(8, 8, Endian::Be);
        let args: [u64; 6] = std::array::from_fn(|i| arg(env, i as u8));
        let t0 = std::time::Instant::now();
        let mono = move || t0.elapsed().as_nanos() as u64;
        match crate::wait::drive(&mut self.fds, &abi, env, name, &args, 0, &mono) {
            Some(Ok(v)) => ret(v),
            Some(Err(e)) => {
                if e == crate::sock::errno::EDEADLK {
                    eprintln!("s390: deadlock in fd wait");
                }
                Self::fail_ret((abi.errno)(e))
            }
            None => Self::fail_ret(errno::ENOSYS),
        }
    }

    fn dispatch(&mut self, env: &mut BareEnv, nr: u64) -> Disp {
        if let Some(name) = s390::name(nr)
            && crate::wait::NAMES.contains(&name)
        {
            return self.wait_call(env, nr);
        }
        match nr {
            s390::EXIT | s390::EXIT_GROUP => Disp::Exit(arg(env, 0) as u32),
            s390::READ => {
                let (fd, buf, len) = (arg(env, 0), arg(env, 1), arg(env, 2));
                let mut tmp = vec![0u8; len.min(1 << 20) as usize];
                let n = if fd == 0 {
                    if self.stdin_pos >= self.stdin_buf.len() {
                        0
                    } else {
                        let take = tmp.len().min(self.stdin_buf.len() - self.stdin_pos);
                        tmp[..take].copy_from_slice(
                            &self.stdin_buf[self.stdin_pos..self.stdin_pos + take],
                        );
                        self.stdin_pos += take;
                        take
                    }
                } else if self.fds.file(fd as u32).is_none() {
                    // ファイル以外の対象（eventfd・timerfd 等）は fd 表経由。
                    if self.fds.target(fd as u32).is_none() {
                        return Self::fail_ret(errno::EBADF);
                    }
                    let abi = crate::wait::WaitAbi::generic(8, 8, Endian::Be);
                    let t0 = std::time::Instant::now();
                    let mono = move || t0.elapsed().as_nanos() as u64;
                    return match crate::wait::read_other(
                        &mut self.fds,
                        &abi,
                        env,
                        fd as u32,
                        buf,
                        len,
                        0,
                        &mono,
                    ) {
                        Ok(v) => ret(v),
                        Err(e) => Self::fail_ret((abi.errno)(e)),
                    };
                } else {
                    let Some(f) = self.fds.file_mut(fd as u32) else {
                        return Self::fail_ret(errno::EBADF);
                    };
                    match f.read(&mut tmp) {
                        Ok(n) => n,
                        Err(e) => return Self::fail_ret_host(e),
                    }
                };
                if env.backend.mem.write(VirtAddr(buf), &tmp[..n]).is_err() {
                    return Self::fail_ret(errno::EFAULT);
                }
                ret(n as u64)
            }
            s390::READV => {
                let (fd, iov, cnt) = (arg(env, 0), arg(env, 1), arg(env, 2));
                let mut total = 0u64;
                for i in 0..cnt.min(64) {
                    let base = self.mem_u(env, iov + i * 16);
                    let len = self.mem_u(env, iov + i * 16 + 8);
                    if len == 0 {
                        continue;
                    }
                    let mut tmp = vec![0u8; len.min(1 << 20) as usize];
                    let n = if fd == 0 {
                        if self.stdin_pos >= self.stdin_buf.len() {
                            break;
                        }
                        let take = tmp.len().min(self.stdin_buf.len() - self.stdin_pos);
                        tmp[..take].copy_from_slice(
                            &self.stdin_buf[self.stdin_pos..self.stdin_pos + take],
                        );
                        self.stdin_pos += take;
                        take
                    } else {
                        let Some(f) = self.fds.file_mut(fd as u32) else {
                            return Self::fail_ret(errno::EBADF);
                        };
                        match f.read(&mut tmp) {
                            Ok(n) => n,
                            Err(e) => return Self::fail_ret_host(e),
                        }
                    };
                    if env.backend.mem.write(VirtAddr(base), &tmp[..n]).is_err() {
                        return Self::fail_ret(errno::EFAULT);
                    }
                    total += n as u64;
                    if n < tmp.len() {
                        break;
                    }
                }
                ret(total)
            }
            s390::WRITE => {
                let (fd, buf, len) = (arg(env, 0), arg(env, 1), arg(env, 2));
                if fd >= 3
                    && self.fds.file(fd as u32).is_none()
                    && self.fds.target(fd as u32).is_some()
                {
                    // ファイル以外の対象（eventfd 等）は fd 表経由。
                    let abi = crate::wait::WaitAbi::generic(8, 8, Endian::Be);
                    let t0 = std::time::Instant::now();
                    let mono = move || t0.elapsed().as_nanos() as u64;
                    return match crate::wait::write_other(
                        &mut self.fds,
                        &abi,
                        env,
                        fd as u32,
                        buf,
                        len,
                        0,
                        &mono,
                    ) {
                        Ok(v) => ret(v),
                        Err(e) => Self::fail_ret((abi.errno)(e)),
                    };
                }
                let mut tmp = vec![0u8; len.min(1 << 20) as usize];
                if env.backend.mem.read(VirtAddr(buf), &mut tmp, ACC).is_err() {
                    return Self::fail_ret(errno::EFAULT);
                }
                if let Err(d) = self.write_to(fd, &tmp) {
                    return d;
                }
                ret(len)
            }
            s390::WRITEV => {
                let (fd, iov, cnt) = (arg(env, 0), arg(env, 1), arg(env, 2));
                let mut total = 0u64;
                for i in 0..cnt.min(64) {
                    let base = self.mem_u(env, iov + i * 16);
                    let len = self.mem_u(env, iov + i * 16 + 8);
                    let mut tmp = vec![0u8; len.min(1 << 20) as usize];
                    if env.backend.mem.read(VirtAddr(base), &mut tmp, ACC).is_err() {
                        return Self::fail_ret(errno::EFAULT);
                    }
                    if let Err(d) = self.write_to(fd, &tmp) {
                        return d;
                    }
                    total += len;
                }
                ret(total)
            }
            s390::BRK => {
                let req = arg(env, 0);
                if req != 0 {
                    let old_page = self.heap_end.div_ceil(0x1000);
                    let new_page = req.div_ceil(0x1000);
                    if new_page > old_page {
                        // 伸長: 新領域を RW でマップしてから伸ばす。
                        let _ = env.backend.mem.map(
                            VirtAddr(old_page * 0x1000),
                            new_page - old_page,
                            Perms::RW,
                        );
                    } else if new_page < old_page {
                        // 縮小: 新しい break より上のページを外す。
                        env.backend
                            .mem
                            .unmap(VirtAddr(new_page * 0x1000), old_page - new_page);
                    }
                    self.heap_end = req;
                }
                ret(self.heap_end)
            }
            s390::OPEN | s390::OPENAT | s390::OPENAT2 => {
                let (p_off, flags) = if nr == s390::OPEN {
                    (0u8, arg(env, 1))
                } else {
                    (1u8, arg(env, 2))
                };
                let p_addr = arg(env, p_off);
                let Some(p) = self.cstr(env, p_addr) else {
                    return Self::fail_ret(errno::EFAULT);
                };
                let hp = self.host_path(&p);
                let acc = flags & 3;
                let mut o = std::fs::OpenOptions::new();
                o.read(acc != 1)
                    .write(acc != 0)
                    .append(flags & 0x400 != 0)
                    .truncate(flags & 0x200 != 0)
                    .create(flags & 0x40 != 0);
                match o.open(&hp) {
                    Ok(f) => ret(u64::from(self.fds.alloc(polyisa_kernel::FdTarget::File(f)))),
                    Err(e) => Self::fail_ret_host(e),
                }
            }
            s390::CLOSE => {
                let fd = arg(env, 0);
                if fd < 3 {
                    ret(0)
                } else if self.fds.ent(fd as u32).is_some() {
                    self.fds.clear(fd as u32);
                    ret(0)
                } else {
                    Self::fail_ret(errno::EBADF)
                }
            }
            s390::LSEEK => {
                let (fd, off, wh) = (arg(env, 0), arg(env, 1) as i64, arg(env, 2));
                let Some(f) = self.fds.file_mut(fd as u32) else {
                    return Self::fail_ret(errno::EBADF);
                };
                let pos = match wh {
                    0 => SeekFrom::Start(off as u64),
                    1 => SeekFrom::Current(off),
                    _ => SeekFrom::End(off),
                };
                match f.seek(pos) {
                    Ok(n) => ret(n),
                    Err(e) => Self::fail_ret_host(e),
                }
            }
            s390::UNAME => {
                let buf = arg(env, 0);
                let fields = ["Linux", "polyisa", "6.6.0-polyisa", "#1", "s390x", "(none)"];
                let mut ok = true;
                for (i, s) in fields.iter().enumerate() {
                    let mut v = vec![0u8; 65];
                    v[..s.len()].copy_from_slice(s.as_bytes());
                    ok &= env
                        .backend
                        .mem
                        .write(VirtAddr(buf + i as u64 * 65), &v)
                        .is_ok();
                }
                if ok {
                    ret(0)
                } else {
                    Self::fail_ret(errno::EFAULT)
                }
            }
            s390::GETPID | s390::SET_TID_ADDRESS => ret(self.pid()),
            s390::GETPPID => ret(0),
            s390::GETUID | s390::GETGID | s390::GETEUID | s390::GETEGID => ret(0),
            s390::GETCPU => ret(0),
            s390::IOCTL => Self::fail_ret(errno::ENOTTY),
            s390::FCNTL
            | s390::MADVISE
            | s390::MPROTECT
            | s390::SCHED_YIELD
            | s390::RT_SIGACTION
            | s390::RT_SIGPROCMASK
            | s390::SET_ROBUST_LIST
            | s390::FACCESSAT
            | s390::ACCESS
            | s390::FSYNC
            | s390::SYNC
            | s390::MUNMAP
            | s390::NANOSLEEP
            | s390::PPOLL
            | s390::PSELECT6
            | s390::PERSONALITY
            | s390::TIMES
            | s390::PRCTL
            | s390::SCHED_GETAFFINITY
            | s390::POLL
            | s390::SELECT => ret(0),
            s390::GETRANDOM => {
                let (buf, len) = (arg(env, 0), arg(env, 1));
                let mut v = vec![0xabu8; len.min(1 << 20) as usize];
                // 決定的な値で埋める（再現性のため）。
                for (i, b) in v.iter_mut().enumerate() {
                    *b = (i as u8) ^ 0x5a;
                }
                if env.backend.mem.write(VirtAddr(buf), &v).is_err() {
                    return Self::fail_ret(errno::EFAULT);
                }
                ret(v.len() as u64)
            }
            s390::GETRLIMIT => {
                // getrlimit(res, rlim): ポインタは第 2 引数（r3）。
                let rlim = arg(env, 1);
                if rlim != 0 {
                    let inf = u64::MAX;
                    if !self.put_u64(env, rlim, inf) || !self.put_u64(env, rlim + 8, inf) {
                        return Self::fail_ret(errno::EFAULT);
                    }
                }
                ret(0)
            }
            s390::PRLIMIT64 => {
                // prlimit64(pid, res, new, old): 書き戻し先は第 4 引数（r5）。
                let rlim = arg(env, 3);
                if rlim != 0 {
                    let inf = u64::MAX;
                    if !self.put_u64(env, rlim, inf) || !self.put_u64(env, rlim + 8, inf) {
                        return Self::fail_ret(errno::EFAULT);
                    }
                }
                ret(0)
            }
            s390::GETTIMEOFDAY | s390::CLOCK_GETTIME => {
                let (clk, tp) = (arg(env, 0), arg(env, 1));
                let _ = clk;
                let t = if nr == s390::CLOCK_GETTIME {
                    tp
                } else {
                    arg(env, 0)
                };
                let (sec, nsec) = match self.mono_start {
                    Some(s) => {
                        let e = s.elapsed();
                        (e.as_secs(), u64::from(e.subsec_nanos()))
                    }
                    None => {
                        self.mono_start = Some(std::time::Instant::now());
                        (0, 0)
                    }
                };
                if t != 0 && (!self.put_u64(env, t, sec) || !self.put_u64(env, t + 8, nsec)) {
                    return Self::fail_ret(errno::EFAULT);
                }
                ret(0)
            }
            s390::GETCWD => {
                let (buf, len) = (arg(env, 0), arg(env, 1));
                let cwd = if self.cwd.is_empty() {
                    "/".to_string()
                } else {
                    self.cwd.clone()
                };
                let bytes = cwd.as_bytes();
                if bytes.len() + 1 > len as usize {
                    return Self::fail_ret(errno::ERANGE);
                }
                let mut v = bytes.to_vec();
                v.push(0);
                if env.backend.mem.write(VirtAddr(buf), &v).is_err() {
                    return Self::fail_ret(errno::EFAULT);
                }
                ret(v.len() as u64)
            }
            s390::NEWFSTATAT | s390::STATX => {
                let (dirfd, path, buf) = (arg(env, 0), arg(env, 1), arg(env, 2));
                self.stat_at(env, dirfd, path, buf)
            }
            s390::STAT | s390::LSTAT => {
                let (path, buf) = (arg(env, 0), arg(env, 1));
                self.stat_at(env, 0, path, buf)
            }
            s390::FSTAT => {
                let (fd, buf) = (arg(env, 0), arg(env, 1));
                if fd < 3 {
                    // fd 0–2 は文字デバイスとして受理する。
                    if let Ok(m) = polyisa_host::stat("/dev/null")
                        && self.put_stat(env, buf, &m)
                    {
                        return ret(0);
                    }
                    return Self::fail_ret(errno::EBADF);
                }
                let Some(f) = self.fds.file_mut(fd as u32) else {
                    return Self::fail_ret(errno::EBADF);
                };
                match polyisa_host::fstat(f) {
                    Ok(m) => {
                        if self.put_stat(env, buf, &m) {
                            ret(0)
                        } else {
                            Self::fail_ret(errno::EFAULT)
                        }
                    }
                    Err(e) => Self::fail_ret_host(e),
                }
            }
            s390::READLINKAT => {
                let (buf, len) = (arg(env, 2), arg(env, 3));
                let exe = self.exe_path.clone();
                let bytes = exe.as_bytes();
                let n = bytes.len().min(len as usize);
                if env.backend.mem.write(VirtAddr(buf), &bytes[..n]).is_err() {
                    return Self::fail_ret(errno::EFAULT);
                }
                ret(n as u64)
            }
            s390::MMAP => {
                // s390 の 90 番は old_mmap: r2 が 6 語の引数ブロック
                // （addr,len,prot,flags,fd,offset）を指す。
                let p = arg(env, 0);
                let mut margs = [0u64; 6];
                let mut ok = true;
                for (i, a) in margs.iter_mut().enumerate() {
                    match self.get_u64(env, p + i as u64 * 8) {
                        Some(v) => *a = v,
                        None => {
                            ok = false;
                            break;
                        }
                    }
                }
                if !ok {
                    return Self::fail_ret(errno::EFAULT);
                }
                self.do_mmap(env, margs[0], margs[1], margs[2])
            }
            s390::MMAP2 => {
                // mmap2: 引数はレジスタ（offset は 4KiB ページ単位、無視）。
                let (addr, len, prot) = (arg(env, 0), arg(env, 1), arg(env, 2));
                self.do_mmap(env, addr, len, prot)
            }
            s390::FUTEX => Self::fail_ret(errno::EAGAIN),
            s390::UMASK => {
                // umask(2): 返回旧值并记新值。chmod 语义未模拟（GAP）。
                let old = self.umask;
                self.umask = arg(env, 0) as u32 & 0o777;
                ret(old as u64)
            }
            // ---- ソケット ----
            s390::SOCKETCALL
            | s390::SOCKET
            | s390::SOCKETPAIR
            | s390::BIND
            | s390::CONNECT
            | s390::LISTEN
            | s390::ACCEPT4
            | s390::GETSOCKOPT
            | s390::SETSOCKOPT
            | s390::GETSOCKNAME
            | s390::GETPEERNAME
            | s390::SENDTO
            | s390::SENDMSG
            | s390::RECVFROM
            | s390::RECVMSG
            | s390::SHUTDOWN => self.sock_call(env, nr),
            _ => Disp::Unimpl,
        }
    }
}

impl TrapHandler for Linux {
    /// `brk` の初期値。ローダが像の末尾を渡す。
    fn init_brk(&mut self, image_end: u64) {
        self.heap_end = image_end;
        self.mmap_next = image_end.div_ceil(0x1000) * 0x1000 + 0x1000;
    }

    fn handle_trap(&mut self, env: &mut BareEnv, code: u32) -> TrapOutcome {
        // `svc imm`: imm が 0 以外ならそれ自体が syscall 番号
        // （ESA 系の旧形式）。0 なら番号は r1。
        let nr = if code != 0 {
            u64::from(code)
        } else {
            reg(env, 1)
        };
        if std::env::var_os("POLYISA_S390_SYS_TRACE").is_some() {
            let name = s390::name(nr).unwrap_or("?");
            eprintln!(
                "s390: sys {nr} ({name}) a2={:#x} a3={:#x} a4={:#x}",
                reg(env, 2),
                reg(env, 3),
                reg(env, 4)
            );
        }
        match self.dispatch(env, nr) {
            Disp::Ret(v) => {
                env.backend.set(Gpr(2).state(), v);
                TrapOutcome::Handled
            }
            Disp::Exit(code) => TrapOutcome::Exit(code),
            Disp::Unimpl => {
                if !self.reported.contains(&nr) {
                    self.reported.push(nr);
                    let name = s390::name(nr).unwrap_or("?");
                    eprintln!("s390: unimplemented syscall {nr} ({name})");
                }
                env.backend
                    .set(Gpr(2).state(), (-(errno::ENOSYS as i64)) as u64);
                TrapOutcome::Handled
            }
        }
    }
}
