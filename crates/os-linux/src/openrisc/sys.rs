// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! OpenRISC Linux の syscall 処理（段階20 OR4 の最小構成）。
//!
//! 規約: 番号は r11、引数は r3-r8、戻り値は r11、失敗は -errno。
//! `l.sys` は例外ベクタ 0xc00 の Trap として届く。
//!
//! 単一プロセス・単一スレッド模型: clone/execve/パイプ/ソケット/
//! シグナル配送は未実装（ENOSYS または登録のみ受理）。or1k_atomic
//! （番号 244）は未実装として止める（Gap）。ゲストはビッグ
//! エンディアンなのでポインタ・iovec・stat の語は BE で読み書きする。
//! ファイル mmap は MAP_PRIVATE の読み込み近似（書き戻しなし）。
//! Ref: SRC-LINUX-OPENRISC-UAPI; SPEC-OPENRISC-1000 §6.1.

use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

use polyisa_engine::bare::BareEnv;
use polyisa_guest_openrisc::sem;
use polyisa_kernel::FdTable;
use polyisa_mem::{Access, AccessKind, Align, Endian, PAGE_SIZE, PageNo, Perms, VirtAddr};
use polyisa_sem::Backend as _;

use crate::{TrapHandler, TrapOutcome, openrisc::nr};

/// write/writev が集めたバイト。
#[derive(Default)]
pub struct OpenriscIo {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

mod errno {
    pub const EPERM: u64 = 1;
    pub const ENOENT: u64 = 2;
    pub const EIO: u64 = 5;
    pub const EBADF: u64 = 9;
    pub const ENOMEM: u64 = 12;
    pub const EACCES: u64 = 13;
    pub const EFAULT: u64 = 14;
    pub const ENOTDIR: u64 = 20;
    pub const EINVAL: u64 = 22;
    pub const ENOTTY: u64 = 25;
    pub const ENAMETOOLONG: u64 = 36;
    pub const ENOSYS: u64 = 38;
}

fn host_errno(e: Option<i32>) -> u64 {
    match e {
        Some(2) => errno::ENOENT,
        Some(13) => errno::EACCES,
        Some(9) => errno::EBADF,
        Some(22) => errno::EINVAL,
        Some(1) => errno::EPERM,
        _ => errno::EIO,
    }
}

/// OpenRISC Linux の syscall 状態機械。
pub struct Linux {
    /// 標準出力・標準エラーの捕獲。
    pub io: OpenriscIo,
    fds: FdTable,
    heap_end: u64,
    brk_start: u64,
    mmap_next: u64,
    pid: u64,
    guest_root: String,
    /// 実行ファイルのパス。readlinkat("/proc/self/exe") が返す。
    pub exe_path: String,
    /// 標準入力へ供給するバイト。
    pub stdin_buf: Vec<u8>,
    stdin_pos: usize,
    stack_lo: u64,
    stack_hi: u64,
    /// getdents64 の fd 毎の読み出し位置（エントリ番号）。
    dir_off: std::collections::BTreeMap<u32, usize>,
}

impl Default for Linux {
    fn default() -> Self {
        Self::new()
    }
}

enum WriteFd {
    Stdout,
    Stderr,
    File,
}

impl Linux {
    #[must_use]
    pub fn new() -> Self {
        Self {
            io: OpenriscIo::default(),
            fds: FdTable::default(),
            heap_end: 0,
            brk_start: 0,
            mmap_next: 0x6000_0000,
            pid: std::process::id().into(),
            guest_root: String::new(),
            exe_path: String::new(),
            stdin_buf: Vec::new(),
            stdin_pos: 0,
            stack_lo: 0,
            stack_hi: 0,
            dir_off: std::collections::BTreeMap::new(),
        }
    }

    /// syscall のバッファアクセスが伸ばし得るスタック窓。
    pub fn set_stack_window(&mut self, lo: u64, hi: u64) {
        self.stack_lo = lo;
        self.stack_hi = hi;
    }

    fn grow_stack(&self, env: &mut BareEnv, addr: u64, len: u64) {
        if self.stack_hi <= self.stack_lo || len == 0 {
            return;
        }
        let first = addr & !(PAGE_SIZE - 1);
        let last = addr.wrapping_add(len - 1) & !(PAGE_SIZE - 1);
        let mut p = first;
        while p <= last {
            if p >= self.stack_lo
                && p < self.stack_hi
                && !env.backend.mem.is_mapped(PageNo(p / PAGE_SIZE))
            {
                let _ = env.backend.mem.map(VirtAddr(p), 1, Perms::RW);
            }
            p = p.wrapping_add(PAGE_SIZE);
            if p == 0 {
                break;
            }
        }
    }

    /// ゲストルート（`--root`）。
    pub fn set_guest_root(&mut self, root: &str) {
        self.guest_root = root.to_string();
    }

    fn acc(&self, kind: AccessKind) -> Access {
        Access {
            endian: Endian::Be,
            align: Align::Unaligned,
            kind,
        }
    }

    fn rget(&self, env: &mut BareEnv, i: u32) -> u64 {
        env.backend.get(sem::r_ref(i)) & 0xffff_ffff
    }

    fn rset(&self, env: &mut BareEnv, i: u32, v: u64) {
        env.backend.set(sem::r_ref(i), v & 0xffff_ffff);
    }

    /// 戻り値の約束: 成功は値、失敗は -errno（32 ビット符号）。
    fn ret(&self, env: &mut BareEnv, r: Result<u64, u64>) {
        let v = match r {
            Ok(v) => v & 0xffff_ffff,
            Err(e) => (0u64.wrapping_sub(e)) & 0xffff_ffff,
        };
        self.rset(env, 11, v);
    }

    fn get_bytes(&self, env: &mut BareEnv, addr: u64, n: usize) -> Result<Vec<u8>, u64> {
        let mut buf = vec![0u8; n.min(1 << 22)];
        if buf.is_empty() {
            return Ok(buf);
        }
        let a = addr & 0xffff_ffff;
        if env
            .backend
            .mem
            .read(VirtAddr(a), &mut buf, self.acc(AccessKind::DataRead))
            .is_err()
        {
            self.grow_stack(env, a, buf.len() as u64);
            env.backend
                .mem
                .read(VirtAddr(a), &mut buf, self.acc(AccessKind::DataRead))
                .map_err(|_| errno::EFAULT)?;
        }
        Ok(buf)
    }

    fn put_bytes(&self, env: &mut BareEnv, addr: u64, data: &[u8]) -> Result<(), u64> {
        let a = addr & 0xffff_ffff;
        if env.backend.mem.write(VirtAddr(a), data).is_err() {
            self.grow_stack(env, a, data.len() as u64);
            env.backend
                .mem
                .write(VirtAddr(a), data)
                .map_err(|_| errno::EFAULT)?;
        }
        Ok(())
    }

    fn mem_u32(&self, env: &mut BareEnv, addr: u64) -> u32 {
        let b = self.get_bytes(env, addr, 4).unwrap_or_default();
        u32::from_be_bytes(b[..4].try_into().unwrap_or([0; 4]))
    }

    fn put_u32(&self, env: &mut BareEnv, addr: u64, v: u32) -> Result<(), u64> {
        self.put_bytes(env, addr, &v.to_be_bytes())
    }

    fn put_u64(&self, env: &mut BareEnv, addr: u64, v: u64) -> Result<(), u64> {
        self.put_bytes(env, addr, &v.to_be_bytes())
    }

    fn cstr(&self, env: &mut BareEnv, addr: u64) -> Result<String, u64> {
        let mut out = Vec::new();
        for i in 0..4096u64 {
            let b = self.get_bytes(env, addr + i, 1)?;
            if b[0] == 0 {
                return String::from_utf8(out).map_err(|_| errno::EINVAL);
            }
            out.push(b[0]);
        }
        Err(errno::ENAMETOOLONG)
    }

    /// ゲストパスをホストパスに写す（root 内閉じ込め）。
    fn host_path(&self, _dirfd: u64, path: &str) -> Option<String> {
        if self.guest_root.is_empty() {
            return Some(path.to_string());
        }
        crate::guest_path::resolve_guest_path(&self.guest_root, "/", path)
    }

    fn writer(&mut self, fd: u32) -> Result<WriteFd, u64> {
        match fd {
            1 => Ok(WriteFd::Stdout),
            2 => Ok(WriteFd::Stderr),
            _ if self.fds.get(fd).is_some() => Ok(WriteFd::File),
            _ => Err(errno::EBADF),
        }
    }

    fn sys_write(&mut self, env: &mut BareEnv, fd: u32, buf: u64, len: u64) -> Result<u64, u64> {
        let data = self.get_bytes(env, buf, len as usize)?;
        match self.writer(fd)? {
            WriteFd::Stdout => {
                self.io.stdout.extend_from_slice(&data);
                let _ = std::io::stdout().write_all(&data);
                Ok(data.len() as u64)
            }
            WriteFd::Stderr => {
                self.io.stderr.extend_from_slice(&data);
                let _ = std::io::stderr().write_all(&data);
                Ok(data.len() as u64)
            }
            WriteFd::File => match self.fds.get_mut(fd).unwrap().write(&data) {
                Ok(n) => Ok(n as u64),
                Err(e) => Err(host_errno(e.raw_os_error())),
            },
        }
    }

    /// iovec は 32 ビット ABI の {u32 base, u32 len} の対（BE）。
    fn sys_writev(&mut self, env: &mut BareEnv, fd: u32, iov: u64, cnt: u64) -> Result<u64, u64> {
        let mut total = 0u64;
        for i in 0..cnt.min(1024) {
            let base = u64::from(self.mem_u32(env, iov + i * 8));
            let len = u64::from(self.mem_u32(env, iov + i * 8 + 4));
            match self.sys_write(env, fd, base, len) {
                Ok(n) => total += n,
                Err(e) => return if total > 0 { Ok(total) } else { Err(e) },
            }
        }
        Ok(total)
    }

    fn sys_read(&mut self, env: &mut BareEnv, fd: u32, buf: u64, len: u64) -> Result<u64, u64> {
        let len = (len as usize).min(1 << 20);
        let mut tmp = vec![0u8; len];
        let n = match fd {
            0 => {
                let avail = self.stdin_buf.len().saturating_sub(self.stdin_pos);
                let n = avail.min(len);
                tmp[..n].copy_from_slice(&self.stdin_buf[self.stdin_pos..self.stdin_pos + n]);
                self.stdin_pos += n;
                n
            }
            _ => match self.fds.get_mut(fd) {
                Some(f) => match f.read(&mut tmp) {
                    Ok(n) => n,
                    Err(e) => return Err(host_errno(e.raw_os_error())),
                },
                None => return Err(errno::EBADF),
            },
        };
        self.put_bytes(env, buf, &tmp[..n])?;
        Ok(n as u64)
    }

    fn sys_readv(&mut self, env: &mut BareEnv, fd: u32, iov: u64, cnt: u64) -> Result<u64, u64> {
        let mut total = 0u64;
        for i in 0..cnt.min(1024) {
            let base = u64::from(self.mem_u32(env, iov + i * 8));
            let len = u64::from(self.mem_u32(env, iov + i * 8 + 4));
            match self.sys_read(env, fd, base, len) {
                Ok(n) => {
                    total += n;
                    if n < len {
                        break;
                    }
                }
                Err(e) => return if total > 0 { Ok(total) } else { Err(e) },
            }
        }
        Ok(total)
    }

    fn sys_openat(
        &mut self,
        env: &mut BareEnv,
        dirfd: u64,
        path: u64,
        flags: u64,
        _m: u64,
    ) -> Result<u64, u64> {
        let gpath = self.cstr(env, path)?;
        let Some(full) = self.host_path(dirfd, &gpath) else {
            return Err(errno::EACCES);
        };
        let accmode = flags & 3;
        let mut opt = std::fs::OpenOptions::new();
        opt.read(accmode != 1).write(accmode != 0);
        if flags & 0o100 != 0 {
            opt.create(true);
        }
        if flags & 0o1000 != 0 {
            opt.truncate(true);
        }
        match opt.open(&full) {
            Ok(f) => {
                let fd = self.fds.alloc(Some(f));
                self.fds.remember_path(fd, full);
                Ok(u64::from(fd))
            }
            Err(e) => Err(host_errno(e.raw_os_error())),
        }
    }

    /// asm-generic の struct stat（112 バイト。BE で主要項目だけ埋める）。
    fn put_stat(
        &self,
        env: &mut BareEnv,
        addr: u64,
        meta: &std::fs::Metadata,
        chr: bool,
    ) -> Result<(), u64> {
        self.put_bytes(env, addr, &[0u8; 112])?;
        let mode = if chr {
            0o620 | 0o020000 // S_IFCHR|0620
        } else if meta.is_dir() {
            0o755 | 0o040000
        } else {
            0o644 | 0o100000
        };
        self.put_u64(env, addr + 8, 1)?; // st_ino
        self.put_u32(env, addr + 16, mode)?; // st_mode
        self.put_u32(env, addr + 20, 1)?; // st_nlink
        self.put_u64(env, addr + 48, if chr { 0 } else { meta.len() })?; // st_size
        self.put_u32(env, addr + 56, 4096)?; // st_blksize
        self.put_u64(env, addr + 64, meta.len() / 512)?;
        Ok(())
    }

    fn sys_fstat(&mut self, env: &mut BareEnv, fd: u32, st: u64) -> Result<u64, u64> {
        match fd {
            0..=2 => self
                .put_stat(
                    env,
                    st,
                    &std::fs::metadata("/dev/null")
                        .unwrap_or_else(|_| std::fs::metadata("/").unwrap()),
                    true,
                )
                .map(|_| 0),
            _ => match self.fds.get(fd) {
                Some(f) => {
                    let m = f.metadata().map_err(|e| host_errno(e.raw_os_error()))?;
                    self.put_stat(env, st, &m, false).map(|_| 0)
                }
                None => Err(errno::EBADF),
            },
        }
    }

    fn sys_brk(&mut self, env: &mut BareEnv, addr: u64) -> u64 {
        let addr = addr & 0xffff_ffff;
        if self.heap_end == 0 {
            self.heap_end = self.brk_start;
        }
        if addr == 0 {
            return self.heap_end;
        }
        if addr < self.brk_start {
            return self.heap_end;
        }
        // 伸ばす分をページ割付する（縮小は許す・回収しない近似）。
        if addr > self.heap_end {
            let first = self.heap_end & !(PAGE_SIZE - 1);
            let mut p = first;
            while p < addr {
                if !env.backend.mem.is_mapped(PageNo(p / PAGE_SIZE))
                    && env.backend.mem.map(VirtAddr(p), 1, Perms::RW).is_err()
                {
                    return self.heap_end;
                }
                p += PAGE_SIZE;
            }
        }
        self.heap_end = addr;
        addr
    }

    fn sys_mmap(&mut self, env: &mut BareEnv, a: [u64; 6]) -> Result<u64, u64> {
        let (addr, len, prot, flags, fd, off) = (a[0], a[1], a[2], a[3], a[4], a[5]);
        let len = (len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if len == 0 || len > 0x4000_0000 {
            return Err(errno::EINVAL);
        }
        const MAP_FIXED: u64 = 0x10;
        let base = if flags & MAP_FIXED != 0 {
            addr & !(PAGE_SIZE - 1)
        } else {
            let b = self.mmap_next;
            self.mmap_next = self.mmap_next.wrapping_add(len);
            b
        };
        let pages = len / PAGE_SIZE;
        // PROT_* の下位 3 ビットは Perms の R/W/X と同じ配列。
        env.backend
            .mem
            .map(VirtAddr(base), pages, Perms((prot & 7) as u8))
            .map_err(|_| errno::ENOMEM)?;
        // ファイル裏付けなら中身を読み込む（MAP_PRIVATE 近似）。
        if flags & 8 == 0
            && fd != u64::MAX
            && let Some(f) = self.fds.get_mut(fd as u32)
        {
            let mut buf = vec![0u8; len as usize];
            if f.seek(SeekFrom::Start(off)).is_ok() {
                let _ = f.read(&mut buf);
                let _ = env.backend.mem.write(VirtAddr(base), &buf);
            }
        }
        Ok(base)
    }

    fn sys_uname(&mut self, env: &mut BareEnv, addr: u64) -> Result<u64, u64> {
        // struct utsname: 6 つの 65 バイト文字列。
        let mut img = [0u8; 65 * 6];
        for (i, s) in ["Linux", "polyisa", "6.1.0-polyisa", "#1", "or1k", "(none)"]
            .iter()
            .enumerate()
        {
            img[i * 65..i * 65 + s.len()].copy_from_slice(s.as_bytes());
        }
        self.put_bytes(env, addr, &img).map(|_| 0)
    }

    fn sys_clock_gettime(&mut self, env: &mut BareEnv, _clk: u64, ts: u64) -> Result<u64, u64> {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        // timespec は {i32 sec, i32 nsec}（32 ビット ABI）。
        self.put_u32(env, ts, d.as_secs() as u32)?;
        self.put_u32(env, ts + 4, d.subsec_nanos())?;
        Ok(0)
    }

    /// clock_gettime64 の timespec64（{i64 sec, i64 nsec}）。BE。
    fn sys_clock_gettime64(&mut self, env: &mut BareEnv, _clk: u64, ts: u64) -> Result<u64, u64> {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        self.put_u64(env, ts, d.as_secs())?;
        self.put_u64(env, ts + 8, u64::from(d.subsec_nanos()))?;
        Ok(0)
    }

    /// getdents64: linux_dirent64 { u64 ino, i64 off, u16 reclen,
    /// u8 type, char name[] } を 8 バイト整列で並べる。
    /// 全エントリを都度列挙し、fd 毎の読み出し位置で進める近似。
    /// Ref: SRC-LINUX (include/linux/dirent.h).
    fn sys_getdents64(
        &mut self,
        env: &mut BareEnv,
        fd: u32,
        buf: u64,
        len: u64,
    ) -> Result<u64, u64> {
        let Some(path) = self.fds.path_of(fd).map(str::to_string) else {
            return Err(errno::EBADF);
        };
        if !std::path::Path::new(&path).is_dir() {
            return Err(errno::ENOTDIR);
        }
        let mut ents: Vec<(u64, u8, Vec<u8>)> = Vec::new();
        let rd = std::fs::read_dir(&path).map_err(|e| host_errno(e.raw_os_error()))?;
        for e in rd.flatten() {
            let ft = e.file_type().map_err(|e| host_errno(e.raw_os_error()))?;
            let t = if ft.is_dir() {
                4u8
            } else if ft.is_symlink() {
                10
            } else {
                8
            };
            let ino = polyisa_host::dirent_ino(&e);
            ents.push((ino, t, e.file_name().into_encoded_bytes()));
        }
        let mut out = Vec::new();
        let mut pos = *self.dir_off.get(&fd).unwrap_or(&0usize);
        let mut idx = 0usize;
        for (ino, t, name) in &ents {
            let reclen = (19 + name.len() + 1 + 7) & !7;
            if out.len() + reclen > len as usize {
                break;
            }
            idx += 1;
            if idx <= pos {
                continue;
            }
            let mut rec = Vec::with_capacity(reclen);
            rec.extend_from_slice(&ino.to_be_bytes());
            rec.extend_from_slice(&((idx as u64) as i64).to_be_bytes());
            rec.extend_from_slice(&(reclen as u16).to_be_bytes());
            rec.push(*t);
            rec.extend_from_slice(name);
            rec.push(0);
            while rec.len() < reclen {
                rec.push(0);
            }
            out.extend_from_slice(&rec);
            pos = idx;
        }
        self.dir_off.insert(fd, pos);
        let n = out.len() as u64;
        if n != 0 {
            self.put_bytes(env, buf, &out)?;
        }
        Ok(n)
    }

    fn sys_readlinkat(
        &mut self,
        env: &mut BareEnv,
        _dirfd: u64,
        path: u64,
        buf: u64,
        len: u64,
    ) -> Result<u64, u64> {
        let gpath = self.cstr(env, path)?;
        if gpath != "/proc/self/exe" {
            return Err(errno::ENOENT);
        }
        let s = self.exe_path.as_bytes();
        let n = s.len().min(len as usize);
        self.put_bytes(env, buf, &s[..n])?;
        Ok(n as u64)
    }

    fn dispatch(&mut self, env: &mut BareEnv, nr_: u64, a: [u64; 6]) -> Result<u64, u64> {
        match nr_ {
            nr::IOCTL => Err(errno::ENOTTY),
            nr::FCNTL => {
                // F_GETFD=1・F_SETFD=2・F_GETFL=3・F_SETFL=4 のみ受理。
                // 標準三役は fds 表にないので番号で通す。
                if a[0] > 2 && self.fds.get(a[0] as u32).is_none() {
                    Err(errno::EBADF)
                } else {
                    match a[1] {
                        1 => Ok(0),
                        3 => Ok(0o2000002), // O_RDWR|O_LARGEFILE
                        2 | 4 => Ok(0),
                        _ => Err(errno::EINVAL),
                    }
                }
            }
            nr::GETDENTS64 => self.sys_getdents64(env, a[0] as u32, a[1], a[2]),
            nr::OPENAT => self.sys_openat(env, a[0], a[1], a[2], a[3]),
            nr::CLOSE => {
                if a[0] < 3 {
                    Ok(0)
                } else if self.fds.get(a[0] as u32).is_some() {
                    self.fds.clear(a[0] as u32);
                    Ok(0)
                } else {
                    Err(errno::EBADF)
                }
            }
            nr::LSEEK => match self.fds.get_mut(a[0] as u32) {
                Some(f) => {
                    let w = match a[2] {
                        0 => SeekFrom::Start(a[1]),
                        1 => SeekFrom::Current(a[1] as i64),
                        _ => SeekFrom::End(a[1] as i64),
                    };
                    f.seek(w).map_err(|e| host_errno(e.raw_os_error()))
                }
                None => Err(errno::EBADF),
            },
            nr::READ => self.sys_read(env, a[0] as u32, a[1], a[2]),
            nr::WRITE => self.sys_write(env, a[0] as u32, a[1], a[2]),
            nr::READV => self.sys_readv(env, a[0] as u32, a[1], a[2]),
            nr::WRITEV => self.sys_writev(env, a[0] as u32, a[1], a[2]),
            nr::PREAD64 => Err(errno::ENOSYS),
            nr::READLINKAT => self.sys_readlinkat(env, a[0], a[1], a[2], a[3]),
            nr::NEWFSTATAT => {
                let gpath = self.cstr(env, a[1])?;
                let Some(full) = self.host_path(a[0], &gpath) else {
                    return Err(errno::EACCES);
                };
                match std::fs::metadata(&full) {
                    Ok(m) => self.put_stat(env, a[2], &m, false).map(|_| 0),
                    Err(e) => Err(host_errno(e.raw_os_error())),
                }
            }
            nr::FSTAT => self.sys_fstat(env, a[0] as u32, a[1]),
            nr::EXIT | nr::EXIT_GROUP => unreachable!(),
            nr::SET_TID_ADDRESS => Ok(self.pid),
            nr::FUTEX => Err(errno::ENOSYS),
            nr::SET_ROBUST_LIST => Ok(0),
            nr::NANOSLEEP => Ok(0),
            nr::CLOCK_GETTIME => self.sys_clock_gettime(env, a[0], a[1]),
            nr::CLOCK_GETTIME64 => self.sys_clock_gettime64(env, a[0], a[1]),
            nr::RT_SIGACTION | nr::RT_SIGPROCMASK => Ok(0),
            nr::UNAME => self.sys_uname(env, a[0]),
            nr::GETPID | nr::GETTID => Ok(self.pid),
            nr::GETPPID => Ok(1),
            nr::GETUID | nr::GETEUID | nr::GETGID | nr::GETEGID => Ok(0),
            // uid/gid の変更系は単一ユーザ近似で受理のみ。
            nr::SETREGID
            | nr::SETGID
            | nr::SETREUID
            | nr::SETUID
            | nr::SETRESUID
            | nr::SETRESGID
            | nr::SETFSUID
            | nr::SETFSGID => Ok(0),
            nr::BRK => Ok(self.sys_brk(env, a[0])),
            nr::MUNMAP => Ok(0),
            nr::MMAP => self.sys_mmap(env, a),
            nr::MPROTECT => Ok(0),
            nr::PRLIMIT64 => Ok(0),
            nr::GETRANDOM => {
                let mut buf = vec![0u8; (a[1] as usize).min(256)];
                // 決定論的なダミー乱数（Gap: 暗論的強度は不要の検査用）。
                for (i, b) in buf.iter_mut().enumerate() {
                    *b = (i as u8).wrapping_mul(73).wrapping_add(41);
                }
                self.put_bytes(env, a[0], &buf)?;
                Ok(buf.len() as u64)
            }
            nr::FACCESSAT => {
                let gpath = self.cstr(env, a[1])?;
                let Some(full) = self.host_path(a[0], &gpath) else {
                    return Err(errno::EACCES);
                };
                if std::fs::metadata(&full).is_ok() {
                    Ok(0)
                } else {
                    Err(errno::ENOENT)
                }
            }
            nr::STATX => Err(errno::ENOSYS),
            _ => Err(errno::ENOSYS),
        }
    }
}

impl TrapHandler for Linux {
    fn handle_trap(&mut self, env: &mut BareEnv, code: u32) -> TrapOutcome {
        if u64::from(code) != sem::TRAP_SYS {
            return TrapOutcome::Unimplemented;
        }
        let nr_ = self.rget(env, 11);
        let a = [
            self.rget(env, 3),
            self.rget(env, 4),
            self.rget(env, 5),
            self.rget(env, 6),
            self.rget(env, 7),
            self.rget(env, 8),
        ];
        if nr_ == nr::EXIT || nr_ == nr::EXIT_GROUP {
            return TrapOutcome::Exit((a[0] & 0xff) as u32);
        }
        if nr_ == nr::OR1K_ATOMIC {
            // or1k 専用の原子的操作 syscall。単一スレッド模型のため
            // l.lwa/l.swa で代替すべきもの。未実装として報告する（Gap）。
            return TrapOutcome::Unimplemented;
        }
        let r = self.dispatch(env, nr_, a);
        self.ret(env, r);
        TrapOutcome::Handled
    }

    fn init_brk(&mut self, image_end: u64) {
        self.brk_start = (image_end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        self.heap_end = self.brk_start;
    }
}
