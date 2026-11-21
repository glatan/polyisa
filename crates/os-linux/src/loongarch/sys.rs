// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! LoongArch Linux の syscall 処理。
//!
//! 規約（SRC-LINUX — arch/loongarch syscall 規約、asm-generic）:
//! - 発行点は `syscall`（慣例の即値 0）。
//! - 番号は $a7（$r11）、引数は $a0–$a5（$r4–$r9）、
//!   戻り値は $a0（$r4）。失敗は $a0 = -errno。
//! - errno は asm-generic の値そのまま。
//!
//! 単一プロセス・単一スレッド模型: clone/execve/パイプ/ソケット/
//! epoll/タイマ系は ENOSYS。シグナル枠組みは登録を受理するだけで
//! 配送しない。LoongArch はリトルエンディアンのみ。
//! 信頼できないゲストバイナリには使わないこと。
// Ref: SRC-LINUX — arch/loongarch/kernel/entry.S,
// include/uapi/asm-generic/unistd.h.

use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

use polyisa_engine::bare::BareEnv;
use polyisa_guest_loongarch::sem;
use polyisa_kernel::FdTable;
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};
use polyisa_sem::Backend as _;

use crate::{TrapHandler, TrapOutcome, loongarch};

/// write/writev が集めたバイト。標準出力と標準エラーを分ける。
#[derive(Default)]
pub struct LoongarchIo {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// errno。asm-generic の値（ホストと同じ番号）。
mod errno {
    pub const EPERM: u64 = 1;
    pub const ENOENT: u64 = 2;
    pub const EIO: u64 = 5;
    pub const EBADF: u64 = 9;
    pub const ENOMEM: u64 = 12;
    pub const EACCES: u64 = 13;
    pub const EFAULT: u64 = 14;
    pub const EINVAL: u64 = 22;
    pub const ENOTTY: u64 = 25;
    pub const ERANGE: u64 = 34;
    pub const ENAMETOOLONG: u64 = 36;
    pub const ENOSYS: u64 = 38;
}

/// ホスト errno を asm-generic の番号に写す（代表分）。
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

/// LoongArch Linux の syscall 状態機械。
/// $a7=番号、$a0–$a5=引数、$a0=戻り値。
pub struct Linux {
    /// 標準出力・標準エラーの捕獲。テストが読む。
    pub io: LoongarchIo,
    /// 開いたファイルの表（ゲスト fd 3 以降）。
    fds: FdTable,
    /// プログラムブレーク。0 は未初期化。
    heap_end: u64,
    /// brk 領域の開始（ELF の image_end）。`init_brk` が設定する。
    brk_start: u64,
    /// mmap の次に置く場所。
    mmap_next: u64,
    /// ホストから見たプロセス識別子。getpid/gettid が返す。
    pid: u64,
    /// ゲストの作業ディレクトリ。空はホストの作業ディレクトリ。
    cwd: String,
    /// 実行ファイルのパス。`readlinkat("/proc/self/exe")` が返す。
    pub exe_path: String,
    /// 標準入力へ供給するバイト。
    pub stdin_buf: Vec<u8>,
    stdin_pos: usize,
    /// MONOTONIC 時計の起点。
    mono_start: Option<std::time::Instant>,
    /// LA32 モデルか（ポインタ引数を 32 ビットに折り返す）。
    pub la64: bool,
    /// 報告済みの未実装番号（一度だけ出す）。
    reported: Vec<u64>,
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
    /// LoongArch Linux の状態機械を作る。
    #[must_use]
    pub fn new() -> Self {
        Self {
            io: LoongarchIo::default(),
            fds: FdTable::default(),
            heap_end: 0,
            brk_start: 0,
            mmap_next: 0x0000_0000_7000_0000,
            pid: std::process::id().into(),
            cwd: String::new(),
            exe_path: String::new(),
            stdin_buf: Vec::new(),
            stdin_pos: 0,
            mono_start: None,
            la64: true,
            reported: Vec::new(),
        }
    }

    /// アクセス属性（常に LE・非整列許容）。
    fn acc(&self, kind: AccessKind) -> Access {
        Access {
            endian: Endian::Le,
            align: Align::Unaligned,
            kind,
        }
    }

    /// LA32 ならポインタを 32 ビットに折り返す。
    fn ptr(&self, v: u64) -> u64 {
        if self.la64 { v } else { v & 0xffff_ffff }
    }

    /// $r`i` を読む。
    fn rget(&self, env: &mut BareEnv, i: u32) -> u64 {
        env.backend.get(sem::r_ref(i))
    }

    /// $r`i` へ書く。
    fn rset(&self, env: &mut BareEnv, i: u32, v: u64) {
        env.backend.set(sem::r_ref(i), v);
    }

    /// ゲストメモリから `n` バイト読む。
    fn get_bytes(&self, env: &mut BareEnv, addr: u64, n: usize) -> Result<Vec<u8>, u64> {
        let mut buf = vec![0u8; n.min(1 << 22)];
        if buf.is_empty() {
            return Ok(buf);
        }
        env.backend
            .mem
            .read(
                VirtAddr(self.ptr(addr)),
                &mut buf,
                self.acc(AccessKind::DataRead),
            )
            .map_err(|_| errno::EFAULT)?;
        Ok(buf)
    }

    /// ゲストメモリへバイト列を書く。
    fn put_bytes(&self, env: &mut BareEnv, addr: u64, data: &[u8]) -> Result<(), u64> {
        env.backend
            .mem
            .write(VirtAddr(self.ptr(addr)), data)
            .map_err(|_| errno::EFAULT)
    }

    /// ゲストの u64 を読む。
    fn mem_u64(&self, env: &mut BareEnv, addr: u64) -> u64 {
        let b = self.get_bytes(env, addr, 8).unwrap_or_default();
        u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8]))
    }

    /// ゲストの u64 を書く。
    fn put_u64(&self, env: &mut BareEnv, addr: u64, v: u64) -> Result<(), u64> {
        self.put_bytes(env, addr, &v.to_le_bytes())
    }

    /// ゲストの u32 を書く。
    fn put_u32(&self, env: &mut BareEnv, addr: u64, v: u32) -> Result<(), u64> {
        self.put_bytes(env, addr, &v.to_le_bytes())
    }

    /// NUL 終端のゲスト文字列を読む。
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

    /// 書き込み先の分類。
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

    /// `writev`（iov は u64 の二つ組）。
    fn sys_writev(&mut self, env: &mut BareEnv, fd: u32, iov: u64, cnt: u64) -> Result<u64, u64> {
        let mut total = 0u64;
        for i in 0..cnt.min(1024) {
            let base = self.mem_u64(env, iov + i * 16);
            let len = self.mem_u64(env, iov + i * 16 + 8);
            match self.sys_write(env, fd, base, len) {
                Ok(n) => total = total.wrapping_add(n),
                Err(e) => {
                    return if total > 0 { Ok(total) } else { Err(e) };
                }
            }
        }
        Ok(total)
    }

    /// `read`。
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

    /// `readv`。
    fn sys_readv(&mut self, env: &mut BareEnv, fd: u32, iov: u64, cnt: u64) -> Result<u64, u64> {
        let mut total = 0u64;
        for i in 0..cnt.min(1024) {
            let base = self.mem_u64(env, iov + i * 16);
            let len = self.mem_u64(env, iov + i * 16 + 8);
            match self.sys_read(env, fd, base, len) {
                Ok(n) => {
                    total = total.wrapping_add(n);
                    if n < len {
                        break;
                    }
                }
                Err(e) => {
                    return if total > 0 { Ok(total) } else { Err(e) };
                }
            }
        }
        Ok(total)
    }

    /// `lseek`。
    fn sys_lseek(&mut self, fd: u32, off: i64, whence: u64) -> Result<u64, u64> {
        if whence > 2 {
            return Err(errno::EINVAL);
        }
        let Some(f) = self.fds.get_mut(fd) else {
            return Err(errno::EBADF);
        };
        let w = match whence {
            0 => SeekFrom::Start(off as u64),
            1 => SeekFrom::Current(off),
            _ => SeekFrom::End(off),
        };
        match f.seek(w) {
            Ok(p) => Ok(p),
            Err(e) => Err(host_errno(e.raw_os_error())),
        }
    }

    /// `close`。
    fn sys_close(&mut self, fd: u32) -> Result<u64, u64> {
        if fd < 3 {
            return Ok(0);
        }
        if self.fds.get(fd).is_some() {
            self.fds.clear(fd);
            Ok(0)
        } else {
            Err(errno::EBADF)
        }
    }

    /// `openat`（O_* フラグは asm-generic の値）。
    fn sys_openat(
        &mut self,
        env: &mut BareEnv,
        dirfd: u64,
        path: u64,
        flags: u64,
        _mode: u64,
    ) -> Result<u64, u64> {
        let guest_path = self.cstr(env, path)?;
        let Some(full) = self.host_path(dirfd, &guest_path) else {
            return Err(errno::EBADF);
        };
        let accmode = flags & 3;
        let mut opt = std::fs::OpenOptions::new();
        opt.read(accmode != 1)
            .write(accmode != 0)
            .append(flags & 0o2000 != 0);
        if flags & 0o100 != 0 {
            opt.create(true);
        }
        if flags & 0o1000 != 0 {
            opt.truncate(true);
        }
        // O_NOFOLLOW・O_PATH・O_DIRECTORY は最小実装では捨てる。
        // Gap: GAP-0062（O_* 全集と *at フラグの整備は後の段階）。
        match opt.open(&full) {
            Ok(f) => {
                let fd = self.fds.alloc(Some(f));
                self.fds.remember_path(fd, full.clone());
                Ok(u64::from(fd))
            }
            Err(e) => Err(host_errno(e.raw_os_error())),
        }
    }

    /// asm-generic `struct stat`（LoongArch の newfstat）。
    /// レイアウト: st_dev u64, st_ino u64, st_mode u32, st_nlink u32,
    /// st_uid u32, st_gid u32, st_rdev u64, __pad1 u64, st_size i64,
    /// st_blksize i32, __pad2 i32, st_blocks i64,
    /// atime i64, ansec i64, mtime i64, mnsec i64, ctime i64, cnsec i64,
    /// __unused u32×2。計 128 バイト。
    /// Ref: SRC-LINUX — include/uapi/asm-generic/stat.h.
    fn put_stat(&self, env: &mut BareEnv, addr: u64, md: &polyisa_host::Stat) -> Result<(), u64> {
        self.put_u64(env, addr, md.dev)?;
        self.put_u64(env, addr + 8, md.ino)?;
        self.put_u32(env, addr + 16, md.mode)?;
        self.put_u32(env, addr + 20, md.nlink as u32)?;
        self.put_u32(env, addr + 24, md.uid)?;
        self.put_u32(env, addr + 28, md.gid)?;
        self.put_u64(env, addr + 32, md.rdev)?;
        self.put_u64(env, addr + 40, 0)?;
        self.put_u64(env, addr + 48, md.size)?;
        self.put_u32(env, addr + 56, md.blksize as u32)?;
        self.put_u32(env, addr + 60, 0)?;
        self.put_u64(env, addr + 64, md.blocks)?;
        self.put_u64(env, addr + 72, md.atime as u64)?;
        self.put_u64(env, addr + 80, md.atime_nsec as u64)?;
        self.put_u64(env, addr + 88, md.mtime as u64)?;
        self.put_u64(env, addr + 96, md.mtime_nsec as u64)?;
        self.put_u64(env, addr + 104, md.ctime as u64)?;
        self.put_u64(env, addr + 112, md.ctime_nsec as u64)?;
        Ok(())
    }

    /// `fstat`。
    fn sys_fstat(&mut self, env: &mut BareEnv, fd: u32, addr: u64) -> Result<u64, u64> {
        let md = match fd {
            0..=2 => {
                // 端末・パイプはキャラクタデバイス風の合成 stat。
                let f =
                    std::fs::File::open("/dev/null").map_err(|e| host_errno(e.raw_os_error()))?;
                polyisa_host::fstat(&f).map_err(|e| host_errno(e.raw_os_error()))?
            }
            _ => match self.fds.get(fd) {
                Some(f) => polyisa_host::fstat(f).map_err(|e| host_errno(e.raw_os_error()))?,
                None => return Err(errno::EBADF),
            },
        };
        self.put_stat(env, addr, &md)?;
        Ok(0)
    }

    /// `newfstatat`（AT_FDCWD と通常パス。flag は最小限）。
    fn sys_fstatat(
        &mut self,
        env: &mut BareEnv,
        dirfd: u64,
        path: u64,
        addr: u64,
        _flags: u64,
    ) -> Result<u64, u64> {
        let guest_path = self.cstr(env, path)?;
        let Some(full) = self.host_path(dirfd, &guest_path) else {
            return Err(errno::EBADF);
        };
        let md = polyisa_host::lstat(&full).map_err(|e| host_errno(e.raw_os_error()))?;
        self.put_stat(env, addr, &md)?;
        Ok(0)
    }

    /// ゲストパスをホストパスへ写す。dirfd は AT_FDCWD(-100)
    /// か `remember_path` で覚えたディレクトリ fd。
    fn host_path(&self, dirfd: u64, guest_path: &str) -> Option<String> {
        const AT_FDCWD: u64 = (-100i64) as u64;
        if guest_path.starts_with('/') || dirfd == AT_FDCWD {
            Some(crate::guest_path::join_guest_path(&self.cwd, guest_path))
        } else {
            self.fds
                .path_of(dirfd as u32)
                .map(|dir| format!("{}/{}", dir.trim_end_matches('/'), guest_path))
        }
    }

    /// `brk`。0 なら現在値を返す。伸びる側は領域の写像として行う。
    fn sys_brk(&mut self, env: &mut BareEnv, addr: u64) -> u64 {
        if self.heap_end == 0 {
            self.heap_end = self.brk_start;
        }
        let addr = self.ptr(addr);
        if addr == 0 || addr < self.brk_start {
            return self.heap_end;
        }
        if addr > self.heap_end {
            let start = self.heap_end & !0xfff;
            let end = (addr + 0xfff) & !0xfff;
            let pages = end.saturating_sub(start) / 0x1000;
            if pages > 0
                && env
                    .backend
                    .mem
                    .map(VirtAddr(start), pages, Perms::RW)
                    .is_err()
            {
                return self.heap_end;
            }
        }
        self.heap_end = addr;
        self.heap_end
    }

    /// `mmap`。匿名 RW のみ。ファイル写像は LA10 で整備する。
    #[allow(clippy::too_many_arguments)]
    fn sys_mmap(
        &mut self,
        env: &mut BareEnv,
        addr: u64,
        len: u64,
        prot: u64,
        flags: u64,
        fd: u64,
        off: u64,
    ) -> Result<u64, u64> {
        const MAP_FIXED: u64 = 0x10;
        const MAP_ANON: u64 = 0x20;
        let len = (len + 0xfff) & !0xfff;
        if len == 0 {
            return Err(errno::EINVAL);
        }
        let mut perms = Perms::NONE;
        if prot & 1 != 0 {
            perms = Perms(perms.0 | Perms::R.0);
        }
        if prot & 2 != 0 {
            perms = Perms(perms.0 | Perms::W.0);
        }
        if prot & 4 != 0 {
            perms = Perms(perms.0 | Perms::X.0);
        }
        let at = if flags & MAP_FIXED != 0 {
            self.ptr(addr) & !0xfff
        } else {
            let at = self.mmap_next;
            self.mmap_next = self.mmap_next.wrapping_add(len + 0x1000);
            at
        };
        env.backend
            .mem
            .map(VirtAddr(at), len / 0x1000, perms)
            .map_err(|_| errno::ENOMEM)?;
        if flags & MAP_ANON == 0 {
            // ファイル写像: 読み込んで内容だけ写す（書き戻しはしない）。
            let Some(f) = self.fds.get_mut(fd as u32) else {
                return Err(errno::EBADF);
            };
            let mut buf = vec![0u8; len as usize];
            let w = SeekFrom::Start(off);
            if f.seek(w).is_ok() {
                let mut filled = 0;
                while filled < buf.len() {
                    match f.read(&mut buf[filled..]) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => filled += n,
                    }
                }
                buf.truncate(filled);
                let _ = self.put_bytes(env, at, &buf);
            }
        }
        Ok(at)
    }

    /// `munmap`。
    fn sys_munmap(&mut self, env: &mut BareEnv, addr: u64, len: u64) -> Result<u64, u64> {
        let at = self.ptr(addr) & !0xfff;
        let pages = (len + 0xfff) & !0xfff;
        env.backend.mem.unmap(VirtAddr(at), pages / 0x1000);
        Ok(0)
    }

    /// `mprotect`。権限の更新だけを行う。
    fn sys_mprotect(
        &mut self,
        env: &mut BareEnv,
        addr: u64,
        len: u64,
        prot: u64,
    ) -> Result<u64, u64> {
        let mut perms = Perms::NONE;
        if prot & 1 != 0 {
            perms = Perms(perms.0 | Perms::R.0);
        }
        if prot & 2 != 0 {
            perms = Perms(perms.0 | Perms::W.0);
        }
        if prot & 4 != 0 {
            perms = Perms(perms.0 | Perms::X.0);
        }
        let at = self.ptr(addr) & !0xfff;
        let pages = (len + 0xfff) & !0xfff;
        env.backend
            .mem
            .protect(VirtAddr(at), pages / 0x1000, perms)
            .map_err(|_| errno::ENOMEM)?;
        Ok(0)
    }

    /// `uname`。utsname は 6×65 バイト。
    fn sys_uname(&mut self, env: &mut BareEnv, addr: u64) -> Result<u64, u64> {
        let fields: [&[u8]; 6] = [
            b"Linux",
            b"polyisa",
            b"6.6.0-polyisa",
            b"#1",
            if self.la64 {
                b"loongarch64"
            } else {
                b"loongarch32"
            },
            b"",
        ];
        let mut buf = vec![0u8; 6 * 65];
        for (i, s) in fields.iter().enumerate() {
            buf[i * 65..i * 65 + s.len()].copy_from_slice(s);
        }
        self.put_bytes(env, addr, &buf)?;
        Ok(0)
    }

    /// `clock_gettime`・`gettimeofday` 系の時刻を timespec に書く。
    fn put_timespec(&self, env: &mut BareEnv, addr: u64, sec: u64, nsec: u64) -> Result<(), u64> {
        self.put_u64(env, addr, sec)?;
        self.put_u64(env, addr + 8, nsec)
    }

    /// `clock_gettime`。REALTIME は壁時計、MONOTONIC は起点からの経過。
    fn sys_clock_gettime(&mut self, env: &mut BareEnv, clk: u64, addr: u64) -> Result<u64, u64> {
        match clk {
            0 => {
                let d = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                self.put_timespec(env, addr, d.as_secs(), u64::from(d.subsec_nanos()))?;
            }
            1 => {
                let start = *self.mono_start.get_or_insert_with(std::time::Instant::now);
                let d = start.elapsed();
                self.put_timespec(env, addr, d.as_secs(), u64::from(d.subsec_nanos()))?;
            }
            _ => self.put_timespec(env, addr, 0, 0)?,
        }
        Ok(0)
    }

    /// `nanosleep`。
    fn sys_nanosleep(&mut self, env: &mut BareEnv, req: u64, _rem: u64) -> Result<u64, u64> {
        let sec = self.mem_u64(env, req);
        let nsec = self.mem_u64(env, req + 8);
        let d = std::time::Duration::new(sec, nsec as u32);
        if d.as_millis() < 5000 {
            std::thread::sleep(d);
        }
        Ok(0)
    }

    /// `readlinkat`。/proc/self/exe は exe_path を返す。
    fn sys_readlinkat(
        &mut self,
        env: &mut BareEnv,
        dirfd: u64,
        path: u64,
        buf: u64,
        bufsiz: u64,
    ) -> Result<u64, u64> {
        let guest_path = self.cstr(env, path)?;
        let target = if guest_path == "/proc/self/exe" {
            self.exe_path.clone()
        } else {
            let Some(full) = self.host_path(dirfd, &guest_path) else {
                return Err(errno::EBADF);
            };
            match std::fs::read_link(&full) {
                Ok(t) => t.to_string_lossy().into_owned(),
                Err(e) => return Err(host_errno(e.raw_os_error())),
            }
        };
        let bytes = target.as_bytes();
        let n = bytes.len().min(bufsiz as usize);
        self.put_bytes(env, buf, &bytes[..n])?;
        Ok(n as u64)
    }

    /// `getcwd`。
    fn sys_getcwd(&mut self, env: &mut BareEnv, buf: u64, size: u64) -> Result<u64, u64> {
        let cwd = if self.cwd.is_empty() { "/" } else { &self.cwd };
        let mut b = cwd.as_bytes().to_vec();
        b.push(0);
        if b.len() as u64 > size {
            return Err(errno::ERANGE);
        }
        self.put_bytes(env, buf, &b)?;
        Ok(b.len() as u64)
    }

    /// `getrandom`。決定論的な疑似乱数（xorshift）で埋める。
    /// 暗号学的品質は持たない。テスト決定性のための合成値。
    /// Gap: GAP-0062（合成値の扱い）。
    fn sys_getrandom(
        &mut self,
        env: &mut BareEnv,
        buf: u64,
        len: u64,
        _flags: u64,
    ) -> Result<u64, u64> {
        let n = (len as usize).min(1 << 20);
        let mut out = vec![0u8; n];
        let mut s: u64 = 0x9e37_79b9_7f4a_7c15 ^ u64::from(self.pid as u32);
        for chunk in out.chunks_mut(8) {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            chunk.copy_from_slice(&s.to_le_bytes()[..chunk.len()]);
        }
        self.put_bytes(env, buf, &out)?;
        Ok(n as u64)
    }

    /// `sched_getaffinity`。1 CPU を報告する。
    fn sys_sched_getaffinity(
        &mut self,
        env: &mut BareEnv,
        _pid: u64,
        size: u64,
        mask: u64,
    ) -> Result<u64, u64> {
        if size < 8 {
            return Err(errno::EINVAL);
        }
        self.put_u64(env, mask, 1)?;
        Ok(0)
    }

    /// `prlimit64`。rlimit は無限を返す（合成値）。
    fn sys_prlimit64(
        &mut self,
        env: &mut BareEnv,
        _pid: u64,
        _res: u64,
        _new: u64,
        old: u64,
    ) -> Result<u64, u64> {
        if old != 0 {
            self.put_u64(env, old, u64::MAX)?;
            self.put_u64(env, old + 8, u64::MAX)?;
        }
        Ok(0)
    }

    /// `getcpu`。
    fn sys_getcpu(
        &mut self,
        env: &mut BareEnv,
        cpu: u64,
        node: u64,
        _cache: u64,
    ) -> Result<u64, u64> {
        if cpu != 0 {
            self.put_u32(env, cpu, 0)?;
        }
        if node != 0 {
            self.put_u32(env, node, 0)?;
        }
        Ok(0)
    }

    /// `ioctl`。端末判定（TCGETS=0x5401）には ENOTTY、その他は ENOSYS。
    fn sys_ioctl(&mut self, fd: u32, req: u64, _arg: u64) -> Result<u64, u64> {
        match req {
            0x5401 | 0x5402 | 0x5403 | 0x5413 => Err(errno::ENOTTY),
            _ => {
                let _ = fd;
                Err(errno::ENOSYS)
            }
        }
    }

    /// `fcntl`。最小限（F_GETFL は 0、F_DUPFD は複製）。
    fn sys_fcntl(&mut self, fd: u32, cmd: u64, arg: u64) -> Result<u64, u64> {
        match cmd {
            // F_DUPFD=0, F_DUPFD_CLOEXEC=1030
            0 | 1030 => {
                let Some(f) = self.fds.get(fd) else {
                    return Err(errno::EBADF);
                };
                let nf = f.try_clone().map_err(|e| host_errno(e.raw_os_error()))?;
                let nfd = self.fds.alloc(Some(nf));
                if (nfd as u64) < arg {
                    self.fds.clear(nfd);
                    return Err(errno::EINVAL);
                }
                Ok(u64::from(nfd))
            }
            // F_GETFD=1, F_GETFL=3, F_SETFD=2, F_SETFL=4
            1 | 3 => Ok(0),
            2 | 4 => Ok(0),
            _ => Err(errno::EINVAL),
        }
    }

    /// `dup`。
    fn sys_dup(&mut self, fd: u32) -> Result<u64, u64> {
        let Some(f) = self.fds.get(fd) else {
            return Err(errno::EBADF);
        };
        let nf = f.try_clone().map_err(|e| host_errno(e.raw_os_error()))?;
        Ok(u64::from(self.fds.alloc(Some(nf))))
    }
}

/// `handle_trap` 内の syscall ディスパッチ。
impl Linux {
    fn syscall(&mut self, env: &mut BareEnv) -> TrapOutcome {
        let nr = self.rget(env, 11);
        let a: Vec<u64> = (0..6).map(|i| self.rget(env, 4 + i)).collect();
        if std::env::var_os("POLYISA_LOONGARCH_SYSCALL").is_some() {
            eprintln!(
                "loongarch: syscall {}({}) args={:x?}",
                loongarch::name(nr).unwrap_or("?"),
                nr,
                a
            );
        }
        let ret: Result<u64, u64> = match nr {
            loongarch::nr::WRITE => self.sys_write(env, a[0] as u32, a[1], a[2]),
            loongarch::nr::WRITEV => self.sys_writev(env, a[0] as u32, a[1], a[2]),
            loongarch::nr::READ => self.sys_read(env, a[0] as u32, a[1], a[2]),
            loongarch::nr::READV => self.sys_readv(env, a[0] as u32, a[1], a[2]),
            loongarch::nr::CLOSE => self.sys_close(a[0] as u32),
            loongarch::nr::LSEEK => self.sys_lseek(a[0] as u32, a[1] as i64, a[2]),
            loongarch::nr::OPENAT => self.sys_openat(env, a[0], a[1], a[2], a[3]),
            loongarch::nr::FSTAT => self.sys_fstat(env, a[0] as u32, a[1]),
            loongarch::nr::NEWFSTATAT => self.sys_fstatat(env, a[0], a[1], a[2], a[3]),
            loongarch::nr::BRK => Ok(self.sys_brk(env, a[0])),
            loongarch::nr::MMAP => self.sys_mmap(env, a[0], a[1], a[2], a[3], a[4], a[5]),
            loongarch::nr::MUNMAP => self.sys_munmap(env, a[0], a[1]),
            loongarch::nr::MPROTECT => self.sys_mprotect(env, a[0], a[1], a[2]),
            loongarch::nr::UTSNAME => self.sys_uname(env, a[0]),
            loongarch::nr::CLOCK_GETTIME => self.sys_clock_gettime(env, a[0], a[1]),
            loongarch::nr::CLOCK_GETRES => self.put_timespec(env, a[1], 0, 1).map(|()| 0),
            loongarch::nr::NANOSLEEP => self.sys_nanosleep(env, a[0], a[1]),
            loongarch::nr::READLINKAT => self.sys_readlinkat(env, a[0], a[1], a[2], a[3]),
            loongarch::nr::GETCWD => self.sys_getcwd(env, a[0], a[1]),
            loongarch::nr::GETRANDOM => self.sys_getrandom(env, a[0], a[1], a[2]),
            loongarch::nr::SCHED_GETAFFINITY => self.sys_sched_getaffinity(env, a[0], a[1], a[2]),
            loongarch::nr::PRLIMIT64 => self.sys_prlimit64(env, a[0], a[1], a[2], a[3]),
            loongarch::nr::GETCPU => self.sys_getcpu(env, a[0], a[1], a[2]),
            loongarch::nr::IOCTL => self.sys_ioctl(a[0] as u32, a[1], a[2]),
            loongarch::nr::FCNTL => self.sys_fcntl(a[0] as u32, a[1], a[2]),
            loongarch::nr::DUP => self.sys_dup(a[0] as u32),
            loongarch::nr::EXIT | loongarch::nr::EXIT_GROUP => {
                return TrapOutcome::Exit(a[0] as u32);
            }
            loongarch::nr::GETPID | loongarch::nr::GETTID => Ok(self.pid),
            loongarch::nr::GETPPID => Ok(self.pid.saturating_sub(1)),
            loongarch::nr::GETUID
            | loongarch::nr::GETEUID
            | loongarch::nr::GETGID
            | loongarch::nr::GETEGID => Ok(1000),
            loongarch::nr::SET_TID_ADDRESS => Ok(self.pid),
            loongarch::nr::SET_ROBUST_LIST
            | loongarch::nr::RT_SIGACTION
            | loongarch::nr::RT_SIGPROCMASK
            | loongarch::nr::RT_SIGRETURN
            | loongarch::nr::SCHED_YIELD => Ok(0),
            // futex は単一スレッド模型で常に即座に返す。
            loongarch::nr::FUTEX => Ok(0),
            _ => {
                if !self.reported.contains(&nr) {
                    self.reported.push(nr);
                    if std::env::var_os("POLYISA_LOONGARCH_DEBUG").is_some() {
                        eprintln!("loongarch: 未実装 syscall {nr}");
                    }
                }
                Err(errno::ENOSYS)
            }
        };
        match ret {
            Ok(v) => self.rset(env, 4, v),
            Err(e) => self.rset(env, 4, e.wrapping_neg()),
        }
        TrapOutcome::Handled
    }
}

impl TrapHandler for Linux {
    fn handle_trap(&mut self, env: &mut BareEnv, code: u32) -> TrapOutcome {
        if u64::from(code) & sem::TRAP_SYS == sem::TRAP_SYS {
            return self.syscall(env);
        }
        // break・未定義命令は未実装として止める。
        TrapOutcome::Unimplemented
    }

    fn init_brk(&mut self, image_end: u64) {
        self.brk_start = (image_end + 0xfff) & !0xfff;
        // LA32 でも 0x7000_0000 に置く（両方とも入る値）。
        self.mmap_next = 0x0000_0000_7000_0000;
    }
}
