// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! SuperH Linux の syscall 処理。
//!
//! 規約（SRC-LINUX — arch/sh syscall 規約）:
//! - 発行点は `trapa #0x10`–`#0x1f`（即値は引数の個数分だけ使い分ける）。
//! - 番号は R3、引数は R4–R7・R0・R1、戻り値は R0。失敗は R0 = -errno。
//! - SH には SYSCALL 命令はなく、全て trapa 経由。
//!
//! 単一プロセス・単一スレッド模型: fork/clone/execve/パイプ/ソケット/
//! epoll/タイマ系は ENOSYS。シグナル枠組みは登録を受理するだけで
//! 配送しない。統計・時刻の一部は合成値。直列化はゲストエンディアンに
//! 従う（LE/BE 両対応）。
//! 信頼できないゲストバイナリには使わないこと。
// Ref: SRC-LINUX (7.3) — arch/sh/kernel/entry-common.S,
// arch/sh/kernel/syscalls/syscall.tbl.

use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

use polyisa_engine::bare::BareEnv;
use polyisa_guest_superh::sem;
use polyisa_kernel::FdTable;
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};
use polyisa_sem::Backend as _;

use crate::{TrapHandler, TrapOutcome, superh};

/// write/writev が集めたバイト。標準出力と標準エラーを分ける。
#[derive(Default)]
pub struct SuperhIo {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// SuperH Linux の syscall 状態機械。
/// R3=番号、R4–R7・R0・R1=引数、R0=戻り値。
// Gap: GAP-0060
pub struct Linux {
    /// 標準出力・標準エラーの捕獲。テストが読む。
    pub io: SuperhIo,
    /// 開いたファイルの表（ゲスト fd 3 以降）。
    fds: FdTable,
    /// プログラムブレーク。0 は未初期化。
    heap_end: u64,
    /// brk 領域の開始（ELF の image_end）。`init_brk` が設定する。
    brk_start: u64,
    /// mmap の次に置く場所。init_brk から離して取る。
    mmap_next: u64,
    /// ファイル作成の umask。
    umask: u32,
    /// ホストから見たプロセス識別子。getpid/gettid が返す。
    pid: u64,
    /// ゲストの作業ディレクトリ。空はホストの作業ディレクトリ。
    cwd: String,
    /// 実行ファイルのパス。`readlinkat("/proc/self/exe")` が返す。
    pub exe_path: String,
    /// データアクセスのエンディアン（ELF から実行ループが設定する）。
    pub endian: Endian,
    /// 標準入力へ供給するバイト。
    pub stdin_buf: Vec<u8>,
    stdin_pos: usize,
    /// MONOTONIC 時計の起点。
    mono_start: Option<std::time::Instant>,
    /// ディレクトリ fd の getdents 位置（エントリの通し番号）。
    dir_pos: std::collections::HashMap<u32, usize>,
    /// 報告済みの未実装番号（一度だけ出す）。
    reported: Vec<u64>,
}

impl Default for Linux {
    fn default() -> Self {
        Self::new()
    }
}

impl Linux {
    /// SuperH Linux の状態機械を作る。
    #[must_use]
    pub fn new() -> Self {
        Self {
            io: SuperhIo::default(),
            fds: FdTable::default(),
            heap_end: 0,
            brk_start: 0,
            mmap_next: 0x7000_0000,
            umask: 0o22,
            pid: std::process::id().into(),
            cwd: String::new(),
            exe_path: String::new(),
            endian: Endian::Le,
            stdin_buf: Vec::new(),
            stdin_pos: 0,
            mono_start: None,
            dir_pos: std::collections::HashMap::new(),
            reported: Vec::new(),
        }
    }

    /// ゲストエンディアンのバイト列を u32 にする。
    fn u32_of(&self, b: &[u8]) -> u32 {
        match self.endian {
            Endian::Le => u32::from_le_bytes(b[..4].try_into().unwrap_or([0; 4])),
            Endian::Be => u32::from_be_bytes(b[..4].try_into().unwrap_or([0; 4])),
        }
    }

    fn acc(&self, kind: AccessKind) -> Access {
        Access {
            endian: self.endian,
            align: Align::Unaligned,
            kind,
        }
    }

    /// ゲストメモリから `n` バイト読む。
    fn get_bytes(&self, env: &mut BareEnv, addr: u64, n: usize) -> Result<Vec<u8>, u64> {
        let mut buf = vec![0u8; n.min(1 << 22)];
        if buf.is_empty() {
            return Ok(buf);
        }
        env.backend
            .mem
            .read(VirtAddr(addr), &mut buf, self.acc(AccessKind::DataRead))
            .map_err(|_| u64::from(superh::errno::EFAULT))?;
        Ok(buf)
    }

    /// ゲストメモリへバイト列を書く。
    fn put_bytes(&self, env: &mut BareEnv, addr: u64, data: &[u8]) -> Result<(), u64> {
        env.backend
            .mem
            .write(VirtAddr(addr), data)
            .map_err(|_| u64::from(superh::errno::EFAULT))
    }

    /// ゲストエンディアンで u16 を書く。
    fn put16(&self, env: &mut BareEnv, addr: u64, v: u16) -> Result<(), u64> {
        let b = match self.endian {
            Endian::Le => v.to_le_bytes(),
            Endian::Be => v.to_be_bytes(),
        };
        self.put_bytes(env, addr, &b)
    }

    /// ゲストエンディアンで u32 を書く。
    fn put32(&self, env: &mut BareEnv, addr: u64, v: u32) -> Result<(), u64> {
        let b = match self.endian {
            Endian::Le => v.to_le_bytes(),
            Endian::Be => v.to_be_bytes(),
        };
        self.put_bytes(env, addr, &b)
    }

    /// ゲストエンディアンで u64 を書く。
    fn put64(&self, env: &mut BareEnv, addr: u64, v: u64) -> Result<(), u64> {
        let b = match self.endian {
            Endian::Le => v.to_le_bytes(),
            Endian::Be => v.to_be_bytes(),
        };
        self.put_bytes(env, addr, &b)
    }

    /// ゲストエンディアンで u32 を読む（失敗時 0）。
    fn mem_u(&self, env: &mut BareEnv, addr: u64) -> u64 {
        let mut b = [0u8; 4];
        env.backend
            .mem
            .read(VirtAddr(addr), &mut b, self.acc(AccessKind::DataRead))
            .map_or(0, |()| u64::from(self.u32_of(&b)))
    }

    /// NUL 終端のゲスト文字列を読む。
    fn get_cstr(&self, env: &mut BareEnv, addr: u64) -> Result<Vec<u8>, u64> {
        let mut out = Vec::new();
        let acc = self.acc(AccessKind::DataRead);
        for a in (addr..).take(4096) {
            let mut b = [0u8; 1];
            if env.backend.mem.read(VirtAddr(a), &mut b, acc).is_err() {
                return Err(u64::from(superh::errno::EFAULT));
            }
            if b[0] == 0 {
                return Ok(out);
            }
            out.push(b[0]);
        }
        Err(u64::from(superh::errno::ENAMETOOLONG))
    }

    /// ゲストのパスをホストのパスへ（相対は cwd から）。
    fn host_path(&self, guest: &[u8]) -> String {
        let path = String::from_utf8_lossy(guest).into_owned();
        if path.starts_with('/') || self.cwd.is_empty() {
            path
        } else {
            format!("{}/{}", self.cwd.trim_end_matches('/'), path)
        }
    }

    /// ゲスト fd をホストの File として取る。
    fn file_of(&mut self, fd: u32) -> Result<&mut std::fs::File, u64> {
        self.fds.file_mut(fd).ok_or(u64::from(superh::errno::EBADF))
    }

    /// 読み用に fd を開いているものを返す。0/1/2 と FdTable の両方を見る。
    fn reader(&mut self, fd: u32) -> Result<ReadFd<'_>, u64> {
        match fd {
            0 => Ok(ReadFd::Stdin),
            1 | 2 => Err(u64::from(superh::errno::EBADF)),
            _ => self
                .fds
                .file_mut(fd)
                .map(ReadFd::File)
                .ok_or(u64::from(superh::errno::EBADF)),
        }
    }

    fn writer(&mut self, fd: u32) -> Result<WriteFd<'_>, u64> {
        match fd {
            0 => Err(u64::from(superh::errno::EBADF)),
            1 => Ok(WriteFd::Stdout),
            2 => Ok(WriteFd::Stderr),
            _ => self
                .fds
                .file_mut(fd)
                .map(WriteFd::File)
                .ok_or(u64::from(superh::errno::EBADF)),
        }
    }

    /// SH の `O_*`（asm-generic）をホストの `OpenOptions` 用フラグへ写す。
    fn open_flags(guest: u32) -> std::fs::OpenOptions {
        use superh::oflag::*;
        let mut oo = std::fs::OpenOptions::new();
        let accmode = guest & ACCMODE;
        oo.read(accmode != 1).write(accmode != 0);
        oo.append(guest & APPEND != 0);
        if guest & TRUNC != 0 {
            oo.truncate(true);
        }
        if guest & CREAT != 0 {
            oo.create(true);
        }
        if guest & EXCL != 0 {
            oo.create_new(true);
        }
        oo
    }

    /// open/openat の共通部。dirfd は AT_FDCWD か fd 保持の
    /// ディレクトリ（fd 経由の相対解決は fd の記憶パスを基底にする）。
    fn sys_open(
        &mut self,
        env: &mut BareEnv,
        dirfd: i64,
        path_addr: u64,
        flags: u32,
        mode: u32,
    ) -> Result<u64, u64> {
        const AT_FDCWD: i64 = -100;
        let path = self.get_cstr(env, path_addr)?;
        let base = if path.starts_with(b"/") || dirfd == AT_FDCWD {
            self.host_path(&path)
        } else if let Some(dir) = self.fds.path_of(dirfd as u32) {
            format!(
                "{}/{}",
                dir.trim_end_matches('/'),
                String::from_utf8_lossy(&path)
            )
        } else {
            return Err(u64::from(superh::errno::EBADF));
        };
        let oo = Self::open_flags(flags);
        let _ = mode;
        match oo.open(&base) {
            Ok(f) => {
                let fd = self.fds.alloc(polyisa_kernel::FdTarget::File(f));
                self.fds.remember_path(fd, base);
                Ok(u64::from(fd))
            }
            Err(e) => Err(host_errno(e.raw_os_error())),
        }
    }

    /// `read`/`pread64` の共通部。
    fn sys_read(&mut self, env: &mut BareEnv, fd: u32, buf: u64, len: u64) -> Result<u64, u64> {
        let len = len.min(1 << 20) as usize;
        let r = self.reader(fd)?;
        match r {
            ReadFd::Stdin => {
                let mut chunk = vec![0u8; len];
                let n = if self.stdin_pos < self.stdin_buf.len() {
                    let avail = &self.stdin_buf[self.stdin_pos..];
                    let take = avail.len().min(len);
                    chunk[..take].copy_from_slice(&avail[..take]);
                    self.stdin_pos += take;
                    take
                } else {
                    0
                };
                self.put_bytes(env, buf, &chunk[..n])?;
                Ok(n as u64)
            }
            ReadFd::File(f) => {
                let mut chunk = vec![0u8; len];
                match f.read(&mut chunk) {
                    Ok(n) => {
                        self.put_bytes(env, buf, &chunk[..n])?;
                        Ok(n as u64)
                    }
                    Err(e) => Err(host_errno(e.raw_os_error())),
                }
            }
        }
    }

    /// `pread64`。ファイル位置を変えずに offset から読む。
    fn sys_pread(
        &mut self,
        env: &mut BareEnv,
        fd: u32,
        buf: u64,
        len: u64,
        off: u64,
    ) -> Result<u64, u64> {
        let len = len.min(1 << 20) as usize;
        let f = self.file_of(fd)?;
        let mut chunk = vec![0u8; len];
        match polyisa_host::pread(f, &mut chunk, off) {
            Ok(n) => {
                self.put_bytes(env, buf, &chunk[..n])?;
                Ok(n as u64)
            }
            Err(e) => Err(host_errno(e.raw_os_error())),
        }
    }

    /// `write`/`pwrite64` の共通部。
    fn sys_write(&mut self, env: &mut BareEnv, fd: u32, buf: u64, len: u64) -> Result<u64, u64> {
        let data = self.get_bytes(env, buf, len as usize)?;
        let w = self.writer(fd)?;
        match w {
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
            WriteFd::File(f) => match f.write(&data) {
                Ok(n) => Ok(n as u64),
                Err(e) => Err(host_errno(e.raw_os_error())),
            },
        }
    }

    /// `pwrite64`。ファイル位置を変えずに offset へ書く。
    fn sys_pwrite(
        &mut self,
        env: &mut BareEnv,
        fd: u32,
        buf: u64,
        len: u64,
        off: u64,
    ) -> Result<u64, u64> {
        let len = len.min(1 << 20) as usize;
        let data = self.get_bytes(env, buf, len)?;
        let f = self.file_of(fd)?;
        match polyisa_host::pwrite(f, &data, off) {
            Ok(n) => Ok(n as u64),
            Err(e) => Err(host_errno(e.raw_os_error())),
        }
    }

    /// `readv`（iov は u32 の二つ組）。
    fn sys_readv(&mut self, env: &mut BareEnv, fd: u32, iov: u64, cnt: u64) -> Result<u64, u64> {
        let mut total = 0u64;
        for i in 0..cnt.min(1024) {
            let base = self.mem_u(env, iov + i * 8);
            let len = self.mem_u(env, iov + i * 8 + 4);
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

    /// `writev`。
    fn sys_writev(&mut self, env: &mut BareEnv, fd: u32, iov: u64, cnt: u64) -> Result<u64, u64> {
        let mut total = 0u64;
        for i in 0..cnt.min(1024) {
            let base = self.mem_u(env, iov + i * 8);
            let len = self.mem_u(env, iov + i * 8 + 4);
            match self.sys_write(env, fd, base, len) {
                Ok(n) => total = total.wrapping_add(n),
                Err(e) => {
                    return if total > 0 { Ok(total) } else { Err(e) };
                }
            }
        }
        Ok(total)
    }

    /// `lseek`。
    fn sys_lseek(&mut self, fd: u32, off: i64, whence: u32) -> Result<u64, u64> {
        if whence > 2 {
            return Err(u64::from(superh::errno::EINVAL));
        }
        if whence == 0 && off == 0 {
            self.dir_pos.remove(&fd);
        }
        let f = self.file_of(fd)?;
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
        if self.fds.ent(fd).is_some() {
            self.fds.clear(fd);
            self.dir_pos.remove(&fd);
            Ok(0)
        } else {
            Err(u64::from(superh::errno::EBADF))
        }
    }

    /// ホストのメタデータをゲストの `stat64`（104B）に写す。
    /// SH-32 のレイアウトは uapi/asm/stat.h の stat64 に従う
    /// （ARM/m68k と同じ形）。
    /// Ref: SRC-LINUX (7.3) — arch/sh/include/uapi/asm/stat.h.
    fn put_stat64(&self, env: &mut BareEnv, addr: u64, md: &polyisa_host::Stat) -> Result<(), u64> {
        // 0: u64 dev, 8: pad0(4), 12: u32 __st_ino, 16: u32 mode,
        // 20: u32 nlink, 24: u32 uid, 28: u32 gid, 32: u64 rdev,
        // 40: pad3(4), 44: pad(4), 48: i64 size, 56: u32 blksize,
        // 60: pad(4), 64: u64 blocks, 72: u32 atime, 76: u32 ansec,
        // 80: u32 mtime, 84: u32 mnsec, 88: u32 ctime, 92: u32 cnsec,
        // 96: u64 ino
        self.put64(env, addr, md.dev)?;
        self.put32(env, addr + 12, md.ino as u32)?;
        self.put32(env, addr + 16, md.mode)?;
        self.put32(env, addr + 20, md.nlink as u32)?;
        self.put32(env, addr + 24, md.uid)?;
        self.put32(env, addr + 28, md.gid)?;
        self.put64(env, addr + 32, md.rdev)?;
        self.put64(env, addr + 48, md.size)?;
        self.put32(env, addr + 56, md.blksize as u32)?;
        self.put64(env, addr + 64, md.blocks)?;
        self.put32(env, addr + 72, md.atime as u32)?;
        self.put32(env, addr + 76, md.atime_nsec as u32)?;
        self.put32(env, addr + 80, md.mtime as u32)?;
        self.put32(env, addr + 84, md.mtime_nsec as u32)?;
        self.put32(env, addr + 88, md.ctime as u32)?;
        self.put32(env, addr + 92, md.ctime_nsec as u32)?;
        self.put64(env, addr + 96, md.ino)
    }

    /// ホストのメタデータを旧 `struct stat`（SH-32・60B+pad）に写す。
    /// Ref: SRC-LINUX (7.3) — arch/sh/include/uapi/asm/stat.h.
    fn put_stat(&self, env: &mut BareEnv, addr: u64, md: &polyisa_host::Stat) -> Result<(), u64> {
        // u32 dev, u32 ino, u16 mode, u16 nlink, u16 uid, u16 gid,
        // u32 rdev, i32 size, u32 blksize, u32 blocks,
        // u32 atime/ansec/mtime/mnsec/ctime/cnsec, u32 __unused[2]
        self.put32(env, addr, md.dev as u32)?;
        self.put32(env, addr + 4, md.ino as u32)?;
        self.put16(env, addr + 8, md.mode as u16)?;
        self.put16(env, addr + 10, md.nlink as u16)?;
        self.put16(env, addr + 12, md.uid as u16)?;
        self.put16(env, addr + 14, md.gid as u16)?;
        self.put32(env, addr + 16, md.rdev as u32)?;
        self.put32(env, addr + 20, md.size as u32)?;
        self.put32(env, addr + 24, md.blksize as u32)?;
        self.put32(env, addr + 28, md.blocks as u32)?;
        self.put32(env, addr + 32, md.atime as u32)?;
        self.put32(env, addr + 36, md.atime_nsec as u32)?;
        self.put32(env, addr + 40, md.mtime as u32)?;
        self.put32(env, addr + 44, md.mtime_nsec as u32)?;
        self.put32(env, addr + 48, md.ctime as u32)?;
        self.put32(env, addr + 52, md.ctime_nsec as u32)
    }

    /// `statx`（256B）。
    fn put_statx(&self, env: &mut BareEnv, addr: u64, md: &polyisa_host::Stat) -> Result<(), u64> {
        // statx: 0 u32 mask, 4 u32 blksize, 8 u64 attributes,
        // 16 u32 nlink, 20 u32 uid, 24 u32 gid, 28 u16 mode, 30 u16 spare,
        // 32 u64 ino, 40 u64 size, 48 u64 blocks, 56 u64 attrs_mask,
        // 64 atime {i64 sec,i32 nsec,i32 reserved}, 80 btime,
        // 96 ctime, 112 mtime,
        // 128 u32 rdev_major, 132 u32 rdev_minor,
        // 136 u32 dev_major, 140 u32 dev_minor,
        // 144 u64 mnt_id, 152 u32 dio_mem_align, 156 u32 dio_off_align,
        // 160 u64 spare[12]。
        // 予約・未対応フィールドは 0 で埋める（btime/mnt_id 等は
        // 未提供）。書き込むのは STATX_BASIC_STATS（0x7ff）の範囲
        // なので mask もそれに合わせる。
        // Ref: SRC-LINUX — include/uapi/linux/stat.h（struct statx）.
        for i in 0..32u64 {
            self.put64(env, addr + i * 8, 0)?;
        }
        // Linux の dev_t 符号化から major/minor を取り出す
        // （new_encode_dev/new_decode_dev の逆）。
        fn major(d: u64) -> u32 {
            (((d >> 8) & 0xfff) | (d >> 32)) as u32
        }
        fn minor(d: u64) -> u32 {
            ((d & 0xff) | ((d >> 12) & !0xff)) as u32
        }
        self.put32(env, addr, 0x07ff)?; // STATX_BASIC_STATS
        self.put32(env, addr + 4, md.blksize as u32)?;
        self.put32(env, addr + 16, md.nlink as u32)?;
        self.put32(env, addr + 20, md.uid)?;
        self.put32(env, addr + 24, md.gid)?;
        self.put16(env, addr + 28, md.mode as u16)?;
        self.put64(env, addr + 32, md.ino)?;
        self.put64(env, addr + 40, md.size)?;
        self.put64(env, addr + 48, md.blocks)?;
        self.put64(env, addr + 64, md.atime as u64)?;
        self.put32(env, addr + 72, md.atime_nsec as u32)?;
        self.put64(env, addr + 96, md.ctime as u64)?;
        self.put32(env, addr + 104, md.ctime_nsec as u32)?;
        self.put64(env, addr + 112, md.mtime as u64)?;
        self.put32(env, addr + 120, md.mtime_nsec as u32)?;
        self.put32(env, addr + 128, major(md.rdev))?;
        self.put32(env, addr + 132, minor(md.rdev))?;
        self.put32(env, addr + 136, major(md.dev))?;
        self.put32(env, addr + 140, minor(md.dev))
    }

    /// stat 系の共通部。`target` は fd かホストパス。レイアウトは
    /// stat/stat64/statx。
    fn sys_stat(
        &mut self,
        env: &mut BareEnv,
        target: StatTarget,
        out: u64,
        lstat: bool,
        kind: StatKind,
    ) -> Result<u64, u64> {
        let md = match target {
            StatTarget::Fd(fd) => match fd {
                0..=2 => match polyisa_host::stat("/dev/null") {
                    Ok(m) => m,
                    Err(e) => return Err(host_errno(e.raw_os_error())),
                },
                _ => match self.fds.file(fd) {
                    Some(f) => match polyisa_host::fstat(f) {
                        Ok(m) => m,
                        Err(e) => return Err(host_errno(e.raw_os_error())),
                    },
                    None => return Err(u64::from(superh::errno::EBADF)),
                },
            },
            StatTarget::Path(host) => {
                let r = if lstat {
                    polyisa_host::lstat(&host)
                } else {
                    polyisa_host::stat(&host)
                };
                match r {
                    Ok(m) => m,
                    Err(e) => return Err(host_errno(e.raw_os_error())),
                }
            }
        };
        match kind {
            StatKind::Stat => self.put_stat(env, out, &md)?,
            StatKind::Stat64 => self.put_stat64(env, out, &md)?,
            StatKind::Statx => self.put_statx(env, out, &md)?,
        }
        Ok(0)
    }

    /// dirfd + ゲストパスを stat 対象に解決する。`flags` の
    /// AT_EMPTY_PATH（0x1000）が立った空パスは dirfd 自身を stat
    /// する（busybox が開いた dir fd に fstatat する形）。
    fn stat_target(
        &mut self,
        env: &mut BareEnv,
        dirfd: i64,
        path_addr: u64,
        flags: u32,
    ) -> Result<StatTarget, u64> {
        const AT_FDCWD: i64 = -100;
        const AT_EMPTY_PATH: u32 = 0x1000;
        let path = self.get_cstr(env, path_addr)?;
        if path.is_empty() {
            // 空パス: AT_EMPTY_PATH なら dirfd 自身。それ以外の空パスも
            // dirfd の stat に寄せる近似（GAP-0060）。
            return if dirfd >= 0 {
                let _ = flags & AT_EMPTY_PATH;
                Ok(StatTarget::Fd(dirfd as u32))
            } else {
                Err(u64::from(superh::errno::ENOENT))
            };
        }
        let host = if path.starts_with(b"/") || dirfd == AT_FDCWD {
            self.host_path(&path)
        } else if let Some(dir) = self.fds.path_of(dirfd as u32) {
            format!(
                "{}/{}",
                dir.trim_end_matches('/'),
                String::from_utf8_lossy(&path)
            )
        } else {
            return Err(u64::from(superh::errno::EBADF));
        };
        Ok(StatTarget::Path(host))
    }

    /// `getdents64`。linux_dirent64: u64 d_ino, u64 d_off, u16 d_reclen,
    /// u8 d_type, name\0。`.`/`..` は合成しない（parisc/alpha 先例）。
    // Gap: GAP-0060
    fn sys_getdents64(
        &mut self,
        env: &mut BareEnv,
        fd: u32,
        buf: u64,
        count: u64,
    ) -> Result<u64, u64> {
        let path = self.fds.path_of(fd).map(str::to_string).unwrap_or_default();
        if path.is_empty() {
            return Err(u64::from(superh::errno::ENOTDIR));
        }
        let rd = match std::fs::read_dir(&path) {
            Ok(r) => r,
            Err(e) => return Err(host_errno(e.raw_os_error())),
        };
        let mut entries: Vec<(u64, String, u8)> = rd
            .filter_map(std::result::Result::ok)
            .map(|e| {
                let ino = polyisa_host::dirent_ino(&e);
                let ft = e.file_type().ok();
                let t = if ft.is_some_and(|t| t.is_dir()) {
                    4u8
                } else if ft.is_some_and(|t| t.is_symlink()) {
                    10
                } else {
                    0
                };
                (ino, e.file_name().to_string_lossy().into_owned(), t)
            })
            .collect();
        entries.sort_by_key(|e| e.0);
        let count = (count as usize).min(1 << 20);
        let mut pos = *self.dir_pos.get(&fd).unwrap_or(&0);
        let mut out = Vec::new();
        let le = self.endian == Endian::Le;
        let mut emitted = 0usize;
        for (i, (ino, name, t)) in entries.iter().enumerate().skip(pos) {
            let reclen = 19 + name.len() + 1;
            let aligned = reclen.next_multiple_of(8);
            if out.len() + aligned > count {
                break;
            }
            let push = |out: &mut Vec<u8>, v: u64, w: usize| match (le, w) {
                (true, 2) => out.extend_from_slice(&(v as u16).to_le_bytes()),
                (false, 2) => out.extend_from_slice(&(v as u16).to_be_bytes()),
                (true, _) => out.extend_from_slice(&v.to_le_bytes()),
                (false, _) => out.extend_from_slice(&v.to_be_bytes()),
            };
            push(&mut out, *ino, 8);
            push(&mut out, (i + 1) as u64, 8);
            push(&mut out, u64::from(aligned as u16), 2);
            out.push(*t);
            out.extend_from_slice(name.as_bytes());
            out.push(0);
            out.resize(out.len() + (aligned - reclen), 0);
            pos += 1;
            emitted += 1;
        }
        if emitted > 0 {
            self.dir_pos.insert(fd, pos);
        }
        self.put_bytes(env, buf, &out)?;
        Ok(out.len() as u64)
    }

    /// `readlink`/`readlinkat`。/proc/self/exe は exe_path を返す
    /// （GAP-0060。/proc の合成はこれだけ）。
    fn sys_readlink(
        &mut self,
        env: &mut BareEnv,
        path_addr: u64,
        buf: u64,
        len: u64,
    ) -> Result<u64, u64> {
        let path = self.get_cstr(env, path_addr)?;
        let host = self.host_path(&path);
        let target = if host == "/proc/self/exe" {
            self.exe_path.clone()
        } else {
            match std::fs::read_link(&host) {
                Ok(t) => t.to_string_lossy().into_owned(),
                Err(e) => return Err(host_errno(e.raw_os_error())),
            }
        };
        let n = target.len().min(len as usize);
        self.put_bytes(env, buf, &target.as_bytes()[..n])?;
        Ok(n as u64)
    }

    /// `ioctl`。TCGETS/TCSETS/TIOCGWINSZ/FIONREAD だけ。
    fn sys_ioctl(&mut self, env: &mut BareEnv, fd: u32, req: u64, argp: u64) -> Result<u64, u64> {
        const TCGETS: u64 = 0x5401;
        const TCSETS: u64 = 0x5402;
        const TIOCGWINSZ: u64 = 0x5413;
        const FIONREAD: u64 = 0x541b;
        match req {
            TCGETS | TCSETS => {
                if fd > 2 {
                    return Err(u64::from(superh::errno::ENOTTY));
                }
                if req == TCGETS {
                    // termios（36B）。cflag に B38400|CS8 を入れる。
                    let mut b = [0u8; 36];
                    let cflag: u32 = 0x1cb0;
                    let bytes = match self.endian {
                        Endian::Le => cflag.to_le_bytes(),
                        Endian::Be => cflag.to_be_bytes(),
                    };
                    b[8..12].copy_from_slice(&bytes);
                    self.put_bytes(env, argp, &b)?;
                }
                Ok(0)
            }
            TIOCGWINSZ => {
                // winsize { u16 row, col, xpixel, ypixel }。
                self.put16(env, argp, 24)?;
                self.put16(env, argp + 2, 80)?;
                self.put16(env, argp + 4, 0)?;
                self.put16(env, argp + 6, 0)?;
                Ok(0)
            }
            FIONREAD => {
                self.put32(env, argp, 0)?;
                Ok(0)
            }
            _ => Err(u64::from(superh::errno::ENOTTY)),
        }
    }

    /// `fcntl`/`fcntl64`。FD フラグと dup だけ。
    fn sys_fcntl(&mut self, fd: u32, cmd: u32, arg: u64) -> Result<u64, u64> {
        match cmd {
            // F_DUPFD(0)/F_DUPFD_CLOEXEC(1030)：fd の複製。
            0 | 1030 => match self.fds.file(fd) {
                Some(f) => match f.try_clone() {
                    Ok(g) => {
                        let nfd = self
                            .fds
                            .alloc_where(polyisa_kernel::FdTarget::File(g), |i| {
                                3 + i >= arg as usize
                            });
                        let p = self.fds.path_of(fd).map(str::to_string);
                        if let Some(p) = p {
                            self.fds.remember_path(nfd, p);
                        }
                        Ok(u64::from(nfd))
                    }
                    Err(e) => Err(host_errno(e.raw_os_error())),
                },
                None => Err(u64::from(superh::errno::EBADF)),
            },
            1 => Ok(0), // F_GETFD
            2 => Ok(0), // F_SETFD
            3 => Ok(0), // F_GETFL（フラグは覚えていない — GAP-0060）
            4 => Ok(0), // F_SETFL
            _ => Err(u64::from(superh::errno::EINVAL)),
        }
    }

    /// `brk`。0 は現ブレークを返し、それ以外は要求値を適用する
    /// （失敗しても現ブレークを返す — kernel の sys_brk と同じ）。
    /// 拡大分のページはここで RW に張る。
    fn sys_brk(&mut self, env: &mut BareEnv, addr: u64) -> u64 {
        if addr == 0 || addr < self.brk_start {
            return self.heap_end;
        }
        if addr > self.heap_end {
            let lo = self.heap_end.div_ceil(4096) * 4096;
            let hi = addr.div_ceil(4096) * 4096;
            if (lo..hi)
                .step_by(4096)
                .any(|a| env.backend.mem.is_mapped(polyisa_mem::PageNo(a / 4096)))
            {
                return self.heap_end;
            }
            if hi > lo
                && env
                    .backend
                    .mem
                    .map(VirtAddr(lo), (hi - lo) / 4096, Perms::RW)
                    .is_err()
            {
                return self.heap_end;
            }
        }
        self.heap_end = addr;
        addr
    }

    /// `mmap`/`mmap2`。`pgoff` はページ単位（呼び出し側が変換する）。
    /// 非 MAP_FIXED は自前の番地を割り当てる。file-backed は内容を
    /// 事前読みする近似（共有・後続 write の反映はない — GAP-0060）。
    #[allow(clippy::too_many_arguments)]
    fn sys_mmap(
        &mut self,
        env: &mut BareEnv,
        addr: u64,
        len: u64,
        prot: u32,
        flags: u32,
        fd: i64,
        pgoff: u64,
    ) -> Result<u64, u64> {
        if len == 0 {
            return Err(u64::from(superh::errno::EINVAL));
        }
        let pages = len.div_ceil(4096);
        let fixed = flags & superh::mmap_flag::FIXED != 0;
        let base = if fixed {
            addr & !0xfff
        } else {
            let b = self.mmap_next;
            self.mmap_next += pages * 4096;
            b
        };
        let mut p = 0u8;
        if prot & superh::mman::PROT_READ != 0 {
            p |= Perms::R.0;
        }
        if prot & superh::mman::PROT_WRITE != 0 {
            p |= Perms::W.0;
        }
        if prot & superh::mman::PROT_EXEC != 0 {
            p |= Perms::X.0;
        }
        if fixed {
            // MAP_FIXED は衝突していても置き換え（GAP-0060）。
            env.backend.mem.unmap(VirtAddr(base), pages);
        }
        match env.backend.mem.map(VirtAddr(base), pages, Perms(p)) {
            Ok(()) => {}
            Err(_) => return Err(u64::from(superh::errno::ENOMEM)),
        }
        if flags & superh::mmap_flag::ANONYMOUS == 0 && fd >= 0 {
            // ファイル対応: 内容を写像へ事前読みする。
            let mut left = (pages * 4096).min(1 << 24);
            let mut at = base;
            let mut off = pgoff * 4096;
            while left > 0 {
                let n = left.min(64 * 1024);
                let mut buf = vec![0u8; n as usize];
                let got = match self.fds.file_mut(fd as u32) {
                    Some(f) => match polyisa_host::pread(f, &mut buf, off) {
                        Ok(g) => g,
                        Err(_) => break,
                    },
                    None => break,
                };
                if got == 0 {
                    break;
                }
                self.put_bytes(env, at, &buf[..got])?;
                at += got as u64;
                off += got as u64;
                left -= got as u64;
            }
        }
        Ok(base)
    }

    /// `munmap`。
    fn sys_munmap(&mut self, env: &mut BareEnv, addr: u64, len: u64) -> u64 {
        let pages = len.div_ceil(4096);
        env.backend.mem.unmap(VirtAddr(addr & !0xfff), pages);
        0
    }

    /// `mprotect`。ゲストページの許可を張り替える。未写像ページが
    /// あれば ENOMEM（Linux の VMA ギャップと同等の失敗として返す）。
    fn sys_mprotect(
        &mut self,
        env: &mut BareEnv,
        addr: u64,
        len: u64,
        prot: u32,
    ) -> Result<u64, u64> {
        let lo = addr & !0xfff;
        let Some(end) = addr.checked_add(len) else {
            return Err(u64::from(superh::errno::EINVAL));
        };
        let hi = end.div_ceil(4096) * 4096;
        if hi <= lo {
            return Err(u64::from(superh::errno::EINVAL));
        }
        let mut p = 0u8;
        if prot & superh::mman::PROT_READ != 0 {
            p |= Perms::R.0;
        }
        if prot & superh::mman::PROT_WRITE != 0 {
            p |= Perms::W.0;
        }
        if prot & superh::mman::PROT_EXEC != 0 {
            p |= Perms::X.0;
        }
        match env
            .backend
            .mem
            .protect(VirtAddr(lo), (hi - lo) / 4096, Perms(p))
        {
            Ok(()) => Ok(0),
            Err(_) => Err(u64::from(superh::errno::ENOMEM)),
        }
    }

    /// `getrandom`。/dev/urandom を読み、開けなければ固定値で
    /// 埋める（エミュレーション環境の近似）。
    fn sys_getrandom(&mut self, env: &mut BareEnv, buf: u64, len: u64) -> Result<u64, u64> {
        let n = (len as usize).min(1 << 20);
        let mut data = vec![0u8; n];
        match std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut data)) {
            Ok(()) => {}
            Err(_) => {
                // 乱数源が無い環境では xorshift で埋める近似。
                let mut s = 0x2545_f491_4f6c_dd1du64;
                for b in &mut data {
                    s ^= s << 13;
                    s ^= s >> 7;
                    s ^= s << 17;
                    *b = s as u8;
                }
            }
        }
        self.put_bytes(env, buf, &data)?;
        Ok(n as u64)
    }

    /// `uname`（65B×6）。machine は sh4 とする。
    fn sys_uname(&mut self, env: &mut BareEnv, addr: u64) -> Result<u64, u64> {
        let fields = ["Linux", "polyisa", "6.1.0-polyisa", "#1", "sh4", "(none)"];
        for (i, f) in fields.iter().enumerate() {
            let mut b = [0u8; 65];
            b[..f.len()].copy_from_slice(f.as_bytes());
            self.put_bytes(env, addr + (i * 65) as u64, &b)?;
        }
        Ok(0)
    }

    /// `sysinfo`（32 ビット形式・64B）。値は合成（GAP-0060）。
    fn sys_sysinfo(&mut self, env: &mut BareEnv, addr: u64) -> Result<u64, u64> {
        let secs = self.mono_start.map(|s| s.elapsed().as_secs()).unwrap_or(0) as u32;
        let total = 512 * 1024 * 1024u32;
        self.put32(env, addr, secs)?; // uptime
        self.put32(env, addr + 4, 0)?; // loads[3]
        self.put32(env, addr + 8, 0)?;
        self.put32(env, addr + 12, 0)?;
        self.put32(env, addr + 16, total)?; // totalram
        self.put32(env, addr + 20, total)?; // freeram
        self.put32(env, addr + 24, 0)?; // sharedram
        self.put32(env, addr + 28, 0)?; // bufferram
        self.put32(env, addr + 32, 0)?; // totalswap
        self.put32(env, addr + 36, 0)?; // freeswap
        self.put16(env, addr + 40, 1)?; // procs
        self.put16(env, addr + 42, 0)?; // pad
        self.put32(env, addr + 44, 0)?; // totalhigh
        self.put32(env, addr + 48, 0)?; // freehigh
        self.put32(env, addr + 52, 1)?; // mem_unit
        Ok(0)
    }

    /// `statfs64`（88B）と `statfs`（64B）の共通部。値は合成（GAP-0060）。
    fn sys_statfs(&mut self, env: &mut BareEnv, addr: u64, wide: bool) -> Result<u64, u64> {
        if wide {
            self.put32(env, addr, 0xEF53)?;
            self.put32(env, addr + 4, 4096)?;
            self.put64(env, addr + 8, 1 << 22)?;
            self.put64(env, addr + 16, 1 << 21)?;
            self.put64(env, addr + 24, 1 << 21)?;
            self.put64(env, addr + 32, 1 << 20)?;
            self.put64(env, addr + 40, 1 << 20)?;
            self.put64(env, addr + 48, 0)?; // fsid
            self.put32(env, addr + 56, 255)?;
            self.put32(env, addr + 60, 4096)?;
            self.put32(env, addr + 64, 0)?;
        } else {
            let fields = [0xEF53u32, 4096, 1 << 22, 1 << 21, 1 << 21, 1 << 20, 1 << 19];
            for (i, v) in fields.iter().enumerate() {
                self.put32(env, addr + (i * 4) as u64, *v)?;
            }
            self.put64(env, addr + 28, 0)?; // fsid
            self.put32(env, addr + 36, 255)?;
        }
        Ok(0)
    }

    /// `gettimeofday`/`clock_gettime`/`time`/`times` の単調時計。
    fn mono_us(&mut self) -> u64 {
        self.mono_start
            .get_or_insert_with(std::time::Instant::now)
            .elapsed()
            .as_micros() as u64
    }

    /// `timespec`（32 ビット。u32×2）を書く。
    fn put_timespec(&self, env: &mut BareEnv, addr: u64, sec: u64, nsec: u64) -> Result<(), u64> {
        self.put32(env, addr, sec as u32)?;
        self.put32(env, addr + 4, nsec as u32)
    }

    /// `access`/`faccessat`/`faccessat2` の共通部（存在確認だけ。
    /// mode ビットの検査はしない — GAP-0060）。
    fn sys_access(&mut self, env: &mut BareEnv, dirfd: i64, path_addr: u64) -> Result<u64, u64> {
        const AT_FDCWD: i64 = -100;
        let path = self.get_cstr(env, path_addr)?;
        let host = if path.starts_with(b"/") || dirfd == AT_FDCWD {
            self.host_path(&path)
        } else if let Some(dir) = self.fds.path_of(dirfd as u32) {
            format!(
                "{}/{}",
                dir.trim_end_matches('/'),
                String::from_utf8_lossy(&path)
            )
        } else {
            return Err(u64::from(superh::errno::EBADF));
        };
        match polyisa_host::stat(&host) {
            Ok(_) => Ok(0),
            Err(e) => Err(host_errno(e.raw_os_error())),
        }
    }

    /// 番号で振り分ける。`Err(e)` は errno（正の値）で返す。
    #[allow(clippy::too_many_lines)]
    fn syscall(&mut self, env: &mut BareEnv, nr: u64, a: &[u64; 6]) -> Result<u64, u64> {
        use superh::errno as E;
        use superh::nr as N;
        let e = |x: u32| u64::from(x);
        match nr {
            // ---- プロセス ----
            N::FORK | N::VFORK | N::CLONE | N::EXECVE | N::EXECVEAT => Err(e(E::ENOSYS)),
            // 子を作れないので wait 系は常に ECHILD。
            N::WAITPID | N::WAIT4 | N::WAITID => Err(e(E::ECHILD)),
            N::GETPID | N::GETTID => Ok(self.pid),
            N::GETPPID => Ok(1),
            N::GETPGRP | N::GETPGID | N::GETSID => Ok(self.pid),
            N::SETPGID | N::SETSID => Ok(self.pid),
            N::GETUID
            | N::GETEUID
            | N::GETGID
            | N::GETEGID
            | N::GETUID32
            | N::GETEUID32
            | N::GETGID32
            | N::GETEGID32 => Ok(0),
            N::GETGROUPS | N::GETGROUPS32 => Ok(0),
            N::SETGROUPS | N::SETGROUPS32 => Ok(0),
            N::GETRESUID | N::GETRESGID | N::GETRESUID32 | N::GETRESGID32 => {
                // (ruid, euid, suid) を三語書く。
                for p in a.iter().take(3) {
                    self.put32(env, *p, 0)?;
                }
                Ok(0)
            }
            N::SETUID
            | N::SETGID
            | N::SETREUID
            | N::SETREGID
            | N::SETRESUID
            | N::SETRESGID
            | N::SETFSUID
            | N::SETFSGID
            | N::SETUID32
            | N::SETGID32
            | N::SETREUID32
            | N::SETREGID32
            | N::SETRESUID32
            | N::SETRESGID32
            | N::SETFSUID32
            | N::SETFSGID32 => Ok(0),
            // ---- ファイル I/O ----
            N::READ => self.sys_read(env, a[0] as u32, a[1], a[2]),
            N::PREAD64 => {
                // pread64(fd, buf, len, pos) — pos は r7:r0 の対
                // （entry-common.S の引数対応で 4・5 番目のスロットが
                // 下位・上位語）。
                let off = (a[3] & 0xffff_ffff) | ((a[4] & 0xffff_ffff) << 32);
                self.sys_pread(env, a[0] as u32, a[1], a[2], off)
            }
            N::PWRITE64 => {
                let off = (a[3] & 0xffff_ffff) | ((a[4] & 0xffff_ffff) << 32);
                self.sys_pwrite(env, a[0] as u32, a[1], a[2], off)
            }
            N::WRITE => self.sys_write(env, a[0] as u32, a[1], a[2]),
            N::READV | N::PREADV => self.sys_readv(env, a[0] as u32, a[1], a[2]),
            N::WRITEV | N::PWRITEV => self.sys_writev(env, a[0] as u32, a[1], a[2]),
            N::OPEN => self.sys_open(env, -100, a[0], a[1] as u32, a[2] as u32),
            N::OPENAT => self.sys_open(env, a[0] as i32 as i64, a[1], a[2] as u32, a[3] as u32),
            N::OPENAT2 => {
                // openat2(dirfd, path, how*, usize) — how の先頭語が
                // flags。近似的に openat と同じ扱い（resolve フラグの
                // 検査はしない — GAP-0060）。
                let flags = self.mem_u(env, a[2]) as u32;
                self.sys_open(env, a[0] as i32 as i64, a[1], flags, 0)
            }
            N::CREAT => {
                let flags = superh::oflag::CREAT | superh::oflag::TRUNC | 1;
                self.sys_open(env, -100, a[0], flags, a[1] as u32)
            }
            N::CLOSE => self.sys_close(a[0] as u32),
            N::LSEEK => self.sys_lseek(a[0] as u32, i64::from(a[1] as u32 as i32), a[2] as u32),
            N::_LLSEEK => {
                // _llseek(fd, hi, lo, result_ptr, whence)
                let fd = a[0] as u32;
                let off = ((a[1] & 0xffff_ffff) << 32) | (a[2] & 0xffff_ffff);
                let ptr = a[3];
                let wh = a[4] as u32;
                let f = self.file_of(fd)?;
                let w = match wh {
                    0 => SeekFrom::Start(off),
                    1 => SeekFrom::Current(off as i64),
                    2 => SeekFrom::End(off as i64),
                    _ => return Err(e(E::EINVAL)),
                };
                match f.seek(w) {
                    Ok(p) => {
                        self.put64(env, ptr, p)?;
                        Ok(0)
                    }
                    Err(err) => Err(host_errno(err.raw_os_error())),
                }
            }
            // ---- stat 系 ----
            N::STAT => {
                let t = self.stat_target(env, -100, a[0], 0)?;
                self.sys_stat(env, t, a[1], false, StatKind::Stat)
            }
            N::LSTAT => {
                let t = self.stat_target(env, -100, a[0], 0)?;
                self.sys_stat(env, t, a[1], true, StatKind::Stat)
            }
            N::FSTAT => self.sys_stat(
                env,
                StatTarget::Fd(a[0] as u32),
                a[1],
                false,
                StatKind::Stat,
            ),
            N::STAT64 => {
                let t = self.stat_target(env, -100, a[0], 0)?;
                self.sys_stat(env, t, a[1], false, StatKind::Stat64)
            }
            N::LSTAT64 => {
                let t = self.stat_target(env, -100, a[0], 0)?;
                self.sys_stat(env, t, a[1], true, StatKind::Stat64)
            }
            N::FSTAT64 => self.sys_stat(
                env,
                StatTarget::Fd(a[0] as u32),
                a[1],
                false,
                StatKind::Stat64,
            ),
            N::FSTATAT64 => {
                // fstatat64(dirfd, path, buf, flags)
                let lstat = a[3] & 0x100 != 0; // AT_SYMLINK_NOFOLLOW
                let t = self.stat_target(env, a[0] as i32 as i64, a[1], a[3] as u32)?;
                self.sys_stat(env, t, a[2], lstat, StatKind::Stat64)
            }
            N::STATX => {
                // statx(dirfd, path, flags, mask, buf)
                let lstat = a[2] & 0x100 != 0;
                let t = self.stat_target(env, a[0] as i32 as i64, a[1], a[2] as u32)?;
                self.sys_stat(env, t, a[4], lstat, StatKind::Statx)
            }
            // ---- アクセス・属性 ----
            N::ACCESS => self.sys_access(env, -100, a[0]),
            N::FACCESSAT => self.sys_access(env, a[0] as i32 as i64, a[1]),
            N::FACCESSAT2 => {
                // faccessat2(dirfd, path, mode, flags)。flags は
                // AT_EACCESS/AT_SYMLINK_NOFOLLOW/AT_EMPTY_PATH を
                // 取る。単一ユーザ・単一プロセス近似では効かせられ
                // ないので、flags=0 のみ faccessat と同じ扱いにし、
                // 非 0 は ENOSYS とする。
                // Ref: SRC-LINUX — fs/open.c（do_faccessat）.
                if a[3] != 0 {
                    Err(e(E::ENOSYS))
                } else {
                    self.sys_access(env, a[0] as i32 as i64, a[1])
                }
            }
            N::CHMOD | N::FCHMOD | N::FCHMODAT => Ok(0),
            N::CHOWN
            | N::FCHOWN
            | N::LCHOWN
            | N::FCHOWNAT
            | N::LCHOWN32
            | N::FCHOWN32
            | N::CHOWN32 => Ok(0),
            // ---- ディレクトリと名前 ----
            N::GETDENTS64 => self.sys_getdents64(env, a[0] as u32, a[1], a[2]),
            N::GETDENTS => Err(e(E::ENOSYS)),
            N::GETCWD => {
                let cwd = if self.cwd.is_empty() {
                    std::env::current_dir()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_else(|_| "/".to_string())
                } else {
                    self.cwd.clone()
                };
                let b = cwd.as_bytes();
                let n = (b.len() + 1).min(a[1] as usize);
                self.put_bytes(env, a[0], &b[..n.min(b.len())])?;
                if n > 0 {
                    self.put_bytes(env, a[0].wrapping_add((n - 1) as u64), &[0])?;
                }
                Ok(n as u64)
            }
            N::CHDIR => {
                let path = self.get_cstr(env, a[0])?;
                let host = self.host_path(&path);
                if polyisa_host::stat(&host)
                    .map(|m| m.mode & 0o170000 == 0o040000)
                    .unwrap_or(false)
                {
                    self.cwd = host;
                    Ok(0)
                } else {
                    Err(e(E::ENOENT))
                }
            }
            N::FCHDIR => Ok(0),
            N::MKDIR | N::MKDIRAT => {
                let idx = if nr == N::MKDIR { 0 } else { 1 };
                if nr == N::MKDIRAT && a[0] as i32 != -100 {
                    return Err(e(E::EBADF));
                }
                let path = self.get_cstr(env, a[idx])?;
                match std::fs::create_dir(self.host_path(&path)) {
                    Ok(()) => Ok(0),
                    Err(err) => Err(host_errno(err.raw_os_error())),
                }
            }
            N::RMDIR => {
                let path = self.get_cstr(env, a[0])?;
                match std::fs::remove_dir(self.host_path(&path)) {
                    Ok(()) => Ok(0),
                    Err(err) => Err(host_errno(err.raw_os_error())),
                }
            }
            N::UNLINK | N::UNLINKAT => {
                let idx = if nr == N::UNLINK { 0 } else { 1 };
                if nr == N::UNLINKAT && a[0] as i32 != -100 {
                    return Err(e(E::EBADF));
                }
                let path = self.get_cstr(env, a[idx])?;
                match std::fs::remove_file(self.host_path(&path)) {
                    Ok(()) => Ok(0),
                    Err(err) => Err(host_errno(err.raw_os_error())),
                }
            }
            N::RENAME | N::RENAMEAT => {
                let (x, y) = if nr == N::RENAME {
                    (a[0], a[1])
                } else {
                    if a[0] as i32 != -100 || a[2] as i32 != -100 {
                        return Err(e(E::EBADF));
                    }
                    (a[1], a[3])
                };
                let from = self.get_cstr(env, x)?;
                let to = self.get_cstr(env, y)?;
                match std::fs::rename(self.host_path(&from), self.host_path(&to)) {
                    Ok(()) => Ok(0),
                    Err(err) => Err(host_errno(err.raw_os_error())),
                }
            }
            N::LINK | N::LINKAT => {
                let (x, y) = if nr == N::LINK {
                    (a[0], a[1])
                } else {
                    if a[0] as i32 != -100 || a[2] as i32 != -100 {
                        return Err(e(E::EBADF));
                    }
                    (a[1], a[3])
                };
                let from = self.get_cstr(env, x)?;
                let to = self.get_cstr(env, y)?;
                match std::fs::hard_link(self.host_path(&from), self.host_path(&to)) {
                    Ok(()) => Ok(0),
                    Err(err) => Err(host_errno(err.raw_os_error())),
                }
            }
            N::SYMLINK | N::SYMLINKAT => {
                let (x, y) = if nr == N::SYMLINK {
                    (a[0], a[1])
                } else {
                    if a[1] as i32 != -100 {
                        return Err(e(E::EBADF));
                    }
                    (a[0], a[2])
                };
                let from = self.get_cstr(env, x)?;
                let to = self.get_cstr(env, y)?;
                match polyisa_host::symlink(&String::from_utf8_lossy(&from), &self.host_path(&to)) {
                    Ok(()) => Ok(0),
                    Err(err) => Err(host_errno(err.raw_os_error())),
                }
            }
            N::READLINK => self.sys_readlink(env, a[0], a[1], a[2]),
            N::READLINKAT => {
                if a[0] as i32 != -100 {
                    return Err(e(E::EBADF));
                }
                self.sys_readlink(env, a[1], a[2], a[3])
            }
            N::TRUNCATE | N::TRUNCATE64 => {
                let path = self.get_cstr(env, a[0])?;
                // truncate64 は len が 64 ビットで a[1]:a[2]。
                let len = if nr == N::TRUNCATE {
                    a[1]
                } else {
                    (a[1] & 0xffff_ffff) | ((a[2] & 0xffff_ffff) << 32)
                };
                match std::fs::OpenOptions::new()
                    .write(true)
                    .open(self.host_path(&path))
                    .and_then(|f| f.set_len(len))
                {
                    Ok(()) => Ok(0),
                    Err(err) => Err(host_errno(err.raw_os_error())),
                }
            }
            N::FTRUNCATE | N::FTRUNCATE64 => {
                let fd = a[0] as u32;
                let len = if nr == N::FTRUNCATE {
                    a[1]
                } else {
                    (a[1] & 0xffff_ffff) | ((a[2] & 0xffff_ffff) << 32)
                };
                match self.file_of(fd).and_then(|f| {
                    f.set_len(len).map_err(|_| e(E::EIO))?;
                    Ok(())
                }) {
                    Ok(()) => Ok(0),
                    Err(err) => Err(err),
                }
            }
            // ---- モード・マウント等（EPERM）----
            N::MKNOD
            | N::MKNODAT
            | N::MOUNT
            | N::UMOUNT
            | N::UMOUNT2
            | N::PIVOT_ROOT
            | N::CHROOT
            | N::REBOOT
            | N::ACCT
            | N::INIT_MODULE
            | N::DELETE_MODULE
            | N::FINIT_MODULE
            | N::SWAPON
            | N::SWAPOFF
            | N::SETDOMAINNAME
            | N::SETHOSTNAME => Err(e(E::EPERM)),
            N::UMASK => {
                let old = self.umask;
                self.umask = a[0] as u32 & 0o777;
                Ok(u64::from(old))
            }
            // ---- ディスクリプタ操作 ----
            N::DUP => match self.fds.file(a[0] as u32) {
                Some(f) => match f.try_clone() {
                    Ok(g) => {
                        let nfd = self.fds.alloc(polyisa_kernel::FdTarget::File(g));
                        let p = self.fds.path_of(a[0] as u32).map(str::to_string);
                        if let Some(p) = p {
                            self.fds.remember_path(nfd, p);
                        }
                        Ok(u64::from(nfd))
                    }
                    Err(err) => Err(host_errno(err.raw_os_error())),
                },
                None => Err(e(E::EBADF)),
            },
            N::DUP2 | N::DUP3 => {
                let (old, new) = (a[0] as u32, a[1] as u32);
                if old == new {
                    return Ok(u64::from(new));
                }
                let p = self.fds.path_of(old).map(str::to_string);
                let g = match self.fds.file(old).and_then(|f| f.try_clone().ok()) {
                    Some(g) => g,
                    None => return Err(e(E::EBADF)),
                };
                self.fds.place_close(new, polyisa_kernel::FdTarget::File(g));
                if let Some(p) = p {
                    self.fds.remember_path(new, p);
                }
                Ok(u64::from(new))
            }
            N::FCNTL | N::FCNTL64 => self.sys_fcntl(a[0] as u32, a[1] as u32, a[2]),
            N::IOCTL => self.sys_ioctl(env, a[0] as u32, a[1], a[2]),
            N::PIPE | N::PIPE2 => Err(e(E::ENOSYS)),
            N::SENDFILE64 => {
                // sendfile64(out, in, off*, count)。off* は 64 ビット。
                // off==NULL なら in のファイル位置を進める（read を使う）。
                let (out_fd, in_fd, offp, count) =
                    (a[0] as u32, a[1] as u32, a[2], a[3].min(1 << 24));
                let mut pos = if offp != 0 {
                    let b = self.get_bytes(env, offp, 8)?;
                    match self.endian {
                        Endian::Le => u64::from_le_bytes(b.try_into().unwrap_or([0; 8])),
                        Endian::Be => u64::from_be_bytes(b.try_into().unwrap_or([0; 8])),
                    }
                } else {
                    0
                };
                let mut sent = 0u64;
                while sent < count {
                    let n = (count - sent).min(64 * 1024) as usize;
                    let mut buf = vec![0u8; n];
                    let got = match self.fds.file_mut(in_fd) {
                        Some(f) => {
                            let r = if offp != 0 {
                                polyisa_host::pread(f, &mut buf, pos)
                            } else {
                                f.read(&mut buf)
                            };
                            match r {
                                Ok(g) => g,
                                Err(err) => {
                                    return if sent > 0 {
                                        Ok(sent)
                                    } else {
                                        Err(host_errno(err.raw_os_error()))
                                    };
                                }
                            }
                        }
                        None => return Err(e(E::EBADF)),
                    };
                    if got == 0 {
                        break;
                    }
                    // バッファ経由で writer に直接書く。
                    let w = match self.writer(out_fd) {
                        Ok(w) => w,
                        Err(err) => {
                            return if sent > 0 { Ok(sent) } else { Err(err) };
                        }
                    };
                    let wn = match w {
                        WriteFd::Stdout => {
                            self.io.stdout.extend_from_slice(&buf[..got]);
                            let _ = std::io::stdout().write_all(&buf[..got]);
                            got
                        }
                        WriteFd::Stderr => {
                            self.io.stderr.extend_from_slice(&buf[..got]);
                            let _ = std::io::stderr().write_all(&buf[..got]);
                            got
                        }
                        WriteFd::File(f) => match f.write(&buf[..got]) {
                            Ok(n) => n,
                            Err(err) => {
                                return if sent > 0 {
                                    Ok(sent)
                                } else {
                                    Err(host_errno(err.raw_os_error()))
                                };
                            }
                        },
                    };
                    sent += wn as u64;
                    pos += got as u64;
                    if wn < got {
                        break;
                    }
                }
                if offp != 0 {
                    self.put64(env, offp, pos)?;
                }
                Ok(sent)
            }
            // ---- メモリ ----
            N::BRK => Ok(self.sys_brk(env, a[0])),
            N::MMAP => {
                // sys_mmap(addr,len,prot,flags,fd,off) — off はバイト。
                let pgoff = a[5] / 4096;
                self.sys_mmap(
                    env,
                    a[0],
                    a[1],
                    a[2] as u32,
                    a[3] as u32,
                    a[4] as i32 as i64,
                    pgoff,
                )
            }
            N::MMAP2 => {
                // mmap2 の offset はページ単位。
                self.sys_mmap(
                    env,
                    a[0],
                    a[1],
                    a[2] as u32,
                    a[3] as u32,
                    a[4] as i32 as i64,
                    a[5],
                )
            }
            N::MUNMAP => Ok(self.sys_munmap(env, a[0], a[1])),
            N::MPROTECT => self.sys_mprotect(env, a[0], a[1], a[2] as u32),
            N::MREMAP => Err(e(E::ENOMEM)),
            N::MADVISE
            | N::MINCORE
            | N::MSYNC
            | N::MLOCK
            | N::MUNLOCK
            | N::MLOCKALL
            | N::MUNLOCKALL
            | N::MLOCK2
            | N::FADVISE64
            | N::FADVISE64_64
            | N::READAHEAD
            | N::FALLOCATE => Ok(0),
            N::UNAME => self.sys_uname(env, a[0]),
            N::SYSINFO => self.sys_sysinfo(env, a[0]),
            N::CACHEFLUSH => Ok(0), // フラットメモリモデルでは nop
            // ---- 時間 ----
            N::TIME => {
                let secs = now_secs();
                let tp = a[0];
                if tp != 0 {
                    self.put32(env, tp, secs as u32)?;
                }
                Ok(secs)
            }
            N::GETTIMEOFDAY => {
                let (sec, usec) = now_us();
                self.put32(env, a[0], sec as u32)?;
                self.put32(env, a[0] + 4, usec as u32)?;
                Ok(0)
            }
            N::STIME | N::SETTIMEOFDAY => Ok(0),
            N::CLOCK_GETTIME | N::CLOCK_GETTIME64 => {
                let mono = a[0] == 1; // CLOCK_MONOTONIC
                let (sec, nsec) = if mono {
                    let us = self.mono_us();
                    (us / 1_000_000, (us % 1_000_000) * 1000)
                } else {
                    now_ns()
                };
                if nr == N::CLOCK_GETTIME {
                    self.put_timespec(env, a[1], sec, nsec)?;
                } else {
                    // __kernel_timespec { i64 sec, i64 nsec }。
                    self.put64(env, a[1], sec)?;
                    self.put64(env, a[1] + 8, nsec)?;
                }
                Ok(0)
            }
            N::CLOCK_GETRES | N::CLOCK_GETRES_TIME64 => {
                if nr == N::CLOCK_GETRES {
                    self.put_timespec(env, a[1], 0, 1)?;
                } else {
                    self.put64(env, a[1], 0)?;
                    self.put64(env, a[1] + 8, 1)?;
                }
                Ok(0)
            }
            N::CLOCK_SETTIME | N::CLOCK_SETTIME64 | N::CLOCK_ADJTIME | N::ADJTIMEX => Ok(0),
            N::NANOSLEEP | N::CLOCK_NANOSLEEP | N::CLOCK_NANOSLEEP_TIME64 => Ok(0),
            N::TIMES => {
                // tms { utime, stime, cutime, cstime } u32×4。
                for i in 0..4 {
                    self.put32(env, a[0] + i * 4, 0)?;
                }
                Ok(self.mono_us() / 10_000)
            }
            N::UTIME | N::UTIMES | N::UTIMENSAT | N::UTIMENSAT_TIME64 | N::FUTIMESAT => Ok(0),
            // ---- 資源 ----
            N::GETRLIMIT | N::UGETRLIMIT => {
                // rlimit { u32 cur, u32 max }。RLIMIT_INFINITY 相当。
                self.put32(env, a[1], 0xffff_ffff)?;
                self.put32(env, a[1] + 4, 0xffff_ffff)?;
                Ok(0)
            }
            N::PRLIMIT64 => {
                // rlimit64 { u64 cur, u64 max }。
                if a[3] != 0 {
                    self.put64(env, a[3], 0xffff_ffff_ffff_ffff)?;
                    self.put64(env, a[3] + 8, 0xffff_ffff_ffff_ffff)?;
                }
                Ok(0)
            }
            N::SETRLIMIT => Ok(0),
            N::GETRUSAGE => {
                if a[1] != 0 {
                    let _ = self.put32(env, a[1], 0);
                }
                Ok(0)
            }
            // getpriority(which, who) は nice 値を返す。最小権限の 20 を返す。
            N::GETPRIORITY => Ok(20),
            N::SETPRIORITY | N::NICE => Ok(0),
            N::SCHED_SETPARAM | N::SCHED_SETSCHEDULER | N::SCHED_YIELD => Ok(0),
            N::SCHED_GETPARAM | N::SCHED_GETSCHEDULER => {
                if a[1] != 0 {
                    let _ = self.put32(env, a[1], 0);
                }
                Ok(0)
            }
            N::SCHED_GET_PRIORITY_MAX => Ok(99),
            N::SCHED_GET_PRIORITY_MIN => Ok(1),
            N::SCHED_RR_GET_INTERVAL | N::SCHED_RR_GET_INTERVAL_TIME64 => {
                let _ = self.put_timespec(env, a[1], 0, 1_000_000);
                Ok(0)
            }
            N::SCHED_SETAFFINITY => Ok(0),
            N::SCHED_GETAFFINITY => {
                // cpu0 だけのマスク。
                let mut b = vec![0u8; a[1].min(128) as usize];
                if !b.is_empty() {
                    b[0] = 1;
                }
                self.put_bytes(env, a[2], &b)?;
                Ok(0)
            }
            N::GETCPU => {
                if a[0] != 0 {
                    let _ = self.put32(env, a[0], 0);
                }
                if a[1] != 0 {
                    let _ = self.put32(env, a[1], 0);
                }
                Ok(0)
            }
            N::IOPRIO_SET => Ok(0),
            N::IOPRIO_GET => Ok(0),
            N::GETITIMER | N::SETITIMER | N::ALARM => Ok(0),
            // ---- シグナル（受理するだけ。配送経路はない — GAP-0060）----
            N::SIGACTION
            | N::RT_SIGACTION
            | N::SIGPROCMASK
            | N::RT_SIGPROCMASK
            | N::SIGPENDING
            | N::RT_SIGPENDING
            | N::SIGSUSPEND
            | N::RT_SIGSUSPEND
            | N::RT_SIGTIMEDWAIT
            | N::RT_SIGTIMEDWAIT_TIME64
            | N::RT_SIGQUEUEINFO
            | N::SIGALTSTACK
            | N::RT_TGSIGQUEUEINFO
            | N::SIGNALFD
            | N::SIGNALFD4 => Ok(0),
            N::SIGRETURN | N::RT_SIGRETURN => Ok(0),
            N::KILL | N::TKILL | N::TGKILL => {
                if a[0] == 0 || a[0] == self.pid {
                    Ok(0)
                } else {
                    Err(e(E::ESRCH))
                }
            }
            // ---- スレッド・同期 ----
            N::FUTEX | N::FUTEX_TIME64 => {
                // 単一スレッド。WAKE は 0、WAIT は EAGAIN と同義で即抜け。
                Ok(0)
            }
            N::SET_TID_ADDRESS => {
                let pid = self.pid as u32;
                if a[0] != 0 {
                    let _ = self.put32(env, a[0], pid);
                }
                Ok(u64::from(pid))
            }
            N::SET_ROBUST_LIST => Ok(0),
            N::GET_ROBUST_LIST => Err(e(E::ENOSYS)),
            // ---- 選択・poll（即時「準備なし」。revents 群は 0 クリア）----
            N::_NEWSELECT
            | N::POLL
            | N::PSELECT6
            | N::PSELECT6_TIME64
            | N::PPOLL
            | N::PPOLL_TIME64 => Ok(0),
            N::PAUSE => Ok(0),
            // ---- ファイルシステム情報 ----
            N::STATFS | N::FSTATFS => self.sys_statfs(env, a[1], false),
            N::STATFS64 | N::FSTATFS64 => self.sys_statfs(env, a[2], true),
            N::USTAT => Ok(0),
            // ---- 属性拡張 ----
            N::SETXATTR | N::LSETXATTR | N::FSETXATTR => Ok(0),
            N::GETXATTR
            | N::LGETXATTR
            | N::FGETXATTR
            | N::LISTXATTR
            | N::LLISTXATTR
            | N::FLISTXATTR => Err(e(E::ENOTSUP)),
            N::REMOVEXATTR | N::LREMOVEXATTR | N::FREMOVEXATTR => Ok(0),
            // ---- 認証・機能 ----
            N::CAPGET | N::CAPSET => Ok(0),
            N::PERSONALITY => Ok(0),
            N::PRCTL | N::SECCOMP => Ok(0),
            N::SYNC | N::FSYNC | N::FDATASYNC | N::SYNCFS | N::FLOCK => Ok(0),
            N::GETRANDOM => self.sys_getrandom(env, a[0], a[1]),
            // ---- 未対応群（ENOSYS）----
            N::SOCKETCALL | N::IPC => Err(e(E::ENOSYS)),
            N::SYSLOG
            | N::QUOTACTL
            | N::QUOTACTL_FD
            | N::PTRACE
            | N::USELIB
            | N::VHANGUP
            | N::SYSFS
            | N::BDFLUSH
            | N::NFSSERVCTL
            | N::_SYSCTL
            | N::ADD_KEY
            | N::REQUEST_KEY
            | N::KEYCTL
            | N::KEXEC_LOAD
            | N::LOOKUP_DCOOKIE
            | N::REMAP_FILE_PAGES
            | N::MBIND
            | N::GET_MEMPOLICY
            | N::SET_MEMPOLICY
            | N::MIGRATE_PAGES
            | N::MOVE_PAGES
            | N::UNSHARE
            | N::MOUNT_SETATTR
            | N::OPEN_TREE
            | N::MOVE_MOUNT
            | N::FSOPEN
            | N::FSCONFIG
            | N::FSMOUNT
            | N::FSPICK
            | N::PIDFD_OPEN
            | N::PIDFD_SEND_SIGNAL
            | N::PIDFD_GETFD
            | N::CLOSE_RANGE
            | N::PROCESS_MADVISE
            | N::EPOLL_PWAIT2
            | N::KCMP
            | N::PROCESS_VM_READV
            | N::PROCESS_VM_WRITEV
            | N::SETNS
            | N::FANOTIFY_INIT
            | N::FANOTIFY_MARK
            | N::BPF
            | N::USERFAULTFD
            | N::PERF_EVENT_OPEN
            | N::IO_SETUP
            | N::IO_DESTROY
            | N::IO_GETEVENTS
            | N::IO_SUBMIT
            | N::IO_CANCEL
            | N::IO_URING_SETUP
            | N::IO_URING_ENTER
            | N::IO_URING_REGISTER
            | N::MEMBARRIER
            | N::RSEQ
            | N::COPY_FILE_RANGE
            | N::SPLICE
            | N::TEE
            | N::VMSPLICE
            | N::MEMFD_CREATE => Err(e(E::ENOSYS)),
            N::INOTIFY_INIT
            | N::INOTIFY_ADD_WATCH
            | N::INOTIFY_RM_WATCH
            | N::INOTIFY_INIT1
            | N::EPOLL_CREATE
            | N::EPOLL_CTL
            | N::EPOLL_WAIT
            | N::EPOLL_CREATE1
            | N::EPOLL_PWAIT
            | N::TIMERFD_CREATE
            | N::TIMERFD_SETTIME
            | N::TIMERFD_GETTIME
            | N::TIMERFD_SETTIME64
            | N::TIMERFD_GETTIME64
            | N::EVENTFD
            | N::EVENTFD2
            | N::TIMER_CREATE
            | N::TIMER_SETTIME
            | N::TIMER_GETTIME
            | N::TIMER_GETOVERRUN
            | N::TIMER_DELETE
            | N::TIMER_SETTIME64
            | N::TIMER_GETTIME64
            | N::MQ_OPEN
            | N::MQ_UNLINK
            | N::MQ_TIMEDSEND
            | N::MQ_TIMEDRECEIVE
            | N::MQ_NOTIFY
            | N::MQ_GETSETATTR
            | N::MQ_TIMEDSEND_TIME64
            | N::MQ_TIMEDRECEIVE_TIME64
            | N::RESTART_SYSCALL => Err(e(E::ENOSYS)),
            _ => {
                if !self.reported.contains(&nr) {
                    self.reported.push(nr);
                    let name = superh::name(nr).unwrap_or("?");
                    eprintln!("superh: 未実装の syscall {nr} ({name}) — ENOSYS");
                }
                Err(e(E::ENOSYS))
            }
        }
    }
}

/// stat 対象。fd か、解決済みのホストパス。
enum StatTarget {
    /// ゲスト fd（0..=2 は /dev/null に寄せる）。
    Fd(u32),
    /// 解決済みのホストパス。
    Path(String),
}

/// stat 直列化の種別。
enum StatKind {
    /// 旧 `struct stat`（60B+pad）。
    Stat,
    /// `stat64`（104B）。
    Stat64,
    /// `statx`（256B）。
    Statx,
}

/// `read` 系で返す実体。
enum ReadFd<'a> {
    Stdin,
    File(&'a mut std::fs::File),
}

/// `write` 系で返す実体。
enum WriteFd<'a> {
    Stdout,
    Stderr,
    File(&'a mut std::fs::File),
}

impl TrapHandler for Linux {
    fn handle_trap(&mut self, env: &mut BareEnv, code: u32) -> TrapOutcome {
        // `trapa #0x10`-`#0x1f` が syscall 発行点。
        if !(superh::TRAPA_SYS_BASE..=superh::TRAPA_SYS_TOP).contains(&code) {
            return TrapOutcome::Unimplemented;
        }
        let r = |env: &mut BareEnv, i: u8| env.backend.get(sem::R(i).state());
        let nr = u64::from(r(env, 3));
        let a = [
            u64::from(r(env, 4)),
            u64::from(r(env, 5)),
            u64::from(r(env, 6)),
            u64::from(r(env, 7)),
            u64::from(r(env, 0)),
            u64::from(r(env, 1)),
        ];
        if trace() {
            let name = superh::name(nr).unwrap_or("?");
            eprintln!(
                "sys {nr} {name} pc={:#x} a0={:#x} a1={:#x} a2={:#x} a3={:#x} a4={:#x} a5={:#x}",
                env.pc, a[0], a[1], a[2], a[3], a[4], a[5]
            );
        }
        match nr {
            superh::nr::EXIT | superh::nr::EXIT_GROUP => TrapOutcome::Exit(a[0] as u32),
            _ => {
                let ret = match self.syscall(env, nr, &a) {
                    Ok(v) => v & 0xffff_ffff,
                    Err(err) => (0u64).wrapping_sub(err),
                };
                env.backend.set(sem::R(0).state(), ret as u32);
                TrapOutcome::Handled
            }
        }
    }

    fn init_brk(&mut self, image_end: u64) {
        let e = image_end.div_ceil(4096) * 4096;
        self.brk_start = e;
        self.heap_end = e;
        self.mmap_next = e + 0x800_0000;
    }
}

/// syscall トレースのスイッチ。
fn trace() -> bool {
    std::env::var_os("POLYISA_SUPERH_SYSCALLS").is_some()
}

/// エポックからの秒。
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// エポックからの（秒、マイクロ秒）。
fn now_us() -> (u64, u64) {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    (d.as_secs(), u64::from(d.subsec_micros()))
}

/// エポックからの（秒、ナノ秒）。
fn now_ns() -> (u64, u64) {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    (d.as_secs(), u64::from(d.subsec_nanos()))
}

/// ホストの errno をゲスト errno に写す。SH の errno は
/// asm-generic でホスト Linux と同じ番号なので恒等写しでよい
/// （未知は EIO に畳む）。
fn host_errno(e: Option<i32>) -> u64 {
    let e = e.unwrap_or(superh::errno::EIO as i32);
    if e <= 0 || e > 133 {
        u64::from(superh::errno::EIO)
    } else {
        u64::from(e as u32)
    }
}
