// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! MIPS Linux の syscall 処理。o32・n32・n64 を一つの実装で扱う。
//!
//! o32 は引数を a0–a3 とスタック（sp+16 以降）から取り、n32/n64 は
//! a0–a5 から取る。o32 の 64 ビット引数は偶数位置の語対で渡り、奇数位置に
//! 来るものはパッド語を一つ挟む。n32/n64 では 64 ビット引数は一本の
//! レジスタで渡る。エラーは a3=1 と v0=errno で返す。
//! errno は `mips::host_to_mips_errno` で MIPS の値に直す。
//!
//! 試作の合意事項：仮想カーネル・VFS・ゲストルートの適用は後の段階である。
//! ここではホストのファイルに直接触る。信頼できないゲストバイナリには
//! 使わないこと。fork/clone/execve/パイプは未対応（ENOSYS）。
// Ref: SRC-LINUX (7.3).

use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

use polyisa_engine::bare::BareEnv;
use polyisa_guest_mips::sem::{self, Gpr};
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};
use polyisa_sem::Backend as _;

use crate::{TrapHandler, TrapOutcome, mips, mips_n32, mips_n64, mips_o32};

/// ゲスト ABI。番号表・引数の取り出し・ポインタ幅が変わる。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Abi {
    O32,
    N32,
    N64,
}

impl Abi {
    /// ポインタと `long` の幅。
    fn ptr_bits(self) -> u32 {
        match self {
            Abi::O32 | Abi::N32 => 32,
            Abi::N64 => 64,
        }
    }

    /// 番号から名前を引く（番号表は ABI ごと）。
    fn name(self, nr: u64) -> Option<&'static str> {
        match self {
            Abi::O32 => mips_o32::name(nr),
            Abi::N32 => mips_n32::name(nr),
            Abi::N64 => mips_n64::name(nr),
        }
    }

    /// 引数レジスタの数。o32 は 4、n32/n64 は 6。
    fn arg_regs(self) -> usize {
        match self {
            Abi::O32 => 4,
            Abi::N32 | Abi::N64 => 6,
        }
    }
}

/// o32 の write が集めたバイト。標準出力と標準エラーを分ける。
#[derive(Default)]
pub struct MipsIo {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// MIPS Linux の syscall 状態機械。
pub struct Linux {
    abi: Abi,
    endian: Endian,
    /// 標準入出力の capture。テストが読む。
    pub io: MipsIo,
    /// 開いたファイルの表（ゲスト fd 3 以降）。
    fds: polyisa_kernel::FdTable,
    /// プログラムブレーク。0 は未初期化。
    heap_end: u64,
    /// mmap の次に置く場所。末尾から伸ばす。
    mmap_next: u64,
    umask: u32,
    /// ホストから見たプロセス識別子。getpid/gettid が返す。
    pid: u64,
    /// ゲストの作業ディレクトリ。空はホストの作業ディレクトリ。
    cwd: String,
    /// ゲストの実行ファイルのホストパス。/proc/self/exe の readlink 用。
    pub exe_path: String,
    /// 報告済みの未実装番号（一度だけ出す）。
    reported: Vec<u64>,
    /// 標準入力へ供給するバイト。
    pub stdin_buf: Vec<u8>,
    stdin_pos: usize,
    /// MONOTONIC 時計の起点。
    mono_start: Option<std::time::Instant>,
    /// ディレクトリ fd の getdents 位置（エントリの通し番号）。
    dir_pos: std::collections::HashMap<u32, usize>,
}

impl Linux {
    /// o32 ABI の Linux 状態機械を作る。
    #[must_use]
    pub fn o32(endian: Endian) -> Self {
        Self::new(Abi::O32, endian)
    }

    /// n32 ABI。
    #[must_use]
    pub fn n32(endian: Endian) -> Self {
        Self::new(Abi::N32, endian)
    }

    /// n64 ABI。
    #[must_use]
    pub fn n64(endian: Endian) -> Self {
        Self::new(Abi::N64, endian)
    }

    /// ABI とエンディアンを指定して作る。ELF の形式に合わせる。
    #[must_use]
    pub fn new(abi: Abi, endian: Endian) -> Self {
        Self {
            abi,
            endian,
            io: MipsIo::default(),
            fds: polyisa_kernel::FdTable::default(),
            heap_end: 0,
            mmap_next: 0x7000_0000,
            umask: 0o22,
            pid: 0,
            cwd: String::new(),
            exe_path: String::new(),
            reported: Vec::new(),
            stdin_buf: Vec::new(),
            stdin_pos: 0,
            mono_start: None,
            dir_pos: std::collections::HashMap::new(),
        }
    }

    fn pid(&mut self) -> u64 {
        if self.pid == 0 {
            self.pid = 1;
        }
        self.pid
    }

    fn arg_regs(env: &mut BareEnv, i: usize) -> u64 {
        reg(env, (4 + i) as u8)
    }

    /// 引数 `i`（0 起算）を取り出す。o32 の 5 番目以降はスタックにある。
    fn arg(&self, env: &mut BareEnv, i: usize) -> u64 {
        let regs = self.abi.arg_regs();
        if i < regs {
            Self::arg_regs(env, i)
        } else {
            // o32 は sp+16 から 32 ビットずつ。n32/n64 は 7 番目以降が sp にある。
            let sp = reg(env, 29);
            let base = match self.abi {
                Abi::O32 => sp.wrapping_add(16),
                _ => sp,
            };
            let off = base.wrapping_add(((i - regs) * (self.abi.ptr_bits() as usize / 8)) as u64);
            self.mem_u(env, off)
        }
    }

    /// 取り出した引数列から 64 ビット引数を組み立てる。
    /// n32/n64 は一語（レジスタは 64 ビット）、o32 は偶数位置の二語。
    fn a64(&self, args: &[u64; 8], slot: usize) -> u64 {
        match self.abi {
            Abi::N32 | Abi::N64 => args[slot],
            _ => {
                let a = args[slot] & 0xffff_ffff;
                let b = args[slot + 1] & 0xffff_ffff;
                match self.endian {
                    Endian::Be => (a << 32) | b,
                    Endian::Le => (b << 32) | a,
                }
            }
        }
    }

    /// 呼び出し規約どおり結果を書き戻す。`v0` に値、`a3` に 0（成功）。
    fn ok(env: &mut BareEnv, v: u64) -> u64 {
        let _ = v;
        set_reg(env, 7, 0);
        v
    }

    /// エラー。`a3` に 1、`v0` に正の errno（MIPS の値）。
    fn fail(&self, env: &mut BareEnv, errno: u32) -> u64 {
        set_reg(env, 7, 1);
        u64::from(errno)
    }

    /// ホスト errno を MIPS errno に直して失敗を返す。
    fn fail_host(&self, env: &mut BareEnv, e: i32) -> u64 {
        self.fail(env, mips::host_to_mips_errno(e.max(0).unsigned_abs()))
    }

    /// 結果の書き戻し。戻り値 `r` を v0 に、a3 を 0 にする。
    fn ret(env: &mut BareEnv, r: u64) -> u64 {
        set_reg(env, 2, r);
        Self::ok(env, r)
    }

    /// 戻り値がポインタなら ABI 幅で包む。
    fn ret_ptr(&self, env: &mut BareEnv, r: u64) -> u64 {
        let r = match self.abi.ptr_bits() {
            32 => r & 0xffff_ffff,
            _ => r,
        };
        Self::ret(env, r)
    }

    fn acc(&self, kind: AccessKind) -> Access {
        Access {
            endian: self.endian,
            align: Align::Unaligned,
            kind,
        }
    }

    /// ポインタ幅の値をメモリから読む。
    fn mem_u(&self, env: &mut BareEnv, addr: u64) -> u64 {
        match self.abi.ptr_bits() {
            32 => {
                let mut b = [0u8; 4];
                env.backend
                    .mem
                    .read(VirtAddr(addr), &mut b, self.acc(AccessKind::DataRead))
                    .map_or(0, |()| {
                        u64::from(match self.endian {
                            Endian::Be => u32::from_be_bytes(b),
                            Endian::Le => u32::from_le_bytes(b),
                        })
                    })
            }
            _ => {
                let mut b = [0u8; 8];
                env.backend
                    .mem
                    .read(VirtAddr(addr), &mut b, self.acc(AccessKind::DataRead))
                    .map_or(0, |()| match self.endian {
                        Endian::Be => u64::from_be_bytes(b),
                        Endian::Le => u64::from_le_bytes(b),
                    })
            }
        }
    }

    /// ポインタ幅の値をメモリに書く。
    fn put_u(&self, env: &mut BareEnv, addr: u64, v: u64) -> bool {
        let bytes = match (self.abi.ptr_bits(), self.endian) {
            (32, Endian::Be) => (v as u32).to_be_bytes().to_vec(),
            (32, Endian::Le) => (v as u32).to_le_bytes().to_vec(),
            (_, Endian::Be) => v.to_be_bytes().to_vec(),
            (_, Endian::Le) => v.to_le_bytes().to_vec(),
        };
        env.backend.mem.write(VirtAddr(addr), &bytes).is_ok()
    }

    /// 固定サイズの値を書く（エンディアン適用）。
    fn put<N: NumBytes>(&self, env: &mut BareEnv, addr: u64, v: N) -> bool {
        env.backend
            .mem
            .write(VirtAddr(addr), &v.bytes(self.endian))
            .is_ok()
    }

    /// C 文字列を読む。上限 4096。
    fn read_cstr(&self, env: &mut BareEnv, addr: u64) -> Result<Vec<u8>, u32> {
        let mut out = Vec::new();
        let acc = self.acc(AccessKind::DataRead);
        for a in (addr..).take(4096) {
            let mut b = [0u8; 1];
            if env.backend.mem.read(VirtAddr(a), &mut b, acc).is_err() {
                return Err(mips::errno::EFAULT);
            }
            if b[0] == 0 {
                return Ok(out);
            }
            out.push(b[0]);
        }
        Err(mips::errno::ENAMETOOLONG)
    }

    fn read_bytes(&self, env: &mut BareEnv, addr: u64, len: usize) -> Result<Vec<u8>, u32> {
        let mut buf = vec![0u8; len.min(1 << 20)];
        if buf.is_empty() {
            return Ok(buf);
        }
        env.backend
            .mem
            .read(VirtAddr(addr), &mut buf, self.acc(AccessKind::DataRead))
            .map_err(|_| mips::errno::EFAULT)?;
        Ok(buf)
    }

    fn write_bytes(&self, env: &mut BareEnv, addr: u64, data: &[u8]) -> Result<(), u32> {
        env.backend
            .mem
            .write(VirtAddr(addr), data)
            .map_err(|_| mips::errno::EFAULT)
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
    fn file_of(&mut self, fd: u32) -> Result<&mut std::fs::File, u32> {
        self.fds.file_mut(fd).ok_or(mips::errno::EBADF)
    }

    /// 読み用に fd を開いているものを返す。0/1/2 と FdTable の両方を見る。
    fn reader(&mut self, fd: u32) -> Result<ReadFd<'_>, u32> {
        match fd {
            0 => Ok(ReadFd::Stdin),
            1 | 2 => Err(mips::errno::EBADF),
            _ => self
                .fds
                .file_mut(fd)
                .map(ReadFd::File)
                .ok_or(mips::errno::EBADF),
        }
    }

    fn writer(&mut self, fd: u32) -> Result<WriteFd<'_>, u32> {
        match fd {
            0 => Err(mips::errno::EBADF),
            1 => Ok(WriteFd::Stdout),
            2 => Ok(WriteFd::Stderr),
            _ => self
                .fds
                .file_mut(fd)
                .map(WriteFd::File)
                .ok_or(mips::errno::EBADF),
        }
    }

    /// MIPS `O_*` をホストの `OpenOptions` 用フラグへ写す。
    fn open_flags(guest: u32) -> std::fs::OpenOptions {
        use mips::oflag::*;
        let mut oo = std::fs::OpenOptions::new();
        let accmode = guest & 3;
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

    /// open/openat の共通部。`dirfd` は AT_FDCWD でなければ EBADF 相当として扱う。
    fn do_open(&mut self, env: &mut BareEnv, path_addr: u64, flags: u32, mode: u32) -> u64 {
        let path = match self.read_cstr(env, path_addr) {
            Ok(p) => p,
            Err(e) => return self.fail(env, e),
        };
        let host = self.host_path(&path);
        if std::env::var_os("POLYISA_MIPS_SYSCALLS").is_some() {
            eprintln!("  open {path:?} -> {host:?}");
        }
        let oo = Self::open_flags(flags);
        let _ = mode;
        match oo.open(&host) {
            Ok(f) => {
                let fd = self.fds.alloc(polyisa_kernel::FdTarget::File(f));
                self.fds.remember_path(fd, host);
                Self::ret(env, u64::from(fd))
            }
            Err(e) => self.fail_host(env, e.raw_os_error().unwrap_or(mips::errno::EIO as i32)),
        }
    }

    /// ホストのメタデータをゲストの stat 系構造体に写す。
    /// `wide` は n64/o32 の stat64/stat の区別ではなく stat64 系 112 バイト形式を
    /// 使うとき真。o32 の古い `struct stat` は別形式。
    fn put_stat64(&self, env: &mut BareEnv, addr: u64, md: &polyisa_host::Stat) -> bool {
        // MIPS stat64 レイアウト（o32 は 32 ビット型、n64 は同形 112B）。
        // u32 dev + 12 pad, u64 ino, u32 mode, u32 nlink, u32 uid, u32 gid,
        // u32 rdev + 12 pad, i64 size, i32 atime, u32 ansec, i32 mtime, u32 mnsec,
        // i32 ctime, u32 cnsec, u32 blksize, u32 pad2, i64 blocks
        let w32 = |v: u64| -> [u8; 4] {
            match self.endian {
                Endian::Be => (v as u32).to_be_bytes(),
                Endian::Le => (v as u32).to_le_bytes(),
            }
        };
        let w64 = |v: u64| -> [u8; 8] {
            match self.endian {
                Endian::Be => v.to_be_bytes(),
                Endian::Le => v.to_le_bytes(),
            }
        };
        let mut b = [0u8; 112];
        let mut p = |off: usize, bytes: &[u8]| b[off..off + bytes.len()].copy_from_slice(bytes);
        p(0, &w32(md.dev));
        p(16, &w64(md.ino));
        p(24, &w32(u64::from(md.mode)));
        p(28, &w32(md.nlink));
        p(32, &w32(u64::from(md.uid)));
        p(36, &w32(u64::from(md.gid)));
        p(40, &w32(md.rdev));
        p(56, &w64(md.size));
        p(64, &w32(md.atime as u64));
        p(68, &w32(md.atime_nsec as u64));
        p(72, &w32(md.mtime as u64));
        p(76, &w32(md.mtime_nsec as u64));
        p(80, &w32(md.ctime as u64));
        p(84, &w32(md.ctime_nsec as u64));
        p(88, &w32(md.blksize));
        p(96, &w64(md.blocks));
        env.backend.mem.write(VirtAddr(addr), &b).is_ok()
    }

    /// n64 の `struct stat`（112B、上と同形だが時刻が 64 ビット）。
    fn put_stat_n64(&self, env: &mut BareEnv, addr: u64, md: &polyisa_host::Stat) -> bool {
        // u32 dev + 12 pad, u64 ino, u32 mode, u32 nlink, u32 uid, u32 gid,
        // u32 rdev + 12 pad, i64 size,
        // u32 atime, u32 ansec, u32 mtime, u32 mnsec, u32 ctime, u32 cnsec,
        // u32 blksize, u32 pad2, u64 blocks
        let w32 = |v: u64| -> [u8; 4] {
            match self.endian {
                Endian::Be => (v as u32).to_be_bytes(),
                Endian::Le => (v as u32).to_le_bytes(),
            }
        };
        let w64 = |v: u64| -> [u8; 8] {
            match self.endian {
                Endian::Be => v.to_be_bytes(),
                Endian::Le => v.to_le_bytes(),
            }
        };
        let mut b = [0u8; 112];
        let mut p = |off: usize, bytes: &[u8]| b[off..off + bytes.len()].copy_from_slice(bytes);
        p(0, &w32(md.dev));
        p(16, &w64(md.ino));
        p(24, &w32(u64::from(md.mode)));
        p(28, &w32(md.nlink));
        p(32, &w32(u64::from(md.uid)));
        p(36, &w32(u64::from(md.gid)));
        p(40, &w32(md.rdev));
        p(56, &w64(md.size));
        p(64, &w32(md.atime as u64));
        p(68, &w32(md.atime_nsec as u64));
        p(72, &w32(md.mtime as u64));
        p(76, &w32(md.mtime_nsec as u64));
        p(80, &w32(md.ctime as u64));
        p(84, &w32(md.ctime_nsec as u64));
        p(88, &w32(md.blksize));
        p(96, &w64(md.blocks));
        env.backend.mem.write(VirtAddr(addr), &b).is_ok()
    }

    /// o32 の古い `struct stat`（136 バイト）。
    fn put_stat_o32(&self, env: &mut BareEnv, addr: u64, md: &polyisa_host::Stat) -> bool {
        let w32 = |v: i64| -> [u8; 4] {
            match self.endian {
                Endian::Be => (v as u32).to_be_bytes(),
                Endian::Le => (v as u32).to_le_bytes(),
            }
        };
        let mut b = [0u8; 136];
        let mut p = |off: usize, v: i64| b[off..off + 4].copy_from_slice(&w32(v));
        p(0, md.dev as i64);
        p(16, md.ino as i64);
        p(20, i64::from(md.mode));
        p(24, md.nlink as i64);
        p(28, i64::from(md.uid));
        p(32, i64::from(md.gid));
        p(36, md.rdev as i64);
        p(52, md.size as i64);
        p(60, md.atime);
        p(64, md.atime_nsec);
        p(68, md.mtime);
        p(72, md.mtime_nsec);
        p(76, md.ctime);
        p(80, md.ctime_nsec);
        p(84, md.blksize as i64);
        p(88, md.blocks as i64);
        env.backend.mem.write(VirtAddr(addr), &b).is_ok()
    }

    /// ABI に合った stat を書く。
    fn put_stat(
        &self,
        env: &mut BareEnv,
        addr: u64,
        md: &polyisa_host::Stat,
        wide64: bool,
    ) -> bool {
        match (self.abi, wide64) {
            (Abi::N64, _) => self.put_stat_n64(env, addr, md),
            (Abi::N32, _) | (Abi::O32, true) => self.put_stat64(env, addr, md),
            (Abi::O32, false) => self.put_stat_o32(env, addr, md),
        }
    }

    /// fstat/stat/stat64/lstat/fstatat 共通の解決。
    fn do_stat(
        &mut self,
        env: &mut BareEnv,
        fd: Option<u32>,
        path_addr: u64,
        out: u64,
        wide64: bool,
        _no_follow: bool,
    ) -> u64 {
        let md = if let Some(fd) = fd {
            match fd {
                0..=2 => match polyisa_host::stat(&format!("/proc/self/fd/{fd}")) {
                    Ok(m) => m,
                    Err(e) => {
                        return self
                            .fail_host(env, e.raw_os_error().unwrap_or(mips::errno::EIO as i32));
                    }
                },
                _ => match self.fds.file(fd) {
                    Some(f) => match polyisa_host::fstat(f) {
                        Ok(m) => m,
                        Err(e) => {
                            return self.fail_host(
                                env,
                                e.raw_os_error().unwrap_or(mips::errno::EIO as i32),
                            );
                        }
                    },
                    None => return self.fail(env, mips::errno::EBADF),
                },
            }
        } else {
            let path = match self.read_cstr(env, path_addr) {
                Ok(p) => p,
                Err(e) => return self.fail(env, e),
            };
            match polyisa_host::stat(&self.host_path(&path)) {
                Ok(m) => m,
                Err(e) => {
                    return self
                        .fail_host(env, e.raw_os_error().unwrap_or(mips::errno::EIO as i32));
                }
            }
        };
        if self.put_stat(env, out, &md, wide64) {
            Self::ret(env, 0)
        } else {
            self.fail(env, mips::errno::EFAULT)
        }
    }

    /// 無名 mmap/mmap2。ファイル写像は ENOSYS。
    fn do_mmap(&mut self, env: &mut BareEnv, addr: u64, len: u64, prot: u64, flags: u64) -> u64 {
        let len = len.max(1);
        let pages = len.div_ceil(polyisa_mem::PAGE_SIZE);
        let base = if flags & u64::from(mips::mflag::FIXED) != 0 && addr != 0 {
            addr
        } else {
            let b = self.mmap_next;
            self.mmap_next = self.mmap_next.wrapping_add(pages * polyisa_mem::PAGE_SIZE);
            b
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
        match env.backend.mem.map(VirtAddr(base), pages, Perms(p)) {
            Ok(()) => self.ret_ptr(env, base),
            Err(_) => self.fail(env, mips::errno::ENOMEM),
        }
    }

    /// brk。0 なら現在値を返す。像の末尾は `init_brk` で受ける。
    fn do_brk(&mut self, env: &mut BareEnv, addr: u64) -> u64 {
        if addr == 0 {
            return self.ret_ptr(env, self.heap_end);
        }
        if addr < self.heap_end {
            // 縮小は受け付けるが解放はしない。
            self.heap_end = addr;
            return self.ret_ptr(env, self.heap_end);
        }
        let page_base = self.heap_end.next_multiple_of(polyisa_mem::PAGE_SIZE);
        if addr > page_base {
            let need = (addr - page_base).div_ceil(polyisa_mem::PAGE_SIZE);
            if env
                .backend
                .mem
                .map(VirtAddr(page_base), need, Perms::RW)
                .is_err()
            {
                return self.fail(env, mips::errno::ENOMEM);
            }
        }
        self.heap_end = addr;
        self.ret_ptr(env, self.heap_end)
    }

    /// `utsname` 6 フィールド。フィールド幅は 65。
    fn do_uname(&mut self, env: &mut BareEnv, addr: u64) -> u64 {
        let fields: [&[u8]; 6] = [
            b"Linux",
            b"polyisa",
            b"6.19.0",
            b"#1 polyisa",
            b"mips",
            b"(none)",
        ];
        let machine: &[u8] = match self.abi {
            Abi::O32 | Abi::N32 => b"mips",
            Abi::N64 => b"mips64",
        };
        let fields = [
            fields[0], fields[1], fields[2], fields[3], machine, fields[5],
        ];
        for (i, f) in fields.iter().enumerate() {
            let mut buf = [0u8; 65];
            buf[..f.len()].copy_from_slice(f);
            if env
                .backend
                .mem
                .write(VirtAddr(addr + (i * 65) as u64), &buf)
                .is_err()
            {
                return self.fail(env, mips::errno::EFAULT);
            }
        }
        Self::ret(env, 0)
    }

    /// `sysinfo`（112 バイト）。最小限の値を返す。
    fn do_sysinfo(&mut self, env: &mut BareEnv, addr: u64) -> u64 {
        let secs = self.mono_start.map(|s| s.elapsed().as_secs()).unwrap_or(0) as i64;
        let w =
            |env: &mut BareEnv, off: u64, v: i64| self.put::<U64x>(env, addr + off, U64x(v as u64));
        let mem_unit = 1u64;
        let total = 512 * 1024 * 1024u64;
        let _ = w(env, 0, secs);
        let _ = w(env, 8, 0); // loads[3] は飛ばす
        let _ = w(env, 20, (total / mem_unit) as i64);
        let _ = w(env, 28, (total / mem_unit) as i64);
        let _ = w(env, 84, mem_unit as i64);
        Self::ret(env, 0)
    }

    /// `getrandom`。
    fn do_getrandom(&mut self, env: &mut BareEnv, buf: u64, len: u64) -> u64 {
        let mut data = vec![0u8; len.min(1 << 20) as usize];
        match std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut data)) {
            Ok(()) => match self.write_bytes(env, buf, &data) {
                Ok(()) => Self::ret(env, data.len() as u64),
                Err(e) => self.fail(env, e),
            },
            Err(e) => self.fail_host(env, e.raw_os_error().unwrap_or(mips::errno::EIO as i32)),
        }
    }

    /// `getdents64`。linux_dirent64: u64 d_ino, u64 d_off, u16 d_reclen, u8 d_type, name\0。
    fn do_getdents64(&mut self, env: &mut BareEnv, fd: u32, buf: u64, count: u64) -> u64 {
        let path = self.fds.path_of(fd).map(str::to_string).unwrap_or_default();
        if path.is_empty() {
            return self.fail(env, mips::errno::ENOTDIR);
        }
        let rd = match std::fs::read_dir(&path) {
            Ok(r) => r,
            Err(e) => {
                return self.fail_host(env, e.raw_os_error().unwrap_or(mips::errno::EIO as i32));
            }
        };
        let mut out = Vec::new();
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
        // "." と ".." を先頭に足す。
        let mut all = vec![(1u64, ".".to_string(), 4u8), (1, "..".to_string(), 4u8)];
        all.extend(entries);
        let count = count as usize;
        let w64 = |v: u64| match self.endian {
            Endian::Be => v.to_be_bytes(),
            Endian::Le => v.to_le_bytes(),
        };
        let w16 = |v: u16| match self.endian {
            Endian::Be => v.to_be_bytes(),
            Endian::Le => v.to_le_bytes(),
        };
        // ディレクトリ位置を fd ごとに持ち、続きから返す。先頭から
        // 返し続けると呼び出し側が終了しない。
        let mut pos = *self.dir_pos.get(&fd).unwrap_or(&0);
        let mut emitted = 0usize;
        for (i, (ino, name, t)) in all.iter().enumerate().skip(pos) {
            let reclen = 19 + name.len() + 1;
            let aligned = reclen.next_multiple_of(8);
            if out.len() + aligned > count {
                break;
            }
            out.extend_from_slice(&w64(*ino));
            // d_off は次エントリの位置（最後は out.len()+aligned）。
            out.extend_from_slice(&w64((i + 1) as u64));
            out.extend_from_slice(&w16(aligned as u16));
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
        match self.write_bytes(env, buf, &out) {
            Ok(()) => Self::ret(env, out.len() as u64),
            Err(e) => self.fail(env, e),
        }
    }

    /// `readlink`/`readlinkat`。
    fn do_readlink(&mut self, env: &mut BareEnv, path_addr: u64, buf: u64, len: u64) -> u64 {
        let path = match self.read_cstr(env, path_addr) {
            Ok(p) => p,
            Err(e) => return self.fail(env, e),
        };
        let host = self.host_path(&path);
        // /proc/self/exe はゲストの exe_path へ。
        let target = if host == "/proc/self/exe" {
            self.exe_path.clone()
        } else {
            match std::fs::read_link(&host) {
                Ok(t) => t.to_string_lossy().into_owned(),
                Err(e) => {
                    return self
                        .fail_host(env, e.raw_os_error().unwrap_or(mips::errno::EIO as i32));
                }
            }
        };
        let n = target.len().min(len as usize);
        match self.write_bytes(env, buf, &target.as_bytes()[..n]) {
            Ok(()) => Self::ret(env, n as u64),
            Err(e) => self.fail(env, e),
        }
    }

    /// `read`/`pread`。
    fn do_read(&mut self, env: &mut BareEnv, fd: u32, buf: u64, len: u64) -> u64 {
        let len = len.min(1 << 20) as usize;
        let r = match self.reader(fd) {
            Ok(r) => r,
            Err(e) => return self.fail(env, e),
        };
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
                match self.write_bytes(env, buf, &chunk[..n]) {
                    Ok(()) => Self::ret(env, n as u64),
                    Err(e) => self.fail(env, e),
                }
            }
            ReadFd::File(f) => {
                let mut chunk = vec![0u8; len];
                match f.read(&mut chunk) {
                    Ok(n) => match self.write_bytes(env, buf, &chunk[..n]) {
                        Ok(()) => Self::ret(env, n as u64),
                        Err(e) => self.fail(env, e),
                    },
                    Err(e) => {
                        self.fail_host(env, e.raw_os_error().unwrap_or(mips::errno::EIO as i32))
                    }
                }
            }
        }
    }

    /// `write`/`pwrite`。
    fn do_write(&mut self, env: &mut BareEnv, fd: u32, buf: u64, len: u64) -> u64 {
        let data = match self.read_bytes(env, buf, len as usize) {
            Ok(d) => d,
            Err(e) => return self.fail(env, e),
        };
        let w = match self.writer(fd) {
            Ok(w) => w,
            Err(e) => return self.fail(env, e),
        };
        match w {
            WriteFd::Stdout => {
                self.io.stdout.extend_from_slice(&data);
                let _ = std::io::Write::write_all(&mut std::io::stdout(), &data);
                Self::ret(env, data.len() as u64)
            }
            WriteFd::Stderr => {
                self.io.stderr.extend_from_slice(&data);
                let _ = std::io::Write::write_all(&mut std::io::stderr(), &data);
                Self::ret(env, data.len() as u64)
            }
            WriteFd::File(f) => match f.write(&data) {
                Ok(n) => Self::ret(env, n as u64),
                Err(e) => self.fail_host(env, e.raw_os_error().unwrap_or(mips::errno::EIO as i32)),
            },
        }
    }

    /// `sendfile`/`sendfile64`。offset==NULL のみ受け付ける（cat が使う形）。
    /// in_fd からチャンク読みして out_fd の writer へ流し、転送数を返す。
    fn do_sendfile(
        &mut self,
        env: &mut BareEnv,
        out_fd: u32,
        in_fd: u32,
        off: u64,
        cnt: u64,
    ) -> u64 {
        if off != 0 {
            return self.fail(env, mips::errno::EINVAL);
        }
        let mut left = cnt.min(1 << 22) as usize;
        let mut done = 0u64;
        while left > 0 {
            let n = left.min(64 * 1024);
            let mut buf = vec![0u8; n];
            let got = {
                let r = match self.reader(in_fd) {
                    Ok(r) => r,
                    Err(e) => return self.fail(env, e),
                };
                match r {
                    ReadFd::Stdin => {
                        let avail = self.stdin_buf.len().saturating_sub(self.stdin_pos);
                        let take = avail.min(n);
                        buf[..take].copy_from_slice(
                            &self.stdin_buf[self.stdin_pos..self.stdin_pos + take],
                        );
                        self.stdin_pos += take;
                        take
                    }
                    ReadFd::File(f) => match f.read(&mut buf) {
                        Ok(n) => n,
                        Err(e) => {
                            return self.fail_host(
                                env,
                                e.raw_os_error().unwrap_or(mips::errno::EIO as i32),
                            );
                        }
                    },
                }
            };
            if got == 0 {
                break;
            }
            let w = match self.writer(out_fd) {
                Ok(w) => w,
                Err(e) => return self.fail(env, e),
            };
            let put = match w {
                WriteFd::Stdout => {
                    self.io.stdout.extend_from_slice(&buf[..got]);
                    let _ = std::io::Write::write_all(&mut std::io::stdout(), &buf[..got]);
                    got
                }
                WriteFd::Stderr => {
                    self.io.stderr.extend_from_slice(&buf[..got]);
                    let _ = std::io::Write::write_all(&mut std::io::stderr(), &buf[..got]);
                    got
                }
                WriteFd::File(f) => match f.write(&buf[..got]) {
                    Ok(n) => n,
                    Err(e) => {
                        return self
                            .fail_host(env, e.raw_os_error().unwrap_or(mips::errno::EIO as i32));
                    }
                },
            };
            done += put as u64;
            left -= got;
            if put < got {
                break;
            }
        }
        Self::ret(env, done)
    }

    /// `readv`/`writev`。
    fn do_readv(&mut self, env: &mut BareEnv, fd: u32, iov: u64, cnt: u64) -> u64 {
        let mut total = 0u64;
        let w = u64::from(self.abi.ptr_bits() / 8);
        let dbg = std::env::var_os("POLYISA_MIPS_SYSCALLS").is_some();
        for i in 0..cnt.min(1024) {
            let base = self.mem_u(env, iov + i * 2 * w);
            let len = self.mem_u(env, iov + i * 2 * w + w);
            let n = self.do_read(env, fd, base, len);
            if dbg {
                eprintln!("  readv fd={fd} base={base:#x} len={len:#x} -> {n}");
            }
            if get_reg(env, 7) != 0 {
                return n;
            }
            total = total.wrapping_add(n);
            if n < len {
                break;
            }
        }
        Self::ret(env, total)
    }

    fn do_writev(&mut self, env: &mut BareEnv, fd: u32, iov: u64, cnt: u64) -> u64 {
        let mut total = 0u64;
        let w = u64::from(self.abi.ptr_bits() / 8);
        for i in 0..cnt.min(1024) {
            let base = self.mem_u(env, iov + i * 2 * w);
            let len = self.mem_u(env, iov + i * 2 * w + w);
            let n = self.do_write(env, fd, base, len);
            if get_reg(env, 7) != 0 {
                return n;
            }
            total = total.wrapping_add(n);
        }
        Self::ret(env, total)
    }

    /// `lseek`。
    fn do_lseek(&mut self, env: &mut BareEnv, fd: u32, off: i64, whence: u32) -> u64 {
        if whence > 2 {
            return self.fail(env, mips::errno::EINVAL);
        }
        // ディレクトリの巻き戻し（rewinddir）は getdents 位置も戻す。
        if whence == 0 && off == 0 {
            self.dir_pos.remove(&fd);
        }
        let f = match self.file_of(fd) {
            Ok(f) => f,
            Err(e) => return self.fail(env, e),
        };
        let w = match whence {
            0 => SeekFrom::Start(off as u64),
            1 => SeekFrom::Current(off),
            2 => SeekFrom::End(off),
            _ => unreachable!(),
        };
        match f.seek(w) {
            Ok(p) => Self::ret(env, p),
            Err(e) => self.fail_host(env, e.raw_os_error().unwrap_or(mips::errno::EIO as i32)),
        }
    }

    /// `ioctl`。TCGETS/TCSETS/TIOCGWINSZ/FIONREAD/TIOCNOTTY だけ。
    fn do_ioctl(&mut self, env: &mut BareEnv, fd: u32, req: u64, argp: u64) -> u64 {
        match req {
            mips::ioc::TCGETS | mips::ioc::TCSETS => {
                // tty でない fd には ENOTTY を返す。
                match fd {
                    0..=2 => Self::ret(env, 0),
                    _ => self.fail(env, mips::errno::ENOTTY),
                }
            }
            mips::ioc::TIOCGWINSZ => {
                // winsize { ws_row, ws_col, ws_xpixel, ws_ypixel }。80x24 を返す。
                let row: u16 = 24;
                let col: u16 = 80;
                let mut b = [0u8; 8];
                let e = self.endian;
                let w = |v: u16| match e {
                    Endian::Be => v.to_be_bytes(),
                    Endian::Le => v.to_le_bytes(),
                };
                b[0..2].copy_from_slice(&w(row));
                b[2..4].copy_from_slice(&w(col));
                match self.write_bytes(env, argp, &b) {
                    Ok(()) => Self::ret(env, 0),
                    Err(x) => self.fail(env, x),
                }
            }
            mips::ioc::FIONREAD => {
                let n = 0u32; // stdin は即時読めるバイト数不明。0 を返す
                if self.put::<U32x>(env, argp, U32x(n)) {
                    Self::ret(env, 0)
                } else {
                    self.fail(env, mips::errno::EFAULT)
                }
            }
            mips::ioc::TIOCNOTTY => Self::ret(env, 0),
            _ => self.fail(env, mips::errno::ENOTTY),
        }
    }

    /// `fcntl`/`fcntl64`。FD フラグだけ。
    fn do_fcntl(&mut self, env: &mut BareEnv, _fd: u32, cmd: u32, _arg: u64) -> u64 {
        match cmd {
            1 => Self::ret(env, 0), // F_GETFD
            2 => Self::ret(env, 0), // F_SETFD
            3 => Self::ret(env, 0), // F_GETFL（フラグは覚えていない）
            4 => Self::ret(env, 0), // F_SETFL
            _ => self.fail(env, mips::errno::EINVAL),
        }
    }

    /// `gettimeofday`/`clock_gettime`/`time`/`times`。
    fn mono_us(&mut self) -> u64 {
        self.mono_start
            .get_or_insert_with(std::time::Instant::now)
            .elapsed()
            .as_micros() as u64
    }

    fn put_timespec(&self, env: &mut BareEnv, addr: u64, sec: u64, nsec: u64) -> bool {
        if self.abi.ptr_bits() == 64 {
            self.put::<U64x>(env, addr, U64x(sec)) && self.put::<U64x>(env, addr + 8, U64x(nsec))
        } else {
            self.put::<U32x>(env, addr, U32x(sec as u32))
                && self.put::<U32x>(env, addr + 4, U32x(nsec as u32))
        }
    }

    /// `statfs`/`fstatfs`/`statfs64`/`fstatfs64`。
    /// MIPS の形式は汎用と並びが違い、f_frsize が f_bsize の直後に来る。
    /// layout は `FsLayout` を見る。値は合成（実 fs を反映しない）。
    fn do_statfs(&mut self, env: &mut BareEnv, addr: u64, layout: FsLayout) -> u64 {
        let w32 = |v: u32| match self.endian {
            Endian::Be => v.to_be_bytes(),
            Endian::Le => v.to_le_bytes(),
        };
        let w64 = |v: u64| match self.endian {
            Endian::Be => v.to_be_bytes(),
            Endian::Le => v.to_le_bytes(),
        };
        // フィールド（type, bsize, frsize, blocks, bfree, files, ffree,
        // bavail, namelen）の合成値。
        let fields = [
            0xEF53u64,
            4096,
            4096,
            1 << 22,
            1 << 21,
            1 << 20,
            1 << 19,
            1 << 20,
            255,
        ];
        let mut b = vec![0u8; layout.size()];
        match layout {
            FsLayout::Short => {
                // u32 の列 + fsid(8B) + namelen + spare[6]。68 バイト。
                for (i, v) in fields[..8].iter().enumerate() {
                    b[i * 4..i * 4 + 4].copy_from_slice(&w32(*v as u32));
                }
                b[40..44].copy_from_slice(&w32(fields[8] as u32));
            }
            FsLayout::W64 => {
                // u32 三つ + pad + u64 五つ + fsid(8B) + namelen + spare[6]。
                // 92 バイト。
                for (i, v) in fields[..3].iter().enumerate() {
                    b[i * 4..i * 4 + 4].copy_from_slice(&w32(*v as u32));
                }
                for (i, v) in fields[3..8].iter().enumerate() {
                    b[16 + i * 8..24 + i * 8].copy_from_slice(&w64(*v));
                }
                b[64..68].copy_from_slice(&w32(fields[8] as u32));
            }
            FsLayout::Full => {
                // u64 の列 + fsid(8B) + namelen + spare[6]u64。128 バイト。
                for (i, v) in fields[..8].iter().enumerate() {
                    b[i * 8..i * 8 + 8].copy_from_slice(&w64(*v));
                }
                b[72..80].copy_from_slice(&w64(fields[8]));
            }
        }
        match self.write_bytes(env, addr, &b) {
            Ok(()) => Self::ret(env, 0),
            Err(e) => self.fail(env, e),
        }
    }

    /// `ustat`。f_tfree/f_tinode はポインタ幅、f_fname/f_fpack は 6B の列。
    fn do_ustat(&mut self, env: &mut BareEnv, addr: u64) -> u64 {
        let ptr = (self.abi.ptr_bits() / 8) as usize;
        let mut b = vec![0u8; ptr * 2 + 12];
        let w = |v: u64| match (self.abi.ptr_bits(), self.endian) {
            (32, Endian::Be) => (v as u32).to_be_bytes().to_vec(),
            (32, Endian::Le) => (v as u32).to_le_bytes().to_vec(),
            (_, Endian::Be) => v.to_be_bytes().to_vec(),
            (_, Endian::Le) => v.to_le_bytes().to_vec(),
        };
        b[..ptr].copy_from_slice(&w(1 << 20));
        b[ptr..ptr * 2].copy_from_slice(&w(1 << 20));
        match self.write_bytes(env, addr, &b) {
            Ok(()) => Self::ret(env, 0),
            Err(e) => self.fail(env, e),
        }
    }
}

/// `statfs` 系のバッファ形式。MIPS の uapi が定める三つの並び。
#[derive(Clone, Copy, PartialEq, Eq)]
enum FsLayout {
    /// o32/n32 の `statfs`: u32 の列。68 バイト。
    Short,
    /// 32 ビット ABI の `statfs64`: u32 頭 + パッド + u64 群。92 バイト。
    W64,
    /// n64 の `statfs`: u64 の列。128 バイト。
    Full,
}

impl FsLayout {
    fn size(self) -> usize {
        match self {
            FsLayout::Short => 68,
            FsLayout::W64 => 92,
            FsLayout::Full => 128,
        }
    }
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

fn reg(env: &mut BareEnv, i: u8) -> u64 {
    if i == 0 {
        0
    } else {
        env.backend.get(Gpr(i).state())
    }
}

fn get_reg(env: &mut BareEnv, i: u8) -> u64 {
    reg(env, i)
}

fn set_reg(env: &mut BareEnv, i: u8, v: u64) {
    if i != 0 {
        env.backend.set(Gpr(i).state(), v);
    }
}

/// エンディアンを取る数値のバイト化。
trait NumBytes {
    fn bytes(&self, e: Endian) -> Vec<u8>;
}

struct U32x(u32);
struct U64x(u64);

// put<> の型引数に使うマーカー。

impl NumBytes for U32x {
    fn bytes(&self, e: Endian) -> Vec<u8> {
        match e {
            Endian::Be => self.0.to_be_bytes().to_vec(),
            Endian::Le => self.0.to_le_bytes().to_vec(),
        }
    }
}

impl NumBytes for U64x {
    fn bytes(&self, e: Endian) -> Vec<u8> {
        match e {
            Endian::Be => self.0.to_be_bytes().to_vec(),
            Endian::Le => self.0.to_le_bytes().to_vec(),
        }
    }
}

impl TrapHandler for Linux {
    /// `brk` の初期値。ローダが像の末尾を渡す。
    fn init_brk(&mut self, image_end: u64) {
        self.heap_end = image_end;
        // mmap アリーナはヒープ直上には置かない。向上する brk と
        // 向上する mmap が衝突し、map() の重複書きが既存ページを
        // ゼロ初期化で上書きするため。
        self.mmap_next = image_end.div_ceil(0x1000) * 0x1000 + 0x800_0000;
    }

    fn handle_trap(&mut self, env: &mut BareEnv, _code: u32) -> TrapOutcome {
        let nr = reg(env, 2) & 0xffff_ffff;
        let base = match self.abi {
            Abi::O32 => 4000,
            Abi::N32 => 6000,
            Abi::N64 => 5000,
        };
        let off = nr.wrapping_sub(base);
        let abi = self.abi;
        if std::env::var_os("POLYISA_MIPS_SYSCALLS").is_some() {
            let name = abi.name(nr).unwrap_or("?");
            eprintln!(
                "sys {nr} {name} a0={:#x} a1={:#x}",
                reg(env, 4),
                reg(env, 5)
            );
        }
        let r = match abi {
            Abi::O32 => self.dispatch_o32(env, off),
            Abi::N32 => self.dispatch_64(env, off, mips_n32::name(nr)),
            Abi::N64 => self.dispatch_64(env, off, mips_n64::name(nr)),
        };
        match r {
            Disp::Ret(v) => {
                set_reg(env, 2, v);
                TrapOutcome::Handled
            }
            Disp::Exit(code) => TrapOutcome::Exit(code),
            Disp::Unimpl => {
                let name = abi.name(nr).unwrap_or("?");
                if !self.reported.contains(&nr) {
                    self.reported.push(nr);
                    eprintln!("mips {abi:?}: unimplemented syscall {nr} ({name})");
                }
                set_reg(env, 2, u64::from(mips::errno::ENOSYS));
                set_reg(env, 7, 1);
                TrapOutcome::Handled
            }
        }
    }
}

enum Disp {
    /// v0 に書く値（a3 は個別に書く）。
    Ret(u64),
    Exit(u32),
    /// 未実装。ENOSYS を返して続ける。
    Unimpl,
}

/// dispatch の戻りを作る。ok() は a3=0、fail() は a3=1 を書いたうえで値を返す。
fn ret(v: u64) -> Disp {
    Disp::Ret(v)
}

impl Linux {
    /// ソケット系 syscall を `sock` 正準層へ委譲する（socketcall
    /// 副番号の展開を含む）。errno・SO_*・O_* は MIPS 独自系。
    /// 待ち要求は単一スレッド消化で進め、進行不能はデッドロック
    /// として報告する。
    fn sock_call(&mut self, env: &mut BareEnv, name: &str, args: &[u64; 8]) -> Disp {
        let mut abi = crate::sock::SockAbi::generic((self.abi.ptr_bits() / 8) as u8, self.endian);
        abi.errno = mips::host_to_mips_errno;
        abi.so_to_host = crate::sock::so_odd_to_host;
        abi.sock_nonblock = 0x80; // mips O_NONBLOCK
        abi.sock_cloexec = 0x80000; // mips O_CLOEXEC
        let map = crate::sock::unix_path_map("", &self.cwd);
        let a6: &[u64; 6] = args[..6].try_into().unwrap_or(&[0; 6]);
        let t0 = std::time::Instant::now();
        let mono = move || t0.elapsed().as_nanos() as u64;
        match crate::sock::drive(&mut self.fds, &abi, env, name, a6, &map, 0, &mono) {
            Some(Ok(v)) => ret(Self::ok(env, v)),
            Some(Err(e)) => {
                if e == crate::sock::errno::EDEADLK {
                    eprintln!("mips: deadlock in fd wait");
                }
                self.fail_ret(env, (abi.errno)(e))
            }
            None => self.fail_ret(env, mips::errno::ENOSYS),
        }
    }

    /// o32 の番号（4000 からの通し番号）で振り分ける。
    fn dispatch_o32(&mut self, env: &mut BareEnv, n: u64) -> Disp {
        let args: [u64; 8] = std::array::from_fn(|i| self.arg(env, i));
        match n {
            // exit=1, exit_group=246
            1 => Disp::Exit((args[0] & 0xff) as u32),
            246 => Disp::Exit((args[0] & 0xff) as u32),
            // fork=2, vfork は表にない
            2 => self.fail_ret(env, mips::errno::ENOSYS),
            // read=3, write=4
            3 => {
                let fd = args[0] as u32;
                let buf = args[1];
                let len = args[2];
                ret(self.do_read(env, fd, buf, len))
            }
            4 => {
                let fd = args[0] as u32;
                let buf = args[1];
                let len = args[2];
                ret(self.do_write(env, fd, buf, len))
            }
            // open=5, openat=288
            5 => ret(self.do_open(env, args[0], args[1] as u32, args[2] as u32)),
            288 => {
                let dirfd = args[0] as u32;
                if dirfd as i32 != -100 {
                    return self.fail_ret(env, mips::errno::EBADF);
                }
                ret(self.do_open(env, args[1], args[2] as u32, args[3] as u32))
            }
            // close=6
            6 => {
                let fd = args[0] as u32;
                if fd < 3 {
                    return ret(Self::ret(env, 0));
                }
                if self.fds.ent(fd).is_some() {
                    self.fds.clear(fd);
                    self.dir_pos.remove(&fd);
                    ret(Self::ret(env, 0))
                } else {
                    self.fail_ret(env, mips::errno::EBADF)
                }
            }
            // waitpid=7, wait4=114, waitid=278
            7 | 114 | 278 => self.fail_ret(env, mips::errno::ECHILD),
            // creat=8
            8 => {
                let flags = mips::oflag::CREAT | mips::oflag::TRUNC | 1;
                ret(self.do_open(env, args[0], flags, args[1] as u32))
            }
            // link=9, linkat=296
            9 | 296 => self.unimpl_path2(env),
            // unlink=10, unlinkat=294
            10 => self.unimpl_path1(env),
            294 => {
                let dirfd = args[0] as u32;
                if dirfd as i32 != -100 {
                    return self.fail_ret(env, mips::errno::EBADF);
                }
                self.unimpl_path1_at(env, 1)
            }
            // execve=11
            11 => self.fail_ret(env, mips::errno::ENOSYS),
            // chdir=12, fchdir=133
            12 => {
                let __a0 = args[0];
                let path = match self.read_cstr(env, __a0) {
                    Ok(p) => p,
                    Err(e) => return self.fail_ret(env, e),
                };
                let host = self.host_path(&path);
                if polyisa_host::stat(&host)
                    .map(|m| m.mode & 0o170000 == 0o040000)
                    .unwrap_or(false)
                {
                    self.cwd = host;
                    ret(Self::ret(env, 0))
                } else {
                    self.fail_ret(env, mips::errno::ENOENT)
                }
            }
            133 => ret(Self::ret(env, 0)),
            // time=13
            13 => {
                let secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let tp = args[0];
                if tp != 0 && !self.put_u(env, tp, secs) {
                    return self.fail_ret(env, mips::errno::EFAULT);
                }
                ret(Self::ret(env, secs))
            }
            // mknod=14
            14 => self.fail_ret(env, mips::errno::EPERM),
            // chmod=15, fchmod=94, fchmodat=299
            15 | 94 | 299 => ret(Self::ret(env, 0)),
            // lchown=16, chown=202, fchown=95, fchownat=291
            16 | 202 | 95 | 291 => ret(Self::ret(env, 0)),
            // lseek=19, _llseek=140
            19 => {
                let fd = args[0] as u32;
                let off = args[1] as u32 as i32;
                let wh = args[2] as u32;
                ret(self.do_lseek(env, fd, i64::from(off), wh))
            }
            140 => {
                // _llseek(fd, hi, lo, result_ptr, whence)
                let fd = args[0] as u32;
                let hi = u64::from(args[1] as u32);
                let lo = u64::from(args[2] as u32);
                let ptr = args[3];
                let wh = args[4] as u32;
                let off = ((hi << 32) | lo) as i64;
                let f = match self.file_of(fd) {
                    Ok(f) => f,
                    Err(e) => return self.fail_ret(env, e),
                };
                let w = match wh {
                    0 => SeekFrom::Start(off as u64),
                    1 => SeekFrom::Current(off),
                    2 => SeekFrom::End(off),
                    _ => return self.fail_ret(env, mips::errno::EINVAL),
                };
                match f.seek(w) {
                    Ok(p) => {
                        if self.put::<U64x>(env, ptr, U64x(p)) {
                            ret(Self::ret(env, 0))
                        } else {
                            self.fail_ret(env, mips::errno::EFAULT)
                        }
                    }
                    Err(e) => self.fail_ret_host(env, e),
                }
            }
            // getpid=20, getppid=64, gettid=222
            20 => ret(Self::ret(env, self.pid())),
            64 => ret(Self::ret(env, 0)),
            222 => ret(Self::ret(env, self.pid())),
            // mount=21, umount=22, umount2=52, pivot_root=216, reboot=88, swapon, swapoff
            21 | 22 | 52 | 216 | 88 | 115 | 87 => self.fail_ret(env, mips::errno::EPERM),
            // setuid=23, setgid=46, setreuid=70, setregid=71, setresuid=? , setfsuid/setfsgid
            23 | 46 | 70 | 71 => ret(Self::ret(env, 0)),
            // getuid=24, geteuid=49, getgid=47, getegid=50, getgroups=80
            24 | 49 | 47 | 50 => ret(Self::ret(env, 0)),
            80 => ret(Self::ret(env, 0)),
            81 => ret(Self::ret(env, 0)),
            // setpgid=57, getpgid=132, getsid=151, setsid=66
            57 | 132 | 66 => ret(Self::ret(env, self.pid())),
            151 => ret(Self::ret(env, self.pid())),
            // utime=30, utimes=267, utimensat=316
            30 | 267 | 316 => ret(Self::ret(env, 0)),
            // access=33, faccessat=300, faccessat2=439
            33 => self.unimpl_path1(env),
            300 => {
                let dirfd = args[0] as u32;
                if dirfd as i32 != -100 {
                    return self.fail_ret(env, mips::errno::EBADF);
                }
                self.unimpl_path1_at(env, 1)
            }
            439 => self.fail_ret(env, mips::errno::ENOSYS),
            // nice=34, getpriority=96, setpriority=97
            34 => ret(Self::ret(env, 0)),
            96 => ret(Self::ret(env, 0)),
            97 => ret(Self::ret(env, 0)),
            // sync=36, fsync=118, fdatasync=152, sync_file_range=305, msync=144
            36 | 118 | 152 | 305 | 144 => {
                let fd = if n != 36 { args[0] as u32 } else { 0 };
                if n != 36
                    && let Some(f) = self.fds.file(fd)
                {
                    let _ = f.sync_all();
                }
                ret(Self::ret(env, 0))
            }
            // kill=37, tkill=236, tgkill=266
            37 | 236 | 266 => {
                let _ = args[0];
                ret(Self::ret(env, 0))
            }
            // rename=38, renameat=295, renameat2=351
            38 | 295 => self.unimpl_path2(env),
            351 => self.fail_ret(env, mips::errno::ENOSYS),
            // mkdir=39, mkdirat=289
            39 => {
                let __a0 = args[0];
                let path = match self.read_cstr(env, __a0) {
                    Ok(p) => p,
                    Err(e) => return self.fail_ret(env, e),
                };
                match std::fs::create_dir(self.host_path(&path)) {
                    Ok(()) => ret(Self::ret(env, 0)),
                    Err(e) => self.fail_ret_host(env, e),
                }
            }
            289 => {
                let dirfd = args[0] as u32;
                if dirfd as i32 != -100 {
                    return self.fail_ret(env, mips::errno::EBADF);
                }
                let path = match self.read_cstr(env, args[1]) {
                    Ok(p) => p,
                    Err(e) => return self.fail_ret(env, e),
                };
                match std::fs::create_dir(self.host_path(&path)) {
                    Ok(()) => ret(Self::ret(env, 0)),
                    Err(e) => self.fail_ret_host(env, e),
                }
            }
            // rmdir=40
            40 => self.unimpl_path1(env),
            // dup=41, dup2=63, dup3=327
            41 => {
                let fd = args[0] as u32;
                match self.dup_fd(fd, 3) {
                    Ok(n) => ret(Self::ret(env, n)),
                    Err(e) => self.fail_ret(env, e),
                }
            }
            63 => {
                let old = args[0] as u32;
                let new = args[1] as u32;
                match self.dup2_fd(old, new) {
                    Ok(()) => ret(Self::ret(env, u64::from(new))),
                    Err(e) => self.fail_ret(env, e),
                }
            }
            327 => {
                let old = args[0] as u32;
                let new = args[1] as u32;
                match self.dup2_fd(old, new) {
                    Ok(()) => ret(Self::ret(env, u64::from(new))),
                    Err(e) => self.fail_ret(env, e),
                }
            }
            // pipe=42, pipe2=328
            42 | 328 => self.fail_ret(env, mips::errno::ENOSYS),
            // times=43
            43 => {
                let us = self.mono_us();
                // tms {utime, stime, cutime, cstime} *i32 — 値は使わない
                let t = args[0];
                if t != 0 {
                    for i in 0..4u64 {
                        let _ = self.put::<U32x>(env, t + i * 4, U32x(0));
                    }
                }
                ret(Self::ret(env, us / 10_000))
            }
            // brk=45
            45 => ret(self.do_brk(env, args[0])),
            // acct=51
            51 => self.fail_ret(env, mips::errno::ENOSYS),
            // ioctl=54, fcntl=55, fcntl64=220
            54 => {
                let fd = args[0] as u32;
                ret(self.do_ioctl(env, fd, args[1], args[2]))
            }
            55 | 220 => {
                let fd = args[0] as u32;
                ret(self.do_fcntl(env, fd, args[1] as u32, args[2]))
            }
            // setpgid=57 handled above
            // umask=60
            60 => {
                let old = self.umask;
                self.umask = args[0] as u32 & 0o777;
                ret(Self::ret(env, u64::from(old)))
            }
            // ustat=62 → do_ustat
            // dup2=63 handled, getppid=64, getpgrp=65
            65 => ret(Self::ret(env, self.pid())),
            // sigaction=67, sigsuspend=72, sigpending=73
            67 | 72 | 73 | 126 => ret(Self::ret(env, 0)),
            // sethostname=74
            74 => ret(Self::ret(env, 0)),
            // setrlimit=75, getrlimit=76, getrusage=77, prlimit64=338
            75 => ret(Self::ret(env, 0)),
            76 => {
                let p = args[1];
                let lim = [u32::MAX; 2]; // rlim_cur, rlim_max を INF に
                if p != 0
                    && !self.put::<U64x>(
                        env,
                        p,
                        U64x(u64::from(lim[0]) | (u64::from(lim[1]) << 32)),
                    )
                {
                    return self.fail_ret(env, mips::errno::EFAULT);
                }
                ret(Self::ret(env, 0))
            }
            338 => {
                let p = args[3];
                if p != 0 {
                    // prlimit64 {rlim_cur, rlim_max} u64x2 = 16B
                    let _ = self.put::<U64x>(env, p, U64x(u64::MAX));
                    let _ = self.put::<U64x>(env, p + 8, U64x(u64::MAX));
                }
                ret(Self::ret(env, 0))
            }
            77 => ret(Self::ret(env, 0)),
            // gettimeofday=78, settimeofday=79
            78 => {
                let tv = args[0];
                let tz = args[1];
                let (sec, usec) = Self::now();
                if tv != 0
                    && (!self.put_u(env, tv, sec)
                        || !self.put_u(env, tv + self.abi.ptr_bits() as u64 / 8, usec))
                {
                    return self.fail_ret(env, mips::errno::EFAULT);
                }
                if tz != 0 {
                    let _ = self.put::<U32x>(env, tz, U32x(0));
                    let _ = self.put::<U32x>(env, tz + 4, U32x(0));
                }
                ret(Self::ret(env, 0))
            }
            79 => ret(Self::ret(env, 0)),
            // getgroups=80, setgroups=81 handled
            // symlink=83, symlinkat=297
            83 | 297 => self.unimpl_path2(env),
            // readlink=85, readlinkat=298
            85 => ret(self.do_readlink(env, args[0], args[1], args[2])),
            298 => {
                let dirfd = args[0] as u32;
                if dirfd as i32 != -100 {
                    return self.fail_ret(env, mips::errno::EBADF);
                }
                ret(self.do_readlink(env, args[1], args[2], args[3]))
            }
            // mmap=90（旧形: offset はページ単位ではない。o32 の旧 mmap は引数6）
            90 => {
                // o32 の mmap は fd, offset を stack args で受ける。offset はバイト。
                let addr = args[0];
                let len = args[1];
                let prot = args[2];
                let flags = args[3];
                let _fd = args[4] as u32;
                let _off = args[5];
                if flags & u64::from(mips::mflag::ANONYMOUS) == 0 {
                    return self.fail_ret(env, mips::errno::ENODEV);
                }
                ret(self.do_mmap(env, addr, len, prot, flags))
            }
            // munmap=91
            91 => {
                let addr = args[0];
                let len = args[1].max(1);
                env.backend
                    .mem
                    .unmap(VirtAddr(addr), len.div_ceil(polyisa_mem::PAGE_SIZE));
                ret(Self::ret(env, 0))
            }
            // truncate=92, ftruncate=93, truncate64=211, ftruncate64=212
            92 => {
                let __a0 = args[0];
                let path = match self.read_cstr(env, __a0) {
                    Ok(p) => p,
                    Err(e) => return self.fail_ret(env, e),
                };
                let len = args[1];
                match std::fs::OpenOptions::new()
                    .write(true)
                    .open(self.host_path(&path))
                    .and_then(|f| f.set_len(len))
                {
                    Ok(()) => ret(Self::ret(env, 0)),
                    Err(e) => self.fail_ret_host(env, e),
                }
            }
            93 => {
                let fd = args[0] as u32;
                let len = args[1];
                match self
                    .file_of(fd)
                    .and_then(|f| f.set_len(len).map_err(|_| mips::errno::EIO).map(|_| f))
                {
                    Ok(_) => ret(Self::ret(env, 0)),
                    Err(e) => self.fail_ret(env, e),
                }
            }
            211 => {
                let __a0 = args[0];
                let path = match self.read_cstr(env, __a0) {
                    Ok(p) => p,
                    Err(e) => return self.fail_ret(env, e),
                };
                // o32: len は奇数位置なので a1 にパッド、a2/a3 の語対。
                let len = self.a64(&args, 2);
                match std::fs::OpenOptions::new()
                    .write(true)
                    .open(self.host_path(&path))
                    .and_then(|f| f.set_len(len))
                {
                    Ok(()) => ret(Self::ret(env, 0)),
                    Err(e) => self.fail_ret_host(env, e),
                }
            }
            212 => {
                let fd = args[0] as u32;
                // o32: len は奇数位置なので a1 にパッド、a2/a3 の語対。
                let len = self.a64(&args, 2);
                match self.file_of(fd) {
                    Ok(f) => match f.set_len(len) {
                        Ok(()) => ret(Self::ret(env, 0)),
                        Err(e) => self.fail_ret_host(env, e),
                    },
                    Err(e) => self.fail_ret(env, e),
                }
            }
            // ustat=62（dev 番号は使わない。arg1 のバッファだけを埋める）
            62 => ret(self.do_ustat(env, args[1])),
            // statfs=99, fstatfs=100（68B）、statfs64=255, fstatfs64=256（92B）
            99 | 100 => ret(self.do_statfs(env, args[1], FsLayout::Short)),
            255 | 256 => ret(self.do_statfs(env, args[1], FsLayout::W64)),
            // socketcall=102 と o32 の直番号（4168–4184=168–184、accept4=4334=334）。
            102 | 168..=184 | 334 => {
                let Some(name) = mips_o32::name(4000 + n) else {
                    return self.fail_ret(env, mips::errno::ENOSYS);
                };
                self.sock_call(env, name, &args)
            }
            // stat=106, lstat=107, fstat=108
            106 | 107 => {
                let path = args[0];
                let out = args[1];
                ret(self.do_stat(env, None, path, out, false, n == 107))
            }
            108 => {
                let fd = args[0] as u32;
                let out = args[1];
                ret(self.do_stat(env, Some(fd), 0, out, false, false))
            }
            // stat64=213, lstat64=214, fstat64=215, fstatat64=293
            213 | 214 => {
                let path = args[0];
                let out = args[1];
                ret(self.do_stat(env, None, path, out, true, n == 214))
            }
            215 => {
                let fd = args[0] as u32;
                let out = args[1];
                ret(self.do_stat(env, Some(fd), 0, out, true, false))
            }
            293 => {
                let dirfd = args[0] as u32;
                if dirfd as i32 != -100 {
                    return self.fail_ret(env, mips::errno::EBADF);
                }
                ret(self.do_stat(env, None, args[1], args[2], true, false))
            }
            // lookup_dcookie=247
            // getdents=141（旧 getdents。d_reclen の形式が違う。getdents64 に回す）
            141 => self.fail_ret(env, mips::errno::ENOSYS),
            // _newselect=142, poll=188, ppoll=302
            142 | 188 | 302 => ret(Self::ret(env, 0)),
            // flock=143
            143 => ret(Self::ret(env, 0)),
            // readv=145, writev=146
            145 => {
                let fd = args[0] as u32;
                ret(self.do_readv(env, fd, args[1], args[2]))
            }
            146 => {
                let fd = args[0] as u32;
                ret(self.do_writev(env, fd, args[1], args[2]))
            }
            // cacheflush=147, cachectl=148, sysmips=149
            147 | 148 => ret(Self::ret(env, 0)),
            149 => ret(Self::ret(env, 0)),
            // getsid=151 handled, fdatasync=152 handled
            // nanosleep=166, clock_nanosleep=265
            166 => {
                let rq = args[0];
                let _rm = args[1];
                let _ = rq;
                ret(Self::ret(env, 0))
            }
            265 => ret(Self::ret(env, 0)),
            // mremap=167
            167 => self.fail_ret(env, mips::errno::ENOMEM),
            // sched_yield=162
            162 => ret(Self::ret(env, 0)),
            // getcpu=312
            312 => {
                let cpu = args[0];
                let node = args[1];
                if cpu != 0 {
                    let _ = self.put::<U32x>(env, cpu, U32x(0));
                }
                if node != 0 {
                    let _ = self.put::<U32x>(env, node, U32x(0));
                }
                ret(Self::ret(env, 0))
            }
            // waitid=278 → ENOSYS 系の扱いは上で済む
            // personality=136
            136 => ret(Self::ret(env, 0)),
            // getrlimit=76 handled, poll=188 handled
            // sigreturn=?
            // rt_sigaction=194, rt_sigprocmask=195, rt_sigpending=196,
            // rt_sigtimedwait=197, rt_sigqueueinfo=198, rt_sigsuspend=199
            194 => {
                // sig は MIPS 番号。ハンドラの記録だけ行う。
                let _signo = args[0];
                let _act = args[1];
                let old = args[2];
                if old != 0 {
                    // kernel sigaction は 24B（handler,flags,mask,restorer）
                    let mut z = [0u8; 24];
                    z[0..4].copy_from_slice(&[0; 4]);
                    let _ = self.write_bytes(env, old, &z);
                }
                ret(Self::ret(env, 0))
            }
            195 => ret(Self::ret(env, 0)),
            196 => {
                let set = args[0];
                if set != 0 {
                    let _ = self.write_bytes(env, set, &[0u8; 16]);
                }
                ret(Self::ret(env, 0))
            }
            197 => self.fail_ret(env, mips::errno::EINTR),
            198 | 332 => ret(Self::ret(env, 0)),
            199 => ret(Self::ret(env, 0)),
            // pread64=200, pwrite64=201
            200 => {
                let fd = args[0] as u32;
                let buf = args[1];
                let len = args[2];
                // o32: pos は a3 にパッドを挟み、スタックの二語（sp+16/sp+20）。
                let pos = self.a64(&args, 4);
                ret(self.do_pread(env, fd, buf, len, pos))
            }
            201 => {
                let fd = args[0] as u32;
                let buf = args[1];
                let len = args[2];
                // o32: pos は a3 にパッドを挟み、スタックの二語（sp+16/sp+20）。
                let pos = self.a64(&args, 4);
                ret(self.do_pwrite(env, fd, buf, len, pos))
            }
            // getcwd=203
            203 => {
                let buf = args[0];
                let len = args[1];
                let cwd = if self.cwd.is_empty() {
                    std::env::current_dir()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_else(|_| "/".to_string())
                } else {
                    self.cwd.clone()
                };
                if cwd.len() + 1 > len as usize {
                    return self.fail_ret(env, mips::errno::ERANGE);
                }
                match self.write_bytes(env, buf, cwd.as_bytes()) {
                    Ok(()) => {
                        let _ = self.write_bytes(env, buf + cwd.len() as u64, &[0]);
                        ret(Self::ret(env, cwd.len() as u64 + 1))
                    }
                    Err(e) => self.fail_ret(env, e),
                }
            }
            // sendfile=207, sendfile64=237
            207 | 237 => {
                ret(self.do_sendfile(env, args[0] as u32, args[1] as u32, args[2], args[3]))
            }
            // mmap2=210
            210 => {
                let addr = args[0];
                let len = args[1];
                let prot = args[2];
                let flags = args[3];
                let _fd = args[4] as u32;
                let _pgoff = args[5];
                if flags & u64::from(mips::mflag::ANONYMOUS) == 0 {
                    return self.fail_ret(env, mips::errno::ENODEV);
                }
                ret(self.do_mmap(env, addr, len, prot, flags))
            }
            // stat64 213-215 handled, fcntl64=220 handled, gettid=222 handled
            // fadvise64=223? o32 216? fadvise64=254?
            // uname=122
            122 => ret(self.do_uname(env, args[0])),
            // set_thread_area=283
            283 => {
                let addr = args[0];
                env.backend.set(sem::hwr_ref(3), addr);
                ret(Self::ret(env, 0))
            }
            // getdents64=219
            219 => {
                let fd = args[0] as u32;
                ret(self.do_getdents64(env, fd, args[1], args[2]))
            }
            // set_tid_address=252
            252 => ret(Self::ret(env, self.pid())),
            // clock_gettime=263, clock_settime=262, clock_gettime64=403
            263 | 403 => {
                let clk = args[0];
                let tp = args[1];
                let (sec, nsec) = if clk == 1 {
                    let us = self.mono_us();
                    (us / 1_000_000, (us % 1_000_000) * 1000)
                } else {
                    let (s, u) = Self::now();
                    (s, u * 1000)
                };
                if tp != 0 && !self.put_timespec(env, tp, sec, nsec) {
                    return self.fail_ret(env, mips::errno::EFAULT);
                }
                ret(Self::ret(env, 0))
            }
            262 => ret(Self::ret(env, 0)),
            // tgkill=266 handled, utimes=267 handled
            // statx=366
            366 => {
                let dirfd = args[0] as u32;
                if dirfd as i32 != -100 {
                    return self.fail_ret(env, mips::errno::EBADF);
                }
                // statx 構造体は 256B。statx_timestamp 等の配置は asm-generic と同じ。
                ret(self.do_statx(env, args[1], args[4]))
            }
            // rseq=367, set_robust_list=309, prctl=192, membarrier=358
            367 => {
                if args[3] != 0 {
                    return self.fail_ret(env, mips::errno::EINVAL);
                }
                ret(Self::ret(env, 0))
            }
            309 => ret(Self::ret(env, 0)),
            192 => {
                let opt = args[0] as u32;
                // PR_SET_NAME=15 は成功、PR_GET_NAME=16 は名前を返す
                match opt {
                    15 => ret(Self::ret(env, 0)),
                    16 => {
                        let _ = self.write_bytes(env, args[1], b"polyisa\0");
                        ret(Self::ret(env, 0))
                    }
                    _ => ret(Self::ret(env, 0)),
                }
            }
            358 => ret(Self::ret(env, 0)),
            // getrandom=353
            353 => ret(self.do_getrandom(env, args[0], args[1])),
            // memfd_create=354? secret=, fchmodat2=452
            354 => self.fail_ret(env, mips::errno::ENOSYS),
            // sched_getaffinity=240, sched_setaffinity=239
            240 => {
                let set = args[2];
                if set != 0 {
                    let _ = self.write_bytes(env, set, &[1u8]);
                }
                ret(Self::ret(env, 0))
            }
            239 => ret(Self::ret(env, 0)),
            // openat2=437
            437 => self.fail_ret(env, mips::errno::ENOSYS),
            // getgid=47 handled, setgroups=81 handled
            _ => Disp::Unimpl,
        }
    }

    /// n32/n64 の番号（各基準からの通し番号）。asm-generic に近いが番号体系は
    /// MIPS 固有で、名前で振り分ける。
    fn dispatch_64(&mut self, env: &mut BareEnv, _off: u64, name: Option<&'static str>) -> Disp {
        let args: [u64; 8] = std::array::from_fn(|i| self.arg(env, i));
        let Some(name) = name else {
            return Disp::Unimpl;
        };
        if crate::sock::NAMES.contains(&name) {
            return self.sock_call(env, name, &args);
        }
        match name {
            "exit" | "exit_group" => Disp::Exit((args[0] & 0xff) as u32),
            "read" => {
                let fd = args[0] as u32;
                ret(self.do_read(env, fd, args[1], args[2]))
            }
            "write" => {
                let fd = args[0] as u32;
                ret(self.do_write(env, fd, args[1], args[2]))
            }
            "open" => ret(self.do_open(env, args[0], args[1] as u32, args[2] as u32)),
            "openat" => {
                let dirfd = args[0] as u32;
                if dirfd as i32 != -100 {
                    return self.fail_ret(env, mips::errno::EBADF);
                }
                ret(self.do_open(env, args[1], args[2] as u32, args[3] as u32))
            }
            "close" => {
                let fd = args[0] as u32;
                if fd < 3 {
                    return ret(Self::ret(env, 0));
                }
                if self.fds.ent(fd).is_some() {
                    self.fds.clear(fd);
                    self.dir_pos.remove(&fd);
                    ret(Self::ret(env, 0))
                } else {
                    self.fail_ret(env, mips::errno::EBADF)
                }
            }
            "stat" | "lstat" => {
                ret(self.do_stat(env, None, args[0], args[1], true, name == "lstat"))
            }
            "fstat" => {
                let fd = args[0] as u32;
                ret(self.do_stat(env, Some(fd), 0, args[1], true, false))
            }
            "newfstatat" | "fstatat64" => {
                let dirfd = args[0] as u32;
                if dirfd as i32 != -100 {
                    return self.fail_ret(env, mips::errno::EBADF);
                }
                ret(self.do_stat(env, None, args[1], args[2], true, false))
            }
            "statx" => {
                let dirfd = args[0] as u32;
                if dirfd as i32 != -100 {
                    return self.fail_ret(env, mips::errno::EBADF);
                }
                ret(self.do_statx(env, args[1], args[4]))
            }
            "poll" | "ppoll" | "_newselect" | "pselect6" => ret(Self::ret(env, 0)),
            "lseek" => {
                let fd = args[0] as u32;
                let off = args[1] as i64;
                let wh = args[2] as u32;
                ret(self.do_lseek(env, fd, off, wh))
            }
            "mmap" => {
                let flags = args[3];
                if flags & u64::from(mips::mflag::ANONYMOUS) == 0 {
                    return self.fail_ret(env, mips::errno::ENODEV);
                }
                ret(self.do_mmap(env, args[0], args[1], args[2], flags))
            }
            "munmap" => {
                let addr = args[0];
                let len = args[1].max(1);
                env.backend
                    .mem
                    .unmap(VirtAddr(addr), len.div_ceil(polyisa_mem::PAGE_SIZE));
                ret(Self::ret(env, 0))
            }
            "mprotect" => ret(Self::ret(env, 0)),
            "brk" => ret(self.do_brk(env, args[0])),
            "rt_sigaction" => ret(Self::ret(env, 0)),
            "rt_sigprocmask" => ret(Self::ret(env, 0)),
            "rt_sigpending" => {
                let set = args[0];
                if set != 0 {
                    let _ = self.write_bytes(env, set, &[0u8; 16]);
                }
                ret(Self::ret(env, 0))
            }
            "rt_sigtimedwait" => self.fail_ret(env, mips::errno::EINTR),
            "rt_sigqueueinfo" | "rt_tgsigqueueinfo" => ret(Self::ret(env, 0)),
            "rt_sigsuspend" => ret(Self::ret(env, 0)),
            "ioctl" => {
                let fd = args[0] as u32;
                ret(self.do_ioctl(env, fd, args[1], args[2]))
            }
            "pread64" => {
                let fd = args[0] as u32;
                ret(self.do_pread(env, fd, args[1], args[2], self.a64(&args, 3)))
            }
            "pwrite64" => {
                let fd = args[0] as u32;
                ret(self.do_pwrite(env, fd, args[1], args[2], self.a64(&args, 3)))
            }
            "readv" => {
                let fd = args[0] as u32;
                ret(self.do_readv(env, fd, args[1], args[2]))
            }
            "writev" => {
                let fd = args[0] as u32;
                ret(self.do_writev(env, fd, args[1], args[2]))
            }
            "access" => self.unimpl_path1(env),
            "faccessat" | "faccessat2" => {
                let dirfd = args[0] as u32;
                if dirfd as i32 != -100 {
                    return self.fail_ret(env, mips::errno::EBADF);
                }
                self.unimpl_path1_at(env, 1)
            }
            "pipe" | "pipe2" => self.fail_ret(env, mips::errno::ENOSYS),
            "dup" => {
                let fd = args[0] as u32;
                match self.dup_fd(fd, 3) {
                    Ok(n) => ret(Self::ret(env, n)),
                    Err(e) => self.fail_ret(env, e),
                }
            }
            "dup2" | "dup3" => {
                let old = args[0] as u32;
                let new = args[1] as u32;
                match self.dup2_fd(old, new) {
                    Ok(()) => ret(Self::ret(env, u64::from(new))),
                    Err(e) => self.fail_ret(env, e),
                }
            }
            "sched_yield" => ret(Self::ret(env, 0)),
            "mremap" => self.fail_ret(env, mips::errno::ENOMEM),
            "msync" | "mincore" | "madvise" => ret(Self::ret(env, 0)),
            "shmget" | "shmat" | "shmctl" => self.fail_ret(env, mips::errno::ENOSYS),
            "getpid" | "gettid" | "getppid" | "getpgid" | "getsid" | "setpgid" | "setsid" => {
                ret(Self::ret(env, self.pid()))
            }
            "fork" | "vfork" | "clone" | "execve" | "wait4" | "waitid" | "waitpid" => {
                self.fail_ret(env, mips::errno::ENOSYS)
            }
            "kill" | "tkill" | "tgkill" => ret(Self::ret(env, 0)),
            "uname" => ret(self.do_uname(env, args[0])),
            "fcntl" | "fcntl64" => {
                let fd = args[0] as u32;
                ret(self.do_fcntl(env, fd, args[1] as u32, args[2]))
            }
            "flock" | "fsync" | "fdatasync" | "sync" | "sync_file_range" => {
                if name != "sync"
                    && let Some(f) = self.fds.file(args[0] as u32)
                {
                    let _ = f.sync_all();
                }
                ret(Self::ret(env, 0))
            }
            "truncate" | "ftruncate" | "truncate64" | "ftruncate64" => {
                if name.starts_with('f') {
                    let fd = args[0] as u32;
                    let len = self.a64(&args, 1);
                    match self.file_of(fd) {
                        Ok(f) => match f.set_len(len) {
                            Ok(()) => ret(Self::ret(env, 0)),
                            Err(e) => self.fail_ret_host(env, e),
                        },
                        Err(e) => self.fail_ret(env, e),
                    }
                } else {
                    let __a0 = args[0];
                    let path = match self.read_cstr(env, __a0) {
                        Ok(p) => p,
                        Err(e) => return self.fail_ret(env, e),
                    };
                    let len = self.a64(&args, 1);
                    match std::fs::OpenOptions::new()
                        .write(true)
                        .open(self.host_path(&path))
                        .and_then(|f| f.set_len(len))
                    {
                        Ok(()) => ret(Self::ret(env, 0)),
                        Err(e) => self.fail_ret_host(env, e),
                    }
                }
            }
            "getdents" | "getdents64" => {
                let fd = args[0] as u32;
                ret(self.do_getdents64(env, fd, args[1], args[2]))
            }
            "getcwd" => {
                let buf = args[0];
                let len = args[1];
                let cwd = if self.cwd.is_empty() {
                    std::env::current_dir()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_else(|_| "/".to_string())
                } else {
                    self.cwd.clone()
                };
                if cwd.len() + 1 > len as usize {
                    return self.fail_ret(env, mips::errno::ERANGE);
                }
                match self.write_bytes(env, buf, cwd.as_bytes()) {
                    Ok(()) => {
                        let _ = self.write_bytes(env, buf + cwd.len() as u64, &[0]);
                        ret(Self::ret(env, cwd.len() as u64 + 1))
                    }
                    Err(e) => self.fail_ret(env, e),
                }
            }
            "chdir" => {
                let __a0 = args[0];
                let path = match self.read_cstr(env, __a0) {
                    Ok(p) => p,
                    Err(e) => return self.fail_ret(env, e),
                };
                let host = self.host_path(&path);
                if polyisa_host::stat(&host)
                    .map(|m| m.mode & 0o170000 == 0o040000)
                    .unwrap_or(false)
                {
                    self.cwd = host;
                    ret(Self::ret(env, 0))
                } else {
                    self.fail_ret(env, mips::errno::ENOENT)
                }
            }
            "fchdir" => ret(Self::ret(env, 0)),
            "rename" | "renameat" | "renameat2" | "link" | "linkat" | "unlink" | "unlinkat"
            | "symlink" | "symlinkat" => self.unimpl_path2(env),
            "mkdir" | "mkdirat" => {
                let idx = if name == "mkdir" { 0 } else { 1 };
                let __ai = self.arg(env, idx);
                let path = match self.read_cstr(env, __ai) {
                    Ok(p) => p,
                    Err(e) => return self.fail_ret(env, e),
                };
                match std::fs::create_dir(self.host_path(&path)) {
                    Ok(()) => ret(Self::ret(env, 0)),
                    Err(e) => self.fail_ret_host(env, e),
                }
            }
            "rmdir" => self.unimpl_path1(env),
            "creat" => {
                let flags = mips::oflag::CREAT | mips::oflag::TRUNC | 1;
                ret(self.do_open(env, args[0], flags, args[1] as u32))
            }
            "readlink" => ret(self.do_readlink(env, args[0], args[1], args[2])),
            "readlinkat" => {
                let dirfd = args[0] as u32;
                if dirfd as i32 != -100 {
                    return self.fail_ret(env, mips::errno::EBADF);
                }
                ret(self.do_readlink(env, args[1], args[2], args[3]))
            }
            "umask" => {
                let old = self.umask;
                self.umask = args[0] as u32 & 0o777;
                ret(Self::ret(env, u64::from(old)))
            }
            "gettimeofday" | "settimeofday" | "utime" | "utimes" | "utimensat" | "times"
            | "getrusage" | "sysinfo" => {
                if name == "sysinfo" {
                    ret(self.do_sysinfo(env, args[0]))
                } else if name == "gettimeofday" {
                    let tv = args[0];
                    let tz = args[1];
                    let (sec, usec) = Self::now();
                    if tv != 0
                        && (!self.put_u(env, tv, sec)
                            || !self.put_u(env, tv + self.abi.ptr_bits() as u64 / 8, usec))
                    {
                        return self.fail_ret(env, mips::errno::EFAULT);
                    }
                    if tz != 0 {
                        let _ = self.put::<U32x>(env, tz, U32x(0));
                        let _ = self.put::<U32x>(env, tz + 4, U32x(0));
                    }
                    ret(Self::ret(env, 0))
                } else {
                    ret(Self::ret(env, 0))
                }
            }
            "nanosleep" | "clock_nanosleep" => ret(Self::ret(env, 0)),
            "clock_gettime" | "clock_gettime64" => {
                let clk = args[0];
                let tp = args[1];
                let (sec, nsec) = if clk == 1 {
                    let us = self.mono_us();
                    (us / 1_000_000, (us % 1_000_000) * 1000)
                } else {
                    let (s, u) = Self::now();
                    (s, u * 1000)
                };
                if tp != 0 && !self.put_timespec(env, tp, sec, nsec) {
                    return self.fail_ret(env, mips::errno::EFAULT);
                }
                ret(Self::ret(env, 0))
            }
            "clock_settime" => ret(Self::ret(env, 0)),
            "getuid" | "geteuid" | "getgid" | "getegid" | "getgroups" | "setgroups" | "setuid"
            | "setgid" => ret(Self::ret(env, 0)),
            "gethostname" | "sethostname" => ret(Self::ret(env, 0)),
            "getrlimit" | "setrlimit" | "prlimit64" => {
                let p = if name == "prlimit64" {
                    args[3]
                } else {
                    args[1]
                };
                if p != 0 {
                    let _ = self.put::<U64x>(env, p, U64x(u64::MAX));
                    let _ = self.put::<U64x>(env, p + 8, U64x(u64::MAX));
                }
                ret(Self::ret(env, 0))
            }
            "ptrace" => self.fail_ret(env, mips::errno::EPERM),
            "getcpu" | "sched_getaffinity" | "sched_setaffinity" => {
                if name == "sched_getaffinity" {
                    let set = args[2];
                    if set != 0 {
                        let _ = self.write_bytes(env, set, &[1u8]);
                    }
                } else if name == "getcpu" {
                    let cpu = args[0];
                    let node = args[1];
                    if cpu != 0 {
                        let _ = self.put::<U32x>(env, cpu, U32x(0));
                    }
                    if node != 0 {
                        let _ = self.put::<U32x>(env, node, U32x(0));
                    }
                }
                ret(Self::ret(env, 0))
            }
            "getrandom" => ret(self.do_getrandom(env, args[0], args[1])),
            "set_tid_address" => ret(Self::ret(env, self.pid())),
            "set_robust_list" | "rseq" | "membarrier" => ret(Self::ret(env, 0)),
            "set_thread_area" => {
                if std::env::var_os("POLYISA_MIPS_TRACE").is_some() {
                    eprintln!("set_thread_area arg={:#x}", args[0]);
                }
                env.backend.set(sem::hwr_ref(3), args[0]);
                ret(Self::ret(env, 0))
            }
            "cacheflush" | "cachectl" | "sysmips" => ret(Self::ret(env, 0)),
            "ustat" => ret(self.do_ustat(env, args[1])),
            "statfs" | "fstatfs" => {
                // n64 は 128B の long 形式、n32 は 68B の u32 形式。
                let layout = match self.abi {
                    Abi::N64 => FsLayout::Full,
                    _ => FsLayout::Short,
                };
                ret(self.do_statfs(env, args[1], layout))
            }
            "statfs64" | "fstatfs64" => ret(self.do_statfs(env, args[1], FsLayout::W64)),
            "sendfile" | "sendfile64" => {
                ret(self.do_sendfile(env, args[0] as u32, args[1] as u32, args[2], args[3]))
            }
            "personality" | "prctl" | "acct" | "mount" | "umount" | "umount2" | "pivot_root"
            | "reboot" | "swapon" | "swapoff" | "quotactl" | "quotactl_fd" | "capget"
            | "capset" | "sigaltstack" | "syslog" | "init_module" | "delete_module"
            | "ioprio_set" | "ioprio_get" => ret(Self::ret(env, 0)),
            _ => Disp::Unimpl,
        }
    }

    fn do_pread(&mut self, env: &mut BareEnv, fd: u32, buf: u64, len: u64, pos: u64) -> u64 {
        let data_len = len.min(1 << 20) as usize;
        match self.reader(fd) {
            Ok(ReadFd::File(f)) => {
                let mut chunk = vec![0u8; data_len];
                match polyisa_host::pread(f, &mut chunk, pos) {
                    Ok(n) => match self.write_bytes(env, buf, &chunk[..n]) {
                        Ok(()) => Self::ret(env, n as u64),
                        Err(e) => self.fail(env, e),
                    },
                    Err(e) => {
                        self.fail_host(env, e.raw_os_error().unwrap_or(mips::errno::EIO as i32))
                    }
                }
            }
            Ok(ReadFd::Stdin) => self.fail(env, mips::errno::ESPIPE),
            Err(e) => self.fail(env, e),
        }
    }

    fn do_pwrite(&mut self, env: &mut BareEnv, fd: u32, buf: u64, len: u64, pos: u64) -> u64 {
        let data = match self.read_bytes(env, buf, len as usize) {
            Ok(d) => d,
            Err(e) => return self.fail(env, e),
        };
        match self.writer(fd) {
            Ok(WriteFd::File(f)) => match polyisa_host::pwrite(f, &data, pos) {
                Ok(n) => Self::ret(env, n as u64),
                Err(e) => self.fail_host(env, e.raw_os_error().unwrap_or(mips::errno::EIO as i32)),
            },
            Ok(_) => self.fail(env, mips::errno::ESPIPE),
            Err(e) => self.fail(env, e),
        }
    }

    /// `statx`（asm-generic と同じ 256B 構造）。
    fn do_statx(&mut self, env: &mut BareEnv, path_addr: u64, out: u64) -> u64 {
        let path = match self.read_cstr(env, path_addr) {
            Ok(p) => p,
            Err(e) => return self.fail(env, e),
        };
        let md = match polyisa_host::stat(&self.host_path(&path)) {
            Ok(m) => m,
            Err(e) => {
                return self.fail_host(env, e.raw_os_error().unwrap_or(mips::errno::EIO as i32));
            }
        };
        let mut b = [0u8; 256];
        let w32 = |v: u32| match self.endian {
            Endian::Be => v.to_be_bytes(),
            Endian::Le => v.to_le_bytes(),
        };
        let w64 = |v: u64| match self.endian {
            Endian::Be => v.to_be_bytes(),
            Endian::Le => v.to_le_bytes(),
        };
        b[0..4].copy_from_slice(&w32(0x1fff)); // mask = STATX_ALL
        b[4..8].copy_from_slice(&w32(4096)); // blksize
        b[8..16].copy_from_slice(&w64(0x1fff)); // attributes
        b[16..20].copy_from_slice(&w32(md.nlink as u32));
        b[20..24].copy_from_slice(&w32(md.uid));
        b[24..28].copy_from_slice(&w32(md.gid));
        b[28..32].copy_from_slice(&w32(md.mode as u16 as u32));
        b[40..48].copy_from_slice(&w64(md.ino));
        b[48..56].copy_from_slice(&w64(md.size));
        b[56..64].copy_from_slice(&w64(md.blocks));
        b[64..72].copy_from_slice(&w64(0x1fff)); // attributes_mask
        // atime/mtime/ctime/btime は sec i64 + nsec u32 + pad
        b[80..88].copy_from_slice(&w64(md.atime as u64));
        b[88..92].copy_from_slice(&w32(md.atime_nsec as u32));
        // btime はホストでは取れない。0 のまま。
        b[112..120].copy_from_slice(&w64(md.ctime as u64));
        b[120..124].copy_from_slice(&w32(md.ctime_nsec as u32));
        b[128..136].copy_from_slice(&w64(md.mtime as u64));
        b[136..140].copy_from_slice(&w32(md.mtime_nsec as u32));
        b[144..148].copy_from_slice(&w32(md.rdev as u32));
        b[152..156].copy_from_slice(&w32(md.dev as u32));
        match self.write_bytes(env, out, &b) {
            Ok(()) => Self::ret(env, 0),
            Err(e) => self.fail(env, e),
        }
    }

    /// パス一つを取る削除系。未対応のものは ENOSYS。
    fn unimpl_path1(&mut self, env: &mut BareEnv) -> Disp {
        let __a0 = self.arg(env, 0);
        let path = match self.read_cstr(env, __a0) {
            Ok(p) => p,
            Err(e) => return self.fail_ret(env, e),
        };
        let host = self.host_path(&path);
        let nr = reg(env, 2) & 0xffff_ffff;
        match self.abi.name(nr) {
            Some("unlink") | Some("rmdir") => {
                let r = if self.abi.name(nr) == Some("unlink") {
                    std::fs::remove_file(&host)
                } else {
                    std::fs::remove_dir(&host)
                };
                match r {
                    Ok(()) => ret(Self::ret(env, 0)),
                    Err(e) => self.fail_ret_host(env, e),
                }
            }
            Some("access") | Some("faccessat") => {
                let ok = polyisa_host::stat(&host).is_ok();
                ret(if ok {
                    Self::ret(env, 0)
                } else {
                    self.fail(env, mips::errno::ENOENT)
                })
            }
            _ => self.fail_ret(env, mips::errno::ENOSYS),
        }
    }

    /// dirfd + パス一つ。
    fn unimpl_path1_at(&mut self, env: &mut BareEnv, idx: usize) -> Disp {
        let __ai = self.arg(env, idx);
        let path = match self.read_cstr(env, __ai) {
            Ok(p) => p,
            Err(e) => return self.fail_ret(env, e),
        };
        let host = self.host_path(&path);
        let nr = reg(env, 2) & 0xffff_ffff;
        match self.abi.name(nr) {
            Some("unlinkat") => match std::fs::remove_file(&host) {
                Ok(()) => ret(Self::ret(env, 0)),
                Err(e) => self.fail_ret_host(env, e),
            },
            Some("faccessat") | Some("faccessat2") => ret(if polyisa_host::stat(&host).is_ok() {
                Self::ret(env, 0)
            } else {
                self.fail(env, mips::errno::ENOENT)
            }),
            _ => self.fail_ret(env, mips::errno::ENOSYS),
        }
    }

    /// パス二つを取る系（link/rename/symlink）。
    fn unimpl_path2(&mut self, env: &mut BareEnv) -> Disp {
        let nr = reg(env, 2) & 0xffff_ffff;
        let name = self.abi.name(nr).unwrap_or("");
        let (a_idx, b_idx) = match name {
            "link" | "rename" | "symlink" => (0, 1),
            "linkat" | "renameat" | "symlinkat" => (1, 3),
            "renameat2" => (1, 3),
            _ => return self.fail_ret(env, mips::errno::ENOSYS),
        };
        let __aa = self.arg(env, a_idx);
        let pa = match self.read_cstr(env, __aa) {
            Ok(p) => p,
            Err(e) => return self.fail_ret(env, e),
        };
        let __ab = self.arg(env, b_idx);
        let pb = match self.read_cstr(env, __ab) {
            Ok(p) => p,
            Err(e) => return self.fail_ret(env, e),
        };
        let (ha, hb) = (self.host_path(&pa), self.host_path(&pb));
        let r = match name {
            "link" | "linkat" => std::fs::hard_link(&ha, &hb),
            "rename" | "renameat" | "renameat2" => std::fs::rename(&ha, &hb),
            "symlink" | "symlinkat" => polyisa_host::symlink(&String::from_utf8_lossy(&pa), &hb),
            _ => return self.fail_ret(env, mips::errno::ENOSYS),
        };
        match r {
            Ok(()) => ret(Self::ret(env, 0)),
            Err(e) => self.fail_ret_host(env, e),
        }
    }

    /// fd の複製（dup/dup2/dup3）。FdTable が保持する File を複製する。
    fn dup_fd(&mut self, old: u32, _min: u32) -> Result<u64, u32> {
        let f = self
            .fds
            .file(old)
            .and_then(|f| f.try_clone().ok())
            .ok_or(mips::errno::EBADF)?;
        let n = self.fds.alloc(polyisa_kernel::FdTarget::File(f));
        Ok(u64::from(n))
    }

    fn dup2_fd(&mut self, old: u32, new: u32) -> Result<(), u32> {
        let f = self
            .fds
            .file(old)
            .and_then(|f| f.try_clone().ok())
            .ok_or(mips::errno::EBADF)?;
        self.fds.place_close(new, polyisa_kernel::FdTarget::File(f));
        Ok(())
    }

    fn fail_ret(&self, env: &mut BareEnv, errno: u32) -> Disp {
        Disp::Ret(self.fail(env, errno))
    }

    fn fail_ret_host(&self, env: &mut BareEnv, e: std::io::Error) -> Disp {
        Disp::Ret(self.fail_host(env, e.raw_os_error().unwrap_or(mips::errno::EIO as i32)))
    }

    /// 現在時刻（sec, usec）。
    fn now() -> (u64, u64) {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| (d.as_secs(), u64::from(d.subsec_micros())))
            .unwrap_or((0, 0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> BareEnv {
        BareEnv::new(core::mem::size_of::<polyisa_guest_mips::CpuState>())
    }

    fn set_reg(env: &mut BareEnv, i: u8, v: u64) {
        super::set_reg(env, i, v);
    }

    fn map(env: &mut BareEnv, addr: u64, pages: u64) {
        env.backend
            .mem
            .map(VirtAddr(addr), pages, Perms::RW)
            .unwrap();
    }

    fn acc() -> Access {
        Access {
            endian: Endian::Le,
            align: Align::Unaligned,
            kind: AccessKind::DataRead,
        }
    }

    fn put32(env: &mut BareEnv, addr: u64, v: u32) {
        env.backend
            .mem
            .write(VirtAddr(addr), &v.to_le_bytes())
            .unwrap();
    }

    fn tmpfile(data: &[u8]) -> std::path::PathBuf {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "polyisa-mips-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::write(&p, data).unwrap();
        p
    }

    /// o32 の pread64 は 64 ビット引数がスタックの語対（a3 はパッド）。
    /// sp+16/sp+20 を読み、a3 をパッドとして扱う回帰。
    #[test]
    fn o32_pread64_reads_offset_from_stack() {
        let p = tmpfile(b"0123456789abcdef");
        let mut sys = Linux::o32(Endian::Le);
        let mut env = env();
        let fd = sys.fds.alloc(polyisa_kernel::FdTarget::File(
            std::fs::File::open(&p).unwrap(),
        ));
        map(&mut env, 0x5000, 1); // buf
        map(&mut env, 0x9000, 1); // スタック
        set_reg(&mut env, 29, 0x9000);
        put32(&mut env, 0x9010, 6); // pos_lo
        put32(&mut env, 0x9014, 0); // pos_hi
        set_reg(&mut env, 2, 4200);
        set_reg(&mut env, 4, u64::from(fd));
        set_reg(&mut env, 5, 0x5000);
        set_reg(&mut env, 6, 8);
        set_reg(&mut env, 7, 0xdead_beef); // a3 = パッド（値は読まない）
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(reg(&mut env, 7), 0, "成功は a3=0");
        assert_eq!(reg(&mut env, 2), 8);
        let mut out = [0u8; 8];
        env.backend
            .mem
            .read(VirtAddr(0x5000), &mut out, acc())
            .unwrap();
        assert_eq!(&out, b"6789abcd");
    }

    /// o32 の truncate64 は長さが奇数位置なので a1 にパッド、a2/a3 の語対。
    #[test]
    fn o32_truncate64_uses_aligned_pair() {
        let p = tmpfile(b"0123456789abcdef");
        let mut sys = Linux::o32(Endian::Le);
        let mut env = env();
        map(&mut env, 0x6000, 1);
        let s = p.to_str().unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x6000), s.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x6000 + s.len() as u64), &[0])
            .unwrap();
        set_reg(&mut env, 2, 4211);
        set_reg(&mut env, 4, 0x6000);
        set_reg(&mut env, 5, 0); // a1 = パッド
        set_reg(&mut env, 6, 7); // len_lo
        set_reg(&mut env, 7, 0); // len_hi
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(reg(&mut env, 7), 0);
        assert_eq!(std::fs::metadata(&p).unwrap().len(), 7);
    }

    /// n64/n32 の pread64 は pos を一本のレジスタ（a3）で受ける。
    #[test]
    fn n64_pread64_single_word_offset() {
        let p = tmpfile(b"0123456789abcdef");
        let mut sys = Linux::n64(Endian::Le);
        let mut env = env();
        let fd = sys.fds.alloc(polyisa_kernel::FdTarget::File(
            std::fs::File::open(&p).unwrap(),
        ));
        map(&mut env, 0x5000, 1);
        set_reg(&mut env, 2, 5016);
        set_reg(&mut env, 4, u64::from(fd));
        set_reg(&mut env, 5, 0x5000);
        set_reg(&mut env, 6, 8);
        set_reg(&mut env, 7, 6); // pos
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(reg(&mut env, 7), 0);
        assert_eq!(reg(&mut env, 2), 8);
        let mut out = [0u8; 8];
        env.backend
            .mem
            .read(VirtAddr(0x5000), &mut out, acc())
            .unwrap();
        assert_eq!(&out, b"6789abcd");
    }

    /// o32 の mmap=90 は fd/offset をスタック引数（sp+16/sp+20）で受ける。
    #[test]
    fn o32_mmap_takes_stack_args() {
        let mut sys = Linux::o32(Endian::Le);
        let mut env = env();
        sys.init_brk(0x1_0000);
        map(&mut env, 0x9000, 1);
        set_reg(&mut env, 29, 0x9000);
        put32(&mut env, 0x9010, 0xffff_ffff); // fd
        put32(&mut env, 0x9014, 0); // offset
        set_reg(&mut env, 2, 4090);
        set_reg(&mut env, 4, 0);
        set_reg(&mut env, 5, 0x1000);
        set_reg(&mut env, 6, 3); // R|W
        set_reg(
            &mut env,
            7,
            u64::from(mips::mflag::PRIVATE | mips::mflag::ANONYMOUS),
        );
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(reg(&mut env, 7), 0, "無名 mmap は成功");
        assert_ne!(reg(&mut env, 2), 0);
        // ファイル写像は ENODEV（スタックの fd を読む経路に入る）。
        set_reg(&mut env, 2, 4090);
        set_reg(&mut env, 7, u64::from(mips::mflag::PRIVATE));
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(reg(&mut env, 7), 1);
        assert_eq!(reg(&mut env, 2), u64::from(mips::errno::ENODEV));
    }

    /// statfs 系のレイアウト。o32 statfs=68B、statfs64=92B、n64 statfs=128B。
    #[test]
    fn statfs_layouts() {
        let mut sys = Linux::o32(Endian::Le);
        let mut env = env();
        map(&mut env, 0x5000, 1);
        // o32 statfs（68B）: namelen は offset 40。
        assert_eq!(sys.do_statfs(&mut env, 0x5000, FsLayout::Short), 0);
        let mut b = [0u8; 68];
        env.backend
            .mem
            .read(VirtAddr(0x5000), &mut b, acc())
            .unwrap();
        assert_eq!(u32::from_le_bytes(b[0..4].try_into().unwrap()), 0xEF53);
        assert_eq!(u32::from_le_bytes(b[4..8].try_into().unwrap()), 4096);
        assert_eq!(u32::from_le_bytes(b[8..12].try_into().unwrap()), 4096);
        assert_eq!(u32::from_le_bytes(b[40..44].try_into().unwrap()), 255);
        // statfs64（92B）: pad の後ろに u64 群、namelen は offset 64。
        assert_eq!(sys.do_statfs(&mut env, 0x5000, FsLayout::W64), 0);
        let mut b = [0u8; 92];
        env.backend
            .mem
            .read(VirtAddr(0x5000), &mut b, acc())
            .unwrap();
        assert_eq!(u32::from_le_bytes(b[0..4].try_into().unwrap()), 0xEF53);
        assert_eq!(u64::from_le_bytes(b[16..24].try_into().unwrap()), 1 << 22);
        assert_eq!(u32::from_le_bytes(b[64..68].try_into().unwrap()), 255);
        // n64（128B）: namelen は offset 72。
        let mut sys64 = Linux::n64(Endian::Le);
        assert_eq!(sys64.do_statfs(&mut env, 0x5000, FsLayout::Full), 0);
        let mut b = [0u8; 128];
        env.backend
            .mem
            .read(VirtAddr(0x5000), &mut b, acc())
            .unwrap();
        assert_eq!(u64::from_le_bytes(b[0..8].try_into().unwrap()), 0xEF53);
        assert_eq!(u64::from_le_bytes(b[72..80].try_into().unwrap()), 255);
    }

    /// iovec の要素は {base,len} の対。n64 では 1 要素 16B。
    /// ストライドを 8B と誤ると前要素の len を base として読む回帰。
    #[test]
    fn n64_readv_iovec_stride() {
        let p = tmpfile(b"0123456789abcdef");
        let mut sys = Linux::n64(Endian::Le);
        let mut env = env();
        let fd = sys.fds.alloc(polyisa_kernel::FdTarget::File(
            std::fs::File::open(&p).unwrap(),
        ));
        map(&mut env, 0x6000, 1); // iov
        map(&mut env, 0x7000, 1); // buf0
        map(&mut env, 0x8000, 1); // buf1
        let put64 = |env: &mut BareEnv, addr: u64, v: u64| {
            env.backend
                .mem
                .write(VirtAddr(addr), &v.to_le_bytes())
                .unwrap();
        };
        put64(&mut env, 0x6000, 0x7000);
        put64(&mut env, 0x6008, 4);
        put64(&mut env, 0x6010, 0x8000);
        put64(&mut env, 0x6018, 4);
        set_reg(&mut env, 2, 5018); // readv
        set_reg(&mut env, 4, u64::from(fd));
        set_reg(&mut env, 5, 0x6000);
        set_reg(&mut env, 6, 2);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(reg(&mut env, 7), 0);
        assert_eq!(reg(&mut env, 2), 8);
        let mut b = [0u8; 4];
        env.backend
            .mem
            .read(VirtAddr(0x7000), &mut b, acc())
            .unwrap();
        assert_eq!(&b, b"0123");
        env.backend
            .mem
            .read(VirtAddr(0x8000), &mut b, acc())
            .unwrap();
        assert_eq!(&b, b"4567");
    }

    /// getdents64 は呼び出しごとにディレクトリ位置を進める。
    /// 先頭から返し続けると readdir ループが終わらない。
    #[test]
    fn getdents64_advances_position() {
        let dir = std::env::temp_dir().join(format!("polyisa-dir-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a"), b"x").unwrap();
        let mut sys = Linux::o32(Endian::Le);
        let mut env = env();
        map(&mut env, 0x6000, 1);
        let s = dir.to_str().unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x6000), s.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x6000 + s.len() as u64), &[0])
            .unwrap();
        set_reg(&mut env, 2, 4005); // open
        set_reg(&mut env, 4, 0x6000);
        set_reg(&mut env, 5, 0); // O_RDONLY
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let fd = reg(&mut env, 2) as u32;
        map(&mut env, 0x8000, 1);
        let getdents = |sys: &mut Linux, env: &mut BareEnv| -> u64 {
            set_reg(env, 2, 4219);
            set_reg(env, 4, u64::from(fd));
            set_reg(env, 5, 0x8000);
            set_reg(env, 6, 0x800);
            assert!(matches!(sys.handle_trap(env, 0), TrapOutcome::Handled));
            reg(env, 2)
        };
        let n1 = getdents(&mut sys, &mut env);
        assert!(n1 > 0, "初回はエントリあり: {n1}");
        let mut n = n1;
        for _ in 0..8 {
            let k = getdents(&mut sys, &mut env);
            if k == 0 {
                break;
            }
            n += k;
        }
        assert_eq!(getdents(&mut sys, &mut env), 0, "末尾で 0 を返す");
        let _ = std::fs::remove_file(dir.join("a"));
        let _ = std::fs::remove_dir(&dir);
        let _ = n;
    }
}
