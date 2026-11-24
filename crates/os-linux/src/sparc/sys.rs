// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! SPARC Linux の syscall 処理とウィンドウの退避・復元。
//!
//! 番号は %g1、引数は %o0–%o5、戻り値は %o0。失敗は
//! キャリー flag を立て %o0 に正の errno を入れる。発行点は
//! sparc32 が `ta 0x10`（tt=0x90）、sparc64 が `ta 0x6d`
//! （tt=0x16d）。`ta 3`（tt=0x83 / V9 0x103）は flushw。
//! sem が上げるウィンドウトラップ（V8 の 0x05/0x06、V9 の
//! spill 0x80–0x9f・fill 0xc0–0xdf）は、カーネルと同じく
//! 窓の l0–i7 をその窓の %o6（%sp）が指す退避域（V9 は +2047
//! の BIAS 付き）へ書き出す・読み戻すことで再現し、PC は
//! 進めずに save/restore を再実行させる。
//! 見える %o0–%o5・%g1 の物理位置は CWP と `nwindows`・
//! `word64` パラメータから sem と同じ式で求める。
//!
//! 試作の合意事項：仮想カーネル・VFS・ゲストルートの適用は後の段階である。
//! ここではホストのファイルに直接触る。信頼できないゲストバイナリには
//! 使わないこと。fork/clone/execve/パイプは未対応（ENOSYS）。
// Ref: SRC-LINUX (7.3), SPEC-SPARC-V8 (Version 8), SPEC-SPARC-V9.

use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

use polyisa_engine::bare::BareEnv;
use polyisa_guest_sparc::{CpuState, sem};
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};
use polyisa_sem::{Backend as _, StateRef, W64};

use crate::{TrapHandler, TrapOutcome, sparc};

/// SPARC の write が集めたバイト。標準出力と標準エラーを分ける。
#[derive(Default)]
pub struct SparcIo {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// SPARC Linux の syscall 状態機械。%g1=番号、%o0–%o5=引数。
pub struct Linux {
    /// 標準入出力の capture。テストが読む。
    pub io: SparcIo,
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
    /// ユーザスタックの上端。窓退避・復帰でのフォルトを
    /// 写像の伸長で処理するために実行ループが設定する。
    /// 0 は未設定（伸長しない）。
    pub stack_top: u64,
    /// スタック成長の下限。
    pub stack_limit: u64,
}

impl Default for Linux {
    fn default() -> Self {
        Self::new()
    }
}

impl Linux {
    /// SPARC Linux の状態機械を作る。データはビッグエンディアン。
    #[must_use]
    pub fn new() -> Self {
        Self {
            io: SparcIo::default(),
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
            stack_top: 0,
            stack_limit: 0,
        }
    }

    fn pid(&mut self) -> u64 {
        if self.pid == 0 {
            self.pid = 1;
        }
        self.pid
    }

    /// 引数 `i`（0 起算）を取り出す。0–5 は %o0–%o5。
    /// 6 以降（スタック引数）は扱う syscall がないので 0 とする。
    /// 32 ビットモデルでは下位 32 ビットだけが意味を持つ。
    // Ref: SRC-LINUX (7.3) — syscall(2) の sparc 規約。
    fn arg(&mut self, env: &mut BareEnv, i: usize) -> u64 {
        if i >= 6 {
            return 0;
        }
        let v = reg(env, 8 + i as u8);
        if is_v9(env) { v } else { v & 0xffff_ffff }
    }

    /// 64 ビット引数を取り出す。sparc64 はそのまま 1 語。
    /// sparc32 は連続した 2 レジスタに上位語から入る
    /// （偶数レジスタへのそろえは行わない。pread64 の
    /// poshi/poslo は o3/o4 に入る）。
    // Ref: SRC-LINUX (7.3) — arch/sparc/kernel/sys_sparc32.c.
    fn arg64(&mut self, env: &mut BareEnv, idx: usize) -> u64 {
        if is_v9(env) {
            return self.arg(env, idx);
        }
        (self.arg(env, idx) << 32) | self.arg(env, idx + 1)
    }

    fn acc(&self, kind: AccessKind) -> Access {
        Access {
            endian: Endian::Be,
            align: Align::Unaligned,
            kind,
        }
    }

    /// ポインタ幅の語をメモリから読む（失敗は 0）。未写像なら
    /// スタック成長窓の内側に限って写像を伸ばしてもう一度試す。
    fn mem_u(&mut self, env: &mut BareEnv, addr: u64) -> u64 {
        let ws = wsize(env) as usize;
        let mut b = [0u8; 8];
        let acc = self.acc(AccessKind::DataRead);
        if env
            .backend
            .mem
            .read(VirtAddr(addr), &mut b[..ws], acc)
            .is_err()
            && !(self.grow_stack(env, addr, ws as u64)
                && env
                    .backend
                    .mem
                    .read(VirtAddr(addr), &mut b[..ws], acc)
                    .is_ok())
        {
            return 0;
        }
        if ws == 8 {
            u64::from_be_bytes(b)
        } else {
            u64::from(u32::from_be_bytes(b[..4].try_into().unwrap()))
        }
    }

    /// ポインタ幅の語をメモリに書く。未写像ならスタック成長窓の
    /// 内側に限って写像を伸ばしてもう一度試す（カーネルの
    /// copy_to_user と同じくフォルト駆動で伸びる想定）。
    fn put_u(&mut self, env: &mut BareEnv, addr: u64, v: u64) -> bool {
        let ws = wsize(env);
        let b = if ws == 8 {
            v.to_be_bytes().to_vec()
        } else {
            (v as u32).to_be_bytes().to_vec()
        };
        self.put_bytes(env, addr, &b)
    }

    /// 32 ビット値を書く。
    fn put32(&mut self, env: &mut BareEnv, addr: u64, v: u32) -> bool {
        self.put_bytes(env, addr, &v.to_be_bytes())
    }

    /// 64 ビット値を書く。
    fn put64(&mut self, env: &mut BareEnv, addr: u64, v: u64) -> bool {
        self.put_bytes(env, addr, &v.to_be_bytes())
    }

    /// 16 ビット値を書く。
    fn put16(&mut self, env: &mut BareEnv, addr: u64, v: u16) -> bool {
        self.put_bytes(env, addr, &v.to_be_bytes())
    }

    /// `put_u`/`put32`/`put64`/`put16` の共通部。
    fn put_bytes(&mut self, env: &mut BareEnv, addr: u64, data: &[u8]) -> bool {
        if env.backend.mem.write(VirtAddr(addr), data).is_ok() {
            return true;
        }
        self.grow_stack(env, addr, data.len() as u64)
            && env.backend.mem.write(VirtAddr(addr), data).is_ok()
    }

    /// C 文字列を読む。上限 4096。
    fn read_cstr(&mut self, env: &mut BareEnv, addr: u64) -> Result<Vec<u8>, u32> {
        let mut out = Vec::new();
        let acc = self.acc(AccessKind::DataRead);
        for a in (addr..).take(4096) {
            let mut b = [0u8; 1];
            if env.backend.mem.read(VirtAddr(a), &mut b, acc).is_err()
                && !(self.grow_stack(env, a, 1)
                    && env.backend.mem.read(VirtAddr(a), &mut b, acc).is_ok())
            {
                return Err(sparc::errno::EFAULT);
            }
            if b[0] == 0 {
                return Ok(out);
            }
            out.push(b[0]);
        }
        Err(sparc::errno::ENAMETOOLONG)
    }

    fn read_bytes(&mut self, env: &mut BareEnv, addr: u64, len: usize) -> Result<Vec<u8>, u32> {
        let mut buf = vec![0u8; len.min(1 << 20)];
        if buf.is_empty() {
            return Ok(buf);
        }
        let acc = self.acc(AccessKind::DataRead);
        if env.backend.mem.read(VirtAddr(addr), &mut buf, acc).is_err()
            && !(self.grow_stack(env, addr, buf.len() as u64)
                && env.backend.mem.read(VirtAddr(addr), &mut buf, acc).is_ok())
        {
            return Err(sparc::errno::EFAULT);
        }
        Ok(buf)
    }

    fn write_bytes(&mut self, env: &mut BareEnv, addr: u64, data: &[u8]) -> Result<(), u32> {
        if env.backend.mem.write(VirtAddr(addr), data).is_ok() {
            return Ok(());
        }
        if self.grow_stack(env, addr, data.len() as u64)
            && env.backend.mem.write(VirtAddr(addr), data).is_ok()
        {
            return Ok(());
        }
        Err(sparc::errno::EFAULT)
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
        self.fds.file_mut(fd).ok_or(sparc::errno::EBADF)
    }

    /// 読み用に fd を開いているものを返す。0/1/2 と FdTable の両方を見る。
    fn reader(&mut self, fd: u32) -> Result<ReadFd<'_>, u32> {
        match fd {
            0 => Ok(ReadFd::Stdin),
            1 | 2 => Err(sparc::errno::EBADF),
            _ => self
                .fds
                .file_mut(fd)
                .map(ReadFd::File)
                .ok_or(sparc::errno::EBADF),
        }
    }

    fn writer(&mut self, fd: u32) -> Result<WriteFd<'_>, u32> {
        match fd {
            0 => Err(sparc::errno::EBADF),
            1 => Ok(WriteFd::Stdout),
            2 => Ok(WriteFd::Stderr),
            _ => self
                .fds
                .file_mut(fd)
                .map(WriteFd::File)
                .ok_or(sparc::errno::EBADF),
        }
    }

    /// sparc の `O_*`（独自表）をホストの `OpenOptions` 用フラグへ写す。
    fn open_flags(guest: u32) -> std::fs::OpenOptions {
        use sparc::oflag::*;
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

    /// open/openat の共通部。`dirfd` は AT_FDCWD でなければ EBADF 相当として扱う。
    fn do_open(&mut self, env: &mut BareEnv, path_addr: u64, flags: u32, mode: u32) -> u64 {
        let path = match self.read_cstr(env, path_addr) {
            Ok(p) => p,
            Err(e) => return fail(e),
        };
        let host = self.host_path(&path);
        if trace() {
            eprintln!("  open {path:?} -> {host:?}");
        }
        let oo = Self::open_flags(flags);
        let _ = mode;
        match oo.open(&host) {
            Ok(f) => {
                let fd = self.fds.alloc(polyisa_kernel::FdTarget::File(f));
                self.fds.remember_path(fd, host);
                ret(u64::from(fd))
            }
            Err(e) => fail_host(e.raw_os_error().unwrap_or(sparc::errno::EIO as i32)),
        }
    }

    /// ホストのメタデータをゲストの stat 形に写す。レイアウトは ABI と
    /// syscall で違う。sparc32 の `stat64` 系と sparc64 の `stat` 系が
    /// 104B（中身は別形）。`statx` は `put_statx`、sparc64 の
    /// `stat64` 系は `put_kstat64`、sparc32 の `stat` 系は
    /// `put_stat32` を使う（E3 で照合）。
    /// Ref: SRC-LINUX (7.3) — arch/sparc/include/uapi/asm/stat.h.
    fn put_stat(&mut self, env: &mut BareEnv, addr: u64, md: &polyisa_host::Stat) -> bool {
        let mut ok = true;
        if is_v9(env) {
            // sparc64 struct stat（104B）:
            // 0: u32 dev, 4: pad, 8: u64 ino, 16: u32 mode,
            // 20: i16 nlink, 22: pad, 24: u32 uid, 28: u32 gid,
            // 32: u32 rdev, 36: pad, 40: i64 size, 48: i64 atime,
            // 56: i64 mtime, 64: i64 ctime, 72: i64 blksize,
            // 80: i64 blocks, 88: unused[2]
            ok &= self.put32(env, addr, md.dev as u32);
            ok &= self.put64(env, addr + 8, md.ino);
            ok &= self.put32(env, addr + 16, md.mode);
            ok &= self.put16(env, addr + 20, md.nlink as u16);
            ok &= self.put32(env, addr + 24, md.uid);
            ok &= self.put32(env, addr + 28, md.gid);
            ok &= self.put32(env, addr + 32, md.rdev as u32);
            ok &= self.put64(env, addr + 40, md.size);
            ok &= self.put64(env, addr + 48, md.atime as u64);
            ok &= self.put64(env, addr + 56, md.mtime as u64);
            ok &= self.put64(env, addr + 64, md.ctime as u64);
            ok &= self.put64(env, addr + 72, md.blksize);
            ok &= self.put64(env, addr + 80, md.blocks);
        } else {
            // sparc32 struct stat64:
            // 0: u64 dev, 8: u64 ino, 16: u32 mode, 20: u32 nlink,
            // 24: u32 uid, 28: u32 gid, 32: u64 rdev, 40: pad[8],
            // 48: i64 size, 56: u32 blksize, 60: pad[8], 68: u32 blocks,
            // 72: u32 atime, 76: u32 ansec, 80: u32 mtime, 84: u32 mnsec,
            // 88: u32 ctime, 92: u32 cnsec, 96: u32 x2
            ok &= self.put64(env, addr, md.dev);
            ok &= self.put64(env, addr + 8, md.ino);
            ok &= self.put32(env, addr + 16, md.mode);
            ok &= self.put32(env, addr + 20, md.nlink as u32);
            ok &= self.put32(env, addr + 24, md.uid);
            ok &= self.put32(env, addr + 28, md.gid);
            ok &= self.put64(env, addr + 32, md.rdev);
            ok &= self.put64(env, addr + 48, md.size);
            ok &= self.put32(env, addr + 56, md.blksize as u32);
            ok &= self.put32(env, addr + 68, md.blocks as u32);
            ok &= self.put32(env, addr + 72, md.atime as u32);
            ok &= self.put32(env, addr + 76, md.atime_nsec as u32);
            ok &= self.put32(env, addr + 80, md.mtime as u32);
            ok &= self.put32(env, addr + 84, md.mtime_nsec as u32);
            ok &= self.put32(env, addr + 88, md.ctime as u32);
            ok &= self.put32(env, addr + 92, md.ctime_nsec as u32);
        }
        ok
    }

    /// `statx`（256B）。使うフィールドだけ立てる
    /// （mask には取れた項目の合併を書く）。形は ABI 共通。
    fn put_statx(&mut self, env: &mut BareEnv, addr: u64, md: &polyisa_host::Stat) -> bool {
        // statx: 0 u32 mask, 4 u32 blksize, 8 u64 attributes,
        // 16 u32 nlink, 20 u32 uid, 24 u32 gid, 28 u16 mode, 30 u16 spare,
        // 32 u64 ino, 40 u64 size, 48 u64 blocks, 56 u64 attrs_mask,
        // 64 atime {i64 sec,i32 nsec,u32 pad}, 80 btime, 96 ctime, 112 mtime,
        // 128 u32 rdev_major, 132 u32 rdev_minor,
        // 136 u32 dev_major, 140 u32 dev_minor, 144 u64 spare[14]
        let mut ok = true;
        ok &= self.put32(env, addr, 0x0fff); // STATX_ALL 相当
        ok &= self.put32(env, addr + 4, md.blksize as u32);
        ok &= self.put32(env, addr + 16, md.nlink as u32);
        ok &= self.put32(env, addr + 20, md.uid);
        ok &= self.put32(env, addr + 24, md.gid);
        ok &= self.put16(env, addr + 28, md.mode as u16);
        ok &= self.put64(env, addr + 32, md.ino);
        ok &= self.put64(env, addr + 40, md.size);
        ok &= self.put64(env, addr + 48, md.blocks);
        ok &= self.put64(env, addr + 64, md.atime as u64);
        ok &= self.put32(env, addr + 72, md.atime_nsec as u32);
        ok &= self.put64(env, addr + 96, md.ctime as u64);
        ok &= self.put32(env, addr + 104, md.ctime_nsec as u32);
        ok &= self.put64(env, addr + 112, md.mtime as u64);
        ok &= self.put32(env, addr + 120, md.mtime_nsec as u32);
        ok
    }

    /// sparc64 の `stat64` 系 syscall が書く `struct kernel_stat64`
    /// （144B）。ユーザの `struct stat` とは別形で、glibc が
    /// `xstatconv` で変換する。
    /// Ref: SRC-LINUX (7.3) — arch/sparc/include/uapi/asm/stat.h.
    fn put_kstat64(&mut self, env: &mut BareEnv, addr: u64, md: &polyisa_host::Stat) -> bool {
        // 0: u64 dev, 8: u64 ino, 16: u64 nlink, 24: u32 mode,
        // 28: u32 uid, 32: u32 gid, 36: pad, 40: u64 rdev,
        // 48: i64 size, 56: i64 blksize, 64: i64 blocks,
        // 72/88/104: {sec,nsec} の時刻、120: unused[3]
        let mut ok = true;
        ok &= self.put64(env, addr, md.dev);
        ok &= self.put64(env, addr + 8, md.ino);
        ok &= self.put64(env, addr + 16, md.nlink);
        ok &= self.put32(env, addr + 24, md.mode);
        ok &= self.put32(env, addr + 28, md.uid);
        ok &= self.put32(env, addr + 32, md.gid);
        ok &= self.put64(env, addr + 40, md.rdev);
        ok &= self.put64(env, addr + 48, md.size);
        ok &= self.put64(env, addr + 56, md.blksize);
        ok &= self.put64(env, addr + 64, md.blocks);
        ok &= self.put64(env, addr + 72, md.atime as u64);
        ok &= self.put64(env, addr + 80, md.atime_nsec as u64);
        ok &= self.put64(env, addr + 88, md.mtime as u64);
        ok &= self.put64(env, addr + 96, md.mtime_nsec as u64);
        ok &= self.put64(env, addr + 104, md.ctime as u64);
        ok &= self.put64(env, addr + 112, md.ctime_nsec as u64);
        ok
    }

    /// sparc32 の `stat` 系 syscall が書く旧 `struct stat`（64B）。
    /// Ref: SRC-LINUX (7.3) — arch/sparc/include/uapi/asm/stat.h.
    fn put_stat32(&mut self, env: &mut BareEnv, addr: u64, md: &polyisa_host::Stat) -> bool {
        // 0: u16 dev, 4: u32 ino, 8: u32 mode, 12: i16 nlink,
        // 14: u16 uid, 16: u16 gid, 18: u16 rdev, 20: i32 size,
        // 24/28: atime sec/nsec, 32/36: mtime, 40/44: ctime,
        // 48: i32 blksize, 52: i32 blocks, 56: unused[2]
        let mut ok = true;
        ok &= self.put16(env, addr, md.dev as u16);
        ok &= self.put32(env, addr + 4, md.ino as u32);
        ok &= self.put32(env, addr + 8, md.mode);
        ok &= self.put16(env, addr + 12, md.nlink as u16);
        ok &= self.put16(env, addr + 14, md.uid as u16);
        ok &= self.put16(env, addr + 16, md.gid as u16);
        ok &= self.put16(env, addr + 18, md.rdev as u16);
        ok &= self.put32(env, addr + 20, md.size as u32);
        ok &= self.put32(env, addr + 24, md.atime as u32);
        ok &= self.put32(env, addr + 28, md.atime_nsec as u32);
        ok &= self.put32(env, addr + 32, md.mtime as u32);
        ok &= self.put32(env, addr + 36, md.mtime_nsec as u32);
        ok &= self.put32(env, addr + 40, md.ctime as u32);
        ok &= self.put32(env, addr + 44, md.ctime_nsec as u32);
        ok &= self.put32(env, addr + 48, md.blksize as u32);
        ok &= self.put32(env, addr + 52, md.blocks as u32);
        ok
    }

    /// `stat` 系の共通部。`dirfd`/`path`/`fd` と書き込むバッファの
    /// レイアウト（`StatFmt`）を取る。
    fn do_stat(
        &mut self,
        env: &mut BareEnv,
        fd: Option<u32>,
        path_addr: Option<u64>,
        out: u64,
        lstat: bool,
        fmt: StatFmt,
    ) -> u64 {
        let md = match (fd, path_addr) {
            (Some(fd), _) => match fd {
                0..=2 => match polyisa_host::stat("/dev/null") {
                    Ok(m) => m,
                    Err(e) => return fail_host(e.raw_os_error().unwrap_or(5)),
                },
                _ => match self.fds.file(fd) {
                    Some(f) => match polyisa_host::fstat(f) {
                        Ok(m) => m,
                        Err(e) => {
                            return fail_host(e.raw_os_error().unwrap_or(5));
                        }
                    },
                    None => return fail(sparc::errno::EBADF),
                },
            },
            (None, Some(path_addr)) => {
                let path = match self.read_cstr(env, path_addr) {
                    Ok(p) => p,
                    Err(e) => return fail(e),
                };
                let host = self.host_path(&path);
                let r = if lstat {
                    polyisa_host::lstat(&host)
                } else {
                    polyisa_host::stat(&host)
                };
                match r {
                    Ok(m) => m,
                    Err(e) => {
                        return fail_host(e.raw_os_error().unwrap_or(sparc::errno::EIO as i32));
                    }
                }
            }
            _ => return fail(sparc::errno::EINVAL),
        };
        let ok = match fmt {
            StatFmt::Statx => self.put_statx(env, out, &md),
            StatFmt::Stat64 if is_v9(env) => self.put_kstat64(env, out, &md),
            StatFmt::Stat64 => self.put_stat(env, out, &md),
            StatFmt::Stat if is_v9(env) => self.put_stat(env, out, &md),
            StatFmt::Stat => self.put_stat32(env, out, &md),
        };
        if ok {
            ret(0)
        } else {
            fail(sparc::errno::EFAULT)
        }
    }

    /// `mmap`/`mmap2`（addr は無視して自前割当。fixed ならその位置）。
    /// sparc の mmap（71）のオフセットはバイト単位、mmap2（56・32 だけ）
    /// はページ単位。ファイル写像は `fd` を `offset` まで読んで
    /// 内容を置くだけ（書き戻しはしない。MAP_SHARED は近似）。
    fn do_mmap(&mut self, env: &mut BareEnv, args: &[u64; 6], page_off: bool) -> u64 {
        let (addr, len, prot, flags) = (args[0], args[1], args[2], args[3]);
        let (fd, off) = (args[4] as u32 as i32 as i64, args[5]);
        if len == 0 {
            return fail(sparc::errno::EINVAL);
        }
        let pages = len.div_ceil(4096);
        let fixed = flags & sparc::mmap_flag::FIXED != 0;
        let base = if fixed {
            addr & !0xfff
        } else {
            let b = self.mmap_next;
            self.mmap_next += pages * 4096;
            b
        };
        let mut p = 0u8;
        if prot & sparc::prot::READ != 0 {
            p |= Perms::R.0;
        }
        if prot & sparc::prot::WRITE != 0 {
            p |= Perms::W.0;
        }
        if prot & sparc::prot::EXEC != 0 {
            p |= Perms::X.0;
        }
        if env
            .backend
            .mem
            .map(VirtAddr(base), pages, Perms(p))
            .is_err()
        {
            return fail(sparc::errno::ENOMEM);
        }
        // 匿名写像でなければ fd の中身を offset から読み込む。
        let anon = flags & sparc::mmap_flag::ANONYMOUS != 0;
        if !anon && fd >= 0 {
            let off = if page_off { off * 4096 } else { off };
            let r = self.file_of(fd as u32).and_then(|f| {
                f.seek(SeekFrom::Start(off))
                    .map_err(|_| sparc::errno::EIO)?;
                let mut buf = vec![0u8; len as usize];
                let n = f.read(&mut buf).map_err(|_| sparc::errno::EIO)?;
                buf.truncate(n);
                Ok(buf)
            });
            match r {
                Ok(buf) => {
                    if self.write_bytes(env, base, &buf).is_err() {
                        return fail(sparc::errno::EFAULT);
                    }
                }
                Err(e) => return fail(e),
            }
        }
        ret(base)
    }

    /// `brk`。新しいブレークを返す。
    fn do_brk(&mut self, env: &mut BareEnv, addr: u64) -> u64 {
        if self.heap_end == 0 {
            // 未初期化なら今のアドレスをそのまま返す。
            return ret(addr);
        }
        if addr != 0 && addr > self.heap_end {
            // 旧ブレークを含む部分ページは既に写像・使用済みなので、
            // その次のページからだけを新規に確保する（再写像で bss を
            // ゼロ化しないため）。
            let lo = self.heap_end.div_ceil(4096) * 4096;
            let hi = addr.div_ceil(4096) * 4096;
            if hi > lo {
                let pages = (hi - lo) / 4096;
                let _ = env.backend.mem.map(VirtAddr(lo), pages, Perms::RW);
            }
            self.heap_end = addr;
        } else if addr != 0 {
            self.heap_end = addr;
        }
        ret(self.heap_end)
    }

    /// `uname`（65B×6）。machine は ABI で sparc64 / sparc。
    fn do_uname(&mut self, env: &mut BareEnv, addr: u64) -> u64 {
        let machine: &[u8] = if is_v9(env) { b"sparc64" } else { b"sparc" };
        let fields: [&[u8]; 6] = [
            b"Linux",
            b"polyisa",
            b"6.19.0",
            b"#1 polyisa",
            machine,
            b"(none)",
        ];
        for (i, f) in fields.iter().enumerate() {
            let mut buf = [0u8; 65];
            buf[..f.len()].copy_from_slice(f);
            if self.write_bytes(env, addr + (i * 65) as u64, &buf).is_err() {
                return fail(sparc::errno::EFAULT);
            }
        }
        ret(0)
    }

    /// `sysinfo`。フィールドはポインタ幅の語（long）が並ぶ。
    fn do_sysinfo(&mut self, env: &mut BareEnv, addr: u64) -> u64 {
        let secs = self.mono_start.map(|s| s.elapsed().as_secs()).unwrap_or(0);
        let ws = wsize(env);
        let total = 512 * 1024 * 1024u64;
        let mut ok = true;
        ok &= self.put_u(env, addr, secs); // uptime
        ok &= self.put_u(env, addr + ws, 0); // loads[0]
        ok &= self.put_u(env, addr + ws * 2, 0);
        ok &= self.put_u(env, addr + ws * 3, 0);
        ok &= self.put_u(env, addr + ws * 4, total);
        ok &= self.put_u(env, addr + ws * 5, total);
        ok &= self.put_u(env, addr + ws * 6, 0);
        ok &= self.put_u(env, addr + ws * 7, 0);
        ok &= self.put_u(env, addr + ws * 8, 0);
        ok &= self.put_u(env, addr + ws * 9, 0);
        ok &= self.put16(env, addr + ws * 10, 1); // procs
        ok &= self.put16(env, addr + ws * 10 + 2, 0);
        ok &= self.put32(env, addr + ws * 10 + 4, 0); // totalhigh
        ok &= self.put32(env, addr + ws * 10 + 8, 0); // freehigh
        ok &= self.put32(env, addr + ws * 10 + 12, 1); // mem_unit
        if ok {
            ret(0)
        } else {
            fail(sparc::errno::EFAULT)
        }
    }

    /// `getrandom`。
    fn do_getrandom(&mut self, env: &mut BareEnv, buf: u64, len: u64) -> u64 {
        let mut data = vec![0u8; len.min(1 << 20) as usize];
        match std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut data)) {
            Ok(()) => match self.write_bytes(env, buf, &data) {
                Ok(()) => ret(data.len() as u64),
                Err(e) => fail(e),
            },
            Err(e) => fail_host(e.raw_os_error().unwrap_or(sparc::errno::EIO as i32)),
        }
    }

    /// `getdents64`。linux_dirent64: u64 d_ino, u64 d_off, u16 d_reclen,
    /// u8 d_type, name\0。
    fn do_getdents64(&mut self, env: &mut BareEnv, fd: u32, buf: u64, count: u64) -> u64 {
        let path = self.fds.path_of(fd).map(str::to_string).unwrap_or_default();
        if path.is_empty() {
            return fail(sparc::errno::ENOTDIR);
        }
        let rd = match std::fs::read_dir(&path) {
            Ok(r) => r,
            Err(e) => {
                return fail_host(e.raw_os_error().unwrap_or(sparc::errno::EIO as i32));
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
        let mut all = vec![(1u64, ".".to_string(), 4u8), (1, "..".to_string(), 4u8)];
        all.extend(entries);
        let count = count as usize;
        let mut pos = *self.dir_pos.get(&fd).unwrap_or(&0);
        let mut emitted = 0usize;
        for (i, (ino, name, t)) in all.iter().enumerate().skip(pos) {
            let reclen = 19 + name.len() + 1;
            let aligned = reclen.next_multiple_of(8);
            if out.len() + aligned > count {
                break;
            }
            out.extend_from_slice(&ino.to_be_bytes());
            out.extend_from_slice(&((i + 1) as u64).to_be_bytes());
            out.extend_from_slice(&(aligned as u16).to_be_bytes());
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
            Ok(()) => ret(out.len() as u64),
            Err(e) => fail(e),
        }
    }

    /// `readlink`/`readlinkat`。/proc/self/exe は exe_path を返す。
    fn do_readlink(&mut self, env: &mut BareEnv, path_addr: u64, buf: u64, len: u64) -> u64 {
        let path = match self.read_cstr(env, path_addr) {
            Ok(p) => p,
            Err(e) => return fail(e),
        };
        let host = self.host_path(&path);
        let target = if host == "/proc/self/exe" {
            self.exe_path.clone()
        } else {
            match std::fs::read_link(&host) {
                Ok(t) => t.to_string_lossy().into_owned(),
                Err(e) => {
                    return fail_host(e.raw_os_error().unwrap_or(sparc::errno::EIO as i32));
                }
            }
        };
        let n = target.len().min(len as usize);
        match self.write_bytes(env, buf, &target.as_bytes()[..n]) {
            Ok(()) => ret(n as u64),
            Err(e) => fail(e),
        }
    }

    /// `read`/`pread64`。
    fn do_read(&mut self, env: &mut BareEnv, fd: u32, buf: u64, len: u64) -> u64 {
        let len = len.min(1 << 20) as usize;
        let r = match self.reader(fd) {
            Ok(r) => r,
            Err(e) => return fail(e),
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
                    Ok(()) => ret(n as u64),
                    Err(e) => fail(e),
                }
            }
            ReadFd::File(f) => {
                let mut chunk = vec![0u8; len];
                match f.read(&mut chunk) {
                    Ok(n) => match self.write_bytes(env, buf, &chunk[..n]) {
                        Ok(()) => ret(n as u64),
                        Err(e) => fail(e),
                    },
                    Err(e) => fail_host(e.raw_os_error().unwrap_or(sparc::errno::EIO as i32)),
                }
            }
        }
    }

    /// `pread64`。
    fn do_pread(&mut self, env: &mut BareEnv, fd: u32, buf: u64, len: u64, off: u64) -> u64 {
        let len = len.min(1 << 20) as usize;
        let f = match self.file_of(fd) {
            Ok(f) => f,
            Err(e) => return fail(e),
        };
        let mut chunk = vec![0u8; len];
        match polyisa_host::pread(f, &mut chunk, off) {
            Ok(n) => match self.write_bytes(env, buf, &chunk[..n]) {
                Ok(()) => ret(n as u64),
                Err(e) => fail(e),
            },
            Err(e) => fail_host(e.raw_os_error().unwrap_or(sparc::errno::EIO as i32)),
        }
    }

    /// `write`/`pwrite64`。
    fn do_write(&mut self, env: &mut BareEnv, fd: u32, buf: u64, len: u64) -> u64 {
        let data = match self.read_bytes(env, buf, len as usize) {
            Ok(d) => d,
            Err(e) => return fail(e),
        };
        let w = match self.writer(fd) {
            Ok(w) => w,
            Err(e) => return fail(e),
        };
        match w {
            WriteFd::Stdout => {
                self.io.stdout.extend_from_slice(&data);
                let _ = std::io::Write::write_all(&mut std::io::stdout(), &data);
                ret(data.len() as u64)
            }
            WriteFd::Stderr => {
                self.io.stderr.extend_from_slice(&data);
                let _ = std::io::Write::write_all(&mut std::io::stderr(), &data);
                ret(data.len() as u64)
            }
            WriteFd::File(f) => match f.write(&data) {
                Ok(n) => ret(n as u64),
                Err(e) => fail_host(e.raw_os_error().unwrap_or(sparc::errno::EIO as i32)),
            },
        }
    }

    /// `pwrite64`。ファイル位置を変えずに offset へ書く。
    fn do_pwrite(&mut self, env: &mut BareEnv, fd: u32, buf: u64, len: u64, off: u64) -> u64 {
        let len = len.min(1 << 20) as usize;
        let data = match self.read_bytes(env, buf, len) {
            Ok(d) => d,
            Err(e) => return fail(e),
        };
        let f = match self.file_of(fd) {
            Ok(f) => f,
            Err(e) => return fail(e),
        };
        match polyisa_host::pwrite(f, &data, off) {
            Ok(n) => ret(n as u64),
            Err(e) => fail_host(e.raw_os_error().unwrap_or(sparc::errno::EIO as i32)),
        }
    }

    /// `sendfile`/`sendfile64`。offset==NULL の形だけ。
    fn do_sendfile(
        &mut self,
        _env: &mut BareEnv,
        out_fd: u32,
        in_fd: u32,
        off: u64,
        cnt: u64,
    ) -> u64 {
        if off != 0 {
            return fail(sparc::errno::EINVAL);
        }
        let mut left = cnt.min(1 << 22) as usize;
        let mut done = 0u64;
        while left > 0 {
            let n = left.min(64 * 1024);
            let mut buf = vec![0u8; n];
            let got = {
                let r = match self.reader(in_fd) {
                    Ok(r) => r,
                    Err(e) => return fail(e),
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
                            return fail_host(e.raw_os_error().unwrap_or(sparc::errno::EIO as i32));
                        }
                    },
                }
            };
            if got == 0 {
                break;
            }
            let w = match self.writer(out_fd) {
                Ok(w) => w,
                Err(e) => return fail(e),
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
                        return fail_host(e.raw_os_error().unwrap_or(sparc::errno::EIO as i32));
                    }
                },
            };
            done += put as u64;
            left -= got;
            if put < got {
                break;
            }
        }
        ret(done)
    }

    /// `readv`/`writev`（iov はポインタ幅の語の二つ組）。
    fn do_readv(&mut self, env: &mut BareEnv, fd: u32, iov: u64, cnt: u64) -> u64 {
        let ws = wsize(env);
        let mut total = 0u64;
        for i in 0..cnt.min(1024) {
            let base = self.mem_u(env, iov + i * 2 * ws);
            let len = self.mem_u(env, iov + i * 2 * ws + ws);
            let n = self.do_read(env, fd, base, len);
            if is_err_r(n) {
                return n;
            }
            total = total.wrapping_add(n);
            if n < len {
                break;
            }
        }
        ret(total)
    }

    fn do_writev(&mut self, env: &mut BareEnv, fd: u32, iov: u64, cnt: u64) -> u64 {
        let ws = wsize(env);
        let mut total = 0u64;
        for i in 0..cnt.min(1024) {
            let base = self.mem_u(env, iov + i * 2 * ws);
            let len = self.mem_u(env, iov + i * 2 * ws + ws);
            let n = self.do_write(env, fd, base, len);
            if is_err_r(n) {
                return n;
            }
            total = total.wrapping_add(n);
        }
        ret(total)
    }

    /// `lseek`/`_llseek`。
    fn do_lseek(&mut self, _env: &mut BareEnv, fd: u32, off: i64, whence: u32) -> u64 {
        if whence > 2 {
            return fail(sparc::errno::EINVAL);
        }
        if whence == 0 && off == 0 {
            self.dir_pos.remove(&fd);
        }
        let f = match self.file_of(fd) {
            Ok(f) => f,
            Err(e) => return fail(e),
        };
        let w = match whence {
            0 => SeekFrom::Start(off as u64),
            1 => SeekFrom::Current(off),
            2 => SeekFrom::End(off),
            _ => unreachable!(),
        };
        match f.seek(w) {
            Ok(p) => ret(p),
            Err(e) => fail_host(e.raw_os_error().unwrap_or(sparc::errno::EIO as i32)),
        }
    }

    /// `ioctl`。TCGETS/TCSETS/TIOCGWINSZ/FIONREAD だけ。
    /// 番号は sparc 固有（SunOS 型の _IOR/_IOW エンコード）。
    // Ref: SRC-LINUX (7.3) — arch/sparc/include/uapi/asm/ioctls.h.
    fn do_ioctl(&mut self, env: &mut BareEnv, fd: u32, req: u64, argp: u64) -> u64 {
        const TCGETS: u64 = 0x4024_5408;
        const TCSETS: u64 = 0x8024_5409;
        const TIOCGWINSZ: u64 = 0x4008_7468;
        const FIONREAD: u64 = 0x4004_667f;
        match req {
            TCGETS | TCSETS => {
                if fd > 2 {
                    return fail(sparc::errno::ENOTTY);
                }
                if req == TCGETS {
                    // termios（36B）。cflag に B38400|CS8 を入れる。
                    let mut b = [0u8; 36];
                    b[8..12].copy_from_slice(&0x1cb0u32.to_be_bytes());
                    let _ = self.write_bytes(env, argp, &b);
                }
                ret(0)
            }
            TIOCGWINSZ => {
                let mut b = [0u8; 8];
                b[0..2].copy_from_slice(&24u16.to_be_bytes());
                b[2..4].copy_from_slice(&80u16.to_be_bytes());
                match self.write_bytes(env, argp, &b) {
                    Ok(()) => ret(0),
                    Err(x) => fail(x),
                }
            }
            FIONREAD => {
                if self.put32(env, argp, 0) {
                    ret(0)
                } else {
                    fail(sparc::errno::EFAULT)
                }
            }
            _ => fail(sparc::errno::ENOTTY),
        }
    }

    /// `fcntl`/`fcntl64`。FD フラグと dup だけ。
    fn do_fcntl(&mut self, _env: &mut BareEnv, fd: u32, cmd: u32, arg: u64) -> u64 {
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
                        ret(u64::from(nfd))
                    }
                    Err(e) => fail_host(e.raw_os_error().unwrap_or(sparc::errno::EIO as i32)),
                },
                None => fail(sparc::errno::EBADF),
            },
            1 => ret(0), // F_GETFD
            2 => ret(0), // F_SETFD
            3 => ret(0), // F_GETFL（フラグは覚えていない）
            4 => ret(0), // F_SETFL
            _ => fail(sparc::errno::EINVAL),
        }
    }

    /// `gettimeofday`/`clock_gettime`/`time`/`times` の単調時計。
    fn mono_us(&mut self) -> u64 {
        self.mono_start
            .get_or_insert_with(std::time::Instant::now)
            .elapsed()
            .as_micros() as u64
    }

    /// `timespec`（ポインタ幅の語×2）を書く。
    fn put_timespec(&mut self, env: &mut BareEnv, addr: u64, sec: u64, nsec: u64) -> bool {
        let ws = wsize(env);
        self.put_u(env, addr, sec) && self.put_u(env, addr + ws, nsec)
    }

    /// `statfs64`（88B）と `statfs`（64B）の共通部。
    fn do_statfs(&mut self, env: &mut BareEnv, addr: u64, wide: bool) -> u64 {
        let mut ok = true;
        if wide {
            // u32 type, u32 bsize, u64 blocks..ffree, fsid(8B),
            // u32 namelen, u32 frsize, u32 flags, u32 spare[4]。88B。
            ok &= self.put32(env, addr, 0xEF53);
            ok &= self.put32(env, addr + 4, 4096);
            ok &= self.put64(env, addr + 8, 1 << 22);
            ok &= self.put64(env, addr + 16, 1 << 21);
            ok &= self.put64(env, addr + 24, 1 << 21);
            ok &= self.put64(env, addr + 32, 1 << 20);
            ok &= self.put64(env, addr + 40, 1 << 20);
            ok &= self.put64(env, addr + 48, 0); // fsid
            ok &= self.put32(env, addr + 56, 255);
            ok &= self.put32(env, addr + 60, 4096);
            ok &= self.put32(env, addr + 64, 0);
        } else {
            // u32 の列 + fsid(8B) + namelen + spare[6]。64B。
            let fields = [0xEF53u32, 4096, 1 << 22, 1 << 21, 1 << 21, 1 << 20, 1 << 19];
            for (i, v) in fields.iter().enumerate() {
                ok &= self.put32(env, addr + (i * 4) as u64, *v);
            }
            ok &= self.put64(env, addr + 28, 0); // fsid
            ok &= self.put32(env, addr + 36, 255);
        }
        if ok {
            ret(0)
        } else {
            fail(sparc::errno::EFAULT)
        }
    }

    /// 窓 `w`（物理番号）の退避域の先頭アドレス。その窓の
    /// %o6（%sp）が指し、V9 では 2047 の BIAS を足す。
    fn win_spill_addr(&mut self, env: &mut BareEnv, w: u64) -> u64 {
        let v9 = is_v9(env);
        let i = win_slot(env, w, 6);
        let sp = slot(env, i);
        if v9 {
            sp.wrapping_add(2047)
        } else {
            sp & 0xffff_ffff
        }
    }

    /// 窓 `w`（物理番号）の l0–i7 を、その窓の %o6（%sp）が指す
    /// 退避域へ書く。退避先は各フレームの先頭 16 語で、V9 は
    /// さらに 2047 の BIAS を足した場所。失敗は偽。
    // Ref: SRC-LINUX (7.3) — arch/sparc/kernel/wof.S の STORE_WINDOW(sp)。
    fn spill_window(&mut self, env: &mut BareEnv, w: u64) -> bool {
        let v9 = is_v9(env);
        let addr = self.win_spill_addr(env, w);
        let mut buf = vec![0u8; if v9 { 128 } else { 64 }];
        for j in 0..16usize {
            let i = win_slot(env, w, 8 + j as u64);
            let v = slot(env, i);
            if v9 {
                buf[j * 8..j * 8 + 8].copy_from_slice(&v.to_be_bytes());
            } else {
                buf[j * 4..j * 4 + 4].copy_from_slice(&(v as u32).to_be_bytes());
            }
        }
        self.write_bytes(env, addr, &buf).is_ok()
    }

    /// 窓 `w`（物理番号）の l0–i7 を退避域から読み戻す。
    /// 退避先は `w` の %o6 の値で、そのスロットはカレント窓の
    /// %i6 と別名なので、現在値から取る。失敗は偽。
    // Ref: SRC-LINUX (7.3) — arch/sparc/kernel/wuf.S の LOAD_WINDOW(sp)。
    fn fill_window(&mut self, env: &mut BareEnv, w: u64) -> bool {
        let v9 = is_v9(env);
        let p = cur_win(env);
        let i = win_slot(env, p, 22);
        let sp = slot(env, i);
        let addr = if v9 {
            sp.wrapping_add(2047)
        } else {
            sp & 0xffff_ffff
        };
        let n = if v9 { 128 } else { 64 };
        let buf = match self.read_bytes(env, addr, n) {
            Ok(b) => b,
            Err(_) => return false,
        };
        for j in 0..16usize {
            let v = if v9 {
                u64::from_be_bytes(buf[j * 8..j * 8 + 8].try_into().unwrap())
            } else {
                u64::from(u32::from_be_bytes(
                    buf[j * 4..j * 4 + 4].try_into().unwrap(),
                ))
            };
            let i = win_slot(env, w, 8 + j as u64);
            set_slot(env, i, v);
        }
        true
    }

    /// flushw（ta 3）。退避対象の窓すべてを書き出す。
    fn do_flushw(&mut self, env: &mut BareEnv) -> TrapOutcome {
        let nw = nwindows(env);
        let p = cur_win(env);
        let n = env.backend.get(sem::canrestore_ref());
        for k in 1..=n {
            let w = (p + k) % nw;
            if !self.spill_window(env, w) {
                let addr = self.win_spill_addr(env, w);
                let len = if is_v9(env) { 128 } else { 64 };
                if !(self.grow_stack(env, addr, len) && self.spill_window(env, w)) {
                    return TrapOutcome::Unimplemented;
                }
            }
        }
        env.backend.set(sem::canrestore_ref(), 0);
        env.backend.set(sem::cansave_ref(), nw - 2);
        next_insn(env);
        TrapOutcome::Handled
    }

    /// `ta 0x6e`（sparc64 getcontext）。ユーザの %o0 が指す
    /// ucontext にトラップ時点のコンテキストを書く。カーネルは
    /// `sparc64_get_context` で struct をゼロ初期化してから
    /// sigmask・mc_gregs（tstate/pc/npc/y/g1-g7/o0-o7）・
    /// mc_fp・mc_i7 を書き、FPU 領域は enab=0 のまま残す。
    /// Ref: SRC-LINUX — arch/sparc/kernel/signal_64.c,
    /// arch/sparc/include/uapi/asm/uctx.h.
    ///
    /// ユーザレイアウト（64 ビット、オフセット 16 進）:
    ///   uc_link@00, uc_flags@08, uc_sigmask@10, pad@18,
    ///   mc_gregs@20（TSTATE/PC/NPC/Y/G1-G7/O0-O7 の順 19 語）、
    ///   mc_fp@b8, mc_i7@c0, mc_fpregs@c8（enab=0）。
    ///   uc_mcontext は long double 整列で 0x20 から始まる。
    fn do_getcontext(&mut self, env: &mut BareEnv) -> TrapOutcome {
        const UC_SIZE: u64 = 0x1e0;
        let ucp = reg(env, 8);
        if !self
            .write_bytes(env, ucp, &vec![0u8; UC_SIZE as usize])
            .is_ok()
        {
            return TrapOutcome::Unimplemented;
        }
        // sigmask はシグナル非対応のため 0（ゼロ初期化済み）。
        let npc = env.backend.get(sem::npc_ref());
        let mut g = [0u64; 19];
        g[0] = env.backend.get(sem::tstate_ref());
        g[1] = npc;
        g[2] = npc.wrapping_add(4);
        g[3] = env.backend.get(sem::y_ref());
        for (i, slot) in g.iter_mut().enumerate().skip(4) {
            *slot = reg(env, (i - 3) as u8);
        }
        for (i, v) in g.iter().enumerate() {
            if !self.put64(env, ucp + 0x20 + i as u64 * 8, *v) {
                return TrapOutcome::Unimplemented;
            }
        }
        let fp = reg(env, 30);
        let i7 = reg(env, 31);
        if !self.put64(env, ucp + 0xb8, fp) || !self.put64(env, ucp + 0xc0, i7) {
            return TrapOutcome::Unimplemented;
        }
        next_insn(env);
        TrapOutcome::Handled
    }

    /// `addr..addr+len` の未写像ページを、スタック成長窓の
    /// `[stack_limit, stack_top)` 内にあるものだけ写像する。
    /// 戻り値は「もう一度試せるか」。
    fn grow_stack(&mut self, env: &mut BareEnv, addr: u64, len: u64) -> bool {
        if self.stack_top == 0 || addr < self.stack_limit || addr + len > self.stack_top {
            return false;
        }
        let rw = Perms(Perms::R.0 | Perms::W.0);
        let mut a = addr & !0xfff;
        while a < addr + len {
            if !env.backend.mem.is_mapped(polyisa_mem::PageNo(a / 4096))
                && env.backend.mem.map(VirtAddr(a), 1, rw).is_err()
            {
                return false;
            }
            a += 4096;
        }
        true
    }

    /// ウィンドウあふれ。cansave==0 で save できないとき、最古の
    /// in-register 祖先窓（restore 方向の端 = 物理番号で
    /// p+canrestore）を退避して clean 窓にし、pc を動かさず
    /// save を再実行させる。save が入る窓（物理 p-1）は clean 窓
    /// であり、退避対象ではない。
    fn do_win_overflow(&mut self, env: &mut BareEnv) -> TrapOutcome {
        let nw = nwindows(env);
        let p = cur_win(env);
        let w = (p + env.backend.get(sem::canrestore_ref())) % nw;
        if !self.spill_window(env, w) {
            // 退避先が未写像なら、スタック成長窓の内側に限って
            // 写像を伸ばしてもう一度試す。
            let addr = self.win_spill_addr(env, w);
            let len = if is_v9(env) { 128 } else { 64 };
            if !(self.grow_stack(env, addr, len) && self.spill_window(env, w)) {
                return TrapOutcome::Unimplemented;
            }
        }
        // 空きは 1 枚分戻る。退避した分の中身はスタックへ移ったので
        // canrestore からは外す（戻る途中の不足トラップで埋め戻す）。
        env.backend.set(sem::cansave_ref(), 1);
        let cr = env.backend.get(sem::canrestore_ref());
        env.backend.set(sem::canrestore_ref(), cr.saturating_sub(1));
        TrapOutcome::Handled
    }

    /// ウィンドウ不足。canrestore==0 で restore できないとき、
    /// restore 方向の隣（物理番号で p+1）の窓をスタックから
    /// 埋め戻し、pc を動かさず restore を再実行させる。
    fn do_win_underflow(&mut self, env: &mut BareEnv) -> TrapOutcome {
        let nw = nwindows(env);
        let p = cur_win(env);
        let w = (p + 1) % nw;
        if !self.fill_window(env, w) {
            let addr = self.win_spill_addr(env, w);
            let len = if is_v9(env) { 128 } else { 64 };
            if !(self.grow_stack(env, addr, len) && self.fill_window(env, w)) {
                return TrapOutcome::Unimplemented;
            }
        }
        // RESTORED と同じ規約：埋め戻した窓が live に戻るので
        // canrestore を増やし、clean 窩が 1 枚減る分 cansave を
        // 減らす。
        let cr = env.backend.get(sem::canrestore_ref());
        env.backend.set(sem::canrestore_ref(), cr + 1);
        let cs = env.backend.get(sem::cansave_ref());
        env.backend.set(sem::cansave_ref(), cs.saturating_sub(1));
        TrapOutcome::Handled
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

/// syscall トレースのスイッチ。
fn trace() -> bool {
    std::env::var_os("POLYISA_SPARC_SYSCALLS").is_some()
}

/// `word64` パラメータ。V9（sparc64）なら真。
fn is_v9(env: &mut BareEnv) -> bool {
    env.backend.param::<polyisa_guest_sparc::Word64Param>()
}

/// `nwindows` パラメータ（既定 8）。
fn nwindows(env: &mut BareEnv) -> u64 {
    u64::from(env.backend.param::<polyisa_guest_sparc::NwindowsParam>())
}

/// ポインタ幅の語のバイト数。
fn wsize(env: &mut BareEnv) -> u64 {
    if is_v9(env) { 8 } else { 4 }
}

/// 物理レジスタスロットを指す。
fn gpr_ref(i: usize) -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, g) + i * 8)
}

/// 物理スロットを読む。
fn slot(env: &mut BareEnv, i: usize) -> u64 {
    env.backend.get(gpr_ref(i))
}

/// 物理スロットに書く。
fn set_slot(env: &mut BareEnv, i: usize, v: u64) {
    env.backend.set(gpr_ref(i), v);
}

/// カレント窓の物理番号。V8 は cwp そのまま、V9 は反転した
/// `(nw - cwp mod nw) mod nw` が基底になる（sem::phys_index と同じ式）。
fn cur_win(env: &mut BareEnv) -> u64 {
    let cwp = env.backend.get(sem::cwp_ref());
    let nw = nwindows(env);
    if is_v9(env) {
        (nw - cwp % nw) % nw
    } else {
        cwp
    }
}

/// 見えるレジスタ番号を物理スロット番号へ（sem::phys_index と同じ式）。
fn phys(env: &mut BareEnv, r: u8) -> usize {
    if r < 8 {
        return usize::from(r);
    }
    let nw = nwindows(env);
    let base = cur_win(env) * 16;
    8 + ((base + u64::from(r - 8)) % (nw * 16)) as usize
}

/// 窓 `w`（物理番号）のブロック内オフセット `off` のスロット番号。
/// 1 ブロック 16 本はその窓の out（+0..+7）と local（+8..+15）で、
/// in（+16..+23）は次の窓の out と別名なので `nw*16` で折り返す。
fn win_slot(env: &mut BareEnv, w: u64, off: u64) -> usize {
    let nw = nwindows(env);
    8 + ((w * 16 + off) % (nw * 16)) as usize
}

/// 見えるレジスタ `r`（0–31）を読む。
fn reg(env: &mut BareEnv, r: u8) -> u64 {
    if r == 0 {
        return 0;
    }
    let i = phys(env, r);
    slot(env, i)
}

/// 見えるレジスタ `r`（0–31）に書く。%g0 への書き込みは捨てる。
fn set_reg(env: &mut BareEnv, r: u8, v: u64) {
    if r != 0 {
        let v = if is_v9(env) { v } else { v & 0xffff_ffff };
        let i = phys(env, r);
        set_slot(env, i, v);
    }
}

/// キャリー flag を立てる・倒す。V8 は PSR.C（bit 20）、
/// V9 は %ccr の icc.c（bit 0）。
fn set_carry(env: &mut BareEnv, on: bool) {
    if is_v9(env) {
        // カーネルは icc.c（bit0）と xcc.c（bit4）の両方を更新する。
        // Ref: SRC-LINUX (7.3) — arch/sparc/kernel/syscalls.S.
        let c = env.backend.get(sem::ccr_ref());
        env.backend
            .set(sem::ccr_ref(), if on { c | 0x11 } else { c & !0x11 });
    } else {
        let p = env.backend.get(sem::psr_ref());
        env.backend.set(
            sem::psr_ref(),
            if on { p | (1 << 20) } else { p & !(1 << 20) },
        );
    }
}

/// pc を npc に、npc を +4 に進める（処理済みトラップの復帰）。
/// ウィンドウの退避・復元では呼ばない（save/restore を再実行する）。
fn next_insn(env: &mut BareEnv) {
    let mask = if is_v9(env) { u64::MAX } else { 0xffff_ffff };
    let npc = env.backend.get(sem::npc_ref());
    env.backend.set(sem::pc_ref(), npc & mask);
    env.backend.set(sem::npc_ref(), npc.wrapping_add(4) & mask);
}

/// 戻り値が -errno か（内部表現）。
fn is_err_r(v: u64) -> bool {
    (v as i64) < 0 && (v as i64) > -4096
}

/// 成功の戻り値。
fn ret(v: u64) -> u64 {
    v
}

/// 失敗（内部表現は -errno。コミット時に正の errno へ戻す）。
fn fail(errno: u32) -> u64 {
    (u64::from(errno)).wrapping_neg()
}

/// ホスト errno を sparc errno（SunOS 系の独自番号）に写して失敗を返す。
fn fail_host(e: i32) -> u64 {
    fail(host_errno(e))
}

/// ホスト（asm-generic）の errno を sparc の番号へ写す。
/// 34 までは同じ値で、35 以降のよく出るものだけ写す。
fn host_errno(e: i32) -> u32 {
    use sparc::errno as E;
    let Ok(v) = u32::try_from(e) else {
        return E::EIO;
    };
    match v {
        0..=34 => v,
        35 => E::EDEADLK,
        36 => E::ENAMETOOLONG,
        38 => E::ENOSYS,
        39 => E::ENOTEMPTY,
        40 => E::ELOOP,
        42 => E::ENOMSG,
        43 => E::EIDRM,
        60 => E::ENOSTR,
        61 => E::ENODATA,
        62 => E::ETIME,
        63 => E::ENOSR,
        67 => E::ENOLINK,
        71 => E::EPROTO,
        72 => E::EMULTIHOP,
        74 => E::EBADMSG,
        75 => E::EOVERFLOW,
        84 => E::EILSEQ,
        87 => E::EUSERS,
        88 => E::ENOTSOCK,
        89 => E::EDESTADDRREQ,
        90 => E::EMSGSIZE,
        91 => E::EPROTOTYPE,
        92 => E::ENOPROTOOPT,
        93 => E::EPROTONOSUPPORT,
        95 => E::EOPNOTSUPP,
        96 => E::EPFNOSUPPORT,
        97 => E::EAFNOSUPPORT,
        98 => E::EADDRINUSE,
        99 => E::EADDRNOTAVAIL,
        100 => E::ENETDOWN,
        101 => E::ENETUNREACH,
        102 => E::ENETRESET,
        103 => E::ECONNABORTED,
        104 => E::ECONNRESET,
        105 => E::ENOBUFS,
        106 => E::EISCONN,
        107 => E::ENOTCONN,
        108 => E::ESHUTDOWN,
        110 => E::ETIMEDOUT,
        111 => E::ECONNREFUSED,
        115 => E::EINPROGRESS,
        116 => E::ESTALE,
        122 => E::EDQUOT,
        _ => E::EIO,
    }
}

/// dispatch の戻り。
/// `stat` 系が書くバッファのレイアウト指定。
enum StatFmt {
    /// `stat`/`lstat`/`fstat`（`newfstatat` 相当含む）。
    Stat,
    /// `stat64`/`lstat64`/`fstat64`/`fstatat64`。
    Stat64,
    /// `statx`。
    Statx,
}

enum Disp {
    /// %o0 に書く値（内部表現。負なら -errno）。
    Ret(u64),
    Exit(u32),
    /// 未実装。ENOSYS を返して続ける。
    Unimpl,
}

fn ok_ret(v: u64) -> Disp {
    Disp::Ret(ret(v))
}

fn fail_ret(errno: u32) -> Disp {
    Disp::Ret(fail(errno))
}

fn fail_ret_host(e: i32) -> Disp {
    Disp::Ret(fail_host(e))
}

impl TrapHandler for Linux {
    /// `brk` の初期値。ローダが像の末尾を渡す。
    fn init_brk(&mut self, image_end: u64) {
        self.heap_end = image_end;
        self.mmap_next = image_end.div_ceil(0x1000) * 0x1000 + 0x800_0000;
    }

    fn handle_trap(&mut self, env: &mut BareEnv, _code: u32) -> TrapOutcome {
        // トラップ番号は実行時の値なので例外の code ではなく
        // TBR.tt 相当の状態から読む。
        let tt = env.backend.get(sem::tt_ref());
        match tt {
            // ta 0x10（sparc32 syscall）と ta 0x6d（sparc64 syscall）。
            0x90 | 0x16d => self.syscall(env),
            // ta 3（flushw）。窓の退避を全部行ってから次へ進む。
            0x83 | 0x103 => self.do_flushw(env),
            // ta 0x6e（sparc64 getcontext）。ucontext をユーザ
            // メモリに書き、トラップ命令の次へ進む。
            0x16e => {
                if is_v9(env) {
                    self.do_getcontext(env)
                } else {
                    TrapOutcome::Unimplemented
                }
            }
            // V8 の window_overflow。V9 は spill_*_normal（0x80–0x9f）。
            0x05 => {
                if is_v9(env) {
                    TrapOutcome::Unimplemented
                } else {
                    self.do_win_overflow(env)
                }
            }
            // V8 の window_underflow。V9 は fill_*_normal（0xc0–0xdf）。
            0x06 => {
                if is_v9(env) {
                    TrapOutcome::Unimplemented
                } else {
                    self.do_win_underflow(env)
                }
            }
            0x80..=0x9f => {
                if is_v9(env) {
                    self.do_win_overflow(env)
                } else {
                    TrapOutcome::Unimplemented
                }
            }
            0xc0..=0xdf => {
                if is_v9(env) {
                    self.do_win_underflow(env)
                } else {
                    TrapOutcome::Unimplemented
                }
            }
            _ => TrapOutcome::Unimplemented,
        }
    }
}

impl Linux {
    /// `ta 0x10`/`ta 0x6d` からの syscall 処理。番号と引数を
    /// ウィンドウ越しに読み、結果を %o0 とキャリー flag に書く。
    fn syscall(&mut self, env: &mut BareEnv) -> TrapOutcome {
        let nr = reg(env, 1) & if is_v9(env) { u64::MAX } else { 0xffff_ffff };
        if trace() {
            let name = sparc::name(nr).unwrap_or("?");
            eprintln!(
                "sys {nr} {name} o0={:#x} o1={:#x} o2={:#x} o3={:#x} o4={:#x} o5={:#x}",
                self.arg(env, 0),
                self.arg(env, 1),
                self.arg(env, 2),
                self.arg(env, 3),
                self.arg(env, 4),
                self.arg(env, 5),
            );
        }
        match self.dispatch(env, nr) {
            Disp::Ret(v) => {
                if trace() {
                    eprintln!("  -> {v:#x}");
                }
                if is_err_r(v) {
                    set_carry(env, true);
                    set_reg(env, 8, (v as i64).unsigned_abs());
                } else {
                    set_carry(env, false);
                    set_reg(env, 8, v);
                }
                next_insn(env);
                TrapOutcome::Handled
            }
            Disp::Exit(code) => TrapOutcome::Exit(code),
            Disp::Unimpl => {
                let name = sparc::name(nr).unwrap_or("?");
                if !self.reported.contains(&nr) {
                    self.reported.push(nr);
                    eprintln!("sparc: unimplemented syscall {nr} ({name})");
                }
                set_carry(env, true);
                set_reg(env, 8, u64::from(sparc::errno::ENOSYS));
                next_insn(env);
                TrapOutcome::Handled
            }
        }
    }

    /// ソケット系 syscall を `sock` 正準層へ委譲する（socketcall
    /// 副番号の展開を含む）。errno は SunOS 系の独自値へ写し、
    /// SO_* も独自系。ポインタ幅は v8=4・v9=8。待ち要求は
    /// 単一スレッド消化で進め、進行不能はデッドロックとして報告。
    fn sock_call(&mut self, env: &mut BareEnv, n: u64, args: &[u64; 6]) -> Disp {
        let Some(name) = sparc::name(n) else {
            return fail_ret(sparc::errno::ENOSYS);
        };
        let mut abi = crate::sock::SockAbi::generic(if is_v9(env) { 8 } else { 4 }, Endian::Be);
        abi.errno = |e| host_errno(e as i32);
        abi.so_to_host = crate::sock::so_odd_to_host;
        let map = crate::sock::unix_path_map("", &self.cwd);
        let t0 = std::time::Instant::now();
        let mono = move || t0.elapsed().as_nanos() as u64;
        match crate::sock::drive(&mut self.fds, &abi, env, name, args, &map, 0, &mono) {
            Some(Ok(v)) => ok_ret(v),
            Some(Err(e)) => {
                if e == crate::sock::errno::EDEADLK {
                    eprintln!("sparc: deadlock in fd wait");
                }
                fail_ret((abi.errno)(e))
            }
            None => fail_ret(sparc::errno::ENOSYS),
        }
    }

    /// 番号で振り分ける。戻り値は Disp で返し、%o0 は syscall が書く。
    #[allow(clippy::too_many_lines)]
    fn dispatch(&mut self, env: &mut BareEnv, n: u64) -> Disp {
        use sparc::errno as E;
        use sparc::nr as N;
        let args: [u64; 6] = std::array::from_fn(|i| self.arg(env, i));
        match n {
            // ---- プロセス ----
            N::EXIT | N::EXIT_GROUP => Disp::Exit((args[0] & 0xff) as u32),
            N::FORK | N::VFORK | N::CLONE | N::CLONE3 | N::EXECVE | N::EXECVEAT => {
                fail_ret(E::ENOSYS)
            }
            // waitpid 相当。子を作れないので常に ECHILD。
            N::WAIT4 | N::WAITID | N::WAITPID => fail_ret(E::ECHILD),
            N::GETPID | N::GETTID => ok_ret(self.pid()),
            N::GETPPID => ok_ret(0),
            N::GETPGRP | N::GETPGID | N::GETSID => ok_ret(self.pid()),
            N::SETPGID => ok_ret(0),
            N::SETSID => ok_ret(self.pid()),
            N::GETUID
            | N::GETEUID
            | N::GETGID
            | N::GETEGID
            | N::GETUID32
            | N::GETEUID32
            | N::GETGID32
            | N::GETEGID32 => ok_ret(0),
            N::GETGROUPS | N::GETGROUPS32 => ok_ret(0),
            N::SETGROUPS | N::SETGROUPS32 => ok_ret(0),
            N::GETRESUID | N::GETRESGID => {
                // (ruid, euid, suid) をポインタ幅で三語書く。
                for a in args.iter().take(3) {
                    if !self.put_u(env, *a, 0) {
                        return fail_ret(E::EFAULT);
                    }
                }
                ok_ret(0)
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
            | N::SETFSUID32
            | N::SETFSGID32 => ok_ret(0),
            // ---- ファイル I/O ----
            N::READ => Disp::Ret(self.do_read(env, args[0] as u32, args[1], args[2])),
            N::PREAD64 => {
                // pread64(fd, buf, len, pos)。sparc32 は pos が o4:o5。
                let off = self.arg64(env, 3);
                Disp::Ret(self.do_pread(env, args[0] as u32, args[1], args[2], off))
            }
            N::PWRITE64 => {
                let off = self.arg64(env, 3);
                Disp::Ret(self.do_pwrite(env, args[0] as u32, args[1], args[2], off))
            }
            N::WRITE => Disp::Ret(self.do_write(env, args[0] as u32, args[1], args[2])),
            N::READV => Disp::Ret(self.do_readv(env, args[0] as u32, args[1], args[2])),
            N::WRITEV => Disp::Ret(self.do_writev(env, args[0] as u32, args[1], args[2])),
            N::SENDFILE | N::SENDFILE64 => {
                Disp::Ret(self.do_sendfile(env, args[0] as u32, args[1] as u32, args[2], args[3]))
            }
            N::OPEN => Disp::Ret(self.do_open(env, args[0], args[1] as u32, args[2] as u32)),
            N::OPENAT => {
                if args[0] as i32 != -100 {
                    return fail_ret(E::EBADF);
                }
                Disp::Ret(self.do_open(env, args[1], args[2] as u32, args[3] as u32))
            }
            N::CREAT => {
                let flags = sparc::oflag::CREAT | sparc::oflag::TRUNC | 1;
                Disp::Ret(self.do_open(env, args[0], flags, args[1] as u32))
            }
            N::CLOSE => {
                let fd = args[0] as u32;
                if fd < 3 {
                    return ok_ret(0);
                }
                if self.fds.ent(fd).is_some() {
                    self.fds.clear(fd);
                    self.dir_pos.remove(&fd);
                    ok_ret(0)
                } else {
                    fail_ret(E::EBADF)
                }
            }
            N::LSEEK => {
                let off = if is_v9(env) {
                    args[1] as i64
                } else {
                    i64::from(args[1] as u32 as i32)
                };
                Disp::Ret(self.do_lseek(env, args[0] as u32, off, args[2] as u32))
            }
            N::LLSEEK => {
                // _llseek(fd, hi, lo, result_ptr, whence)
                let fd = args[0] as u32;
                let off = (args[1] << 32) | (args[2] & 0xffff_ffff);
                let ptr = args[3];
                let wh = args[4] as u32;
                let f = match self.file_of(fd) {
                    Ok(f) => f,
                    Err(e) => return fail_ret(e),
                };
                let w = match wh {
                    0 => SeekFrom::Start(off),
                    1 => SeekFrom::Current(off as i64),
                    2 => SeekFrom::End(off as i64),
                    _ => return fail_ret(E::EINVAL),
                };
                match f.seek(w) {
                    Ok(p) => {
                        if self.put64(env, ptr, p) {
                            ok_ret(0)
                        } else {
                            fail_ret(E::EFAULT)
                        }
                    }
                    Err(e) => fail_ret_host(e.raw_os_error().unwrap_or(E::EIO as i32)),
                }
            }
            // ---- stat 系 ----
            N::STAT => {
                Disp::Ret(self.do_stat(env, None, Some(args[0]), args[1], false, StatFmt::Stat))
            }
            N::STAT64 => {
                Disp::Ret(self.do_stat(env, None, Some(args[0]), args[1], false, StatFmt::Stat64))
            }
            N::LSTAT | N::OLDLSTAT => {
                Disp::Ret(self.do_stat(env, None, Some(args[0]), args[1], true, StatFmt::Stat))
            }
            N::LSTAT64 => {
                Disp::Ret(self.do_stat(env, None, Some(args[0]), args[1], true, StatFmt::Stat64))
            }
            N::FSTAT => Disp::Ret(self.do_stat(
                env,
                Some(args[0] as u32),
                None,
                args[1],
                false,
                StatFmt::Stat,
            )),
            N::FSTAT64 => Disp::Ret(self.do_stat(
                env,
                Some(args[0] as u32),
                None,
                args[1],
                false,
                StatFmt::Stat64,
            )),
            N::FSTATAT64 => {
                if args[0] as i32 != -100 {
                    return fail_ret(E::EBADF);
                }
                let lstat = args[3] & 0x100 != 0; // AT_SYMLINK_NOFOLLOW
                Disp::Ret(self.do_stat(env, None, Some(args[1]), args[2], lstat, StatFmt::Stat64))
            }
            N::STATX => {
                // statx(dirfd, path, flags, mask, buf)
                let dirfd = args[0] as i32;
                let lstat = args[2] & 0x100 != 0;
                if dirfd == -100 {
                    Disp::Ret(self.do_stat(
                        env,
                        None,
                        Some(args[1]),
                        args[4],
                        lstat,
                        StatFmt::Statx,
                    ))
                } else if dirfd >= 0 && args[2] & 0x1000 != 0 {
                    // 実 fd + AT_EMPTY_PATH(0x1000) + 空 path は fd 自身
                    // の fstat。dirfd 相対のパス解決は未対応。
                    match self.read_cstr(env, args[1]) {
                        Ok(p) if p.is_empty() => Disp::Ret(self.do_stat(
                            env,
                            Some(dirfd as u32),
                            None,
                            args[4],
                            lstat,
                            StatFmt::Statx,
                        )),
                        Ok(_) => fail_ret(E::ENOSYS),
                        Err(e) => fail_ret(e),
                    }
                } else {
                    fail_ret(E::EBADF)
                }
            }
            // ---- アクセス・属性 ----
            N::ACCESS => {
                let path = match self.read_cstr(env, args[0]) {
                    Ok(p) => p,
                    Err(e) => return fail_ret(e),
                };
                match polyisa_host::stat(&self.host_path(&path)) {
                    Ok(_) => ok_ret(0),
                    Err(e) => fail_ret_host(e.raw_os_error().unwrap_or(E::EIO as i32)),
                }
            }
            N::FACCESSAT | N::FACCESSAT2 => {
                if args[0] as i32 != -100 {
                    return fail_ret(E::EBADF);
                }
                let path = match self.read_cstr(env, args[1]) {
                    Ok(p) => p,
                    Err(e) => return fail_ret(e),
                };
                match polyisa_host::stat(&self.host_path(&path)) {
                    Ok(_) => ok_ret(0),
                    Err(e) => fail_ret_host(e.raw_os_error().unwrap_or(E::EIO as i32)),
                }
            }
            N::CHMOD | N::FCHMOD | N::FCHMODAT | N::FCHMODAT2 => ok_ret(0),
            N::CHOWN
            | N::FCHOWN
            | N::LCHOWN
            | N::FCHOWNAT
            | N::LCHOWN32
            | N::FCHOWN32
            | N::CHOWN32 => ok_ret(0),
            // ---- ディレクトリと名前 ----
            N::GETDENTS64 => Disp::Ret(self.do_getdents64(env, args[0] as u32, args[1], args[2])),
            N::GETDENTS => fail_ret(E::ENOSYS),
            N::GETCWD => {
                let cwd = if self.cwd.is_empty() {
                    std::env::current_dir()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_else(|_| "/".to_string())
                } else {
                    self.cwd.clone()
                };
                let b = cwd.as_bytes();
                if args[1] == 0 {
                    return fail_ret(E::EINVAL);
                }
                let n = (b.len() + 1).min(args[1] as usize);
                match self.write_bytes(env, args[0], &b[..n.min(b.len())]) {
                    Ok(()) => {
                        let _ = self.write_bytes(env, args[0].wrapping_add((n - 1) as u64), &[0]);
                        ok_ret(n as u64)
                    }
                    Err(e) => fail_ret(e),
                }
            }
            N::CHDIR => {
                let path = match self.read_cstr(env, args[0]) {
                    Ok(p) => p,
                    Err(e) => return fail_ret(e),
                };
                let host = self.host_path(&path);
                if polyisa_host::stat(&host)
                    .map(|m| m.mode & 0o170000 == 0o040000)
                    .unwrap_or(false)
                {
                    self.cwd = host;
                    ok_ret(0)
                } else {
                    fail_ret(E::ENOENT)
                }
            }
            N::FCHDIR => ok_ret(0),
            N::MKDIR | N::MKDIRAT => {
                let idx = if n == N::MKDIR { 0 } else { 1 };
                let path = match self.read_cstr(env, args[idx]) {
                    Ok(p) => p,
                    Err(e) => return fail_ret(e),
                };
                match std::fs::create_dir(self.host_path(&path)) {
                    Ok(()) => ok_ret(0),
                    Err(e) => fail_ret_host(e.raw_os_error().unwrap_or(E::EIO as i32)),
                }
            }
            N::RMDIR => {
                let path = match self.read_cstr(env, args[0]) {
                    Ok(p) => p,
                    Err(e) => return fail_ret(e),
                };
                match std::fs::remove_dir(self.host_path(&path)) {
                    Ok(()) => ok_ret(0),
                    Err(e) => fail_ret_host(e.raw_os_error().unwrap_or(E::EIO as i32)),
                }
            }
            N::UNLINK | N::UNLINKAT => {
                let idx = if n == N::UNLINK { 0 } else { 1 };
                let path = match self.read_cstr(env, args[idx]) {
                    Ok(p) => p,
                    Err(e) => return fail_ret(e),
                };
                match std::fs::remove_file(self.host_path(&path)) {
                    Ok(()) => ok_ret(0),
                    Err(e) => fail_ret_host(e.raw_os_error().unwrap_or(E::EIO as i32)),
                }
            }
            N::RENAME | N::RENAMEAT | N::RENAMEAT2 => {
                let (a, b) = if n == N::RENAME {
                    (args[0], args[1])
                } else {
                    (args[1], args[3])
                };
                let from = match self.read_cstr(env, a) {
                    Ok(p) => p,
                    Err(e) => return fail_ret(e),
                };
                let to = match self.read_cstr(env, b) {
                    Ok(p) => p,
                    Err(e) => return fail_ret(e),
                };
                match std::fs::rename(self.host_path(&from), self.host_path(&to)) {
                    Ok(()) => ok_ret(0),
                    Err(e) => fail_ret_host(e.raw_os_error().unwrap_or(E::EIO as i32)),
                }
            }
            N::LINK | N::LINKAT => {
                // link(old,new) / linkat(olddirfd,old,newdirfd,new,flags)。
                // AT_FDCWD 以外の dirfd は未対応。
                let (a, b) = if n == N::LINK {
                    (args[0], args[1])
                } else {
                    if args[0] as i32 != -100 || args[2] as i32 != -100 {
                        return fail_ret(E::EBADF);
                    }
                    (args[1], args[3])
                };
                let from = match self.read_cstr(env, a) {
                    Ok(p) => p,
                    Err(e) => return fail_ret(e),
                };
                let to = match self.read_cstr(env, b) {
                    Ok(p) => p,
                    Err(e) => return fail_ret(e),
                };
                match std::fs::hard_link(self.host_path(&from), self.host_path(&to)) {
                    Ok(()) => ok_ret(0),
                    Err(e) => fail_ret_host(e.raw_os_error().unwrap_or(E::EIO as i32)),
                }
            }
            N::SYMLINK | N::SYMLINKAT => {
                let (a, b) = if n == N::SYMLINK {
                    (args[0], args[1])
                } else {
                    (args[0], args[2])
                };
                let from = match self.read_cstr(env, a) {
                    Ok(p) => p,
                    Err(e) => return fail_ret(e),
                };
                let to = match self.read_cstr(env, b) {
                    Ok(p) => p,
                    Err(e) => return fail_ret(e),
                };
                match polyisa_host::symlink(&String::from_utf8_lossy(&from), &self.host_path(&to)) {
                    Ok(()) => ok_ret(0),
                    Err(e) => fail_ret_host(e.raw_os_error().unwrap_or(E::EIO as i32)),
                }
            }
            N::READLINK => Disp::Ret(self.do_readlink(env, args[0], args[1], args[2])),
            N::READLINKAT => {
                if args[0] as i32 != -100 {
                    return fail_ret(E::EBADF);
                }
                Disp::Ret(self.do_readlink(env, args[1], args[2], args[3]))
            }
            N::TRUNCATE | N::TRUNCATE64 | N::FTRUNCATE | N::FTRUNCATE64 => match n {
                N::TRUNCATE | N::TRUNCATE64 => {
                    let path = match self.read_cstr(env, args[0]) {
                        Ok(p) => p,
                        Err(e) => return fail_ret(e),
                    };
                    // sparc32 の len は 64 ビット引数（o2:o3）。
                    let len = if n == N::TRUNCATE {
                        args[1]
                    } else {
                        self.arg64(env, 1)
                    };
                    match std::fs::OpenOptions::new()
                        .write(true)
                        .open(self.host_path(&path))
                        .and_then(|f| f.set_len(len))
                    {
                        Ok(()) => ok_ret(0),
                        Err(e) => fail_ret_host(e.raw_os_error().unwrap_or(E::EIO as i32)),
                    }
                }
                _ => {
                    let fd = args[0] as u32;
                    let len = if n == N::FTRUNCATE {
                        args[1]
                    } else {
                        self.arg64(env, 1)
                    };
                    match self.file_of(fd).and_then(|f| {
                        f.set_len(len).map_err(|_| sparc::errno::EIO)?;
                        Ok(())
                    }) {
                        Ok(()) => ok_ret(0),
                        Err(e) => fail_ret(e),
                    }
                }
            },
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
            | N::SWAPON
            | N::SWAPOFF
            | N::SETDOMAINNAME
            | N::SETHOSTNAME => fail_ret(E::EPERM),
            N::UMASK => {
                let old = self.umask;
                self.umask = args[0] as u32 & 0o777;
                ok_ret(u64::from(old))
            }
            // ---- ディスクリプタ操作 ----
            N::DUP => match self.fds.file(args[0] as u32) {
                Some(f) => match f.try_clone() {
                    Ok(g) => {
                        let nfd = self.fds.alloc(polyisa_kernel::FdTarget::File(g));
                        let p = self.fds.path_of(args[0] as u32).map(str::to_string);
                        if let Some(p) = p {
                            self.fds.remember_path(nfd, p);
                        }
                        ok_ret(u64::from(nfd))
                    }
                    Err(e) => fail_ret_host(e.raw_os_error().unwrap_or(E::EIO as i32)),
                },
                None => fail_ret(E::EBADF),
            },
            N::DUP2 | N::DUP3 => {
                let (old, new) = (args[0] as u32, args[1] as u32);
                if old == new {
                    return ok_ret(u64::from(new));
                }
                let p = self.fds.path_of(old).map(str::to_string);
                let g = match self.fds.file(old).and_then(|f| f.try_clone().ok()) {
                    Some(g) => g,
                    None => return fail_ret(E::EBADF),
                };
                self.fds.place_close(new, polyisa_kernel::FdTarget::File(g));
                if let Some(p) = p {
                    self.fds.remember_path(new, p);
                }
                ok_ret(u64::from(new))
            }
            N::FCNTL | N::FCNTL64 => {
                Disp::Ret(self.do_fcntl(env, args[0] as u32, args[1] as u32, args[2]))
            }
            N::IOCTL => Disp::Ret(self.do_ioctl(env, args[0] as u32, args[1], args[2])),
            N::PIPE | N::PIPE2 => fail_ret(E::ENOSYS),
            // ---- メモリ ----
            N::BRK => Disp::Ret(self.do_brk(env, args[0])),
            N::MMAP => Disp::Ret(self.do_mmap(env, &args, false)),
            N::MMAP2 => Disp::Ret(self.do_mmap(env, &args, true)),
            N::MUNMAP => {
                let pages = args[1].div_ceil(4096);
                env.backend.mem.unmap(VirtAddr(args[0] & !0xfff), pages);
                ok_ret(0)
            }
            N::MPROTECT => {
                let mut p = 0u8;
                if args[2] & sparc::prot::READ != 0 {
                    p |= Perms::R.0;
                }
                if args[2] & sparc::prot::WRITE != 0 {
                    p |= Perms::W.0;
                }
                if args[2] & sparc::prot::EXEC != 0 {
                    p |= Perms::X.0;
                }
                let pages = args[1].div_ceil(4096);
                match env
                    .backend
                    .mem
                    .protect(VirtAddr(args[0] & !0xfff), pages, Perms(p))
                {
                    Ok(()) => ok_ret(0),
                    Err(_) => fail_ret(E::ENOMEM),
                }
            }
            N::UNAME => Disp::Ret(self.do_uname(env, args[0])),
            N::GETPAGESIZE => ok_ret(4096),
            N::SYSINFO => Disp::Ret(self.do_sysinfo(env, args[0])),
            N::MREMAP => fail_ret(E::ENOMEM),
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
            | N::FALLOCATE => ok_ret(0),
            // ---- 時間 ----
            N::TIME => {
                let secs = now_secs();
                let tp = args[0];
                if tp != 0 && !self.put_u(env, tp, secs) {
                    return fail_ret(E::EFAULT);
                }
                ok_ret(secs)
            }
            N::GETTIMEOFDAY => {
                let (sec, usec) = now_us();
                let ws = wsize(env);
                let mut ok = true;
                ok &= self.put_u(env, args[0], sec);
                ok &= self.put_u(env, args[0] + ws, usec);
                if ok { ok_ret(0) } else { fail_ret(E::EFAULT) }
            }
            N::SETTIMEOFDAY => ok_ret(0),
            N::CLOCK_GETTIME | N::CLOCK_GETTIME64 => {
                let mono = args[0] == 1; // CLOCK_MONOTONIC
                let (sec, nsec) = if mono {
                    let us = self.mono_us();
                    (us / 1_000_000, (us % 1_000_000) * 1000)
                } else {
                    now_ns()
                };
                if n == N::CLOCK_GETTIME {
                    if self.put_timespec(env, args[1], sec, nsec) {
                        ok_ret(0)
                    } else {
                        fail_ret(E::EFAULT)
                    }
                } else {
                    // time64 形式：i64 sec + i64 nsec。
                    let ok = self.put64(env, args[1], sec) && self.put64(env, args[1] + 8, nsec);
                    if ok { ok_ret(0) } else { fail_ret(E::EFAULT) }
                }
            }
            N::CLOCK_GETRES | N::CLOCK_GETRES_TIME64 => {
                if n == N::CLOCK_GETRES {
                    if self.put_timespec(env, args[1], 0, 1) {
                        ok_ret(0)
                    } else {
                        fail_ret(E::EFAULT)
                    }
                } else {
                    let ok = self.put64(env, args[1], 0) && self.put64(env, args[1] + 8, 1);
                    if ok { ok_ret(0) } else { fail_ret(E::EFAULT) }
                }
            }
            N::CLOCK_SETTIME | N::CLOCK_SETTIME64 | N::CLOCK_ADJTIME | N::ADJTIMEX => ok_ret(0),
            N::NANOSLEEP | N::CLOCK_NANOSLEEP | N::CLOCK_NANOSLEEP_TIME64 => ok_ret(0),
            N::TIMES => {
                // tms { utime, stime, cutime, cstime }、ポインタ幅の語×4。
                let ws = wsize(env);
                let mut ok = true;
                for i in 0..4 {
                    ok &= self.put_u(env, args[0] + i * ws, 0);
                }
                if ok {
                    ok_ret(self.mono_us() / 10_000)
                } else {
                    fail_ret(E::EFAULT)
                }
            }
            N::UTIME | N::UTIMES | N::UTIMENSAT | N::UTIMENSAT_TIME64 | N::FUTIMESAT => ok_ret(0),
            // ---- 資源 ----
            N::GETRLIMIT => {
                // rlimit { cur, max }、ポインタ幅の語×2。RLIMIT_INFINITY 相当。
                let ws = wsize(env);
                let inf = if is_v9(env) {
                    u64::MAX
                } else {
                    u64::from(u32::MAX)
                };
                let mut ok = true;
                ok &= self.put_u(env, args[1], inf);
                ok &= self.put_u(env, args[1] + ws, inf);
                if ok { ok_ret(0) } else { fail_ret(E::EFAULT) }
            }
            N::PRLIMIT64 => {
                // rlimit64 { u64 cur, u64 max }。
                if args[3] != 0 {
                    let mut ok = true;
                    ok &= self.put64(env, args[3], u64::MAX);
                    ok &= self.put64(env, args[3] + 8, u64::MAX);
                    if !ok {
                        return fail_ret(E::EFAULT);
                    }
                }
                ok_ret(0)
            }
            N::SETRLIMIT => ok_ret(0),
            N::GETRUSAGE => {
                if args[1] != 0 {
                    let _ = self.put_u(env, args[1], 0);
                }
                ok_ret(0)
            }
            // getpriority(which, who) は nice 値を返す。最小権限の 20 を返す。
            N::GETPRIORITY => ok_ret(20),
            N::SETPRIORITY | N::NICE => ok_ret(0),
            N::SCHED_SETPARAM | N::SCHED_SETSCHEDULER | N::SCHED_YIELD => ok_ret(0),
            N::SCHED_GETPARAM | N::SCHED_GETSCHEDULER => {
                if args[1] != 0 {
                    let _ = self.put_u(env, args[1], 0);
                }
                ok_ret(0)
            }
            N::SCHED_GET_PRIORITY_MAX => ok_ret(99),
            N::SCHED_GET_PRIORITY_MIN => ok_ret(1),
            N::SCHED_RR_GET_INTERVAL | N::SCHED_RR_GET_INTERVAL_TIME64 => {
                let _ = self.put_timespec(env, args[1], 0, 1_000_000);
                ok_ret(0)
            }
            N::SCHED_SETAFFINITY | N::SCHED_SET_AFFINITY => ok_ret(0),
            N::SCHED_GETAFFINITY | N::SCHED_GET_AFFINITY => {
                // cpu0 だけのマスク。
                let mut b = vec![0u8; args[1].min(128) as usize];
                b[0] = 1;
                match self.write_bytes(env, args[2], &b) {
                    Ok(()) => ok_ret(0),
                    Err(e) => fail_ret(e),
                }
            }
            N::GETCPU => {
                if args[0] != 0 {
                    let _ = self.put32(env, args[0], 0);
                }
                if args[1] != 0 {
                    let _ = self.put32(env, args[1], 0);
                }
                ok_ret(0)
            }
            N::IOPRIO_SET => ok_ret(0),
            N::IOPRIO_GET => ok_ret(0),
            N::GETITIMER | N::SETITIMER | N::ALARM => ok_ret(0),
            // ---- シグナル（受け付けるだけ）----
            N::SIGACTION
            | N::RT_SIGACTION
            | N::SIGPROCMASK
            | N::RT_SIGPROCMASK
            | N::SIGPENDING
            | N::RT_SIGPENDING
            | N::SIGSUSPEND
            | N::RT_SIGSUSPEND
            | N::RT_SIGTIMEDWAIT
            | N::RT_SIGQUEUEINFO
            | N::SIGALTSTACK
            | N::RT_TGSIGQUEUEINFO
            | N::SIGNAL
            | N::SGETMASK
            | N::SSETMASK
            | N::SIGNALFD
            | N::SIGNALFD4 => ok_ret(0),
            N::RT_SIGRETURN | N::SIGRETURN => ok_ret(0),
            N::KILL | N::TKILL | N::TGKILL => {
                if args[0] == 0 || args[0] == self.pid {
                    ok_ret(0)
                } else {
                    fail_ret(E::ESRCH)
                }
            }
            // ---- スレッド・同期 ----
            N::FUTEX | N::FUTEX_TIME64 => {
                // 単一スレッド。WAKE は 0、WAIT は即抜け。
                ok_ret(0)
            }
            N::SET_TID_ADDRESS => {
                let pid = self.pid() as u32;
                if args[0] != 0 {
                    let _ = self.put32(env, args[0], pid);
                }
                ok_ret(u64::from(pid))
            }
            N::SET_ROBUST_LIST => ok_ret(0),
            N::GET_ROBUST_LIST => fail_ret(E::ENOSYS),
            // ---- 選択・poll ----
            N::SELECT
            | N::NEWSELECT
            | N::POLL
            | N::PSELECT6
            | N::PSELECT6_TIME64
            | N::PPOLL
            | N::PPOLL_TIME64 => ok_ret(0), // 即時「準備なし」。fd 群の健全性は見ない。
            N::PAUSE => ok_ret(0),
            // ---- ファイルシステム情報 ----
            N::STATFS => Disp::Ret(self.do_statfs(env, args[1], false)),
            N::FSTATFS => Disp::Ret(self.do_statfs(env, args[1], false)),
            N::STATFS64 => Disp::Ret(self.do_statfs(env, args[2], true)),
            N::FSTATFS64 => Disp::Ret(self.do_statfs(env, args[2], true)),
            N::USTAT => ok_ret(0),
            // ---- 属性拡張 ----
            N::SETXATTR | N::LSETXATTR | N::FSETXATTR => ok_ret(0),
            N::GETXATTR
            | N::LGETXATTR
            | N::FGETXATTR
            | N::LISTXATTR
            | N::LLISTXATTR
            | N::FLISTXATTR => fail_ret(E::ENOTSUP),
            N::REMOVEXATTR | N::LREMOVEXATTR | N::FREMOVEXATTR => ok_ret(0),
            // ---- 認証・機能 ----
            N::CAPGET | N::CAPSET => ok_ret(0),
            N::PERSONALITY => ok_ret(0),
            N::PRCTL | N::SECCOMP => ok_ret(0),
            N::SYSLOG
            | N::QUOTACTL
            | N::PTRACE
            | N::USELIB
            | N::VHANGUP
            | N::SYSFS
            | N::BDFLUSH
            | N::NFSSERVCTL
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
            | N::PIDFD_GETFD
            | N::PIDFD_SEND_SIGNAL
            | N::CLOSE_RANGE
            | N::OPENAT2
            | N::PROCESS_MADVISE
            | N::EPOLL_PWAIT2
            | N::FUTEX_WAITV
            | N::KCMP
            | N::PROCESS_VM_READV
            | N::PROCESS_VM_WRITEV
            | N::SETNS
            | N::FANOTIFY_INIT
            | N::FANOTIFY_MARK
            | N::NAME_TO_HANDLE_AT
            | N::OPEN_BY_HANDLE_AT
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
            | N::IO_PGETEVENTS
            | N::IO_PGETEVENTS_TIME64
            | N::MEMBARRIER
            | N::RSEQ
            | N::RSEQ_SLICE_YIELD
            | N::COPY_FILE_RANGE
            | N::SPLICE
            | N::TEE
            | N::VMSPLICE
            | N::PKEY_MPROTECT
            | N::PKEY_ALLOC
            | N::PKEY_FREE
            | N::MEMFD_CREATE
            | N::FINIT_MODULE
            | N::SCHED_SETATTR
            | N::SCHED_GETATTR
            | N::SENDMMSG
            | N::RECVMMSG
            | N::RECVMMSG_TIME64
            | N::SEMTIMEDOP
            | N::SEMTIMEDOP_TIME64
            | N::IPC
            | N::QUERY_MODULE
            | N::CREATE_MODULE
            | N::GET_KERNEL_SYMS
            | N::AFS_SYSCALL
            | N::SYSCTL
            | N::VSERVER
            | N::PERFCTR
            | N::PCICONFIG_READ
            | N::PCICONFIG_WRITE
            | N::UTRAP_INSTALL
            | N::MEMORY_ORDERING
            | N::KERN_FEATURES
            | N::READDIR
            | N::EXECV
            | N::GETDOMAINNAME
            | N::LANDLOCK_CREATE_RULESET
            | N::LANDLOCK_ADD_RULE
            | N::LANDLOCK_RESTRICT_SELF
            | N::PROCESS_MRELEASE
            | N::SET_MEMPOLICY_HOME_NODE
            | N::CACHESTAT
            | N::MAP_SHADOW_STACK
            | N::FUTEX_WAKE
            | N::FUTEX_WAIT
            | N::FUTEX_REQUEUE
            | N::STATMOUNT
            | N::LISTMOUNT
            | N::LSM_GET_SELF_ATTR
            | N::LSM_SET_SELF_ATTR
            | N::LSM_LIST_MODULES
            | N::MSEAL
            | N::SETXATTRAT
            | N::GETXATTRAT
            | N::LISTXATTRAT
            | N::REMOVEXATTRAT
            | N::OPEN_TREE_ATTR
            | N::FILE_GETATTR
            | N::FILE_SETATTR
            | N::LISTNS
            | N::FCHROOT
            | N::RESTART_SYSCALL => fail_ret(E::ENOSYS),
            // ---- ソケット・イベント ----
            N::SOCKETCALL
            | N::SOCKET
            | N::BIND
            | N::CONNECT
            | N::LISTEN
            | N::GETSOCKNAME
            | N::GETPEERNAME
            | N::SOCKETPAIR
            | N::SENDTO
            | N::RECVFROM
            | N::SHUTDOWN
            | N::SETSOCKOPT
            | N::GETSOCKOPT
            | N::SENDMSG
            | N::RECVMSG
            | N::ACCEPT
            | N::ACCEPT4 => self.sock_call(env, n, &args),
            N::SEMGET
            | N::SEMCTL
            | N::MSGSND
            | N::MSGRCV
            | N::MSGGET
            | N::MSGCTL
            | N::SHMAT
            | N::SHMDT
            | N::SHMGET
            | N::SHMCTL => fail_ret(E::ENOSYS),
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
            | N::RT_SIGTIMEDWAIT_TIME64
            | N::STIME => fail_ret(E::ENOSYS),
            // ---- 同期・その他成功系 ----
            N::SYNC | N::FSYNC | N::FDATASYNC | N::SYNCFS | N::FLOCK => ok_ret(0),
            N::GETRANDOM => Disp::Ret(self.do_getrandom(env, args[0], args[1])),
            _ => Disp::Unimpl,
        }
    }
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
