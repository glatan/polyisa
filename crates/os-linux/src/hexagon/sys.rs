// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Hexagon Linux の syscall 処理（段階22 HX11）。
//!
//! 規約（正本 `kernel-asm/syscall.h`・`vm_entry.S`）: 発行点は
//! `trap0(#1)`（trap code 1）。番号は r6、引数は r0-r5、戻り値は
//! r0、失敗は r0 = -errno（32 ビット）。nr62 `sys_llseek`、nr222
//! `sys_mmap_pgoff`（pgoff 単位）、nr79/80 `fstatat64`/`fstat64`
//! （asm-generic `struct stat64`・time32・104 バイト・LE）。
//! nr84 `sys_sync_file_range2`、nr223 `sys_hexagon_fadvise64_64`。
//!
//! 単一プロセス・単一スレッド模型: clone/execve/wait/パイプ/
//! シグナル配送は未実装（ENOSYS または登録のみ受理 —
//!）。リトルエンディアンのみ。
//! 信頼できないゲストバイナリには使わないこと。
//! Ref: SRC-LINUX-HEXAGON-UAPI.

use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

use polyisa_engine::bare::BareEnv;
use polyisa_guest_hexagon::sem;
use polyisa_kernel::FdTable;
use polyisa_mem::{Access, AccessKind, Align, Endian, PAGE_SIZE, PageNo, Perms, VirtAddr};
use polyisa_sem::Backend as _;

use crate::{TrapHandler, TrapOutcome, hexagon, hexagon::nr};

/// write/writev が集めたバイト。標準出力と標準エラーを分ける。
#[derive(Default)]
pub struct HexagonIo {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// errno。asm-generic の値。
mod errno {
    pub const EPERM: u64 = 1;
    pub const ENOENT: u64 = 2;
    pub const EIO: u64 = 5;
    pub const EBADF: u64 = 9;
    pub const ENOMEM: u64 = 12;
    pub const EACCES: u64 = 13;
    pub const EFAULT: u64 = 14;
    pub const EEXIST: u64 = 17;
    pub const ENOTDIR: u64 = 20;
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
        Some(20) => errno::ENOTDIR,
        _ => errno::EIO,
    }
}

/// Hexagon Linux の syscall 状態機械。
/// r6=番号、r0-r5=引数、r0=戻り値。
pub struct Linux {
    /// 標準出力・標準エラーの捕獲。テストが読む。
    pub io: HexagonIo,
    /// 開いたファイルの表（ゲスト fd 3 以降）。
    fds: FdTable,
    /// プログラムブレーク。0 は未初期化。
    heap_end: u64,
    /// brk 領域の開始（ELF の image_end）。`init_brk` が設定する。
    brk_start: u64,
    /// mmap の次に置く場所。
    mmap_next: u64,
    /// getpid/gettid が返すプロセス識別子。
    pid: u64,
    /// ゲストの作業ディレクトリ。空は "/"（loongarch と同じ近似）。
    cwd: String,
    /// ゲストのルート（`--root`）。空は隔離なし。
    guest_root: String,
    /// 実行ファイルのパス。`readlinkat("/proc/self/exe")` が返す。
    pub exe_path: String,
    /// 標準入力へ供給するバイト。
    pub stdin_buf: Vec<u8>,
    stdin_pos: usize,
    /// syscall バッファが伸ばし得るスタック窓 `[lo, hi)`。
    /// 0/0 は成長しない（root 未指定の旧来動作）。
    stack_lo: u64,
    stack_hi: u64,
    /// getdents64 の fd 毎の読み出し位置（エントリ番号）。
    dir_pos: std::collections::BTreeMap<u32, u64>,
    /// rt_sigprocmask が保持する blocked マスク（配送しない近似 —
    sig_mask: u64,
    /// umask の保持値。
    umask: u32,
    /// MONOTONIC 時計の起点。
    mono_start: Option<std::time::Instant>,
    /// fd 待ちの時計起点。初回の待ちで立ち上げ、呼び出し間で共有。
    wait_start: Option<std::time::Instant>,
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
    /// Hexagon Linux の状態機械を作る。
    #[must_use]
    pub fn new() -> Self {
        Self {
            io: HexagonIo::default(),
            fds: FdTable::default(),
            heap_end: 0,
            brk_start: 0,
            mmap_next: 0x6000_0000,
            pid: std::process::id().into(),
            cwd: String::new(),
            guest_root: String::new(),
            exe_path: String::new(),
            stdin_buf: Vec::new(),
            stdin_pos: 0,
            stack_lo: 0,
            stack_hi: 0,
            dir_pos: std::collections::BTreeMap::new(),
            sig_mask: 0,
            umask: 0o22,
            mono_start: None,
            wait_start: None,
            reported: Vec::new(),
        }
    }

    /// syscall のバッファアクセスが伸ばし得るスタック窓を設定する。
    /// ローダが `Growth` に渡す `[limit, top)` と同じ範囲。
    pub fn set_stack_window(&mut self, lo: u64, hi: u64) {
        self.stack_lo = lo;
        self.stack_hi = hi;
    }

    /// `[addr, addr+len)` の未マップページをスタック窓の中で割付る。
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

    /// ゲストのルートを設定する（`--root`・テストの chroot 相当）。
    pub fn set_guest_root(&mut self, root: &str) {
        self.guest_root = root.to_string();
    }

    /// アクセス属性（常に LE・非整列許容）。
    fn acc(&self, kind: AccessKind) -> Access {
        Access {
            endian: Endian::Le,
            align: Align::Unaligned,
            kind,
        }
    }

    /// r`i` を読む（32 ビットレジスタを u64 へゼロ拡張）。
    fn rget(&self, env: &mut BareEnv, i: u32) -> u64 {
        u64::from(env.backend.get(sem::r_ref(i)))
    }

    /// r`i` へ書く（32 ビットに折り返す）。
    fn rset(&self, env: &mut BareEnv, i: u32, v: u64) {
        env.backend.set(sem::r_ref(i), (v & 0xffff_ffff) as u32);
    }

    /// 戻り値の約束: 成功は値、失敗は -errno（r0・32 ビット）。
    /// Ref: SRC-LINUX-HEXAGON-UAPI — kernel-asm/syscall.h
    /// （syscall_get_return_value は r00、IS_ERR_VALUE で失敗判定）。
    fn ret(&self, env: &mut BareEnv, r: Result<u64, u64>) {
        let v = match r {
            Ok(v) => v & 0xffff_ffff,
            Err(e) => (0u64.wrapping_sub(e)) & 0xffff_ffff,
        };
        self.rset(env, 0, v);
    }

    /// ゲストメモリから `n` バイト読む。
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

    /// ゲストメモリへバイト列を書く。
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

    /// ゲストの u32 を読む（LE）。
    fn mem_u32(&self, env: &mut BareEnv, addr: u64) -> u32 {
        let b = self.get_bytes(env, addr, 4).unwrap_or_default();
        u32::from_le_bytes(b[..4].try_into().unwrap_or([0; 4]))
    }

    /// ゲストの u32 を書く（LE）。
    fn put_u32(&self, env: &mut BareEnv, addr: u64, v: u32) -> Result<(), u64> {
        self.put_bytes(env, addr, &v.to_le_bytes())
    }

    /// ゲストの u64 を書く（LE）。
    fn put_u64(&self, env: &mut BareEnv, addr: u64, v: u64) -> Result<(), u64> {
        self.put_bytes(env, addr, &v.to_le_bytes())
    }

    /// ゲストの u64 を読む（LE）。
    fn mem_u64(&self, env: &mut BareEnv, addr: u64) -> u64 {
        let b = self.get_bytes(env, addr, 8).unwrap_or_default();
        u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8]))
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

    /// ゲストパスをホストパスへ写す。dirfd は AT_FDCWD(-100)
    /// か `remember_path` で覚えたディレクトリ fd。
    /// 最終要素のシンボリックリンクは辿らない。root 配下にノードが
    /// 無い `/dev/*` はホストの devtmpfs へ通す。
    fn host_path(&self, dirfd: u64, path: &str) -> Option<String> {
        // dirfd は 32 ビットレジスタ値（AT_FDCWD=-100 は 0xffffff9c
        // として届く）。u32 に落として比較する。
        const AT_FDCWD: u32 = (-100i32) as u32;
        let cwd = if self.cwd.is_empty() { "/" } else { &self.cwd };
        if path.starts_with('/') || dirfd as u32 == AT_FDCWD {
            let r = if self.guest_root.is_empty() {
                crate::guest_path::join_guest_path(cwd, path)
            } else {
                crate::guest_path::resolve_guest_path(&self.guest_root, cwd, path)?
            };
            if !self.guest_root.is_empty()
                && path.starts_with("/dev/")
                && !std::path::Path::new(&r).exists()
            {
                return Some(path.to_string());
            }
            return Some(r);
        }
        let dir = self.fds.path_of(dirfd as u32)?;
        Some(format!("{}/{}", dir.trim_end_matches('/'), path))
    }

    /// `host_path` に最終要素のシンボリックリンク解釈を重ねる。
    fn host_path_followed(&self, dirfd: u64, path: &str) -> Option<String> {
        const AT_FDCWD: u32 = (-100i32) as u32;
        if path.starts_with('/') || dirfd as u32 == AT_FDCWD {
            let cwd = if self.cwd.is_empty() { "/" } else { &self.cwd };
            if self.guest_root.is_empty() {
                return Some(crate::guest_path::join_guest_path(cwd, path));
            }
            let r = crate::guest_path::resolve_guest_path_links(&self.guest_root, cwd, path)?;
            if path.starts_with("/dev/") && !std::path::Path::new(&r).exists() {
                return Some(path.to_string());
            }
            return Some(r);
        }
        // dirfd 相対: 先に連結してから辿る（最小近似）。
        let p = self.host_path(dirfd, path)?;
        if self.guest_root.is_empty() {
            return Some(p);
        }
        crate::guest_path::resolve_guest_path_links(&self.guest_root, "/", &p)
    }

    fn writer(&mut self, fd: u32) -> Result<WriteFd, u64> {
        match fd {
            1 => Ok(WriteFd::Stdout),
            2 => Ok(WriteFd::Stderr),
            _ if self.fds.file(fd).is_some() => Ok(WriteFd::File),
            _ => Err(errno::EBADF),
        }
    }

    fn sys_write(&mut self, env: &mut BareEnv, fd: u32, buf: u64, len: u64) -> Result<u64, u64> {
        if fd >= 3 && self.fds.target(fd).is_some() && self.fds.file(fd).is_none() {
            // ファイル以外の対象（eventfd 等）は fd 表経由。
            let abi = crate::wait::WaitAbi::generic(4, 8, Endian::Le);
            let t0 = self.wait_epoch();
            let mono = move || t0.elapsed().as_nanos() as u64;
            return match crate::wait::write_other(&mut self.fds, &abi, env, fd, buf, len, 0, &mono)
            {
                Ok(v) => Ok(v),
                Err(e) => Err(u64::from((abi.errno)(e))),
            };
        }
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
            WriteFd::File => match self.fds.file_mut(fd).unwrap().write(&data) {
                Ok(n) => Ok(n as u64),
                Err(e) => Err(host_errno(e.raw_os_error())),
            },
        }
    }

    /// iovec は 32 ビット ABI の {u32 base, u32 len} の対（LE）。
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
        if fd >= 3 && self.fds.target(fd).is_some() && self.fds.file(fd).is_none() {
            // ファイル以外の対象（eventfd・timerfd 等）は fd 表経由。
            let abi = crate::wait::WaitAbi::generic(4, 8, Endian::Le);
            let t0 = self.wait_epoch();
            let mono = move || t0.elapsed().as_nanos() as u64;
            return match crate::wait::read_other(
                &mut self.fds,
                &abi,
                env,
                fd,
                buf,
                len as u64,
                0,
                &mono,
            ) {
                Ok(v) => Ok(v),
                Err(e) => Err(u64::from((abi.errno)(e))),
            };
        }
        let mut tmp = vec![0u8; len];
        let n = match fd {
            0 => {
                let avail = self.stdin_buf.len().saturating_sub(self.stdin_pos);
                let n = avail.min(len);
                tmp[..n].copy_from_slice(&self.stdin_buf[self.stdin_pos..self.stdin_pos + n]);
                self.stdin_pos += n;
                n
            }
            _ => match self.fds.file_mut(fd) {
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
        let Some(full) = self.host_path_followed(dirfd, &gpath) else {
            return Err(errno::EACCES);
        };
        // asm-generic の O_*: ACCMODE=3, CREAT=0o100, EXCL=0o200,
        // TRUNC=0o1000, APPEND=0o2000, DSYNC=0o10000,
        // DIRECT=0o40000, LARGEFILE=0o100000, DIRECTORY=0o200000,
        // NOFOLLOW=0o400000, NOATIME=0o1000000, CLOEXEC=0o2000000。
        // O_DIRECTORY=0o200000 は開いたあとがディレクトリで
        // なければ ENOTDIR。残りのフラグ（O_NOFOLLOW・O_CLOEXEC・
        // O_SYNC 系・O_LARGEFILE）は無視する。
        // Ref: SRC-LINUX — include/uapi/asm-generic/fcntl.h。
        let accmode = flags & 3;
        let mut opt = std::fs::OpenOptions::new();
        opt.read(accmode != 1)
            .write(accmode != 0)
            .append(flags & 0o2000 != 0);
        if flags & 0o100 != 0 {
            opt.create(true);
        }
        if flags & 0o200 != 0 {
            opt.create_new(true);
        }
        if flags & 0o1000 != 0 {
            opt.truncate(true);
        }
        match opt.open(&full) {
            Ok(f) => {
                if flags & 0o200000 != 0 && !std::path::Path::new(&full).is_dir() {
                    return Err(errno::ENOTDIR);
                }
                let fd = self.fds.alloc(polyisa_kernel::FdTarget::File(f));
                self.fds.remember_path(fd, full);
                Ok(u64::from(fd))
            }
            Err(e) => Err(host_errno(e.raw_os_error())),
        }
    }

    /// asm-generic `struct stat64`（fstatat64/fstat64 の出力、
    /// time32・104 バイト・LE）。オフセットは or1k（BE）と同じ
    /// 配列: st_dev u64@0, st_ino u64@8, st_mode u32@16,
    /// st_nlink u32@20, st_uid u32@24, st_gid u32@28,
    /// st_rdev u64@32, __pad1 u64@40, st_size i64@48,
    /// st_blksize i32@56, __pad2 i32@60, st_blocks i64@64,
    /// st_atime i32@72, st_atime_nsec u32@76, st_mtime@80/84,
    /// st_ctime@88/92, __unused u32×2@96。
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
        self.put_u32(env, addr + 72, md.atime as u32)?;
        self.put_u32(env, addr + 76, md.atime_nsec as u32)?;
        self.put_u32(env, addr + 80, md.mtime as u32)?;
        self.put_u32(env, addr + 84, md.mtime_nsec as u32)?;
        self.put_u32(env, addr + 88, md.ctime as u32)?;
        self.put_u32(env, addr + 92, md.ctime_nsec as u32)?;
        self.put_u64(env, addr + 96, 0)?;
        Ok(())
    }

    fn sys_fstat(&mut self, env: &mut BareEnv, fd: u32, st: u64) -> Result<u64, u64> {
        let md = match fd {
            0..=2 => {
                // 端末・パイプはキャラクタデバイス風の合成 stat。
                let f =
                    std::fs::File::open("/dev/null").map_err(|e| host_errno(e.raw_os_error()))?;
                polyisa_host::fstat(&f).map_err(|e| host_errno(e.raw_os_error()))?
            }
            _ => match self.fds.file(fd) {
                Some(f) => polyisa_host::fstat(f).map_err(|e| host_errno(e.raw_os_error()))?,
                None => return Err(errno::EBADF),
            },
        };
        self.put_stat(env, st, &md).map(|_| 0)
    }

    /// `fstatat64(dirfd, path, stat64*, flags)`。
    /// AT_SYMLINK_NOFOLLOW(0x100) で最終要素のリンク解釈を止める。
    /// AT_EMPTY_PATH+空パス は dirfd 自身を stat する近似
    fn sys_fstatat(
        &mut self,
        env: &mut BareEnv,
        dirfd: u64,
        path: u64,
        addr: u64,
        flags: u64,
    ) -> Result<u64, u64> {
        const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
        const AT_EMPTY_PATH: u64 = 0x1000;
        let gpath = self.cstr(env, path)?;
        if gpath.is_empty() && flags & AT_EMPTY_PATH != 0 {
            return self.sys_fstat(env, dirfd as u32, addr);
        }
        let md = if flags & AT_SYMLINK_NOFOLLOW != 0 {
            let Some(full) = self.host_path(dirfd, &gpath) else {
                return Err(errno::EACCES);
            };
            polyisa_host::lstat(&full)
        } else {
            let Some(full) = self.host_path_followed(dirfd, &gpath) else {
                return Err(errno::EACCES);
            };
            polyisa_host::stat(&full)
        }
        .map_err(|e| host_errno(e.raw_os_error()))?;
        self.put_stat(env, addr, &md).map(|_| 0)
    }

    /// `statx`（asm-generic の `struct statx`、256 バイト）。
    /// btime/mnt_id/attributes は未提供。
    /// Ref: SRC-LINUX — include/uapi/linux/stat.h.
    fn sys_statx(
        &mut self,
        env: &mut BareEnv,
        dirfd: u64,
        path: u64,
        flags: u64,
        _mask: u64,
        out: u64,
    ) -> Result<u64, u64> {
        let gpath = self.cstr(env, path)?;
        const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
        const AT_EMPTY_PATH: u64 = 0x1000;
        let full = if flags & AT_EMPTY_PATH != 0 && gpath.is_empty() {
            match self.fds.path_of(dirfd as u32) {
                Some(p) => p.to_string(),
                None => return Err(errno::EBADF),
            }
        } else if flags & AT_SYMLINK_NOFOLLOW != 0 {
            match self.host_path(dirfd, &gpath) {
                Some(p) => p,
                None => return Err(errno::EACCES),
            }
        } else {
            match self.host_path_followed(dirfd, &gpath) {
                Some(p) => p,
                None => return Err(errno::EACCES),
            }
        };
        let md = if flags & AT_SYMLINK_NOFOLLOW != 0 {
            polyisa_host::lstat(&full)
        } else {
            polyisa_host::stat(&full)
        }
        .map_err(|e| host_errno(e.raw_os_error()))?;
        let mut b = [0u8; 256];
        let w16 = |v: u16, b: &mut [u8]| b.copy_from_slice(&v.to_le_bytes());
        let w32 = |v: u32, b: &mut [u8]| b.copy_from_slice(&v.to_le_bytes());
        let w64 = |v: u64, b: &mut [u8]| b.copy_from_slice(&v.to_le_bytes());
        // new_encode_dev から major/minor を取る。
        let major = |d: u64| -> u32 { (((d >> 8) & 0xfff) | (d >> 32)) as u32 };
        let minor = |d: u64| -> u32 { ((d & 0xff) | ((d >> 12) & !0xff)) as u32 };
        // UAPI `struct statx`: mask@0, blksize@4, attributes@8,
        // nlink@16, uid@20, gid@24, mode@28, ino@32, size@40,
        // blocks@48, attributes_mask@56, atime@64, btime@80,
        // ctime@96, mtime@112, rdev_{ma,mi}@128/132,
        // dev_{ma,mi}@136/140, mnt_id@144。
        w32(0x7ff, &mut b[0..4]); // mask = STATX_BASIC_STATS
        w32(md.blksize as u32, &mut b[4..8]);
        w32(md.nlink as u32, &mut b[16..20]);
        w32(md.uid, &mut b[20..24]);
        w32(md.gid, &mut b[24..28]);
        w16(md.mode as u16, &mut b[28..30]);
        w64(md.ino, &mut b[32..40]);
        w64(md.size, &mut b[40..48]);
        w64(md.blocks, &mut b[48..56]);
        w64(md.atime as u64, &mut b[64..72]);
        w32(md.atime_nsec as u32, &mut b[72..76]);
        w64(md.ctime as u64, &mut b[96..104]);
        w32(md.ctime_nsec as u32, &mut b[104..108]);
        w64(md.mtime as u64, &mut b[112..120]);
        w32(md.mtime_nsec as u32, &mut b[120..124]);
        w32(major(md.rdev), &mut b[128..132]);
        w32(minor(md.rdev), &mut b[132..136]);
        w32(major(md.dev), &mut b[136..140]);
        w32(minor(md.dev), &mut b[140..144]);
        self.put_bytes(env, out, &b)?;
        Ok(0)
    }

    fn sys_brk(&mut self, env: &mut BareEnv, addr: u64) -> u64 {
        let addr = addr & 0xffff_ffff;
        if self.heap_end == 0 {
            self.heap_end = self.brk_start;
        }
        if addr == 0 || addr < self.brk_start {
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

    /// `mmap2(addr, len, prot, flags, fd, pgoff)`。pgoff は
    /// 4KiB ページ単位（asm-generic `sys_mmap2` → hexagon では
    /// `sys_mmap_pgoff`）。file-backed は内容を事前読みする近似
    /// （共有・後続 write の反映はない）。
    /// Ref: SRC-LINUX — mm/mmap.c（sys_mmap2）,
    /// kernel/syscalltab.c（sys_mmap2→sys_mmap_pgoff）.
    fn sys_mmap2(&mut self, env: &mut BareEnv, a: [u64; 6]) -> Result<u64, u64> {
        let (addr, len, prot, flags, fd, pgoff) = (a[0], a[1], a[2], a[3], a[4], a[5]);
        let len = (len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if len == 0 || len > 0x4000_0000 {
            return Err(errno::EINVAL);
        }
        const MAP_FIXED: u64 = 0x10;
        const MAP_ANONYMOUS: u64 = 0x20;
        const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;
        let mut base = if flags & MAP_FIXED != 0 {
            addr & !(PAGE_SIZE - 1)
        } else {
            // hint が空きなら hint を使う（musl ldso は hint 付きで
            // 呼ぶ）。埋まっていれば従来どおり次の窓から取る。
            let hint = addr & !(PAGE_SIZE - 1);
            let mut ok = hint != 0;
            if ok {
                for p in (hint..hint + len).step_by(PAGE_SIZE as usize) {
                    if env.backend.mem.is_mapped(PageNo(p / PAGE_SIZE)) {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                hint
            } else {
                let b = self.mmap_next;
                self.mmap_next = self.mmap_next.wrapping_add(len);
                b
            }
        };
        if flags & MAP_FIXED_NOREPLACE != 0 {
            for p in (base..base + len).step_by(PAGE_SIZE as usize) {
                if env.backend.mem.is_mapped(PageNo(p / PAGE_SIZE)) {
                    return Err(errno::EEXIST);
                }
            }
        }
        // MAP_FIXED で既存の写像に重なる分は張り直す。
        if flags & MAP_FIXED != 0 {
            env.backend.mem.unmap(VirtAddr(base), len / PAGE_SIZE);
        }
        let pages = len / PAGE_SIZE;
        // PROT_* の下位 3 ビットは Perms の R/W/X と同じ配列。
        let want = Perms((prot & 7) as u8);
        let file_backed = flags & MAP_ANONYMOUS == 0 && self.fds.file(fd as u32).is_some();
        // ファイル裏付けは中身の事前読みを伴うので、書き込み
        // 不可の要求でも RW で割り付けて埋めてから protect で
        // 要求の許可へ戻す。
        env.backend
            .mem
            .map(
                VirtAddr(base),
                pages,
                if file_backed { Perms::RW } else { want },
            )
            .map_err(|_| errno::ENOMEM)?;
        if file_backed {
            // pgoff をバイトオフセットに直して pread で読む
            // （fd の現位置を動かさない）。
            let mut left = len.min(1 << 24);
            let mut at = base;
            let mut off = pgoff << 12;
            while left > 0 {
                let n = left.min(64 * 1024) as usize;
                let mut buf = vec![0u8; n];
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
            if want.0 & Perms::W.0 == 0 {
                let _ = env.backend.mem.protect(VirtAddr(base), pages, want);
            }
        }
        if base == 0 {
            // ベース 0 を返すとエラー値に見えるので退避する
            // （通常 hint なしは mmap_next から取るので到達しない）。
            base = self.mmap_next;
            self.mmap_next = self.mmap_next.wrapping_add(len);
        }
        Ok(base)
    }

    /// `munmap`。写像を外す。
    fn sys_munmap(&mut self, env: &mut BareEnv, addr: u64, len: u64) -> Result<u64, u64> {
        let at = (addr & 0xffff_ffff) & !(PAGE_SIZE - 1);
        let pages = (len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        env.backend.mem.unmap(VirtAddr(at), pages / PAGE_SIZE);
        Ok(0)
    }

    /// `mprotect`。写像済みの範囲だけ権限を更新する（部分的に
    /// 未写像の範囲は無視する近似）。
    fn sys_mprotect(
        &mut self,
        env: &mut BareEnv,
        addr: u64,
        len: u64,
        prot: u64,
    ) -> Result<u64, u64> {
        let want = Perms((prot & 7) as u8);
        let at = (addr & 0xffff_ffff) & !(PAGE_SIZE - 1);
        let pages = len.div_ceil(PAGE_SIZE);
        for i in 0..pages {
            let p = at + i * PAGE_SIZE;
            if env.backend.mem.is_mapped(PageNo(p / PAGE_SIZE)) {
                let _ = env.backend.mem.protect(VirtAddr(p), 1, want);
            }
        }
        Ok(0)
    }

    /// `sys_llseek(fd, off_hi, off_lo, result*, whence)`。
    /// 結果は result* へ u64（LE）で書き、戻り値は 0
    /// （asm-generic 32 ビットの llseek 規約 — musl の lseek 経路
    /// もこの形で呼ぶ）。
    /// Ref: SRC-LINUX — fs/read_write.c（sys_llseek）.
    fn sys_llseek(
        &mut self,
        env: &mut BareEnv,
        fd: u32,
        hi: u64,
        lo: u64,
        result: u64,
        whence: u64,
    ) -> Result<u64, u64> {
        let off = ((hi & 0xffff_ffff) << 32) | (lo & 0xffff_ffff);
        let Some(f) = self.fds.file_mut(fd) else {
            return Err(errno::EBADF);
        };
        let w = match whence {
            0 => SeekFrom::Start(off),
            1 => SeekFrom::Current(off as i64),
            2 => SeekFrom::End(off as i64),
            _ => return Err(errno::EINVAL),
        };
        match f.seek(w) {
            Ok(p) => {
                self.put_u64(env, result, p)?;
                Ok(0)
            }
            Err(e) => Err(host_errno(e.raw_os_error())),
        }
    }

    /// `pread64`/`pwrite64` の位置。hexagon は LE なので 64 ビット
    /// 引数対は a[3]=下位, a[4]=上位（BE の or1k と逆）。
    fn pos64(a: &[u64; 6]) -> u64 {
        (a[3] & 0xffff_ffff) | ((a[4] & 0xffff_ffff) << 32)
    }

    /// `pread64`。ファイル位置を変えずに読む。
    fn sys_pread(
        &mut self,
        env: &mut BareEnv,
        fd: u32,
        buf: u64,
        len: u64,
        off: u64,
    ) -> Result<u64, u64> {
        let len = (len as usize).min(1 << 20);
        let Some(f) = self.fds.file_mut(fd) else {
            return Err(errno::EBADF);
        };
        let mut tmp = vec![0u8; len];
        match polyisa_host::pread(f, &mut tmp, off) {
            Ok(n) => {
                self.put_bytes(env, buf, &tmp[..n])?;
                Ok(n as u64)
            }
            Err(e) => Err(host_errno(e.raw_os_error())),
        }
    }

    /// `pwrite64`。ファイル位置を変えずに書く。
    fn sys_pwrite(
        &mut self,
        env: &mut BareEnv,
        fd: u32,
        buf: u64,
        len: u64,
        off: u64,
    ) -> Result<u64, u64> {
        let len = (len as usize).min(1 << 20);
        let data = self.get_bytes(env, buf, len)?;
        let Some(f) = self.fds.file_mut(fd) else {
            return Err(errno::EBADF);
        };
        match polyisa_host::pwrite(f, &data, off) {
            Ok(n) => Ok(n as u64),
            Err(e) => Err(host_errno(e.raw_os_error())),
        }
    }

    /// `sendfile64(out, in, off*, count)`。off* は u64（LE）の
    /// 位置ポインタ（NULL なら in の現位置から進める）。
    fn sys_sendfile(
        &mut self,
        env: &mut BareEnv,
        out_fd: u32,
        in_fd: u32,
        off: u64,
        count: u64,
    ) -> Result<u64, u64> {
        let count = (count as usize).min(1 << 24);
        let mut pos: Option<u64> = None;
        if off != 0 {
            pos = Some(self.mem_u64(env, off));
        }
        let data = {
            let Some(f) = self.fds.file_mut(in_fd) else {
                return Err(errno::EBADF);
            };
            if let Some(p) = pos
                && f.seek(SeekFrom::Start(p)).is_err()
            {
                return Err(errno::EINVAL);
            }
            let mut buf = vec![0u8; count];
            match f.read(&mut buf) {
                Ok(n) => {
                    buf.truncate(n);
                    buf
                }
                Err(e) => return Err(host_errno(e.raw_os_error())),
            }
        };
        let n = match self.writer(out_fd)? {
            WriteFd::Stdout => {
                self.io.stdout.extend_from_slice(&data);
                let _ = std::io::stdout().write_all(&data);
                data.len()
            }
            WriteFd::Stderr => {
                self.io.stderr.extend_from_slice(&data);
                let _ = std::io::stderr().write_all(&data);
                data.len()
            }
            WriteFd::File => match self.fds.file_mut(out_fd).unwrap().write(&data) {
                Ok(n) => n,
                Err(e) => return Err(host_errno(e.raw_os_error())),
            },
        };
        if off != 0 {
            self.put_u64(env, off, pos.unwrap_or(0) + n as u64)?;
        }
        Ok(n as u64)
    }

    /// `getdents64`: linux_dirent64 { u64 ino, i64 off, u16 reclen,
    /// u8 type, char name[] } を 8 バイト整列で並べる（LE）。
    /// `.`/`..` を先頭に合成する。fd 毎の読み出し位置で進める近似。
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
        let mut ents: Vec<(u64, u8, Vec<u8>)> = vec![(1, 4, b".".to_vec()), (1, 4, b"..".to_vec())];
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
        let mut pos = self.dir_pos.get(&fd).copied().unwrap_or(0) as usize;
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
            rec.extend_from_slice(&ino.to_le_bytes());
            rec.extend_from_slice(&((idx as u64) as i64).to_le_bytes());
            rec.extend_from_slice(&(reclen as u16).to_le_bytes());
            rec.push(*t);
            rec.extend_from_slice(name);
            rec.push(0);
            while rec.len() < reclen {
                rec.push(0);
            }
            out.extend_from_slice(&rec);
            pos = idx;
        }
        self.dir_pos.insert(fd, pos as u64);
        let n = out.len() as u64;
        if n != 0 {
            self.put_bytes(env, buf, &out)?;
        }
        Ok(n)
    }

    /// `readlinkat`。/proc/self/exe は exe_path を返す。その他は
    /// ホストのリンクを辿る。
    fn sys_readlinkat(
        &mut self,
        env: &mut BareEnv,
        dirfd: u64,
        path: u64,
        buf: u64,
        len: u64,
    ) -> Result<u64, u64> {
        let gpath = self.cstr(env, path)?;
        let target = if gpath == "/proc/self/exe" {
            self.exe_path.clone()
        } else {
            let Some(full) = self.host_path(dirfd, &gpath) else {
                return Err(errno::EBADF);
            };
            match std::fs::read_link(&full) {
                Ok(t) => t.to_string_lossy().into_owned(),
                Err(e) => return Err(host_errno(e.raw_os_error())),
            }
        };
        let b = target.as_bytes();
        let n = b.len().min(len as usize);
        self.put_bytes(env, buf, &b[..n])?;
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

    /// `chdir`。ゲストの cwd を更新するだけ（ホストの cwd は
    /// 触らない）。
    fn sys_chdir(&mut self, env: &mut BareEnv, path: u64) -> Result<u64, u64> {
        let gpath = self.cstr(env, path)?;
        let Some(full) = self.host_path_followed((-100i64) as u64, &gpath) else {
            return Err(errno::EACCES);
        };
        match std::fs::metadata(&full) {
            Ok(md) if md.is_dir() => {}
            Ok(_) => return Err(errno::ENOTDIR),
            Err(e) => return Err(host_errno(e.raw_os_error())),
        }
        let cwd = if self.cwd.is_empty() { "/" } else { &self.cwd };
        self.cwd = crate::guest_path::join_guest_path(cwd, &gpath);
        Ok(0)
    }

    /// `fchdir`。fd の記憶パスへ移る。
    fn sys_fchdir(&mut self, fd: u32) -> Result<u64, u64> {
        let Some(host) = self.fds.path_of(fd).map(str::to_string) else {
            return Err(errno::EBADF);
        };
        if !std::path::Path::new(&host).is_dir() {
            return Err(errno::ENOTDIR);
        }
        // ゲスト側 cwd は root から剥がした形で覚える（最小近似）。
        let root_trim = self.guest_root.trim_end_matches('/');
        self.cwd = host
            .strip_prefix(root_trim)
            .map_or_else(|| host.clone(), |s| s.to_string());
        if self.cwd.is_empty() {
            self.cwd = "/".to_string();
        }
        Ok(0)
    }

    /// `mkdirat`。
    fn sys_mkdirat(
        &mut self,
        env: &mut BareEnv,
        dirfd: u64,
        path: u64,
        _mode: u64,
    ) -> Result<u64, u64> {
        let gpath = self.cstr(env, path)?;
        let Some(full) = self.host_path(dirfd, &gpath) else {
            return Err(errno::EACCES);
        };
        std::fs::create_dir(&full).map_err(|e| host_errno(e.raw_os_error()))?;
        Ok(0)
    }

    /// `unlinkat`。AT_REMOVEDIR（0x200）で `rmdir` 扱い。
    fn sys_unlinkat(
        &mut self,
        env: &mut BareEnv,
        dirfd: u64,
        path: u64,
        flags: u64,
    ) -> Result<u64, u64> {
        let gpath = self.cstr(env, path)?;
        let Some(full) = self.host_path(dirfd, &gpath) else {
            return Err(errno::EACCES);
        };
        const AT_REMOVEDIR: u64 = 0x200;
        let r = if flags & AT_REMOVEDIR != 0 {
            std::fs::remove_dir(&full)
        } else {
            std::fs::remove_file(&full)
        };
        r.map_err(|e| host_errno(e.raw_os_error()))?;
        Ok(0)
    }

    /// `renameat`。
    fn sys_renameat(
        &mut self,
        env: &mut BareEnv,
        oldfd: u64,
        old: u64,
        newfd: u64,
        new: u64,
    ) -> Result<u64, u64> {
        let old_g = self.cstr(env, old)?;
        let new_g = self.cstr(env, new)?;
        let (Some(oh), Some(nh)) = (self.host_path(oldfd, &old_g), self.host_path(newfd, &new_g))
        else {
            return Err(errno::EACCES);
        };
        std::fs::rename(&oh, &nh).map_err(|e| host_errno(e.raw_os_error()))?;
        Ok(0)
    }

    /// `symlinkat`（ホストの symlink として作る）。
    fn sys_symlinkat(
        &mut self,
        env: &mut BareEnv,
        target: u64,
        newdirfd: u64,
        linkpath: u64,
    ) -> Result<u64, u64> {
        let target_g = self.cstr(env, target)?;
        let link_g = self.cstr(env, linkpath)?;
        let Some(lh) = self.host_path(newdirfd, &link_g) else {
            return Err(errno::EACCES);
        };
        polyisa_host::symlink(&target_g, &lh).map_err(|e| host_errno(e.raw_os_error()))?;
        Ok(0)
    }

    /// `linkat`（ホストの hard link として作る）。
    fn sys_linkat(
        &mut self,
        env: &mut BareEnv,
        olddirfd: u64,
        old: u64,
        newdirfd: u64,
        new: u64,
    ) -> Result<u64, u64> {
        let old_g = self.cstr(env, old)?;
        let new_g = self.cstr(env, new)?;
        let (Some(oh), Some(nh)) = (
            self.host_path(olddirfd, &old_g),
            self.host_path(newdirfd, &new_g),
        ) else {
            return Err(errno::EACCES);
        };
        std::fs::hard_link(&oh, &nh).map_err(|e| host_errno(e.raw_os_error()))?;
        Ok(0)
    }

    /// `mknodat`。通常ファイルだけ実際に作る（それ以外のノードは
    /// 受理のみ）。
    fn sys_mknodat(
        &mut self,
        env: &mut BareEnv,
        dirfd: u64,
        path: u64,
        mode: u64,
        dev: u64,
    ) -> Result<u64, u64> {
        let gpath = self.cstr(env, path)?;
        let Some(full) = self.host_path(dirfd, &gpath) else {
            return Err(errno::EACCES);
        };
        // S_IFREG(0o100000) 以外はホスト特権が要るので受理のみ。
        if mode & 0o170000 != 0o100000 {
            return Ok(0);
        }
        polyisa_host::mknod(&full, (mode & 0o7777) as u32, dev)
            .map_err(|e| host_errno(e.raw_os_error()))?;
        Ok(0)
    }

    /// `ftruncate64`/`truncate64`。
    fn sys_truncate(
        &mut self,
        env: &mut BareEnv,
        fd_or_path: u64,
        is_fd: bool,
        dirfd: u64,
        len: u64,
    ) -> Result<u64, u64> {
        if is_fd {
            let Some(f) = self.fds.file_mut(fd_or_path as u32) else {
                return Err(errno::EBADF);
            };
            f.set_len(len).map_err(|e| host_errno(e.raw_os_error()))?;
        } else {
            let gpath = self.cstr(env, fd_or_path)?;
            let Some(full) = self.host_path(dirfd, &gpath) else {
                return Err(errno::EACCES);
            };
            let f = std::fs::OpenOptions::new()
                .write(true)
                .open(&full)
                .map_err(|e| host_errno(e.raw_os_error()))?;
            f.set_len(len).map_err(|e| host_errno(e.raw_os_error()))?;
        }
        Ok(0)
    }

    /// `fchmodat`（AT_SYMLINK_NOFOLLOW なしのパスだけ）。
    fn sys_fchmodat(
        &mut self,
        env: &mut BareEnv,
        dirfd: u64,
        path: u64,
        mode: u64,
    ) -> Result<u64, u64> {
        let gpath = self.cstr(env, path)?;
        let Some(full) = self.host_path_followed(dirfd, &gpath) else {
            return Err(errno::EACCES);
        };
        polyisa_host::chmod(&full, (mode & 0o7777) as u32)
            .map_err(|e| host_errno(e.raw_os_error()))?;
        Ok(0)
    }

    /// `utimensat`（time32 timespec×2）。times が NULL なら現在
    /// 時刻、mtime だけ std で近似する。
    fn sys_utimensat(
        &mut self,
        env: &mut BareEnv,
        dirfd: u64,
        path: u64,
        times: u64,
        flags: u64,
    ) -> Result<u64, u64> {
        let gpath = self.cstr(env, path)?;
        const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
        let full = if flags & AT_SYMLINK_NOFOLLOW != 0 {
            self.host_path(dirfd, &gpath)
        } else {
            self.host_path_followed(dirfd, &gpath)
        };
        let Some(full) = full else {
            return Err(errno::EACCES);
        };
        let mtime = if times == 0 {
            std::time::SystemTime::now()
        } else {
            // timespec32 ×2: atime@{sec i32,nsec i32}, mtime@+8。
            let sec = u64::from(self.mem_u32(env, times + 8));
            let nsec = u64::from(self.mem_u32(env, times + 12));
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::new(sec, nsec as u32)
        };
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&full)
            .map_err(|e| host_errno(e.raw_os_error()))?;
        f.set_modified(mtime)
            .map_err(|e| host_errno(e.raw_os_error()))?;
        Ok(0)
    }

    /// `prlimit64(pid, res, new, old)`。old に rlimit64（u64×2）
    /// の合成値を書く。new は受理のみ（単一プロセス近似 — Gap:
    ///）。resource >= RLIM_NLIMITS(16) は EINVAL。
    fn sys_prlimit64(
        &mut self,
        env: &mut BareEnv,
        res: u64,
        new: u64,
        old: u64,
    ) -> Result<u64, u64> {
        const RLIM_NLIMITS: u64 = 16;
        const RLIM64_INFINITY: u64 = u64::MAX;
        if res >= RLIM_NLIMITS {
            return Err(errno::EINVAL);
        }
        if new != 0 {
            // 書き込みは受理のみ（反映しない近似）。
        }
        if old != 0 {
            self.put_u64(env, old, RLIM64_INFINITY)?;
            self.put_u64(env, old + 8, RLIM64_INFINITY)?;
        }
        Ok(0)
    }

    /// `getrlimit(res, rlim*)`（32 ビット ABI: u32×2）。
    fn sys_getrlimit(&mut self, env: &mut BareEnv, res: u64, addr: u64) -> Result<u64, u64> {
        if res >= 16 {
            return Err(errno::EINVAL);
        }
        self.put_u32(env, addr, u32::MAX)?;
        self.put_u32(env, addr + 4, u32::MAX)?;
        Ok(0)
    }

    /// `setrlimit`。受理のみ（単一プロセス近似）。
    fn sys_setrlimit(&mut self, res: u64) -> Result<u64, u64> {
        if res >= 16 {
            return Err(errno::EINVAL);
        }
        Ok(0)
    }

    /// `rt_sigaction(sig, act, oldact, sigsetsize)`。配送しない
    /// 近似。oldact には SIG_DFL 相当の
    /// asm-generic `struct sigaction`（{handler u32, flags u32,
    /// restorer u32, mask u64} = 20B）のゼロを書く。sigsetsize は
    /// 8 固定でなければ EINVAL。
    fn sys_rt_sigaction(&mut self, env: &mut BareEnv, oldact: u64, sz: u64) -> Result<u64, u64> {
        if sz != 8 {
            return Err(errno::EINVAL);
        }
        if oldact != 0 {
            self.put_bytes(env, oldact, &[0u8; 20])?;
        }
        Ok(0)
    }

    /// `rt_sigprocmask(how, set, oldset, sigsetsize)`。
    /// SIG_BLOCK=0/UNBLOCK=1/SETMASK=2。blocked マスクは保持する
    /// が配送はしない。
    fn sys_rt_sigprocmask(
        &mut self,
        env: &mut BareEnv,
        how: u64,
        set: u64,
        old: u64,
        sz: u64,
    ) -> Result<u64, u64> {
        if sz != 8 {
            return Err(errno::EINVAL);
        }
        if old != 0 {
            self.put_u64(env, old, self.sig_mask)?;
        }
        if set != 0 {
            let b = self.get_bytes(env, set, 8)?;
            let v = u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8]));
            let m = match how {
                0 => self.sig_mask | v,
                1 => self.sig_mask & !v,
                2 => v,
                _ => return Err(errno::EINVAL),
            };
            // SIGKILL(9)/SIGSTOP(19) はブロック不可。
            self.sig_mask = m & !((1u64 << (9 - 1)) | (1u64 << (19 - 1)));
        }
        Ok(0)
    }

    /// `uname`。utsname は 6×65 バイト。machine は "hexagon"。
    fn sys_uname(&mut self, env: &mut BareEnv, addr: u64) -> Result<u64, u64> {
        let mut img = [0u8; 65 * 6];
        for (i, s) in [
            "Linux",
            "polyisa",
            "6.1.0-polyisa",
            "#1",
            "hexagon",
            "(none)",
        ]
        .iter()
        .enumerate()
        {
            img[i * 65..i * 65 + s.len()].copy_from_slice(s.as_bytes());
        }
        self.put_bytes(env, addr, &img).map(|_| 0)
    }

    /// `clock_gettime`（time32 timespec {i32,i32}）。
    fn sys_clock_gettime(&mut self, env: &mut BareEnv, clk: u64, ts: u64) -> Result<u64, u64> {
        let (sec, nsec) = self.clock_value(clk);
        self.put_u32(env, ts, sec as u32)?;
        self.put_u32(env, ts + 4, nsec)?;
        Ok(0)
    }

    /// `clock_gettime64`（timespec64 {i64,i64}・LE）。
    fn sys_clock_gettime64(&mut self, env: &mut BareEnv, clk: u64, ts: u64) -> Result<u64, u64> {
        let (sec, nsec) = self.clock_value(clk);
        self.put_u64(env, ts, sec)?;
        self.put_u64(env, ts + 8, u64::from(nsec))?;
        Ok(0)
    }

    /// `clock_getres` / `clock_getres_time64`。1ns を報告する。
    fn sys_clock_getres(&mut self, env: &mut BareEnv, ts: u64, w64: bool) -> Result<u64, u64> {
        if ts != 0 {
            if w64 {
                self.put_u64(env, ts, 0)?;
                self.put_u64(env, ts + 8, 1)?;
            } else {
                self.put_u32(env, ts, 0)?;
                self.put_u32(env, ts + 4, 1)?;
            }
        }
        Ok(0)
    }

    /// 時計の値。REALTIME は壁時計、それ以外は起点からの経過。
    fn clock_value(&mut self, clk: u64) -> (u64, u32) {
        match clk {
            0 => {
                let d = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                (d.as_secs(), d.subsec_nanos())
            }
            _ => {
                let start = *self.mono_start.get_or_insert_with(std::time::Instant::now);
                let d = start.elapsed();
                (d.as_secs(), d.subsec_nanos())
            }
        }
    }

    /// `nanosleep`（time32）。短い要求だけ実際に眠る近似
    fn sys_nanosleep(&mut self, env: &mut BareEnv, req: u64, _rem: u64) -> Result<u64, u64> {
        let sec = u64::from(self.mem_u32(env, req));
        let nsec = self.mem_u32(env, req + 4);
        let d = std::time::Duration::new(sec, nsec);
        if d.as_millis() < 5000 {
            std::thread::sleep(d);
        }
        Ok(0)
    }

    /// `gettimeofday`。timeval = {i32 sec, i32 usec}（time32）。
    fn sys_gettimeofday(&mut self, env: &mut BareEnv, tv: u64, _tz: u64) -> Result<u64, u64> {
        if tv != 0 {
            let d = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            self.put_u32(env, tv, d.as_secs() as u32)?;
            self.put_u32(env, tv + 4, d.subsec_micros())?;
        }
        Ok(0)
    }

    /// `sysinfo`（32 ビット ABI・64 バイト: uptime u32@0,
    /// loads u32[3]@4, totalram@16, freeram@20, sharedram@24,
    /// bufferram@28, totalswap@32, freeswap@36, procs u16@40,
    /// pad@42, totalhigh@44, freehigh@48, mem_unit@52, _f@56）。
    /// 合成値（total/free 1 GiB 風）。
    fn sys_sysinfo(&mut self, env: &mut BareEnv, addr: u64) -> Result<u64, u64> {
        let mut b = [0u8; 64];
        let w32 = |v: u32, b: &mut [u8]| b.copy_from_slice(&v.to_le_bytes());
        let w16 = |v: u16, b: &mut [u8]| b.copy_from_slice(&v.to_le_bytes());
        let start = *self.mono_start.get_or_insert_with(std::time::Instant::now);
        w32(start.elapsed().as_secs() as u32, &mut b[0..4]);
        w32(1 << 30, &mut b[16..20]); // totalram
        w32(1 << 30, &mut b[20..24]); // freeram
        w32(1 << 29, &mut b[24..28]); // sharedram
        w16(2, &mut b[40..42]); // procs
        w32(1, &mut b[52..56]); // mem_unit
        self.put_bytes(env, addr, &b)?;
        Ok(0)
    }

    /// `times`。tms 4×u32 を 0 で返し、経過 tick（100Hz 想定）を戻す。
    fn sys_times(&mut self, env: &mut BareEnv, buf: u64) -> Result<u64, u64> {
        if buf != 0 {
            self.put_bytes(env, buf, &[0u8; 16])?;
        }
        let start = *self.mono_start.get_or_insert_with(std::time::Instant::now);
        Ok(start.elapsed().as_millis() as u64 / 10)
    }

    /// `getrusage`（32 ビット ABI・72 バイト）の最小 0 初期化。
    fn sys_getrusage(&mut self, env: &mut BareEnv, _who: u64, buf: u64) -> Result<u64, u64> {
        self.put_bytes(env, buf, &[0u8; 72])?;
        Ok(0)
    }

    /// `statfs64`/`fstatfs64` 共通の合成値書き込み
    /// （asm-generic `struct statfs64`・84 バイト。f_type u32@0,
    /// f_bsize u32@4, f_blocks u64@8, f_bfree@16, f_bavail@24,
    /// f_files@32, f_ffree@40, f_fsid@48, f_namelen u32@56,
    /// f_frsize u32@60, f_flags u32@64, f_spare u32[4]@68）。
    /// Ref: SRC-LINUX — include/uapi/asm-generic/statfs.h.
    fn put_statfs(&self, env: &mut BareEnv, addr: u64) -> Result<(), u64> {
        let mut b = [0u8; 96];
        let w64 = |v: u64, b: &mut [u8]| b.copy_from_slice(&v.to_le_bytes());
        let w32 = |v: u32, b: &mut [u8]| b.copy_from_slice(&v.to_le_bytes());
        w32(0x0102_1997, &mut b[0..4]); // f_type = TMPFS 風
        w32(4096, &mut b[4..8]); // f_bsize
        w64(1 << 20, &mut b[8..16]); // f_blocks
        w64(1 << 19, &mut b[16..24]); // f_bfree
        w64(1 << 19, &mut b[24..32]); // f_bavail
        w32(255, &mut b[56..60]); // f_namelen
        w32(4096, &mut b[60..64]); // f_frsize
        self.put_bytes(env, addr, &b)
    }

    /// `statfs64`。パスの存在確認だけ行う。
    fn sys_statfs(
        &mut self,
        env: &mut BareEnv,
        path: u64,
        _sz: u64,
        addr: u64,
    ) -> Result<u64, u64> {
        let gpath = self.cstr(env, path)?;
        let Some(full) = self.host_path_followed((-100i64) as u64, &gpath) else {
            return Err(errno::EACCES);
        };
        if std::fs::metadata(&full).is_err() {
            return Err(errno::ENOENT);
        }
        self.put_statfs(env, addr)?;
        Ok(0)
    }

    /// `getrandom`。決定論的な疑似乱数（xorshift）で埋める。
    /// 暗号学的品質は持たない。テスト決定性のための合成値
    fn sys_getrandom(
        &mut self,
        env: &mut BareEnv,
        buf: u64,
        len: u64,
        _f: u64,
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
        if size == 0 || size > 128 {
            return Err(errno::EINVAL);
        }
        self.put_bytes(env, mask, &vec![0u8; size as usize])?;
        self.put_u32(env, mask, 1)?;
        Ok(0)
    }

    /// `getcpu`。
    fn sys_getcpu(&mut self, env: &mut BareEnv, cpu: u64, node: u64, _c: u64) -> Result<u64, u64> {
        if cpu != 0 {
            self.put_u32(env, cpu, 0)?;
        }
        if node != 0 {
            self.put_u32(env, node, 0)?;
        }
        Ok(0)
    }

    /// `ioctl`。端末判定（TCGETS=0x5401 など）には ENOTTY、
    /// その他は ENOSYS。
    fn sys_ioctl(&mut self, _fd: u32, req: u64, _arg: u64) -> Result<u64, u64> {
        match req {
            0x5401 | 0x5402 | 0x5403 | 0x5413 => Err(errno::ENOTTY),
            _ => Err(errno::ENOSYS),
        }
    }

    /// `fcntl64`。F_DUPFD/F_DUPFD_CLOEXEC は複製、GET/SET 系は
    /// 最小受理。
    fn sys_fcntl(&mut self, fd: u32, cmd: u64, arg: u64) -> Result<u64, u64> {
        match cmd {
            // F_DUPFD=0, F_DUPFD_CLOEXEC=1030
            0 | 1030 => {
                let Some(f) = self.fds.file(fd) else {
                    return Err(errno::EBADF);
                };
                let nf = f.try_clone().map_err(|e| host_errno(e.raw_os_error()))?;
                let nfd = self.fds.alloc(polyisa_kernel::FdTarget::File(nf));
                if u64::from(nfd) < arg {
                    self.fds.clear(nfd);
                    return Err(errno::EINVAL);
                }
                Ok(u64::from(nfd))
            }
            // F_GETFD=1, F_GETFL=3
            1 => Ok(0),
            3 => Ok(0o2000002), // O_RDWR|O_LARGEFILE
            // F_SETFD=2, F_SETFL=4
            2 | 4 => Ok(0),
            _ => Err(errno::EINVAL),
        }
    }

    /// `dup`。
    fn sys_dup(&mut self, fd: u32) -> Result<u64, u64> {
        let Some(f) = self.fds.file(fd) else {
            return Err(errno::EBADF);
        };
        let nf = f.try_clone().map_err(|e| host_errno(e.raw_os_error()))?;
        Ok(u64::from(
            self.fds.alloc(polyisa_kernel::FdTarget::File(nf)),
        ))
    }

    /// `dup3(oldfd, newfd, flags)`。newfd を指定位置へ複製する。
    fn sys_dup3(&mut self, old: u32, new: u32, _flags: u64) -> Result<u64, u64> {
        if old == new {
            return Err(errno::EINVAL);
        }
        let Some(f) = self.fds.file(old) else {
            return Err(errno::EBADF);
        };
        let nf = f.try_clone().map_err(|e| host_errno(e.raw_os_error()))?;
        let path = self.fds.path_of(old).map(str::to_string);
        self.fds
            .place_close(new, polyisa_kernel::FdTarget::File(nf));
        if let Some(p) = path {
            self.fds.remember_path(new, p);
        }
        Ok(u64::from(new))
    }

    /// `copy_file_range`（busybox cp/dd の近似: 事前に読んで
    /// 書き出す。fd 位置は off* を使わない場合にだけ進める —
    fn sys_copy_file_range(
        &mut self,
        env: &mut BareEnv,
        in_fd: u32,
        in_off: u64,
        out_fd: u32,
        out_off: u64,
        len: u64,
    ) -> Result<u64, u64> {
        let len = (len as usize).min(1 << 24);
        let ipos = if in_off != 0 {
            Some(self.mem_u64(env, in_off))
        } else {
            None
        };
        let opos = if out_off != 0 {
            Some(self.mem_u64(env, out_off))
        } else {
            None
        };
        let data = {
            let Some(f) = self.fds.file_mut(in_fd) else {
                return Err(errno::EBADF);
            };
            if let Some(p) = ipos
                && f.seek(SeekFrom::Start(p)).is_err()
            {
                return Err(errno::EINVAL);
            }
            let mut buf = vec![0u8; len];
            match f.read(&mut buf) {
                Ok(n) => {
                    buf.truncate(n);
                    buf
                }
                Err(e) => return Err(host_errno(e.raw_os_error())),
            }
        };
        let n = {
            let Some(f) = self.fds.file_mut(out_fd) else {
                return Err(errno::EBADF);
            };
            if let Some(p) = opos
                && f.seek(SeekFrom::Start(p)).is_err()
            {
                return Err(errno::EINVAL);
            }
            match f.write(&data) {
                Ok(n) => n,
                Err(e) => return Err(host_errno(e.raw_os_error())),
            }
        };
        if in_off != 0 {
            self.put_u64(env, in_off, ipos.unwrap_or(0) + n as u64)?;
        }
        if out_off != 0 {
            self.put_u64(env, out_off, opos.unwrap_or(0) + n as u64)?;
        }
        Ok(n as u64)
    }

    /// `faccessat`/`faccessat2`。実在確認だけ（モードの検査は
    /// しない近似）。AT_EMPTY_PATH+空パスは fd
    /// の存在で代える。
    fn sys_faccessat(
        &mut self,
        env: &mut BareEnv,
        dirfd: u64,
        path: u64,
        flags: u64,
    ) -> Result<u64, u64> {
        const AT_EMPTY_PATH: u64 = 0x1000;
        let gpath = self.cstr(env, path)?;
        if gpath.is_empty() && flags & AT_EMPTY_PATH != 0 {
            return if dirfd as u32 <= 2 || self.fds.file(dirfd as u32).is_some() {
                Ok(0)
            } else {
                Err(errno::EBADF)
            };
        }
        let Some(full) = self.host_path_followed(dirfd, &gpath) else {
            return Err(errno::EACCES);
        };
        if std::fs::metadata(&full).is_ok() {
            Ok(0)
        } else {
            Err(errno::ENOENT)
        }
    }

    /// `getgroups`。0 グループ（補助グループなし）を返す。
    fn sys_getgroups(&mut self, _size: u64, _list: u64) -> Result<u64, u64> {
        Ok(0)
    }

    /// `getresuid`/`getresgid`（uid=euid=suid=0 を書く）。
    fn sys_getresid(&mut self, env: &mut BareEnv, a: [u64; 3]) -> Result<u64, u64> {
        for p in a {
            if p != 0 {
                self.put_u32(env, p, 0)?;
            }
        }
        Ok(0)
    }

    /// ソケット系 syscall を `sock` 正準層へ委譲する。待ち要求は
    /// 単一スレッド消化で進め、進行不能はデッドロックとして報告。
    /// 戻り値 Err はゲスト errno（asm-generic と同値）。
    fn sock_call(&mut self, env: &mut BareEnv, name: &str, a: &[u64; 6]) -> Result<u64, u64> {
        let abi = crate::sock::SockAbi::generic(4, Endian::Le);
        let map = crate::sock::unix_path_map(&self.guest_root, &self.cwd);
        let t0 = self.wait_epoch();
        let mono = move || t0.elapsed().as_nanos() as u64;
        match crate::sock::drive(&mut self.fds, &abi, env, name, a, &map, 0, &mono) {
            Some(Ok(v)) => Ok(v),
            Some(Err(e)) => {
                if e == crate::sock::errno::EDEADLK {
                    eprintln!("hexagon: deadlock in fd wait");
                }
                Err(u64::from((abi.errno)(e)))
            }
            None => Err(errno::ENOSYS),
        }
    }

    /// 待ち合わせ系 syscall を `wait` 正準層へ委譲する。
    /// fd 待ち用の時計起点。初回の待ちで立ち上げ、呼び出し間で
    /// 共有する（timerfd の期限を跨呼び出しで揃える）。
    fn wait_epoch(&mut self) -> std::time::Instant {
        *self.wait_start.get_or_insert_with(std::time::Instant::now)
    }

    fn wait_call(&mut self, env: &mut BareEnv, name: &str, a: &[u64; 6]) -> Result<u64, u64> {
        // hexagon は asm-generic：32 ビットでも timespec は 64 ビット幅。
        let mut abi = crate::wait::WaitAbi::generic(4, 8, Endian::Le);
        abi.epoll_ev_size = 16;
        let t0 = self.wait_epoch();
        let mono = move || t0.elapsed().as_nanos() as u64;
        match crate::wait::drive(&mut self.fds, &abi, env, name, a, 0, &mono) {
            Some(Ok(v)) => Ok(v),
            Some(Err(e)) => {
                if e == crate::sock::errno::EDEADLK {
                    eprintln!("hexagon: deadlock in fd wait");
                }
                Err(u64::from((abi.errno)(e)))
            }
            None => Err(errno::ENOSYS),
        }
    }

    /// dispatch。nr は r6、引数は r0-r5（32 ビットに折り返し済み）。
    fn dispatch(&mut self, env: &mut BareEnv, nr_: u64, a: [u64; 6]) -> Result<u64, u64> {
        if let Some(name) = hexagon::name(nr_)
            && crate::sock::NAMES.contains(&name)
        {
            return self.sock_call(env, name, &a);
        }
        if let Some(name) = hexagon::name(nr_)
            && crate::wait::NAMES.contains(&name)
        {
            return self.wait_call(env, name, &a);
        }
        match nr_ {
            nr::IOCTL => self.sys_ioctl(a[0] as u32, a[1], a[2]),
            nr::FCNTL64 => self.sys_fcntl(a[0] as u32, a[1], a[2]),
            nr::GETDENTS64 => self.sys_getdents64(env, a[0] as u32, a[1], a[2]),
            nr::OPENAT => self.sys_openat(env, a[0], a[1], a[2], a[3]),
            nr::CLOSE => {
                if a[0] < 3 {
                    Ok(0)
                } else if self.fds.ent(a[0] as u32).is_some() {
                    self.fds.clear(a[0] as u32);
                    Ok(0)
                } else {
                    Err(errno::EBADF)
                }
            }
            nr::LLSEEK => self.sys_llseek(env, a[0] as u32, a[1], a[2], a[3], a[4]),
            nr::READ => self.sys_read(env, a[0] as u32, a[1], a[2]),
            nr::WRITE => self.sys_write(env, a[0] as u32, a[1], a[2]),
            nr::READV => self.sys_readv(env, a[0] as u32, a[1], a[2]),
            nr::WRITEV => self.sys_writev(env, a[0] as u32, a[1], a[2]),
            // pread64/pwrite64 の pos は LE の 64 ビット引数対
            // （a[3]=下位, a[4]=上位 — BE の or1k と逆）。
            nr::PREAD64 => self.sys_pread(env, a[0] as u32, a[1], a[2], Self::pos64(&a)),
            nr::PWRITE64 => self.sys_pwrite(env, a[0] as u32, a[1], a[2], Self::pos64(&a)),
            nr::SENDFILE64 => self.sys_sendfile(env, a[0] as u32, a[1] as u32, a[2], a[3]),
            nr::READLINKAT => self.sys_readlinkat(env, a[0], a[1], a[2], a[3]),
            nr::FSTATAT64 => self.sys_fstatat(env, a[0], a[1], a[2], a[3]),
            nr::FSTAT64 => self.sys_fstat(env, a[0] as u32, a[1]),
            nr::STATX => self.sys_statx(env, a[0], a[1], a[2], a[3], a[4]),
            nr::EXIT | nr::EXIT_GROUP => unreachable!(),
            nr::SET_TID_ADDRESS => Ok(self.pid),
            nr::SET_ROBUST_LIST => Ok(0),
            nr::NANOSLEEP => self.sys_nanosleep(env, a[0], a[1]),
            nr::CLOCK_GETTIME => self.sys_clock_gettime(env, a[0], a[1]),
            nr::CLOCK_GETRES => self.sys_clock_getres(env, a[1], false),
            nr::CLOCK_NANOSLEEP => self.sys_nanosleep(env, a[2], a[3]),
            nr::CLOCK_GETTIME64 => self.sys_clock_gettime64(env, a[0], a[1]),
            nr::CLOCK_GETRES_TIME64 => self.sys_clock_getres(env, a[1], true),
            nr::CLOCK_NANOSLEEP_TIME64 => {
                // timespec64 {i64,i64} を読んで nanosleep に委ねる。
                let sec = self.mem_u64(env, a[2]);
                let nsec = self.mem_u64(env, a[2] + 8);
                let d = std::time::Duration::new(sec, nsec as u32);
                if d.as_millis() < 5000 {
                    std::thread::sleep(d);
                }
                Ok(0)
            }
            nr::RT_SIGACTION => self.sys_rt_sigaction(env, a[2], a[3]),
            nr::RT_SIGPROCMASK => self.sys_rt_sigprocmask(env, a[0], a[1], a[2], a[3]),
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
            | nr::SETFSGID
            | nr::SETPGID
            | nr::SETGROUPS
            | nr::FCHOWN
            | nr::FCHOWNAT => Ok(0),
            nr::GETRESUID | nr::GETRESGID => self.sys_getresid(env, [a[0], a[1], a[2]]),
            nr::GETGROUPS => self.sys_getgroups(a[0], a[1]),
            nr::BRK => Ok(self.sys_brk(env, a[0])),
            nr::MUNMAP => self.sys_munmap(env, a[0], a[1]),
            nr::MMAP2 => self.sys_mmap2(env, a),
            nr::MPROTECT => self.sys_mprotect(env, a[0], a[1], a[2]),
            // prlimit64(pid, res, new_rlim, old_rlim)。
            nr::PRLIMIT64 => self.sys_prlimit64(env, a[1], a[2], a[3]),
            nr::GETRLIMIT => self.sys_getrlimit(env, a[0], a[1]),
            nr::SETRLIMIT => self.sys_setrlimit(a[0]),
            nr::GETRANDOM => self.sys_getrandom(env, a[0], a[1], a[2]),
            nr::FACCESSAT | nr::FACCESSAT2 => self.sys_faccessat(env, a[0], a[1], a[3]),
            nr::GETCWD => self.sys_getcwd(env, a[0], a[1]),
            nr::CHDIR => self.sys_chdir(env, a[0]),
            nr::FCHDIR => self.sys_fchdir(a[0] as u32),
            nr::MKDIRAT => self.sys_mkdirat(env, a[0], a[1], a[2]),
            nr::UNLINKAT => self.sys_unlinkat(env, a[0], a[1], a[2]),
            nr::RENAMEAT => self.sys_renameat(env, a[0], a[1], a[2], a[3]),
            nr::SYMLINKAT => self.sys_symlinkat(env, a[0], a[1], a[2]),
            nr::LINKAT => self.sys_linkat(env, a[0], a[1], a[2], a[3]),
            nr::MKNODAT => self.sys_mknodat(env, a[0], a[1], a[2], a[3]),
            nr::TRUNCATE64 => self.sys_truncate(env, a[0], false, (-100i64) as u64, a[1]),
            nr::FTRUNCATE64 => self.sys_truncate(env, a[0], true, 0, a[1]),
            nr::FCHMOD => {
                let Some(f) = self.fds.file(a[0] as u32) else {
                    return Err(errno::EBADF);
                };
                polyisa_host::fchmod(f, (a[1] & 0o7777) as u32)
                    .map_err(|e| host_errno(e.raw_os_error()))?;
                Ok(0)
            }
            nr::FCHMODAT => self.sys_fchmodat(env, a[0], a[1], a[2]),
            nr::STATFS64 => self.sys_statfs(env, a[0], a[1], a[2]),
            nr::FSTATFS64 => {
                if a[0] < 3 && self.fds.file(a[0] as u32).is_none() {
                    return Err(errno::EBADF);
                }
                self.put_statfs(env, a[2]).map(|()| 0)
            }
            nr::UTIMENSAT => self.sys_utimensat(env, a[0], a[1], a[2], a[3]),
            nr::GETTIMEOFDAY => self.sys_gettimeofday(env, a[0], a[1]),
            nr::SYSINFO => self.sys_sysinfo(env, a[0]),
            nr::TIMES => self.sys_times(env, a[0]),
            nr::GETRUSAGE => self.sys_getrusage(env, a[0], a[1]),
            nr::SCHED_GETAFFINITY => self.sys_sched_getaffinity(env, a[0], a[1], a[2]),
            nr::GETCPU => self.sys_getcpu(env, a[0], a[1], a[2]),
            nr::DUP => self.sys_dup(a[0] as u32),
            nr::DUP3 => self.sys_dup3(a[0] as u32, a[1] as u32, a[2]),
            nr::COPY_FILE_RANGE => {
                self.sys_copy_file_range(env, a[0] as u32, a[1], a[2] as u32, a[3], a[4])
            }
            // umask は新旧の入れ替えだけを行う。
            nr::UMASK => {
                let old = self.umask;
                self.umask = (a[0] & 0o777) as u32;
                Ok(u64::from(old))
            }
            // personality・sched 系・シグナル枠組み・メモリ通知・
            // 同期系は受理のみ（配送・反映はしない近似 —
            nr::PERSONALITY => Ok(0),
            nr::SIGALTSTACK
            | nr::RT_SIGPENDING
            | nr::RT_SIGRETURN
            | nr::SETPRIORITY
            | nr::PRCTL
            | nr::SETSID
            | nr::MADVISE
            | nr::MSYNC
            | nr::MINCORE
            | nr::MLOCK
            | nr::MUNLOCK
            | nr::MLOCKALL
            | nr::MUNLOCKALL
            | nr::FLOCK
            | nr::SYNC
            | nr::FSYNC
            | nr::FDATASYNC
            | nr::SYNC_FILE_RANGE2
            | nr::FADVISE64_64
            | nr::SCHED_YIELD
            | nr::SCHED_SETPARAM
            | nr::SCHED_SETSCHEDULER
            | nr::SCHED_SETAFFINITY
            | nr::IOPRIO_SET
            | nr::SETHOSTNAME
            | nr::SETDOMAINNAME
            | nr::VHANGUP
            | nr::RESTART_SYSCALL => Ok(0),
            nr::GETPRIORITY => Ok(0),
            nr::GETPGID | nr::GETSID => Ok(self.pid),
            nr::SCHED_GET_PRIORITY_MAX | nr::SCHED_GET_PRIORITY_MIN => Ok(0),
            // futex は単一スレッド模型で競合しない。ENOSYS（or1k と
            // 同じ近似）。
            nr::FUTEX | nr::FUTEX_TIME64 => Err(errno::ENOSYS),
            _ => Err(errno::ENOSYS),
        }
    }
}

/// `handle_trap` 内の syscall ディスパッチ。
impl TrapHandler for Linux {
    fn handle_trap(&mut self, env: &mut BareEnv, code: u32) -> TrapOutcome {
        // Linux hexagon の syscall 発行点は trap0(#1)。
        // それ以外の trap0 番号・trap1 は未実装として止める。
        // Ref: SRC-LINUX-HEXAGON-UAPI — kernel/vm_entry.S
        // （`do_trap0(#1)` が syscall 入口）。
        if code != 1 {
            return TrapOutcome::Unimplemented;
        }
        let nr_ = self.rget(env, 6);
        let a = [
            self.rget(env, 0),
            self.rget(env, 1),
            self.rget(env, 2),
            self.rget(env, 3),
            self.rget(env, 4),
            self.rget(env, 5),
        ];
        if std::env::var_os("POLYISA_HEXAGON_SYSCALL").is_some() {
            eprintln!(
                "hexagon: syscall {}({}) args={:x?}",
                hexagon::name(nr_).unwrap_or("?"),
                nr_,
                a
            );
        }
        if nr_ == nr::EXIT || nr_ == nr::EXIT_GROUP {
            return TrapOutcome::Exit((a[0] & 0xff) as u32);
        }
        let r = self.dispatch(env, nr_, a);
        if let Err(e) = r
            && e == errno::ENOSYS
            && !self.reported.contains(&nr_)
        {
            self.reported.push(nr_);
            eprintln!(
                "hexagon: 未実装 syscall {}（{}）",
                nr_,
                hexagon::name(nr_).unwrap_or("?")
            );
        }
        self.ret(env, r);
        TrapOutcome::Handled
    }

    fn init_brk(&mut self, image_end: u64) {
        self.brk_start = (image_end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        self.heap_end = self.brk_start;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_guest_hexagon::CpuState;

    fn env() -> BareEnv {
        BareEnv::new(core::mem::size_of::<CpuState>())
    }

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("polyisa-hexagon-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// trap0(#1) で r6=番号・r0-r5=引数・r0=戻り値の規約。
    /// Ref: SRC-LINUX-HEXAGON-UAPI — kernel-asm/syscall.h.
    #[test]
    fn trap0_one_dispatches_syscall_via_r6_r0() {
        let mut sys = Linux::new();
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x4000), 1, Perms::RW).unwrap();
        // getpid → r0 に pid が返る。
        sys.rset(&mut env, 6, nr::GETPID);
        let r = sys.handle_trap(&mut env, 1);
        assert_eq!(r, TrapOutcome::Handled);
        assert_eq!(sys.rget(&mut env, 0), sys.pid);
        // write(1, buf, len) は a=r0..r2、戻り値 r0=len。
        env.backend.mem.write(VirtAddr(0x4000), b"hi").unwrap();
        sys.rset(&mut env, 6, nr::WRITE);
        sys.rset(&mut env, 0, 1);
        sys.rset(&mut env, 1, 0x4000);
        sys.rset(&mut env, 2, 2);
        assert_eq!(sys.handle_trap(&mut env, 1), TrapOutcome::Handled);
        assert_eq!(sys.rget(&mut env, 0), 2);
        assert_eq!(sys.io.stdout, b"hi");
        // exit_group は Exit で返す（レジスタ経路は使わない）。
        sys.rset(&mut env, 6, nr::EXIT_GROUP);
        sys.rset(&mut env, 0, 7);
        assert_eq!(sys.handle_trap(&mut env, 1), TrapOutcome::Exit(7));
        // trap0(#0)/(#2) など 1 以外は未実装で止める。
        assert_eq!(sys.handle_trap(&mut env, 0), TrapOutcome::Unimplemented);
        assert_eq!(sys.handle_trap(&mut env, 2), TrapOutcome::Unimplemented);
    }

    /// `llseek(fd, hi, lo, result*, whence)` — result* に u64(LE)
    /// を書いて 0 を返す（asm-generic 32 ビット規約）。
    /// Ref: SRC-LINUX — fs/read_write.c sys_llseek.
    #[test]
    fn llseek_writes_result_pointer_le() {
        let dir = tmpdir("llseek");
        let f = dir.join("f");
        std::fs::write(&f, b"0123456789abcdef").unwrap();
        let mut sys = Linux::new();
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
        let fd = sys.fds.alloc(polyisa_kernel::FdTarget::File(
            std::fs::File::open(&f).unwrap(),
        ));
        // SEEK_SET で off=0x1_0000_0006（hi=1, lo=6）。
        let r = sys.sys_llseek(&mut env, fd, 1, 6, 0x2000, 0);
        assert_eq!(r, Ok(0));
        let pos = sys.fds.file_mut(fd).unwrap().stream_position().unwrap();
        let b = sys.get_bytes(&mut env, 0x2000, 8).unwrap();
        assert_eq!(u64::from_le_bytes(b.try_into().unwrap()), pos);
        assert_eq!(pos, 0x1_0000_0006);
        let r = sys.sys_llseek(&mut env, fd, 0, 0, 0x2000, 2);
        assert_eq!(r, Ok(0));
        let b = sys.get_bytes(&mut env, 0x2000, 8).unwrap();
        assert_eq!(u64::from_le_bytes(b.try_into().unwrap()), 16);
        assert_eq!(
            sys.sys_llseek(&mut env, fd, 0, 0, 0x2000, 9),
            Err(errno::EINVAL)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `mmap2` の pgoff は 4KiB ページ単位（sys_mmap_pgoff）。
    /// pgoff=2 ならファイルの 0x2000 から読む。
    /// Ref: SRC-LINUX — mm/mmap.c sys_mmap2,
    /// kernel/syscalltab.c（sys_mmap2→sys_mmap_pgoff）.
    #[test]
    fn mmap2_pgoff_is_page_units() {
        let dir = tmpdir("mmap2");
        let f = dir.join("f");
        let mut data = vec![0u8; 0x4000];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i >> 8) as u8;
        }
        std::fs::write(&f, &data).unwrap();
        let mut sys = Linux::new();
        let mut env = env();
        let fd = sys.fds.alloc(polyisa_kernel::FdTarget::File(
            std::fs::File::open(&f).unwrap(),
        ));
        // MAP_PRIVATE|MAP_FIXED, prot=R, pgoff=2 → 0x8000 に
        // data[0x2000..] を載せる。
        let a = [0x8000, 0x1000, 1, 0x12, u64::from(fd), 2];
        let r = sys.sys_mmap2(&mut env, a);
        assert_eq!(r, Ok(0x8000));
        let got = sys.get_bytes(&mut env, 0x8000, 0x10).unwrap();
        assert_eq!(&got[..], &data[0x2000..0x2010]);
        // 読み取り専用の要求では W は立たない（protect で戻す）。
        assert!(sys.put_bytes(&mut env, 0x8000, &[0xaa]).is_err());
        // 匿名写像はページゼロ。
        let a = [0, 0x1000, 3, 0x22, u64::MAX, 0];
        let r = sys.sys_mmap2(&mut env, a).unwrap();
        let got = sys.get_bytes(&mut env, r, 4).unwrap();
        assert_eq!(got, [0, 0, 0, 0]);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// asm-generic `struct stat64`（104B・LE）のレイアウト。
    /// Ref: SRC-LINUX — include/uapi/asm-generic/stat.h.
    #[test]
    fn stat64_layout_asm_generic_le() {
        let dir = tmpdir("stat64");
        let f = dir.join("f");
        std::fs::write(&f, b"abc").unwrap();
        let mut sys = Linux::new();
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x4000), 1, Perms::RW).unwrap();
        let fd = sys.fds.alloc(polyisa_kernel::FdTarget::File(
            std::fs::File::open(&f).unwrap(),
        ));
        let r = sys.sys_fstat(&mut env, fd, 0x4000);
        assert_eq!(r, Ok(0));
        let b = sys.get_bytes(&mut env, 0x4000, 104).unwrap();
        let r32 = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let r64 = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let md = polyisa_host::stat(&f.to_string_lossy()).unwrap();
        assert_eq!(r64(0), md.dev, "st_dev @0");
        assert_eq!(r64(8), md.ino, "st_ino @8");
        assert_eq!(r32(16) & 0o170000, 0o100000, "st_mode S_IFREG @16");
        assert_eq!(r32(24), md.uid, "st_uid @24");
        assert_eq!(r64(48), 3, "st_size @48");
        assert_eq!(r32(56), md.blksize as u32, "st_blksize @56");
        assert_eq!(r64(64), md.blocks, "st_blocks @64");
        assert_eq!(r32(72), md.atime as u32, "st_atime @72");
        assert_eq!(r32(80), md.mtime as u32, "st_mtime @80");
        assert_eq!(r32(88), md.ctime as u32, "st_ctime @88");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `pread64` の pos は LE の 64 ビット引数対（a[3]=下位,
    /// a[4]=上位）。回帰: BE の or1k と逆。
    #[test]
    fn pread64_offset_pair_le() {
        let dir = tmpdir("pread");
        let f = dir.join("f");
        std::fs::write(&f, b"0123456789abcdef").unwrap();
        let mut sys = Linux::new();
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x5000), 1, Perms::RW).unwrap();
        let fd = sys.fds.alloc(polyisa_kernel::FdTarget::File(
            std::fs::File::open(&f).unwrap(),
        ));
        // pos = 0x0000_0001_0000_0004 → a[3]=4（下位）, a[4]=1（上位）。
        let a = [u64::from(fd), 0x5000, 4, 4, 1, 0];
        let off = Linux::pos64(&a);
        assert_eq!(off, 0x1_0000_0004);
        let r = sys.sys_pread(&mut env, fd, 0x5000, 4, 4);
        assert_eq!(r, Ok(4));
        assert_eq!(sys.get_bytes(&mut env, 0x5000, 4).unwrap(), b"4567");
        assert_eq!(sys.fds.file_mut(fd).unwrap().stream_position().unwrap(), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `prlimit64` は old に rlimit64（u64×2 無限・LE）を書く。
    #[test]
    fn prlimit64_writes_rlimit() {
        let mut sys = Linux::new();
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x6000), 1, Perms::RW).unwrap();
        assert_eq!(sys.sys_prlimit64(&mut env, 7, 0, 0x6000), Ok(0));
        let b = sys.get_bytes(&mut env, 0x6000, 16).unwrap();
        assert_eq!(u64::from_le_bytes(b[0..8].try_into().unwrap()), u64::MAX);
        assert_eq!(u64::from_le_bytes(b[8..16].try_into().unwrap()), u64::MAX);
        assert_eq!(
            sys.sys_prlimit64(&mut env, 16, 0, 0x6000),
            Err(errno::EINVAL)
        );
    }

    /// `rt_sigprocmask` は sigsetsize=8 必須で blocked マスクを
    /// 往復する（SIGKILL/SIGSTOP は落ちる・LE）。
    #[test]
    fn rt_sigprocmask_roundtrip() {
        let mut sys = Linux::new();
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x7000), 1, Perms::RW).unwrap();
        env.backend
            .mem
            .write(
                VirtAddr(0x7000),
                &(1u64 << 8 | 1u64 << 3 | 1u64 << 18).to_le_bytes(),
            )
            .unwrap();
        let r = sys.sys_rt_sigprocmask(&mut env, 2, 0x7000, 0x7008, 8);
        assert_eq!(r, Ok(0));
        let b = sys.get_bytes(&mut env, 0x7008, 8).unwrap();
        assert_eq!(u64::from_le_bytes(b.try_into().unwrap()), 0);
        assert_eq!(sys.sig_mask, 1 << 3);
        assert_eq!(
            sys.sys_rt_sigprocmask(&mut env, 2, 0, 0, 4),
            Err(errno::EINVAL)
        );
    }

    /// `uname` の machine は "hexagon"。
    #[test]
    fn uname_machine_is_hexagon() {
        let mut sys = Linux::new();
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x8000), 1, Perms::RW).unwrap();
        assert_eq!(sys.sys_uname(&mut env, 0x8000), Ok(0));
        let b = sys.get_bytes(&mut env, 0x8000 + 65 * 4, 7).unwrap();
        assert_eq!(&b[..], b"hexagon");
    }
}
