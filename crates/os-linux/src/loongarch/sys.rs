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
use polyisa_mem::{Access, AccessKind, Align, Endian, PAGE_SIZE, PageNo, Perms, VirtAddr};
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
    pub const ENOTDIR: u64 = 20;
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
    /// ゲストのルート。空は隔離なし（従来動作）。
    guest_root: String,
    /// 実行ファイルのパス。`readlinkat("/proc/self/exe")` が返す。
    pub exe_path: String,
    /// 標準入力へ供給するバイト。
    pub stdin_buf: Vec<u8>,
    stdin_pos: usize,
    /// ディレクトリ fd の getdents 位置（次に出すエントリの添字）。
    dir_pos: std::collections::BTreeMap<u32, u64>,
    /// MONOTONIC 時計の起点。
    mono_start: Option<std::time::Instant>,
    /// LA32 モデルか（ポインタ引数を 32 ビットに折り返す）。
    pub la64: bool,
    /// umask の保持値。
    umask: u32,
    /// 報告済みの未実装番号（一度だけ出す）。
    reported: Vec<u64>,
    /// スタック成長窓 `[lo, hi)`。syscall が読み書きする
    /// ユーザバッファがこの窓内の未マップページに掛かるとき、
    /// Linux の GROWSDOWN VMA 相当に遅延割付する。
    /// 0/0 は成長しない（root 未指定の旧来動作）。
    stack_lo: u64,
    stack_hi: u64,
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
            guest_root: String::new(),
            exe_path: String::new(),
            stdin_buf: Vec::new(),
            stdin_pos: 0,
            dir_pos: std::collections::BTreeMap::new(),
            mono_start: None,
            la64: true,
            umask: 0o22,
            reported: Vec::new(),
            stack_lo: 0,
            stack_hi: 0,
        }
    }

    /// syscall のバッファアクセスが伸ばし得るスタック窓を設定する。
    /// ローダが `StackGrowth` に渡す `[limit, top)` と同じ範囲。
    /// Ref: SRC-LINUX (7.3) — expand_stack / GROWSDOWN VMA は
    /// カーネルのユーザコピー（copy_to_user 等）でも下方成長する。
    pub fn set_stack_window(&mut self, lo: u64, hi: u64) {
        self.stack_lo = lo;
        self.stack_hi = hi;
    }

    /// `[addr, addr+len)` の未マップページをスタック窓の中で割付る。
    /// 窓外に掛かる場合でも窓内の分は埋める（Linux は VMA に
    /// 部分的に掛かる copy_to_user で窓内のページは埋める）。
    fn grow_stack(&self, env: &mut BareEnv, addr: u64, len: u64) {
        if self.stack_hi <= self.stack_lo || len == 0 {
            return;
        }
        let first = addr & !PAGE_SIZE.wrapping_sub(1);
        let last = addr.wrapping_add(len - 1) & !PAGE_SIZE.wrapping_sub(1);
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
        let a = self.ptr(addr);
        if env
            .backend
            .mem
            .read(VirtAddr(a), &mut buf, self.acc(AccessKind::DataRead))
            .is_err()
        {
            // スタック窓内なら GROWSDOWN 相当に割付てから再試行。
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
        let a = self.ptr(addr);
        if env.backend.mem.write(VirtAddr(a), data).is_err() {
            self.grow_stack(env, a, data.len() as u64);
            env.backend
                .mem
                .write(VirtAddr(a), data)
                .map_err(|_| errno::EFAULT)?;
        }
        Ok(())
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
            _ if self.fds.file(fd).is_some() => Ok(WriteFd::File),
            _ => Err(errno::EBADF),
        }
    }

    fn sys_write(&mut self, env: &mut BareEnv, fd: u32, buf: u64, len: u64) -> Result<u64, u64> {
        if fd >= 3 && self.fds.target(fd).is_some() && self.fds.file(fd).is_none() {
            // ファイル以外の対象（eventfd 等）は fd 表経由。
            let abi = crate::wait::WaitAbi::generic(8, 8, Endian::Le);
            let t0 = std::time::Instant::now();
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
        if fd >= 3 && self.fds.target(fd).is_some() && self.fds.file(fd).is_none() {
            // ファイル以外の対象（eventfd・timerfd 等）は fd 表経由。
            let abi = crate::wait::WaitAbi::generic(8, 8, Endian::Le);
            let t0 = std::time::Instant::now();
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
        let Some(f) = self.fds.file_mut(fd) else {
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
        if self.fds.ent(fd).is_some() {
            self.fds.clear(fd);
            Ok(0)
        } else {
            Err(errno::EBADF)
        }
    }

    /// `openat`（O_* フラグは asm-generic の値）。
    /// O_NOFOLLOW（0o400000）がなければ最終要素のリンクを辿る。
    fn sys_openat(
        &mut self,
        env: &mut BareEnv,
        dirfd: u64,
        path: u64,
        flags: u64,
        _mode: u64,
    ) -> Result<u64, u64> {
        let guest_path = self.cstr(env, path)?;
        const O_NOFOLLOW: u64 = 0o400000;
        let full = if flags & O_NOFOLLOW != 0 {
            self.host_path(dirfd, &guest_path)
        } else {
            self.host_path_followed(dirfd, &guest_path)
        };
        let Some(full) = full else {
            return Err(errno::EACCES);
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
                let fd = self.fds.alloc(polyisa_kernel::FdTarget::File(f));
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
            _ => match self.fds.file(fd) {
                Some(f) => polyisa_host::fstat(f).map_err(|e| host_errno(e.raw_os_error()))?,
                None => return Err(errno::EBADF),
            },
        };
        self.put_stat(env, addr, &md)?;
        Ok(0)
    }

    /// `newfstatat`。AT_SYMLINK_NOFOLLOW（0x100）で最終要素の
    /// リンク解釈を止める。
    fn sys_fstatat(
        &mut self,
        env: &mut BareEnv,
        dirfd: u64,
        path: u64,
        addr: u64,
        flags: u64,
    ) -> Result<u64, u64> {
        let guest_path = self.cstr(env, path)?;
        const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
        let full = if flags & AT_SYMLINK_NOFOLLOW != 0 {
            self.host_path(dirfd, &guest_path)
        } else {
            self.host_path_followed(dirfd, &guest_path)
        };
        let Some(full) = full else {
            return Err(errno::EACCES);
        };
        let md = if flags & AT_SYMLINK_NOFOLLOW != 0 {
            polyisa_host::lstat(&full)
        } else {
            polyisa_host::stat(&full)
        }
        .map_err(|e| host_errno(e.raw_os_error()))?;
        self.put_stat(env, addr, &md)?;
        Ok(0)
    }

    /// `statx`（asm-generic の `struct statx`、256 バイト）。
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
        let guest_path = self.cstr(env, path)?;
        const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
        const AT_EMPTY_PATH: u64 = 0x1000;
        let full = if flags & AT_EMPTY_PATH != 0 && guest_path.is_empty() {
            self.fds
                .path_of(dirfd as u32)
                .map(str::to_string)
                .unwrap_or_default()
        } else if flags & AT_SYMLINK_NOFOLLOW != 0 {
            match self.host_path(dirfd, &guest_path) {
                Some(p) => p,
                None => return Err(errno::EACCES),
            }
        } else {
            match self.host_path_followed(dirfd, &guest_path) {
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
        // Linux の dev_t 符号化（new_encode_dev）から major/minor
        // を取り出す（new_decode_dev の逆）。
        let major = |d: u64| -> u32 { (((d >> 8) & 0xfff) | (d >> 32)) as u32 };
        let minor = |d: u64| -> u32 { ((d & 0xff) | ((d >> 12) & !0xff)) as u32 };
        // UAPI `struct statx`（include/uapi/linux/stat.h）の
        // オフセット: ino@0x20、size@0x28、blocks@0x30、
        // attributes_mask@0x38、atime@0x40、btime@0x50、
        // ctime@0x60、mtime@0x70、rdev_{major,minor}@0x80/0x84、
        // dev_{major,minor}@0x88/0x8c、mnt_id@0x90。
        // btime/mnt_id/attributes は未提供なので 0 のまま残し、
        // mask は STATX_BASIC_STATS（提供分）に合わせる。
        w32(0x7ff, &mut b[0..4]); // mask = STATX_BASIC_STATS
        w32(md.blksize as u32, &mut b[4..8]); // blksize
        // attributes @0x08 = 0。
        w32(md.nlink as u32, &mut b[16..20]);
        w32(md.uid, &mut b[20..24]);
        w32(md.gid, &mut b[24..28]);
        w16(md.mode as u16, &mut b[28..30]);
        w64(md.ino, &mut b[32..40]);
        w64(md.size, &mut b[40..48]);
        w64(md.blocks, &mut b[48..56]);
        // attributes_mask @0x38 = 0（attributes を出さない）。
        w64(md.atime as u64, &mut b[64..72]);
        w32(md.atime_nsec as u32, &mut b[72..76]);
        // btime @0x50 未提供。
        w64(md.ctime as u64, &mut b[96..104]);
        w32(md.ctime_nsec as u32, &mut b[104..108]);
        w64(md.mtime as u64, &mut b[112..120]);
        w32(md.mtime_nsec as u32, &mut b[120..124]);
        w32(major(md.rdev), &mut b[128..132]);
        w32(minor(md.rdev), &mut b[132..136]);
        w32(major(md.dev), &mut b[136..140]);
        w32(minor(md.dev), &mut b[140..144]);
        // mnt_id @0x90 未提供。
        self.put_bytes(env, out, &b)?;
        Ok(0)
    }

    /// `faccessat`。実在確認だけ（モードの検査はしない）。
    fn sys_faccessat(
        &mut self,
        env: &mut BareEnv,
        dirfd: u64,
        path: u64,
        _mode: u64,
        _flags: u64,
    ) -> Result<u64, u64> {
        let guest_path = self.cstr(env, path)?;
        let Some(full) = self.host_path_followed(dirfd, &guest_path) else {
            return Err(errno::EACCES);
        };
        match std::fs::metadata(&full) {
            Ok(_) => Ok(0),
            Err(e) => Err(host_errno(e.raw_os_error())),
        }
    }

    /// `getdents64`。linux_dirent64: u64 d_ino, u64 d_off, u16 d_reclen,
    /// u8 d_type, name\0。`.`/`..` を先頭に合成する。
    fn sys_getdents64(
        &mut self,
        env: &mut BareEnv,
        fd: u32,
        buf: u64,
        count: u64,
    ) -> Result<u64, u64> {
        let path = self.fds.path_of(fd).map(str::to_string).unwrap_or_default();
        if path.is_empty() {
            return Err(errno::ENOTDIR);
        }
        let rd = std::fs::read_dir(&path).map_err(|e| host_errno(e.raw_os_error()))?;
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
                    8
                };
                (ino, e.file_name().to_string_lossy().into_owned(), t)
            })
            .collect();
        entries.sort_by(|a, b| a.1.cmp(&b.1));
        let mut all = vec![(1u64, ".".to_string(), 4u8), (1, "..".to_string(), 4u8)];
        all.extend(entries);
        let count = count as usize;
        // 呼び出しごとに位置を進める。d_off は次のエントリの添字 +1。
        let mut i = usize::try_from(self.dir_pos.get(&fd).copied().unwrap_or(0)).unwrap_or(0);
        let mut out = Vec::new();
        for (ino, name, t) in all.iter().skip(i) {
            let reclen = 19 + name.len() + 1;
            let aligned = reclen.next_multiple_of(8);
            if out.len() + aligned > count {
                break;
            }
            let next = (i + 1) as u64;
            out.extend_from_slice(&ino.to_le_bytes());
            out.extend_from_slice(&next.to_le_bytes());
            out.extend_from_slice(&(aligned as u16).to_le_bytes());
            out.push(*t);
            out.extend_from_slice(name.as_bytes());
            out.push(0);
            out.resize(out.len() + (aligned - reclen), 0);
            i += 1;
        }
        self.dir_pos.insert(fd, i as u64);
        self.put_bytes(env, buf, &out)?;
        Ok(out.len() as u64)
    }

    /// `gettimeofday`。timeval = {sec, usec}。
    fn sys_gettimeofday(&mut self, env: &mut BareEnv, tv: u64, _tz: u64) -> Result<u64, u64> {
        if tv != 0 {
            let d = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            self.put_u64(env, tv, d.as_secs())?;
            self.put_u64(env, tv + 8, u64::from(d.subsec_micros()))?;
        }
        Ok(0)
    }

    /// `sysinfo`。合成値（free 1 GiB 総メモリ 1 GiB 風）。
    fn sys_sysinfo(&mut self, env: &mut BareEnv, addr: u64) -> Result<u64, u64> {
        let mut b = [0u8; 112];
        let w64 = |v: u64, b: &mut [u8]| b.copy_from_slice(&v.to_le_bytes());
        let w32 = |v: u32, b: &mut [u8]| b.copy_from_slice(&v.to_le_bytes());
        let w16 = |v: u16, b: &mut [u8]| b.copy_from_slice(&v.to_le_bytes());
        let start = *self.mono_start.get_or_insert_with(std::time::Instant::now);
        w64(start.elapsed().as_secs(), &mut b[0..8]); // uptime
        // loads[3] は 0 のまま。
        w64(1 << 30, &mut b[32..40]); // totalram
        w64(1 << 30, &mut b[40..48]); // freeram
        w64(1 << 29, &mut b[48..56]); // sharedram
        w16(2, &mut b[104..106]); // procs
        w32(1, &mut b[108..112]); // mem_unit
        self.put_bytes(env, addr, &b)?;
        Ok(0)
    }

    /// `times`。tms 4×u64 を 0 で返し、経過 tick を戻す。
    fn sys_times(&mut self, env: &mut BareEnv, buf: u64) -> Result<u64, u64> {
        if buf != 0 {
            self.put_bytes(env, buf, &[0u8; 32])?;
        }
        let start = *self.mono_start.get_or_insert_with(std::time::Instant::now);
        Ok(start.elapsed().as_millis() as u64 / 10)
    }

    /// `getrusage`。最小の 0 初期化（ru_utime/ru_stime のみ使う実装が多い）。
    fn sys_getrusage(&mut self, env: &mut BareEnv, _who: u64, buf: u64) -> Result<u64, u64> {
        self.put_bytes(env, buf, &[0u8; 144])?;
        Ok(0)
    }

    /// `statfs`/`fstatfs` 共通の合成値書き込み（asm-generic、120 バイト）。
    fn put_statfs(&self, env: &mut BareEnv, addr: u64) -> Result<(), u64> {
        let mut b = [0u8; 120];
        let w64 = |v: u64, b: &mut [u8]| b.copy_from_slice(&v.to_le_bytes());
        w64(0x0102_1997, &mut b[0..8]); // f_type = TMPFS 風
        w64(4096, &mut b[8..16]); // f_bsize
        w64(1 << 20, &mut b[16..24]); // f_blocks
        w64(1 << 19, &mut b[24..32]); // f_bfree
        w64(1 << 19, &mut b[32..40]); // f_bavail
        w64(255, &mut b[64..72]); // f_namelen
        w64(4096, &mut b[72..80]); // f_frsize
        self.put_bytes(env, addr, &b)
    }

    /// `statfs`。パスの存在確認だけ行う。
    fn sys_statfs(&mut self, env: &mut BareEnv, path: u64, addr: u64) -> Result<u64, u64> {
        let guest_path = self.cstr(env, path)?;
        let Some(full) = self.host_path_followed((-100i64) as u64, &guest_path) else {
            return Err(errno::EACCES);
        };
        if std::fs::metadata(&full).is_err() {
            return Err(errno::ENOENT);
        }
        self.put_statfs(env, addr)?;
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
        let guest_path = self.cstr(env, path)?;
        let Some(full) = self.host_path(dirfd, &guest_path) else {
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
        let guest_path = self.cstr(env, path)?;
        let Some(full) = self.host_path(dirfd, &guest_path) else {
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

    /// `ftruncate`/`truncate`。
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
            let guest_path = self.cstr(env, fd_or_path)?;
            let Some(full) = self.host_path(dirfd, &guest_path) else {
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

    /// `fchmod`（host chmod 相当）。
    fn sys_fchmod(&mut self, fd: u32, mode: u64) -> Result<u64, u64> {
        let Some(f) = self.fds.file(fd) else {
            return Err(errno::EBADF);
        };
        polyisa_host::fchmod(f, (mode & 0o7777) as u32)
            .map_err(|e| host_errno(e.raw_os_error()))?;
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
        let guest_path = self.cstr(env, path)?;
        let Some(full) = self.host_path_followed(dirfd, &guest_path) else {
            return Err(errno::EACCES);
        };
        polyisa_host::chmod(&full, (mode & 0o7777) as u32)
            .map_err(|e| host_errno(e.raw_os_error()))?;
        Ok(0)
    }

    /// `utimensat`。times が NULL なら現在時刻、配列なら
    /// atime/mtime を mtime だけ std で近似する。
    /// Gap: GAP-0062（atime 側の反映はしない）。
    fn sys_utimensat(
        &mut self,
        env: &mut BareEnv,
        dirfd: u64,
        path: u64,
        times: u64,
        flags: u64,
    ) -> Result<u64, u64> {
        let guest_path = self.cstr(env, path)?;
        const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
        let full = if flags & AT_SYMLINK_NOFOLLOW != 0 {
            self.host_path(dirfd, &guest_path)
        } else {
            self.host_path_followed(dirfd, &guest_path)
        };
        let Some(full) = full else {
            return Err(errno::EACCES);
        };
        let mtime = if times == 0 {
            std::time::SystemTime::now()
        } else {
            let sec = self.mem_u64(env, times + 16);
            let nsec = self.mem_u64(env, times + 24);
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

    /// `sendfile`。オフセット指定なし（out_fd の現位置へ継ぎ足す）
    /// の近似。in_fd の現位置は進める。
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

    /// `pread64`。
    fn sys_pread64(
        &mut self,
        env: &mut BareEnv,
        fd: u32,
        buf: u64,
        len: u64,
        off: u64,
    ) -> Result<u64, u64> {
        let len = (len as usize).min(1 << 20);
        let mut tmp = vec![0u8; len];
        let n = match self.fds.file_mut(fd) {
            Some(f) => {
                if f.seek(SeekFrom::Start(off)).is_err() {
                    return Err(errno::EINVAL);
                }
                match f.read(&mut tmp) {
                    Ok(n) => n,
                    Err(e) => return Err(host_errno(e.raw_os_error())),
                }
            }
            None => return Err(errno::EBADF),
        };
        self.put_bytes(env, buf, &tmp[..n])?;
        Ok(n as u64)
    }

    /// `chdir`。ゲストの cwd を更新するだけ（ホストの cwd は触らない）。
    fn sys_chdir(&mut self, env: &mut BareEnv, path: u64) -> Result<u64, u64> {
        let guest_path = self.cstr(env, path)?;
        let Some(full) = self.host_path_followed((-100i64) as u64, &guest_path) else {
            return Err(errno::EACCES);
        };
        match std::fs::metadata(&full) {
            Ok(md) if md.is_dir() => {}
            Ok(_) => return Err(errno::ENOTDIR),
            Err(e) => return Err(host_errno(e.raw_os_error())),
        }
        self.cwd = crate::guest_path::join_guest_path(&self.cwd, &guest_path);
        Ok(0)
    }

    /// ゲストパスをホストパスへ写す。dirfd は AT_FDCWD(-100)
    /// か `remember_path` で覚えたディレクトリ fd。
    /// 最終要素のシンボリックリンクは辿らない。
    fn host_path(&self, dirfd: u64, guest_path: &str) -> Option<String> {
        const AT_FDCWD: u64 = (-100i64) as u64;
        if guest_path.starts_with('/') || dirfd == AT_FDCWD {
            let r = crate::guest_path::resolve_guest_path(&self.guest_root, &self.cwd, guest_path)?;
            // devtmpfs 相当: ゲストルート配下にノードが無い `/dev/…`
            // はホストの devtmpfs へ通す（GAP-0062 のデバイス近似）。
            if !self.guest_root.is_empty()
                && guest_path.starts_with("/dev/")
                && !std::path::Path::new(&r).exists()
            {
                return Some(guest_path.to_string());
            }
            Some(r)
        } else {
            let dir = self.fds.path_of(dirfd as u32)?;
            // dirfd 経路はホストのディレクトリパスに直接連結する
            // （resolve の root は既に dir の中に含まれる）。
            let joined = format!("{}/{}", dir.trim_end_matches('/'), guest_path);
            Some(joined)
        }
    }

    /// `host_path` に最終要素のシンボリックリンク解釈を重ねる。
    /// dirfd 経路は `resolve_guest_path_links` に root+cwd で渡せる
    /// ゲスト側のフルパスを先に組み立てる。
    fn host_path_followed(&self, dirfd: u64, guest_path: &str) -> Option<String> {
        const AT_FDCWD: u64 = (-100i64) as u64;
        if guest_path.starts_with('/') || dirfd == AT_FDCWD || self.guest_root.is_empty() {
            if guest_path.starts_with('/') || dirfd == AT_FDCWD {
                let r = crate::guest_path::resolve_guest_path_links(
                    &self.guest_root,
                    &self.cwd,
                    guest_path,
                )?;
                // `host_path` と同じ devtmpfs 近似（GAP-0062）。
                if !self.guest_root.is_empty()
                    && guest_path.starts_with("/dev/")
                    && !std::path::Path::new(&r).exists()
                {
                    return Some(guest_path.to_string());
                }
                return Some(r);
            }
            // guest_root なしの dirfd 相対は host_path と同じ連結後、
            // ホスト側で辿る（最小近似）。
            return self.host_path(dirfd, guest_path);
        }
        // dirfd 相対: dir のホストパスを guest_root から剥がして
        // ゲスト側の絶対パスに戻し、リンク解釈へ回す。
        let dir = self.fds.path_of(dirfd as u32)?;
        let root_trim = self.guest_root.trim_end_matches('/');
        let rel = dir
            .strip_prefix(root_trim)
            .map(|s| s.trim_start_matches('/'))?;
        let g = format!("/{rel}/{guest_path}");
        crate::guest_path::resolve_guest_path_links(&self.guest_root, "/", &g)
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
            let Some(f) = self.fds.file_mut(fd as u32) else {
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
            b"7.3.0",
            b"#1 polyisa",
            if self.la64 {
                b"loongarch64"
            } else {
                b"loongarch32"
            },
            b"(none)",
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
                let Some(f) = self.fds.file(fd) else {
                    return Err(errno::EBADF);
                };
                let nf = f.try_clone().map_err(|e| host_errno(e.raw_os_error()))?;
                let nfd = self.fds.alloc(polyisa_kernel::FdTarget::File(nf));
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
        let Some(f) = self.fds.file(fd) else {
            return Err(errno::EBADF);
        };
        let nf = f.try_clone().map_err(|e| host_errno(e.raw_os_error()))?;
        Ok(u64::from(
            self.fds.alloc(polyisa_kernel::FdTarget::File(nf)),
        ))
    }
}

/// `handle_trap` 内の syscall ディスパッチ。
impl Linux {
    /// ソケット系 syscall を `sock` 正準層へ委譲する。待ち要求は
    /// 単一スレッド消化で進め、進行不能はデッドロックとして報告。
    /// 戻り値 Err はゲスト errno（asm-generic と同値）。
    fn sock_call(&mut self, env: &mut BareEnv, name: &str, a: &[u64]) -> Result<u64, u64> {
        let abi = crate::sock::SockAbi::generic(8, Endian::Le);
        let map = crate::sock::unix_path_map(&self.guest_root, &self.cwd);
        let mut a6 = [0u64; 6];
        a6[..a.len().min(6)].copy_from_slice(&a[..a.len().min(6)]);
        let t0 = std::time::Instant::now();
        let mono = move || t0.elapsed().as_nanos() as u64;
        match crate::sock::drive(&mut self.fds, &abi, env, name, &a6, &map, 0, &mono) {
            Some(Ok(v)) => Ok(v),
            Some(Err(e)) => {
                if e == crate::sock::errno::EDEADLK {
                    eprintln!("loongarch: deadlock in fd wait");
                }
                Err(u64::from((abi.errno)(e)))
            }
            None => Err(errno::ENOSYS),
        }
    }

    /// 待ち合わせ系 syscall を `wait` 正準層へ委譲する。
    fn wait_call(&mut self, env: &mut BareEnv, name: &str, a: &[u64]) -> Result<u64, u64> {
        let abi = crate::wait::WaitAbi::generic(8, 8, Endian::Le);
        let mut a6 = [0u64; 6];
        a6[..a.len().min(6)].copy_from_slice(&a[..a.len().min(6)]);
        let t0 = std::time::Instant::now();
        let mono = move || t0.elapsed().as_nanos() as u64;
        match crate::wait::drive(&mut self.fds, &abi, env, name, &a6, 0, &mono) {
            Some(Ok(v)) => Ok(v),
            Some(Err(e)) => {
                if e == crate::sock::errno::EDEADLK {
                    eprintln!("loongarch: deadlock in fd wait");
                }
                Err(u64::from((abi.errno)(e)))
            }
            None => Err(errno::ENOSYS),
        }
    }

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
        // ソケット系は `sock` 正準層へ委譲する。
        if let Some(name) = loongarch::name(nr)
            && crate::sock::NAMES.contains(&name)
        {
            match self.sock_call(env, name, &a) {
                Ok(v) => self.rset(env, 4, v),
                Err(e) => self.rset(env, 4, e.wrapping_neg()),
            }
            return TrapOutcome::Handled;
        }
        // 待ち合わせ系は `wait` 正準層へ委譲する。
        if let Some(name) = loongarch::name(nr)
            && crate::wait::NAMES.contains(&name)
        {
            match self.wait_call(env, name, &a) {
                Ok(v) => self.rset(env, 4, v),
                Err(e) => self.rset(env, 4, e.wrapping_neg()),
            }
            return TrapOutcome::Handled;
        }
        let ret: Result<u64, u64> = match nr {
            loongarch::nr::WRITE => self.sys_write(env, a[0] as u32, a[1], a[2]),
            loongarch::nr::WRITEV => self.sys_writev(env, a[0] as u32, a[1], a[2]),
            loongarch::nr::READ => self.sys_read(env, a[0] as u32, a[1], a[2]),
            loongarch::nr::READV => self.sys_readv(env, a[0] as u32, a[1], a[2]),
            loongarch::nr::PREAD64 => self.sys_pread64(env, a[0] as u32, a[1], a[2], a[3]),
            loongarch::nr::SENDFILE => self.sys_sendfile(env, a[0] as u32, a[1] as u32, a[2], a[3]),
            loongarch::nr::CLOSE => self.sys_close(a[0] as u32),
            loongarch::nr::LSEEK => self.sys_lseek(a[0] as u32, a[1] as i64, a[2]),
            loongarch::nr::OPENAT => self.sys_openat(env, a[0], a[1], a[2], a[3]),
            loongarch::nr::FSTAT => self.sys_fstat(env, a[0] as u32, a[1]),
            loongarch::nr::NEWFSTATAT => self.sys_fstatat(env, a[0], a[1], a[2], a[3]),
            loongarch::nr::STATX => self.sys_statx(env, a[0], a[1], a[2], a[3], a[4]),
            loongarch::nr::FACCESSAT => self.sys_faccessat(env, a[0], a[1], a[2], a[3]),
            loongarch::nr::GETDENTS64 => self.sys_getdents64(env, a[0] as u32, a[1], a[2]),
            loongarch::nr::MKDIRAT => self.sys_mkdirat(env, a[0], a[1], a[2]),
            loongarch::nr::UNLINKAT => self.sys_unlinkat(env, a[0], a[1], a[2]),
            loongarch::nr::RENAMEAT => self.sys_renameat(env, a[0], a[1], a[2], a[3]),
            loongarch::nr::SYMLINKAT => self.sys_symlinkat(env, a[0], a[1], a[2]),
            loongarch::nr::TRUNCATE => self.sys_truncate(env, a[0], false, (-100i64) as u64, a[1]),
            loongarch::nr::FTRUNCATE => self.sys_truncate(env, a[0], true, 0, a[1]),
            loongarch::nr::FCHMOD => self.sys_fchmod(a[0] as u32, a[1]),
            loongarch::nr::FCHMODAT => self.sys_fchmodat(env, a[0], a[1], a[2]),
            loongarch::nr::STATFS => self.sys_statfs(env, a[0], a[1]),
            loongarch::nr::FSTATFS => self.put_statfs(env, a[1]).map(|()| 0),
            loongarch::nr::UTIMENSAT => self.sys_utimensat(env, a[0], a[1], a[2], a[3]),
            loongarch::nr::CHDIR => self.sys_chdir(env, a[0]),
            loongarch::nr::GETTIMEOFDAY => self.sys_gettimeofday(env, a[0], a[1]),
            loongarch::nr::SYSINFO => self.sys_sysinfo(env, a[0]),
            loongarch::nr::TIMES => self.sys_times(env, a[0]),
            loongarch::nr::GETRUSAGE => self.sys_getrusage(env, a[0], a[1]),
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
            | loongarch::nr::GETEGID => Ok(0),
            loongarch::nr::SET_TID_ADDRESS => Ok(self.pid),
            // umask は新旧の入れ替えだけを行う。
            loongarch::nr::UMASK => {
                let old = self.umask;
                self.umask = (a[0] & 0o777) as u32;
                Ok(u64::from(old))
            }
            // prctl/シグナル枠組み/バリア系は登録受理のみ（配送しない）。
            loongarch::nr::PRCTL
            | loongarch::nr::SIGALTSTACK
            | loongarch::nr::SETPRIORITY
            | loongarch::nr::MADVISE
            | loongarch::nr::MSYNC
            | loongarch::nr::MINCORE
            | loongarch::nr::FLOCK
            | loongarch::nr::SYNC
            | loongarch::nr::FSYNC
            | loongarch::nr::FDATASYNC
            | loongarch::nr::SET_ROBUST_LIST
            | loongarch::nr::RT_SIGACTION
            | loongarch::nr::RT_SIGPROCMASK
            | loongarch::nr::RT_SIGRETURN
            | loongarch::nr::SCHED_YIELD => Ok(0),
            loongarch::nr::GETPRIORITY => Ok(0),
            // clock_nanosleep は相对時刻のみ nanosleep に委ねる。
            loongarch::nr::CLOCK_NANOSLEEP => self.sys_nanosleep(env, a[2], a[3]),
            // 単一プロセス・単一スレッド模型: fork/exec/待機/パイプ/
            // ソケット系は ENOSYS。GAP-0062。
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `struct statx` の UAPI オフセット検査（回帰: ino 以降が
    /// +8 ずれていた）。`include/uapi/linux/stat.h` 正本。
    #[test]
    fn statx_writes_uapi_layout() {
        let dir = std::env::temp_dir().join(format!("polyisa-la-statx-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("f");
        std::fs::write(&f, b"abc").unwrap();
        let mut sys = Linux::new();
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_loongarch::CpuState>());
        // 出力バッファ + 空の path 文字列領域。
        env.backend
            .mem
            .map(VirtAddr(0x10000), 1, Perms::RW)
            .unwrap();
        let file = std::fs::File::open(&f).unwrap();
        let fd = sys.fds.alloc(polyisa_kernel::FdTarget::File(file));
        sys.fds.remember_path(fd, f.to_string_lossy().into_owned());
        // AT_EMPTY_PATH(0x1000) + 空 path → fd の記憶パスを stat。
        let r = sys.sys_statx(&mut env, u64::from(fd), 0x10000, 0x1000, 0, 0x10400);
        assert_eq!(r, Ok(0));
        let b = sys.get_bytes(&mut env, 0x10400, 256).unwrap();
        let r32 = |o: usize| -> u32 { u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) };
        let r64 = |o: usize| -> u64 { u64::from_le_bytes(b[o..o + 8].try_into().unwrap()) };
        let md = polyisa_host::stat(&f.to_string_lossy()).unwrap();
        assert_eq!(r32(0x00), 0x7ff, "mask = STATX_BASIC_STATS");
        assert_eq!(r64(0x08), 0, "attributes 未提供");
        assert_eq!(r32(0x1c) as u16, md.mode as u16);
        assert_eq!(r64(0x20), md.ino, "ino @0x20");
        assert_eq!(r64(0x28), 3, "size @0x28");
        assert_eq!(r64(0x30), md.blocks, "blocks @0x30");
        assert_eq!(r64(0x38), 0, "attributes_mask @0x38");
        assert_eq!(r64(0x40), md.atime as u64, "atime @0x40");
        assert_eq!(r32(0x48), md.atime_nsec as u32);
        assert_eq!(r64(0x50), 0, "btime 未提供");
        assert_eq!(r64(0x60), md.ctime as u64, "ctime @0x60");
        assert_eq!(r32(0x68), md.ctime_nsec as u32);
        assert_eq!(r64(0x70), md.mtime as u64, "mtime @0x70");
        assert_eq!(r32(0x78), md.mtime_nsec as u32);
        // dev_major/minor @0x88/0x8c（new_decode_dev の値）。
        let dev = md.dev;
        let major = (((dev >> 8) & 0xfff) | (dev >> 32)) as u32;
        let minor = ((dev & 0xff) | ((dev >> 12) & !0xff)) as u32;
        assert_eq!(r32(0x88), major, "dev_major @0x88");
        assert_eq!(r32(0x8c), minor, "dev_minor @0x8c");
        assert_eq!(r64(0x90), 0, "mnt_id 未提供");
        std::fs::remove_dir_all(&dir).ok();
    }
}
