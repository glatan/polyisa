// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! OpenRISC Linux の syscall 処理（段階20 OR9）。
//!
//! 規約: 番号は r11、引数は r3-r8、戻り値は r11、失敗は -errno。
//! `l.sys` は例外ベクタ 0xc00 の Trap として届く。
//!
//! 単一プロセス・単一スレッド模型: clone/execve/パイプ/ソケット/
//! シグナル配送は未実装（ENOSYS または登録のみ受理）。or1k_atomic
//! （番号 244）は未実装として止める（Gap: GAP-0064）。ゲストは
//! ビッグエンディアンなのでポインタ・iovec・stat の語は BE で
//! 読み書きする。stat は asm-generic `struct stat64`（time32 の
//! 104 バイト）。ファイル mmap2 は pgoff 単位の offset を使った
//! MAP_PRIVATE 事前読み近似（共有・書き戻しなし — Gap: GAP-0064）。
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
    /// rt_sigprocmask が保持する blocked マスク（配送しない近似 —
    /// Gap: GAP-0064）。
    sig_mask: u64,
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
            sig_mask: 0,
        }
    }

    /// syscall のバッファアクセスが伸ばし得るスタック窓
    /// （窓内の未写像ページを遅延割付する近似）。
    /// Gap: GAP-0065
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

    /// ゲストパスをホストパスに写す（root 内閉じ込め）。dirfd は
    /// AT_FDCWD(-100) か `remember_path` で覚えたディレクトリ fd
    /// （superh/loongarch と同じ近似 — Gap: GAP-0064 の dirfd 近似）。
    /// root 配下にノードが無い `/dev/*` はホストの devtmpfs へ通す。
    fn host_path(&self, dirfd: u64, path: &str) -> Option<String> {
        const AT_FDCWD: u64 = (-100i64) as u64;
        if self.guest_root.is_empty() {
            if path.starts_with('/') || dirfd == AT_FDCWD {
                return Some(path.to_string());
            }
            let dir = self.fds.path_of(dirfd as u32)?;
            return Some(format!("{}/{}", dir.trim_end_matches('/'), path));
        }
        if path.starts_with('/') || dirfd == AT_FDCWD {
            let r = crate::guest_path::resolve_guest_path(&self.guest_root, "/", path)?;
            if path.starts_with("/dev/") && !std::path::Path::new(&r).exists() {
                return Some(path.to_string());
            }
            return Some(r);
        }
        let dir = self.fds.path_of(dirfd as u32)?;
        Some(format!("{}/{}", dir.trim_end_matches('/'), path))
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
        let Some(full) = self.host_path(dirfd, &gpath) else {
            return Err(errno::EACCES);
        };
        // asm-generic の O_*: ACCMODE=3, CREAT=0o100, EXCL=0o200,
        // TRUNC=0o1000, APPEND=0o2000。残りのフラグ（O_DIRECTORY・
        // O_NOFOLLOW・O_CLOEXEC・O_SYNC 系）は無視する（Gap: GAP-0064）。
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
                let fd = self.fds.alloc(polyisa_kernel::FdTarget::File(f));
                self.fds.remember_path(fd, full);
                Ok(u64::from(fd))
            }
            Err(e) => Err(host_errno(e.raw_os_error())),
        }
    }

    /// asm-generic `struct stat64`（fstatat64/fstat64 の出力、
    /// time32・104 バイト・BE）。レイアウト: st_dev u64@0,
    /// st_ino u64@8, st_mode u32@16, st_nlink u32@20, st_uid u32@24,
    /// st_gid u32@28, st_rdev u64@32, __pad1 u64@40, st_size i64@48,
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
    /// （Gap: GAP-0064）。
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
        let Some(full) = self.host_path(dirfd, &gpath) else {
            return Err(errno::EACCES);
        };
        let md = if flags & AT_SYMLINK_NOFOLLOW != 0 {
            polyisa_host::lstat(&full)
        } else {
            polyisa_host::stat(&full)
        }
        .map_err(|e| host_errno(e.raw_os_error()))?;
        self.put_stat(env, addr, &md).map(|_| 0)
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

    /// `mmap2(addr, len, prot, flags, fd, pgoff)`。pgoff は
    /// 4KiB ページ単位（asm-generic `sys_mmap2`）。
    /// file-backed は内容を事前読みする近似（共有・後続 write の
    /// 反映はない — Gap: GAP-0064）。
    /// Ref: SRC-LINUX — include/uapi/asm-generic/mman-common.h,
    /// mm/mmap.c（sys_mmap2）.
    ///
    /// なお旧実装は a[5] をバイトオフセットとして使っていたが
    /// BIN-DISTRO-OR1K の経路では見えなかった。本エミュレータは
    /// 主 ELF と ldso の双方をローダが直接写像する（PT_INTERP
    /// は `load_segments_bias` で処理）ため、musl ldso が発行する
    /// file-backed mmap2 は mallocng のガード/ヒープ用の匿名写像
    /// と pgoff=0 の形に限られ、pgoff>0 の file-backed mmap2 を
    /// 踏む経路が無かったためである。
    fn sys_mmap2(&mut self, env: &mut BareEnv, a: [u64; 6]) -> Result<u64, u64> {
        let (addr, len, prot, flags, fd, pgoff) = (a[0], a[1], a[2], a[3], a[4], a[5]);
        let len = (len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if len == 0 || len > 0x4000_0000 {
            return Err(errno::EINVAL);
        }
        const MAP_FIXED: u64 = 0x10;
        const MAP_ANONYMOUS: u64 = 0x20;
        let base = if flags & MAP_FIXED != 0 {
            addr & !(PAGE_SIZE - 1)
        } else {
            let b = self.mmap_next;
            self.mmap_next = self.mmap_next.wrapping_add(len);
            b
        };
        let pages = len / PAGE_SIZE;
        // PROT_* の下位 3 ビットは Perms の R/W/X と同じ配列。
        let want = Perms((prot & 7) as u8);
        let file_backed = flags & MAP_ANONYMOUS == 0 && self.fds.file(fd as u32).is_some();
        // ファイル裏付けは中身の事前読みを伴うので、書き込み
        // 不可の要求でも RW で割り付けて埋めてから protect で
        // 要求の許可へ戻す（実カーネルは中身を載せたうえで
        // VMA の許可を張る）。
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
        Ok(base)
    }

    /// `sys_llseek(fd, off_hi, off_lo, result*, whence)`。
    /// 結果は result* へ u64（BE）で書き、戻り値は 0
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

    /// `pread64(fd, buf, len, pos)`。pos は BE ABI の 64 ビット
    /// 引数対 r6:r7（a[3]=上位, a[4]=下位）。ファイル位置を
    /// 変えずに読む。
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

    /// `prlimit64(pid, res, new, old)`。old に rlimit64（u64×2）
    /// の合成値を書く。new は受理のみ（単一プロセス近似 — Gap:
    /// GAP-0064）。resource >= RLIM_NLIMITS(16) は EINVAL。
    fn sys_prlimit64(&mut self, env: &mut BareEnv, res: u64, old: u64) -> Result<u64, u64> {
        const RLIM_NLIMITS: u64 = 16;
        const RLIM64_INFINITY: u64 = u64::MAX;
        if res >= RLIM_NLIMITS {
            return Err(errno::EINVAL);
        }
        if old != 0 {
            self.put_u64(env, old, RLIM64_INFINITY)?;
            self.put_u64(env, old + 8, RLIM64_INFINITY)?;
        }
        Ok(0)
    }

    /// `rt_sigaction(sig, act, oldact, sigsetsize)`。配送しない
    /// 近似（Gap: GAP-0064）。oldact には SIG_DFL 相当の
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
    /// が配送はしない（Gap: GAP-0064）。
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
            let v = u64::from_be_bytes(b[..8].try_into().unwrap_or([0; 8]));
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

    /// ソケット系 syscall を `sock` 正準層へ委譲する。待ち要求は
    /// 単一スレッド消化で進め、進行不能はデッドロックとして報告。
    /// 戻り値 Err はゲスト errno（asm-generic と同値）。
    fn sock_call(&mut self, env: &mut BareEnv, name: &str, a: &[u64; 6]) -> Result<u64, u64> {
        let abi = crate::sock::SockAbi::generic(4, Endian::Be);
        let map = crate::sock::unix_path_map(&self.guest_root, "");
        let t0 = std::time::Instant::now();
        let mono = move || t0.elapsed().as_nanos() as u64;
        match crate::sock::drive(&mut self.fds, &abi, env, name, a, &map, 0, &mono) {
            Some(Ok(v)) => Ok(v),
            Some(Err(e)) => {
                if e == crate::sock::errno::EDEADLK {
                    eprintln!("openrisc: deadlock in fd wait");
                }
                Err(u64::from((abi.errno)(e)))
            }
            None => Err(errno::ENOSYS),
        }
    }

    fn dispatch(&mut self, env: &mut BareEnv, nr_: u64, a: [u64; 6]) -> Result<u64, u64> {
        if let Some(name) = crate::openrisc::name(nr_)
            && crate::sock::NAMES.contains(&name)
        {
            return self.sock_call(env, name, &a);
        }
        match nr_ {
            nr::IOCTL => Err(errno::ENOTTY),
            nr::FCNTL => {
                // F_GETFD=1・F_SETFD=2・F_GETFL=3・F_SETFL=4 のみ受理。
                // 標準三役は fds 表にないので番号で通す。
                if a[0] > 2 && self.fds.file(a[0] as u32).is_none() {
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
            // pread64 の pos は BE の 64 ビット引数対（a[3]=上位,
            // a[4]=下位）。
            nr::PREAD64 => {
                let off = ((a[3] & 0xffff_ffff) << 32) | (a[4] & 0xffff_ffff);
                self.sys_pread(env, a[0] as u32, a[1], a[2], off)
            }
            nr::READLINKAT => self.sys_readlinkat(env, a[0], a[1], a[2], a[3]),
            nr::FSTATAT64 => self.sys_fstatat(env, a[0], a[1], a[2], a[3]),
            nr::FSTAT64 => self.sys_fstat(env, a[0] as u32, a[1]),
            nr::EXIT | nr::EXIT_GROUP => unreachable!(),
            nr::SET_TID_ADDRESS => Ok(self.pid),
            nr::FUTEX => Err(errno::ENOSYS),
            nr::SET_ROBUST_LIST => Ok(0),
            nr::NANOSLEEP => Ok(0),
            nr::CLOCK_GETTIME => self.sys_clock_gettime(env, a[0], a[1]),
            nr::CLOCK_GETTIME64 => self.sys_clock_gettime64(env, a[0], a[1]),
            // rt_sigaction(sig, act, oldact, sigsetsize)。
            nr::RT_SIGACTION => self.sys_rt_sigaction(env, a[2], a[3]),
            // rt_sigprocmask(how, set, oldset, sigsetsize)。
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
            | nr::SETFSGID => Ok(0),
            nr::BRK => Ok(self.sys_brk(env, a[0])),
            nr::MUNMAP => Ok(0),
            nr::MMAP2 => self.sys_mmap2(env, a),
            nr::MPROTECT => Ok(0),
            // prlimit64(pid, res, new_rlim, old_rlim)。
            nr::PRLIMIT64 => self.sys_prlimit64(env, a[1], a[3]),
            nr::GETRANDOM => {
                let mut buf = vec![0u8; (a[1] as usize).min(256)];
                // 決定論的なダミー乱数（暗論的強度は不要の検査用 —
                // Gap: GAP-0064）。
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
            // l.lwa/l.swa で代替すべきもの。未実装として報告する
            // （Gap: GAP-0064）。
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

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_guest_openrisc::CpuState;

    fn env() -> BareEnv {
        BareEnv::new(core::mem::size_of::<CpuState>())
    }

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("polyisa-or1k-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// `llseek(fd, hi, lo, result*, whence)` — result* に u64(BE)
    /// を書いて 0 を返す（asm-generic 32 ビット規約。回帰: 以前は
    /// (fd,off,whence) 型で値を直接返していた）。
    /// Ref: SRC-LINUX — fs/read_write.c sys_llseek.
    #[test]
    fn llseek_writes_result_pointer() {
        let dir = tmpdir("llseek");
        let f = dir.join("f");
        std::fs::write(&f, b"0123456789abcdef").unwrap();
        let mut sys = Linux::new();
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
        let fd = sys.fds.alloc(polyisa_kernel::FdTarget::File(
            std::fs::File::open(&f).unwrap(),
        ));
        // SEEK_SET で off=0x1_0000_0006（hi=1, lo=6）→ 末尾 +2。
        let r = sys.sys_llseek(&mut env, fd, 1, 6, 0x2000, 0);
        assert_eq!(r, Ok(0));
        // 実際の位置は 16 へ飽和し得ない — f.seek はそのまま通る。
        let pos = sys.fds.file_mut(fd).unwrap().stream_position().unwrap();
        let b = sys.get_bytes(&mut env, 0x2000, 8).unwrap();
        assert_eq!(u64::from_be_bytes(b.try_into().unwrap()), pos);
        assert_eq!(pos, 0x1_0000_0006);
        // SEEK_END: whence=2, off=0 → ファイル長 16。
        let r = sys.sys_llseek(&mut env, fd, 0, 0, 0x2000, 2);
        assert_eq!(r, Ok(0));
        let b = sys.get_bytes(&mut env, 0x2000, 8).unwrap();
        assert_eq!(u64::from_be_bytes(b.try_into().unwrap()), 16);
        // whence=2 以外の未知値は EINVAL。
        assert_eq!(
            sys.sys_llseek(&mut env, fd, 0, 0, 0x2000, 9),
            Err(errno::EINVAL)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `mmap2` の pgoff は 4KiB ページ単位（回帰: バイト値として
    /// 使っていた）。pgoff=2 ならファイルの 0x2000 から読む。
    /// Ref: SRC-LINUX — mm/mmap.c sys_mmap2.
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

    /// asm-generic `struct stat64`（104B・BE）のレイアウト。
    /// Ref: SRC-LINUX — include/uapi/asm-generic/stat.h.
    #[test]
    fn stat64_layout_asm_generic() {
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
        let r32 = |o: usize| u32::from_be_bytes(b[o..o + 4].try_into().unwrap());
        let r64 = |o: usize| u64::from_be_bytes(b[o..o + 8].try_into().unwrap());
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

    /// `pread64` はファイル位置を動かさず pos から読む
    /// （BE の 64 ビット引数対 hi:lo）。
    #[test]
    fn pread64_offset_pair() {
        let dir = tmpdir("pread");
        let f = dir.join("f");
        std::fs::write(&f, b"0123456789abcdef").unwrap();
        let mut sys = Linux::new();
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x5000), 1, Perms::RW).unwrap();
        let fd = sys.fds.alloc(polyisa_kernel::FdTarget::File(
            std::fs::File::open(&f).unwrap(),
        ));
        // pos = 0x0000_0000_0000_0004（hi=0, lo=4）→ "4567"。
        let r = sys.sys_pread(&mut env, fd, 0x5000, 4, 4);
        assert_eq!(r, Ok(4));
        assert_eq!(sys.get_bytes(&mut env, 0x5000, 4).unwrap(), b"4567");
        assert_eq!(sys.fds.file_mut(fd).unwrap().stream_position().unwrap(), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `prlimit64` は old に rlimit64（u64×2 無限）を書く。
    #[test]
    fn prlimit64_writes_rlimit() {
        let mut sys = Linux::new();
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x6000), 1, Perms::RW).unwrap();
        assert_eq!(sys.sys_prlimit64(&mut env, 7, 0x6000), Ok(0));
        let b = sys.get_bytes(&mut env, 0x6000, 16).unwrap();
        assert_eq!(u64::from_be_bytes(b[0..8].try_into().unwrap()), u64::MAX);
        assert_eq!(u64::from_be_bytes(b[8..16].try_into().unwrap()), u64::MAX);
        assert_eq!(sys.sys_prlimit64(&mut env, 16, 0x6000), Err(errno::EINVAL));
    }

    /// `rt_sigprocmask` は sigsetsize=8 必須で blocked マスクを
    /// 往復する（SIGKILL/SIGSTOP は落ちる）。
    #[test]
    fn rt_sigprocmask_roundtrip() {
        let mut sys = Linux::new();
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x7000), 1, Perms::RW).unwrap();
        env.backend
            .mem
            .write(
                VirtAddr(0x7000),
                &(1u64 << 8 | 1u64 << 3 | 1u64 << 18).to_be_bytes(),
            )
            .unwrap();
        // SETMASK: KILL(9)/STOP(19) ビットは落ち、SIGILL(4) の
        // ビットだけ残る。
        let r = sys.sys_rt_sigprocmask(&mut env, 2, 0x7000, 0x7008, 8);
        assert_eq!(r, Ok(0));
        let b = sys.get_bytes(&mut env, 0x7008, 8).unwrap();
        assert_eq!(u64::from_be_bytes(b.try_into().unwrap()), 0);
        assert_eq!(sys.sig_mask, 1 << 3);
        assert_eq!(
            sys.sys_rt_sigprocmask(&mut env, 2, 0, 0, 4),
            Err(errno::EINVAL)
        );
    }
}
