// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! AArch64 Linux の syscall 処理。LP64 の単一 ABI。
//!
//! x8 が番号、x0–x5 が引数、x0 が戻り値。エラーは負の errno を x0 に置く
//! （asm-generic の慣例で、a3 のようなフラグはない）。errno は汎用値。
//!
//! 試作の合意事項：仮想カーネル・VFS・ゲストルートの適用は後の段階である。
//! ここではホストのファイルに直接触る。信頼できないゲストバイナリには
//! 使わないこと。fork/clone/execve/パイプは未対応（ENOSYS）。
// Ref: SRC-LINUX (7.3).

use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

use polyisa_engine::bare::BareEnv;
use polyisa_guest_aarch64::sem::Gpr;
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};
use polyisa_sem::Backend as _;

use crate::{TrapHandler, TrapOutcome, aarch64, aarch64::errno};

/// 標準入出力の capture。テストが読む。
#[derive(Default)]
pub struct Aarch64Io {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// AArch64 Linux の syscall 状態機械。
pub struct Linux {
    endian: Endian,
    /// 標準入出力の capture。テストが読む。
    pub io: Aarch64Io,
    /// 開いたファイルの表（ゲスト fd 3 以降）。
    fds: polyisa_kernel::FdTable,
    /// プログラムブレーク。0 は未初期化。
    heap_end: u64,
    /// mmap の次に置く場所。像の末尾から伸ばす。
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
}

impl Default for Linux {
    fn default() -> Self {
        Self::new(Endian::Le)
    }
}

enum ReadFd<'a> {
    Stdin,
    File(&'a mut std::fs::File),
}

enum WriteFd<'a> {
    Stdout,
    Stderr,
    File(&'a mut std::fs::File),
}

fn reg(env: &mut BareEnv, r: u8) -> u64 {
    env.backend.get(Gpr(r).state())
}

/// dispatch の戻りを作る。`v` は x0 にそのまま書く値（負 errno も含む）。
fn ret(v: u64) -> Disp {
    Disp::Ret(v)
}

enum Disp {
    /// x0 に書く値。
    Ret(u64),
    Exit(u32),
    /// 未実装。ENOSYS を返して続ける。
    Unimpl,
}

impl Linux {
    /// リトルエンディアンの Linux 状態機械を作る。
    #[must_use]
    pub fn new(endian: Endian) -> Self {
        Self {
            endian,
            io: Aarch64Io::default(),
            fds: polyisa_kernel::FdTable::default(),
            heap_end: 0,
            mmap_next: 0x0000_7f00_0000_0000,
            umask: 0o22,
            pid: 0,
            cwd: String::new(),
            exe_path: String::new(),
            reported: Vec::new(),
            stdin_buf: Vec::new(),
            stdin_pos: 0,
            mono_start: None,
        }
    }

    fn pid(&mut self) -> u64 {
        if self.pid == 0 {
            self.pid = 1;
        }
        self.pid
    }

    /// エラー。負 errno を戻り値とする（asm-generic の慣例）。
    fn fail(errno: u32) -> u64 {
        (-(errno as i64)) as u64
    }

    /// ホスト errno を負で返す（asm-generic はホストと同じ値）。
    fn fail_host(e: i32) -> u64 {
        Self::fail(e.max(0).unsigned_abs())
    }

    fn fail_ret(errno: u32) -> Disp {
        Disp::Ret(Self::fail(errno))
    }

    fn fail_ret_host(e: std::io::Error) -> Disp {
        Disp::Ret(Self::fail_host(
            e.raw_os_error().unwrap_or(errno::EIO as i32),
        ))
    }

    fn acc(&self, kind: AccessKind) -> Access {
        Access {
            endian: self.endian,
            align: Align::Unaligned,
            kind,
        }
    }

    /// 64 ビット値をメモリから読む。読めなければ 0。
    fn mem_u(&self, env: &mut BareEnv, addr: u64) -> u64 {
        let mut b = [0u8; 8];
        env.backend
            .mem
            .read(VirtAddr(addr), &mut b, self.acc(AccessKind::DataRead))
            .map_or(0, |()| match self.endian {
                Endian::Be => u64::from_be_bytes(b),
                Endian::Le => u64::from_le_bytes(b),
            })
    }

    /// 固定サイズの値を書く（エンディアン適用）。
    fn put_u64(&self, env: &mut BareEnv, addr: u64, v: u64) -> bool {
        let bytes = match self.endian {
            Endian::Be => v.to_be_bytes(),
            Endian::Le => v.to_le_bytes(),
        };
        env.backend.mem.write(VirtAddr(addr), &bytes).is_ok()
    }

    fn put_u32(&self, env: &mut BareEnv, addr: u64, v: u32) -> bool {
        let bytes = match self.endian {
            Endian::Be => v.to_be_bytes(),
            Endian::Le => v.to_le_bytes(),
        };
        env.backend.mem.write(VirtAddr(addr), &bytes).is_ok()
    }

    /// C 文字列を読む。上限 4096。
    fn read_cstr(&self, env: &mut BareEnv, addr: u64) -> Result<Vec<u8>, u32> {
        let mut out = Vec::new();
        let acc = self.acc(AccessKind::DataRead);
        for a in (addr..).take(4096) {
            let mut b = [0u8; 1];
            if env.backend.mem.read(VirtAddr(a), &mut b, acc).is_err() {
                return Err(errno::EFAULT);
            }
            if b[0] == 0 {
                return Ok(out);
            }
            out.push(b[0]);
        }
        Err(errno::ENAMETOOLONG)
    }

    fn read_bytes(&self, env: &mut BareEnv, addr: u64, len: usize) -> Result<Vec<u8>, u32> {
        let mut buf = vec![0u8; len.min(1 << 20)];
        if buf.is_empty() {
            return Ok(buf);
        }
        env.backend
            .mem
            .read(VirtAddr(addr), &mut buf, self.acc(AccessKind::DataRead))
            .map_err(|_| errno::EFAULT)?;
        Ok(buf)
    }

    fn write_bytes(&self, env: &mut BareEnv, addr: u64, data: &[u8]) -> Result<(), u32> {
        env.backend
            .mem
            .write(VirtAddr(addr), data)
            .map_err(|_| errno::EFAULT)
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
        self.fds.get_mut(fd).ok_or(errno::EBADF)
    }

    /// 読み用に fd を開いているものを返す。0/1/2 と FdTable の両方を見る。
    fn reader(&mut self, fd: u32) -> Result<ReadFd<'_>, u32> {
        match fd {
            0 => Ok(ReadFd::Stdin),
            1 | 2 => Err(errno::EBADF),
            _ => self.fds.get_mut(fd).map(ReadFd::File).ok_or(errno::EBADF),
        }
    }

    fn writer(&mut self, fd: u32) -> Result<WriteFd<'_>, u32> {
        match fd {
            0 => Err(errno::EBADF),
            1 => Ok(WriteFd::Stdout),
            2 => Ok(WriteFd::Stderr),
            _ => self.fds.get_mut(fd).map(WriteFd::File).ok_or(errno::EBADF),
        }
    }

    /// 汎用 `O_*` をホストの `OpenOptions` 用フラグへ写す。
    fn open_flags(guest: u64) -> std::fs::OpenOptions {
        use aarch64::oflag::*;
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

    /// `openat` の実体。`dirfd` は AT_FDCWD だけ受け付ける。
    fn do_open(&mut self, env: &mut BareEnv, path_addr: u64, flags: u64, _mode: u64) -> u64 {
        let path = match self.read_cstr(env, path_addr) {
            Ok(p) => p,
            Err(e) => return Self::fail(e),
        };
        let host = self.host_path(&path);
        let oo = Self::open_flags(flags);
        match oo.open(&host) {
            Ok(f) => {
                let fd = self.fds.alloc(Some(f));
                self.fds.remember_path(fd, host);
                u64::from(fd)
            }
            Err(e) => Self::fail_host(e.raw_os_error().unwrap_or(errno::EIO as i32)),
        }
    }

    /// ホストのメタデータを asm-generic の `struct stat`（128 バイト）に写す。
    /// u64 dev, u64 ino, u32 mode, u32 nlink, u32 uid, u32 gid, u64 rdev,
    /// u64 pad1, i64 size, i32 blksize, i32 pad2, i64 blocks,
    /// timespec atime/mtime/ctime（各 i64+u32+pad）、u32 unused[2]。
    /// Ref: SRC-LINUX (7.3) `include/uapi/asm-generic/stat.h`。
    fn put_stat(&self, env: &mut BareEnv, addr: u64, md: &polyisa_host::Stat) -> bool {
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
        let mut b = [0u8; 128];
        let mut p = |off: usize, bytes: &[u8]| b[off..off + bytes.len()].copy_from_slice(bytes);
        p(0, &w64(md.dev));
        p(8, &w64(md.ino));
        p(16, &w32(u64::from(md.mode)));
        p(20, &w32(md.nlink));
        p(24, &w32(u64::from(md.uid)));
        p(28, &w32(u64::from(md.gid)));
        p(32, &w64(md.rdev));
        p(48, &w64(md.size));
        p(56, &w32(md.blksize));
        p(64, &w64(md.blocks));
        p(72, &w64(md.atime as u64));
        p(80, &w64(md.atime_nsec as u64));
        p(88, &w64(md.mtime as u64));
        p(96, &w64(md.mtime_nsec as u64));
        p(104, &w64(md.ctime as u64));
        p(112, &w64(md.ctime_nsec as u64));
        env.backend.mem.write(VirtAddr(addr), &b).is_ok()
    }

    /// `struct statx`（256 バイト、asm-generic と同形）。
    fn do_statx(&mut self, env: &mut BareEnv, path_addr: u64, out: u64) -> u64 {
        let path = match self.read_cstr(env, path_addr) {
            Ok(p) => p,
            Err(e) => return Self::fail(e),
        };
        let md = match polyisa_host::stat(&self.host_path(&path)) {
            Ok(m) => m,
            Err(e) => return Self::fail_host(e.raw_os_error().unwrap_or(errno::EIO as i32)),
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
        b[80..88].copy_from_slice(&w64(md.atime as u64));
        b[88..92].copy_from_slice(&w32(md.atime_nsec as u32));
        b[112..120].copy_from_slice(&w64(md.ctime as u64));
        b[120..124].copy_from_slice(&w32(md.ctime_nsec as u32));
        b[128..136].copy_from_slice(&w64(md.mtime as u64));
        b[136..140].copy_from_slice(&w32(md.mtime_nsec as u32));
        b[144..148].copy_from_slice(&w32(md.rdev as u32));
        b[152..156].copy_from_slice(&w32(md.dev as u32));
        match self.write_bytes(env, out, &b) {
            Ok(()) => 0,
            Err(e) => Self::fail(e),
        }
    }

    /// fstat/newfstatat 共通の解決。
    fn do_stat(&mut self, env: &mut BareEnv, fd: Option<u32>, path_addr: u64, out: u64) -> u64 {
        let md = if let Some(fd) = fd {
            match fd {
                0..=2 => match polyisa_host::stat(&format!("/proc/self/fd/{fd}")) {
                    Ok(m) => m,
                    Err(e) => {
                        return Self::fail_host(e.raw_os_error().unwrap_or(errno::EIO as i32));
                    }
                },
                _ => match self.fds.get(fd) {
                    Some(f) => match polyisa_host::fstat(f) {
                        Ok(m) => m,
                        Err(e) => {
                            return Self::fail_host(e.raw_os_error().unwrap_or(errno::EIO as i32));
                        }
                    },
                    None => return Self::fail(errno::EBADF),
                },
            }
        } else {
            let path = match self.read_cstr(env, path_addr) {
                Ok(p) => p,
                Err(e) => return Self::fail(e),
            };
            match polyisa_host::stat(&self.host_path(&path)) {
                Ok(m) => m,
                Err(e) => {
                    return Self::fail_host(e.raw_os_error().unwrap_or(errno::EIO as i32));
                }
            }
        };
        if self.put_stat(env, out, &md) {
            0
        } else {
            Self::fail(errno::EFAULT)
        }
    }

    /// 無名 mmap。ファイル写像は ENOSYS。
    fn do_mmap(&mut self, env: &mut BareEnv, addr: u64, len: u64, prot: u64, flags: u64) -> u64 {
        let len = len.max(1);
        let pages = len.div_ceil(polyisa_mem::PAGE_SIZE);
        let base = if flags & aarch64::mflag::FIXED != 0 && addr != 0 {
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
            Ok(()) => base,
            Err(_) => Self::fail(errno::ENOMEM),
        }
    }

    /// brk。0 なら現在値を返す。像の末尾は `init_brk` で受ける。
    fn do_brk(&mut self, env: &mut BareEnv, addr: u64) -> u64 {
        if addr == 0 {
            return self.heap_end;
        }
        if addr < self.heap_end {
            self.heap_end = addr;
            return self.heap_end;
        }
        let page_base = self.heap_end & !(polyisa_mem::PAGE_SIZE - 1);
        let need = (addr - page_base).div_ceil(polyisa_mem::PAGE_SIZE);
        if need > 0
            && env
                .backend
                .mem
                .map(VirtAddr(page_base), need, Perms::RW)
                .is_err()
        {
            return Self::fail(errno::ENOMEM);
        }
        self.heap_end = addr;
        self.heap_end
    }

    /// `utsname` 6 フィールド。フィールド幅は 65。
    fn do_uname(&mut self, env: &mut BareEnv, addr: u64) -> u64 {
        let fields: [&[u8]; 6] = [
            b"Linux",
            b"polyisa",
            b"6.19.0",
            b"#1 polyisa",
            b"aarch64",
            b"(none)",
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
                return Self::fail(errno::EFAULT);
            }
        }
        0
    }

    /// `sysinfo`（112 バイト）。最小限の値を返す。
    fn do_sysinfo(&mut self, env: &mut BareEnv, addr: u64) -> u64 {
        let secs = self.mono_start.map(|s| s.elapsed().as_secs()).unwrap_or(0);
        let mut b = [0u8; 112];
        let w64 = |v: u64| match self.endian {
            Endian::Be => v.to_be_bytes(),
            Endian::Le => v.to_le_bytes(),
        };
        let w32 = |v: u32| match self.endian {
            Endian::Be => v.to_be_bytes(),
            Endian::Le => v.to_le_bytes(),
        };
        b[0..8].copy_from_slice(&w64(secs));
        b[32..40].copy_from_slice(&w64(4 << 30)); // totalram
        b[40..48].copy_from_slice(&w64(3 << 30)); // freeram
        b[72..80].copy_from_slice(&w64(1 << 30)); // totalswap
        b[80..88].copy_from_slice(&w64(1 << 29)); // freeswap
        b[88..90].copy_from_slice(&w32(1)[0..2].try_into().unwrap_or([0, 0]));
        b[96..100].copy_from_slice(&w32(1)); // mem_unit
        match self.write_bytes(env, addr, &b) {
            Ok(()) => 0,
            Err(e) => Self::fail(e),
        }
    }

    /// `statfs64`（asm-generic は 120 バイト）。最小の埋め方。
    fn do_statfs(&mut self, env: &mut BareEnv, addr: u64) -> u64 {
        let mut b = [0u8; 120];
        let w64 = |v: u64| match self.endian {
            Endian::Be => v.to_be_bytes(),
            Endian::Le => v.to_le_bytes(),
        };
        // f_type = EXT2_SUPER_MAGIC 0xEF53、残りは妥当な値を置く。
        b[0..8].copy_from_slice(&w64(0xEF53));
        b[8..16].copy_from_slice(&w64(4096)); // f_bsize
        b[16..24].copy_from_slice(&w64(1 << 20)); // f_blocks
        b[24..32].copy_from_slice(&w64(1 << 19)); // f_bfree
        b[32..40].copy_from_slice(&w64(1 << 19)); // f_bavail
        b[64..72].copy_from_slice(&w64(255)); // f_namelen
        b[72..80].copy_from_slice(&w64(4096)); // f_frsize
        match self.write_bytes(env, addr, &b) {
            Ok(()) => 0,
            Err(e) => Self::fail(e),
        }
    }

    /// `getdents64`。linux_dirent64: u64 d_ino, u64 d_off, u16 d_reclen,
    /// u8 d_type, name\0。
    fn do_getdents64(&mut self, env: &mut BareEnv, fd: u32, buf: u64, count: u64) -> u64 {
        let path = self.fds.path_of(fd).map(str::to_string).unwrap_or_default();
        if path.is_empty() {
            return Self::fail(errno::ENOTDIR);
        }
        let rd = match std::fs::read_dir(&path) {
            Ok(r) => r,
            Err(e) => return Self::fail_host(e.raw_os_error().unwrap_or(errno::EIO as i32)),
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
                    8
                };
                (ino, e.file_name().to_string_lossy().into_owned(), t)
            })
            .collect();
        entries.sort_by_key(|e| e.0);
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
        for (i, (ino, name, t)) in all.iter().enumerate() {
            let reclen = 19 + name.len() + 1;
            let aligned = reclen.next_multiple_of(8);
            if out.len() + aligned > count {
                break;
            }
            out.extend_from_slice(&w64(*ino));
            out.extend_from_slice(&w64((i + 1) as u64));
            out.extend_from_slice(&w16(aligned as u16));
            out.push(*t);
            out.extend_from_slice(name.as_bytes());
            out.push(0);
            out.resize(out.len() + (aligned - reclen), 0);
        }
        match self.write_bytes(env, buf, &out) {
            Ok(()) => out.len() as u64,
            Err(e) => Self::fail(e),
        }
    }

    /// `readlinkat`。/proc/self/exe はゲストの exe_path へ。
    fn do_readlink(&mut self, env: &mut BareEnv, path_addr: u64, buf: u64, len: u64) -> u64 {
        let path = match self.read_cstr(env, path_addr) {
            Ok(p) => p,
            Err(e) => return Self::fail(e),
        };
        let host = self.host_path(&path);
        let target = if host == "/proc/self/exe" {
            self.exe_path.clone()
        } else {
            match std::fs::read_link(&host) {
                Ok(t) => t.to_string_lossy().into_owned(),
                Err(e) => {
                    return Self::fail_host(e.raw_os_error().unwrap_or(errno::EIO as i32));
                }
            }
        };
        let n = target.len().min(len as usize);
        match self.write_bytes(env, buf, &target.as_bytes()[..n]) {
            Ok(()) => n as u64,
            Err(e) => Self::fail(e),
        }
    }

    /// `read`。
    fn do_read(&mut self, env: &mut BareEnv, fd: u32, buf: u64, len: u64) -> u64 {
        let len = len.min(1 << 20) as usize;
        let r = match self.reader(fd) {
            Ok(r) => r,
            Err(e) => return Self::fail(e),
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
                    Ok(()) => n as u64,
                    Err(e) => Self::fail(e),
                }
            }
            ReadFd::File(f) => {
                let mut chunk = vec![0u8; len];
                match f.read(&mut chunk) {
                    Ok(n) => match self.write_bytes(env, buf, &chunk[..n]) {
                        Ok(()) => n as u64,
                        Err(e) => Self::fail(e),
                    },
                    Err(e) => Self::fail_host(e.raw_os_error().unwrap_or(errno::EIO as i32)),
                }
            }
        }
    }

    /// `write`。stdout/stderr は capture しつつホストにも流す。
    fn do_write(&mut self, env: &mut BareEnv, fd: u32, buf: u64, len: u64) -> u64 {
        let data = match self.read_bytes(env, buf, len as usize) {
            Ok(d) => d,
            Err(e) => return Self::fail(e),
        };
        let w = match self.writer(fd) {
            Ok(w) => w,
            Err(e) => return Self::fail(e),
        };
        match w {
            WriteFd::Stdout => {
                self.io.stdout.extend_from_slice(&data);
                let _ = std::io::Write::write_all(&mut std::io::stdout(), &data);
                data.len() as u64
            }
            WriteFd::Stderr => {
                self.io.stderr.extend_from_slice(&data);
                let _ = std::io::Write::write_all(&mut std::io::stderr(), &data);
                data.len() as u64
            }
            WriteFd::File(f) => match f.write(&data) {
                Ok(n) => n as u64,
                Err(e) => Self::fail_host(e.raw_os_error().unwrap_or(errno::EIO as i32)),
            },
        }
    }

    /// `readv`/`writev`（iovec は 16 バイト単位）。
    fn do_readv(&mut self, env: &mut BareEnv, fd: u32, iov: u64, cnt: u64) -> u64 {
        let mut total = 0u64;
        for i in 0..cnt.min(1024) {
            let base = self.mem_u(env, iov + i * 16);
            let len = self.mem_u(env, iov + i * 16 + 8);
            let n = self.do_read(env, fd, base, len);
            if (n as i64) < 0 {
                return n;
            }
            total = total.wrapping_add(n);
            if n < len {
                break;
            }
        }
        total
    }

    fn do_writev(&mut self, env: &mut BareEnv, fd: u32, iov: u64, cnt: u64) -> u64 {
        let mut total = 0u64;
        for i in 0..cnt.min(1024) {
            let base = self.mem_u(env, iov + i * 16);
            let len = self.mem_u(env, iov + i * 16 + 8);
            let n = self.do_write(env, fd, base, len);
            if (n as i64) < 0 {
                return n;
            }
            total = total.wrapping_add(n);
        }
        total
    }

    /// `lseek`。
    fn do_lseek(&mut self, _env: &mut BareEnv, fd: u32, off: i64, whence: u32) -> u64 {
        let f = match self.file_of(fd) {
            Ok(f) => f,
            Err(e) => return Self::fail(e),
        };
        let w = match whence {
            0 => SeekFrom::Start(off as u64),
            1 => SeekFrom::Current(off),
            2 => SeekFrom::End(off),
            _ => return Self::fail(errno::EINVAL),
        };
        match f.seek(w) {
            Ok(p) => p,
            Err(e) => Self::fail_host(e.raw_os_error().unwrap_or(errno::EIO as i32)),
        }
    }

    /// `pread64`/`pwrite64`。pos は一語。
    fn do_pread(&mut self, env: &mut BareEnv, fd: u32, buf: u64, len: u64, pos: u64) -> u64 {
        let data_len = len.min(1 << 20) as usize;
        match self.reader(fd) {
            Ok(ReadFd::File(f)) => {
                let mut chunk = vec![0u8; data_len];
                match polyisa_host::pread(f, &mut chunk, pos) {
                    Ok(n) => match self.write_bytes(env, buf, &chunk[..n]) {
                        Ok(()) => n as u64,
                        Err(e) => Self::fail(e),
                    },
                    Err(e) => Self::fail_host(e.raw_os_error().unwrap_or(errno::EIO as i32)),
                }
            }
            Ok(ReadFd::Stdin) => Self::fail(errno::ESPIPE),
            Err(e) => Self::fail(e),
        }
    }

    fn do_pwrite(&mut self, env: &mut BareEnv, fd: u32, buf: u64, len: u64, pos: u64) -> u64 {
        let data = match self.read_bytes(env, buf, len as usize) {
            Ok(d) => d,
            Err(e) => return Self::fail(e),
        };
        match self.writer(fd) {
            Ok(WriteFd::File(f)) => match polyisa_host::pwrite(f, &data, pos) {
                Ok(n) => n as u64,
                Err(e) => Self::fail_host(e.raw_os_error().unwrap_or(errno::EIO as i32)),
            },
            Ok(_) => Self::fail(errno::ESPIPE),
            Err(e) => Self::fail(e),
        }
    }

    /// `ioctl`。TCGETS/TCSETS/TIOCGWINSZ/FIONREAD/TIOCNOTTY だけ。
    fn do_ioctl(&mut self, env: &mut BareEnv, fd: u32, req: u64, argp: u64) -> u64 {
        use aarch64::ioc::*;
        match req {
            TCGETS | TCSETS => match fd {
                0..=2 => 0,
                _ => Self::fail(errno::ENOTTY),
            },
            TIOCGWINSZ => {
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
                    Ok(()) => 0,
                    Err(x) => Self::fail(x),
                }
            }
            FIONREAD => {
                if self.put_u32(env, argp, 0) {
                    0
                } else {
                    Self::fail(errno::EFAULT)
                }
            }
            TIOCNOTTY => 0,
            _ => Self::fail(errno::ENOTTY),
        }
    }

    /// `fcntl`。FD フラグだけ。
    fn do_fcntl(&mut self, _env: &mut BareEnv, _fd: u32, cmd: u32, _arg: u64) -> u64 {
        match cmd {
            1 => 0, // F_GETFD
            2 => 0, // F_SETFD
            3 => 0, // F_GETFL（フラグは覚えていない）
            4 => 0, // F_SETFL
            _ => Self::fail(errno::EINVAL),
        }
    }

    /// `getrandom`。/dev/urandom を読む。
    fn do_getrandom(&mut self, env: &mut BareEnv, buf: u64, len: u64) -> u64 {
        let mut data = vec![0u8; len.min(1 << 20) as usize];
        match std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut data)) {
            Ok(()) => match self.write_bytes(env, buf, &data) {
                Ok(()) => data.len() as u64,
                Err(e) => Self::fail(e),
            },
            Err(e) => Self::fail_host(e.raw_os_error().unwrap_or(errno::EIO as i32)),
        }
    }

    /// `gettimeofday`/`clock_gettime`/`clock_getres`。
    fn mono_us(&mut self) -> u64 {
        self.mono_start
            .get_or_insert_with(std::time::Instant::now)
            .elapsed()
            .as_micros() as u64
    }

    fn put_timespec(&self, env: &mut BareEnv, addr: u64, sec: u64, nsec: u64) -> bool {
        self.put_u64(env, addr, sec) && self.put_u64(env, addr + 8, nsec)
    }

    /// 現在時刻（sec, usec）。
    fn now() -> (u64, u64) {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| (d.as_secs(), u64::from(d.subsec_micros())))
            .unwrap_or((0, 0))
    }

    /// fd の複製（dup3）。FdTable が保持する File を複製する。
    fn dup2_fd(&mut self, old: u32, new: u32) -> Result<(), u32> {
        let f = self
            .fds
            .get(old)
            .and_then(|f| f.try_clone().ok())
            .ok_or(errno::EBADF)?;
        self.fds.place(new, Some(f));
        Ok(())
    }

    /// dirfd + パス一つを取る系。
    fn path1_at(&mut self, env: &mut BareEnv, name: &str, idx: usize) -> Disp {
        let path_addr = reg(env, idx as u8);
        let path = match self.read_cstr(env, path_addr) {
            Ok(p) => p,
            Err(e) => return Self::fail_ret(e),
        };
        let host = self.host_path(&path);
        match name {
            "unlinkat" => {
                let flags = reg(env, 2);
                let r = if flags & 0x200 != 0 {
                    std::fs::remove_dir(&host)
                } else {
                    std::fs::remove_file(&host)
                };
                match r {
                    Ok(()) => ret(0),
                    Err(e) => Self::fail_ret_host(e),
                }
            }
            "faccessat" | "faccessat2" => ret(if polyisa_host::stat(&host).is_ok() {
                0
            } else {
                Self::fail(errno::ENOENT)
            }),
            "fchmodat" => ret(0),
            _ => Self::fail_ret(errno::ENOSYS),
        }
    }

    /// パス二つを取る系（linkat/renameat/symlinkat）。
    fn path2_at(&mut self, env: &mut BareEnv, name: &str) -> Disp {
        let pa_addr = reg(env, 1);
        let pa = match self.read_cstr(env, pa_addr) {
            Ok(p) => p,
            Err(e) => return Self::fail_ret(e),
        };
        let pb_addr = reg(env, 3);
        let pb = match self.read_cstr(env, pb_addr) {
            Ok(p) => p,
            Err(e) => return Self::fail_ret(e),
        };
        let (ha, hb) = (self.host_path(&pa), self.host_path(&pb));
        let r = match name {
            "linkat" => std::fs::hard_link(&ha, &hb),
            "renameat" | "renameat2" => std::fs::rename(&ha, &hb),
            "symlinkat" => polyisa_host::symlink(&String::from_utf8_lossy(&pa), &hb),
            _ => return Self::fail_ret(errno::ENOSYS),
        };
        match r {
            Ok(()) => ret(0),
            Err(e) => Self::fail_ret_host(e),
        }
    }

    /// メインの振り分け。戻りは `Disp`。
    fn dispatch(&mut self, env: &mut BareEnv, name: Option<&'static str>) -> Disp {
        let args: [u64; 6] = std::array::from_fn(|i| reg(env, i as u8));
        let Some(name) = name else {
            return Disp::Unimpl;
        };
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
            "openat" => {
                let dirfd = args[0] as u32;
                if dirfd as i32 != -100 {
                    return Self::fail_ret(errno::EBADF);
                }
                ret(self.do_open(env, args[1], args[2], args[3]))
            }
            "close" => {
                let fd = args[0] as u32;
                if fd < 3 {
                    return ret(0);
                }
                if self.fds.get(fd).is_some() {
                    self.fds.clear(fd);
                    ret(0)
                } else {
                    Self::fail_ret(errno::EBADF)
                }
            }
            "fstat" => {
                let fd = args[0] as u32;
                ret(self.do_stat(env, Some(fd), 0, args[1]))
            }
            "newfstatat" => {
                let dirfd = args[0] as u32;
                if dirfd as i32 != -100 {
                    return Self::fail_ret(errno::EBADF);
                }
                ret(self.do_stat(env, None, args[1], args[2]))
            }
            "statx" => {
                let dirfd = args[0] as u32;
                if dirfd as i32 != -100 {
                    return Self::fail_ret(errno::EBADF);
                }
                ret(self.do_statx(env, args[1], args[4]))
            }
            "ppoll" | "pselect6" => ret(0),
            "lseek" => {
                let fd = args[0] as u32;
                let off = args[1] as i64;
                let wh = args[2] as u32;
                ret(self.do_lseek(env, fd, off, wh))
            }
            "mmap" => {
                let flags = args[3];
                if flags & aarch64::mflag::ANONYMOUS == 0 {
                    return Self::fail_ret(errno::ENODEV);
                }
                ret(self.do_mmap(env, args[0], args[1], args[2], flags))
            }
            "munmap" => {
                let addr = args[0];
                let len = args[1].max(1);
                env.backend
                    .mem
                    .unmap(VirtAddr(addr), len.div_ceil(polyisa_mem::PAGE_SIZE));
                ret(0)
            }
            "mprotect" | "msync" | "mincore" | "madvise" => ret(0),
            "mremap" => Self::fail_ret(errno::ENOMEM),
            "brk" => ret(self.do_brk(env, args[0])),
            "rt_sigaction" | "rt_sigprocmask" | "sigaltstack" => ret(0),
            "rt_sigpending" => {
                let set = args[0];
                if set != 0 {
                    let _ = self.write_bytes(env, set, &[0u8; 16]);
                }
                ret(0)
            }
            "rt_sigreturn" | "getitimer" | "setitimer" | "futex" => Self::fail_ret(errno::ENOSYS),
            "ioctl" => {
                let fd = args[0] as u32;
                ret(self.do_ioctl(env, fd, args[1], args[2]))
            }
            "pread64" => {
                let fd = args[0] as u32;
                ret(self.do_pread(env, fd, args[1], args[2], args[3]))
            }
            "pwrite64" => {
                let fd = args[0] as u32;
                ret(self.do_pwrite(env, fd, args[1], args[2], args[3]))
            }
            "readv" => {
                let fd = args[0] as u32;
                ret(self.do_readv(env, fd, args[1], args[2]))
            }
            "writev" => {
                let fd = args[0] as u32;
                ret(self.do_writev(env, fd, args[1], args[2]))
            }
            "sched_yield" => ret(0),
            "getpid" | "gettid" | "getppid" | "getpgid" | "getsid" | "setpgid" | "setsid" => {
                ret(self.pid())
            }
            "clone" | "execve" | "wait4" | "waitid" => Self::fail_ret(errno::ENOSYS),
            "kill" | "tkill" | "tgkill" => ret(0),
            "uname" => ret(self.do_uname(env, args[0])),
            "fcntl" => {
                let fd = args[0] as u32;
                ret(self.do_fcntl(env, fd, args[1] as u32, args[2]))
            }
            "flock" | "fsync" | "fdatasync" | "sync" => {
                if name != "sync"
                    && let Some(f) = self.fds.get(args[0] as u32)
                {
                    let _ = f.sync_all();
                }
                ret(0)
            }
            "truncate64" | "ftruncate64" => {
                if name == "ftruncate64" {
                    let fd = args[0] as u32;
                    let len = args[1];
                    match self.file_of(fd) {
                        Ok(f) => match f.set_len(len) {
                            Ok(()) => ret(0),
                            Err(e) => Self::fail_ret_host(e),
                        },
                        Err(e) => Self::fail_ret(e),
                    }
                } else {
                    let path = match self.read_cstr(env, args[0]) {
                        Ok(p) => p,
                        Err(e) => return Self::fail_ret(e),
                    };
                    let len = args[1];
                    match std::fs::OpenOptions::new()
                        .write(true)
                        .open(self.host_path(&path))
                        .and_then(|f| f.set_len(len))
                    {
                        Ok(()) => ret(0),
                        Err(e) => Self::fail_ret_host(e),
                    }
                }
            }
            "getdents64" => {
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
                    return Self::fail_ret(errno::ERANGE);
                }
                match self.write_bytes(env, buf, cwd.as_bytes()) {
                    Ok(()) => {
                        let _ = self.write_bytes(env, buf + cwd.len() as u64, &[0]);
                        ret(cwd.len() as u64 + 1)
                    }
                    Err(e) => Self::fail_ret(e),
                }
            }
            "chdir" => {
                let path = match self.read_cstr(env, args[0]) {
                    Ok(p) => p,
                    Err(e) => return Self::fail_ret(e),
                };
                let host = self.host_path(&path);
                if polyisa_host::stat(&host)
                    .map(|m| m.mode & 0o170000 == 0o040000)
                    .unwrap_or(false)
                {
                    self.cwd = host;
                    ret(0)
                } else {
                    Self::fail_ret(errno::ENOENT)
                }
            }
            "fchdir" => ret(0),
            "unlinkat" | "faccessat" | "faccessat2" | "fchmodat" => self.path1_at(env, name, 1),
            "renameat" | "renameat2" | "linkat" | "symlinkat" => self.path2_at(env, name),
            "mkdirat" => {
                let path = match self.read_cstr(env, args[1]) {
                    Ok(p) => p,
                    Err(e) => return Self::fail_ret(e),
                };
                match std::fs::create_dir(self.host_path(&path)) {
                    Ok(()) => ret(0),
                    Err(e) => Self::fail_ret_host(e),
                }
            }
            "dup" => {
                let fd = args[0] as u32;
                match self
                    .fds
                    .get(fd)
                    .and_then(|f| f.try_clone().ok())
                    .map(|f| self.fds.alloc(Some(f)))
                {
                    Some(n) => ret(u64::from(n)),
                    None => Self::fail_ret(errno::EBADF),
                }
            }
            "dup3" => {
                let old = args[0] as u32;
                let new = args[1] as u32;
                match self.dup2_fd(old, new) {
                    Ok(()) => ret(u64::from(new)),
                    Err(e) => Self::fail_ret(e),
                }
            }
            "mknodat" | "pipe2" | "sendfile" | "rseq" => Self::fail_ret(errno::ENOSYS),
            "readlinkat" => {
                let dirfd = args[0] as u32;
                if dirfd as i32 != -100 {
                    return Self::fail_ret(errno::EBADF);
                }
                ret(self.do_readlink(env, args[1], args[2], args[3]))
            }
            "umask" => {
                let old = self.umask;
                self.umask = args[0] as u32 & 0o777;
                ret(u64::from(old))
            }
            "gettimeofday" | "times" | "getrusage" | "sysinfo" | "utimensat" => {
                if name == "sysinfo" {
                    ret(self.do_sysinfo(env, args[0]))
                } else if name == "gettimeofday" {
                    let tv = args[0];
                    let tz = args[1];
                    let (sec, usec) = Self::now();
                    if tv != 0 && (!self.put_u64(env, tv, sec) || !self.put_u64(env, tv + 8, usec))
                    {
                        return Self::fail_ret(errno::EFAULT);
                    }
                    if tz != 0 {
                        let _ = self.put_u32(env, tz, 0);
                        let _ = self.put_u32(env, tz + 4, 0);
                    }
                    ret(0)
                } else {
                    ret(0)
                }
            }
            "nanosleep" | "clock_nanosleep" => ret(0),
            "clock_gettime" | "clock_getres" => {
                let clk = args[0];
                let tp = args[1];
                let (sec, nsec) = if name == "clock_getres" {
                    (0, 1)
                } else if clk == 1 {
                    let us = self.mono_us();
                    (us / 1_000_000, (us % 1_000_000) * 1000)
                } else {
                    let (s, u) = Self::now();
                    (s, u * 1000)
                };
                if tp != 0 && !self.put_timespec(env, tp, sec, nsec) {
                    return Self::fail_ret(errno::EFAULT);
                }
                ret(0)
            }
            "getuid" | "geteuid" | "getgid" | "getegid" | "getgroups" | "setgroups" => ret(0),
            "sethostname" => ret(0),
            "getrlimit" | "setrlimit" | "prlimit64" => {
                let p = if name == "prlimit64" {
                    args[3]
                } else {
                    args[1]
                };
                if p != 0 {
                    let _ = self.put_u64(env, p, u64::MAX);
                    let _ = self.put_u64(env, p + 8, u64::MAX);
                }
                ret(0)
            }
            "ptrace" => Self::fail_ret(errno::EPERM),
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
                        let _ = self.put_u32(env, cpu, 0);
                    }
                    if node != 0 {
                        let _ = self.put_u32(env, node, 0);
                    }
                }
                ret(0)
            }
            "getrandom" => ret(self.do_getrandom(env, args[0], args[1])),
            "set_tid_address" => ret(self.pid()),
            "set_robust_list" | "membarrier" => ret(0),
            "statfs64" | "fstatfs64" => ret(self.do_statfs(env, args[1])),
            "personality" | "prctl" | "acct" | "mount" | "umount2" | "pivot_root" | "reboot"
            | "swapon" | "swapoff" | "quotactl" | "syslog" | "init_module" | "delete_module"
            | "fchmod" | "fchownat" | "fchown" => ret(0),
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

    fn handle_trap(&mut self, env: &mut BareEnv, _code: u32) -> TrapOutcome {
        let nr = reg(env, 8);
        let r = self.dispatch(env, aarch64::name(nr));
        match r {
            Disp::Ret(v) => {
                env.backend.set(Gpr(0).state(), v);
                TrapOutcome::Handled
            }
            Disp::Exit(code) => TrapOutcome::Exit(code),
            Disp::Unimpl => {
                if !self.reported.contains(&nr) {
                    self.reported.push(nr);
                    let name = aarch64::name(nr).unwrap_or("?");
                    eprintln!("aarch64: unimplemented syscall {nr} ({name})");
                }
                env.backend
                    .set(Gpr(0).state(), (-(errno::ENOSYS as i64)) as u64);
                TrapOutcome::Handled
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unimplemented_syscall_returns_enosys_and_continues() {
        let mut sys = Linux::default();
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_aarch64::CpuState>());
        env.backend.set(Gpr(8).state(), 9999);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(
            env.backend.get(Gpr(0).state()),
            (-(errno::ENOSYS as i64)) as u64
        );
    }

    #[test]
    fn write_to_stdout_is_captured() {
        let mut sys = Linux::default();
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_aarch64::CpuState>());
        env.backend
            .mem
            .map(VirtAddr(0x10000), 1, Perms::RW)
            .unwrap();
        env.backend.mem.write(VirtAddr(0x10000), b"hi").unwrap();
        env.backend.set(Gpr(8).state(), aarch64::WRITE);
        env.backend.set(Gpr(0).state(), 1);
        env.backend.set(Gpr(1).state(), 0x10000);
        env.backend.set(Gpr(2).state(), 2);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(sys.io.stdout, b"hi");
        assert_eq!(env.backend.get(Gpr(0).state()), 2);
    }
}
