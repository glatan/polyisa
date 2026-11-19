// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! m68k Linux の syscall 処理。
//!
//! 番号は d0、引数は d1–d5（6 個目以降はスタック）、戻り値は d0。
//! 失敗は d0 = -errno（負の値）で返す。errno・`O_*`/`MAP_*` の値は
//! 共通表と同じなのでホストの errno をそのまま使う。
//! trap #0 が発行点である（実行ループが code==0 でここへ渡す）。
//!
//! 試作の合意事項：仮想カーネル・VFS・ゲストルートの適用は後の段階である。
//! ここではホストのファイルに直接触る。信頼できないゲストバイナリには
//! 使わないこと。fork/clone/execve/パイプは未対応（ENOSYS）。
// Ref: SRC-LINUX (7.3).

use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

use polyisa_engine::bare::BareEnv;
use polyisa_guest_m68k::sem::{A, D};
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};
use polyisa_sem::Backend as _;

use crate::{TrapHandler, TrapOutcome, m68k};

/// m68k の write が集めたバイト。標準出力と標準エラーを分ける。
#[derive(Default)]
pub struct M68kIo {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// m68k Linux の syscall 状態機械。d0=番号、d1–d5=引数。
pub struct Linux {
    /// 標準入出力の capture。テストが読む。
    pub io: M68kIo,
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

impl Default for Linux {
    fn default() -> Self {
        Self::new()
    }
}

impl Linux {
    /// m68k Linux の状態機械を作る。データはビッグエンディアン。
    #[must_use]
    pub fn new() -> Self {
        Self {
            io: M68kIo::default(),
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

    /// 引数 `i`（0 起算）を取り出す。0–4 は d1–d5、5 番目は a0。
    /// スタック経由の引数はない。
    // Ref: SRC-LINUX (7.3) — syscall(2) の m68k 規約。
    fn arg(&self, env: &mut BareEnv, i: usize) -> u64 {
        match i {
            0..=4 => reg(env, i as u8 + 1),
            5 => u64::from(env.backend.get(A(0).state())),
            _ => 0,
        }
    }

    /// レジスタから 64 ビット引数を組み立てる（連続する 2 レジスタ。
    /// `lo` が小さい側の語。アライメントの丸めは呼び出し側が行う）。
    fn pair(&self, env: &mut BareEnv, lo_slot: usize) -> u64 {
        let a = self.arg(env, lo_slot) & 0xffff_ffff;
        let hi = self.arg(env, lo_slot + 1) & 0xffff_ffff;
        (hi << 32) | a
    }

    fn acc(&self, kind: AccessKind) -> Access {
        Access {
            endian: Endian::Be,
            align: Align::Unaligned,
            kind,
        }
    }

    /// 32 ビット値をメモリから読む。
    fn mem_u(&self, env: &mut BareEnv, addr: u64) -> u64 {
        let mut b = [0u8; 4];
        env.backend
            .mem
            .read(VirtAddr(addr), &mut b, self.acc(AccessKind::DataRead))
            .map_or(0, |()| u64::from(u32::from_be_bytes(b)))
    }

    /// ポインタ幅（32 ビット）の値をメモリに書く。
    fn put_u(&self, env: &mut BareEnv, addr: u64, v: u64) -> bool {
        env.backend
            .mem
            .write(VirtAddr(addr), &(v as u32).to_be_bytes())
            .is_ok()
    }

    /// 32 ビット値を書く。
    fn put32(&self, env: &mut BareEnv, addr: u64, v: u32) -> bool {
        self.put_u(env, addr, u64::from(v))
    }

    /// 64 ビット値を書く。
    fn put64(&self, env: &mut BareEnv, addr: u64, v: u64) -> bool {
        env.backend
            .mem
            .write(VirtAddr(addr), &v.to_be_bytes())
            .is_ok()
    }

    /// 16 ビット値を書く。
    fn put16(&self, env: &mut BareEnv, addr: u64, v: u16) -> bool {
        env.backend
            .mem
            .write(VirtAddr(addr), &v.to_be_bytes())
            .is_ok()
    }

    /// C 文字列を読む。上限 4096。
    fn read_cstr(&self, env: &mut BareEnv, addr: u64) -> Result<Vec<u8>, u32> {
        let mut out = Vec::new();
        let acc = self.acc(AccessKind::DataRead);
        for a in (addr..).take(4096) {
            let mut b = [0u8; 1];
            if env.backend.mem.read(VirtAddr(a), &mut b, acc).is_err() {
                return Err(m68k::errno::EFAULT);
            }
            if b[0] == 0 {
                return Ok(out);
            }
            out.push(b[0]);
        }
        Err(m68k::errno::ENAMETOOLONG)
    }

    fn read_bytes(&self, env: &mut BareEnv, addr: u64, len: usize) -> Result<Vec<u8>, u32> {
        let mut buf = vec![0u8; len.min(1 << 20)];
        if buf.is_empty() {
            return Ok(buf);
        }
        env.backend
            .mem
            .read(VirtAddr(addr), &mut buf, self.acc(AccessKind::DataRead))
            .map_err(|_| m68k::errno::EFAULT)?;
        Ok(buf)
    }

    fn write_bytes(&self, env: &mut BareEnv, addr: u64, data: &[u8]) -> Result<(), u32> {
        env.backend
            .mem
            .write(VirtAddr(addr), data)
            .map_err(|_| m68k::errno::EFAULT)
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
        self.fds.get_mut(fd).ok_or(m68k::errno::EBADF)
    }

    /// 読み用に fd を開いているものを返す。0/1/2 と FdTable の両方を見る。
    fn reader(&mut self, fd: u32) -> Result<ReadFd<'_>, u32> {
        match fd {
            0 => Ok(ReadFd::Stdin),
            1 | 2 => Err(m68k::errno::EBADF),
            _ => self
                .fds
                .get_mut(fd)
                .map(ReadFd::File)
                .ok_or(m68k::errno::EBADF),
        }
    }

    fn writer(&mut self, fd: u32) -> Result<WriteFd<'_>, u32> {
        match fd {
            0 => Err(m68k::errno::EBADF),
            1 => Ok(WriteFd::Stdout),
            2 => Ok(WriteFd::Stderr),
            _ => self
                .fds
                .get_mut(fd)
                .map(WriteFd::File)
                .ok_or(m68k::errno::EBADF),
        }
    }

    /// m68k の `O_*`（asm-generic）をホストの `OpenOptions` 用フラグへ写す。
    fn open_flags(guest: u32) -> std::fs::OpenOptions {
        use m68k::oflag::*;
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
                let fd = self.fds.alloc(Some(f));
                self.fds.remember_path(fd, host);
                ret(u64::from(fd))
            }
            Err(e) => fail_host(e.raw_os_error().unwrap_or(m68k::errno::EIO as i32)),
        }
    }

    /// ホストのメタデータをゲストの `stat64`（104B）に写す。
    /// m68k のレイアウトは uapi/asm/stat.h の stat64 に従う（E3 で照合）。
    /// Ref: SRC-LINUX (7.3) — arch/arm/include/uapi/asm/stat.h.
    fn put_stat64(&self, env: &mut BareEnv, addr: u64, md: &polyisa_host::Stat) -> bool {
        // 0: u64 dev, 8: pad0(4), 12: u32 __st_ino, 16: u32 mode,
        // 20: u32 nlink, 24: u32 uid, 28: u32 gid, 32: u64 rdev,
        // 40: pad3(4), 44: pad(4), 48: i64 size, 56: u32 blksize,
        // 60: pad(4), 64: u64 blocks, 72: u32 atime, 76: u32 ansec,
        // 80: u32 mtime, 84: u32 mnsec, 88: u32 ctime, 92: u32 cnsec,
        // 96: u64 ino
        let mut ok = true;
        ok &= self.put64(env, addr, md.dev);
        ok &= self.put32(env, addr + 12, md.ino as u32);
        ok &= self.put32(env, addr + 16, md.mode);
        ok &= self.put32(env, addr + 20, md.nlink as u32);
        ok &= self.put32(env, addr + 24, md.uid);
        ok &= self.put32(env, addr + 28, md.gid);
        ok &= self.put64(env, addr + 32, md.rdev);
        ok &= self.put64(env, addr + 48, md.size);
        ok &= self.put32(env, addr + 56, md.blksize as u32);
        ok &= self.put64(env, addr + 64, md.blocks);
        ok &= self.put32(env, addr + 72, md.atime as u32);
        ok &= self.put32(env, addr + 76, md.atime_nsec as u32);
        ok &= self.put32(env, addr + 80, md.mtime as u32);
        ok &= self.put32(env, addr + 84, md.mtime_nsec as u32);
        ok &= self.put32(env, addr + 88, md.ctime as u32);
        ok &= self.put32(env, addr + 92, md.ctime_nsec as u32);
        ok &= self.put64(env, addr + 96, md.ino);
        ok
    }

    /// `statx`（256B）。fstatat64 で使う形と同じ値を statx の形で置く。
    /// 使うフィールドだけ立てる（mask には取れた項目の合併を書く）。
    fn put_statx(&self, env: &mut BareEnv, addr: u64, md: &polyisa_host::Stat) -> bool {
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

    /// `stat` 系の共通部。`dirfd`/`path`/`fd` と statx かの区別を取る。
    fn do_stat(
        &mut self,
        env: &mut BareEnv,
        fd: Option<u32>,
        path_addr: Option<u64>,
        out: u64,
        lstat: bool,
        statx: bool,
    ) -> u64 {
        let md = match (fd, path_addr) {
            (Some(fd), _) => match fd {
                0..=2 => match polyisa_host::stat("/dev/null") {
                    Ok(m) => m,
                    Err(e) => return fail_host(e.raw_os_error().unwrap_or(5)),
                },
                _ => match self.fds.get(fd) {
                    Some(f) => match polyisa_host::fstat(f) {
                        Ok(m) => m,
                        Err(e) => {
                            return fail_host(e.raw_os_error().unwrap_or(5));
                        }
                    },
                    None => return fail(m68k::errno::EBADF),
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
                        return fail_host(e.raw_os_error().unwrap_or(m68k::errno::EIO as i32));
                    }
                }
            }
            _ => return fail(m68k::errno::EINVAL),
        };
        let ok = if statx {
            self.put_statx(env, out, &md)
        } else {
            self.put_stat64(env, out, &md)
        };
        if ok {
            ret(0)
        } else {
            fail(m68k::errno::EFAULT)
        }
    }

    /// `mmap2`（addr は無視して自前割当。fixed ならその位置）。
    fn do_mmap(&mut self, env: &mut BareEnv, addr: u64, len: u64, prot: u64, flags: u64) -> u64 {
        if len == 0 {
            return fail(m68k::errno::EINVAL);
        }
        let pages = len.div_ceil(4096);
        let fixed = flags & m68k::mmap_flag::FIXED != 0;
        let base = if fixed {
            addr & !0xfff
        } else {
            let b = self.mmap_next;
            self.mmap_next += pages * 4096;
            b
        };
        let mut p = 0u8;
        if prot & m68k::prot::READ != 0 {
            p |= Perms::R.0;
        }
        if prot & m68k::prot::WRITE != 0 {
            p |= Perms::W.0;
        }
        if prot & m68k::prot::EXEC != 0 {
            p |= Perms::X.0;
        }
        match env.backend.mem.map(VirtAddr(base), pages, Perms(p)) {
            Ok(()) => ret(base),
            Err(_) => fail(m68k::errno::ENOMEM),
        }
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

    /// `uname`（65B×6）。machine は m68k とする。
    fn do_uname(&mut self, env: &mut BareEnv, addr: u64) -> u64 {
        let fields: [&[u8]; 6] = [
            b"Linux",
            b"polyisa",
            b"6.19.0",
            b"#1 polyisa",
            b"m68k",
            b"(none)",
        ];
        for (i, f) in fields.iter().enumerate() {
            let mut buf = [0u8; 65];
            buf[..f.len()].copy_from_slice(f);
            if self.write_bytes(env, addr + (i * 65) as u64, &buf).is_err() {
                return fail(m68k::errno::EFAULT);
            }
        }
        ret(0)
    }

    /// `sysinfo`（32 ビット形式・64B）。
    fn do_sysinfo(&mut self, env: &mut BareEnv, addr: u64) -> u64 {
        let secs = self.mono_start.map(|s| s.elapsed().as_secs()).unwrap_or(0) as u32;
        let total = 512 * 1024 * 1024u32;
        let mut ok = true;
        ok &= self.put32(env, addr, secs); // uptime
        ok &= self.put32(env, addr + 4, 0); // loads[0]
        ok &= self.put32(env, addr + 8, 0);
        ok &= self.put32(env, addr + 12, 0);
        ok &= self.put32(env, addr + 16, total);
        ok &= self.put32(env, addr + 20, total);
        ok &= self.put32(env, addr + 24, 0);
        ok &= self.put32(env, addr + 28, 0);
        ok &= self.put32(env, addr + 32, 0);
        ok &= self.put32(env, addr + 36, 0);
        ok &= self.put16(env, addr + 40, 1); // procs
        ok &= self.put16(env, addr + 42, 0);
        ok &= self.put32(env, addr + 44, 0);
        ok &= self.put32(env, addr + 48, 0);
        ok &= self.put32(env, addr + 52, 1); // mem_unit
        if ok {
            ret(0)
        } else {
            fail(m68k::errno::EFAULT)
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
            Err(e) => fail_host(e.raw_os_error().unwrap_or(m68k::errno::EIO as i32)),
        }
    }

    /// `getdents64`。linux_dirent64: u64 d_ino, u64 d_off, u16 d_reclen,
    /// u8 d_type, name\0。
    fn do_getdents64(&mut self, env: &mut BareEnv, fd: u32, buf: u64, count: u64) -> u64 {
        let path = self.fds.path_of(fd).map(str::to_string).unwrap_or_default();
        if path.is_empty() {
            return fail(m68k::errno::ENOTDIR);
        }
        let rd = match std::fs::read_dir(&path) {
            Ok(r) => r,
            Err(e) => {
                return fail_host(e.raw_os_error().unwrap_or(m68k::errno::EIO as i32));
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
                    return fail_host(e.raw_os_error().unwrap_or(m68k::errno::EIO as i32));
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
                    Err(e) => fail_host(e.raw_os_error().unwrap_or(m68k::errno::EIO as i32)),
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
            Err(e) => fail_host(e.raw_os_error().unwrap_or(m68k::errno::EIO as i32)),
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
                Err(e) => fail_host(e.raw_os_error().unwrap_or(m68k::errno::EIO as i32)),
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
            Err(e) => fail_host(e.raw_os_error().unwrap_or(m68k::errno::EIO as i32)),
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
            return fail(m68k::errno::EINVAL);
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
                            return fail_host(e.raw_os_error().unwrap_or(m68k::errno::EIO as i32));
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
                        return fail_host(e.raw_os_error().unwrap_or(m68k::errno::EIO as i32));
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

    /// `readv`/`writev`（iov は u32 の二つ組）。
    fn do_readv(&mut self, env: &mut BareEnv, fd: u32, iov: u64, cnt: u64) -> u64 {
        let mut total = 0u64;
        for i in 0..cnt.min(1024) {
            let base = self.mem_u(env, iov + i * 8);
            let len = self.mem_u(env, iov + i * 8 + 4);
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
        let mut total = 0u64;
        for i in 0..cnt.min(1024) {
            let base = self.mem_u(env, iov + i * 8);
            let len = self.mem_u(env, iov + i * 8 + 4);
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
            return fail(m68k::errno::EINVAL);
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
            Err(e) => fail_host(e.raw_os_error().unwrap_or(m68k::errno::EIO as i32)),
        }
    }

    /// `ioctl`。TCGETS/TCSETS/TIOCGWINSZ/FIONREAD だけ。
    fn do_ioctl(&mut self, env: &mut BareEnv, fd: u32, req: u64, argp: u64) -> u64 {
        const TCGETS: u64 = 0x5401;
        const TCSETS: u64 = 0x5402;
        const TIOCGWINSZ: u64 = 0x5413;
        const FIONREAD: u64 = 0x541b;
        match req {
            TCGETS | TCSETS => {
                if fd > 2 {
                    return fail(m68k::errno::ENOTTY);
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
                    fail(m68k::errno::EFAULT)
                }
            }
            _ => fail(m68k::errno::ENOTTY),
        }
    }

    /// `fcntl`/`fcntl64`。FD フラグと dup だけ。
    fn do_fcntl(&mut self, _env: &mut BareEnv, fd: u32, cmd: u32, arg: u64) -> u64 {
        match cmd {
            // F_DUPFD(0)/F_DUPFD_CLOEXEC(1030)：fd の複製。
            0 | 1030 => match self.fds.get(fd) {
                Some(f) => match f.try_clone() {
                    Ok(g) => {
                        let nfd = self.fds.alloc_where(Some(g), |i| 3 + i >= arg as usize);
                        let p = self.fds.path_of(fd).map(str::to_string);
                        if let Some(p) = p {
                            self.fds.remember_path(nfd, p);
                        }
                        ret(u64::from(nfd))
                    }
                    Err(e) => fail_host(e.raw_os_error().unwrap_or(m68k::errno::EIO as i32)),
                },
                None => fail(m68k::errno::EBADF),
            },
            1 => ret(0), // F_GETFD
            2 => ret(0), // F_SETFD
            3 => ret(0), // F_GETFL（フラグは覚えていない）
            4 => ret(0), // F_SETFL
            _ => fail(m68k::errno::EINVAL),
        }
    }

    /// `gettimeofday`/`clock_gettime`/`time`/`times` の単調時計。
    fn mono_us(&mut self) -> u64 {
        self.mono_start
            .get_or_insert_with(std::time::Instant::now)
            .elapsed()
            .as_micros() as u64
    }

    /// `timespec`（32 ビット。u32×2）を書く。
    fn put_timespec(&self, env: &mut BareEnv, addr: u64, sec: u64, nsec: u64) -> bool {
        self.put32(env, addr, sec as u32) && self.put32(env, addr + 4, nsec as u32)
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
            fail(m68k::errno::EFAULT)
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

/// syscall トレースのスイッチ。
fn trace() -> bool {
    std::env::var_os("POLYISA_M68K_SYSCALLS").is_some()
}

fn reg(env: &mut BareEnv, i: u8) -> u64 {
    u64::from(env.backend.get(D(i).state()))
}

fn set_reg(env: &mut BareEnv, i: u8, v: u64) {
    env.backend.set(D(i).state(), v as u32);
}

/// 戻り値が -errno か。
fn is_err_r(v: u64) -> bool {
    let v = v as u32 as i32;
    (-4096..0).contains(&v)
}

/// 成功の戻り値（r0 に置く値そのもの）。
fn ret(v: u64) -> u64 {
    v & 0xffff_ffff
}

/// 失敗。r0 = -errno。
fn fail(errno: u32) -> u64 {
    u64::from(errno.wrapping_neg())
}

/// ホスト errno を m68k errno（asm-generic と同じ番号）に写して失敗を返す。
fn fail_host(e: i32) -> u64 {
    fail(e.unsigned_abs())
}

/// dispatch の戻り。
enum Disp {
    /// r0 に書く値。
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

    fn handle_trap(&mut self, env: &mut BareEnv, code: u32) -> TrapOutcome {
        // trap #0（ベクタ 32）のみ syscall。他の trap は CPU 例外として
        // 配送するため呼び出し側へ返す。
        if code != 32 {
            return TrapOutcome::Unimplemented;
        }
        let nr = reg(env, 0) & 0xffff_ffff;
        if trace() {
            let name = m68k::name(nr).unwrap_or("?");
            eprintln!(
                "sys {nr} {name} d1={:#x} d2={:#x}",
                reg(env, 1),
                reg(env, 2)
            );
        }
        let r = self.dispatch(env, nr);
        match r {
            Disp::Ret(v) => {
                set_reg(env, 0, v);
                TrapOutcome::Handled
            }
            Disp::Exit(code) => TrapOutcome::Exit(code),
            Disp::Unimpl => {
                let name = m68k::name(nr).unwrap_or("?");
                if !self.reported.contains(&nr) {
                    self.reported.push(nr);
                    eprintln!("m68k: unimplemented syscall {nr} ({name})");
                }
                set_reg(env, 0, fail(m68k::errno::ENOSYS));
                TrapOutcome::Handled
            }
        }
    }
}

impl Linux {
    /// 番号で振り分ける。戻り値は Disp で返し、r0 は handle_trap が書く。
    #[allow(clippy::too_many_lines)]
    fn dispatch(&mut self, env: &mut BareEnv, n: u64) -> Disp {
        use m68k::errno as E;
        let args: [u64; 8] = std::array::from_fn(|i| self.arg(env, i));
        match n {
            // ---- プロセス ----
            m68k::EXIT | m68k::EXIT_GROUP => Disp::Exit((args[0] & 0xff) as u32),
            m68k::FORK | m68k::VFORK | m68k::CLONE | m68k::EXECVE | m68k::EXECVEAT => {
                fail_ret(E::ENOSYS)
            }
            // waitpid 相当。子を作れないので常に ECHILD。
            7 | m68k::WAIT4 | m68k::WAITID => fail_ret(E::ECHILD),
            m68k::GETPID | m68k::GETTID => ok_ret(self.pid()),
            m68k::GETPPID => ok_ret(0),
            m68k::GETPGRP | m68k::GETPGID | m68k::GETSID => ok_ret(self.pid()),
            m68k::SETPGID | m68k::SETSID => ok_ret(self.pid()),
            m68k::GETUID
            | m68k::GETEUID
            | m68k::GETGID
            | m68k::GETEGID
            | m68k::GETUID32
            | m68k::GETEUID32
            | m68k::GETGID32
            | m68k::GETEGID32 => ok_ret(0),
            m68k::GETGROUPS | m68k::GETGROUPS32 => ok_ret(0),
            m68k::SETGROUPS | m68k::SETGROUPS32 => ok_ret(0),
            m68k::GETRESUID | m68k::GETRESGID | m68k::GETRESUID32 | m68k::GETRESGID32 => {
                // (ruid, euid, suid) を三語書く。
                for a in args.iter().take(3) {
                    if !self.put32(env, *a, 0) {
                        return fail_ret(E::EFAULT);
                    }
                }
                ok_ret(0)
            }
            m68k::SETUID
            | m68k::SETGID
            | m68k::SETREUID
            | m68k::SETREGID
            | m68k::SETRESUID
            | m68k::SETRESGID
            | m68k::SETFSUID
            | m68k::SETFSGID
            | m68k::SETUID32
            | m68k::SETGID32
            | m68k::SETREUID32
            | m68k::SETREGID32
            | m68k::SETRESUID32
            | m68k::SETRESGID32
            | m68k::SETFSUID32
            | m68k::SETFSGID32 => ok_ret(0),
            // ---- ファイル I/O ----
            m68k::READ => Disp::Ret(self.do_read(env, args[0] as u32, args[1], args[2])),
            m68k::PREAD64 => {
                // pread64(fd, buf, len, pad, off_lo, off_hi)
                let off = self.pair(env, 3);
                Disp::Ret(self.do_pread(env, args[0] as u32, args[1], args[2], off))
            }
            m68k::PWRITE64 => {
                // pwrite64(fd, buf, len, pad, off_lo, off_hi)
                let off = self.pair(env, 3);
                Disp::Ret(self.do_pwrite(env, args[0] as u32, args[1], args[2], off))
            }
            m68k::WRITE => Disp::Ret(self.do_write(env, args[0] as u32, args[1], args[2])),
            m68k::READV => Disp::Ret(self.do_readv(env, args[0] as u32, args[1], args[2])),
            m68k::WRITEV => Disp::Ret(self.do_writev(env, args[0] as u32, args[1], args[2])),
            m68k::SENDFILE | m68k::SENDFILE64 => {
                Disp::Ret(self.do_sendfile(env, args[0] as u32, args[1] as u32, args[2], args[3]))
            }
            m68k::OPEN => Disp::Ret(self.do_open(env, args[0], args[1] as u32, args[2] as u32)),
            m68k::OPENAT => {
                if args[0] as i32 != -100 {
                    return fail_ret(E::EBADF);
                }
                Disp::Ret(self.do_open(env, args[1], args[2] as u32, args[3] as u32))
            }
            m68k::CREAT => {
                let flags = m68k::oflag::CREAT | m68k::oflag::TRUNC | 1;
                Disp::Ret(self.do_open(env, args[0], flags, args[1] as u32))
            }
            m68k::CLOSE => {
                let fd = args[0] as u32;
                if fd < 3 {
                    return ok_ret(0);
                }
                if self.fds.get(fd).is_some() {
                    self.fds.clear(fd);
                    self.dir_pos.remove(&fd);
                    ok_ret(0)
                } else {
                    fail_ret(E::EBADF)
                }
            }
            m68k::LSEEK => Disp::Ret(self.do_lseek(
                env,
                args[0] as u32,
                i64::from(args[1] as u32 as i32),
                args[2] as u32,
            )),
            m68k::LLSEEK => {
                // _llseek(fd, hi, lo, result_ptr, whence)
                let fd = args[0] as u32;
                let off = ((args[1] & 0xffff_ffff) << 32) | (args[2] & 0xffff_ffff);
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
            // ---- stat 系（stat64 レイアウト）----
            m68k::STAT | m68k::STAT64 => {
                Disp::Ret(self.do_stat(env, None, Some(args[0]), args[1], false, false))
            }
            m68k::LSTAT | m68k::LSTAT64 => {
                Disp::Ret(self.do_stat(env, None, Some(args[0]), args[1], true, false))
            }
            m68k::FSTAT | m68k::FSTAT64 => {
                Disp::Ret(self.do_stat(env, Some(args[0] as u32), None, args[1], false, false))
            }
            m68k::FSTATAT64 => {
                if args[0] as i32 != -100 {
                    return fail_ret(E::EBADF);
                }
                let lstat = args[3] & 0x100 != 0; // AT_SYMLINK_NOFOLLOW
                Disp::Ret(self.do_stat(env, None, Some(args[1]), args[2], lstat, false))
            }
            m68k::STATX => {
                // statx(dirfd, path, flags, mask, buf)
                if args[0] as i32 != -100 {
                    return fail_ret(E::EBADF);
                }
                let lstat = args[2] & 0x100 != 0;
                Disp::Ret(self.do_stat(env, None, Some(args[1]), args[4], lstat, true))
            }
            // ---- アクセス・属性 ----
            m68k::ACCESS => {
                let path = match self.read_cstr(env, args[0]) {
                    Ok(p) => p,
                    Err(e) => return fail_ret(e),
                };
                match polyisa_host::stat(&self.host_path(&path)) {
                    Ok(_) => ok_ret(0),
                    Err(e) => fail_ret_host(e.raw_os_error().unwrap_or(E::EIO as i32)),
                }
            }
            m68k::FACCESSAT | m68k::FACCESSAT2 => {
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
            m68k::CHMOD | m68k::FCHMOD | m68k::FCHMODAT => ok_ret(0),
            m68k::CHOWN
            | m68k::FCHOWN
            | m68k::LCHOWN
            | m68k::FCHOWNAT
            | m68k::LCHOWN32
            | m68k::FCHOWN32
            | m68k::CHOWN32 => ok_ret(0),
            // ---- ディレクトリと名前 ----
            m68k::GETDENTS64 => {
                Disp::Ret(self.do_getdents64(env, args[0] as u32, args[1], args[2]))
            }
            m68k::GETDENTS => fail_ret(E::ENOSYS),
            m68k::GETCWD => {
                let cwd = if self.cwd.is_empty() {
                    std::env::current_dir()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_else(|_| "/".to_string())
                } else {
                    self.cwd.clone()
                };
                let b = cwd.as_bytes();
                let n = (b.len() + 1).min(args[1] as usize);
                match self.write_bytes(env, args[0], &b[..n.min(b.len())]) {
                    Ok(()) => {
                        let _ = self.put32(env, args[0].wrapping_add((n - 1) as u64), 0);
                        ok_ret(n as u64)
                    }
                    Err(e) => fail_ret(e),
                }
            }
            m68k::CHDIR => {
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
            m68k::FCHDIR => ok_ret(0),
            m68k::MKDIR | m68k::MKDIRAT => {
                let idx = if n == m68k::MKDIR { 0 } else { 1 };
                let path = match self.read_cstr(env, args[idx]) {
                    Ok(p) => p,
                    Err(e) => return fail_ret(e),
                };
                match std::fs::create_dir(self.host_path(&path)) {
                    Ok(()) => ok_ret(0),
                    Err(e) => fail_ret_host(e.raw_os_error().unwrap_or(E::EIO as i32)),
                }
            }
            m68k::RMDIR => {
                let path = match self.read_cstr(env, args[0]) {
                    Ok(p) => p,
                    Err(e) => return fail_ret(e),
                };
                match std::fs::remove_dir(self.host_path(&path)) {
                    Ok(()) => ok_ret(0),
                    Err(e) => fail_ret_host(e.raw_os_error().unwrap_or(E::EIO as i32)),
                }
            }
            m68k::UNLINK | m68k::UNLINKAT => {
                let idx = if n == m68k::UNLINK { 0 } else { 1 };
                let path = match self.read_cstr(env, args[idx]) {
                    Ok(p) => p,
                    Err(e) => return fail_ret(e),
                };
                match std::fs::remove_file(self.host_path(&path)) {
                    Ok(()) => ok_ret(0),
                    Err(e) => fail_ret_host(e.raw_os_error().unwrap_or(E::EIO as i32)),
                }
            }
            m68k::RENAME | m68k::RENAMEAT => {
                let (a, b) = if n == m68k::RENAME {
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
            m68k::LINK | m68k::LINKAT => {
                // link(old,new) / linkat(olddirfd,old,newdirfd,new,flags)。
                // AT_FDCWD 以外の dirfd は未対応。
                let (a, b) = if n == m68k::LINK {
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
            m68k::SYMLINK | m68k::SYMLINKAT => {
                let (a, b) = if n == m68k::SYMLINK {
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
            m68k::READLINK => Disp::Ret(self.do_readlink(env, args[0], args[1], args[2])),
            m68k::READLINKAT => {
                if args[0] as i32 != -100 {
                    return fail_ret(E::EBADF);
                }
                Disp::Ret(self.do_readlink(env, args[1], args[2], args[3]))
            }
            m68k::TRUNCATE | m68k::TRUNCATE64 | m68k::FTRUNCATE | m68k::FTRUNCATE64 => match n {
                m68k::TRUNCATE | m68k::TRUNCATE64 => {
                    let path = match self.read_cstr(env, args[0]) {
                        Ok(p) => p,
                        Err(e) => return fail_ret(e),
                    };
                    // truncate64 は len が d2:d3（lo:hi）。
                    let len = if n == m68k::TRUNCATE {
                        args[1]
                    } else {
                        self.pair(env, 1)
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
                    // ftruncate64 は fd=d1, len=d2:d3（lo:hi）。
                    let len = if n == m68k::FTRUNCATE {
                        args[1]
                    } else {
                        self.pair(env, 1)
                    };
                    match self.file_of(fd).and_then(|f| {
                        f.set_len(len).map_err(|_| m68k::errno::EIO)?;
                        Ok(())
                    }) {
                        Ok(()) => ok_ret(0),
                        Err(e) => fail_ret(e),
                    }
                }
            },
            // ---- モード・マウント等（EPERM）----
            m68k::MKNOD
            | m68k::MKNODAT
            | m68k::MOUNT
            | m68k::UMOUNT
            | m68k::UMOUNT2
            | m68k::PIVOT_ROOT
            | m68k::CHROOT
            | m68k::REBOOT
            | m68k::ACCT
            | m68k::INIT_MODULE
            | m68k::DELETE_MODULE
            | m68k::SWAPON
            | m68k::SWAPOFF
            | m68k::SETDOMAINNAME
            | m68k::SETHOSTNAME => fail_ret(E::EPERM),
            m68k::UMASK => {
                let old = self.umask;
                self.umask = args[0] as u32 & 0o777;
                ok_ret(u64::from(old))
            }
            // ---- ディスクリプタ操作 ----
            m68k::DUP => match self.fds.get(args[0] as u32) {
                Some(f) => match f.try_clone() {
                    Ok(g) => {
                        let nfd = self.fds.alloc(Some(g));
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
            m68k::DUP2 | m68k::DUP3 => {
                let (old, new) = (args[0] as u32, args[1] as u32);
                if old == new {
                    return ok_ret(u64::from(new));
                }
                let p = self.fds.path_of(old).map(str::to_string);
                let g = match self.fds.get(old).and_then(|f| f.try_clone().ok()) {
                    Some(g) => g,
                    None => return fail_ret(E::EBADF),
                };
                self.fds.place(new, Some(g));
                if let Some(p) = p {
                    self.fds.remember_path(new, p);
                }
                ok_ret(u64::from(new))
            }
            m68k::FCNTL | m68k::FCNTL64 => {
                Disp::Ret(self.do_fcntl(env, args[0] as u32, args[1] as u32, args[2]))
            }
            m68k::IOCTL => Disp::Ret(self.do_ioctl(env, args[0] as u32, args[1], args[2])),
            m68k::PIPE | m68k::PIPE2 => fail_ret(E::ENOSYS),
            // ---- メモリ ----
            m68k::BRK => Disp::Ret(self.do_brk(env, args[0])),
            m68k::MMAP2 => Disp::Ret(self.do_mmap(env, args[0], args[1], args[2], args[3])),
            m68k::MUNMAP => {
                let pages = args[1].div_ceil(4096);
                env.backend.mem.unmap(VirtAddr(args[0] & !0xfff), pages);
                ok_ret(0)
            }
            m68k::MPROTECT => {
                let mut p = 0u8;
                if args[2] & m68k::prot::READ != 0 {
                    p |= Perms::R.0;
                }
                if args[2] & m68k::prot::WRITE != 0 {
                    p |= Perms::W.0;
                }
                if args[2] & m68k::prot::EXEC != 0 {
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
            m68k::UNAME => Disp::Ret(self.do_uname(env, args[0])),
            m68k::SYSINFO => Disp::Ret(self.do_sysinfo(env, args[0])),
            m68k::MREMAP => fail_ret(E::ENOMEM),
            m68k::MADVISE
            | m68k::MINCORE
            | m68k::MSYNC
            | m68k::MLOCK
            | m68k::MUNLOCK
            | m68k::MLOCKALL
            | m68k::MUNLOCKALL
            | m68k::MLOCK2
            | m68k::FADVISE64
            | m68k::READAHEAD
            | m68k::FALLOCATE => ok_ret(0),
            // ---- 時間 ----
            m68k::TIME => {
                let secs = now_secs();
                let tp = args[0];
                if tp != 0 && !self.put32(env, tp, secs as u32) {
                    return fail_ret(E::EFAULT);
                }
                ok_ret(secs)
            }
            m68k::GETTIMEOFDAY => {
                let (sec, usec) = now_us();
                let mut ok = true;
                ok &= self.put32(env, args[0], sec as u32);
                ok &= self.put32(env, args[0] + 4, usec as u32);
                if ok { ok_ret(0) } else { fail_ret(E::EFAULT) }
            }
            m68k::SETTIMEOFDAY => ok_ret(0),
            m68k::CLOCK_GETTIME | m68k::CLOCK_GETTIME64 => {
                let mono = args[0] == 1; // CLOCK_MONOTONIC
                let (sec, nsec) = if mono {
                    let us = self.mono_us();
                    (us / 1_000_000, (us % 1_000_000) * 1000)
                } else {
                    now_ns()
                };
                if n == m68k::CLOCK_GETTIME {
                    if self.put_timespec(env, args[1], sec, nsec) {
                        ok_ret(0)
                    } else {
                        fail_ret(E::EFAULT)
                    }
                } else {
                    // time64 形式：i64 sec + i64 nsec（下位 32 だけ）。
                    let ok = self.put64(env, args[1], sec) && self.put64(env, args[1] + 8, nsec);
                    if ok { ok_ret(0) } else { fail_ret(E::EFAULT) }
                }
            }
            m68k::CLOCK_GETRES | m68k::CLOCK_GETRES_TIME64 => {
                if n == m68k::CLOCK_GETRES {
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
            m68k::CLOCK_SETTIME | m68k::CLOCK_SETTIME64 | m68k::CLOCK_ADJTIME | m68k::ADJTIMEX => {
                ok_ret(0)
            }
            m68k::NANOSLEEP | m68k::CLOCK_NANOSLEEP | m68k::CLOCK_NANOSLEEP_TIME64 => ok_ret(0),
            m68k::TIMES => {
                // tms { utime, stime, cutime, cstime } u32×4。
                let mut ok = true;
                for i in 0..4 {
                    ok &= self.put32(env, args[0] + i * 4, 0);
                }
                if ok {
                    ok_ret(self.mono_us() / 10_000)
                } else {
                    fail_ret(E::EFAULT)
                }
            }
            m68k::UTIMES | m68k::UTIMENSAT | m68k::UTIMENSAT_TIME64 | m68k::FUTIMESAT => ok_ret(0),
            // ---- 資源 ----
            m68k::UGETRLIMIT => {
                // rlimit { u32 cur, u32 max }。RLIMIT_INFINITY 相当。
                let mut ok = true;
                ok &= self.put32(env, args[1], 0xffff_ffff);
                ok &= self.put32(env, args[1] + 4, 0xffff_ffff);
                if ok { ok_ret(0) } else { fail_ret(E::EFAULT) }
            }
            m68k::PRLIMIT64 => {
                // rlimit64 { u64 cur, u64 max }。
                if args[3] != 0 {
                    let mut ok = true;
                    ok &= self.put64(env, args[3], 0xffff_ffff_ffff_ffff);
                    ok &= self.put64(env, args[3] + 8, 0xffff_ffff_ffff_ffff);
                    if !ok {
                        return fail_ret(E::EFAULT);
                    }
                }
                ok_ret(0)
            }
            m68k::SETRLIMIT => ok_ret(0),
            m68k::GETRUSAGE => {
                if args[1] != 0 {
                    let _ = self.put32(env, args[1], 0);
                }
                ok_ret(0)
            }
            // getpriority(which, who) は nice 値を返す。最小権限の 20 を返す。
            m68k::GETPRIORITY => ok_ret(20),
            m68k::SETPRIORITY | m68k::NICE => ok_ret(0),
            m68k::SCHED_SETPARAM | m68k::SCHED_SETSCHEDULER | m68k::SCHED_YIELD => ok_ret(0),
            m68k::SCHED_GETPARAM | m68k::SCHED_GETSCHEDULER => {
                if args[1] != 0 {
                    let _ = self.put32(env, args[1], 0);
                }
                ok_ret(0)
            }
            m68k::SCHED_GET_PRIORITY_MAX => ok_ret(99),
            m68k::SCHED_GET_PRIORITY_MIN => ok_ret(1),
            m68k::SCHED_RR_GET_INTERVAL | m68k::SCHED_RR_GET_INTERVAL_TIME64 => {
                let _ = self.put_timespec(env, args[1], 0, 1_000_000);
                ok_ret(0)
            }
            m68k::SCHED_SETAFFINITY => ok_ret(0),
            m68k::SCHED_GETAFFINITY => {
                // cpu0 だけのマスク。
                let mut b = vec![0u8; args[1].min(128) as usize];
                b[0] = 1;
                match self.write_bytes(env, args[2], &b) {
                    Ok(()) => ok_ret(0),
                    Err(e) => fail_ret(e),
                }
            }
            m68k::GETCPU => {
                if args[0] != 0 {
                    let _ = self.put32(env, args[0], 0);
                }
                if args[1] != 0 {
                    let _ = self.put32(env, args[1], 0);
                }
                ok_ret(0)
            }
            m68k::IOPRIO_SET => ok_ret(0),
            m68k::IOPRIO_GET => ok_ret(0),
            m68k::GETITIMER | m68k::SETITIMER => ok_ret(0),
            // ---- シグナル（受け付けるだけ）----
            m68k::SIGACTION
            | m68k::RT_SIGACTION
            | m68k::SIGPROCMASK
            | m68k::RT_SIGPROCMASK
            | m68k::SIGPENDING
            | m68k::RT_SIGPENDING
            | m68k::SIGSUSPEND
            | m68k::RT_SIGSUSPEND
            | m68k::RT_SIGTIMEDWAIT
            | m68k::RT_SIGQUEUEINFO
            | m68k::SIGALTSTACK
            | m68k::RT_TGSIGQUEUEINFO
            | m68k::SIGNALFD
            | m68k::SIGNALFD4 => ok_ret(0),
            m68k::RT_SIGRETURN => ok_ret(0),
            m68k::KILL | m68k::TKILL | m68k::TGKILL => {
                if args[0] == 0 || args[0] == self.pid {
                    ok_ret(0)
                } else {
                    fail_ret(E::ESRCH)
                }
            }
            // ---- スレッド・同期 ----
            m68k::FUTEX | m68k::FUTEX_TIME64 => {
                // 単一スレッド。WAKE は 0、WAIT は EAGAIN と同義で即抜け。
                ok_ret(0)
            }
            m68k::SET_TID_ADDRESS => {
                let pid = self.pid() as u32;
                if args[0] != 0 {
                    let _ = self.put32(env, args[0], pid);
                }
                ok_ret(u64::from(pid))
            }
            m68k::SET_ROBUST_LIST => ok_ret(0),
            m68k::GET_ROBUST_LIST => fail_ret(E::ENOSYS),
            // ---- 選択・poll ----
            m68k::NEWSELECT
            | m68k::POLL
            | m68k::PSELECT6
            | m68k::PSELECT6_TIME64
            | m68k::PPOLL
            | m68k::PPOLL_TIME64 => {
                // 即時「準備なし」。fd 群の健全性は見ない。
                let _ = env;
                ok_ret(0)
            }
            m68k::PAUSE => ok_ret(0),
            // ---- ファイルシステム情報 ----
            m68k::STATFS => Disp::Ret(self.do_statfs(env, args[1], false)),
            m68k::FSTATFS => Disp::Ret(self.do_statfs(env, args[1], false)),
            m68k::STATFS64 => Disp::Ret(self.do_statfs(env, args[2], true)),
            m68k::FSTATFS64 => Disp::Ret(self.do_statfs(env, args[2], true)),
            m68k::USTAT => ok_ret(0),
            // ---- 属性拡張 ----
            m68k::SETXATTR | m68k::LSETXATTR | m68k::FSETXATTR => ok_ret(0),
            m68k::GETXATTR
            | m68k::LGETXATTR
            | m68k::FGETXATTR
            | m68k::LISTXATTR
            | m68k::LLISTXATTR
            | m68k::FLISTXATTR => fail_ret(E::ENOTSUP),
            m68k::REMOVEXATTR | m68k::LREMOVEXATTR | m68k::FREMOVEXATTR => ok_ret(0),
            // ---- 認証・機能 ----
            m68k::CAPGET | m68k::CAPSET => ok_ret(0),
            m68k::PERSONALITY => ok_ret(0),
            m68k::PRCTL | m68k::SECCOMP => ok_ret(0),
            m68k::SYSLOG
            | m68k::QUOTACTL
            | m68k::PTRACE
            | m68k::USELIB
            | m68k::VHANGUP
            | m68k::SYSFS
            | m68k::BDFLUSH
            | m68k::NFSSERVCTL
            | m68k::ADD_KEY
            | m68k::REQUEST_KEY
            | m68k::KEYCTL
            | m68k::KEXEC_LOAD
            | m68k::LOOKUP_DCOOKIE
            | m68k::REMAP_FILE_PAGES
            | m68k::MBIND
            | m68k::GET_MEMPOLICY
            | m68k::SET_MEMPOLICY
            | m68k::MIGRATE_PAGES
            | m68k::MOVE_PAGES
            | m68k::UNSHARE
            | m68k::MOUNT_SETATTR
            | m68k::OPEN_TREE
            | m68k::MOVE_MOUNT
            | m68k::FSOPEN
            | m68k::PIDFD_OPEN
            | m68k::PIDFD_GETFD
            | m68k::PIDFD_SEND_SIGNAL
            | m68k::CLONE3
            | m68k::CLOSE_RANGE
            | m68k::OPENAT2
            | m68k::PROCESS_MADVISE
            | m68k::EPOLL_PWAIT2
            | m68k::FUTEX_WAITV
            | m68k::KCMP
            | m68k::PROCESS_VM_READV
            | m68k::PROCESS_VM_WRITEV
            | m68k::SETNS
            | m68k::FANOTIFY_INIT
            | m68k::FANOTIFY_MARK
            | m68k::NAME_TO_HANDLE_AT
            | m68k::OPEN_BY_HANDLE_AT
            | m68k::BPF
            | m68k::USERFAULTFD
            | m68k::PERF_EVENT_OPEN
            | m68k::IO_SETUP
            | m68k::IO_DESTROY
            | m68k::IO_GETEVENTS
            | m68k::IO_SUBMIT
            | m68k::IO_CANCEL
            | m68k::IO_URING_SETUP
            | m68k::IO_PGETEVENTS_TIME64
            | m68k::MEMBARRIER
            | m68k::RSEQ
            | m68k::COPY_FILE_RANGE
            | m68k::SPLICE
            | m68k::TEE
            | m68k::VMSPLICE
            | m68k::PKEY_MPROTECT
            | m68k::PKEY_ALLOC
            | m68k::PKEY_FREE
            | m68k::MEMFD_CREATE
            | m68k::FINIT_MODULE
            | m68k::SCHED_SETATTR
            | m68k::SCHED_GETATTR
            | m68k::RENAMEAT2
            | m68k::SENDMMSG
            | m68k::RECVMMSG
            | m68k::RECVMMSG_TIME64
            | m68k::SEMTIMEDOP_TIME64 => fail_ret(E::ENOSYS),
            // ---- ソケット・イベント ----
            m68k::SOCKET
            | m68k::BIND
            | m68k::CONNECT
            | m68k::LISTEN
            | m68k::GETSOCKNAME
            | m68k::GETPEERNAME
            | m68k::SOCKETPAIR
            | m68k::SENDTO
            | m68k::RECVFROM
            | m68k::SHUTDOWN
            | m68k::SETSOCKOPT
            | m68k::GETSOCKOPT
            | m68k::SENDMSG
            | m68k::RECVMSG
            | m68k::ACCEPT4 => fail_ret(E::ENOSYS),
            m68k::SEMGET
            | m68k::SEMCTL
            | m68k::MSGSND
            | m68k::MSGRCV
            | m68k::MSGGET
            | m68k::MSGCTL
            | m68k::SHMAT
            | m68k::SHMDT
            | m68k::SHMGET
            | m68k::SHMCTL => fail_ret(E::ENOSYS),
            m68k::INOTIFY_INIT
            | m68k::INOTIFY_ADD_WATCH
            | m68k::INOTIFY_RM_WATCH
            | m68k::INOTIFY_INIT1
            | m68k::EPOLL_CREATE
            | m68k::EPOLL_CTL
            | m68k::EPOLL_WAIT
            | m68k::EPOLL_CREATE1
            | m68k::EPOLL_PWAIT
            | m68k::TIMERFD_CREATE
            | m68k::TIMERFD_SETTIME
            | m68k::TIMERFD_GETTIME
            | m68k::TIMERFD_SETTIME64
            | m68k::TIMERFD_GETTIME64
            | m68k::EVENTFD
            | m68k::EVENTFD2
            | m68k::TIMER_CREATE
            | m68k::TIMER_SETTIME
            | m68k::TIMER_GETTIME
            | m68k::TIMER_GETOVERRUN
            | m68k::TIMER_DELETE
            | m68k::TIMER_SETTIME64
            | m68k::TIMER_GETTIME64
            | m68k::MQ_OPEN
            | m68k::MQ_UNLINK
            | m68k::MQ_TIMEDSEND
            | m68k::MQ_TIMEDRECEIVE
            | m68k::MQ_NOTIFY
            | m68k::MQ_GETSETATTR
            | m68k::MQ_TIMEDSEND_TIME64
            | m68k::MQ_TIMEDRECEIVE_TIME64
            | m68k::RT_SIGTIMEDWAIT_TIME64 => fail_ret(E::ENOSYS),
            // ---- 同期・その他成功系 ----
            m68k::SYNC | m68k::FDATASYNC | m68k::SYNCFS | m68k::FLOCK => ok_ret(0),
            m68k::GETRANDOM => Disp::Ret(self.do_getrandom(env, args[0], args[1])),
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
