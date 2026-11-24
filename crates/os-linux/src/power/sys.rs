// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Power（ppc64）Linux の syscall 処理。ppc64 の単一 ABI。
//!
//! r0 が番号、r3–r8 が引数、r3 が戻り値。エラーは CR0.SO（CR の
//! IBM bit3 = 0x1000_0000）を立てて r3 に正の errno を返す
//! （SPEC-POWER-ABI）。errno は汎用値。
//!
//! 試作の合意事項は aarch64 と同じ: ホストのファイルに直接触る。
//! 信頼できないゲストバイナリには使わないこと。
//! fork/clone/execve/パイプは未対応（ENOSYS）。
// Ref: SRC-LINUX (7.3), SPEC-POWER-ABI (ELFv2 r1.5).

use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

use polyisa_engine::bare::BareEnv;
use polyisa_guest_power::sem::{Gpr, cr_ref};
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};
use polyisa_sem::Backend as _;

use crate::{TrapHandler, TrapOutcome, power, power::errno};

/// CR0.SO（CR の IBM bit3）。
const CR0_SO: u64 = 0x1000_0000;

/// 標準入出力の capture。テストが読む。
#[derive(Default)]
pub struct PowerIo {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// ppc64 Linux の syscall 状態機械。
pub struct Linux {
    endian: Endian,
    /// 標準入出力の capture。テストが読む。
    pub io: PowerIo,
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
    /// ゲストのルート。空は隔離なし（従来動作）。
    guest_root: String,
    /// ゲストの実行ファイルのホストパス。/proc/self/exe の readlink 用。
    pub exe_path: String,
    /// 報告済みの未実装番号（一度だけ出す）。
    reported: Vec<u64>,
    /// 標準入力へ供給するバイト。
    pub stdin_buf: Vec<u8>,
    stdin_pos: usize,
    /// ディレクトリ fd の getdents 位置（次に出すエントリの添字）。
    dir_pos: std::collections::BTreeMap<u32, u64>,
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

/// 引数 i（0–5）は r3–r8。
fn arg(env: &mut BareEnv, i: u8) -> u64 {
    reg(env, i + 3)
}

/// dispatch の戻りを作る。`v` は r3 にそのまま書く値（負 errno も含む）。
fn ret(v: u64) -> Disp {
    Disp::Ret(v)
}

enum Disp {
    /// r3 に書く値（負値は errno の符号反転として扱う）。
    Ret(u64),
    Exit(u32),
    /// 未実装。ENOSYS を返して続ける。
    Unimpl,
}

impl Linux {
    /// ELF の `EI_DATA` に合わせてデータエンディアンを切り替える。
    pub fn set_endian(&mut self, endian: Endian) {
        self.endian = endian;
    }

    /// リトルエンディアンの Linux 状態機械を作る。
    #[must_use]
    pub fn new(endian: Endian) -> Self {
        Self {
            endian,
            io: PowerIo::default(),
            fds: polyisa_kernel::FdTable::default(),
            heap_end: 0,
            mmap_next: 0x0000_7f00_0000_0000,
            umask: 0o22,
            pid: 0,
            cwd: String::new(),
            guest_root: String::new(),
            exe_path: String::new(),
            reported: Vec::new(),
            stdin_buf: Vec::new(),
            stdin_pos: 0,
            dir_pos: std::collections::BTreeMap::new(),
            mono_start: None,
        }
    }

    fn pid(&mut self) -> u64 {
        if self.pid == 0 {
            self.pid = 1;
        }
        self.pid
    }

    /// エラー。負 errno を戻り値とし、出口で CR0.SO と正値に写す。
    fn fail(errno: u32) -> u64 {
        (-(errno as i64)) as u64
    }

    /// ホスト errno を負で返す。
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

    /// ゲストのルートを設ける。ゲストの絶対パスをこのディレクトリ
    /// 配下に閉じ込める（polyisa 側の設計判断）。
    pub fn set_guest_root(&mut self, root: &str) {
        self.guest_root = root.to_string();
        if !root.is_empty() && self.cwd.is_empty() {
            self.cwd = "/".to_string();
        }
    }

    /// ゲストのパスをホストのパスへ（相対は cwd から、root 内に閉じ込める）。
    fn host_path(&self, guest: &[u8]) -> Option<String> {
        let path = String::from_utf8_lossy(guest).into_owned();
        crate::guest_path::resolve_guest_path(&self.guest_root, &self.cwd, &path)
    }

    /// リンクを辿る操作（open/stat/access 等）のためのホストパス。
    fn host_path_followed(&self, guest: &[u8]) -> Option<String> {
        let path = String::from_utf8_lossy(guest);
        crate::guest_path::resolve_guest_path_links(&self.guest_root, &self.cwd, &path)
    }

    /// ゲスト fd をホストの File として取る。
    fn file_of(&mut self, fd: u32) -> Result<&mut std::fs::File, u32> {
        self.fds.file_mut(fd).ok_or(errno::EBADF)
    }

    /// 読み用に fd を開いているものを返す。
    fn reader(&mut self, fd: u32) -> Result<ReadFd<'_>, u32> {
        match fd {
            0 => Ok(ReadFd::Stdin),
            1 | 2 => Err(errno::EBADF),
            _ => self.fds.file_mut(fd).map(ReadFd::File).ok_or(errno::EBADF),
        }
    }

    fn writer(&mut self, fd: u32) -> Result<WriteFd<'_>, u32> {
        match fd {
            0 => Err(errno::EBADF),
            1 => Ok(WriteFd::Stdout),
            2 => Ok(WriteFd::Stderr),
            _ => self.fds.file_mut(fd).map(WriteFd::File).ok_or(errno::EBADF),
        }
    }

    /// 汎用 `O_*` をホストの `OpenOptions` 用フラグへ写す。
    fn open_flags(guest: u64) -> std::fs::OpenOptions {
        use power::oflag::*;
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

    /// `open`/`openat` の実体。
    fn do_open(&mut self, env: &mut BareEnv, path_addr: u64, flags: u64, _mode: u64) -> u64 {
        let path = match self.read_cstr(env, path_addr) {
            Ok(p) => p,
            Err(e) => return Self::fail(e),
        };
        let Some(host) = self.host_path_followed(&path) else {
            return Self::fail(errno::EPERM);
        };
        let oo = Self::open_flags(flags);
        match oo.open(&host) {
            Ok(f) => {
                let fd = self.fds.alloc(polyisa_kernel::FdTarget::File(f));
                self.fds.remember_path(fd, host);
                u64::from(fd)
            }
            Err(e) => Self::fail_host(e.raw_os_error().unwrap_or(errno::EIO as i32)),
        }
    }

    /// ホストのメタデータを ppc64 の `struct stat`（144 バイト）に写す。
    /// u64 dev, u64 ino, u64 nlink, u32 mode, u32 uid, u32 gid, u32 pad,
    /// u64 rdev, i64 size, u64 blksize, u64 blocks,
    /// u64 atime/nsec/mtime/nsec/ctime/nsec, u64 unused[3]。
    /// Ref: SRC-LINUX (7.3) `arch/powerpc/include/uapi/asm/stat.h`。
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
        let mut b = [0u8; 144];
        let mut p = |off: usize, bytes: &[u8]| b[off..off + bytes.len()].copy_from_slice(bytes);
        p(0, &w64(md.dev));
        p(8, &w64(md.ino));
        p(16, &w64(md.nlink));
        p(24, &w32(u64::from(md.mode)));
        p(28, &w32(u64::from(md.uid)));
        p(32, &w32(u64::from(md.gid)));
        p(40, &w64(md.rdev));
        p(48, &w64(md.size));
        p(56, &w64(md.blksize));
        p(64, &w64(md.blocks));
        p(72, &w64(md.atime as u64));
        p(80, &w64(md.atime_nsec as u64));
        p(88, &w64(md.mtime as u64));
        p(96, &w64(md.mtime_nsec as u64));
        p(104, &w64(md.ctime as u64));
        p(112, &w64(md.ctime_nsec as u64));
        env.backend.mem.write(VirtAddr(addr), &b).is_ok()
    }

    /// `struct statx`（256 バイト、汎用レイアウト）。
    fn do_statx(&mut self, env: &mut BareEnv, path_addr: u64, out: u64) -> u64 {
        let path = match self.read_cstr(env, path_addr) {
            Ok(p) => p,
            Err(e) => return Self::fail(e),
        };
        let Some(host) = self.host_path_followed(&path) else {
            return Self::fail(errno::EPERM);
        };
        let md = match polyisa_host::stat(&host) {
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
        // Ref: SRC-LINUX — struct statx（include/uapi/linux/stat.h）。
        b[28..30].copy_from_slice(&w32(u32::from(md.mode as u16))[0..2]);
        b[32..40].copy_from_slice(&w64(md.ino));
        b[40..48].copy_from_slice(&w64(md.size));
        b[48..56].copy_from_slice(&w64(md.blocks));
        b[56..64].copy_from_slice(&w64(0x1fff)); // attributes_mask
        b[64..72].copy_from_slice(&w64(md.atime as u64));
        b[72..76].copy_from_slice(&w32(md.atime_nsec as u32));
        b[96..104].copy_from_slice(&w64(md.ctime as u64));
        b[104..108].copy_from_slice(&w32(md.ctime_nsec as u32));
        b[112..120].copy_from_slice(&w64(md.mtime as u64));
        b[120..124].copy_from_slice(&w32(md.mtime_nsec as u32));
        // dev_t の major/minor 分解（UAPI の makedev エンコード）。
        let major = |d: u64| ((d >> 8) as u32 & 0xfff) | ((d >> 32) as u32 & !0xfff);
        let minor = |d: u64| (d as u32 & 0xff) | ((d >> 12) as u32 & !0xff);
        b[128..132].copy_from_slice(&w32(major(md.rdev)));
        b[132..136].copy_from_slice(&w32(minor(md.rdev)));
        b[136..140].copy_from_slice(&w32(major(md.dev)));
        b[140..144].copy_from_slice(&w32(minor(md.dev)));
        match self.write_bytes(env, out, &b) {
            Ok(()) => 0,
            Err(e) => Self::fail(e),
        }
    }

    /// stat/lstat/fstat/newfstatat 共通の解決。
    fn do_stat(&mut self, env: &mut BareEnv, fd: Option<u32>, path_addr: u64, out: u64) -> u64 {
        let md = if let Some(fd) = fd {
            match fd {
                0..=2 => match polyisa_host::stat(&format!("/proc/self/fd/{fd}")) {
                    Ok(m) => m,
                    Err(e) => {
                        return Self::fail_host(e.raw_os_error().unwrap_or(errno::EIO as i32));
                    }
                },
                _ => match self.fds.file(fd) {
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
            let Some(host) = self.host_path_followed(&path) else {
                return Self::fail(errno::EPERM);
            };
            match polyisa_host::stat(&host) {
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

    /// `mmap`。匿名はゼロ埋め、ファイル裏付けは `fd` の `off` から写す。
    /// MAP_SHARED の書き戻しは未実装（プライベート写像として扱う）。
    #[allow(clippy::too_many_arguments)]
    fn do_mmap(
        &mut self,
        env: &mut BareEnv,
        addr: u64,
        len: u64,
        prot: u64,
        flags: u64,
        fd: u32,
        off: u64,
    ) -> u64 {
        let len = len.max(1);
        let pages = len.div_ceil(polyisa_mem::PAGE_SIZE);
        let base = if flags & power::mflag::FIXED != 0 && addr != 0 {
            env.backend.mem.unmap(VirtAddr(addr), pages);
            addr
        } else {
            let Some(b) = self.find_free_run(env, pages) else {
                return Self::fail(errno::ENOMEM);
            };
            self.mmap_next = b + pages * polyisa_mem::PAGE_SIZE;
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
        let data = if flags & power::mflag::ANONYMOUS == 0 {
            let need = usize::try_from(len).unwrap_or(usize::MAX);
            let mut data = vec![0u8; need];
            match self.file_of(fd) {
                Ok(f) => {
                    use std::io::{Read, Seek, SeekFrom};
                    if f.seek(SeekFrom::Start(off)).is_err() {
                        return Self::fail(errno::EIO);
                    }
                    let mut filled = 0;
                    while filled < data.len() {
                        match f.read(&mut data[filled..]) {
                            Ok(0) => break,
                            Ok(n) => filled += n,
                            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                            Err(_) => return Self::fail(errno::EIO),
                        }
                    }
                    data.truncate(filled);
                }
                Err(e) => return Self::fail(e),
            }
            Some(data)
        } else {
            None
        };
        if env
            .backend
            .mem
            .map(VirtAddr(base), pages, Perms(Perms::R.0 | Perms::W.0))
            .is_err()
        {
            return Self::fail(errno::ENOMEM);
        }
        if let Some(data) = data
            && env.backend.mem.write(VirtAddr(base), &data).is_err()
        {
            return Self::fail(errno::EFAULT);
        }
        if p != (Perms::R.0 | Perms::W.0)
            && env
                .backend
                .mem
                .protect(VirtAddr(base), pages, Perms(p))
                .is_err()
        {
            return Self::fail(errno::ENOMEM);
        }
        base
    }

    /// `mmap_next` から上方に `pages` 連続の未写像区間を探す。
    fn find_free_run(&self, env: &BareEnv, pages: u64) -> Option<u64> {
        use polyisa_mem::PageNo;
        let mut base = self.mmap_next;
        for _ in 0..(1 << 22) {
            let mut ok = true;
            for i in 0..pages {
                let no = (base / polyisa_mem::PAGE_SIZE).checked_add(i)?;
                if env.backend.mem.is_mapped(PageNo(no)) {
                    base = (no + 1) * polyisa_mem::PAGE_SIZE;
                    ok = false;
                    break;
                }
            }
            if ok {
                return Some(base);
            }
        }
        None
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
        // 旧ブレークを含む部分ページは既に写像・使用済みなので、
        // その次のページからだけを新規に確保する（再写像で bss を
        // ゼロ化しないため）。arm の実装と同じ規則。
        let lo = self.heap_end.div_ceil(polyisa_mem::PAGE_SIZE) * polyisa_mem::PAGE_SIZE;
        let hi = addr.div_ceil(polyisa_mem::PAGE_SIZE) * polyisa_mem::PAGE_SIZE;
        if hi > lo
            && env
                .backend
                .mem
                .map(VirtAddr(lo), (hi - lo) / polyisa_mem::PAGE_SIZE, Perms::RW)
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
            b"ppc64le",
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
        // Ref: SRC-LINUX — struct sysinfo の 64bit レイアウト。
        b[64..72].copy_from_slice(&w64(1 << 30)); // totalswap
        b[72..80].copy_from_slice(&w64(1 << 29)); // freeswap
        b[80..82].copy_from_slice(&w32(1)[0..2]); // procs
        b[104..108].copy_from_slice(&w32(1)); // mem_unit
        match self.write_bytes(env, addr, &b) {
            Ok(()) => 0,
            Err(e) => Self::fail(e),
        }
    }

    /// `statfs`/`statfs64`/`fstatfs`/`fstatfs64`（120 バイト）。最小の埋め方。
    fn do_statfs(&mut self, env: &mut BareEnv, addr: u64) -> u64 {
        let mut b = [0u8; 120];
        let w64 = |v: u64| match self.endian {
            Endian::Be => v.to_be_bytes(),
            Endian::Le => v.to_le_bytes(),
        };
        b[0..8].copy_from_slice(&w64(0xEF53));
        b[8..16].copy_from_slice(&w64(4096));
        b[16..24].copy_from_slice(&w64(1 << 20));
        b[24..32].copy_from_slice(&w64(1 << 19));
        b[32..40].copy_from_slice(&w64(1 << 19));
        b[64..72].copy_from_slice(&w64(255));
        b[72..80].copy_from_slice(&w64(4096));
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
        let mut i = usize::try_from(self.dir_pos.get(&fd).copied().unwrap_or(0)).unwrap_or(0);
        for (ino, name, t) in all.iter().skip(i) {
            let reclen = 19 + name.len() + 1;
            let aligned = reclen.next_multiple_of(8);
            if out.len() + aligned > count {
                break;
            }
            let next = (i + 1) as u64;
            out.extend_from_slice(&w64(*ino));
            out.extend_from_slice(&w64(next));
            out.extend_from_slice(&w16(aligned as u16));
            out.push(*t);
            out.extend_from_slice(name.as_bytes());
            out.push(0);
            out.resize(out.len() + (aligned - reclen), 0);
            i += 1;
        }
        self.dir_pos.insert(fd, i as u64);
        match self.write_bytes(env, buf, &out) {
            Ok(()) => out.len() as u64,
            Err(e) => Self::fail(e),
        }
    }

    /// `readlink`/`readlinkat`。/proc/self/exe はゲストの exe_path へ。
    fn do_readlink(&mut self, env: &mut BareEnv, path_addr: u64, buf: u64, len: u64) -> u64 {
        let path = match self.read_cstr(env, path_addr) {
            Ok(p) => p,
            Err(e) => return Self::fail(e),
        };
        let Some(host) = self.host_path(&path) else {
            return Self::fail(errno::EPERM);
        };
        let guest = String::from_utf8_lossy(&path).into_owned();
        let target = if guest == "/proc/self/exe" {
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
            Err(e) => {
                // ファイル以外の対象（eventfd・timerfd 等）は fd 表経由。
                if e == errno::EBADF && self.fds.target(fd).is_some() {
                    let abi = crate::wait::WaitAbi::generic(8, 8, self.endian);
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
                        Ok(v) => v,
                        Err(e) => Self::fail((abi.errno)(e)),
                    };
                }
                return Self::fail(e);
            }
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
            Err(e) => {
                // ファイル以外の対象（eventfd 等）は fd 表経由。
                if e == errno::EBADF && self.fds.target(fd).is_some() {
                    let abi = crate::wait::WaitAbi::generic(8, 8, self.endian);
                    let t0 = std::time::Instant::now();
                    let mono = move || t0.elapsed().as_nanos() as u64;
                    return match crate::wait::write_other(
                        &mut self.fds,
                        &abi,
                        env,
                        fd,
                        buf,
                        len,
                        0,
                        &mono,
                    ) {
                        Ok(v) => v,
                        Err(e) => Self::fail((abi.errno)(e)),
                    };
                }
                return Self::fail(e);
            }
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
        if self.dir_pos.contains_key(&fd) {
            match whence {
                0 => {
                    self.dir_pos.insert(fd, off.max(0) as u64);
                    return off.max(0) as u64;
                }
                1 => {
                    let p = self.dir_pos.get(&fd).copied().unwrap_or(0);
                    let n = p.saturating_add_signed(off);
                    self.dir_pos.insert(fd, n);
                    return n;
                }
                _ => return Self::fail(errno::EINVAL),
            }
        }
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
        use power::ioc::*;
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

    /// `fcntl`/`fcntl64`。FD フラグだけ。
    fn do_fcntl(&mut self, _env: &mut BareEnv, _fd: u32, cmd: u32, _arg: u64) -> u64 {
        match cmd {
            1 => 0, // F_GETFD
            2 => 0, // F_SETFD
            3 => 0, // F_GETFL
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
            .file(old)
            .and_then(|f| f.try_clone().ok())
            .ok_or(errno::EBADF)?;
        self.fds.place_close(new, polyisa_kernel::FdTarget::File(f));
        Ok(())
    }

    /// dirfd + パス一つを取る系。
    fn path1_at(&mut self, env: &mut BareEnv, name: &str, idx: usize) -> Disp {
        let path_addr = arg(env, idx as u8);
        let path = match self.read_cstr(env, path_addr) {
            Ok(p) => p,
            Err(e) => return Self::fail_ret(e),
        };
        let host = if matches!(
            name,
            "access" | "faccessat" | "faccessat2" | "fchmodat" | "stat" | "lstat"
        ) {
            self.host_path_followed(&path)
        } else {
            self.host_path(&path)
        };
        let Some(host) = host else {
            return Self::fail_ret(errno::EPERM);
        };
        match name {
            "unlink" | "unlinkat" => {
                let flags = if name == "unlinkat" { arg(env, 2) } else { 0 };
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
            "rmdir" => match std::fs::remove_dir(&host) {
                Ok(()) => ret(0),
                Err(e) => Self::fail_ret_host(e),
            },
            "access" | "faccessat" | "faccessat2" => {
                // mode は access=arg1、faccessat*=arg2。
                let mode = arg(env, if name == "access" { 1 } else { 2 });
                let st = polyisa_host::stat(&host);
                // ゲストは uid=0 として動く（getuid 系は 0 を返す）。
                // root の access: R/W は存在すれば可、X は exec ビットが
                // どれか一つあれば可（カーネルの規約）。
                let ok = match st {
                    Err(_) => false,
                    Ok(md) => {
                        let need = mode as u32 & 7; // R_OK=4 W_OK=2 X_OK=1
                        need & 1 == 0 || md.mode & 0o111 != 0
                    }
                };
                ret(if ok { 0 } else { Self::fail(errno::EACCES) })
            }
            "fchmodat" => ret(0),
            _ => Self::fail_ret(errno::ENOSYS),
        }
    }

    /// パス二つを取る系（link/rename/symlink 系）。
    fn path2_at(&mut self, env: &mut BareEnv, name: &str) -> Disp {
        // *at 形は dirfd,old,newdirfd,new なので old=idx1,new=idx3。
        // 単パス形は old=idx0,new=idx1。
        let (a_idx, b_idx) = if name.ends_with("at") {
            (1u8, 3u8)
        } else {
            (0, 1)
        };
        let a_addr = arg(env, a_idx);
        let pa = match self.read_cstr(env, a_addr) {
            Ok(p) => p,
            Err(e) => return Self::fail_ret(e),
        };
        let b_addr = arg(env, b_idx);
        let pb = match self.read_cstr(env, b_addr) {
            Ok(p) => p,
            Err(e) => return Self::fail_ret(e),
        };
        let (Some(ha), Some(hb)) = (self.host_path(&pa), self.host_path(&pb)) else {
            return Self::fail_ret(errno::EPERM);
        };
        let r = match name {
            "link" | "linkat" => std::fs::hard_link(&ha, &hb),
            "rename" | "renameat" | "renameat2" => std::fs::rename(&ha, &hb),
            "symlink" | "symlinkat" => polyisa_host::symlink(&String::from_utf8_lossy(&pa), &hb),
            _ => return Self::fail_ret(errno::ENOSYS),
        };
        match r {
            Ok(()) => ret(0),
            Err(e) => Self::fail_ret_host(e),
        }
    }

    /// ソケット系 syscall を `sock` 正準層へ委譲する（socketcall
    /// 副番号の展開を含む）。待ち要求は単一スレッド消化で進め、
    /// 進行不能はデッドロックとして報告。
    fn sock_call(&mut self, env: &mut BareEnv, name: &str, args: &[u64; 6]) -> Disp {
        let abi = crate::sock::SockAbi::generic(8, self.endian);
        let map = crate::sock::unix_path_map(&self.guest_root, &self.cwd);
        let t0 = std::time::Instant::now();
        let mono = move || t0.elapsed().as_nanos() as u64;
        match crate::sock::drive(&mut self.fds, &abi, env, name, args, &map, 0, &mono) {
            Some(Ok(v)) => ret(v),
            Some(Err(e)) => {
                if e == crate::sock::errno::EDEADLK {
                    eprintln!("power: deadlock in fd wait");
                }
                Self::fail_ret((abi.errno)(e))
            }
            None => Self::fail_ret(errno::ENOSYS),
        }
    }

    /// 待ち合わせ系 syscall を `wait` 正準層へ委譲する。
    fn wait_call(&mut self, env: &mut BareEnv, name: &str, args: &[u64; 6]) -> Disp {
        let abi = crate::wait::WaitAbi::generic(8, 8, self.endian);
        let t0 = std::time::Instant::now();
        let mono = move || t0.elapsed().as_nanos() as u64;
        match crate::wait::drive(&mut self.fds, &abi, env, name, args, 0, &mono) {
            Some(Ok(v)) => ret(v),
            Some(Err(e)) => {
                if e == crate::sock::errno::EDEADLK {
                    eprintln!("power: deadlock in fd wait");
                }
                Self::fail_ret((abi.errno)(e))
            }
            None => Self::fail_ret(errno::ENOSYS),
        }
    }

    /// メインの振り分け。戻りは `Disp`。
    fn dispatch(&mut self, env: &mut BareEnv, name: Option<&'static str>) -> Disp {
        let args: [u64; 6] = std::array::from_fn(|i| arg(env, i as u8));
        let Some(name) = name else {
            return Disp::Unimpl;
        };
        if crate::sock::NAMES.contains(&name) {
            return self.sock_call(env, name, &args);
        }
        if crate::wait::NAMES.contains(&name) {
            return self.wait_call(env, name, &args);
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
            "open" => ret(self.do_open(env, args[0], args[1], args[2])),
            "openat" => {
                let dirfd = args[0] as u32;
                if dirfd as i32 != -100 {
                    return Self::fail_ret(errno::EBADF);
                }
                ret(self.do_open(env, args[1], args[2], args[3]))
            }
            "creat" => ret(self.do_open(env, args[0], 0o101 | 0o100, args[1])),
            "close" => {
                let fd = args[0] as u32;
                if fd < 3 {
                    return ret(0);
                }
                if self.fds.ent(fd).is_some() {
                    self.fds.clear(fd);
                    self.fds.forget_path(fd);
                    self.dir_pos.remove(&fd);
                    ret(0)
                } else {
                    Self::fail_ret(errno::EBADF)
                }
            }
            "fstat" => {
                let fd = args[0] as u32;
                ret(self.do_stat(env, Some(fd), 0, args[1]))
            }
            "stat" | "lstat" => ret(self.do_stat(env, None, args[0], args[1])),
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
            "poll" | "ppoll" | "pselect6" | "select" | "newselect" | "epoll_create"
            | "epoll_create1" | "epoll_ctl" | "epoll_wait" | "epoll_pwait" => ret(0),
            "lseek" => {
                let fd = args[0] as u32;
                let off = args[1] as i64;
                let wh = args[2] as u32;
                ret(self.do_lseek(env, fd, off, wh))
            }
            "mmap" => ret(self.do_mmap(
                env,
                args[0],
                args[1],
                args[2],
                args[3],
                args[4] as u32,
                args[5],
            )),
            "munmap" => {
                let addr = args[0];
                let len = args[1].max(1);
                env.backend
                    .mem
                    .unmap(VirtAddr(addr), len.div_ceil(polyisa_mem::PAGE_SIZE));
                ret(0)
            }
            "mprotect" | "msync" | "mincore" | "madvise" | "mlock" | "munlock" | "mlockall"
            | "munlockall" | "mlock2" | "sync_file_range" | "fadvise64" | "readahead" => ret(0),
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
            "rt_sigreturn" | "rt_sigsuspend" | "rt_sigtimedwait" | "rt_sigqueueinfo"
            | "getitimer" | "setitimer" | "futex" | "restart_syscall" => {
                Self::fail_ret(errno::ENOSYS)
            }
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
            "getpid" | "gettid" | "getppid" | "getpgid" | "getpgrp" | "getsid" | "setpgid"
            | "setsid" => ret(self.pid()),
            "fork" | "vfork" | "clone" | "execve" | "waitpid" | "wait4" | "waitid" | "pipe"
            | "pipe2" | "sendfile" | "rseq" => Self::fail_ret(errno::ENOSYS),
            "kill" | "tkill" | "tgkill" => ret(0),
            "uname" => ret(self.do_uname(env, args[0])),
            "fcntl" | "fcntl64" => {
                let fd = args[0] as u32;
                ret(self.do_fcntl(env, fd, args[1] as u32, args[2]))
            }
            "flock" | "fsync" | "fdatasync" | "sync" => {
                if name != "sync"
                    && let Some(f) = self.fds.file(args[0] as u32)
                {
                    let _ = f.sync_all();
                }
                ret(0)
            }
            "truncate" | "ftruncate" | "truncate64" | "ftruncate64" => {
                if name.starts_with('f') {
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
                    let Some(host) = self.host_path_followed(&path) else {
                        return Self::fail_ret(errno::EPERM);
                    };
                    match std::fs::OpenOptions::new()
                        .write(true)
                        .open(host)
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
            "getdents" => Self::fail_ret(errno::ENOSYS),
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
            "chdir" | "fchdir" => {
                if name == "fchdir" {
                    return ret(0);
                }
                let path = match self.read_cstr(env, args[0]) {
                    Ok(p) => p,
                    Err(e) => return Self::fail_ret(e),
                };
                let Some(host) = self.host_path_followed(&path) else {
                    return Self::fail_ret(errno::EPERM);
                };
                if polyisa_host::stat(&host)
                    .map(|m| m.mode & 0o170000 == 0o040000)
                    .unwrap_or(false)
                {
                    self.cwd = crate::guest_path::join_guest_path(
                        &self.cwd,
                        &String::from_utf8_lossy(&path),
                    );
                    ret(0)
                } else {
                    Self::fail_ret(errno::ENOENT)
                }
            }
            "unlink" | "rmdir" | "unlinkat" | "access" | "faccessat" | "faccessat2"
            | "fchmodat" => self.path1_at(
                env,
                name,
                if name == "unlink" || name == "rmdir" || name == "access" {
                    0
                } else {
                    1
                },
            ),
            "mkdir" | "mkdirat" => {
                let idx = if name == "mkdir" { 0 } else { 1 };
                let path = match self.read_cstr(env, args[idx]) {
                    Ok(p) => p,
                    Err(e) => return Self::fail_ret(e),
                };
                let Some(host) = self.host_path(&path) else {
                    return Self::fail_ret(errno::EPERM);
                };
                match std::fs::create_dir(host) {
                    Ok(()) => ret(0),
                    Err(e) => Self::fail_ret_host(e),
                }
            }
            "mknod" | "mknodat" => Self::fail_ret(errno::ENOSYS),
            "link" | "rename" | "symlink" | "renameat" | "renameat2" | "linkat" | "symlinkat" => {
                self.path2_at(env, name)
            }
            "chmod" | "fchmod" | "chown" | "lchown" | "fchown" | "fchownat" | "utime"
            | "futimensat" | "utimensat" | "setfsuid" | "setfsgid" | "setuid" | "setgid"
            | "setreuid" | "setregid" | "setresuid" | "setresgid" | "capget" | "capset"
            | "sethostname" | "setdomainname" | "settimeofday" | "acct" | "syslog" | "sysfs"
            | "quotactl" | "mount" | "umount2" | "chroot" | "pivot_root" | "swapon" | "swapoff"
            | "reboot" | "vhangup" | "adjtimex" | "personality" | "prctl" | "nice"
            | "setpriority" | "getpriority" | "alarm" | "pause" | "sched_setaffinity"
            | "inotify_init" | "inotify_init1" | "fallocate" | "fchownat2" => ret(0),
            "dup" => {
                let fd = args[0] as u32;
                match self
                    .fds
                    .file(fd)
                    .and_then(|f| f.try_clone().ok())
                    .map(|f| self.fds.alloc(polyisa_kernel::FdTarget::File(f)))
                {
                    Some(n) => ret(u64::from(n)),
                    None => Self::fail_ret(errno::EBADF),
                }
            }
            "dup2" | "dup3" => {
                let old = args[0] as u32;
                let new = args[1] as u32;
                match self.dup2_fd(old, new) {
                    Ok(()) => ret(u64::from(new)),
                    Err(e) => Self::fail_ret(e),
                }
            }
            "readlink" | "readlinkat" => {
                if name == "readlinkat" {
                    let dirfd = args[0] as u32;
                    if dirfd as i32 != -100 {
                        return Self::fail_ret(errno::EBADF);
                    }
                    ret(self.do_readlink(env, args[1], args[2], args[3]))
                } else {
                    ret(self.do_readlink(env, args[0], args[1], args[2]))
                }
            }
            "umask" => {
                let old = self.umask;
                self.umask = args[0] as u32 & 0o777;
                ret(u64::from(old))
            }
            "gettimeofday" | "times" | "getrusage" | "sysinfo" => {
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
            "time" => {
                let tp = args[0];
                let (sec, _) = Self::now();
                if tp != 0 && !self.put_u64(env, tp, sec) {
                    return Self::fail_ret(errno::EFAULT);
                }
                ret(sec)
            }
            "nanosleep" | "clock_nanosleep" => ret(0),
            "clock_gettime" | "clock_getres" | "clock_settime" => {
                if name == "clock_settime" {
                    return ret(0);
                }
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
            "getuid" | "geteuid" | "getgid" | "getegid" | "getgroups" | "setgroups"
            | "getresuid" | "getresgid" | "getpriority0" => ret(0),
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
            "getcpu" | "sched_getaffinity" => {
                if name == "sched_getaffinity" {
                    let set = args[2];
                    if set != 0 {
                        let _ = self.write_bytes(env, set, &[1u8]);
                    }
                } else {
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
            "statfs" | "fstatfs" => ret(self.do_statfs(env, args[1])),
            "statfs64" | "fstatfs64" => ret(self.do_statfs(env, args[2])),
            "ipc" | "sysctl" | "llseek" | "io_setup" | "io_destroy" | "io_getevents"
            | "io_submit" | "io_cancel" | "splice" | "tee" | "vmsplice" | "copy_file_range"
            | "perf_event_open" | "seccomp" | "memfd_create" | "signalfd" | "signalfd4"
            | "eventfd" | "eventfd2" | "timerfd_create" | "timerfd_settime" | "timerfd_gettime"
            | "init_module" | "delete_module" | "statfs0" => Self::fail_ret(errno::ENOSYS),
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
        let nr = reg(env, 0);
        let r = self.dispatch(env, power::name(nr));
        let cr = env.backend.get(cr_ref());
        match r {
            Disp::Ret(v) => {
                // 負の戻り値は errno。CR0.SO = 1 にして r3 に正値を返す。
                let (cr_new, ret) = if (v as i64) < 0 {
                    (cr | CR0_SO, (-(v as i64)) as u64)
                } else {
                    (cr & !CR0_SO, v)
                };
                env.backend.set(cr_ref(), cr_new);
                env.backend.set(Gpr(3).state(), ret);
                TrapOutcome::Handled
            }
            Disp::Exit(code) => TrapOutcome::Exit(code),
            Disp::Unimpl => {
                if !self.reported.contains(&nr) {
                    self.reported.push(nr);
                    let name = power::name(nr).unwrap_or("?");
                    eprintln!("power: unimplemented syscall {nr} ({name})");
                }
                env.backend.set(cr_ref(), cr | CR0_SO);
                env.backend.set(Gpr(3).state(), u64::from(errno::ENOSYS));
                TrapOutcome::Handled
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unimplemented_syscall_returns_enosys_via_cr0_so() {
        let mut sys = Linux::default();
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
        env.backend.set(Gpr(0).state(), 9999);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(env.backend.get(Gpr(3).state()), u64::from(errno::ENOSYS));
        assert_ne!(env.backend.get(cr_ref()) & CR0_SO, 0);
    }

    #[test]
    fn success_clears_cr0_so() {
        let mut sys = Linux::default();
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
        env.backend.set(cr_ref(), CR0_SO);
        env.backend.set(Gpr(0).state(), power::GETPID);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(env.backend.get(cr_ref()) & CR0_SO, 0);
        assert_ne!(env.backend.get(Gpr(3).state()), 0);
    }

    #[test]
    fn write_to_stdout_is_captured() {
        let mut sys = Linux::default();
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
        env.backend
            .mem
            .map(VirtAddr(0x10000), 1, Perms::RW)
            .unwrap();
        env.backend.mem.write(VirtAddr(0x10000), b"hi").unwrap();
        env.backend.set(Gpr(0).state(), power::WRITE);
        env.backend.set(Gpr(3).state(), 1);
        env.backend.set(Gpr(4).state(), 0x10000);
        env.backend.set(Gpr(5).state(), 2);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(sys.io.stdout, b"hi");
        assert_eq!(env.backend.get(Gpr(3).state()), 2);
        assert_eq!(env.backend.get(cr_ref()) & CR0_SO, 0);
    }
}
