// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 4.3BSD-Reno パーソナリティの実装。a.out の配置、初期スタック、
//! `chmk` のシステムコール機械、ファイル系・`break`/`sbrk`・`exit`。
//!
//! この裸モデルは VAX の仮想記憶を通さない —— ユーザの仮想
//! アドレスがそのまま物理メモリになる（VA=PA）。P0 空間
//! （0x0000_0000..0x3fff_ffff）に text/data/bss とヒープを置き、
//! P1 空間の上端近くにスタックを張る。
//!
//! 引数規約は `vax` モジュールの文書のとおり。
//! Ref: SPEC-BSD-43.
// Gap: GAP-0088 と同じ近似（単一プロセス・root 模型）を取る ——
// BSD 側の行は OS6 で別途立てる。

use std::collections::HashMap;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

use polyisa_engine::bare::BareEnv;
use polyisa_engine::run::{TrapHandler, TrapOutcome};
use polyisa_guest_vax::{psl, reg, sem};
use polyisa_loader::aout;
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};

use super::{NAMES, errno, sig};

/// スタックの上端（P1 空間側。USRSTACK の近似）。
const STACK_TOP: u32 = 0x7fff_0000;
/// 起きてから張るスタック量（512 KiB）。
const STACK_SZ: u32 = 0x8_0000;

/// P0 空間の上端。
const P0_TOP: u64 = 0x4000_0000;

/// fd の上限（getdtablesize の値と同じ）。
const NOFILE: u32 = 64;

/// `write` 系で捕まえた標準出力と標準エラー、標準入力の供給列。
#[derive(Default)]
pub struct BsdIo {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// 標準入力に返す列。`read(0)` はこれを `stdin_pos` から出す。
    pub stdin: Vec<u8>,
    /// `stdin` の消費済み先頭位置。
    pub stdin_pos: usize,
}

/// パイプの読み側（`kernel::PipeTable` の id）。
struct PipeEnd {
    id: u64,
    read: bool,
}

/// 4.3BSD-Reno（VAX）の syscall 状態機械。
pub struct Bsd {
    /// 標準入出力の capture。テストが読む。
    pub io: BsdIo,
    /// ゲスト fd 3 以降のホストファイル表。
    fds: polyisa_kernel::FdTable,
    /// ディレクトリ fd（開けた記録 —— 列挙は getdirentries 側。
    /// read は EISDIR）。
    dirs: HashMap<u32, String>,
    /// パイプ端の表。
    pipes: HashMap<u32, PipeEnd>,
    pipe_tab: polyisa_kernel::PipeTable,
    /// ゲストルートのホストパス。空はホストの `cwd` 起点。
    root: String,
    /// ゲストの作業ディレクトリ。
    cwd: String,
    /// プログラムブレーク（仮想アドレス）。
    brk: u32,
    /// データの先頭（brk の下限）。
    data_lo: u32,
    /// getpid が返す識別子。
    pid: u32,
    /// `umask` の現値。
    umask: u32,
    /// 一度だけ報告した未実装 syscall。
    reported: Vec<u32>,
}

impl Default for Bsd {
    fn default() -> Self {
        Self::new("")
    }
}

/// dispatch の戻り。
enum Disp {
    /// r0 に置く値（成功）。
    Ret(u32),
    /// r0・r1 に置く 2 語の値。
    Ret2(u32, u32),
    /// errno で失敗。
    Fail(u32),
    /// プロセス終了。
    Exit(u32),
}

impl Bsd {
    /// パーソナリティを作る。`root` はゲストパスを引くホスト側の
    /// ルート（空ならルート閉じ込めなし）。
    #[must_use]
    pub fn new(root: &str) -> Self {
        Self {
            io: BsdIo::default(),
            fds: polyisa_kernel::FdTable::default(),
            dirs: HashMap::new(),
            pipes: HashMap::new(),
            pipe_tab: polyisa_kernel::PipeTable::default(),
            root: root.to_string(),
            cwd: "/".to_string(),
            brk: 0,
            data_lo: 0,
            pid: 42,
            umask: 0o22,
            reported: Vec::new(),
        }
    }

    // ---- メモリアクセス（VA=PA） ----

    fn acc(kind: AccessKind) -> Access {
        Access {
            endian: Endian::Le,
            align: Align::Unaligned,
            kind,
        }
    }

    fn r32(env: &BareEnv, va: u64) -> Option<u32> {
        let mut b = [0u8; 4];
        env.backend
            .mem
            .read(VirtAddr(va), &mut b, Self::acc(AccessKind::DataRead))
            .ok()?;
        Some(u32::from_le_bytes(b))
    }

    fn w32(env: &mut BareEnv, va: u64, v: u32) -> bool {
        env.backend
            .mem
            .write(VirtAddr(va), &v.to_le_bytes())
            .is_ok()
    }

    fn w16(env: &mut BareEnv, va: u64, v: u16) -> bool {
        env.backend
            .mem
            .write(VirtAddr(va), &v.to_le_bytes())
            .is_ok()
    }

    /// `ap` 起点の第 `i` 引数（4(ap) から 32 ビットずつ）。
    fn ag(env: &BareEnv, ap: u32, i: u32) -> u32 {
        Self::r32(env, u64::from(ap) + 4 + 4 * u64::from(i)).unwrap_or(0)
    }

    /// ゲストの読み出し（呼び側は長さを制限済み）。
    fn read_bytes(&self, env: &BareEnv, va: u64, n: usize) -> Result<Vec<u8>, u32> {
        let mut v = vec![0u8; n.min(1 << 20)];
        env.backend
            .mem
            .read(VirtAddr(va), &mut v, Self::acc(AccessKind::DataRead))
            .map_err(|_| errno::EFAULT)?;
        Ok(v)
    }

    fn write_bytes(&self, env: &mut BareEnv, va: u64, data: &[u8]) -> Result<(), u32> {
        env.backend
            .mem
            .write(VirtAddr(va), data)
            .map_err(|_| errno::EFAULT)
    }

    /// NUL 終端の文字列を読む。
    fn read_cstr(&self, env: &BareEnv, va: u64) -> Result<String, u32> {
        let mut v = Vec::new();
        for i in 0..4096u64 {
            let mut b = [0u8];
            env.backend
                .mem
                .read(VirtAddr(va + i), &mut b, Self::acc(AccessKind::DataRead))
                .map_err(|_| errno::EFAULT)?;
            if b[0] == 0 {
                return String::from_utf8(v).map_err(|_| errno::EINVAL);
            }
            v.push(b[0]);
        }
        Err(errno::ENAMETOOLONG)
    }

    // ---- パス解決 ----

    /// ゲストパスをルート内に解決する（`..` はルートで飽和）。
    fn resolve(&self, g: &str) -> Option<String> {
        let abs = if g.starts_with('/') {
            g.to_string()
        } else {
            format!("{}/{}", self.cwd.trim_end_matches('/'), g)
        };
        let mut segs: Vec<&str> = Vec::new();
        for s in abs.split('/') {
            match s {
                "" | "." => {}
                ".." => {
                    segs.pop();
                }
                _ => segs.push(s),
            }
        }
        let joined = segs.join("/");
        Some(if self.root.is_empty() {
            format!("/{joined}")
        } else {
            format!("{}/{joined}", self.root.trim_end_matches('/'))
        })
    }

    /// ゲストパスをホスト側に解決する（`open` 系の入口）。
    fn host_path(&self, env: &BareEnv, addr: u64) -> Result<String, u32> {
        let g = self.read_cstr(env, addr)?;
        self.resolve(&g).ok_or(errno::EACCES)
    }

    // ---- fd ----

    /// 次に使える fd（最小の空き。stdio 0-2 は占有扱い）。
    fn alloc_fd(&mut self) -> Option<u32> {
        (3u32..NOFILE).find(|&fd| !self.fd_used(fd))
    }

    fn fd_used(&self, fd: u32) -> bool {
        self.fds.get(fd).is_some()
            || self.dirs.contains_key(&fd)
            || self.pipes.contains_key(&fd)
            || fd <= 2
    }

    // ---- BSD struct stat ----
    // 4.3BSD-Reno: dev(4) ino(4) mode(2) nlink(2) uid(2) gid(2)
    // rdev(4) size(4) atime(4) spare(4) mtime(4) spare(4)
    // ctime(4) spare(4) blksize(4) blocks(4) spare4(8) = 64 B。

    fn write_stat(&self, env: &mut BareEnv, md: &polyisa_host::Stat, buf: u64) -> Disp {
        let mut st = [0u8; 64];
        {
            let mut l = |off: usize, v: u32| st[off..off + 4].copy_from_slice(&v.to_le_bytes());
            l(0, md.dev.min(u64::from(u32::MAX)) as u32);
            l(4, md.ino.min(u64::from(u32::MAX)) as u32);
            l(16, md.rdev.min(u64::from(u32::MAX)) as u32);
            l(20, md.size.min(u64::from(u32::MAX)) as u32);
            l(24, md.atime.max(0) as u32);
            l(32, md.mtime.max(0) as u32);
            l(40, md.ctime.max(0) as u32);
            l(48, 1024); // st_blksize
            l(52, md.size.div_ceil(512).min(u64::from(u32::MAX)) as u32);
        }
        {
            let mut w = |off: usize, v: u16| st[off..off + 2].copy_from_slice(&v.to_le_bytes());
            w(8, (md.mode & 0xffff) as u16);
            w(10, md.nlink.min(0xffff) as u16);
            w(12, (md.uid & 0xffff) as u16);
            w(14, (md.gid & 0xffff) as u16);
        }
        match self.write_bytes(env, buf, &st) {
            Ok(()) => Disp::Ret(0),
            Err(e) => Disp::Fail(e),
        }
    }

    // ---- syscall 実体 ----
    // Gap: GAP-0089

    fn sys_read(&mut self, env: &mut BareEnv, fd: u32, buf: u32, n: u32) -> Disp {
        let n = usize::try_from(n).unwrap_or(0);
        if !self.fd_used(fd) {
            return Disp::Fail(errno::EBADF);
        }
        if self.dirs.contains_key(&fd) {
            return Disp::Fail(errno::EISDIR);
        }
        if let Some(p) = self.pipes.get(&fd) {
            if !p.read {
                return Disp::Fail(errno::EBADF);
            }
            let id = p.id;
            return match self.pipe_tab.read(id, n) {
                polyisa_kernel::PipeRead::Bytes(data) => {
                    let k = data.len();
                    if self.write_bytes(env, u64::from(buf), &data).is_err() {
                        Disp::Fail(errno::EFAULT)
                    } else {
                        Disp::Ret(k as u32)
                    }
                }
                // 単一プロセス近似: 書き手の残りなし = EOF と同じ 0。
                polyisa_kernel::PipeRead::Eof | polyisa_kernel::PipeRead::Empty => Disp::Ret(0),
            };
        }
        if let Some(f) = self.fds.get_mut(fd) {
            let mut tmp = vec![0u8; n.min(1 << 16)];
            return match f.read(&mut tmp) {
                Ok(got) => {
                    if self.write_bytes(env, u64::from(buf), &tmp[..got]).is_err() {
                        Disp::Fail(errno::EFAULT)
                    } else {
                        Disp::Ret(got as u32)
                    }
                }
                Err(e) => Disp::Fail(host_err(e.raw_os_error())),
            };
        }
        if fd != 0 {
            return Disp::Fail(errno::EBADF);
        }
        let rest = &self.io.stdin[self.io.stdin_pos.min(self.io.stdin.len())..];
        let got = rest.len().min(n);
        if self.write_bytes(env, u64::from(buf), &rest[..got]).is_err() {
            return Disp::Fail(errno::EFAULT);
        }
        self.io.stdin_pos += got;
        Disp::Ret(got as u32)
    }

    fn sys_write(&mut self, env: &mut BareEnv, fd: u32, buf: u32, n: u32) -> Disp {
        let n = usize::try_from(n).unwrap_or(0);
        if !self.fd_used(fd) {
            return Disp::Fail(errno::EBADF);
        }
        if self.dirs.contains_key(&fd) {
            return Disp::Fail(errno::EISDIR);
        }
        let data = match self.read_bytes(env, u64::from(buf), n) {
            Ok(d) => d,
            Err(e) => return Disp::Fail(e),
        };
        if let Some(p) = self.pipes.get(&fd) {
            if p.read {
                return Disp::Fail(errno::EBADF);
            }
            return match self.pipe_tab.write(p.id, &data) {
                Some(k) => Disp::Ret(k as u32),
                None => Disp::Fail(errno::EPIPE),
            };
        }
        if let Some(f) = self.fds.get_mut(fd) {
            return match f.write_all(&data) {
                Ok(()) => Disp::Ret(n as u32),
                Err(e) => Disp::Fail(host_err(e.raw_os_error())),
            };
        }
        match fd {
            1 => {
                self.io.stdout.extend_from_slice(&data);
                let _ = std::io::stdout().write_all(&data);
                Disp::Ret(n as u32)
            }
            2 => {
                self.io.stderr.extend_from_slice(&data);
                let _ = std::io::stderr().write_all(&data);
                Disp::Ret(n as u32)
            }
            _ => Disp::Fail(errno::EBADF),
        }
    }

    fn sys_open(&mut self, env: &mut BareEnv, a: &[u32], creat: bool) -> Disp {
        let path = match self.host_path(env, u64::from(a[0])) {
            Ok(p) => p,
            Err(e) => return Disp::Fail(e),
        };
        // BSD の open 旗: 0-2 がアクセスモード、O_NDELAY=4・
        // O_APPEND=010・O_CREAT=01000・O_TRUNC=02000・O_EXCL=04000。
        let flags = if creat { 0o1000 } else { a[1] };
        let Some(fd) = self.alloc_fd() else {
            return Disp::Fail(errno::EMFILE);
        };
        let existed = polyisa_host::stat(&path).is_ok();
        let mut o = std::fs::OpenOptions::new();
        match flags & 3 {
            0 => {
                o.read(true);
            }
            1 => {
                o.write(true);
            }
            _ => {
                o.read(true).write(true);
            }
        }
        if flags & 0o10 != 0 {
            o.append(true);
        }
        if creat || flags & 0o1000 != 0 {
            o.create(true);
            if flags & 0o2000 != 0 || creat {
                o.truncate(true);
            }
        }
        if std::fs::metadata(&path)
            .map(|m| m.is_dir())
            .unwrap_or(false)
        {
            // BSD でもディレクトリは open できる（read は EISDIR、
            // 列挙は getdirentries —— OS6）。
            if flags & 3 != 0 {
                return Disp::Fail(errno::EISDIR);
            }
            self.dirs.insert(fd, path);
            return Disp::Ret(fd);
        }
        match o.open(&path) {
            Ok(f) => {
                self.fds.place(fd, Some(f));
                if (creat || flags & 0o1000 != 0) && !existed {
                    let perm = a[2] & 0o777 & !self.umask;
                    let _ = polyisa_host::chmod(&path, perm);
                }
                Disp::Ret(fd)
            }
            Err(e) => Disp::Fail(host_err(e.raw_os_error())),
        }
    }

    fn sys_stat(&mut self, env: &mut BareEnv, a: &[u32], lstat: bool, fd_arg: bool) -> Disp {
        let md = if fd_arg {
            let fd = a[0];
            if !self.fd_used(fd) {
                return Disp::Fail(errno::EBADF);
            }
            if let Some(f) = self.fds.get(fd) {
                match polyisa_host::fstat(f) {
                    Ok(m) => m,
                    Err(_) => return Disp::Fail(errno::EIO),
                }
            } else if let Some(p) = self.dirs.get(&fd) {
                match polyisa_host::stat(p) {
                    Ok(m) => m,
                    Err(_) => return Disp::Fail(errno::EIO),
                }
            } else {
                match polyisa_host::stat("/dev/null") {
                    Ok(m) => m,
                    Err(_) => return Disp::Fail(errno::EBADF),
                }
            }
        } else {
            let path = match self.host_path(env, u64::from(a[0])) {
                Ok(p) => p,
                Err(e) => return Disp::Fail(e),
            };
            match if lstat {
                polyisa_host::lstat(&path)
            } else {
                polyisa_host::stat(&path)
            } {
                Ok(m) => m,
                Err(e) => return Disp::Fail(host_err(e.raw_os_error())),
            }
        };
        self.write_stat(env, &md, u64::from(a[1]))
    }

    /// `break`/`sbrk` 共通部。`abs` なら絶対の新ブレーク、
    /// さもなくば増分。戻りは `abs` で 0、増分で旧ブレーク。
    fn sys_brk(&mut self, env: &mut BareEnv, v: u32, abs: bool) -> Disp {
        let old = self.brk;
        let new = if abs { v } else { self.brk.wrapping_add(v) }.max(self.data_lo);
        if u64::from(new) >= u64::from(STACK_TOP - STACK_SZ) {
            return Disp::Fail(errno::ENOMEM);
        }
        let hi = (u64::from(new) + polyisa_mem::PAGE_SIZE - 1) & !(polyisa_mem::PAGE_SIZE - 1);
        let cur = (u64::from(old) + polyisa_mem::PAGE_SIZE - 1) & !(polyisa_mem::PAGE_SIZE - 1);
        if hi > cur {
            let pages = (hi - cur) / polyisa_mem::PAGE_SIZE;
            let perms = Perms(Perms::R.0 | Perms::W.0);
            if env.backend.mem.map(VirtAddr(cur), pages, perms).is_err() {
                return Disp::Fail(errno::ENOMEM);
            }
        }
        self.brk = new;
        Disp::Ret(if abs { 0 } else { old })
    }

    /// sig（シグナル配送なしモデル）での終了。
    fn die(s: u8) -> Disp {
        Disp::Exit(u32::from(s) | sig::CORE)
    }

    /// `fd` の実体を `nf` に複写する（dup/dup2/F_DUPFD の共有部）。
    fn sys_dup_place(&mut self, fd: u32, nf: u32) -> Disp {
        if let Some(p) = self.pipes.get(&fd) {
            let (id, read) = (p.id, p.read);
            self.pipe_tab.dup(id, read);
            self.pipes.insert(nf, PipeEnd { id, read });
            return Disp::Ret(nf);
        }
        if let Some(p) = self.dirs.get(&fd) {
            let p = p.clone();
            self.dirs.insert(nf, p);
            return Disp::Ret(nf);
        }
        if let Some(f) = self.fds.get_mut(fd) {
            return match f.try_clone() {
                Ok(n) => {
                    self.fds.place(nf, Some(n));
                    Disp::Ret(nf)
                }
                Err(e) => Disp::Fail(host_err(e.raw_os_error())),
            };
        }
        // stdio の複写は未対応（dup'd stdio への実体結び付けが
        // ない —— 要るときになったら V7 式の alias を持つ）。
        Disp::Fail(errno::EBADF)
    }

    /// execve(name, argv, envp)。成功したら戻らない —— 空間を
    /// 組み替えてエントリへ跳ぶ。fd は持ち越す。
    fn sys_exec(&mut self, env: &mut BareEnv, name: u32, argp: u32, _envp: u32) -> Disp {
        let path = match self.host_path(env, u64::from(name)) {
            Ok(p) => p,
            Err(e) => return Disp::Fail(e),
        };
        match polyisa_host::stat(&path) {
            Ok(m) if m.mode & 0o111 != 0 => {}
            Ok(_) => return Disp::Fail(errno::EACCES),
            Err(e) => return Disp::Fail(host_err(e.raw_os_error())),
        }
        // argp が指す char *argv[]（NULL 終端）を読む。
        let mut argv: Vec<String> = Vec::new();
        for i in 0..2048u64 {
            let Some(p) = Self::r32(env, u64::from(argp) + 4 * i) else {
                return Disp::Fail(errno::EFAULT);
            };
            if p == 0 {
                break;
            }
            match self.read_cstr(env, u64::from(p)) {
                Ok(s) => argv.push(s),
                Err(e) => return Disp::Fail(e),
            }
        }
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => return Disp::Fail(host_err(e.raw_os_error())),
        };
        if aout::parse(&bytes, aout::Arch::Vax).is_err() {
            return Disp::Fail(errno::ENOEXEC);
        }
        if argv.is_empty() {
            argv.push(self.read_cstr(env, u64::from(name)).unwrap_or_default());
        }
        env.backend
            .mem
            .unmap(VirtAddr(0), P0_TOP / polyisa_mem::PAGE_SIZE);
        env.backend.mem.unmap(
            VirtAddr(u64::from(STACK_TOP - STACK_SZ)),
            u64::from(STACK_SZ) / polyisa_mem::PAGE_SIZE,
        );
        match self.load_exec(env, &bytes, &argv) {
            Ok(entry) => {
                env.pc = u64::from(entry);
                sem::r_set(&mut env.backend, reg::PC as u8, entry);
                Disp::Ret(0)
            }
            Err(_) => Disp::Fail(errno::ENOEXEC),
        }
    }

    /// syscall 番号 `n` を `ap` の引数で実行する。
    fn dispatch(&mut self, env: &mut BareEnv, n: u32, ap: u32) -> Disp {
        match n {
            // indir: a[0] が呼ぶ番号、残りが引数（ap を 4 進める）。
            0 => self.dispatch(env, Self::ag(env, ap, 0), ap + 4),
            1 => Disp::Exit(Self::ag(env, ap, 0) & 0xff),
            2 | 66 => Disp::Fail(errno::EAGAIN), // fork/vfork —— 単一プロセス
            7 | 84 => Disp::Fail(errno::ECHILD), // wait4/wait
            3 => self.sys_read(
                env,
                Self::ag(env, ap, 0),
                Self::ag(env, ap, 1),
                Self::ag(env, ap, 2),
            ),
            4 => self.sys_write(
                env,
                Self::ag(env, ap, 0),
                Self::ag(env, ap, 1),
                Self::ag(env, ap, 2),
            ),
            5 => self.sys_open(
                env,
                &[
                    Self::ag(env, ap, 0),
                    Self::ag(env, ap, 1),
                    Self::ag(env, ap, 2),
                ],
                false,
            ),
            8 => self.sys_open(env, &[Self::ag(env, ap, 0), 1, Self::ag(env, ap, 1)], true),
            6 => {
                let fd = Self::ag(env, ap, 0);
                if !self.fd_used(fd) {
                    return Disp::Fail(errno::EBADF);
                }
                self.fds.clear(fd);
                self.dirs.remove(&fd);
                if let Some(p) = self.pipes.remove(&fd) {
                    self.pipe_tab.close(p.id, p.read);
                }
                Disp::Ret(0)
            }
            9 => {
                let old = match self.host_path(env, u64::from(Self::ag(env, ap, 0))) {
                    Ok(p) => p,
                    Err(e) => return Disp::Fail(e),
                };
                let new = match self.host_path(env, u64::from(Self::ag(env, ap, 1))) {
                    Ok(p) => p,
                    Err(e) => return Disp::Fail(e),
                };
                match std::fs::hard_link(&old, &new) {
                    Ok(()) => Disp::Ret(0),
                    Err(e) => Disp::Fail(host_err(e.raw_os_error())),
                }
            }
            10 => {
                let path = match self.host_path(env, u64::from(Self::ag(env, ap, 0))) {
                    Ok(p) => p,
                    Err(e) => return Disp::Fail(e),
                };
                if std::fs::metadata(&path)
                    .map(|m| m.is_dir())
                    .unwrap_or(false)
                {
                    return Disp::Fail(errno::EPERM);
                }
                match std::fs::remove_file(&path) {
                    Ok(()) => Disp::Ret(0),
                    Err(e) => Disp::Fail(host_err(e.raw_os_error())),
                }
            }
            11 | 59 => self.sys_exec(
                env,
                Self::ag(env, ap, 0),
                Self::ag(env, ap, 1),
                Self::ag(env, ap, 2),
            ),
            12 => {
                let path = match self.host_path(env, u64::from(Self::ag(env, ap, 0))) {
                    Ok(p) => p,
                    Err(e) => return Disp::Fail(e),
                };
                match std::fs::metadata(&path) {
                    Ok(m) if m.is_dir() => {
                        let g = self
                            .read_cstr(env, u64::from(Self::ag(env, ap, 0)))
                            .unwrap_or_else(|_| "/".into());
                        self.cwd = if g.starts_with('/') {
                            g
                        } else {
                            format!("{}/{}", self.cwd.trim_end_matches('/'), g)
                        };
                        Disp::Ret(0)
                    }
                    Ok(_) => Disp::Fail(errno::ENOTDIR),
                    Err(e) => Disp::Fail(host_err(e.raw_os_error())),
                }
            }
            14 => {
                // mknod: 通常ファイルのみ（デバイスはホスト権限外）。
                let path = match self.host_path(env, u64::from(Self::ag(env, ap, 0))) {
                    Ok(p) => p,
                    Err(e) => return Disp::Fail(e),
                };
                if Self::ag(env, ap, 1) & 0o170000 != 0 {
                    return Disp::Fail(errno::EPERM);
                }
                match std::fs::File::create(&path) {
                    Ok(_) => Disp::Ret(0),
                    Err(e) => Disp::Fail(host_err(e.raw_os_error())),
                }
            }
            15 => {
                let path = match self.host_path(env, u64::from(Self::ag(env, ap, 0))) {
                    Ok(p) => p,
                    Err(e) => return Disp::Fail(e),
                };
                match polyisa_host::chmod(&path, Self::ag(env, ap, 1)) {
                    Ok(()) => Disp::Ret(0),
                    Err(e) => Disp::Fail(host_err(e.raw_os_error())),
                }
            }
            16 => {
                // chown: root モデルでは成功扱い（存在の検査はする）。
                let path = match self.host_path(env, u64::from(Self::ag(env, ap, 0))) {
                    Ok(p) => p,
                    Err(e) => return Disp::Fail(e),
                };
                match polyisa_host::stat(&path) {
                    Ok(_) => Disp::Ret(0),
                    Err(e) => Disp::Fail(host_err(e.raw_os_error())),
                }
            }
            17 => self.sys_brk(env, Self::ag(env, ap, 0), true),
            19 => {
                // lseek(fd, off, whence) —— off は 32 ビット符号付き。
                let fd = Self::ag(env, ap, 0);
                let Some(f) = self.fds.get_mut(fd) else {
                    return if fd <= 2 || self.pipes.contains_key(&fd) || self.dirs.contains_key(&fd)
                    {
                        Disp::Fail(errno::ESPIPE)
                    } else {
                        Disp::Fail(errno::EBADF)
                    };
                };
                let pos = match Self::ag(env, ap, 2) {
                    0 => SeekFrom::Start(u64::from(Self::ag(env, ap, 1))),
                    1 => SeekFrom::Current(i64::from(Self::ag(env, ap, 1) as i32)),
                    2 => SeekFrom::End(i64::from(Self::ag(env, ap, 1) as i32)),
                    _ => return Disp::Fail(errno::EINVAL),
                };
                match f.seek(pos) {
                    Ok(p) => Disp::Ret(p.min(u64::from(u32::MAX)) as u32),
                    Err(e) => Disp::Fail(host_err(e.raw_os_error())),
                }
            }
            20 => Disp::Ret(self.pid),
            23 | 46 | 34 | 44 | 82 | 83 | 95 | 103 | 108 | 109 | 110 | 112 => Disp::Ret(0),
            // ^ setuid/setgid/nice/profil/setpgrp/setitimer/fsync/
            //   sigreturn/sigvec/sigblock/sigsetmask/sigstack ——
            //   効かないが成功扱いにする近似。
            24 | 47 => Disp::Ret(0),  // getuid/getgid —— root モデル
            25 | 122 => Disp::Ret(0), // stime/settimeofday —— 時計は書かない
            27 => Disp::Ret(0),       // alarm —— タイマなし
            29 | 111 => Disp::Fail(errno::EINTR), // pause/sigsuspend
            30 | 138 => {
                // utime/utimes: 時刻更新は省略。存在の検査はする。
                let path = match self.host_path(env, u64::from(Self::ag(env, ap, 0))) {
                    Ok(p) => p,
                    Err(e) => return Disp::Fail(e),
                };
                match polyisa_host::stat(&path) {
                    Ok(_) => Disp::Ret(0),
                    Err(e) => Disp::Fail(host_err(e.raw_os_error())),
                }
            }
            31 | 32 | 54 => Disp::Fail(errno::ENOTTY), // stty/gtty/ioctl
            33 => {
                let path = match self.host_path(env, u64::from(Self::ag(env, ap, 0))) {
                    Ok(p) => p,
                    Err(e) => return Disp::Fail(e),
                };
                match polyisa_host::stat(&path) {
                    Ok(md) => {
                        if Self::ag(env, ap, 1) & 1 != 0 && md.mode & 0o111 == 0 {
                            Disp::Fail(errno::EACCES)
                        } else {
                            Disp::Ret(0)
                        }
                    }
                    Err(e) => Disp::Fail(host_err(e.raw_os_error())),
                }
            }
            35 => {
                // ftime: struct timeb {time(4)・millitm(2)・timezone(2)・dstflag(2)}。
                let tp = u64::from(Self::ag(env, ap, 0));
                let t = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                let ok = Self::w32(env, tp, t.as_secs() as u32)
                    && Self::w16(env, tp + 4, t.subsec_millis() as u16)
                    && Self::w16(env, tp + 6, 0)
                    && Self::w16(env, tp + 8, 0);
                if ok {
                    Disp::Ret(0)
                } else {
                    Disp::Fail(errno::EFAULT)
                }
            }
            36 => Disp::Ret(0), // sync
            37 => {
                // kill(pid, sig): 自プロセスのみ。
                let pid = Self::ag(env, ap, 0);
                if pid != self.pid && pid != 0 {
                    return Disp::Fail(errno::ESRCH);
                }
                let s = Self::ag(env, ap, 1);
                if s == 0 {
                    return Disp::Ret(0);
                }
                if s > 31 {
                    return Disp::Fail(errno::EINVAL);
                }
                Self::die(s as u8)
            }
            38 => self.sys_stat(
                env,
                &[Self::ag(env, ap, 0), Self::ag(env, ap, 1)],
                false,
                false,
            ),
            40 => self.sys_stat(
                env,
                &[Self::ag(env, ap, 0), Self::ag(env, ap, 1)],
                true,
                false,
            ),
            62 => self.sys_stat(
                env,
                &[Self::ag(env, ap, 0), Self::ag(env, ap, 1)],
                false,
                true,
            ),
            41 => {
                let fd = Self::ag(env, ap, 0);
                if !self.fd_used(fd) {
                    return Disp::Fail(errno::EBADF);
                }
                match self.alloc_fd() {
                    Some(nf) => self.sys_dup_place(fd, nf),
                    None => Disp::Fail(errno::EMFILE),
                }
            }
            90 => {
                // dup2(fd, fd2)。
                let (fd, fd2) = (Self::ag(env, ap, 0), Self::ag(env, ap, 1));
                if !self.fd_used(fd) || fd2 >= NOFILE {
                    return Disp::Fail(errno::EBADF);
                }
                if fd == fd2 {
                    return Disp::Ret(fd);
                }
                self.fds.clear(fd2);
                self.dirs.remove(&fd2);
                if let Some(p) = self.pipes.remove(&fd2) {
                    self.pipe_tab.close(p.id, p.read);
                }
                self.sys_dup_place(fd, fd2)
            }
            42 => {
                // pipe() → r0=読み側・r1=書き側。
                let Some(r) = (3u32..NOFILE).find(|&f| !self.fd_used(f)) else {
                    return Disp::Fail(errno::EMFILE);
                };
                self.pipes.insert(r, PipeEnd { id: 0, read: true });
                let Some(w) = ((r + 1)..NOFILE).find(|&f| !self.fd_used(f)) else {
                    self.pipes.remove(&r);
                    return Disp::Fail(errno::EMFILE);
                };
                let id = self.pipe_tab.open();
                self.pipes.get_mut(&r).unwrap().id = id;
                self.pipes.insert(w, PipeEnd { id, read: false });
                Disp::Ret2(r, w)
            }
            43 => {
                // times(buf): tms 4×long を 0 で埋める。
                let buf = u64::from(Self::ag(env, ap, 0));
                if (0..4).all(|i| Self::w32(env, buf + 4 * i, 0)) {
                    Disp::Ret(0)
                } else {
                    Disp::Fail(errno::EFAULT)
                }
            }
            57 => {
                // symlink(old, new)。
                let old = match self.read_cstr(env, u64::from(Self::ag(env, ap, 0))) {
                    Ok(s) => s,
                    Err(e) => return Disp::Fail(e),
                };
                let new = match self.host_path(env, u64::from(Self::ag(env, ap, 1))) {
                    Ok(p) => p,
                    Err(e) => return Disp::Fail(e),
                };
                match polyisa_host::symlink(&old, &new) {
                    Ok(()) => Disp::Ret(0),
                    Err(e) => Disp::Fail(host_err(e.raw_os_error())),
                }
            }
            58 => {
                // readlink(path, buf, n)。
                let path = match self.host_path(env, u64::from(Self::ag(env, ap, 0))) {
                    Ok(p) => p,
                    Err(e) => return Disp::Fail(e),
                };
                match std::fs::read_link(&path) {
                    Ok(t) => {
                        let s = t.to_string_lossy();
                        let n = (Self::ag(env, ap, 2) as usize).min(s.len());
                        if self
                            .write_bytes(env, u64::from(Self::ag(env, ap, 1)), &s.as_bytes()[..n])
                            .is_err()
                        {
                            Disp::Fail(errno::EFAULT)
                        } else {
                            Disp::Ret(n as u32)
                        }
                    }
                    Err(e) => Disp::Fail(host_err(e.raw_os_error())),
                }
            }
            60 => {
                let old = self.umask;
                self.umask = Self::ag(env, ap, 0) & 0o777;
                Disp::Ret(old)
            }
            61 => {
                // chroot: ルートを張り替える。
                let path = match self.host_path(env, u64::from(Self::ag(env, ap, 0))) {
                    Ok(p) => p,
                    Err(e) => return Disp::Fail(e),
                };
                match std::fs::metadata(&path) {
                    Ok(m) if m.is_dir() => {
                        self.root = path;
                        self.cwd = "/".to_string();
                        Disp::Ret(0)
                    }
                    Ok(_) => Disp::Fail(errno::ENOTDIR),
                    Err(e) => Disp::Fail(host_err(e.raw_os_error())),
                }
            }
            64 => Disp::Ret(512), // getpagesize —— VAX は 512 B ページ
            69 => self.sys_brk(env, Self::ag(env, ap, 0), false), // sbrk
            81 => Disp::Ret(self.pid), // getpgrp
            86 => {
                // getitimer(which, value): 2 timeval = 16 B を 0 で。
                let v = u64::from(Self::ag(env, ap, 1));
                if (0..4).all(|i| Self::w32(env, v + 4 * i, 0)) {
                    Disp::Ret(0)
                } else {
                    Disp::Fail(errno::EFAULT)
                }
            }
            87 => {
                // gethostname(buf, len)。
                let name = b"vax780\0";
                let n = (Self::ag(env, ap, 1) as usize).min(name.len());
                if self
                    .write_bytes(env, u64::from(Self::ag(env, ap, 0)), &name[..n])
                    .is_ok()
                {
                    Disp::Ret(0)
                } else {
                    Disp::Fail(errno::EFAULT)
                }
            }
            88 => Disp::Ret(0),      // sethostname —— root モデル
            89 => Disp::Ret(NOFILE), // getdtablesize
            92 => {
                // fcntl(fd, cmd, arg): F_DUPFD=0 だけ扱う。
                let (fd, cmd) = (Self::ag(env, ap, 0), Self::ag(env, ap, 1));
                if !self.fd_used(fd) {
                    return Disp::Fail(errno::EBADF);
                }
                if cmd == 0 {
                    let lo = Self::ag(env, ap, 2).max(3);
                    match (lo..NOFILE).find(|&f| !self.fd_used(f)) {
                        Some(nf) => self.sys_dup_place(fd, nf),
                        None => Disp::Fail(errno::EMFILE),
                    }
                } else {
                    Disp::Ret(0)
                }
            }
            116 => {
                // gettimeofday(tv, tz): tv={sec,usec}、tz={minwest,dst}。
                let t = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                let tv = u64::from(Self::ag(env, ap, 0));
                let ok = tv == 0
                    || (Self::w32(env, tv, t.as_secs() as u32)
                        && Self::w32(env, tv + 4, t.subsec_micros()));
                let tz = u64::from(Self::ag(env, ap, 1));
                let ok = ok && (tz == 0 || (Self::w32(env, tz, 0) && Self::w32(env, tz + 4, 0)));
                if ok {
                    Disp::Ret(0)
                } else {
                    Disp::Fail(errno::EFAULT)
                }
            }
            117 => {
                // getrusage(who, ru): 16 long = 64 B を 0 で埋める。
                let r = u64::from(Self::ag(env, ap, 1));
                if (0..16).all(|i| Self::w32(env, r + 4 * i, 0)) {
                    Disp::Ret(0)
                } else {
                    Disp::Fail(errno::EFAULT)
                }
            }
            120 | 121 => {
                // readv/writev(fd, iov, cnt): iov = {base,len} × cnt。
                let (fd, iov, cnt) = (
                    Self::ag(env, ap, 0),
                    u64::from(Self::ag(env, ap, 1)),
                    Self::ag(env, ap, 2),
                );
                if cnt > 16 {
                    return Disp::Fail(errno::EINVAL);
                }
                let mut total = 0u32;
                for i in 0..cnt {
                    let (Some(base), Some(len)) = (
                        Self::r32(env, iov + 8 * u64::from(i)),
                        Self::r32(env, iov + 8 * u64::from(i) + 4),
                    ) else {
                        return Disp::Fail(errno::EFAULT);
                    };
                    let sub = if n == 120 {
                        self.sys_read(env, fd, base, len)
                    } else {
                        self.sys_write(env, fd, base, len)
                    };
                    match sub {
                        Disp::Ret(k) => {
                            total += k;
                            if k < len {
                                return Disp::Ret(total);
                            }
                        }
                        other => return other,
                    }
                }
                Disp::Ret(total)
            }
            128 => {
                // rename(old, new)。
                let old = match self.host_path(env, u64::from(Self::ag(env, ap, 0))) {
                    Ok(p) => p,
                    Err(e) => return Disp::Fail(e),
                };
                let new = match self.host_path(env, u64::from(Self::ag(env, ap, 1))) {
                    Ok(p) => p,
                    Err(e) => return Disp::Fail(e),
                };
                match std::fs::rename(&old, &new) {
                    Ok(()) => Disp::Ret(0),
                    Err(e) => Disp::Fail(host_err(e.raw_os_error())),
                }
            }
            129 => {
                // truncate(path, len)。
                let path = match self.host_path(env, u64::from(Self::ag(env, ap, 0))) {
                    Ok(p) => p,
                    Err(e) => return Disp::Fail(e),
                };
                match std::fs::File::create(&path)
                    .and_then(|f| f.set_len(u64::from(Self::ag(env, ap, 1))))
                {
                    Ok(()) => Disp::Ret(0),
                    Err(e) => Disp::Fail(host_err(e.raw_os_error())),
                }
            }
            130 => {
                // ftruncate(fd, len)。
                match self.fds.get(Self::ag(env, ap, 0)) {
                    Some(f) => match f.set_len(u64::from(Self::ag(env, ap, 1))) {
                        Ok(()) => Disp::Ret(0),
                        Err(e) => Disp::Fail(host_err(e.raw_os_error())),
                    },
                    None => Disp::Fail(errno::EBADF),
                }
            }
            136 => {
                // mkdir(path, mode)。
                let path = match self.host_path(env, u64::from(Self::ag(env, ap, 0))) {
                    Ok(p) => p,
                    Err(e) => return Disp::Fail(e),
                };
                match std::fs::create_dir(&path) {
                    Ok(()) => {
                        let _ =
                            polyisa_host::chmod(&path, Self::ag(env, ap, 1) & 0o777 & !self.umask);
                        Disp::Ret(0)
                    }
                    Err(e) => Disp::Fail(host_err(e.raw_os_error())),
                }
            }
            137 => {
                // rmdir(path)。
                let path = match self.host_path(env, u64::from(Self::ag(env, ap, 0))) {
                    Ok(p) => p,
                    Err(e) => return Disp::Fail(e),
                };
                match std::fs::remove_dir(&path) {
                    Ok(()) => Disp::Ret(0),
                    Err(e) => Disp::Fail(host_err(e.raw_os_error())),
                }
            }
            // mount/umount/ptrace/acct/reboot/vhangup/swapon —
            // 特権または模型の外。
            21 | 22 | 26 | 51 | 55 | 76 | 85 => Disp::Fail(errno::EPERM),
            // socket 一族・mmap 一族・getdirentries・select 等の
            // 未実装 —— nosys 相当として EINVAL に倒す。
            _ => {
                if !self.reported.contains(&n) {
                    self.reported.push(n);
                    eprintln!(
                        "bsd: 未実装の syscall {n}（{}）",
                        NAMES.get(n as usize).copied().unwrap_or("?")
                    );
                }
                Disp::Fail(errno::EINVAL)
            }
        }
    }

    /// a.out を読み、仮想アドレス空間・初期スタックを組み立てて
    /// エントリポイントを返す。
    ///
    /// 配置（Ref: SPEC-BSD-43 §5 a.out、N_TXTOFF マクロ）:
    /// - 0413 (ZMAGIC): text は file offset 1024 → vaddr 0、
    ///   data は file offset 1024+text → text 以降の 1024 境界
    /// - 0407 (OMAGIC): text は file offset 32 → vaddr 0、
    ///   data は text の直後に連続
    ///
    /// 初期スタック: [argc][argv*][0][envp*][0]、envp は空。
    /// エントリは `a_entry + 2` —— 先頭の 2 バイトは calls 用の
    /// レジスタセーブマスクで、rei 経由の飛び込みでは飛び越す。
    pub fn load_exec(
        &mut self,
        env: &mut BareEnv,
        bytes: &[u8],
        argv: &[String],
    ) -> Result<u32, String> {
        let h = aout::parse(bytes, aout::Arch::Vax).map_err(|e| format!("a.out: {e:?}"))?;
        let txtoff = if h.magic == aout::ZMAGIC {
            1024
        } else {
            h.hdr_len
        };
        let text_bytes = bytes
            .get(txtoff as usize..(txtoff + h.text) as usize)
            .ok_or_else(|| "a.out: text が切れている".to_string())?;
        let data_bytes = bytes
            .get((txtoff + h.text) as usize..(txtoff + h.text + h.data) as usize)
            .ok_or_else(|| "a.out: data が切れている".to_string())?;
        if h.entry + 2 >= P0_TOP {
            return Err("entry が P0 空間を外れる".to_string());
        }

        let data_va: u64 = match h.magic {
            aout::OMAGIC => h.text,
            // NMAGIC/ZMAGIC は次の 1024 境界（BSD の CLBYTES=1024）。
            _ => h.text.next_multiple_of(1024),
        };
        let bss_lo = data_va + h.data;
        self.data_lo = data_va as u32;
        self.brk = (bss_lo + h.bss) as u32;
        if bss_lo + h.bss >= u64::from(STACK_TOP - STACK_SZ) {
            return Err("data+bss がユーザ空間を超える".to_string());
        }

        // P0 側の写像（text+data+bss までを一続きで）。
        let perms = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        let hi = (bss_lo + h.bss + polyisa_mem::PAGE_SIZE - 1) & !(polyisa_mem::PAGE_SIZE - 1);
        env.backend
            .mem
            .map(VirtAddr(0), hi / polyisa_mem::PAGE_SIZE, perms)
            .map_err(|e| format!("mem: {e:?}"))?;
        env.backend
            .mem
            .write(VirtAddr(0), text_bytes)
            .map_err(|e| format!("text: {e:?}"))?;
        env.backend
            .mem
            .write(VirtAddr(data_va), data_bytes)
            .map_err(|e| format!("data: {e:?}"))?;

        // スタック領域を張る。
        let sb = u64::from(STACK_TOP - STACK_SZ);
        env.backend
            .mem
            .map(
                VirtAddr(sb),
                u64::from(STACK_SZ) / polyisa_mem::PAGE_SIZE,
                perms,
            )
            .map_err(|e| format!("stack: {e:?}"))?;

        // 初期スタック: 文字列を上端から下へ、続いてポインタ表。
        let mut sp: u64 = u64::from(STACK_TOP);
        let mut strs: Vec<u32> = Vec::new();
        for s in argv.iter().rev() {
            sp = (sp - s.len() as u64 - 1) & !3;
            env.backend
                .mem
                .write(VirtAddr(sp), s.as_bytes())
                .map_err(|e| format!("argv: {e:?}"))?;
            strs.push(sp as u32);
        }
        strs.reverse();
        // envp 終端・argv 終端・argv・argc（envp は空）。
        sp -= 4;
        Self::w32(env, sp, 0);
        sp -= 4;
        Self::w32(env, sp, 0);
        for a in strs.iter().rev() {
            sp -= 4;
            Self::w32(env, sp, *a);
        }
        sp -= 4;
        Self::w32(env, sp, strs.len() as u32);

        // レジスタと PSL: r0-r11 = 0、sp = argc の位置、
        // pc = a_entry + 2（calls マスクを飛び越す）、CUR=PRV=user。
        for i in 0..12u8 {
            sem::r_set(&mut env.backend, i, 0);
        }
        sem::r_set(&mut env.backend, reg::AP as u8, 0);
        sem::r_set(&mut env.backend, reg::FP as u8, 0);
        sem::r_set(&mut env.backend, reg::SP as u8, sp as u32);
        let entry = (h.entry + 2) as u32;
        sem::r_set(&mut env.backend, reg::PC as u8, entry);
        sem::psl_put(&mut env.backend, psl::USER | 0x3 << psl::PRV_MOD);
        Ok(entry)
    }
}

/// ホスト errno を BSD errno に写す。
fn host_err(e: Option<i32>) -> u32 {
    match e.unwrap_or(errno::EIO as i32) {
        1 => errno::EPERM,
        2 => errno::ENOENT,
        3 => errno::ESRCH,
        4 => errno::EINTR,
        5 => errno::EIO,
        9 => errno::EBADF,
        11 => errno::EAGAIN,
        12 => errno::ENOMEM,
        13 => errno::EACCES,
        14 => errno::EFAULT,
        16 => errno::EBUSY,
        17 => errno::EEXIST,
        18 => errno::EXDEV,
        19 => errno::ENODEV,
        20 => errno::ENOTDIR,
        21 => errno::EISDIR,
        22 => errno::EINVAL,
        23 | 24 => errno::EMFILE,
        25 => errno::ENOTTY,
        27 => errno::EFBIG,
        28 => errno::ENOSPC,
        29 => errno::ESPIPE,
        30 => errno::EROFS,
        31 => errno::EMLINK,
        32 => errno::EPIPE,
        _ => errno::EIO,
    }
}

/// トレースの出力口（環境変数で有効化）。
fn trace() -> bool {
    std::env::var_os("POLYISA_BSD_TRACE").is_some()
}

impl TrapHandler for Bsd {
    fn handle_trap(&mut self, env: &mut BareEnv, code: u32) -> TrapOutcome {
        if trace() && code != sem::scb::CHMK {
            eprintln!(
                "bsd trap code={code:#x} pc={:#x} sp={:#x} ap={:#x} psl={:#x}",
                env.pc,
                sem::r_get(&env.backend, reg::SP as u8),
                sem::r_get(&env.backend, reg::AP as u8),
                sem::psl_get(&env.backend),
            );
        }
        if code == sem::scb::CHMK {
            // sem が積んだコードを取り出して sp を戻す。
            let sp = sem::r_get(&env.backend, reg::SP as u8);
            let Some(call) = Self::r32(env, u64::from(sp)) else {
                return TrapOutcome::Exit(u32::from(sig::SEGV) | sig::CORE);
            };
            sem::r_set(&mut env.backend, reg::SP as u8, sp.wrapping_add(4));
            let ap = sem::r_get(&env.backend, reg::AP as u8);
            if trace() {
                let name = NAMES.get(call as usize).copied().unwrap_or("?");
                eprintln!("bsd sys {call}({name}) ap={ap:#x}");
            }
            let disp = self.dispatch(env, call, ap);
            // CUR_MOD を user に戻す（rei の復帰に相当）。
            let p = sem::psl_get(&env.backend);
            sem::psl_put(&mut env.backend, (p & !(0x3 << psl::CUR_MOD)) | psl::USER);
            match disp {
                Disp::Exit(c) => TrapOutcome::Exit(c),
                Disp::Ret(v) => {
                    sem::r_set(&mut env.backend, 0, v);
                    let p = sem::psl_get(&env.backend) & !(1 << psl::C);
                    sem::psl_put(&mut env.backend, p);
                    TrapOutcome::Handled
                }
                Disp::Ret2(a, b) => {
                    sem::r_set(&mut env.backend, 0, a);
                    sem::r_set(&mut env.backend, 1, b);
                    let p = sem::psl_get(&env.backend) & !(1 << psl::C);
                    sem::psl_put(&mut env.backend, p);
                    TrapOutcome::Handled
                }
                Disp::Fail(e) => {
                    sem::r_set(&mut env.backend, 0, e);
                    let p = sem::psl_get(&env.backend) | (1 << psl::C);
                    sem::psl_put(&mut env.backend, p);
                    TrapOutcome::Handled
                }
            }
        } else {
            // 権限外のチェンジモード・実機 fault 系はプロセス終了へ。
            let Disp::Exit(c) = (match code {
                sem::scb::ACV | sem::scb::TNV => Self::die(sig::SEGV),
                sem::scb::BPT => Self::die(sig::TRAP),
                sem::scb::ARITHMETIC => Self::die(sig::FPE),
                _ => Self::die(sig::SYS),
            }) else {
                unreachable!()
            };
            TrapOutcome::Exit(c)
        }
    }

    fn handle_unimpl(&mut self, _env: &mut BareEnv, _pc: u64, _word: u64) -> TrapOutcome {
        TrapOutcome::Unimplemented
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_engine::run::Outcome;

    /// テスト用の VAX a.out（OMAGIC: 32 バイトヘッダ直後が text）。
    fn aout(text: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        for v in [u32::from(aout::OMAGIC), text.len() as u32, 0, 0, 0, 0, 0, 0] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(text);
        b
    }

    /// Bsd と BareEnv を exec 済みの状態で返す。
    fn boot(root: &str, bytes: &[u8], argv: &[String]) -> (Bsd, BareEnv, u32) {
        let mut sys = Bsd::new(root);
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_vax::CpuState>());
        polyisa_guest_vax::install_params(
            &mut env.backend,
            &polyisa_guest_vax::model_params("vax"),
        );
        env.backend.addr_mask = 0xFFFF_FFFF;
        let entry = sys.load_exec(&mut env, bytes, argv).unwrap();
        env.pc = u64::from(entry);
        (sys, env, entry)
    }

    /// ZMAGIC 実バイナリの配置 —— テキスト @0、データは次の
    /// 1024 境界、初期スタックが [argc][argv][0][envp][0] の形。
    #[test]
    fn load_zmagic_layout() {
        let root = "../../.testdata/bin-distro-bsd43reno";
        let bytes = std::fs::read(format!("{root}/bin/echo")).unwrap();
        let argv = vec!["/bin/echo".to_string(), "hello".to_string()];
        let (sys, env, entry) = boot(root, &bytes, &argv);
        // エントリはマスク語を飛ばした +2、CUR/PRV は user。
        assert_eq!(entry, 2);
        assert_eq!(
            sem::psl_get(&env.backend) & 0xf << psl::PRV_MOD,
            0xf << psl::PRV_MOD
        );
        // data は 1024 境界（echo: text=0x1c00 → data=0x1c00）。
        assert_eq!(sys.data_lo, 0x1c00);
        assert_eq!(sys.brk, 0x2400);
        // スタック: [argc=2][p0][p1][0][0] → 文字列。
        let sp = u64::from(sem::r_get(&env.backend, reg::SP as u8));
        assert_eq!(Bsd::r32(&env, sp), Some(2));
        let p0 = Bsd::r32(&env, sp + 4).unwrap();
        let p1 = Bsd::r32(&env, sp + 8).unwrap();
        assert_eq!(Bsd::r32(&env, sp + 12), Some(0));
        assert_eq!(Bsd::r32(&env, sp + 16), Some(0));
        let s0 = sys.read_cstr(&env, u64::from(p0)).unwrap();
        let s1 = sys.read_cstr(&env, u64::from(p1)).unwrap();
        assert_eq!(s0, "/bin/echo");
        assert_eq!(s1, "hello");
        // テキストの先頭は calls 用マスク（実行対象ではない）。
        let mut w = [0u8; 2];
        env.backend
            .mem
            .read(VirtAddr(0), &mut w, Access::DATA_LE)
            .unwrap();
        assert_eq!(u16::from_le_bytes(w), 0x0f00);
    }

    /// chmk の授受 —— sem が積んだコード語を [sp] から取って
    /// sp を戻す、引数は ap+4 から、成功は C=0+r0、失敗は
    /// C=1+r0=errno、exit は実行系の終了になる。
    #[test]
    fn chmk_boundary() {
        // プログラム（va 0）:
        //   00: 00 00                       calls マスク
        //   02: movl #$0x100, r12           AP を引数ブロックへ
        //   09: chmk $20                    getpid → r0=42, C=0
        //   0b: chmk $4                     write(1,0x140,4) → "TEST"
        //   0d: movl #$0x120, r12
        //   14: chmk $4                     write(99,...) → EBADF
        //   16: movl #$0x110, r12
        //   1d: chmk $1                     exit(7)
        let mut text = vec![
            0x00, 0x00, // mask
            0xd0, 0x8f, 0x00, 0x01, 0x00, 0x00, 0x5c, // movl #$0x100,r12
            0xbc, 0x14, // chmk $20
            0xbc, 0x04, // chmk $4
            0xd0, 0x8f, 0x20, 0x01, 0x00, 0x00, 0x5c, // movl #$0x120,r12
            0xbc, 0x04, // chmk $4
            0xd0, 0x8f, 0x10, 0x01, 0x00, 0x00, 0x5c, // movl #$0x110,r12
            0xbc, 0x01, // chmk $1
        ];
        text.resize(0x140, 0);
        for (v, off) in [(1u32, 0x104), (0x140, 0x108), (4, 0x10c)] {
            text[off..off + 4].copy_from_slice(&v.to_le_bytes());
        }
        for (v, off) in [(99u32, 0x124), (0x140, 0x128), (4, 0x12c)] {
            text[off..off + 4].copy_from_slice(&v.to_le_bytes());
        }
        text[0x114..0x118].copy_from_slice(&7u32.to_le_bytes());
        text.extend_from_slice(b"TEST");

        let bytes = aout(&text);
        let argv = vec!["/t".to_string()];
        let (mut sys, mut env, _e) = boot("", &bytes, &argv);
        let feats = polyisa_guest_vax::model_feats("vax");
        let sp0 = sem::r_get(&env.backend, reg::SP as u8);
        let step = |env: &mut BareEnv, sys: &mut Bsd| polyisa_guest_vax::run::step(env, sys, feats);
        let cc = |env: &BareEnv| sem::psl_get(&env.backend) & (1 << psl::C);

        step(&mut env, &mut sys).unwrap(); // movl
        // getpid: 成功 → r0=pid、C=0、コード語を sp から戻す。
        step(&mut env, &mut sys).unwrap();
        assert_eq!(sem::r_get(&env.backend, 0), sys.pid);
        assert_eq!(cc(&env), 0);
        assert_eq!(sem::r_get(&env.backend, reg::SP as u8), sp0);
        // write(1, 0x140, 4): 成功 → r0=4、stdout に "TEST"。
        step(&mut env, &mut sys).unwrap();
        assert_eq!(sem::r_get(&env.backend, 0), 4);
        assert_eq!(cc(&env), 0);
        assert_eq!(sys.io.stdout, b"TEST");
        step(&mut env, &mut sys).unwrap(); // movl
        // write(99, ...): EBADF → C=1、r0=errno。
        step(&mut env, &mut sys).unwrap();
        assert_eq!(sem::r_get(&env.backend, 0), errno::EBADF);
        assert_ne!(cc(&env), 0);
        step(&mut env, &mut sys).unwrap(); // movl
        // exit(7): 実行系の終了になる。
        match step(&mut env, &mut sys) {
            Err(Outcome::Exit(7)) => {}
            other => panic!("exit: {other:?}"),
        }
    }
}
