// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Alpha の Linux syscall 処理（段階16-10/11）。
//!
//! `call_pal` の関数番号で振り分ける: `callsys`(0x83) が syscall
//! で、番号は v0、引数は a0–a5、戻り値は v0、a3=1 が失敗印。
//! `rduniq`/`wruniq` はスレッドポインタの転送。`imb`/`cflush`/
//! `draina` は順序付き実行のインタプリタでは何もしない。
//! 浮動小数点補完と非整列補完はこの実装では CPU 側が完結するため
//! （gentrap 経路の補完は発生しない）、OSF の getsysinfo/setsysinfo
//! は受理するだけで状態を持たない。
// Ref: SRC-LINUX (7.3), SPEC-ALPHA-ARM.

use std::io::{Read, Seek, SeekFrom};

use polyisa_engine::bare::BareEnv;
use polyisa_engine::run::{TrapHandler, TrapOutcome};
use polyisa_guest_alpha::sem;
use polyisa_kernel::FdTable;
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};
use polyisa_sem::Backend as _;

use crate::alpha::{AT_FDCWD, errno, mman, name, nr, oflag};

/// `call_pal` の PAL 関数番号（Linux がユーザから使うもの）。
// Ref: SRC-LINUX (7.3) — arch/alpha/include/uapi/asm/pal.h.
mod pal {
    /// PAL_cflush: キャッシュフラッシュ。no-op。
    pub const CFLUSH: u32 = 0x01;
    /// PAL_draina: 命令キューの排出。no-op。
    pub const DRAINA: u32 = 0x02;
    /// PAL_callsys: Linux syscall 発行点。
    pub const CALLSYS: u32 = 0x83;
    /// PAL_imb: I-cache の一貫化。インタプリタでは no-op。
    pub const IMB: u32 = 0x86;
    /// PAL_rduniq: v0 ← スレッドユニーク値。
    pub const RDUNIQ: u32 = 0x9e;
    /// PAL_wruniq: スレッドユニーク値 ← a0。
    pub const WRUNIQ: u32 = 0x9f;
}

/// 整数レジスタの読み出し（v0=0, a0=16 .. a5=21, a3=19, ra=26, sp=30）。
fn reg(env: &mut BareEnv, n: u8) -> u64 {
    env.backend.get(sem::Gpr(n).state())
}

fn set_reg(env: &mut BareEnv, n: u8, v: u64) {
    sem::Gpr(n).set(&mut env.backend, v);
}

fn trace() -> bool {
    std::env::var_os("POLYISA_ALPHA_SYSCALLS").is_some()
}

/// 標準入出力の捕獲。テストが読む。
#[derive(Default)]
pub struct AlphaIo {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Alpha Linux の syscall 状態機械。v0=番号、a0–a5=引数。
// Gap: GAP-0046 — 単一プロセス模型の意図的な簡略化（fork なし、
// select/poll/nanosleep はスタブ、statfs は合成値）。
pub struct Linux {
    /// 標準入出力の capture。
    pub io: AlphaIo,
    /// 標準入力へ供給するバイト。
    pub stdin_buf: Vec<u8>,
    /// /proc/self/exe の readlink が返す絶対パス。ローダが置く。
    pub exe_path: String,
    stdin_pos: usize,
    /// 開いたファイル（fd 3 以降）。0–2 は標準入出力。
    fds: FdTable,
    /// ゲストの相対パスをホストパスへ写す基準（chdir が動かす）。
    cwd: String,
    /// プログラムブレーク。0 は未初期化。
    heap_end: u64,
    /// `brk` が下げられない下限（exec 時点のブレーク）。
    brk_start: u64,
    /// 匿名 mmap の次の割当位置（ヒープの上に空間を取る）。
    mmap_next: u64,
    /// 報告済みの未実装番号（一度だけ出す）。
    reported: Vec<u64>,
    /// ホストから見たプロセス識別子。
    pid: u64,
    /// gettimeofday/clock_gettime の単調時計の起点。
    mono_start: Option<std::time::Instant>,
    /// rt_sigprocmask が見せる仮想のシグナルマスク。
    sig_mask: u64,
    /// getdents64 の fd ごとの走査位置（entries, pos）。
    dir_scans: std::collections::HashMap<u32, DirScan>,
    /// `umask` が保持する現在値。
    umask: u32,
    /// `prctl(PR_SET_NAME/GET_NAME)`・`comm` の仮想名。
    proc_name: [u8; 16],
    /// dup2 で 0–2 に結ばれたファイル（シェルのリダイレクト相当）。
    std_fds: [Option<std::fs::File>; 3],
    /// close された標準 fd。以後その fd の入出力は EBADF。
    std_closed: [bool; 3],
}

/// getdents64 の fd ごとの走査状態（entries, pos）。
type DirScan = (Vec<(u64, String, u8)>, usize);

impl Default for Linux {
    fn default() -> Self {
        Self::new()
    }
}

impl Linux {
    /// Alpha Linux の状態機械を作る。
    #[must_use]
    pub fn new() -> Self {
        Self {
            io: AlphaIo::default(),
            stdin_buf: Vec::new(),
            exe_path: String::new(),
            stdin_pos: 0,
            fds: FdTable::default(),
            cwd: String::new(),
            heap_end: 0,
            brk_start: 0,
            mmap_next: 0,
            reported: Vec::new(),
            pid: 0,
            mono_start: None,
            sig_mask: 0,
            dir_scans: std::collections::HashMap::new(),
            umask: 0o22,
            proc_name: *b"polyisa\0\0\0\0\0\0\0\0\0",
            std_fds: [None, None, None],
            std_closed: [false; 3],
        }
    }

    /// ゲストから見た pid。単一プロセスの模型なので常に 1（init）
    /// を返す（再現性のため固定 pid とする本実装の設計判断）。
    fn pid(&mut self) -> u64 {
        if self.pid == 0 {
            self.pid = 1;
        }
        self.pid
    }

    /// 引数 `i`（0 起算）を取り出す。a0–a5 = $16–$21。
    // Ref: SRC-LINUX (7.3) — syscall(2) の Alpha 規約。
    fn arg(&self, env: &mut BareEnv, i: usize) -> u64 {
        if i < 6 { reg(env, 16 + i as u8) } else { 0 }
    }

    /// LE/整列のデータアクセス属性。
    fn acc(kind: AccessKind) -> Access {
        Access {
            endian: Endian::Le,
            align: Align::Natural,
            kind,
        }
    }

    /// ゲストメモリからバイト列を読む。
    fn read_bytes(&mut self, env: &mut BareEnv, addr: u64, len: usize) -> Option<Vec<u8>> {
        let mut v = vec![0u8; len];
        env.backend
            .mem
            .read(VirtAddr(addr), &mut v, Self::acc(AccessKind::DataRead))
            .ok()?;
        Some(v)
    }

    /// NUL 終端のパス文字列を読む。
    fn read_cstr(&mut self, env: &mut BareEnv, addr: u64) -> Result<Vec<u8>, u32> {
        let mut out = Vec::new();
        let mut a = addr;
        loop {
            let b = self.read_bytes(env, a, 64).ok_or(errno::EFAULT)?;
            match b.iter().position(|&c| c == 0) {
                Some(i) => {
                    out.extend_from_slice(&b[..i]);
                    return Ok(out);
                }
                None => {
                    out.extend_from_slice(&b);
                    a += 64;
                    if out.len() > 4096 {
                        return Err(errno::ENAMETOOLONG);
                    }
                }
            }
        }
    }

    /// ゲストメモリへバイト列を書く。
    fn write_bytes(&mut self, env: &mut BareEnv, addr: u64, data: &[u8]) -> bool {
        env.backend.mem.write(VirtAddr(addr), data).is_ok()
    }

    /// LE の u32 を書く。
    fn put32(&mut self, env: &mut BareEnv, addr: u64, v: u32) -> bool {
        self.write_bytes(env, addr, &v.to_le_bytes())
    }

    /// LE の u64 を書く。
    fn put64(&mut self, env: &mut BareEnv, addr: u64, v: u64) -> bool {
        self.write_bytes(env, addr, &v.to_le_bytes())
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

    /// `dirfd` 指定のパスをホストパスへ。AT_FDCWD は cwd、
    /// その他は fd に覚えたパスを基点にする。
    fn host_path_at(&mut self, dirfd: i64, guest: &[u8]) -> Result<String, u32> {
        if String::from_utf8_lossy(guest).starts_with('/') {
            return Ok(self.host_path(guest));
        }
        if dirfd == AT_FDCWD {
            return Ok(self.host_path(guest));
        }
        if dirfd < 0 {
            return Err(errno::EBADF);
        }
        match self.fds.path_of(dirfd as u32) {
            Some(base) => Ok(format!(
                "{}/{}",
                base.trim_end_matches('/'),
                String::from_utf8_lossy(guest)
            )),
            None => Err(errno::EBADF),
        }
    }

    /// fd の上限。GETDTABLESIZE・RLIMIT_NOFILE と一致させる。
    const MAX_FD: u32 = 1024;

    /// fd のホストファイル。0–2 は差し替え分だけ返す。
    fn file_of(&self, fd: u32) -> Option<&std::fs::File> {
        if fd < 3 {
            self.std_fds[fd as usize].as_ref()
        } else {
            self.fds.file(fd)
        }
    }

    /// `file_of` の可変版。
    fn file_of_mut(&mut self, fd: u32) -> Option<&mut std::fs::File> {
        if fd < 3 {
            self.std_fds[fd as usize].as_mut()
        } else {
            self.fds.file_mut(fd)
        }
    }

    /// fd が読み書き可能に開いているか。0–2 は close 状態を見る。
    fn fd_open(&self, fd: u32) -> bool {
        if fd < 3 {
            !self.std_closed[fd as usize]
        } else {
            self.fds.ent(fd).is_some()
        }
    }

    /// 標準 fd の複製に使うホストファイル。差し替え済みは
    /// `try_clone`、未差し替えは /dev/fd/N を開き直して
    /// dup(0–2) を表す。
    fn std_clone(&self, fd: u32) -> Result<std::fs::File, u32> {
        if let Some(f) = self.std_fds[fd as usize].as_ref() {
            return f.try_clone().map_err(host_errno);
        }
        if self.std_closed[fd as usize] {
            return Err(errno::EBADF);
        }
        let p = format!("/dev/fd/{fd}");
        let r = std::fs::OpenOptions::new()
            .read(fd == 0)
            .write(fd != 0)
            .open(&p);
        r.or_else(|_| std::fs::File::open(&p)).map_err(host_errno)
    }

    /// FdTable の最小空き fd（EMFILE の検査用）。
    fn next_free_fd(&self) -> u32 {
        self.fds
            .first_hole_where(|_| true)
            .map(|i| 3 + i as u32)
            .unwrap_or(3 + self.fds.len() as u32)
    }

    /// FdTable へ置く。MAX_FD を越えるなら EMFILE。
    fn alloc_file(&mut self, f: std::fs::File) -> Result<u32, u32> {
        if self.next_free_fd() >= Self::MAX_FD {
            return Err(errno::EMFILE);
        }
        Ok(self.fds.alloc(polyisa_kernel::FdTarget::File(f)))
    }

    /// 標準入力バッファから `n` バイト取り出す。
    fn stdin_read(&mut self, n: usize) -> Vec<u8> {
        let rest = &self.stdin_buf[self.stdin_pos.min(self.stdin_buf.len())..];
        let k = rest.len().min(n);
        let data = rest[..k].to_vec();
        self.stdin_pos += k;
        data
    }

    /// ファイル fd から `n` バイト読む。
    fn file_read(&mut self, fd: u32, n: usize) -> Result<Vec<u8>, u32> {
        let f = self.file_of_mut(fd).ok_or(errno::EBADF)?;
        let mut buf = vec![0u8; n];
        let k = f.read(&mut buf).map_err(host_errno)?;
        buf.truncate(k);
        Ok(buf)
    }

    /// `data` を fd へ書く。1/2 は差し替えがなければ
    /// capture＋ホスト出力、それ以外はファイル。
    fn out_write(&mut self, fd: u32, data: &[u8]) -> Result<usize, u32> {
        use std::io::Write as _;
        match fd {
            0..=2 => {
                if self.std_closed[fd as usize] {
                    return Err(errno::EBADF);
                }
                if let Some(f) = self.std_fds[fd as usize].as_mut() {
                    return f.write(data).map_err(host_errno);
                }
                match fd {
                    0 => Err(errno::EBADF),
                    1 => {
                        self.io.stdout.extend_from_slice(data);
                        let _ = std::io::Write::write_all(&mut std::io::stdout(), data);
                        Ok(data.len())
                    }
                    _ => {
                        self.io.stderr.extend_from_slice(data);
                        let _ = std::io::Write::write_all(&mut std::io::stderr(), data);
                        Ok(data.len())
                    }
                }
            }
            _ => self
                .fds
                .file_mut(fd)
                .ok_or(errno::EBADF)?
                .write(data)
                .map_err(host_errno),
        }
    }

    /// 単調時計のマイクロ秒。
    fn mono_us(&mut self) -> u64 {
        self.mono_start
            .get_or_insert_with(std::time::Instant::now)
            .elapsed()
            .as_micros() as u64
    }

    /// `brk` の状態遷移。`sys_brk` が要求を適用して現在値を返し、
    /// `sys_osf_brk` は要求と不一致なら -ENOMEM に写す。つまり
    /// 下限未満の要求と写像失敗は a3=1 の ENOMEM になる。
    /// 内部の写像粒度はエミュレータのページ（4096。ゲストの
    /// getpagesize=8192 とは別物）。
    // Ref: SRC-LINUX (7.3) — sys_brk, sys_osf_brk (arch/alpha/kernel/osf_sys.c)。
    fn sys_brk(&mut self, env: &mut BareEnv, addr: u64) -> Result<u64, u32> {
        if addr == 0 {
            return Ok(self.heap_end);
        }
        if addr < self.brk_start {
            return Err(errno::ENOMEM);
        }
        if addr > self.heap_end {
            // 旧ブレークを含む部分ページは既に写像済みなので、
            // その次のページからだけを新規に確保する。
            let lo = self.heap_end.div_ceil(4096) * 4096;
            let hi = addr.div_ceil(4096) * 4096;
            // ヒープ上方に先行する mmap があれば衝突（map は既存
            // ページを黙って置き換えるため、先に検査する）。
            if (lo..hi)
                .step_by(4096)
                .any(|a| env.backend.mem.is_mapped(polyisa_mem::PageNo(a / 4096)))
            {
                return Err(errno::ENOMEM);
            }
            if hi > lo
                && env
                    .backend
                    .mem
                    .map(VirtAddr(lo), (hi - lo) / 4096, Perms::RW)
                    .is_err()
            {
                return Err(errno::ENOMEM);
            }
        }
        self.heap_end = addr;
        Ok(addr)
    }

    /// `write`。fd の検査は len==0 の早期リターンより先（vfs_write と同順）。
    fn sys_write(&mut self, env: &mut BareEnv, fd: u32, buf: u64, len: u64) -> Result<u64, u32> {
        if !self.fd_open(fd) || (fd == 0 && self.std_fds[0].is_none()) {
            return Err(errno::EBADF);
        }
        if fd >= 3 && self.fds.target(fd).is_some() && self.fds.file(fd).is_none() {
            // ファイル以外の対象（eventfd 等）は fd 表経由。
            let mut abi = crate::wait::WaitAbi::generic(8, 8, Endian::Le);
            abi.errno = |e| host_errno(std::io::Error::from_raw_os_error(e as i32));
            let t0 = std::time::Instant::now();
            let mono = move || t0.elapsed().as_nanos() as u64;
            return match crate::wait::write_other(&mut self.fds, &abi, env, fd, buf, len, 0, &mono)
            {
                Ok(v) => Ok(v),
                Err(e) => Err((abi.errno)(e)),
            };
        }
        let n = usize::try_from(len).unwrap_or(1 << 20).min(1 << 20);
        let data = self.read_bytes(env, buf, n).ok_or(errno::EFAULT)?;
        self.out_write(fd, &data).map(|n| n as u64)
    }

    /// `read`。fd0 は stdin_buf を順送り（差し替え時はファイル）、
    /// ファイルは FdTable。
    fn sys_read(&mut self, env: &mut BareEnv, fd: u32, buf: u64, len: u64) -> Result<u64, u32> {
        if !self.fd_open(fd) || ((fd == 1 || fd == 2) && self.std_fds[fd as usize].is_none()) {
            return Err(errno::EBADF);
        }
        let n = usize::try_from(len).unwrap_or(1 << 20).min(1 << 20);
        if n == 0 {
            return Ok(0);
        }
        let data = if fd == 0 && self.std_fds[0].is_none() {
            self.stdin_read(n)
        } else if self.fds.target(fd).is_some() && self.fds.file(fd).is_none() {
            // ファイル以外の対象（eventfd・timerfd 等）は fd 表経由。
            let mut abi = crate::wait::WaitAbi::generic(8, 8, Endian::Le);
            abi.errno = |e| host_errno(std::io::Error::from_raw_os_error(e as i32));
            let t0 = std::time::Instant::now();
            let mono = move || t0.elapsed().as_nanos() as u64;
            return match crate::wait::read_other(&mut self.fds, &abi, env, fd, buf, len, 0, &mono) {
                Ok(v) => Ok(v),
                Err(e) => Err((abi.errno)(e)),
            };
        } else {
            self.file_read(fd, n)?
        };
        if !self.write_bytes(env, buf, &data) {
            return Err(errno::EFAULT);
        }
        Ok(data.len() as u64)
    }

    /// `readv`（iovec = {u64 base, u64 len} の配列）。
    fn sys_readv(&mut self, env: &mut BareEnv, fd: u32, iov: u64, cnt: u64) -> Result<u64, u32> {
        if !self.fd_open(fd) || ((fd == 1 || fd == 2) && self.std_fds[fd as usize].is_none()) {
            return Err(errno::EBADF);
        }
        let mut total = 0u64;
        for i in 0..cnt.min(1024) {
            let Some(ia) = iov.checked_add(i * 16) else {
                return if total > 0 {
                    Ok(total)
                } else {
                    Err(errno::EFAULT)
                };
            };
            let base = self.read_u(env, ia).ok_or(errno::EFAULT)?;
            let len = self.read_u(env, ia + 8).ok_or(errno::EFAULT)?;
            let n = usize::try_from(len).unwrap_or(1 << 20).min(1 << 20);
            let data = if fd == 0 && self.std_fds[0].is_none() {
                self.stdin_read(n)
            } else {
                match self.file_read(fd, n) {
                    Ok(d) => d,
                    Err(e) => return if total > 0 { Ok(total) } else { Err(e) },
                }
            };
            if !self.write_bytes(env, base, &data) {
                return if total > 0 {
                    Ok(total)
                } else {
                    Err(errno::EFAULT)
                };
            }
            total += data.len() as u64;
            if (data.len() as u64) < len {
                break;
            }
        }
        Ok(total)
    }

    /// `writev`。
    fn sys_writev(&mut self, env: &mut BareEnv, fd: u32, iov: u64, cnt: u64) -> Result<u64, u32> {
        if !self.fd_open(fd) || (fd == 0 && self.std_fds[0].is_none()) {
            return Err(errno::EBADF);
        }
        let mut total = 0u64;
        for i in 0..cnt.min(1024) {
            let Some(ia) = iov.checked_add(i * 16) else {
                return if total > 0 {
                    Ok(total)
                } else {
                    Err(errno::EFAULT)
                };
            };
            let base = self.read_u(env, ia).ok_or(errno::EFAULT)?;
            let len = self.read_u(env, ia + 8).ok_or(errno::EFAULT)?;
            let n = usize::try_from(len).unwrap_or(1 << 20).min(1 << 20);
            let data = self.read_bytes(env, base, n).ok_or(errno::EFAULT)?;
            match self.out_write(fd, &data) {
                Ok(n) => {
                    total += n as u64;
                    if (n as u64) < len {
                        break;
                    }
                }
                Err(e) => return if total > 0 { Ok(total) } else { Err(e) },
            }
        }
        Ok(total)
    }

    /// ゲストメモリの u64 を読む。
    fn read_u(&mut self, env: &mut BareEnv, addr: u64) -> Option<u64> {
        self.read_bytes(env, addr, 8)
            .map(|b| u64::from_le_bytes(b[..8].try_into().unwrap()))
    }

    /// `sendfile`(out_fd, in_fd, off*, count)。in はファイル限定、
    /// off==NULL は in の現在位置から。
    fn sys_sendfile(
        &mut self,
        env: &mut BareEnv,
        out_fd: u32,
        in_fd: u32,
        off_addr: u64,
        count: u64,
    ) -> Result<u64, u32> {
        if !self.fd_open(out_fd) {
            return Err(errno::EBADF);
        }
        if self.file_of(in_fd).is_none() {
            return Err(errno::EBADF);
        }
        let mut pos = 0u64;
        let data = if off_addr != 0 {
            pos = self.read_u(env, off_addr).ok_or(errno::EFAULT)?;
            // off 指定時は fd の位置を動かさない（read_at）。
            let f = self.file_of(in_fd).unwrap();
            let mut buf = vec![0u8; usize::try_from(count).unwrap_or(1 << 20).min(1 << 20)];
            let n = polyisa_host::pread(f, &mut buf, pos).map_err(host_errno)?;
            buf.truncate(n);
            buf
        } else {
            let f = self.file_of_mut(in_fd).unwrap();
            let mut buf = vec![0u8; usize::try_from(count).unwrap_or(1 << 20).min(1 << 20)];
            let n = f.read(&mut buf).map_err(host_errno)?;
            buf.truncate(n);
            buf
        };
        let n = self.out_write(out_fd, &data)? as u64;
        if off_addr != 0 && !self.put64(env, off_addr, pos + n) {
            return Err(errno::EFAULT);
        }
        Ok(n)
    }

    /// `pread64`。alpha は off が a3–a4 に跨る ABI だが
    /// レジスタ呼出しではそのまま 64 ビットで届く。
    fn sys_pread64(
        &mut self,
        env: &mut BareEnv,
        fd: u32,
        buf: u64,
        len: u64,
        off: u64,
    ) -> Result<u64, u32> {
        // pread は fd の位置を動かさない。
        if (off as i64) < 0 {
            return Err(errno::EINVAL);
        }
        let f = self.file_of(fd).ok_or(errno::EBADF)?;
        let mut data = vec![0u8; usize::try_from(len).unwrap_or(1 << 20).min(1 << 20)];
        let n = polyisa_host::pread(f, &mut data, off).map_err(host_errno)?;
        data.truncate(n);
        if !self.write_bytes(env, buf, &data) {
            return Err(errno::EFAULT);
        }
        Ok(n as u64)
    }

    /// `pwrite64`。pread64 と同じ引数配置で fd の位置を動かさない。
    fn sys_pwrite64(
        &mut self,
        env: &mut BareEnv,
        fd: u32,
        buf: u64,
        len: u64,
        off: u64,
    ) -> Result<u64, u32> {
        if (off as i64) < 0 {
            return Err(errno::EINVAL);
        }
        let n = usize::try_from(len).unwrap_or(1 << 20).min(1 << 20);
        let data = self.read_bytes(env, buf, n).ok_or(errno::EFAULT)?;
        let f = self.file_of(fd).ok_or(errno::EBADF)?;
        polyisa_host::pwrite(f, &data, off)
            .map(|n| n as u64)
            .map_err(host_errno)
    }

    /// `lseek`。SEEK_SET/CUR/END = 0/1/2。
    fn sys_lseek(
        &mut self,
        _env: &mut BareEnv,
        fd: u32,
        off: i64,
        whence: u64,
    ) -> Result<u64, u32> {
        // SEEK_SET の負オフセットは EINVAL（ラップしない）。
        if whence == 0 && off < 0 {
            return Err(errno::EINVAL);
        }
        if fd < 3 && self.std_fds[fd as usize].is_none() {
            // 未差し替えの標準入出力はシーク不可。
            return Err(if self.std_closed[fd as usize] {
                errno::EBADF
            } else {
                errno::ESPIPE
            });
        }
        let f = self.file_of_mut(fd).ok_or(errno::EBADF)?;
        let w = match whence {
            0 => SeekFrom::Start(off as u64),
            1 => SeekFrom::Current(off),
            2 => SeekFrom::End(off),
            _ => return Err(errno::EINVAL),
        };
        match f.seek(w) {
            Ok(p) => Ok(p),
            // 位置が負になるのは EINVAL、シーク不可は ESPIPE。
            Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => Err(errno::EINVAL),
            Err(_) => Err(errno::ESPIPE),
        }
    }

    /// `close`。0–2 は差し替えを外して閉じた印を残し、
    /// ファイルはスロットを空ける。
    fn sys_close(&mut self, _env: &mut BareEnv, fd: u32) -> Result<u64, u32> {
        if fd < 3 {
            self.std_fds[fd as usize] = None;
            self.std_closed[fd as usize] = true;
            return Ok(0);
        }
        if self.fds.file(fd).is_none() {
            return Err(errno::EBADF);
        }
        self.fds.clear(fd);
        self.fds.forget_path(fd);
        self.dir_scans.remove(&fd);
        Ok(0)
    }

    /// `open`/`openat` の共通部。
    fn sys_open(
        &mut self,
        env: &mut BareEnv,
        dirfd: i64,
        path_addr: u64,
        flags: u32,
        mode: u32,
    ) -> Result<u64, u32> {
        let path = self.read_cstr(env, path_addr)?;
        // 空のパス名は ENOENT（AT_EMPTY_PATH は stat 系専用）。
        if path.is_empty() {
            return Err(errno::ENOENT);
        }
        let host = self.host_path_at(dirfd, &path)?;
        // O_NOFOLLOW: 末尾要素がシンボリックリンクなら ELOOP。
        // open 前に検査して O_CREAT と組み合わせたとき実体を
        // 作らせない。
        if flags & oflag::NOFOLLOW != 0
            && std::fs::symlink_metadata(&host)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
        {
            return Err(errno::ELOOP);
        }
        let existed = std::fs::symlink_metadata(&host).is_ok();
        let mut oo = std::fs::OpenOptions::new();
        let accmode = flags & oflag::ACCMODE;
        oo.read(accmode != 1).write(accmode != 0);
        oo.append(flags & oflag::APPEND != 0);
        if flags & oflag::TRUNC != 0 {
            oo.truncate(true);
        }
        if flags & oflag::CREAT != 0 {
            oo.create(true);
            // O_EXCL は O_CREAT と組のときだけ排他生成になる。
            if flags & oflag::EXCL != 0 {
                oo.create_new(true);
            }
        }
        match oo.open(&host) {
            Ok(f) => {
                // O_DIRECTORY: ディレクトリでなければ ENOTDIR。
                if flags & oflag::DIRECTORY != 0 {
                    match f.metadata() {
                        Ok(m) if m.is_dir() => {}
                        Ok(_) => return Err(errno::ENOTDIR),
                        Err(e) => return Err(host_errno(e)),
                    }
                }
                // O_CREAT で新規作成したときだけ mode & ~umask を適用
                // （既存ファイルの mode は変えない）。
                if flags & oflag::CREAT != 0 && !existed {
                    let _ = polyisa_host::fchmod(&f, (mode & 0o7777) & !self.umask);
                }
                let fd = self.alloc_file(f)?;
                self.fds.remember_path(fd, host);
                Ok(u64::from(fd))
            }
            Err(e) => Err(host_errno(e)),
        }
    }

    /// `dup`/`dup2`/`dup3`。`strict` は dup3（同値 EINVAL、flags は
    /// O_CLOEXEC のみ許可）。dup2 は同値でも有効 fd なら成功。
    /// newfd が 0–2 なら標準入出力の差し替え（リダイレクト）。
    fn sys_dup(
        &mut self,
        _env: &mut BareEnv,
        fd: u32,
        newfd: Option<u32>,
        strict: bool,
    ) -> Result<u64, u32> {
        let g = if fd < 3 {
            self.std_clone(fd)?
        } else {
            self.fds
                .file(fd)
                .ok_or(errno::EBADF)?
                .try_clone()
                .map_err(|_| errno::EIO)?
        };
        let nfd = match newfd {
            Some(n) => {
                if n == fd {
                    if strict {
                        return Err(errno::EINVAL);
                    }
                    return Ok(u64::from(n));
                }
                if n >= Self::MAX_FD {
                    return Err(errno::EBADF);
                }
                if n < 3 {
                    self.std_fds[n as usize] = Some(g);
                    self.std_closed[n as usize] = false;
                } else {
                    self.fds.place_close(n, polyisa_kernel::FdTarget::File(g));
                    self.dir_scans.remove(&n);
                }
                n
            }
            None => self.alloc_file(g)?,
        };
        if nfd >= 3 {
            // 複製先に複製元のパスを継承。元にパスがなければ
            // 置き換えた先の古いパスを消す。
            match self.fds.path_of(fd).map(str::to_string) {
                Some(p) => self.fds.remember_path(nfd, p),
                None => self.fds.forget_path(nfd),
            }
        }
        Ok(u64::from(nfd))
    }

    /// `fcntl`。複製（F_DUPFD=0、F_DUPFD_CLOEXEC=1030）だけ実装し、
    /// フラグ系は成功だけ返す。
    fn sys_fcntl(&mut self, _env: &mut BareEnv, fd: u32, cmd: u32, arg: u64) -> Result<u64, u32> {
        match cmd {
            // F_DUPFD=0 / F_DUPFD_CLOEXEC=1030 は arg 以上の最小空きfd。
            0 | 1030 => {
                if arg >= u64::from(Self::MAX_FD) {
                    return Err(errno::EINVAL);
                }
                let g = if fd < 3 {
                    self.std_clone(fd)?
                } else {
                    self.fds
                        .file(fd)
                        .ok_or(errno::EBADF)?
                        .try_clone()
                        .map_err(|_| errno::EIO)?
                };
                // arg 未満のスロットは使えない。空きがなければ
                // 表の末尾か arg の大きい方に伸ばす。
                let nfd = match self.fds.first_hole_where(|i| (3 + i) as u64 >= arg) {
                    Some(i) => 3 + i as u32,
                    None => (3 + self.fds.len() as u64).max(arg).max(3) as u32,
                };
                if nfd >= Self::MAX_FD {
                    return Err(errno::EMFILE);
                }
                self.fds.place_close(nfd, polyisa_kernel::FdTarget::File(g));
                if let Some(p) = self.fds.path_of(fd).map(str::to_string) {
                    self.fds.remember_path(nfd, p);
                }
                Ok(u64::from(nfd))
            }
            1..=4 => Ok(0),
            _ => Err(errno::EINVAL),
        }
    }

    /// `ioctl`。端末の判定に使う TCGETS 系だけ ENOTTY を返す
    /// （エミュレータは端末を持たない）。
    fn sys_ioctl(
        &mut self,
        _env: &mut BareEnv,
        fd: u32,
        _req: u64,
        _argp: u64,
    ) -> Result<u64, u32> {
        if !self.fd_open(fd) {
            return Err(errno::EBADF);
        }
        Err(errno::ENOTTY)
    }

    /// `stat`/`stat64`/`fstatat64` の共通部。`at_empty` は
    /// AT_EMPTY_PATH — パスが空なら dirfd 自身を対象にする。
    #[allow(clippy::too_many_arguments)]
    fn sys_stat(
        &mut self,
        env: &mut BareEnv,
        dirfd: i64,
        path_addr: u64,
        out: u64,
        lstat: bool,
        wide: bool,
        at_empty: bool,
    ) -> Result<u64, u32> {
        let path = self.read_cstr(env, path_addr)?;
        let md = if path.is_empty() && at_empty && dirfd >= 0 {
            // AT_EMPTY_PATH: dirfd のファイル自体を stat する。
            match self.file_of(dirfd as u32) {
                Some(f) => polyisa_host::fstat(f).map_err(host_errno)?,
                None => return Err(errno::EBADF),
            }
        } else {
            if path.is_empty() {
                return Err(errno::ENOENT);
            }
            let host = self.host_path_at(dirfd, &path)?;
            let r = if lstat {
                polyisa_host::lstat(&host)
            } else {
                polyisa_host::stat(&host)
            };
            r.map_err(host_errno)?
        };
        if self.put_stat(env, out, &md, wide) {
            Ok(0)
        } else {
            Err(errno::EFAULT)
        }
    }

    /// `fstat`/`fstat64`。
    fn sys_fstat(&mut self, env: &mut BareEnv, fd: u32, out: u64, wide: bool) -> Result<u64, u32> {
        if fd < 3 && self.std_closed[fd as usize] {
            return Err(errno::EBADF);
        }
        let md = match self.file_of(fd) {
            Some(f) => polyisa_host::fstat(f).map_err(host_errno)?,
            None if fd < 3 => polyisa_host::stat("/dev/null").map_err(host_errno)?,
            None => return Err(errno::EBADF),
        };
        if self.put_stat(env, out, &md, wide) {
            Ok(0)
        } else {
            Err(errno::EFAULT)
        }
    }

    /// Alpha の `struct stat`（80B、ino は 32 ビット）または
    /// `struct stat64`（136B）を書く。
    // Ref: SRC-LINUX (7.3) — arch/alpha/include/uapi/asm/stat.h.
    fn put_stat(&mut self, env: &mut BareEnv, a: u64, m: &polyisa_host::Stat, wide: bool) -> bool {
        let mut ok = true;
        if wide {
            // stat64: dev0, ino8, rdev16, size24, blocks32, mode40,
            // uid44, gid48, blksize52, nlink56, pad0 60, atime64,
            // atime_nsec72, mtime80, mtime_nsec88, ctime96, ctime_nsec104。
            ok &= self.put64(env, a, m.dev);
            ok &= self.put64(env, a + 8, m.ino);
            ok &= self.put64(env, a + 16, m.rdev);
            ok &= self.put64(env, a + 24, m.size);
            ok &= self.put64(env, a + 32, m.blocks);
            ok &= self.put32(env, a + 40, m.mode);
            ok &= self.put32(env, a + 44, m.uid);
            ok &= self.put32(env, a + 48, m.gid);
            ok &= self.put32(env, a + 52, m.blksize as u32);
            ok &= self.put32(env, a + 56, m.nlink as u32);
            ok &= self.put32(env, a + 60, 0);
            ok &= self.put64(env, a + 64, m.atime as u64);
            ok &= self.put64(env, a + 72, m.atime_nsec as u64);
            ok &= self.put64(env, a + 80, m.mtime as u64);
            ok &= self.put64(env, a + 88, m.mtime_nsec as u64);
            ok &= self.put64(env, a + 96, m.ctime as u64);
            ok &= self.put64(env, a + 104, m.ctime_nsec as u64);
            // __unused[3]（112–136）はゼロ埋め。
            ok &= self.write_bytes(env, a + 112, &[0u8; 24]);
        } else {
            // stat: dev u32@0, ino u32@4, mode u32@8, nlink u32@12,
            // uid@16, gid@20, rdev u32@24, pad@28, size i64@32,
            // atime@40, mtime@48, ctime@56, blksize u32@64,
            // blocks u32@68, flags@72, gen@76。
            ok &= self.put32(env, a, m.dev as u32);
            ok &= self.put32(env, a + 4, m.ino as u32);
            ok &= self.put32(env, a + 8, m.mode);
            ok &= self.put32(env, a + 12, m.nlink as u32);
            ok &= self.put32(env, a + 16, m.uid);
            ok &= self.put32(env, a + 20, m.gid);
            ok &= self.put32(env, a + 24, m.rdev as u32);
            ok &= self.put32(env, a + 28, 0);
            ok &= self.put64(env, a + 32, m.size);
            ok &= self.put64(env, a + 40, m.atime as u64);
            ok &= self.put64(env, a + 48, m.mtime as u64);
            ok &= self.put64(env, a + 56, m.ctime as u64);
            ok &= self.put32(env, a + 64, m.blksize as u32);
            ok &= self.put32(env, a + 68, m.blocks as u32);
            ok &= self.put32(env, a + 72, 0);
            ok &= self.put32(env, a + 76, 0);
        }
        ok
    }

    /// 単一パス引数のファイル操作（mkdir/rmdir/unlink/truncate 等）。
    fn sys_path_op(
        &mut self,
        env: &mut BareEnv,
        dirfd: i64,
        path_addr: u64,
        op: impl FnOnce(&str) -> std::io::Result<()>,
    ) -> Result<u64, u32> {
        let path = self.read_cstr(env, path_addr)?;
        let host = self.host_path_at(dirfd, &path)?;
        op(&host).map(|_| 0).map_err(host_errno)
    }

    /// 2 パス引数のファイル操作（rename/link）。
    fn sys_path_op2(
        &mut self,
        env: &mut BareEnv,
        old_dirfd: i64,
        old_addr: u64,
        new_dirfd: i64,
        new_addr: u64,
        op: impl FnOnce(&str, &str) -> std::io::Result<()>,
    ) -> Result<u64, u32> {
        let old_p = self.read_cstr(env, old_addr)?;
        let new_p = self.read_cstr(env, new_addr)?;
        let a = self.host_path_at(old_dirfd, &old_p)?;
        let b = self.host_path_at(new_dirfd, &new_p)?;
        op(&a, &b).map(|_| 0).map_err(host_errno)
    }

    /// `chmod`/`fchmodat`。
    fn sys_chmod(
        &mut self,
        env: &mut BareEnv,
        dirfd: i64,
        path_addr: u64,
        mode: u32,
    ) -> Result<u64, u32> {
        let path = self.read_cstr(env, path_addr)?;
        let host = self.host_path_at(dirfd, &path)?;
        polyisa_host::chmod(&host, mode)
            .map(|_| 0)
            .map_err(host_errno)
    }

    /// `access`/`faccessat`（mode: F_OK=0, X_OK=1, W_OK=2, R_OK=4）。
    fn sys_access(
        &mut self,
        env: &mut BareEnv,
        dirfd: i64,
        path_addr: u64,
        mode: u64,
    ) -> Result<u64, u32> {
        let path = self.read_cstr(env, path_addr)?;
        let host = self.host_path_at(dirfd, &path)?;
        match polyisa_host::stat(&host) {
            Ok(m) => {
                let need = match mode {
                    0 => 0,
                    1 => 0o111,
                    2 => 0o222,
                    4 => 0o444,
                    5 => 0o555,
                    6 => 0o666,
                    7 => 0o777,
                    _ => return Err(errno::EINVAL),
                };
                // X_OK の実行ビットはディレクトリでは検索許可の意味。
                if need == 0 || m.mode & need != 0 {
                    Ok(0)
                } else {
                    Err(errno::EACCES)
                }
            }
            Err(e) => Err(host_errno(e)),
        }
    }

    /// `readlink`/`readlinkat`。/proc/self/exe は exe_path、
    /// /proc/self/fd/N は fd のパス、それ以外はホストの readlink。
    fn sys_readlink(
        &mut self,
        env: &mut BareEnv,
        dirfd: i64,
        path_addr: u64,
        buf: u64,
        len: u64,
    ) -> Result<u64, u32> {
        let path = self.read_cstr(env, path_addr)?;
        let gs = String::from_utf8_lossy(&path).into_owned();
        let target: Result<String, u32> = if gs == "/proc/self/exe" {
            Ok(self.exe_path.clone())
        } else if let Some(rest) = gs.strip_prefix("/proc/self/fd/") {
            match rest.parse::<u32>() {
                Ok(fd) if fd <= 2 => Ok("/dev/null".to_string()),
                Ok(fd) => self
                    .fds
                    .path_of(fd)
                    .map(str::to_string)
                    .ok_or(errno::ENOENT),
                Err(_) => Err(errno::ENOENT),
            }
        } else {
            let host = self.host_path_at(dirfd, &path)?;
            std::fs::read_link(&host)
                .map(|p| p.display().to_string())
                .map_err(host_errno)
        };
        let t = target?;
        let n = (t.len() as u64).min(len) as usize;
        if !self.write_bytes(env, buf, &t.as_bytes()[..n]) {
            return Err(errno::EFAULT);
        }
        Ok(n as u64)
    }

    /// `getdents64`（linux_dirent64: u64 ino, u64 off, u16 reclen,
    /// u8 type, name\0）を詰める。fd ごとに走査位置を覚え、
    /// 末尾に達したら 0 を返して呼び出し側のループを終わらせる。
    fn sys_getdents64(
        &mut self,
        env: &mut BareEnv,
        fd: u32,
        buf: u64,
        count: u64,
    ) -> Result<u64, u32> {
        // fd の検査が先（kernel の順序: 不正 fd は EBADF）。
        if self.fds.file(fd).is_none() {
            return Err(errno::EBADF);
        }
        // 1 レコードすら入らない count は EINVAL（EOF ではない）。
        if count < 24 {
            return Err(errno::EINVAL);
        }
        if !self.dir_scans.contains_key(&fd) {
            let path = self
                .fds
                .path_of(fd)
                .map(str::to_string)
                .ok_or(errno::ENOTDIR)?;
            let rd = std::fs::read_dir(&path).map_err(host_errno)?;
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
            self.dir_scans.insert(fd, (entries, 0));
        }
        let (entries, pos) = self.dir_scans.get_mut(&fd).unwrap();
        let limit = usize::try_from(count).unwrap_or(usize::MAX);
        let mut out = Vec::new();
        let mut i = *pos;
        while i < entries.len() {
            let (ino, nm, t) = &entries[i];
            let name = nm.as_bytes();
            let reclen = (19 + name.len() + 1).div_ceil(8) * 8;
            if out.len() + reclen > limit {
                break;
            }
            out.extend_from_slice(&ino.to_le_bytes());
            out.extend_from_slice(&(i as u64 + 1).to_le_bytes());
            out.extend_from_slice(&(reclen as u16).to_le_bytes());
            out.push(*t);
            out.extend_from_slice(name);
            out.push(0);
            while out.len() % 8 != 0 {
                out.push(0);
            }
            i += 1;
        }
        *pos = i;
        if !self.write_bytes(env, buf, &out) {
            return Err(errno::EFAULT);
        }
        Ok(out.len() as u64)
    }

    /// `mmap`（sys_osf_mmap：最終引数はバイトオフセット）。
    // Ref: SRC-LINUX (7.3) — sys_osf_mmap。
    fn sys_mmap(&mut self, env: &mut BareEnv, args: &[u64; 6]) -> Result<u64, u32> {
        let (addr, len, prot, flags) = (args[0], args[1], args[2] as u32, args[3] as u32);
        let (fd, off) = (args[4] as u32 as i32 as i64, args[5]);
        if len == 0 || len > (1 << 30) {
            return Err(if len == 0 {
                errno::EINVAL
            } else {
                errno::ENOMEM
            });
        }
        if flags & mman::MAP_FIXED != 0 && addr & 0xfff != 0 {
            return Err(errno::EINVAL); // MAP_FIXED はページ整列必須
        }
        if flags & mman::MAP_ANONYMOUS == 0 {
            // ファイル写像は fd を写像前に検査する（kernel と同順）。
            if fd < 0 || self.file_of(fd as u32).is_none() {
                return Err(errno::EBADF);
            }
        }
        let pages = len.div_ceil(4096);
        let base = if flags & mman::MAP_FIXED != 0 {
            addr & !0xfff
        } else {
            // 既存写像（ヒープや先行 mmap）を踏まない隙間を上向きに探す。
            // map は既存ページを黙って置き換えるため、先に検査する。
            let mut b = self.mmap_next.max(self.brk_start + 0x400_0000);
            let mut tries = 0;
            while (b..b + pages * 4096)
                .step_by(4096)
                .any(|a| env.backend.mem.is_mapped(polyisa_mem::PageNo(a / 4096)))
            {
                tries += 1;
                if tries > 4096 {
                    return Err(errno::ENOMEM);
                }
                b += 4096;
            }
            self.mmap_next = b + pages * 4096;
            b
        };
        let mut p = 0u8;
        if prot & mman::PROT_READ != 0 {
            p |= Perms::R.0;
        }
        if prot & mman::PROT_WRITE != 0 {
            p |= Perms::W.0;
        }
        if prot & mman::PROT_EXEC != 0 {
            p |= Perms::X.0;
        }
        if env
            .backend
            .mem
            .map(VirtAddr(base), pages, Perms(p))
            .is_err()
        {
            return Err(errno::ENOMEM);
        }
        if flags & mman::MAP_ANONYMOUS == 0 {
            // ファイル裏付けの読み込みは fd の位置を動かさない。
            let f = self.file_of(fd as u32).unwrap();
            let mut buf = vec![0u8; len as usize];
            let n = polyisa_host::pread(f, &mut buf, off).map_err(host_errno)?;
            buf.truncate(n);
            if !self.write_bytes(env, base, &buf) {
                return Err(errno::EFAULT);
            }
        }
        Ok(base)
    }

    /// `munmap`。
    fn sys_munmap(&mut self, env: &mut BareEnv, addr: u64, len: u64) -> Result<u64, u32> {
        if len == 0 || addr & 0xfff != 0 {
            return Err(errno::EINVAL); // addr はページ整列必須
        }
        let Some(end) = addr.checked_add(len) else {
            return Err(errno::EINVAL);
        };
        if len > (1 << 30) {
            return Err(errno::ENOMEM); // 非現実的サイズは拒否（host DoS 回避）
        }
        let pages = end.div_ceil(4096) - addr / 4096;
        env.backend.mem.unmap(VirtAddr(addr), pages);
        Ok(0)
    }

    /// `mprotect`。範囲はページ境界に丸める。
    fn sys_mprotect(
        &mut self,
        env: &mut BareEnv,
        addr: u64,
        len: u64,
        prot: u32,
    ) -> Result<u64, u32> {
        let lo = addr & !0xfff;
        let Some(end) = addr.checked_add(len) else {
            return Err(errno::EINVAL);
        };
        let hi = end.div_ceil(4096) * 4096;
        if hi <= lo {
            return Err(errno::EINVAL);
        }
        let mut p = 0u8;
        if prot & mman::PROT_READ != 0 {
            p |= Perms::R.0;
        }
        if prot & mman::PROT_WRITE != 0 {
            p |= Perms::W.0;
        }
        if prot & mman::PROT_EXEC != 0 {
            p |= Perms::X.0;
        }
        match env
            .backend
            .mem
            .protect(VirtAddr(lo), (hi - lo) / 4096, Perms(p))
        {
            Ok(()) => Ok(0),
            Err(_) => Err(errno::ENOMEM),
        }
    }

    /// `mincore`。全写像ページは常駐なので vec に 1 を詰める。
    fn sys_mincore(
        &mut self,
        env: &mut BareEnv,
        addr: u64,
        len: u64,
        vec: u64,
    ) -> Result<u64, u32> {
        // addr はページ整列必須。
        if addr & 0xfff != 0 {
            return Err(errno::EINVAL);
        }
        let pages = len.div_ceil(0x2000).min(1 << 20);
        if !self.write_bytes(env, vec, &vec![1u8; pages as usize]) {
            return Err(errno::EFAULT);
        }
        Ok(0)
    }

    /// `getrlimit`/`prlimit64` の struct rlimit（u64×2）。
    /// 資源番号は Alpha 独自の順序（STACK=3, CORE=4, RSS=5,
    /// NOFILE=6, AS=7, NPROC=8, MEMLOCK=9）。
    // Ref: SRC-LINUX (7.3) — arch/alpha/include/uapi/asm/resource.h.
    fn put_rlimit(&mut self, env: &mut BareEnv, addr: u64, res: u64) -> Result<u64, u32> {
        // Alpha の RLIM_INFINITY は 0x7fffffffffffffff。
        const RLIM_INFINITY: u64 = 0x7fff_ffff_ffff_ffff;
        let (cur, max) = match res {
            // RLIMIT_STACK はスタック窓と一致させる。
            3 => (8 << 20, RLIM_INFINITY),
            // RLIMIT_NOFILE は FdTable の上限（GETDTABLESIZE）と一致。
            6 => (1024, 1024),
            _ => (RLIM_INFINITY, RLIM_INFINITY),
        };
        if !self.put64(env, addr, cur) || !self.put64(env, addr + 8, max) {
            return Err(errno::EFAULT);
        }
        Ok(0)
    }

    /// timespec（u64×2）を書く。
    fn put_timespec(
        &mut self,
        env: &mut BareEnv,
        addr: u64,
        sec: u64,
        nsec: u64,
    ) -> Result<u64, u32> {
        if !self.put64(env, addr, sec) || !self.put64(env, addr + 8, nsec) {
            return Err(errno::EFAULT);
        }
        Ok(0)
    }

    /// `clock_gettime`。全クロック id を実時間に揃える — 単一
    /// プロセスのエミュレータでは monotonic/boottime と wall の
    /// 区別に意味がなく、busybox `date` のように wall 値を期待
    /// する呼び出し側が正しい値を得られる。
    fn sys_clock_gettime(&mut self, env: &mut BareEnv, _clk: u64, tp: u64) -> Result<u64, u32> {
        // clock_gettime は tp==NULL で EFAULT（gettimeofday と違い
        // copy_to_user が無条件）。
        if tp == 0 {
            return Err(errno::EFAULT);
        }
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        self.put_timespec(env, tp, d.as_secs(), u64::from(d.subsec_nanos()))
    }

    /// `osf_gettimeofday` は 32 ビットの timeval（sec u32, usec u32）
    /// を書く。nr 359 とは別レイアウト。tz はゼロ埋めの timezone。
    // Ref: SRC-LINUX (7.3) — osf_sys.c osf_gettimeofday。
    fn sys_osf_gettimeofday(&mut self, env: &mut BareEnv, tv: u64, tz: u64) -> Result<u64, u32> {
        if tz != 0 && !self.write_bytes(env, tz, &[0u8; 8]) {
            return Err(errno::EFAULT);
        }
        if tv == 0 {
            return Ok(0);
        }
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        if !self.put32(env, tv, d.as_secs() as u32) || !self.put32(env, tv + 4, d.subsec_micros()) {
            return Err(errno::EFAULT);
        }
        Ok(0)
    }

    /// `gettimeofday`（tv = {u64 sec, u64 usec}。tz はゼロ埋めの
    /// struct timezone を書く）。
    fn sys_gettimeofday(&mut self, env: &mut BareEnv, tv: u64, tz: u64) -> Result<u64, u32> {
        if tz != 0 && !self.write_bytes(env, tz, &[0u8; 8]) {
            return Err(errno::EFAULT);
        }
        if tv == 0 {
            return Ok(0);
        }
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        if !self.put64(env, tv, d.as_secs())
            || !self.put64(env, tv + 8, u64::from(d.subsec_micros()))
        {
            return Err(errno::EFAULT);
        }
        Ok(0)
    }

    /// `getrandom`。
    fn sys_getrandom(&mut self, env: &mut BareEnv, buf: u64, len: u64) -> Result<u64, u32> {
        let mut data = vec![0u8; len.min(1 << 20) as usize];
        match std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut data)) {
            Ok(()) => {
                if !self.write_bytes(env, buf, &data) {
                    return Err(errno::EFAULT);
                }
                Ok(data.len() as u64)
            }
            Err(e) => Err(host_errno(e)),
        }
    }

    /// `uname`。Linux の utsname を 6 個の 65 バイト領域に書く。
    // Ref: SRC-LINUX (7.3) — struct new_utsname。
    fn sys_uname(&mut self, env: &mut BareEnv, addr: u64) -> Result<u64, u32> {
        // Alpha の machine 名は "alpha"。
        const FIELDS: [&str; 6] = ["Linux", "polyisa", "7.3.0", "#1 polyisa", "alpha", "(none)"];
        let mut image = [0u8; 65 * 6];
        for (i, s) in FIELDS.iter().enumerate() {
            let b = s.as_bytes();
            image[65 * i..65 * i + b.len()].copy_from_slice(b);
        }
        if !self.write_bytes(env, addr, &image) {
            return Err(errno::EFAULT);
        }
        Ok(0)
    }

    /// `sysinfo`（uptime@0、loads[3]@8、totalram@32、freeram@40、
    /// mem_unit@104）。
    fn sys_sysinfo(&mut self, env: &mut BareEnv, addr: u64) -> Result<u64, u32> {
        let secs = self.mono_start.map(|s| s.elapsed().as_secs()).unwrap_or(0);
        let mut img = [0u8; 112];
        img[..8].copy_from_slice(&(secs as i64).to_le_bytes());
        img[32..40].copy_from_slice(&(512u64 << 20).to_le_bytes()); // totalram
        img[40..48].copy_from_slice(&(256u64 << 20).to_le_bytes()); // freeram
        img[104..108].copy_from_slice(&1u32.to_le_bytes()); // mem_unit
        if !self.write_bytes(env, addr, &img[..112]) {
            return Err(errno::EFAULT);
        }
        Ok(0)
    }

    /// `times`（tms: utime/stime/cutime/cstime の long×4）。
    fn sys_times(&mut self, env: &mut BareEnv, addr: u64) -> Result<u64, u32> {
        let us = self.mono_us();
        let ticks = us / 10_000; // USER_HZ=100 換算
        let mut img = [0u8; 32];
        img[..8].copy_from_slice(&ticks.to_le_bytes());
        if addr != 0 && !self.write_bytes(env, addr, &img) {
            return Err(errno::EFAULT);
        }
        Ok(ticks)
    }

    /// `statfs`/`statfs64`（u64 フィールドの並び）。`is_path` が
    /// 真なら `target` は検査するパスのポインタ、偽なら fd。
    /// `sz` は statfs64 のバッファ宣言サイズ（statfs は構造体の
    /// 固定サイズ）— 書き込みはそれを越えない。
    fn sys_statfs(
        &mut self,
        env: &mut BareEnv,
        addr: u64,
        wide: bool,
        target: u64,
        is_path: bool,
        sz: u64,
    ) -> Result<u64, u32> {
        if is_path {
            let path = self.read_cstr(env, target)?;
            let host = self.host_path(&path);
            polyisa_host::stat(&host).map_err(host_errno)?; // ENOENT 等
        } else if target < 3 {
            if self.std_closed[target as usize] {
                return Err(errno::EBADF);
            }
        } else if self.fds.file(target as u32).is_none() {
            return Err(errno::EBADF);
        }
        let mut img = [0u8; 128];
        img[..8].copy_from_slice(&0xEF53u64.to_le_bytes());
        img[8..16].copy_from_slice(&0x2000u64.to_le_bytes()); // bsize
        img[16..24].copy_from_slice(&0x10_0000u64.to_le_bytes()); // blocks
        img[24..32].copy_from_slice(&0x8_0000u64.to_le_bytes()); // bfree
        img[32..40].copy_from_slice(&0x8_0000u64.to_le_bytes()); // bavail
        img[40..48].copy_from_slice(&0x1_0000u64.to_le_bytes()); // files
        img[48..56].copy_from_slice(&0x1_0000u64.to_le_bytes()); // ffree
        img[64..72].copy_from_slice(&255u64.to_le_bytes()); // namelen
        img[72..80].copy_from_slice(&0x2000u64.to_le_bytes()); // frsize
        let n = if wide { 128 } else { 96 };
        let n = n.min(usize::try_from(sz).unwrap_or(usize::MAX));
        if !self.write_bytes(env, addr, &img[..n]) {
            return Err(errno::EFAULT);
        }
        Ok(0)
    }

    /// `getcwd`。cwd を絶対パスとして返す（未 chdir なら "/"）。
    fn sys_getcwd(&mut self, env: &mut BareEnv, buf: u64, len: u64) -> Result<u64, u32> {
        let s = if self.cwd.is_empty() {
            "/".to_string()
        } else {
            self.cwd.clone()
        };
        let n = s.len() + 1;
        if (n as u64) > len {
            return Err(errno::ERANGE);
        }
        if !self.write_bytes(env, buf, s.as_bytes())
            || !self.write_bytes(env, buf + s.len() as u64, &[0])
        {
            return Err(errno::EFAULT);
        }
        Ok(n as u64)
    }

    /// `chdir`/`fchdir`。ゲストの絶対パスとして cwd を更新する。
    fn sys_chdir(&mut self, env: &mut BareEnv, path_addr: u64) -> Result<u64, u32> {
        let path = self.read_cstr(env, path_addr)?;
        let host = self.host_path(&path);
        match polyisa_host::stat(&host) {
            Ok(m) if m.mode & 0o170000 == 0o040000 => {
                // ゲスト視点の絶対パスを覚える。
                let g = String::from_utf8_lossy(&path).into_owned();
                self.cwd = if g.starts_with('/') {
                    g
                } else if self.cwd.is_empty() || self.cwd == "/" {
                    format!("/{g}")
                } else {
                    format!("{}/{g}", self.cwd.trim_end_matches('/'))
                };
                Ok(0)
            }
            Ok(_) => Err(errno::ENOTDIR),
            Err(e) => Err(host_errno(e)),
        }
    }

    /// `utimensat`/`futimesat`/`utimes`。times==NULL は現在時刻。
    /// futimesat で path が空なら dirfd 自体のファイルを対象にする
    /// （futimens 相当）。
    // Ref: SRC-LINUX (7.3) — utimensat(2)。
    fn sys_utimens(
        &mut self,
        env: &mut BareEnv,
        dirfd: i64,
        path_addr: u64,
        times_addr: u64,
        timeval: bool,
    ) -> Result<u64, u32> {
        const UTIME_NOW: u64 = (1 << 30) - 1;
        const UTIME_OMIT: u64 = (1 << 30) - 2;
        let now = std::time::SystemTime::now();
        // timespec[2]（utimes は timeval[2] で sub 値が usec）
        let (mut atime, mut mtime) = (Some(now), Some(now));
        if times_addr != 0 {
            let mut read_ts = |a: u64| -> Result<Option<std::time::SystemTime>, u32> {
                let sec = self.read_u(env, a).ok_or(errno::EFAULT)? as i64;
                let sub = self.read_u(env, a + 8).ok_or(errno::EFAULT)?;
                let nsec = if timeval {
                    // usec → nsec。溢れは EINVAL（timespec64_valid と同じ）。
                    sub.checked_mul(1000).ok_or(errno::EINVAL)?
                } else {
                    sub
                };
                Ok(match nsec {
                    UTIME_NOW => Some(now),
                    UTIME_OMIT => None,
                    // tv_nsec/tv_usec は 1e9 未満必須。
                    n if n < 1_000_000_000 => Some(
                        std::time::UNIX_EPOCH
                            + std::time::Duration::new(sec.max(0) as u64, n as u32),
                    ),
                    _ => return Err(errno::EINVAL),
                })
            };
            atime = read_ts(times_addr)?;
            mtime = read_ts(times_addr + 16)?;
        }
        let mut ft = std::fs::FileTimes::new();
        if let Some(a) = atime {
            ft = ft.set_accessed(a);
        }
        if let Some(m) = mtime {
            ft = ft.set_modified(m);
        }
        // path==NULL または空文字列は futimens 相当（dirfd のファイル）。
        // path_addr != 0 の不正ポインタは EFAULT。
        let path = if path_addr == 0 {
            Vec::new()
        } else {
            self.read_cstr(env, path_addr)?
        };
        if path.is_empty() {
            // futimens 相当: dirfd のファイル。
            if dirfd < 0 {
                return Err(errno::EBADF);
            }
            let f = self.fds.file(dirfd as u32).ok_or(errno::EBADF)?;
            return f.set_times(ft).map(|_| 0).map_err(host_errno);
        }
        let host = self.host_path_at(dirfd, &path)?;
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&host)
            .map_err(host_errno)?;
        f.set_times(ft).map(|_| 0).map_err(host_errno)
    }

    /// `osf_set_program_attributes`。bss 末尾を新しい start_brk と
    /// brk にする（OSF ABI の初期化手続き）。
    // Ref: SRC-LINUX (7.3) — osf_sys.c sys_osf_set_program_attributes。
    fn sys_set_program_attributes(&mut self, _env: &mut BareEnv, bss: u64, len: u64) -> u64 {
        let b = bss + len;
        self.brk_start = b;
        self.heap_end = b;
        0
    }

    /// `nanosleep`/`clock_nanosleep`。req を読んで EFAULT/EINVAL を
    /// 返せるようにし、実時間は眠らず rem を 0 にする（速度優先）。
    fn sys_nanosleep(&mut self, env: &mut BareEnv, req: u64, rem: u64) -> Result<u64, u32> {
        // req の妥当性検査（不正ポインタは EFAULT）。
        if req == 0 || self.read_u(env, req).is_none() {
            return Err(errno::EFAULT);
        }
        // tv_nsec は 1e9 未満必須（timespec64_valid）。
        let nsec = self.read_u(env, req + 8).ok_or(errno::EFAULT)?;
        if nsec >= 1_000_000_000 {
            return Err(errno::EINVAL);
        }
        if rem != 0 && (!self.put64(env, rem, 0) || !self.put64(env, rem + 8, 0)) {
            return Err(errno::EFAULT);
        }
        Ok(0)
    }

    /// `rt_sigaction`。oldact に SIG_DFL 相当を書く。
    fn sys_rt_sigaction(
        &mut self,
        env: &mut BareEnv,
        _act: u64,
        oldact: u64,
        sz: u64,
    ) -> Result<u64, u32> {
        // rt_sigaction の sigsetsize は 8 固定（別サイズは EINVAL）。
        if sz != 8 {
            return Err(errno::EINVAL);
        }
        if oldact != 0 && !self.write_bytes(env, oldact, &[0u8; 32]) {
            return Err(errno::EFAULT);
        }
        Ok(0)
    }

    /// `rt_sigprocmask`（SIG_BLOCK=0/UNBLOCK=1/SETMASK=2）。
    fn sys_rt_sigprocmask(
        &mut self,
        env: &mut BareEnv,
        how: u64,
        set: u64,
        old: u64,
        sz: u64,
    ) -> Result<u64, u32> {
        // sigset は 8 バイト固定（別サイズは EINVAL）。
        if sz != 8 {
            return Err(errno::EINVAL);
        }
        if old != 0 && !self.put64(env, old, self.sig_mask) {
            return Err(errno::EFAULT);
        }
        if set != 0 {
            let v = self.read_u(env, set).ok_or(errno::EFAULT)?;
            self.sig_mask = match how {
                0 => self.sig_mask | v,
                1 => self.sig_mask & !v,
                2 => v,
                _ => return Err(errno::EINVAL),
            };
        }
        Ok(0)
    }

    /// `getcpu`（cpu/node を NULL 許容で書く）。
    fn sys_getcpu(
        &mut self,
        env: &mut BareEnv,
        cpu: u64,
        node: u64,
        _cache: u64,
    ) -> Result<u64, u32> {
        if cpu != 0 && !self.put32(env, cpu, 0) {
            return Err(errno::EFAULT);
        }
        if node != 0 && !self.put32(env, node, 0) {
            return Err(errno::EFAULT);
        }
        Ok(0)
    }

    /// `gethostname`。
    fn sys_gethostname(&mut self, env: &mut BareEnv, addr: u64, len: u64) -> Result<u64, u32> {
        let n = ("polyisa".len() + 1).min(usize::try_from(len).unwrap_or(usize::MAX));
        if !self.write_bytes(env, addr, &b"polyisa\0"[..n]) {
            return Err(errno::EFAULT);
        }
        Ok(0)
    }

    /// `getpagesize`。Alpha Linux のページは 8KiB。
    // Ref: SRC-LINUX (7.3) — arch/alpha/include/asm/page.h.
    fn sys_getpagesize(&mut self) -> u64 {
        0x2000
    }

    /// ソケット系 syscall を `sock` 正準層へ委譲する。errno ・
    /// SO_*・O_* は OSF 系の独自値。待ち要求は単一スレッド消化で
    /// 進め、進行不能はデッドロックとして報告。
    fn sock_call(&mut self, env: &mut BareEnv, name: &str, args: &[u64; 6]) -> AlphaResult {
        let mut abi = crate::sock::SockAbi::generic(8, Endian::Le);
        abi.errno = |e| host_errno(std::io::Error::from_raw_os_error(e as i32));
        abi.so_to_host = crate::sock::so_odd_to_host;
        abi.sock_nonblock = 0x4; // O_NONBLOCK (OSF)
        abi.sock_cloexec = 1 << 21; // O_CLOEXEC
        let map = crate::sock::unix_path_map("", &self.cwd);
        let t0 = std::time::Instant::now();
        let mono = move || t0.elapsed().as_nanos() as u64;
        match crate::sock::drive(&mut self.fds, &abi, env, name, args, &map, 0, &mono) {
            Some(Ok(v)) => AlphaResult::Value(v),
            Some(Err(e)) => {
                if e == crate::sock::errno::EDEADLK {
                    eprintln!("alpha: deadlock in fd wait");
                }
                AlphaResult::Fail((abi.errno)(e))
            }
            None => AlphaResult::Fail(errno::ENOSYS),
        }
    }

    /// 待ち合わせ系 syscall を `wait` 正準層へ委譲する。errno
    /// ・O_* は OSF 系の独自値。
    fn wait_call(&mut self, env: &mut BareEnv, name: &str, args: &[u64; 6]) -> AlphaResult {
        let mut abi = crate::wait::WaitAbi::generic(8, 8, Endian::Le);
        abi.errno = |e| host_errno(std::io::Error::from_raw_os_error(e as i32));
        abi.nonblock = 0x4; // O_NONBLOCK (OSF)
        abi.cloexec = 1 << 21; // O_CLOEXEC
        let t0 = std::time::Instant::now();
        let mono = move || t0.elapsed().as_nanos() as u64;
        match crate::wait::drive(&mut self.fds, &abi, env, name, args, 0, &mono) {
            Some(Ok(v)) => AlphaResult::Value(v),
            Some(Err(e)) => {
                if e == crate::sock::errno::EDEADLK {
                    eprintln!("alpha: deadlock in fd wait");
                }
                AlphaResult::Fail((abi.errno)(e))
            }
            None => AlphaResult::Fail(errno::ENOSYS),
        }
    }

    /// 番号で振り分ける。戻り値は (v0, a3) の組または終了。
    fn dispatch(&mut self, env: &mut BareEnv, n: u64) -> AlphaResult {
        let args: [u64; 6] = std::array::from_fn(|i| self.arg(env, i));
        if let Some(name) = crate::alpha::name(n)
            && crate::sock::NAMES.contains(&name)
        {
            return self.sock_call(env, name, &args);
        }
        if let Some(name) = crate::alpha::name(n)
            && crate::wait::NAMES.contains(&name)
        {
            return self.wait_call(env, name, &args);
        }
        match n {
            nr::EXIT | nr::EXIT_GROUP => AlphaResult::Exit((args[0] & 0xff) as u32),
            nr::READ => self.sys_read(env, args[0] as u32, args[1], args[2]).into(),
            nr::WRITE => self.sys_write(env, args[0] as u32, args[1], args[2]).into(),
            nr::READV => self.sys_readv(env, args[0] as u32, args[1], args[2]).into(),
            nr::WRITEV => self
                .sys_writev(env, args[0] as u32, args[1], args[2])
                .into(),
            nr::PREAD64 => self
                .sys_pread64(env, args[0] as u32, args[1], args[2], args[3])
                .into(),
            nr::PWRITE64 => self
                .sys_pwrite64(env, args[0] as u32, args[1], args[2], args[3])
                .into(),
            nr::LSEEK => self
                .sys_lseek(env, args[0] as u32, args[1] as i64, args[2])
                .into(),
            nr::CLOSE => self.sys_close(env, args[0] as u32).into(),
            nr::OPEN => self
                .sys_open(env, AT_FDCWD, args[0], args[1] as u32, args[2] as u32)
                .into(),
            nr::OPENAT => self
                .sys_open(env, args[0] as i64, args[1], args[2] as u32, args[3] as u32)
                .into(),
            nr::MKDIR | nr::MKDIRAT => {
                let (d, p, mode) = if n == nr::MKDIR {
                    (AT_FDCWD, args[0], args[1] as u32)
                } else {
                    (args[0] as i64, args[1], args[2] as u32)
                };
                let perm = mode & !self.umask;
                self.sys_path_op(env, d, p, |p| {
                    std::fs::create_dir(p).and_then(|_| polyisa_host::chmod(p, perm))
                })
                .into()
            }
            nr::RMDIR => self
                .sys_path_op(env, AT_FDCWD, args[0], |p| std::fs::remove_dir(p))
                .into(),
            nr::UNLINK => self
                .sys_path_op(env, AT_FDCWD, args[0], |p| std::fs::remove_file(p))
                .into(),
            nr::UNLINKAT => {
                // AT_REMOVEDIR=0x200 なら rmdir 相当。
                let dir = args[2] & 0x200 != 0;
                self.sys_path_op(env, args[0] as i64, args[1], |p| {
                    if dir {
                        std::fs::remove_dir(p)
                    } else {
                        std::fs::remove_file(p)
                    }
                })
                .into()
            }
            nr::RENAME => self
                .sys_path_op2(env, AT_FDCWD, args[0], AT_FDCWD, args[1], |a, b| {
                    std::fs::rename(a, b)
                })
                .into(),
            nr::RENAMEAT => self
                .sys_path_op2(
                    env,
                    args[0] as i64,
                    args[1],
                    args[2] as i64,
                    args[3],
                    |a, b| std::fs::rename(a, b),
                )
                .into(),
            nr::LINK => self
                .sys_path_op2(env, AT_FDCWD, args[0], AT_FDCWD, args[1], |a, b| {
                    std::fs::hard_link(a, b)
                })
                .into(),
            nr::LINKAT => self
                .sys_path_op2(
                    env,
                    args[0] as i64,
                    args[1],
                    args[2] as i64,
                    args[3],
                    |a, b| std::fs::hard_link(a, b),
                )
                .into(),
            nr::SYMLINK | nr::SYMLINKAT => {
                let (dirfd, old_p, new_p) = if n == nr::SYMLINK {
                    (AT_FDCWD, args[0], args[1])
                } else {
                    // symlinkat(old, newdirfd, new)
                    (args[1] as i64, args[0], args[2])
                };
                let target = self.read_cstr(env, old_p);
                let link = self.read_cstr(env, new_p);
                match (target, link) {
                    (Ok(t), Ok(l)) => {
                        let lh = self.host_path_at(dirfd, &l);
                        match lh {
                            Ok(lh) => polyisa_host::symlink(&String::from_utf8_lossy(&t), &lh)
                                .map(|_| 0u64)
                                .map_err(host_errno)
                                .into(),
                            Err(e) => AlphaResult::Fail(e),
                        }
                    }
                    (Err(e), _) | (_, Err(e)) => AlphaResult::Fail(e),
                }
            }
            nr::CHMOD => self
                .sys_chmod(env, AT_FDCWD, args[0], args[1] as u32)
                .into(),
            nr::FCHMODAT => self
                .sys_chmod(env, args[0] as i64, args[1], args[2] as u32)
                .into(),
            nr::FCHMOD => {
                let path = self.fds.path_of(args[0] as u32).map(str::to_string);
                match path {
                    Some(p) => polyisa_host::chmod(&p, args[1] as u32)
                        .map(|_| 0u64)
                        .map_err(host_errno)
                        .into(),
                    None => AlphaResult::Fail(errno::EBADF),
                }
            }
            nr::CHOWN | nr::FCHOWNAT | nr::FCHOWN => AlphaResult::Value(0),
            nr::TRUNCATE => {
                let len = args[1];
                self.sys_path_op(env, AT_FDCWD, args[0], |p| {
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(p)
                        .and_then(|f| f.set_len(len))
                })
                .into()
            }
            nr::FTRUNCATE => match self.file_of(args[0] as u32) {
                Some(f) => f.set_len(args[1]).map(|_| 0u64).map_err(host_errno).into(),
                None => AlphaResult::Fail(errno::EBADF),
            },
            nr::MKNOD | nr::MKNODAT => {
                // 通常ファイルのみ。FIFO/デバイスは EPERM。
                let mode = args[if n == nr::MKNOD { 1 } else { 2 }] as u32;
                if mode & 0o170000 != 0 && mode & 0o170000 != 0o100000 {
                    AlphaResult::Fail(errno::EPERM)
                } else {
                    let (d, p) = if n == nr::MKNOD {
                        (AT_FDCWD, args[0])
                    } else {
                        (args[0] as i64, args[1])
                    };
                    let perm = (mode & 0o7777) & !self.umask;
                    self.sys_path_op(env, d, p, |p| {
                        std::fs::File::create(p).and_then(|_| polyisa_host::chmod(p, perm))
                    })
                    .into()
                }
            }
            nr::DUP => self.sys_dup(env, args[0] as u32, None, false).into(),
            nr::DUP2 => self
                .sys_dup(env, args[0] as u32, Some(args[1] as u32), false)
                .into(),
            nr::DUP3 => {
                // dup3 の flags は O_CLOEXEC(0x200000) のみ許可。
                if args[2] != 0 && args[2] & !oflag::CLOEXEC as u64 != 0 {
                    AlphaResult::Fail(errno::EINVAL)
                } else {
                    self.sys_dup(env, args[0] as u32, Some(args[1] as u32), true)
                        .into()
                }
            }
            nr::FCNTL => self
                .sys_fcntl(env, args[0] as u32, args[1] as u32, args[2])
                .into(),
            nr::IOCTL => self.sys_ioctl(env, args[0] as u32, args[1], args[2]).into(),
            nr::BRK => self.sys_brk(env, args[0]).into(),
            nr::MMAP => self.sys_mmap(env, &args).into(),
            nr::MUNMAP => self.sys_munmap(env, args[0], args[1]).into(),
            nr::MPROTECT => self
                .sys_mprotect(env, args[0], args[1], args[2] as u32)
                .into(),
            nr::MINCORE => self.sys_mincore(env, args[0], args[1], args[2]).into(),
            nr::STAT => self
                .sys_stat(env, AT_FDCWD, args[0], args[1], false, false, false)
                .into(),
            nr::LSTAT => self
                .sys_stat(env, AT_FDCWD, args[0], args[1], true, false, false)
                .into(),
            nr::FSTAT => self.sys_fstat(env, args[0] as u32, args[1], false).into(),
            nr::STAT64 => self
                .sys_stat(env, AT_FDCWD, args[0], args[1], false, true, false)
                .into(),
            nr::LSTAT64 => self
                .sys_stat(env, AT_FDCWD, args[0], args[1], true, true, false)
                .into(),
            nr::FSTAT64 => self.sys_fstat(env, args[0] as u32, args[1], true).into(),
            // AT_SYMLINK_NOFOLLOW=0x100、AT_EMPTY_PATH=0x1000。
            nr::FSTATAT64 => self
                .sys_stat(
                    env,
                    args[0] as i64,
                    args[1],
                    args[2],
                    args[3] & 0x100 != 0,
                    true,
                    args[3] & 0x1000 != 0,
                )
                .into(),
            nr::ACCESS => self.sys_access(env, AT_FDCWD, args[0], args[1]).into(),
            nr::FACCESSAT => self
                .sys_access(env, args[0] as i64, args[1], args[2])
                .into(),
            nr::READLINK => self
                .sys_readlink(env, AT_FDCWD, args[0], args[1], args[2])
                .into(),
            nr::READLINKAT => self
                .sys_readlink(env, args[0] as i64, args[1], args[2], args[3])
                .into(),
            nr::GETDENTS64 => self
                .sys_getdents64(env, args[0] as u32, args[1], args[2])
                .into(),
            nr::GETCWD => self.sys_getcwd(env, args[0], args[1]).into(),
            nr::CHDIR => self.sys_chdir(env, args[0]).into(),
            nr::STATFS => self
                .sys_statfs(env, args[1], false, args[0], true, 96)
                .into(),
            nr::FSTATFS => self
                .sys_statfs(env, args[1], false, args[0], false, 96)
                .into(),
            // statfs64(path, sz, buf) / fstatfs64(fd, sz, buf) は3引数で、
            // 書き込みは呼び出し側が宣言する sz バイトまでに制限する
            // （超えて書くと呼び出し側のスタックを壊す）。
            nr::STATFS64 => self
                .sys_statfs(env, args[2], true, args[0], true, args[1])
                .into(),
            nr::FSTATFS64 => self
                .sys_statfs(env, args[2], true, args[0], false, args[1])
                .into(),
            nr::GETRLIMIT => self.put_rlimit(env, args[1], args[0]).into(),
            nr::PRLIMIT64 => {
                if args[3] != 0 {
                    self.put_rlimit(env, args[3], args[1]).into()
                } else {
                    AlphaResult::Value(0)
                }
            }
            nr::SETRLIMIT => AlphaResult::Value(0),
            nr::UNAME => self.sys_uname(env, args[0]).into(),
            nr::SYSINFO => self.sys_sysinfo(env, args[0]).into(),
            nr::TIMES => self.sys_times(env, args[0]).into(),
            nr::GETTIMEOFDAY => self.sys_gettimeofday(env, args[0], args[1]).into(),
            nr::OSF_GETTIMEOFDAY => self.sys_osf_gettimeofday(env, args[0], args[1]).into(),
            nr::CLOCK_GETTIME => self.sys_clock_gettime(env, args[0], args[1]).into(),
            nr::CLOCK_GETRES => self.put_timespec(env, args[1], 0, 1).into(),
            nr::NANOSLEEP | nr::CLOCK_NANOSLEEP => {
                let (req, rem) = if n == nr::NANOSLEEP {
                    (args[0], args[1])
                } else {
                    (args[2], args[3])
                };
                self.sys_nanosleep(env, req, rem).into()
            }
            nr::GETRANDOM => self.sys_getrandom(env, args[0], args[1]).into(),
            nr::GETPAGESIZE => AlphaResult::Value(self.sys_getpagesize()),
            // getxpid/getxuid/getxgid は第2戻り値を a4($20) に書く
            // （ppid/euid/egid を返す Alpha 固有の syscall ABI）。
            // Ref: SRC-LINUX (arch/alpha/kernel/sys_alpha.c —
            //      getxpid/getxuid/getxgid は第2値を a4 に返す)。
            nr::GETXPID => {
                set_reg(env, 20, 1); // a4 = ppid
                AlphaResult::Value(self.pid())
            }
            nr::GETXUID => {
                set_reg(env, 20, 0); // a4 = euid
                AlphaResult::Value(0)
            }
            nr::GETXGID => {
                set_reg(env, 20, 0); // a4 = egid
                AlphaResult::Value(0)
            }
            nr::GETTID | nr::SET_TID_ADDRESS => AlphaResult::Value(self.pid()),
            nr::GETPPID => AlphaResult::Value(1),
            nr::GETEUID | nr::GETEGID => AlphaResult::Value(0),
            nr::GETRESUID | nr::GETRESGID => {
                // ruid/euid/suid = 0 を3個書く。
                for &a in args.iter().take(3) {
                    if a != 0 && !self.put32(env, a, 0) {
                        return AlphaResult::Fail(errno::EFAULT);
                    }
                }
                AlphaResult::Value(0)
            }
            nr::GETPGRP | nr::GETPGID | nr::GETSID => AlphaResult::Value(self.pid()),
            nr::GETGROUPS => AlphaResult::Value(0),
            nr::SETPGID
            | nr::SETGID
            | nr::SETUID
            | nr::SETREUID
            | nr::SETREGID
            | nr::SETRESUID
            | nr::SETRESGID
            | nr::SETFSUID
            | nr::SETFSGID
            | nr::SETSID
            | nr::SETITIMER
            | nr::CAPSET => AlphaResult::Value(0),
            nr::FCHDIR => {
                // fd のディレクトリへ chdir する（ファイルなら ENOTDIR）。
                match self.fds.path_of(args[0] as u32).map(str::to_string) {
                    Some(p) => match polyisa_host::stat(&p) {
                        Ok(m) if m.mode & 0o170000 == 0o040000 => {
                            self.cwd = p;
                            AlphaResult::Value(0)
                        }
                        Ok(_) => AlphaResult::Fail(errno::ENOTDIR),
                        Err(e) => AlphaResult::Fail(host_errno(e)),
                    },
                    None => AlphaResult::Fail(errno::EBADF),
                }
            }
            nr::GETHOSTNAME => self.sys_gethostname(env, args[0], args[1]).into(),
            nr::GETDTABLESIZE => AlphaResult::Value(1024),
            nr::UTIMES => self
                .sys_utimens(env, AT_FDCWD, args[0], args[1], true)
                .into(),
            nr::FUTIMESAT => self
                .sys_utimens(env, args[0] as i64, args[1], args[2], true)
                .into(),
            nr::UTIMENSAT => self
                .sys_utimens(env, args[0] as i64, args[1], args[2], false)
                .into(),
            nr::GETCPU => self.sys_getcpu(env, args[0], args[1], args[2]).into(),
            nr::RT_SIGACTION => self.sys_rt_sigaction(env, args[1], args[2], args[3]).into(),
            // osf_sigaction(sig, act, oact) は3引数で sigsetsize を
            // 取らない（rt 版と混同すると常に EINVAL になる）。
            // oact には {handler u64, mask u32, flags u32} = 16B を書く。
            // Ref: SRC-LINUX (7.3) — osf_sigaction。
            nr::SIGACTION => {
                if args[2] != 0 && !self.write_bytes(env, args[2], &[0u8; 16]) {
                    return AlphaResult::Fail(errno::EFAULT);
                }
                AlphaResult::Value(0)
            }
            nr::RT_SIGPROCMASK => self
                .sys_rt_sigprocmask(env, args[0], args[1], args[2], args[3])
                .into(),
            nr::RT_SIGPENDING | nr::SIGPENDING => {
                if self.put64(env, args[0], self.sig_mask) {
                    AlphaResult::Value(0)
                } else {
                    AlphaResult::Fail(errno::EFAULT)
                }
            }
            nr::SIGALTSTACK => {
                // ss 指定時はポインタの読み取り可能性を検査する。
                if args[0] != 0 && self.read_u(env, args[0]).is_none() {
                    return AlphaResult::Fail(errno::EFAULT);
                }
                // old に {sp:0, flags:SS_DISABLE, size:0} を書く。
                if args[1] != 0
                    && (!self.put64(env, args[1], 0)
                        || !self.put32(env, args[1] + 8, 2)
                        || !self.put64(env, args[1] + 16, 0))
                {
                    return AlphaResult::Fail(errno::EFAULT);
                }
                AlphaResult::Value(0)
            }
            nr::SIGSUSPEND | nr::RT_SIGSUSPEND => AlphaResult::Fail(errno::EINTR),
            nr::RT_SIGRETURN => AlphaResult::Unimpl,
            // kill 系: 単一プロセスなので自分自身（pid=1 / pid0=自身の
            // グループ / tid=1）への送信は成功、他は ESRCH。
            nr::KILL => {
                if args[0] as i64 == self.pid() as i64 || args[0] == 0 {
                    AlphaResult::Value(0)
                } else {
                    AlphaResult::Fail(errno::ESRCH)
                }
            }
            nr::TKILL => {
                if args[0] == self.pid() {
                    AlphaResult::Value(0)
                } else {
                    AlphaResult::Fail(errno::ESRCH)
                }
            }
            nr::TGKILL => {
                if args[0] == self.pid() && args[1] == self.pid() {
                    AlphaResult::Value(0)
                } else {
                    AlphaResult::Fail(errno::ESRCH)
                }
            }
            nr::SCHED_YIELD => AlphaResult::Value(0),
            // SCHED_OTHER=0, FIFO=1, RR=2, BATCH=3, IDLE=5, DEADLINE=6。
            nr::SCHED_GET_PRIORITY_MAX | nr::SCHED_GET_PRIORITY_MIN => {
                let (mx, mn) = match args[0] {
                    1 | 2 => (99, 1),
                    0 | 3 | 5 | 6 => (0, 0),
                    _ => return AlphaResult::Fail(errno::EINVAL),
                };
                AlphaResult::Value(if n == nr::SCHED_GET_PRIORITY_MAX {
                    mx
                } else {
                    mn
                })
            }
            nr::SCHED_GETPARAM => {
                // param.sched_priority(u32) に 0 を書く。
                if !self.put32(env, args[1], 0) {
                    return AlphaResult::Fail(errno::EFAULT);
                }
                AlphaResult::Value(0)
            }
            nr::SCHED_SETPARAM | nr::SCHED_SETSCHEDULER => AlphaResult::Value(0),
            nr::SCHED_GETSCHEDULER => AlphaResult::Value(0), // SCHED_OTHER
            nr::SCHED_RR_GET_INTERVAL => self.put_timespec(env, args[1], 0, 0).into(),
            nr::SET_ROBUST_LIST | nr::GET_ROBUST_LIST => AlphaResult::Value(0),
            nr::OSF_GETSYSINFO | nr::OSF_SETSYSINFO => AlphaResult::Value(0),
            nr::OSF_SET_PROGRAM_ATTRIBUTES => {
                AlphaResult::Value(self.sys_set_program_attributes(env, args[2], args[3]))
            }
            nr::MADVISE
            | nr::READAHEAD
            | nr::FADVISE64
            | nr::MLOCK
            | nr::MUNLOCK
            | nr::MLOCKALL
            | nr::MUNLOCKALL
            | nr::SYNC => AlphaResult::Value(0),
            nr::FSYNC | nr::FDATASYNC => {
                let fd = args[0] as u32;
                match self.file_of(fd) {
                    Some(f) => match f.sync_all() {
                        Ok(()) => AlphaResult::Value(0),
                        Err(e) => AlphaResult::Fail(host_errno(e)),
                    },
                    // 未差し替えの標準入出力は同期対象なしで成功。
                    None if fd < 3 && !self.std_closed[fd as usize] => AlphaResult::Value(0),
                    None => AlphaResult::Fail(errno::EBADF),
                }
            }
            nr::UMASK => {
                let old = self.umask;
                self.umask = (args[0] as u32) & 0o777;
                AlphaResult::Value(u64::from(old))
            }
            nr::PERSONALITY => AlphaResult::Value(0),
            nr::PRCTL => {
                // PR_GET_NAME=16: comm を buf へ 16B 書く。それ以外は 0。
                if args[0] == 16 {
                    let name = self.proc_name;
                    if !self.write_bytes(env, args[1], &name) {
                        return AlphaResult::Fail(errno::EFAULT);
                    }
                }
                AlphaResult::Value(0)
            }
            // poll/select 系のスタブ: タイムアウト扱いで 0 を返すが、
            // 出力集合・revents もクリアして呼び出し側の判定を守る。
            nr::POLL | nr::PPOLL => {
                // pollfd = {fd i32, events i16, revents i16}（8B）。
                let (fds, nfds) = (args[0], args[1]);
                for i in 0..nfds.min(1024) {
                    let a = fds.wrapping_add(i * 8);
                    if !self.write_bytes(env, a + 6, &[0, 0]) {
                        return AlphaResult::Fail(errno::EFAULT);
                    }
                }
                AlphaResult::Value(0)
            }
            nr::SELECT | nr::PSELECT6 => {
                // 各 fd_set を 0 クリア（kernel は maxfd で切るが
                // スタブなので全幅クリアでよい）。sigmask は触らない。
                let n = args[0];
                let words = n.min(1024).div_ceil(64) * 8;
                for &a in args.iter().take(4).skip(1) {
                    if a != 0 {
                        let z = vec![0u8; words as usize];
                        if !self.write_bytes(env, a, &z) {
                            return AlphaResult::Fail(errno::EFAULT);
                        }
                    }
                }
                AlphaResult::Value(0)
            }
            nr::GETITIMER => {
                if self.write_bytes(env, args[1], &[0u8; 32]) {
                    AlphaResult::Value(0)
                } else {
                    AlphaResult::Fail(errno::EFAULT)
                }
            }
            nr::GETRUSAGE => {
                if self.write_bytes(env, args[1], &[0u8; 144]) {
                    AlphaResult::Value(0)
                } else {
                    AlphaResult::Fail(errno::EFAULT)
                }
            }
            nr::CAPGET => {
                if self.write_bytes(env, args[1], &[0u8; 24]) {
                    AlphaResult::Value(0)
                } else {
                    AlphaResult::Fail(errno::EFAULT)
                }
            }
            nr::IOPRIO_SET | nr::IOPRIO_GET => AlphaResult::Value(0),
            nr::SENDFILE => self
                .sys_sendfile(env, args[0] as u32, args[1] as u32, args[2], args[3])
                .into(),
            nr::WAIT4 | nr::WAITID => AlphaResult::Fail(errno::ECHILD),
            nr::FORK | nr::VFORK | nr::CLONE | nr::EXECVE | nr::PTRACE => AlphaResult::Unimpl,
            nr::STATX => AlphaResult::Unimpl,
            _ => AlphaResult::Unimpl,
        }
    }
}

/// ホストの io エラーを alpha の errno へ写す（主要写像のみ。
/// 未知は EIO）。alpha の errno は OSF 系の独自表。
fn host_errno(e: std::io::Error) -> u32 {
    match e.raw_os_error() {
        Some(1) => errno::EPERM,
        Some(2) => errno::ENOENT,
        Some(4) => errno::EINTR,
        Some(5) => errno::EIO,
        Some(9) => errno::EBADF,
        Some(11) => errno::EAGAIN,
        Some(12) => errno::ENOMEM,
        Some(13) => errno::EACCES,
        Some(14) => errno::EFAULT,
        Some(16) => errno::EBUSY,
        Some(17) => errno::EEXIST,
        Some(18) => errno::EXDEV,
        Some(20) => errno::ENOTDIR,
        Some(21) => errno::EISDIR,
        Some(22) => errno::EINVAL,
        Some(23) => errno::ENFILE,
        Some(24) => errno::EMFILE,
        Some(25) => errno::ENOTTY,
        Some(28) => errno::ENOSPC,
        Some(30) => errno::EROFS,
        Some(31) => errno::EMLINK,
        Some(32) => errno::EPIPE,
        Some(26) => errno::ETXTBSY,
        Some(27) => errno::EFBIG,
        Some(29) => errno::ESPIPE,
        Some(33) => errno::EDOM,
        Some(34) => errno::ERANGE,
        Some(36) => errno::ENAMETOOLONG,
        Some(39) => errno::ENOTEMPTY,
        Some(40) => errno::ELOOP,
        Some(75) => errno::EOVERFLOW,
        Some(116) => errno::ESTALE,
        // ソケット系（OSF 独自番号。sock 正準層から到達する）。
        Some(35) => errno::EDEADLK,
        Some(37) => errno::ENOLCK,
        Some(38) => errno::ENOSYS,
        Some(88) => errno::ENOTSOCK,
        Some(89) => 39, // EDESTADDRREQ
        Some(90) => errno::EMSGSIZE,
        Some(91) => 41, // EPROTOTYPE
        Some(92) => 42, // ENOPROTOOPT
        Some(93) => 43, // EPROTONOSUPPORT
        Some(94) => 44, // ESOCKTNOSUPPORT
        Some(95) => errno::EOPNOTSUPP,
        Some(96) => 46, // EPFNOSUPPORT
        Some(97) => errno::EAFNOSUPPORT,
        Some(98) => errno::EADDRINUSE,
        Some(99) => 49,  // EADDRNOTAVAIL
        Some(100) => 50, // ENETDOWN
        Some(101) => 51, // ENETUNREACH
        Some(102) => 52, // ENETRESET
        Some(103) => 53, // ECONNABORTED
        Some(104) => errno::ECONNRESET,
        Some(105) => 55, // ENOBUFS
        Some(106) => 56, // EISCONN
        Some(107) => 57, // ENOTCONN
        Some(108) => 58, // ESHUTDOWN
        Some(109) => 59, // ETOOMANYREFS
        Some(110) => errno::ETIMEDOUT,
        Some(111) => 61, // ECONNREFUSED
        Some(112) => 64, // EHOSTDOWN
        Some(113) => 65, // EHOSTUNREACH
        Some(114) => 37, // EALREADY
        Some(115) => errno::EINPROGRESS,
        Some(61) => 86, // ENODATA
        Some(62) => 83, // ETIME
        Some(63) => 82, // ENOSR
        Some(60) => 87, // ENOSTR
        Some(67) => 89, // ENOLINK
        Some(71) => 85, // EPROTO
        Some(42) => 80, // ENOMSG
        Some(43) => 81, // EIDRM
        Some(84) => errno::EILSEQ,
        _ => errno::EIO,
    }
}

/// syscall 内部戻り値。`(v0, a3)` に写すか、Exit で終了するか。
enum AlphaResult {
    /// v0 に値、a3=0。
    Value(u64),
    /// a3=1 で v0 が errno。
    Fail(u32),
    /// 終了コード。
    Exit(u32),
    /// 未実装番号。
    Unimpl,
}

impl From<Result<u64, u32>> for AlphaResult {
    fn from(r: Result<u64, u32>) -> Self {
        match r {
            Ok(v) => AlphaResult::Value(v),
            Err(e) => AlphaResult::Fail(e),
        }
    }
}

impl TrapHandler for Linux {
    /// `brk` の初期値。ローダが像の末尾を渡す。カーネルは
    /// ELF_PAGEALIGN（Alpha は 8KiB）で切り上げる。
    fn init_brk(&mut self, image_end: u64) {
        let b = image_end.next_multiple_of(0x2000);
        self.heap_end = b;
        self.brk_start = b;
    }

    fn handle_trap(&mut self, env: &mut BareEnv, code: u32) -> TrapOutcome {
        match code {
            pal::CALLSYS => {}
            pal::RDUNIQ => {
                let v = env.backend.get(sem::uniq_ref());
                set_reg(env, 0, v);
                return TrapOutcome::Handled;
            }
            pal::WRUNIQ => {
                let v = reg(env, 16);
                env.backend.set(sem::uniq_ref(), v);
                return TrapOutcome::Handled;
            }
            // 順序付き実行のインタプリタではキャッシュ・キューの
            // 実効動作がないので imb/cflush/draina は no-op。
            pal::IMB | pal::CFLUSH | pal::DRAINA => return TrapOutcome::Handled,
            // halt/bpt/bugchk/gentrap とその他の PAL 関数はこの段階
            // では未実装（呼び出し側が Unimplemented に写す）。
            _ => return TrapOutcome::Unimplemented,
        }
        let nr_val = reg(env, 0);
        if trace() {
            let nm = name(nr_val).unwrap_or("?");
            eprintln!(
                "sys {nr_val} {nm} a0={:#x} a1={:#x}",
                reg(env, 16),
                reg(env, 17)
            );
        }
        match self.dispatch(env, nr_val) {
            AlphaResult::Value(v) => {
                set_reg(env, 0, v);
                set_reg(env, 19, 0);
                TrapOutcome::Handled
            }
            AlphaResult::Fail(e) => {
                set_reg(env, 0, u64::from(e));
                set_reg(env, 19, 1);
                TrapOutcome::Handled
            }
            AlphaResult::Exit(c) => TrapOutcome::Exit(c),
            AlphaResult::Unimpl => {
                let nm = name(nr_val).unwrap_or("?");
                if !self.reported.contains(&nr_val) {
                    self.reported.push(nr_val);
                    eprintln!("alpha: unimplemented syscall {nr_val} ({nm})");
                }
                set_reg(env, 0, u64::from(errno::ENOSYS));
                set_reg(env, 19, 1);
                TrapOutcome::Handled
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> BareEnv {
        BareEnv::new(core::mem::size_of::<polyisa_guest_alpha::CpuState>())
    }

    fn callsys(sys: &mut Linux, env: &mut BareEnv, n: u64, args: [u64; 6]) -> TrapOutcome {
        set_reg(env, 0, n);
        for (i, a) in args.iter().enumerate() {
            set_reg(env, 16 + i as u8, *a);
        }
        sys.handle_trap(env, pal::CALLSYS)
    }

    #[test]
    fn callsys_write_captures_stdout() {
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x8000), 1, Perms::RW).unwrap();
        env.backend.mem.write(VirtAddr(0x8000), b"hi\n").unwrap();
        let mut sys = Linux::new();
        match callsys(&mut sys, &mut env, nr::WRITE, [1, 0x8000, 3, 0, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), 3);
        assert_eq!(reg(&mut env, 19), 0);
        assert_eq!(sys.io.stdout, b"hi\n");
    }

    #[test]
    fn callsys_write_bad_fd_sets_a3() {
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x8000), 1, Perms::RW).unwrap();
        env.backend.mem.write(VirtAddr(0x8000), b"hi").unwrap();
        let mut sys = Linux::new();
        match callsys(&mut sys, &mut env, nr::WRITE, [9, 0x8000, 2, 0, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        // Alpha の失敗規約は a3=1 で v0 が正の errno。
        assert_eq!(reg(&mut env, 0), u64::from(errno::EBADF));
        assert_eq!(reg(&mut env, 19), 1);
    }

    #[test]
    fn callsys_exit_group_returns_exit() {
        let mut env = env();
        let mut sys = Linux::new();
        match callsys(&mut sys, &mut env, nr::EXIT_GROUP, [7, 0, 0, 0, 0, 0]) {
            TrapOutcome::Exit(7) => {}
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn callsys_unknown_nr_is_enosys() {
        let mut env = env();
        let mut sys = Linux::new();
        match callsys(&mut sys, &mut env, 9999, [0; 6]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        // Alpha の ENOSYS は 78（汎用の 38 ではない）。
        assert_eq!(reg(&mut env, 0), u64::from(errno::ENOSYS));
        assert_eq!(reg(&mut env, 19), 1);
    }

    #[test]
    fn callsys_brk_grows_and_maps() {
        let mut env = env();
        let mut sys = Linux::new();
        sys.init_brk(0x1_0000);
        // 照会は現在値を返す。
        match callsys(&mut sys, &mut env, nr::BRK, [0; 6]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), 0x1_0000);
        // 伸長すると新ブレークを返し、範囲は写像される。
        match callsys(&mut sys, &mut env, nr::BRK, [0x2_0000, 0, 0, 0, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), 0x2_0000);
        assert!(
            env.backend
                .mem
                .is_mapped(polyisa_mem::PageNo(0x1_0000 / 4096))
        );
        let data = [0xaa; 8];
        env.backend.mem.write(VirtAddr(0x1_8000), &data).unwrap();
    }

    #[test]
    fn pal_rduniq_wruniq_roundtrip() {
        let mut env = env();
        let mut sys = Linux::new();
        // wruniq a0 → 保持域へ。
        set_reg(&mut env, 16, 0xdead_beef);
        match sys.handle_trap(&mut env, pal::WRUNIQ) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(env.backend.get(sem::uniq_ref()), 0xdead_beef);
        // rduniq → v0 に戻る。
        set_reg(&mut env, 0, 0);
        match sys.handle_trap(&mut env, pal::RDUNIQ) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), 0xdead_beef);
    }

    #[test]
    fn pal_imb_cflush_draina_are_noop() {
        let mut env = env();
        let mut sys = Linux::new();
        for code in [pal::IMB, pal::CFLUSH, pal::DRAINA] {
            match sys.handle_trap(&mut env, code) {
                TrapOutcome::Handled => {}
                o => panic!("{code:#x}: {o:?}"),
            }
        }
    }

    #[test]
    fn pal_unknown_code_is_unimplemented() {
        let mut env = env();
        let mut sys = Linux::new();
        // PAL_halt（0x00）や未割当番号はこの段階では未実装。
        for code in [0x00, 0x81, 0xaa, 0xbe] {
            match sys.handle_trap(&mut env, code) {
                TrapOutcome::Unimplemented => {}
                o => panic!("{code:#x}: {o:?}"),
            }
        }
    }

    /// テスト用の一時ファイル。ドロップで削除する。
    struct TmpFile(std::path::PathBuf);
    impl TmpFile {
        fn new(name: &str, data: &[u8]) -> Self {
            let p =
                std::env::temp_dir().join(format!("polyisa_alpha_{}_{}", std::process::id(), name));
            std::fs::write(&p, data).unwrap();
            Self(p)
        }
        /// ゲストメモリへ書き込める C 文字列（絶対パス）。
        fn cstr(&self) -> Vec<u8> {
            let mut v = self.0.display().to_string().into_bytes();
            v.push(0);
            v
        }
    }
    impl Drop for TmpFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn callsys_open_read_roundtrip() {
        let tmp = TmpFile::new("open_read", b"abcdef");
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x8000), 2, Perms::RW).unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x8000), &tmp.cstr())
            .unwrap();
        let mut sys = Linux::new();
        // open(path, O_RDONLY=0)。
        match callsys(&mut sys, &mut env, nr::OPEN, [0x8000, 0, 0, 0, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 19), 0);
        let fd = reg(&mut env, 0) as u32;
        assert!(fd >= 3);
        // read(fd, 0x9000, 4)。
        match callsys(
            &mut sys,
            &mut env,
            nr::READ,
            [u64::from(fd), 0x9000, 4, 0, 0, 0],
        ) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), 4);
        let mut buf = [0u8; 4];
        env.backend
            .mem
            .read(VirtAddr(0x9000), &mut buf, Linux::acc(AccessKind::DataRead))
            .unwrap();
        assert_eq!(&buf, b"abcd");
    }

    #[test]
    fn callsys_writev_captures_stdout() {
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x8000), 2, Perms::RW).unwrap();
        env.backend.mem.write(VirtAddr(0x8000), b"hello").unwrap();
        env.backend.mem.write(VirtAddr(0x8100), b"world").unwrap();
        // iovec[2] = {{0x8000,5},{0x8100,5}}。
        for (i, (b, l)) in [(0x8000u64, 5u64), (0x8100, 5)].iter().enumerate() {
            env.backend
                .mem
                .write(VirtAddr(0x8200 + i as u64 * 16), &b.to_le_bytes())
                .unwrap();
            env.backend
                .mem
                .write(VirtAddr(0x8200 + i as u64 * 16 + 8), &l.to_le_bytes())
                .unwrap();
        }
        let mut sys = Linux::new();
        match callsys(&mut sys, &mut env, nr::WRITEV, [1, 0x8200, 2, 0, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), 10);
        assert_eq!(sys.io.stdout, b"helloworld");
    }

    #[test]
    fn callsys_stat64_layout() {
        let tmp = TmpFile::new("stat64", b"1234567890");
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x8000), 3, Perms::RW).unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x8000), &tmp.cstr())
            .unwrap();
        let mut sys = Linux::new();
        match callsys(&mut sys, &mut env, nr::STAT64, [0x8000, 0x9000, 0, 0, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), 0);
        // size は stat64 レイアウトの offset 24。
        let mut b = [0u8; 8];
        env.backend
            .mem
            .read(
                VirtAddr(0x9000 + 24),
                &mut b,
                Linux::acc(AccessKind::DataRead),
            )
            .unwrap();
        assert_eq!(u64::from_le_bytes(b), 10);
        // mode は offset 40（u32）。通常ファイル 0o100xxx。
        let mut m = [0u8; 4];
        env.backend
            .mem
            .read(
                VirtAddr(0x9000 + 40),
                &mut m,
                Linux::acc(AccessKind::DataRead),
            )
            .unwrap();
        assert_eq!(u32::from_le_bytes(m) & 0o170000, 0o100000);
    }

    #[test]
    fn callsys_getdents64_paginates() {
        let dir = std::env::temp_dir().join(format!("polyisa_alpha_dir_{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("a"), b"1").unwrap();
        std::fs::write(dir.join("b"), b"2").unwrap();
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x8000), 4, Perms::RW).unwrap();
        let mut c = dir.display().to_string().into_bytes();
        c.push(0);
        env.backend.mem.write(VirtAddr(0x8000), &c).unwrap();
        let mut sys = Linux::new();
        match callsys(&mut sys, &mut env, nr::OPEN, [0x8000, 0, 0, 0, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        let fd = reg(&mut env, 0);
        // 1 回目は >0 バイト、2 回目（同じ count）は末尾なら 0。
        match callsys(
            &mut sys,
            &mut env,
            nr::GETDENTS64,
            [fd, 0x9000, 512, 0, 0, 0],
        ) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert!(reg(&mut env, 0) > 0);
        match callsys(
            &mut sys,
            &mut env,
            nr::GETDENTS64,
            [fd, 0xA000, 512, 0, 0, 0],
        ) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn callsys_mmap_anonymous_maps_memory() {
        let mut env = env();
        let mut sys = Linux::new();
        sys.init_brk(0x1_0000);
        // mmap(0, 8192, RW=3, MAP_ANON(0x10)|MAP_PRIVATE(2), -1, 0)。
        let neg1 = u64::MAX;
        match callsys(&mut sys, &mut env, nr::MMAP, [0, 8192, 3, 0x12, neg1, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        let base = reg(&mut env, 0);
        assert_eq!(reg(&mut env, 19), 0);
        assert!(base > 0x1_0000);
        env.backend.mem.write(VirtAddr(base), &[0xaa; 4]).unwrap();
    }

    #[test]
    fn callsys_rt_sigprocmask_roundtrip() {
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x8000), 1, Perms::RW).unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x8000), &0x40u64.to_le_bytes())
            .unwrap();
        let mut sys = Linux::new();
        // SIG_SETMASK=2 で mask=0x40 を設定し、old に旧値を書く。
        match callsys(
            &mut sys,
            &mut env,
            nr::RT_SIGPROCMASK,
            [2, 0x8000, 0x8010, 8, 0, 0],
        ) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), 0);
        let mut b = [0u8; 8];
        env.backend
            .mem
            .read(VirtAddr(0x8010), &mut b, Linux::acc(AccessKind::DataRead))
            .unwrap();
        assert_eq!(u64::from_le_bytes(b), 0); // 旧マスクは 0
        // 照会（set=NULL, old あり）。
        match callsys(
            &mut sys,
            &mut env,
            nr::RT_SIGPROCMASK,
            [2, 0, 0x8018, 8, 0, 0],
        ) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        env.backend
            .mem
            .read(VirtAddr(0x8018), &mut b, Linux::acc(AccessKind::DataRead))
            .unwrap();
        assert_eq!(u64::from_le_bytes(b), 0x40);
    }

    /// パス文字列をゲストメモリに置いて open し、fd を返す。
    fn open_tmp(sys: &mut Linux, env: &mut BareEnv, tmp: &TmpFile) -> u64 {
        env.backend
            .mem
            .write(VirtAddr(0x8000), &tmp.cstr())
            .unwrap();
        match callsys(sys, env, nr::OPEN, [0x8000, 0, 0, 0, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(env, 19), 0);
        reg(env, 0)
    }

    #[test]
    fn callsys_pread64_preserves_fd_position() {
        let tmp = TmpFile::new("pread_pos", b"0123456789");
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x8000), 4, Perms::RW).unwrap();
        let mut sys = Linux::new();
        let fd = open_tmp(&mut sys, &mut env, &tmp);
        // pread64(fd, buf, 2, off=8) は位置を動かさない。
        match callsys(&mut sys, &mut env, nr::PREAD64, [fd, 0x9000, 2, 8, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), 2);
        // 直後の read はオフセット0から読む（位置が保持される）。
        match callsys(&mut sys, &mut env, nr::READ, [fd, 0x9100, 2, 0, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        let mut b = [0u8; 2];
        env.backend
            .mem
            .read(VirtAddr(0x9100), &mut b, Linux::acc(AccessKind::DataRead))
            .unwrap();
        assert_eq!(&b, b"01");
        // 負オフセットは EINVAL。
        match callsys(
            &mut sys,
            &mut env,
            nr::PREAD64,
            [fd, 0x9000, 2, u64::MAX, 0, 0],
        ) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), u64::from(errno::EINVAL));
    }

    #[test]
    fn callsys_sendfile_keeps_input_position() {
        let tmp = TmpFile::new("sendfile_pos", b"0123456789");
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x8000), 4, Perms::RW).unwrap();
        let mut sys = Linux::new();
        let fd = open_tmp(&mut sys, &mut env, &tmp);
        env.backend
            .mem
            .write(VirtAddr(0x9500), &8u64.to_le_bytes())
            .unwrap();
        // sendfile(stdout, in, &off=8, 2): off は8→10 に進み、
        // fd の位置は動かない。
        match callsys(&mut sys, &mut env, nr::SENDFILE, [1, fd, 0x9500, 2, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), 2);
        assert_eq!(sys.io.stdout, b"89");
        let mut b = [0u8; 8];
        env.backend
            .mem
            .read(VirtAddr(0x9500), &mut b, Linux::acc(AccessKind::DataRead))
            .unwrap();
        assert_eq!(u64::from_le_bytes(b), 10);
        // fd の現在位置は変わっていない。
        match callsys(&mut sys, &mut env, nr::READ, [fd, 0x9100, 2, 0, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        env.backend
            .mem
            .read(
                VirtAddr(0x9100),
                &mut b[..2],
                Linux::acc(AccessKind::DataRead),
            )
            .unwrap();
        assert_eq!(&b[..2], b"01");
    }

    #[test]
    fn callsys_dup2_same_fd_succeeds_dup3_rejects() {
        let tmp = TmpFile::new("dup_same", b"x");
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x8000), 2, Perms::RW).unwrap();
        let mut sys = Linux::new();
        let fd = open_tmp(&mut sys, &mut env, &tmp);
        // dup2(fd, fd) は成功して fd を返す。
        match callsys(&mut sys, &mut env, nr::DUP2, [fd, fd, 0, 0, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), fd);
        assert_eq!(reg(&mut env, 19), 0);
        // dup3(fd, fd, 0) は EINVAL。
        match callsys(&mut sys, &mut env, nr::DUP3, [fd, fd, 0, 0, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), u64::from(errno::EINVAL));
        // dup3 に O_CLOEXEC 以外の旗は EINVAL。
        match callsys(&mut sys, &mut env, nr::DUP3, [fd, 5, 1, 0, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), u64::from(errno::EINVAL));
        // 上限を超える newfd は EBADF。
        match callsys(&mut sys, &mut env, nr::DUP2, [fd, 0x1_0000, 0, 0, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), u64::from(errno::EBADF));
    }

    #[test]
    fn callsys_munmap_rejects_bad_args() {
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x8000), 1, Perms::RW).unwrap();
        let mut sys = Linux::new();
        for (a, l) in [(0x8001u64, 0x1000), (0x8000, 0), (0x8000, u64::MAX)] {
            match callsys(&mut sys, &mut env, nr::MUNMAP, [a, l, 0, 0, 0, 0]) {
                TrapOutcome::Handled => {}
                o => panic!("{o:?}"),
            }
            assert_eq!(reg(&mut env, 19), 1, "munmap({a:#x},{l:#x})");
            assert!(
                reg(&mut env, 0) == u64::from(errno::EINVAL)
                    || reg(&mut env, 0) == u64::from(errno::ENOMEM)
            );
        }
    }

    #[test]
    fn callsys_times_propagates_efault() {
        let mut env = env();
        let mut sys = Linux::new();
        // 未写像の buf は EFAULT（以前は 0 成功に化けていた）。
        match callsys(&mut sys, &mut env, nr::TIMES, [0xdead_0000, 0, 0, 0, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), u64::from(errno::EFAULT));
        assert_eq!(reg(&mut env, 19), 1);
    }

    #[test]
    fn callsys_getdents64_validates_args() {
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x8000), 1, Perms::RW).unwrap();
        env.backend.mem.map(VirtAddr(0x9000), 1, Perms::RW).unwrap();
        let mut sys = Linux::new();
        // 未オープン fd は EBADF（count の検査より先）。
        match callsys(
            &mut sys,
            &mut env,
            nr::GETDENTS64,
            [9, 0x8000, 512, 0, 0, 0],
        ) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), u64::from(errno::EBADF));
        // 開いた fd で、1 レコード入らない count は EINVAL。
        env.backend.mem.write(VirtAddr(0x9000), b"/tmp\0").unwrap();
        match callsys(
            &mut sys,
            &mut env,
            nr::OPEN,
            [0x9000, u64::from(oflag::DIRECTORY), 0, 0, 0, 0],
        ) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        let fd = reg(&mut env, 0);
        assert_eq!(reg(&mut env, 19), 0);
        match callsys(&mut sys, &mut env, nr::GETDENTS64, [fd, 0x8000, 8, 0, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), u64::from(errno::EINVAL));
    }

    #[test]
    fn callsys_statfs64_respects_declared_size() {
        // df の実害: statfs64(path, sz=0x58, buf) が宣言を越えて
        // 書き込み、呼び出し側のスタックを破壊していた。
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x8000), 2, Perms::RW).unwrap();
        env.backend.mem.write(VirtAddr(0x8000), b"/tmp\0").unwrap();
        // buf 後方の canary。
        env.backend
            .mem
            .write(VirtAddr(0x8900), &[0xaa; 64])
            .unwrap();
        let mut sys = Linux::new();
        match callsys(
            &mut sys,
            &mut env,
            nr::STATFS64,
            [0x8000, 0x58, 0x8880, 0, 0, 0],
        ) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 19), 0, "v0={}", reg(&mut env, 0));
        // 0x8880+0x58 = 0x88d8 まで書く。0x8900 以降は無傷のはず。
        let mut buf = [0u8; 64];
        env.backend
            .mem
            .read(VirtAddr(0x8900), &mut buf, Linux::acc(AccessKind::DataRead))
            .unwrap();
        assert_eq!(buf, [0xaa; 64]);
    }

    #[test]
    fn callsys_getrlimit_uses_alpha_resource_numbers() {
        // RLIMIT_NOFILE は Alpha では 6（汎用の 7 ではない）。
        // RLIM_INFINITY は 0x7fffffffffffffff。
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x8000), 1, Perms::RW).unwrap();
        let mut sys = Linux::new();
        match callsys(&mut sys, &mut env, nr::GETRLIMIT, [6, 0x8000, 0, 0, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 19), 0);
        let mut b = [0u8; 16];
        env.backend
            .mem
            .read(VirtAddr(0x8000), &mut b, Linux::acc(AccessKind::DataRead))
            .unwrap();
        assert_eq!(u64::from_le_bytes(b[..8].try_into().unwrap()), 1024);
        assert_eq!(u64::from_le_bytes(b[8..].try_into().unwrap()), 1024);
        // 4 は CORE — NOFILE ではない。
        match callsys(&mut sys, &mut env, nr::GETRLIMIT, [4, 0x8000, 0, 0, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        env.backend
            .mem
            .read(VirtAddr(0x8000), &mut b, Linux::acc(AccessKind::DataRead))
            .unwrap();
        assert_eq!(
            u64::from_le_bytes(b[..8].try_into().unwrap()),
            0x7fff_ffff_ffff_ffff
        );
    }

    #[test]
    fn callsys_osf_sigaction_is_three_arg() {
        // nr 156 は3引数（sigsetsize なし）。rt 版と同じ経路に
        // すると a3 のゴミで EINVAL になっていた。
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x8000), 1, Perms::RW).unwrap();
        let mut sys = Linux::new();
        match callsys(
            &mut sys,
            &mut env,
            nr::SIGACTION,
            [2, 0, 0x8000, 0xffff_ffff, 0, 0],
        ) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), 0);
        assert_eq!(reg(&mut env, 19), 0);
        // rt 版は sigsetsize != 8 を EINVAL にする。
        match callsys(&mut sys, &mut env, nr::RT_SIGACTION, [2, 0, 0, 4, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), u64::from(errno::EINVAL));
    }

    #[test]
    fn callsys_dup2_to_stdout_redirects() {
        // dup2(fd,1) が成功を返しながら無視される問題の回帰。
        use std::io::Read as _;
        let dir = std::env::temp_dir();
        let p = dir.join(format!("polyisa_t_{}", std::process::id()));
        std::fs::write(&p, b"x").unwrap();
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x8000), 1, Perms::RW).unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x8000), p.to_str().unwrap().as_bytes())
            .unwrap();
        let mut sys = Linux::new();
        // 書き込み用に開き直す。
        match callsys(&mut sys, &mut env, nr::OPEN, [0x8000, 1, 0, 0, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        let fd = reg(&mut env, 0);
        assert_eq!(reg(&mut env, 19), 0);
        match callsys(&mut sys, &mut env, nr::DUP2, [fd, 1, 0, 0, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), 1);
        env.backend.mem.write(VirtAddr(0x8000), b"rdr").unwrap();
        match callsys(&mut sys, &mut env, nr::WRITE, [1, 0x8000, 3, 0, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), 3);
        // ホスト capture には入らず、ファイルへ書かれる（位置 0 からの上書き）。
        assert!(sys.io.stdout.is_empty());
        let mut s = String::new();
        std::fs::File::open(&p)
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        assert_eq!(s, "rdr");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn callsys_openat_empty_path_is_enoent() {
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x8000), 1, Perms::RW).unwrap();
        env.backend.mem.write(VirtAddr(0x8000), &[0u8; 4]).unwrap();
        let mut sys = Linux::new();
        match callsys(
            &mut sys,
            &mut env,
            nr::OPENAT,
            [-100i64 as u64, 0x8000, 0, 0, 0, 0],
        ) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), u64::from(errno::ENOENT));
        assert_eq!(reg(&mut env, 19), 1);
    }

    #[test]
    fn callsys_kill_self_succeeds() {
        let mut env = env();
        let mut sys = Linux::new();
        // 自分（pid=1）への kill は成功。
        match callsys(&mut sys, &mut env, nr::KILL, [1, 0, 0, 0, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), 0);
        // 他の pid は ESRCH。
        match callsys(&mut sys, &mut env, nr::KILL, [2, 0, 0, 0, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), u64::from(errno::ESRCH));
    }

    #[test]
    fn callsys_gettimeofday_zeroes_tz() {
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x8000), 1, Perms::RW).unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x8080), &[0xff; 16])
            .unwrap();
        let mut sys = Linux::new();
        match callsys(
            &mut sys,
            &mut env,
            nr::GETTIMEOFDAY,
            [0x8000, 0x8080, 0, 0, 0, 0],
        ) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 19), 0);
        let mut b = [0u8; 8];
        env.backend
            .mem
            .read(VirtAddr(0x8080), &mut b, Linux::acc(AccessKind::DataRead))
            .unwrap();
        assert_eq!(b, [0; 8]);
    }

    #[test]
    fn callsys_nanosleep_validates_nsec() {
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x8000), 1, Perms::RW).unwrap();
        let mut sys = Linux::new();
        // tv_nsec = 1e9 は EINVAL。
        env.backend
            .mem
            .write(VirtAddr(0x8000), &0u64.to_le_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x8008), &1_000_000_000u64.to_le_bytes())
            .unwrap();
        match callsys(&mut sys, &mut env, nr::NANOSLEEP, [0x8000, 0, 0, 0, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), u64::from(errno::EINVAL));
    }

    #[test]
    fn callsys_utimes_overflow_is_einval_not_panic() {
        // usec の u64 最大値は sub*1000 で溢れる — パニックせず EINVAL。
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x8000), 2, Perms::RW).unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x8000), b"/tmp/polyisa_ut\0")
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x8080), &u64::MAX.to_le_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x8088), &u64::MAX.to_le_bytes())
            .unwrap();
        let mut sys = Linux::new();
        match callsys(&mut sys, &mut env, nr::UTIMES, [0x8000, 0x8080, 0, 0, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), u64::from(errno::EINVAL));
        assert_eq!(reg(&mut env, 19), 1);
    }

    #[test]
    fn callsys_pwrite64_writes_at_offset() {
        let dir = std::env::temp_dir();
        let p = dir.join(format!("polyisa_pw_{}", std::process::id()));
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x8000), 1, Perms::RW).unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x8000), p.to_str().unwrap().as_bytes())
            .unwrap();
        let mut sys = Linux::new();
        // O_RDWR|O_CREAT で新規作成する。
        match callsys(
            &mut sys,
            &mut env,
            nr::OPEN,
            [0x8000, u64::from(2 | oflag::CREAT), 0o644, 0, 0, 0],
        ) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        let fd = reg(&mut env, 0);
        assert_eq!(reg(&mut env, 19), 0, "v0={}", reg(&mut env, 0));
        env.backend.mem.write(VirtAddr(0x8000), b"xy").unwrap();
        match callsys(&mut sys, &mut env, nr::PWRITE64, [fd, 0x8000, 2, 4, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), 2);
        assert_eq!(std::fs::read(&p).unwrap(), b"\0\0\0\0xy");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn callsys_brk_reports_collision_with_mmap() {
        // ヒープの成長が先行 mmap を踏む場合は ENOMEM。
        let mut env = env();
        let mut sys = Linux::new();
        sys.init_brk(0x1_0000);
        // brk_start+64MiB に 1 ページの mmap を置く。
        let base = 0x2000 + 0x400_0000;
        env.backend.mem.map(VirtAddr(base), 1, Perms::RW).unwrap();
        match callsys(&mut sys, &mut env, nr::BRK, [base + 0x2000, 0, 0, 0, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), u64::from(errno::ENOMEM));
        assert_eq!(reg(&mut env, 19), 1);
    }
}
