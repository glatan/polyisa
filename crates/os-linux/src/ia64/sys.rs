// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! IA-64 Linux の syscall 機械（段階21 IA10/IA11）。
//!
//! 発行点は `break 0x100000`（run::step が即値を code に載せて
//! `handle_trap` へ渡す）とゲートページの入口呼出。ゲートは
//! `install_gate_page` が `gate::CODE` に実バンドルを書く形で
//! 供給する（IP フックでなく命令列を置く選択: ia64 のゲートは
//! 固定領域の実行コードで、br.call/br.ret b6 の規約をそのまま
//! 再現できる。via_epc は epc の特権移行だけを差し替えて
//! via_break と同じ形に畳む近似 — Gap: GAP-0068）。
//! 番号は r15−`NR_BASE`、引数は現在フレームの out0–out5
//! （`sem::out_get`。epc 呼出では br.call で sol=0 になった新
//! フレームの先頭に呼出側の引数が写るので、両経路で同じ
//! 読み方が成立する）。結果は r8・r10。単一プロセス・単一
//! スレッド模型（fork/clone/execve/socket/pipe 系は ENOSYS
//! — Gap: GAP-0068）。
//! Ref: SRC-LINUX-66 — kernel/entry.S, kernel/gate.S, syscall.tbl.

use std::io::{Read, Seek, SeekFrom, Write as _};

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::InterpBackend;
use polyisa_guest_ia64::{bundle, encode_br_ret, encode_break_m, encode_nop_i, sem};
use polyisa_kernel::FdTable;
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};

use crate::ia64::{NR_BASE, NR_SYSCALLS, brk, errno, gate, mman, name, nr, oflag};
use crate::{TrapHandler, TrapOutcome};

/// `AT_FDCWD`。SRC-LINUX-66 uapi-linux/fcntl.h。
const AT_FDCWD: i64 = -100;

fn trace() -> bool {
    std::env::var_os("POLYISA_IA64_SYSCALLS").is_some()
}

/// write が集めたバイト（テストが読む）。
#[derive(Default)]
pub struct Ia64Io {
    /// 標準出力。
    pub stdout: Vec<u8>,
    /// 標準エラー。
    pub stderr: Vec<u8>,
}

/// IA-64 Linux の syscall 状態機械。r15−NR_BASE=表番号、
/// out0–out5=引数、r8/r10=戻り値。
// Gap: GAP-0068 — 単一プロセス模型の意図的な簡略化（fork/execve
// なし、signal はスタブ、statfs は合成値、pipe/socket は ENOSYS）。
pub struct Linux {
    /// 標準出力・標準エラーの捕獲。
    pub io: Ia64Io,
    /// 標準入力へ供給するバイト。
    pub stdin_buf: Vec<u8>,
    /// /proc/self/exe の readlink が返す絶対パス。ローダが置く。
    pub exe_path: String,
    stdin_pos: usize,
    /// 開いたファイルの表（ゲスト fd 3 以降）。
    fds: FdTable,
    /// ゲストの相対パスをホストパスへ写す基準（chdir が動かす）。
    cwd: String,
    /// プログラムブレーク。0 は未初期化。
    heap_end: u64,
    /// `brk` が下げられない下限（exec 時点のブレーク）。
    brk_start: u64,
    /// 匿名 mmap の次の割当位置。
    mmap_next: u64,
    /// 報告済みの未実装番号（一度だけ出す）。
    reported: Vec<u64>,
    /// ホストから見たプロセス識別子（固定 pid=1）。
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
    #[must_use]
    pub fn new() -> Self {
        Self {
            io: Ia64Io::default(),
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
            proc_name: *b"busybox\0\0\0\0\0\0\0\0\0",
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

    /// LE/非整列のデータアクセス属性。
    fn acc(kind: AccessKind) -> Access {
        Access {
            endian: Endian::Le,
            align: Align::Unaligned,
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
    fn read_cstr(&mut self, env: &mut BareEnv, addr: u64) -> Result<Vec<u8>, u64> {
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

    /// ゲストメモリの u64 を読む。
    fn read_u(&mut self, env: &mut BareEnv, addr: u64) -> Option<u64> {
        self.read_bytes(env, addr, 8)
            .map(|b| u64::from_le_bytes(b[..8].try_into().unwrap()))
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
    fn host_path_at(&mut self, dirfd: i64, guest: &[u8]) -> Result<String, u64> {
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

    /// fd の上限。RLIMIT_NOFILE と一致させる。
    const MAX_FD: u32 = 1024;

    /// fd のホストファイル。0–2 は差し替え分だけ返す。
    fn file_of(&self, fd: u32) -> Option<&std::fs::File> {
        if fd < 3 {
            self.std_fds[fd as usize].as_ref()
        } else {
            self.fds.get(fd)
        }
    }

    /// `file_of` の可変版。
    fn file_of_mut(&mut self, fd: u32) -> Option<&mut std::fs::File> {
        if fd < 3 {
            self.std_fds[fd as usize].as_mut()
        } else {
            self.fds.get_mut(fd)
        }
    }

    /// fd が読み書き可能に開いているか。0–2 は close 状態を見る。
    fn fd_open(&self, fd: u32) -> bool {
        if fd < 3 {
            !self.std_closed[fd as usize]
        } else {
            self.fds.get(fd).is_some()
        }
    }

    /// 標準 fd の複製に使うホストファイル。差し替え済みは
    /// `try_clone`、未差し替えは /dev/fd/N を開き直して
    /// dup(0–2) を表す。
    fn std_clone(&self, fd: u32) -> Result<std::fs::File, u64> {
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
    fn alloc_file(&mut self, f: std::fs::File) -> Result<u32, u64> {
        if self.next_free_fd() >= Self::MAX_FD {
            return Err(errno::EMFILE);
        }
        Ok(self.fds.alloc(Some(f)))
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
    fn file_read(&mut self, fd: u32, n: usize) -> Result<Vec<u8>, u64> {
        let f = self.file_of_mut(fd).ok_or(errno::EBADF)?;
        let mut buf = vec![0u8; n];
        let k = f.read(&mut buf).map_err(host_errno)?;
        buf.truncate(k);
        Ok(buf)
    }

    /// `data` を fd へ書く。1/2 は差し替えがなければ
    /// capture＋ホスト出力、それ以外はファイル。
    fn out_write(&mut self, fd: u32, data: &[u8]) -> Result<usize, u64> {
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
                        let _ = std::io::stdout().write_all(data);
                        Ok(data.len())
                    }
                    _ => {
                        self.io.stderr.extend_from_slice(data);
                        let _ = std::io::stderr().write_all(data);
                        Ok(data.len())
                    }
                }
            }
            _ => self
                .fds
                .get_mut(fd)
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

    /// `brk` の状態遷移。エミュレータのページは 4096（ia64 の
    /// CONFIG_IA64_PAGE_SIZE_4KB と同じ）。
    fn sys_brk(&mut self, env: &mut BareEnv, addr: u64) -> Result<u64, u64> {
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

    /// `write`。fd の検査は len==0 の早期リターンより先。
    fn sys_write(&mut self, env: &mut BareEnv, fd: u32, buf: u64, len: u64) -> Result<u64, u64> {
        if !self.fd_open(fd) || (fd == 0 && self.std_fds[0].is_none()) {
            return Err(errno::EBADF);
        }
        let n = usize::try_from(len).unwrap_or(1 << 20).min(1 << 20);
        let data = self.read_bytes(env, buf, n).ok_or(errno::EFAULT)?;
        self.out_write(fd, &data).map(|n| n as u64)
    }

    /// `read`。fd0 は stdin_buf を順送り（差し替え時はファイル）、
    /// ファイルは FdTable。
    fn sys_read(&mut self, env: &mut BareEnv, fd: u32, buf: u64, len: u64) -> Result<u64, u64> {
        if !self.fd_open(fd) || ((fd == 1 || fd == 2) && self.std_fds[fd as usize].is_none()) {
            return Err(errno::EBADF);
        }
        let n = usize::try_from(len).unwrap_or(1 << 20).min(1 << 20);
        if n == 0 {
            return Ok(0);
        }
        let data = if fd == 0 && self.std_fds[0].is_none() {
            self.stdin_read(n)
        } else {
            self.file_read(fd, n)?
        };
        if !self.write_bytes(env, buf, &data) {
            return Err(errno::EFAULT);
        }
        Ok(data.len() as u64)
    }

    /// `readv`（iovec = {u64 base, u64 len} の配列）。
    fn sys_readv(&mut self, env: &mut BareEnv, fd: u32, iov: u64, cnt: u64) -> Result<u64, u64> {
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
    fn sys_writev(&mut self, env: &mut BareEnv, fd: u32, iov: u64, cnt: u64) -> Result<u64, u64> {
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

    /// `sendfile`(out_fd, in_fd, off*, count)。in はファイル限定、
    /// off==NULL は in の現在位置から。
    fn sys_sendfile(
        &mut self,
        env: &mut BareEnv,
        out_fd: u32,
        in_fd: u32,
        off_addr: u64,
        count: u64,
    ) -> Result<u64, u64> {
        if !self.fd_open(out_fd) {
            return Err(errno::EBADF);
        }
        if self.file_of(in_fd).is_none() {
            return Err(errno::EBADF);
        }
        let mut pos = 0u64;
        let data = if off_addr != 0 {
            pos = self.read_u(env, off_addr).ok_or(errno::EFAULT)?;
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

    /// `pread64`。ia64 では off は 1 引数で届く。
    fn sys_pread64(
        &mut self,
        env: &mut BareEnv,
        fd: u32,
        buf: u64,
        len: u64,
        off: u64,
    ) -> Result<u64, u64> {
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
    ) -> Result<u64, u64> {
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
    ) -> Result<u64, u64> {
        if whence == 0 && off < 0 {
            return Err(errno::EINVAL);
        }
        if fd < 3 && self.std_fds[fd as usize].is_none() {
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
            Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => Err(errno::EINVAL),
            Err(_) => Err(errno::ESPIPE),
        }
    }

    /// `close`。0–2 は差し替えを外して閉じた印を残し、
    /// ファイルはスロットを空ける。
    fn sys_close(&mut self, _env: &mut BareEnv, fd: u32) -> Result<u64, u64> {
        if fd < 3 {
            self.std_fds[fd as usize] = None;
            self.std_closed[fd as usize] = true;
            return Ok(0);
        }
        if self.fds.get(fd).is_none() {
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
    ) -> Result<u64, u64> {
        let path = self.read_cstr(env, path_addr)?;
        // 空のパス名は ENOENT（AT_EMPTY_PATH は stat 系専用）。
        if path.is_empty() {
            return Err(errno::ENOENT);
        }
        let host = self.host_path_at(dirfd, &path)?;
        // O_NOFOLLOW: 末尾要素がシンボリックリンクなら ELOOP。
        if flags as u64 & oflag::NOFOLLOW != 0
            && std::fs::symlink_metadata(&host)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
        {
            return Err(errno::ELOOP);
        }
        let existed = std::fs::symlink_metadata(&host).is_ok();
        let mut oo = std::fs::OpenOptions::new();
        let accmode = u64::from(flags) & oflag::ACCMODE;
        oo.read(accmode != 1).write(accmode != 0);
        oo.append(flags as u64 & oflag::APPEND != 0);
        if flags as u64 & oflag::TRUNC != 0 {
            oo.truncate(true);
        }
        if flags as u64 & oflag::CREAT != 0 {
            oo.create(true);
            if flags as u64 & oflag::EXCL != 0 {
                oo.create_new(true);
            }
        }
        match oo.open(&host) {
            Ok(f) => {
                if flags as u64 & oflag::DIRECTORY != 0 {
                    match f.metadata() {
                        Ok(m) if m.is_dir() => {}
                        Ok(_) => return Err(errno::ENOTDIR),
                        Err(e) => return Err(host_errno(e)),
                    }
                }
                if flags as u64 & oflag::CREAT != 0 && !existed {
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
    /// O_CLOEXEC のみ許可）。newfd が 0–2 なら標準入出力の差し替え。
    fn sys_dup(
        &mut self,
        _env: &mut BareEnv,
        fd: u32,
        newfd: Option<u32>,
        strict: bool,
    ) -> Result<u64, u64> {
        let g = if fd < 3 {
            self.std_clone(fd)?
        } else {
            self.fds
                .get(fd)
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
                    self.fds.place(n, Some(g));
                    self.dir_scans.remove(&n);
                }
                n
            }
            None => self.alloc_file(g)?,
        };
        if nfd >= 3 {
            match self.fds.path_of(fd).map(str::to_string) {
                Some(p) => self.fds.remember_path(nfd, p),
                None => self.fds.forget_path(nfd),
            }
        }
        Ok(u64::from(nfd))
    }

    /// `fcntl`。複製（F_DUPFD=0、F_DUPFD_CLOEXEC=1030）だけ実装し、
    /// フラグ系は成功だけ返す。
    fn sys_fcntl(&mut self, _env: &mut BareEnv, fd: u32, cmd: u32, arg: u64) -> Result<u64, u64> {
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
                        .get(fd)
                        .ok_or(errno::EBADF)?
                        .try_clone()
                        .map_err(|_| errno::EIO)?
                };
                let nfd = match self.fds.first_hole_where(|i| (3 + i) as u64 >= arg) {
                    Some(i) => 3 + i as u32,
                    None => (3 + self.fds.len() as u64).max(arg).max(3) as u32,
                };
                if nfd >= Self::MAX_FD {
                    return Err(errno::EMFILE);
                }
                self.fds.place(nfd, Some(g));
                if let Some(p) = self.fds.path_of(fd).map(str::to_string) {
                    self.fds.remember_path(nfd, p);
                }
                Ok(u64::from(nfd))
            }
            // F_GETFL=3 には O_LARGEFILE を立てて返す（LP64 の
            // force_o_largefile）。
            3 => Ok(oflag::LARGEFILE),
            1 | 2 | 4 => Ok(0),
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
    ) -> Result<u64, u64> {
        if !self.fd_open(fd) {
            return Err(errno::EBADF);
        }
        Err(errno::ENOTTY)
    }

    /// `stat`/`lstat`/`newfstatat` の共通部。ia64 の struct stat は
    /// 144B の 1 種のみ（stat64 別名は表に無い）。`at_empty` は
    /// AT_EMPTY_PATH — パスが空なら dirfd 自身を対象にする。
    fn sys_stat(
        &mut self,
        env: &mut BareEnv,
        dirfd: i64,
        path_addr: u64,
        out: u64,
        lstat: bool,
        at_empty: bool,
    ) -> Result<u64, u64> {
        let path = self.read_cstr(env, path_addr)?;
        let md = if path.is_empty() && at_empty && dirfd >= 0 {
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
        if self.put_stat(env, out, &md) {
            Ok(0)
        } else {
            Err(errno::EFAULT)
        }
    }

    /// `fstat`。
    fn sys_fstat(&mut self, env: &mut BareEnv, fd: u32, out: u64) -> Result<u64, u64> {
        if fd < 3 && self.std_closed[fd as usize] {
            return Err(errno::EBADF);
        }
        let md = match self.file_of(fd) {
            Some(f) => polyisa_host::fstat(f).map_err(host_errno)?,
            None if fd < 3 => polyisa_host::stat("/dev/null").map_err(host_errno)?,
            None => return Err(errno::EBADF),
        };
        if self.put_stat(env, out, &md) {
            Ok(0)
        } else {
            Err(errno::EFAULT)
        }
    }

    /// ia64 の `struct stat`（144B）を書く。
    /// dev0, ino8, nlink16, mode24, uid28, gid32, pad36, rdev40,
    /// size48, atime56, atime_nsec64, mtime72, mtime_nsec80,
    /// ctime88, ctime_nsec96, blksize104, blocks112, unused120–144。
    // Ref: SRC-LINUX-66 — uapi-asm/stat.h.
    fn put_stat(&mut self, env: &mut BareEnv, a: u64, m: &polyisa_host::Stat) -> bool {
        let mut ok = true;
        ok &= self.put64(env, a, m.dev);
        ok &= self.put64(env, a + 8, m.ino);
        ok &= self.put64(env, a + 16, m.nlink);
        ok &= self.put32(env, a + 24, m.mode);
        ok &= self.put32(env, a + 28, m.uid);
        ok &= self.put32(env, a + 32, m.gid);
        ok &= self.put32(env, a + 36, 0);
        ok &= self.put64(env, a + 40, m.rdev);
        ok &= self.put64(env, a + 48, m.size);
        ok &= self.put64(env, a + 56, m.atime as u64);
        ok &= self.put64(env, a + 64, m.atime_nsec as u64);
        ok &= self.put64(env, a + 72, m.mtime as u64);
        ok &= self.put64(env, a + 80, m.mtime_nsec as u64);
        ok &= self.put64(env, a + 88, m.ctime as u64);
        ok &= self.put64(env, a + 96, m.ctime_nsec as u64);
        ok &= self.put64(env, a + 104, m.blksize);
        ok &= self.put64(env, a + 112, m.blocks);
        ok &= self.write_bytes(env, a + 120, &[0u8; 24]);
        ok
    }

    /// 単一パス引数のファイル操作（mkdir/rmdir/unlink/truncate 等）。
    fn sys_path_op(
        &mut self,
        env: &mut BareEnv,
        dirfd: i64,
        path_addr: u64,
        op: impl FnOnce(&str) -> std::io::Result<()>,
    ) -> Result<u64, u64> {
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
    ) -> Result<u64, u64> {
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
    ) -> Result<u64, u64> {
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
    ) -> Result<u64, u64> {
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
    ) -> Result<u64, u64> {
        let path = self.read_cstr(env, path_addr)?;
        let gs = String::from_utf8_lossy(&path).into_owned();
        let target: Result<String, u64> = if gs == "/proc/self/exe" {
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
    ) -> Result<u64, u64> {
        if self.fds.get(fd).is_none() {
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

    /// `mmap`（ia64 の sys_mmap は第 6 引数をバイトオフセットで
    /// 取る）。`pg_shift` が真なら mmap2 のページ単位オフセット。
    // Ref: SRC-LINUX-66 — arch/ia64/kernel/sys_ia64.c sys_mmap2。
    fn sys_mmap(&mut self, env: &mut BareEnv, args: &[u64; 6], pg_shift: u32) -> Result<u64, u64> {
        let (addr, len, prot, flags) = (args[0], args[1], args[2] as u32, args[3] as u32);
        let (fd, off) = (args[4] as u32 as i32 as i64, args[5] << pg_shift);
        if len == 0 || len > (1 << 30) {
            return Err(if len == 0 {
                errno::EINVAL
            } else {
                errno::ENOMEM
            });
        }
        if u64::from(flags) & mman::MAP_FIXED != 0 && addr & 0xfff != 0 {
            return Err(errno::EINVAL);
        }
        if u64::from(flags) & mman::MAP_ANONYMOUS == 0
            && (fd < 0 || self.file_of(fd as u32).is_none())
        {
            return Err(errno::EBADF);
        }
        let pages = len.div_ceil(4096);
        let base = if u64::from(flags) & mman::MAP_FIXED != 0 {
            addr & !0xfff
        } else {
            // 既存写像を踏まない隙間を上向きに探す。
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
        if u64::from(prot) & mman::PROT_READ != 0 {
            p |= Perms::R.0;
        }
        if u64::from(prot) & mman::PROT_WRITE != 0 {
            p |= Perms::W.0;
        }
        if u64::from(prot) & mman::PROT_EXEC != 0 {
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
        if u64::from(flags) & mman::MAP_ANONYMOUS == 0 {
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
    fn sys_munmap(&mut self, env: &mut BareEnv, addr: u64, len: u64) -> Result<u64, u64> {
        if len == 0 || addr & 0xfff != 0 {
            return Err(errno::EINVAL);
        }
        let Some(end) = addr.checked_add(len) else {
            return Err(errno::EINVAL);
        };
        if len > (1 << 30) {
            return Err(errno::ENOMEM);
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
    ) -> Result<u64, u64> {
        let lo = addr & !0xfff;
        let Some(end) = addr.checked_add(len) else {
            return Err(errno::EINVAL);
        };
        let hi = end.div_ceil(4096) * 4096;
        if hi <= lo {
            return Err(errno::EINVAL);
        }
        let mut p = 0u8;
        if u64::from(prot) & mman::PROT_READ != 0 {
            p |= Perms::R.0;
        }
        if u64::from(prot) & mman::PROT_WRITE != 0 {
            p |= Perms::W.0;
        }
        if u64::from(prot) & mman::PROT_EXEC != 0 {
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

    /// `mremap`。MREMAP_MAYMOVE 付きだけ新領域へ複写して畳む
    /// （インプレース伸長はモデルに無い — Gap: GAP-0068）。
    fn sys_mremap(
        &mut self,
        env: &mut BareEnv,
        old_addr: u64,
        old_len: u64,
        new_len: u64,
        flags: u64,
    ) -> Result<u64, u64> {
        if flags & mman::MREMAP_MAYMOVE == 0 {
            return Err(errno::ENOMEM);
        }
        let data = self
            .read_bytes(env, old_addr, old_len.min(new_len) as usize)
            .ok_or(errno::EFAULT)?;
        let args = [
            0,
            new_len,
            mman::PROT_READ | mman::PROT_WRITE,
            mman::MAP_PRIVATE | mman::MAP_ANONYMOUS,
            0,
            0,
        ];
        let base = self.sys_mmap(env, &args, 0)?;
        if !self.write_bytes(env, base, &data) {
            return Err(errno::EFAULT);
        }
        let _ = self.sys_munmap(env, old_addr, old_len);
        Ok(base)
    }

    /// `mincore`。全写像ページは常駐なので vec に 1 を詰める。
    fn sys_mincore(
        &mut self,
        env: &mut BareEnv,
        addr: u64,
        len: u64,
        vec: u64,
    ) -> Result<u64, u64> {
        if addr & 0xfff != 0 {
            return Err(errno::EINVAL);
        }
        let pages = len.div_ceil(4096).min(1 << 20);
        if !self.write_bytes(env, vec, &vec![1u8; pages as usize]) {
            return Err(errno::EFAULT);
        }
        Ok(0)
    }

    /// `getrlimit`/`prlimit64` の struct rlimit（u64×2）。
    /// 資源番号は asm-generic の順序（STACK=3, CORE=4, RSS=5,
    /// NPROC=6, NOFILE=7, MEMLOCK=8, AS=9）。
    // Ref: SRC-LINUX-66 — uapi-asm-generic/resource.h.
    fn put_rlimit(&mut self, env: &mut BareEnv, addr: u64, res: u64) -> Result<u64, u64> {
        let (cur, max) = match res {
            // RLIMIT_STACK はスタック窓と一致させる。
            3 => (8 << 20, u64::MAX),
            // RLIMIT_NOFILE は FdTable の上限と一致。
            7 => (1024, 1024),
            _ => (u64::MAX, u64::MAX),
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
    ) -> Result<u64, u64> {
        if !self.put64(env, addr, sec) || !self.put64(env, addr + 8, nsec) {
            return Err(errno::EFAULT);
        }
        Ok(0)
    }

    /// `clock_gettime`。全クロック id を実時間に揃える。
    fn sys_clock_gettime(&mut self, env: &mut BareEnv, _clk: u64, tp: u64) -> Result<u64, u64> {
        if tp == 0 {
            return Err(errno::EFAULT);
        }
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        self.put_timespec(env, tp, d.as_secs(), u64::from(d.subsec_nanos()))
    }

    /// `gettimeofday`（tv = {u64 sec, u64 usec}。tz はゼロ埋めの
    /// struct timezone を書く）。
    fn sys_gettimeofday(&mut self, env: &mut BareEnv, tv: u64, tz: u64) -> Result<u64, u64> {
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
    fn sys_getrandom(&mut self, env: &mut BareEnv, buf: u64, len: u64) -> Result<u64, u64> {
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

    /// `uname`。machine は "ia64"。
    // Ref: SRC-LINUX-66 — struct new_utsname。
    fn sys_uname(&mut self, env: &mut BareEnv, addr: u64) -> Result<u64, u64> {
        const FIELDS: [&str; 6] = ["Linux", "polyisa", "6.6.0", "#1 polyisa", "ia64", "(none)"];
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
    fn sys_sysinfo(&mut self, env: &mut BareEnv, addr: u64) -> Result<u64, u64> {
        let secs = self.mono_start.map(|s| s.elapsed().as_secs()).unwrap_or(0);
        let mut img = [0u8; 112];
        img[..8].copy_from_slice(&(secs as i64).to_le_bytes());
        img[32..40].copy_from_slice(&(512u64 << 20).to_le_bytes());
        img[40..48].copy_from_slice(&(256u64 << 20).to_le_bytes());
        img[104..108].copy_from_slice(&1u32.to_le_bytes());
        if !self.write_bytes(env, addr, &img[..112]) {
            return Err(errno::EFAULT);
        }
        Ok(0)
    }

    /// `times`（tms: utime/stime/cutime/cstime の long×4）。
    fn sys_times(&mut self, env: &mut BareEnv, addr: u64) -> Result<u64, u64> {
        let us = self.mono_us();
        let ticks = us / 10_000; // USER_HZ=100 換算
        let mut img = [0u8; 32];
        img[..8].copy_from_slice(&ticks.to_le_bytes());
        if addr != 0 && !self.write_bytes(env, addr, &img) {
            return Err(errno::EFAULT);
        }
        Ok(ticks)
    }

    /// `statfs`/`statfs64`。ia64 の LP64 では statfs==statfs64
    /// （u64 フィールドの並び、128B）。`sz` は呼び出し側が宣言する
    /// バッファサイズ（書き込みはそれを越えない）。
    fn sys_statfs(
        &mut self,
        env: &mut BareEnv,
        addr: u64,
        target: u64,
        is_path: bool,
        sz: u64,
    ) -> Result<u64, u64> {
        if is_path {
            let path = self.read_cstr(env, target)?;
            let host = self.host_path(&path);
            polyisa_host::stat(&host).map_err(host_errno)?; // ENOENT 等
        } else if target < 3 {
            if self.std_closed[target as usize] {
                return Err(errno::EBADF);
            }
        } else if self.fds.get(target as u32).is_none() {
            return Err(errno::EBADF);
        }
        let mut img = [0u8; 128];
        img[..8].copy_from_slice(&0xEF53u64.to_le_bytes());
        img[8..16].copy_from_slice(&0x1000u64.to_le_bytes()); // bsize
        img[16..24].copy_from_slice(&0x10_0000u64.to_le_bytes());
        img[24..32].copy_from_slice(&0x8_0000u64.to_le_bytes());
        img[32..40].copy_from_slice(&0x8_0000u64.to_le_bytes());
        img[40..48].copy_from_slice(&0x1_0000u64.to_le_bytes());
        img[48..56].copy_from_slice(&0x1_0000u64.to_le_bytes());
        img[64..72].copy_from_slice(&255u64.to_le_bytes()); // namelen
        img[72..80].copy_from_slice(&0x1000u64.to_le_bytes()); // frsize
        let n = 128usize.min(usize::try_from(sz).unwrap_or(usize::MAX));
        if !self.write_bytes(env, addr, &img[..n]) {
            return Err(errno::EFAULT);
        }
        Ok(0)
    }

    /// `getcwd`。cwd を絶対パスとして返す（未 chdir なら "/"）。
    fn sys_getcwd(&mut self, env: &mut BareEnv, buf: u64, len: u64) -> Result<u64, u64> {
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
    fn sys_chdir(&mut self, env: &mut BareEnv, path_addr: u64) -> Result<u64, u64> {
        let path = self.read_cstr(env, path_addr)?;
        let host = self.host_path(&path);
        match polyisa_host::stat(&host) {
            Ok(m) if m.mode & 0o170000 == 0o040000 => {
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
    // Ref: SRC-LINUX-66 — utimensat(2)。
    fn sys_utimens(
        &mut self,
        env: &mut BareEnv,
        dirfd: i64,
        path_addr: u64,
        times_addr: u64,
        timeval: bool,
    ) -> Result<u64, u64> {
        const UTIME_NOW: u64 = (1 << 30) - 1;
        const UTIME_OMIT: u64 = (1 << 30) - 2;
        let now = std::time::SystemTime::now();
        let (mut atime, mut mtime) = (Some(now), Some(now));
        if times_addr != 0 {
            let mut read_ts = |a: u64| -> Result<Option<std::time::SystemTime>, u64> {
                let sec = self.read_u(env, a).ok_or(errno::EFAULT)? as i64;
                let sub = self.read_u(env, a + 8).ok_or(errno::EFAULT)?;
                let nsec = if timeval {
                    sub.checked_mul(1000).ok_or(errno::EINVAL)?
                } else {
                    sub
                };
                Ok(match nsec {
                    UTIME_NOW => Some(now),
                    UTIME_OMIT => None,
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
        let path = if path_addr == 0 {
            Vec::new()
        } else {
            self.read_cstr(env, path_addr)?
        };
        if path.is_empty() {
            if dirfd < 0 {
                return Err(errno::EBADF);
            }
            let f = self.fds.get(dirfd as u32).ok_or(errno::EBADF)?;
            return f.set_times(ft).map(|_| 0).map_err(host_errno);
        }
        let host = self.host_path_at(dirfd, &path)?;
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&host)
            .map_err(host_errno)?;
        f.set_times(ft).map(|_| 0).map_err(host_errno)
    }

    /// `nanosleep`/`clock_nanosleep`。req を読んで EFAULT/EINVAL を
    /// 返せるようにし、実時間は眠らず rem を 0 にする（速度優先）。
    fn sys_nanosleep(&mut self, env: &mut BareEnv, req: u64, rem: u64) -> Result<u64, u64> {
        if req == 0 || self.read_u(env, req).is_none() {
            return Err(errno::EFAULT);
        }
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
    /// sigaction = {handler u64, flags u64, restorer u64, mask 8B}
    /// = 32B（asm-generic の並び）。
    fn sys_rt_sigaction(
        &mut self,
        env: &mut BareEnv,
        _act: u64,
        oldact: u64,
        sz: u64,
    ) -> Result<u64, u64> {
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
    ) -> Result<u64, u64> {
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
    ) -> Result<u64, u64> {
        if cpu != 0 && !self.put32(env, cpu, 0) {
            return Err(errno::EFAULT);
        }
        if node != 0 && !self.put32(env, node, 0) {
            return Err(errno::EFAULT);
        }
        Ok(0)
    }

    /// 表番号 `n`（r15 − NR_BASE）の実装本体。
    fn dispatch(&mut self, env: &mut BareEnv, n: u64, args: [u64; 6]) -> Ia64Result {
        match n {
            nr::EXIT | nr::EXIT_GROUP => Ia64Result::Exit((args[0] & 0xff) as u32),
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
            nr::RENAMEAT | nr::RENAMEAT2 => {
                // RENAME_NOREPLACE 等の flags は未対応（0 以外は EINVAL）。
                if n == nr::RENAMEAT2 && args[4] != 0 {
                    return Ia64Result::Fail(errno::EINVAL);
                }
                self.sys_path_op2(
                    env,
                    args[0] as i64,
                    args[1],
                    args[2] as i64,
                    args[3],
                    |a, b| std::fs::rename(a, b),
                )
                .into()
            }
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
                    (Ok(t), Ok(l)) => match self.host_path_at(dirfd, &l) {
                        Ok(lh) => polyisa_host::symlink(&String::from_utf8_lossy(&t), &lh)
                            .map(|_| 0u64)
                            .map_err(host_errno)
                            .into(),
                        Err(e) => Ia64Result::Fail(e),
                    },
                    (Err(e), _) | (_, Err(e)) => Ia64Result::Fail(e),
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
                    None => Ia64Result::Fail(errno::EBADF),
                }
            }
            nr::CHOWN | nr::LCHOWN | nr::FCHOWNAT | nr::FCHOWN => Ia64Result::Value(0),
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
                None => Ia64Result::Fail(errno::EBADF),
            },
            nr::MKNOD | nr::MKNODAT => {
                let mode = args[if n == nr::MKNOD { 1 } else { 2 }] as u32;
                if mode & 0o170000 != 0 && mode & 0o170000 != 0o100000 {
                    Ia64Result::Fail(errno::EPERM)
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
                if args[2] != 0 && args[2] & !oflag::CLOEXEC != 0 {
                    Ia64Result::Fail(errno::EINVAL)
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
            nr::MMAP => self.sys_mmap(env, &args, 0).into(),
            nr::MMAP2 => self.sys_mmap(env, &args, 12).into(),
            nr::MUNMAP => self.sys_munmap(env, args[0], args[1]).into(),
            nr::MPROTECT => self
                .sys_mprotect(env, args[0], args[1], args[2] as u32)
                .into(),
            nr::MREMAP => self
                .sys_mremap(env, args[0], args[1], args[2], args[3])
                .into(),
            nr::MINCORE => self.sys_mincore(env, args[0], args[1], args[2]).into(),
            nr::STAT => self
                .sys_stat(env, AT_FDCWD, args[0], args[1], false, false)
                .into(),
            nr::LSTAT => self
                .sys_stat(env, AT_FDCWD, args[0], args[1], true, false)
                .into(),
            nr::FSTAT => self.sys_fstat(env, args[0] as u32, args[1]).into(),
            // AT_SYMLINK_NOFOLLOW=0x100、AT_EMPTY_PATH=0x1000。
            nr::NEWFSTATAT => self
                .sys_stat(
                    env,
                    args[0] as i64,
                    args[1],
                    args[2],
                    args[3] & 0x100 != 0,
                    args[3] & 0x1000 != 0,
                )
                .into(),
            nr::ACCESS => self.sys_access(env, AT_FDCWD, args[0], args[1]).into(),
            nr::FACCESSAT | nr::FACCESSAT2 => self
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
            nr::FCHDIR => match self.fds.path_of(args[0] as u32).map(str::to_string) {
                Some(p) => match polyisa_host::stat(&p) {
                    Ok(m) if m.mode & 0o170000 == 0o040000 => {
                        self.cwd = p;
                        Ia64Result::Value(0)
                    }
                    Ok(_) => Ia64Result::Fail(errno::ENOTDIR),
                    Err(e) => Ia64Result::Fail(host_errno(e)),
                },
                None => Ia64Result::Fail(errno::EBADF),
            },
            // statfs(path, buf) / fstatfs(fd, buf) は 2 引数、
            // statfs64/fstatfs64 は (path|fd, sz, buf) の 3 引数。
            nr::STATFS => self.sys_statfs(env, args[1], args[0], true, 128).into(),
            nr::FSTATFS => self.sys_statfs(env, args[1], args[0], false, 128).into(),
            nr::STATFS64 => self.sys_statfs(env, args[2], args[0], true, args[1]).into(),
            nr::FSTATFS64 => self
                .sys_statfs(env, args[2], args[0], false, args[1])
                .into(),
            nr::GETRLIMIT => self.put_rlimit(env, args[1], args[0]).into(),
            nr::PRLIMIT64 => {
                if args[3] != 0 {
                    self.put_rlimit(env, args[3], args[1]).into()
                } else {
                    Ia64Result::Value(0)
                }
            }
            nr::SETRLIMIT => Ia64Result::Value(0),
            nr::UNAME => self.sys_uname(env, args[0]).into(),
            nr::SYSINFO => self.sys_sysinfo(env, args[0]).into(),
            nr::TIMES => self.sys_times(env, args[0]).into(),
            nr::GETTIMEOFDAY => self.sys_gettimeofday(env, args[0], args[1]).into(),
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
            nr::OLD_GETPAGESIZE => Ia64Result::Value(4096),
            nr::GETTID | nr::SET_TID_ADDRESS => Ia64Result::Value(self.pid()),
            nr::GETPID => Ia64Result::Value(self.pid()),
            nr::GETPPID => Ia64Result::Value(1),
            nr::GETUID | nr::GETEUID | nr::GETGID | nr::GETEGID => Ia64Result::Value(0),
            nr::GETRESUID | nr::GETRESGID => {
                // ruid/euid/suid = 0 を3個書く。
                for &a in args.iter().take(3) {
                    if a != 0 && !self.put32(env, a, 0) {
                        return Ia64Result::Fail(errno::EFAULT);
                    }
                }
                Ia64Result::Value(0)
            }
            nr::GETPGID | nr::GETSID => Ia64Result::Value(self.pid()),
            nr::GETGROUPS => Ia64Result::Value(0),
            nr::SETPGID
            | nr::SETGID
            | nr::SETUID
            | nr::SETREUID
            | nr::SETREGID
            | nr::SETSID
            | nr::SETITIMER
            | nr::SETHOSTNAME
            | nr::SETDOMAINNAME
            | nr::CAPSET
            | nr::IOPRIO_SET => Ia64Result::Value(0),
            nr::IOPRIO_GET => Ia64Result::Value(0),
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
            nr::RT_SIGPROCMASK => self
                .sys_rt_sigprocmask(env, args[0], args[1], args[2], args[3])
                .into(),
            nr::RT_SIGPENDING => {
                // 配送しない実装なので pending 集合は常に空。
                if self.put64(env, args[0], 0) {
                    Ia64Result::Value(0)
                } else {
                    Ia64Result::Fail(errno::EFAULT)
                }
            }
            nr::SIGALTSTACK => {
                // ss 指定時はポインタの読み取り可能性を検査する。
                if args[0] != 0 && self.read_u(env, args[0]).is_none() {
                    return Ia64Result::Fail(errno::EFAULT);
                }
                // stack_t {sp, flags:i32+pad, size} = 24B。
                // old には {sp:0, flags:SS_DISABLE=2, size:0} を書く。
                if args[1] != 0
                    && (!self.put64(env, args[1], 0)
                        || !self.put32(env, args[1] + 8, 2)
                        || !self.put64(env, args[1] + 16, 0))
                {
                    return Ia64Result::Fail(errno::EFAULT);
                }
                Ia64Result::Value(0)
            }
            nr::RT_SIGSUSPEND => Ia64Result::Fail(errno::EINTR),
            nr::KILL | nr::TKILL | nr::TGKILL => {
                // 単一プロセス: 自分自身（pid=1 / 0=グループ）への
                // 送信は成功、他は ESRCH。
                if args[0] as i64 == self.pid() as i64 || args[0] == 0 {
                    Ia64Result::Value(0)
                } else {
                    Ia64Result::Fail(errno::ESRCH)
                }
            }
            nr::SCHED_YIELD => Ia64Result::Value(0),
            nr::SCHED_GET_PRIORITY_MAX | nr::SCHED_GET_PRIORITY_MIN => {
                let (mx, mn) = match args[0] {
                    1 | 2 => (99, 1),
                    0 | 3 | 5 | 6 => (0, 0),
                    _ => return Ia64Result::Fail(errno::EINVAL),
                };
                Ia64Result::Value(if n == nr::SCHED_GET_PRIORITY_MAX {
                    mx
                } else {
                    mn
                })
            }
            nr::SCHED_GETPARAM => {
                if !self.put32(env, args[1], 0) {
                    return Ia64Result::Fail(errno::EFAULT);
                }
                Ia64Result::Value(0)
            }
            nr::SCHED_SETPARAM | nr::SCHED_SETSCHEDULER => Ia64Result::Value(0),
            nr::SCHED_GETSCHEDULER => Ia64Result::Value(0),
            nr::SCHED_RR_GET_INTERVAL => self.put_timespec(env, args[1], 0, 0).into(),
            nr::SCHED_GETAFFINITY => {
                // 1 CPU だけのマスク（bit0）を書く。戻り値は書いた
                // マスクのバイト数。
                let len = args[1].min(8);
                let mut img = [0u8; 8];
                img[0] = 1;
                if !self.write_bytes(env, args[2], &img[..len as usize]) {
                    return Ia64Result::Fail(errno::EFAULT);
                }
                Ia64Result::Value(len)
            }
            nr::SCHED_SETAFFINITY => Ia64Result::Value(0),
            nr::SET_ROBUST_LIST => Ia64Result::Value(0),
            nr::MADVISE
            | nr::READAHEAD
            | nr::FADVISE64
            | nr::FLOCK
            | nr::MSYNC
            | nr::MLOCK
            | nr::MLOCK2
            | nr::MUNLOCK
            | nr::MLOCKALL
            | nr::MUNLOCKALL
            | nr::SYNC
            | nr::VHANGUP => Ia64Result::Value(0),
            nr::FSYNC | nr::FDATASYNC => {
                let fd = args[0] as u32;
                match self.file_of(fd) {
                    Some(f) => match f.sync_all() {
                        Ok(()) => Ia64Result::Value(0),
                        Err(e) => Ia64Result::Fail(host_errno(e)),
                    },
                    None if fd < 3 && !self.std_closed[fd as usize] => Ia64Result::Value(0),
                    None => Ia64Result::Fail(errno::EBADF),
                }
            }
            nr::UMASK => {
                let old = self.umask;
                self.umask = (args[0] as u32) & 0o777;
                Ia64Result::Value(u64::from(old))
            }
            nr::PERSONALITY => Ia64Result::Value(0),
            nr::PRCTL => {
                // PR_SET_NAME=15 / PR_GET_NAME=16。
                match args[0] {
                    15 => {
                        let b = self
                            .read_bytes(env, args[1], 16)
                            .unwrap_or([0u8; 16].to_vec());
                        self.proc_name.copy_from_slice(&b[..16.min(b.len())]);
                        Ia64Result::Value(0)
                    }
                    16 => {
                        let name = self.proc_name;
                        if !self.write_bytes(env, args[1], &name) {
                            return Ia64Result::Fail(errno::EFAULT);
                        }
                        Ia64Result::Value(0)
                    }
                    _ => Ia64Result::Value(0),
                }
            }
            // poll/select 系のスタブ: タイムアウト扱いで 0 を返すが、
            // 出力集合・revents もクリアして呼び出し側の判定を守る。
            nr::POLL | nr::PPOLL => {
                // pollfd = {fd i32, events i16, revents i16}（8B）。
                let (fds, nfds) = (args[0], args[1]);
                for i in 0..nfds.min(1024) {
                    let a = fds.wrapping_add(i * 8);
                    if !self.write_bytes(env, a + 6, &[0, 0]) {
                        return Ia64Result::Fail(errno::EFAULT);
                    }
                }
                Ia64Result::Value(0)
            }
            nr::SELECT | nr::PSELECT6 => {
                let n = args[0];
                let words = n.min(1024).div_ceil(64) * 8;
                for &a in args.iter().take(4).skip(1) {
                    if a != 0 {
                        let z = vec![0u8; words as usize];
                        if !self.write_bytes(env, a, &z) {
                            return Ia64Result::Fail(errno::EFAULT);
                        }
                    }
                }
                Ia64Result::Value(0)
            }
            nr::GETITIMER => {
                if self.write_bytes(env, args[1], &[0u8; 32]) {
                    Ia64Result::Value(0)
                } else {
                    Ia64Result::Fail(errno::EFAULT)
                }
            }
            nr::GETRUSAGE => {
                if self.write_bytes(env, args[1], &[0u8; 144]) {
                    Ia64Result::Value(0)
                } else {
                    Ia64Result::Fail(errno::EFAULT)
                }
            }
            nr::CAPGET => {
                if self.write_bytes(env, args[1], &[0u8; 24]) {
                    Ia64Result::Value(0)
                } else {
                    Ia64Result::Fail(errno::EFAULT)
                }
            }
            nr::SENDFILE => self
                .sys_sendfile(env, args[0] as u32, args[1] as u32, args[2], args[3])
                .into(),
            nr::WAIT4 | nr::WAITID => Ia64Result::Fail(errno::ECHILD),
            nr::EXECVE
            | nr::EXECVEAT
            | nr::CLONE
            | nr::CLONE2
            | nr::PTRACE
            | nr::PIPE
            | nr::PIPE2 => Ia64Result::Unimpl,
            _ => Ia64Result::Unimpl,
        }
    }

    /// 戻り値規約: 成功は r8=値・r10=0、失敗は r8=errno・r10=-1。
    /// r8/r10 の NaT は落とす。
    /// Ref: SRC-LINUX-66 — kernel/entry.S（strace_error の
    /// 反転と r10 設定の規約）.
    fn ret(b: &mut InterpBackend, r: Result<u64, u64>) {
        let (r8, r10) = match r {
            Ok(v) => (v, 0),
            Err(e) => (e, u64::MAX),
        };
        sem::gr_set(b, 8, r8);
        sem::nat_set(b, 8, false);
        sem::gr_set(b, 10, r10);
        sem::nat_set(b, 10, false);
    }

    /// r15 の番号と out0–out5 の引数を読んで dispatch し、
    /// r8/r10 に結果を書く。
    fn syscall(&mut self, env: &mut BareEnv) -> TrapOutcome {
        let b = &mut env.backend;
        // 範囲検査は `n = r15 - NR_BASE` が 0..NR_SYSCALLS。epc
        // 入口の `tnat.nz p10` に倣い r15 が NaT なら EINVAL
        // （break 経路にも同じ近似を適用 — Gap: GAP-0068）。
        if sem::nat_get(b, 15) {
            Self::ret(b, Err(errno::EINVAL));
            return TrapOutcome::Handled;
        }
        let n = sem::gr_get(b, 15).wrapping_sub(NR_BASE);
        let a = [
            sem::out_get(b, 0),
            sem::out_get(b, 1),
            sem::out_get(b, 2),
            sem::out_get(b, 3),
            sem::out_get(b, 4),
            sem::out_get(b, 5),
        ];
        if trace() {
            let nm = name(n).unwrap_or("?");
            eprintln!("sys {n} {nm} a0={:#x} a1={:#x}", a[0], a[1]);
        }
        if n >= NR_SYSCALLS {
            Self::ret(&mut env.backend, Err(errno::ENOSYS));
            return TrapOutcome::Handled;
        }
        match self.dispatch(env, n, a) {
            Ia64Result::Value(v) => {
                Self::ret(&mut env.backend, Ok(v));
                TrapOutcome::Handled
            }
            Ia64Result::Fail(e) => {
                Self::ret(&mut env.backend, Err(e));
                TrapOutcome::Handled
            }
            Ia64Result::Exit(c) => TrapOutcome::Exit(c),
            Ia64Result::Unimpl => {
                let nm = name(n).unwrap_or("?");
                if !self.reported.contains(&n) {
                    self.reported.push(n);
                    eprintln!("ia64: unimplemented syscall {n} ({nm})");
                }
                Self::ret(&mut env.backend, Err(errno::ENOSYS));
                TrapOutcome::Handled
            }
        }
    }
}

/// syscall 内部戻り値。r8/r10 に写すか、Exit で終了するか。
enum Ia64Result {
    /// r8 に値、r10=0。
    Value(u64),
    /// r10=-1 で r8 が errno。
    Fail(u64),
    /// 終了コード。
    Exit(u32),
    /// 未実装番号（ENOSYS に畳んで一度だけ報告）。
    Unimpl,
}

impl From<Result<u64, u64>> for Ia64Result {
    fn from(r: Result<u64, u64>) -> Self {
        match r {
            Ok(v) => Ia64Result::Value(v),
            Err(e) => Ia64Result::Fail(e),
        }
    }
}

/// ホストの io エラーを ia64 の errno へ写す。ia64 は asm-generic
/// の errno 表でホスト Linux と同じ値なので、raw_os_error を
/// そのまま使う（未知は EIO）。
fn host_errno(e: std::io::Error) -> u64 {
    e.raw_os_error().map(|v| v as u64).unwrap_or(errno::EIO)
}

impl TrapHandler for Linux {
    /// `brk` の初期値。ローダが像の末尾を渡す。カーネルは
    /// ELF_PAGEALIGN（ia64 のページは 4KiB）で切り上げる。
    fn init_brk(&mut self, image_end: u64) {
        let b = image_end.next_multiple_of(4096);
        self.heap_end = b;
        self.brk_start = b;
    }

    fn handle_trap(&mut self, env: &mut BareEnv, code: u32) -> TrapOutcome {
        // __IA64_BREAK_SYSCALL 以外の break 値（KDB/KPROBE は
        // ユーザモードで到達しない）と TRAP_ILL 等の内部番号は
        // 未実装に畳む。
        if code != brk::SYSCALL {
            return TrapOutcome::Unimplemented;
        }
        self.syscall(env)
    }
}

/// ゲート領域を写像し、コードページに via_break/via_epc 入口の
/// バンドルを書く。
///
/// 両入口とも `{ .mib break 0x100000; nop.i 0; br.ret.sptk.many b6 }`
/// （正本 gate.S の __kernel_syscall_via_break と同じ形）。
/// __kernel_syscall_via_epc は epc の特権移行で syscall 本体を
/// 呼ぶが、ユーザに観測される規約（r15/out 引数・r8/r10 戻り・
/// b6 経由の復帰）は同一なので同じバンドルに畳む
/// （Gap: GAP-0068）。`gate::SIGTRAMP` は位置の予約のみで、
/// 中身はシグナル配送の実装時に置く。`gate::ADDR` 側は
/// AT_SYSINFO_EHDR が指す ELF ヘッダページの置き場として
/// 読み出し専用に開ける（中身はローダ側が供給する）。
// Ref: SRC-LINUX-66 — kernel/gate.S, kernel/mm-init.c.
pub fn install_gate_page(env: &mut BareEnv) -> Result<(), String> {
    let brk_w = encode_break_m(&[0, u64::from(brk::SYSCALL)]).ok_or("encode break.m")? as u64;
    let nop_w = encode_nop_i(&[0, 0]).ok_or("encode nop.i")? as u64;
    let ret_w = encode_br_ret(&[0, 6]).ok_or("encode br.ret")? as u64;
    let b = bundle::pack_bundle(8, false, brk_w, nop_w, ret_w);
    let mem = &mut env.backend.mem;
    mem.map(VirtAddr(gate::ADDR), 1, Perms::R)
        .map_err(|e| format!("gate ehdr: {e:?}"))?;
    mem.map(VirtAddr(gate::CODE), 1, Perms::RW)
        .map_err(|e| format!("gate code: {e:?}"))?;
    for addr in [gate::SYSCALL_VIA_BREAK, gate::SYSCALL_VIA_EPC] {
        mem.write(VirtAddr(addr), &b.to_le_bytes())
            .map_err(|e| format!("gate write: {e:?}"))?;
    }
    // コードページは PAGE_GATE（実行専用）に合わせる。
    mem.protect(VirtAddr(gate::CODE), 1, Perms::X)
        .map_err(|e| format!("gate protect: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_engine::run::Outcome;
    use polyisa_guest_ia64::{CpuState, FEAT_ITANIUM, FEAT_ITANIUM2, cfm_bit, encode_nop_b, run};
    use polyisa_sem::Backend as _;

    const CPU: u128 = FEAT_ITANIUM | FEAT_ITANIUM2;
    const BASE: u64 = 0x40_0000;
    const DATA: u64 = 0x50_0000;

    fn env() -> BareEnv {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        env.backend
            .mem
            .map(VirtAddr(BASE), 1, Perms(0b111))
            .unwrap();
        env.backend.mem.map(VirtAddr(DATA), 1, Perms::RW).unwrap();
        env
    }

    fn put_bundle(env: &mut BareEnv, addr: u64, b: u128) {
        env.backend
            .mem
            .write(VirtAddr(addr), &b.to_le_bytes())
            .unwrap();
    }

    /// `{ .mib <slot0>; nop.i; <slot2 B> }`（stop 付き）。
    fn mib(stop: bool, s0: u64, s1: u64, s2: u64) -> u128 {
        bundle::pack_bundle(8, stop, s0, s1, s2)
    }

    /// 現在フレーム（sof, sol）に設定する。
    fn set_frame(env: &mut BareEnv, sof: u64, sol: u64) {
        env.backend.set(sem::cfm_ref(), sof | (sol << cfm_bit::SOL));
    }

    fn break_w() -> u64 {
        encode_break_m(&[0, u64::from(brk::SYSCALL)]).unwrap() as u64
    }

    fn nop_i() -> u64 {
        encode_nop_i(&[0, 0]).unwrap() as u64
    }

    /// break で write(fd=1, buf, len) を発行して次命令群へ戻る。
    /// 引数は現在フレームの out0–out2（sol>0 のフレームで
    /// フレーム位置の解決も兼ねて確かめる）。
    #[test]
    fn break_syscall_write_and_resume() {
        let mut env = env();
        let mut sys = Linux::new();
        // sof=10, sol=4 → out0.. は仮想 r36..。
        set_frame(&mut env, 10, 4);
        sem::gr_set(&mut env.backend, 15, NR_BASE + nr::WRITE);
        for (i, v) in [1u64, DATA, 2].iter().enumerate() {
            sem::gr_set(&mut env.backend, (32 + 4 + i) as u32, *v);
        }
        env.backend.mem.write(VirtAddr(DATA), b"hi").unwrap();
        let nop_b = encode_nop_b(&[0, 0]).unwrap() as u64;
        put_bundle(&mut env, BASE, mib(true, break_w(), nop_i(), nop_b));
        env.pc = BASE;
        run::step(&mut env, &mut sys, CPU).unwrap();
        // r8 = 書いたバイト数、r10 = 0（成功旗）。
        assert_eq!(sem::gr_get(&env.backend, 8), 2);
        assert_eq!(sem::gr_get(&env.backend, 10), 0);
        assert!(!sem::nat_get(&env.backend, 8));
        assert_eq!(sys.io.stdout, b"hi");
        // Handled の復帰は break の次のスロット（戻り先規約）。
        assert_eq!(env.pc, BASE | 1);
        // 残りスロットを進めると次のバンドルへ。
        run::step(&mut env, &mut sys, CPU).unwrap();
        assert_eq!(env.pc, BASE + 16);
    }

    /// 未知番号は ENOSYS（r8=errno・r10=-1）。
    #[test]
    fn unknown_nr_returns_enosys() {
        let mut env = env();
        let mut sys = Linux::new();
        set_frame(&mut env, 8, 0);
        sem::gr_set(&mut env.backend, 15, NR_BASE + NR_SYSCALLS);
        put_bundle(&mut env, BASE, mib(true, break_w(), nop_i(), 0));
        env.pc = BASE;
        run::step(&mut env, &mut sys, CPU).unwrap();
        assert_eq!(sem::gr_get(&env.backend, 8), errno::ENOSYS);
        assert_eq!(sem::gr_get(&env.backend, 10), u64::MAX);
    }

    /// r15 が NaT なら EINVAL（epc 入口の tnat.nz と同じ判定）。
    #[test]
    fn nat_nr_returns_einval() {
        let mut env = env();
        let mut sys = Linux::new();
        set_frame(&mut env, 8, 0);
        sem::gr_set(&mut env.backend, 15, NR_BASE + nr::WRITE);
        sem::nat_set(&mut env.backend, 15, true);
        put_bundle(&mut env, BASE, mib(true, break_w(), nop_i(), 0));
        env.pc = BASE;
        run::step(&mut env, &mut sys, CPU).unwrap();
        assert_eq!(sem::gr_get(&env.backend, 8), errno::EINVAL);
        assert_eq!(sem::gr_get(&env.backend, 10), u64::MAX);
        assert_eq!(sys.io.stdout, Vec::<u8>::new());
    }

    /// syscall 以外の break 値はパーソナリティの未実装（
    /// `Outcome::Unimplemented` に写る）。
    #[test]
    fn non_syscall_break_is_unimplemented() {
        let mut env = env();
        let mut sys = Linux::new();
        let kdb = encode_break_m(&[0, 0x80100]).unwrap() as u64;
        put_bundle(&mut env, BASE, mib(true, kdb, nop_i(), 0));
        env.pc = BASE;
        let r = run::step(&mut env, &mut sys, CPU);
        assert!(matches!(r, Err(Outcome::Unimplemented { .. })));
    }

    /// exit_group は TrapOutcome::Exit → Outcome::Exit に写る。
    #[test]
    fn exit_group_exits() {
        let mut env = env();
        let mut sys = Linux::new();
        set_frame(&mut env, 8, 0);
        sem::gr_set(&mut env.backend, 15, NR_BASE + nr::EXIT_GROUP);
        sem::gr_set(&mut env.backend, 32, 42);
        put_bundle(&mut env, BASE, mib(true, break_w(), nop_i(), 0));
        env.pc = BASE;
        let r = run::step(&mut env, &mut sys, CPU);
        assert!(matches!(r, Err(Outcome::Exit(42))));
    }

    /// ゲートページ経由（epc 入口への br.call）でも同じ規約で
    /// syscall が往復し、br.ret b6 で呼出側へ戻る。
    #[test]
    fn gate_epc_call_roundtrip() {
        let mut env = env();
        let mut sys = Linux::new();
        install_gate_page(&mut env).unwrap();
        // { .mib nop.m; nop.i; br.call b6=b2 } → ゲート入口へ。
        env.backend.set(sem::br_ref(2), gate::SYSCALL_VIA_EPC);
        let nop_m = polyisa_guest_ia64::encode_nop_m(&[0, 0]).unwrap() as u64;
        let call = polyisa_guest_ia64::encode_br_call_ind(&[0, 6, 2]).unwrap() as u64;
        put_bundle(&mut env, BASE, mib(true, nop_m, nop_i(), call));
        // 呼出側のフレームに引数を用意（br.call で新フレームの
        // r32.. に写る）。
        set_frame(&mut env, 10, 4);
        sem::gr_set(&mut env.backend, 15, NR_BASE + nr::WRITE);
        for (i, v) in [1u64, DATA, 3].iter().enumerate() {
            sem::gr_set(&mut env.backend, (32 + 4 + i) as u32, *v);
        }
        env.backend.mem.write(VirtAddr(DATA), b"epc").unwrap();
        env.pc = BASE;
        run::step(&mut env, &mut sys, CPU).unwrap();
        assert_eq!(env.pc, gate::SYSCALL_VIA_EPC);
        // ゲートのバンドル: break → Handled（復帰は次スロット）。
        run::step(&mut env, &mut sys, CPU).unwrap();
        assert_eq!(env.pc, gate::SYSCALL_VIA_EPC | 1);
        // 残りスロット: nop.i → br.ret b6 で呼出側へ戻る。
        run::step(&mut env, &mut sys, CPU).unwrap();
        assert_eq!(env.pc, BASE + 16);
        assert_eq!(sem::gr_get(&env.backend, 8), 3);
        assert_eq!(sem::gr_get(&env.backend, 10), 0);
        assert_eq!(sys.io.stdout, b"epc");
        // br.ret b6 で呼出側フレームに復帰（sol=4 が戻る）。
        assert_eq!(env.backend.get(sem::cfm_ref()) >> cfm_bit::SOL & 0x7f, 4);
    }

    /// via_break 入口も同じバンドル形で syscall を往復する。
    #[test]
    fn gate_via_break_roundtrip() {
        let mut env = env();
        let mut sys = Linux::new();
        install_gate_page(&mut env).unwrap();
        env.backend.set(sem::br_ref(2), gate::SYSCALL_VIA_BREAK);
        let nop_m = polyisa_guest_ia64::encode_nop_m(&[0, 0]).unwrap() as u64;
        let call = polyisa_guest_ia64::encode_br_call_ind(&[0, 6, 2]).unwrap() as u64;
        put_bundle(&mut env, BASE, mib(true, nop_m, nop_i(), call));
        set_frame(&mut env, 8, 0);
        sem::gr_set(&mut env.backend, 15, NR_BASE + nr::EXIT_GROUP);
        sem::gr_set(&mut env.backend, 32, 7);
        env.pc = BASE;
        run::step(&mut env, &mut sys, CPU).unwrap();
        let r = run::step(&mut env, &mut sys, CPU);
        assert!(matches!(r, Err(Outcome::Exit(7))));
    }
}
