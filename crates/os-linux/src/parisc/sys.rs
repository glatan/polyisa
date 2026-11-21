// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! PA-RISC Linux の syscall 処理。`cli` の実行ループからページゼロの
//! ゲートウェイ入口を `handle_trap` の code として委譲される。
//!
//! 規約（SRC-LINUX — arch/parisc syscall 規約）:
//! - 発行点は `ble 0x100(%sr2,%r0)`。ゲートウェイ番地 `0x100` が
//!   `handle_trap` の code に来る。
//! - 番号は `r20`、引数は `r26`（arg0）から `r21`（arg5）へ降順、
//!   戻り値は `r28`（エラーは負の errno）、戻り番地は `r31`。
//!   キュー（`iaoq_f`/`iaoq_b`）の `r31` への復帰は実行ループ側。
//! - `0xb0` は LWS（`r20`=副番号 0=CAS/1=CAS64/2=CAS2/3=xchg/
//!   4=store、`r26`=adr。CAS は `r25`=old・`r24`=new、CAS2/
//!   xchg/store はポインタ経由＋サイズコード。結果 `r28`、
//!   状態 `r21`=0/-errno）。
//! - `0xe0`（set_thread_pointer: `cr27 = r26`）は実行ループの
//!   内蔵処理で、ここには来ない。
//! - hppa 固有: 64 ビット引数は (hi, lo) の語対として渡る
//!   （`parisc_pread64`/`parisc_fadvise64_64` など）。mmap の
//!   オフセットはバイト単位、mmap2 はページオフセット。
//!
//! 実装対象は hppa32（BE）の Linux ユーザー ABI。FdTable による
//! fd 管理・dirfd 対応パス解決・stat/stat64/statx・getdents64・
//! ファイル操作全般を alpha/sys.rs の型に写す。fork/clone/
//! execve/wait4 などプロセス生成系は単一プロセスモデルのため
//! ENOSYS（GAP-0058）。

use std::collections::HashMap;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

use polyisa_engine::bare::BareEnv;
use polyisa_guest_parisc::sem;
use polyisa_kernel::FdTable;
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};
use polyisa_sem::Backend as _;

use crate::parisc::{at, errno, gate, lws, mman, nr, oflag, res};
use crate::{TrapHandler, TrapOutcome};

/// AT_FDCWD。
const AT_FDCWD: i64 = at::FDCWD;

/// getdents64 の fd ごとの走査状態（entries, pos）。
type DirScan = (Vec<(u64, String, u8)>, usize);

/// PA-RISC の write が集めたバイト。標準出力と標準エラーを分ける。
#[derive(Default)]
pub struct PariscIo {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// PA-RISC Linux の syscall 状態機械。`r20`=番号、`r26`–`r21`=引数。
// Gap: GAP-0058 — 単一プロセス模型の意図的な簡略化（fork/exec なし、
// select/poll/nanosleep はスタブ、statfs は合成値、シグナル配送なし）。
pub struct Linux {
    /// 標準入出力の capture。テストが読む。
    pub io: PariscIo,
    /// ゲスト fd → ホストファイル。ゲスト fd は 3 から。
    fds: FdTable,
    /// getdents64 の走査位置（fd ごと）。
    dir_scans: HashMap<u32, DirScan>,
    /// ゲストのカレントディレクトリ。相対パスの基点。
    cwd: String,
    /// プログラムブレーク。0 は未初期化。
    heap_end: u64,
    /// brk 領域の開始（ELF の image_end）。`init_brk` が設定する。
    brk_start: u64,
    /// mmap の次に置く場所。末尾から伸ばす。
    mmap_next: u64,
    umask: u32,
    /// ホストから見たプロセス識別子。getpid/gettid が返す。
    pid: u64,
    /// ゲストの実行ファイルのホストパス。/proc/self/exe の readlink 用。
    pub exe_path: String,
    /// 報告済みの未実装番号（一度だけ出す）。
    reported: Vec<u64>,
    /// 標準入力へ供給するバイト。
    pub stdin_buf: Vec<u8>,
    stdin_pos: usize,
    /// MONOTONIC 時計の起点。
    mono_start: Option<std::time::Instant>,
    /// getrandom の決定的乱数状態。
    rand_state: u64,
    /// rt_sigprocmask 系で覚える仮のシグナルマスク。
    sig_mask: u64,
    /// prctl(PR_SET_NAME) で覚える comm（16B）。
    proc_name: [u8; 16],
    /// 0–2 の差し替え fd（dup2 のリダイレクト先）。
    std_fds: [Option<std::fs::File>; 3],
    /// 0–2 の close 状態。
    std_closed: [bool; 3],
}

impl Default for Linux {
    fn default() -> Self {
        Self::new()
    }
}

/// エラー errno を負値にして `r28` へ返す値にする。
fn fail(e: u32) -> u64 {
    (-(e as i64)) as u64
}

/// `r28` へ書く値・Exit・未実装の三択。
enum Disp {
    /// r28 にこの値を書いて続ける。
    Ret(u64),
    /// 終了コード付きで抜ける。
    Exit(u32),
    /// 未実装番号（ENOSYS を書いて報告する）。
    Unimpl,
}

fn ok(v: u64) -> Disp {
    Disp::Ret(v)
}

fn bad(e: u32) -> Disp {
    Disp::Ret(fail(e))
}

fn res(r: Result<u64, u32>) -> Disp {
    match r {
        Ok(v) => Disp::Ret(v),
        Err(e) => bad(e),
    }
}

impl Linux {
    /// PA-RISC Linux の状態機械を作る。データはビッグエンディアン。
    #[must_use]
    pub fn new() -> Self {
        Self {
            io: PariscIo::default(),
            fds: FdTable::default(),
            dir_scans: HashMap::new(),
            cwd: String::new(),
            heap_end: 0,
            brk_start: 0,
            mmap_next: 0x6000_0000,
            umask: 0o22,
            pid: 0,
            exe_path: String::new(),
            reported: Vec::new(),
            stdin_buf: Vec::new(),
            stdin_pos: 0,
            mono_start: None,
            rand_state: 0x9e37_79b9_7f4a_7c15,
            sig_mask: 0,
            proc_name: [0; 16],
            std_fds: [None, None, None],
            std_closed: [false; 3],
        }
    }

    /// ELF の `image_end` からプログラムブレークを初期化する。
    pub fn init_brk(&mut self, image_end: u64) {
        let e = image_end.div_ceil(4096) * 4096;
        self.brk_start = e;
        self.heap_end = e;
        // mmap 領域はヒープの後ろに十分な間を取る。
        self.mmap_next = self.mmap_next.max(e + 0x400_0000);
    }

    fn pid(&mut self) -> u64 {
        if self.pid == 0 {
            self.pid = 1;
        }
        self.pid
    }

    /// 単調時計の経過。
    fn mono(&mut self) -> std::time::Duration {
        self.mono_start
            .get_or_insert_with(std::time::Instant::now)
            .elapsed()
    }

    // ---- メモリ補助（BE・32 ビット ABI）----

    fn acc(&self, kind: AccessKind) -> Access {
        Access {
            endian: Endian::Be,
            align: Align::Unaligned,
            kind,
        }
    }

    fn read_bytes(&mut self, env: &mut BareEnv, addr: u64, len: usize) -> Option<Vec<u8>> {
        let mut v = vec![0u8; len.min(1 << 20)];
        env.backend
            .mem
            .read(VirtAddr(addr), &mut v, self.acc(AccessKind::DataRead))
            .ok()?;
        Some(v)
    }

    fn write_bytes(&mut self, env: &mut BareEnv, addr: u64, data: &[u8]) -> bool {
        env.backend.mem.write(VirtAddr(addr), data).is_ok()
    }

    /// BE の u32 を読む。
    fn get32(&mut self, env: &mut BareEnv, addr: u64) -> Option<u64> {
        env.backend
            .mem
            .read_value(VirtAddr(addr), 4, self.acc(AccessKind::DataRead))
            .ok()
    }

    /// BE の u16 を読む（現状はテストの dirent 検査だけが使う）。
    #[cfg(test)]
    fn get16(&mut self, env: &mut BareEnv, addr: u64) -> Option<u64> {
        env.backend
            .mem
            .read_value(VirtAddr(addr), 2, self.acc(AccessKind::DataRead))
            .ok()
    }

    /// BE の u64 を読む。
    fn get64(&mut self, env: &mut BareEnv, addr: u64) -> Option<u64> {
        env.backend
            .mem
            .read_value(VirtAddr(addr), 8, self.acc(AccessKind::DataRead))
            .ok()
    }

    /// BE の u32 を書く。
    fn put32(&mut self, env: &mut BareEnv, addr: u64, v: u32) -> bool {
        env.backend
            .mem
            .write(VirtAddr(addr), &v.to_be_bytes())
            .is_ok()
    }

    /// BE の u16 を書く。
    fn put16(&mut self, env: &mut BareEnv, addr: u64, v: u16) -> bool {
        env.backend
            .mem
            .write(VirtAddr(addr), &v.to_be_bytes())
            .is_ok()
    }

    /// BE の u64 を書く。
    fn put64(&mut self, env: &mut BareEnv, addr: u64, v: u64) -> bool {
        env.backend
            .mem
            .write(VirtAddr(addr), &v.to_be_bytes())
            .is_ok()
    }

    /// C 文字列を読む。上限 4096。
    fn read_cstr(&mut self, env: &mut BareEnv, addr: u64) -> Result<Vec<u8>, u32> {
        let mut out = Vec::new();
        for i in 0..4096u64 {
            let mut b = [0u8; 1];
            if env
                .backend
                .mem
                .read(VirtAddr(addr + i), &mut b, self.acc(AccessKind::DataRead))
                .is_err()
            {
                return Err(errno::EFAULT);
            }
            if b[0] == 0 {
                return Ok(out);
            }
            out.push(b[0]);
        }
        Err(errno::ENAMETOOLONG)
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
        self.mono().as_micros() as u64
    }

    // ---- syscall 本体 ----

    /// `brk`。0 は現ブレークを返し、それ以外は要求値を適用する
    /// （失敗しても現ブレークを返す — kernel の sys_brk と同じ）。
    fn sys_brk(&mut self, env: &mut BareEnv, addr: u64) -> u64 {
        if addr == 0 || addr < self.brk_start {
            return self.heap_end;
        }
        if addr > self.heap_end {
            let lo = self.heap_end.div_ceil(4096) * 4096;
            let hi = addr.div_ceil(4096) * 4096;
            if (lo..hi)
                .step_by(4096)
                .any(|a| env.backend.mem.is_mapped(polyisa_mem::PageNo(a / 4096)))
            {
                return self.heap_end;
            }
            if hi > lo
                && env
                    .backend
                    .mem
                    .map(VirtAddr(lo), (hi - lo) / 4096, Perms::RW)
                    .is_err()
            {
                return self.heap_end;
            }
        }
        self.heap_end = addr;
        addr
    }

    /// `write`。fd の検査は len==0 の早期リターンより先（vfs_write と同順）。
    fn sys_write(&mut self, env: &mut BareEnv, fd: u32, buf: u64, len: u64) -> Result<u64, u32> {
        if !self.fd_open(fd) || (fd == 0 && self.std_fds[0].is_none()) {
            return Err(errno::EBADF);
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
        } else {
            self.file_read(fd, n)?
        };
        if !self.write_bytes(env, buf, &data) {
            return Err(errno::EFAULT);
        }
        Ok(data.len() as u64)
    }

    /// `readv`（iovec = {u32 base, u32 len} の配列）。
    fn sys_readv(&mut self, env: &mut BareEnv, fd: u32, iov: u64, cnt: u64) -> Result<u64, u32> {
        if !self.fd_open(fd) || ((fd == 1 || fd == 2) && self.std_fds[fd as usize].is_none()) {
            return Err(errno::EBADF);
        }
        let mut total = 0u64;
        for i in 0..cnt.min(1024) {
            let Some(ia) = iov.checked_add(i * 8) else {
                return if total > 0 {
                    Ok(total)
                } else {
                    Err(errno::EFAULT)
                };
            };
            let base = self.get32(env, ia).ok_or(errno::EFAULT)?;
            let len = self.get32(env, ia + 4).ok_or(errno::EFAULT)?;
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
            let Some(ia) = iov.checked_add(i * 8) else {
                return if total > 0 {
                    Ok(total)
                } else {
                    Err(errno::EFAULT)
                };
            };
            let base = self.get32(env, ia).ok_or(errno::EFAULT)?;
            let len = self.get32(env, ia + 4).ok_or(errno::EFAULT)?;
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

    /// `sendfile`/`sendfile64`（out, in, off*, count）。`wide` が真
    /// なら offset は loff_t*(u64)、偽なら off_t*(u32)。in は
    /// ファイル限定、off==NULL は in の現在位置から。
    fn sys_sendfile(
        &mut self,
        env: &mut BareEnv,
        out_fd: u32,
        in_fd: u32,
        off_addr: u64,
        count: u64,
        wide: bool,
    ) -> Result<u64, u32> {
        if !self.fd_open(out_fd) {
            return Err(errno::EBADF);
        }
        if self.file_of(in_fd).is_none() {
            return Err(errno::EBADF);
        }
        let mut pos = 0u64;
        let data = if off_addr != 0 {
            pos = if wide {
                self.get64(env, off_addr).ok_or(errno::EFAULT)?
            } else {
                self.get32(env, off_addr).ok_or(errno::EFAULT)?
            };
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
        if off_addr != 0 {
            let ok = if wide {
                self.put64(env, off_addr, pos + n)
            } else {
                self.put32(env, off_addr, (pos + n) as u32)
            };
            if !ok {
                return Err(errno::EFAULT);
            }
        }
        Ok(n)
    }

    /// `pread64`。hppa は 64 ビットの off が (hi, lo) の語対で届く
    /// （`parisc_pread64` — generic の lo, hi ではなく hi が先）。
    // Ref: SRC-LINUX (7.3) — parisc_pread64 (sys_parisc32.c)。
    fn sys_pread64(
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
        let f = self.file_of(fd).ok_or(errno::EBADF)?;
        let mut data = vec![0u8; usize::try_from(len).unwrap_or(1 << 20).min(1 << 20)];
        let n = polyisa_host::pread(f, &mut data, off).map_err(host_errno)?;
        data.truncate(n);
        if !self.write_bytes(env, buf, &data) {
            return Err(errno::EFAULT);
        }
        Ok(n as u64)
    }

    /// `pwrite64`。pread64 と同じ (hi, lo) の語対で fd の位置を動かさない。
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

    /// `lseek`。SEEK_SET/CUR/END = 0/1/2。off は i32 の符号拡張。
    fn sys_lseek(
        &mut self,
        _env: &mut BareEnv,
        fd: u32,
        off: i64,
        whence: u64,
    ) -> Result<u64, u32> {
        if whence == 0 && off < 0 {
            return Err(errno::EINVAL);
        }
        if whence == 0 && off == 0 {
            self.dir_scans.remove(&fd);
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

    /// `_llseek(fd, hi, lo, result*, whence)`。hppa32 では hi/lo が
    /// 別引数で届き、結果は 64 ビット値を `result` へ書く。
    fn sys_llseek(
        &mut self,
        env: &mut BareEnv,
        fd: u32,
        hi: u64,
        lo: u64,
        out: u64,
        whence: u64,
    ) -> Result<u64, u32> {
        let off = ((hi as i64) << 32) | lo as i64;
        if out == 0 {
            return Err(errno::EFAULT);
        }
        if fd < 3 && self.std_fds[fd as usize].is_none() {
            return Err(if self.std_closed[fd as usize] {
                errno::EBADF
            } else {
                errno::ESPIPE
            });
        }
        let w = match whence {
            0 => {
                if off < 0 {
                    return Err(errno::EINVAL);
                }
                self.dir_scans.remove(&fd);
                SeekFrom::Start(off as u64)
            }
            1 => SeekFrom::Current(off),
            2 => SeekFrom::End(off),
            _ => return Err(errno::EINVAL),
        };
        let f = self.file_of_mut(fd).ok_or(errno::EBADF)?;
        match f.seek(w) {
            Ok(p) => {
                if !self.put64(env, out, p) {
                    return Err(errno::EFAULT);
                }
                Ok(0)
            }
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
        if self.fds.get(fd).is_none() {
            return Err(errno::EBADF);
        }
        self.fds.clear(fd);
        self.fds.forget_path(fd);
        self.dir_scans.remove(&fd);
        Ok(0)
    }

    /// `open`/`openat` の共通部。hppa の O_* は独自ビット位置
    /// （CREAT=1<<8、EXCL=1<<10、LARGEFILE=1<<11、NOFOLLOW=1<<7、
    /// DIRECTORY=1<<12、NONBLOCK=1<<16、CLOEXEC=1<<21、PATH=1<<22。
    /// TRUNC=1<<9 と ACCMODE=3 は asm-generic）。
    // Ref: SRC-LINUX (7.3) — arch/parisc/include/uapi/asm/fcntl.h.
    fn sys_open(
        &mut self,
        env: &mut BareEnv,
        dirfd: i64,
        path_addr: u64,
        flags: u32,
        mode: u32,
    ) -> Result<u64, u32> {
        let path = self.read_cstr(env, path_addr)?;
        if path.is_empty() {
            return Err(errno::ENOENT);
        }
        let host = self.host_path_at(dirfd, &path)?;
        if flags as u64 & oflag::NOFOLLOW != 0
            && std::fs::symlink_metadata(&host)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
        {
            return Err(errno::ELOOP);
        }
        let existed = std::fs::symlink_metadata(&host).is_ok();
        let mut oo = std::fs::OpenOptions::new();
        let accmode = flags as u64 & oflag::ACCMODE;
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
    ) -> Result<u64, u32> {
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

    /// `fcntl`/`fcntl64`。複製（F_DUPFD=0、F_DUPFD_CLOEXEC=1030）
    /// だけ実装し、フラグ系は成功だけ返す。
    fn sys_fcntl(&mut self, _env: &mut BareEnv, fd: u32, cmd: u32, arg: u64) -> Result<u64, u32> {
        match cmd {
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
            1..=4 => Ok(0),
            _ => Err(errno::EINVAL),
        }
    }

    /// `ioctl`。hppa の ioctl 方向ビットは generic と逆（
    /// `_IOC_READ`=1/`_IOC_WRITE`=2、`uapi/asm/ioctl.h`）だが、
    /// エミュレータは端末を持たないので開いた fd には一律 ENOTTY。
    // Ref: SRC-LINUX (7.3) — arch/parisc/include/uapi/asm/ioctl.h.
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

    /// `stat`/`stat64`/`fstatat64`/`statx` の共通部。`at_empty` は
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

    /// `statx`（256B）。fstatat64 で使う形と同じ値を statx の形で置く。
    /// Ref: SRC-LINUX (7.3) — include/uapi/linux/stat.h.
    fn sys_statx(
        &mut self,
        env: &mut BareEnv,
        dirfd: i64,
        path_addr: u64,
        flags: u64,
        out: u64,
    ) -> Result<u64, u32> {
        let path = self.read_cstr(env, path_addr)?;
        let at_empty = flags & at::EMPTY_PATH != 0;
        let lstat = flags & at::SYMLINK_NOFOLLOW != 0;
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
        // statx: 0 u32 mask, 4 u32 blksize, 8 u64 attributes,
        // 16 u32 nlink, 20 u32 uid, 24 u32 gid, 28 u16 mode, 30 u16 spare,
        // 32 u64 ino, 40 u64 size, 48 u64 blocks, 56 u64 attrs_mask,
        // 64 atime {i64 sec,u32 nsec,u32 pad}, 80 btime, 96 ctime, 112 mtime,
        // 128 u32 rdev_major, 132 u32 rdev_minor,
        // 136 u32 dev_major, 140 u32 dev_minor, 144 u64 spare[14]
        let mut ok = true;
        ok &= self.put32(env, out, 0x0fff); // STATX_ALL 相当
        ok &= self.put32(env, out + 4, md.blksize as u32);
        ok &= self.put32(env, out + 16, md.nlink as u32);
        ok &= self.put32(env, out + 20, md.uid);
        ok &= self.put32(env, out + 24, md.gid);
        ok &= self.put16(env, out + 28, md.mode as u16);
        ok &= self.put64(env, out + 32, md.ino);
        ok &= self.put64(env, out + 40, md.size);
        ok &= self.put64(env, out + 48, md.blocks);
        ok &= self.put64(env, out + 64, md.atime as u64);
        ok &= self.put32(env, out + 72, md.atime_nsec as u32);
        ok &= self.put64(env, out + 96, md.ctime as u64);
        ok &= self.put32(env, out + 104, md.ctime_nsec as u32);
        ok &= self.put64(env, out + 112, md.mtime as u64);
        ok &= self.put32(env, out + 120, md.mtime_nsec as u32);
        if ok { Ok(0) } else { Err(errno::EFAULT) }
    }

    /// `struct stat`（hppa 固有の 104B。16/32 ビット混在で uid/gid
    /// が末尾側に置かれる独自レイアウト）または `struct stat64`
    /// （104B。arm/m68k 型の generic stat64 と同じ並び）を BE で書く。
    // Ref: SRC-LINUX (7.3) — arch/parisc/include/uapi/asm/stat.h。
    fn put_stat(&mut self, env: &mut BareEnv, a: u64, m: &polyisa_host::Stat, wide: bool) -> bool {
        let mut ok = true;
        if wide {
            // stat64: dev u64@0, pad@8, __st_ino@12(未使用), mode@16,
            // nlink@20, uid@24, gid@28, rdev u64@32, pad@40, size i64@48,
            // blksize i32@56, pad@60, blocks i64@64, atime@72, ansec@76,
            // mtime@80, mnsec@84, ctime@88, cnsec@92, ino u64@96
            ok &= self.put64(env, a, m.dev);
            ok &= self.put32(env, a + 12, m.ino as u32);
            ok &= self.put32(env, a + 16, m.mode);
            ok &= self.put32(env, a + 20, m.nlink as u32);
            ok &= self.put32(env, a + 24, m.uid);
            ok &= self.put32(env, a + 28, m.gid);
            ok &= self.put64(env, a + 32, m.rdev);
            ok &= self.put64(env, a + 48, m.size);
            ok &= self.put32(env, a + 56, m.blksize as u32);
            ok &= self.put64(env, a + 64, m.blocks);
            ok &= self.put32(env, a + 72, m.atime as u32);
            ok &= self.put32(env, a + 76, m.atime_nsec as u32);
            ok &= self.put32(env, a + 80, m.mtime as u32);
            ok &= self.put32(env, a + 84, m.mtime_nsec as u32);
            ok &= self.put32(env, a + 88, m.ctime as u32);
            ok &= self.put32(env, a + 92, m.ctime_nsec as u32);
            ok &= self.put64(env, a + 96, m.ino);
        } else {
            // stat: dev u32@0, ino u32@4, mode u16@8, nlink u16@10,
            // reserved1@12, reserved2@14, rdev u32@16, size i32@20,
            // atime@24, ansec@28, mtime@32, mnsec@36, ctime@40, cnsec@44,
            // blksize i32@48, blocks i32@52, unused1-4 u32@56..68,
            // unused5 u16@72, fstype i16@74, realdev u32@76,
            // basemode u16@80, spareshort u16@82, uid u32@84, gid u32@88,
            // spare4 u32[3]@92..104
            ok &= self.put32(env, a, m.dev as u32);
            ok &= self.put32(env, a + 4, m.ino as u32);
            ok &= self.put16(env, a + 8, m.mode as u16);
            ok &= self.put16(env, a + 10, m.nlink as u16);
            ok &= self.put32(env, a + 16, m.rdev as u32);
            ok &= self.put32(env, a + 20, m.size as u32);
            ok &= self.put32(env, a + 24, m.atime as u32);
            ok &= self.put32(env, a + 28, m.atime_nsec as u32);
            ok &= self.put32(env, a + 32, m.mtime as u32);
            ok &= self.put32(env, a + 36, m.mtime_nsec as u32);
            ok &= self.put32(env, a + 40, m.ctime as u32);
            ok &= self.put32(env, a + 44, m.ctime_nsec as u32);
            ok &= self.put32(env, a + 48, m.blksize as u32);
            ok &= self.put32(env, a + 52, m.blocks as u32);
            ok &= self.put32(env, a + 84, m.uid);
            ok &= self.put32(env, a + 88, m.gid);
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
    #[allow(clippy::too_many_arguments)]
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

    /// `access`/`faccessat`/`faccessat2`（mode: F_OK=0, X_OK=1, W_OK=2, R_OK=4）。
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
    /// u8 type, name\0、BE）を詰める。fd ごとに走査位置を覚え、
    /// 末尾に達したら 0 を返して呼び出し側のループを終わらせる。
    /// `.`/`..` は合成しない（GAP-0058 — alpha/m68k の
    /// heavy_program 系と同じ制限を持つ）。
    fn sys_getdents64(
        &mut self,
        env: &mut BareEnv,
        fd: u32,
        buf: u64,
        count: u64,
    ) -> Result<u64, u32> {
        if self.fds.get(fd).is_none() {
            return Err(errno::EBADF);
        }
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
            out.extend_from_slice(&ino.to_be_bytes());
            out.extend_from_slice(&(i as u64 + 1).to_be_bytes());
            out.extend_from_slice(&(reclen as u16).to_be_bytes());
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

    /// `mmap`/`mmap2`。`pgoff_bytes` が真なら最終引数をページ
    /// オフセット（mmap2）、偽ならバイトオフセット（mmap）として
    /// 解釈する。hppa の MAP_FIXED=0x04、MAP_ANONYMOUS=0x10 は
    /// asm-generic（0x10/0x20）と異なる独自値。
    // Ref: SRC-LINUX (7.3) — arch/parisc/include/uapi/asm/mman.h。
    fn sys_mmap(
        &mut self,
        env: &mut BareEnv,
        args: &[u64; 6],
        pgoff_bytes: bool,
    ) -> Result<u64, u32> {
        let (addr, len, prot, flags) = (args[0], args[1], args[2] as u32, args[3] as u32);
        let (fd, off) = (
            args[4] as u32 as i32 as i64,
            if pgoff_bytes { args[5] << 12 } else { args[5] },
        );
        if len == 0 || len > (1 << 30) {
            return Err(if len == 0 {
                errno::EINVAL
            } else {
                errno::ENOMEM
            });
        }
        if flags as u64 & u64::from(mman::MAP_FIXED) != 0 && addr & 0xfff != 0 {
            return Err(errno::EINVAL); // MAP_FIXED はページ整列必須
        }
        // mmap はバイトオフセットがページ整列必須（EINVAL）。
        if !pgoff_bytes && off & 0xfff != 0 {
            return Err(errno::EINVAL);
        }
        if flags as u64 & u64::from(mman::MAP_ANONYMOUS) == 0
            && (fd < 0 || self.file_of(fd as u32).is_none())
        {
            return Err(errno::EBADF);
        }
        let pages = len.div_ceil(4096);
        let base = if flags as u64 & u64::from(mman::MAP_FIXED) != 0 {
            addr & !0xfff
        } else {
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
        if flags as u64 & u64::from(mman::MAP_ANONYMOUS) == 0 {
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

    /// `mprotect`。範囲をページ境界に丸めて権限を変える。
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
        if addr & 0xfff != 0 {
            return Err(errno::EINVAL);
        }
        let pages = len.div_ceil(4096).min(1 << 20);
        if !self.write_bytes(env, vec, &vec![1u8; pages as usize]) {
            return Err(errno::EFAULT);
        }
        Ok(0)
    }

    /// `getrlimit`（struct rlimit = u32×2）。資源番号は hppa では
    /// asm-generic/resource.h の汎用順序（STACK=3、NOFILE=7、AS=9）。
    // Ref: SRC-LINUX (7.3) — include/uapi/asm-generic/resource.h.
    fn sys_getrlimit(&mut self, env: &mut BareEnv, addr: u64, r: u64) -> Result<u64, u32> {
        let (cur, max) = match r {
            res::STACK => (8 << 20, res::RLIM_INFINITY),
            res::NOFILE => (u64::from(Self::MAX_FD), u64::from(Self::MAX_FD)),
            _ => (res::RLIM_INFINITY, res::RLIM_INFINITY),
        };
        if !self.put32(env, addr, cur as u32) || !self.put32(env, addr + 4, max as u32) {
            return Err(errno::EFAULT);
        }
        Ok(0)
    }

    /// `prlimit64`（struct rlimit64 = u64×2）を old_limit へ書く。
    fn sys_prlimit64(&mut self, env: &mut BareEnv, addr: u64, r: u64) -> Result<u64, u32> {
        let (cur, max) = match r {
            res::STACK => (8 << 20, res::RLIM64_INFINITY),
            res::NOFILE => (u64::from(Self::MAX_FD), u64::from(Self::MAX_FD)),
            _ => (res::RLIM64_INFINITY, res::RLIM64_INFINITY),
        };
        if !self.put64(env, addr, cur) || !self.put64(env, addr + 8, max) {
            return Err(errno::EFAULT);
        }
        Ok(0)
    }

    /// timespec（i32 sec + i32 nsec、hppa32 の old_timespec32）を書く。
    fn put_timespec(
        &mut self,
        env: &mut BareEnv,
        addr: u64,
        sec: u64,
        nsec: u64,
    ) -> Result<u64, u32> {
        if !self.put32(env, addr, sec as u32) || !self.put32(env, addr + 4, nsec as u32) {
            return Err(errno::EFAULT);
        }
        Ok(0)
    }

    /// timespec64（i64 sec + i64 nsec）を書く。
    fn put_timespec64(
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

    /// `clock_gettime`。全クロック id を実時間に揃える。
    fn sys_clock_gettime(&mut self, env: &mut BareEnv, _clk: u64, tp: u64) -> Result<u64, u32> {
        if tp == 0 {
            return Err(errno::EFAULT);
        }
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        self.put_timespec(env, tp, d.as_secs(), u64::from(d.subsec_nanos()))
    }

    /// `clock_gettime64`。
    fn sys_clock_gettime64(&mut self, env: &mut BareEnv, _clk: u64, tp: u64) -> Result<u64, u32> {
        if tp == 0 {
            return Err(errno::EFAULT);
        }
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        self.put_timespec64(env, tp, d.as_secs(), u64::from(d.subsec_nanos()))
    }

    /// `gettimeofday`（tv = {u32 sec, u32 usec}。tz はゼロ埋めの
    /// struct timezone {i32,i32} を書く）。
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
        if !self.put32(env, tv, d.as_secs() as u32) || !self.put32(env, tv + 4, d.subsec_micros()) {
            return Err(errno::EFAULT);
        }
        Ok(0)
    }

    /// `getrandom`。決定的 xorshift で埋める（再現性のため）。
    fn sys_getrandom(&mut self, env: &mut BareEnv, buf: u64, len: u64) -> Result<u64, u32> {
        let n = usize::try_from(len).unwrap_or(1 << 20).min(1 << 20);
        let mut out = vec![0u8; n];
        let mut s = self.rand_state;
        for b in out.iter_mut() {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            *b = s as u8;
        }
        self.rand_state = s;
        if !self.write_bytes(env, buf, &out) {
            return Err(errno::EFAULT);
        }
        Ok(n as u64)
    }

    /// `uname`。machine は "parisc"。
    // Ref: SRC-LINUX (7.3) — struct new_utsname。
    fn sys_uname(&mut self, env: &mut BareEnv, addr: u64) -> Result<u64, u32> {
        const FIELDS: [&str; 6] = [
            "Linux",
            "polyisa",
            "7.3.0",
            "#1 polyisa",
            "parisc",
            "(none)",
        ];
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

    /// `sysinfo`（hppa32 の struct sysinfo: 4 バイト long = 64B。
    /// uptime@0、loads[3]@4、totalram@16、freeram@20、sharedram@24、
    /// bufferram@28、totalswap@32、freeswap@36、procs u16@40、pad@42、
    /// totalhigh@44、freehigh@48、mem_unit u32@52）。
    // Ref: SRC-LINUX (7.3) — include/uapi/linux/sysinfo.h.
    fn sys_sysinfo(&mut self, env: &mut BareEnv, addr: u64) -> Result<u64, u32> {
        let secs = self.mono().as_secs() as u32;
        let total = 512u32 << 20;
        let mut ok = true;
        ok &= self.put32(env, addr, secs); // uptime
        ok &= self.put32(env, addr + 4, 0); // loads[0]
        ok &= self.put32(env, addr + 8, 0);
        ok &= self.put32(env, addr + 12, 0);
        ok &= self.put32(env, addr + 16, total); // totalram
        ok &= self.put32(env, addr + 20, total); // freeram
        ok &= self.put32(env, addr + 24, 0);
        ok &= self.put32(env, addr + 28, 0);
        ok &= self.put32(env, addr + 32, 0);
        ok &= self.put32(env, addr + 36, 0);
        ok &= self.put16(env, addr + 40, 1); // procs
        ok &= self.put16(env, addr + 42, 0);
        ok &= self.put32(env, addr + 44, 0);
        ok &= self.put32(env, addr + 48, 0);
        ok &= self.put32(env, addr + 52, 1); // mem_unit
        if ok { Ok(0) } else { Err(errno::EFAULT) }
    }

    /// `times`（tms: long×4 = 16 バイト。戻り値はクロック）。
    fn sys_times(&mut self, env: &mut BareEnv, addr: u64) -> Result<u64, u32> {
        let us = self.mono_us();
        let ticks = us / 10_000; // USER_HZ=100 換算
        if addr != 0 {
            let mut img = [0u8; 16];
            img[..4].copy_from_slice(&(ticks as u32).to_be_bytes());
            if !self.write_bytes(env, addr, &img) {
                return Err(errno::EFAULT);
            }
        }
        Ok(ticks)
    }

    /// `statfs`（64B）/`statfs64`（88B）/`fstatfs`/`fstatfs64` の共通部。
    /// hppa32 は asm-generic/statfs.h — statfs は u32 の列+fsid(8B)+
    /// namelen+frsize+flags+spare[4]、statfs64 は u64 フィールド型。
    /// `sz` は statfs64 のバッファ宣言サイズ（statfs は構造体の
    /// 固定サイズ）— 書き込みはそれを越えない。
    // Ref: SRC-LINUX (7.3) — include/uapi/asm-generic/statfs.h.
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
        } else if self.fds.get(target as u32).is_none() {
            return Err(errno::EBADF);
        }
        let mut ok = true;
        if wide {
            // statfs64: u32 type, u32 bsize, u64 blocks..ffree,
            // fsid(8B), u32 namelen, u32 frsize, u32 flags, u32 spare[4]。
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
            // statfs: u32 の列 + fsid(8B) + namelen + frsize + flags + spare[4]。
            let fields = [0xEF53u32, 4096, 1 << 22, 1 << 21, 1 << 21, 1 << 20, 1 << 19];
            for (i, v) in fields.iter().enumerate() {
                ok &= self.put32(env, addr + (i * 4) as u64, *v);
            }
            ok &= self.put64(env, addr + 28, 0); // fsid
            ok &= self.put32(env, addr + 36, 255);
            ok &= self.put32(env, addr + 40, 4096);
        }
        let _ = sz;
        if ok { Ok(0) } else { Err(errno::EFAULT) }
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

    /// `chdir`。ゲストの絶対パスとして cwd を更新する。
    fn sys_chdir(&mut self, env: &mut BareEnv, path_addr: u64) -> Result<u64, u32> {
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

    /// `utimensat`/`futimesat`/`utimes`/`utimensat_time64`。
    /// times==NULL は現在時刻。futimesat で path が空なら dirfd
    /// 自体のファイルを対象にする（futimens 相当）。
    /// `timeval` は {i32 sec, i32 usec}、`ts64` は {i64 sec, i64 nsec}、
    /// それ以外は {i32 sec, i32 nsec}。
    // Ref: SRC-LINUX (7.3) — utimensat(2)。
    fn sys_utimens(
        &mut self,
        env: &mut BareEnv,
        dirfd: i64,
        path_addr: u64,
        times_addr: u64,
        timeval: bool,
        ts64: bool,
    ) -> Result<u64, u32> {
        const UTIME_NOW: u64 = (1 << 30) - 1;
        const UTIME_OMIT: u64 = (1 << 30) - 2;
        let now = std::time::SystemTime::now();
        let (mut atime, mut mtime) = (Some(now), Some(now));
        if times_addr != 0 {
            let mut read_ts = |a: u64| -> Result<Option<std::time::SystemTime>, u32> {
                let (sec, sub) = if ts64 {
                    (
                        self.get64(env, a).ok_or(errno::EFAULT)? as i64,
                        self.get64(env, a + 8).ok_or(errno::EFAULT)?,
                    )
                } else {
                    (
                        self.get32(env, a).ok_or(errno::EFAULT)? as u32 as i32 as i64,
                        self.get32(env, a + 4).ok_or(errno::EFAULT)?,
                    )
                };
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
            let stride = if ts64 { 16 } else { 8 };
            atime = read_ts(times_addr)?;
            mtime = read_ts(times_addr + stride)?;
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

    /// `utime`。utimbuf = {i32 actime, i32 modtime}（8B）。
    fn sys_utime(
        &mut self,
        env: &mut BareEnv,
        path_addr: u64,
        times_addr: u64,
    ) -> Result<u64, u32> {
        let path = self.read_cstr(env, path_addr)?;
        let host = self.host_path(&path);
        let ft = if times_addr == 0 {
            let now = std::time::SystemTime::now();
            std::fs::FileTimes::new()
                .set_accessed(now)
                .set_modified(now)
        } else {
            let a = self.get32(env, times_addr).ok_or(errno::EFAULT)? as u32 as i32;
            let m = self.get32(env, times_addr + 4).ok_or(errno::EFAULT)? as u32 as i32;
            let at = std::time::UNIX_EPOCH + std::time::Duration::new(a.max(0) as u64, 0);
            let mt = std::time::UNIX_EPOCH + std::time::Duration::new(m.max(0) as u64, 0);
            std::fs::FileTimes::new().set_accessed(at).set_modified(mt)
        };
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&host)
            .map_err(host_errno)?;
        f.set_times(ft).map(|_| 0).map_err(host_errno)
    }

    /// `nanosleep`/`clock_nanosleep`/`clock_nanosleep_time64`。
    /// req を読んで EFAULT/EINVAL を返せるようにし、実時間は眠らず
    /// rem を 0 にする（速度優先）。
    fn sys_nanosleep(
        &mut self,
        env: &mut BareEnv,
        req: u64,
        rem: u64,
        ts64: bool,
    ) -> Result<u64, u32> {
        let (sec, nsec) = if ts64 {
            (
                self.get64(env, req).ok_or(errno::EFAULT)?,
                self.get64(env, req + 8).ok_or(errno::EFAULT)?,
            )
        } else {
            (
                self.get32(env, req).ok_or(errno::EFAULT)?,
                self.get32(env, req + 4).ok_or(errno::EFAULT)?,
            )
        };
        let _ = sec;
        if nsec >= 1_000_000_000 {
            return Err(errno::EINVAL);
        }
        if rem != 0 {
            let ok = if ts64 {
                self.put64(env, rem, 0) && self.put64(env, rem + 8, 0)
            } else {
                self.put32(env, rem, 0) && self.put32(env, rem + 4, 0)
            };
            if !ok {
                return Err(errno::EFAULT);
            }
        }
        Ok(0)
    }

    /// `rt_sigaction`。hppa32 の compat_sigaction は
    /// {handler u32, flags u32, restorer u32, mask u64} = 20B。
    /// oldact に SIG_DFL 相当を書く。
    fn sys_rt_sigaction(
        &mut self,
        env: &mut BareEnv,
        _act: u64,
        oldact: u64,
        sz: u64,
    ) -> Result<u64, u32> {
        if sz != 8 {
            return Err(errno::EINVAL);
        }
        if oldact != 0 && !self.write_bytes(env, oldact, &[0u8; 20]) {
            return Err(errno::EFAULT);
        }
        Ok(0)
    }

    /// `rt_sigprocmask`（SIG_BLOCK=0/UNBLOCK=1/SETMASK=2。
    /// sigset_t は 8B 固定）。
    fn sys_rt_sigprocmask(
        &mut self,
        env: &mut BareEnv,
        how: u64,
        set: u64,
        old: u64,
        sz: u64,
    ) -> Result<u64, u32> {
        if sz != 8 {
            return Err(errno::EINVAL);
        }
        if old != 0 && !self.put64(env, old, self.sig_mask) {
            return Err(errno::EFAULT);
        }
        if set != 0 {
            let v = self.get64(env, set).ok_or(errno::EFAULT)?;
            self.sig_mask = match how {
                0 => self.sig_mask | v,
                1 => self.sig_mask & !v,
                2 => v,
                _ => return Err(errno::EINVAL),
            };
        }
        Ok(0)
    }

    /// `sigprocmask`（旧型。old_sigset_t = u32）。
    fn sys_sigprocmask(
        &mut self,
        env: &mut BareEnv,
        how: u64,
        set: u64,
        old: u64,
    ) -> Result<u64, u32> {
        if old != 0 && !self.put32(env, old, self.sig_mask as u32) {
            return Err(errno::EFAULT);
        }
        if set != 0 {
            let v = self.get32(env, set).ok_or(errno::EFAULT)?;
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
    fn sys_getcpu(&mut self, env: &mut BareEnv, cpu: u64, node: u64) -> Result<u64, u32> {
        if cpu != 0 && !self.put32(env, cpu, 0) {
            return Err(errno::EFAULT);
        }
        if node != 0 && !self.put32(env, node, 0) {
            return Err(errno::EFAULT);
        }
        Ok(0)
    }

    /// `poll`/`ppoll`/`ppoll_time64` のスタブ。revents を 0 にして
    /// タイムアウト相当（0）を返す。pollfd = {fd i32, events i16,
    /// revents i16}（8B）。
    fn sys_poll(&mut self, env: &mut BareEnv, fds: u64, nfds: u64) -> Result<u64, u32> {
        for i in 0..nfds.min(1024) {
            let a = fds.wrapping_add(i * 8);
            if !self.write_bytes(env, a + 6, &[0, 0]) {
                return Err(errno::EFAULT);
            }
        }
        Ok(0)
    }

    /// `_newselect`/`pselect6`/`pselect6_time64` のスタブ。
    /// hppa32 の fd_set は u32 語の配列 — n ビットぶん全 0 クリア
    /// してタイムアウト相当（0）を返す。
    fn sys_select(&mut self, env: &mut BareEnv, args: &[u64; 6]) -> Result<u64, u32> {
        let n = args[0];
        let bytes = n.min(1024).div_ceil(32) * 4;
        for &a in args.iter().take(4).skip(1) {
            if a != 0 {
                let z = vec![0u8; bytes as usize];
                if !self.write_bytes(env, a, &z) {
                    return Err(errno::EFAULT);
                }
            }
        }
        Ok(0)
    }

    /// 通常 syscall（code=0x100）のディスパッチ。
    // Ref: SRC-LINUX (7.3) — syscall 規約（r20=nr, r26..r21=args, r28=ret）。
    fn dispatch(&mut self, env: &mut BareEnv, n: u64, args: &[u64; 6]) -> Disp {
        match n {
            nr::EXIT | nr::EXIT_GROUP => Disp::Exit((args[0] & 0xff) as u32),
            nr::READ => res(self.sys_read(env, args[0] as u32, args[1], args[2])),
            nr::WRITE => res(self.sys_write(env, args[0] as u32, args[1], args[2])),
            nr::READV => res(self.sys_readv(env, args[0] as u32, args[1], args[2])),
            nr::WRITEV => res(self.sys_writev(env, args[0] as u32, args[1], args[2])),
            // hppa は 64 ビット引数が (hi, lo) の語対（generic の
            // lo, hi ではない）。pread64(fd, buf, count, hi, lo)。
            nr::PREAD64 => res(self.sys_pread64(
                env,
                args[0] as u32,
                args[1],
                args[2],
                (args[3] << 32) | args[4],
            )),
            nr::PWRITE64 => res(self.sys_pwrite64(
                env,
                args[0] as u32,
                args[1],
                args[2],
                (args[3] << 32) | args[4],
            )),
            nr::LSEEK => res(self.sys_lseek(
                env,
                args[0] as u32,
                args[1] as u32 as i32 as i64,
                args[2],
            )),
            nr::_LLSEEK => res(self.sys_llseek(
                env,
                args[0] as u32,
                args[1],
                args[2],
                args[3],
                args[4],
            )),
            nr::SENDFILE => res(self.sys_sendfile(
                env,
                args[0] as u32,
                args[1] as u32,
                args[2],
                args[3],
                false,
            )),
            nr::SENDFILE64 => res(self.sys_sendfile(
                env,
                args[0] as u32,
                args[1] as u32,
                args[2],
                args[3],
                true,
            )),
            nr::CLOSE => res(self.sys_close(env, args[0] as u32)),
            nr::OPEN => res(self.sys_open(env, AT_FDCWD, args[0], args[1] as u32, args[2] as u32)),
            nr::CREAT => res(self.sys_open(
                env,
                AT_FDCWD,
                args[0],
                (oflag::CREAT | oflag::TRUNC | 1) as u32, // O_WRONLY|O_CREAT|O_TRUNC
                args[1] as u32,
            )),
            nr::OPENAT => res(self.sys_open(
                env,
                args[0] as u32 as i32 as i64,
                args[1],
                args[2] as u32,
                args[3] as u32,
            )),
            nr::MKDIR | nr::MKDIRAT => {
                let (d, p, mode) = if n == nr::MKDIR {
                    (AT_FDCWD, args[0], args[1] as u32)
                } else {
                    (args[0] as u32 as i32 as i64, args[1], args[2] as u32)
                };
                let perm = mode & !self.umask;
                res(self.sys_path_op(env, d, p, |p| {
                    std::fs::create_dir(p).and_then(|_| polyisa_host::chmod(p, perm))
                }))
            }
            nr::RMDIR => res(self.sys_path_op(env, AT_FDCWD, args[0], |p| {
                std::fs::remove_dir(p)
            })),
            nr::UNLINK => res(self.sys_path_op(env, AT_FDCWD, args[0], |p| {
                std::fs::remove_file(p)
            })),
            nr::UNLINKAT => {
                let dir = args[2] & at::REMOVEDIR != 0;
                res(self.sys_path_op(env, args[0] as u32 as i32 as i64, args[1], |p| {
                    if dir {
                        std::fs::remove_dir(p)
                    } else {
                        std::fs::remove_file(p)
                    }
                }))
            }
            nr::RENAME => res(self.sys_path_op2(env, AT_FDCWD, args[0], AT_FDCWD, args[1], |a, b| {
                std::fs::rename(a, b)
            })),
            nr::RENAMEAT => res(self.sys_path_op2(
                env,
                args[0] as u32 as i32 as i64,
                args[1],
                args[2] as u32 as i32 as i64,
                args[3],
                |a, b| std::fs::rename(a, b),
            )),
            nr::LINK => res(self.sys_path_op2(env, AT_FDCWD, args[0], AT_FDCWD, args[1], |a, b| {
                std::fs::hard_link(a, b)
            })),
            nr::LINKAT => res(self.sys_path_op2(
                env,
                args[0] as u32 as i32 as i64,
                args[1],
                args[2] as u32 as i32 as i64,
                args[3],
                |a, b| std::fs::hard_link(a, b),
            )),
            nr::SYMLINK | nr::SYMLINKAT => {
                let (dirfd, old_p, new_p) = if n == nr::SYMLINK {
                    (AT_FDCWD, args[0], args[1])
                } else {
                    (args[1] as u32 as i32 as i64, args[0], args[2])
                };
                let target = self.read_cstr(env, old_p);
                let link = self.read_cstr(env, new_p);
                match (target, link) {
                    (Ok(t), Ok(l)) => match self.host_path_at(dirfd, &l) {
                        Ok(lh) => res(polyisa_host::symlink(&String::from_utf8_lossy(&t), &lh)
                            .map(|_| 0u64)
                            .map_err(host_errno)),
                        Err(e) => bad(e),
                    },
                    (Err(e), _) | (_, Err(e)) => bad(e),
                }
            }
            nr::CHMOD => res(self.sys_chmod(env, AT_FDCWD, args[0], args[1] as u32)),
            nr::FCHMODAT => res(self.sys_chmod(
                env,
                args[0] as u32 as i32 as i64,
                args[1],
                args[2] as u32,
            )),
            nr::FCHMOD => {
                let path = self.fds.path_of(args[0] as u32).map(str::to_string);
                match path {
                    Some(p) => res(polyisa_host::chmod(&p, args[1] as u32)
                        .map(|_| 0u64)
                        .map_err(host_errno)),
                    None => bad(errno::EBADF),
                }
            }
            nr::CHOWN | nr::LCHOWN | nr::FCHOWNAT | nr::FCHOWN => ok(0),
            nr::TRUNCATE => {
                let len = args[1] as u32 as i32 as i64;
                res(self.sys_path_op(env, AT_FDCWD, args[0], |p| {
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(p)
                        .and_then(|f| f.set_len(len.max(0) as u64))
                }))
            }
            nr::TRUNCATE64 => {
                let len = ((args[1] as i64) << 32) | args[2] as i64;
                res(self.sys_path_op(env, AT_FDCWD, args[0], |p| {
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(p)
                        .and_then(|f| f.set_len(len.max(0) as u64))
                }))
            }
            nr::FTRUNCATE => {
                let len = args[1] as u32 as i32 as i64;
                match self.file_of(args[0] as u32) {
                    Some(f) => res(f.set_len(len.max(0) as u64).map(|_| 0u64).map_err(host_errno)),
                    None => bad(errno::EBADF),
                }
            }
            nr::FTRUNCATE64 => {
                let len = ((args[1] as i64) << 32) | args[2] as i64;
                match self.file_of(args[0] as u32) {
                    Some(f) => res(f.set_len(len.max(0) as u64).map(|_| 0u64).map_err(host_errno)),
                    None => bad(errno::EBADF),
                }
            }
            nr::MKNOD | nr::MKNODAT => {
                let mode = args[if n == nr::MKNOD { 1 } else { 2 }] as u32;
                if mode & 0o170000 != 0 && mode & 0o170000 != 0o100000 {
                    bad(errno::EPERM)
                } else {
                    let (d, p) = if n == nr::MKNOD {
                        (AT_FDCWD, args[0])
                    } else {
                        (args[0] as u32 as i32 as i64, args[1])
                    };
                    let perm = (mode & 0o7777) & !self.umask;
                    res(self.sys_path_op(env, d, p, |p| {
                        std::fs::File::create(p).and_then(|_| polyisa_host::chmod(p, perm))
                    }))
                }
            }
            nr::DUP => res(self.sys_dup(env, args[0] as u32, None, false)),
            nr::DUP2 => res(self.sys_dup(env, args[0] as u32, Some(args[1] as u32), false)),
            nr::DUP3 => {
                if args[2] != 0 && args[2] & !(oflag::CLOEXEC) != 0 {
                    bad(errno::EINVAL)
                } else {
                    res(self.sys_dup(env, args[0] as u32, Some(args[1] as u32), true))
                }
            }
            nr::FCNTL | nr::FCNTL64 => {
                res(self.sys_fcntl(env, args[0] as u32, args[1] as u32, args[2]))
            }
            nr::IOCTL => res(self.sys_ioctl(env, args[0] as u32, args[1], args[2])),
            nr::BRK => ok(self.sys_brk(env, args[0])),
            nr::MMAP => res(self.sys_mmap(env, args, false)),
            nr::MMAP2 => res(self.sys_mmap(env, args, true)),
            nr::MUNMAP => res(self.sys_munmap(env, args[0], args[1])),
            nr::MPROTECT => res(self.sys_mprotect(env, args[0], args[1], args[2] as u32)),
            nr::MINCORE => res(self.sys_mincore(env, args[0], args[1], args[2])),
            nr::MREMAP => bad(errno::ENOMEM), // 移動は非対応（ENOMEM で退避）
            nr::STAT => res(self.sys_stat(env, AT_FDCWD, args[0], args[1], false, false, false)),
            nr::LSTAT => res(self.sys_stat(env, AT_FDCWD, args[0], args[1], true, false, false)),
            nr::FSTAT => res(self.sys_fstat(env, args[0] as u32, args[1], false)),
            nr::STAT64 => res(self.sys_stat(env, AT_FDCWD, args[0], args[1], false, true, false)),
            nr::LSTAT64 => res(self.sys_stat(env, AT_FDCWD, args[0], args[1], true, true, false)),
            nr::FSTAT64 => res(self.sys_fstat(env, args[0] as u32, args[1], true)),
            // AT_SYMLINK_NOFOLLOW=0x100、AT_EMPTY_PATH=0x1000。
            nr::FSTATAT64 => res(self.sys_stat(
                env,
                args[0] as u32 as i32 as i64,
                args[1],
                args[2],
                args[3] & at::SYMLINK_NOFOLLOW != 0,
                true,
                args[3] & at::EMPTY_PATH != 0,
            )),
            nr::STATX => res(self.sys_statx(
                env,
                args[0] as u32 as i32 as i64,
                args[1],
                args[2],
                args[4],
            )),
            nr::ACCESS => res(self.sys_access(env, AT_FDCWD, args[0], args[1])),
            nr::FACCESSAT | nr::FACCESSAT2 => res(self.sys_access(
                env,
                args[0] as u32 as i32 as i64,
                args[1],
                args[2],
            )),
            nr::READLINK => res(self.sys_readlink(env, AT_FDCWD, args[0], args[1], args[2])),
            nr::READLINKAT => res(self.sys_readlink(
                env,
                args[0] as u32 as i32 as i64,
                args[1],
                args[2],
                args[3],
            )),
            nr::GETDENTS64 => res(self.sys_getdents64(env, args[0] as u32, args[1], args[2])),
            nr::GETCWD => res(self.sys_getcwd(env, args[0], args[1])),
            nr::CHDIR => res(self.sys_chdir(env, args[0])),
            nr::FCHDIR => {
                match self.fds.path_of(args[0] as u32).map(str::to_string) {
                    Some(p) => match polyisa_host::stat(&p) {
                        Ok(m) if m.mode & 0o170000 == 0o040000 => {
                            self.cwd = p;
                            ok(0)
                        }
                        Ok(_) => bad(errno::ENOTDIR),
                        Err(e) => bad(host_errno(e)),
                    },
                    None => bad(errno::EBADF),
                }
            }
            nr::STATFS => res(self.sys_statfs(env, args[1], false, args[0], true, 64)),
            nr::FSTATFS => res(self.sys_statfs(env, args[1], false, args[0], false, 64)),
            nr::STATFS64 => res(self.sys_statfs(env, args[2], true, args[0], true, args[1])),
            nr::FSTATFS64 => res(self.sys_statfs(env, args[2], true, args[0], false, args[1])),
            nr::GETRLIMIT => res(self.sys_getrlimit(env, args[1], args[0])),
            nr::SETRLIMIT => ok(0),
            nr::PRLIMIT64 => {
                if args[3] != 0 {
                    res(self.sys_prlimit64(env, args[3], args[1]))
                } else {
                    ok(0)
                }
            }
            nr::GETRUSAGE => {
                // rusage = timeval{u32×2}×2 + long u32×14 = 72B。
                if self.write_bytes(env, args[1], &[0u8; 72]) {
                    ok(0)
                } else {
                    bad(errno::EFAULT)
                }
            }
            nr::GETITIMER => {
                // itimerval = {interval,value}×{sec,usec u32} = 16B。
                if self.write_bytes(env, args[1], &[0u8; 16]) {
                    ok(0)
                } else {
                    bad(errno::EFAULT)
                }
            }
            nr::SETITIMER => ok(0),
            nr::UNAME => res(self.sys_uname(env, args[0])),
            nr::SYSINFO => res(self.sys_sysinfo(env, args[0])),
            nr::TIMES => res(self.sys_times(env, args[0])),
            nr::TIME => {
                let secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if args[0] != 0 && !self.put32(env, args[0], secs as u32) {
                    return bad(errno::EFAULT);
                }
                ok(secs)
            }
            nr::GETTIMEOFDAY => res(self.sys_gettimeofday(env, args[0], args[1])),
            nr::CLOCK_GETTIME => res(self.sys_clock_gettime(env, args[0], args[1])),
            nr::CLOCK_GETTIME64 => res(self.sys_clock_gettime64(env, args[0], args[1])),
            nr::CLOCK_GETRES => res(self.put_timespec(env, args[1], 0, 1)),
            nr::CLOCK_GETRES_TIME64 => res(self.put_timespec64(env, args[1], 0, 1)),
            nr::NANOSLEEP => res(self.sys_nanosleep(env, args[0], args[1], false)),
            nr::CLOCK_NANOSLEEP => res(self.sys_nanosleep(env, args[2], args[3], false)),
            nr::CLOCK_NANOSLEEP_TIME64 => res(self.sys_nanosleep(env, args[2], args[3], true)),
            nr::GETRANDOM => res(self.sys_getrandom(env, args[0], args[1])),
            nr::GETTID | nr::SET_TID_ADDRESS => ok(self.pid()),
            nr::GETPID => ok(self.pid()),
            nr::GETPPID => ok(1),
            nr::GETUID | nr::GETEUID | nr::GETGID | nr::GETEGID => ok(0),
            nr::GETRESUID | nr::GETRESGID => {
                for &a in args.iter().take(3) {
                    if a != 0 && !self.put32(env, a, 0) {
                        return bad(errno::EFAULT);
                    }
                }
                ok(0)
            }
            nr::GETPGRP | nr::GETPGID | nr::GETSID => ok(self.pid()),
            nr::GETGROUPS => ok(0),
            nr::SETPGID
            | nr::SETGID
            | nr::SETUID
            | nr::SETREUID
            | nr::SETREGID
            | nr::SETRESUID
            | nr::SETRESGID
            | nr::SETFSUID
            | nr::SETFSGID
            | nr::SETGROUPS
            | nr::SETSID
            | nr::CAPSET => ok(0),
            nr::CAPGET => {
                // cap_user_data（{u32×3}×2 = 24B）をゼロ埋め。
                if args[1] != 0 && !self.write_bytes(env, args[1], &[0u8; 24]) {
                    return bad(errno::EFAULT);
                }
                ok(0)
            }
            nr::UTIMES => res(self.sys_utimens(env, AT_FDCWD, args[0], args[1], true, false)),
            nr::FUTIMESAT => res(self.sys_utimens(
                env,
                args[0] as u32 as i32 as i64,
                args[1],
                args[2],
                true,
                false,
            )),
            nr::UTIMENSAT => res(self.sys_utimens(
                env,
                args[0] as u32 as i32 as i64,
                args[1],
                args[2],
                false,
                false,
            )),
            nr::UTIMENSAT_TIME64 => res(self.sys_utimens(
                env,
                args[0] as u32 as i32 as i64,
                args[1],
                args[2],
                false,
                true,
            )),
            nr::UTIME => res(self.sys_utime(env, args[0], args[1])),
            nr::GETCPU => res(self.sys_getcpu(env, args[0], args[1])),
            nr::RT_SIGACTION => res(self.sys_rt_sigaction(env, args[1], args[2], args[3])),
            nr::RT_SIGPROCMASK => res(self.sys_rt_sigprocmask(
                env, args[0], args[1], args[2], args[3],
            )),
            nr::SIGPROCMASK => res(self.sys_sigprocmask(env, args[0], args[1], args[2])),
            nr::RT_SIGPENDING => {
                if args[1] != 8 {
                    bad(errno::EINVAL)
                } else if self.put64(env, args[0], self.sig_mask) {
                    ok(0)
                } else {
                    bad(errno::EFAULT)
                }
            }
            nr::SIGPENDING => {
                if self.put32(env, args[0], self.sig_mask as u32) {
                    ok(0)
                } else {
                    bad(errno::EFAULT)
                }
            }
            nr::SGETMASK => ok(self.sig_mask),
            nr::SSETMASK => {
                let old = self.sig_mask;
                self.sig_mask = args[0] & 0xffff_ffff;
                ok(old)
            }
            nr::SIGNAL => ok(0), // 旧ハンドラ=SIG_DFL
            nr::SIGALTSTACK => {
                // ss 指定時はポインタの読み取り可能性を検査する。
                if args[0] != 0 && self.get32(env, args[0]).is_none() {
                    return bad(errno::EFAULT);
                }
                // old stack_t = {sp u32, flags i32, size u32} = 12B。
                if args[1] != 0
                    && (!self.put32(env, args[1], 0)
                        || !self.put32(env, args[1] + 4, 2)
                        || !self.put32(env, args[1] + 8, 0))
                {
                    return bad(errno::EFAULT);
                }
                ok(0)
            }
            nr::RT_SIGSUSPEND | nr::PAUSE => bad(errno::EINTR),
            nr::RT_SIGTIMEDWAIT | nr::RT_SIGQUEUEINFO | nr::RT_TGSIGQUEUEINFO => ok(0),
            nr::KILL => {
                if args[0] as i64 == self.pid() as i64 || args[0] == 0 {
                    ok(0)
                } else {
                    bad(errno::ESRCH)
                }
            }
            nr::TKILL => {
                if args[0] == self.pid() {
                    ok(0)
                } else {
                    bad(errno::ESRCH)
                }
            }
            nr::TGKILL => {
                if args[0] == self.pid() && args[1] == self.pid() {
                    ok(0)
                } else {
                    bad(errno::ESRCH)
                }
            }
            nr::SCHED_YIELD => ok(0),
            // SCHED_OTHER=0, FIFO=1, RR=2, BATCH=3, IDLE=5, DEADLINE=6。
            nr::SCHED_GET_PRIORITY_MAX | nr::SCHED_GET_PRIORITY_MIN => {
                let (mx, mn) = match args[0] {
                    1 | 2 => (99, 1),
                    0 | 3 | 5 | 6 => (0, 0),
                    _ => return bad(errno::EINVAL),
                };
                ok(if n == nr::SCHED_GET_PRIORITY_MAX { mx } else { mn })
            }
            nr::SCHED_GETPARAM => {
                if !self.put32(env, args[1], 0) {
                    return bad(errno::EFAULT);
                }
                ok(0)
            }
            nr::SCHED_SETPARAM | nr::SCHED_SETSCHEDULER => ok(0),
            nr::SCHED_GETSCHEDULER => ok(0), // SCHED_OTHER
            nr::SCHED_RR_GET_INTERVAL => res(self.put_timespec(env, args[1], 0, 0)),
            nr::SCHED_RR_GET_INTERVAL_TIME64 => res(self.put_timespec64(env, args[1], 0, 0)),
            nr::SCHED_SETAFFINITY => ok(0),
            nr::SCHED_GETAFFINITY => {
                // cpu0 だけ立った mask を cpusetsize バイト書く。
                let size = args[1] as usize;
                let mask = args[2];
                if mask == 0 || size == 0 {
                    bad(errno::EINVAL)
                } else {
                    let mut m = vec![0u8; size.min(1024)];
                    m[0] = 1;
                    if self.write_bytes(env, mask, &m) {
                        ok(0)
                    } else {
                        bad(errno::EFAULT)
                    }
                }
            }
            nr::SET_ROBUST_LIST | nr::GET_ROBUST_LIST => ok(0),
            nr::MADVISE
            | nr::READAHEAD
            | nr::FADVISE64_64
            | nr::MLOCK
            | nr::MUNLOCK
            | nr::MLOCKALL
            | nr::MUNLOCKALL
            | nr::MLOCK2
            | nr::SYNC
            | nr::SYNCFS
            | nr::SYNC_FILE_RANGE
            | nr::FALLOCATE
            | nr::FLOCK
            | nr::MSYNC
            | nr::FUTEX
            | nr::FUTEX_TIME64
            | nr::IOPRIO_SET
            | nr::IOPRIO_GET
            | nr::NICE
            | nr::SETPRIORITY
            | nr::ALARM
            | nr::CACHEFLUSH
            | nr::PERSONALITY => ok(0),
            nr::GETPRIORITY => ok(20), // nice 0 = 20（Linux 値域 0–39）
            nr::FSYNC | nr::FDATASYNC => {
                let fd = args[0] as u32;
                match self.file_of(fd) {
                    Some(f) => match f.sync_all() {
                        Ok(()) => ok(0),
                        Err(e) => bad(host_errno(e)),
                    },
                    None if fd < 3 && !self.std_closed[fd as usize] => ok(0),
                    None => bad(errno::EBADF),
                }
            }
            nr::UMASK => {
                let old = self.umask;
                self.umask = (args[0] as u32) & 0o777;
                ok(u64::from(old))
            }
            nr::PRCTL => {
                match args[0] {
                    // PR_SET_NAME=15: comm を 16B 読み取る。
                    15 => match self.read_bytes(env, args[1], 16) {
                        Some(b) => {
                            self.proc_name.copy_from_slice(&b[..16]);
                            ok(0)
                        }
                        None => bad(errno::EFAULT),
                    },
                    // PR_GET_NAME=16: comm を buf へ 16B 書く。
                    16 => {
                        let name = self.proc_name;
                        if self.write_bytes(env, args[1], &name) {
                            ok(0)
                        } else {
                            bad(errno::EFAULT)
                        }
                    }
                    _ => ok(0),
                }
            }
            nr::POLL | nr::PPOLL | nr::PPOLL_TIME64 => {
                res(self.sys_poll(env, args[0], args[1]))
            }
            nr::_NEWSELECT | nr::PSELECT6 | nr::PSELECT6_TIME64 => {
                res(self.sys_select(env, args))
            }
            // xattr: set/remove 系は成功扱い、get/list 系は
            // ENOTSUP（hppa では ENOTSUP=EOPNOTSUPP=223）。
            nr::SETXATTR | nr::LSETXATTR | nr::FSETXATTR | nr::REMOVEXATTR
            | nr::LREMOVEXATTR | nr::FREMOVEXATTR => ok(0),
            nr::GETXATTR | nr::LGETXATTR | nr::FGETXATTR | nr::LISTXATTR | nr::LLISTXATTR
            | nr::FLISTXATTR => bad(errno::EOPNOTSUPP),
            // 単一プロセス/単一スレッドモデルのためプロセス生成・
            // exec・wait 系は未対応（GAP-0058）。ptrace も同じ扱い。
            nr::FORK
            | nr::VFORK
            | nr::CLONE
            | nr::CLONE3
            | nr::EXECVE
            | nr::EXECVEAT
            | nr::WAITPID
            | nr::WAIT4
            | nr::WAITID
            | nr::PTRACE
            | nr::RT_SIGRETURN
            | nr::RESTART_SYSCALL
            // pipe 系・socket/IPC 系・eventfd/epoll 系など単一
            // プロセスモデルでは実装できないもの。
            | nr::PIPE
            | nr::PIPE2
            | nr::EPOLL_CREATE => Disp::Unimpl,
            // 旧型 getdents。正規は getdents64。
            nr::GETDENTS => Disp::Unimpl,
            nr::RSEQ => Disp::Unimpl, // glibc は ENOSYS でフォールバック
            nr::ACCT
            | nr::MOUNT
            | nr::UMOUNT2
            | nr::PIVOT_ROOT
            | nr::CHROOT
            | nr::SWAPON
            | nr::SWAPOFF
            | nr::REBOOT
            | nr::INIT_MODULE
            | nr::DELETE_MODULE
            | nr::QUOTACTL
            | nr::SETHOSTNAME
            | nr::SETDOMAINNAME
            | nr::VHANGUP
            | nr::STIME
            | nr::SETTIMEOFDAY
            | nr::ADJTIMEX
            | nr::CLOCK_SETTIME
            | nr::CLOCK_SETTIME64
            | nr::CLOCK_ADJTIME
            | nr::CLOCK_ADJTIME64 => bad(errno::EPERM),
            nr::USTAT | nr::USELIB | nr::SYSFS | nr::BDFLUSH | nr::_SYSCTL | nr::SYSLOG => {
                bad(errno::ENOSYS)
            }
            _ => Disp::Unimpl,
        }
    }

    /// 引数 `i`（0 起算）を取り出す。0–5 は r26–r21 の降順、
    /// 6 は番号レジスタ r20 を指す内部添字。
    // Ref: SRC-LINUX (7.3) — syscall 規約（r26..r21=args, r20=nr）。
    fn arg(env: &mut BareEnv, i: usize) -> u64 {
        let r = match i {
            0..=5 => 26 - i as u8,
            6 => 20,
            _ => return 0,
        };
        env.backend.get(sem::Gr(r).state())
    }

    /// 戻り値を r28 に書く。
    // Ref: SRC-LINUX (7.3) — syscall 規約（r28=ret）。
    fn ret(env: &mut BareEnv, v: u64) {
        env.backend.set(sem::Gr(28).state(), v);
    }

    /// 通常 syscall（code=0x100）のディスパッチ。
    // Ref: SRC-LINUX (7.3) — syscall 規約（r20=nr, r26..r21=args, r28=ret）。
    fn syscall(&mut self, env: &mut BareEnv) -> TrapOutcome {
        let n = Self::arg(env, 6); // r20
        let args: [u64; 6] = std::array::from_fn(|i| Self::arg(env, i));
        match self.dispatch(env, n, &args) {
            Disp::Ret(v) => {
                Self::ret(env, v);
            }
            Disp::Exit(c) => return TrapOutcome::Exit(c),
            Disp::Unimpl => {
                // 未実装は既定で ENOSYS を返して続ける（設計:
                // docs/design/user-mode.md の「未実装のシステムコール」）。
                if !self.reported.contains(&n) {
                    self.reported.push(n);
                    eprintln!(
                        "run: unhandled parisc syscall {n} ({})",
                        super::name(n).unwrap_or("?")
                    );
                }
                Self::ret(env, fail(errno::ENOSYS));
            }
        }
        TrapOutcome::Handled
    }

    /// LWS-CAS（gate::LWS）。`r20`=副番号、`r26`=adr。
    /// 状態は `r21`（0/-errno）。which 表はカーネルの `lws_table`
    /// （0=CAS32、1=CAS64、2=CAS2、3=atomic_xchg、4=atomic_store、
    /// 5 以上は ENOSYS）。
    /// which=0（CAS）: `r25`=old、`r24`=new。読めた元の値は `r28`
    /// に返す。
    /// which=1 は 32 ビットカーネルでは ENOSYS（lws_exit_nosys）。
    /// which=2（CAS2）: `r25`/`r24` は old/new 値へのポインタ、
    /// `r23` はサイズコード。`r28` は成否（0=成功、非0=失敗）。
    /// which=3（atomic_xchg）: `r25`=サイズコード、`r24`=new 値への
    /// ポインタ、`r23`=旧値の書き戻し先。
    /// which=4（atomic_store）: `r25`=サイズコード、`r24`=値への
    /// ポインタ。
    /// 正本の `lws_start` は which<5 のディスパッチ前に `r28` を
    /// `lws_table` の番地で破壊する（"Scratch use of r28"）。
    /// which>=5 は `comiclr,>>`→`b,n lws_exit_nosys` が先行する
    /// ため `r28` は不変。プローブ域（ロック・クリティカル部の前）
    /// のフォルトは `lws_fault`（`r28`=1、`r21`=-EFAULT）、
    /// クリティカル部のフォルトは `lws_pagefault`（`r28`=3、
    /// `r21`=-EAGAIN）。ロック競合（EAGAIN、`r28`=1/2）は単一
    /// スレッドモデルでは起きないため対象外。
    // Ref: SRC-LINUX — arch/parisc/kernel/syscall.S
    // `lws_start` / `lws_table` / `lws_compare_and_swap`
    // / `lws_compare_and_swap_2` / `lws_atomic_xchg`
    // / `lws_atomic_store` / `lws_fault` / `lws_pagefault`。
    fn lws(&mut self, env: &mut BareEnv) -> TrapOutcome {
        let which = Self::arg(env, 6); // r20
        let adr = Self::arg(env, 0);
        let old = Self::arg(env, 1);
        let new = Self::arg(env, 2);
        if which < lws::ENTRIES {
            // `ldo R%lws_table(%r1),%r28` — ディスパッチ前の
            // スクラッチ破壊。
            Self::ret(env, lws::TABLE_ADDR);
        }
        let status: u32 = match which {
            lws::CAS => self.lws_cas(env, adr, old, new),
            // which=1（CAS64）は 32 ビットカーネルでは
            // `b,n lws_exit_nosys`（r28 は上で破壊済み）。
            lws::CAS64 => errno::ENOSYS,
            lws::CAS2 => self.lws_cas2(env, adr, old, new),
            lws::XCHG => self.lws_xchg(env, adr),
            lws::STORE => self.lws_store(env, adr),
            // which>=5 は r28 不変のまま lws_exit_nosys。
            _ => errno::ENOSYS,
        };
        env.backend
            .set(sem::Gr(21).state(), (-(status as i64)) as u64);
        TrapOutcome::Handled
    }

    /// `lws_fault`（プローブ域のフォルト）: `r28`=1、`r21`=-EFAULT。
    // Ref: SRC-LINUX — syscall.S `lws_fault`
    // （ldo 1(%r0),%r28 / ldo -EFAULT(%r0),%r21）。
    fn lws_fault(env: &mut BareEnv) -> u32 {
        Self::ret(env, 1);
        errno::EFAULT
    }

    /// `lws_pagefault`（クリティカル部のフォルト）: `r28`=3、
    /// `r21`=-EAGAIN。プローブを通った後のロード/ストアがページ
    /// 跨ぎ等でフォルトした場合に到達する。
    // Ref: SRC-LINUX — syscall.S `lws_pagefault`
    // （ldo 3(%r0),%r28 / ldo -EAGAIN(%r0),%r21）。
    fn lws_pagefault(env: &mut BareEnv) -> u32 {
        Self::ret(env, 3);
        errno::EAGAIN
    }

    /// LWS `which=0`（CAS、`lws_compare_and_swap`）。
    /// `r26`=adr、`r25`=old、`r24`=new。読めた元の値は `r28` に
    /// 返す（不一致でも）。正本は比較の前に `ldw`+`proberi`+
    /// `stbys,e` で r26 の読み・書き可否を無条件に検査する。
    /// 非整列 adr は整列検査をせず、非整列データ参照トラップの
    /// `handle_unaligned` によるエミュレートで成立する（`stbys,e`
    /// も非整列 adr では語先頭〜adr 未満を 0 で埋める副作用を
    /// 持つ）。
    // Ref: SRC-LINUX — arch/parisc/kernel/syscall.S
    // `lws_compare_and_swap`（traps.c/unaligned.c の非整列
    // エミュレート経路を含む）。
    fn lws_cas(&mut self, env: &mut BareEnv, adr: u64, old: u64, new: u64) -> u32 {
        let Some(cur) = self.get32(env, adr) else {
            return Self::lws_fault(env);
        };
        if !self.stbys_probe(env, adr) {
            return Self::lws_fault(env);
        }
        Self::ret(env, cur);
        if cur == old && !self.write_bytes(env, adr, &(new as u32).to_be_bytes()) {
            return Self::lws_pagefault(env);
        }
        0
    }

    /// LWS `which=2`（CAS2、`lws_compare_and_swap_2`）。
    /// `r23`=サイズコード（0/1/2/3 → 8/16/32/64 ビット。>=4 は
    /// ENOSYS）。`r25`/`r24` から old/new を読み、`adr` の
    /// `size` バイトと比較して一致なら new を書く。`r28` は
    /// 0=成功・非0=不一致。正本は `cas2_lock_start` で r26 を
    /// 語整列した番地に `ldw`+`proberi`+`stbys,e` を無条件実行
    /// してからロック・比較に入る。
    // Ref: SRC-LINUX — arch/parisc/kernel/syscall.S
    // `lws_compare_and_swap_2` / `cas2_lock_start`。
    fn lws_cas2(&mut self, env: &mut BareEnv, adr: u64, old_p: u64, new_p: u64) -> u32 {
        let size = Self::arg(env, 3); // r23
        if size > 3 {
            return errno::ENOSYS;
        }
        let n = 1usize << size;
        let (Some(old), Some(new)) = (
            self.read_bytes(env, old_p, n),
            self.read_bytes(env, new_p, n),
        ) else {
            return Self::lws_fault(env);
        };
        if self.read_bytes(env, adr & !3, 4).is_none() || !self.stbys_probe(env, adr & !3) {
            return Self::lws_fault(env);
        }
        let Some(cur) = self.read_bytes(env, adr, n) else {
            return Self::lws_pagefault(env);
        };
        if cur != old {
            Self::ret(env, 1);
            return 0;
        }
        if !self.write_bytes(env, adr, &new) {
            return Self::lws_pagefault(env);
        }
        Self::ret(env, 0);
        0
    }

    /// LWS `which=3`（atomic_xchg、`lws_atomic_xchg`）。
    /// `r25`=サイズコード（0/1/2/3 → 8/16/32/64 ビット。>=4 は
    /// ENOSYS）、`r24`=new 値へのポインタ、`r23`=旧値の書き戻し先。
    /// カーネルの代入順どおり「`*r23 = *r26` → `*r26 = *r24`」で、
    /// `r28` は 0=成功・非0=失敗。
    /// 正本は各 arm で `*r24` の読み（+proberi）と `*r23` への
    /// `stbys,e`（8/16bit は語整列した番地、32bit は r23 そのもの、
    /// 64bit は語整列した 2 語）を行い、ついで `atomic_xchg_start`
    /// で語整列した r26 の `ldw`+`stbys,e` を実行してから
    /// クリティカル部に入る（部分書き込みを残さない）。
    // Ref: SRC-LINUX — arch/parisc/kernel/syscall.S `lws_atomic_xchg`
    // / `atomic_xchg_start`。
    fn lws_xchg(&mut self, env: &mut BareEnv, adr: u64) -> u32 {
        let size = Self::arg(env, 1); // r25
        let new_p = Self::arg(env, 2); // r24
        let old_p = Self::arg(env, 3); // r23
        if size > 3 {
            return errno::ENOSYS;
        }
        let n = 1usize << size;
        if self.read_bytes(env, new_p, n).is_none() {
            return Self::lws_fault(env);
        }
        let old_ok = match size {
            3 => self.stbys_probe(env, old_p & !3) && self.stbys_probe(env, (old_p & !3) + 4),
            2 => self.stbys_probe(env, old_p),
            _ => self.stbys_probe(env, old_p & !3),
        };
        if !old_ok {
            return Self::lws_fault(env);
        }
        if self.read_bytes(env, adr & !3, 4).is_none() || !self.stbys_probe(env, adr & !3) {
            return Self::lws_fault(env);
        }
        let Some(cur) = self.read_bytes(env, adr, n) else {
            return Self::lws_pagefault(env);
        };
        if !self.write_bytes(env, old_p, &cur) {
            return Self::lws_pagefault(env);
        }
        let Some(new) = self.read_bytes(env, new_p, n) else {
            return Self::lws_pagefault(env);
        };
        if !self.write_bytes(env, adr, &new) {
            return Self::lws_pagefault(env);
        }
        Self::ret(env, 0);
        0
    }

    /// LWS `which=4`（atomic_store、`lws_atomic_store`）。
    /// `r25`=サイズコード（0/1/2/3 → 8/16/32/64 ビット。>=4 は
    /// ENOSYS）、`r24`=値へのポインタ。`*r26 = *r24`。
    /// `r28` は 0=成功・非0=失敗。正本は各 arm で `*r24` の読み、
    /// ついで `atomic_store_start` で語整列した r26 の `ldw`（読み
    /// 可否）+`stbys,e`（書き可否）を実行してからクリティカル部に
    /// 入る。
    // Ref: SRC-LINUX — syscall.S `lws_atomic_store`
    // / `atomic_store_start`。
    fn lws_store(&mut self, env: &mut BareEnv, adr: u64) -> u32 {
        let size = Self::arg(env, 1); // r25
        let val_p = Self::arg(env, 2); // r24
        if size > 3 {
            return errno::ENOSYS;
        }
        let n = 1usize << size;
        let Some(val) = self.read_bytes(env, val_p, n) else {
            return Self::lws_fault(env);
        };
        if self.read_bytes(env, adr & !3, 4).is_none() || !self.stbys_probe(env, adr & !3) {
            return Self::lws_fault(env);
        }
        if !self.write_bytes(env, adr, &val) {
            return Self::lws_pagefault(env);
        }
        Self::ret(env, 0);
        0
    }

    /// 書き込み可否のプローブ（値は書かない）。カーネルの
    /// `stbys,e`（整列番地）相当で、先頭バイトを W 要求として読む。
    // Ref: SRC-LINUX — syscall.S `stbys,e`（page fault 事前検査）。
    fn can_write(&self, env: &mut BareEnv, addr: u64) -> bool {
        let mut b = [0u8; 1];
        env.backend
            .mem
            .read(VirtAddr(addr), &mut b, self.acc(AccessKind::DataWrite))
            .is_ok()
    }

    /// `stbys,e %r0,0(addr)`（PSW.E=0）相当の書込プローブ。addr が
    /// 語の先頭バイトなら何も書かず保護だけ検査し、非整列なら語
    /// 先頭〜addr 未満を r0=0 で埋める。検査の可否を返す。
    // Ref: SPEC-PARISC-11 §5-52 / SRC-LINUX — syscall.S の
    // `stbys,e` プローブ。
    fn stbys_probe(&mut self, env: &mut BareEnv, addr: u64) -> bool {
        if !self.can_write(env, addr) {
            return false;
        }
        let pad = (addr & 3) as usize;
        pad == 0 || self.write_bytes(env, addr & !3, &[0u8; 3][..pad])
    }
}

/// ホストの io エラーを hppa の errno へ写す。hppa の errno は
/// 1–34 が asm-generic/errno-base.h と同値、35 以上は HP-UX 系の
/// 独自表（ENOSYS=251 など）。マッピングはホスト（generic Linux）
/// の errno 番号 → hppa の番号。
// Ref: SRC-LINUX (7.3) — arch/parisc/include/uapi/asm/errno.h。
fn host_errno(e: std::io::Error) -> u32 {
    match e.raw_os_error() {
        Some(1) => errno::EPERM,
        Some(2) => errno::ENOENT,
        Some(3) => errno::ESRCH,
        Some(4) => errno::EINTR,
        Some(5) => errno::EIO,
        Some(6) => errno::ENXIO,
        Some(7) => errno::E2BIG,
        Some(8) => errno::ENOEXEC,
        Some(9) => errno::EBADF,
        Some(10) => errno::ECHILD,
        Some(11) => errno::EAGAIN,
        Some(12) => errno::ENOMEM,
        Some(13) => errno::EACCES,
        Some(14) => errno::EFAULT,
        Some(15) => errno::ENOTBLK,
        Some(16) => errno::EBUSY,
        Some(17) => errno::EEXIST,
        Some(18) => errno::EXDEV,
        Some(19) => errno::ENODEV,
        Some(20) => errno::ENOTDIR,
        Some(21) => errno::EISDIR,
        Some(22) => errno::EINVAL,
        Some(23) => errno::ENFILE,
        Some(24) => errno::EMFILE,
        Some(25) => errno::ENOTTY,
        Some(26) => errno::ETXTBSY,
        Some(27) => errno::EFBIG,
        Some(28) => errno::ENOSPC,
        Some(29) => errno::ESPIPE,
        Some(30) => errno::EROFS,
        Some(31) => errno::EMLINK,
        Some(32) => errno::EPIPE,
        Some(33) => errno::EDOM,
        Some(34) => errno::ERANGE,
        // --- generic errno.h の値（ホスト側）→ hppa 独自表 ---
        Some(35) => errno::EDEADLK,          // 45
        Some(36) => errno::ENAMETOOLONG,     // 248
        Some(37) => errno::ENOLCK,           // 46
        Some(38) => errno::ENOSYS,           // 251
        Some(39) => errno::ENOTEMPTY,        // 247
        Some(40) => errno::ELOOP,            // 249
        Some(41) => errno::ENOMSG,           // 35
        Some(42) => errno::EIDRM,            // 36
        Some(43) => errno::ECHRNG,           // 37
        Some(44) => errno::EL2NSYNC,         // 38
        Some(45) => errno::EL3HLT,           // 39
        Some(46) => errno::EL3RST,           // 40
        Some(47) => errno::ELNRNG,           // 41
        Some(48) => errno::EUNATCH,          // 42
        Some(49) => errno::ENOCSI,           // 43
        Some(50) => errno::EL2HLT,           // 44
        Some(51) => errno::EBADE,            // 160
        Some(52) => errno::EBADR,            // 161
        Some(53) => errno::EXFULL,           // 162
        Some(54) => errno::ENOANO,           // 163
        Some(55) => errno::EBADRQC,          // 164
        Some(56) => errno::EBADSLT,          // 165
        Some(57) => errno::EDEADLK,          // EDEADLOCK = EDEADLK
        Some(59) => errno::EBFONT,           // 166
        Some(60) => errno::ENOSTR,           // 54
        Some(61) => errno::ENODATA,          // 51
        Some(62) => errno::ETIME,            // 52
        Some(63) => errno::ENOSR,            // 53
        Some(64) => errno::ENONET,           // 50
        Some(65) => errno::ENOPKG,           // 55
        Some(66) => errno::EREMOTE,          // 71
        Some(67) => errno::ENOLINK,          // 57
        Some(68) => errno::EADV,             // 58
        Some(69) => errno::ESRMNT,           // 59
        Some(70) => errno::ECOMM,            // 60
        Some(71) => errno::EPROTO,           // 61
        Some(72) => errno::EMULTIHOP,        // 64
        Some(73) => errno::EDOTDOT,          // 66
        Some(74) => errno::EBADMSG,          // 67
        Some(75) => errno::EOVERFLOW,        // 72
        Some(76) => errno::ENOTUNIQ,         // 167
        Some(77) => errno::EBADFD,           // 168
        Some(78) => errno::EREMCHG,          // 169
        Some(79) => errno::ELIBACC,          // 170
        Some(80) => errno::ELIBBAD,          // 171
        Some(81) => errno::ELIBSCN,          // 172
        Some(82) => errno::ELIBMAX,          // 173
        Some(83) => errno::ELIBEXEC,         // 174
        Some(84) => errno::EILSEQ,           // 47
        Some(85) => errno::ERESTART,         // 175
        Some(86) => errno::ESTRPIPE,         // 176
        Some(87) => errno::EUSERS,           // 68
        Some(88) => errno::ENOTSOCK,         // 216
        Some(89) => errno::EDESTADDRREQ,     // 217
        Some(90) => errno::EMSGSIZE,         // 218
        Some(91) => errno::EPROTOTYPE,       // 219
        Some(92) => errno::ENOPROTOOPT,      // 220
        Some(93) => errno::EPROTONOSUPPORT,  // 221
        Some(94) => errno::ESOCKTNOSUPPORT,  // 222
        Some(95) => errno::EOPNOTSUPP,       // 223
        Some(96) => errno::EPFNOSUPPORT,     // 224
        Some(97) => errno::EAFNOSUPPORT,     // 225
        Some(98) => errno::EADDRINUSE,       // 226
        Some(99) => errno::EADDRNOTAVAIL,    // 227
        Some(100) => errno::ENETDOWN,        // 228
        Some(101) => errno::ENETUNREACH,     // 229
        Some(102) => errno::ENETRESET,       // 230
        Some(103) => errno::ECONNABORTED,    // 231
        Some(104) => errno::ECONNRESET,      // 232
        Some(105) => errno::ENOBUFS,         // 233
        Some(106) => errno::EISCONN,         // 234
        Some(107) => errno::ENOTCONN,        // 235
        Some(108) => errno::ESHUTDOWN,       // 236
        Some(109) => errno::ETOOMANYREFS,    // 237
        Some(110) => errno::ETIMEDOUT,       // 238
        Some(111) => errno::ECONNREFUSED,    // 239
        Some(112) => errno::EHOSTDOWN,       // 241
        Some(113) => errno::EHOSTUNREACH,    // 242
        Some(114) => errno::EALREADY,        // 244
        Some(115) => errno::EINPROGRESS,     // 245
        Some(116) => errno::ESTALE,          // 70
        Some(117) => errno::EUCLEAN,         // 177
        Some(118) => errno::ENOTNAM,         // 178
        Some(119) => errno::ENAVAIL,         // 179
        Some(120) => errno::EISNAM,          // 180
        Some(121) => errno::EREMOTEIO,       // 181
        Some(122) => errno::EDQUOT,          // 69
        Some(123) => errno::ENOMEDIUM,       // 182
        Some(124) => errno::EMEDIUMTYPE,     // 183
        Some(125) => errno::ECANCELLED,      // 253
        Some(126) => errno::ENOKEY,          // 184
        Some(127) => errno::EKEYEXPIRED,     // 185
        Some(128) => errno::EKEYREVOKED,     // 186
        Some(129) => errno::EKEYREJECTED,    // 187
        Some(130) => errno::EOWNERDEAD,      // 254
        Some(131) => errno::ENOTRECOVERABLE, // 255
        Some(132) => errno::ERFKILL,         // 256
        Some(133) => errno::EHWPOISON,       // 257
        _ => errno::EIO,
    }
}

impl TrapHandler for Linux {
    /// `code` は実行ループが載せるゲートウェイ番地（0x100=syscall、
    /// 0xb0=LWS）。それ以外の番地は未対応。
    fn handle_trap(&mut self, env: &mut BareEnv, code: u32) -> TrapOutcome {
        match code {
            gate::SYSCALL => self.syscall(env),
            gate::LWS => self.lws(env),
            _ => TrapOutcome::Unimplemented,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_guest_parisc::CpuState;

    fn env() -> BareEnv {
        BareEnv::new(core::mem::size_of::<CpuState>())
    }

    fn set_r(env: &mut BareEnv, r: u8, v: u64) {
        env.backend.set(sem::Gr(r).state(), v);
    }

    fn get_r(env: &mut BareEnv, r: u8) -> u64 {
        env.backend.get(sem::Gr(r).state())
    }

    /// `syscall.tbl` の表と `syscall_name` の ABI 引きが一致する。
    #[test]
    fn parisc_syscall_table_matches_guest_abi() {
        assert_eq!(
            crate::syscall_name(crate::GuestAbi::PariscLinux, 4),
            Some("write")
        );
        assert_eq!(
            crate::syscall_name(crate::GuestAbi::PariscLinux, 59),
            Some("uname")
        );
        assert_eq!(
            crate::syscall_name(crate::GuestAbi::PariscLinux, 222),
            Some("exit_group")
        );
        assert_eq!(
            crate::syscall_name(crate::GuestAbi::PariscLinux, 9999),
            None
        );
        // 表は番号昇順（binary_search が成り立つ）。
        for w in crate::parisc::SYSCALLS.windows(2) {
            assert!(w[0].0 < w[1].0, "表が昇順でない: {w:?}");
        }
    }

    /// 未実装 syscall は ENOSYS を r28 に返して続ける。
    #[test]
    fn unimplemented_syscall_returns_enosys_and_continues() {
        let mut sys = Linux::new();
        let mut env = env();
        set_r(&mut env, 20, 9999);
        assert!(matches!(
            sys.handle_trap(&mut env, gate::SYSCALL),
            TrapOutcome::Handled
        ));
        assert_eq!(get_r(&mut env, 28), (-(errno::ENOSYS as i64)) as u64);
    }

    /// `exit_group` は Exit として返る（r28 は触らない）。
    #[test]
    fn exit_group_returns_exit_outcome() {
        let mut sys = Linux::new();
        let mut env = env();
        set_r(&mut env, 20, crate::parisc::nr::EXIT_GROUP);
        set_r(&mut env, 26, 7);
        assert!(matches!(
            sys.handle_trap(&mut env, gate::SYSCALL),
            TrapOutcome::Exit(7)
        ));
    }

    /// write(1,…) は stdout に乗り、戻り値はバイト数。
    #[test]
    fn write_captures_stdout() {
        let mut sys = Linux::new();
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x4000), 1, Perms::RW).unwrap();
        env.backend.mem.write(VirtAddr(0x4000), b"ok\n\0").unwrap();
        set_r(&mut env, 20, crate::parisc::nr::WRITE);
        set_r(&mut env, 26, 1);
        set_r(&mut env, 25, 0x4000);
        set_r(&mut env, 24, 3);
        assert!(matches!(
            sys.handle_trap(&mut env, gate::SYSCALL),
            TrapOutcome::Handled
        ));
        assert_eq!(sys.io.stdout, b"ok\n");
        assert_eq!(get_r(&mut env, 28), 3);
    }

    /// open/read/close の FdTable 往復。
    #[test]
    fn open_read_close_roundtrip() {
        let dir = std::env::temp_dir().join("polyisa-parisc-open");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("t.txt");
        std::fs::write(&p, b"hello").unwrap();
        let mut sys = Linux::new();
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x4000), 1, Perms::RW).unwrap();
        env.backend.mem.map(VirtAddr(0x8000), 1, Perms::RW).unwrap();
        let ps = p.to_str().unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x4000), ps.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x4000 + ps.len() as u64), &[0])
            .unwrap();
        // open(path, O_RDONLY=0)
        set_r(&mut env, 20, crate::parisc::nr::OPEN);
        set_r(&mut env, 26, 0x4000);
        set_r(&mut env, 25, 0);
        assert!(matches!(
            sys.handle_trap(&mut env, gate::SYSCALL),
            TrapOutcome::Handled
        ));
        let fd = get_r(&mut env, 28);
        assert_eq!(fd, 3);
        // read(fd, buf, 5)
        set_r(&mut env, 20, crate::parisc::nr::READ);
        set_r(&mut env, 26, fd);
        set_r(&mut env, 25, 0x8000);
        set_r(&mut env, 24, 5);
        assert!(matches!(
            sys.handle_trap(&mut env, gate::SYSCALL),
            TrapOutcome::Handled
        ));
        assert_eq!(get_r(&mut env, 28), 5);
        assert_eq!(sys.read_bytes(&mut env, 0x8000, 5).unwrap(), b"hello");
        // close(fd)
        set_r(&mut env, 20, crate::parisc::nr::CLOSE);
        set_r(&mut env, 26, fd);
        assert!(matches!(
            sys.handle_trap(&mut env, gate::SYSCALL),
            TrapOutcome::Handled
        ));
        assert_eq!(get_r(&mut env, 28), 0);
        // 再 read は EBADF。
        set_r(&mut env, 20, crate::parisc::nr::READ);
        assert!(matches!(
            sys.handle_trap(&mut env, gate::SYSCALL),
            TrapOutcome::Handled
        ));
        assert_eq!(get_r(&mut env, 28), (-(errno::EBADF as i64)) as u64);
    }

    /// stat64（104B）のレイアウト: dev u64@0, mode@16, uid@24,
    /// size i64@48, ino u64@96。
    // Ref: SRC-LINUX (7.3) — arch/parisc/include/uapi/asm/stat.h.
    #[test]
    fn stat64_layout_matches_hppa() {
        let dir = std::env::temp_dir().join("polyisa-parisc-stat");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("s.txt");
        std::fs::write(&p, b"xyz").unwrap();
        let mut sys = Linux::new();
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x4000), 1, Perms::RW).unwrap();
        env.backend.mem.map(VirtAddr(0x8000), 1, Perms::RW).unwrap();
        let ps = p.to_str().unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x4000), ps.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x4000 + ps.len() as u64), &[0])
            .unwrap();
        // stat64(path, buf)
        set_r(&mut env, 20, crate::parisc::nr::STAT64);
        set_r(&mut env, 26, 0x4000);
        set_r(&mut env, 25, 0x8000);
        assert!(matches!(
            sys.handle_trap(&mut env, gate::SYSCALL),
            TrapOutcome::Handled
        ));
        assert_eq!(get_r(&mut env, 28), 0);
        let mode = sys.get32(&mut env, 0x8000 + 16).unwrap();
        assert_eq!(mode & 0o170000, 0o100000, "通常ファイル");
        assert_eq!(sys.get64(&mut env, 0x8000 + 48), Some(3), "size");
        assert_ne!(sys.get64(&mut env, 0x8000 + 96), Some(0), "ino");
    }

    /// getdents64（linux_dirent64、BE）: reclen は 8 整列、末尾に
    /// 達したら 0。`.`/`..` は合成しない（GAP-0058）。
    #[test]
    fn getdents64_records_be() {
        let dir = std::env::temp_dir().join("polyisa-parisc-dents");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a"), b"").unwrap();
        std::fs::write(dir.join("b"), b"").unwrap();
        let mut sys = Linux::new();
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x4000), 1, Perms::RW).unwrap();
        env.backend.mem.map(VirtAddr(0x8000), 4, Perms::RW).unwrap();
        let ps = dir.to_str().unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x4000), ps.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x4000 + ps.len() as u64), &[0])
            .unwrap();
        // open(dir, O_RDONLY|O_DIRECTORY(1<<12))
        set_r(&mut env, 20, crate::parisc::nr::OPEN);
        set_r(&mut env, 26, 0x4000);
        set_r(&mut env, 25, 1 << 12);
        assert!(matches!(
            sys.handle_trap(&mut env, gate::SYSCALL),
            TrapOutcome::Handled
        ));
        let fd = get_r(&mut env, 28);
        assert_eq!(fd, 3);
        // getdents64(fd, buf, 4096)
        set_r(&mut env, 20, crate::parisc::nr::GETDENTS64);
        set_r(&mut env, 26, fd);
        set_r(&mut env, 25, 0x8000);
        set_r(&mut env, 24, 4096);
        assert!(matches!(
            sys.handle_trap(&mut env, gate::SYSCALL),
            TrapOutcome::Handled
        ));
        let n = get_r(&mut env, 28);
        assert!(n >= 48, "2 エントリ分以上: {n}");
        // 先頭レコードの reclen（u16 @+16、BE）が 8 整列。
        let reclen = sys.get16(&mut env, 0x8000 + 16).unwrap();
        assert_eq!(reclen % 8, 0);
        assert!(reclen >= 24);
        // 2 回目は 0（走査位置の終端）。
        assert!(matches!(
            sys.handle_trap(&mut env, gate::SYSCALL),
            TrapOutcome::Handled
        ));
        assert_eq!(get_r(&mut env, 28), 0);
    }

    /// fstatat64（AT_FDCWD + AT_SYMLINK_NOFOLLOW）と pread64 の
    /// (hi,lo) 語対。
    #[test]
    fn fstatat64_and_pread64_hi_lo() {
        let dir = std::env::temp_dir().join("polyisa-parisc-fstatat");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("f.txt");
        std::fs::write(&p, b"0123456789").unwrap();
        let mut sys = Linux::new();
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x4000), 1, Perms::RW).unwrap();
        env.backend.mem.map(VirtAddr(0x8000), 1, Perms::RW).unwrap();
        let ps = p.to_str().unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x4000), ps.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x4000 + ps.len() as u64), &[0])
            .unwrap();
        // fstatat64(AT_FDCWD=-100, path, buf, 0)
        set_r(&mut env, 20, crate::parisc::nr::FSTATAT64);
        set_r(&mut env, 26, (-100i64) as u64);
        set_r(&mut env, 25, 0x4000);
        set_r(&mut env, 24, 0x8000);
        set_r(&mut env, 23, 0);
        assert!(matches!(
            sys.handle_trap(&mut env, gate::SYSCALL),
            TrapOutcome::Handled
        ));
        assert_eq!(get_r(&mut env, 28), 0);
        assert_eq!(sys.get64(&mut env, 0x8000 + 48), Some(10));
        // open + pread64(fd, buf, 4, hi=0, lo=3) → "3456"
        set_r(&mut env, 20, crate::parisc::nr::OPEN);
        set_r(&mut env, 26, 0x4000);
        set_r(&mut env, 25, 0);
        sys.handle_trap(&mut env, gate::SYSCALL);
        let fd = get_r(&mut env, 28);
        set_r(&mut env, 20, crate::parisc::nr::PREAD64);
        set_r(&mut env, 26, fd);
        set_r(&mut env, 25, 0x8100);
        set_r(&mut env, 24, 4);
        set_r(&mut env, 23, 0); // poshi
        set_r(&mut env, 22, 3); // poslo
        assert!(matches!(
            sys.handle_trap(&mut env, gate::SYSCALL),
            TrapOutcome::Handled
        ));
        assert_eq!(get_r(&mut env, 28), 4);
        assert_eq!(sys.read_bytes(&mut env, 0x8100, 4).unwrap(), b"3456");
    }

    /// getrlimit（u32×2）は NOFILE=7 で FdTable 上限を返す。
    #[test]
    fn getrlimit_writes_hppa32_rlimit() {
        let mut sys = Linux::new();
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x4000), 1, Perms::RW).unwrap();
        set_r(&mut env, 20, crate::parisc::nr::GETRLIMIT);
        set_r(&mut env, 26, crate::parisc::res::NOFILE); // 7
        set_r(&mut env, 25, 0x4000);
        assert!(matches!(
            sys.handle_trap(&mut env, gate::SYSCALL),
            TrapOutcome::Handled
        ));
        assert_eq!(get_r(&mut env, 28), 0);
        assert_eq!(sys.get32(&mut env, 0x4000), Some(1024));
        assert_eq!(sys.get32(&mut env, 0x4004), Some(1024));
    }

    /// fork/clone/execve/wait4 は ENOSYS（GAP-0058）。
    #[test]
    fn process_syscalls_are_enosys() {
        let mut sys = Linux::new();
        let mut env = env();
        for &n in &[
            crate::parisc::nr::FORK,
            crate::parisc::nr::CLONE,
            crate::parisc::nr::EXECVE,
            crate::parisc::nr::WAIT4,
        ] {
            set_r(&mut env, 20, n);
            assert!(matches!(
                sys.handle_trap(&mut env, gate::SYSCALL),
                TrapOutcome::Handled
            ));
            assert_eq!(
                get_r(&mut env, 28),
                (-(errno::ENOSYS as i64)) as u64,
                "nr {n}"
            );
        }
    }

    /// 0x100/0xb0 以外のゲートウェイ番地は Unimplemented。
    #[test]
    fn unknown_gateway_offset_is_unimplemented() {
        let mut sys = Linux::new();
        let mut env = env();
        assert!(matches!(
            sys.handle_trap(&mut env, 0x00),
            TrapOutcome::Unimplemented
        ));
        assert!(matches!(
            sys.handle_trap(&mut env, 0x400),
            TrapOutcome::Unimplemented
        ));
    }

    /// LWS which=1（ELF64 CAS 入口）は 32 ビットカーネルどおり
    /// ENOSYS を r21 に返す。which<5 のディスパッチ前に
    /// `ldo R%lws_table(%r1),%r28` が走るため r28 は lws_table の
    /// 番地で破壊される。
    // Ref: SRC-LINUX — syscall.S `lws_compare_and_swap64` は
    // !CONFIG_64BIT で `lws_exit_nosys` に分岐。`lws_start` の
    // "Scratch use of r28"（syscall.S:514）。
    #[test]
    fn lws_cas64_is_enosys_on_32bit() {
        let mut sys = Linux::new();
        let mut env = env();
        set_r(&mut env, 20, lws::CAS64);
        set_r(&mut env, 28, 0xdead_beef);
        assert!(matches!(
            sys.handle_trap(&mut env, gate::LWS),
            TrapOutcome::Handled
        ));
        assert_eq!(get_r(&mut env, 21), (-(errno::ENOSYS as i64)) as u64);
        assert_eq!(get_r(&mut env, 28), lws::TABLE_ADDR);
    }

    /// which>=5 の ENOSYS は `comiclr,>>`→`b,n lws_exit_nosys` が
    /// `ldo R%lws_table,%r28` より先に分岐するため r28 は不変。
    // Ref: SRC-LINUX — syscall.S `lws_start`（syscall.S:509-514）。
    #[test]
    fn lws_invalid_which_is_enosys_and_keeps_r28() {
        let mut sys = Linux::new();
        let mut env = env();
        set_r(&mut env, 20, lws::ENTRIES); // which=5
        set_r(&mut env, 28, 0xdead_beef);
        assert!(matches!(
            sys.handle_trap(&mut env, gate::LWS),
            TrapOutcome::Handled
        ));
        assert_eq!(get_r(&mut env, 21), (-(errno::ENOSYS as i64)) as u64);
        assert_eq!(get_r(&mut env, 28), 0xdead_beef);
    }

    /// LWS which=0（CAS）のプローブ域フォルトは r28=1・r21=-EFAULT
    /// （カーネルの lws_fault と同じ）。
    // Ref: SRC-LINUX — syscall.S `lws_fault`: ldo 1,%r28 / -EFAULT,%r21。
    #[test]
    fn lws_cas_fault_sets_r28_and_errno() {
        let mut sys = Linux::new();
        let mut env = env();
        set_r(&mut env, 20, lws::CAS);
        set_r(&mut env, 26, 0x5000); // 未写像
        set_r(&mut env, 25, 1);
        set_r(&mut env, 24, 2);
        assert!(matches!(
            sys.handle_trap(&mut env, gate::LWS),
            TrapOutcome::Handled
        ));
        assert_eq!(get_r(&mut env, 28), 1);
        assert_eq!(get_r(&mut env, 21), (-(errno::EFAULT as i64)) as u64);
        // 未写像の非整列 adr も読みプローブ（ldw）で EFAULT + r28=1。
        let mut env2 = BareEnv::new(core::mem::size_of::<CpuState>());
        set_r(&mut env2, 20, lws::CAS);
        set_r(&mut env2, 26, 0x5002);
        assert!(matches!(
            sys.handle_trap(&mut env2, gate::LWS),
            TrapOutcome::Handled
        ));
        assert_eq!(get_r(&mut env2, 28), 1);
        assert_eq!(get_r(&mut env2, 21), (-(errno::EFAULT as i64)) as u64);
    }

    /// LWS which=0（CAS）は読み取り専用ページでは不一致・一致に
    /// 関わらず比較前の `stbys,e` 書込プローブで r28=1・r21=-EFAULT
    /// （正本は比較の前に書込可否を検査する）。
    // Ref: SRC-LINUX — syscall.S `lws_compare_and_swap` の
    // `stbys,e %r0,0(%r26)`（extable → lws_fault）。
    #[test]
    fn lws_cas_write_probe_faults_on_read_only() {
        let mut sys = Linux::new();
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x4000), 1, Perms::RW).unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x4000), &0x1111_2222u32.to_be_bytes())
            .unwrap();
        env.backend
            .mem
            .protect(VirtAddr(0x4000), 1, Perms::R)
            .unwrap();
        set_r(&mut env, 20, lws::CAS);
        set_r(&mut env, 26, 0x4000);
        set_r(&mut env, 25, 0x9999_9999); // 不一致でも
        set_r(&mut env, 24, 0x3333_4444);
        assert!(matches!(
            sys.handle_trap(&mut env, gate::LWS),
            TrapOutcome::Handled
        ));
        assert_eq!(get_r(&mut env, 28), 1);
        assert_eq!(get_r(&mut env, 21), (-(errno::EFAULT as i64)) as u64);
        // 読めるので元値は破壊されない（proberi ではなく
        // lws_fault の ldo 1,%r28 が来る）。
        assert_eq!(sys.get32(&mut env, 0x4000), Some(0x1111_2222));
    }

    /// LWS which=0（CAS）の非整列 adr は写像+許可があれば非整列
    /// エミュレート（正本の handle_unaligned）で成立する。
    /// `stbys,e %r0,0(%r26)` は語先頭〜adr 未満を 0 で埋める副作用を
    /// 持つ（SPEC-PARISC-11 §5-52）。
    // Ref: SRC-LINUX — traps.c/unaligned.c の非整列エミュレート経路。
    #[test]
    fn lws_cas_unaligned_succeeds_on_mapped() {
        let mut sys = Linux::new();
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x4000), 1, Perms::RW).unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x4000), &0xaabb_ccddu32.to_be_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x4004), &0x1122_3344u32.to_be_bytes())
            .unwrap();
        set_r(&mut env, 20, lws::CAS);
        set_r(&mut env, 26, 0x4002); // 非整列
        set_r(&mut env, 25, 0xccdd_1122); // old = [0x4002,0x4006)
        set_r(&mut env, 24, 0x5566_7788); // new
        assert!(matches!(
            sys.handle_trap(&mut env, gate::LWS),
            TrapOutcome::Handled
        ));
        assert_eq!(get_r(&mut env, 28), 0xccdd_1122); // 元値
        assert_eq!(get_r(&mut env, 21), 0);
        // 交差した語内容: stbys,e が [0x4000,0x4002) を 0 書きし、
        // CAS が [0x4002,0x4006) に new を書く。
        assert_eq!(sys.get32(&mut env, 0x4000), Some(0x0000_5566));
        assert_eq!(sys.get32(&mut env, 0x4004), Some(0x7788_3344));
    }

    /// LWS which=0（CAS）のクリティカル部フォルトは `lws_pagefault`
    /// の r28=3・r21=-EAGAIN（プローブ域の r28=1・-EFAULT と区別）。
    /// プローブを通った後の `stw` がページ跨ぎで後半だけ書込不可の
    /// 場合に到達する。
    // Ref: SRC-LINUX — syscall.S `lws_pagefault`（critical region の
    // fixup → ldo 3,%r28 / -EAGAIN,%r21）。
    #[test]
    fn lws_cas_critical_fault_sets_r28_eagain() {
        let mut sys = Linux::new();
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x4000), 1, Perms::RW).unwrap();
        env.backend.mem.map(VirtAddr(0x5000), 1, Perms::RW).unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x4ffe), &0x1122u16.to_be_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x5000), &0x3344u16.to_be_bytes())
            .unwrap();
        env.backend
            .mem
            .protect(VirtAddr(0x5000), 1, Perms::R)
            .unwrap();
        set_r(&mut env, 20, lws::CAS);
        set_r(&mut env, 26, 0x4ffe); // [0x4ffe,0x5002) に跨る
        set_r(&mut env, 25, 0x1122_3344); // 一致
        set_r(&mut env, 24, 0x5566_7788);
        assert!(matches!(
            sys.handle_trap(&mut env, gate::LWS),
            TrapOutcome::Handled
        ));
        assert_eq!(get_r(&mut env, 28), 3);
        assert_eq!(get_r(&mut env, 21), (-(errno::EAGAIN as i64)) as u64);
    }

    /// LWS which=2（CAS2）も比較の前に語整列した r26 の `ldw`+
    /// `stbys,e` を無条件実行する。読み取り専用ページでは不一致で
    /// あっても r28=1・r21=-EFAULT。
    // Ref: SRC-LINUX — syscall.S `cas2_lock_start`（ldw/proberi/
    // stbys,e → lws_fault）。
    #[test]
    fn lws_cas2_write_probe_faults_on_read_only() {
        let mut sys = Linux::new();
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x4000), 1, Perms::RW).unwrap();
        env.backend.mem.map(VirtAddr(0x5000), 1, Perms::RW).unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x4100), &0x11u32.to_be_bytes())
            .unwrap(); // old
        env.backend
            .mem
            .write(VirtAddr(0x4200), &0x22u32.to_be_bytes())
            .unwrap(); // new
        env.backend
            .mem
            .write(VirtAddr(0x5000), &0x33u32.to_be_bytes())
            .unwrap(); // cur != old
        env.backend
            .mem
            .protect(VirtAddr(0x5000), 1, Perms::R)
            .unwrap();
        set_r(&mut env, 20, lws::CAS2);
        set_r(&mut env, 26, 0x5000); // R-only かつ不一致
        set_r(&mut env, 25, 0x4100);
        set_r(&mut env, 24, 0x4200);
        set_r(&mut env, 23, 2); // 32bit
        assert!(matches!(
            sys.handle_trap(&mut env, gate::LWS),
            TrapOutcome::Handled
        ));
        assert_eq!(get_r(&mut env, 28), 1);
        assert_eq!(get_r(&mut env, 21), (-(errno::EFAULT as i64)) as u64);
    }

    /// LWS which=3（atomic_xchg）: `*r23 = *r26` してから
    /// `*r26 = *r24`。r28=0・r21=0。
    // Ref: SRC-LINUX — syscall.S `lws_atomic_xchg`。
    #[test]
    fn lws_atomic_xchg_swaps_via_old_out() {
        let mut sys = Linux::new();
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x4000), 1, Perms::RW).unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x4100), &0x1122_3344u32.to_be_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x4200), &0xaabb_ccddu32.to_be_bytes())
            .unwrap();
        set_r(&mut env, 20, lws::XCHG);
        set_r(&mut env, 26, 0x4100); // exchange address
        set_r(&mut env, 25, 2); // size: 32bit
        set_r(&mut env, 24, 0x4200); // new value ptr
        set_r(&mut env, 23, 0x4300); // old value out ptr
        assert!(matches!(
            sys.handle_trap(&mut env, gate::LWS),
            TrapOutcome::Handled
        ));
        assert_eq!(get_r(&mut env, 28), 0);
        assert_eq!(get_r(&mut env, 21), 0);
        assert_eq!(sys.get32(&mut env, 0x4300), Some(0x1122_3344));
        assert_eq!(sys.get32(&mut env, 0x4100), Some(0xaabb_ccdd));

        // サイズコード >=4 は ENOSYS。which<5 のディスパッチ前に
        // `ldo R%lws_table,%r28` が走るので r28 は lws_table 番地で
        // 破壊される。
        let mut env2 = BareEnv::new(core::mem::size_of::<CpuState>());
        env2.backend
            .mem
            .map(VirtAddr(0x4000), 1, Perms::RW)
            .unwrap();
        set_r(&mut env2, 20, lws::XCHG);
        set_r(&mut env2, 26, 0x4100);
        set_r(&mut env2, 25, 4);
        set_r(&mut env2, 28, 0xdead_beef);
        assert!(matches!(
            sys.handle_trap(&mut env2, gate::LWS),
            TrapOutcome::Handled
        ));
        assert_eq!(get_r(&mut env2, 21), (-(errno::ENOSYS as i64)) as u64);
        assert_eq!(get_r(&mut env2, 28), lws::TABLE_ADDR);
    }

    /// LWS which=4（atomic_store）: `*r26 = *r24`。r28=0・r21=0。
    // Ref: SRC-LINUX — syscall.S `lws_atomic_store`。
    #[test]
    fn lws_atomic_store_writes_value() {
        let mut sys = Linux::new();
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x4000), 1, Perms::RW).unwrap();
        env.backend.mem.write(VirtAddr(0x4200), &[0x77u8]).unwrap();
        set_r(&mut env, 20, lws::STORE);
        set_r(&mut env, 26, 0x4100); // dest
        set_r(&mut env, 25, 0); // size: 8bit
        set_r(&mut env, 24, 0x4200); // value ptr
        assert!(matches!(
            sys.handle_trap(&mut env, gate::LWS),
            TrapOutcome::Handled
        ));
        assert_eq!(get_r(&mut env, 28), 0);
        assert_eq!(get_r(&mut env, 21), 0);
        let mut b = [0u8; 4];
        env.backend
            .mem
            .read(VirtAddr(0x4100), &mut b, sys.acc(AccessKind::DataRead))
            .unwrap();
        assert_eq!(b, [0x77, 0, 0, 0]);

        // 未写像の書き込み先は r28=1・r21=-EFAULT。
        let mut env2 = BareEnv::new(core::mem::size_of::<CpuState>());
        env2.backend
            .mem
            .map(VirtAddr(0x4000), 1, Perms::RW)
            .unwrap();
        env2.backend
            .mem
            .write(VirtAddr(0x4200), &0x77u32.to_be_bytes())
            .unwrap();
        set_r(&mut env2, 20, lws::STORE);
        set_r(&mut env2, 26, 0x9100); // 未写像
        set_r(&mut env2, 25, 2);
        set_r(&mut env2, 24, 0x4200);
        assert!(matches!(
            sys.handle_trap(&mut env2, gate::LWS),
            TrapOutcome::Handled
        ));
        assert_eq!(get_r(&mut env2, 28), 1);
        assert_eq!(get_r(&mut env2, 21), (-(errno::EFAULT as i64)) as u64);

        // 書込専用ページも `ldw` の読みプローブで r28=1・r21=-EFAULT
        // （正本は `atomic_store_start` で語整列した r26 の `ldw`+
        // `stbys,e` を実行する）。
        let mut env3 = BareEnv::new(core::mem::size_of::<CpuState>());
        env3.backend
            .mem
            .map(VirtAddr(0x4000), 1, Perms::RW)
            .unwrap();
        env3.backend
            .mem
            .write(VirtAddr(0x4200), &0x77u32.to_be_bytes())
            .unwrap();
        env3.backend.mem.map(VirtAddr(0x8000), 1, Perms::W).unwrap();
        set_r(&mut env3, 20, lws::STORE);
        set_r(&mut env3, 26, 0x8000);
        set_r(&mut env3, 25, 2);
        set_r(&mut env3, 24, 0x4200);
        assert!(matches!(
            sys.handle_trap(&mut env3, gate::LWS),
            TrapOutcome::Handled
        ));
        assert_eq!(get_r(&mut env3, 28), 1);
        assert_eq!(get_r(&mut env3, 21), (-(errno::EFAULT as i64)) as u64);
    }
}
