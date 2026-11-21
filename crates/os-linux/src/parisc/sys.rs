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
//!
//! 実装対象は bare バイナリの起動に必要な最小集合と、静的大部分の
//! libc 初期化が呼ぶ ioctl/mmap/brk/uname/get*id/sigaction 系。
//! fork/clone/execve/ファイルシステムは未対応（ENOSYS）。

use polyisa_engine::bare::BareEnv;
use polyisa_guest_parisc::sem;
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};
use polyisa_sem::Backend as _;

use crate::parisc::{errno, gate, lws, mman};
use crate::{TrapHandler, TrapOutcome};

/// PA-RISC の write が集めたバイト。標準出力と標準エラーを分ける。
#[derive(Default)]
pub struct PariscIo {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// PA-RISC Linux の syscall 状態機械。`r20`=番号、`r26`–`r21`=引数。
pub struct Linux {
    /// 標準入出力の capture。テストが読む。
    pub io: PariscIo,
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
}

impl Default for Linux {
    fn default() -> Self {
        Self::new()
    }
}

impl Linux {
    /// PA-RISC Linux の状態機械を作る。データはビッグエンディアン。
    #[must_use]
    pub fn new() -> Self {
        Self {
            io: PariscIo::default(),
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
        let mut v = vec![0u8; len];
        env.backend
            .mem
            .read(VirtAddr(addr), &mut v, self.acc(AccessKind::DataRead))
            .ok()?;
        Some(v)
    }

    fn write_bytes(&mut self, env: &mut BareEnv, addr: u64, data: &[u8]) -> bool {
        env.backend.mem.write(VirtAddr(addr), data).is_ok()
    }

    fn get32(&mut self, env: &mut BareEnv, addr: u64) -> Option<u64> {
        env.backend
            .mem
            .read_value(VirtAddr(addr), 4, self.acc(AccessKind::DataRead))
            .ok()
    }

    // ---- レジスタ ABI ----

    /// 引数 `i`（0 起算）。arg0=r26, arg1=r25, …, arg5=r21、
    /// 番号は `arg(env, 6)`（r20）。戻りは下位 32 ビットのみ。
    // Ref: SRC-LINUX (7.3) — syscall(2) の hppa 規約。
    fn arg(env: &mut BareEnv, i: usize) -> u64 {
        env.backend.get(sem::Gr(26 - i as u8).state()) & 0xffff_ffff
    }

    fn ret(env: &mut BareEnv, v: u64) {
        env.backend.set(sem::Gr(28).state(), v);
    }

    // ---- syscall 本体 ----

    /// `write`/`writev`。fd 1/2 は capture とホスト出力、0 は EBADF。
    /// fd の検査は len==0 の早期リターンより先（vfs_write と同順）。
    fn sys_write(&mut self, env: &mut BareEnv, fd: u64, buf: u64, len: u64) -> u64 {
        if fd != 1 && fd != 2 {
            return (-(errno::EBADF as i64)) as u64;
        }
        let n = usize::try_from(len).unwrap_or(1 << 20).min(1 << 20);
        let Some(data) = self.read_bytes(env, buf, n) else {
            return (-(errno::EFAULT as i64)) as u64;
        };
        match fd {
            1 => {
                self.io.stdout.extend_from_slice(&data);
                use std::io::Write as _;
                let _ = std::io::stdout().write_all(&data);
            }
            _ => {
                self.io.stderr.extend_from_slice(&data);
                use std::io::Write as _;
                let _ = std::io::stderr().write_all(&data);
            }
        }
        data.len() as u64
    }

    fn sys_writev(&mut self, env: &mut BareEnv, fd: u64, iov: u64, cnt: u64) -> u64 {
        if fd != 1 && fd != 2 {
            return (-(errno::EBADF as i64)) as u64;
        }
        let mut total = 0u64;
        for i in 0..cnt.min(1024) {
            let Some(base) = self.get32(env, iov + i * 8) else {
                return (-(errno::EFAULT as i64)) as u64;
            };
            let Some(len) = self.get32(env, iov + i * 8 + 4) else {
                return (-(errno::EFAULT as i64)) as u64;
            };
            let n = self.sys_write(env, fd, base, len);
            if (n as i64) < 0 {
                return n;
            }
            total += n;
            if n != len {
                break;
            }
        }
        total
    }

    /// `read`/`readv`。fd 0 は `stdin_buf` を順送り。
    fn sys_read(&mut self, env: &mut BareEnv, fd: u64, buf: u64, len: u64) -> u64 {
        if fd != 0 {
            return (-(errno::EBADF as i64)) as u64;
        }
        let avail = self.stdin_buf.len().saturating_sub(self.stdin_pos);
        let n = (len as usize).min(avail);
        let chunk = self.stdin_buf[self.stdin_pos..self.stdin_pos + n].to_vec();
        self.stdin_pos += n;
        if n > 0 && !self.write_bytes(env, buf, &chunk) {
            return (-(errno::EFAULT as i64)) as u64;
        }
        n as u64
    }

    fn sys_readv(&mut self, env: &mut BareEnv, fd: u64, iov: u64, cnt: u64) -> u64 {
        if fd != 0 {
            return (-(errno::EBADF as i64)) as u64;
        }
        let mut total = 0u64;
        for i in 0..cnt.min(1024) {
            let Some(base) = self.get32(env, iov + i * 8) else {
                return (-(errno::EFAULT as i64)) as u64;
            };
            let Some(len) = self.get32(env, iov + i * 8 + 4) else {
                return (-(errno::EFAULT as i64)) as u64;
            };
            let n = self.sys_read(env, fd, base, len);
            if (n as i64) < 0 {
                return n;
            }
            total += n;
            if n != len {
                break;
            }
        }
        total
    }

    /// `brk`（alpha と同じ規約。0 は現ブレークを返す）。
    fn sys_brk(&mut self, env: &mut BareEnv, addr: u64) -> u64 {
        if addr == 0 {
            return self.heap_end;
        }
        if addr < self.brk_start {
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

    /// `mmap`/`mmap2`。無名 PRIVATE/FIXED のみ。ファイル写像は
    /// ENODEV（`pgoff` の単位差は mmap2 で <<12 だが無名写像では無意味）。
    fn sys_mmap(&mut self, env: &mut BareEnv, args: &[u64; 6]) -> u64 {
        let (addr, len, prot, flags) = (args[0], args[1], args[2] as u32, args[3] as u32);
        if len == 0 || len > (1 << 30) {
            return (-(errno::EINVAL as i64)) as u64;
        }
        if flags & mman::MAP_ANONYMOUS == 0 {
            return (-(errno::ENODEV as i64)) as u64; // ファイル写像は未対応
        }
        if flags & mman::MAP_FIXED != 0 && addr & 0xfff != 0 {
            return (-(errno::EINVAL as i64)) as u64;
        }
        let pages = len.div_ceil(4096);
        let base = if flags & mman::MAP_FIXED != 0 {
            addr & !0xfff
        } else {
            let mut b = self.mmap_next;
            let mut tries = 0;
            while (b..b + pages * 4096)
                .step_by(4096)
                .any(|a| env.backend.mem.is_mapped(polyisa_mem::PageNo(a / 4096)))
            {
                tries += 1;
                if tries > 4096 {
                    return (-(errno::ENOMEM as i64)) as u64;
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
            return (-(errno::ENOMEM as i64)) as u64;
        }
        base
    }

    /// `munmap`。
    fn sys_munmap(&mut self, env: &mut BareEnv, addr: u64, len: u64) -> u64 {
        if len == 0 || addr & 0xfff != 0 {
            return (-(errno::EINVAL as i64)) as u64;
        }
        let Some(end) = addr.checked_add(len) else {
            return (-(errno::EINVAL as i64)) as u64;
        };
        if len > (1 << 30) {
            return (-(errno::ENOMEM as i64)) as u64;
        }
        let pages = end.div_ceil(4096) - addr / 4096;
        env.backend.mem.unmap(VirtAddr(addr), pages);
        0
    }

    /// `mprotect`。範囲をページ境界に丸めて権限を変える。
    fn sys_mprotect(&mut self, env: &mut BareEnv, addr: u64, len: u64, prot: u64) -> u64 {
        let lo = addr & !0xfff;
        let Some(end) = addr.checked_add(len) else {
            return (-(errno::EINVAL as i64)) as u64;
        };
        let hi = end.div_ceil(4096) * 4096;
        if hi <= lo {
            return (-(errno::EINVAL as i64)) as u64;
        }
        let mut p = 0u8;
        if prot as u32 & mman::PROT_READ != 0 {
            p |= Perms::R.0;
        }
        if prot as u32 & mman::PROT_WRITE != 0 {
            p |= Perms::W.0;
        }
        if prot as u32 & mman::PROT_EXEC != 0 {
            p |= Perms::X.0;
        }
        if env
            .backend
            .mem
            .protect(VirtAddr(lo), (hi - lo) / 4096, Perms(p))
            .is_err()
        {
            return (-(errno::ENOMEM as i64)) as u64;
        }
        0
    }

    /// `uname`。machine は "parisc"。
    fn sys_uname(&mut self, env: &mut BareEnv, addr: u64) -> u64 {
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
            return (-(errno::EFAULT as i64)) as u64;
        }
        0
    }

    /// `sysinfo`（hppa32 の struct sysinfo: 4 バイト long。
    /// uptime@0、loads[3]@4、totalram@16、freeram@20、mem_unit@52）。
    fn sys_sysinfo(&mut self, env: &mut BareEnv, addr: u64) -> u64 {
        let secs = self.mono().as_secs();
        let mut img = [0u8; 112];
        img[..4].copy_from_slice(&(secs as u32).to_be_bytes());
        img[16..20].copy_from_slice(&(512u32 << 20).to_be_bytes()); // totalram
        img[20..24].copy_from_slice(&(256u32 << 20).to_be_bytes()); // freeram
        img[52..56].copy_from_slice(&1u32.to_be_bytes()); // mem_unit
        if !self.write_bytes(env, addr, &img) {
            return (-(errno::EFAULT as i64)) as u64;
        }
        0
    }

    /// `times`（tms: long×4 = 16 バイト。戻り値はクロック）。
    fn sys_times(&mut self, env: &mut BareEnv, addr: u64) -> u64 {
        let us = self.mono().as_micros() as u64;
        let ticks = us / 10_000; // USER_HZ=100 換算
        if addr != 0 {
            let mut img = [0u8; 16];
            img[..4].copy_from_slice(&(ticks as u32).to_be_bytes());
            if !self.write_bytes(env, addr, &img) {
                return (-(errno::EFAULT as i64)) as u64;
            }
        }
        ticks
    }

    /// `gettimeofday`（tv_sec/tv_usec の long×2）。
    fn sys_gettimeofday(&mut self, env: &mut BareEnv, tv: u64, _tz: u64) -> u64 {
        let d = self.mono();
        if tv != 0 {
            let mut img = [0u8; 8];
            img[..4].copy_from_slice(&(d.as_secs() as u32).to_be_bytes());
            img[4..8].copy_from_slice(&d.subsec_micros().to_be_bytes());
            if !self.write_bytes(env, tv, &img) {
                return (-(errno::EFAULT as i64)) as u64;
            }
        }
        0
    }

    /// `clock_gettime`（timespec: long sec + long nsec）。
    fn sys_clock_gettime(&mut self, env: &mut BareEnv, _clk: u64, ts: u64) -> u64 {
        let d = self.mono();
        let mut img = [0u8; 8];
        img[..4].copy_from_slice(&(d.as_secs() as u32).to_be_bytes());
        img[4..8].copy_from_slice(&d.subsec_nanos().to_be_bytes());
        if !self.write_bytes(env, ts, &img) {
            return (-(errno::EFAULT as i64)) as u64;
        }
        0
    }

    /// `clock_gettime64`（timespec64: i64 sec + i64 nsec）。
    fn sys_clock_gettime64(&mut self, env: &mut BareEnv, _clk: u64, ts: u64) -> u64 {
        let d = self.mono();
        let mut img = [0u8; 16];
        img[..8].copy_from_slice(&(d.as_secs() as i64).to_be_bytes());
        img[8..16].copy_from_slice(&(i64::from(d.subsec_nanos())).to_be_bytes());
        if !self.write_bytes(env, ts, &img) {
            return (-(errno::EFAULT as i64)) as u64;
        }
        0
    }

    /// `clock_getres`（timespec: long sec + long nsec = 1ns 分解能）。
    fn sys_clock_getres(&mut self, env: &mut BareEnv, _clk: u64, res: u64) -> u64 {
        if res != 0 {
            let mut img = [0u8; 8];
            img[4..8].copy_from_slice(&1u32.to_be_bytes());
            if !self.write_bytes(env, res, &img) {
                return (-(errno::EFAULT as i64)) as u64;
            }
        }
        0
    }

    /// `getrandom`。決定的 xorshift で埋める（再現性のため）。
    fn sys_getrandom(&mut self, env: &mut BareEnv, buf: u64, len: u64, _flags: u64) -> u64 {
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
            return (-(errno::EFAULT as i64)) as u64;
        }
        n as u64
    }

    /// `getcwd`。
    fn sys_getcwd(&mut self, env: &mut BareEnv, buf: u64, len: u64) -> u64 {
        let s = "/";
        let n = s.len() + 1;
        if n as u64 > len {
            return (-(errno::ERANGE as i64)) as u64;
        }
        if !self.write_bytes(env, buf, s.as_bytes())
            || !self.write_bytes(env, buf + s.len() as u64, &[0])
        {
            return (-(errno::EFAULT as i64)) as u64;
        }
        n as u64
    }

    /// `readlink`/`readlinkat`。/proc/self/exe だけ `exe_path`、
    /// ほかは ENOENT。
    fn sys_readlink(&mut self, env: &mut BareEnv, path_addr: u64, buf: u64, len: u64) -> u64 {
        let path = self.read_cstr(env, path_addr).unwrap_or_default();
        let path = String::from_utf8_lossy(&path);
        let target = if path == "/proc/self/exe" {
            self.exe_path.clone()
        } else {
            return (-(errno::ENOENT as i64)) as u64;
        };
        let b = target.as_bytes();
        let n = b.len().min(len as usize);
        if !self.write_bytes(env, buf, &b[..n]) {
            return (-(errno::EFAULT as i64)) as u64;
        }
        n as u64
    }

    fn read_cstr(&mut self, env: &mut BareEnv, addr: u64) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        for i in 0..4096u64 {
            let mut b = [0u8; 1];
            env.backend
                .mem
                .read(VirtAddr(addr + i), &mut b, self.acc(AccessKind::DataRead))
                .ok()?;
            if b[0] == 0 {
                return Some(out);
            }
            out.push(b[0]);
        }
        Some(out)
    }

    /// 通常 syscall（code=0x100）のディスパッチ。
    // Ref: SRC-LINUX (7.3) — syscall 規約（r20=nr, r26..r21=args, r28=ret）。
    fn syscall(&mut self, env: &mut BareEnv) -> TrapOutcome {
        let n = Self::arg(env, 6); // r20
        let args: [u64; 6] = [
            Self::arg(env, 0),
            Self::arg(env, 1),
            Self::arg(env, 2),
            Self::arg(env, 3),
            Self::arg(env, 4),
            Self::arg(env, 5),
        ];
        let name = super::name(n);
        let r: Option<u64> = match name {
            Some("exit") | Some("exit_group") => {
                return TrapOutcome::Exit(args[0] as u32);
            }
            Some("write") => Some(self.sys_write(env, args[0], args[1], args[2])),
            Some("writev") => Some(self.sys_writev(env, args[0], args[1], args[2])),
            Some("read") => Some(self.sys_read(env, args[0], args[1], args[2])),
            Some("readv") => Some(self.sys_readv(env, args[0], args[1], args[2])),
            Some("brk") => Some(self.sys_brk(env, args[0])),
            Some("uname") => Some(self.sys_uname(env, args[0])),
            Some("sysinfo") => Some(self.sys_sysinfo(env, args[0])),
            Some("times") => Some(self.sys_times(env, args[0])),
            Some("gettimeofday") => Some(self.sys_gettimeofday(env, args[0], args[1])),
            Some("clock_gettime") => Some(self.sys_clock_gettime(env, args[0], args[1])),
            Some("clock_gettime64") => Some(self.sys_clock_gettime64(env, args[0], args[1])),
            Some("clock_getres") => Some(self.sys_clock_getres(env, args[0], args[1])),
            Some("nanosleep") | Some("clock_nanosleep") => Some(0),
            Some("getcwd") => Some(self.sys_getcwd(env, args[0], args[1])),
            Some("readlink") => Some(self.sys_readlink(env, args[0], args[1], args[2])),
            Some("readlinkat") => {
                // AT_FDCWD の /proc/self/exe のみ。
                Some(self.sys_readlink(env, args[1], args[2], args[3]))
            }
            Some("mmap") | Some("mmap2") => Some(self.sys_mmap(env, &args)),
            Some("munmap") => Some(self.sys_munmap(env, args[0], args[1])),
            Some("mprotect") => Some(self.sys_mprotect(env, args[0], args[1], args[2])),
            Some("ioctl") => Some((-(errno::ENOTTY as i64)) as u64),
            Some("lseek") | Some("_llseek") => Some((-(errno::ESPIPE as i64)) as u64),
            Some("access") | Some("faccessat") | Some("faccessat2") => {
                Some((-(errno::ENOENT as i64)) as u64)
            }
            Some("set_tid_address") | Some("getpid") | Some("gettid") => Some(self.pid()),
            Some("getppid") => Some(self.pid()),
            Some("getuid") | Some("geteuid") | Some("getgid") | Some("getegid") => Some(0),
            Some("getgroups") => Some(0),
            Some("getpgrp") | Some("getsid") | Some("getpgid") => Some(0),
            Some("umask") => {
                let old = self.umask;
                self.umask = (args[0] as u32) & 0o777;
                Some(u64::from(old))
            }
            // 標準 fd だけが開いている。close 0-2 は成功扱い、
            // それ以外は EBADF。
            Some("close") => {
                if args[0] <= 2 {
                    Some(0)
                } else {
                    Some((-(errno::EBADF as i64)) as u64)
                }
            }
            Some("time") => {
                let secs = self.mono().as_secs();
                if args[0] != 0 && !self.write_bytes(env, args[0], &(secs as u32).to_be_bytes()) {
                    Some((-(errno::EFAULT as i64)) as u64)
                } else {
                    Some(secs)
                }
            }
            Some("sched_getaffinity") => {
                // 1 CPU として 0b1 を書く（未写像なら EFAULT）。
                let mask = args[2];
                if mask != 0 && args[1] >= 4 && !self.write_bytes(env, mask, &1u32.to_be_bytes()) {
                    Some((-(errno::EFAULT as i64)) as u64)
                } else {
                    Some(0)
                }
            }
            Some("rt_sigaction")
            | Some("rt_sigprocmask")
            | Some("sigprocmask")
            | Some("sigpending")
            | Some("rt_sigpending")
            | Some("sigaltstack")
            | Some("sigsuspend")
            | Some("rt_sigsuspend")
            | Some("set_robust_list")
            | Some("personality")
            | Some("sched_yield") => Some(0),
            Some("getrandom") => Some(self.sys_getrandom(env, args[0], args[1], args[2])),
            _ => {
                // 未実装は既定で ENOSYS を返して続ける（設計:
                // docs/design/user-mode.md の「未実装のシステムコール」）。
                if !self.reported.contains(&n) {
                    self.reported.push(n);
                    eprintln!(
                        "run: unhandled parisc syscall {n} ({})",
                        name.unwrap_or("?")
                    );
                }
                Some((-(errno::ENOSYS as i64)) as u64)
            }
        };
        if let Some(v) = r {
            Self::ret(env, v);
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
        // `ldw 0(%r26)` — 読みプローブ。`proberi` の読みアクセス権
        // 検査はフラットメモリでは読み可否と同義。
        let Some(cur) = self.get32(env, adr) else {
            return Self::lws_fault(env);
        };
        // `stbys,e %r0,0(%r26)` — 書込可否の検査（非整列なら語先頭
        // 〜adr 未満の 0 書きも行う）。
        if !self.stbys_probe(env, adr) {
            return Self::lws_fault(env);
        }
        // クリティカル部の `ldw`+`sub,<>`+`stw`。プローブ済みの再読は
        // 失敗しないので cur をそのまま使う。書込の失敗（ページ跨ぎ
        // の後半が書込不可等）は lws_pagefault。
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
        // old/new 値の読み込み（各 arm の ldX。非整列はエミュレート）。
        let (Some(old), Some(new)) = (
            self.read_bytes(env, old_p, n),
            self.read_bytes(env, new_p, n),
        ) else {
            return Self::lws_fault(env);
        };
        // `depi` で語整列した r26 に `ldw`+`proberi`+`stbys,e` を
        // 無条件実行（読み可否+書き可否。語先頭への stbys,e は
        // 何も書かない）。
        if self.read_bytes(env, adr & !3, 4).is_none() || !self.stbys_probe(env, adr & !3) {
            return Self::lws_fault(env);
        }
        // クリティカル部の比較・書込の失敗は lws_pagefault。
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
        // 各 arm の先頭: `*r24` の読み（+proberi 相当）。
        if self.read_bytes(env, new_p, n).is_none() {
            return Self::lws_fault(env);
        }
        // `*r23` の書込可否。arm ごとの stbys,e の形状は上の
        // コメントどおり（32bit arm の非整列 r23 では stbys,e が
        // 語先頭〜r23 未満を 0 で埋める）。
        let old_ok = match size {
            3 => self.stbys_probe(env, old_p & !3) && self.stbys_probe(env, (old_p & !3) + 4),
            2 => self.stbys_probe(env, old_p),
            _ => self.stbys_probe(env, old_p & !3),
        };
        if !old_ok {
            return Self::lws_fault(env);
        }
        // `atomic_xchg_start`: 語整列した r26 の `ldw`+`stbys,e`。
        if self.read_bytes(env, adr & !3, 4).is_none() || !self.stbys_probe(env, adr & !3) {
            return Self::lws_fault(env);
        }
        // カーネルと同じ順で逐次化する: `*r23 = *r26` の後に
        // `*r24` を読み直して `*r26` に書く（r23==r24 の別名でも
        // 結果が一致する）。クリティカル部のフォルトは lws_pagefault。
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
    // Ref: SRC-LINUX — arch/parisc/kernel/syscall.S `lws_atomic_store`
    // / `atomic_store_start`。
    fn lws_store(&mut self, env: &mut BareEnv, adr: u64) -> u32 {
        let size = Self::arg(env, 1); // r25
        let val_p = Self::arg(env, 2); // r24
        if size > 3 {
            return errno::ENOSYS;
        }
        let n = 1usize << size;
        // 各 arm の先頭: `*r24` の読み（非整列はエミュレート）。
        let Some(val) = self.read_bytes(env, val_p, n) else {
            return Self::lws_fault(env);
        };
        // `atomic_store_start`: 語整列した r26 の `ldw`+`stbys,e`。
        if self.read_bytes(env, adr & !3, 4).is_none() || !self.stbys_probe(env, adr & !3) {
            return Self::lws_fault(env);
        }
        // クリティカル部の `*r26 = *r24` の失敗は lws_pagefault。
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
