// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! SuperH Linux の syscall 処理（段階18-6 のスタブ）。
//!
//! 規約（SRC-LINUX — arch/sh syscall 規約）:
//! - 発行点は `trapa #0x10`–`#0x1f`（即値は引数の個数分だけ使い分ける）。
//! - 番号は R3、引数は R4–R9、戻り値は R0。失敗は R0 = -errno。
//! - SH には SYSCALL 命令はなく、全て trapa 経由。
//!
//! ここはスタブ: exit/exit_group・write/writev・read・brk・uname・
//! getpid/gettid・get*id 系だけを実装し、他は ENOSYS を返す。
//! BusyBox 実行（S18-1）に必要な残りの ABI（openat・fstat64・
//! mmap2・fork/execve・シグナル枠組み）は後続段階で足す。
//! 信頼できないゲストバイナリには使わないこと。

use std::io::Write as _;

use polyisa_engine::bare::BareEnv;
use polyisa_guest_superh::sem;
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};
use polyisa_sem::Backend as _;

use crate::{TrapHandler, TrapOutcome, superh};

/// write/writev が集めたバイト。標準出力と標準エラーを分ける。
#[derive(Default)]
pub struct SuperhIo {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// SuperH Linux の syscall 状態機械（スタブ）。
/// R3=番号、R4–R9=引数、R0=戻り値。
// Gap: GAP-0060
pub struct Linux {
    /// 標準出力・標準エラーの捕獲。テストが読む。
    pub io: SuperhIo,
    /// プログラムブレーク。0 は未初期化。
    heap_end: u64,
    /// brk 領域の開始（ELF の image_end）。`init_brk` が設定する。
    brk_start: u64,
    /// ホストから見たプロセス識別子。getpid/gettid が返す。
    pid: u64,
    /// 実行ファイルのパス。`readlinkat("/proc/self/exe")` が返す。
    pub exe_path: String,
    /// データアクセスのエンディアン（ELF から実行ループが設定する）。
    pub endian: Endian,
    /// 標準入力へ供給するバイト。
    pub stdin_buf: Vec<u8>,
    stdin_pos: usize,
    /// 報告済みの未実装番号（一度だけ出す）。
    reported: Vec<u64>,
}

impl Default for Linux {
    fn default() -> Self {
        Self::new()
    }
}

impl Linux {
    /// SuperH Linux の状態機械を作る。
    #[must_use]
    pub fn new() -> Self {
        Self {
            io: SuperhIo::default(),
            heap_end: 0,
            brk_start: 0,
            pid: std::process::id().into(),
            exe_path: String::new(),
            endian: Endian::Le,
            stdin_buf: Vec::new(),
            stdin_pos: 0,
            reported: Vec::new(),
        }
    }

    /// ゲストエンディアンの 4 バイトを u32 にする。
    fn u32_of(&self, b: &[u8]) -> u32 {
        match self.endian {
            Endian::Le => u32::from_le_bytes(b[..4].try_into().unwrap_or([0; 4])),
            Endian::Be => u32::from_be_bytes(b[..4].try_into().unwrap_or([0; 4])),
        }
    }

    /// ゲストメモリから `n` バイト読む。
    fn get_bytes(&self, env: &mut BareEnv, addr: u64, n: usize) -> Result<Vec<u8>, u64> {
        let mut buf = vec![0u8; n];
        let acc = Access {
            endian: self.endian,
            align: Align::Unaligned,
            kind: AccessKind::DataRead,
        };
        env.backend
            .mem
            .read(VirtAddr(addr), &mut buf, acc)
            .map_err(|_| u64::from(superh::errno::EFAULT))?;
        Ok(buf)
    }

    /// ゲストメモリへバイト列を書く。
    fn put_bytes(&self, env: &mut BareEnv, addr: u64, data: &[u8]) -> Result<(), u64> {
        env.backend
            .mem
            .write(VirtAddr(addr), data)
            .map_err(|_| u64::from(superh::errno::EFAULT))
    }

    /// ゲストエンディアンで u32 を書く。
    fn put32(&self, env: &mut BareEnv, addr: u64, v: u32) -> Result<(), u64> {
        let b = match self.endian {
            Endian::Le => v.to_le_bytes(),
            Endian::Be => v.to_be_bytes(),
        };
        self.put_bytes(env, addr, &b)
    }

    /// ゲストエンディアンで u64 を書く。
    fn put64(&self, env: &mut BareEnv, addr: u64, v: u64) -> Result<(), u64> {
        let b = match self.endian {
            Endian::Le => v.to_le_bytes(),
            Endian::Be => v.to_be_bytes(),
        };
        self.put_bytes(env, addr, &b)
    }

    /// NUL 終端のゲスト文字列を読む。
    fn get_cstr(&self, env: &mut BareEnv, addr: u64) -> Result<String, u64> {
        let mut out = Vec::new();
        for i in 0..4096u64 {
            let b = self.get_bytes(env, addr + i, 1)?;
            if b[0] == 0 {
                return String::from_utf8(out).map_err(|_| u64::from(superh::errno::EINVAL));
            }
            out.push(b[0]);
        }
        Err(u64::from(superh::errno::ENAMETOOLONG))
    }

    /// `mprotect`。ゲストページの許可を張り替える。未写像ページが
    /// あれば ENOMEM（Linux の VMA ギャップと同等の失敗として返す）。
    fn sys_mprotect(
        &mut self,
        env: &mut BareEnv,
        addr: u64,
        len: u64,
        prot: u32,
    ) -> Result<u64, u64> {
        let lo = addr & !0xfff;
        let Some(end) = addr.checked_add(len) else {
            return Err(u64::from(superh::errno::EINVAL));
        };
        let hi = end.div_ceil(4096) * 4096;
        if hi <= lo {
            return Err(u64::from(superh::errno::EINVAL));
        }
        let mut p = 0u8;
        if prot & superh::mman::PROT_READ != 0 {
            p |= Perms::R.0;
        }
        if prot & superh::mman::PROT_WRITE != 0 {
            p |= Perms::W.0;
        }
        if prot & superh::mman::PROT_EXEC != 0 {
            p |= Perms::X.0;
        }
        match env
            .backend
            .mem
            .protect(VirtAddr(lo), (hi - lo) / 4096, Perms(p))
        {
            Ok(()) => Ok(0),
            Err(_) => Err(u64::from(superh::errno::ENOMEM)),
        }
    }

    /// `getrandom`。/dev/urandom を読み、開けなければ固定値で
    /// 埋める（エミュレーション環境の近似）。
    fn sys_getrandom(&mut self, env: &mut BareEnv, buf: u64, len: u64) -> Result<u64, u64> {
        let n = (len as usize).min(1 << 20);
        let mut data = vec![0u8; n];
        use std::io::Read as _;
        match std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut data)) {
            Ok(()) => {}
            Err(_) => {
                // 乱数源が無い環境では xorshift で埋める近似。
                let mut s = 0x2545_f491_4f6c_dd1du64;
                for b in &mut data {
                    s ^= s << 13;
                    s ^= s >> 7;
                    s ^= s << 17;
                    *b = s as u8;
                }
            }
        }
        self.put_bytes(env, buf, &data)?;
        Ok(n as u64)
    }

    /// `readlinkat`。`AT_FDCWD` と /proc/self/exe に限る近似。
    fn sys_readlinkat(
        &mut self,
        env: &mut BareEnv,
        dirfd: i64,
        path: u64,
        buf: u64,
        len: u64,
    ) -> Result<u64, u64> {
        const AT_FDCWD: i64 = -100;
        let target = if dirfd == AT_FDCWD {
            let p = self.get_cstr(env, path)?;
            if p == "/proc/self/exe" {
                self.exe_path.clone()
            } else {
                match std::fs::read_link(&p) {
                    Ok(t) => t.to_string_lossy().into_owned(),
                    Err(e) => {
                        return Err(host_errno(e.raw_os_error()));
                    }
                }
            }
        } else {
            return Err(u64::from(superh::errno::EBADF));
        };
        let n = target.len().min(len as usize);
        self.put_bytes(env, buf, &target.as_bytes()[..n])?;
        Ok(n as u64)
    }

    /// `brk`。0 は現ブレークを返し、それ以外は要求値を適用する
    /// （失敗しても現ブレークを返す — kernel の sys_brk と同じ）。
    /// 拡大分のページはここで RW に張る。
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

    /// `nr` を実行して R0 の値を返す。`Err(code)` は `-errno`。
    fn syscall(&mut self, env: &mut BareEnv, nr: u64, a: &[u64; 6]) -> Result<u64, u64> {
        match nr {
            superh::nr::WRITE => {
                let (fd, buf, len) = (a[0] as u32, a[1], a[2] as usize);
                let data = self.get_bytes(env, buf, len)?;
                if std::env::var_os("POLYISA_SUPERH_DEBUG").is_some() {
                    eprintln!(
                        "superh: write fd={fd} buf={buf:#x} len={len} data={:?}",
                        String::from_utf8_lossy(&data[..data.len().min(80)])
                    );
                }
                match fd {
                    1 => {
                        self.io.stdout.extend_from_slice(&data);
                        std::io::stdout().write_all(&data).ok();
                        Ok(len as u64)
                    }
                    2 => {
                        self.io.stderr.extend_from_slice(&data);
                        std::io::stderr().write_all(&data).ok();
                        Ok(len as u64)
                    }
                    _ => Err(u64::from(superh::errno::EBADF)),
                }
            }
            superh::nr::WRITEV => {
                let (fd, iov, cnt) = (a[0] as u32, a[1], a[2] as usize);
                let mut total = 0usize;
                let mut out = Vec::new();
                for i in 0..cnt {
                    let rec = self.get_bytes(env, iov + 8 * i as u64, 8)?;
                    let (b0, l0) = rec.split_at(4);
                    let base = self.u32_of(b0);
                    let len = self.u32_of(l0) as usize;
                    let bytes = self.get_bytes(env, u64::from(base), len)?;
                    out.extend_from_slice(&bytes);
                    total += bytes.len();
                }
                match fd {
                    1 => {
                        self.io.stdout.extend_from_slice(&out);
                        std::io::stdout().write_all(&out).ok();
                        Ok(total as u64)
                    }
                    2 => {
                        self.io.stderr.extend_from_slice(&out);
                        std::io::stderr().write_all(&out).ok();
                        Ok(total as u64)
                    }
                    _ => Err(u64::from(superh::errno::EBADF)),
                }
            }
            superh::nr::READ => {
                let (fd, buf, len) = (a[0] as u32, a[1], a[2] as usize);
                if fd != 0 {
                    return Err(u64::from(superh::errno::EBADF));
                }
                let avail = self.stdin_buf.len().saturating_sub(self.stdin_pos);
                let n = avail.min(len);
                if n > 0 {
                    let chunk = self.stdin_buf[self.stdin_pos..self.stdin_pos + n].to_vec();
                    env.backend
                        .mem
                        .write(VirtAddr(buf), &chunk)
                        .map_err(|_| u64::from(superh::errno::EFAULT))?;
                    self.stdin_pos += n;
                }
                Ok(n as u64)
            }
            superh::nr::BRK => {
                // kernel の sys_brk と同じく、失敗しても現ブレークを返す。
                Ok(self.sys_brk(env, a[0]))
            }
            superh::nr::UNAME => {
                if std::env::var_os("POLYISA_SUPERH_DEBUG").is_some() {
                    eprintln!("superh: uname buf={:#x}", a[0]);
                }
                // struct utsname: 6 個の 65 バイトフィールド。
                let fields = ["Linux", "polyisa", "6.1.0-polyisa", "#1", "sh4", "(none)"];
                for (i, f) in fields.iter().enumerate() {
                    let mut b = [0u8; 65];
                    b[..f.len()].copy_from_slice(f.as_bytes());
                    env.backend
                        .mem
                        .write(VirtAddr(a[0] + (i * 65) as u64), &b)
                        .map_err(|_| u64::from(superh::errno::EFAULT))?;
                }
                if std::env::var_os("POLYISA_SUPERH_DEBUG").is_some() {
                    let mut b = [0u8; 65 * 6];
                    let _ = self.get_bytes(env, a[0], 65 * 6);
                    let _ = env.backend.mem.read(
                        VirtAddr(a[0]),
                        &mut b,
                        Access {
                            endian: self.endian,
                            align: Align::Unaligned,
                            kind: AccessKind::DataRead,
                        },
                    );
                    for i in 0..6 {
                        eprintln!(
                            "superh: uname field{i} = {:?}",
                            String::from_utf8_lossy(&b[i * 65..i * 65 + 12])
                        );
                    }
                }
                Ok(0)
            }
            superh::nr::GETPID | superh::nr::GETTID => Ok(self.pid),
            superh::nr::GETPPID => Ok(1),
            superh::nr::GETUID32
            | superh::nr::GETGID32
            | superh::nr::GETEUID32
            | superh::nr::GETEGID32
            | superh::nr::GETUID
            | superh::nr::GETGID
            | superh::nr::GETEUID
            | superh::nr::GETEGID => Ok(0),
            superh::nr::SET_TID_ADDRESS => Ok(self.pid),
            superh::nr::SET_ROBUST_LIST => Ok(0),
            superh::nr::UGETRLIMIT => {
                // rlimit { u32 cur, u32 max }。RLIMIT_INFINITY 相当。
                self.put32(env, a[1], 0xffff_ffff)?;
                self.put32(env, a[1] + 4, 0xffff_ffff)?;
                Ok(0)
            }
            superh::nr::MPROTECT => self.sys_mprotect(env, a[0], a[1], a[2] as u32),
            superh::nr::GETRANDOM => self.sys_getrandom(env, a[0], a[1]),
            superh::nr::READLINKAT => {
                self.sys_readlinkat(env, a[0] as i32 as i64, a[1], a[2], a[3])
            }
            superh::nr::CLOCK_GETTIME => {
                // timespec { u32 sec, u32 nsec }。
                let (sec, nsec) = now_ns();
                self.put32(env, a[1], sec as u32)?;
                self.put32(env, a[1] + 4, nsec as u32)?;
                Ok(0)
            }
            superh::nr::CLOCK_GETTIME64 => {
                // __kernel_timespec { i64 sec, i64 nsec }。
                let (sec, nsec) = now_ns();
                self.put64(env, a[1], sec)?;
                self.put64(env, a[1] + 8, nsec)?;
                Ok(0)
            }
            _ => {
                if !self.reported.contains(&nr) {
                    self.reported.push(nr);
                    let name = superh::name(nr).unwrap_or("?");
                    eprintln!("superh: 未実装の syscall {nr} ({name}) — ENOSYS");
                }
                Err(u64::from(superh::errno::ENOSYS))
            }
        }
    }
}

impl TrapHandler for Linux {
    fn handle_trap(&mut self, env: &mut BareEnv, code: u32) -> TrapOutcome {
        // `trapa #0x10`-`#0x1f` が syscall 発行点。
        if !(superh::TRAPA_SYS_BASE..=superh::TRAPA_SYS_TOP).contains(&code) {
            return TrapOutcome::Unimplemented;
        }
        let r = |env: &mut BareEnv, i: u8| env.backend.get(sem::R(i).state());
        let nr = u64::from(r(env, 3));
        let a = [
            u64::from(r(env, 4)),
            u64::from(r(env, 5)),
            u64::from(r(env, 6)),
            u64::from(r(env, 7)),
            u64::from(r(env, 0)),
            u64::from(r(env, 1)),
        ];
        match nr {
            superh::nr::EXIT | superh::nr::EXIT_GROUP => TrapOutcome::Exit(a[0] as u32),
            _ => {
                let ret = match self.syscall(env, nr, &a) {
                    Ok(v) => v,
                    Err(e) => (0u64).wrapping_sub(e),
                };
                env.backend.set(sem::R(0).state(), ret as u32);
                TrapOutcome::Handled
            }
        }
    }

    fn init_brk(&mut self, image_end: u64) {
        let e = image_end.div_ceil(4096) * 4096;
        self.brk_start = e;
        self.heap_end = e;
    }
}

/// エポックからの (sec, nsec)。
fn now_ns() -> (u64, u64) {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    (d.as_secs(), u64::from(d.subsec_nanos()))
}

/// ホストの errno をゲスト errno に写す。SH の errno は
/// asm-generic でホスト Linux と同じ番号なので恒等写しでよい
/// （未知は EIO に畳む）。
fn host_errno(e: Option<i32>) -> u64 {
    let e = e.unwrap_or(superh::errno::EIO as i32);
    if e <= 0 || e > 133 {
        u64::from(superh::errno::EIO)
    } else {
        u64::from(e as u32)
    }
}
