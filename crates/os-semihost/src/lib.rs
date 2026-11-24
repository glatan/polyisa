// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! semihosting パーソナリティ。
//!
//! ARM Semihosting（仕様 2.0、`SYS_*` 演算）をホスト入出力へ写す。
//! 入口は ISA ごとに異なり、このクレートは ISA 中立の演算本体
//! （`Semi::call`）と、 aarch64 / arm 用の `TrapHandler` 実装を
//! それぞれ `SemiA64`/`SemiA32` のラッパで持つ。
//! riscv の ebreak 入口は cli の `EcallHandler` 適合層が
//! `Semi::call` を呼ぶ（二系統の trap 経路は GAP-0024）。
//!
//! 意図的な簡略化（GAP-0090）:
//! - SYS_SYSTEM はホストのシェルへ渡さず常に失敗 (-1)。
//! - CLOCK/ELAPSED は時計なしの 0、TICKFREQ は 100 固定。
//! - `root` を与えるとファイル系演算のパスはその下に閉じ込める。

use polyisa_engine::bare::BareEnv;
use polyisa_mem::{Access, AccessKind, Align, Endian, VirtAddr};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};

/// `SYS_*` の演算番号（Semihosting 2.0）。
pub mod sysno {
    pub const OPEN: u32 = 0x01;
    pub const CLOSE: u32 = 0x02;
    pub const WRITEC: u32 = 0x03;
    pub const WRITE0: u32 = 0x04;
    pub const WRITE: u32 = 0x05;
    pub const READ: u32 = 0x06;
    pub const READC: u32 = 0x07;
    pub const ISERROR: u32 = 0x08;
    pub const ISTTY: u32 = 0x09;
    pub const SEEK: u32 = 0x0a;
    pub const FLEN: u32 = 0x0c;
    pub const TMPNAM: u32 = 0x0d;
    pub const REMOVE: u32 = 0x0e;
    pub const RENAME: u32 = 0x0f;
    pub const CLOCK: u32 = 0x10;
    pub const TIME: u32 = 0x11;
    pub const SYSTEM: u32 = 0x12;
    pub const ERRNO: u32 = 0x13;
    pub const GET_CMDLINE: u32 = 0x15;
    pub const HEAPINFO: u32 = 0x16;
    pub const EXIT: u32 = 0x18;
    pub const EXIT_EXTENDED: u32 = 0x20;
    pub const ELAPSED: u32 = 0x30;
    pub const TICKFREQ: u32 = 0x31;
}

/// 演算結果。
pub enum Reply {
    /// レジスタへ書き戻す値（符号付きで -1 もあり得る）。
    Ret(i64),
    /// プロセス終了（SYS_EXIT 系）。
    Exit(u64),
    /// 知らない演算。
    Unimpl,
}

/// stdio の capture と stdin 供給（テストが読む）。
#[derive(Default)]
pub struct SemiIo {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// `SYS_READ(0)`/`SYS_READC` に返す列。
    pub stdin: Vec<u8>,
    pub stdin_pos: usize,
}

/// パラメータブロックの語幅。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WordSize {
    /// AArch32・rv32 の 4 バイト語。
    W32,
    /// AArch64・rv64 の 8 バイト語。
    W64,
}

/// semihosting の状態機械。
// Gap: GAP-0090
pub struct Semi {
    /// 標準入出力の capture。
    pub io: SemiIo,
    /// SYS_OPEN が作った fd → ホストファイル。fd は 4 から採番。
    files: HashMap<u32, std::fs::File>,
    next_fd: u32,
    errno: i64,
    /// SYS_GET_CMDLINE が返すコマンド行（引数を空白連結）。
    cmdline: String,
    /// HEAPINFO が報告する境界（heap_base, heap_limit, stack_base,
    /// stack_limit）。実行系の側が設定する。
    pub heap_info: [u64; 4],
    tmpnam_id: u32,
    /// ファイル系演算のパスを閉じ込めるホストルート。空は制限なし。
    root: String,
    /// パラメータブロックの語の並び（AArch64 BE 対応）。
    endian: Endian,
    /// 一度だけ報告した未知演算。
    reported: Vec<u32>,
}

impl Default for Semi {
    fn default() -> Self {
        Self::new("")
    }
}

impl Semi {
    /// `root` はファイル系演算のパスを引くホスト側のルート
    /// （空なら閉じ込めなし）。
    #[must_use]
    pub fn new(root: &str) -> Self {
        Self {
            io: SemiIo::default(),
            files: HashMap::new(),
            next_fd: 4,
            errno: 0,
            cmdline: String::new(),
            heap_info: [0; 4],
            tmpnam_id: 0,
            root: root.to_string(),
            endian: Endian::Le,
            reported: Vec::new(),
        }
    }

    /// GET_CMDLINE に使うコマンド行を設定する。
    pub fn set_cmdline(&mut self, argv: &[String]) {
        self.cmdline = argv.join(" ");
    }

    /// ファイル系演算のパスを閉じ込めるルートを設定する。
    pub fn set_root(&mut self, root: &str) {
        self.root = root.to_string();
    }

    /// パラメータブロックの語の並びを設定する。
    pub fn set_endian(&mut self, endian: Endian) {
        self.endian = endian;
    }

    // ---- メモリアクセス ----

    fn acc(kind: AccessKind) -> Access {
        Access {
            endian: Endian::Le,
            align: Align::Unaligned,
            kind,
        }
    }

    fn r32(&self, env: &BareEnv, va: u64) -> Option<u32> {
        let mut b = [0u8; 4];
        env.backend
            .mem
            .read(VirtAddr(va), &mut b, Self::acc(AccessKind::DataRead))
            .ok()?;
        Some(match self.endian {
            Endian::Le => u32::from_le_bytes(b),
            Endian::Be => u32::from_be_bytes(b),
        })
    }

    fn r64(&self, env: &BareEnv, va: u64) -> Option<u64> {
        let mut b = [0u8; 8];
        env.backend
            .mem
            .read(VirtAddr(va), &mut b, Self::acc(AccessKind::DataRead))
            .ok()?;
        Some(match self.endian {
            Endian::Le => u64::from_le_bytes(b),
            Endian::Be => u64::from_be_bytes(b),
        })
    }

    fn w32(&self, env: &mut BareEnv, va: u64, v: u32) -> bool {
        let b = match self.endian {
            Endian::Le => v.to_le_bytes(),
            Endian::Be => v.to_be_bytes(),
        };
        env.backend.mem.write(VirtAddr(va), &b).is_ok()
    }

    fn w64(&self, env: &mut BareEnv, va: u64, v: u64) -> bool {
        let b = match self.endian {
            Endian::Le => v.to_le_bytes(),
            Endian::Be => v.to_be_bytes(),
        };
        env.backend.mem.write(VirtAddr(va), &b).is_ok()
    }

    /// 語幅 `ws` の語を読む。
    fn rw(&self, env: &BareEnv, va: u64, ws: WordSize) -> Option<u64> {
        match ws {
            WordSize::W32 => self.r32(env, va).map(u64::from),
            WordSize::W64 => self.r64(env, va),
        }
    }

    fn ww(&self, env: &mut BareEnv, va: u64, v: u64, ws: WordSize) -> bool {
        match ws {
            WordSize::W32 => self.w32(env, va, v as u32),
            WordSize::W64 => self.w64(env, va, v),
        }
    }

    /// `base` の語列から `n` 語を読む。失敗は None。
    fn block(&self, env: &BareEnv, base: u64, n: u64, ws: WordSize) -> Option<Vec<u64>> {
        let w = match ws {
            WordSize::W32 => 4,
            WordSize::W64 => 8,
        };
        (0..n).map(|i| self.rw(env, base + w * i, ws)).collect()
    }

    fn read_bytes(env: &BareEnv, va: u64, n: u64) -> Option<Vec<u8>> {
        let mut b = vec![0u8; usize::try_from(n).ok()?.min(1 << 20)];
        env.backend
            .mem
            .read(VirtAddr(va), &mut b, Self::acc(AccessKind::DataRead))
            .ok()?;
        Some(b)
    }

    fn write_bytes(env: &mut BareEnv, va: u64, b: &[u8]) -> bool {
        env.backend.mem.write(VirtAddr(va), b).is_ok()
    }

    /// `{ptr,len}` の文字列を読む。
    fn read_str(env: &BareEnv, ptr: u64, len: u64) -> Option<String> {
        let b = Self::read_bytes(env, ptr, len.min(4096))?;
        String::from_utf8(b).ok()
    }

    /// ゲストパスをホストパスへ。`root` 非空のときは
    /// `..` で上に抜けられない形に閉じ込める。
    fn resolve(&self, gpath: &str) -> Option<String> {
        if self.root.is_empty() {
            return Some(gpath.to_string());
        }
        let mut comps: Vec<&str> = Vec::new();
        for c in gpath.split('/') {
            match c {
                "" | "." => {}
                ".." => {
                    comps.pop()?;
                }
                c => comps.push(c),
            }
        }
        let mut p = self.root.trim_end_matches('/').to_string();
        p.push('/');
        p.push_str(&comps.join("/"));
        Some(p)
    }

    fn alloc_fd(&mut self) -> u32 {
        let fd = self.next_fd;
        self.next_fd += 1;
        fd
    }

    /// `SYS_*` 演算の本体。`op` は番号、`param` はレジスタの値
    /// （多くはパラメータブロックのアドレス、ISERROR・32 ビットの
    /// SYS_EXIT は値そのもの）、`ws` はブロックの語幅。
    pub fn call(&mut self, env: &mut BareEnv, op: u32, param: u64, ws: WordSize) -> Reply {
        self.errno = 0;
        let r = self.dispatch(env, op, param, ws);
        if let Reply::Unimpl = r
            && !self.reported.contains(&op)
        {
            self.reported.push(op);
            eprintln!("semihost: 未知の SYS_{op:#x}");
        }
        r
    }

    #[allow(clippy::too_many_lines)]
    fn dispatch(&mut self, env: &mut BareEnv, op: u32, param: u64, ws: WordSize) -> Reply {
        match op {
            sysno::OPEN => {
                let Some(b) = self.block(env, param, 3, ws) else {
                    return Reply::Ret(-1);
                };
                let Some(name) = Self::read_str(env, b[0], b[2]) else {
                    self.errno = 1;
                    return Reply::Ret(-1);
                };
                let Some(path) = self.resolve(&name) else {
                    self.errno = 1;
                    return Reply::Ret(-1);
                };
                // モード: 0-1=read、2-3=r+、4-5=w、6-7=w+、
                // 8-9=a、10-11=a+（b 変種は unix では同じ）。
                let mut o = std::fs::OpenOptions::new();
                match b[1] {
                    0 | 1 => {
                        o.read(true);
                    }
                    2 | 3 => {
                        o.read(true).write(true);
                    }
                    4 | 5 => {
                        o.write(true).create(true).truncate(true);
                    }
                    6 | 7 => {
                        o.read(true).write(true).create(true).truncate(true);
                    }
                    8 | 9 => {
                        o.write(true).create(true).append(true);
                    }
                    _ => {
                        o.read(true).write(true).create(true).append(true);
                    }
                }
                match o.open(&path) {
                    Ok(f) => {
                        let fd = self.alloc_fd();
                        self.files.insert(fd, f);
                        Reply::Ret(i64::from(fd))
                    }
                    Err(e) => {
                        self.errno = i64::from(e.raw_os_error().unwrap_or(1));
                        Reply::Ret(-1)
                    }
                }
            }
            sysno::CLOSE => {
                let Some(b) = self.block(env, param, 1, ws) else {
                    return Reply::Ret(-1);
                };
                if self.files.remove(&(b[0] as u32)).is_some() {
                    Reply::Ret(0)
                } else {
                    Reply::Ret(-1)
                }
            }
            sysno::WRITEC => {
                // param は書く文字のアドレス。
                let Some(b) = Self::read_bytes(env, param, 1) else {
                    return Reply::Ret(-1);
                };
                self.io.stderr.extend_from_slice(&b);
                let _ = std::io::stderr().write_all(&b);
                Reply::Ret(0)
            }
            sysno::WRITE0 => {
                // NUL 終端の文字列を stdout へ。
                let mut n = 0u64;
                let mut s = Vec::new();
                loop {
                    let Some(b) = Self::read_bytes(env, param + n, 1) else {
                        return Reply::Ret(-1);
                    };
                    if b[0] == 0 {
                        break;
                    }
                    s.push(b[0]);
                    n += 1;
                    if n > 1 << 20 {
                        return Reply::Ret(-1);
                    }
                }
                self.io.stdout.extend_from_slice(&s);
                let _ = std::io::stdout().write_all(&s);
                Reply::Ret(0)
            }
            sysno::WRITE => {
                let Some(b) = self.block(env, param, 3, ws) else {
                    return Reply::Ret(-1);
                };
                let Some(data) = Self::read_bytes(env, b[1], b[2]) else {
                    return Reply::Ret(-1);
                };
                // 戻りは「書けなかったバイト数」。
                let fd = b[0] as u32;
                if let Some(f) = self.files.get_mut(&fd) {
                    return match f.write_all(&data) {
                        Ok(()) => Reply::Ret(0),
                        Err(e) => {
                            self.errno = i64::from(e.raw_os_error().unwrap_or(1));
                            Reply::Ret(-1)
                        }
                    };
                }
                match fd {
                    1 => {
                        self.io.stdout.extend_from_slice(&data);
                        let _ = std::io::stdout().write_all(&data);
                        Reply::Ret(0)
                    }
                    2 => {
                        self.io.stderr.extend_from_slice(&data);
                        let _ = std::io::stderr().write_all(&data);
                        Reply::Ret(0)
                    }
                    _ => Reply::Ret(-1),
                }
            }
            sysno::READ => {
                let Some(b) = self.block(env, param, 3, ws) else {
                    return Reply::Ret(-1);
                };
                let fd = b[0] as u32;
                let want = usize::try_from(b[2]).unwrap_or(0);
                if let Some(f) = self.files.get_mut(&fd) {
                    let mut tmp = vec![0u8; want.min(1 << 20)];
                    return match f.read(&mut tmp) {
                        Ok(got) => {
                            if Self::write_bytes(env, b[1], &tmp[..got]) {
                                Reply::Ret(b[2] as i64 - got as i64)
                            } else {
                                Reply::Ret(-1)
                            }
                        }
                        Err(e) => {
                            self.errno = i64::from(e.raw_os_error().unwrap_or(1));
                            Reply::Ret(-1)
                        }
                    };
                }
                if fd != 0 {
                    return Reply::Ret(-1);
                }
                let rest = &self.io.stdin[self.io.stdin_pos.min(self.io.stdin.len())..];
                let got = rest.len().min(want);
                if !Self::write_bytes(env, b[1], &rest[..got]) {
                    return Reply::Ret(-1);
                }
                self.io.stdin_pos += got;
                Reply::Ret(b[2] as i64 - got as i64)
            }
            sysno::READC => {
                let rest = &self.io.stdin[self.io.stdin_pos.min(self.io.stdin.len())..];
                match rest.first() {
                    Some(&c) => {
                        self.io.stdin_pos += 1;
                        Reply::Ret(i64::from(c))
                    }
                    None => Reply::Ret(-1),
                }
            }
            sysno::ISERROR => Reply::Ret(i64::from((param as i64) < 0)),
            sysno::ISTTY => {
                let Some(b) = self.block(env, param, 1, ws) else {
                    return Reply::Ret(-1);
                };
                // 0-2 は端末（capture 先）、ファイルは端末でない。
                Reply::Ret(i64::from(b[0] <= 2))
            }
            sysno::SEEK => {
                let Some(b) = self.block(env, param, 2, ws) else {
                    return Reply::Ret(-1);
                };
                let Some(f) = self.files.get_mut(&(b[0] as u32)) else {
                    return Reply::Ret(-1);
                };
                match f.seek(SeekFrom::Start(b[1])) {
                    Ok(_) => Reply::Ret(0),
                    Err(e) => {
                        self.errno = i64::from(e.raw_os_error().unwrap_or(1));
                        Reply::Ret(-1)
                    }
                }
            }
            sysno::FLEN => {
                let Some(b) = self.block(env, param, 1, ws) else {
                    return Reply::Ret(-1);
                };
                match self
                    .files
                    .get(&(b[0] as u32))
                    .and_then(|f| f.metadata().ok())
                {
                    Some(m) => Reply::Ret(m.len() as i64),
                    None => Reply::Ret(-1),
                }
            }
            sysno::TMPNAM => {
                let Some(b) = self.block(env, param, 3, ws) else {
                    return Reply::Ret(-1);
                };
                self.tmpnam_id += 1;
                let name = format!(":tmp{:04x}", self.tmpnam_id - 1);
                let n = (name.len() + 1).min(b[2] as usize);
                let mut buf = name.into_bytes();
                buf.truncate(n.saturating_sub(1));
                buf.push(0);
                if Self::write_bytes(env, b[0], &buf) {
                    Reply::Ret(0)
                } else {
                    Reply::Ret(-1)
                }
            }
            sysno::REMOVE => {
                let Some(b) = self.block(env, param, 2, ws) else {
                    return Reply::Ret(-1);
                };
                let Some(name) = Self::read_str(env, b[0], b[1]) else {
                    return Reply::Ret(-1);
                };
                let Some(path) = self.resolve(&name) else {
                    return Reply::Ret(-1);
                };
                match std::fs::remove_file(&path) {
                    Ok(()) => Reply::Ret(0),
                    Err(e) => {
                        self.errno = i64::from(e.raw_os_error().unwrap_or(1));
                        Reply::Ret(-1)
                    }
                }
            }
            sysno::RENAME => {
                let Some(b) = self.block(env, param, 4, ws) else {
                    return Reply::Ret(-1);
                };
                let (Some(old), Some(new)) = (
                    Self::read_str(env, b[0], b[1]),
                    Self::read_str(env, b[2], b[3]),
                ) else {
                    return Reply::Ret(-1);
                };
                let (Some(old), Some(new)) = (self.resolve(&old), self.resolve(&new)) else {
                    return Reply::Ret(-1);
                };
                match std::fs::rename(&old, &new) {
                    Ok(()) => Reply::Ret(0),
                    Err(e) => {
                        self.errno = i64::from(e.raw_os_error().unwrap_or(1));
                        Reply::Ret(-1)
                    }
                }
            }
            sysno::CLOCK => Reply::Ret(0), // 時計なし
            sysno::TIME => {
                let t = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                Reply::Ret(t as i64)
            }
            // ホストのシェルは呼ばない（GAP-0090）。
            sysno::SYSTEM => Reply::Ret(-1),
            sysno::ERRNO => Reply::Ret(self.errno),
            sysno::GET_CMDLINE => {
                let Some(b) = self.block(env, param, 2, ws) else {
                    return Reply::Ret(-1);
                };
                let cap = b[1] as usize;
                if cap == 0 {
                    return Reply::Ret(-1);
                }
                let mut bytes = self.cmdline.clone().into_bytes();
                bytes.push(0);
                bytes.truncate(cap);
                if *bytes.last().unwrap() != 0 {
                    *bytes.last_mut().unwrap() = 0;
                }
                if !Self::write_bytes(env, b[0], &bytes) {
                    return Reply::Ret(-1);
                }
                // 実際に書いた長さ（NUL 込み）をブロックへ戻す。
                if !self.ww(env, param + ws as u64, bytes.len() as u64, ws) {
                    return Reply::Ret(-1);
                }
                Reply::Ret(0)
            }
            sysno::HEAPINFO => {
                let Some(b) = self.block(env, param, 1, ws) else {
                    return Reply::Ret(-1);
                };
                for (i, v) in self.heap_info.iter().enumerate() {
                    if !self.ww(env, b[0] + ws as u64 * i as u64, *v, ws) {
                        return Reply::Ret(-1);
                    }
                }
                Reply::Ret(0)
            }
            sysno::EXIT | sysno::EXIT_EXTENDED => {
                // 64 ビットの SYS_EXIT と EXIT_EXTENDED は
                // {reason, code} ブロック。32 ビットの SYS_EXIT は
                // param が reason そのもの（コードは 0）。
                let code = match (op, ws) {
                    (sysno::EXIT, WordSize::W32) => 0,
                    _ => self.block(env, param, 2, ws).map(|b| b[1]).unwrap_or(0),
                };
                Reply::Exit(code)
            }
            sysno::ELAPSED => {
                // {lo_ptr, hi_ptr} に経過 tick を書く。時計なしの 0。
                let Some(b) = self.block(env, param, 2, ws) else {
                    return Reply::Ret(-1);
                };
                if self.ww(env, b[0], 0, ws) && self.ww(env, b[1], 0, ws) {
                    Reply::Ret(0)
                } else {
                    Reply::Ret(-1)
                }
            }
            sysno::TICKFREQ => Reply::Ret(100),
            _ => Reply::Unimpl,
        }
    }
}

#[cfg(feature = "guest-arm")]
mod a32;
#[cfg(feature = "guest-aarch64")]
mod a64;

#[cfg(feature = "guest-arm")]
pub use a32::SemiA32;
#[cfg(feature = "guest-aarch64")]
pub use a64::SemiA64;
