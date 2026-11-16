// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! WASI preview1 のコンテキスト。fd 表・プリオープン・引数・環境・
//! 標準入出力・時計・乱数を保持し、各ホスト関数の実体を置く。
//!
//! fd 3 以降のスロット割当と `File` の保持は `polyisa_kernel::FdTable`
//! （os-linux と同じ基盤）を使い、用途の区別（ファイル/ディレクトリ/
//! プリオープン）だけをここで並行して持つ。パスの閉じ込めは字句的な
//! 正規化で行い、プリオープン根からの `..` 脱出は ENOTCAPABLE にする。
//! Ref: SPEC-WASI-P1 (wasi_snapshot_preview1).

use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Component, Path, PathBuf};

use polyisa_guest_wasm::exec::MemInst;
use polyisa_guest_wasm::types::Val;

use crate::abi::{self, In, Out, errno, filetype};

/// 標準入出力の capture。テストが読む（os-linux の `Aarch64Io` と同じ形）。
#[derive(Default)]
pub struct WasiIo {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// fd 3 以降のスロットの用途。
#[derive(Debug)]
enum FdKind {
    /// 通常ファイル。
    File {
        /// fdflags の APPEND。
        append: bool,
    },
    /// `path_open` で開いたディレクトリ。
    Dir {
        /// ホスト側の実パス。
        host: PathBuf,
    },
    /// プリオープン（起動時に割り当てるディレクトリ）。
    Preopen {
        /// ホスト側の実パス。
        host: PathBuf,
        /// ゲストに見せる名前（`fd_prestat_dir_name` が返す）。
        guest: String,
    },
}

/// preview1 の実行コンテキスト。ホスト関数はこれを `Rc<RefCell>` 越しに触る。
pub struct WasiCtx {
    /// `args_get` が返す argv。`args[0]` はプログラム名。
    pub args: Vec<String>,
    /// `environ_get` が返す `KEY=VALUE` 列。
    pub env: Vec<String>,
    /// 標準入力へ供給するバイト。
    pub stdin: Vec<u8>,
    stdin_pos: usize,
    /// 標準入出力の capture（`echo_stdio` に関わらず貯まる）。
    pub io: WasiIo,
    /// 真なら fd 1/2 への書き込みをホストの stdout/stderr にも流す。
    pub echo_stdio: bool,
    /// fd 3 以降のファイル実体とスロット割当（kernel::FdTable と共用）。
    fds: polyisa_kernel::FdTable,
    /// スロットの用途。配列添字は `fd - 3` で `fds.len()` と揃える。
    kinds: Vec<Option<FdKind>>,
    /// MONOTONIC 時計の起点。
    mono: std::time::Instant,
    /// `random_get` のフォールバック用の xorshift 状態。
    rng: u64,
}

impl Default for WasiCtx {
    fn default() -> Self {
        Self::new()
    }
}

impl WasiCtx {
    /// 空のコンテキスト。fd 0/1/2 は標準入出力として常に存在する。
    #[must_use]
    pub fn new() -> Self {
        Self {
            args: Vec::new(),
            env: Vec::new(),
            stdin: Vec::new(),
            stdin_pos: 0,
            io: WasiIo::default(),
            echo_stdio: true,
            fds: polyisa_kernel::FdTable::default(),
            kinds: Vec::new(),
            mono: std::time::Instant::now(),
            rng: seed_rng(),
        }
    }

    /// プリオープンを追加する。戻り値は割り当てたゲスト fd（3 以降）。
    /// `guest` は `fd_prestat_dir_name` が返す名前（普通 "/" か "."）。
    pub fn preopen(&mut self, guest: &str, host_dir: &str) -> u32 {
        let fd = self.alloc_kind_slot();
        self.kinds[usize::try_from(fd).unwrap() - 3] = Some(FdKind::Preopen {
            host: PathBuf::from(host_dir),
            guest: guest.to_string(),
        });
        fd
    }

    /// `File` を持たないスロット（Dir/Preopen）の割当。`fds` の穴探しは
    /// `Option<File>` しか見ないため、`kinds` 側も空きであることを
    /// `extra_free` で併せて確認する（Dir/Preopen スロットの再利用防止）。
    fn alloc_kind_slot(&mut self) -> u32 {
        let kinds = &self.kinds;
        let fd = self
            .fds
            .alloc_where(None, |i| kinds.get(i).is_none_or(|k| k.is_none()));
        self.grow_kinds();
        fd
    }

    fn grow_kinds(&mut self) {
        while self.kinds.len() < self.fds.len() {
            self.kinds.push(None);
        }
    }

    fn kind(&self, fd: u32) -> Option<&FdKind> {
        usize::try_from(fd)
            .ok()
            .and_then(|i| self.kinds.get(i.checked_sub(3)?))
            .and_then(|k| k.as_ref())
    }

    fn dir_host(&self, fd: u32) -> Option<&Path> {
        match self.kind(fd)? {
            FdKind::Dir { host } | FdKind::Preopen { host, .. } => Some(host),
            _ => None,
        }
    }

    /// `path` を `root` の内側に字句解決する。絶対パス・`..` の脱出は
    /// NOTCAPABLE（preview1 の preopen 越権）。シンボリックリンクの
    /// 中間要素追跡はしない（段階 12 の既知の隙。GAP 候補）。
    fn resolve_under(root: &Path, path: &[u8]) -> Result<PathBuf, u16> {
        let s = String::from_utf8_lossy(path);
        let rel = Path::new(s.as_ref());
        if rel.is_absolute() {
            return Err(errno::NOTCAPABLE);
        }
        let mut out = root.to_path_buf();
        let mut depth = 0usize;
        for c in rel.components() {
            match c {
                Component::Normal(p) => {
                    out.push(p);
                    depth += 1;
                }
                Component::CurDir => {}
                Component::ParentDir => {
                    if depth == 0 {
                        return Err(errno::NOTCAPABLE);
                    }
                    out.pop();
                    depth -= 1;
                }
                // RootDir は is_absolute で弾いた。Prefix は非 Unix のみ。
                _ => return Err(errno::NOTCAPABLE),
            }
        }
        Ok(out)
    }

    // -----------------------------------------------------------------------
    // args / environ
    // -----------------------------------------------------------------------

    /// `args_sizes_get(argc*, argv_buf_size*)`。
    fn args_sizes_get(&mut self, mem: &mut MemInst, argv: &[Val]) -> u16 {
        let mut o = Out::new(mem);
        let buf_size: u32 = self.args.iter().map(|a| a.len() as u32 + 1).sum();
        w2(&mut o, argv, |o, p| {
            o.u32(p[0], self.args.len() as u32)?;
            o.u32(p[1], buf_size)
        })
    }

    /// `args_get(argv**, argv_buf*)`。
    fn args_get(&mut self, mem: &mut MemInst, argv: &[Val]) -> u16 {
        let (ptrs, buf) = (a32(argv, 0), a32(argv, 1));
        let mut o = Out::new(mem);
        let mut cur = buf;
        for (i, a) in self.args.iter().enumerate() {
            if o.u32(ptrs + 4 * i as u32, cur).is_err() {
                return errno::FAULT;
            }
            if o.bytes(cur, a.as_bytes()).is_err() || o.u8(cur + a.len() as u32, 0).is_err() {
                return errno::FAULT;
            }
            cur += a.len() as u32 + 1;
        }
        errno::SUCCESS
    }

    /// `environ_sizes_get`。
    fn environ_sizes_get(&mut self, mem: &mut MemInst, argv: &[Val]) -> u16 {
        let mut o = Out::new(mem);
        let buf_size: u32 = self.env.iter().map(|e| e.len() as u32 + 1).sum();
        w2(&mut o, argv, |o, p| {
            o.u32(p[0], self.env.len() as u32)?;
            o.u32(p[1], buf_size)
        })
    }

    /// `environ_get`。
    fn environ_get(&mut self, mem: &mut MemInst, argv: &[Val]) -> u16 {
        let (ptrs, buf) = (a32(argv, 0), a32(argv, 1));
        let mut o = Out::new(mem);
        let mut cur = buf;
        for (i, e) in self.env.iter().enumerate() {
            if o.u32(ptrs + 4 * i as u32, cur).is_err() {
                return errno::FAULT;
            }
            if o.bytes(cur, e.as_bytes()).is_err() || o.u8(cur + e.len() as u32, 0).is_err() {
                return errno::FAULT;
            }
            cur += e.len() as u32 + 1;
        }
        errno::SUCCESS
    }

    // -----------------------------------------------------------------------
    // fd の読み書き
    // -----------------------------------------------------------------------

    /// iovec 列を読み出す。`(base, len)` を最大 1024 個。
    fn iovecs(mem: &mut MemInst, iovs: u32, cnt: u32) -> Result<Vec<(u32, u32)>, u16> {
        let mut out = Vec::new();
        let mut inp = In::new(mem);
        for i in 0..cnt.min(1024) {
            let base = inp.u32(iovs + i * abi::IOVEC_SIZE)?;
            let len = inp.u32(iovs + i * abi::IOVEC_SIZE + 4)?;
            out.push((base, len.min(1 << 24)));
        }
        Ok(out)
    }

    /// `fd_write(fd, iovs, iovs_len, nwritten*)`。
    fn fd_write(&mut self, mem: &mut MemInst, argv: &[Val]) -> u16 {
        let (fd, iovs, cnt, out) = (a32(argv, 0), a32(argv, 1), a32(argv, 2), a32(argv, 3));
        let ivs = match Self::iovecs(mem, iovs, cnt) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let mut total = 0u32;
        for (base, len) in ivs {
            let data = match In::new(mem).bytes(base, len) {
                Ok(d) => d,
                Err(e) => return e,
            };
            match self.write_one(fd, &data) {
                Ok(n) => {
                    total = total.saturating_add(n);
                    if n < len {
                        break;
                    }
                }
                Err(e) => return e,
            }
        }
        match Out::new(mem).u32(out, total) {
            Ok(()) => errno::SUCCESS,
            Err(e) => e,
        }
    }

    /// `fd` へ `data` を書く。
    fn write_one(&mut self, fd: u32, data: &[u8]) -> Result<u32, u16> {
        match fd {
            1 => {
                self.io.stdout.extend_from_slice(data);
                if self.echo_stdio {
                    let _ = std::io::stdout().write_all(data);
                }
                Ok(data.len() as u32)
            }
            2 => {
                self.io.stderr.extend_from_slice(data);
                if self.echo_stdio {
                    let _ = std::io::stderr().write_all(data);
                }
                Ok(data.len() as u32)
            }
            0 => Err(errno::BADF),
            _ => match self.kind(fd) {
                Some(FdKind::Dir { .. } | FdKind::Preopen { .. }) => Err(errno::BADF),
                Some(FdKind::File { append }) => {
                    let append = *append;
                    let f = self.fds.get_mut(fd).ok_or(errno::BADF)?;
                    if append {
                        let _ = f.seek(SeekFrom::End(0));
                    }
                    f.write_all(data)
                        .map(|()| data.len() as u32)
                        .map_err(|e| abi::errno_of(&e))
                }
                None => Err(errno::BADF),
            },
        }
    }

    /// `fd_read(fd, iovs, iovs_len, nread*)`。
    fn fd_read(&mut self, mem: &mut MemInst, argv: &[Val]) -> u16 {
        let (fd, iovs, cnt, out) = (a32(argv, 0), a32(argv, 1), a32(argv, 2), a32(argv, 3));
        let ivs = match Self::iovecs(mem, iovs, cnt) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let mut total = 0u32;
        for (base, len) in ivs {
            match self.read_one(mem, fd, base, len) {
                Ok(n) => {
                    total = total.saturating_add(n);
                    if n < len {
                        break;
                    }
                }
                Err(e) => return e,
            }
        }
        match Out::new(mem).u32(out, total) {
            Ok(()) => errno::SUCCESS,
            Err(e) => e,
        }
    }

    /// `fd` から最大 `len` バイト読み、ゲスト `base` に置く。
    fn read_one(&mut self, mem: &mut MemInst, fd: u32, base: u32, len: u32) -> Result<u32, u16> {
        let len = len as usize;
        match fd {
            0 => {
                let avail = self.stdin.len().saturating_sub(self.stdin_pos);
                let n = avail.min(len);
                let chunk = self.stdin[self.stdin_pos..self.stdin_pos + n].to_vec();
                self.stdin_pos += n;
                Out::new(mem).bytes(base, &chunk)?;
                Ok(n as u32)
            }
            1 | 2 => Err(errno::BADF),
            _ => match self.kind(fd) {
                Some(FdKind::Dir { .. } | FdKind::Preopen { .. }) => Err(errno::ISDIR),
                Some(FdKind::File { .. }) => {
                    let f = self.fds.get_mut(fd).ok_or(errno::BADF)?;
                    let mut buf = vec![0u8; len];
                    match f.read(&mut buf) {
                        Ok(n) => {
                            buf.truncate(n);
                            Out::new(mem).bytes(base, &buf)?;
                            Ok(n as u32)
                        }
                        Err(e) => Err(abi::errno_of(&e)),
                    }
                }
                None => Err(errno::BADF),
            },
        }
    }

    /// `fd_close`。
    fn fd_close(&mut self, _mem: &mut MemInst, argv: &[Val]) -> u16 {
        let fd = a32(argv, 0);
        if fd < 3 {
            return errno::BADF;
        }
        let i = fd as usize - 3;
        if self.kinds.get(i).is_none_or(|k| k.is_none()) && self.fds.get(fd).is_none() {
            return errno::BADF;
        }
        self.fds.clear(fd);
        if let Some(k) = self.kinds.get_mut(i) {
            *k = None;
        }
        errno::SUCCESS
    }

    /// `fd_seek(fd, offset:i64, whence:u8, newoffset*)`。
    fn fd_seek(&mut self, mem: &mut MemInst, argv: &[Val]) -> u16 {
        let (fd, off, wh, out) = (
            a32(argv, 0),
            a64(argv, 1) as i64,
            a32(argv, 2) as u8,
            a32(argv, 3),
        );
        match self.kind(fd) {
            Some(FdKind::Dir { .. } | FdKind::Preopen { .. }) => return errno::BADF,
            Some(FdKind::File { .. }) => {}
            None if fd < 3 => return errno::SPIPE,
            None => return errno::BADF,
        }
        let seek = match wh {
            abi::whence::SET => SeekFrom::Start(off as u64),
            abi::whence::CUR => SeekFrom::Current(off),
            abi::whence::END => SeekFrom::End(off),
            _ => return errno::INVAL,
        };
        let f = match self.fds.get_mut(fd) {
            Some(f) => f,
            None => return errno::BADF,
        };
        match f.seek(seek) {
            Ok(pos) => match Out::new(mem).u64(out, pos) {
                Ok(()) => errno::SUCCESS,
                Err(e) => e,
            },
            Err(e) => abi::errno_of(&e),
        }
    }

    /// `fd_tell(fd, newoffset*)`。
    fn fd_tell(&mut self, mem: &mut MemInst, argv: &[Val]) -> u16 {
        let (fd, out) = (a32(argv, 0), a32(argv, 1));
        match self.kind(fd) {
            Some(FdKind::File { .. }) => {}
            Some(_) => return errno::BADF,
            None => return if fd < 3 { errno::SPIPE } else { errno::BADF },
        }
        let f = match self.fds.get_mut(fd) {
            Some(f) => f,
            None => return errno::BADF,
        };
        match f.stream_position() {
            Ok(pos) => match Out::new(mem).u64(out, pos) {
                Ok(()) => errno::SUCCESS,
                Err(e) => e,
            },
            Err(e) => abi::errno_of(&e),
        }
    }

    // -----------------------------------------------------------------------
    // prestat / fdstat / filestat
    // -----------------------------------------------------------------------

    /// `fd_prestat_get(fd, prestat*)`。
    fn fd_prestat_get(&mut self, mem: &mut MemInst, argv: &[Val]) -> u16 {
        let (fd, ptr) = (a32(argv, 0), a32(argv, 1));
        let Some(FdKind::Preopen { guest, .. }) = self.kind(fd) else {
            return errno::BADF;
        };
        let mut o = Out::new(mem);
        if o.u8(ptr, 0).is_err() {
            return errno::FAULT;
        }
        match o.u32(ptr + 4, guest.len() as u32) {
            Ok(()) => errno::SUCCESS,
            Err(e) => e,
        }
    }

    /// `fd_prestat_dir_name(fd, path*, path_len)`。
    fn fd_prestat_dir_name(&mut self, mem: &mut MemInst, argv: &[Val]) -> u16 {
        let (fd, ptr, len) = (a32(argv, 0), a32(argv, 1), a32(argv, 2));
        let Some(FdKind::Preopen { guest, .. }) = self.kind(fd) else {
            return errno::BADF;
        };
        let n = (guest.len() as u32).min(len);
        match Out::new(mem).bytes(ptr, &guest.as_bytes()[..n as usize]) {
            Ok(()) => errno::SUCCESS,
            Err(e) => e,
        }
    }

    /// fd の filetype。
    fn filetype_of(&self, fd: u32) -> Option<u8> {
        Some(match fd {
            0..=2 => filetype::CHARACTER_DEVICE,
            _ => match self.kind(fd)? {
                FdKind::File { .. } => filetype::REGULAR_FILE,
                FdKind::Dir { .. } | FdKind::Preopen { .. } => filetype::DIRECTORY,
            },
        })
    }

    /// `fd_fdstat_get(fd, fdstat*)`。24 バイト配置。
    fn fd_fdstat_get(&mut self, mem: &mut MemInst, argv: &[Val]) -> u16 {
        let (fd, ptr) = (a32(argv, 0), a32(argv, 1));
        let Some(ft) = self.filetype_of(fd) else {
            return errno::BADF;
        };
        let flags = match self.kind(fd) {
            Some(FdKind::File { append: true }) => abi::fdflag::APPEND,
            _ => 0,
        };
        // rights はモードに応じた代表セットを返す（厳密な権限追跡はしない）。
        let (base, inh) = match fd {
            0 => (abi::rights::FD_READ | abi::rights::FD_FDSTAT_SET_FLAGS, 0),
            1 | 2 => (abi::rights::FD_WRITE | abi::rights::FD_FDSTAT_SET_FLAGS, 0),
            _ => (abi::rights::FILE_ALL, abi::rights::FILE_ALL),
        };
        let mut o = Out::new(mem);
        let w = (|| {
            o.u8(ptr, ft)?;
            o.u16(ptr + 2, flags)?;
            o.u64(ptr + 8, base)?;
            o.u64(ptr + 16, inh)
        })();
        match w {
            Ok(()) => errno::SUCCESS,
            Err(e) => e,
        }
    }

    /// `fd_filestat_get(fd, filestat*)`。64 バイト配置。
    fn fd_filestat_get(&mut self, mem: &mut MemInst, argv: &[Val]) -> u16 {
        let (fd, ptr) = (a32(argv, 0), a32(argv, 1));
        let Some(ft) = self.filetype_of(fd) else {
            return errno::BADF;
        };
        // メタデータが取れるなら size/ino を入れる。取れなければ 0。
        let md = match self.kind(fd) {
            Some(FdKind::File { .. }) => self.fds.get(fd).and_then(|f| f.metadata().ok()),
            Some(FdKind::Dir { host } | FdKind::Preopen { host, .. }) => {
                std::fs::metadata(host).ok()
            }
            None => None,
        };
        let mut o = Out::new(mem);
        let w = (|| {
            o.u64(ptr, 0)?; // dev
            o.u64(ptr + 8, 0)?; // ino（移植面では取れない。GAP 候補）
            o.u8(ptr + 16, ft)?;
            o.u64(ptr + 24, 1)?; // nlink
            o.u64(ptr + 32, md.as_ref().map_or(0, std::fs::Metadata::len))?;
            o.u64(ptr + 40, mtime_ns(md.as_ref(), std::fs::Metadata::accessed))?;
            o.u64(ptr + 48, mtime_ns(md.as_ref(), std::fs::Metadata::modified))?;
            o.u64(ptr + 56, mtime_ns(md.as_ref(), std::fs::Metadata::created))
        })();
        match w {
            Ok(()) => errno::SUCCESS,
            Err(e) => e,
        }
    }

    // -----------------------------------------------------------------------
    // path_open / fd_readdir
    // -----------------------------------------------------------------------

    /// `path_open(dirfd, dirflags, path*, path_len, oflags,
    ///             rights_base:i64, rights_inh:i64, fdflags, fd*)`。
    #[allow(clippy::too_many_arguments)]
    fn path_open(&mut self, mem: &mut MemInst, argv: &[Val]) -> u16 {
        let (dirfd, _dirflags, path_ptr, path_len, oflags, rbase, _rinh, fdflags, out) = (
            a32(argv, 0),
            a32(argv, 1),
            a32(argv, 2),
            a32(argv, 3),
            a32(argv, 4) as u16,
            a64(argv, 5),
            a64(argv, 6),
            a32(argv, 7) as u16,
            a32(argv, 8),
        );
        let Some(root) = self.dir_host(dirfd).map(Path::to_path_buf) else {
            return errno::BADF;
        };
        let path = match In::new(mem).path(path_ptr, path_len) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let host = match Self::resolve_under(&root, &path) {
            Ok(h) => h,
            Err(e) => return e,
        };
        let append = fdflags & abi::fdflag::APPEND != 0;
        let is_dir_req = oflags & abi::oflag::DIRECTORY != 0;
        if is_dir_req {
            // ディレクトリ指定。存在してディレクトリなら Dir スロットを開く。
            return match std::fs::metadata(&host) {
                Ok(md) if md.is_dir() => {
                    let fd = self.alloc_dir(host);
                    match Out::new(mem).u32(out, fd) {
                        Ok(()) => errno::SUCCESS,
                        Err(e) => e,
                    }
                }
                Ok(_) => errno::NOTDIR,
                Err(e) => abi::errno_of(&e),
            };
        }
        let md = match std::fs::symlink_metadata(&host) {
            Ok(m) => Some(m),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return abi::errno_of(&e),
        };
        if md.as_ref().is_some_and(|m| m.is_dir()) {
            // oflags なしでディレクトリを開くのは path_open でも認める
            // （wasi-libc の opendir が DIRECTORY 無しで来る実装がある）。
            let fd = self.alloc_dir(host);
            return match Out::new(mem).u32(out, fd) {
                Ok(()) => errno::SUCCESS,
                Err(e) => e,
            };
        }
        let read = rbase & abi::rights::FD_READ != 0 || rbase & abi::rights::FD_WRITE == 0;
        let write = rbase & abi::rights::FD_WRITE != 0 || append;
        let creat = oflags & abi::oflag::CREAT != 0;
        let mut oo = std::fs::OpenOptions::new();
        oo.read(read)
            .write(write || (oflags & abi::oflag::TRUNC != 0) || creat)
            .append(append)
            .truncate(oflags & abi::oflag::TRUNC != 0)
            .create(creat)
            .create_new(oflags & abi::oflag::EXCL != 0 && creat);
        let f = match oo.open(&host) {
            Ok(f) => f,
            Err(e) => return abi::errno_of(&e),
        };
        let fd = self.alloc_file(f, append);
        match Out::new(mem).u32(out, fd) {
            Ok(()) => errno::SUCCESS,
            Err(e) => e,
        }
    }

    fn alloc_file(&mut self, f: std::fs::File, append: bool) -> u32 {
        let kinds = &self.kinds;
        let fd = self
            .fds
            .alloc_where(Some(f), |i| kinds.get(i).is_none_or(|k| k.is_none()));
        self.grow_kinds();
        self.kinds[fd as usize - 3] = Some(FdKind::File { append });
        fd
    }

    fn alloc_dir(&mut self, host: PathBuf) -> u32 {
        let fd = self.alloc_kind_slot();
        self.kinds[fd as usize - 3] = Some(FdKind::Dir { host });
        fd
    }

    /// `fd_readdir(fd, buf*, buf_len, cookie:i64, bufused*)`。
    /// エントリは名前順に安定化し、"."、".." を先頭に置く。
    /// cookie は次に出すエントリの添字として解釈する。
    fn fd_readdir(&mut self, mem: &mut MemInst, argv: &[Val]) -> u16 {
        let (fd, buf, buf_len, cookie, used_ptr) = (
            a32(argv, 0),
            a32(argv, 1),
            a32(argv, 2),
            a64(argv, 3),
            a32(argv, 4),
        );
        let Some(dir) = self.dir_host(fd).map(Path::to_path_buf) else {
            return errno::BADF;
        };
        let mut entries: Vec<(String, u8)> = vec![
            (".".to_string(), filetype::DIRECTORY),
            ("..".to_string(), filetype::DIRECTORY),
        ];
        match std::fs::read_dir(&dir) {
            Ok(rd) => {
                for e in rd.flatten() {
                    let ft = e
                        .file_type()
                        .map(|t| {
                            if t.is_dir() {
                                filetype::DIRECTORY
                            } else if t.is_file() {
                                filetype::REGULAR_FILE
                            } else if t.is_symlink() {
                                filetype::SYMBOLIC_LINK
                            } else {
                                filetype::UNKNOWN
                            }
                        })
                        .unwrap_or(filetype::UNKNOWN);
                    entries.push((e.file_name().to_string_lossy().into_owned(), ft));
                }
            }
            Err(e) => return abi::errno_of(&e),
        }
        entries[2..].sort_by(|a, b| a.0.cmp(&b.0));
        let mut o = Out::new(mem);
        let mut pos = buf;
        let end = buf.saturating_add(buf_len);
        let mut idx = cookie;
        while let Some((name, ft)) = entries.get(usize::try_from(idx).unwrap_or(usize::MAX)) {
            let nb = name.as_bytes();
            let room = end.saturating_sub(pos) as usize;
            if room < abi::DIRENT_HEAD as usize {
                break;
            }
            let copy = nb.len().min(room - abi::DIRENT_HEAD as usize);
            let head = {
                let mut h = [0u8; 24];
                h[0..8].copy_from_slice(&(idx + 1).to_le_bytes()); // d_next
                // d_ino（8..16）は移植面で取れないため 0。
                h[16..20].copy_from_slice(&(nb.len() as u32).to_le_bytes()); // d_namlen
                h[20] = *ft;
                h
            };
            if o.bytes(pos, &head).is_err() {
                return errno::FAULT;
            }
            if o.bytes(pos + abi::DIRENT_HEAD, &nb[..copy]).is_err() {
                return errno::FAULT;
            }
            if copy < nb.len() {
                // 名前がはみ出した。bufused は末尾まで（部分返し）。
                pos = end;
                break;
            }
            pos += abi::DIRENT_HEAD + nb.len() as u32;
            idx += 1;
        }
        match o.u32(used_ptr, pos - buf) {
            Ok(()) => errno::SUCCESS,
            Err(e) => e,
        }
    }

    // -----------------------------------------------------------------------
    // clock / random
    // -----------------------------------------------------------------------

    /// `clock_time_get(id, precision:i64, time*)`。ナノ秒。
    fn clock_time_get(&mut self, mem: &mut MemInst, argv: &[Val]) -> u16 {
        let (id, _prec, ptr) = (a32(argv, 0), a64(argv, 1), a32(argv, 2));
        let ns = match id {
            abi::clock::REALTIME => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0),
            abi::clock::MONOTONIC | abi::clock::PROCESS_CPUTIME | abi::clock::THREAD_CPUTIME => {
                // CPU 時計は専用の時間源がないため MONOTONIC で代用する。
                self.mono.elapsed().as_nanos() as u64
            }
            _ => return errno::INVAL,
        };
        match Out::new(mem).u64(ptr, ns) {
            Ok(()) => errno::SUCCESS,
            Err(e) => e,
        }
    }

    /// `random_get(buf*, buf_len)`。`/dev/urandom` をまず試し、
    /// 開けない環境ではコンテキストの xorshift で埋める。
    fn random_get(&mut self, mem: &mut MemInst, argv: &[Val]) -> u16 {
        let (ptr, len) = (a32(argv, 0), a32(argv, 1));
        let len = len.min(1 << 24) as usize;
        let mut buf = vec![0u8; len];
        let filled = std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut buf))
            .is_ok();
        if !filled {
            for b in &mut buf {
                *b = self.next_rand() as u8;
            }
        }
        match Out::new(mem).bytes(ptr, &buf) {
            Ok(()) => errno::SUCCESS,
            Err(e) => e,
        }
    }

    fn next_rand(&mut self) -> u64 {
        // xorshift64*。セキュリティ用途ではなくフォールバック。
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    // -----------------------------------------------------------------------
    // ディスパッチ
    // -----------------------------------------------------------------------

    /// `name` の preview1 関数を呼ぶ。戻りは errno（proc_exit など
    /// 値を返さないものは `Vec::new`）。未知名は `None` を返し、
    /// 呼び出し側が ENOSYS スタブに落とす。
    pub fn call(
        &mut self,
        name: &str,
        mem: &mut MemInst,
        argv: &[Val],
    ) -> Option<Result<Vec<Val>, u16>> {
        let e = match name {
            "args_sizes_get" => self.args_sizes_get(mem, argv),
            "args_get" => self.args_get(mem, argv),
            "environ_sizes_get" => self.environ_sizes_get(mem, argv),
            "environ_get" => self.environ_get(mem, argv),
            "fd_write" => self.fd_write(mem, argv),
            "fd_read" => self.fd_read(mem, argv),
            "fd_close" => self.fd_close(mem, argv),
            "fd_seek" => self.fd_seek(mem, argv),
            "fd_tell" => self.fd_tell(mem, argv),
            "fd_prestat_get" => self.fd_prestat_get(mem, argv),
            "fd_prestat_dir_name" => self.fd_prestat_dir_name(mem, argv),
            "fd_fdstat_get" => self.fd_fdstat_get(mem, argv),
            "fd_filestat_get" => self.fd_filestat_get(mem, argv),
            "path_open" => self.path_open(mem, argv),
            "fd_readdir" => self.fd_readdir(mem, argv),
            "clock_time_get" => self.clock_time_get(mem, argv),
            "random_get" => self.random_get(mem, argv),
            _ => return None,
        };
        Some(if e == errno::SUCCESS {
            Ok(vec![Val::I32(0)])
        } else {
            Ok(vec![Val::I32(u32::from(e))])
        })
    }
}

// `proc_exit` は Trap で運ぶ（`call` の外で扱う）。

fn mtime_ns(
    md: Option<&std::fs::Metadata>,
    f: impl Fn(&std::fs::Metadata) -> std::io::Result<std::time::SystemTime>,
) -> u64 {
    md.and_then(|m| f(m).ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// 引数の i32。
fn a32(argv: &[Val], i: usize) -> u32 {
    argv.get(i).map_or(0, Val::as_i32)
}

/// 引数の i64。
fn a64(argv: &[Val], i: usize) -> u64 {
    match argv.get(i) {
        Some(Val::I64(v)) => *v,
        Some(Val::I32(v)) => u64::from(*v),
        _ => 0,
    }
}

/// 2 個の u32 出力を書く sizes_get 系の共通形。
fn w2(
    o: &mut Out<'_>,
    argv: &[Val],
    f: impl FnOnce(&mut Out<'_>, &[u32; 2]) -> Result<(), u16>,
) -> u16 {
    let p = [a32(argv, 0), a32(argv, 1)];
    match f(o, &p) {
        Ok(()) => errno::SUCCESS,
        Err(e) => e,
    }
}

fn seed_rng() -> u64 {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9e37_79b9_7f4a_7c15);
    t ^ (u64::from(std::process::id()) << 32) | 1
}

#[cfg(test)]
mod tests {
    //! `WasiCtx::call` 経由の preview1 関数の単体試験。`MemInst` を
    //! 直接組み立てて errno とゲストメモリ上の結果を検査する。
    //! Ref: SPEC-WASI-P1 (wasi_snapshot_preview1).

    use super::*;
    use polyisa_guest_wasm::types::{Limits, MemType};

    /// 1 ページのメモリを作る。
    fn mem() -> MemInst {
        MemInst::new(MemType {
            lim: Limits { min: 1, max: None },
        })
    }

    fn quiet() -> WasiCtx {
        let mut c = WasiCtx::new();
        c.echo_stdio = false;
        c
    }

    /// errno だけを取り出す `call` の薄い包み。
    fn call(ctx: &mut WasiCtx, mem: &mut MemInst, name: &str, argv: &[Val]) -> u16 {
        match ctx.call(name, mem, argv) {
            Some(Ok(v)) => v.first().map_or(u16::MAX, |x| x.as_i32() as u16),
            Some(Err(e)) => e,
            None => u16::MAX,
        }
    }

    fn i32v(v: u32) -> Val {
        Val::I32(v)
    }

    fn ru32(mem: &mut MemInst, addr: u32) -> u32 {
        let mut b = [0u8; 4];
        mem.read(u64::from(addr), &mut b).unwrap();
        u32::from_le_bytes(b)
    }

    fn ru64(mem: &mut MemInst, addr: u32) -> u64 {
        let mut b = [0u8; 8];
        mem.read(u64::from(addr), &mut b).unwrap();
        u64::from_le_bytes(b)
    }

    fn rbytes(mem: &mut MemInst, addr: u32, n: u32) -> Vec<u8> {
        let mut b = vec![0u8; n as usize];
        mem.read(u64::from(addr), &mut b).unwrap();
        b
    }

    #[test]
    fn args_round_trip() {
        let mut ctx = quiet();
        ctx.args = vec!["prog".into(), "x".into(), "yz".into()];
        let mut m = mem();
        // sizes: argc=3, buf = 5+2+3 = 10。
        assert_eq!(
            call(&mut ctx, &mut m, "args_sizes_get", &[i32v(0), i32v(4)]),
            errno::SUCCESS
        );
        assert_eq!(ru32(&mut m, 0), 3);
        assert_eq!(ru32(&mut m, 4), 10);
        // ポインタ表を 16、文字列を 256 に書かせる。
        assert_eq!(
            call(&mut ctx, &mut m, "args_get", &[i32v(16), i32v(256)]),
            errno::SUCCESS
        );
        let p0 = ru32(&mut m, 16);
        let p1 = ru32(&mut m, 20);
        let p2 = ru32(&mut m, 24);
        assert_eq!((p0, p1, p2), (256, 261, 263));
        assert_eq!(rbytes(&mut m, p0, 5), b"prog\0");
        assert_eq!(rbytes(&mut m, p1, 2), b"x\0");
        assert_eq!(rbytes(&mut m, p2, 3), b"yz\0");
    }

    #[test]
    fn environ_round_trip() {
        let mut ctx = quiet();
        ctx.env = vec!["A=1".into(), "BB=cd".into()];
        let mut m = mem();
        assert_eq!(
            call(&mut ctx, &mut m, "environ_sizes_get", &[i32v(0), i32v(4)]),
            errno::SUCCESS
        );
        assert_eq!(ru32(&mut m, 0), 2);
        assert_eq!(ru32(&mut m, 4), 10);
        assert_eq!(
            call(&mut ctx, &mut m, "environ_get", &[i32v(16), i32v(256)]),
            errno::SUCCESS
        );
        let p0 = ru32(&mut m, 16);
        assert_eq!(rbytes(&mut m, p0, 4), b"A=1\0");
    }

    #[test]
    fn fd_write_captures_stdout() {
        let mut ctx = quiet();
        let mut m = mem();
        m.write(64, b"hi\n").unwrap();
        // iovec {buf=64, len=3} at 0。
        m.write(0, &64u32.to_le_bytes()).unwrap();
        m.write(4, &3u32.to_le_bytes()).unwrap();
        assert_eq!(
            call(
                &mut ctx,
                &mut m,
                "fd_write",
                &[i32v(1), i32v(0), i32v(1), i32v(8)]
            ),
            errno::SUCCESS
        );
        assert_eq!(ru32(&mut m, 8), 3);
        assert_eq!(ctx.io.stdout, b"hi\n");
    }

    #[test]
    fn fd_write_and_read_bad_fds() {
        let mut ctx = quiet();
        let mut m = mem();
        m.write(0, &64u32.to_le_bytes()).unwrap();
        m.write(4, &1u32.to_le_bytes()).unwrap();
        let args = [i32v(0), i32v(0), i32v(1), i32v(8)];
        assert_eq!(call(&mut ctx, &mut m, "fd_write", &args), errno::BADF);
        let args = [i32v(9), i32v(0), i32v(1), i32v(8)];
        assert_eq!(call(&mut ctx, &mut m, "fd_write", &args), errno::BADF);
        assert_eq!(call(&mut ctx, &mut m, "fd_read", &args), errno::BADF);
    }

    #[test]
    fn fd_read_stdin() {
        let mut ctx = quiet();
        ctx.stdin = b"abc".to_vec();
        let mut m = mem();
        m.write(0, &256u32.to_le_bytes()).unwrap();
        m.write(4, &2u32.to_le_bytes()).unwrap();
        assert_eq!(
            call(
                &mut ctx,
                &mut m,
                "fd_read",
                &[i32v(0), i32v(0), i32v(1), i32v(8)]
            ),
            errno::SUCCESS
        );
        assert_eq!(ru32(&mut m, 8), 2);
        assert_eq!(rbytes(&mut m, 256, 2), b"ab");
        // 残りの 1 バイトだけ読める。
        assert_eq!(
            call(
                &mut ctx,
                &mut m,
                "fd_read",
                &[i32v(0), i32v(0), i32v(1), i32v(8)]
            ),
            errno::SUCCESS
        );
        assert_eq!(ru32(&mut m, 8), 1);
        assert_eq!(rbytes(&mut m, 256, 1), b"c");
    }

    #[test]
    fn fd_close_and_stdio_rules() {
        let mut ctx = quiet();
        let mut m = mem();
        // fd 0-2 は閉じられない、fd 3 は未割当で BADF。
        assert_eq!(call(&mut ctx, &mut m, "fd_close", &[i32v(1)]), errno::BADF);
        assert_eq!(call(&mut ctx, &mut m, "fd_close", &[i32v(3)]), errno::BADF);
        // fd_seek/fd_tell は std fd で SPIPE、未知 fd で BADF。
        let se = [i32v(1), Val::I64(0), i32v(0), i32v(8)];
        assert_eq!(call(&mut ctx, &mut m, "fd_seek", &se), errno::SPIPE);
        let se = [i32v(9), Val::I64(0), i32v(0), i32v(8)];
        assert_eq!(call(&mut ctx, &mut m, "fd_seek", &se), errno::BADF);
        assert_eq!(
            call(&mut ctx, &mut m, "fd_tell", &[i32v(2), i32v(8)]),
            errno::SPIPE
        );
    }

    #[test]
    fn prestat_and_fdstat() {
        let mut ctx = quiet();
        let dir = std::env::temp_dir().join(format!("polyisa-wasi-{}", std::process::id()));
        let fd = ctx.preopen("/", dir.to_str().unwrap());
        assert_eq!(fd, 3);
        let mut m = mem();
        assert_eq!(
            call(&mut ctx, &mut m, "fd_prestat_get", &[i32v(3), i32v(8)]),
            errno::SUCCESS
        );
        assert_eq!(rbytes(&mut m, 8, 1)[0], 0); // PREOPENTYPE_DIR
        assert_eq!(ru32(&mut m, 12), 1); // "/" の長さ
        assert_eq!(
            call(
                &mut ctx,
                &mut m,
                "fd_prestat_dir_name",
                &[i32v(3), i32v(16), i32v(1)]
            ),
            errno::SUCCESS
        );
        assert_eq!(rbytes(&mut m, 16, 1), b"/");
        // 非プリオープンには BADF。
        assert_eq!(
            call(&mut ctx, &mut m, "fd_prestat_get", &[i32v(1), i32v(8)]),
            errno::BADF
        );
        // fdstat: preopen は DIRECTORY、stdout は CHARACTER_DEVICE。
        assert_eq!(
            call(&mut ctx, &mut m, "fd_fdstat_get", &[i32v(3), i32v(24)]),
            errno::SUCCESS
        );
        assert_eq!(rbytes(&mut m, 24, 1)[0], filetype::DIRECTORY);
        assert_eq!(
            call(&mut ctx, &mut m, "fd_fdstat_get", &[i32v(1), i32v(24)]),
            errno::SUCCESS
        );
        assert_eq!(rbytes(&mut m, 24, 1)[0], filetype::CHARACTER_DEVICE);
    }

    #[test]
    fn path_open_seek_tell_and_escape() {
        let dir = std::env::temp_dir().join(format!("polyisa-wasi-path-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("f.txt"), "contents").unwrap();
        let mut ctx = quiet();
        ctx.preopen("/", dir.to_str().unwrap());
        let mut m = mem();
        // "f.txt" を 256 に書き、fd を 2048 に受け取る。
        m.write(256, b"f.txt").unwrap();
        // rights_base = FD_READ|FD_SEEK|FD_TELL = 0x26。
        let po = [
            i32v(3),
            i32v(0),
            i32v(256),
            i32v(5),
            i32v(0),
            Val::I64(0x26),
            Val::I64(0),
            i32v(0),
            i32v(2048),
        ];
        assert_eq!(call(&mut ctx, &mut m, "path_open", &po), errno::SUCCESS);
        let fd = ru32(&mut m, 2048);
        assert_eq!(fd, 4);
        // fd_tell=0 → seek END → tell=8。
        assert_eq!(
            call(&mut ctx, &mut m, "fd_tell", &[i32v(fd), i32v(2060)]),
            errno::SUCCESS
        );
        assert_eq!(ru64(&mut m, 2060), 0);
        let se = [
            i32v(fd),
            Val::I64(0),
            i32v(abi::whence::END as u32),
            i32v(2060),
        ];
        assert_eq!(call(&mut ctx, &mut m, "fd_seek", &se), errno::SUCCESS);
        assert_eq!(ru64(&mut m, 2060), 8);
        // プリオープンの外への `..` 脱出は NOTCAPABLE。
        m.write(256, b"../outside").unwrap();
        let po = [
            i32v(3),
            i32v(0),
            i32v(256),
            i32v(10),
            i32v(0),
            Val::I64(0),
            Val::I64(0),
            i32v(0),
            i32v(2048),
        ];
        assert_eq!(call(&mut ctx, &mut m, "path_open", &po), errno::NOTCAPABLE);
        // 絶対パスも NOTCAPABLE。
        m.write(256, b"/etc/passwd").unwrap();
        let po = [
            i32v(3),
            i32v(0),
            i32v(256),
            i32v(11),
            i32v(0),
            Val::I64(0),
            Val::I64(0),
            i32v(0),
            i32v(2048),
        ];
        assert_eq!(call(&mut ctx, &mut m, "path_open", &po), errno::NOTCAPABLE);
        // fd_close で解放してもう一度閉じると BADF。
        assert_eq!(
            call(&mut ctx, &mut m, "fd_close", &[i32v(fd)]),
            errno::SUCCESS
        );
        assert_eq!(call(&mut ctx, &mut m, "fd_close", &[i32v(fd)]), errno::BADF);
    }

    #[test]
    fn filestat_and_readdir() {
        let dir = std::env::temp_dir().join(format!("polyisa-wasi-rd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("b.txt"), "bb").unwrap();
        std::fs::write(dir.join("a.txt"), "a").unwrap();
        let mut ctx = quiet();
        ctx.preopen("/", dir.to_str().unwrap());
        let mut m = mem();
        // プリオープン fd=3 の filestat は DIRECTORY。
        assert_eq!(
            call(&mut ctx, &mut m, "fd_filestat_get", &[i32v(3), i32v(64)]),
            errno::SUCCESS
        );
        assert_eq!(rbytes(&mut m, 80, 1)[0], filetype::DIRECTORY);
        // readdir: "."、".." の後に名前順 a.txt、b.txt。
        assert_eq!(
            call(
                &mut ctx,
                &mut m,
                "fd_readdir",
                &[i32v(3), i32v(1024), i32v(1024), Val::I64(0), i32v(8)]
            ),
            errno::SUCCESS
        );
        let used = ru32(&mut m, 8);
        // 4 エントリ分のヘッダ + 名前（可変長: head + namlen）。
        assert_eq!(used, 4 * abi::DIRENT_HEAD + 1 + 2 + 5 + 5);
        // 3 番目のエントリは a.txt（"."、".." の後、名前順で安定）。
        // 先頭 2 件の幅は (24+1)+(24+2) = 51。
        let third = 1024 + abi::DIRENT_HEAD + 1 + abi::DIRENT_HEAD + 2;
        // d_type はヘッダの +20。
        assert_eq!(rbytes(&mut m, third + 20, 1)[0], filetype::REGULAR_FILE);
        let mut nb = [0u8; 5];
        m.read(u64::from(third + abi::DIRENT_HEAD), &mut nb)
            .unwrap();
        assert_eq!(&nb, b"a.txt");
    }

    #[test]
    fn clock_and_random() {
        let mut ctx = quiet();
        let mut m = mem();
        // REALTIME と MONOTONIC は SUCCESS で非ゼロ。
        for id in [0u32, 1] {
            assert_eq!(
                call(
                    &mut ctx,
                    &mut m,
                    "clock_time_get",
                    &[i32v(id), Val::I64(0), i32v(8)]
                ),
                errno::SUCCESS
            );
            assert_ne!(ru64(&mut m, 8), 0);
        }
        // 未知の clockid は INVAL。
        assert_eq!(
            call(
                &mut ctx,
                &mut m,
                "clock_time_get",
                &[i32v(9), Val::I64(0), i32v(8)]
            ),
            errno::INVAL
        );
        // random_get はバッファを埋める（全ゼロのままではない）。
        assert_eq!(
            call(&mut ctx, &mut m, "random_get", &[i32v(256), i32v(32)]),
            errno::SUCCESS
        );
        assert!(rbytes(&mut m, 256, 32).iter().any(|b| *b != 0));
    }

    #[test]
    fn unknown_name_returns_none() {
        let mut ctx = quiet();
        let mut m = mem();
        assert!(ctx.call("fd_advise", &mut m, &[]).is_none());
        assert!(ctx.call("nonesuch", &mut m, &[]).is_none());
    }
}
