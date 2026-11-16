// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! WASI preview1（`wasi_snapshot_preview1`）の ABI 定数と構造体配置。
//!
//! errno・filetype・open フラグ・rights の番号表と、iovec/prestat/fdstat/
//! filestat/dirent のバイト配置をここに集める。値はすべてリトルエンディアン
//! （wasm のメモリ表現と同じ）。条文・コードの複製はしない。
//! Ref: SPEC-WASI-P1 (wasi_snapshot_preview1).

#![allow(dead_code)]

/// errno 値。`errno` の順序は preview1 の宣言どおり。
pub mod errno {
    pub const SUCCESS: u16 = 0;
    pub const ACCES: u16 = 2;
    pub const AGAIN: u16 = 6;
    pub const BADF: u16 = 8;
    pub const BUSY: u16 = 10;
    pub const DQUOT: u16 = 19;
    pub const EXIST: u16 = 20;
    pub const FAULT: u16 = 21;
    pub const FBIG: u16 = 22;
    pub const INTR: u16 = 27;
    pub const INVAL: u16 = 28;
    pub const IO: u16 = 29;
    pub const ISDIR: u16 = 31;
    pub const LOOP: u16 = 32;
    pub const MFILE: u16 = 33;
    pub const MLINK: u16 = 34;
    pub const NAMETOOLONG: u16 = 37;
    pub const NFILE: u16 = 41;
    pub const NODEV: u16 = 43;
    pub const NOENT: u16 = 44;
    pub const NOMEM: u16 = 48;
    pub const NOSPC: u16 = 51;
    pub const NOSYS: u16 = 52;
    pub const NOTDIR: u16 = 54;
    pub const NOTEMPTY: u16 = 55;
    pub const NOTSOCK: u16 = 57;
    pub const NOTSUP: u16 = 58;
    pub const OVERFLOW: u16 = 61;
    pub const PERM: u16 = 63;
    pub const PIPE: u16 = 64;
    pub const RANGE: u16 = 68;
    pub const ROFS: u16 = 69;
    pub const SPIPE: u16 = 70;
    pub const STALE: u16 = 72;
    pub const TXTBSY: u16 = 74;
    pub const XDEV: u16 = 75;
    pub const NOTCAPABLE: u16 = 76;
}

/// `filetype` の値。
pub mod filetype {
    pub const UNKNOWN: u8 = 0;
    pub const BLOCK_DEVICE: u8 = 1;
    pub const CHARACTER_DEVICE: u8 = 2;
    pub const DIRECTORY: u8 = 3;
    pub const REGULAR_FILE: u8 = 4;
    pub const SOCKET_DGRAM: u8 = 5;
    pub const SOCKET_STREAM: u8 = 6;
    pub const SYMBOLIC_LINK: u8 = 7;
}

/// `clockid` の値。
pub mod clock {
    pub const REALTIME: u32 = 0;
    pub const MONOTONIC: u32 = 1;
    pub const PROCESS_CPUTIME: u32 = 2;
    pub const THREAD_CPUTIME: u32 = 3;
}

/// `fdflags`（fdstat / path_open の 16 ビット）。
pub mod fdflag {
    pub const APPEND: u16 = 1 << 0;
    pub const DSYNC: u16 = 1 << 1;
    pub const NONBLOCK: u16 = 1 << 2;
    pub const RSYNC: u16 = 1 << 3;
    pub const SYNC: u16 = 1 << 4;
}

/// `oflags`（path_open）。
pub mod oflag {
    pub const CREAT: u16 = 1 << 0;
    pub const DIRECTORY: u16 = 1 << 1;
    pub const EXCL: u16 = 1 << 2;
    pub const TRUNC: u16 = 1 << 3;
}

/// `lookupflags`（path_open の dirflags）。
pub mod lookup {
    pub const SYMLINK_FOLLOW: u16 = 1 << 0;
}

/// `rights` の代表ビット（fd 系と path 系の先頭部分）。
pub mod rights {
    pub const FD_DATASYNC: u64 = 1 << 0;
    pub const FD_READ: u64 = 1 << 1;
    pub const FD_SEEK: u64 = 1 << 2;
    pub const FD_FDSTAT_SET_FLAGS: u64 = 1 << 3;
    pub const FD_SYNC: u64 = 1 << 4;
    pub const FD_TELL: u64 = 1 << 5;
    pub const FD_WRITE: u64 = 1 << 6;
    pub const FD_ADVISE: u64 = 1 << 7;
    pub const FD_ALLOCATE: u64 = 1 << 8;
    pub const PATH_CREATE_DIRECTORY: u64 = 1 << 9;
    pub const PATH_CREATE_FILE: u64 = 1 << 10;
    pub const PATH_LINK_SOURCE: u64 = 1 << 11;
    pub const PATH_LINK_TARGET: u64 = 1 << 12;
    pub const PATH_OPEN: u64 = 1 << 13;
    pub const FD_READDIR: u64 = 1 << 14;
    pub const PATH_READLINK: u64 = 1 << 15;
    pub const PATH_REMOVE_DIRECTORY: u64 = 1 << 16;
    pub const PATH_RENAME_SOURCE: u64 = 1 << 17;
    pub const PATH_RENAME_TARGET: u64 = 1 << 18;
    pub const PATH_SYMLINK: u64 = 1 << 19;
    pub const PATH_UNLINK_FILE: u64 = 1 << 20;
    pub const PATH_FILESTAT_GET: u64 = 1 << 21;
    pub const PATH_FILESTAT_SET_SIZE: u64 = 1 << 22;
    pub const PATH_FILESTAT_SET_TIMES: u64 = 1 << 23;
    pub const FD_FILESTAT_GET: u64 = 1 << 24;
    pub const FD_FILESTAT_SET_SIZE: u64 = 1 << 25;
    pub const FD_FILESTAT_SET_TIMES: u64 = 1 << 26;
    pub const POLL_FD_READWRITE: u64 = 1 << 27;
    pub const SOCK_ACCEPT: u64 = 1 << 28;
    pub const SOCK_RECV: u64 = 1 << 29;
    pub const SOCK_SEND: u64 = 1 << 30;
    pub const SOCK_SHUTDOWN: u64 = 1 << 31;
    /// 通常ファイルに要求し得るフルセット（inheriting と同じ）。
    pub const FILE_ALL: u64 = (1 << 21) - 1;
}

/// `whence`（fd_seek）。
pub mod whence {
    pub const SET: u8 = 0;
    pub const CUR: u8 = 1;
    pub const END: u8 = 2;
}

/// iovec `{buf:u32, buf_len:u32}` のサイズ。
pub const IOVEC_SIZE: u32 = 8;
/// fdstat `{filetype:u8, flags:u16, rights_base:u64, rights_inh:u64}` のサイズ。
pub const FDSTAT_SIZE: u32 = 24;
/// filestat のサイズ。
pub const FILESTAT_SIZE: u32 = 64;
/// prestat `{tag:u8, dir.pr_name_len:u32}` のサイズ。
pub const PRESTAT_SIZE: u32 = 8;
/// dirent ヘッダ（名前を除く）のサイズ。
pub const DIRENT_HEAD: u32 = 24;

/// ゲストメモリへの書き込み口。`MemInst::write` を薄く包む。
pub struct Out<'a> {
    mem: &'a mut polyisa_guest_wasm::exec::MemInst,
}

impl<'a> Out<'a> {
    pub fn new(mem: &'a mut polyisa_guest_wasm::exec::MemInst) -> Self {
        Self { mem }
    }

    /// 失敗はすべて EFAULT。
    pub fn bytes(&mut self, addr: u32, data: &[u8]) -> Result<(), u16> {
        self.mem
            .write(u64::from(addr), data)
            .map_err(|_| errno::FAULT)
    }

    pub fn u8(&mut self, addr: u32, v: u8) -> Result<(), u16> {
        self.bytes(addr, &[v])
    }

    pub fn u16(&mut self, addr: u32, v: u16) -> Result<(), u16> {
        self.bytes(addr, &v.to_le_bytes())
    }

    pub fn u32(&mut self, addr: u32, v: u32) -> Result<(), u16> {
        self.bytes(addr, &v.to_le_bytes())
    }

    pub fn u64(&mut self, addr: u32, v: u64) -> Result<(), u16> {
        self.bytes(addr, &v.to_le_bytes())
    }
}

/// ゲストメモリからの読み出し口。
pub struct In<'a> {
    mem: &'a mut polyisa_guest_wasm::exec::MemInst,
}

impl<'a> In<'a> {
    pub fn new(mem: &'a mut polyisa_guest_wasm::exec::MemInst) -> Self {
        Self { mem }
    }

    pub fn bytes(&mut self, addr: u32, len: u32) -> Result<Vec<u8>, u16> {
        // 先に境界だけ検査してから確保する（大きな len で無駄確保しない）。
        if u64::from(addr) + u64::from(len) > self.mem.byte_len() {
            return Err(errno::FAULT);
        }
        let mut buf = vec![0u8; len as usize];
        self.mem
            .read(u64::from(addr), &mut buf)
            .map_err(|_| errno::FAULT)?;
        Ok(buf)
    }

    pub fn u32(&mut self, addr: u32) -> Result<u32, u16> {
        let b = self.bytes(addr, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// NUL まで、または `max` までのバイト列をパス文字として読む。
    /// preview1 のパス引数は長さ指定なので `max` をそのまま使う。
    pub fn path(&mut self, addr: u32, len: u32) -> Result<Vec<u8>, u16> {
        if len > (1 << 24) {
            return Err(errno::INVAL);
        }
        self.bytes(addr, len)
    }
}

/// ホストの `io::Error` を preview1 の errno に写す。
/// Unix の生 errno（Linux 値）を先に見て、取れなければ ErrorKind で落とす。
#[must_use]
pub fn errno_of(e: &std::io::Error) -> u16 {
    if let Some(raw) = e.raw_os_error() {
        return match raw {
            1 => errno::PERM,
            2 => errno::NOENT,
            4 => errno::INTR,
            5 => errno::IO,
            9 => errno::BADF,
            11 => errno::AGAIN,
            12 => errno::NOMEM,
            13 => errno::ACCES,
            14 => errno::FAULT,
            16 => errno::BUSY,
            17 => errno::EXIST,
            18 => errno::XDEV,
            19 => errno::NODEV,
            20 => errno::NOTDIR,
            21 => errno::ISDIR,
            22 => errno::INVAL,
            23 => errno::NFILE,
            24 => errno::MFILE,
            26 => errno::TXTBSY,
            27 => errno::FBIG,
            28 => errno::NOSPC,
            29 => errno::SPIPE,
            30 => errno::ROFS,
            31 => errno::MLINK,
            32 => errno::PIPE,
            36 => errno::NAMETOOLONG,
            38 => errno::NOSYS,
            39 => errno::NOTEMPTY,
            40 => errno::LOOP,
            75 => errno::OVERFLOW,
            88 => errno::NOTSOCK,
            116 => errno::STALE,
            122 => errno::DQUOT,
            _ => errno::IO,
        };
    }
    use std::io::ErrorKind as K;
    match e.kind() {
        K::NotFound => errno::NOENT,
        K::PermissionDenied => errno::ACCES,
        K::AlreadyExists => errno::EXIST,
        K::InvalidInput | K::InvalidData => errno::INVAL,
        K::Interrupted => errno::INTR,
        K::WouldBlock => errno::AGAIN,
        K::WriteZero | K::BrokenPipe => errno::PIPE,
        _ => errno::IO,
    }
}
