// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! ホスト依存の機能。標準ライブラリにないものだけを自前の FFI で補う。
//!
//! FFI 宣言は後の段階で足す。ここでは OS 非依存の問い合わせだけを提供する。

// unsafe 許可クレート（docs/design/workspace.md「`unsafe` の扱い」）。
// 自前の FFI 宣言を呼ぶため。
#![allow(unsafe_code)]

pub mod exec_mem;

/// 利用可能な並列数。作業スレッドの数の目安に使う。
#[must_use]
pub fn parallelism() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// シンボリックリンクを作る。`ln -s` の仮想カーネル実装が使う。
/// 可搬な std には作成 API がないためホスト依存としてここに置く。
#[cfg(unix)]
pub fn symlink(old: &str, new: &str) -> std::io::Result<()> {
    std::os::unix::fs::symlink(old, new)
}

/// 非 Unix ホストでは未対応の旨を返す。
#[cfg(not(unix))]
pub fn symlink(_old: &str, _new: &str) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "symlink is not supported on this host",
    ))
}

/// パスの許可ビットを変える（chmod）。ゲストの chmod 系実装が使う。
/// 非 Unix ホストでは成功だけ返す。
#[cfg(unix)]
pub fn chmod(path: &str, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// 非 Unix ホストでは成功だけ返す。
#[cfg(not(unix))]
pub fn chmod(_path: &str, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

/// 開いたファイルの許可ビットを変える。`O_CREAT` で作ったファイルへ
/// mode を適用する用途で、非 Unix ホストでは成功だけ返す。
#[cfg(unix)]
pub fn fchmod(f: &std::fs::File, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    f.set_permissions(std::fs::Permissions::from_mode(mode))
}

/// 非 Unix ホストでは成功だけ返す。
#[cfg(not(unix))]
pub fn fchmod(_f: &std::fs::File, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_least_one() {
        assert!(parallelism() >= 1);
    }
}

/// ホストの `metadata` を移植可能な形で返す。ゲストの `stat` 系を組み立てる
/// ために `os-linux` が使う。フィールドは Unix の stat に揃え、
/// 取れない値は 0 にする（Windows でもコンパイルできるようにするため）。
#[derive(Clone, Copy, Debug, Default)]
pub struct Stat {
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub nlink: u64,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u64,
    pub size: u64,
    pub blksize: u64,
    pub blocks: u64,
    pub atime: i64,
    pub atime_nsec: i64,
    pub mtime: i64,
    pub mtime_nsec: i64,
    pub ctime: i64,
    pub ctime_nsec: i64,
}

#[cfg(unix)]
fn fill_stat(md: &std::fs::Metadata) -> Stat {
    use std::os::unix::fs::MetadataExt as _;
    Stat {
        dev: md.dev(),
        ino: md.ino(),
        mode: md.mode(),
        nlink: md.nlink(),
        uid: md.uid(),
        gid: md.gid(),
        rdev: md.rdev(),
        size: md.size(),
        blksize: md.blksize(),
        blocks: md.blocks(),
        atime: md.atime(),
        atime_nsec: md.atime_nsec(),
        mtime: md.mtime(),
        mtime_nsec: md.mtime_nsec(),
        ctime: md.ctime(),
        ctime_nsec: md.ctime_nsec(),
    }
}

#[cfg(not(unix))]
fn fill_stat(md: &std::fs::Metadata) -> Stat {
    Stat {
        size: md.len(),
        ..Stat::default()
    }
}

/// `std::fs::metadata` の移植版。
pub fn stat(path: &str) -> std::io::Result<Stat> {
    std::fs::metadata(path).map(|m| fill_stat(&m))
}

/// `std::fs::symlink_metadata` の移植版。
pub fn lstat(path: &str) -> std::io::Result<Stat> {
    std::fs::symlink_metadata(path).map(|m| fill_stat(&m))
}

/// `File::metadata` の移植版。
pub fn fstat(f: &std::fs::File) -> std::io::Result<Stat> {
    f.metadata().map(|m| fill_stat(&m))
}

/// `FileExt::read_at` の移植版。
#[cfg(unix)]
pub fn pread(f: &std::fs::File, buf: &mut [u8], off: u64) -> std::io::Result<usize> {
    use std::os::unix::fs::FileExt as _;
    f.read_at(buf, off)
}

#[cfg(not(unix))]
pub fn pread(f: &std::fs::File, buf: &mut [u8], off: u64) -> std::io::Result<usize> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    let mut f = f.try_clone()?;
    f.seek(SeekFrom::Start(off))?;
    f.read(buf)
}

/// `FileExt::write_at` の移植版。
#[cfg(unix)]
pub fn pwrite(f: &std::fs::File, buf: &[u8], off: u64) -> std::io::Result<usize> {
    use std::os::unix::fs::FileExt as _;
    f.write_at(buf, off)
}

#[cfg(not(unix))]
pub fn pwrite(f: &std::fs::File, buf: &[u8], off: u64) -> std::io::Result<usize> {
    use std::io::{Seek as _, SeekFrom, Write as _};
    let mut f = f.try_clone()?;
    f.seek(SeekFrom::Start(off))?;
    f.write(buf)
}

/// `DirEntry` の inode。`getdents` の d_ino に使う。
#[cfg(unix)]
pub fn dirent_ino(e: &std::fs::DirEntry) -> u64 {
    use std::os::unix::fs::MetadataExt as _;
    e.metadata().map(|m| m.ino()).unwrap_or(0)
}

#[cfg(not(unix))]
pub fn dirent_ino(_e: &std::fs::DirEntry) -> u64 {
    0
}
