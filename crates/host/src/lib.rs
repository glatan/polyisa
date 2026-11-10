// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! ホスト依存の機能。標準ライブラリにないものだけを自前の FFI で補う。
//!
//! FFI 宣言は後の段階で足す。ここでは OS 非依存の問い合わせだけを提供する。

#![forbid(unsafe_code)]

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_least_one() {
        assert!(parallelism() >= 1);
    }
}
