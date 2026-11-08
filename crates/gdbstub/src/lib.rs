// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! GDB リモートシリアルプロトコルのサーバ。`std::net` の TCP で待つ。
//!
//! プロトコルの実装は後の段階で足す。

#![forbid(unsafe_code)]

/// 待ち受けの設定。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Config {
    /// `127.0.0.1:1234` のような addr。
    pub addr: String,
}

impl Config {
    #[must_use]
    pub fn new(addr: &str) -> Self {
        Self {
            addr: addr.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holds_addr() {
        assert_eq!(Config::new("127.0.0.1:1234").addr, "127.0.0.1:1234");
    }
}
