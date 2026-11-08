// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 決定的な擬似乱数（SplitMix64）。テストの再現に使う。

/// 決定的な乱数源。同じ種からは同じ列が出る。
#[derive(Clone, Debug)]
pub struct Rng {
    state: u64,
}

impl Rng {
    /// 種から作る。
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// 内部状態を返す。失敗事例の再現に使う。
    #[must_use]
    pub const fn state(&self) -> u64 {
        self.state
    }

    /// 次の `u64` を返す。
    pub const fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// `[0, bound)` の範囲で返す。`bound == 0` のときは 0。
    pub const fn next_below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            return 0;
        }
        // 剰余による偏りはテスト用途では許す。決定的であることが要件である。
        self.next_u64() % bound
    }

    /// 指定のバイト列を乱数で埋める。
    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() {
            let v = self.next_u64().to_le_bytes();
            let n = (buf.len() - i).min(8);
            buf[i..i + n].copy_from_slice(&v[..n]);
            i += n;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..16 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn known_first_values() {
        // SplitMix64 の既知の先頭値。実装の取り違えを検出する。
        let mut r = Rng::new(0);
        assert_eq!(r.next_u64(), 0xe220_a839_7b1d_cdaf);
        assert_eq!(r.next_u64(), 0x6e78_9e6a_a1b9_65f4);
    }

    #[test]
    fn below_range() {
        let mut r = Rng::new(1);
        for _ in 0..100 {
            assert!(r.next_below(10) < 10);
        }
        assert_eq!(r.next_below(0), 0);
    }
}
