//! ソフトウェア浮動小数点。ホストの FPU を使わず、整数演算で実装する。
//!
//! NaN 規則などの ISA ごとの選択は呼び出し側が設定で渡す。
//! 演算の中身は IEEE 754 の確認後に実装する。ここでは型だけを提供する。

#![forbid(unsafe_code)]

/// 32 ビット形式のビット列。`f32` との変換は再解釈のみで、演算には使わない。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct F32(pub u32);

/// 64 ビット形式のビット列。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct F64(pub u64);

impl F32 {
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }
}

impl F64 {
    #[must_use]
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_roundtrip() {
        assert_eq!(F32::from_bits(0x3f80_0000).bits(), 0x3f80_0000);
        assert_eq!(
            F64::from_bits(0x3ff0_0000_0000_0000).bits(),
            0x3ff0_0000_0000_0000
        );
    }
}
