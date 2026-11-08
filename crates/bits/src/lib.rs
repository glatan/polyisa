//! ビット操作。CPU や ISA の概念を持たない。
//!
//! ISADL の生成コード、ゲストメモリ、命令意味論の土台になる。

#![forbid(unsafe_code)]

/// 幅 `width`（1〜64）のマスクを返す。`width == 64` では全ビットが立つ。
#[must_use]
pub const fn mask(width: u32) -> u64 {
    assert!(width >= 1 && width <= 64);
    if width == 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    }
}

/// `value` の下位 `width` ビットだけを取り出す。
#[must_use]
pub const fn truncate(value: u64, width: u32) -> u64 {
    value & mask(width)
}

/// `value` の下位 `width` ビットを符号拡張して返す。
#[must_use]
pub const fn sign_extend(value: u64, width: u32) -> i64 {
    assert!(width >= 1 && width <= 64);
    let v = truncate(value, width);
    if width == 64 {
        v as i64
    } else if (v >> (width - 1)) & 1 == 1 {
        (v | !mask(width)) as i64
    } else {
        v as i64
    }
}

/// `[hi:lo]`（両端を含む）のビットフィールドを取り出す。`hi >= lo` とする。
#[must_use]
pub const fn extract_field(value: u64, hi: u32, lo: u32) -> u64 {
    assert!(hi < 64 && lo <= hi);
    (value >> lo) & mask(hi - lo + 1)
}

/// `[hi:lo]` に `field` をはめ込む。はみ出した上位は切り捨てる。
#[must_use]
pub const fn insert_field(dst: u64, hi: u32, lo: u32, field: u64) -> u64 {
    assert!(hi < 64 && lo <= hi);
    let m = mask(hi - lo + 1) << lo;
    (dst & !m) | ((field << lo) & m)
}

/// 幅 `width` の加算。桁上げと符号付きオーバーフローを返す。
#[must_use]
pub const fn add_carry(a: u64, b: u64, carry_in: bool, width: u32) -> (u64, bool, bool) {
    let m = mask(width);
    let a = a & m;
    let b = b & m;
    let c = (a as u128) + (b as u128) + (carry_in as u128);
    let result = (c as u64) & m;
    let carry_out = (c >> width) & 1 == 1;
    // 符号付きオーバーフロー：被加数と加数の符号が同じで、結果の符号が異なるとき。
    let sign = 1u64 << (width - 1);
    let overflow = ((a ^ result) & (b ^ result) & sign) != 0;
    (result, carry_out, overflow)
}

/// 幅 `width` の減算（`a - b - borrow_in`）。桁借りと符号付きオーバーフローを返す。
#[must_use]
pub const fn sub_borrow(a: u64, b: u64, borrow_in: bool, width: u32) -> (u64, bool, bool) {
    let m = mask(width);
    // `a - b - c = a + (2^w - b) + (1 - c) - 2^w`。加算の桁上げの反転が桁借りになる。
    let nb = m - (b & m);
    let (r, carry_out, _) = add_carry(a & m, nb, !borrow_in, width);
    let borrow_out = !carry_out;
    let sign = 1u64 << (width - 1);
    let overflow = ((a ^ b) & (a ^ r) & sign) != 0;
    (r, borrow_out, overflow)
}

/// 64 ビットの全幅乗算。下位と上位を返す。
#[must_use]
pub const fn mul_wide(a: u64, b: u64) -> (u64, u64) {
    let p = (a as u128) * (b as u128);
    (p as u64, (p >> 64) as u64)
}

/// バイト列から多バイト値を読む。長さが足りないときは `None`。
#[must_use]
pub fn read_le(bytes: &[u8], width_bytes: usize) -> Option<u64> {
    if bytes.len() < width_bytes || width_bytes > 8 {
        return None;
    }
    let mut v = 0u64;
    let mut i = 0;
    while i < width_bytes {
        v |= u64::from(bytes[i]) << (8 * i);
        i += 1;
    }
    Some(v)
}

/// バイト列から多バイト値（ビッグエンディアン）を読む。
#[must_use]
pub fn read_be(bytes: &[u8], width_bytes: usize) -> Option<u64> {
    if bytes.len() < width_bytes || width_bytes > 8 {
        return None;
    }
    let mut v = 0u64;
    let mut i = 0;
    while i < width_bytes {
        v = (v << 8) | u64::from(bytes[i]);
        i += 1;
    }
    Some(v)
}

/// 値をバイト列に書く（リトルエンディアン）。長さが足りないときは `false`。
pub fn write_le(bytes: &mut [u8], value: u64, width_bytes: usize) -> bool {
    if bytes.len() < width_bytes || width_bytes > 8 {
        return false;
    }
    let mut i = 0;
    while i < width_bytes {
        bytes[i] = (value >> (8 * i)) as u8;
        i += 1;
    }
    true
}

/// 値をバイト列に書く（ビッグエンディアン）。
pub fn write_be(bytes: &mut [u8], value: u64, width_bytes: usize) -> bool {
    if bytes.len() < width_bytes || width_bytes > 8 {
        return false;
    }
    let mut i = 0;
    while i < width_bytes {
        bytes[i] = (value >> (8 * (width_bytes - 1 - i))) as u8;
        i += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_edges() {
        assert_eq!(mask(1), 0x1);
        assert_eq!(mask(32), 0xffff_ffff);
        assert_eq!(mask(64), u64::MAX);
    }

    #[test]
    fn sign_extend_cases() {
        assert_eq!(sign_extend(0xff, 8), -1);
        assert_eq!(sign_extend(0x7f, 8), 127);
        assert_eq!(sign_extend(0x80, 8), -128);
        assert_eq!(sign_extend(0xffff_ffff_ffff_ffff, 64), -1);
        assert_eq!(sign_extend(0x1, 1), -1);
        assert_eq!(sign_extend(0x0, 1), 0);
    }

    #[test]
    fn field_roundtrip() {
        let v = 0xdead_beef_cafe_f00du64;
        assert_eq!(extract_field(v, 15, 0), 0xf00d);
        assert_eq!(insert_field(0, 15, 0, 0x1_2345), 0x2345);
        assert_eq!(insert_field(v, 31, 16, 0), 0xdead_beef_0000_f00d);
    }

    #[test]
    fn add_sub_flags() {
        let (r, c, o) = add_carry(0xff, 0x01, false, 8);
        assert_eq!((r, c, o), (0x00, true, false));
        let (r, _, o) = add_carry(0x7f, 0x01, false, 8);
        assert_eq!((r, o), (0x80, true));
        let (r, b, _) = sub_borrow(0x00, 0x01, false, 8);
        assert_eq!((r, b), (0xff, true));
        let (r, b, _) = sub_borrow(0x05, 0x03, false, 8);
        assert_eq!((r, b), (0x02, false));
        // 64 ビット全幅の桁上げ。
        let (r, c, _) = add_carry(u64::MAX, 1, false, 64);
        assert_eq!((r, c), (0, true));
    }

    #[test]
    fn endian_roundtrip() {
        let mut buf = [0u8; 8];
        assert!(write_le(&mut buf, 0x1234_5678_9abc_def0, 8));
        assert_eq!(read_le(&buf, 8), Some(0x1234_5678_9abc_def0));
        assert!(write_be(&mut buf, 0x1234_5678_9abc_def0, 8));
        assert_eq!(read_be(&buf, 8), Some(0x1234_5678_9abc_def0));
        assert_eq!(read_le(&buf[..3], 4), None);
        assert!(!write_le(&mut buf[..3], 1, 4));
    }

    #[test]
    fn mul_wide_cases() {
        assert_eq!(mul_wide(0, u64::MAX), (0, 0));
        assert_eq!(mul_wide(u64::MAX, u64::MAX), (1, u64::MAX - 1));
    }
}
