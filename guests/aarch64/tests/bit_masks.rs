// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Arm ARM `DecodeBitMasks`（論理即値のビットマスク展開）の回帰試験。
//!
//! 要素マスクを「ビット数」でなく「その幅の全ビット」で作る回帰を押さえる
//! （`esize=8` の要素に `0xFF` でなく `7` を立てる誤りがあった）。
//! Ref: SPEC-ARM-ARM-A (Armv9-A ARM ARM 2024-09) shared/functions。

use polyisa_guest_aarch64::sem::decode_bit_masks;

#[test]
fn repeated_byte_element_masks() {
    // tst x0, #0x8080808080808080 (0xf201c01f) → n=0, imms=0x30, immr=1。
    assert_eq!(
        decode_bit_masks(0, 0x30, 1, true),
        Some(0x8080_8080_8080_8080)
    );
    // orr x0, xzr, #0x0101010101010101 (0xb200c3e0) → n=0, imms=0x30, immr=0。
    assert_eq!(
        decode_bit_masks(0, 0x30, 0, true),
        Some(0x0101_0101_0101_0101)
    );
}

#[test]
fn wider_elements_and_rotation() {
    // and x4, x4, #0x7fffffff: imms=0x1e で 31 個のセットビット。
    assert_eq!(decode_bit_masks(1, 0x1e, 0, true), Some(0x7fff_ffff));
    // 32bit で N=1 は予約（decode 不可）。
    assert_eq!(decode_bit_masks(1, 0x20, 0, false), None);
    // imms==levels（全ビット）は即値論理では予約。
    assert_eq!(decode_bit_masks(1, 0x3f, 0, true), None);
}
