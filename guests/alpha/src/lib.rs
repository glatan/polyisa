// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Alpha AXP のゲスト ISA。段階16の骨格。
//!
//! `CpuState` と機能・モデル宣言、ISADL から生成した命令集合・
//! デコード・逆アセンブルの殻を提供する。命令の意味論は後続の
//! 段階で `sem` 層として足す。
//!
//! 出典は SPEC-ALPHA-ARM である。
//! Ref: SPEC-ALPHA-ARM.

#![forbid(unsafe_code)]

// ISADL モデルから生成した命令集合・デコード・逆アセンブルの殻。
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// Alpha の ISA ファミリ名。
pub struct Alpha;

impl polyisa_guest::GuestIsa for Alpha {
    fn family() -> &'static str {
        "alpha"
    }
}

/// CPU 状態。`#[repr(C)]` で配置を固定し、`StateRef` はここを指す。
#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct CpuState {
    /// 整数レジスタ r0-31。r31 は読み出しで常に 0。
    pub r: [u64; 32],
    /// FP レジスタ f0-31 のビットイメージ。
    pub f: [u64; 32],
    /// FP 制御レジスタ（FPCR）。
    pub fpcr: u64,
    /// プログラムカウンタ。
    pub pc: u64,
    /// PAL の rduniq/wruniq が転送するユニーク値（スレッドポインタ）。
    pub uniq: u64,
}
