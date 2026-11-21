// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! SuperH のゲスト ISA。段階18の骨格。
//!
//! `CpuState` と機能・モデル宣言、ISADL から生成した命令集合・
//! デコード・逆アセンブルの殻を提供する。命令の意味論は `sem`
//! 層として後続の段階で足す。
//!
//! 対象モデルは SH-1・SH-2・SH-2E・SH-2A（SH2A-FPU を含む）・
//! SH-3・SH-3E・SH-4・SH-4A・J-core（J2）。SH3-DSP は範囲外。
//! フェッチは常に 16 ビットパーセルだが、SH-2A の 32 ビット命令は
//! 2 パーセルから構成される。リトルエンディアン（SH-4）と
//! ビッグエンディアン（SH-4EB）の両方の並びを扱う。
//! 出典は SPEC-SUPERH-SH2・SPEC-SUPERH-SH3・SPEC-SUPERH-SH4・
//! SPEC-SUPERH-SH2A・SPEC-SUPERH-SH4A・SPEC-SUPERH-JCORE である。
//! Ref: SPEC-SUPERH-SH2, SPEC-SUPERH-SH3, SPEC-SUPERH-SH4,
//! SPEC-SUPERH-SH2A, SPEC-SUPERH-SH4A, SPEC-SUPERH-JCORE.

#![forbid(unsafe_code)]

// ISADL モデルから生成した命令集合・デコード・逆アセンブルの殻。
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// 命令の意味論。範囲は `sem` 層のヘッダにある。
pub mod sem;

/// SuperH の ISA ファミリ名。
pub struct Superh;

impl polyisa_guest::GuestIsa for Superh {
    fn family() -> &'static str {
        "superh"
    }
}

/// CPU 状態。`#[repr(C)]` で配置を固定し、`StateRef` はここを指す。
/// 整数レジスタは 32 ビット幅の SH アーキテクチャに合わせて u32 で
/// 持つ。
/// Ref: SPEC-SUPERH-SH4 §2（レジスタ構成）.
#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct CpuState {
    /// 汎用レジスタ R0-R15。
    pub r: [u32; 16],
    /// プログラムカウンタ（実行中の命令番地）。
    pub pc: u32,
    /// プロシージャレジスタ（JSR/BSR のリンク先）。
    pub pr: u32,
    /// ステータスレジスタ。T/S/IMASK/Q/M/FD/RC など。
    /// Ref: SPEC-SUPERH-SH4 §2.4.
    pub sr: u32,
    /// グローバルベースレジスタ。
    pub gbr: u32,
    /// ベクタベースレジスタ。
    pub vbr: u32,
    /// MAC 上位・下位（積和の 64 ビット保持）。
    pub mach: u32,
    /// MAC 下位。
    pub macl: u32,
    /// 浮動小数点通信レジスタ（整数・FP 間の受け渡し）。
    pub fpul: u32,
    /// FP レジスタ FR0-FR15 のビットイメージ。
    pub fr: [u32; 16],
    /// SH-4 の代替 FP バンク XF0-XF15（FRCHG で切替）。
    /// Ref: SPEC-SUPERH-SH4 §6（XF バンク）.
    pub xf: [u32; 16],
    /// 浮動小数点状態制御レジスタ。RM/Flag/DN/PR/SZ/FR など。
    /// Ref: SPEC-SUPERH-SH4 §6.
    pub fpscr: u32,
    /// セーブドジェネラルレジスタ（SH-3E/SH-4。例外時の R15 退避）。
    /// Ref: SPEC-SUPERH-SH4 §2.
    pub sgr: u32,
    /// セーブドステータスレジスタ（SH-3/SH-4 の例外時 SR 退避）。
    /// Ref: SPEC-SUPERH-SH4 §2.
    pub ssr: u32,
    /// セーブドプログラムカウンタ（例外時 PC 退避）。
    /// Ref: SPEC-SUPERH-SH4 §2.
    pub spc: u32,
    /// デバッグベースレジスタ（SH-4A。UBC 系）。
    /// Ref: SPEC-SUPERH-SH4A.
    pub dbr: u32,
    /// テーブルベースレジスタ（SH-2A。JSR/N @@(disp8,TBR) の基底）。
    /// Ref: SPEC-SUPERH-SH2A.
    pub tbr: u32,
    /// SH-4 のレジスタバンク R0_BANK-R7_BANK（例外時切替用）。
    /// Ref: SPEC-SUPERH-SH4 §2.
    pub rbank: [u32; 8],
}
