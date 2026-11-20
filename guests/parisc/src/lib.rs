// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! PA-RISC のゲスト ISA。段階17の骨格。
//!
//! `CpuState` と機能・モデル宣言、ISADL から生成した命令集合・
//! デコード・逆アセンブルの殻を提供する。命令の意味論は `sem`
//! 層として後続の段階で足す。
//!
//! 対象は PA-RISC 1.1・2.0 と MAX 拡張（1.0 は公開の根拠資料が
//! ないため範囲外。段階17 の着手条件で除外を決定）。
//! 出典は SPEC-PARISC-11・SPEC-PARISC-20 である。
//! Ref: SPEC-PARISC-11, SPEC-PARISC-20.

#![forbid(unsafe_code)]

// ISADL モデルから生成した命令集合・デコード・逆アセンブルの殻。
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// 命令の意味論。範囲は `sem` 層のヘッダにある。
pub mod sem;

/// PA-RISC の ISA ファミリ名。
pub struct Parisc;

impl polyisa_guest::GuestIsa for Parisc {
    fn family() -> &'static str {
        "parisc"
    }
}

/// CPU 状態。`#[repr(C)]` で配置を固定し、`StateRef` はここを指す。
/// PA 2.0 の 64 ビット幅に合わせて u64 で持つ（1.1 の 32 ビット
/// 命令は下位 32 ビットだけを使う）。
#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct CpuState {
    /// 汎用レジスタ r0-31。r0 は読み出しで常に 0、書き込みは破棄
    /// （ソースの 0 供給はハードの規約）。
    /// Ref: SPEC-PARISC-11 §2.2.
    pub gr: [u64; 32],
    /// 空間レジスタ sr0-7。
    pub sr: [u64; 8],
    /// 制御レジスタ cr0-31。cr11 は SAR（シフト量）、
    /// cr27 は Linux がスレッドポインタに使う（mfctl cr27）。
    pub cr: [u64; 32],
    /// FP レジスタ fr0-31 のビットイメージ。
    pub f: [u64; 32],
    /// 命令アドレスオフセットキューの前要素（実行中の命令番地）。
    /// Ref: SPEC-PARISC-11 §4.
    pub iaoq_f: u64,
    /// 命令アドレスオフセットキューの後要素（次の命令番地）。
    pub iaoq_b: u64,
    /// 命令アドレス空間キューの前要素。
    pub iasq_f: u64,
    /// 命令アドレス空間キューの後要素。
    pub iasq_b: u64,
    /// プロセッサ状態語。N（無効化）・B（分岐成立）・C/V
    /// （キャリ・オーバーフロ）・W（2.0 のワイド）など。
    /// Ref: SPEC-PARISC-11 §2.5.
    pub psw: u64,
}
