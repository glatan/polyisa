// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! LoongArch のゲスト ISA。段階19 の骨格。
//!
//! `CpuState` と機能・モデル宣言、ISADL から生成した命令集合・
//! デコード・逆アセンブルの殻を提供する。命令の意味論は `sem`
//! 層として後続の段階で足す。
//!
//! 対象は LA32 と LA64 の基本命令集合（ユーザモードの全語彙と
//! 特権命令の入口まで）。LSX/LASX/LBT は機能旗の宣言のみで、
//! 命令の割当ては LA13 で棚卸す。LoongArch はリトルエンディアン。
//! 出典は SPEC-LOONGARCH-RM である。
//! Ref: SPEC-LOONGARCH-RM §1（アーキテクチャ構成）.

#![forbid(unsafe_code)]

// ISADL モデルから生成した命令集合・デコード・逆アセンブルの殻。
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// 命令の意味論。範囲は `sem` 層のヘッダにある。
pub mod sem;

/// LoongArch の ISA ファミリ名。
pub struct Loongarch;

impl polyisa_guest::GuestIsa for Loongarch {
    fn family() -> &'static str {
        "loongarch"
    }
}

/// CSR の番号。`CpuState::csr` の添字は建築上の CSR 番号そのまま。
/// ユーザモードから直接触れるのは CPUCFG・RDTIME* が返す情報で、
/// CSRRD/CSRWR/CSRXCHG・ERTN は特権入口として配列に写す。
/// Ref: SPEC-LOONGARCH-RM §4（制御・状態レジスタ一覧）.
pub mod csr {
    /// 現在モード情報（CRMD）。
    pub const CRMD: usize = 0x0;
    /// 例外前モード情報（PRMD）。
    pub const PRMD: usize = 0x1;
    /// 拡張ユニット有効（EUEN。FPU/LSX/LASX/LBT の許可）。
    pub const EUEN: usize = 0x2;
    /// 雑多制御（MISC）。
    pub const MISC: usize = 0x3;
    /// 例外構成（ECFG）。
    pub const ECFG: usize = 0x4;
    /// 例外状態（ESTAT）。
    pub const ESTAT: usize = 0x5;
    /// 例外戻り番地（ERA）。
    pub const ERA: usize = 0x6;
    /// 例外の悪いアドレス（BADV）。
    pub const BADV: usize = 0x7;
    /// 例外の悪い命令（BADI）。
    pub const BADI: usize = 0x8;
    /// 例外入口（EENTRY）。
    pub const EENTRY: usize = 0xc;
    /// CPU 識別（CPUID）。
    pub const CPUID: usize = 0x20;
    /// データセーブ SAVE0-15 の先頭。
    pub const SAVE0: usize = 0x30;
    /// LL ビット制御（LLBCTL）。
    pub const LLBCTL: usize = 0x60;
}

/// CPU 状態。`#[repr(C)]` で配置を固定し、`StateRef` はここを指す。
/// GR/FR は GRLEN=64 の格納で、LA32 では実行ループ側が
/// アドレスを 32 ビットに折り返す（`InterpBackend::addr_mask`）。
/// `.w` 命令の結果は LA32/LA64 とも符号拡張の不変式を守る。
/// Ref: SPEC-LOONGARCH-RM §2.1（レジスタ構成）, §3.1（FR/FCC/FCSR）,
/// §4（CSR 一覧）.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CpuState {
    /// 汎用レジスタ r0-r31（r0 は常に 0）。
    pub r: [u64; 32],
    /// FP レジスタ f0-f31 のビットイメージ（単精度は下位 32 ビット）。
    pub f: [u64; 32],
    /// LSX ベクトルレジスタ vr0-vr31 のビットイメージ。
    /// LSX は実装済み部分集合のみが触る（LA13 参照）。
    /// Ref: SPEC-LOONGARCH-RM Vol.2 §1（LSX 概要）.
    pub vr: [u128; 32],
    /// プログラムカウンタ（実行中の命令番地）。
    pub pc: u64,
    /// 浮動小数点条件フラグ FCC0-FCC7（下位 8 ビット）。
    /// Ref: SPEC-LOONGARCH-RM §3.1（FCC）.
    pub fcc: u64,
    /// FCSR0-FCSR3（丸め・フラグ・有効・原因）。
    /// Ref: SPEC-LOONGARCH-RM §3.2（FCSR 定義）.
    pub fcsr: [u32; 4],
    /// 制御・状態レジスタの写像。添字は建築上の CSR 番号
    /// （0x000-0x1ff までを保持。DMW0-3 等の 0x180 台も入る）。
    pub csr: [u64; 512],
    /// CPUCFG が返す構成情報（語番号 0-63 の固定値表）。
    /// Ref: SPEC-LOONGARCH-RM §2.2.10.2（CPUCFG）.
    pub cpucfg: [u32; 64],
    /// RDTIME* が読む安定カウンタ。実行ループが 1 ステップ毎に
    /// 進める決定論的な時計。
    /// Ref: SPEC-LOONGARCH-RM §2.2.10.1（RDTIME 系）.
    pub stable_counter: u64,
}

impl Default for CpuState {
    fn default() -> Self {
        Self {
            r: [0; 32],
            f: [0; 32],
            vr: [0; 32],
            pc: 0,
            fcc: 0,
            fcsr: [0; 4],
            csr: [0; 512],
            cpucfg: [0; 64],
            stable_counter: 0,
        }
    }
}
