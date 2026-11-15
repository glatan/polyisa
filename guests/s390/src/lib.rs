// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! s390/zArchitecture ゲスト。生成したデコーダと意味論をまとめる。
//!
//! 対象は z/Architecture ユーザーモード（64 ビット・ビッグエンディアン）を
//! 主軸に、ESA/390 の命令面（31 ビットアドレス指定）を bare 実行で併せて
//! カバーする。命令は可変長で先頭バイトの上位 2 ビットが長さを決める:
//! 00→2B, 01→4B, 10→4B, 11→6B。16 本の GPR、2 ビットの条件コード
//! （PSW.CC）、16 本の FPR を持つ。Linux のシステムコールは `svc 0` で、
//! 番号は r1、引数は r2–r7、戻り値は r2、エラーは負の値（-errno）で返る。
//!
//! 出典は SPEC-S390-ZARCH-POP（SA22-7832）・SPEC-S390-ESA390-POP
//! （SA22-7201）・SPEC-S390-ABI（s390x ELF psABI）。DFP（10 進浮動小数）と
//! HFP（16 進浮動小数）の完全実装は範囲外で、それらの命令は
//! Unimplemented 例外に落とす（docs/notes-stage7-25-pending.md の
//! GAP-XXXX 参照）。
// Ref: SPEC-S390-ZARCH-POP (SA22-7832-13), SPEC-S390-ESA390-POP (SA22-7201-08),
// Ref: SPEC-S390-ABI.

#![forbid(unsafe_code)]

pub mod sem;

/// s390 の CPU 状態。`InterpBackend` が持つバイト列の配置。
///
/// - `r` は r0–r15。`x2`/`b2` フィールドの 0 は「レジスタ参照なし」で、
///   この規約は意味論が扱う（r0 の格納値自体は命令によっては使える）。
/// - `f` は f0–f15 の 64 ビットスロット。128 ビット（拡張）浮動小数は
///   (f0,f2) 等のペアで、試作では先頭レジスタの f64 近似として扱う
///   （GAP。丸め・精度は厳密ではない）。
/// - `cc` は PSW の 2 ビット条件コード（0–3）。
/// - `ar` はアクセスレジスタ（ear/sar/lam/stam）。ユーザーモードでは
///   内容の意味は Linux が決める TLS 領域などに使われる。
/// - `fpc` は FPC レジスタ（efpc/sfpc/lfpc/stfpc が読み書きする）。
/// - `pm` はプログラムマスク（ipm が CC と一緒に書き戻す 4 ビット）。
/// - `amask` は有効アドレスに掛けるマスク。64 ビットモードでは
///   `!0`、ESA/390 の 31 ビットモードでは `0x7fff_ffff`。
#[repr(C)]
#[derive(Clone)]
pub struct CpuState {
    /// 汎用レジスタ r0–r15。
    pub r: [u64; 16],
    /// 浮動小数点レジスタ f0–f15（各 64 ビット）。
    pub f: [u64; 16],
    /// アクセスレジスタ a0–a15（32 ビット値を下位に置く）。
    pub ar: [u64; 16],
    /// 条件コード（0–3）。
    pub cc: u64,
    /// FPC レジスタ。
    pub fpc: u64,
    /// プログラムマスク（4 ビット）。
    pub pm: u64,
    /// 有効アドレスのマスク（64 ビット = !0、ESA/390 31 ビット = 0x7fffffff）。
    pub amask: u64,
    /// STCK 系の単調増加カウンタ（簡易時計）。
    pub clk: u64,
}

impl Default for CpuState {
    fn default() -> Self {
        Self {
            r: [0; 16],
            f: [0; 16],
            ar: [0; 16],
            cc: 0,
            fpc: 0,
            pm: 0,
            amask: u64::MAX,
            clk: 0,
        }
    }
}

// 生成コード（Insn enum・decode・disasm・モデル表）。
include!(concat!(env!("OUT_DIR"), "/generated.rs"));
