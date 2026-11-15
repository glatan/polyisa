// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! ARM（AArch32・ARM 状態）ゲスト。生成したデコーダと意味論をまとめる。
//!
//! 対象は ARMv5TE〜ARMv7-A の ARM 状態（A32）で、Thumb/Thumb-2 は
//! 対象外である。固定長 32 ビット、遅延スロットなし、全命令に条件
//  実行（cond=bits[31:28]）がある。pc の読み値は「命令アドレス+8」。
//! 出典は SPEC-ARM-ARM-A（Arm ARM A32）である。

#![forbid(unsafe_code)]

pub mod sem;

/// AArch32（ARM 状態）の CPU 状態。`InterpBackend` が持つバイト列の配置。
///
/// - `r[15]` は「実行中のアドレス+8」ではなく実 pc を保持する。命令意味論
///   が pc を読むときは実行ループが渡す命令アドレスを使う。
/// - `cpsr` は N(31) Z(30) C(29) V(28) と GE(19:16) を保持する。
/// - `vfp` は D0–D31 の 64 ビットスロット。S レジスタは D の半分として
///   意味論が取り出す（S2n は Dn の下位、S2n+1 は上位）。
#[repr(C)]
#[derive(Clone, Default)]
pub struct CpuState {
    /// 汎用レジスタ r0–r15。
    pub r: [u32; 16],
    /// CPSR（ユーザビュー。N/Z/C/V/GE だけを保持する）。
    pub cpsr: u32,
    /// 予約。
    pub pad0: u32,
    /// TPIDRURW（ユーザ読み書き TLS）。set_tls が書く。
    pub tpidrurw: u32,
    /// TPIDRURO（ユーザ読み取り専用 TLS）。set_tls の値の鏡。
    pub tpidruro: u32,
    /// FPSCR。
    pub fpscr: u32,
    /// 予約。
    pub pad1: u32,
    /// VFP の D0–D31。
    pub vfp: [u64; 32],
    /// 排他的ロードの監視対象アドレス（診断用。単一スレッドでは常に成功）。
    pub excl_addr: u64,
    /// 監視中のサイズ（バイト）。
    pub excl_size: u64,
}

include!(concat!(env!("OUT_DIR"), "/generated.rs"));
