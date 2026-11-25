// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Power ISA（64 ビット）ゲスト。生成したデコーダと意味論をまとめる。
//!
//! 対象は ppc64 ユーザーモード（ELFv2・リトルエンディアンを主軸）。
//! 固定長 32 ビット、遅延スロットなし。r0 は命令によっては値 0 を
//! 示し、r2 は ELFv2 の TOC、r12 は大域入口の宛先、r13 は TLS を
//! 保持する。システムコールは `sc`（主オペコード 17）で、番号は r0、
//! 引数は r3–r8、戻り値は r3、エラーは CR0 の SO ビットで返る。
//! 出典は SPEC-POWER-ISA（Power ISA v3.1C）と SPEC-POWER-ABI
//! （64-Bit ELF V2 ABI r1.5）である。
// Ref: SPEC-POWER-ISA (v3.1C), SPEC-POWER-ABI (ELFv2 r1.5).

#![forbid(unsafe_code)]

pub mod sem;

/// ppc64 の CPU 状態。`InterpBackend` が持つバイト列の配置。
///
/// - `r` は r0–r31。r0 の「値 0 として読む」規約は意味論が扱う。
/// - `cr` は条件レジスタ 32 ビット。フィールド i（0–7）の 4 ビットは
///   IBM 番号の CR[4i:4i+3]（数値では `cr >> (28-4i) & 0xf`）。各
///   フィールドの内訳は IBM 番号で LT=0,GT=1,EQ=2,SO=3（数値では
///   0x8,0x4,0x2,0x1）。
/// - `xer` は SO(bit31)・OV(bit30)・CA(bit29) を保持する。
/// - `vsr` は VSR0–VSR63 の 128 ビットスロット。FPR i は VSR[i] の
///   IBM 上位 64 ビット（u128 の上位半分）として読む。
/// - `res` は load-and-reserve の監視対象アドレス（0 は予約なし）。
#[repr(C)]
#[derive(Clone)]
pub struct CpuState {
    /// 汎用レジスタ r0–r31。
    pub r: [u64; 32],
    /// リンクレジスタ（SPR 8）。
    pub lr: u64,
    /// カウントレジスタ（SPR 9）。
    pub ctr: u64,
    /// 条件レジスタ（32 ビット）。
    pub cr: u64,
    /// XER（SO/OV/CA）。
    pub xer: u64,
    /// FPSCR。
    pub fpscr: u64,
    /// VSR0–VSR63（128 ビット）。FPR・VR はこの別名。
    pub vsr: [u128; 64],
    /// lwarx/ldarx の予約アドレス。0 は予約なし。
    pub res: u64,
    /// 予約サイズ（バイト）。
    pub res_len: u64,
    /// PVR（SPR 287。読み取り専用のプロセッサ版）。
    pub pvr: u64,
    /// タイムベース相当の単調カウンタ（mftb/mfspr 268,269）。
    pub tb: u64,
}

impl Default for CpuState {
    fn default() -> Self {
        Self {
            r: [0; 32],
            lr: 0,
            ctr: 0,
            cr: 0,
            xer: 0,
            fpscr: 0,
            vsr: [0; 64],
            res: 0,
            res_len: 0,
            pvr: 0,
            tb: 0,
        }
    }
}

// 生成コード（Insn enum・decode・disasm・モデル表）。
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_gates_fp_altivec_vsx_decode() {
        let power6 = model_feats("power6");
        assert_ne!(power6 & FEAT_FP, 0);
        assert_ne!(power6 & FEAT_ALTIVEC, 0);
        assert_eq!(power6 & FEAT_VSX, 0);

        // 主オペコードは bits[31:26]。整数命令は機能なしでも残る。
        let addi = 14u32 << 26;
        let x4 = 4u32 << 26;
        let lfs = 48u32 << 26;
        let x59 = 59u32 << 26;
        let x60 = 60u32 << 26;
        let x63 = 63u32 << 26;
        assert_eq!(decode_model_ex(addi as u128, 32, true, 0), Some(Insn::Addi));

        assert_eq!(
            decode_model_ex(x4 as u128, 32, true, power6),
            Some(Insn::X4)
        );
        assert_eq!(
            decode_model_ex(lfs as u128, 32, true, power6),
            Some(Insn::Lfs)
        );
        assert_eq!(
            decode_model_ex(x59 as u128, 32, true, power6),
            Some(Insn::X59)
        );
        assert_eq!(
            decode_model_ex(x63 as u128, 32, true, power6),
            Some(Insn::X63)
        );
        assert_eq!(decode_model_ex(x60 as u128, 32, true, power6), None);

        let generic = model_feats("generic");
        assert_eq!(
            decode_model_ex(x60 as u128, 32, true, generic),
            Some(Insn::X60)
        );

        // POWER6 から個別に fp/altivec を落とすと対応する符号化は
        // デコードしない。粗分類の混合群は最小機能でゲートする。
        let no_fp = power6 & !FEAT_FP;
        assert_eq!(decode_model_ex(lfs as u128, 32, true, no_fp), None);
        assert_eq!(decode_model_ex(x59 as u128, 32, true, no_fp), None);
        assert_eq!(decode_model_ex(x63 as u128, 32, true, no_fp), None);
        assert_eq!(decode_model_ex(x4 as u128, 32, true, no_fp), Some(Insn::X4));

        let no_altivec = power6 & !FEAT_ALTIVEC;
        assert_eq!(decode_model_ex(x4 as u128, 32, true, no_altivec), None);
    }
}
