// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! IA-64 最小のゲスト ISA。段階2の試作であり、バンドル・述語・回転を確かめる。
//!
//! 整数演算のみ持つ。41ビットスロット・テンプレート割り当て・MLX・F系・B系・
//! レジスタスタック・NaT/ALAT・バンドルアドレス報告は本格実装で足す。
//! 回転は 8本の回転域と RRB（基底）で表す動的なレジスタ参照の最小形である。

#![forbid(unsafe_code)]

pub mod sem;

// 空のモデルから生成した殻。ISADL 記述の追加後に中身が増える。
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// IA-64 の ISA ファミリ名。
pub struct Ia64;

impl polyisa_guest::GuestIsa for Ia64 {
    fn family() -> &'static str {
        "ia64"
    }
}

/// CPU 状態。`#[repr(C)]` で配置を固定する。
#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct CpuState {
    /// 汎用レジスタ 32本（静的域の代用）。
    pub g: [u64; 32],
    /// 回転レジスタ 8本。
    pub rot: [u64; 8],
    /// 述語レジスタ 8本（0/1）。
    pub pr: [u64; 8],
    /// 回転基底（RRB）。
    pub rrb: u64,
    /// プログラムカウンタ（バンドルアドレス）。
    pub pc: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_guest::GuestIsa;

    #[test]
    fn family_name() {
        assert_eq!(Ia64::family(), "ia64");
    }

    #[test]
    fn state_layout_pinned() {
        assert_eq!(core::mem::offset_of!(CpuState, g), 0);
        assert_eq!(core::mem::offset_of!(CpuState, rot), 32 * 8);
        assert_eq!(core::mem::offset_of!(CpuState, pr), 32 * 8 + 8 * 8);
        assert_eq!(core::mem::offset_of!(CpuState, rrb), 32 * 8 + 8 * 8 + 8 * 8);
        assert_eq!(
            core::mem::offset_of!(CpuState, pc),
            32 * 8 + 8 * 8 + 8 * 8 + 8
        );
    }

    #[test]
    fn insn_count() {
        // 試作のバンドル6件。
        assert_eq!(INSNS.len(), 6);
    }

    #[test]
    fn decode_spot_checks() {
        // 試作パターンは上位8ビットで区別する（実符号化の簡略化）。
        // Ref: SPEC-IA64-SDM (Rev 2.3).
        let hi = |b: u128| b << 120;
        assert_eq!(decode(hi(0x01), 128), Some(Insn::Add));
        assert_eq!(decode(hi(0x02), 128), Some(Insn::Sub));
        assert_eq!(decode(hi(0x03), 128), Some(Insn::AddPred));
        assert_eq!(decode(hi(0x04), 128), Some(Insn::AddRot));
        assert_eq!(decode(hi(0x05), 128), Some(Insn::Nop));
        assert_eq!(decode(hi(0x06), 128), Some(Insn::Br));
        assert_eq!(decode(hi(0xFF), 128), None);
    }

    #[test]
    fn cpu_models() {
        assert!(FEATURES.contains(&"itanium"));
        assert!(MODELS.contains(&"generic"));
    }
}
