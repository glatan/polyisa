// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! SPARC V8 試作のゲスト ISA。段階2の試作であり、裸実行で遅延スロットを確かめる。
//!
//! レジスタウィンドウはフラットな32本で代用し、動的なレジスタ参照は本格実装で足す。
//! 遅延スロットは pc/npc の組で表し、分岐の決定と遅延スロットの実行を分ける。
//! BA の annul が立っているときは、遅延スロットの命令を実行しない。

#![forbid(unsafe_code)]

pub mod sem;

// 空のモデルから生成した殻。ISADL 記述の追加後に中身が増える。
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// SPARC の ISA ファミリ名。
pub struct Sparc;

impl polyisa_guest::GuestIsa for Sparc {
    fn family() -> &'static str {
        "sparc"
    }
}

/// CPU 状態。`#[repr(C)]` で配置を固定する。
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CpuState {
    // Gap: GAP-0018
    /// 整数レジスタ g0〜g31。g0 は読むと 0、書き込みは捨てる。
    pub g: [u64; 32],
    /// プログラムカウンタ。
    pub pc: u64,
    /// 次のプログラムカウンタ（遅延スロットの実行先）。
    pub npc: u64,
    /// annul ビット。1 のとき、次の遅延スロットは実行しない。
    pub annul: u64,
}

impl Default for CpuState {
    fn default() -> Self {
        Self {
            g: [0; 32],
            pc: 0,
            npc: 4,
            annul: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_guest::GuestIsa;

    #[test]
    fn family_name() {
        assert_eq!(Sparc::family(), "sparc");
    }

    #[test]
    fn state_layout_pinned() {
        assert_eq!(core::mem::offset_of!(CpuState, g), 0);
        assert_eq!(core::mem::offset_of!(CpuState, pc), 32 * 8);
        assert_eq!(core::mem::offset_of!(CpuState, npc), 32 * 8 + 8);
        assert_eq!(core::mem::offset_of!(CpuState, annul), 32 * 8 + 16);
    }

    #[test]
    fn insn_count() {
        // 試作の整数10件。
        assert_eq!(INSNS.len(), 10);
    }

    #[test]
    fn decode_spot_checks() {
        // 命令語はビット配置から手で組み立てる。Ref: SPEC-SPARC-V8。
        // F3 は op + rd + op3 + rs1 + i=0 + 予約0 + rs2 の実符号化である。
        assert_eq!(decode(0x8200_8003, 32), Some(Insn::Add));
        assert_eq!(decode(0x8220_8003, 32), Some(Insn::Sub));
        assert_eq!(decode(0x8208_8003, 32), Some(Insn::And));
        assert_eq!(decode(0x8210_8003, 32), Some(Insn::Or));
        assert_eq!(decode(0x8328_8003, 32), Some(Insn::Sll));
        assert_eq!(decode(0x8fc0_4002, 32), Some(Insn::Jmpl));
        assert_eq!(decode(0xc200_8003, 32), Some(Insn::Ld));
        assert_eq!(decode(0xc620_8000, 32), Some(Insn::St));
        assert_eq!(decode(0x0301_2345, 32), Some(Insn::Sethi));
        assert_eq!(decode(0x1080_0100, 32), Some(Insn::Ba));
        assert_eq!(decode(0xffff_ffff, 32), None);
    }

    #[test]
    fn cpu_models() {
        assert!(FEATURES.contains(&"v8"));
        assert!(MODELS.contains(&"generic"));
    }
}
