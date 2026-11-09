// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! MIPS I 試作のゲスト ISA。段階3の最小であり、裸実行で遅延スロットを確かめる。
//!
//! R 形式の整数演算と LW/SW・BEQ・J・HI/LO 乗除算に加え、R6 の割り当て直しの
//! 最小形（ADDI の pre-R6 ゲートと BEQZALC）を持つ。BOVC/BEQC は field 間比較の
//! where が要るため先送りする。FPU、microMIPS、ロード遅延、branch likely、
//! 両エンディアンの切り替えは本格実装で足す。

#![forbid(unsafe_code)]

pub mod sem;

// 空のモデルから生成した殻。ISADL 記述の追加後に中身が増える。
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// MIPS の ISA ファミリ名。
pub struct Mips;

impl polyisa_guest::GuestIsa for Mips {
    fn family() -> &'static str {
        "mips"
    }
}

/// CPU 状態。`#[repr(C)]` で配置を固定する。
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CpuState {
    /// 整数レジスタ $0〜$31。$0 は読むと 0、書き込みは捨てる。
    /// 32ビットで包んだ値を下位に持つ（RV64 の GPR と同じ約束）。
    pub g: [u64; 32],
    /// プログラムカウンタ。
    pub pc: u64,
    /// 次のプログラムカウンタ（遅延スロットの実行先）。
    pub npc: u64,
    /// HI レジスタ（乗除算の上位。下位32ビットを使う）。
    pub hi: u64,
    /// LO レジスタ（乗除算の下位・商。下位32ビットを使う）。
    pub lo: u64,
}

impl Default for CpuState {
    fn default() -> Self {
        Self {
            g: [0; 32],
            pc: 0,
            npc: 4,
            hi: 0,
            lo: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_guest::GuestIsa;

    #[test]
    fn family_name() {
        assert_eq!(Mips::family(), "mips");
    }

    #[test]
    fn state_layout_pinned() {
        assert_eq!(core::mem::offset_of!(CpuState, g), 0);
        assert_eq!(core::mem::offset_of!(CpuState, pc), 32 * 8);
        assert_eq!(core::mem::offset_of!(CpuState, npc), 32 * 8 + 8);
        assert_eq!(core::mem::offset_of!(CpuState, hi), 32 * 8 + 16);
        assert_eq!(core::mem::offset_of!(CpuState, lo), 32 * 8 + 24);
    }

    #[test]
    fn insn_count() {
        // 試作の整数19件（nop は sll $0,$0,0 の別名として扱う）。
        assert_eq!(INSNS.len(), 19);
    }

    #[test]
    fn decode_spot_checks() {
        // 命令語はビット配置から手で組み立てる。Ref: SPEC-MIPS-IV。
        assert_eq!(decode(0x0043_0821, 32), Some(Insn::Addu));
        assert_eq!(decode(0x0043_0823, 32), Some(Insn::Subu));
        assert_eq!(decode(0x0043_0824, 32), Some(Insn::And));
        assert_eq!(decode(0x0043_0825, 32), Some(Insn::Or));
        assert_eq!(decode(0x0003_0880, 32), Some(Insn::Sll));
        assert_eq!(decode(0x0022_0018, 32), Some(Insn::Mult));
        assert_eq!(decode(0x0022_0019, 32), Some(Insn::Multu));
        assert_eq!(decode(0x0022_001a, 32), Some(Insn::Div));
        assert_eq!(decode(0x0022_001b, 32), Some(Insn::Divu));
        assert_eq!(decode(0x0000_0810, 32), Some(Insn::Mfhi));
        assert_eq!(decode(0x0000_0812, 32), Some(Insn::Mflo));
        assert_eq!(decode(0x0020_0011, 32), Some(Insn::Mthi));
        assert_eq!(decode(0x0020_0013, 32), Some(Insn::Mtlo));
        // nop は sll $0,$0,0 の別名であり、Sll に解釈する。
        assert_eq!(decode(0x0000_0000, 32), Some(Insn::Sll));
        assert_eq!(decode(0x8c41_0010, 32), Some(Insn::Lw));
        assert_eq!(decode(0xac41_0010, 32), Some(Insn::Sw));
        assert_eq!(decode(0x1022_0004, 32), Some(Insn::Beq));
        assert_eq!(decode(0x0800_0400, 32), Some(Insn::J));
        // R6 の割り当て直し：op=001000 は pre-R6 では ADDI。
        // Ref: SPEC-MIPS-R6 (Rev 6.06).
        assert_eq!(decode(0x2043_0010, 32), Some(Insn::Addi));
        // R6 では rs==0 && rt!=0 の符号化が BEQZALC になる。
        assert_eq!(decode(0x2001_0004, 32), Some(Insn::Addi));
        assert_eq!(
            decode_model_ex(0x2001_0004, 32, true, FEAT_MIPS_R6),
            Some(Insn::Beqzalc)
        );
        // R6 で BOVC/BEQC になる符号化は未実装のため None（現 r6 は大部分 illegal）。
        assert_eq!(decode_model_ex(0x2043_0010, 32, true, FEAT_MIPS_R6), None);
        assert_eq!(decode(0xffff_ffff, 32), None);
    }

    #[test]
    fn cpu_models() {
        assert!(FEATURES.contains(&"mips1"));
        assert!(FEATURES.contains(&"mips_r6"));
        assert!(MODELS.contains(&"r3000"));
        assert!(MODELS.contains(&"r6"));
    }
}
