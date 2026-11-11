// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! MIPS I の整数命令。遅延スロット、符号付き溢れ、非整列ロードを裸実行で確かめる。
//!
//! R6 は遅延スロット付きの分岐とジャンプ、非整列ロード、HI/LO 乗除算を復号しない。
//! BEQZALC だけが R6 側の命令である。ロード遅延、エンディアンの切り替え、o32 は後の回で足す。

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
    /// 0 除算の挙動。0 は HI/LO を保つ。0 以外は HI と LO に 0 を書く。
    /// ゼロ埋めの裸実行は 0 なので、従来の「不変」と同じになる。
    /// Ref: SPEC-MIPS-IV (Rev 3.2) の DIV の UNPREDICTABLE。
    pub div_zero_writes_zero: u64,
}

impl Default for CpuState {
    fn default() -> Self {
        Self {
            g: [0; 32],
            pc: 0,
            npc: 4,
            hi: 0,
            lo: 0,
            div_zero_writes_zero: 0,
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
        assert_eq!(
            core::mem::offset_of!(CpuState, div_zero_writes_zero),
            32 * 8 + 32
        );
    }

    #[test]
    fn insn_count() {
        // MIPS I の整数命令。nop は sll $0,$0,0 の別名。R6 の beqzalc を1件含む。
        assert_eq!(INSNS.len(), 59);
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
        // ADDIU は R6 でも残る。
        assert_eq!(decode(0x2443_0010, 32), Some(Insn::Addiu));
        assert_eq!(
            decode_model_ex(0x2443_0010, 32, true, FEAT_MIPS_R6),
            Some(Insn::Addiu)
        );
        // HI/LO 乗除算は R6 で削除される（MUL/MUH/MOD 系は本格実装）。
        assert_eq!(decode(0x0022_0018, 32), Some(Insn::Mult));
        assert_eq!(decode_model_ex(0x0022_0018, 32, true, FEAT_MIPS_R6), None);
        assert_eq!(
            decode_model_ex(0x2001_0004, 32, true, FEAT_MIPS_R6),
            Some(Insn::Beqzalc)
        );
        // R6 で BOVC/BEQC になる符号化は未実装のため None（現 r6 は大部分 illegal）。
        assert_eq!(decode_model_ex(0x2043_0010, 32, true, FEAT_MIPS_R6), None);
        // Release 6 は遅延スロット付きの BEQ を外す。LUI は残る。
        assert_eq!(decode(0x3c01_0001, 32), Some(Insn::Lui));
        assert_eq!(decode(0x1022_0004, 32), Some(Insn::Beq));
        assert_eq!(decode_model_ex(0x1022_0004, 32, true, FEAT_MIPS_R6), None);
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
