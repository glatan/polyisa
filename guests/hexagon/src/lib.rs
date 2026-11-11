// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Hexagon 最小のゲスト ISA。段階2の試作であり、パケットの一括反映を確かめる。
//!
//! スロット整数演算と、ループ 0 の終端判定を持つ。duplex・imm 拡張・
//! HVX・複数スレッドは試作に含まない。パケットは2スロットを想定し、
//! 書き込みの一括反映と .new 転送を sem で表す。終端のパケットでは、
//! commit が LC0 と SA0 から次の pc を決める。

#![forbid(unsafe_code)]

pub mod sem;

// 空のモデルから生成した殻。ISADL 記述の追加後に中身が増える。
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// Hexagon の ISA ファミリ名。
pub struct Hexagon;

impl polyisa_guest::GuestIsa for Hexagon {
    fn family() -> &'static str {
        "hexagon"
    }
}

/// CPU 状態。`#[repr(C)]` で配置を固定する。
#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct CpuState {
    /// 汎用レジスタ 32本（32ビット）。
    pub r: [u32; 32],
    /// プログラムカウンタ。
    pub pc: u32,
    /// パケットバッファ（スロットの書き込み先）。
    pub pkt: [u32; 32],
    /// パケットの有効マスク（1ビットが1レジスタに対応する）。
    pub pkt_valid: u32,
    /// ハードウェアループ 0 の開始アドレス。
    pub sa0: u32,
    /// ハードウェアループ 0 の残り回数。
    pub lc0: u32,
    /// このパケットがループ 0 の終端なら 1。
    pub loop_end: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_guest::GuestIsa;

    #[test]
    fn family_name() {
        assert_eq!(Hexagon::family(), "hexagon");
    }

    #[test]
    fn state_layout_pinned() {
        assert_eq!(core::mem::offset_of!(CpuState, r), 0);
        assert_eq!(core::mem::offset_of!(CpuState, pc), 32 * 4);
        assert_eq!(core::mem::offset_of!(CpuState, pkt), 32 * 4 + 4);
        let pkt_valid = 32 * 4 + 4 + 32 * 4;
        assert_eq!(core::mem::offset_of!(CpuState, pkt_valid), pkt_valid);
        assert_eq!(core::mem::offset_of!(CpuState, sa0), pkt_valid + 4);
        assert_eq!(core::mem::offset_of!(CpuState, lc0), pkt_valid + 8);
        assert_eq!(core::mem::offset_of!(CpuState, loop_end), pkt_valid + 12);
    }

    #[test]
    fn insn_count() {
        // 試作のスロット6件。
        assert_eq!(INSNS.len(), 6);
    }

    #[test]
    fn decode_spot_checks() {
        // 試作パターンは上位8ビットで区別する（実符号化の簡略化）。
        // Ref: SPEC-HEXAGON-PRM (V73).
        assert_eq!(decode(0x0100_0000, 32), Some(Insn::Add));
        assert_eq!(decode(0x0200_0000, 32), Some(Insn::Sub));
        assert_eq!(decode(0x0300_0000, 32), Some(Insn::And));
        assert_eq!(decode(0x0400_0000, 32), Some(Insn::Or));
        assert_eq!(decode(0x0500_0000, 32), Some(Insn::MovImm));
        assert_eq!(decode(0x0600_0000, 32), Some(Insn::Jump));
        assert_eq!(decode(0xFF00_0000, 32), None);
    }

    #[test]
    fn cpu_models() {
        assert!(FEATURES.contains(&"v73"));
        assert!(MODELS.contains(&"generic"));
    }
}
