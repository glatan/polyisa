// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! m68k のゲスト ISA。段階14の骨格。
//!
//! `CpuState` と機能・モデル宣言、sem 層の土台を提供する。
//! 命令は16ビット固定の制御系（nop/reset/rte/rts/rtr/illegal）に加えて、
//! EA モード命令群を spec 駆動で段階的に増やしている。
//! EA モードの解釈と拡張語の消費は `ea.rs`、意味論は `sem.rs`。
//!
//! 出典は SPEC-M68K-PRM (M68000PM/AD Rev 1) である。
//! Ref: SPEC-M68K-PRM (Rev 1).

#![forbid(unsafe_code)]

pub mod ea;
pub mod sem;

// ISADL モデルから生成した命令集合・デコード・逆アセンブルの殻。
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// m68k の ISA ファミリ名。
pub struct M68k;

impl polyisa_guest::GuestIsa for M68k {
    fn family() -> &'static str {
        "m68k"
    }
}

/// CPU 状態。`#[repr(C)]` で配置を固定し、`StateRef` はここを指す。
#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct CpuState {
    /// データレジスタ D0〜D7。
    pub d: [u32; 8],
    /// アドレスレジスタ A0〜A6。A7 は `usp`/`ssp` に分かれる。
    pub a: [u32; 7],
    /// ユーザースタックポインタ（A7、SR.S=0 のとき有効）。
    pub usp: u32,
    /// スーパーバイザスタックポインタ（A7、SR.S=1 のとき有効）。
    pub ssp: u32,
    /// プログラムカウンタ。
    pub pc: u32,
    /// ステータスレジスタ。下位 16 ビットが有効
    ///（システムバイト: T/S/IPL、ユーザーバイト: CCR の X N Z V C）。
    pub sr: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_guest::GuestIsa;

    #[test]
    fn family_name() {
        assert_eq!(M68k::family(), "m68k");
    }

    #[test]
    fn state_layout_pinned() {
        // sem.rs の StateRef が依存する配置を固定する。
        // 末尾への追加は許すが、既存項目の移動は許さない。
        assert_eq!(core::mem::offset_of!(CpuState, d), 0);
        assert_eq!(core::mem::offset_of!(CpuState, a), 8 * 4);
        assert_eq!(core::mem::offset_of!(CpuState, usp), 8 * 4 + 7 * 4);
        assert_eq!(core::mem::offset_of!(CpuState, ssp), 8 * 4 + 8 * 4);
        assert_eq!(core::mem::offset_of!(CpuState, pc), 8 * 4 + 9 * 4);
        assert_eq!(core::mem::offset_of!(CpuState, sr), 8 * 4 + 10 * 4);
    }

    #[test]
    fn insn_count() {
        // F0 の固定ワード13件 + move/movea 5件 + moveq + C2 の14件
        // + C3 の15件（or/and/eor 9、即値3、単項3）+ C4 の16件（シフトreg/mem）+ C5 の8件（ビット操作）+ C6 の5件（bra/bsr/bcc/jmp/jsr）+ C7 の2件（scc/dbcc）+ C8 の4件 + C9 の6件 + C10 の8件 + C11 の4件 + C12 の5件（bcd）+ C13 の4件（chk/move ccr|sr）+ D2 の12件（extb_l、neg、negx、mull、divl、addx/subx 4、cas 3）。
        assert_eq!(INSNS.len(), 130);
    }

    #[test]
    fn decode_spot_checks() {
        // Ref: SPEC-M68K-PRM (Rev 1).
        assert_eq!(decode(0x4E71, 16), Some(Insn::Nop));
        assert_eq!(decode(0x4E70, 16), Some(Insn::Reset));
        assert_eq!(decode(0x4E73, 16), Some(Insn::Rte));
        assert_eq!(decode(0x4E75, 16), Some(Insn::Rts));
        assert_eq!(decode(0x4E77, 16), Some(Insn::Rtr));
        assert_eq!(decode(0x4AFC, 16), Some(Insn::Illegal));
        assert_eq!(decode(0x4E76, 16), Some(Insn::Trapv));
        assert_eq!(decode(0xA000, 16), Some(Insn::Linea));
        assert_eq!(decode(0xFFFF, 16), Some(Insn::Linef));
        assert_eq!(decode(0x4E60, 16), Some(Insn::Mv2usp));
        assert_eq!(decode(0x4E68, 16), Some(Insn::Mvfrusp));
    }

    #[test]
    fn disasm_word_fixed() {
        assert_eq!(disasm_word(0x4E71, 16).as_deref(), Some("nop"));
    }

    #[test]
    fn cpu_models() {
        assert!(FEATURES.contains(&"m68000"));
        for n in ["i68000", "i68010", "i68020", "i68030", "i68040", "i68060"] {
            assert!(MODELS.contains(&n), "{n}");
        }
        // 親チェーンで世代機能が累積する。
        assert_eq!(
            model_feats("i68060"),
            FEAT_M68000 | FEAT_M68010 | FEAT_M68020 | FEAT_M68030 | FEAT_M68040 | FEAT_M68060
        );
        // 挙動パラメータは世代ごとに上書きされる。
        let p000 = model_params("i68000");
        assert_eq!(p000.odd_access, 0);
        assert!(!p000.mvfrsr_priv);
        assert_eq!(p000.movem_base, 0);
        let p010 = model_params("i68010");
        assert!(p010.mvfrsr_priv);
        assert_eq!(p010.odd_access, 0);
        let p020 = model_params("i68020");
        assert_eq!(p020.odd_access, 1);
        assert_eq!(p020.movem_base, 1);
        // パラメータも親チェーンで継承される。
        assert_eq!(model_params("i68060"), p020);
    }
}
