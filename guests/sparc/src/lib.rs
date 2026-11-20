// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! SPARC のゲスト ISA。段階15の本実装。
//!
//! `CpuState` はグローバル 8 本とウィンドウファイル（最大 32 枚 ×
//! 16 本）の整数レジスタ、浮動小数点レジスタ、PC/nPC、CWP、
//! PSR（V7/V8）と TSTATE（V9）、Y、FSR、GSR、TICK に加え、
//! トラップ種別 `tt`（TBR の tt フィールド相当）と V9 の %ccr を
//! 持つ。`tt` は実行時のトラップ番号を運ぶ状態で、V8 モデルでは
//! V8 の、V9 モデルでは V9 の trap type が入る。見える
//! レジスタ番号 r8-r31 の物理位置は CWP と `nwindows` パラメータで
//! 決まる。遅延スロットは pc/npc の組で表し、分岐の決定と遅延
//! スロットの実行を分ける。
//! 命令とモデルの記述は `spec/sparc.rs` の ISADL モデルから生成する。
//!
//! 出典は SPEC-SPARC-V7 (Solbourne 101482-00)、SPEC-SPARC-V8
//! (Version 8)、SPEC-SPARC-V9 (SAV09R1459912) である。
//! Ref: SPEC-SPARC-V7.
//! Ref: SPEC-SPARC-V8 (Version 8).
//! Ref: SPEC-SPARC-V9.

#![forbid(unsafe_code)]

pub mod sem;

// ISADL モデルから生成した命令集合・デコード・逆アセンブル。
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// SPARC の ISA ファミリ名。
pub struct Sparc;

impl polyisa_guest::GuestIsa for Sparc {
    fn family() -> &'static str {
        "sparc"
    }
}

/// ウィンドウ枚数の上限。仕様の実装範囲は 2 から 32。
/// Ref: SPEC-SPARC-V8 (Version 8) §The Windowed Integer Registers.
pub const NWINDOWS_MAX: usize = 32;

/// 整数レジスタファイルの本数。グローバル 8 本と、ウィンドウ
/// ファイルの最大（`NWINDOWS_MAX` 枚 × 16 本）。実際に使う枚数は
/// `nwindows` パラメータが決め、残りは届かない領域になる。
pub const REG_FILE: usize = 8 + NWINDOWS_MAX * 16;

/// CPU 状態。`#[repr(C)]` で配置を固定し、`StateRef` はここを指す。
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CpuState {
    /// グローバルとウィンドウファイル。V7/V8 は下位 32 ビットだけを使う。
    /// 見える番号から物理番号への対応は CWP と `nwindows` が決める。
    pub g: [u64; REG_FILE],
    /// 浮動小数点レジスタ f0-f31。V7/V8 は 32 ビットとして、
    /// V9 は 64 ビットとして解釈する。
    pub f: [u64; 32],
    /// プログラムカウンタ。
    pub pc: u64,
    /// 次のプログラムカウンタ（遅延スロットの実行先）。
    pub npc: u64,
    /// 現在のウィンドウ。sem はこちらを正本として読み書きし、
    /// PSR/TSTATE の CWP 桁への反映は後続ステップで扱う。
    pub cwp: u64,
    /// annul ビット。1 のとき、次の遅延スロットは実行しない。
    pub annul: u64,
    /// V7/V8 のプロセッサ状態レジスタ（PSR）。CWP 桁は `cwp` が持つ。
    pub psr: u32,
    /// V9 のトラップ状態レジスタ（TSTATE）。CWP 桁は `cwp` が持つ。
    pub tstate: u64,
    /// V7/V8 の Y レジスタ（MULScc と乗除の補助）。
    pub y: u64,
    /// 浮動小数点状態レジスタ（FSR）。V7/V8 と V9 で桁の意味が違う。
    pub fsr: u64,
    /// V9 の GSR（VIS の丸め係数とアライン量）。
    pub gsr: u64,
    /// V9 の %tick の基準（仮想時刻は実行ループが読む）。
    pub tick: u64,
    /// トラップ種別（TBR の tt フィールド相当）。ticc や内部例外が
    /// トラップ番号をここへ積み、OS パーソナリティがベクタ分岐に使う。
    pub tt: u64,
    /// V9 の条件コードレジスタ（%ccr）。下位 4 ビットが ICC、
    /// 上位 4 ビットが XCC。V7/V8 では PSR の ICC を使う。
    pub ccr: u64,
    /// V9 の ASI レジスタ（%asi）。i=1 の ASI 指定形が読む。
    pub asi: u64,
    /// V9 の FPRS（%fprs）。FEF（ビット 2）が f レジスタの有効化。
    pub fprs: u64,
    /// 退避不要で進めるウィンドウ数。V9 の CANSAVE に相当し、
    /// V7/V8 では WIM を近似したカウンタとして使う。SAVE が 0 で
    /// あふれトラップを起こし、OS パーソナリティが最古の窓を
    /// ユーザスタックへ退避してから再実行させる。
    pub cansave: u64,
    /// 復帰先として中身があるウィンドウ数。V9 の CANRESTORE に
    /// 相当する。RESTORE が 0 で不足トラップを起こし、
    /// パーソナリティがスタックから埋め戻してから再実行させる。
    pub canrestore: u64,
}

impl Default for CpuState {
    fn default() -> Self {
        Self {
            g: [0; REG_FILE],
            f: [0; 32],
            pc: 0,
            npc: 4,
            cwp: 0,
            annul: 0,
            psr: 0,
            tstate: 0,
            y: 0,
            fsr: 0,
            gsr: 0,
            tick: 0,
            tt: 0,
            ccr: 0,
            // V9 の ASI_PRIMARY。V8 ではこのフィールドは使わない。
            asi: 0x80,
            fprs: 0,
            // `nwindows` 既定値 8 に合わせて全ウィンドウを空きと
            // する。別の枚数で動かすときは側（パーソナリティや
            // テスト）が枚数 - 1 に合わせて初期化する。
            cansave: 7,
            canrestore: 0,
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
        // sem.rs の StateRef が依存する配置を固定する。
        // 末尾への追加は許すが、既存項目の移動は許さない。
        assert_eq!(core::mem::offset_of!(CpuState, g), 0);
        assert_eq!(core::mem::offset_of!(CpuState, f), REG_FILE * 8);
        assert_eq!(core::mem::offset_of!(CpuState, pc), REG_FILE * 8 + 32 * 8);
        assert_eq!(core::mem::offset_of!(CpuState, npc), REG_FILE * 8 + 33 * 8);
        assert_eq!(core::mem::offset_of!(CpuState, cwp), REG_FILE * 8 + 34 * 8);
        assert_eq!(
            core::mem::offset_of!(CpuState, annul),
            REG_FILE * 8 + 35 * 8
        );
        assert_eq!(core::mem::offset_of!(CpuState, psr), REG_FILE * 8 + 36 * 8);
        // psr は 4 バイトなので、その後ろに 4 バイトのパディングが入る。
        assert_eq!(
            core::mem::offset_of!(CpuState, tstate),
            REG_FILE * 8 + 37 * 8
        );
        assert_eq!(core::mem::offset_of!(CpuState, y), REG_FILE * 8 + 38 * 8);
        assert_eq!(core::mem::offset_of!(CpuState, fsr), REG_FILE * 8 + 39 * 8);
        assert_eq!(core::mem::offset_of!(CpuState, gsr), REG_FILE * 8 + 40 * 8);
        assert_eq!(core::mem::offset_of!(CpuState, tick), REG_FILE * 8 + 41 * 8);
        assert_eq!(core::mem::offset_of!(CpuState, tt), REG_FILE * 8 + 42 * 8);
        assert_eq!(core::mem::offset_of!(CpuState, ccr), REG_FILE * 8 + 43 * 8);
        assert_eq!(core::mem::offset_of!(CpuState, asi), REG_FILE * 8 + 44 * 8);
        assert_eq!(core::mem::offset_of!(CpuState, fprs), REG_FILE * 8 + 45 * 8);
        assert_eq!(
            core::mem::offset_of!(CpuState, cansave),
            REG_FILE * 8 + 46 * 8
        );
        assert_eq!(
            core::mem::offset_of!(CpuState, canrestore),
            REG_FILE * 8 + 47 * 8
        );
    }

    #[test]
    fn insn_count() {
        // 骨格の命令集合（整数演算・load/store 全サイズ・ASI 形・分岐・FPU・VIS）。
        assert_eq!(INSNS.len(), 360);
    }

    #[test]
    fn decode_spot_checks() {
        // 命令語はビット配置から手で組み立てる。Ref: SPEC-SPARC-V8 (Version 8).
        // F3 は op + rd + op3 + rs1 + i + 予約 + rs2 の実符号化である。
        assert_eq!(decode(0x8200_8003, 32), Some(Insn::Add));
        assert_eq!(decode(0x8220_8003, 32), Some(Insn::Sub));
        assert_eq!(decode(0x8208_8003, 32), Some(Insn::And));
        assert_eq!(decode(0x8210_8003, 32), Some(Insn::Or));
        assert_eq!(decode(0x8328_8003, 32), Some(Insn::Sll));
        assert_eq!(decode(0x8fc0_4002, 32), Some(Insn::Jmpl));
        assert_eq!(decode(0xc200_8003, 32), Some(Insn::Ld));
        assert_eq!(decode(0xc620_8000, 32), Some(Insn::St));
        assert_eq!(decode(0x0301_2345, 32), Some(Insn::Sethi));
        assert_eq!(decode(0x1080_0100, 32), Some(Insn::Bicc));
        assert_eq!(decode(0x4080_0100, 32), Some(Insn::Call));
        assert_eq!(decode(0x0000_0000, 32), Some(Insn::Unimp));
        // 即値形（i=1）。
        assert_eq!(decode(0x8200_6003, 32), Some(Insn::AddI));
        assert_eq!(decode(0x81e8_2000, 32), Some(Insn::RestoreI));
        assert_eq!(decode(0xffff_ffff, 32), None);
    }

    #[test]
    fn decode_v9_excludes_v8_privileged() {
        // V8 の特権命令は saved/restored/return/flushw/rdpr/wrpr と
        // 符号化が衝突するので、v9 feature ではデコードしない。
        // Ref: SPEC-SPARC-V9 §Privileged Instructions.
        assert_eq!(
            decode_model_ex(0x81c8_0000, 32, false, FEAT_V7 | FEAT_V8),
            Some(Insn::Rett)
        );
        // V9 では同じ符号化が非特権の return になる。
        assert_eq!(
            decode_model_ex(0x81c8_0000, 32, true, FEAT_V7 | FEAT_V8 | FEAT_V9),
            Some(Insn::Return)
        );
        assert_eq!(
            decode_model_ex(0x8148_0000, 32, true, FEAT_V7 | FEAT_V8 | FEAT_V9),
            None
        );
        assert_eq!(
            decode_model_ex(0x8148_0000, 32, false, FEAT_V7 | FEAT_V8),
            Some(Insn::Rdpsr)
        );
        // v9 ゲート側（rdccr/rdpc）は逆に v9 でのみデコードする。
        assert_eq!(
            decode_model_ex(0x8140_8000, 32, true, FEAT_V7 | FEAT_V8 | FEAT_V9),
            Some(Insn::Rdccr)
        );
        assert_eq!(
            decode_model_ex(0x8140_8000, 32, false, FEAT_V7 | FEAT_V8),
            None
        );
    }

    #[test]
    fn cpu_models() {
        assert!(FEATURES.contains(&"v7"));
        assert!(FEATURES.contains(&"v8"));
        assert!(FEATURES.contains(&"v9"));
        assert!(FEATURES.contains(&"vis"));
        assert!(FEATURES.contains(&"vis2"));
        for n in ["v7", "v8", "v9", "ultrasparc", "ultrasparc3", "leon3"] {
            assert!(MODELS.contains(&n), "{n}");
        }
        // 親チェーンで機能が累積する。
        assert_eq!(model_feats("v8"), FEAT_V7 | FEAT_V8);
        assert_eq!(
            model_feats("ultrasparc"),
            FEAT_V7 | FEAT_V8 | FEAT_V9 | FEAT_VIS
        );
        // パラメータも親チェーンで継承される。
        assert_eq!(model_params("v7").nwindows, 8);
        assert!(!model_params("v8").word64);
        assert!(model_params("v9").word64);
        assert!(model_params("ultrasparc3").word64);
        assert!(!model_params("leon3").word64);
    }
}
