// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! WebAssembly ゲスト ISA。段階12の本実装。
//!
//! 構成:
//! - `types`: 値型・参照型・外部型・実行時値の定義。
//! - `module`: デコード済みモジュールの形。
//! - `instr`: 命令集合と関数本体バイト列の解読。
//! - `decode`: バイナリ形式（ヘッダ・セクション・LEB128）の検査つき読み出し。
//! - `validate`: モジュールと関数本体の検証（付録のスタック型付け）。
//! - `exec`: ストア・インスタンス化・構造化インタプリタ（専用ループ）。
//! - `sexpr`: `.wast`/`.wat` 向けの S 式読み出し。
//! - `wat`: テキスト形式のモジュールをバイナリへ組み立てる。
//! - `wast`: `.wast` スクリプト（assert_*/invoke/register）の実行。
//!
//! `sem`/`CpuState` は段階2の試作の残置で、生成メタデータと裸
//! バックエンド上の最小の意味論を持つ。本実装は `exec` を使う。
//!
//! 出典は SPEC-WASM-CORE 3.0 (Release 3.0) である。
//! Ref: SPEC-WASM-CORE (3.0).

#![forbid(unsafe_code)]

pub mod decode;
pub mod exec;
pub mod instr;
pub mod module;
pub mod sem;
pub mod sexpr;
pub mod types;
pub mod validate;
pub mod wast;
pub mod wat;

// 空のモデルから生成した殻。ISADL 記述の追加後に中身が増える。
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// WebAssembly の ISA ファミリ名。
pub struct Wasm;

impl polyisa_guest::GuestIsa for Wasm {
    fn family() -> &'static str {
        "wasm"
    }
}

/// 段階2試作の状態（`sem` が参照する）。本実装は `exec::Store` を使う。
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CpuState {
    /// オペランドスタック（i32 のみ。64段）。
    pub stack: [u32; 64],
    /// ローカル変数（8個）。
    pub locals: [u32; 8],
    /// スタックポインタ（次に積む位置）。
    pub sp: u32,
    /// 関数内オフセット。
    pub off: u32,
    /// 関数番号。
    pub func: u32,
}

impl Default for CpuState {
    fn default() -> Self {
        Self {
            stack: [0; 64],
            locals: [0; 8],
            sp: 0,
            off: 0,
            func: 0,
        }
    }
}

/// バイナリから `Validated` を作る（decode+validate）。
pub fn compile(bytes: &[u8]) -> Result<validate::Validated, exec::Error> {
    let m = decode::decode_module(bytes).map_err(exec::Error::Decode)?;
    validate::validate_module(m).map_err(exec::Error::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_guest::GuestIsa;

    #[test]
    fn family_name() {
        assert_eq!(Wasm::family(), "wasm");
    }

    #[test]
    fn state_layout_pinned() {
        assert_eq!(core::mem::offset_of!(CpuState, stack), 0);
        assert_eq!(core::mem::offset_of!(CpuState, locals), 64 * 4);
        assert_eq!(core::mem::offset_of!(CpuState, sp), 64 * 4 + 8 * 4);
        assert_eq!(core::mem::offset_of!(CpuState, off), 64 * 4 + 8 * 4 + 4);
        assert_eq!(core::mem::offset_of!(CpuState, func), 64 * 4 + 8 * 4 + 8);
    }

    #[test]
    fn insn_count() {
        // 試作の整数8件。
        assert_eq!(INSNS.len(), 8);
    }

    #[test]
    fn decode_spot_checks() {
        // オペコードは1バイト。
        // Ref: SPEC-WASM-CORE (3.0).
        assert_eq!(decode(0x00, 8), Some(Insn::Unreachable));
        assert_eq!(decode(0x01, 8), Some(Insn::Nop));
        assert_eq!(decode(0x0C, 8), Some(Insn::Br));
        assert_eq!(decode(0x1A, 8), Some(Insn::Drop));
        assert_eq!(decode(0x20, 8), Some(Insn::LocalGet));
        assert_eq!(decode(0x21, 8), Some(Insn::LocalSet));
        assert_eq!(decode(0x41, 8), Some(Insn::I32Const));
        assert_eq!(decode(0x6A, 8), Some(Insn::I32Add));
        assert_eq!(decode(0xFF, 8), None);
    }

    #[test]
    fn cpu_models() {
        assert!(FEATURES.contains(&"mvp"));
        assert!(MODELS.contains(&"generic"));
    }
}
