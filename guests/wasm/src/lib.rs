// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! WebAssembly 最小のゲスト ISA。段階2の試作であり、スタックマシンとトラップを確かめる。
//!
//! 単一関数の整数演算と、制御フレームのない void 関数の検証を持つ。
//! 線形メモリ・テーブル・グローバル・関数呼び出し・GC は試作に含まない。
//! プログラムカウンタは func（関数番号）と off（関数内オフセット）の組であり、
//! 線形メモリの外にあるコードを指す（自己書き換えなし）。

#![forbid(unsafe_code)]

pub mod sem;
pub mod validate;

// 空のモデルから生成した殻。ISADL 記述の追加後に中身が増える。
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// WebAssembly の ISA ファミリ名。
pub struct Wasm;

impl polyisa_guest::GuestIsa for Wasm {
    fn family() -> &'static str {
        "wasm"
    }
}

/// CPU 状態というより実行フレーム。`#[repr(C)]` で配置を固定する。
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
