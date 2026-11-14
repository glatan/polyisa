// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! AArch64（A64）整数命令。条件フラグ、レジスタ分岐、ペア/排他ロードを裸実行で確かめる。
//!
//! レジスタ 31 は命令形式で SP と ZR に分かれる（加減算とアドレス計算は SP、
//! ほかは ZR）。遅延スロットはない。svc は OS パーソナリティへ委ねる。
//! エンディアンはモデルが持つ（LP64 は LE、BE は FEAT_BE）。

#![forbid(unsafe_code)]

pub mod sem;

// ISADL 記述から生成したデコーダ・命令列挙・モデル表。
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// AArch64 の ISA ファミリ名。
pub struct Aarch64;

impl polyisa_guest::GuestIsa for Aarch64 {
    fn family() -> &'static str {
        "aarch64"
    }
}

/// CPU 状態。`#[repr(C)]` で配置を固定する。
#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct CpuState {
    /// 汎用レジスタ x0〜x30。レジスタ番号 31 は形式により ZR/SP。
    pub x: [u64; 31],
    /// スタックポインタ（SP_EL0）。
    pub sp: u64,
    /// プログラムカウンタ。
    pub pc: u64,
    /// 条件フラグ。下位 4 ビットに N<<3 | Z<<2 | C<<1 | V。
    pub nzcv: u64,
    /// 浮動小数点制御レジスタ。
    pub fpcr: u64,
    /// 浮動小数点状態レジスタ。
    pub fpsr: u64,
    /// スレッドローカル記憶への指針（TPIDR_EL0）。`set_thread_area` が書く。
    /// Ref: SRC-LINUX (7.3) の `arch/arm64/kernel/ptrace.c`。
    pub tpidr: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_guest::GuestIsa;

    #[test]
    fn family_name() {
        assert_eq!(Aarch64::family(), "aarch64");
    }

    #[test]
    fn state_layout_pinned() {
        assert_eq!(core::mem::offset_of!(CpuState, x), 0);
        assert_eq!(core::mem::offset_of!(CpuState, sp), 31 * 8);
        assert_eq!(core::mem::offset_of!(CpuState, pc), 32 * 8);
        assert_eq!(core::mem::offset_of!(CpuState, nzcv), 33 * 8);
        assert_eq!(core::mem::offset_of!(CpuState, fpcr), 34 * 8);
        assert_eq!(core::mem::offset_of!(CpuState, fpsr), 35 * 8);
        assert_eq!(core::mem::offset_of!(CpuState, tpidr), 36 * 8);
    }

    #[test]
    fn cpu_models() {
        assert!(MODELS.contains(&"generic"));
        assert!(MODELS.contains(&"generic_v81"));
    }

    #[test]
    fn decode_spot_checks() {
        // 命令語はビット配置から手で組み立てる。Ref: SPEC-ARM-ARM-A。
        assert_eq!(decode(0x1400_0001, 32), Some(Insn::B));
        assert_eq!(decode(0x9400_0001, 32), Some(Insn::Bl));
        assert_eq!(decode(0x5400_0020, 32), Some(Insn::BCond));
        // ret (Rn=30)
        assert_eq!(decode(0xd65f_03c0, 32), Some(Insn::Ret));
        // nop はヒント空間（SYS の部分集合）に入る
        assert_eq!(decode(0xd503_201f, 32), Some(Insn::Sys));
        // svc #0
        assert_eq!(decode(0xd400_0001, 32), Some(Insn::Svc));
        // movz x0, #0x2a
        assert_eq!(decode(0xd280_0540, 32), Some(Insn::Movz));
        // add x0, x1, #4
        assert_eq!(decode(0x9100_1020, 32), Some(Insn::AddImm));
        // ldr x0, [x1]
        assert_eq!(decode(0xf940_0020, 32), Some(Insn::LdrUX));
        // str x0, [x1]
        assert_eq!(decode(0xf900_0020, 32), Some(Insn::StrUX));
        // stp x0, x1, [sp, #-16]!
        assert_eq!(decode(0xa9bf_07e0, 32), Some(Insn::StpXPre));
        assert_eq!(decode(0xffff_ffff, 32), None);
    }
}
