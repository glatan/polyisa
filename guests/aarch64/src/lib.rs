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
    /// FP/SIMD レジスタ v0〜v31。各 128 ビット。
    /// B/H/S/D/Q アクセスは末尾からの部分ビューとして扱う。
    pub v: [u128; 32],
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
        // u128 の 16 バイト整列で 296→304 にパディングされる。
        assert_eq!(core::mem::offset_of!(CpuState, v), 304);
    }

    #[test]
    fn cpu_models() {
        assert!(MODELS.contains(&"generic"));
        assert!(MODELS.contains(&"generic_v81"));
    }

    #[test]
    fn feature_gates_fp_and_asimd_decode() {
        let generic = model_feats("generic");
        assert_ne!(generic & FEAT_FP, 0);
        assert_ne!(generic & FEAT_ASIMD, 0);

        // fmov w1,s0 / str s0,[x0,#4] / dup v0.16b,w1 / ldr q0,[x0,#0x20]
        let fmov = 0x1e26_0001u32;
        let str_s = 0xbd00_0400u32;
        let dup = 0x4e01_0c20u32;
        let ldr_q = 0x3dc0_0800u32;
        let add = 0x9100_1020u32;
        assert_eq!(
            decode_model_ex(u128::from(fmov), 32, true, generic),
            Some(Insn::FmovWS)
        );
        assert_eq!(
            decode_model_ex(u128::from(str_s), 32, true, generic),
            Some(Insn::StrSVu)
        );
        assert_eq!(
            decode_model_ex(u128::from(dup), 32, true, generic),
            Some(Insn::DupGen)
        );
        assert_eq!(
            decode_model_ex(u128::from(ldr_q), 32, true, generic),
            Some(Insn::LdrQVu)
        );

        // FP/ASIMD を両方落としても整数命令は残る。スカラー FP と
        // ベクタアクセスはともにデコードしない。
        let no_fp_simd = generic & !(FEAT_FP | FEAT_ASIMD);
        assert_eq!(
            decode_model_ex(u128::from(add), 32, true, no_fp_simd),
            Some(Insn::AddImm)
        );
        assert_eq!(
            decode_model_ex(u128::from(fmov), 32, true, no_fp_simd),
            None
        );
        assert_eq!(
            decode_model_ex(u128::from(str_s), 32, true, no_fp_simd),
            None
        );
        assert_eq!(decode_model_ex(u128::from(dup), 32, true, no_fp_simd), None);
        assert_eq!(
            decode_model_ex(u128::from(ldr_q), 32, true, no_fp_simd),
            None
        );

        // デバッグ用に機能を個別へ崩した場合は、スカラー FP と
        // ベクタアクセスのゲートが分かれる。
        let fp_only = (generic & !FEAT_ASIMD) | FEAT_FP;
        assert_eq!(
            decode_model_ex(u128::from(fmov), 32, true, fp_only),
            Some(Insn::FmovWS)
        );
        assert_eq!(
            decode_model_ex(u128::from(str_s), 32, true, fp_only),
            Some(Insn::StrSVu)
        );
        assert_eq!(decode_model_ex(u128::from(dup), 32, true, fp_only), None);
        assert_eq!(decode_model_ex(u128::from(ldr_q), 32, true, fp_only), None);
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
