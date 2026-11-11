// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! x86 最小のゲスト ISA。段階4の最小であり、可変長デコードを確かめる。
//!
//! i386 の469件を持つ。ModRM/SIB 汎用・XMM最小・near Jcc・MOVZX・CMOVB・ADD RIP等を含む。
//! REX 接頭辞はデコード前に剥がし、Insは共有して64ビット意味論に切り替える。
//! SYSCALL/CPUID は最小形、ModRM は register-direct（全組合せ）・mod=01+disp8・
//! mod=10+disp32・絶対番地と SIB base+index 形（スケール付き、disp8/disp32・disp なしを含む）を持ち、
//! EFLAGS は CF/PF/AF/ZF/SF/OF の 6 旗を追跡する。条件分岐は符号付き（JL/JGE/JLE/JG）まで持つ。

#![forbid(unsafe_code)]

pub mod sem;

// 空のモデルから生成した殻。ISADL 記述の追加後に中身が増える。
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// x86 の ISA ファミリ名。
pub struct X86;

impl polyisa_guest::GuestIsa for X86 {
    fn family() -> &'static str {
        "x86"
    }
}

/// CPU 状態。`#[repr(C)]` で配置を固定する。
/// レジスタ順は EAX,ECX,EDX,EBX,ESP,EBP,ESI,EDI である。
/// 64ビット拡張の上位32ビットは `h` に置く（x86-64 の RAX..RDI に対応）。
#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct CpuState {
    /// 汎用レジスタ 8本の下位32ビット。
    pub g: [u32; 8],
    /// 命令ポインタの下位32ビット（64ビット実行でも上位は不変とする試作）。
    pub eip: u32,
    /// フラグレジスタ（CF bit0、PF bit2、AF bit4、ZF bit6、SF bit7、OF bit11 を使う）。
    pub eflags: u32,
    /// 汎用レジスタ 8本の上位32ビット（x86-64 のみ使う）。
    pub h: [u32; 8],
    /// 拡張レジスタ R8-R15（64ビット、x86-64 のみ使う）。
    pub x: [u64; 8],
    /// XMM レジスタ 16本。下位・上位の u64 ずつ置く（x86-64 のみ使う）。
    pub xmm: [[u64; 2]; 16],
    /// x87 制御ワード（FNSTCW/FLDCW で使う。run_image が 0x037F に初期化する）。
    pub fcw: u16,
    /// x87 の TOP。空のスタックは 0 で、FLD は 1 減らしてから書く。
    pub top: u16,
    /// x87 レジスタの指数部。bit15 が符号、bit14:0 がバイアス 16383 の指数。
    pub st_exp: [u16; 8],
    /// x87 レジスタの仮数。bit63 が整数ビット。
    pub st_sig: [u64; 8],
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_guest::GuestIsa;

    #[test]
    fn family_name() {
        assert_eq!(X86::family(), "x86");
    }

    #[test]
    fn state_layout_pinned() {
        assert_eq!(core::mem::offset_of!(CpuState, g), 0);
        assert_eq!(core::mem::offset_of!(CpuState, eip), 8 * 4);
        assert_eq!(core::mem::offset_of!(CpuState, eflags), 8 * 4 + 4);
        assert_eq!(core::mem::offset_of!(CpuState, h), 8 * 4 + 4 + 4);
        assert_eq!(core::mem::offset_of!(CpuState, x), 8 * 4 + 4 + 4 + 8 * 4);
        assert_eq!(
            core::mem::offset_of!(CpuState, xmm),
            8 * 4 + 4 + 4 + 8 * 4 + 8 * 8
        );
        assert_eq!(
            core::mem::offset_of!(CpuState, fcw),
            8 * 4 + 4 + 4 + 8 * 4 + 8 * 8 + 16 * 16
        );
        assert_eq!(core::mem::offset_of!(CpuState, top), 394);
        assert_eq!(core::mem::offset_of!(CpuState, st_exp), 396);
        assert_eq!(core::mem::offset_of!(CpuState, st_sig), 416);
    }

    #[test]
    fn insn_count() {
        // 試作の整数117件。
        assert_eq!(INSNS.len(), 725);
    }

    #[test]
    fn decode_spot_checks() {
        // 命令語はビット配置から手で組み立てる。Ref: SPEC-X86-INTEL-SDM。
        assert_eq!(decode(0x90, 8), Some(Insn::Nop));
        assert_eq!(decode(0xF4, 8), Some(Insn::Hlt));
        assert_eq!(decode(0xFC, 8), Some(Insn::Cld));
        assert_eq!(decode(0xFD, 8), Some(Insn::Std));
        assert_eq!(decode(0x98, 8), Some(Insn::Cwde));
        // CDQ/CQO (0x99)。od 0x5acde6 対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x99, 8), Some(Insn::Cdq));
        assert_eq!(decode(0x99, 16), None);
        assert_eq!(decode(0x40, 8), Some(Insn::IncEax));
        assert_eq!(decode(0x41, 8), Some(Insn::IncEcx));
        assert_eq!(decode(0x42, 8), Some(Insn::IncEdx));
        assert_eq!(decode(0x43, 8), Some(Insn::IncEbx));
        assert_eq!(decode(0x44, 8), Some(Insn::IncEsp));
        assert_eq!(decode(0x45, 8), Some(Insn::IncEbp));
        assert_eq!(decode(0x46, 8), Some(Insn::IncEsi));
        assert_eq!(decode(0x47, 8), Some(Insn::IncEdi));
        assert_eq!(decode(0x48, 8), Some(Insn::DecEax));
        assert_eq!(decode(0x49, 8), Some(Insn::DecEcx));
        assert_eq!(decode(0x4A, 8), Some(Insn::DecEdx));
        assert_eq!(decode(0x4B, 8), Some(Insn::DecEbx));
        assert_eq!(decode(0x4C, 8), Some(Insn::DecEsp));
        assert_eq!(decode(0x4D, 8), Some(Insn::DecEbp));
        assert_eq!(decode(0x4E, 8), Some(Insn::DecEsi));
        assert_eq!(decode(0x4F, 8), Some(Insn::DecEdi));
        // 40ビット：opcode + imm32（下位32ビットは don't care）。
        // 試作の word 組立は opcode 上位詰めであり実メモリLE像と逆。fetch結合時に直す。
        assert_eq!(decode(0x05_0000_0001, 40), Some(Insn::AddEax));
        assert_eq!(decode(0x05_ffff_ffff, 40), Some(Insn::AddEax));
        assert_eq!(decode(0xB8_1234_5678, 40), Some(Insn::MovR32Imm));
        assert_eq!(decode(0xBB_1234_5678, 40), Some(Insn::MovR32Imm));
        assert_eq!(decode(0xB8_1234_5678, 32), None);
        // 16ビット：opcode + disp8。
        assert_eq!(decode(0xEBFE, 16), Some(Insn::Jmp8));
        assert_eq!(decode(0xEB00, 16), Some(Insn::Jmp8));
        // 16ビット2バイトオペコード：SYSCALL (0F 05)、CPUID (0F A2)。
        assert_eq!(decode(0x0F05, 16), Some(Insn::Syscall));
        assert_eq!(decode(0x0FA2, 16), Some(Insn::Cpuid));
        // BSWAP r32/r64 (0F C8+rd)。ls -l 0x429c02 対応。REX 剥がし済み.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0FC9, 16), Some(Insn::Bswap));
        assert_eq!(decode(0x0FC8, 16), Some(Insn::Bswap));
        assert_eq!(decode(0x0FCF, 16), Some(Insn::Bswap));
        // ModRM register-direct 全組合せ：ADD (01 /r dst=rm)、MOV (8B /r dst=reg)、
        // CMP (39)、AND (21)、OR (09)、SUB (29)、XOR (31)、MOV store (89 /r dst=rm)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x01C8, 16), Some(Insn::AddRm32));
        assert_eq!(decode(0x01D8, 16), Some(Insn::AddRm32));
        assert_eq!(decode(0x01C3, 16), Some(Insn::AddRm32));
        assert_eq!(decode(0x8BC1, 16), Some(Insn::MovRm32));
        assert_eq!(decode(0x8BD8, 16), Some(Insn::MovRm32));
        // ModRM の mod=00 (メモリ) は register-direct とは一致しない。
        assert_eq!(decode(0x0108, 16), Some(Insn::AddM32R32Memnd));
        assert_eq!(decode(0x8B08, 16), Some(Insn::MovEaxMemnd));
        // スタック操作とコール/リターン：PUSH EAX (50)、POP EAX (58)、PUSH EBP (55)、
        // POP EBP (5D)、CALL rel32 (E8+imm32)、RET (C3)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xE8_0000_0010, 40), Some(Insn::CallRel32));
        assert_eq!(decode(0xC3, 8), Some(Insn::Ret));
        // 比較・条件分岐：CMP EAX,imm32 (3D)、TEST EAX,EAX (85 C0)、JE (74)、JNE (75)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x3D_0000_0001, 40), Some(Insn::CmpEax));
        assert_eq!(decode(0x85C0, 16), Some(Insn::TestRm32));
        // TEST r/m32,r32 mod=00 [base] (85 /r)。find 0x5d17f7 対応.
        // 85 07 は TEST EAX,(RDI).
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x8507, 16), Some(Insn::TestRm32Memnd));
        assert_eq!(decode(0x8507, 8), None);
        assert_eq!(decode(0x7400, 16), Some(Insn::Je));
        assert_eq!(decode(0x75FE, 16), Some(Insn::Jne));
        // 符号なし条件分岐：JB (72)、JAE (73)、JBE (76)、JA (77)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x7200, 16), Some(Insn::Jb));
        assert_eq!(decode(0x7300, 16), Some(Insn::Jae));
        assert_eq!(decode(0x7600, 16), Some(Insn::Jbe));
        assert_eq!(decode(0x7700, 16), Some(Insn::Ja));
        // 符号付き条件分岐：JL (7C)、JGE (7D)、JLE (7E)、JG (7F)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x7C00, 16), Some(Insn::Jl));
        assert_eq!(decode(0x7DFE, 16), Some(Insn::Jge));
        assert_eq!(decode(0x7E00, 16), Some(Insn::Jle));
        assert_eq!(decode(0x7FFE, 16), Some(Insn::Jg));
        assert_eq!(decode(0x7800, 16), Some(Insn::Js));
        assert_eq!(decode(0x7C00, 8), None);
        // C7 /0 (MOV r/m,imm32)：REX は剥がしてあるため Insn を共有する。
        // 64ビット切り替えは dispatch が REX.W で行う。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0000_C7C0_1234_5678, 48), Some(Insn::MovRmImm));
        assert_eq!(decode(0x0000_C7C1_1234_5678, 48), Some(Insn::MovRmImm));
        assert_eq!(decode(0x0000_C700_1234_5678, 48), Some(Insn::MovRmImmMemnd));
        // 83 /r (算術 imm8 群)：/0 ADD、/1 OR、/2 ADC、/3 SBB、
        // /4 AND、/5 SUB、/6 XOR、/7 CMP。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0083_C0F0, 24), Some(Insn::AddRmImm8));
        assert_eq!(decode(0x0083_C9F0, 24), Some(Insn::OrRmImm8));
        assert_eq!(decode(0x0083_D0F0, 24), Some(Insn::AdcRmImm8));
        assert_eq!(decode(0x0083_D9F0, 24), Some(Insn::SbbRmImm8));
        assert_eq!(decode(0x0083_E4F0, 24), Some(Insn::AndRmImm8));
        assert_eq!(decode(0x0083_E0F0, 24), Some(Insn::AndRmImm8));
        assert_eq!(decode(0x0083_E9F0, 24), Some(Insn::SubRmImm8));
        assert_eq!(decode(0x0083_F1F0, 24), Some(Insn::XorRmImm8));
        assert_eq!(decode(0x0083_F9F0, 24), Some(Insn::CmpRmImm8));
        // SUB r/m32,imm8 (29 /5)。64ビット版も同じ語形で REX.W を付ける。
        assert_eq!(decode(0x0083_EB00, 24), Some(Insn::SubRmImm8));
        // SUB r/m32,imm32 (81 /5)。64ビット版は REX.W を付ける。
        assert_eq!(decode(0x81EB_0000_0000, 48), Some(Insn::SubRm32Imm));
        assert_eq!(decode(0x81E8_0000_0000, 48), Some(Insn::SubRm32Imm));
        // mod=01 m8 形：CMP [EBX+disp8],imm8 (83 7B ..) と reg 任意形。
        assert_eq!(decode(0x837B_1000, 32), Some(Insn::CmpRmImm8m8));
        assert_eq!(decode(0x8379_1000, 32), Some(Insn::CmpRmImm8m8));
        assert_eq!(decode(0x837C_1000, 32), None);
        assert_eq!(decode(0x0083_00F0, 24), Some(Insn::AddRmImm8Memnd));
        // string 操作（F3 接頭辞は実行側で剥がす）。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xA4, 8), Some(Insn::Movsb));
        assert_eq!(decode(0xA5, 8), Some(Insn::Movsd));
        assert_eq!(decode(0xAA, 8), Some(Insn::Stosb));
        assert_eq!(decode(0xAB, 8), Some(Insn::Stosd));
        assert_eq!(decode(0xA4, 16), None);
        // ENDBR64 (F3 0F 1E FA)：F3 接頭辞は実行側で剥がす。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F1EFA, 24), Some(Insn::Endbr64));
        assert_eq!(decode(0x0F1EC8, 24), Some(Insn::Rdsspq));
        // NOP r/m (0F 1F /0)：F3/0x66 接頭辞は実行側で剥がす。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F1F00, 24), Some(Insn::Nopl));
        // MOVSXD r,r/m32 (63 /r)。REX.W で 64ビット符号拡張。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x63C6, 16), Some(Insn::Movsxd));
        assert_eq!(decode(0x6300, 16), Some(Insn::MovsxdMemnd));
        // XMM 最小セット（66 接頭辞は実行側で剥がす）。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F6EC6, 24), Some(Insn::MovdXmm));
        assert_eq!(decode(0x0F6E00, 24), None);
        assert_eq!(decode(0x0F60C0, 24), Some(Insn::Punpcklbw));
        assert_eq!(decode(0x0F61C0, 24), Some(Insn::Punpcklwd));
        assert_eq!(decode(0x0F70C000, 32), Some(Insn::Pshufd));
        assert_eq!(decode(0x0F7EC6, 24), Some(Insn::MovqR64Xmm));
        assert_eq!(decode(0x0F10C0, 24), Some(Insn::MovupsLoadXmm));
        assert_eq!(decode(0x0F1107, 24), Some(Insn::MovupsStoreMemnd));
        assert_eq!(decode(0x0F114418F0, 40), Some(Insn::MovupsStoreSibd));
        assert_eq!(decode(0x0F1007, 24), Some(Insn::MovupsLoadMemnd));
        assert_eq!(decode(0x0F104310, 32), Some(Insn::MovupsLoadMem8));
        assert_eq!(decode(0x0F114310, 32), Some(Insn::MovupsStoreMem8));
        assert_eq!(decode(0x0F108368040000, 56), Some(Insn::MovupsLoadMem32));
        assert_eq!(decode(0x0F118368040000, 56), Some(Insn::MovupsStoreMem32));
        assert_eq!(decode(0x0F100433, 32), Some(Insn::MovupsLoadSib));
        assert_eq!(decode(0x0F110433, 32), Some(Insn::MovupsStoreSib));
        assert_eq!(decode(0x0F10443310, 40), Some(Insn::MovupsLoadSibd));
        // MOVAPS xmm, [SIB+disp8] (0F 28)。diff -q 0x4a55eb の 0F 28 44 24 50。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F28442450, 40), Some(Insn::MovapsLoadSibd));
        assert_eq!(decode(0x0F2907, 24), Some(Insn::MovapsStoreMemnd));
        assert_eq!(decode(0x0F294310, 32), Some(Insn::MovapsStoreMem8));
        assert_eq!(decode(0x0FE707, 24), Some(Insn::MovntdqStoreMemnd));
        assert_eq!(decode(0x0FE74310, 32), Some(Insn::MovntdqStoreMem8));
        assert_eq!(decode(0x0F1F0400, 32), Some(Insn::NoplSib));
        assert_eq!(decode(0x0F1F440000, 40), Some(Insn::NoplSibd));
        assert_eq!(decode(0x0F1F840000000000, 64), Some(Insn::NoplSibd32));
        assert_eq!(decode(0x0F100578563412, 56), Some(Insn::MovupsLoadRip));
        assert_eq!(decode(0x0F110578563412, 56), Some(Insn::MovupsStoreRip));
        // near Jcc (0F 80-8F + disp32)。6バイト.
        assert_eq!(decode(0x0F8200000000, 48), Some(Insn::JbRel32));
        assert_eq!(decode(0x0F8700000000, 48), Some(Insn::JaRel32));
        assert_eq!(decode(0x0F8400000000, 48), Some(Insn::JeRel32));
        assert_eq!(decode(0x0F8500000000, 48), Some(Insn::JneRel32));
        assert_eq!(decode(0x0F8000000000, 48), Some(Insn::JoRel32));
        assert_eq!(decode(0x0F8F00000000, 48), Some(Insn::JgRel32));
        // SUB r/m,imm32 (81 /5)。64ビット版は REX.W を付ける.
        assert_eq!(decode(0x81EB00000000, 48), Some(Insn::SubRm32Imm));
        // CMP r/m,imm32 (81 /7)。
        assert_eq!(decode(0x81FB00000000, 48), Some(Insn::CmpRm32Imm));
        // CMP m32,imm32 mod=01 [base+disp8] (81 /7)。81 7D 08 + imm32.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x817D0800000000, 56), Some(Insn::CmpRm32ImmMem8));
        assert_eq!(decode(0x817D0800000000, 48), None);
        // CMP m32,imm32 mod=10 [base+disp32] (81 /7)。ls -l 0x429bda 対応.
        // 81 BD 00 FF FF FF 54 5A 69 66 は [RBP-0x100]==0x66695A54 比較.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(
            decode(0x81BD00FFFFFF545A6966, 80),
            Some(Insn::CmpRm32ImmMem32)
        );
        assert_eq!(decode(0x81BD00FFFFFF545A6966, 64), None);
        // ADD/OR/ADC/SBB/AND/XOR r/m,imm32 (81 /0-6)。64ビット版は REX.W を付ける.
        assert_eq!(decode(0x81C300000000, 48), Some(Insn::AddRm32Imm));
        assert_eq!(decode(0x4881C300000000, 56), Some(Insn::AddRm64Imm));
        assert_eq!(decode(0x81C900000000, 48), Some(Insn::OrRm32Imm));
        assert_eq!(decode(0x81D200000000, 48), Some(Insn::AdcRm32Imm));
        assert_eq!(decode(0x81DB00000000, 48), Some(Insn::SbbRm32Imm));
        assert_eq!(decode(0x81E400000000, 48), Some(Insn::AndRm32Imm));
        assert_eq!(decode(0x81F100000000, 48), Some(Insn::XorRm32Imm));
        assert_eq!(
            decode(0xC78405A0FBFFFF00000000, 88),
            Some(Insn::MovRmImmSibd32)
        );
        assert_eq!(
            decode(0x0F11841590FBFFFF, 64),
            Some(Insn::MovupsStoreSibd32)
        );
        assert_eq!(
            decode(0x0F29841590FBFFFF, 64),
            Some(Insn::MovapsStoreSibd32)
        );
        assert_eq!(decode(0x0FB70500000000, 56), Some(Insn::MovzxR32M16Rip));
        assert_eq!(decode(0x0FB60576641700, 56), Some(Insn::MovzxR32M8Rip));
        assert_eq!(decode(0x0FB6F6, 24), Some(Insn::MovzxR32R8));
        assert_eq!(decode(0x0FB69500F0FFFF, 56), Some(Insn::MovzxR32M8Mem32));
        assert_eq!(decode(0x0FB60406, 32), Some(Insn::MovzxR32M8Sib));
        assert_eq!(decode(0x0FBE0424, 32), Some(Insn::MovsxR32M8Sib));
        assert_eq!(decode(0x0F6F0C0E, 32), Some(Insn::MovdquLoadSib));
        assert_eq!(decode(0x8875BF, 24), Some(Insn::MovM8R8Mem8));
        assert_eq!(decode(0x394F08, 24), Some(Insn::CmpRmMem8));
        assert_eq!(decode(0x390B, 16), Some(Insn::CmpRmMemnd));
        assert_eq!(decode(0x81C900000000, 48), Some(Insn::OrRm32Imm));
        assert_eq!(decode(0x81D200000000, 48), Some(Insn::AdcRm32Imm));
        assert_eq!(decode(0x81DB00000000, 48), Some(Insn::SbbRm32Imm));
        assert_eq!(decode(0x81E400000000, 48), Some(Insn::AndRm32Imm));
        assert_eq!(decode(0x81F100000000, 48), Some(Insn::XorRm32Imm));
        assert_eq!(decode(0x810D0000000000000000, 80), Some(Insn::OrRm32Rip));
        assert_eq!(decode(0x8125D9D11F00F3FE3FFC, 80), Some(Insn::AndRm32Rip));
        assert_eq!(decode(0x81050000000000000000, 80), Some(Insn::AddRm32Rip));
        assert_eq!(decode(0xC7050000000004000000, 80), Some(Insn::MovRmImmRip));
        assert_eq!(decode(0x807C386800, 40), Some(Insn::CmpRm8ImmSibd));
        // ANDB SIB+disp8 (80 /4 mod=01)。grep 0x434710 対応.
        // 80 64 0F 3A F3 は [RDI+RCX+0x3A]&=0xF3.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x80640F3AF3, 40), Some(Insn::AndRm8ImmSibd));
        assert_eq!(decode(0x80640F3AF3, 32), None);
        // CMPB SIB+disp32 (80 /7 mod=10)。stat 0x429875 対応.
        // 80 BC 05 F0 FE FF FF 00 は [RBP+RAX-0x110]==0x00 比較.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x80BC05F0FEFFFF00, 64), Some(Insn::CmpRm8ImmSibd32));
        assert_eq!(decode(0x80BC05F0FEFFFF00, 56), None);
        assert_eq!(decode(0x807F6900, 32), Some(Insn::CmpRm8ImmMem8));
        assert_eq!(decode(0xC6476801, 32), Some(Insn::MovRm8ImmMem8));
        assert_eq!(decode(0x808B5603000080, 56), Some(Insn::OrRm8ImmMem32));
        assert_eq!(decode(0x80F908, 24), Some(Insn::CmpRm8Imm));
        assert_eq!(decode(0xBCFFFFFFFFFFFFFFFF, 72), Some(Insn::MovR64Imm64));
        assert_eq!(decode(0xC785000000000000, 64), Some(Insn::MovRm16ImmM32));
        // MOVW SIB+disp8 (66 C7 /0 SIB mod=01)。stat 0x5af402 対応.
        // 66 C7 44 24 11 53 00 は [RSP+0x11]=0x53。66 剥がし済み.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xC74424115300, 48), Some(Insn::MovRm16ImmSibd));
        assert_eq!(decode(0xC74424115300, 40), None);
        // MOVW SIB (66 C7 /0 SIB mod=00)。hexdump 0x5c82dd 対応.
        // 66 C7 04 24 6C 6C は [R12]=0x6C6C。66 剥がし済み.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xC704246C6C, 40), Some(Insn::MovRm16ImmSib));
        assert_eq!(decode(0xC704246C6C, 32), None);
        // MOVW [base+disp8],imm16 (66 C7 /0 mod=01)。hexdump 0x5c84f9 対応.
        // 66 C7 43 5C 01 01 は [RBX+0x5C]=0x0101。66 剥がし済み.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xC7435C0101, 40), Some(Insn::MovRm16ImmMem8));
        assert_eq!(decode(0xC7435C0101, 32), None);
        // MOVW [RIP+disp32],imm16 (66 C7 05 + disp32 + imm16)。od 0x5ac863 対応.
        // 66 C7 05 54 60 0C 00 01 00 は [RIP+0xC6054]=1。66 剥がし済み.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xC70554600C000100, 64), Some(Insn::MovRm16ImmRip));
        assert_eq!(decode(0xC70554600C000100, 56), None);
        assert_eq!(decode(0xF6C110, 24), Some(Insn::TestRm8Imm));
        assert_eq!(decode(0xA801, 16), Some(Insn::TestAlImm));
        assert_eq!(decode(0xF6050000000002, 56), Some(Insn::TestM8ImmRip));
        assert_eq!(decode(0xF6430402, 32), Some(Insn::TestM8ImmMem8));
        assert_eq!(decode(0xF644240180, 40), Some(Insn::TestM8ImmSibd));
        // TEST m8,SIB mod=00 (F6 /0 SIB)。ls -l 0x40e342 対応。41 F6 04 24 04 は REX.B 剥がし済み.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xF6042404, 32), Some(Insn::TestM8ImmSib));
        assert_eq!(decode(0xF6042404, 24), None);
        assert_eq!(decode(0x803D41DB190000, 56), Some(Insn::CmpRm8ImmRip));
        assert_eq!(decode(0x80A3550300007F, 56), Some(Insn::AndRm8ImmMem32));
        // ANDB m8,imm8 mod=01 [base+disp8] (80 /4)。grep 0x442d1d 対応.
        // 80 67 38 90 は ANDB $0x90,0x38(%rdi).
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x80673890, 32), Some(Insn::AndRm8ImmMem8));
        assert_eq!(decode(0x80673890, 24), None);
        // ORB m8,imm8 mod=01 [base+disp8] (80 /1)。sed 0x5bde04 対応.
        // 80 4B 44 02 は ORB $0x02,0x44(%rbx).
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x804B4402, 32), Some(Insn::OrRm8ImmMem8));
        assert_eq!(decode(0x804B4402, 24), None);
        assert_eq!(decode(0x836F0401, 32), Some(Insn::SubRmImm8Mem8));
        assert_eq!(decode(0x83770401, 32), Some(Insn::XorRmImm8Mem8));
        assert_eq!(decode(0x83480801, 32), Some(Insn::OrRmImm8Mem8));
        assert_eq!(decode(0xFF5710, 24), Some(Insn::CallRMem8));
        assert_eq!(decode(0xC605B188260001, 56), Some(Insn::MovRm8ImmRip));
        assert_eq!(decode(0x338CC198000000, 56), Some(Insn::XorRSibd32));
        assert_eq!(decode(0x0FD68990000000, 56), Some(Insn::MovqM64XmmMem32));
        assert_eq!(decode(0x0FB71441, 32), Some(Insn::MovzxR32M16Sib));
        assert_eq!(decode(0x832000, 24), Some(Insn::AndRmImm8Memnd));
        assert_eq!(decode(0xFFD0, 16), Some(Insn::CallRRm));
        assert_eq!(decode(0xB501, 16), Some(Insn::MovR8Imm));
        assert_eq!(decode(0x0F73FA08, 32), Some(Insn::Pslldq));
        assert_eq!(decode(0x0F73D80D, 32), Some(Insn::Psrldq));
        assert_eq!(decode(0x0FF8D0, 24), Some(Insn::Psubb));
        assert_eq!(decode(0x385407FF, 32), Some(Insn::CmpM8R8Sibd));
        assert_eq!(decode(0xFFC0, 16), Some(Insn::IncRm));
        assert_eq!(decode(0x8A1406, 24), Some(Insn::MovR8M8Sib));
        assert_eq!(decode(0x92, 8), Some(Insn::XchgRdxAx));
        // XCHG CH, CL (86 E9)。base64 0x4bd97a。
        assert_eq!(decode(0x86E9, 16), Some(Insn::XchgR8));
        // DEC DL (FE CA)。dc 0x40efa1。
        assert_eq!(decode(0xFECA, 16), Some(Insn::DecR8));
        assert_eq!(decode(0xFEC2, 16), Some(Insn::IncR8));
        assert_eq!(decode(0x803F2D, 24), Some(Insn::CmpRm8ImmMemnd));
        assert_eq!(decode(0x6AFD, 16), Some(Insn::PushImm8));
        assert_eq!(decode(0xFF9578FFFFFF, 48), Some(Insn::CallRMem32));
        // FF 14 E5 40 15 4E 00: CALL [disp32+index*8]。true 0x403f86 対応.
        // Ref: SPEC-X86-INTEL-SDM.
        assert_eq!(decode(0xFF14E540154E00, 56), Some(Insn::CallRSibabs));
        assert_eq!(decode(0xFF14E540154E00, 24), None);
        assert_eq!(decode(0xFF14F7, 24), Some(Insn::CallRSib));
        // 0F B7 BC 2D C0 A2 4D 00: MOVZX r32,m16 SIB+disp32。echo 0x4c05ba 対応.
        // Ref: SPEC-X86-INTEL-SDM.
        assert_eq!(
            decode(0x0FB7BC2DC0A24D00, 64),
            Some(Insn::MovzxR32M16Sibd32)
        );
        assert_eq!(decode(0x0FB7BC2DC0A24D00, 56), None);
        // FF 85 98 FA FF FF: INC m32 [base+disp32]。uname 0x4b3c4a 対応.
        assert_eq!(decode(0xFF8598FAFFFF, 48), Some(Insn::IncRmMem32));
        // 0F BE 82 A0 A2 4D 00: MOVSX r32,m8 [base+disp32]。echo 0x4c00d6 対応.
        // Ref: SPEC-X86-INTEL-SDM.
        assert_eq!(decode(0x0FBE82A0A24D00, 56), Some(Insn::MovsxR32M8Mem32));
        assert_eq!(decode(0x0FBE82A0A24D00, 48), None);
        // FF 24 F5 28 91 4E 00: JMP [disp32+index*8]。uname 0x4d05e8 対応.
        assert_eq!(decode(0xFF24F528914E00, 56), Some(Insn::JmpRSibabs));
        // 01 14 ED 90 25 71 00: ADD m32,r32 [disp32+index*8]。echo 0x4c08d1 対応.
        // Ref: SPEC-X86-INTEL-SDM.
        assert_eq!(decode(0x0114ED90257100, 56), Some(Insn::AddM32R32Sibabs));
        // ADD m,r SIB mod=00。sort 0x4d2c0d の 01 3C E3。base=5 は直接番地なので別。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x013CE3, 24), Some(Insn::AddM32R32Sib));
        // 39 2C D5 10 24 71 00: CMP m32,r32 [disp32+index*8]。id 0x4bfd44 対応.
        assert_eq!(decode(0x392CD510247100, 56), Some(Insn::CmpM32R32Sibabs));
        // 03 BC 24 E0 00 00 00: ADD r64, [base+disp32] SIB。id 0x4d31d6 対応.
        assert_eq!(decode(0x03BC24E0000000, 56), Some(Insn::AddRSibd32));
        assert_eq!(decode(0x03BC24E0000000, 32), None);
        assert_eq!(decode(0x392CD510247100, 32), None);
        assert_eq!(decode(0x0114ED90257100, 32), None);
        // 83 3C C5 90 25 71 00 00: CMP m64,imm8 [disp32+index*8]。id 0x4c0a78 対応.
        assert_eq!(decode(0x833CC59025710000, 64), Some(Insn::CmpRmImm8Sibabs));
        assert_eq!(decode(0x833CC59025710000, 32), None);
        // 81 65 20 FF 0F 00 00: AND m64,imm32 [base+disp8]。echo/id 0x4c08a2 対応.
        // Ref: SPEC-X86-INTEL-SDM.
        assert_eq!(decode(0x816520FF0F0000, 56), Some(Insn::AndRm32ImmMem8));
        // F7 45 20 00 F0 FF FF: TEST m64,imm32 [base+disp8]。echo 0x4bfb84 対応.
        assert_eq!(decode(0xF7452000F0FFFF, 56), Some(Insn::TestRm32ImmMem8));
        assert_eq!(decode(0xF7452000F0FFFF, 48), None);
        assert_eq!(decode(0x816520FF0F0000, 48), None);
        assert_eq!(decode(0xFF24F528914E00, 24), None);
        assert_eq!(decode(0xFF8598FAFFFF, 40), None);
        // JMP [base+disp8] (FF /4 mod=01)。seq の停止点 0x47e635 に対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xFF6018, 24), Some(Insn::JmpRMem8));
        assert_eq!(decode(0xFF6018, 16), None);
        // MOVSX r32,r/m8 reg-direct (0F BE /r mod=11)。seq の停止点 0x40b775 に対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0FBEC6, 24), Some(Insn::MovsxR32R8));
        // JMP [base+index*scale] (FF /4 SIB mod=00)。seq の停止点 0x40c83b に対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xFF24CA, 24), Some(Insn::JmpRSib));
        assert_eq!(decode(0x630482, 24), Some(Insn::MovsxdSib));
        assert_eq!(decode(0x630571620C00, 48), Some(Insn::MovsxdRip));
        assert_eq!(decode(0x634304, 24), Some(Insn::MovsxdMem8));
        assert_eq!(decode(0x0F443D186D1700, 56), Some(Insn::CmoveRip));
        assert_eq!(decode(0x881DD1DE1600, 48), Some(Insn::MovM8R8Rip));
        assert_eq!(decode(0x2B042528000000, 56), Some(Insn::SubRSibabs));
        assert_eq!(decode(0x335DD8, 24), Some(Insn::XorRMem8));
        assert_eq!(decode(0xC1C808, 24), Some(Insn::RorRm32Imm8));
        assert_eq!(decode(0x0FAFC2, 24), Some(Insn::ImulRRm));
        assert_eq!(decode(0x800C2400, 32), Some(Insn::OrRm8ImmSib));
        assert_eq!(decode(0xFF25DA8F2600, 48), Some(Insn::JmpRRip));
        assert_eq!(decode(0x84FF, 16), Some(Insn::TestR8R8));
        assert_eq!(decode(0x83470C01, 32), Some(Insn::AddRmImm8Mem8));
        assert_eq!(decode(0x0F94C5, 24), Some(Insn::Sete));
        assert_eq!(decode(0x3B2E, 16), Some(Insn::CmpRMemnd));
        assert_eq!(decode(0x3905DFCF1D00, 48), Some(Insn::CmpRmRip));
        assert_eq!(decode(0x0F6F057CC61600, 56), Some(Insn::MovdqaLoadRip));
        assert_eq!(decode(0x0F6F45D0, 32), Some(Insn::MovdquLoadMem8));
        assert_eq!(decode(0x0F6F07, 24), Some(Insn::MovdquLoadMemnd));
        assert_eq!(decode(0x0F290506CB2100, 56), Some(Insn::MovapsStoreRip));
        assert_eq!(decode(0x0345B0, 24), Some(Insn::AddRMem8));
        assert_eq!(decode(0x2B4DC8, 24), Some(Insn::SubRMem8));
        assert_eq!(decode(0x80E580, 24), Some(Insn::AndRm8Imm));
        assert_eq!(decode(0x830D0000000040, 56), Some(Insn::OrRmImm8Rip));
        assert_eq!(decode(0x832577D21F00CF, 56), Some(Insn::AndRmImm8Rip));
        // SUB [RIP+disp32],imm8 (83 2D + disp32 + imm8)。head の停止点 0x417b1b に対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x832D012D250001, 56), Some(Insn::SubRmImm8Rip));
        assert_eq!(decode(0x832D012D250001, 48), None);
        assert_eq!(decode(0x0F6E8500000000, 56), Some(Insn::MovdXmmM32));
        assert_eq!(decode(0x0F6E05930B1E00, 56), Some(Insn::MovdXmmRip));
        assert_eq!(decode(0x0931, 16), Some(Insn::OrM32R32Memnd));
        assert_eq!(decode(0xF7D0, 16), Some(Insn::NotRm32));
        assert_eq!(decode(0xF7D8, 16), Some(Insn::NegRm32));
        assert_eq!(decode(0xF7E1, 16), Some(Insn::MulRm32));
        // IMUL r/m32 (F7 /5)。ls -l 0x4a479e 対応。48 F7 EF は REX.W 剥がし済み.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xF7EF, 16), Some(Insn::ImulRm32));
        assert_eq!(decode(0xF7EF, 8), None);
        assert_eq!(decode(0xF7F7, 16), Some(Insn::DivRm32));
        assert_eq!(decode(0xF7F9, 16), Some(Insn::IdivRm32));
        // DIV m32 SIB+disp8 (F7 /6 mod=01 rm=100)。F7 74 24 0C は [RSP+0x0C].
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xF774240C, 32), Some(Insn::DivRm32Sibd));
        // DIV m32 SIB mod=00 (F7 /6)。xxd 0x473876 の F7 34 24。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xF73424, 24), Some(Insn::DivRm32Sib));
        // MOV m16,imm16 mod=00 [base] (66 C7 /0)。xxd 0x4b240f の C7 07 6C 6C。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xC7076C6C, 32), Some(Insn::MovRm16ImmMemnd));
        assert_eq!(decode(0xF774240C, 24), None);
        assert_eq!(decode(0xA900000001, 40), Some(Insn::TestEaxImm));
        assert_eq!(decode(0x0B1500000000, 48), Some(Insn::OrRRip));
        assert_eq!(decode(0x090500000000, 48), Some(Insn::OrMRip));
        // OR r32,[base+index*scale] (0B /r mod=00 SIB)。0B 04 24 は orl (%rsp),%eax.
        // sed 0x5be0c9 対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0B0424, 24), Some(Insn::OrRSib));
        assert_eq!(decode(0x0B0424, 16), None);
        // CMP m32,r32 SIB [base+index*scale] (39 /r mod=00)。paste 0x5ad26b 対応.
        // 44 39 2C 24 は REX.R 剥がし済み.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x392C24, 24), Some(Insn::CmpM32R32Sib));
        assert_eq!(decode(0x392C24, 16), None);
        // ADD r32,[base+index*scale] (03 /r mod=00 SIB)。md5sum 0x5ca46d 対応.
        // 44 03 0C 9F は REX.R 剥がし済み.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x030C9F, 24), Some(Insn::AddRSib));
        assert_eq!(decode(0x030C9F, 8), None);
        // CMOVNE r64/r32, m64/m32 [RIP+disp32] (0F 45 05 + disp32)。ln 0x5a9e44 対応.
        // 48 0F 45 05 34 00 0C 00 は REX.W 剥がし済み.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F450534000C00, 56), Some(Insn::CmovneRip));
        assert_eq!(decode(0x0F450534000C00, 48), None);
        // XOR r8,[base] (32 /r mod=00)。32 06 は XOR AL,[RSI].
        // cksum 0x5c7fc7 対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x3206, 16), Some(Insn::XorR8M8Memnd));
        assert_eq!(decode(0x3206, 8), None);
        assert_eq!(decode(0x833F0F, 24), Some(Insn::CmpRmImm8Memnd));
        // CMP m32,imm8 mod=10 [base+disp32] (83 /7)。
        assert_eq!(decode(0x83BDD8FBFFFF00, 56), Some(Insn::CmpRmImm8Mem32));
        assert_eq!(decode(0x00C1EA08, 24), Some(Insn::ShrRm32Imm8));
        // CMP [RIP+disp32],imm8 (83 3D + disp32 + imm8)。
        assert_eq!(decode(0x833D0000000038, 56), Some(Insn::CmpRmImm8Rip));
        // CMOVB r,r/m (0F 42 /r)。
        assert_eq!(decode(0x0F42C2, 24), Some(Insn::Cmovb));
        assert_eq!(decode(0x0F45F0, 24), Some(Insn::Cmovne));
        assert_eq!(decode(0x0F44F8, 24), Some(Insn::Cmove));
        assert_eq!(decode(0x0F49C8, 24), Some(Insn::Cmovns));
        assert_eq!(decode(0x0F46E0, 24), Some(Insn::Cmovbe));
        // CMOVBE r, [base+disp8] (0F 46 mod=01)。test 0x4d2874 の 48 0F 46 6B 08。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F466B08, 32), Some(Insn::CmovbeMem8));
        // SUB r32, [base+index*scale] (2B /r SIB mod=00)。basename 0x4898fc の 2B 04 32。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x2B0432, 24), Some(Insn::SubRSib));
        // INC m32 [base+index*scale+disp32] (FF /0 SIB mod=10)。basename 0x4899d0。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xFF849490020000, 56), Some(Insn::IncRmSibd32));
        // ADD m32, r32 SIB+disp32 (01 /r mod=10)。basename 0x48995c の 01 AC 84 90 02 00 00。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x01AC8490020000, 56), Some(Insn::AddM32R32Sibd32));
        assert_eq!(decode(0x0F47CA, 24), Some(Insn::Cmova));
        assert_eq!(decode(0x0F43C0, 24), Some(Insn::Cmovae));
        assert_eq!(decode(0x0F448570FEFFFF, 56), Some(Insn::CmoveM64));
        assert_eq!(decode(0x0F44A518FFFFFF, 56), Some(Insn::CmoveM64));
        // CMOVNE r64,m64 mod=10 [base+disp32] (0F 45)。grep 0x442f5f 対応.
        // 0F 45 85 58 FF FF FF は CMOVNE RAX,[RBP-0xA8].
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F458558FFFFFF, 56), Some(Insn::CmovneM64));
        assert_eq!(decode(0x0F458558FFFFFF, 48), None);
        assert_eq!(decode(0x69C788000000, 48), Some(Insn::ImulRImm));
        // IMUL r64, [SIB+disp8], imm32。mktemp 0x4d85cf の 69 44 24 08 01 00 01 00。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x6944240801000100, 64), Some(Insn::ImulRImmSibd));
        // MOVW [base+index*scale+disp32],imm16。gzip 0x485910 の C7 84 03 6E 0E 00 00 08 00。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(
            decode(0xC784036E0E00000800, 72),
            Some(Insn::MovRm16ImmSibd32)
        );
        // MOVW [base+disp32],imm16。gzip 0x485966 の C7 83 CE 12 00 00 08 00。
        assert_eq!(decode(0xC783CE1200000800, 64), Some(Insn::MovRm16ImmDisp32));
        assert_eq!(decode(0xC785000000000100, 64), Some(Insn::MovRm16ImmM32));
        assert_eq!(decode(0xC784000000000100, 64), None);
        // MOV [base+index*scale+disp32],r。66 付きは16ビット。gzip 0x4859e4。
        assert_eq!(decode(0x898c93ec120000, 56), Some(Insn::MovSibd32Eax));
        // INCW [base+index*scale+disp32]。gzip 0x484ac0 の FF 84 B0 84 04 00 00。
        assert_eq!(decode(0xff84b084040000, 56), Some(Insn::IncRmSibd32));
        // SHL m8,1 [base+disp32]。gzip 0x484b2e の D0 A0 F1 2A 00 00。
        assert_eq!(decode(0xD0A0F12A0000, 48), Some(Insn::ShlM81Mem32));
        // CMPW [base+index*scale],imm8。gzip 0x4846ab の 83 3C 87 00。
        assert_eq!(decode(0x833c8700, 32), Some(Insn::CmpRmImm8Sib));
        // CMP [base], r。66 付きは16ビット。gzip 0x4845d8 の 39 03。
        assert_eq!(decode(0x3903, 16), Some(Insn::CmpRmMemnd));
        // CMP [base+index*scale], r。gzip 0x4845a8 の 39 24 AF。
        assert_eq!(decode(0x3924af, 24), Some(Insn::CmpM32R32Sib));
        // MOV r16, [base]。gzip 0x4847b6 の 8B 06。
        assert_eq!(decode(0x8b06, 16), Some(Insn::MovEaxMemnd));
        // ADD r16, [base]。gzip 0x4847b9 の 03 01。
        assert_eq!(decode(0x0301, 16), Some(Insn::AddRMemnd));
        // DEC [base+disp32]。gzip 0x484714 の FF 8B F4 2A 00 00。
        assert_eq!(decode(0xff8bf42a0000, 48), Some(Insn::DecRmMem32));
        // SUB [base+disp32], r32。gzip 0x48473b の 29 83 F8 2A 00 00。
        assert_eq!(decode(0x2983f82a0000, 48), Some(Insn::SubM32R32Mem32));
        // INC [base+disp32]。66 付きは16ビット。gzip 0x484a42 の FF 82 A8 13 00 00。
        assert_eq!(decode(0xff82a8130000, 48), Some(Insn::IncRmMem32));
        // ADD [base+index*scale+disp32], r。gzip 0x484a11 の 01 8C 82 64 13 00 00。
        assert_eq!(decode(0x018c8264130000, 56), Some(Insn::AddM32R32Sibd32));
        // CMPW [base+index*scale+disp32],imm8。gzip 0x485212 の 83 BC 8C 66 13 00 00 00。
        assert_eq!(decode(0x83bc8c6613000000, 64), Some(Insn::CmpRmImm8Sibd32));
        // AND [base+index*scale], r32。bzip2 0x47f93d の 21 0C 94。
        assert_eq!(decode(0x210c94, 24), Some(Insn::AndM32R32Sib));
        // AND (%rdi), %rax。chat 0x4d3473 の 21 07。
        assert_eq!(decode(0x2107, 16), Some(Insn::AndM32R32Memnd));
        // SHL [base+disp8],imm8。bzip2 0x480237 の C1 67 70 08。
        assert_eq!(decode(0xC1677008, 32), Some(Insn::ShlM32Imm8Mem8));
        // ADD [SIB+disp8],imm32。bzip2 0x480dcd の 81 44 24 28 02 01 00 00。
        assert_eq!(decode(0x8144242802010000, 64), Some(Insn::AddRm32ImmSibd));
        // OR r, [SIB+disp32]。bzip2 0x480ec8 の 0B 94 07 98 00 00 00。
        assert_eq!(decode(0x0B940798000000, 56), Some(Insn::OrRSibd32));
        // OR [index*scale+disp32], r。dd 0x4cde66 の 09 04 CD 90 36 71 00。
        assert_eq!(decode(0x0904CD00200000, 56), Some(Insn::OrM32R32Sibabs));
        // IMUL r, [SIB], imm32。dd 0x4067c3 の 69 0C 24 40 42 0F 00。
        assert_eq!(decode(0x690C2440420F00, 56), Some(Insn::ImulRImmSib));
        // DIVSD xmm,m64 RIP。dd 0x4928e8 の 0F 5E 05 + disp32。
        assert_eq!(decode(0x0F5E05F80F0000, 56), Some(Insn::DivsdXmmM64Rip));
        assert_eq!(decode(0x0F5EC8, 24), Some(Insn::Divsd));
        // FLD m80 RIP。dd 0x4d0e58 の DB 2D + disp32。
        assert_eq!(decode(0xDB2DFA0F0000, 48), Some(Insn::FldM80Rip));
        assert_eq!(decode(0x6B1567FD1A0038, 56), Some(Insn::ImulRImm8Rip));
        assert_eq!(decode(0x6BF638, 24), Some(Insn::ImulRImm8));
        assert_eq!(decode(0x00C1F908, 24), Some(Insn::SarRm32Imm8));
        // BT r/m32,r32 (0F A3 /r mod=11)。wc の停止点 0x5b380d に対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0FA3E8, 24), Some(Insn::BtR32Rm));
        assert_eq!(decode(0x0FA3E8, 8), None);
        assert_eq!(decode(0x00D3FF, 16), Some(Insn::SarRm32Cl));
        assert_eq!(decode(0x00D3E0, 16), Some(Insn::ShlRm32Cl));
        assert_eq!(decode(0x00D1FF, 16), Some(Insn::SarRm321));
        // ROL r/m32,1 (D1 /0 mod=11)。D1 C2 は roll $1,%edx.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x00D1C2, 16), Some(Insn::RolRm321));
        assert_eq!(decode(0x00D1C2, 8), None);
        // ROR r/m64,1 (D1 /1 mod=11)。sha512sum 0x4b47c4 の 48 D1 C9。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x00D1C9, 16), Some(Insn::RorRm321));
        // ADD r,[RIP+disp32] (03 05 + disp32)。
        assert_eq!(decode(0x030500000000, 48), Some(Insn::AddRRip));
        // MOVZX r32,m16 mod=10 (0F B7 /r)。
        assert_eq!(decode(0x0FB7B7F0020000, 56), Some(Insn::MovzxR32M16Mem32));
        assert_eq!(
            decode(0xC78405A0FBFFFF00000000, 88),
            Some(Insn::MovRmImmSibd32)
        );
        assert_eq!(decode(0xC7042410000000, 56), Some(Insn::MovRmImmSib));
        assert_eq!(
            decode(0xC704251406000002000000, 88),
            Some(Insn::MovRmImmSibabs)
        );
        // C7 04 CD + disp32 + imm32: MOV [disp32+index*8],imm32。echo/id 0x4bfc0e 対応.
        assert_eq!(
            decode(0xC704CDC023710000000000, 88),
            Some(Insn::MovRmImmSibabs)
        );
        assert_eq!(decode(0x85D2, 16), Some(Insn::TestRm32));
        assert_eq!(decode(0x0F285710, 32), Some(Insn::MovapsLoadMem8));
        assert_eq!(decode(0x0F28F5, 24), Some(Insn::MovapsLoadXmm));
        assert_eq!(decode(0x0FBDC0, 24), Some(Insn::BsrRRm));
        assert_eq!(decode(0x3C02, 16), Some(Insn::CmpAlImm));
        assert_eq!(decode(0x3B3C2510000000, 56), Some(Insn::CmpRSibabs));
        assert_eq!(decode(0x873DB6381A00, 48), Some(Insn::XchgRRip));
        assert_eq!(decode(0xC60000, 24), Some(Insn::MovRm8ImmMemnd));
        // MOVB [RAX],0x25 (C6 00 25): stat 0x40c912 対応。imm 下位3=101 でも decode する.
        // MR形式の where 地雷対策 (M8 で ModRM 位置を見る).
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xC60025, 24), Some(Insn::MovRm8ImmMemnd));
        assert_eq!(decode(0xC60025, 16), None);
        assert_eq!(decode(0x0FB77416FE, 40), Some(Insn::MovzxR32M16Sibd));
        assert_eq!(decode(0x8A0E, 16), Some(Insn::MovR8M8Memnd));
        assert_eq!(decode(0xFF157D111A00, 48), Some(Insn::CallRRip));
        assert_eq!(decode(0x0F744810, 32), Some(Insn::PcmpeqbMem8));
        assert_eq!(decode(0x019578FEFFFF, 48), Some(Insn::AddM32R32Mem32));
        assert_eq!(decode(0xF7C400080000, 48), Some(Insn::TestRm32Imm));
        assert_eq!(decode(0x0FEFC0, 24), Some(Insn::Pxor));
        assert_eq!(decode(0x0FBCC0, 24), Some(Insn::BsfRRm));
        assert_eq!(decode(0x0FD7C0, 24), Some(Insn::Pmovmskb));
        assert_eq!(decode(0x0F74C1, 24), Some(Insn::Pcmpeqb));
        // MULSD xmm,xmm (F2 0F 59 /r mod=11)。seq の停止点 0x5adf8c に対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F59C2, 24), Some(Insn::Mulsd));
        assert_eq!(decode(0x0F59C2, 8), None);
        // ADDSD xmm,m64 SIB mod=00 (F2 0F 58)。seq の停止点 0x5adf90 に対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F580424, 32), Some(Insn::AddsdM64Sib));
        assert_eq!(decode(0x0F580424, 24), None);
        // ADDSD xmm,m64 SIB+disp8 (F2 0F 58)。seq 0x499253 の 0F 58 44 24 10。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F58442410, 40), Some(Insn::AddsdXmmM64Sibd));
        assert_eq!(decode(0x0F58442410, 32), None);
        // ANDPD xmm,xmm / xmm,[RIP+disp32] (66 0F 54)。seq の停止点 0x45b75b に対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F54C0, 24), Some(Insn::Andpd));
        assert_eq!(decode(0x0F54C0, 16), None);
        assert_eq!(decode(0x0F540D1DFE1900, 56), Some(Insn::AndpdRip));
        assert_eq!(decode(0x0F540D1DFE1900, 48), None);
        // UCOMISD xmm,xmm (66 0F 2E /r mod=11)。seq の停止点 0x45b74d に対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F2EC0, 24), Some(Insn::Ucomisd));
        assert_eq!(decode(0x0F2EC0, 16), None);
        // UCOMISD xmm,m64 mod=00/01/10/RIP (66 0F 2E)。seq の停止点 0x45b763 に対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F2E03, 24), Some(Insn::UcomisdMemnd));
        assert_eq!(decode(0x0F2E03, 16), None);
        assert_eq!(decode(0x0F2E4840, 32), Some(Insn::UcomisdMem8));
        assert_eq!(decode(0x0F2E4840, 24), None);
        assert_eq!(decode(0x0F2E8300000000, 56), Some(Insn::UcomisdMem32));
        assert_eq!(decode(0x0F2E8300000000, 48), None);
        assert_eq!(decode(0x0F2E0D351A1A00, 56), Some(Insn::UcomisdRip));
        assert_eq!(decode(0x0F2E0D351A1A00, 48), None);
        assert_eq!(decode(0x0F76C0, 24), Some(Insn::Pcmpeqd));
        assert_eq!(decode(0x0FDAEC, 24), Some(Insn::Pminub));
        // PMAXUB xmm,xmm (66 0F DE /r)。df 0x4d0bcd 対応。66 剥がし済み.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0FDED8, 24), Some(Insn::Pmaxub));
        assert_eq!(decode(0x0FDED8, 16), None);
        // AND AX,imm16 (66 25 + imm16)。seq の停止点 0x476e57 に対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x250C00, 24), Some(Insn::AndAxImm16));
        assert_eq!(decode(0x250C00, 8), None);
        // CMP AX,imm16 (66 3D + imm16)。seq の停止点 0x476e5b に対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x3D0800, 24), Some(Insn::CmpAxImm16));
        assert_eq!(decode(0x3D0800, 8), None);
        // ADD r/m16,imm16 (66 81 /0 mod=11)。seq の停止点 0x4c4677 に対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x81C6FF03, 32), Some(Insn::AddRm16Imm));
        assert_eq!(decode(0x81C6FF03, 8), None);
        // AND r/m16,imm16 (66 81 /4 mod=11)。seq の停止点 0x40b7f1 に対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x81E2FF08, 32), Some(Insn::AndRm16Imm));
        // CMP r/m16,imm16 (66 81 /7)。basename 0x4bfaa8 の 66 81 FF C0 0F。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x81FFC00F, 32), Some(Insn::CmpRm16Imm));
        assert_eq!(decode(0x81E2FF08, 8), None);
        // PMINUB xmm,m128 mod=00/01/10 (66 0F DA /r、SIBなし)。head の停止点 0x4dddd5 に対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0FDA03, 24), Some(Insn::PminubMemnd));
        assert_eq!(decode(0x0FDA03, 16), None);
        assert_eq!(decode(0x0FDA4050, 32), Some(Insn::PminubMem8));
        assert_eq!(decode(0x0FDA4050, 24), None);
        assert_eq!(decode(0x0FDA8300000000, 56), Some(Insn::PminubMem32));
        assert_eq!(decode(0x0FDA8300000000, 48), None);
        // FNSTCW/FLDCW m16 mod=00/01/10 (D9 /7//5)。seq の停止点 0x476e4a に対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xD93B, 16), Some(Insn::FnstcwMemnd));
        assert_eq!(decode(0xD93B, 24), None);
        assert_eq!(decode(0xD97DC6, 24), Some(Insn::FnstcwMem8));
        assert_eq!(decode(0xD97DC6, 8), None);
        assert_eq!(decode(0xD9BB00000000, 48), Some(Insn::FnstcwMem32));
        assert_eq!(decode(0xD9BB00000000, 56), None);
        assert_eq!(decode(0xD92B, 16), Some(Insn::FldcwMemnd));
        assert_eq!(decode(0xD92B, 24), None);
        assert_eq!(decode(0xD96DC6, 24), Some(Insn::FldcwMem8));
        assert_eq!(decode(0xD96DC6, 8), None);
        assert_eq!(decode(0xD9AB00000000, 48), Some(Insn::FldcwMem32));
        assert_eq!(decode(0xD9AB00000000, 56), None);
        assert_eq!(decode(0x8305DF641F0001, 56), Some(Insn::AddRm32Imm8Rip));
        assert_eq!(decode(0x0FEBC4, 24), Some(Insn::Por));
        // POR xmm,m128 SIB+disp32 (66 0F EB mod=10 rm=100)。grep 0x43d15b 対応.
        // 66 は剥がし済み。0F EB 84 9D C0 DFFF FF は por xmm0,[rbp+rbx*4-0x2040].
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0FEB849DC0DFFFFF, 64), Some(Insn::PorSibd32));
        assert_eq!(decode(0x0FEB849DC0DFFFFF, 56), None);
        assert_eq!(decode(0x0F62C0, 24), Some(Insn::Punpckldq));
        assert_eq!(decode(0x0F6CC0, 24), Some(Insn::Punpcklqdq));
        assert_eq!(decode(0x0F6FC0, 24), Some(Insn::MovdquLoadXmm));
        // REX 剥離後の代表値：44 0F 6F CD (MOVDQA xmm9,xmm5) は 0F 6F CD として decode する.
        assert_eq!(decode(0x0F6FCD, 24), Some(Insn::MovdquLoadXmm));
        assert_eq!(decode(0x0F6F4020, 32), Some(Insn::MovdquLoadMem8));
        assert_eq!(decode(0x0F6F07, 24), Some(Insn::MovdquLoadMemnd));
        // MOVDQU m128,xmm (F3 0F 7F) と MOVDQA m128,xmm (66 0F 7F)。F3/66 は剥がし済み.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F7FC0, 24), Some(Insn::MovdquStoreXmm));
        assert_eq!(decode(0x0F7F07, 24), Some(Insn::MovdquStoreMemnd));
        assert_eq!(decode(0x0F7F4020, 32), Some(Insn::MovdquStoreMem8));
        assert_eq!(decode(0x88042511060000, 56), Some(Insn::MovSibabsR8));
        assert_eq!(decode(0x0FDBC1, 24), Some(Insn::Pand));
        assert_eq!(decode(0x0FD60500000000, 56), Some(Insn::MovqM64XmmRip));
        assert_eq!(decode(0x0F7E05F1D11F00, 56), Some(Insn::MovqXmmM64Rip));
        assert_eq!(decode(0x0F10841590FBFFFF, 64), Some(Insn::MovupsLoadSibd32));
        assert_eq!(
            decode(0x0F11841590FBFFFF, 64),
            Some(Insn::MovupsStoreSibd32)
        );
        assert_eq!(
            decode(0x0F29841590FBFFFF, 64),
            Some(Insn::MovapsStoreSibd32)
        );
        // C7 /0 m64,imm32 (RBP+disp32)。
        assert_eq!(decode(0xC7850000000000000000, 80), Some(Insn::MovRmImmM32));
        assert_eq!(decode(0xC7839004000001000000, 80), Some(Insn::MovRmImmM32));
        assert_eq!(decode(0xC74004FFFFFFFF, 56), Some(Insn::MovRmImmM8));
        assert_eq!(decode(0xC700FFFFFFFF, 48), Some(Insn::MovRmImmMemnd));
        assert_eq!(decode(0xC744240810000000, 64), Some(Insn::MovRmImmSibd));
        // ループと近傍ジャンプ：LOOP rel8 (E2)、JMP rel32 (E9)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xE2FE, 16), Some(Insn::Loop));
        assert_eq!(decode(0xE9_0000_0010, 40), Some(Insn::JmpRel32));
        // 実バイナリ頻出イディオム：XOR r/m32,r32 (31 /r。31 C0 はゼロ化)、SUB EAX,imm32 (2D)、
        // MOV r/m32,r32 (89 /r。89 E5 は関数枠の入口)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x31C0, 16), Some(Insn::XorRm32));
        assert_eq!(decode(0x31C9, 16), Some(Insn::XorRm32));
        assert_eq!(decode(0x3108, 16), None);
        assert_eq!(decode(0x2D_0000_0001, 40), Some(Insn::SubEax));
        assert_eq!(decode(0x29C8, 16), Some(Insn::SubRm32));
        assert_eq!(decode(0x29D8, 16), Some(Insn::SubRm32));
        assert_eq!(decode(0x89E5, 16), Some(Insn::MovMr32));
        assert_eq!(decode(0x89D8, 16), Some(Insn::MovMr32));
        assert_eq!(decode(0xC9, 8), Some(Insn::Leave));
        // PUSH/POP r32 全レジスタ：PUSH 50+r、POP 58+r。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x50, 8), Some(Insn::PushEax));
        assert_eq!(decode(0x51, 8), Some(Insn::PushEcx));
        assert_eq!(decode(0x52, 8), Some(Insn::PushEdx));
        assert_eq!(decode(0x53, 8), Some(Insn::PushEbx));
        assert_eq!(decode(0x54, 8), Some(Insn::PushEsp));
        assert_eq!(decode(0x55, 8), Some(Insn::PushEbp));
        assert_eq!(decode(0x56, 8), Some(Insn::PushEsi));
        assert_eq!(decode(0x57, 8), Some(Insn::PushEdi));
        assert_eq!(decode(0x58, 8), Some(Insn::PopEax));
        assert_eq!(decode(0x59, 8), Some(Insn::PopEcx));
        assert_eq!(decode(0x5A, 8), Some(Insn::PopEdx));
        assert_eq!(decode(0x5B, 8), Some(Insn::PopEbx));
        assert_eq!(decode(0x5C, 8), Some(Insn::PopEsp));
        assert_eq!(decode(0x5D, 8), Some(Insn::PopEbp));
        assert_eq!(decode(0x5E, 8), Some(Insn::PopEsi));
        assert_eq!(decode(0x5F, 8), Some(Insn::PopEdi));
        // EAX-imm32 群の残り：AND (25)、OR (0D)、XOR imm (35)。
        // ADD (05)/SUB (2D)/CMP (3D) と合わせ6種が揃う。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x25_1234_5678, 40), Some(Insn::AndEax));
        assert_eq!(decode(0x0D_FFFF_FFFF, 40), Some(Insn::OrEax));
        // OR AX,imm16 (66 0D)。seq 0x4d74c9 の 66 0D FE 3F。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0DFE3F, 24), Some(Insn::OrAxImm16));
        // FLD m80 SIB (DB /5)。seq 0x4d74d4 の DB 2C 24。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xDB2C24, 24), Some(Insn::FldM80Sib));
        // FSTP m80 SIB+disp8 (DB /7)。seq 0x4d74d7 の DB 7C 24 20。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xDB7C2420, 32), Some(Insn::FstpM80Sibd));
        // FADD ST(0), ST(0) (D8 C0)。seq 0x4d097d。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xD8C0, 16), Some(Insn::FaddSt));
        // FLDZ (D9 EE)。seq 0x4d097f。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xD9EE, 16), Some(Insn::Fldz));
        // FXCH ST(1) (D9 C9)。seq 0x4d0981。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xD9C9, 16), Some(Insn::FxchSt));
        // FUCOMI ST(1) (DB E9)。seq 0x4d0983。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xDBE9, 16), Some(Insn::FucomiSt));
        // FUCOMIP ST(1) (DF E9)。dd 0x4d0ea6。
        assert_eq!(decode(0xDFE9, 16), Some(Insn::FucomipSt));
        // FMUL m32 RIP (D8 /1)。seq 0x4d0bf4 の D8 0D FA 0F 00 00。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xD80DFA0F0000, 48), Some(Insn::FmulM32Rip));
        // SUB m32,imm8 SIB+disp8 (83 /5)。seq 0x4d0bfa の 83 6C 24 58 1C。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x836C24581C, 40), Some(Insn::SubRmImm8Sibd));
        // XOR m64,imm8 SIB+disp8 (83 /6)。sort 0x4d3045 の 83 74 24 10 07。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x8374241007, 40), Some(Insn::XorRmImm8Sibd));
        // FNSTCW m16 SIB+disp8 (D9 /7)。seq 0x4d0c17 の D9 7C 24 4E。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xD97C244E, 32), Some(Insn::FnstcwSibd));
        // FLDCW m16 SIB+disp8 (D9 /5)。seq 0x4d0c2d の D9 6C 24 4C。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xD96C244C, 32), Some(Insn::FldcwSibd));
        // FISTP m64 SIB+disp8 (DF /7)。seq 0x4d0c31 の DF 7C 24 30。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xDF7C2430, 32), Some(Insn::FistpM64Sibd));
        // FILD m64 SIB+disp8 (DF /5)。seq 0x4d0c4d の DF 6C 24 30。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xDF6C2430, 32), Some(Insn::FildM64Sibd));
        // AND r32, [SIB+disp8] (23 /r)。seq 0x4d0d34 の 23 7C 24 3C。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x237C243C, 32), Some(Insn::AndRSibd));
        assert_eq!(decode(0x35_0000_00FF, 40), Some(Insn::XorImm));
        // シフト：SHL EAX,imm8 (C1 E0 ib)、SHR EAX,imm8 (C1 E8 ib)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x00C1_E002, 24), Some(Insn::ShlRm32Imm8));
        assert_eq!(decode(0x00C1_E81F, 24), Some(Insn::ShrRm32Imm8));
        assert_eq!(decode(0x00C1_E320, 24), Some(Insn::ShlRm32Imm8));
        // /6 (110) や mod=00 は別命令であり一致しない。
        assert_eq!(decode(0x00C1_F002, 24), None);
        assert_eq!(decode(0x00C1_2002, 24), None);
        // INT 0x80 (CD 80)：i386 のシステムコール命令。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xCD80, 16), Some(Insn::Int80));
        assert_eq!(decode(0xCD81, 16), None);
        // LEA 汎用形：base/index 任意。dst=reg は実行側で抽出する。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x008D_4310, 24), Some(Insn::LeaM8));
        assert_eq!(decode(0x008D_4B10, 24), Some(Insn::LeaM8));
        assert_eq!(decode(0x008D_8310, 24), None);
        assert_eq!(decode(0x8D83_7856_3412, 48), Some(Insn::LeaM32));
        assert_eq!(decode(0x8D8B_7856_3412, 48), Some(Insn::LeaM32));
        // SIB+disp32 形は 56ビット長でなければ一致しない。
        assert_eq!(decode(0x8D84_7856_3412, 48), None);
        assert_eq!(decode(0x8D43_7856_3412, 48), None);
        assert_eq!(decode(0x8D03, 16), Some(Insn::LeaMnd));
        assert_eq!(decode(0x8D1B, 16), Some(Insn::LeaMnd));
        assert_eq!(decode(0x8D05, 16), None);
        assert_eq!(decode(0x8D05_7856_3412, 48), Some(Insn::LeaAbs));
        assert_eq!(decode(0x008D_0433, 24), Some(Insn::LeaSib));
        assert_eq!(decode(0x008D_0425, 24), None);
        assert_eq!(decode(0x8D44_3310, 32), Some(Insn::LeaSibd));
        assert_eq!(decode(0x8D44_7B10, 32), Some(Insn::LeaSibd));
        assert_eq!(decode(0x008D_8473_1000_0000, 56), Some(Insn::LeaSibd32));
        assert_eq!(decode(0x008D_84FB_1000_0000, 56), Some(Insn::LeaSibd32));
        assert_eq!(decode(0x008D_0475_1000_0000, 56), Some(Insn::LeaSibabs));
        assert_eq!(decode(0x008D_04F5_1000_0000, 56), Some(Insn::LeaSibabs));
        assert_eq!(decode(0x008D_0433_1000_0000, 56), None);
        assert_eq!(decode(0x39C8, 16), Some(Insn::CmpRm32));
        assert_eq!(decode(0x39D8, 16), Some(Insn::CmpRm32));
        assert_eq!(decode(0x39AD60FEFFFF, 48), Some(Insn::CmpRmMem32));
        assert_eq!(decode(0x0F43AD68FEFFFF, 56), Some(Insn::CmovaeM64));
        assert_eq!(decode(0x033C2500000000, 56), Some(Insn::AddRSibabs));
        assert_eq!(decode(0x21C8, 16), Some(Insn::AndRm32));
        assert_eq!(decode(0x21D8, 16), Some(Insn::AndRm32));
        assert_eq!(decode(0x09C8, 16), Some(Insn::OrRm32));
        assert_eq!(decode(0x09D8, 16), Some(Insn::OrRm32));
        // mod=01 の 39 /r は register-direct ではなく一致しない。
        assert_eq!(decode(0x397C, 16), None);
        // ModRM 汎用形：base は実行側で抽出する。SIB (rm=100) と絶対番地 (rm=101)
        // は別 Insn であり一致しない。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x008B_4310, 24), Some(Insn::MovEaxMem8));
        assert_eq!(decode(0x008B_4B10, 24), Some(Insn::MovEaxMem8));
        assert_eq!(decode(0x0089_43F0, 24), Some(Insn::MovMemEax8));
        // base/reg 任意：MOV ECX,[EBP+disp8] (8B 4D ..) も同じ Insn。
        assert_eq!(decode(0x008B_4D10, 24), Some(Insn::MovEaxMem8));
        assert_eq!(decode(0x0089_4DF0, 24), Some(Insn::MovMemEax8));
        assert_eq!(decode(0x008B_4410, 24), None);
        assert_eq!(decode(0x8B03, 16), Some(Insn::MovEaxMemnd));
        assert_eq!(decode(0x8B0B, 16), Some(Insn::MovEaxMemnd));
        assert_eq!(decode(0x0313, 16), Some(Insn::AddRMemnd));
        assert_eq!(decode(0x8903, 16), Some(Insn::MovMemndEax));
        assert_eq!(decode(0x8B00, 16), Some(Insn::MovEaxMemnd));
        assert_eq!(decode(0x8B04, 16), None);
        assert_eq!(decode(0x8B05, 16), None);
        assert_eq!(decode(0x8B83_7856_3412, 48), Some(Insn::MovEaxMem32));
        assert_eq!(decode(0x8B8B_7856_3412, 48), Some(Insn::MovEaxMem32));
        assert_eq!(decode(0x8983_7856_3412, 48), Some(Insn::MovMemEax32));
        assert_eq!(decode(0x8B84_7856_3412, 48), None);
        assert_eq!(decode(0x8B05_7856_3412, 48), Some(Insn::MovEaxAbs));
        assert_eq!(decode(0x8905_7856_3412, 48), Some(Insn::MovAbsEax));
        // reg 任意：MOV [RIP+disp32],RDI (89 3D ..) も同じ Insn。
        assert_eq!(decode(0x893D_C2D6_1F00, 48), Some(Insn::MovAbsEax));
        // mod違い・長さ違いは一致しない。
        assert_eq!(decode(0x8B43_7856_3412, 48), None);
        assert_eq!(decode(0x8B83_7856_3412, 32), None);
        assert_eq!(decode(0x008B_8310, 24), None);
        // SIB 汎用形：scale/index/base は実行側で抽出する。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x008B_0433, 24), Some(Insn::MovEaxSib));
        assert_eq!(decode(0x008B_0434, 24), Some(Insn::MovEaxSib));
        assert_eq!(decode(0x008B_0425, 24), None);
        assert_eq!(decode(0x0089_0433, 24), Some(Insn::MovSibEax));
        assert_eq!(decode(0x8B44_3310, 32), Some(Insn::MovEaxSibd));
        assert_eq!(decode(0x8B44_7B10, 32), Some(Insn::MovEaxSibd));
        // reg 任意：MOV ECX,[EBX+ESI*2+disp8] (8B 4C 73 ..) も同じ Insn。
        assert_eq!(decode(0x8B4C_7310, 32), Some(Insn::MovEaxSibd));
        assert_eq!(decode(0x8944_33F0, 32), Some(Insn::MovSibdEax));
        assert_eq!(decode(0x8B04_3310, 32), None);
        assert_eq!(decode(0x008B_8473_1000_0000, 56), Some(Insn::MovEaxSibd32));
        assert_eq!(decode(0x008B_84FB_1000_0000, 56), Some(Insn::MovEaxSibd32));
        assert_eq!(decode(0x0089_84FB_1000_0000, 56), Some(Insn::MovSibd32Eax));
        assert_eq!(decode(0x008B_0475_1000_0000, 56), Some(Insn::MovEaxSibabs));
        assert_eq!(decode(0x008B_04F5_1000_0000, 56), Some(Insn::MovEaxSibabs));
        assert_eq!(decode(0x0089_04F5_1000_0000, 56), Some(Insn::MovSibabsEax));
        assert_eq!(decode(0x008B_0433_1000_0000, 56), None);
        // 長さ違いは一致しない。
        assert_eq!(decode(0x008B_8473_1000_0000, 32), None);
        // 長さ違いは一致しない。
        assert_eq!(decode(0x90, 16), None);
        assert_eq!(decode(0xFFFF_FFFF, 32), None);
        // OR r/m8,imm8 reg-direct (80 /1 mod=11)。80 CD 08 は OR CH,8。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x80CD08, 24), Some(Insn::OrRm8Imm));
        assert_eq!(decode(0x80C808, 24), Some(Insn::OrRm8Imm));
        assert_eq!(decode(0x80CD08, 16), None);
        // MOVQ xmm,[base+disp8] (F3 0F 7E mod=01)。F3 は実行側で剥がすため decode は 0F 7E から。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F7E4338, 32), Some(Insn::MovqXmmM64Mem8));
        assert_eq!(decode(0x0F7E4338, 24), None);
        // TEST m16,imm16 mod=00 [base] (66 F7 /0)。66 は実行側で剥がすため decode は F7 から。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xF7030202, 32), Some(Insn::TestM16ImmMemnd));
        // TEST m16,imm16 mod=01 [base+disp8] (66 F7 /0)。hexdump 0x5c8822 対応.
        // F7 45 08 02 04 は TESTW $0x402,[R13+0x8] (REX.B 剥がし済み)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xF745080204, 40), Some(Insn::TestM16ImmMem8));
        assert_eq!(decode(0xF745080204, 32), None);
        // TEST m32,imm32 mod=00 [base] (F7 /0)。F7 00 FD FF FF FF は testl $FFFFFFFD,(%rax).
        // tac 0x5b0ca8 対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xF700FDFFFFFF, 48), Some(Insn::TestRm32ImmMemnd));
        assert_eq!(decode(0xF700FDFFFFFF, 40), None);
        assert_eq!(decode(0xF7030202, 24), None);
        // MOVHPS xmm,[base+disp8] (0F 16 mod=01)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F164338, 32), Some(Insn::MovhpsXmmM64Mem8));
        assert_eq!(decode(0x0F164338, 24), None);
        // MOVLPD xmm,[base] (66 0F 12 mod=00)。66 は実行側で剥がすため decode は 0F 12 から。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F120F, 24), Some(Insn::MovlpdXmmM64Memnd));
        assert_eq!(decode(0x0F120F, 16), None);
        // XORPS xmm,xmm reg-direct (0F 57 /r)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F57C0, 24), Some(Insn::Xorps));
        assert_eq!(decode(0x0F57C0, 16), None);
        // PADDB xmm,xmm reg-direct (66 0F FC /r)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0FFCC1, 24), Some(Insn::Paddb));
        assert_eq!(decode(0x0FFCC1, 16), None);
        // PCMPGTB xmm,xmm reg-direct (66 0F 64 /r)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F64C6, 24), Some(Insn::Pcmpgtb));
        assert_eq!(decode(0x0F64C6, 16), None);
        // PANDN xmm,xmm reg-direct (66 0F DF /r)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0FDFC7, 24), Some(Insn::Pandn));
        assert_eq!(decode(0x0FDFC7, 16), None);
        // CVTSI2SD xmm,r64 reg-direct (F2 REX.W 0F 2A /r)。F2/REX は実行側で剥がす.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F2AC0, 24), Some(Insn::Cvtsi2sdR64));
        assert_eq!(decode(0x0F2AC0, 16), None);
        // ADDSD xmm,xmm reg-direct (F2 0F 58 /r)。F2 は実行側で剥がす.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F58C8, 24), Some(Insn::Addsd));
        assert_eq!(decode(0x0F58C8, 16), None);
        // COMISD xmm,xmm reg-direct (66 0F 2F /r)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F2FC1, 24), Some(Insn::Comisd));
        assert_eq!(decode(0x0F2FC1, 16), None);
        // SUBSD xmm,xmm reg-direct (F2 0F 5C /r)。F2 は実行側で剥がす.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F5CC1, 24), Some(Insn::Subsd));
        assert_eq!(decode(0x0F5CC1, 16), None);
        // MULSD xmm,m64 RIP (F2 0F 59 05 + disp32)。F2 は実行側で剥がす.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F590500000000, 56), Some(Insn::MulsdXmmM64Rip));
        assert_eq!(decode(0x0F590500000000, 48), None);
        // MULSD xmm,m64 SIB+disp8 (F2 0F 59)。seq 0x49924a の 0F 59 44 24 08。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F59442408, 40), Some(Insn::MulsdXmmM64Sibd));
        assert_eq!(decode(0x0F59442408, 32), None);
        // ADDSD xmm,m64 RIP (F2 0F 58 05 + disp32)。F2 は実行側で剥がす.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F580500000000, 56), Some(Insn::AddsdXmmM64Rip));
        assert_eq!(decode(0x0F580500000000, 48), None);
        // CVTTSD2SI r64,xmm reg-direct (F2 REX.W 0F 2C /r)。F2/REX は実行側で剥がす.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F2CC0, 24), Some(Insn::Cvttsd2siR64));
        assert_eq!(decode(0x0F2CC0, 16), None);
        // AND m,imm8 SIB mod=01 no_index (83 /4 + SIB + disp8 + imm8)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x8364241000, 40), Some(Insn::AndRmImm8Sibd));
        assert_eq!(decode(0x8364241000, 32), None);
        // OR m,imm8 SIB mod=01 (83 /1 + SIB + disp8 + imm8)。4A 83 4C 23 08 01 は REX.W+X 付き.
        // REX は剥がし済みのため decode は 83 4C 23 08 01 から.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x834C230801, 40), Some(Insn::OrRmImm8Sibd));
        assert_eq!(decode(0x834C230801, 32), None);
        // ADD m,imm8 SIB mod=01 no_index (83 /0 + SIB + disp8 + imm8)。48 83 44 24 08 08 は REX.W 付き.
        // REX は剥がし済みのため decode は 83 44 24 08 08 から。test 0x5b1d4e 対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x8344240808, 40), Some(Insn::AddRmImm8Sibd));
        assert_eq!(decode(0x8344240808, 32), None);
        // AND m,imm8 SIB mod=00 no_index (83 /4 + SIB + imm8)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x83242400, 32), Some(Insn::AndRmImm8Sib));
        assert_eq!(decode(0x83242400, 24), None);
        // AND m,imm8 SIB mod=00 [base+index*scale] (83 /4 + SIB + imm8)。
        // 83 24 88 00 は andl $0,(%rax,%rcx,4).
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x83248800, 32), Some(Insn::AndRmImm8Sib));
        assert_eq!(decode(0x83248800, 24), None);
        // MOVZX r32,r16 reg-direct (0F B7 /r)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0FB7C3, 24), Some(Insn::MovzxR32R16));
        assert_eq!(decode(0x0FB7C300, 32), None);
        // BT r32,imm8 reg-direct (0F BA /4 ib)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0FBAE31E, 32), Some(Insn::BtR32Imm));
        assert_eq!(decode(0x0FBAE31E, 24), None);
        // BTS r32/r64,imm8 reg-direct (0F BA /5 ib)。REX.W で64ビット.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0FBAEB34, 32), Some(Insn::BtsR32Imm));
        assert_eq!(decode(0x0FBAEB34, 24), None);
        // TEST m16,imm16 RIP (66 F7 05 + disp32 + imm16)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xF705000000003102, 64), Some(Insn::TestM16ImmRip));
        assert_eq!(decode(0xF705000000003102, 56), None);
        // TEST m32,imm32 RIP (F7 05 + disp32 + imm32)。ls 0x4963b6 の F7 05 FC DB 27 00 31 02 00 00。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(
            decode(0xF705FCDB270031020000, 80),
            Some(Insn::TestRm32ImmRip)
        );
        // SUB m,r SIB+disp8 (29 /r mod=01)。wc 0x49e1db の 29 44 24 78。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x29442478, 32), Some(Insn::SubMRSibd));
        // MOVAPS [sib], xmm (0F 29 mod=00)。od 0x49788f の 0F 29 14 24。
        // MOVAPS [sib+disp8], xmm (0F 29 mod=01)。sed 0x400d19 の 0F 29 44 24 D8。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F291424, 32), Some(Insn::MovapsStoreSib));
        assert_eq!(decode(0x0F294424D8, 40), Some(Insn::MovapsStoreSibd));
        // OR m,r SIB+disp8 (09 /r mod=01)。sed 0x400d55 の 09 4C C4 D8。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x094CC4D8, 32), Some(Insn::OrM32R32Sibd));
        // OR r, [sib+disp8] (0B /r mod=01)。sed 0x4c9424 の 0B 44 24 18。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0B442418, 32), Some(Insn::OrRSibd));
        // INC m32 SIB mod=00 (FF /0)。sed 0x4ca2c7 の FF 04 91。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xFF0491, 24), Some(Insn::IncRmSib));
        // DEC m32 SIB mod=00 (FF /1)。xxd 0x4b2bee の FF 0C 24。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xFF0C24, 24), Some(Insn::DecRmSib));
        // CMP m8, r8 RIP (38 /r mod=00 rm=101)。grep 0x4aec6d の 38 35 C4 4B 26 00。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x3835C44B2600, 48), Some(Insn::CmpM8R8Rip));
        // FLDS RIP (D9 /0)。seq 0x402335 の D9 05 2D 89 0E 00。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xD9052D890E00, 48), Some(Insn::FldM32Rip));
        // FSTP ST(0) (DD D8)。seq 0x4024ee。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xDDD8, 16), Some(Insn::FstpSt));
        // FILD m32 SIB+disp8 (DB /0)。seq 0x4018bc の DB 44 24 20。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xDB442420, 32), Some(Insn::FildM32Sibd));
        // FILD m64 SIB (DF /5)。seq 0x4018c4 の DF 2C 24。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xDF2C24, 24), Some(Insn::FildM64Sib));
        // FMULP ST(1) (DE C9)。seq 0x4018c7。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xDEC9, 16), Some(Insn::FmulpSt));
        // FSUBP ST(i) (DE E8+i)。seq 0x4d0c51 の DE E9。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xDEE9, 16), Some(Insn::FsubpSt));
        // FSTP m64 SIB+disp8 (DD /3)。seq 0x4d3169 の DD 5C 24 08。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xDD5C2408, 32), Some(Insn::FstpM64Sibd));
        // FLDL (%rax) (DD /0)。seq 0x4d0723 の DD 00。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xDD00, 16), Some(Insn::FldM64Memnd));
        // FSTP m80 (%rdi) (DB /7)。seq 0x4d0725 の DB 3F。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xDB3F, 16), Some(Insn::FstpM80Memnd));
        // PUSH m64 SIB+disp8 (FF /6)。seq 0x4d1a81 の FF 74 24 68。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xFF742468, 32), Some(Insn::PushRmSibd));
        // FLD m80 SIB+disp32 (DB /5)。seq 0x4d0853 の DB AC 24 80 1D 00 00。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xDBAC24801D0000, 56), Some(Insn::FldM80Sibd32));
        // FLD ST(0) (D9 C0)。seq 0x4d0867。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xD9C0, 16), Some(Insn::FldSt));
        // FSTP m80 SIB (DB /7)。seq 0x4d0869 の DB 3C 24。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xDB3C24, 24), Some(Insn::FstpM80Sib));
        // FSTP m80 SIB+disp32 (DB /7)。seq 0x4d0874 の DB BC 24 80 1D 00 00。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xDBBC24801D0000, 56), Some(Insn::FstpM80Sibd32));
        // FLD m80 SIB+disp8 (DB /5)。seq 0x4d7466 の DB 6C 24 20。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xDB6C2420, 32), Some(Insn::FldM80Sibd));
        // OR m8, r8 SIB+disp8 (08 /r mod=01)。sed 0x4a87dd の 08 44 24 2F。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0844242F, 32), Some(Insn::OrM8R8Sibd));
        // OR m32,imm32 SIB mod=00 (81 /1)。awk 0x4a4354 の 81 0C 24 00 04 00 00。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x810C2400040000, 56), Some(Insn::OrRm32ImmSib));
        // OR m,imm8 SIB mod=00 (83 /1)。awk 0x4a1704 の 83 0C 24 01。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x830C2401, 32), Some(Insn::OrRmImm8Sib));
        // TEST r,m SIB mod=00 (85 /r)。awk 0x4a1c82 の 85 34 24。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x853424, 24), Some(Insn::TestRSib));
        // CMOVNE r,m64 SIB+disp8 no_index (0F 45 mod=01)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F45442450, 40), Some(Insn::CmovneR64Sibd));
        assert_eq!(decode(0x0F45442450, 32), None);
        // CMOVGE r32, [SIB+disp8] (0F 4D)。seq 0x4d137a の 0F 4D 44 24 10。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F4D442410, 40), Some(Insn::CmovgeR32Sibd));
        assert_eq!(decode(0x0F4D442410, 32), None);
        // CMOVL r32, [SIB] mod=00 no_index (0F 4C)。cut 0x492257 の 44 0F 4C 14 24。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F4C1424, 32), Some(Insn::CmovlR32Sib));
        // CMOVS (%rsp), %ecx。sed 0x4c9eb0 の 0F 48 0C 24。
        assert_eq!(decode(0x0F480C24, 32), Some(Insn::CmovsR32Sib));
        assert_eq!(decode(0x0F4C1424, 24), None);
        // IMUL r,m32 SIB+disp8 (0F AF mod=01)。hexdump 0x5c8ca2 対応.
        // 0F AF 6C 24 14 は imul ebp,[r12+0x14] (REX.B 剥がし済み)。
        // 下位32は ImulRMem8 に一致するため否定は24で行う.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0FAF6C2414, 40), Some(Insn::ImulRSibd));
        assert_eq!(decode(0x0FAF6C2414, 24), None);
        // XOR r/m8,r8 reg-direct (30 /r)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x30C0, 16), Some(Insn::XorM8R8));
        assert_eq!(decode(0x30C0, 8), None);
        // AND r/m8,r8 reg-direct (20 /r)。
        assert_eq!(decode(0x20C7, 16), Some(Insn::AndM8R8));
        assert_eq!(decode(0x20C7, 8), None);
        // XADD r32,[base] (0F C1 mod=00)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0FC103, 24), Some(Insn::XaddR32Memnd));
        assert_eq!(decode(0x0FC103, 16), None);
        assert_eq!(decode(0x0FC10500000000, 56), Some(Insn::XaddR32Rip));
        assert_eq!(decode(0x0FA5C8, 24), Some(Insn::ShldR32Cl));
        // SHRD r/m32,r32,CL (0F AD /r mod=11)。seq 10 の停止点 0x4c4425 (4C 0F AD C0 は REX 剥がし済み) に対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0FADC0, 24), Some(Insn::ShrdR32Cl));
        assert_eq!(decode(0x0FADC0, 16), None);
        // NOPL [base+disp32] (0F 1F mod=10)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F1F8000000000, 56), Some(Insn::NoplMem32));
        assert_eq!(decode(0x0F1F8000000000, 48), None);
        // NOPL [base+disp8] (0F 1F mod=01)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F1F4000, 32), Some(Insn::NoplMem8));
        assert_eq!(decode(0x0F1F4000, 24), None);
        // CMPB [base],imm8 SIB mod=00 no_index (80 /7 + SIB + imm8)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x803C2443, 32), Some(Insn::CmpRm8ImmSib));
        assert_eq!(decode(0x803C2443, 24), None);
        // CMPB [base+index*scale],imm8 SIB mod=00 indexed (80 /7)。grep 0x43e0e4 対応.
        // 80 3C 13 00 は CMPB $0x00,(%rbx,%rdx).
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x803C1300, 32), Some(Insn::CmpRm8ImmSib));
        assert_eq!(decode(0x803C1300, 24), None);
        // MOVB [base+disp32],imm8 (C6 /0 mod=10)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xC68550FBFFFF20, 56), Some(Insn::MovRm8ImmMem32));
        assert_eq!(decode(0xC68550FBFFFF20, 48), None);
        // SUB r,m32 SIB+disp8 no_index (2B mod=01)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x2B442408, 32), Some(Insn::SubRSibd));
        assert_eq!(decode(0x2B442408, 24), None);
        // SUB r,m32 SIB+disp8 [base+index*scale+disp8] (2B mod=01)。
        // 2B 44 B0 50 は subl 0x50(%rax,%rsi,4),%eax.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x2B44B050, 32), Some(Insn::SubRSibd));
        assert_eq!(decode(0x2B44B050, 24), None);
        // ORB [base+index*scale+disp8],imm8 (80 /1 SIB mod=01)。seq の停止点 0x45b828 に対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x804C04F800, 40), Some(Insn::OrRm8ImmSibd));
        assert_eq!(decode(0x804C04F800, 32), None);
        // OR r8,m8 SIB mod=01 (0A /r)。head の停止点 0x5a96cc に対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0A44240A, 32), Some(Insn::OrR8M8Sibd));
        assert_eq!(decode(0x0A44240A, 24), None);
        // OR r8,m8 RIP (0A 05 + disp32)。find 0x5c44a7 対応.
        // 0A 05 F5 E3 0A 00 は OR AL,[RIP+0xAE3F5].
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0A05F5E30A00, 48), Some(Insn::OrR8M8Rip));
        assert_eq!(decode(0x0A05F5E30A00, 32), None);
        // OR r8,r/m8 reg-direct (0A /r mod=11)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0AC0, 16), Some(Insn::OrR8R8));
        assert_eq!(decode(0x0AC0, 8), None);
        // SHR r/m8,imm8 (C0 /5 mod=11)。head の停止点 0x4c9097 に対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xC0E805, 24), Some(Insn::ShrRm8Imm8));
        assert_eq!(decode(0xC0E805, 8), None);
        // SHR r/m8,1 (D0 /5 mod=11)。sed の停止点 0x5bdd7d (41 D0 ED は REX.B 剥がし済み) に対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xD0ED, 16), Some(Insn::ShrRm81));
        assert_eq!(decode(0xD0ED, 8), None);
        // MOVB [base+index*scale+disp8],imm8 (C6 /0 SIB mod=01)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xC64428FE3A, 40), Some(Insn::MovRm8ImmSibd));
        assert_eq!(decode(0xC64428FE3A, 32), None);
        // MOVB [base+index*scale],imm8 (C6 /0 SIB mod=00)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xC604163A, 32), Some(Insn::MovRm8ImmSib));
        assert_eq!(decode(0xC604163A, 24), None);
        // ADD r,m SIB+disp8 no_index (03 mod=01)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x03442418, 32), Some(Insn::AddRSibd));
        assert_eq!(decode(0x03442418, 24), None);
        // ADD r,m SIB+disp8 indexed (03 mod=01)。03 44 B4 28 は ADD EAX,[RSP+RSI*4+0x28].
        // sha1sum 0x5cab68 対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0344B428, 32), Some(Insn::AddRSibd));
        assert_eq!(decode(0x0344B428, 24), None);
        // MOVSX r32,m8 RIP (0F BE 05 + disp32)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0FBE0500000000, 56), Some(Insn::MovsxR32M8Rip));
        assert_eq!(decode(0x0FBE0500000000, 48), None);
        // MOVZX r32,m16 mod=01 [base+disp8] (0F B7 /r)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0FB75610, 32), Some(Insn::MovzxR32M16Mem8));
        assert_eq!(decode(0x0FB75610, 24), None);
        // MOVZX r32,m16 mod=00 [base] (0F B7 /r)。ls -l 0x4824c4 対応.
        // 0F B7 0E は movzwl (%rsi),%ecx.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0FB70E, 24), Some(Insn::MovzxR32M16Memnd));
        assert_eq!(decode(0x0FB70E, 32), None);
        // MOVAPS [base+disp32],xmm (0F 29 mod=10)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F2985E0FEFFFF, 56), Some(Insn::MovapsStoreMem32));
        // 下位48ビット 29 85 E0 FE FF FF は SUB [rbp+disp32], eax。
        assert_eq!(decode(0x0F2985E0FEFFFF, 48), Some(Insn::SubM32R32Mem32));
        // OR m32,r32 SIB+disp32 (09 /r SIB mod=10)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0994B008080000, 56), Some(Insn::OrM32R32Sibd32));
        assert_eq!(decode(0x0994B008080000, 48), None);
        // OR m32,r32 SIB [base+index*scale] (09 /r SIB mod=00)。
        // 09 3C B4 は orl %edi,(%rsp,%rsi,4).
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x093CB4, 24), Some(Insn::OrM32R32Sib));
        assert_eq!(decode(0x093CB4, 8), None);
        // CMP r,m SIB mod=00 [base+index*scale] (3B /r)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x3B0407, 24), Some(Insn::CmpRSib));
        assert_eq!(decode(0x3B0407, 16), None);
        // CMP r,m SIB mod=01 [base+index*scale+disp8] (3B /r)。
        // 3B 4C 24 14 は cmpl 0x14(%rsp),%ecx.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x3B4C2414, 32), Some(Insn::CmpRSibd));
        assert_eq!(decode(0x3B4C2414, 24), None);
        // TEST r,m SIB mod=01 [base+index*scale+disp8] (85 /r)。wc の停止点 0x5b3696 に対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x8544241C, 32), Some(Insn::TestRSibd));
        assert_eq!(decode(0x8544241C, 24), None);
        // TEST r,m SIB+disp32 (85 /r mod=10 rm=100)。grep 0x43d250 対応.
        // 85 94 15 A8 00 00 00 は test [r13+r10+0xA8],edx (REX 剥がし済み).
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x859415A8000000, 56), Some(Insn::TestRSibd32));
        assert_eq!(decode(0x859415A8000000, 48), None);
        // SUB m32,r32 mod=01 [base+disp8] (29 /r)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x296DA0, 24), Some(Insn::SubM32R32Mem8));
        assert_eq!(decode(0x296DA0, 16), None);
        // MOV [base+index*scale],r8 SIB mod=00 (88 /r)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x881407, 24), Some(Insn::MovM8R8Sib));
        assert_eq!(decode(0x881407, 16), None);
        assert_eq!(decode(0x88B41400000000, 56), Some(Insn::MovM8R8Sibd32));
        // MOV [base+index*scale+disp8],r8 SIB mod=01 (88 /r)。88 44 31 FF は [RCX+RSI-1],AL.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x884431FF, 32), Some(Insn::MovM8R8Sibd));
        assert_eq!(decode(0x884431FF, 24), None);
        // INC m32 [base] (FF /0 mod=00)。FF 03 は incl (%rbx).
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xFF03, 16), Some(Insn::IncRmMemnd));
        assert_eq!(decode(0xFF03, 24), None);
        // CALL m32 [base] (FF /2 mod=00)。FF 17 は call (%rdi)。REX.B 剥がし済み 41 FF 17 は call (%r15).
        // find -name 0x5c3479 対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xFF17, 16), Some(Insn::CallRMemnd));
        assert_eq!(decode(0xFF17, 8), None);
        // INC m32 [base+index*scale+disp8] (FF /0 SIB mod=01)。FF 44 97 FC は incl -4(%rdi,%rdx,4).
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xFF4497FC, 32), Some(Insn::IncRmSibd));
        assert_eq!(decode(0xFF4497FC, 24), None);
        // DEC m32 [base+index*scale+disp8] (FF /1 SIB mod=01)。FF 4C 24 0C は decl 0x0C(%rsp).
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xFF4C240C, 32), Some(Insn::DecRmSibd));
        assert_eq!(decode(0xFF4C240C, 24), None);
        // INC m32 [base+disp8] (FF /0 mod=01、SIBなし)。FF 43 2C は incl 0x2C(%rbx).
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xFF432C, 24), Some(Insn::IncRmMem8));
        assert_eq!(decode(0xFF432C, 16), None);
        // DEC m32 [base+disp8] (FF /1 mod=01、SIBなし)。FF 4B 2C は decl 0x2C(%rbx).
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xFF4B2C, 24), Some(Insn::DecRmMem8));
        assert_eq!(decode(0xFF4B2C, 16), None);
        // INC m32 [RIP+disp32] (FF /0 mod=00 rm=101)。FF 05 DE 4B 0B 00 は incl 0xb4bde(%rip).
        // sed 0x5bdcc0 対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xFF05DE4B0B00, 48), Some(Insn::IncRmRip));
        assert_eq!(decode(0xFF05DE4B0B00, 32), None);
        // DEC m32 [RIP+disp32] (FF /1 mod=00 rm=101)。FF 0D A7 A8 0C 00 は decl 0xca8a7(%rip).
        // du -s 0x5a7fe7 対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xFF0DA7A80C00, 48), Some(Insn::DecRmRip));
        assert_eq!(decode(0xFF0DA7A80C00, 32), None);
        // ADD m32,r32 SIB+disp8 (01 /r SIB mod=01)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x016C2418, 32), Some(Insn::AddM32R32Sibd));
        assert_eq!(decode(0x016C2418, 24), None);
        // CMP m,imm8 SIB mod=00 no_index (83 /7 + SIB + imm8)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x833C2400, 32), Some(Insn::CmpRmImm8Sib));
        assert_eq!(decode(0x833C2400, 24), None);
        // CMP m,imm8 SIB mod=00 [base+index*scale] (83 /7 + SIB + imm8)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x833CD300, 32), Some(Insn::CmpRmImm8Sib));
        assert_eq!(decode(0x833CD300, 24), None);
        // TEST r,m mod=01 [base+disp8] (85 /r)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x857804, 24), Some(Insn::TestRMem8));
        assert_eq!(decode(0x857804, 32), None);
        // OR m32,imm32 mod=00 [base] (81 /1)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x810F0C240000, 48), Some(Insn::OrRm32ImmMemnd));
        assert_eq!(decode(0x810F0C240000, 40), None);
        // OR AL,imm8 (0C ib)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0C80, 16), Some(Insn::OrAlImm));
        assert_eq!(decode(0x0C80, 8), None);
        // CALL [base+index*scale+disp8] (FF /2 SIB mod=01)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xFF542448, 32), Some(Insn::CallRSibd));
        assert_eq!(decode(0xFF542448, 24), None);
        // CALL [base+index*scale+disp32] (FF /2 SIB mod=10)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xFF942480000000, 56), Some(Insn::CallRSibd32));
        assert_eq!(decode(0xFF942480000000, 48), None);
        // OR r/m8,r8 reg-direct (08 /r)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x08D0, 16), Some(Insn::OrM8R8));
        assert_eq!(decode(0x08D0, 8), None);
        // AND r8,m8 mod=10 [base+disp32] (22 /r)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x228540FBFFFF, 48), Some(Insn::AndR8M8Mem32));
        assert_eq!(decode(0x228540FBFFFF, 40), None);
        // CMPB [base+disp32],imm8 (80 /7 mod=10)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x80BD50FBFFFF20, 56), Some(Insn::CmpRm8ImmMem32));
        assert_eq!(decode(0x80BD50FBFFFF20, 48), None);
        // CMP m32,r32 SIB+disp8 no_index (39 mod=01)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        // 39 84 24 88 00 00 00: CMP m64, r64 SIB+disp32。true 0x4bed0c 対応.
        // Ref: SPEC-X86-INTEL-SDM.
        assert_eq!(decode(0x39842488000000, 56), Some(Insn::CmpM32R32Sibd32));
        assert_eq!(decode(0x39842488000000, 32), None);
        assert_eq!(decode(0x39542414, 32), Some(Insn::CmpM32R32Sibd));
        assert_eq!(decode(0x39542414, 24), None);
        // MOVSX r32,m8 mod=01 [base+disp8] (0F BE /r)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0FBE7101, 32), Some(Insn::MovsxR32M8Mem8));
        assert_eq!(decode(0x0FBE7101, 24), None);
        // ADD m16,imm8 SIB mod=00 (66 83 /0)。66 は実行側で剥がす.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x83045101, 32), Some(Insn::AddM16ImmSib));
        assert_eq!(decode(0x83045101, 24), None);
        // CMP m32,imm8 SIB mod=01 no_index (83 /7 + SIB + disp8 + imm8)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        // 83 BC 24 D8 00 00 00 00: CMP m64,imm8 SIB+disp32。true 0x4bed16 対応.
        // Ref: SPEC-X86-INTEL-SDM.
        assert_eq!(decode(0x83BC24D800000000, 64), Some(Insn::CmpRmImm8Sibd32));
        assert_eq!(decode(0x83BC24D800000000, 56), None);
        assert_eq!(decode(0x837C241400, 40), Some(Insn::CmpRmImm8Sibd));
        assert_eq!(decode(0x837C241400, 32), None);
        // CMP m64,imm8 SIB+disp8 indexed (83 /7 + SIB + disp8 + imm8)。48 83 7C C1 F8 00 は REX 剥がし済み.
        // seq 10 の停止点 0x45bbd8 対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x837CC1F800, 40), Some(Insn::CmpRmImm8Sibd));
        assert_eq!(decode(0x837CC1F800, 32), None);
        // SETE m8 mod=10 [base+disp32] (0F 94 /r)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F94850BFBFFFF, 56), Some(Insn::SeteM8Mem32));
        assert_eq!(decode(0x0F94850BFBFFFF, 48), None);
        // SETE m8 mod=01 [base+disp8] (0F 94 /r)。grep 0x442245 対応.
        // 0F 94 45 97 は SETE -0x69(%rbp).
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F944597, 32), Some(Insn::SeteM8Mem8));
        assert_eq!(decode(0x0F944597, 24), None);
        // SETNE m8 mod=10 [base+disp32] (0F 95 /r)。grep 0x43ddc1 対応.
        // 0F 95 85 C0 FD FF FF は SETNE -0x240(%rbp).
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F9585C0FDFFFF, 56), Some(Insn::SetneM8Mem32));
        assert_eq!(decode(0x0F9585C0FDFFFF, 48), None);
        // SETLE m8 mod=10 [base+disp32] (0F 9E /r)。grep 0x43e091 対応.
        // 0F 9E 85 73 FD FF FF は SETLE -0x28D(%rbp).
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F9E8573FDFFFF, 56), Some(Insn::SetleM8Mem32));
        assert_eq!(decode(0x0F9E8573FDFFFF, 48), None);
        // SETNE m8 SIB+disp8 (0F 95 SIB mod=01)。ls -l 0x42a294 対応.
        // 0F 95 44 F0 06 は [RAX+RSI*8+0x06].
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F9544F006, 40), Some(Insn::SetneM8Sibd));
        assert_eq!(decode(0x0F9544F006, 32), None);
        // SETE m8 SIB+disp8 (0F 94 SIB mod=01)。df 0x5a797e 対応.
        // 0F 94 44 24 1F は SETE [RSP+0x1F] (no_index)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F9444241F, 40), Some(Insn::SeteM8Sibd));
        assert_eq!(decode(0x0F9444241F, 32), None);
        // SUB r/m8,r8 reg-direct (28 /r)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x28D1, 16), Some(Insn::SubM8R8));
        assert_eq!(decode(0x28D1, 8), None);
        // MOVSX r,m8 mod=00 [base] (0F BE /r)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0FBE13, 24), Some(Insn::MovsxR32M8Memnd));
        assert_eq!(decode(0x0FBE13, 16), None);
        // MOVSX r32,m8 SIB mod=01 [base+index*scale+disp8] (0F BE)。wc の停止点 0x5b385a に対応.
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0FBE7C241B, 40), Some(Insn::MovsxR32M8Sibd));
        assert_eq!(decode(0x0FBE7C241B, 32), None);
    }

    #[test]
    fn cpu_models() {
        assert!(FEATURES.contains(&"i386"));
        assert!(MODELS.contains(&"generic32"));
    }
}
