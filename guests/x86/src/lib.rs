// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! x86 最小のゲスト ISA。段階4の最小であり、可変長デコードを確かめる。
//!
//! i386 の197件を持つ。ModRM/SIB 汎用・XMM最小・near Jcc・MOVZX・CMOVB・ADD RIP等を含む。
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
    /// XMM レジスタ 8本。下位・上位の u64 ずつ置く（x86-64 のみ使う）。
    pub xmm: [[u64; 2]; 8],
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
    }

    #[test]
    fn insn_count() {
        // 試作の整数116件。
        assert_eq!(INSNS.len(), 197);
    }

    #[test]
    fn decode_spot_checks() {
        // 命令語はビット配置から手で組み立てる。Ref: SPEC-X86-INTEL-SDM。
        assert_eq!(decode(0x90, 8), Some(Insn::Nop));
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
        // ModRM register-direct 全組合せ：ADD (01 /r dst=rm)、MOV (8B /r dst=reg)、
        // CMP (39)、AND (21)、OR (09)、SUB (29)、XOR (31)、MOV store (89 /r dst=rm)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x01C8, 16), Some(Insn::AddRm32));
        assert_eq!(decode(0x01D8, 16), Some(Insn::AddRm32));
        assert_eq!(decode(0x01C3, 16), Some(Insn::AddRm32));
        assert_eq!(decode(0x8BC1, 16), Some(Insn::MovRm32));
        assert_eq!(decode(0x8BD8, 16), Some(Insn::MovRm32));
        // ModRM の mod=00 (メモリ) は register-direct とは一致しない。
        assert_eq!(decode(0x0108, 16), None);
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
        assert_eq!(decode(0x7C00, 8), None);
        // C7 /0 (MOV r/m,imm32)：REX は剥がしてあるため Insn を共有する。
        // 64ビット切り替えは dispatch が REX.W で行う。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0000_C7C0_1234_5678, 48), Some(Insn::MovRmImm));
        assert_eq!(decode(0x0000_C7C1_1234_5678, 48), Some(Insn::MovRmImm));
        assert_eq!(decode(0x0000_C700_1234_5678, 48), None);
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
        assert_eq!(decode(0x0083_00F0, 24), None);
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
        // NOP r/m (0F 1F /0)：F3/0x66 接頭辞は実行側で剥がす。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0F1F00, 24), Some(Insn::Nopl));
        // MOVSXD r,r/m32 (63 /r)。REX.W で 64ビット符号拡張。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x63C6, 16), Some(Insn::Movsxd));
        assert_eq!(decode(0x6300, 16), None);
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
        assert_eq!(decode(0x0F100433, 32), Some(Insn::MovupsLoadSib));
        assert_eq!(decode(0x0F110433, 32), Some(Insn::MovupsStoreSib));
        assert_eq!(decode(0x0F10443310, 40), Some(Insn::MovupsLoadSibd));
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
        assert_eq!(decode(0x81C900000000, 48), Some(Insn::OrRm32Imm));
        assert_eq!(decode(0x81D200000000, 48), Some(Insn::AdcRm32Imm));
        assert_eq!(decode(0x81DB00000000, 48), Some(Insn::SbbRm32Imm));
        assert_eq!(decode(0x81E400000000, 48), Some(Insn::AndRm32Imm));
        assert_eq!(decode(0x81F100000000, 48), Some(Insn::XorRm32Imm));
        assert_eq!(decode(0x810D0000000000000000, 80), Some(Insn::OrRm32Rip));
        assert_eq!(decode(0x81050000000000000000, 80), Some(Insn::AddRm32Rip));
        assert_eq!(decode(0xC7050000000004000000, 80), Some(Insn::MovRmImmRip));
        assert_eq!(decode(0xC785000000000000, 64), Some(Insn::MovRm16ImmM32));
        assert_eq!(decode(0xF6C110, 24), Some(Insn::TestRm8Imm));
        assert_eq!(decode(0xA801, 16), Some(Insn::TestAlImm));
        assert_eq!(decode(0xF6050000000002, 56), Some(Insn::TestM8ImmRip));
        assert_eq!(decode(0x80E580, 24), Some(Insn::AndRm8Imm));
        assert_eq!(decode(0x830D0000000040, 56), Some(Insn::OrRmImm8Rip));
        assert_eq!(decode(0x0F6E8500000000, 56), Some(Insn::MovdXmmM32));
        assert_eq!(decode(0xF7D0, 16), Some(Insn::NotRm32));
        assert_eq!(decode(0xF7D8, 16), Some(Insn::NegRm32));
        assert_eq!(decode(0xA900000001, 40), Some(Insn::TestEaxImm));
        assert_eq!(decode(0x0B1500000000, 48), Some(Insn::OrRRip));
        assert_eq!(decode(0x090500000000, 48), Some(Insn::OrMRip));
        assert_eq!(decode(0x833F0F, 24), Some(Insn::CmpRmImm8Memnd));
        assert_eq!(decode(0x00C1EA08, 24), Some(Insn::ShrRm32Imm8));
        // CMP [RIP+disp32],imm8 (83 3D + disp32 + imm8)。
        assert_eq!(decode(0x833D0000000038, 56), Some(Insn::CmpRmImm8Rip));
        // CMOVB r,r/m (0F 42 /r)。
        assert_eq!(decode(0x0F42C2, 24), Some(Insn::Cmovb));
        assert_eq!(decode(0x0F45F0, 24), Some(Insn::Cmovne));
        assert_eq!(decode(0x0F44F8, 24), Some(Insn::Cmove));
        // ADD r,[RIP+disp32] (03 05 + disp32)。
        assert_eq!(decode(0x030500000000, 48), Some(Insn::AddRRip));
        // MOVZX r32,r/m16 (0F B7 95 + disp32)。
        assert_eq!(decode(0x0FB79500000000, 56), Some(Insn::MovzxR32M16));
        assert_eq!(
            decode(0xC78405A0FBFFFF00000000, 88),
            Some(Insn::MovRmImmSibd32)
        );
        assert_eq!(decode(0x85D2, 16), Some(Insn::TestRm32));
        assert_eq!(decode(0xF7C400080000, 48), Some(Insn::TestRm32Imm));
        assert_eq!(decode(0x0FEFC0, 24), Some(Insn::Pxor));
        assert_eq!(decode(0x0F62C0, 24), Some(Insn::Punpckldq));
        assert_eq!(decode(0x0FD60500000000, 56), Some(Insn::MovqM64XmmRip));
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
        assert_eq!(decode(0x35_0000_00FF, 40), Some(Insn::XorImm));
        // シフト：SHL EAX,imm8 (C1 E0 ib)、SHR EAX,imm8 (C1 E8 ib)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x00C1_E002, 24), Some(Insn::ShlEax));
        assert_eq!(decode(0x00C1_E81F, 24), Some(Insn::ShrRm32Imm8));
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
    }

    #[test]
    fn cpu_models() {
        assert!(FEATURES.contains(&"i386"));
        assert!(MODELS.contains(&"generic32"));
    }
}
