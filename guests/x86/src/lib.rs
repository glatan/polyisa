// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! x86 最小のゲスト ISA。段階4の最小であり、可変長デコードを確かめる。
//!
//! i386 の126件に x86-64 最小の REX.W 7件を加えた計133件を持つ。
//! REX.W は 0x48 のみ、R8-R15・SIB・64ビットメモリ形式は本格実装で足す。
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
    }

    #[test]
    fn insn_count() {
        // 試作の整数133件。
        assert_eq!(INSNS.len(), 133);
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
        assert_eq!(decode(0xB8_1234_5678, 40), Some(Insn::MovEax));
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
        // ModRM の mod=00 (メモリ) は未対応であり一致しない。
        assert_eq!(decode(0x0108, 16), None);
        assert_eq!(decode(0x8B08, 16), None);
        // スタック操作とコール/リターン：PUSH EAX (50)、POP EAX (58)、PUSH EBP (55)、
        // POP EBP (5D)、CALL rel32 (E8+imm32)、RET (C3)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xE8_0000_0010, 40), Some(Insn::CallRel32));
        assert_eq!(decode(0xC3, 8), Some(Insn::Ret));
        // 比較・条件分岐：CMP EAX,imm32 (3D)、TEST EAX,EAX (85 C0)、JE (74)、JNE (75)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x3D_0000_0001, 40), Some(Insn::CmpEax));
        assert_eq!(decode(0x85C0, 16), Some(Insn::TestEax));
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
        // REX.W 最小形：48 C7 C0+imm32 (MOV RAX,imm32)、48 8B/89/01/29/39 /r、
        // 48 8D 05+disp32 (LEA RAX,[RIP+disp32])。R8-R15 は未対応。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x0048_C7C0_1234_5678, 56), Some(Insn::MovRm64Imm));
        assert_eq!(decode(0x0048_C7C1_1234_5678, 56), Some(Insn::MovRm64Imm));
        assert_eq!(decode(0x0048_C700_1234_5678, 56), None);
        assert_eq!(decode(0x488BD8, 24), Some(Insn::MovRm64));
        assert_eq!(decode(0x4889D8, 24), Some(Insn::MovMr64));
        assert_eq!(decode(0x4801D8, 24), Some(Insn::AddRm64));
        assert_eq!(decode(0x4829D8, 24), Some(Insn::SubRm64));
        assert_eq!(decode(0x4839D8, 24), Some(Insn::CmpRm64));
        assert_eq!(decode(0x4801C0, 24), Some(Insn::AddRm64));
        assert_eq!(decode(0x0048_8D05_7856_3412, 56), Some(Insn::LeaRip64));
        assert_eq!(decode(0x0048_8D05_7856_3412, 32), None);
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
        assert_eq!(decode(0x00C1_E81F, 24), Some(Insn::ShrEax));
        // /6 (110) や mod=00 は別命令であり一致しない。
        assert_eq!(decode(0x00C1_F002, 24), None);
        assert_eq!(decode(0x00C1_2002, 24), None);
        // INT 0x80 (CD 80)：i386 のシステムコール命令。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xCD80, 16), Some(Insn::Int80));
        assert_eq!(decode(0xCD81, 16), None);
        // LEA r32 (8D /r、dst=reg)：EBX+disp8・EBX+disp32・絶対番地・SIB 各形。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x008D_4310, 24), Some(Insn::LeaM8));
        assert_eq!(decode(0x008D_4B10, 24), Some(Insn::LeaM8));
        assert_eq!(decode(0x008D_8310, 24), None);
        assert_eq!(decode(0x8D83_7856_3412, 48), Some(Insn::LeaM32));
        assert_eq!(decode(0x8D05_7856_3412, 48), Some(Insn::LeaAbs));
        assert_eq!(decode(0x008D_0433, 24), Some(Insn::LeaSib));
        assert_eq!(decode(0x8D44_3310, 32), Some(Insn::LeaSibd));
        assert_eq!(decode(0x8D44_7310, 32), Some(Insn::LeaSibS2));
        assert_eq!(decode(0x8D44_B310, 32), Some(Insn::LeaSibS4));
        assert_eq!(decode(0x8D44_F310, 32), Some(Insn::LeaSibS8));
        assert_eq!(decode(0x008D_0473, 24), Some(Insn::LeaSibS2nd));
        assert_eq!(decode(0x008D_04B3, 24), Some(Insn::LeaSibS4nd));
        assert_eq!(decode(0x008D_04F3, 24), Some(Insn::LeaSibS8nd));
        assert_eq!(decode(0x008D_8473_1000_0000, 56), Some(Insn::LeaSibS2d32));
        assert_eq!(decode(0x008D_84B3_1000_0000, 56), Some(Insn::LeaSibS4d32));
        assert_eq!(decode(0x008D_84F3_1000_0000, 56), Some(Insn::LeaSibS8d32));
        assert_eq!(decode(0x008D_0475_1000_0000, 56), Some(Insn::LeaSibS2a32));
        assert_eq!(decode(0x008D_04B5_1000_0000, 56), Some(Insn::LeaSibS4a32));
        assert_eq!(decode(0x008D_04F5_1000_0000, 56), Some(Insn::LeaSibS8a32));
        assert_eq!(decode(0x39C8, 16), Some(Insn::CmpRm32));
        assert_eq!(decode(0x39D8, 16), Some(Insn::CmpRm32));
        assert_eq!(decode(0x21C8, 16), Some(Insn::AndRm32));
        assert_eq!(decode(0x21D8, 16), Some(Insn::AndRm32));
        assert_eq!(decode(0x09C8, 16), Some(Insn::OrRm32));
        assert_eq!(decode(0x09D8, 16), Some(Insn::OrRm32));
        // mod=01 の 39 /r は register-direct ではなく一致しない。
        assert_eq!(decode(0x397C, 16), None);
        // SIB base+index 最小形：MOV EAX,[EBX+ESI] (8B 04 33) と MOV [EBX+ESI],EAX (89 04 33)。
        assert_eq!(decode(0x008B_0433, 24), Some(Insn::MovEaxSib));
        assert_eq!(decode(0x0089_0433, 24), Some(Insn::MovSibEax));
        assert_eq!(decode(0x008B_0434, 24), None);
        // SIB+disp8：MOV EAX,[EBX+ESI+disp8] (8B 44 33 ib) と MOV [EBX+ESI+disp8],EAX (89 44 33 ib)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x8B44_3310, 32), Some(Insn::MovEaxSibd));
        assert_eq!(decode(0x8944_33F0, 32), Some(Insn::MovSibdEax));
        assert_eq!(decode(0x8B44_3400, 32), None);
        // MUL/DIV/IDIV EAX,ECX (F7 /4,/6,/7)。ModRM の reg フィールドで区別する。
        // F7 E0 (/4 rm=000) は未対応の別命令であり一致しない。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0xF7E1, 16), Some(Insn::MulRm32));
        assert_eq!(decode(0xF7F1, 16), Some(Insn::DivRm32));
        assert_eq!(decode(0xF7F9, 16), Some(Insn::IdivRm32));
        assert_eq!(decode(0xF7E0, 16), None);
        // SIB スケール付き（ss=01/10/11）：*2=0x73、*4=0xB3、*8=0xF3。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x8B44_7310, 32), Some(Insn::MovEaxSibS2));
        assert_eq!(decode(0x8944_7310, 32), Some(Insn::MovSibS2Eax));
        assert_eq!(decode(0x8B44_B310, 32), Some(Insn::MovEaxSibS4));
        assert_eq!(decode(0x8944_B310, 32), Some(Insn::MovSibS4Eax));
        assert_eq!(decode(0x8B44_F310, 32), Some(Insn::MovEaxSibS8));
        assert_eq!(decode(0x8944_F310, 32), Some(Insn::MovSibS8Eax));
        // SIB スケール付き・disp なし：MOV EAX,[EBX+ESI*{2,4,8}] (8B 04 {73,B3,F3}) と
        // MOV [EBX+ESI*{2,4,8}],EAX (89 04 {73,B3,F3})。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x008B_0473, 24), Some(Insn::MovEaxSibS2nd));
        assert_eq!(decode(0x0089_0473, 24), Some(Insn::MovSibS2ndEax));
        assert_eq!(decode(0x008B_04B3, 24), Some(Insn::MovEaxSibS4nd));
        assert_eq!(decode(0x0089_04B3, 24), Some(Insn::MovSibS4ndEax));
        assert_eq!(decode(0x008B_04F3, 24), Some(Insn::MovEaxSibS8nd));
        assert_eq!(decode(0x0089_04F3, 24), Some(Insn::MovSibS8ndEax));
        // SIB スケール付き・disp32：MOV EAX,[EBX+ESI*{2,4,8}+disp32]
        // (8B 84 {73,B3,F3}+disp32) と MOV [EBX+ESI*{2,4,8}+disp32],EAX (89 84 ...)、
        // 直接番地 base：MOV EAX,[ESI*{2,4,8}+disp32] (8B 04 {75,B5,F5}+disp32) と
        // MOV [ESI*{2,4,8}+disp32],EAX (89 04 ...)（56ビット）。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(
            decode(0x008B_8473_1000_0000, 56),
            Some(Insn::MovEaxSibS2d32)
        );
        assert_eq!(
            decode(0x0089_8473_1000_0000, 56),
            Some(Insn::MovSibS2d32Eax)
        );
        assert_eq!(
            decode(0x008B_84B3_1000_0000, 56),
            Some(Insn::MovEaxSibS4d32)
        );
        assert_eq!(
            decode(0x0089_84B3_1000_0000, 56),
            Some(Insn::MovSibS4d32Eax)
        );
        assert_eq!(
            decode(0x008B_84F3_1000_0000, 56),
            Some(Insn::MovEaxSibS8d32)
        );
        assert_eq!(
            decode(0x0089_84F3_1000_0000, 56),
            Some(Insn::MovSibS8d32Eax)
        );
        assert_eq!(
            decode(0x008B_0475_1000_0000, 56),
            Some(Insn::MovEaxSibS2a32)
        );
        assert_eq!(
            decode(0x0089_0475_1000_0000, 56),
            Some(Insn::MovSibS2a32Eax)
        );
        assert_eq!(
            decode(0x008B_04B5_1000_0000, 56),
            Some(Insn::MovEaxSibS4a32)
        );
        assert_eq!(
            decode(0x0089_04B5_1000_0000, 56),
            Some(Insn::MovSibS4a32Eax)
        );
        assert_eq!(
            decode(0x008B_04F5_1000_0000, 56),
            Some(Insn::MovEaxSibS8a32)
        );
        assert_eq!(
            decode(0x0089_04F5_1000_0000, 56),
            Some(Insn::MovSibS8a32Eax)
        );
        // 長さ違いは一致しない。
        assert_eq!(decode(0x008B_8473_1000_0000, 32), None);
        // ModRM mod=01 + disp8：MOV EAX,[EBX+disp8] (8B 43 ..) と MOV [EBX+disp8],EAX (89 43 ..)。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x008B_4310, 24), Some(Insn::MovEaxMem));
        assert_eq!(decode(0x0089_43F0, 24), Some(Insn::MovMemEax));
        // mod=00 [EBX]（disp なし）：gas は disp8=0 を mod=00 に畳む。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x8B03, 16), Some(Insn::MovEaxMemnd));
        assert_eq!(decode(0x8903, 16), Some(Insn::MovMemndEax));
        assert_eq!(decode(0x8B00, 16), None);
        // ModRM mod=10 + disp32：MOV EAX,[EBX+disp32] (8B 83+disp32) と
        // MOV [EBX+disp32],EAX (89 83+disp32)。絶対番地：MOV EAX,[disp32] (8B 05+disp32) と
        // MOV [disp32],EAX (89 05+disp32)。disp32 は LE 実バイト列を上位詰めで表す。
        // Ref: SPEC-X86-INTEL-SDM (v093).
        assert_eq!(decode(0x8B83_7856_3412, 48), Some(Insn::MovEaxMemd32));
        assert_eq!(decode(0x8983_7856_3412, 48), Some(Insn::MovMemd32Eax));
        assert_eq!(decode(0x8B05_7856_3412, 48), Some(Insn::MovEaxAbs));
        assert_eq!(decode(0x8905_7856_3412, 48), Some(Insn::MovAbsEax));
        // mod違い・長さ違いは一致しない。
        assert_eq!(decode(0x8B43_7856_3412, 48), None);
        assert_eq!(decode(0x8B83_7856_3412, 32), None);
        // disp8 の値は don't care であり、mod=10 (disp32) とは一致しない。
        assert_eq!(decode(0x008B_8310, 24), None);
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
