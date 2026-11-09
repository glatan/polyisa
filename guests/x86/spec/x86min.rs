// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// x86 最小の ISADL モデル（段階4の最小）。
//
// i386 の整数78件に絞る。可変長（8/16/24/32/40ビット）のデコード入口と
// ModRM register-direct の最小形を確かめる。
// ModRM の disp32・絶対番地・スケール付き SIB と Rust フック・遅延フラグ・x87・SSE・
// 64ビット・セグメントは本格実装で足す。
// SYSCALL/CPUID は退出・識別情報の最小形のみ持つ（機能導出は本格実装で足す）。
// SYSCALL (0F 05) は IA-32e 用であり 32bit 正統は SYSENTER (0F 34) だが、
// 試作では x86-64 への橋渡しとして SYSCALL を先に持つ。i386 feature の無条件有効は試作の割り切りである。
// imm32/disp8 の切り出しは本格実装で足す。
// 出典は SPEC-X86-INTEL-SDM Combined v093 (2026-09-24) である。
// Ref: SPEC-X86-INTEL-SDM (v093).

use polyisa_isadl::model::*;
use polyisa_isadl::pattern::Pattern;
use polyisa_isadl::pred::Pred;

/// x86 最小の検査済みモデルを作る。
pub fn build_model() -> polyisa_isadl::Model {
    let mut m = polyisa_isadl::Model::new();

    for class in ["alu", "jump", "system", "load", "store"] {
        m.timing_classes.push(class.to_string());
    }

    // Ref: SPEC-X86-INTEL-SDM (v093).
    m.features.push(Feature {
        name: "i386".to_string(),
        implies: vec![],
        conflicts: vec![],
    });
    m.models.push(ModelDef {
        name: "generic32".to_string(),
        parent: String::new(),
        add_features: vec!["i386".to_string()],
        remove_features: vec![],
    });

    m.regclasses.push(RegClass {
        name: "gpr".to_string(),
        dynamic: false,
    });

    // F1: オペランドを取り出さない形式（imm/disp は本格実装で足す）。
    m.formats.push(Format {
        name: "F1".to_string(),
        fields: vec![],
        operands: vec![],
    });

    // (名前, 形式, パターン, 構文, 分類)
    // 可変長：8ビット単独、16ビット（opcode+disp8/modrm）、24ビット（opcode+modrm+disp8、
    // opcode+modrm+SIB）、32ビット（opcode+modrm+SIB+disp8）、40ビット（opcode+imm32）。
    // メモリ形式は mod=01+disp8 と SIB base+index（±disp8）のみ持つ。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let insns: &[(&str, &str, &str, &str, &str)] = &[
        ("nop", "F1", "10010000", "nop", "alu"),
        ("inc_eax", "F1", "01000000", "inc eax", "alu"),
        ("inc_ecx", "F1", "01000001", "inc ecx", "alu"),
        ("inc_edx", "F1", "01000010", "inc edx", "alu"),
        ("inc_ebx", "F1", "01000011", "inc ebx", "alu"),
        ("inc_esp", "F1", "01000100", "inc esp", "alu"),
        ("inc_ebp", "F1", "01000101", "inc ebp", "alu"),
        ("inc_esi", "F1", "01000110", "inc esi", "alu"),
        ("inc_edi", "F1", "01000111", "inc edi", "alu"),
        ("dec_eax", "F1", "01001000", "dec eax", "alu"),
        ("dec_ecx", "F1", "01001001", "dec ecx", "alu"),
        ("dec_edx", "F1", "01001010", "dec edx", "alu"),
        ("dec_ebx", "F1", "01001011", "dec ebx", "alu"),
        ("dec_esp", "F1", "01001100", "dec esp", "alu"),
        ("dec_ebp", "F1", "01001101", "dec ebp", "alu"),
        ("dec_esi", "F1", "01001110", "dec esi", "alu"),
        ("dec_edi", "F1", "01001111", "dec edi", "alu"),
        ("add_eax", "F1", "00000101 ................................", "add eax, {imm}", "alu"),
        ("jmp8", "F1", "11101011 ........", "jmp {imm}", "jump"),
        ("add_rm32", "F1", "00000001 11001000", "add eax, ecx", "alu"),
        ("mov_rm32", "F1", "10001011 11000001", "mov eax, ecx", "alu"),
        ("mov_eax_mem", "F1", "10001011 01000011 ........", "mov eax, [ebx+disp8]", "load"),
        ("mov_mem_eax", "F1", "10001001 01000011 ........", "mov [ebx+disp8], eax", "store"),
        ("mov_eax_sib", "F1", "10001011 00000100 00110011", "mov eax, [ebx+esi]", "load"),
        ("mov_sib_eax", "F1", "10001001 00000100 00110011", "mov [ebx+esi], eax", "store"),
        ("mov_eax_sibd", "F1", "10001011 01000100 00110011 ........", "mov eax, [ebx+esi+disp8]", "load"),
        ("mov_sibd_eax", "F1", "10001001 01000100 00110011 ........", "mov [ebx+esi+disp8], eax", "store"),
        ("mov_eax_sib_s2", "F1", "10001011 01000100 01110011 ........", "mov eax, [ebx+esi*2+disp8]", "load"),
        ("mov_sib_s2_eax", "F1", "10001001 01000100 01110011 ........", "mov [ebx+esi*2+disp8], eax", "store"),
        ("mov_eax_sib_s4", "F1", "10001011 01000100 10110011 ........", "mov eax, [ebx+esi*4+disp8]", "load"),
        ("mov_sib_s4_eax", "F1", "10001001 01000100 10110011 ........", "mov [ebx+esi*4+disp8], eax", "store"),
        ("mov_eax_sib_s8", "F1", "10001011 01000100 11110011 ........", "mov eax, [ebx+esi*8+disp8]", "load"),
        ("mov_sib_s8_eax", "F1", "10001001 01000100 11110011 ........", "mov [ebx+esi*8+disp8], eax", "store"),
        ("push_eax", "F1", "01010000", "push eax", "store"),
        ("push_ecx", "F1", "01010001", "push ecx", "store"),
        ("push_edx", "F1", "01010010", "push edx", "store"),
        ("push_ebx", "F1", "01010011", "push ebx", "store"),
        ("push_esp", "F1", "01010100", "push esp", "store"),
        ("push_ebp", "F1", "01010101", "push ebp", "store"),
        ("push_esi", "F1", "01010110", "push esi", "store"),
        ("push_edi", "F1", "01010111", "push edi", "store"),
        ("pop_eax", "F1", "01011000", "pop eax", "load"),
        ("pop_ecx", "F1", "01011001", "pop ecx", "load"),
        ("pop_edx", "F1", "01011010", "pop edx", "load"),
        ("pop_ebx", "F1", "01011011", "pop ebx", "load"),
        ("pop_esp", "F1", "01011100", "pop esp", "load"),
        ("pop_ebp", "F1", "01011101", "pop ebp", "load"),
        ("pop_esi", "F1", "01011110", "pop esi", "load"),
        ("pop_edi", "F1", "01011111", "pop edi", "load"),
        ("call_rel32", "F1", "11101000 ................................", "call {imm}", "jump"),
        ("ret", "F1", "11000011", "ret", "jump"),
        ("cmp_eax", "F1", "00111101 ................................", "cmp eax, {imm}", "alu"),
        ("test_eax", "F1", "10000101 11000000", "test eax, eax", "alu"),
        ("je", "F1", "01110100 ........", "je {imm}", "jump"),
        ("jne", "F1", "01110101 ........", "jne {imm}", "jump"),
        ("jb", "F1", "01110010 ........", "jb {imm}", "jump"),
        ("jae", "F1", "01110011 ........", "jae {imm}", "jump"),
        ("jbe", "F1", "01110110 ........", "jbe {imm}", "jump"),
        ("ja", "F1", "01110111 ........", "ja {imm}", "jump"),
        ("loop", "F1", "11100010 ........", "loop {imm}", "jump"),
        ("jmp_rel32", "F1", "11101001 ................................", "jmp {imm}", "jump"),
        ("xor_eax", "F1", "00110001 11000000", "xor eax, eax", "alu"),
        ("and_eax", "F1", "00100101 ................................", "and eax, {imm}", "alu"),
        ("or_eax", "F1", "00001101 ................................", "or eax, {imm}", "alu"),
        ("xor_imm", "F1", "00110101 ................................", "xor eax, {imm}", "alu"),
        ("shl_eax", "F1", "11000001 11100000 ........", "shl eax, {imm}", "alu"),
        ("shr_eax", "F1", "11000001 11101000 ........", "shr eax, {imm}", "alu"),
        ("int80", "F1", "11001101 10000000", "int 0x80", "system"),
        ("lea_eax", "F1", "10001101 01000011 ........", "lea eax, [ebx+disp8]", "alu"),
        ("cmp_rm32", "F1", "00111001 11001000", "cmp eax, ecx", "alu"),
        ("and_rm32", "F1", "00100001 11001000", "and eax, ecx", "alu"),
        ("or_rm32", "F1", "00001001 11001000", "or eax, ecx", "alu"),
        ("sub_eax", "F1", "00101101 ................................", "sub eax, {imm}", "alu"),
        ("mov_ebp_esp", "F1", "10001001 11100101", "mov ebp, esp", "alu"),
        ("leave", "F1", "11001001", "leave", "alu"),
        ("mov_eax", "F1", "10111000 ................................", "mov eax, {imm}", "alu"),
        ("syscall", "F1", "00001111 00000101", "syscall", "system"),
        ("cpuid", "F1", "00001111 10100010", "cpuid", "system"),
    ];
    for (name, format, pattern, syntax, timing) in insns {
        m.insns.push(Insn {
            name: name.to_string(),
            format: format.to_string(),
            pattern: Pattern::parse(pattern).expect("valid pattern"),
            when: Pred::True,
            wheres: vec![],
            syntax: syntax.to_string(),
            timing: timing.to_string(),
        });
    }
    m
}
