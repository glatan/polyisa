// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// x86 最小の ISADL モデル（段階4の最小）。
//
// i386 の整数126件に C7・83 の /r と string 操作・MOVSXD の計134件。
// REX 接頭辞はデコード前に剥がし、Insは共有して意味論で切り替える。
// 可変長（8/16/24/32/40/48/56ビット）のデコード入口と
// ModRM register-direct の全レジスタ組合せを確かめる。
// REX.W=1 の64ビット演算と R8-R15・SIB・64ビットメモリ形式は意味論・実行側で足す。
// ModRM の disp32・絶対番地は EBX 基底と直接番地のみ持つ。SIB base は EBX または
// 直接番地のみ持つ。Rust フック・遅延フラグ・x87・SSE・セグメントと
// REX.W 最小以外の64ビット拡張は本格実装で足す。
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

    for class in ["alu", "jump", "system", "load", "store", "mult", "div"] {
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

    // ModRM/SIB のフィールド。長さごとにビット位置が変わるため形式を分ける。
    // 末尾の数字はパターン長（ビット）を表す。
    for (name, hi, lo) in [
        ("m8_mod", 15, 14),
        ("m8_reg", 13, 11),
        ("m8_rm", 10, 8),
        ("mr_mod", 7, 6),
        ("mr_reg", 5, 3),
        ("mr_rm", 2, 0),
        ("m32_mod", 39, 38),
        ("m32_reg", 37, 35),
        ("m32_rm", 34, 32),
        ("s8_mod", 23, 22),
        ("s8_reg", 21, 19),
        ("s8_rm", 18, 16),
        ("s8_ss", 15, 14),
        ("s8_idx", 13, 11),
        ("s8_base", 10, 8),
        ("n8_mod", 15, 14),
        ("n8_reg", 13, 11),
        ("n8_rm", 10, 8),
        ("n8_ss", 7, 6),
        ("n8_idx", 5, 3),
        ("n8_base", 2, 0),
        ("d32_mod", 47, 46),
        ("d32_reg", 45, 43),
        ("d32_rm", 42, 40),
        ("d32_ss", 39, 38),
        ("d32_idx", 37, 35),
        ("d32_base", 34, 32),
    ] {
        m.fields.push(Field {
            name: name.to_string(),
            kind: FieldKind::Bits { hi, lo },
        });
    }
    for (name, fields) in [
        ("M8", vec!["m8_mod", "m8_reg", "m8_rm"]),
        ("MR", vec!["mr_mod", "mr_reg", "mr_rm"]),
        ("M32", vec!["m32_mod", "m32_reg", "m32_rm"]),
        (
            "S8",
            vec!["s8_mod", "s8_reg", "s8_rm", "s8_ss", "s8_idx", "s8_base"],
        ),
        (
            "N8",
            vec!["n8_mod", "n8_reg", "n8_rm", "n8_ss", "n8_idx", "n8_base"],
        ),
        (
            "D32",
            vec![
                "d32_mod",
                "d32_reg",
                "d32_rm",
                "d32_ss",
                "d32_idx",
                "d32_base",
            ],
        ),
    ] {
        m.formats.push(Format {
            name: name.to_string(),
            fields: fields.iter().map(|s| s.to_string()).collect(),
            operands: vec![],
        });
    }

    // (名前, 形式, パターン, 構文, 分類)
    // 可変長：8ビット単独、16ビット（opcode+disp8/modrm）、24ビット（opcode+modrm+disp8、
    // opcode+modrm+SIB）、32ビット（opcode+modrm+SIB+disp8）、40ビット（opcode+imm32）、
    // 48ビット（opcode+modrm+disp32）、56ビット（opcode+modrm+SIB+disp32）。
    // メモリ形式は ModRM base 任意（mod=01+disp8・mod=10+disp32・mod=00）と
    // SIB base/index/scale 任意（mod=00/01/10・直接番地 base を含む）を持つ。
    // base/index/scale/disp の展開は where と実行側の抽出で行う。
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
        ("add_rm32", "F1", "00000001 11......", "add r/m32, r32", "alu"),
        ("mov_rm32", "F1", "10001011 11......", "mov r32, r/m32", "alu"),
        ("mov_eax_abs", "F1", "10001011 00000101 ................................", "mov eax, [disp32]", "load"),
        ("mov_abs_eax", "F1", "10001001 00000101 ................................", "mov [disp32], eax", "store"),
        ("mul_rm32", "F1", "11110111 11100001", "mul eax, ecx", "mult"),
        ("div_rm32", "F1", "11110111 11110001", "div eax, ecx", "div"),
        ("idiv_rm32", "F1", "11110111 11111001", "idiv eax, ecx", "div"),
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
        ("jl", "F1", "01111100 ........", "jl {imm}", "jump"),
        ("jge", "F1", "01111101 ........", "jge {imm}", "jump"),
        ("jle", "F1", "01111110 ........", "jle {imm}", "jump"),
        ("jg", "F1", "01111111 ........", "jg {imm}", "jump"),
        ("loop", "F1", "11100010 ........", "loop {imm}", "jump"),
        ("jmp_rel32", "F1", "11101001 ................................", "jmp {imm}", "jump"),
        ("xor_rm32", "F1", "00110001 11......", "xor r/m32, r32", "alu"),
        ("and_eax", "F1", "00100101 ................................", "and eax, {imm}", "alu"),
        ("or_eax", "F1", "00001101 ................................", "or eax, {imm}", "alu"),
        ("xor_imm", "F1", "00110101 ................................", "xor eax, {imm}", "alu"),
        ("shl_eax", "F1", "11000001 11100000 ........", "shl eax, {imm}", "alu"),
        ("shr_eax", "F1", "11000001 11101000 ........", "shr eax, {imm}", "alu"),
        ("int80", "F1", "11001101 10000000", "int 0x80", "system"),
        ("cmp_rm32", "F1", "00111001 11......", "cmp r/m32, r32", "alu"),
        ("and_rm32", "F1", "00100001 11......", "and r/m32, r32", "alu"),
        ("or_rm32", "F1", "00001001 11......", "or r/m32, r32", "alu"),
        ("sub_rm32", "F1", "00101001 11......", "sub r/m32, r32", "alu"),
        ("sub_eax", "F1", "00101101 ................................", "sub eax, {imm}", "alu"),
        ("mov_mr32", "F1", "10001001 11......", "mov r/m32, r32", "alu"),
        ("leave", "F1", "11001001", "leave", "alu"),
        ("mov_eax", "F1", "10111000 ................................", "mov eax, {imm}", "alu"),
        ("syscall", "F1", "00001111 00000101", "syscall", "system"),
        ("cpuid", "F1", "00001111 10100010", "cpuid", "system"),
        ("mov_rm_imm", "F1", "11000111 11000... ................................", "mov r/m, {imm}", "alu"),
        ("and_rm_imm8", "F1", "10000011 11...100 ........", "and r/m, {imm}", "alu"),
        ("movsxd", "F1", "01100011 11......", "movsxd r, r/m32", "alu"),
        ("movsb", "F1", "10100100", "movsb", "load"),
        ("movsd", "F1", "10100101", "movsd", "load"),
        ("stosb", "F1", "10101010", "stosb", "store"),
        ("stosd", "F1", "10101011", "stosd", "store"),
        ("endbr64", "F1", "00001111 00011110 11111010", "endbr64", "alu"),
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
    // ModRM/SIB の汎用形。base/index/scale は実行側で抽出する。
    // mod/rm の一致は where で絞る（パターンの don't care と組み合わせる）。
    let wc = |field: &str, op: WhereOp, value: u128| WhereClause {
        field: field.to_string(),
        op,
        value,
    };
    // (名前, 形式, パターン, where, 構文, 分類)
    type MemDef<'a> = (&'a str, &'a str, &'a str, Vec<WhereClause>, &'a str, &'a str);
    let mem: &[MemDef] = &[ 
        (
            "mov_eax_mem8",
            "M8",
            "10001011 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "mov r32, [r/m+disp8]",
            "load",
        ),
        (
            "mov_mem_eax8",
            "M8",
            "10001001 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "mov [r/m+disp8], r32",
            "store",
        ),
        (
            "mov_eax_mem32",
            "M32",
            "10001011 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "mov r32, [r/m+disp32]",
            "load",
        ),
        (
            "mov_mem_eax32",
            "M32",
            "10001001 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "mov [r/m+disp32], r32",
            "store",
        ),
        (
            "mov_eax_memnd",
            "MR",
            "10001011 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "mov r32, [r/m]",
            "load",
        ),
        (
            "mov_memnd_eax",
            "MR",
            "10001001 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "mov [r/m], r32",
            "store",
        ),
        (
            "mov_eax_sib",
            "N8",
            "10001011 00...100 ........",
            vec![wc("n8_base", WhereOp::Ne, 5)],
            "mov r32, [r/m+sib]",
            "load",
        ),
        (
            "mov_sib_eax",
            "N8",
            "10001001 00...100 ........",
            vec![wc("n8_base", WhereOp::Ne, 5)],
            "mov [r/m+sib], r32",
            "store",
        ),
        (
            "lea_m8",
            "M8",
            "10001101 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "lea r32, [r/m+disp8]",
            "alu",
        ),
        (
            "lea_m32",
            "M32",
            "10001101 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "lea r32, [r/m+disp32]",
            "alu",
        ),
        (
            "lea_mnd",
            "MR",
            "10001101 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "lea r32, [r/m]",
            "alu",
        ),
        (
            "mov_eax_sibd",
            "S8",
            "10001011 01...100 ........ ........",
            vec![],
            "mov r32, [r/m+sib+disp8]",
            "load",
        ),
        (
            "mov_sibd_eax",
            "S8",
            "10001001 01...100 ........ ........",
            vec![],
            "mov [r/m+sib+disp8], r32",
            "store",
        ),
        (
            "lea_sib",
            "N8",
            "10001101 00...100 ........",
            vec![wc("n8_base", WhereOp::Ne, 5)],
            "lea r32, [r/m+sib]",
            "alu",
        ),
        (
            "lea_sibd",
            "S8",
            "10001101 01...100 ........ ........",
            vec![],
            "lea r32, [r/m+sib+disp8]",
            "alu",
        ),
        (
            "lea_abs",
            "F1",
            "10001101 00...101 ................................",
            vec![],
            "lea r32, [disp32]",
            "alu",
        ),
        (
            "mov_eax_sibd32",
            "D32",
            "10001011 10...100 ........ ................................",
            vec![],
            "mov r32, [r/m+sib+disp32]",
            "load",
        ),
        (
            "mov_sibd32_eax",
            "D32",
            "10001001 10...100 ........ ................................",
            vec![],
            "mov [r/m+sib+disp32], r32",
            "store",
        ),
        (
            "mov_eax_sibabs",
            "D32",
            "10001011 00...100 ........ ................................",
            vec![wc("d32_base", WhereOp::Eq, 5)],
            "mov r32, [sib+disp32]",
            "load",
        ),
        (
            "mov_sibabs_eax",
            "D32",
            "10001001 00...100 ........ ................................",
            vec![wc("d32_base", WhereOp::Eq, 5)],
            "mov [sib+disp32], r32",
            "store",
        ),
        (
            "lea_sibd32",
            "D32",
            "10001101 10...100 ........ ................................",
            vec![],
            "lea r32, [r/m+sib+disp32]",
            "alu",
        ),
        (
            "lea_sibabs",
            "D32",
            "10001101 00...100 ........ ................................",
            vec![wc("d32_base", WhereOp::Eq, 5)],
            "lea r32, [sib+disp32]",
            "alu",
        ),
    ];
    for (name, format, pattern, wheres, syntax, timing) in mem {
        m.insns.push(Insn {
            name: name.to_string(),
            format: format.to_string(),
            pattern: Pattern::parse(pattern).expect("valid pattern"),
            when: Pred::True,
            wheres: wheres.clone(),
            syntax: syntax.to_string(),
            timing: timing.to_string(),
        });
    }
    m
}
