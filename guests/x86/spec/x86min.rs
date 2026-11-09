// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// x86 最小の ISADL モデル（段階4の最小）。
//
// i386 の105件に ModRM/SIB 汎用 23件と string・NOP・MOVSXD・C7・83 を加えた計106件。
// REX 接頭辞はデコード前に剥がし、Insは共有して意味論で切り替える。
// 可変長（8/16/24/32/40/48/56ビット）のデコード入口と
// ModRM/SIB は base/index/scale 汎用形（where 付き）で確かめる。
// REX.W=1 の64ビット演算と R8-R15 は意味論・実行側で扱う。
// ModRM・SIB とも base/index 任意。絶対番地は 32bit・RIP相対（64bit）を持つ。
// Rust フック・遅延フラグ・x87・SSE・セグメントは本格実装で足す。
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
        ("mov_eax_abs", "F1", "10001011 00...101 ................................", "mov eax, [disp32]", "load"),
        ("mov_abs_eax", "F1", "10001001 00...101 ................................", "mov [disp32], eax", "store"),
        ("mul_rm32", "F1", "11110111 11100...", "mul eax, r/m32", "mult"),
        ("div_rm32", "F1", "11110111 11110...", "div eax, r/m32", "div"),
        ("idiv_rm32", "F1", "11110111 11111...", "idiv eax, r/m32", "div"),
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
        
        ("int80", "F1", "11001101 10000000", "int 0x80", "system"),
        ("cmp_rm32", "F1", "00111001 11......", "cmp r/m32, r32", "alu"),
        ("and_rm32", "F1", "00100001 11......", "and r/m32, r32", "alu"),
        ("or_rm32", "F1", "00001001 11......", "or r/m32, r32", "alu"),
        ("sub_rm32", "F1", "00101001 11......", "sub r/m32, r32", "alu"),
        ("sub_eax", "F1", "00101101 ................................", "sub eax, {imm}", "alu"),
        ("mov_mr32", "F1", "10001001 11......", "mov r/m32, r32", "alu"),
        ("leave", "F1", "11001001", "leave", "alu"),
        ("mov_r32_imm", "F1", "10111... ................................", "mov r32, {imm}", "alu"),
        ("mov_r64_imm64", "F1", "10111... ................................................................", "mov r64, {imm}", "alu"),
        ("syscall", "F1", "00001111 00000101", "syscall", "system"),
        ("cpuid", "F1", "00001111 10100010", "cpuid", "system"),
        ("mov_rm_imm", "F1", "11000111 11000... ................................", "mov r/m, {imm}", "alu"),
        ("add_rm_imm8", "F1", "10000011 11000... ........", "add r/m, {imm}", "alu"),
        ("or_rm_imm8", "F1", "10000011 11001... ........", "or r/m, {imm}", "alu"),
        ("adc_rm_imm8", "F1", "10000011 11010... ........", "adc r/m, {imm}", "alu"),
        ("sbb_rm_imm8", "F1", "10000011 11011... ........", "sbb r/m, {imm}", "alu"),
        ("and_rm_imm8", "F1", "10000011 11100... ........", "and r/m, {imm}", "alu"),
        ("sub_rm_imm8", "F1", "10000011 11101... ........", "sub r/m, {imm}", "alu"),
        ("xor_rm_imm8", "F1", "10000011 11110... ........", "xor r/m, {imm}", "alu"),
        ("cmp_rm_imm8", "F1", "10000011 11111... ........", "cmp r/m, {imm}", "alu"),
        ("sub_rm32_imm", "F1", "10000001 11101... ................................", "sub r/m32, {imm}", "alu"),
        ("sub_rm64_imm", "F1", "01001000 10000001 11101... ................................", "sub r/m64, {imm}", "alu"),
        ("cmp_rm32_imm", "F1", "10000001 11111... ................................", "cmp r/m32, {imm}", "alu"),
        ("cmp_rm64_imm", "F1", "01001000 10000001 11111... ................................", "cmp r/m64, {imm}", "alu"),
        ("movsxd", "F1", "01100011 11......", "movsxd r, r/m32", "alu"),
        ("movsb", "F1", "10100100", "movsb", "load"),
        ("movsd", "F1", "10100101", "movsd", "load"),
        ("stosb", "F1", "10101010", "stosb", "store"),
        ("stosd", "F1", "10101011", "stosd", "store"),
        ("endbr64", "F1", "00001111 00011110 11111010", "endbr64", "alu"),
        ("nopl", "F1", "00001111 00011111 00000000", "nopl", "alu"),
        // XMM 最小セット（66 接頭辞は実行側で剥がす。REX.W は dispatch で見る）。
        // MOVD xmm,r32 (66 0F 6E /r)。reg-direct のみ。
        ("movd_xmm", "F1", "00001111 01101110 11......", "movd xmm, r32", "load"),
        ("movd_xmm_m32", "F1", "00001111 01101110 10000101 ................................", "movd xmm, m32", "load"),
        // PUNPCKLBW xmm,xmm (66 0F 60 /r)。reg-direct のみ。
        ("punpcklbw", "F1", "00001111 01100000 11......", "punpcklbw xmm, xmm", "alu"),
        // PUNPCKLWD xmm,xmm (66 0F 61 /r)。reg-direct のみ。
        ("punpcklwd", "F1", "00001111 01100001 11......", "punpcklwd xmm, xmm", "alu"),
        // PSHUFD xmm,xmm,imm8 (66 0F 70 /r ib)。reg-direct のみ。
        ("pshufd", "F1", "00001111 01110000 11...... ........", "pshufd xmm, xmm", "alu"),
        // MOVQ r64,xmm (66 REX.W 0F 7E /r)。reg-direct のみ。
        ("movq_r64_xmm", "F1", "00001111 01111110 11......", "movq r64, xmm", "load"),
        // MOVUPS xmm,xmm / m128,xmm (0F 10 / 0F 11)。reg-direct は F1。
        ("movups_load_xmm", "F1", "00001111 00010000 11......", "movups xmm, xmm", "load"),
        ("movups_store_xmm", "F1", "00001111 00010001 11......", "movups xmm, xmm", "store"),
        // near Jcc (0F 80-8F + disp32)。6バイト。条件は dispatch で分ける。
        ("jo_rel32", "F1", "00001111 10000000 ................................", "jo rel32", "jump"),
        ("jno_rel32", "F1", "00001111 10000001 ................................", "jno rel32", "jump"),
        ("jb_rel32", "F1", "00001111 10000010 ................................", "jb rel32", "jump"),
        ("jae_rel32", "F1", "00001111 10000011 ................................", "jae rel32", "jump"),
        ("je_rel32", "F1", "00001111 10000100 ................................", "je rel32", "jump"),
        ("jne_rel32", "F1", "00001111 10000101 ................................", "jne rel32", "jump"),
        ("jbe_rel32", "F1", "00001111 10000110 ................................", "jbe rel32", "jump"),
        ("ja_rel32", "F1", "00001111 10000111 ................................", "ja rel32", "jump"),
        ("js_rel32", "F1", "00001111 10001000 ................................", "js rel32", "jump"),
        ("jns_rel32", "F1", "00001111 10001001 ................................", "jns rel32", "jump"),
        ("jp_rel32", "F1", "00001111 10001010 ................................", "jp rel32", "jump"),
        ("jnp_rel32", "F1", "00001111 10001011 ................................", "jnp rel32", "jump"),
        ("jl_rel32", "F1", "00001111 10001100 ................................", "jl rel32", "jump"),
        ("jge_rel32", "F1", "00001111 10001101 ................................", "jge rel32", "jump"),
        ("jle_rel32", "F1", "00001111 10001110 ................................", "jle rel32", "jump"),
        ("jg_rel32", "F1", "00001111 10001111 ................................", "jg rel32", "jump"),
        ("nopl_sibd32", "F1", "00001111 00011111 10000100 ........ ................................", "nopl [r/m+sib+disp32]", "alu"),
        // MOVZX r32,r/m16 (0F B7 /r)。RBP+disp32 形。
        ("movzx_r32_m16", "F1", "00001111 10110111 10010101 ................................", "movzx r32, r/m16", "load"),
        // CMOVB r32/r64, r/m32/r/m64 (0F 42 /r)。reg-direct のみ。REX.W で切替.
        ("cmovb", "F1", "00001111 01000010 11......", "cmovb r, r/m", "alu"),
        // CMOVNE r32/r64, r/m32/r/m64 (0F 45 /r)。reg-direct のみ.
        ("cmovne", "F1", "00001111 01000101 11......", "cmovne r, r/m", "alu"),
        // CMOVE r32/r64, r/m32/r/m64 (0F 44 /r)。reg-direct のみ.
        ("cmove", "F1", "00001111 01000100 11......", "cmove r, r/m", "alu"),
        // CMOVNS r32/r64, r/m32/r/m64 (0F 49 /r)。reg-direct のみ.
        ("cmovns", "F1", "00001111 01001001 11......", "cmovns r, r/m", "alu"),
        ("cmovbe", "F1", "00001111 01000110 11......", "cmovbe r, r/m", "alu"),
        // OR m32,imm32 RIP (81 0D + disp32 + imm32)。64ビット RIP相対.
        ("or_rm32_rip", "F1", "10000001 00001101 ................................ ................................", "or r/m32, {imm}", "alu"),
        // OR r32,m32 RIP (0B 15 + disp32)。
        ("or_r_rip", "F1", "00001011 00...101 ................................", "or r32, m32", "alu"),
        // OR m32,r32 RIP (09 05 + disp32)。
        ("or_m_rip", "F1", "00001001 00...101 ................................", "or m32, r32", "alu"),
        // ADD m32,imm32 RIP (81 05 + disp32 + imm32).
        ("add_rm32_rip", "F1", "10000001 00000101 ................................ ................................", "add r/m32, {imm}", "alu"),
        // C7 /0 RIP+disp32+imm32 (10バイト)。REX.W で64ビット.
        ("mov_rm_imm_rip", "F1", "11000111 00000101 ................................ ................................", "mov r/m, {imm}", "alu"),
        // 81 /r imm32 群 (ADD/OR/ADC/SBB/AND/XOR)。reg-direct のみ。REX.W で64切替 (ADDのみ64あり).
        ("add_rm32_imm", "F1", "10000001 11000... ................................", "add r/m32, {imm}", "alu"),
        ("add_rm64_imm", "F1", "01001000 10000001 11000... ................................", "add r/m64, {imm}", "alu"),
        ("or_rm32_imm", "F1", "10000001 11001... ................................", "or r/m32, {imm}", "alu"),
        ("adc_rm32_imm", "F1", "10000001 11010... ................................", "adc r/m32, {imm}", "alu"),
        ("sbb_rm32_imm", "F1", "10000001 11011... ................................", "sbb r/m32, {imm}", "alu"),
        ("and_rm32_imm", "F1", "10000001 11100... ................................", "and r/m32, {imm}", "alu"),
        ("xor_rm32_imm", "F1", "10000001 11110... ................................", "xor r/m32, {imm}", "alu"),
        // C7 /0 SIB+disp32+imm32 (11バイト)。REX.W で64切替は dispatch で.
        ("mov_rm_imm_sibd32", "F1", "11000111 10...100 ........ ................................ ................................", "mov r/m, {imm}", "alu"),
        // MOVUPS SIB+disp32 (8バイト)。
        ("movups_load_sibd32", "F1", "00001111 00010000 10...100 ........ ................................", "movups xmm, [r/m+sib+disp32]", "load"),
        ("movups_store_sibd32", "F1", "00001111 00010001 10...100 ........ ................................", "movups [r/m+sib+disp32], xmm", "store"),
        // MOVAPS SIB+disp32 (8バイト)。
        ("movaps_store_sibd32", "F1", "00001111 00101001 10...100 ........ ................................", "movaps [r/m+sib+disp32], xmm", "store"),
        // MOVZX r32,m16 RIP (0F B7 05 + disp32)。
        ("movzx_r32_m16_rip", "F1", "00001111 10110111 00000101 ................................", "movzx r32, m16", "load"),
        // PXOR xmm,xmm (66 0F EF /r)。
        ("pxor", "F1", "00001111 11101111 11......", "pxor xmm, xmm", "alu"),
        ("punpckldq", "F1", "00001111 01100010 11......", "punpckldq xmm, xmm", "alu"),
        ("movq_m64_xmm_rip", "F1", "00001111 11010110 00...101 ................................", "movq m64, xmm", "store"),
        ("shr_rm32_imm8", "F1", "11000001 11101... ........", "shr r/m32, {imm}", "alu"),
        ("sar_rm32_imm8", "F1", "11000001 11111... ........", "sar r/m32, {imm}", "alu"),
        // TEST r/m32,r32 (85 /r)。
        ("test_rm32", "F1", "10000101 11......", "test r/m32, r32", "alu"),
        ("test_rm32_imm", "F1", "11110111 11000... ................................", "test r/m32, {imm}", "alu"),
        ("not_rm32", "F1", "11110111 11010...", "not r/m32", "alu"),
        ("neg_rm32", "F1", "11110111 11011...", "neg r/m32", "alu"),
        ("test_rm8_imm", "F1", "11110110 11000... ........", "test r/m8, {imm}", "alu"),
        ("and_rm8_imm", "F1", "10000000 11100... ........", "and r/m8, {imm}", "alu"),
        ("test_m8_imm_rip", "F1", "11110110 00000101 ................................ ........", "test m8, {imm}", "alu"),
        ("or_rm_imm8_rip", "F1", "10000011 00001101 ................................ ........", "or r/m, {imm}", "alu"),
        ("test_al_imm", "F1", "10101000 ........", "test al, {imm}", "alu"),
        ("test_eax_imm", "F1", "10101001 ................................", "test eax, {imm}", "alu"),
        // ADD r32, m32 (03 /r)。RIP/abs のみ。REX.W で64ビット.
        ("add_r_rip", "F1", "00000011 00...101 ................................", "add r, [rip]", "alu"),
        // CMP [RIP+disp32],imm8 (83 3D + disp32 + imm8)。64ビット RIP相対.
        ("cmp_rm_imm8_rip", "F1", "10000011 00111101 ................................ ........", "cmp r/m, {imm}", "alu"),
        // C7 /0 m64,imm32 (REX.W)。RBP+disp32 形 (mod=10 rm=101)。REX は剥がし済み.
        ("mov_rm_imm_m32", "F1", "11000111 10000101 ................................ ................................", "mov r/m, {imm}", "alu"),
        ("mov_rm16_imm_m32", "F1", "11000111 10000101 ................................ ................", "mov r/m16, {imm}", "alu"),
        // MOVUPS RIP相対 (64ビットの mod=00 rm=101)。disp32 は実行側で RIP 加算する。
        ("movups_load_rip", "F1", "00001111 00010000 00...101 ................................", "movups xmm, [rip]", "load"),
        ("movups_store_rip", "F1", "00001111 00010001 00...101 ................................", "movups [rip], xmm", "store"),
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
        (
            "cmp_rm_imm8m8",
            "S8",
            "10000011 01111... ........ ........",
            vec![wc("s8_rm", WhereOp::Ne, 4)],
            "cmp r/m, {imm}",
            "alu",
        ),
        (
            "cmp_rm_imm8_memnd",
            "M8",
            "10000011 00111... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4), wc("m8_rm", WhereOp::Ne, 5)],
            "cmp r/m, {imm}",
            "alu",
        ),
        (
            "movups_load_memnd",
            "MR",
            "00001111 00010000 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "movups xmm, [r/m]",
            "load",
        ),
        (
            "movups_store_memnd",
            "MR",
            "00001111 00010001 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "movups [r/m], xmm",
            "store",
        ),
        (
            "movups_load_mem8",
            "M8",
            "00001111 00010000 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "movups xmm, [r/m+disp8]",
            "load",
        ),
        (
            "movups_store_mem8",
            "M8",
            "00001111 00010001 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "movups [r/m+disp8], xmm",
            "store",
        ),
        (
            "movups_load_sib",
            "N8",
            "00001111 00010000 00...100 ........",
            vec![wc("n8_base", WhereOp::Ne, 5)],
            "movups xmm, [r/m+sib]",
            "load",
        ),
        (
            "movups_store_sib",
            "N8",
            "00001111 00010001 00...100 ........",
            vec![wc("n8_base", WhereOp::Ne, 5)],
            "movups [r/m+sib], xmm",
            "store",
        ),
        (
            "movups_load_sibd",
            "S8",
            "00001111 00010000 01...100 ........ ........",
            vec![],
            "movups xmm, [r/m+sib+disp8]",
            "load",
        ),
        (
            "movups_store_sibd",
            "S8",
            "00001111 00010001 01...100 ........ ........",
            vec![],
            "movups [r/m+sib+disp8], xmm",
            "store",
        ),
        (
            "movntdq_store_memnd",
            "MR",
            "00001111 11100111 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "movntdq [r/m], xmm",
            "store",
        ),
        (
            "movntdq_store_mem8",
            "M8",
            "00001111 11100111 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "movntdq [r/m+disp8], xmm",
            "store",
        ),
        (
            "movaps_store_memnd",
            "MR",
            "00001111 00101001 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "movaps [r/m], xmm",
            "store",
        ),
        (
            "movaps_store_mem8",
            "M8",
            "00001111 00101001 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "movaps [r/m+disp8], xmm",
            "store",
        ),
        (
            "nopl_sib",
            "N8",
            "00001111 00011111 00...100 ........",
            vec![wc("n8_base", WhereOp::Ne, 5)],
            "nopl [r/m+sib]",
            "alu",
        ),
        (
            "nopl_sibd",
            "S8",
            "00001111 00011111 01...100 ........ ........",
            vec![],
            "nopl [r/m+sib+disp8]",
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
