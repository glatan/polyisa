// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Gap: GAP-0015
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
        ("c8_mod", 47, 46),
        ("c8_reg", 45, 43),
        ("c8_rm", 42, 40),
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
        // 66 C7 /0 mod=10（disp32+imm16、64ビット語）。rm は ModRM の下位3ビット。
        ("i16_rm", 50, 48),
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
        ("C8", vec!["c8_mod", "c8_reg", "c8_rm"]),
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
        // HLT (F4)。ユーザーモードでは特権例外になるが、glibc の abort は
        // 続けて exit を置く。ここでは 1 バイト進めてその後続を実行する。
        ("hlt", "F1", "11110100", "hlt", "system"),
        ("cld", "F1", "11111100", "cld", "alu"),
        ("std", "F1", "11111101", "std", "alu"),
        // BSWAP r32/r64 (0F C8+rd)。REX.B で拡張、REX.W で64bit。F3/66 剥がし済み.
        ("bswap", "F1", "00001111 11001...", "bswap", "alu"),
        ("inc_eax", "F1", "01000000", "inc eax", "alu"),
        ("inc_ecx", "F1", "01000001", "inc ecx", "alu"),
        ("inc_edx", "F1", "01000010", "inc edx", "alu"),
        ("inc_ebx", "F1", "01000011", "inc ebx", "alu"),
        ("inc_esp", "F1", "01000100", "inc esp", "alu"),
        ("inc_ebp", "F1", "01000101", "inc ebp", "alu"),
        ("inc_esi", "F1", "01000110", "inc esi", "alu"),
        ("inc_edi", "F1", "01000111", "inc edi", "alu"),
        // INC r/m (FF /0 reg-direct)。REX.W で64bit.
        ("inc_rm", "F1", "11111111 11000...", "inc r/m", "alu"),
        // DEC r/m (FF /1 reg-direct)。REX.W で64bit.
        ("dec_rm", "F1", "11111111 11001...", "dec r/m", "alu"),
        // DEC r8 (FE /1 mod=11)。dc 0x40efa1 の FE CA。
        ("dec_r8", "F1", "11111110 11001...", "dec r8", "alu"),
        // INC r8 (FE /0 mod=11)。同じオペコードの増分。
        ("inc_r8", "F1", "11111110 11000...", "inc r8", "alu"),
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
        ("imul_rm32", "F1", "11110111 11101...", "imul eax, r/m32", "mult"),
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
        // PUSH imm32 (68 id)。64ビットでは符号拡張して8バイト積む.
        ("push_imm32", "F1", "01101000 ................................", "push {imm}", "store"),
        // PUSH imm8 (6A ib)。64ビットでは符号拡張して8バイト積む.
        ("push_imm8", "F1", "01101010 ........", "push {imm}", "store"),
        // MOV r8,imm8 (B0+r ib)。REX.B で拡張、REX ありは低8・なしの4-7は上位8.
        ("mov_r8_imm", "F1", "10110... ........", "mov r8, {imm}", "load"),
        // XCHG r32/r64, RAX (90-97)。90 は NOP と共有のため 91-97 のみ。REX.B で拡張、REX.W で64bit.
        ("xchg_rcx_ax", "F1", "10010001", "xchg rcx, rax", "alu"),
        ("xchg_rdx_ax", "F1", "10010010", "xchg rdx, rax", "alu"),
        ("xchg_rbx_ax", "F1", "10010011", "xchg rbx, rax", "alu"),
        ("xchg_rsp_ax", "F1", "10010100", "xchg rsp, rax", "alu"),
        ("xchg_rbp_ax", "F1", "10010101", "xchg rbp, rax", "alu"),
        ("xchg_rsi_ax", "F1", "10010110", "xchg rsi, rax", "alu"),
        ("xchg_rdi_ax", "F1", "10010111", "xchg rdi, rax", "alu"),
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
        ("cmp_al_imm", "F1", "00111100 ........", "cmp al, {imm}", "alu"),
        // OR AL,imm8 (0C ib)。
        ("or_al_imm", "F1", "00001100 ........", "or al, {imm}", "alu"),
        
        ("je", "F1", "01110100 ........", "je {imm}", "jump"),
        ("jne", "F1", "01110101 ........", "jne {imm}", "jump"),
        ("jo", "F1", "01110000 ........", "jo {imm}", "jump"),
        ("jno", "F1", "01110001 ........", "jno {imm}", "jump"),
        ("jb", "F1", "01110010 ........", "jb {imm}", "jump"),
        ("jae", "F1", "01110011 ........", "jae {imm}", "jump"),
        ("jbe", "F1", "01110110 ........", "jbe {imm}", "jump"),
        ("ja", "F1", "01110111 ........", "ja {imm}", "jump"),
        ("jl", "F1", "01111100 ........", "jl {imm}", "jump"),
        ("jge", "F1", "01111101 ........", "jge {imm}", "jump"),
        ("js", "F1", "01111000 ........", "js {imm}", "jump"),
        ("jns", "F1", "01111001 ........", "jns {imm}", "jump"),
        ("jp", "F1", "01111010 ........", "jp {imm}", "jump"),
        ("jnp", "F1", "01111011 ........", "jnp {imm}", "jump"),
        ("jle", "F1", "01111110 ........", "jle {imm}", "jump"),
        ("jg", "F1", "01111111 ........", "jg {imm}", "jump"),
        ("loop", "F1", "11100010 ........", "loop {imm}", "jump"),
        ("jmp_rel32", "F1", "11101001 ................................", "jmp {imm}", "jump"),
        ("xor_rm32", "F1", "00110001 11......", "xor r/m32, r32", "alu"),
        ("and_eax", "F1", "00100101 ................................", "and eax, {imm}", "alu"),
        ("or_eax", "F1", "00001101 ................................", "or eax, {imm}", "alu"),
        ("xor_imm", "F1", "00110101 ................................", "xor eax, {imm}", "alu"),
        ("int80", "F1", "11001101 10000000", "int 0x80", "system"),
        ("cmp_rm32", "F1", "00111001 11......", "cmp r/m32, r32", "alu"),
        ("and_rm32", "F1", "00100001 11......", "and r/m32, r32", "alu"),
        ("or_rm32", "F1", "00001001 11......", "or r/m32, r32", "alu"),
        ("sub_rm32", "F1", "00101001 11......", "sub r/m32, r32", "alu"),
        ("adc_rm32", "F1", "00010001 11......", "adc r/m32, r32", "alu"),
        ("sbb_rm32", "F1", "00011001 11......", "sbb r/m32, r32", "alu"),
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
        // MOVSXD r, m32 mod=00/01/10 (63 /r)。SIBなし。REX.W で64bit符号拡張.
        ("movsxd_memnd", "MR", "01100011 00......", "movsxd r, m32", "load"),
        ("movsxd_mem8", "M8", "01100011 01...... ........", "movsxd r, m32", "load"),
        ("movsxd_mem32", "M32", "01100011 10...... ................................", "movsxd r, m32", "load"),
        // MOVSXD r, m32 RIP (63 05 + disp32)。REX.W で64bit符号拡張.
        ("movsxd_rip", "F1", "01100011 00...101 ................................", "movsxd r, m32", "load"),
        ("movsb", "F1", "10100100", "movsb", "load"),
        ("movsd", "F1", "10100101", "movsd", "load"),
        ("stosb", "F1", "10101010", "stosb", "store"),
        ("stosd", "F1", "10101011", "stosd", "store"),
        ("endbr64", "F1", "00001111 00011110 11111010", "endbr64", "alu"),
        // RDSSPQ r64 (F3 REX.W 0F 1E /1)。CETシャドースタック未実装のためNOP扱い.
        // F3/REX.W は剥がし済みのため 0F 1E C8 の3Bで受ける。
        ("rdsspq", "F1", "00001111 00011110 11001000", "rdsspq", "system"),
        ("nopl", "F1", "00001111 00011111 00000000", "nopl", "alu"),
        // NOPL [base+disp8] (0F 1F mod=01)。何もしない.
        ("nopl_mem8", "F1", "00001111 00011111 01...... ........", "nopl [r/m+disp8]", "alu"),
        // NOPL [base+disp32] (0F 1F mod=10)。何もしない.
        ("nopl_mem32", "F1", "00001111 00011111 10...... ................................", "nopl [r/m+disp32]", "alu"),
        // XMM 最小セット（66 接頭辞は実行側で剥がす。REX.W は dispatch で見る）。
        // MOVD xmm,r32 (66 0F 6E /r)。reg-direct のみ。
        ("movd_xmm", "F1", "00001111 01101110 11......", "movd xmm, r32", "load"),
        ("movd_xmm_m32", "F1", "00001111 01101110 10000101 ................................", "movd xmm, m32", "load"),
        ("movd_xmm_rip", "F1", "00001111 01101110 00...101 ................................", "movd xmm, m32", "load"),
        // PUNPCKLBW xmm,xmm (66 0F 60 /r)。reg-direct のみ。
        ("punpcklbw", "F1", "00001111 01100000 11......", "punpcklbw xmm, xmm", "alu"),
        // PUNPCKLWD xmm,xmm (66 0F 61 /r)。reg-direct のみ。
        ("punpcklwd", "F1", "00001111 01100001 11......", "punpcklwd xmm, xmm", "alu"),
        // PSHUFD xmm,xmm,imm8 (66 0F 70 /r ib)。reg-direct のみ。
        ("pshufd", "F1", "00001111 01110000 11...... ........", "pshufd xmm, xmm", "alu"),
        // PSHUFLW (F2 0F 70 /r ib) はバイト列共有のため Insn::Pshufd を共用し dispatch で切替.
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
        // MOVZX r32,m16 mod=10 [base+disp32] (0F B7)。SIBなし、REX.W で64bit.
        ("movzx_r32_m16_mem32", "M32", "00001111 10110111 10...... ................................", "movzx r32, m16", "load"),
        // CMOVB r32/r64, r/m32/r/m64 (0F 42 /r)。reg-direct のみ。REX.W で切替.
        ("cmovb", "F1", "00001111 01000010 11......", "cmovb r, r/m", "alu"),
        ("cmovo", "F1", "00001111 01000000 11......", "cmovo r, r/m", "alu"),
        ("cmovno", "F1", "00001111 01000001 11......", "cmovno r, r/m", "alu"),
        // CMOVNE r32/r64, r/m32/r/m64 (0F 45 /r)。reg-direct のみ.
        ("cmovne", "F1", "00001111 01000101 11......", "cmovne r, r/m", "alu"),
        // CMOVE r32/r64, r/m32/r/m64 (0F 44 /r)。reg-direct のみ.
        ("cmove", "F1", "00001111 01000100 11......", "cmove r, r/m", "alu"),
        // CMOVNS r32/r64, r/m32/r/m64 (0F 49 /r)。reg-direct のみ.
        ("cmovns", "F1", "00001111 01001001 11......", "cmovns r, r/m", "alu"),
        ("cmovbe", "F1", "00001111 01000110 11......", "cmovbe r, r/m", "alu"),
        // CMOVBE r, [base+disp8] (0F 46 mod=01 rm!=4)。test 0x4d2874 対応.
        ("cmovbe_mem8", "F1", "00001111 01000110 01...... ........", "cmovbe r, m", "load"),
        // CMOVNE r, [base+disp8] (0F 45 mod=01 rm!=4)。ed 0x4b5cd8 の 0F 45 43 30。
        ("cmovne_mem8", "F1", "00001111 01000101 01...... ........", "cmovne r, m", "load"),
        ("cmova", "F1", "00001111 01000111 11......", "cmova r, r/m", "alu"),
        ("cmovae", "F1", "00001111 01000011 11......", "cmovae r, r/m", "alu"),
        ("cmovs", "F1", "00001111 01001000 11......", "cmovs r, r/m", "alu"),
        ("cmovp", "F1", "00001111 01001010 11......", "cmovp r, r/m", "alu"),
        ("cmovnp", "F1", "00001111 01001011 11......", "cmovnp r, r/m", "alu"),
        ("cmovl", "F1", "00001111 01001100 11......", "cmovl r, r/m", "alu"),
        ("cmovge", "F1", "00001111 01001101 11......", "cmovge r, r/m", "alu"),
        ("cmovle", "F1", "00001111 01001110 11......", "cmovle r, r/m", "alu"),
        ("cmovg", "F1", "00001111 01001111 11......", "cmovg r, r/m", "alu"),
        // SETcc r/m8 reg-direct (0F 90-9F /r mod=11)。REXありは低8、なしの4-7は上位8.
        ("seto", "F1", "00001111 10010000 11......", "seto r/m8", "alu"),
        ("setno", "F1", "00001111 10010001 11......", "setno r/m8", "alu"),
        ("setb", "F1", "00001111 10010010 11......", "setb r/m8", "alu"),
        ("setae", "F1", "00001111 10010011 11......", "setae r/m8", "alu"),
        ("sete", "F1", "00001111 10010100 11......", "sete r/m8", "alu"),
        ("setne", "F1", "00001111 10010101 11......", "setne r/m8", "alu"),
        ("setbe", "F1", "00001111 10010110 11......", "setbe r/m8", "alu"),
        ("seta", "F1", "00001111 10010111 11......", "seta r/m8", "alu"),
        ("sets", "F1", "00001111 10011000 11......", "sets r/m8", "alu"),
        ("setns", "F1", "00001111 10011001 11......", "setns r/m8", "alu"),
        ("setp", "F1", "00001111 10011010 11......", "setp r/m8", "alu"),
        ("setnp", "F1", "00001111 10011011 11......", "setnp r/m8", "alu"),
        ("setl", "F1", "00001111 10011100 11......", "setl r/m8", "alu"),
        ("setge", "F1", "00001111 10011101 11......", "setge r/m8", "alu"),
        ("setle", "F1", "00001111 10011110 11......", "setle r/m8", "alu"),
        ("setg", "F1", "00001111 10011111 11......", "setg r/m8", "alu"),
        // SETNE m8 SIB+disp8 (0F 95 SIB mod=01)。ls -l 0x42a294 対応。REX.X/B は dispatch で見る.
        ("setne_m8_sibd", "F1", "00001111 10010101 01...100 ........ ........", "setne m8", "alu"),
        // SETE m8 SIB+disp8 (0F 94 SIB mod=01)。df 0x5a797e 対応。index有無は問わずdispatchで切替.
        (
            "sete_m8_sibd",
            "F1",
            "00001111 10010100 01...100 ........ ........",
            "sete m8",
            "alu",
        ),
        ("cmove_m64", "M32", "00001111 01000100 10...... ................................", "cmove r64, m64", "load"),
        // CMOVNE r64,m64 mod=10 [base+disp32] (0F 45)。grep 0x442f5f 対応.
        ("cmovne_m64", "M32", "00001111 01000101 10...... ................................", "cmovne r64, m64", "load"),
        ("cmovne_r64_sibd", "F1", "00001111 01000101 01...100 ..100... ........", "cmovne r, m64", "load"),
        ("cmovge_r32_sibd", "F1", "00001111 01001101 01...100 ..100... ........", "cmovge r, m32", "load"),
        // CMOVL r32, [SIB] mod=00 no_index。cut 0x492257 の 44 0F 4C 14 24。変位なし。base=5 は長さが違う.
        ("cmovl_r32_sib", "F1", "00001111 01001100 00...100 ..100...", "cmovl r, m32", "load"),
        // CMOVS r32, [SIB] mod=00 no_index。sed 0x4c9eb0 の 0F 48 0C 24。base=5 は長さが違う.
        ("cmovs_r32_sib", "F1", "00001111 01001000 00...100 ..100...", "cmovs r, m32", "load"),
        ("cmove_r64_sibd", "F1", "00001111 01000100 01...100 ..100... ........", "cmove r, m64", "load"),
        // SUB r32/r64, m32/m64 SIB+disp8 (2B mod=01)。index有無は問わずdispatchで切替.
        ("sub_r_sibd", "F1", "00101011 01...100 ........ ........", "sub r, m", "alu"),
        // ADD r32/r64, m32/m64 SIB+disp8 (03 mod=01)。index有無は問わずdispatchで切替.
        // sha1sum 0x5cab68 対応。REX.W で64bit.
        ("add_r_sibd", "F1", "00000011 01...100 ........ ........", "add r, m", "alu"),
        // OR r32/r64, m32/m64 SIB+disp8 (0B mod=01)。sed 0x4c9424 対応。REX.W で64bit.
        ("or_r_sibd", "F1", "00001011 01...100 ........ ........", "or r, m", "alu"),
        // ADD m32,r32 SIB+disp32 (01 mod=10)。basename 0x48995c 対応.
        ("add_m32_r32_sibd32", "D32", "00000001 10...100 ........ ................................", "add m, r", "alu"),
        // SUB m32/m64,r32/r64 SIB+disp8 (29 mod=01)。wc 0x49e1db 対応。REX.W で64bit.
        ("sub_m_r_sibd", "F1", "00101001 01...100 ........ ........", "sub m, r", "alu"),
        // ADD m32,r32 SIB+disp8 (01 mod=01)。
        ("add_m32_r32_sibd", "F1", "00000001 01...100 ........ ........", "add m, r", "alu"),
        // CMP m32,r32 SIB+disp8 (39 mod=01)。
        ("cmp_m32_r32_sibd", "F1", "00111001 01...100 ........ ........", "cmp m, r", "alu"),
        // ADD m16,imm8 SIB mod=00 [base+index*scale] (66 83 /0)。66 接頭辞は実行側で剥がす.
        ("add_m16_imm_sib", "F1", "10000011 00000100 ........ ........", "add m16, {imm}", "alu"),
        // CMP m32,imm8 SIB mod=01 [base+index*scale+disp8] (83 /7)。seq 10 の停止点 0x45bbd8 対応.
        // index 固定を外し dispatch で no_index/索引を切替 (AND/OR/ADD sibd と同型)。
        ("cmp_rm_imm8_sibd", "F1", "10000011 01111100 ........ ........ ........", "cmp r/m, {imm}", "alu"),
        // CMP m32/m64,imm8 SIB+disp32 (83 /7 mod=10)。true 0x4bed16 対応.
        (
            "cmp_rm_imm8_sibd32",
            "F1",
            "10000011 10111100 ........ ................................ ........",
            "cmp r/m, {imm}",
            "alu",
        ),
        // CMP m32,imm8 SIB mod=00 (83 /7、no_index non-abs)。index=100 固定.
        ("cmp_rm_imm8_sib", "F1", "10000011 00111100 ........ ........", "cmp r/m, {imm}", "alu"),
        // CMP m,imm8 [index*scale+disp32] (83 /7 SIB mod=00 base=直接番地)。id 0x4c0a78 対応.
        (
            "cmp_rm_imm8_sibabs",
            "F1",
            "10000011 00111100 .....101 ................................ ........",
            "cmp r/m, {imm}",
            "alu",
        ),
        // CMP r32/r64, m32/m64 SIB mod=00 [base+index*scale] (3B /r)。
        ("cmp_r_sib", "F1", "00111011 00...100 ........", "cmp r, m", "alu"),
        // XADD r32, m32 [base] (0F C1 mod=00)。LOCK 接頭辞は実行側で無視する.
        ("xadd_r32_memnd", "MR", "00001111 11000001 00......", "xadd r32, m32", "alu"),
        // INC m32 [base] (FF /0 mod=00)。CF 以外の 5 旗を更新する.
        ("inc_rm_memnd", "MR", "11111111 00000...", "inc r/m", "alu"),
        // INC m32 [base+index*scale] (FF /0 SIB mod=00)。sed 0x4ca2c7 対応。base=5 は長さが違う.
        ("inc_rm_sib", "F1", "11111111 00000100 ........", "inc r/m", "alu"),
        // INC m32 [base+index*scale+disp8] (FF /0 SIB mod=01)。
        ("inc_rm_sibd", "S8", "11111111 01000100 ........ ........", "inc r/m", "alu"),
        // INC m32 [base+index*scale+disp32] (FF /0 SIB mod=10)。basename 0x4899d0 対応.
        ("inc_rm_sibd32", "D32", "11111111 10000100 ........ ................................", "inc r/m", "alu"),
        // DEC m32 [base+index*scale] (FF /1 SIB mod=00)。xxd 0x4b2bee 対応。base=5 は長さが違う.
        ("dec_rm_sib", "F1", "11111111 00001100 ........", "dec r/m", "alu"),
        // DEC m32 [base+index*scale+disp8] (FF /1 SIB mod=01)。
        ("dec_rm_sibd", "S8", "11111111 01001100 ........ ........", "dec r/m", "alu"),
        // INC m32 [base+disp8] (FF /0 mod=01、SIBなし)。
        ("inc_rm_mem8", "M8", "11111111 01000... ........", "inc r/m", "alu"),
        // INC m32 [RIP+disp32] (FF /0 mod=00 rm=101)。sed 0x5bdcc0 対応.
        ("inc_rm_rip", "F1", "11111111 00000101 ................................", "inc r/m", "alu"),
        // DEC m32 [base+disp8] (FF /1 mod=01、SIBなし)。
        ("dec_rm_mem8", "M8", "11111111 01001... ........", "dec r/m", "alu"),
        // DEC m32 [RIP+disp32] (FF /1 mod=00 rm=101)。du -s 0x5a7fe7 対応.
        ("dec_rm_rip", "F1", "11111111 00001101 ................................", "dec r/m", "alu"),
        // OR r8,m8 SIB mod=01 [base+index*scale+disp8] (0A /r)。dst は reg.
        ("or_r8_m8_sibd", "S8", "00001010 01...100 ........ ........", "or r8, m8", "load"),
        // OR r8,r/m8 reg-direct (0A /r mod=11)。
        ("or_r8_r8", "F1", "00001010 11......", "or r8, r/m8", "alu"),
        // SHR r/m8,imm8 (C0 /5 mod=11)。REX なしの 4-7 は上位8ビット.
        ("shr_rm8_imm8", "F1", "11000000 11101... ........", "shr r/m8, {imm}", "alu"),
        // SHR r/m8,1 (D0 /5 mod=11)。sed 0x5bdd7d (41 D0 ED) 対応.
        ("shr_rm8_1", "F1", "11010000 11101...", "shr r/m8, 1", "alu"),
        // XADD r32, m32 [RIP+disp32] (0F C1 mod=00 rm=101)。LOCK は無視.
        ("xadd_r32_rip", "F1", "00001111 11000001 00...101 ................................", "xadd r32, m32", "alu"),
        // SHLD r/m32,r32,CL (0F A5 /r mod=11)。REX.W で64ビット.
        ("shld_r32_cl", "F1", "00001111 10100101 11......", "shld r/m, r, cl", "alu"),
        // SHRD r/m32,r32,CL (0F AD /r mod=11)。seq 10 の停止点 0x4c4425 対応。REX.W で64ビット.
        ("shrd_r32_cl", "F1", "00001111 10101101 11......", "shrd r/m, r, cl", "alu"),
        // CMOVE r64/r32, m64/m32 [RIP+disp32] (0F 44 05/0D... + disp32)。REX.W で64bit.
        ("cmove_rip", "F1", "00001111 01000100 00...101 ................................", "cmove r, m", "load"),
        // CMOVNE r64/r32, m64/m32 [RIP+disp32] (0F 45 05 + disp32)。ln 0x5a9e44 対応。REX.W で64bit.
        ("cmovne_rip", "F1", "00001111 01000101 00...101 ................................", "cmovne r, m", "load"),
        ("imul_r_imm", "F1", "01101001 11...... ................................", "imul r, r/m, {imm}", "alu"),
        // IMUL r, [SIB+disp8], imm32 (69 /r)。mktemp 0x4d85cf の 48 69 44 24 08 01 00 01 00。
        ("imul_r_imm_sibd", "F1", "01101001 01...100 ..100... ........ ................................", "imul r, m, {imm}", "alu"),
        // IMUL r, [base+disp8], imm32 (69 /r mod=01 rm!=4)。ifplugd 0x4264b0 の 69 43 04。
        ("imul_r_imm_mem8", "F1", "01101001 01...... ........ ................................", "imul r, m, {imm}", "alu"),
        // IMUL r32/r64, r/m32/r/m64, imm8 reg-direct (6B /r ib mod=11)。REX.W で64bit.
        ("imul_r_imm8", "F1", "01101011 11...... ........", "imul r, r/m, {imm}", "alu"),
        // IMUL r64,r/m64,imm8 RIP (6B /r ib + disp32 + imm8)。REX.W で64bit.
        ("imul_r_imm8_rip", "F1", "01101011 00...101 ................................ ........", "imul r, r/m, {imm}", "alu"),
        // OR m32,imm32 RIP (81 0D + disp32 + imm32)。64ビット RIP相対.
        ("or_rm32_rip", "F1", "10000001 00001101 ................................ ................................", "or r/m32, {imm}", "alu"),
        // AND m32,imm32 RIP (81 25 + disp32 + imm32)。64ビット RIP相対.
        ("and_rm32_rip", "F1", "10000001 00100101 ................................ ................................", "and r/m32, {imm}", "alu"),
        // OR r32,m32 RIP (0B 15 + disp32)。
        ("or_r_rip", "F1", "00001011 00...101 ................................", "or r32, m32", "alu"),
        // IMUL r32,m32 RIP (0F AF 05 + disp32)。
        ("imul_r_rip", "F1", "00001111 10101111 00...101 ................................", "imul r, m32", "load"),
        // XOR r32,m32 RIP (33 1D/05 + disp32)。
        ("xor_r_rip", "F1", "00110011 00...101 ................................", "xor r32, m32", "alu"),
        // AND r32,m32 RIP (23 05 + disp32)。
        ("and_r_rip", "F1", "00100011 00...101 ................................", "and r32, m32", "alu"),
        // ADC r32,m32 RIP (13 05 + disp32)。
        ("adc_r_rip", "F1", "00010011 00...101 ................................", "adc r32, m32", "alu"),
        // SBB r32,m32 RIP (1B 05 + disp32)。
        ("sbb_r_rip", "F1", "00011011 00...101 ................................", "sbb r32, m32", "alu"),
        // SUB r32,m32 RIP (2B 1D/05 + disp32)。2B 05 は mod=00 rm=101.
        ("sub_r_rip", "F1", "00101011 00...101 ................................", "sub r32, m32", "alu"),
        // CALL r/m64 mod=01 [base+disp8] (FF /2)。64ビット間接コール.
        ("call_r_mem8", "M8", "11111111 01010... ........", "call r/m64", "jump"),
        // CALL r/m64 mod=00 [base] (FF /2)。SIBなし.
        ("call_r_memnd", "MR", "11111111 00010...", "call r/m64", "jump"),
        // CALL r/m64 reg-direct (FF /2 mod=11)。レジスタ間接コール.
        ("call_r_rm", "F1", "11111111 11010...", "call r/m64", "jump"),
        // CALL [base+index*scale] (FF /2 SIB mod=00)。64ビット間接コール.
        ("call_r_sib", "N8", "11111111 00010100 ........", "call r/m64", "jump"),
        // JMP [base+index*scale] (FF /4 SIB mod=00)。64ビット間接ジャンプ.
        ("jmp_r_sib", "N8", "11111111 00100100 ........", "jmp r/m64", "jump"),
        // CALL [base+index*scale+disp32] (FF /2 SIB mod=10)。64ビット間接コール.
        ("call_r_sibd32", "F1", "11111111 10010100 ........ ................................", "call r/m64", "jump"),
        // XCHG r32,r/m32 (87 /r)。reg-direct・mod=00/01/10/RIP (SIBなし).
        ("xchg_r_rm", "F1", "10000111 11......", "xchg r32, r/m32", "alu"),
        // XCHG r8, r/m8 (86 /r mod=11)。base64 0x4bd97a の 86 E9。
        ("xchg_r8", "F1", "10000110 11......", "xchg r8, r/m8", "alu"),
        ("xchg_r_memnd", "MR", "10000111 00......", "xchg r32, [r/m]", "alu"),
        ("xchg_r_mem8", "M8", "10000111 01...... ........", "xchg r32, m32", "alu"),
        ("xchg_r_mem32", "M32", "10000111 10...... ................................", "xchg r32, m32", "alu"),
        ("xchg_r_rip", "F1", "10000111 00...101 ................................", "xchg r32, m32", "alu"),
        // CALL [RIP+disp32] (FF /2 RIP)。
        ("call_r_rip", "F1", "11111111 00010101 ................................", "call r/m64", "jump"),
        // ADD m32,r32 mod=00 [base] (01 /r)。REX.W で64bit.
        ("add_m32_r32_memnd", "MR", "00000001 00......", "add m32, r32", "alu"),
        // AND m32,r32 mod=00 [base] (21 /r)。chat 0x4d3473 の andq %rax, (%rdi)。
        ("and_m32_r32_memnd", "MR", "00100001 00......", "and m32, r32", "alu"),
        // ADD m32,r32 mod=01 [base+disp8] (01 /r)。
        ("add_m32_r32_mem8", "M8", "00000001 01...... ........", "add m32, r32", "alu"),
        // ADD m32,r32 mod=10 [base+disp32] (01 /r)。
        ("add_m32_r32_mem32", "M32", "00000001 10...... ................................", "add m32, r32", "alu"),
        // OR m32,r32 mod=00 [base] (09 /r)。REX.W で64bit.
        ("or_m32_r32_memnd", "MR", "00001001 00......", "or m32, r32", "alu"),
        // OR m32,r32 mod=01 [base+disp8] (09 /r)。
        ("or_m32_r32_mem8", "M8", "00001001 01...... ........", "or m32, r32", "alu"),
        // OR m32,r32 mod=10 [base+disp32] (09 /r)。
        ("or_m32_r32_mem32", "M32", "00001001 10...... ................................", "or m32, r32", "alu"),
        // ADD m32,r32 RIP (01 05 + disp32)。
        ("add_m32_r32_rip", "F1", "00000001 00...101 ................................", "add m32, r32", "alu"),
        // BSR r32/r64, r/m32/r/m64 (0F BD /r)。reg-direct・mod=00/01/10/RIP (SIBなし).
        ("bsr_r_rm", "F1", "00001111 10111101 11......", "bsr r, r/m", "alu"),
        ("bsr_r_memnd", "MR", "00001111 10111101 00......", "bsr r, [r/m]", "load"),
        ("bsr_r_mem8", "M8", "00001111 10111101 01...... ........", "bsr r, m32", "load"),
        ("bsr_r_mem32", "M32", "00001111 10111101 10...... ................................", "bsr r, m32", "load"),
        ("bsr_r_rip", "F1", "00001111 10111101 00...101 ................................", "bsr r, m32", "load"),
        // BSF r32/r64, r/m32/r/m64 (0F BC /r)。reg-direct・mod=00/01/10/RIP (SIBなし).
        ("bsf_r_rm", "F1", "00001111 10111100 11......", "bsf r, r/m", "alu"),
        ("bsf_r_memnd", "MR", "00001111 10111100 00......", "bsf r, [r/m]", "load"),
        ("bsf_r_mem8", "M8", "00001111 10111100 01...... ........", "bsf r, m32", "load"),
        ("bsf_r_mem32", "M32", "00001111 10111100 10...... ................................", "bsf r, m32", "load"),
        ("bsf_r_rip", "F1", "00001111 10111100 00...101 ................................", "bsf r, m32", "load"),
        // CMPXCHG r32/r64, r/m32/r/m64 (0F B1 /r)。reg-direct・mod=00/01/10/RIP (SIBなし).
        ("cmpxchg_r_rm", "F1", "00001111 10110001 11......", "cmpxchg r, r/m", "alu"),
        ("cmpxchg_r_memnd", "MR", "00001111 10110001 00......", "cmpxchg [r/m], r", "alu"),
        ("cmpxchg_r_mem8", "M8", "00001111 10110001 01...... ........", "cmpxchg [r/m], r", "alu"),
        ("cmpxchg_r_mem32", "M32", "00001111 10110001 10...... ................................", "cmpxchg [r/m], r", "alu"),
        ("cmpxchg_r_rip", "F1", "00001111 10110001 00...101 ................................", "cmpxchg [rip], r", "alu"),
        // JMP r/m64 reg-direct (FF /4 mod=11)。
        ("jmp_r_rm", "F1", "11111111 11100...", "jmp r/m64", "jump"),
        // JMP [base] (FF /4 mod=00)。
        ("jmp_r_memnd", "MR", "11111111 00100...", "jmp r/m64", "jump"),
        // JMP [base+disp8] (FF /4 mod=01)。
        ("jmp_r_mem8", "M8", "11111111 01100... ........", "jmp r/m64", "jump"),
        // JMP [base+disp32] (FF /4 mod=10)。
        ("jmp_r_mem32", "M32", "11111111 00110... ................................", "jmp r/m64", "jump"),
        // JMP [RIP+disp32] (FF /4 RIP)。
        ("jmp_r_rip", "F1", "11111111 00100101 ................................", "jmp r/m64", "jump"),
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
        // OR m32,imm32 mod=00 [base] (81 /1)。REX.W で64bit.
        ("or_rm32_imm_memnd", "MR", "10000001 00001... ................................", "or r/m32, {imm}", "alu"),
        // OR m32,imm32 SIB mod=00 [base+index*scale] (81 /1)。awk 0x4a4354 対応。base=5 は長さが違う.
        ("or_rm32_imm_sib", "F1", "10000001 00001100 ........ ................................", "or r/m32, {imm}", "alu"),
        // ADD m32,imm32 SIB mod=01 [base+index*scale+disp8] (81 /0)。bzip2 0x480dcd 対応。
        (
            "add_rm32_imm_sibd",
            "F1",
            "10000001 01000100 ........ ........ ................................",
            "add r/m32, {imm}",
            "alu",
        ),
        // CMP m32,imm32 mod=00 [base] (81 /7)。REX.W で64bit.
        ("cmp_rm32_imm_memnd", "MR", "10000001 00111... ................................", "cmp r/m32, {imm}", "alu"),
        // OR m32,imm32 mod=01 [base+disp8] (81 /1)。SIB は fetch で弾く.
        ("or_rm32_imm_mem8", "M8", "10000001 01001... ........ ................................", "or r/m32, {imm}", "alu"),
        // AND m32/m64,imm32 mod=01 [base+disp8] (81 /4)。echo/id 0x4c08a2 対応.
        (
            "and_rm32_imm_mem8",
            "M8",
            "10000001 01100... ........ ................................",
            "and r/m32, {imm}",
            "alu",
        ),
        // CMP m32,imm32 mod=01 [base+disp8] (81 /7)。SIBなし.
        (
            "cmp_rm32_imm_mem8",
            "M8",
            "10000001 01111... ........ ................................",
            "cmp r/m32, {imm}",
            "alu"
        ),
        // CMP m32,imm32 mod=10 [base+disp32] (81 /7)。SIBなし.
        (
            "cmp_rm32_imm_mem32",
            "M32",
            "10000001 10111... ................................ ................................",
            "cmp r/m32, {imm}",
            "alu"
        ),
        ("adc_rm32_imm", "F1", "10000001 11010... ................................", "adc r/m32, {imm}", "alu"),
        ("sbb_rm32_imm", "F1", "10000001 11011... ................................", "sbb r/m32, {imm}", "alu"),
        ("and_rm32_imm", "F1", "10000001 11100... ................................", "and r/m32, {imm}", "alu"),
        ("xor_rm32_imm", "F1", "10000001 11110... ................................", "xor r/m32, {imm}", "alu"),
        // C7 /0 SIB+disp32+imm32 (11バイト)。REX.W で64切替は dispatch で.
        ("mov_rm_imm_sibd32", "F1", "11000111 10...100 ........ ................................ ................................", "mov r/m, {imm}", "alu"),
        // C7 /0 SIB 直接番地+disp32+imm32 (11バイト、mod=00)。idx=100・base=101 固定以外は fetch で弾く.
        // index は任意。base=101 が直接番地。echo/id 0x4bfc0e は RCX*8+disp32.
        ("mov_rm_imm_sibabs", "F1", "11000111 00000100 .....101 ................................ ................................", "mov r/m, {imm}", "alu"),
        // C7 /0 SIB mod=00 [base+index*scale]+imm32 (7バイト)。SIB 直接番地なし.
        ("mov_rm_imm_sib", "F1", "11000111 00...100 ........ ................................", "mov r/m, {imm}", "alu"),
        // C7 /0 SIB mod=01 [base+index*scale+disp8]+imm32 (8バイト).
        ("mov_rm_imm_sibd", "F1", "11000111 01...100 ........ ........ ................................", "mov r/m, {imm}", "alu"),
        // MOVUPS SIB+disp32 (8バイト)。
        ("movups_load_sibd32", "F1", "00001111 00010000 10...100 ........ ................................", "movups xmm, [r/m+sib+disp32]", "load"),
        ("movups_store_sibd32", "F1", "00001111 00010001 10...100 ........ ................................", "movups [r/m+sib+disp32], xmm", "store"),
        // MOVAPS SIB+disp32 (8バイト)。
        ("movaps_store_sibd32", "F1", "00001111 00101001 10...100 ........ ................................", "movaps [r/m+sib+disp32], xmm", "store"),
        // MOVZX r32,m16 RIP (0F B7 05 + disp32)。
        ("movzx_r32_m16_rip", "F1", "00001111 10110111 00...101 ................................", "movzx r32, m16", "load"),
        // MOVZX r32,m8 RIP (0F B6 05 + disp32)。F3/66 接頭辞なし.
        ("movzx_r32_m8_rip", "F1", "00001111 10110110 00...101 ................................", "movzx r32, m8", "load"),
        // MOVSX r32,m8 RIP (0F BE 05 + disp32)。
        ("movsx_r32_m8_rip", "F1", "00001111 10111110 00...101 ................................", "movsx r32, m8", "load"),
        // MOVSX r32/r64,r/m8 reg-direct (0F BE /r mod=11)。REX.R/B で 8-15 に拡張.
        ("movsx_r32_r8", "F1", "00001111 10111110 11......", "movsx r32, r/m8", "load"),
        // MOVZX r32,r/m8 reg-direct (0F B6 /r mod=11)。REX ありは低8、なしの4-7は上位8.
        ("movzx_r32_r8", "F1", "00001111 10110110 11......", "movzx r32, r/m8", "load"),
        // MOVZX r32,r16 reg-direct (0F B7 /r mod=11)。
        ("movzx_r32_r16", "F1", "00001111 10110111 11......", "movzx r32, r16", "load"),
        // BT r32,imm8 (0F BA /4 ib reg-direct)。
        ("bt_r32_imm", "F1", "00001111 10111010 11100... ........", "bt r32, {imm}", "alu"),
        // BT m32,imm8 mod=00 [base] (0F BA /4)。SIB/RIP は取得長で分離するため固定不要.
        ("bt_m32_imm", "F1", "00001111 10111010 00100... ........", "bt m32, {imm}", "alu"),
        // BT m32,imm8 SIB mod=01 [base+disp8] (0F BA /4 + ModRM + SIB + disp8 + imm8)。
        ("bt_m32_imm_sibd", "F1", "00001111 10111010 01100100 ........ ........ ........", "bt m32, {imm}", "alu"),
        // BTS r32/r64,imm8 (0F BA /5 ib reg-direct)。REX.W で64ビット.
        ("bts_r32_imm", "F1", "00001111 10111010 11101... ........", "bts r32, {imm}", "alu"),
        // BT r/m32,r32 (0F A3 /r mod=11)。REX.R/B で 8-15 に拡張.
        ("bt_r32_rm", "F1", "00001111 10100011 11......", "bt r/m32, r32", "alu"),
        // BTS r/m32,r32 (0F AB /r mod=11)。REX.W で64ビット.
        ("bts_r32_rm", "F1", "00001111 10101011 11......", "bts r/m32, r32", "alu"),
        // PXOR xmm,xmm (66 0F EF /r)。
        ("pxor", "F1", "00001111 11101111 11......", "pxor xmm, xmm", "alu"),
        // XORPS xmm,xmm (0F 57 /r)。PXOR と等価のため意味論を共有する.
        ("xorps", "F1", "00001111 01010111 11......", "xorps xmm, xmm", "alu"),
        ("punpckldq", "F1", "00001111 01100010 11......", "punpckldq xmm, xmm", "alu"),
        // PUNPCKLQDQ xmm,xmm (66 0F 6C /r)。reg-direct のみ。
        ("punpcklqdq", "F1", "00001111 01101100 11......", "punpcklqdq xmm, xmm", "alu"),
        // PAND xmm,xmm (66 0F DB /r)。reg-direct のみ。
        ("pand", "F1", "00001111 11011011 11......", "pand xmm, xmm", "alu"),
        // ANDPD xmm,xmm (66 0F 54 /r mod=11)。PAND と等価のため意味論を共有する.
        ("andpd", "F1", "00001111 01010100 11......", "andpd xmm, xmm", "alu"),
        // ANDPD xmm,[RIP+disp32] (66 0F 54 /r mod=00 rm=101)。
        ("andpd_rip", "F1", "00001111 01010100 00...101 ................................", "andpd xmm, m128", "load"),
        // PSLLDQ xmm,imm8 (66 0F 73 /7 ib)。reg-direct のみ、66必須.
        ("pslldq", "F1", "00001111 01110011 11111... ........", "pslldq xmm, {imm}", "alu"),
        // PSRLDQ xmm,imm8 (66 0F 73 /3 ib)。reg-direct のみ、66必須.
        ("psrldq", "F1", "00001111 01110011 11011... ........", "psrldq xmm, {imm}", "alu"),
        // PSUBB xmm,xmm (66 0F F8 /r)。reg-direct のみ.
        ("psubb", "F1", "00001111 11111000 11......", "psubb xmm, xmm", "alu"),
        // PADDB xmm,xmm (66 0F FC /r)。reg-direct のみ、REX.R/B で 8-15 に拡張する.
        ("paddb", "F1", "00001111 11111100 11......", "paddb xmm, xmm", "alu"),
        // PCMPGTB xmm,xmm (66 0F 64 /r)。reg-direct のみ、REX.R/B で 8-15 に拡張する.
        ("pcmpgtb", "F1", "00001111 01100100 11......", "pcmpgtb xmm, xmm", "alu"),
        // PANDN xmm,xmm (66 0F DF /r)。reg-direct のみ、REX.R/B で 8-15 に拡張する.
        ("pandn", "F1", "00001111 11011111 11......", "pandn xmm, xmm", "alu"),
        // CVTSI2SD xmm,r64 (F2 REX.W 0F 2A /r reg-direct)。F2 接頭辞は実行側で剥がす.
        ("cvtsi2sd_r64", "F1", "00001111 00101010 11......", "cvtsi2sd xmm, r64", "load"),
        // ADDSD xmm,xmm (F2 0F 58 /r reg-direct)。F2 接頭辞は実行側で剥がす.
        ("addsd", "F1", "00001111 01011000 11......", "addsd xmm, xmm", "alu"),
        // ADDSD xmm,m64 SIB mod=00 [base+index*scale] (F2 0F 58)。F2 は剥がし済み.
        ("addsd_m64_sib", "F1", "00001111 01011000 00...100 ........", "addsd xmm, m64", "load"),
        ("addsd_xmm_m64_sibd", "F1", "00001111 01011000 01...100 ........ ........", "addsd xmm, m64", "load"),
        // ADDSD xmm,m64 RIP (F2 0F 58 05 + disp32)。F2 接頭辞は実行側で剥がす.
        ("addsd_xmm_m64_rip", "F1", "00001111 01011000 00...101 ................................", "addsd xmm, m64", "load"),
        // SUBSD xmm,xmm (F2 0F 5C /r reg-direct)。F2 接頭辞は実行側で剥がす.
        ("subsd", "F1", "00001111 01011100 11......", "subsd xmm, xmm", "alu"),
        // MULSD xmm,m64 RIP (F2 0F 59 05 + disp32)。F2 接頭辞は実行側で剥がす.
        ("mulsd_xmm_m64_rip", "F1", "00001111 01011001 00...101 ................................", "mulsd xmm, m64", "load"),
        // DIVSD xmm,m64 RIP (F2 0F 5E 05 + disp32)。F2 接頭辞は実行側で剥がす。dd 0x4928e8 対応.
        ("divsd_xmm_m64_rip", "F1", "00001111 01011110 00...101 ................................", "divsd xmm, m64", "load"),
        // DIVSD xmm,xmm (F2 0F 5E /r reg-direct)。F2 接頭辞は実行側で剥がす。dd 0x492911 対応.
        ("divsd", "F1", "00001111 01011110 11......", "divsd xmm, xmm", "alu"),
        ("mulsd_xmm_m64_sibd", "F1", "00001111 01011001 01...100 ........ ........", "mulsd xmm, m64", "load"),
        // MULSD xmm,xmm (F2 0F 59 /r reg-direct)。F2 は剥がし済み.
        ("mulsd", "F1", "00001111 01011001 11......", "mulsd xmm, xmm", "alu"),
        // COMISD xmm,xmm (66 0F 2F /r reg-direct)。
        ("comisd", "F1", "00001111 00101111 11......", "comisd xmm, xmm", "alu"),
        // UCOMISD xmm,xmm (66 0F 2E /r mod=11)。順序なしの旗は COMISD と等価のため意味論を共有する.
        ("ucomisd", "F1", "00001111 00101110 11......", "ucomisd xmm, xmm", "alu"),
        // UCOMISD xmm,m64 mod=00/01/10/RIP (66 0F 2E)。COMISD と等価のため意味論を共有する.
        ("ucomisd_memnd", "MR", "00001111 00101110 00......", "ucomisd xmm, m64", "load"),
        ("ucomisd_mem8", "M8", "00001111 00101110 01...... ........", "ucomisd xmm, m64", "load"),
        ("ucomisd_mem32", "M32", "00001111 00101110 10...... ................................", "ucomisd xmm, m64", "load"),
        ("ucomisd_rip", "F1", "00001111 00101110 00...101 ................................", "ucomisd xmm, m64", "load"),
        // CVTTSD2SI r64,xmm (F2 REX.W 0F 2C /r reg-direct)。F2 接頭辞は実行側で剥がす.
        ("cvttsd2si_r64", "F1", "00001111 00101100 11......", "cvttsd2si r64, xmm", "load"),
        // PMINUB xmm,xmm (66 0F DA /r)。reg-direct のみ.
        ("pminub", "F1", "00001111 11011010 11......", "pminub xmm, xmm", "alu"),
        // PMAXUB xmm,xmm (66 0F DE /r)。df 0x4d0bcd 対応。reg-direct のみ.
        ("pmaxub", "F1", "00001111 11011110 11......", "pmaxub xmm, xmm", "alu"),
        // PCMPEQD xmm,xmm (66 0F 76 /r)。reg-direct のみ.
        ("pcmpeqd", "F1", "00001111 01110110 11......", "pcmpeqd xmm, xmm", "alu"),
        // PMOVMSKB r32,xmm (66 0F D7 /r)。reg-direct のみ、REX.W で64bit.
        ("pmovmskb", "F1", "00001111 11010111 11......", "pmovmskb r32, xmm", "load"),
        // PCMPEQB xmm,xmm (66 0F 74 /r)。reg-direct のみ.
        ("pcmpeqb", "F1", "00001111 01110100 11......", "pcmpeqb xmm, xmm", "alu"),
        // POR xmm,xmm (66 0F EB /r)。reg-direct のみ.
        ("por", "F1", "00001111 11101011 11......", "por xmm, xmm", "alu"),
        // CWDE/CDQE (0x98)。AX→EAX / EAX→RAX 符号拡張。REX.W で切替.
        ("cwde", "F1", "10011000", "cwde", "alu"),
        // CDQ/CQO (0x99)。EAX→EDX:EAX / RAX→RDX:RAX 符号拡張。od 0x5acde6 対応。REX.W で切替.
        ("cdq", "F1", "10011001", "cdq", "alu"),
        ("movq_m64_xmm_rip", "F1", "00001111 11010110 00...101 ................................", "movq m64, xmm", "store"),
        // MOVQ xmm,m64 RIP (F3 0F 7E 05 + disp32)。F3 接頭辞は実行側で剥がす。
        ("movq_xmm_m64_rip", "F1", "00001111 01111110 00...101 ................................", "movq xmm, m64", "load"),
        // MOVDQU xmm,xmm (F3 0F 6F reg-direct)。16B 非整列転送は MOVUPS と等価のため意味論を共有する。
        // MOVDQA xmm,xmm (66 0F 6F reg-direct) も等価のため MovdquLoadXmm を共用する.
        ("movdqu_load_xmm", "F1", "00001111 01101111 11......", "movdqu xmm, xmm", "load"),
        // MOVDQU m128,xmm (F3 0F 7F /r)。16B 非整列転送は MOVUPS と等価のため意味論を共有する.
        // MOVDQA m128,xmm (66 0F 7F /r) も等価のため共用する.
        ("movdqu_store_xmm", "F1", "00001111 01111111 11......", "movdqu m128, xmm", "store"),
        // MOVDQA xmm,m128 RIP (66 0F 6F 05 + disp32)。66必須、アライメントは問わない.
        ("movdqa_load_rip", "F1", "00001111 01101111 00...101 ................................", "movdqa xmm, m128", "load"),
        // MOVQ m64,xmm mod=00/01/10 (66 0F D6 /r)。SIBなし.
        ("movq_m64_xmm_memnd", "MR", "00001111 11010110 00......", "movq m64, xmm", "store"),
        ("movq_m64_xmm_mem8", "M8", "00001111 11010110 01...... ........", "movq m64, xmm", "store"),
        ("movq_m64_xmm_mem32", "M32", "00001111 11010110 10...... ................................", "movq m64, xmm", "store"),
        // MOVQ xmm,m64 mod=01 [base+disp8] (F3 0F 7E /r)。F3 接頭辞は実行側で剥がす。SIBなし.
        ("movq_xmm_m64_mem8", "M8", "00001111 01111110 01...... ........", "movq xmm, m64", "load"),
        // MOVHPS xmm,m64 mod=01 [base+disp8] (0F 16 /r)。SIBなし.
        ("movhps_xmm_m64_mem8", "M8", "00001111 00010110 01...... ........", "movhps xmm, m64", "load"),
        // MOVLPD xmm,m64 mod=00 [base] (66 0F 12 /r)。SIBなし.
        ("movlpd_xmm_m64_memnd", "MR", "00001111 00010010 00......", "movlpd xmm, m64", "load"),
        // MOVAPS xmm,m128 mod=00/01/10/RIP (0F 28 /r)。SIBなし、MOVUPS と等価.
        ("movaps_load_memnd", "MR", "00001111 00101000 00......", "movaps xmm, m128", "load"),
        ("movaps_load_mem8", "M8", "00001111 00101000 01...... ........", "movaps xmm, m128", "load"),
        ("movaps_load_mem32", "M32", "00001111 00101000 10...... ................................", "movaps xmm, m128", "load"),
        ("movaps_load_rip", "F1", "00001111 00101000 00...101 ................................", "movaps xmm, m128", "load"),
        // MOVAPS xmm,xmm reg-direct (0F 28 /r mod=11)。MOVUPS と等価.
        ("movaps_load_xmm", "F1", "00001111 00101000 11......", "movaps xmm, xmm", "load"),
        // MOVAPS [RIP+disp32],xmm (0F 29 05 + disp32)。
        ("movaps_store_rip", "F1", "00001111 00101001 00...101 ................................", "movaps [rip], xmm", "store"),
        ("shr_rm32_imm8", "F1", "11000001 11101... ........", "shr r/m32, {imm}", "alu"),
        ("sar_rm32_imm8", "F1", "11000001 11111... ........", "sar r/m32, {imm}", "alu"),
        ("shr_rm32_1", "F1", "11010001 11101...", "shr r/m32, 1", "alu"),
        ("shl_rm32_1", "F1", "11010001 11100...", "shl r/m32, 1", "alu"),
        ("sar_rm32_1", "F1", "11010001 11111...", "sar r/m32, 1", "alu"),
        ("rol_rm32_1", "F1", "11010001 11000...", "rol r/m32, 1", "alu"),
        // ROR r/m,1 (D1 /1 mod=11)。sha512sum 0x4b47c4 の 48 D1 C9。
        ("ror_rm32_1", "F1", "11010001 11001...", "ror r/m32, 1", "alu"),
        // IMUL r32/r64, r/m32/r/m64 (0F AF /r)。reg-direct・mod=00/01/10/RIP (SIBなし).
        ("imul_r_rm", "F1", "00001111 10101111 11......", "imul r, r/m", "alu"),
        ("imul_r_memnd", "MR", "00001111 10101111 00......", "imul r, [r/m]", "load"),
        ("imul_r_mem8", "M8", "00001111 10101111 01...... ........", "imul r, m32", "load"),
        ("imul_r_mem32", "M32", "00001111 10101111 10...... ................................", "imul r, m32", "load"),
        // IMUL r32/r64, m32/m64 SIB+disp8 (0F AF mod=01)。index有無は問わずdispatchで切替.
        // hexdump 0x5c8ca2 (41 0F AF 6C 24 14) 対応。REX.W で64bit.
        (
            "imul_r_sibd",
            "F1",
            "00001111 10101111 01...100 ........ ........",
            "imul r, m",
            "load",
        ),
        ("shl_rm32_imm8", "F1", "11000001 11100... ........", "shl r/m32, {imm}", "alu"),
        ("ror_rm32_imm8", "F1", "11000001 11001... ........", "ror r/m32, {imm}", "alu"),
        ("rol_rm32_imm8", "F1", "11000001 11000... ........", "rol r/m32, {imm}", "alu"),
        ("sar_rm32_cl", "F1", "11010011 11111...", "sar r/m32, cl", "alu"),
        ("shl_rm32_cl", "F1", "11010011 11100...", "shl r/m32, cl", "alu"),
        ("shr_rm32_cl", "F1", "11010011 11101...", "shr r/m32, cl", "alu"),
        // TEST r/m32,r32 (85 /r)。
        ("test_rm32", "F1", "10000101 11......", "test r/m32, r32", "alu"),
        ("test_rm32_imm", "F1", "11110111 11000... ................................", "test r/m32, {imm}", "alu"),
        // TEST m16,imm16 mod=00 [base] (66 F7 /0)。66 接頭辞は実行側で剥がす.
        ("test_m16_imm_memnd", "F1", "11110111 00000... ................", "test m16, {imm}", "alu"),
        // TEST m16,imm16 mod=01 [base+disp8] (66 F7 /0)。hexdump 0x5c8822 対応.
        // 66 41 F7 45 08 02 04 は TESTW $0x402,[R13+0x8]。66 剥がし済み.
        (
            "test_m16_imm_mem8",
            "F1",
            "11110111 01000... ........ ................",
            "test m16, {imm}",
            "alu",
        ),
        // TEST m16,imm16 RIP (66 F7 05 + disp32 + imm16)。66 接頭辞は実行側で剥がす.
        ("test_m16_imm_rip", "F1", "11110111 00000101 ................................ ................", "test m16, {imm}", "alu"),
        // TEST m32,imm32 RIP (F7 05 + disp32 + imm32)。ls 0x4963b6 対応.
        ("test_rm32_imm_rip", "F1", "11110111 00000101 ................................ ................................", "test m32, {imm}", "alu"),
        // TEST m32,imm32 mod=00 [base] (F7 /0)。tac 0x5b0ca8 対応.
        ("test_rm32_imm_memnd", "F1", "11110111 00000... ................................", "test m32, {imm}", "alu"),
        // TEST m32/m64,imm32 mod=01 [base+disp8] (F7 /0)。echo 0x4bfb84 対応.
        (
            "test_rm32_imm_mem8",
            "F1",
            "11110111 01000... ........ ................................",
            "test m32, {imm}",
            "alu",
        ),
        ("not_rm32", "F1", "11110111 11010...", "not r/m32", "alu"),
        ("neg_rm32", "F1", "11110111 11011...", "neg r/m32", "alu"),
        ("test_rm8_imm", "F1", "11110110 11000... ........", "test r/m8, {imm}", "alu"),
        ("and_rm8_imm", "F1", "10000000 11100... ........", "and r/m8, {imm}", "alu"),
        ("or_rm8_imm", "F1", "10000000 11001... ........", "or r/m8, {imm}", "alu"),
        ("cmp_rm8_imm", "F1", "10000000 11111... ........", "cmp r/m8, {imm}", "alu"),
        // CMPB [base],imm8 SIB mod=00 (80 /7)。index有無は問わずdispatchで切替.
        // grep 0x43e0e4 (indexed) 対応。80 3C 13 00 は CMPB $0x00,(%rbx,%rdx).
        ("cmp_rm8_imm_sib", "F1", "10000000 00111100 ........ ........", "cmp r/m8, {imm}", "alu"),
        // AND m32/m64,imm8 SIB mod=01 [base+disp8] (83 /4)。index有無は問わずdispatchで切替.
        ("and_rm_imm8_sibd", "F1", "10000011 01100100 ........ ........ ........", "and r/m, {imm}", "alu"),
        // SUB m32/m64,imm8 SIB mod=01 [base+disp8] (83 /5)。index有無は問わずdispatchで切替.
        // seq 0x4d0bfa の 83 6C 24 58 1C は subl $0x1c, 0x58(%rsp).
        ("sub_rm_imm8_sibd", "F1", "10000011 01101100 ........ ........ ........", "sub r/m, {imm}", "alu"),
        ("xor_rm_imm8_sibd", "F1", "10000011 01110100 ........ ........ ........", "xor r/m, {imm}", "alu"),
        // OR m32/m64,imm8 SIB mod=01 [base+disp8] (83 /1)。index有無は問わずdispatchで切替.
        ("or_rm_imm8_sibd", "F1", "10000011 01001100 ........ ........ ........", "or r/m, {imm}", "alu"),
        // OR m32/m64,imm8 SIB mod=00 [base+index*scale] (83 /1)。awk 0x4a1704 対応。base=5 は長さが違う.
        ("or_rm_imm8_sib", "F1", "10000011 00001100 ........ ........", "or r/m, {imm}", "alu"),
        // AND m32/m64,imm8 SIB mod=00 [base] (83 /4)。index有無は問わずdispatchで切替.
        ("and_rm_imm8_sib", "F1", "10000011 00100100 ........ ........", "and r/m, {imm}", "alu"),
        ("cmp_rm8_imm_sibd", "F1", "10000000 01111100 ........ ........ ........", "cmp r/m8, {imm}", "alu"),
        // CMPB m8,imm8 SIB mod=10 [base+index*scale+disp32] (80 /7)。stat 0x429875 対応.8B.
        ("cmp_rm8_imm_sibd32", "F1", "10000000 10111100 ........ ................................ ........", "cmp r/m8, {imm}", "alu"),
        ("test_m8_imm_rip", "F1", "11110110 00000101 ................................ ........", "test m8, {imm}", "alu"),
        // TEST m8,imm8 mod=00 [base] (F6 /0)。SIBなし.
        ("test_m8_imm_memnd", "MR", "11110110 00000... ........", "test m8, {imm}", "alu"),
        // TEST m8,imm8 mod=01 [base+disp8] (F6 /0)。
        ("test_m8_imm_mem8", "M8", "11110110 01000... ........ ........", "test m8, {imm}", "alu"),
        // TEST m8,imm8 mod=10 [base+disp32] (F6 /0)。
        ("test_m8_imm_mem32", "M32", "11110110 10000... ................................ ........", "test m8, {imm}", "alu"),
        // TEST m8,imm8 SIB mod=01 [base+index*scale+disp8] (F6 /0)。5B.
        ("test_m8_imm_sibd", "F1", "11110110 01000100 ........ ........ ........", "test m8, {imm}", "alu"),
        // TEST m8,imm8 SIB mod=00 [base+index*scale] (F6 /0)。ls -l 0x40e342 対応.4B.
        ("test_m8_imm_sib", "F1", "11110110 00000100 ........ ........", "test m8, {imm}", "alu"),
        // CMP r32, m32 RIP (3B 05 + disp32)。
        ("cmp_r_rip", "F1", "00111011 00...101 ................................", "cmp r32, m32", "alu"),
        // CMP r/m32, r32 RIP (39 05 + disp32)。dst=mem.
        ("cmp_rm_rip", "F1", "00111001 00...101 ................................", "cmp r/m32, r32", "alu"),
        ("or_rm_imm8_rip", "F1", "10000011 00001101 ................................ ........", "or r/m, {imm}", "alu"),
        // AND m32,imm8 RIP (83 25 + disp32 + imm8)。64ビット RIP相対.
        ("and_rm_imm8_rip", "F1", "10000011 00100101 ................................ ........", "and r/m, {imm}", "alu"),
        // SUB m32,imm8 RIP (83 2D + disp32 + imm8)。64ビット RIP相対.
        ("sub_rm_imm8_rip", "F1", "10000011 00101101 ................................ ........", "sub r/m, {imm}", "alu"),
        ("test_al_imm", "F1", "10101000 ........", "test al, {imm}", "alu"),
        ("test_eax_imm", "F1", "10101001 ................................", "test eax, {imm}", "alu"),
        // AND AX,imm16 (66 25 + imm16)。66 接頭辞は実行側で剥がす.
        ("and_ax_imm16", "F1", "00100101 ................", "and ax, {imm}", "alu"),
        // CMP AX,imm16 (66 3D + imm16)。66 接頭辞は実行側で剥がす.
        ("cmp_ax_imm16", "F1", "00111101 ................", "cmp ax, {imm}", "alu"),
        // OR AX,imm16 (66 0D + imm16)。66 接頭辞は実行側で剥がす。seq 0x4d74c9。
        ("or_ax_imm16", "F1", "00001101 ................", "or ax, {imm}", "alu"),
        // ADD r/m16,imm16 (66 81 /0 mod=11)。66 接頭辞は実行側で剥がす.
        ("add_rm16_imm", "F1", "10000001 11000... ................", "add r/m16, {imm}", "alu"),
        // AND r/m16,imm16 (66 81 /4 mod=11)。66 接頭辞は実行側で剥がす.
        ("and_rm16_imm", "F1", "10000001 11100... ................", "and r/m16, {imm}", "alu"),
        // CMP r/m16,imm16 (66 81 /7 mod=11)。66 接頭辞は実行側で剥がす。basename 0x4bfaa8 対応.
        ("cmp_rm16_imm", "F1", "10000001 11111... ................", "cmp r/m16, {imm}", "alu"),
        // ADD r32, m32 (03 /r)。RIP/abs のみ。REX.W で64ビット.
        ("add_r_rip", "F1", "00000011 00...101 ................................", "add r, [rip]", "alu"),
        // CMP [RIP+disp32],imm8 (83 3D + disp32 + imm8)。64ビット RIP相対.
        ("cmp_rm_imm8_rip", "F1", "10000011 00111101 ................................ ........", "cmp r/m, {imm}", "alu"),
        // CMPB [RIP+disp32],imm8 (80 3D + disp32 + imm8)。8ビット比較.
        ("cmp_rm8_imm_rip", "F1", "10000000 00111101 ................................ ........", "cmp r/m8, {imm}", "alu"),
        // MOVB [RIP+disp32],imm8 (C6 05 + disp32 + imm8)。8ビット書き込み.
        ("mov_rm8_imm_rip", "F1", "11000110 00000101 ................................ ........", "mov r/m8, {imm}", "store"),
        // ADD m32/m64,imm8 mod=01 [base+disp8] (83 /0)。REX.W で64bit.
        ("add_rm_imm8_mem8", "F1", "10000011 01000... ........ ........", "add r/m, {imm}", "alu"),
        // ADD m32/m64,imm8 mod=00 [base] (83 /0)。REX.W で64bit.
        ("add_rm_imm8_memnd", "F1", "10000011 00000... ........", "add r/m, {imm}", "alu"),
        // ADD m32/m64,imm8 mod=10 [base+disp32] (83 /0)。REX.W で64bit.
        ("add_rm_imm8_mem32", "F1", "10000011 10000... ................................ ........", "add r/m, {imm}", "alu"),
        // ADD m32/m64,imm8 SIB+disp8 (83 /0 SIB mod=01)。test 0x5b1d4e 対応.5B.
        ("add_rm_imm8_sibd", "F1", "10000011 01000100 ........ ........ ........", "add r/m, {imm}", "alu"),
        // OR m32/m64,imm8 mod=00 [base] (83 /1)。REX.W で64bit.
        ("or_rm_imm8_memnd", "F1", "10000011 00001... ........", "or r/m, {imm}", "alu"),
        // OR m32/m64,imm8 mod=01 [base+disp8] (83 /1)。
        ("or_rm_imm8_mem8", "F1", "10000011 01001... ........ ........", "or r/m, {imm}", "alu"),
        // OR m32/m64,imm8 mod=10 [base+disp32] (83 /1)。
        ("or_rm_imm8_mem32", "F1", "10000011 10001... ................................ ........", "or r/m, {imm}", "alu"),
        // ADD m32,imm8 RIP (83 05 + disp32 + imm8)。REX.W で64bit切替.
        ("add_rm32_imm8_rip", "F1", "10000011 00000101 ................................ ........", "add r/m, {imm}", "alu"),
        // SUB m32/m64,imm8 mod=01 [base+disp8] (83 /5)。REX.W で64bit.
        ("sub_rm_imm8_mem8", "F1", "10000011 01101... ........ ........", "sub r/m, {imm}", "alu"),
        // SUB m32/m64,imm8 mod=00 [base] (83 /5)。REX.W で64bit.
        ("sub_rm_imm8_memnd", "F1", "10000011 00101... ........", "sub r/m, {imm}", "alu"),
        // SUB m32/m64,imm8 mod=10 [base+disp32] (83 /5)。REX.W で64bit.
        ("sub_rm_imm8_mem32", "F1", "10000011 10101... ................................ ........", "sub r/m, {imm}", "alu"),
        // XOR m32/m64,imm8 mod=01 [base+disp8] (83 /6)。REX.W で64bit.
        ("xor_rm_imm8_mem8", "F1", "10000011 01110... ........ ........", "xor r/m, {imm}", "alu"),
        // XOR m32/m64,imm8 mod=00 [base] (83 /6)。REX.W で64bit.
        ("xor_rm_imm8_memnd", "F1", "10000011 00110... ........", "xor r/m, {imm}", "alu"),
        // XOR m32/m64,imm8 mod=10 [base+disp32] (83 /6)。REX.W で64bit.
        ("xor_rm_imm8_mem32", "F1", "10000011 10110... ................................ ........", "xor r/m, {imm}", "alu"),
        // AND m32/m64,imm8 mod=01 [base+disp8] (83 /4)。REX.W で64bit.
        ("and_rm_imm8_mem8", "F1", "10000011 01100... ........ ........", "and r/m, {imm}", "alu"),
        // AND m32/m64,imm8 mod=00 [base] (83 /4)。REX.W で64bit.
        ("and_rm_imm8_memnd", "F1", "10000011 00100... ........", "and r/m, {imm}", "alu"),
        // AND m32/m64,imm8 mod=10 [base+disp32] (83 /4)。REX.W で64bit.
        ("and_rm_imm8_mem32", "F1", "10000011 10100... ................................ ........", "and r/m, {imm}", "alu"),
        // CMP m32/m64,imm8 mod=10 [base+disp32] (83 /7)。REX.W で64bit.
        ("cmp_rm_imm8_mem32", "F1", "10000011 10111... ................................ ........", "cmp r/m, {imm}", "alu"),
        // MOVW [base],imm16 (66 C7 /0 mod=00)。xxd 0x4b240f 対応.4B+66.
        ("mov_rm16_imm_memnd", "F1", "11000111 00000... ................", "mov r/m16, {imm}", "alu"),
        // MOVW [base+disp8],imm16 (66 C7 /0 mod=01)。hexdump 0x5c84f9 対応.5B+66.
        // 66 C7 43 5C 01 01 は [RBX+0x5C]=0x0101。66 剥がし済み.
        (
            "mov_rm16_imm_mem8",
            "F1",
            "11000111 01000... ........ ................",
            "mov r/m16, {imm}",
            "alu",
        ),
        // MOVW [base+index*scale+disp8],imm16 (66 C7 /0 SIB mod=01)。stat 0x5af402 対応.6B+66.
        ("mov_rm16_imm_sibd", "F1", "11000111 01000100 ........ ........ ................", "mov r/m16, {imm}", "alu"),
        // MOVW [base+index*scale+disp32],imm16 (66 C7 /0 SIB mod=10)。gzip 0x485910 の 66 C7 84 03。
        ("mov_rm16_imm_sibd32", "F1", "11000111 10000100 ........ ................................ ................", "mov r/m16, {imm}", "alu"),
        // MOVW [base+index*scale],imm16 (66 C7 /0 SIB mod=00)。hexdump 0x5c82dd 対応.5B+66.
        // index有無は問わずdispatchで切替.
        (
            "mov_rm16_imm_sib",
            "F1",
            "11000111 00000100 ........ ................",
            "mov r/m16, {imm}",
            "alu",
        ),
        // MOVW [RIP+disp32],imm16 (66 C7 05 + disp32 + imm16)。od 0x5ac863 対応.9B+66.
        ("mov_rm16_imm_rip", "F1", "11000111 00000101 ................................ ................", "mov r/m16, {imm}", "alu"),
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
            "mov_rm16_imm_m32",
            "F1",
            "11000111 10000101 ................................ ................",
            vec![wc("i16_rm", WhereOp::Eq, 5)],
            "mov r/m16, {imm}",
            "alu",
        ),
        (
            "shl_m32_imm8_mem8",
            "S8",
            "11000001 01100... ........ ........",
            vec![wc("s8_rm", WhereOp::Ne, 4)],
            "shl r/m32, {imm}",
            "alu",
        ),
        (
            "mov_rm16_imm_disp32",
            "F1",
            "11000111 10000... ................................ ................",
            vec![wc("i16_rm", WhereOp::Ne, 4), wc("i16_rm", WhereOp::Ne, 5)],
            "mov r/m16, {imm}",
            "alu",
        ),
        (
            "shl_m8_1_mem32",
            "M32",
            "11010000 10100... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "shl r/m8, 1",
            "alu",
        ),
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
        // C7 /0 m32/m64,imm32 mod=10 (SIBなし)。REX.W で64bit。base 任意.
        (
            "mov_rm_imm_m32",
            "M32",
            "11000111 10000... ................................ ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "mov r/m, {imm}",
            "alu",
        ),
        // C7 /0 m32/m64,imm32 mod=01 [base+disp8] (SIBなし)。REX.W で64bit.
        (
            "mov_rm_imm_m8",
            "C8",
            "11000111 01000... ........ ................................",
            vec![wc("c8_rm", WhereOp::Ne, 4)],
            "mov r/m, {imm}",
            "alu",
        ),
        // C7 /0 m32/m64,imm32 mod=00 [base] (SIB/絶対番地なし)。REX.W で64bit.
        (
            "mov_rm_imm_memnd",
            "M32",
            "11000111 00000... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4), wc("m32_rm", WhereOp::Ne, 5)],
            "mov r/m, {imm}",
            "alu",
        ),
        (
            "cmp_rm_mem32",
            "M32",
            "00111001 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "cmp r/m32, r32",
            "alu",
        ),
        (
            "sete_m8_mem32",
            "M32",
            "00001111 10010100 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "sete m8",
            "alu",
        ),
        (
            "sete_m8_mem8",
            "M8",
            "00001111 10010100 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "sete m8",
            "alu",
        ),
        (
            "setle_m8_mem32",
            "M32",
            "00001111 10011110 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "setle m8",
            "alu",
        ),
        (
            "setne_m8_mem32",
            "M32",
            "00001111 10010101 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "setne m8",
            "alu",
        ),
        (
            "call_r_mem32",
            "M32",
            "11111111 10010... ................................",
            vec![],
            "call r/m64",
            "jump",
        ),
        (
            "cmp_rm_mem8",
            "M8",
            "00111001 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "cmp r/m32, r32",
            "alu",
        ),
        (
            "cmp_rm_memnd",
            "MR",
            "00111001 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "cmp r/m32, r32",
            "alu",
        ),
        (
            "cmp_r_memnd",
            "MR",
            "00111011 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "cmp r32, m32",
            "alu",
        ),
        (
            "cmp_r_mem8",
            "M8",
            "00111011 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "cmp r32, m32",
            "alu",
        ),
        (
            "cmp_r_mem32",
            "M32",
            "00111011 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "cmp r32, m32",
            "alu",
        ),
        (
            "cmp_r_sibd",
            "S8",
            "00111011 01...100 ........ ........",
            vec![],
            "cmp r32, [r/m+sib+disp8]",
            "alu",
        ),
        (
            "cmovae_m64",
            "M32",
            "00001111 01000011 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "cmovae r64, m64",
            "load",
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
            "add_r_mem8",
            "M8",
            "00000011 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "add r32, m32",
            "alu",
        ),
        (
            "div_rm32_mem8",
            "M8",
            "11110111 01110... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "div eax, r/m32",
            "div",
        ),
        (
            "div_rm32_sibd",
            "S8",
            "11110111 01110100 ........ ........",
            vec![],
            "div eax, r/m32",
            "div",
        ),
        (
            "div_rm32_sib",
            "N8",
            "11110111 00110100 ........",
            vec![wc("n8_base", WhereOp::Ne, 5)],
            "div eax, r/m32",
            "div",
        ),
        (
            "cvtsi2sd_m32_mem8",
            "M8",
            "00001111 00101010 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "cvtsi2sd xmm, m32",
            "load",
        ),
        (
            "add_r_mem32",
            "M32",
            "00000011 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "add r32, m32",
            "alu",
        ),
        (
            "xor_r_memnd",
            "MR",
            "00110011 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "xor r32, m32",
            "alu",
        ),
        (
            "xor_r_mem8",
            "M8",
            "00110011 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "xor r32, m32",
            "alu",
        ),
        (
            "xor_r_mem32",
            "M32",
            "00110011 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "xor r32, m32",
            "alu",
        ),
        (
            "xor_r_sib",
            "N8",
            "00110011 00...100 ........",
            vec![wc("n8_base", WhereOp::Ne, 5)],
            "xor r32, [r/m+sib]",
            "alu",
        ),
        (
            "sub_r_sib",
            "N8",
            "00101011 00...100 ........",
            vec![wc("n8_base", WhereOp::Ne, 5)],
            "sub r32, [r/m+sib]",
            "alu",
        ),
        (
            "xor_r_sibd",
            "S8",
            "00110011 01...100 ........ ........",
            vec![],
            "xor r32, [r/m+sib+disp8]",
            "alu",
        ),
        (
            "xor_r_sibd32",
            "D32",
            "00110011 10...100 ........ ................................",
            vec![],
            "xor r32, [r/m+sib+disp32]",
            "alu",
        ),
        // ADD r32,[base+index*scale] (03 /r mod=00 SIB)。md5sum 0x5ca46d 対応.
        (
            "add_r_sib",
            "N8",
            "00000011 00...100 ........",
            vec![wc("n8_base", WhereOp::Ne, 5)],
            "add r32, [r/m+sib]",
            "alu",
        ),
        // CMP m32,r32 SIB [base+index*scale] (39 /r mod=00)。paste 0x5ad26b 対応.
        (
            "cmp_m32_r32_sib",
            "N8",
            "00111001 00...100 ........",
            vec![wc("n8_base", WhereOp::Ne, 5)],
            "cmp m, r",
            "alu",
        ),
        (
            "cmp_r_sibd32",
            "D32",
            "00111011 10...100 ........ ................................",
            vec![],
            "cmp r32, [r/m+sib+disp32]",
            "alu",
        ),
        // ADD r32/r64, m32/m64 SIB+disp32 (03 /r mod=10)。id 0x4d31d6 対応.
        (
            "add_r_sibd32",
            "D32",
            "00000011 10...100 ........ ................................",
            vec![],
            "add r, m",
            "alu",
        ),
        // CMP m32/m64, r32/r64 SIB+disp32 (39 /r mod=10)。true 0x4bed0c 対応.
        (
            "cmp_m32_r32_sibd32",
            "D32",
            "00111001 10...100 ........ ................................",
            vec![],
            "cmp m, r",
            "alu",
        ),
        (
            "and_r_memnd",
            "MR",
            "00100011 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "and r32, m32",
            "alu",
        ),
        (
            "and_r_mem8",
            "M8",
            "00100011 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "and r32, m32",
            "alu",
        ),
        (
            "and_r_sibd",
            "S8",
            "00100011 01...100 ........ ........",
            vec![],
            "and r32, [r/m+sib+disp8]",
            "alu",
        ),
        (
            "and_r_mem32",
            "M32",
            "00100011 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "and r32, m32",
            "alu",
        ),
        // INC m32 mod=10 [base+disp32] (FF /0)。uname 0x4b3c4a 対応.
        (
            "inc_rm_mem32",
            "M32",
            "11111111 10000... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "inc r/m",
            "alu",
        ),
        // DEC m32 mod=10 [base+disp32] (FF /1)。gzip 0x484714 の decl 0x2af4(%rbx)。
        (
            "dec_rm_mem32",
            "M32",
            "11111111 10001... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "dec r/m",
            "alu",
        ),
        (
            "adc_r_memnd",
            "MR",
            "00010011 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "adc r32, m32",
            "alu",
        ),
        (
            "adc_r_mem8",
            "M8",
            "00010011 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "adc r32, m32",
            "alu",
        ),
        (
            "adc_r_mem32",
            "M32",
            "00010011 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "adc r32, m32",
            "alu",
        ),
        (
            "sbb_r_memnd",
            "MR",
            "00011011 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "sbb r32, m32",
            "alu",
        ),
        (
            "sbb_r_mem8",
            "M8",
            "00011011 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "sbb r32, m32",
            "alu",
        ),
        (
            "sbb_r_mem32",
            "M32",
            "00011011 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "sbb r32, m32",
            "alu",
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
            "add_r_memnd",
            "MR",
            "00000011 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "add r32, [r/m]",
            "alu",
        ),
        (
            "movzx_r32_m8_memnd",
            "MR",
            "00001111 10110110 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "movzx r32, m8",
            "load",
        ),
        (
            "movzx_r32_m16_memnd",
            "MR",
            "00001111 10110111 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "movzx r32, m16",
            "load",
        ),
        (
            "movsx_r32_m8_memnd",
            "MR",
            "00001111 10111110 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "movsx r, m8",
            "load",
        ),
        (
            "movzx_r32_m8_mem8",
            "M8",
            "00001111 10110110 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "movzx r32, m8",
            "load",
        ),
        (
            "movsx_r32_m8_mem8",
            "M8",
            "00001111 10111110 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "movsx r32, m8",
            "load",
        ),
        // MOVSX r32,m8 mod=10 [base+disp32] (0F BE)。echo 0x4c00d6 対応.
        (
            "movsx_r32_m8_mem32",
            "M32",
            "00001111 10111110 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "movsx r32, m8",
            "load",
        ),
        (
            "and_r8_m8_mem32",
            "M32",
            "00100010 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "and r8, m8",
            "alu",
        ),
        (
            "test_r_mem8",
            "M8",
            "10000101 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "test r, m",
            "alu",
        ),
        (
            "test_r_sibd",
            "S8",
            "10000101 01...100 ........ ........",
            vec![],
            "test r32, [r/m+sib+disp8]",
            "alu",
        ),
        (
            "test_r_sib",
            "N8",
            "10000101 00...100 ........",
            vec![wc("n8_base", WhereOp::Ne, 5)],
            "test r, [r/m+sib]",
            "alu",
        ),
        // TEST r,m SIB+disp32 (85 /r mod=10 rm=100)。grep 0x43d250 対応.7B(+REX).
        (
            "test_r_sibd32",
            "F1",
            "10000101 10...100 ........ ................................",
            vec![],
            "test r, [r/m+sib+disp32]",
            "alu",
        ),
        (
            "test_rm32_memnd",
            "MR",
            "10000101 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "test r/m32, r32",
            "alu",
        ),
        (
            "movzx_r32_m16_mem8",
            "M8",
            "00001111 10110111 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "movzx r32, m16",
            "load",
        ),
        (
            "movzx_r32_m8_mem32",
            "M32",
            "00001111 10110110 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "movzx r32, m8",
            "load",
        ),
        (
            "fnstcw_memnd",
            "MR",
            "11011001 00111...",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "fnstcw m16",
            "alu",
        ),
        (
            "fnstcw_mem8",
            "M8",
            "11011001 01111... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "fnstcw m16",
            "alu",
        ),
        (
            "fnstcw_sibd",
            "S8",
            "11011001 01111100 ........ ........",
            vec![],
            "fnstcw m16",
            "alu",
        ),
        (
            "fnstcw_mem32",
            "M32",
            "11011001 10111... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "fnstcw m16",
            "alu",
        ),
        (
            "fldcw_memnd",
            "MR",
            "11011001 00101...",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "fldcw m16",
            "alu",
        ),
        (
            "fldcw_mem8",
            "M8",
            "11011001 01101... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "fldcw m16",
            "alu",
        ),
        (
            "fldcw_sibd",
            "S8",
            "11011001 01101100 ........ ........",
            vec![],
            "fldcw m16",
            "alu",
        ),
        (
            "fldcw_mem32",
            "M32",
            "11011001 10101... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "fldcw m16",
            "alu",
        ),
        (
            "fld_m32_rip",
            "F1",
            "11011001 00000101 ................................",
            vec![],
            "fld m32",
            "alu",
        ),
        (
            "fmul_m32_rip",
            "F1",
            "11011000 00001101 ................................",
            vec![],
            "fmul m32",
            "alu",
        ),
        (
            "fld_m64_memnd",
            "MR",
            "11011101 00000...",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "fld m64",
            "alu",
        ),
        (
            "fstp_m80_memnd",
            "MR",
            "11011011 00111...",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "fstp m80",
            "alu",
        ),
        (
            "fstp_m80_sib",
            "N8",
            "11011011 00111100 ........",
            vec![wc("n8_base", WhereOp::Ne, 5)],
            "fstp m80",
            "alu",
        ),
        (
            "fstp_m80_sibd32",
            "D32",
            "11011011 10111100 ........ ................................",
            vec![],
            "fstp m80",
            "alu",
        ),
        (
            "fstp_m80_sibd",
            "S8",
            "11011011 01111100 ........ ........",
            vec![],
            "fstp m80",
            "alu",
        ),
        (
            "push_rm_sibd",
            "S8",
            "11111111 01110100 ........ ........",
            vec![],
            "push m",
            "store",
        ),
        (
            "fld_m80_sibd32",
            "D32",
            "11011011 10101100 ........ ................................",
            vec![],
            "fld m80",
            "alu",
        ),
        (
            "fld_m80_sibd",
            "S8",
            "11011011 01101100 ........ ........",
            vec![],
            "fld m80",
            "alu",
        ),
        (
            "fld_m80_sib",
            "N8",
            "11011011 00101100 ........",
            vec![wc("n8_base", WhereOp::Ne, 5)],
            "fld m80",
            "alu",
        ),
        // FLD m80 [RIP+disp32] (DB /5 mod=00 rm=5)。dd 0x4d0e58 対応。
        (
            "fld_m80_rip",
            "F1",
            "11011011 00101101 ................................",
            vec![],
            "fld m80",
            "alu",
        ),
        (
            "fld_st",
            "F1",
            "11011001 11000...",
            vec![],
            "fld st",
            "alu",
        ),
        (
            "fldz",
            "F1",
            "11011001 11101110",
            vec![],
            "fldz",
            "alu",
        ),
        (
            "fxch_st",
            "F1",
            "11011001 11001...",
            vec![],
            "fxch st",
            "alu",
        ),
        (
            "fucomi_st",
            "F1",
            "11011011 11101...",
            vec![],
            "fucomi st",
            "alu",
        ),
        // FUCOMIP ST(0), ST(i) (DF E8+i)。dd 0x4d0ea6 対応。
        (
            "fucomip_st",
            "F1",
            "11011111 11101...",
            vec![],
            "fucomip st",
            "alu",
        ),
        (
            "fstp_st",
            "F1",
            "11011101 11011...",
            vec![],
            "fstp st",
            "alu",
        ),
        (
            "fild_m32_sibd",
            "S8",
            "11011011 01000100 ........ ........",
            vec![],
            "fild m32",
            "alu",
        ),
        (
            "fild_m64_sib",
            "N8",
            "11011111 00101100 ........",
            vec![wc("n8_base", WhereOp::Ne, 5)],
            "fild m64",
            "alu",
        ),
        (
            "fistp_m64_sibd",
            "S8",
            "11011111 01111100 ........ ........",
            vec![],
            "fistp m64",
            "alu",
        ),
        (
            "fild_m64_sibd",
            "S8",
            "11011111 01101100 ........ ........",
            vec![],
            "fild m64",
            "alu",
        ),
        (
            "fmulp_st",
            "F1",
            "11011110 11001...",
            vec![],
            "fmulp st",
            "alu",
        ),
        (
            "fsubp_st",
            "F1",
            "11011110 11101...",
            vec![],
            "fsubp st",
            "alu",
        ),
        (
            "fadd_st",
            "F1",
            "11011000 11000...",
            vec![],
            "fadd st",
            "alu",
        ),
        (
            "fstp_m64_sibd",
            "S8",
            "11011101 01011100 ........ ........",
            vec![],
            "fstp m64",
            "alu",
        ),
        (
            "pcmpeqb_memnd",
            "MR",
            "00001111 01110100 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "pcmpeqb xmm, m128",
            "load",
        ),
        (
            "pcmpeqb_mem8",
            "M8",
            "00001111 01110100 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "pcmpeqb xmm, m128",
            "load",
        ),
        (
            "pcmpeqb_mem32",
            "M32",
            "00001111 01110100 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "pcmpeqb xmm, m128",
            "load",
        ),
        (
            "pminub_memnd",
            "MR",
            "00001111 11011010 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "pminub xmm, m128",
            "load",
        ),
        (
            "pminub_mem8",
            "M8",
            "00001111 11011010 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "pminub xmm, m128",
            "load",
        ),
        (
            "pminub_mem32",
            "M32",
            "00001111 11011010 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "pminub xmm, m128",
            "load",
        ),
        (
            "por_memnd",
            "MR",
            "00001111 11101011 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "por xmm, m128",
            "load",
        ),
        (
            "por_mem8",
            "M8",
            "00001111 11101011 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "por xmm, m128",
            "load",
        ),
        (
            "por_mem32",
            "M32",
            "00001111 11101011 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "por xmm, m128",
            "load",
        ),
        // POR xmm,m128 SIB+disp32 (66 0F EB mod=10 rm=100)。grep 0x43d15b 対応.8B.
        (
            "por_sibd32",
            "F1",
            "00001111 11101011 10...100 ........ ................................",
            vec![],
            "por xmm, m128",
            "load",
        ),
        (
            "movzx_r32_m8_sib",
            "N8",
            "00001111 10110110 00...100 ........",
            vec![wc("n8_base", WhereOp::Ne, 5)],
            "movzx r32, m8",
            "load",
        ),
        (
            "movsx_r32_m8_sib",
            "N8",
            "00001111 10111110 00...100 ........",
            vec![wc("n8_base", WhereOp::Ne, 5)],
            "movsx r32, m8",
            "load",
        ),
        (
            "movsx_r32_m8_sibd",
            "S8",
            "00001111 10111110 01...100 ........ ........",
            vec![],
            "movsx r32, m8",
            "load",
        ),
        (
            "movzx_r32_m8_sibd",
            "S8",
            "00001111 10110110 01...100 ........ ........",
            vec![],
            "movzx r32, m8",
            "load",
        ),
        (
            "movzx_r32_m8_sibd32",
            "D32",
            "00001111 10110110 10...100 ........ ................................",
            vec![],
            "movzx r32, m8",
            "load",
        ),
        (
            "movzx_r32_m16_sibd",
            "S8",
            "00001111 10110111 01...100 ........ ........",
            vec![],
            "movzx r32, m16",
            "load",
        ),
        // MOVZX r32,m16 SIB+disp32 (0F B7 mod=10)。echo 0x4c05ba 対応.
        (
            "movzx_r32_m16_sibd32",
            "D32",
            "00001111 10110111 10...100 ........ ................................",
            vec![],
            "movzx r32, m16",
            "load",
        ),
        (
            "movzx_r32_m16_sib",
            "N8",
            "00001111 10110111 00...100 ........",
            vec![wc("n8_base", WhereOp::Ne, 5)],
            "movzx r32, m16",
            "load",
        ),
        (
            "movsxd_sib",
            "N8",
            "01100011 00...100 ........",
            vec![wc("n8_base", WhereOp::Ne, 5)],
            "movsxd r, m32",
            "load",
        ),
        (
            "movsxd_sibd",
            "S8",
            "01100011 01...100 ........ ........",
            vec![],
            "movsxd r, m32",
            "load",
        ),
        (
            "movsxd_sibd32",
            "D32",
            "01100011 10...100 ........ ................................",
            vec![],
            "movsxd r, m32",
            "load",
        ),
        (
            "sub_r_memnd",
            "MR",
            "00101011 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "sub r32, [r/m]",
            "alu",
        ),
        (
            "sub_r_mem8",
            "M8",
            "00101011 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "sub r32, m32",
            "alu",
        ),
        (
            "sub_m32_r32_mem8",
            "M8",
            "00101001 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "sub m32, r32",
            "alu",
        ),
        // SUB m32, r32 mod=10 [base+disp32] (29 /r)。gzip 0x48473b の subl %eax, 0x2af8(%rbx)。
        (
            "sub_m32_r32_mem32",
            "M32",
            "00101001 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "sub m32, r32",
            "alu",
        ),
        (
            "sub_r_mem32",
            "M32",
            "00101011 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "sub r32, m32",
            "alu",
        ),
        (
            "or_r_memnd",
            "MR",
            "00001011 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "or r32, [r/m]",
            "alu",
        ),
        (
            "or_r_mem8",
            "M8",
            "00001011 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "or r32, m32",
            "alu",
        ),
        (
            "or_r_mem32",
            "M32",
            "00001011 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "or r32, m32",
            "alu",
        ),
        // OR r32/r64, [base+index*scale+disp32] (0B /r SIB mod=10)。bzip2 0x480ec8 対応。
        (
            "or_r_sibd32",
            "D32",
            "00001011 10...100 ........ ................................",
            vec![],
            "or r32, [r/m+sib+disp32]",
            "alu",
        ),
        // OR r32,[base+index*scale] (0B /r mod=00 SIB)。sed 0x5be0c9 対応.
        (
            "or_r_sib",
            "N8",
            "00001011 00...100 ........",
            vec![wc("n8_base", WhereOp::Ne, 5)],
            "or r32, [r/m+sib]",
            "alu",
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
            "mov_m8_r8_sib",
            "N8",
            "10001000 00...100 ........",
            vec![wc("n8_base", WhereOp::Ne, 5)],
            "mov [r/m+sib], r8",
            "store",
        ),
        (
            "mov_m8_r8_sibd",
            "S8",
            "10001000 01...100 ........ ........",
            vec![],
            "mov [r/m+sib+disp8], r8",
            "store",
        ),
        (
            "mov_m8_r8_sibd32",
            "D32",
            "10001000 10...100 ........ ................................",
            vec![],
            "mov [r/m+sib+disp32], r8",
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
            "and_m32_r32_sib",
            "N8",
            "00100001 00...100 ........",
            vec![wc("n8_base", WhereOp::Ne, 5)],
            "and [r/m+sib], r32",
            "alu",
        ),
        (
            "or_m32_r32_sib",
            "N8",
            "00001001 00...100 ........",
            vec![wc("n8_base", WhereOp::Ne, 5)],
            "or [r/m+sib], r32",
            "alu",
        ),
        (
            "or_m32_r32_sibd",
            "S8",
            "00001001 01...100 ........ ........",
            vec![],
            "or [r/m+sib+disp8], r32",
            "alu",
        ),
        (
            "or_m32_r32_sibd32",
            "D32",
            "00001001 10...100 ........ ................................",
            vec![],
            "or [r/m+sib+disp32], r32",
            "alu",
        ),
        // OR m32/m64, r32/r64 [index*scale+disp32] (09 /r SIB mod=00 base=直接番地)。dd 0x4cde65 対応.
        (
            "or_m32_r32_sibabs",
            "D32",
            "00001001 00...100 ........ ................................",
            vec![wc("d32_base", WhereOp::Eq, 5)],
            "or [r/m+sib+disp32], r32",
            "alu",
        ),
        // IMUL r, [SIB], imm32 (69 /r mod=00)。base=5 は disp32 が付く。dd 0x4067c3 対応。
        (
            "imul_r_imm_sib",
            "D32",
            "01101001 00...100 ........ ................................",
            vec![wc("d32_base", WhereOp::Ne, 5)],
            "imul r, m, {imm}",
            "alu",
        ),
        // ADD m32,r32 [index*scale+disp32] (01 /r SIB mod=00 base=直接番地)。echo 0x4c08d1 対応.
        // CMP m32,r32 [index*scale+disp32] (39 /r SIB mod=00 base=直接番地)。id 0x4bfd44 対応.
        (
            "cmp_m32_r32_sibabs",
            "D32",
            "00111001 00...100 ........ ................................",
            vec![wc("d32_base", WhereOp::Eq, 5)],
            "cmp m, r",
            "alu",
        ),
        (
            "add_m32_r32_sibabs",
            "D32",
            "00000001 00...100 ........ ................................",
            vec![wc("d32_base", WhereOp::Eq, 5)],
            "add m, r",
            "alu",
        ),
        (
            "add_m32_r32_sib",
            "N8",
            "00000001 00...100 ........",
            vec![wc("n8_base", WhereOp::Ne, 5)],
            "add m, r",
            "alu",
        ),
        (
            "call_r_sibabs",
            "D32",
            "11111111 00010100 ........ ................................",
            vec![wc("d32_base", WhereOp::Eq, 5)],
            "call r/m64",
            "jump",
        ),
        // JMP [index*scale+disp32] (FF /4 SIB mod=00 base=直接番地)。uname 0x4d05e8 対応.
        (
            "jmp_r_sibabs",
            "D32",
            "11111111 00100100 ........ ................................",
            vec![wc("d32_base", WhereOp::Eq, 5)],
            "jmp r/m64",
            "jump",
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
            "mov_sibabs_r8",
            "D32",
            "10001000 00...100 ........ ................................",
            vec![wc("d32_base", WhereOp::Eq, 5)],
            "mov [sib+disp32], r8",
            "store",
        ),
        (
            "mov_m8_r8_memnd",
            "MR",
            "10001000 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "mov [r/m], r8",
            "store",
        ),
        (
            "mov_m8_r8_mem8",
            "M8",
            "10001000 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "mov [r/m+disp8], r8",
            "store",
        ),
        (
            "mov_m8_r8_mem32",
            "M32",
            "10001000 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "mov [r/m+disp32], r8",
            "store",
        ),
        (
            "mov_m8_r8_rip",
            "F1",
            "10001000 00...101 ................................",
            vec![],
            "mov [rip], r8",
            "store",
        ),
        (
            "mov_r8_m8_memnd",
            "MR",
            "10001010 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "mov r8, [r/m]",
            "load",
        ),
        // XOR r8,[base] (32 /r mod=00)。cksum 0x5c7fc7 対応.
        (
            "xor_r8_m8_memnd",
            "MR",
            "00110010 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "xor r8, [r/m]",
            "alu",
        ),
        (
            "mov_r8_m8_mem8",
            "M8",
            "10001010 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "mov r8, [r/m+disp8]",
            "load",
        ),
        (
            "mov_r8_m8_mem32",
            "M32",
            "10001010 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "mov r8, [r/m+disp32]",
            "load",
        ),
        (
            "mov_r8_m8_sib",
            "N8",
            "10001010 00...100 ........",
            vec![wc("n8_base", WhereOp::Ne, 5)],
            "mov r8, [r/m+sib]",
            "load",
        ),
        (
            "mov_r8_m8_sibd",
            "S8",
            "10001010 01...100 ........ ........",
            vec![],
            "mov r8, [r/m+sib+disp8]",
            "load",
        ),
        (
            "call_r_sibd",
            "S8",
            "11111111 01010100 ........ ........",
            vec![],
            "call r/m64",
            "jump",
        ),
        (
            "mov_r8_m8_sibd32",
            "D32",
            "10001010 10...100 ........ ................................",
            vec![],
            "mov r8, [r/m+sib+disp32]",
            "load",
        ),
        (
            "mov_r8_m8_rip",
            "F1",
            "10001010 00...101 ................................",
            vec![],
            "mov r8, [rip]",
            "load",
        ),
        // OR r8,m8 RIP (0A 05 + disp32)。find 0x5c44a7 対応.
        (
            "or_r8_m8_rip",
            "F1",
            "00001010 00...101 ................................",
            vec![],
            "or r8, m8",
            "load",
        ),
        (
            "mov_r8_m8",
            "F1",
            "10001010 11......",
            vec![],
            "mov r8, r/m8",
            "load",
        ),
        (
            "test_r8_r8",
            "F1",
            "10000100 11......",
            vec![],
            "test r/m8, r8",
            "alu",
        ),
        (
            "test_m8_r8_memnd",
            "MR",
            "10000100 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "test [r/m], r8",
            "alu",
        ),
        (
            "test_m8_r8_mem8",
            "M8",
            "10000100 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "test [r/m+disp8], r8",
            "alu",
        ),
        (
            "test_m8_r8_mem32",
            "M32",
            "10000100 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "test [r/m+disp32], r8",
            "alu",
        ),
        (
            "sub_m8_r8",
            "F1",
            "00101000 11......",
            vec![],
            "sub r/m8, r8",
            "alu",
        ),
        (
            "or_m8_r8",
            "F1",
            "00001000 11......",
            vec![],
            "or r/m8, r8",
            "alu",
        ),
        (
            "and_m8_r8",
            "F1",
            "00100000 11......",
            vec![],
            "and r/m8, r8",
            "alu",
        ),
        (
            "xor_m8_r8",
            "F1",
            "00110000 11......",
            vec![],
            "xor r/m8, r8",
            "alu",
        ),
        (
            "cmp_m8_r8",
            "F1",
            "00111000 11......",
            vec![],
            "cmp r/m8, r8",
            "alu",
        ),
        (
            "cmp_m8_r8_memnd",
            "MR",
            "00111000 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "cmp [r/m], r8",
            "alu",
        ),
        (
            "cmp_m8_r8_mem8",
            "M8",
            "00111000 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "cmp [r/m+disp8], r8",
            "alu",
        ),
        (
            "cmp_m8_r8_mem32",
            "M32",
            "00111000 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "cmp [r/m+disp32], r8",
            "alu",
        ),
        (
            "cmp_m8_r8_rip",
            "F1",
            "00111000 00...101 ................................",
            vec![],
            "cmp [rip], r8",
            "alu",
        ),
        (
            "cmp_m8_r8_sib",
            "N8",
            "00111000 00...100 ........",
            vec![wc("n8_base", WhereOp::Ne, 5)],
            "cmp [r/m+sib], r8",
            "alu",
        ),
        (
            "cmp_m8_r8_sibd",
            "S8",
            "00111000 01...100 ........ ........",
            vec![],
            "cmp [r/m+sib+disp8], r8",
            "alu",
        ),
        (
            "or_m8_r8_sibd",
            "S8",
            "00001000 01...100 ........ ........",
            vec![],
            "or [r/m+sib+disp8], r8",
            "alu",
        ),
        (
            "cmp_m8_r8_sibd32",
            "D32",
            "00111000 10...100 ........ ................................",
            vec![],
            "cmp [r/m+sib+disp32], r8",
            "alu",
        ),
        (
            "cmp_r8_m8",
            "F1",
            "00111010 11......",
            vec![],
            "cmp r8, r/m8",
            "alu",
        ),
        (
            "cmp_r8_m8_memnd",
            "MR",
            "00111010 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "cmp r8, [r/m]",
            "alu",
        ),
        (
            "cmp_r8_m8_mem8",
            "M8",
            "00111010 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "cmp r8, [r/m+disp8]",
            "alu",
        ),
        (
            "cmp_r8_m8_mem32",
            "M32",
            "00111010 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "cmp r8, [r/m+disp32]",
            "alu",
        ),
        (
            "cmp_r8_m8_sib",
            "N8",
            "00111010 00...100 ........",
            vec![wc("n8_base", WhereOp::Ne, 5)],
            "cmp r8, [r/m+sib]",
            "alu",
        ),
        (
            "cmp_r8_m8_sibd",
            "S8",
            "00111010 01...100 ........ ........",
            vec![],
            "cmp r8, [r/m+sib+disp8]",
            "alu",
        ),
        (
            "cmp_r8_m8_sibd32",
            "D32",
            "00111010 10...100 ........ ................................",
            vec![],
            "cmp r8, [r/m+sib+disp32]",
            "alu",
        ),
        (
            "mov_m8_r8",
            "F1",
            "10001000 11......",
            vec![],
            "mov r/m8, r8",
            "store",
        ),
        (
            "add_r_sibabs",
            "D32",
            "00000011 00...100 ........ ................................",
            vec![wc("d32_base", WhereOp::Eq, 5)],
            "add r32, [sib+disp32]",
            "alu",
        ),
        (
            "cmp_r_sibabs",
            "D32",
            "00111011 00...100 ........ ................................",
            vec![wc("d32_base", WhereOp::Eq, 5)],
            "cmp r32, [sib+disp32]",
            "alu",
        ),
        (
            "sub_r_sibabs",
            "D32",
            "00101011 00...100 ........ ................................",
            vec![wc("d32_base", WhereOp::Eq, 5)],
            "sub r32, [sib+disp32]",
            "alu",
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
            "cmp_rm8_imm_mem8",
            "S8",
            "10000000 01111... ........ ........",
            vec![wc("s8_rm", WhereOp::Ne, 4)],
            "cmp r/m8, {imm}",
            "alu",
        ),
        // CMPB m8,imm8 mod=00 [base] (80 /7)。SIBなし.
        (
            "cmp_rm8_imm_memnd",
            "F1",
            "10000000 00111... ........",
            vec![],
            "cmp r/m8, {imm}",
            "alu",
        ),
        (
            "or_rm8_imm_mem32",
            "F1",
            "10000000 10001... ................................ ........",
            vec![],
            "or r/m8, {imm}",
            "alu",
        ),
        (
            "or_rm8_imm_memnd",
            "F1",
            "10000000 00001... ........",
            vec![],
            "or r/m8, {imm}",
            "alu",
        ),
        (
            "or_rm8_imm_sib",
            "F1",
            "10000000 00001100 00100100 ........",
            vec![],
            "or [rsp], {imm}",
            "alu",
        ),
        (
            "or_rm8_imm_sibd",
            "F1",
            "10000000 01001100 ........ ........ ........",
            vec![],
            "or [r/m+sib+disp8], {imm}",
            "alu",
        ),
        // ORB m8,imm8 mod=01 [base+disp8] (80 /1)。sed 0x5bde04 対応.4B.
        (
            "or_rm8_imm_mem8",
            "F1",
            "10000000 01001... ........ ........",
            vec![],
            "or r/m8, {imm}",
            "alu",
        ),
        (
            "and_rm8_imm_mem32",
            "F1",
            "10000000 10100... ................................ ........",
            vec![],
            "and r/m8, {imm}",
            "alu",
        ),
        // ANDB m8,imm8 mod=01 [base+disp8] (80 /4)。grep 0x442d1d 対応.4B.
        (
            "and_rm8_imm_mem8",
            "F1",
            "10000000 01100... ........ ........",
            vec![],
            "and r/m8, {imm}",
            "alu",
        ),
        // ANDB m8,imm8 SIB mod=01 [base+index*scale+disp8] (80 /4)。grep 0x434710 対応.5B.
        (
            "and_rm8_imm_sibd",
            "F1",
            "10000000 01100100 ........ ........ ........",
            vec![],
            "and r/m8, {imm}",
            "alu",
        ),
        (
            "cmp_rm8_imm_mem32",
            "F1",
            "10000000 10111... ................................ ........",
            vec![],
            "cmp r/m8, {imm}",
            "alu",
        ),
        (
            "mov_rm8_imm_mem8",
            "S8",
            "11000110 01000... ........ ........",
            vec![wc("s8_rm", WhereOp::Ne, 4)],
            "mov r/m8, {imm}",
            "store",
        ),
        (
            "mov_rm8_imm_memnd",
            "M8",
            "11000110 00000... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4), wc("m8_rm", WhereOp::Ne, 5)],
            "mov r/m8, {imm}",
            "store",
        ),
        (
            "mov_rm8_imm_sibd",
            "S8",
            "11000110 01000100 ........ ........ ........",
            vec![],
            "mov r/m8, {imm}",
            "store",
        ),
        // MOVB [base+index*scale+disp32],imm8 (C6 /0 SIB mod=10)。
        (
            "mov_rm8_imm_sibd32",
            "F1",
            "11000110 10000100 ........ ................................ ........",
            vec![],
            "mov r/m8, {imm}",
            "store",
        ),
        // MOVB [base+index*scale],imm8 (C6 /0 SIB mod=00)。
        (
            "mov_rm8_imm_sib",
            "F1",
            "11000110 00000100 ........ ........",
            vec![],
            "mov r/m8, {imm}",
            "store",
        ),
        (
            "mov_rm8_imm_mem32",
            "M32",
            "11000110 10000... ................................ ........",
            // SIB は取得長64で分岐するためここでは除外しない.
            vec![],
            "mov r/m8, {imm}",
            "store",
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
        // MOVDQU xmm,m128 mod=01 (F3 0F 6F)。SIBなし。MOVUPS と等価のため意味論を共有する。
        (
            "movdqu_load_mem8",
            "M8",
            "00001111 01101111 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "movdqu xmm, m128",
            "load",
        ),
        // MOVDQU xmm,m128 mod=00 [base] (F3 0F 6F)。SIB/絶対番地なし.
        (
            "movdqu_load_memnd",
            "MR",
            "00001111 01101111 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "movdqu xmm, m128",
            "load",
        ),
        // MOVDQU xmm,m128 mod=10 [base+disp32] (F3 0F 6F)。SIBなし.
        (
            "movdqu_load_mem32",
            "M32",
            "00001111 01101111 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "movdqu xmm, m128",
            "load",
        ),
        // MOVDQU xmm,m128 SIB mod=00 [base+index*scale] (F3 0F 6F / 66 0F 6F)。
        // MOVDQA とバイト列共有のため意味論は MOVUPS と等価で共用する.
        (
            "movdqu_load_sib",
            "N8",
            "00001111 01101111 00...100 ........",
            vec![wc("n8_base", WhereOp::Ne, 5)],
            "movdqu xmm, m128",
            "load",
        ),
        // MOVDQU m128,xmm mod=00 [base] (F3 0F 7F)。SIB/絶対番地なし。MOVUPS と等価.
        (
            "movdqu_store_memnd",
            "MR",
            "00001111 01111111 00......",
            vec![wc("mr_rm", WhereOp::Ne, 4), wc("mr_rm", WhereOp::Ne, 5)],
            "movdqu m128, xmm",
            "store",
        ),
        // MOVDQU m128,xmm mod=01 [base+disp8] (F3 0F 7F)。SIBなし。MOVUPS と等価.
        (
            "movdqu_store_mem8",
            "M8",
            "00001111 01111111 01...... ........",
            vec![wc("m8_rm", WhereOp::Ne, 4)],
            "movdqu m128, xmm",
            "store",
        ),
        // MOVDQU m128,xmm mod=10 [base+disp32] (F3 0F 7F)。SIBなし。MOVUPS と等価.
        (
            "movdqu_store_mem32",
            "M32",
            "00001111 01111111 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "movdqu m128, xmm",
            "store",
        ),
        // MOVDQU m128,xmm SIB mod=00 [base+index*scale] (F3 0F 7F / 66 0F 7F)。
        // MOVDQA とバイト列共有のため意味論は MOVUPS と等価で共用する.
        (
            "movdqu_store_sib",
            "N8",
            "00001111 01111111 00...100 ........",
            vec![wc("n8_base", WhereOp::Ne, 5)],
            "movdqu m128, xmm",
            "store",
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
            "movups_load_mem32",
            "M32",
            "00001111 00010000 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "movups xmm, [r/m+disp32]",
            "load",
        ),
        (
            "movups_store_mem32",
            "M32",
            "00001111 00010001 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "movups [r/m+disp32], xmm",
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
            "movaps_store_sib",
            "N8",
            "00001111 00101001 00...100 ........",
            vec![wc("n8_base", WhereOp::Ne, 5)],
            "movaps [r/m+sib], xmm",
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
            "movaps_load_sibd",
            "S8",
            "00001111 00101000 01...100 ........ ........",
            vec![],
            "movaps xmm, [r/m+sib+disp8]",
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
            "movaps_store_sibd",
            "S8",
            "00001111 00101001 01...100 ........ ........",
            vec![],
            "movaps [r/m+sib+disp8], xmm",
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
            "movaps_store_mem32",
            "M32",
            "00001111 00101001 10...... ................................",
            vec![wc("m32_rm", WhereOp::Ne, 4)],
            "movaps [r/m+disp32], xmm",
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
