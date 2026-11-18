// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 80486 タイミングモデルの検証（ロードマップ S13-3、E4a）。
//!
//! `timing::classify` が map デコード結果から引いた命令属性を
//! `timing::I486` の発行モデルに流し、SPEC-X86-I486（Intel486 PRM）
//! の基本クロック・AGI・接頭辞ペナルティと一致するかを検証する。
//! 単発命令のクロック表と、依存・接頭辞を含む命令列の両方を扱う。

use polyisa_guest_x86::timing::{I486, InsnTiming, classify};
use polyisa_guest_x86::{
    DEFAULT_FEATS, MODE_ADR_A32, MODE_ADR_SHIFT, MODE_OPD_O32, MODE_OPD_SHIFT, decode_map,
};

const M32: u32 = MODE_OPD_O32 << MODE_OPD_SHIFT | MODE_ADR_A32 << MODE_ADR_SHIFT;
/// 16 ビットモード（O16+A16）は両フィールド 0。
const M16: u32 = 0;

fn xt(bytes: &[u8], modes: u32, taken: bool) -> InsnTiming {
    let d = decode_map(bytes, modes, DEFAULT_FEATS)
        .unwrap_or_else(|| panic!("undecodable {bytes:02x?}"));
    classify(&d, taken).unwrap_or_else(|| panic!("unclassified {bytes:02x?}"))
}

/// 単発命令の 486 クロック数。
fn one(bytes: &[u8]) -> u64 {
    I486::new().step(&xt(bytes, M32, true))
}

/// 命令列の合計クロック数。`taken` は分岐命令の成否。
fn seq(insns: &[(&[u8], bool)]) -> u64 {
    let mut m = I486::new();
    for (b, t) in insns {
        m.step(&xt(b, M32, *t));
    }
    m.time
}

#[test]
fn i486_base_clocks() {
    // Ref: SPEC-X86-I486 命令クロック表。
    for (b, want, what) in [
        // ALU: r,r / r,m / m,r / r,i / m,i / acc,i
        (&[0x01, 0xD8][..], 1, "add r32,r32"),
        (&[0x29, 0xD8][..], 1, "sub r,r"),
        (&[0x31, 0xD8][..], 1, "xor r,r"),
        (&[0x09, 0xD8][..], 1, "or r,r"),
        (&[0x21, 0xD8][..], 1, "and r,r"),
        (&[0x03, 0x18][..], 2, "add r,[eax]"),
        (&[0x2B, 0x18][..], 2, "sub r,m"),
        (&[0x01, 0x18][..], 3, "add [eax],r"),
        (&[0x39, 0xD8][..], 1, "cmp r,r"),
        (&[0x39, 0x18][..], 2, "cmp [eax],r"),
        (&[0x3B, 0x18][..], 2, "cmp r,[eax]"),
        (&[0x85, 0x18][..], 2, "test [eax],r"),
        (&[0x83, 0xC0, 0x01][..], 1, "add r,imm8"),
        (&[0x83, 0x00, 0x01][..], 3, "add [eax],imm8"),
        (
            &[0x81, 0x00, 0x01, 0x00, 0x00, 0x00][..],
            3,
            "add [eax],imm32",
        ),
        (&[0x83, 0x38, 0x01][..], 2, "cmp [eax],imm8"),
        (&[0x05, 0x01, 0x00, 0x00, 0x00][..], 1, "add eax,imm"),
        (&[0x04, 0x01][..], 1, "add al,imm"),
        (&[0x15, 0x01, 0x00, 0x00, 0x00][..], 1, "adc eax,imm"),
        // MOV は全形 1
        (&[0x89, 0xD8][..], 1, "mov r,r"),
        (&[0x8B, 0xD8][..], 1, "mov r,r"),
        (&[0x8B, 0x08][..], 1, "mov r,[eax]"),
        (&[0x89, 0x08][..], 1, "mov [eax],r"),
        (
            &[0xC7, 0x00, 0x01, 0x00, 0x00, 0x00][..],
            1,
            "mov [eax],imm",
        ),
        (&[0xB8, 0x01, 0x00, 0x00, 0x00][..], 1, "mov eax,imm"),
        (&[0xB0, 0x01][..], 1, "mov al,imm"),
        // INC/DEC/NEG/NOT
        (&[0xFF, 0xC0][..], 1, "inc r/m r"),
        (&[0xFE, 0xC0][..], 1, "inc r8"),
        (&[0x40][..], 1, "inc eax +r"),
        (&[0xFF, 0x08][..], 3, "dec [eax]"),
        (&[0xF7, 0xD8][..], 1, "neg r"),
        (&[0xF7, 0x18][..], 3, "neg [eax]"),
        (&[0xF7, 0xD0][..], 1, "not r"),
        // XCHG/MOVSX/ZX/LEA
        (&[0x87, 0xD8][..], 3, "xchg r,r"),
        (&[0x87, 0x18][..], 5, "xchg [eax],r"),
        (&[0x93][..], 3, "xchg eax,ebx +r"),
        (&[0x0F, 0xB6, 0xD8][..], 3, "movzx"),
        (&[0x0F, 0xB6, 0x08][..], 3, "movzx m"),
        (&[0x0F, 0xBE, 0xD8][..], 3, "movsx"),
        (&[0x8D, 0x03][..], 1, "lea"),
        // シフト・SHLD/SHRD
        (&[0xD1, 0xE8][..], 2, "shr r,1"),
        (&[0xD3, 0xE8][..], 2, "shr r,cl"),
        (&[0xC1, 0xE8, 0x03][..], 2, "shr r,imm8"),
        (&[0xD1, 0x28][..], 4, "shr [eax],1"),
        (&[0xD1, 0xD0][..], 2, "rcl r,1"),
        (&[0x0F, 0xA4, 0xD8, 0x04][..], 2, "shld r,r,imm"),
        (&[0x0F, 0xA5, 0xD8][..], 2, "shld r,r,cl"),
        (&[0x0F, 0xAC, 0x08, 0x04][..], 3, "shrd [eax],r,imm"),
        // BT 系（レジスタ形）
        (&[0x0F, 0xA3, 0xD8][..], 3, "bt r,r"),
        (&[0x0F, 0xBA, 0xE8, 0x03][..], 6, "bts r,imm"),
        (&[0x0F, 0xAB, 0xD8][..], 6, "bts r,r"),
        // スタック
        (&[0x50][..], 1, "push eax"),
        (&[0xFF, 0x30][..], 4, "push [eax]"),
        (&[0x68, 0x01, 0x00, 0x00, 0x00][..], 1, "push imm32"),
        (&[0x6A, 0x01][..], 1, "push imm8"),
        (&[0x58][..], 1, "pop eax"),
        (&[0x8F, 0x00][..], 5, "pop [eax]"),
        (&[0x60][..], 11, "pusha"),
        (&[0x61][..], 9, "popa"),
        (&[0x9C][..], 4, "pushf"),
        (&[0x9D][..], 6, "popf"),
        // 制御移転
        (&[0xE8, 0x00, 0x00, 0x00, 0x00][..], 3, "call rel"),
        (&[0xFF, 0xD0][..], 5, "call r"),
        (&[0xEB, 0x00][..], 3, "jmp short"),
        (&[0xE9, 0x00, 0x00, 0x00, 0x00][..], 3, "jmp near"),
        (&[0xFF, 0xE0][..], 5, "jmp r"),
        (&[0xC3][..], 5, "ret"),
        (&[0xC2, 0x04, 0x00][..], 5, "ret imm16"),
        // 変換・雑
        (&[0x98][..], 3, "cwde"),
        (&[0x99][..], 2, "cdq"),
        (&[0x9F][..], 2, "lahf"),
        (&[0x9E][..], 3, "sahf"),
        (&[0xD7][..], 4, "xlat"),
        (&[0xF8][..], 2, "clc"),
        (&[0xF9][..], 2, "stc"),
        (&[0xF5][..], 2, "cmc"),
        (&[0xFC][..], 2, "cld"),
        (&[0x0F, 0xC8][..], 1, "bswap eax"),
        // 除算（幅別固定値）
        (&[0xF6, 0xF0][..], 16, "div r8"),
        (&[0xF7, 0xF0][..], 40, "div r32"),
        (&[0xF6, 0xF8][..], 19, "idiv r8"),
        (&[0xF7, 0xF8][..], 43, "idiv r32"),
        // 複合
        (&[0x0F, 0xB1, 0xD8][..], 6, "cmpxchg r,r"),
        (&[0x0F, 0xB1, 0x18][..], 7, "cmpxchg m,r"),
        (&[0x0F, 0xC1, 0xD8][..], 4, "xadd r,r"),
        (&[0x0F, 0xC1, 0x18][..], 7, "xadd m,r"),
    ] {
        assert_eq!(one(b), want, "{what} {b:02x?}");
    }
}

#[test]
fn i486_branch_clocks() {
    // jcc/loop 系は成否でクロックが変わる（taken/nt）。
    for (b, t, nt, what) in [
        (&[0x74, 0x00][..], 3, 1, "je short"),
        (&[0x0F, 0x84, 0x00, 0x00, 0x00, 0x00][..], 3, 1, "je near"),
        (&[0xE3, 0x00][..], 8, 5, "jcxz"),
        (&[0xE2, 0x00][..], 7, 6, "loop"),
        (&[0xE1, 0x00][..], 9, 6, "loope"),
        (&[0xE0, 0x00][..], 9, 6, "loopne"),
    ] {
        assert_eq!(I486::new().step(&xt(b, M32, true)), t, "{what} taken");
        assert_eq!(I486::new().step(&xt(b, M32, false)), nt, "{what} nt");
    }
}

#[test]
fn i486_agi_and_prefix() {
    // Ref: SPEC-X86-I486 — AGI（直前命令が書いた reg を EA が使うと +1）。
    let mov_eax_imm: &[u8] = &[0xB8, 0x00, 0x00, 0x00, 0x00];
    let mov_ecx_imm: &[u8] = &[0xB9, 0x00, 0x00, 0x00, 0x00];
    let mov_ecx_eax_ptr: &[u8] = &[0x8B, 0x08]; // mov ecx,[eax]
    // AGI あり: mov eax,imm; mov ecx,[eax] → 1 + (1+1)
    assert_eq!(seq(&[(mov_eax_imm, false), (mov_ecx_eax_ptr, false)]), 3);
    // AGI なし（eax を書かない）: mov ecx,imm; mov ecx,[eax] → 2
    assert_eq!(seq(&[(mov_ecx_imm, false), (mov_ecx_eax_ptr, false)]), 2);
    // 直前のみ（2 つ前は効かない）: mov eax; mov ecx; mov edx,[eax] → 3
    let mov_edx_eax_ptr: &[u8] = &[0x8B, 0x10];
    assert_eq!(
        seq(&[
            (mov_eax_imm, false),
            (mov_ecx_imm, false),
            (mov_edx_eax_ptr, false)
        ]),
        3
    );
    // 接頭辞は 1 バイト +1。
    let add66: &[u8] = &[0x66, 0x01, 0xD8]; // add ax,bx
    let mov_seg: &[u8] = &[0x2E, 0x8B, 0x08]; // mov ecx,cs:[eax]
    assert_eq!(one(add66), 2, "operand-size prefix");
    assert_eq!(one(mov_seg), 2, "seg override");
    // AGI と接頭辞は独立に加算。
    assert_eq!(seq(&[(mov_eax_imm, false), (mov_seg, false)]), 4);
    // 16 ビットアドレス形でも AGI。
    let mov_ax_bx_ptr: &[u8] = &[0x8B, 0x07]; // mov ax,[bx]
    let mov_bx_imm: &[u8] = &[0xBB, 0x00, 0x00];
    assert_eq!(
        {
            let mut m = I486::new();
            for b in [mov_bx_imm, mov_ax_bx_ptr] {
                m.step(&xt(b, M16, false));
            }
            m.time
        },
        3
    );
}

#[test]
fn i486_unclassified() {
    // 値依存・範囲外の命令は classify が None / c486=None。
    for b in [
        &[0x0F, 0xBC, 0xD8][..], // bsf（値依存）
        &[0x0F, 0xAF, 0xD8][..], // imul 2op（値依存）
        &[0xF7, 0xE0][..],       // mul r32（値依存）
        &[0x6B, 0xD8, 0x05][..], // imul r,r,imm（値依存）
        &[0xF3, 0xA4][..],       // rep movsb（未採録）
        &[0xD9, 0xE8][..],       // fld1（x87 未採録）
        &[0x0F, 0x94, 0xD8][..], // sete（未採録）
    ] {
        let d = decode_map(b, M32, DEFAULT_FEATS);
        match d.and_then(|d| classify(&d, false)) {
            None => {}
            Some(x) => assert!(x.c486.is_none(), "{b:02x?} must be value-dep"),
        }
    }
}
