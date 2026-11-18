// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Pentium (P5) タイミングモデルの検証（ロードマップ S13-3、E4a）。
//!
//! `timing::classify` の命令属性を `timing::Pentium` の U/V パイプ
//! 発行モデルに流し、SPEC-X86-PENTIUM（241428/241430）の命令
//! クロック・ペアリング規則・AGI・バンク競合と一致するかを検証する。
//! ペアリングは命令列でしか起きないので、列の合計クロックを主に見る。

use polyisa_guest_x86::timing::{InsnTiming, Pentium, classify};
use polyisa_guest_x86::{
    DEFAULT_FEATS, MODE_ADR_A32, MODE_ADR_SHIFT, MODE_OPD_O32, MODE_OPD_SHIFT, decode_map,
};

const M32: u32 = MODE_OPD_O32 << MODE_OPD_SHIFT | MODE_ADR_A32 << MODE_ADR_SHIFT;

fn xt(bytes: &[u8]) -> InsnTiming {
    let d =
        decode_map(bytes, M32, DEFAULT_FEATS).unwrap_or_else(|| panic!("undecodable {bytes:02x?}"));
    classify(&d, true).unwrap_or_else(|| panic!("unclassified {bytes:02x?}"))
}

/// 命令列の合計クロック（アドレスはバンク判定に使う）。
fn seq(insns: &[(&[u8], Option<u64>)]) -> u64 {
    let mut m = Pentium::new();
    for (b, a) in insns {
        m.step(xt(b), *a);
    }
    m.time
}

#[test]
fn p5_base_clocks() {
    // Ref: SPEC-X86-PENTIUM 命令クロック表。単発は U パイプで完結。
    for (b, want, what) in [
        (&[0x01, 0xD8][..], 1, "add r,r"),
        (&[0x03, 0x18][..], 2, "add r,m"),
        (&[0x01, 0x18][..], 3, "add m,r"),
        (&[0x83, 0x00, 0x01][..], 3, "add m,imm"),
        (&[0x05, 0x01, 0x00, 0x00, 0x00][..], 1, "add acc,imm"),
        (&[0x13, 0x18][..], 4, "adc r,m"),
        (&[0x11, 0x18][..], 3, "adc m,r"),
        (&[0x39, 0x18][..], 2, "cmp m,r"),
        (&[0x8B, 0x08][..], 1, "mov r,m"),
        (&[0x89, 0x08][..], 1, "mov m,r"),
        (&[0xC7, 0x00, 0x01, 0x00, 0x00, 0x00][..], 1, "mov m,imm"),
        (&[0xFF, 0xC0][..], 1, "inc r"),
        (&[0xFF, 0x08][..], 3, "dec m"),
        (&[0xF7, 0xD8][..], 1, "neg r"),
        (&[0xF7, 0x18][..], 3, "neg m"),
        (&[0x87, 0xD8][..], 3, "xchg r,r"),
        (&[0x87, 0x18][..], 3, "xchg m,r"),
        (&[0x93][..], 2, "xchg eax,ebx"),
        (&[0x0F, 0xB6, 0xD8][..], 3, "movzx"),
        (&[0x8D, 0x03][..], 1, "lea"),
        (&[0x90][..], 2, "xchg eax,eax"),
        (&[0xD7][..], 4, "xlat"),
        (&[0x98][..], 3, "cwde"),
        (&[0x99][..], 2, "cdq"),
        (&[0x9F][..], 2, "lahf"),
        (&[0x9E][..], 2, "sahf"),
        (&[0xF8][..], 2, "clc"),
        (&[0x0F, 0xC8][..], 1, "bswap"),
        (&[0xD1, 0xE8][..], 1, "shr r,1"),
        (&[0xC1, 0xE8, 0x03][..], 1, "shr r,imm"),
        (&[0xD3, 0xE8][..], 4, "shr r,cl"),
        (&[0xD3, 0x28][..], 4, "shr m,cl"),
        (&[0xD1, 0x28][..], 3, "shr m,1"),
        (&[0x0F, 0xA4, 0xD8, 0x04][..], 4, "shld r,imm"),
        (&[0x0F, 0xAC, 0x08, 0x04][..], 4, "shrd m,imm"),
        (&[0x0F, 0xA5, 0xD8][..], 4, "shld r,cl"),
        (&[0x0F, 0xA5, 0x08][..], 5, "shld m,cl"),
        (&[0x0F, 0xA3, 0xD8][..], 4, "bt r,r"),
        (&[0x0F, 0xBA, 0xE8, 0x03][..], 4, "bts r,imm"),
        (&[0x50][..], 1, "push r"),
        (&[0xFF, 0x30][..], 2, "push m"),
        (&[0x6A, 0x01][..], 1, "push imm"),
        (&[0x58][..], 1, "pop r"),
        (&[0x8F, 0x00][..], 3, "pop m"),
        (&[0x9D][..], 6, "popf"),
        (&[0xE8, 0x00, 0x00, 0x00, 0x00][..], 1, "call rel"),
        (&[0xFF, 0xD0][..], 2, "call r"),
        (&[0xFF, 0x10][..], 4, "call m"),
        (&[0xC3][..], 2, "ret"),
        (&[0xC2, 0x04, 0x00][..], 4, "ret imm"),
        (&[0xEB, 0x00][..], 1, "jmp short"),
        (&[0xFF, 0xE0][..], 2, "jmp r"),
        (&[0x74, 0x00][..], 1, "je"),
        (&[0xF6, 0xE0][..], 11, "mul r8"),
        (&[0xF7, 0xE0][..], 10, "mul r32"),
        (&[0x66, 0xF7, 0xE0][..], 12, "mul r16 + prefix"),
        (&[0x0F, 0xAF, 0xD8][..], 10, "imul r,r"),
        (&[0x6B, 0xD8, 0x05][..], 10, "imul r,r,imm8"),
        (&[0xF6, 0xF0][..], 17, "div r8"),
        (&[0xF7, 0xF0][..], 41, "div r32"),
        (&[0x66, 0xF7, 0xF0][..], 26, "div r16 + prefix"),
        (&[0xF7, 0xF8][..], 46, "idiv r32"),
        (&[0x0F, 0xB1, 0xD8][..], 5, "cmpxchg r,r"),
        (&[0x0F, 0xB1, 0x18][..], 6, "cmpxchg m,r"),
        (&[0x0F, 0xC1, 0xD8][..], 3, "xadd r,r"),
        (&[0x0F, 0xC1, 0x18][..], 4, "xadd m,r"),
    ] {
        assert_eq!(seq(&[(b, None)]), want, "{what} {b:02x?}");
    }
}

#[test]
fn p5_pairing() {
    // Ref: SPEC-X86-PENTIUM — U/V ペアリング規則。
    let add_eax_ebx: &[u8] = &[0x01, 0xD8];
    let add_ecx_ebx: &[u8] = &[0x01, 0xD9];
    let mov_eax_imm: &[u8] = &[0xB8, 0x01, 0x00, 0x00, 0x00];
    let cmp_eax_ebx: &[u8] = &[0x39, 0xD8];
    let je: &[u8] = &[0x74, 0x00];
    // UV+UV 依存なし → 1 クロックでペア。
    assert_eq!(seq(&[(add_eax_ebx, None), (add_ecx_ebx, None)]), 1);
    // RAW（V が U の書き込み先を読む）→ ペア不可。
    let add_eax_ebx_again: &[u8] = &[0x01, 0xD8];
    let add_eax_ecx: &[u8] = &[0x01, 0xC8]; // add eax,ecx
    assert_eq!(seq(&[(add_eax_ebx_again, None), (add_eax_ecx, None)]), 2);
    // WAW もペア不可。
    assert_eq!(seq(&[(mov_eax_imm, None), (mov_eax_imm, None)]), 2);
    // flags を書く U に続く分岐は例外的にペア可。
    assert_eq!(seq(&[(cmp_eax_ebx, None), (je, None)]), 1);
    // ADC は PU → V 側には置けない（U→U で 2）。
    let adc_ecx_ebx: &[u8] = &[0x11, 0xD9];
    assert_eq!(seq(&[(add_eax_ebx, None), (adc_ecx_ebx, None)]), 2);
    // PU は U 側ならペアの先頭に立てる。
    let adc_eax_ebx: &[u8] = &[0x11, 0xD8];
    assert_eq!(seq(&[(adc_eax_ebx, None), (add_ecx_ebx, None)]), 1);
    // シフト（PU）も U 側先頭でペア可。
    let shr_eax_3: &[u8] = &[0xC1, 0xE8, 0x03];
    assert_eq!(seq(&[(shr_eax_3, None), (add_ecx_ebx, None)]), 1);
    // 分岐（PV）は U 側には置けない → 直列。
    assert_eq!(seq(&[(je, None), (add_ecx_ebx, None)]), 2);
    // NP はペア不可（neg=1 + add=1 = 2）。
    let neg_eax: &[u8] = &[0xF7, 0xD8];
    assert_eq!(seq(&[(neg_eax, None), (add_ecx_ebx, None)]), 2);
    // 3 クロックの U 側（RMW=UV）でも V は初クロックに並走する。
    let add_eax_ptr_ebx: &[u8] = &[0x01, 0x18]; // add [eax],ebx
    assert_eq!(seq(&[(add_eax_ptr_ebx, None), (add_ecx_ebx, None)]), 3);
    // V 側が 2 クロックならペアは max(u, v)。
    let add_ebx_eax_ptr: &[u8] = &[0x03, 0x18]; // add ebx,[eax]（2, UV）
    let sub_ecx_eax_ptr: &[u8] = &[0x2B, 0x08]; // sub ecx,[eax]（2, UV）
    assert_eq!(
        seq(&[
            (add_ebx_eax_ptr, Some(0x100)),
            (sub_ecx_eax_ptr, Some(0x104))
        ]),
        2
    );
    // 接頭辞付き命令は V パイプに入れない → 直列（1 + 1+接頭辞1）。
    let add_ecx_ebx_66: &[u8] = &[0x66, 0x01, 0xD9];
    assert_eq!(seq(&[(add_eax_ebx, None), (add_ecx_ebx_66, None)]), 3);
    // 呼び出し・戻りは消費をそのまま足す（call=1,ret=2）。
    let call: &[u8] = &[0xE8, 0x00, 0x00, 0x00, 0x00];
    let ret: &[u8] = &[0xC3];
    assert_eq!(seq(&[(call, None), (ret, None)]), 3);
}

#[test]
fn p5_disp_imm_and_bank() {
    let add_ecx_ebx: &[u8] = &[0x01, 0xD9];
    // 即値+変位の同時存在はペア不可（PENTIUM の規則）。
    let add_mem_imm: &[u8] = &[0x81, 0x00, 0x01, 0x00, 0x00, 0x00]; // add [eax],imm32
    let add_mem_disp_imm: &[u8] = &[0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
    assert_eq!(seq(&[(add_mem_imm, Some(0x100)), (add_ecx_ebx, None)]), 3);
    assert_eq!(
        seq(&[(add_mem_disp_imm, Some(0x100)), (add_ecx_ebx, None)]),
        4
    );
    // D-cache バンク衝突（addr[4:2] 一致）→ V は 1 クロック遅延。
    let mov_ecx_eax_ptr: &[u8] = &[0x8B, 0x08]; // mov ecx,[eax]
    let mov_ebx_edx_ptr: &[u8] = &[0x8B, 0x1A]; // mov ebx,[edx]
    // 別バンク → ペア可。
    assert_eq!(
        seq(&[
            (mov_ecx_eax_ptr, Some(0x100)),
            (mov_ebx_edx_ptr, Some(0x104))
        ]),
        1
    );
    // 同バンク（0x100 と 0x120 は (a>>2)&7 がともに 0）→ V は 1 遅延。
    assert_eq!(
        seq(&[
            (mov_ecx_eax_ptr, Some(0x100)),
            (mov_ebx_edx_ptr, Some(0x120))
        ]),
        2
    );
    // U が複数クロックならバンク遅延は U のクロックに吸収される。
    let add_ebx_eax_ptr: &[u8] = &[0x03, 0x18];
    let sub_ecx_eax_ptr: &[u8] = &[0x2B, 0x08];
    assert_eq!(
        seq(&[
            (add_ebx_eax_ptr, Some(0x100)),
            (sub_ecx_eax_ptr, Some(0x120))
        ]),
        3
    );
    // メモリ読みと無関係なレジスタ演算はバンク衝突なし。
    let add_edx_ebx: &[u8] = &[0x01, 0xDA];
    assert_eq!(
        seq(&[(mov_ecx_eax_ptr, Some(0x100)), (add_edx_ebx, None)]),
        1
    );
}

#[test]
fn p5_agi_and_prefix() {
    // AGI: 直前命令が書いた reg を EA が使うと +1。
    let mov_eax_imm: &[u8] = &[0xB8, 0x00, 0x00, 0x00, 0x00];
    let mov_ecx_eax_ptr: &[u8] = &[0x8B, 0x08];
    assert_eq!(seq(&[(mov_eax_imm, None), (mov_ecx_eax_ptr, None)]), 3);
    // 接頭辞 +1。
    let add66: &[u8] = &[0x66, 0x01, 0xD8];
    assert_eq!(seq(&[(add66, None)]), 2);
}
