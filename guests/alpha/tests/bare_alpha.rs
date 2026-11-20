// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Alpha の命令語単位のデコード検査（段階16の骨格）。
//! 生成デコーダがリテラル語を正しく分類することを見る。
//! 出典は SPEC-ALPHA-ARM である。
//! Ref: SPEC-ALPHA-ARM.

use polyisa_guest_alpha::*;

const ALL: u128 = FEAT_BWX | FEAT_CIX | FEAT_FIX | FEAT_MVI | FEAT_EV5 | FEAT_EV56 | FEAT_EV7;

fn dec(word: u32) -> Option<Insn> {
    decode_model_ex(word as u128, 32, false, ALL)
}

#[test]
fn decode_core_insns() {
    // bis $31,$31,$31（nop の正体）。
    assert_eq!(dec(0x47ff_041f), Some(Insn::Bis));
    // addq $1,$2,$3 と addq $1,0x55,$3（リテラル形）。
    assert_eq!(dec(0x4022_0403), Some(Insn::Addq));
    assert_eq!(dec(0x402a_b403), Some(Insn::AddqI));
    // ret $31,($26),1。
    assert_eq!(dec(0x6bfa_8001), Some(Insn::Ret));
    // implver $10。
    assert_eq!(dec(0x47e0_3d8a), Some(Insn::Implver));
}

#[test]
fn decode_memory_and_branch() {
    // ldq $1,0($2) と stq $1,16($2)。
    assert_eq!(dec(0xa402_0000), Some(Insn::Ldq));
    assert_eq!(dec(0xb402_0010), Some(Insn::Stq));
    // br $31,.-4（disp21 = -1）。
    assert_eq!(dec(0xc3ff_ffff), Some(Insn::Br));
    // beq $1,+8（disp21 = 2）。
    assert_eq!(dec(0xe420_0002), Some(Insn::Beq));
    // mb と callsys（call_pal 0x83）。
    assert_eq!(dec(0x6000_4000), Some(Insn::Mb));
    assert_eq!(dec(0x0000_0083), Some(Insn::CallPal));
    // pal19（PAL 予約オペコード）。
    assert_eq!(dec(0x6400_0000), Some(Insn::Pal19));
}

#[test]
fn fp_qualifier_variants_decode() {
    // adds/su $f0,$f1,$f2（修飾子 fn[10:6]=10110 はワイルドカードで受理）。
    assert_eq!(dec(0x5801_b002), Some(Insn::Adds));
    // cvtts $f2,$f3（fn=0x0AC）。
    assert_eq!(dec(0x5802_1583), Some(Insn::Cvtts));
    // cvtst / cvtst/s は cvtts と fn[5:0] が同じで wheres が分ける。
    assert_eq!(dec(0x5802_5583), Some(Insn::Cvtst));
    assert_eq!(dec(0x5802_d583), Some(Insn::CvtstS));
    // cpys $f0,$f1,$f2（opcode 0x17 の固定 function）。
    assert_eq!(dec(0x5c01_0402), Some(Insn::Cpys));
}

#[test]
fn extension_features_gate_decode() {
    // ldbu $5,16($6)（BWX）。
    let ldbu = 0x28a6_0010u128;
    assert_eq!(decode_model_ex(ldbu, 32, false, ALL), Some(Insn::Ldbu));
    // 拡張を持たないモデル（ev5 相当）では予約命令。
    assert_eq!(decode_model_ex(ldbu, 32, false, 0), None);
    // sextw $31,$7,$8（BWX。ra 桁は読まない）。
    let sextw = 0x73e7_0028u128;
    assert_eq!(decode_model_ex(sextw, 32, false, ALL), Some(Insn::Sextw));
    assert_eq!(decode_model_ex(sextw, 32, false, FEAT_CIX), None);
    // sqrts/su $f1,$f2（FIX）。
    let sqrts = 0x5001_b162u128;
    assert_eq!(decode_model_ex(sqrts, 32, false, ALL), Some(Insn::Sqrts));
    assert_eq!(decode_model_ex(sqrts, 32, false, FEAT_BWX), None);
    // ctpop $31,$5,$6（CIX）。
    let ctpop = 0x73e5_0606u128;
    assert_eq!(decode_model_ex(ctpop, 32, false, ALL), Some(Insn::Ctpop));
    assert_eq!(decode_model_ex(ctpop, 32, false, FEAT_MVI), None);
    // 世代ゲート。wh64 は EV56、wh64en は EV7 の追加。
    let wh64 = 0x6000_f800u128;
    let wh64en = 0x6000_fc00u128;
    assert_eq!(
        decode_model_ex(wh64, 32, false, FEAT_EV56),
        Some(Insn::Wh64)
    );
    assert_eq!(decode_model_ex(wh64, 32, false, FEAT_EV5), None);
    assert_eq!(
        decode_model_ex(wh64en, 32, false, FEAT_EV7),
        Some(Insn::Wh64en)
    );
    assert_eq!(decode_model_ex(wh64en, 32, false, FEAT_EV56), None);
}

#[test]
fn disasm_renders_mnemonic() {
    assert_eq!(disasm(Insn::Bis), "bis {ra}, {rb}, {rc}");
    assert_eq!(disasm(Insn::Ldq), "ldq {ra}, {disp16}({rb})");
    assert_eq!(disasm(Insn::CallPal), "call_pal {palfn}");
}
