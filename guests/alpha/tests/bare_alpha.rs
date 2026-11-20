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

// ---- 段階16-4: 実行の最小集合 ----

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::InterpExit;
use polyisa_guest_alpha::sem;
use polyisa_sem::Backend as _;

fn env() -> BareEnv {
    BareEnv::new(core::mem::size_of::<CpuState>())
}

fn gpr(env: &mut BareEnv, n: u8) -> u64 {
    env.backend.get(sem::Gpr(n).state())
}

/// `lda ra, disp(rb)`（op=001000）。
const fn lda(ra: u32, rb: u32, disp: u32) -> u32 {
    (0x08 << 26) | (ra << 21) | (rb << 16) | (disp & 0xffff)
}

#[test]
fn lda_loads_constant_from_r31() {
    let mut env = env();
    // lda r1, 42(r31)。
    let insn = dec(lda(1, 31, 42)).unwrap();
    let ok = env.step(|b| sem::exec(b, insn, lda(1, 31, 42), 0)).unwrap();
    assert!(ok);
    assert_eq!(gpr(&mut env, 1), 42);
}

#[test]
fn ldah_shifts_disp16() {
    let mut env = env();
    // ldah r1, 0x1234(r31) → r1 = 0x1234_0000。
    let word = (0x09 << 26) | (1 << 21) | (31 << 16) | 0x1234;
    let insn = dec(word).unwrap();
    let ok = env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    assert!(ok);
    assert_eq!(gpr(&mut env, 1), 0x1234_0000);
}

#[test]
fn ldah_scales_only_the_displacement() {
    let mut env = env();
    env.backend.set(sem::Gpr(2).state(), 0x5000);
    // ldah r1, 1(r2): 変位だけ <<16 して rb に足す → 0x5000+0x10000。
    let word = (0x09 << 26) | (1 << 21) | (2 << 16) | 1;
    let insn = dec(word).unwrap();
    let ok = env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    assert!(ok);
    assert_eq!(gpr(&mut env, 1), 0x1_5000);
}

#[test]
fn lda_writes_to_r31_are_dropped() {
    let mut env = env();
    // lda r31, 1(r31): r31 への書き込みは破棄される。
    let word = lda(31, 31, 1);
    let insn = dec(word).unwrap();
    let ok = env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    assert!(ok);
    assert_eq!(gpr(&mut env, 31), 0);
}

#[test]
fn br_links_and_jumps_forward() {
    let mut env = env();
    // br r1, +2 語先（disp21=2 → pc+4+8）。
    let word = (0x30 << 26) | (1 << 21) | 2;
    let insn = dec(word).unwrap();
    let ok = env.step(|b| sem::exec(b, insn, word, 0x1000)).unwrap();
    assert!(ok);
    assert_eq!(gpr(&mut env, 1), 0x1004);
    assert_eq!(env.backend.ctrl, polyisa_engine::interp::Ctrl::Jump(0x100c));
}

#[test]
fn ret_jumps_through_rb() {
    let mut env = env();
    env.backend.set(sem::Gpr(26).state(), 0x2222);
    // ret $31,($26),1（低2ビットはマスクされる）。検証済みの
    // 実エンコード 0x6bfa8001 と同じ、subcode=10・hint=1 を使う。
    let word = (0x1a << 26) | (26 << 16) | 0x8001;
    let insn = dec(word).unwrap();
    let ok = env.step(|b| sem::exec(b, insn, word, 0x1000)).unwrap();
    assert!(ok);
    assert_eq!(env.backend.ctrl, polyisa_engine::interp::Ctrl::Jump(0x2220));
}

#[test]
fn call_pal_raises_trap_with_palfn() {
    let mut env = env();
    // call_pal 0x83（callsys）。
    let word = 0x83u32;
    let insn = dec(word).unwrap();
    match env.step(|b| sem::exec::<_>(b, insn, word, 0)) {
        Err(InterpExit::Exception(e)) => {
            assert_eq!(e.kind, polyisa_sem::ExceptionKind::Trap);
            assert_eq!(e.code, 0x83);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn operate_insns_are_unimplemented_for_now() {
    let mut env = env();
    // bis $31,$31,$31 は段階16-5 の整数 Operate。ここでは false。
    let word = 0x47ff_041fu32;
    let insn = dec(word).unwrap();
    let ok = env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    assert!(!ok);
}
