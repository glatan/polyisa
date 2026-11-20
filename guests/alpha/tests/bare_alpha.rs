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
fn load_store_insns_are_unimplemented_for_now() {
    let mut env = env();
    // ldq $1,0($2) は段階16-7 の load/store。ここでは false。
    let word = 0xa402_0000u32;
    let insn = dec(word).unwrap();
    let ok = env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    assert!(!ok);
}

// ---- 段階16-5: 整数 Operate ----

/// OPERATE 形式の手エンコード（f は fn[11:5] の 7 ビット）。
const fn opr(op: u32, ra: u32, rb: u32, f: u32, rc: u32) -> u32 {
    (op << 26) | (ra << 21) | (rb << 16) | (f << 5) | rc
}

/// OPERATE リテラル形（bit12=1、桁 20-13 が 8 ビット即値）。
const fn opl(op: u32, ra: u32, lit: u32, f: u32, rc: u32) -> u32 {
    (op << 26) | (ra << 21) | (lit << 13) | (1 << 12) | (f << 5) | rc
}

/// 1 命令を実行する。戻り値は `exec` の受理可否。
fn run1(env: &mut BareEnv, word: u32) -> bool {
    let insn = dec(word).unwrap();
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap()
}

#[test]
fn operate_add_sub_and_scaled_forms() {
    let mut env = env();
    env.backend.set(sem::Gpr(1).state(), 10);
    env.backend.set(sem::Gpr(2).state(), 5);
    // addq r1,r2,r3 = 15（op=010000 f=0100000）。
    assert!(run1(&mut env, opr(0x10, 1, 2, 0x20, 3)));
    assert_eq!(gpr(&mut env, 3), 15);
    // addq r1,0x55,r4 = 95（リテラル形）。
    assert!(run1(&mut env, opl(0x10, 1, 0x55, 0x20, 4)));
    assert_eq!(gpr(&mut env, 4), 95);
    // subq r2,r1,r5 = 5-10 = -5。
    assert!(run1(&mut env, opr(0x10, 2, 1, 0x29, 5)));
    assert_eq!(gpr(&mut env, 5), -5i64 as u64);
    // s4addq r2,r1,r6 = 5*4+10 = 30。
    assert!(run1(&mut env, opr(0x10, 2, 1, 0x22, 6)));
    assert_eq!(gpr(&mut env, 6), 30);
    // s8subq r2,r1,r7 = 5*8-10 = 30。
    assert!(run1(&mut env, opr(0x10, 2, 1, 0x3b, 7)));
    assert_eq!(gpr(&mut env, 7), 30);
}

#[test]
fn operate_longword_results_are_sign_extended() {
    let mut env = env();
    env.backend.set(sem::Gpr(1).state(), 0x8000_0000);
    // addl r1,0,r2 → sext32(0x80000000) = 0xffffffff80000000。
    assert!(run1(&mut env, opl(0x10, 1, 0, 0x00, 2)));
    assert_eq!(gpr(&mut env, 2), 0xffff_ffff_8000_0000);
    // subl r31,1,r3 → sext32(-1) = 0xffffffffffffffff。
    assert!(run1(&mut env, opl(0x10, 31, 1, 0x09, 3)));
    assert_eq!(gpr(&mut env, 3), -1i64 as u64);
}

#[test]
fn operate_compares() {
    let mut env = env();
    env.backend.set(sem::Gpr(1).state(), 5);
    env.backend.set(sem::Gpr(2).state(), -1i64 as u64);
    // cmplt r2,0,r3 → -1 < 0 → 1（符号付き）。
    assert!(run1(&mut env, opl(0x10, 2, 0, 0x4d, 3)));
    assert_eq!(gpr(&mut env, 3), 1);
    // cmpult r2,r1,r4 → (unsigned)-1 >= 5 → 0。
    assert!(run1(&mut env, opr(0x10, 2, 1, 0x1d, 4)));
    assert_eq!(gpr(&mut env, 4), 0);
    // cmpeq r1,5,r5 → 1。
    assert!(run1(&mut env, opl(0x10, 1, 5, 0x2d, 5)));
    assert_eq!(gpr(&mut env, 5), 1);
    // cmpule r1,r2,r6 → 5 <= (u64)-1 → 1。
    assert!(run1(&mut env, opr(0x10, 1, 2, 0x3d, 6)));
    assert_eq!(gpr(&mut env, 6), 1);
    // cmple r1,0,r7 → 5 <= 0 → 0。
    assert!(run1(&mut env, opl(0x10, 1, 0, 0x6d, 7)));
    assert_eq!(gpr(&mut env, 7), 0);
}

#[test]
fn operate_cmpbge_byte_lanes() {
    let mut env = env();
    env.backend.set(sem::Gpr(1).state(), 0x0001_0203_0405_0607);
    env.backend.set(sem::Gpr(2).state(), 0x0706_0504_0302_0100);
    // cmpbge r1,r2,r3: バイト単位の unsigned 比較で下位4バイトのみ ge。
    assert!(run1(&mut env, opr(0x10, 1, 2, 0x0f, 3)));
    assert_eq!(gpr(&mut env, 3), 0x0f);
    // 同値同士は全バイト ge → 0xff。
    assert!(run1(&mut env, opr(0x10, 1, 1, 0x0f, 4)));
    assert_eq!(gpr(&mut env, 4), 0xff);
}

#[test]
fn operate_logic_and_cmov() {
    let mut env = env();
    env.backend.set(sem::Gpr(1).state(), 0x00ff_00ff_00ff_00ff);
    env.backend.set(sem::Gpr(2).state(), 0x0f0f_0f0f_0f0f_0f0f);
    // and r1,r2,r3 = 0x000f000f000f000f。
    assert!(run1(&mut env, opr(0x11, 1, 2, 0x00, 3)));
    assert_eq!(gpr(&mut env, 3), 0x000f_000f_000f_000f);
    // ornot r1,~r2 → r1 | ~r2 = 0xf0ff_f0ff_f0ff_f0ff。
    assert!(run1(&mut env, opr(0x11, 1, 2, 0x28, 4)));
    assert_eq!(gpr(&mut env, 4), 0xf0ff_f0ff_f0ff_f0ff);
    // eqv r1,r2 → ~(r1^r2)。
    assert!(run1(&mut env, opr(0x11, 1, 2, 0x48, 5)));
    assert_eq!(gpr(&mut env, 5), !0x0ff0_0ff0_0ff0_0ff0u64);
    // bic r1,r2 → r1 & ~r2 = 0x00f0_00f0_00f0_00f0。
    assert!(run1(&mut env, opr(0x11, 1, 2, 0x08, 6)));
    assert_eq!(gpr(&mut env, 6), 0x00f0_00f0_00f0_00f0);
    // cmoveq r1(≠0),r2,r7: 偽なので r7 は元値のまま。
    env.backend.set(sem::Gpr(7).state(), 0xdead_beef);
    assert!(run1(&mut env, opr(0x11, 1, 2, 0x24, 7)));
    assert_eq!(gpr(&mut env, 7), 0xdead_beef);
    // cmoveq r31(=0),r2,r8: 真 → r8 = r2。
    assert!(run1(&mut env, opr(0x11, 31, 2, 0x24, 8)));
    assert_eq!(gpr(&mut env, 8), 0x0f0f_0f0f_0f0f_0f0f);
    // cmovlbs r2(LSB=1),r1,r9 → r9 = r1。
    assert!(run1(&mut env, opr(0x11, 2, 1, 0x14, 9)));
    assert_eq!(gpr(&mut env, 9), 0x00ff_00ff_00ff_00ff);
    // cmovlbc r2(LSB=1),r1,r10 → 偽 → r10 保持。
    env.backend.set(sem::Gpr(10).state(), 0x1234);
    assert!(run1(&mut env, opr(0x11, 2, 1, 0x16, 10)));
    assert_eq!(gpr(&mut env, 10), 0x1234);
}

#[test]
fn operate_cmov_boundary_conditions() {
    let mut env = env();
    // ra=0: lt→偽、ge→真、le→真、gt→偽、ne→偽。
    env.backend.set(sem::Gpr(2).state(), 0xaaaa);
    env.backend.set(sem::Gpr(3).state(), 0xbbbb);
    assert!(run1(&mut env, opr(0x11, 31, 2, 0x44, 4))); // cmovlt 0 → 偽
    assert_eq!(gpr(&mut env, 4), 0);
    assert!(run1(&mut env, opr(0x11, 31, 2, 0x46, 5))); // cmovge 0 → 真
    assert_eq!(gpr(&mut env, 5), 0xaaaa);
    assert!(run1(&mut env, opr(0x11, 31, 2, 0x64, 6))); // cmovle 0 → 真
    assert_eq!(gpr(&mut env, 6), 0xaaaa);
    assert!(run1(&mut env, opr(0x11, 31, 2, 0x66, 7))); // cmovgt 0 → 偽
    assert_eq!(gpr(&mut env, 7), 0);
    assert!(run1(&mut env, opr(0x11, 31, 2, 0x26, 8))); // cmovne 0 → 偽
    assert_eq!(gpr(&mut env, 8), 0);
    // ra=i64::MIN: lt→真、ge→偽。
    env.backend.set(sem::Gpr(1).state(), i64::MIN as u64);
    assert!(run1(&mut env, opr(0x11, 1, 3, 0x44, 9))); // cmovlt → 真
    assert_eq!(gpr(&mut env, 9), 0xbbbb);
    env.backend.set(sem::Gpr(10).state(), 0xcccc);
    assert!(run1(&mut env, opr(0x11, 1, 3, 0x46, 10))); // cmovge → 偽
    assert_eq!(gpr(&mut env, 10), 0xcccc);
    // エイリアシング: cmovne r1,r3,r1（rc=ra、真 → r1=r3）。
    assert!(run1(&mut env, opr(0x11, 1, 3, 0x26, 1)));
    assert_eq!(gpr(&mut env, 1), 0xbbbb);
    // リテラル形の論理: and r1,0xff,r11。
    assert!(run1(&mut env, opl(0x11, 1, 0xff, 0x00, 11)));
    assert_eq!(gpr(&mut env, 11), 0xbb);
}

#[test]
fn operate_shifts() {
    let mut env = env();
    env.backend.set(sem::Gpr(1).state(), 0x0123_4567_89ab_cdef);
    env.backend.set(sem::Gpr(2).state(), 8);
    // srl r1,r2,r3 → >>8。
    assert!(run1(&mut env, opr(0x12, 1, 2, 0x34, 3)));
    assert_eq!(gpr(&mut env, 3), 0x0001_2345_6789_abcd);
    // sll r1,r2,r4 → <<8。
    assert!(run1(&mut env, opr(0x12, 1, 2, 0x39, 4)));
    assert_eq!(gpr(&mut env, 4), 0x2345_6789_abcd_ef00);
    // sra: 負数は符号維持。シフト量は 6 ビットにマスク（65→1）。
    env.backend.set(sem::Gpr(5).state(), -1i64 as u64);
    env.backend.set(sem::Gpr(6).state(), 65);
    assert!(run1(&mut env, opr(0x12, 5, 6, 0x3c, 7)));
    assert_eq!(gpr(&mut env, 7), -1i64 as u64);
    assert!(run1(&mut env, opr(0x12, 1, 6, 0x34, 8)));
    assert_eq!(gpr(&mut env, 8), 0x0123_4567_89ab_cdef >> 1);
    // シフト量 0 と 63。
    env.backend.set(sem::Gpr(9).state(), 0);
    env.backend.set(sem::Gpr(10).state(), 63);
    assert!(run1(&mut env, opr(0x12, 1, 9, 0x34, 11)));
    assert_eq!(gpr(&mut env, 11), 0x0123_4567_89ab_cdef);
    assert!(run1(&mut env, opr(0x12, 1, 10, 0x34, 12)));
    assert_eq!(gpr(&mut env, 12), 0x0123_4567_89ab_cdef >> 63);
}

#[test]
fn operate_zap_and_zapnot() {
    let mut env = env();
    env.backend.set(sem::Gpr(1).state(), 0x1122_3344_5566_7788);
    env.backend.set(sem::Gpr(2).state(), 0b1000_0001);
    // zapnot: マスクの立つバイト（0 と 7）だけ残す。
    assert!(run1(&mut env, opr(0x12, 1, 2, 0x31, 3)));
    assert_eq!(gpr(&mut env, 3), 0x1100_0000_0000_0088);
    // zap: マスクの立つバイトを消す。
    assert!(run1(&mut env, opr(0x12, 1, 2, 0x30, 4)));
    assert_eq!(gpr(&mut env, 4), 0x0022_3344_5566_7700);
    // リテラル形も同じマスク意味。
    assert!(run1(&mut env, opl(0x12, 1, 0b1000_0001, 0x31, 5)));
    assert_eq!(gpr(&mut env, 5), 0x1100_0000_0000_0088);
}

#[test]
fn operate_ext_ins_msk() {
    let mut env = env();
    // ARM の使用例に出る定数（バイトは下位から b8..b7）。
    env.backend.set(sem::Gpr(1).state(), 0xb7b6_b5b4_b3b2_b1b8);
    env.backend.set(sem::Gpr(2).state(), 5);
    // extbl r1,r2,r3 → バイト5 = 0xb5。
    assert!(run1(&mut env, opr(0x12, 1, 2, 0x06, 3)));
    assert_eq!(gpr(&mut env, 3), 0xb5);
    // extqh r1,r2,r4 → a << (64-40) = 0xb4b3b2b1b8000000。
    assert!(run1(&mut env, opr(0x12, 1, 2, 0x7a, 4)));
    assert_eq!(gpr(&mut env, 4), 0xb4b3_b2b1_b800_0000);
    // extqh pos=0 は全 64 ビットをそのまま返す。
    env.backend.set(sem::Gpr(5).state(), 0);
    assert!(run1(&mut env, opr(0x12, 1, 5, 0x7a, 6)));
    assert_eq!(gpr(&mut env, 6), 0xb7b6_b5b4_b3b2_b1b8);
    // insbl r1,r2,r7 → (a & 0xff) << 40 = 0xb8 << 40。
    assert!(run1(&mut env, opr(0x12, 1, 2, 0x0b, 7)));
    assert_eq!(gpr(&mut env, 7), 0x0000_b800_0000_0000);
    // mskbl r1,r2,r8 → バイト5を消す → 0xb7b600b4b3b2b1b8。
    assert!(run1(&mut env, opr(0x12, 1, 2, 0x02, 8)));
    assert_eq!(gpr(&mut env, 8), 0xb7b6_00b4_b3b2_b1b8);
    // mskqh r1,r2,r9 → pos=5 の折り返しで下位5バイトを消す。
    assert!(run1(&mut env, opr(0x12, 1, 2, 0x72, 9)));
    assert_eq!(gpr(&mut env, 9), 0xb7b6_b500_0000_0000);
    // リテラル形の位置指定も同じ意味（extbl r1,#1,r10 → byte1）。
    assert!(run1(&mut env, opl(0x12, 1, 1, 0x06, 10)));
    assert_eq!(gpr(&mut env, 10), 0xb1);
}

#[test]
fn operate_h_forms_boundary_positions() {
    let mut env = env();
    env.backend.set(sem::Gpr(1).state(), 0xb7b6_b5b4_b3b2_b1b8);
    // pos=0: ins_h/msk_h は「64 シフト」で全フィールドが前の語側に
    // 逃げるため 0 / 無変化（QEMU の二段シフトと同じ）。
    env.backend.set(sem::Gpr(2).state(), 0);
    // insqh r1,r2,r3: pos=0 → 0。
    assert!(run1(&mut env, opr(0x12, 1, 2, 0x77, 3)));
    assert_eq!(gpr(&mut env, 3), 0);
    // mskqh r1,r2,r4: pos=0 → 変化なし。
    assert!(run1(&mut env, opr(0x12, 1, 2, 0x72, 4)));
    assert_eq!(gpr(&mut env, 4), 0xb7b6_b5b4_b3b2_b1b8);
    // extqh r1,r2,r5: pos=0 は「a << 0」で全ビットそのまま。
    assert!(run1(&mut env, opr(0x12, 1, 2, 0x7a, 5)));
    assert_eq!(gpr(&mut env, 5), 0xb7b6_b5b4_b3b2_b1b8);
    // pos=7: insqh は a >> 8 でバイト7をバイト0へ（高位フィールドの
    // 折り返し部分）。
    env.backend.set(sem::Gpr(6).state(), 7);
    assert!(run1(&mut env, opr(0x12, 1, 6, 0x77, 7)));
    assert_eq!(gpr(&mut env, 7), 0x00b7_b6b5_b4b3_b2b1);
    // inswh pos=7 → (a & 0xffff) >> 8 = 0xb1（バイト1だけ残る）。
    assert!(run1(&mut env, opr(0x12, 1, 6, 0x57, 8)));
    assert_eq!(gpr(&mut env, 8), 0xb1);
    // mskwh pos=7 → マスク >>8 = 0xff でバイト0を消す。
    assert!(run1(&mut env, opr(0x12, 1, 6, 0x52, 9)));
    assert_eq!(gpr(&mut env, 9), 0xb7b6_b5b4_b3b2_b100);
    // extwh pos=7 → a<<8 の下位2バイト = 0xb800。
    assert!(run1(&mut env, opr(0x12, 1, 6, 0x5a, 10)));
    assert_eq!(gpr(&mut env, 10), 0xb800);
    // extwl r1,r6: pos=7 の下位2バイト抽出 = 0x00b7（バイト7のみ）。
    assert!(run1(&mut env, opr(0x12, 1, 6, 0x16, 11)));
    assert_eq!(gpr(&mut env, 11), 0xb7);
}

#[test]
fn operate_v_overflow_traps() {
    let mut env = env();
    env.backend.set(sem::Gpr(1).state(), i64::MAX as u64);
    // addq/v r1,1,r2 → 符号付きオーバーフロー → Trap(code=1)。
    let word = opl(0x10, 1, 1, 0x60, 2);
    let insn = dec(word).unwrap();
    match env.step(|b| sem::exec::<_>(b, insn, word, 0)) {
        Err(InterpExit::Exception(e)) => {
            assert_eq!(e.kind, polyisa_sem::ExceptionKind::Trap);
            assert_eq!(e.code, 1);
        }
        other => panic!("unexpected: {other:?}"),
    }
    // オーバーフロー時は rc を書かない。
    assert_eq!(gpr(&mut env, 2), 0);
    // 桁あふれなしなら普通に書く。
    env.backend.set(sem::Gpr(3).state(), 41);
    assert!(run1(&mut env, opl(0x10, 3, 1, 0x60, 4)));
    assert_eq!(gpr(&mut env, 4), 42);
    // subl/v: 0x80000000 - 1 → 32 ビットの範囲を出るので例外。
    env.backend.set(sem::Gpr(5).state(), 0xffff_ffff_8000_0000);
    let word = opl(0x10, 5, 1, 0x49, 6);
    let insn = dec(word).unwrap();
    assert!(matches!(
        env.step(|b| sem::exec::<_>(b, insn, word, 0)),
        Err(InterpExit::Exception(_))
    ));
    // subq/v の負方向: i64::MIN - 1 → アンダーフローで例外。
    env.backend.set(sem::Gpr(7).state(), i64::MIN as u64);
    let word = opl(0x10, 7, 1, 0x69, 8);
    let insn = dec(word).unwrap();
    assert!(matches!(
        env.step(|b| sem::exec::<_>(b, insn, word, 0)),
        Err(InterpExit::Exception(_))
    ));
    // addl/v: 32 ビット幅で見て溢れないなら通る（-1 + 1 = 0）。
    env.backend.set(sem::Gpr(9).state(), -1i64 as u64);
    assert!(run1(&mut env, opl(0x10, 9, 1, 0x40, 10)));
    assert_eq!(gpr(&mut env, 10), 0);
    // addl/v: 0x7fffffff + 1 → 32 ビットオーバーフローで例外。
    env.backend.set(sem::Gpr(11).state(), 0x7fff_ffff);
    let word = opl(0x10, 11, 1, 0x40, 12);
    let insn = dec(word).unwrap();
    assert!(matches!(
        env.step(|b| sem::exec::<_>(b, insn, word, 0)),
        Err(InterpExit::Exception(_))
    ));
}

#[test]
fn operate_scaled_longword_sign_extends() {
    let mut env = env();
    // s4addl r1,r31,r2: r1=0x40000000 → 0x40000000*4 = 0x100000000
    // の低 32 ビットは 0 → 符号拡張で 0。
    env.backend.set(sem::Gpr(1).state(), 0x4000_0000);
    assert!(run1(&mut env, opr(0x10, 1, 31, 0x02, 2)));
    assert_eq!(gpr(&mut env, 2), 0);
    // s8addl r1,r31,r3: r1=0x30000000 → *8 = 0x180000000 →
    // 低32 = 0x80000000 → 符号拡張で 0xffffffff80000000。
    env.backend.set(sem::Gpr(1).state(), 0x3000_0000);
    assert!(run1(&mut env, opr(0x10, 1, 31, 0x12, 3)));
    assert_eq!(gpr(&mut env, 3), 0xffff_ffff_8000_0000);
    // rc への書き込み先が r31 でも例外なく受理される。
    assert!(run1(&mut env, opr(0x10, 1, 31, 0x02, 31)));
    // rc/rs の ra=r31: 値は捨てるがフラグ副作用は残る。
    assert!(run1(&mut env, 0x63e0_f000)); // rs r31
    assert_eq!(env.backend.get(sem::rx_flag_ref()), 1);
    assert!(run1(&mut env, 0x63e0_e000)); // rc r31
    assert_eq!(env.backend.get(sem::rx_flag_ref()), 0);
}

#[test]
fn misc_nops_and_counters() {
    let mut env = env();
    // mb/wmb/trapb/excb/fetch 系は何もしない。
    for w in [
        0x6000_4000u32, // mb
        0x6000_4400,    // wmb
        0x6000_0000,    // trapb
        0x6000_0400,    // excb
        0x6000_8000,    // fetch
        0x6000_f800,    // wh64（EV56+）
    ] {
        assert!(dec(w).is_some(), "decode {w:#x}");
        assert!(run1(&mut env, w));
    }
    // rpcc r1: cycle_ref の値を読む。
    env.backend.set(sem::cycle_ref(), 123);
    assert!(run1(&mut env, 0x6020_c000));
    assert_eq!(gpr(&mut env, 1), 123);
    // rs r2: rx_flag を読んで 1 にする。rc r3 は 1 を読んで 0 にする。
    assert!(run1(&mut env, 0x6040_f000));
    assert_eq!(env.backend.get(sem::rx_flag_ref()), 1);
    assert!(run1(&mut env, 0x6060_e000));
    assert_eq!(gpr(&mut env, 3), 1);
    assert_eq!(env.backend.get(sem::rx_flag_ref()), 0);
}
