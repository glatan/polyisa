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
    // minub8 $5,$6,$7（MVI。0x1C/f=0x3a）。
    let minub8 = (0x1cu128 << 26) | (5 << 21) | (6 << 16) | (0x3a << 5) | 7;
    assert_eq!(decode_model_ex(minub8, 32, false, ALL), Some(Insn::Minub8));
    assert_eq!(decode_model_ex(minub8, 32, false, FEAT_CIX), None);
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
fn unimplemented_insns_return_false() {
    let mut env = env();
    // VAX F 形式の ldf f31,0(r31) は段階16-9 でも未実装（VAX
    // F/G 形式は対象外）。ここでは false。
    let word = (0x20u32 << 26) | (31 << 21) | (31 << 16);
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
    run1_at(env, word, 0)
}

/// pc を指定して 1 命令を実行する。
fn run1_at(env: &mut BareEnv, word: u32, pc: u64) -> bool {
    let insn = dec(word).unwrap();
    env.step(|b| sem::exec(b, insn, word, pc)).unwrap()
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
    // pos=0: ins_h/msk_h は「64 ビットシフト」で全フィールドが語外に
    // 逃げるため 0 / 無変化（ARM §4.6.3/§4.6.4 の byte_loc=64）。
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
    // オーバーフロー時も真値の下位 64 ビットは rc に書かれる
    // （ARM §4.4.3）。
    assert_eq!(gpr(&mut env, 2), 0x8000_0000_0000_0000);
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

// ---- 段階16-6: 乗算と拡張 ----

/// 0x1C の 1 入力形（FOPRZ。ra 桁は不使用 → 31 を置く）。
const fn oprz(ra: u32, rb: u32, f: u32, rc: u32) -> u32 {
    opr(0x1c, ra, rb, f, rc)
}

#[test]
fn operate_mul_family() {
    let mut env = env();
    env.backend.set(sem::Gpr(1).state(), 7);
    env.backend.set(sem::Gpr(2).state(), 6);
    // mull r1,r2,r3 = 42（op=0x13 f=0x00）。
    assert!(run1(&mut env, opr(0x13, 1, 2, 0x00, 3)));
    assert_eq!(gpr(&mut env, 3), 42);
    // mulq r1,r2,r4 = 42。
    assert!(run1(&mut env, opr(0x13, 1, 2, 0x20, 4)));
    assert_eq!(gpr(&mut env, 4), 42);
    // mull: 積の低 32 だけを符号拡張（0x8000_0000*2 → 0）。
    env.backend.set(sem::Gpr(5).state(), 0x8000_0000);
    assert!(run1(&mut env, opl(0x13, 5, 2, 0x00, 6)));
    assert_eq!(gpr(&mut env, 6), 0);
    // umulh: 0xffffffffffffffff * 同 = hi 0xfffffffffffffffe。
    env.backend.set(sem::Gpr(7).state(), -1i64 as u64);
    assert!(run1(&mut env, opr(0x13, 7, 7, 0x30, 8)));
    assert_eq!(gpr(&mut env, 8), 0xffff_ffff_ffff_fffe);
    // mull/v: 32 ビットに収まれば通す、溢れれば Trap(code=1)。
    env.backend.set(sem::Gpr(9).state(), 0x1_0000);
    assert!(run1(&mut env, opl(0x13, 9, 0x10, 0x40, 10)));
    assert_eq!(gpr(&mut env, 10), 0x10_0000);
    env.backend.set(sem::Gpr(11).state(), 0x8000_0000);
    let word = opl(0x13, 11, 2, 0x40, 12);
    let insn = dec(word).unwrap();
    assert!(matches!(
        env.step(|b| sem::exec::<_>(b, insn, word, 0)),
        Err(InterpExit::Exception(_))
    ));
    // mulq/v: i64::MAX*2 は溢れる、3*7 は通る。
    env.backend.set(sem::Gpr(13).state(), i64::MAX as u64);
    let word = opl(0x13, 13, 2, 0x60, 14);
    let insn = dec(word).unwrap();
    assert!(matches!(
        env.step(|b| sem::exec::<_>(b, insn, word, 0)),
        Err(InterpExit::Exception(_))
    ));
    assert!(run1(&mut env, opl(0x13, 1, 3, 0x60, 15)));
    assert_eq!(gpr(&mut env, 15), 21);
}

#[test]
fn operate_extension_unary() {
    let mut env = env();
    // sextb/sextw（BWX、f=0x00/0x01）。ra 桁は不使用。
    env.backend.set(sem::Gpr(1).state(), 0x80);
    assert!(run1(&mut env, oprz(31, 1, 0x00, 2)));
    assert_eq!(gpr(&mut env, 2), -128i64 as u64);
    env.backend.set(sem::Gpr(1).state(), 0x8000);
    assert!(run1(&mut env, oprz(31, 1, 0x01, 3)));
    assert_eq!(gpr(&mut env, 3), -32768i64 as u64);
    // ctpop/ctlz/cttz（CIX）。
    env.backend.set(sem::Gpr(1).state(), -1i64 as u64);
    assert!(run1(&mut env, oprz(31, 1, 0x30, 4)));
    assert_eq!(gpr(&mut env, 4), 64);
    env.backend.set(sem::Gpr(1).state(), 1);
    assert!(run1(&mut env, oprz(31, 1, 0x32, 5)));
    assert_eq!(gpr(&mut env, 5), 63);
    env.backend.set(sem::Gpr(1).state(), i64::MIN as u64);
    assert!(run1(&mut env, oprz(31, 1, 0x33, 6)));
    assert_eq!(gpr(&mut env, 6), 63);
    // 0 の端は 64。
    env.backend.set(sem::Gpr(1).state(), 0);
    assert!(run1(&mut env, oprz(31, 1, 0x32, 7)));
    assert_eq!(gpr(&mut env, 7), 64);
    assert!(run1(&mut env, oprz(31, 1, 0x33, 8)));
    assert_eq!(gpr(&mut env, 8), 64);
    assert!(run1(&mut env, oprz(31, 1, 0x30, 9)));
    assert_eq!(gpr(&mut env, 9), 0);
    // ctlz の中間値（0x0100.. → 先頭ゼロ 7）。
    env.backend.set(sem::Gpr(1).state(), 0x0100_0000_0000_0000);
    assert!(run1(&mut env, oprz(31, 1, 0x32, 10)));
    assert_eq!(gpr(&mut env, 10), 7);
    // sextb/sextw のリテラル形（ARM §4.6.5 の `SEXTx #b.ib` 形）。
    // sextb #0x80 → -128、sextw #0x80 → +128。
    // (0x1c<<26)|(31<<21)|(0x80<<13)|(1<<12)|(f<<5)|rc。
    assert_eq!(dec(0x73f0_1005u32), Some(Insn::SextbI));
    assert!(run1(&mut env, 0x73f0_1005));
    assert_eq!(gpr(&mut env, 5), -128i64 as u64);
    assert_eq!(dec(0x73f0_1026u32), Some(Insn::SextwI));
    assert!(run1(&mut env, 0x73f0_1026));
    assert_eq!(gpr(&mut env, 6), 0x80);
}

#[test]
fn operate_mvi_pack_and_minmax() {
    let mut env = env();
    // unpkbw: バイト 0-3 → ワード 0-3。
    env.backend.set(sem::Gpr(1).state(), 0xdead_beef);
    assert!(run1(&mut env, oprz(31, 1, 0x34, 2)));
    assert_eq!(gpr(&mut env, 2), 0x00de_00ad_00be_00ef);
    // pkwb: その逆。
    assert!(run1(&mut env, oprz(31, 2, 0x36, 3)));
    assert_eq!(gpr(&mut env, 3), 0xdead_beef);
    // unpkbl: バイト 0 → ロング0、バイト1 → ロング1。
    env.backend.set(sem::Gpr(1).state(), 0xbeef);
    assert!(run1(&mut env, oprz(31, 1, 0x35, 4)));
    assert_eq!(gpr(&mut env, 4), 0x0000_00be_0000_00ef);
    // pklb: その逆。
    assert!(run1(&mut env, oprz(31, 4, 0x37, 5)));
    assert_eq!(gpr(&mut env, 5), 0xbeef);
    // perr: バイトごとの絶対差の和。
    env.backend.set(sem::Gpr(1).state(), 0);
    env.backend.set(sem::Gpr(6).state(), 0x0102_0304_0506_0708);
    assert!(run1(&mut env, opr(0x1c, 1, 6, 0x31, 7)));
    assert_eq!(gpr(&mut env, 7), 36);
    // minub8: 0 と全1の min → 0。
    env.backend.set(sem::Gpr(6).state(), -1i64 as u64);
    assert!(run1(&mut env, opr(0x1c, 1, 6, 0x3a, 8)));
    assert_eq!(gpr(&mut env, 8), 0);
    // minsb8: 全-1 と 1 の符号付き min → -1。
    env.backend.set(sem::Gpr(9).state(), 0x0101_0101_0101_0101);
    assert!(run1(&mut env, opr(0x1c, 6, 9, 0x38, 10)));
    assert_eq!(gpr(&mut env, 10), -1i64 as u64);
    // minsw4: ワード単位の符号付き min。
    env.backend.set(sem::Gpr(11).state(), 0x8000_8000_8000_8000);
    env.backend.set(sem::Gpr(12).state(), 0x0001_0001_0001_0001);
    assert!(run1(&mut env, opr(0x1c, 11, 12, 0x39, 13)));
    assert_eq!(gpr(&mut env, 13), 0x8000_8000_8000_8000);
    // maxuw4: ワード単位の unsigned max。
    env.backend.set(sem::Gpr(14).state(), 0xffff_0000_ffff_0000);
    env.backend.set(sem::Gpr(15).state(), 0x0000_ffff_0000_ffff);
    assert!(run1(&mut env, opr(0x1c, 14, 15, 0x3d, 16)));
    assert_eq!(gpr(&mut env, 16), 0xffff_ffff_ffff_ffff);
    // maxsb8: 符号付きバイト max。0x80..(-1 各バイト) vs 0x01.. → 1。
    env.backend.set(sem::Gpr(18).state(), 0x8080_8080_8080_8080);
    assert!(run1(&mut env, opr(0x1c, 9, 18, 0x3e, 19)));
    assert_eq!(gpr(&mut env, 19), 0x0101_0101_0101_0101);
    // maxsw4: 符号付きワード max。0x7fff 各ワード vs 0xffff(-1) 各
    // ワード → 0x7fff 側。
    env.backend.set(sem::Gpr(20).state(), 0x7fff_7fff_7fff_7fff);
    assert!(run1(&mut env, opr(0x1c, 20, 6, 0x3f, 21)));
    assert_eq!(gpr(&mut env, 21), 0x7fff_7fff_7fff_7fff);
    // minuw4: unsigned ワード min。0x0001 各ワード vs 0xffff 各
    // ワード → 0x0001 側。
    env.backend.set(sem::Gpr(22).state(), 0xffff_ffff_ffff_ffff);
    assert!(run1(&mut env, opr(0x1c, 12, 22, 0x3b, 23)));
    assert_eq!(gpr(&mut env, 23), 0x0001_0001_0001_0001);
    // maxub8: unsigned バイト max。0x80.. vs 0x01.. → 0x80 側。
    assert!(run1(&mut env, opr(0x1c, 9, 18, 0x3c, 24)));
    assert_eq!(gpr(&mut env, 24), 0x8080_8080_8080_8080);
    // リテラル形: minub8 r1(0),0x55,r17 → 0。
    assert!(run1(&mut env, opl(0x1c, 1, 0x55, 0x3a, 17)));
    assert_eq!(gpr(&mut env, 17), 0);
}

// ---- 段階16-7: load/store ----

/// メモリ形式（opcode, ra, disp(rb)）。
const fn memw(op: u32, ra: u32, rb: u32, disp: u32) -> u32 {
    (op << 26) | (ra << 21) | (rb << 16) | (disp & 0xffff)
}

#[test]
fn load_store_roundtrip() {
    let mut env = env();
    env.map_rw(0x1_0000, 2).unwrap();
    env.backend.set(sem::Gpr(1).state(), 0x1_0008);
    // stq r2,0(r1); ldq r3,0(r1)。
    env.backend.set(sem::Gpr(2).state(), 0x1122_3344_5566_7788);
    assert!(run1(&mut env, memw(0x2d, 2, 1, 0)));
    assert!(run1(&mut env, memw(0x29, 3, 1, 0)));
    assert_eq!(gpr(&mut env, 3), 0x1122_3344_5566_7788);
    // stl + ldl: ldl は符号拡張して返す。
    env.backend.set(sem::Gpr(4).state(), 0x8000_0000);
    assert!(run1(&mut env, memw(0x2c, 4, 1, 0xfff8)));
    assert!(run1(&mut env, memw(0x28, 5, 1, 0xfff8)));
    assert_eq!(gpr(&mut env, 5), 0xffff_ffff_8000_0000);
    // stb/ldbu・stw/ldwu（BWX）。負 displacement も試す。
    assert!(run1(&mut env, memw(0x0e, 4, 1, 0xffff)));
    assert!(run1(&mut env, memw(0x0a, 6, 1, 0xffff)));
    assert_eq!(gpr(&mut env, 6), 0);
    env.backend.set(sem::Gpr(7).state(), 0xcafe);
    assert!(run1(&mut env, memw(0x0d, 7, 1, 0xfffe)));
    assert!(run1(&mut env, memw(0x0c, 8, 1, 0xfffe)));
    assert_eq!(gpr(&mut env, 8), 0xcafe);
}

#[test]
fn ldq_u_stq_u_mask_address() {
    let mut env = env();
    env.map_rw(0x1_0000, 1).unwrap();
    // 非整列の実効アドレスでも & ~7 に丸めて整列 quad アクセス。
    env.backend.set(sem::Gpr(1).state(), 0x1_0003);
    env.backend.set(sem::Gpr(2).state(), 0xaabb_ccdd_eeff_0011);
    assert!(run1(&mut env, memw(0x0f, 2, 1, 0)));
    assert!(run1(&mut env, memw(0x0b, 3, 1, 0)));
    assert_eq!(gpr(&mut env, 3), 0xaabb_ccdd_eeff_0011);
    // 整列 ldq を同じ番地（非整列指定）に当てると整列例外。
    let word = memw(0x29, 4, 1, 0);
    let insn = dec(word).unwrap();
    assert!(matches!(
        env.step(|b| sem::exec::<_>(b, insn, word, 0)),
        Err(InterpExit::Exception(_))
    ));
    // ra=31 宛ての load は UNOP — 未写像の番地でも止まらない。
    env.backend.set(sem::Gpr(9).state(), 0x5555_0000);
    assert!(run1(&mut env, memw(0x0b, 31, 9, 0)));
    assert!(run1(&mut env, memw(0x29, 31, 9, 0)));
}

#[test]
fn load_locked_store_conditional() {
    let mut env = env();
    env.map_rw(0x1_0000, 1).unwrap();
    env.backend.set(sem::Gpr(1).state(), 0x1_0000);
    env.backend.set(sem::Gpr(2).state(), 0xdead_beef);
    assert!(run1(&mut env, memw(0x2d, 2, 1, 0)));
    // ldq_l → stq_c（同じ番地）は成功して 1。
    assert!(run1(&mut env, memw(0x2b, 3, 1, 0)));
    assert_eq!(gpr(&mut env, 3), 0xdead_beef);
    env.backend.set(sem::Gpr(4).state(), 42);
    assert!(run1(&mut env, memw(0x2f, 4, 1, 0)));
    assert_eq!(gpr(&mut env, 4), 1);
    assert!(run1(&mut env, memw(0x29, 5, 1, 0)));
    assert_eq!(gpr(&mut env, 5), 42);
    // 予約なしの stq_c は失敗して 0。番地も書かれない。
    env.backend.set(sem::Gpr(6).state(), 77);
    assert!(run1(&mut env, memw(0x2f, 6, 1, 0)));
    assert_eq!(gpr(&mut env, 6), 0);
    assert!(run1(&mut env, memw(0x29, 7, 1, 0)));
    assert_eq!(gpr(&mut env, 7), 42);
    // ldl_l/stl_c のペアも同様（ldl_l は符号拡張）。
    assert!(run1(&mut env, memw(0x2a, 8, 1, 0)));
    assert_eq!(gpr(&mut env, 8), 42);
    env.backend.set(sem::Gpr(9).state(), 0x8000_0000);
    assert!(run1(&mut env, memw(0x2e, 9, 1, 0)));
    assert_eq!(gpr(&mut env, 9), 1);
    assert!(run1(&mut env, memw(0x28, 10, 1, 0)));
    assert_eq!(gpr(&mut env, 10), 0xffff_ffff_8000_0000);
    // 予約なしの stl_c も 0 を返して書かない。
    env.backend.set(sem::Gpr(11).state(), 7);
    assert!(run1(&mut env, memw(0x2e, 11, 1, 0)));
    assert_eq!(gpr(&mut env, 11), 0);
    // ld*_l→st*_c の間の自分の store でも予約は解除される
    // （interp バックエンドの規約）。
    assert!(run1(&mut env, memw(0x2b, 12, 1, 0)));
    assert!(run1(&mut env, memw(0x2d, 2, 1, 0)));
    env.backend.set(sem::Gpr(13).state(), 1);
    assert!(run1(&mut env, memw(0x2f, 13, 1, 0)));
    assert_eq!(gpr(&mut env, 13), 0);
}

// ---- 段階16-8: 条件分岐 ----

/// 分岐形式（op, ra, disp21）。
const fn brw(op: u32, ra: u32, disp21: u32) -> u32 {
    (op << 26) | (ra << 21) | (disp21 & 0x1fffff)
}

#[test]
fn integer_conditional_branches() {
    let mut env = env();
    // beq r1=0,+1 → pc+4+4 = pc+8 に飛ぶ。ra にリンクは書かない。
    env.backend.set(sem::Gpr(1).state(), 0);
    assert!(run1_at(&mut env, brw(0x39, 1, 1), 0x1000));
    assert_eq!(env.pc, 0x1008);
    assert_eq!(gpr(&mut env, 1), 0);
    // beq r31 は常に真。
    env.pc = 0;
    assert!(run1_at(&mut env, brw(0x39, 31, 1), 0x1000));
    assert_eq!(env.pc, 0x1008);
    // 偽側は素通し（env.pc は変わらない）。リンクも書かない。
    env.pc = 0;
    env.backend.set(sem::Gpr(2).state(), 1);
    assert!(run1_at(&mut env, brw(0x39, 2, 1), 0x1000));
    assert_eq!(env.pc, 0);
    assert_eq!(gpr(&mut env, 2), 1);
    // bne、負 displacement（disp=-2 → pc+4-8 = pc-4）。
    env.backend.set(sem::Gpr(3).state(), 5);
    assert!(run1_at(&mut env, brw(0x3d, 3, 0x1f_fffe), 0x2000));
    assert_eq!(env.pc, 0x1ffc);
    // 符号条件: -1 は lt/le/ge/gt をそれぞれ真/真/偽/偽にする。
    env.pc = 0;
    env.backend.set(sem::Gpr(4).state(), -1i64 as u64);
    assert!(run1_at(&mut env, brw(0x3a, 4, 1), 0x1000));
    assert_eq!(env.pc, 0x1008);
    env.pc = 0;
    assert!(run1_at(&mut env, brw(0x3b, 4, 1), 0x1000));
    assert_eq!(env.pc, 0x1008);
    env.pc = 0;
    assert!(run1_at(&mut env, brw(0x3e, 4, 1), 0x1000));
    assert_eq!(env.pc, 0);
    env.pc = 0;
    assert!(run1_at(&mut env, brw(0x3f, 4, 1), 0x1000));
    assert_eq!(env.pc, 0);
    // blbc/blbs は最下位ビット。
    env.backend.set(sem::Gpr(5).state(), 2);
    env.pc = 0;
    assert!(run1_at(&mut env, brw(0x38, 5, 1), 0x1000));
    assert_eq!(env.pc, 0x1008);
    env.pc = 0;
    assert!(run1_at(&mut env, brw(0x3c, 5, 1), 0x1000));
    assert_eq!(env.pc, 0);
    env.backend.set(sem::Gpr(5).state(), 3);
    env.pc = 0;
    assert!(run1_at(&mut env, brw(0x3c, 5, 1), 0x1000));
    assert_eq!(env.pc, 0x1008);
}

#[test]
fn fp_conditional_branches() {
    let mut env = env();
    // fbeq: +0.0 → 真、-0.0 → 真（符号桁を除いて比べる）、1.0 → 偽。
    env.pc = 0;
    env.backend.set(sem::Fpr(1).state(), 0);
    assert!(run1_at(&mut env, brw(0x31, 1, 1), 0x1000));
    assert_eq!(env.pc, 0x1008);
    env.pc = 0;
    env.backend.set(sem::Fpr(1).state(), i64::MIN as u64); // -0.0
    assert!(run1_at(&mut env, brw(0x31, 1, 1), 0x1000));
    assert_eq!(env.pc, 0x1008);
    env.pc = 0;
    env.backend.set(sem::Fpr(1).state(), 0x3ff0_0000_0000_0000); // +1.0
    assert!(run1_at(&mut env, brw(0x31, 1, 1), 0x1000));
    assert_eq!(env.pc, 0);
    // fbne: -0.0 → 偽、1.0 → 真。
    env.backend.set(sem::Fpr(1).state(), i64::MIN as u64);
    assert!(run1_at(&mut env, brw(0x35, 1, 1), 0x1000));
    assert_eq!(env.pc, 0);
    env.backend.set(sem::Fpr(1).state(), 0x3ff0_0000_0000_0000);
    env.pc = 0;
    assert!(run1_at(&mut env, brw(0x35, 1, 1), 0x1000));
    assert_eq!(env.pc, 0x1008);
    // fblt: -0.0 → 偽（+0.0 に畳む）、-1.0 → 真。
    env.backend.set(sem::Fpr(1).state(), i64::MIN as u64);
    env.pc = 0;
    assert!(run1_at(&mut env, brw(0x32, 1, 1), 0x1000));
    assert_eq!(env.pc, 0);
    env.backend.set(sem::Fpr(1).state(), 0xbff0_0000_0000_0000); // -1.0
    env.pc = 0;
    assert!(run1_at(&mut env, brw(0x32, 1, 1), 0x1000));
    assert_eq!(env.pc, 0x1008);
    // fble: -0.0 は「0 以下」→ 真。fbgT: -0.0 → 偽。
    env.backend.set(sem::Fpr(1).state(), i64::MIN as u64);
    env.pc = 0;
    assert!(run1_at(&mut env, brw(0x33, 1, 1), 0x1000));
    assert_eq!(env.pc, 0x1008);
    env.pc = 0;
    assert!(run1_at(&mut env, brw(0x37, 1, 1), 0x1000));
    assert_eq!(env.pc, 0);
    // fbge: -0.0 → 真、-1.0 → 偽。
    env.backend.set(sem::Fpr(1).state(), i64::MIN as u64);
    env.pc = 0;
    assert!(run1_at(&mut env, brw(0x36, 1, 1), 0x1000));
    assert_eq!(env.pc, 0x1008);
    env.backend.set(sem::Fpr(1).state(), 0xbff0_0000_0000_0000);
    env.pc = 0;
    assert!(run1_at(&mut env, brw(0x36, 1, 1), 0x1000));
    assert_eq!(env.pc, 0);
    // f31 は +0.0 を読む → fbeq 真。
    env.pc = 0;
    assert!(run1_at(&mut env, brw(0x31, 31, 1), 0x1000));
    assert_eq!(env.pc, 0x1008);
    // NaN の扱いはビット単位（IEEE 比較ではない）。負 NaN は負の
    // ビット列 → fblt/fble 真。正 NaN → fbge/fbgt 真。
    env.backend.set(sem::Fpr(1).state(), 0xfff8_0000_0000_0000); // -NaN
    env.pc = 0;
    assert!(run1_at(&mut env, brw(0x32, 1, 1), 0x1000));
    assert_eq!(env.pc, 0x1008);
    env.pc = 0;
    assert!(run1_at(&mut env, brw(0x33, 1, 1), 0x1000));
    assert_eq!(env.pc, 0x1008);
    env.backend.set(sem::Fpr(1).state(), 0x7ff8_0000_0000_0000); // +NaN
    env.pc = 0;
    assert!(run1_at(&mut env, brw(0x36, 1, 1), 0x1000));
    assert_eq!(env.pc, 0x1008);
    env.pc = 0;
    assert!(run1_at(&mut env, brw(0x37, 1, 1), 0x1000));
    assert_eq!(env.pc, 0x1008);
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

// ---- 段階16-9: 浮動小数点 ----

/// FP レジスタの読み出し（内部表現のまま）。
fn fpr(env: &mut BareEnv, n: u8) -> u64 {
    env.backend.get(sem::Fpr(n).state())
}

/// FP OPERATE 3 項形（fpfn は fn[10:0] 全体。bits 15-5）。
const fn fop3(op: u32, fa: u32, fb: u32, fpfn: u32, fc: u32) -> u32 {
    (op << 26) | (fa << 21) | (fb << 16) | (fpfn << 5) | fc
}

/// FP OPERATE 2 項形（fa 桁は 31 固定）。
const fn fop2(op: u32, fb: u32, fpfn: u32, fc: u32) -> u32 {
    (op << 26) | (31 << 21) | (fb << 16) | (fpfn << 5) | fc
}

/// 整数→FP 転送形（FITF。rb 桁は 31 固定）。
const fn fitf(ra: u32, fn11: u32, fc: u32) -> u32 {
    (0x14 << 26) | (ra << 21) | (31 << 16) | (fn11 << 5) | fc
}

/// FP→整数転送形（FFTI。rb 桁は 31 固定）。
const fn ffti(fa: u32, fn11: u32, rc: u32) -> u32 {
    (0x1c << 26) | (fa << 21) | (31 << 16) | (fn11 << 5) | rc
}

// S 形式内部表現の定数（f32 の 1.0/2.0/3.0/42.0）。
const S_ONE: u64 = 0x3ff0_0000_0000_0000;
const S_TWO: u64 = 0x4000_0000_0000_0000;
const S_THREE: u64 = 0x4008_0000_0000_0000;
const S_42: u64 = 0x4045_0000_0000_0000;
// T 形式は生の f64 ビット列。
const T_ONE: u64 = 0x3ff0_0000_0000_0000;
const T_TWO: u64 = 0x4000_0000_0000_0000;
const T_THREE: u64 = 0x4008_0000_0000_0000;
const T_42: u64 = 0x4045_0000_0000_0000;
const T_NAN: u64 = 0x7ff8_0000_0000_0000;
/// cmpt* の真値（f64 の 2.0）。
const CMP_TRUE: u64 = 0x4000_0000_0000_0000;

#[test]
fn fp_load_store_t_roundtrip() {
    let mut env = env();
    env.map_rw(0x1_0000, 2).unwrap();
    env.backend.set(sem::Gpr(1).state(), 0x1_0008);
    env.backend.set(sem::Fpr(2).state(), 0x1122_3344_5566_7788);
    // stt f2,0(r1); ldt f3,0(r1) — 生の 64 ビット転送。
    assert!(run1(&mut env, memw(0x27, 2, 1, 0)));
    assert!(run1(&mut env, memw(0x23, 3, 1, 0)));
    assert_eq!(fpr(&mut env, 3), 0x1122_3344_5566_7788);
    // 整数側からも同じビット列が見える。
    assert!(run1(&mut env, memw(0x29, 5, 1, 0)));
    assert_eq!(gpr(&mut env, 5), 0x1122_3344_5566_7788);
    // stt してから ldt で戻す。負 displacement も試す。
    env.backend.set(sem::Fpr(4).state(), T_ONE);
    assert!(run1(&mut env, memw(0x27, 4, 1, 0xfff8)));
    assert!(run1(&mut env, memw(0x23, 6, 1, 0xfff8)));
    assert_eq!(fpr(&mut env, 6), T_ONE);
}

#[test]
fn fp_load_store_s_roundtrip() {
    let mut env = env();
    env.map_rw(0x1_0000, 1).unwrap();
    env.backend.set(sem::Gpr(1).state(), 0x1_0000);
    // f32 の 1.0 (0x3f800000) を lds で読むと S 内部表現になる。
    env.backend.set(sem::Gpr(2).state(), 0x3f80_0000);
    assert!(run1(&mut env, memw(0x2c, 2, 1, 0))); // stl
    assert!(run1(&mut env, memw(0x22, 3, 1, 0))); // lds
    assert_eq!(fpr(&mut env, 3), S_ONE);
    // sts はメモリに f32 ビット列を書き戻す。
    env.backend.set(sem::Fpr(4).state(), S_TWO);
    assert!(run1(&mut env, memw(0x26, 4, 1, 0))); // sts
    assert!(run1(&mut env, memw(0x28, 5, 1, 0))); // ldl（符号拡張）
    assert_eq!(gpr(&mut env, 5), 0x4000_0000);
    // lds f31,0(r1) は UNOP/prefetch でメモリを読まない。
    assert!(run1(&mut env, memw(0x22, 31, 31, 0)));
}

#[test]
fn fp_arith_s_and_t() {
    let mut env = env();
    // adds f1,f2,f3: 1.0 + 2.0 = 3.0。無修飾の fn11 は rm bits=10
    // （/n=最近接偶数）なので基本 op + 0x080。
    env.backend.set(sem::Fpr(1).state(), S_ONE);
    env.backend.set(sem::Fpr(2).state(), S_TWO);
    assert!(run1(&mut env, fop3(0x16, 1, 2, 0x080, 3)));
    assert_eq!(fpr(&mut env, 3), S_THREE);
    // subs: 3.0 - 1.0 = 2.0（fn=0x081）。
    env.backend.set(sem::Fpr(4).state(), S_THREE);
    assert!(run1(&mut env, fop3(0x16, 4, 1, 0x081, 5)));
    assert_eq!(fpr(&mut env, 5), S_TWO);
    // muls: 2.0 * 3.0 = 6.0 → f32 6.0=0x40c00000 → sreg。
    assert!(run1(&mut env, fop3(0x16, 2, 4, 0x082, 6)));
    assert_eq!(fpr(&mut env, 6), 0x4018_0000_0000_0000);
    // divs: 3.0 / 2.0 = 1.5 → f32 0x3fc00000 → sreg 0x3ff8...。
    assert!(run1(&mut env, fop3(0x16, 4, 2, 0x083, 7)));
    assert_eq!(fpr(&mut env, 7), 0x3ff8_0000_0000_0000);
    // addt/subt/mult/divt は生 f64 で同じ値を通す。
    env.backend.set(sem::Fpr(8).state(), T_ONE);
    env.backend.set(sem::Fpr(9).state(), T_TWO);
    assert!(run1(&mut env, fop3(0x16, 8, 9, 0x0a0, 10)));
    assert_eq!(fpr(&mut env, 10), T_THREE);
    env.backend.set(sem::Fpr(11).state(), T_THREE);
    assert!(run1(&mut env, fop3(0x16, 11, 9, 0x0a3, 12)));
    assert_eq!(fpr(&mut env, 12), 0x3ff8_0000_0000_0000); // 1.5
    // adds/su（/s+/u 修飾、rm=/n の fn11=0x580）も同じ結果。
    assert!(run1(&mut env, fop3(0x16, 1, 2, 0x580, 13)));
    assert_eq!(fpr(&mut env, 13), S_THREE);
    // /m（負無限大方向丸め、fn[7:6]=01）の経路: 0.1+0.2 は
    // 表現可能境界の丸めが見える。0x3fb999999999999a+0x3fc999999999999a。
    // 結果の正確な下位は softfloat 任せだが、/n との差分が出ない
    // 正確値（1.0+2.0）では同じになる。
    assert!(run1(&mut env, fop3(0x16, 1, 2, 0x0c0, 14)));
    assert_eq!(fpr(&mut env, 14), S_THREE);
}

#[test]
fn fp_cmpt_and_unordered() {
    let mut env = env();
    env.backend.set(sem::Fpr(1).state(), T_ONE);
    env.backend.set(sem::Fpr(2).state(), T_TWO);
    // cmpteq: 1.0 == 2.0 → 0。cmptlt: 1.0 < 2.0 → 真。cmptle も真。
    assert!(run1(&mut env, fop3(0x16, 1, 2, 0x0a5, 3)));
    assert_eq!(fpr(&mut env, 3), 0);
    assert!(run1(&mut env, fop3(0x16, 1, 2, 0x0a6, 3)));
    assert_eq!(fpr(&mut env, 3), CMP_TRUE);
    assert!(run1(&mut env, fop3(0x16, 2, 2, 0x0a7, 3)));
    assert_eq!(fpr(&mut env, 3), CMP_TRUE);
    assert!(run1(&mut env, fop3(0x16, 2, 1, 0x0a6, 3)));
    assert_eq!(fpr(&mut env, 3), 0); // 2.0 < 1.0 は偽
    // cmptun: 順序付きなら 0、NaN を含むと真。
    assert!(run1(&mut env, fop3(0x16, 1, 2, 0x0a4, 3)));
    assert_eq!(fpr(&mut env, 3), 0);
    env.backend.set(sem::Fpr(4).state(), T_NAN);
    assert!(run1(&mut env, fop3(0x16, 4, 1, 0x0a4, 3)));
    assert_eq!(fpr(&mut env, 3), CMP_TRUE);
    // NaN では le/lt/eq も全て偽。
    assert!(run1(&mut env, fop3(0x16, 4, 1, 0x0a7, 3)));
    assert_eq!(fpr(&mut env, 3), 0);
}

#[test]
fn fp_sqrt_and_cvt() {
    let mut env = env();
    // sqrts f1,f2: sqrt(4.0)=2.0。f32 4.0=0x40800000 → sreg。
    env.backend.set(sem::Fpr(1).state(), 0x4010_0000_0000_0000);
    assert!(run1(&mut env, fop2(0x14, 1, 0x00b, 2)));
    assert_eq!(fpr(&mut env, 2), S_TWO);
    // sqrtt: sqrt(9.0)=3.0。f64 9.0 = 0x4022_0000_0000_0000。
    env.backend.set(sem::Fpr(3).state(), 0x4022_0000_0000_0000);
    assert!(run1(&mut env, fop2(0x14, 3, 0x02b, 4)));
    assert_eq!(fpr(&mut env, 4), T_THREE);
    // cvtts f5,f6: T 2.5 → S。f32 2.5=0x40200000 → sreg。
    env.backend.set(sem::Fpr(5).state(), 0x4004_0000_0000_0000);
    assert!(run1(&mut env, fop2(0x16, 5, 0x02c, 6)));
    assert_eq!(fpr(&mut env, 6), 0x4004_0000_0000_0000);
    // cvtst f7,f8: S 2.0 → T 2.0。
    env.backend.set(sem::Fpr(7).state(), S_TWO);
    assert!(run1(&mut env, fop2(0x16, 7, 0x2ac, 8)));
    assert_eq!(fpr(&mut env, 8), T_TWO);
    // cvtst/s も同じ変換経路。
    assert!(run1(&mut env, fop2(0x16, 7, 0x6ac, 9)));
    assert_eq!(fpr(&mut env, 9), T_TWO);
    // cvttq f10,f11: 3.7 → 3（無修飾 = /c 0 方向切り捨て）。
    env.backend.set(sem::Fpr(10).state(), 0x400d_9999_9999_999a);
    assert!(run1(&mut env, fop2(0x16, 10, 0x02f, 11)));
    assert_eq!(fpr(&mut env, 11), 3);
    // cvtqs f12,f13: int 42 → S 42.0。
    env.backend.set(sem::Fpr(12).state(), 42);
    assert!(run1(&mut env, fop2(0x16, 12, 0x03c, 13)));
    assert_eq!(fpr(&mut env, 13), S_42);
    // cvtqt: int 42 → T 42.0。
    assert!(run1(&mut env, fop2(0x16, 12, 0x03e, 14)));
    assert_eq!(fpr(&mut env, 14), T_42);
}

#[test]
fn fp_itof_ftoi_moves() {
    let mut env = env();
    // itofs r1,f2: r の下位 32 ビットを S 内部表現へ。
    env.backend.set(sem::Gpr(1).state(), 0x3f80_0000);
    assert!(run1(&mut env, fitf(1, 0x004, 2)));
    assert_eq!(fpr(&mut env, 2), S_ONE);
    // ftois f2,r3: 逆変換で f32 ビット列を符号拡張して返す。
    assert!(run1(&mut env, ffti(2, 0x078, 3)));
    assert_eq!(gpr(&mut env, 3), 0x3f80_0000);
    // ftois は符号拡張する（ARM §4.10.18: Rc<63:32> ← SEXT(Fav<63>)）。
    env.backend.set(sem::Gpr(7).state(), -1i64 as u64);
    assert!(run1(&mut env, fitf(7, 0x004, 8)));
    assert!(run1(&mut env, ffti(8, 0x078, 9)));
    assert_eq!(gpr(&mut env, 9), -1i64 as u64);
    // itoft r4,f5 / ftoit f5,r6 は生の 64 ビット転送。
    env.backend.set(sem::Gpr(4).state(), 0xdead_beef_cafe_f00d);
    assert!(run1(&mut env, fitf(4, 0x024, 5)));
    assert_eq!(fpr(&mut env, 5), 0xdead_beef_cafe_f00d);
    assert!(run1(&mut env, ffti(5, 0x070, 6)));
    assert_eq!(gpr(&mut env, 6), 0xdead_beef_cafe_f00d);
}

#[test]
fn fp_cpys_and_fcmov() {
    let mut env = env();
    // cpys f1,f2,f3: 符号は f1、残りは f2 から。
    env.backend.set(sem::Fpr(1).state(), 0x0000_0000_0000_1111);
    env.backend.set(sem::Fpr(2).state(), 0x8000_0000_0000_2222);
    assert!(run1(&mut env, fop3(0x17, 1, 2, 0x020, 3)));
    assert_eq!(fpr(&mut env, 3), 0x0000_0000_0000_2222);
    // cpysn: f1 の符号を反転して取る。
    assert!(run1(&mut env, fop3(0x17, 1, 2, 0x021, 4)));
    assert_eq!(fpr(&mut env, 4), 0x8000_0000_0000_2222);
    // cpyse: 符号+指数（上位 12 ビット）を f1 から取る。
    assert!(run1(&mut env, fop3(0x17, 1, 2, 0x022, 5)));
    assert_eq!(fpr(&mut env, 5), 0x0000_0000_0000_2222);
    // cpys f31,f6,f7 = fabs(f6) のイディオム。
    env.backend.set(sem::Fpr(6).state(), 0xbff0_0000_0000_0000); // -1.0
    assert!(run1(&mut env, fop3(0x17, 31, 6, 0x020, 7)));
    assert_eq!(fpr(&mut env, 7), T_ONE);
    // fcmoveq f6,f7,f8: fa=0 のとき rc←rb。
    env.backend.set(sem::Fpr(7).state(), T_TWO);
    assert!(run1(&mut env, fop3(0x17, 31, 7, 0x02a, 8)));
    assert_eq!(fpr(&mut env, 8), T_TWO);
    // fa≠0 なら rc は据え置き。
    env.backend.set(sem::Fpr(6).state(), T_ONE);
    env.backend.set(sem::Fpr(9).state(), T_THREE);
    assert!(run1(&mut env, fop3(0x17, 6, 7, 0x02a, 9)));
    assert_eq!(fpr(&mut env, 9), T_THREE);
    // fcmovlt: 負の fa（-0.0 ではなく真の負）で真。
    env.backend.set(sem::Fpr(10).state(), 0xbff0_0000_0000_0000);
    assert!(run1(&mut env, fop3(0x17, 10, 7, 0x02c, 11)));
    assert_eq!(fpr(&mut env, 11), T_TWO);
}

#[test]
fn fp_fpcr_and_cvtlq_cvtql() {
    let mut env = env();
    // mt_fpcr f1 で書き、mf_fpcr f2 で読み戻す。
    env.backend.set(sem::Fpr(1).state(), 0x0c00_0000_0000_0000);
    assert!(run1(&mut env, fop3(0x17, 1, 31, 0x024, 31)));
    assert!(run1(&mut env, fop3(0x17, 2, 31, 0x025, 31)));
    assert_eq!(fpr(&mut env, 2), 0x0c00_0000_0000_0000);
    // cvtql f3,f4: 整数 42 を S 内部表現の整数領域へ。
    env.backend.set(sem::Fpr(3).state(), 42);
    assert!(run1(&mut env, fop2(0x17, 3, 0x030, 4)));
    assert_eq!(fpr(&mut env, 4), 0x0000_0005_4000_0000);
    // cvtlq f4,f5: L 形式を quadword に戻す（ARM §4.10.2
    // SEXT(Fbv<63:62> || Fbv<58:29>)）→ 42 に戻る。
    assert!(run1(&mut env, fop2(0x17, 4, 0x010, 5)));
    assert_eq!(fpr(&mut env, 5), 42);
    // 負値: cvtql(-1) → <63:62>=11, <58:29>=0x3fffffff。
    env.backend.set(sem::Fpr(6).state(), -1i64 as u64);
    assert!(run1(&mut env, fop2(0x17, 6, 0x030, 7)));
    assert_eq!(fpr(&mut env, 7), 0xc7ff_ffff_e000_0000);
    // cvtlq で -1 に戻る（符号拡張）。
    assert!(run1(&mut env, fop2(0x17, 7, 0x010, 8)));
    assert_eq!(fpr(&mut env, 8), -1i64 as u64);
}
