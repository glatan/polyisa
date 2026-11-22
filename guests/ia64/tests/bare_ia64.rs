// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! IA-64 骨格の最小テスト。CpuState の構成と定数レジスタ
//! （r0・p0）・NaT ビットの規則を確かめる。
//! 出典は SPEC-IA64-SDM Rev 2.3 (2010-05) である。
//! Ref: SPEC-IA64-SDM (Rev 2.3).

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::InterpExit;
use polyisa_guest_ia64::bundle::{self, Unit};
use polyisa_guest_ia64::{
    CpuState, FEAT_ITANIUM, FEAT_ITANIUM2, FEAT_UNIT_A, FEAT_UNIT_I, IP_SLOT_MASK, Insn,
    decode_model_ex, disasm_word_ex, encode_add, encode_br_cond_sptk_few, encode_break_f,
    encode_break_i, encode_brl_cond_sptk_few, encode_cmp_lt_or, encode_fma_s0, encode_hint_f,
    encode_ld4, encode_mov_ip, encode_movl, encode_nop_b, encode_nop_f, encode_nop_i, encode_nop_x,
    encode_padd1, encode_pcmp4_eq, encode_psub1, encode_st4, encode_sub_imm8, extract_ops, sem,
};

fn env() -> BareEnv {
    BareEnv::new(core::mem::size_of::<CpuState>())
}

#[test]
fn state_layout_pinned() {
    assert_eq!(core::mem::offset_of!(CpuState, gr), 0);
    assert_eq!(core::mem::offset_of!(CpuState, gr_nat), 128 * 8);
    let pr = 128 * 8 + 2 * 8;
    assert_eq!(core::mem::offset_of!(CpuState, pr), pr);
    assert_eq!(core::mem::offset_of!(CpuState, br), pr + 8);
    let ip = pr + 8 + 8 * 8;
    assert_eq!(core::mem::offset_of!(CpuState, ip), ip);
    let pfs = ip + 8;
    assert_eq!(core::mem::offset_of!(CpuState, pfs), pfs);
    assert_eq!(core::mem::offset_of!(CpuState, lc), pfs + 8);
    assert_eq!(core::mem::offset_of!(CpuState, ec), pfs + 16);
    assert_eq!(core::mem::offset_of!(CpuState, bsp), pfs + 24);
    assert_eq!(core::mem::offset_of!(CpuState, bspstore), pfs + 32);
    assert_eq!(core::mem::offset_of!(CpuState, rnat), pfs + 40);
    assert_eq!(core::mem::offset_of!(CpuState, unat), pfs + 48);
    assert_eq!(core::mem::offset_of!(CpuState, ccv), pfs + 56);
    assert_eq!(core::mem::offset_of!(CpuState, fpsr), pfs + 64);
    assert_eq!(core::mem::offset_of!(CpuState, rsc), pfs + 72);
    assert_eq!(core::mem::offset_of!(CpuState, itc), pfs + 80);
    let cfm = pfs + 88;
    assert_eq!(core::mem::offset_of!(CpuState, cfm), cfm);
    assert_eq!(core::mem::offset_of!(CpuState, rse_dirty), cfm + 8);
    assert_eq!(core::mem::offset_of!(CpuState, alat), cfm + 16);
    assert_eq!(
        core::mem::offset_of!(CpuState, alat_valid),
        cfm + 16 + 32 * 8
    );
    assert_eq!(
        core::mem::offset_of!(CpuState, psr_um),
        cfm + 16 + 32 * 8 + 8
    );
    assert_eq!(core::mem::size_of::<CpuState>(), cfm + 16 + 32 * 8 + 16);
}

#[test]
fn gr0_and_p0_are_constant() {
    let mut env = env();
    sem::gr_set(&mut env.backend, 0, !0);
    sem::gr_set(&mut env.backend, 1, 42);
    assert_eq!(sem::gr_get(&env.backend, 0), 0);
    assert_eq!(sem::gr_get(&env.backend, 1), 42);
    // p0 は既定でも書き込んでも常に 1。
    assert!(sem::pred(&env.backend, 0));
    assert!(!sem::pred(&env.backend, 3));
    sem::pr_set(&mut env.backend, 1 << 3);
    assert!(sem::pred(&env.backend, 0));
    assert!(sem::pred(&env.backend, 3));
    sem::pr_set(&mut env.backend, 0);
    assert!(sem::pred(&env.backend, 0));
    assert!(!sem::pred(&env.backend, 3));
}

#[test]
fn nat_bits_per_gr() {
    let mut env = env();
    assert!(!sem::nat_get(&env.backend, 5));
    assert!(!sem::nat_get(&env.backend, 70));
    sem::nat_set(&mut env.backend, 5, true);
    sem::nat_set(&mut env.backend, 70, true);
    assert!(sem::nat_get(&env.backend, 5));
    assert!(sem::nat_get(&env.backend, 70));
    assert!(!sem::nat_get(&env.backend, 6));
    sem::nat_set(&mut env.backend, 5, false);
    assert!(!sem::nat_get(&env.backend, 5));
}

#[test]
fn ip_slot_field() {
    // ip の下位 4 ビットがバンドル内のスロット番号。
    assert_eq!(IP_SLOT_MASK, 0xf);
}

#[test]
fn exec_is_unimplemented() {
    let mut env = env();
    let e = sem::exec(&mut env.backend, Insn::FmaS0, 0, 0).unwrap_err();
    assert!(matches!(e, InterpExit::Unimplemented(_)));
}

#[test]
fn exec_qp_suppression() {
    let mut env = env();
    // qp が偽なら意味論を実行しない（副作用なしで進む）。
    sem::gr_set(&mut env.backend, 1, 40);
    sem::gr_set(&mut env.backend, 2, 2);
    let w = encode_add(&[6, 4, 1, 2]).unwrap(); // (p6) add r4 = r1, r2
    let ok = sem::exec(&mut env.backend, Insn::Add, w, 0).unwrap();
    assert!(!ok);
    assert_eq!(sem::gr_get(&env.backend, 4), 0);
    // qp が偽なら未実装の命令でも落ちない。
    let ld = encode_ld4(&[6, 4, 2]).unwrap();
    let ok = sem::exec(&mut env.backend, Insn::Ld4, ld, 0).unwrap();
    assert!(!ok);
    // p6 を立てると実行される。
    sem::pr_set(&mut env.backend, 1 << 6);
    let ok = sem::exec(&mut env.backend, Insn::Add, w, 0).unwrap();
    assert!(ok);
    assert_eq!(sem::gr_get(&env.backend, 4), 42);
}

// ---- 段階21 IA3: バンドル・スロット語・生成符号化の最小検査 ----
// 命令語は生成 encode_* で組み立て、スロット文脈つきの
// decode_model_ex / disasm_word_ex で往復させる。
// Ref: SPEC-IA64-SDM (Rev 2.3).

const CPU: u128 = FEAT_ITANIUM | FEAT_ITANIUM2;

/// テンプレート値・ストップビット・3 スロットから 128 ビット
/// バンドル語を組み立てる。slot0=bits[45:5]、slot1=bits[86:46]、
/// slot2=bits[127:87]。
fn mk_bundle(templ: u8, stop: bool, s0: u64, s1: u64, s2: u64) -> u128 {
    (s2 as u128) << 87
        | (s1 as u128) << 46
        | (s0 as u128) << 5
        | (templ as u128) << 1
        | stop as u128
}

/// スロット文脈で encode→decode→再符号化の往復を確かめ、
/// 逆アセンブルが指定のニーモニックで始まることを確認する。
fn slot_roundtrip(unit: Unit, enc: Option<u128>, want_insn: Insn, want: &str) -> u128 {
    let word = enc.expect("encode");
    let insn = bundle::decode_slot(unit, word, CPU).expect("decode");
    assert_eq!(insn, want_insn);
    assert!(bundle::fits_slot(bundle::insn_unit(insn), unit));
    let text = disasm_word_ex(
        word,
        bundle::slot_len(unit),
        true,
        CPU | bundle::slot_feats(unit),
    )
    .expect("disasm");
    assert!(text.contains(want), "{want} を含まない: {text}");
    word
}

#[test]
fn a_unit_forms() {
    // A1 型: add r1 = r2, r3（qp=0, r1=5, r2=6, r3=7）
    let w = slot_roundtrip(Unit::I, encode_add(&[0, 5, 6, 7]), Insn::Add, "add r5");
    // A 型は I/M 両スロットに置ける。
    assert_eq!(bundle::decode_slot(Unit::M, w, CPU), Some(Insn::Add));
    // A3 型: sub_imm8 r1 = imm8, r3
    let w2 = slot_roundtrip(
        Unit::M,
        encode_sub_imm8(&[0, 9, 0x23, 8]),
        Insn::SubImm8,
        "sub r9 = 35",
    );
    // I スロットでもデコードできる（A 型）。
    assert_eq!(bundle::decode_slot(Unit::I, w2, CPU), Some(Insn::SubImm8));
    // F 文脈では同じ語が fma.s0 として解釈される
    // （IA-64 はテンプレートなしでは一意でない）。add にはならない。
    assert_ne!(bundle::decode_slot(Unit::F, w, CPU), Some(Insn::Add));
}

#[test]
fn i_unit_forms() {
    // mov.i r1 = ip
    let w = slot_roundtrip(Unit::I, encode_mov_ip(&[0, 3]), Insn::MovIp, "mov r3 = ip");
    // M スロットでは同じ 41 ビット語は別命令（dep 等）に解釈される
    // かデコード不能になるが、mov.ip にはならない。
    assert_ne!(bundle::decode_slot(Unit::M, w, CPU), Some(Insn::MovIp));
    // nop.i（imm21=0）
    slot_roundtrip(Unit::I, encode_nop_i(&[0, 0]), Insn::NopI, "nop.i");
}

#[test]
fn m_unit_forms() {
    // ld4 r1 = [r3]
    let w = slot_roundtrip(Unit::M, encode_ld4(&[0, 4, 2]), Insn::Ld4, "ld4 r4 = [r2]");
    // I 文脈では dep 等の別命令として解釈されるが、ld4 にはならない。
    assert_ne!(bundle::decode_slot(Unit::I, w, CPU), Some(Insn::Ld4));
    // st4 [r3] = r2
    slot_roundtrip(Unit::M, encode_st4(&[0, 7, 6]), Insn::St4, "st4 [r7] = r6");
}

#[test]
fn f_unit_forms() {
    // fma.s.s0 f1 = f3, f4, f2（F1 型。operand 順は qp, f1, f3, f4, f2）
    let w = slot_roundtrip(
        Unit::F,
        encode_fma_s0(&[0, 8, 9, 10, 11]),
        Insn::FmaS0,
        "fma.s0 f8 = f9, f10, f11",
    );
    // I 文脈でも別命令として解釈され得るが、F 命令ではない。
    assert_ne!(bundle::decode_slot(Unit::I, w, CPU), Some(Insn::FmaS0));
}

#[test]
fn b_unit_forms() {
    // br.cond.sptk.few tgt21（16 バイト整列分岐先の IP 相対値）
    let w = slot_roundtrip(
        Unit::B,
        encode_br_cond_sptk_few(&[0, 0x40]),
        Insn::BrCondSptkFew,
        "br.cond.sptk.few",
    );
    assert_ne!(
        bundle::decode_slot(Unit::M, w, CPU),
        Some(Insn::BrCondSptkFew)
    );
}

#[test]
fn x_unit_82bit_forms() {
    // movl r1 = imm64（82 ビット語）
    let w = slot_roundtrip(
        Unit::X,
        encode_movl(&[0, 12, 0xdead_beef_1234_5678]),
        Insn::Movl,
        "movl r12",
    );
    assert_eq!(bundle::slot_len(Unit::X), 82);
    // nop.x imm62
    slot_roundtrip(Unit::X, encode_nop_x(&[0, 0x1f]), Insn::NopX, "nop.x");
    // 82 ビット語の上位は 41 ビット L スロットをまたぐ。
    assert_eq!(w >> 82, 0);
    assert_ne!(w >> 41, 0);
}

#[test]
fn operand_extraction_roundtrip() {
    use polyisa_guest_ia64::extract_ops;
    let w = encode_add(&[3, 5, 6, 7]).unwrap();
    let insn = bundle::decode_slot(Unit::I, w, CPU).unwrap();
    let ops = extract_ops(insn, w);
    assert_eq!(ops, vec![3, 5, 6, 7]);
    assert_eq!(encode_add(&ops), Some(w));
}

#[test]
fn template_table_matches_sdm() {
    let t = &bundle::TEMPLATES;
    // 有効 12 個、予約 4 個（3, a, d, f）。
    assert_eq!(t.iter().filter(|d| d.is_some()).count(), 12);
    for i in [3usize, 0xa, 0xd, 0xf] {
        assert!(t[i].is_none());
    }
    assert_eq!(t[0].unwrap().slots, [Unit::M, Unit::I, Unit::I]);
    assert_eq!(t[2].unwrap().slots, [Unit::M, Unit::L, Unit::X]);
    assert_eq!(t[5].unwrap().boundary, 1);
    assert_eq!(t[1].unwrap().boundary, 2);
}

#[test]
fn bundle_fields_and_stops() {
    let nop_i = encode_nop_i(&[0, 0]).unwrap() as u64;
    let ld4 = encode_ld4(&[0, 4, 2]).unwrap() as u64;
    // MII テンプレート 1（slot1 後にストップ）、s ビット 0。
    let b = mk_bundle(1, false, ld4, nop_i, nop_i);
    assert_eq!(bundle::template_index(b), 1);
    assert!(!bundle::bundle_stop(b));
    assert_eq!(bundle::bundle_slot(b, 0), ld4);
    assert_eq!(bundle::bundle_slot(b, 1), nop_i);
    assert_eq!(bundle::bundle_slot(b, 2), nop_i);
    assert_eq!(bundle::template_stops(b), Some([false, true, false]));
}

#[test]
fn decode_mii_bundle() {
    let ld4 = encode_ld4(&[0, 4, 2]).unwrap() as u64;
    let add = encode_add(&[0, 5, 6, 7]).unwrap() as u64;
    let nop_i = encode_nop_i(&[0, 0]).unwrap() as u64;
    let b = mk_bundle(0, true, ld4, add, nop_i);
    let insns = bundle::decode_bundle(b, CPU).expect("decode MII");
    assert_eq!(insns.len(), 3);
    assert_eq!(insns[0].insn, Insn::Ld4);
    assert_eq!(insns[1].insn, Insn::Add); // A 型が I スロットに収まる
    assert_eq!(insns[2].insn, Insn::NopI);
    assert_eq!(insns[0].slot, 0);
    assert_eq!(insns[2].slot, 2);
}

#[test]
fn decode_mlx_bundle() {
    let ld4 = encode_ld4(&[0, 4, 2]).unwrap() as u64;
    let movl = encode_movl(&[0, 12, 0x0123_4567_89ab_cdef]).unwrap();
    let x_lo = (movl & ((1u128 << 41) - 1)) as u64; // slot2 = X 半分
    let l_hi = (movl >> 41) as u64; // slot1 = L 半分
    let b = mk_bundle(2, false, ld4, l_hi, x_lo);
    assert_eq!(bundle::template_desc(b).unwrap().name, "MLX");
    assert_eq!(bundle::bundle_x_word(b), movl);
    let insns = bundle::decode_bundle(b, CPU).expect("decode MLX");
    assert_eq!(insns.len(), 2);
    assert_eq!(insns[0].insn, Insn::Ld4);
    assert_eq!(insns[1].slot, 2);
    assert_eq!(insns[1].insn, Insn::Movl);
}

#[test]
fn template_unit_mismatch_rejected() {
    // I 専用の mov.i を B スロットに置いた MIB 風の語は
    // decode_bundle を失敗させる（スロット文脈で解釈しない）。
    let mov_ip = encode_mov_ip(&[0, 3]).unwrap() as u64;
    let ld4 = encode_ld4(&[0, 4, 2]).unwrap() as u64;
    let add = encode_add(&[0, 5, 6, 7]).unwrap() as u64;
    let b = mk_bundle(8, false, ld4, add, mov_ip); // MIB: slot2 は B
    assert!(bundle::decode_bundle(b, CPU).is_none());
}

#[test]
fn context_flags_select_interpretation() {
    // 同じ 41 ビット語でも文脈フィーチャで型が変わる。
    let w = encode_add(&[0, 5, 6, 7]).unwrap();
    assert_eq!(
        decode_model_ex(w, 41, true, CPU | FEAT_UNIT_I | FEAT_UNIT_A),
        Some(Insn::Add)
    );
    assert_eq!(decode_model_ex(w, 41, true, CPU | FEAT_UNIT_I), None);
}

// ---- 段階21 IA3 レビュー修正の回帰テスト ----
// 修正した符号化が gas が出す実語と一致し、旧（誤りの）
// オペコード空間や固定桁を倒した語が当該命令に解釈されない
// ことを確かめる。
// Ref: SPEC-IA64-SDM (Rev 2.3) / binutils ia64-opc-{a,b,f,x}.c.

#[test]
fn cmp_lt_or_is_or_space() {
    // gas が `cmp.lt.or p2,p3 = r4, r0`（疑似形式、r3 桁側の
    // オペランド順）に出す語と一致する。
    // OpX2TbTaC(0xd, 0, 1, 0, 0)、r2 桁 [19:13] は建築的に
    // r0 のため 0 固定。
    let w = encode_cmp_lt_or(&[0, 2, 3, 4]).unwrap();
    assert_eq!(w, 0x01b0_1840_0080);
    assert_eq!(bundle::decode_slot(Unit::I, w, CPU), Some(Insn::CmpLtOr));
    // A 型なので M スロットでも同じ解釈。
    assert_eq!(bundle::decode_slot(Unit::M, w, CPU), Some(Insn::CmpLtOr));
    let t = disasm_word_ex(w, 41, true, CPU | FEAT_UNIT_I | FEAT_UNIT_A).expect("disasm");
    assert!(t.contains("cmp.lt.or p2, p3 = r4, r0"), "{t}");
    // 旧誤りパターンの空間（cmp4.lt 相当: op=0xc,x2=1,tb=0）は
    // cmp_lt_or に解釈されない。
    let old_space = 0x1840_1840_0080u128;
    assert_ne!(
        bundle::decode_slot(Unit::I, old_space, CPU),
        Some(Insn::CmpLtOr)
    );
    // r2 桁を立てた語は受理しない（r0 固定の桁）。
    let bad_r2 = w | (5u128 << 13);
    assert_ne!(
        bundle::decode_slot(Unit::I, bad_r2, CPU),
        Some(Insn::CmpLtOr)
    );
    assert_eq!(extract_ops(Insn::CmpLtOr, w), vec![0, 2, 3, 4]);
}

#[test]
fn pcmp4_eq_field_layout() {
    // gas が `pcmp4.eq r10 = r30, r31` に出す語と一致する。
    // OpX2aZaZbX4X2b(8, 1, 1, 0, 9, 0)。
    let w = encode_pcmp4_eq(&[0, 10, 30, 31]).unwrap();
    assert_eq!(w, 0x0115_21f3_c280);
    assert_eq!(w & 0x1fff8000000, 0x11520000000);
    assert_eq!(bundle::decode_slot(Unit::I, w, CPU), Some(Insn::Pcmp4Eq));
    // za(bit36)・x4・x2b を変えた語は pcmp4.eq ではない
    // （旧パターンが指していた空間は別命令か未定義）。
    assert_ne!(
        bundle::decode_slot(Unit::I, w ^ (1u128 << 36), CPU),
        Some(Insn::Pcmp4Eq)
    );
    let x4_changed = (w & !(0xfu128 << 29)) | (4u128 << 29);
    assert_ne!(
        bundle::decode_slot(Unit::I, x4_changed, CPU),
        Some(Insn::Pcmp4Eq)
    );
    let x2b_changed = w | (1u128 << 27);
    assert_ne!(
        bundle::decode_slot(Unit::I, x2b_changed, CPU),
        Some(Insn::Pcmp4Eq)
    );
}

#[test]
fn padd_psub_za_pinned() {
    // binutils: padd1 (8,1,0,0,0,0)、psub1 (8,1,0,0,1,0)。
    // za(bit36) は 0 固定。
    let w = encode_padd1(&[0, 5, 6, 7]).unwrap();
    assert_eq!(w & 0x1fff8000000, 0x10400000000);
    assert_eq!(bundle::decode_slot(Unit::I, w, CPU), Some(Insn::Padd1));
    let w2 = encode_psub1(&[0, 5, 6, 7]).unwrap();
    assert_eq!(w2 & 0x1fff8000000, 0x10420000000);
    assert_eq!(bundle::decode_slot(Unit::I, w2, CPU), Some(Insn::Psub1));
    // za を立てると padd4/psub4 の空間（未収録）で、1 系ではない。
    for (bad, insn) in [
        (w | (1u128 << 36), Insn::Padd1),
        (w2 | (1u128 << 36), Insn::Psub1),
    ] {
        assert_ne!(bundle::decode_slot(Unit::I, bad, CPU), Some(insn));
    }
}

#[test]
fn f_unit_misc_x3_pinned() {
    // break.f/nop.f/hint.f は x3[35:33]=0 固定（正本 F15/F16）。
    for (enc, insn) in [
        (encode_break_f(&[0, 0]), Insn::BreakF),
        (encode_nop_f(&[0, 0]), Insn::NopF),
        (encode_hint_f(&[0, 0]), Insn::HintF),
    ] {
        let w = enc.expect("encode");
        assert_eq!(bundle::decode_slot(Unit::F, w, CPU), Some(insn));
        // x3 の下位 2 ビットを立てた語は当該命令ではない。
        assert_ne!(
            bundle::decode_slot(Unit::F, w | (0b110u128 << 33), CPU),
            Some(insn)
        );
    }
}

#[test]
fn brl_cond_btype_pinned() {
    // OpBtypePaWhaD(0xc, 0, 0, 0, 0): btype[8:6]=0 が sptk.few。
    let w = encode_brl_cond_sptk_few(&[0, 0x100]).unwrap();
    assert_eq!(w & 0x7ee000011c0, 0x18000000000);
    assert_eq!(
        bundle::decode_slot(Unit::X, w, CPU),
        Some(Insn::BrlCondSptkFew)
    );
    // btype≠0（例えば ret の 4）は受理しない。
    assert_ne!(
        bundle::decode_slot(Unit::X, w | (4u128 << 6), CPU),
        Some(Insn::BrlCondSptkFew)
    );
}

// ---- 段階21 IA4: 実行ループ（バンドル進行・RIP 管理）の最小検査 ----
// `run::step` が RIP（バンドルアドレス|スロット番号）で 16 バイトの
// バンドルを読み、命令群を stop・末端・分岐成立で切ることを確かめる。
// Ref: SPEC-IA64-SDM (Rev 2.3).

use polyisa_engine::run::{Outcome, TrapHandler, TrapOutcome};
use polyisa_guest_ia64::run;
use polyisa_mem::{Perms, VirtAddr};

const BASE: u64 = 0x1_0000;

/// トラップを捌かないハンドラ。`handled` 記録つきの別型を下で使う。
struct NoSys;

impl TrapHandler for NoSys {
    fn handle_trap(&mut self, _env: &mut BareEnv, _code: u32) -> TrapOutcome {
        TrapOutcome::Unimplemented
    }
}

/// 実行・読み書き可能なページを BASE に写像した環境。
fn run_env() -> BareEnv {
    let mut env = env();
    env.backend
        .mem
        .map(VirtAddr(BASE), 1, Perms(Perms::RW.0 | Perms::X.0))
        .unwrap();
    env
}

fn put_bundle(env: &mut BareEnv, addr: u64, b: u128) {
    env.backend
        .mem
        .write(VirtAddr(addr), &b.to_le_bytes())
        .unwrap();
}

fn step(env: &mut BareEnv) -> Result<(), Outcome> {
    run::step(env, &mut NoSys, CPU)
}

#[test]
fn bundle_group_progression() {
    // MII（テンプレート 0）に stop ビット。3 スロットが 1 群で進む。
    let mut env = run_env();
    sem::gr_set(&mut env.backend, 1, 40);
    sem::gr_set(&mut env.backend, 2, 2);
    let add4 = encode_add(&[0, 4, 1, 2]).unwrap() as u64;
    let add5 = encode_add(&[0, 5, 1, 2]).unwrap() as u64;
    let nop = encode_nop_i(&[0, 0]).unwrap() as u64;
    put_bundle(&mut env, BASE, mk_bundle(0, true, add4, add5, nop));
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(sem::gr_get(&env.backend, 4), 42);
    assert_eq!(sem::gr_get(&env.backend, 5), 42);
    assert_eq!(env.pc, BASE + 16);
    // 状態の ip 面も次の命令位置に同期する。
    use polyisa_sem::Backend as _;
    assert_eq!(env.backend.get(sem::ip_ref()), BASE + 16);
}

#[test]
fn stop_boundary_splits_step() {
    // MII（テンプレート 1）は slot1 後にストップ。1 ステップは
    // slot0-1 だけを進め、次は slot2 から。
    let mut env = run_env();
    sem::gr_set(&mut env.backend, 1, 40);
    sem::gr_set(&mut env.backend, 2, 2);
    let add4 = encode_add(&[0, 4, 1, 2]).unwrap() as u64;
    let add5 = encode_add(&[0, 5, 1, 2]).unwrap() as u64;
    let add6 = encode_add(&[0, 6, 1, 2]).unwrap() as u64;
    put_bundle(&mut env, BASE, mk_bundle(1, true, add4, add5, add6));
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE | 2);
    assert_eq!(sem::gr_get(&env.backend, 5), 42);
    assert_eq!(sem::gr_get(&env.backend, 6), 0);
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 16);
    assert_eq!(sem::gr_get(&env.backend, 6), 42);
}

#[test]
fn slot_entry_and_ip_read() {
    // スロット 1 への進入。slot1 の mov r3 = ip はバンドル
    // アドレス（建築の IP は下位 4 ビット 0）を読む。
    let mut env = run_env();
    let nop = encode_nop_i(&[0, 0]).unwrap() as u64;
    let movip = encode_mov_ip(&[0, 3]).unwrap() as u64;
    put_bundle(&mut env, BASE, mk_bundle(0, true, nop, movip, nop));
    env.pc = BASE | 1;
    step(&mut env).unwrap();
    assert_eq!(sem::gr_get(&env.backend, 3), BASE);
    assert_eq!(env.pc, BASE + 16);
}

#[test]
fn mlx_lx_insn_progresses_as_one() {
    // MLX は slot1+slot2 が 1 命令。スロット 1 への進入で L+X
    // 命令が走り、スロット番号 1 の ip を持つ。
    let mut env = run_env();
    let add = encode_add(&[0, 4, 1, 2]).unwrap() as u64;
    let movl = encode_movl(&[0, 8, 0x0123_4567_89ab_cdef]).unwrap();
    let x_lo = (movl & ((1u128 << 41) - 1)) as u64;
    let l_hi = (movl >> 41) as u64;
    let b = mk_bundle(2, true, add, l_hi, x_lo);
    // slot0 からの通常進行。
    sem::gr_set(&mut env.backend, 1, 40);
    sem::gr_set(&mut env.backend, 2, 2);
    put_bundle(&mut env, BASE, b);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(sem::gr_get(&env.backend, 4), 42);
    assert_eq!(sem::gr_get(&env.backend, 8), 0x0123_4567_89ab_cdef);
    assert_eq!(env.pc, BASE + 16);
    // slot1 への進入も同じ命令を実行する。
    sem::gr_set(&mut env.backend, 8, 0);
    env.pc = BASE | 1;
    step(&mut env).unwrap();
    assert_eq!(sem::gr_get(&env.backend, 8), 0x0123_4567_89ab_cdef);
    assert_eq!(env.pc, BASE + 16);
    // slot2 への進入は長命令の途中で、不正として TRAP_ILL に
    // 落ちる（NoSys は Unimplemented を返す）。
    env.pc = BASE | 2;
    assert_eq!(
        step(&mut env),
        Err(Outcome::Unimplemented {
            pc: BASE | 2,
            word: 0
        })
    );
}

#[test]
fn taken_branch_skips_group_tail() {
    // MBB（テンプレート 9）で slot1 の br.cond が成立したら
    // slot2 の br.cond（別の着地点）は実行しない。
    let mut env = run_env();
    let t1 = 0x2_0000u64;
    let t2 = 0x3_0000u64;
    let add = encode_add(&[0, 4, 1, 2]).unwrap() as u64;
    // tgt25c はバンドルアドレスからの変位（下位 4 ビット 0 の値）。
    let br1 = encode_br_cond_sptk_few(&[0, t1 - BASE]).unwrap() as u64;
    let br2 = encode_br_cond_sptk_few(&[0, t2 - BASE]).unwrap() as u64;
    put_bundle(&mut env, BASE, mk_bundle(9, true, add, br1, br2));
    sem::gr_set(&mut env.backend, 1, 40);
    sem::gr_set(&mut env.backend, 2, 2);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(sem::gr_get(&env.backend, 4), 42);
    assert_eq!(env.pc, t1);
}

#[test]
fn qp_false_branch_not_taken() {
    // (p6) br.cond で p6 が偽ならスルーして次の命令位置へ進む。
    let mut env = run_env();
    let t1 = 0x2_0000u64;
    let add = encode_add(&[0, 4, 1, 2]).unwrap() as u64;
    let br = encode_br_cond_sptk_few(&[6, t1 - BASE]).unwrap() as u64;
    let nop = encode_nop_b(&[0, 0]).unwrap() as u64;
    put_bundle(&mut env, BASE, mk_bundle(9, true, add, br, nop));
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 16);
    // p6 を立てると成立する。
    sem::pr_set(&mut env.backend, 1 << 6);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.pc, t1);
}

#[test]
fn break_traps_and_resumes_at_next_insn() {
    // break.i は即値を code に載せて OS パーソナリティへ渡り、
    // Handled なら次の命令位置（スロットを 1 進めた ip）で再開。
    struct Rec {
        code: u32,
    }
    impl TrapHandler for Rec {
        fn handle_trap(&mut self, _env: &mut BareEnv, code: u32) -> TrapOutcome {
            self.code = code;
            TrapOutcome::Handled
        }
    }
    let mut env = run_env();
    let mut sys = Rec { code: 0 };
    let add = encode_add(&[0, 4, 1, 2]).unwrap() as u64;
    let brk = encode_break_i(&[0, 0x100000]).unwrap() as u64;
    let nop = encode_nop_i(&[0, 0]).unwrap() as u64;
    put_bundle(&mut env, BASE, mk_bundle(0, true, add, brk, nop));
    sem::gr_set(&mut env.backend, 1, 40);
    sem::gr_set(&mut env.backend, 2, 2);
    env.pc = BASE;
    run::step(&mut env, &mut sys, CPU).unwrap();
    assert_eq!(sys.code, 0x100000);
    assert_eq!(sem::gr_get(&env.backend, 4), 42);
    assert_eq!(env.pc, BASE | 2);
}

#[test]
fn exit_outcome_propagates() {
    struct ExitSys;
    impl TrapHandler for ExitSys {
        fn handle_trap(&mut self, _env: &mut BareEnv, _code: u32) -> TrapOutcome {
            TrapOutcome::Exit(42)
        }
    }
    let mut env = run_env();
    let brk = encode_break_i(&[0, 0x100000]).unwrap() as u64;
    let nop = encode_nop_i(&[0, 0]).unwrap() as u64;
    put_bundle(&mut env, BASE, mk_bundle(0, true, nop, brk, nop));
    env.pc = BASE;
    let mut sys = ExitSys;
    assert_eq!(run::step(&mut env, &mut sys, CPU), Err(Outcome::Exit(42)));
}

#[test]
fn reserved_template_is_ill() {
    // 予約テンプレート（3）は TRAP_ILL。NoSys は Unimplemented。
    let mut env = run_env();
    let nop = encode_nop_i(&[0, 0]).unwrap() as u64;
    put_bundle(&mut env, BASE, mk_bundle(3, true, nop, nop, nop));
    env.pc = BASE;
    assert!(matches!(
        step(&mut env),
        Err(Outcome::Unimplemented { pc: BASE, .. })
    ));
}

#[test]
fn run_loop_exits_via_driver() {
    // engine::run::run 駆動で 2 バンドル進んで break → Exit。
    struct ExitSys;
    impl TrapHandler for ExitSys {
        fn handle_trap(&mut self, _env: &mut BareEnv, _code: u32) -> TrapOutcome {
            TrapOutcome::Exit(7)
        }
    }
    let mut env = run_env();
    let add = encode_add(&[0, 4, 1, 2]).unwrap() as u64;
    let nop = encode_nop_i(&[0, 0]).unwrap() as u64;
    let brk = encode_break_i(&[0, 0x100000]).unwrap() as u64;
    put_bundle(&mut env, BASE, mk_bundle(0, true, add, nop, nop));
    put_bundle(&mut env, BASE + 16, mk_bundle(0, true, nop, brk, nop));
    sem::gr_set(&mut env.backend, 1, 40);
    sem::gr_set(&mut env.backend, 2, 2);
    env.pc = BASE;
    let mut sys = ExitSys;
    let o = polyisa_engine::run::run(
        &mut env,
        &mut sys,
        16,
        |env| env.pc,
        |env, sys| run::step(env, sys, CPU),
    );
    assert_eq!(o, Outcome::Exit(7));
    assert_eq!(sem::gr_get(&env.backend, 4), 42);
}

// ---- 段階21 IA5: 整数・比較・述語テスト・シフト・MM・転送の意味論 ----
// 命令語は生成 encode_* で組み立て、exec を直接呼ぶ。即値・位置系の
// オペランドはフィールド符号化の値（len=len-1、cpos6=63-pos、
// cnt2a=count-1、ccnt5=31-count、immu5b=tf の imm-32）。
// Ref: SPEC-IA64-SDM (Rev 2.3).

use polyisa_guest_ia64::{
    encode_add_1, encode_addp4, encode_addp4_i, encode_and, encode_and_imm8, encode_andcm,
    encode_break_m, encode_cmp_eq, encode_cmp_eq_and, encode_cmp_eq_or_andcm, encode_cmp_lt,
    encode_cmp_lt_and, encode_cmp_lt_or_andcm, encode_cmp_lt_unc, encode_cmp_lt_unc_i,
    encode_cmp_ltu_i, encode_cmp4_eq_unc, encode_cmp4_lt, encode_czx1_l, encode_czx1_r, encode_dep,
    encode_dep_imm, encode_dep_z, encode_dep_z_imm, encode_extr, encode_extr_u, encode_hint_m,
    encode_mix1_l, encode_mix4_r, encode_mov_br, encode_mov_from_br, encode_mov_i_from_ar,
    encode_mov_i_to_ar, encode_mov_m_from_ar, encode_mov_m_to_ar, encode_mov_pr, encode_mov_pr_rot,
    encode_mov_psr_um, encode_mov_ret, encode_mov_to_pr, encode_mpy4, encode_mux1, encode_nop_m,
    encode_or, encode_pack2_sss, encode_pack2_uss, encode_pack4_sss, encode_padd2, encode_pavg1,
    encode_pavg2_raz, encode_pavgsub1, encode_pcmp1_eq, encode_pcmp2_gt, encode_pmax2,
    encode_pmin1_u, encode_pmpy2_l, encode_pmpy2_r, encode_pmpyshr2, encode_pmpyshr2_u,
    encode_popcnt, encode_psad1, encode_pshl2, encode_pshl2_i, encode_pshladd2, encode_pshr2,
    encode_pshr2_u_i, encode_pshradd2, encode_rum, encode_shl, encode_shladd, encode_shladdp4,
    encode_shr, encode_shr_u, encode_shrp, encode_sub, encode_sub_1, encode_sum, encode_sxt1,
    encode_tbit_nz_and, encode_tbit_nz_or_andcm, encode_tbit_z, encode_tbit_z_unc, encode_tf_z,
    encode_tnat_nz_and, encode_tnat_z, encode_unpack1_h, encode_unpack4_l, encode_xor,
    encode_xor_imm8, encode_zxt2,
};
use polyisa_sem::{Backend as _, StateRef, W64};

/// exec を 1 命令呼び、Ok の真偽を返す。
fn x(env: &mut BareEnv, insn: Insn, w: u128) -> bool {
    sem::exec(&mut env.backend, insn, w, 0x1000).unwrap()
}

/// exec の失敗（Trap の code）。
fn xerr(env: &mut BareEnv, insn: Insn, w: u128) -> u64 {
    match sem::exec(&mut env.backend, insn, w, 0x1000).unwrap_err() {
        InterpExit::Exception(e) => e.code,
        e => panic!("trap 以外の退出: {e:?}"),
    }
}

fn gr(env: &BareEnv, i: u32) -> u64 {
    sem::gr_get(&env.backend, i)
}

fn nat(env: &BareEnv, i: u32) -> bool {
    sem::nat_get(&env.backend, i)
}

fn p(env: &BareEnv, i: u32) -> bool {
    sem::pred(&env.backend, i)
}

fn set_gr(env: &mut BareEnv, i: u32, v: u64) {
    sem::gr_set(&mut env.backend, i, v);
}

/// 16 ビット要素 4 個を束ねる。
fn p16(e0: u64, e1: u64, e2: u64, e3: u64) -> u64 {
    e0 | e1 << 16 | e2 << 32 | e3 << 48
}

/// バイト要素 8 個を束ねる。
fn p8(v: [u64; 8]) -> u64 {
    v.iter()
        .enumerate()
        .fold(0, |a, (i, e)| a | (e & 0xff) << (8 * i))
}

#[test]
fn alu_three_operand_and_nat() {
    let mut env = env();
    set_gr(&mut env, 1, 40);
    set_gr(&mut env, 2, 2);
    assert!(x(&mut env, Insn::Add, encode_add(&[0, 4, 1, 2]).unwrap()));
    assert_eq!(gr(&env, 4), 42);
    assert!(!nat(&env, 4));
    x(&mut env, Insn::Add1, encode_add_1(&[0, 4, 1, 2]).unwrap());
    assert_eq!(gr(&env, 4), 43);
    x(&mut env, Insn::Sub, encode_sub(&[0, 4, 1, 2]).unwrap());
    assert_eq!(gr(&env, 4), 38);
    x(&mut env, Insn::Sub1, encode_sub_1(&[0, 4, 1, 2]).unwrap());
    assert_eq!(gr(&env, 4), 37);
    // ラップの確認。sub 0 - 1 = !0。
    set_gr(&mut env, 1, 0);
    set_gr(&mut env, 2, 1);
    x(&mut env, Insn::Sub, encode_sub(&[0, 4, 1, 2]).unwrap());
    assert_eq!(gr(&env, 4), u64::MAX);
    // ソース NaT が結果へ伝播する。
    set_gr(&mut env, 2, 3);
    sem::nat_set(&mut env.backend, 2, true);
    x(&mut env, Insn::Add, encode_add(&[0, 4, 1, 2]).unwrap());
    assert_eq!(gr(&env, 4), 3);
    assert!(nat(&env, 4));
    // 片方だけの NaT で伝播し、nat が無ければ落ちる。
    x(&mut env, Insn::Add, encode_add(&[0, 4, 1, 2]).unwrap());
    sem::nat_set(&mut env.backend, 2, false);
    x(&mut env, Insn::Add, encode_add(&[0, 5, 1, 2]).unwrap());
    assert!(!nat(&env, 5));
}

#[test]
fn alu_logic_and_imm8() {
    let mut env = env();
    set_gr(&mut env, 1, 0xf0f0_0f0f);
    set_gr(&mut env, 2, 0x0ff0_ff00);
    x(&mut env, Insn::And, encode_and(&[0, 4, 1, 2]).unwrap());
    assert_eq!(gr(&env, 4), 0x00f0_0f00);
    x(&mut env, Insn::Andcm, encode_andcm(&[0, 4, 1, 2]).unwrap());
    assert_eq!(gr(&env, 4), 0xf000_000f);
    x(&mut env, Insn::Or, encode_or(&[0, 4, 1, 2]).unwrap());
    assert_eq!(gr(&env, 4), 0xfff0_ff0f);
    x(&mut env, Insn::Xor, encode_xor(&[0, 4, 1, 2]).unwrap());
    assert_eq!(gr(&env, 4), 0xff00_f00f);
    // imm8 形: imm は符号拡張される。0x80 は -128。
    set_gr(&mut env, 3, 10);
    x(
        &mut env,
        Insn::AndImm8,
        encode_and_imm8(&[0, 4, 0x80, 3]).unwrap(),
    );
    assert_eq!(gr(&env, 4), 10u64 & 0xffff_ffff_ffff_ff80);
    x(
        &mut env,
        Insn::XorImm8,
        encode_xor_imm8(&[0, 4, 0x7f, 3]).unwrap(),
    );
    assert_eq!(gr(&env, 4), 10 ^ 0x7f);
    // NaT は r3 側のみ見る。
    sem::nat_set(&mut env.backend, 3, true);
    x(
        &mut env,
        Insn::AndImm8,
        encode_and_imm8(&[0, 5, 0x7f, 3]).unwrap(),
    );
    assert!(nat(&env, 5));
}

#[test]
fn addp4_and_shladd() {
    let mut env = env();
    // addp4: 下位 32 ビットの和、上位は r3{31:30} を {62:61} に移す。
    set_gr(&mut env, 1, 0xffff_ffff);
    set_gr(&mut env, 2, 0xc000_0002);
    x(&mut env, Insn::Addp4, encode_addp4(&[0, 4, 1, 2]).unwrap());
    // 0xffff_ffff + 0xc000_0002 = 0x1_c000_0001 → 下位 32 は 0xc000_0001、
    // r3{31:30}=3 → bits{62:61}=3。
    assert_eq!(gr(&env, 4), 0x6000_0000_c000_0001);
    // addp4_i も同じ後処理（imm14=1 + r3 として処理）。
    x(
        &mut env,
        Insn::Addp4I,
        encode_addp4_i(&[0, 4, 1, 2]).unwrap(),
    );
    assert_eq!(gr(&env, 4), 0x6000_0000_c000_0003);
    // shladd: (r2 << (cnt2a+1)) + r3。cnt2a=1 → 2 シフト。
    set_gr(&mut env, 5, 3);
    set_gr(&mut env, 6, 7);
    x(
        &mut env,
        Insn::Shladd,
        encode_shladd(&[0, 4, 5, 1, 6]).unwrap(),
    );
    assert_eq!(gr(&env, 4), 19);
    // shladdp4 は結果を addp4 後処理する。
    set_gr(&mut env, 6, 0x8000_0001);
    x(
        &mut env,
        Insn::Shladdp4,
        encode_shladdp4(&[0, 4, 5, 1, 6]).unwrap(),
    );
    // (3<<2)+0x80000001 = 0x8000000d → zext32 = 0x8000000d、
    // r3{31:30}=2 → bits62:61 = 2。
    assert_eq!(gr(&env, 4), 0x4000_0000_8000_000d);
}

#[test]
fn cmp_normal_and_unc() {
    let mut env = env();
    set_gr(&mut env, 10, 5);
    set_gr(&mut env, 11, 7);
    // cmp.lt: 5 < 7 → p5=1, p6=0。
    x(
        &mut env,
        Insn::CmpLt,
        encode_cmp_lt(&[0, 5, 6, 10, 11]).unwrap(),
    );
    assert!(p(&env, 5));
    assert!(!p(&env, 6));
    // 逆向き: 7 < 5 → p5=0, p6=1。
    x(
        &mut env,
        Insn::CmpLt,
        encode_cmp_lt(&[0, 5, 6, 11, 10]).unwrap(),
    );
    assert!(!p(&env, 5));
    assert!(p(&env, 6));
    // .unc は qp 偽でも p1=p2=0 に沈める。
    sem::pr_set(&mut env.backend, (1 << 5) | (1 << 6));
    let w = encode_cmp_lt_unc(&[9, 5, 6, 10, 11]).unwrap(); // (p9)
    x(&mut env, Insn::CmpLtUnc, w);
    assert!(!p(&env, 5));
    assert!(!p(&env, 6));
    // qp 真なら普通に評価する。
    sem::pr_set(&mut env.backend, 1 << 9);
    x(&mut env, Insn::CmpLtUnc, w);
    assert!(p(&env, 5));
    assert!(!p(&env, 6));
    // ソース NaT は p1=p2=0。
    sem::nat_set(&mut env.backend, 10, true);
    x(
        &mut env,
        Insn::CmpLt,
        encode_cmp_lt(&[0, 5, 6, 10, 11]).unwrap(),
    );
    assert!(!p(&env, 5));
    assert!(!p(&env, 6));
    // p1 == p2 は不正命令。
    assert_eq!(
        xerr(
            &mut env,
            Insn::CmpLt,
            encode_cmp_lt(&[0, 5, 5, 10, 11]).unwrap()
        ),
        sem::TRAP_ILL
    );
}

#[test]
fn cmp4_is_32bit_and_imm_forms() {
    let mut env = env();
    // cmp4 は下位 32 ビットだけを比べる。64 ビットでは 1 < 2 だが
    // 32 ビットでは -1 > ... ではなく 1 < 2 のまま。
    set_gr(&mut env, 10, 0xffff_ffff_0000_0001);
    set_gr(&mut env, 11, 2);
    x(
        &mut env,
        Insn::Cmp4Lt,
        encode_cmp4_lt(&[0, 5, 6, 10, 11]).unwrap(),
    );
    assert!(p(&env, 5));
    // 32 ビットの負数: 0xffff_ffff は -1 < 2 → p5=1（64 ビットなら偽）。
    set_gr(&mut env, 10, 0xffff_ffff);
    x(
        &mut env,
        Insn::Cmp4Lt,
        encode_cmp4_lt(&[0, 5, 6, 10, 11]).unwrap(),
    );
    assert!(p(&env, 5));
    // ltu imm8 形: 符号なしで imm8 vs r3。127 <u 5 は偽 → p6=1。
    set_gr(&mut env, 11, 5);
    x(
        &mut env,
        Insn::CmpLtuI,
        encode_cmp_ltu_i(&[0, 5, 6, 0x7f, 11]).unwrap(),
    );
    assert!(!p(&env, 5));
    assert!(p(&env, 6));
    x(
        &mut env,
        Insn::CmpLtuI,
        encode_cmp_ltu_i(&[0, 5, 6, 2, 11]).unwrap(),
    );
    assert!(p(&env, 5)); // 2 <u 5 → 真
    assert!(!p(&env, 6));
    // .unc の即値形も qp 偽でクリア。
    sem::pr_set(&mut env.backend, (1 << 5) | (1 << 6));
    x(
        &mut env,
        Insn::CmpLtUncI,
        encode_cmp_lt_unc_i(&[9, 5, 6, 0, 11]).unwrap(),
    );
    assert!(!p(&env, 5));
    assert!(!p(&env, 6));
    // cmp4.unc も同じく qp 偽クリア。
    sem::pr_set(&mut env.backend, (1 << 5) | (1 << 6));
    x(
        &mut env,
        Insn::Cmp4EqUnc,
        encode_cmp4_eq_unc(&[9, 5, 6, 10, 11]).unwrap(),
    );
    assert!(!p(&env, 5));
    assert!(!p(&env, 6));
}

#[test]
fn cmp_parallel_and_accumulating() {
    let mut env = env();
    set_gr(&mut env, 9, u64::MAX); // -1
    // 並列 and 形「a rel 0」疑似形式: cmp.lt.and = r9 < 0。
    sem::pr_set(&mut env.backend, (1 << 5) | (1 << 6));
    x(
        &mut env,
        Insn::CmpLtAnd,
        encode_cmp_lt_and(&[0, 5, 6, 9]).unwrap(),
    );
    assert!(p(&env, 5));
    assert!(p(&env, 6));
    // 偽なら両方 0 に沈む。
    set_gr(&mut env, 9, 3);
    x(
        &mut env,
        Insn::CmpLtAnd,
        encode_cmp_lt_and(&[0, 5, 6, 9]).unwrap(),
    );
    assert!(!p(&env, 5));
    assert!(!p(&env, 6));
    // .or 形: 真で両方 1、偽で据え置き。
    set_gr(&mut env, 9, u64::MAX);
    x(
        &mut env,
        Insn::CmpLtOr,
        encode_cmp_lt_or(&[0, 5, 6, 9]).unwrap(),
    );
    assert!(p(&env, 5));
    assert!(p(&env, 6));
    // 偽で据え置き（p7 は関係ないビットなので残る）。
    sem::pr_set(&mut env.backend, 1 << 7);
    set_gr(&mut env, 9, 4);
    x(
        &mut env,
        Insn::CmpLtOr,
        encode_cmp_lt_or(&[0, 5, 6, 9]).unwrap(),
    );
    assert!(p(&env, 5) || !p(&env, 6));
    assert!(p(&env, 7));
    // .or.andcm 形: 真で p1=1,p2=0。
    set_gr(&mut env, 9, u64::MAX);
    x(
        &mut env,
        Insn::CmpLtOrAndcm,
        encode_cmp_lt_or_andcm(&[0, 5, 6, 9]).unwrap(),
    );
    assert!(p(&env, 5));
    assert!(!p(&env, 6));
    // レジスタ形の .and は関係が eq/ne。
    set_gr(&mut env, 10, 5);
    set_gr(&mut env, 11, 5);
    sem::pr_set(&mut env.backend, (1 << 5) | (1 << 6));
    x(
        &mut env,
        Insn::CmpEqAnd,
        encode_cmp_eq_and(&[0, 5, 6, 10, 11]).unwrap(),
    );
    assert!(p(&env, 5));
    set_gr(&mut env, 11, 6);
    x(
        &mut env,
        Insn::CmpEqAnd,
        encode_cmp_eq_and(&[0, 5, 6, 10, 11]).unwrap(),
    );
    assert!(!p(&env, 5));
    assert!(!p(&env, 6));
    // .or.andcm レジスタ形。
    x(
        &mut env,
        Insn::CmpEqOrAndcm,
        encode_cmp_eq_or_andcm(&[0, 5, 6, 10, 10]).unwrap(),
    );
    assert!(p(&env, 5));
    assert!(!p(&env, 6));
}

#[test]
fn tbit_tnat_tf_predicates() {
    let mut env = env();
    set_gr(&mut env, 9, 1 << 40);
    // tbit.z: bit40=1 → z は偽 → p5=0,p6=1。
    x(
        &mut env,
        Insn::TbitZ,
        encode_tbit_z(&[0, 5, 6, 9, 40]).unwrap(),
    );
    assert!(!p(&env, 5));
    assert!(p(&env, 6));
    // tbit.z.unc は qp 偽でもクリア。
    sem::pr_set(&mut env.backend, (1 << 5) | (1 << 6));
    x(
        &mut env,
        Insn::TbitZUnc,
        encode_tbit_z_unc(&[9, 5, 6, 9, 40]).unwrap(),
    );
    assert!(!p(&env, 5));
    assert!(!p(&env, 6));
    // tbit.nz.and: bit40=1 → 真 → 据え置き。
    sem::pr_set(&mut env.backend, (1 << 5) | (1 << 6));
    x(
        &mut env,
        Insn::TbitNzAnd,
        encode_tbit_nz_and(&[0, 5, 6, 9, 40]).unwrap(),
    );
    assert!(p(&env, 5));
    assert!(p(&env, 6));
    // r9.nat が立つと .and は両方 0。
    sem::nat_set(&mut env.backend, 9, true);
    x(
        &mut env,
        Insn::TbitNzAnd,
        encode_tbit_nz_and(&[0, 5, 6, 9, 40]).unwrap(),
    );
    assert!(!p(&env, 5));
    assert!(!p(&env, 6));
    // tbit.nz.or.andcm: 真で p1=1,p2=0。
    sem::nat_set(&mut env.backend, 9, false);
    x(
        &mut env,
        Insn::TbitNzOrAndcm,
        encode_tbit_nz_or_andcm(&[0, 5, 6, 9, 40]).unwrap(),
    );
    assert!(p(&env, 5));
    assert!(!p(&env, 6));
    // tnat.z: r9.nat=0 → z は真 → p5=1,p6=0。
    x(&mut env, Insn::TnatZ, encode_tnat_z(&[0, 5, 6, 9]).unwrap());
    assert!(p(&env, 5));
    assert!(!p(&env, 6));
    // tnat.nz.and: nat=1 で真 → 据え置き。
    sem::nat_set(&mut env.backend, 9, true);
    sem::pr_set(&mut env.backend, (1 << 5) | (1 << 6));
    x(
        &mut env,
        Insn::TnatNzAnd,
        encode_tnat_nz_and(&[0, 5, 6, 9]).unwrap(),
    );
    assert!(p(&env, 5));
    assert!(p(&env, 6));
    // tf: features 32-63 は未定義で常に 0 → z は常に真。
    x(&mut env, Insn::TfZ, encode_tf_z(&[0, 5, 6, 0]).unwrap());
    assert!(p(&env, 5));
    assert!(!p(&env, 6));
}

#[test]
fn integer_shifts() {
    let mut env = env();
    set_gr(&mut env, 5, 1);
    set_gr(&mut env, 6, 4);
    x(&mut env, Insn::Shl, encode_shl(&[0, 4, 5, 6]).unwrap());
    assert_eq!(gr(&env, 4), 16);
    // count > 63 → 0。
    set_gr(&mut env, 6, 70);
    x(&mut env, Insn::Shl, encode_shl(&[0, 4, 5, 6]).unwrap());
    assert_eq!(gr(&env, 4), 0);
    // shr: オペランド順は [r1, r2(count), r3(data)]。
    set_gr(&mut env, 5, 0x8000_0000_0000_0000);
    set_gr(&mut env, 6, 4);
    x(&mut env, Insn::Shr, encode_shr(&[0, 4, 6, 5]).unwrap());
    assert_eq!(gr(&env, 4), 0xf800_0000_0000_0000);
    x(&mut env, Insn::ShrU, encode_shr_u(&[0, 4, 6, 5]).unwrap());
    assert_eq!(gr(&env, 4), 0x0800_0000_0000_0000);
    // shrp: [r2:r3] >> cnt6。cnt6=4。r2 の下位 nibble=0 なので上位 4 ビットは 0。
    set_gr(&mut env, 5, 0x1234_5678_9abc_def0);
    set_gr(&mut env, 6, 0x0fed_cba9_8765_4321);
    x(&mut env, Insn::Shrp, encode_shrp(&[0, 4, 5, 6, 4]).unwrap());
    assert_eq!(gr(&env, 4), 0x00fe_dcba_9876_5432);
    // cnt6=0 は r3 そのまま。
    x(&mut env, Insn::Shrp, encode_shrp(&[0, 4, 5, 6, 0]).unwrap());
    assert_eq!(gr(&env, 4), 0x0fed_cba9_8765_4321);
}

#[test]
fn extract_and_deposit() {
    let mut env = env();
    set_gr(&mut env, 5, 0xdead_beef_1234_5678);
    // extr: bits[15:4] = 0x567 → 符号つきは bit11 まで取ると…
    // pos=4,len=8 → 0x67 → sext 8 = 0x67。
    x(&mut env, Insn::Extr, encode_extr(&[0, 4, 5, 4, 7]).unwrap());
    assert_eq!(gr(&env, 4), 0x67);
    // pos=4,len=8 で先頭ビットが立つ例: pos=60,len=4 → 0xd…上位
    // 0xd = 1101 → sext4 = -3。
    x(
        &mut env,
        Insn::Extr,
        encode_extr(&[0, 4, 5, 60, 3]).unwrap(),
    );
    assert_eq!(gr(&env, 4), u64::MAX - 2);
    // extr.u はゼロ拡張。
    x(
        &mut env,
        Insn::ExtrU,
        encode_extr_u(&[0, 4, 5, 60, 3]).unwrap(),
    );
    assert_eq!(gr(&env, 4), 0xd);
    // pos+len が 64 を超えると切られる: pos=60,len=8 → len=4。
    x(
        &mut env,
        Insn::ExtrU,
        encode_extr_u(&[0, 4, 5, 60, 7]).unwrap(),
    );
    assert_eq!(gr(&env, 4), 0xd);
    // dep.z: pos=8,len=8（cpos6a=63-8=55、len6=7）で下位 8 ビットを置く。
    set_gr(&mut env, 5, 0xab);
    x(
        &mut env,
        Insn::DepZ,
        encode_dep_z(&[0, 4, 5, 55, 7]).unwrap(),
    );
    assert_eq!(gr(&env, 4), 0xab00);
    // dep.z imm8: 0x80 → -128 を len で切ると下位 8 ビット全部。
    x(
        &mut env,
        Insn::DepZImm,
        encode_dep_z_imm(&[0, 4, 0x80, 55, 7]).unwrap(),
    );
    assert_eq!(gr(&env, 4), 0x8000);
    // dep (merge): r3 の pos 近傍だけを r2 の右詰めフィールドで置く。
    set_gr(&mut env, 5, 0xab);
    set_gr(&mut env, 6, u64::MAX);
    // cpos6c=63-8=55、len4=7 → bits[15:8] = 0xab。
    x(
        &mut env,
        Insn::Dep,
        encode_dep(&[0, 4, 5, 6, 55, 7]).unwrap(),
    );
    assert_eq!(gr(&env, 4), 0xffff_ffff_ffff_abff);
    // dep imm1: 1 を 1 ビットだけ deposit。imm1=1 → -1 (全 1)。
    // pos=8,len=1 → bit8 = 1。
    set_gr(&mut env, 6, 0);
    x(
        &mut env,
        Insn::DepImm,
        encode_dep_imm(&[0, 4, 1, 6, 55, 0]).unwrap(),
    );
    assert_eq!(gr(&env, 4), 0x100);
    // NaT: merge 形は r2|r3、ゼロ形は r2 のみ。
    sem::nat_set(&mut env.backend, 6, true);
    x(
        &mut env,
        Insn::Dep,
        encode_dep(&[0, 4, 5, 6, 55, 7]).unwrap(),
    );
    assert!(nat(&env, 4));
    sem::nat_set(&mut env.backend, 6, false);
    x(
        &mut env,
        Insn::DepZ,
        encode_dep_z(&[0, 4, 5, 55, 7]).unwrap(),
    );
    assert!(!nat(&env, 4));
}

#[test]
fn extend_count_and_czx() {
    let mut env = env();
    set_gr(&mut env, 5, 0x0000_0000_ff12_3480);
    x(&mut env, Insn::Zxt2, encode_zxt2(&[0, 4, 5]).unwrap());
    assert_eq!(gr(&env, 4), 0x3480);
    x(&mut env, Insn::Sxt1, encode_sxt1(&[0, 4, 5]).unwrap());
    assert_eq!(gr(&env, 4), 0xffff_ffff_ffff_ff80);
    // czx1.l は MSB 側からゼロバイトを探す。byte7=0 → 0。
    set_gr(&mut env, 5, 0x00ff_eeff_1122_3344);
    x(&mut env, Insn::Czx1L, encode_czx1_l(&[0, 4, 5]).unwrap());
    assert_eq!(gr(&env, 4), 0);
    // czx1.r は LSB 側から。最初のゼロバイトは byte7 → 7。
    x(&mut env, Insn::Czx1R, encode_czx1_r(&[0, 4, 5]).unwrap());
    assert_eq!(gr(&env, 4), 7);
    // ゼロが無いと要素数（8）。
    set_gr(&mut env, 5, 0x0102_0304_0506_0708);
    x(&mut env, Insn::Czx1R, encode_czx1_r(&[0, 4, 5]).unwrap());
    assert_eq!(gr(&env, 4), 8);
    // popcnt。
    set_gr(&mut env, 5, 0xffff_0000_ffff_0000);
    x(&mut env, Insn::Popcnt, encode_popcnt(&[0, 4, 5]).unwrap());
    assert_eq!(gr(&env, 4), 32);
}

#[test]
fn parallel_alu_multimedia() {
    let mut env = env();
    let a = p16(1, 2, 0xffff, 0x8000);
    let c = p16(3, 0xfffe, 2, 1);
    set_gr(&mut env, 5, a);
    set_gr(&mut env, 6, c);
    // padd2: 要素ごとの 16 ビット加算（wrap）。
    x(&mut env, Insn::Padd2, encode_padd2(&[0, 4, 5, 6]).unwrap());
    assert_eq!(gr(&env, 4), p16(4, 0x10000 & 0xffff, 1, 0x8001));
    // pavg1: (a+b+1)/2 ではなく (a+b)>>1 | lsb。bytes 200,200 → 200。
    set_gr(&mut env, 5, p8([200, 10, 0, 0, 0, 0, 0, 0]));
    set_gr(&mut env, 6, p8([200, 21, 0, 0, 0, 0, 0, 0]));
    x(&mut env, Insn::Pavg1, encode_pavg1(&[0, 4, 5, 6]).unwrap());
    assert_eq!(gr(&env, 4), p8([200, (31 >> 1) | 1, 0, 0, 0, 0, 0, 0]));
    // pavg2.raz: (a+b+1)>>1。
    set_gr(&mut env, 5, p16(10, 0, 0, 0));
    set_gr(&mut env, 6, p16(11, 0, 0, 0));
    x(
        &mut env,
        Insn::Pavg2Raz,
        encode_pavg2_raz(&[0, 4, 5, 6]).unwrap(),
    );
    assert_eq!(gr(&env, 4), 11);
    // pavgsub1: 半分の差（9 ビットの 2 の補数で >>1）。
    set_gr(&mut env, 5, p8([10, 0, 0, 0, 0, 0, 0, 0]));
    set_gr(&mut env, 6, p8([20, 0, 0, 0, 0, 0, 0, 0]));
    x(
        &mut env,
        Insn::Pavgsub1,
        encode_pavgsub1(&[0, 4, 5, 6]).unwrap(),
    );
    // -10 → 0x1f6 & 0x1ff → >>1 |0 → 0xfb。
    assert_eq!(gr(&env, 4), 0xfb);
    // pcmp1.eq / pcmp2.gt。
    set_gr(&mut env, 5, p8([7, 8, 0, 0, 0, 0, 0, 0]));
    set_gr(&mut env, 6, p8([7, 9, 0, 0, 0, 0, 0, 0]));
    x(
        &mut env,
        Insn::Pcmp1Eq,
        encode_pcmp1_eq(&[0, 4, 5, 6]).unwrap(),
    );
    // byte0 は 7==7 → 0xff、byte1 は 8!=9 → 0、byte2-7 は 0==0 → 0xff。
    assert_eq!(gr(&env, 4), 0xffff_ffff_ffff_00ff);
    set_gr(&mut env, 5, p16(5, 0xfffe, 0, 0));
    set_gr(&mut env, 6, p16(4, 1, 0, 0));
    x(
        &mut env,
        Insn::Pcmp2Gt,
        encode_pcmp2_gt(&[0, 4, 5, 6]).unwrap(),
    );
    // elem0: 5>4 → 0xffff、elem1: -2>1 → 0、elem2-3: 0>0 → 0。
    assert_eq!(gr(&env, 4), 0xffff);
    assert_eq!((gr(&env, 4) >> 16) & 0xffff, 0); // -2 > 1 は偽
}

#[test]
fn parallel_shiftadd_saturation() {
    let mut env = env();
    // pshladd2: シフト飽和→加算飽和。cnt2b=0 → count=1。
    set_gr(&mut env, 5, p16(0x4000, 1, 0, 0));
    set_gr(&mut env, 6, p16(1, 0x7fff, 0, 0));
    x(
        &mut env,
        Insn::Pshladd2,
        encode_pshladd2(&[0, 4, 5, 0, 6]).unwrap(),
    );
    // 0x4000<<1 = 0x8000 → sat16 = 0x7fff; +1 → 0x7fff (飽和)。
    // 1<<1 = 2; +0x7fff = 0x8001 → sat16 = 0x7fff。
    assert_eq!(gr(&env, 4), p16(0x7fff, 0x7fff, 0, 0));
    // pshradd2: 算術右シフト→加算飽和。cnt2b=1 → count=2。
    set_gr(&mut env, 5, p16(0xfff0, 0x8000, 0, 0));
    set_gr(&mut env, 6, p16(1, 0, 0, 0));
    x(
        &mut env,
        Insn::Pshradd2,
        encode_pshradd2(&[0, 4, 5, 1, 6]).unwrap(),
    );
    // -16>>2 = -4; +1 = -3 = 0xfffd。-32768>>2 = -8192 = 0xe000。
    assert_eq!(gr(&env, 4), p16(0xfffd, 0xe000, 0, 0));
    // cnt2b=3 は予約 → 不正命令。
    assert_eq!(
        xerr(
            &mut env,
            Insn::Pshladd2,
            encode_pshladd2(&[0, 4, 5, 3, 6]).unwrap()
        ),
        sem::TRAP_ILL
    );
}

#[test]
fn parallel_shifts() {
    let mut env = env();
    set_gr(&mut env, 5, p16(1, 0x8000, 0xffff, 0x7fff));
    set_gr(&mut env, 6, 4);
    // pshl2 var: count=r6 min 16。
    x(&mut env, Insn::Pshl2, encode_pshl2(&[0, 4, 5, 6]).unwrap());
    assert_eq!(gr(&env, 4), p16(16, 0, 0xfff0, 0xfff0));
    // count > 16 → 16。
    set_gr(&mut env, 6, 20);
    x(&mut env, Insn::Pshl2, encode_pshl2(&[0, 4, 5, 6]).unwrap());
    assert_eq!(gr(&env, 4), 0);
    // pshr2 var: オペランド [r1, r2(count), r3(data)]。
    set_gr(&mut env, 6, 4);
    x(&mut env, Insn::Pshr2, encode_pshr2(&[0, 4, 6, 5]).unwrap());
    assert_eq!(gr(&env, 4), p16(0, 0xf800, 0xffff, 0x07ff));
    // pshr2.u 即値形: cnt5 直接値。
    x(
        &mut env,
        Insn::Pshr2UI,
        encode_pshr2_u_i(&[0, 4, 5, 4]).unwrap(),
    );
    assert_eq!(gr(&env, 4), p16(0, 0x0800, 0x0fff, 0x07ff));
    // pshl2 即値形: ccnt5 = 31-count。count=3 → 28。
    set_gr(&mut env, 5, p16(1, 2, 3, 4));
    x(
        &mut env,
        Insn::Pshl2I,
        encode_pshl2_i(&[0, 4, 5, 28]).unwrap(),
    );
    assert_eq!(gr(&env, 4), p16(8, 16, 24, 32));
}

#[test]
fn mux_mix_pack_unpack() {
    let mut env = env();
    let src = p8([7, 6, 5, 4, 3, 2, 1, 0]);
    set_gr(&mut env, 5, src);
    // mux1 @rev (mbtype4=0xb) はバイト順を逆転する。
    x(&mut env, Insn::Mux1, encode_mux1(&[0, 4, 5, 0xb]).unwrap());
    assert_eq!(gr(&env, 4), src.swap_bytes());
    // 予約された mbtype4 は不正命令フォールト。
    assert_eq!(
        xerr(&mut env, Insn::Mux1, encode_mux1(&[0, 4, 5, 1]).unwrap()),
        sem::TRAP_ILL
    );
    // mix1.l: 奇数要素同士を y→x で交互に並べる。y=0x11 連続、
    // x の奇数バイトは 6,4,2,0。
    set_gr(&mut env, 6, 0x1111_1111_1111_1111);
    x(&mut env, Insn::Mix1L, encode_mix1_l(&[0, 4, 5, 6]).unwrap());
    assert_eq!(gr(&env, 4), 0x0011_0211_0411_0611);
    // mix4.r: 偶数 32 ビット要素の y→x 交互。y0=0xdef0,x0=0x5678。
    set_gr(&mut env, 5, 0x0000_1234_0000_5678);
    set_gr(&mut env, 6, 0x0000_9abc_0000_def0);
    x(&mut env, Insn::Mix4R, encode_mix4_r(&[0, 4, 5, 6]).unwrap());
    assert_eq!(gr(&env, 4), 0x0000_5678_0000_def0);
    // unpack1.h: x/y の上位バイトを交互に。
    set_gr(&mut env, 5, 0xaa_bb_cc_dd_ee_ff_00_11);
    set_gr(&mut env, 6, 0x22_33_44_55_66_77_88_99);
    x(
        &mut env,
        Insn::Unpack1H,
        encode_unpack1_h(&[0, 4, 5, 6]).unwrap(),
    );
    assert_eq!(gr(&env, 4), 0xaa22_bb33_cc44_dd55);
    // unpack4.l: 32 ビット要素の下位同士。y0,x0。
    x(
        &mut env,
        Insn::Unpack4L,
        encode_unpack4_l(&[0, 4, 5, 6]).unwrap(),
    );
    assert_eq!(gr(&env, 4), 0xee_ff_00_11_66_77_88_99);
    // pack2.sss: 16 ビット符号つきを 8 ビット飽和。
    set_gr(&mut env, 5, p16(200, 0x8100, 0, 0));
    set_gr(&mut env, 6, p16(100, 0x7fff, 0, 0));
    x(
        &mut env,
        Insn::Pack2Sss,
        encode_pack2_sss(&[0, 4, 5, 6]).unwrap(),
    );
    // y: 100→100, 0x7fff→0x7f; x: 200→0x7f, -32512→0x80。
    assert_eq!(gr(&env, 4), p8([100, 0x7f, 0, 0, 0x7f, 0x80, 0, 0]));
    // pack2.uss: 負は 0 に飽和。
    set_gr(&mut env, 6, p16(0x8000, 300, 0, 0));
    x(
        &mut env,
        Insn::Pack2Uss,
        encode_pack2_uss(&[0, 4, 5, 6]).unwrap(),
    );
    assert_eq!(gr(&env, 4) & 0xffff, 0xff00); // -32768→0, 300→0xff
    // pack4.sss: 32 ビット → 16 ビット飽和。
    set_gr(&mut env, 5, 0x0000_0001_0000_0000); // x0=0, x1=1
    set_gr(&mut env, 6, 0x0000_0000_0000_7fff); // y0=0x7fff, y1=0
    x(
        &mut env,
        Insn::Pack4Sss,
        encode_pack4_sss(&[0, 4, 5, 6]).unwrap(),
    );
    // y0→0x7fff, y1→0, x0→0, x1→1（上位半分が r2 側）。
    assert_eq!(gr(&env, 4), p16(0x7fff, 0, 0, 1));
}

#[test]
fn pmin_pmax_psad_mpy() {
    let mut env = env();
    set_gr(&mut env, 5, p8([5, 200, 0, 0, 0, 0, 0, 0]));
    set_gr(&mut env, 6, p8([9, 100, 0, 0, 0, 0, 0, 0]));
    x(
        &mut env,
        Insn::Pmin1U,
        encode_pmin1_u(&[0, 4, 5, 6]).unwrap(),
    );
    assert_eq!(gr(&env, 4), p8([5, 100, 0, 0, 0, 0, 0, 0]));
    set_gr(&mut env, 5, p16(0xfffe, 5, 0, 0)); // -2, 5
    set_gr(&mut env, 6, p16(1, 0x8000, 0, 0)); // 1, -32768
    x(&mut env, Insn::Pmax2, encode_pmax2(&[0, 4, 5, 6]).unwrap());
    assert_eq!(gr(&env, 4), p16(1, 5, 0, 0));
    // psad1: 絶対差の和。
    set_gr(&mut env, 5, p8([10, 20, 0, 0, 0, 0, 0, 0]));
    set_gr(&mut env, 6, p8([30, 5, 0, 0, 0, 0, 0, 0]));
    x(&mut env, Insn::Psad1, encode_psad1(&[0, 4, 5, 6]).unwrap());
    assert_eq!(gr(&env, 4), 35);
    // mpy4: 32 ビット要素ごとの積の下位 32 ビット（Poulson）。
    set_gr(&mut env, 5, 0x0000_0004_0000_0003);
    set_gr(&mut env, 6, 0x0000_0005_0000_0006);
    x(&mut env, Insn::Mpy4, encode_mpy4(&[0, 4, 5, 6]).unwrap());
    assert_eq!(gr(&env, 4), 0x0000_0014_0000_0012);
    // pmpy2.r: 要素 0/2 の符号つき積を 32 ビットで置く。
    set_gr(&mut env, 5, p16(3, 0xffff, 5, 7));
    set_gr(&mut env, 6, p16(4, 2, 6, 8));
    x(
        &mut env,
        Insn::Pmpy2R,
        encode_pmpy2_r(&[0, 4, 5, 6]).unwrap(),
    );
    assert_eq!(gr(&env, 4), 0x0000_001e_0000_000c); // 5*6=30, 3*4=12
    // pmpy2.l: 要素 1/3。(-1)*2=-2、7*8=56。
    x(
        &mut env,
        Insn::Pmpy2L,
        encode_pmpy2_l(&[0, 4, 5, 6]).unwrap(),
    );
    assert_eq!(gr(&env, 4), 0x0000_0038_ffff_fffe);
    // pmpyshr2（ct2d=3 → count=16）: 積の上位 16 ビット。
    set_gr(&mut env, 5, p16(0x4000, 0x8000, 1, 0xffff));
    set_gr(&mut env, 6, p16(2, 2, 3, 4));
    x(
        &mut env,
        Insn::Pmpyshr2,
        encode_pmpyshr2(&[0, 4, 5, 6, 3]).unwrap(),
    );
    // 0x4000*2=0x8000→0、-32768*2=-65536→0xffff、3→0、-4→0xffff。
    assert_eq!(gr(&env, 4), p16(0, 0xffff, 0, 0xffff));
    // pmpyshr2.u（ct2d=0 → count=0）: 積の下位 16 ビット。
    x(
        &mut env,
        Insn::Pmpyshr2U,
        encode_pmpyshr2_u(&[0, 4, 5, 6, 0]).unwrap(),
    );
    // 0x8000、0x0000、3、0xfffc（0xffff*4 符号なし=0x3fffc→0xfffc）。
    assert_eq!(gr(&env, 4), p16(0x8000, 0, 3, 0xfffc));
}

#[test]
fn register_transfers() {
    let mut env = env();
    // mov r1 = ip: バンドルアドレス（下位 4 ビット 0）。
    sem::exec(
        &mut env.backend,
        Insn::MovIp,
        encode_mov_ip(&[0, 3]).unwrap(),
        0x12342,
    )
    .unwrap();
    assert_eq!(gr(&env, 3), 0x12340);
    // mov r1 = pr。
    sem::pr_set(&mut env.backend, (1 << 5) | (1 << 9));
    x(&mut env, Insn::MovPr, encode_mov_pr(&[0, 3]).unwrap());
    assert_eq!(gr(&env, 3), (1 << 5) | (1 << 9) | 1);
    // mov to pr: imm17 のマスクで r2 を PR へ写す。
    // mask17 の bits5,7 → m7a=0b1010000 → field = 0xa0。
    set_gr(&mut env, 2, (1 << 5) | (1 << 7));
    sem::pr_set(&mut env.backend, 0);
    x(
        &mut env,
        Insn::MovToPr,
        encode_mov_to_pr(&[0, 2, 0xa0]).unwrap(),
    );
    assert!(p(&env, 5));
    assert!(p(&env, 7));
    assert!(!p(&env, 6));
    assert!(p(&env, 0)); // p0 は常に 1
    // mov r1 = psr.um（sum/rum で書いた値が読める）。
    x(&mut env, Insn::Sum, encode_sum(&[0, 0b101011]).unwrap());
    x(
        &mut env,
        Insn::MovPsrUm,
        encode_mov_psr_um(&[0, 4]).unwrap(),
    );
    assert_eq!(gr(&env, 4), 0b101011);
    x(&mut env, Insn::Rum, encode_rum(&[0, 0b001010]).unwrap());
    x(
        &mut env,
        Insn::MovPsrUm,
        encode_mov_psr_um(&[0, 4]).unwrap(),
    );
    assert_eq!(gr(&env, 4), 0b100001);
    // mov.pr.rot: imm44（sext44）の bits16-63 を pr.rot に写す。
    // フィールド値 0x0fff_ffff_0000（bits{43:16}=1）→ sext44 で
    // 0xffff_ffff_ffff_0000 → p16-63 = 1。
    x(
        &mut env,
        Insn::MovPrRot,
        encode_mov_pr_rot(&[0, 0x0fff_ffff_0000]).unwrap(),
    );
    for i in 16..64 {
        assert!(p(&env, i), "p{i}");
    }
    // BR 転送。
    env.backend.set(sem::br_ref(3), 0x5000);
    x(
        &mut env,
        Insn::MovFromBr,
        encode_mov_from_br(&[0, 4, 3]).unwrap(),
    );
    assert_eq!(gr(&env, 4), 0x5000);
    set_gr(&mut env, 5, 0x6000);
    x(&mut env, Insn::MovBr, encode_mov_br(&[0, 2, 5, 0]).unwrap());
    assert_eq!(env.backend.get(sem::br_ref(2)), 0x6000);
    // mov.ret も BR 書き込み（ret の予報タグは無視）。
    x(
        &mut env,
        Insn::MovRet,
        encode_mov_ret(&[0, 2, 5, 0]).unwrap(),
    );
    assert_eq!(env.backend.get(sem::br_ref(2)), 0x6000);
    // ソース NaT は消費フォールト骨格 → TRAP_NAT。
    sem::nat_set(&mut env.backend, 5, true);
    assert_eq!(
        xerr(&mut env, Insn::MovBr, encode_mov_br(&[0, 2, 5, 0]).unwrap()),
        sem::TRAP_NAT
    );
}

#[test]
fn ar_transfers() {
    let mut env = env();
    // mov.i ar.lc = r10 → mov.i r11 = ar.lc の往復。
    set_gr(&mut env, 10, 1234);
    x(
        &mut env,
        Insn::MovIToAr,
        encode_mov_i_to_ar(&[0, 65, 10]).unwrap(),
    );
    x(
        &mut env,
        Insn::MovIFromAr,
        encode_mov_i_from_ar(&[0, 11, 65]).unwrap(),
    );
    assert_eq!(gr(&env, 11), 1234);
    // mov.m ar.ccv = r10 / mov.m r11 = ar.ccv。
    x(
        &mut env,
        Insn::MovMToAr,
        encode_mov_m_to_ar(&[0, 32, 10]).unwrap(),
    );
    x(
        &mut env,
        Insn::MovMFromAr,
        encode_mov_m_from_ar(&[0, 11, 32]).unwrap(),
    );
    assert_eq!(gr(&env, 11), 1234);
    // ar.itc は M 側から読める（既定 0）。
    env.backend.set(
        StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, itc)),
        0x777,
    );
    x(
        &mut env,
        Insn::MovMFromAr,
        encode_mov_m_from_ar(&[0, 11, 44]).unwrap(),
    );
    assert_eq!(gr(&env, 11), 0x777);
    // I 形式は pfs/lc/ec 以外を触れない（unat は M 専用）。
    assert_eq!(
        xerr(
            &mut env,
            Insn::MovIFromAr,
            encode_mov_i_from_ar(&[0, 11, 36]).unwrap()
        ),
        sem::TRAP_ILL
    );
    // ar.itc への書き込みは読み取り専用 → 不正。
    assert_eq!(
        xerr(
            &mut env,
            Insn::MovMToAr,
            encode_mov_m_to_ar(&[0, 44, 10]).unwrap()
        ),
        sem::TRAP_ILL
    );
    // ar.rsc へのユーザ書き込みはカーネル AR → フォールト。
    assert_eq!(
        xerr(
            &mut env,
            Insn::MovMToAr,
            encode_mov_m_to_ar(&[0, 16, 10]).unwrap()
        ),
        sem::TRAP_ILL
    );
    // bspstore 書き込みは bsp も更新される（rsc.mode=0 のとき）。
    x(
        &mut env,
        Insn::MovMToAr,
        encode_mov_m_to_ar(&[0, 18, 10]).unwrap(),
    );
    assert_eq!(
        env.backend
            .get(StateRef::<W64>::from_offset(core::mem::offset_of!(
                CpuState, bspstore
            ))),
        1234
    );
    assert_eq!(
        env.backend
            .get(StateRef::<W64>::from_offset(core::mem::offset_of!(
                CpuState, bsp
            ))),
        1234
    );
}

#[test]
fn predicated_group_step() {
    // MII: slot0 に cmp.eq（A 型は M スロットに置ける）、slot1 に
    // (p6) add、slot2 に (p7) add。1 群内で cmp の結果が述語として
    // 後続スロットへ届く。
    let mut env = run_env();
    sem::gr_set(&mut env.backend, 1, 40);
    sem::gr_set(&mut env.backend, 2, 40);
    let cmp = encode_cmp_eq(&[0, 6, 7, 1, 2]).unwrap() as u64;
    let add4 = encode_add(&[6, 4, 1, 2]).unwrap() as u64;
    let add5 = encode_add(&[7, 5, 1, 2]).unwrap() as u64;
    put_bundle(&mut env, BASE, mk_bundle(0, true, cmp, add4, add5));
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(sem::gr_get(&env.backend, 4), 80); // p6 成立 → 実行
    assert_eq!(sem::gr_get(&env.backend, 5), 0); // p7 不成立 → 抑止
    // 等しくない場合は逆。
    let mut env = run_env();
    sem::gr_set(&mut env.backend, 1, 40);
    sem::gr_set(&mut env.backend, 2, 41);
    put_bundle(&mut env, BASE, mk_bundle(0, true, cmp, add4, add5));
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(sem::gr_get(&env.backend, 4), 0);
    assert_eq!(sem::gr_get(&env.backend, 5), 81);
}

#[test]
fn m_unit_break_nop_extr_u() {
    // M43: nop.m / hint.m / break.m が M スロットで解読される。
    let w = encode_nop_m(&[0, 0x11]).unwrap();
    assert_eq!(bundle::decode_slot(Unit::M, w, CPU), Some(Insn::NopM));
    let w = encode_break_m(&[0, 0x123]).unwrap();
    assert_eq!(bundle::decode_slot(Unit::M, w, CPU), Some(Insn::BreakM));
    // 意味論: nop.m は無害、break.m は即値を code に載せる。
    let mut env = env();
    assert!(x(&mut env, Insn::NopM, encode_nop_m(&[0, 0]).unwrap()));
    assert!(x(&mut env, Insn::HintM, encode_hint_m(&[0, 0]).unwrap()));
    assert_eq!(
        xerr(&mut env, Insn::BreakM, encode_break_m(&[0, 0x123]).unwrap()),
        0x123
    );
    // extr.u は I スロットで解読・逆アセンブルされる。
    let w = encode_extr_u(&[0, 4, 5, 8, 7]).unwrap();
    assert_eq!(bundle::decode_slot(Unit::I, w, CPU), Some(Insn::ExtrU));
    let t = disasm_word_ex(w, 41, true, CPU | FEAT_UNIT_I | FEAT_UNIT_A).unwrap();
    assert!(t.contains("extr.u"), "{t}");
    // .unc の逆アセンブルは単一の点（..unc にならない）。
    let w = encode_cmp_lt_unc(&[0, 5, 6, 10, 11]).unwrap();
    let t = disasm_word_ex(w, 41, true, CPU | FEAT_UNIT_I | FEAT_UNIT_A).unwrap();
    assert!(t.contains("cmp.lt.unc"), "{t}");
    assert!(!t.contains(".."), "{t}");
}
