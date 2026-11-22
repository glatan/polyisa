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
    encode_brl_cond_sptk_few, encode_cmp_lt_or, encode_fma_s0, encode_hint_f, encode_ld4,
    encode_mov_ip, encode_movl, encode_nop_f, encode_nop_i, encode_nop_x, encode_padd1,
    encode_pcmp4_eq, encode_psub1, encode_st4, encode_sub_imm8, extract_ops, sem,
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
    assert_eq!(core::mem::size_of::<CpuState>(), cfm + 16 + 32 * 8 + 8);
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
    let e = sem::exec(&mut env.backend, Insn::Add, 0, 0).unwrap_err();
    assert!(matches!(e, InterpExit::Unimplemented(_)));
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
