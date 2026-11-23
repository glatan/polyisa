// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Hexagon 骨格の最小テスト。CpuState の構成・述語の規則・
//! パケット未確定域（pkt_*）の commit と .new 転送、dot-if
//! 抑制の入口を確かめる。
//! 出典は SPEC-HEXAGON-PRM V79 (80-N2040-60 Rev AB) である。
//! Ref: SPEC-HEXAGON-PRM (V79).

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::InterpExit;
use polyisa_guest_hexagon::packet::{self, ComposeError, Group, Kind, SplitError};
use polyisa_guest_hexagon::{
    CpuState, Insn, cnum, decode, decode_model_ex, disasm_word_ex, encode, extract_ops, sem,
};

fn env() -> BareEnv {
    BareEnv::new(core::mem::size_of::<CpuState>())
}

#[test]
fn state_layout_pinned() {
    assert_eq!(core::mem::offset_of!(CpuState, r), 0);
    assert_eq!(core::mem::offset_of!(CpuState, p), 32 * 4);
    let pc = 32 * 4 + 4;
    assert_eq!(core::mem::offset_of!(CpuState, pc), pc);
    assert_eq!(core::mem::offset_of!(CpuState, sa0), pc + 4);
    assert_eq!(core::mem::offset_of!(CpuState, lc0), pc + 8);
    assert_eq!(core::mem::offset_of!(CpuState, sa1), pc + 12);
    assert_eq!(core::mem::offset_of!(CpuState, lc1), pc + 16);
    assert_eq!(core::mem::offset_of!(CpuState, m0), pc + 20);
    assert_eq!(core::mem::offset_of!(CpuState, m1), pc + 24);
    assert_eq!(core::mem::offset_of!(CpuState, usr), pc + 28);
    assert_eq!(core::mem::offset_of!(CpuState, ugp), pc + 32);
    assert_eq!(core::mem::offset_of!(CpuState, gp), pc + 36);
    assert_eq!(core::mem::offset_of!(CpuState, cs0), pc + 40);
    assert_eq!(core::mem::offset_of!(CpuState, cs1), pc + 44);
    assert_eq!(core::mem::offset_of!(CpuState, hwt), pc + 48);
    assert_eq!(core::mem::offset_of!(CpuState, endloop), pc + 52);
    let pkt = pc + 56;
    assert_eq!(core::mem::offset_of!(CpuState, pkt_r), pkt);
    assert_eq!(core::mem::offset_of!(CpuState, pkt_r_ok), pkt + 32 * 4);
    assert_eq!(core::mem::offset_of!(CpuState, pkt_p), pkt + 32 * 4 + 4);
    assert_eq!(core::mem::offset_of!(CpuState, pkt_p_ok), pkt + 32 * 4 + 8);
    let prod = pkt + 32 * 4 + 12;
    assert_eq!(core::mem::offset_of!(CpuState, pkt_prod), prod);
    assert_eq!(core::mem::offset_of!(CpuState, nv_pos), prod + 16);
    assert_eq!(core::mem::size_of::<CpuState>(), prod + 20);
}

#[test]
fn predicate_bytes() {
    let mut env = env();
    // p_i は P3:0 のバイト i。比較結果は 0xff/0x00。
    sem::p_set(&mut env.backend, 1, 0xff);
    sem::p_set(&mut env.backend, 3, 0x01);
    assert!(sem::pred(&env.backend, 1));
    assert!(sem::pred(&env.backend, 3));
    assert!(!sem::pred(&env.backend, 0));
    // P3:0 は制御レジスタ c4 としても見える。
    assert_eq!(
        sem::c_get(&env.backend, cnum::P3_0.into()).unwrap(),
        0x01_00_ff_00
    );
}

#[test]
fn control_register_map() {
    let mut env = env();
    sem::c_set(&mut env.backend, cnum::SA0.into(), 0x1000).unwrap();
    sem::c_set(&mut env.backend, cnum::LC0.into(), 4).unwrap();
    sem::c_set(&mut env.backend, cnum::GP.into(), 0x8000).unwrap();
    sem::c_set(&mut env.backend, cnum::USR.into(), 1).unwrap();
    assert_eq!(sem::c_get(&env.backend, cnum::SA0.into()).unwrap(), 0x1000);
    assert_eq!(sem::c_get(&env.backend, cnum::LC0.into()).unwrap(), 4);
    assert_eq!(sem::c_get(&env.backend, cnum::GP.into()).unwrap(), 0x8000);
    assert_eq!(sem::c_get(&env.backend, cnum::USR.into()).unwrap(), 1);
    // PC は書き込み不可、未収録の番号は不正。
    assert!(sem::c_set(&mut env.backend, cnum::PC.into(), 0).is_err());
    assert!(sem::c_get(&env.backend, 20).is_err());
}

#[test]
fn packet_buffers_until_commit() {
    let mut env = env();
    sem::r_set(&mut env.backend, 1, 10);
    // 未確定域に書いても確定値は変わらず、commit でまとめて映る。
    sem::pkt_w(&mut env.backend, 3, 30);
    sem::pkt_w(&mut env.backend, 4, 40);
    assert_eq!(sem::r_get(&env.backend, 3), 0);
    sem::commit(&mut env.backend).unwrap();
    assert_eq!(sem::r_get(&env.backend, 3), 30);
    assert_eq!(sem::r_get(&env.backend, 4), 40);
    assert_eq!(sem::r_get(&env.backend, 1), 10);
    // 述語も同じ。
    sem::pkt_pw(&mut env.backend, 2, 0xff);
    assert!(!sem::pred(&env.backend, 2));
    sem::commit(&mut env.backend).unwrap();
    assert!(sem::pred(&env.backend, 2));
}

#[test]
fn new_reads_packet_temp() {
    let mut env = env();
    // パケット内の生産値を .new で読む。commit 後は生産が消える。
    assert_eq!(sem::r_new(&env.backend, 3), None);
    sem::pkt_w(&mut env.backend, 3, 30);
    assert_eq!(sem::r_new(&env.backend, 3), Some(30));
    sem::commit(&mut env.backend).unwrap();
    assert_eq!(sem::r_new(&env.backend, 3), None);
    // pX.new も同じ。
    sem::pkt_pw(&mut env.backend, 0, 0xff);
    assert_eq!(sem::p_new(&env.backend, 0), Some(true));
}

#[test]
fn dotif_suppresses() {
    let mut env = env();
    sem::p_set(&mut env.backend, 0, 0xff);
    let with = |cond: Option<sem::DotIf>| sem::Ctx {
        cond,
        ..sem::Ctx::default()
    };
    // if (p0) は真で抑制しない（命令の意味論に達する）。
    let c = sem::DotIf {
        p: 0,
        neg: false,
        new: false,
    };
    let e = sem::exec(&mut env.backend, Insn::Trap0, 1, with(Some(c))).unwrap_err();
    assert!(matches!(e, InterpExit::Exception(_)));
    // if (!p0) は偽なので抑制される。
    let c = sem::DotIf {
        p: 0,
        neg: true,
        new: false,
    };
    assert_eq!(
        sem::exec(&mut env.backend, Insn::Nop, 0, with(Some(c))),
        Ok(false)
    );
    // if (p1) で p1 未設定は抑制される。
    let c = sem::DotIf {
        p: 1,
        neg: false,
        new: false,
    };
    assert_eq!(
        sem::exec(&mut env.backend, Insn::Nop, 0, with(Some(c))),
        Ok(false)
    );
}

// ---- HX3: パケット層のテスト ----

/// Parse 桁を任意値に置き換えた語を作る。
fn with_pp(word: u32, pp: u32) -> u32 {
    (word & !0xc000) | ((pp & 3) << 14)
}

const NOP: u32 = 0x7f00_0000; // nop（pp は with_pp で付ける）
const ADD_RI: u32 = 0xb004_00a3; // r3 = add(r4,#5)
const LDW: u32 = 0x9184_0003; // r3 = memw(r4+#0)
const STW: u32 = 0xa184_0500; // memw(r4+#0) = r5
const JUMPR: u32 = 0x5284_0000; // jumpr r4
const JUMP: u32 = 0x5800_0004; // jump #8
const IFP0JUMP: u32 = 0x5c00_0004; // if (p0) jump #8
const CALLR: u32 = 0x50a0_0000; // callr r0
const RDCR: u32 = 0x6a08_0003; // r3 = c8

#[test]
fn split_lengths() {
    // 1–4 語のパケット。
    for (n, pps) in [
        (1, &[3][..]),
        (2, &[1, 3][..]),
        (3, &[1, 1, 3][..]),
        (4, &[1, 1, 1, 3][..]),
    ] {
        let words: Vec<u32> = pps.iter().map(|&pp| with_pp(NOP, pp)).collect();
        let (pkt, used) = packet::split(&words).unwrap();
        assert_eq!(pkt.words.len(), n);
        assert_eq!(used, n);
        assert_eq!(pkt.endloop, 0);
        assert!(pkt.words.iter().all(|w| w.kind == Kind::Insn));
    }
    // 終端後の語は次パケットに残る。
    let words = [with_pp(NOP, 3), with_pp(NOP, 3)];
    let (pkt, used) = packet::split(&words).unwrap();
    assert_eq!(pkt.words.len(), 1);
    assert_eq!(used, 1);
}

#[test]
fn split_loop_markers() {
    // endloop0 は 1 語目の Parse 10（2 語以上）。
    let (pkt, _) = packet::split(&[with_pp(NOP, 2), with_pp(NOP, 3)]).unwrap();
    assert_eq!(pkt.endloop, 1);
    // endloop1 は 2 語目の Parse 10（3 語以上）。
    let (pkt, _) = packet::split(&[with_pp(NOP, 1), with_pp(NOP, 2), with_pp(NOP, 3)]).unwrap();
    assert_eq!(pkt.endloop, 2);
    // 両方。
    let (pkt, _) = packet::split(&[with_pp(NOP, 2), with_pp(NOP, 2), with_pp(NOP, 3)]).unwrap();
    assert_eq!(pkt.endloop, 3);
    // 4 語版。
    let (pkt, _) = packet::split(&[
        with_pp(NOP, 1),
        with_pp(NOP, 2),
        with_pp(NOP, 1),
        with_pp(NOP, 3),
    ])
    .unwrap();
    assert_eq!(pkt.endloop, 2);
}

#[test]
fn split_errors() {
    // 終端なし。
    assert_eq!(
        packet::split(&[with_pp(NOP, 1)]).unwrap_err(),
        SplitError::Unterminated
    );
    // 4 語連続で終端がない。
    let words = [with_pp(NOP, 1); 4];
    assert_eq!(packet::split(&words).unwrap_err(), SplitError::Unterminated);
    // 空列。
    assert_eq!(packet::split(&[]).unwrap_err(), SplitError::Unterminated);
    // Parse 10 は 3 語目以降に置けない。
    let words = [
        with_pp(NOP, 1),
        with_pp(NOP, 1),
        with_pp(NOP, 2),
        with_pp(NOP, 3),
    ];
    assert_eq!(
        packet::split(&words).unwrap_err(),
        SplitError::BadLoopMarker
    );
    // 予約の duplex ICLASS（0xF = [31:29]111 + bit13=1）。
    assert_eq!(
        packet::split(&[0xe000_2000]).unwrap_err(),
        SplitError::BadDuplexClass
    );
}

#[test]
fn duplex_extract() {
    // { r3 = memw(r4+#0) ; r0 = add(r0,#0) } の L1/A duplex
    // （llvm-mc 実符号 0x40000043）。
    let w = 0x4000_0043;
    assert_eq!(packet::duplex_iclass(w), 4);
    assert_eq!(packet::duplex_groups(w), Some((Group::L1, Group::A)));
    let (lo, hi) = packet::duplex_subs(w);
    assert_eq!(lo, 0x0043);
    assert_eq!(hi, 0x0000);
    let (pkt, used) = packet::split(&[w]).unwrap();
    assert_eq!(used, 1);
    assert_eq!(
        pkt.words[0].kind,
        Kind::Duplex {
            lo: Group::L1,
            hi: Group::A
        }
    );
    // pack_duplex の往復。
    let p = packet::pack_duplex(0x0043, 0x0000, Group::L1, Group::A).unwrap();
    assert_eq!(p, w);
    // S2/A（memd(r29+#16)=r5:4 の 0x60002a12）。
    let p = packet::pack_duplex(0x0a12, 0x0000, Group::S2, Group::A).unwrap();
    assert_eq!(p, 0x6000_2a12);
    // 表にない組合せは組めない。
    assert!(packet::pack_duplex(0, 0, Group::A, Group::L1).is_none());
    assert!(packet::pack_duplex(0, 0, Group::L1, Group::S2).is_none());
}

#[test]
fn subinsn_decode() {
    // 13 ビット語はグループ文脈旗付きで decode_model_ex に通す。
    assert_eq!(
        packet::decode_sub(Group::L1, 0x0043, 0),
        Some(Insn::DxL1Memw)
    );
    assert_eq!(
        packet::decode_sub(Group::L1, 0x1843, 0),
        Some(Insn::DxL1Memub)
    );
    assert_eq!(
        packet::decode_sub(Group::L2, 0x0210, 0),
        Some(Insn::DxL2Memh)
    );
    assert_eq!(
        packet::decode_sub(Group::L2, 0x0a10, 0),
        Some(Insn::DxL2Memuh)
    );
    assert_eq!(
        packet::decode_sub(Group::L2, 0x1c45, 0),
        Some(Insn::DxL2Ldwsp)
    );
    assert_eq!(
        packet::decode_sub(Group::L2, 0x1f00, 0),
        Some(Insn::DxL2Deallocframe)
    );
    assert_eq!(
        packet::decode_sub(Group::L2, 0x1f40, 0),
        Some(Insn::DxL2Deallocret)
    );
    assert_eq!(
        packet::decode_sub(Group::L2, 0x1f44, 0),
        Some(Insn::DxL2Deallocret)
    );
    // 述語選択桁 1-3 は未割当で拒否。
    assert_eq!(packet::decode_sub(Group::L2, 0x1f41, 0), None);
    assert_eq!(packet::decode_sub(Group::L2, 0x1fc1, 0), None);
    assert_eq!(
        packet::decode_sub(Group::L2, 0x1fc4, 0),
        Some(Insn::DxL2Jumpr)
    );
    assert_eq!(
        packet::decode_sub(Group::S1, 0x0245, 0),
        Some(Insn::DxS1Memw)
    );
    assert_eq!(
        packet::decode_sub(Group::S2, 0x0245, 0),
        Some(Insn::DxS2Memh)
    );
    assert_eq!(
        packet::decode_sub(Group::S2, 0x0a12, 0),
        Some(Insn::DxS2Stdsp)
    );
    assert_eq!(
        packet::decode_sub(Group::S2, 0x1c20, 0),
        Some(Insn::DxS2Allocframe)
    );
    assert_eq!(packet::decode_sub(Group::A, 0x0031, 0), Some(Insn::DxAAddi));
    assert_eq!(packet::decode_sub(Group::A, 0x0941, 0), Some(Insn::DxAUimm));
    assert_eq!(
        packet::decode_sub(Group::A, 0x0c20, 0),
        Some(Insn::DxASpadd)
    );
    assert_eq!(packet::decode_sub(Group::A, 0x1322, 0), Some(Insn::DxASub1));
    assert_eq!(
        packet::decode_sub(Group::A, 0x1930, 0),
        Some(Insn::DxACmpeq)
    );
    assert_eq!(packet::decode_sub(Group::A, 0x1a4b, 0), Some(Insn::DxAClr));
    assert_eq!(
        packet::decode_sub(Group::A, 0x1c70, 0),
        Some(Insn::DxACombi)
    );
    assert_eq!(
        packet::decode_sub(Group::A, 0x1d30, 0),
        Some(Insn::DxAComb0)
    );
    assert_eq!(
        packet::decode_sub(Group::A, 0x1d38, 0),
        Some(Insn::DxAComb1)
    );
    // A 型で未割当の [11:8]=1011 はデコードできない。
    assert_eq!(packet::decode_sub(Group::A, 0x1b00, 0), None);
    // 文脈旗がないと dx_* はデコードできない。
    assert_eq!(decode_model_ex(0x0043, 13, true, 0), None);
}

#[test]
fn insn32_decode() {
    assert_eq!(decode(0xb004_c0a3, 32), Some(Insn::AddRi));
    assert_eq!(extract_ops(Insn::AddRi, 0xb004_c0a3), vec![3, 4, 5]);
    assert_eq!(decode(0xf304_c503, 32), Some(Insn::AddRr));
    assert_eq!(extract_ops(Insn::AddRr, 0xf304_c503), vec![3, 4, 5]);
    assert_eq!(decode(0x7f00_c000, 32), Some(Insn::Nop));
    assert_eq!(decode(0x7809_c683, 32), Some(Insn::EqS16));
    assert_eq!(extract_ops(Insn::EqS16, 0x7809_c683), vec![3, 0x1234]);
    assert_eq!(decode(0x9184_c003, 32), Some(Insn::LdRi));
    // ops は [d, s, sz3, 生即値]（sz3=4 が memw、生値 0）。
    assert_eq!(extract_ops(Insn::LdRi, 0x9184_c003), vec![3, 4, 4, 0]);
    // scaled 即値（#1024 → 生値 256。<<2 は実行側で掛ける）。
    assert_eq!(extract_ops(Insn::LdRi, 0x9184_e003), vec![3, 4, 4, 256]);
    assert_eq!(decode(0xa184_c500, 32), Some(Insn::StRi));
    assert_eq!(extract_ops(Insn::StRi, 0xa184_c500), vec![4, 5, 4, 0]);
    // ST の負の scaled 即値（#-8 → 生値 0x7fe）。
    assert_eq!(extract_ops(Insn::StRi, 0xa784_e5fe), vec![4, 5, 4, 0x7fe]);
    assert_eq!(decode(0x5800_c004, 32), Some(Insn::JumpPcrel));
    assert_eq!(extract_ops(Insn::JumpPcrel, 0x5800_c004), vec![8]);
    assert_eq!(decode(0x5a00_c004, 32), Some(Insn::CallPcrel));
    assert_eq!(decode(0x5284_c000, 32), Some(Insn::Jumpr));
    assert_eq!(extract_ops(Insn::Jumpr, 0x5284_c000), vec![4]);
    assert_eq!(decode(0x6a08_c003, 32), Some(Insn::Rdcr));
    assert_eq!(extract_ops(Insn::Rdcr, 0x6a08_c003), vec![3, 8]);
    assert_eq!(decode(0x6223_c008, 32), Some(Insn::Wrcr));
    assert_eq!(decode(0xf203_c400, 32), Some(Insn::CmpeqRr));
    assert_eq!(extract_ops(Insn::CmpeqRr, 0xf203_c400), vec![0, 3, 4]);
    assert_eq!(decode(0xf243_c400, 32), Some(Insn::CmpgtRr));
    assert_eq!(decode(0x0123_5159, 32), Some(Insn::Immext));
    assert_eq!(extract_ops(Insn::Immext, 0x0123_5159), vec![0x048d159]);
}

#[test]
fn encode_decode_roundtrip() {
    // エンコーダは Parse 桁を書かないため pp=3 を足して復号する。
    let rt = |insn: Insn, ops: &[u64]| {
        let w = encode(insn, ops).expect("encode") as u32;
        assert_eq!(decode(with_pp(w, 3).into(), 32), Some(insn));
        w
    };
    let w = rt(Insn::AddRi, &[3, 4, 5]);
    assert_eq!(w & !0xc000, 0xb004_00a3);
    let w = rt(Insn::AddRr, &[3, 4, 5]);
    assert_eq!(w & !0xc000, 0xf304_0503);
    let w = rt(Insn::EqS16, &[3, 0x1234]);
    assert_eq!(w & !0xc000, 0x7809_0683);
    let w = rt(Insn::LdRi, &[3, 4, 4, 256]);
    assert_eq!(extract_ops(Insn::LdRi, u128::from(w)), vec![3, 4, 4, 256]);
    let w = rt(Insn::StRi, &[4, 5, 4, 4]);
    assert_eq!(extract_ops(Insn::StRi, u128::from(w)), vec![4, 5, 4, 4]);
    rt(Insn::Nop, &[]);
    rt(Insn::Jumpr, &[4]);
    rt(Insn::CmpeqRr, &[1, 3, 4]);
    rt(Insn::Immext, &[0x048d159]);
    // 13 ビット subinsn の往復。
    let rt13 = |insn: Insn, ops: &[u64], g: Group| {
        let w = encode(insn, ops).expect("encode13") as u16;
        assert_eq!(packet::decode_sub(g, w, 0), Some(insn));
        w
    };
    assert_eq!(rt13(Insn::DxL1Memw, &[3, 4, 0], Group::L1), 0x0043);
    assert_eq!(rt13(Insn::DxASub1, &[2, 2], Group::A), 0x1322);
    assert_eq!(rt13(Insn::DxACmpeq, &[3, 0], Group::A), 0x1930);
    rt13(Insn::DxS2Stwsp, &[3, 5], Group::S2);
    rt13(Insn::DxACombi, &[0, 2, 3], Group::A);
}

#[test]
fn extender_pairing() {
    // { r3 = add(r4,##0x12345678) }（llvm-mc 実符号）。
    let ext = 0x0123_5159;
    let base = 0xb004_c703;
    let (pkt, used) = packet::split(&[ext, base]).unwrap();
    assert_eq!(used, 2);
    assert_eq!(pkt.words[0].kind, Kind::Extender);
    assert_eq!(pkt.words[1].kind, Kind::Insn);
    let slots = packet::expand(&pkt).unwrap();
    assert_eq!(slots.len(), 1);
    assert_eq!(slots[0].word as u32, base);
    assert_eq!(slots[0].ext, Some(0x048d159));
    assert_eq!(slots[0].slot, 3); // ALU32 は最上位スロットへ
    // 26 ビット拡張値と基底即値の下位 6 ビットを併合。
    let imm6 = extract_ops(Insn::AddRi, u128::from(base))[2] as u32 & 0x3f;
    assert_eq!(packet::apply_ext(0x048d159, imm6), 0x1234_5678);
}

#[test]
fn extender_errors() {
    // 終端語が extender（対象命令がない）。
    let (pkt, _) = packet::split(&[with_pp(0x0123_0000, 3)]).unwrap();
    assert_eq!(
        packet::expand(&pkt).unwrap_err(),
        ComposeError::TrailingExtender
    );
    // extender 2 連続。
    let (pkt, _) = packet::split(&[with_pp(0x0123_0000, 1), with_pp(0x0123_0000, 3)]).unwrap();
    assert_eq!(
        packet::expand(&pkt).unwrap_err(),
        ComposeError::DoubleExtender
    );
    // duplex の hi subinsn が拡張不能な形（mov）のとき拒否。
    let dup = packet::pack_duplex(0x1010, 0x1010, Group::A, Group::A).unwrap();
    let (pkt, _) = packet::split(&[with_pp(0x0123_0000, 1), dup]).unwrap();
    assert_eq!(
        packet::expand(&pkt).unwrap_err(),
        ComposeError::ExtenderBeforeDuplex
    );
}

#[test]
fn extender_before_duplex() {
    // extender は duplex の slot1 subinsn（A-type の add/uimm 形）に
    // 適用できる（llvm-mc 実符号 { r1 = add(r1,##..) ; r0 = add(r0,#1) }
    // → 01235159 23813100）。
    let dup = packet::pack_duplex(0x1100, 0x0381, Group::A, Group::A).unwrap();
    assert_eq!(dup, 0x2381_3100);
    let (pkt, _) = packet::split(&[0x0123_5159, dup]).unwrap();
    let slots = packet::expand(&pkt).unwrap();
    assert_eq!(slots.len(), 2);
    assert_eq!(slots[0].slot, 1);
    assert_eq!(slots[0].ext, Some(0x048d159));
    assert_eq!(slots[1].slot, 0);
    assert_eq!(slots[1].ext, None);
}

#[test]
fn slot_assignment() {
    // 単独命令は許容スロットの最上位へ。
    let (pkt, _) = packet::split(&[with_pp(ADD_RI, 3)]).unwrap();
    let s = packet::expand(&pkt).unwrap();
    assert_eq!(s[0].slot, 3); // ALU32
    let (pkt, _) = packet::split(&[with_pp(LDW, 3)]).unwrap();
    let s = packet::expand(&pkt).unwrap();
    assert_eq!(s[0].slot, 0); // 単独 LD は slot0 固定
    let (pkt, _) = packet::split(&[with_pp(JUMPR, 3)]).unwrap();
    let s = packet::expand(&pkt).unwrap();
    assert_eq!(s[0].slot, 2); // JR は slot 2 固定
    let (pkt, _) = packet::split(&[with_pp(JUMP, 3)]).unwrap();
    let s = packet::expand(&pkt).unwrap();
    assert_eq!(s[0].slot, 3); // J は {2,3} の上位
    let (pkt, _) = packet::split(&[with_pp(CALLR, 3)]).unwrap();
    let s = packet::expand(&pkt).unwrap();
    assert_eq!(s[0].slot, 2); // callr も JR 系で slot 2 固定
    let (pkt, _) = packet::split(&[with_pp(RDCR, 3)]).unwrap();
    let s = packet::expand(&pkt).unwrap();
    assert_eq!(s[0].slot, 3); // CR は slot3 固定
    // { J ; ALU32 }（メモリ順 = slot3 → slot0 の単調減少）。
    let (pkt, _) = packet::split(&[with_pp(JUMP, 1), with_pp(ADD_RI, 3)]).unwrap();
    let s = packet::expand(&pkt).unwrap();
    assert_eq!((s[0].slot, s[1].slot), (3, 2));
    // { JR ; ALU32 } → JR は slot 2 固定で ALU32 は下位へ。
    let (pkt, _) = packet::split(&[with_pp(JUMPR, 1), with_pp(ADD_RI, 3)]).unwrap();
    let s = packet::expand(&pkt).unwrap();
    assert_eq!((s[0].slot, s[1].slot), (2, 1));
    // { ALU32 ; LD } → LD が slot0、ALU32 は上位へ。
    let (pkt, _) = packet::split(&[with_pp(ADD_RI, 1), with_pp(LDW, 3)]).unwrap();
    let s = packet::expand(&pkt).unwrap();
    assert_eq!((s[0].slot, s[1].slot), (3, 0));
    // { LD ; ALU32 } は slot の単調減少が組めず拒否。
    let (pkt, _) = packet::split(&[with_pp(LDW, 1), with_pp(ADD_RI, 3)]).unwrap();
    assert_eq!(
        packet::expand(&pkt).unwrap_err(),
        ComposeError::NoSlotAssign
    );
    // { ALU32 ; duplex(S1 ストア, A) } → subinsn は slot1/slot0 固定。
    let dup = packet::pack_duplex(0x0245, 0x1322, Group::S1, Group::A).unwrap();
    let (pkt, _) = packet::split(&[with_pp(ADD_RI, 1), dup]).unwrap();
    let s = packet::expand(&pkt).unwrap();
    assert_eq!((s[0].slot, s[1].slot, s[2].slot), (3, 1, 0));
    // duplex の hi が jumpr R31 なら拒否（slot0 固定のため）。
    let dup = packet::pack_duplex(0x0245, 0x1fc0, Group::S1, Group::L2).unwrap();
    let (pkt, _) = packet::split(&[dup]).unwrap();
    assert_eq!(packet::expand(&pkt).unwrap_err(), ComposeError::JumpRSlot);
    // 同一グループの数値順規則（A/A: slot1 が小さい側）。
    // add1(0x1100→key 0x1100) を slot0、mov(0x1010→key 0x1000) を slot1 に
    // 置くのは合法。逆は拒否。
    let dup = packet::pack_duplex(0x1100, 0x1010, Group::A, Group::A).unwrap();
    let (pkt, _) = packet::split(&[dup]).unwrap();
    assert!(packet::expand(&pkt).is_ok());
    let dup = packet::pack_duplex(0x1010, 0x1100, Group::A, Group::A).unwrap();
    let (pkt, _) = packet::split(&[dup]).unwrap();
    assert_eq!(packet::expand(&pkt).unwrap_err(), ComposeError::DuplexOrder);
}

#[test]
fn new_predicate_producer() {
    // { p0 = cmp.eq(r3,#0) ; if (p0.new) r19 = #0 }
    // （llvm-mc 実符号 0x39303a4b: slot0=clr、slot1=cmpeq）。
    let (pkt, _) = packet::split(&[0x3930_3a4b]).unwrap();
    assert!(packet::expand(&pkt).is_ok());
    // 生成側がないと拒否。
    let dup = packet::pack_duplex(0x1a4b, 0x1010, Group::A, Group::A).unwrap();
    let (pkt, _) = packet::split(&[dup]).unwrap();
    assert_eq!(packet::expand(&pkt).unwrap_err(), ComposeError::NewProducer);
    // 32 ビット Pd=cmp.eq が生成側になる。
    let p0eq = with_pp(0xf203_c400, 1);
    let dup = packet::pack_duplex(0x1a4b, 0x1010, Group::A, Group::A).unwrap();
    let (pkt, _) = packet::split(&[p0eq, dup]).unwrap();
    assert!(packet::expand(&pkt).is_ok());
    // 32 ビット Pd=cmp.gt も生成側になる（cmp.eq だけでなく
    // Pd=[!]cmp.* 全般を認識する）。
    let p0gt = with_pp(0xf243_c400, 1);
    let dup = packet::pack_duplex(0x1a4b, 0x1010, Group::A, Group::A).unwrap();
    let (pkt, _) = packet::split(&[p0gt, dup]).unwrap();
    assert!(packet::expand(&pkt).is_ok());
    // L2 jumpr/dealloc_return の dprd3=6/7（p0.new/!p0.new）も
    // .new 消費側。生成側がないと拒否。
    let dup = packet::pack_duplex(0x1fc6, 0x0043, Group::L2, Group::L1).unwrap();
    let (pkt, _) = packet::split(&[dup]).unwrap();
    assert_eq!(packet::expand(&pkt).unwrap_err(), ComposeError::NewProducer);
    // 生成側を添えれば受理（p0.new と !p0.new の両方）。
    for jumpr_new in [0x1fc6u16, 0x1fc7] {
        let dup = packet::pack_duplex(jumpr_new, 0x0043, Group::L2, Group::L1).unwrap();
        let (pkt, _) = packet::split(&[p0eq, dup]).unwrap();
        assert!(packet::expand(&pkt).is_ok());
    }
}

#[test]
fn too_many_insns() {
    // duplex は subinsn 2 個を消費するので、3 命令 + duplex は 5
    // 命令分で超過。
    let dup = packet::pack_duplex(0x1010, 0x1010, Group::A, Group::A).unwrap();
    let words = [
        with_pp(ADD_RI, 1),
        with_pp(ADD_RI, 1),
        with_pp(ADD_RI, 1),
        dup,
    ];
    let (pkt, _) = packet::split(&words).unwrap();
    assert_eq!(
        packet::expand(&pkt).unwrap_err(),
        ComposeError::TooManyInsns
    );
    // 4 命令（2 + duplex）はギリギリ収まる。
    let words = [with_pp(ADD_RI, 1), with_pp(ADD_RI, 1), dup];
    let (pkt, _) = packet::split(&words).unwrap();
    assert!(packet::expand(&pkt).is_ok());
}

#[test]
fn dual_store_and_mem_noshuf() {
    // dual store: ST 2 個は slot1/slot0（llvm-mc 実符号でも
    // { memw(..)=.. ; memw(..)=.. } は同符号化）。
    let (pkt, _) = packet::split(&[with_pp(STW, 1), with_pp(STW, 3)]).unwrap();
    let s = packet::expand(&pkt).unwrap();
    assert_eq!((s[0].slot, s[1].slot), (1, 0));
    // slot1 store + slot0 load（:mem_noshuf が付く形。符号化上は
    // 区別できないので受理する）。
    let (pkt, _) = packet::split(&[with_pp(STW, 1), with_pp(LDW, 3)]).unwrap();
    let s = packet::expand(&pkt).unwrap();
    assert_eq!((s[0].slot, s[1].slot), (1, 0));
    // 逆順（load が slot1、store が slot0）も受理。
    let (pkt, _) = packet::split(&[with_pp(LDW, 1), with_pp(STW, 3)]).unwrap();
    let s = packet::expand(&pkt).unwrap();
    assert_eq!((s[0].slot, s[1].slot), (1, 0));
    // 単独 ST は slot0 固定で、ST を先頭にすると後続が割り当て
    // られない。
    let (pkt, _) = packet::split(&[with_pp(ADD_RI, 1), with_pp(STW, 3)]).unwrap();
    let s = packet::expand(&pkt).unwrap();
    assert_eq!((s[0].slot, s[1].slot), (3, 0));
    let (pkt, _) = packet::split(&[with_pp(STW, 1), with_pp(ADD_RI, 3)]).unwrap();
    assert_eq!(
        packet::expand(&pkt).unwrap_err(),
        ComposeError::NoSlotAssign
    );
}

#[test]
fn program_flow_combo() {
    // 無条件 jump を先頭には置けない。
    let (pkt, _) = packet::split(&[with_pp(JUMP, 1), with_pp(JUMP, 3)]).unwrap();
    assert_eq!(
        packet::expand(&pkt).unwrap_err(),
        ComposeError::BadJumpCombo
    );
    // JR 系は dual jump を組めない（前後どちらでも拒否）。
    let (pkt, _) = packet::split(&[with_pp(JUMPR, 1), with_pp(JUMP, 3)]).unwrap();
    assert_eq!(
        packet::expand(&pkt).unwrap_err(),
        ComposeError::BadJumpCombo
    );
    let (pkt, _) = packet::split(&[with_pp(JUMP, 1), with_pp(JUMPR, 3)]).unwrap();
    assert_eq!(
        packet::expand(&pkt).unwrap_err(),
        ComposeError::BadJumpCombo
    );
    // 3 個のフロー命令も拒否。
    let words = [with_pp(JUMP, 1), with_pp(JUMP, 1), with_pp(JUMP, 3)];
    let (pkt, _) = packet::split(&words).unwrap();
    assert_eq!(
        packet::expand(&pkt).unwrap_err(),
        ComposeError::BadJumpCombo
    );
    // 条件付き jump + 無条件 jump は合法（先頭が条件付き）。
    let (pkt, _) = packet::split(&[with_pp(IFP0JUMP, 1), with_pp(JUMP, 3)]).unwrap();
    let s = packet::expand(&pkt).unwrap();
    assert_eq!((s[0].slot, s[1].slot), (3, 2));
    // jumpr R31 subinsn もフロー命令で、dual を組めない。
    let dup = packet::pack_duplex(0x1fc0, 0x1010, Group::L2, Group::A).unwrap();
    let (pkt, _) = packet::split(&[with_pp(JUMP, 1), dup]).unwrap();
    assert_eq!(
        packet::expand(&pkt).unwrap_err(),
        ComposeError::BadJumpCombo
    );
    // jumpr R31 単独（deallocframe との同パケット）は受理。
    let dup = packet::pack_duplex(0x1fc0, 0x1f00, Group::L2, Group::L2).unwrap();
    let (pkt, _) = packet::split(&[dup]).unwrap();
    let s = packet::expand(&pkt).unwrap();
    assert_eq!((s[0].slot, s[1].slot), (1, 0));
}

#[test]
fn duplex_order_key() {
    // L2/L2 の memh 同士は du3+base+dst がフィールドなので、値が
    // 異なってもどちらの順でも受理される。
    for (lo, hi) in [(0x0440u16, 0x0012u16), (0x0012, 0x0440)] {
        let dup = packet::pack_duplex(lo, hi, Group::L2, Group::L2).unwrap();
        let (pkt, _) = packet::split(&[dup]).unwrap();
        assert!(packet::expand(&pkt).is_ok());
    }
    // L2/L2 の memh(0x0440) と memb(0x1012) はオペコード桁が残る
    // ので順序が強制される（小さい memh が slot1）。
    let dup = packet::pack_duplex(0x1012, 0x0440, Group::L2, Group::L2).unwrap();
    let (pkt, _) = packet::split(&[dup]).unwrap();
    assert!(packet::expand(&pkt).is_ok());
    let dup = packet::pack_duplex(0x0440, 0x1012, Group::L2, Group::L2).unwrap();
    let (pkt, _) = packet::split(&[dup]).unwrap();
    assert_eq!(packet::expand(&pkt).unwrap_err(), ComposeError::DuplexOrder);
    // A/A の条件クリアは dprd[6:4] が比較に残る（clr p0 < clr !p0）。
    let dup = packet::pack_duplex(0x1a72, 0x1a61, Group::A, Group::A).unwrap();
    let (pkt, _) = packet::split(&[dup]).unwrap();
    assert!(packet::expand(&pkt).is_ok());
    let dup = packet::pack_duplex(0x1a61, 0x1a72, Group::A, Group::A).unwrap();
    let (pkt, _) = packet::split(&[dup]).unwrap();
    assert_eq!(packet::expand(&pkt).unwrap_err(), ComposeError::DuplexOrder);
    // A/A の combine は第 1 即値 du2a[4:3] が比較に残る。
    // key(cb(#0,#1)=0x1c20)=0x1c00 < key(cb(#1,#0)=0x1c09)=0x1c08
    // なので 0x1c20 が slot1。
    let dup = packet::pack_duplex(0x1c09, 0x1c20, Group::A, Group::A).unwrap();
    let (pkt, _) = packet::split(&[dup]).unwrap();
    assert!(packet::expand(&pkt).is_ok());
    let dup = packet::pack_duplex(0x1c20, 0x1c09, Group::A, Group::A).unwrap();
    let (pkt, _) = packet::split(&[dup]).unwrap();
    assert_eq!(packet::expand(&pkt).unwrap_err(), ComposeError::DuplexOrder);
}

#[test]
fn reserved_bits_and_values() {
    // dx_a_clr の dprd 1-3 は未割当で拒否。
    for sub in [0x1a13u16, 0x1a23, 0x1a33] {
        assert_eq!(packet::decode_sub(Group::A, sub, 0), None);
    }
    // dx_l2_deallocframe は [5:0] が 0 固定（述語選択なし）。
    assert_eq!(packet::decode_sub(Group::L2, 0x1f01, 0), None);
    assert_eq!(packet::decode_sub(Group::L2, 0x1f08, 0), None);
    assert_eq!(
        packet::decode_sub(Group::L2, 0x1f00, 0),
        Some(Insn::DxL2Deallocframe)
    );
    // S1 ストアは {t} が読み出しソース（形式は DXS1）。
    let rt13 = |insn: Insn, ops: &[u64], g: Group| {
        let w = encode(insn, ops).expect("encode13") as u16;
        assert_eq!(packet::decode_sub(g, w, 0), Some(insn));
        w
    };
    // memw(r4+#8)=r5 → s=4, t=5, u=2。
    assert_eq!(rt13(Insn::DxS1Memw, &[4, 5, 2], Group::S1), 0x0245);
}

#[test]
fn disasm_representative() {
    // 生成した逆アセンブラが代表命令を出す。
    assert_eq!(
        disasm_word_ex(0xb004_c0a3, 32, true, 0).as_deref(),
        Some("add r3,r4,#5")
    );
    assert_eq!(
        disasm_word_ex(0x7f00_c000, 32, true, 0).as_deref(),
        Some("nop")
    );
    assert_eq!(
        disasm_word_ex(0x0123_5159, 32, true, 0).as_deref(),
        Some("immext #4772185")
    );
}

// ---- HX4: パケット単位 step ----
// `run::step` が PC から語を読んでパケットを確定し、スロット命令を
// 同時発行の意味論（読みはパケット開始時点、書き込みは終端で一括
// commit）で実行することを確かめる。
// Ref: SPEC-HEXAGON-PRM (V79) Section 10.

use polyisa_engine::run::{Outcome, TrapHandler, TrapOutcome};
use polyisa_guest_hexagon::run;
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};
use polyisa_sem::Backend as _;

const BASE: u64 = 0x1_0000;

/// トラップを捌かないハンドラ。
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

/// 命令語列を書き込む。
fn put(env: &mut BareEnv, addr: u64, words: &[u32]) {
    let mut b = Vec::new();
    for w in words {
        b.extend_from_slice(&w.to_le_bytes());
    }
    env.backend.mem.write(VirtAddr(addr), &b).unwrap();
}

fn step(env: &mut BareEnv) -> Result<(), Outcome> {
    run::step(env, &mut NoSys, 0)
}

#[test]
fn packet_progress() {
    // 1 語パケットが 2 連続。pc は語ごとに進み、commit が確定させる。
    let mut env = run_env();
    let w1 = with_pp(encode(Insn::AddRi, &[1, 0, 5]).unwrap() as u32, 3);
    let w2 = with_pp(encode(Insn::AddRi, &[2, 1, 7]).unwrap() as u32, 3);
    put(&mut env, BASE, &[w1, w2]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(sem::r_get(&env.backend, 1), 5);
    assert_eq!(env.pc, BASE + 4);
    // 状態の pc 面も次のパケットに同期する。
    assert_eq!(env.backend.get(sem::pc_ref()), BASE as u32 + 4);
    step(&mut env).unwrap();
    // 直前のパケットで確定した r1 を読む。
    assert_eq!(sem::r_get(&env.backend, 2), 12);
    assert_eq!(env.pc, BASE + 8);
}

#[test]
fn simultaneous_old_reads() {
    // { r1 = add(r0,#5) ; r2 = add(r1,#1) } — r2 はパケット開始
    // 時点の r1（0）を読む。同時発行で先行命令の生産値は見えない。
    let mut env = run_env();
    let w1 = with_pp(encode(Insn::AddRi, &[1, 0, 5]).unwrap() as u32, 1);
    let w2 = with_pp(encode(Insn::AddRi, &[2, 1, 1]).unwrap() as u32, 3);
    put(&mut env, BASE, &[w1, w2]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(sem::r_get(&env.backend, 1), 5);
    assert_eq!(sem::r_get(&env.backend, 2), 1);
}

#[test]
fn simultaneous_swap_duplex() {
    // { r1 = r2 ; r2 = r1 }（duplex A/A、llvm-mc 実符号 0x30213012）。
    // 両方が古い値を読むので値が入れ替わる。
    let mut env = run_env();
    sem::r_set(&mut env.backend, 1, 0xaa);
    sem::r_set(&mut env.backend, 2, 0xbb);
    let dup = packet::pack_duplex(0x1012, 0x1021, Group::A, Group::A).unwrap();
    assert_eq!(dup, 0x3021_3012);
    put(&mut env, BASE, &[dup]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(sem::r_get(&env.backend, 1), 0xbb);
    assert_eq!(sem::r_get(&env.backend, 2), 0xaa);
}

#[test]
fn new_predicate_transfer() {
    // { p0 = cmp.eq(r3,#0) ; if (p0.new) r19 = #0 }
    // （llvm-mc 実符号 0x39303a4b）。p0.new は同一パケット内の
    // 生産値を読む。
    let mut env = run_env();
    put(&mut env, BASE, &[0x3930_3a4b]);
    env.pc = BASE;
    // 生産値が真 → 条件クリアが効く。
    sem::r_set(&mut env.backend, 3, 0);
    sem::r_set(&mut env.backend, 19, 0xdead);
    step(&mut env).unwrap();
    assert_eq!(sem::r_get(&env.backend, 19), 0);
    assert_eq!(sem::p_get(&env.backend, 0), 0xff);
    // 生産値が偽 → 抑制されて r19 は変わらない。
    let mut env = run_env();
    put(&mut env, BASE, &[0x3930_3a4b]);
    env.pc = BASE;
    sem::r_set(&mut env.backend, 3, 5);
    sem::r_set(&mut env.backend, 19, 0xdead);
    step(&mut env).unwrap();
    assert_eq!(sem::r_get(&env.backend, 19), 0xdead);
    assert_eq!(sem::p_get(&env.backend, 0), 0);
}

#[test]
fn dotif_suppresses_at_step() {
    // { r0 = #0 ; if ([!]p0) r19 = #0 }（llvm-mc 実符号）。
    // 条件形の述語選択桁をフェッチ層が DotIf に写す。
    for (word, p0, want) in [
        (0x2800_3a6b, 0x00, 0xdead), // if (p0)、p0 偽 → 抑制
        (0x2800_3a6b, 0xff, 0),      // if (p0)、p0 真 → 実行
        (0x2800_3a7b, 0x00, 0),      // if (!p0)、p0 偽 → 実行
        (0x2800_3a7b, 0xff, 0xdead), // if (!p0)、p0 真 → 抑制
    ] {
        let mut env = run_env();
        put(&mut env, BASE, &[word]);
        env.pc = BASE;
        sem::p_set(&mut env.backend, 0, p0);
        sem::r_set(&mut env.backend, 19, 0xdead);
        step(&mut env).unwrap();
        assert_eq!(
            sem::r_get(&env.backend, 19),
            want,
            "word={word:#x} p0={p0:#x}"
        );
        // 無条件側の r0 は必ず書かれる。
        assert_eq!(sem::r_get(&env.backend, 0), 0);
    }
}

#[test]
fn duplex_memory_exec() {
    // { r3 = memw(r4+#0) ; r0 = add(r0,#0) }（duplex L1/A、
    // llvm-mc 実符号 0x40000043）。メモリ系 subinsn も実行する。
    let mut env = run_env();
    env.backend
        .mem
        .write(VirtAddr(BASE + 0x100), &0x1234_5678u32.to_le_bytes())
        .unwrap();
    put(&mut env, BASE, &[0x4000_0043]);
    env.pc = BASE;
    sem::r_set(&mut env.backend, 4, (BASE + 0x100) as u32);
    sem::r_set(&mut env.backend, 0, 41);
    step(&mut env).unwrap();
    assert_eq!(sem::r_get(&env.backend, 3), 0x1234_5678);
    // add(r0,#0) は実行されるが値は変わらない。
    assert_eq!(sem::r_get(&env.backend, 0), 41);
}

#[test]
fn packet_jump_and_call() {
    // { jump #8 } — pc 相対の直接分岐。
    let mut env = run_env();
    let w = with_pp(encode(Insn::JumpPcrel, &[8]).unwrap() as u32, 3);
    put(&mut env, BASE, &[w]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 8);
    // { call #8 } — LR（r31）に次のパケットを残して分岐。
    let mut env = run_env();
    let w = with_pp(encode(Insn::CallPcrel, &[8]).unwrap() as u32, 3);
    put(&mut env, BASE, &[w]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 8);
    assert_eq!(sem::r_get(&env.backend, 31), (BASE + 4) as u32);
    // { jumpr r4 } — 間接分岐。
    let mut env = run_env();
    let w = with_pp(encode(Insn::Jumpr, &[4]).unwrap() as u32, 3);
    put(&mut env, BASE, &[w]);
    env.pc = BASE;
    sem::r_set(&mut env.backend, 4, 0x2400);
    step(&mut env).unwrap();
    assert_eq!(env.pc, 0x2400);
}

/// trap の即値を記録するハンドラ。
struct Rec {
    code: Option<u32>,
    outcome: TrapOutcome,
}

impl TrapHandler for Rec {
    fn handle_trap(&mut self, _env: &mut BareEnv, code: u32) -> TrapOutcome {
        self.code = Some(code);
        self.outcome
    }
}

#[test]
fn trap0_exits_to_os() {
    // trap0(#1)（llvm-mc 実符号 0x5400c004）。即値を code に載せて
    // OS パーソナリティへ退出する。
    let mut env = run_env();
    put(&mut env, BASE, &[0x5400_c004, with_pp(NOP, 3)]);
    env.pc = BASE;
    let mut sys = Rec {
        code: None,
        outcome: TrapOutcome::Exit(42),
    };
    let o = run::step(&mut env, &mut sys, 0);
    assert_eq!(o, Err(Outcome::Exit(42)));
    assert_eq!(sys.code, Some(1));
    // Handled なら次のパケットから続行する。
    let mut env = run_env();
    put(&mut env, BASE, &[0x5400_c004, with_pp(NOP, 3)]);
    env.pc = BASE;
    let mut sys = Rec {
        code: None,
        outcome: TrapOutcome::Handled,
    };
    run::step(&mut env, &mut sys, 0).unwrap();
    assert_eq!(sys.code, Some(1));
    assert_eq!(env.pc, BASE + 4);
}

#[test]
fn endloop_marker_recorded() {
    // Parse 10 のループ終端標識が CpuState.endloop に転記される
    // （LC/SA の処理は commit が行う。LC=0 のままでは分岐しない）。
    let mut env = run_env();
    put(&mut env, BASE, &[with_pp(NOP, 2), with_pp(NOP, 3)]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.backend.get(sem::endloop_ref()), 1);
    assert_eq!(env.pc, BASE + 8);
}

#[test]
fn illegal_packet_is_trap() {
    // 復号できない語は illegal パケットとして handle_trap(TRAP_ILL)。
    let mut env = run_env();
    put(&mut env, BASE, &[0xffff_ffff]);
    env.pc = BASE;
    assert_eq!(
        step(&mut env),
        Err(Outcome::Unimplemented {
            pc: BASE,
            word: 0xffff_ffff
        })
    );
    // split の失敗（終端なし）も同じ。
    let mut env = run_env();
    put(&mut env, BASE, &[with_pp(NOP, 1)]);
    env.pc = BASE;
    assert!(matches!(step(&mut env), Err(Outcome::Unimplemented { .. })));
}
/// HX5: llvm-mc が出した正規符号と decode/ops の対応表。
/// （word, Insn, extract_ops の生値, 元の asm）
const HX5_WORDS: &[(u32, Insn, &[u64])] = &[
    (0x00004000, Insn::Immext, &[0]),                // immext(#0x0)
    (0x6a49c803, Insn::Addpc, &[3, 16]),             // r3=add(pc,#0x10)
    (0x6b01e290, Insn::Pfc9, &[0, 1, 2]),            // p0=fastcorner9(p1,p2)
    (0x6b02c100, Insn::Pand, &[0, 2, 1]),            // p0=and(p1,p2)
    (0x6b11c2c0, Insn::PandA, &[0, 1, 2, 3]),        // p0=and(p1,and(p2,p3))
    (0x6b11e290, Insn::Pfc9n, &[0, 1, 2]),           // p0=!fastcorner9(p1,p2)
    (0x6b22c100, Insn::Por, &[0, 2, 1]),             // p0=or(p1,p2)
    (0x6b31c2c0, Insn::PandO, &[0, 1, 2, 3]),        // p0=and(p1,or(p2,p3))
    (0x6b41c200, Insn::Pxor, &[0, 1, 2]),            // p0=xor(p1,p2)
    (0x6b51c2c0, Insn::PorA, &[0, 1, 2, 3]),         // p0=or(p1,and(p2,p3))
    (0x6b62c100, Insn::Pandn, &[0, 2, 1]),           // p0=and(p1,!p2)
    (0x6b71c2c0, Insn::PorO, &[0, 1, 2, 3]),         // p0=or(p1,or(p2,p3))
    (0x6b81c000, Insn::Pany8, &[0, 1]),              // p0=any8(p1)
    (0x6b91c2c0, Insn::PandAn, &[0, 1, 2, 3]),       // p0=and(p1,and(p2,!p3))
    (0x6ba1c000, Insn::Pall8, &[0, 1]),              // p0=all8(p1)
    (0x6bb1c2c0, Insn::PandOn, &[0, 1, 2, 3]),       // p0=and(p1,or(p2,!p3))
    (0x6bc1c000, Insn::Pnot, &[0, 1]),               // p0=not(p1)
    (0x6bd1c2c0, Insn::PorAn, &[0, 1, 2, 3]),        // p0=or(p1,and(p2,!p3))
    (0x6be2c100, Insn::Porn, &[0, 2, 1]),            // p0=or(p1,!p2)
    (0x6bf1c2c0, Insn::PorOn, &[0, 1, 2, 3]),        // p0=or(p1,or(p2,!p3))
    (0x7004c003, Insn::Aslh, &[3, 4]),               // r3=aslh(r4)
    (0x7024c003, Insn::Asrh, &[3, 4]),               // r3=asrh(r4)
    (0x70a4c003, Insn::Sxtb, &[3, 4]),               // r3=sxtb(r4)
    (0x70c4c003, Insn::Zxth, &[3, 4]),               // r3=zxth(r4)
    (0x70e4c003, Insn::Sxth, &[3, 4]),               // r3=sxth(r4)
    (0x7304c243, Insn::MuxRi, &[3, 0, 4, 18]),       // r3=mux(p0,r4,#0x12)
    (0x7304e244, Insn::CombRi, &[4, 4, 18]),         // r5:4=combine(r4,#0x12)
    (0x7324e244, Insn::CombIr, &[4, 4, 18]),         // r5:4=combine(#0x12,r4)
    (0x7344e243, Insn::CmpeqRdI, &[3, 4, 18]),       // r3=cmp.eq(r4,#0x12)
    (0x7364e243, Insn::CmpeqnRdI, &[3, 4, 18]),      // r3=!cmp.eq(r4,#0x12)
    (0x7384c243, Insn::MuxIr, &[3, 0, 4, 18]),       // r3=mux(p0,#0x12,r4)
    (0x7504c240, Insn::CmpeqI, &[0, 4, 18]),         // p0=cmp.eq(r4,#0x12)
    (0x7504c250, Insn::CmpeqnI, &[0, 4, 18]),        // p0=!cmp.eq(r4,#0x12)
    (0x7544c240, Insn::CmpgtI, &[0, 4, 18]),         // p0=cmp.gt(r4,#0x12)
    (0x7544c250, Insn::CmpgtnI, &[0, 4, 18]),        // p0=!cmp.gt(r4,#0x12)
    (0x7584c240, Insn::CmpgtuI, &[0, 4, 18]),        // p0=cmp.gtu(r4,#0x12)
    (0x7584c250, Insn::CmpgtunI, &[0, 4, 18]),       // p0=!cmp.gtu(r4,#0x12)
    (0x7604c243, Insn::AndRi, &[3, 4, 18]),          // r3=and(r4,#0x12)
    (0x7644c243, Insn::SubIr, &[3, 4, 18]),          // r3=sub(#0x12,r4)
    (0x7684c243, Insn::OrRi, &[3, 4, 18]),           // r3=or(r4,#0x12)
    (0x7a1ac243, Insn::MuxIi, &[3, 0, 18, 52]),      // r3=mux(p0,#0x12,#0x34)
    (0x7c1ac244, Insn::CombIi, &[4, 18, 52]),        // r5:4=combine(#0x12,#0x34)
    (0x7c80c244, Insn::CombIu6, &[4, 18, 0]),        // r5:4=combine(#0x12,##0x0)
    (0x8004c504, Insn::Asr64I, &[4, 4, 5]),          // r5:4=asr(r5:4,#0x5)
    (0x8004c524, Insn::Lsr64I, &[4, 4, 5]),          // r5:4=lsr(r5:4,#0x5)
    (0x8004c544, Insn::Asl64I, &[4, 4, 5]),          // r5:4=asl(r5:4,#0x5)
    (0x8004c564, Insn::Rol64I, &[4, 4, 5]),          // r5:4=rol(r5:4,#0x5)
    (0x8006c084, Insn::VsathubP, &[4, 6]),           // r5:4=vsathub(r7:6)
    (0x8006c0a4, Insn::VsatwuhP, &[4, 6]),           // r5:4=vsatwuh(r7:6)
    (0x8006c0c4, Insn::VsatwhP, &[4, 6]),            // r5:4=vsatwh(r7:6)
    (0x8006c0e4, Insn::VsathbP, &[4, 6]),            // r5:4=vsathb(r7:6)
    (0x8084c084, Insn::Not64, &[4, 4]),              // r5:4=not(r5:4)
    (0x8084c0a4, Insn::Neg64, &[4, 4]),              // r5:4=neg(r5:4)
    (0x8084c0c4, Insn::Abs64, &[4, 4]),              // r5:4=abs(r5:4)
    (0x80c4c084, Insn::Deinterleave, &[4, 4]),       // r5:4=deinterleave(r5:4)
    (0x80c4c0a4, Insn::Interleave, &[4, 4]),         // r5:4=interleave(r5:4)
    (0x80c4c0c4, Insn::Brev64, &[4, 4]),             // r5:4=brev(r5:4)
    (0x80c4c5e4, Insn::Asr64IRnd, &[4, 4, 5]),       // r5:4=asr(r5:4,#0x5):rnd
    (0x8206c504, Insn::Sub64AsrI, &[4, 6, 5]),       // r5:4-=asr(r7:6,#0x5)
    (0x8206c524, Insn::Sub64LsrI, &[4, 6, 5]),       // r5:4-=lsr(r7:6,#0x5)
    (0x8206c544, Insn::Sub64AslI, &[4, 6, 5]),       // r5:4-=asl(r7:6,#0x5)
    (0x8206c564, Insn::Sub64RolI, &[4, 6, 5]),       // r5:4-=rol(r7:6,#0x5)
    (0x8206c584, Insn::Add64AsrI, &[4, 6, 5]),       // r5:4+=asr(r7:6,#0x5)
    (0x8206c5a4, Insn::Add64LsrI, &[4, 6, 5]),       // r5:4+=lsr(r7:6,#0x5)
    (0x8206c5c4, Insn::Add64AslI, &[4, 6, 5]),       // r5:4+=asl(r7:6,#0x5)
    (0x8206c5e4, Insn::Add64RolI, &[4, 6, 5]),       // r5:4+=rol(r7:6,#0x5)
    (0x8246c504, Insn::And64AsrI, &[4, 6, 5]),       // r5:4&=asr(r7:6,#0x5)
    (0x8246c524, Insn::And64LsrI, &[4, 6, 5]),       // r5:4&=lsr(r7:6,#0x5)
    (0x8246c544, Insn::And64AslI, &[4, 6, 5]),       // r5:4&=asl(r7:6,#0x5)
    (0x8246c564, Insn::And64RolI, &[4, 6, 5]),       // r5:4&=rol(r7:6,#0x5)
    (0x8246c584, Insn::Or64AsrI, &[4, 6, 5]),        // r5:4|=asr(r7:6,#0x5)
    (0x8246c5a4, Insn::Or64LsrI, &[4, 6, 5]),        // r5:4|=lsr(r7:6,#0x5)
    (0x8246c5c4, Insn::Or64AslI, &[4, 6, 5]),        // r5:4|=asl(r7:6,#0x5)
    (0x8246c5e4, Insn::Or64RolI, &[4, 6, 5]),        // r5:4|=rol(r7:6,#0x5)
    (0x8286c524, Insn::Xor64LsrI, &[4, 6, 5]),       // r5:4^=lsr(r7:6,#0x5)
    (0x8286c544, Insn::Xor64AslI, &[4, 6, 5]),       // r5:4^=asl(r7:6,#0x5)
    (0x8286c564, Insn::Xor64RolI, &[4, 6, 5]),       // r5:4^=rol(r7:6,#0x5)
    (0x8404c004, Insn::Vsxtbh, &[4, 4]),             // r5:4=vsxtbh(r4)
    (0x8404c044, Insn::Vzxtbh, &[4, 4]),             // r5:4=vzxtbh(r4)
    (0x8404c084, Insn::Vsxthw, &[4, 4]),             // r5:4=vsxthw(r4)
    (0x8404c0c4, Insn::Vzxthw, &[4, 4]),             // r5:4=vzxthw(r4)
    (0x8444c004, Insn::Sxtw, &[4, 4]),               // r5:4=sxtw(r4)
    (0x8444c044, Insn::Vsplath, &[4, 4]),            // r5:4=vsplath(r4)
    (0x8444c084, Insn::VsplatbP, &[4, 4]),           // r5:4=vsplatb(r4)
    (0x8504c300, Insn::TstbitI, &[0, 4, 3]),         // p0=tstbit(r4,#0x3)
    (0x8524c300, Insn::TstbitnI, &[0, 4, 3]),        // p0=!tstbit(r4,#0x3)
    (0x8543c000, Insn::PdRs, &[0, 3]),               // p0=r3
    (0x8584ff00, Insn::BitsclrI, &[0, 4, 63]),       // p0=bitsclr(r4,#0x3f)
    (0x8704caa3, Insn::Tableidxb, &[3, 4, 5, 10]),   // r3=tableidxb(r4,#0x5,#0xa):raw
    (0x8744c9a3, Insn::Tableidxh, &[3, 4, 5, 9]),    // r3=tableidxh(r4,#0x5,#0x9):raw
    (0x8784c8a3, Insn::Tableidxw, &[3, 4, 5, 8]),    // r3=tableidxw(r4,#0x5,#0x8):raw
    (0x87c4c7a3, Insn::Tableidxd, &[3, 4, 5, 7]),    // r3=tableidxd(r4,#0x5,#0x7):raw
    (0x8804c003, Insn::Vsathub, &[3, 4]),            // r3=vsathub(r5:4)
    (0x8804c043, Insn::Vsatwh, &[3, 4]),             // r3=vsatwh(r5:4)
    (0x8804c083, Insn::Vsatwuh, &[3, 4]),            // r3=vsatwuh(r5:4)
    (0x8804c0c3, Insn::Vsathb, &[3, 4]),             // r3=vsathb(r5:4)
    (0x8844c003, Insn::Clb64, &[3, 4]),              // r3=clb(r5:4)
    (0x8844c043, Insn::Cl064, &[3, 4]),              // r3=cl0(r5:4)
    (0x8844c083, Insn::Cl164, &[3, 4]),              // r3=cl1(r5:4)
    (0x8864c003, Insn::Normamt64, &[3, 4]),          // r3=normamt(r5:4)
    (0x8864c063, Insn::Popcount, &[3, 4]),           // r3=popcount(r5:4)
    (0x8864fe43, Insn::Clbadd64, &[3, 4, 62]),       // r3=add(clb(r5:4),#-0x2)
    (0x8884c003, Insn::Vtrunohb, &[3, 4]),           // r3=vtrunohb(r5:4)
    (0x8884c043, Insn::Vtrunehb, &[3, 4]),           // r3=vtrunehb(r5:4)
    (0x8884c083, Insn::Vrndwh, &[3, 4]),             // r3=vrndwh(r5:4)
    (0x8884c0c3, Insn::VrndwhSat, &[3, 4]),          // r3=vrndwh(r5:4):sat
    (0x88c4c003, Insn::Sat, &[3, 4]),                // r3=sat(r5:4)
    (0x88c4c023, Insn::RoundSat, &[3, 4]),           // r3=round(r5:4):sat
    (0x88c4c784, Insn::BitsplitI, &[4, 4, 7]),       // r5:4=bitsplit(r4,#0x7)
    (0x88e4c043, Insn::Ct064, &[3, 4]),              // r3=ct0(r5:4)
    (0x88e4c083, Insn::Ct164, &[3, 4]),              // r3=ct1(r5:4)
    (0x8940c003, Insn::RdPs, &[3, 0]),               // r3=p0
    (0x8c04c083, Insn::Clb, &[3, 4]),                // r3=clb(r4)
    (0x8c04c0a3, Insn::Cl0, &[3, 4]),                // r3=cl0(r4)
    (0x8c04c0c3, Insn::Cl1, &[3, 4]),                // r3=cl1(r4)
    (0x8c04c0e3, Insn::Normamt, &[3, 4]),            // r3=normamt(r4)
    (0x8c04c503, Insn::AsrI, &[3, 4, 5]),            // r3=asr(r4,#0x5)
    (0x8c04c523, Insn::LsrI, &[3, 4, 5]),            // r3=lsr(r4,#0x5)
    (0x8c04c543, Insn::AslI, &[3, 4, 5]),            // r3=asl(r4,#0x5)
    (0x8c04c563, Insn::RolI, &[3, 4, 5]),            // r3=rol(r4,#0x5)
    (0x8c24fe03, Insn::Clbadd, &[3, 4, 62]),         // r3=add(clb(r4),#-0x2)
    (0x8c44c083, Insn::Ct0, &[3, 4]),                // r3=ct0(r4)
    (0x8c44c0a3, Insn::Ct1, &[3, 4]),                // r3=ct1(r4)
    (0x8c44c0c3, Insn::Brev, &[3, 4]),               // r3=brev(r4)
    (0x8c44c0e3, Insn::Vsplatb, &[3, 4]),            // r3=vsplatb(r4)
    (0x8c44c503, Insn::AsrIRnd, &[3, 4, 5]),         // r3=asr(r4,#0x5):rnd
    (0x8c44c543, Insn::AslISat, &[3, 4, 5]),         // r3=asl(r4,#0x5):sat
    (0x8c84c003, Insn::VsathbRs, &[3, 4]),           // r3=vsathb(r4)
    (0x8c84c043, Insn::VsathubRs, &[3, 4]),          // r3=vsathub(r4)
    (0x8c84c083, Insn::Abs, &[3, 4]),                // r3=abs(r4)
    (0x8c84c0a3, Insn::AbsSat, &[3, 4]),             // r3=abs(r4):sat
    (0x8c84c0c3, Insn::NegSat, &[3, 4]),             // r3=neg(r4):sat
    (0x8c84c0e3, Insn::Swiz, &[3, 4]),               // r3=swiz(r4)
    (0x8cc4c083, Insn::Sath, &[3, 4]),               // r3=sath(r4)
    (0x8cc4c0a3, Insn::Satuh, &[3, 4]),              // r3=satuh(r4)
    (0x8cc4c0c3, Insn::Satub, &[3, 4]),              // r3=satub(r4)
    (0x8cc4c0e3, Insn::Satb, &[3, 4]),               // r3=satb(r4)
    (0x8cc4c303, Insn::SetbitI, &[3, 4, 3]),         // r3=setbit(r4,#0x3)
    (0x8cc4c323, Insn::ClrbitI, &[3, 4, 3]),         // r3=clrbit(r4,#0x3)
    (0x8cc4c343, Insn::TogglebitI, &[3, 4, 3]),      // r3=togglebit(r4,#0x3)
    (0x8ce4c503, Insn::CroundI, &[3, 4, 5]),         // r3=cround(r4,#0x5)
    (0x8ce4c583, Insn::RoundI, &[3, 4, 5]),          // r3=round(r4,#0x5)
    (0x8ce4c5c3, Insn::RoundISat, &[3, 4, 5]),       // r3=round(r4,#0x5):sat
    (0x8d24c543, Insn::Extractu, &[3, 4, 5, 10]),    // r3=extractu(r4,#0x5,#0xa)
    (0x8da4c543, Insn::Extract, &[3, 4, 5, 10]),     // r3=extract(r4,#0x5,#0xa)
    (0x8e04c503, Insn::SubAsrI, &[3, 4, 5]),         // r3-=asr(r4,#0x5)
    (0x8e04c523, Insn::SubLsrI, &[3, 4, 5]),         // r3-=lsr(r4,#0x5)
    (0x8e04c543, Insn::SubAslI, &[3, 4, 5]),         // r3-=asl(r4,#0x5)
    (0x8e04c563, Insn::SubRolI, &[3, 4, 5]),         // r3-=rol(r4,#0x5)
    (0x8e04c583, Insn::AddAsrI, &[3, 4, 5]),         // r3+=asr(r4,#0x5)
    (0x8e04c5a3, Insn::AddLsrI, &[3, 4, 5]),         // r3+=lsr(r4,#0x5)
    (0x8e04c5c3, Insn::AddAslI, &[3, 4, 5]),         // r3+=asl(r4,#0x5)
    (0x8e04c5e3, Insn::AddRolI, &[3, 4, 5]),         // r3+=rol(r4,#0x5)
    (0x8e44c503, Insn::AndAsrI, &[3, 4, 5]),         // r3&=asr(r4,#0x5)
    (0x8e44c523, Insn::AndLsrI, &[3, 4, 5]),         // r3&=lsr(r4,#0x5)
    (0x8e44c543, Insn::AndAslI, &[3, 4, 5]),         // r3&=asl(r4,#0x5)
    (0x8e44c563, Insn::AndRolI, &[3, 4, 5]),         // r3&=rol(r4,#0x5)
    (0x8e44c583, Insn::OrAsrI, &[3, 4, 5]),          // r3|=asr(r4,#0x5)
    (0x8e44c5a3, Insn::OrLsrI, &[3, 4, 5]),          // r3|=lsr(r4,#0x5)
    (0x8e44c5c3, Insn::OrAslI, &[3, 4, 5]),          // r3|=asl(r4,#0x5)
    (0x8e44c5e3, Insn::OrRolI, &[3, 4, 5]),          // r3|=rol(r4,#0x5)
    (0x8e84c523, Insn::XorLsrI, &[3, 4, 5]),         // r3^=lsr(r4,#0x5)
    (0x8e84c543, Insn::XorAslI, &[3, 4, 5]),         // r3^=asl(r4,#0x5)
    (0x8e84c563, Insn::XorRolI, &[3, 4, 5]),         // r3^=rol(r4,#0x5)
    (0x8f24c543, Insn::Insert, &[3, 4, 5, 10]),      // r3=insert(r4,#0x5,#0xa)
    (0xc006c464, Insn::ValignbI, &[4, 6, 4, 3]),     // r5:4=valignb(r5:4,r7:6,#0x3)
    (0xc084c664, Insn::VsplicebI, &[4, 4, 6, 3]),    // r5:4=vspliceb(r5:4,r7:6,#0x3)
    (0xc104c606, Insn::Extractu64R, &[6, 4, 6]),     // r7:6=extractu(r5:4,r7:6)
    (0xc144c623, Insn::VaddhubSat, &[3, 4, 6]),      // r3=vaddhub(r5:4,r7:6):sat
    (0xc184c644, Insn::Vtrunewh, &[4, 4, 6]),        // r5:4=vtrunewh(r5:4,r7:6)
    (0xc184c664, Insn::VtrunehbP, &[4, 4, 6]),       // r5:4=vtrunehb(r5:4,r7:6)
    (0xc184c684, Insn::Vtrunowh, &[4, 4, 6]),        // r5:4=vtrunowh(r5:4,r7:6)
    (0xc184c6a4, Insn::VtrunohbP, &[4, 4, 6]),       // r5:4=vtrunohb(r5:4,r7:6)
    (0xc184c6c4, Insn::Lfs, &[4, 4, 6]),             // r5:4=lfs(r5:4,r7:6)
    (0xc1c4c686, Insn::Extract64R, &[6, 4, 6]),      // r7:6=extract(r5:4,r7:6)
    (0xc206c404, Insn::ValignbP, &[4, 0, 6, 4]),     // r5:4=valignb(r5:4,r7:6,p0)
    (0xc284c604, Insn::VsplicebP, &[4, 0, 4, 6]),    // r5:4=vspliceb(r5:4,r7:6,p0)
    (0xc2c4c604, Insn::AddCarry, &[4, 0, 4, 6]),     // r5:4=add(r5:4,r7:6,p0):carry
    (0xc2e4c604, Insn::SubCarry, &[4, 0, 4, 6]),     // r5:4=sub(r5:4,r7:6,p0):carry
    (0xc384c504, Insn::Asr64Rr, &[4, 4, 5]),         // r5:4=asr(r5:4,r5)
    (0xc384c544, Insn::Lsr64Rr, &[4, 4, 5]),         // r5:4=lsr(r5:4,r5)
    (0xc384c584, Insn::Asl64Rr, &[4, 4, 5]),         // r5:4=asl(r5:4,r5)
    (0xc384c5c4, Insn::Lsl64Rr, &[4, 4, 5]),         // r5:4=lsl(r5:4,r5)
    (0xc3c4c444, Insn::Vcnegh, &[4, 4, 4]),          // r5:4=vcnegh(r5:4,r4)
    (0xc405c463, Insn::Addasl, &[3, 5, 4, 3]),       // r3=addasl(r4,r5,#0x3)
    (0xc604c503, Insn::AsrRrSat, &[3, 4, 5]),        // r3=asr(r4,r5):sat
    (0xc604c583, Insn::AslRrSat, &[3, 4, 5]),        // r3=asl(r4,r5):sat
    (0xc644c503, Insn::AsrRr, &[3, 4, 5]),           // r3=asr(r4,r5)
    (0xc644c543, Insn::LsrRr, &[3, 4, 5]),           // r3=lsr(r4,r5)
    (0xc644c583, Insn::AslRr, &[3, 4, 5]),           // r3=asl(r4,r5)
    (0xc644c5c3, Insn::LslRr, &[3, 4, 5]),           // r3=lsl(r4,r5)
    (0xc684c503, Insn::SetbitR, &[3, 4, 5]),         // r3=setbit(r4,r5)
    (0xc684c543, Insn::ClrbitR, &[3, 4, 5]),         // r3=clrbit(r4,r5)
    (0xc684c583, Insn::TogglebitR, &[3, 4, 5]),      // r3=togglebit(r4,r5)
    (0xc69fc5c3, Insn::LslIr, &[3, 62, 5]),          // r3=lsl(#-0x2,r5)
    (0xc6c4c503, Insn::CroundR, &[3, 4, 5]),         // r3=cround(r4,r5)
    (0xc6c4c583, Insn::RoundR, &[3, 4, 5]),          // r3=round(r4,r5)
    (0xc6c4c5c3, Insn::RoundRSat, &[3, 4, 5]),       // r3=round(r4,r5):sat
    (0xc704c500, Insn::TstbitR, &[0, 4, 5]),         // p0=tstbit(r4,r5)
    (0xc724c500, Insn::TstbitnR, &[0, 4, 5]),        // p0=!tstbit(r4,r5)
    (0xc744c500, Insn::BitssetR, &[0, 4, 5]),        // p0=bitsset(r4,r5)
    (0xc784c500, Insn::BitsclrR, &[0, 4, 5]),        // p0=bitsclr(r4,r5)
    (0xc7a4c500, Insn::BitsclrnR, &[0, 4, 5]),       // p0=!bitsclr(r4,r5)
    (0xc7c4c540, Insn::CmpbGt, &[0, 4, 5]),          // p0=cmpb.gt(r4,r5)
    (0xc7c4c560, Insn::CmphEq, &[0, 4, 5]),          // p0=cmph.eq(r4,r5)
    (0xc7c4c580, Insn::CmphGt, &[0, 4, 5]),          // p0=cmph.gt(r4,r5)
    (0xc7c4c5a0, Insn::CmphGtu, &[0, 4, 5]),         // p0=cmph.gtu(r4,r5)
    (0xc7c4c5c0, Insn::CmpbEq, &[0, 4, 5]),          // p0=cmpb.eq(r4,r5)
    (0xc7c4c5e0, Insn::CmpbGtu, &[0, 4, 5]),         // p0=cmpb.gtu(r4,r5)
    (0xc804c403, Insn::InsertR, &[3, 4, 4]),         // r3=insert(r4,r5:4)
    (0xc904c403, Insn::ExtractuR, &[3, 4, 4]),       // r3=extractu(r4,r5:4)
    (0xc904c443, Insn::ExtractR, &[3, 4, 4]),        // r3=extract(r4,r5:4)
    (0xca04c606, Insn::Insert64R, &[6, 4, 6]),       // r7:6=insert(r5:4,r7:6)
    (0xca84c604, Insn::Xor64Xor, &[4, 4, 6]),        // r5:4^=xor(r5:4,r7:6)
    (0xcb06c504, Insn::Or64Asr, &[4, 6, 5]),         // r5:4|=asr(r7:6,r5)
    (0xcb06c544, Insn::Or64Lsr, &[4, 6, 5]),         // r5:4|=lsr(r7:6,r5)
    (0xcb06c584, Insn::Or64Asl, &[4, 6, 5]),         // r5:4|=asl(r7:6,r5)
    (0xcb06c5c4, Insn::Or64Lsl, &[4, 6, 5]),         // r5:4|=lsl(r7:6,r5)
    (0xcb26e4e4, Insn::Vrcnegh, &[4, 6, 4]),         // r5:4+=vrcnegh(r7:6,r4)
    (0xcb86c504, Insn::Sub64Asr, &[4, 6, 5]),        // r5:4-=asr(r7:6,r5)
    (0xcb86c544, Insn::Sub64Lsr, &[4, 6, 5]),        // r5:4-=lsr(r7:6,r5)
    (0xcb86c584, Insn::Sub64Asl, &[4, 6, 5]),        // r5:4-=asl(r7:6,r5)
    (0xcb86c5c4, Insn::Sub64Lsl, &[4, 6, 5]),        // r5:4-=lsl(r7:6,r5)
    (0xcbc6c504, Insn::Add64Asr, &[4, 6, 5]),        // r5:4+=asr(r7:6,r5)
    (0xcbc6c544, Insn::Add64Lsr, &[4, 6, 5]),        // r5:4+=lsr(r7:6,r5)
    (0xcbc6c584, Insn::Add64Asl, &[4, 6, 5]),        // r5:4+=asl(r7:6,r5)
    (0xcbc6c5c4, Insn::Add64Lsl, &[4, 6, 5]),        // r5:4+=lsl(r7:6,r5)
    (0xcc04c503, Insn::OrAsr, &[3, 4, 5]),           // r3|=asr(r4,r5)
    (0xcc04c543, Insn::OrLsr, &[3, 4, 5]),           // r3|=lsr(r4,r5)
    (0xcc04c583, Insn::OrAsl, &[3, 4, 5]),           // r3|=asl(r4,r5)
    (0xcc04c5c3, Insn::OrLsl, &[3, 4, 5]),           // r3|=lsl(r4,r5)
    (0xcc84c503, Insn::SubAsr, &[3, 4, 5]),          // r3-=asr(r4,r5)
    (0xcc84c543, Insn::SubLsr, &[3, 4, 5]),          // r3-=lsr(r4,r5)
    (0xcc84c583, Insn::SubAsl, &[3, 4, 5]),          // r3-=asl(r4,r5)
    (0xcc84c5c3, Insn::SubLsl, &[3, 4, 5]),          // r3-=lsl(r4,r5)
    (0xccc4c503, Insn::AddAsr, &[3, 4, 5]),          // r3+=asr(r4,r5)
    (0xccc4c543, Insn::AddLsr, &[3, 4, 5]),          // r3+=lsr(r4,r5)
    (0xccc4c583, Insn::AddAsl, &[3, 4, 5]),          // r3+=asl(r4,r5)
    (0xccc4c5c3, Insn::AddLsl, &[3, 4, 5]),          // r3+=lsl(r4,r5)
    (0xd004c603, Insn::Parity64, &[3, 4, 6]),        // r3=parity(r5:4,r7:6)
    (0xd104c604, Insn::Vmux, &[4, 0, 4, 6]),         // r5:4=vmux(p0,r5:4,r7:6)
    (0xd284c600, Insn::Cmp64Eq, &[0, 4, 6]),         // p0=cmp.eq(r5:4,r7:6)
    (0xd284c640, Insn::Cmp64Gt, &[0, 4, 6]),         // p0=cmp.gt(r5:4,r7:6)
    (0xd284c680, Insn::Cmp64Gtu, &[0, 4, 6]),        // p0=cmp.gtu(r5:4,r7:6)
    (0xd304c604, Insn::Vaddub64, &[4, 4, 6]),        // r5:4=vaddub(r5:4,r7:6)
    (0xd304c624, Insn::Vaddub64Sat, &[4, 4, 6]),     // r5:4=vaddub(r5:4,r7:6):sat
    (0xd304c644, Insn::Vaddh64, &[4, 4, 6]),         // r5:4=vaddh(r5:4,r7:6)
    (0xd304c664, Insn::Vaddh64Sat, &[4, 4, 6]),      // r5:4=vaddh(r5:4,r7:6):sat
    (0xd304c684, Insn::Vadduh64Sat, &[4, 4, 6]),     // r5:4=vadduh(r5:4,r7:6):sat
    (0xd304c6a4, Insn::Vaddw64, &[4, 4, 6]),         // r5:4=vaddw(r5:4,r7:6)
    (0xd304c6c4, Insn::Vaddw64Sat, &[4, 4, 6]),      // r5:4=vaddw(r5:4,r7:6):sat
    (0xd304c6e4, Insn::Add64, &[4, 4, 6]),           // r5:4=add(r5:4,r7:6)
    (0xd326c404, Insn::Vsubub64, &[4, 6, 4]),        // r5:4=vsubub(r5:4,r7:6)
    (0xd326c424, Insn::Vsubub64Sat, &[4, 6, 4]),     // r5:4=vsubub(r5:4,r7:6):sat
    (0xd326c444, Insn::Vsubh64, &[4, 6, 4]),         // r5:4=vsubh(r5:4,r7:6)
    (0xd326c464, Insn::Vsubh64Sat, &[4, 6, 4]),      // r5:4=vsubh(r5:4,r7:6):sat
    (0xd326c484, Insn::Vsubuh64Sat, &[4, 6, 4]),     // r5:4=vsubuh(r5:4,r7:6):sat
    (0xd326c4a4, Insn::Vsubw64, &[4, 6, 4]),         // r5:4=vsubw(r5:4,r7:6)
    (0xd326c4c4, Insn::Vsubw64Sat, &[4, 6, 4]),      // r5:4=vsubw(r5:4,r7:6):sat
    (0xd326c4e4, Insn::Sub64, &[4, 6, 4]),           // r5:4=sub(r5:4,r7:6)
    (0xd344c604, Insn::Vavgub64, &[4, 4, 6]),        // r5:4=vavgub(r5:4,r7:6)
    (0xd344c624, Insn::Vavgub64Rnd, &[4, 4, 6]),     // r5:4=vavgub(r5:4,r7:6):rnd
    (0xd344c644, Insn::Vavgh64, &[4, 4, 6]),         // r5:4=vavgh(r5:4,r7:6)
    (0xd344c664, Insn::Vavgh64Rnd, &[4, 4, 6]),      // r5:4=vavgh(r5:4,r7:6):rnd
    (0xd344c684, Insn::Vavgh64Crnd, &[4, 4, 6]),     // r5:4=vavgh(r5:4,r7:6):crnd
    (0xd344c6a4, Insn::Vavguh64, &[4, 4, 6]),        // r5:4=vavguh(r5:4,r7:6)
    (0xd344c6c4, Insn::Vavguh64Rnd, &[4, 4, 6]),     // r5:4=vavguh(r5:4,r7:6):rnd
    (0xd364c604, Insn::Vavgw64, &[4, 4, 6]),         // r5:4=vavgw(r5:4,r7:6)
    (0xd364c624, Insn::Vavgw64Rnd, &[4, 4, 6]),      // r5:4=vavgw(r5:4,r7:6):rnd
    (0xd364c644, Insn::Vavgw64Crnd, &[4, 4, 6]),     // r5:4=vavgw(r5:4,r7:6):crnd
    (0xd364c664, Insn::Vavguw64, &[4, 4, 6]),        // r5:4=vavguw(r5:4,r7:6)
    (0xd364c684, Insn::Vavguw64Rnd, &[4, 4, 6]),     // r5:4=vavguw(r5:4,r7:6):rnd
    (0xd364c6a4, Insn::Add64Sat, &[4, 4, 6]),        // r5:4=add(r5:4,r7:6):sat
    (0xd364c6c4, Insn::Add64RawLo, &[4, 4, 6]),      // r5:4=add(r5:4,r7:6):raw:lo
    (0xd364c6e4, Insn::Add64RawHi, &[4, 4, 6]),      // r5:4=add(r5:4,r7:6):raw:hi
    (0xd386c404, Insn::Vnavgh64, &[4, 6, 4]),        // r5:4=vnavgh(r5:4,r7:6)
    (0xd386c424, Insn::Vnavgh64RndSat, &[4, 6, 4]),  // r5:4=vnavgh(r5:4,r7:6):rnd:sat
    (0xd386c444, Insn::Vnavgh64CrndSat, &[4, 6, 4]), // r5:4=vnavgh(r5:4,r7:6):crnd:sat
    (0xd386c464, Insn::Vnavgw64, &[4, 6, 4]),        // r5:4=vnavgw(r5:4,r7:6)
    (0xd386c484, Insn::Vnavgw64RndSat, &[4, 6, 4]),  // r5:4=vnavgw(r5:4,r7:6):rnd:sat
    (0xd386c4c4, Insn::Vnavgw64CrndSat, &[4, 6, 4]), // r5:4=vnavgw(r5:4,r7:6):crnd:sat
    (0xd3a6c404, Insn::Vminub64, &[4, 6, 4]),        // r5:4=vminub(r5:4,r7:6)
    (0xd3a6c424, Insn::Vminh64, &[4, 6, 4]),         // r5:4=vminh(r5:4,r7:6)
    (0xd3a6c444, Insn::Vminuh64, &[4, 6, 4]),        // r5:4=vminuh(r5:4,r7:6)
    (0xd3a6c464, Insn::Vminw64, &[4, 6, 4]),         // r5:4=vminw(r5:4,r7:6)
    (0xd3a6c484, Insn::Vminuw64, &[4, 6, 4]),        // r5:4=vminuw(r5:4,r7:6)
    (0xd3a6c4a4, Insn::Vmaxuw64, &[4, 6, 4]),        // r5:4=vmaxuw(r5:4,r7:6)
    (0xd3a6c4c4, Insn::Min64, &[4, 6, 4]),           // r5:4=min(r5:4,r7:6)
    (0xd3a6c4e4, Insn::Minu64, &[4, 6, 4]),          // r5:4=minu(r5:4,r7:6)
    (0xd3c4c684, Insn::Max64, &[4, 4, 6]),           // r5:4=max(r5:4,r7:6)
    (0xd3c4c6a4, Insn::Maxu64, &[4, 4, 6]),          // r5:4=maxu(r5:4,r7:6)
    (0xd3c6c404, Insn::Vmaxub64, &[4, 6, 4]),        // r5:4=vmaxub(r5:4,r7:6)
    (0xd3c6c424, Insn::Vmaxh64, &[4, 6, 4]),         // r5:4=vmaxh(r5:4,r7:6)
    (0xd3c6c444, Insn::Vmaxuh64, &[4, 6, 4]),        // r5:4=vmaxuh(r5:4,r7:6)
    (0xd3c6c464, Insn::Vmaxw64, &[4, 6, 4]),         // r5:4=vmaxw(r5:4,r7:6)
    (0xd3c6c4c4, Insn::Vmaxb64, &[4, 6, 4]),         // r5:4=vmaxb(r5:4,r7:6)
    (0xd3c6c4e4, Insn::Vminb64, &[4, 6, 4]),         // r5:4=vminb(r5:4,r7:6)
    (0xd3e4c5e3, Insn::Modwrap, &[3, 4, 5]),         // r3=modwrap(r4,r5)
    (0xd3e4c604, Insn::And64, &[4, 4, 6]),           // r5:4=and(r5:4,r7:6)
    (0xd3e4c624, Insn::Andn64, &[4, 4, 6]),          // r5:4=and(r7:6,~r5:4)
    (0xd3e4c644, Insn::Or64, &[4, 4, 6]),            // r5:4=or(r5:4,r7:6)
    (0xd3e4c664, Insn::Orn64, &[4, 4, 6]),           // r5:4=or(r7:6,~r5:4)
    (0xd3e4c684, Insn::Xor64, &[4, 4, 6]),           // r5:4=xor(r5:4,r7:6)
    (0xd424c504, Insn::BitsplitR, &[4, 4, 5]),       // r5:4=bitsplit(r4,r5)
    (0xd505c403, Insn::AddLl, &[3, 5, 4]),           // r3=add(r4.l,r5.l)
    (0xd505c403, Insn::AddLl, &[3, 5, 4]),           // r3=add(r4.l,r5.l)
    (0xd505c443, Insn::AddLh, &[3, 5, 4]),           // r3=add(r4.l,r5.h)
    (0xd505c443, Insn::AddLh, &[3, 5, 4]),           // r3=add(r4.l,r5.h)
    (0xd505c483, Insn::AddLlSat, &[3, 5, 4]),        // r3=add(r4.l,r5.l):sat
    (0xd505c483, Insn::AddLlSat, &[3, 5, 4]),        // r3=add(r4.l,r5.l):sat
    (0xd505c4c3, Insn::AddLhSat, &[3, 5, 4]),        // r3=add(r4.l,r5.h):sat
    (0xd505c4c3, Insn::AddLhSat, &[3, 5, 4]),        // r3=add(r4.l,r5.h):sat
    (0xd525c403, Insn::SubLl, &[3, 5, 4]),           // r3=sub(r4.l,r5.l)
    (0xd525c443, Insn::SubLh, &[3, 5, 4]),           // r3=sub(r4.l,r5.h)
    (0xd525c483, Insn::SubLlSat, &[3, 5, 4]),        // r3=sub(r4.l,r5.l):sat
    (0xd525c4c3, Insn::SubLhSat, &[3, 5, 4]),        // r3=sub(r4.l,r5.h):sat
    (0xd545c403, Insn::AddLlS16, &[3, 5, 4]),        // r3=add(r4.l,r5.l):<<16
    (0xd545c423, Insn::AddLhS16, &[3, 5, 4]),        // r3=add(r4.l,r5.h):<<16
    (0xd545c443, Insn::AddHlS16, &[3, 5, 4]),        // r3=add(r4.h,r5.l):<<16
    (0xd545c463, Insn::AddHhS16, &[3, 5, 4]),        // r3=add(r4.h,r5.h):<<16
    (0xd545c483, Insn::AddLlSatS16, &[3, 5, 4]),     // r3=add(r4.l,r5.l):sat:<<16
    (0xd545c4a3, Insn::AddLhSatS16, &[3, 5, 4]),     // r3=add(r4.l,r5.h):sat:<<16
    (0xd545c4c3, Insn::AddHlSatS16, &[3, 5, 4]),     // r3=add(r4.h,r5.l):sat:<<16
    (0xd545c4e3, Insn::AddHhSatS16, &[3, 5, 4]),     // r3=add(r4.h,r5.h):sat:<<16
    (0xd565c403, Insn::SubLlS16, &[3, 5, 4]),        // r3=sub(r4.l,r5.l):<<16
    (0xd565c423, Insn::SubLhS16, &[3, 5, 4]),        // r3=sub(r4.l,r5.h):<<16
    (0xd565c443, Insn::SubHlS16, &[3, 5, 4]),        // r3=sub(r4.h,r5.l):<<16
    (0xd565c463, Insn::SubHhS16, &[3, 5, 4]),        // r3=sub(r4.h,r5.h):<<16
    (0xd565c483, Insn::SubLlSatS16, &[3, 5, 4]),     // r3=sub(r4.l,r5.l):sat:<<16
    (0xd565c4a3, Insn::SubLhSatS16, &[3, 5, 4]),     // r3=sub(r4.l,r5.h):sat:<<16
    (0xd565c4c3, Insn::SubHlSatS16, &[3, 5, 4]),     // r3=sub(r4.h,r5.l):sat:<<16
    (0xd565c4e3, Insn::SubHhSatS16, &[3, 5, 4]),     // r3=sub(r4.h,r5.h):sat:<<16
    (0xd5a5c403, Insn::Min, &[3, 5, 4]),             // r3=min(r4,r5)
    (0xd5a5c483, Insn::Minu, &[3, 5, 4]),            // r3=minu(r4,r5)
    (0xd5c4c503, Insn::Max, &[3, 4, 5]),             // r3=max(r4,r5)
    (0xd5c4c583, Insn::Maxu, &[3, 4, 5]),            // r3=maxu(r4,r5)
    (0xd5e4c503, Insn::Parity, &[3, 4, 5]),          // r3=parity(r4,r5)
    (0xda04c243, Insn::OrAndI, &[3, 4, 18]),         // r3|=and(r4,#0x12)
    (0xda43c244, Insn::OrAc, &[3, 4, 18]),           // r3=or(r4,and(r3,#0x12))
    (0xda84c243, Insn::OrOrI, &[3, 4, 18]),          // r3|=or(r4,#0x12)
    (0xdb24c345, Insn::Add3, &[3, 4, 5, 18]),        // r3=add(r4,add(r5,#0x12))
    (0xdba4c345, Insn::Sub3, &[3, 4, 5, 18]),        // r3=add(r4,sub(#0x12,r5))
    (0xdd04c240, Insn::CmpbEqI, &[0, 4, 18]),        // p0=cmpb.eq(r4,#0x12)
    (0xdd04c248, Insn::CmphEqI, &[0, 4, 18]),        // p0=cmph.eq(r4,#0x12)
    (0xdd24c240, Insn::CmpbGtI, &[0, 4, 18]),        // p0=cmpb.gt(r4,#0x12)
    (0xdd24c248, Insn::CmphGtI, &[0, 4, 18]),        // p0=cmph.gt(r4,#0x12)
    (0xdd44c240, Insn::CmpbGtuI, &[0, 4, 18]),       // p0=cmpb.gtu(r4,#0x12)
    (0xdd44c248, Insn::CmphGtuI, &[0, 4, 18]),       // p0=cmph.gtu(r4,#0x12)
    (0xde03e420, Insn::CandAsl, &[3, 4, 18]),        // r3=and(#0x12,asl(r3,#0x4))
    (0xde03e422, Insn::CorAsl, &[3, 4, 18]),         // r3=or(#0x12,asl(r3,#0x4))
    (0xde03e424, Insn::CaddAsl, &[3, 4, 18]),        // r3=add(#0x12,asl(r3,#0x4))
    (0xde03e426, Insn::CsubAsl, &[3, 4, 18]),        // r3=sub(#0x12,asl(r3,#0x4))
    (0xde03e430, Insn::CandLsr, &[3, 4, 18]),        // r3=and(#0x12,lsr(r3,#0x4))
    (0xde03e432, Insn::CorLsr, &[3, 4, 18]),         // r3=or(#0x12,lsr(r3,#0x4))
    (0xde03e434, Insn::CaddLsr, &[3, 4, 18]),        // r3=add(#0x12,lsr(r3,#0x4))
    (0xde03e436, Insn::CsubLsr, &[3, 4, 18]),        // r3=sub(#0x12,lsr(r3,#0x4))
    (0xe204c243, Insn::AddAccI, &[3, 4, 18]),        // r3+=add(r4,#0x12)
    (0xe284c243, Insn::SubAccI, &[3, 4, 18]),        // r3-=add(r4,#0x12)
    (0xef04c523, Insn::AddAcc, &[3, 4, 5]),          // r3+=add(r4,r5)
    (0xef05c463, Insn::AddsubAcc, &[3, 5, 4]),       // r3+=sub(r4,r5)
    (0xef25c403, Insn::OrAndn, &[3, 5, 4]),          // r3|=and(r5,~r4)
    (0xef25c423, Insn::AndAndn, &[3, 5, 4]),         // r3&=and(r5,~r4)
    (0xef25c443, Insn::XorAndn, &[3, 5, 4]),         // r3^=and(r5,~r4)
    (0xef44c503, Insn::AndAnd, &[3, 4, 5]),          // r3&=and(r4,r5)
    (0xef44c523, Insn::AndOr, &[3, 4, 5]),           // r3&=or(r4,r5)
    (0xef44c543, Insn::AndXor, &[3, 4, 5]),          // r3&=xor(r4,r5)
    (0xef44c563, Insn::OrAnd, &[3, 4, 5]),           // r3|=and(r4,r5)
    (0xef84c523, Insn::SubAcc, &[3, 4, 5]),          // r3-=add(r4,r5)
    (0xef84c563, Insn::XorXor, &[3, 4, 5]),          // r3^=xor(r4,r5)
    (0xefc4c503, Insn::OrOr, &[3, 4, 5]),            // r3|=or(r4,r5)
    (0xefc4c523, Insn::OrXor, &[3, 4, 5]),           // r3|=xor(r4,r5)
    (0xefc4c543, Insn::XorAnd, &[3, 4, 5]),          // r3^=and(r4,r5)
    (0xefc4c563, Insn::XorOr, &[3, 4, 5]),           // r3^=or(r4,r5)
    (0xf104c503, Insn::AndRr, &[3, 4, 5]),           // r3=and(r4,r5)
    (0xf124c503, Insn::OrRr, &[3, 4, 5]),            // r3=or(r4,r5)
    (0xf164c503, Insn::XorRr, &[3, 4, 5]),           // r3=xor(r4,r5)
    (0xf184c503, Insn::Andn2Rr, &[3, 4, 5]),         // r3=and(r5,~r4)
    (0xf1a4c503, Insn::Orn2Rr, &[3, 4, 5]),          // r3=or(r5,~r4)
    (0xf204c500, Insn::CmpeqRr, &[0, 4, 5]),         // p0=cmp.eq(r4,r5)
    (0xf204c510, Insn::CmpeqnRr, &[0, 4, 5]),        // p0=!cmp.eq(r4,r5)
    (0xf244c500, Insn::CmpgtRr, &[0, 4, 5]),         // p0=cmp.gt(r4,r5)
    (0xf244c510, Insn::CmpgtnRr, &[0, 4, 5]),        // p0=!cmp.gt(r4,r5)
    (0xf264c500, Insn::CmpgtuRr, &[0, 4, 5]),        // p0=cmp.gtu(r4,r5)
    (0xf264c510, Insn::CmpgtunRr, &[0, 4, 5]),       // p0=!cmp.gtu(r4,r5)
    (0xf304c503, Insn::AddRr, &[3, 4, 5]),           // r3=add(r4,r5)
    (0xf325c403, Insn::SubRr, &[3, 5, 4]),           // r3=sub(r4,r5)
    (0xf344c503, Insn::CmpeqRdRr, &[3, 4, 5]),       // r3=cmp.eq(r4,r5)
    (0xf364c503, Insn::CmpeqnRdRr, &[3, 4, 5]),      // r3=!cmp.eq(r4,r5)
    (0xf385c403, Insn::CombHh, &[3, 5, 4]),          // r3=combine(r4.h,r5.h)
    (0xf3a5c403, Insn::CombHl, &[3, 5, 4]),          // r3=combine(r4.h,r5.l)
    (0xf3c5c403, Insn::CombLh, &[3, 5, 4]),          // r3=combine(r4.l,r5.h)
    (0xf3e5c403, Insn::CombLl, &[3, 5, 4]),          // r3=combine(r4.l,r5.l)
    (0xf404c503, Insn::MuxRr, &[3, 0, 4, 5]),        // r3=mux(p0,r4,r5)
    (0xf504c504, Insn::CombineRr, &[4, 4, 5]),       // r5:4=combine(r4,r5)
    (0xf584c504, Insn::Packhl, &[4, 4, 5]),          // r5:4=packhl(r4,r5)
    (0xf604c503, Insn::VaddhRr, &[3, 4, 5]),         // r3=vaddh(r4,r5)
    (0xf624c503, Insn::VaddhSatRr, &[3, 4, 5]),      // r3=vaddh(r4,r5):sat
    (0xf644c503, Insn::AddSatRr, &[3, 4, 5]),        // r3=add(r4,r5):sat
    (0xf664c503, Insn::VadduhSatRr, &[3, 4, 5]),     // r3=vadduh(r4,r5):sat
    (0xf685c403, Insn::VsubhRr, &[3, 5, 4]),         // r3=vsubh(r4,r5)
    (0xf6a5c403, Insn::VsubhSatRr, &[3, 5, 4]),      // r3=vsubh(r4,r5):sat
    (0xf6e5c403, Insn::VsubuhSatRr, &[3, 5, 4]),     // r3=vsubuh(r4,r5):sat
    (0xf704c503, Insn::VavghRr, &[3, 4, 5]),         // r3=vavgh(r4,r5)
    (0xf724c503, Insn::VavghRndRr, &[3, 4, 5]),      // r3=vavgh(r4,r5):rnd
    (0xf765c403, Insn::VnavghRr, &[3, 5, 4]),        // r3=vnavgh(r4,r5)
];

#[test]
fn hx5_decode_map() {
    for &(w, insn, ops) in HX5_WORDS {
        assert_eq!(decode(w.into(), 32), Some(insn), "word {w:#010x}");
        assert_eq!(extract_ops(insn, u128::from(w)), ops, "ops {w:#010x}");
    }
}
// ---- HX5: 実行意味論 ----

/// 1 命令パケット（pp=3 埋込みの llvm-mc 符号）を実行する。
fn exec1(env: &mut BareEnv, word: u32) {
    put(env, BASE, &[word]);
    env.pc = BASE;
    step(env).unwrap();
}

#[test]
fn hx5_alu32() {
    let mut env = run_env();
    sem::r_set(&mut env.backend, 4, 0x7fff_ffff);
    sem::r_set(&mut env.backend, 5, 2);
    // r3 = add(r4,r5):sat — 飽和 + USR.OVF。
    exec1(&mut env, 0xf644c503);
    assert_eq!(sem::r_get(&env.backend, 3), 0x7fff_ffff);
    assert_eq!(env.backend.get(sem::usr_ref()) & 1, 1);
    // r3 = sub(r4,r5) — 第 1 被演算子 - 第 2 被演算子。
    exec1(&mut env, 0xf325c403);
    assert_eq!(sem::r_get(&env.backend, 3), 0x7fff_fffd);
    // r3 = and(r5,~r4) — 2 & ~0x7fffffff = 0。
    exec1(&mut env, 0xf184c503);
    assert_eq!(sem::r_get(&env.backend, 3), 0);
    sem::r_set(&mut env.backend, 4, 0xffff_fffd);
    exec1(&mut env, 0xf184c503);
    assert_eq!(sem::r_get(&env.backend, 3), 2);
    // r3 = or(r5,~r4) — 2 | ~0xffff_fffd = 2。
    exec1(&mut env, 0xf1a4c503);
    assert_eq!(sem::r_get(&env.backend, 3), 2);
    // r3 = xor(r4,r5) — 0xffff_fffd ^ 2。
    exec1(&mut env, 0xf164c503);
    assert_eq!(sem::r_get(&env.backend, 3), 0xffff_ffff);
    // r3 = sub(#0x12,r4) — 0x12 - 0xffff_fffd = 0x15。
    exec1(&mut env, 0x7644c243);
    assert_eq!(sem::r_get(&env.backend, 3), 0x15);
    // r3 = sub(r4,r5):sat — 0x80000000 - 2 のアンダーフロー。
    sem::r_set(&mut env.backend, 4, 0x8000_0000);
    exec1(&mut env, 0xf6c5c403);
    assert_eq!(sem::r_get(&env.backend, 3), 0x8000_0000);
}

#[test]
fn hx5_combine_mux() {
    let mut env = run_env();
    sem::r_set(&mut env.backend, 4, 0x1111_2222);
    sem::r_set(&mut env.backend, 5, 0x3333_4444);
    // r5:4 = combine(r4,r5) — 下位=第 2 オペランド、上位=第 1。
    exec1(&mut env, 0xf504c504);
    assert_eq!(sem::r_get(&env.backend, 4), 0x3333_4444);
    assert_eq!(sem::r_get(&env.backend, 5), 0x1111_2222);
    // r3 = combine(r4.h,r5.l) — 直前の combine で確定した
    // r4=0x33334444, r5=0x11112222 を読む。(t.h<<16)|s.l。
    exec1(&mut env, 0xf3a5c403);
    assert_eq!(sem::r_get(&env.backend, 3), 0x3333_2222);
    // r5:4 = combine(#0x12,#0x34)。
    exec1(&mut env, 0x7c1ac244);
    assert_eq!(sem::r_get(&env.backend, 4), 0x34);
    assert_eq!(sem::r_get(&env.backend, 5), 0x12);
    // r5:4 = packhl(r4,r5) — w0=(t.l,s.l)、w1=(t.h,s.h)。
    sem::r_set(&mut env.backend, 4, 0xaaaa_1111);
    sem::r_set(&mut env.backend, 5, 0xbbbb_2222);
    exec1(&mut env, 0xf584c504);
    assert_eq!(sem::r_get(&env.backend, 4), 0x1111_2222);
    assert_eq!(sem::r_get(&env.backend, 5), 0xaaaa_bbbb);
    // mux: p0=0 → 第 3 オペランド、p0=1 → 第 2。
    sem::p_set(&mut env.backend, 0, 0);
    exec1(&mut env, 0xf404c503); // r3 = mux(p0,r4,r5)
    assert_eq!(sem::r_get(&env.backend, 3), 0xaaaa_bbbb);
    sem::p_set(&mut env.backend, 0, 0xff);
    exec1(&mut env, 0xf404c503);
    assert_eq!(sem::r_get(&env.backend, 3), 0x1111_2222);
    // r3 = mux(p0,#0x12,#0x34)。
    exec1(&mut env, 0x7a1ac243);
    assert_eq!(sem::r_get(&env.backend, 3), 0x12);
}

#[test]
fn hx5_predicates() {
    let mut env = run_env();
    sem::r_set(&mut env.backend, 4, 5);
    sem::r_set(&mut env.backend, 5, 7);
    exec1(&mut env, 0xf204c500); // p0 = cmp.eq(r4,r5)
    assert_eq!(sem::p_get(&env.backend, 0), 0);
    exec1(&mut env, 0xf244c500); // p0 = cmp.gt(r4,r5)
    assert_eq!(sem::p_get(&env.backend, 0), 0);
    exec1(&mut env, 0xf264c500); // p0 = cmp.gtu(r4,r5)
    assert_eq!(sem::p_get(&env.backend, 0), 0);
    exec1(&mut env, 0xf244c510); // p0 = !cmp.gt(r4,r5)
    assert_eq!(sem::p_get(&env.backend, 0), 0xff);
    sem::r_set(&mut env.backend, 4, 0xffff_ffff);
    exec1(&mut env, 0xf264c500); // gtu: 0xffffffff > 7
    assert_eq!(sem::p_get(&env.backend, 0), 0xff);
    exec1(&mut env, 0xf244c500); // gt: -1 > 7 → false
    assert_eq!(sem::p_get(&env.backend, 0), 0);
    // 即値比較。p0 = cmp.gtu(r4,#0x12) — u9 として解釈。
    exec1(&mut env, 0x7584c240);
    assert_eq!(sem::p_get(&env.backend, 0), 0xff);
    // r3 = p0（zxt）、p0 = r3。
    exec1(&mut env, 0x8940c003);
    assert_eq!(sem::r_get(&env.backend, 3), 0xff);
    sem::r_set(&mut env.backend, 3, 0xaa);
    exec1(&mut env, 0x8543c000); // p0 = r3
    assert_eq!(sem::p_get(&env.backend, 0), 0xaa);
    // p 演算。p0 = and(p1,or(p2,!p3))。
    sem::p_set(&mut env.backend, 1, 0xff);
    sem::p_set(&mut env.backend, 2, 0);
    sem::p_set(&mut env.backend, 3, 0xff);
    exec1(&mut env, 0x6bb1c2c0); // and(p1,or(p2,!p3))
    assert_eq!(sem::p_get(&env.backend, 0), 0);
    sem::p_set(&mut env.backend, 3, 0);
    exec1(&mut env, 0x6bb1c2c0);
    assert_eq!(sem::p_get(&env.backend, 0), 0xff);
    // fastcorner9: 9 連続ビット。p1=0xff,p2=0xff → 連続 16 ビット → 真。
    sem::p_set(&mut env.backend, 1, 0xff);
    sem::p_set(&mut env.backend, 2, 0xff);
    exec1(&mut env, 0x6b01e290);
    assert_eq!(sem::p_get(&env.backend, 0), 0xff);
    // (0xff<<8)|0x7f = 0xff7f → 複製で 16 連続 → 真。
    sem::p_set(&mut env.backend, 2, 0x7f);
    exec1(&mut env, 0x6b01e290);
    assert_eq!(sem::p_get(&env.backend, 0), 0xff);
    // (0x3f<<8)|0x7f = 0x3f7f → 最長 7 連続 → 偽。
    sem::p_set(&mut env.backend, 1, 0x3f);
    exec1(&mut env, 0x6b01e290);
    assert_eq!(sem::p_get(&env.backend, 0), 0);
    // cmpb/cmph。p0 = cmpb.eq(r4,r5)。
    sem::r_set(&mut env.backend, 4, 0x12);
    sem::r_set(&mut env.backend, 5, 0x112);
    exec1(&mut env, 0xc7c4c5c0);
    assert_eq!(sem::p_get(&env.backend, 0), 0xff);
    exec1(&mut env, 0xc7c4c560); // cmph.eq
    assert_eq!(sem::p_get(&env.backend, 0), 0);
}

#[test]
fn hx5_pair_ops() {
    let mut env = run_env();
    sem::r_set(&mut env.backend, 4, 0xffff_ffff);
    sem::r_set(&mut env.backend, 5, 0x7fff_ffff);
    sem::r_set(&mut env.backend, 6, 1);
    sem::r_set(&mut env.backend, 7, 0);
    // r5:4 = add(r5:4,r7:6):sat — 0x7fff..ff + 1 で飽和。
    exec1(&mut env, 0xd364c6a4);
    assert_eq!(sem::r_get(&env.backend, 4), 0xffff_ffff);
    assert_eq!(sem::r_get(&env.backend, 5), 0x7fff_ffff);
    // r5:4 = sub(r5:4,r7:6) — 第 1 ペア - 第 2 ペア。
    exec1(&mut env, 0xd326c4e4);
    assert_eq!(sem::r_get(&env.backend, 4), 0xffff_fffe);
    assert_eq!(sem::r_get(&env.backend, 5), 0x7fff_ffff);
    // p0 = cmp.gtu(r5:4,r7:6) — 0x7fff..fe > 1 → 真。
    exec1(&mut env, 0xd284c680);
    assert_eq!(sem::p_get(&env.backend, 0), 0xff);
    // r5:4 = max(r5:4,r7:6) — 符号。
    exec1(&mut env, 0xd3c4c684);
    assert_eq!(
        (sem::r_get(&env.backend, 4), sem::r_get(&env.backend, 5)),
        (0xffff_fffe, 0x7fff_ffff)
    );
    // carry: p0=0xff（繰上り 1）。
    sem::p_set(&mut env.backend, 0, 0xff);
    sem::r_set(&mut env.backend, 4, 0xffff_ffff);
    sem::r_set(&mut env.backend, 5, 0xffff_ffff);
    sem::r_set(&mut env.backend, 6, 1);
    sem::r_set(&mut env.backend, 7, 0);
    exec1(&mut env, 0xc2c4c604); // r5:4 = add(r5:4,r7:6,p0):carry
    assert_eq!(sem::r_get(&env.backend, 4), 1);
    assert_eq!(sem::r_get(&env.backend, 5), 0);
    assert_eq!(sem::p_get(&env.backend, 0), 0xff); // キャリーアウト。
}

#[test]
fn hx5_shifts() {
    let mut env = run_env();
    sem::r_set(&mut env.backend, 4, 0x8000_0001);
    sem::r_set(&mut env.backend, 5, 5);
    // r3 = asr(r4,#5)。
    exec1(&mut env, 0x8c04c503);
    assert_eq!(sem::r_get(&env.backend, 3), 0xfc00_0000);
    // r3 = lsr(r4,#5)。
    exec1(&mut env, 0x8c04c523);
    assert_eq!(sem::r_get(&env.backend, 3), 0x0400_0000);
    // r3 = rol(r4,#5)。
    exec1(&mut env, 0x8c04c563);
    assert_eq!(sem::r_get(&env.backend, 3), 0x0000_0030);
    // r3 = asr(r4,r5): r5=5 → 算術右 5。
    exec1(&mut env, 0xc644c503);
    assert_eq!(sem::r_get(&env.backend, 3), 0xfc00_0000);
    // 負シフト量: r5 = -3 → 左 3。
    sem::r_set(&mut env.backend, 5, 0xffff_fffd);
    exec1(&mut env, 0xc644c583); // r3 = asl(r4,r5) — 負量は算術右
    assert_eq!(sem::r_get(&env.backend, 3), 0xf000_0000);
    // asl:sat — 0x40000000 asl 1 → 飽和。
    sem::r_set(&mut env.backend, 4, 0x4000_0000);
    sem::r_set(&mut env.backend, 5, 1);
    exec1(&mut env, 0xc604c583);
    assert_eq!(sem::r_get(&env.backend, 3), 0x7fff_ffff);
    // 64 ビット。r5:4 = lsl(r5:4,r5) — r5=5 がシフト量。
    sem::r_set(&mut env.backend, 4, 1);
    sem::r_set(&mut env.backend, 5, 5);
    exec1(&mut env, 0xc384c5c4);
    assert_eq!(
        (sem::r_get(&env.backend, 4), sem::r_get(&env.backend, 5)),
        (0x0000_0020, 0x0000_00a0)
    );
    // r3 = lsl(#-2,r5) — zxt した 0xfffffffe を論理シフト。
    sem::r_set(&mut env.backend, 5, 4);
    exec1(&mut env, 0xc69fc5c3);
    assert_eq!(sem::r_get(&env.backend, 3), 0xffff_ffe0);
    // r3 = addasl(r4,r5,#3) = r4 + r5<<3。
    sem::r_set(&mut env.backend, 4, 10);
    sem::r_set(&mut env.backend, 5, 2);
    exec1(&mut env, 0xc405c463);
    assert_eq!(sem::r_get(&env.backend, 3), 26);
    // r3 += asr(r4,#5) — 破壊的累積は同じ語の古い r3 を読む。
    sem::r_set(&mut env.backend, 3, 100);
    sem::r_set(&mut env.backend, 4, 0x8000_0000);
    exec1(&mut env, 0x8e04c583);
    assert_eq!(
        sem::r_get(&env.backend, 3),
        100u32.wrapping_add(0xfc00_0000)
    );
}

#[test]
fn hx5_bits() {
    let mut env = run_env();
    sem::r_set(&mut env.backend, 4, 0x00f0_f000);
    exec1(&mut env, 0x8c04c0a3); // cl0
    assert_eq!(sem::r_get(&env.backend, 3), 8);
    exec1(&mut env, 0x8c04c0c3); // cl1（先頭 1 の個数=0）
    assert_eq!(sem::r_get(&env.backend, 3), 0);
    sem::r_set(&mut env.backend, 4, 0xffff_f0f0);
    exec1(&mut env, 0x8c04c0c3); // cl1（先頭 1 の個数=16+4=20）
    assert_eq!(sem::r_get(&env.backend, 3), 20);
    exec1(&mut env, 0x8c04c083); // clb = 先頭符号ビット列=20
    assert_eq!(sem::r_get(&env.backend, 3), 20);
    exec1(&mut env, 0x8c44c083); // ct0（末尾 0 の個数=4）
    assert_eq!(sem::r_get(&env.backend, 3), 4);
    sem::r_set(&mut env.backend, 4, 0x0000_ffff);
    exec1(&mut env, 0x8c44c0a3); // ct1（末尾 1 の個数=16）
    assert_eq!(sem::r_get(&env.backend, 3), 16);
    exec1(&mut env, 0x8c04c0e3); // normamt = 16-1=15
    assert_eq!(sem::r_get(&env.backend, 3), 15);
    sem::r_set(&mut env.backend, 4, 0xaaa5_555a);
    sem::r_set(&mut env.backend, 5, 0xffff_00ff);
    exec1(&mut env, 0xd5e4c503); // parity = popcount(r4&r5)&1
    let want = (0xaaa5_555au32 & 0xffff_00ff).count_ones() & 1;
    assert_eq!(sem::r_get(&env.backend, 3), want);
    exec1(&mut env, 0x8c44c0c3); // brev
    assert_eq!(sem::r_get(&env.backend, 3), 0xaaa5_555au32.reverse_bits());
    exec1(&mut env, 0x8c84c0e3); // swiz
    assert_eq!(sem::r_get(&env.backend, 3), 0x5a55_a5aa);
    // popcount(r5:4)。
    sem::r_set(&mut env.backend, 4, 0xffff_ffff);
    sem::r_set(&mut env.backend, 5, 1);
    exec1(&mut env, 0x8864c063);
    assert_eq!(sem::r_get(&env.backend, 3), 33);
    // tstbit/setbit/clrbit/togglebit。
    sem::r_set(&mut env.backend, 4, 0x8);
    exec1(&mut env, 0x8504c300); // p0 = tstbit(r4,#3)
    assert_eq!(sem::p_get(&env.backend, 0), 0xff);
    exec1(&mut env, 0x8524c300); // !tstbit
    assert_eq!(sem::p_get(&env.backend, 0), 0);
    sem::r_set(&mut env.backend, 4, 0);
    exec1(&mut env, 0x8cc4c303); // r3 = setbit(r4,#3)
    assert_eq!(sem::r_get(&env.backend, 3), 8);
    exec1(&mut env, 0x8cc4c323); // r3 = clrbit(r4,#3)
    assert_eq!(sem::r_get(&env.backend, 3), 0);
    exec1(&mut env, 0x8cc4c343); // r3 = togglebit(r4,#3)
    assert_eq!(sem::r_get(&env.backend, 3), 8);
    // bitsclr/bitsset。
    sem::r_set(&mut env.backend, 4, 0xc);
    sem::r_set(&mut env.backend, 5, 0xf);
    exec1(&mut env, 0xc784c500); // p0 = bitsclr(r4,r5) — r4&r5!=0 → 偽
    assert_eq!(sem::p_get(&env.backend, 0), 0);
    sem::r_set(&mut env.backend, 4, 0x30);
    exec1(&mut env, 0xc784c500); // r4&r5==0 → 真
    assert_eq!(sem::p_get(&env.backend, 0), 0xff);
    exec1(&mut env, 0xc744c500); // bitsset(r4,r5) — r4&r5==r5? 0x30&0xf!=0xf → 偽
    assert_eq!(sem::p_get(&env.backend, 0), 0);
}

#[test]
fn hx5_bitfield() {
    let mut env = run_env();
    // extract: 幅 5、オフセット 10 → 符号拡張。
    sem::r_set(&mut env.backend, 4, 0b0_1111 << 10);
    exec1(&mut env, 0x8da4c543); // r3 = extract(r4,#5,#10)
    assert_eq!(sem::r_get(&env.backend, 3), 0xf);
    sem::r_set(&mut env.backend, 4, 0b1_0000 << 10); // フィールド先頭ビット=1
    exec1(&mut env, 0x8da4c543);
    assert_eq!(sem::r_get(&env.backend, 3), 0xffff_fff0);
    exec1(&mut env, 0x8d24c543); // r3 = extractu(r4,#5,#10)
    assert_eq!(sem::r_get(&env.backend, 3), 0x10);
    // insert: r3 の [14:10] を r4 の下位 5 ビットで置換。
    sem::r_set(&mut env.backend, 3, 0xffff_ffff);
    sem::r_set(&mut env.backend, 4, 0b1_0101);
    exec1(&mut env, 0x8f24c543); // r3 = insert(r4,#5,#10)
    assert_eq!(sem::r_get(&env.backend, 3), 0xffff_d7ff);
    // bitsplit: #7 で分割。
    sem::r_set(&mut env.backend, 4, 0x1234_567f);
    exec1(&mut env, 0x88c4c784);
    assert_eq!(sem::r_get(&env.backend, 4), 0x7f);
    assert_eq!(sem::r_get(&env.backend, 5), 0x1234_567f >> 7);
    // tableidxb(r4,#5,#10):raw — off=10、幅 5 でフィールド抽出。
    sem::r_set(&mut env.backend, 3, 0xdead_beef);
    sem::r_set(&mut env.backend, 4, 0x0000_5430); // off10..14 = 0b10101
    exec1(&mut env, 0x8704caa3);
    let field = (0x5430u32 >> 10) & 0x1f;
    let want = (0xdead_beef & !0x1f) | field;
    assert_eq!(sem::r_get(&env.backend, 3), want);
}

#[test]
fn hx5_sat_round() {
    let mut env = run_env();
    // sat(r5:4): 64→32 飽和。
    sem::r_set(&mut env.backend, 4, 0x0000_0001);
    sem::r_set(&mut env.backend, 5, 0x7fff_ffff);
    exec1(&mut env, 0x88c4c003);
    assert_eq!(sem::r_get(&env.backend, 3), 0x7fff_ffff);
    assert_eq!(env.backend.get(sem::usr_ref()) & 1, 1);
    // sath/satuh/satb/satub。
    sem::r_set(&mut env.backend, 4, 0x0001_2345);
    exec1(&mut env, 0x8cc4c083); // sath
    assert_eq!(sem::r_get(&env.backend, 3), 0x7fff);
    exec1(&mut env, 0x8cc4c0a3); // satuh
    assert_eq!(sem::r_get(&env.backend, 3), 0xffff);
    sem::r_set(&mut env.backend, 4, 0xffff_ff80); // -128
    exec1(&mut env, 0x8cc4c0e3); // satb → -128
    assert_eq!(sem::r_get(&env.backend, 3), 0xffff_ff80);
    exec1(&mut env, 0x8cc4c0c3); // satub → 負→0
    assert_eq!(sem::r_get(&env.backend, 3), 0);
    // round(r5:4):sat — sat64(x+0x080000000) の上位ワード。
    sem::r_set(&mut env.backend, 4, 0xf800_0000);
    sem::r_set(&mut env.backend, 5, 0x7fff_ffff);
    exec1(&mut env, 0x88c4c023);
    assert_eq!(sem::r_get(&env.backend, 3), 0x7fff_ffff);
    // vsathub / vsathb / vsatwh / vsatwuh（64→32 パック）。
    sem::r_set(&mut env.backend, 4, 0x8001_7fff);
    sem::r_set(&mut env.backend, 5, 0x0080_ffff);
    exec1(&mut env, 0x8804c003); // vsathub — usat_8(h[i])→ub[i]
    assert_eq!(sem::r_get(&env.backend, 3), 0x8000_00ff);
    exec1(&mut env, 0x8804c0c3); // vsathb — sat_8(h[i])→b[i]
    assert_eq!(sem::r_get(&env.backend, 3), 0x7fff_807f);
    // vrndwh。
    sem::r_set(&mut env.backend, 4, 0x0000_8000);
    sem::r_set(&mut env.backend, 5, 0x0000_8001);
    exec1(&mut env, 0x8884c083);
    assert_eq!(sem::r_get(&env.backend, 3), 0x0001_0001);
}

#[test]
fn hx5_vector() {
    let mut env = run_env();
    // vtrunehb / vtrunohb: 偶数/奇数バイトを集める。
    sem::r_set(&mut env.backend, 4, 0x3322_1100);
    sem::r_set(&mut env.backend, 5, 0x7766_5544);
    exec1(&mut env, 0x8884c043); // r3 = vtrunehb(r5:4)
    assert_eq!(sem::r_get(&env.backend, 3), 0x6644_2200);
    exec1(&mut env, 0x8884c003); // vtrunohb
    assert_eq!(sem::r_get(&env.backend, 3), 0x7755_3311);
    // vsplatb / vsplath。
    sem::r_set(&mut env.backend, 4, 0x0000_00ab);
    exec1(&mut env, 0x8c44c0e3); // r3 = vsplatb(r4)
    assert_eq!(sem::r_get(&env.backend, 3), 0xabab_abab);
    exec1(&mut env, 0x8444c044); // r5:4 = vsplath(r4)
    assert_eq!(sem::r_get(&env.backend, 4), 0x00ab_00ab);
    assert_eq!(sem::r_get(&env.backend, 5), 0x00ab_00ab);
    // vsxtbh/vzxtbh（バイト→半語、符号/ゼロ拡張）。
    sem::r_set(&mut env.backend, 4, 0x80ff_7f01);
    exec1(&mut env, 0x8404c004); // r5:4 = vsxtbh(r4)
    assert_eq!(sem::r_get(&env.backend, 4), 0x007f_0001);
    assert_eq!(sem::r_get(&env.backend, 5), 0xff80_ffff);
    sem::r_set(&mut env.backend, 4, 0x80ff_7f01);
    exec1(&mut env, 0x8404c044); // r5:4 = vzxtbh(r4)
    assert_eq!(sem::r_get(&env.backend, 4), 0x007f_0001);
    assert_eq!(sem::r_get(&env.backend, 5), 0x0080_00ff);
    // interleave/deinterleave。
    sem::r_set(&mut env.backend, 4, 0xffff_ffff);
    sem::r_set(&mut env.backend, 5, 0);
    exec1(&mut env, 0x80c4c0a4); // r5:4 = interleave(r5:4)
    assert_eq!(sem::r_get(&env.backend, 4), 0x5555_5555);
    assert_eq!(sem::r_get(&env.backend, 5), 0x5555_5555);
    exec1(&mut env, 0x80c4c084); // r5:4 = deinterleave — 元の対に戻る
    assert_eq!(
        (sem::r_get(&env.backend, 4), sem::r_get(&env.backend, 5)),
        (0xffff_ffff, 0)
    );
    // valignb: (Rss>>>24)|(Rtt<<40)。
    sem::r_set(&mut env.backend, 4, 0x11);
    sem::r_set(&mut env.backend, 5, 0x22);
    sem::r_set(&mut env.backend, 6, 0x33);
    sem::r_set(&mut env.backend, 7, 0x44);
    exec1(&mut env, 0xc006c464); // valignb(r5:4,r7:6,#3)
    assert_eq!(
        (sem::r_get(&env.backend, 4), sem::r_get(&env.backend, 5)),
        (0x0000_4400, 0x0000_1100)
    );
    // vaddh（32 ビット 2 レーン）。
    sem::r_set(&mut env.backend, 4, 0x0002_7fff);
    sem::r_set(&mut env.backend, 5, 0x0001_0002);
    exec1(&mut env, 0xf604c503);
    assert_eq!(sem::r_get(&env.backend, 3), 0x0003_8001);
    exec1(&mut env, 0xf624c503); // :sat → 下位 0x8001→sat→0x7fff
    assert_eq!(sem::r_get(&env.backend, 3), 0x0003_7fff);
}

#[test]
fn hx5_misc() {
    let mut env = run_env();
    // add(pc,#u6) — PC = BASE → BASE+16。
    exec1(&mut env, 0x6a49c803);
    assert_eq!(sem::r_get(&env.backend, 3), BASE as u32 + 0x10);
    // modwrap: 3 mod 5 = 3、6 mod 5 = 1、-1 mod 5 = 4。
    sem::r_set(&mut env.backend, 4, 6);
    sem::r_set(&mut env.backend, 5, 5);
    exec1(&mut env, 0xd3e4c5e3);
    assert_eq!(sem::r_get(&env.backend, 3), 1);
    sem::r_set(&mut env.backend, 4, 0xffff_ffff);
    exec1(&mut env, 0xd3e4c5e3);
    assert_eq!(sem::r_get(&env.backend, 3), 4);
    // max/min/maxu/minu（32 ビット）。
    sem::r_set(&mut env.backend, 4, 0xffff_ffff); // -1
    sem::r_set(&mut env.backend, 5, 7);
    exec1(&mut env, 0xd5c4c503); // r3 = max(r4,r5) — 符号 → 7
    assert_eq!(sem::r_get(&env.backend, 3), 7);
    exec1(&mut env, 0xd5c4c583); // r3 = maxu(r4,r5) — 無符号 → 0xffffffff
    assert_eq!(sem::r_get(&env.backend, 3), 0xffff_ffff);
    exec1(&mut env, 0xd5a5c403); // r3 = min(r4,r5) — 符号 → -1
    assert_eq!(sem::r_get(&env.backend, 3), 0xffff_ffff);
    exec1(&mut env, 0xd5a5c483); // r3 = minu(r4,r5) — 無符号 → 7
    assert_eq!(sem::r_get(&env.backend, 3), 7);
    // sxtw。
    sem::r_set(&mut env.backend, 4, 0xffff_8000);
    exec1(&mut env, 0x8444c004);
    assert_eq!(
        (sem::r_get(&env.backend, 4), sem::r_get(&env.backend, 5)),
        (0xffff_8000, 0xffff_ffff)
    );
    // abs/abs:sat/neg:sat。
    sem::r_set(&mut env.backend, 4, 0x8000_0000);
    exec1(&mut env, 0x8c84c0a3); // abs(r4):sat → 0x7fffffff
    assert_eq!(sem::r_get(&env.backend, 3), 0x7fff_ffff);
    exec1(&mut env, 0x8c84c0c3); // neg(r4):sat → 0x7fffffff
    assert_eq!(sem::r_get(&env.backend, 3), 0x7fff_ffff);
    // 複合三項: r3 = add(r4,add(r5,#-2)) → db64e3c5。
    sem::r_set(&mut env.backend, 4, 10);
    sem::r_set(&mut env.backend, 5, 7);
    exec1(&mut env, 0xdb64e3c5);
    assert_eq!(sem::r_get(&env.backend, 3), 15);
    // r3 = add(r4,sub(#0x12,r5)) → r4 - r5 + 0x12。
    exec1(&mut env, 0xdba4c345);
    assert_eq!(sem::r_get(&env.backend, 3), 21);
    // r3 |= or(r4,#0x12)。
    sem::r_set(&mut env.backend, 3, 1);
    exec1(&mut env, 0xda84c243);
    assert_eq!(sem::r_get(&env.backend, 3), 1 | (10 | 0x12));
}

// ---- HX6: load/store・memop・`.new` 値ストア ----

/// HX6 の復号対応表（llvm-mc hexagonv73 実符号）。
/// （word, Insn, extract_ops の生値）
const HX6_WORDS: &[(u32, Insn, &[u64])] = &[
    (0x9104c003, Insn::LdRi, &[3, 4, 0, 0]),     // r3=memb(r4+#0)
    (0x9124c003, Insn::LdRi, &[3, 4, 1, 0]),     // r3=memub(r4+#0)
    (0x9144c003, Insn::LdRi, &[3, 4, 2, 0]),     // r3=memh(r4+#0)
    (0x9164c003, Insn::LdRi, &[3, 4, 3, 0]),     // r3=memuh(r4+#0)
    (0x9184c003, Insn::LdRi, &[3, 4, 4, 0]),     // r3=memw(r4+#0)
    (0x91c4c004, Insn::LdRi, &[4, 4, 6, 0]),     // r5:4=memd(r4+#0)
    (0xa104c500, Insn::StRi, &[4, 5, 0, 0]),     // memb(r4+#0)=r5
    (0xa144c500, Insn::StRi, &[4, 5, 2, 0]),     // memh(r4+#0)=r5
    (0xa184c500, Insn::StRi, &[4, 5, 4, 0]),     // memw(r4+#0)=r5
    (0xa1c4c601, Insn::StRi, &[4, 6, 6, 1]),     // memd(r4+#8)=r7:6
    (0xa164c500, Insn::StRi, &[4, 5, 3, 0]),     // memh(r4+#0)=r5.h
    (0x9b84c043, Insn::LdPi, &[3, 4, 4, 2]),     // r3=memw(r4++#8)
    (0xab84c510, Insn::StPi, &[4, 5, 4, 2]),     // memw(r4++#8)=r5
    (0x9d84e003, Insn::LdPr, &[3, 4, 4, 1]),     // r3=memw(r4++m1)
    (0x9984c043, Insn::LdPci, &[3, 4, 4, 0, 2]), // r3=memw(r4++#8:circ(m0))
    (0x9984c203, Insn::LdPcr, &[3, 4, 4, 0]),    // r3=memw(r4++i:circ(m0))
    (0x9f84c003, Insn::LdPbr, &[3, 4, 4, 0]),    // r3=memw(r4++m0:brev)
    (0xaf84c500, Insn::StPbr, &[4, 5, 4, 0]),    // memw(r4++m0:brev)=r5
    (0x4980c803, Insn::LdGp, &[3, 4, 64]),       // r3=memw(gp+#0x100)
    (0x4880c540, Insn::StGp, &[5, 4, 64]),       // memw(gp+#0x100)=r5
    (0x9b84dd03, Insn::LdAs, &[3, 4, 4, 52]),    // r3=memw(r4=##x)
    (0xab84c5b4, Insn::StAs, &[4, 5, 4, 52]),    // memw(r4=##x)=r5
    (0x9d84fd03, Insn::LdSa, &[3, 4, 4, 2, 52]), // r3=memw(r4<<#2+##x)
    (0xad84e5b0, Insn::StSa, &[4, 5, 4, 2, 48]), // memw(r4<<#2+##x)=r5
    (0x3a85e603, Insn::LdRro, &[3, 5, 6, 4, 2]), // r3=memw(r5+r6<<#2)
    (0x3b85e607, Insn::StRro, &[5, 6, 7, 4, 2]), // memw(r5+r6<<#2)=r7
    (0x3c44c012, Insn::StI, &[4, 2, 0, 18]),     // memw(r4+#0)=#0x12
    (0x3c44df12, Insn::StI, &[4, 2, 62, 18]),    // memw(r4+#0xf8)=#0x12
    (0x3844c012, Insn::StIp, &[4, 2, 0, 18, 0, 0]), // if(p0)同上
    (0x3f44c001, Insn::MopI, &[4, 2, 0, 0, 1]),  // memw(r4+#0)+=#1
    (0x3e44c065, Insn::MopR, &[4, 2, 0, 3, 5]),  // memw(r4+#0)|=r5
    (0x4184c023, Insn::LdPq, &[3, 4, 4, 1, 0, 0]), // if(p0)r3=memw(r4+#4)
    (0x4584c023, Insn::LdPq, &[3, 4, 4, 1, 0, 1]), // if(!p0)同上
    (0x4084c508, Insn::StPq, &[4, 5, 4, 1, 0, 0]), // if(p0)memw(r4+#4)=r5
    (0x9b84e043, Insn::LdPqPi, &[3, 4, 4, 2, 0, 0]), // if(p0) post-inc
    (0xab84e510, Insn::StPqPi, &[4, 5, 4, 2, 0, 0]),
    (0x9f80e083, Insn::LdPqAbs, &[3, 4, 0, 0, 0]), // if(p0)r3=memw(#u6)
    (0xaf80c580, Insn::StPqAbs, &[5, 4, 0, 0, 0]),
    (0x3085e603, Insn::LdPqRo, &[3, 5, 6, 4, 2, 0, 0]),
    (0x3485e607, Insn::StPqRo, &[5, 6, 7, 4, 2, 0, 0]),
    (0xa1a4d200, Insn::StNt, &[4, 5, 2, 1, 0]), // memw(r4+#0)=r.new
    (0xaba4d210, Insn::StPiNt, &[4, 5, 2, 1, 2]), // post-inc .new
    (0xada4d200, Insn::StPrNt, &[4, 5, 2, 1, 0]), // ++m0 .new
    (0xa9a4d210, Insn::StPciNt, &[4, 5, 2, 1, 0, 2]), // circ .new
    (0xa9a4d202, Insn::StPcrNt, &[4, 5, 2, 1, 0]), // i:circ .new
    (0x48a0d240, Insn::StGpNt, &[5, 2, 1, 64]), // gp .new
    (0x40a4d208, Insn::StPqNt, &[4, 5, 2, 1, 1, 0, 0]), // if(p0) .new
    (0xaba4f210, Insn::StPqPiNt, &[4, 5, 2, 1, 2, 0, 0]),
    (0x3ba6e712, Insn::StRoNt, &[6, 7, 5, 2, 1, 2]), // reg-off .new
    (0x34a6e712, Insn::StPqRoNt, &[6, 7, 5, 2, 1, 2, 0, 0]),
    (0xafa0d280, Insn::StPqAbsNt, &[5, 2, 1, 0, 0, 0]), // if(p0) abs .new
];

#[test]
fn hx6_decode_map() {
    for &(w, insn, ops) in HX6_WORDS {
        assert_eq!(decode(w.into(), 32), Some(insn), "word {w:#010x}");
        assert_eq!(extract_ops(insn, u128::from(w)), ops, "ops {w:#010x}");
    }
}

/// パケットを実行する（put + pc + step）。
fn exec_pkt(env: &mut BareEnv, words: &[u32]) {
    put(env, BASE, words);
    env.pc = BASE;
    step(env).unwrap();
}

/// メモリを `n` バイト読む。
fn peek(env: &mut BareEnv, addr: u64, n: usize) -> u64 {
    let acc = Access {
        endian: Endian::Le,
        align: Align::Natural,
        kind: AccessKind::DataRead,
    };
    env.backend.mem.read_value(VirtAddr(addr), n, acc).unwrap()
}

/// メモリに `n` バイト書く。
fn poke(env: &mut BareEnv, addr: u64, v: u64, n: usize) {
    env.backend
        .mem
        .write(VirtAddr(addr), &v.to_le_bytes()[..n])
        .unwrap();
}

/// コードページ（BASE・RWX）内のデータ領域。
const DATA: u64 = BASE + 0x800;

#[test]
fn hx6_ld_sizes() {
    // memb/memub/memh/memuh/memw/memd の符号・ゼロ拡張。
    let mut env = run_env();
    poke(&mut env, DATA, 0x6677_8899_2211_ff80, 8);
    sem::r_set(&mut env.backend, 4, DATA as u32);
    exec1(&mut env, 0x9104c003); // memb → 0x80 の符号拡張
    assert_eq!(sem::r_get(&env.backend, 3), 0xffff_ff80);
    exec1(&mut env, 0x9124c003); // memub → 0x80 のゼロ拡張
    assert_eq!(sem::r_get(&env.backend, 3), 0x80);
    exec1(&mut env, 0x9144c003); // memh → 0xff80 の符号拡張
    assert_eq!(sem::r_get(&env.backend, 3), 0xffff_ff80);
    exec1(&mut env, 0x9164c003); // memuh → ゼロ拡張
    assert_eq!(sem::r_get(&env.backend, 3), 0xff80);
    exec1(&mut env, 0x9184c003); // memw
    assert_eq!(sem::r_get(&env.backend, 3), 0x2211_ff80);
    exec1(&mut env, 0x91c4c004); // memd → r5:4（偶数側が下位）
    assert_eq!(sem::r_get(&env.backend, 4), 0x2211_ff80);
    assert_eq!(sem::r_get(&env.backend, 5), 0x6677_8899);
    // r29 相対（SP ベース。レジスタ+即値形と同じ形で s5=29）。
    sem::r_set(&mut env.backend, 29, (DATA - 64) as u32);
    exec1(&mut env, 0x919d_c203); // r3 = memw(r29+#64)
    assert_eq!(sem::r_get(&env.backend, 3), 0x2211_ff80);
}

#[test]
fn hx6_st_sizes() {
    // memb/memh/memw/memd/memh(=Rt.h) のストア幅。
    let mut env = run_env();
    sem::r_set(&mut env.backend, 4, DATA as u32);
    sem::r_set(&mut env.backend, 5, 0xaabb_ccdd);
    sem::r_set(&mut env.backend, 6, 0x1122_3344);
    sem::r_set(&mut env.backend, 7, 0x5566_7788);
    exec1(&mut env, 0xa104c500); // memb = r5
    assert_eq!(peek(&mut env, DATA, 1), 0xdd);
    exec1(&mut env, 0xa144c500); // memh = r5
    assert_eq!(peek(&mut env, DATA, 2), 0xccdd);
    exec1(&mut env, 0xa184c500); // memw = r5
    assert_eq!(peek(&mut env, DATA, 4), 0xaabb_ccdd);
    exec1(&mut env, 0xa1c4c601); // memd(r4+#8) = r7:6
    assert_eq!(peek(&mut env, DATA + 8, 8), 0x5566_7788_1122_3344);
    exec1(&mut env, 0xa164c500); // memh = r5.h（上位半語）
    assert_eq!(peek(&mut env, DATA, 2), 0xaabb);
    // r29 相対ストア。
    sem::r_set(&mut env.backend, 29, DATA as u32);
    exec1(&mut env, 0xa19d_c500); // memw(r29+#0) = r5
    assert_eq!(peek(&mut env, DATA, 4), 0xaabb_ccdd);
}

#[test]
fn hx6_post_incr() {
    // Rx++#s4（符号付き・サイズスケール）と Rx++Mu。
    // EA は更新前の Rx、ポストインクリメント分は commit 時に確定。
    let mut env = run_env();
    poke(&mut env, DATA, 0x1111_1111, 4);
    poke(&mut env, DATA + 8, 0x2222_2222, 4);
    poke(&mut env, DATA + 16, 0x3333_3333, 4);
    sem::r_set(&mut env.backend, 4, DATA as u32);
    sem::r_set(&mut env.backend, 5, 0xdead_beef);
    exec1(&mut env, 0x9b84c043); // r3 = memw(r4++#8)
    assert_eq!(sem::r_get(&env.backend, 3), 0x1111_1111);
    assert_eq!(sem::r_get(&env.backend, 4), (DATA + 8) as u32);
    exec1(&mut env, 0x9b84c043); // 2 回目は +8 の位置を読む
    assert_eq!(sem::r_get(&env.backend, 3), 0x2222_2222);
    exec1(&mut env, 0x9b84c1c3); // r3 = memw(r4++#-8)
    assert_eq!(sem::r_get(&env.backend, 3), 0x3333_3333);
    assert_eq!(sem::r_get(&env.backend, 4), (DATA + 8) as u32);
    exec1(&mut env, 0xab84c510); // memw(r4++#8) = r5
    assert_eq!(peek(&mut env, DATA + 8, 4), 0xdead_beef);
    assert_eq!(sem::r_get(&env.backend, 4), (DATA + 16) as u32);
    // Rx++Mu は Mu 全値が増分量（m1 に 16 を設定）。
    sem::c_set(&mut env.backend, cnum::M1.into(), 16).unwrap();
    exec1(&mut env, 0x9d84e003); // r3 = memw(r4++m1)
    assert_eq!(sem::r_get(&env.backend, 3), 0x3333_3333);
    assert_eq!(sem::r_get(&env.backend, 4), (DATA + 32) as u32);
    // ストアも同じ（m0 に -4）。
    sem::c_set(&mut env.backend, cnum::M0.into(), -4i32 as u32).unwrap();
    exec1(&mut env, 0xad84c500); // memw(r4++m0) = r5
    assert_eq!(peek(&mut env, DATA + 32, 4), 0xdead_beef);
    assert_eq!(sem::r_get(&env.backend, 4), (DATA + 28) as u32);
}

#[test]
fn hx6_circ() {
    // 円環アドレッシング: M0 = {I<<17 | length[16:0]}、
    // CS0 = バッファ開始。EA は更新前の Rx、折り返しは
    // [cs0, cs0+len) 内の新しい Rx だけに掛かる。
    let mut env = run_env();
    poke(&mut env, DATA, 0xaaaa_0001, 4);
    poke(&mut env, DATA + 4, 0xaaaa_0002, 4);
    poke(&mut env, DATA + 8, 0xaaaa_0003, 4);
    // length=16、I=2 → M0 = (2<<17)|16。
    sem::c_set(&mut env.backend, cnum::M0.into(), (2 << 17) | 16).unwrap();
    sem::c_set(&mut env.backend, cnum::CS0.into(), DATA as u32).unwrap();
    // r4 = cs0+8 で ++#8 → 新しい r4 = cs0+16 は範囲外 → cs0 に
    // 折り返し。EA は更新前の cs0+8。
    sem::r_set(&mut env.backend, 4, (DATA + 8) as u32);
    exec1(&mut env, 0x9984c043); // r3 = memw(r4++#8:circ(m0))
    assert_eq!(sem::r_get(&env.backend, 3), 0xaaaa_0003);
    assert_eq!(sem::r_get(&env.backend, 4), DATA as u32);
    // i:circ は M0 の I 桁<<scale が増分量（I=2 → +8）。
    // r4 = cs0+4 → +8 = cs0+12 で範囲内。
    sem::r_set(&mut env.backend, 4, (DATA + 4) as u32);
    exec1(&mut env, 0x9984c203); // r3 = memw(r4++i:circ(m0))
    assert_eq!(sem::r_get(&env.backend, 3), 0xaaaa_0002);
    assert_eq!(sem::r_get(&env.backend, 4), (DATA + 12) as u32);
    // ストアの円環: r4 = cs0+8 で ++#8 → cs0 に折り返し。
    sem::r_set(&mut env.backend, 4, (DATA + 8) as u32);
    sem::r_set(&mut env.backend, 5, 0xbbbb_0003);
    exec1(&mut env, 0xa984c510); // memw(r4++#8:circ(m0)) = r5
    assert_eq!(peek(&mut env, DATA + 8, 4), 0xbbbb_0003);
    assert_eq!(sem::r_get(&env.backend, 4), DATA as u32);
    // length=0 は折り返しなし（素の加算）。
    sem::c_set(&mut env.backend, cnum::M0.into(), 0).unwrap();
    exec1(&mut env, 0x9984c043);
    assert_eq!(sem::r_get(&env.backend, 3), 0xaaaa_0001);
    assert_eq!(sem::r_get(&env.backend, 4), (DATA + 8) as u32);
}

#[test]
fn hx6_brev() {
    // brev: EA = Rx.H | bit_reverse(Rx.L)。下位 16 ビットの
    // ビット反転オフセット＋上位 16 ビットの基底。
    // brev16(0x2010) = 0x0804 → r4 = 0x1_2010 で EA = DATA+4。
    let mut env = run_env();
    poke(&mut env, DATA + 4, 0xcccc_dddd, 4);
    sem::r_set(&mut env.backend, 4, 0x1_2010);
    sem::r_set(&mut env.backend, 5, 0x5555_6666);
    sem::c_set(&mut env.backend, cnum::M0.into(), 4).unwrap();
    exec1(&mut env, 0x9f84c003); // r3 = memw(r4++m0:brev)
    assert_eq!(sem::r_get(&env.backend, 3), 0xcccc_dddd);
    assert_eq!(sem::r_get(&env.backend, 4), 0x1_2014);
    // ストアも同じ EA 規則（rx は同じく 0x1_2010 に戻す）。
    sem::r_set(&mut env.backend, 4, 0x1_2010);
    exec1(&mut env, 0xaf84c500); // memw(r4++m0:brev) = r5
    assert_eq!(peek(&mut env, DATA + 4, 4), 0x5555_6666);
    assert_eq!(sem::r_get(&env.backend, 4), 0x1_2014);
}

#[test]
fn hx6_gp_and_abs() {
    // gp 相対（u16:scale オフセット）と ## 絶対。
    let mut env = run_env();
    sem::c_set(&mut env.backend, cnum::GP.into(), DATA as u32).unwrap();
    poke(&mut env, DATA + 0x100, 0x9999_8888, 4);
    exec1(&mut env, 0x4980c803); // r3 = memw(gp+#0x100)
    assert_eq!(sem::r_get(&env.backend, 3), 0x9999_8888);
    sem::r_set(&mut env.backend, 5, 0x7777_6666);
    exec1(&mut env, 0x4880c540); // memw(gp+#0x100) = r5
    assert_eq!(peek(&mut env, DATA + 0x100, 4), 0x7777_6666);
    // extender + gp 形 = ## 絶対（gp は見ない）。
    // r3 = memw(##0x1_0804)（imm26=0x2041 → 0x10804>>6=0x201+? の
    // 併合は apply_ext(e, raw6)。ここでは DATA=0x1_0800+4）。
    let addr = DATA + 4;
    let ext_hi = (addr >> 6) & 0x3ff_ffff;
    let raw6 = addr & 0x3f;
    // ld_gp の素語（ldgp16 の下位 6 ビットに raw6 が入る）。
    let base = encode(Insn::LdGp, &[3, 4, raw6]).unwrap() as u32;
    let extw = encode(Insn::Immext, &[ext_hi]).unwrap() as u32;
    poke(&mut env, addr, 0x5555_4444, 4);
    exec_pkt(&mut env, &[extw | (1 << 14), base | (3 << 14)]);
    assert_eq!(sem::r_get(&env.backend, 3), 0x5555_4444);
    // absolute-set: r4 = memw(r4=##addr) — ロードして Re に EA を
    // 残す（sa6 も ##imm の下位 6 ビット）。
    let base = encode(Insn::LdAs, &[3, 4, 4, raw6]).unwrap() as u32;
    exec_pkt(&mut env, &[extw | (1 << 14), base | (3 << 14)]);
    assert_eq!(sem::r_get(&env.backend, 3), 0x5555_4444);
    assert_eq!(sem::r_get(&env.backend, 4), addr as u32);
    // shifted-abs: r3 = memw(r4<<#2 + ##addr)。
    sem::r_set(&mut env.backend, 4, 0x10);
    poke(&mut env, addr + 0x40, 0x3333_2222, 4);
    let base = encode(Insn::LdSa, &[3, 4, 4, 2, raw6]).unwrap() as u32;
    exec_pkt(&mut env, &[extw | (1 << 14), base | (3 << 14)]);
    assert_eq!(sem::r_get(&env.backend, 3), 0x3333_2222);
    // ストア版 absolute-set / shifted-abs。
    sem::r_set(&mut env.backend, 5, 0x1111_0000);
    let base = encode(Insn::StAs, &[4, 5, 4, raw6]).unwrap() as u32;
    exec_pkt(&mut env, &[extw | (1 << 14), base | (3 << 14)]);
    assert_eq!(peek(&mut env, addr, 4), 0x1111_0000);
    assert_eq!(sem::r_get(&env.backend, 4), addr as u32);
    // StAs が r4 = ea に更新するため Ru を再設定する。
    sem::r_set(&mut env.backend, 5, 0x9999_0000);
    sem::r_set(&mut env.backend, 4, 0x10);
    let base = encode(Insn::StSa, &[4, 5, 4, 2, raw6]).unwrap() as u32;
    exec_pkt(&mut env, &[extw | (1 << 14), base | (3 << 14)]);
    assert_eq!(peek(&mut env, addr + 0x40, 4), 0x9999_0000);
}

#[test]
fn hx6_reg_offset() {
    // memXX(Rs+Ru<<#u2)。
    let mut env = run_env();
    poke(&mut env, DATA + 0x80, 0xf0f0_e0e0, 4);
    sem::r_set(&mut env.backend, 5, DATA as u32);
    sem::r_set(&mut env.backend, 6, 0x20);
    sem::r_set(&mut env.backend, 7, 0x1234_abcd);
    exec1(&mut env, 0x3a85e603); // r3 = memw(r5+r6<<#2)
    assert_eq!(sem::r_get(&env.backend, 3), 0xf0f0_e0e0);
    exec1(&mut env, 0x3b85e607); // memw(r5+r6<<#2) = r7
    assert_eq!(peek(&mut env, DATA + 0x80, 4), 0x1234_abcd);
}

#[test]
fn hx6_store_imm() {
    // memXX(Rs+#u6) = #s8 — 全サイズと符号なしオフセット。
    let mut env = run_env();
    sem::r_set(&mut env.backend, 4, DATA as u32);
    exec1(&mut env, 0x3c44c012); // memw(r4+#0) = #0x12
    assert_eq!(peek(&mut env, DATA, 4), 0x12);
    // u6 の符号なし上限（62<<2 = 0xf8。符号解釈なら負になる
    // 領域）。Ref: memop/store-imm のオフセットは #u6。
    exec1(&mut env, 0x3c44df12); // memw(r4+#0xf8) = #0x12
    assert_eq!(peek(&mut env, DATA + 0xf8, 4), 0x12);
    exec1(&mut env, 0x3c04df92); // memb(r4+#0x3f) = #0x12
    assert_eq!(peek(&mut env, DATA + 0x3f, 1), 0x12);
    exec1(&mut env, 0x3c24df92); // memh(r4+#0x7e) = #0x12
    assert_eq!(peek(&mut env, DATA + 0x7e, 2), 0x12);
    // 負の即値は符号拡張で書く（si8 = s8）。
    let w = encode(Insn::StI, &[4, 2, 0, 0x80]).unwrap() as u32;
    exec1(&mut env, with_pp(w, 3));
    assert_eq!(peek(&mut env, DATA, 4), 0xffff_ff80);
}

#[test]
fn hx6_memop() {
    // memXX(Rs+#u6) op= — read-modify-write。slot0 専用。
    let mut env = run_env();
    sem::r_set(&mut env.backend, 4, DATA as u32);
    sem::r_set(&mut env.backend, 5, 0x100);
    poke(&mut env, DATA, 0x100, 4);
    exec1(&mut env, 0x3f44c001); // += #1
    assert_eq!(peek(&mut env, DATA, 4), 0x101);
    exec1(&mut env, 0x3f44c021); // -= #1
    assert_eq!(peek(&mut env, DATA, 4), 0x100);
    exec1(&mut env, 0x3f44c063); // = setbit(#3)
    assert_eq!(peek(&mut env, DATA, 4), 0x108);
    exec1(&mut env, 0x3f44c043); // = clrbit(#3)
    assert_eq!(peek(&mut env, DATA, 4), 0x100);
    exec1(&mut env, 0x3e44c005); // += r5（0x100）
    assert_eq!(peek(&mut env, DATA, 4), 0x200);
    exec1(&mut env, 0x3e44c025); // -= r5
    assert_eq!(peek(&mut env, DATA, 4), 0x100);
    exec1(&mut env, 0x3e44c045); // &= r5
    assert_eq!(peek(&mut env, DATA, 4), 0x100);
    exec1(&mut env, 0x3e44c065); // |= r5
    assert_eq!(peek(&mut env, DATA, 4), 0x100);
    // 大きいオフセット（31<<2 = 0x7c）でも符号なし。
    exec1(&mut env, 0x3f44cf81); // memw(r4+#0x7c) += #1
    assert_eq!(peek(&mut env, DATA + 0x7c, 4), 1);
}

#[test]
fn hx6_pred_mem() {
    // 述語付き load/store: if ([!]pX[.new])。
    let mut env = run_env();
    poke(&mut env, DATA + 4, 0xaaaa_bbbb, 4);
    sem::r_set(&mut env.backend, 4, DATA as u32);
    sem::r_set(&mut env.backend, 5, 0x1234_5678);
    // if (p0): p0=0 → 抑制（レジスタもメモリも変わらない）。
    sem::p_set(&mut env.backend, 0, 0);
    exec1(&mut env, 0x4184c023);
    assert_eq!(sem::r_get(&env.backend, 3), 0);
    exec1(&mut env, 0x4084c508);
    assert_eq!(peek(&mut env, DATA + 4, 4), 0xaaaa_bbbb);
    // p0=1 → 実行。
    sem::p_set(&mut env.backend, 0, 0xff);
    exec1(&mut env, 0x4184c023);
    assert_eq!(sem::r_get(&env.backend, 3), 0xaaaa_bbbb);
    exec1(&mut env, 0x4084c508);
    assert_eq!(peek(&mut env, DATA + 4, 4), 0x1234_5678);
    // if (!p0): p0=1 → 抑制。
    exec1(&mut env, 0x4584c023);
    assert_eq!(sem::r_get(&env.backend, 3), 0xaaaa_bbbb); // 前値のまま
    sem::p_set(&mut env.backend, 0, 0);
    exec1(&mut env, 0x4584c023);
    assert_eq!(sem::r_get(&env.backend, 3), 0x1234_5678);
    // post-inc の抑制: if (!p0) で p0=1 → Rx 更新も起きない。
    sem::p_set(&mut env.backend, 0, 0xff);
    sem::r_set(&mut env.backend, 4, DATA as u32);
    exec1(&mut env, 0x9b84e843); // if (!p0) r3 = memw(r4++#8)
    assert_eq!(sem::r_get(&env.backend, 4), DATA as u32);
    exec1(&mut env, 0xab84e514); // if (!p0) memw(r4++#8) = r5
    assert_eq!(sem::r_get(&env.backend, 4), DATA as u32);
    // reg-offset 述語付き。
    sem::r_set(&mut env.backend, 5, DATA as u32);
    sem::r_set(&mut env.backend, 6, 0x20);
    sem::r_set(&mut env.backend, 7, 0x7777_8888);
    poke(&mut env, DATA + 0x80, 0x5555_6666, 4);
    sem::p_set(&mut env.backend, 0, 0xff);
    exec1(&mut env, 0x3085e603); // if (p0) r3 = memw(r5+r6<<#2)
    assert_eq!(sem::r_get(&env.backend, 3), 0x5555_6666);
    exec1(&mut env, 0x3485e607); // if (p0) memw(r5+r6<<#2) = r7
    assert_eq!(peek(&mut env, DATA + 0x80, 4), 0x7777_8888);
    // 述語付きストア即値（if (p0) memw(r4+#0) = #0x12）。
    sem::r_set(&mut env.backend, 4, DATA as u32);
    sem::p_set(&mut env.backend, 0, 0);
    exec1(&mut env, 0x3844c012);
    assert_eq!(peek(&mut env, DATA, 4), 0);
    sem::p_set(&mut env.backend, 0, 0xff);
    exec1(&mut env, 0x3844c012);
    assert_eq!(peek(&mut env, DATA, 4), 0x12);
    // if (p0.new): 生産側と同じパケットでだけ発火。
    // { p0 = cmp.eq(r1,r2) ; if (p0.new) r3 = memw(r4+#4) }
    sem::r_set(&mut env.backend, 1, 7);
    sem::r_set(&mut env.backend, 2, 7);
    exec_pkt(&mut env, &[0xf201_4200, 0x4384_c023]);
    assert_eq!(sem::r_get(&env.backend, 3), 0x1234_5678);
    sem::r_set(&mut env.backend, 3, 0);
    sem::r_set(&mut env.backend, 2, 8); // cmp.eq → p0.new = 偽
    exec_pkt(&mut env, &[0xf201_4200, 0x4384_c023]);
    assert_eq!(sem::r_get(&env.backend, 3), 0);
    // { p0 = cmp.eq(r1,r2) ; if (p0.new) memw(r4+#4) = r5 }
    // （r5 は reg-offset の確認で別値になっているため再設定）。
    sem::r_set(&mut env.backend, 2, 7);
    sem::r_set(&mut env.backend, 5, 0x8765_4321);
    exec_pkt(&mut env, &[0xf201_4200, 0x4284_c508]);
    assert_eq!(peek(&mut env, DATA + 4, 4), 0x8765_4321);
}

#[test]
fn hx6_pred_abs() {
    // 述語付き abs（#u6 はバイトアドレス、拡張は ##imm 全体）。
    let mut env = run_env();
    let addr = DATA + 0x40;
    let ext_hi = (addr >> 6) & 0x3ff_ffff;
    let raw6 = addr & 0x3f;
    let extw = encode(Insn::Immext, &[ext_hi]).unwrap() as u32 | (1 << 14);
    poke(&mut env, addr, 0xabcd_0001, 4);
    sem::p_set(&mut env.backend, 0, 0xff);
    // if (p0) r3 = memw(#addr)（u6a は符号なし絶対アドレス）。
    let base = encode(Insn::LdPqAbs, &[3, 4, raw6, 0, 0]).unwrap() as u32;
    exec_pkt(&mut env, &[extw, base | (3 << 14)]);
    assert_eq!(sem::r_get(&env.backend, 3), 0xabcd_0001);
    // if (p0) memw(#addr) = r5。
    sem::r_set(&mut env.backend, 5, 0xabcd_0002);
    let base = encode(Insn::StPqAbs, &[5, 4, raw6, 0, 0]).unwrap() as u32;
    exec_pkt(&mut env, &[extw, base | (3 << 14)]);
    assert_eq!(peek(&mut env, addr, 4), 0xabcd_0002);
    // p0=0 では抑制。
    sem::p_set(&mut env.backend, 0, 0);
    sem::r_set(&mut env.backend, 3, 0);
    exec_pkt(&mut env, &[extw, base | (3 << 14)]);
    assert_eq!(peek(&mut env, addr, 4), 0xabcd_0002);
}

#[test]
fn hx6_new_store() {
    // `.new` 値ストア: 生産距離 Nt の位置の命令が書く最初の
    // gpr の未確定値がソース。
    let mut env = run_env();
    sem::r_set(&mut env.backend, 4, DATA as u32);
    // { r5 = #0x12 ; memw(r4+#0) = r5.new }（nt=1）。
    exec_pkt(&mut env, &[0x7800_4245, 0xa1a4_d200]);
    assert_eq!(peek(&mut env, DATA, 4), 0x12);
    assert_eq!(sem::r_get(&env.backend, 5), 0x12);
    // 生産はパケットの古い値でなく未確定値: r5 に先に別値を置き、
    // 生産命令の書き込みがストアに届く（上で確認済み）。
    // nt=2（2 個前の生産命令）。
    exec_pkt(&mut env, &[0x7800_4245, 0x7800_4686, 0xa1a4_d400]);
    assert_eq!(peek(&mut env, DATA, 4), 0x12);
    // nt=3。
    exec_pkt(
        &mut env,
        &[0x7800_4245, 0xb000_4026, 0xb000_4047, 0xa1a4_d600],
    );
    assert_eq!(peek(&mut env, DATA, 4), 0x12);
    // post-inc .new（memw(r4++#8) = r5.new）。
    sem::r_set(&mut env.backend, 4, DATA as u32);
    exec_pkt(&mut env, &[0x7800_4245, 0xaba4_d210]);
    assert_eq!(peek(&mut env, DATA, 4), 0x12);
    assert_eq!(sem::r_get(&env.backend, 4), (DATA + 8) as u32);
    // 述語付き .new（if (p0) memw(r4+#4) = r5.new）。p0 偽では
    // 抑制（nv_src に到達しない）。post-inc で r4 が進むため
    // 基底を戻す。
    sem::r_set(&mut env.backend, 4, DATA as u32);
    sem::p_set(&mut env.backend, 0, 0);
    exec_pkt(&mut env, &[0x7800_4245, 0x40a4_d208]);
    assert_eq!(peek(&mut env, DATA + 4, 4), 0);
    sem::p_set(&mut env.backend, 0, 0xff);
    exec_pkt(&mut env, &[0x7800_4245, 0x40a4_d208]);
    assert_eq!(peek(&mut env, DATA + 4, 4), 0x12);
    // reg-offset .new（memw(r6+r7<<#2) = r5.new）。
    sem::r_set(&mut env.backend, 6, DATA as u32);
    sem::r_set(&mut env.backend, 7, 0x40);
    exec_pkt(&mut env, &[0x7800_4245, 0x3ba6_e712]);
    assert_eq!(peek(&mut env, DATA + 0x100, 4), 0x12);
    // 述語付き abs .new（if (p0) memw(##addr) = r5.new）。
    // u6b は ##addr の下位 6 ビット（DATA+0x80 → 0）。
    let addr = DATA + 0x80;
    let ext_hi = (addr >> 6) & 0x3ff_ffff;
    let extw = encode(Insn::Immext, &[ext_hi]).unwrap() as u32 | (1 << 14);
    exec_pkt(&mut env, &[0x7800_4245, extw, 0xafa0_d280]);
    assert_eq!(peek(&mut env, addr, 4), 0x12);
    // memb/memh の .new（sz2 の全幅）。
    exec_pkt(&mut env, &[0x7800_4245, 0xa1a4_c204]); // memb(r4+#4)
    assert_eq!(peek(&mut env, DATA + 4, 1), 0x12);
    exec_pkt(&mut env, &[0x7800_4245, 0xa1a4_ca02]); // memh(r4+#4)
    assert_eq!(peek(&mut env, DATA + 4, 2), 0x12);
    // Mu 修飾 .new（m1 = +16）。
    sem::r_set(&mut env.backend, 4, DATA as u32);
    sem::c_set(&mut env.backend, cnum::M1.into(), 16).unwrap();
    exec_pkt(&mut env, &[0x7800_4245, 0xada4_f200]);
    assert_eq!(peek(&mut env, DATA, 4), 0x12);
    assert_eq!(sem::r_get(&env.backend, 4), (DATA + 16) as u32);
    // 円環 .new（cs0+8 → +8 で cs0 に折り返し）。
    sem::c_set(&mut env.backend, cnum::M0.into(), (2 << 17) | 16).unwrap();
    sem::c_set(&mut env.backend, cnum::CS0.into(), DATA as u32).unwrap();
    sem::r_set(&mut env.backend, 4, (DATA + 8) as u32);
    exec_pkt(&mut env, &[0x7800_4245, 0xa9a4_d210]);
    assert_eq!(peek(&mut env, DATA + 8, 4), 0x12);
    assert_eq!(sem::r_get(&env.backend, 4), DATA as u32);
    // i:circ .new（I=2 → +8。cs0+4 → cs0+12）。
    sem::r_set(&mut env.backend, 4, (DATA + 4) as u32);
    exec_pkt(&mut env, &[0x7800_4245, 0xa9a4_d202]);
    assert_eq!(peek(&mut env, DATA + 4, 4), 0x12);
    assert_eq!(sem::r_get(&env.backend, 4), (DATA + 12) as u32);
    // brev .new（rx = 0x1_2010 → EA = DATA+4）。
    sem::c_set(&mut env.backend, cnum::M0.into(), 4).unwrap();
    sem::r_set(&mut env.backend, 4, 0x1_2010);
    exec_pkt(&mut env, &[0x7800_4245, 0xafa4_d200]);
    assert_eq!(peek(&mut env, DATA + 4, 4), 0x12);
    assert_eq!(sem::r_get(&env.backend, 4), 0x1_2014);
    // gp 相対 .new。
    sem::c_set(&mut env.backend, cnum::GP.into(), DATA as u32).unwrap();
    exec_pkt(&mut env, &[0x7800_4245, 0x48a0_d240]); // memw(gp+#0x100)
    assert_eq!(peek(&mut env, DATA + 0x100, 4), 0x12);
    // 述語付き reg-offset .new（if (p0) memw(r6+r7<<#2) = r5.new）。
    sem::p_set(&mut env.backend, 0, 0xff);
    exec_pkt(&mut env, &[0x7800_4245, 0x34a6_e712]);
    assert_eq!(peek(&mut env, DATA + 0x100, 4), 0x12);
    // 3 命令パケット: {p0 = cmp.eq ; r5 = #imm ; if (p0.new)
    // memw(r4++#8) = r5.new}。述語も .new で読み、値は nt=1 の
    // 生産（pos1）から取る。
    sem::r_set(&mut env.backend, 4, DATA as u32);
    sem::r_set(&mut env.backend, 1, 7);
    sem::r_set(&mut env.backend, 2, 7);
    exec_pkt(&mut env, &[0xf201_4200, 0x7800_4245, 0xaba4_f290]);
    assert_eq!(peek(&mut env, DATA, 4), 0x12);
    assert_eq!(sem::r_get(&env.backend, 4), (DATA + 8) as u32);
}

#[test]
fn hx6_new_store_errors() {
    // 生産側がいない（単独の .new ストア）は構成エラー →
    // illegal パケット。
    let mut env = run_env();
    sem::r_set(&mut env.backend, 4, DATA as u32);
    put(&mut env, BASE, &[0xa1a4_d200]);
    env.pc = BASE;
    assert!(matches!(step(&mut env), Err(Outcome::Unimplemented { .. })));
    // 生産距離にいる命令が gpr を書かない（ストア同士）も
    // 実行時 illegal。
    let mut env = run_env();
    sem::r_set(&mut env.backend, 4, DATA as u32);
    sem::r_set(&mut env.backend, 5, 1);
    put(&mut env, BASE, &[with_pp(0xa104_c500, 1), 0xa1a4_d200]);
    env.pc = BASE;
    assert!(matches!(step(&mut env), Err(Outcome::Unimplemented { .. })));
}

#[test]
fn hx6_dual_store_order() {
    // 同一パケットの 2 ストアは slot1 → slot0 の順で処理される。
    // 重なる領域は slot0（後ろの語）が勝つ。
    let mut env = run_env();
    sem::r_set(&mut env.backend, 4, DATA as u32);
    sem::r_set(&mut env.backend, 5, 0x1122_3344);
    sem::r_set(&mut env.backend, 6, 0xee);
    // { memw(r4+#0) = r5 ; memb(r4+#0) = r6 }
    // （先の語が slot1 → 先に処理 → slot0 の byte が残る）。
    let stw = with_pp(encode(Insn::StRi, &[4, 5, 4, 0]).unwrap() as u32, 1);
    let stb = with_pp(encode(Insn::StRi, &[4, 6, 0, 0]).unwrap() as u32, 3);
    exec_pkt(&mut env, &[stw, stb]);
    assert_eq!(peek(&mut env, DATA, 4), 0x1122_33ee);
    // mem_noshuf（slot1 store + slot0 load）: ロードはストア
    // 済みの値を読む（実行順どおり）。
    let ldw = with_pp(encode(Insn::LdRi, &[3, 4, 4, 0]).unwrap() as u32, 3);
    exec_pkt(&mut env, &[stw, ldw]);
    assert_eq!(sem::r_get(&env.backend, 3), 0x1122_3344);
}

#[test]
fn hx6_alignment() {
    // 非整列アクセスは例外（illegal パケットへ畳まれる）。
    let mut env = run_env();
    sem::r_set(&mut env.backend, 4, (DATA + 1) as u32);
    put(&mut env, BASE, &[0x9184_c003]); // r3 = memw(r4+#0)、奇数 EA
    env.pc = BASE;
    assert!(matches!(step(&mut env), Err(Outcome::Unimplemented { .. })));
    // memh の奇数アドレスも同じ。
    let mut env = run_env();
    sem::r_set(&mut env.backend, 4, (DATA + 1) as u32);
    put(&mut env, BASE, &[0x9144_c003]);
    env.pc = BASE;
    assert!(matches!(step(&mut env), Err(Outcome::Unimplemented { .. })));
    // memb は常に整列。
    let mut env = run_env();
    poke(&mut env, DATA + 1, 0x5a, 1);
    sem::r_set(&mut env.backend, 4, (DATA + 1) as u32);
    exec1(&mut env, 0x9104c003);
    assert_eq!(sem::r_get(&env.backend, 3), 0x5a);
}

// ---- HX7: 分岐・frame・system ----
// 語は llvm-mc 実符号（V73 プロファイル）をそのまま使う。

#[test]
fn hx7_pred_jumps() {
    // { if (p0) jump #0 } = 0x5c00c000（jump:nt）。p0 真で分岐、
    // 偽で次へ進む。分岐先として jump #0x10 の形を使う。
    // { if (p0) jump:nt #off } — off は r15 桁（pc+off）。
    let j = |off: u64| -> u32 {
        // `if (p0) jump` = 0x5c00c000 + r15 桁（{23:22}+{20:16}
        // +{13}+{7:1}、zfill 2）。
        let f = (off >> 2) as u32;
        0x5c00_c000
            | (((f >> 13) & 3) << 22)
            | (((f >> 8) & 0x1f) << 16)
            | (((f >> 7) & 1) << 13)
            | ((f & 0x7f) << 1)
    };
    let mut env = run_env();
    put(&mut env, BASE, &[j(0x40)]);
    env.pc = BASE;
    sem::p_set(&mut env.backend, 0, 0xff);
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 0x40);
    let mut env = run_env();
    put(&mut env, BASE, &[j(0x40)]);
    env.pc = BASE;
    sem::p_set(&mut env.backend, 0, 0);
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 4);
    // if (!p1) jump:t（llvm-mc 実符号 0x5c20d100 → +off）。
    // { if (!p1) jump:t #off }：否定 + p1、hint は意味論を変えない。
    let jn = |off: u64| -> u32 {
        let f = (off >> 2) as u32;
        0x5c20_d100
            | (((f >> 13) & 3) << 22)
            | (((f >> 8) & 0x1f) << 16)
            | (((f >> 7) & 1) << 13)
            | ((f & 0x7f) << 1)
    };
    let mut env = run_env();
    put(&mut env, BASE, &[jn(0x40)]);
    env.pc = BASE;
    sem::p_set(&mut env.backend, 1, 0);
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 0x40, "if (!p1) jump:t、p1 偽で分岐");
    let mut env = run_env();
    put(&mut env, BASE, &[jn(0x40)]);
    env.pc = BASE;
    sem::p_set(&mut env.backend, 1, 0xff);
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 4, "if (!p1) jump:t、p1 真で抑制");
    // { if (p0.new) jump:nt } の生産ペア（p0 = cmp.eq + jump_pqn。
    // jump_pqn = 0x5c00c800 + r15 桁。実符号照合: 5343c800 系）。
    let jpn = |off: u64| -> u32 {
        let f = (off >> 2) as u32;
        0x5c00_c800
            | (((f >> 13) & 3) << 22)
            | (((f >> 8) & 0x1f) << 16)
            | (((f >> 7) & 1) << 13)
            | ((f & 0x7f) << 1)
    };
    // { p0 = cmp.eq(r3,#5)（非終端）; if (p0.new) jump:nt }。
    let mut env = run_env();
    let cmp = with_pp(0x7503_40a0, 1); // p0 = cmp.eq(r3,#5)
    put(&mut env, BASE, &[cmp, jpn(0x40)]);
    env.pc = BASE;
    sem::r_set(&mut env.backend, 3, 5);
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 0x40, "p0.new 真で分岐");
    assert_eq!(sem::p_get(&env.backend, 0), 0xff);
    let mut env = run_env();
    put(&mut env, BASE, &[cmp, jpn(0x40)]);
    env.pc = BASE;
    sem::r_set(&mut env.backend, 3, 4);
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 8, "p0.new 偽で抑制（2 語分進む）");
}

#[test]
fn hx7_cond_calls_and_indirect() {
    // { if (p0) call } = 0x5d00c000 + r15 桁。p0 真で LR 更新+分岐。
    let c = |off: u64| -> u32 {
        let f = (off >> 2) as u32;
        0x5d00_c000
            | (((f >> 13) & 3) << 22)
            | (((f >> 8) & 0x1f) << 16)
            | (((f >> 7) & 1) << 13)
            | ((f & 0x7f) << 1)
    };
    let mut env = run_env();
    put(&mut env, BASE, &[c(0x40)]);
    env.pc = BASE;
    sem::p_set(&mut env.backend, 0, 0xff);
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 0x40);
    assert_eq!(sem::r_get(&env.backend, 31), (BASE + 4) as u32, "LR=r31");
    let mut env = run_env();
    put(&mut env, BASE, &[c(0x40)]);
    env.pc = BASE;
    sem::p_set(&mut env.backend, 0, 0);
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 4);
    assert_eq!(sem::r_get(&env.backend, 31), 0, "抑制時 LR は変えない");
    // { if (p0) callr r3 } = 0x5103c000 / if (!p0) = 0x5123c000。
    let mut env = run_env();
    put(&mut env, BASE, &[0x5103_c000]);
    env.pc = BASE;
    sem::p_set(&mut env.backend, 0, 0xff);
    sem::r_set(&mut env.backend, 3, 0x8000);
    step(&mut env).unwrap();
    assert_eq!(env.pc, 0x8000);
    assert_eq!(sem::r_get(&env.backend, 31), (BASE + 4) as u32);
    let mut env = run_env();
    put(&mut env, BASE, &[0x5123_c000]);
    env.pc = BASE;
    sem::p_set(&mut env.backend, 0, 0xff);
    sem::r_set(&mut env.backend, 3, 0x8000);
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 4, "if (!p0) callr、p0 真で抑制");
    // { if (!p0) jumpr:t r3 } = 0x5363d000（hint は意味論を変えない）。
    let mut env = run_env();
    put(&mut env, BASE, &[0x5363_d000]);
    env.pc = BASE;
    sem::p_set(&mut env.backend, 0, 0);
    sem::r_set(&mut env.backend, 3, 0x7000);
    step(&mut env).unwrap();
    assert_eq!(env.pc, 0x7000);
    // { if (p0.new) jumpr:nt r3 } = 0x5343c800（p0 生産ペア）。
    let mut env = run_env();
    let cmp = with_pp(0x7503_40a0, 1);
    put(&mut env, BASE, &[cmp, 0x5343_c800]);
    env.pc = BASE;
    sem::r_set(&mut env.backend, 3, 0x6000);
    sem::r_set(&mut env.backend, 4, 0); // cmp.eq 用の比較値は同じ r3
    step(&mut env).unwrap();
    // p0 = cmp.eq(r3,#5) は偽（r3=0x6000）→ jumpr 抑制。
    assert_eq!(env.pc, BASE + 8);
}

#[test]
fn hx7_reg_cond_jumps() {
    // `if (Rs{!=,>=,==,<=} #0) jump`（llvm-mc 実符号系。
    // r13 桁 = {21}+{13}+{11:1}、zfill 2）。hint 桁 bit12。
    let rcj = |sel: u32, off: u64| -> u32 {
        let f = (off >> 2) as u32;
        0x6103_d000
            | (sel << 22)
            | (((f >> 12) & 1) << 21)
            | (((f >> 7) & 1) << 13)
            | ((f & 0x7f) << 1)
    };
    // sel: 00=!= 01=>= 10=== 11=<=
    for (sel, v, want) in [
        (0u32, 7u32, true), // r3!=0 で分岐
        (0, 0, false),
        (1, 0, true), // >=0 は 0 でも分岐
        (1, 0xffff_ffff, false),
        (2, 0, true), // ==0
        (2, 1, false),
        (3, 0xffff_ffff, true), // <=0 は負でも分岐
        (3, 1, false),
    ] {
        let mut env = run_env();
        put(&mut env, BASE, &[rcj(sel, 0x40)]);
        env.pc = BASE;
        sem::r_set(&mut env.backend, 3, v);
        step(&mut env).unwrap();
        assert_eq!(
            env.pc,
            if want { BASE + 0x40 } else { BASE + 4 },
            "sel={sel} r3={v:#x}"
        );
    }
}

#[test]
fn hx7_compound_cj() {
    // `1440c206` = p0 = cmp.eq(r0,r2); if (!p0.new) jump:nt #0xc。
    let mut env = run_env();
    put(&mut env, BASE, &[0x1440_c206]);
    env.pc = BASE;
    sem::r_set(&mut env.backend, 0, 1);
    sem::r_set(&mut env.backend, 2, 2);
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 0xc, "cmp 偽 + !p0.new で分岐");
    assert_eq!(sem::p_get(&env.backend, 0), 0);
    let mut env = run_env();
    put(&mut env, BASE, &[0x1440_c206]);
    env.pc = BASE;
    sem::r_set(&mut env.backend, 0, 2);
    sem::r_set(&mut env.backend, 2, 2);
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 4);
    assert_eq!(sem::p_get(&env.backend, 0), 0xff);
    // `1003c500` = p0 = cmp.eq(r3,#5); if (p0.new) jump:nt #0。
    // オフセット 0 は自身へ分岐（pc + 0 → 無限ループになるので、
    // 即値だけ直して正のオフセットにする）。bits[7:1]+[21:20]。
    let cji = |r: u32, u: u32, off: u64| -> u32 {
        let f = (off >> 2) as u32;
        0x1003_c000 | (r << 16) | (u << 8) | (((f >> 7) & 3) << 20) | ((f & 0x7f) << 1)
    };
    let mut env = run_env();
    put(&mut env, BASE, &[cji(3, 5, 0x30)]);
    env.pc = BASE;
    sem::r_set(&mut env.backend, 3, 5);
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 0x30, "cmp.eq 真 + p0.new で分岐");
    assert_eq!(sem::p_get(&env.backend, 0), 0xff);
    let mut env = run_env();
    put(&mut env, BASE, &[cji(3, 5, 0x30)]);
    env.pc = BASE;
    sem::r_set(&mut env.backend, 3, 9);
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 4);
}

#[test]
fn hx7_nvj() {
    // `{ r3 = add(r0,#1); if (cmp.eq(r3.new,r5)) jump:t }` —
    // llvm-mc 実符号 [0xb0004023, 0x2002e500]。N.t = 距離×2
    // （nt3=2 → 1 命令前の生産を読む）。分岐先 r9=0 は自身。
    let mut env = run_env();
    put(
        &mut env,
        BASE,
        &[
            0xb000_4023, // r3 = add(r0,#1)（pp=01）
            0x2002_e500, // if (cmp.eq(r3.new,r5)) jump:t #0
        ],
    );
    env.pc = BASE;
    sem::r_set(&mut env.backend, 0, 4);
    sem::r_set(&mut env.backend, 5, 5);
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE, "cmp 真で jump（target=パケット先頭）");
    assert_eq!(sem::r_get(&env.backend, 3), 5, "生産側 add も commit");
    // 偽なら 2 語進む。
    let mut env = run_env();
    put(&mut env, BASE, &[0xb000_4023, 0x2002_e500]);
    env.pc = BASE;
    sem::r_set(&mut env.backend, 0, 4);
    sem::r_set(&mut env.backend, 5, 9);
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 8);
    // 距離 2 の生産も読める（llvm-mc 実符号 0x2004e500）。
    let mut env = run_env();
    put(
        &mut env,
        BASE,
        &[
            0xb000_4023,             // r3 = add(r0,#1)
            with_pp(0xb000_c024, 1), // r4 = add(r0,#1)（途中語）
            0x2004_e500,
        ],
    );
    env.pc = BASE;
    sem::r_set(&mut env.backend, 0, 4);
    sem::r_set(&mut env.backend, 5, 5);
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE, "距離 2 でも r3.new を読む");
    // 即値形: `2402e500` = cmp.eq(r3.new,#5) 距離 1（実符号）。
    let mut env = run_env();
    put(&mut env, BASE, &[0xb000_4023, 0x2402_e500]);
    env.pc = BASE;
    sem::r_set(&mut env.backend, 0, 4);
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE, "cmp.eq(r3.new,#5) 真で分岐");
    // 生産者不在（NVJ だけ）→ illegal。
    let mut env = run_env();
    put(&mut env, BASE, &[0x2002_e500]);
    env.pc = BASE;
    assert!(matches!(step(&mut env), Err(Outcome::Unimplemented { .. })));
}

#[test]
fn hx7_transfer_jump() {
    // `1603c700` = r3 = #7; jump #0（tj_i）。`1704c300` = r3 = r4;
    // jump #0（tj_r）。
    let mut env = run_env();
    put(&mut env, BASE, &[0x1603_c700]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE, "r9=0 で自身へ");
    assert_eq!(sem::r_get(&env.backend, 3), 7);
    let mut env = run_env();
    put(&mut env, BASE, &[0x1704_c300]);
    env.pc = BASE;
    sem::r_set(&mut env.backend, 4, 0xbeef);
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE);
    assert_eq!(sem::r_get(&env.backend, 3), 0xbeef);
}

#[test]
fn hx7_dual_jump() {
    // { if (p0) jump A ; call B }: 先の jump が成立なら call は
    // まるごと無視（LR を書かない）。
    let j = |off: u64| -> u32 {
        let f = (off >> 2) as u32;
        0x5c00_4000 // pp=01（非終端）
            | (((f >> 13) & 3) << 22)
            | (((f >> 8) & 0x1f) << 16)
            | (((f >> 7) & 1) << 13)
            | ((f & 0x7f) << 1)
    };
    let call = |off: u64| -> u32 {
        let f = (off >> 2) as u32;
        0x5a00_c000
            | (((f >> 13) & 3) << 22)
            | (((f >> 8) & 0x1f) << 16)
            | (((f >> 7) & 1) << 13)
            | ((f & 0x7f) << 1)
    };
    // p0 真 → 1 個目の jump が勝ち、call の LR 更新は起きない。
    let mut env = run_env();
    put(&mut env, BASE, &[j(0x40), call(0x60)]);
    env.pc = BASE;
    sem::p_set(&mut env.backend, 0, 0xff);
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 0x40);
    assert_eq!(
        sem::r_get(&env.backend, 31),
        0,
        "無視された call は LR を書かない"
    );
    // p0 偽 → call が実行され LR=r31 に次パケットを残す。
    let mut env = run_env();
    put(&mut env, BASE, &[j(0x40), call(0x60)]);
    env.pc = BASE;
    sem::p_set(&mut env.backend, 0, 0);
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 0x60);
    assert_eq!(sem::r_get(&env.backend, 31), (BASE + 8) as u32);
    // 無条件系 2 個・JR を含む組合せは illegal。
    let mut env = run_env();
    put(
        &mut env,
        BASE,
        &[
            with_pp(0x5800_c004, 1), // jump #8
            with_pp(0x5800_c004, 3), // jump #8
        ],
    );
    env.pc = BASE;
    assert!(matches!(step(&mut env), Err(Outcome::Unimplemented { .. })));
    let mut env = run_env();
    put(
        &mut env,
        BASE,
        &[
            with_pp(0x5c00_c004, 1), // if (p0) jump
            with_pp(0x5283_c000, 3), // jumpr r3
        ],
    );
    env.pc = BASE;
    assert!(matches!(step(&mut env), Err(Outcome::Unimplemented { .. })));
}

#[test]
fn hx7_frames() {
    // allocframe(#0x18) = 0xa09dc003。SP=0x9000 → 記録は
    // 0x8ff8 に {FP_old, LR_old}、FP=0x8ff8、SP=0x8fe0。
    let mut env = run_env();
    // フレーム記録の書き込み先がマップ済み領域に要る。
    env.backend
        .mem
        .map(VirtAddr(0x8000), 1, Perms(Perms::RW.0))
        .unwrap();
    sem::r_set(&mut env.backend, 29, 0x9000);
    sem::r_set(&mut env.backend, 30, 0xaaaa);
    sem::r_set(&mut env.backend, 31, 0xbbbb);
    put(&mut env, BASE, &[0xa09d_c003]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(sem::r_get(&env.backend, 30), 0x8ff8);
    assert_eq!(sem::r_get(&env.backend, 29), 0x8fe0);
    assert_eq!(peek(&mut env, 0x8ff8, 4), 0xaaaa, "FP_old at [FP]");
    assert_eq!(peek(&mut env, 0x8ffc, 4), 0xbbbb, "LR_old at [FP+4]");
    // deallocframe: r31:30 = memd(r30); SP=r30+8。
    let mut env = run_env();
    env.backend
        .mem
        .map(VirtAddr(0x8000), 1, Perms(Perms::RW.0))
        .unwrap();
    poke(&mut env, 0x8ff8, 0x1111, 4);
    poke(&mut env, 0x8ffc, 0x2222, 4);
    sem::r_set(&mut env.backend, 29, 0x8fe0);
    sem::r_set(&mut env.backend, 30, 0x8ff8);
    put(&mut env, BASE, &[0x901e_c01e]); // deallocframe
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(sem::r_get(&env.backend, 30), 0x1111, "FP 復帰");
    assert_eq!(sem::r_get(&env.backend, 31), 0x2222, "LR 復帰");
    assert_eq!(sem::r_get(&env.backend, 29), 0x9000, "SP = r30+8");
    // dealloc_return: 復帰のうえ LR（上位ワード）へ分岐。
    let mut env = run_env();
    env.backend
        .mem
        .map(VirtAddr(0x8000), 1, Perms(Perms::RW.0))
        .unwrap();
    poke(&mut env, 0x8ff8, 0x1111, 4);
    poke(&mut env, 0x8ffc, 0x6000, 4);
    sem::r_set(&mut env.backend, 29, 0x8fe0);
    sem::r_set(&mut env.backend, 30, 0x8ff8);
    put(&mut env, BASE, &[0x961e_c01e]); // dealloc_return
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.pc, 0x6000);
    assert_eq!(sem::r_get(&env.backend, 30), 0x1111);
    assert_eq!(sem::r_get(&env.backend, 31), 0x6000);
    assert_eq!(sem::r_get(&env.backend, 29), 0x9000);
    // if (!p0) dealloc_return（0x961ef01e）: p0 偽で復帰、真で抑制。
    let mut env = run_env();
    env.backend
        .mem
        .map(VirtAddr(0x8000), 1, Perms(Perms::RW.0))
        .unwrap();
    poke(&mut env, 0x8ff8, 0x1111, 4);
    poke(&mut env, 0x8ffc, 0x6000, 4);
    sem::r_set(&mut env.backend, 30, 0x8ff8);
    sem::p_set(&mut env.backend, 0, 0);
    put(&mut env, BASE, &[0x961e_f01e]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.pc, 0x6000);
    let mut env = run_env();
    env.backend
        .mem
        .map(VirtAddr(0x8000), 1, Perms(Perms::RW.0))
        .unwrap();
    sem::r_set(&mut env.backend, 30, 0x8ff8);
    sem::p_set(&mut env.backend, 0, 0xff);
    put(&mut env, BASE, &[0x961e_f01e]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 4, "p0 真で !p0 抑制");
    // r7:6 = deallocframe(r29):raw（0x901dc006）: 任意対への raw 形。
    let mut env = run_env();
    env.backend
        .mem
        .map(VirtAddr(0x8000), 1, Perms(Perms::RW.0))
        .unwrap();
    poke(&mut env, 0x8ff8, 0x3333, 4);
    poke(&mut env, 0x8ffc, 0x4444, 4);
    sem::r_set(&mut env.backend, 29, 0x8ff8);
    put(&mut env, BASE, &[0x901d_c006]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(sem::r_get(&env.backend, 6), 0x3333);
    assert_eq!(sem::r_get(&env.backend, 7), 0x4444);
    assert_eq!(sem::r_get(&env.backend, 29), 0x9000);
    // allocframe → dealloc_return の往復。
    let mut env = run_env();
    env.backend
        .mem
        .map(VirtAddr(0x8000), 1, Perms(Perms::RW.0))
        .unwrap();
    sem::r_set(&mut env.backend, 29, 0x9000);
    sem::r_set(&mut env.backend, 30, 0xaaaa);
    sem::r_set(&mut env.backend, 31, 0x5000);
    put(&mut env, BASE, &[0xa09d_c003, 0x961e_c01e]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(sem::r_get(&env.backend, 29), 0x8fe0);
    assert_eq!(sem::r_get(&env.backend, 30), 0x8ff8);
    step(&mut env).unwrap();
    assert_eq!(env.pc, 0x5000, "LR 復帰先へ");
    assert_eq!(sem::r_get(&env.backend, 30), 0xaaaa);
    assert_eq!(sem::r_get(&env.backend, 31), 0x5000);
    assert_eq!(sem::r_get(&env.backend, 29), 0x9000);
    // duplex: { r0 = #0 ; allocframe(#0x10) }（実符号 0x68003c20）。
    let mut env = run_env();
    env.backend
        .mem
        .map(VirtAddr(0x8000), 1, Perms(Perms::RW.0))
        .unwrap();
    sem::r_set(&mut env.backend, 29, 0x9000);
    sem::r_set(&mut env.backend, 30, 0xaaaa);
    sem::r_set(&mut env.backend, 31, 0xbbbb);
    put(&mut env, BASE, &[0x6800_3c20]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(sem::r_get(&env.backend, 30), 0x8ff8);
    assert_eq!(sem::r_get(&env.backend, 29), 0x8fe8);
    // duplex: { r0 = #0 ; dealloc_return }（実符号 0x48003f40）。
    let mut env = run_env();
    env.backend
        .mem
        .map(VirtAddr(0x8000), 1, Perms(Perms::RW.0))
        .unwrap();
    poke(&mut env, 0x8ff8, 0x1111, 4);
    poke(&mut env, 0x8ffc, 0x6000, 4);
    sem::r_set(&mut env.backend, 30, 0x8ff8);
    put(&mut env, BASE, &[0x4800_3f40]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.pc, 0x6000);
    assert_eq!(sem::r_get(&env.backend, 30), 0x1111);
    assert_eq!(sem::r_get(&env.backend, 29), 0x9000);
    // duplex: { r0 = #0 ; deallocframe }（実符号 0x48003f00）。
    let mut env = run_env();
    env.backend
        .mem
        .map(VirtAddr(0x8000), 1, Perms(Perms::RW.0))
        .unwrap();
    poke(&mut env, 0x8ff8, 0x1111, 4);
    poke(&mut env, 0x8ffc, 0x2222, 4);
    sem::r_set(&mut env.backend, 30, 0x8ff8);
    put(&mut env, BASE, &[0x4800_3f00]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 4, "deallocframe は分岐しない");
    assert_eq!(sem::r_get(&env.backend, 30), 0x1111);
    assert_eq!(sem::r_get(&env.backend, 31), 0x2222);
    // duplex: { r0 = #0 ; if (!p0) jumpr r31 }（実符号 0x48003fc5）。
    let mut env = run_env();
    sem::r_set(&mut env.backend, 31, 0x7777);
    sem::p_set(&mut env.backend, 0, 0);
    put(&mut env, BASE, &[0x4800_3fc5]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.pc, 0x7777);
    let mut env = run_env();
    sem::r_set(&mut env.backend, 31, 0x7777);
    sem::p_set(&mut env.backend, 0, 0xff);
    put(&mut env, BASE, &[0x4800_3fc5]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 4);
}

#[test]
fn hx7_traps_and_hints() {
    // trap0(#0x3f) = 0x5400c71c（u8 即値）。trap1(r3,#0x7f) =
    // 0x5483cf1c → code = 0x100|0x7f。pause は no-op。
    let mut env = run_env();
    put(&mut env, BASE, &[0x5400_c71c]);
    env.pc = BASE;
    let mut sys = Rec {
        code: None,
        outcome: TrapOutcome::Exit(9),
    };
    assert_eq!(run::step(&mut env, &mut sys, 0), Err(Outcome::Exit(9)));
    assert_eq!(sys.code, Some(0x3f));
    let mut env = run_env();
    put(&mut env, BASE, &[0x5483_cf1c]);
    env.pc = BASE;
    let mut sys = Rec {
        code: None,
        outcome: TrapOutcome::Exit(9),
    };
    assert_eq!(run::step(&mut env, &mut sys, 0), Err(Outcome::Exit(9)));
    assert_eq!(sys.code, Some(0x17f));
    // pause(#0x155) = 0x5441ca14 は no-op で次へ進む。
    let mut env = run_env();
    put(&mut env, BASE, &[0x5441_ca14]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 4);
    // hintjr(r3) = 0x52a3c000 は建築状態を変えない no-op。
    let mut env = run_env();
    put(&mut env, BASE, &[0x52a3_c000]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 4);
    // if (!p0.new) jumpr:t r4（パケット内 p0 生産つき、
    // llvm-mc 実符号 0x5364d800）。生産が真なら !p0.new で抑制。
    let mut env = run_env();
    put(&mut env, BASE, &[0x7503_40a0, 0x5364_d800]);
    env.pc = BASE;
    sem::r_set(&mut env.backend, 3, 5);
    sem::r_set(&mut env.backend, 4, 0x4321);
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 8, "p0.new 真で !p0.new 抑制");
    let mut env = run_env();
    put(&mut env, BASE, &[0x7503_40a0, 0x5364_d800]);
    env.pc = BASE;
    sem::r_set(&mut env.backend, 3, 4);
    sem::r_set(&mut env.backend, 4, 0x4321);
    step(&mut env).unwrap();
    assert_eq!(env.pc, 0x4321, "p0.new 偽で分岐");
}

// ---- HX8: ハードウェアループ ----
// Ref: SPEC-HEXAGON-PRM (V79) Section 8.

#[test]
fn hx8_loop_words() {
    // llvm-mc 実符号との突き合わせ。
    // loop0(#0,#10) / loop1(#8,#100) / loop0(#16,r5) / loop1(#12,r31)
    for (w, insn, ops) in [
        (0x6900_c042u32, Insn::Loop0i, &[0u64, 10] as &[u64]),
        (0x6923_c030, Insn::Loop1i, &[8, 100]),
        (0x6005_c100, Insn::Loop0r, &[16, 5]),
        (0x603f_c018, Insn::Loop1r, &[12, 31]),
    ] {
        assert_eq!(decode(u128::from(w), 32), Some(insn), "decode {w:#010x}");
        assert_eq!(extract_ops(insn, u128::from(w)), ops, "ops {w:#010x}");
        assert_eq!(decode(u128::from(w), 13), None, "duplex {w:#010x}");
    }
    // エンコード往復。
    for (insn, ops) in [
        (Insn::Loop0i, &[8u64, 3] as &[u64]),
        (Insn::Loop1i, &[16, 100]),
        (Insn::Loop0r, &[8, 5]),
        (Insn::Loop1r, &[8, 31]),
    ] {
        let w = encode(insn, ops).unwrap() as u32;
        assert_eq!(decode(u128::from(w), 32), Some(insn));
        assert_eq!(extract_ops(insn, u128::from(w)), ops);
    }
    // 符号表示。
    assert_eq!(
        disasm_word_ex(0x6900_c042, 32, true, 0).as_deref(),
        Some("loop0(#0,#10)")
    );
    assert_eq!(
        disasm_word_ex(0x603f_c018, 32, true, 0).as_deref(),
        Some("loop1(#12,r31)")
    );
}

#[test]
fn hx8_loop0_imm() {
    // loop0(#8,#3): 宣言パケットから +8 バイト先のパケットを
    // 3 回回る。LC0 は endloop でだけ変わる。
    let mut env = run_env();
    let l = with_pp(encode(Insn::Loop0i, &[8, 3]).unwrap() as u32, 3);
    let body0 = with_pp(encode(Insn::AddRi, &[1, 1, 1]).unwrap() as u32, 2);
    let body1 = with_pp(encode(Insn::AddRi, &[2, 2, 1]).unwrap() as u32, 3);
    let after = with_pp(encode(Insn::EqS16, &[3, 99]).unwrap() as u32, 3);
    put(&mut env, BASE, &[l, with_pp(NOP, 3), body0, body1, after]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(
        sem::c_get(&env.backend, cnum::SA0.into()).unwrap(),
        BASE as u32 + 8
    );
    assert_eq!(sem::c_get(&env.backend, cnum::LC0.into()).unwrap(), 3);
    assert_eq!(env.pc, BASE + 4);
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 8, "ループ先頭パケットへ進む");
    for (n, lc) in [(1, 2), (2, 1)] {
        step(&mut env).unwrap();
        assert_eq!(sem::r_get(&env.backend, 1), n);
        assert_eq!(sem::r_get(&env.backend, 2), n);
        assert_eq!(sem::c_get(&env.backend, cnum::LC0.into()).unwrap(), lc);
        assert_eq!(env.pc, BASE + 8, "LC0>1 で SA0 復帰");
    }
    // LC0=1 の終端では減算せず通り抜ける。
    step(&mut env).unwrap();
    assert_eq!(sem::r_get(&env.backend, 1), 3);
    assert_eq!(sem::c_get(&env.backend, cnum::LC0.into()).unwrap(), 1);
    assert_eq!(env.pc, BASE + 16);
    step(&mut env).unwrap();
    assert_eq!(sem::r_get(&env.backend, 3), 99);
    assert_eq!(env.pc, BASE + 20);
}

#[test]
fn hx8_loop1_reg() {
    // loop1(#4,r5): レジスタカウント。外側ループ用の組。
    let mut env = run_env();
    let l = with_pp(encode(Insn::Loop1r, &[4, 5]).unwrap() as u32, 3);
    let body0 = with_pp(encode(Insn::AddRi, &[1, 1, 1]).unwrap() as u32, 2);
    let body1 = with_pp(encode(Insn::AddRi, &[2, 2, 1]).unwrap() as u32, 2);
    let body2 = with_pp(encode(Insn::AddRi, &[3, 3, 1]).unwrap() as u32, 3);
    let after = with_pp(encode(Insn::EqS16, &[4, 7]).unwrap() as u32, 3);
    put(&mut env, BASE, &[l, body0, body1, body2, after]);
    env.pc = BASE;
    sem::r_set(&mut env.backend, 5, 2);
    step(&mut env).unwrap();
    assert_eq!(
        sem::c_get(&env.backend, cnum::SA1.into()).unwrap(),
        BASE as u32 + 4
    );
    assert_eq!(sem::c_get(&env.backend, cnum::LC1.into()).unwrap(), 2);
    // 1 周目: LC1 2→1 で SA1 復帰。2 周目: LC1=1 で抜ける。
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 4, "LC1>1 で SA1 復帰");
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 16, "LC1=1 でループ脱出");
    step(&mut env).unwrap();
    assert_eq!(sem::r_get(&env.backend, 1), 2);
    assert_eq!(sem::r_get(&env.backend, 2), 2);
    assert_eq!(sem::r_get(&env.backend, 3), 2);
    assert_eq!(sem::r_get(&env.backend, 4), 7);
}

#[test]
fn hx8_nested_loops() {
    // PRM 例の形: 外側 loop1 の体内で内側 loop0 を毎周宣言する。
    //   +0  loop1(#8,#2)
    //   +4  nop
    //   +8  loop0(#8,#3)          <- SA1 が指す外側先頭
    //   +12 nop
    //   +16 r1+=1 :endloop0       <- SA0 が指す内側先頭
    //   +20 r2+=1
    //   +24 r3+=1
    //   +28 r4+=1 :endloop1
    //   +32 r5+=1
    //   +36 r6=#9
    let mut env = run_env();
    let l1 = with_pp(encode(Insn::Loop1i, &[8, 2]).unwrap() as u32, 3);
    let l0 = with_pp(encode(Insn::Loop0i, &[8, 3]).unwrap() as u32, 3);
    let last = with_pp(encode(Insn::EqS16, &[6, 9]).unwrap() as u32, 3);
    put(
        &mut env,
        BASE,
        &[
            l1,
            with_pp(NOP, 3),
            l0,
            with_pp(NOP, 3),
            with_pp(encode(Insn::AddRi, &[1, 1, 1]).unwrap() as u32, 2),
            with_pp(encode(Insn::AddRi, &[2, 2, 1]).unwrap() as u32, 3),
            with_pp(encode(Insn::AddRi, &[3, 3, 1]).unwrap() as u32, 1),
            with_pp(encode(Insn::AddRi, &[4, 4, 1]).unwrap() as u32, 2),
            with_pp(encode(Insn::AddRi, &[5, 5, 1]).unwrap() as u32, 3),
            last,
        ],
    );
    env.pc = BASE;
    step(&mut env).unwrap(); // loop1
    step(&mut env).unwrap(); // nop
    step(&mut env).unwrap(); // loop0
    assert_eq!(
        sem::c_get(&env.backend, cnum::SA0.into()).unwrap(),
        BASE as u32 + 16
    );
    step(&mut env).unwrap(); // nop -> +16
    // 内側 3 周。
    for n in 1..=3 {
        step(&mut env).unwrap();
        assert_eq!(sem::r_get(&env.backend, 1), n);
        assert_eq!(env.pc, if n < 3 { BASE + 16 } else { BASE + 24 });
    }
    // 外側 1 周目の終端: LC1 2→1 で SA1（loop0 宣言）へ。
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 8);
    assert_eq!(sem::r_get(&env.backend, 3), 1);
    step(&mut env).unwrap(); // loop0 再宣言で LC0 が 3 に戻る
    assert_eq!(sem::c_get(&env.backend, cnum::LC0.into()).unwrap(), 3);
    step(&mut env).unwrap(); // nop
    // 内側 3 周（2 周目）。
    for _ in 0..3 {
        step(&mut env).unwrap();
    }
    assert_eq!(sem::r_get(&env.backend, 1), 6);
    assert_eq!(env.pc, BASE + 24);
    // 外側 2 周目の終端: LC1=1 で脱出。
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 36);
    assert_eq!(sem::c_get(&env.backend, cnum::LC1.into()).unwrap(), 1);
    step(&mut env).unwrap();
    assert_eq!(sem::r_get(&env.backend, 3), 2);
    assert_eq!(sem::r_get(&env.backend, 4), 2);
    assert_eq!(sem::r_get(&env.backend, 5), 2);
    assert_eq!(sem::r_get(&env.backend, 6), 9);
}

#[test]
fn hx8_dual_endloop() {
    // 1 パケットに :endloop0:endloop1 が両方付く形。
    // 内側 loop0 が先に裁かれる。
    let mut env = run_env();
    let l1 = with_pp(encode(Insn::Loop1i, &[8, 2]).unwrap() as u32, 3);
    let l0 = with_pp(encode(Insn::Loop0i, &[4, 2]).unwrap() as u32, 3);
    let b0 = with_pp(encode(Insn::AddRi, &[1, 1, 1]).unwrap() as u32, 2);
    let b1 = with_pp(encode(Insn::AddRi, &[2, 2, 1]).unwrap() as u32, 2);
    let b2 = with_pp(encode(Insn::AddRi, &[3, 3, 1]).unwrap() as u32, 3);
    let last = with_pp(encode(Insn::EqS16, &[4, 5]).unwrap() as u32, 3);
    put(&mut env, BASE, &[l1, l0, b0, b1, b2, last]);
    env.pc = BASE;
    step(&mut env).unwrap();
    step(&mut env).unwrap();
    // 終端パケット実行: LC0 2→1 で SA0 復帰（LC1 はまだ不変）。
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 8);
    assert_eq!(sem::c_get(&env.backend, cnum::LC0.into()).unwrap(), 1);
    assert_eq!(sem::c_get(&env.backend, cnum::LC1.into()).unwrap(), 2);
    // 2 回目: LC0=1 で内側判定を通り、LC1 2→1 で SA1 復帰。
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 8, "SA1 は内側先頭と同じアドレス");
    assert_eq!(sem::c_get(&env.backend, cnum::LC1.into()).unwrap(), 1);
    // 3 回目: 両方 LC=1 で脱出。
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 20);
    assert_eq!(sem::r_get(&env.backend, 1), 3);
    step(&mut env).unwrap();
    assert_eq!(sem::r_get(&env.backend, 4), 5);
}

#[test]
fn hx8_loop_zero_and_one() {
    // LC=0/1 の宣言でも本体は必ず 1 回実行され、終端で
    // 減算せずに抜ける（LC は端境でもそのまま残る）。
    for count in [0u64, 1] {
        let mut env = run_env();
        let l = with_pp(encode(Insn::Loop0i, &[4, count]).unwrap() as u32, 3);
        let b0 = with_pp(encode(Insn::AddRi, &[1, 1, 1]).unwrap() as u32, 2);
        let b1 = with_pp(encode(Insn::EqS16, &[2, 1]).unwrap() as u32, 3);
        let last = with_pp(encode(Insn::EqS16, &[3, 2]).unwrap() as u32, 3);
        put(&mut env, BASE, &[l, b0, b1, last]);
        env.pc = BASE;
        step(&mut env).unwrap();
        step(&mut env).unwrap();
        assert_eq!(env.pc, BASE + 12, "LC={count} は 1 回で脱出");
        assert_eq!(sem::r_get(&env.backend, 1), 1);
        assert_eq!(
            sem::c_get(&env.backend, cnum::LC0.into()).unwrap(),
            count as u32
        );
        step(&mut env).unwrap();
        assert_eq!(sem::r_get(&env.backend, 3), 2);
    }
}

#[test]
fn hx8_loop_extender() {
    // `loop0(##0x12345678,#10)`（llvm-mc 実符号）: extender
    // 併合でもオフセットは PC 相対のまま（jump と同じ規則で、
    // SA = パケット先頭 + 併合値）。
    let mut env = run_env();
    put(
        &mut env,
        BASE,
        &[with_pp(0x0123_5159, 1), with_pp(0x6900_ce03, 3)],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(
        sem::c_get(&env.backend, cnum::SA0.into()).unwrap(),
        BASE as u32 + 0x1234_5678
    );
    assert_eq!(sem::c_get(&env.backend, cnum::LC0.into()).unwrap(), 3);
    assert_eq!(env.pc, BASE + 8);
}

#[test]
fn hx8_loop_packet_rules() {
    // ループ終端パケットのプログラムフロー命令は拒否。
    let (pkt, _) = packet::split(&[with_pp(NOP, 2), with_pp(JUMP, 3)]).unwrap();
    assert_eq!(packet::expand(&pkt).unwrap_err(), ComposeError::LoopEndFlow);
    // duplex の jumpr R31 もフロー命令。
    let dup = packet::pack_duplex(0x1fc0, 0x1010, Group::L2, Group::A).unwrap();
    let (pkt, _) = packet::split(&[with_pp(NOP, 2), dup]).unwrap();
    assert_eq!(packet::expand(&pkt).unwrap_err(), ComposeError::LoopEndFlow);
    // endloop0 パケットで SA0/LC0 を書く loop0 宣言は拒否。
    let l0 = with_pp(encode(Insn::Loop0i, &[8, 3]).unwrap() as u32, 2);
    let (pkt, _) = packet::split(&[l0, with_pp(NOP, 3)]).unwrap();
    assert_eq!(
        packet::expand(&pkt).unwrap_err(),
        ComposeError::LoopEndWrite
    );
    // endloop0 で c1=Rs（LC0 への転送）も拒否。
    let wc = with_pp(encode(Insn::Wrcr, &[1, 5]).unwrap() as u32, 2);
    let (pkt, _) = packet::split(&[wc, with_pp(NOP, 3)]).unwrap();
    assert_eq!(
        packet::expand(&pkt).unwrap_err(),
        ComposeError::LoopEndWrite
    );
    // 反対側の組（endloop0 で loop1 / c3=Rs）は許容。
    let l1 = with_pp(encode(Insn::Loop1i, &[8, 3]).unwrap() as u32, 2);
    let (pkt, _) = packet::split(&[l1, with_pp(NOP, 3)]).unwrap();
    assert!(packet::expand(&pkt).is_ok(), "endloop0 で SA1/LC1 は書ける");
    let wc3 = with_pp(encode(Insn::Wrcr, &[3, 5]).unwrap() as u32, 2);
    let (pkt, _) = packet::split(&[wc3, with_pp(NOP, 3)]).unwrap();
    assert!(packet::expand(&pkt).is_ok());
    // loop 宣言パケットの投機的間接ジャンプは拒否。
    let l = with_pp(encode(Insn::Loop0i, &[8, 3]).unwrap() as u32, 1);
    let j = with_pp(encode(Insn::JumprPqn, &[31, 0, 0]).unwrap() as u32, 3);
    let (pkt, _) = packet::split(&[l, j]).unwrap();
    assert_eq!(
        packet::expand(&pkt).unwrap_err(),
        ComposeError::LoopSetupFlow
    );
    // new-value compare jump も拒否。
    let nv = with_pp(encode(Insn::NvjEqr, &[2, 5, 0, 4]).unwrap() as u32, 3);
    let (pkt, _) = packet::split(&[l, nv]).unwrap();
    assert_eq!(
        packet::expand(&pkt).unwrap_err(),
        ComposeError::LoopSetupFlow
    );
    // dealloc_return（32 ビット形）も拒否。
    let d = with_pp(encode(Insn::Deallocret, &[30, 30]).unwrap() as u32, 3);
    let (pkt, _) = packet::split(&[l, d]).unwrap();
    assert_eq!(
        packet::expand(&pkt).unwrap_err(),
        ComposeError::LoopSetupFlow
    );
    // duplex の dealloc_return も拒否。
    let dup = packet::pack_duplex(0x1f40, 0x1010, Group::L2, Group::A).unwrap();
    let (pkt, _) = packet::split(&[l, dup]).unwrap();
    assert_eq!(
        packet::expand(&pkt).unwrap_err(),
        ComposeError::LoopSetupFlow
    );
    // loop 宣言と普通の命令の同居は許容。
    let i = with_pp(encode(Insn::AddRi, &[1, 1, 1]).unwrap() as u32, 3);
    let (pkt, _) = packet::split(&[l, i]).unwrap();
    assert!(packet::expand(&pkt).is_ok());
}
