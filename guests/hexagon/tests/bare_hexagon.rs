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
    assert_eq!(core::mem::size_of::<CpuState>(), pkt + 32 * 4 + 12);
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
    // if (p0) は真で抑制しない（Unimplemented に達する）。
    let c = sem::DotIf {
        p: 0,
        neg: false,
        new: false,
    };
    let e = sem::exec(&mut env.backend, Insn::DxL2Deallocframe, 0, with(Some(c))).unwrap_err();
    assert!(matches!(e, InterpExit::Unimplemented(_)));
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

#[test]
fn exec_is_unimplemented() {
    let mut env = env();
    // frame 系（allocframe/deallocframe/dealloc_return）は HX7。
    let e = sem::exec(
        &mut env.backend,
        Insn::DxL2Deallocframe,
        0,
        sem::Ctx::default(),
    )
    .unwrap_err();
    assert!(matches!(e, InterpExit::Unimplemented(_)));
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
    assert_eq!(decode(0x9184_c003, 32), Some(Insn::LdwRi));
    assert_eq!(extract_ops(Insn::LdwRi, 0x9184_c003), vec![3, 4, 0]);
    // scaled 即値（#1024 → 256<<2）。
    assert_eq!(extract_ops(Insn::LdwRi, 0x9184_e003), vec![3, 4, 1024]);
    assert_eq!(decode(0xa184_c500, 32), Some(Insn::StwRi));
    assert_eq!(extract_ops(Insn::StwRi, 0xa184_c500), vec![4, 5, 0]);
    // ST の負の scaled 即値（#-8 → 0x7fe<<2 の生値）。
    assert_eq!(extract_ops(Insn::StwRi, 0xa784_e5fe), vec![4, 5, 0x1ff8]);
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
    let w = rt(Insn::LdwRi, &[3, 4, 1024]);
    assert_eq!(extract_ops(Insn::LdwRi, u128::from(w)), vec![3, 4, 1024]);
    let w = rt(Insn::StwRi, &[4, 5, 16]);
    assert_eq!(extract_ops(Insn::StwRi, u128::from(w)), vec![4, 5, 16]);
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
use polyisa_mem::{Perms, VirtAddr};
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
    // （LC/SA の処理自体は HX8）。
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
