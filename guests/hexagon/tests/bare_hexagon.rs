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
