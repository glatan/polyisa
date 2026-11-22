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
    // if (p0) は真で抑制しない（Unimplemented に達する）。
    let c = sem::DotIf {
        p: 0,
        neg: false,
        new: false,
    };
    let e = sem::exec(&mut env.backend, Insn::Nop, 0, Some(c)).unwrap_err();
    assert!(matches!(e, InterpExit::Unimplemented(_)));
    // if (!p0) は偽なので抑制される。
    let c = sem::DotIf {
        p: 0,
        neg: true,
        new: false,
    };
    assert_eq!(
        sem::exec(&mut env.backend, Insn::Nop, 0, Some(c)),
        Ok(false)
    );
    // if (p1) で p1 未設定は抑制される。
    let c = sem::DotIf {
        p: 1,
        neg: false,
        new: false,
    };
    assert_eq!(
        sem::exec(&mut env.backend, Insn::Nop, 0, Some(c)),
        Ok(false)
    );
}

#[test]
fn exec_is_unimplemented() {
    let mut env = env();
    let e = sem::exec(&mut env.backend, Insn::Nop, 0, None).unwrap_err();
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
const JUMPR: u32 = 0x5284_0000; // jumpr r4
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
    assert_eq!(s[0].slot, 3); // J は {2,3} の上位
    let (pkt, _) = packet::split(&[with_pp(RDCR, 3)]).unwrap();
    let s = packet::expand(&pkt).unwrap();
    assert_eq!(s[0].slot, 3); // CR は slot3 固定
    // { J ; ALU32 }（メモリ順 = slot3 → slot0 の単調減少）。
    let (pkt, _) = packet::split(&[with_pp(JUMPR, 1), with_pp(ADD_RI, 3)]).unwrap();
    let s = packet::expand(&pkt).unwrap();
    assert_eq!((s[0].slot, s[1].slot), (3, 2));
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
