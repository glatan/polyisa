// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Hexagon 骨格の最小テスト。CpuState の構成・述語の規則・
//! パケット未確定域（pkt_*）の commit と .new 転送、dot-if
//! 抑制の入口を確かめる。
//! 出典は SPEC-HEXAGON-PRM V79 (80-N2040-60 Rev AB) である。
//! Ref: SPEC-HEXAGON-PRM (V79).

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::InterpExit;
use polyisa_guest_hexagon::{CpuState, Insn, cnum, sem};

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
    let e = sem::exec(&mut env.backend, Insn::Bad, 0, Some(c)).unwrap_err();
    assert!(matches!(e, InterpExit::Unimplemented(_)));
    // if (!p0) は偽なので抑制される。
    let c = sem::DotIf {
        p: 0,
        neg: true,
        new: false,
    };
    assert_eq!(
        sem::exec(&mut env.backend, Insn::Bad, 0, Some(c)),
        Ok(false)
    );
    // if (p1) で p1 未設定は抑制される。
    let c = sem::DotIf {
        p: 1,
        neg: false,
        new: false,
    };
    assert_eq!(
        sem::exec(&mut env.backend, Insn::Bad, 0, Some(c)),
        Ok(false)
    );
}

#[test]
fn exec_is_unimplemented() {
    let mut env = env();
    let e = sem::exec(&mut env.backend, Insn::Bad, 0, None).unwrap_err();
    assert!(matches!(e, InterpExit::Unimplemented(_)));
}
