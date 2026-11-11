// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! R3000 の検証列。裸の命令を実行し、同じ列のサイクル数を設計文書の表と照合する。
//!
//! 加算・ストア・分岐・ジャンプは 1、ロードの結果は開始+2、乗算は開始+12、
//! 除算は開始+35、syscall は 0。キャッシュはモデルしない。
//! Ref: SPEC-MIPS-R3000 (Rev 1.0).

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::InterpExit;
use polyisa_guest_mips::CpuState;
use polyisa_guest_mips::sem::{self, Gpr};
use polyisa_sem::{Backend as _, ExceptionKind};
use polyisa_timing::{ExactModel, InstrEvent, TimingModel as _, VirtualTime};

const HI: u64 = 1 << 32;
const LO: u64 = 1 << 33;

fn env() -> BareEnv {
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    env.map_rw(0, 1).unwrap();
    env
}

fn g(env: &mut BareEnv, r: u8) -> u64 {
    env.backend.get(Gpr(r).state())
}

fn bit(reg: u8) -> u64 {
    1 << reg
}

fn cycles(events: &[&InstrEvent]) -> u64 {
    let mut model = ExactModel::r3000();
    for event in events {
        model.observe(event);
    }
    let VirtualTime(n) = model.now();
    n
}

#[test]
fn sequences_match_the_published_table() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 12);
    env.backend.set(Gpr(2).state(), 10);
    env.step(|b| sem::addu(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(g(&mut env, 3), 22);
    let alu = InstrEvent::new(0x1000, "alu")
        .reads(bit(1) | bit(2))
        .writes(bit(3));
    assert_eq!(cycles(&[&alu]), 1);

    env.backend.set(Gpr(4).state(), 0x100);
    env.backend.set(Gpr(5).state(), 0x11);
    env.step(|b| sem::sw(b, Gpr(5), Gpr(4), 0)).unwrap();
    let store = InstrEvent::new(0x1004, "store").reads(bit(4) | bit(5));
    assert_eq!(cycles(&[&store]), 1);

    env.backend.set(sem::pc_ref(), 0x2000);
    env.step(|b| sem::beq_delay(b, Gpr(1), Gpr(1), 0x2000, 4))
        .unwrap();
    assert_eq!(env.backend.get(sem::npc_ref()), 0x2014);
    let branch = InstrEvent::new(0x2000, "branch").reads(bit(1));
    assert_eq!(cycles(&[&branch]), 1);

    env.step(|b| sem::j_delay(b, 0x3000)).unwrap();
    assert_eq!(env.backend.get(sem::npc_ref()), 0x3000);
    let jump = InstrEvent::new(0x2004, "jump");
    assert_eq!(cycles(&[&jump]), 1);

    env.step(|b| sem::lw(b, Gpr(6), Gpr(4), 0)).unwrap();
    assert_eq!(g(&mut env, 6), 0x11);
    let load = InstrEvent::new(0x1008, "load").reads(bit(4)).writes(bit(6));
    assert_eq!(cycles(&[&load]), 1);

    env.step(|b| sem::addu(b, Gpr(7), Gpr(6), Gpr(2))).unwrap();
    assert_eq!(g(&mut env, 7), 0x1b);
    let use_load = InstrEvent::new(0x100c, "alu")
        .reads(bit(6) | bit(2))
        .writes(bit(7));
    assert_eq!(cycles(&[&load, &use_load]), 3);

    env.step(|b| sem::addu(b, Gpr(8), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(g(&mut env, 8), 22);
    let independent = InstrEvent::new(0x1010, "alu")
        .reads(bit(1) | bit(2))
        .writes(bit(8));
    assert_eq!(cycles(&[&load, &independent]), 2);

    env.backend.set(Gpr(1).state(), 7);
    env.backend.set(Gpr(2).state(), 6);
    env.step(|b| sem::mult(b, Gpr(1), Gpr(2))).unwrap();
    env.step(|b| sem::mflo(b, Gpr(9))).unwrap();
    assert_eq!(g(&mut env, 9), 42);
    let mult = InstrEvent::new(0x1014, "mult")
        .reads(bit(1) | bit(2))
        .writes(HI | LO);
    let mflo = InstrEvent::new(0x1018, "alu").reads(LO).writes(bit(9));
    assert_eq!(cycles(&[&mult]), 1);
    assert_eq!(cycles(&[&mult, &mflo]), 13);

    env.backend.set(Gpr(1).state(), 42);
    env.backend.set(Gpr(2).state(), 6);
    env.step(|b| sem::div(b, Gpr(1), Gpr(2))).unwrap();
    env.step(|b| sem::mflo(b, Gpr(10))).unwrap();
    assert_eq!(g(&mut env, 10), 7);
    let div = InstrEvent::new(0x101c, "div")
        .reads(bit(1) | bit(2))
        .writes(HI | LO);
    let mflo_div = InstrEvent::new(0x1020, "alu").reads(LO).writes(bit(10));
    assert_eq!(cycles(&[&div]), 1);
    assert_eq!(cycles(&[&div, &mflo_div]), 36);

    let err = env.step(sem::syscall);
    match err {
        Err(InterpExit::Exception(exception)) => assert_eq!(exception.kind, ExceptionKind::Break),
        other => panic!("syscall should raise, got {other:?}"),
    }
    let system = InstrEvent::new(0x1024, "system");
    assert_eq!(cycles(&[&system]), 0);
}
