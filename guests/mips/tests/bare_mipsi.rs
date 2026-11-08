// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! MIPS I 試作の命令単位のテスト。裸実行環境で CPU 状態と遅延スロットを検査する.
//! 出典は SPEC-MIPS-IV Rev 3.2 (1995-09) である.
//! Ref: SPEC-MIPS-IV (Rev 3.2).

use polyisa_engine::bare::BareEnv;
use polyisa_guest_mips::CpuState;
use polyisa_guest_mips::sem::{self, Gpr};
use polyisa_sem::Backend as _;

fn env() -> BareEnv {
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    env.map_rw(0x1_0000, 1).unwrap();
    env.map_rw(0x0, 1).unwrap();
    env
}

fn g(env: &mut BareEnv, r: u8) -> u64 {
    env.backend.get(Gpr(r).state())
}

#[test]
fn add_sub_logic() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 12);
    env.backend.set(Gpr(2).state(), 10);
    env.step(|b| sem::addu(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(g(&mut env, 3), 22);
    env.step(|b| sem::subu(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(g(&mut env, 3), 2);
    env.step(|b| sem::and(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(g(&mut env, 3), 8);
    env.step(|b| sem::or(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(g(&mut env, 3), 14);
    // $0 への書き込みは捨てる。
    env.step(|b| sem::addu(b, Gpr(0), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(g(&mut env, 0), 0);
}

#[test]
fn addu_wraps_without_trap() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 0xffff_ffff);
    env.backend.set(Gpr(2).state(), 1);
    // ADDU は trap せず下位32ビットで包む。
    env.step(|b| sem::addu(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(g(&mut env, 3), 0);
}

#[test]
fn shift_uses_low_5bits() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 1);
    env.step(|b| sem::sll(b, Gpr(2), Gpr(1), 2)).unwrap();
    assert_eq!(g(&mut env, 2), 4);
}

#[test]
fn load_store_be_roundtrip() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 0x100);
    env.backend.set(Gpr(2).state(), 0x1234_5678);
    env.step(|b| sem::sw(b, Gpr(2), Gpr(1), 0)).unwrap();
    env.step(|b| sem::lw(b, Gpr(3), Gpr(1), 0)).unwrap();
    assert_eq!(g(&mut env, 3), 0x1234_5678);
}

#[test]
fn delay_slot_executes_before_branch() {
    let mut env = env();
    env.backend.set(sem::pc_ref(), 0x1000);
    // fallthrough は sem 内部で pc+8 を計算する。
    env.backend.set(sem::npc_ref(), 0x1008);
    env.backend.set(Gpr(1).state(), 5);
    env.backend.set(Gpr(2).state(), 5);
    // beq 成立：npc=pc+4+disp*4。
    env.step(|b| sem::beq_delay(b, Gpr(1), Gpr(2), 0x1000, 4))
        .unwrap();
    assert_eq!(env.backend.get(sem::npc_ref()), 0x1014);
    // 遅延スロットは必ず実行される。
    env.backend.set(Gpr(3).state(), 0);
    env.step(|b| sem::addu(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(g(&mut env, 3), 10);
    env.step(sem::commit).unwrap();
    assert_eq!(env.backend.get(sem::pc_ref()), 0x1014);
    // 不成立：npc は fallthrough のまま。
    env.backend.set(sem::pc_ref(), 0x2000);
    env.backend.set(sem::npc_ref(), 0x2008);
    env.backend.set(Gpr(2).state(), 6);
    env.step(|b| sem::beq_delay(b, Gpr(1), Gpr(2), 0x2000, 4))
        .unwrap();
    assert_eq!(env.backend.get(sem::npc_ref()), 0x2008);
}

#[test]
fn jump_defers_one_slot() {
    let mut env = env();
    env.backend.set(sem::pc_ref(), 0x1000);
    env.backend.set(sem::npc_ref(), 0x1008);
    env.step(|b| sem::j_delay(b, 0x3000)).unwrap();
    assert_eq!(env.backend.get(sem::npc_ref()), 0x3000);
    env.step(sem::commit).unwrap();
    assert_eq!(env.backend.get(sem::pc_ref()), 0x3000);
    assert_eq!(env.backend.get(sem::npc_ref()), 0x3004);
}
