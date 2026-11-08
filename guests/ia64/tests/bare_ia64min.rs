// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! IA-64 最小の命令単位のテスト。裸実行環境で述語と回転を検査する.
//! 出典は SPEC-IA64-SDM Rev 2.3 (2010-05) である.
//! Ref: SPEC-IA64-SDM (Rev 2.3).

use polyisa_engine::bare::BareEnv;
use polyisa_guest_ia64::CpuState;
use polyisa_guest_ia64::sem::{self, Gpr, Pred, Rot};
use polyisa_sem::{Backend as _, StateRef, W64};

fn env() -> BareEnv {
    BareEnv::new(core::mem::size_of::<CpuState>())
}

fn g(env: &mut BareEnv, r: u8) -> u64 {
    env.backend.get(Gpr(r).state())
}

fn pr_ref(i: u8) -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, pr) + (i as usize) * 8)
}

fn rot_ref(i: u8) -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, rot) + (i as usize) * 8)
}

fn rrb_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, rrb))
}

fn pc_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, pc))
}

#[test]
fn add_sub() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 40);
    env.backend.set(Gpr(2).state(), 2);
    env.step(|b| sem::add(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(g(&mut env, 3), 42);
    env.step(|b| sem::sub(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(g(&mut env, 3), 38);
}

#[test]
fn pred_guards_write() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 40);
    env.backend.set(Gpr(2).state(), 2);
    env.backend.set(Gpr(3).state(), 0);
    // p1 = 真：書き込む。
    env.backend.set(pr_ref(1), 1);
    env.step(|b| sem::add_pred(b, Pred(1), Gpr(3), Gpr(1), Gpr(2)))
        .unwrap();
    assert_eq!(g(&mut env, 3), 42);
    // p2 = 偽：書かない。
    env.backend.set(pr_ref(2), 0);
    env.step(|b| sem::add_pred(b, Pred(2), Gpr(3), Gpr(1), Gpr(2)))
        .unwrap();
    assert_eq!(g(&mut env, 3), 42);
}

#[test]
fn rotating_reads_rrb_plus_index() {
    let mut env = env();
    // rot[2] = 100、RRB=1 のとき論理0は物理1を読む。
    env.backend.set(rot_ref(2), 100);
    env.backend.set(rrb_ref(), 1);
    env.backend.set(Gpr(2).state(), 5);
    env.step(|b| sem::add_rot(b, Gpr(3), Rot(0), Gpr(2)))
        .unwrap();
    // 論理0 + RRB1 = 物理1。rot[1] は 0 のままなので結果は 5。
    assert_eq!(g(&mut env, 3), 5);
    // RRB=2 のとき論理0は物理2を読む。
    env.backend.set(rrb_ref(), 2);
    env.step(|b| sem::add_rot(b, Gpr(3), Rot(0), Gpr(2)))
        .unwrap();
    assert_eq!(g(&mut env, 3), 105);
}

#[test]
fn br_sets_pc() {
    let mut env = env();
    env.step(|b| sem::br(b, 0x1000)).unwrap();
    assert_eq!(env.backend.get(pc_ref()), 0x1000);
}

#[test]
fn nop_keeps_state() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 7);
    env.step(sem::nop).unwrap();
    assert_eq!(g(&mut env, 1), 7);
}
