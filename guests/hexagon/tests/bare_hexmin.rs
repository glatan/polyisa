// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Hexagon 最小の命令単位のテスト。裸実行環境でパケットの一括反映を検査する.
//! 出典は SPEC-HEXAGON-PRM V73 である.
//! Ref: SPEC-HEXAGON-PRM (V73).

use polyisa_engine::bare::BareEnv;
use polyisa_guest_hexagon::CpuState;
use polyisa_guest_hexagon::sem::{self, R};
use polyisa_sem::Backend as _;

fn env() -> BareEnv {
    BareEnv::new(core::mem::size_of::<CpuState>())
}

fn r(env: &mut BareEnv, i: u8) -> u32 {
    env.backend.get(R(i).state())
}

#[test]
fn packet_buffers_until_commit() {
    let mut env = env();
    env.backend.set(R(1).state(), 10);
    env.backend.set(R(2).state(), 20);
    // スロット2件を実行してもレジスタは変わらない。
    env.step(|b| sem::add(b, R(3), R(1), R(2))).unwrap();
    env.step(|b| sem::sub(b, R(4), R(2), R(1))).unwrap();
    assert_eq!(r(&mut env, 3), 0);
    assert_eq!(r(&mut env, 4), 0);
    // commit でまとめて反映される。
    env.step(sem::commit).unwrap();
    assert_eq!(r(&mut env, 3), 30);
    assert_eq!(r(&mut env, 4), 10);
}

#[test]
fn new_forwards_packet_temp() {
    let mut env = env();
    env.backend.set(R(1).state(), 10);
    env.backend.set(R(2).state(), 20);
    env.backend.set(R(5).state(), 1);
    // r3 = r1 + r2 をバッファし、r4 = r3.new + r5 で一時値を読む。
    env.step(|b| sem::add(b, R(3), R(1), R(2))).unwrap();
    env.step(|b| sem::add_new(b, R(4), R(3), R(5))).unwrap();
    env.step(sem::commit).unwrap();
    assert_eq!(r(&mut env, 3), 30);
    assert_eq!(r(&mut env, 4), 31);
}

#[test]
fn and_or_logic() {
    let mut env = env();
    env.backend.set(R(1).state(), 0b1100);
    env.backend.set(R(2).state(), 0b1010);
    env.step(|b| sem::and(b, R(3), R(1), R(2))).unwrap();
    env.step(|b| sem::or(b, R(4), R(1), R(2))).unwrap();
    env.step(sem::commit).unwrap();
    assert_eq!(r(&mut env, 3), 0b1000);
    assert_eq!(r(&mut env, 4), 0b1110);
}

#[test]
fn commit_preserves_unwritten() {
    let mut env = env();
    env.backend.set(R(10).state(), 99);
    env.backend.set(R(1).state(), 1);
    env.step(|b| sem::mov_imm(b, R(3), 7)).unwrap();
    env.step(sem::commit).unwrap();
    assert_eq!(r(&mut env, 3), 7);
    assert_eq!(r(&mut env, 10), 99);
    assert_eq!(r(&mut env, 1), 1);
}

#[test]
fn jump_sets_pc() {
    let mut env = env();
    env.step(|b| sem::jump(b, 0x1000)).unwrap();
    assert_eq!(env.backend.get(sem::pc_ref()), 0x1000);
}
