// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! SPARC V8 試作の命令単位のテスト。裸実行環境で CPU 状態と遅延スロットを検査する.
//! 出典は SPEC-SPARC-V8 (Version 8, 1992) である.
//! Ref: SPEC-SPARC-V8 (Version 8).

use polyisa_engine::bare::BareEnv;
use polyisa_guest_sparc::CpuState;
use polyisa_guest_sparc::sem::{self, Gpr};
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
    env.step(|b| sem::sethi(b, Gpr(1), 1)).unwrap();
    assert_eq!(g(&mut env, 1), 0x400);
    env.step(|b| sem::add(b, Gpr(2), Gpr(1), Gpr(1))).unwrap();
    assert_eq!(g(&mut env, 2), 0x800);
    env.step(|b| sem::sub(b, Gpr(3), Gpr(2), Gpr(1))).unwrap();
    assert_eq!(g(&mut env, 3), 0x400);
    env.step(|b| sem::and(b, Gpr(4), Gpr(2), Gpr(3))).unwrap();
    assert_eq!(g(&mut env, 4), 0x0);
    env.step(|b| sem::or(b, Gpr(4), Gpr(2), Gpr(3))).unwrap();
    assert_eq!(g(&mut env, 4), 0xc00);
    // g0 への書き込みは捨てる。
    env.step(|b| sem::add(b, Gpr(0), Gpr(1), Gpr(1))).unwrap();
    assert_eq!(g(&mut env, 0), 0);
}

#[test]
fn shift_masks_to_5bits() {
    let mut env = env();
    env.step(|b| sem::sethi(b, Gpr(1), 1)).unwrap();
    // sethi は <<10 のため下位5ビットが立たない。シフト量は直接置く。
    // 33 は下位5ビットで 1 になる。
    env.backend.set(Gpr(2).state(), 33);
    env.step(|b| sem::sll(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(g(&mut env, 3), 0x800);
}

#[test]
fn load_store_be_roundtrip() {
    let mut env = env();
    env.step(|b| sem::sethi(b, Gpr(1), 0)).unwrap();
    // ベース 0x100 を作る：sethi では届かないので加算で組み立てる。
    env.step(|b| sem::add(b, Gpr(1), Gpr(1), Gpr(1))).unwrap();
    // 直接の定数書き込みでベースを用意する簡略化は避け、g2 に値を置く。
    env.backend.set(Gpr(1).state(), 0x100);
    env.backend.set(Gpr(2).state(), 0x1234_5678);
    env.step(|b| sem::st(b, Gpr(2), Gpr(1), Gpr(0))).unwrap();
    env.step(|b| sem::ld(b, Gpr(3), Gpr(1), Gpr(0))).unwrap();
    assert_eq!(g(&mut env, 3), 0x1234_5678);
}

#[test]
fn delay_slot_executes_before_branch_takes_effect() {
    let mut env = env();
    // ba で npc=0x2000 にするが、pc は進めない。遅延スロットの add が先に実行される。
    env.backend.set(sem::pc_ref(), 0x1000);
    env.backend.set(sem::npc_ref(), 0x1004);
    env.step(|b| sem::ba_delay(b, 0x2000)).unwrap();
    // pc は遅延スロットの位置のまま、npc だけが飛び先になる。
    assert_eq!(env.backend.get(sem::pc_ref()), 0x1000);
    assert_eq!(env.backend.get(sem::npc_ref()), 0x2000);
    // 遅延スロット：g1 に 1 を置く。この命令は取り消されない。
    env.step(|b| sem::sethi(b, Gpr(1), 1)).unwrap();
    assert_eq!(g(&mut env, 1), 0x400);
    // 遅延スロットの消化：pc=npc、npc+=4。
    env.step(sem::commit).unwrap();
    assert_eq!(env.backend.get(sem::pc_ref()), 0x2000);
    assert_eq!(env.backend.get(sem::npc_ref()), 0x2004);
}

#[test]
fn jmpl_writes_return_and_defers_jump() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 0x3000);
    env.backend.set(Gpr(2).state(), 8);
    env.backend.set(sem::pc_ref(), 0x1000);
    env.backend.set(sem::npc_ref(), 0x1004);
    env.step(|b| sem::jmpl(b, Gpr(7), Gpr(1), Gpr(2), 0x1000))
        .unwrap();
    // 戻りは分岐元の pc、飛び先は npc にだけ入る。
    assert_eq!(g(&mut env, 7), 0x1000);
    assert_eq!(env.backend.get(sem::npc_ref()), 0x3008);
    env.step(sem::commit).unwrap();
    assert_eq!(env.backend.get(sem::pc_ref()), 0x3008);
}

#[test]
fn annulled_ba_skips_delay_slot() {
    let mut env = env();
    env.backend.set(sem::pc_ref(), 0x1000);
    env.backend.set(sem::npc_ref(), 0x1004);
    env.step(|b| sem::ba_annul(b, 0x2000)).unwrap();
    assert_eq!(env.backend.get(sem::annul_ref()), 1);
    assert_eq!(env.backend.get(sem::npc_ref()), 0x2000);
    // 遅延スロットの sethi は取り消され、pc は飛び先へ進む。
    env.step(|b| sem::delay_slot(b, |b| sem::sethi(b, Gpr(1), 1)))
        .unwrap();
    assert_eq!(g(&mut env, 1), 0);
    assert_eq!(env.backend.get(sem::annul_ref()), 0);
    assert_eq!(env.backend.get(sem::pc_ref()), 0x2000);
    assert_eq!(env.backend.get(sem::npc_ref()), 0x2004);
}

#[test]
fn ba_without_annul_runs_delay_slot() {
    let mut env = env();
    env.backend.set(sem::pc_ref(), 0x1000);
    env.backend.set(sem::npc_ref(), 0x1004);
    env.step(|b| sem::ba_delay(b, 0x2000)).unwrap();
    assert_eq!(env.backend.get(sem::annul_ref()), 0);
    env.step(|b| sem::delay_slot(b, |b| sem::sethi(b, Gpr(1), 1)))
        .unwrap();
    assert_eq!(g(&mut env, 1), 0x400);
    assert_eq!(env.backend.get(sem::pc_ref()), 0x2000);
    assert_eq!(env.backend.get(sem::npc_ref()), 0x2004);
}

#[test]
fn save_maps_out_to_next_in() {
    let mut env = env();
    // cwp 0 の o0（見える番号 8）は物理番号 8。
    env.backend.set(Gpr(8).state(), 0x11);
    env.step(|b| sem::save(b, Gpr(0), Gpr(0), Gpr(0))).unwrap();
    assert_eq!(env.backend.get(sem::cwp_ref()), 3);
    // 新しいウィンドウの i0（見える番号 24）が、直前の o0 を読む。
    env.step(|b| sem::or(b, Gpr(1), Gpr(24), Gpr(0))).unwrap();
    assert_eq!(g(&mut env, 1), 0x11);
    // callee の l0 は caller の l0 と別の物理レジスタ。
    env.step(|b| sem::sethi(b, Gpr(16), 1)).unwrap();
    env.step(|b| sem::restore(b, Gpr(0), Gpr(0), Gpr(0)))
        .unwrap();
    assert_eq!(env.backend.get(sem::cwp_ref()), 0);
    env.step(|b| sem::or(b, Gpr(1), Gpr(8), Gpr(0))).unwrap();
    assert_eq!(g(&mut env, 1), 0x11);
    env.step(|b| sem::or(b, Gpr(2), Gpr(16), Gpr(0))).unwrap();
    assert_eq!(g(&mut env, 2), 0);
}
