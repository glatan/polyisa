// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! SPARC の骨格の命令単位のテスト。裸実行環境で CPU 状態と遅延スロットを検査する。
//! 出典は SPEC-SPARC-V8 (Version 8, 1992) である。
//! Ref: SPEC-SPARC-V8 (Version 8).

use polyisa_engine::bare::BareEnv;
use polyisa_guest_sparc::CpuState;
use polyisa_guest_sparc::sem::{self, Gpr, Src2};
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
    env.step(|b| sem::add(b, Gpr(2), Gpr(1), Src2::Reg(Gpr(1))))
        .unwrap();
    assert_eq!(g(&mut env, 2), 0x800);
    env.step(|b| sem::sub(b, Gpr(3), Gpr(2), Src2::Reg(Gpr(1))))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0x400);
    env.step(|b| sem::and(b, Gpr(4), Gpr(2), Src2::Reg(Gpr(3))))
        .unwrap();
    assert_eq!(g(&mut env, 4), 0x0);
    env.step(|b| sem::or(b, Gpr(4), Gpr(2), Src2::Reg(Gpr(3))))
        .unwrap();
    assert_eq!(g(&mut env, 4), 0xc00);
    // g0 への書き込みは捨てる。
    env.step(|b| sem::add(b, Gpr(0), Gpr(1), Src2::Reg(Gpr(1))))
        .unwrap();
    assert_eq!(g(&mut env, 0), 0);
}

#[test]
fn imm_operands() {
    let mut env = env();
    env.step(|b| sem::sethi(b, Gpr(1), 1)).unwrap();
    env.step(|b| sem::add(b, Gpr(2), Gpr(1), Src2::Imm(-4)))
        .unwrap();
    assert_eq!(g(&mut env, 2), 0x3fc);
}

#[test]
fn shift_masks_to_5bits_on_v8() {
    let mut env = env();
    env.step(|b| sem::sethi(b, Gpr(1), 1)).unwrap();
    // 33 は下位5ビットで 1 になる。
    env.backend.set(Gpr(2).state(), 33);
    env.step(|b| sem::sll(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(2))))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0x800);
}

#[test]
fn load_store_be_roundtrip() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 0x100);
    env.backend.set(Gpr(2).state(), 0x1234_5678);
    env.step(|b| sem::st(b, Gpr(2), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    env.step(|b| sem::ld(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0x1234_5678);
}

#[test]
fn delay_slot_executes_before_branch_takes_effect() {
    let mut env = env();
    // bicc で npc=0x2000 にするが、pc は進めない。遅延スロットの sethi が先に実行される。
    env.backend.set(sem::pc_ref(), 0x1000);
    env.backend.set(sem::npc_ref(), 0x1004);
    env.step(|b| sem::bicc(b, 0, 8, 0x1000, 0x2000)).unwrap();
    assert_eq!(env.backend.get(sem::pc_ref()), 0x1000);
    assert_eq!(env.backend.get(sem::npc_ref()), 0x2000);
    env.step(|b| sem::sethi(b, Gpr(1), 1)).unwrap();
    assert_eq!(g(&mut env, 1), 0x400);
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
    env.step(|b| sem::jmpl(b, Gpr(7), Gpr(1), Src2::Reg(Gpr(2)), 0x1000))
        .unwrap();
    assert_eq!(g(&mut env, 7), 0x1000);
    assert_eq!(env.backend.get(sem::npc_ref()), 0x3008);
    env.step(sem::commit).unwrap();
    assert_eq!(env.backend.get(sem::pc_ref()), 0x3008);
}

#[test]
fn call_writes_return_to_o7() {
    let mut env = env();
    env.backend.set(sem::pc_ref(), 0x1000);
    env.backend.set(sem::npc_ref(), 0x1004);
    env.step(|b| sem::call(b, 0x1000, 0x8000)).unwrap();
    assert_eq!(g(&mut env, 15), 0x1000);
    assert_eq!(env.backend.get(sem::npc_ref()), 0x8000);
}

#[test]
fn annulled_ba_skips_delay_slot() {
    let mut env = env();
    env.backend.set(sem::pc_ref(), 0x1000);
    env.backend.set(sem::npc_ref(), 0x1004);
    // ba,a: 成立の annul。遅延スロットは取り消される。
    env.step(|b| sem::bicc(b, 1, 8, 0x1000, 0x2000)).unwrap();
    assert_eq!(env.backend.get(sem::annul_ref()), 1);
    assert_eq!(env.backend.get(sem::npc_ref()), 0x2000);
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
    env.step(|b| sem::bicc(b, 0, 8, 0x1000, 0x2000)).unwrap();
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
    env.step(|b| sem::save(b, Gpr(0), Gpr(0), Src2::Reg(Gpr(0))))
        .unwrap();
    assert_eq!(env.backend.get(sem::cwp_ref()), 7);
    // 新しいウィンドウの i0（見える番号 24）が、直前の o0 を読む。
    env.step(|b| sem::or(b, Gpr(1), Gpr(24), Src2::Reg(Gpr(0))))
        .unwrap();
    assert_eq!(g(&mut env, 1), 0x11);
    // callee の l0 は caller の l0 と別の物理レジスタ。
    env.step(|b| sem::sethi(b, Gpr(16), 1)).unwrap();
    env.step(|b| sem::restore(b, Gpr(0), Gpr(0), Src2::Reg(Gpr(0))))
        .unwrap();
    assert_eq!(env.backend.get(sem::cwp_ref()), 0);
    env.step(|b| sem::or(b, Gpr(1), Gpr(8), Src2::Reg(Gpr(0))))
        .unwrap();
    assert_eq!(g(&mut env, 1), 0x11);
    env.step(|b| sem::or(b, Gpr(2), Gpr(16), Src2::Reg(Gpr(0))))
        .unwrap();
    assert_eq!(g(&mut env, 2), 0);
}

#[test]
fn cond_holds_table() {
    let mut env = env();
    // ICC Z=1（psr 22 ビット）。be は成立、bne は不成立。
    env.backend.set(sem::psr_ref(), 1 << 22);
    env.step(|b| sem::bicc(b, 0, 1, 0x1000, 0x2000)).unwrap();
    assert_eq!(env.backend.get(sem::npc_ref()), 0x2000);
    env.backend.set(sem::npc_ref(), 0x1004);
    env.step(|b| sem::bicc(b, 0, 9, 0x1000, 0x2000)).unwrap();
    // 不成立なら npc は pc+8。
    assert_eq!(env.backend.get(sem::npc_ref()), 0x1008);
}

#[test]
fn not_taken_branch_advances_pc_by_8() {
    let mut env = env();
    // bne（cond 9）に Z=1 で不成立。遅延スロットは実行され、pc は pc+8 へ。
    env.backend.set(sem::psr_ref(), 1 << 22);
    env.backend.set(sem::pc_ref(), 0x1000);
    env.backend.set(sem::npc_ref(), 0x1004);
    env.step(|b| sem::bicc(b, 0, 9, 0x1000, 0x2000)).unwrap();
    assert_eq!(env.backend.get(sem::npc_ref()), 0x1008);
    env.step(|b| sem::delay_slot(b, |b| sem::sethi(b, Gpr(1), 1)))
        .unwrap();
    assert_eq!(g(&mut env, 1), 0x400);
    assert_eq!(env.backend.get(sem::pc_ref()), 0x1008);
    assert_eq!(env.backend.get(sem::npc_ref()), 0x100c);
}

#[test]
fn cond_table_matches_icc() {
    // cond 表を ICC の 16 通りで網羅する。Ref: SPEC-SPARC-V8 (Version 8) §Bicc.
    // (cond, n, z, v, c, taken)
    let cases: &[(u8, u8, u8, u8, u8, bool)] = &[
        (0, 0, 0, 0, 0, false), // bn
        (1, 0, 1, 0, 0, true),  // be = z
        (1, 0, 0, 0, 0, false),
        (2, 1, 0, 0, 0, true), // ble = z | n^v
        (2, 1, 1, 1, 0, true), // z=1 → n^v=0 でも成立
        (3, 1, 0, 0, 0, true), // bl = n^v
        (3, 0, 0, 1, 0, true),
        (3, 0, 0, 0, 0, false),
        (4, 0, 0, 0, 1, true), // bleu = c | z
        (4, 0, 1, 0, 0, true),
        (4, 1, 0, 0, 0, false), // n^v=1 だが c=z=0 → 不成立
        (5, 0, 0, 0, 1, true),  // bcs = c
        (5, 0, 0, 0, 0, false),
        (6, 1, 0, 0, 0, true), // bneg = n
        (6, 0, 0, 0, 0, false),
        (7, 0, 0, 1, 0, true), // bvs = v
        (7, 0, 0, 0, 0, false),
        (8, 0, 0, 0, 0, true),  // ba
        (9, 0, 1, 0, 0, false), // bne = !z
        (9, 0, 0, 0, 0, true),
        (10, 1, 0, 0, 0, false), // bg = !z & !(n^v)
        (10, 0, 0, 0, 0, true),
        (10, 0, 1, 0, 0, false),
        (11, 1, 0, 0, 0, false), // bge = !(n^v)
        (11, 0, 0, 1, 0, false),
        (11, 1, 0, 1, 0, true),
        (12, 0, 0, 0, 1, false), // bgu = !c & !z
        (12, 0, 0, 0, 0, true),
        (13, 0, 0, 0, 0, true), // bcc = !c
        (13, 0, 0, 0, 1, false),
        (14, 1, 0, 0, 0, false), // bpos = !n
        (14, 0, 0, 0, 0, true),
        (15, 0, 0, 1, 0, false), // bvc = !v
        (15, 0, 0, 0, 0, true),
    ];
    for &(cond, n, z, v, c, expect) in cases {
        let mut env = env();
        let psr = ((n as u32) << 23) | ((z as u32) << 22) | ((v as u32) << 21) | ((c as u32) << 20);
        env.backend.set(sem::psr_ref(), psr);
        env.backend.set(sem::pc_ref(), 0x1000);
        env.backend.set(sem::npc_ref(), 0x1004);
        env.step(|b| sem::bicc(b, 0, cond, 0x1000, 0x2000)).unwrap();
        let want = if expect { 0x2000 } else { 0x1008 };
        assert_eq!(
            env.backend.get(sem::npc_ref()),
            want,
            "cond={cond} nzcv={n}{z}{v}{c}"
        );
    }
}
