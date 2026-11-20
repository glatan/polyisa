// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! SPARC の骨格の命令単位のテスト。裸実行環境で CPU 状態と遅延スロットを検査する。
//! 出典は SPEC-SPARC-V8 (Version 8, 1992) である。
//! Ref: SPEC-SPARC-V8 (Version 8).

use polyisa_engine::bare::BareEnv;
use polyisa_guest_sparc::CpuState;
use polyisa_guest_sparc::sem::{self, Fpr, Gpr, Src2};
use polyisa_sem::Backend as _;

fn env() -> BareEnv {
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    env.map_rw(0x1_0000, 1).unwrap();
    env.map_rw(0x0, 1).unwrap();
    // 既定 nwindows=8 のユーザ初期状態（全ウィンドウ空き）。
    env.backend.set(sem::cansave_ref(), 7);
    env
}

fn g(env: &mut BareEnv, r: u8) -> u64 {
    env.backend.get(Gpr(r).state())
}

/// 単精度 %fN を書く。f 配列は倍精度スロット 32 個で、%fN は
/// スロット N>>1 の半分（偶数=上位、奇数=下位）。
fn fset_s(env: &mut BareEnv, n: u8, v: u64) {
    let old = env.backend.get(Fpr(n >> 1).state());
    let new = if n & 1 == 0 {
        (old & 0xffff_ffff) | (v << 32)
    } else {
        (old & 0xffff_ffff_0000_0000) | (v & 0xffff_ffff)
    };
    env.backend.set(Fpr(n >> 1).state(), new);
}

fn fget_s(env: &mut BareEnv, n: u8) -> u64 {
    let v = env.backend.get(Fpr(n >> 1).state());
    if n & 1 == 0 { v >> 32 } else { v & 0xffff_ffff }
}

/// 倍精度 %dN（偶数）= スロット N>>1 全体。
fn fset_d(env: &mut BareEnv, n: u8, v: u64) {
    env.backend.set(Fpr(n >> 1).state(), v);
}

fn fget_d(env: &mut BareEnv, n: u8) -> u64 {
    env.backend.get(Fpr(n >> 1).state())
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
fn annulled_cond_branch_not_taken_skips_slot() {
    let mut env = env();
    env.backend.set(sem::pc_ref(), 0x1000);
    env.backend.set(sem::npc_ref(), 0x1004);
    // Z=0 なので be,a は不成立。遅延スロットは取り消される。
    env.backend.set(sem::psr_ref(), 0);
    env.step(|b| sem::bicc(b, 1, 1, 0x1000, 0x2000)).unwrap();
    assert_eq!(env.backend.get(sem::annul_ref()), 1);
    assert_eq!(env.backend.get(sem::npc_ref()), 0x1008);
    env.step(|b| sem::delay_slot(b, |b| sem::sethi(b, Gpr(1), 1)))
        .unwrap();
    assert_eq!(g(&mut env, 1), 0);
    assert_eq!(env.backend.get(sem::annul_ref()), 0);
    assert_eq!(env.backend.get(sem::pc_ref()), 0x1008);
    assert_eq!(env.backend.get(sem::npc_ref()), 0x100c);
}

#[test]
fn annulled_cond_branch_taken_runs_slot() {
    let mut env = env();
    env.backend.set(sem::pc_ref(), 0x1000);
    env.backend.set(sem::npc_ref(), 0x1004);
    // Z=1 なので be,a は成立。成立時は a にかかわらずスロットを実行する。
    env.backend.set(sem::psr_ref(), 1 << 22);
    env.step(|b| sem::bicc(b, 1, 1, 0x1000, 0x2000)).unwrap();
    assert_eq!(env.backend.get(sem::annul_ref()), 0);
    assert_eq!(env.backend.get(sem::npc_ref()), 0x2000);
    env.step(|b| sem::delay_slot(b, |b| sem::sethi(b, Gpr(1), 1)))
        .unwrap();
    assert_eq!(g(&mut env, 1), 0x400);
    assert_eq!(env.backend.get(sem::pc_ref()), 0x2000);
    assert_eq!(env.backend.get(sem::npc_ref()), 0x2004);
}

#[test]
fn not_taken_cond_branch_runs_slot() {
    let mut env = env();
    env.backend.set(sem::pc_ref(), 0x1000);
    env.backend.set(sem::npc_ref(), 0x1004);
    // a=0 では不成立でも遅延スロットを実行し、pc+8 へ進む。
    env.backend.set(sem::psr_ref(), 0);
    env.step(|b| sem::bicc(b, 0, 1, 0x1000, 0x2000)).unwrap();
    assert_eq!(env.backend.get(sem::annul_ref()), 0);
    assert_eq!(env.backend.get(sem::npc_ref()), 0x1008);
    env.step(|b| sem::delay_slot(b, |b| sem::sethi(b, Gpr(1), 1)))
        .unwrap();
    assert_eq!(g(&mut env, 1), 0x400);
    assert_eq!(env.backend.get(sem::pc_ref()), 0x1008);
    assert_eq!(env.backend.get(sem::npc_ref()), 0x100c);
}

#[test]
fn call_writes_return_and_jumps() {
    let mut env = env();
    env.backend.set(sem::pc_ref(), 0x1000);
    env.backend.set(sem::npc_ref(), 0x1004);
    // call は戻りとして命令自身の pc を %o7 に書く。
    env.step(|b| sem::call(b, 0x1000, 0x4000)).unwrap();
    assert_eq!(g(&mut env, 15), 0x1000);
    assert_eq!(env.backend.get(sem::npc_ref()), 0x4000);
    env.step(|b| sem::delay_slot(b, |b| sem::sethi(b, Gpr(1), 1)))
        .unwrap();
    assert_eq!(env.backend.get(sem::pc_ref()), 0x4000);
    assert_eq!(env.backend.get(sem::npc_ref()), 0x4004);
}

#[test]
fn jmpl_writes_return_and_jumps() {
    let mut env = env();
    env.backend.set(sem::pc_ref(), 0x1000);
    env.backend.set(sem::npc_ref(), 0x1004);
    env.backend.set(Gpr(1).state(), 0x3000);
    // jmpl %g1+8, %g2。戻り（pc）を %g2 に書き npc は %g1+8。
    env.step(|b| sem::jmpl(b, Gpr(2), Gpr(1), Src2::Imm(8), 0x1000))
        .unwrap();
    assert_eq!(g(&mut env, 2), 0x1000);
    assert_eq!(env.backend.get(sem::npc_ref()), 0x3008);
}

#[test]
fn ret_is_jmpl_to_i7_plus_8() {
    let mut env = env();
    env.backend.set(sem::pc_ref(), 0x1000);
    env.backend.set(sem::npc_ref(), 0x1004);
    // ret = jmpl %i7+8, %g0。cwp=0 では r31 が i7 に対応する。
    env.backend.set(Gpr(31).state(), 0x5000);
    env.step(|b| sem::jmpl(b, Gpr(0), Gpr(31), Src2::Imm(8), 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(sem::npc_ref()), 0x5008);
    env.step(|b| sem::delay_slot(b, |b| sem::sethi(b, Gpr(1), 1)))
        .unwrap();
    assert_eq!(env.backend.get(sem::pc_ref()), 0x5008);
}

#[test]
fn cti_in_delay_slot_keeps_its_annul() {
    let mut env = env();
    env.backend.set(sem::pc_ref(), 0x1000);
    env.backend.set(sem::npc_ref(), 0x1004);
    // 外側の ba と、遅延スロット内の ba,a（DCTI couple）。内側が
    // 立てる annul は消費されず、次のスロットの判定に残る。
    env.step(|b| sem::bicc(b, 0, 8, 0x1000, 0x2000)).unwrap();
    env.step(|b| sem::delay_slot_exec(b, |bb| sem::bicc(bb, 1, 8, 0x1004, 0x3000)))
        .unwrap();
    assert_eq!(env.backend.get(sem::annul_ref()), 1);
    assert_eq!(env.backend.get(sem::npc_ref()), 0x3000);
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

fn psr(env: &mut BareEnv) -> u32 {
    env.backend.get(sem::psr_ref())
}

fn icc(env: &mut BareEnv) -> u32 {
    (psr(env) >> 20) & 0xf
}

fn yv(env: &mut BareEnv) -> u64 {
    env.backend.get(sem::y_ref())
}

#[test]
fn addx_subx_carry_chain() {
    let mut env = env();
    // 64 ビット加算 {g3:g2} = {g5:g4} + {g7:g6} を addcc+addx で。
    // 下位の繰り上がりが C を通じて上位へ伝わる。
    env.backend.set(Gpr(4).state(), 0xffff_ffff);
    env.backend.set(Gpr(5).state(), 0x0000_0001);
    env.backend.set(Gpr(6).state(), 1);
    env.backend.set(Gpr(7).state(), 0xffff_ffff);
    env.step(|b| sem::addcc(b, Gpr(2), Gpr(4), Src2::Reg(Gpr(6))))
        .unwrap();
    // 0xffff_ffff + 1 = 0x1_0000_0000 → res=0, Z=1, C=1, V=0。
    assert_eq!(g(&mut env, 2), 0);
    assert_eq!(icc(&mut env), 0b0101, "nzcv");
    env.step(|b| sem::addx(b, Gpr(3), Gpr(5), Src2::Reg(Gpr(7))))
        .unwrap();
    // 1 + 0xffff_ffff + 1 = 0x1_0000_0001 → 32 ビットでは 1。
    assert_eq!(g(&mut env, 3), 1);
    // subx は借りを引く。C=1（借り）なら結果が 1 減る。
    env.backend.set(sem::psr_ref(), 1 << 20);
    env.step(|b| sem::subx(b, Gpr(8), Gpr(5), Src2::Reg(Gpr(6))))
        .unwrap();
    assert_eq!(g(&mut env, 8), 0xffff_ffff);
    // C=0（借りなし）なら素の減算と同じ。
    env.backend.set(sem::psr_ref(), 0);
    env.step(|b| sem::subx(b, Gpr(8), Gpr(5), Src2::Reg(Gpr(6))))
        .unwrap();
    assert_eq!(g(&mut env, 8), 0);
}

#[test]
fn cc_flags_from_ops() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 0x7fff_ffff);
    env.backend.set(Gpr(2).state(), 1);
    // addcc: 0x7fffffff+1 = 0x80000000 → N=1, Z=0, V=1, C=0。
    env.step(|b| sem::addcc(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(2))))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0x8000_0000);
    assert_eq!(icc(&mut env), 0b1010);
    // subcc: 3 - 5 → N=1, C=1（借り）。
    env.backend.set(Gpr(1).state(), 3);
    env.backend.set(Gpr(2).state(), 5);
    env.step(|b| sem::subcc(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(2))))
        .unwrap();
    assert_eq!(icc(&mut env), 0b1001);
    // andcc: 論理演算は V=C=0。f0f0 & 0 → Z=1。
    env.backend.set(Gpr(1).state(), 0xf0f0);
    env.backend.set(Gpr(2).state(), 0x0f00);
    env.step(|b| sem::andcc(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(2))))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0);
    assert_eq!(icc(&mut env), 0b0100);
    // orcc: 0xfff0 は正なので N=Z=0。
    env.step(|b| sem::orcc(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(2))))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0xfff0);
    assert_eq!(icc(&mut env), 0b0000);
}

#[test]
fn logic_ops_andn_orn_xor_xnor() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 0xff00_ff00);
    env.backend.set(Gpr(2).state(), 0x0f0f_0f0f);
    env.step(|b| sem::andn(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(2))))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0xf000_f000);
    env.step(|b| sem::orn(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(2))))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0xfff0_fff0);
    env.step(|b| sem::xor(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(2))))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0xf00f_f00f);
    env.step(|b| sem::xnor(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(2))))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0x0ff0_0ff0);
}

#[test]
fn mul_div_and_y() {
    let mut env = env();
    // umul: 0x10000 * 0x10000 = 0x1_0000_0000 → rd=0, Y=1。
    env.backend.set(Gpr(1).state(), 0x1_0000);
    env.backend.set(Gpr(2).state(), 0x1_0000);
    env.step(|b| sem::umul(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(2))))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0);
    assert_eq!(yv(&mut env), 1);
    // smul: -1 * -1 = 1 → rd=1, Y=0。
    env.backend.set(Gpr(1).state(), 0xffff_ffff);
    env.backend.set(Gpr(2).state(), 0xffff_ffff);
    env.step(|b| sem::smul(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(2))))
        .unwrap();
    assert_eq!(g(&mut env, 3), 1);
    assert_eq!(yv(&mut env), 0);
    // udiv: {Y=0, rs1=100} / 7 → q=14, rem=2。
    env.backend.set(sem::y_ref(), 0);
    env.backend.set(Gpr(1).state(), 100);
    env.backend.set(Gpr(2).state(), 7);
    env.step(|b| sem::udiv(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(2))))
        .unwrap();
    assert_eq!(g(&mut env, 3), 14);
    assert_eq!(yv(&mut env), 2);
    // sdiv: {Y=-1, rs1=0xffff_ff9c}（-100）/ 7 → q=-14, rem=-2。
    env.backend.set(sem::y_ref(), 0xffff_ffff);
    env.backend.set(Gpr(1).state(), 0xffff_ff9c);
    env.step(|b| sem::sdiv(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(2))))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0xffff_fff2);
    assert_eq!(yv(&mut env), 0xffff_fffe);
}

#[test]
fn udivcc_sets_v_on_quotient_overflow() {
    let mut env = env();
    // 被除数 {Y=1, rs1=0} = 0x1_0000_0000、除数 1 → 商が 32 ビット超
    // で飽和 0xffffffff。N=1, V=1, Z=0, C=0。
    env.backend.set(sem::y_ref(), 1);
    env.backend.set(Gpr(1).state(), 0);
    env.backend.set(Gpr(2).state(), 1);
    env.step(|b| sem::udivcc(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(2))))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0xffff_ffff);
    assert_eq!(icc(&mut env), 0b1010);
}

#[test]
fn sdiv_saturates_min_by_minus_one() {
    let mut env = env();
    // 被除数 {Y=0x80000000, rs1=0} = INT64_MIN、除数 -1 →
    // 商は 2^63 で 32 ビット超。符号が同じ → 正の飽和 0x7fffffff。
    env.backend.set(sem::y_ref(), 0x8000_0000);
    env.backend.set(Gpr(1).state(), 0);
    env.backend.set(Gpr(2).state(), 0xffff_ffff);
    env.step(|b| sem::sdiv(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(2))))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0x7fff_ffff);
    // 負の飽和。被除数 {Y=0x80000000, rs1=0} = INT64_MIN、除数 1 →
    // 商 INT64_MIN < INT32_MIN → 0x8000_0000。
    env.backend.set(sem::y_ref(), 0x8000_0000);
    env.backend.set(Gpr(2).state(), 1);
    env.step(|b| sem::sdiv(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(2))))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0x8000_0000);
}

#[test]
fn div_by_zero_raises_trap() {
    let mut env = env();
    env.backend.set(sem::y_ref(), 0);
    env.backend.set(Gpr(1).state(), 10);
    env.backend.set(Gpr(2).state(), 0);
    let r = env.step(|b| sem::udiv(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(2))));
    assert!(r.is_err());
}

#[test]
fn mulscc_steps() {
    let mut env = env();
    // N^V=0 → op1 = rs1>>1。Y<0>=0 → 加算なし。rs1=8 → res=4。
    // rs1[0]=0 → Y = 0x80000000 >> 1。
    env.backend.set(sem::psr_ref(), 0);
    env.backend.set(Gpr(1).state(), 8);
    env.backend.set(Gpr(2).state(), 3);
    env.backend.set(sem::y_ref(), 0x8000_0000);
    env.step(|b| sem::mulscc(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(2))))
        .unwrap();
    assert_eq!(g(&mut env, 3), 4);
    assert_eq!(yv(&mut env), 0x4000_0000);
    assert_eq!(icc(&mut env), 0b0000);
    // N^V=1 → op1 の最上位が 1。Y<0>=0 なら加算なし。
    // rs1=9 → op1 = 0x80000004。rs1[0]=1 → Y[31]=1。
    env.backend.set(sem::psr_ref(), 1 << 23); // N=1, V=0
    env.backend.set(Gpr(1).state(), 9);
    env.backend.set(sem::y_ref(), 2);
    env.step(|b| sem::mulscc(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(2))))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0x8000_0004);
    assert_eq!(yv(&mut env), 0x8000_0001);
    assert_eq!(icc(&mut env), 0b1000);
    // Y<0>=1 → operand2 を加算。rs1=0x10, Y=3, src2=5 →
    // op1 = 8, res = 13。繰り上がりなし → C=0。
    env.backend.set(sem::psr_ref(), 0);
    env.backend.set(Gpr(1).state(), 0x10);
    env.backend.set(Gpr(2).state(), 5);
    env.backend.set(sem::y_ref(), 3);
    env.step(|b| sem::mulscc(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(2))))
        .unwrap();
    assert_eq!(g(&mut env, 3), 13);
    assert_eq!(yv(&mut env), 1);
    assert_eq!(icc(&mut env), 0b0000);
    // 加算で繰り上がり → C=1。op1 = 0x7fffffff, op2 = 0xffffffff →
    // res = 0x7ffffffe, C=1。rs1[0]=1 → Y[31]=1。
    env.backend.set(sem::psr_ref(), 0);
    env.backend.set(Gpr(1).state(), 0xffff_ffff);
    env.backend.set(Gpr(2).state(), 0xffff_ffff);
    env.backend.set(sem::y_ref(), 1);
    env.step(|b| sem::mulscc(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(2))))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0x7fff_fffe);
    assert_eq!(yv(&mut env), 0x8000_0000);
    assert_eq!(icc(&mut env), 0b0001);
}

#[test]
fn shifts() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 0x8000_00f0);
    env.backend.set(Gpr(2).state(), 4);
    env.step(|b| sem::srl(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(2))))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0x0800_000f);
    env.step(|b| sem::sra(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(2))))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0xf800_000f);
    // 即値形のシフト（shcnt は simm13 の下位 5 ビット）。
    env.step(|b| sem::sll(b, Gpr(3), Gpr(1), Src2::Imm(33)))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0x0000_01e0);
}

#[test]
fn load_store_sizes_be() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 0x200);
    // BE の [0x12 0x34 0x56 0x78] を書いて部分ロードを確かめる。
    env.backend.set(Gpr(2).state(), 0x1234_5678);
    env.step(|b| sem::st(b, Gpr(2), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    env.step(|b| sem::ldub(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0x12);
    env.step(|b| sem::ldub(b, Gpr(3), Gpr(1), Src2::Imm(3)))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0x78);
    env.step(|b| sem::lduh(b, Gpr(3), Gpr(1), Src2::Imm(2)))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0x5678);
    // 符号拡張。0x80ff_7f00 の先頭バイトと先頭ハーフ。
    env.backend.set(Gpr(2).state(), 0x80ff_7f00);
    env.step(|b| sem::st(b, Gpr(2), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    env.step(|b| sem::ldsb(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0xffff_ff80);
    env.step(|b| sem::ldsh(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0xffff_80ff);
    // stb/sth で部分書き込みし、ld で読み戻す。
    env.backend.set(Gpr(2).state(), 0xaabb_ccdd);
    env.step(|b| sem::stb(b, Gpr(2), Gpr(1), Src2::Imm(1)))
        .unwrap();
    env.step(|b| sem::sth(b, Gpr(2), Gpr(1), Src2::Imm(2)))
        .unwrap();
    env.step(|b| sem::ld(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0x80dd_ccdd);
}

#[test]
fn ldd_std_pair() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 0x300);
    env.backend.set(Gpr(4).state(), 0xdead_beef);
    env.backend.set(Gpr(5).state(), 0x1234_5678);
    // std は rd=hi（アドレス側）、rd2=lo。
    env.step(|b| sem::std(b, Gpr(4), Gpr(5), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    env.step(|b| sem::ldd(b, Gpr(6), Gpr(7), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    assert_eq!(g(&mut env, 6), 0xdead_beef);
    assert_eq!(g(&mut env, 7), 0x1234_5678);
}

#[test]
fn ldstub_loads_and_sets_ff() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 0x400);
    env.backend.set(Gpr(2).state(), 0x42);
    env.step(|b| sem::stb(b, Gpr(2), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    env.step(|b| sem::ldstub(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    // 読んだ値は元のバイト、メモリは 0xff になる。
    assert_eq!(g(&mut env, 3), 0x42);
    env.step(|b| sem::ldub(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0xff);
}

#[test]
fn swap_exchanges_word() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 0x500);
    env.backend.set(Gpr(2).state(), 0xaaaa_bbbb);
    env.backend.set(Gpr(3).state(), 0x1111_2222);
    env.step(|b| sem::st(b, Gpr(2), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    env.step(|b| sem::swap(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    // rd はメモリの旧値、メモリは rd の旧値。
    assert_eq!(g(&mut env, 3), 0xaaaa_bbbb);
    env.step(|b| sem::ld(b, Gpr(4), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    assert_eq!(g(&mut env, 4), 0x1111_2222);
}

#[test]
fn exec_decodes_asi_load() {
    let mut env = env();
    // lduba [%g1 + %g0] %asi, %g3 の命令語（op3=010001, i=0,
    // asi=0x0a）。ASI 形は特権命令なので PSR.S を立てて実行する。
    // アドレス空間の選択は後続ステップまで通常空間に畳まれる。
    let word: u32 = (0b11 << 30) | (3 << 25) | (0b010001 << 19) | (1 << 14) | (0x0a << 5);
    let insn = polyisa_guest_sparc::decode(u128::from(word), 32).unwrap();
    assert_eq!(insn, polyisa_guest_sparc::Insn::Lduba);
    env.backend.set(sem::psr_ref(), 1 << 7);
    env.backend.set(Gpr(1).state(), 0x600);
    env.backend.set(Gpr(2).state(), 0xab);
    env.step(|b| sem::stb(b, Gpr(2), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    assert_eq!(g(&mut env, 3), 0xab);
}

#[test]
fn asi_in_user_mode_traps() {
    let mut env = env();
    // PSR.S=0 のユーザーモードで ASI 形を実行すると
    // privileged_instruction（tt=3, code=3）になる。
    let word: u32 = (0b11 << 30) | (3 << 25) | (0b010001 << 19) | (1 << 14) | (0x0a << 5);
    let insn = polyisa_guest_sparc::decode(u128::from(word), 32).unwrap();
    env.backend.set(sem::psr_ref(), 0);
    let r = env.step(|b| sem::exec(b, insn, word, 0));
    assert!(r.is_err());
    assert_eq!(env.backend.get(sem::tt_ref()), 3);
}

#[test]
fn ticc_taken_sets_tt_and_traps() {
    let mut env = env();
    // Z=1 で te は成立。trap 番号は 0x80 + ((rs1 + operand2) & 0x7f)。
    env.backend.set(sem::psr_ref(), 1 << 22);
    env.backend.set(Gpr(1).state(), 0x100);
    let r = env.step(|b| sem::ticc(b, 1, false, Gpr(1), Src2::Imm(0x10)));
    assert!(r.is_err());
    assert_eq!(env.backend.get(sem::tt_ref()), 0x90);
}

#[test]
fn ticc_uses_v9_trap_type_on_word64() {
    let mut env = env();
    // word64（V9）では trap type は 0x100 + N。
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    let r = env.step(|b| sem::ticc(b, 8, false, Gpr(0), Src2::Imm(0x10)));
    assert!(r.is_err());
    assert_eq!(env.backend.get(sem::tt_ref()), 0x110);
}

#[test]
fn privileged_uses_v9_opcode_trap_type_on_word64() {
    let mut env = env();
    // word64（V9）の特権命令は privileged_opcode=0x11。
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    let r = env.step(|b| Err::<(), _>(sem::privileged(b)));
    assert!(r.is_err());
    assert_eq!(env.backend.get(sem::tt_ref()), 0x11);
}

#[test]
fn ticc_not_taken_is_nop() {
    let mut env = env();
    // Z=0 で te は不成立。tt は変わらず例外も起きない。
    env.backend.set(sem::psr_ref(), 0);
    env.step(|b| sem::ticc(b, 1, false, Gpr(1), Src2::Imm(0x10)))
        .unwrap();
    assert_eq!(env.backend.get(sem::tt_ref()), 0);
}

#[test]
fn wry_then_rdy_round_trip() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 0xdead_beef);
    // wr %g1, 0xfff, %y。書き込みは XOR。Y は 32 ビット。
    env.step(|b| sem::wry(b, Gpr(1), Src2::Imm(0xfff))).unwrap();
    assert_eq!(env.backend.get(sem::y_ref()), 0xdead_b110);
    env.step(|b| sem::rdy(b, Gpr(2))).unwrap();
    assert_eq!(g(&mut env, 2), 0xdead_b110);
}

#[test]
fn wrccr_then_rdccr_round_trip() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 0x1ff);
    // wr %g1, %g0, %ccr。下位 8 ビットだけが入る。
    env.step(|b| sem::wrccr(b, Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    assert_eq!(env.backend.get(sem::ccr_ref()), 0xff);
    env.step(|b| sem::rdccr(b, Gpr(2))).unwrap();
    assert_eq!(g(&mut env, 2), 0xff);
}

#[test]
fn rdpc_reads_own_pc() {
    let mut env = env();
    env.step(|b| sem::rdpc(b, Gpr(1), 0x3000)).unwrap();
    assert_eq!(g(&mut env, 1), 0x3000);
}

#[test]
fn privileged_insn_traps() {
    let mut env = env();
    // rd %psr, %g5（op3=101001）。特権違反で tt=3, code=3。
    let word: u32 = (0b10 << 30) | (5 << 25) | (0b101001 << 19);
    let insn = polyisa_guest_sparc::decode(u128::from(word), 32).unwrap();
    assert_eq!(insn, polyisa_guest_sparc::Insn::Rdpsr);
    let r = env.step(|b| sem::exec(b, insn, word, 0));
    assert!(r.is_err());
    assert_eq!(env.backend.get(sem::tt_ref()), 3);
}

#[test]
fn rett_in_user_mode_traps() {
    let mut env = env();
    // rett %g1 + %g0（op3=111001, i=0）。ユーザーモードではトラップ。
    let word: u32 = (0b10 << 30) | (0b111001 << 19) | (1 << 14);
    let insn = polyisa_guest_sparc::decode(u128::from(word), 32).unwrap();
    assert_eq!(insn, polyisa_guest_sparc::Insn::Rett);
    let r = env.step(|b| sem::exec(b, insn, word, 0));
    assert!(r.is_err());
    assert_eq!(env.backend.get(sem::tt_ref()), 3);
}

#[test]
fn ta_imm_decodes_and_traps() {
    let mut env = env();
    // ta 0x10（cond=8 常に成立、i=1, rs1=0, imm=0x10）。
    let word: u32 = (0b10 << 30) | (8 << 25) | (0b111010 << 19) | (1 << 13) | 0x10;
    let insn = polyisa_guest_sparc::decode(u128::from(word), 32).unwrap();
    assert_eq!(insn, polyisa_guest_sparc::Insn::TiccI);
    let r = env.step(|b| sem::exec(b, insn, word, 0));
    assert!(r.is_err());
    assert_eq!(env.backend.get(sem::tt_ref()), 0x90);
}

// ---- V9 追加分（SP9）。word64 パラメータと v9 feature の組を使う。 ----

const V9_FEATS: u128 =
    polyisa_guest_sparc::FEAT_V7 | polyisa_guest_sparc::FEAT_V8 | polyisa_guest_sparc::FEAT_V9;

fn dec_v9(word: u32) -> polyisa_guest_sparc::Insn {
    polyisa_guest_sparc::decode_model_ex(u128::from(word), 32, true, V9_FEATS).unwrap()
}

#[test]
fn v9_shiftx_uses_six_bit_count() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    env.backend.set(Gpr(1).state(), 1);
    // sllx %g1, 40, %g2（op3=100101, i=1, x=1, shcnt6=40）。
    let word: u32 =
        (0b10 << 30) | (2 << 25) | (0b100101 << 19) | (1 << 14) | (1 << 13) | (1 << 12) | 40;
    let insn = dec_v9(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::SllxI);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    assert_eq!(g(&mut env, 2), 1u64 << 40);
    // srlx %g2, %g3(=20), %g4。レジスタ形は i=0, x=1, bits11-5=0。
    env.backend.set(Gpr(3).state(), 20);
    let word2: u32 = (0b10 << 30) | (4 << 25) | (0b100110 << 19) | (2 << 14) | (1 << 12) | 3;
    let insn2 = dec_v9(word2);
    assert_eq!(insn2, polyisa_guest_sparc::Insn::Srlx);
    env.step(|b| sem::exec(b, insn2, word2, 0)).unwrap();
    assert_eq!(g(&mut env, 4), 1u64 << 20);
}

#[test]
fn v9_mulx_and_divx_use_full_width() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    env.backend.set(Gpr(1).state(), 0x1_0000_0002);
    // mulx %g1, %g1, %g2。積の下位 64 ビット。
    env.step(|b| sem::mulx(b, Gpr(2), Gpr(1), Src2::Reg(Gpr(1))))
        .unwrap();
    assert_eq!(g(&mut env, 2), 0x1_0000_0002u64.wrapping_mul(0x1_0000_0002));
    // sdivx %g3, 2, %g4。-6 / 2 = -3。
    env.backend.set(Gpr(3).state(), (-6i64) as u64);
    env.step(|b| sem::sdivx(b, Gpr(4), Gpr(3), Src2::Imm(2)))
        .unwrap();
    assert_eq!(g(&mut env, 4), (-3i64) as u64);
    // udivx の 0 除算は division_by_zero=0x28。
    let r = env.step(|b| sem::udivx(b, Gpr(4), Gpr(3), Src2::Reg(Gpr(0))));
    assert!(r.is_err());
    assert_eq!(env.backend.get(sem::tt_ref()), 0x28);
}

#[test]
fn v9_alu_uses_full_operands() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    // V9 の add/sub/logic は全 64 ビットで演算し、結果をそのまま
    // rd に書く（符号拡張はしない。ICC の N だけ bit31 を見る）。
    env.backend.set(Gpr(1).state(), 0xffff_ffff_ffff_ffff);
    env.step(|b| sem::add(b, Gpr(2), Gpr(1), Src2::Imm(1)))
        .unwrap();
    assert_eq!(g(&mut env, 2), 0);
    env.backend.set(Gpr(1).state(), 0x7fff_ffff);
    env.step(|b| sem::add(b, Gpr(2), Gpr(1), Src2::Imm(1)))
        .unwrap();
    assert_eq!(g(&mut env, 2), 0x8000_0000);
}

#[test]
fn v9_sethi_zero_extends() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    // sethi %hi(0x80808080), %g1。V9 の sethi は上位 32 ビットを
    // 0 で埋める（符号拡張しない）。符号拡張だと %hi/%lo の
    // 2 命令で上位ビット付き定数を作れない。
    env.step(|b| sem::sethi(b, Gpr(1), 0x202020)).unwrap();
    assert_eq!(g(&mut env, 1), 0x8080_8000);
    // or %g1, %lo(0x80808080), %g1 で 0x80808080 になる。
    env.step(|b| sem::or(b, Gpr(1), Gpr(1), Src2::Imm(0x80)))
        .unwrap();
    assert_eq!(g(&mut env, 1), 0x8080_8080);
}

#[test]
fn v9_addcc_updates_icc_and_xcc() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    // addcc %g1(-1), 1, %g2。32 ビット結果も 64 ビット結果も 0 で、
    // ICC も XCC も Z と C が立つ（0b0101_0101 = 0x55）。
    env.backend.set(Gpr(1).state(), 0xffff_ffff_ffff_ffff);
    env.step(|b| sem::addcc(b, Gpr(2), Gpr(1), Src2::Imm(1)))
        .unwrap();
    assert_eq!(env.backend.get(sem::ccr_ref()), 0x55);
}

#[test]
fn v9_movcc_moves_on_condition() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    // movz %icc, %g2, %g1（bit18=1, cond=0001(z), i=0, cc=0, rs2=g2）。
    // Z は %ccr の icc.z（bit2）。
    let word: u32 = (0b10 << 30) | (1 << 25) | (0b101100 << 19) | (1 << 18) | (1 << 14) | 2;
    let insn = dec_v9(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Movcc);
    env.backend.set(sem::ccr_ref(), 1 << 2);
    env.backend.set(Gpr(1).state(), 0xaaaa);
    env.backend.set(Gpr(2).state(), 0xbeef);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    assert_eq!(g(&mut env, 1), 0xbeef);
    // Z が消えれば転送しない。
    env.backend.set(sem::ccr_ref(), 0);
    env.backend.set(Gpr(1).state(), 0xaaaa);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    assert_eq!(g(&mut env, 1), 0xaaaa);
    // movz %xcc（cc 桁=1）は xcc.z（bit6）を見る。
    let wordx: u32 = word | (1 << 12);
    let insnx = dec_v9(wordx);
    assert_eq!(insnx, polyisa_guest_sparc::Insn::Movcc);
    env.backend.set(sem::ccr_ref(), 1 << 6);
    env.step(|b| sem::exec(b, insnx, wordx, 0)).unwrap();
    assert_eq!(g(&mut env, 1), 0xbeef);
}

#[test]
fn v9_movr_moves_on_register_condition() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    // movrz %g1, %g2, %g3（rcond=1）。rs1=0 なら転送する。
    let word: u32 = (0b10 << 30) | (3 << 25) | (0b101111 << 19) | (1 << 14) | (1 << 10) | 2;
    let insn = dec_v9(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Movr);
    env.backend.set(Gpr(1).state(), 0);
    env.backend.set(Gpr(2).state(), 0x7777);
    env.backend.set(Gpr(3).state(), 0x1234);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    assert_eq!(g(&mut env, 3), 0x7777);
    // rs1 != 0 なら変わらない。
    env.backend.set(Gpr(1).state(), 5);
    env.backend.set(Gpr(3).state(), 0x1234);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    assert_eq!(g(&mut env, 3), 0x1234);
}

#[test]
fn v9_popc_counts_ones() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    // popc %g1, %g2（op3=101110, rs1=0, i=0）。
    let word: u32 = (0b10 << 30) | (2 << 25) | (0b101110 << 19) | 1;
    let insn = dec_v9(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Popc);
    env.backend.set(Gpr(1).state(), 0xf0f0_f0f0_00ff_00ff);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    assert_eq!(g(&mut env, 2), 32);
}

#[test]
fn v9_casa_exchanges_on_match() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    env.backend.set(Gpr(1).state(), 0x600);
    env.backend.set(Gpr(2).state(), 0x1111_2222); // 新値（rd）
    env.backend.set(Gpr(3).state(), 0xaaaa_bbbb); // 比較値（rs2）
    env.step(|b| sem::st(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    // casa [%g1] 0x80, %g3, %g2（op3=111100, i=0, asi=0x80）。
    let word: u32 = (0b11 << 30) | (2 << 25) | (0b111100 << 19) | (1 << 14) | (0x80 << 5) | 3;
    let insn = dec_v9(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Casa);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    // 一致したのでメモリは新値、rd には旧値が戻る。
    env.step(|b| sem::ld(b, Gpr(4), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    assert_eq!(g(&mut env, 4), 0x1111_2222);
    assert_eq!(g(&mut env, 2), 0xaaaa_bbbb);
    // 不一致ならメモリは変わらず rd に現値が戻る。
    env.backend.set(Gpr(3).state(), 0xdead_beef);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    env.step(|b| sem::ld(b, Gpr(4), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    assert_eq!(g(&mut env, 4), 0x1111_2222);
    assert_eq!(g(&mut env, 2), 0x1111_2222);
}

#[test]
fn v9_casxa_exchanges_doubleword() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    env.backend.set(Gpr(1).state(), 0x700);
    env.backend.set(Gpr(2).state(), 0xdead_beef_cafe_f00d); // 新値（rd）
    env.backend.set(Gpr(3).state(), 0x0123_4567_89ab_cdef); // 比較値（rs2）
    // メモリを st 2 発で用意する。
    env.backend.set(Gpr(4).state(), 0x0123_4567);
    env.step(|b| sem::st(b, Gpr(4), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    env.backend.set(Gpr(4).state(), 0x89ab_cdef);
    env.step(|b| sem::st(b, Gpr(4), Gpr(1), Src2::Imm(4)))
        .unwrap();
    // メモリには比較値（rs2=%g3）が置かれている。
    // casxa [%g1] 0x80, %g3, %g2（op3=111110）。
    let word: u32 = (0b11 << 30) | (2 << 25) | (0b111110 << 19) | (1 << 14) | (0x80 << 5) | 3;
    let insn = dec_v9(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Casxa);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    env.step(|b| sem::ld(b, Gpr(4), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    assert_eq!(g(&mut env, 4), 0xdead_beef);
    assert_eq!(g(&mut env, 2), 0x0123_4567_89ab_cdef);
}

#[test]
fn v9_return_sets_npc() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    env.backend.set(Gpr(1).state(), 0x1230);
    // return %g1 + 4（op3=111001, i=1）。rett と同じ op3 で非特権。
    // return は restore と同じく戻る窓が必要なので canrestore=1。
    env.backend.set(sem::canrestore_ref(), 1);
    let word: u32 = (0b10 << 30) | (0b111001 << 19) | (1 << 14) | (1 << 13) | 4;
    let insn = dec_v9(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::ReturnI);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    assert_eq!(env.backend.get(sem::npc_ref()), 0x1234);
}

#[test]
fn v9_save_increments_cwp() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    // V9 では SAVE で CWP が増え、RESTORE で減る（V7/V8 とは逆）。
    env.backend.set(sem::cwp_ref(), 3);
    env.step(|b| sem::save(b, Gpr(16), Gpr(0), Src2::Reg(Gpr(0))))
        .unwrap();
    assert_eq!(env.backend.get(sem::cwp_ref()), 4);
    env.step(|b| sem::restore(b, Gpr(16), Gpr(0), Src2::Reg(Gpr(0))))
        .unwrap();
    assert_eq!(env.backend.get(sem::cwp_ref()), 3);
}

#[test]
fn v9_rdpr_traps_in_user_mode() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    // rdpr %tpc, %g1（op3=101010）。特権命令は
    // privileged_opcode=0x11。
    let word: u32 = (0b10 << 30) | (1 << 25) | (0b101010 << 19);
    let insn = dec_v9(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Rdpr);
    let r = env.step(|b| sem::exec(b, insn, word, 0));
    assert!(r.is_err());
    assert_eq!(env.backend.get(sem::tt_ref()), 0x11);
}

#[test]
fn v9_tcc_imm8_forms() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    // ta %icc, %g0 + 0x90。icc 即値形で bit7 が立つ語。
    // 即値は符号拡張後も 7 ビットに折れるので番号は 0x10 相当。
    let word: u32 = (0b10 << 30) | (8 << 25) | (0b111010 << 19) | (1 << 13) | (1 << 7) | 0x10;
    let insn = dec_v9(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::TccI);
    let r = env.step(|b| sem::exec(b, insn, word, 0));
    assert!(r.is_err());
    assert_eq!(env.backend.get(sem::tt_ref()), 0x110);
    // ta %xcc, %g0 + 0x40。xcc 形（bit12=1）の 8 ビット即値。
    let wordx: u32 = (0b10 << 30) | (8 << 25) | (0b111010 << 19) | (1 << 13) | (1 << 12) | 0x40;
    let insnx = dec_v9(wordx);
    assert_eq!(insnx, polyisa_guest_sparc::Insn::TccxI);
    let rx = env.step(|b| sem::exec(b, insnx, wordx, 0));
    assert!(rx.is_err());
    assert_eq!(env.backend.get(sem::tt_ref()), 0x140);
}

#[test]
fn v9_nop_insns_do_nothing() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    // membar #StoreStore|#StoreLoad（rs1=01111, i=1, mask=0b0001010）。
    let word: u32 = (0b10 << 30) | (0b101000 << 19) | (0b01111 << 14) | (1 << 13) | 0b0001010;
    let insn = dec_v9(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Membar);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    // prefetch（op3=101101）も no-op。
    let pf: u32 = (0b11 << 30) | (0b101101 << 19) | (1 << 14) | (0x8b << 5);
    let insn2 = dec_v9(pf);
    assert_eq!(insn2, polyisa_guest_sparc::Insn::Prefetch);
    env.step(|b| sem::exec(b, insn2, pf, 0)).unwrap();
}

#[test]
fn v9_amask_drops_high_address_bits() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    // PSTATE.AM（TSTATE bit11）を立てると jmpl の飛び先と rd に
    // 書く戻りの上位 32 ビットが落ちる。
    env.backend.set(sem::tstate_ref(), 1 << 11);
    env.backend.set(Gpr(1).state(), 0x1_0000_0200);
    env.step(|b| sem::jmpl(b, Gpr(7), Gpr(1), Src2::Imm(0), 0x1_0000_0080))
        .unwrap();
    assert_eq!(env.backend.get(sem::npc_ref()), 0x200);
    assert_eq!(g(&mut env, 7), 0x80);
    // AM が 0 なら全幅が残る。
    env.backend.set(sem::tstate_ref(), 0);
    env.step(|b| sem::jmpl(b, Gpr(7), Gpr(1), Src2::Imm(0), 0))
        .unwrap();
    assert_eq!(env.backend.get(sem::npc_ref()), 0x1_0000_0200);
}

#[test]
fn v9_save_aliases_caller_out_to_callee_in() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    // caller の %o0 に値を入れて save すると callee から %i0 に見える。
    env.backend.set(Gpr(1).state(), 0x1234_5678);
    env.step(|b| sem::or(b, Gpr(8), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    env.step(|b| sem::save(b, Gpr(3), Gpr(0), Src2::Reg(Gpr(0))))
        .unwrap();
    assert_eq!(env.backend.get(sem::cwp_ref()), 1);
    env.step(|b| sem::or(b, Gpr(7), Gpr(24), Src2::Reg(Gpr(0))))
        .unwrap();
    assert_eq!(g(&mut env, 7), 0x1234_5678);
    // callee の %o0 は caller の %o0 とは別のスロット。
    env.step(|b| sem::or(b, Gpr(7), Gpr(8), Src2::Reg(Gpr(0))))
        .unwrap();
    assert_eq!(g(&mut env, 7), 0);
    // restore で戻ると %o0 が読める。
    env.step(|b| sem::restore(b, Gpr(3), Gpr(0), Src2::Reg(Gpr(0))))
        .unwrap();
    assert_eq!(env.backend.get(sem::cwp_ref()), 0);
    env.step(|b| sem::or(b, Gpr(7), Gpr(8), Src2::Reg(Gpr(0))))
        .unwrap();
    assert_eq!(g(&mut env, 7), 0x1234_5678);
}

#[test]
fn v9_addcc_xcc_uses_64bit_result() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    // 64 ビットでは正、下位 32 ビットでは負の結果。xcc.n は 0、
    // icc.n は 1 になる。
    env.backend.set(Gpr(1).state(), 0x1_8000_0000);
    env.step(|b| sem::addcc(b, Gpr(2), Gpr(1), Src2::Imm(0)))
        .unwrap();
    // icc = n z v c = 0b1000、xcc = 0b0000 → ccr = 0x08。
    assert_eq!(env.backend.get(sem::ccr_ref()), 0x08);
}

#[test]
fn v9_movfcc_moves_when_fcond_holds() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    // %fsr.fcc0 = 2（greater）。movfcc fg（fcond=6）, %fcc0 は成立。
    env.backend.set(sem::fsr_ref(), 2 << 10);
    env.backend.set(Gpr(5).state(), 0xdead_beef);
    let word: u32 = (0b10 << 30) | (3 << 25) | (0b101100 << 19) | (6 << 14) | 5;
    let insn = dec_v9(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Movfcc);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    assert_eq!(g(&mut env, 3), 0xdead_beef);
    // fcond=fe（9）は fcc0=2 では不成立なので rd は変わらない。
    let word2: u32 = (0b10 << 30) | (4 << 25) | (0b101100 << 19) | (9 << 14) | 5;
    let insn2 = dec_v9(word2);
    env.step(|b| sem::exec(b, insn2, word2, 0)).unwrap();
    assert_eq!(g(&mut env, 4), 0);
}

#[test]
fn shift_imm32_rejects_reserved_bit5() {
    // 32 ビットシフト即値形の bit5 は予約。1 が立つ語は解読しない。
    let word: u32 = (0b10 << 30) | (2 << 25) | (0b100101 << 19) | (1 << 14) | (1 << 13) | 33;
    assert!(polyisa_guest_sparc::decode_model_ex(u128::from(word), 32, false, V9_FEATS).is_none());
}

// ---- SP10: FPU ----

fn dec_v8(word: u32) -> polyisa_guest_sparc::Insn {
    polyisa_guest_sparc::decode_model_ex(
        u128::from(word),
        32,
        false,
        polyisa_guest_sparc::FEAT_V7 | polyisa_guest_sparc::FEAT_V8,
    )
    .unwrap()
}

fn fp_env() -> BareEnv {
    let mut env = env();
    // PSR.EF（bit12）を立てて FPU を有効にする。
    env.backend.set(sem::psr_ref(), 1 << 12);
    env
}

#[test]
fn fp_disabled_traps_when_ef_clear() {
    let mut env = env();
    env.backend.set(Fpr(1).state(), 0x3fc0_0000);
    // fadds %f1, %f2, %f3。
    let word: u32 = (0b10 << 30) | (3 << 25) | (0b110100 << 19) | (1 << 14) | (0x41 << 5) | 2;
    let insn = dec_v8(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Fadds);
    let r = env.step(|b| sem::exec(b, insn, word, 0));
    assert!(r.is_err());
    assert_eq!(env.backend.get(sem::tt_ref()), 0x04);
}

#[test]
fn fadds_computes_single_sum() {
    let mut env = fp_env();
    fset_s(&mut env, 1, 0x3fc0_0000); // 1.5f
    fset_s(&mut env, 2, 0x4010_0000); // 2.25f
    let word: u32 = (0b10 << 30) | (3 << 25) | (0b110100 << 19) | (1 << 14) | (0x41 << 5) | 2;
    env.step(|b| sem::exec(b, dec_v8(word), word, 0)).unwrap();
    // 3.75f。
    assert_eq!(fget_s(&mut env, 3), 0x4070_0000);
}

#[test]
fn fcmpd_writes_fcc() {
    let mut env = fp_env();
    // %d2 = 1.0、%d4 = 2.0。2.0 > 1.0 なので lt=1。
    fset_d(&mut env, 2, 0x3ff0_0000_0000_0000);
    fset_d(&mut env, 4, 0x4000_0000_0000_0000);
    let word: u32 = (0b10 << 30) | (0b110101 << 19) | (2 << 14) | (0x52 << 5) | 4;
    env.step(|b| sem::exec(b, dec_v8(word), word, 0)).unwrap();
    assert_eq!(env.backend.get(sem::fsr_ref()) & (0b11 << 10), 1 << 10);
}

#[test]
fn fp_conversions() {
    let mut env = fp_env();
    // fstoi %f2(-1.5f), %f3 → -1。
    fset_s(&mut env, 2, 0xbfc0_0000);
    let word: u32 = (0b10 << 30) | (3 << 25) | (0b110100 << 19) | (0xd1 << 5) | 2;
    env.step(|b| sem::exec(b, dec_v8(word), word, 0)).unwrap();
    assert_eq!(fget_s(&mut env, 3), (-1i32) as u32 as u64);
    // fitos %f4(42), %f5 → 42.0f。
    fset_s(&mut env, 4, 42);
    let word2: u32 = (0b10 << 30) | (5 << 25) | (0b110100 << 19) | (0xc4 << 5) | 4;
    env.step(|b| sem::exec(b, dec_v8(word2), word2, 0)).unwrap();
    assert_eq!(fget_s(&mut env, 5), 0x4228_0000);
}

#[test]
fn ldf_stf_roundtrip() {
    let mut env = fp_env();
    env.backend.set(Gpr(1).state(), 0x1_0000);
    fset_s(&mut env, 1, 0xdead_beef);
    // stf %f1, [%g1 + 0]。
    let word: u32 = (0b11 << 30) | (1 << 25) | (0b100100 << 19) | (1 << 14) | (1 << 13);
    env.step(|b| sem::exec(b, dec_v8(word), word, 0)).unwrap();
    // ldf [%g1 + 0], %f5。
    let word2: u32 = (0b11 << 30) | (5 << 25) | (0b100000 << 19) | (1 << 14) | (1 << 13);
    env.step(|b| sem::exec(b, dec_v8(word2), word2, 0)).unwrap();
    assert_eq!(fget_s(&mut env, 5), 0xdead_beef);
}

#[test]
fn v9_fmovscc_moves_on_icc() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    env.backend.set(sem::tstate_ref(), 1 << 12); // PSTATE.PEF
    env.backend.set(sem::fprs_ref(), 0b100); // FPRS.FEF
    env.backend.set(sem::ccr_ref(), 0b0100); // icc.z=1
    fset_s(&mut env, 5, 0xdead_beef);
    // fmovscc %icc, e(cond=1), %f5, %f3。bit18=0, bit13=1, cc=0。
    let word: u32 =
        (0b10 << 30) | (3 << 25) | (0b110101 << 19) | (1 << 14) | (1 << 13) | (1 << 5) | 5;
    let insn = dec_v9(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Fmovscc);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    assert_eq!(fget_s(&mut env, 3), 0xdead_beef);
}

#[test]
fn v9_fcmp_selects_fccn() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    env.backend.set(sem::tstate_ref(), 1 << 12); // PSTATE.PEF
    env.backend.set(sem::fprs_ref(), 0b100); // FPRS.FEF
    fset_s(&mut env, 2, 0x4000_0000); // 2.0f
    fset_s(&mut env, 4, 0x3f80_0000); // 1.0f
    // fcmps %fcc1, %f2, %f4 → gt=2 を fcc1（FSR bit32-33）へ。
    let word: u32 = (0b10 << 30) | (1 << 25) | (0b110101 << 19) | (2 << 14) | (0x51 << 5) | 4;
    let insn = dec_v9(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Fcmps);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    assert_eq!(env.backend.get(sem::fsr_ref()) & (0b11 << 32), 2 << 32);
    // fcc0 は動かない。
    assert_eq!(env.backend.get(sem::fsr_ref()) & (0b11 << 10), 0);
}

fn v9_fp_env() -> BareEnv {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    env.backend.set(sem::tstate_ref(), 1 << 12); // PSTATE.PEF
    env.backend.set(sem::fprs_ref(), 0b100); // FPRS.FEF
    env
}

#[test]
fn v9_fstox_converts_single_to_i64() {
    let mut env = v9_fp_env();
    // fstox の opf は 0x81（fdtox は 0x82）。
    let word: u32 = (0b10 << 30) | (4 << 25) | (0b110100 << 19) | (0x81 << 5) | 2;
    let insn = dec_v9(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Fstox);
    let word2: u32 = (0b10 << 30) | (4 << 25) | (0b110100 << 19) | (0x82 << 5) | 2;
    assert_eq!(dec_v9(word2), polyisa_guest_sparc::Insn::Fdtox);
    fset_s(&mut env, 2, 0xbfc0_0000); // -1.5f
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    // -1 を 64 ビットで %d4 に書く。
    assert_eq!(fget_d(&mut env, 4), 0xffff_ffff_ffff_ffff);
}

#[test]
fn v9_odd_d_field_uses_upper_bank() {
    let mut env = v9_fp_env();
    env.backend.set(Gpr(1).state(), 0x1_0000);
    env.backend.set(Gpr(2).state(), 0x0123_4567_89ab_cdef);
    env.step(|b| sem::stx(b, Gpr(2), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    // lddf [%g1 + 0], %f31 — V9 では奇数桁は上位バンクを指し、
    // フィールド 31 は %d62（スロット 31）。合法。
    let word: u32 = (0b11 << 30) | (31 << 25) | (0b100011 << 19) | (1 << 14) | (1 << 13);
    let insn = dec_v9(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::LddfI);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    assert_eq!(env.backend.get(Fpr(31).state()), 0x0123_4567_89ab_cdef);
}

#[test]
fn v8_odd_d_field_aligns_to_even() {
    let mut env = fp_env();
    fset_d(&mut env, 2, 0x3ff0_0000_0000_0000); // %d2 = 1.0
    fset_d(&mut env, 4, 0x4000_0000_0000_0000); // %d4 = 2.0
    // faddd %d2, %d4, %d31 → V8 では %d30 に畳む。
    let word: u32 = (0b10 << 30) | (31 << 25) | (0b110100 << 19) | (2 << 14) | (0x42 << 5) | 4;
    let insn = dec_v8(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Faddd);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    // 3.0 = 0x40080000_00000000。
    assert_eq!(fget_d(&mut env, 30), 0x4008_0000_0000_0000);
}

#[test]
fn v9_ldfsr_preserves_fcc1_3() {
    let mut env = v9_fp_env();
    env.backend.set(Gpr(1).state(), 0x1_0000);
    // fcc1 = gt（2）を FSR bit32-33 に置く。
    env.backend.set(sem::fsr_ref(), 2u64 << 32);
    // stf でメモリに 0x0000_0c00（fcc0=3 だけの値）を置く。
    fset_s(&mut env, 6, 0x0000_0c00);
    let st: u32 = (0b11 << 30) | (6 << 25) | (0b100100 << 19) | (1 << 14) | (1 << 13);
    env.step(|b| sem::exec(b, dec_v9(st), st, 0)).unwrap();
    // ldfsr [%g1]。
    let word: u32 = (0b11 << 30) | (0b100001 << 19) | (1 << 14) | (1 << 13);
    let insn = dec_v9(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::LdfsrI);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    let fsr = env.backend.get(sem::fsr_ref());
    assert_eq!(fsr & 0xffff_ffff, 0x0c00);
    // fcc1-3 は保存される。
    assert_eq!(fsr >> 32, 2);
}

// ---- SP11: ユーザ ASI・VIS ----

const VIS_FEATS: u128 = V9_FEATS | polyisa_guest_sparc::FEAT_VIS;
const VIS2_FEATS: u128 = VIS_FEATS | polyisa_guest_sparc::FEAT_VIS2;

fn dec_vis(word: u32) -> polyisa_guest_sparc::Insn {
    polyisa_guest_sparc::decode_model_ex(u128::from(word), 32, true, VIS_FEATS).unwrap()
}

fn dec_vis2(word: u32) -> polyisa_guest_sparc::Insn {
    polyisa_guest_sparc::decode_model_ex(u128::from(word), 32, true, VIS2_FEATS).unwrap()
}

#[test]
fn v9_rdwrasi_roundtrip() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    env.backend.set(Gpr(1).state(), 0x80);
    // wrasi %g1, %g0, %asi。
    let wr: u32 = (0b10 << 30) | (3 << 25) | (0b110000 << 19) | (1 << 14);
    let insn = dec_v9(wr);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Wrasi);
    env.step(|b| sem::exec(b, insn, wr, 0)).unwrap();
    assert_eq!(env.backend.get(sem::asi_ref()), 0x80);
    // rdasi %g3。
    let rd: u32 = (0b10 << 30) | (3 << 25) | (0b101000 << 19) | (3 << 14);
    let insn = dec_v9(rd);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Rdasi);
    env.step(|b| sem::exec(b, insn, rd, 0)).unwrap();
    assert_eq!(g(&mut env, 3), 0x80);
}

#[test]
fn v9_user_asi_load_and_privilege() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    env.backend.set(Gpr(1).state(), 0x100);
    env.backend.set(Gpr(5).state(), 0xdead_beef);
    env.step(|b| sem::stb(b, Gpr(5), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    // nonrestricted ASI（0x80 以上）は非特権でも読める。
    env.backend.set(sem::asi_ref(), 0x80);
    let word: u32 = (0b11 << 30) | (2 << 25) | (0b010001 << 19) | (1 << 14) | (1 << 13);
    let insn = dec_v9(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::LdubaI);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    assert_eq!(g(&mut env, 2), 0xef);
    // restricted ASI（0x80 未満）は privileged_action=0x37。
    env.backend.set(sem::asi_ref(), 0x10);
    let r = env.step(|b| sem::exec(b, insn, word, 0));
    assert!(r.is_err());
    assert_eq!(env.backend.get(sem::tt_ref()), 0x37);
}

#[test]
fn v9_asi_reg_form_uses_asi_field() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    env.backend.set(Gpr(1).state(), 0x100);
    env.backend.set(Gpr(5).state(), 0xef);
    env.step(|b| sem::stb(b, Gpr(5), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    // lduba [%g1] 0x80, %g2。asi フィールドは命令の中にある。
    let word: u32 = (0b11 << 30) | (2 << 25) | (0b010001 << 19) | (1 << 14) | (0x80 << 5);
    let insn = dec_v9(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Lduba);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    assert_eq!(g(&mut env, 2), 0xef);
    // レジスタ形でも restricted ASI は privileged_action。
    let bad: u32 = (0b11 << 30) | (2 << 25) | (0b010001 << 19) | (1 << 14) | (0x10 << 5);
    let insn = dec_v9(bad);
    let r = env.step(|b| sem::exec(b, insn, bad, 0));
    assert!(r.is_err());
}

#[test]
fn v9_rdwrgsr_and_fprs() {
    // rdgsr/wrgsr は FPU 有効が要る。
    let mut env = v9_fp_env();
    env.backend.set(Gpr(1).state(), 0x1234_5678_9abc_def0);
    // wrgsr %g1, %g0, %gsr。
    let wr: u32 = (0b10 << 30) | (19 << 25) | (0b110000 << 19) | (1 << 14);
    let insn = dec_v9(wr);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Wrgsr);
    env.step(|b| sem::exec(b, insn, wr, 0)).unwrap();
    assert_eq!(env.backend.get(sem::gsr_ref()), 0x1234_5678_9abc_def0);
    // rdgsr %g3。
    let rd: u32 = (0b10 << 30) | (3 << 25) | (0b101000 << 19) | (19 << 14);
    let insn = dec_v9(rd);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Rdgsr);
    env.step(|b| sem::exec(b, insn, rd, 0)).unwrap();
    assert_eq!(g(&mut env, 3), 0x1234_5678_9abc_def0);
    // wrfprs %g1(=0xf0), %g0, %fprs → 下位 32 ビットをそのまま保持。
    env.backend.set(Gpr(1).state(), 0xf0);
    let wr2: u32 = (0b10 << 30) | (6 << 25) | (0b110000 << 19) | (1 << 14);
    let insn = dec_v9(wr2);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Wrfprs);
    env.step(|b| sem::exec(b, insn, wr2, 0)).unwrap();
    assert_eq!(env.backend.get(sem::fprs_ref()), 0xf0);
    env.backend.set(Gpr(1).state(), 0b101);
    env.step(|b| sem::exec(b, insn, wr2, 0)).unwrap();
    assert_eq!(env.backend.get(sem::fprs_ref()), 0b101);
    // rdfprs %g3。
    let rd2: u32 = (0b10 << 30) | (3 << 25) | (0b101000 << 19) | (6 << 14);
    env.step(|b| sem::exec(b, dec_v9(rd2), rd2, 0)).unwrap();
    assert_eq!(g(&mut env, 3), 0b101);
}

#[test]
fn vis_insn_needs_vis_feature() {
    // fand %f2, %f4, %f6。V9 だけでは解読できない。
    let word: u32 = (0b10 << 30) | (6 << 25) | (0b110110 << 19) | (2 << 14) | (0x70 << 5) | 4;
    assert!(polyisa_guest_sparc::decode_model_ex(u128::from(word), 32, true, V9_FEATS).is_none());
    assert_eq!(dec_vis(word), polyisa_guest_sparc::Insn::Fand);
    // edge8n は VIS2 専用。
    let e: u32 = (0b10 << 30) | (6 << 25) | (0b110110 << 19) | (4 << 14) | (1 << 5) | 5;
    assert!(polyisa_guest_sparc::decode_model_ex(u128::from(e), 32, true, VIS_FEATS).is_none());
    assert_eq!(dec_vis2(e), polyisa_guest_sparc::Insn::Edge8n);
    // V9 の %asi 形は V8 では解読できない。
    let lduba_i: u32 = (0b11 << 30) | (2 << 25) | (0b010001 << 19) | (1 << 14) | (1 << 13);
    assert!(
        polyisa_guest_sparc::decode_model_ex(
            u128::from(lduba_i),
            32,
            false,
            polyisa_guest_sparc::FEAT_V7 | polyisa_guest_sparc::FEAT_V8
        )
        .is_none()
    );
}

#[test]
fn vis_alignaddr_and_faligndata() {
    let mut env = v9_fp_env();
    env.backend.set(Gpr(1).state(), 0x1003);
    env.backend.set(Gpr(2).state(), 0x10);
    // alignaddr %g1, %g2, %g3。rd = (rs1+rs2) & ~8、GSR.align = 和の下位3ビット。
    let word: u32 = (0b10 << 30) | (3 << 25) | (0b110110 << 19) | (1 << 14) | (0x18 << 5) | 2;
    let insn = dec_vis(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Alignaddr);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    assert_eq!(g(&mut env, 3), 0x1010);
    assert_eq!(env.backend.get(sem::gsr_ref()) & 7, 3);
    // alignaddrl は GSR.align に負の和を入れる。
    let wl: u32 = (0b10 << 30) | (3 << 25) | (0b110110 << 19) | (1 << 14) | (0x1a << 5) | 2;
    env.step(|b| sem::exec(b, dec_vis(wl), wl, 0)).unwrap();
    assert_eq!(env.backend.get(sem::gsr_ref()) & 7, (-0x1013i64 & 7) as u64);
    // faligndata %f2, %f4, %f6。align=3 なら 24 ビット左の連結。
    env.backend.set(sem::gsr_ref(), 3);
    fset_d(&mut env, 2, 0x1111_2222_3333_4444);
    fset_d(&mut env, 4, 0x5555_6666_7777_8888);
    let w: u32 = (0b10 << 30) | (6 << 25) | (0b110110 << 19) | (2 << 14) | (0x48 << 5) | 4;
    let insn = dec_vis(w);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Faligndata);
    env.step(|b| sem::exec(b, insn, w, 0)).unwrap();
    // (0x1111222233334444 << 24) | (0x5555666677778888 >> 40)
    //   = 0x22333344_44555566。
    assert_eq!(fget_d(&mut env, 6), 0x2233_3344_4455_5566);
    // align=0 なら rs1 そのもの。
    env.backend.set(sem::gsr_ref(), 0);
    env.step(|b| sem::exec(b, insn, w, 0)).unwrap();
    assert_eq!(fget_d(&mut env, 6), 0x1111_2222_3333_4444);
}

#[test]
fn vis_edge8cc_mask_and_cc() {
    let mut env = v9_fp_env();
    env.backend.set(Gpr(4).state(), 0x1002);
    env.backend.set(Gpr(5).state(), 0x1005);
    // edge8cc %g4, %g5, %g6。
    let word: u32 = (0b10 << 30) | (6 << 25) | (0b110110 << 19) | (4 << 14) | 5;
    let insn = dec_vis(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Edge8cc);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    // 同じブロック内：left=0xff>>2=0x3f、right=0xff<<2&0xff=0xfc → 0x3c。
    assert_eq!(g(&mut env, 6), 0x3c);
    // s1-s2 < 0 → icc.n=1、xcc.n=1。
    let ccr = env.backend.get(sem::ccr_ref());
    assert_eq!(ccr & 0b1000, 0b1000);
    assert_eq!(ccr & 0b1000_0000, 0b1000_0000);
    // ブロックをまたぐときは left だけ。
    env.backend.set(Gpr(5).state(), 0x2005);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    assert_eq!(g(&mut env, 6), 0x3f);
}

#[test]
fn vis_array8_reorders_address_fields() {
    let mut env = v9_fp_env();
    // x=bits21:11、y=bits43:33、z=bits63:55 に 1 を置く。
    env.backend
        .set(Gpr(1).state(), (1 << 11) | (1 << 33) | (1 << 55));
    env.backend.set(Gpr(2).state(), 0);
    // array8 %g1, %g2, %g3。
    let word: u32 = (0b10 << 30) | (3 << 25) | (0b110110 << 19) | (1 << 14) | (0x10 << 5) | 2;
    let insn = dec_vis(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Array8);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    // 各フィールドの下位は lx=1,ly=1,lz=1 → 1 | 1<<2 | 1<<4 = 0x15。
    assert_eq!(g(&mut env, 3), 0x15);
}

#[test]
fn vis_bmask_and_bshuffle() {
    let mut env = v9_fp_env();
    env.backend.set(Gpr(1).state(), 0x100);
    env.backend.set(Gpr(2).state(), 0x300);
    // bmask %g1, %g2, %g3。rd = rs1+rs2、GSR[63:32] に和。
    let word: u32 = (0b10 << 30) | (3 << 25) | (0b110110 << 19) | (1 << 14) | (0x19 << 5) | 2;
    let insn = dec_vis2(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Bmask);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    assert_eq!(g(&mut env, 3), 0x400);
    assert_eq!(env.backend.get(sem::gsr_ref()) >> 32, 0x400);
    // bshuffle %f2, %f4, %f6。マスク 0x76543210 → rs1 をそのまま、
    // 0xfedcba98 → rs2 をそのまま選ぶ。
    fset_d(&mut env, 2, 0x1111_2222_3333_4444);
    fset_d(&mut env, 4, 0xaaaa_bbbb_cccc_dddd);
    let w: u32 = (0b10 << 30) | (6 << 25) | (0b110110 << 19) | (2 << 14) | (0x4c << 5) | 4;
    let insn = dec_vis2(w);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Bshuffle);
    env.backend.set(sem::gsr_ref(), 0x7654_3210u64 << 32);
    env.step(|b| sem::exec(b, insn, w, 0)).unwrap();
    assert_eq!(fget_d(&mut env, 6), 0x1111_2222_3333_4444);
    env.backend.set(sem::gsr_ref(), 0xfedc_ba98u64 << 32);
    env.step(|b| sem::exec(b, insn, w, 0)).unwrap();
    assert_eq!(fget_d(&mut env, 6), 0xaaaa_bbbb_cccc_dddd);
}

#[test]
fn vis_fpcmpeq16_bitmask() {
    let mut env = v9_fp_env();
    fset_d(&mut env, 2, 0x0001_0002_0003_0004);
    fset_d(&mut env, 4, 0x0001_0002_0003_ffff);
    // fpcmpeq16 %f2, %f4, %g5。レーン3だけ不一致 → 0b1110。
    let word: u32 = (0b10 << 30) | (5 << 25) | (0b110110 << 19) | (2 << 14) | (0x2a << 5) | 4;
    let insn = dec_vis(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Fpcmpeq16);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    assert_eq!(g(&mut env, 5), 0b1110);
}

#[test]
fn vis_fpadd16_sub16_lane_arithmetic() {
    let mut env = v9_fp_env();
    fset_d(&mut env, 2, 0x0001_ffff_0003_0004);
    fset_d(&mut env, 4, 0x0010_0001_0030_0040);
    // fpadd16 %f2, %f4, %f6。レーン 1 は 0xffff+1 → 0 に戻る（桁上がりなし）。
    let word: u32 = (0b10 << 30) | (6 << 25) | (0b110110 << 19) | (2 << 14) | (0x50 << 5) | 4;
    let insn = dec_vis(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Fpadd16);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    assert_eq!(fget_d(&mut env, 6), 0x0011_0000_0033_0044);
    // fpsub16s %f2, %f4, %f8。単精度形は %f2 / %f4 の値を使う。
    // 0x0001-0x0010=fff1、0xffff-0x0001=fffe → 0xfff1_fffe。
    let ws: u32 = (0b10 << 30) | (8 << 25) | (0b110110 << 19) | (2 << 14) | (0x55 << 5) | 4;
    let insn = dec_vis(ws);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Fpsub16s);
    env.step(|b| sem::exec(b, insn, ws, 0)).unwrap();
    assert_eq!(fget_s(&mut env, 8), 0xfff1_fffe);
}

#[test]
fn vis_fmul8x16_and_pack() {
    let mut env = v9_fp_env();
    fset_s(&mut env, 2, 0x0102_0304);
    fset_d(&mut env, 4, 0x0100_0200_0300_0400);
    // fmul8x16 %f2, %f4, %f6。(u8 * s16 + 0x80) >> 8。
    // byte i * word i: 4*1024→16、3*768→9、2*512→4、1*256→1。
    let word: u32 = (0b10 << 30) | (6 << 25) | (0b110110 << 19) | (2 << 14) | (0x31 << 5) | 4;
    let insn = dec_vis(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Fmul8x16);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    assert_eq!(fget_d(&mut env, 6), 0x0001_0004_0009_0010);
    // fpack16 %f4, %f8。GSR.scale=0 で >> 7 → u8 に飽和。
    // lanes: 0x0100=256→2、0x0200=512→4、0x0300=768→6、0x0400=1024→8。
    env.backend.set(sem::gsr_ref(), 0);
    let w: u32 = (0b10 << 30) | (8 << 25) | (0b110110 << 19) | (0x3b << 5) | 4;
    let insn = dec_vis(w);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Fpack16);
    env.step(|b| sem::exec(b, insn, w, 0)).unwrap();
    assert_eq!(fget_s(&mut env, 8), 0x0204_0608);
    // 負値は 0、256 超は 255 に飽和する。
    fset_d(&mut env, 4, 0x8000_ffff_4000_0080);
    env.step(|b| sem::exec(b, insn, w, 0)).unwrap();
    // lane0: 0x0080=128>>7→1、lane1: 0x4000=16384>>7=128、lane2: 0xffff=-1→0、
    // lane3: 0x8000=-32768→0。
    assert_eq!(fget_s(&mut env, 8), 0x0000_8001);
}

#[test]
fn vis_fpmerge_fexpand_fpackfix() {
    let mut env = v9_fp_env();
    fset_s(&mut env, 2, 0xa1b2_c3d4);
    fset_s(&mut env, 4, 0x1122_3344);
    // fpmerge %f2, %f4, %f6。バイトを交互に並べる。
    let word: u32 = (0b10 << 30) | (6 << 25) | (0b110110 << 19) | (2 << 14) | (0x4b << 5) | 4;
    let insn = dec_vis(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Fpmerge);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    assert_eq!(fget_d(&mut env, 6), 0xa111_b222_c333_d444);
    // fexpand %f4, %f8。各バイトを <<4 の 16 ビットに展開。
    let we: u32 = (0b10 << 30) | (8 << 25) | (0b110110 << 19) | (0x4d << 5) | 4;
    let insn = dec_vis(we);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Fexpand);
    env.step(|b| sem::exec(b, insn, we, 0)).unwrap();
    assert_eq!(fget_d(&mut env, 8), 0x0110_0220_0330_0440);
    // fpackfix %f4, %f10。scale=0 で >>16、符号付き 16 ビット飽和。
    env.backend.set(sem::gsr_ref(), 0);
    fset_d(&mut env, 4, 0x0001_0000_7fff_ffff);
    let wf: u32 = (0b10 << 30) | (10 << 25) | (0b110110 << 19) | (0x3d << 5) | 4;
    let insn = dec_vis(wf);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Fpackfix);
    env.step(|b| sem::exec(b, insn, wf, 0)).unwrap();
    // lane0 = 0x7fffffff>>16 = 0x7fff、lane1 = 0x00010000>>16 = 1。
    assert_eq!(fget_s(&mut env, 10), 0x0001_7fff);
}

#[test]
fn vis_fpack32_and_pdist() {
    let mut env = v9_fp_env();
    fset_d(&mut env, 2, 0xaabb_ccdd_eeff_0011);
    fset_d(&mut env, 4, 0x0400_0000_ffff_ffff);
    env.backend.set(sem::gsr_ref(), 0);
    // fpack32 %f2, %f4, %f6。rs1 を <<8 して末尾バイトを埋める。
    let word: u32 = (0b10 << 30) | (6 << 25) | (0b110110 << 19) | (2 << 14) | (0x3a << 5) | 4;
    let insn = dec_vis(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Fpack32);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    // lane0 = -1 → 0、lane1 = 0x04000000>>23 = 8。rs1<<8 の各ワード
    // 最下位バイトはクリアされて飽和値が入る。
    assert_eq!(fget_d(&mut env, 6), 0xbbcc_dd08_ff00_1100);
    // pdist %f2, %f4, %f8。8 バイトの絶対差の和を rd に累積。
    fset_d(&mut env, 2, 0x0102_0304_0506_0708);
    fset_d(&mut env, 4, 0x0807_0605_0403_0201);
    fset_d(&mut env, 8, 5);
    let wp: u32 = (0b10 << 30) | (8 << 25) | (0b110110 << 19) | (2 << 14) | (0x3e << 5) | 4;
    let insn = dec_vis(wp);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Pdist);
    env.step(|b| sem::exec(b, insn, wp, 0)).unwrap();
    // 7+5+3+1+1+3+5+7 = 32、累積 5 → 37。
    assert_eq!(fget_d(&mut env, 8), 37);
}

#[test]
fn vis_fef_gates_vis_ops() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    env.backend.set(sem::tstate_ref(), 1 << 12); // PSTATE.PEF
    // FPRS.FEF=0 → fand は fp_disabled。
    let word: u32 = (0b10 << 30) | (6 << 25) | (0b110110 << 19) | (2 << 14) | (0x70 << 5) | 4;
    let insn = dec_vis(word);
    let r = env.step(|b| sem::exec(b, insn, word, 0));
    assert!(r.is_err());
    assert_eq!(env.backend.get(sem::tt_ref()), 0x20);
    // FEF を立てると実行できる。
    env.backend.set(sem::fprs_ref(), 0b100);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
}

#[test]
fn vis_fmul8x16au_sign_extends_constant() {
    let mut env = v9_fp_env();
    fset_s(&mut env, 2, 0x0202_0202);
    // AU の定数は rs2 の上位 16 ビットの符号付き値。0x8000 → -32768。
    fset_s(&mut env, 4, 0x8000_0000);
    // fmul8x16au %f2, %f4, %f6。(2 * -32768 + 0x80) >> 8 = -256 = 0xff00。
    let word: u32 = (0b10 << 30) | (6 << 25) | (0b110110 << 19) | (2 << 14) | (0x33 << 5) | 4;
    let insn = dec_vis(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Fmul8x16au);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    assert_eq!(fget_d(&mut env, 6), 0xff00_ff00_ff00_ff00);
}

#[test]
fn v9_casa_restricted_asi_traps() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    env.backend.set(Gpr(1).state(), 0x100);
    // casa [%g1] 0x10, %g2, %g3。restricted ASI → privileged_action。
    let word: u32 = (0b11 << 30) | (3 << 25) | (0b111100 << 19) | (1 << 14) | (0x10 << 5) | 2;
    let insn = dec_v9(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Casa);
    let r = env.step(|b| sem::exec(b, insn, word, 0));
    assert!(r.is_err());
    assert_eq!(env.backend.get(sem::tt_ref()), 0x37);
    // %asi=0x80 の casa_i は通る。メモリは別の値を入れておく。
    env.backend.set(sem::asi_ref(), 0x80);
    env.backend.set(Gpr(2).state(), 0x1111);
    env.backend.set(Gpr(3).state(), 0x2222);
    env.step(|b| sem::st(b, Gpr(2), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    let wi: u32 = (0b11 << 30) | (3 << 25) | (0b111100 << 19) | (1 << 14) | (1 << 13) | 2;
    let insn = dec_v9(wi);
    assert_eq!(insn, polyisa_guest_sparc::Insn::CasaI);
    env.step(|b| sem::exec(b, insn, wi, 0)).unwrap();
}

#[test]
fn v9_fprs_dirty_bit_after_f_write() {
    let mut env = v9_fp_env();
    env.backend.set(Fpr(5).state(), 0xdead_beef);
    // fmovs %f5, %f3。
    let word: u32 = (0b10 << 30) | (3 << 25) | (0b110100 << 19) | (1 << 5) | 5;
    env.step(|b| sem::exec(b, dec_v9(word), word, 0)).unwrap();
    // FPRS.DL（bit0）が立つ。
    assert_eq!(env.backend.get(sem::fprs_ref()) & 1, 1);
}

#[test]
fn ldd_odd_rd_is_illegal() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 0x100);
    // ldd の rd は偶数が要る。sem 層で拒否する。
    let r = env.step(|b| sem::ldd(b, Gpr(3), Gpr(4), Gpr(1), Src2::Reg(Gpr(0))));
    assert!(r.is_err());
    let r = env.step(|b| sem::std(b, Gpr(3), Gpr(4), Gpr(1), Src2::Reg(Gpr(0))));
    assert!(r.is_err());
}

#[test]
fn save_traps_when_cansave_empty() {
    let mut env = env();
    env.backend.set(sem::cansave_ref(), 0);
    let r = env.step(|b| sem::save(b, Gpr(0), Gpr(0), Src2::Reg(Gpr(0))));
    assert!(r.is_err());
    // V8 の window_overflow = 0x05。CWP とカウンタは変えない。
    assert_eq!(env.backend.get(sem::tt_ref()), 0x05);
    assert_eq!(env.backend.get(sem::cwp_ref()), 0);
    // SAVED で窓を空きに戻すと SAVE が通る。saved は OTHERWIN=0
    // のモデルでは cansave++・canrestore--（SPEC-SPARC-V9 §SAVED
    // の遷移）なので、退避済みの使用窓がある想定で canrestore=1
    // を置く。
    env.backend.set(sem::canrestore_ref(), 1);
    env.step(sem::saved).unwrap();
    assert_eq!(env.backend.get(sem::cansave_ref()), 1);
    env.step(|b| sem::save(b, Gpr(0), Gpr(0), Src2::Reg(Gpr(0))))
        .unwrap();
    assert_eq!(env.backend.get(sem::cwp_ref()), 7);
    assert_eq!(env.backend.get(sem::cansave_ref()), 0);
    assert_eq!(env.backend.get(sem::canrestore_ref()), 1);
}

#[test]
fn restore_traps_when_canrestore_empty() {
    let mut env = env();
    let r = env.step(|b| sem::restore(b, Gpr(0), Gpr(0), Src2::Reg(Gpr(0))));
    assert!(r.is_err());
    // V8 の window_underflow = 0x06。
    assert_eq!(env.backend.get(sem::tt_ref()), 0x06);
    assert_eq!(env.backend.get(sem::cwp_ref()), 0);
    // RESTORED で埋め戻せる窓を戻すと RESTORE が通る。restored は
    // OTHERWIN=0 のモデルでは canrestore++・cansave--
    // （SPEC-SPARC-V9 §RESTORED の遷移）なので、cansave は
    // 7→6→7 に戻る。
    env.step(sem::restored).unwrap();
    env.step(|b| sem::restore(b, Gpr(0), Gpr(0), Src2::Reg(Gpr(0))))
        .unwrap();
    assert_eq!(env.backend.get(sem::cwp_ref()), 1);
    assert_eq!(env.backend.get(sem::canrestore_ref()), 0);
    assert_eq!(env.backend.get(sem::cansave_ref()), 7);
}

#[test]
fn v9_window_traps_use_spill_fill_vectors() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    env.backend.set(sem::cansave_ref(), 0);
    let r = env.step(|b| sem::save(b, Gpr(0), Gpr(0), Src2::Reg(Gpr(0))));
    assert!(r.is_err());
    // V9 の spill_0_normal = 0x80。
    assert_eq!(env.backend.get(sem::tt_ref()), 0x80);
    env.backend.set(sem::canrestore_ref(), 0);
    let r = env.step(|b| sem::restore(b, Gpr(0), Gpr(0), Src2::Reg(Gpr(0))));
    assert!(r.is_err());
    // V9 の fill_0_normal = 0xc0。
    assert_eq!(env.backend.get(sem::tt_ref()), 0xc0);
}

#[test]
fn v9_bpcc_uses_selected_cc() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    // XCC の Z（ccr bit6）を倒して bne 成立にする。
    env.backend.set(sem::ccr_ref(), 0);
    // bne,pt %xcc → cc=0b10、cond=0b1001。
    env.step(|b| sem::bpcc(b, 0, 0b1001, 0b10, 0x100, 0x300))
        .unwrap();
    assert_eq!(env.backend.get(sem::npc_ref()), 0x300);
    // ICC 側（cc=0b00）は Z が未設定なので成立する。
    env.step(|b| sem::bpcc(b, 0, 0b1001, 0b00, 0x100, 0x300))
        .unwrap();
    assert_eq!(env.backend.get(sem::npc_ref()), 0x300);
    // XCC に Z を立てると xcc 側だけ不成立になる。
    env.backend.set(sem::ccr_ref(), 1 << 6);
    env.step(|b| sem::bpcc(b, 0, 0b1001, 0b10, 0x100, 0x300))
        .unwrap();
    assert_eq!(env.backend.get(sem::npc_ref()), 0x108);
}

#[test]
fn v9_bpr_evaluates_signed_register() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    env.backend.set(Gpr(9).state(), 0xffff_ffff_ffff_ffffu64); // -1
    // brlz（rcond=011）は負で成立。
    env.step(|b| sem::bpr(b, 0, 0b011, Gpr(9), 0x100, 0x300))
        .unwrap();
    assert_eq!(env.backend.get(sem::npc_ref()), 0x300);
    // brgez（rcond=111）は不成立 → pc+8。
    env.step(|b| sem::bpr(b, 0, 0b111, Gpr(9), 0x100, 0x300))
        .unwrap();
    assert_eq!(env.backend.get(sem::npc_ref()), 0x108);
    // 予約の rcond=000 は illegal instruction トラップ。
    let r = env.step(|b| sem::bpr(b, 0, 0b000, Gpr(9), 0x100, 0x300));
    assert!(r.is_err());
    assert_eq!(env.backend.get(sem::tt_ref()), 0x10);
}

#[test]
fn fbfcc_uses_fcc0() {
    let mut env = env();
    // FSR.fcc0 = 0（eq）で fbe が成立。
    env.step(|b| sem::fbfcc(b, 0, 0b1001, 0x100, 0x300))
        .unwrap();
    assert_eq!(env.backend.get(sem::npc_ref()), 0x300);
    // fcc0 = 1（lt）なら fbe は不成立。
    env.backend.set(sem::fsr_ref(), 1 << 10);
    env.step(|b| sem::fbfcc(b, 0, 0b1001, 0x100, 0x300))
        .unwrap();
    assert_eq!(env.backend.get(sem::npc_ref()), 0x108);
}

#[test]
fn v9_fbpfcc_selects_fcc_and_annuls() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    // fcc1 = 3（unordered）→ fsr bit 32-33。
    env.backend.set(sem::fsr_ref(), 0b11 << 32);
    // fbu（cond=0b0111）fcc1 は成立。
    env.step(|b| sem::fbpfcc(b, 0, 0b0111, 1, 0x100, 0x300))
        .unwrap();
    assert_eq!(env.backend.get(sem::npc_ref()), 0x300);
    // fba,a は常に annul。
    env.step(|b| sem::fbpfcc(b, 1, 0b1000, 0, 0x100, 0x300))
        .unwrap();
    assert_eq!(env.backend.get(sem::annul_ref()), 1);
}

#[test]
fn v9_flushw_is_privileged() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    // flushw（op3=101011）はユーザーモードでは
    // privileged_opcode（tt=0x11）。`ta 3` のソフトウェア
    // flushw とは別経路。
    let word: u32 = (0b10 << 30) | (0b101011 << 19);
    let insn = dec_v9(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Flushw);
    let r = env.step(|b| sem::exec(b, insn, word, 0));
    assert!(r.is_err());
    assert_eq!(env.backend.get(sem::tt_ref()), 0x11);
}

#[test]
fn v9_casxa_asi_form_exchanges_and_rejects_reserved_bits() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    env.backend.set(sem::asi_ref(), 0x80);
    env.backend.set(Gpr(1).state(), 0x700);
    env.backend.set(Gpr(2).state(), 0xdead_beef_cafe_f00d); // rd（新値）
    env.backend.set(Gpr(3).state(), 0x0123_4567_89ab_cdef); // rs2（比較値）
    env.backend.set(Gpr(4).state(), 0x0123_4567);
    env.step(|b| sem::st(b, Gpr(4), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    env.backend.set(Gpr(4).state(), 0x89ab_cdef);
    env.step(|b| sem::st(b, Gpr(4), Gpr(1), Src2::Imm(4)))
        .unwrap();
    // casxa_i [%g1] %asi, %g3, %g2（i=1、rs2 フィールドは下位
    // 5 ビット）。
    let word: u32 = (0b11 << 30) | (2 << 25) | (0b111110 << 19) | (1 << 14) | (1 << 13) | 3;
    let insn = dec_v9(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::CasxaI);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    // %g3 とメモリが一致するので交換が起き、rd には旧値が戻る。
    assert_eq!(g(&mut env, 2), 0x0123_4567_89ab_cdef);
    env.step(|b| sem::ldx(b, Gpr(4), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    assert_eq!(g(&mut env, 4), 0xdead_beef_cafe_f00d);
    // 予約ビット（rs2 フィールドの上位）が立つ語は解読できない。
    let bad: u32 = (0b11 << 30) | (2 << 25) | (0b111110 << 19) | (1 << 14) | (1 << 13) | 0x143;
    assert!(polyisa_guest_sparc::decode_model_ex(u128::from(bad), 32, true, V9_FEATS).is_none());
}

#[test]
fn v9_fasi_blk_loads_eight_slots() {
    let mut env = v9_fp_env();
    env.backend.set(Gpr(1).state(), 0x1_0000);
    // 64 バイトを stx で用意する。
    for i in 0..8u64 {
        env.backend.set(Gpr(2).state(), 0x1000 + i);
        env.step(|b| sem::stx(b, Gpr(2), Gpr(1), Src2::Imm((i * 8) as i64)))
            .unwrap();
    }
    // lddfa [%g1 + %g0] 0xf0, %f0（fd フィールド=0 → %d0 から
    // 8 スロット）。
    let word: u32 = (0b11 << 30) | (0b110011 << 19) | (1 << 14) | (0xf0 << 5);
    let insn = dec_v9(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Lddfa);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    for i in 0..8u8 {
        assert_eq!(fget_d(&mut env, i * 2), 0x1000 + u64::from(i));
    }
    // stdfa で書き戻せることも確かめる。
    let w: u32 = (0b11 << 30) | (0b110111 << 19) | (1 << 14) | (0xf0 << 5);
    let insn = dec_v9(w);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Stdfa);
    env.step(|b| sem::exec(b, insn, w, 0)).unwrap();
}

#[test]
fn v9_fasi_blk_out_of_range_field_traps() {
    let mut env = v9_fp_env();
    env.backend.set(Gpr(1).state(), 0x1_0000);
    let pc0 = env.backend.get(sem::pc_ref());
    let npc0 = env.backend.get(sem::npc_ref());
    let cwp0 = env.backend.get(sem::cwp_ref());
    // fd=25 → R=56。R%8==0 でも R>48 は 8 スロット目が f 配列を
    // 越えるので illegal。状態破壊がないことも併せて見る
    // （Fpr(28..) の先は pc/npc/cwp にエイリアスする）。
    let word: u32 = (0b11 << 30) | (25 << 25) | (0b110011 << 19) | (1 << 14) | (0xf0 << 5);
    let insn = dec_v9(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Lddfa);
    let r = env.step(|b| sem::exec(b, insn, word, 0));
    assert!(r.is_err());
    assert_eq!(env.backend.get(sem::tt_ref()), 0x10);
    assert_eq!(env.backend.get(sem::pc_ref()), pc0);
    assert_eq!(env.backend.get(sem::npc_ref()), npc0);
    assert_eq!(env.backend.get(sem::cwp_ref()), cwp0);
}

#[test]
fn v9_fasi_blk_requires_64_byte_alignment() {
    let mut env = v9_fp_env();
    // fd=0 は合法でもアドレスが 64 バイト境界に乗らないと
    // mem_address_not_aligned 相当の例外になる（8 バイトには
    // 揃っているが 64 バイトには揃っていない 0x10008）。
    env.backend.set(Gpr(1).state(), 0x1_0008);
    let word: u32 = (0b11 << 30) | (0b110011 << 19) | (1 << 14) | (0xf0 << 5);
    let insn = dec_v9(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Lddfa);
    let r = env.step(|b| sem::exec(b, insn, word, 0));
    assert!(r.is_err());
}

#[test]
fn v9_fasi_blk_on_wrong_size_traps() {
    let mut env = v9_fp_env();
    env.backend.set(Gpr(1).state(), 0x1_0000);
    // BLK ASI は lddfa/stdfa 限定。ldfa に付けると illegal。
    let w: u32 = (0b11 << 30) | (0b110000 << 19) | (1 << 14) | (0xf0 << 5);
    let insn = dec_v9(w);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Ldfa);
    let r = env.step(|b| sem::exec(b, insn, w, 0));
    assert!(r.is_err());
    assert_eq!(env.backend.get(sem::tt_ref()), 0x10);
    // SHORT ASI（0xd0 系）も同じく lddfa/stdfa 限定。
    let w2: u32 = (0b11 << 30) | (0b110110 << 19) | (1 << 14) | (0xd0 << 5);
    let insn2 = dec_v9(w2);
    assert_eq!(insn2, polyisa_guest_sparc::Insn::Stqfa);
    let r2 = env.step(|b| sem::exec(b, insn2, w2, 0));
    assert!(r2.is_err());
    assert_eq!(env.backend.get(sem::tt_ref()), 0x10);
}

#[test]
fn v9_fasi_short_loads_bytes() {
    let mut env = v9_fp_env();
    env.backend.set(Gpr(1).state(), 0x1_0000);
    env.backend.set(Gpr(2).state(), 0x5a);
    env.step(|b| sem::stb(b, Gpr(2), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    // lddfa [%g1 + %g0] 0xd0, %f2 — FL8 は 1 バイトをゼロ拡張で
    // 載せる。fd=2 → スロット 1（%d2）。
    let word: u32 = (0b11 << 30) | (2 << 25) | (0b110011 << 19) | (1 << 14) | (0xd0 << 5);
    let insn = dec_v9(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Lddfa);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    assert_eq!(fget_d(&mut env, 2), 0x5a);
}

#[test]
fn v9_ldqfa_rejects_misaligned_field() {
    let mut env = v9_fp_env();
    env.backend.set(Gpr(1).state(), 0x1_0000);
    // fd=2 は q 番号が 4 の倍数にならないので illegal。
    let word: u32 = (0b11 << 30) | (2 << 25) | (0b110010 << 19) | (1 << 14) | (0x80 << 5);
    let insn = dec_v9(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Ldqfa);
    let r = env.step(|b| sem::exec(b, insn, word, 0));
    assert!(r.is_err());
    assert_eq!(env.backend.get(sem::tt_ref()), 0x10);
    // fd=0 は受理される（16 バイトを 2 スロットへ）。
    let word0: u32 = (0b11 << 30) | (0b110010 << 19) | (1 << 14) | (0x80 << 5);
    let insn0 = dec_v9(word0);
    env.step(|b| sem::exec(b, insn0, word0, 0)).unwrap();
}

#[test]
fn v9_ldx_stx_ldsw_full_width() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    env.backend.set(Gpr(1).state(), 0x1_0000);
    env.backend.set(Gpr(2).state(), 0xfedc_ba98_7654_3210);
    env.step(|b| sem::stx(b, Gpr(2), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    env.step(|b| sem::ldx(b, Gpr(3), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0xfedc_ba98_7654_3210);
    // ldsw は 32 ビットを符号拡張する。
    env.step(|b| sem::ldsw(b, Gpr(4), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    assert_eq!(g(&mut env, 4), 0xffff_ffff_fedc_ba98);
}

#[test]
fn v9_ldxa_stxa_use_asi_register() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    // i=1 の形は %asi レジスタを読む。0x80（ASI_P）は非制限。
    env.backend.set(sem::asi_ref(), 0x80);
    env.backend.set(Gpr(1).state(), 0x1_0000);
    env.backend.set(Gpr(2).state(), 0x1122_3344_5566_7788);
    let w: u32 = (0b11 << 30) | (2 << 25) | (0b011110 << 19) | (1 << 14) | (1 << 13);
    let insn = dec_v9(w);
    assert_eq!(insn, polyisa_guest_sparc::Insn::StxaI);
    env.step(|b| sem::exec(b, insn, w, 0)).unwrap();
    let w2: u32 = (0b11 << 30) | (3 << 25) | (0b011011 << 19) | (1 << 14) | (1 << 13);
    let insn2 = dec_v9(w2);
    assert_eq!(insn2, polyisa_guest_sparc::Insn::LdxaI);
    env.step(|b| sem::exec(b, insn2, w2, 0)).unwrap();
    assert_eq!(g(&mut env, 3), 0x1122_3344_5566_7788);
}
