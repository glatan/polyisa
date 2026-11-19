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
fn v9_alu32_sign_extends_result() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    // V9 の 32 ビット演算は結果を符号拡張して rd に書く。
    env.backend.set(Gpr(1).state(), 0xffff_ffff_ffff_ffff);
    env.step(|b| sem::add(b, Gpr(2), Gpr(1), Src2::Imm(1)))
        .unwrap();
    assert_eq!(g(&mut env, 2), 0);
    env.backend.set(Gpr(1).state(), 0x7fff_ffff);
    env.step(|b| sem::add(b, Gpr(2), Gpr(1), Src2::Imm(1)))
        .unwrap();
    assert_eq!(g(&mut env, 2), 0xffff_ffff_8000_0000);
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
    env.backend.set(Gpr(2).state(), 0xaaaa_bbbb); // 比較値
    env.backend.set(Gpr(3).state(), 0x1111_2222); // 新値
    env.step(|b| sem::st(b, Gpr(2), Gpr(1), Src2::Reg(Gpr(0))))
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
    env.backend.set(Gpr(2).state(), 0xdead_beef);
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
    env.backend.set(Gpr(2).state(), 0x0123_4567_89ab_cdef);
    env.backend.set(Gpr(3).state(), 0xdead_beef_cafe_f00d);
    // メモリを st 2 発で用意する（ldx/stx は未実装）。
    env.backend.set(Gpr(4).state(), 0x0123_4567);
    env.step(|b| sem::st(b, Gpr(4), Gpr(1), Src2::Reg(Gpr(0))))
        .unwrap();
    env.backend.set(Gpr(4).state(), 0x89ab_cdef);
    env.step(|b| sem::st(b, Gpr(4), Gpr(1), Src2::Imm(4)))
        .unwrap();
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
    // flushw も本モデルでは no-op。
    let fw: u32 = (0b10 << 30) | (0b101011 << 19);
    let insn2 = dec_v9(fw);
    assert_eq!(insn2, polyisa_guest_sparc::Insn::Flushw);
    env.step(|b| sem::exec(b, insn2, fw, 0)).unwrap();
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
    env.backend.set(Fpr(1).state(), 0x3fc0_0000); // 1.5f
    env.backend.set(Fpr(2).state(), 0x4010_0000); // 2.25f
    let word: u32 = (0b10 << 30) | (3 << 25) | (0b110100 << 19) | (1 << 14) | (0x41 << 5) | 2;
    env.step(|b| sem::exec(b, dec_v8(word), word, 0)).unwrap();
    // 3.75f。
    assert_eq!(env.backend.get(Fpr(3).state()), 0x4070_0000);
}

#[test]
fn fcmpd_writes_fcc() {
    let mut env = fp_env();
    // %d2 = 1.0（f2 が上位）、%d4 = 2.0。2.0 > 1.0 なので lt=1。
    env.backend.set(Fpr(2).state(), 0x3ff0_0000);
    env.backend.set(Fpr(4).state(), 0x4000_0000);
    let word: u32 = (0b10 << 30) | (0b110101 << 19) | (2 << 14) | (0x52 << 5) | 4;
    env.step(|b| sem::exec(b, dec_v8(word), word, 0)).unwrap();
    assert_eq!(env.backend.get(sem::fsr_ref()) & (0b11 << 10), 1 << 10);
}

#[test]
fn fp_conversions() {
    let mut env = fp_env();
    // fstoi %f2(-1.5f), %f3 → -1。
    env.backend.set(Fpr(2).state(), 0xbfc0_0000);
    let word: u32 = (0b10 << 30) | (3 << 25) | (0b110100 << 19) | (0xd1 << 5) | 2;
    env.step(|b| sem::exec(b, dec_v8(word), word, 0)).unwrap();
    assert_eq!(env.backend.get(Fpr(3).state()), (-1i32) as u32 as u64);
    // fitos %f4(42), %f5 → 42.0f。
    env.backend.set(Fpr(4).state(), 42);
    let word2: u32 = (0b10 << 30) | (5 << 25) | (0b110100 << 19) | (0xc4 << 5) | 4;
    env.step(|b| sem::exec(b, dec_v8(word2), word2, 0)).unwrap();
    assert_eq!(env.backend.get(Fpr(5).state()), 0x4228_0000);
}

#[test]
fn ldf_stf_roundtrip() {
    let mut env = fp_env();
    env.backend.set(Gpr(1).state(), 0x1_0000);
    env.backend.set(Fpr(1).state(), 0xdead_beef);
    // stf %f1, [%g1 + 0]。
    let word: u32 = (0b11 << 30) | (1 << 25) | (0b100100 << 19) | (1 << 14) | (1 << 13);
    env.step(|b| sem::exec(b, dec_v8(word), word, 0)).unwrap();
    // ldf [%g1 + 0], %f5。
    let word2: u32 = (0b11 << 30) | (5 << 25) | (0b100000 << 19) | (1 << 14) | (1 << 13);
    env.step(|b| sem::exec(b, dec_v8(word2), word2, 0)).unwrap();
    assert_eq!(env.backend.get(Fpr(5).state()), 0xdead_beef);
}

#[test]
fn v9_fmovscc_moves_on_icc() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    env.backend.set(sem::tstate_ref(), 1 << 12); // PSTATE.PEF
    env.backend.set(sem::ccr_ref(), 0b0100); // icc.z=1
    env.backend.set(Fpr(5).state(), 0xdead_beef);
    // fmovscc %icc, e(cond=1), %f5, %f3。bit18=0, bit13=1, cc=0。
    let word: u32 =
        (0b10 << 30) | (3 << 25) | (0b110101 << 19) | (1 << 14) | (1 << 13) | (1 << 5) | 5;
    let insn = dec_v9(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Fmovscc);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    assert_eq!(env.backend.get(Fpr(3).state()), 0xdead_beef);
}

#[test]
fn v9_fcmp_selects_fccn() {
    let mut env = env();
    env.backend.set_param::<polyisa_guest_sparc::Word64Param>(1);
    env.backend.set(sem::tstate_ref(), 1 << 12); // PSTATE.PEF
    env.backend.set(Fpr(2).state(), 0x4000_0000); // 2.0f
    env.backend.set(Fpr(4).state(), 0x3f80_0000); // 1.0f
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
    env.backend.set(Fpr(2).state(), 0xbfc0_0000); // -1.5f
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    // -1 を 64 ビットで %d4 に書く（f4=上位, f5=下位）。
    assert_eq!(env.backend.get(Fpr(4).state()), 0xffff_ffff);
    assert_eq!(env.backend.get(Fpr(5).state()), 0xffff_ffff);
}

#[test]
fn v9_odd_d_field_is_illegal() {
    let mut env = v9_fp_env();
    env.backend.set(Gpr(1).state(), 0x1_0000);
    // lddf [%g1 + 0], %f31 — フィールド 31 は上位バンク %d62（未モデル）。
    let word: u32 = (0b11 << 30) | (31 << 25) | (0b100011 << 19) | (1 << 14) | (1 << 13);
    let insn = dec_v9(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::LddfI);
    let r = env.step(|b| sem::exec(b, insn, word, 0));
    assert!(r.is_err());
    // f[32] 相当（pc のオフセット）に書き込まれていないこと。
    assert_eq!(env.backend.get(sem::pc_ref()), 0);
}

#[test]
fn v8_odd_d_field_aligns_to_even() {
    let mut env = fp_env();
    env.backend.set(Fpr(2).state(), 0x3ff0_0000); // %d2 = 1.0
    env.backend.set(Fpr(4).state(), 0x4000_0000); // %d4 = 2.0
    // faddd %d2, %d4, %d31 → V8 では %d30 に畳む。
    let word: u32 = (0b10 << 30) | (31 << 25) | (0b110100 << 19) | (2 << 14) | (0x42 << 5) | 4;
    let insn = dec_v8(word);
    assert_eq!(insn, polyisa_guest_sparc::Insn::Faddd);
    env.step(|b| sem::exec(b, insn, word, 0)).unwrap();
    // 3.0 = 0x40080000_00000000。
    assert_eq!(env.backend.get(Fpr(30).state()), 0x4008_0000);
    assert_eq!(env.backend.get(Fpr(31).state()), 0);
}

#[test]
fn v9_ldfsr_preserves_fcc1_3() {
    let mut env = v9_fp_env();
    env.backend.set(Gpr(1).state(), 0x1_0000);
    // fcc1 = gt（2）を FSR bit32-33 に置く。
    env.backend.set(sem::fsr_ref(), 2u64 << 32);
    // stf でメモリに 0x0000_0c00（fcc0=3 だけの値）を置く。
    env.backend.set(Fpr(6).state(), 0x0000_0c00);
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
