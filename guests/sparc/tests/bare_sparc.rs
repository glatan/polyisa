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
