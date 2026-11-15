// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! A32 の命令意味論の単位テスト。実バイナリの実行で見つけた
//! 振る舞いの回帰を集める。

use polyisa_engine::bare::BareEnv;
use polyisa_guest_arm::sem::{self, Gpr};
use polyisa_sem::Backend;

fn env() -> BareEnv {
    BareEnv::new(core::mem::size_of::<polyisa_guest_arm::CpuState>())
}

#[test]
fn mov_and_bic_write_regs() {
    let mut env = env();
    env.backend.set(Gpr(13).state(), 0xbffe_ef28u32);
    env.backend.set(Gpr(5).state(), 0xdeadu32);
    // mov r0, r5
    env.step(|b| sem::dp_reg(b, 0xe1a0_0005, 0x100)).unwrap();
    let v: u32 = env.backend.get(Gpr(0).state());
    assert_eq!(v, 0xdead);
    // mov r0, sp（sp=r13 の読み出しは通常の汎用レジスタ）
    env.step(|b| sem::dp_reg(b, 0xe1a0_000d, 0x22244)).unwrap();
    let v: u32 = env.backend.get(Gpr(0).state());
    assert_eq!(v, 0xbffe_ef28);
    // bic r12, r0, #15
    env.step(|b| sem::dp_imm(b, 0xe3c0_c00f, 0x22248)).unwrap();
    let v: u32 = env.backend.get(Gpr(12).state());
    assert_eq!(v, 0xbffe_ef20);
    // mov sp, r12
    env.step(|b| sem::dp_reg(b, 0xe1a0_d00c, 0x2224c)).unwrap();
    let v: u32 = env.backend.get(Gpr(13).state());
    assert_eq!(v, 0xbffe_ef20);
}

#[test]
fn rn_rm_pc_reads_as_insn_addr_plus_8() {
    let mut env = env();
    // mov r0, pc。命令アドレス 0x100 での実行なら r0 = 0x108。
    env.step(|b| sem::dp_reg(b, 0xe1a0_000f, 0x100)).unwrap();
    let v: u32 = env.backend.get(Gpr(0).state());
    assert_eq!(v, 0x108);
    // add r1, pc, #4 → 0x208 + 4。PIC の典型的な形。
    env.step(|b| sem::dp_imm(b, 0xe28f_1004, 0x200)).unwrap();
    let v: u32 = env.backend.get(Gpr(1).state());
    assert_eq!(v, 0x20c);
}

/// GE[3:0] の値を CPSR から取り出す。
fn ge(env: &mut BareEnv) -> u32 {
    let c: u32 = env.backend.get(sem::cpsr_ref());
    (c >> 16) & 0xf
}

fn q(env: &mut BareEnv) -> bool {
    let c: u32 = env.backend.get(sem::cpsr_ref());
    c & (1 << 27) != 0
}

#[test]
fn parallel_add16_masks_lanes_and_sets_ge() {
    let mut env = env();
    // sadd16 r0, r1, r2：lo = -1+1 = 0（GE）、hi = 1+1 = 2（GE）。
    env.backend.set(Gpr(1).state(), 0x0001_ffffu32);
    env.backend.set(Gpr(2).state(), 0x0001_0001u32);
    env.step(|b| sem::media(b, 0xe611_0f12, 0)).unwrap();
    let v: u32 = env.backend.get(Gpr(0).state());
    assert_eq!(v, 0x0002_0000);
    assert_eq!(ge(&mut env), 0b1111);

    // lo が負になるとそのレーンの GE が落ちる。0x8000 + 1 = -32767。
    env.backend.set(Gpr(1).state(), 0x0000_8000u32);
    env.backend.set(Gpr(2).state(), 0x0000_0001u32);
    env.step(|b| sem::media(b, 0xe611_0f12, 0)).unwrap();
    let v: u32 = env.backend.get(Gpr(0).state());
    assert_eq!(v, 0x0000_8001);
    assert_eq!(ge(&mut env), 0b1100);
}

#[test]
fn parallel_add8_unsigned_carry_ge() {
    let mut env = env();
    // uadd8 r0, r1, r2：b0/b1/b3 は 0xff+1 で繰り上がり、b2 は 2+1。
    env.backend.set(Gpr(1).state(), 0xff02_ffffu32);
    env.backend.set(Gpr(2).state(), 0x0101_0101u32);
    env.step(|b| sem::media(b, 0xe651_0f92, 0)).unwrap();
    let v: u32 = env.backend.get(Gpr(0).state());
    assert_eq!(v, 0x0003_0000);
    assert_eq!(ge(&mut env), 0b1011);
}

#[test]
fn parallel_halving_signed_unsigned() {
    let mut env = env();
    // shsub16 r0, r1, r2：(4-2)>>1 = 1、(8-2)>>1 = 3。
    env.backend.set(Gpr(1).state(), 0x0004_0008u32);
    env.backend.set(Gpr(2).state(), 0x0002_0002u32);
    env.step(|b| sem::media(b, 0xe631_0f72, 0)).unwrap();
    let v: u32 = env.backend.get(Gpr(0).state());
    assert_eq!(v, 0x0001_0003);
    // uhadd8 r0, r1, r2：(0xff+1)>>1 = 0x80、(0x02+0x04)>>1 = 3。
    env.backend.set(Gpr(1).state(), 0xff02_0000u32);
    env.backend.set(Gpr(2).state(), 0x0104_0000u32);
    env.step(|b| sem::media(b, 0xe671_0f92, 0)).unwrap();
    let v: u32 = env.backend.get(Gpr(0).state());
    assert_eq!(v, 0x8003_0000);
}

#[test]
fn sat16_pair_detection_and_usat_bits() {
    let mut env = env();
    // ssat16 r0, #5, r1：r1 = 0xffff_8000 → lo=0x8000(負→-16)、hi=0xffff(負→-1?)。
    // imm=4 → 範囲は -16..15。hi=0xffff=-1 → そのまま。lo=-32768 → -16=0xfff0。
    env.backend.set(Gpr(1).state(), 0xffff_8000u32);
    env.step(|b| sem::media(b, 0xe6a4_0f31, 0)).unwrap();
    let v: u32 = env.backend.get(Gpr(0).state());
    assert_eq!(v, 0xffff_fff0);
    assert!(q(&mut env));

    // usat16 r0, #5, r1：imm=5 → 0..31。hi=0xffff なら 31、lo=0x8000 なら 31。
    env.backend.set(Gpr(1).state(), 0xffff_8000u32);
    env.step(|b| sem::media(b, 0xe6e5_0f31, 0)).unwrap();
    let v: u32 = env.backend.get(Gpr(0).state());
    assert_eq!(v, 0x001f_001f);
}

#[test]
fn usat32_clamps_to_imm_bits() {
    let mut env = env();
    // usat r0, #8, r1：0..255。負数は 0。
    env.backend.set(Gpr(1).state(), 0xffff_ff80u32);
    env.step(|b| sem::media(b, 0xe6e8_0011, 0)).unwrap();
    let v: u32 = env.backend.get(Gpr(0).state());
    assert_eq!(v, 0);
    assert!(q(&mut env));
    // 0x1ff → 255。
    env.backend.set(Gpr(1).state(), 0x1ffu32);
    env.step(|b| sem::media(b, 0xe6e8_0011, 0)).unwrap();
    let v: u32 = env.backend.get(Gpr(0).state());
    assert_eq!(v, 0xff);
}

#[test]
fn bfi_inserts_field_and_bfc_clears() {
    let mut env = env();
    // bfi r0, r1, #24, #8：r1[7:0] を r0[31:24] へ。
    env.backend.set(Gpr(0).state(), 0x1122_3344u32);
    env.backend.set(Gpr(1).state(), 0xaa55_cc77u32);
    env.step(|b| sem::media(b, 0xe7df_0c11, 0)).unwrap();
    let v: u32 = env.backend.get(Gpr(0).state());
    assert_eq!(v, 0x7722_3344);
    // bfc r0, #4, #8：bits[11:4] をクリア。
    env.backend.set(Gpr(0).state(), 0xffff_ffffu32);
    env.step(|b| sem::media(b, 0xe7cb_021f, 0)).unwrap();
    let v: u32 = env.backend.get(Gpr(0).state());
    assert_eq!(v, 0xffff_f00f);
}

#[test]
fn qsub_subtracts_and_qdsub_double_saturates() {
    let mut env = env();
    // qsub r0, r1, r2：sat(r1 - r2)。0 - 1 = -1（飽和なし）。
    env.backend.set(Gpr(1).state(), 0u32);
    env.backend.set(Gpr(2).state(), 1u32);
    env.step(|b| sem::dp_sreg(b, 0xe122_0051, 0)).unwrap();
    let v: u32 = env.backend.get(Gpr(0).state());
    assert_eq!(v, 0xffff_ffff);
    // INT_MIN - 1 → 0x8000_0000 + Q。
    env.backend.set(Gpr(1).state(), 0x8000_0000u32);
    env.backend.set(Gpr(2).state(), 1u32);
    env.step(|b| sem::dp_sreg(b, 0xe122_0051, 0)).unwrap();
    let v: u32 = env.backend.get(Gpr(0).state());
    assert_eq!(v, 0x8000_0000);
    assert!(q(&mut env));
    // qdsub r0, r1, r2：sat(r1 - sat(2*r2))。r2=0x4000_0000 → 2*r2=INT_MAX…
    // 2*0x4000_0000=0x8000_0000 は正の飽和で 0x7fff_ffff → 0 - 0x7fff_ffff。
    env.backend.set(Gpr(1).state(), 0u32);
    env.backend.set(Gpr(2).state(), 0x4000_0000u32);
    env.step(|b| sem::dp_sreg(b, 0xe162_0051, 0)).unwrap();
    let v: u32 = env.backend.get(Gpr(0).state());
    assert_eq!(v, 0x8000_0001);
    assert!(q(&mut env));
}

#[test]
fn umaal_adds_both_accumulators() {
    let mut env = env();
    // umaal r0, r1, r2, r3：r0:r1 = r2*r3 + r0 + r1。
    env.backend.set(Gpr(0).state(), 5u32);
    env.backend.set(Gpr(1).state(), 7u32);
    env.backend.set(Gpr(2).state(), 0xffff_ffffu32);
    env.backend.set(Gpr(3).state(), 0xffff_ffffu32);
    // 0xffffffff^2 = 0xfffffffe00000001 + 5 + 7 = 0xfffffffe0000000d。
    env.step(|b| sem::mul(b, 0xe041_0392, 0)).unwrap();
    let lo: u32 = env.backend.get(Gpr(0).state());
    let hi: u32 = env.backend.get(Gpr(1).state());
    assert_eq!(lo, 0x0000_000d);
    assert_eq!(hi, 0xffff_fffe);
}

#[test]
fn smulbt_selects_halves_correctly() {
    let mut env = env();
    // smulbt r0, r1, r2：r1[15:0] * r2[31:16] = 3 * 5 = 15。
    env.backend.set(Gpr(1).state(), 0xaaaa_0003u32);
    env.backend.set(Gpr(2).state(), 0x0005_bbbbu32);
    env.step(|b| sem::dp_reg(b, 0xe160_02c1, 0)).unwrap();
    let v: u32 = env.backend.get(Gpr(0).state());
    assert_eq!(v, 15);
    // smlatb r0, r1, r2, r3：r1[31:16] * r2[15:0] + r3 = 4*6 + 1。
    env.backend.set(Gpr(1).state(), 0x0004_0000u32);
    env.backend.set(Gpr(2).state(), 0xcccc_0006u32);
    env.backend.set(Gpr(3).state(), 1u32);
    env.step(|b| sem::dp_reg(b, 0xe100_32a1, 0)).unwrap();
    let v: u32 = env.backend.get(Gpr(0).state());
    assert_eq!(v, 25);
}

#[test]
fn rev16_swaps_bytes_within_halfwords() {
    let mut env = env();
    // rev16 r0, r1：[b3 b2 b1 b0] → [b2 b3 b0 b1]。
    env.backend.set(Gpr(1).state(), 0x1122_3344u32);
    env.step(|b| sem::media(b, 0xe6bf_0fb1, 0)).unwrap();
    let v: u32 = env.backend.get(Gpr(0).state());
    assert_eq!(v, 0x2211_4433);
}

#[test]
fn teq_reg_shift_executes_as_data_processing() {
    let mut env = env();
    // teq r1, r2, lsr r3：misc に落ちずフラグだけ立つ。
    env.backend.set(Gpr(1).state(), 0xf0f0_f0f0u32);
    env.backend.set(Gpr(2).state(), 0xf0f0_f0f0u32);
    env.backend.set(Gpr(3).state(), 0u32);
    env.step(|b| sem::dp_sreg(b, 0xe131_0332, 0)).unwrap();
    let c: u32 = env.backend.get(sem::cpsr_ref());
    // r1 ^ (r2 lsr 0) = 0 → Z=1。
    assert_eq!(c & (1 << 30), 1 << 30);
}
