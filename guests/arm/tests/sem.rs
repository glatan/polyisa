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
