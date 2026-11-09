// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! x86 最小の命令単位のテスト。裸実行環境で CPU 状態を検査する.
//! 出典は SPEC-X86-INTEL-SDM Combined v093 である.
//! Ref: SPEC-X86-INTEL-SDM (v093).

use polyisa_engine::bare::BareEnv;
use polyisa_guest_x86::CpuState;
use polyisa_guest_x86::sem::{self, Gpr};
use polyisa_sem::Backend as _;

fn env() -> BareEnv {
    BareEnv::new(core::mem::size_of::<CpuState>())
}

fn eax(env: &mut BareEnv) -> u32 {
    env.backend.get(Gpr::eax().state())
}

#[test]
fn nop_keeps_state() {
    let mut env = env();
    env.backend.set(Gpr::eax().state(), 42);
    env.step(sem::nop).unwrap();
    assert_eq!(eax(&mut env), 42);
}

#[test]
fn inc_dec_wraps() {
    let mut env = env();
    env.backend.set(Gpr::eax().state(), 0xffff_ffff);
    env.step(sem::inc_eax).unwrap();
    assert_eq!(eax(&mut env), 0);
    env.step(sem::dec_eax).unwrap();
    assert_eq!(eax(&mut env), 0xffff_ffff);
}

#[test]
fn add_mov_imm() {
    let mut env = env();
    env.step(|b| sem::mov_eax(b, 0x1234_5678)).unwrap();
    assert_eq!(eax(&mut env), 0x1234_5678);
    env.step(|b| sem::add_eax(b, 1)).unwrap();
    assert_eq!(eax(&mut env), 0x1234_5679);
    // 32ビットで包む。
    env.step(|b| sem::mov_eax(b, 0xffff_ffff)).unwrap();
    env.step(|b| sem::add_eax(b, 1)).unwrap();
    assert_eq!(eax(&mut env), 0);
}

#[test]
fn syscall_traps() {
    use polyisa_engine::interp::InterpExit;
    use polyisa_sem::ExceptionKind;
    let r = env_step(|b| sem::syscall(b, 0x1000));
    assert!(matches!(
        r,
        Err(InterpExit::Exception(e)) if e.kind == ExceptionKind::Trap && e.addr == Some(0x1000)
    ));
}

fn env_step<F>(f: F) -> Result<(), polyisa_engine::interp::InterpExit>
where
    F: FnOnce(
        &mut polyisa_engine::interp::InterpBackend,
    ) -> Result<(), polyisa_engine::interp::InterpExit>,
{
    let mut env = env();
    env.step(f)
}

#[test]
fn cpuid_leaf0_returns_vendor() {
    let mut env = env();
    env.backend.set(sem::Gpr(0).state(), 0);
    env.step(sem::cpuid).unwrap();
    assert_eq!(env.backend.get(sem::Gpr(0).state()), 1);
    assert_eq!(env.backend.get(sem::Gpr(3).state()), 0x756e_6547);
    assert_eq!(env.backend.get(sem::Gpr(1).state()), 0x6c65_746e);
    assert_eq!(env.backend.get(sem::Gpr(2).state()), 0x4965_6e69);
    // leaf 1 は試作ではゼロを返す。
    env.backend.set(sem::Gpr(0).state(), 1);
    env.step(sem::cpuid).unwrap();
    assert_eq!(env.backend.get(sem::Gpr(0).state()), 0);
}

#[test]
fn modrm_register_direct() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 35);
    env.step(|b| sem::mov_eax(b, 7)).unwrap();
    // MOV EAX, ECX：EAX=35。
    env.step(sem::mov_rm32).unwrap();
    assert_eq!(eax(&mut env), 35);
    // ADD EAX, ECX：EAX=70。
    env.step(sem::add_rm32).unwrap();
    assert_eq!(eax(&mut env), 70);
}

#[test]
fn mem_load_store_disp8() {
    let mut env = env();
    env.map_rw(0, 1).unwrap();
    // EBX=0x100 を base にし、EAX=0x12345678 を [+0x10] に書いて読む。
    env.backend.set(Gpr(3).state(), 0x100);
    env.backend.set(Gpr(0).state(), 0x1234_5678);
    env.step(|b| sem::mov_mem_eax(b, 0x10)).unwrap();
    env.step(|b| sem::mov_eax_mem(b, 0x10)).unwrap();
    assert_eq!(eax(&mut env), 0x1234_5678);
    // disp8 は符号付き：-1 は base-1 を指す。
    env.backend.set(Gpr(0).state(), 0xAABB_CCDD);
    env.step(|b| sem::mov_mem_eax(b, -1)).unwrap();
    env.step(|b| sem::mov_eax_mem(b, -1)).unwrap();
    assert_eq!(eax(&mut env), 0xAABB_CCDD);
}

#[test]
fn push_pop_roundtrip() {
    let mut env = env();
    env.map_rw(0, 1).unwrap();
    // ESP=0x200 から PUSH EAX (7)。ESP=0x1fc、[0x1fc]=7。
    env.backend.set(Gpr(4).state(), 0x200);
    env.backend.set(Gpr(0).state(), 7);
    env.step(|b| sem::push_reg(b, Gpr(0))).unwrap();
    assert_eq!(env.backend.get(Gpr(4).state()), 0x1fc);
    env.backend.set(Gpr(0).state(), 0);
    env.step(|b| sem::pop_reg(b, Gpr(0))).unwrap();
    assert_eq!(eax(&mut env), 7);
    assert_eq!(env.backend.get(Gpr(4).state()), 0x200);
}

#[test]
fn call_ret_roundtrip() {
    let mut env = env();
    env.map_rw(0, 1).unwrap();
    // CALL rel32: eip=0x1000、disp=0x20 → 戻り 0x1005 を積み、eip=0x1025。
    env.backend.set(Gpr(4).state(), 0x200);
    env.step(|b| sem::call_rel32(b, 0x1000, 0x20)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x1025);
    assert_eq!(env.backend.get(Gpr(4).state()), 0x1fc);
    // RET：eip=0x1005 に戻り、ESP=0x200 に戻る。
    env.step(sem::ret).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x1005);
    assert_eq!(env.backend.get(Gpr(4).state()), 0x200);
}

#[test]
fn cmp_sets_zf_cf() {
    let mut env = env();
    // EAX=5 と 5：ZF=1、CF=0。
    env.backend.set(Gpr(0).state(), 5);
    env.step(|b| sem::cmp_eax(b, 5)).unwrap();
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x40, 0x40);
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x1, 0);
    // EAX=5 と 6：ZF=0、CF=1（符号なしで借り）。
    env.step(|b| sem::cmp_eax(b, 6)).unwrap();
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x40, 0);
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x1, 1);
}

#[test]
fn test_eax_sets_zf() {
    let mut env = env();
    // EAX=0：ZF=1、CF=0。
    env.backend.set(Gpr(0).state(), 0);
    env.step(sem::test_eax).unwrap();
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x40, 0x40);
    // EAX=1：ZF=0、CF=0、EAX 不変。
    env.backend.set(Gpr(0).state(), 1);
    env.step(sem::test_eax).unwrap();
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x40, 0);
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x1, 0);
    assert_eq!(eax(&mut env), 1);
}

#[test]
fn je_jne_branch_on_zf() {
    let mut env = env();
    // ZF=1：JE は飛び、JNE は飛ばない。
    env.backend.set(Gpr(0).state(), 5);
    env.step(|b| sem::cmp_eax(b, 5)).unwrap();
    env.backend.set(sem::eip_ref(), 0x1000);
    env.step(|b| sem::je(b, 0x1000, 0x10)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x1012);
    env.backend.set(sem::eip_ref(), 0x1000);
    env.step(|b| sem::jne(b, 0x1000, 0x10)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x1000);
    // ZF=0：JE は飛ばず、JNE は飛ぶ。
    env.step(|b| sem::cmp_eax(b, 6)).unwrap();
    assert_eq!(eax(&mut env), 5);
    env.backend.set(sem::eip_ref(), 0x1000);
    env.step(|b| sem::je(b, 0x1000, 0x10)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x1000);
    env.step(|b| sem::jne(b, 0x1000, 0x10)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x1012);
}

#[test]
fn loop_counts_down() {
    let mut env = env();
    // ECX=3 から LOOP -2 を回す：3→2→1→0 で抜ける。
    env.backend.set(Gpr(1).state(), 3);
    env.backend.set(sem::eip_ref(), 0x1000);
    env.step(|b| sem::loop_rel8(b, 0x1000, -2)).unwrap();
    assert_eq!(env.backend.get(Gpr(1).state()), 2);
    env.step(|b| sem::loop_rel8(b, 0x1000, -2)).unwrap();
    assert_eq!(env.backend.get(Gpr(1).state()), 1);
    env.step(|b| sem::loop_rel8(b, 0x1000, -2)).unwrap();
    assert_eq!(env.backend.get(Gpr(1).state()), 0);
    assert_eq!(env.backend.get(sem::eip_ref()), 0x1000);
    // taken：ECX=2、disp=+0x10 → eip=0x1012。
    env.backend.set(Gpr(1).state(), 2);
    env.backend.set(sem::eip_ref(), 0x1000);
    env.step(|b| sem::loop_rel8(b, 0x1000, 0x10)).unwrap();
    assert_eq!(env.backend.get(Gpr(1).state()), 1);
    assert_eq!(env.backend.get(sem::eip_ref()), 0x1012);
}

#[test]
fn jmp_rel32_jumps() {
    let mut env = env();
    env.backend.set(sem::eip_ref(), 0x1000);
    env.step(|b| sem::jmp_rel32(b, 0x1000, 0x100)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x1105);
}

#[test]
fn jmp_sets_eip() {
    let mut env = env();
    env.backend.set(sem::eip_ref(), 0x1000);
    env.step(|b| sem::jmp8(b, 0x2000)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x2000);
}

#[test]
fn varlen_decode_lengths() {
    // 可変長：8/16/40ビットの入口で分かれることは lib の decode テストで確認する。
    // ここでは意味論が長さによらず動くことを確認する。
    let mut env = env();
    env.step(|b| sem::mov_eax(b, 7)).unwrap();
    env.step(sem::inc_eax).unwrap();
    assert_eq!(eax(&mut env), 8);
}
