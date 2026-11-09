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
