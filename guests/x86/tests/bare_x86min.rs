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
fn int80_traps_with_vector() {
    use polyisa_engine::interp::InterpExit;
    use polyisa_sem::ExceptionKind;
    let r = env_step(|b| sem::int80(b, 0x1000));
    assert!(matches!(
        r,
        Err(InterpExit::Exception(e)) if e.kind == ExceptionKind::Trap && e.code == 0x80 && e.addr == Some(0x1000)
    ));
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
    env.step(|b| sem::mov_rm32(b, Gpr(0), Gpr(1))).unwrap();
    assert_eq!(eax(&mut env), 35);
    // ADD EAX, ECX：EAX=70。
    env.step(|b| sem::add_rm32(b, Gpr(0), Gpr(1))).unwrap();
    assert_eq!(eax(&mut env), 70);
}

#[test]
fn regreg_matrix_roundtrip() {
    // register-direct 全組合せの行列：高レジスタを含む dst/src で往復する。
    // MOV r32,r/m32 (dst=reg)：ESI→EDI。
    let mut env = env();
    env.backend.set(Gpr(6).state(), 0x1234_5678);
    env.step(|b| sem::mov_rm32(b, Gpr(7), Gpr(6))).unwrap();
    assert_eq!(env.backend.get(Gpr(7).state()), 0x1234_5678);
    // MOV r/m32,r32 (dst=rm)：EBX→EBP。
    env.backend.set(Gpr(3).state(), 0x1111_2222);
    env.step(|b| sem::mov_mr32(b, Gpr(5), Gpr(3))).unwrap();
    assert_eq!(env.backend.get(Gpr(5).state()), 0x1111_2222);
    // ADD EDX,ESI：0x100+0x20=0x120。
    env.backend.set(Gpr(2).state(), 0x100);
    env.backend.set(Gpr(6).state(), 0x20);
    env.step(|b| sem::add_rm32(b, Gpr(2), Gpr(6))).unwrap();
    assert_eq!(env.backend.get(Gpr(2).state()), 0x120);
    // SUB EDI,EBX：0x120-0x20=0x100、ZF=0。
    env.backend.set(Gpr(7).state(), 0x120);
    env.backend.set(Gpr(3).state(), 0x20);
    env.step(|b| sem::sub_rm32(b, Gpr(7), Gpr(3))).unwrap();
    assert_eq!(env.backend.get(Gpr(7).state()), 0x100);
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x40, 0);
    // SUB で同値引き：ZF=1。
    env.step(|b| sem::sub_rm32(b, Gpr(7), Gpr(7))).unwrap();
    assert_eq!(env.backend.get(Gpr(7).state()), 0);
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x40, 0x40);
    // XOR ECX,ECX：ゼロ化イディオムの汎用形。
    env.backend.set(Gpr(1).state(), 0xDEAD_BEEF);
    env.step(|b| sem::xor_rm32(b, Gpr(1), Gpr(1))).unwrap();
    assert_eq!(env.backend.get(Gpr(1).state()), 0);
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x40, 0x40);
    // XOR ESI,EDI：0xff ^ 0xf0 = 0x0f。
    env.backend.set(Gpr(6).state(), 0xff);
    env.backend.set(Gpr(7).state(), 0xf0);
    env.step(|b| sem::xor_rm32(b, Gpr(6), Gpr(7))).unwrap();
    assert_eq!(env.backend.get(Gpr(6).state()), 0x0f);
    // AND/OR の高レジスタ組合せ。
    env.backend.set(Gpr(6).state(), 0b1100);
    env.backend.set(Gpr(7).state(), 0b1010);
    env.step(|b| sem::and_rm32(b, Gpr(6), Gpr(7))).unwrap();
    assert_eq!(env.backend.get(Gpr(6).state()), 0b1000);
    env.backend.set(Gpr(6).state(), 0b1100);
    env.step(|b| sem::or_rm32(b, Gpr(6), Gpr(7))).unwrap();
    assert_eq!(env.backend.get(Gpr(6).state()), 0b1110);
    // CMP ESI,EDI：比較のみで dst 不変。
    env.backend.set(Gpr(6).state(), 7);
    env.backend.set(Gpr(7).state(), 7);
    env.step(|b| sem::cmp_rm32(b, Gpr(6), Gpr(7))).unwrap();
    assert_eq!(env.backend.get(Gpr(6).state()), 7);
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x40, 0x40);
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
fn mem_load_store_no_disp() {
    // mod=00 [EBX]：disp なしの最小形。
    let mut env = env();
    env.map_rw(0, 1).unwrap();
    env.backend.set(Gpr(3).state(), 0x100);
    env.backend.set(Gpr(0).state(), 0xDEAD_BEEF);
    env.step(sem::mov_memnd_eax).unwrap();
    env.backend.set(Gpr(0).state(), 0);
    env.step(sem::mov_eax_memnd).unwrap();
    assert_eq!(eax(&mut env), 0xDEAD_BEEF);
}

#[test]
fn mem_load_store_disp32() {
    let mut env = env();
    env.map_rw(0, 1).unwrap();
    // EBX=0x100 を base にし、EAX=0x12345678 を [+0x20] に書いて読む。
    env.backend.set(Gpr(3).state(), 0x100);
    env.backend.set(Gpr(0).state(), 0x1234_5678);
    env.step(|b| sem::mov_memd32_eax(b, 0x20)).unwrap();
    env.backend.set(Gpr(0).state(), 0);
    env.step(|b| sem::mov_eax_memd32(b, 0x20)).unwrap();
    assert_eq!(eax(&mut env), 0x1234_5678);
    // disp32 は符号付き：-1 は base-1 を指す。
    env.backend.set(Gpr(0).state(), 0xAABB_CCDD);
    env.step(|b| sem::mov_memd32_eax(b, -1)).unwrap();
    env.backend.set(Gpr(0).state(), 0);
    env.step(|b| sem::mov_eax_memd32(b, -1)).unwrap();
    assert_eq!(eax(&mut env), 0xAABB_CCDD);
}

#[test]
fn mem_load_store_absolute() {
    let mut env = env();
    env.map_rw(0, 1).unwrap();
    // 絶対番地 [0x200] に EAX=0x55AA55AA を書いて読む。
    env.backend.set(Gpr(0).state(), 0x55AA_55AA);
    env.step(|b| sem::mov_abs_eax(b, 0x200)).unwrap();
    env.backend.set(Gpr(0).state(), 0);
    env.step(|b| sem::mov_eax_abs(b, 0x200)).unwrap();
    assert_eq!(eax(&mut env), 0x55AA_55AA);
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
fn xor_zeroes_and_sets_zf() {
    let mut env = env();
    env.backend.set(Gpr(0).state(), 0x1234_5678);
    env.step(|b| sem::xor_rm32(b, Gpr(0), Gpr(0))).unwrap();
    assert_eq!(eax(&mut env), 0);
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x40, 0x40);
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x1, 0);
}

#[test]
fn sub_wraps_and_sets_flags() {
    let mut env = env();
    // 5 - 5 = 0：ZF=1、CF=0。
    env.backend.set(Gpr(0).state(), 5);
    env.step(|b| sem::sub_eax(b, 5)).unwrap();
    assert_eq!(eax(&mut env), 0);
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x40, 0x40);
    // 5 - 6：0xffffffff、CF=1。
    env.backend.set(Gpr(0).state(), 5);
    env.step(|b| sem::sub_eax(b, 6)).unwrap();
    assert_eq!(eax(&mut env), 0xffff_ffff);
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x40, 0);
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x1, 1);
}

#[test]
fn flags_add_overflow() {
    let mut env = env();
    // 0x7fffffff + 1 = 0x80000000：OF=SF=AF=PF=1、CF=ZF=0。
    env.backend.set(Gpr(0).state(), 0x7FFF_FFFF);
    env.step(|b| sem::add_eax(b, 1)).unwrap();
    assert_eq!(eax(&mut env), 0x8000_0000);
    assert_eq!(env.backend.get(sem::eflags_ref()), 0x894);
    // 0xffffffff + 1 = 0：CF=ZF=AF=PF=1、SF=OF=0。
    env.backend.set(Gpr(0).state(), 0xFFFF_FFFF);
    env.step(|b| sem::add_eax(b, 1)).unwrap();
    assert_eq!(eax(&mut env), 0);
    assert_eq!(env.backend.get(sem::eflags_ref()), 0x55);
    // 0 - 1 = 0xffffffff：CF=PF=AF=SF=1、ZF=OF=0。
    env.backend.set(Gpr(0).state(), 0);
    env.step(|b| sem::sub_eax(b, 1)).unwrap();
    assert_eq!(eax(&mut env), 0xFFFF_FFFF);
    assert_eq!(env.backend.get(sem::eflags_ref()), 0x95);
}

#[test]
fn flags_logic_clears_cf_of() {
    let mut env = env();
    // 先に ADD で OF=1 にしてから AND で消えることを見る。
    env.backend.set(Gpr(0).state(), 0x7FFF_FFFF);
    env.step(|b| sem::add_eax(b, 1)).unwrap();
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x800, 0x800);
    env.backend.set(Gpr(0).state(), 0xF0);
    env.backend.set(Gpr(1).state(), 0x0F);
    env.step(|b| sem::and_rm32(b, Gpr(0), Gpr(1))).unwrap();
    assert_eq!(eax(&mut env), 0);
    // ZF=PF=1、CF=OF=SF=0。AF は ADD 時の 1 が保存される。
    assert_eq!(env.backend.get(sem::eflags_ref()), 0x54);
}

#[test]
fn flags_inc_dec_preserve_cf() {
    let mut env = env();
    // SUB で CF=1 にしてから INC。EAX=0xffffffff→0。
    env.backend.set(Gpr(0).state(), 0);
    env.step(|b| sem::sub_eax(b, 1)).unwrap();
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x1, 1);
    env.step(|b| sem::inc_r32(b, Gpr(0))).unwrap();
    assert_eq!(eax(&mut env), 0);
    // ZF=PF=AF=1、CF=1（保存）、SF=OF=0。
    assert_eq!(env.backend.get(sem::eflags_ref()), 0x55);
    // DEC で CF 保存：EAX=1→0、CF=1 のまま ZF=1。
    env.backend.set(Gpr(0).state(), 1);
    env.step(|b| sem::dec_r32(b, Gpr(0))).unwrap();
    assert_eq!(eax(&mut env), 0);
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x1, 1);
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x40, 0x40);
}

#[test]
fn flags_shift() {
    let mut env = env();
    // 0x40000000 << 1：CF=0、OF=1、SF=PF=1。
    env.backend.set(sem::eflags_ref(), 0);
    env.backend.set(Gpr(0).state(), 0x4000_0000);
    env.step(|b| sem::shl_eax(b, 1)).unwrap();
    assert_eq!(eax(&mut env), 0x8000_0000);
    assert_eq!(env.backend.get(sem::eflags_ref()), 0x884);
    // 0x80000001 >> 1：CF=1、OF=1（旧最上位）、SF=0、PF=1。
    env.backend.set(sem::eflags_ref(), 0);
    env.backend.set(Gpr(0).state(), 0x8000_0001);
    env.step(|b| sem::shr_eax(b, 1)).unwrap();
    assert_eq!(eax(&mut env), 0x4000_0000);
    assert_eq!(env.backend.get(sem::eflags_ref()), 0x805);
    // カウント 0 は結果も旗も変えない。
    env.backend.set(Gpr(0).state(), 5);
    env.backend.set(sem::eflags_ref(), 0x1234);
    env.step(|b| sem::shl_eax(b, 32)).unwrap();
    assert_eq!(eax(&mut env), 5);
    assert_eq!(env.backend.get(sem::eflags_ref()), 0x1234);
}

#[test]
fn and_or_xor_imm() {
    let mut env = env();
    // 0b1100 & 0b1010 = 0b1000。ZF=0、CF=0。
    env.backend.set(Gpr(0).state(), 0b1100);
    env.step(|b| sem::and_eax(b, 0b1010)).unwrap();
    assert_eq!(eax(&mut env), 0b1000);
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x40, 0);
    // 0 | 0 = 0。ZF=1。
    env.backend.set(Gpr(0).state(), 0);
    env.step(|b| sem::or_eax(b, 0)).unwrap();
    assert_eq!(eax(&mut env), 0);
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x40, 0x40);
    // 0xff ^ 0xff = 0。ZF=1。
    env.backend.set(Gpr(0).state(), 0xff);
    env.step(|b| sem::xor_imm(b, 0xff)).unwrap();
    assert_eq!(eax(&mut env), 0);
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x40, 0x40);
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x1, 0);
}

#[test]
fn shifts_mask_count() {
    let mut env = env();
    // 1 << 31 = 0x80000000。
    env.backend.set(Gpr(0).state(), 1);
    env.step(|b| sem::shl_eax(b, 31)).unwrap();
    assert_eq!(eax(&mut env), 0x8000_0000);
    // 0x80000000 >> 1 = 0x40000000（論理）。
    env.step(|b| sem::shr_eax(b, 1)).unwrap();
    assert_eq!(eax(&mut env), 0x4000_0000);
    // カウントは下位5ビット：33 は 1 と同じ。
    env.backend.set(Gpr(0).state(), 1);
    env.step(|b| sem::shl_eax(b, 33)).unwrap();
    assert_eq!(eax(&mut env), 2);
}

#[test]
fn lea_and_reg_logic() {
    let mut env = env();
    // LEA EAX,[EBX+disp8]：メモリに触れず EBX+0x10。
    env.backend.set(Gpr(3).state(), 0x100);
    env.step(|b| sem::lea_m8(b, Gpr(0), 0x10)).unwrap();
    assert_eq!(eax(&mut env), 0x110);
    // disp=-1：0xFF。
    env.step(|b| sem::lea_m8(b, Gpr(0), -1)).unwrap();
    assert_eq!(eax(&mut env), 0xFF);
    // CMP EAX,ECX：5 vs 5 で ZF=1、CF=0。EAX 不変。
    env.backend.set(Gpr(0).state(), 5);
    env.backend.set(Gpr(1).state(), 5);
    env.step(|b| sem::cmp_rm32(b, Gpr(0), Gpr(1))).unwrap();
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x40, 0x40);
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x1, 0);
    assert_eq!(eax(&mut env), 5);
    // 4 vs 5 で ZF=0、CF=1。
    env.backend.set(Gpr(0).state(), 4);
    env.step(|b| sem::cmp_rm32(b, Gpr(0), Gpr(1))).unwrap();
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x40, 0);
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x1, 1);
    // AND EAX,ECX：0b1100 & 0b1010 = 0b1000、ZF=0、CF=0。
    env.backend.set(Gpr(0).state(), 0b1100);
    env.backend.set(Gpr(1).state(), 0b1010);
    env.step(|b| sem::and_rm32(b, Gpr(0), Gpr(1))).unwrap();
    assert_eq!(eax(&mut env), 0b1000);
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x40, 0);
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x1, 0);
    // OR EAX,ECX：0 | 0xff = 0xff、ZF=0。LEA は EFLAGS を変えない。
    env.backend.set(Gpr(3).state(), 0x100);
    env.backend.set(sem::eflags_ref(), 0);
    env.step(|b| sem::lea_m8(b, Gpr(0), 0x10)).unwrap();
    assert_eq!(eax(&mut env), 0x110);
    assert_eq!(env.backend.get(sem::eflags_ref()), 0);
    env.backend.set(Gpr(0).state(), 0);
    env.backend.set(Gpr(1).state(), 0xff);
    env.step(|b| sem::or_rm32(b, Gpr(0), Gpr(1))).unwrap();
    assert_eq!(eax(&mut env), 0xff);
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x40, 0);
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x1, 0);
}

#[test]
fn lea_matrix() {
    // LEA 全番地形の行列：dst 任意、メモリに触れない。
    let mut env = env();
    env.map_rw(0, 1).unwrap();
    // EBX=0x100、ESI=0x10。dst=ECX に入れる。
    env.backend.set(Gpr(3).state(), 0x100);
    env.backend.set(Gpr(6).state(), 0x10);
    env.step(|b| sem::lea_m8(b, Gpr(1), 0x10)).unwrap();
    assert_eq!(env.backend.get(Gpr(1).state()), 0x110);
    env.step(|b| sem::lea_m32(b, Gpr(1), 0x20)).unwrap();
    assert_eq!(env.backend.get(Gpr(1).state()), 0x120);
    env.step(|b| sem::lea_abs(b, Gpr(1), 0x300)).unwrap();
    assert_eq!(env.backend.get(Gpr(1).state()), 0x300);
    env.step(|b| sem::lea_sib(b, Gpr(1))).unwrap();
    assert_eq!(env.backend.get(Gpr(1).state()), 0x110);
    env.step(|b| sem::lea_sibd(b, Gpr(1), 0x10)).unwrap();
    assert_eq!(env.backend.get(Gpr(1).state()), 0x120);
    // スケール付き：*4 で [0x140+disp]。
    env.step(|b| sem::lea_sib_s4(b, Gpr(1), 0x10)).unwrap();
    assert_eq!(env.backend.get(Gpr(1).state()), 0x150);
    env.step(|b| sem::lea_sib_s4nd(b, Gpr(1))).unwrap();
    assert_eq!(env.backend.get(Gpr(1).state()), 0x140);
    env.step(|b| sem::lea_sib_s4d32(b, Gpr(1), 0x20)).unwrap();
    assert_eq!(env.backend.get(Gpr(1).state()), 0x160);
    env.step(|b| sem::lea_sib_s4a32(b, Gpr(1), 0x200)).unwrap();
    assert_eq!(env.backend.get(Gpr(1).state()), 0x240);
    // *2/*8 の代表：disp なし。
    env.step(|b| sem::lea_sib_s2nd(b, Gpr(2))).unwrap();
    assert_eq!(env.backend.get(Gpr(2).state()), 0x120);
    env.step(|b| sem::lea_sib_s8nd(b, Gpr(2))).unwrap();
    assert_eq!(env.backend.get(Gpr(2).state()), 0x180);
}

#[test]
fn frame_setup_and_leave() {
    let mut env = env();
    env.map_rw(0, 1).unwrap();
    // 正規の関数枠：PUSH EBP; MOV EBP,ESP; ...; LEAVE。
    env.backend.set(Gpr(4).state(), 0x300);
    env.backend.set(Gpr(5).state(), 0xAAAA_BBBB);
    env.step(|b| sem::push_reg(b, Gpr(5))).unwrap();
    assert_eq!(env.backend.get(Gpr(4).state()), 0x2fc);
    env.step(|b| sem::mov_mr32(b, Gpr(5), Gpr(4))).unwrap();
    assert_eq!(env.backend.get(Gpr(5).state()), 0x2fc);
    // ローカル代わりに PUSH EAX。
    env.backend.set(Gpr(0).state(), 0x1111_2222);
    env.step(|b| sem::push_reg(b, Gpr(0))).unwrap();
    assert_eq!(env.backend.get(Gpr(4).state()), 0x2f8);
    // LEAVE：ESP=EBP に戻し、POP EBP で復帰。
    env.step(sem::leave).unwrap();
    assert_eq!(env.backend.get(Gpr(5).state()), 0xAAAA_BBBB);
    assert_eq!(env.backend.get(Gpr(4).state()), 0x300);
}

#[test]
fn callee_saved_prologue_epilogue() {
    let mut env = env();
    env.map_rw(0, 1).unwrap();
    // 正規のプロローグ：PUSH EBP; MOV EBP,ESP; PUSH EBX/ESI/EDI。
    env.backend.set(Gpr(4).state(), 0x400);
    env.backend.set(Gpr(5).state(), 0xAAAA);
    env.backend.set(Gpr(3).state(), 0xBBBB);
    env.backend.set(Gpr(6).state(), 0xCCCC);
    env.backend.set(Gpr(7).state(), 0xDDDD);
    env.step(|b| sem::push_reg(b, Gpr(5))).unwrap();
    env.step(|b| sem::mov_mr32(b, Gpr(5), Gpr(4))).unwrap();
    env.step(|b| sem::push_reg(b, Gpr(3))).unwrap();
    env.step(|b| sem::push_reg(b, Gpr(6))).unwrap();
    env.step(|b| sem::push_reg(b, Gpr(7))).unwrap();
    assert_eq!(env.backend.get(Gpr(4).state()), 0x3f0);
    // 作業中にレジスタを壊す。
    env.backend.set(Gpr(3).state(), 0);
    env.backend.set(Gpr(6).state(), 0);
    env.backend.set(Gpr(7).state(), 0);
    // エピローグ：POP EDI/ESI/EBX; LEAVE。
    env.step(|b| sem::pop_reg(b, Gpr(7))).unwrap();
    env.step(|b| sem::pop_reg(b, Gpr(6))).unwrap();
    env.step(|b| sem::pop_reg(b, Gpr(3))).unwrap();
    env.step(sem::leave).unwrap();
    assert_eq!(env.backend.get(Gpr(3).state()), 0xBBBB);
    assert_eq!(env.backend.get(Gpr(6).state()), 0xCCCC);
    assert_eq!(env.backend.get(Gpr(7).state()), 0xDDDD);
    assert_eq!(env.backend.get(Gpr(5).state()), 0xAAAA);
    assert_eq!(env.backend.get(Gpr(4).state()), 0x400);
}

#[test]
fn inc_dec_all_regs() {
    let mut env = env();
    // ECX/EDX/EBX/ESP/EBP/ESI/EDI を回す。DEC 0 は 0xffffffff に包む。
    for (r, start) in [
        (1u8, 10u32),
        (2, 20),
        (3, 30),
        (4, 0x100),
        (5, 50),
        (6, 60),
        (7, 70),
    ] {
        env.backend.set(Gpr(r).state(), start);
        env.step(|b| sem::inc_r32(b, Gpr(r))).unwrap();
        assert_eq!(env.backend.get(Gpr(r).state()), start.wrapping_add(1));
        env.step(|b| sem::dec_r32(b, Gpr(r))).unwrap();
        env.step(|b| sem::dec_r32(b, Gpr(r))).unwrap();
        assert_eq!(env.backend.get(Gpr(r).state()), start.wrapping_sub(1));
    }
    env.backend.set(Gpr(2).state(), 0);
    env.step(|b| sem::dec_r32(b, Gpr(2))).unwrap();
    assert_eq!(env.backend.get(Gpr(2).state()), 0xffff_ffff);
}

#[test]
fn pop_esp_takes_popped_value() {
    let mut env = env();
    env.map_rw(0, 1).unwrap();
    // [0x100] に置いた値を POP ESP で取り出す。ESP は old+4 ではなく取り出し値になる。
    env.backend.set(Gpr(4).state(), 0x100);
    env.backend.set(Gpr(0).state(), 0x1234_5678);
    env.step(|b| sem::push_reg(b, Gpr(0))).unwrap();
    assert_eq!(env.backend.get(Gpr(4).state()), 0xfc);
    env.backend.set(Gpr(0).state(), 0);
    env.step(|b| sem::pop_reg(b, Gpr(4))).unwrap();
    assert_eq!(env.backend.get(Gpr(4).state()), 0x1234_5678);
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
fn unsigned_branches() {
    let mut env = env();
    // 4 vs 5：CF=1、ZF=0。JB/JBE は飛び、JAE/JA は飛ばない。
    env.backend.set(Gpr(0).state(), 4);
    env.backend.set(Gpr(1).state(), 5);
    env.step(|b| sem::cmp_rm32(b, Gpr(0), Gpr(1))).unwrap();
    env.backend.set(sem::eip_ref(), 0x1000);
    env.step(|b| sem::jb(b, 0x1000, 0x10)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x1012);
    env.backend.set(sem::eip_ref(), 0x1000);
    env.step(|b| sem::jbe(b, 0x1000, 0x10)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x1012);
    env.backend.set(sem::eip_ref(), 0x1000);
    env.step(|b| sem::jae(b, 0x1000, 0x10)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x1000);
    env.backend.set(sem::eip_ref(), 0x1000);
    env.step(|b| sem::ja(b, 0x1000, 0x10)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x1000);
    // 5 vs 5：ZF=1、CF=0。JBE/JAE は飛び、JB/JA は飛ばない。
    env.backend.set(Gpr(0).state(), 5);
    env.step(|b| sem::cmp_eax(b, 5)).unwrap();
    env.backend.set(sem::eip_ref(), 0x2000);
    env.step(|b| sem::jbe(b, 0x2000, 0x10)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x2012);
    env.backend.set(sem::eip_ref(), 0x2000);
    env.step(|b| sem::jae(b, 0x2000, 0x10)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x2012);
    env.backend.set(sem::eip_ref(), 0x2000);
    env.step(|b| sem::jb(b, 0x2000, 0x10)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x2000);
    env.backend.set(sem::eip_ref(), 0x2000);
    env.step(|b| sem::ja(b, 0x2000, 0x10)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x2000);
    // 6 vs 5：CF=0、ZF=0。JA/JAE は飛び、JB/JBE は飛ばない。
    env.backend.set(Gpr(0).state(), 6);
    env.step(|b| sem::cmp_rm32(b, Gpr(0), Gpr(1))).unwrap();
    env.backend.set(sem::eip_ref(), 0x3000);
    env.step(|b| sem::ja(b, 0x3000, 0x10)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x3012);
    env.backend.set(sem::eip_ref(), 0x3000);
    env.step(|b| sem::jae(b, 0x3000, 0x10)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x3012);
    env.backend.set(sem::eip_ref(), 0x3000);
    env.step(|b| sem::jb(b, 0x3000, 0x10)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x3000);
    env.backend.set(sem::eip_ref(), 0x3000);
    env.step(|b| sem::jbe(b, 0x3000, 0x10)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x3000);
}

#[test]
fn signed_branches() {
    let mut env = env();
    // 4 vs 5（負）：JL/JLE は飛び、JGE/JG は飛ばない。
    env.backend.set(Gpr(0).state(), 4);
    env.backend.set(Gpr(1).state(), 5);
    env.step(|b| sem::cmp_rm32(b, Gpr(0), Gpr(1))).unwrap();
    env.backend.set(sem::eip_ref(), 0x1000);
    env.step(|b| sem::jl(b, 0x1000, 0x10)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x1012);
    env.backend.set(sem::eip_ref(), 0x1000);
    env.step(|b| sem::jge(b, 0x1000, 0x10)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x1000);
    env.backend.set(sem::eip_ref(), 0x1000);
    env.step(|b| sem::jle(b, 0x1000, 0x10)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x1012);
    env.backend.set(sem::eip_ref(), 0x1000);
    env.step(|b| sem::jg(b, 0x1000, 0x10)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x1000);
    // 5 vs 5（等）：JGE/JLE は飛び、JL/JG は飛ばない。
    env.backend.set(Gpr(0).state(), 5);
    env.step(|b| sem::cmp_rm32(b, Gpr(0), Gpr(1))).unwrap();
    env.backend.set(sem::eip_ref(), 0x2000);
    env.step(|b| sem::jl(b, 0x2000, 0x10)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x2000);
    env.backend.set(sem::eip_ref(), 0x2000);
    env.step(|b| sem::jge(b, 0x2000, 0x10)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x2012);
    env.backend.set(sem::eip_ref(), 0x2000);
    env.step(|b| sem::jle(b, 0x2000, 0x10)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x2012);
    env.backend.set(sem::eip_ref(), 0x2000);
    env.step(|b| sem::jg(b, 0x2000, 0x10)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x2000);
    // 6 vs 5（正）：JGE/JG は飛び、JL/JLE は飛ばない。
    env.backend.set(Gpr(0).state(), 6);
    env.step(|b| sem::cmp_rm32(b, Gpr(0), Gpr(1))).unwrap();
    env.backend.set(sem::eip_ref(), 0x3000);
    env.step(|b| sem::jl(b, 0x3000, 0x10)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x3000);
    env.backend.set(sem::eip_ref(), 0x3000);
    env.step(|b| sem::jge(b, 0x3000, 0x10)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x3012);
    env.backend.set(sem::eip_ref(), 0x3000);
    env.step(|b| sem::jle(b, 0x3000, 0x10)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x3000);
    env.backend.set(sem::eip_ref(), 0x3000);
    env.step(|b| sem::jg(b, 0x3000, 0x10)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x3012);
    // あふれ：0x7fffffff vs -1。符号付きでは正（SF==OF=1）。
    // JL は飛ばず、JGE が飛ぶ。
    env.backend.set(Gpr(0).state(), 0x7FFF_FFFF);
    env.backend.set(Gpr(1).state(), 0xFFFF_FFFF);
    env.step(|b| sem::cmp_rm32(b, Gpr(0), Gpr(1))).unwrap();
    env.backend.set(sem::eip_ref(), 0x4000);
    env.step(|b| sem::jl(b, 0x4000, 0x10)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x4000);
    env.backend.set(sem::eip_ref(), 0x4000);
    env.step(|b| sem::jge(b, 0x4000, 0x10)).unwrap();
    assert_eq!(env.backend.get(sem::eip_ref()), 0x4012);
}

#[test]
fn sib_base_index_roundtrip() {
    let mut env = env();
    env.map_rw(0, 1).unwrap();
    // EBX=0x100、ESI=0x20。[0x120] に EAX を書いて読む。
    env.backend.set(Gpr(3).state(), 0x100);
    env.backend.set(Gpr(6).state(), 0x20);
    env.backend.set(Gpr(0).state(), 0xDEAD_BEEF);
    env.step(sem::mov_sib_eax).unwrap();
    env.backend.set(Gpr(0).state(), 0);
    env.step(sem::mov_eax_sib).unwrap();
    assert_eq!(eax(&mut env), 0xDEAD_BEEF);
}

#[test]
fn sib_disp8_roundtrip() {
    let mut env = env();
    env.map_rw(0, 1).unwrap();
    // EBX=0x100、ESI=0x20、disp=0x10 → [0x130] に書いて読む。
    env.backend.set(Gpr(3).state(), 0x100);
    env.backend.set(Gpr(6).state(), 0x20);
    env.backend.set(Gpr(0).state(), 0xA5A5_A5A5);
    env.step(|b| sem::mov_sibd_eax(b, 0x10)).unwrap();
    env.backend.set(Gpr(0).state(), 0);
    env.step(|b| sem::mov_eax_sibd(b, 0x10)).unwrap();
    assert_eq!(eax(&mut env), 0xA5A5_A5A5);
    // disp=-1：0x100+0x20-1 = 0x11f。
    env.step(|b| sem::mov_sibd_eax(b, -1)).unwrap();
    env.backend.set(Gpr(0).state(), 0);
    env.step(|b| sem::mov_eax_sibd(b, -1)).unwrap();
    assert_eq!(eax(&mut env), 0xA5A5_A5A5);
}

#[test]
fn sib_scaled_roundtrip() {
    let mut env = env();
    env.map_rw(0, 1).unwrap();
    // EBX=0x100、ESI=0x10、*4 で [0x140] に書いて読む。
    env.backend.set(Gpr(3).state(), 0x100);
    env.backend.set(Gpr(6).state(), 0x10);
    env.backend.set(Gpr(0).state(), 0x1234_5678);
    env.step(|b| sem::mov_sib_s4_eax(b, 0)).unwrap();
    env.backend.set(Gpr(0).state(), 0);
    env.step(|b| sem::mov_eax_sib_s4(b, 0)).unwrap();
    assert_eq!(eax(&mut env), 0x1234_5678);
    // *2：0x100+0x10*2+0 = 0x120。
    env.backend.set(Gpr(3).state(), 0x100);
    env.backend.set(Gpr(6).state(), 0x10);
    env.backend.set(Gpr(0).state(), 0x55AA_55AA);
    env.step(|b| sem::mov_sib_s2_eax(b, 0)).unwrap();
    env.backend.set(Gpr(0).state(), 0);
    env.step(|b| sem::mov_eax_sib_s2(b, 0)).unwrap();
    assert_eq!(eax(&mut env), 0x55AA_55AA);
    // *8、disp=-16：0x100+0x80-0x10 = 0x170。
    env.backend.set(Gpr(3).state(), 0x100);
    env.backend.set(Gpr(6).state(), 0x10);
    env.backend.set(Gpr(0).state(), 0x9ABC_DEF0);
    env.step(|b| sem::mov_sib_s8_eax(b, -16)).unwrap();
    env.backend.set(Gpr(0).state(), 0);
    env.step(|b| sem::mov_eax_sib_s8(b, -16)).unwrap();
    assert_eq!(eax(&mut env), 0x9ABC_DEF0);
}

#[test]
fn sib_scaled_nd_roundtrip() {
    // SIB スケール付き・disp なし：mod=00 の base+index*scale を裸実行で回す。
    // EBX=0x100、ESI=0x10。*2 で [0x120]、*4 で [0x140]、*8 で [0x180]。
    let mut env = env();
    env.map_rw(0, 1).unwrap();
    env.backend.set(Gpr(3).state(), 0x100);
    env.backend.set(Gpr(6).state(), 0x10);
    env.backend.set(Gpr(0).state(), 0x1111_2222);
    env.step(sem::mov_sib_s2nd_eax).unwrap();
    env.backend.set(Gpr(0).state(), 0);
    env.step(sem::mov_eax_sib_s2nd).unwrap();
    assert_eq!(eax(&mut env), 0x1111_2222);
    env.backend.set(Gpr(3).state(), 0x100);
    env.backend.set(Gpr(6).state(), 0x10);
    env.backend.set(Gpr(0).state(), 0x3333_4444);
    env.step(sem::mov_sib_s4nd_eax).unwrap();
    env.backend.set(Gpr(0).state(), 0);
    env.step(sem::mov_eax_sib_s4nd).unwrap();
    assert_eq!(eax(&mut env), 0x3333_4444);
    env.backend.set(Gpr(3).state(), 0x100);
    env.backend.set(Gpr(6).state(), 0x10);
    env.backend.set(Gpr(0).state(), 0x5555_6666);
    env.step(sem::mov_sib_s8nd_eax).unwrap();
    env.backend.set(Gpr(0).state(), 0);
    env.step(sem::mov_eax_sib_s8nd).unwrap();
    assert_eq!(eax(&mut env), 0x5555_6666);
}

#[test]
fn sib_disp32_roundtrip() {
    // SIB スケール付き・disp32：mod=10（EBX 基底）と mod=00 直接番地 base を往復する。
    let mut env = env();
    env.map_rw(0, 1).unwrap();
    // EBX=0x100、ESI=0x10、disp=0x20。
    // *2 で [0x140]、*4 で [0x160]、*8 で [0x1a0]。
    env.backend.set(Gpr(3).state(), 0x100);
    env.backend.set(Gpr(6).state(), 0x10);
    env.backend.set(Gpr(0).state(), 0x1111_2222);
    env.step(|b| sem::mov_sib_s2d32_eax(b, 0x20)).unwrap();
    env.backend.set(Gpr(0).state(), 0);
    env.step(|b| sem::mov_eax_sib_s2d32(b, 0x20)).unwrap();
    assert_eq!(eax(&mut env), 0x1111_2222);
    env.backend.set(Gpr(0).state(), 0x3333_4444);
    env.step(|b| sem::mov_sib_s4d32_eax(b, 0x20)).unwrap();
    env.backend.set(Gpr(0).state(), 0);
    env.step(|b| sem::mov_eax_sib_s4d32(b, 0x20)).unwrap();
    assert_eq!(eax(&mut env), 0x3333_4444);
    env.backend.set(Gpr(0).state(), 0x5555_6666);
    env.step(|b| sem::mov_sib_s8d32_eax(b, 0x20)).unwrap();
    env.backend.set(Gpr(0).state(), 0);
    env.step(|b| sem::mov_eax_sib_s8d32(b, 0x20)).unwrap();
    assert_eq!(eax(&mut env), 0x5555_6666);
    // 直接番地 base：ESI=0x10、disp=0x200。
    // *2 で [0x220]、*4 で [0x240]、*8 で [0x280]。
    env.backend.set(Gpr(6).state(), 0x10);
    env.backend.set(Gpr(0).state(), 0x7777_8888);
    env.step(|b| sem::mov_sib_s2a32_eax(b, 0x200)).unwrap();
    env.backend.set(Gpr(0).state(), 0);
    env.step(|b| sem::mov_eax_sib_s2a32(b, 0x200)).unwrap();
    assert_eq!(eax(&mut env), 0x7777_8888);
    env.backend.set(Gpr(0).state(), 0x9999_AAAA);
    env.step(|b| sem::mov_sib_s4a32_eax(b, 0x200)).unwrap();
    env.backend.set(Gpr(0).state(), 0);
    env.step(|b| sem::mov_eax_sib_s4a32(b, 0x200)).unwrap();
    assert_eq!(eax(&mut env), 0x9999_AAAA);
    env.backend.set(Gpr(0).state(), 0xBBBB_CCCC);
    env.step(|b| sem::mov_sib_s8a32_eax(b, 0x200)).unwrap();
    env.backend.set(Gpr(0).state(), 0);
    env.step(|b| sem::mov_eax_sib_s8a32(b, 0x200)).unwrap();
    assert_eq!(eax(&mut env), 0xBBBB_CCCC);
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

#[test]
fn mul_widens_to_edx_eax() {
    // 0xffffffff * 2 = 0x1_fffffffe。EAX=下位、EDX=上位。
    let mut env = env();
    env.backend.set(Gpr(0).state(), 0xffff_ffff);
    env.backend.set(Gpr(1).state(), 2);
    env.step(sem::mul_rm32).unwrap();
    assert_eq!(eax(&mut env), 0xffff_fffe);
    assert_eq!(env.backend.get(Gpr(2).state()), 1);
}

#[test]
fn div_quotient_remainder() {
    let mut env = env();
    // DIV: EDX:EAX=17 / ECX=5 → EAX=3、EDX=2。
    env.backend.set(Gpr(2).state(), 0);
    env.backend.set(Gpr(0).state(), 17);
    env.backend.set(Gpr(1).state(), 5);
    env.step(|b| sem::div_rm32(b, 0x1000)).unwrap();
    assert_eq!(eax(&mut env), 3);
    assert_eq!(env.backend.get(Gpr(2).state()), 2);
}

#[test]
fn div_by_zero_traps() {
    use polyisa_engine::interp::InterpExit;
    use polyisa_sem::ExceptionKind;
    let mut env = env();
    env.backend.set(Gpr(2).state(), 0);
    env.backend.set(Gpr(0).state(), 17);
    env.backend.set(Gpr(1).state(), 0);
    let r = env.step(|b| sem::div_rm32(b, 0x1000));
    assert!(matches!(
        r,
        Err(InterpExit::Exception(e)) if e.kind == ExceptionKind::DivZero && e.addr == Some(0x1000)
    ));
}

#[test]
fn idiv_signed() {
    // IDIV: EDX:EAX=-7 / ECX=2 -> EAX=-3, EDX=-1.
    let mut env = env();
    env.backend.set(Gpr(2).state(), 0xffff_ffff);
    env.backend.set(Gpr(0).state(), 0xffff_fff9);
    env.backend.set(Gpr(1).state(), 2);
    env.step(|b| sem::idiv_rm32(b, 0x1000)).unwrap();
    assert_eq!(eax(&mut env), 0xffff_fffd);
    assert_eq!(env.backend.get(Gpr(2).state()), 0xffff_ffff);
}

#[test]
fn idiv_overflow_traps() {
    use polyisa_engine::interp::InterpExit;
    use polyisa_sem::ExceptionKind;
    // INT_MIN / -1 は商が収まらないため DivZero。
    let mut env = env();
    env.backend.set(Gpr(2).state(), 0xffff_ffff);
    env.backend.set(Gpr(0).state(), 0x8000_0000);
    env.backend.set(Gpr(1).state(), 0xffff_ffff);
    let r = env.step(|b| sem::idiv_rm32(b, 0x1000));
    assert!(matches!(
        r,
        Err(InterpExit::Exception(e)) if e.kind == ExceptionKind::DivZero && e.addr == Some(0x1000)
    ));
}

#[test]
fn r64_read_write_split() {
    // 64ビットレジスタは上位 h と下位 g に分割して持つ。
    let mut env = env();
    env.step(|b| {
        sem::write64(b, Gpr(1), 0x1122_3344_5566_7788);
        Ok(())
    })
    .unwrap();
    assert_eq!(env.backend.get(Gpr(1).state()), 0x5566_7788);
    assert_eq!(env.backend.get(sem::hi_ref(Gpr(1))), 0x1122_3344);
    // MOV r64：EDX の全64ビットが ECX に移る。
    env.step(|b| {
        sem::write64(b, Gpr(2), 0x00AA_BBCC_DDEE_FF11);
        Ok(())
    })
    .unwrap();
    env.step(|b| sem::mov_rm64(b, Gpr(1), Gpr(2))).unwrap();
    assert_eq!(env.backend.get(Gpr(1).state()), 0xDDEE_FF11);
    assert_eq!(env.backend.get(sem::hi_ref(Gpr(1))), 0x00AA_BBCC);
}

#[test]
fn r64_add_flags() {
    // 0xffffffffffffffff + 1 = 0：CF=ZF=AF=PF=1、SF=OF=0。
    let mut env = env();
    env.step(|b| {
        sem::write64(b, Gpr(0), 0xFFFF_FFFF_FFFF_FFFF);
        Ok(())
    })
    .unwrap();
    env.step(|b| {
        sem::write64(b, Gpr(1), 1);
        Ok(())
    })
    .unwrap();
    env.step(|b| sem::add_rm64(b, Gpr(0), Gpr(1))).unwrap();
    assert_eq!(env.backend.get(Gpr(0).state()), 0);
    assert_eq!(env.backend.get(sem::hi_ref(Gpr(0))), 0);
    assert_eq!(env.backend.get(sem::eflags_ref()), 0x55);
    // 0x7fffffffffffffff + 1：SF=OF=1。
    env.step(|b| {
        sem::write64(b, Gpr(0), 0x7FFF_FFFF_FFFF_FFFF);
        Ok(())
    })
    .unwrap();
    env.step(|b| sem::add_rm64(b, Gpr(0), Gpr(1))).unwrap();
    assert_eq!(env.backend.get(sem::hi_ref(Gpr(0))), 0x8000_0000);
    assert_eq!(env.backend.get(sem::eflags_ref()) & 0x880, 0x880);
}

#[test]
fn rip_relative_lea() {
    // LEA RAX,[RIP+disp32]：次命令先頭 + disp が入る。
    let mut env = env();
    env.step(|b| sem::lea_rip64(b, Gpr(0), 0x1007, 0x10))
        .unwrap();
    assert_eq!(env.backend.get(Gpr(0).state()), 0x1017);
    assert_eq!(env.backend.get(sem::hi_ref(Gpr(0))), 0);
    // 負の disp。
    env.step(|b| sem::lea_rip64(b, Gpr(1), 0x1007, -0x10))
        .unwrap();
    assert_eq!(env.backend.get(Gpr(1).state()), 0xFF7);
}
