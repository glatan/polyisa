// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! MIPS I 試作の命令単位のテスト。裸実行環境で CPU 状態と遅延スロットを検査する.
//! 出典は SPEC-MIPS-IV Rev 3.2 (1995-09) である.
//! Ref: SPEC-MIPS-IV (Rev 3.2).

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::InterpExit;
use polyisa_guest_mips::CpuState;
use polyisa_guest_mips::sem::{self, Gpr};
use polyisa_mem::Endian;
use polyisa_sem::{Backend as _, ExceptionKind};

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
    env.backend.set(Gpr(1).state(), 12);
    env.backend.set(Gpr(2).state(), 10);
    env.step(|b| sem::addu(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(g(&mut env, 3), 22);
    env.step(|b| sem::subu(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(g(&mut env, 3), 2);
    env.step(|b| sem::and(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(g(&mut env, 3), 8);
    env.step(|b| sem::or(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(g(&mut env, 3), 14);
    // $0 への書き込みは捨てる。
    env.step(|b| sem::addu(b, Gpr(0), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(g(&mut env, 0), 0);
}

#[test]
fn addu_wraps_without_trap() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 0xffff_ffff);
    env.backend.set(Gpr(2).state(), 1);
    // ADDU は trap せず下位32ビットで包む。
    env.step(|b| sem::addu(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(g(&mut env, 3), 0);
}

#[test]
fn shift_uses_low_5bits() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 1);
    env.step(|b| sem::sll(b, Gpr(2), Gpr(1), 2)).unwrap();
    assert_eq!(g(&mut env, 2), 4);
}

#[test]
fn load_store_le_roundtrip_and_lwl() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 0x100);
    env.backend.set(Gpr(2).state(), 0x1122_3344);
    env.step(|b| sem::sw_endian(b, Gpr(2), Gpr(1), 0, Endian::Le))
        .unwrap();
    let mut bytes = [0u8; 4];
    env.backend
        .mem
        .read(
            polyisa_mem::VirtAddr(0x100),
            &mut bytes,
            polyisa_mem::Access {
                endian: Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(bytes, [0x44, 0x33, 0x22, 0x11]);
    env.step(|b| sem::lw_endian(b, Gpr(3), Gpr(1), 0, Endian::Le))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0x1122_3344);
    // LE の LWL、オフセット 0。最上位バイトだけがメモリの先頭バイトになる。
    env.backend
        .mem
        .write(polyisa_mem::VirtAddr(0x100), &[0x11, 0x22, 0x33, 0x44])
        .unwrap();
    env.backend.set(Gpr(3).state(), 0x00ee_eeee);
    env.step(|b| sem::lwl(b, Gpr(3), Gpr(1), 0, Endian::Le))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0x11ee_eeee);
}

#[test]
fn load_store_be_roundtrip() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 0x100);
    env.backend.set(Gpr(2).state(), 0x1234_5678);
    env.step(|b| sem::sw(b, Gpr(2), Gpr(1), 0)).unwrap();
    env.step(|b| sem::lw(b, Gpr(3), Gpr(1), 0)).unwrap();
    assert_eq!(g(&mut env, 3), 0x1234_5678);
}

#[test]
fn delay_slot_executes_before_branch() {
    let mut env = env();
    env.backend.set(sem::pc_ref(), 0x1000);
    // fallthrough は sem 内部で pc+8 を計算する。
    env.backend.set(sem::npc_ref(), 0x1008);
    env.backend.set(Gpr(1).state(), 5);
    env.backend.set(Gpr(2).state(), 5);
    // beq 成立：npc=pc+4+disp*4。
    env.step(|b| sem::beq_delay(b, Gpr(1), Gpr(2), 0x1000, 4))
        .unwrap();
    assert_eq!(env.backend.get(sem::npc_ref()), 0x1014);
    // 遅延スロットは必ず実行される。
    env.backend.set(Gpr(3).state(), 0);
    env.step(|b| sem::addu(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(g(&mut env, 3), 10);
    env.step(sem::commit).unwrap();
    assert_eq!(env.backend.get(sem::pc_ref()), 0x1014);
    // 不成立：npc は fallthrough のまま。
    env.backend.set(sem::pc_ref(), 0x2000);
    env.backend.set(sem::npc_ref(), 0x2008);
    env.backend.set(Gpr(2).state(), 6);
    env.step(|b| sem::beq_delay(b, Gpr(1), Gpr(2), 0x2000, 4))
        .unwrap();
    assert_eq!(env.backend.get(sem::npc_ref()), 0x2008);
}

#[test]
fn mult_div_hi_lo() {
    let mut env = env();
    // 7 * 6 = 42。HI=0、LO=42。
    env.backend.set(Gpr(1).state(), 7);
    env.backend.set(Gpr(2).state(), 6);
    env.step(|b| sem::mult(b, Gpr(1), Gpr(2))).unwrap();
    env.step(|b| sem::mfhi(b, Gpr(3))).unwrap();
    env.step(|b| sem::mflo(b, Gpr(4))).unwrap();
    assert_eq!(g(&mut env, 3), 0);
    assert_eq!(g(&mut env, 4), 42);
    // 符号付き: -2 * 6 = -12。HI=0xffffffff、LO=0xfffffff4。
    env.backend.set(Gpr(1).state(), 0xffff_ffff_ffff_fffe);
    env.step(|b| sem::mult(b, Gpr(1), Gpr(2))).unwrap();
    env.step(|b| sem::mfhi(b, Gpr(3))).unwrap();
    env.step(|b| sem::mflo(b, Gpr(4))).unwrap();
    assert_eq!(g(&mut env, 3), 0xffff_ffff);
    assert_eq!(g(&mut env, 4), 0xffff_fff4);
    // DIV: 42 / 6 = 7 余り 0。
    env.backend.set(Gpr(5).state(), 42);
    env.backend.set(Gpr(6).state(), 6);
    env.step(|b| sem::div(b, Gpr(5), Gpr(6))).unwrap();
    env.step(|b| sem::mflo(b, Gpr(7))).unwrap();
    env.step(|b| sem::mfhi(b, Gpr(8))).unwrap();
    assert_eq!(g(&mut env, 7), 7);
    assert_eq!(g(&mut env, 8), 0);
    // 0 除算は HI/LO 不変。
    env.step(|b| sem::div(b, Gpr(5), Gpr(0))).unwrap();
    env.step(|b| sem::mflo(b, Gpr(7))).unwrap();
    env.step(|b| sem::mfhi(b, Gpr(8))).unwrap();
    assert_eq!(g(&mut env, 7), 7);
    assert_eq!(g(&mut env, 8), 0);
    // DIVU: 0xffffffff / 2 = 0x7fffffff 余り 1。
    env.backend.set(Gpr(9).state(), 0xffff_ffff);
    env.backend.set(Gpr(10).state(), 2);
    env.step(|b| sem::divu(b, Gpr(9), Gpr(10))).unwrap();
    env.step(|b| sem::mflo(b, Gpr(11))).unwrap();
    env.step(|b| sem::mfhi(b, Gpr(12))).unwrap();
    assert_eq!(g(&mut env, 11), 0x7fff_ffff);
    assert_eq!(g(&mut env, 12), 1);
    // MTHI/MTLO/MFHI/MFLO の往復。
    env.step(|b| sem::mthi(b, Gpr(9))).unwrap();
    env.step(|b| sem::mtlo(b, Gpr(10))).unwrap();
    env.step(|b| sem::mfhi(b, Gpr(13))).unwrap();
    env.step(|b| sem::mflo(b, Gpr(14))).unwrap();
    assert_eq!(g(&mut env, 13), 0xffff_ffff);
    assert_eq!(g(&mut env, 14), 2);
}

#[test]
fn addi_wraps() {
    let mut env = env();
    // 0x7fffffff + 1 は 32 ビットで包んで 0x80000000 になる。
    env.backend.set(Gpr(1).state(), 0x7fff_ffff);
    env.step(|b| sem::addi(b, Gpr(2), Gpr(1), 1)).unwrap();
    assert_eq!(g(&mut env, 2), 0x8000_0000);
    // $0 への書き込みは捨てる。
    env.step(|b| sem::addi(b, Gpr(0), Gpr(1), 1)).unwrap();
    assert_eq!(g(&mut env, 0), 0);
}

#[test]
fn addiu_wraps_like_addi() {
    // ADDIU は R6 でも残る。trap なしで 32 ビットに包む。
    // $0 への書き込みは捨てる。
    let mut env = env();
    env.backend.set(Gpr(1).state(), 0xffff_ffff);
    env.step(|b| sem::addiu(b, Gpr(2), Gpr(1), 2)).unwrap();
    assert_eq!(g(&mut env, 2), 1);
    env.step(|b| sem::addiu(b, Gpr(0), Gpr(1), 2)).unwrap();
    assert_eq!(g(&mut env, 0), 0);
}

#[test]
fn beqzalc_links_and_branches_without_delay_slot() {
    let mut env = env();
    // R6 の BEQZALC は遅延スロットなし：rt==0 のとき 1 ステップで pc が飛ぶ。
    // リンク（$31=pc+4）は条件によらず書く。
    env.backend.set(sem::pc_ref(), 0x1000);
    env.backend.set(sem::npc_ref(), 0xdead_beef);
    env.backend.set(Gpr(1).state(), 0);
    env.step(|b| sem::beqzalc(b, Gpr(0), Gpr(1), 0x1000, 4))
        .unwrap();
    assert_eq!(env.backend.get(sem::pc_ref()), 0x1014);
    assert_eq!(g(&mut env, 31), 0x1004);
    // npc には触らない。
    assert_eq!(env.backend.get(sem::npc_ref()), 0xdead_beef);
    // rt!=0 のときは分岐せず、pc を次の命令へ進めてリンクを書く。
    env.backend.set(sem::pc_ref(), 0x2000);
    env.backend.set(Gpr(1).state(), 7);
    env.step(|b| sem::beqzalc(b, Gpr(0), Gpr(1), 0x2000, 4))
        .unwrap();
    assert_eq!(env.backend.get(sem::pc_ref()), 0x2004);
    assert_eq!(g(&mut env, 31), 0x2004);
}

#[test]
fn jump_defers_one_slot() {
    let mut env = env();
    env.backend.set(sem::pc_ref(), 0x1000);
    env.backend.set(sem::npc_ref(), 0x1008);
    env.step(|b| sem::j_delay(b, 0x3000)).unwrap();
    assert_eq!(env.backend.get(sem::npc_ref()), 0x3000);
    env.step(sem::commit).unwrap();
    assert_eq!(env.backend.get(sem::pc_ref()), 0x3000);
    assert_eq!(env.backend.get(sem::npc_ref()), 0x3004);
}

#[test]
fn logic_shift_and_slt() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 0xffff_ffff);
    env.backend.set(Gpr(2).state(), 1);
    env.step(|b| sem::xor(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(g(&mut env, 3), 0xffff_fffe);
    env.step(|b| sem::nor(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(g(&mut env, 3), 0);
    env.step(|b| sem::slt(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(g(&mut env, 3), 1);
    env.step(|b| sem::sltu(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(g(&mut env, 3), 0);
    env.step(|b| sem::srl(b, Gpr(3), Gpr(1), 4)).unwrap();
    assert_eq!(g(&mut env, 3), 0x0fff_ffff);
    env.step(|b| sem::sra(b, Gpr(3), Gpr(1), 4)).unwrap();
    assert_eq!(g(&mut env, 3), 0xffff_ffff);
}

#[test]
fn andi_lui_and_sltiu_extend_immediate() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 0xffff_0000);
    env.step(|b| sem::andi(b, Gpr(2), Gpr(1), 0x00ff)).unwrap();
    assert_eq!(g(&mut env, 2), 0);
    env.step(|b| sem::lui(b, Gpr(2), 0x1234)).unwrap();
    assert_eq!(g(&mut env, 2), 0x1234_0000);
    // SLTIU は即値を符号拡張してから符号なしで比べる。即値 1 なら rs==0 のときだけ真。
    env.backend.set(Gpr(1).state(), 0);
    env.step(|b| sem::sltiu(b, Gpr(2), Gpr(1), 1)).unwrap();
    assert_eq!(g(&mut env, 2), 1);
    env.backend.set(Gpr(1).state(), 1);
    env.step(|b| sem::sltiu(b, Gpr(2), Gpr(1), 1)).unwrap();
    assert_eq!(g(&mut env, 2), 0);
    env.backend.set(Gpr(1).state(), 0);
    env.step(|b| sem::sltiu(b, Gpr(2), Gpr(1), -1)).unwrap();
    assert_eq!(g(&mut env, 2), 1);
}

#[test]
fn bltz_runs_with_delay() {
    let mut env = env();
    env.backend.set(sem::pc_ref(), 0x1000);
    env.backend.set(sem::npc_ref(), 0x1008);
    env.backend.set(Gpr(1).state(), 0xffff_ffff);
    env.step(|b| sem::bltz_delay(b, Gpr(1), 0x1000, 4)).unwrap();
    assert_eq!(env.backend.get(sem::npc_ref()), 0x1014);
    env.backend.set(Gpr(1).state(), 0);
    env.backend.set(sem::pc_ref(), 0x1000);
    env.step(|b| sem::bltz_delay(b, Gpr(1), 0x1000, 4)).unwrap();
    assert_eq!(env.backend.get(sem::npc_ref()), 0x1008);
}

#[test]
fn jal_links_past_the_delay_slot() {
    let mut env = env();
    env.step(|b| sem::jal_delay(b, 0x1000, 0x3000)).unwrap();
    assert_eq!(g(&mut env, 31), 0x1008);
    assert_eq!(env.backend.get(sem::npc_ref()), 0x3000);
}

#[test]
fn lb_sign_extends_into_low_32() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 0x100);
    env.backend.set(Gpr(2).state(), 0xff);
    env.step(|b| sem::sb(b, Gpr(2), Gpr(1), 0, Endian::Be))
        .unwrap();
    env.step(|b| sem::lb(b, Gpr(3), Gpr(1), 0, Endian::Be))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0xffff_ffff);
}

#[test]
fn lwl_swl_merge_big_endian_word() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 0x100);
    env.backend.set(Gpr(2).state(), 0x1122_3344);
    env.step(|b| sem::sw(b, Gpr(2), Gpr(1), 0)).unwrap();
    env.backend.set(Gpr(3).state(), 0xee);
    env.step(|b| sem::lwl(b, Gpr(3), Gpr(1), 1, Endian::Be))
        .unwrap();
    assert_eq!(g(&mut env, 3), 0x2233_44ee);
    env.backend.set(Gpr(4).state(), 0xaabb_ccdd);
    env.step(|b| sem::swl(b, Gpr(4), Gpr(1), 1, Endian::Be))
        .unwrap();
    env.step(|b| sem::lw(b, Gpr(5), Gpr(1), 0)).unwrap();
    assert_eq!(g(&mut env, 5), 0x11aa_bbcc);
}

#[test]
fn add_overflow_leaves_destination() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 0x7fff_ffff);
    env.backend.set(Gpr(2).state(), 1);
    env.backend.set(Gpr(3).state(), 0x11);
    let err = env.step(|b| sem::add(b, Gpr(3), Gpr(1), Gpr(2)));
    match err {
        Err(InterpExit::Exception(e)) => assert_eq!(e.kind, ExceptionKind::Trap),
        other => panic!("overflow should trap, got {other:?}"),
    }
    assert_eq!(g(&mut env, 3), 0x11);
}

#[test]
fn div_zero_can_clear_hi_lo() {
    let mut env = env();
    env.backend.set(Gpr(1).state(), 7);
    env.backend.set(Gpr(2).state(), 3);
    env.step(|b| sem::div(b, Gpr(1), Gpr(2))).unwrap();
    env.backend.set(sem::div_zero_writes_zero_ref(), 1);
    env.step(|b| sem::div(b, Gpr(1), Gpr(0))).unwrap();
    env.step(|b| sem::mflo(b, Gpr(3))).unwrap();
    env.step(|b| sem::mfhi(b, Gpr(4))).unwrap();
    assert_eq!(g(&mut env, 3), 0);
    assert_eq!(g(&mut env, 4), 0);
}

#[test]
fn syscall_raises_break() {
    let mut env = env();
    let err = env.step(sem::syscall);
    match err {
        Err(InterpExit::Exception(e)) => {
            assert_eq!(e.kind, ExceptionKind::Break);
            assert_eq!(e.code, 1);
        }
        other => panic!("syscall should raise, got {other:?}"),
    }
}
