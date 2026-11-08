//! RV64I の命令単位のテスト。裸実行環境で CPU 状態とメモリを検査する。
//!
//! 命令語の組み立てはビット配置の定義から手で行う。生成したエンコーダに
//! 置き換えるのは、逆変換の生成の実装後である。

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::{Ctrl, InterpExit};
use polyisa_guest_riscv::sem::Gpr;
use polyisa_guest_riscv::{CpuState, sem};
use polyisa_sem::Backend as _;

fn env() -> BareEnv {
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    env.map_rw(0x1_0000, 1).unwrap();
    env
}

fn x(env: &mut BareEnv, r: u8) -> u64 {
    env.backend.get(Gpr(r).state())
}

#[test]
fn addi_add() {
    let mut env = env();
    env.step(|b| sem::addi(b, Gpr(1), Gpr(0), 40)).unwrap();
    env.step(|b| sem::addi(b, Gpr(2), Gpr(0), 2)).unwrap();
    env.step(|b| sem::add(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(x(&mut env, 3), 42);
    // x0 への書き込みは捨てる。
    env.step(|b| sem::addi(b, Gpr(0), Gpr(0), 1)).unwrap();
    assert_eq!(x(&mut env, 0), 0);
}

#[test]
fn sub_slt_sltu() {
    let mut env = env();
    env.step(|b| sem::addi(b, Gpr(1), Gpr(0), 5)).unwrap();
    env.step(|b| sem::sub(b, Gpr(2), Gpr(0), Gpr(1))).unwrap();
    // 0 - 5 は 64 ビットで包む。
    assert_eq!(x(&mut env, 2), 0xffff_ffff_ffff_fffb);
    env.step(|b| sem::slt(b, Gpr(3), Gpr(2), Gpr(1))).unwrap();
    assert_eq!(x(&mut env, 3), 1);
    env.step(|b| sem::sltu(b, Gpr(4), Gpr(2), Gpr(1))).unwrap();
    assert_eq!(x(&mut env, 4), 0);
}

#[test]
fn shifts_w_suffix() {
    let mut env = env();
    env.step(|b| sem::addi(b, Gpr(1), Gpr(0), 1)).unwrap();
    env.step(|b| sem::slli(b, Gpr(1), Gpr(1), 63)).unwrap();
    assert_eq!(x(&mut env, 1), 0x8000_0000_0000_0000);
    env.step(|b| sem::srai(b, Gpr(2), Gpr(1), 63)).unwrap();
    assert_eq!(x(&mut env, 2), 0xffff_ffff_ffff_ffff);
    env.step(|b| sem::srli(b, Gpr(3), Gpr(1), 63)).unwrap();
    assert_eq!(x(&mut env, 3), 1);
}

#[test]
fn addiw_sraw_sign() {
    let mut env = env();
    // 0x80000 を 20 ビット符号付きとみなすと -524288。LUI は 32 ビット符号拡張する。
    env.step(|b| sem::lui(b, Gpr(1), -524288)).unwrap();
    assert_eq!(x(&mut env, 1), 0xffff_ffff_8000_0000);
    env.step(|b| sem::addi(b, Gpr(2), Gpr(0), 1)).unwrap();
    env.step(|b| sem::sraw(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(x(&mut env, 3), 0xffff_ffff_c000_0000);
    env.step(|b| sem::addiw(b, Gpr(4), Gpr(0), -1)).unwrap();
    assert_eq!(x(&mut env, 4), 0xffff_ffff_ffff_ffff);
}

#[test]
fn lui_auipc() {
    let mut env = env();
    env.step(|b| sem::lui(b, Gpr(1), 0x12345)).unwrap();
    assert_eq!(x(&mut env, 1), 0x1234_5000);
    env.step(|b| sem::auipc(b, Gpr(2), 0x1_0000, 1)).unwrap();
    assert_eq!(x(&mut env, 2), 0x1_1000);
}

#[test]
fn load_store_roundtrip() {
    let mut env = env();
    env.map_rw(0x0, 1).unwrap();
    env.step(|b| sem::addi(b, Gpr(1), Gpr(0), 0x100)).unwrap();
    env.step(|b| sem::addi(b, Gpr(2), Gpr(0), 0)).unwrap();
    env.step(|b| sem::addi(b, Gpr(2), Gpr(2), -2)).unwrap();
    // x2 = -2。sw で下位 32 ビットだけ書く。
    env.step(|b| sem::sw(b, Gpr(1), Gpr(2), 0)).unwrap();
    env.step(|b| sem::lw(b, Gpr(3), Gpr(1), 0)).unwrap();
    assert_eq!(x(&mut env, 3), 0xffff_ffff_ffff_fffe);
    env.step(|b| sem::lwu(b, Gpr(4), Gpr(1), 0)).unwrap();
    assert_eq!(x(&mut env, 4), 0xffff_fffe);
    env.step(|b| sem::lb(b, Gpr(5), Gpr(1), 0)).unwrap();
    assert_eq!(x(&mut env, 5), 0xffff_ffff_ffff_fffe);
    env.step(|b| sem::lbu(b, Gpr(6), Gpr(1), 0)).unwrap();
    assert_eq!(x(&mut env, 6), 0xfe);
    env.step(|b| sem::sd(b, Gpr(1), Gpr(2), 8)).unwrap();
    env.step(|b| sem::ld(b, Gpr(7), Gpr(1), 8)).unwrap();
    assert_eq!(x(&mut env, 7), 0xffff_ffff_ffff_fffe);
}

#[test]
fn branch_and_jump() {
    let mut env = env();
    env.pc = 0x1_0000;
    env.step(|b| sem::addi(b, Gpr(1), Gpr(0), 1)).unwrap();
    // beq x0, x0, +16：成立する。
    let pc = env.pc;
    env.step(|b| sem::beq(b, Gpr(0), Gpr(0), pc, 16)).unwrap();
    assert_eq!(env.pc, 0x1_0010);
    // bne x0, x0, +16：成立しない。
    let pc = env.pc;
    env.step(|b| sem::bne(b, Gpr(0), Gpr(0), pc, 16)).unwrap();
    assert_eq!(env.pc, 0x1_0010);
    // jal x5, +8：戻りを書き、飛ぶ。
    let pc = env.pc;
    env.step(|b| sem::jal(b, Gpr(5), pc, 8)).unwrap();
    assert_eq!(x(&mut env, 5), 0x1_0014);
    assert_eq!(env.pc, 0x1_0018);
    // jalr x0, 0(x5)：x0 への書き込みは捨て、飛ぶ。
    let pc = env.pc;
    env.step(|b| sem::jalr(b, Gpr(0), Gpr(5), pc, 0)).unwrap();
    assert_eq!(env.pc, 0x1_0014);
    assert_eq!(x(&mut env, 0), 0);
}

#[test]
fn blt_signed_vs_unsigned() {
    let mut env = env();
    env.step(|b| sem::addi(b, Gpr(1), Gpr(0), -1)).unwrap();
    env.step(|b| sem::addi(b, Gpr(2), Gpr(0), 1)).unwrap();
    // 符号付きでは -1 < 1、符号なしでは -1（巨大値）> 1。
    env.step(|b| sem::blt(b, Gpr(1), Gpr(2), 0x100, 8)).unwrap();
    assert!(matches!(env.backend.ctrl, Ctrl::Jump(0x108)));
    env.backend.ctrl = Ctrl::Fallthrough;
    env.step(|b| sem::bltu(b, Gpr(1), Gpr(2), 0x100, 8))
        .unwrap();
    assert!(matches!(env.backend.ctrl, Ctrl::Fallthrough));
}

#[test]
fn logic_and_w_suffix() {
    let mut env = env();
    env.step(|b| sem::addi(b, Gpr(1), Gpr(0), 0b1100)).unwrap();
    env.step(|b| sem::addi(b, Gpr(2), Gpr(0), 0b1010)).unwrap();
    env.step(|b| sem::xori(b, Gpr(3), Gpr(1), 0b1010)).unwrap();
    assert_eq!(x(&mut env, 3), 0b0110);
    env.step(|b| sem::ori(b, Gpr(3), Gpr(1), 0b1010)).unwrap();
    assert_eq!(x(&mut env, 3), 0b1110);
    env.step(|b| sem::andi(b, Gpr(3), Gpr(1), 0b1010)).unwrap();
    assert_eq!(x(&mut env, 3), 0b1000);
    env.step(|b| sem::xor(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(x(&mut env, 3), 0b0110);
    env.step(|b| sem::or(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(x(&mut env, 3), 0b1110);
    env.step(|b| sem::and(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(x(&mut env, 3), 0b1000);
    // シフトと W 接尾辞。
    env.step(|b| sem::sll(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(x(&mut env, 3), 0b1100u64 << 10);
    env.step(|b| sem::srl(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(x(&mut env, 3), 0b1100u64 >> 10);
    env.step(|b| sem::addi(b, Gpr(4), Gpr(0), -8)).unwrap();
    env.step(|b| sem::sra(b, Gpr(3), Gpr(4), Gpr(2))).unwrap();
    assert_eq!(x(&mut env, 3), 0xffff_ffff_ffff_ffff);
    env.step(|b| sem::addw(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(x(&mut env, 3), 22);
    env.step(|b| sem::subw(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(x(&mut env, 3), 2);
    env.step(|b| sem::sllw(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(x(&mut env, 3), 0b1100u64 << 10);
    env.step(|b| sem::srlw(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(x(&mut env, 3), 0);
    // bge/bgeu。x1=12、x2=10。
    env.step(|b| sem::bge(b, Gpr(1), Gpr(2), 0x200, 8)).unwrap();
    assert!(matches!(env.backend.ctrl, Ctrl::Jump(0x208)));
    env.backend.ctrl = Ctrl::Fallthrough;
    env.step(|b| sem::bgeu(b, Gpr(2), Gpr(1), 0x200, 8))
        .unwrap();
    assert!(matches!(env.backend.ctrl, Ctrl::Fallthrough));
}

#[test]
fn system_exits() {
    let mut env = env();
    let r = env.step(|b| sem::ecall(b, 0x100));
    assert!(matches!(
        r,
        Err(InterpExit::Exception(e)) if e.addr == Some(0x100)
    ));
    let r = env.step(|b| sem::ebreak(b, 0x104));
    assert!(matches!(r, Err(InterpExit::Exception(_))));
    env.step(sem::fence).unwrap();
    env.step(sem::fence_i).unwrap();
}
