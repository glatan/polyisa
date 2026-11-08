// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
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

fn xf(env: &mut BareEnv, r: u8) -> u32 {
    use polyisa_guest_riscv::sem::Fpr;
    (env.backend.get(Fpr(r).state()) & 0xffff_ffff) as u32
}

fn x64(env: &mut BareEnv, r: u8) -> u64 {
    use polyisa_guest_riscv::sem::Fpr;
    env.backend.get(Fpr(r).state())
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
fn m_extension() {
    let mut env = env();
    env.step(|b| sem::addi(b, Gpr(1), Gpr(0), 7)).unwrap();
    env.step(|b| sem::addi(b, Gpr(2), Gpr(0), 6)).unwrap();
    env.step(|b| sem::mul(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(x(&mut env, 3), 42);
    env.step(|b| sem::div(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(x(&mut env, 3), 1);
    env.step(|b| sem::rem(b, Gpr(3), Gpr(1), Gpr(2))).unwrap();
    assert_eq!(x(&mut env, 3), 1);
    // 0 除算とオーバーフロー。
    env.step(|b| sem::div(b, Gpr(3), Gpr(1), Gpr(0))).unwrap();
    assert_eq!(x(&mut env, 3), u64::MAX);
    env.step(|b| sem::rem(b, Gpr(3), Gpr(1), Gpr(0))).unwrap();
    assert_eq!(x(&mut env, 3), 7);
    env.step(|b| sem::addi(b, Gpr(4), Gpr(0), -8)).unwrap();
    env.step(|b| sem::div(b, Gpr(5), Gpr(4), Gpr(0))).unwrap();
    assert_eq!(x(&mut env, 5), u64::MAX);
    // MULW。x6 の下位 32 ビットは 0x80000000。
    env.step(|b| sem::lui(b, Gpr(6), -524288)).unwrap();
    env.step(|b| sem::mulw(b, Gpr(10), Gpr(6), Gpr(1))).unwrap();
    assert_eq!(x(&mut env, 10), 0xffff_ffff_8000_0000);
    // x11 に最小値を置き、MULHU と -1 除算を確かめる。
    env.step(|b| sem::slli(b, Gpr(11), Gpr(6), 32)).unwrap();
    assert_eq!(x(&mut env, 11), 0x8000_0000_0000_0000);
    env.step(|b| sem::mulhu(b, Gpr(9), Gpr(11), Gpr(11)))
        .unwrap();
    assert_eq!(x(&mut env, 9), 0x4000_0000_0000_0000);
    env.step(|b| sem::addi(b, Gpr(7), Gpr(0), -1)).unwrap();
    env.step(|b| sem::div(b, Gpr(8), Gpr(11), Gpr(7))).unwrap();
    assert_eq!(x(&mut env, 8), 0x8000_0000_0000_0000);
}

#[test]
fn csr_read_write_set_clear() {
    use polyisa_guest_riscv::sem::Csr;
    let mut env = env();
    // fcsr (0x003) に書いて読む。U モードの読み書き CSR である。
    env.step(|b| sem::addi(b, Gpr(1), Gpr(0), 42)).unwrap();
    let pc = env.pc;
    env.step(|b| sem::csrrw(b, Gpr(2), Gpr(1), Csr(0x003), pc))
        .unwrap();
    assert_eq!(x(&mut env, 2), 0);
    let pc = env.pc;
    env.step(|b| sem::csrrw(b, Gpr(2), Gpr(0), Csr(0x003), pc))
        .unwrap();
    assert_eq!(x(&mut env, 2), 42);
    // ビットを立てる。戻り値は書き換え前の値。
    let pc = env.pc;
    env.step(|b| sem::csrrsi(b, Gpr(3), 0b101, Csr(0x003), pc))
        .unwrap();
    assert_eq!(x(&mut env, 3), 0);
    // 0b011111 を置き、x1=0b101010 のビットを落とす（0b011111 & ~0b101010 = 0b010101）。
    let pc = env.pc;
    env.step(|b| sem::csrrwi(b, Gpr(0), 0b11111, Csr(0x003), pc))
        .unwrap();
    let pc = env.pc;
    env.step(|b| sem::csrrc(b, Gpr(3), Gpr(1), Csr(0x003), pc))
        .unwrap();
    assert_eq!(x(&mut env, 3), 0b011111);
    let pc = env.pc;
    env.step(|b| sem::csrrs(b, Gpr(4), Gpr(0), Csr(0x003), pc))
        .unwrap();
    assert_eq!(x(&mut env, 4), 0b010101);
    // rs1=x0 の CSRRS は書き込まない。
    let pc = env.pc;
    env.step(|b| sem::csrrs(b, Gpr(3), Gpr(0), Csr(0x003), pc))
        .unwrap();
    assert_eq!(x(&mut env, 3), 0b010101);
    // uimm=0 の CSRRSI は書き込まない。
    let pc = env.pc;
    env.step(|b| sem::csrrsi(b, Gpr(3), 0, Csr(0x003), pc))
        .unwrap();
    assert_eq!(x(&mut env, 3), 0b010101);
}

#[test]
fn csr_permission_checks() {
    use polyisa_guest_riscv::sem::Csr;
    use polyisa_sem::{StateRef, W64};
    fn priv_of() -> StateRef<W64> {
        StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, priv_level))
    }
    let mut env = env();
    // 初期状態は U モード (0) である。
    assert_eq!(env.backend.get(priv_of()), 0);
    // U モードで cycle (0xC00、読み出し専用) を読むのは成功する。
    let pc = env.pc;
    env.step(|b| sem::csrrs(b, Gpr(1), Gpr(0), Csr(0xC00), pc))
        .unwrap();
    // U モードで読み出し専用 CSR に書くと不正命令になる。
    let pc = env.pc;
    let r = env.step(|b| sem::csrrw(b, Gpr(1), Gpr(0), Csr(0xC00), pc));
    assert!(matches!(r, Err(InterpExit::Exception(e)) if e.code == 2 && e.addr == Some(pc)));
    // U モードで M 権限の CSR (mstatus, 0x300) に触ると不正命令になる。
    let pc = env.pc;
    let r = env.step(|b| sem::csrrs(b, Gpr(1), Gpr(0), Csr(0x300), pc));
    assert!(matches!(r, Err(InterpExit::Exception(e)) if e.code == 2 && e.addr == Some(pc)));
    // U モードで未定義の U 権限 CSR (0x010) に触ると不正命令になる。
    let pc = env.pc;
    let r = env.step(|b| sem::csrrs(b, Gpr(1), Gpr(0), Csr(0x010), pc));
    assert!(matches!(r, Err(InterpExit::Exception(e)) if e.code == 2 && e.addr == Some(pc)));
    // M モードでは M 権限の CSR に触れる。
    env.backend.set(priv_of(), 3);
    let pc = env.pc;
    env.step(|b| sem::csrrw(b, Gpr(1), Gpr(0), Csr(0x300), pc))
        .unwrap();
    // 読み出し専用への書き込みは M モードでも不正命令になる。
    let pc = env.pc;
    let r = env.step(|b| sem::csrrw(b, Gpr(1), Gpr(0), Csr(0xC00), pc));
    assert!(matches!(r, Err(InterpExit::Exception(e)) if e.code == 2 && e.addr == Some(pc)));
    // M モードでの読み出し専用の読み出しは成功する。
    let pc = env.pc;
    env.step(|b| sem::csrrs(b, Gpr(1), Gpr(0), Csr(0xC00), pc))
        .unwrap();
}

#[test]
fn lr_sc_success_and_fail() {
    let mut env = env();
    env.map_rw(0x0, 1).unwrap();
    env.step(|b| sem::addi(b, Gpr(1), Gpr(0), 0x100)).unwrap();
    env.step(|b| sem::addi(b, Gpr(2), Gpr(0), 7)).unwrap();
    env.step(|b| sem::sw(b, Gpr(1), Gpr(2), 0)).unwrap();
    // 予約して条件付きストア。成功で 0 を書く。
    env.step(|b| sem::lr_w(b, Gpr(3), Gpr(1), 0)).unwrap();
    assert_eq!(x(&mut env, 3), 7);
    env.step(|b| sem::addi(b, Gpr(4), Gpr(0), 9)).unwrap();
    env.step(|b| sem::sc_w(b, Gpr(5), Gpr(1), Gpr(4), 0))
        .unwrap();
    assert_eq!(x(&mut env, 5), 0);
    env.step(|b| sem::lw(b, Gpr(6), Gpr(1), 0)).unwrap();
    assert_eq!(x(&mut env, 6), 9);
    // 予約なしのストアは予約を奪う。SC は失敗し 0 以外を書く。
    env.step(|b| sem::lr_w(b, Gpr(3), Gpr(1), 0)).unwrap();
    env.step(|b| sem::sw(b, Gpr(1), Gpr(2), 0)).unwrap();
    env.step(|b| sem::sc_w(b, Gpr(5), Gpr(1), Gpr(4), 0))
        .unwrap();
    assert_ne!(x(&mut env, 5), 0);
    env.step(|b| sem::lw(b, Gpr(6), Gpr(1), 0)).unwrap();
    assert_eq!(x(&mut env, 6), 7);
}

#[test]
fn amo_ops() {
    let mut env = env();
    env.map_rw(0x0, 1).unwrap();
    env.step(|b| sem::addi(b, Gpr(1), Gpr(0), 0x200)).unwrap();
    env.step(|b| sem::addi(b, Gpr(2), Gpr(0), 12)).unwrap();
    env.step(|b| sem::sw(b, Gpr(1), Gpr(2), 0)).unwrap();
    // SWAP：古い値を返し、新しい値を置く。
    env.step(|b| sem::addi(b, Gpr(3), Gpr(0), 5)).unwrap();
    env.step(|b| sem::amoswap_w(b, Gpr(4), Gpr(1), Gpr(3), 0))
        .unwrap();
    assert_eq!(x(&mut env, 4), 12);
    env.step(|b| sem::lw(b, Gpr(5), Gpr(1), 0)).unwrap();
    assert_eq!(x(&mut env, 5), 5);
    // ADD：5 + 12。
    env.step(|b| sem::amoadd_d(b, Gpr(4), Gpr(1), Gpr(2), 0))
        .unwrap();
    assert_eq!(x(&mut env, 4), 5);
    env.step(|b| sem::ld(b, Gpr(5), Gpr(1), 0)).unwrap();
    assert_eq!(x(&mut env, 5), 17);
    // MIN（符号付き）：-1 と 17 では -1 が残る。
    env.step(|b| sem::addi(b, Gpr(6), Gpr(0), -1)).unwrap();
    env.step(|b| sem::amomin_d(b, Gpr(4), Gpr(1), Gpr(6), 0))
        .unwrap();
    assert_eq!(x(&mut env, 4), 17);
    env.step(|b| sem::ld(b, Gpr(5), Gpr(1), 0)).unwrap();
    assert_eq!(x(&mut env, 5), u64::MAX);
    // MAXU（符号なし）：0xffff... と 1 では 0xffff... が残る。
    env.step(|b| sem::addi(b, Gpr(7), Gpr(0), 1)).unwrap();
    env.step(|b| sem::amomaxu_d(b, Gpr(4), Gpr(1), Gpr(7), 0))
        .unwrap();
    assert_eq!(x(&mut env, 4), u64::MAX);
    env.step(|b| sem::ld(b, Gpr(5), Gpr(1), 0)).unwrap();
    assert_eq!(x(&mut env, 5), u64::MAX);
}

#[test]
fn f_arithmetic() {
    use polyisa_guest_riscv::sem::Fpr;
    let mut env = env();
    // f1 = 1.5、f2 = 2.25 を置く。
    env.backend.set(
        Fpr(1).state(),
        0x0000_0000_3fc0_0000 | 0xffff_ffff_0000_0000,
    );
    env.backend.set(
        Fpr(2).state(),
        0x0000_0000_4010_0000 | 0xffff_ffff_0000_0000,
    );
    env.step(|b| sem::fadd_s(b, Fpr(3), Fpr(1), Fpr(2)))
        .unwrap();
    assert_eq!(xf(&mut env, 3), 0x4070_0000);
    env.step(|b| sem::fsub_s(b, Fpr(3), Fpr(2), Fpr(1)))
        .unwrap();
    assert_eq!(xf(&mut env, 3), 0x3f40_0000);
    env.step(|b| sem::fmul_s(b, Fpr(3), Fpr(1), Fpr(2)))
        .unwrap();
    assert_eq!(xf(&mut env, 3), 0x4058_0000);
    env.step(|b| sem::fdiv_s(b, Fpr(3), Fpr(2), Fpr(1)))
        .unwrap();
    assert_eq!(xf(&mut env, 3), 0x3fc0_0000);
    // NXが立つことを確認（2.25/1.5は正確なので別途不正確演算で確認）。
    env.backend.set(
        Fpr(1).state(),
        0x0000_0000_3fc0_0000 | 0xffff_ffff_0000_0000,
    );
    env.backend.set(
        Fpr(2).state(),
        0x0000_0000_3dcc_cccd | 0xffff_ffff_0000_0000,
    );
    env.step(|b| sem::fadd_s(b, Fpr(3), Fpr(1), Fpr(2)))
        .unwrap();
    let fcsr: u64 = env
        .backend
        .get(polyisa_sem::StateRef::<polyisa_sem::W64>::from_offset(
            core::mem::offset_of!(polyisa_guest_riscv::CpuState, csr) + 3 * 8,
        ));
    assert_ne!(fcsr & 1, 0, "NXが立つはず");
}

#[test]
fn f_sqrt_min_max_class() {
    use polyisa_guest_riscv::sem::Fpr;
    let mut env = env();
    env.backend.set(
        Fpr(1).state(),
        0x0000_0000_4000_0000 | 0xffff_ffff_0000_0000,
    );
    env.step(|b| sem::fsqrt_s(b, Fpr(2), Fpr(1))).unwrap();
    assert_eq!(xf(&mut env, 2), 0x3fb5_04f3);
    env.backend.set(
        Fpr(3).state(),
        0x0000_0000_7fc0_0000 | 0xffff_ffff_0000_0000,
    );
    // NaN が混ざるともう一方が選ばれる。
    env.step(|b| sem::fmin_s(b, Fpr(4), Fpr(1), Fpr(3)))
        .unwrap();
    assert_eq!(xf(&mut env, 4), 0x4000_0000);
    env.step(|b| sem::fmax_s(b, Fpr(4), Fpr(3), Fpr(1)))
        .unwrap();
    assert_eq!(xf(&mut env, 4), 0x4000_0000);
    // 分類：+normal は 64、-0 は 8、qNaN は 512。
    env.step(|b| sem::fclass_s(b, Gpr(5), Fpr(1))).unwrap();
    assert_eq!(x(&mut env, 5), 64);
    env.backend.set(
        Fpr(6).state(),
        0x0000_0000_8000_0000 | 0xffff_ffff_0000_0000,
    );
    env.step(|b| sem::fclass_s(b, Gpr(5), Fpr(6))).unwrap();
    assert_eq!(x(&mut env, 5), 8);
    env.step(|b| sem::fclass_s(b, Gpr(5), Fpr(3))).unwrap();
    assert_eq!(x(&mut env, 5), 512);
}

#[test]
fn f_convert_move_compare() {
    use polyisa_guest_riscv::sem::Fpr;
    let mut env = env();
    env.map_rw(0x0, 1).unwrap();
    // 1.5 を置く。
    env.backend.set(
        Fpr(1).state(),
        0x0000_0000_3fc0_0000 | 0xffff_ffff_0000_0000,
    );
    // fcvt.w.s(1.5) = 2、fcvt.s.w(2) = 2.0。
    env.step(|b| sem::fcvt_w_s(b, Gpr(2), Fpr(1), 0)).unwrap();
    assert_eq!(x(&mut env, 2), 2);
    env.step(|b| sem::fcvt_s_w(b, Fpr(3), Gpr(2), 0)).unwrap();
    assert_eq!(xf(&mut env, 3), 0x4000_0000);
    // feq / flt。
    env.step(|b| sem::feq_s(b, Gpr(4), Fpr(1), Fpr(1))).unwrap();
    assert_eq!(x(&mut env, 4), 1);
    env.step(|b| sem::flt_s(b, Gpr(4), Fpr(1), Fpr(3))).unwrap();
    assert_eq!(x(&mut env, 4), 1);
    // fsgnj で符号を入れ替える。
    env.step(|b| sem::fsgnjn_s(b, Fpr(4), Fpr(1), Fpr(3)))
        .unwrap();
    assert_eq!(xf(&mut env, 4), 0xbfc0_0000);
    // fmv.x.w / fmv.w.x でビット列を往復させる。
    env.step(|b| sem::fmv_x_w(b, Gpr(5), Fpr(1))).unwrap();
    assert_eq!(x(&mut env, 5), 0x0000_0000_3fc0_0000);
    env.step(|b| sem::fmv_w_x(b, Fpr(6), Gpr(5))).unwrap();
    assert_eq!(xf(&mut env, 6), 0x3fc0_0000);
    // fsw / flw でメモリを往復させる。
    env.step(|b| sem::addi(b, Gpr(7), Gpr(0), 0x100)).unwrap();
    env.step(|b| sem::fsw(b, Gpr(7), Fpr(1), 0)).unwrap();
    env.step(|b| sem::flw(b, Fpr(8), Gpr(7), 0)).unwrap();
    assert_eq!(xf(&mut env, 8), 0x3fc0_0000);
}

#[test]
fn d_arithmetic() {
    use polyisa_guest_riscv::sem::Fpr;
    let mut env = env();
    env.map_rw(0, 1).unwrap();
    // f64 1.5 と 2.25 を置く。
    env.backend.set(Fpr(1).state(), 0x3FF8_0000_0000_0000);
    env.backend.set(Fpr(2).state(), 0x4002_0000_0000_0000);
    env.step(|b| sem::fadd_d(b, Fpr(3), Fpr(1), Fpr(2)))
        .unwrap();
    assert_eq!(x64(&mut env, 3), 0x400E_0000_0000_0000);
    env.step(|b| sem::fsub_d(b, Fpr(3), Fpr(2), Fpr(1)))
        .unwrap();
    assert_eq!(x64(&mut env, 3), 0x3FE8_0000_0000_0000);
    env.step(|b| sem::fmul_d(b, Fpr(3), Fpr(1), Fpr(2)))
        .unwrap();
    assert_eq!(x64(&mut env, 3), 0x400B_0000_0000_0000);
    env.step(|b| sem::fdiv_d(b, Fpr(3), Fpr(2), Fpr(1)))
        .unwrap();
    assert_eq!(x64(&mut env, 3), 0x3FF8_0000_0000_0000);
    env.step(|b| sem::fsqrt_d(b, Fpr(3), Fpr(2))).unwrap();
    assert_eq!(x64(&mut env, 3), 0x3FF8_0000_0000_0000);
    // 比較と分類。
    env.step(|b| sem::flt_d(b, Gpr(4), Fpr(1), Fpr(2))).unwrap();
    assert_eq!(x(&mut env, 4), 1);
    env.step(|b| sem::feq_d(b, Gpr(4), Fpr(1), Fpr(1))).unwrap();
    assert_eq!(x(&mut env, 4), 1);
    env.step(|b| sem::fclass_d(b, Gpr(4), Fpr(1))).unwrap();
    assert_eq!(x(&mut env, 4), 64);
    // 整数との往復。1.5 は偶数丸めで 2 になる。
    env.step(|b| sem::fcvt_l_d(b, Gpr(4), Fpr(1), 0)).unwrap();
    assert_eq!(x(&mut env, 4), 2);
    env.step(|b| sem::fcvt_d_l(b, Fpr(5), Gpr(4), 0)).unwrap();
    assert_eq!(x64(&mut env, 5), 0x4000_0000_0000_0000);
    env.step(|b| sem::fcvt_s_d(b, Fpr(6), Fpr(1), 0)).unwrap();
    assert_eq!(xf(&mut env, 6), 0x3FC0_0000);
    // fmv.d.x / fmv.x.d / fld / fsd でビット列を往復させる。
    env.step(|b| sem::addi(b, Gpr(7), Gpr(0), 0x300)).unwrap();
    env.step(|b| sem::fmv_d_x(b, Fpr(7), Gpr(7))).unwrap();
    assert_eq!(x64(&mut env, 7), 0x300);
    env.step(|b| sem::fmv_x_d(b, Gpr(8), Fpr(2))).unwrap();
    assert_eq!(x(&mut env, 8), 0x4002_0000_0000_0000);
    env.step(|b| sem::fsd(b, Gpr(7), Fpr(2), 0)).unwrap();
    env.step(|b| sem::fld(b, Fpr(9), Gpr(7), 0)).unwrap();
    assert_eq!(x64(&mut env, 9), 0x4002_0000_0000_0000);
}

#[test]
fn fma_fused() {
    use polyisa_guest_riscv::sem::Fpr;
    let mut env = env();
    env.map_rw(0, 1).unwrap();
    // 単一丸めの証人値（ホスト mul_add・高精度演算と突合済み）。
    // f32: a=0xbbed0000, b=0xfe466d80, c=0xd1e23e49。
    for (i, bits) in [0xbbed0000u64, 0xfe466d80, 0xd1e23e49].iter().enumerate() {
        env.backend
            .set(Fpr(i as u8 + 1).state(), 0xffff_ffff_0000_0000 | bits);
    }
    env.step(|b| sem::fmadd_s(b, Fpr(4), Fpr(1), Fpr(2), Fpr(3)))
        .unwrap();
    assert_eq!(xf(&mut env, 4), 0x7ab7_b35f);
    env.step(|b| sem::fmsub_s(b, Fpr(5), Fpr(1), Fpr(2), Fpr(3)))
        .unwrap();
    assert_eq!(xf(&mut env, 5), 0x7ab7_b360);
    env.step(|b| sem::fnmadd_s(b, Fpr(6), Fpr(1), Fpr(2), Fpr(3)))
        .unwrap();
    assert_eq!(xf(&mut env, 6), 0xfab7_b35f);
    env.step(|b| sem::fnmsub_s(b, Fpr(7), Fpr(1), Fpr(2), Fpr(3)))
        .unwrap();
    assert_eq!(xf(&mut env, 7), 0xfab7_b360);
    // f64: a=0xb65feea97d824264, b=0x718d4d05e8e22743, c=0xe63658c912d0498d。
    for (i, bits) in [
        0xb65feea97d824264u64,
        0x718d4d05e8e22743,
        0xe63658c912d0498d,
    ]
    .iter()
    .enumerate()
    {
        env.backend.set(Fpr(i as u8 + 11).state(), *bits);
    }
    env.step(|b| sem::fmadd_d(b, Fpr(14), Fpr(11), Fpr(12), Fpr(13)))
        .unwrap();
    assert_eq!(x64(&mut env, 14), 0xe7fd3d25c8a80f51);
    env.step(|b| sem::fmsub_d(b, Fpr(15), Fpr(11), Fpr(12), Fpr(13)))
        .unwrap();
    assert_eq!(x64(&mut env, 15), 0xe7fd3d25c5dcf62e);
    env.step(|b| sem::fnmsub_d(b, Fpr(16), Fpr(11), Fpr(12), Fpr(13)))
        .unwrap();
    assert_eq!(x64(&mut env, 16), 0x67fd3d25c5dcf62e);
    env.step(|b| sem::fnmadd_d(b, Fpr(17), Fpr(11), Fpr(12), Fpr(13)))
        .unwrap();
    assert_eq!(x64(&mut env, 17), 0x67fd3d25c8a80f51);
}

#[test]
fn c_compressed() {
    let mut env = env();
    env.map_rw(0, 1).unwrap();
    env.pc = 0x1_0000;
    // C.ADDI / C.LI / C.ADDIW：32ビット版への委譲。
    env.step(|b| sem::c_addi(b, Gpr(1), 5)).unwrap();
    assert_eq!(x(&mut env, 1), 5);
    env.step(|b| sem::c_li(b, Gpr(2), -3)).unwrap();
    assert_eq!(x(&mut env, 2), 0xffff_ffff_ffff_fffd);
    env.step(|b| sem::c_addiw(b, Gpr(3), 1)).unwrap();
    assert_eq!(x(&mut env, 3), 1);
    // C.ADDI4SPN：x2基準。
    env.step(|b| sem::addi(b, Gpr(2), Gpr(0), 0x100)).unwrap();
    env.step(|b| sem::c_addi4spn(b, Gpr(4), 16)).unwrap();
    assert_eq!(x(&mut env, 4), 0x110);
    // C.SLLI。
    env.step(|b| sem::c_slli(b, Gpr(4), 2)).unwrap();
    assert_eq!(x(&mut env, 4), 0x440);
    // C.LW / C.SW、C.LD / C.SD、C.LWSP系の往復。
    env.step(|b| sem::c_sw(b, Gpr(2), Gpr(4), 0)).unwrap();
    env.step(|b| sem::c_lw(b, Gpr(5), Gpr(2), 0)).unwrap();
    assert_eq!(x(&mut env, 5), 0x440);
    env.step(|b| sem::c_sd(b, Gpr(2), Gpr(4), 8)).unwrap();
    env.step(|b| sem::c_ld(b, Gpr(6), Gpr(2), 8)).unwrap();
    assert_eq!(x(&mut env, 6), 0x440);
    env.step(|b| sem::c_swsp(b, Gpr(4), 0)).unwrap();
    env.step(|b| sem::c_lwsp(b, Gpr(7), 0)).unwrap();
    assert_eq!(x(&mut env, 7), 0x440);
    env.step(|b| sem::c_sdsp(b, Gpr(4), 8)).unwrap();
    env.step(|b| sem::c_ldsp(b, Gpr(8), 8)).unwrap();
    assert_eq!(x(&mut env, 8), 0x440);
    // C.FLD / C.FSD、C.FLDSP / C.FSDSP の往復。
    use polyisa_guest_riscv::sem::Fpr;
    env.backend.set(Fpr(10).state(), 0x4002_0000_0000_0000);
    env.step(|b| sem::c_fsd(b, Gpr(2), Fpr(10), 16)).unwrap();
    env.step(|b| sem::c_fld(b, Fpr(11), Gpr(2), 16)).unwrap();
    assert_eq!(x64(&mut env, 11), 0x4002_0000_0000_0000);
    env.step(|b| sem::c_fsdsp(b, Fpr(10), 24)).unwrap();
    env.step(|b| sem::c_fldsp(b, Fpr(12), 24)).unwrap();
    assert_eq!(x64(&mut env, 12), 0x4002_0000_0000_0000);
    // C.J / C.BEQZ / C.BNEZ。
    let pc = env.pc;
    env.step(|b| sem::c_j(b, pc, 16)).unwrap();
    assert_eq!(env.pc, 0x1_0010);
    let pc = env.pc;
    env.step(|b| sem::c_beqz(b, Gpr(0), pc, 16)).unwrap();
    assert_eq!(env.pc, 0x1_0020);
    let pc = env.pc;
    env.step(|b| sem::c_bnez(b, Gpr(0), pc, 16)).unwrap();
    assert_eq!(env.pc, 0x1_0020);
    // C.SRLI / C.SRAI / C.ANDI / C.SUB・XOR・OR・AND / C.SUBW・ADDW。
    env.step(|b| sem::addi(b, Gpr(9), Gpr(0), -8)).unwrap();
    env.step(|b| sem::c_srli(b, Gpr(9), 2)).unwrap();
    assert_eq!(x(&mut env, 9), 0x3fff_ffff_ffff_fffe);
    env.step(|b| sem::c_srai(b, Gpr(9), 2)).unwrap();
    assert_eq!(x(&mut env, 9), 0x0fff_ffff_ffff_ffff);
    env.step(|b| sem::c_andi(b, Gpr(9), 0xff)).unwrap();
    assert_eq!(x(&mut env, 9), 0xff);
    env.step(|b| sem::addi(b, Gpr(10), Gpr(0), 10)).unwrap();
    env.step(|b| sem::c_sub(b, Gpr(10), Gpr(9))).unwrap();
    assert_eq!(x(&mut env, 10), 0xffff_ffff_ffff_ff0b);
    env.step(|b| sem::c_addw(b, Gpr(10), Gpr(9))).unwrap();
    assert_eq!(x(&mut env, 10), 0xa);
    // C.LUI / C.ADDI16SP の分岐。
    env.step(|b| sem::c_lui_addi16sp(b, Gpr(11), 1)).unwrap();
    assert_eq!(x(&mut env, 11), 0x1000);
    env.step(|b| sem::addi(b, Gpr(2), Gpr(0), 0x100)).unwrap();
    env.step(|b| sem::c_lui_addi16sp(b, Gpr(2), 16)).unwrap();
    assert_eq!(x(&mut env, 2), 0x110);
    // C.JAL（RV32）の展開。
    let pc = env.pc;
    env.step(|b| sem::c_jal(b, pc, 16)).unwrap();
    assert_eq!(env.pc, pc + 16);
    assert_eq!(x(&mut env, 1), (pc + 2) & 0xffff_ffff);
}

#[test]
fn c_jump_moves() {
    use polyisa_guest_riscv::sem::Fpr;
    let mut env = env();
    env.pc = 0x1_0000;
    env.map_rw(0, 1).unwrap();
    // C.MV / C.ADD。
    env.step(|b| sem::addi(b, Gpr(2), Gpr(0), 7)).unwrap();
    env.step(|b| sem::c_mv(b, Gpr(1), Gpr(2))).unwrap();
    assert_eq!(x(&mut env, 1), 7);
    env.step(|b| sem::c_add(b, Gpr(1), Gpr(2))).unwrap();
    assert_eq!(x(&mut env, 1), 14);
    // C.JR / C.JALR。
    env.step(|b| sem::addi(b, Gpr(3), Gpr(0), 0x40)).unwrap();
    let pc = env.pc;
    env.step(|b| sem::c_jr(b, Gpr(3), pc)).unwrap();
    assert_eq!(env.pc, 0x40);
    assert_eq!(x(&mut env, 1), 14);
    env.pc = pc;
    env.step(|b| sem::c_jalr(b, Gpr(3), pc)).unwrap();
    assert_eq!(env.pc, 0x40);
    assert_eq!(x(&mut env, 1), pc + 2);
    // RV32 版は戻りと飛び先を32ビットで包む。
    env.pc = pc;
    env.step(|b| sem::c_jalr_rv32(b, Gpr(3), pc)).unwrap();
    assert_eq!(env.pc, 0x40);
    assert_eq!(x(&mut env, 1), (pc + 2) & 0xffff_ffff);
    env.step(|b| sem::c_jr_rv32(b, Gpr(3), pc)).unwrap();
    assert_eq!(env.pc, 0x40);
    // C.EBREAK は ebreak と同じ退出になる。
    env.pc = 0x1_0080;
    let r = env.step(|b| sem::c_ebreak(b, 0x1_0080));
    assert!(matches!(r, Err(InterpExit::Exception(_))));
    // C.FLW / C.FSW、C.FLWSP / C.FSWSP の往復（RV32符号化・RV64実行）。
    env.step(|b| sem::addi(b, Gpr(4), Gpr(0), 0x100)).unwrap();
    env.backend.set(Fpr(10).state(), 0xFFFF_FFFF_3FC0_0000);
    env.step(|b| sem::c_fsw(b, Gpr(4), Fpr(10), 0)).unwrap();
    env.step(|b| sem::c_flw(b, Fpr(11), Gpr(4), 0)).unwrap();
    assert_eq!(xf(&mut env, 11), 0x3FC0_0000);
    env.step(|b| sem::addi(b, Gpr(2), Gpr(0), 0x100)).unwrap();
    env.step(|b| sem::c_fswsp(b, Fpr(10), 8)).unwrap();
    env.step(|b| sem::c_flwsp(b, Fpr(12), 8)).unwrap();
    assert_eq!(xf(&mut env, 12), 0x3FC0_0000);
}

#[test]
fn rv32_wrap_semantics() {
    let mut env = env();
    env.map_rw(0, 1).unwrap();
    // 0xFFFFFFFF + 1 は 32 ビットで包んで 0 になる（RV64 では 0x100000000）。
    env.step(|b| sem::addi_rv32(b, Gpr(1), Gpr(0), -1)).unwrap();
    assert_eq!(x(&mut env, 1), 0xffff_ffff_ffff_ffff);
    env.step(|b| sem::addi_rv32(b, Gpr(2), Gpr(0), 1)).unwrap();
    env.step(|b| sem::add_rv32(b, Gpr(3), Gpr(1), Gpr(2)))
        .unwrap();
    assert_eq!(x(&mut env, 3), 0);
    // 符号付き比較では -1 < 1、符号なしでは 0xFFFFFFFF > 1。
    env.step(|b| sem::slt_rv32(b, Gpr(4), Gpr(1), Gpr(2)))
        .unwrap();
    assert_eq!(x(&mut env, 4), 1);
    env.step(|b| sem::sltu_rv32(b, Gpr(4), Gpr(1), Gpr(2)))
        .unwrap();
    assert_eq!(x(&mut env, 4), 0);
    // 算術右シフトは符号を伸ばす。slli は下位 5 ビットだけ使う。
    env.step(|b| sem::srai_rv32(b, Gpr(5), Gpr(1), 31)).unwrap();
    assert_eq!(x(&mut env, 5), 0xffff_ffff_ffff_ffff);
    env.step(|b| sem::slli_rv32(b, Gpr(5), Gpr(2), 33)).unwrap();
    assert_eq!(x(&mut env, 5), 2);
    // 7 % -1 = 0。(-1)*(-1) の上位 32 ビットは 0。
    env.step(|b| sem::addi_rv32(b, Gpr(6), Gpr(0), 7)).unwrap();
    env.step(|b| sem::rem_rv32(b, Gpr(7), Gpr(6), Gpr(1)))
        .unwrap();
    assert_eq!(x(&mut env, 7), 0);
    env.step(|b| sem::mulh_rv32(b, Gpr(7), Gpr(1), Gpr(1)))
        .unwrap();
    assert_eq!(x(&mut env, 7), 0);
    // ロードストアは下位 32 ビットで往復する。
    env.step(|b| sem::addi_rv32(b, Gpr(9), Gpr(0), 0x100))
        .unwrap();
    env.step(|b| sem::sw_rv32(b, Gpr(9), Gpr(1), 0)).unwrap();
    env.step(|b| sem::lw_rv32(b, Gpr(10), Gpr(9), 0)).unwrap();
    assert_eq!(x(&mut env, 10), 0xffff_ffff_ffff_ffff);
    // JAL の戻りと飛び先は 32 ビットで包む。
    env.step(|b| sem::jal_rv32(b, Gpr(8), 0xffff_fff0, 32))
        .unwrap();
    assert_eq!(env.pc, 0x10);
    assert_eq!(x(&mut env, 8), 0xffff_ffff_ffff_fff4);
    // JALR のベース加算も 32 ビットで包む。
    env.step(|b| sem::addi_rv32(b, Gpr(11), Gpr(0), -256))
        .unwrap();
    env.step(|b| sem::jalr_rv32(b, Gpr(0), Gpr(11), 0x1000, 0x10))
        .unwrap();
    assert_eq!(env.pc, 0xffff_ff10);
    assert_eq!(x(&mut env, 0), 0);
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

#[test]
fn store_fault_leaves_state_unchanged() {
    let mut env = env();
    // 書き込み先に値を置き、退避レジスタを初期化する。
    env.step(|b| sem::addi(b, Gpr(1), Gpr(0), 0x1_0000))
        .unwrap();
    env.step(|b| sem::addi(b, Gpr(2), Gpr(0), 0x5a)).unwrap();
    env.step(|b| sem::sw(b, Gpr(1), Gpr(2), 0)).unwrap();
    env.step(|b| sem::addi(b, Gpr(3), Gpr(0), 0)).unwrap();
    // 未写像へのストアは失敗し、rd と既存メモリを変えない。
    let r = env.step(|b| sem::sw(b, Gpr(1), Gpr(2), 0x1_0000));
    assert!(r.is_err());
    assert_eq!(x(&mut env, 3), 0);
    env.step(|b| sem::lw(b, Gpr(4), Gpr(1), 0)).unwrap();
    assert_eq!(x(&mut env, 4), 0x5a);
    // AMO も同様に、失敗時は rd を変えない。
    env.step(|b| sem::addi(b, Gpr(5), Gpr(0), 0)).unwrap();
    let r = env.step(|b| sem::amoswap_w(b, Gpr(5), Gpr(1), Gpr(2), 0x1_0000));
    assert!(r.is_err());
    assert_eq!(x(&mut env, 5), 0);
    // 未写像の読み出しは値が要るため未定義にしない（読み出し側の確認）。
    let r = env.step(|b| sem::lw(b, Gpr(6), Gpr(1), 0x1_0000));
    assert!(r.is_err());
    assert_eq!(x(&mut env, 6), 0);
}
