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
    // cycle (0xC00) に書いて読む。
    env.step(|b| sem::addi(b, Gpr(1), Gpr(0), 42)).unwrap();
    env.step(|b| sem::csrrw(b, Gpr(2), Gpr(1), Csr(0xC00)))
        .unwrap();
    assert_eq!(x(&mut env, 2), 0);
    env.step(|b| sem::csrrw(b, Gpr(2), Gpr(0), Csr(0xC00)))
        .unwrap();
    assert_eq!(x(&mut env, 2), 42);
    // ビットを立てる。戻り値は書き換え前の値。
    env.step(|b| sem::csrrsi(b, Gpr(3), 0b101, Csr(0xC00)))
        .unwrap();
    assert_eq!(x(&mut env, 3), 0);
    // 0b011111 を置き、x1=0b101010 のビットを落とす（0b011111 & ~0b101010 = 0b010101）。
    env.step(|b| sem::csrrwi(b, Gpr(0), 0b11111, Csr(0xC00)))
        .unwrap();
    env.step(|b| sem::csrrc(b, Gpr(3), Gpr(1), Csr(0xC00)))
        .unwrap();
    assert_eq!(x(&mut env, 3), 0b011111);
    env.step(|b| sem::csrrs(b, Gpr(4), Gpr(0), Csr(0xC00)))
        .unwrap();
    assert_eq!(x(&mut env, 4), 0b010101);
    // rs1=x0 の CSRRS は書き込まない。
    env.step(|b| sem::csrrs(b, Gpr(3), Gpr(0), Csr(0xC00)))
        .unwrap();
    assert_eq!(x(&mut env, 3), 0b010101);
    // uimm=0 の CSRRSI は書き込まない。
    env.step(|b| sem::csrrsi(b, Gpr(3), 0, Csr(0xC00))).unwrap();
    assert_eq!(x(&mut env, 3), 0b010101);
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
