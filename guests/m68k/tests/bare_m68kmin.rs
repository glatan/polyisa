// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! m68k 最小の命令単位のテスト。裸実行環境で骨格の振り分けを検査する。
//! 出典は SPEC-M68K-PRM (M68000PM/AD Rev 1) である。
//! Ref: SPEC-M68K-PRM (Rev 1).

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::InterpExit;
use polyisa_guest_m68k::ea::{self, Ea};
use polyisa_guest_m68k::sem::{self, A, D, Ssp, Usp};
use polyisa_guest_m68k::{CpuState, Insn};
use polyisa_mem::{Access, AccessKind, Align, Endian, VirtAddr};
use polyisa_sem::Backend as _;

/// データ読み出し（BE・自然整列）のテスト用アクセス。
const DRD: Access = Access {
    endian: Endian::Be,
    align: Align::Natural,
    kind: AccessKind::DataRead,
};

fn env() -> BareEnv {
    BareEnv::new(core::mem::size_of::<CpuState>())
}

/// 命令拡張語を書き込むためのマッピング済み環境。
fn env_with_code(words: &[u16]) -> BareEnv {
    let mut env = env();
    // 拡張語は Fetch として読むので X を含める。
    env.backend
        .mem
        .map(VirtAddr(0x1000), 1, polyisa_mem::Perms(0b111))
        .unwrap();
    let mut bytes = Vec::new();
    for w in words {
        bytes.extend_from_slice(&w.to_be_bytes());
    }
    env.backend.mem.write(VirtAddr(0x1000), &bytes).unwrap();
    env
}

/// 命令語（0x1000）に加えて 0x4000 にデータページを写像する。
fn env_with_data(words: &[u16], data: &[u8]) -> BareEnv {
    let mut env = env_with_code(words);
    env.backend
        .mem
        .map(VirtAddr(0x4000), 1, polyisa_mem::Perms::RW)
        .unwrap();
    env.backend.mem.write(VirtAddr(0x4000), data).unwrap();
    env
}

/// `Ea` の結果を検査用の値にする。
fn ea_value(ea: Ea<polyisa_engine::interp::InterpBackend>) -> u64 {
    match ea {
        Ea::D(n) => 0xD000 + u64::from(n),
        Ea::A(n) => 0xA000 + u64::from(n),
        Ea::Addr(a) => a,
        Ea::Imm(v) => u64::from(v),
    }
}

#[test]
fn nop_executes() {
    let mut env = env();
    env.step(|b| sem::exec(b, Insn::Nop, 0x4E71, 0)).unwrap();
}

#[test]
fn illegal_raises_vector4() {
    let mut env = env();
    let e = env
        .step(|b| sem::exec(b, Insn::Illegal, 0x4AFC, 0))
        .expect_err("illegal は例外");
    match e {
        InterpExit::Exception(x) => assert_eq!(x.code, 4),
        other => panic!("unexpected exit: {other:?}"),
    }
}

// ---- EA 評価（B2: デコード方式の EA 解釈経路） ----

#[test]
fn ea_reg_direct() {
    let mut env = env();
    let (e, n) = env.step(|b| ea::eval(b, 0, 3, 4, 0x1000)).unwrap();
    assert_eq!(ea_value(e), 0xD003);
    assert_eq!(n, 0);
    let (e, n) = env.step(|b| ea::eval(b, 1, 2, 4, 0x1000)).unwrap();
    assert_eq!(ea_value(e), 0xA002);
    assert_eq!(n, 0);
}

#[test]
fn ea_areg_indirect_and_prepost() {
    let mut env = env();
    env.backend.set(A(2).state(), 0x4000);
    // (A2)
    let (e, n) = env.step(|b| ea::eval(b, 2, 2, 4, 0x1000)).unwrap();
    assert_eq!(ea_value(e), 0x4000);
    assert_eq!(n, 0);
    // (A2)+ long: アドレスは更新前、A2 は +4。
    let (e, n) = env.step(|b| ea::eval(b, 3, 2, 4, 0x1000)).unwrap();
    assert_eq!(ea_value(e), 0x4000);
    assert_eq!(n, 0);
    assert_eq!(env.backend.get(A(2).state()), 0x4004);
    // -(A2) long: A2 は -4 されてから使われる。
    let (e, n) = env.step(|b| ea::eval(b, 4, 2, 4, 0x1000)).unwrap();
    assert_eq!(ea_value(e), 0x4000);
    assert_eq!(n, 0);
    assert_eq!(env.backend.get(A(2).state()), 0x4000);
}

#[test]
fn ea_a7_byte_adjusts_by_two() {
    let mut env = env();
    env.backend.set(Usp.state(), 0x2000);
    // -(A7) byte は 2 下げる（語境界の維持）。
    let (e, _) = env.step(|b| ea::eval(b, 4, 7, 1, 0x1000)).unwrap();
    assert_eq!(ea_value(e), 0x1FFE);
    assert_eq!(env.backend.get(Usp.state()), 0x1FFE);
}

#[test]
fn ea_d16_and_abs() {
    let mut env = env_with_code(&[0x0010, 0x8000, 0x1234, 0x5678]);
    env.backend.set(A(1).state(), 0x3000);
    // d16(A1) = 0x3000 + 0x10。
    let (e, n) = env.step(|b| ea::eval(b, 5, 1, 4, 0x1000)).unwrap();
    assert_eq!(ea_value(e), 0x3010);
    assert_eq!(n, 1);
    // (xxx).W: 0x8000 は符号拡張で 0xFFFF8000。
    let (e, n) = env.step(|b| ea::eval(b, 7, 0, 4, 0x1002)).unwrap();
    assert_eq!(ea_value(e), 0xFFFF_8000);
    assert_eq!(n, 1);
    // (xxx).L: 0x12345678。
    let (e, n) = env.step(|b| ea::eval(b, 7, 1, 4, 0x1004)).unwrap();
    assert_eq!(ea_value(e), 0x1234_5678);
    assert_eq!(n, 2);
}

#[test]
fn ea_pc_relative() {
    let mut env = env_with_code(&[0x0020, 0x0000]);
    // d16(PC): 拡張語アドレス 0x1000 + 0x20。
    let (e, n) = env.step(|b| ea::eval(b, 7, 2, 4, 0x1000)).unwrap();
    assert_eq!(ea_value(e), 0x1020);
    assert_eq!(n, 1);
}

#[test]
fn ea_immediate() {
    let mut env = env_with_code(&[0xBEEF, 0x1234, 0xABCD]);
    // #imm word。
    let (e, n) = env.step(|b| ea::eval(b, 7, 4, 2, 0x1000)).unwrap();
    assert_eq!(ea_value(e), 0xBEEF);
    assert_eq!(n, 1);
    // #imm long。
    let (e, n) = env.step(|b| ea::eval(b, 7, 4, 4, 0x1002)).unwrap();
    assert_eq!(ea_value(e), 0x1234_ABCD);
    assert_eq!(n, 2);
    assert_eq!(ea::ext_words(7, 4, 4), Some(2));
    assert_eq!(ea::ext_words(7, 4, 1), Some(1));
    // 未定義の組み合わせは拡張語を消費しない（合法性は eval が弾く）。
    assert_eq!(ea::ext_words(7, 5, 4), Some(0));
}

#[test]
fn ea_brief_index() {
    // A3.w + disp 0x40（bit15=A、14-12=3、11=W）。
    let mut env = env_with_code(&[0xB040]);
    env.backend.set(A(1).state(), 0x5000);
    env.backend.set(A(3).state(), 0x10);
    // d8(A1,A3.w): A3.w = 0x0010 sext、disp 0x40 → 0x5050。
    let (e, n) = env.step(|b| ea::eval(b, 6, 1, 4, 0x1000)).unwrap();
    assert_eq!(ea_value(e), 0x5050);
    assert_eq!(n, 1);
}

#[test]
fn ea_pc_indexed_and_wrap() {
    // D0.l + disp 0x20（bit15=D、14-12=0、11=L）。
    let mut env = env_with_code(&[0x0820]);
    env.backend.set(D(0).state(), 0xFFFF_FF80);
    // d8(PC,D0.l): -0x80 の索引で 0x1000 - 0x80 + 0x20。W32 で
    // 折り返すので 32bit 境界を跨いでも低位に収まる。
    let (e, n) = env.step(|b| ea::eval(b, 7, 3, 4, 0x1000)).unwrap();
    assert_eq!(ea_value(e), 0xFA0);
    assert_eq!(n, 1);
}

#[test]
fn ea_a7_supervisor_uses_ssp() {
    let mut env = env();
    env.backend.set(sem::sr_ref(), 1 << sem::sr_bit::S);
    env.backend.set(Ssp.state(), 0x7000);
    env.backend.set(Usp.state(), 0x2000);
    // SR.S=1 では A7 は SSP。(A7) indirect。
    let (e, _) = env.step(|b| ea::eval(b, 2, 7, 4, 0x1000)).unwrap();
    assert_eq!(ea_value(e), 0x7000);
    // 索引の A7 も SSP を読む（A7.w + disp 0 = 0xF000）。
    let mut env2 = env_with_code(&[0xF000]);
    env2.backend.set(sem::sr_ref(), 1 << sem::sr_bit::S);
    env2.backend.set(Ssp.state(), 0x7000);
    env2.backend.set(A(1).state(), 0x5000);
    let (e, _) = env2.step(|b| ea::eval(b, 6, 1, 4, 0x1000)).unwrap();
    assert_eq!(ea_value(e), 0x5000 + 0x7000);
}

#[test]
fn ea_imm_byte_uses_low_byte() {
    let mut env = env_with_code(&[0x12FF]);
    // #imm byte は拡張語の下位バイトのみ。
    let (e, n) = env.step(|b| ea::eval(b, 7, 4, 1, 0x1000)).unwrap();
    assert_eq!(ea_value(e), 0xFF);
    assert_eq!(n, 1);
}

#[test]
fn ea_reserved_mode7_is_illegal() {
    let mut env = env_with_code(&[0x0000]);
    let e = match env.step(|b| ea::eval(b, 7, 5, 4, 0x1000)) {
        Err(e) => e,
        Ok(_) => panic!("mode7 reg5 は未定義"),
    };
    match e {
        InterpExit::Exception(x) => assert_eq!(x.code, 4),
        other => panic!("unexpected exit: {other:?}"),
    }
}

#[test]
fn ea_ext_words_covers_eval() {
    // 代表組み合わせで ext_words と eval の消費語数を照合。
    let mut env = env_with_code(&[0x1234, 0x5678, 0x9ABC, 0xDEF0]);
    env.backend.set(A(0).state(), 0x2000);
    for (mode, reg, size) in [
        (0u8, 1u8, 4u32),
        (1, 1, 4),
        (2, 0, 4),
        (3, 0, 4),
        (4, 0, 4),
        (5, 0, 4),
        (6, 0, 4),
        (7, 0, 4),
        (7, 1, 4),
        (7, 2, 4),
        (7, 3, 4),
        (7, 4, 1),
        (7, 4, 2),
        (7, 4, 4),
    ] {
        // (An)+/-(An) は A0 を更新するので毎回戻す。
        env.backend.set(A(0).state(), 0x2000);
        let want = ea::ext_words(mode, reg, size).expect("定義済みの EA");
        let (_, got) = env.step(|b| ea::eval(b, mode, reg, size, 0x1000)).unwrap();
        assert_eq!(got, want, "mode={mode} reg={reg} size={size}");
    }
}

// ---- MOVE/MOVEA/MOVEQ（C1: 命令群の先頭） ----

#[test]
fn move_l_imm_to_d() {
    // move.l #0x12345678,D0: 0010 000 000 111 100 = 0x203C。
    let mut env = env_with_code(&[0x203C, 0x1234, 0x5678]);
    env.step(|b| sem::exec(b, Insn::MoveL, 0x203C, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0x1234_5678);
    assert_eq!(ea::insn_ext_words(Insn::MoveL, 0x203C), Some(2));
}

#[test]
fn move_b_d_to_d_flags() {
    // move.b D1,D0: 0001 000 000 000 001 = 0x1001。
    let mut env = env_with_code(&[0x1001]);
    env.backend.set(D(0).state(), 0xFF00);
    env.backend.set(D(1).state(), 0x1234_AB56);
    env.step(|b| sem::exec(b, Insn::MoveB, 0x1001, 0x1000))
        .unwrap();
    // 下位バイトのみ転送、上位は保持。
    assert_eq!(env.backend.get(D(0).state()), 0xFF56);
    // 0x56 は正なので N=0・Z=0。
    assert_eq!(env.backend.get(sem::ccr_ref()) & 0b1100, 0);
    // 負値は N を立てる。
    env.backend.set(D(1).state(), 0x80);
    env.step(|b| sem::exec(b, Insn::MoveB, 0x1001, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0xFF80);
    assert_ne!(env.backend.get(sem::ccr_ref()) & (1 << sem::sr_bit::N), 0);
}

#[test]
fn move_w_mem_to_d() {
    // move.w (A2),D0: 0011 000 000 010 010 = 0x3012。
    let mut env = env_with_data(&[0x3012], &0x8000u16.to_be_bytes());
    env.backend.set(A(2).state(), 0x4000);
    env.backend.set(D(0).state(), 0xDEAD_0000);
    env.step(|b| sem::exec(b, Insn::MoveW, 0x3012, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0xDEAD_8000);
    assert_ne!(env.backend.get(sem::ccr_ref()) & (1 << sem::sr_bit::N), 0);
}

#[test]
fn move_l_d_to_mem() {
    // move.l D1,(A2): 0010 010 010 000 001 = 0x2481。
    let mut env = env_with_data(&[0x2481], &[0; 4]);
    env.backend.set(A(2).state(), 0x4000);
    env.backend.set(D(1).state(), 0xDEAD_BEEF);
    env.step(|b| sem::exec(b, Insn::MoveL, 0x2481, 0x1000))
        .unwrap();
    let mut buf = [0u8; 4];
    env.backend
        .mem
        .read(VirtAddr(0x4000), &mut buf, DRD)
        .unwrap();
    assert_eq!(buf, 0xDEAD_BEEFu32.to_be_bytes());
}

#[test]
fn move_w_postinc() {
    // move.w (A2)+,D0: 0011 000 000 011 010 = 0x301A。
    let mut env = env_with_data(&[0x301A], &0x1234u16.to_be_bytes());
    env.backend.set(A(2).state(), 0x4000);
    env.step(|b| sem::exec(b, Insn::MoveW, 0x301A, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0x1234);
    assert_eq!(env.backend.get(A(2).state()), 0x4002);
}

#[test]
fn move_l_abs_w_to_d() {
    // move.l (0x4000).W,D0: 0010 000 000 111 000 = 0x2038、拡張語 0x4000。
    let mut env = env_with_data(&[0x2038, 0x4000], &0xCAFEBABEu32.to_be_bytes());
    env.step(|b| sem::exec(b, Insn::MoveL, 0x2038, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0xCAFE_BABE);
    assert_eq!(ea::insn_ext_words(Insn::MoveL, 0x2038), Some(1));
}

#[test]
fn movea_w_sign_extends() {
    // movea.w #0x8000,A3: 0011 011 001 111 100 = 0x367C。
    let mut env = env_with_code(&[0x367C, 0x8000]);
    env.step(|b| sem::exec(b, Insn::MoveaW, 0x367C, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(A(3).state()), 0xFFFF_8000);
    // movea は旗を更新しない。
    assert_eq!(env.backend.get(sem::ccr_ref()), 0);
    assert_eq!(ea::insn_ext_words(Insn::MoveaW, 0x367C), Some(1));
}

#[test]
fn moveq_sign_and_zero() {
    // moveq #0x80,D1: 0111 001 0 10000000 = 0x7280。
    let mut env = env_with_code(&[0x7280]);
    env.step(|b| sem::exec(b, Insn::Moveq, 0x7280, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(1).state()), 0xFFFF_FF80);
    assert_eq!(env.backend.get(sem::ccr_ref()), 1 << sem::sr_bit::N);
    // moveq #0,D0: 0x7000 → Z。
    let mut env = env_with_code(&[0x7000]);
    env.step(|b| sem::exec(b, Insn::Moveq, 0x7000, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0);
    assert_eq!(env.backend.get(sem::ccr_ref()), 1 << sem::sr_bit::Z);
}

#[test]
fn move_pc_relative_dest_is_illegal() {
    // move.w D1,d16(PC): 0011 010 111 000 001 = 0x35C1 は宛先に
    // PC 相対を使えず illegal。
    let mut env = env_with_code(&[0x35C1, 0x0000]);
    let e = match env.step(|b| sem::exec(b, Insn::MoveW, 0x35C1, 0x1000)) {
        Err(e) => e,
        Ok(()) => panic!("PC 相対宛ては illegal"),
    };
    match e {
        InterpExit::Exception(x) => assert_eq!(x.code, 4),
        other => panic!("unexpected exit: {other:?}"),
    }
}

#[test]
fn move_l_d_to_abs_l_dest_ext() {
    // move.l D1,(0x4000).L: 0010 001 111 000 001 = 0x23C1。
    // 宛先が拡張語2語を消費する。
    let mut env = env_with_data(&[0x23C1, 0x0000, 0x4000], &[0; 4]);
    env.backend.set(D(1).state(), 0xCAFE_BEEF);
    env.step(|b| sem::exec(b, Insn::MoveL, 0x23C1, 0x1000))
        .unwrap();
    let mut buf = [0u8; 4];
    env.backend
        .mem
        .read(VirtAddr(0x4000), &mut buf, DRD)
        .unwrap();
    assert_eq!(buf, 0xCAFE_BEEFu32.to_be_bytes());
    assert_eq!(ea::insn_ext_words(Insn::MoveL, 0x23C1), Some(2));
}

#[test]
fn move_w_d_to_postinc_and_predec() {
    // move.w D1,(A2)+: 0011 010 011 000 001 = 0x34C1。
    let mut env = env_with_data(&[0x34C1], &[0; 4]);
    env.backend.set(A(2).state(), 0x4000);
    env.backend.set(D(1).state(), 0xBEEF);
    env.step(|b| sem::exec(b, Insn::MoveW, 0x34C1, 0x1000))
        .unwrap();
    let mut buf = [0u8; 2];
    env.backend
        .mem
        .read(VirtAddr(0x4000), &mut buf, DRD)
        .unwrap();
    assert_eq!(buf, 0xBEEFu16.to_be_bytes());
    assert_eq!(env.backend.get(A(2).state()), 0x4002);

    // move.w D1,-(A2): 0011 010 100 000 001 = 0x3501。
    let mut env = env_with_data(&[0x3501], &[0; 4]);
    env.backend.set(A(2).state(), 0x4002);
    env.backend.set(D(1).state(), 0xBEEF);
    env.step(|b| sem::exec(b, Insn::MoveW, 0x3501, 0x1000))
        .unwrap();
    env.backend
        .mem
        .read(VirtAddr(0x4000), &mut buf, DRD)
        .unwrap();
    assert_eq!(buf, 0xBEEFu16.to_be_bytes());
    assert_eq!(env.backend.get(A(2).state()), 0x4000);
}

#[test]
fn move_w_imm_to_abs_w_both_ea_ext() {
    // move.w #0x1234,(0x4000).W: 0011 000 111 111 100 = 0x31FC。
    // 両 EA が拡張語を消費する（1 + 1 = 2 語）。
    let mut env = env_with_data(&[0x31FC, 0x1234, 0x4000], &[0; 2]);
    env.step(|b| sem::exec(b, Insn::MoveW, 0x31FC, 0x1000))
        .unwrap();
    let mut buf = [0u8; 2];
    env.backend
        .mem
        .read(VirtAddr(0x4000), &mut buf, DRD)
        .unwrap();
    assert_eq!(buf, 0x1234u16.to_be_bytes());
    assert_eq!(ea::insn_ext_words(Insn::MoveW, 0x31FC), Some(2));
}

#[test]
fn movea_l_imm_to_a() {
    // movea.l #0x12345678,A3: 0010 011 001 111 100 = 0x267C。
    let mut env = env_with_code(&[0x267C, 0x1234, 0x5678]);
    env.step(|b| sem::exec(b, Insn::MoveaL, 0x267C, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(A(3).state()), 0x1234_5678);
    assert_eq!(ea::insn_ext_words(Insn::MoveaL, 0x267C), Some(2));
}

#[test]
fn move_preserves_x_flag() {
    // move.b D1,D0。X は更新しないが N/Z は結果に従い V/C は消す。
    let mut env = env_with_code(&[0x1001]);
    env.backend.set(sem::ccr_ref(), 0b11111);
    env.step(|b| sem::exec(b, Insn::MoveB, 0x1001, 0x1000))
        .unwrap();
    // X=1 保持、Z=1（結果 0）、N=V=C=0。
    assert_eq!(
        env.backend.get(sem::ccr_ref()),
        (1 << sem::sr_bit::X) | (1 << sem::sr_bit::Z)
    );
}

#[test]
fn move_b_byte_an_is_undecodable() {
    // move.b <ea>,An・move.b An,<ea> は未割当符号化（where で弾く）。
    assert_eq!(polyisa_guest_m68k::decode(0x1041, 16), None);
    assert_eq!(polyisa_guest_m68k::decode(0x1009, 16), None);
    // movea.w の宛先 An 直は MoveA をデコードする。
    assert_eq!(polyisa_guest_m68k::decode(0x367C, 16), Some(Insn::MoveaW));
}

#[test]
fn add_w_ea_to_d() {
    // add.w (A2),D0: 1101 000 001 010 010 = 0xD052。下位語のみ更新。
    let mut env = env_with_data(&[0xD052], &0x0090u16.to_be_bytes());
    env.backend.set(A(2).state(), 0x4000);
    env.backend.set(D(0).state(), 0x1234_5670);
    env.step(|b| sem::exec(b, Insn::Add, 0xD052, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0x1234_5700);
    assert_eq!(env.backend.get(sem::ccr_ref()), 0);
}

#[test]
fn add_l_d_to_ea_carry() {
    // add.l D1,(A2): 1101 001 110 010 010 = 0xD392。Dn→EA 方向。
    let mut env = env_with_data(&[0xD392], &0x100u32.to_be_bytes());
    env.backend.set(A(2).state(), 0x4000);
    env.backend.set(D(1).state(), 0xFFFF_FF80);
    env.step(|b| sem::exec(b, Insn::AddDn, 0xD392, 0x1000))
        .unwrap();
    let mut buf = [0u8; 4];
    env.backend
        .mem
        .read(VirtAddr(0x4000), &mut buf, DRD)
        .unwrap();
    assert_eq!(u32::from_be_bytes(buf), 0x80);
    // 繰り上がりで C=X=1。
    assert_eq!(
        env.backend.get(sem::ccr_ref()),
        (1 << sem::sr_bit::X) | (1 << sem::sr_bit::C)
    );
}

#[test]
fn sub_w_ea_to_d_borrow() {
    // sub.w D1,D0: 1001 000 001 000 001 = 0x9041。
    let mut env = env_with_code(&[0x9041]);
    env.backend.set(D(0).state(), 0xAAAA_0001);
    env.backend.set(D(1).state(), 0x0002);
    env.step(|b| sem::exec(b, Insn::Sub, 0x9041, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0xAAAA_FFFF);
    assert_eq!(
        env.backend.get(sem::ccr_ref()),
        (1 << sem::sr_bit::X) | (1 << sem::sr_bit::N) | (1 << sem::sr_bit::C)
    );
}

#[test]
fn sub_l_d_to_ea_order() {
    // sub.l D1,(A2): 1001 001 110 010 010 = 0x9392。<ea> - Dn の向き。
    let mut env = env_with_data(&[0x9392], &0x80u32.to_be_bytes());
    env.backend.set(A(2).state(), 0x4000);
    env.backend.set(D(1).state(), 0x100);
    env.step(|b| sem::exec(b, Insn::SubDn, 0x9392, 0x1000))
        .unwrap();
    let mut buf = [0u8; 4];
    env.backend
        .mem
        .read(VirtAddr(0x4000), &mut buf, DRD)
        .unwrap();
    // 0x80 - 0x100 = 0xFFFFFF80（借り）。
    assert_eq!(u32::from_be_bytes(buf), 0xFFFF_FF80);
    assert_eq!(
        env.backend.get(sem::ccr_ref()),
        (1 << sem::sr_bit::X) | (1 << sem::sr_bit::N) | (1 << sem::sr_bit::C)
    );
}

#[test]
fn adda_w_sign_extends() {
    // adda.w #0x8000,A3: 1101 011 011 111 100 = 0xD6FC。
    let mut env = env_with_code(&[0xD6FC, 0x8000]);
    env.step(|b| sem::exec(b, Insn::Add, 0xD6FC, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(A(3).state()), 0xFFFF_8000);
    assert_eq!(ea::insn_ext_words(Insn::Add, 0xD6FC), Some(1));
    // suba.l D1,A2: 1001 010 111 000 001 = 0x95C1。旗は不変。
    let mut env = env_with_code(&[0x95C1]);
    env.backend.set(A(2).state(), 0x1000);
    env.backend.set(D(1).state(), 1);
    env.backend.set(sem::ccr_ref(), 0b11111);
    env.step(|b| sem::exec(b, Insn::SubaL, 0x95C1, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(A(2).state()), 0xFFF);
    assert_eq!(env.backend.get(sem::ccr_ref()), 0b11111);
}

#[test]
fn addq_subq_value_eight() {
    // addq.b #8,D1: 0101 000 0 00 000 001 = 0x5001。qdat=0 は 8。
    let mut env = env_with_code(&[0x5001]);
    env.backend.set(D(1).state(), 0xFC);
    env.step(|b| sem::exec(b, Insn::Addq, 0x5001, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(1).state()), 0x04);
    assert_eq!(
        env.backend.get(sem::ccr_ref()),
        (1 << sem::sr_bit::X) | (1 << sem::sr_bit::C)
    );
    // subq.w #8,D0: 0101 000 1 01 000 000 = 0x5140。
    let mut env = env_with_code(&[0x5140]);
    env.backend.set(D(0).state(), 0x1000);
    env.step(|b| sem::exec(b, Insn::Subq, 0x5140, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0xFF8);
}

#[test]
fn addq_l_to_a_keeps_flags() {
    // addq.l #1,A2: 0101 001 0 10 001 010 = 0x528A。An は旗不変。
    let mut env = env_with_code(&[0x528A]);
    env.backend.set(A(2).state(), 1);
    env.backend.set(sem::ccr_ref(), 0b11111);
    env.step(|b| sem::exec(b, Insn::Addq, 0x528A, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(A(2).state()), 2);
    assert_eq!(env.backend.get(sem::ccr_ref()), 0b11111);
}

#[test]
fn addq_b_to_a_is_illegal() {
    // addq.b #1,A0: 0101 000 0 00 001 000 = 0x5008。byte 宛て An は illegal。
    let mut env = env_with_code(&[0x5008]);
    let e = env
        .step(|b| sem::exec(b, Insn::Addq, 0x5008, 0x1000))
        .expect_err("byte 宛て An は illegal");
    match e {
        InterpExit::Exception(x) => assert_eq!(x.code, 4),
        other => panic!("unexpected exit: {other:?}"),
    }
}

#[test]
fn cmp_w_equal_sets_z_preserves_x() {
    // cmp.w D1,D0: 1011 000 001 000 001 = 0xB041。
    let mut env = env_with_code(&[0xB041]);
    env.backend.set(D(0).state(), 0xBEEF_0005);
    env.backend.set(D(1).state(), 0xDEAD_0005);
    env.backend.set(sem::ccr_ref(), 1 << sem::sr_bit::X);
    env.step(|b| sem::exec(b, Insn::Cmp, 0xB041, 0x1000))
        .unwrap();
    // Z=1・X は保持・N/V/C=0。D0 は変わらない。
    assert_eq!(
        env.backend.get(sem::ccr_ref()),
        (1 << sem::sr_bit::X) | (1 << sem::sr_bit::Z)
    );
    assert_eq!(env.backend.get(D(0).state()), 0xBEEF_0005);
}

#[test]
fn cmpa_w_sign_extends() {
    // cmpa.w #0x8000,A2: 1011 010 011 111 100 = 0xB4FC。opm=3 は cmpa.w。
    let mut env = env_with_code(&[0xB4FC, 0x8000]);
    env.backend.set(A(2).state(), 0xFFFF_8000);
    env.step(|b| sem::exec(b, Insn::Cmp, 0xB4FC, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(sem::ccr_ref()), 1 << sem::sr_bit::Z);
}

#[test]
fn cmpm_b_postinc_both() {
    // cmpm.b (A1)+,(A2)+: 1011 010 1 00 001 001 = 0xB509。
    let mut env = env_with_data(&[0xB509], &[0x05, 0x03]);
    env.backend.set(A(1).state(), 0x4000);
    env.backend.set(A(2).state(), 0x4001);
    env.step(|b| sem::exec(b, Insn::Cmpm, 0xB509, 0x1000))
        .unwrap();
    // (A2)=0x03 - (A1)=0x05 = -2。N=1・C=1。両方のポインタが進む。
    assert_eq!(
        env.backend.get(sem::ccr_ref()),
        (1 << sem::sr_bit::N) | (1 << sem::sr_bit::C)
    );
    assert_eq!(env.backend.get(A(1).state()), 0x4001);
    assert_eq!(env.backend.get(A(2).state()), 0x4002);
}

#[test]
fn addi_l_ext_two_words() {
    // addi.l #0x12345678,D0: 0000 0110 10 000 000 = 0x0680。
    let mut env = env_with_code(&[0x0680, 0x1234, 0x5678]);
    env.backend.set(D(0).state(), 1);
    env.step(|b| sem::exec(b, Insn::Addi, 0x0680, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0x1234_5679);
    assert_eq!(ea::insn_ext_words(Insn::Addi, 0x0680), Some(2));
}

#[test]
fn subi_b_imm() {
    // subi.b #1,D0: 0000 0100 00 000 000 = 0x0400、拡張語 0x0001。
    let mut env = env_with_code(&[0x0400, 0x0001]);
    env.backend.set(D(0).state(), 0xBEEF_0100);
    env.step(|b| sem::exec(b, Insn::Subi, 0x0400, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0xBEEF_01FF);
    // 借りで N=C=X。
    assert_eq!(
        env.backend.get(sem::ccr_ref()),
        (1 << sem::sr_bit::X) | (1 << sem::sr_bit::N) | (1 << sem::sr_bit::C)
    );
    assert_eq!(ea::insn_ext_words(Insn::Subi, 0x0400), Some(1));
}

#[test]
fn cmpi_b_to_mem() {
    // cmpi.b #5,(A2): 0000 1100 00 010 010 = 0x0C12。
    let mut env = env_with_data(&[0x0C12, 0x0005], &[0x05]);
    env.backend.set(A(2).state(), 0x4000);
    env.step(|b| sem::exec(b, Insn::Cmpi, 0x0C12, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(sem::ccr_ref()), 1 << sem::sr_bit::Z);
}

#[test]
fn imm_dest_pc_relative_is_illegal() {
    // addi.w #1,2(PC): 0000 0110 01 111 010 = 0x067A。宛先 PC 相対は illegal。
    let mut env = env_with_code(&[0x067A, 0x0001]);
    let e = env
        .step(|b| sem::exec(b, Insn::Addi, 0x067A, 0x1000))
        .expect_err("宛先 PC 相対は illegal");
    match e {
        InterpExit::Exception(x) => assert_eq!(x.code, 4),
        other => panic!("unexpected exit: {other:?}"),
    }
}

#[test]
fn decode_c2_spot() {
    assert_eq!(polyisa_guest_m68k::decode(0xD052, 16), Some(Insn::Add));
    assert_eq!(polyisa_guest_m68k::decode(0xD392, 16), Some(Insn::AddDn));
    assert_eq!(polyisa_guest_m68k::decode(0x95C1, 16), Some(Insn::SubaL));
    assert_eq!(polyisa_guest_m68k::decode(0x5001, 16), Some(Insn::Addq));
    assert_eq!(polyisa_guest_m68k::decode(0x5140, 16), Some(Insn::Subq));
    assert_eq!(polyisa_guest_m68k::decode(0xB509, 16), Some(Insn::Cmpm));
    assert_eq!(polyisa_guest_m68k::decode(0x0C12, 16), Some(Insn::Cmpi));
    // addx/subx: emode 0 は Dn↔Dn、emode 1 は -(Ay),-(Ax)。
    assert_eq!(polyisa_guest_m68k::decode(0xD301, 16), Some(Insn::AddxD));
    assert_eq!(polyisa_guest_m68k::decode(0xD309, 16), Some(Insn::AddxM));
}

#[test]
fn cmpi_dest_is_strictly_decoded() {
    // 68000 では cmpi の EA も宛先オペランドとして厳密にデコードされる。
    // cmpi.w #1,A0: 0000 1100 01 001 000 = 0x0C48 → illegal。
    let mut env = env_with_code(&[0x0C48, 0x0001]);
    let e = env
        .step(|b| sem::exec(b, Insn::Cmpi, 0x0C48, 0x1000))
        .expect_err("cmpi の An 宛ては illegal");
    match e {
        InterpExit::Exception(x) => assert_eq!(x.code, 4),
        other => panic!("unexpected exit: {other:?}"),
    }
    // cmpi.w #1,2(PC): 0000 1100 01 111 010 = 0x0C7A → illegal。
    let mut env = env_with_code(&[0x0C7A, 0x0001]);
    let e = env
        .step(|b| sem::exec(b, Insn::Cmpi, 0x0C7A, 0x1000))
        .expect_err("cmpi の PC 相対宛ては illegal");
    match e {
        InterpExit::Exception(x) => assert_eq!(x.code, 4),
        other => panic!("unexpected exit: {other:?}"),
    }
}

#[test]
fn or_w_ea_to_d() {
    // or.w (A2),D0: 1000 000 0 01 010 010 = 0x8052。
    let mut env = env_with_data(&[0x8052], &0x0FF0u16.to_be_bytes());
    env.backend.set(A(2).state(), 0x4000);
    env.backend.set(D(0).state(), 0x1234_F000);
    env.step(|b| sem::exec(b, Insn::Or, 0x8052, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0x1234_FFF0);
    assert_eq!(env.backend.get(sem::ccr_ref()), 1 << sem::sr_bit::N);
}

#[test]
fn or_l_d_to_ea() {
    // or.l D1,(A2): 1000 001 1 10 010 010 = 0x8392。Dn→EA 方向。
    let mut env = env_with_data(&[0x8392], &0x1000u32.to_be_bytes());
    env.backend.set(A(2).state(), 0x4000);
    env.backend.set(D(1).state(), 0x0F0F_0001);
    env.step(|b| sem::exec(b, Insn::OrLDn, 0x8392, 0x1000))
        .unwrap();
    let mut buf = [0u8; 4];
    env.backend
        .mem
        .read(VirtAddr(0x4000), &mut buf, DRD)
        .unwrap();
    assert_eq!(u32::from_be_bytes(buf), 0x0F0F_1001);
}

#[test]
fn and_l_ea_to_d() {
    // and.l D1,D0: 1100 000 0 10 000 001 = 0xC081。
    let mut env = env_with_code(&[0xC081]);
    env.backend.set(D(0).state(), 0xFF00_FF00);
    env.backend.set(D(1).state(), 0x0FF0_0FF0);
    env.backend.set(sem::ccr_ref(), 0b11111);
    env.step(|b| sem::exec(b, Insn::And, 0xC081, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0x0F00_0F00);
    // V/C=0・N=0・Z=0、X は保持。
    assert_eq!(env.backend.get(sem::ccr_ref()), 1 << sem::sr_bit::X);
}

#[test]
fn eor_w_d_to_d() {
    // eor.w D1,D0: 1011 001 1 01 000 000 = 0xB340。
    let mut env = env_with_code(&[0xB340]);
    env.backend.set(D(0).state(), 0xBEEF_00FF);
    env.backend.set(D(1).state(), 0x0FF0);
    env.step(|b| sem::exec(b, Insn::Eor, 0xB340, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0xBEEF_0F0F);
}

#[test]
fn not_w_and_clr_l() {
    // not.w D0: 0100 0110 01 000 000 = 0x4640。
    let mut env = env_with_code(&[0x4640]);
    env.backend.set(D(0).state(), 0xBEEF_00FF);
    env.step(|b| sem::exec(b, Insn::Not, 0x4640, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0xBEEF_FF00);
    assert_eq!(env.backend.get(sem::ccr_ref()), 1 << sem::sr_bit::N);
    // clr.l D0: 0100 0010 10 000 000 = 0x4280。
    let mut env = env_with_code(&[0x4280]);
    env.backend.set(D(0).state(), 0xDEAD_BEEF);
    env.step(|b| sem::exec(b, Insn::Clr, 0x4280, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0);
    assert_eq!(env.backend.get(sem::ccr_ref()), 1 << sem::sr_bit::Z);
}

#[test]
fn tst_b_d_flags_only() {
    // tst.b D0: 0100 1010 00 000 000 = 0x4A00。書き戻しなし。
    let mut env = env_with_code(&[0x4A00]);
    env.backend.set(D(0).state(), 0xBEEF_0180);
    env.step(|b| sem::exec(b, Insn::Tst, 0x4A00, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(sem::ccr_ref()), 1 << sem::sr_bit::N);
    assert_eq!(env.backend.get(D(0).state()), 0xBEEF_0180);
}

#[test]
fn tst_b_to_a_is_illegal() {
    // tst.b A0: 0100 1010 00 001 000 = 0x4A08。68000 では An 宛て illegal。
    let mut env = env_with_code(&[0x4A08]);
    let e = env
        .step(|b| sem::exec(b, Insn::Tst, 0x4A08, 0x1000))
        .expect_err("tst の An 宛ては illegal");
    match e {
        InterpExit::Exception(x) => assert_eq!(x.code, 4),
        other => panic!("unexpected exit: {other:?}"),
    }
}

#[test]
fn ori_andi_eori_normal() {
    // ori.w #0x00F0,D0: 0000 0000 01 000 000 = 0x0040。
    let mut env = env_with_code(&[0x0040, 0x00F0]);
    env.backend.set(D(0).state(), 0xBEEF_0F00);
    env.step(|b| sem::exec(b, Insn::Ori, 0x0040, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0xBEEF_0FF0);
    assert_eq!(ea::insn_ext_words(Insn::Ori, 0x0040), Some(1));
    // andi.b #0x0F,D0: 0000 0010 00 000 000 = 0x0200。
    let mut env = env_with_code(&[0x0200, 0x000F]);
    env.backend.set(D(0).state(), 0xBEEF_FFF8);
    env.step(|b| sem::exec(b, Insn::Andi, 0x0200, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0xBEEF_FF08);
    // eori.l #1,D0: 0000 1010 10 000 000 = 0x0A80。
    let mut env = env_with_code(&[0x0A80, 0x0000, 0x0001]);
    env.backend.set(D(0).state(), 0xDEAD_BEEF);
    env.step(|b| sem::exec(b, Insn::Eori, 0x0A80, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0xDEAD_BEEE);
    assert_eq!(ea::insn_ext_words(Insn::Eori, 0x0A80), Some(2));
}

#[test]
fn imm_to_ccr_masks_flag_bits() {
    // ori to ccr: 0x003C + 拡張語 0x0083。書けるのは旗5ビットのみ。
    let mut env = env_with_code(&[0x003C, 0x0083]);
    env.step(|b| sem::exec(b, Insn::Ori, 0x003C, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(sem::ccr_ref()), 0x03);
    // 拡張語は1語のみ（to CCR は2オペランド目を消費しない）。
    assert_eq!(ea::insn_ext_words(Insn::Ori, 0x003C), Some(1));
}

#[test]
fn imm_to_sr_supervisor() {
    // ori to sr: 0x007C + 拡張語 0x2000。スーパーバイザで S=1 のまま。
    let mut env = env_with_code(&[0x007C, 0x2000]);
    env.backend.set(sem::sr_ref(), 0x2000);
    env.step(|b| sem::exec(b, Insn::Ori, 0x007C, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(sem::sr_ref()), 0x2000);
    // ユーザーモードならベクタ 8（特権違反）。
    let mut env = env_with_code(&[0x007C, 0x2000]);
    env.backend.set(sem::sr_ref(), 0);
    let e = env
        .step(|b| sem::exec(b, Insn::Ori, 0x007C, 0x1000))
        .expect_err("to SR はスーパーバイザ必須");
    match e {
        InterpExit::Exception(x) => assert_eq!(x.code, 8),
        other => panic!("unexpected exit: {other:?}"),
    }
}

#[test]
fn decode_c3_spot() {
    assert_eq!(polyisa_guest_m68k::decode(0x8052, 16), Some(Insn::Or));
    assert_eq!(polyisa_guest_m68k::decode(0x8392, 16), Some(Insn::OrLDn));
    assert_eq!(polyisa_guest_m68k::decode(0xC081, 16), Some(Insn::And));
    assert_eq!(polyisa_guest_m68k::decode(0xB340, 16), Some(Insn::Eor));
    assert_eq!(polyisa_guest_m68k::decode(0x4640, 16), Some(Insn::Not));
    assert_eq!(polyisa_guest_m68k::decode(0x4A00, 16), Some(Insn::Tst));
    // or.b Dn→Dn の空間は sbcd（C12 で実装済み）。or.w Dn→An は未割当。
    assert_eq!(polyisa_guest_m68k::decode(0x8300, 16), Some(Insn::SbcdR));
    assert_eq!(polyisa_guest_m68k::decode(0x8308, 16), Some(Insn::SbcdM));
    assert_eq!(polyisa_guest_m68k::decode(0xC100, 16), Some(Insn::AbcdR));
    assert_eq!(polyisa_guest_m68k::decode(0xC108, 16), Some(Insn::AbcdM));
    assert_eq!(polyisa_guest_m68k::decode(0x4800, 16), Some(Insn::Nbcd));
    assert_eq!(polyisa_guest_m68k::decode(0x8348, 16), None);
    // and.w Dn→Dn/An の空間は exg（C9 で実装済み）。
    assert_eq!(polyisa_guest_m68k::decode(0xC340, 16), Some(Insn::ExgDd));
    assert_eq!(polyisa_guest_m68k::decode(0xC348, 16), Some(Insn::ExgAa));
    // tas・move to/from sr の空間（qsz=3）は未割当。
    assert_eq!(polyisa_guest_m68k::decode(0x4AC0, 16), None);
}

#[test]
fn or_d_to_pc_relative_is_illegal() {
    // or.w D1,2(PC): 1000 001 1 01 111 010 = 0x837A。宛先 PC 相対は illegal。
    let mut env = env_with_code(&[0x837A]);
    let e = env
        .step(|b| sem::exec(b, Insn::OrWDn, 0x837A, 0x1000))
        .expect_err("宛先 PC 相対は illegal");
    match e {
        InterpExit::Exception(x) => assert_eq!(x.code, 4),
        other => panic!("unexpected exit: {other:?}"),
    }
}

/// C4: レジスタシフトの基本（即値カウント・方向・旗）。
// Ref: SPEC-M68K-PRM (Rev 1) §ASx/LSx/ROXx/ROx.
#[test]
fn shift_reg_forms() {
    // asl.l #2, D0: 0xC000_0001 << 2 = 0x0000_0004。
    // 符号が 1→0 に変化するので V=1、最後に出たビット=1 で C=X=1。
    let mut env = env_with_code(&[0xE580]);
    env.backend.set(D(0).state(), 0xC000_0001);
    env.step(|b| sem::exec(b, Insn::Asl, 0xE580, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0x0000_0004);
    assert_eq!(env.backend.get(sem::ccr_ref()) & 0x1F, 0b1_0_0_1_1);

    // lsr.b #4, D0: 0xA5 >> 4 = 0x0A。出たビットは bit3=0 → C=X=0。
    let mut env = env_with_code(&[0xE808]);
    env.backend.set(D(0).state(), 0xA5);
    env.step(|b| sem::exec(b, Insn::Lsr, 0xE808, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()) & 0xFF, 0x0A);
    assert_eq!(env.backend.get(sem::ccr_ref()) & 0x1F, 0);

    // lsl.l D1,D0 で D1=64 → mod 64 でカウント0。値不変・C=0・X 保持。
    let mut env = env_with_code(&[0xE3A8]);
    env.backend.set(D(0).state(), 0x8000_0001);
    env.backend.set(D(1).state(), 0x40);
    env.backend.set(sem::ccr_ref(), 1 << sem::sr_bit::X);
    env.step(|b| sem::exec(b, Insn::Lsl, 0xE3A8, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0x8000_0001);
    assert_eq!(env.backend.get(sem::ccr_ref()) & 0x1F, 0b1_1_0_0_0);

    // roxr.w #1, D0: X=1 なら {X,D}={1,0x0001}→ 0x8000 + X=1。C=X=1。
    let mut env = env_with_code(&[0xE250]);
    env.backend.set(D(0).state(), 0x0001);
    env.backend.set(sem::ccr_ref(), 1 << sem::sr_bit::X);
    env.step(|b| sem::exec(b, Insn::Roxr, 0xE250, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()) & 0xFFFF, 0x8000);
    assert_eq!(env.backend.get(sem::ccr_ref()) & 0x1F, 0b1_1_0_0_1);
}

/// C4: メモリシフトは word・カウント1 固定、EA はメモリ alterable のみ。
// Ref: SPEC-M68K-PRM (Rev 1) §ASx.
#[test]
fn shift_mem_form() {
    // asr.w (a0): 0x8001 >>a 1 = 0xC000。N=1, C=X=1。
    let mut env = env_with_data(&[0xE0D0], &0x8001u16.to_be_bytes());
    env.backend.set(A(0).state(), 0x4000);
    env.step(|b| sem::exec(b, Insn::AsrM, 0xE0D0, 0x1000))
        .unwrap();
    let mut buf = [0u8; 2];
    env.backend
        .mem
        .read(VirtAddr(0x4000), &mut buf, DRD)
        .unwrap();
    assert_eq!(u16::from_be_bytes(buf), 0xC000);
    assert_eq!(env.backend.get(sem::ccr_ref()) & 0x1F, 0b1_1_0_0_1);

    // EA が Dn 直のメモリシフト符号化は illegal。
    let mut env = env_with_code(&[0xE0C0]);
    let ex = env
        .step(|b| sem::exec(b, Insn::AsrM, 0xE0C0, 0x1000))
        .unwrap_err();
    match ex {
        InterpExit::Exception(x) => assert_eq!(x.code, 4),
        e => panic!("unexpected: {e:?}"),
    }
}

/// C5: ビット操作（reg/imm・Dn mod32・メモリ mod8・Z 旗・書き戻し）。
// Ref: SPEC-M68K-PRM (Rev 1) §BTST/BCHG/BCLR/BSET.
#[test]
fn bit_op_forms() {
    // btst #37, D0: imm 形は拡張語がビット番号。Dn 宛は mod 32 で bit5。
    // D0 = 0x20 → bit5=1 → Z=0。
    let mut env = env_with_code(&[0x0800, 0x0025]);
    env.backend.set(D(0).state(), 0x20);
    env.step(|b| sem::exec(b, Insn::BtstI, 0x0800, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(sem::ccr_ref()) & (1 << sem::sr_bit::Z), 0);

    // bset D1, D0: D1=7 → bit7 を立てる。D0=0 → 0x80、bit7 は 0→Z=1。
    let mut env = env_with_code(&[0x03C0]);
    env.backend.set(D(0).state(), 0);
    env.backend.set(D(1).state(), 7);
    env.step(|b| sem::exec(b, Insn::Bset, 0x03C0, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0x80);
    assert_eq!(
        env.backend.get(sem::ccr_ref()) & (1 << sem::sr_bit::Z),
        1 << sem::sr_bit::Z
    );

    // bclr #9, (a0): メモリはバイト mod8 → bit1 をクリア。0x06 → 0x04。
    let mut env = env_with_data(&[0x0890, 0x0009], &[0x06]);
    env.backend.set(A(0).state(), 0x4000);
    env.step(|b| sem::exec(b, Insn::BclrI, 0x0890, 0x1000))
        .unwrap();
    let mut buf = [0u8; 1];
    env.backend
        .mem
        .read(VirtAddr(0x4000), &mut buf, DRD)
        .unwrap();
    assert_eq!(buf[0], 0x04);
    // テスト時の bit1 は 1 だったので Z=0。
    assert_eq!(env.backend.get(sem::ccr_ref()) & (1 << sem::sr_bit::Z), 0);

    // bchg で非 alterable（PC 相対）は illegal。
    let mut env = env_with_code(&[0x087A, 0x0000]);
    let ex = env
        .step(|b| sem::exec(b, Insn::BchgI, 0x087A, 0x1000))
        .unwrap_err();
    match ex {
        InterpExit::Exception(x) => assert_eq!(x.code, 4),
        e => panic!("unexpected: {e:?}"),
    }
}

/// C5: デコード・拡張語数・旗保持のスポット検査。
#[test]
fn decode_c5_spot() {
    // btst Dn,<ea> = 0000 rrr 1 00 mmm rrr。
    assert_eq!(polyisa_guest_m68k::decode(0x0101, 16), Some(Insn::Btst));
    // emode=1 は MOVEP の空間（C10 で実装済み）。
    assert_eq!(polyisa_guest_m68k::decode(0x0148, 16), Some(Insn::MovepLm));
    // bchg/bclr/bset reg 形。
    assert_eq!(polyisa_guest_m68k::decode(0x0141, 16), Some(Insn::Bchg));
    assert_eq!(polyisa_guest_m68k::decode(0x0181, 16), Some(Insn::Bclr));
    assert_eq!(polyisa_guest_m68k::decode(0x01C1, 16), Some(Insn::Bset));
    // imm 形。
    assert_eq!(polyisa_guest_m68k::decode(0x0800, 16), Some(Insn::BtstI));
    assert_eq!(polyisa_guest_m68k::decode(0x08C0, 16), Some(Insn::BsetI));

    // 拡張語数: imm 形はビット番号語 + EA 語。
    assert_eq!(ea::insn_ext_words(Insn::BsetI, 0x08F9), Some(3)); // (xxx).L
    assert_eq!(ea::insn_ext_words(Insn::BtstI, 0x0800), Some(1)); // Dn
    assert_eq!(ea::insn_ext_words(Insn::Btst, 0x0101), Some(0));
    assert_eq!(ea::insn_ext_words(Insn::Btst, 0x013C), Some(1)); // #imm EA

    // btst は #imm EA も合法（即値のビットを読む）。
    let mut env = env_with_code(&[0x083C, 0x0004, 0x0010]);
    env.backend.set(sem::ccr_ref(), 0x1F); // XNVCZ 全部立てる
    env.step(|b| sem::exec(b, Insn::BtstI, 0x083C, 0x1000))
        .unwrap();
    // 0x10 の bit4=1 → Z=0、XNVC は保持（0x1F & !Z = 0x1B）。
    assert_eq!(env.backend.get(sem::ccr_ref()), 0x1B);

    // imm 形で An 直は illegal。
    let mut env = env_with_code(&[0x0848, 0x0000]);
    let ex = env
        .step(|b| sem::exec(b, Insn::BchgI, 0x0848, 0x1000))
        .unwrap_err();
    match ex {
        InterpExit::Exception(x) => assert_eq!(x.code, 4),
        e => panic!("unexpected: {e:?}"),
    }
}

/// C6: 分岐系。bra/bcc の変位・bsr/jsr の push・jmp/jsr の EA・
/// rts/rtr の pop と旗規約を見る。
// Ref: SPEC-M68K-PRM (Rev 1) §BRA/BSR/Bcc/JMP/JSR/RTS/RTR.
#[test]
fn branch_forms() {
    use polyisa_engine::interp::Ctrl;

    // bra byte disp: 0x6002 = bra +2 → pc+2+2。
    let mut env = env_with_code(&[0x6002]);
    env.step(|b| sem::exec(b, Insn::Bra, 0x6002, 0x1000))
        .unwrap();
    match env.backend.ctrl {
        Ctrl::Jump(t) => assert_eq!(t, 0x1004),
        c => panic!("unexpected ctrl: {c:?}"),
    }

    // bra word disp: 0x6000 + ext 0x0100 → pc+2+0x100。
    let mut env = env_with_code(&[0x6000, 0x0100]);
    env.step(|b| sem::exec(b, Insn::Bra, 0x6000, 0x1000))
        .unwrap();
    match env.backend.ctrl {
        Ctrl::Jump(t) => assert_eq!(t, 0x1102),
        c => panic!("unexpected ctrl: {c:?}"),
    }

    // beq byte disp -2（0x67FE）: Z=1 なら分岐、Z=0 なら素通り。
    let mut env = env_with_code(&[0x67FE]);
    env.backend.set(sem::ccr_ref(), 1 << sem::sr_bit::Z);
    env.step(|b| sem::exec(b, Insn::Bcc, 0x67FE, 0x1000))
        .unwrap();
    match env.backend.ctrl {
        Ctrl::Jump(t) => assert_eq!(t, 0x1000), // pc+2-2
        c => panic!("unexpected ctrl: {c:?}"),
    }
    let mut env = env_with_code(&[0x67FE]);
    env.step(|b| sem::exec(b, Insn::Bcc, 0x67FE, 0x1000))
        .unwrap();
    assert_eq!(env.backend.ctrl, Ctrl::Fallthrough);

    // bsr byte +2: 戻りアドレス pc+2 を push して分岐。
    let mut env = env_with_data(&[0x6102], &[]);
    env.backend.set(sem::Ssp.state(), 0x4004);
    env.backend.set(sem::sr_ref(), 1 << sem::sr_bit::S);
    env.step(|b| sem::exec(b, Insn::Bsr, 0x6102, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(sem::Ssp.state()), 0x4000);
    match env.backend.ctrl {
        Ctrl::Jump(t) => assert_eq!(t, 0x1004),
        c => panic!("unexpected ctrl: {c:?}"),
    }
    let mut buf = [0u8; 4];
    env.backend
        .mem
        .read(VirtAddr(0x4000), &mut buf, DRD)
        .unwrap();
    assert_eq!(u32::from_be_bytes(buf), 0x1002);
}

/// C6: jmp/jsr/rts/rtr。
#[test]
fn jump_return_forms() {
    use polyisa_engine::interp::Ctrl;

    // jmp (a0): 0x4ED0。a0=0x5000 へ飛ぶ。
    let mut env = env_with_code(&[0x4ED0]);
    env.backend.set(A(0).state(), 0x5000);
    env.step(|b| sem::exec(b, Insn::Jmp, 0x4ED0, 0x1000))
        .unwrap();
    match env.backend.ctrl {
        Ctrl::Jump(t) => assert_eq!(t, 0x5000),
        c => panic!("unexpected ctrl: {c:?}"),
    }

    // jmp の非制御 EA（postinc）は illegal。
    let mut env = env_with_code(&[0x4ED8]);
    let ex = env
        .step(|b| sem::exec(b, Insn::Jmp, 0x4ED8, 0x1000))
        .unwrap_err();
    match ex {
        InterpExit::Exception(x) => assert_eq!(x.code, 4),
        e => panic!("unexpected: {e:?}"),
    }

    // jsr (xxx).l: 0x4EB9 + abs.l。戻り値は pc+6。
    let mut env = env_with_data(&[0x4EB9, 0x0000, 0x6000], &[]);
    env.backend.set(sem::Ssp.state(), 0x4004);
    env.backend.set(sem::sr_ref(), 1 << sem::sr_bit::S);
    env.step(|b| sem::exec(b, Insn::Jsr, 0x4EB9, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(sem::Ssp.state()), 0x4000);
    match env.backend.ctrl {
        Ctrl::Jump(t) => assert_eq!(t, 0x6000),
        c => panic!("unexpected ctrl: {c:?}"),
    }
    let mut buf = [0u8; 4];
    env.backend
        .mem
        .read(VirtAddr(0x4000), &mut buf, DRD)
        .unwrap();
    assert_eq!(u32::from_be_bytes(buf), 0x1006);

    // rts: (SP)+ の long を pc へ。
    let mut env = env_with_data(&[0x4E75], &0x0000_7000u32.to_be_bytes());
    env.backend.set(sem::Ssp.state(), 0x4000);
    env.backend.set(sem::sr_ref(), 1 << sem::sr_bit::S);
    env.step(|b| sem::exec(b, Insn::Rts, 0x4E75, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(sem::Ssp.state()), 0x4004);
    match env.backend.ctrl {
        Ctrl::Jump(t) => assert_eq!(t, 0x7000),
        c => panic!("unexpected ctrl: {c:?}"),
    }

    // rtr: (SP)+ の word →CCR（5bit）、long →pc。
    let mut env = env_with_data(&[0x4E77], &[0x00, 0xFA, 0x00, 0x00, 0x70, 0x00]);
    env.backend.set(sem::Ssp.state(), 0x4000);
    env.backend.set(sem::sr_ref(), 1 << sem::sr_bit::S);
    env.step(|b| sem::exec(b, Insn::Rtr, 0x4E77, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(sem::ccr_ref()), 0x1A); // 0xFA & 0x1F
    assert_eq!(env.backend.get(sem::Ssp.state()), 0x4006);
    match env.backend.ctrl {
        Ctrl::Jump(t) => assert_eq!(t, 0x7000),
        c => panic!("unexpected ctrl: {c:?}"),
    }
}

/// C7: scc/dbcc。条件の真偽・Dn 下位ワードの減算・-1 停止を見る。
// Ref: SPEC-M68K-PRM (Rev 1) §Scc/DBcc.
#[test]
fn scc_dbcc_forms() {
    use polyisa_engine::interp::Ctrl;

    // seq D0（0x57C0: cc=7=EQ）: Z=1 なら 0xFF、Z=0 なら 0x00。
    let mut env = env_with_code(&[0x57C0]);
    env.backend.set(sem::ccr_ref(), 1 << sem::sr_bit::Z);
    env.step(|b| sem::exec(b, Insn::Scc, 0x57C0, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()) & 0xFF, 0xFF);
    let mut env = env_with_code(&[0x57C0]);
    env.step(|b| sem::exec(b, Insn::Scc, 0x57C0, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()) & 0xFF, 0x00);

    // st D0（0x50C0: cc=0=T）は常に 0xFF。
    let mut env = env_with_code(&[0x50C0]);
    env.step(|b| sem::exec(b, Insn::Scc, 0x50C0, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()) & 0xFF, 0xFF);

    // scc で非 alterable（#imm 宛）は illegal。
    let mut env = env_with_code(&[0x50FC]);
    let ex = env
        .step(|b| sem::exec(b, Insn::Scc, 0x50FC, 0x1000))
        .unwrap_err();
    match ex {
        InterpExit::Exception(x) => assert_eq!(x.code, 4),
        e => panic!("unexpected: {e:?}"),
    }

    // dbeq D0, disp（0x57C8 + 変位語）: Z=0 → lo-1、!=0xFFFF なら分岐。
    let mut env = env_with_code(&[0x57C8, 0x0010]);
    env.backend.set(D(0).state(), 0x0003);
    env.step(|b| sem::exec(b, Insn::Dbcc, 0x57C8, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0x0002);
    match env.backend.ctrl {
        Ctrl::Jump(t) => assert_eq!(t, 0x1012), // pc+2+0x10
        c => panic!("unexpected ctrl: {c:?}"),
    }

    // Z=1（条件真）なら減算も分岐もしない。
    let mut env = env_with_code(&[0x57C8, 0x0010]);
    env.backend.set(D(0).state(), 0x0003);
    env.backend.set(sem::ccr_ref(), 1 << sem::sr_bit::Z);
    env.step(|b| sem::exec(b, Insn::Dbcc, 0x57C8, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0x0003);
    assert_eq!(env.backend.ctrl, Ctrl::Fallthrough);

    // lo=0 → lo-1=0xFFFF になれば分岐しない（カウンタ終了）。
    let mut env = env_with_code(&[0x57C8, 0x0010]);
    env.backend.set(D(0).state(), 0xA500_0000);
    env.step(|b| sem::exec(b, Insn::Dbcc, 0x57C8, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0xA500_FFFF);
    assert_eq!(env.backend.ctrl, Ctrl::Fallthrough);
}

/// C7: 固定条件の両端と decode 排他。
#[test]
fn scc_dbcc_fixed_cc() {
    use polyisa_engine::interp::Ctrl;

    // sf D0（0x51C0: cc=1=F）は常に 0x00。
    let mut env = env_with_code(&[0x51C0]);
    env.backend.set(D(0).state(), 0xFF);
    env.step(|b| sem::exec(b, Insn::Scc, 0x51C0, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()) & 0xFF, 0x00);

    // dbt（0x50C8: cc=0=T）は減算も分岐もしない。
    let mut env = env_with_code(&[0x50C8, 0x0010]);
    env.backend.set(D(0).state(), 0x0003);
    env.step(|b| sem::exec(b, Insn::Dbcc, 0x50C8, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0x0003);
    assert_eq!(env.backend.ctrl, Ctrl::Fallthrough);

    // scc をメモリ (a0) 宛に書く。
    let mut env = env_with_data(&[0x50D0], &[0x00]);
    env.backend.set(A(0).state(), 0x4000);
    env.step(|b| sem::exec(b, Insn::Scc, 0x50D0, 0x1000))
        .unwrap();
    let mut buf = [0u8; 1];
    env.backend
        .mem
        .read(VirtAddr(0x4000), &mut buf, DRD)
        .unwrap();
    assert_eq!(buf[0], 0xFF);

    // decode 排他: emode=1 の語は scc ではなく dbcc。
    assert_eq!(polyisa_guest_m68k::decode(0x57C0, 16), Some(Insn::Scc));
    assert_eq!(polyisa_guest_m68k::decode(0x57C8, 16), Some(Insn::Dbcc));
    // qsz!=3 の語は addq/subq であって scc/dbcc ではない。
    assert_eq!(polyisa_guest_m68k::decode(0x5240, 16), Some(Insn::Addq));
}

/// C8: lea/pea/link/unlk。
// Ref: SPEC-M68K-PRM (Rev 1) §LEA/PEA/LINK/UNLK.
#[test]
fn lea_pea_link_unlk() {
    // lea (a0),a1: 0x43D0。アドレスそのものを a1 へ（旗不変）。
    let mut env = env_with_code(&[0x43D0]);
    env.backend.set(A(0).state(), 0x5000);
    env.backend.set(sem::ccr_ref(), 0x1F);
    env.step(|b| sem::exec(b, Insn::Lea, 0x43D0, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(A(1).state()), 0x5000);
    assert_eq!(env.backend.get(sem::ccr_ref()), 0x1F);

    // lea ($4000).w,a0: 0x41F8 + 拡張語。
    let mut env = env_with_code(&[0x41F8, 0x4000]);
    env.step(|b| sem::exec(b, Insn::Lea, 0x41F8, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(A(0).state()), 0x4000);

    // lea に非制御 EA（(a0)+）を与えると illegal。
    let mut env = env_with_code(&[0x43D8]);
    assert!(
        env.step(|b| sem::exec(b, Insn::Lea, 0x43D8, 0x1000))
            .is_err()
    );

    // pea (a0): 0x4850。a0 の値を long で push。
    let mut env = env_with_data(&[0x4850], &[]);
    env.backend.set(A(0).state(), 0x6000);
    env.backend.set(sem::Ssp.state(), 0x4004);
    env.backend.set(sem::sr_ref(), 1 << sem::sr_bit::S);
    env.step(|b| sem::exec(b, Insn::Pea, 0x4850, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(sem::Ssp.state()), 0x4000);
    let mut buf = [0u8; 4];
    env.backend
        .mem
        .read(VirtAddr(0x4000), &mut buf, DRD)
        .unwrap();
    assert_eq!(u32::from_be_bytes(buf), 0x6000);

    // link a1,#-4: 0x4E51 + 0xFFFC。
    // ssp=0x4008 → sp-=4 → mem[0x4004]=a1旧値、a1=0x4004、sp=0x4004-4=0x4000。
    let mut env = env_with_data(&[0x4E51, 0xFFFC], &[]);
    env.backend.set(A(1).state(), 0x1234_5678);
    env.backend.set(sem::Ssp.state(), 0x4008);
    env.backend.set(sem::sr_ref(), 1 << sem::sr_bit::S);
    env.step(|b| sem::exec(b, Insn::Link, 0x4E51, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(A(1).state()), 0x4004);
    assert_eq!(env.backend.get(sem::Ssp.state()), 0x4000);
    env.backend
        .mem
        .read(VirtAddr(0x4004), &mut buf, DRD)
        .unwrap();
    assert_eq!(u32::from_be_bytes(buf), 0x1234_5678);

    // unlk a1: 0x4E59。sp=a1=0x4000、pop → a1=mem値、sp=0x4004。
    let mut env = env_with_data(&[0x4E59], &[]);
    env.backend.set(A(1).state(), 0x4000);
    env.backend.set(sem::Ssp.state(), 0x4000);
    env.backend.set(sem::sr_ref(), 1 << sem::sr_bit::S);
    env.backend
        .mem
        .write(VirtAddr(0x4000), &0xABCD_1234u32.to_be_bytes())
        .unwrap();
    env.step(|b| sem::exec(b, Insn::Unlk, 0x4E59, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(A(1).state()), 0xABCD_1234);
    assert_eq!(env.backend.get(sem::Ssp.state()), 0x4004);

    // 語数: link は常に 1、lea/pea は EA 拡張語。
    assert_eq!(ea::insn_ext_words(Insn::Link, 0x4E51), Some(1));
    assert_eq!(ea::insn_ext_words(Insn::Unlk, 0x4E59), Some(0));
    assert_eq!(ea::insn_ext_words(Insn::Lea, 0x41F8), Some(1)); // abs.w
    assert_eq!(ea::insn_ext_words(Insn::Pea, 0x4850), Some(0)); // (a0)
}

/// C8: decode 排他と a7 辺の挙動。
#[test]
fn lea_pea_link_unlk_edge() {
    // decode 排他: 0x4ED0=jmp(a0) vs 0x4FD0=lea(a0),a7（bit8）。
    assert_eq!(polyisa_guest_m68k::decode(0x4ED0, 16), Some(Insn::Jmp));
    assert_eq!(polyisa_guest_m68k::decode(0x4FD0, 16), Some(Insn::Lea));
    assert_eq!(polyisa_guest_m68k::decode(0x4E50, 16), Some(Insn::Link));
    assert_eq!(polyisa_guest_m68k::decode(0x4E59, 16), Some(Insn::Unlk));
    assert_eq!(polyisa_guest_m68k::decode(0x4E71, 16), Some(Insn::Nop));
    // 0x4840 は swap（C9 で実装済み）— pea の emode=0 空間。
    assert_eq!(polyisa_guest_m68k::decode(0x4840, 16), Some(Insn::Swap));

    // link a7,#-4: sp は「push 後の sp + disp」。ssp=0x4008 →
    // mem[0x4004]=0x4008、a7=0x4004-4=0x4000。
    let mut env = env_with_data(&[0x4E57, 0xFFFC], &[]);
    env.backend.set(sem::Ssp.state(), 0x4008);
    env.backend.set(sem::sr_ref(), 1 << sem::sr_bit::S);
    env.step(|b| sem::exec(b, Insn::Link, 0x4E57, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(sem::Ssp.state()), 0x4000);
    let mut buf = [0u8; 4];
    env.backend
        .mem
        .read(VirtAddr(0x4004), &mut buf, DRD)
        .unwrap();
    assert_eq!(u32::from_be_bytes(buf), 0x4008);

    // unlk a7: sp=a7 のあと pop 値が a7 に残る（最後の書き込み優先）。
    let mut env = env_with_data(&[0x4E5F], &[]);
    env.backend.set(sem::Ssp.state(), 0x4000);
    env.backend.set(sem::sr_ref(), 1 << sem::sr_bit::S);
    env.backend
        .mem
        .write(VirtAddr(0x4000), &0xDEAD_BEEFu32.to_be_bytes())
        .unwrap();
    env.step(|b| sem::exec(b, Insn::Unlk, 0x4E5F, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(sem::Ssp.state()), 0xDEAD_BEEF);
}

/// C9: exg/swap/ext。
// Ref: SPEC-M68K-PRM (Rev 1) §EXG/SWAP/EXT.
#[test]
fn exg_swap_ext() {
    // exg d0,d1: 0xC141。32bit 交換、旗不変。
    let mut env = env_with_code(&[0xC141]);
    env.backend.set(D(0).state(), 0x1111_2222);
    env.backend.set(D(1).state(), 0x3333_4444);
    env.backend.set(sem::ccr_ref(), 0x1F);
    env.step(|b| sem::exec(b, Insn::ExgDd, 0xC141, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0x3333_4444);
    assert_eq!(env.backend.get(D(1).state()), 0x1111_2222);
    assert_eq!(env.backend.get(sem::ccr_ref()), 0x1F);

    // exg a0,a1: 0xC149。
    let mut env = env_with_code(&[0xC149]);
    env.backend.set(A(0).state(), 0x1000);
    env.backend.set(A(1).state(), 0x2000);
    env.step(|b| sem::exec(b, Insn::ExgAa, 0xC149, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(A(0).state()), 0x2000);
    assert_eq!(env.backend.get(A(1).state()), 0x1000);

    // exg d0,a0: 0xC188（dreg=0、ereg=0）。
    let mut env = env_with_code(&[0xC188]);
    env.backend.set(D(0).state(), 0xAAAA);
    env.backend.set(A(0).state(), 0xBBBB);
    env.step(|b| sem::exec(b, Insn::ExgDa, 0xC188, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0xBBBB);
    assert_eq!(env.backend.get(A(0).state()), 0xAAAA);

    // swap d0: 0x4840。0x1234_5678 → 0x5678_1234、N=0 Z=0、X 保持。
    let mut env = env_with_code(&[0x4840]);
    env.backend.set(D(0).state(), 0x1234_5678);
    env.backend.set(sem::ccr_ref(), 0x1F);
    env.step(|b| sem::exec(b, Insn::Swap, 0x4840, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0x5678_1234);
    // 0x1F & !0b1111 | N/Z → bit4(X) のみ残る。
    assert_eq!(env.backend.get(sem::ccr_ref()), 0x10);

    // swap で負数: 0x0000_8000 → 0x8000_0000 → N=1。
    let mut env = env_with_code(&[0x4840]);
    env.backend.set(D(0).state(), 0x0000_8000);
    env.step(|b| sem::exec(b, Insn::Swap, 0x4840, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0x8000_0000);
    assert_eq!(env.backend.get(sem::ccr_ref()) & 0x08, 0x08);

    // ext.w d0: 0x4880。byte 0x80 → word 0xFF80、上位 word 保持、N=1。
    let mut env = env_with_code(&[0x4880]);
    env.backend.set(D(0).state(), 0xABCD_0080);
    env.step(|b| sem::exec(b, Insn::ExtW, 0x4880, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0xABCD_FF80);
    assert_eq!(env.backend.get(sem::ccr_ref()) & 0x08, 0x08);

    // ext.l d0: 0x48C0。word 0x7FFF → 0x0000_7FFF、N=0 Z=0。
    let mut env = env_with_code(&[0x48C0]);
    env.backend.set(D(0).state(), 0x1234_7FFF);
    env.step(|b| sem::exec(b, Insn::ExtL, 0x48C0, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0x0000_7FFF);
    assert_eq!(env.backend.get(sem::ccr_ref()) & 0x0C, 0x00);

    // decode: exg の空間は and_*_dn と排他。
    assert_eq!(polyisa_guest_m68k::decode(0xC140, 16), Some(Insn::ExgDd));
    assert_eq!(polyisa_guest_m68k::decode(0xC148, 16), Some(Insn::ExgAa));
    assert_eq!(polyisa_guest_m68k::decode(0xC188, 16), Some(Insn::ExgDa));
    assert_eq!(polyisa_guest_m68k::decode(0x4840, 16), Some(Insn::Swap));
    assert_eq!(polyisa_guest_m68k::decode(0x4880, 16), Some(Insn::ExtW));
    assert_eq!(polyisa_guest_m68k::decode(0x48C0, 16), Some(Insn::ExtL));
    // and.l d0,d0 (0xC180) は emode=0 で残る。
    assert_eq!(polyisa_guest_m68k::decode(0xC180, 16), Some(Insn::AndLDn));
}

/// C10: movem/movep。
// Ref: SPEC-M68K-PRM (Rev 1) §MOVEM/MOVEP.
#[test]
fn movem_movep() {
    // movem.l <list>,(a0) = 0100 1000 11 010 000 = 0x48D0、mask 0x0003。
    let mut env = env_with_data(&[0x48D0, 0x0003], &[]);
    env.backend.set(D(0).state(), 0x1111_2222);
    env.backend.set(D(1).state(), 0x3333_4444);
    env.backend.set(A(0).state(), 0x4000);
    env.backend.set(sem::ccr_ref(), 0x1F);
    env.step(|b| sem::exec(b, Insn::MovrmL, 0x48D0, 0x1000))
        .unwrap();
    let mut buf = [0u8; 8];
    env.backend
        .mem
        .read(VirtAddr(0x4000), &mut buf, DRD)
        .unwrap();
    assert_eq!(&buf[..4], &0x1111_2222u32.to_be_bytes());
    assert_eq!(&buf[4..8], &0x3333_4444u32.to_be_bytes());
    assert_eq!(env.backend.get(sem::ccr_ref()), 0x1F);

    // mrmem.w (a0),<list>: 0x4C90、mask 0x0001 → d0 = sext16(mem)。
    let mut env = env_with_data(&[0x4C90, 0x0001], &[]);
    env.backend.set(A(0).state(), 0x4000);
    env.backend
        .mem
        .write(VirtAddr(0x4000), &0x8000u16.to_be_bytes())
        .unwrap();
    env.step(|b| sem::exec(b, Insn::MrmemW, 0x4C90, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0xFFFF_8000);

    // movrm.w -(a7): 0x48A7? -(a7) = 0x48 27 系… 0100 1000 10 100 111 = 0x48A7。
    // mask 0x8001 → predec 反転: bit0=A7, bit15=D0 → A7(自身)とD0 を退避。
    let mut env = env_with_data(&[0x48A7, 0x8001], &[]);
    env.backend.set(D(0).state(), 0x0000_BEEF);
    env.backend.set(sem::Ssp.state(), 0x4004);
    env.backend.set(sem::sr_ref(), 1 << sem::sr_bit::S);
    env.step(|b| sem::exec(b, Insn::MovrmW, 0x48A7, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(sem::Ssp.state()), 0x4000);
    // 格納値は初期値のまま（predec でも減算前の An が書かれる）。
    let mut buf2 = [0u8; 4];
    env.backend
        .mem
        .read(VirtAddr(0x4000), &mut buf2, DRD)
        .unwrap();
    assert_eq!(&buf2[..2], &0xBEEFu16.to_be_bytes()); // d0
    assert_eq!(&buf2[2..4], &0x4004u16.to_be_bytes()); // a7 初期値

    // mrmem.l (a0)+,<list>: 0x4CD8、mask 0x8000 → a7 = mem、
    // a0 += 4。
    let mut env = env_with_data(&[0x4CD8, 0x8000], &[]);
    env.backend.set(A(0).state(), 0x4000);
    env.backend.set(sem::sr_ref(), 1 << sem::sr_bit::S);
    env.backend
        .mem
        .write(VirtAddr(0x4000), &0x7777_6666u32.to_be_bytes())
        .unwrap();
    env.step(|b| sem::exec(b, Insn::MrmemL, 0x4CD8, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(sem::Ssp.state()), 0x7777_6666);
    assert_eq!(env.backend.get(A(0).state()), 0x4004);

    // movep.w (d16,a0),d0: 0x0108 + 変位 0x0000。
    // mem[0x4000]=0xAB, mem[0x4002]=0xCD → d0.w = 0xABCD（上位 word 保持）。
    let mut env = env_with_data(&[0x0108, 0x0000], &[0xAB, 0, 0xCD]);
    env.backend.set(A(0).state(), 0x4000);
    env.backend.set(D(0).state(), 0x1234_5678);
    env.step(|b| sem::exec(b, Insn::MovepWm, 0x0108, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0x1234_ABCD);

    // movep.l d0→(d16,a0): 0x01C8 + 変位 0x0002 → mem[a0+2+{0,2,4,6}]。
    let mut env = env_with_data(&[0x01C8, 0x0002], &[]);
    env.backend.set(A(0).state(), 0x4000);
    env.backend.set(D(0).state(), 0x11_22_33_44);
    env.step(|b| sem::exec(b, Insn::MovepLr, 0x01C8, 0x1000))
        .unwrap();
    let mut buf3 = [0u8; 8];
    env.backend
        .mem
        .read(VirtAddr(0x4002), &mut buf3, DRD)
        .unwrap();
    assert_eq!(buf3, [0x11, 0, 0x22, 0, 0x33, 0, 0x44, 0]);

    // 語数: movrm は EA 拡張語 + マスク1語。
    assert_eq!(ea::insn_ext_words(Insn::MovrmW, 0x48A0), Some(1)); // -(a0)
    assert_eq!(ea::insn_ext_words(Insn::MrmemL, 0x4CF8), Some(2)); // abs.w
    assert_eq!(ea::insn_ext_words(Insn::MovepWm, 0x0108), Some(1));
    // movrm.l <list>,($4000).w: 0x48F8、mask 0x0003、abs.w 拡張語。
    let mut env = env_with_data(&[0x48F8, 0x0003, 0x4000], &[]);
    env.backend.set(D(0).state(), 0xAAAA);
    env.backend.set(D(1).state(), 0xBBBB);
    env.step(|b| sem::exec(b, Insn::MovrmL, 0x48F8, 0x1000))
        .unwrap();
    let mut buf4 = [0u8; 8];
    env.backend
        .mem
        .read(VirtAddr(0x4000), &mut buf4, DRD)
        .unwrap();
    assert_eq!(&buf4[..4], &0x0000_AAAAu32.to_be_bytes());
    assert_eq!(&buf4[4..8], &0x0000_BBBBu32.to_be_bytes());
    assert_eq!(ea::insn_ext_words(Insn::MovrmL, 0x48F8), Some(2));

    // movrm に (a0)+ は illegal。
    let mut env = env_with_data(&[0x48D8, 0x0001], &[]);
    assert!(
        env.step(|b| sem::exec(b, Insn::MovrmW, 0x48D8, 0x1000))
            .is_err()
    );
}

/// C11: mulu/muls/divu/divs。
// Ref: SPEC-M68K-PRM (Rev 1) §MULU/MULS/DIVU/DIVS.
#[test]
fn mul_div() {
    // mulu d0,d1: 0xC2C0。0x0003 × 0x0004 = 12、上位 word は無視。
    let mut env = env_with_code(&[0xC2C0]);
    env.backend.set(D(0).state(), 0xDEAD_0003);
    env.backend.set(D(1).state(), 0x0000_0004);
    env.step(|b| sem::exec(b, Insn::Mulu, 0xC2C0, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(1).state()), 12);

    // muls d0,d1: 0xC3C0。-1 × -1 = 1。
    let mut env = env_with_code(&[0xC3C0]);
    env.backend.set(D(0).state(), 0x0000_FFFF);
    env.backend.set(D(1).state(), 0xFFFF_FFFF);
    env.step(|b| sem::exec(b, Insn::Muls, 0xC3C0, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(1).state()), 1);

    // muls で負: -2 × 3 = -6 = 0xFFFF_FFFA → N=1。
    let mut env = env_with_code(&[0xC3C0]);
    env.backend.set(D(0).state(), 0x0000_FFFE);
    env.backend.set(D(1).state(), 0x0000_0003);
    env.step(|b| sem::exec(b, Insn::Muls, 0xC3C0, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(1).state()), 0xFFFF_FFFA);
    assert_eq!(env.backend.get(sem::ccr_ref()) & 0x08, 0x08);

    // divu d0,d1: 0x82C0。0x1000_0000 ÷ 0x1000 = 0x10000 → ovf。
    // ovf 規約: V=1, N=1, Z=0, Dn 不変。
    let mut env = env_with_code(&[0x82C0]);
    env.backend.set(D(0).state(), 0x0000_1000);
    env.backend.set(D(1).state(), 0x1000_0000);
    env.backend.set(sem::ccr_ref(), 0x1F);
    env.step(|b| sem::exec(b, Insn::Divu, 0x82C0, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(1).state()), 0x1000_0000);
    assert_eq!(env.backend.get(sem::ccr_ref()), 0x1A);

    // divu 商が 16bit を超えると ovf（Dn 不変）。次は正常系:
    // 100 ÷ 3 = 33 r 1 → d1 = 0x0001_0021。
    let mut env = env_with_code(&[0x82C0]);
    env.backend.set(D(0).state(), 3);
    env.backend.set(D(1).state(), 100);
    env.step(|b| sem::exec(b, Insn::Divu, 0x82C0, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(1).state()), 0x0001_0021);

    // divu 0: 例外ベクタ 5。
    let mut env = env_with_code(&[0x82C0]);
    env.backend.set(D(0).state(), 0);
    env.backend.set(D(1).state(), 100);
    let r = env.step(|b| sem::exec(b, Insn::Divu, 0x82C0, 0x1000));
    assert!(r.is_err());

    // divs d0,d1: 0x83C0。-6 ÷ 3 = -2 r 0 → d1 = 0x0000_FFFE。
    let mut env = env_with_code(&[0x83C0]);
    env.backend.set(D(0).state(), 3);
    env.backend.set(D(1).state(), 0xFFFF_FFFA);
    env.step(|b| sem::exec(b, Insn::Divs, 0x83C0, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(1).state()), 0x0000_FFFE);

    // divs の ovf 境界: -32769 は商に収まらない → V=1 N=1。
    // -7 ÷ 3 = -2 r -1 → d1 = 0xFFFF_FFFE（剰余は負）。
    let mut env = env_with_code(&[0x83C0]);
    env.backend.set(D(0).state(), 3);
    env.backend.set(D(1).state(), 0xFFFF_FFF9); // -7
    env.step(|b| sem::exec(b, Insn::Divs, 0x83C0, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(1).state()), 0xFFFF_FFFE);

    // divs ovf: 0x0002_0000 ÷ 1 = 0x20000 → ovf。Dn 不変。
    let mut env = env_with_code(&[0x83C0]);
    env.backend.set(D(0).state(), 1);
    env.backend.set(D(1).state(), 0x0002_0000);
    env.step(|b| sem::exec(b, Insn::Divs, 0x83C0, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(1).state()), 0x0002_0000);

    // divu 0 はベクタ 5。
    let mut env = env_with_code(&[0x82C0]);
    env.backend.set(D(0).state(), 0);
    env.backend.set(D(1).state(), 0x1234);
    match env.step(|b| sem::exec(b, Insn::Divu, 0x82C0, 0x1000)) {
        Err(InterpExit::Exception(e)) => assert_eq!(e.code, 5),
        r => panic!("expected vector 5: {r:?}"),
    }
    // 例外時は Dn 不変。
    assert_eq!(env.backend.get(D(1).state()), 0x1234);

    // An 直宛 source は illegal（ベクタ 4）。
    let mut env = env_with_code(&[0x82C8]);
    match env.step(|b| sem::exec(b, Insn::Divu, 0x82C8, 0x1000)) {
        Err(InterpExit::Exception(e)) => assert_eq!(e.code, 4),
        r => panic!("expected illegal: {r:?}"),
    }

    // 語数: ea 拡張語のみ。
    assert_eq!(ea::insn_ext_words(Insn::Mulu, 0xC2C0), Some(0));
    assert_eq!(ea::insn_ext_words(Insn::Divu, 0x82F8), Some(1)); // abs.w
}

#[test]
fn bcd_arith() {
    // abcd d1,d0: 0xC001。09 + 12 = 21（補正あり）。
    let mut env = env_with_code(&[0xC001]);
    env.backend.set(D(0).state(), 0xBEEF_0009);
    env.backend.set(D(1).state(), 0x0000_0012);
    env.step(|b| sem::exec(b, Insn::AbcdR, 0xC001, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0xBEEF_0021);
    assert_eq!(env.backend.get(sem::ccr_ref()) & 0x1F, 0);

    // abcd で X 入力: 09 + 12 + 1 = 22。
    let mut env = env_with_code(&[0xC001]);
    env.backend.set(D(0).state(), 0x09);
    env.backend.set(D(1).state(), 0x12);
    env.backend.set(sem::ccr_ref(), 1 << sem::sr_bit::X);
    env.step(|b| sem::exec(b, Insn::AbcdR, 0xC001, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0x22);

    // abcd 45 + 55 = 100 → 00 で C/X=1。
    let mut env = env_with_code(&[0xC001]);
    env.backend.set(D(0).state(), 0x45);
    env.backend.set(D(1).state(), 0x55);
    env.step(|b| sem::exec(b, Insn::AbcdR, 0xC001, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0x00);
    assert_eq!(
        env.backend.get(sem::ccr_ref()) & 0x1F,
        (1 << sem::sr_bit::X) | (1 << sem::sr_bit::C)
    );

    // abcd の Z は累積: 旧 Z=1 かつ結果 0 → Z=1。
    let mut env = env_with_code(&[0xC001]);
    env.backend.set(D(0).state(), 0x45);
    env.backend.set(D(1).state(), 0x55);
    env.backend.set(sem::ccr_ref(), 1 << sem::sr_bit::Z);
    env.step(|b| sem::exec(b, Insn::AbcdR, 0xC001, 0x1000))
        .unwrap();
    assert_eq!(
        env.backend.get(sem::ccr_ref()) & 0x1F,
        (1 << sem::sr_bit::X) | (1 << sem::sr_bit::Z) | (1 << sem::sr_bit::C)
    );

    // abcd の V: 18+67=85（生和 bit7=0→結果 bit7=1 → V=1）。
    let mut env = env_with_code(&[0xC001]);
    env.backend.set(D(0).state(), 0x18);
    env.backend.set(D(1).state(), 0x67);
    env.step(|b| sem::exec(b, Insn::AbcdR, 0xC001, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0x85);
    assert_eq!(
        env.backend.get(sem::ccr_ref()) & 0x1F,
        (1 << sem::sr_bit::V) | (1 << sem::sr_bit::N)
    );

    // sbcd d1,d0: 0x8001。00 - 01 = 99、borrow で X/C=1、N=1。
    let mut env = env_with_code(&[0x8001]);
    env.backend.set(D(0).state(), 0x00);
    env.backend.set(D(1).state(), 0x01);
    env.step(|b| sem::exec(b, Insn::SbcdR, 0x8001, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0x99);
    assert_eq!(
        env.backend.get(sem::ccr_ref()) & 0x1F,
        (1 << sem::sr_bit::X) | (1 << sem::sr_bit::N) | (1 << sem::sr_bit::C)
    );

    // sbcd の実機固有ケース: 0x10 - 0x0F - 1(X) = 0xFA、X/C=1、N=1。
    // （下位ニブル借用のみで -0x60 補正は入らない）
    let mut env = env_with_code(&[0x8001]);
    env.backend.set(D(0).state(), 0x10);
    env.backend.set(D(1).state(), 0x0F);
    env.backend.set(sem::ccr_ref(), 1 << sem::sr_bit::X);
    env.step(|b| sem::exec(b, Insn::SbcdR, 0x8001, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0xFA);
    assert_eq!(
        env.backend.get(sem::ccr_ref()) & 0x1F,
        (1 << sem::sr_bit::X) | (1 << sem::sr_bit::N) | (1 << sem::sr_bit::C)
    );

    // sbcd 0xA3 - 0xBC = 0x81（両ニブル借用 → -0x66 相当）。
    let mut env = env_with_code(&[0x8001]);
    env.backend.set(D(0).state(), 0xA3);
    env.backend.set(D(1).state(), 0xBC);
    env.step(|b| sem::exec(b, Insn::SbcdR, 0x8001, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0x81);

    // sbcd 同一値: 0x42 - 0x42 = 0x00（Z は累積: 旧 Z=0 → 0 のまま）。
    let mut env = env_with_code(&[0x8001]);
    env.backend.set(D(0).state(), 0x42);
    env.backend.set(D(1).state(), 0x42);
    env.step(|b| sem::exec(b, Insn::SbcdR, 0x8001, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0x00);
    assert_eq!(env.backend.get(sem::ccr_ref()) & 0x1F, 0);

    // nbcd d0: 0x4800。0 - 0x00 - 1(X) = 0x99、X/C=1。
    let mut env = env_with_code(&[0x4800]);
    env.backend.set(D(0).state(), 0x00);
    env.backend.set(sem::ccr_ref(), 1 << sem::sr_bit::X);
    env.step(|b| sem::exec(b, Insn::Nbcd, 0x4800, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0x99);
    assert_eq!(
        env.backend.get(sem::ccr_ref()) & 0x1F,
        (1 << sem::sr_bit::X) | (1 << sem::sr_bit::N) | (1 << sem::sr_bit::C)
    );

    // nbcd 0x80 → 0x20、V=1（生差 bit7=1 かつ結果 bit7=0）。
    let mut env = env_with_code(&[0x4800]);
    env.backend.set(D(0).state(), 0x80);
    env.step(|b| sem::exec(b, Insn::Nbcd, 0x4800, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0x20);
    assert_eq!(
        env.backend.get(sem::ccr_ref()) & 0x1F,
        (1 << sem::sr_bit::X) | (1 << sem::sr_bit::V) | (1 << sem::sr_bit::C)
    );

    // nbcd 0x00 → 0x00。Z 累積: 旧 Z=1 → Z=1、C=0。
    let mut env = env_with_code(&[0x4800]);
    env.backend.set(D(0).state(), 0x00);
    env.backend.set(sem::ccr_ref(), 1 << sem::sr_bit::Z);
    env.step(|b| sem::exec(b, Insn::Nbcd, 0x4800, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0x00);
    assert_eq!(env.backend.get(sem::ccr_ref()) & 0x1F, 1 << sem::sr_bit::Z);
}

#[test]
fn bcd_mem_predec() {
    // abcd -(a1),-(a2): 0xC409。src=(a1-1), dst=(a2-1)。結果を a2-1 へ。
    let mut env = env_with_data(&[0xC409], &[0x11, 0x25]);
    env.backend.set(A(1).state(), 0x4002);
    env.backend.set(A(2).state(), 0x4001);
    env.step(|b| sem::exec(b, Insn::AbcdM, 0xC409, 0x1000))
        .unwrap();
    // src=mem[0x4001]=0x25、dst=mem[0x4000]=0x11 → 0x11+0x25=0x36。
    let mut buf = [0u8; 1];
    env.backend
        .mem
        .read(VirtAddr(0x4000), &mut buf, DRD)
        .unwrap();
    assert_eq!(buf[0], 0x36);
    assert_eq!(env.backend.get(A(1).state()), 0x4001);
    assert_eq!(env.backend.get(A(2).state()), 0x4000);

    // sbcd -(a1),-(a1): 0x8309。Ax==Ay の別名ケース。
    // src=(a1-1), dst=(a1-2)。結果を a1-2 へ。実機もこの順序。
    let mut env = env_with_data(&[0x8309], &[0x12, 0x34]);
    env.backend.set(A(1).state(), 0x4002);
    env.step(|b| sem::exec(b, Insn::SbcdM, 0x8309, 0x1000))
        .unwrap();
    // src = mem[0x4001] = 0x34、dst = mem[0x4000] = 0x12 → 0x12-0x34 = 0x78。
    // X/C=1、V=1（生差は負だが補正後は正）。
    let mut buf = [0u8; 1];
    env.backend
        .mem
        .read(VirtAddr(0x4000), &mut buf, DRD)
        .unwrap();
    assert_eq!(buf[0], 0x78);
    assert_eq!(env.backend.get(A(1).state()), 0x4000);
    assert_eq!(
        env.backend.get(sem::ccr_ref()) & 0x1F,
        (1 << sem::sr_bit::X) | (1 << sem::sr_bit::V) | (1 << sem::sr_bit::C)
    );

    // abcd -(a7),-(a0): 0xC00F。A7 は byte でも -2。
    // ユーザモード（S=0）では A7 EA は USP を参照する。
    let mut env = env_with_data(&[0xC00F], &[0x15, 0x27]);
    env.backend.set(Usp.state(), 0x4002);
    env.backend.set(A(0).state(), 0x4002);
    env.step(|b| sem::exec(b, Insn::AbcdM, 0xC00F, 0x1000))
        .unwrap();
    // src = mem[a7-2 = 0x4000] = 0x15、dst = mem[a0-1 = 0x4001] = 0x27。
    // 0x15 + 0x27 = 0x42 → mem[0x4001]。
    let mut buf = [0u8; 1];
    env.backend
        .mem
        .read(VirtAddr(0x4001), &mut buf, DRD)
        .unwrap();
    assert_eq!(buf[0], 0x42);
    assert_eq!(env.backend.get(Usp.state()), 0x4000);
    assert_eq!(env.backend.get(A(0).state()), 0x4001);

    // nbcd は An 直宛が illegal（ベクタ 4）。
    let mut env = env_with_code(&[0x4808]);
    match env.step(|b| sem::exec(b, Insn::Nbcd, 0x4808, 0x1000)) {
        Err(InterpExit::Exception(e)) => assert_eq!(e.code, 4),
        r => panic!("expected illegal: {r:?}"),
    }

    // nbcd -(a0): 0x4820。メモリ経路: 0 - 0x30 = 0x70。
    let mut env = env_with_data(&[0x4820], &[0x30]);
    env.backend.set(A(0).state(), 0x4001);
    env.step(|b| sem::exec(b, Insn::Nbcd, 0x4820, 0x1000))
        .unwrap();
    let mut buf = [0u8; 1];
    env.backend
        .mem
        .read(VirtAddr(0x4000), &mut buf, DRD)
        .unwrap();
    // X/C=1、V=1（生差は負だが補正後は正）。
    assert_eq!(buf[0], 0x70);
    assert_eq!(env.backend.get(A(0).state()), 0x4000);
    assert_eq!(
        env.backend.get(sem::ccr_ref()) & 0x1F,
        (1 << sem::sr_bit::X) | (1 << sem::sr_bit::V) | (1 << sem::sr_bit::C)
    );

    // nbcd の PC 相対・即値宛も illegal。
    let mut env = env_with_code(&[0x483A]);
    match env.step(|b| sem::exec(b, Insn::Nbcd, 0x483A, 0x1000)) {
        Err(InterpExit::Exception(e)) => assert_eq!(e.code, 4),
        r => panic!("expected illegal: {r:?}"),
    }
    let mut env = env_with_code(&[0x483C]);
    match env.step(|b| sem::exec(b, Insn::Nbcd, 0x483C, 0x1000)) {
        Err(InterpExit::Exception(e)) => assert_eq!(e.code, 4),
        r => panic!("expected illegal: {r:?}"),
    }

    // 語数: abcd/sbcd は 0、nbcd は EA 拡張語数。
    assert_eq!(ea::insn_ext_words(Insn::AbcdR, 0xC001), Some(0));
    assert_eq!(ea::insn_ext_words(Insn::SbcdM, 0x8309), Some(0));
    assert_eq!(ea::insn_ext_words(Insn::Nbcd, 0x4800), Some(0));
    assert_eq!(ea::insn_ext_words(Insn::Nbcd, 0x4838), Some(1)); // abs.w
    assert_eq!(ea::insn_ext_words(Insn::Nbcd, 0x4839), Some(2)); // abs.l
}

// ---- C13: trap/trapv/chk/reset/linea/linef・move to/from ccr|sr ----

#[test]
fn c13_decode_spots() {
    for w in 0x4E40..=0x4E4F {
        assert_eq!(
            polyisa_guest_m68k::decode(w, 16),
            Some(Insn::Trap),
            "{w:#06x}"
        );
    }
    assert_eq!(polyisa_guest_m68k::decode(0x4E76, 16), Some(Insn::Trapv));
    assert_eq!(polyisa_guest_m68k::decode(0x4E72, 16), Some(Insn::Stop));
    assert_eq!(polyisa_guest_m68k::decode(0xA000, 16), Some(Insn::Linea));
    assert_eq!(polyisa_guest_m68k::decode(0xAFFF, 16), Some(Insn::Linea));
    assert_eq!(polyisa_guest_m68k::decode(0xF000, 16), Some(Insn::Linef));
    assert_eq!(polyisa_guest_m68k::decode(0xFFFF, 16), Some(Insn::Linef));
    // chk d0,d0: 0100 000 110 000 000
    assert_eq!(polyisa_guest_m68k::decode(0x4180, 16), Some(Insn::Chk));
    // move <ea>,ccr / <ea>,sr / sr,<ea>
    assert_eq!(polyisa_guest_m68k::decode(0x44C0, 16), Some(Insn::Mv2ccr));
    assert_eq!(polyisa_guest_m68k::decode(0x46C0, 16), Some(Insn::Mv2sr));
    assert_eq!(polyisa_guest_m68k::decode(0x40C0, 16), Some(Insn::Mvfrsr));
}

#[test]
fn trap_raises_vector32_plus_n() {
    let mut env = env();
    let e = env
        .step(|b| sem::exec(b, Insn::Trap, 0x4E45, 0))
        .expect_err("trap は例外");
    match e {
        // trap #5 → ベクタ 37。
        InterpExit::Exception(x) => assert_eq!(x.code, 32 + 5),
        other => panic!("unexpected exit: {other:?}"),
    }
}

#[test]
fn trapv_raises_only_when_v_set() {
    // V=0 → 例外なし。
    let mut env = env();
    env.step(|b| sem::exec(b, Insn::Trapv, 0x4E76, 0)).unwrap();
    // V=1 → ベクタ 7。
    let mut env2 = crate::env();
    env2.backend
        .set(sem::ccr_ref(), (1 << sem::sr_bit::V) as u8);
    let e = env2
        .step(|b| sem::exec(b, Insn::Trapv, 0x4E76, 0))
        .expect_err("V=1 の trapv は例外");
    match e {
        InterpExit::Exception(x) => assert_eq!(x.code, 7),
        other => panic!("unexpected exit: {other:?}"),
    }
}

#[test]
fn linea_linef_raise_vectors_10_11() {
    let mut env = env();
    let e = env
        .step(|b| sem::exec(b, Insn::Linea, 0xA123, 0))
        .expect_err("linea は例外");
    match e {
        InterpExit::Exception(x) => assert_eq!(x.code, 10),
        other => panic!("unexpected exit: {other:?}"),
    }
    let mut env2 = crate::env();
    let e = env2
        .step(|b| sem::exec(b, Insn::Linef, 0xF123, 0))
        .expect_err("linef は例外");
    match e {
        InterpExit::Exception(x) => assert_eq!(x.code, 11),
        other => panic!("unexpected exit: {other:?}"),
    }
}

#[test]
fn chk_pass_clears_nzvc() {
    // chk #5,d0 = 0100 000 110 111 100 = 0x41FC（即値 EA 拡張語）。
    let mut env = env_with_data(&[0x41FC, 0x0005], &[]);
    env.backend.set(D(0).state(), 3);
    env.backend.set(sem::ccr_ref(), 0x1F);
    env.step(|b| sem::exec(b, Insn::Chk, 0x41FC, 0x1000))
        .unwrap();
    // 通過時は X のみ保持。
    assert_eq!(env.backend.get(sem::ccr_ref()) & 0x1F, 1 << sem::sr_bit::X);
}

#[test]
fn chk_trap_bound_and_negative() {
    // d0=6 > bound 5 → ベクタ 6、N=0。
    let mut env = env_with_data(&[0x41FC, 0x0005], &[]);
    env.backend.set(D(0).state(), 6);
    env.backend.set(sem::ccr_ref(), 0x1F);
    let e = env
        .step(|b| sem::exec(b, Insn::Chk, 0x41FC, 0x1000))
        .expect_err("上限超過で例外");
    match e {
        InterpExit::Exception(x) => assert_eq!(x.code, 6),
        other => panic!("unexpected exit: {other:?}"),
    }
    assert_eq!(env.backend.get(sem::ccr_ref()) & (1 << sem::sr_bit::N), 0);

    // d0=-1 < 0 → ベクタ 6、N=1。
    let mut env2 = env_with_data(&[0x41FC, 0x0005], &[]);
    env2.backend.set(D(0).state(), 0xFFFF);
    env2.backend.set(sem::ccr_ref(), 0);
    let e = env2
        .step(|b| sem::exec(b, Insn::Chk, 0x41FC, 0x1000))
        .expect_err("負数で例外");
    match e {
        InterpExit::Exception(x) => assert_eq!(x.code, 6),
        other => panic!("unexpected exit: {other:?}"),
    }
    assert_eq!(
        env2.backend.get(sem::ccr_ref()) & (1 << sem::sr_bit::N),
        1 << sem::sr_bit::N
    );

    // chk の An 宛（上限が An）は illegal。
    let mut env3 = crate::env();
    let e = env3
        .step(|b| sem::exec(b, Insn::Chk, 0x4188, 0))
        .expect_err("chk の An 上限は illegal");
    match e {
        InterpExit::Exception(x) => assert_eq!(x.code, 4),
        other => panic!("unexpected exit: {other:?}"),
    }
}

#[test]
fn move_to_ccr_reads_word_writes_low5() {
    // move (a0),ccr = 0100 0100 11 010 000 = 0x44D0。
    // 実機は word 読み。下位 byte の 5bit のみ CCR へ。
    let mut env = env_with_data(&[0x44D0], &[0x12, 0xBC]);
    env.backend.set(A(0).state(), 0x4000);
    env.backend.set(sem::ccr_ref(), 0x05);
    env.step(|b| sem::exec(b, Insn::Mv2ccr, 0x44D0, 0x1000))
        .unwrap();
    // 0xBC & 0x1F = 0x1C（word 0x12BC の下位 byte）。
    assert_eq!(env.backend.get(sem::ccr_ref()) & 0x1F, 0xBC & 0x1F);
}

#[test]
fn move_from_sr_writes_sr() {
    // move sr,(a0) = 0100 0000 11 010 000 = 0x40D0。
    // 68000 ではユーザモード（S=0）でも実行可。
    let mut env = env_with_data(&[0x40D0], &[0, 0]);
    env.backend.set(A(0).state(), 0x4000);
    env.backend.set(sem::sr_ref(), 0x001F);
    env.step(|b| sem::exec(b, Insn::Mvfrsr, 0x40D0, 0x1000))
        .unwrap();
    let mut buf = [0u8; 2];
    env.backend
        .mem
        .read(VirtAddr(0x4000), &mut buf, DRD)
        .unwrap();
    assert_eq!(u16::from_be_bytes(buf), 0x001F);
}

#[test]
fn move_to_sr_requires_supervisor() {
    // move (a0),sr = 0100 0110 11 010 000 = 0x46D0。
    // ユーザモード → ベクタ 8。
    let mut env = env_with_data(&[0x46D0], &[0x27, 0x00]);
    env.backend.set(A(0).state(), 0x4000);
    let e = env
        .step(|b| sem::exec(b, Insn::Mv2sr, 0x46D0, 0x1000))
        .expect_err("ユーザモードの move to sr は特権違反");
    match e {
        InterpExit::Exception(x) => assert_eq!(x.code, 8),
        other => panic!("unexpected exit: {other:?}"),
    }

    // スーパーバイザ（S=1）→ sr 更新（0xA71F マスク）。
    let mut env2 = env_with_data(&[0x46D0], &[0xFF, 0xFF]);
    env2.backend.set(A(0).state(), 0x4000);
    env2.backend.set(sem::sr_ref(), 0x2000);
    env2.step(|b| sem::exec(b, Insn::Mv2sr, 0x46D0, 0x1000))
        .unwrap();
    assert_eq!(env2.backend.get(sem::sr_ref()), 0xA71F);
}

#[test]
fn reset_requires_supervisor() {
    // ユーザモード → ベクタ 8。
    let mut env = env();
    let e = env
        .step(|b| sem::exec(b, Insn::Reset, 0x4E70, 0))
        .expect_err("ユーザモードの reset は特権違反");
    match e {
        InterpExit::Exception(x) => assert_eq!(x.code, 8),
        other => panic!("unexpected exit: {other:?}"),
    }
    // スーパーバイザ → 外部リセット（CPU 状態不変）で正常終了。
    let mut env2 = crate::env();
    env2.backend.set(sem::sr_ref(), 0x2000);
    env2.step(|b| sem::exec(b, Insn::Reset, 0x4E70, 0)).unwrap();
}

#[test]
fn c13_illegal_eas() {
    // move <ea>,ccr / <ea>,sr の An 宛は illegal。
    let mut env = env();
    let e = env
        .step(|b| sem::exec(b, Insn::Mv2ccr, 0x44C8, 0))
        .expect_err("mv2ccr の An 宛は illegal");
    match e {
        InterpExit::Exception(x) => assert_eq!(x.code, 4),
        other => panic!("unexpected exit: {other:?}"),
    }
    let mut env2 = crate::env();
    let e = env2
        .step(|b| sem::exec(b, Insn::Mv2sr, 0x46C8, 0))
        .expect_err("mv2sr の An 宛は illegal");
    match e {
        InterpExit::Exception(x) => assert_eq!(x.code, 4),
        other => panic!("unexpected exit: {other:?}"),
    }
    // move sr,<ea> の PC 相対・即値宛も illegal（0x40FA / 0x40FC）。
    for w in [0x40FA, 0x40FC] {
        let mut env3 = crate::env();
        let e = env3
            .step(|b| sem::exec(b, Insn::Mvfrsr, w, 0))
            .expect_err("mvfrsr の非書換宛は illegal");
        match e {
            InterpExit::Exception(x) => assert_eq!(x.code, 4, "{w:#06x}"),
            other => panic!("unexpected exit: {other:?}"),
        }
    }
}

#[test]
fn chk_bound_equal_passes() {
    // d0 == bound → 通過（NZVC=0）。
    let mut env = env_with_data(&[0x41FC, 0x0005], &[]);
    env.backend.set(D(0).state(), 5);
    env.backend.set(sem::ccr_ref(), 0x1F);
    env.step(|b| sem::exec(b, Insn::Chk, 0x41FC, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(sem::ccr_ref()) & 0x1F, 1 << sem::sr_bit::X);
}

// ---- C14: rte/stop/move usp・例外配送 ----

#[test]
fn c14_decode_spots() {
    assert_eq!(polyisa_guest_m68k::decode(0x4E60, 16), Some(Insn::Mv2usp));
    assert_eq!(polyisa_guest_m68k::decode(0x4E67, 16), Some(Insn::Mv2usp));
    assert_eq!(polyisa_guest_m68k::decode(0x4E68, 16), Some(Insn::Mvfrusp));
    assert_eq!(polyisa_guest_m68k::decode(0x4E6F, 16), Some(Insn::Mvfrusp));
}

#[test]
fn move_usp_both_directions() {
    // move a0,usp = 0x4E60（S=1 が必要）。
    let mut env = env();
    env.backend.set(sem::sr_ref(), 0x2000);
    env.backend.set(A(0).state(), 0x1234_5678);
    env.step(|b| sem::exec(b, Insn::Mv2usp, 0x4E60, 0)).unwrap();
    assert_eq!(env.backend.get(Usp.state()), 0x1234_5678);

    // move usp,a1 = 0x4E69。
    let mut env2 = crate::env();
    env2.backend.set(sem::sr_ref(), 0x2000);
    env2.backend.set(Usp.state(), 0xABCD_EF01);
    env2.step(|b| sem::exec(b, Insn::Mvfrusp, 0x4E69, 0))
        .unwrap();
    assert_eq!(env2.backend.get(A(1).state()), 0xABCD_EF01);

    // ユーザモードでは両方向ともベクタ 8。
    let mut env3 = crate::env();
    let e = env3
        .step(|b| sem::exec(b, Insn::Mv2usp, 0x4E60, 0))
        .expect_err("ユーザ move to usp は特権違反");
    match e {
        InterpExit::Exception(x) => assert_eq!(x.code, 8),
        other => panic!("unexpected exit: {other:?}"),
    }
    let mut env4 = crate::env();
    let e = env4
        .step(|b| sem::exec(b, Insn::Mvfrusp, 0x4E68, 0))
        .expect_err("ユーザ move from usp は特権違反");
    match e {
        InterpExit::Exception(x) => assert_eq!(x.code, 8),
        other => panic!("unexpected exit: {other:?}"),
    }
}

#[test]
fn rte_pops_frame_in_supervisor() {
    // ssp に [sr][pc] フレームを置いて rte → 復元。
    let mut env = env_with_data(&[0x4E73], &[0xA7, 0x1F, 0x00, 0x12, 0x34, 0x56]);
    env.backend.set(sem::sr_ref(), 0x2000);
    env.backend.set(Ssp.state(), 0x4000);
    env.step(|b| sem::exec(b, Insn::Rte, 0x4E73, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(Ssp.state()), 0x4006);
    assert_eq!(env.backend.get(sem::sr_ref()), 0xA71F);
    // 復元 pc は Jump に残る。
    match env.backend.ctrl {
        polyisa_engine::interp::Ctrl::Jump(t) => assert_eq!(t, 0x0012_3456),
        other => panic!("expected jump: {other:?}"),
    }

    // ユーザモードではベクタ 8。
    let mut env2 = crate::env();
    let e = env2
        .step(|b| sem::exec(b, Insn::Rte, 0x4E73, 0))
        .expect_err("ユーザ rte は特権違反");
    match e {
        InterpExit::Exception(x) => assert_eq!(x.code, 8),
        other => panic!("unexpected exit: {other:?}"),
    }
}

#[test]
fn stop_loads_sr_and_halts() {
    // stop #imm: sr = imm & 0xA71F、pc は戻り先ではなく命令自身へ。
    let mut env = env_with_data(&[0x4E72, 0xAFFF], &[]);
    env.backend.set(sem::sr_ref(), 0x2000);
    env.step(|b| sem::exec(b, Insn::Stop, 0x4E72, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(sem::sr_ref()), 0xA71F);
    match env.backend.ctrl {
        polyisa_engine::interp::Ctrl::Jump(t) => assert_eq!(t, 0x1000),
        other => panic!("expected jump-to-self: {other:?}"),
    }

    // ユーザモードではベクタ 8。
    let mut env2 = crate::env();
    let e = env2
        .step(|b| sem::exec(b, Insn::Stop, 0x4E72, 0))
        .expect_err("ユーザ stop は特権違反");
    match e {
        InterpExit::Exception(x) => assert_eq!(x.code, 8),
        other => panic!("unexpected exit: {other:?}"),
    }
}

#[test]
fn deliver_pushes_frame_and_jumps_vector() {
    // trap #8 相当の配送を直接呼ぶ。フレームは [sr][pc] の 6B。
    let mut env = env_with_data(&[0x4E48], &[0, 0, 0, 0, 0, 0, 0, 0]);
    env.backend.set(sem::sr_ref(), 0x001F);
    env.backend.set(Usp.state(), 0x5000);
    env.backend.set(Ssp.state(), 0x4100);
    // ベクタ 40 = trap #8 → 番地 0xA0 にハンドラ先頭を置く。
    env.backend
        .mem
        .map(VirtAddr(0), 1, polyisa_mem::Perms::RW)
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0xA0), &[0x00, 0x00, 0xBE, 0xEF])
        .unwrap();
    env.step(|b| sem::deliver(b, 40, 0x1000, 2)).unwrap();
    // ssp -= 6、S=1、T=0、フレームは [sr][pc]。
    assert_eq!(env.backend.get(Ssp.state()), 0x40FA);
    assert_eq!(env.backend.get(sem::sr_ref()) & 0xA000, 0x2000);
    let mut buf = [0u8; 6];
    env.backend
        .mem
        .read(VirtAddr(0x40FA), &mut buf, DRD)
        .unwrap();
    assert_eq!(&buf[..2], &[0x00, 0x1F]); // 配送前の sr
    assert_eq!(&buf[2..6], &[0x00, 0x00, 0x10, 0x02]); // head+len
    match env.backend.ctrl {
        polyisa_engine::interp::Ctrl::Jump(t) => assert_eq!(t, 0xBEEF),
        other => panic!("expected jump: {other:?}"),
    }

    // code=8（特権違反）の積み pc は命令自身の先頭。
    let mut env2 = env_with_data(&[0x4E70], &[]);
    env2.backend.set(sem::sr_ref(), 0x0000);
    env2.backend.set(Usp.state(), 0x5000);
    env2.backend.set(Ssp.state(), 0x4100);
    env2.backend
        .mem
        .map(VirtAddr(0), 1, polyisa_mem::Perms::RW)
        .unwrap();
    env2.step(|b| sem::deliver(b, 8, 0x1000, 2)).unwrap();
    let mut buf2 = [0u8; 6];
    env2.backend
        .mem
        .read(VirtAddr(0x40FA), &mut buf2, DRD)
        .unwrap();
    assert_eq!(&buf2[2..6], &[0x00, 0x00, 0x10, 0x00]); // head
}

#[test]
fn move_usp_a7_uses_ssp_in_supervisor() {
    // move a7,usp: S=1 の A7 は SSP を指す。
    let mut env = env();
    env.backend.set(sem::sr_ref(), 0x2000);
    env.backend.set(Ssp.state(), 0x7777_0000);
    env.step(|b| sem::exec(b, Insn::Mv2usp, 0x4E67, 0)).unwrap();
    assert_eq!(env.backend.get(Usp.state()), 0x7777_0000);

    // move usp,a7: USP の値は SSP に書かれる。
    let mut env2 = crate::env();
    env2.backend.set(sem::sr_ref(), 0x2000);
    env2.backend.set(Usp.state(), 0x1111_2222);
    env2.step(|b| sem::exec(b, Insn::Mvfrusp, 0x4E6F, 0))
        .unwrap();
    assert_eq!(env2.backend.get(Ssp.state()), 0x1111_2222);
}

#[test]
fn rte_restores_user_mode_frame() {
    // フレームの sr が S=0 なら復帰後はユーザモード（A7=USP）。
    let mut env = env_with_data(&[0x4E73], &[0x00, 0x1F, 0x00, 0x00, 0x30, 0x00]);
    env.backend.set(sem::sr_ref(), 0x2000);
    env.backend.set(Ssp.state(), 0x4000);
    env.backend.set(Usp.state(), 0x5000);
    env.step(|b| sem::exec(b, Insn::Rte, 0x4E73, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(Ssp.state()), 0x4006);
    assert_eq!(env.backend.get(sem::sr_ref()) & 0x2000, 0);
    assert_eq!(env.backend.get(sem::sr_ref()) & 0x1F, 0x1F);
    match env.backend.ctrl {
        polyisa_engine::interp::Ctrl::Jump(t) => assert_eq!(t, 0x3000),
        other => panic!("expected jump: {other:?}"),
    }
}

// D1: CPU モデルの挙動パラメータ（cpu-models.md の param 句）。
// Ref: SPEC-M68K-PRM (Rev 1) §MOVEM / §MOVE from SR と
// SPEC-M68K-UM (MC68020) の奇数アクセス。

/// 68010 以降の MOVE from SR は特権命令。
#[test]
fn mvfrsr_privileged_on_68010() {
    // move from sr,d0。68000（既定）ではユーザモードでも成功する。
    let mut env = env_with_code(&[0x40C0]);
    env.backend.set(sem::sr_ref(), 0);
    env.step(|b| sem::exec(b, Insn::Mvfrsr, 0x40C0, 0x1000))
        .expect("68000 ではユーザでも読める");

    // i68010 のパラメータでは特権違反（ベクタ 8）。
    let mut env = env_with_code(&[0x40C0]);
    polyisa_guest_m68k::install_params(
        &mut env.backend,
        &polyisa_guest_m68k::model_params("i68010"),
    );
    env.backend.set(sem::sr_ref(), 0);
    let e = env
        .step(|b| sem::exec(b, Insn::Mvfrsr, 0x40C0, 0x1000))
        .expect_err("68010+ では特権違反");
    match e {
        InterpExit::Exception(x) => assert_eq!(x.code, 8),
        other => panic!("unexpected exit: {other:?}"),
    }
}

/// MOVEM -(An) で An がマスクに含まれるときの格納値の世代差。
#[test]
fn movem_base_in_list_param() {
    // movem.l a0,-(a0)。predec マスクは reg r ↔ bit 15-r で A0=bit7。
    for (model, want) in [("", 0x4800u32), ("i68020", 0x47FC)] {
        let mut env = env_with_data(&[0x48E0, 0x0080], &[]);
        if !model.is_empty() {
            polyisa_guest_m68k::install_params(
                &mut env.backend,
                &polyisa_guest_m68k::model_params(model),
            );
        }
        env.backend.set(A(0).state(), 0x4800);
        env.step(|b| sem::exec(b, Insn::MovrmL, 0x48E0, 0x1000))
            .unwrap();
        let mut buf = [0u8; 4];
        env.backend
            .mem
            .read(VirtAddr(0x47FC), &mut buf, DRD)
            .unwrap();
        assert_eq!(u32::from_be_bytes(buf), want, "model={model:?}");
        // An は転送後に最終アドレスへ更新される。
        assert_eq!(env.backend.get(A(0).state()), 0x47FC);
    }
}

/// 68020 以降は奇数アドレスの word アクセスを許す。
#[test]
fn odd_access_param() {
    // move.w (a0),d0。a0 = 0x4001（奇数）。
    for (model, ok) in [("", false), ("i68020", true)] {
        let mut env = env_with_data(&[0x3010], &[0; 8]);
        if !model.is_empty() {
            polyisa_guest_m68k::install_params(
                &mut env.backend,
                &polyisa_guest_m68k::model_params(model),
            );
        }
        env.backend.set(A(0).state(), 0x4001);
        let r = env.step(|b| sem::exec(b, Insn::MoveW, 0x3010, 0x1000));
        if ok {
            r.expect("68020+ では奇数アクセスを許す");
        } else {
            match r.expect_err("68000 ではアドレスエラー") {
                InterpExit::Exception(x) => {
                    assert_eq!(x.kind, polyisa_sem::ExceptionKind::Align)
                }
                other => panic!("unexpected exit: {other:?}"),
            }
        }
    }
}

/// D2: 68020 full 形式 EA — IS=1・BD32 の lea（busybox _start の LOAD_GOT 形）。
#[test]
fn full_ext_lea_is_bd32() {
    // lea %pc@(bd32,is),%a5 = 4bfb 0170 001a 3de8
    // ext @0x1002 → a5 = 0x1002 + 0x001a3de8 = 0x001a4dea
    let mut env = env_with_code(&[0x4BFB, 0x0170, 0x001A, 0x3DE8]);
    polyisa_guest_m68k::install_params(
        &mut env.backend,
        &polyisa_guest_m68k::model_params("i68020"),
    );
    // d0.w は非ゼロでも IS=1 なので寄与しない。
    env.backend.set(D(0).state(), 7);
    env.step(|b| sem::exec(b, Insn::Lea, 0x4BFB, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(A(5).state()), 0x1002 + 0x001A3DE8);
}

/// D2: full 形式 src EA の消費語数（3語）を反映して宛先拡張語を読む。
/// move.l %a5@(bd32,is),%d16(a6) — src が動的に 3 語消費するので
/// dest の d16 は pc+8 にある（静的 1 語と見誤ると pc+4 の BD を読む）。
#[test]
fn move_full_src_dyn_dest_ext() {
    // 2d75 0170 0000 006c ff2c  @pc=0x1000
    // src = *(a5 + 0x6c) → dest = *(a6 - 0xd4)
    let mut env = env_with_data(&[0x2D75, 0x0170, 0x0000, 0x006C, 0xFF2C], &[]);
    polyisa_guest_m68k::install_params(
        &mut env.backend,
        &polyisa_guest_m68k::model_params("i68020"),
    );
    env.backend.set(A(5).state(), 0x4000);
    env.backend.set(A(6).state(), 0x4100);
    env.backend
        .mem
        .write(VirtAddr(0x406C), &0xDEAD_BEEFu32.to_be_bytes())
        .unwrap();
    env.step(|b| sem::exec(b, Insn::MoveL, 0x2D75, 0x1000))
        .unwrap();
    let mut buf = [0u8; 4];
    env.backend
        .mem
        .read(VirtAddr(0x402C), &mut buf, DRD)
        .unwrap();
    assert_eq!(u32::from_be_bytes(buf), 0xDEADBEEF);
}

/// D2: neg.l — 結果の negate と NZVC（V は 0x80000000 のときのみ）。
#[test]
fn neg_long() {
    let mut env = env_with_code(&[0x4482]);
    env.backend.set(D(2).state(), 5);
    env.backend.set(sem::ccr_ref(), 0x10); // X=1
    env.step(|b| sem::exec(b, Insn::Neg, 0x4482, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(2).state()), (-5i32) as u32);
    // X=1 N=1（負） Z=0 V=0 C=1（非ゼロ→C）
    assert_eq!(env.backend.get(sem::ccr_ref()) & 0x1F, 0x19);
}

/// D2: extb.l — バイト→ロング符号拡張。
#[test]
fn extb_long() {
    let mut env = env_with_code(&[0x49C3]);
    env.backend.set(D(3).state(), 0x1234_0080);
    env.step(|b| sem::exec(b, Insn::ExtbL, 0x49C3, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(3).state()), 0xFFFF_FF80);
}

/// D2: bfextu — Dn フィールドの抽出。
#[test]
fn bfextu_reg() {
    // bfextu d0{4:8},d1 = e9c0, ext: dst=1(D1), Do=0, off=4, Dw=0, wid=8 → 0x1108
    let mut env = env_with_code(&[0xE9C0, 0x1108]);
    polyisa_guest_m68k::install_params(
        &mut env.backend,
        &polyisa_guest_m68k::model_params("i68020"),
    );
    env.backend.set(D(0).state(), 0x0AB0_0000);
    env.step(|b| sem::exec(b, Insn::Bfextu, 0xE9C0, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(1).state()), 0xAB);
}

/// D2: mull — 32x32→32（ext siz=0）。muls.l d0,d1: ext Dl=1 → 0x0001。
#[test]
fn mull_32() {
    let mut env = env_with_code(&[0x4C02, 0x1801]);
    polyisa_guest_m68k::install_params(
        &mut env.backend,
        &polyisa_guest_m68k::model_params("i68020"),
    );
    // muls.l d2,d1 — ext[15:12]=Dl（被乗数＋下位積の宛先）、
    // ext[11]=符号、ext[10]=64 ビット積。0x1801 = Dl=1・符号付き・32。
    env.backend.set(D(2).state(), (-3i32) as u32);
    env.backend.set(D(1).state(), 7);
    env.step(|b| sem::exec(b, Insn::Mull, 0x4C02, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(1).state()), (-21i32) as u32);
}

/// D2: tst.l An — 68020+ では合法、68000 では illegal。
#[test]
fn tst_areg_model() {
    for (model, ok) in [("", false), ("i68020", true)] {
        let mut env = env_with_code(&[0x4A8C]);
        if !model.is_empty() {
            polyisa_guest_m68k::install_params(
                &mut env.backend,
                &polyisa_guest_m68k::model_params(model),
            );
        }
        env.backend.set(A(4).state(), 0x8000_0000);
        let r = env.step(|b| sem::exec(b, Insn::Tst, 0x4A8C, 0x1000));
        if ok {
            r.unwrap();
            // 負 → N=1。X は保持（初期 0）。
            assert_eq!(env.backend.get(sem::ccr_ref()) & 0x1F, 0x08);
        } else {
            match r.expect_err("68000 では An への tst は illegal") {
                InterpExit::Exception(x) => assert_eq!(x.code, 4),
                other => panic!("unexpected exit: {other:?}"),
            }
        }
    }
}

/// D2 デバッグ: move.l d16(a2),d8(a6,d0.l*4,-0xd0)（auxv table 書き込み形）
/// 2daa 0004 0d20 ff30 — dest = a6 + d0*4 - 0xd0
#[test]
fn move_full_dest_bd16() {
    let mut env = env_with_data(&[0x2DAA, 0x0004, 0x0D20, 0xFF30], &[0; 8]);
    polyisa_guest_m68k::install_params(
        &mut env.backend,
        &polyisa_guest_m68k::model_params("i68020"),
    );
    env.backend.set(A(6).state(), 0x40D0);
    env.backend.set(D(0).state(), 25);
    env.backend.set(A(2).state(), 0x4000);
    env.backend
        .mem
        .write(VirtAddr(0x4004), &0xDEAD_BEEFu32.to_be_bytes())
        .unwrap();
    env.step(|b| sem::exec(b, Insn::MoveL, 0x2DAA, 0x1000))
        .unwrap();
    // dest = a6 + d0*4 - 0xd0 = 0x40d0 + 100 - 208 = 0x4064
    let mut buf = [0u8; 4];
    env.backend
        .mem
        .read(VirtAddr(0x4064), &mut buf, DRD)
        .unwrap();
    assert_eq!(u32::from_be_bytes(buf), 0xDEAD_BEEF);
}

/// D2 デバッグ: lea pc@(bd32,is) のベースが拡張語アドレス(pc+2)であること。
#[test]
fn lea_pc_ext_base() {
    // 4bfb 0170 0013 8bbc @pc=0x1000 → a5 = 0x1002 + 0x138bbc = 0x138dbe
    let mut env = env_with_code(&[0x4BFB, 0x0170, 0x0013, 0x8BBC]);
    polyisa_guest_m68k::install_params(
        &mut env.backend,
        &polyisa_guest_m68k::model_params("i68020"),
    );
    env.step(|b| sem::exec(b, Insn::Lea, 0x4BFB, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(A(5).state()), 0x1002 + 0x138BBC);
}

/// D2 デバッグ: デコード確認。
#[test]
fn decode_d2_insns() {
    for (w, name) in [
        (0x4BFBu16, "lea"),
        (0x2275, "movea"),
        (0x2271, "movea"),
        (0x2DAA, "move"),
    ] {
        let i = polyisa_guest_m68k::decode_model_ex(
            w as u128,
            16,
            true,
            polyisa_guest_m68k::model_feats("i68020"),
        );
        assert!(i.is_some(), "{name} {w:#06x} が decode されるべき: {i:?}");
    }
}

/// D2 レビュー修正: I/IS フィールドの実符号化（gas/binutils 準拠）。
/// bits[1:0]=OD サイズ（0/1=なし、2=語、3=long）、bit2=postindexed。
#[test]
fn full_ext_words_iis() {
    // BD16 + preindexed・語 OD（iis=2）→ ext1+1+1
    assert_eq!(ea::full_ext_words(0x0122), 3);
    // BD32 + 語 OD（iis=2）→ ext1+2+1
    assert_eq!(ea::full_ext_words(0x0172), 4);
    // BD16 + long OD（iis=3）→ ext1+1+2
    assert_eq!(ea::full_ext_words(0x0123), 4);
    // BD32・インダイレクトなし（iis=0）→ ext1+2（busybox GOT 形）
    assert_eq!(ea::full_ext_words(0x0170), 3);
    // BD なし・postindexed null OD（iis=5）→ ext1 のみ
    assert_eq!(ea::full_ext_words(0x0105), 1);
}

/// D2 レビュー修正: postindexed（iis=6、語 OD）の評価順序
/// （索引は間接読み出しの後に足す）。
#[test]
fn full_index_postindexed() {
    // move.l ([a0],d1.w)+od,d0 = 2030 1106 od
    let mut env = env_with_data(&[0x2030, 0x1106, 0x0100], &[0; 8]);
    polyisa_guest_m68k::install_params(
        &mut env.backend,
        &polyisa_guest_m68k::model_params("i68020"),
    );
    env.backend.set(A(0).state(), 0x4000);
    env.backend.set(D(1).state(), 0x10);
    env.backend
        .mem
        .write(VirtAddr(0x4000), &0x4100u32.to_be_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x4210), &0xDEAD_BEEFu32.to_be_bytes())
        .unwrap();
    env.step(|b| sem::exec(b, Insn::MoveL, 0x2030, 0x1000))
        .unwrap();
    // addr = mem32(a0) + od + d1 = 0x4100 + 0x100 + 0x10 = 0x4210
    assert_eq!(env.backend.get(D(0).state()), 0xDEAD_BEEF);
}

/// D2 レビュー修正: preindexed（iis=2、語 OD）の評価順序
/// （索引は間接読み出しの前に足す）。
#[test]
fn full_index_preindexed() {
    // move.l ([a0,d1.w])+od,d0 = 2030 1102 od
    let mut env = env_with_data(&[0x2030, 0x1102, 0x0200], &[0; 8]);
    polyisa_guest_m68k::install_params(
        &mut env.backend,
        &polyisa_guest_m68k::model_params("i68020"),
    );
    env.backend.set(A(0).state(), 0x4000);
    env.backend.set(D(1).state(), 0x10);
    env.backend
        .mem
        .write(VirtAddr(0x4010), &0x4200u32.to_be_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x4400), &0xCAFE_BABEu32.to_be_bytes())
        .unwrap();
    env.step(|b| sem::exec(b, Insn::MoveL, 0x2030, 0x1000))
        .unwrap();
    // addr = mem32(a0 + d1) + od = mem32(0x4010) + 0x200 = 0x4400
    assert_eq!(env.backend.get(D(0).state()), 0xCAFE_BABE);
}

/// D2 レビュー修正: negx — d=全1・X=1 でも借用（C=X=1）。
#[test]
fn negx_borrow_full() {
    let mut env = env_with_code(&[0x4080]);
    env.backend.set(D(0).state(), 0xFFFF_FFFF);
    env.backend.set(sem::ccr_ref(), 0x10); // X=1
    env.step(|b| sem::exec(b, Insn::Negx, 0x4080, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0);
    // C=X=1、Z=1（結果 0。Z は累積だが旧 Z=0 → 0。実は Z=0）
    assert_eq!(env.backend.get(sem::ccr_ref()) & 0x1F, 0x11);
}

/// D2: subx.l — X 込み減算と累積 Z。
#[test]
fn subx_l_borrow() {
    let mut env = env_with_code(&[0x9580]);
    env.backend.set(D(2).state(), 5);
    env.backend.set(D(0).state(), 3);
    env.backend.set(sem::ccr_ref(), 0x10); // X=1
    env.step(|b| sem::exec(b, Insn::SubxD, 0x9580, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(2).state()), 1);
    // 借りなし → C=X=0、結果非零 → Z=0。
    assert_eq!(env.backend.get(sem::ccr_ref()) & 0x1F, 0x00);
}

/// D2: addx.l — X 込み加算で桁上げ。
#[test]
fn addx_l_carry() {
    let mut env = env_with_code(&[0xD380]);
    env.backend.set(D(1).state(), 0xFFFF_FFF0);
    env.backend.set(D(0).state(), 0x20);
    env.step(|b| sem::exec(b, Insn::AddxD, 0xD380, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(1).state()), 0x10);
    // 桁上げ → C=X=1。
    assert_eq!(env.backend.get(sem::ccr_ref()) & 0x1F, 0x11);
}

/// D2: subx のメモリ形式 -(Ay),-(Ax)。
#[test]
fn subx_m_predec() {
    // データ領域 0x4000 からの配置: src=3 は 0x4004、dst=5 は 0x400c。
    let mut data = [0u8; 16];
    data[4..8].copy_from_slice(&3u32.to_be_bytes());
    data[12..16].copy_from_slice(&5u32.to_be_bytes());
    let mut env = env_with_data(&[0x9588], &data);
    // 0x9588: dx=2（dst の Ax）、emode=1、dy=0（src の Ay）。
    env.backend.set(A(0).state(), 0x4008); // src: -(A0) → 0x4004
    env.backend.set(A(2).state(), 0x4010); // dst: -(A2) → 0x400c
    env.step(|b| sem::exec(b, Insn::SubxM, 0x9588, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(A(0).state()), 0x4004);
    assert_eq!(env.backend.get(A(2).state()), 0x400c);
    let mut buf = [0u8; 4];
    env.backend
        .mem
        .read(polyisa_mem::VirtAddr(0x400c), &mut buf, DRD)
        .unwrap();
    assert_eq!(u32::from_be_bytes(buf), 2);
}

/// D2: cas.l — 一致時は Du を書き、不一致時は Dc に <ea> を入れる。
#[test]
fn cas_l_both_paths() {
    // cas.l d0,d1,(a2) = 0x0ED2 + ext Du=1(bits8:6)/Dc=0(bits2:0) → 0x0040。
    let mut env = env_with_data(&[0x0ED2, 0x0040], &5u32.to_be_bytes());
    polyisa_guest_m68k::install_params(
        &mut env.backend,
        &polyisa_guest_m68k::model_params("i68020"),
    );
    env.backend.set(A(2).state(), 0x4000);
    // 一致: mem=5, Dc(d0)=5, Du(d1)=7 → mem=7、Z=1。
    env.backend.set(D(0).state(), 5);
    env.backend.set(D(1).state(), 7);
    env.step(|b| sem::exec(b, Insn::Casl, 0x0ED2, 0x1000))
        .unwrap();
    let mut buf = [0u8; 4];
    env.backend
        .mem
        .read(polyisa_mem::VirtAddr(0x4000), &mut buf, DRD)
        .unwrap();
    assert_eq!(u32::from_be_bytes(buf), 7);
    assert_eq!(env.backend.get(sem::ccr_ref()) & 0x1F, 0x04); // Z=1

    // 不一致: mem=7, Dc(d2)=5, Du(d3)=9 → mem 不変、Dc=7、Z=0。
    let mut env = env_with_data(&[0x0ED2, 0x00C2], &7u32.to_be_bytes());
    polyisa_guest_m68k::install_params(
        &mut env.backend,
        &polyisa_guest_m68k::model_params("i68020"),
    );
    env.backend.set(A(2).state(), 0x4000);
    env.backend.set(D(2).state(), 5);
    env.backend.set(D(3).state(), 9);
    env.step(|b| sem::exec(b, Insn::Casl, 0x0ED2, 0x1000))
        .unwrap();
    let mut buf = [0u8; 4];
    env.backend
        .mem
        .read(polyisa_mem::VirtAddr(0x4000), &mut buf, DRD)
        .unwrap();
    assert_eq!(u32::from_be_bytes(buf), 7);
    assert_eq!(env.backend.get(D(2).state()), 7);
    assert_eq!(env.backend.get(sem::ccr_ref()) & 0x1F, 0x00); // 7-5=2 → 旗なし
}

/// D2 レビュー修正: bfexts — 負フィールドの符号拡張。
#[test]
fn bfexts_neg() {
    // bfexts d0{4:8},d1 = ebc0, ext dst=1,off=4,wid=8 → 0x1108
    let mut env = env_with_code(&[0xEBC0, 0x1108]);
    polyisa_guest_m68k::install_params(
        &mut env.backend,
        &polyisa_guest_m68k::model_params("i68020"),
    );
    env.backend.set(D(0).state(), 0x0AB0_0000);
    env.step(|b| sem::exec(b, Insn::Bfexts, 0xEBC0, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(1).state()), 0xFFFF_FFAB);
}

/// D2 レビュー修正: bfffo — wid<32 のフィールド内先頭セットビット。
#[test]
fn bfffo_narrow() {
    // bfffo d0{4:8},d1 = edc0, ext dst=1,off=4,wid=8 → 0x1108
    let mut env = env_with_code(&[0xEDC0, 0x1108]);
    polyisa_guest_m68k::install_params(
        &mut env.backend,
        &polyisa_guest_m68k::model_params("i68020"),
    );
    // field = 0x0B → フィールド内 LZ=4 → pos = 4+4 = 8
    env.backend.set(D(0).state(), 0x00B0_0000);
    env.step(|b| sem::exec(b, Insn::Bfffo, 0xEDC0, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(1).state()), 8);
}

/// D2 レビュー修正: bfins — wid=32 のマージと旗。
#[test]
fn bfins_w32() {
    // bfins d1,d0{0:32} = efc0, ext src=1,off=0,wid=0(=32) → 0x1000
    let mut env = env_with_code(&[0xEFC0, 0x1000]);
    polyisa_guest_m68k::install_params(
        &mut env.backend,
        &polyisa_guest_m68k::model_params("i68020"),
    );
    env.backend.set(D(0).state(), 0x1234_5678);
    env.backend.set(D(1).state(), 0xDEAD_BEEF);
    env.step(|b| sem::exec(b, Insn::Bfins, 0xEFC0, 0x1000))
        .unwrap();
    assert_eq!(env.backend.get(D(0).state()), 0xDEAD_BEEF);
    // 旗は挿入フィールド: N=1,Z=0
    assert_eq!(env.backend.get(sem::ccr_ref()) & 0x0C, 0x08);
}

/// D2 レビュー修正: neg の full 形式 EA で動的語数が出る。
#[test]
fn neg_full_ext_len() {
    // neg.l d8(a0,full) = 40b0, ext1 0170 → 3 語
    let n = ea::insn_ext_dyn(Insn::Neg, 0x40B0, true, true, |i| {
        [0x0170u16, 0, 0x100].get(i as usize).copied()
    });
    assert_eq!(n, Some(3));
}

/// D2 レビュー修正: mull/divl は 68020+ 限定（i68000 では decode 不可）。
#[test]
fn mull_model_gate() {
    assert!(
        polyisa_guest_m68k::decode_model_ex(0x4C00, 16, true, polyisa_guest_m68k::model_feats(""),)
            .is_none(),
        "i68000 では mull は illegal"
    );
    assert!(
        polyisa_guest_m68k::decode_model_ex(
            0x4C00,
            16,
            true,
            polyisa_guest_m68k::model_feats("i68020"),
        )
        .is_some()
    );
}

/// D2 デバッグ: movea.l d8(a1,a0.l),a1 — busybox TLS アクセス形。
/// 非整列（addr≡2 mod4）の .l 読み出し値が正しいこと。
#[test]
fn movea_brief_tls_pattern() {
    let mut env = env_with_data(&[0x2271, 0x8800], &[0; 8]);
    polyisa_guest_m68k::install_params(
        &mut env.backend,
        &polyisa_guest_m68k::model_params("i68020"),
    );
    env.backend.set(A(1).state(), 0xFFFF_9004);
    env.backend.set(A(0).state(), 0x0000_B3D2);
    // ea = 0xffff9004 + 0x0000b3d2 = 0x43d6（データページ内・非整列）
    env.backend
        .mem
        .write(VirtAddr(0x43d4), &0x801a_6f34u32.to_be_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x43d8), &0x801a_6f28u32.to_be_bytes())
        .unwrap();
    // まず直接 mem.read で値を確かめる
    let mut buf = [0u8; 4];
    env.backend
        .mem
        .read(VirtAddr(0x43d6), &mut buf, DRD)
        .unwrap();
    env.step(|b| sem::exec(b, Insn::MoveaL, 0x2271, 0x1000))
        .unwrap();
    assert_eq!(
        env.backend.get(A(1).state()),
        0x6F34_801A,
        "nonaligned .l read"
    );
}

/// D2 デバッグ: busybox 実値そのまま（a0=0x801b23d2, tp-0x6ffc 読み出し）。
#[test]
fn movea_brief_tls_real() {
    let mut env = env_with_code(&[0x2271, 0x8800]);
    polyisa_guest_m68k::install_params(
        &mut env.backend,
        &polyisa_guest_m68k::model_params("i68020"),
    );
    env.backend
        .mem
        .map(VirtAddr(0x801ab000), 1, polyisa_mem::Perms::RW)
        .unwrap();
    env.backend.set(A(1).state(), 0xFFFF_9004);
    env.backend.set(A(0).state(), 0x801B_23D2);
    // ea = 0x801ab3d6。実ダンプ値を書く
    let dump: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x80, 0x1a, 0x6f, 0x34, 0x80, 0x1a, 0x6f, 0x28, 0x80, 0x1a, 0x6f,
        0x28,
    ];
    env.backend.mem.write(VirtAddr(0x801ab3d0), &dump).unwrap();
    env.step(|b| sem::exec(b, Insn::MoveaL, 0x2271, 0x1000))
        .unwrap();
    let got = env.backend.get(A(1).state());
    assert_eq!(got, 0x6F34_801A);
}
