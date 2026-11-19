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

#[test]
fn unimplemented_is_undefined() {
    let mut env = env();
    let e = env
        .step(|b| sem::exec(b, Insn::Rts, 0x4E75, 0))
        .expect_err("rts は未実装");
    match e {
        InterpExit::Exception(x) => assert_eq!(x.code, 0x4E75),
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
