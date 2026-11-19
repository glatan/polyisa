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
use polyisa_mem::VirtAddr;
use polyisa_sem::Backend as _;

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
    assert_eq!(ea::ext_words(7, 5, 4), None);
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
