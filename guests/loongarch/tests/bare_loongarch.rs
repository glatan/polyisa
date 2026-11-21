// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! LoongArch の命令語単位のデコード検査と、interp バックエンド
//! での裸実行検査（段階19・LA4）。生成デコーダがリテラル語を
//! 正しく分類し、`la64` 機能で LA64 専用命令がゲートされる
//! ことを見る。末尾の裸実行は LA4 の最小意味論
//! （加算・定数形成・b/jirl・ld/st・syscall）を検査する。
//! 出典は SPEC-LOONGARCH-RM である。
//! Ref: SPEC-LOONGARCH-RM §2, Appendix B（符号化表）.

use polyisa_guest_loongarch::*;

const LA64: u128 = FEAT_LA32 | FEAT_LA64;
const LA32: u128 = FEAT_LA32;

fn dec(word: u32) -> Option<Insn> {
    decode_model_ex(u128::from(word), 32, false, LA64)
}

fn dec_la32(word: u32) -> Option<Insn> {
    decode_model_ex(u128::from(word), 32, false, LA32)
}

/// 語を組み立てる。ops は `extract_ops` と同じ順。
fn enc(i: Insn, ops: &[u64]) -> u32 {
    encode(i, ops).unwrap() as u32
}

#[test]
fn decode_fixed_width_core() {
    // add.w rd,rj,rk: 0010_0000_0010_0000_0 rk rj rd。
    let w = enc(Insn::AddW, &[1, 2, 3]);
    assert_eq!(dec(w), Some(Insn::AddW));
    assert_eq!(w, 0x0010_0c41);
    // sub.w / add.d / sub.d。
    assert_eq!(dec(enc(Insn::SubW, &[1, 2, 3])), Some(Insn::SubW));
    assert_eq!(dec(enc(Insn::AddD, &[1, 2, 3])), Some(Insn::AddD));
    assert_eq!(dec(enc(Insn::SubD, &[1, 2, 3])), Some(Insn::SubD));
    // and/or/xor/nor。
    assert_eq!(dec(enc(Insn::And, &[1, 2, 3])), Some(Insn::And));
    assert_eq!(dec(enc(Insn::Or, &[1, 2, 3])), Some(Insn::Or));
    assert_eq!(dec(enc(Insn::Xor, &[1, 2, 3])), Some(Insn::Xor));
    assert_eq!(dec(enc(Insn::Nor, &[1, 2, 3])), Some(Insn::Nor));
}

#[test]
fn decode_immediates() {
    assert_eq!(dec(enc(Insn::AddiW, &[4, 5, 100])), Some(Insn::AddiW));
    assert_eq!(dec(enc(Insn::AddiD, &[4, 5, 100])), Some(Insn::AddiD));
    assert_eq!(dec(enc(Insn::Slti, &[4, 5, 7])), Some(Insn::Slti));
    assert_eq!(dec(enc(Insn::Sltui, &[4, 5, 7])), Some(Insn::Sltui));
    assert_eq!(dec(enc(Insn::Andi, &[4, 5, 0xff])), Some(Insn::Andi));
    assert_eq!(dec(enc(Insn::Ori, &[4, 5, 0xff])), Some(Insn::Ori));
    assert_eq!(dec(enc(Insn::Xori, &[4, 5, 0xff])), Some(Insn::Xori));
    assert_eq!(dec(enc(Insn::Lu12iW, &[4, 0x12345])), Some(Insn::Lu12iW));
    assert_eq!(dec(enc(Insn::Lu32iD, &[4, 0x12345])), Some(Insn::Lu32iD));
    assert_eq!(dec(enc(Insn::Lu52iD, &[4, 5, 0xabc])), Some(Insn::Lu52iD));
    assert_eq!(dec(enc(Insn::Pcaddi, &[4, 1])), Some(Insn::Pcaddi));
    assert_eq!(dec(enc(Insn::Pcalau12i, &[4, 1])), Some(Insn::Pcalau12i));
    assert_eq!(dec(enc(Insn::Pcaddu12i, &[4, 1])), Some(Insn::Pcaddu12i));
    assert_eq!(dec(enc(Insn::Pcaddu18i, &[4, 1])), Some(Insn::Pcaddu18i));
}

#[test]
fn decode_memory() {
    for (i, name) in [
        (Insn::LdB, "ld.b"),
        (Insn::LdH, "ld.h"),
        (Insn::LdW, "ld.w"),
        (Insn::LdD, "ld.d"),
        (Insn::StB, "st.b"),
        (Insn::StH, "st.h"),
        (Insn::StW, "st.w"),
        (Insn::StD, "st.d"),
        (Insn::LdBu, "ld.bu"),
        (Insn::LdHu, "ld.hu"),
        (Insn::LdWu, "ld.wu"),
    ] {
        let w = enc(i, &[4, 5, 8]);
        assert_eq!(dec(w), Some(i), "{name}");
    }
}

#[test]
fn decode_branch() {
    // b/bl の ops[0] は <<2 済みのオフセット（raw26<<2）。
    assert_eq!(dec(enc(Insn::B, &[16])), Some(Insn::B));
    assert_eq!(dec(enc(Insn::Bl, &[16])), Some(Insn::Bl));
    assert_eq!(dec(enc(Insn::Jirl, &[0, 1, 0])), Some(Insn::Jirl));
    // beq rj,rd,offs16。
    assert_eq!(dec(enc(Insn::Beq, &[4, 5, 0x10])), Some(Insn::Beq));
    assert_eq!(dec(enc(Insn::Bne, &[4, 5, 0x10])), Some(Insn::Bne));
    assert_eq!(dec(enc(Insn::Blt, &[4, 5, 0x10])), Some(Insn::Blt));
    assert_eq!(dec(enc(Insn::Bge, &[4, 5, 0x10])), Some(Insn::Bge));
    assert_eq!(dec(enc(Insn::Bltu, &[4, 5, 0x10])), Some(Insn::Bltu));
    assert_eq!(dec(enc(Insn::Bgeu, &[4, 5, 0x10])), Some(Insn::Bgeu));
    // beqz/bnez: ops は [rj, offs21<<2]。
    assert_eq!(dec(enc(Insn::Beqz, &[4, 0x40])), Some(Insn::Beqz));
    assert_eq!(dec(enc(Insn::Bnez, &[4, 0x40])), Some(Insn::Bnez));
    // bceqz/bcnez（FCC 分岐。LA9 で意味論）。
    assert_eq!(dec(enc(Insn::Bceqz, &[0, 0x40])), Some(Insn::Bceqz));
    assert_eq!(dec(enc(Insn::Bcnez, &[0, 0x40])), Some(Insn::Bcnez));
}

#[test]
fn decode_system() {
    assert_eq!(dec(enc(Insn::Syscall, &[0])), Some(Insn::Syscall));
    assert_eq!(dec(enc(Insn::Break, &[0])), Some(Insn::Break));
    assert_eq!(dec(enc(Insn::Dbar, &[0])), Some(Insn::Dbar));
    assert_eq!(dec(enc(Insn::Ibar, &[0])), Some(Insn::Ibar));
    assert_eq!(dec(enc(Insn::RdtimelW, &[4, 0])), Some(Insn::RdtimelW));
    assert_eq!(dec(enc(Insn::RdtimehW, &[4, 0])), Some(Insn::RdtimehW));
    assert_eq!(dec(enc(Insn::RdtimeD, &[4, 0])), Some(Insn::RdtimeD));
    assert_eq!(dec(enc(Insn::Cpucfg, &[4, 5])), Some(Insn::Cpucfg));
    assert_eq!(dec(enc(Insn::Csrrd, &[4, 0, 0x10])), Some(Insn::Csrrd));
    assert_eq!(dec(enc(Insn::Csrwr, &[4, 1, 0x10])), Some(Insn::Csrwr));
    assert_eq!(dec(enc(Insn::Csrxchg, &[4, 5, 0x10])), Some(Insn::Csrxchg));
    assert_eq!(dec(enc(Insn::Ertn, &[])), Some(Insn::Ertn));
}

#[test]
fn decode_la32_gating() {
    // LA64 専用は LA32 機能集合では解読できない。
    // Ref: SPEC-LOONGARCH-RM §2.1 表 2（LA32 必須部分集合）.
    for i in [
        Insn::AddD,
        Insn::SubD,
        Insn::AddiD,
        Insn::LdD,
        Insn::StD,
        Insn::Lu32iD,
        Insn::Lu52iD,
        Insn::RdtimeD,
        Insn::MulD,
        Insn::DivD,
        Insn::SllD,
        Insn::SlliD,
    ] {
        let ops: &[u64] = match i {
            Insn::Lu32iD => &[4, 1],
            Insn::Lu52iD => &[4, 5, 1],
            Insn::RdtimeD => &[4, 0],
            Insn::LdD | Insn::StD => &[4, 5, 8],
            Insn::SlliD => &[4, 5, 3],
            _ => &[4, 5, 6],
        };
        let w = enc(i, ops);
        assert_eq!(dec(w), Some(i));
        assert_eq!(dec_la32(w), None, "{i:?} should be LA64-only");
    }
    // 共有語彙は LA32 でも解読できる。
    for i in [
        Insn::AddW,
        Insn::SubW,
        Insn::AddiW,
        Insn::LdW,
        Insn::StW,
        Insn::Beq,
        Insn::B,
        Insn::Syscall,
        Insn::RdtimelW,
        Insn::Cpucfg,
    ] {
        let ops: &[u64] = match i {
            Insn::LdW | Insn::StW => &[4, 5, 8],
            Insn::Beq => &[4, 5, 0x10],
            Insn::B => &[16],
            Insn::Syscall => &[0],
            Insn::RdtimelW => &[4, 0],
            Insn::Cpucfg => &[4, 5],
            _ => &[4, 5, 6],
        };
        let w = enc(i, ops);
        assert_eq!(dec_la32(w), Some(i), "{i:?} should decode on LA32");
    }
}

// ---- 裸実行（interp バックエンド）----

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::Ctrl;
use polyisa_guest_loongarch::sem;
use polyisa_sem::Backend as _;

fn env() -> BareEnv {
    BareEnv::new(core::mem::size_of::<CpuState>())
}

fn gpr(env: &mut BareEnv, n: u32) -> u64 {
    env.backend.get(sem::r_ref(n))
}

fn set_gpr(env: &mut BareEnv, n: u32, v: u64) {
    env.backend.set(sem::r_ref(n), v);
}

/// 1 命令語を pc=0x1000 で実行する（run_loongarch の step と
/// 同じ規則で pc を進める）。
fn step(env: &mut BareEnv, word: u32) {
    step_at(env, word, 0x1000);
}

fn step_at(env: &mut BareEnv, word: u32, pc: u64) {
    let insn = decode_model_ex(u128::from(word), 32, true, LA64).unwrap();
    env.backend.ctrl = Ctrl::Fallthrough;
    let ok = sem::exec(&mut env.backend, insn, word, pc, true).unwrap();
    assert!(ok, "insn {word:#x} unimplemented");
    match env.backend.ctrl {
        Ctrl::Jump(t) => env.pc = t,
        Ctrl::Fallthrough => env.pc = pc.wrapping_add(4),
    }
}

#[test]
fn exec_add_addi_lu12i() {
    let mut env = env();
    set_gpr(&mut env, 5, 10);
    // add.w r4 = r5 + r6(r6=0) → 10。
    step(&mut env, enc(Insn::AddW, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), 10);
    // addi.w r4 = r4 + (-5)。
    step(&mut env, enc(Insn::AddiW, &[4, 4, 0xffb]));
    assert_eq!(gpr(&mut env, 4), 5);
    // lu12i.w r4 = sext(0x12345 << 12)。
    step(&mut env, enc(Insn::Lu12iW, &[4, 0x12345]));
    assert_eq!(gpr(&mut env, 4), 0x1234_5000);
    // .w 結果の符号拡張: add.w 0x7fffffff+1 → sext32(-1)。
    set_gpr(&mut env, 5, 0x7fff_ffff);
    set_gpr(&mut env, 6, 1);
    step(&mut env, enc(Insn::AddW, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), 0xffff_ffff_8000_0000);
    // add.d は 64 ビットまま。
    step(&mut env, enc(Insn::AddD, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), 0x8000_0000);
    // r0 への書き込みは捨てる。
    step(&mut env, enc(Insn::AddiW, &[0, 0, 7]));
    assert_eq!(gpr(&mut env, 0), 0);
}

#[test]
fn exec_ldst_word() {
    use polyisa_mem::{Perms, VirtAddr};
    let mut env = env();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    set_gpr(&mut env, 5, 0x2000);
    set_gpr(&mut env, 4, 0xdead_beef_1234_5678);
    // st.d r4 → [r5+8]、ld.d r7 ← [r5+8]。
    step(&mut env, enc(Insn::StD, &[4, 5, 8]));
    step(&mut env, enc(Insn::LdD, &[7, 5, 8]));
    assert_eq!(gpr(&mut env, 7), 0xdead_beef_1234_5678);
    // st.w は下位 32 ビット、ld.w は符号拡張。
    step(&mut env, enc(Insn::StW, &[4, 5, 16]));
    step(&mut env, enc(Insn::LdW, &[7, 5, 16]));
    assert_eq!(gpr(&mut env, 7), 0x1234_5678);
    // ld.wu はゼロ拡張。
    set_gpr(&mut env, 4, 0xffff_ffff_8000_0000);
    step(&mut env, enc(Insn::StW, &[4, 5, 24]));
    step(&mut env, enc(Insn::LdWu, &[7, 5, 24]));
    assert_eq!(gpr(&mut env, 7), 0x8000_0000);
    step(&mut env, enc(Insn::LdW, &[7, 5, 24]));
    assert_eq!(gpr(&mut env, 7), 0xffff_ffff_8000_0000);
}

#[test]
fn exec_branch_b_jirl() {
    let mut env = env();
    // b +8（offs26=8 → pc+8）。
    step_at(&mut env, enc(Insn::B, &[8]), 0x1000);
    assert_eq!(env.pc, 0x1008);
    // bl -4（offs26 生値 0x3ffffff → pc-4）、$ra=pc+4。
    step_at(&mut env, enc(Insn::Bl, &[0x0fff_fffc]), 0x2000);
    assert_eq!(env.pc, 0x1ffc);
    assert_eq!(gpr(&mut env, 1), 0x2004);
    // jirl r0, r5, 2 → pc = r5 + 8。
    set_gpr(&mut env, 5, 0x4000);
    step_at(&mut env, enc(Insn::Jirl, &[0, 5, 2]), 0x1000);
    assert_eq!(env.pc, 0x4008);
    // jirl r4, r5, 0 → rd=pc+4。
    step_at(&mut env, enc(Insn::Jirl, &[4, 5, 0]), 0x1000);
    assert_eq!(env.pc, 0x4000);
    assert_eq!(gpr(&mut env, 4), 0x1004);
}

#[test]
fn exec_syscall_raises_trap() {
    use polyisa_engine::interp::InterpExit;
    use polyisa_sem::ExceptionKind;
    let mut env = env();
    let word = enc(Insn::Syscall, &[0]);
    let insn = decode_model_ex(u128::from(word), 32, true, LA64).unwrap();
    let r = sem::exec(&mut env.backend, insn, word, 0x1000, true);
    match r {
        Err(InterpExit::Exception(e)) => {
            assert_eq!(e.kind, ExceptionKind::Trap);
            assert_eq!(e.code, sem::TRAP_SYS);
        }
        _ => panic!("syscall should raise Trap"),
    }
}

#[test]
fn exec_counters_cpucfg() {
    let mut env = env();
    env.backend.set(sem::cnt_ref(), 0x0123_4567_89ab_cdef);
    step(&mut env, enc(Insn::RdtimelW, &[4, 0]));
    assert_eq!(gpr(&mut env, 4), 0xffff_ffff_89ab_cdef);
    step(&mut env, enc(Insn::RdtimehW, &[4, 0]));
    assert_eq!(gpr(&mut env, 4), 0x0123_4567);
    step(&mut env, enc(Insn::RdtimeD, &[4, 0]));
    assert_eq!(gpr(&mut env, 4), 0x0123_4567_89ab_cdef);
    // cpucfg[r5] は未初期化なら 0。
    set_gpr(&mut env, 5, 2);
    step(&mut env, enc(Insn::Cpucfg, &[4, 5]));
    assert_eq!(gpr(&mut env, 4), 0);
}
