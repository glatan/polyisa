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

// ---- LA5: 整数算術・ビット操作の実行検査 ----

#[test]
fn exec_la5_counts_and_reversals() {
    let mut env = env();
    // clz.w / ctz.w。
    set_gpr(&mut env, 5, 0x00f0_0000);
    step(&mut env, enc(Insn::ClzW, &[4, 5]));
    assert_eq!(gpr(&mut env, 4), 8);
    step(&mut env, enc(Insn::CtzW, &[4, 5]));
    assert_eq!(gpr(&mut env, 4), 20);
    // clz.d / ctz.d。
    set_gpr(&mut env, 5, 0x80);
    step(&mut env, enc(Insn::ClzD, &[4, 5]));
    assert_eq!(gpr(&mut env, 4), 56);
    step(&mut env, enc(Insn::CtzD, &[4, 5]));
    assert_eq!(gpr(&mut env, 4), 7);
    // clo.w: rj[31:0]=0xffff_ff00 → leading ones は 24。
    set_gpr(&mut env, 5, 0xffff_ff00);
    step(&mut env, enc(Insn::CloW, &[4, 5]));
    assert_eq!(gpr(&mut env, 4), 24);
    // revb.2h: 各半語内バイト交換 → 0x2211_4433。
    set_gpr(&mut env, 5, 0x1122_3344);
    step(&mut env, enc(Insn::Revb2h, &[4, 5]));
    assert_eq!(gpr(&mut env, 4), 0x2211_4433);
    // revb.d: 全バイト反転。
    set_gpr(&mut env, 5, 0x0123_4567_89ab_cdef);
    step(&mut env, enc(Insn::RevbD, &[4, 5]));
    assert_eq!(gpr(&mut env, 4), 0xefcd_ab89_6745_2301);
    // revh.d: 半語順の全反転。
    step(&mut env, enc(Insn::RevhD, &[4, 5]));
    assert_eq!(gpr(&mut env, 4), 0xcdef_89ab_4567_0123);
    // revh.2w: 各 32 ビット語内の半語交換。
    step(&mut env, enc(Insn::Revh2w, &[4, 5]));
    assert_eq!(gpr(&mut env, 4), 0x4567_0123_cdef_89ab);
    // bitrev.w: 0xf0 → 0x0f00_0000。
    set_gpr(&mut env, 5, 0xf0);
    step(&mut env, enc(Insn::BitrevW, &[4, 5]));
    assert_eq!(gpr(&mut env, 4), 0x0000_0000_0f00_0000);
    // bitrev.d: 1 → 0x8000_0000_0000_0000。
    set_gpr(&mut env, 5, 1);
    step(&mut env, enc(Insn::BitrevD, &[4, 5]));
    assert_eq!(gpr(&mut env, 4), 0x8000_0000_0000_0000);
    // bitrev.4b: 各バイト内ビット反転: 0x01_80 → 0x80_01。
    set_gpr(&mut env, 5, 0x0180);
    step(&mut env, enc(Insn::Bitrev4b, &[4, 5]));
    assert_eq!(gpr(&mut env, 4), 0x8001);
}

#[test]
fn exec_la5_mul_div() {
    let mut env = env();
    set_gpr(&mut env, 5, 7);
    set_gpr(&mut env, 6, 6);
    step(&mut env, enc(Insn::MulW, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), 42);
    // mulh.w: 0x10000 * 0x10000 = 0x1_0000_0000 の上位 32 → 1。
    set_gpr(&mut env, 5, 0x1_0000);
    set_gpr(&mut env, 6, 0x1_0000);
    step(&mut env, enc(Insn::MulhW, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), 1);
    // mulh.wu: 同 → 1。
    step(&mut env, enc(Insn::MulhWu, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), 1);
    // mulw.d.w: (-1) * 2 = -2 の 64 ビット積。
    set_gpr(&mut env, 5, 0xffff_ffff);
    set_gpr(&mut env, 6, 2);
    step(&mut env, enc(Insn::MulwDW, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), (-2i64) as u64);
    // mulw.d.wu: 0xffff_ffff * 2 = 0x1_ffff_fffe。
    step(&mut env, enc(Insn::MulwDWu, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), 0x1_ffff_fffe);
    // mul.d / mulh.d: -2 * 3 = -6、上位は -1。
    set_gpr(&mut env, 5, (-2i64) as u64);
    set_gpr(&mut env, 6, 3);
    step(&mut env, enc(Insn::MulD, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), (-6i64) as u64);
    step(&mut env, enc(Insn::MulhD, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), (-1i64) as u64);
    // mulh.du: max * max の上位。
    set_gpr(&mut env, 5, u64::MAX);
    set_gpr(&mut env, 6, u64::MAX);
    step(&mut env, enc(Insn::MulhDu, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), u64::MAX - 1);
    // div.d / mod.d: 20 / 6 = 3 余り 2。
    set_gpr(&mut env, 5, 20);
    set_gpr(&mut env, 6, 6);
    step(&mut env, enc(Insn::DivD, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), 3);
    step(&mut env, enc(Insn::ModD, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), 2);
    // div.w: -20 / 6 = -3（0 方向切り捨て）。
    set_gpr(&mut env, 5, (-20i64) as u64);
    step(&mut env, enc(Insn::DivW, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), (-3i64) as u64);
    step(&mut env, enc(Insn::ModW, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), (-2i64) as u64);
    // div.du: max / 2 = 0x7fff_ffff_ffff_ffff。
    set_gpr(&mut env, 5, u64::MAX);
    set_gpr(&mut env, 6, 2);
    step(&mut env, enc(Insn::DivDu, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), 0x7fff_ffff_ffff_ffff);
    // mod.du: max % 2 = 1。
    step(&mut env, enc(Insn::ModDu, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), 1);
    // crc.w.b.w / crcc.w.b.w: rj=0 に 0xff を 1 バイト供給。
    set_gpr(&mut env, 5, 0);
    set_gpr(&mut env, 6, 0xff);
    step(&mut env, enc(Insn::CrcWBW, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), 0x2d02_ef8d);
    step(&mut env, enc(Insn::CrccWBW, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), 0xad7d_5351);
    // crc.w.h.w: 2 バイト 0x5678。
    set_gpr(&mut env, 6, 0x5678);
    step(&mut env, enc(Insn::CrcWHW, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), 0x65ee_073f);
}

#[test]
fn exec_la5_rotr_bstr_misc() {
    let mut env = env();
    // rotr.d: 1 >>rot 1 = 0x8000_0000_0000_0000。
    set_gpr(&mut env, 5, 1);
    set_gpr(&mut env, 6, 1);
    step(&mut env, enc(Insn::RotrD, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), 0x8000_0000_0000_0000);
    // rotr.w: rk[4:0] のみ有効（33 → 1）。
    set_gpr(&mut env, 6, 33);
    step(&mut env, enc(Insn::RotrW, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), (-0x8000_0000i64) as u64);
    // rotri.w: 0x8000_0000 rotr 4 → 0x0800_0000。
    set_gpr(&mut env, 5, 0x8000_0000);
    step(&mut env, enc(Insn::RotriW, &[4, 5, 4]));
    assert_eq!(gpr(&mut env, 4), 0x0800_0000);
    // bstrpick.d: rj=0xf0f0, msb=11, lsb=4 → 0x0f0。
    set_gpr(&mut env, 5, 0xf0f0);
    step(&mut env, enc(Insn::BstrpickD, &[4, 5, 15, 8]));
    assert_eq!(gpr(&mut env, 4), 0xf0);
    // bstrins.w: rd[19:16] = rj[3:0]、bit31=1 なので sext。
    set_gpr(&mut env, 4, 0xaaaa_aaaa);
    set_gpr(&mut env, 5, 0xf);
    step(&mut env, enc(Insn::BstrinsW, &[4, 5, 19, 16]));
    assert_eq!(gpr(&mut env, 4), 0xffff_ffff_aaaf_aaaa);
    // maskeqz / masknez。
    set_gpr(&mut env, 5, 0x55);
    set_gpr(&mut env, 6, 0);
    step(&mut env, enc(Insn::Maskeqz, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), 0);
    step(&mut env, enc(Insn::Masknez, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), 0x55);
    // alsl.d: rj << (sa2+1) + rk = 0x100 << 3 + 0x30 = 0x830。
    set_gpr(&mut env, 5, 0x100);
    set_gpr(&mut env, 6, 0x30);
    step(&mut env, enc(Insn::AlslD, &[4, 5, 6, 2]));
    assert_eq!(gpr(&mut env, 4), 0x830);
    // bytepick.d: {rk, rj} >> 16。
    set_gpr(&mut env, 5, 0x1122_3344_5566_7788);
    set_gpr(&mut env, 6, 0xaabb_ccdd_eeff_0011);
    step(&mut env, enc(Insn::BytepickD, &[4, 5, 6, 2]));
    assert_eq!(gpr(&mut env, 4), 0x0011_1122_3344_5566);
    // addu16i.d: rj + sext(0x8000 << 16) = 0x1_0000_0000 - 0x8000_0000。
    set_gpr(&mut env, 5, 0x1_0000_0000);
    step(&mut env, enc(Insn::Addu16iD, &[4, 5, 0x8000]));
    assert_eq!(gpr(&mut env, 4), 0x8000_0000);
}

// ---- LA6: index・ptr 形式、LL/SC、AM*、bound check ----

/// メモリページを 1 枚張った環境を返す。
fn mem_env() -> BareEnv {
    use polyisa_mem::{Perms, VirtAddr};
    let mut env = env();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env
}

/// 8 バイトをメモリに書く。
fn poke64(env: &mut BareEnv, addr: u64, v: u64) {
    use polyisa_mem::{Access, AccessKind, Align, Endian, VirtAddr};
    let acc = Access {
        endian: Endian::Le,
        align: Align::Natural,
        kind: AccessKind::DataWrite,
    };
    env.backend
        .mem
        .write_value(VirtAddr(addr), v, 8, acc)
        .unwrap();
}

/// メモリから `n` バイトを読む。
fn peek(env: &mut BareEnv, addr: u64, n: usize) -> u64 {
    use polyisa_mem::{Access, AccessKind, Align, Endian, VirtAddr};
    let acc = Access {
        endian: Endian::Le,
        align: Align::Natural,
        kind: AccessKind::DataRead,
    };
    env.backend.mem.read_value(VirtAddr(addr), n, acc).unwrap()
}

#[test]
fn exec_la6_ldx_stx() {
    let mut env = mem_env();
    poke64(&mut env, 0x2000, 0xdead_beef_1234_5678);
    set_gpr(&mut env, 5, 0x1ff0);
    set_gpr(&mut env, 6, 0x10);
    // ldx.d r4 ← [r5+r6]。
    step(&mut env, enc(Insn::LdxD, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), 0xdead_beef_1234_5678);
    // ldx.b は符号拡張。
    set_gpr(&mut env, 6, 0x17);
    step(&mut env, enc(Insn::LdxB, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), (-0x22i64) as u64);
    // ldx.bu はゼロ拡張。
    step(&mut env, enc(Insn::LdxBu, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), 0xde);
    // ldx.h / ldx.hu。
    set_gpr(&mut env, 6, 0x10);
    step(&mut env, enc(Insn::LdxH, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), 0x5678);
    poke64(&mut env, 0x2010, 0x8000);
    set_gpr(&mut env, 6, 0x20);
    step(&mut env, enc(Insn::LdxHu, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), 0x8000);
    step(&mut env, enc(Insn::LdxH, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), (-0x8000i64) as u64);
    // ldx.w / ldx.wu。
    poke64(&mut env, 0x2018, 0x8000_0001);
    set_gpr(&mut env, 6, 0x28);
    step(&mut env, enc(Insn::LdxW, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), (-0x7fff_ffffi64) as u64);
    step(&mut env, enc(Insn::LdxWu, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), 0x8000_0001);
    // stx.b/h/w/d（ea = r5 + r6 = 0x2018）。
    set_gpr(&mut env, 4, 0xaabb_ccdd_eeff_0099);
    step(&mut env, enc(Insn::StxD, &[4, 5, 6]));
    assert_eq!(peek(&mut env, 0x2018, 8), 0xaabb_ccdd_eeff_0099);
    step(&mut env, enc(Insn::StxB, &[4, 5, 6]));
    assert_eq!(peek(&mut env, 0x2018, 1), 0x99);
    step(&mut env, enc(Insn::StxH, &[4, 5, 6]));
    assert_eq!(peek(&mut env, 0x2018, 2), 0x0099);
    step(&mut env, enc(Insn::StxW, &[4, 5, 6]));
    assert_eq!(peek(&mut env, 0x2018, 4), 0xeeff_0099);
}

#[test]
fn exec_la6_ldptr_stptr() {
    let mut env = mem_env();
    poke64(&mut env, 0x2000, 0x8000_0001_dead_beef);
    set_gpr(&mut env, 5, 0x2008);
    // ldptr.w: si14=-2（0x3ffe）→ ea = rj - 8 = 0x2000。
    step(&mut env, enc(Insn::LdptrW, &[4, 5, 0x3ffe]));
    assert_eq!(gpr(&mut env, 4), (-0x2152_4111i64) as u64);
    // ldptr.d。
    step(&mut env, enc(Insn::LdptrD, &[4, 5, 0x3ffe]));
    assert_eq!(gpr(&mut env, 4), 0x8000_0001_dead_beef);
    // stptr.w は下位 32 ビット。si14=1 → ea = 0x200c。
    set_gpr(&mut env, 4, 0xffff_ffff_1234_5678);
    step(&mut env, enc(Insn::StptrW, &[4, 5, 1]));
    assert_eq!(peek(&mut env, 0x200c, 4), 0x1234_5678);
    // stptr.d: si14=0 → ea = rj = 0x2008。
    step(&mut env, enc(Insn::StptrD, &[4, 5, 0]));
    assert_eq!(peek(&mut env, 0x2008, 8), 0xffff_ffff_1234_5678);
    // 負の si14（0x3ffc → -4 → ea = 0x2010 - 16 = 0x2000）。
    // 0x2008 は stptr.d で 0xffff_ffff_1234_5678 に更新済みだが、
    // 0x2000 の上位 32 ビットは変わっていない。
    set_gpr(&mut env, 5, 0x2010);
    step(&mut env, enc(Insn::LdptrD, &[4, 5, 0x3ffc]));
    assert_eq!(gpr(&mut env, 4), 0x8000_0001_dead_beef);
}

#[test]
fn exec_la6_ll_sc() {
    let mut env = mem_env();
    poke64(&mut env, 0x2000, 0x55);
    set_gpr(&mut env, 5, 0x2000);
    // ll.w → 旧値を sext で読む。
    step(&mut env, enc(Insn::LlW, &[4, 5, 0]));
    assert_eq!(gpr(&mut env, 4), 0x55);
    // sc.w は予約が生きているので成功、書き込み、rd=1。
    set_gpr(&mut env, 4, 0xaa);
    step(&mut env, enc(Insn::ScW, &[4, 5, 0]));
    assert_eq!(gpr(&mut env, 4), 1);
    assert_eq!(peek(&mut env, 0x2000, 4), 0xaa);
    // 予約なしの sc.w は失敗で rd=0、書き込まない。
    set_gpr(&mut env, 4, 0xbb);
    step(&mut env, enc(Insn::ScW, &[4, 5, 0]));
    assert_eq!(gpr(&mut env, 4), 0);
    assert_eq!(peek(&mut env, 0x2000, 4), 0xaa);
    // ll.d → sc.d。
    step(&mut env, enc(Insn::LlD, &[4, 5, 0]));
    assert_eq!(gpr(&mut env, 4), 0xaa);
    set_gpr(&mut env, 4, 0x0123_4567_89ab_cdef);
    step(&mut env, enc(Insn::ScD, &[4, 5, 0]));
    assert_eq!(gpr(&mut env, 4), 1);
    assert_eq!(peek(&mut env, 0x2000, 8), 0x0123_4567_89ab_cdef);
    // llacq/screl（ea = GR[rj]）。
    step(&mut env, enc(Insn::LlacqW, &[4, 5]));
    assert_eq!(gpr(&mut env, 4), (-0x7654_3211i64) as u64);
    set_gpr(&mut env, 4, 0x77);
    step(&mut env, enc(Insn::ScrelW, &[4, 5]));
    assert_eq!(gpr(&mut env, 4), 1);
    assert_eq!(peek(&mut env, 0x2000, 4), 0x77);
    step(&mut env, enc(Insn::LlacqD, &[4, 5]));
    assert_eq!(gpr(&mut env, 4), 0x0123_4567_0000_0077);
    set_gpr(&mut env, 4, 0x1111_2222_3333_4444);
    step(&mut env, enc(Insn::ScrelD, &[4, 5]));
    assert_eq!(gpr(&mut env, 4), 1);
    assert_eq!(peek(&mut env, 0x2000, 8), 0x1111_2222_3333_4444);
    // ll → 重なる番地への store で予約を潰し sc は失敗。
    step(&mut env, enc(Insn::LlW, &[4, 5, 0]));
    set_gpr(&mut env, 6, 9);
    step(&mut env, enc(Insn::StB, &[6, 5, 0]));
    set_gpr(&mut env, 4, 0x55);
    step(&mut env, enc(Insn::ScW, &[4, 5, 0]));
    assert_eq!(gpr(&mut env, 4), 0);
    // sc.q: [rj] ← rd、[rj+8] ← rk、rd ← 1。
    step(&mut env, enc(Insn::LlD, &[4, 5, 0]));
    set_gpr(&mut env, 4, 0xaaaa_aaaa_aaaa_aaaa);
    set_gpr(&mut env, 6, 0xbbbb_bbbb_bbbb_bbbb);
    step(&mut env, enc(Insn::ScQ, &[4, 6, 5]));
    assert_eq!(gpr(&mut env, 4), 1);
    assert_eq!(peek(&mut env, 0x2000, 8), 0xaaaa_aaaa_aaaa_aaaa);
    assert_eq!(peek(&mut env, 0x2008, 8), 0xbbbb_bbbb_bbbb_bbbb);
}

#[test]
fn exec_la6_am() {
    let mut env = mem_env();
    poke64(&mut env, 0x2000, 0x1_0000_0100);
    set_gpr(&mut env, 5, 0x2000);
    set_gpr(&mut env, 6, 0x200);
    // amadd.w: rd ← 旧値(sext)、mem += rk[31:0]。
    step(&mut env, enc(Insn::AmaddW, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), 0x100);
    assert_eq!(peek(&mut env, 0x2000, 4), 0x300);
    // amadd.d: rd ← 旧値、mem += rk。
    step(&mut env, enc(Insn::AmaddD, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), 0x1_0000_0300);
    assert_eq!(peek(&mut env, 0x2000, 8), 0x1_0000_0500);
    // amswap.d。
    set_gpr(&mut env, 6, 0xdead_beef);
    step(&mut env, enc(Insn::AmswapD, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), 0x1_0000_0500);
    assert_eq!(peek(&mut env, 0x2000, 8), 0xdead_beef);
    // amand.d / amor.d / amxor.d。
    set_gpr(&mut env, 6, 0xff);
    step(&mut env, enc(Insn::AmandD, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), 0xdead_beef);
    assert_eq!(peek(&mut env, 0x2000, 8), 0xef);
    step(&mut env, enc(Insn::AmorD, &[4, 5, 6]));
    assert_eq!(peek(&mut env, 0x2000, 8), 0xff);
    set_gpr(&mut env, 6, 0x0f);
    step(&mut env, enc(Insn::AmxorD, &[4, 5, 6]));
    assert_eq!(peek(&mut env, 0x2000, 8), 0xf0);
    // ammax.d: 符号付き max(mem, rk)。mem=0xf0、rk=-1 → 0xf0。
    set_gpr(&mut env, 6, (-1i64) as u64);
    step(&mut env, enc(Insn::AmmaxD, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), 0xf0);
    assert_eq!(peek(&mut env, 0x2000, 8), 0xf0);
    // ammax.du: mem=0xf0、rk=-1（unsigned 巨大）→ -1。
    step(&mut env, enc(Insn::AmmaxDu, &[4, 5, 6]));
    assert_eq!(peek(&mut env, 0x2000, 8), (-1i64) as u64);
    // ammin.d: mem=-1、rk=5 → -1。
    set_gpr(&mut env, 6, 5);
    step(&mut env, enc(Insn::AmminD, &[4, 5, 6]));
    assert_eq!(peek(&mut env, 0x2000, 8), (-1i64) as u64);
    // ammin.du: mem=-1（巨大）、rk=5 → 5。
    step(&mut env, enc(Insn::AmminDu, &[4, 5, 6]));
    assert_eq!(peek(&mut env, 0x2000, 8), 5);
    // ammax.wu: mem=5、rk=0xffff_ff00 → 0xff00 側（sext で戻る）。
    set_gpr(&mut env, 6, 0xffff_ff00);
    step(&mut env, enc(Insn::AmmaxWu, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), 5);
    assert_eq!(peek(&mut env, 0x2000, 4), 0xffff_ff00);
    // amadd.b / amswap.b（FAM3 形、番地は rj）。
    poke64(&mut env, 0x2010, 0x1f);
    set_gpr(&mut env, 7, 0x2010);
    set_gpr(&mut env, 6, 0x10);
    step(&mut env, enc(Insn::AmaddB, &[4, 6, 7]));
    assert_eq!(gpr(&mut env, 4), 0x1f);
    assert_eq!(peek(&mut env, 0x2010, 1), 0x2f);
    set_gpr(&mut env, 6, 0xcc);
    step(&mut env, enc(Insn::AmswapB, &[4, 6, 7]));
    assert_eq!(gpr(&mut env, 4), 0x2f);
    assert_eq!(peek(&mut env, 0x2010, 1), 0xcc);
    // amadd.h / amswap.h（ea = rj = 0x2010）。
    set_gpr(&mut env, 6, 0x23);
    step(&mut env, enc(Insn::AmaddH, &[4, 6, 7]));
    assert_eq!(gpr(&mut env, 4), 0xcc);
    assert_eq!(peek(&mut env, 0x2010, 2), 0xef);
    set_gpr(&mut env, 6, 0x1234);
    step(&mut env, enc(Insn::AmswapH, &[4, 6, 7]));
    assert_eq!(gpr(&mut env, 4), 0xef);
    assert_eq!(peek(&mut env, 0x2010, 2), 0x1234);
    // _db 系は単一スレッドで同じ動作。
    poke64(&mut env, 0x2020, 1);
    set_gpr(&mut env, 7, 0x2020);
    step(&mut env, enc(Insn::AmaddDbD, &[4, 7, 6]));
    assert_eq!(gpr(&mut env, 4), 1);
    assert_eq!(peek(&mut env, 0x2020, 8), 1 + 0x1234);
}

#[test]
fn exec_la6_amcas() {
    let mut env = mem_env();
    poke64(&mut env, 0x2000, 0x55);
    set_gpr(&mut env, 5, 0x2000);
    set_gpr(&mut env, 6, 0xaa);
    // amcas.b: rd=期待値 0x55、一致 → 書き込み、rd ← 旧値 0x55。
    set_gpr(&mut env, 4, 0x55);
    step(&mut env, enc(Insn::AmcasB, &[4, 6, 5]));
    assert_eq!(gpr(&mut env, 4), 0x55);
    assert_eq!(peek(&mut env, 0x2000, 1), 0xaa);
    // 不一致（mem=0xaa、期待 0x55）→ 書き込まず、rd ← 0xaa（sext）。
    set_gpr(&mut env, 4, 0x55);
    step(&mut env, enc(Insn::AmcasB, &[4, 6, 5]));
    assert_eq!(gpr(&mut env, 4), (-0x56i64) as u64);
    assert_eq!(peek(&mut env, 0x2000, 1), 0xaa);
    // amcas.d: 一致する 64 ビット比較。
    poke64(&mut env, 0x2010, 0x0123_4567_89ab_cdef);
    set_gpr(&mut env, 5, 0x2010);
    set_gpr(&mut env, 6, 0xfeed_face_cafe_beef);
    set_gpr(&mut env, 4, 0x0123_4567_89ab_cdef);
    step(&mut env, enc(Insn::AmcasD, &[4, 6, 5]));
    assert_eq!(gpr(&mut env, 4), 0x0123_4567_89ab_cdef);
    assert_eq!(peek(&mut env, 0x2010, 8), 0xfeed_face_cafe_beef);
    // amcas.w / amcas_db.w。
    poke64(&mut env, 0x2020, 0x8000_0001);
    set_gpr(&mut env, 5, 0x2020);
    set_gpr(&mut env, 6, 0x4000_0002);
    set_gpr(&mut env, 4, 0x8000_0001);
    step(&mut env, enc(Insn::AmcasW, &[4, 6, 5]));
    assert_eq!(gpr(&mut env, 4), (-0x7fff_ffffi64) as u64);
    assert_eq!(peek(&mut env, 0x2020, 4), 0x4000_0002);
    // amcas.h。
    poke64(&mut env, 0x2028, 0x7777);
    set_gpr(&mut env, 5, 0x2028);
    set_gpr(&mut env, 6, 0x8888);
    set_gpr(&mut env, 4, 0x7777);
    step(&mut env, enc(Insn::AmcasDbH, &[4, 6, 5]));
    assert_eq!(gpr(&mut env, 4), 0x7777);
    assert_eq!(peek(&mut env, 0x2028, 2), 0x8888);
}

#[test]
fn exec_la6_ldgt_ldle() {
    use polyisa_engine::interp::InterpExit;
    use polyisa_sem::ExceptionKind;
    let mut env = mem_env();
    poke64(&mut env, 0x2000, 0x99);
    set_gpr(&mut env, 5, 0x2000);
    set_gpr(&mut env, 6, 0x1000);
    // rj > rk なので ldgt.b は成功、sext 読み。
    step(&mut env, enc(Insn::LdgtB, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), (-0x67i64) as u64);
    // ldle.b: rj <= rk は不成立（0x2000 > 0x1000）→ BCE 例外。
    let word = enc(Insn::LdleB, &[4, 5, 6]);
    let insn = decode_model_ex(u128::from(word), 32, true, LA64).unwrap();
    let r = sem::exec(&mut env.backend, insn, word, 0x1000, true);
    match r {
        Err(InterpExit::Exception(e)) => {
            assert_eq!(e.kind, ExceptionKind::Trap);
            assert_eq!(e.code, sem::TRAP_BND);
        }
        _ => panic!("ldle.b should raise bound check"),
    }
    // rj <= rk を満たせば ldle.d は読める。
    set_gpr(&mut env, 6, 0x2000);
    step(&mut env, enc(Insn::LdleD, &[4, 5, 6]));
    assert_eq!(gpr(&mut env, 4), 0x99);
    // stgt.d / stle.d。
    set_gpr(&mut env, 4, 0x77);
    step(&mut env, enc(Insn::StleD, &[4, 5, 6]));
    assert_eq!(peek(&mut env, 0x2000, 8), 0x77);
    set_gpr(&mut env, 6, 0x1000);
    step(&mut env, enc(Insn::StgtW, &[4, 5, 6]));
    assert_eq!(peek(&mut env, 0x2000, 4), 0x77);
}

// ---- LA7: 条件分岐・ASRT ----

/// FCC 束を書く（LA9 の fcc 書き込みと同じ表現）。
fn set_fcc(env: &mut BareEnv, v: u64) {
    env.backend.set(sem::fcc_ref(), v);
}

#[test]
fn exec_la7_cond_branches() {
    let mut env = env();
    set_gpr(&mut env, 5, 0x10);
    set_gpr(&mut env, 6, 0x10);
    // beq r5,r6,offs=+8 → pc=0x1000+8。
    step_at(&mut env, enc(Insn::Beq, &[5, 6, 2]), 0x1000);
    assert_eq!(env.pc, 0x1008);
    // bne r5,r6 → 不成立 → fallthrough。
    step_at(&mut env, enc(Insn::Bne, &[5, 6, 4]), 0x1000);
    assert_eq!(env.pc, 0x1004);
    // blt: r5(-1) < r6(0) → taken、負の offs。
    set_gpr(&mut env, 5, (-1i64) as u64);
    set_gpr(&mut env, 6, 0);
    step_at(&mut env, enc(Insn::Blt, &[5, 6, 0xfffe]), 0x2000);
    assert_eq!(env.pc, 0x1ff8);
    // bge: -1 >= 0 は不成立。
    step_at(&mut env, enc(Insn::Bge, &[5, 6, 3]), 0x2000);
    assert_eq!(env.pc, 0x2004);
    // bltu: -1(=u64::MAX) < 0 は不成立。
    step_at(&mut env, enc(Insn::Bltu, &[5, 6, 3]), 0x2000);
    assert_eq!(env.pc, 0x2004);
    // bgeu: u64::MAX >= 0 → taken。
    step_at(&mut env, enc(Insn::Bgeu, &[5, 6, 3]), 0x2000);
    assert_eq!(env.pc, 0x200c);
    // beqz: r5==0 → taken、offs21 は <<2 済みで渡す。
    set_gpr(&mut env, 5, 0);
    step_at(&mut env, enc(Insn::Beqz, &[5, 0x40]), 0x3000);
    assert_eq!(env.pc, 0x3040);
    // bnez: r5!=0 → taken。
    set_gpr(&mut env, 5, 7);
    step_at(&mut env, enc(Insn::Bnez, &[5, 0x20]), 0x3000);
    assert_eq!(env.pc, 0x3020);
}

#[test]
fn exec_la7_fcc_branches() {
    let mut env = env();
    // bceqz: fcc3=0 → taken。
    set_fcc(&mut env, 0);
    step_at(&mut env, enc(Insn::Bceqz, &[3, 0x10]), 0x4000);
    assert_eq!(env.pc, 0x4010);
    // bcnez: fcc3=1 → taken。
    set_fcc(&mut env, 1 << 3);
    step_at(&mut env, enc(Insn::Bcnez, &[3, 0x10]), 0x4000);
    assert_eq!(env.pc, 0x4010);
    // fcc3=1 のとき bceqz は fallthrough。
    step_at(&mut env, enc(Insn::Bceqz, &[3, 0x10]), 0x4000);
    assert_eq!(env.pc, 0x4004);
    // fcc0 は独立。fcc0=1 で fcc3 の分岐は影響なし。
    set_fcc(&mut env, 1);
    step_at(&mut env, enc(Insn::Bcnez, &[3, 0x10]), 0x4000);
    assert_eq!(env.pc, 0x4004);
    step_at(&mut env, enc(Insn::Bcnez, &[0, 0x10]), 0x4000);
    assert_eq!(env.pc, 0x4010);
}

#[test]
fn exec_la7_asrt() {
    use polyisa_engine::interp::InterpExit;
    use polyisa_sem::ExceptionKind;
    let mut env = env();
    set_gpr(&mut env, 5, 0x10);
    set_gpr(&mut env, 6, 0x20);
    // asrtle.d: rj(0x10) <= rk(0x20) → no-op。
    step(&mut env, enc(Insn::AsrtleD, &[5, 6]));
    // asrtle.d: rj > rk → BCE 例外。
    set_gpr(&mut env, 5, 0x30);
    let word = enc(Insn::AsrtleD, &[5, 6]);
    let insn = decode_model_ex(u128::from(word), 32, true, LA64).unwrap();
    let r = sem::exec(&mut env.backend, insn, word, 0x1000, true);
    match r {
        Err(InterpExit::Exception(e)) => {
            assert_eq!(e.kind, ExceptionKind::Trap);
            assert_eq!(e.code, sem::TRAP_BND);
        }
        _ => panic!("asrtle.d should raise bound check"),
    }
    // asrtgt.d: rj(0x30) > rk(0x20) → no-op。
    step(&mut env, enc(Insn::AsrtgtD, &[5, 6]));
    // asrtgt.d: rj <= rk → 例外。
    set_gpr(&mut env, 5, 0x20);
    let word = enc(Insn::AsrtgtD, &[5, 6]);
    let insn = decode_model_ex(u128::from(word), 32, true, LA64).unwrap();
    let r = sem::exec(&mut env.backend, insn, word, 0x1000, true);
    assert!(matches!(r, Err(InterpExit::Exception(_))));
}

// ---- LA8: CSR・特権入口 ----

/// CSR 値を読む（CpuState.csr 配列の直接参照）。
fn csr_val(env: &mut BareEnv, n: usize) -> u64 {
    use polyisa_sem::W64;
    env.backend.get(polyisa_sem::StateRef::<W64>::from_offset(
        core::mem::offset_of!(CpuState, csr) + n * 8,
    ))
}

#[test]
fn exec_la8_csr() {
    use polyisa_guest_loongarch::csr;
    let mut env = env();
    // csrwr rd, csr: rd の値を CSR へ書き、rd ← 旧値（0）。
    set_gpr(&mut env, 4, 0xdead_beef);
    step(&mut env, enc(Insn::Csrwr, &[4, 1, csr::SAVE0 as u64]));
    assert_eq!(csr_val(&mut env, csr::SAVE0), 0xdead_beef);
    assert_eq!(gpr(&mut env, 4), 0);
    // csrrd rd, csr: CSR 値を読む。
    step(&mut env, enc(Insn::Csrrd, &[5, 0, csr::SAVE0 as u64]));
    assert_eq!(gpr(&mut env, 5), 0xdead_beef);
    // csrxchg rd, rj, csr: mask=rj で CSR 一部差し替え。
    // CSR=0xdead_beef, rd=0x1234, rj(mask)=0xff00 →
    // CSR=(0xdead_beef & ~0xff00) | (0x1234 & 0xff00) = 0xdead_12ef。
    set_gpr(&mut env, 6, 0x1234);
    set_gpr(&mut env, 7, 0xff00);
    step(&mut env, enc(Insn::Csrxchg, &[6, 7, csr::SAVE0 as u64]));
    assert_eq!(csr_val(&mut env, csr::SAVE0), 0xdead_12ef);
    assert_eq!(gpr(&mut env, 6), 0xdead_beef);
    // 範囲外 CSR（>= 512）は読み 0・書き捨て。
    step(&mut env, enc(Insn::Csrrd, &[5, 0, 0x600]));
    assert_eq!(gpr(&mut env, 5), 0);
    set_gpr(&mut env, 4, 0xaa);
    step(&mut env, enc(Insn::Csrwr, &[4, 1, 0x600]));
    assert_eq!(gpr(&mut env, 4), 0);
}

#[test]
fn exec_la8_ertn() {
    use polyisa_guest_loongarch::csr;
    let mut env = env();
    // ERA=0x8000、PRMD[2:0]=5、CRMD=0x1f8 →
    // ertn: pc=0x8000、CRMD = (0x1f8 & ~7) | 5 = 0x1fd。
    env.backend.set(
        polyisa_sem::StateRef::<polyisa_sem::W64>::from_offset(
            core::mem::offset_of!(CpuState, csr) + csr::ERA * 8,
        ),
        0x8000,
    );
    env.backend.set(
        polyisa_sem::StateRef::<polyisa_sem::W64>::from_offset(
            core::mem::offset_of!(CpuState, csr) + csr::PRMD * 8,
        ),
        5,
    );
    env.backend.set(
        polyisa_sem::StateRef::<polyisa_sem::W64>::from_offset(
            core::mem::offset_of!(CpuState, csr) + csr::CRMD * 8,
        ),
        0x1f8,
    );
    step_at(&mut env, enc(Insn::Ertn, &[]), 0x1000);
    assert_eq!(env.pc, 0x8000);
    assert_eq!(csr_val(&mut env, csr::CRMD), 0x1fd);
}

#[test]
fn exec_la8_priv_approx() {
    use polyisa_engine::interp::InterpExit;
    let mut env = env();
    // TLB 系・cacop・idle・invtlb・ldpte は no-op。
    for i in [
        Insn::Tlbclr,
        Insn::Tlbfill,
        Insn::Tlbflush,
        Insn::Tlbrd,
        Insn::Tlbsrch,
        Insn::Tlbwr,
    ] {
        step(&mut env, enc(i, &[]));
    }
    step(&mut env, enc(Insn::Idle, &[0]));
    step(&mut env, enc(Insn::Cacop, &[0, 5, 0]));
    step(&mut env, enc(Insn::Invtlb, &[0, 5, 6]));
    step(&mut env, enc(Insn::Ldpte, &[5, 0]));
    // lddir は rd ← 0。
    set_gpr(&mut env, 4, 0xff);
    step(&mut env, enc(Insn::Lddir, &[4, 5, 0]));
    assert_eq!(gpr(&mut env, 4), 0);
    // iocsrrd.d は rd ← 0、iocsrwr.* は no-op。
    set_gpr(&mut env, 4, 0xff);
    step(&mut env, enc(Insn::IocsrrdD, &[4, 5]));
    assert_eq!(gpr(&mut env, 4), 0);
    step(&mut env, enc(Insn::IocsrwrD, &[4, 5]));
    // dbcl は例外。code = TRAP_DBG_BASE | code15。
    let word = enc(Insn::Dbcl, &[0x123]);
    let insn = decode_model_ex(u128::from(word), 32, true, LA64).unwrap();
    let r = sem::exec(&mut env.backend, insn, word, 0x1000, true);
    match r {
        Err(InterpExit::Exception(e)) => {
            assert_eq!(e.code, sem::TRAP_DBG_BASE | 0x123);
        }
        _ => panic!("dbcl should trap"),
    }
}

#[test]
fn exec_la8_rdtime_cntid() {
    let mut env = env();
    env.backend.set(sem::cnt_ref(), 0x0123_4567_89ab_cdef);
    // rdtime.d: rd ← 全 64 ビット、rj ← Counter ID（近似 0）。
    set_gpr(&mut env, 6, 0xff);
    step(&mut env, enc(Insn::RdtimeD, &[4, 6]));
    assert_eq!(gpr(&mut env, 4), 0x0123_4567_89ab_cdef);
    assert_eq!(gpr(&mut env, 6), 0);
    // rdtimel.w: rd ← sext(low32)、rj ← 0。
    step(&mut env, enc(Insn::RdtimelW, &[4, 6]));
    assert_eq!(gpr(&mut env, 4), (-0x7654_3211i64) as u64);
    assert_eq!(gpr(&mut env, 6), 0);
    // rdtimeh.w: rd ← sext(high32)。
    step(&mut env, enc(Insn::RdtimehW, &[4, 6]));
    assert_eq!(gpr(&mut env, 4), 0x0123_4567);
}

// ---- LA9: スカラ FP ----

/// FR[`n`] のビット列。
fn fr(env: &mut BareEnv, n: u32) -> u64 {
    env.backend.get(sem::fr_ref(n))
}

fn set_fr(env: &mut BareEnv, n: u32, v: u64) {
    env.backend.set(sem::fr_ref(n), v);
}

/// FCC 束。
fn fcc_bundle(env: &mut BareEnv) -> u64 {
    env.backend.get(sem::fcc_ref())
}

/// FCSR 語を読む。
fn fcsr_val(env: &mut BareEnv, n: u32) -> u32 {
    use polyisa_sem::W32;
    env.backend.get(polyisa_sem::StateRef::<W32>::from_offset(
        core::mem::offset_of!(CpuState, fcsr) + n as usize * 4,
    ))
}

fn set_fcsr(env: &mut BareEnv, n: u32, v: u32) {
    use polyisa_sem::W32;
    env.backend.set(
        polyisa_sem::StateRef::<W32>::from_offset(
            core::mem::offset_of!(CpuState, fcsr) + n as usize * 4,
        ),
        v,
    );
}

const F64_1: u64 = 0x3ff0_0000_0000_0000;
const F64_2: u64 = 0x4000_0000_0000_0000;
const F64_3: u64 = 0x4008_0000_0000_0000;
const F64_4: u64 = 0x4010_0000_0000_0000;
const F64_HALF: u64 = 0x3fe0_0000_0000_0000;
const F64_N2: u64 = 0xc000_0000_0000_0000;
const F64_NAN: u64 = 0x7ff8_0000_0000_0000;
const F32_1: u64 = 0x3f80_0000;
const F32_2: u64 = 0x4000_0000;
const F32_N1_5: u64 = 0xbfc0_0000;

#[test]
fn exec_la9_fp_arith() {
    let mut env = env();
    // fadd.d 1.0 + 2.0 = 3.0。
    set_fr(&mut env, 1, F64_1);
    set_fr(&mut env, 2, F64_2);
    step(&mut env, enc(Insn::FaddD, &[0, 1, 2]));
    assert_eq!(fr(&mut env, 0), F64_3);
    // fsub.d 3.0 - 1.0 = 2.0。
    step(&mut env, enc(Insn::FsubD, &[0, 0, 1]));
    assert_eq!(fr(&mut env, 0), F64_2);
    // fmul.d 2.0 * 2.0 = 4.0。
    step(&mut env, enc(Insn::FmulD, &[0, 0, 0]));
    assert_eq!(fr(&mut env, 0), F64_4);
    // fdiv.d 4.0 / 4.0 = 1.0。
    step(&mut env, enc(Insn::FdivD, &[0, 0, 0]));
    assert_eq!(fr(&mut env, 0), F64_1);
    // fadd.s: f32 ビットは下位 32 ビット。1.0f + 2.0f = 3.0f。
    set_fr(&mut env, 1, F32_1);
    set_fr(&mut env, 2, F32_2);
    step(&mut env, enc(Insn::FaddS, &[0, 1, 2]));
    assert_eq!(fr(&mut env, 0), 0x4040_0000);
    // fsqrt.d 4.0 = 2.0。
    set_fr(&mut env, 1, F64_4);
    step(&mut env, enc(Insn::FsqrtD, &[0, 1]));
    assert_eq!(fr(&mut env, 0), F64_2);
    // frecip.d 2.0 = 0.5、frsqrt.d 4.0 = 0.5。
    set_fr(&mut env, 1, F64_2);
    step(&mut env, enc(Insn::FrecipD, &[0, 1]));
    assert_eq!(fr(&mut env, 0), F64_HALF);
    set_fr(&mut env, 1, F64_4);
    step(&mut env, enc(Insn::FrsqrtD, &[0, 1]));
    assert_eq!(fr(&mut env, 0), F64_HALF);
    // 近似命令は正確演算で代替。
    set_fr(&mut env, 1, F64_2);
    step(&mut env, enc(Insn::FrecipeD, &[0, 1]));
    assert_eq!(fr(&mut env, 0), F64_HALF);
    step(&mut env, enc(Insn::FrsqrteD, &[0, 1]));
    assert_eq!(fr(&mut env, 0), (1.0f64 / 2f64.sqrt()).to_bits());
    // FP の割込フラグが FCSR0 に載る: 1/2 は正確だが、
    // 0/0 → NaN で invalid が立つ。
    set_fr(&mut env, 1, 0);
    set_fr(&mut env, 2, 0);
    step(&mut env, enc(Insn::FdivD, &[0, 1, 2]));
    assert!(fcsr_val(&mut env, 0) & (1 << 28) != 0, "cause.V");
    assert!(fcsr_val(&mut env, 0) & (1 << 20) != 0, "flags.V");
}

#[test]
fn exec_la9_fp_min_max_mag_sign() {
    let mut env = env();
    set_fr(&mut env, 1, F64_1);
    set_fr(&mut env, 2, F64_N2);
    // fmax.d(1.0, -2.0) = 1.0、fmin.d = -2.0。
    step(&mut env, enc(Insn::FmaxD, &[0, 1, 2]));
    assert_eq!(fr(&mut env, 0), F64_1);
    step(&mut env, enc(Insn::FminD, &[0, 1, 2]));
    assert_eq!(fr(&mut env, 0), F64_N2);
    // fmaxa.d(1.0, -2.0) = -2.0（|x| が大きい方）、fmina.d = 1.0。
    step(&mut env, enc(Insn::FmaxaD, &[0, 1, 2]));
    assert_eq!(fr(&mut env, 0), F64_N2);
    step(&mut env, enc(Insn::FminaD, &[0, 1, 2]));
    assert_eq!(fr(&mut env, 0), F64_1);
    // fabs/fneg/fmov/fcopysign。
    step(&mut env, enc(Insn::FabsD, &[0, 2]));
    assert_eq!(fr(&mut env, 0), F64_2);
    step(&mut env, enc(Insn::FnegD, &[0, 1]));
    assert_eq!(fr(&mut env, 0), 0xbff0_0000_0000_0000);
    step(&mut env, enc(Insn::FmovD, &[0, 1]));
    assert_eq!(fr(&mut env, 0), F64_1);
    step(&mut env, enc(Insn::FcopysignD, &[0, 1, 2]));
    assert_eq!(fr(&mut env, 0), F64_1 | (1u64 << 63));
}

#[test]
fn exec_la9_fp_fma() {
    let mut env = env();
    set_fr(&mut env, 1, F64_2);
    set_fr(&mut env, 2, F64_3);
    set_fr(&mut env, 3, F64_1);
    // fmadd.d = 2*3+1 = 7.0。
    step(&mut env, enc(Insn::FmaddD, &[0, 1, 2, 3]));
    assert_eq!(fr(&mut env, 0), 0x401c_0000_0000_0000);
    // fmsub.d = 2*3-1 = 5.0。
    step(&mut env, enc(Insn::FmsubD, &[0, 1, 2, 3]));
    assert_eq!(fr(&mut env, 0), 0x4014_0000_0000_0000);
    // fnmadd.d = -(2*3+1) = -7.0。
    step(&mut env, enc(Insn::FnmaddD, &[0, 1, 2, 3]));
    assert_eq!(fr(&mut env, 0), 0xc01c_0000_0000_0000);
    // fnmsub.d = -(2*3-1) = -5.0。
    step(&mut env, enc(Insn::FnmsubD, &[0, 1, 2, 3]));
    assert_eq!(fr(&mut env, 0), 0xc014_0000_0000_0000);
}

#[test]
fn exec_la9_fp_scaleb_logb_class() {
    let mut env = env();
    // fscaleb.d 1.0 * 2^3 = 8.0。fk は整数ビット 3。
    set_fr(&mut env, 1, F64_1);
    set_fr(&mut env, 2, 3);
    step(&mut env, enc(Insn::FscalebD, &[0, 1, 2]));
    assert_eq!(fr(&mut env, 0), 0x4020_0000_0000_0000);
    // 負の n: 4.0 * 2^-2 = 1.0。
    set_fr(&mut env, 1, F64_4);
    set_fr(&mut env, 2, (-2i64) as u64);
    step(&mut env, enc(Insn::FscalebD, &[0, 1, 2]));
    assert_eq!(fr(&mut env, 0), F64_1);
    // flogb.d 8.0 = 3.0。flogb.d 0.5 = -1.0。flogb.d 0.0 = -inf。
    set_fr(&mut env, 1, 0x4020_0000_0000_0000);
    step(&mut env, enc(Insn::FlogbD, &[0, 1]));
    assert_eq!(fr(&mut env, 0), F64_3);
    set_fr(&mut env, 1, F64_HALF);
    step(&mut env, enc(Insn::FlogbD, &[0, 1]));
    assert_eq!(fr(&mut env, 0), 0xbff0_0000_0000_0000);
    set_fr(&mut env, 1, 0);
    step(&mut env, enc(Insn::FlogbD, &[0, 1]));
    assert_eq!(fr(&mut env, 0), 0xfff0_0000_0000_0000);
    // 非正規化: 最小 denormal（2^-1074）→ -1074.0。
    set_fr(&mut env, 1, 1);
    step(&mut env, enc(Insn::FlogbD, &[0, 1]));
    assert_eq!(fr(&mut env, 0), (-1074.0f64).to_bits());
    // fclass.d: 1.0 → bit8(+norm)、-inf → bit2、0 → bit6、NaN → bit1。
    set_fr(&mut env, 1, F64_1);
    step(&mut env, enc(Insn::FclassD, &[0, 1]));
    assert_eq!(fr(&mut env, 0), 1 << 8);
    set_fr(&mut env, 1, 0xfff0_0000_0000_0000);
    step(&mut env, enc(Insn::FclassD, &[0, 1]));
    assert_eq!(fr(&mut env, 0), 1 << 2);
    set_fr(&mut env, 1, 0);
    step(&mut env, enc(Insn::FclassD, &[0, 1]));
    assert_eq!(fr(&mut env, 0), 1 << 6);
    set_fr(&mut env, 1, F64_NAN);
    step(&mut env, enc(Insn::FclassD, &[0, 1]));
    assert_eq!(fr(&mut env, 0), 1 << 1);
    set_fr(&mut env, 1, 1);
    step(&mut env, enc(Insn::FclassD, &[0, 1]));
    assert_eq!(fr(&mut env, 0), 1 << 7);
}

#[test]
fn exec_la9_fcmp() {
    let mut env = env();
    set_fr(&mut env, 1, F64_1);
    set_fr(&mut env, 2, F64_2);
    // CEQ(4): 1.0 == 2.0 → 0。CLT(2): 1.0 < 2.0 → 1。
    step(&mut env, enc(Insn::FcmpCondD, &[0, 1, 2, 4]));
    assert_eq!(fcc_bundle(&mut env) & 1, 0);
    step(&mut env, enc(Insn::FcmpCondD, &[1, 1, 2, 2]));
    assert_eq!((fcc_bundle(&mut env) >> 1) & 1, 1);
    // CLE(6): 1.0 <= 2.0 → 1。CNE(16): 1.0 != 2.0 → 1。
    step(&mut env, enc(Insn::FcmpCondD, &[2, 1, 2, 6]));
    assert_eq!((fcc_bundle(&mut env) >> 2) & 1, 1);
    step(&mut env, enc(Insn::FcmpCondD, &[3, 1, 2, 0x10]));
    assert_eq!((fcc_bundle(&mut env) >> 3) & 1, 1);
    // NaN: CUN(8) → 1、COR(0x14) → 0、CUNE(0x18) → 1。
    set_fr(&mut env, 1, F64_NAN);
    step(&mut env, enc(Insn::FcmpCondD, &[4, 1, 2, 8]));
    assert_eq!((fcc_bundle(&mut env) >> 4) & 1, 1);
    step(&mut env, enc(Insn::FcmpCondD, &[5, 1, 2, 0x14]));
    assert_eq!((fcc_bundle(&mut env) >> 5) & 1, 0);
    step(&mut env, enc(Insn::FcmpCondD, &[6, 1, 2, 0x18]));
    assert_eq!((fcc_bundle(&mut env) >> 6) & 1, 1);
    // .s 形式でも動く。fcc7 に CEQ(4)。
    set_fr(&mut env, 1, F32_1);
    set_fr(&mut env, 2, F32_2);
    step(&mut env, enc(Insn::FcmpCondS, &[7, 1, 2, 4]));
    assert_eq!((fcc_bundle(&mut env) >> 7) & 1, 0);
}

#[test]
fn exec_la9_fsel_and_moves() {
    let mut env = env();
    set_fr(&mut env, 1, F64_1);
    set_fr(&mut env, 2, F64_2);
    // fsel: fcc3=0 → fj(1.0)、fcc3=1 → fk(2.0)。
    set_fcc(&mut env, 0);
    step(&mut env, enc(Insn::Fsel, &[0, 1, 2, 3]));
    assert_eq!(fr(&mut env, 0), F64_1);
    set_fcc(&mut env, 1 << 3);
    step(&mut env, enc(Insn::Fsel, &[0, 1, 2, 3]));
    assert_eq!(fr(&mut env, 0), F64_2);
    // movgr2fr.d / movfr2gr.d。
    set_gpr(&mut env, 5, F64_3);
    step(&mut env, enc(Insn::Movgr2frD, &[4, 5]));
    assert_eq!(fr(&mut env, 4), F64_3);
    step(&mut env, enc(Insn::Movfr2grD, &[6, 4]));
    assert_eq!(gpr(&mut env, 6), F64_3);
    // movgr2fr.w: 下位 32 ビット、上位 0。
    set_gpr(&mut env, 5, 0xffff_ffff_3f80_0000);
    step(&mut env, enc(Insn::Movgr2frW, &[4, 5]));
    assert_eq!(fr(&mut env, 4), 0x3f80_0000);
    // movgr2frh.w: 上位 32 ビット、下位不変。
    set_gpr(&mut env, 5, 0x1234_5678);
    step(&mut env, enc(Insn::Movgr2frhW, &[4, 5]));
    assert_eq!(fr(&mut env, 4), 0x1234_5678_3f80_0000);
    // movfr2gr.s / movfrh2gr.s: 符号拡張。
    step(&mut env, enc(Insn::Movfr2grS, &[6, 4]));
    assert_eq!(gpr(&mut env, 6), 0x3f80_0000);
    step(&mut env, enc(Insn::Movfrh2grS, &[6, 4]));
    assert_eq!(gpr(&mut env, 6), 0x1234_5678);
    // movfr2cf / movcf2fr / movgr2cf / movcf2gr。
    set_fr(&mut env, 1, 3);
    step(&mut env, enc(Insn::Movfr2cf, &[2, 1]));
    assert_eq!((fcc_bundle(&mut env) >> 2) & 1, 1);
    set_fr(&mut env, 4, 0xdead_beef);
    step(&mut env, enc(Insn::Movcf2fr, &[4, 2]));
    assert_eq!(fr(&mut env, 4), 0xdead_beef | 1);
    set_gpr(&mut env, 5, 4);
    step(&mut env, enc(Insn::Movgr2cf, &[5, 5]));
    assert_eq!((fcc_bundle(&mut env) >> 5) & 1, 0);
    step(&mut env, enc(Insn::Movcf2gr, &[6, 2]));
    assert_eq!(gpr(&mut env, 6), 1);
    // movgr2fcsr / movfcsr2gr: fcsr0 全語、fcsr3 は RM エイリアス。
    set_gpr(&mut env, 5, 0x1f1f_00ff);
    step(&mut env, enc(Insn::Movgr2fcsr, &[0, 5]));
    assert_eq!(fcsr_val(&mut env, 0), 0x1f1f_00ff);
    step(&mut env, enc(Insn::Movfcsr2gr, &[6, 0]));
    assert_eq!(gpr(&mut env, 6), 0x1f1f_00ff);
    // fcsr3=RM エイリアス: 書き込みは FCSR0[9:8]、読みはそのビット。
    set_gpr(&mut env, 5, 0x200);
    step(&mut env, enc(Insn::Movgr2fcsr, &[3, 5]));
    assert_eq!(fcsr_val(&mut env, 0) & 0x300, 0x200);
    assert_eq!(fcsr_val(&mut env, 0) & !0x300, 0x1f1f_00ff & !0x300);
    step(&mut env, enc(Insn::Movfcsr2gr, &[6, 3]));
    assert_eq!(gpr(&mut env, 6), 0x200);
    // fcsr1=enables エイリアス。
    set_gpr(&mut env, 5, 0x1e);
    step(&mut env, enc(Insn::Movgr2fcsr, &[1, 5]));
    assert_eq!(fcsr_val(&mut env, 0) & 0x1f, 0x1e);
    step(&mut env, enc(Insn::Movfcsr2gr, &[6, 1]));
    assert_eq!(gpr(&mut env, 6), 0x1e);
}

#[test]
fn exec_la9_fp_convert() {
    let mut env = env();
    // ffint.d.w: 42 → 42.0。
    set_fr(&mut env, 1, 42);
    step(&mut env, enc(Insn::FfintDW, &[0, 1]));
    assert_eq!(fr(&mut env, 0), (42.0f64).to_bits());
    // ffint.s.l: -7 → -7.0f。
    set_fr(&mut env, 1, (-7i64) as u64);
    step(&mut env, enc(Insn::FfintSL, &[0, 1]));
    assert_eq!(fr(&mut env, 0), (-7.0f32).to_bits() as u64);
    // ftint.l.d: 2.9 → 2（RNE）、ftintrp.l.d → 3。
    set_fr(&mut env, 1, (2.9f64).to_bits());
    step(&mut env, enc(Insn::FtintLD, &[0, 1]));
    assert_eq!(fr(&mut env, 0), 3); // RNE 2.9 → 3
    step(&mut env, enc(Insn::FtintrzLD, &[0, 1]));
    assert_eq!(fr(&mut env, 0), 2);
    step(&mut env, enc(Insn::FtintrpLD, &[0, 1]));
    assert_eq!(fr(&mut env, 0), 3);
    step(&mut env, enc(Insn::FtintrmLD, &[0, 1]));
    assert_eq!(fr(&mut env, 0), 2);
    // ftint.w.s: -1.6f → -2（RNE）、ftintrne.w.s も -2、
    // ftintrz.w.s → -1。
    set_fr(&mut env, 1, F32_N1_5);
    step(&mut env, enc(Insn::FtintrneWS, &[0, 1]));
    assert_eq!(fr(&mut env, 0), (-2i32) as u32 as u64);
    step(&mut env, enc(Insn::FtintrzWS, &[0, 1]));
    assert_eq!(fr(&mut env, 0), (-1i32) as u32 as u64);
    // ftint の動的 rm: FCSR.RM=RZ(1) → -1.5 → -1。
    set_fcsr(&mut env, 0, 1 << 8);
    step(&mut env, enc(Insn::FtintWS, &[0, 1]));
    assert_eq!(fr(&mut env, 0), (-1i32) as u32 as u64);
    set_fcsr(&mut env, 0, 0);
    // fcvt.s.d: 1.5 → 1.5f。fcvt.d.s 戻す。
    set_fr(&mut env, 1, (1.5f64).to_bits());
    step(&mut env, enc(Insn::FcvtSD, &[0, 1]));
    assert_eq!(fr(&mut env, 0), 0x3fc0_0000);
    step(&mut env, enc(Insn::FcvtDS, &[0, 0]));
    assert_eq!(fr(&mut env, 0), (1.5f64).to_bits());
    // frint.d: 2.5 → 2.0（RNE）、FCSR.RM=RP(2) → 3.0。
    set_fr(&mut env, 1, (2.5f64).to_bits());
    step(&mut env, enc(Insn::FrintD, &[0, 1]));
    assert_eq!(fr(&mut env, 0), F64_2);
    set_fcsr(&mut env, 0, 2 << 8);
    step(&mut env, enc(Insn::FrintD, &[0, 1]));
    assert_eq!(fr(&mut env, 0), F64_3);
    set_fcsr(&mut env, 0, 0);
    // ffint.s.w: 丸めが効く（-2.5 int はないので int→fp は正確）。
    set_fr(&mut env, 1, 0x8000_0001);
    step(&mut env, enc(Insn::FfintSW, &[0, 1]));
    assert_eq!(fr(&mut env, 0), (-2147483647.0f32).to_bits() as u64);
}

#[test]
fn exec_la9_fp_memory() {
    let mut env = mem_env();
    poke64(&mut env, 0x2000, F64_3);
    set_gpr(&mut env, 5, 0x2000);
    // fld.d f4 ← [r5+0]。
    step(&mut env, enc(Insn::FldD, &[4, 5, 0]));
    assert_eq!(fr(&mut env, 4), F64_3);
    // fld.s f4 ← [r5+8]（下位 32、上位 0）。
    poke64(&mut env, 0x2008, 0xffff_ffff_4040_0000);
    step(&mut env, enc(Insn::FldS, &[4, 5, 8]));
    assert_eq!(fr(&mut env, 4), 0x4040_0000);
    // fst.d / fst.s。
    set_fr(&mut env, 4, F64_1);
    step(&mut env, enc(Insn::FstD, &[4, 5, 16]));
    assert_eq!(peek(&mut env, 0x2010, 8), F64_1);
    set_fr(&mut env, 4, 0xaabb_ccdd_1234_5678);
    step(&mut env, enc(Insn::FstS, &[4, 5, 24]));
    assert_eq!(peek(&mut env, 0x2018, 4), 0x1234_5678);
    // fldx.d / fstx.s（ea = rj + rk）。
    set_gpr(&mut env, 6, 0x20);
    poke64(&mut env, 0x2020, F64_2);
    step(&mut env, enc(Insn::FldxD, &[4, 5, 6]));
    assert_eq!(fr(&mut env, 4), F64_2);
    set_fr(&mut env, 4, 0x4040_0000);
    step(&mut env, enc(Insn::FstxS, &[4, 5, 6]));
    assert_eq!(peek(&mut env, 0x2020, 4), 0x4040_0000);
    // fldgt.d / fstle.d（bound check）。
    set_gpr(&mut env, 6, 0x1000);
    step(&mut env, enc(Insn::FldgtD, &[4, 5, 6]));
    assert_eq!(fr(&mut env, 4), F64_3);
    set_fr(&mut env, 4, F64_4);
    set_gpr(&mut env, 6, 0x2000);
    step(&mut env, enc(Insn::FstleD, &[4, 5, 6]));
    assert_eq!(peek(&mut env, 0x2000, 8), F64_4);
}
