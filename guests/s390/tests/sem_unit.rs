// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! s390/zArchitecture の命令単位テスト（層1・unit、S11-1）。
//!
//! BareEnv の解釈実行で、可変長命令語を `sem::exec` に渡して CPU 状態を
//! 検査する。命令語は PoP のフィールド規約（exec の切り出しと同じ
//! 右詰め表現）で手で組み立てる。出典は SPEC-S390-ZARCH-POP
//! （SA22-7832）と SPEC-S390-ESA390-POP（SA22-7201）。

use polyisa_engine::bare::BareEnv;
use polyisa_guest_s390::Insn;
use polyisa_guest_s390::sem::{self, Fpr, Gpr};
use polyisa_mem::{Perms, VirtAddr};
use polyisa_sem::Backend;

fn env() -> BareEnv {
    let mut e = BareEnv::new(core::mem::size_of::<polyisa_guest_s390::CpuState>());
    e.backend.set(sem::amask_ref(), u64::MAX);
    e
}

fn run(env: &mut BareEnv, insn: Insn, w: u64, pc: u64) {
    env.step(|b| sem::exec(b, insn, w, pc)).unwrap();
}

fn r(env: &mut BareEnv, i: u8) -> u64 {
    env.backend.get(Gpr(i).state())
}

fn f(env: &mut BareEnv, i: u8) -> u64 {
    env.backend.get(Fpr(i).state())
}

fn cc(env: &mut BareEnv) -> u64 {
    env.backend.get(sem::cc_ref())
}

#[test]
fn lghi_aghi_set_gpr64() {
    let mut e = env();
    // lghi %r5, -7 → a7 59 ff f9（RI: a7 | r1 9 | i2）。
    run(&mut e, Insn::Lghi, 0xa759_fff9, 0x100);
    assert_eq!(r(&mut e, 5), 0xffff_ffff_ffff_fff9u64);
    // aghi %r5, -1 → a7 5b ff ff。-7 + -1 = -8。
    run(&mut e, Insn::Aghi, 0xa75b_ffff, 0x104);
    assert_eq!(r(&mut e, 5), 0xffff_ffff_ffff_fff8);
    // lghi %r3, 0x1234 → a7 39 12 34。
    run(&mut e, Insn::Lghi, 0xa739_1234, 0x108);
    assert_eq!(r(&mut e, 3), 0x1234);
}

#[test]
fn lgr_lgfr_move_and_extend() {
    let mut e = env();
    run(&mut e, Insn::Aghi, 0xa71b_ffff, 0x100); // r1 = -1
    // lgr %r3,%r1 → b9 04 00 31。
    run(&mut e, Insn::B9, 0xb904_0031, 0x104);
    assert_eq!(r(&mut e, 3), u64::MAX);
    // lgfr %r3,%r1 は -1 のまま。llgfr はゼロ拡張。
    run(&mut e, Insn::B9, 0xb916_0031, 0x108);
    assert_eq!(r(&mut e, 3), 0xffff_ffff);
}

#[test]
fn stg_lg_roundtrip_be() {
    let mut e = env();
    e.backend.mem.map(VirtAddr(0x8000), 1, Perms::RW).unwrap();
    e.backend.set(Gpr(10).state(), 0x8008);
    e.backend.set(Gpr(5).state(), 0x0123_4567_89ab_cdef);
    // stg %r5, 0(%r10) → e3 50 a0 00 00 24（RXY: func=0x24）。
    run(&mut e, Insn::E3, 0xe350_a000_0024, 0x100);
    // メモリはビッグエンディアン。
    let mut buf = [0u8; 8];
    e.backend
        .mem
        .read(
            VirtAddr(0x8008),
            &mut buf,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Be,
                align: polyisa_mem::Align::Natural,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(buf, [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
    // lg %r7, 0(%r10) → e3 70 a0 00 00 04。
    run(&mut e, Insn::E3, 0xe370_a000_0004, 0x108);
    assert_eq!(r(&mut e, 7), 0x0123_4567_89ab_cdef);
}

#[test]
fn ar_sr_set_cc_signed() {
    let mut e = env();
    e.backend.set(Gpr(2).state(), 5);
    e.backend.set(Gpr(3).state(), 9);
    // ar %r2,%r3 → 1a 23: r2 = 14、CC=2（正、桁上げなし）。
    run(&mut e, Insn::Ar, 0x1a23, 0x100);
    assert_eq!(r(&mut e, 2) & 0xffff_ffff, 14);
    // sr %r3,%r2 → 1b 32: 9 - 14 = -5 → CC=1。
    run(&mut e, Insn::Sr, 0x1b32, 0x104);
    assert_eq!(r(&mut e, 3) as i32, -5);
    assert_eq!(cc(&mut e), 1);
}

#[test]
fn cr_eq_cc0() {
    let mut e = env();
    e.backend.set(Gpr(4).state(), 0xdead_beef);
    e.backend.set(Gpr(5).state(), 0xdead_beef);
    // cr %r4,%r5 → 19 45。
    run(&mut e, Insn::Cr, 0x1945, 0x100);
    assert_eq!(cc(&mut e), 0);
}

#[test]
fn bcr_r2_zero_is_nop() {
    // BCR m,0（いわゆる `br %r0` ホットパッチ）は分岐しない。
    // 制御の jump 先が立たないことを Fallthrough で確認する。
    let mut e = env();
    run(&mut e, Insn::Bcr, 0x07e0, 0x100);
    assert_eq!(e.backend.ctrl, polyisa_engine::interp::Ctrl::Fallthrough);
}

#[test]
fn bctr_r2_zero_counts_down() {
    let mut e = env();
    e.backend.set(Gpr(3).state(), 5);
    // bctr %r3,0 → 06 30: デクリメントのみ、分岐しない。
    run(&mut e, Insn::Bctr, 0x0630, 0x100);
    assert_eq!(r(&mut e, 3), 4);
    assert_eq!(e.backend.ctrl, polyisa_engine::interp::Ctrl::Fallthrough);
}

#[test]
fn icm_stcm_clm_packed_bytes() {
    let mut e = env();
    e.backend.mem.map(VirtAddr(0x9000), 1, Perms::RW).unwrap();
    // メモリにパック済みバイト 0xaa 0xbb 0xcc を書く。
    e.backend
        .mem
        .write(VirtAddr(0x9010), &[0xaa, 0xbb, 0xcc])
        .unwrap();
    e.backend.set(Gpr(13).state(), 0x9010);
    // icm %r2, 0b1010, 0(%r13) → bf 2a d0 00。
    // mask bit0 → r2 の左端バイト（byte4）← aa、bit2 → byte6 ← bb
    // （メモリは選択バイト順に連続して読む）。
    run(&mut e, Insn::Icm, 0xbf2a_d000, 0x100);
    assert_eq!(r(&mut e, 2) & 0xffff_ffff, 0xaa00_bb00);
    // stcm %r4, 0b0011, 0(%r13): r4 の byte6,7 をメモリへ連続で書く。
    e.backend.set(Gpr(4).state(), 0x1122_3344_5566_7788);
    run(&mut e, Insn::Stcm, 0xbe43_d004, 0x108);
    let mut buf = [0u8; 2];
    e.backend
        .mem
        .read(
            VirtAddr(0x9014),
            &mut buf,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Be,
                align: polyisa_mem::Align::Natural,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(buf, [0x77, 0x88]);
    // clm %r4, 0b0011, 0(%r13): byte6=0x77, byte7=0x88 と等しい → CC=0。
    run(&mut e, Insn::Clm, 0xbd43_d004, 0x110);
    assert_eq!(cc(&mut e), 0);
    // 1 バイト変えて CC=2（レジスタ側が大）。
    e.backend.mem.write(VirtAddr(0x9014), &[0x76]).unwrap();
    run(&mut e, Insn::Clm, 0xbd43_d004, 0x118);
    assert_eq!(cc(&mut e), 2);
}

#[test]
fn larl_relative_address() {
    let mut e = env();
    // larl %r11, +0x80 → c0 b0 00 00 00 40（RIL: i2=0x40 → pc+0x80）。
    run(&mut e, Insn::Larl, 0xc0b0_0000_0040, 0x100);
    assert_eq!(r(&mut e, 11), 0x180);
}

#[test]
fn ldr_adbr_sdbr_mdbr_ddbr() {
    let mut e = env();
    e.backend.set(Fpr(0).state(), 0x3ff8_0000_0000_0000); // 1.5
    e.backend.set(Fpr(1).state(), 0x4000_0000_0000_0000); // 2.0
    // adbr %f2,%f0 → b3 1a 00 20 → f2 = f2 + f0。まず ldr で値を入れる。
    // ldr %f2,%f1 → 28 21。
    run(&mut e, Insn::Ldr, 0x2821, 0x100);
    assert_eq!(f(&mut e, 2), 0x4000_0000_0000_0000);
    run(&mut e, Insn::B3, 0xb31a_0020, 0x104); // adbr %f2,%f0 → 3.5
    assert_eq!(f(&mut e, 2), 0x400c_0000_0000_0000);
    run(&mut e, Insn::B3, 0xb31b_0020, 0x108); // sdbr %f2,%f0 → 2.0
    assert_eq!(f(&mut e, 2), 0x4000_0000_0000_0000);
    run(&mut e, Insn::B3, 0xb31c_0020, 0x10c); // mdbr %f2,%f0 → 3.0
    assert_eq!(f(&mut e, 2), 0x4008_0000_0000_0000);
    run(&mut e, Insn::B3, 0xb31d_0020, 0x110); // ddbr %f2,%f0 → 2.0
    assert_eq!(f(&mut e, 2), 0x4000_0000_0000_0000);
}

#[test]
fn madbr_fused_rrf() {
    // MADBR は RRF-a: `B3 1e | r1 0 | r2 r3`。byte2 上位が r1（宛先）、
    // byte3 上位が r2、下位が r3。b3 1e 20 80 は madbr %f2,%f8,%f0 →
    // f2 = f0*f8 + f2（llvm-mc の encode で確認済み）。
    let mut e = env();
    e.backend.set(Fpr(8).state(), 0x4014_0000_0000_0000); // 5.0
    e.backend.set(Fpr(0).state(), 0x4000_0000_0000_0000); // 2.0
    e.backend.set(Fpr(2).state(), 0x4008_0000_0000_0000); // 3.0
    run(&mut e, Insn::B3, 0xb31e_2080, 0x100);
    // f2 = f0*f8 + f2 = 2*5 + 3 = 13.0。
    assert_eq!(f(&mut e, 2), 0x402a_0000_0000_0000);
}

#[test]
fn cdgbr_cgdbr_convert() {
    let mut e = env();
    e.backend.set(Gpr(1).state(), 42);
    // cdgbr %f2,%r1 → b3 a5 00 21。
    run(&mut e, Insn::B3, 0xb3a5_0021, 0x100);
    assert_eq!(f(&mut e, 2), 0x4045_0000_0000_0000);
    // cgdbr %r1,5,%f2 → b3 a9 50 12: 42.0 → 42（m3=5: trunc）。
    run(&mut e, Insn::B3, 0xb3a9_5012, 0x108);
    assert_eq!(r(&mut e, 1), 42);
}

#[test]
fn lgdr_ldgr_bit_moves() {
    let mut e = env();
    e.backend.set(Fpr(3).state(), 0x3ff0_0000_0000_0000);
    // lgdr %r1,%f3 → b3 cd 00 13: GPR に FPR のビット列。
    run(&mut e, Insn::B3, 0xb3cd_0013, 0x100);
    assert_eq!(r(&mut e, 1), 0x3ff0_0000_0000_0000);
    // ldgr %f5,%r7 → b3 c1 00 57: FPR に GPR のビット列。
    e.backend.set(Gpr(7).state(), 0x4008_0000_0000_0000);
    run(&mut e, Insn::B3, 0xb3c1_0057, 0x108);
    assert_eq!(f(&mut e, 5), 0x4008_0000_0000_0000);
}

#[test]
fn mvcl_copies_big_endian() {
    let mut e = env();
    e.backend.mem.map(VirtAddr(0xa000), 1, Perms::RW).unwrap();
    e.backend.mem.write(VirtAddr(0xa100), b"polyisa!").unwrap();
    // mvcl %r2,%r4 → 0e 24。r2=dst|r2+1=len、r4=src|r4+1=srclen。
    e.backend.set(Gpr(2).state(), 0xa200);
    e.backend.set(Gpr(3).state(), 8);
    e.backend.set(Gpr(4).state(), 0xa100);
    e.backend.set(Gpr(5).state(), 8);
    run(&mut e, Insn::Mvcl, 0x0e24, 0x100);
    let mut buf = [0u8; 8];
    e.backend
        .mem
        .read(
            VirtAddr(0xa200),
            &mut buf,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Be,
                align: polyisa_mem::Align::Natural,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(&buf, b"polyisa!");
}

#[test]
fn tm_cli_branches() {
    let mut e = env();
    e.backend.mem.map(VirtAddr(0xb000), 1, Perms::RW).unwrap();
    e.backend.mem.write(VirtAddr(0xb010), &[0x30]).unwrap();
    e.backend.set(Gpr(13).state(), 0xb010);
    // cli 0(%r13), 0x30 → 95 30 d0 00。
    run(&mut e, Insn::Cli, 0x9530_d000, 0x100);
    assert_eq!(cc(&mut e), 0);
    // tm 0(%r13), 0x10 → 91 10 d0 00: 0x30 & 0x10 = 0x10。PoP の TM は
    // 選択ビットが全部 1 → CC=3、全部 0 → CC=0、混在 → CC=1。
    // ここでは唯一の選択ビットが立つので CC=3。
    run(&mut e, Insn::Tm, 0x9110_d000, 0x104);
    assert_eq!(cc(&mut e), 3);
    // tm 0(%r13), 0x3c → 0x30 & 0x3c = 0x30: マスク 2-5 番目ビットのうち
    // 2,3 は 0 → 混在 → CC=1。
    run(&mut e, Insn::Tm, 0x913c_d000, 0x108);
    assert_eq!(cc(&mut e), 1);
}

#[test]
fn esa_31bit_amask() {
    // ESA/390 側: amask=0x7fffffff の 31 ビット有効アドレス指定では、
    // `la` は下位 32 ビットのみ書き換えて上位を保持する。
    let mut e = env();
    e.backend.set(sem::amask_ref(), 0x7fff_ffff);
    e.backend.set(Gpr(2).state(), 0xdead_beef_0000_0000);
    e.backend.set(Gpr(3).state(), 0x100);
    // la %r2, 0(%r3) → 41 20 30 00。
    run(&mut e, Insn::La, 0x4120_3000, 0x100);
    assert_eq!(r(&mut e, 2), 0xdead_beef_0000_0100);
}
