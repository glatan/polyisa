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

// ======== ステージ 11 レビュー修正の回帰テスト ========

use polyisa_engine::interp::{Ctrl, InterpExit};

/// trap を期待する実行。例外を返す。
fn run_exc(env: &mut BareEnv, insn: Insn, w: u64, pc: u64) -> InterpExit {
    env.step(|b| sem::exec(b, insn, w, pc)).unwrap_err()
}

#[test]
fn crb_uses_absolute_target() {
    // CRB（RRS）: 分岐先は絶対 D4(B4)。PC 相対ではない。
    let mut e = env();
    e.backend.set(Gpr(5).state(), 7);
    e.backend.set(Gpr(7).state(), 3);
    e.backend.set(Gpr(10).state(), 0x2000);
    // crb %r5,%r7,4,0(%r10) → ec 57 a0 00 40 f6。m=4 は CC1（小）で分岐。
    // 7>3 → CC2 → 分岐しない。
    run(&mut e, Insn::Ec, 0xec57_a000_40f6, 0x1000);
    assert_eq!(e.backend.ctrl, Ctrl::Fallthrough);
    // r5=1 なら CC1 → 分岐。先は b4 レジスタの中身（絶対アドレス）。
    e.backend.set(Gpr(5).state(), 1);
    run(&mut e, Insn::Ec, 0xec57_a000_40f6, 0x1000);
    assert_eq!(e.backend.ctrl, Ctrl::Jump(0x2000));
}

#[test]
fn brxh_increments_by_r3_compares_with_r3p1() {
    // BRXH（RSI）: 増分レジスタは r3、比較値は r3|1。分岐先は pc+i2*2。
    let mut e = env();
    e.backend.set(Gpr(2).state(), 10);
    e.backend.set(Gpr(4).state(), 1);
    e.backend.set(Gpr(5).state(), 20);
    // brxh %r2,%r4,+0x20 → 84 24 00 10。r2 += r4、r2 > r5 で分岐。
    run(&mut e, Insn::Brxh, 0x8424_0010, 0x1000);
    assert_eq!(r(&mut e, 2), 11);
    assert_eq!(e.backend.ctrl, Ctrl::Fallthrough);
    // r5=5 にすれば 12>5 で分岐。
    e.backend.set(Gpr(5).state(), 5);
    run(&mut e, Insn::Brxh, 0x8424_0010, 0x1000);
    assert_eq!(r(&mut e, 2), 12);
    assert_eq!(e.backend.ctrl, Ctrl::Jump(0x1020));
    // 奇数 r3 は増分と比較値が同じレジスタになる。
    e.backend.set(Gpr(3).state(), 0);
    e.backend.set(Gpr(7).state(), 1);
    // brxh %r3,%r7,+0x20 → 84 37 00 10。r3+=r7 → 1、1>1 で分岐しない。
    run(&mut e, Insn::Brxh, 0x8437_0010, 0x2000);
    assert_eq!(r(&mut e, 3), 1);
    assert_eq!(e.backend.ctrl, Ctrl::Fallthrough);
}

#[test]
fn brxhg_relative_64bit() {
    // BRXHG（EC 0x44）: 64 ビット版の BRXH。分岐先は pc+i2*2。
    let mut e = env();
    e.backend.set(Gpr(2).state(), 0x1_0000_0000);
    e.backend.set(Gpr(4).state(), 1);
    e.backend.set(Gpr(5).state(), 2);
    // brxhg %r2,%r4,+0x20 → ec 24 00 10 00 44。64 ビットなので
    // 0x1_0000_0001 > 2 で分岐（32 ビット計算だと 1>2 で取れない）。
    run(&mut e, Insn::Ec, 0xec24_0010_0044, 0x4000);
    assert_eq!(r(&mut e, 2), 0x1_0000_0001);
    assert_eq!(e.backend.ctrl, Ctrl::Jump(0x4020));
}

#[test]
fn bxhg_absolute_target() {
    // BXHG（EB 0x44）: 絶対 D2(B2) 分岐の 64 ビット版。
    let mut e = env();
    e.backend.set(Gpr(2).state(), 10);
    e.backend.set(Gpr(4).state(), 1);
    e.backend.set(Gpr(5).state(), 1);
    e.backend.set(Gpr(10).state(), 0x3000);
    // bxhg %r2,%r4,0(%r10) → eb 24 a0 00 00 44。r2=11 > r5=1 → 分岐。
    run(&mut e, Insn::Eb, 0xeb24_a000_0044, 0x1000);
    assert_eq!(r(&mut e, 2), 11);
    assert_eq!(e.backend.ctrl, Ctrl::Jump(0x3000));
}

#[test]
fn cit_traps_on_own_comparison() {
    // CIT: r1 と i2 を自分で比較し、m3 の条件が合えば trap。
    // 先行する CC の値は参照しない。
    let mut e = env();
    e.backend.set(Gpr(5).state(), 127);
    // cit %r5,127,8 → ec 50 00 7f 80 72。m3=8 は「等しい」で trap。
    // CC=2 を残しても自分の比較で trap する。
    e.backend.set(sem::cc_ref(), 2);
    let err = run_exc(&mut e, Insn::Ec, 0xec50_007f_8072, 0x1000);
    assert!(matches!(err, InterpExit::Exception(_)));
    // r5=126 なら等しくない → 先行 CC が 0 でも trap しない。
    e.backend.set(Gpr(5).state(), 126);
    e.backend.set(sem::cc_ref(), 0);
    run(&mut e, Insn::Ec, 0xec50_007f_8072, 0x1000);
    assert_eq!(e.backend.ctrl, Ctrl::Fallthrough);
}

#[test]
fn crt_traps_on_register_compare() {
    let mut e = env();
    e.backend.set(Gpr(5).state(), 5);
    e.backend.set(Gpr(7).state(), 5);
    // crt %r5,%r7,8 → b9 72 80 57（m3=8: 等しいで trap）。
    let err = run_exc(&mut e, Insn::B9, 0xb972_8057, 0x100);
    assert!(matches!(err, InterpExit::Exception(_)));
    // 不等なら通る。
    e.backend.set(Gpr(7).state(), 6);
    run(&mut e, Insn::B9, 0xb972_8057, 0x100);
    assert_eq!(e.backend.ctrl, Ctrl::Fallthrough);
}

#[test]
fn clgfi_zero_extends_immediate() {
    // CLGFI の I2 は 32 ビットゼロ拡張。
    let mut e = env();
    e.backend.set(Gpr(2).state(), 0x8000_0000);
    // clgfi %r2,0x80000000 → c2 2e 80 00 00 00。等しい → CC0。
    // （符号拡張なら 0xffffffff80000000 との比較で CC1 になる）
    run(&mut e, Insn::Clgfi, 0xc22e_8000_0000, 0x100);
    assert_eq!(cc(&mut e), 0);
}

#[test]
fn flogr_writes_index_and_cleared_source() {
    let mut e = env();
    e.backend.set(Gpr(6).state(), 0x42);
    // flogr %r4,%r6 → b9 83 00 46。
    // r4 = 先頭 1 ビットの位置（0x42 の最上位 bit は bit6 → index 57）、
    // r5 = そのビットを落とした値 = 0x02。CC=2（非ゼロ）。
    run(&mut e, Insn::B9, 0xb983_0046, 0x100);
    assert_eq!(r(&mut e, 4), 57);
    assert_eq!(r(&mut e, 5), 2);
    assert_eq!(cc(&mut e), 2);
    // ゼロ入力: r4=64、r5=0、CC=0。
    e.backend.set(Gpr(6).state(), 0);
    run(&mut e, Insn::B9, 0xb983_0046, 0x108);
    assert_eq!(r(&mut e, 4), 64);
    assert_eq!(r(&mut e, 5), 0);
    assert_eq!(cc(&mut e), 0);
}

#[test]
fn lbr_lhr_preserve_high_half() {
    let mut e = env();
    e.backend.set(Gpr(3).state(), 0xdead_beef_cafe_0000);
    e.backend.set(Gpr(5).state(), 0xff80);
    // lbr %r3,%r5 → b9 26 00 35: 下位 32 ビットだけ更新、上位は保持。
    run(&mut e, Insn::B9, 0xb926_0035, 0x100);
    assert_eq!(r(&mut e, 3), 0xdead_beef_ffff_ff80);
    // lhr %r3,%r5 → b9 27 00 35。
    e.backend.set(Gpr(3).state(), 0xdead_beef_0000_0000);
    run(&mut e, Insn::B9, 0xb927_0035, 0x108);
    assert_eq!(r(&mut e, 3), 0xdead_beef_ffff_ff80);
    // lrvr %r3,%r5 → b9 1f 00 35: バイト反転した下位 32 ビットを書く。
    e.backend.set(Gpr(3).state(), 0xaaaa_0000_0000_0000);
    e.backend.set(Gpr(5).state(), 0x1122_3344);
    run(&mut e, Insn::B9, 0xb91f_0035, 0x110);
    assert_eq!(r(&mut e, 3), 0xaaaa_0000_4433_2211);
}

#[test]
fn mlr_writes_pair_low_halves() {
    let mut e = env();
    // ペア r4/r5 の上位半分が保持されること。
    e.backend.set(Gpr(4).state(), 0xaaaa_1111_0000_0000);
    e.backend.set(Gpr(5).state(), 0xbbbb_2222_0000_0003);
    e.backend.set(Gpr(6).state(), 0x0000_0005);
    // mlr %r4,%r6 → b9 96 00 46: 3*5 = 15。
    // r4 の下位 32 = 0（上位）、r5 の下位 32 = 15（下位）。
    run(&mut e, Insn::B9, 0xb996_0046, 0x100);
    assert_eq!(r(&mut e, 4), 0xaaaa_1111_0000_0000);
    assert_eq!(r(&mut e, 5), 0xbbbb_2222_0000_000f);
}

#[test]
fn shifts_do_not_clobber_cc() {
    let mut e = env();
    e.backend.set(Gpr(4).state(), 0x8000_0000);
    e.backend.set(sem::cc_ref(), 1);
    // sll %r4,7 → 89 40 00 07: CC は変えない。
    run(&mut e, Insn::Sll, 0x8940_0007, 0x100);
    assert_eq!(cc(&mut e), 1);
    // sra %r4,8 → 8a 40 00 08。
    run(&mut e, Insn::Sra, 0x8a40_0008, 0x104);
    assert_eq!(cc(&mut e), 1);
    // srda %r4,8 → 8e 40 00 08（ペアシフト、CC は変えない）。
    e.backend.set(Gpr(4).state(), 0x8000_0000);
    e.backend.set(Gpr(5).state(), 0);
    run(&mut e, Insn::Srda, 0x8e40_0008, 0x108);
    assert_eq!(cc(&mut e), 1);
}

#[test]
fn ts_tests_leftmost_bit() {
    let mut e = env();
    e.backend.mem.map(VirtAddr(0xc000), 1, Perms::RW).unwrap();
    e.backend.mem.write(VirtAddr(0xc010), &[0x01]).unwrap();
    e.backend.set(Gpr(10).state(), 0xc010);
    // ts 0(%r10) → 93 00 a0 00: 最左ビットは 0 → CC0、書き込みは 0xff。
    run(&mut e, Insn::Ts, 0x9300_a000, 0x100);
    assert_eq!(cc(&mut e), 0);
    let mut buf = [0u8; 1];
    e.backend
        .mem
        .read(
            VirtAddr(0xc010),
            &mut buf,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Be,
                align: polyisa_mem::Align::Natural,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(buf, [0xff]);
    // 0x80 を書いて CC1。
    e.backend.mem.write(VirtAddr(0xc010), &[0x80]).unwrap();
    run(&mut e, Insn::Ts, 0x9300_a000, 0x108);
    assert_eq!(cc(&mut e), 1);
}

#[test]
fn icm_cc1_on_leftmost_top_bit() {
    let mut e = env();
    e.backend.mem.map(VirtAddr(0xd000), 1, Perms::RW).unwrap();
    e.backend
        .mem
        .write(VirtAddr(0xd010), &[0x81, 0x00])
        .unwrap();
    e.backend.set(Gpr(10).state(), 0xd010);
    e.backend.set(Gpr(3).state(), 0);
    // icm %r3, 0b0011, 0(%r10) → bf 33 a0 00: byte6,7 に挿入。
    // 左端挿入バイト 0x81 の最上位ビットが 1 → CC1。
    run(&mut e, Insn::Icm, 0xbf33_a000, 0x100);
    assert_eq!(cc(&mut e), 1);
    // 全部ゼロなら CC0。
    e.backend
        .mem
        .write(VirtAddr(0xd010), &[0x00, 0x00])
        .unwrap();
    run(&mut e, Insn::Icm, 0xbf33_a000, 0x108);
    assert_eq!(cc(&mut e), 0);
    // 0x01 なら CC2（非ゼロだが最上位ビットは 0）。
    e.backend
        .mem
        .write(VirtAddr(0xd010), &[0x01, 0x00])
        .unwrap();
    run(&mut e, Insn::Icm, 0xbf33_a000, 0x110);
    assert_eq!(cc(&mut e), 2);
}

#[test]
fn clm_uses_first_difference() {
    let mut e = env();
    e.backend.mem.map(VirtAddr(0xe000), 1, Perms::RW).unwrap();
    e.backend.set(Gpr(3).state(), 0x0000_0000_0000_1234);
    // レジスタの byte6=0x12、byte7=0x34。メモリは先が大・後が小:
    // 最初の差が r<m なら CC1（後の差で上書きされないこと）。
    e.backend
        .mem
        .write(VirtAddr(0xe010), &[0x40, 0x01])
        .unwrap();
    e.backend.set(Gpr(10).state(), 0xe010);
    // clm %r3, 0b0011, 0(%r10) → bd 33 a0 00。
    run(&mut e, Insn::Clm, 0xbd33_a000, 0x100);
    assert_eq!(cc(&mut e), 1);
}

#[test]
fn tmhh_checks_selected_bits_only() {
    let mut e = env();
    e.backend.set(Gpr(7).state(), 0xff00_0000_0000_0000);
    // tmhh %r7,0xf000 → a7 72 f0 00: 上位 16 ビットの 0xf000 部分が
    // 全部 1（0xff00 & 0xf000 = 0xf000）→ CC3。
    run(&mut e, Insn::Tmhh, 0xa772_f000, 0x100);
    assert_eq!(cc(&mut e), 3);
    // 0x00ff なら選択ビットが全部 0 → CC0。
    run(&mut e, Insn::Tmhh, 0xa772_00ff, 0x104);
    assert_eq!(cc(&mut e), 0);
    // 0xffff なら混在（0xff00 & 0xffff = 0xff00 ≠ 0xffff）→ CC1。
    run(&mut e, Insn::Tmhh, 0xa772_ffff, 0x108);
    assert_eq!(cc(&mut e), 1);
}

#[test]
fn nihf_sets_cc() {
    let mut e = env();
    e.backend.set(Gpr(2).state(), 0xffff_ffff_ffff_ffff);
    // nihf %r2,0x80000000 → c0 2a 80 00 00 00: 上位 32 が 0x80000000
    // になって非ゼロ → CC1（PoP の論理 CC は 0/1）。
    run(&mut e, Insn::Nihf, 0xc02a_8000_0000, 0x100);
    assert_eq!(r(&mut e, 2), 0x8000_0000_ffff_ffff);
    assert_eq!(cc(&mut e), 1);
    // 結果ゼロ → CC0。
    e.backend.set(Gpr(2).state(), 0x0000_0000_ffff_ffff);
    run(&mut e, Insn::Nihf, 0xc02a_8000_0000, 0x104);
    assert_eq!(cc(&mut e), 0);
}

#[test]
fn cdbr_nan_gives_cc3() {
    let mut e = env();
    // 静穏 NaN（全 1 指数 + 非ゼロ仮数）。
    e.backend.set(Fpr(1).state(), 0x7ff8_0000_0000_0000);
    e.backend.set(Fpr(2).state(), 0x3ff0_0000_0000_0000);
    // cdbr %f1,%f2 → b3 19 00 12。
    run(&mut e, Insn::B3, 0xb319_0012, 0x100);
    assert_eq!(cc(&mut e), 3);
    // 通常比較は 0/1/2。
    run(&mut e, Insn::B3, 0xb319_0021, 0x104); // cdbr %f2,%f1 → 1.0 vs NaN → CC3
    assert_eq!(cc(&mut e), 3);
    e.backend.set(Fpr(1).state(), 0x4000_0000_0000_0000); // 2.0
    run(&mut e, Insn::B3, 0xb319_0021, 0x108); // cdbr %f2,%f1 → 1.0 < 2.0 → CC1
    assert_eq!(cc(&mut e), 1);
}

#[test]
fn cgdbr_leaves_cc_unchanged() {
    let mut e = env();
    e.backend.set(Fpr(2).state(), 0x4045_0000_0000_0000); // 42.0
    e.backend.set(sem::cc_ref(), 2);
    // cgdbr %r1,5,%f2 → b3 a9 50 12（m3=5: 0 方向丸め）。
    run(&mut e, Insn::B3, 0xb3a9_5012, 0x100);
    assert_eq!(r(&mut e, 1), 42);
    assert_eq!(cc(&mut e), 2); // CC は変えない。
}

#[test]
fn mvst_cc1_r1_at_end_char_r2_unchanged() {
    // PoP: CC1（終端文字を移し終えた）とき R1 = 第 1 オペランド内の
    // 終端文字のアドレス（格納した NUL の位置を指す）、R2 は不変。
    let mut e = env();
    e.backend.mem.map(VirtAddr(0xf000), 1, Perms::RW).unwrap();
    e.backend.mem.write(VirtAddr(0xf100), b"ab\0cd").unwrap();
    e.backend.set(Gpr(0).state(), 0); // 終端文字 = NUL
    e.backend.set(Gpr(4).state(), 0xf200);
    e.backend.set(Gpr(5).state(), 0xf100);
    // mvst %r4,%r5 → b2 55 00 45。"ab\0" をコピーする。
    run(&mut e, Insn::SB2, 0xb255_0045, 0x100);
    assert_eq!(r(&mut e, 4), 0xf202); // 格納した NUL の位置
    assert_eq!(r(&mut e, 5), 0xf100); // R2 は不変
    assert_eq!(cc(&mut e), 1);
    let mut buf = [0u8; 3];
    e.backend
        .mem
        .read(
            VirtAddr(0xf200),
            &mut buf,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Be,
                align: polyisa_mem::Align::Natural,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(&buf, b"ab\0");
}

#[test]
fn mvst_end_char_comes_from_r0() {
    // 終端文字は GR0 下位バイト（ここでは 'c'）。NUL 固定ではない。
    let mut e = env();
    e.backend.mem.map(VirtAddr(0xf000), 1, Perms::RW).unwrap();
    e.backend.mem.write(VirtAddr(0xf100), b"ab\0cd").unwrap();
    e.backend.set(Gpr(0).state(), u64::from(b'c'));
    e.backend.set(Gpr(4).state(), 0xf200);
    e.backend.set(Gpr(5).state(), 0xf100);
    run(&mut e, Insn::SB2, 0xb255_0045, 0x100);
    // 'a','b','\0','c' を移す。'c' が終端 → R1 は 'c' の格納位置。
    assert_eq!(r(&mut e, 4), 0xf203);
    assert_eq!(r(&mut e, 5), 0xf100);
    assert_eq!(cc(&mut e), 1);
    let mut buf = [0u8; 4];
    e.backend
        .mem
        .read(
            VirtAddr(0xf200),
            &mut buf,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Be,
                align: polyisa_mem::Align::Natural,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(&buf, b"ab\0c");
}

#[test]
fn bprp_c5_is_nop() {
    // C5 xx は BPRP（分枝予測ヒント）= no-op。分岐・例外ともしない。
    let mut e = env();
    e.backend.set(Gpr(5).state(), 0x1234);
    run(&mut e, Insn::Bprp, 0xc504_1234_5678, 0x1000);
    assert_eq!(e.backend.ctrl, Ctrl::Fallthrough);
    run(&mut e, Insn::Bprp, 0xc505_ffff_ffff, 0x1000);
    assert_eq!(e.backend.ctrl, Ctrl::Fallthrough);
}

#[test]
fn agf_slg_operate_64bit() {
    let mut e = env();
    e.backend.mem.map(VirtAddr(0xf000), 1, Perms::RW).unwrap();
    e.backend
        .mem
        .write(VirtAddr(0xf810), &0xffff_ffffu32.to_be_bytes())
        .unwrap();
    e.backend.set(Gpr(10).state(), 0xf810);
    e.backend.set(Gpr(5).state(), 0x1_0000_0000);
    // agf %r5,0(%r10) → e3 50 a0 00 00 18: r5 += sext32(mem) = -1。
    run(&mut e, Insn::E3, 0xe350_a000_0018, 0x100);
    assert_eq!(r(&mut e, 5), 0xffff_ffff);
    // slgf %r5,0(%r10) → e3 50 a0 00 00 1b: r5 -= zext32(mem)、
    // 64 ビット演算なので 0x1_0000_0000 - 0xffff_ffff = 1。
    e.backend.set(Gpr(5).state(), 0x1_0000_0000);
    run(&mut e, Insn::E3, 0xe350_a000_001b, 0x104);
    assert_eq!(r(&mut e, 5), 1);
}

#[test]
fn cds_uses_low_halves() {
    let mut e = env();
    e.backend.mem.map(VirtAddr(0xf000), 1, Perms::RW).unwrap();
    // メモリ = {0x11,0x22}（2 語）。
    e.backend
        .mem
        .write(VirtAddr(0xf410), &0x0000_0011_0000_0022u64.to_be_bytes())
        .unwrap();
    e.backend.set(Gpr(10).state(), 0xf410);
    // ペア r4/r5 の下位半分 = {0x11,0x22} → 一致 → mem = r6/r7 下位 = {0x33,0x44}。
    e.backend.set(Gpr(4).state(), 0xaaaa_0000_0000_0011);
    e.backend.set(Gpr(5).state(), 0xbbbb_0000_0000_0022);
    e.backend.set(Gpr(6).state(), 0x0000_0033);
    e.backend.set(Gpr(7).state(), 0x0000_0044);
    // cds %r4,%r6,0(%r10) → bb 46 a0 00。
    run(&mut e, Insn::Cds, 0xbb46_a000, 0x100);
    assert_eq!(cc(&mut e), 0);
    let mut buf = [0u8; 8];
    e.backend
        .mem
        .read(
            VirtAddr(0xf410),
            &mut buf,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Be,
                align: polyisa_mem::Align::Natural,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(buf, 0x0000_0033_0000_0044u64.to_be_bytes());
    // 上位半分は比較対象ではないので、残っていること。
    assert_eq!(r(&mut e, 4), 0xaaaa_0000_0000_0011);
    assert_eq!(r(&mut e, 5), 0xbbbb_0000_0000_0022);
}

#[test]
fn ecag_returns_all_ones() {
    // ECAG: キャッシュ情報がない場合（QEMU と同じ）全 1 を返す。
    let mut e = env();
    // ecag %r4,%r5,8(%r6) → eb 45 60 08 00 4c。
    run(&mut e, Insn::Eb, 0xeb45_6008_004c, 0x100);
    assert_eq!(r(&mut e, 4), u64::MAX);
}

#[test]
fn lpgr_int_min_sets_cc3() {
    let mut e = env();
    e.backend.set(Gpr(5).state(), i64::MIN as u64);
    // lpgr %r4,%r5 → b9 00 00 45: |INT_MIN| はオーバーフローで CC3。
    run(&mut e, Insn::B9, 0xb900_0045, 0x100);
    assert_eq!(r(&mut e, 4), i64::MIN as u64);
    assert_eq!(cc(&mut e), 3);
    // lngfr %r4,%r5 → b9 11 00 45（32 ビット版）。0x80000000 → CC3。
    e.backend.set(Gpr(5).state(), 0xffff_ffff_8000_0000);
    run(&mut e, Insn::B9, 0xb911_0045, 0x104);
    assert_eq!(cc(&mut e), 3);
}

#[test]
fn resolve_execute_modifies_second_byte() {
    // 4 バイト命令の byte1（ビット 16-23）に OR。
    let w = sem::resolve_execute(0xd203_1000, 4, 0x0f);
    assert_eq!(w, 0xd203_1000 | (0x0f << 16));
    // 6 バイト命令の byte1（ビット 32-39）。
    let w = sem::resolve_execute(0xd205_1000_2000, 6, 0xaa);
    assert_eq!(w, 0xd205_1000_2000 | (0xaa << 32));
    // 修飾 0 や長さ不足は無変換。
    assert_eq!(sem::resolve_execute(0x0700, 2, 0), 0x0700);
    // 2 バイト命令の byte1 = 最下位バイト。
    assert_eq!(sem::resolve_execute(0x0700, 2, 0xf0), 0x07f0);
}

#[test]
fn execute_target_rx_and_ril() {
    let regs = |i: u8| match i {
        10 => 0x8000,
        5 => 0x40,
        _ => 0,
    };
    // ex %r2,0(%r10,%r5) → 44 25 a0 00 のつもり（x2=5,b2=10,d=0）。
    // RX: byte1 = r1<<4|x2 = 0x25、byte2-3 = b2<<4|d = 0xa000。
    let (a, r1) = sem::execute_target(Insn::Ex, 0x4425_a000, 0x1000, regs, u64::MAX);
    assert_eq!(a, 0x8040);
    assert_eq!(r1, 2);
    // exrl %r3,+0x40 → c6 30 00 00 00 20: pc + 2*0x20。
    let (a, r1) = sem::execute_target(Insn::Exrl, 0xc630_0000_0020, 0x1000, regs, u64::MAX);
    assert_eq!(a, 0x1040);
    assert_eq!(r1, 3);
    // amask は絶対側だけでなく RIL にも掛ける。
    let (a, _) = sem::execute_target(Insn::Exrl, 0xc630_0000_0020, 0x1000, regs, 0x7fff_ffff);
    assert_eq!(a, 0x1040);
}
