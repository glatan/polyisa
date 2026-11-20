// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! PA-RISC の命令語単位のデコード検査（段階17・PR3）。
//! 生成デコーダがリテラル語を正しく分類し、arch/MAX 完語で
//! ゲートされることを見る。即値や変位の復元は意味論側なので
//! ここでは命令種別だけを見る。
//! 出典は SPEC-PARISC-11・SPEC-PARISC-20 と QEMU
//! target/hppa/insns.decode である。
//! Ref: SPEC-PARISC-11, SPEC-PARISC-20.

use polyisa_guest_parisc::*;

const ALL: u128 = FEAT_PA11 | FEAT_PA20 | FEAT_MAX1 | FEAT_MAX2;
const PA11: u128 = FEAT_PA11;
const PA11_MAX1: u128 = FEAT_PA11 | FEAT_MAX1;

fn dec(word: u32) -> Option<Insn> {
    decode_model_ex(word as u128, 32, false, ALL)
}

fn decf(word: u32, feats: u128) -> Option<Insn> {
    decode_model_ex(word as u128, 32, false, feats)
}

#[test]
fn decode_core_arith() {
    // add r1,r2,r3（opcode 0x02、pos20-27=011000、d=0）。
    assert_eq!(dec(0x0822_0603), Some(Insn::Add));
    // and/or/xor/uxor/sub/cmpclr（同形式で拡張桁だけが違う）。
    assert_eq!(dec(0x0822_0203), Some(Insn::And));
    assert_eq!(dec(0x0822_0243), Some(Insn::Or));
    assert_eq!(dec(0x0822_0283), Some(Insn::Xor));
    assert_eq!(dec(0x0822_0383), Some(Insn::Uxor));
    assert_eq!(dec(0x0822_0403), Some(Insn::Sub));
    assert_eq!(dec(0x0822_0883), Some(Insn::Cmpclr));
    // add,c は sh=0 固定、0111 + sh!=0 は MAX-1 の hshladd。
    assert_eq!(dec(0x0822_0703), Some(Insn::AddC));
    assert_eq!(dec(0x0822_0743), Some(Insn::Hshladd));
    // MAX-1 半語演算（pos16-25 の拡張桁で区別）。
    assert_eq!(dec(0x0822_03c3), Some(Insn::Hadd));
    assert_eq!(dec(0x0822_02c3), Some(Insn::Havg));
    assert_eq!(dec(0x0822_01c3), Some(Insn::Hsub));
}

#[test]
fn decode_immediates() {
    // ldil L%0x123456,r1 / addil 2,r1 / ldo 4(r2),r3。
    assert_eq!(dec(0x2032_3456), Some(Insn::Ldil));
    assert_eq!(dec(0x2820_0002), Some(Insn::Addil));
    assert_eq!(dec(0x3443_0008), Some(Insn::Ldo));
    // addi 5,r4,r5 と ,tsv / subi / cmpiclr（11 ビット即値形）。
    assert_eq!(dec(0xb485_000a), Some(Insn::Addi));
    assert_eq!(dec(0xb485_080a), Some(Insn::AddiTsv));
    assert_eq!(dec(0x9485_000a), Some(Insn::Subi));
    assert_eq!(dec(0x9085_000a), Some(Insn::Cmpiclr));
}

#[test]
fn decode_memory() {
    // オフセット形式（opcode 0x10-0x1b の 14 ビット + sp）。
    assert_eq!(dec(0x4043_0000), Some(Insn::Ldb));
    assert_eq!(dec(0x4443_0000), Some(Insn::Ldh));
    assert_eq!(dec(0x4843_0000), Some(Insn::Ldw));
    assert_eq!(dec(0x4c43_0000), Some(Insn::Ldwm));
    assert_eq!(dec(0x6862_0000), Some(Insn::Stw));
    assert_eq!(dec(0x6c62_0000), Some(Insn::Stwm));
    // index 形式（opcode 0x03、pos19=0、pos22-25 が完語）。
    assert_eq!(dec(0x0c43_0084), Some(Insn::Ldx));
    assert_eq!(dec(0x0c43_01c4), Some(Insn::Ldcwx));
    // im5 形式（pos19=1）。
    assert_eq!(dec(0x0c43_1084), Some(Insn::Ldi));
    // stby/stdby（pos22-25=1100/1101）。
    assert_eq!(dec(0x0c43_3304), Some(Insn::Stby));
    assert_eq!(dec(0x0c43_3344), Some(Insn::Stdby));
    // FP の index/offset 形。
    assert_eq!(dec(0x2443_0004), Some(Insn::Fldwx));
    assert_eq!(dec(0x2c43_0004), Some(Insn::Flddx));
    assert_eq!(dec(0x5843_0000), Some(Insn::FldwO));
    assert_eq!(dec(0x5c43_0004), Some(Insn::Ldwm2));
    assert_eq!(dec(0x7c62_0004), Some(Insn::Stwm2));
    // PA 2.0 の 64 ビット形（0x14/0x1c、pos30 が 0/1）。
    assert_eq!(dec(0x5043_0000), Some(Insn::Ldd));
    assert_eq!(dec(0x5043_0002), Some(Insn::Fldd));
    assert_eq!(dec(0x7043_0000), Some(Insn::Std));
    assert_eq!(dec(0x7043_0002), Some(Insn::Fstd));
}

#[test]
fn decode_branches() {
    // be/ble（opcode 0x38/0x39）。
    assert_eq!(dec(0xe042_0010), Some(Insn::Be));
    assert_eq!(dec(0xe442_0010), Some(Insn::Ble));
    // bl/gate/bl,push/bl long（pos16-18 が形を分ける）。
    assert_eq!(dec(0xebe0_0008), Some(Insn::Bl));
    assert_eq!(dec(0xebe0_2008), Some(Insn::Gate));
    assert_eq!(dec(0xebe0_8008), Some(Insn::BlPush));
    assert_eq!(dec(0xe800_a010), Some(Insn::BlLong));
    // blr/bv/bve（pos16-18=010/110/111）。
    assert_eq!(dec(0xe849_4000), Some(Insn::Blr));
    assert_eq!(dec(0xe81a_4018), Some(Insn::BlrH));
    assert_eq!(dec(0xe840_c000), Some(Insn::Bv));
    assert_eq!(dec(0xe840_d000), Some(Insn::Bve));
    assert_eq!(dec(0xe840_f000), Some(Insn::BveL));
    // 条件分岐（opcode で系統、pos30 が n）。
    assert_eq!(dec(0x8022_0004), Some(Insn::Cmpb));
    assert_eq!(dec(0x8822_0004), Some(Insn::CmpbF));
    assert_eq!(dec(0x8422_0004), Some(Insn::Cmpbi));
    assert_eq!(dec(0xa022_0004), Some(Insn::Addb));
    assert_eq!(dec(0xc822_0004), Some(Insn::Movb));
    assert_eq!(dec(0xcc22_0004), Some(Insn::Movbi));
    // bb（pos17 の 1 が条件判定ビット選択の固定桁）。
    assert_eq!(dec(0xc005_c000), Some(Insn::BbSar));
    assert_eq!(dec(0xc405_c000), Some(Insn::BbImm));
}

#[test]
fn decode_shift_extract_deposit() {
    // shrp（pos19-21 が SAR/imm/d 形を分ける）。
    assert_eq!(dec(0xd064_0005), Some(Insn::ShrpSar));
    assert_eq!(dec(0xd064_0205), Some(Insn::ShrpSar));
    assert_eq!(dec(0xd064_0805), Some(Insn::ShrpImm));
    assert_eq!(dec(0xd064_0c05), Some(Insn::ShrpImmD));
    // extr（pos19-20=10/11、pos22 が d=1 形の桁）。
    assert_eq!(dec(0xd064_1005), Some(Insn::ExtrSar));
    assert_eq!(dec(0xd064_1205), Some(Insn::ExtrSarD));
    assert_eq!(dec(0xd064_1805), Some(Insn::ExtrImm));
    assert_eq!(dec(0xd864_1805), Some(Insn::ExtrImmD));
    // dep/depi（opcode 0x35/0x3c/0x3d。pos19-20=bits12-11 が
    // SAR/imm/depi を分け、depi_sar は pos22 が d 選択）。
    assert_eq!(dec(0xd464_0005), Some(Insn::DepSar));
    assert_eq!(dec(0xd464_0205), Some(Insn::DepSarD));
    assert_eq!(dec(0xd464_0805), Some(Insn::DepImm));
    assert_eq!(dec(0xf064_1805), Some(Insn::DepImmD));
    assert_eq!(dec(0xd464_1005), Some(Insn::DepiSar));
    assert_eq!(dec(0xd464_1805), Some(Insn::DepiImm));
    assert_eq!(dec(0xf464_1c05), Some(Insn::DepiImmD));
}

#[test]
fn decode_system() {
    // opcode 0x00 の pos19-26 が副 opcode。
    assert_eq!(dec(0x0064_0000), Some(Insn::Break));
    assert_eq!(dec(0x0000_0400), Some(Insn::Sync));
    assert_eq!(dec(0x0004_1820), Some(Insn::Mtsp));
    assert_eq!(dec(0x0084_1840), Some(Insn::Mtctl));
    assert_eq!(dec(0x0004_1860), Some(Insn::Mtsm));
    assert_eq!(dec(0x0000_04a5), Some(Insn::Mfsp));
    assert_eq!(dec(0x0000_08a5), Some(Insn::Mfctl));
    assert_eq!(dec(0x0000_10a5), Some(Insn::Ldsid));
    assert_eq!(dec(0x0000_0e65), Some(Insn::Rsm));
    assert_eq!(dec(0x0000_0d65), Some(Insn::Ssm));
    assert_eq!(dec(0x0000_0c00), Some(Insn::Rfi));
    assert_eq!(dec(0x0000_0ca0), Some(Insn::RfiR));
    assert_eq!(dec(0x1400_0000), Some(Insn::Diag));
    // opcode 0x01 のメモリ管理。
    assert_eq!(dec(0x0440_3280), Some(Insn::Fdc));
    assert_eq!(dec(0x0440_1200), Some(Insn::Pxtlb));
    assert_eq!(dec(0x0440_1340), Some(Insn::Lpa));
}

#[test]
fn decode_fp() {
    // fid と class 0/1/2/3（opcode 0x0c。class 完語は
    // pos16-26＝bits15-5 に埋まる）。
    assert_eq!(dec(0x3000_0000), Some(Insn::FidF));
    assert_eq!(dec(0x3020_4002), Some(Insn::FcpyF));
    assert_eq!(dec(0x3020_4802), Some(Insn::FcpyD));
    assert_eq!(dec(0x3020_0a02), Some(Insn::FcnvDF));
    assert_eq!(dec(0x3022_0400), Some(Insn::FcmpF));
    assert_eq!(dec(0x3000_0420), Some(Insn::Ftest));
    assert_eq!(dec(0x3022_0603), Some(Insn::FaddF));
    // fmt は pos19-20＝bits12-11。
    assert_eq!(dec(0x3022_0e03), Some(Insn::FaddD));
    // fmpyadd/fmpysub（opcode 0x06/0x26、pos26＝bit5 が fmt）。
    assert_eq!(dec(0x1822_0020), Some(Insn::FmpyaddF));
    assert_eq!(dec(0x1822_0000), Some(Insn::FmpyaddD));
    assert_eq!(dec(0x9822_0020), Some(Insn::FmpysubF));
}

#[test]
fn decode_max2() {
    // hshl/mixh/permh（opcode 0x3e、MAX-2）。
    assert_eq!(dec(0xf800_8903), Some(Insn::Hshl));
    assert_eq!(dec(0xf820_8404), Some(Insn::MixhL));
    assert_eq!(dec(0xf822_6644), Some(Insn::Permh));
}

#[test]
fn feature_gates() {
    // PA 2.0 完語は pa20 が無いと解けない。
    for (word, want) in [
        (0x5043_0000, Insn::Ldd),
        (0x0c43_3344, Insn::Stdby),
        (0xe840_d000, Insn::Bve),
        (0xd064_0c05, Insn::ShrpImmD),
        (0x9c22_0004, Insn::CmpbD),
        (0xec22_0004, Insn::CmpbiD),
        (0x0000_14a5, Insn::Mfia),
        (0x0440_0800, Insn::Ixtlbt),
        (0x3020_4002, Insn::FcpyF),
    ] {
        assert_eq!(decf(word, ALL), Some(want), "{word:#x}");
    }
    // これらは PA 1.1 のみでは解けない。
    for word in [
        0x5043_0000u32,
        0x0c43_3344,
        0xe840_d000,
        0xd064_0c05,
        0x9c22_0004,
        0xec22_0004,
        0x0440_0800,
    ] {
        assert_eq!(decf(word, PA11), None, "{word:#x}");
    }
    // mfia と fldw の offset 形は QEMU が pa20 を見ないので非ゲート。
    assert_eq!(decf(0x0000_14a5, PA11), Some(Insn::Mfia));
    assert_eq!(decf(0x5843_0000, PA11), Some(Insn::FldwO));
    // opcode 0x0e の PA 2.0 FP 形。
    assert_eq!(decf(0x3820_4002, ALL), Some(Insn::FcpyFw));
    assert_eq!(decf(0x3820_4002, PA11), None);
    assert_eq!(decf(0x3800_4700, ALL), Some(Insn::Xmpyu));
    assert_eq!(decf(0x3800_4700, PA11), None);
    // MAX-1 は max1、MAX-2 は max2 が要る。
    assert_eq!(decf(0x0822_03c3, PA11_MAX1), Some(Insn::Hadd));
    assert_eq!(decf(0x0822_03c3, PA11), None);
    assert_eq!(decf(0xf800_8903, ALL), Some(Insn::Hshl));
    assert_eq!(decf(0xf800_8903, PA11_MAX1), None);
    // PA1.x 専用の ixtlbx は pa20 機では解けない（ixtlbt は
    // 別の固定桁を持つのでフォールスルーしない）。
    assert_eq!(decf(0x0440_1000, PA11), Some(Insn::IxtlbxD));
    assert_eq!(decf(0x0440_1000, ALL), None);
    // 未定義語は落ちる。
    assert_eq!(dec(0xffff_ffff), None);
}

#[test]
fn extract_operands_regression() {
    // hshr の r は pos6-10（bits25-21）。hshl とは桁が違う。
    // hshr,s r9,4,r7。
    let w = 0xf920_cd07;
    assert_eq!(dec(w), Some(Insn::HshrS));
    assert_eq!(extract_ops(Insn::HshrS, w as u128), vec![9, 4, 7]);
    // 分岐変位は bit0（pos31）の符号素材まで届く。取出し値は
    // bits12-2<<1 | bit0。be で符号ビットを立てた形。
    let w = 0xe020_0555;
    assert_eq!(dec(w), Some(Insn::Be));
    let ops = extract_ops(Insn::Be, w as u128);
    assert_eq!(ops[3], 0x2ab);
    assert_eq!(ops[4], 0);
    // _s 形の sp は assemble_sr3x＝bits15-13 の 3 ビット
    // （sp2 なら上位 2 ビットしか取れない）。
    let w = 0x0422_a220;
    assert_eq!(decf(w, PA11), Some(Insn::PxtlbS));
    assert_eq!(extract_ops(Insn::PxtlbS, w as u128), vec![1, 2, 5, 1]);
    let w = 0x0464_c040;
    assert_eq!(decf(w, PA11), Some(Insn::IxtlbxI));
    assert_eq!(extract_ops(Insn::IxtlbxI, w as u128), vec![3, 4, 6, 1]);
}
