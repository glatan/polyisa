// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! OpenRISC の命令語単位のデコード・エンコード検査（段階20・OR3）。
//! 付録の機械語表に照らして主要形式の語を往復させ、機能旗
//! （fpu / f64a32 / orb64）での語彙ゲートを見る。
//! 出典は SPEC-OPENRISC-1000 付録 "Instruction set listing" である。

use polyisa_guest_openrisc::*;

const BASE: u128 = FEAT_DSLOT;
const FPU: u128 = FEAT_DSLOT | FEAT_FPU;
const F64: u128 = FEAT_DSLOT | FEAT_FPU | FEAT_F64A32;
const ALL: u128 = FEAT_DSLOT | FEAT_FPU | FEAT_F64A32 | FEAT_ORB64;

fn dec(word: u32) -> Option<Insn> {
    decode_model_ex(u128::from(word), 32, false, BASE)
}

fn dec_f(word: u32, feats: u128) -> Option<Insn> {
    decode_model_ex(u128::from(word), 32, false, feats)
}

/// 語を組み立てる。ops は `extract_ops` と同じ順。
fn enc(i: Insn, ops: &[u64]) -> u32 {
    encode(i, ops).unwrap() as u32
}

#[test]
fn decode_branches() {
    // l.j/l.jal/l.bnf/l.bf: 26 ビット変位。
    assert_eq!(dec(enc(Insn::LJ, &[0x12345])), Some(Insn::LJ));
    assert_eq!(dec(enc(Insn::LJal, &[0x12345])), Some(Insn::LJal));
    assert_eq!(dec(enc(Insn::LBnf, &[7])), Some(Insn::LBnf));
    assert_eq!(dec(enc(Insn::LBf, &[7])), Some(Insn::LBf));
    // 機械語表の固定ビット確認: l.j は 0x00000000 + N。
    assert_eq!(enc(Insn::LJ, &[0]), 0x0000_0000);
    assert_eq!(dec(0x0000_0000), Some(Insn::LJ));
    // l.jr/l.jalr: rB 桁。
    assert_eq!(dec(enc(Insn::LJr, &[9])), Some(Insn::LJr));
    assert_eq!(enc(Insn::LJr, &[9]), 0x4400_4800);
    assert_eq!(dec(enc(Insn::LJalr, &[9])), Some(Insn::LJalr));
    // l.adrp: D + 21 ビット。
    assert_eq!(dec(enc(Insn::LAdrp, &[3, 0x1fffff])), Some(Insn::LAdrp));
    assert_eq!(enc(Insn::LAdrp, &[0, 0]), 0x0800_0000);
}

#[test]
fn decode_movhi_macrc() {
    // l.movhi rD,K: bit16=0。l.macrc rD: bit16=1 かつ下位 16 ビット 0。
    let w = enc(Insn::LMovhi, &[11, 0xbeef]);
    assert_eq!(w, 0x1960_beef);
    assert_eq!(dec(w), Some(Insn::LMovhi));
    let m = enc(Insn::LMacrc, &[11]);
    assert_eq!(m, 0x1961_0000);
    assert_eq!(dec(m), Some(Insn::LMacrc));
    // l.nop: 0x15000000 + K。
    assert_eq!(enc(Insn::LNop, &[0]), 0x1500_0000);
    assert_eq!(dec(0x1500_0000), Some(Insn::LNop));
}

#[test]
fn decode_system() {
    assert_eq!(enc(Insn::LSys, &[0]), 0x2000_0000);
    assert_eq!(dec(0x2000_0000), Some(Insn::LSys));
    assert_eq!(enc(Insn::LTrap, &[0]), 0x2100_0000);
    assert_eq!(dec(0x2100_0000), Some(Insn::LTrap));
    assert_eq!(enc(Insn::LMsync, &[]), 0x2200_0000);
    assert_eq!(dec(0x2200_0000), Some(Insn::LMsync));
    assert_eq!(dec(0x2280_0000), Some(Insn::LPsync));
    assert_eq!(dec(0x2300_0000), Some(Insn::LCsync));
    // l.rfe は全ビット未規定。
    assert_eq!(dec(0x2400_0000), Some(Insn::LRfe));
}

#[test]
fn decode_loads_stores() {
    // ロード: D + A + 符号 I。
    assert_eq!(enc(Insn::LLwz, &[3, 1, 0x10]), 0x8461_0010);
    assert_eq!(dec(0x8461_0010), Some(Insn::LLwz));
    for (i, name) in [
        (Insn::LLwz, "lwz"),
        (Insn::LLws, "lws"),
        (Insn::LLbz, "lbz"),
        (Insn::LLbs, "lbs"),
        (Insn::LLhz, "lhz"),
        (Insn::LLhs, "lhs"),
        (Insn::LLwa, "lwa"),
    ] {
        let w = enc(i, &[3, 1, 0x20]);
        assert_eq!(dec(w), Some(i), "{name}");
    }
    // ストア: 分割即値 I = [25:21]|[10:0]。ops は (i, a, b) 順。
    let w = enc(Insn::LSw, &[0x1234, 1, 2]);
    assert_eq!(w & 0xfc00_0000, 0xd400_0000);
    assert_eq!((w >> 21) & 0x1f, 0x1234 >> 11);
    assert_eq!(w & 0x7ff, 0x1234 & 0x7ff);
    assert_eq!(dec(w), Some(Insn::LSw));
    assert_eq!(extract_ops(Insn::LSw, u128::from(w)), vec![0x1234, 1, 2]);
    for i in [Insn::LSwa, Insn::LSb, Insn::LSh] {
        let w = enc(i, &[0x40, 1, 2]);
        assert_eq!(dec(w), Some(i));
    }
}

#[test]
fn decode_immediate_alu() {
    assert_eq!(dec(enc(Insn::LAddi, &[3, 4, 0x8000])), Some(Insn::LAddi));
    assert_eq!(dec(enc(Insn::LAddic, &[3, 4, 1])), Some(Insn::LAddic));
    assert_eq!(dec(enc(Insn::LAndi, &[3, 4, 0xff])), Some(Insn::LAndi));
    assert_eq!(dec(enc(Insn::LOri, &[3, 4, 0xff])), Some(Insn::LOri));
    assert_eq!(dec(enc(Insn::LXori, &[3, 4, 0xff])), Some(Insn::LXori));
    assert_eq!(dec(enc(Insn::LMuli, &[3, 4, 7])), Some(Insn::LMuli));
    // l.ori r3,r0,K が典型的な定数ロード: 0xa8600000 | K。
    assert_eq!(enc(Insn::LOri, &[3, 0, 0x1234]), 0xa860_1234);
}

#[test]
fn decode_shift_imm() {
    for (i, lit) in [
        (Insn::LSlli, 0b00u32),
        (Insn::LSrli, 0b01),
        (Insn::LSrai, 0b10),
        (Insn::LRori, 0b11),
    ] {
        let w = enc(i, &[3, 4, 5]);
        assert_eq!(dec(w), Some(i));
        assert_eq!((w >> 6) & 3, lit);
        assert_eq!(w & 0x3f, 5);
    }
}

#[test]
fn decode_sf_imm() {
    // l.sf*i: [25:21] が条件副演算、rA + 符号 I。ops は (a, i)。
    for (i, f) in [
        (Insn::LSfeqi, 0x00),
        (Insn::LSfnei, 0x01),
        (Insn::LSfgtui, 0x02),
        (Insn::LSfgeui, 0x03),
        (Insn::LSfltui, 0x04),
        (Insn::LSfleui, 0x05),
        (Insn::LSfgtsi, 0x0a),
        (Insn::LSfgesi, 0x0b),
        (Insn::LSfltsi, 0x0c),
        (Insn::LSflesi, 0x0d),
    ] {
        let w = enc(i, &[4, 0x123]);
        assert_eq!(dec(w), Some(i), "fn {f:#x}");
        assert_eq!((w >> 21) & 0x1f, f);
    }
}

#[test]
fn decode_reg_alu() {
    // 3 項演算: D + A + B + 副演算。
    for (i, low) in [
        (Insn::LAdd, 0x00u32),
        (Insn::LAddc, 0x01),
        (Insn::LSub, 0x02),
        (Insn::LAnd, 0x03),
        (Insn::LOr, 0x04),
        (Insn::LXor, 0x05),
        (Insn::LCmov, 0x0e),
    ] {
        let w = enc(i, &[3, 4, 5]);
        assert_eq!(dec(w), Some(i));
        assert_eq!(w & 0xf, low);
    }
    // シフト系: [9:6] が副演算、[3:0]=1000。
    for (i, sub) in [
        (Insn::LSll, 0b0000u32),
        (Insn::LSrl, 0b0001),
        (Insn::LSra, 0b0010),
        (Insn::LRor, 0b0011),
    ] {
        let w = enc(i, &[3, 4, 5]);
        assert_eq!(dec(w), Some(i));
        assert_eq!((w >> 6) & 0xf, sub);
        assert_eq!(w & 0xf, 0x8);
    }
    // 乗除: [9:8]=11。
    for i in [Insn::LMul, Insn::LDiv, Insn::LDivu, Insn::LMulu] {
        assert_eq!(dec(enc(i, &[3, 4, 5])), Some(i));
    }
    // MAC 宛先の muld/muldu は D 桁を持たない。ops は (a, b)。
    assert_eq!(dec(enc(Insn::LMuld, &[4, 5])), Some(Insn::LMuld));
    assert_eq!(dec(enc(Insn::LMuldu, &[4, 5])), Some(Insn::LMuldu));
    // 拡張・探索系。
    for i in [
        Insn::LExths,
        Insn::LExtws,
        Insn::LExtbs,
        Insn::LExtwz,
        Insn::LExthz,
        Insn::LExtbz,
        Insn::LFf1,
        Insn::LFl1,
    ] {
        assert_eq!(dec(enc(i, &[3, 4, 0])), Some(i));
    }
}

#[test]
fn decode_sf_reg() {
    for i in [
        Insn::LSfeq,
        Insn::LSfne,
        Insn::LSfgtu,
        Insn::LSfgeu,
        Insn::LSfltu,
        Insn::LSfleu,
        Insn::LSfgts,
        Insn::LSfges,
        Insn::LSflts,
        Insn::LSfles,
    ] {
        assert_eq!(dec(enc(i, &[4, 5])), Some(i));
    }
    // l.sfeq r3,r4 の語形: 0xe4000000 系。
    assert_eq!(enc(Insn::LSfeq, &[3, 4]) & 0xffe0_0000, 0xe400_0000);
}

#[test]
fn decode_spr_mac() {
    // l.mfspr rD,rA,K。
    assert_eq!(enc(Insn::LMfspr, &[3, 0, 0x11]), 0xb460_0011);
    assert_eq!(dec(0xb460_0011), Some(Insn::LMfspr));
    // l.mtspr rA,rB,K: 分割即値。ops は (a, b, k) 順。
    let w = enc(Insn::LMtspr, &[0, 4, 0x1234]);
    assert_eq!(w & 0xfc00_0000, 0xc000_0000);
    assert_eq!(dec(w), Some(Insn::LMtspr));
    assert_eq!(extract_ops(Insn::LMtspr, u128::from(w)), vec![0, 4, 0x1234]);
    // MAC: ops は (a, b)。
    for i in [Insn::LMac, Insn::LMsb, Insn::LMacu, Insn::LMsbu] {
        assert_eq!(dec(enc(i, &[4, 5])), Some(i));
    }
    assert_eq!(dec(enc(Insn::LMaci, &[4, 0x100])), Some(Insn::LMaci));
}

#[test]
fn decode_custom() {
    for (i, opc) in [
        (Insn::LCust1, 0x1c),
        (Insn::LCust2, 0x1d),
        (Insn::LCust3, 0x1e),
        (Insn::LCust4, 0x1f),
        (Insn::LCust6, 0x3d),
        (Insn::LCust7, 0x3e),
        (Insn::LCust8, 0x3f),
    ] {
        assert_eq!(dec((opc << 26) as u32), Some(i));
    }
    // l.cust5 rD,rA,rB,L,K: ops は (d, a, b, l, k) 順。
    let w = enc(Insn::LCust5, &[1, 2, 3, 4, 5]);
    assert_eq!(dec(w), Some(Insn::LCust5));
    assert_eq!(
        extract_ops(Insn::LCust5, u128::from(w)),
        vec![1, 2, 3, 4, 5]
    );
}

#[test]
fn decode_fp_gated() {
    // fpu なしでは lf.* は解読しない。
    let w = enc(Insn::LfAddS, &[3, 4, 5]);
    assert_eq!(w & 0xff, 0x00);
    assert_eq!(dec(w), None);
    assert_eq!(dec_f(w, FPU), Some(Insn::LfAddS));
    // ORFPX32 の主命令群。
    for i in [
        Insn::LfAddS,
        Insn::LfSubS,
        Insn::LfMulS,
        Insn::LfDivS,
        Insn::LfMaddS,
        Insn::LfSfeqS,
        Insn::LfSfneS,
        Insn::LfSfgtS,
        Insn::LfSfgeS,
        Insn::LfSfltS,
        Insn::LfSfleS,
        Insn::LfSfueqS,
        Insn::LfSfuneS,
        Insn::LfSfugtS,
        Insn::LfSfugeS,
        Insn::LfSfultS,
        Insn::LfSfuleS,
        Insn::LfSfunS,
    ] {
        let w = if matches!(i, Insn::LfAddS | Insn::LfSubS | Insn::LfMulS | Insn::LfDivS) {
            enc(i, &[3, 4, 5])
        } else {
            enc(i, &[4, 5])
        };
        assert_eq!(dec_f(w, FPU), Some(i));
    }
    // itof/ftoi .s: ops は (d, a)。
    assert_eq!(dec_f(enc(Insn::LfItofS, &[3, 4]), FPU), Some(Insn::LfItofS));
    assert_eq!(dec_f(enc(Insn::LfFtoiS, &[3, 4]), FPU), Some(Insn::LfFtoiS));
    // l.lf も fpu ゲート。
    assert_eq!(dec(enc(Insn::LLf, &[3, 1, 0x10])), None);
    assert_eq!(dec_f(enc(Insn::LLf, &[3, 1, 0x10]), FPU), Some(Insn::LLf));
}

#[test]
fn decode_fp64_gated() {
    // lf.*.d は f64a32 ゲート。OO はペアオフセット。
    for i in [
        Insn::LfAddD,
        Insn::LfSubD,
        Insn::LfMulD,
        Insn::LfDivD,
        Insn::LfMaddD,
        Insn::LfSfeqD,
        Insn::LfSfneD,
        Insn::LfSfgtD,
        Insn::LfSfgeD,
        Insn::LfSfltD,
        Insn::LfSfleD,
        Insn::LfSfueqD,
        Insn::LfSfuneD,
        Insn::LfSfugtD,
        Insn::LfSfugeD,
        Insn::LfSfultD,
        Insn::LfSfuleD,
        Insn::LfSfunD,
    ] {
        let w = if matches!(i, Insn::LfAddD | Insn::LfSubD | Insn::LfMulD | Insn::LfDivD) {
            enc(i, &[6, 4, 2, 0])
        } else {
            enc(i, &[4, 2, 0])
        };
        assert_eq!(dec_f(w, FPU), None);
        assert_eq!(dec_f(w, F64), Some(i));
    }
    // stod/dtos: ops は (d, a, oo)。
    assert_eq!(
        dec_f(enc(Insn::LfStodD, &[6, 4, 0]), F64),
        Some(Insn::LfStodD)
    );
    assert_eq!(
        dec_f(enc(Insn::LfDtosD, &[4, 6, 2]), F64),
        Some(Insn::LfDtosD)
    );
    // itof/ftoi .d: ops は (d, a, oo)。
    assert_eq!(
        dec_f(enc(Insn::LfItofD, &[6, 4, 2]), F64),
        Some(Insn::LfItofD)
    );
    assert_eq!(
        dec_f(enc(Insn::LfFtoiD, &[4, 6, 0]), F64),
        Some(Insn::LfFtoiD)
    );
    // l.ld/l.sd は orb64 ゲート（宣言のみの機能）。
    let w = enc(Insn::LLd, &[3, 1, 0x10]);
    assert_eq!(dec(w), None);
    assert_eq!(dec_f(w, ALL), Some(Insn::LLd));
    let w = enc(Insn::LSd, &[0x10, 1, 2]);
    assert_eq!(dec_f(w, ALL), Some(Insn::LSd));
}

#[test]
fn encode_rejects_out_of_range() {
    // 桁溢れはエンコード失敗。
    assert_eq!(encode(Insn::LJ, &[1 << 26]), None);
    assert_eq!(encode(Insn::LMovhi, &[32, 0]), None);
    assert_eq!(encode(Insn::LMovhi, &[0, 1 << 16]), None);
    assert_eq!(encode(Insn::LSw, &[1 << 16, 0, 0]), None);
    // 項数違いも失敗。
    assert_eq!(encode(Insn::LAdd, &[1, 2]), None);
}

#[test]
fn disasm_renders_ops() {
    assert_eq!(
        disasm_word(u128::from(enc(Insn::LJ, &[4])), 32).as_deref(),
        Some("l.j 4")
    );
    assert_eq!(
        disasm_word(u128::from(enc(Insn::LAdd, &[3, 4, 5])), 32).as_deref(),
        Some("l.add r3, r4, r5")
    );
    assert_eq!(
        disasm_word(u128::from(enc(Insn::LAddi, &[3, 4, 0x10])), 32).as_deref(),
        Some("l.addi r3, r4, 16")
    );
    assert_eq!(
        disasm_word(u128::from(enc(Insn::LSw, &[0x20, 1, 2])), 32).as_deref(),
        Some("l.sw 32(r1), r2")
    );
    assert_eq!(
        disasm_word(u128::from(enc(Insn::LMovhi, &[11, 0x1234])), 32).as_deref(),
        Some("l.movhi r11, 4660")
    );
    assert_eq!(
        disasm_word(u128::from(0x2000_0000u32), 32).as_deref(),
        Some("l.sys 0")
    );
}
