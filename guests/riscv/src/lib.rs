// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! RISC-V のゲスト ISA。ISADL 記述は参照資料の確認後に `spec/` に書く。
//!
//! ここではクレートの殻と CPU 状態の形だけを提供する。

#![forbid(unsafe_code)]

pub mod sem;
pub mod timing;

// 空のモデルから生成した殻。ISADL 記述の追加後に中身が増える。
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// RISC-V の ISA ファミリ名。
pub struct Riscv;

impl polyisa_guest::GuestIsa for Riscv {
    fn family() -> &'static str {
        "riscv"
    }
}

/// CPU 状態。`#[repr(C)]` で配置を固定し、`StateRef` はここを指す。
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CpuState {
    /// 整数レジスタ x0〜x31。RV32 では下位 32 ビットに符号拡張した値を置く
    ///（W 接尾辞の書き戻しと同じ約束）。読み出しは下位 32 ビットを使う。
    pub x: [u64; 32],
    /// プログラムカウンタ。
    pub pc: u64,
    /// CSR ファイル。12 ビットのアドレスで引く。
    pub csr: [u64; 4096],
    /// 浮動小数点レジスタ f0〜f31。単精度の値は NaN ボックスして入れる。
    pub f: [u64; 32],
    /// 現在の特権レベル（0=U、1=S、3=M）。CSR の権限検査に使う。
    /// 裸実行の初期値は 0（U）であり、M モードのテストハーネスは明示的に 3 を置く。
    pub priv_level: u64,
}

impl Default for CpuState {
    fn default() -> Self {
        Self {
            x: [0; 32],
            pc: 0,
            csr: [0; 4096],
            f: [0; 32],
            priv_level: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_guest::GuestIsa;

    #[test]
    fn family_name() {
        assert_eq!(Riscv::family(), "riscv");
    }

    #[test]
    fn x0_is_first() {
        let s = CpuState::default();
        assert_eq!(s.x[0], 0);
        assert_eq!(core::mem::offset_of!(CpuState, pc), 32 * 8);
        assert_eq!(core::mem::offset_of!(CpuState, csr), 32 * 8 + 8);
    }

    #[test]
    fn state_layout_pinned() {
        // sem.rs の StateRef と runner の offset_of が依存する配置を固定する。
        // 末尾への追加は許すが、既存項目の移動は許さない。
        assert_eq!(core::mem::offset_of!(CpuState, x), 0);
        assert_eq!(core::mem::offset_of!(CpuState, pc), 32 * 8);
        assert_eq!(core::mem::offset_of!(CpuState, csr), 32 * 8 + 8);
        assert_eq!(core::mem::offset_of!(CpuState, f), 32 * 8 + 8 + 4096 * 8);
        assert_eq!(
            core::mem::offset_of!(CpuState, priv_level),
            32 * 8 + 8 + 4096 * 8 + 32 * 8
        );
    }

    #[test]
    fn insn_count() {
        // RV64I 53 件＋M 13 件＋CSR 6 件＋A 22 件＋F 26 件＋D 28 件＋C 40 件＋FMA 8 件。
        assert_eq!(INSNS.len(), 293);
    }

    #[test]
    fn operands_r_fields() {
        // add x1,x2,x3 = 0x003100b3。Ref: SPEC-RISCV-UNPRIV。
        let o = ops_r(0x0031_00b3);
        assert_eq!((o.rd, o.rs1, o.rs2), (1, 2, 3));
    }

    #[test]
    fn cpu_models() {
        // 汎用CPUモデルと機能集合。RVA相当のRV64GCを汎用とする。
        assert!(FEATURES.contains(&"rv64"));
        assert!(FEATURES.contains(&"c"));
        assert!(FEATURES.contains(&"zicsr"));
        assert!(MODELS.contains(&"rv64gc"));
    }

    #[test]
    fn decode_spot_checks() {
        // 命令語はビット配置から手で組み立てる（ Ref: SPEC-RISCV-UNPRIV）。
        assert_eq!(decode(0x0020_8133, 32), Some(Insn::Add));
        assert_eq!(decode(0x4020_8133, 32), Some(Insn::Sub));
        assert_eq!(decode(0x0001_2183, 32), Some(Insn::Lw));
        assert_eq!(decode(0x0080_b183, 32), Some(Insn::Ld));
        assert_eq!(decode(0x0051_819b, 32), Some(Insn::Addiw));
        assert_eq!(decode(0x0000_00ef, 32), Some(Insn::Jal));
        assert_eq!(decode(0x0020_8063, 32), Some(Insn::Beq));
        assert_eq!(decode(0x0000_0073, 32), Some(Insn::Ecall));
        assert_eq!(decode(0x0ff0_000f, 32), Some(Insn::Fence));
        assert_eq!(decode(0x8330_000f, 32), Some(Insn::Fence)); // fence.tso
        assert_eq!(decode(0x0000_000f, 32), Some(Insn::Fence)); // fence 0,0（ヒント）
        assert_eq!(decode(0x0331_000f, 32), Some(Insn::Fence)); // rs1 非ゼロの予約形
        assert_eq!(decode(0x0000_100f, 32), Some(Insn::FenceI));
        assert_eq!(decode(0x0001_100f, 32), Some(Insn::FenceI)); // rs1 非ゼロの予約形
        assert_eq!(decode(0x0220_80b3, 32), Some(Insn::Mul));
        assert_eq!(decode(0x0220_c4b3, 32), Some(Insn::Div));
        assert_eq!(decode(0x0220_f4bb, 32), Some(Insn::Remuw));
        assert_eq!(decode(0xc001_10f3, 32), Some(Insn::Csrrw));
        assert_eq!(decode(0xc010_21f3, 32), Some(Insn::Csrrs));
        assert_eq!(decode(0x1000_a12f, 32), Some(Insn::LrW));
        assert_eq!(decode(0x1820_b1af, 32), Some(Insn::ScD));
        assert_eq!(decode(0x0000_a187, 32), Some(Insn::Flw));
        assert_eq!(decode(0x0020_f1d3, 32), Some(Insn::FaddS));
        assert_eq!(decode(0xa031_20d3, 32), Some(Insn::FeqS));
        assert_eq!(decode(0x0020_b1af, 32), Some(Insn::AmoaddD));
        assert_eq!(decode(0xe020_a1af, 32), Some(Insn::AmomaxuW));
        assert_eq!(decode(0x0000_b187, 32), Some(Insn::Fld));
        assert_eq!(decode(0x0220_f1d3, 32), Some(Insn::FaddD));
        assert_eq!(decode(0xf200_81d3, 32), Some(Insn::FmvDX));
        assert_eq!(decode(0xd200_f1d3, 32), Some(Insn::FcvtDW));
        assert_eq!(decode(0x0820_f1c3, 32), Some(Insn::FmaddS));
        assert_eq!(decode(0x0a20_f1c3, 32), Some(Insn::FmaddD));
        assert_eq!(decode(0x0000, 16), Some(Insn::CAddi4spn));
        assert_eq!(decode(0x2000, 16), Some(Insn::CFld));
        assert_eq!(decode(0x8001, 16), Some(Insn::CSrli));
        assert_eq!(decode(0x8401, 16), Some(Insn::CSrai));
        assert_eq!(decode(0x8c21, 16), Some(Insn::CXor));
        assert_eq!(decode(0x9c01, 16), Some(Insn::CSubw));
        assert_eq!(decode(0x8082, 16), Some(Insn::CJr));
        assert_eq!(decode(0x810e, 16), Some(Insn::CMv));
        assert_eq!(decode(0x9082, 16), Some(Insn::CJalr));
        assert_eq!(decode(0x910a, 16), Some(Insn::CAdd));
        assert_eq!(decode(0x9012, 16), Some(Insn::CAdd)); // rd=x0 の HINT
        assert_eq!(decode(0x806a, 16), Some(Insn::CMv)); // rd=x0 の HINT
        assert_eq!(decode(0x9161, 16), Some(Insn::CSrli)); // RV64 の shamt[5]
        assert_eq!(decode(0x9002, 16), Some(Insn::CEbreak));
        assert_eq!(decode(0x8002, 16), None);
        // 既定は RV64：c_flw と同符号化の c_ld が先に一致する。
        assert_eq!(decode(0x6000, 16), Some(Insn::CLd));
        assert_eq!(decode(0x6001, 16), Some(Insn::CLuiAddi16sp));
        assert_eq!(decode(0xa000, 16), Some(Insn::CFsd));
        assert_eq!(decode(0x4000, 16), Some(Insn::CLw));
        assert_eq!(decode(0x0001, 16), Some(Insn::CAddi));
        assert_eq!(decode(0xa001, 16), Some(Insn::CJ));
        assert_eq!(decode(0x0002, 16), Some(Insn::CSlli));
        assert_eq!(decode(0x6002, 16), Some(Insn::CLdsp));
        assert_eq!(decode(0xffff_ffff, 32), None);
        assert_eq!(decode(0x0020_8133, 16), None);
    }

    #[test]
    fn decode_model_resolves_rv32_overlap() {
        // モデル対応デコード（ADR-0006）。RV32/RV64 で符号化が重なる
        // 5 通りは、`when` の述語で振り分ける。
        // Ref: SPEC-RISCV-UNPRIV (20250508) §C.
        // c.jal / c.addiw。
        assert_eq!(decode_model(0x2001, 16, true), Some(Insn::CAddiw));
        assert_eq!(decode_model(0x2001, 16, false), Some(Insn::CJal));
        // c.flw / c.ld。
        assert_eq!(decode_model(0x6000, 16, true), Some(Insn::CLd));
        assert_eq!(decode_model(0x6000, 16, false), Some(Insn::CFlw));
        // c.fsw / c.sd。
        assert_eq!(decode_model(0xe000, 16, true), Some(Insn::CSd));
        assert_eq!(decode_model(0xe000, 16, false), Some(Insn::CFsw));
        // c.flwsp / c.ldsp。
        assert_eq!(decode_model(0x6002, 16, true), Some(Insn::CLdsp));
        assert_eq!(decode_model(0x6002, 16, false), Some(Insn::CFlwsp));
        // c.fswsp / c.sdsp。
        assert_eq!(decode_model(0xe002, 16, true), Some(Insn::CSdsp));
        assert_eq!(decode_model(0xe002, 16, false), Some(Insn::CFswsp));
        // 重ならない命令は XLEN によらず同じ。
        assert_eq!(decode_model(0x0000, 16, true), Some(Insn::CAddi4spn));
        assert_eq!(decode_model(0x0000, 16, false), Some(Insn::CAddi4spn));
        assert_eq!(decode_model(0x8002, 16, true), None);
        assert_eq!(decode_model(0x8002, 16, false), None);
    }

    #[test]
    fn encode_spot_checks() {
        // add x1,x2,x3 = 0x003100b3。Ref: SPEC-RISCV-UNPRIV。
        assert_eq!(encode(Insn::Add, &[1, 2, 3]), Some(0x0031_00b3));
        // 範囲外・個数違い・固定ビットとの衝突は None。
        assert_eq!(encode(Insn::Add, &[1, 2, 32]), None);
        assert_eq!(encode(Insn::Add, &[1, 2]), None);
        // fence は fm/pred/succ の一般形を持ち、0,0 はヒントとして有効。
        assert_eq!(encode(Insn::Fence, &[0, 0, 0x0ff]), Some(0x0ff0_000f));
        assert_eq!(encode(Insn::Fence, &[0, 0, 0]), Some(0x0000_000f));
        // addi x1,x2,3 = 0x00310093。Ref: SPEC-RISCV-UNPRIV。
        assert_eq!(encode(Insn::Addi, &[1, 2, 3]), Some(0x0031_0093));
        // beq x1,x2,8: imm[12|11|10:5|4:1|0] = 0|0|000000|0100|0。
        assert_eq!(encode(Insn::Beq, &[1, 2, 8]), Some(0x0020_8463));
    }

    #[test]
    fn encode_decode_roundtrip() {
        // 生成した往復表の全件を、生成した encode/decode/抽出で確かめる。
        for (insn, ops, len, is_rv64, feats) in ENCODE_ROUNDTRIP {
            let word = encode(*insn, ops).unwrap_or_else(|| {
                panic!("encode failed: {insn:?} {ops:?}");
            });
            let got = decode_model_ex(word, *len, *is_rv64, *feats);
            assert_eq!(got, Some(*insn), "decode {word:#x} for {insn:?}");
            assert_eq!(
                &extract_ops(*insn, word)[..],
                &ops[..],
                "ops mismatch for {insn:?} {word:#x}"
            );
        }
        // 採取できなかった命令があれば表の意味が薄れるので、現状は
        // 空を要求する（Hook 型のオペランドを持つ形式が増えたら見直す）。
        assert!(ENCODE_SKIPPED.is_empty(), "{:?}", ENCODE_SKIPPED);
    }

    #[test]
    fn feature_gates_extension_decode() {
        // 基本整数は rv64i でデコードできるが、M/A/F/C/CSR/Zifencei は
        // それぞれの機能を持たないモデルでは不正命令になる。
        let rv64i = model_feats("rv64i");
        assert_eq!(
            decode_model_ex(0x0020_8133, 32, true, rv64i),
            Some(Insn::Add)
        );
        assert_eq!(
            decode_model_ex(0x0ff0_000f, 32, true, rv64i),
            Some(Insn::Fence)
        );
        assert_eq!(
            decode_model_ex(0x0000_0073, 32, true, rv64i),
            Some(Insn::Ecall)
        );
        assert_eq!(decode_model_ex(0x0220_80b3, 32, true, rv64i), None); // mul
        assert_eq!(decode_model_ex(0x1000_a12f, 32, true, rv64i), None); // lr.w
        assert_eq!(decode_model_ex(0x0020_f1d3, 32, true, rv64i), None); // fadd.s
        assert_eq!(decode_model_ex(0xc001_10f3, 32, true, rv64i), None); // csrrw
        assert_eq!(decode_model_ex(0x0000_100f, 32, true, rv64i), None); // fence.i
        assert_eq!(decode_model_ex(0x0001, 16, true, rv64i), None); // c.addi

        let rv64im = model_feats("rv64im");
        assert_eq!(
            decode_model_ex(0x0220_80b3, 32, true, rv64im),
            Some(Insn::Mul)
        );
        assert_eq!(decode_model_ex(0x1000_a12f, 32, true, rv64im), None);

        // rv64imac は f/d を外すが M/A/C と CSR 類は使える。
        let imac = model_feats("rv64imac");
        assert_eq!(
            decode_model_ex(0x1000_a12f, 32, true, imac),
            Some(Insn::LrW)
        );
        assert_eq!(decode_model_ex(0x0001, 16, true, imac), Some(Insn::CAddi));
        assert_eq!(
            decode_model_ex(0xc001_10f3, 32, true, imac),
            Some(Insn::Csrrw)
        );
        assert_eq!(decode_model_ex(0x0020_f1d3, 32, true, imac), None);
        assert_eq!(decode_model_ex(0x0220_f1d3, 32, true, imac), None);

        let gc = model_feats("rv64gc");
        assert_eq!(
            decode_model_ex(0x0020_f1d3, 32, true, gc),
            Some(Insn::FaddS)
        );
        assert_eq!(
            decode_model_ex(0x0220_f1d3, 32, true, gc),
            Some(Insn::FaddD)
        );

        // D なしで F だけを足した構成では、倍精度から整数への
        // 変換もデコードしない（誤って F 側へ分類しない）。
        let f_only = model_feats("rv64imac") | FEAT_F;
        assert_eq!(decode_model_ex(0xd200_81d3, 32, true, f_only), None);
    }

    #[test]
    fn feature_gates_rv32_compressed_and_rv64_float_moves() {
        // RV32GC では c.flw/c.fsw 側へ振り分け、RV64 限定の
        // fmv.x.d/fmv.d.x は不正命令になる。
        let rv32gc = model_feats("rv32gc");
        assert_eq!(decode_model_ex(0x6000, 16, false, rv32gc), Some(Insn::CFlw));
        assert_eq!(decode_model_ex(0xe000, 16, false, rv32gc), Some(Insn::CFsw));
        assert_eq!(decode_model_ex(0xf200_81d3, 32, false, rv32gc), None);

        let rv64gc = model_feats("rv64gc");
        assert_eq!(decode_model_ex(0x6000, 16, true, rv64gc), Some(Insn::CLd));
        assert_eq!(
            decode_model_ex(0xf200_81d3, 32, true, rv64gc),
            Some(Insn::FmvDX)
        );
    }

    #[test]
    fn disasm_word_fills_operands() {
        // 生成したエンコーダで組み立てた語をそのまま逆アセンブルする。
        let w = encode(Insn::Add, &[1, 2, 3]).unwrap();
        assert_eq!(disasm_word(w, 32).as_deref(), Some("add x1, x2, x3"));
        let w = encode(Insn::Addi, &[5, 6, 7]).unwrap();
        assert_eq!(disasm_word(w, 32).as_deref(), Some("addi x5, x6, 7"));
        let w = encode(Insn::Beq, &[1, 2, 8]).unwrap();
        assert_eq!(disasm_word(w, 32).as_deref(), Some("beq x1, x2, 8"));
        let w = encode(Insn::Sw, &[2, 3, 12]).unwrap();
        assert_eq!(disasm_word(w, 32).as_deref(), Some("sw x3, 12(x2)"));
        let w = encode(Insn::Csrrw, &[1, 0x300, 2]).unwrap();
        assert_eq!(disasm_word(w, 32).as_deref(), Some("csrrw x1, 768, x2"));
        // 命令語のない列は None。穴のない構文はそのまま返る。
        assert_eq!(disasm_word(0xffff_ffff, 32), None);
        assert_eq!(disasm_word(0x0000_0073, 32).as_deref(), Some("ecall"));
    }
}
