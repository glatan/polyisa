//! RISC-V のゲスト ISA。ISADL 記述は参照資料の確認後に `spec/` に書く。
//!
//! ここではクレートの殻と CPU 状態の形だけを提供する。

#![forbid(unsafe_code)]

pub mod sem;

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
        assert_eq!(INSNS.len(), 196);
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
        assert_eq!(decode(0x0000_100f, 32), Some(Insn::FenceI));
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
}
