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
    /// 整数レジスタ x0〜x31。RV32 では下位 32 ビットだけを使う。
    pub x: [u64; 32],
    /// プログラムカウンタ。
    pub pc: u64,
    /// CSR ファイル。12 ビットのアドレスで引く。権限検査は後の段階で足す。
    pub csr: [u64; 4096],
}

impl Default for CpuState {
    fn default() -> Self {
        Self {
            x: [0; 32],
            pc: 0,
            csr: [0; 4096],
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
    fn insn_count() {
        // RV64I 53 件＋M 13 件＋CSR 6 件＋A 22 件。
        assert_eq!(INSNS.len(), 94);
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
        assert_eq!(decode(0x0020_b1af, 32), Some(Insn::AmoaddD));
        assert_eq!(decode(0xe020_a1af, 32), Some(Insn::AmomaxuW));
        assert_eq!(decode(0xffff_ffff, 32), None);
        assert_eq!(decode(0x0020_8133, 16), None);
    }
}
