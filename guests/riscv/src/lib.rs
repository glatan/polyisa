//! RISC-V のゲスト ISA。ISADL 記述は参照資料の確認後に `spec/` に書く。
//!
//! ここではクレートの殻と CPU 状態の形だけを提供する。

#![forbid(unsafe_code)]

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
#[derive(Clone, Debug, Default)]
pub struct CpuState {
    /// 整数レジスタ x0〜x31。RV32 では下位 32 ビットだけを使う。
    pub x: [u64; 32],
    /// プログラムカウンタ。
    pub pc: u64,
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
    }

    #[test]
    fn insn_count() {
        // RV32I 共通 37 件のうちシフト 3 件を RV64 版で置換し、RV64 専用 12 件と SYSTEM 4 件を足す。
        assert_eq!(INSNS.len(), 53);
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
        assert_eq!(decode(0xffff_ffff, 32), None);
        assert_eq!(decode(0x0020_8133, 16), None);
    }
}
