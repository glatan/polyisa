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
}
