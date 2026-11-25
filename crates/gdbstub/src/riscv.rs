// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! rv64 のレジスタ表とターゲット記述（target.xml）の生成。
//!
//! `g` パケットの順序は x0–x31、pc、f0–f31、fcsr とし、機能は
//! `org.gnu.gdb.riscv.cpu` と `org.gnu.gdb.riscv.fpu` に分ける。
//! 表は ISADL のレジスタ記述生成の代用としてここに手書きする。
// Gap: GAP-0023 — レジスタ記述を ISADL から生成するまでの手書き表。

/// 1 レジスタの記述。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RegDesc {
    /// GDB のレジスタ名。
    pub name: &'static str,
    /// 幅（ビット）。
    pub bits: u16,
    /// 所属する機能名。
    pub feature: &'static str,
}

/// 整数系の機能名。
pub const CPU_FEATURE: &str = "org.gnu.gdb.riscv.cpu";
/// 浮動小数点系の機能名。
pub const FPU_FEATURE: &str = "org.gnu.gdb.riscv.fpu";

const fn cpu(name: &'static str) -> RegDesc {
    RegDesc {
        name,
        bits: 64,
        feature: CPU_FEATURE,
    }
}

const fn fpu(name: &'static str) -> RegDesc {
    RegDesc {
        name,
        bits: 64,
        feature: FPU_FEATURE,
    }
}

/// rv64 の `g` の順序のレジスタ表。pc は 33 個目（番号 32）。
pub const RISCV64_REGS: &[RegDesc] = &[
    cpu("x0"),
    cpu("x1"),
    cpu("x2"),
    cpu("x3"),
    cpu("x4"),
    cpu("x5"),
    cpu("x6"),
    cpu("x7"),
    cpu("x8"),
    cpu("x9"),
    cpu("x10"),
    cpu("x11"),
    cpu("x12"),
    cpu("x13"),
    cpu("x14"),
    cpu("x15"),
    cpu("x16"),
    cpu("x17"),
    cpu("x18"),
    cpu("x19"),
    cpu("x20"),
    cpu("x21"),
    cpu("x22"),
    cpu("x23"),
    cpu("x24"),
    cpu("x25"),
    cpu("x26"),
    cpu("x27"),
    cpu("x28"),
    cpu("x29"),
    cpu("x30"),
    cpu("x31"),
    cpu("pc"),
    fpu("f0"),
    fpu("f1"),
    fpu("f2"),
    fpu("f3"),
    fpu("f4"),
    fpu("f5"),
    fpu("f6"),
    fpu("f7"),
    fpu("f8"),
    fpu("f9"),
    fpu("f10"),
    fpu("f11"),
    fpu("f12"),
    fpu("f13"),
    fpu("f14"),
    fpu("f15"),
    fpu("f16"),
    fpu("f17"),
    fpu("f18"),
    fpu("f19"),
    fpu("f20"),
    fpu("f21"),
    fpu("f22"),
    fpu("f23"),
    fpu("f24"),
    fpu("f25"),
    fpu("f26"),
    fpu("f27"),
    fpu("f28"),
    fpu("f29"),
    fpu("f30"),
    fpu("f31"),
    RegDesc {
        name: "fcsr",
        bits: 32,
        feature: FPU_FEATURE,
    },
];

/// `regs` からターゲット記述を組み立てる。機能は出現順にまとめ、
/// regnum は `regs` の位置を使う。Ref: SPEC-GDB-RSP.
#[must_use]
pub fn target_xml(regs: &[RegDesc]) -> String {
    let mut s = String::from(
        "<?xml version=\"1.0\"?><!DOCTYPE target SYSTEM \"gdb-target.dtd\">\
         <target version=\"1.0\"><architecture>riscv:rv64</architecture>",
    );
    let mut open = "";
    for (i, r) in regs.iter().enumerate() {
        if r.feature != open {
            if !open.is_empty() {
                s.push_str("</feature>");
            }
            open = r.feature;
            s.push_str("<feature name=\"");
            s.push_str(open);
            s.push_str("\">");
        }
        let ty = if r.name == "pc" {
            "code_ptr"
        } else if r.feature == FPU_FEATURE && r.bits == 64 {
            "ieee_double"
        } else {
            "int"
        };
        s.push_str(&format!(
            "<reg name=\"{}\" bitsize=\"{}\" regnum=\"{i}\" type=\"{ty}\"/>",
            r.name, r.bits
        ));
    }
    if !open.is_empty() {
        s.push_str("</feature>");
    }
    s.push_str("</target>");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reg_order_and_numbers() {
        assert_eq!(RISCV64_REGS.len(), 66);
        assert_eq!(RISCV64_REGS[0].name, "x0");
        assert_eq!(RISCV64_REGS[31].name, "x31");
        assert_eq!(RISCV64_REGS[32].name, "pc");
        assert_eq!(RISCV64_REGS[32].feature, CPU_FEATURE);
        assert_eq!(RISCV64_REGS[33].name, "f0");
        assert_eq!(RISCV64_REGS[64].name, "f31");
        assert_eq!(RISCV64_REGS[65].name, "fcsr");
        assert_eq!(RISCV64_REGS[65].bits, 32);
        assert_eq!(RISCV64_REGS[65].feature, FPU_FEATURE);
    }

    #[test]
    fn target_xml_groups_features() {
        let xml = target_xml(RISCV64_REGS);
        assert!(xml.contains("<architecture>riscv:rv64</architecture>"));
        let cpu = xml
            .find("<feature name=\"org.gnu.gdb.riscv.cpu\">")
            .unwrap();
        let fpu = xml
            .find("<feature name=\"org.gnu.gdb.riscv.fpu\">")
            .unwrap();
        assert!(cpu < fpu);
        assert!(xml.contains("<reg name=\"x0\" bitsize=\"64\" regnum=\"0\""));
        assert!(xml.contains("<reg name=\"pc\" bitsize=\"64\" regnum=\"32\" type=\"code_ptr\"/>"));
        assert!(xml.contains("regnum=\"33\""));
        assert!(xml.contains("<reg name=\"fcsr\" bitsize=\"32\" regnum=\"65\""));
        assert_eq!(xml.matches("</feature>").count(), 2);
        assert!(xml.ends_with("</target>"));
    }

    #[test]
    fn target_xml_keeps_feature_order() {
        let regs = [
            RegDesc {
                name: "a",
                bits: 8,
                feature: "f1",
            },
            RegDesc {
                name: "b",
                bits: 8,
                feature: "f2",
            },
        ];
        let xml = target_xml(&regs);
        assert!(xml.contains("<feature name=\"f1\"><reg name=\"a\" bitsize=\"8\" regnum=\"0\""));
        assert!(xml.contains("<feature name=\"f2\"><reg name=\"b\" bitsize=\"8\" regnum=\"1\""));
    }
}
