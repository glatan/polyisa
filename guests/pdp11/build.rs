// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! PDP-11 の ISADL 記述。出典は SPEC-PDP11-ARCH83 ほかである。

// Ref: SPEC-PDP11-ARCH83.
include!("spec/pdp11.rs");

fn main() {
    println!("cargo::rerun-if-changed=spec/");
    println!("cargo::rerun-if-changed=build.rs");
    let model = build_model();
    // 命令語は 16 ビット固定。指定子が消費する拡張語は命令語に
    // 含まれない（PD3 の指定子評価器が読む）。
    for insn in &model.insns {
        assert!(insn.pattern.len() == 16, "{}", insn.name);
    }
    let report = polyisa_isadl::validate(&model);
    assert!(
        report.errors.is_empty(),
        "invalid PDP-11 model: {:?}",
        report.errors
    );
    let generated = polyisa_isagen::generate(&model).expect("valid PDP-11 model");
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let mut all = String::new();
    for part in [
        &generated.insn_type,
        &generated.decoder,
        &generated.disassembler,
        &generated.encoder,
        &generated.operands,
        &generated.metadata,
        &generated.map_decoder,
    ] {
        all.push_str(part);
        all.push('\n');
    }
    std::fs::write(out.join("generated.rs"), all).expect("write generated.rs");
}
