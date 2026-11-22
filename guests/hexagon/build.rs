// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Hexagon の ISADL 記述。主正本は SPEC-HEXAGON-PRM V79
//! （80-N2040-60 Rev AB）、版差は SPEC-HEXAGON-PRM-PREV 群。

// Ref: SPEC-HEXAGON-PRM (V79), SPEC-HEXAGON-PRM-PREV.
include!("spec/hexagon.rs");

fn main() {
    println!("cargo::rerun-if-changed=spec/");
    println!("cargo::rerun-if-changed=build.rs");
    let model = build_model();
    // 命令語は 32 ビット。duplex・constant extender も 1 語。
    for insn in &model.insns {
        assert!(insn.pattern.len() == 32, "{}", insn.name);
    }
    let report = polyisa_isadl::validate(&model);
    assert!(
        report.errors.is_empty(),
        "invalid Hexagon model: {:?}",
        report.errors
    );
    let generated = polyisa_isagen::generate(&model).expect("valid Hexagon model");
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let mut all = String::new();
    for part in [
        &generated.insn_type,
        &generated.decoder,
        &generated.disassembler,
        &generated.encoder,
        &generated.operands,
        &generated.metadata,
    ] {
        all.push_str(part);
        all.push('\n');
    }
    std::fs::write(out.join("generated.rs"), all).expect("write generated.rs");
}
