// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! m68k 最小の ISADL 記述。出典は SPEC-M68K-PRM である。

// Ref: SPEC-M68K-PRM (Rev 1).
include!("spec/m68kmin.rs");

fn main() {
    println!("cargo::rerun-if-changed=spec/");
    println!("cargo::rerun-if-changed=build.rs");
    let model = build_model();
    for insn in &model.insns {
        assert!(insn.pattern.len() == 16, "{}", insn.name);
    }
    let report = polyisa_isadl::validate(&model);
    assert!(
        report.errors.is_empty(),
        "invalid m68k model: {:?}",
        report.errors
    );
    let generated = polyisa_isagen::generate(&model).expect("valid m68k model");
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
