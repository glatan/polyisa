// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! s390/zArchitecture（ESA/390 を含むユーザーモード面）の ISADL 記述。

// Ref: SPEC-S390-ZARCH-POP (SA22-7832-13), SPEC-S390-ESA390-POP (SA22-7201-08).
include!("spec/zarch.rs");

fn main() {
    println!("cargo::rerun-if-changed=spec/");
    println!("cargo::rerun-if-changed=build.rs");
    let model = build_model();
    for insn in &model.insns {
        assert!(
            matches!(insn.pattern.len(), 16 | 32 | 48),
            "{}: {}",
            insn.name,
            insn.pattern.len()
        );
    }
    let report = polyisa_isadl::validate(&model);
    assert!(
        report.errors.is_empty(),
        "invalid s390 model: {:?}",
        report.errors
    );
    let generated = polyisa_isagen::generate(&model).expect("valid s390 model");
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
