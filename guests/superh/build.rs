// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! SuperH の ISADL 記述。出典は SPEC-SUPERH-SH2（SH-1/SH-2）、
//! SPEC-SUPERH-SH3（SH-3/SH-3E）、SPEC-SUPERH-SH4（SH-4）、
//! SPEC-SUPERH-SH2A（SH-2A/SH2A-FPU）、SPEC-SUPERH-SH4A（SH-4A）、
//! SPEC-SUPERH-JCORE（J-core）である。

// Ref: SPEC-SUPERH-SH2, SPEC-SUPERH-SH3, SPEC-SUPERH-SH4,
// SPEC-SUPERH-SH2A, SPEC-SUPERH-SH4A, SPEC-SUPERH-JCORE.
include!("spec/superh.rs");

fn main() {
    println!("cargo::rerun-if-changed=spec/");
    println!("cargo::rerun-if-changed=build.rs");
    let model = build_model();
    for insn in &model.insns {
        assert!(matches!(insn.pattern.len(), 16 | 32), "{}", insn.name);
    }
    let report = polyisa_isadl::validate(&model);
    assert!(
        report.errors.is_empty(),
        "invalid superh model: {:?}",
        report.errors
    );
    let generated = polyisa_isagen::generate(&model).expect("valid superh model");
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
