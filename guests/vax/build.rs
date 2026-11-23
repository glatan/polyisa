// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! VAX の ISADL 記述。出典は SPEC-VAX-ARM と SPEC-VAX-MICROVAX である。

// Ref: SPEC-VAX-ARM, SPEC-VAX-MICROVAX.
include!("spec/vax.rs");

fn main() {
    println!("cargo::rerun-if-changed=spec/");
    println!("cargo::rerun-if-changed=build.rs");
    let model = build_model();
    // オペコード部は 1 バイト本体か 0xFD/0xFE/0xFF 接頭の 2 バイト。
    for insn in &model.insns {
        assert!(
            insn.pattern.len() == 8 || insn.pattern.len() == 16,
            "{}",
            insn.name
        );
    }
    let report = polyisa_isadl::validate(&model);
    assert!(
        report.errors.is_empty(),
        "invalid VAX model: {:?}",
        report.errors
    );
    let generated = polyisa_isagen::generate(&model).expect("valid VAX model");
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
