// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `spec/` の ISADL 記述からコードを生成する。

// Ref: SPEC-ARM-ARM-A (Armv9-A ARM ARM 2024-09).
include!("spec/a64i.rs");

fn main() {
    // ISADL 記述の変更で再生成するための監視指定。
    println!("cargo::rerun-if-changed=spec/");
    println!("cargo::rerun-if-changed=build.rs");
    let model = build_model();
    for insn in &model.insns {
        assert!(insn.pattern.len() == 32, "{}", insn.name);
    }
    let report = polyisa_isadl::validate(&model);
    assert!(
        report.errors.is_empty(),
        "invalid A64 model: {:?}",
        report.errors
    );
    let generated = polyisa_isagen::generate(&model).expect("valid A64 model");
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
