// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! x86 最小の ISADL 記述。出典は SPEC-X86-INTEL-SDM Combined v093 である。

// Ref: SPEC-X86-INTEL-SDM (v093).
include!("spec/x86min.rs");

fn main() {
    println!("cargo::rerun-if-changed=spec/");
    println!("cargo::rerun-if-changed=build.rs");
    let model = build_model();
    // 可変長：1〜11バイト（imm64 付きは 72 ビット、SIB+disp32+imm32 付きは 88 ビット）。
    for insn in &model.insns {
        assert!(
            [8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88].contains(&insn.pattern.len()),
            "{}",
            insn.name
        );
    }
    let report = polyisa_isadl::validate(&model);
    assert!(
        report.errors.is_empty(),
        "invalid x86 model: {:?}",
        report.errors
    );
    let generated = polyisa_isagen::generate(&model).expect("valid x86 model");
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
