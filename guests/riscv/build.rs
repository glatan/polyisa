//! `spec/` の ISADL 記述からコードを生成する。

// Ref: SPEC-RISCV-UNPRIV (20250508).
include!("spec/rv64i.rs");

fn main() {
    // ISADL 記述の変更で再生成するための監視指定。
    println!("cargo::rerun-if-changed=spec/");
    println!("cargo::rerun-if-changed=build.rs");
    let model = build_model();
    for insn in &model.insns {
        assert!(
            insn.pattern.len() == 16 || insn.pattern.len() == 32,
            "{}",
            insn.name
        );
    }
    let report = polyisa_isadl::validate(&model);
    assert!(
        report.errors.is_empty(),
        "invalid RV64I model: {:?}",
        report.errors
    );
    let generated = polyisa_isagen::generate(&model).expect("valid RV64I model");
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let mut all = String::new();
    for part in [
        &generated.insn_type,
        &generated.decoder,
        &generated.disassembler,
        &generated.encoder,
        &generated.metadata,
    ] {
        all.push_str(part);
        all.push('\n');
    }
    std::fs::write(out.join("generated.rs"), all).expect("write generated.rs");
}
