//! `spec/` の ISADL 記述からコードを生成する。記述自体は参照資料の確認後に書く。

fn main() {
    // ISADL 記述の変更で再生成するための監視指定。
    println!("cargo::rerun-if-changed=spec/");
    // 確認前は記述が空のため、空のモデルから殻を生成する。
    let model = polyisa_isagen::Model::new();
    let generated = polyisa_isagen::generate(&model).expect("empty model is valid");
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
