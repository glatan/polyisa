// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `isagen` の生成物を `target/isagen/<isa>/` に書き出す。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use polyisa_isagen::Generated;

use crate::specs;

pub(crate) fn cmd_isagen_dump(root: &Path, isa: &str) -> Result<Vec<PathBuf>, String> {
    let spec = specs::find_spec(isa)
        .ok_or_else(|| format!("unknown ISA: {isa}\nknown: {}", specs::known_isas()))?;
    let model = (spec.build)();
    let generated = polyisa_isagen::generate(&model).map_err(|e| e.to_string())?;
    let files = generated_files(&generated);
    let dir = root.join("target/isagen").join(isa);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut written = Vec::new();
    for (name, body) in &files {
        let path = dir.join(name);
        std::fs::write(&path, body).map_err(|e| format!("{}: {e}", path.display()))?;
        written.push(path);
    }
    Ok(written)
}

/// `Generated` のフィールドごとにファイルを分ける。
/// `generated.rs` は `build.rs` が `OUT_DIR` に書く連結と同じ内容である。
pub(crate) fn generated_files(g: &Generated) -> BTreeMap<String, String> {
    let parts = [
        ("insn_type.rs", g.insn_type.as_str()),
        ("decoder.rs", g.decoder.as_str()),
        ("disassembler.rs", g.disassembler.as_str()),
        ("encoder.rs", g.encoder.as_str()),
        ("operands.rs", g.operands.as_str()),
        ("metadata.rs", g.metadata.as_str()),
    ];
    let mut out = BTreeMap::new();
    let mut all = String::new();
    for (name, body) in parts {
        out.insert(name.to_string(), body.to_string());
        all.push_str(body);
        all.push('\n');
    }
    out.insert("generated.rs".to_string(), all);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dump_splits_generated_and_keeps_build_rs_name() {
        let spec = specs::find_spec("riscv").expect("riscv");
        let model = (spec.build)();
        let generated = polyisa_isagen::generate(&model).expect("generate");
        let files = generated_files(&generated);
        assert!(files.contains_key("generated.rs"));
        assert!(files.contains_key("decoder.rs"));
        let combined = files.get("generated.rs").expect("combined");
        assert!(combined.contains(files.get("insn_type.rs").expect("type")));
        assert!(combined.contains(files.get("metadata.rs").expect("meta")));
    }
}
