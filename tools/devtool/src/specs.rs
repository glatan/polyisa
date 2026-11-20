// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! ゲストの spec を `build.rs` と同じ `include!` で取り込む。

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use polyisa_isadl::Model;

mod aarch64 {
    include!("../../../guests/aarch64/spec/a64i.rs");
}
mod alpha {
    include!("../../../guests/alpha/spec/alpha.rs");
}
mod arm {
    include!("../../../guests/arm/spec/armi.rs");
}
mod hexagon {
    include!("../../../guests/hexagon/spec/hexmin.rs");
}
mod ia64 {
    include!("../../../guests/ia64/spec/ia64min.rs");
}
mod m68k {
    include!("../../../guests/m68k/spec/m68kmin.rs");
}
mod mips {
    include!("../../../guests/mips/spec/mipsi.rs");
}
mod parisc {
    include!("../../../guests/parisc/spec/parisc.rs");
}
mod power {
    include!("../../../guests/power/spec/poweri.rs");
}
mod riscv {
    include!("../../../guests/riscv/spec/rv64i.rs");
}
mod s390 {
    include!("../../../guests/s390/spec/zarch.rs");
}
mod sparc {
    include!("../../../guests/sparc/spec/sparc.rs");
}
mod wasm {
    include!("../../../guests/wasm/spec/wasmmin.rs");
}
mod x86 {
    mod x86map {
        include!("../../../guests/x86/spec/x86map.rs");
    }
    mod x86cpu {
        include!("../../../guests/x86/spec/x86cpu.rs");
    }
    include!("../../../guests/x86/spec/x86min.rs");
}

pub(crate) struct IsaSpec {
    pub isa: &'static str,
    pub rel_paths: &'static [&'static str],
    pub build: fn() -> Model,
}

const SPECS: &[IsaSpec] = &[
    IsaSpec {
        isa: "aarch64",
        rel_paths: &["guests/aarch64/spec/a64i.rs"],
        build: aarch64::build_model,
    },
    IsaSpec {
        isa: "alpha",
        rel_paths: &["guests/alpha/spec/alpha.rs"],
        build: alpha::build_model,
    },
    IsaSpec {
        isa: "arm",
        rel_paths: &["guests/arm/spec/armi.rs"],
        build: arm::build_model,
    },
    IsaSpec {
        isa: "hexagon",
        rel_paths: &["guests/hexagon/spec/hexmin.rs"],
        build: hexagon::build_model,
    },
    IsaSpec {
        isa: "ia64",
        rel_paths: &["guests/ia64/spec/ia64min.rs"],
        build: ia64::build_model,
    },
    IsaSpec {
        isa: "m68k",
        rel_paths: &["guests/m68k/spec/m68kmin.rs"],
        build: m68k::build_model,
    },
    IsaSpec {
        isa: "mips",
        rel_paths: &["guests/mips/spec/mipsi.rs"],
        build: mips::build_model,
    },
    IsaSpec {
        isa: "parisc",
        rel_paths: &["guests/parisc/spec/parisc.rs"],
        build: parisc::build_model,
    },
    IsaSpec {
        isa: "power",
        rel_paths: &["guests/power/spec/poweri.rs"],
        build: power::build_model,
    },
    IsaSpec {
        isa: "riscv",
        rel_paths: &["guests/riscv/spec/rv64i.rs"],
        build: riscv::build_model,
    },
    IsaSpec {
        isa: "s390",
        rel_paths: &["guests/s390/spec/zarch.rs"],
        build: s390::build_model,
    },
    IsaSpec {
        isa: "sparc",
        rel_paths: &["guests/sparc/spec/sparc.rs"],
        build: sparc::build_model,
    },
    IsaSpec {
        isa: "wasm",
        rel_paths: &["guests/wasm/spec/wasmmin.rs"],
        build: wasm::build_model,
    },
    IsaSpec {
        isa: "x86",
        rel_paths: &[
            "guests/x86/spec/x86min.rs",
            "guests/x86/spec/x86map.rs",
            "guests/x86/spec/x86cpu.rs",
        ],
        build: x86::build_model,
    },
];

pub(crate) fn isa_specs() -> &'static [IsaSpec] {
    SPECS
}

pub(crate) fn find_spec(isa: &str) -> Option<&'static IsaSpec> {
    SPECS.iter().find(|s| s.isa == isa)
}

pub(crate) fn known_isas() -> String {
    SPECS.iter().map(|s| s.isa).collect::<Vec<_>>().join(", ")
}

/// `include!("spec/…")` のファイル名を、現れた順に集める。
pub(crate) fn spec_includes(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let marker = "include!(\"spec/";
    for line in text.lines() {
        let Some(start) = line.find(marker) else {
            continue;
        };
        let rest = &line[start + marker.len()..];
        let Some(end) = rest.find('"') else {
            continue;
        };
        if !rest[..end].is_empty() {
            out.push(rest[..end].to_string());
        }
    }
    out
}

pub(crate) fn check_spec_table(root: &Path) -> Result<(), String> {
    let found = discover_includes(root)?;
    let table: Vec<(&str, &str)> = SPECS
        .iter()
        .flat_map(|s| s.rel_paths.iter().map(|p| (s.isa, file_name(p))))
        .collect();
    let violations = spec_table_violations(&table, &found);
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations.join("; "))
    }
}

fn file_name(rel: &str) -> &str {
    rel.rsplit('/').next().unwrap_or(rel)
}

fn discover_includes(root: &Path) -> Result<BTreeMap<String, Vec<String>>, String> {
    let guests = root.join("guests");
    let rd = std::fs::read_dir(&guests).map_err(|e| format!("{}: {e}", guests.display()))?;
    let mut dirs: Vec<_> = rd.flatten().map(|e| e.path()).collect();
    dirs.sort();
    let mut found = BTreeMap::new();
    for dir in dirs {
        if !dir.is_dir() {
            continue;
        }
        let Some(isa) = dir.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let build = dir.join("build.rs");
        if !build.is_file() {
            continue;
        }
        let text =
            std::fs::read_to_string(&build).map_err(|e| format!("{}: {e}", build.display()))?;
        let includes = spec_includes(&text);
        if !includes.is_empty() {
            found.insert(isa.to_string(), includes);
        }
    }
    Ok(found)
}

pub(crate) fn spec_table_violations(
    table: &[(&str, &str)],
    found: &BTreeMap<String, Vec<String>>,
) -> Vec<String> {
    let mut violations = Vec::new();
    let mut table_isas = BTreeSet::new();
    for (isa, file) in table {
        table_isas.insert(*isa);
        match found.get(*isa) {
            None => violations.push(format!("{isa}: 表の {file} が build.rs にない")),
            Some(files) if !files.iter().any(|f| f == file) => {
                violations.push(format!("{isa}: 表の {file} が build.rs にない"));
            }
            Some(_) => {}
        }
    }
    for (isa, files) in found {
        for file in files {
            let listed = table.iter().any(|(name, spec)| name == isa && spec == file);
            if !listed {
                violations.push(format!("{isa}: build.rs の {file} が表にない"));
            }
        }
        if !table_isas.contains(isa.as_str()) && files.is_empty() {
            violations.push(format!("{isa}: build.rs の spec が表にない"));
        }
    }
    violations.sort();
    violations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_table_matches_build_scripts() {
        check_spec_table(&crate::workspace_root()).expect("spec table");
    }

    #[test]
    fn include_line_is_parsed() {
        let text = "include!(\"spec/rv64i.rs\");\ninclude!(\"other.rs\");\n";
        assert_eq!(spec_includes(text), vec!["rv64i.rs".to_string()]);
    }

    #[test]
    fn mismatched_spec_file_is_a_violation() {
        let table = [("riscv", "rv64i.rs")];
        let mut found = BTreeMap::new();
        found.insert("riscv".to_string(), vec!["other.rs".to_string()]);
        let v = spec_table_violations(&table, &found);
        assert!(v.iter().any(|s| s.contains("表にない")), "{v:?}");
        assert!(v.iter().any(|s| s.contains("build.rs にない")), "{v:?}");
    }

    #[test]
    fn missing_isa_is_a_violation() {
        let table = [("riscv", "rv64i.rs"), ("mips", "mipsi.rs")];
        let mut found = BTreeMap::new();
        found.insert("riscv".to_string(), vec!["rv64i.rs".to_string()]);
        let v = spec_table_violations(&table, &found);
        assert!(
            v.iter()
                .any(|s| s.contains("mips") && s.contains("build.rs にない")),
            "{v:?}"
        );
    }
}
