// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! CPU モデルの選択から機能集合を解決する。
//!
//! 入力は isagen が生成した定数の表（`MODEL_DEFS`、`FEATURE_DEFS`、
//! `FEAT_BITS`）で、ISA ごとに同じ形を持つ。解決の規則は
//! [CPU モデルとバージョンの表現](../../../docs/architecture/cpu-models.md)
//! に従う。親をたどって機能を足し引きし、`implies` で閉包してから
//! `conflicts` を検査する。

use std::collections::{BTreeMap, BTreeSet};

/// `MODEL_DEFS` の要素型。名前、親、追加機能、削除機能、識別情報の対。
pub type ModelRow = (
    &'static str,
    &'static str,
    &'static [&'static str],
    &'static [&'static str],
    &'static [(&'static str, &'static str)],
);
/// `FEATURE_DEFS` の要素型。
pub type FeatureRow = (
    &'static str,
    &'static [&'static str],
    &'static [&'static str],
);

/// 解決した CPU モデル。実行に必要なのは `feats` と `is_rv64` だけで、
/// `features` は識別情報（CPUID 等）の導出と報告に使う。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CpuSel {
    /// 解決したモデルの名前（既定選択を含む）。
    pub name: String,
    /// 閉包済みの機能名の集合。
    pub features: BTreeSet<String>,
    /// `decode_model_ex` の `feats` に渡すビット集合。
    pub feats: u128,
    /// 機能集合に `rv64` があれば `Some(true)`、`rv32` なら `Some(false)`。
    /// どちらもなければ `None`（RISC-V 以外では使わない）。
    pub is_rv64: Option<bool>,
    /// モデルの識別情報。親連鎖を根から順にたどり、近い世代の
    /// 値で同じキーを上書きする（`cpuid.vendor` 等）。
    pub ident: BTreeMap<String, String>,
}

/// モデル名と機能の足し引きから `CpuSel` を解決する。
///
/// `models` は `MODEL_DEFS`、`features` は `FEATURE_DEFS`、
/// `feat_bits` は `FEAT_BITS`。`model` が空なら `models` の先頭を
/// 既定とする。`add`/`remove` は `--cpu` の `+機能`/`-機能`。
///
/// 未知のモデルや機能、`conflicts` 違反はエラーにする。
pub fn resolve(
    models: &[ModelRow],
    features: &[FeatureRow],
    feat_bits: &[(&str, u128)],
    model: &str,
    add: &[&str],
    remove: &[&str],
) -> Result<CpuSel, String> {
    // モデルの親連鎖をたどる。根（親が空文字）まで順に集め、
    // 根から順に add/remove を適用する。
    let name = if model.is_empty() {
        models
            .first()
            .map(|(n, ..)| *n)
            .ok_or("モデルが一つも宣言されていない")?
    } else {
        model
    };
    let mut chain: Vec<&ModelRow> = Vec::new();
    let mut cur = name;
    loop {
        let row = models
            .iter()
            .find(|(n, ..)| *n == cur)
            .ok_or_else(|| format!("未知の CPU モデル: {cur}"))?;
        chain.push(row);
        if row.1.is_empty() {
            break;
        }
        if chain.len() > models.len() {
            return Err(format!("CPU モデルの親が循環している: {name}"));
        }
        cur = row.1;
    }
    let mut set: BTreeSet<String> = BTreeSet::new();
    let mut ident: BTreeMap<String, String> = BTreeMap::new();
    for row in chain.iter().rev() {
        for f in row.2 {
            set.insert((*f).to_string());
        }
        for f in row.3 {
            set.remove(*f);
        }
        for (k, v) in row.4 {
            ident.insert((*k).to_string(), (*v).to_string());
        }
    }
    for f in add {
        check_known(features, f)?;
        set.insert((*f).to_string());
    }
    for f in remove {
        check_known(features, f)?;
        set.remove(*f);
    }
    // `implies` で閉包する（不動点まで）。
    loop {
        let mut grew = false;
        for (n, implies, _) in features {
            if set.contains(*n) {
                for i in *implies {
                    grew |= set.insert((*i).to_string());
                }
            }
        }
        if !grew {
            break;
        }
    }
    // `conflicts` の検査。
    for (n, _, conflicts) in features {
        if set.contains(*n) {
            for c in *conflicts {
                if set.contains(*c) {
                    return Err(format!("機能 {n} と {c} は両立しない"));
                }
            }
        }
    }
    let feats = set
        .iter()
        .filter_map(|f| feat_bits.iter().find(|(n, _)| n == f).map(|(_, b)| *b))
        .fold(0, |acc, b| acc | b);
    let is_rv64 = if set.contains("rv64") {
        Some(true)
    } else if set.contains("rv32") {
        Some(false)
    } else {
        None
    };
    Ok(CpuSel {
        name: name.to_string(),
        features: set,
        feats,
        is_rv64,
        ident,
    })
}

fn check_known(features: &[FeatureRow], name: &str) -> Result<(), String> {
    if features.iter().any(|(n, ..)| *n == name) {
        Ok(())
    } else {
        Err(format!("未知の機能: {name}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tables() -> (Vec<ModelRow>, Vec<FeatureRow>, Vec<(&'static str, u128)>) {
        let models: Vec<ModelRow> = vec![
            (
                "rv64gc",
                "",
                &["rv64", "m", "a", "f", "d", "c"],
                &[],
                &[("cpuid.vendor", "generic")],
            ),
            (
                "rv64imac",
                "rv64gc",
                &[],
                &["f", "d"],
                &[("cpuid.family", "u7")],
            ),
        ];
        let features: Vec<FeatureRow> = vec![
            ("rv64", &[], &[]),
            ("m", &[], &[]),
            ("a", &[], &[]),
            ("f", &[], &[]),
            ("d", &["f"], &[]),
            ("c", &[], &[]),
            ("zba", &["b"], &[]),
            ("b", &[], &[]),
            ("rv32", &[], &["rv64"]),
        ];
        let bits: Vec<(&str, u128)> = vec![("m", 1 << 0), ("c", 1 << 2), ("zba", 1 << 3)];
        (models, features, bits)
    }

    #[test]
    fn model_inherits_parent_and_removes() {
        let (m, f, b) = tables();
        let sel = resolve(&m, &f, &b, "rv64imac", &[], &[]).unwrap();
        assert!(sel.features.contains("rv64") && sel.features.contains("m"));
        assert!(!sel.features.contains("f") && !sel.features.contains("d"));
        assert_eq!(sel.is_rv64, Some(true));
        assert_eq!(sel.feats, (1 << 0) | (1 << 2)); // m と c
    }

    #[test]
    fn implies_closes_and_conflicts_reject() {
        let (m, f, b) = tables();
        // d を足すと f も入る。
        let sel = resolve(&m, &f, &b, "rv64imac", &["d"], &[]).unwrap();
        assert!(sel.features.contains("f") && sel.features.contains("d"));
        // +rv32 は rv64 と衝突する。
        assert!(resolve(&m, &f, &b, "rv64gc", &["rv32"], &[]).is_err());
        // +zba は implies で b も入り、FEAT_BITS でビットになる。
        let sel = resolve(&m, &f, &b, "rv64gc", &["zba"], &[]).unwrap();
        assert_eq!(sel.feats, (1 << 0) | (1 << 2) | (1 << 3));
    }

    #[test]
    fn unknown_model_and_feature_reject() {
        let (m, f, b) = tables();
        assert!(resolve(&m, &f, &b, "nonexistent", &[], &[]).is_err());
        assert!(resolve(&m, &f, &b, "rv64gc", &["nosuch"], &[]).is_err());
    }

    #[test]
    fn ident_inherits_and_overrides() {
        let (m, f, b) = tables();
        // 親のキーは継承し、子が持つキーは上書き・追加される。
        let sel = resolve(&m, &f, &b, "rv64imac", &[], &[]).unwrap();
        assert_eq!(sel.ident.get("cpuid.vendor").unwrap(), "generic");
        assert_eq!(sel.ident.get("cpuid.family").unwrap(), "u7");
    }

    #[test]
    fn empty_model_defaults_to_first() {
        let (m, f, b) = tables();
        let sel = resolve(&m, &f, &b, "", &[], &[]).unwrap();
        assert!(sel.features.contains("rv64"));
    }
}
