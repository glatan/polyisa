// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! ゲスト ISA が実装する共通の型。CPU モデル、機能集合、レジスタ記述。
//!
//! 詳しくは [CPU モデル](../../docs/architecture/cpu-models.md) を見る。

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

/// 機能の名前。ISA ファミリごとに ISADL で宣言する。
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Feature(pub String);

/// 機能の集合。生成器は固定長のビット集合を作るが、ここでは汎用の集合で表す。
#[derive(Clone, Debug, Default)]
pub struct FeatureSet {
    inner: BTreeSet<Feature>,
}

impl FeatureSet {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, name: &str) {
        self.inner.insert(Feature(name.to_string()));
    }

    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.inner.contains(&Feature(name.to_string()))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// 挙動パラメータの値。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ParamValue {
    Bool(bool),
    Int(i128),
    Enum(String),
}

/// CPU モデル。実在または仮想の CPU を表す定義。
#[derive(Clone, Debug)]
pub struct CpuModel {
    /// `x86:pentium_pro` のような名前。
    pub name: String,
    /// 親のプロファイル名。
    pub parent: String,
    pub features: FeatureSet,
    pub params: BTreeMap<String, ParamValue>,
    pub timing_fidelity: polyisa_timing::Fidelity,
}

impl CpuModel {
    #[must_use]
    pub fn new(name: &str, parent: &str) -> Self {
        Self {
            name: name.to_string(),
            parent: parent.to_string(),
            features: FeatureSet::new(),
            params: BTreeMap::new(),
            timing_fidelity: polyisa_timing::Fidelity::None,
        }
    }
}

/// ゲスト ISA クレートが実装する最小の表示。詳細は ISA 実装時に足す。
pub trait GuestIsa {
    /// `riscv`、`x86` のような ISA ファミリ名。
    fn family() -> &'static str;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_set_basic() {
        let mut fs = FeatureSet::new();
        assert!(fs.is_empty());
        fs.insert("sse2");
        assert!(fs.contains("sse2"));
        assert!(!fs.contains("avx2"));
        assert_eq!(fs.len(), 1);
    }

    #[test]
    fn cpu_model_default_fidelity_none() {
        let m = CpuModel::new("riscv:rv64gc", "rva22u64");
        assert_eq!(m.timing_fidelity, polyisa_timing::Fidelity::None);
    }
}
