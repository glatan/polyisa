// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 検査済みモデルの入れ物。構文解析器がこの形を作り、検査と生成が読む。
//!
//! ビット連結（`++`）、スケーリング、フックの詳細は後の段階で足す。
//! ここでは範囲フィールドと名前解決に必要な項目だけを持つ。

use super::pattern::Pattern;
use super::pred::Pred;

/// ISA の宣言。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Isa {
    pub name: String,
    /// 命令フェッチの単位（ビット）。
    pub parcel_bits: u32,
}

/// 実行モードの値の種類。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ModeType {
    Bool,
    Enum(Vec<String>),
}

/// 実行モードの宣言。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Mode {
    pub name: String,
    pub ty: ModeType,
}

/// レジスタクラス。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RegClass {
    pub name: String,
    /// 実行時に位置を計算するかどうか。
    pub dynamic: bool,
}

/// フィールドの取り出し方。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum FieldKind {
    /// 命令語の `[hi:lo]`。
    Bits { hi: u32, lo: u32 },
    /// Rust のフック。逆変換の有無でエンコーダ可否が決まる。
    Hook { has_encoder: bool },
}

/// フィールドの宣言。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Field {
    pub name: String,
    pub kind: FieldKind,
}

/// オペランドの読み書き。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Access {
    Read,
    Write,
    ReadWrite,
}

/// オペランドの宣言。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Operand {
    pub name: String,
    pub regclass: Option<String>,
    pub access: Access,
}

/// 形式。複数命令で共通する配置とオペランド。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Format {
    pub name: String,
    pub fields: Vec<String>,
    pub operands: Vec<Operand>,
}

/// フィールド値の制約（`where`）。デコード時に評価する。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WhereOp {
    Eq,
    Ne,
}

/// フィールド値の制約（`where`）1 件。`field` は形式のフィールド名である。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WhereClause {
    pub field: String,
    pub op: WhereOp,
    pub value: u128,
}

/// 命令。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Insn {
    pub name: String,
    pub format: String,
    pub pattern: Pattern,
    pub when: Pred,
    pub wheres: Vec<WhereClause>,
    pub syntax: String,
    pub timing: String,
}

/// 機能。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Feature {
    pub name: String,
    pub implies: Vec<String>,
    pub conflicts: Vec<String>,
}

/// CPU モデルの定義（機能の足し引きと親の指定）。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ModelDef {
    pub name: String,
    pub parent: String,
    pub add_features: Vec<String>,
    pub remove_features: Vec<String>,
}

/// 検査済みモデルの全体。
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Model {
    pub isa: Option<Isa>,
    pub modes: Vec<Mode>,
    pub regclasses: Vec<RegClass>,
    pub fields: Vec<Field>,
    pub formats: Vec<Format>,
    pub insns: Vec<Insn>,
    pub features: Vec<Feature>,
    pub models: Vec<ModelDef>,
    pub timing_classes: Vec<String>,
}

impl Model {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}
