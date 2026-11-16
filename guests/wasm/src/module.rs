// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! デコード済みモジュールの形。各セクションの宣言をそのまま保持する。
//!
//! 実行用の内部形式（関数本体の解読済み命令列）は `validate` が別途作る。
//! Ref: SPEC-WASM-CORE 5.5（モジュールの構造）.

use crate::instr::Instr;
use crate::types::{FuncType, GlobalType, MemType, RefType, TableType};

/// デコード済みモジュール。
#[derive(Clone, Debug, Default)]
pub struct Module {
    /// 型セクション。
    pub types: Vec<FuncType>,
    /// インポートセクション。
    pub imports: Vec<Import>,
    /// 関数セクション（定義関数の型指標）。
    pub funcs: Vec<u32>,
    /// テーブルセクション（定義テーブル）。
    pub tables: Vec<TableType>,
    /// テーブルごとの初期化式（2.0 の `0x40 0x00` 形）。
    /// `tables` と同じ長さ、`None` = `ref.null` 初期値。
    pub table_inits: Vec<Option<ConstExpr>>,
    /// テーブル要素型が non-null（`(ref ht)` = `0x64` 形）か。
    /// `tables` と同じ長さ。`RefType` は nullability を持たないので
    /// 別ベクトルで追う。
    pub table_nonnull: Vec<bool>,
    /// メモリセクション（定義メモリ。高々1つ）。
    pub mems: Vec<MemType>,
    /// グローバルセクション。
    pub globals: Vec<Global>,
    /// エクスポートセクション。
    pub exports: Vec<Export>,
    /// スタート関数の指標。
    pub start: Option<u32>,
    /// エレメントセクション。
    pub elems: Vec<Elem>,
    /// データセクション。
    pub datas: Vec<Data>,
    /// コードセクション（`funcs` と同じ数・同じ順）。
    pub code: Vec<Code>,
    /// data count セクションがあったときの宣言数。
    pub data_count: Option<u32>,
}

/// インポート宣言。
#[derive(Clone, Debug)]
pub struct Import {
    pub module: String,
    pub name: String,
    pub desc: ImportDesc,
}

/// インポートの記述子。
#[derive(Clone, Debug)]
pub enum ImportDesc {
    Func(u32),
    Table(TableType),
    Mem(MemType),
    Global(GlobalType),
}

/// エクスポート宣言。
#[derive(Clone, Debug)]
pub struct Export {
    pub name: String,
    /// 外部値の種類（0=func, 1=table, 2=mem, 3=global）。
    pub kind: u8,
    pub idx: u32,
}

/// 定数式（グローバル初期化・オフセット式）。検証で命令を限定する。
#[derive(Clone, Debug)]
pub struct ConstExpr {
    pub instrs: Vec<Instr>,
}

/// グローバル定義。
#[derive(Clone, Debug)]
pub struct Global {
    pub ty: GlobalType,
    pub init: ConstExpr,
}

/// エレメントセグメント。
#[derive(Clone, Debug)]
pub struct Elem {
    /// 要素の参照型。
    pub ty: RefType,
    /// 要素型が non-null（`(ref ht)`）か。elemkind 形は `false`。
    pub nonnull: bool,
    /// 初期値列。
    pub init: ElemItem,
    /// セグメントの置き方。
    pub mode: ElemMode,
}

/// エレメントセグメントの初期値。
#[derive(Clone, Debug)]
pub enum ElemItem {
    /// 関数指標の列（flags 0–3 の形）。
    Funcs(Vec<u32>),
    /// 式の列（flags 4–7 の形）。各要素は `ref.func`/`ref.null`/`global.get`。
    Exprs(Vec<ConstExpr>),
}

/// エレメントセグメントの置き方。
#[derive(Clone, Debug)]
pub enum ElemMode {
    /// アクティブ（テーブル指標とオフセット式）。
    Active { table: u32, offset: ConstExpr },
    /// パッシブ。
    Passive,
    /// 宣言のみ（`ref.func` の合法化用）。
    Declared,
}

/// データセグメント。
#[derive(Clone, Debug)]
pub struct Data {
    pub mode: DataMode,
    pub bytes: Vec<u8>,
}

/// データセグメントの置き方。
#[derive(Clone, Debug)]
pub enum DataMode {
    /// アクティブ（メモリ指標とオフセット式）。
    Active { mem: u32, offset: ConstExpr },
    /// パッシブ。
    Passive,
}

/// コードセクションの一関数ぶん。`body` は `end` を含む生の式バイト列。
#[derive(Clone, Debug)]
pub struct Code {
    /// 宣言ローカルの連長表現（個数, 型）。仕様上の合計は
    /// `u32::MAX` 個まで認められるため、展開はしない（実行時に
    /// 呼ばれた関数だけ `exec` が展開する）。
    pub locals: Vec<(u32, crate::types::ValType)>,
    /// 式の生バイト列（`end` で終わる）。
    pub body: Vec<u8>,
}
