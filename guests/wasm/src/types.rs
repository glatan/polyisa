// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! WebAssembly の型と値の定義。宣言だけを置く（実行時の手続きは持たない）。
//!
//! 範囲は WebAssembly 1.0 と 2.0 のコア（数値型、参照型、v128 は型だけ）。
//! memory64・マルチメモリ・GC・関数参照・tail call・threads は対象外。
//! Ref: SPEC-WASM-CORE (3.0 のうち 1.0/2.0 の規則).

/// 値型。バイナリの負のコードは括弧書き。
/// Ref: SPEC-WASM-CORE 5.3.1.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ValType {
    /// `i32`（0x7f）。
    I32,
    /// `i64`（0x7e）。
    I64,
    /// `f32`（0x7d）。
    F32,
    /// `f64`（0x7c）。
    F64,
    /// `v128`（0x7b）。2.0 の範囲で型としてのみ受理する（演算命令は未対応）。
    V128,
    /// 参照型（`funcref` 0x70、`externref` 0x6f）。
    Ref(RefType),
}

/// 参照型の種別。
/// Ref: SPEC-WASM-CORE 5.3.1.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum RefType {
    /// `funcref`（0x70）。
    Func,
    /// `externref`（0x6f）。
    Extern,
    /// 具体型指標のヒープ型 `(ref [null] $t)`（2.0 関数参照）。
    /// 検証で型空間の範囲を調べたあと Func に潰す。
    Idx(u32),
}

impl RefType {
    /// バイナリ上の負の型コード（単バイト形のみ）。
    /// `Idx` は s33 の多バイト形なのでこの変換では表せない。
    /// テキストモジュールの emit 経路は Idx を作らないので
    /// ここで panic することはない。
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Self::Func => 0x70,
            Self::Extern => 0x6f,
            Self::Idx(_) => unreachable!("index heap types are not emitted"),
        }
    }
}

/// 関数型 `[params] -> [results]`。`call_indirect` の型一致は構造の等価で見る。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FuncType {
    pub params: Vec<ValType>,
    pub results: Vec<ValType>,
}

/// `limits`（最小と任意の最大）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Limits {
    pub min: u32,
    pub max: Option<u32>,
}

/// テーブル型（要素型とリミット）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TableType {
    pub et: RefType,
    pub lim: Limits,
}

/// メモリ型。1.0/2.0 ではリミットのみ（32 ビットアドレス）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MemType {
    pub lim: Limits,
}

/// グローバル型（値型と可変性）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GlobalType {
    pub vt: ValType,
    pub mutable: bool,
}

/// 外部型（インポートとエクスポートの型）。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ExternType {
    Func(FuncType),
    Table(TableType),
    Mem(MemType),
    Global(GlobalType),
}

/// ブロック型。`empty`、単一値型、または関数型の指標（multi-value）。
/// `s33` でエンコードされる。
/// Ref: SPEC-WASM-CORE 5.3.3.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlockType {
    Empty,
    Val(ValType),
    Func(u32),
}

/// 実行時の値。浮動小数点はビット表現で持つ（NaN の payload を壊さないため）。
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Val {
    I32(u32),
    I64(u64),
    F32(u32),
    F64(u64),
    V128(u128),
    Ref(RefVal),
}

/// 実行時の参照値。
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum RefVal {
    /// 型付きの null 参照。
    Null(RefType),
    /// store 内の関数アドレス。
    Func(u32),
    /// ホスト側の不透明な参照番号（externref）。
    Extern(u32),
}

impl Val {
    /// `v` の型。
    #[must_use]
    pub fn ty(&self) -> ValType {
        match self {
            Self::I32(_) => ValType::I32,
            Self::I64(_) => ValType::I64,
            Self::F32(_) => ValType::F32,
            Self::F64(_) => ValType::F64,
            Self::V128(_) => ValType::V128,
            Self::Ref(RefVal::Func(_))
            | Self::Ref(RefVal::Null(RefType::Func | RefType::Idx(_))) => {
                ValType::Ref(RefType::Func)
            }
            Self::Ref(RefVal::Extern(_)) | Self::Ref(RefVal::Null(RefType::Extern)) => {
                ValType::Ref(RefType::Extern)
            }
        }
    }

    /// 型 `t` の既定値（ローカル変数・`table.grow` の null 初期化に使う）。
    #[must_use]
    pub fn zero(t: ValType) -> Val {
        match t {
            ValType::I32 => Val::I32(0),
            ValType::I64 => Val::I64(0),
            ValType::F32 => Val::F32(0),
            ValType::F64 => Val::F64(0),
            ValType::V128 => Val::V128(0),
            ValType::Ref(r) => Val::Ref(RefVal::Null(r)),
        }
    }

    #[must_use]
    pub fn i32(v: u32) -> Val {
        Val::I32(v)
    }

    #[must_use]
    pub fn as_i32(&self) -> u32 {
        match self {
            Val::I32(v) => *v,
            _ => 0,
        }
    }
}

/// メモリのページサイズ（64 KiB）。
pub const PAGE: u64 = 65_536;

/// メモリのページ数の上限（4 GiB / 64 KiB）。
pub const MAX_PAGES: u32 = 65_536;

/// メモリのページ数の上限（4 GiB / 64 KiB）。`memory.grow` の max 省略時の既定。
pub const MAX_TABLE: u64 = u32::MAX as u64;
