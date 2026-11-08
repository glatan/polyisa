// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! ISADL の検査済みモデル。字句解析と構文解析は後の段階で足す。
//!
//! 詳しくは [ISA 記述言語](../../../docs/design/isa-description.md) を見る。
//! この骨格は、ビットパターンの照合、述語の評価、静的検査の核を提供する。
//! ファイル単位の構文解析（`.isadl` の全文法）は `isadl` 実装時に文法の参照文書として確定させる。

#![forbid(unsafe_code)]

pub mod model;
pub mod pattern;
pub mod pred;
pub mod validate;

pub use model::Model;
pub use pattern::Pattern;
pub use pred::Pred;
pub use validate::{Report, ValidationError, validate};
