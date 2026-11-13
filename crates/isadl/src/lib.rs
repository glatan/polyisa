// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! ISADL の検査済みモデル。記述面は `guests/<isa>/spec/*.rs` がこのモデルを
//! 組み立てる Rust DSL とする（ADR-0017）。`.isadl` テキストの構文解析は
//! 実装せず、設計文書の文法はフロントエンドの設計として残る。
//!
//! 詳しくは [ISA 記述言語](../../../docs/design/isa-description.md) を見る。
//! この骨格は、ビットパターンの照合、述語の評価、静的検査の核を提供する。

#![forbid(unsafe_code)]

pub mod model;
pub mod pattern;
pub mod pred;
pub mod select;
pub mod validate;

pub use model::Model;
pub use pattern::Pattern;
pub use pred::Pred;
pub use validate::{Report, ValidationError, validate};
