// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Unix V7 パーソナリティ。PDP-11 のユーザーモードで V7 の
//! システムコール規約を実装する。
//!
//! 規約は Unix Programmer's Manual, Seventh Edition の第2部
//! （システムコール）の事実を自前表現で書く。条文・コードの
//! 複製はしない。

// Ref: SPEC-UNIX-V7.

#![forbid(unsafe_code)]

/// PDP-11 の Unix V7 パーソナリティ（`sys` の実装と ABI 定数）。
pub mod pdp11;
