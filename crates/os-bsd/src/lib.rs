// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 4.3BSD-Reno パーソナリティ。VAX のユーザーモードで BSD の
//! システムコール規約を実装する。
//!
//! 規約は 4.3BSD-Reno の UNIX Programmer's Manual の第2部
//! （システムコール）の事実を自前表現で書く。条文・コードの
//! 複製はしない。

// Ref: SPEC-BSD-43.

#![forbid(unsafe_code)]

/// VAX の 4.3BSD-Reno パーソナリティ（`sys` の実装と ABI 定数）。
pub mod vax;
