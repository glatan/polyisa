// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! MIPS o32 のシステムコール番号。基準 4000 に表の通し番号を足した値。
//! exit は 1、write は 4。
// Ref: SRC-LINUX (7.3).

pub const EXIT: u64 = 4001;
pub const WRITE: u64 = 4004;
