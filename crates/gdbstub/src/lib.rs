// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! GDB リモートシリアルプロトコルのサーバ。
//!
//! `rsp` がパケット層、`target` が対象との境界 `DebugTarget`、
//! `server` がパケットの振り分けと応答、`riscv` が rv64 のレジスタ表と
//! ターゲット記述（target.xml）の生成を持つ。パケット形式の事実は
//! SPEC-GDB-RSP による。

#![forbid(unsafe_code)]

pub mod riscv;
pub mod rsp;
pub mod server;
pub mod target;
