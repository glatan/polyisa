// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! IA-64（Itanium）の実行ループ。
//!
//! 1 ステップぶんのバンドル進行は `polyisa_guest_ia64::run::step`
//! （guest 側。bare テストが直接確かめる）で、ここは繰り返しの
//! 駆動とモデル解決の窓口。ELF の入口は IA11 が足す。
//! Ref: SPEC-IA64-SDM (Rev 2.3).

use polyisa_engine::bare::BareEnv;
use polyisa_engine::run::{Outcome, TrapHandler};

/// 実バイナリの処理量を見込んだ上限。
const STEP_LIMIT: u64 = 256_000_000;

/// 実行する CPU モデルの、ループが読む分。
#[derive(Clone, Copy, Debug)]
pub struct Ia64Model {
    /// `bundle::decode_slot` に渡す機能ビット。
    pub feats: u128,
}

impl Ia64Model {
    /// `--cpu` で解決した `CpuSel` から作る。
    #[must_use]
    pub fn new(feats: u128) -> Self {
        Self { feats }
    }
}

/// `entry`（ip = バンドルアドレス|スロット番号）から実行する。
/// `sys` は OS パーソナリティ。
pub fn run(env: &mut BareEnv, entry: u64, model: Ia64Model, sys: &mut impl TrapHandler) -> Outcome {
    env.pc = entry;
    polyisa_engine::run::run(
        env,
        sys,
        STEP_LIMIT,
        |env| env.pc,
        |env, sys| polyisa_guest_ia64::run::step(env, sys, model.feats),
    )
}
