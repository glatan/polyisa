// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! PDP-11 の実行ループ。
//!
//! 1 ステップぶんのワードフェッチ・解読・意味論は
//! `polyisa_guest_pdp11::run::step`（guest 側。bare テストが直接
//! 確かめる）で、ここは繰り返しの駆動とモデル解決の窓口。
//! Unix V7 の a.out ローダと OS パーソナリティは段階25 で足す。
//! Ref: SPEC-PDP11-ARCH83.

use polyisa_engine::bare::BareEnv;
use polyisa_engine::run::{Outcome, TrapHandler};

/// 実バイナリの処理量を見込んだ上限。
const STEP_LIMIT: u64 = 256_000_000;

/// 実行する CPU モデルの、ループが読む分。
#[derive(Clone, Copy, Debug)]
pub struct Pdp11Model {
    /// `decode_model_ex` に渡す機能ビット。
    pub feats: u128,
    /// 意味論が `b.param` で読む挙動パラメータ。
    pub params: polyisa_guest_pdp11::Params,
}

impl Pdp11Model {
    /// モデル名（`MODELS` のいずれか）から解決する。
    /// 未知の名前は既定値になる。
    #[must_use]
    pub fn named(name: &str) -> Self {
        Self {
            feats: polyisa_guest_pdp11::model_feats(name),
            params: polyisa_guest_pdp11::model_params(name),
        }
    }
}

/// `entry` から `model` で実行する。`sys` は OS パーソナリティ。
pub fn run(
    env: &mut BareEnv,
    entry: u64,
    model: Pdp11Model,
    sys: &mut impl TrapHandler,
) -> Outcome {
    env.pc = entry;
    polyisa_guest_pdp11::install_params(&mut env.backend, &model.params);
    // PDP-11 のアドレスは 16 ビットで折り返す。
    env.backend.addr_mask = 0xFFFF;
    polyisa_engine::run::run(
        env,
        sys,
        STEP_LIMIT,
        |env| env.pc,
        |env, sys| polyisa_guest_pdp11::run::step(env, sys, model.feats),
    )
}
