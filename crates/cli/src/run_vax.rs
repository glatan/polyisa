// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! VAX の実行ループ。
//!
//! 1 ステップぶんの可変長フェッチ・解読・意味論は
//! `polyisa_guest_vax::run::step`（guest 側。bare テストが直接
//! 確かめる）で、ここは繰り返しの駆動とモデル解決の窓口。
//! ELF の入口は OS パーソナリティ（段階25 の BSD）と共に足す。
//! Ref: SPEC-VAX-ARM.

use polyisa_engine::bare::BareEnv;
use polyisa_engine::run::{Outcome, TrapHandler};

/// 実バイナリの処理量を見込んだ上限。
const STEP_LIMIT: u64 = 256_000_000;

/// 実行する CPU モデルの、ループが読む分。
#[derive(Clone, Copy, Debug)]
pub struct VaxModel {
    /// `decode_insn_ex` に渡す機能ビット。
    pub feats: u128,
    /// 意味論が `b.param` で読む挙動パラメータ。
    pub params: polyisa_guest_vax::Params,
}

impl VaxModel {
    /// モデル名（`MODELS` のいずれか）から解決する。
    /// 未知の名前はフル VAX の既定になる。
    #[must_use]
    pub fn named(name: &str) -> Self {
        Self {
            feats: polyisa_guest_vax::model_feats(name),
            params: polyisa_guest_vax::model_params(name),
        }
    }
}

/// `entry` から `model` で実行する。`sys` は OS パーソナリティ。
pub fn run(env: &mut BareEnv, entry: u64, model: VaxModel, sys: &mut impl TrapHandler) -> Outcome {
    env.pc = entry;
    polyisa_guest_vax::install_params(&mut env.backend, &model.params);
    // VAX の仮想アドレスは 32 ビットで折り返す。
    env.backend.addr_mask = 0xFFFF_FFFF;
    polyisa_engine::run::run(
        env,
        sys,
        STEP_LIMIT,
        |env| env.pc,
        |env, sys| polyisa_guest_vax::run::step(env, sys, model.feats),
    )
}
