// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! PDP-11 の実行ループ。
//!
//! 1 ステップぶんのワードフェッチ・解読・意味論は
//! `polyisa_guest_pdp11::run::step`（guest 側。bare テストが直接
//! 確かめる）で、ここは繰り返しの駆動とモデル解決の窓口。
//! Unix V7 の a.out は `polyisa_os_v7` のパーソナリティで走る
//! （`run_aout_v7_sys`）。
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

/// PDP-11 の a.out を Unix V7 パーソナリティ `sys` で実行する。
/// `model` は `MODELS` のモデル名 —— V7 の実機が MMU（分離 I/D
/// 可）を持つ 11/70 級なので、指定がなければ `pdp11_70`。
/// `path` は argv[0] にも使う実行ファイルのゲスト側パス。
pub fn run_aout_v7_sys(
    bytes: &[u8],
    path: &str,
    argv: &[String],
    model: &str,
    sys: &mut polyisa_os_v7::pdp11::sys::V7,
) -> Result<u64, String> {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_pdp11::CpuState>());
    // argv[0] はプログラムのパス（ELF の各実行経路と同じ規則）。
    let mut gargv = Vec::with_capacity(argv.len() + 1);
    gargv.push(path.to_string());
    gargv.extend(argv.iter().cloned());
    let entry = sys.load_exec(&mut env, bytes, &gargv)?;
    let m = Pdp11Model::named(model);
    finish_v7(run(&mut env, u64::from(entry), m, sys))
}

/// `Outcome` を cli の戻り値に写す。
fn finish_v7(o: Outcome) -> Result<u64, String> {
    match o {
        Outcome::Exit(code) => Ok(code),
        Outcome::Unimplemented { pc, word } => Err(format!("unimplemented at {pc:#x}: {word:#x}")),
        Outcome::StepLimit { pc } => Err(format!("step limit at {pc:#x}")),
        Outcome::Deadlock => Err("deadlock".to_string()),
    }
}

/// 標準出力を集めたいテスト用（戻り値は終了コードと stdout）。
/// `root` はゲストパスを引くホスト側のルート。標準入力は
/// `input` を `sys.io.stdin` に渡す。
pub fn run_aout_v7_captured_in(
    path: &str,
    argv: &[String],
    root: &str,
    input: &[u8],
) -> Result<(u64, Vec<u8>), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let mut sys = polyisa_os_v7::pdp11::sys::V7::new(root);
    sys.io.stdin = input.to_vec();
    // ゲスト側から見える実行パスは root 相対のパス。
    let gpath = path.strip_prefix(root).unwrap_or(path).to_string();
    let gpath = if gpath.starts_with('/') {
        gpath
    } else {
        format!("/{gpath}")
    };
    let code = run_aout_v7_sys(&bytes, &gpath, argv, "pdp11_70", &mut sys)?;
    Ok((code, sys.io.stdout))
}
