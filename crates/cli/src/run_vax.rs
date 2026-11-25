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

/// VAX の a.out を 4.3BSD パーソナリティ `sys` で実行する。
/// `model` は `MODELS` のモデル名 —— 4.3BSD の実機がフル VAX
/// なので、指定がなければ `vax`。
/// `path` は argv[0] にも使う実行ファイルのゲスト側パス。
pub fn run_aout_bsd_sys(
    bytes: &[u8],
    path: &str,
    argv: &[String],
    model: &str,
    sys: &mut polyisa_os_bsd::vax::sys::Bsd,
) -> Result<u64, String> {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_vax::CpuState>());
    // argv[0] はプログラムのパス（ELF の各実行経路と同じ規則）。
    let mut gargv = Vec::with_capacity(argv.len() + 1);
    gargv.push(path.to_string());
    gargv.extend(argv.iter().cloned());
    let entry = sys.load_exec(&mut env, bytes, &gargv)?;
    let m = VaxModel::named(model);
    finish_bsd(run(&mut env, u64::from(entry), m, sys))
}

/// `Outcome` を cli の戻り値に写す。
fn finish_bsd(o: Outcome) -> Result<u64, String> {
    match o {
        Outcome::Exit(code) => Ok(code),
        Outcome::Unimplemented { pc, word } => Err(format!("unimplemented at {pc:#x}: {word:#x}")),
        Outcome::StepLimit { pc } => Err(format!("step limit at {pc:#x}")),
        Outcome::Deadlock => Err("deadlock".to_string()),
        Outcome::Breakpoint { pc } => Err(format!("breakpoint at {pc:#x}")),
    }
}

/// 標準出力を集めたいテスト用（戻り値は終了コードと stdout）。
/// `root` はゲストパスを引くホスト側のルート。標準入力は
/// `input` を `sys.io.stdin` に渡す。
pub fn run_aout_bsd_captured_in(
    path: &str,
    argv: &[String],
    root: &str,
    input: &[u8],
) -> Result<(u64, Vec<u8>), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let mut sys = polyisa_os_bsd::vax::sys::Bsd::new(root);
    sys.io.stdin = input.to_vec();
    // ゲスト側から見える実行パスは root 相対のパス。
    let gpath = path.strip_prefix(root).unwrap_or(path).to_string();
    let gpath = if gpath.starts_with('/') {
        gpath
    } else {
        format!("/{gpath}")
    };
    let code = run_aout_bsd_sys(&bytes, &gpath, argv, "vax", &mut sys)?;
    Ok((code, sys.io.stdout))
}
