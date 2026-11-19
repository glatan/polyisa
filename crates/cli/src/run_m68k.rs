// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! m68k（68000 系列）のフェッチから次のフェッチまで。
//!
//! 繰り返しと退出の判定は `engine::run::run` に置き、ここでは 1 ステップぶんの
//! フェッチ・解読・意味論を `step` として提供する（Power 試作と同じ構造）。
//!
//! 命令は16ビットの先頭ワードと EA が要求する拡張語（両 EA で最大4語）
//! からなり、命令長は先頭ワードの EA フィールドから `ea::insn_ext_words` で決める
//! （拡張語の中身の読み出しは意味論側が backend 経由で行う）。
//! 命令は偶数アドレスに整列し、データ・命令ともにビッグエンディアン固定。
//! Trap 系例外は 6 バイトフレームを積んでベクタへ配送する（アドレス
//! エラーの 14 バイトフレームは未接続）。デコード不能な語は
//! `Unimplemented` に写す（実機では illegal ベクタ 4 — デコーダが
//! 認める範囲外を例外へ写す経路は未接続）。
//! Ref: SPEC-M68K-PRM (Rev 1).

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::{Ctrl, InterpExit};
use polyisa_engine::run::{Outcome, TrapHandler};
use polyisa_guest_m68k::{decode_model_ex, ea, sem};
use polyisa_mem::{Access, AccessKind, Align, Endian, VirtAddr};
use polyisa_sem::ExceptionKind;

/// 実バイナリの処理量を見込んだ上限。
const STEP_LIMIT: u64 = 256_000_000;

/// 実行する CPU モデルの、ループが読む分。
#[derive(Clone, Copy, Debug)]
pub struct M68kModel {
    /// `decode_model_ex` に渡す機能ビット。
    pub feats: u128,
}

impl M68kModel {
    /// MC68000 の既定モデル。
    #[must_use]
    pub const fn m68000() -> Self {
        Self {
            feats: polyisa_guest_m68k::FEAT_M68000,
        }
    }
}

/// `entry` から `model` で実行する。`sys` は OS パーソナリティ。
pub fn run(env: &mut BareEnv, entry: u64, model: M68kModel, sys: &mut impl TrapHandler) -> Outcome {
    env.pc = entry;
    // PC は32ビットの内部レジスタだがアドレスバスは24ビット。
    // 意味論が 64 ビットで組み立てたアドレスをアクセス直前に切る。
    env.backend.addr_mask = 0x00FF_FFFF;
    polyisa_engine::run::run(
        env,
        sys,
        STEP_LIMIT,
        |env| env.pc,
        |env, sys| step_m68k(env, sys, model),
    )
}

/// 1 命令ぶんのフェッチ・解読・意味論。
// Ref: SPEC-M68K-PRM (Rev 1).
fn step_m68k(
    env: &mut BareEnv,
    _sys: &mut impl TrapHandler,
    model: M68kModel,
) -> Result<(), Outcome> {
    let pc = env.pc;
    let unimpl = |env: &BareEnv, word: u64| Outcome::Unimplemented {
        pc: env.pc,
        word: u128::from(word),
    };
    // 命令は偶数アドレスに整列する（奇数 PC はアドレス例外だが、
    // 例外ベクタの配送は未接続なので Unimplemented に写す）。
    if pc & 1 != 0 {
        return Err(unimpl(env, 0));
    }
    let acc = Access {
        endian: Endian::Be,
        align: Align::Natural,
        kind: AccessKind::Fetch,
    };
    let mut b2 = [0u8; 2];
    // アドレスバスは24ビットなので pc の上位バイトはバスに出ない。
    if env
        .backend
        .mem
        .read(VirtAddr(pc & 0x00FF_FFFF), &mut b2, acc)
        .is_err()
    {
        return Err(unimpl(env, 0));
    }
    let word = u64::from(u16::from_be_bytes(b2));
    let Some(insn) = decode_model_ex(u128::from(word), 16, true, model.feats) else {
        return Err(unimpl(env, word));
    };
    // 命令長は先頭ワードの EA フィールドから決める。拡張語自体は
    // 意味論側が pc+2 以降から backend 経由で読む。
    let Some(ext) = ea::insn_ext_words(insn, word) else {
        return Err(unimpl(env, word));
    };
    let len = 2 + u64::from(ext) * 2;
    match env.step(|b| sem::exec(b, insn, word, pc)) {
        Ok(()) => {
            if env.backend.ctrl == Ctrl::Fallthrough {
                // PC は32ビットのアドレス空間で折り返す。
                env.pc = (env.pc + len) & 0xFFFF_FFFF;
            }
            Ok(())
        }
        // Trap 系例外は 6 バイトフレームを積んでベクタへ（C14）。
        Err(InterpExit::Exception(e)) if e.kind == ExceptionKind::Trap => env
            .step(|b| sem::deliver(b, e.code as u32, pc, len))
            .map_err(|_| unimpl(env, word)),
        // アドレスエラー（14 バイトフレーム）は未接続。
        Err(InterpExit::Exception(_)) | Err(InterpExit::Unimplemented(_)) => Err(unimpl(env, word)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_engine::run::TrapOutcome;
    use polyisa_guest_m68k::Insn;
    use polyisa_mem::Perms;
    use polyisa_sem::Backend as _;

    /// 語列を RX として写像した環境。`base` が入口。
    fn env_at(base: u64, words: &[u16]) -> BareEnv {
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_m68k::CpuState>());
        env.backend
            .mem
            .map(VirtAddr(base & !0xFFF), 1, Perms(0b111))
            .unwrap();
        let mut bytes = Vec::new();
        for w in words {
            bytes.extend_from_slice(&w.to_be_bytes());
        }
        env.backend.mem.write(VirtAddr(base), &bytes).unwrap();
        env
    }

    /// 何もしないハンドラ。trap 委譲のない裸実行に使う。
    struct NoSys;

    impl TrapHandler for NoSys {
        fn handle_trap(&mut self, _env: &mut BareEnv, _code: u32) -> TrapOutcome {
            TrapOutcome::Unimplemented
        }
    }

    #[test]
    fn nop_sequence_advances_pc() {
        // ページ末尾に nop×3 を置き、続きの 0x2000 は未写像で
        // fetch 失敗 → Unimplemented。
        let mut env = env_at(0x1FFA, &[0x4E71, 0x4E71, 0x4E71]);
        let mut sys = NoSys;
        match run(&mut env, 0x1FFA, M68kModel::m68000(), &mut sys) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x2000),
            o => panic!("unexpected outcome: {o:?}"),
        }
        // 実行入口で 24 ビットバスマスクが掛かる契約を固定する。
        assert_eq!(env.backend.addr_mask, 0x00FF_FFFF);
    }

    #[test]
    fn undecodable_word_is_unimplemented() {
        // nop の次がデコード不能（0x4E74 は 68000 では未割当）→ Unimplemented。
        let mut env = env_at(0x1000, &[0x4E71, 0x4E74]);
        let mut sys = NoSys;
        match run(&mut env, 0x1000, M68kModel::m68000(), &mut sys) {
            Outcome::Unimplemented { pc, word } => {
                assert_eq!(pc, 0x1002);
                assert_eq!(word, 0x4E74);
            }
            o => panic!("unexpected outcome: {o:?}"),
        }
    }

    #[test]
    fn illegal_delivers_vector4_frame() {
        // nop; illegal。illegal はベクタ 4 へ配送される（C14）:
        // SSP に [sr][pc] の 6 バイトフレームを積み、S=1 になって
        // ハンドラへ飛ぶ。ハンドラ先は未定義語で Unimplemented にする。
        let mut env = env_at(0x1000, &[0x4E71, 0x4AFC]);
        env.backend.mem.map(VirtAddr(0), 1, Perms::RW).unwrap();
        env.backend.mem.map(VirtAddr(0x4000), 1, Perms::RW).unwrap();
        env.backend.set(sem::Ssp.state(), 0x4100);
        // ベクタ 4（0x10）→ ハンドラ先頭 0x2000。未定義語を置く。
        env.backend
            .mem
            .write(VirtAddr(0x10), &[0, 0, 0x20, 0x00])
            .unwrap();
        env.backend
            .mem
            .map(VirtAddr(0x2000), 1, Perms(0b111))
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x2000), &[0x4E, 0x74])
            .unwrap();
        let mut sys = NoSys;
        match run(&mut env, 0x1000, M68kModel::m68000(), &mut sys) {
            Outcome::Unimplemented { pc, word } => {
                assert_eq!(pc, 0x2000);
                assert_eq!(word, 0x4E74);
            }
            o => panic!("unexpected outcome: {o:?}"),
        }
        // フレーム: ssp = 0x4100-6、[sr][積み pc=0x1002]（illegal は
        // 命令自身の先頭）。S=1・T=0 になっている。
        assert_eq!(env.backend.get(sem::Ssp.state()), 0x40FA);
        assert_eq!(env.backend.get(sem::sr_ref()) & 0x2000, 0x2000);
        let mut buf = [0u8; 6];
        env.backend
            .mem
            .read(
                VirtAddr(0x40FA),
                &mut buf,
                Access {
                    endian: Endian::Be,
                    align: Align::Natural,
                    kind: AccessKind::DataRead,
                },
            )
            .unwrap();
        assert_eq!(&buf[2..6], &[0x00, 0x00, 0x10, 0x02]);
    }

    #[test]
    fn odd_pc_is_unimplemented() {
        let mut env = env_at(0x1000, &[0x4E71]);
        let mut sys = NoSys;
        match run(&mut env, 0x1001, M68kModel::m68000(), &mut sys) {
            Outcome::Unimplemented { pc, word } => {
                assert_eq!(pc, 0x1001);
                assert_eq!(word, 0);
            }
            o => panic!("unexpected outcome: {o:?}"),
        }
    }

    #[test]
    fn insn_ext_words_fixed_is_zero() {
        // F0 形式の固定ワードは拡張語を持たない。
        assert_eq!(ea::insn_ext_words(Insn::Nop, 0x4E71), Some(0));
        assert_eq!(ea::insn_ext_words(Insn::Illegal, 0x4AFC), Some(0));
    }
}
