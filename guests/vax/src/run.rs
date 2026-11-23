// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! VAX の実行ステップ。r15(PC) から可変長の命令をバイト単位で
//! フェッチして解読し、指定子を評価して意味論を実行する。
//!
//! フェッチは必要なバイトを 1 つずつ読む。オペコード語（1/2
//! バイト）のあと、命令の指定子シグネチャ（`insn_ops`）に従って
//! 指定子を 1 個ずつ読み、消費長は `spec_len` のモード表で決める
//! —— 過剰読みをしないので、指定子の拡張バイトがページを跨いでも
//! 触れた分だけフェッチフォルトする。長さだけの経路と完全デコード
//! の一致は VX3 のテストが保証する。
//!
//! 例外の扱いは fault / trap の正本規則に従う: fault 系（フェッチ・
//! アクセス不能の ACV、予約アドレッシングモード、予約命令・特権
//! 命令）は復帰先が命令先頭なので `env.pc` を動かさず配送し、
//! Handled なら同じ命令をやり直す。trap 系（BPT・算術）は復帰先が
//! 次の命令なので `env.pc` を命令終端に進めてから配送する。
//!
//! 解読不能（予約命令）とモデルの機能集合にない命令（サブセット
//! 命令の補完要求）は `emul_dispatch` が振り分ける: hook（既定）
//! なら OS パーソナリティの `handle_unimpl` を先に試し、受けない
//! 場合と scb のときはクラス別の実機 fault に写す —— 省略された
//! 浮動小数点群は予約命令 fault、文字列・十進・CRC・EDITPC 群は
//! 補完例外（SCB 0xC8/0xCC、PSL<FPD> で開始/継続）。
//! 未実装の命令意味論は `Outcome::Unimplemented`（m68k 先例）。
//!
//! 中断可能命令（VX7 以降が本体を実装する）は「反復 1 回 =
//! 1 ステップ」で走る: `sem::partial_save` が PSL<FPD>=1 を立てて
//! PC を命令先頭へ戻すので、次のステップが同じ命令へ再入し
//! `partial_resume` で続行する。
//! Ref: SPEC-VAX-ARM.

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::InterpExit;
use polyisa_engine::run::{Outcome, TrapHandler, TrapOutcome};
use polyisa_mem::{Access, AccessKind, AddressSpace, Align, Endian, VirtAddr};
use polyisa_sem::{Backend as _, ExceptionKind};

use crate::specifier::{self, OpTy};
use crate::{
    DEFAULT_FEATS, EMUL_DISPATCH_SCB, EmulDispatchParam, FEAT_BITS, FEAT_HFP, decode_model_ex, reg,
    sem,
};

/// フェッチのアクセス属性。整列は要求しない（命令はバイト整列）。
const FETCH: Access = Access {
    endian: Endian::Le,
    align: Align::Unaligned,
    kind: AccessKind::Fetch,
};

/// 命令ストリームの読み出し器。バイト単位で必要分だけ読む。
struct Fetch<'a> {
    mem: &'a AddressSpace,
    /// 命令の先頭アドレス。
    pc: u32,
    /// 読み済みのバイト列（オペコード語から連続）。
    buf: Vec<u8>,
}

impl Fetch<'_> {
    /// 次の 1 バイトを読んで `buf` に足す。
    fn byte(&mut self) -> Option<u8> {
        let a = self.pc.wrapping_add(self.buf.len() as u32);
        let mut b = [0u8];
        self.mem.read(VirtAddr(u64::from(a)), &mut b, FETCH).ok()?;
        self.buf.push(b[0]);
        Some(b[0])
    }

    /// オペランド 1 個ぶんを読み、その消費バイト数を返す。
    /// 分岐変位（.b）は指定子バイトを持たず幅ぶん読むだけ。
    /// それ以外は `spec_len` のモード表で長さが確定するまで
    /// 1 バイトずつ足す（入れ子の index でも無限に伸びないよう
    /// 反復を打ち切る）。
    fn opnd(&mut self, ty: OpTy) -> Option<u32> {
        if ty.acc == specifier::Acc::B {
            for _ in 0..ty.width.bytes() {
                self.byte()?;
            }
            return Some(ty.width.bytes());
        }
        let start = self.buf.len();
        for _ in 0..64 {
            if specifier::spec_len(&self.buf[start..], ty.width).is_some() {
                return Some((self.buf.len() - start) as u32);
            }
            self.byte()?;
        }
        None
    }
}

/// `TrapOutcome` を `Outcome` 面へ写す。`pc`/`word` は報告用。
fn trap_result(pc: u32, word: u128, t: TrapOutcome) -> Result<(), Outcome> {
    match t {
        TrapOutcome::Handled => Ok(()),
        TrapOutcome::Exit(code) => Err(Outcome::Exit(u64::from(code))),
        TrapOutcome::Blocked => Err(Outcome::Deadlock),
        TrapOutcome::Unimplemented => Err(Outcome::Unimplemented {
            pc: u64::from(pc),
            word,
        }),
    }
}

/// fault を OS パーソナリティへ配送する。復帰先は命令先頭 —
/// `env.pc` は命令先頭のままにして、Handled ならやり直す。
fn fault(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    pc: u32,
    code: u32,
    word: u128,
) -> Result<(), Outcome> {
    env.pc = u64::from(pc);
    let t = sys.handle_trap(env, code);
    trap_result(pc, word, t)
}

/// 命令を遮っている機能旗を探す。モデルの集合では解けずフル
/// 集合では解ける命令を呼ぶ。`when` は単一の旗なので、それを
/// 抜いた集合で解けなくなる旗が一意に見つかる（旗を持たない
/// 命令は None）。
fn gate(word: u32) -> Option<u128> {
    let len = if word & 0xff >= 0xfd { 16 } else { 8 };
    FEAT_BITS
        .iter()
        .map(|&(_, bit)| bit)
        .find(|&bit| decode_model_ex(u128::from(word), len, false, DEFAULT_FEATS & !bit).is_none())
}

/// 解読不能・機能集合にない・未実装の命令。emul_dispatch=hook
/// （既定）なら OS パーソナリティの補完経路（`handle_unimpl`）を
/// 先に試す。受けなければクラス別の実機 fault に写す —— 省略
/// された浮動小数点群（hfp）は予約命令 fault、文字列・十進・
/// CRC・EDITPC 群は補完例外。補完例外のベクタは PSL<FPD> で
/// 開始（0xC8）/継続（0xCC）を振り分ける正本規則。復帰先は
/// いずれも命令先頭（OS 側の補完が命令を再評価して終端へ進める
/// 契約）。実機が配送前に行う指定子評価と例外フレームのスタック
/// 積みはこの裸モデルの範囲外。
// Gap: GAP-0079
// Ref: SPEC-VAX-ARM（サブセット化の章）, SPEC-VAX-MICROVAX §3.9.
fn unimpl_insn(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    pc: u32,
    word: u32,
) -> Result<(), Outcome> {
    if env.backend.param::<EmulDispatchParam>() != EMUL_DISPATCH_SCB
        && sys.handle_unimpl(env, u64::from(pc), u64::from(word)) == TrapOutcome::Handled
    {
        return Ok(());
    }
    let code = match gate(word) {
        Some(FEAT_HFP) => sem::scb::PRIV_INSN,
        Some(_) => {
            if sem::fpd(&env.backend) {
                sem::scb::EMUL_CONT
            } else {
                sem::scb::EMUL_START
            }
        }
        None => sem::scb::PRIV_INSN,
    };
    fault(env, sys, pc, code, u128::from(word))
}

/// 1 命令ぶんのフェッチ・解読・意味論。`env.pc` は命令の先頭
/// アドレスで、命令の終端（次の命令）・分岐（r15 への書き込み）・
/// 退出で止まる。
pub fn step(env: &mut BareEnv, sys: &mut impl TrapHandler, feats: u128) -> Result<(), Outcome> {
    let pc = env.pc as u32;
    let mut f = Fetch {
        mem: &env.backend.mem,
        pc,
        buf: Vec::with_capacity(8),
    };
    // オペコード語（1 バイト、または 0xfd-0xff 接頭の 2 バイト）。
    let Some(b0) = f.byte() else {
        return fault(env, sys, pc, sem::scb::ACV, 0);
    };
    let (word, oplen) = if b0 >= 0xfd {
        match f.byte() {
            Some(b1) => (u32::from(b0) | u32::from(b1) << 8, 2u32),
            None => return fault(env, sys, pc, sem::scb::ACV, u128::from(b0)),
        }
    } else {
        (u32::from(b0), 1)
    };
    let Some(insn) = decode_model_ex(u128::from(word), oplen * 8, false, feats) else {
        // 全機能なら解ける語はサブセット命令の補完要求、それ以外は
        // 予約命令 fault。
        if decode_model_ex(u128::from(word), oplen * 8, false, DEFAULT_FEATS).is_some() {
            return unimpl_insn(env, sys, pc, word);
        }
        return fault(env, sys, pc, sem::scb::PRIV_INSN, u128::from(word));
    };
    // 指定子列を命令のシグネチャどおりに読む。
    let tys = specifier::insn_ops(insn);
    let mut pos = Vec::with_capacity(tys.len());
    for &ty in tys {
        let s = f.buf.len() as u32;
        match f.opnd(ty) {
            Some(_) => pos.push((pc.wrapping_add(s), pc.wrapping_add(f.buf.len() as u32))),
            None => return fault(env, sys, pc, sem::scb::ACV, u128::from(word)),
        }
    }
    let Some(fetched) = specifier::decode_insn_ex(&f.buf, feats) else {
        // fetch 経路と完全デコードの不一致（内部不整合）。
        return Err(Outcome::Unimplemented {
            pc: u64::from(pc),
            word: u128::from(word),
        });
    };
    // 実行中の r15 は命令の終端（次の命令の位置）。意味論側の
    // PC 相対・即値の評価は pos の絶対位置で決まる。
    let next = pc.wrapping_add(fetched.len);
    sem::r_set(&mut env.backend, reg::PC as u8, next);
    match env.step(|b| sem::exec(b, &fetched, pc, &pos)) {
        Ok(()) => {
            // 制御転送は r15 への書き込みとして表れる（movl #x,pc も
            // 分岐命令も r15 を書く）。中断した反復命令は r15 を命令
            // 先頭へ戻すので同じ命令へ再入する。
            env.pc = u64::from(sem::r_get(&env.backend, reg::PC as u8));
            Ok(())
        }
        Err(InterpExit::Exception(e)) => {
            // fault 系は復帰先が命令先頭（やり直し）、trap 系は次の
            // 命令。メモリ系の例外はコードを ACV に読み替える。
            match e.kind {
                ExceptionKind::Trap | ExceptionKind::Break => env.pc = u64::from(next),
                _ => env.pc = u64::from(pc),
            }
            let code = if e.code != 0 {
                e.code as u32
            } else if matches!(e.kind, ExceptionKind::PageFault | ExceptionKind::Align) {
                sem::scb::ACV
            } else {
                sem::scb::RESERVED_OPERAND
            };
            let t = sys.handle_trap(env, code);
            trap_result(pc, u128::from(word), t)
        }
        Err(InterpExit::Unimplemented(_)) => unimpl_insn(env, sys, pc, word),
    }
}
