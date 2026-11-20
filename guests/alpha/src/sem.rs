// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Alpha AXP の命令意味論。
//!
//! 段階16-4 の範囲は実行ループが必要とする最小集合:
//! `lda`/`ldah`（アドレス形成＝定数ロード）、無条件の制御移譲
//! （`br`/`bsr`/`jmp`/`jsr`/`jsr_coroutine`/`ret`）、`call_pal` の
//! トラップ発生、PAL 予約オペコードの Undefined 例外。
//! 条件分岐は段階16-8、load/store は段階16-7、整数 Operate は
//! 段階16-5 で足す（それ以外の命令は `Ok(false)` を返し、
//! 呼び出し側が未実装として扱う）。
//!
//! 出典は SPEC-ALPHA-ARM である。
//! Ref: SPEC-ALPHA-ARM.

use polyisa_sem::{Backend, StateRef, W64};

use super::{CpuState, Insn, ops_fbrw, ops_fmbr, ops_fmld, ops_fpal, ops_fret};

/// 整数レジスタ参照。r31 は読み出しで常に 0、書き込みは破棄される。
// Ref: SPEC-ALPHA-ARM §Integer registers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Gpr(pub u8);

impl Gpr {
    /// 状態の位置。
    #[must_use]
    pub fn state(self) -> StateRef<W64> {
        StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, r) + (self.0 as usize) * 8)
    }

    /// 読み出し。r31 はハード的に 0 を返す。
    pub fn get<B: Backend>(self, b: &mut B) -> B::V<W64> {
        if self.0 == 31 {
            b.konst::<W64>(0)
        } else {
            b.get(self.state())
        }
    }

    /// 書き込み。r31 への書き込みは捨てる。
    pub fn set<B: Backend>(self, b: &mut B, v: B::V<W64>) {
        if self.0 != 31 {
            b.set(self.state(), v);
        }
    }
}

/// FP レジスタ参照。f31 は読み出しで常に 0（書き込みは破棄）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fpr(pub u8);

impl Fpr {
    /// 状態の位置。
    #[must_use]
    pub fn state(self) -> StateRef<W64> {
        StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, f) + (self.0 as usize) * 8)
    }
}

/// プログラムカウンタの状態位置。
#[must_use]
pub fn pc_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, pc))
}

/// FPCR の状態位置。
#[must_use]
pub fn fpcr_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, fpcr))
}

/// PAL の rduniq/wruniq が転送するユニーク値の状態位置。
#[must_use]
pub fn uniq_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, uniq))
}

/// `disp16` の符号拡張値。
fn sext16(v: u32) -> i64 {
    i64::from(v as u16 as i16)
}

/// `disp21` の符号拡張値。分岐変位はさらに左2シフトして使う。
fn sext21(v: u32) -> i64 {
    i64::from(v) << 43 >> 43
}

/// 命令の意味論。`Ok(true)` は実行完了、`Ok(false)` はこの段階では
/// 未実装（呼び出し側が `Outcome::Unimplemented` に写す）。
/// `pc` はこの命令の番地。
// Ref: SPEC-ALPHA-ARM.
pub fn exec<B: Backend>(b: &mut B, insn: Insn, word: u32, pc: u64) -> Result<bool, B::Exit> {
    match insn {
        // lda ra, disp(rb): ra = rb + sext(disp16)。
        // ldah ra, disp(rb): ra = rb + (sext(disp16) << 16)。
        // rb=31 なら定数ロードとして働く（実行ループの最小命令）。
        // Ref: SPEC-ALPHA-ARM §4.3 lda/ldah.
        Insn::Lda | Insn::Ldah => {
            let o = ops_fmld(u128::from(word));
            let rb = Gpr(o.rb as u8).get(b);
            // ldah は変位だけを 65536 倍してから加える（rb はシフトしない）。
            let disp = sext16(o.disp16) << if insn == Insn::Ldah { 16 } else { 0 };
            let d = b.konst::<W64>(disp as u64);
            let v = b.add(rb, d);
            Gpr(o.ra as u8).set(b, v);
            Ok(true)
        }
        // br ra, disp / bsr ra, disp。ra = pc+4 へリンクして
        // pc+4+sext(disp21)<<2 へ飛ぶ。br の ra=31 は hint だけなので
        // 同じコードで処理できる。
        // Ref: SPEC-ALPHA-ARM §4.3 br/bsr.
        Insn::Br | Insn::Bsr => {
            let o = ops_fbrw(u128::from(word));
            let link = b.konst::<W64>(pc + 4);
            Gpr(o.ra as u8).set(b, link);
            let target = pc
                .wrapping_add(4)
                .wrapping_add((sext21(o.disp21) << 2) as u64);
            let target = b.konst::<W64>(target);
            b.jump(target);
            Ok(true)
        }
        // jmp/jsr/jsr_coroutine ra, (rb), hint。
        // ra = pc+4 を保持して (rb & ~3) へ飛ぶ。hint は予測の手掛かり
        // で、インタプリタでは使わない。
        // Ref: SPEC-ALPHA-ARM §4.3 jmp/jsr/jsr_coroutine.
        Insn::Jmp | Insn::Jsr | Insn::JsrCoroutine => {
            let o = ops_fmbr(u128::from(word));
            let rb = Gpr(o.rb as u8).get(b);
            let mask = b.konst::<W64>(!3);
            let target = b.and(rb, mask);
            let link = b.konst::<W64>(pc + 4);
            Gpr(o.ra as u8).set(b, link);
            b.jump(target);
            Ok(true)
        }
        // ret zero, (rb), hint: (rb & ~3) へ飛ぶ（ra を書かない）。
        // Ref: SPEC-ALPHA-ARM §4.3 ret.
        Insn::Ret => {
            let o = ops_fret(u128::from(word));
            let rb = Gpr(o.rb as u8).get(b);
            let mask = b.konst::<W64>(!3);
            let target = b.and(rb, mask);
            b.jump(target);
            Ok(true)
        }
        // call_pal: PALcode 呼び出し。OS パーソナリティが機能番号で
        // 振り分けるため、code に palfn を載せて Trap を上げる。
        // Ref: SPEC-ALPHA-ARM §4.11 call_pal.
        Insn::CallPal => {
            let o = ops_fpal(u128::from(word));
            Err(b.raise(polyisa_sem::GuestException {
                kind: polyisa_sem::ExceptionKind::Trap,
                code: u64::from(o.palfn),
                addr: None,
                in_delay_slot: false,
            }))
        }
        // PAL 予約オペコード（0x19/0x1B/0x1D/0x1E/0x1F）は
        // Reserved Instruction Fault。Undefined として上げる。
        // Ref: SPEC-ALPHA-ARM §4.11.
        Insn::Pal19 | Insn::Pal1b | Insn::Pal1d | Insn::Pal1e | Insn::Pal1f => {
            Err(b.raise(polyisa_sem::GuestException {
                kind: polyisa_sem::ExceptionKind::Undefined,
                code: u64::from(word),
                addr: None,
                in_delay_slot: false,
            }))
        }
        _ => Ok(false),
    }
}
