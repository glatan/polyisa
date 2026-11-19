// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! m68k 最小の命令意味論。バックエンドに対して総称的に書く。
//!
//! 骨格の段階なので、ここでは CPU 状態の参照と、16ビット固定命令の
//! 振り分けだけを持つ。EA モードの解釈はデコード方式の決定後に足す。
//!
//! 出典は SPEC-M68K-PRM (M68000PM/AD Rev 1) である。
//! Ref: SPEC-M68K-PRM (Rev 1).

use polyisa_sem::{Backend, Cmp, ExceptionKind, Flow, GuestException, StateRef, W8, W32};

use super::CpuState;

/// データレジスタ番号（D0〜D7）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct D(pub u8);

/// アドレスレジスタ番号（A0〜A6）。A7 は `Usp`/`Ssp` で指す。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct A(pub u8);

/// ユーザースタックポインタ（A7、SR.S=0 のとき有効）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Usp;

/// スーパーバイザスタックポインタ（A7、SR.S=1 のとき有効）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ssp;

impl D {
    /// CPU 状態の対応する要素を指す。
    #[must_use]
    pub const fn state(self) -> StateRef<W32> {
        StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, d) + self.0 as usize * 4)
    }
}

impl A {
    /// CPU 状態の対応する要素を指す。
    ///
    /// A7 は `a` 配列にない。`Usp`/`Ssp` を SR.S で選んで使うこと。
    #[must_use]
    pub const fn state(self) -> StateRef<W32> {
        assert!(self.0 < 7, "A7 は Usp/Ssp で指す");
        StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, a) + self.0 as usize * 4)
    }
}

impl Usp {
    /// CPU 状態の対応する要素を指す。
    #[must_use]
    pub const fn state(self) -> StateRef<W32> {
        StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, usp))
    }
}

impl Ssp {
    /// CPU 状態の対応する要素を指す。
    #[must_use]
    pub const fn state(self) -> StateRef<W32> {
        StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, ssp))
    }
}

/// pc を指す。
#[must_use]
pub const fn pc_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, pc))
}

/// SR 全体を指す（システムバイト: T/S/IPL、ユーザーバイト: CCR）。
#[must_use]
pub const fn sr_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, sr))
}

/// CCR（SR のユーザーバイト。X N Z V C）を指す。
#[must_use]
pub const fn ccr_ref() -> StateRef<W8> {
    StateRef::<W8>::from_offset(core::mem::offset_of!(CpuState, sr))
}

/// アドレスレジスタ `n`（0〜7）を読む。n=7 は SR.S で USP/SSP を選ぶ。
pub fn areg<B: Backend>(b: &mut B, n: u8) -> B::V<W32> {
    debug_assert!(n < 8);
    if n == 7 {
        let s = b.get(sr_ref());
        let mask = b.konst::<W32>(1 << sr_bit::S);
        let masked = b.and(s, mask);
        let zero = b.konst::<W32>(0);
        let sup = b.cmp(Cmp::Ne, masked, zero);
        let ssp = b.get(Ssp.state());
        let usp = b.get(Usp.state());
        b.select(sup, ssp, usp)
    } else {
        b.get(A(n).state())
    }
}

/// アドレスレジスタ `n`（0〜7）に書く。n=7 は SR.S で USP/SSP を選ぶ。
/// 保持先が実行時に決まるので `if_then_else` で書き分ける。
pub fn set_areg<B: Backend>(b: &mut B, n: u8, v: B::V<W32>) -> Flow<B> {
    debug_assert!(n < 8);
    if n == 7 {
        let s = b.get(sr_ref());
        let mask = b.konst::<W32>(1 << sr_bit::S);
        let masked = b.and(s, mask);
        let zero = b.konst::<W32>(0);
        let sup = b.cmp(Cmp::Ne, masked, zero);
        b.if_then_else(
            sup,
            |b| {
                b.set(Ssp.state(), v);
                Ok(())
            },
            |b| {
                b.set(Usp.state(), v);
                Ok(())
            },
        )
    } else {
        b.set(A(n).state(), v);
        Ok(())
    }
}

/// SR の各ビット位置。
// Ref: SPEC-M68K-PRM (Rev 1) §Status Register.
pub mod sr_bit {
    /// キャリー（C）。
    pub const C: u32 = 0;
    /// オーバーフロー（V）。
    pub const V: u32 = 1;
    /// ゼロ（Z）。
    pub const Z: u32 = 2;
    /// 負（N）。
    pub const N: u32 = 3;
    /// 拡張（X）。
    pub const X: u32 = 4;
    /// 割り込みマスクの下位ビット（I0）。I0〜I2 が bit 8-10。
    pub const I0: u32 = 8;
    /// スーパーバイザ状態（S）。
    pub const S: u32 = 13;
    /// トレース（T）。
    pub const T: u32 = 15;
}

/// 骨格の16ビット固定命令を振り分ける。
///
/// `insn` は生成デコーダの結果、`w` は命令ワード。`pc` は命令の先頭
/// アドレス。nop と illegal だけを処理し、残りは未実装として
/// `Undefined` に落とす。rts/rtr/rte のスタック復帰と reset の外部
/// 通知は EA・例外処理の経路と一緒に足す。
pub fn exec<B: Backend>(b: &mut B, insn: super::Insn, w: u64, _pc: u64) -> Flow<B> {
    match insn {
        super::Insn::Nop => Ok(()),
        super::Insn::Illegal => Err(b.raise(GuestException {
            kind: ExceptionKind::Trap,
            // m68k の例外ベクタ番号 4（Illegal Instruction）。
            code: 4,
            addr: None,
            in_delay_slot: false,
        })),
        _ => Err(b.raise(GuestException {
            kind: ExceptionKind::Undefined,
            // 診断のため命令ワードを残す。
            code: w,
            addr: None,
            in_delay_slot: false,
        })),
    }
}
