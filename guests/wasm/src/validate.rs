// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 関数本体の検証。制御フレームを持たない void 関数だけを対象にする。
//!
//! 各命令の前後でオペランドスタックの高さが仕様と合うかを見る。
//! `unreachable` の後はスタックを多相にし、終わりまでポップを許す。
//! 結果型は空なので、多相でなければ終わりの高さは 0 でなければならない。
//! 分岐はラベルを持たない試作のため、スタック高を変えない。
//!
//! Ref: SPEC-WASM-CORE (3.0).

/// 検証する命令。即値の値は型に影響しないので持たない。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Nop,
    Unreachable,
    Drop,
    LocalGet(u32),
    LocalSet(u32),
    I32Const,
    I32Add,
    Br,
}

/// 検証が拒否した理由。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// オペランドが足りない。
    StackUnderflow,
    /// ローカル番号が宣言数以上。
    LocalRange,
    /// void 関数の終わりにオペランドが残っている。
    StackLeft,
}

/// `nlocals` 個のローカルを持つ void 関数本体を検証する。
pub fn validate(nlocals: u32, ops: &[Op]) -> Result<(), Reject> {
    let mut height = 0u32;
    let mut poly = false;
    for op in ops {
        match *op {
            Op::Nop | Op::Br => {}
            Op::Unreachable => poly = true,
            Op::I32Const => push(&mut height, poly),
            Op::LocalGet(i) => {
                local(nlocals, i)?;
                push(&mut height, poly);
            }
            Op::Drop => pop(&mut height, poly, 1)?,
            Op::LocalSet(i) => {
                local(nlocals, i)?;
                pop(&mut height, poly, 1)?;
            }
            Op::I32Add => {
                pop(&mut height, poly, 2)?;
                push(&mut height, poly);
            }
        }
    }
    if !poly && height != 0 {
        return Err(Reject::StackLeft);
    }
    Ok(())
}

fn local(nlocals: u32, i: u32) -> Result<(), Reject> {
    if i >= nlocals {
        Err(Reject::LocalRange)
    } else {
        Ok(())
    }
}

fn push(height: &mut u32, poly: bool) {
    if !poly {
        *height += 1;
    }
}

fn pop(height: &mut u32, poly: bool, n: u32) -> Result<(), Reject> {
    if poly {
        return Ok(());
    }
    if *height < n {
        return Err(Reject::StackUnderflow);
    }
    *height -= n;
    Ok(())
}
