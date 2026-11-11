// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! IA-64 最小の命令意味論。バックエンドに対して総称的に書く.
//!
//! バンドル・述語実行・回転の最小形を確かめることが目的である。
//! 1 ステップで 3 スロットを順に実行し、分岐が成立したら残りを実行しない。
//! 41ビットスロット・テンプレート・レジスタスタック・NaT/ALAT・
//! 例外のスロット番号報告は試作に含まない。
//!
//! 出典は SPEC-IA64-SDM Rev 2.3 (2010-05) である。
//! Ref: SPEC-IA64-SDM (Rev 2.3).

use polyisa_sem::{Backend, Cmp, Flow, StateArray, StateRef, W32, W64};

use super::CpuState;

/// 汎用レジスタ番号（静的域 0〜31）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Gpr(pub u8);

impl Gpr {
    /// CPU 状態の対応する要素を指す。
    pub fn state(self) -> StateRef<W64> {
        StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, g) + (self.0 as usize) * 8)
    }
}

/// 述語番号（0〜7）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Pred(pub u8);

/// 回転レジスタ番号（論理番号 0〜7）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rot(pub u8);

fn rot_array() -> StateArray<W64> {
    StateArray::<W64>::from_layout(core::mem::offset_of!(CpuState, rot), 8)
}

fn pr_base() -> usize {
    core::mem::offset_of!(CpuState, pr)
}

fn rrb_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, rrb))
}

fn taken_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, taken))
}

fn not_taken<B: Backend>(b: &mut B) -> B::B {
    let t: B::V<W64> = b.get(taken_ref());
    let zero = b.konst::<W64>(0);
    b.cmp::<W64>(Cmp::Eq, t, zero)
}

/// 3 スロットを 1 ステップで順に実行する。分岐が成立したら残りは実行しない。
pub fn bundle<B: Backend, F0, F1, F2>(b: &mut B, s0: F0, s1: F1, s2: F2) -> Flow<B>
where
    F0: FnOnce(&mut B) -> Flow<B>,
    F1: FnOnce(&mut B) -> Flow<B>,
    F2: FnOnce(&mut B) -> Flow<B>,
{
    let zero = b.konst::<W64>(0);
    b.set(taken_ref(), zero);
    s0(b)?;
    let go1 = not_taken(b);
    b.if_then(go1, |b| {
        s1(b)?;
        let go2 = not_taken(b);
        b.if_then(go2, s2)?;
        Ok(())
    })?;
    let clear = b.konst::<W64>(0);
    b.set(taken_ref(), clear);
    Ok(())
}

fn write_gpr<B: Backend>(b: &mut B, rd: Gpr, v: B::V<W64>) {
    b.set(rd.state(), v);
}

fn read_gpr<B: Backend>(b: &mut B, r: Gpr) -> B::V<W64> {
    b.get(r.state())
}

/// 述語を読む。
fn read_pred<B: Backend>(b: &mut B, p: Pred) -> B::V<W64> {
    let i = b.konst::<W64>(p.0 as u64);
    let idx: B::V<W32> = b.trunc::<W64, W32>(i);
    b.get_indexed(StateArray::<W64>::from_layout(pr_base(), 8), idx)
}

/// ADD。述語 p0（常に真）相当の無条件版。
pub fn add<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read_gpr(b, rs1);
    let y = read_gpr(b, rs2);
    let v = b.add::<W64>(x, y);
    write_gpr(b, rd, v);
    Ok(())
}

/// SUB。
pub fn sub<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read_gpr(b, rs1);
    let y = read_gpr(b, rs2);
    let v = b.sub::<W64>(x, y);
    write_gpr(b, rd, v);
    Ok(())
}

/// ADD.PRED。qp が真のときだけ書き込む。
pub fn add_pred<B: Backend>(b: &mut B, qp: Pred, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read_gpr(b, rs1);
    let y = read_gpr(b, rs2);
    let v = b.add::<W64>(x, y);
    let p = read_pred(b, qp);
    let zero = b.konst::<W64>(0);
    let cond = b.cmp::<W64>(Cmp::Ne, p, zero);
    b.if_then(cond, |b| {
        write_gpr(b, rd, v);
        Ok(())
    })?;
    Ok(())
}

/// 回転位置を RRB 加算で求める（8本のため下位3ビットで包む）。
pub fn rot_index<B: Backend>(b: &mut B, r: Rot) -> B::V<W64> {
    let base: B::V<W64> = b.get(rrb_ref());
    let off = b.konst::<W64>((r.0 as u64) & 7);
    let sum = b.add::<W64>(base, off);
    let mask = b.konst::<W64>(7);
    b.and::<W64>(sum, mask)
}

/// ADD.ROT。回転レジスタを RRB 加算で読む。
pub fn add_rot<B: Backend>(b: &mut B, rd: Gpr, rs1: Rot, rs2: Gpr) -> Flow<B> {
    let idx = rot_index(b, rs1);
    let idx32: B::V<W32> = b.trunc::<W64, W32>(idx);
    let x: B::V<W64> = b.get_indexed(rot_array(), idx32);
    let y = read_gpr(b, rs2);
    let v = b.add::<W64>(x, y);
    write_gpr(b, rd, v);
    Ok(())
}

/// NOP。何もしない。
pub fn nop<B: Backend>(_b: &mut B) -> Flow<B> {
    Ok(())
}

/// BR。バンドルアドレスを進め、後続スロットを止める。
pub fn br<B: Backend>(b: &mut B, target: u64) -> Flow<B> {
    let pc = StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, pc));
    let t = b.konst::<W64>(target);
    b.set(pc, t);
    let one = b.konst::<W64>(1);
    b.set(taken_ref(), one);
    Ok(())
}
