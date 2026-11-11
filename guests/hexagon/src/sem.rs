// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Hexagon 最小の命令意味論。バックエンドに対して総称的に書く.
//!
//! パケットのステップ構成を確かめることが目的である。
//! スロット命令はレジスタに直接書かずパケットバッファに溜め、
//! パケットの終わりで `commit` して一括反映する。
//! `.new` オペランドは同じパケットの一時値（バッファ）を読む。
//! ループ終端のパケットでは、commit が LC0 と SA0 から次の pc を決める。
//! duplex・imm 拡張・HVX は試作に含まない。
//!
//! 出典は SPEC-HEXAGON-PRM V73 (80-N2040-53) である。
//! Ref: SPEC-HEXAGON-PRM (V73).

use polyisa_sem::{Backend, Cmp, Flow, StateRef, W32};

use super::CpuState;

/// 汎用レジスタ番号。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct R(pub u8);

impl R {
    /// CPU 状態の対応する要素を指す。
    pub fn state(self) -> StateRef<W32> {
        StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, r) + (self.0 as usize) * 4)
    }

    fn pkt_state(self) -> StateRef<W32> {
        StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, pkt) + (self.0 as usize) * 4)
    }
}

/// pc を指す。
pub fn pc_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, pc))
}

fn pkt_valid_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, pkt_valid))
}

/// ループ 0 の開始アドレス。
pub fn sa0_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, sa0))
}

/// ループ 0 の残り回数。
pub fn lc0_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, lc0))
}

/// パケットがループ 0 の終端なら 1。
pub fn loop_end_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, loop_end))
}

/// このパケットをループ 0 の終端にする。次の commit が回数を見て pc を決める。
pub fn mark_loop_end<B: Backend>(b: &mut B) -> Flow<B> {
    let one = b.konst::<W32>(1);
    b.set(loop_end_ref(), one);
    Ok(())
}

fn read_reg<B: Backend>(b: &mut B, r: R) -> B::V<W32> {
    b.get(r.state())
}

fn buffer<B: Backend>(b: &mut B, rd: R, v: B::V<W32>) {
    b.set(rd.pkt_state(), v);
    // pkt_valid はレジスタ番号のビットマスクである。
    let cur: B::V<W32> = b.get(pkt_valid_ref());
    let one = b.konst::<W32>(1);
    let shift = b.konst::<W32>(rd.0 as u32);
    let bit = b.shl::<W32>(one, shift);
    let next = b.or::<W32>(cur, bit);
    b.set(pkt_valid_ref(), next);
}

/// パケット内で確定した値を読む（.new）。試作ではバッファを直接読む。
fn read_new<B: Backend>(b: &mut B, r: R) -> B::V<W32> {
    b.get(r.pkt_state())
}

/// ADD。パケットバッファに溜める。
pub fn add<B: Backend>(b: &mut B, rd: R, rs1: R, rs2: R) -> Flow<B> {
    let x = read_reg(b, rs1);
    let y = read_reg(b, rs2);
    let v = b.add::<W32>(x, y);
    buffer(b, rd, v);
    Ok(())
}

/// SUB。パケットバッファに溜める。
pub fn sub<B: Backend>(b: &mut B, rd: R, rs1: R, rs2: R) -> Flow<B> {
    let x = read_reg(b, rs1);
    let y = read_reg(b, rs2);
    let v = b.sub::<W32>(x, y);
    buffer(b, rd, v);
    Ok(())
}

/// AND。パケットバッファに溜める。
pub fn and<B: Backend>(b: &mut B, rd: R, rs1: R, rs2: R) -> Flow<B> {
    let x = read_reg(b, rs1);
    let y = read_reg(b, rs2);
    let v = b.and::<W32>(x, y);
    buffer(b, rd, v);
    Ok(())
}

/// OR。パケットバッファに溜める。
pub fn or<B: Backend>(b: &mut B, rd: R, rs1: R, rs2: R) -> Flow<B> {
    let x = read_reg(b, rs1);
    let y = read_reg(b, rs2);
    let v = b.or::<W32>(x, y);
    buffer(b, rd, v);
    Ok(())
}

/// ADD.NEW。rs1 の .new（一時値）と rs2 を加える。
pub fn add_new<B: Backend>(b: &mut B, rd: R, rs1_new: R, rs2: R) -> Flow<B> {
    let x = read_new(b, rs1_new);
    let y = read_reg(b, rs2);
    let v = b.add::<W32>(x, y);
    buffer(b, rd, v);
    Ok(())
}

/// パケットの終わりで書き込みをまとめて反映する。
/// pkt_valid のビットが立つレジスタだけコピーし、他は保持する。
pub fn commit<B: Backend>(b: &mut B) -> Flow<B> {
    let mask: B::V<W32> = b.get(pkt_valid_ref());
    for i in 0..32u32 {
        let shift = b.konst::<W32>(i);
        let shifted = b.shr_l::<W32>(mask, shift);
        let one = b.konst::<W32>(1);
        let bit = b.and::<W32>(shifted, one);
        let zero = b.konst::<W32>(0);
        let written = b.cmp::<W32>(polyisa_sem::Cmp::Ne, bit, zero);
        let new_v: B::V<W32> = b.get(StateRef::<W32>::from_offset(
            core::mem::offset_of!(CpuState, pkt) + (i as usize) * 4,
        ));
        let old_v: B::V<W32> = b.get(StateRef::<W32>::from_offset(
            core::mem::offset_of!(CpuState, r) + (i as usize) * 4,
        ));
        let chosen = b.select::<W32>(written, new_v, old_v);
        b.set(
            StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, r) + (i as usize) * 4),
            chosen,
        );
    }
    let zero = b.konst::<W32>(0);
    b.set(pkt_valid_ref(), zero);
    apply_loop_end(b)?;
    Ok(())
}

/// 終端パケットの次 pc。LC0 が 2 以上なら SA0 へ戻り、1 なら回数だけ消して pc は維持する。
fn apply_loop_end<B: Backend>(b: &mut B) -> Flow<B> {
    let end: B::V<W32> = b.get(loop_end_ref());
    let zero = b.konst::<W32>(0);
    let is_end = b.cmp::<W32>(Cmp::Ne, end, zero);
    b.if_then(is_end, |b| {
        let lc: B::V<W32> = b.get(lc0_ref());
        let one = b.konst::<W32>(1);
        let cont = b.cmp::<W32>(Cmp::GtU, lc, one);
        let last = b.cmp::<W32>(Cmp::Eq, lc, one);
        b.if_then(cont, |b| {
            let sa: B::V<W32> = b.get(sa0_ref());
            b.set(pc_ref(), sa);
            let dec = b.sub::<W32>(lc, one);
            b.set(lc0_ref(), dec);
            Ok(())
        })?;
        b.if_then(last, |b| {
            let z = b.konst::<W32>(0);
            b.set(lc0_ref(), z);
            Ok(())
        })?;
        Ok(())
    })?;
    let clear = b.konst::<W32>(0);
    b.set(loop_end_ref(), clear);
    Ok(())
}

/// MOV_IMM。imm をパケットバッファに溜める。
pub fn mov_imm<B: Backend>(b: &mut B, rd: R, imm: u32) -> Flow<B> {
    let v = b.konst::<W32>(imm);
    buffer(b, rd, v);
    Ok(())
}

/// JUMP。pc を書き、ループ終端の上書きは commit が行う。
pub fn jump<B: Backend>(b: &mut B, target: u32) -> Flow<B> {
    let t = b.konst::<W32>(target);
    b.set(pc_ref(), t);
    Ok(())
}
