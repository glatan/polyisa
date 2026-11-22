// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! IA-64 の命令意味論（段階21 の骨格）。
//!
//! 具体値インタプリタ（`InterpBackend`）上で動く。命令の実装は
//! IA5 以降で足す。IA4 では進行検査のための最小集合（nop/hint・
//! `break` の Trap 退出・add/adds/addl/movl/mov.ip/br.cond.sptk.few）
//! だけを実装し、残りは `Unimplemented` で落とす。
//! Ref: SPEC-IA64-SDM (Rev 2.3).

use polyisa_engine::interp::{Ctrl, InterpBackend, InterpExit};
use polyisa_sem::{ExceptionKind, GuestException, StateRef, W64};

use crate::{CpuState, Insn, extract_ops};

/// `handle_trap` に渡る内部番号。`break` は即値（immu21/imm62）を
/// そのまま code に載せるため、ぶつからない値を不正命令用に取る。
pub const TRAP_ILL: u64 = u64::MAX;

fn trap(code: u64) -> InterpExit {
    InterpExit::Exception(GuestException {
        kind: ExceptionKind::Trap,
        code,
        addr: None,
        in_delay_slot: false,
    })
}

/// 符号拡張（bits は元の幅）。
fn sext(v: u64, bits: u32) -> u64 {
    let sh = 64 - bits;
    (((v << sh) as i64) >> sh) as u64
}

fn get64(b: &InterpBackend, r: StateRef<W64>) -> u64 {
    let off = r.offset();
    u64::from_le_bytes(b.state[off..off + 8].try_into().expect("w64"))
}

fn set64(b: &mut InterpBackend, r: StateRef<W64>, v: u64) {
    let off = r.offset();
    b.state[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// GR r_i の状態面。
#[must_use]
pub fn gr_ref(i: u32) -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, gr) + (i as usize) * 8)
}

/// GR r_i の値。r0 は常に 0。
#[must_use]
pub fn gr_get(b: &InterpBackend, i: u32) -> u64 {
    if i == 0 { 0 } else { get64(b, gr_ref(i)) }
}

/// GR r_i への代入。r0 への書き込みは捨てる。
pub fn gr_set(b: &mut InterpBackend, i: u32, v: u64) {
    if i != 0 {
        set64(b, gr_ref(i), v);
    }
}

fn nat_off(i: u32) -> (usize, u64) {
    (
        core::mem::offset_of!(CpuState, gr_nat) + (i as usize / 64) * 8,
        1u64 << (i % 64),
    )
}

/// GR r_i の NaT ビット。
#[must_use]
pub fn nat_get(b: &InterpBackend, i: u32) -> bool {
    let (off, mask) = nat_off(i);
    let v = u64::from_le_bytes(b.state[off..off + 8].try_into().expect("w64"));
    v & mask != 0
}

/// GR r_i の NaT ビットの代入。
pub fn nat_set(b: &mut InterpBackend, i: u32, nat: bool) {
    let (off, mask) = nat_off(i);
    let mut v = u64::from_le_bytes(b.state[off..off + 8].try_into().expect("w64"));
    if nat {
        v |= mask;
    } else {
        v &= !mask;
    }
    b.state[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// 述語レジスタの面。
#[must_use]
pub fn pr_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, pr))
}

/// 述語レジスタのマスク。p0 は常に 1。
#[must_use]
pub fn pr_get(b: &InterpBackend) -> u64 {
    get64(b, pr_ref()) | 1
}

/// 述語レジスタの代入。p0 は常に 1。
pub fn pr_set(b: &mut InterpBackend, v: u64) {
    set64(b, pr_ref(), v | 1);
}

/// 述語 p_i の値。
#[must_use]
pub fn pred(b: &InterpBackend, i: u32) -> bool {
    (pr_get(b) >> i) & 1 != 0
}

/// BR b_i の状態面。
#[must_use]
pub fn br_ref(i: u32) -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, br) + (i as usize) * 8)
}

/// 命令ポインタの面。
#[must_use]
pub fn ip_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, ip))
}

/// CFM の面。
#[must_use]
pub fn cfm_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, cfm))
}

/// 1 スロットぶんの意味論。`ip` はこの命令の命令ポインタ（下位
/// 4 ビットがスロット番号）、`word` はスロット語（41 ビット。
/// X 系は 82 ビット）。修飾述語 qp（word[5:0]）が偽なら意味論を
/// 実行せず `Ok(false)` で進む（副作用の一括抑制はこの入口が担う。
/// cmp 系のように qp 偽でも述語を書く形式は IA5 が個別に扱う）。
/// `Ok(true)` は意味論を実行したこと。
pub fn exec(b: &mut InterpBackend, insn: Insn, word: u128, ip: u64) -> Result<bool, InterpExit> {
    if !pred(b, (word & 0x3f) as u32) {
        return Ok(false);
    }
    let ops = extract_ops(insn, word);
    match insn {
        Insn::NopI
        | Insn::NopF
        | Insn::NopB
        | Insn::NopX
        | Insn::HintI
        | Insn::HintF
        | Insn::HintB
        | Insn::HintX => {}
        Insn::BreakI | Insn::BreakF | Insn::BreakB | Insn::BreakX => {
            // code は即値。0x100000（__IA64_BREAK_SYSCALL）の意味は
            // OS パーソナリティ側（IA10/IA11）が解釈する。
            return Err(trap(ops[1]));
        }
        // 進行検査のための最小意味論。NaT は伝播だけを入れ、NaT
        // 消費の検査は IA6 に譲る。
        Insn::Add => {
            let v = gr_get(b, ops[2] as u32).wrapping_add(gr_get(b, ops[3] as u32));
            let nat = nat_get(b, ops[2] as u32) || nat_get(b, ops[3] as u32);
            gr_set(b, ops[1] as u32, v);
            nat_set(b, ops[1] as u32, nat);
        }
        Insn::Adds | Insn::Addl => {
            let bits = if insn == Insn::Adds { 14 } else { 22 };
            let v = sext(ops[2], bits).wrapping_add(gr_get(b, ops[3] as u32));
            let nat = nat_get(b, ops[3] as u32);
            gr_set(b, ops[1] as u32, v);
            nat_set(b, ops[1] as u32, nat);
        }
        Insn::Movl => {
            gr_set(b, ops[1] as u32, ops[2]);
            nat_set(b, ops[1] as u32, false);
        }
        Insn::MovIp => {
            // 建築の IP はバンドルアドレス（下位 4 ビットは常に 0）。
            gr_set(b, ops[1] as u32, ip & !0xf);
            nat_set(b, ops[1] as u32, false);
        }
        Insn::BrCondSptkFew => {
            // tgt25c は IP 相対（バンドルアドレス基準、下位 4 ビット 0）。
            b.ctrl = Ctrl::Jump((ip & !0xf).wrapping_add(sext(ops[1], 25)));
        }
        _ => return Err(InterpExit::Unimplemented(format!("{insn:?}"))),
    }
    Ok(true)
}
