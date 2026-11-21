// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! LoongArch の命令意味論。段階19。
//!
//! 対象は LA32/LA64 のユーザモード全語彙（整数・load/store・
//! LL/SC・AM*・分岐・FPU・カウンタ・CPUCFG）と、CSRRD/CSRWR/
//! CSRXCHG・ERTN 等の特権入口。LSX/LASX/LBT は LA13 の範囲。
//! Ref: SPEC-LOONGARCH-RM §2（基本命令）, §3（FP 命令）,
//! §4（CSR・例外・特権命令）.

use polyisa_mem::{Access, AccessKind, Align, Endian};
use polyisa_sem::{
    Backend, Cmp, ExceptionKind, GuestException, StateArray, StateRef, W8, W16, W32, W64,
};

use crate::{CpuState, Insn, extract_ops};

/// Trap コード（`handle_trap` に渡る内部番号）。
/// `syscall` の発行点（code15 は命令語の即値）。OS
/// パーソナリティは syscall 番号を $a7 から読む。
pub const TRAP_SYS: u64 = 0x1000;
/// 特権・未定義の命令（実行ループは Unimplemented 扱い）。
pub const TRAP_ILL: u64 = 4;
/// `break` 発行点。code = `TRAP_BRK_BASE` | code15。
pub const TRAP_BRK_BASE: u64 = 0x2000;

/// CPU 状態の位置たち。
#[must_use]
pub fn pc_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, pc))
}

/// 汎用レジスタ $r`i`（0–31）。
/// 動的番号のため配列ではなくオフセット計算で引く。
#[must_use]
pub fn r_ref(i: u32) -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, r) + (i as usize) * 8)
}

/// FPU レジスタ $f`i` の生ビット格納面。
#[must_use]
pub fn fr_ref(i: u32) -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, f) + (i as usize) * 8)
}

/// FP レジスタ列。
#[must_use]
pub fn fr_array() -> StateArray<W64> {
    StateArray::<W64>::from_layout(core::mem::offset_of!(CpuState, f), 8)
}

/// 汎用レジスタ列。
#[must_use]
pub fn gr_array() -> StateArray<W64> {
    StateArray::<W64>::from_layout(core::mem::offset_of!(CpuState, r), 8)
}

/// FCC フラグ束（FCC0-FCC7、下位 8 ビット）。
#[must_use]
pub fn fcc_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, fcc))
}

/// FCSR 列（FCSR0-FCSR3。添字は fcsr 番号）。
/// Ref: SPEC-LOONGARCH-RM §3.2（FCSR0-FCSR3）.
#[must_use]
pub fn fcsr_array() -> StateArray<W32> {
    StateArray::<W32>::from_layout(core::mem::offset_of!(CpuState, fcsr), 4)
}

/// 安定カウンタ（RDTIME 系が読む決定論的時計）。
#[must_use]
pub fn cnt_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, stable_counter))
}

/// CPUCFG の構成情報列（word 番号を添字に取る）。
#[must_use]
pub fn cpucfg_array() -> StateArray<W32> {
    StateArray::<W32>::from_layout(core::mem::offset_of!(CpuState, cpucfg), 4)
}

/// 特権 CSR 配列（添字は csr 番号）。
#[must_use]
pub fn csr_array() -> StateArray<W64> {
    StateArray::<W64>::from_layout(core::mem::offset_of!(CpuState, csr), 8)
}

/// 定数。
fn k<B: Backend>(b: &mut B, v: u64) -> B::V<W64> {
    b.konst::<W64>(v)
}

/// $r`i` を読む。$r0 は常に 0。
fn rget<B: Backend>(b: &mut B, i: u64) -> B::V<W64> {
    if i == 0 {
        return k(b, 0);
    }
    let ix = b.konst::<W32>(i as u32);
    b.get_indexed(gr_array(), ix)
}

/// $r`i` へ書く。$r0 への書き込みは捨てる。
fn rset<B: Backend>(b: &mut B, i: u64, v: B::V<W64>) {
    if i == 0 {
        return;
    }
    let ix = b.konst::<W32>(i as u32);
    b.set_indexed(gr_array(), ix, v);
}

/// `.w` 結果の 32 ビット切り詰め＋符号拡張。
/// LA64 では .w 命令の結果は 64 ビットに符号拡張される。
/// Ref: SPEC-LOONGARCH-RM §2.1（.W 結果の符号拡張）.
fn sext_w<B: Backend>(b: &mut B, v: B::V<W64>) -> B::V<W64> {
    let t = b.trunc::<W64, W32>(v);
    b.sext::<W32, W64>(t)
}

/// v の下位 32 ビットをゼロ拡張して 64 ビットにする。
fn zext_w<B: Backend>(b: &mut B, v: B::V<W64>) -> B::V<W64> {
    let t = b.trunc::<W64, W32>(v);
    b.zext::<W32, W64>(t)
}

/// ホスト側の符号拡張（即値用）。
fn sext_n(v: u64, bits: u32) -> u64 {
    (((v as i64) << (64 - bits)) >> (64 - bits)) as u64
}

/// データアクセス属性（常に LE・自然整列）。
const DATA: Access = Access {
    endian: Endian::Le,
    align: Align::Natural,
    kind: AccessKind::DataRead,
};

/// ストア用属性。
const STORE: Access = Access {
    endian: Endian::Le,
    align: Align::Natural,
    kind: AccessKind::DataWrite,
};

/// 例外を投げる。
fn raise<B: Backend>(b: &mut B, kind: ExceptionKind, code: u64) -> B::Exit {
    b.raise(GuestException {
        kind,
        code,
        addr: None,
        in_delay_slot: false,
    })
}

/// 分岐オフセットの符号拡張（ops 値は生の符号なし域）。
/// `scaled` が真なら ops 値は既に <<2 済み（extract_ops が
/// Parts の <<2 を畳んだ形）で、ビット幅は元の幅＋2。
fn offs_n(v: u64, bits: u32, scaled: bool) -> i64 {
    let w = if scaled { bits + 2 } else { bits };
    (sext_n(v, w) as i64) << if scaled { 0 } else { 2 }
}

/// rd = f(rj, rk)。`w` なら結果を .w 規約で符号拡張する。
fn bin3<B: Backend>(
    b: &mut B,
    ops: &[u64],
    w: bool,
    f: impl FnOnce(&mut B, B::V<W64>, B::V<W64>) -> B::V<W64>,
) {
    let a = rget(b, ops[1]);
    let c = rget(b, ops[2]);
    let mut v = f(b, a, c);
    if w {
        v = sext_w(b, v);
    }
    rset(b, ops[0], v);
}

/// rd = f(rj, si12)。`w` なら結果を .w 規約で符号拡張する。
fn imm12<B: Backend>(
    b: &mut B,
    ops: &[u64],
    w: bool,
    f: impl FnOnce(&mut B, B::V<W64>, B::V<W64>) -> B::V<W64>,
) {
    let a = rget(b, ops[1]);
    let c = k(b, sext_n(ops[2], 12));
    let mut v = f(b, a, c);
    if w {
        v = sext_w(b, v);
    }
    rset(b, ops[0], v);
}

/// rd = rj << sa（`sa` は即値。`w` なら .w 規約）。
fn shimm<B: Backend>(
    b: &mut B,
    ops: &[u64],
    w: bool,
    f: impl FnOnce(&mut B, B::V<W64>, B::V<W64>) -> B::V<W64>,
) {
    let a = rget(b, ops[1]);
    let n = k(b, ops[2]);
    let v = f(b, a, n);
    if w {
        let v = sext_w(b, v);
        rset(b, ops[0], v);
    } else {
        rset(b, ops[0], v);
    }
}

/// rd = rj `op` rk（rk の下位 log2 幅をシフト量にする）。
fn shreg<B: Backend>(
    b: &mut B,
    ops: &[u64],
    w: bool,
    f: impl FnOnce(&mut B, B::V<W64>, B::V<W64>) -> B::V<W64>,
) {
    let a = rget(b, ops[1]);
    let n0 = rget(b, ops[2]);
    let m = k(b, if w { 31 } else { 63 });
    let n = b.and(n0, m);
    let v = f(b, a, n);
    if w {
        let v = sext_w(b, v);
        rset(b, ops[0], v);
    } else {
        rset(b, ops[0], v);
    }
}

/// rd = rj `cmp` rk ? 1 : 0。
fn cmp3<B: Backend>(b: &mut B, ops: &[u64], op: Cmp) {
    let a = rget(b, ops[1]);
    let c = rget(b, ops[2]);
    let t = b.cmp::<W64>(op, a, c);
    let one = k(b, 1);
    let zero = k(b, 0);
    let v = b.select::<W64>(t, one, zero);
    rset(b, ops[0], v);
}

/// rd = rj `cmp` sext(si12) ? 1 : 0。
fn cmpi<B: Backend>(b: &mut B, ops: &[u64], op: Cmp) {
    let a = rget(b, ops[1]);
    let c = k(b, sext_n(ops[2], 12));
    let t = b.cmp::<W64>(op, a, c);
    let one = k(b, 1);
    let zero = k(b, 0);
    let v = b.select::<W64>(t, one, zero);
    rset(b, ops[0], v);
}

/// ld.* の共通部。`ea = rj + sext(si12)`。
fn ldst_ea<B: Backend>(b: &mut B, ops: &[u64]) -> B::V<W64> {
    let base = rget(b, ops[1]);
    let d = k(b, sext_n(ops[2], 12));
    b.add(base, d)
}

/// 1 命令の意味論を実行する。`word` は命令語、`pc` は命令番地、
/// `la64` は LA64 モデルで動いているか。戻り値 `Ok(true)` は
/// 実行済み（PC の進めは実行ループ側）、`Ok(false)` は未実装。
// Ref: SPEC-LOONGARCH-RM §2, §3, §4.
#[allow(clippy::too_many_lines)]
pub fn exec<B: Backend>(
    b: &mut B,
    insn: Insn,
    word: u32,
    pc: u64,
    la64: bool,
) -> Result<bool, B::Exit> {
    let _ = la64;
    let ops = extract_ops(insn, u128::from(word));
    match insn {
        // ---- 整数算術 ----
        Insn::AddW => bin3(b, &ops, true, |b, x, y| b.add(x, y)),
        Insn::AddD => bin3(b, &ops, false, |b, x, y| b.add(x, y)),
        Insn::SubW => bin3(b, &ops, true, |b, x, y| b.sub(x, y)),
        Insn::SubD => bin3(b, &ops, false, |b, x, y| b.sub(x, y)),
        Insn::AddiW => imm12(b, &ops, true, |b, x, y| b.add(x, y)),
        Insn::AddiD => imm12(b, &ops, false, |b, x, y| b.add(x, y)),
        Insn::And => bin3(b, &ops, false, |b, x, y| b.and(x, y)),
        Insn::Or => bin3(b, &ops, false, |b, x, y| b.or(x, y)),
        Insn::Xor => bin3(b, &ops, false, |b, x, y| b.xor(x, y)),
        Insn::Nor => bin3(b, &ops, false, |b, x, y| {
            let t = b.or(x, y);
            b.not(t)
        }),
        Insn::Orn => bin3(b, &ops, false, |b, x, y| {
            let t = b.not(y);
            b.or(x, t)
        }),
        Insn::Andn => bin3(b, &ops, false, |b, x, y| {
            let t = b.not(y);
            b.and(x, t)
        }),
        Insn::Andi => {
            let a = rget(b, ops[1]);
            let c = k(b, ops[2]);
            let v = b.and(a, c);
            rset(b, ops[0], v);
        }
        Insn::Ori => {
            let a = rget(b, ops[1]);
            let c = k(b, ops[2]);
            let v = b.or(a, c);
            rset(b, ops[0], v);
        }
        Insn::Xori => {
            let a = rget(b, ops[1]);
            let c = k(b, ops[2]);
            let v = b.xor(a, c);
            rset(b, ops[0], v);
        }
        Insn::Slt => cmp3(b, &ops, Cmp::LtS),
        Insn::Sltu => cmp3(b, &ops, Cmp::LtU),
        Insn::Slti => cmpi(b, &ops, Cmp::LtS),
        Insn::Sltui => cmpi(b, &ops, Cmp::LtU),
        Insn::Lu12iW => {
            // rd = sext(si20 << 12)。Ref: SPEC-LOONGARCH-RM §2.2.1.
            let v = k(b, sext_n(ops[1] << 12, 32));
            rset(b, ops[0], v);
        }
        Insn::Lu32iD => {
            // rd = {sext32(si20), rd[31:0]}。ソースは rd 自身。
            // Ref: SPEC-LOONGARCH-RM §2.2.1.4.
            let r0 = rget(b, ops[0]);
            let m = k(b, 0xffff_ffff);
            let keep = b.and(r0, m);
            let hi = k(b, sext_n(ops[1], 20) << 32);
            let v = b.or(keep, hi);
            rset(b, ops[0], v);
        }
        Insn::Lu52iD => {
            // rd = {si12, rj[51:0]}。
            let r0 = rget(b, ops[1]);
            let m = k(b, 0x000f_ffff_ffff_ffff);
            let keep = b.and(r0, m);
            let hi = k(b, ops[2] << 52);
            let v = b.or(keep, hi);
            rset(b, ops[0], v);
        }
        Insn::Pcaddi => {
            // rd = pc + sext(si20 << 2)。
            let v = k(b, pc.wrapping_add(sext_n(ops[1] << 2, 22)));
            rset(b, ops[0], v);
        }
        Insn::Pcaddu12i => {
            // rd = pc + sext(si20 << 12)。
            let v = k(b, pc.wrapping_add(sext_n(ops[1] << 12, 32)));
            rset(b, ops[0], v);
        }
        Insn::Pcalau12i => {
            // tmp = pc + sext(si20 << 12); rd = tmp & ~0xfff。
            let t = pc.wrapping_add(sext_n(ops[1] << 12, 32));
            let v = k(b, t & !0xfff);
            rset(b, ops[0], v);
        }
        Insn::Pcaddu18i => {
            // rd = pc + sext(si20 << 18)。
            let v = k(b, pc.wrapping_add(sext_n(ops[1] << 18, 38)));
            rset(b, ops[0], v);
        }
        Insn::SlliW => shimm(b, &ops, true, |b, x, n| b.shl::<W64>(x, n)),
        Insn::SlliD => shimm(b, &ops, false, |b, x, n| b.shl::<W64>(x, n)),
        Insn::SrliW => {
            let a0 = rget(b, ops[1]);
            let a = zext_w(b, a0);
            let n = k(b, ops[2] & 31);
            let v0 = b.shr_l::<W64>(a, n);
            let v = sext_w(b, v0);
            rset(b, ops[0], v);
        }
        Insn::SrliD => shimm(b, &ops, false, |b, x, n| b.shr_l::<W64>(x, n)),
        Insn::SraiW => {
            let a0 = rget(b, ops[1]);
            let a = sext_w(b, a0);
            let n = k(b, ops[2] & 31);
            let v0 = b.shr_a::<W64>(a, n);
            let v = sext_w(b, v0);
            rset(b, ops[0], v);
        }
        Insn::SraiD => shimm(b, &ops, false, |b, x, n| b.shr_a::<W64>(x, n)),
        Insn::SllW => {
            let a0 = rget(b, ops[1]);
            let a = zext_w(b, a0);
            let n0 = rget(b, ops[2]);
            let m = k(b, 31);
            let n = b.and(n0, m);
            let v0 = b.shl::<W64>(a, n);
            let v = sext_w(b, v0);
            rset(b, ops[0], v);
        }
        Insn::SllD => shreg(b, &ops, false, |b, x, n| b.shl::<W64>(x, n)),
        Insn::SrlW => {
            let a0 = rget(b, ops[1]);
            let a = zext_w(b, a0);
            let n0 = rget(b, ops[2]);
            let m = k(b, 31);
            let n = b.and(n0, m);
            let v0 = b.shr_l::<W64>(a, n);
            let v = sext_w(b, v0);
            rset(b, ops[0], v);
        }
        Insn::SrlD => shreg(b, &ops, false, |b, x, n| b.shr_l::<W64>(x, n)),
        Insn::SraW => {
            let a0 = rget(b, ops[1]);
            let a = sext_w(b, a0);
            let n0 = rget(b, ops[2]);
            let m = k(b, 31);
            let n = b.and(n0, m);
            let v0 = b.shr_a::<W64>(a, n);
            let v = sext_w(b, v0);
            rset(b, ops[0], v);
        }
        Insn::SraD => shreg(b, &ops, false, |b, x, n| b.shr_a::<W64>(x, n)),
        Insn::ExtWB => {
            let a = rget(b, ops[1]);
            let t = b.trunc::<W64, W8>(a);
            let v = b.sext::<W8, W64>(t);
            rset(b, ops[0], v);
        }
        Insn::ExtWH => {
            let a = rget(b, ops[1]);
            let t = b.trunc::<W64, W16>(a);
            let v = b.sext::<W16, W64>(t);
            rset(b, ops[0], v);
        }
        // ---- 単純 load/store ----
        Insn::LdB | Insn::LdBu => {
            let ea = ldst_ea(b, &ops);
            let v = b.load::<W8>(ea, DATA)?;
            let v = if insn == Insn::LdB {
                b.sext::<W8, W64>(v)
            } else {
                b.zext::<W8, W64>(v)
            };
            rset(b, ops[0], v);
        }
        Insn::LdH | Insn::LdHu => {
            let ea = ldst_ea(b, &ops);
            let v = b.load::<W16>(ea, DATA)?;
            let v = if insn == Insn::LdH {
                b.sext::<W16, W64>(v)
            } else {
                b.zext::<W16, W64>(v)
            };
            rset(b, ops[0], v);
        }
        Insn::LdW | Insn::LdWu => {
            let ea = ldst_ea(b, &ops);
            let v = b.load::<W32>(ea, DATA)?;
            let v = if insn == Insn::LdW {
                b.sext::<W32, W64>(v)
            } else {
                b.zext::<W32, W64>(v)
            };
            rset(b, ops[0], v);
        }
        Insn::LdD => {
            let ea = ldst_ea(b, &ops);
            let v = b.load::<W64>(ea, DATA)?;
            rset(b, ops[0], v);
        }
        Insn::StB => {
            let ea = ldst_ea(b, &ops);
            let v0 = rget(b, ops[0]);
            let v = b.trunc::<W64, W8>(v0);
            b.store::<W8>(ea, v, STORE)?;
        }
        Insn::StH => {
            let ea = ldst_ea(b, &ops);
            let v0 = rget(b, ops[0]);
            let v = b.trunc::<W64, W16>(v0);
            b.store::<W16>(ea, v, STORE)?;
        }
        Insn::StW => {
            let ea = ldst_ea(b, &ops);
            let v0 = rget(b, ops[0]);
            let v = b.trunc::<W64, W32>(v0);
            b.store::<W32>(ea, v, STORE)?;
        }
        Insn::StD => {
            let ea = ldst_ea(b, &ops);
            let v = rget(b, ops[0]);
            b.store::<W64>(ea, v, STORE)?;
        }
        // ---- 基本分岐（LA7 で残りを足す）----
        Insn::B | Insn::Bl => {
            // ops[0] は offs26 を <<2 済み（幅28の符号付き）。
            let t = pc.wrapping_add(offs_n(ops[0], 26, true) as u64);
            if insn == Insn::Bl {
                let lr = k(b, pc.wrapping_add(4));
                rset(b, 1, lr);
            }
            let tv = k(b, t);
            b.jump(tv);
        }
        Insn::Jirl => {
            // rd = pc+4、pc = rj + sext(offs16 << 2)。
            let base = rget(b, ops[1]);
            let d = k(b, offs_n(ops[2], 16, false) as u64);
            let t = b.add(base, d);
            let ra = k(b, pc.wrapping_add(4));
            rset(b, ops[0], ra);
            b.jump(t);
        }
        // ---- 例外・バリア ----
        Insn::Syscall => {
            // OS パーソナリティが拾う。code = TRAP_SYS | code15。
            return Err(raise::<B>(b, ExceptionKind::Trap, TRAP_SYS | ops[0]));
        }
        Insn::Break => {
            return Err(raise::<B>(b, ExceptionKind::Break, TRAP_BRK_BASE | ops[0]));
        }
        Insn::Dbar | Insn::Ibar => {
            // シングルスレッド模型ではフェンスは no-op。
            // Gap: GAP-0063（マルチスレッドの順序付けは未対応）。
        }
        // ---- カウンタ ----
        Insn::RdtimelW => {
            let c = b.get(cnt_ref());
            let v = sext_w(b, c);
            rset(b, ops[0], v);
        }
        Insn::RdtimehW => {
            let c = b.get(cnt_ref());
            let n = k(b, 32);
            let v0 = b.shr_l::<W64>(c, n);
            let v = sext_w(b, v0);
            rset(b, ops[0], v);
        }
        Insn::RdtimeD => {
            let v = b.get(cnt_ref());
            rset(b, ops[0], v);
        }
        Insn::Cpucfg => {
            // cpucfg[ rj ] を rd へ。未設定語は 0 を返す。
            // Ref: SPEC-LOONGARCH-RM §2.2.10.2.
            let idx = rget(b, ops[1]);
            let idx32 = b.trunc::<W64, W32>(idx);
            let lim = b.konst::<W32>(0x20);
            let over = b.cmp::<W32>(Cmp::GeU, idx32, lim);
            let raw = b.get_indexed(cpucfg_array(), idx32);
            let zero = b.konst::<W32>(0);
            let v = b.select::<W32>(over, zero, raw);
            let v64 = b.zext::<W32, W64>(v);
            rset(b, ops[0], v64);
        }
        _ => return Ok(false),
    }
    Ok(true)
}
