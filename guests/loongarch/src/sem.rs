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
    Backend, Cmp, ExceptionKind, Flow, GuestException, StateArray, StateRef, W8, W16, W32, W64,
    W128, Width,
};

use crate::{CpuState, Insn, csr, extract_ops};

/// Trap コード（`handle_trap` に渡る内部番号）。
/// `syscall` の発行点（code15 は命令語の即値）。OS
/// パーソナリティは syscall 番号を $a7 から読む。
pub const TRAP_SYS: u64 = 0x1000;
/// 特権・未定義の命令（実行ループは Unimplemented 扱い）。
pub const TRAP_ILL: u64 = 4;
/// `break` 発行点。code = `TRAP_BRK_BASE` | code15。
pub const TRAP_BRK_BASE: u64 = 0x2000;
/// `dbcl` 発行点。code = `TRAP_DBG_BASE` | code15。
pub const TRAP_DBG_BASE: u64 = 0x4000;

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

/// LSX ベクトルレジスタ列（16 バイト幅。添字は vr 番号）。
/// Ref: SPEC-LOONGARCH-RM Vol.2 §1.
#[must_use]
pub fn vr_array() -> StateArray<W128> {
    StateArray::<W128>::from_layout(core::mem::offset_of!(CpuState, vr), 16)
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

/// データアクセス属性（常に LE・非整列許容）。実機では
/// 非整列の ld/st をハードウェアが透過的に処理し、musl の
/// memcpy/memset もそれに依存するため Unaligned を選ぶ。
/// Ref: SPEC-LOONGARCH-RM §2.2.3（非整列アクセス）.
const DATA: Access = Access {
    endian: Endian::Le,
    align: Align::Unaligned,
    kind: AccessKind::DataRead,
};

/// ストア用属性（DATA と同じく非整列許容）。
const STORE: Access = Access {
    endian: Endian::Le,
    align: Align::Unaligned,
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

/// 64 ビットの leading zeros（二分木選択）。
fn clz64<B: Backend>(b: &mut B, v: B::V<W64>) -> B::V<W64> {
    let mut count = k(b, 64);
    let mut rem = v;
    for w in [32u64, 16, 8, 4, 2] {
        let wv = k(b, w);
        let hi = b.shr_l(rem, wv);
        let zero = k(b, 0);
        let nz = b.cmp::<W64>(Cmp::Ne, hi, zero);
        let sub = b.sub(count, wv);
        count = b.select::<W64>(nz, sub, count);
        rem = b.select::<W64>(nz, hi, rem);
    }
    let one = k(b, 1);
    let hi = b.shr_l(rem, one);
    let zero = k(b, 0);
    let nz = b.cmp::<W64>(Cmp::Ne, hi, zero);
    let two = k(b, 2);
    let a = b.sub(count, two);
    let e = b.sub(count, rem);
    b.select::<W64>(nz, a, e)
}

/// 32 ビットの leading zeros。
fn clz32<B: Backend>(b: &mut B, v: B::V<W64>) -> B::V<W64> {
    let a = zext_w(b, v);
    let c = clz64(b, a);
    let w = k(b, 32);
    b.sub(c, w)
}

/// 64 ビットの trailing zeros（v==0 なら 64）。
fn ctz64<B: Backend>(b: &mut B, v: B::V<W64>) -> B::V<W64> {
    let zero = k(b, 0);
    let neg = b.sub(zero, v);
    let lsb = b.and(v, neg);
    let c = clz64(b, lsb);
    let w = k(b, 63);
    let r = b.sub(w, c);
    let is0 = b.cmp::<W64>(Cmp::Eq, v, zero);
    let w64 = k(b, 64);
    b.select::<W64>(is0, w64, r)
}

/// 32 ビットの trailing zeros（v==0 なら 32）。
fn ctz32<B: Backend>(b: &mut B, v: B::V<W64>) -> B::V<W64> {
    let a = zext_w(b, v);
    let r = ctz64(b, a);
    // 32 ビット入力では 0 のとき 64 ではなく 32。
    let w = k(b, 32);
    let zero = k(b, 0);
    let is0 = b.cmp::<W64>(Cmp::Eq, a, zero);
    let over = b.cmp::<W64>(Cmp::GtU, r, w);
    let capped = b.select::<W64>(over, w, r);
    b.select::<W64>(is0, w, capped)
}

/// `v` を `bits` 幅で右回転（`bits` は 32 または 64）。
fn rotr<B: Backend>(b: &mut B, a: B::V<W64>, n: B::V<W64>, bits: u32) -> B::V<W64> {
    let mut a = a;
    if bits == 32 {
        a = zext_w(b, a);
    }
    let w = k(b, u64::from(bits));
    let l = b.sub(w, n);
    let lo = b.shr_l::<W64>(a, n);
    let hi = b.shl::<W64>(a, l);
    let v = b.or(lo, hi);
    if bits == 32 { zext_w(b, v) } else { v }
}

/// `unit` バイト区切りごとにバイト順を反転（host 側定数畳み）。
/// `width` は全体のビット幅（32 または 64）。
fn byte_swap_in<B: Backend>(b: &mut B, v: B::V<W64>, unit: u32, width: u32) -> B::V<W64> {
    let mut out = k(b, 0);
    let n = width / (unit * 8);
    for i in 0..n {
        let sh_lo = k(b, u64::from(i * unit * 8));
        let chunk = b.shr_l::<W64>(v, sh_lo);
        let mut rev = k(b, 0);
        for j in 0..unit {
            let sh = k(b, u64::from(j * 8));
            let byte = b.shr_l::<W64>(chunk, sh);
            let m = k(b, 0xff);
            let byte = b.and(byte, m);
            let to = k(b, u64::from((unit - 1 - j) * 8));
            let placed = b.shl::<W64>(byte, to);
            rev = b.or(rev, placed);
        }
        let to = k(b, u64::from(i * unit * 8));
        let placed = b.shl::<W64>(rev, to);
        out = b.or(out, placed);
    }
    out
}

/// `group` ビット幅の区切りごとに `unit` ビット要素の順序を反転する。
/// revh.2w は (unit=16, group=32, width=64)、revh.d は (16, 64, 64)。
fn grp_swap<B: Backend>(b: &mut B, v: B::V<W64>, unit: u32, group: u32, width: u32) -> B::V<W64> {
    let mut out = k(b, 0);
    let n = group / unit;
    for g in (0..width).step_by(group as usize) {
        for i in 0..n {
            let sh = k(b, u64::from(g + i * unit));
            let chunk = b.shr_l::<W64>(v, sh);
            let m = k(b, (1u64 << unit) - 1);
            let chunk = b.and(chunk, m);
            let to = k(b, u64::from(g + (n - 1 - i) * unit));
            let placed = b.shl::<W64>(chunk, to);
            out = b.or(out, placed);
        }
    }
    out
}

/// 全ビット反転（`bits` 幅）。
fn bitrev<B: Backend>(b: &mut B, v: B::V<W64>, bits: u32) -> B::V<W64> {
    let mut out = k(b, 0);
    for i in 0..bits {
        let sh = k(b, u64::from(i));
        let bit = b.shr_l::<W64>(v, sh);
        let one = k(b, 1);
        let bit = b.and(bit, one);
        let to = k(b, u64::from(bits - 1 - i));
        let placed = b.shl::<W64>(bit, to);
        out = b.or(out, placed);
    }
    out
}

/// 各 8 ビット区切り内でビット反転。
fn bitrev_bytes<B: Backend>(b: &mut B, v: B::V<W64>, width: u32) -> B::V<W64> {
    let mut out = k(b, 0);
    for i in 0..(width / 8) {
        let sh = k(b, u64::from(i * 8));
        let byte = b.shr_l::<W64>(v, sh);
        let m = k(b, 0xff);
        let byte = b.and(byte, m);
        let rev = bitrev(b, byte, 8);
        let to = k(b, u64::from(i * 8));
        let placed = b.shl::<W64>(rev, to);
        out = b.or(out, placed);
    }
    out
}

/// CRC のビット逐次更新（poly は反映形 0xEDB88320/0x82F63B78）。
/// `bits` 分のシフト回数を畳み込み展開する。
/// Ref: SPEC-LOONGARCH-RM §2.2.1.14（CRC/CRCC の多項式）.
fn crc32<B: Backend>(b: &mut B, mut c: B::V<W32>, poly: u32, bits: u32) -> B::V<W32> {
    for _ in 0..bits {
        let one = b.konst::<W32>(1);
        let lsb = b.and::<W32>(c, one);
        let n1 = b.konst::<W32>(1);
        let shifted = b.shr_l::<W32>(c, n1);
        let p = b.konst::<W32>(poly);
        let x = b.xor::<W32>(shifted, p);
        let z = b.konst::<W32>(0);
        let is1 = b.cmp::<W32>(Cmp::Ne, lsb, z);
        c = b.select::<W32>(is1, x, shifted);
    }
    c
}

/// `insn` が .w 形の単項演算（rj → rd、sext 書き戻し）。
fn un_w<B: Backend>(b: &mut B, ops: &[u64], f: impl FnOnce(&mut B, B::V<W64>) -> B::V<W64>) {
    let a = rget(b, ops[1]);
    let v = f(b, a);
    let v = sext_w(b, v);
    rset(b, ops[0], v);
}

/// `insn` が .d 形の単項演算。
fn un_d<B: Backend>(b: &mut B, ops: &[u64], f: impl FnOnce(&mut B, B::V<W64>) -> B::V<W64>) {
    let a = rget(b, ops[1]);
    let v = f(b, a);
    rset(b, ops[0], v);
}

/// ldx/stx 系の実効番地（`ea = rj + rk`）。
fn ldx_ea<B: Backend>(b: &mut B, ops: &[u64]) -> B::V<W64> {
    let a = rget(b, ops[1]);
    let c = rget(b, ops[2]);
    b.add(a, c)
}

/// ldptr/stptr/ll/sc の実効番地（`ea = rj + sext(si14 << 2)`）。
/// Ref: SPEC-LOONGARCH-RM §2.2.3.2, §2.2.7.
fn ptr_ea<B: Backend>(b: &mut B, ops: &[u64]) -> B::V<W64> {
    let a = rget(b, ops[1]);
    let d = k(b, sext_n(ops[2], 14) << 2);
    b.add(a, d)
}

/// AM* のアクセス属性（read-modify-write）。
const ACC_AM: Access = Access {
    endian: Endian::Le,
    align: Align::Natural,
    kind: AccessKind::AtomicRw,
};

/// LL 系の予約ロード属性。
const ACC_LL: Access = Access {
    endian: Endian::Le,
    align: Align::Natural,
    kind: AccessKind::LoadReserved,
};

/// SC 系の条件付きストア属性。
const ACC_SC: Access = Access {
    endian: Endian::Le,
    align: Align::Natural,
    kind: AccessKind::StoreConditional,
};

/// bound check 例外の trap コード（`handle_trap` へ渡る内部番号）。
/// Ref: SPEC-LOONGARCH-RM §2.2.3.4（BCE）.
pub const TRAP_BND: u64 = 5;

/// CSR 読み出し。idx >= 512 の未割当て番号は 0 を返す
/// （配列近似。Gap: GAP-0063）。
fn csr_load<B: Backend>(b: &mut B, idx: u64) -> B::V<W64> {
    let i64v = k(b, idx);
    let idx32 = b.trunc::<W64, W32>(i64v);
    let lim = b.konst::<W32>(512);
    let over = b.cmp::<W32>(Cmp::GeU, idx32, lim);
    // idx >= 512 でも配列内を読むために下位 9 ビットに折る。
    let mask = b.konst::<W32>(0x1ff);
    let safe = b.and(idx32, mask);
    let raw = b.get_indexed(csr_array(), safe);
    let zero = k(b, 0);
    b.select::<W64>(over, zero, raw)
}

/// CSR 書き込み。idx >= 512 の未割当て番号は捨てる
/// （配列近似。Gap: GAP-0063）。
fn csr_store<B: Backend>(b: &mut B, idx: u64, v: B::V<W64>) -> Result<(), B::Exit> {
    let i64v = k(b, idx);
    let idx32 = b.trunc::<W64, W32>(i64v);
    let lim = b.konst::<W32>(512);
    let ok = b.cmp::<W32>(Cmp::LtU, idx32, lim);
    b.if_then(ok, |b| {
        b.set_indexed(csr_array(), idx32, v);
        Ok(())
    })
}

/// ldgt/ldle/stgt/stle の境界検査。`gt` なら `rj > rk`、
/// さもなければ `rj <= rk` が合法。違反時は BCE に畳む。
/// Ref: SPEC-LOONGARCH-RM §2.2.3.4.
fn bound_check<B: Backend>(b: &mut B, ops: &[u64], gt: bool) -> Result<(), B::Exit> {
    let a = rget(b, ops[1]);
    let c = rget(b, ops[2]);
    let op = if gt { Cmp::GtS } else { Cmp::LeS };
    let ok = b.cmp::<W64>(op, a, c);
    b.if_then_else(
        ok,
        |_| Ok(()),
        |b| Err(raise::<B>(b, ExceptionKind::Trap, TRAP_BND)),
    )
}

/// am*.w 共通。ops = [rd, rj, rk]。`old = *rj32`、
/// `*rj32 = f(old, rk32)`、`rd = sext(old)`。
/// Ref: SPEC-LOONGARCH-RM §2.2.7.1.
fn am_w<B: Backend>(
    b: &mut B,
    ops: &[u64],
    f: impl FnOnce(&mut B, B::V<W32>, B::V<W32>) -> B::V<W32>,
) -> Result<(), B::Exit> {
    let ea = rget(b, ops[1]);
    let x64 = rget(b, ops[2]);
    let x = b.trunc::<W64, W32>(x64);
    let old = b.load::<W32>(ea, ACC_AM)?;
    let new = f(b, old, x);
    b.store::<W32>(ea, new, ACC_AM)?;
    let v = b.sext::<W32, W64>(old);
    rset(b, ops[0], v);
    Ok(())
}

/// am*.d 共通（ops = [rd, rj, rk]）。
fn am_d<B: Backend>(
    b: &mut B,
    ops: &[u64],
    f: impl FnOnce(&mut B, B::V<W64>, B::V<W64>) -> B::V<W64>,
) -> Result<(), B::Exit> {
    let ea = rget(b, ops[1]);
    let x = rget(b, ops[2]);
    let old = b.load::<W64>(ea, ACC_AM)?;
    let new = f(b, old, x);
    b.store::<W64>(ea, new, ACC_AM)?;
    rset(b, ops[0], old);
    Ok(())
}

/// am*.b/.h 共通（FAM3 形で ops = [rd, rk, rj]。番地は rj、
/// データは rk）。`rd = sext(old)`。
fn am_bh<B: Backend, W: Width>(
    b: &mut B,
    ops: &[u64],
    f: impl FnOnce(&mut B, B::V<W>, B::V<W>) -> B::V<W>,
) -> Result<(), B::Exit> {
    let ea = rget(b, ops[2]);
    let x64 = rget(b, ops[1]);
    let x = b.trunc::<W64, W>(x64);
    let old = b.load::<W>(ea, ACC_AM)?;
    let new = f(b, old, x);
    b.store::<W>(ea, new, ACC_AM)?;
    let v = b.sext::<W, W64>(old);
    rset(b, ops[0], v);
    Ok(())
}

// ---- スカラ FP 補助（LA9）----
// Ref: SPEC-LOONGARCH-RM §3.1-§3.2.

/// backend の Rm 定数（polyisa-softfloat の Rm と同じ並び）。
/// Ref: SPEC-LOONGARCH-RM §3.1.4.
const RM_RNE: u8 = 0;
const RM_RTZ: u8 = 1;
const RM_RDN: u8 = 2;
const RM_RUP: u8 = 3;

/// FR[`i`] のビット列。
fn fget<B: Backend>(b: &mut B, i: u64) -> B::V<W64> {
    b.get(fr_ref(i as u32))
}

/// FR[`i`] にビット列を書く。
fn fset<B: Backend>(b: &mut B, i: u64, v: B::V<W64>) {
    b.set(fr_ref(i as u32), v);
}

/// FR[`i`] の下位 32 ビット。
fn fget32<B: Backend>(b: &mut B, i: u64) -> B::V<W32> {
    let v = fget(b, i);
    b.trunc::<W64, W32>(v)
}

/// FR[`i`] の下位 32 ビットに書く。上位は 0 で畳む
/// （spec は「不確定」なので決定的に 0 を選ぶ）。
fn fset32<B: Backend>(b: &mut B, i: u64, v: B::V<W32>) {
    let v = b.zext::<W32, W64>(v);
    fset(b, i, v);
}

/// `fp_flags` を FCSR0 の Cause[28:24]・Flags[20:16] に反映する。
/// backend のフラグ並び（NV,DZ,OF,UF,NX）は LoongArch の VZOUI と
/// 同じ順なのでそのまま写せる。Enables が立っていても
/// FP 例外トラップにはしない近似。Gap: GAP-0063.
/// Ref: SPEC-LOONGARCH-RM §3.1.4（FCSR0 定義）.
fn fpo_end<B: Backend>(b: &mut B) {
    let fl = u64::from(b.fp_flags());
    if fl == 0 {
        return;
    }
    let i0 = b.konst::<W32>(0);
    let f = b.get_indexed(fcsr_array(), i0);
    let flv = b.konst::<W32>(fl as u32);
    let sh24 = b.konst::<W32>(24);
    let cause = b.shl::<W32>(flv, sh24);
    // Cause は直近の演算のもので置き換える。
    let keep = b.konst::<W32>(!0x1f00_0000);
    let kept = b.and::<W32>(f, keep);
    let nv = b.or::<W32>(kept, cause);
    // Flags は累積。
    let sh16 = b.konst::<W32>(16);
    let flg = b.shl::<W32>(flv, sh16);
    let nv = b.or::<W32>(nv, flg);
    b.set_indexed(fcsr_array(), i0, nv);
}

/// FCSR0 の RM ビット（[9:8]）を backend 値で取る。
fn fcsr_rm_bits<B: Backend>(b: &mut B) -> B::V<W32> {
    let i0 = b.konst::<W32>(0);
    let f = b.get_indexed(fcsr_array(), i0);
    let sh = b.konst::<W32>(8);
    let v = b.shr_l::<W32>(f, sh);
    let m = b.konst::<W32>(3);
    b.and::<W32>(v, m)
}

/// FCSR.RM に従って `f(b, rm)` を呼ぶ。LoongArch の RM 値
/// （0=RNE,1=RZ,2=RP,3=RM）を backend の Rm 値（Rne,Rtz,Rdn,Rup）
/// に写像する。Ref: SPEC-LOONGARCH-RM §3.1.4.
fn with_la_rm<B: Backend>(b: &mut B, f: impl Fn(&mut B, u8) -> Flow<B>) -> Flow<B> {
    let rm = fcsr_rm_bits(b);
    let is = |b: &mut B, n: u32| {
        let kv = b.konst::<W32>(n);
        b.cmp::<W32>(Cmp::Eq, rm, kv)
    };
    // LA 0→Rne(0), 1→Rtz(1), 2→Rup(3), 3→Rdn(2)。
    let c0 = is(b, 0);
    b.if_then_else(
        c0,
        |b| f(b, RM_RNE),
        |b| {
            let c1 = is(b, 1);
            b.if_then_else(
                c1,
                |b| f(b, RM_RTZ),
                |b| {
                    let c2 = is(b, 2);
                    b.if_then_else(c2, |b| f(b, RM_RUP), |b| f(b, RM_RDN))
                },
            )
        },
    )
}

/// FCC[`i`] の 0/1 値。
fn fcc_bit<B: Backend>(b: &mut B, i: u64) -> B::V<W64> {
    let f = b.get(fcc_ref());
    let n = k(b, i);
    let v = b.shr_l::<W64>(f, n);
    let one = k(b, 1);
    b.and::<W64>(v, one)
}

/// FCC[`i`] に 0/1 値 `bit` を書く（`bit` は 0 か 1 の値）。
fn fcc_set<B: Backend>(b: &mut B, i: u64, bit: B::V<W64>) {
    let f = b.get(fcc_ref());
    let n = k(b, i);
    let one = k(b, 1);
    let mask = b.shl::<W64>(one, n);
    let nmask = b.not::<W64>(mask);
    let clr = b.and::<W64>(f, nmask);
    let put = b.shl::<W64>(bit, n);
    let nv = b.or::<W64>(clr, put);
    b.set(fcc_ref(), nv);
}

/// 浮動小数点の符号ビットを倒す（|x|）。
fn fabs_v<B: Backend, F: Width>(b: &mut B, a: B::V<F>) -> B::V<F> {
    let m = b.konst::<F>(F::from_u128((1u128 << (F::BITS - 1)) - 1));
    b.and::<F>(a, m)
}

/// 浮動小数点の符号ビットを反転する（-x）。
fn fneg_v<B: Backend, F: Width>(b: &mut B, a: B::V<F>) -> B::V<F> {
    let m = b.konst::<F>(F::from_u128(1u128 << (F::BITS - 1)));
    b.xor::<F>(a, m)
}

/// .s 形式の二項 FP 演算（ops = [fd, fj, fk]）。
fn fbin32<B: Backend>(
    b: &mut B,
    ops: &[u64],
    f: impl FnOnce(&mut B, B::V<W32>, B::V<W32>) -> B::V<W32>,
) {
    let a = fget32(b, ops[1]);
    let c = fget32(b, ops[2]);
    let r = f(b, a, c);
    fset32(b, ops[0], r);
    fpo_end(b);
}

/// .d 形式の二項 FP 演算。
fn fbin64<B: Backend>(
    b: &mut B,
    ops: &[u64],
    f: impl FnOnce(&mut B, B::V<W64>, B::V<W64>) -> B::V<W64>,
) {
    let a = fget(b, ops[1]);
    let c = fget(b, ops[2]);
    let r = f(b, a, c);
    fset(b, ops[0], r);
    fpo_end(b);
}

/// .s 形式の一項 FP 演算（ops = [fd, fj]）。
fn funa32<B: Backend>(b: &mut B, ops: &[u64], f: impl FnOnce(&mut B, B::V<W32>) -> B::V<W32>) {
    let a = fget32(b, ops[1]);
    let r = f(b, a);
    fset32(b, ops[0], r);
    fpo_end(b);
}

/// .d 形式の一項 FP 演算。
fn funa64<B: Backend>(b: &mut B, ops: &[u64], f: impl FnOnce(&mut B, B::V<W64>) -> B::V<W64>) {
    let a = fget(b, ops[1]);
    let r = f(b, a);
    fset(b, ops[0], r);
    fpo_end(b);
}

/// FMAXA/FMINA 相当の絶対値比較。`gt` なら |x|>|y| で x、
/// それ以外は y。|x|==|y| なら fmax/fmin に倒す。
/// Ref: SPEC-LOONGARCH-RM §3.2.1.4.
fn fmag<B: Backend, F: Width>(b: &mut B, a: B::V<F>, c: B::V<F>, gt: bool) -> B::V<F> {
    let aa = fabs_v::<B, F>(b, a);
    let cc = fabs_v::<B, F>(b, c);
    let big = b.flt::<F>(cc, aa);
    let small = b.flt::<F>(aa, cc);
    let rb = b.select::<F>(big, a, c);
    let rs = b.select::<F>(small, a, c);
    if gt { rb } else { rs }
}

/// FSCALEB 近似。`a * 2^n`（`n` は `nbits` の符号付き整数）。
/// 2^n を浮動小数点ビットとして組み立てて `fmul` に流す。
/// 非正規化途中結果は近似（Gap: GAP-0063）。
/// Ref: SPEC-LOONGARCH-RM §3.2.1.7.
fn fscaleb_v<B: Backend, F: Width>(b: &mut B, a: B::V<F>, nbits: B::V<F>) -> B::V<F> {
    let (eb, mb, bias) = if F::BITS == 64 {
        (11u32, 52u64, 1023i64)
    } else {
        (8u32, 23u64, 127i64)
    };
    // n を符号付き整数として取り出す（.s は fk[31:0]、.d は fk）。
    let n64: B::V<W64> = if F::BITS == 64 {
        b.zext::<F, W64>(nbits)
    } else {
        b.sext::<F, W64>(nbits)
    };
    // exp = clamp(n + bias, 0, (1<<eb)-1)。
    let biasv = k(b, bias as u64);
    let raw = b.add::<W64>(n64, biasv);
    let zero = k(b, 0);
    let lim = k(b, (1u64 << eb) - 1);
    let neg = b.cmp::<W64>(Cmp::LtS, raw, zero);
    let c0 = b.select::<W64>(neg, zero, raw);
    let over = b.cmp::<W64>(Cmp::GtS, c0, lim);
    let e = b.select::<W64>(over, lim, c0);
    // pow2 = e << mb の浮動小数点ビット。
    let sh = k(b, mb);
    let p64 = b.shl::<W64>(e, sh);
    let p = b.trunc::<W64, F>(p64);
    b.fmul::<F>(a, p)
}

/// FLOGB。`logB(x)` の IEEE 754 規則（±0→-inf、±inf→+inf、
/// NaN→NaN、非正規化数は正規化後の指数）をビット操作で畳む。
/// logB(±0) の divByZero フラグは立てない近似（Gap: GAP-0063）。
/// Ref: SPEC-LOONGARCH-RM §3.2.1.7.
fn flogb_v<B: Backend, F: Width>(b: &mut B, a: B::V<F>) -> B::V<F> {
    let (eb, mb, bias) = if F::BITS == 64 {
        (11u64, 52u64, 1023i64)
    } else {
        (8u64, 23u64, 127i64)
    };
    let emax = (1u64 << eb) - 1;
    let mmask = (1u64 << mb) - 1;
    let a64 = b.zext::<F, W64>(a);
    let sh_mb = k(b, mb);
    let expf0 = b.shr_l::<W64>(a64, sh_mb);
    let emaxv = k(b, emax);
    let expf = b.and::<W64>(expf0, emaxv);
    let mmv = k(b, mmask);
    let frac = b.and::<W64>(a64, mmv);
    let zero = k(b, 0);
    let e_is_max = b.cmp::<W64>(Cmp::Eq, expf, emaxv);
    let e_is_zero = b.cmp::<W64>(Cmp::Eq, expf, zero);
    let f_nz = b.cmp::<W64>(Cmp::Ne, frac, zero);
    // floor_log2(frac) を f64 への変換で取る（frac!=0 のとき正確）。
    let ffr = b.fcvt_from_u64::<W64>(frac, RM_RNE);
    let sh52 = k(b, 52);
    let e0 = b.shr_l::<W64>(ffr, sh52);
    let m2047 = k(b, 0x7ff);
    let e1 = b.and::<W64>(e0, m2047);
    let b1023 = k(b, 1023);
    let p = b.sub::<W64>(e1, b1023);
    // 非正規化: e = p - (mb + bias - 1)。
    let adj = k(b, (mb as i64 + bias - 1) as u64);
    let e_sub = b.sub::<W64>(p, adj);
    let biasv = k(b, bias as u64);
    let e_norm = b.sub::<W64>(expf, biasv);
    let e = b.select::<W64>(e_is_zero, e_sub, e_norm);
    let e32 = b.trunc::<W64, W32>(e);
    let r_norm = b.fcvt_from_s32::<F>(e32, RM_RNE);
    // 結果の選択: nan→a、inf→+inf、zero→-inf、他→float(e)。
    let pinf = b.konst::<F>(F::from_u128((emax as u128) << mb));
    let ninf = b.konst::<F>(F::from_u128(
        ((emax as u128) << mb) | (1u128 << (F::BITS - 1)),
    ));
    // exp==emax の内側: frac!=0 は NaN→a、frac==0 は inf→+inf。
    let inner = b.select::<F>(f_nz, a, pinf);
    let non_zero = b.select::<F>(e_is_max, inner, r_norm);
    // exp==0 の内側: frac!=0 は非正規化→float(e)、frac==0 は ±0→-inf。
    let z_side = b.select::<F>(f_nz, r_norm, ninf);
    b.select::<F>(e_is_zero, z_side, non_zero)
}

/// FCLASS の RISC-V 並びを LoongArch 並びに写す
/// （LA: bit0=sNaN,bit1=qNaN,bit2..9 = -inf,-norm,-sub,-0,+0,+sub,+norm,+inf）。
/// Ref: SPEC-LOONGARCH-RM §3.2.1.8（Table 8）.
fn fclass_la<B: Backend, F: Width>(b: &mut B, a: B::V<F>) -> B::V<W32> {
    let rv = b.fclass::<F>(a);
    let m = b.konst::<W32>(0xff);
    let lo = b.and::<W32>(rv, m);
    let sh2 = b.konst::<W32>(2);
    let lo = b.shl::<W32>(lo, sh2);
    let sh8 = b.konst::<W32>(8);
    let hi0 = b.shr_l::<W32>(rv, sh8);
    let m3 = b.konst::<W32>(3);
    let hi = b.and::<W32>(hi0, m3);
    b.or::<W32>(lo, hi)
}

/// FTINT.{W/L}.{S/D}・FTINTR*。`src` は F、結果幅は `to64`。
/// fd に整数ビットを書く（.w は下位 32 ビット、上位 0）。
/// Ref: SPEC-LOONGARCH-RM §3.2.3.2-§3.2.3.3.
fn ftint<B: Backend, F: Width>(b: &mut B, ops: &[u64], to64: bool, rm: u8) -> Flow<B> {
    let a = fget(b, ops[1]);
    let a = b.trunc::<W64, F>(a);
    if to64 {
        let i = b.fcvt_s64::<F>(a, rm);
        fset(b, ops[0], i);
    } else {
        let i = b.fcvt_s32::<F>(a, rm);
        fset32(b, ops[0], i);
    }
    fpo_end(b);
    Ok(())
}

/// FFINT{S/D}.{W/L}。fj の整数ビットを F に変換する。
/// Ref: SPEC-LOONGARCH-RM §3.2.3.2.
fn ffint<B: Backend, F: Width>(b: &mut B, ops: &[u64], from64: bool, rm: u8) -> Flow<B> {
    let a64 = fget(b, ops[1]);
    let v = if from64 {
        b.fcvt_from_s64::<F>(a64, rm)
    } else {
        let a = b.trunc::<W64, W32>(a64);
        b.fcvt_from_s32::<F>(a, rm)
    };
    // .s は下位 32 ビットに書き、上位は 0（不確定の決定解）。
    let vv = b.zext::<F, W64>(v);
    fset(b, ops[0], vv);
    fpo_end(b);
    Ok(())
}

/// FRINT。AArch64 と同じく s64 経由の丸め近似。
/// |x|>=2^63・NaN・inf は入力をそのまま返す。
/// Ref: SPEC-LOONGARCH-RM §3.2.3.4.
fn frint_v<B: Backend, F: Width>(b: &mut B, a: B::V<F>, rm: u8) -> B::V<F> {
    let lim_bits: u128 = if F::BITS == 64 {
        0x43e0_0000_0000_0000
    } else {
        0x5f00_0000
    };
    let lim = b.konst::<F>(F::from_u128(lim_bits));
    let abs = fabs_v::<B, F>(b, a);
    let small = b.flt::<F>(abs, lim);
    let i = b.fcvt_s64::<F>(a, rm);
    let r = b.fcvt_from_s64::<F>(i, RM_RNE);
    let via_int = b.select::<F>(small, r, a);
    let ordered = b.feq::<F>(a, a);
    b.select::<F>(ordered, via_int, a)
}

/// FCMP.cond の 22 条件を評価し 0/1 を返す。`cond` は命令語の
/// 5 ビット値。S/C の区別（signaling）による例外は畳まない近似
/// （Gap: GAP-0063）。Ref: SPEC-LOONGARCH-RM §3.2.2.1（Table 9）.
fn fcmp_res<B: Backend, F: Width>(b: &mut B, a: B::V<F>, c: B::V<F>, cond: u64) -> B::V<W64> {
    let one = k(b, 1);
    let zero = k(b, 0);
    let lt = {
        let cnd = b.flt::<F>(a, c);
        b.select::<W64>(cnd, one, zero)
    };
    let eq = {
        let cnd = b.feq::<F>(a, c);
        b.select::<W64>(cnd, one, zero)
    };
    let gt = {
        let cnd = b.flt::<F>(c, a);
        b.select::<W64>(cnd, one, zero)
    };
    let un = {
        let l1 = {
            let cnd = b.fle::<F>(a, c);
            b.select::<W64>(cnd, one, zero)
        };
        let l2 = {
            let cnd = b.fle::<F>(c, a);
            b.select::<W64>(cnd, one, zero)
        };
        let or = b.or::<W64>(l1, l2);
        let n = b.not::<W64>(or);
        b.and::<W64>(n, one)
    };
    // 条件群を先に組み立てる。
    let lt_eq = b.or::<W64>(lt, eq);
    let un_lt = b.or::<W64>(un, lt);
    let un_eq = b.or::<W64>(un, eq);
    let ule = b.or::<W64>(un_lt, eq);
    let lt_gt = b.or::<W64>(lt, gt);
    let ordered = b.or::<W64>(lt_eq, gt);
    let une = b.or::<W64>(un_lt, gt);
    match cond & 0x1f {
        // CAF/SAF。
        0x00 | 0x01 => zero,
        // CLT/SLT。
        0x02 | 0x03 => lt,
        // CEQ/SEQ。
        0x04 | 0x05 => eq,
        // CLE/SLE。
        0x06 | 0x07 => lt_eq,
        // CUN/SUN。
        0x08 | 0x09 => un,
        // CULT/SULT。
        0x0a | 0x0b => un_lt,
        // CUEQ/SUEQ。
        0x0c | 0x0d => un_eq,
        // CULE/SULE。
        0x0e | 0x0f => ule,
        // CNE/SNE。
        0x10 | 0x11 => lt_gt,
        // COR/SOR。
        0x14 | 0x15 => ordered,
        // CUNE/SUNE。
        0x18 | 0x19 => une,
        // 未定義 cond は false に畳む。
        _ => zero,
    }
}

// ---- LSX の部分集合（LA13）。Alpine/musl/BusyBox が実際に
// 実行する命令のみ。ここにない LSX 命令は decode が通っても
// exec 側で Unimplemented ではなく網羅済みのため、語彙自体を
// 宣言しない方針を取った。Ref: SPEC-LOONGARCH-RM Vol.2.

/// 128 ビット定数。
fn k128<B: Backend>(b: &mut B, v: u128) -> B::V<W128> {
    b.konst::<W128>(v)
}

/// vr`i` のビット列。
fn vget<B: Backend>(b: &mut B, i: u64) -> B::V<W128> {
    let ix = b.konst::<W32>(i as u32);
    b.get_indexed(vr_array(), ix)
}

/// vr`i` にビット列を書く。
fn vset<B: Backend>(b: &mut B, i: u64, v: B::V<W128>) {
    let ix = b.konst::<W32>(i as u32);
    b.set_indexed(vr_array(), ix, v);
}

/// ベクトル `v` の `ebits` ビット要素 `idx` を W64 で取り出す
/// （ゼロ拡張済み）。
fn vlane<B: Backend>(b: &mut B, v: B::V<W128>, ebits: u32, idx: u32) -> B::V<W64> {
    let sh = k128(b, u128::from(idx * ebits));
    let x = b.shr_l::<W128>(v, sh);
    let m = k128(b, (1u128 << ebits) - 1);
    let x = b.and(x, m);
    b.trunc::<W128, W64>(x)
}

/// ベクトル `acc` の `ebits` ビット要素 `idx` に `e` を置いた値を返す。
fn vlane_set<B: Backend>(
    b: &mut B,
    acc: B::V<W128>,
    ebits: u32,
    idx: u32,
    e: B::V<W64>,
) -> B::V<W128> {
    let m = k128(b, (1u128 << ebits) - 1);
    let e = b.zext::<W64, W128>(e);
    let e = b.and(e, m);
    let sh = k128(b, u128::from(idx * ebits));
    let e = b.shl(e, sh);
    b.or(acc, e)
}

/// 全 `ebits` ビット要素に `e` を複写したベクトルを返す。
fn vsplat<B: Backend>(b: &mut B, e: B::V<W64>, ebits: u32) -> B::V<W128> {
    let m = k128(b, (1u128 << ebits) - 1);
    let e = b.zext::<W64, W128>(e);
    let mut v = b.and(e, m);
    for i in 1..(128 / ebits) {
        let sh = k128(b, u128::from(i * ebits));
        let y = b.shl(v, sh);
        v = b.or(v, y);
    }
    v
}

/// 32 ビット popcount（SWAR）。Ref: HAKMEM item 169.
fn popcnt32<B: Backend>(b: &mut B, v: B::V<W64>) -> B::V<W64> {
    let m1 = k(b, 0x5555_5555);
    let m2 = k(b, 0x3333_3333);
    let m4 = k(b, 0x0f0f_0f0f);
    let one = k(b, 1);
    let two = k(b, 2);
    let four = k(b, 4);
    let h = k(b, 0x0101_0101);
    let a = b.shr_l::<W64>(v, one);
    let a = b.and(a, m1);
    let v = b.sub(v, a);
    let a = b.shr_l::<W64>(v, two);
    let a = b.and(a, m2);
    let v = b.and(v, m2);
    let v = b.add(v, a);
    let a = b.shr_l::<W64>(v, four);
    let v = b.add(v, a);
    let v = b.and(v, m4);
    let v = b.mul::<W64>(v, h);
    let sh = k(b, 24);
    b.shr_l::<W64>(v, sh)
}

/// 要素ごとの 2 項演算（`ebits` ビット要素）。
/// `vd[i] = f(vj[i], vk[i])`。
fn vbin<B: Backend>(
    b: &mut B,
    ops: &[u64],
    ebits: u32,
    f: impl Fn(&mut B, B::V<W64>, B::V<W64>) -> B::V<W64>,
) {
    let vj = vget(b, ops[1]);
    let vk = vget(b, ops[2]);
    let mut v = k128(b, 0);
    for i in 0..(128 / ebits) {
        let a = vlane(b, vj, ebits, i);
        let c = vlane(b, vk, ebits, i);
        let e = f(b, a, c);
        v = vlane_set(b, v, ebits, i, e);
    }
    vset(b, ops[0], v);
}

/// VLDI の mode 選択（imm[12:8]）から 128 ビット定数を生成する。
/// mode 表は SPEC-LOONGARCH-RM Vol.2 の VLDI 節に基づく。
/// 未対応の mode は `None` を返し、呼び出し側が ILL に畳む。
fn vldi_value(mode: u64, imm8: u64) -> Option<u128> {
    let byte = imm8 & 0xff;
    let splat = |w: u64, ebits: u32| -> u128 {
        let mut v = 0u128;
        for i in 0..(128 / ebits) {
            v |= (w as u128 & ((1u128 << ebits) - 1)) << (i * ebits);
        }
        v
    };
    let sext8 = |bits: u32| -> u64 {
        let s = (((byte as i64) << 56) >> 56) as u64;
        s & ((1u64 << bits) - 1)
    };
    Some(match mode {
        // imm8 を各バイトへ。
        0 => splat(byte, 8),
        // sext8 を各 h/w/d へ。
        1 => splat(sext8(64), 16),
        2 => splat(sext8(64), 32),
        3 => splat(sext8(64), 64),
        // imm8 << 8 を各 h へ。
        4 => splat(byte << 8, 16),
        // imm8 << 16 / << 8 を各 w へ。
        5 => splat(byte << 16, 32),
        6 => splat(byte << 8, 32),
        // (imm8 << 8) | 0xff / (imm8 << 16) | 0xffff を各 w へ。
        7 => splat((byte << 8) | 0xff, 32),
        8 => splat((byte << 16) | 0xffff, 32),
        // imm8 のビット j を byte j の 0x00/0xff マスクへ展開。
        14 => {
            let mut v = 0u128;
            for j in 0..16u32 {
                let bit = if j < 8 { (byte >> j) & 1 } else { 0 };
                if bit == 1 {
                    v |= 0xffu128 << (j * 8);
                }
            }
            v
        }
        _ => return None,
    })
}

/// 1 命令の意味論を実行する。`word` は命令語、`pc` は命令番地、
/// `la64` は LA64 モデルで動いているか。戻り値 `Ok(true)` は
/// 実行済み（PC の進めは実行ループ側）。全 `Insn` 変種を網羅する
/// （match の網羅性で検査）。特権・近似系は GAP-0063 を参照。
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
        // ---- 整数ビット操作・乗除（LA5）----
        Insn::CloW => un_w(b, &ops, |b, x| {
            let nx = b.not(x);
            clz32(b, nx)
        }),
        Insn::ClzW => un_w(b, &ops, |b, x| clz32(b, x)),
        Insn::CtoW => un_w(b, &ops, |b, x| {
            let nx = b.not(x);
            ctz32(b, nx)
        }),
        Insn::CtzW => un_w(b, &ops, |b, x| ctz32(b, x)),
        Insn::CloD => un_d(b, &ops, |b, x| {
            let nx = b.not(x);
            clz64(b, nx)
        }),
        Insn::ClzD => un_d(b, &ops, |b, x| clz64(b, x)),
        Insn::CtoD => un_d(b, &ops, |b, x| {
            let nx = b.not(x);
            ctz64(b, nx)
        }),
        Insn::CtzD => un_d(b, &ops, |b, x| ctz64(b, x)),
        Insn::Revb2h => un_w(b, &ops, |b, x| byte_swap_in(b, x, 2, 32)),
        Insn::Revb4h => un_d(b, &ops, |b, x| byte_swap_in(b, x, 2, 64)),
        Insn::Revb2w => un_d(b, &ops, |b, x| byte_swap_in(b, x, 4, 64)),
        Insn::RevbD => un_d(b, &ops, |b, x| byte_swap_in(b, x, 8, 64)),
        Insn::Revh2w => un_d(b, &ops, |b, x| grp_swap(b, x, 16, 32, 64)),
        Insn::RevhD => un_d(b, &ops, |b, x| grp_swap(b, x, 16, 64, 64)),
        Insn::Bitrev4b => un_w(b, &ops, |b, x| bitrev_bytes(b, x, 32)),
        Insn::Bitrev8b => un_d(b, &ops, |b, x| bitrev_bytes(b, x, 64)),
        Insn::BitrevW => un_w(b, &ops, |b, x| {
            let a = zext_w(b, x);
            bitrev(b, a, 32)
        }),
        Insn::BitrevD => un_d(b, &ops, |b, x| bitrev(b, x, 64)),
        Insn::Maskeqz => {
            let a = rget(b, ops[1]);
            let cnd = rget(b, ops[2]);
            let zero = k(b, 0);
            let eq = b.cmp::<W64>(Cmp::Eq, cnd, zero);
            let z = k(b, 0);
            let v = b.select::<W64>(eq, z, a);
            rset(b, ops[0], v);
        }
        Insn::Masknez => {
            let a = rget(b, ops[1]);
            let cnd = rget(b, ops[2]);
            let zero = k(b, 0);
            let ne = b.cmp::<W64>(Cmp::Ne, cnd, zero);
            let z = k(b, 0);
            let v = b.select::<W64>(ne, z, a);
            rset(b, ops[0], v);
        }
        Insn::AlslW => {
            // rd = sext32((rj[31:0] << (sa2+1)) + rk[31:0])。
            let a = rget(b, ops[1]);
            let c = rget(b, ops[2]);
            let sh = k(b, ops[3] + 1);
            let s = b.shl::<W64>(a, sh);
            let v = b.add(s, c);
            let v = sext_w(b, v);
            rset(b, ops[0], v);
        }
        Insn::AlslWu => {
            let a = rget(b, ops[1]);
            let c = rget(b, ops[2]);
            let sh = k(b, ops[3] + 1);
            let s = b.shl::<W64>(a, sh);
            let v = b.add(s, c);
            let v = zext_w(b, v);
            rset(b, ops[0], v);
        }
        Insn::AlslD => {
            let a = rget(b, ops[1]);
            let c = rget(b, ops[2]);
            let sh = k(b, ops[3] + 1);
            let s = b.shl::<W64>(a, sh);
            let v = b.add(s, c);
            rset(b, ops[0], v);
        }
        Insn::BytepickW => {
            // rd = ({rk, rj} >> (8*sa2))[31:0] の sext 書き戻し。
            let a = rget(b, ops[1]);
            let c = rget(b, ops[2]);
            let sh32 = k(b, 32);
            let cat_hi = b.shl::<W64>(c, sh32);
            let a32 = b.trunc::<W64, W32>(a);
            let a64 = b.zext::<W32, W64>(a32);
            let cat = b.or(cat_hi, a64);
            let sh = k(b, ops[3] * 8);
            let v = b.shr_l::<W64>(cat, sh);
            let v = sext_w(b, v);
            rset(b, ops[0], v);
        }
        Insn::BytepickD => {
            // rd = {rk[8*(8-sa3):0], rj[63:8*(8-sa3)]}。
            let a = rget(b, ops[1]);
            let c = rget(b, ops[2]);
            let n = 64 - ops[3] * 8;
            let sh_n = k(b, n);
            let hi = b.shl::<W64>(c, sh_n);
            let sh_r = k(b, 64 - n);
            let lo = b.shr_l::<W64>(a, sh_r);
            let v = b.or(hi, lo);
            rset(b, ops[0], v);
        }
        Insn::RotrW => {
            let a = rget(b, ops[1]);
            let n0 = rget(b, ops[2]);
            let m = k(b, 31);
            let n = b.and(n0, m);
            let v = rotr(b, a, n, 32);
            let v = sext_w(b, v);
            rset(b, ops[0], v);
        }
        Insn::RotrD => {
            let a = rget(b, ops[1]);
            let n0 = rget(b, ops[2]);
            let m = k(b, 63);
            let n = b.and(n0, m);
            let v = rotr(b, a, n, 64);
            rset(b, ops[0], v);
        }
        Insn::RotriW => {
            let a = rget(b, ops[1]);
            let n = k(b, ops[2] & 31);
            let v = rotr(b, a, n, 32);
            let v = sext_w(b, v);
            rset(b, ops[0], v);
        }
        Insn::RotriD => {
            let a = rget(b, ops[1]);
            let n = k(b, ops[2] & 63);
            let v = rotr(b, a, n, 64);
            rset(b, ops[0], v);
        }
        Insn::BstrinsW => {
            // rd[msb:lsb] = rj[msb-lsb:0]（下位 32 ビット・sext 書き戻し）。
            let (msb, lsb) = (ops[2] as u32, ops[3] as u32);
            let width = msb - lsb + 1;
            let rj = rget(b, ops[1]);
            let rd = rget(b, ops[0]);
            let field = {
                let m = k(
                    b,
                    if width == 64 {
                        u64::MAX
                    } else {
                        (1u64 << width) - 1
                    },
                );
                let f = b.and(rj, m);
                let sh = k(b, u64::from(lsb));
                b.shl::<W64>(f, sh)
            };
            let mask = {
                let m: u64 = ((1u64 << width) - 1) << lsb;
                k(b, m)
            };
            let keep = {
                let nm = b.not(mask);
                b.and(rd, nm)
            };
            let v = b.or(keep, field);
            let v = sext_w(b, v);
            rset(b, ops[0], v);
        }
        Insn::BstrpickW => {
            // rd = zext32(rj[msb:lsb]) の sext 書き戻し。
            let (msb, lsb) = (ops[2] as u32, ops[3] as u32);
            let width = msb - lsb + 1;
            let rj = rget(b, ops[1]);
            let sh = k(b, u64::from(lsb));
            let f = b.shr_l::<W64>(rj, sh);
            let m = k(
                b,
                if width == 64 {
                    u64::MAX
                } else {
                    (1u64 << width) - 1
                },
            );
            let v = b.and(f, m);
            let v = sext_w(b, v);
            rset(b, ops[0], v);
        }
        Insn::BstrinsD => {
            let (msb, lsb) = (ops[2] as u32, ops[3] as u32);
            let width = msb - lsb + 1;
            let rj = rget(b, ops[1]);
            let rd = rget(b, ops[0]);
            let field = {
                let m = k(
                    b,
                    if width == 64 {
                        u64::MAX
                    } else {
                        (1u64 << width) - 1
                    },
                );
                let f = b.and(rj, m);
                let sh = k(b, u64::from(lsb));
                b.shl::<W64>(f, sh)
            };
            let mask = {
                let m: u64 = if width == 64 {
                    u64::MAX
                } else {
                    ((1u64 << width) - 1) << lsb
                };
                k(b, m)
            };
            let keep = {
                let nm = b.not(mask);
                b.and(rd, nm)
            };
            let v = b.or(keep, field);
            rset(b, ops[0], v);
        }
        Insn::BstrpickD => {
            let (msb, lsb) = (ops[2] as u32, ops[3] as u32);
            let width = msb - lsb + 1;
            let rj = rget(b, ops[1]);
            let sh = k(b, u64::from(lsb));
            let f = b.shr_l::<W64>(rj, sh);
            let m = k(
                b,
                if width == 64 {
                    u64::MAX
                } else {
                    (1u64 << width) - 1
                },
            );
            let v = b.and(f, m);
            rset(b, ops[0], v);
        }
        Insn::Addu16iD => {
            // rd = rj + sext(si16 << 16)。
            let a = rget(b, ops[1]);
            let d = k(b, sext_n(ops[2] << 16, 32));
            let v = b.add(a, d);
            rset(b, ops[0], v);
        }
        Insn::MulW => {
            let a = rget(b, ops[1]);
            let c = rget(b, ops[2]);
            let a32 = b.trunc::<W64, W32>(a);
            let c32 = b.trunc::<W64, W32>(c);
            let p = b.mul::<W32>(a32, c32);
            let v = b.sext::<W32, W64>(p);
            rset(b, ops[0], v);
        }
        Insn::MulhW => {
            let a = rget(b, ops[1]);
            let c = rget(b, ops[2]);
            let a32 = b.trunc::<W64, W32>(a);
            let c32 = b.trunc::<W64, W32>(c);
            let p = b.mulh::<W32>(a32, c32);
            let v = b.sext::<W32, W64>(p);
            rset(b, ops[0], v);
        }
        Insn::MulhWu => {
            let a = rget(b, ops[1]);
            let c = rget(b, ops[2]);
            let a32 = b.trunc::<W64, W32>(a);
            let c32 = b.trunc::<W64, W32>(c);
            let p = b.mulhu::<W32>(a32, c32);
            let v = b.sext::<W32, W64>(p);
            rset(b, ops[0], v);
        }
        Insn::MulwDW => {
            // rd = sext32(rj) * sext32(rk) の 64 ビット積。
            let a = rget(b, ops[1]);
            let c = rget(b, ops[2]);
            let a32 = b.trunc::<W64, W32>(a);
            let c32 = b.trunc::<W64, W32>(c);
            let p = b.mulh::<W32>(a32, c32);
            let lo = b.mul::<W32>(a32, c32);
            let lo64 = b.zext::<W32, W64>(lo);
            let hi64 = b.zext::<W32, W64>(p);
            let sh = k(b, 32);
            let hi_sh = b.shl::<W64>(hi64, sh);
            let v = b.or(hi_sh, lo64);
            rset(b, ops[0], v);
        }
        Insn::MulwDWu => {
            // rd = zext32(rj) *u zext32(rk) の 64 ビット積。
            let a = rget(b, ops[1]);
            let c = rget(b, ops[2]);
            let a32 = b.trunc::<W64, W32>(a);
            let c32 = b.trunc::<W64, W32>(c);
            let p = b.mulhu::<W32>(a32, c32);
            let lo = b.mul::<W32>(a32, c32);
            let lo64 = b.zext::<W32, W64>(lo);
            let hi64 = b.zext::<W32, W64>(p);
            let sh = k(b, 32);
            let hi_sh = b.shl::<W64>(hi64, sh);
            let v = b.or(hi_sh, lo64);
            rset(b, ops[0], v);
        }
        Insn::MulD => bin3(b, &ops, false, |b, x, y| b.mul::<W64>(x, y)),
        Insn::MulhD => bin3(b, &ops, false, |b, x, y| b.mulh::<W64>(x, y)),
        Insn::MulhDu => bin3(b, &ops, false, |b, x, y| b.mulhu::<W64>(x, y)),
        Insn::DivW => {
            let a = rget(b, ops[1]);
            let c = rget(b, ops[2]);
            let a32 = b.trunc::<W64, W32>(a);
            let c32 = b.trunc::<W64, W32>(c);
            let q = b.sdiv::<W32>(a32, c32);
            let v = b.sext::<W32, W64>(q);
            rset(b, ops[0], v);
        }
        Insn::ModW => {
            let a = rget(b, ops[1]);
            let c = rget(b, ops[2]);
            let a32 = b.trunc::<W64, W32>(a);
            let c32 = b.trunc::<W64, W32>(c);
            let q = b.srem::<W32>(a32, c32);
            let v = b.sext::<W32, W64>(q);
            rset(b, ops[0], v);
        }
        Insn::DivWu => {
            let a = rget(b, ops[1]);
            let c = rget(b, ops[2]);
            let a32 = b.trunc::<W64, W32>(a);
            let c32 = b.trunc::<W64, W32>(c);
            let q = b.udiv::<W32>(a32, c32);
            let v = b.sext::<W32, W64>(q);
            rset(b, ops[0], v);
        }
        Insn::ModWu => {
            let a = rget(b, ops[1]);
            let c = rget(b, ops[2]);
            let a32 = b.trunc::<W64, W32>(a);
            let c32 = b.trunc::<W64, W32>(c);
            let q = b.urem::<W32>(a32, c32);
            let v = b.sext::<W32, W64>(q);
            rset(b, ops[0], v);
        }
        Insn::DivD => bin3(b, &ops, false, |b, x, y| b.sdiv::<W64>(x, y)),
        Insn::ModD => bin3(b, &ops, false, |b, x, y| b.srem::<W64>(x, y)),
        Insn::DivDu => bin3(b, &ops, false, |b, x, y| b.udiv::<W64>(x, y)),
        Insn::ModDu => bin3(b, &ops, false, |b, x, y| b.urem::<W64>(x, y)),
        Insn::CrcWBW
        | Insn::CrcWHW
        | Insn::CrcWWW
        | Insn::CrcWDW
        | Insn::CrccWBW
        | Insn::CrccWHW
        | Insn::CrccWWW
        | Insn::CrccWDW => {
            // CRC: rd = CRC32(rj, rk の下位 n バイト)。crc 系は
            // 0xEDB88320、crcc 系は 0x82F63B78（反映形）。
            // Ref: SPEC-LOONGARCH-RM §2.2.1.14.
            let crc_c = matches!(
                insn,
                Insn::CrccWBW | Insn::CrccWHW | Insn::CrccWWW | Insn::CrccWDW
            );
            let poly: u32 = if crc_c { 0x82f6_3b78 } else { 0xedb8_8320 };
            let bytes: u64 = match insn {
                Insn::CrcWBW | Insn::CrccWBW => 1,
                Insn::CrcWHW | Insn::CrccWHW => 2,
                Insn::CrcWWW | Insn::CrccWWW => 4,
                _ => 8,
            };
            let rj = rget(b, ops[1]);
            let rk = rget(b, ops[2]);
            let mut c = b.trunc::<W64, W32>(rj);
            for i in 0..bytes {
                let sh = k(b, i * 8);
                let byte = b.shr_l::<W64>(rk, sh);
                let m8 = k(b, 0xff);
                let byte = b.and(byte, m8);
                let b32 = b.trunc::<W64, W32>(byte);
                c = b.xor::<W32>(c, b32);
                c = crc32(b, c, poly, 8);
            }
            let v = b.zext::<W32, W64>(c);
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
        // ---- index 付き load/store（ea = rj + rk、LA6）----
        // Ref: SPEC-LOONGARCH-RM §2.2.3.3.
        Insn::LdxB | Insn::LdxBu => {
            let ea = ldx_ea(b, &ops);
            let v = b.load::<W8>(ea, DATA)?;
            let v = if insn == Insn::LdxB {
                b.sext::<W8, W64>(v)
            } else {
                b.zext::<W8, W64>(v)
            };
            rset(b, ops[0], v);
        }
        Insn::LdxH | Insn::LdxHu => {
            let ea = ldx_ea(b, &ops);
            let v = b.load::<W16>(ea, DATA)?;
            let v = if insn == Insn::LdxH {
                b.sext::<W16, W64>(v)
            } else {
                b.zext::<W16, W64>(v)
            };
            rset(b, ops[0], v);
        }
        Insn::LdxW | Insn::LdxWu => {
            let ea = ldx_ea(b, &ops);
            let v = b.load::<W32>(ea, DATA)?;
            let v = if insn == Insn::LdxW {
                b.sext::<W32, W64>(v)
            } else {
                b.zext::<W32, W64>(v)
            };
            rset(b, ops[0], v);
        }
        Insn::LdxD => {
            let ea = ldx_ea(b, &ops);
            let v = b.load::<W64>(ea, DATA)?;
            rset(b, ops[0], v);
        }
        Insn::StxB => {
            let ea = ldx_ea(b, &ops);
            let v0 = rget(b, ops[0]);
            let v = b.trunc::<W64, W8>(v0);
            b.store::<W8>(ea, v, STORE)?;
        }
        Insn::StxH => {
            let ea = ldx_ea(b, &ops);
            let v0 = rget(b, ops[0]);
            let v = b.trunc::<W64, W16>(v0);
            b.store::<W16>(ea, v, STORE)?;
        }
        Insn::StxW => {
            let ea = ldx_ea(b, &ops);
            let v0 = rget(b, ops[0]);
            let v = b.trunc::<W64, W32>(v0);
            b.store::<W32>(ea, v, STORE)?;
        }
        Insn::StxD => {
            let ea = ldx_ea(b, &ops);
            let v = rget(b, ops[0]);
            b.store::<W64>(ea, v, STORE)?;
        }
        // ---- ldptr/stptr（ea = rj + sext(si14 << 2)、LA6）----
        // Ref: SPEC-LOONGARCH-RM §2.2.3.2.
        Insn::LdptrW => {
            let ea = ptr_ea(b, &ops);
            let v = b.load::<W32>(ea, DATA)?;
            let v = b.sext::<W32, W64>(v);
            rset(b, ops[0], v);
        }
        Insn::LdptrD => {
            let ea = ptr_ea(b, &ops);
            let v = b.load::<W64>(ea, DATA)?;
            rset(b, ops[0], v);
        }
        Insn::StptrW => {
            let ea = ptr_ea(b, &ops);
            let v0 = rget(b, ops[0]);
            let v = b.trunc::<W64, W32>(v0);
            b.store::<W32>(ea, v, STORE)?;
        }
        Insn::StptrD => {
            let ea = ptr_ea(b, &ops);
            let v = rget(b, ops[0]);
            b.store::<W64>(ea, v, STORE)?;
        }
        // ---- LL/SC（LA6。interp の予約機構に載せる）----
        // Ref: SPEC-LOONGARCH-RM §2.2.7.4.
        Insn::LlW => {
            let ea = ptr_ea(b, &ops);
            let v = b.load_reserved::<W32>(ea, ACC_LL)?;
            let v = b.sext::<W32, W64>(v);
            rset(b, ops[0], v);
        }
        Insn::LlD => {
            let ea = ptr_ea(b, &ops);
            let v = b.load_reserved::<W64>(ea, ACC_LL)?;
            rset(b, ops[0], v);
        }
        Insn::ScW => {
            let ea = ptr_ea(b, &ops);
            let v0 = rget(b, ops[0]);
            let v = b.trunc::<W64, W32>(v0);
            let ok = b.store_conditional::<W32>(ea, v, ACC_SC)?;
            let one = k(b, 1);
            let zero = k(b, 0);
            let r = b.select::<W64>(ok, one, zero);
            rset(b, ops[0], r);
        }
        Insn::ScD => {
            let ea = ptr_ea(b, &ops);
            let v = rget(b, ops[0]);
            let ok = b.store_conditional::<W64>(ea, v, ACC_SC)?;
            let one = k(b, 1);
            let zero = k(b, 0);
            let r = b.select::<W64>(ok, one, zero);
            rset(b, ops[0], r);
        }
        Insn::ScQ => {
            // sc.q rd, rk, rj: [rj] ← GR[rd]、[rj+8] ← GR[rk]、
            // rd ← 成功旗。番地は 16 バイト整列必須。
            // Ref: SPEC-LOONGARCH-RM §2.2.7.4.
            let ea = rget(b, ops[2]);
            let m = k(b, 15);
            let low = b.and(ea, m);
            let zero = k(b, 0);
            let mis = b.cmp::<W64>(Cmp::Ne, low, zero);
            b.if_then(mis, |b| Err(raise::<B>(b, ExceptionKind::Align, 0)))?;
            let lo = rget(b, ops[0]);
            let ok = b.store_conditional::<W64>(ea, lo, ACC_SC)?;
            let one = k(b, 1);
            let okv = b.select::<W64>(ok, one, zero);
            // 予約が生きていたときだけ上位 64 ビットも書く。
            let doit = b.cmp::<W64>(Cmp::Ne, okv, zero);
            b.if_then(doit, |b| {
                let hi = rget(b, ops[1]);
                let eight = k(b, 8);
                let ea2 = b.add(ea, eight);
                b.store::<W64>(ea2, hi, STORE)
            })?;
            rset(b, ops[0], okv);
        }
        // llacq/screl は FR2 形（ea = GR[rj]）。単一スレッドでは
        // acquire/release の区別は効かない。Gap: GAP-0063.
        Insn::LlacqW => {
            let ea = rget(b, ops[1]);
            let v = b.load_reserved::<W32>(ea, ACC_LL)?;
            let v = b.sext::<W32, W64>(v);
            rset(b, ops[0], v);
        }
        Insn::LlacqD => {
            let ea = rget(b, ops[1]);
            let v = b.load_reserved::<W64>(ea, ACC_LL)?;
            rset(b, ops[0], v);
        }
        Insn::ScrelW => {
            let ea = rget(b, ops[1]);
            let v0 = rget(b, ops[0]);
            let v = b.trunc::<W64, W32>(v0);
            let ok = b.store_conditional::<W32>(ea, v, ACC_SC)?;
            let one = k(b, 1);
            let zero = k(b, 0);
            let r = b.select::<W64>(ok, one, zero);
            rset(b, ops[0], r);
        }
        Insn::ScrelD => {
            let ea = rget(b, ops[1]);
            let v = rget(b, ops[0]);
            let ok = b.store_conditional::<W64>(ea, v, ACC_SC)?;
            let one = k(b, 1);
            let zero = k(b, 0);
            let r = b.select::<W64>(ok, one, zero);
            rset(b, ops[0], r);
        }
        // preld/preldx はプリフェッチヒント。キャッシュを持たない
        // モデルでは効果なしの no-op。Gap: GAP-0063.
        Insn::Preld | Insn::Preldx => {}
        // ---- bound check 付き load/store（LA6）----
        // Ref: SPEC-LOONGARCH-RM §2.2.3.4（BCE）.
        Insn::LdgtB | Insn::LdgtH | Insn::LdgtW | Insn::LdgtD => {
            bound_check(b, &ops, true)?;
            let ea = rget(b, ops[1]);
            let v = match insn {
                Insn::LdgtB => {
                    let x = b.load::<W8>(ea, DATA)?;
                    b.sext::<W8, W64>(x)
                }
                Insn::LdgtH => {
                    let x = b.load::<W16>(ea, DATA)?;
                    b.sext::<W16, W64>(x)
                }
                Insn::LdgtW => {
                    let x = b.load::<W32>(ea, DATA)?;
                    b.sext::<W32, W64>(x)
                }
                _ => b.load::<W64>(ea, DATA)?,
            };
            rset(b, ops[0], v);
        }
        Insn::LdleB | Insn::LdleH | Insn::LdleW | Insn::LdleD => {
            bound_check(b, &ops, false)?;
            let ea = rget(b, ops[1]);
            let v = match insn {
                Insn::LdleB => {
                    let x = b.load::<W8>(ea, DATA)?;
                    b.sext::<W8, W64>(x)
                }
                Insn::LdleH => {
                    let x = b.load::<W16>(ea, DATA)?;
                    b.sext::<W16, W64>(x)
                }
                Insn::LdleW => {
                    let x = b.load::<W32>(ea, DATA)?;
                    b.sext::<W32, W64>(x)
                }
                _ => b.load::<W64>(ea, DATA)?,
            };
            rset(b, ops[0], v);
        }
        Insn::StgtB | Insn::StgtH | Insn::StgtW | Insn::StgtD => {
            bound_check(b, &ops, true)?;
            let ea = rget(b, ops[1]);
            let v0 = rget(b, ops[0]);
            match insn {
                Insn::StgtB => {
                    let v = b.trunc::<W64, W8>(v0);
                    b.store::<W8>(ea, v, STORE)?;
                }
                Insn::StgtH => {
                    let v = b.trunc::<W64, W16>(v0);
                    b.store::<W16>(ea, v, STORE)?;
                }
                Insn::StgtW => {
                    let v = b.trunc::<W64, W32>(v0);
                    b.store::<W32>(ea, v, STORE)?;
                }
                _ => b.store::<W64>(ea, v0, STORE)?,
            }
        }
        Insn::StleB | Insn::StleH | Insn::StleW | Insn::StleD => {
            bound_check(b, &ops, false)?;
            let ea = rget(b, ops[1]);
            let v0 = rget(b, ops[0]);
            match insn {
                Insn::StleB => {
                    let v = b.trunc::<W64, W8>(v0);
                    b.store::<W8>(ea, v, STORE)?;
                }
                Insn::StleH => {
                    let v = b.trunc::<W64, W16>(v0);
                    b.store::<W16>(ea, v, STORE)?;
                }
                Insn::StleW => {
                    let v = b.trunc::<W64, W32>(v0);
                    b.store::<W32>(ea, v, STORE)?;
                }
                _ => b.store::<W64>(ea, v0, STORE)?,
            }
        }
        // ---- AM*（read-modify-write。単一スレッド近似。
        // _db はデータバリアを兼ねるが単一スレッドでは効果なし。
        // Gap: GAP-0063）----
        // Ref: SPEC-LOONGARCH-RM §2.2.7.1/§2.2.7.2.
        Insn::AmaddW | Insn::AmaddDbW => {
            am_w(b, &ops, |b, x, y| b.add::<W32>(x, y))?;
        }
        Insn::AmaddD | Insn::AmaddDbD => {
            am_d(b, &ops, |b, x, y| b.add::<W64>(x, y))?;
        }
        Insn::AmaddB | Insn::AmaddDbB => {
            am_bh::<B, W8>(b, &ops, |b, x, y| b.add::<W8>(x, y))?;
        }
        Insn::AmaddH | Insn::AmaddDbH => {
            am_bh::<B, W16>(b, &ops, |b, x, y| b.add::<W16>(x, y))?;
        }
        Insn::AmswapW | Insn::AmswapDbW => {
            am_w(b, &ops, |_b, _x, y| y)?;
        }
        Insn::AmswapD | Insn::AmswapDbD => {
            am_d(b, &ops, |_b, _x, y| y)?;
        }
        Insn::AmswapB | Insn::AmswapDbB => {
            am_bh::<B, W8>(b, &ops, |_b, _x, y| y)?;
        }
        Insn::AmswapH | Insn::AmswapDbH => {
            am_bh::<B, W16>(b, &ops, |_b, _x, y| y)?;
        }
        Insn::AmandW | Insn::AmandDbW => {
            am_w(b, &ops, |b, x, y| b.and::<W32>(x, y))?;
        }
        Insn::AmandD | Insn::AmandDbD => {
            am_d(b, &ops, |b, x, y| b.and::<W64>(x, y))?;
        }
        Insn::AmorW | Insn::AmorDbW => {
            am_w(b, &ops, |b, x, y| b.or::<W32>(x, y))?;
        }
        Insn::AmorD | Insn::AmorDbD => {
            am_d(b, &ops, |b, x, y| b.or::<W64>(x, y))?;
        }
        Insn::AmxorW | Insn::AmxorDbW => {
            am_w(b, &ops, |b, x, y| b.xor::<W32>(x, y))?;
        }
        Insn::AmxorD | Insn::AmxorDbD => {
            am_d(b, &ops, |b, x, y| b.xor::<W64>(x, y))?;
        }
        Insn::AmmaxW | Insn::AmmaxDbW => {
            am_w(b, &ops, |b, x, y| {
                let c = b.cmp::<W32>(Cmp::LtS, x, y);
                b.select::<W32>(c, y, x)
            })?;
        }
        Insn::AmmaxD | Insn::AmmaxDbD => {
            am_d(b, &ops, |b, x, y| {
                let c = b.cmp::<W64>(Cmp::LtS, x, y);
                b.select::<W64>(c, y, x)
            })?;
        }
        Insn::AmmaxWu | Insn::AmmaxDbWu => {
            am_w(b, &ops, |b, x, y| {
                let c = b.cmp::<W32>(Cmp::LtU, x, y);
                b.select::<W32>(c, y, x)
            })?;
        }
        Insn::AmmaxDu | Insn::AmmaxDbDu => {
            am_d(b, &ops, |b, x, y| {
                let c = b.cmp::<W64>(Cmp::LtU, x, y);
                b.select::<W64>(c, y, x)
            })?;
        }
        Insn::AmminW | Insn::AmminDbW => {
            am_w(b, &ops, |b, x, y| {
                let c = b.cmp::<W32>(Cmp::LtS, x, y);
                b.select::<W32>(c, x, y)
            })?;
        }
        Insn::AmminD | Insn::AmminDbD => {
            am_d(b, &ops, |b, x, y| {
                let c = b.cmp::<W64>(Cmp::LtS, x, y);
                b.select::<W64>(c, x, y)
            })?;
        }
        Insn::AmminWu | Insn::AmminDbWu => {
            am_w(b, &ops, |b, x, y| {
                let c = b.cmp::<W32>(Cmp::LtU, x, y);
                b.select::<W32>(c, x, y)
            })?;
        }
        Insn::AmminDu | Insn::AmminDbDu => {
            am_d(b, &ops, |b, x, y| {
                let c = b.cmp::<W64>(Cmp::LtU, x, y);
                b.select::<W64>(c, x, y)
            })?;
        }
        // ---- AMCAS（ops = [rd, rk, rj]。*rj が rd と一致すれば
        // rk を書き、rd ← 旧値）----
        // Ref: SPEC-LOONGARCH-RM §2.2.7.3.
        Insn::AmcasB | Insn::AmcasDbB => {
            let ea = rget(b, ops[2]);
            let nv64 = rget(b, ops[1]);
            let ov64 = rget(b, ops[0]);
            let nv = b.trunc::<W64, W8>(nv64);
            let ov = b.trunc::<W64, W8>(ov64);
            let old = b.cmpxchg::<W8>(ea, ov, nv, ACC_AM)?;
            let v = b.sext::<W8, W64>(old);
            rset(b, ops[0], v);
        }
        Insn::AmcasH | Insn::AmcasDbH => {
            let ea = rget(b, ops[2]);
            let nv64 = rget(b, ops[1]);
            let ov64 = rget(b, ops[0]);
            let nv = b.trunc::<W64, W16>(nv64);
            let ov = b.trunc::<W64, W16>(ov64);
            let old = b.cmpxchg::<W16>(ea, ov, nv, ACC_AM)?;
            let v = b.sext::<W16, W64>(old);
            rset(b, ops[0], v);
        }
        Insn::AmcasW | Insn::AmcasDbW => {
            let ea = rget(b, ops[2]);
            let nv64 = rget(b, ops[1]);
            let ov64 = rget(b, ops[0]);
            let nv = b.trunc::<W64, W32>(nv64);
            let ov = b.trunc::<W64, W32>(ov64);
            let old = b.cmpxchg::<W32>(ea, ov, nv, ACC_AM)?;
            let v = b.sext::<W32, W64>(old);
            rset(b, ops[0], v);
        }
        Insn::AmcasD | Insn::AmcasDbD => {
            let ea = rget(b, ops[2]);
            let nv = rget(b, ops[1]);
            let ov = rget(b, ops[0]);
            let old = b.cmpxchg::<W64>(ea, ov, nv, ACC_AM)?;
            rset(b, ops[0], old);
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
        // ---- 条件分岐（LA7）----
        // Ref: SPEC-LOONGARCH-RM §2.2.4.1.
        Insn::Beq | Insn::Bne | Insn::Blt | Insn::Bge | Insn::Bltu | Insn::Bgeu => {
            // ops = [rj, rd, offs16]。ターゲットは pc + sext(offs << 2)。
            let x = rget(b, ops[0]);
            let y = rget(b, ops[1]);
            let cond = match insn {
                Insn::Beq => Cmp::Eq,
                Insn::Bne => Cmp::Ne,
                Insn::Blt => Cmp::LtS,
                Insn::Bge => Cmp::GeS,
                Insn::Bltu => Cmp::LtU,
                _ => Cmp::GeU,
            };
            let c = b.cmp::<W64>(cond, x, y);
            let t = pc.wrapping_add(offs_n(ops[2], 16, false) as u64);
            b.branch(c, t);
        }
        Insn::Beqz | Insn::Bnez => {
            // ops = [rj, offs21]。ターゲットは pc + sext(offs21 << 2)。
            let x = rget(b, ops[0]);
            let zero = k(b, 0);
            let cond = if insn == Insn::Beqz { Cmp::Eq } else { Cmp::Ne };
            let c = b.cmp::<W64>(cond, x, zero);
            let t = pc.wrapping_add(offs_n(ops[1], 21, true) as u64);
            b.branch(c, t);
        }
        Insn::Bceqz | Insn::Bcnez => {
            // ops = [cj, offs21]。FCC[cj] が条件。
            // Ref: SPEC-LOONGARCH-RM §3.4.7.
            let fcc = b.get(fcc_ref());
            let sh = k(b, ops[0]);
            let bit0 = b.shr_l::<W64>(fcc, sh);
            let one = k(b, 1);
            let bit = b.and(bit0, one);
            let zero = k(b, 0);
            let cond = if insn == Insn::Bceqz {
                Cmp::Eq
            } else {
                Cmp::Ne
            };
            let c = b.cmp::<W64>(cond, bit, zero);
            let t = pc.wrapping_add(offs_n(ops[1], 21, true) as u64);
            b.branch(c, t);
        }
        Insn::AsrtleD | Insn::AsrtgtD => {
            // ops = [rj, rk]。asrtle: rj > rk で BCE、asrtgt: rj <= rk で BCE。
            // Ref: SPEC-LOONGARCH-RM §2.2.10.3.
            let a = rget(b, ops[0]);
            let lim = rget(b, ops[1]);
            let c = if insn == Insn::AsrtleD {
                b.cmp::<W64>(Cmp::GtS, a, lim)
            } else {
                b.cmp::<W64>(Cmp::LeS, a, lim)
            };
            b.if_then(c, |b| Err(raise::<B>(b, ExceptionKind::Trap, TRAP_BND)))?;
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
        // rd ← StableCounter、rj ← Counter ID。Counter ID は
        // モデルしないため 0 を返す。Gap: GAP-0063.
        // Ref: SPEC-LOONGARCH-RM §2.2.10.4.
        Insn::RdtimelW => {
            let c = b.get(cnt_ref());
            let v = sext_w(b, c);
            rset(b, ops[0], v);
            let zero = k(b, 0);
            rset(b, ops[1], zero);
        }
        Insn::RdtimehW => {
            let c = b.get(cnt_ref());
            let n = k(b, 32);
            let v0 = b.shr_l::<W64>(c, n);
            let v = sext_w(b, v0);
            rset(b, ops[0], v);
            let zero = k(b, 0);
            rset(b, ops[1], zero);
        }
        Insn::RdtimeD => {
            let v = b.get(cnt_ref());
            rset(b, ops[0], v);
            let zero = k(b, 0);
            rset(b, ops[1], zero);
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
        // ---- CSR 読み書き（LA8）----
        // csr[ idx ] は 512 エントリの配列近似。idx >= 512 の
        // 未割当て番号は読み 0・書き捨て。特権レベルの検査は
        // しない。Gap: GAP-0063.
        // Ref: SPEC-LOONGARCH-RM §4.1.7.
        Insn::Csrrd => {
            // ops = [rd, rj(=0), csr14]。
            let v = csr_load::<B>(b, ops[2]);
            rset(b, ops[0], v);
        }
        Insn::Csrwr => {
            // ops = [rd, rj(=1), csr14]。CSR ← rd 旧値、rd ← CSR 旧値。
            let old = csr_load::<B>(b, ops[2]);
            let nv = rget(b, ops[0]);
            csr_store(b, ops[2], nv)?;
            rset(b, ops[0], old);
        }
        Insn::Csrxchg => {
            // ops = [rd, rj, csr14]。rj を書きマスクに使い、
            // CSR = (CSR & ~mask) | (rd & mask)、rd ← CSR 旧値。
            let old = csr_load::<B>(b, ops[2]);
            let mask = rget(b, ops[1]);
            let rd = rget(b, ops[0]);
            let nmask = b.not(mask);
            let keep = b.and(old, nmask);
            let put = b.and(rd, mask);
            let nv = b.or(keep, put);
            csr_store(b, ops[2], nv)?;
            rset(b, ops[0], old);
        }
        Insn::Ertn => {
            // pc ← CSR.ERA、CRMD[2:0]（PLV・IE）← PRMD[2:0]
            // （PPLV・PIE）。割込・ネストの配送はモデルしない。
            // Gap: GAP-0063.
            // Ref: SPEC-LOONGARCH-RM §4.1.7.
            let idx = k(b, csr::ERA as u64);
            let idx32 = b.trunc::<W64, W32>(idx);
            let era = b.get_indexed(csr_array(), idx32);
            let pidx = k(b, csr::PRMD as u64);
            let pidx32 = b.trunc::<W64, W32>(pidx);
            let prmd = b.get_indexed(csr_array(), pidx32);
            let cidx = k(b, csr::CRMD as u64);
            let cidx32 = b.trunc::<W64, W32>(cidx);
            let crmd = b.get_indexed(csr_array(), cidx32);
            let mask7 = k(b, !7u64);
            let keep = b.and(crmd, mask7);
            let bits = k(b, 7);
            let low = b.and(prmd, bits);
            let ncrmd = b.or(keep, low);
            b.set_indexed(csr_array(), cidx32, ncrmd);
            b.jump(era);
        }
        // ---- 特権・システム近似（LA8）----
        // MMU/TLB・キャッシュ・IOCSR・省電力をモデルしないため、
        // TLB 操作・CACOP・IOCSR・IDLE・INVTLB・LDDIR/LDPTE は
        // 表層のみの no-op 近似。Gap: GAP-0063.
        Insn::Tlbclr
        | Insn::Tlbfill
        | Insn::Tlbflush
        | Insn::Tlbrd
        | Insn::Tlbsrch
        | Insn::Tlbwr
        | Insn::Invtlb
        | Insn::Cacop
        | Insn::Ldpte => {}
        Insn::Idle => {
            // 割込待ち。単一スレッド・割込なしの模型では
            // 直ちに復帰する no-op。Gap: GAP-0063.
        }
        Insn::Lddir => {
            // ページテーブル走査は MMU 未モデルのため rd ← 0。
            // Gap: GAP-0063.
            let zero = k(b, 0);
            rset(b, ops[0], zero);
        }
        Insn::IocsrrdB | Insn::IocsrrdH | Insn::IocsrrdW | Insn::IocsrrdD => {
            // IOCSR 空間はモデルしないので 0 を返す。Gap: GAP-0063.
            let zero = k(b, 0);
            rset(b, ops[0], zero);
        }
        Insn::IocsrwrB | Insn::IocsrwrH | Insn::IocsrwrW | Insn::IocsrwrD => {}
        Insn::Dbcl => {
            // デバッグ例外入口。デバッグモードを持たないため
            // 例外として発火させ、code = TRAP_DBG_BASE | code15。
            // Gap: GAP-0063.
            return Err(raise::<B>(b, ExceptionKind::Trap, TRAP_DBG_BASE | ops[0]));
        }
        // ---- スカラ FP 算術（LA9。丸めは FCSR.RM に従う）----
        // Ref: SPEC-LOONGARCH-RM §3.2.1.1.
        Insn::FaddS => {
            with_la_rm(b, |b, rm| {
                fbin32(b, &ops, |b, x, y| b.fadd_r::<W32>(x, y, rm));
                Ok(())
            })?;
        }
        Insn::FaddD => {
            with_la_rm(b, |b, rm| {
                fbin64(b, &ops, |b, x, y| b.fadd_r::<W64>(x, y, rm));
                Ok(())
            })?;
        }
        Insn::FsubS => {
            with_la_rm(b, |b, rm| {
                fbin32(b, &ops, |b, x, y| b.fsub_r::<W32>(x, y, rm));
                Ok(())
            })?;
        }
        Insn::FsubD => {
            with_la_rm(b, |b, rm| {
                fbin64(b, &ops, |b, x, y| b.fsub_r::<W64>(x, y, rm));
                Ok(())
            })?;
        }
        Insn::FmulS => {
            with_la_rm(b, |b, rm| {
                fbin32(b, &ops, |b, x, y| b.fmul_r::<W32>(x, y, rm));
                Ok(())
            })?;
        }
        Insn::FmulD => {
            with_la_rm(b, |b, rm| {
                fbin64(b, &ops, |b, x, y| b.fmul_r::<W64>(x, y, rm));
                Ok(())
            })?;
        }
        Insn::FdivS => {
            with_la_rm(b, |b, rm| {
                fbin32(b, &ops, |b, x, y| b.fdiv_r::<W32>(x, y, rm));
                Ok(())
            })?;
        }
        Insn::FdivD => {
            with_la_rm(b, |b, rm| {
                fbin64(b, &ops, |b, x, y| b.fdiv_r::<W64>(x, y, rm));
                Ok(())
            })?;
        }
        // FMA 系。FMSUB=fj*fk-fa、FNMADD=-(fj*fk+fa)、
        // FNMSUB=-(fj*fk-fa)。Ref: §3.2.1.2.
        Insn::FmaddS | Insn::FmsubS | Insn::FnmaddS | Insn::FnmsubS => {
            with_la_rm(b, |b, rm| {
                let x = fget32(b, ops[1]);
                let y = fget32(b, ops[2]);
                let mut z = fget32(b, ops[3]);
                if insn == Insn::FmsubS || insn == Insn::FnmsubS {
                    z = fneg_v::<B, W32>(b, z);
                }
                let r0 = b.fmadd_r::<W32>(x, y, z, rm);
                let r = if insn == Insn::FnmaddS || insn == Insn::FnmsubS {
                    fneg_v::<B, W32>(b, r0)
                } else {
                    r0
                };
                fset32(b, ops[0], r);
                fpo_end(b);
                Ok(())
            })?;
        }
        Insn::FmaddD | Insn::FmsubD | Insn::FnmaddD | Insn::FnmsubD => {
            with_la_rm(b, |b, rm| {
                let x = fget(b, ops[1]);
                let y = fget(b, ops[2]);
                let mut z = fget(b, ops[3]);
                if insn == Insn::FmsubD || insn == Insn::FnmsubD {
                    z = fneg_v::<B, W64>(b, z);
                }
                let r0 = b.fmadd_r::<W64>(x, y, z, rm);
                let r = if insn == Insn::FnmaddD || insn == Insn::FnmsubD {
                    fneg_v::<B, W64>(b, r0)
                } else {
                    r0
                };
                fset(b, ops[0], r);
                fpo_end(b);
                Ok(())
            })?;
        }
        // FMIN/FMAX は IEEE maxNum/minNum。Ref: §3.2.1.3.
        Insn::FminS => fbin32(b, &ops, |b, x, y| b.fmin::<W32>(x, y)),
        Insn::FminD => fbin64(b, &ops, |b, x, y| b.fmin::<W64>(x, y)),
        Insn::FmaxS => fbin32(b, &ops, |b, x, y| b.fmax::<W32>(x, y)),
        Insn::FmaxD => fbin64(b, &ops, |b, x, y| b.fmax::<W64>(x, y)),
        // FMAXA/FMINA は絶対値比較。Ref: §3.2.1.4.
        Insn::FmaxaS => fbin32(b, &ops, |b, x, y| fmag::<B, W32>(b, x, y, true)),
        Insn::FmaxaD => fbin64(b, &ops, |b, x, y| fmag::<B, W64>(b, x, y, true)),
        Insn::FminaS => fbin32(b, &ops, |b, x, y| fmag::<B, W32>(b, x, y, false)),
        Insn::FminaD => fbin64(b, &ops, |b, x, y| fmag::<B, W64>(b, x, y, false)),
        // FABS/FNEG/FMOV は符号ビット操作・コピー。Ref: §3.2.1.5/§3.4.1.
        Insn::FabsS => funa32(b, &ops, |b, x| fabs_v::<B, W32>(b, x)),
        Insn::FabsD => funa64(b, &ops, |b, x| fabs_v::<B, W64>(b, x)),
        Insn::FnegS => funa32(b, &ops, |b, x| fneg_v::<B, W32>(b, x)),
        Insn::FnegD => funa64(b, &ops, |b, x| fneg_v::<B, W64>(b, x)),
        Insn::FmovS => funa32(b, &ops, |_b, x| x),
        Insn::FmovD => funa64(b, &ops, |_b, x| x),
        // FSQRT・FRECIP/FRSQRT・近似系。近似命令（FRECIPE/
        // FRSQRTE）は正確演算で代替（Gap: GAP-0063）。
        // Ref: §3.2.1.9-§3.2.1.10.
        Insn::FsqrtS | Insn::FrsqrtS | Insn::FrsqrteS => {
            with_la_rm(b, |b, rm| {
                let a = fget32(b, ops[1]);
                let s = b.fsqrt_r::<W32>(a, rm);
                let r = if insn == Insn::FsqrtS {
                    s
                } else {
                    let one = b.konst::<W32>(0x3f80_0000);
                    b.fdiv::<W32>(one, s)
                };
                fset32(b, ops[0], r);
                fpo_end(b);
                Ok(())
            })?;
        }
        Insn::FsqrtD | Insn::FrsqrtD | Insn::FrsqrteD => {
            with_la_rm(b, |b, rm| {
                let a = fget(b, ops[1]);
                let s = b.fsqrt_r::<W64>(a, rm);
                let r = if insn == Insn::FsqrtD {
                    s
                } else {
                    let one = b.konst::<W64>(0x3ff0_0000_0000_0000);
                    b.fdiv::<W64>(one, s)
                };
                fset(b, ops[0], r);
                fpo_end(b);
                Ok(())
            })?;
        }
        Insn::FrecipS | Insn::FrecipeS => {
            with_la_rm(b, |b, rm| {
                let a = fget32(b, ops[1]);
                let one = b.konst::<W32>(0x3f80_0000);
                let r = b.fdiv_r::<W32>(one, a, rm);
                fset32(b, ops[0], r);
                fpo_end(b);
                Ok(())
            })?;
        }
        Insn::FrecipD | Insn::FrecipeD => {
            with_la_rm(b, |b, rm| {
                let a = fget(b, ops[1]);
                let one = b.konst::<W64>(0x3ff0_0000_0000_0000);
                let r = b.fdiv_r::<W64>(one, a, rm);
                fset(b, ops[0], r);
                fpo_end(b);
                Ok(())
            })?;
        }
        // FSCALEB/FLOGB/FCOPYSIGN。Ref: §3.2.1.7.
        Insn::FscalebS => fbin32(b, &ops, |b, x, y| fscaleb_v::<B, W32>(b, x, y)),
        Insn::FscalebD => fbin64(b, &ops, |b, x, y| fscaleb_v::<B, W64>(b, x, y)),
        Insn::FlogbS => funa32(b, &ops, |b, x| flogb_v::<B, W32>(b, x)),
        Insn::FlogbD => funa64(b, &ops, |b, x| flogb_v::<B, W64>(b, x)),
        Insn::FcopysignS => fbin32(b, &ops, |b, x, y| b.fsgnj::<W32>(x, y)),
        Insn::FcopysignD => fbin64(b, &ops, |b, x, y| b.fsgnj::<W64>(x, y)),
        // FCLASS。Ref: §3.2.1.8.
        Insn::FclassS => {
            let a = fget32(b, ops[1]);
            let v = fclass_la::<B, W32>(b, a);
            fset32(b, ops[0], v);
        }
        Insn::FclassD => {
            let a = fget(b, ops[1]);
            let v = fclass_la::<B, W64>(b, a);
            let v64 = b.zext::<W32, W64>(v);
            fset(b, ops[0], v64);
        }
        // FCMP.cond。ops = [cc, fj, fk, cond]。Ref: §3.2.2.1.
        Insn::FcmpCondS => {
            let a = fget32(b, ops[1]);
            let c = fget32(b, ops[2]);
            let r = fcmp_res::<B, W32>(b, a, c, ops[3]);
            fcc_set(b, ops[0], r);
            fpo_end(b);
        }
        Insn::FcmpCondD => {
            let a = fget(b, ops[1]);
            let c = fget(b, ops[2]);
            let r = fcmp_res::<B, W64>(b, a, c, ops[3]);
            fcc_set(b, ops[0], r);
            fpo_end(b);
        }
        // FCVT。Ref: §3.2.3.1.
        // FCVT.S.D は f64→f32（丸めは FCSR.RM）、FCVT.D.S は f32→f64（正確）。
        Insn::FcvtSD => {
            with_la_rm(b, |b, rm| {
                let a = fget(b, ops[1]);
                let v = b.fcvt_ff::<W64, W32>(a, rm);
                fset32(b, ops[0], v);
                fpo_end(b);
                Ok(())
            })?;
        }
        Insn::FcvtDS => {
            let a = fget32(b, ops[1]);
            let v = b.fcvt_ff::<W32, W64>(a, RM_RNE);
            fset(b, ops[0], v);
            fpo_end(b);
        }
        // FTINT（動的 rm は FCSR.RM）。Ref: §3.2.3.2.
        Insn::FtintWS => with_la_rm(b, |b, rm| ftint::<B, W32>(b, &ops, false, rm))?,
        Insn::FtintLS => with_la_rm(b, |b, rm| ftint::<B, W32>(b, &ops, true, rm))?,
        Insn::FtintWD => with_la_rm(b, |b, rm| ftint::<B, W64>(b, &ops, false, rm))?,
        Insn::FtintLD => with_la_rm(b, |b, rm| ftint::<B, W64>(b, &ops, true, rm))?,
        // FTINTR*（固定 rm。LA の RM/RP/RZ/RNE は backend の
        // Rdn/Rup/Rtz/Rne）。Ref: §3.2.3.3.
        Insn::FtintrmWS => ftint::<B, W32>(b, &ops, false, RM_RDN)?,
        Insn::FtintrmLS => ftint::<B, W32>(b, &ops, true, RM_RDN)?,
        Insn::FtintrmWD => ftint::<B, W64>(b, &ops, false, RM_RDN)?,
        Insn::FtintrmLD => ftint::<B, W64>(b, &ops, true, RM_RDN)?,
        Insn::FtintrpWS => ftint::<B, W32>(b, &ops, false, RM_RUP)?,
        Insn::FtintrpLS => ftint::<B, W32>(b, &ops, true, RM_RUP)?,
        Insn::FtintrpWD => ftint::<B, W64>(b, &ops, false, RM_RUP)?,
        Insn::FtintrpLD => ftint::<B, W64>(b, &ops, true, RM_RUP)?,
        Insn::FtintrzWS => ftint::<B, W32>(b, &ops, false, RM_RTZ)?,
        Insn::FtintrzLS => ftint::<B, W32>(b, &ops, true, RM_RTZ)?,
        Insn::FtintrzWD => ftint::<B, W64>(b, &ops, false, RM_RTZ)?,
        Insn::FtintrzLD => ftint::<B, W64>(b, &ops, true, RM_RTZ)?,
        Insn::FtintrneWS => ftint::<B, W32>(b, &ops, false, RM_RNE)?,
        Insn::FtintrneLS => ftint::<B, W32>(b, &ops, true, RM_RNE)?,
        Insn::FtintrneWD => ftint::<B, W64>(b, &ops, false, RM_RNE)?,
        Insn::FtintrneLD => ftint::<B, W64>(b, &ops, true, RM_RNE)?,
        // FFINT（動的 rm）。Ref: §3.2.3.2.
        Insn::FfintSW => with_la_rm(b, |b, rm| ffint::<B, W32>(b, &ops, false, rm))?,
        Insn::FfintSL => with_la_rm(b, |b, rm| ffint::<B, W32>(b, &ops, true, rm))?,
        Insn::FfintDW => with_la_rm(b, |b, rm| ffint::<B, W64>(b, &ops, false, rm))?,
        Insn::FfintDL => with_la_rm(b, |b, rm| ffint::<B, W64>(b, &ops, true, rm))?,
        // FRINT（動的 rm）。Ref: §3.2.3.4.
        Insn::FrintS => {
            with_la_rm(b, |b, rm| {
                let a = fget32(b, ops[1]);
                let v = frint_v::<B, W32>(b, a, rm);
                fset32(b, ops[0], v);
                fpo_end(b);
                Ok(())
            })?;
        }
        Insn::FrintD => {
            with_la_rm(b, |b, rm| {
                let a = fget(b, ops[1]);
                let v = frint_v::<B, W64>(b, a, rm);
                fset(b, ops[0], v);
                fpo_end(b);
                Ok(())
            })?;
        }
        // FSEL。ops = [fd, fj, fk, ca]。ca=0 → fj、1 → fk。
        // Ref: §3.2.4.2.
        Insn::Fsel => {
            let bit = fcc_bit(b, ops[3]);
            let zero = k(b, 0);
            let c = b.cmp::<W64>(Cmp::Ne, bit, zero);
            let a = fget(b, ops[1]);
            let v = fget(b, ops[2]);
            let r = b.select::<W64>(c, v, a);
            fset(b, ops[0], r);
        }
        // ---- FP・整数・FCC 間転送 ----
        // Ref: §3.2.4.3-§3.2.4.7.
        Insn::Movgr2frW => {
            let v = rget(b, ops[1]);
            let v = b.trunc::<W64, W32>(v);
            fset32(b, ops[0], v);
        }
        Insn::Movgr2frhW => {
            // fd[63:32] ← GR[rj][31:0]、fd[31:0] 不変。
            let old = fget(b, ops[0]);
            let lo_mask = k(b, 0xffff_ffff);
            let lo = b.and::<W64>(old, lo_mask);
            let g = rget(b, ops[1]);
            let g32 = b.and::<W64>(g, lo_mask);
            let sh = k(b, 32);
            let hi = b.shl::<W64>(g32, sh);
            let v = b.or::<W64>(hi, lo);
            fset(b, ops[0], v);
        }
        Insn::Movgr2frD => {
            let v = rget(b, ops[1]);
            fset(b, ops[0], v);
        }
        Insn::Movfr2grS => {
            let v = fget32(b, ops[1]);
            let v = b.sext::<W32, W64>(v);
            rset(b, ops[0], v);
        }
        Insn::Movfrh2grS => {
            let v = fget(b, ops[1]);
            let sh = k(b, 32);
            let hi = b.shr_l::<W64>(v, sh);
            let hi32 = b.trunc::<W64, W32>(hi);
            let v = b.sext::<W32, W64>(hi32);
            rset(b, ops[0], v);
        }
        Insn::Movfr2grD => {
            let v = fget(b, ops[1]);
            rset(b, ops[0], v);
        }
        Insn::Movgr2fcsr => {
            // ops = [fcsrd, rj]。fcsr1-3 は FCSR0 のエイリアスとして
            // 対応フィールドへ写す（fcsr[1..3] の実配列は使わない）。
            // Ref: SPEC-LOONGARCH-RM §3.1.4, §3.2.4.5.
            let g = rget(b, ops[1]);
            let g32 = b.trunc::<W64, W32>(g);
            let i0 = b.konst::<W32>(0);
            let old = b.get_indexed(fcsr_array(), i0);
            let nv = match ops[0] {
                0 => g32,
                1 => {
                    let keep = b.konst::<W32>(!0x1f);
                    let w = b.konst::<W32>(0x1f);
                    let a = b.and::<W32>(old, keep);
                    let p = b.and::<W32>(g32, w);
                    b.or::<W32>(a, p)
                }
                2 => {
                    let keep = b.konst::<W32>(!0x1fff_0000);
                    let w = b.konst::<W32>(0x1fff_0000);
                    let a = b.and::<W32>(old, keep);
                    let p = b.and::<W32>(g32, w);
                    b.or::<W32>(a, p)
                }
                3 => {
                    let keep = b.konst::<W32>(!0x300);
                    let w = b.konst::<W32>(0x300);
                    let a = b.and::<W32>(old, keep);
                    let p = b.and::<W32>(g32, w);
                    b.or::<W32>(a, p)
                }
                _ => old,
            };
            if ops[0] <= 3 {
                b.set_indexed(fcsr_array(), i0, nv);
            }
        }
        Insn::Movfcsr2gr => {
            // ops = [rd, fcsrj]。fcsr1-3 の読みは FCSR0 の対応
            // フィールドを返す。
            let i0 = b.konst::<W32>(0);
            let f = b.get_indexed(fcsr_array(), i0);
            let v = match ops[1] {
                0 => f,
                1 => {
                    let m = b.konst::<W32>(0x1f);
                    b.and::<W32>(f, m)
                }
                2 => {
                    let m = b.konst::<W32>(0x1fff_0000);
                    b.and::<W32>(f, m)
                }
                3 => {
                    let m = b.konst::<W32>(0x300);
                    b.and::<W32>(f, m)
                }
                _ => b.konst::<W32>(0),
            };
            let v = b.sext::<W32, W64>(v);
            rset(b, ops[0], v);
        }
        Insn::Movfr2cf => {
            // ops = [cd, fj]。FCC[cd] ← FR[fj][0]。
            let v = fget(b, ops[1]);
            let one = k(b, 1);
            let bit = b.and::<W64>(v, one);
            fcc_set(b, ops[0], bit);
        }
        Insn::Movcf2fr => {
            // ops = [fd, cj]。FR[fd][0] ← FCC[cj]（他ビット不変）。
            let bit = fcc_bit(b, ops[1]);
            let old = fget(b, ops[0]);
            let m = k(b, !1u64);
            let keep = b.and::<W64>(old, m);
            let v = b.or::<W64>(keep, bit);
            fset(b, ops[0], v);
        }
        Insn::Movgr2cf => {
            // ops = [cd, rj]。FCC[cd] ← GR[rj][0]。
            let v = rget(b, ops[1]);
            let one = k(b, 1);
            let bit = b.and::<W64>(v, one);
            fcc_set(b, ops[0], bit);
        }
        Insn::Movcf2gr => {
            // ops = [rd, cj]。GR[rd] ← FCC[cj]（0/1）。
            let bit = fcc_bit(b, ops[1]);
            rset(b, ops[0], bit);
        }
        // ---- FP load/store ----
        // Ref: SPEC-LOONGARCH-RM §3.2.6.
        Insn::FldS => {
            let ea = ldst_ea(b, &ops);
            let v = b.load::<W32>(ea, DATA)?;
            fset32(b, ops[0], v);
        }
        Insn::FldD => {
            let ea = ldst_ea(b, &ops);
            let v = b.load::<W64>(ea, DATA)?;
            fset(b, ops[0], v);
        }
        Insn::FstS => {
            let ea = ldst_ea(b, &ops);
            let v = fget32(b, ops[0]);
            b.store::<W32>(ea, v, STORE)?;
        }
        Insn::FstD => {
            let ea = ldst_ea(b, &ops);
            let v = fget(b, ops[0]);
            b.store::<W64>(ea, v, STORE)?;
        }
        Insn::FldxS => {
            let ea = ldx_ea(b, &ops);
            let v = b.load::<W32>(ea, DATA)?;
            fset32(b, ops[0], v);
        }
        Insn::FldxD => {
            let ea = ldx_ea(b, &ops);
            let v = b.load::<W64>(ea, DATA)?;
            fset(b, ops[0], v);
        }
        Insn::FstxS => {
            let ea = ldx_ea(b, &ops);
            let v = fget32(b, ops[0]);
            b.store::<W32>(ea, v, STORE)?;
        }
        Insn::FstxD => {
            let ea = ldx_ea(b, &ops);
            let v = fget(b, ops[0]);
            b.store::<W64>(ea, v, STORE)?;
        }
        Insn::FldgtS | Insn::FldgtD => {
            bound_check(b, &ops, true)?;
            let ea = rget(b, ops[1]);
            if insn == Insn::FldgtS {
                let v = b.load::<W32>(ea, DATA)?;
                fset32(b, ops[0], v);
            } else {
                let v = b.load::<W64>(ea, DATA)?;
                fset(b, ops[0], v);
            }
        }
        Insn::FldleS | Insn::FldleD => {
            bound_check(b, &ops, false)?;
            let ea = rget(b, ops[1]);
            if insn == Insn::FldleS {
                let v = b.load::<W32>(ea, DATA)?;
                fset32(b, ops[0], v);
            } else {
                let v = b.load::<W64>(ea, DATA)?;
                fset(b, ops[0], v);
            }
        }
        Insn::FstgtS | Insn::FstgtD => {
            bound_check(b, &ops, true)?;
            let ea = rget(b, ops[1]);
            if insn == Insn::FstgtS {
                let v = fget32(b, ops[0]);
                b.store::<W32>(ea, v, STORE)?;
            } else {
                let v = fget(b, ops[0]);
                b.store::<W64>(ea, v, STORE)?;
            }
        }
        Insn::FstleS | Insn::FstleD => {
            bound_check(b, &ops, false)?;
            let ea = rget(b, ops[1]);
            if insn == Insn::FstleS {
                let v = fget32(b, ops[0]);
                b.store::<W32>(ea, v, STORE)?;
            } else {
                let v = fget(b, ops[0]);
                b.store::<W64>(ea, v, STORE)?;
            }
        }
        // ---- LSX の部分集合（LA13）----
        // Ref: SPEC-LOONGARCH-RM Vol.2.
        // Gap: GAP-0063（VLD/VST の 16 バイト整列規則は
        // 検査しない非整列アクセス近似）。
        Insn::Vld => {
            let ea = ldst_ea(b, &ops);
            let v = b.load::<W128>(ea, DATA)?;
            vset(b, ops[0], v);
        }
        Insn::Vst => {
            let ea = ldst_ea(b, &ops);
            let v = vget(b, ops[0]);
            b.store::<W128>(ea, v, STORE)?;
        }
        Insn::Vldx => {
            let ea = ldx_ea(b, &ops);
            let v = b.load::<W128>(ea, DATA)?;
            vset(b, ops[0], v);
        }
        Insn::Vstx => {
            let ea = ldx_ea(b, &ops);
            let v = vget(b, ops[0]);
            b.store::<W128>(ea, v, STORE)?;
        }
        Insn::VldreplD => {
            // ea = rj + imm8*8（.d のオフセットは要素単位）。
            let base = rget(b, ops[1]);
            let d = k(b, ops[2] << 3);
            let ea = b.add(base, d);
            let e = b.load::<W64>(ea, DATA)?;
            let v = vsplat(b, e, 64);
            vset(b, ops[0], v);
        }
        Insn::Vreplgr2vrW | Insn::Vreplgr2vrD => {
            let ebits = if insn == Insn::Vreplgr2vrW { 32 } else { 64 };
            let e = rget(b, ops[1]);
            let v = vsplat(b, e, ebits);
            vset(b, ops[0], v);
        }
        Insn::Vpickve2grW => {
            // .w は符号拡張して GR へ。Ref: RM Vol.2 VPICKVE2GR.
            let v = vget(b, ops[1]);
            let e = vlane(b, v, 32, ops[2] as u32 & 3);
            let t = b.trunc::<W64, W32>(e);
            let e = b.sext::<W32, W64>(t);
            rset(b, ops[0], e);
        }
        Insn::Vpickve2grDu => {
            let v = vget(b, ops[1]);
            let e = vlane(b, v, 64, ops[2] as u32 & 1);
            rset(b, ops[0], e);
        }
        Insn::Vinsgr2vrW => {
            // vd の要素 idx だけを rj[31:0] で置き換える。
            let idx = ops[2] as u32 & 3;
            let lane: u128 = 0xffff_ffffu128 << (idx * 32);
            let cur = vget(b, ops[0]);
            let nm = k128(b, !lane);
            let keep = b.and(cur, nm);
            let g = rget(b, ops[1]);
            let e = vlane_set(b, keep, 32, idx, g);
            vset(b, ops[0], e);
        }
        Insn::VpcntW => {
            let vj = vget(b, ops[1]);
            let mut v = k128(b, 0);
            for i in 0..4 {
                let a = vlane(b, vj, 32, i);
                let e = popcnt32(b, a);
                v = vlane_set(b, v, 32, i, e);
            }
            vset(b, ops[0], v);
        }
        Insn::VsetnezV => {
            // FCC.cd = (vj != 0)。Ref: RM Vol.2 VSETNEZ.
            let v = vget(b, ops[1]);
            let z = k128(b, 0);
            let ne = b.cmp::<W128>(Cmp::Ne, v, z);
            let one = k(b, 1);
            let zero = k(b, 0);
            let bit = b.select::<W64>(ne, one, zero);
            fcc_set(b, ops[0], bit);
        }
        Insn::VsrliW => {
            let vj = vget(b, ops[1]);
            let n = ops[2] & 31;
            let mut v = k128(b, 0);
            for i in 0..4 {
                let a = vlane(b, vj, 32, i);
                let sh = k(b, n);
                let e = b.shr_l::<W64>(a, sh);
                v = vlane_set(b, v, 32, i, e);
            }
            vset(b, ops[0], v);
        }
        Insn::VslliW => {
            let vj = vget(b, ops[1]);
            let n = ops[2] & 31;
            let mut v = k128(b, 0);
            for i in 0..4 {
                let a = vlane(b, vj, 32, i);
                let sh = k(b, n);
                let e = b.shl::<W64>(a, sh);
                v = vlane_set(b, v, 32, i, e);
            }
            vset(b, ops[0], v);
        }
        Insn::VshufW => {
            // vd.w[i] = vj.w[vk.w[i] mod 4]。Ref: RM Vol.2 VSHUF.
            let vj = vget(b, ops[1]);
            let vk = vget(b, ops[2]);
            let mut v = k128(b, 0);
            for i in 0..4 {
                let n64 = vlane(b, vk, 32, i);
                let n = b.zext::<W64, W128>(n64);
                let m = k128(b, 3);
                let n = b.and(n, m);
                let sc = k128(b, 5);
                let off = b.shl::<W128>(n, sc);
                let shifted = b.shr_l::<W128>(vj, off);
                let e = b.trunc::<W128, W64>(shifted);
                let m64 = k(b, 0xffff_ffff);
                let e = b.and(e, m64);
                v = vlane_set(b, v, 32, i, e);
            }
            vset(b, ops[0], v);
        }
        Insn::VshufB => {
            // vd.b[i] = concat(vj,vk).b[va.b[i] & 31]。
            // 即値が 16 未満なら vj、以上なら vk の下位 16 バイト。
            let vj = vget(b, ops[1]);
            let vk = vget(b, ops[2]);
            let va = vget(b, ops[3]);
            let mut v = k128(b, 0);
            for i in 0..16 {
                let n64 = vlane(b, va, 8, i);
                let n = b.zext::<W64, W128>(n64);
                let m = k128(b, 31);
                let n = b.and(n, m);
                let lim = k128(b, 16);
                let lt = b.cmp::<W128>(Cmp::LtU, n, lim);
                let src = b.select::<W128>(lt, vj, vk);
                let m15 = k128(b, 15);
                let nn = b.and(n, m15);
                let sc = k128(b, 3);
                let off = b.shl::<W128>(nn, sc);
                let shifted = b.shr_l::<W128>(src, off);
                let e = b.trunc::<W128, W64>(shifted);
                let m8 = k(b, 0xff);
                let e = b.and(e, m8);
                v = vlane_set(b, v, 8, i, e);
            }
            vset(b, ops[0], v);
        }
        Insn::Vshuf4iB => {
            // 4 バイトの束ごとに imm8 の 2 ビット対で選ぶ。
            // byte i の選択子は imm8[2*(i mod 4)+1 : 2*(i mod 4)]。
            let vj = vget(b, ops[1]);
            let imm = ops[2];
            let mut v = k128(b, 0);
            for i in 0..16u32 {
                let sel = ((imm >> (2 * (i & 3))) & 3) as u32;
                let src = 4 * (i >> 2) + sel;
                let e = vlane(b, vj, 8, src);
                v = vlane_set(b, v, 8, i, e);
            }
            vset(b, ops[0], v);
        }
        Insn::VilvlB | Insn::VilvlH => {
            // 下位半分の要素を交互配置。vd[2i]=vj[i]、vd[2i+1]=vk[i]。
            let ebits = if insn == Insn::VilvlB { 8 } else { 16 };
            let vj = vget(b, ops[1]);
            let vk = vget(b, ops[2]);
            let half = 64 / ebits;
            let mut v = k128(b, 0);
            for i in 0..half {
                let a = vlane(b, vj, ebits, i);
                v = vlane_set(b, v, ebits, 2 * i, a);
                let c = vlane(b, vk, ebits, i);
                v = vlane_set(b, v, ebits, 2 * i + 1, c);
            }
            vset(b, ops[0], v);
        }
        Insn::VexthWuHu | Insn::VexthHuBu => {
            // 上位半分の要素をゼロ拡張して倍幅へ。
            // hu.bu: byte→half、wu.hu: half→word。
            let (se, de, cnt) = if insn == Insn::VexthHuBu {
                (8u32, 16u32, 8u32)
            } else {
                (16u32, 32u32, 4u32)
            };
            let vj = vget(b, ops[1]);
            let mut v = k128(b, 0);
            for i in 0..cnt {
                let a = vlane(b, vj, se, i + cnt);
                v = vlane_set(b, v, de, i, a);
            }
            vset(b, ops[0], v);
        }
        Insn::VbitreviD => {
            // vd.d[i] = rol(bitrev(vj.d[i]), ui6)。
            // Ref: RM Vol.2 VBITREVI.
            let vj = vget(b, ops[1]);
            let n = ops[2] & 63;
            let mut v = k128(b, 0);
            for i in 0..2 {
                let a = vlane(b, vj, 64, i);
                let r = bitrev(b, a, 64);
                let e = if n == 0 {
                    r
                } else {
                    let shl = k(b, n);
                    let shr = k(b, 64 - n);
                    let lo = b.shl::<W64>(r, shl);
                    let hi = b.shr_l::<W64>(r, shr);
                    b.or(lo, hi)
                };
                v = vlane_set(b, v, 64, i, e);
            }
            vset(b, ops[0], v);
        }
        Insn::VsubiDu => {
            let vj = vget(b, ops[1]);
            let c = k(b, ops[2] & 31);
            let mut v = k128(b, 0);
            for i in 0..2 {
                let a = vlane(b, vj, 64, i);
                let e = b.sub(a, c);
                v = vlane_set(b, v, 64, i, e);
            }
            vset(b, ops[0], v);
        }
        Insn::Vldi => {
            // si13[12:8] が展開 mode、si13[7:0] が即値。
            let imm = ops[1];
            let mode = (imm >> 8) & 0x1f;
            let Some(vv) = vldi_value(mode, imm) else {
                // Gap: GAP-0063（未対応 mode は誤値を置かず
                // ILL に畳む）。
                return Err(raise::<B>(b, ExceptionKind::Trap, TRAP_ILL));
            };
            let v = k128(b, vv);
            vset(b, ops[0], v);
        }
        Insn::VseqW => {
            vbin(b, &ops, 32, |b, a, c| {
                let eq = b.cmp::<W64>(Cmp::Eq, a, c);
                let all = k(b, 0xffff_ffff);
                let z = k(b, 0);
                b.select::<W64>(eq, all, z)
            });
        }
        Insn::VaddD => vbin(b, &ops, 64, |b, a, c| b.add(a, c)),
        Insn::VsubD => vbin(b, &ops, 64, |b, a, c| b.sub(a, c)),
        Insn::VxorV | Insn::VorV | Insn::VandV | Insn::VnorV => {
            let vj = vget(b, ops[1]);
            let vk = vget(b, ops[2]);
            let v = match insn {
                Insn::VxorV => b.xor::<W128>(vj, vk),
                Insn::VorV => b.or::<W128>(vj, vk),
                Insn::VandV => b.and::<W128>(vj, vk),
                _ => {
                    let t = b.or::<W128>(vj, vk);
                    b.not(t)
                }
            };
            vset(b, ops[0], v);
        }
    }
    Ok(true)
}
