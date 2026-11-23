// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! VAX の命令意味論。オペランド指定子の評価（実効アドレス・
//! 自動増減の副作用・値の読み書き）と、最小限の命令本体。
//!
//! 指定子は `specifier` のデコード結果（`Spec`/`Opnd`）を、命令内の
//! 位置情報つきで評価する。評価はオペランド順に逐一起こし、自動
//! 減の先引き・自動増の後付け・間接の読み出しは評価時点の副作用
//! とする。PC 相対の基底と即値の「オペランドアドレス」は命令内の
//! 絶対位置で決まるので、評価には各指定子の先頭・終端の絶対
//! アドレス（`pos`）を渡す。自動増減と index 乗数の刻みは
//! オペランドのデータ型のバイト数（`.a` 系も含め指定子の型文字が
//! 決める）で、index の指数はレジスタ値の乗算として足す。
//!
//! 中断可能命令（文字列・十進。本体は VX7 以降）は
//! 「反復 1 回 = 1 ステップ」の規約で走る: 未完なら建築レジスタ
//! （r0-r5 等。命令ごとの退避先は正本の規則）に進行を残し、
//! `partial_save` が PSL<FPD>=1 と `partial` に作業語を記録して
//! PC を命令先頭へ戻す。再入した同じ命令は `partial_resume` で
//! 作業語を受け取って続きから進め、完了で `partial_done` が
//! 標識を消す。部分実行のない命令の開始時にも `partial_done` を
//! 掃く（FPD=1 でない命令への FPD 再入は建築上 UNPREDICTABLE —
//! 新しい命令として走る決定的な選択）。
//! Ref: SPEC-VAX-ARM.

use polyisa_engine::interp::{InterpBackend, InterpExit};
use polyisa_mem::{Access, AccessKind, Align, Endian};
use polyisa_sem::{Backend as _, ExceptionKind, GuestException, StateRef, W8, W16, W32, W64, W128};

use crate::specifier::{self, Fetched, Legality, OpTy, Opnd, Spec, Width};
use crate::{CpuState, Insn, PART_INSN_NONE, PartialInsn, psl, reg};

/// VAX の例外・トラップを OS パーソナリティへ渡すときのコード。
/// SCB（システム制御ブロック）のベクタオフセットをそのまま使う。
// Ref: SPEC-VAX-ARM（SCB の章）.
pub mod scb {
    /// 予約命令・特権命令 fault。
    pub const PRIV_INSN: u32 = 0x10;
    /// 予約オペランド fault。
    pub const RESERVED_OPERAND: u32 = 0x18;
    /// 予約アドレッシングモード fault。
    pub const RESERVED_MODE: u32 = 0x1c;
    /// アクセス制御違反 fault。
    pub const ACV: u32 = 0x20;
    /// 変換不能 fault。
    pub const TNV: u32 = 0x24;
    /// ブレークポイント trap。
    pub const BPT: u32 = 0x2c;
    /// 算術 trap。
    pub const ARITHMETIC: u32 = 0x34;
    /// change mode to kernel trap。
    pub const CHMK: u32 = 0x40;
    /// change mode to executive trap。
    pub const CHME: u32 = 0x44;
    /// change mode to supervisor trap。
    pub const CHMS: u32 = 0x48;
    /// change mode to user trap。
    pub const CHMU: u32 = 0x4c;
    /// サブセット命令の補完要求: 開始（FPD=0）。
    pub const EMUL_START: u32 = 0xc8;
    /// サブセット命令の補完要求: 継続（FPD=1）。
    pub const EMUL_CONT: u32 = 0xcc;
    /// 算術 trap の型パラメータ。実機はこの値をカーネルスタック
    /// へ積んでから SCB 0x34 へ分岐する。`handle_trap` に渡る
    /// コードは `arith` で SCB ベクタに畳んだ形を使う。
    // Ref: SPEC-VAX-ARM（算術例外の章）.
    pub mod at {
        /// 整数オーバーフロー。
        pub const INT_OVERFLOW: u32 = 1;
        /// 整数ゼロ除算。
        pub const INT_DIV_ZERO: u32 = 2;
        /// 浮動オーバーフロー。
        pub const FLT_OVERFLOW: u32 = 3;
        /// 浮動・十進のゼロ除算。
        pub const FLT_DIV_ZERO: u32 = 4;
        /// 浮動アンダーフロー。
        pub const FLT_UNDERFLOW: u32 = 5;
        /// 十進オーバーフロー。
        pub const DEC_OVERFLOW: u32 = 6;
        /// 添字の範囲違反。
        pub const SUBSCRIPT: u32 = 7;
    }
    /// 算術 trap の配送コード: `SCB ベクタ | 型パラメータ<<16`。
    /// 型は実機ではベクタとは別にスタックへ積まれるパラメータ —
    /// コードへの畳み込みはこのモデルの決定的な表現。
    #[must_use]
    pub const fn arith(ty: u32) -> u32 {
        ARITHMETIC | (ty << 16)
    }
}

/// データの読み出し・書き込みのアクセス属性。VAX は整列を要求
/// しない（オペランドは任意のバイト境界）ので Unaligned。
const DRD: Access = Access {
    endian: Endian::Le,
    align: Align::Unaligned,
    kind: AccessKind::DataRead,
};
const DWR: Access = Access {
    endian: Endian::Le,
    align: Align::Unaligned,
    kind: AccessKind::DataWrite,
};

fn get32(b: &InterpBackend, r: StateRef<W32>) -> u32 {
    let off = r.offset();
    u32::from_le_bytes(b.state[off..off + 4].try_into().expect("w32"))
}

fn set32(b: &mut InterpBackend, r: StateRef<W32>, v: u32) {
    let off = r.offset();
    b.state[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// 汎用レジスタ r_i の状態面。
#[must_use]
pub fn r_ref(i: u8) -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, r) + usize::from(i) * 4)
}

/// 汎用レジスタ r_i の値。
#[must_use]
pub fn r_get(b: &InterpBackend, i: u8) -> u32 {
    get32(b, r_ref(i))
}

/// 汎用レジスタ r_i への代入。
pub fn r_set(b: &mut InterpBackend, i: u8, v: u32) {
    set32(b, r_ref(i), v);
}

/// PSL の状態面。
#[must_use]
pub fn psl_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, psl))
}

/// PSL の値。
#[must_use]
pub fn psl_get(b: &InterpBackend) -> u32 {
    get32(b, psl_ref())
}

/// PSL への代入。
pub fn psl_put(b: &mut InterpBackend, v: u32) {
    set32(b, psl_ref(), v);
}

/// PSL の 1 ビットを読む。
#[must_use]
pub fn psl_flag(b: &InterpBackend, bit: u32) -> bool {
    psl_get(b) & (1 << bit) != 0
}

/// PSL の 1 ビットを書く。
fn psl_flag_set(b: &mut InterpBackend, bit: u32, v: bool) {
    let p = psl_get(b);
    psl_put(b, if v { p | 1 << bit } else { p & !(1 << bit) });
}

/// 現在のアクセスモード（PSL<CUR_MOD>。0=kernel, 3=user）。
#[must_use]
pub fn cur_mod(b: &InterpBackend) -> u32 {
    psl_get(b) >> psl::CUR_MOD & psl::MOD_MASK
}

/// PSL<FPD>（中断可能命令の部分実行の標識）。
#[must_use]
pub fn fpd(b: &InterpBackend) -> bool {
    psl_flag(b, psl::FPD)
}

/// 条件コード N/Z/V を書く（C は保存。mov・mcom・mova 系の規則）。
fn cc_nzv(b: &mut InterpBackend, n: bool, z: bool, v: bool) {
    psl_flag_set(b, psl::N, n);
    psl_flag_set(b, psl::Z, z);
    psl_flag_set(b, psl::V, v);
}

/// 幅 `w` の結果値 `v` で mov 系の条件コードを立てる
/// （N=符号・Z=零・V=0・C 保存）。
fn cc_mov(b: &mut InterpBackend, v: u128, w: Width) {
    let bits = w.bytes() * 8;
    cc_nzv(b, (v >> (bits - 1)) & 1 == 1, v & mask_w(w) == 0, false);
}

/// N/Z/V/C をまとめて書く（演算系。VAX は全演算で C も更新する）。
fn cc_nzvc(b: &mut InterpBackend, n: bool, z: bool, v: bool, c: bool) {
    cc_nzv(b, n, z, v);
    psl_flag_set(b, psl::C, c);
}

/// `w` 幅の値を符号つき整数として解釈する。
fn sext_w(v: u128, w: Width) -> i128 {
    let bits = w.bytes() * 8;
    (((v & mask_w(w)) << (128 - bits)) as i128) >> (128 - bits)
}

/// 符号つき整数 `v` が `w` 幅に表せるか（縮小・オーバーフロー検査）。
fn fits_s(v: i128, w: Width) -> bool {
    let bits = w.bytes() * 8;
    v >= -(1i128 << (bits - 1)) && v < (1i128 << (bits - 1))
}

/// `w` 幅の演算結果 `r` と V/C で条件コードを立てる
/// （N=結果の符号・Z=零）。
fn cc_arith(b: &mut InterpBackend, r: u128, v: bool, c: bool, w: Width) {
    cc_nzvc(b, sext_w(r, w) < 0, r & mask_w(w) == 0, v, c);
}

/// 整数オーバーフロー時の算術 trap。結果の書き戻しと条件コードの
/// 更新のあとに呼ぶ: V=1 で PSL<IV>=1 なら trap（復帰先は次の
/// 命令 —— run 側で env.pc が命令終端に進む）。
// Ref: SPEC-VAX-ARM（整数オーバーフローと IV の章）.
fn iv_trap(b: &InterpBackend) -> Result<(), InterpExit> {
    if psl_flag(b, psl::V) && psl_flag(b, psl::IV) {
        return Err(trap(scb::arith(scb::at::INT_OVERFLOW)));
    }
    Ok(())
}

/// 加算 `a + s + cin` の `w` 幅結果と (V=符号付きあふれ,
/// C=最上位からの桁出し)。
fn add_op(a: u128, s: u128, cin: u128, w: Width) -> (u128, bool, bool) {
    let m = mask_w(w);
    let u = (a & m) + (s & m) + cin;
    let sr = sext_w(a, w) + sext_w(s, w) + cin as i128;
    (u & m, !fits_s(sr, w), u > m)
}

/// 減算 `a - s - bin` の `w` 幅結果と (V=符号付きあふれ,
/// C=借り = 符号なし減算が負になった)。
fn sub_op(a: u128, s: u128, bin: u128, w: Width) -> (u128, bool, bool) {
    let m = mask_w(w);
    let ua = a & m;
    let us = s & m;
    // us + bin > ua と同値（bin は 0/1。加算の桁上げを避ける）。
    let borrow = us > ua || (bin != 0 && us == ua);
    let sr = sext_w(ua, w) - sext_w(us, w) - bin as i128;
    (sr as u128 & m, !fits_s(sr, w), borrow)
}

/// `w` 幅のゼロ除算検査つき商（0 方向へ切り詰め）。除数 0 は
/// 整数ゼロ除算 trap（IV とは無関係に必ず発生する）。
fn div_op(divd: i128, divr: i128, w: Width) -> Result<(i128, bool), InterpExit> {
    if divr == 0 {
        return Err(trap(scb::arith(scb::at::INT_DIV_ZERO)));
    }
    // i128 の除算は 0 方向切り詰めで VAX の商と同じ。divd は
    // quadword までなので i128::MIN/-1 のあふれは起きない。
    let q = divd / divr;
    Ok((q, !fits_s(q, w)))
}

// ---- 中断可能命令の途中状態 ----

fn partial_insn_ref() -> StateRef<W16> {
    StateRef::<W16>::from_offset(
        core::mem::offset_of!(CpuState, partial) + core::mem::offset_of!(PartialInsn, insn),
    )
}

fn partial_work_ref(i: usize) -> StateRef<W32> {
    StateRef::<W32>::from_offset(
        core::mem::offset_of!(CpuState, partial) + core::mem::offset_of!(PartialInsn, work) + i * 4,
    )
}

/// `partial.insn` の生値（部分実行中の命令のオペコード語。
/// `PART_INSN_NONE` は部分実行なし）。
#[must_use]
pub fn partial_insn(b: &InterpBackend) -> u16 {
    let off = partial_insn_ref().offset();
    u16::from_le_bytes(b.state[off..off + 2].try_into().expect("w16"))
}

/// `partial.work[i]` の値（テスト・診断用）。
#[must_use]
pub fn partial_work(b: &InterpBackend, i: usize) -> u32 {
    get32(b, partial_work_ref(i))
}

/// 部分実行の標識を消す。命令の完結時と、部分実行を持たない
/// 命令の開始時に呼ぶ。
pub fn partial_done(b: &mut InterpBackend) {
    psl_flag_set(b, psl::FPD, false);
    b.set(partial_insn_ref(), PART_INSN_NONE);
    for i in 0..4 {
        b.set(partial_work_ref(i), 0u32);
    }
}

/// 反復 1 回ぶんの進行を残して命令を中断する。PSL<FPD>=1、
/// `partial` にオペコード語と作業語を記録し、PC を命令先頭
/// `pc0` に戻す（次のステップが同じ命令へ再入する）。建築上の
/// 退避先（r0-r5 等）への進行の格納は各命令の意味論が行う。
// Ref: SPEC-VAX-ARM（例外と中断可能命令の章）.
pub fn partial_save(b: &mut InterpBackend, opc: u16, work: [u32; 4], pc0: u32) {
    psl_flag_set(b, psl::FPD, true);
    b.set(partial_insn_ref(), opc);
    for (i, &v) in work.iter().enumerate() {
        b.set(partial_work_ref(i), v);
    }
    r_set(b, reg::PC as u8, pc0);
}

/// FPD=1 での再入: 部分実行が自命令（同じオペコード語）のもの
/// なら退避した作業語を返す。命令本体はこれで途中から続くかを
/// 決める。自命令でない・FPD=0 なら None（新しい開始）。
#[must_use]
pub fn partial_resume(b: &mut InterpBackend, opc: u16) -> Option<[u32; 4]> {
    if !fpd(b) || partial_insn(b) != opc {
        return None;
    }
    Some(core::array::from_fn(|i| b.get(partial_work_ref(i))))
}

// ---- オペランド指定子の評価 ----

/// 指定子評価の結果。`.r/.m` は `read` で値を読み、`.w/.m` は
/// `write` で値を書き、`.a` は `loc_addr` の値がオペランド、
/// `.v` は Reg/Mem いずれの基底も取るフィールドの足場として残す。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Loc {
    /// レジスタ内。4 バイトを超える幅は連続レジスタに跨る。
    Reg(u8),
    /// メモリ上（実効アドレス）。
    Mem(u32),
    /// 値自身（短リテラル・即値）。`addr` は指定子拡張の位置 —
    /// .a/.v での評価と、.w/.m への書き込み先（建築上
    /// UNPREDICTABLE の決定的な選択）に使う。
    Val { v: u128, addr: u32 },
}

/// bis/bic/xor の結合子（値と mask → 結果）。
fn bit_op(insn: Insn, v: u128, m: u128) -> u128 {
    match insn {
        Insn::Bisb2 | Insn::Bisb3 | Insn::Bisw2 | Insn::Bisw3 | Insn::Bisl2 | Insn::Bisl3 => v | m,
        Insn::Bicb2 | Insn::Bicb3 | Insn::Bicw2 | Insn::Bicw3 | Insn::Bicl2 | Insn::Bicl3 => v & !m,
        _ => v ^ m,
    }
}

/// データ幅のビットマスク。
fn mask_w(w: Width) -> u128 {
    let n = w.bytes();
    if n >= 16 {
        u128::MAX
    } else {
        (1u128 << (n * 8)) - 1
    }
}

/// レジスタファイルの `w` 幅の読み出し。4 バイトを超える幅は
/// 連続レジスタを連結する。r15 を越える分は r0 へ折り返す
/// （建築上 UNPREDICTABLE の決定的な選択）。
fn reg_read(b: &InterpBackend, r: u8, w: Width) -> u128 {
    let mut v = 0u128;
    for i in 0..w.bytes().max(4) / 4 {
        v |= u128::from(r_get(b, r.wrapping_add(i as u8) & 0xf)) << (32 * i);
    }
    v & mask_w(w)
}

/// レジスタファイルへの `w` 幅の書き込み。部分幅は指定のバイト
/// だけを変えて残りを保存する。
fn reg_write(b: &mut InterpBackend, r: u8, w: Width, v: u128) {
    match w.bytes() {
        1 => r_set(b, r, (r_get(b, r) & !0xff) | u32::from(v as u8)),
        2 => r_set(b, r, (r_get(b, r) & !0xffff) | u32::from(v as u16)),
        n => {
            for i in 0..n / 4 {
                r_set(b, r.wrapping_add(i as u8) & 0xf, (v >> (32 * i)) as u32);
            }
        }
    }
}

/// メモリから `n` バイトを読む（1/2/4/8/16）。
fn load(b: &mut InterpBackend, addr: u32, n: u32) -> Result<u128, InterpExit> {
    let a = u64::from(addr);
    Ok(match n {
        1 => u128::from(b.load::<W8>(a, DRD)?),
        2 => u128::from(b.load::<W16>(a, DRD)?),
        4 => u128::from(b.load::<W32>(a, DRD)?),
        8 => u128::from(b.load::<W64>(a, DRD)?),
        _ => b.load::<W128>(a, DRD)?,
    })
}

/// メモリへ `n` バイトを書く（1/2/4/8/16）。
fn store(b: &mut InterpBackend, addr: u32, n: u32, v: u128) -> Result<(), InterpExit> {
    let a = u64::from(addr);
    match n {
        1 => b.store::<W8>(a, v as u8, DWR),
        2 => b.store::<W16>(a, v as u16, DWR),
        4 => b.store::<W32>(a, v as u32, DWR),
        8 => b.store::<W64>(a, v as u64, DWR),
        _ => b.store::<W128>(a, v, DWR),
    }
}

/// アドレスを生産する指定子の評価（index の基底・.a 系の中身）。
/// `sz` はオペランドのデータ型のバイト数（自動増減の刻み）。
/// `start`/`end` はこの指定子の先頭・終端の絶対アドレスで、
/// PC 相対の基底は `end`。
// Ref: SPEC-VAX-ARM（アドレッシングモードの章）.
fn eval_addr(
    b: &mut InterpBackend,
    s: &Spec,
    sz: u32,
    _start: u32,
    end: u32,
) -> Result<u32, InterpExit> {
    let pc = reg::PC as u8;
    Ok(match s {
        Spec::RegDef(r) => r_get(b, *r),
        Spec::AutoDec(r) => {
            // 使う前にオペランドのデータ型ぶん引く。
            let a = r_get(b, *r).wrapping_sub(sz);
            r_set(b, *r, a);
            a
        }
        Spec::AutoInc(r) => {
            // 使ったあとにオペランドのデータ型ぶん足す。
            let a = r_get(b, *r);
            r_set(b, *r, a.wrapping_add(sz));
            a
        }
        Spec::AutoIncDef(r) => {
            // 間接は常に longword（4）進む。
            let p = r_get(b, *r);
            r_set(b, *r, p.wrapping_add(4));
            load(b, p, 4)? as u32
        }
        Spec::Abs(a) => *a,
        // PC 相対の基底は指定子拡張の直後（=この指定子の終端）。
        Spec::Disp { r, d, .. } => {
            let base = if *r == pc { end } else { r_get(b, *r) };
            base.wrapping_add(*d as u32)
        }
        Spec::DispDef { r, d, .. } => {
            let base = if *r == pc { end } else { r_get(b, *r) };
            load(b, base.wrapping_add(*d as u32), 4)? as u32
        }
        // リテラル・レジスタ・index・即値は基底を生産できない
        // （legality が先に弾くので普通は到達しない）。
        _ => return Err(fault(scb::RESERVED_MODE, None)),
    })
}

/// 指定子を評価して読み書き先を返す。自動増減の更新と間接の
/// 読み出しはここで起きる。`start`/`end` はこの指定子（index なら
/// 全体）の先頭・終端の絶対アドレス。
fn eval_spec(
    b: &mut InterpBackend,
    s: &Spec,
    w: Width,
    start: u32,
    end: u32,
) -> Result<Loc, InterpExit> {
    let sz = w.bytes();
    Ok(match s {
        Spec::Lit(v) => Loc::Val {
            v: u128::from(*v),
            addr: start,
        },
        Spec::Indexed { rx, base } => {
            // 基底指定子の終端は index 指定子全体の終端と同じ位置
            // （PC 相対の基底もそこを基準にする）。
            let a = eval_addr(b, base, sz, start + 1, end)?;
            Loc::Mem(a.wrapping_add(r_get(b, *rx).wrapping_mul(sz)))
        }
        Spec::Reg(r) => Loc::Reg(*r),
        // 即値のオペランドアドレスは拡張バイトの位置そのもの。
        Spec::Imm { v, .. } => Loc::Val {
            v: *v,
            addr: start + 1,
        },
        _ => Loc::Mem(eval_addr(b, s, sz, start, end)?),
    })
}

/// オペランド指定子をアクセス型つきで評価する。アクセスに合わ
/// ない指定子は予約アドレッシングモード fault（SCB 0x1c）。
/// UNPREDICTABLE は受理し、結果は指定子の自然な評価に従う。
// Ref: SPEC-VAX-ARM（アドレッシングモードの章）.
pub fn eval_op(
    b: &mut InterpBackend,
    op: &Opnd,
    ty: OpTy,
    start: u32,
    end: u32,
) -> Result<Loc, InterpExit> {
    let Opnd::Spec(s) = op else {
        return Err(fault(scb::RESERVED_MODE, None));
    };
    if specifier::legality(s, ty.acc) == Legality::Illegal {
        return Err(fault(scb::RESERVED_MODE, None));
    }
    eval_spec(b, s, ty.width, start, end)
}

/// オペランドの読み出し（.r/.m）。幅 `w` のバイト数だけ見る。
pub fn read(b: &mut InterpBackend, loc: &Loc, w: Width) -> Result<u128, InterpExit> {
    match *loc {
        Loc::Reg(r) => Ok(reg_read(b, r, w)),
        Loc::Mem(a) => load(b, a, w.bytes()),
        Loc::Val { v, .. } => Ok(v & mask_w(w)),
    }
}

/// オペランドへの書き込み（.w/.m）。
pub fn write(b: &mut InterpBackend, loc: &Loc, w: Width, v: u128) -> Result<(), InterpExit> {
    match *loc {
        Loc::Reg(r) => {
            reg_write(b, r, w, v);
            Ok(())
        }
        Loc::Mem(a) => store(b, a, w.bytes(), v),
        // 即値への書き込みは建築上 UNPREDICTABLE — 拡張バイトの
        // 位置へのメモリ書き込みとして決定的に振る舞う。
        Loc::Val { addr, .. } => store(b, addr, w.bytes(), v),
    }
}

/// .a/.v オペランドの実効アドレス。Reg は .a では fault
/// （legality が先に弾くので普通は到達しない）。
pub fn loc_addr(loc: &Loc) -> Result<u32, InterpExit> {
    match *loc {
        Loc::Mem(a) | Loc::Val { addr: a, .. } => Ok(a),
        Loc::Reg(_) => Err(fault(scb::RESERVED_MODE, None)),
    }
}

/// 浮動型の語順の並べ替え（自己逆）。VAX は F/D/G/H を 16 ビット
/// 語単位の「3412」順（符号・指数を含む語が最下位アドレス）で
/// 置く。decfp の正準形（`bits()`、符号は最上位ビット）との写像は
/// この指定子層が担う — 整数の mov 系は生の語順を写し、浮動
/// 演算（VX9）がオペランドの入出力にこの写像を掛ける。
// Ref: SPEC-VAX-ARM（浮動小数点形式の章）.
#[must_use]
pub fn fp_order(w: Width, v: u128) -> u128 {
    if !matches!(w, Width::F | Width::D | Width::G | Width::H) {
        return v;
    }
    let n = w.bytes() / 2;
    let mut out = 0u128;
    for i in 0..n {
        out |= ((v >> (16 * i)) & 0xffff) << (16 * (n - 1 - i));
    }
    out
}

/// VAX の fault（予約オペランド・予約モード・特権命令等 — 復帰先は
/// 命令先頭）。SCB のオフセットをコードに載せる。
#[must_use]
pub fn fault(code: u32, addr: Option<u64>) -> InterpExit {
    InterpExit::Exception(GuestException {
        kind: ExceptionKind::Undefined,
        code: u64::from(code),
        addr,
        in_delay_slot: false,
    })
}

/// VAX の trap（BPT・算術等 — 復帰先は次の命令）。
#[must_use]
pub fn trap(code: u32) -> InterpExit {
    InterpExit::Exception(GuestException {
        kind: ExceptionKind::Trap,
        code: u64::from(code),
        addr: None,
        in_delay_slot: false,
    })
}

/// `-(SP)` への積み込み（pushl/pusha 系。SP は先に 4 引かれる。
/// 条件コードは変えない）。
fn push(b: &mut InterpBackend, v: u128) -> Result<(), InterpExit> {
    let sp = r_get(b, reg::SP as u8).wrapping_sub(4);
    r_set(b, reg::SP as u8, sp);
    store(b, sp, 4, v)
}

// ---- 可変長ビットフィールド ----

/// `size` ビットのマスク（size <= 32）。
fn fmask(size: u32) -> u64 {
    (1u64 << size) - 1
}

/// FIELD(pos, size, base) の予約オペランド検査。size > 32、または
/// レジスタ基底で size != 0 かつ pos が 0-31 を越えると fault
/// （pos は符号なし比較 —— 負値は 31 超として弾かれる）。
// Ref: SPEC-VAX-ARM（可変長ビットフィールド命令の節）.
fn field_check(loc: &Loc, pos: i32, size: u32) -> Result<(), InterpExit> {
    if size > 32 || (size != 0 && matches!(loc, Loc::Reg(_)) && pos as u32 > 31) {
        return Err(fault(scb::RESERVED_OPERAND, None));
    }
    Ok(())
}

/// FIELD(pos, size, base) の読み出し（size <= 32 で検査済み。
/// size=0 は 0 を返しバイトを参照しない）。レジスタ基底は
/// {R[n+1]'Rn} の連結、メモリ基底は base + pos<31:3> のバイト列の
/// pos<2:0> ビット目から。
// Ref: SPEC-VAX-ARM（FIELD マクロの定義）.
fn field_get(b: &mut InterpBackend, loc: &Loc, pos: i32, size: u32) -> Result<u32, InterpExit> {
    if size == 0 {
        return Ok(0);
    }
    match *loc {
        Loc::Reg(r) => {
            let hi = r_get(b, r.wrapping_add(1) & 0xf);
            let pair = u64::from(r_get(b, r)) | u64::from(hi) << 32;
            Ok(((pair >> pos as u32) & fmask(size)) as u32)
        }
        _ => {
            let a = loc_addr(loc)?.wrapping_add((pos >> 3) as u32);
            let bit = (pos & 7) as u32;
            let n = 1 + (size - 1 + bit) / 8;
            let mut v = 0u64;
            for i in 0..n {
                v |= (load(b, a.wrapping_add(i), 1)? as u64) << (8 * i);
            }
            Ok(((v >> bit) & fmask(size)) as u32)
        }
    }
}

/// FIELD(pos, size, base) への `v` の下位 `size` ビットの書き込み
/// （size <= 32 で検査済み。size=0 は何もしない）。
fn field_put(
    b: &mut InterpBackend,
    loc: &Loc,
    pos: i32,
    size: u32,
    v: u32,
) -> Result<(), InterpExit> {
    if size == 0 {
        return Ok(());
    }
    match *loc {
        Loc::Reg(r) => {
            let hi = r_get(b, r.wrapping_add(1) & 0xf);
            let pair = u64::from(r_get(b, r)) | u64::from(hi) << 32;
            let m = fmask(size) << pos as u32;
            let new = pair & !m | u64::from(v) << pos as u32 & m;
            r_set(b, r, new as u32);
            r_set(b, r.wrapping_add(1) & 0xf, (new >> 32) as u32);
            Ok(())
        }
        _ => {
            let a = loc_addr(loc)?.wrapping_add((pos >> 3) as u32);
            let bit = (pos & 7) as u32;
            let n = 1 + (size - 1 + bit) / 8;
            let mut old = 0u64;
            for i in 0..n {
                old |= (load(b, a.wrapping_add(i), 1)? as u64) << (8 * i);
            }
            let m = fmask(size) << bit;
            let new = old & !m | u64::from(v) << bit & m;
            for i in 0..n {
                store(b, a.wrapping_add(i), 1, u128::from((new >> (8 * i)) as u8))?;
            }
            Ok(())
        }
    }
}

/// 分岐変位オペランド（.b）の値。
fn br_displ(f: &Fetched, i: usize) -> i32 {
    match f.ops[i] {
        Opnd::Br(d) => d,
        _ => 0,
    }
}

/// 分岐の成立（PC は命令の終端 —— 変位は命令終端基準）。
fn branch(b: &mut InterpBackend, displ: i32) {
    let pc = r_get(b, reg::PC as u8);
    r_set(b, reg::PC as u8, pc.wrapping_add(displ as u32));
}

/// オペランド `i` の評価（`insn_ops` の型と `pos` の位置を引く）。
fn eval(
    b: &mut InterpBackend,
    f: &Fetched,
    pos: &[(u32, u32)],
    i: usize,
) -> Result<Loc, InterpExit> {
    let ty = specifier::insn_ops(f.insn)[i];
    eval_op(b, &f.ops[i], ty, pos[i].0, pos[i].1)
}

/// オペランド `i` の評価+読み出し（`eval` と `read` はともに
/// `&mut` を取るので、入れ子呼び出しを避ける畳込み）。
fn eval_r(
    b: &mut InterpBackend,
    f: &Fetched,
    pos: &[(u32, u32)],
    i: usize,
    w: Width,
) -> Result<u128, InterpExit> {
    let l = eval(b, f, pos, i)?;
    read(b, &l, w)
}

/// オペランド `i` の評価+アドレス化（`.a` 系の値）。
fn eval_a(
    b: &mut InterpBackend,
    f: &Fetched,
    pos: &[(u32, u32)],
    i: usize,
) -> Result<u32, InterpExit> {
    let l = eval(b, f, pos, i)?;
    loc_addr(&l)
}

// ---- キュー（VX7）----
// 項目は {前方リンク, 後方リンク} のロングワード対。insque/remque は
// リンクを絶対アドレスとして扱い、インターロック版はヘッダを基準と
// する自己相対変位として扱う（項目そのものの並びは同じ）。
// インターロック版の「主インターロック」は単一スレッド近似で常に
// 取得成功（副インターロック = ヘッダ語の bit 0 だけをメモリ上の
// ビットとして検査・獲得・解放する）。bit 0 が立っていれば
// N=0・Z=0・V=1・C=1 の失敗終了、<2:1> が残っていれば
// 予約オペランド fault。
// Ref: SPEC-VAX-ARM（キュー命令の節）.
// Gap: GAP-0076 — 単一スレッド近似の記録。

/// キュー命令の予約オペランド検査（8 バイト整列と項目!=ヘッダ）。
fn q_check(entry: u32, hdr: u32) -> Result<(), InterpExit> {
    if entry & 7 != 0 || hdr & 7 != 0 || entry == hdr {
        return Err(fault(scb::RESERVED_OPERAND, None));
    }
    Ok(())
}

/// ヘッダの副インターロック語を読み、競合なら `Ok(None)`、予約
/// オペランドなら fault、獲得可能なら語を返す。
fn q_hdr(b: &mut InterpBackend, h: u32) -> Result<Option<u32>, InterpExit> {
    let v = load(b, h, 4)? as u32;
    if v & 6 != 0 {
        return Err(fault(scb::RESERVED_OPERAND, None));
    }
    Ok(if v & 1 != 0 { None } else { Some(v) })
}

/// インターロック獲得失敗の条件コード（N=0・Z=0・V=1・C=1）。
fn q_fail(b: &mut InterpBackend) {
    cc_nzvc(b, false, false, true, true);
}

// ---- 文字列（VX7）----
// 中断規約: 反復 1 回 = 1 ステップ。建築上の退避先は正本の制御
// ブロックに沿って r0=残り長・r1=走査アドレスの対で r0-r5 へ
// 割り当て、命令固有の作業語（fill/esc・方向・元の長さなど
// レジスタに載らないもの）は partial.work へ。完了時に正本の
// 最終 r0-r5 と条件コードを書いて partial_done。
// Ref: SPEC-VAX-ARM（文字列命令の節、中断の節）.

/// バイト比較の条件コード（第 1 項基準: N=符号付き・C=符号なし）。
fn cc_bcmp(b: &mut InterpBackend, x: u8, y: u8) {
    cc_nzvc(b, (x as i8) < (y as i8), x == y, false, x < y);
}

/// 文字列の条件コード（N=0・Z=残り零・V=0・C=0 —— locc 系）。
fn cc_strz(b: &mut InterpBackend, z: bool) {
    cc_nzvc(b, false, z, false, false);
}

/// 開始（部分実行なし）ならオペランドを評価して初期化関数を
/// 走らせ、作業語を返す。再入なら退避した作業語をそのまま返す。
fn str_enter(
    b: &mut InterpBackend,
    f: &Fetched,
    pos: &[(u32, u32)],
    opc: u16,
    init: impl FnOnce(&mut InterpBackend, &Fetched, &[(u32, u32)]) -> Result<[u32; 4], InterpExit>,
) -> Result<Option<[u32; 4]>, InterpExit> {
    if let Some(w) = partial_resume(b, opc) {
        return Ok(Some(w));
    }
    init(b, f, pos).map(Some)
}

/// 反復が未完なら作業語を残して中断、済みなら標識を消す。
fn str_leave(b: &mut InterpBackend, opc: u16, work: [u32; 4], pc0: u32, done: bool) {
    if done {
        partial_done(b);
    } else {
        partial_save(b, opc, work, pc0);
    }
}

/// movc3: len.rw, src.ab, dst.ab。src>dst（符号なし）なら前向き、
/// そうでなければ末尾から（重なりを壊さない向き —— 正本の規則）。
/// 後ろ向きは movc5 と同じくポインタを末尾に立てて戻る。
/// r0=残り・r1/r3=走査位置、work=[後ろ向き, 元の len]。終了:
/// r0=r2=r4=r5=0・r1=src+len・r3=dst+len、N=V=C=0・Z=1。
fn movc3(
    b: &mut InterpBackend,
    f: &Fetched,
    pos: &[(u32, u32)],
    pc0: u32,
) -> Result<(), InterpExit> {
    const OPC: u16 = 0x28;
    let Some(work) = str_enter(b, f, pos, OPC, |b, f, pos| {
        let len = eval_r(b, f, pos, 0, Width::W)? as u32;
        let s = eval_a(b, f, pos, 1)?;
        let d = eval_a(b, f, pos, 2)?;
        let bwd = s <= d;
        r_set(b, 0, len);
        r_set(b, 1, if bwd { s.wrapping_add(len) } else { s });
        r_set(b, 2, 0);
        r_set(b, 3, if bwd { d.wrapping_add(len) } else { d });
        r_set(b, 4, 0);
        r_set(b, 5, 0);
        Ok([u32::from(bwd), len, 0, 0])
    })?
    else {
        return Ok(());
    };
    let (mut r0, mut r1, mut r3) = (r_get(b, 0), r_get(b, 1), r_get(b, 3));
    let mut done = r0 == 0;
    if !done {
        if work[0] == 0 {
            let v = load(b, r1, 1)?;
            store(b, r3, 1, v)?;
            r1 = r1.wrapping_add(1);
            r3 = r3.wrapping_add(1);
        } else {
            r1 = r1.wrapping_sub(1);
            r3 = r3.wrapping_sub(1);
            let v = load(b, r1, 1)?;
            store(b, r3, 1, v)?;
        }
        r0 -= 1;
        done = r0 == 0;
    }
    r_set(b, 0, r0);
    r_set(b, 1, r1);
    r_set(b, 3, r3);
    if done {
        // 後ろ向きはポインタが頭に戻っている —— 正本の最終値
        // （src/dst + len）へ補正する。
        if work[0] != 0 {
            r_set(b, 1, r1.wrapping_add(work[1]));
            r_set(b, 3, r3.wrapping_add(work[1]));
        }
        cc_strz(b, true);
    }
    str_leave(b, OPC, work, pc0, done);
    Ok(())
}

/// movc5: srclen.rw, src.ab, fill.rb, dstlen.rw, dst.ab。移動後の
/// 残りは fill で埋める。方向の規則は movc3 と同じ。後ろ向きは
/// ポインタを末尾に立てて 1 つずつ戻る（正本のアルゴリズム）。
/// r0=src 残り・r1=src 走査・r2=dst 残り・r3=dst 走査、
/// work=[後ろ向き, fill, 元の srclen, 元の dstlen]。終了:
/// r0=未移動 src 数・r1=src+移動数・r2=r4=r5=0・r3=dst+dstlen、
/// N=srclen<dstlen・Z=等値・V=0・C=符号なし比較。
fn movc5(
    b: &mut InterpBackend,
    f: &Fetched,
    pos: &[(u32, u32)],
    pc0: u32,
) -> Result<(), InterpExit> {
    const OPC: u16 = 0x2c;
    let Some(work) = str_enter(b, f, pos, OPC, |b, f, pos| {
        let sl = eval_r(b, f, pos, 0, Width::W)? as u32;
        let s = eval_a(b, f, pos, 1)?;
        let fill = eval_r(b, f, pos, 2, Width::B)? as u32;
        let dl = eval_r(b, f, pos, 3, Width::W)? as u32;
        let d = eval_a(b, f, pos, 4)?;
        let bwd = s <= d;
        r_set(b, 0, sl);
        r_set(b, 1, if bwd { s.wrapping_add(sl.min(dl)) } else { s });
        r_set(b, 2, dl);
        r_set(b, 3, if bwd { d.wrapping_add(dl) } else { d });
        r_set(b, 4, 0);
        r_set(b, 5, 0);
        Ok([u32::from(bwd), fill, sl, dl])
    })?
    else {
        return Ok(());
    };
    let fill = u128::from(work[1] as u8);
    let (mut r0, mut r1, mut r2, mut r3) = (r_get(b, 0), r_get(b, 1), r_get(b, 2), r_get(b, 3));
    let done = if work[0] == 0 {
        if r0 != 0 && r2 != 0 {
            let v = load(b, r1, 1)?;
            store(b, r3, 1, v)?;
            r0 -= 1;
            r1 = r1.wrapping_add(1);
            r2 -= 1;
            r3 = r3.wrapping_add(1);
        } else if r2 != 0 {
            store(b, r3, 1, fill)?;
            r2 -= 1;
            r3 = r3.wrapping_add(1);
        }
        r2 == 0
    } else {
        if r2 > r0 {
            r2 -= 1;
            r3 = r3.wrapping_sub(1);
            store(b, r3, 1, fill)?;
        } else if r2 != 0 {
            r0 -= 1;
            r1 = r1.wrapping_sub(1);
            r2 -= 1;
            r3 = r3.wrapping_sub(1);
            let v = load(b, r1, 1)?;
            store(b, r3, 1, v)?;
        }
        r2 == 0
    };
    r_set(b, 0, r0);
    r_set(b, 1, r1);
    r_set(b, 2, r2);
    r_set(b, 3, r3);
    if done {
        // 後ろ向きはポインタが頭に戻っている —— 正本の最終値
        // （走った端の 1 つ先）へ補正する。
        if work[0] != 0 {
            r_set(b, 1, r1.wrapping_add(work[2].min(work[3])));
            r_set(b, 3, r3.wrapping_add(work[3]));
        }
        cc_nzvc(
            b,
            work[2] < work[3],
            work[2] == work[3],
            false,
            work[2] < work[3],
        );
    }
    str_leave(b, OPC, work, pc0, done);
    Ok(())
}

/// cmpc3/cmpc5: 文字列の比較。残り 0 側は（cmpc5 では）fill で
/// 拡張して比べる。r0/r2=各残り・r1/r3=各走査、work[0]=fill
/// （cmpc3 では未使用）。終了: 不一致なら r0/r2 に終端バイトを
/// 含む残り・r1/r3 にそのアドレス、一致なら全て 0/終端。CC は
/// 最後に効いたバイト比較（等しければ Z=1 のみ）。
fn cmpc(
    b: &mut InterpBackend,
    f: &Fetched,
    pos: &[(u32, u32)],
    pc0: u32,
) -> Result<(), InterpExit> {
    let c5 = f.insn == Insn::Cmpc5;
    let opc = if c5 { 0x2d } else { 0x29 };
    let Some(work) = str_enter(b, f, pos, opc, |b, f, pos| {
        // cmpc3: len,addr1,addr2 / cmpc5: fill,len1,addr1,len2,addr2。
        let (fill, i1, a1, i2, a2) = if c5 {
            (eval_r(b, f, pos, 0, Width::B)? as u32, 1, 2, 3, 4)
        } else {
            (0, 0, 1, 0, 2)
        };
        let l1 = eval_r(b, f, pos, i1, Width::W)? as u32;
        let p1 = eval_a(b, f, pos, a1)?;
        let l2 = if c5 {
            eval_r(b, f, pos, i2, Width::W)? as u32
        } else {
            l1
        };
        let p2 = eval_a(b, f, pos, a2)?;
        r_set(b, 0, l1);
        r_set(b, 1, p1);
        r_set(b, 2, l2);
        r_set(b, 3, p2);
        Ok([fill, 0, 0, 0])
    })?
    else {
        return Ok(());
    };
    let fill = work[0] as u8;
    let (mut r0, mut r1, mut r2, mut r3) = (r_get(b, 0), r_get(b, 1), r_get(b, 2), r_get(b, 3));
    // 反復 1 回 = 1 バイトの比較。不一致か両者尽きで終了。
    if r0 != 0 && r2 != 0 {
        let x = load(b, r1, 1)? as u8;
        let y = load(b, r3, 1)? as u8;
        if x != y {
            cc_bcmp(b, x, y);
            str_leave(b, opc, work, pc0, true);
            return Ok(());
        }
        r0 -= 1;
        r1 = r1.wrapping_add(1);
        r2 -= 1;
        r3 = r3.wrapping_add(1);
    } else if r0 != 0 {
        let x = load(b, r1, 1)? as u8;
        if x != fill {
            cc_bcmp(b, x, fill);
            str_leave(b, opc, work, pc0, true);
            return Ok(());
        }
        r0 -= 1;
        r1 = r1.wrapping_add(1);
    } else if r2 != 0 {
        let y = load(b, r3, 1)? as u8;
        if y != fill {
            cc_bcmp(b, fill, y);
            str_leave(b, opc, work, pc0, true);
            return Ok(());
        }
        r2 -= 1;
        r3 = r3.wrapping_add(1);
    }
    let done = r0 == 0 && r2 == 0;
    r_set(b, 0, r0);
    r_set(b, 1, r1);
    r_set(b, 2, r2);
    r_set(b, 3, r3);
    if done {
        cc_nzvc(b, false, true, false, false);
    }
    str_leave(b, opc, work, pc0, done);
    Ok(())
}

/// locc/skpc: char.rb, len.rw, addr.ab。locc は一致を探し、skpc は
/// 不一致を探す。r0=残り（見つけたバイトを含む）・r1=その位置
/// （なければ 1 つ先）。CC: N=0・Z=r0==0・V=0・C=0。
fn locc(
    b: &mut InterpBackend,
    f: &Fetched,
    pos: &[(u32, u32)],
    pc0: u32,
) -> Result<(), InterpExit> {
    let skip = f.insn == Insn::Skpc;
    let opc = if skip { 0x3b } else { 0x3a };
    let Some(work) = str_enter(b, f, pos, opc, |b, f, pos| {
        let ch = eval_r(b, f, pos, 0, Width::B)? as u32;
        let len = eval_r(b, f, pos, 1, Width::W)? as u32;
        let a = eval_a(b, f, pos, 2)?;
        r_set(b, 0, len);
        r_set(b, 1, a);
        Ok([ch, 0, 0, 0])
    })?
    else {
        return Ok(());
    };
    let ch = work[0] as u8;
    let (mut r0, mut r1) = (r_get(b, 0), r_get(b, 1));
    let mut done = r0 == 0;
    if !done {
        let x = load(b, r1, 1)? as u8;
        done = (x == ch) != skip;
        if !done {
            r0 -= 1;
            r1 = r1.wrapping_add(1);
            r_set(b, 0, r0);
            r_set(b, 1, r1);
            done = r0 == 0;
        }
    }
    if done {
        cc_strz(b, r0 == 0);
    }
    str_leave(b, opc, work, pc0, done);
    Ok(())
}

/// scanc/spanc: len.rw, addr.ab, tbl.ab, mask.rb。各バイトで
/// 表を引き、scanc は (tbl[b] & mask) != 0 で、spanc は == 0 で
/// 止まる。r0=残り（条件バイトを含む）・r1=その位置・r2=0・
/// r3=tbl。CC: N=0・Z=r0==0・V=0・C=0。
fn scanc(
    b: &mut InterpBackend,
    f: &Fetched,
    pos: &[(u32, u32)],
    pc0: u32,
) -> Result<(), InterpExit> {
    let span = f.insn == Insn::Spanc;
    let opc = if span { 0x2b } else { 0x2a };
    let Some(work) = str_enter(b, f, pos, opc, |b, f, pos| {
        let len = eval_r(b, f, pos, 0, Width::W)? as u32;
        let a = eval_a(b, f, pos, 1)?;
        let t = eval_a(b, f, pos, 2)?;
        let m = eval_r(b, f, pos, 3, Width::B)? as u32;
        r_set(b, 0, len);
        r_set(b, 1, a);
        r_set(b, 2, 0);
        r_set(b, 3, t);
        Ok([m, 0, 0, 0])
    })?
    else {
        return Ok(());
    };
    let m = work[0] as u8;
    let (mut r0, mut r1, r3) = (r_get(b, 0), r_get(b, 1), r_get(b, 3));
    let mut done = r0 == 0;
    if !done {
        let x = load(b, r1, 1)? as u8;
        let t = load(b, r3.wrapping_add(u32::from(x)), 1)? as u8;
        done = (t & m != 0) != span;
        if !done {
            r0 -= 1;
            r1 = r1.wrapping_add(1);
            r_set(b, 0, r0);
            r_set(b, 1, r1);
            done = r0 == 0;
        }
    }
    if done {
        cc_strz(b, r0 == 0);
    }
    str_leave(b, opc, work, pc0, done);
    Ok(())
}

/// matchc: objlen.rw, objaddr.ab, srclen.rw, srcaddr.ab。source 内
/// に object と一致する部分列を探す。r0=object 残り・r1=object
/// 走査・r2=source 残り・r3=source 走査、work[0]=元の objlen。
/// 不一致のたび object を頭に戻して起点を 1 つ進める（正本の
/// アルゴリズム）。終了: 一致なら r0=0・r1=object 終端・r2=一致
/// 末尾以降の source 残り・r3=一致末尾の 1 つ先。CC: Z=r0==0。
fn matchc(
    b: &mut InterpBackend,
    f: &Fetched,
    pos: &[(u32, u32)],
    pc0: u32,
) -> Result<(), InterpExit> {
    const OPC: u16 = 0x39;
    let Some(work) = str_enter(b, f, pos, OPC, |b, f, pos| {
        let ol = eval_r(b, f, pos, 0, Width::W)? as u32;
        let oa = eval_a(b, f, pos, 1)?;
        let sl = eval_r(b, f, pos, 2, Width::W)? as u32;
        let sa = eval_a(b, f, pos, 3)?;
        r_set(b, 0, ol);
        r_set(b, 1, oa);
        r_set(b, 2, sl);
        r_set(b, 3, sa);
        Ok([ol, 0, 0, 0])
    })?
    else {
        return Ok(());
    };
    let (mut r0, mut r1, mut r2, mut r3) = (r_get(b, 0), r_get(b, 1), r_get(b, 2), r_get(b, 3));
    let mut done = r0 == 0;
    if !done && r2 < r0 {
        // 残りが object より短い —— 一致し得ない。
        r3 = r3.wrapping_add(r2);
        r2 = 0;
        done = true;
    } else if !done {
        if load(b, r1, 1)? == load(b, r3, 1)? {
            r0 -= 1;
            r1 = r1.wrapping_add(1);
            r2 -= 1;
            r3 = r3.wrapping_add(1);
        } else {
            // object を頭に戻し、起点を 1 つ進める。
            let k = work[0] - r0;
            r1 = r1.wrapping_sub(k);
            r2 = r2.wrapping_add(k).wrapping_sub(1);
            r3 = r3.wrapping_add(1).wrapping_sub(k);
            r0 = work[0];
        }
        if r0 == 0 {
            done = true;
        } else if r2 < r0 {
            r3 = r3.wrapping_add(r2);
            r2 = 0;
            done = true;
        }
    }
    r_set(b, 0, r0);
    r_set(b, 1, r1);
    r_set(b, 2, r2);
    r_set(b, 3, r3);
    if done {
        cc_strz(b, r0 == 0);
    }
    str_leave(b, OPC, work, pc0, done);
    Ok(())
}

/// movtc/movtuc: srclen.rw, src.ab, fill/esc.rb, tbl.ab, dstlen.rw,
/// dst.ab。src を表で翻して dst へ。movtc は残りを fill で埋め、
/// movtuc は翻訳結果が esc に一致したバイトで止まる。方向の規則は
/// movc3 と同じ（movtuc は常に前向き —— 正本は esc 版に前向き
/// しか書かない）。r0=src 残り・r1=src 走査・r2=0・r3=tbl・
/// r4=dst 残り・r5=dst 走査、work=[方向, fill/esc, srclen, dstlen]。
/// 終了: movtc は r1=src+移動数・r5=dst+dstlen・V=0、movtuc は
/// r1=原因バイト・r5=受け取るはずだった位置・V=esc で止まった。
/// N=srclen<dstlen・Z=等値・C=符号なし比較。
fn movtc(
    b: &mut InterpBackend,
    f: &Fetched,
    pos: &[(u32, u32)],
    pc0: u32,
) -> Result<(), InterpExit> {
    let tuc = f.insn == Insn::Movtuc;
    let opc = if tuc { 0x2f } else { 0x2e };
    let Some(work) = str_enter(b, f, pos, opc, |b, f, pos| {
        let sl = eval_r(b, f, pos, 0, Width::W)? as u32;
        let s = eval_a(b, f, pos, 1)?;
        let esc = eval_r(b, f, pos, 2, Width::B)? as u32;
        let t = eval_a(b, f, pos, 3)?;
        let dl = eval_r(b, f, pos, 4, Width::W)? as u32;
        let d = eval_a(b, f, pos, 5)?;
        let bwd = !tuc && s <= d;
        r_set(b, 0, sl);
        r_set(b, 1, if bwd { s.wrapping_add(sl.min(dl)) } else { s });
        r_set(b, 2, 0);
        r_set(b, 3, t);
        r_set(b, 4, dl);
        r_set(b, 5, if bwd { d.wrapping_add(dl) } else { d });
        Ok([u32::from(bwd), esc, sl, dl])
    })?
    else {
        return Ok(());
    };
    let esc = work[1] as u8;
    let (mut r0, mut r1, r3, mut r4, mut r5) = (
        r_get(b, 0),
        r_get(b, 1),
        r_get(b, 3),
        r_get(b, 4),
        r_get(b, 5),
    );
    let mut hit = false;
    let done = if work[0] == 0 {
        // 前向き: 翻訳しながら移す。movtc は src が尽きた後も
        // dst を fill で埋め切る。movtuc は esc で止まり fill しない。
        if r0 != 0 && r4 != 0 {
            let x = load(b, r1, 1)? as u8;
            let t = load(b, r3.wrapping_add(u32::from(x)), 1)? as u8;
            if tuc && t == esc {
                hit = true;
            } else {
                store(b, r5, 1, u128::from(t))?;
                r0 -= 1;
                r1 = r1.wrapping_add(1);
                r4 -= 1;
                r5 = r5.wrapping_add(1);
            }
        } else if r4 != 0 && !tuc {
            store(b, r5, 1, u128::from(esc))?;
            r4 -= 1;
            r5 = r5.wrapping_add(1);
        }
        if tuc {
            hit || r0 == 0 || r4 == 0
        } else {
            r4 == 0
        }
    } else {
        // 後ろ向き（movtc 専用）: fill を末尾から、続いて移動。
        if r4 > r0 {
            r4 -= 1;
            r5 = r5.wrapping_sub(1);
            store(b, r5, 1, u128::from(esc))?;
        } else if r4 != 0 {
            r0 -= 1;
            r1 = r1.wrapping_sub(1);
            r4 -= 1;
            r5 = r5.wrapping_sub(1);
            let x = load(b, r1, 1)? as u8;
            let t = load(b, r3.wrapping_add(u32::from(x)), 1)? as u8;
            store(b, r5, 1, u128::from(t))?;
        }
        r4 == 0
    };
    r_set(b, 0, r0);
    r_set(b, 1, r1);
    r_set(b, 4, r4);
    r_set(b, 5, r5);
    if done {
        if work[0] != 0 {
            r_set(b, 1, r1.wrapping_add(work[2].min(work[3])));
            r_set(b, 5, r5.wrapping_add(work[3]));
        }
        r_set(b, 2, 0);
        if !tuc {
            r_set(b, 4, 0);
        }
        cc_nzvc(
            b,
            work[2] < work[3],
            work[2] == work[3],
            tuc && hit,
            work[2] < work[3],
        );
    }
    str_leave(b, opc, work, pc0, done);
    Ok(())
}

/// crc: tbl.ab, inicrc.rl, strlen.rw, stream.ab。各バイトを CRC の
/// 下位バイトへ畳み、表（16 ロングワード）を 4 ビットずつ 2 回引く
/// （正本が許す shift 量の選択 —— 4 ビット ×2 で表構造に合わせる）。
/// r0=CRC 途中値・r1=残り・r2=stream 走査、work[0]=tbl。終了:
/// r0=結果・r1=r2=0・r3=stream 終端、N=結果の符号・Z=零・V=0・C=0。
fn crc(b: &mut InterpBackend, f: &Fetched, pos: &[(u32, u32)], pc0: u32) -> Result<(), InterpExit> {
    const OPC: u16 = 0x0b;
    let Some(work) = str_enter(b, f, pos, OPC, |b, f, pos| {
        let t = eval_a(b, f, pos, 0)?;
        let c = eval_r(b, f, pos, 1, Width::L)? as u32;
        let len = eval_r(b, f, pos, 2, Width::W)? as u32;
        let s = eval_a(b, f, pos, 3)?;
        r_set(b, 0, c);
        r_set(b, 1, len);
        r_set(b, 2, s);
        r_set(b, 3, 0);
        Ok([t, 0, 0, 0])
    })?
    else {
        return Ok(());
    };
    let (mut r0, mut r1, mut r2) = (r_get(b, 0), r_get(b, 1), r_get(b, 2));
    let mut done = r1 == 0;
    if !done {
        let x = load(b, r2, 1)? as u32;
        r0 = r0 & !0xff | (r0 ^ x) & 0xff;
        r2 = r2.wrapping_add(1);
        r1 -= 1;
        for _ in 0..2 {
            let i = r0 & 0xf;
            let t = load(b, work[0].wrapping_add(4 * i), 4)? as u32;
            r0 = r0 >> 4 ^ t;
        }
        r_set(b, 0, r0);
        r_set(b, 1, r1);
        r_set(b, 2, r2);
        done = r1 == 0;
    }
    if done {
        r_set(b, 3, r2);
        r_set(b, 2, 0);
        r_set(b, 1, 0);
        cc_nzvc(b, (r0 as i32) < 0, r0 == 0, false, false);
    }
    str_leave(b, OPC, work, pc0, done);
    Ok(())
}

/// 命令 1 個の意味論。`pos[i]` はオペランド i の指定子バイト列の
/// 先頭・終端の絶対アドレス（PC 相対の基底と即値の位置に使う）。
/// `pc0` は命令の先頭アドレス。実行時の r15 は命令の終端
/// （呼び出し側が `pc0 + f.len` に設定済み）。
// Ref: SPEC-VAX-ARM（各命令の意味論）.
pub fn exec(
    b: &mut InterpBackend,
    f: &Fetched,
    pc0: u32,
    pos: &[(u32, u32)],
) -> Result<(), InterpExit> {
    match f.insn {
        Insn::Halt => {
            // カーネルモード専用。bare はユーザーモード（psl::USER）
            // で走るので特権命令 fault になるのが常。
            return Err(if cur_mod(b) == 0 {
                InterpExit::Unimplemented("halt (kernel)".to_string())
            } else {
                fault(scb::PRIV_INSN, None)
            });
        }
        // 反復しない命令は開始時に部分実行の標識を消す。中断可能な
        // 文字列命令は各本体が partial_resume/partial_done を捌く。
        Insn::Movc3
        | Insn::Movc5
        | Insn::Cmpc3
        | Insn::Cmpc5
        | Insn::Locc
        | Insn::Skpc
        | Insn::Scanc
        | Insn::Spanc
        | Insn::Matchc
        | Insn::Movtc
        | Insn::Movtuc
        | Insn::Crc => {}
        _ => partial_done(b),
    }
    match f.insn {
        Insn::Nop => {}
        Insn::Movb | Insn::Movw | Insn::Movl | Insn::Movq | Insn::Movo => {
            let w = specifier::insn_ops(f.insn)[0].width;
            let s = eval(b, f, pos, 0)?;
            let v = read(b, &s, w)?;
            let d = eval(b, f, pos, 1)?;
            write(b, &d, w, v)?;
            cc_mov(b, v, w);
        }
        Insn::Clrb | Insn::Clrw | Insn::Clrl | Insn::Clrq => {
            let w = specifier::insn_ops(f.insn)[0].width;
            let d = eval(b, f, pos, 0)?;
            write(b, &d, w, 0)?;
            cc_nzv(b, false, true, false);
        }
        Insn::Mcomb | Insn::Mcomw | Insn::Mcoml => {
            let w = specifier::insn_ops(f.insn)[0].width;
            let s = eval(b, f, pos, 0)?;
            let v = !read(b, &s, w)? & mask_w(w);
            let d = eval(b, f, pos, 1)?;
            write(b, &d, w, v)?;
            cc_mov(b, v, w);
        }
        Insn::Movzbl | Insn::Movzbw | Insn::Movzwl => {
            let tys = specifier::insn_ops(f.insn);
            let s = eval(b, f, pos, 0)?;
            let v = read(b, &s, tys[0].width)?;
            let d = eval(b, f, pos, 1)?;
            write(b, &d, tys[1].width, v)?;
            // ゼロ拡張なので N は立たない。
            cc_nzv(b, false, v == 0, false);
        }
        Insn::Movab | Insn::Movaw | Insn::Moval | Insn::Movaq | Insn::Movah => {
            let s = eval(b, f, pos, 0)?;
            let a = loc_addr(&s)?;
            let d = eval(b, f, pos, 1)?;
            write(b, &d, Width::L, u128::from(a))?;
            cc_mov(b, u128::from(a), Width::L);
        }
        Insn::Pushab | Insn::Pushaw | Insn::Pushal | Insn::Pushaq | Insn::Pushah => {
            let s = eval(b, f, pos, 0)?;
            let a = loc_addr(&s)?;
            push(b, u128::from(a))?;
        }
        Insn::Pushl => {
            let s = eval(b, f, pos, 0)?;
            let v = read(b, &s, Width::L)?;
            push(b, v)?;
        }
        // ---- 整数演算（VX5）----
        // 加算: 2 項は sum.mx = sum + add、3 項は sum.wx = add1 + add2。
        // adwc は C を桁入れとして足す。C は桁出し、V は符号付き
        // あふれ。V=1 で PSL<IV>=1 なら算術 trap。
        Insn::Addb2 | Insn::Addw2 | Insn::Addl2 | Insn::Adwc => {
            let w = specifier::insn_ops(f.insn)[0].width;
            let cin = u128::from(f.insn == Insn::Adwc && psl_flag(b, psl::C));
            let s = eval(b, f, pos, 0)?;
            let sv = read(b, &s, w)?;
            let d = eval(b, f, pos, 1)?;
            let dv = read(b, &d, w)?;
            let (r, v, c) = add_op(sv, dv, cin, w);
            write(b, &d, w, r)?;
            cc_arith(b, r, v, c, w);
            iv_trap(b)?;
        }
        Insn::Addb3 | Insn::Addw3 | Insn::Addl3 => {
            let w = specifier::insn_ops(f.insn)[0].width;
            let s0 = eval(b, f, pos, 0)?;
            let a = read(b, &s0, w)?;
            let s1 = eval(b, f, pos, 1)?;
            let s = read(b, &s1, w)?;
            let d = eval(b, f, pos, 2)?;
            let (r, v, c) = add_op(a, s, 0, w);
            write(b, &d, w, r)?;
            cc_arith(b, r, v, c, w);
            iv_trap(b)?;
        }
        // 減算: 2 項は dif.mx = dif - sub、3 項は dif.wx = min - sub。
        // sbwc は C を借り入れとして引く。C は借り（符号なし減算の
        // 負化）、V は符号付きあふれ。
        Insn::Subb2 | Insn::Subw2 | Insn::Subl2 | Insn::Sbwc => {
            let w = specifier::insn_ops(f.insn)[0].width;
            let bin = u128::from(f.insn == Insn::Sbwc && psl_flag(b, psl::C));
            let s = eval(b, f, pos, 0)?;
            let sv = read(b, &s, w)?;
            let d = eval(b, f, pos, 1)?;
            let dv = read(b, &d, w)?;
            let (r, v, c) = sub_op(dv, sv, bin, w);
            write(b, &d, w, r)?;
            cc_arith(b, r, v, c, w);
            iv_trap(b)?;
        }
        Insn::Subb3 | Insn::Subw3 | Insn::Subl3 => {
            let w = specifier::insn_ops(f.insn)[0].width;
            let s0 = eval(b, f, pos, 0)?;
            let a = read(b, &s0, w)?;
            let s1 = eval(b, f, pos, 1)?;
            let s = read(b, &s1, w)?;
            let d = eval(b, f, pos, 2)?;
            let (r, v, c) = sub_op(a, s, 0, w);
            write(b, &d, w, r)?;
            cc_arith(b, r, v, c, w);
            iv_trap(b)?;
        }
        // 増減: +1/-1。V はあふれ（最大正→負・最大負→正）、C は保存。
        Insn::Incb | Insn::Incw | Insn::Incl | Insn::Decb | Insn::Decw | Insn::Decl => {
            let w = specifier::insn_ops(f.insn)[0].width;
            let d = eval(b, f, pos, 0)?;
            let dv = read(b, &d, w)?;
            let inc = matches!(f.insn, Insn::Incb | Insn::Incw | Insn::Incl);
            let (r, v, _) = if inc {
                add_op(dv, 1, 0, w)
            } else {
                sub_op(dv, 1, 0, w)
            };
            write(b, &d, w, r)?;
            cc_arith(b, r, v, psl_flag(b, psl::C), w);
            iv_trap(b)?;
        }
        // 符号反転。C=0、V は最負値の反転（結果が表せない）。
        Insn::Mnegb | Insn::Mnegw | Insn::Mnegl => {
            let w = specifier::insn_ops(f.insn)[0].width;
            let s = eval(b, f, pos, 0)?;
            let sv = sext_w(read(b, &s, w)?, w);
            let neg = -sv;
            let d = eval(b, f, pos, 1)?;
            let r = neg as u128 & mask_w(w);
            write(b, &d, w, r)?;
            cc_arith(b, r, !fits_s(neg, w), false, w);
            iv_trap(b)?;
        }
        // 乗算: 真の積の幅ぶんへの切り詰め。C=0、V は幅に収まら
        // ない積（結果は切り詰めた値）。
        Insn::Mulb2 | Insn::Mulw2 | Insn::Mull2 => {
            let w = specifier::insn_ops(f.insn)[0].width;
            let s = eval(b, f, pos, 0)?;
            let sv = sext_w(read(b, &s, w)?, w);
            let d = eval(b, f, pos, 1)?;
            let dv = sext_w(read(b, &d, w)?, w);
            let p = dv * sv;
            write(b, &d, w, p as u128)?;
            cc_arith(b, p as u128, !fits_s(p, w), false, w);
            iv_trap(b)?;
        }
        Insn::Mulb3 | Insn::Mulw3 | Insn::Mull3 => {
            let w = specifier::insn_ops(f.insn)[0].width;
            let s0 = eval(b, f, pos, 0)?;
            let a = sext_w(read(b, &s0, w)?, w);
            let s1 = eval(b, f, pos, 1)?;
            let s = sext_w(read(b, &s1, w)?, w);
            let d = eval(b, f, pos, 2)?;
            let p = a * s;
            write(b, &d, w, p as u128)?;
            cc_arith(b, p as u128, !fits_s(p, w), false, w);
            iv_trap(b)?;
        }
        // 除算: 2 項は quo.mx = quo / divr、3 項は quo.wx =
        // divd / divr。商は 0 方向切り詰め。除数 0 は整数ゼロ除算
        // trap（指定子は評価済み、書き戻しと条件コードは行わない）。
        // 商のあふれ（最負値 / -1）は V=1＋IV で算術 trap。C=0。
        Insn::Divb2 | Insn::Divw2 | Insn::Divl2 => {
            let w = specifier::insn_ops(f.insn)[0].width;
            let s = eval(b, f, pos, 0)?;
            let divr = sext_w(read(b, &s, w)?, w);
            let d = eval(b, f, pos, 1)?;
            let divd = sext_w(read(b, &d, w)?, w);
            let (q, v) = div_op(divd, divr, w)?;
            write(b, &d, w, q as u128)?;
            cc_arith(b, q as u128, v, false, w);
            iv_trap(b)?;
        }
        Insn::Divb3 | Insn::Divw3 | Insn::Divl3 => {
            let w = specifier::insn_ops(f.insn)[0].width;
            let s = eval(b, f, pos, 0)?;
            let divr = sext_w(read(b, &s, w)?, w);
            let dd = eval(b, f, pos, 1)?;
            let divd = sext_w(read(b, &dd, w)?, w);
            let d = eval(b, f, pos, 2)?;
            let (q, v) = div_op(divd, divr, w)?;
            write(b, &d, w, q as u128)?;
            cc_arith(b, q as u128, v, false, w);
            iv_trap(b)?;
        }
        // emul: prod.wq = mulr * muld + add（64 ビットの真の積和。
        // あふれなし。C=0・V=0）。
        Insn::Emul => {
            let s0 = eval(b, f, pos, 0)?;
            let a = sext_w(read(b, &s0, Width::L)?, Width::L);
            let s1 = eval(b, f, pos, 1)?;
            let m = sext_w(read(b, &s1, Width::L)?, Width::L);
            let s2 = eval(b, f, pos, 2)?;
            let add = sext_w(read(b, &s2, Width::L)?, Width::L);
            let d = eval(b, f, pos, 3)?;
            let p = a * m + add;
            write(b, &d, Width::Q, p as u128)?;
            cc_arith(b, p as u128, false, false, Width::Q);
        }
        // ediv: quo.wl / rem.wl = divd.rq / divr.rl（商は 0 方向
        // 切り詰め、剰余は被除数と同符号）。商が longword に収まら
        // ないと V=1（書き戻しは切り詰めた商 —— 決定的な選択）。
        Insn::Ediv => {
            let s = eval(b, f, pos, 0)?;
            let divr = sext_w(read(b, &s, Width::L)?, Width::L);
            let dd = eval(b, f, pos, 1)?;
            let divd = sext_w(read(b, &dd, Width::Q)?, Width::Q);
            let q = eval(b, f, pos, 2)?;
            let m = eval(b, f, pos, 3)?;
            let (quo, v) = div_op(divd, divr, Width::L)?;
            let rem = divd - quo * divr;
            write(b, &q, Width::L, quo as u128)?;
            write(b, &m, Width::L, rem as u128)?;
            cc_arith(b, quo as u128, v, false, Width::L);
            iv_trap(b)?;
        }
        // 比較・テスト: cmp は N=op1<op2（真の符号付き比較。
        // 差の符号ではない）、Z=等値、V=0、C=op1 <u op2（借り）。
        // tst は 0 との比較で C=0。
        Insn::Cmpb | Insn::Cmpw | Insn::Cmpl => {
            let w = specifier::insn_ops(f.insn)[0].width;
            let s0 = eval(b, f, pos, 0)?;
            let a = read(b, &s0, w)?;
            let s1 = eval(b, f, pos, 1)?;
            let s = read(b, &s1, w)?;
            cc_nzvc(
                b,
                sext_w(a, w) < sext_w(s, w),
                a & mask_w(w) == s & mask_w(w),
                false,
                a & mask_w(w) < s & mask_w(w),
            );
        }
        Insn::Tstb | Insn::Tstw | Insn::Tstl => {
            let w = specifier::insn_ops(f.insn)[0].width;
            let s = eval(b, f, pos, 0)?;
            let v = read(b, &s, w)?;
            cc_nzvc(b, sext_w(v, w) < 0, v & mask_w(w) == 0, false, false);
        }
        // 整数変換: 符号拡張（広げ）または切り詰め（縮小）。
        // 縮小で表せない値は V=1、結果は下位ぶん。C=0。
        Insn::Cvtbw | Insn::Cvtbl | Insn::Cvtwb | Insn::Cvtwl | Insn::Cvtlb | Insn::Cvtlw => {
            let tys = specifier::insn_ops(f.insn);
            let s = eval(b, f, pos, 0)?;
            let sv = sext_w(read(b, &s, tys[0].width)?, tys[0].width);
            let dw = tys[1].width;
            let d = eval(b, f, pos, 1)?;
            write(b, &d, dw, sv as u128)?;
            cc_arith(b, sv as u128, !fits_s(sv, dw), false, dw);
            iv_trap(b)?;
        }
        // ---- 論理・ビット・フィールド・分岐複合（VX6）----
        // bis/bic/xor: 2 項は dst.mx を mask で変形、3 項は
        // src を変形して dst.wx へ。N=結果の符号・Z=零・V=0・C 保存。
        Insn::Bisb2
        | Insn::Bisw2
        | Insn::Bisl2
        | Insn::Bicb2
        | Insn::Bicw2
        | Insn::Bicl2
        | Insn::Xorb2
        | Insn::Xorw2
        | Insn::Xorl2 => {
            let w = specifier::insn_ops(f.insn)[0].width;
            let s = eval(b, f, pos, 0)?;
            let m = read(b, &s, w)?;
            let d = eval(b, f, pos, 1)?;
            let dv = read(b, &d, w)?;
            let r = bit_op(f.insn, dv, m) & mask_w(w);
            write(b, &d, w, r)?;
            cc_mov(b, r, w);
        }
        Insn::Bisb3
        | Insn::Bisw3
        | Insn::Bisl3
        | Insn::Bicb3
        | Insn::Bicw3
        | Insn::Bicl3
        | Insn::Xorb3
        | Insn::Xorw3
        | Insn::Xorl3 => {
            let w = specifier::insn_ops(f.insn)[0].width;
            let s0 = eval(b, f, pos, 0)?;
            let m = read(b, &s0, w)?;
            let s1 = eval(b, f, pos, 1)?;
            let sv = read(b, &s1, w)?;
            let d = eval(b, f, pos, 2)?;
            let r = bit_op(f.insn, sv, m) & mask_w(w);
            write(b, &d, w, r)?;
            cc_mov(b, r, w);
        }
        // bit: src AND mask で条件コードだけ立てる（書き戻しなし）。
        Insn::Bitb | Insn::Bitw | Insn::Bitl => {
            let w = specifier::insn_ops(f.insn)[0].width;
            let s0 = eval(b, f, pos, 0)?;
            let m = read(b, &s0, w)?;
            let s1 = eval(b, f, pos, 1)?;
            let t = read(b, &s1, w)? & m & mask_w(w);
            cc_mov(b, t, w);
        }
        // ash: 算術シフト。正のカウントは左（0 補充）、負は右
        // （符号複製）。カウントが幅を越えると結果は 0（左）または
        // 符号の複製（右）。V は左シフトで符号位置に入ったビットが
        // 元の符号と異なるとき（幅を越える左カウントでは src≠0 なら
        // 必ず立つ）。C=0。
        Insn::Ashl | Insn::Ashq => {
            let w = specifier::insn_ops(f.insn)[1].width;
            let s = eval(b, f, pos, 0)?;
            let cnt = sext_w(read(b, &s, Width::B)?, Width::B) as i32;
            let s1 = eval(b, f, pos, 1)?;
            let sv = read(b, &s1, w)?;
            let bits = (w.bytes() * 8) as i32;
            let (r, v) = if cnt > bits {
                (0, sv & mask_w(w) != 0)
            } else if cnt >= 0 {
                let t = sext_w(sv, w) << cnt;
                (t as u128 & mask_w(w), !fits_s(t, w))
            } else if cnt <= 1 - bits {
                (if sext_w(sv, w) < 0 { mask_w(w) } else { 0 }, false)
            } else {
                ((sext_w(sv, w) >> -cnt) as u128 & mask_w(w), false)
            };
            let d = eval(b, f, pos, 2)?;
            write(b, &d, w, r)?;
            cc_arith(b, r, v, false, w);
            iv_trap(b)?;
        }
        // rotl: 32 ビットの左回転（負のカウントは右）。V=0・C 保存。
        Insn::Rotl => {
            let s = eval(b, f, pos, 0)?;
            let cnt = sext_w(read(b, &s, Width::B)?, Width::B) as i32;
            let s1 = eval(b, f, pos, 1)?;
            let sv = read(b, &s1, Width::L)? as u32;
            let d = eval(b, f, pos, 2)?;
            let r = sv.rotate_left(cnt.rem_euclid(32) as u32);
            write(b, &d, Width::L, u128::from(r))?;
            cc_mov(b, u128::from(r), Width::L);
        }
        // extv/extzv: FIELD(pos,size,base) を符号/ゼロ拡張して
        // dst.wl へ。size=0 は dst=0。N=結果の符号・Z=零・V=0・C 保存。
        Insn::Extv | Insn::Extzv => {
            let s = eval(b, f, pos, 0)?;
            let p = read(b, &s, Width::L)? as u32 as i32;
            let s = eval(b, f, pos, 1)?;
            let size = read(b, &s, Width::B)? as u32;
            let base = eval(b, f, pos, 2)?;
            field_check(&base, p, size)?;
            let d = eval(b, f, pos, 3)?;
            let fv = field_get(b, &base, p, size)?;
            let r = if f.insn == Insn::Extv && size != 0 {
                (((fv << (32 - size)) as i32) >> (32 - size)) as u32
            } else {
                fv
            };
            write(b, &d, Width::L, u128::from(r))?;
            cc_mov(b, u128::from(r), Width::L);
        }
        // cmpv/cmpzv: FIELD と src の比較のみ。フィールドが第 1 項
        // （N=field LSS src・C=field LSSU src）。V=0。
        Insn::Cmpv | Insn::Cmpzv => {
            let s = eval(b, f, pos, 0)?;
            let p = read(b, &s, Width::L)? as u32 as i32;
            let s = eval(b, f, pos, 1)?;
            let size = read(b, &s, Width::B)? as u32;
            let base = eval(b, f, pos, 2)?;
            field_check(&base, p, size)?;
            let s = eval(b, f, pos, 3)?;
            let src = read(b, &s, Width::L)? as u32;
            let fv = field_get(b, &base, p, size)?;
            let t = if f.insn == Insn::Cmpv && size != 0 {
                (((fv << (32 - size)) as i32) >> (32 - size)) as u32
            } else {
                fv
            };
            cc_nzvc(b, (t as i32) < (src as i32), t == src, false, t < src);
        }
        // insv: src の下位 size ビットを FIELD へ。size=0 は何も
        // しない。条件コードは変えない。
        Insn::Insv => {
            let s = eval(b, f, pos, 0)?;
            let v = read(b, &s, Width::L)? as u32;
            let s = eval(b, f, pos, 1)?;
            let p = read(b, &s, Width::L)? as u32 as i32;
            let s = eval(b, f, pos, 2)?;
            let size = read(b, &s, Width::B)? as u32;
            let base = eval(b, f, pos, 3)?;
            field_check(&base, p, size)?;
            field_put(b, &base, p, size, v)?;
        }
        // ffs/ffc: フィールド内を下位ビットから走査し、指定状態の
        // 最初のビットの位置（base 基準の絶対位置）を findpos へ。
        // 見つからなければ Z=1 で findpos=startpos+size、size=0
        // なら findpos=startpos・Z=1。N=0・V=0・C=0。
        Insn::Ffs | Insn::Ffc => {
            let s = eval(b, f, pos, 0)?;
            let p = read(b, &s, Width::L)? as u32 as i32;
            let s = eval(b, f, pos, 1)?;
            let size = read(b, &s, Width::B)? as u32;
            let base = eval(b, f, pos, 2)?;
            field_check(&base, p, size)?;
            let d = eval(b, f, pos, 3)?;
            let fv = field_get(b, &base, p, size)?;
            let bits = fv & fmask(size) as u32;
            // 探す状態に合わせて畳む（ffc はフィールド内の 0 ビット）。
            let cand = if f.insn == Insn::Ffs {
                bits
            } else {
                !bits & fmask(size) as u32
            };
            let found = cand != 0;
            let at = if found {
                cand.trailing_zeros() as i32
            } else {
                size as i32
            };
            write(b, &d, Width::L, p.wrapping_add(at) as u32 as u128)?;
            cc_nzvc(b, false, !found, false, false);
        }
        // bb 系: FIELD(pos,1,base) を試して分岐。ss/cs/sc/cc/i 系は
        // 試したビットを新しい状態に書き換える（bbssi/bbcci の
        // インターロックは単一スレッドの近似で非インターロック版と
        // 同じ）。条件コードは変えない。
        Insn::Bbs
        | Insn::Bbc
        | Insn::Bbss
        | Insn::Bbcs
        | Insn::Bbsc
        | Insn::Bbcc
        | Insn::Bbssi
        | Insn::Bbcci => {
            let s = eval(b, f, pos, 0)?;
            let p = read(b, &s, Width::L)? as u32 as i32;
            let base = eval(b, f, pos, 1)?;
            field_check(&base, p, 1)?;
            let old = field_get(b, &base, p, 1)?;
            // (試す状態, 新しい状態)。bbs/bbc は書き換えない。
            let (test, new): (u32, Option<u32>) = match f.insn {
                Insn::Bbs => (1, None),
                Insn::Bbc => (0, None),
                Insn::Bbss | Insn::Bbssi => (1, Some(1)),
                Insn::Bbcs => (0, Some(1)),
                Insn::Bbsc => (1, Some(0)),
                _ => (0, Some(0)), // bbcc, bbcci
            };
            if let Some(n) = new {
                field_put(b, &base, p, 1, n)?;
            }
            if old == test {
                branch(b, br_displ(f, 2));
            }
        }
        // blbs/blbc: src の最下位ビットを試して分岐。
        Insn::Blbs | Insn::Blbc => {
            let s = eval(b, f, pos, 0)?;
            let v = read(b, &s, Width::L)?;
            if v & 1 == u128::from(f.insn == Insn::Blbs) {
                branch(b, br_displ(f, 1));
            }
        }
        // case: tmp = selector - base（幅の減算）。tmp <=u limit なら
        // 命令終端（=displ[0] の位置）を基準に語変位表で分岐、
        // 越えれば表の直後（2+2*limit 先）へ。CC は tmp と limit の
        // 比較（N=tmp LSS limit・Z=等値・V=0・C=tmp LSSU limit）。
        Insn::Caseb | Insn::Casew | Insn::Casel => {
            let w = specifier::insn_ops(f.insn)[0].width;
            let s = eval(b, f, pos, 0)?;
            let sel = read(b, &s, w)?;
            let s = eval(b, f, pos, 1)?;
            let bas = read(b, &s, w)?;
            let s = eval(b, f, pos, 2)?;
            let lim = read(b, &s, w)?;
            let t = sel.wrapping_sub(bas) & mask_w(w);
            let table = r_get(b, reg::PC as u8); // = displ[0] の位置
            if t <= lim {
                let d = load(b, table.wrapping_add(2 * t as u32), 2)? as u16;
                branch(b, i32::from(d as i16));
            } else {
                r_set(b, reg::PC as u8, table.wrapping_add(2 + 2 * lim as u32));
            }
            cc_nzvc(b, sext_w(t, w) < sext_w(lim, w), t == lim, false, t < lim);
        }
        // acb: index += add。add の符号が比較の向きを決める
        // （add>=0 → index<=limit、add<0 → index>=limit で分岐）。
        // N/Z/V は新しい index、C は保存。
        Insn::Acbb | Insn::Acbw | Insn::Acbl => {
            let w = specifier::insn_ops(f.insn)[0].width;
            let s = eval(b, f, pos, 0)?;
            let lim = sext_w(read(b, &s, w)?, w);
            let s = eval(b, f, pos, 1)?;
            let add = sext_w(read(b, &s, w)?, w);
            let d = eval(b, f, pos, 2)?;
            let idx = read(b, &d, w)?;
            let (r, v, _) = add_op(idx, add as u128, 0, w);
            write(b, &d, w, r)?;
            let ni = sext_w(r, w);
            if (add >= 0 && ni <= lim) || (add < 0 && ni >= lim) {
                branch(b, br_displ(f, 3));
            }
            cc_arith(b, r, v, psl_flag(b, psl::C), w);
            iv_trap(b)?;
        }
        // aob: index += 1。aoblss は index<limit、aobleq は
        // index<=limit で分岐。C 保存、V はあふれ。
        Insn::Aoblss | Insn::Aobleq => {
            let s = eval(b, f, pos, 0)?;
            let lim = sext_w(read(b, &s, Width::L)?, Width::L);
            let d = eval(b, f, pos, 1)?;
            let idx = read(b, &d, Width::L)?;
            let (r, v, _) = add_op(idx, 1, 0, Width::L);
            write(b, &d, Width::L, r)?;
            let ni = sext_w(r, Width::L);
            if ni < lim || (f.insn == Insn::Aobleq && ni == lim) {
                branch(b, br_displ(f, 2));
            }
            cc_arith(b, r, v, psl_flag(b, psl::C), Width::L);
            iv_trap(b)?;
        }
        // sob: index -= 1。sobgeq は index>=0、sobgtr は index>0
        // で分岐。C 保存、V はあふれ。
        Insn::Sobgeq | Insn::Sobgtr => {
            let d = eval(b, f, pos, 0)?;
            let idx = read(b, &d, Width::L)?;
            let (r, v, _) = sub_op(idx, 1, 0, Width::L);
            write(b, &d, Width::L, r)?;
            let ni = sext_w(r, Width::L);
            if ni > 0 || (f.insn == Insn::Sobgeq && ni == 0) {
                branch(b, br_displ(f, 1));
            }
            cc_arith(b, r, v, psl_flag(b, psl::C), Width::L);
            iv_trap(b)?;
        }
        Insn::Bpt => return Err(trap(scb::BPT)),
        // ---- キュー・文字列・マスク積み降ろし・CHM（VX7）----
        // insque: 絶対リンクの項目を先行項目の直後へ入れる。
        // (entry) <- (pred)、(entry+4) <- pred、((pred)+4) <- entry、
        // (pred) <- entry。N=succ LSS pred・Z=等値（先頭化）・V=0・
        // C=succ LSSU pred。
        Insn::Insque => {
            let e = eval_a(b, f, pos, 0)?;
            let p = eval_a(b, f, pos, 1)?;
            let s = load(b, p, 4)? as u32;
            store(b, e, 4, u128::from(s))?;
            store(b, e.wrapping_add(4), 4, u128::from(p))?;
            store(b, s.wrapping_add(4), 4, u128::from(e))?;
            store(b, p, 4, u128::from(e))?;
            cc_nzvc(b, (s as i32) < (p as i32), s == p, false, s < p);
        }
        // remque: 絶対リンクの項目を外してアドレスを addr.wl へ。
        // (pred) <- succ、(succ+4) <- pred。N=succ LSS pred・
        // Z=等値（除去で空）・V=後方リンクが項目自身（空キューの
        // ヘッダ除去 —— 除去できる項目がなかった）・C=succ LSSU pred。
        Insn::Remque => {
            let e = eval_a(b, f, pos, 0)?;
            let d = eval(b, f, pos, 1)?;
            let s = load(b, e, 4)? as u32;
            let p = load(b, e.wrapping_add(4), 4)? as u32;
            store(b, p, 4, u128::from(s))?;
            store(b, s.wrapping_add(4), 4, u128::from(p))?;
            write(b, &d, Width::L, u128::from(e))?;
            cc_nzvc(b, (s as i32) < (p as i32), s == p, e == p, s < p);
        }
        // insqhi/insqti: 自己相対リンクの項目をヘッダの直後・直前へ。
        // 成功は N=0・Z=空からの挿入・V=0・C=0。予約オペランド:
        // entry/ヘッダの非 8 バイト整列・ヘッダ=entry・ヘッダ語の
        // <2:1>（insqti は末尾変位 (header+4) の整列も見る）。
        Insn::Insqhi => {
            let e = eval_a(b, f, pos, 0)?;
            let h = eval_a(b, f, pos, 1)?;
            q_check(e, h)?;
            let Some(fw) = q_hdr(b, h)? else {
                q_fail(b);
                return Ok(());
            };
            let succ = h.wrapping_add(fw);
            store(b, h, 4, u128::from(fw | 1))?;
            store(b, e, 4, u128::from(succ.wrapping_sub(e)))?;
            store(b, e.wrapping_add(4), 4, u128::from(h.wrapping_sub(e)))?;
            store(b, succ.wrapping_add(4), 4, u128::from(e.wrapping_sub(succ)))?;
            store(b, h, 4, u128::from(e.wrapping_sub(h)))?;
            cc_nzvc(b, false, succ == h, false, false);
        }
        Insn::Insqti => {
            let e = eval_a(b, f, pos, 0)?;
            let h = eval_a(b, f, pos, 1)?;
            q_check(e, h)?;
            let Some(fw) = q_hdr(b, h)? else {
                q_fail(b);
                return Ok(());
            };
            let bw = load(b, h.wrapping_add(4), 4)? as u32;
            if bw & 7 != 0 {
                return Err(fault(scb::RESERVED_OPERAND, None));
            }
            let pred = h.wrapping_add(bw);
            store(b, h, 4, u128::from(fw | 1))?;
            store(b, e, 4, u128::from(h.wrapping_sub(e)))?;
            store(b, e.wrapping_add(4), 4, u128::from(pred.wrapping_sub(e)))?;
            store(b, pred, 4, u128::from(e.wrapping_sub(pred)))?;
            store(b, h.wrapping_add(4), 4, u128::from(e.wrapping_sub(h)))?;
            store(b, h, 4, u128::from(fw))?;
            cc_nzvc(b, false, pred == h, false, false);
        }
        // remqhi/remqti: ヘッダ直後・直前の項目を外し、その絶対
        // アドレスを addr.wl へ。成功は N=0・Z=除去後に空・
        // V=除去前から空・C=0。空でも addr.wl にはヘッダの位置を
        // 書く（アクセス検査の対象 —— 決定的な選択）。
        Insn::Remqhi => {
            let h = eval_a(b, f, pos, 0)?;
            let d = eval(b, f, pos, 1)?;
            // addr.wl がレジスタのときは等値チェック自体が
            // 不適用（loc_addr は Reg を RESERVED_MODE にする
            // ので、メモリ loc のときだけ比較する）。
            let same = matches!(d, Loc::Mem(_) | Loc::Val { .. }) && loc_addr(&d)? == h;
            if h & 7 != 0 || same {
                return Err(fault(scb::RESERVED_OPERAND, None));
            }
            let Some(fw) = q_hdr(b, h)? else {
                q_fail(b);
                return Ok(());
            };
            let mut z = true;
            if fw != 0 {
                let head = h.wrapping_add(fw);
                let sd = load(b, head, 4)? as u32;
                // 新しい先頭項目が指す次項目の整列も検査する。
                if sd & 7 != 0 {
                    return Err(fault(scb::RESERVED_OPERAND, None));
                }
                let succ = head.wrapping_add(sd);
                store(b, h, 4, u128::from(fw | 1))?;
                store(b, succ.wrapping_add(4), 4, u128::from(h.wrapping_sub(succ)))?;
                store(b, h, 4, u128::from(succ.wrapping_sub(h)))?;
                z = succ == h;
            }
            write(b, &d, Width::L, u128::from(h.wrapping_add(fw)))?;
            cc_nzvc(b, false, z, fw == 0, false);
        }
        Insn::Remqti => {
            let h = eval_a(b, f, pos, 0)?;
            let d = eval(b, f, pos, 1)?;
            // addr.wl がレジスタのときは等値チェック自体が
            // 不適用（loc_addr は Reg を RESERVED_MODE にする
            // ので、メモリ loc のときだけ比較する）。
            let same = matches!(d, Loc::Mem(_) | Loc::Val { .. }) && loc_addr(&d)? == h;
            if h & 7 != 0 || same {
                return Err(fault(scb::RESERVED_OPERAND, None));
            }
            let Some(fw) = q_hdr(b, h)? else {
                q_fail(b);
                return Ok(());
            };
            let bw = load(b, h.wrapping_add(4), 4)? as u32;
            if bw & 7 != 0 {
                return Err(fault(scb::RESERVED_OPERAND, None));
            }
            let mut z = true;
            if bw != 0 {
                let tail = h.wrapping_add(bw);
                let po = load(b, tail.wrapping_add(4), 4)? as u32;
                if po & 7 != 0 {
                    return Err(fault(scb::RESERVED_OPERAND, None));
                }
                let pred = tail.wrapping_add(po);
                store(b, h, 4, u128::from(fw | 1))?;
                store(b, pred, 4, u128::from(h.wrapping_sub(pred)))?;
                store(b, h.wrapping_add(4), 4, u128::from(pred.wrapping_sub(h)))?;
                // 単一項目（前後リンクが一致）なら (header) への
                // 復帰書き込みは前向きリンクを 0 に残すのが正本の
                // 結果 —— uVAX マイクロコードはこの場合先頭側から
                // 外す経路を取る。pred==h では (pred) <- h-pred の
                // 時点で既に 0 なので、何も書かない。
                if pred != h {
                    store(b, h, 4, u128::from(fw))?;
                }
                z = pred == h;
            }
            write(b, &d, Width::L, u128::from(h.wrapping_add(bw)))?;
            cc_nzvc(b, false, z, bw == 0, false);
        }
        // 中断可能な文字列群は本体側で反復 1 回ずつ進める。
        Insn::Movc3 => movc3(b, f, pos, pc0)?,
        Insn::Movc5 => movc5(b, f, pos, pc0)?,
        Insn::Cmpc3 | Insn::Cmpc5 => cmpc(b, f, pos, pc0)?,
        Insn::Locc | Insn::Skpc => locc(b, f, pos, pc0)?,
        Insn::Scanc | Insn::Spanc => scanc(b, f, pos, pc0)?,
        Insn::Matchc => matchc(b, f, pos, pc0)?,
        Insn::Movtc | Insn::Movtuc => movtc(b, f, pos, pc0)?,
        Insn::Crc => crc(b, f, pos, pc0)?,
        // pushr/popr: mask の立ったレジスタを積む/戻す。pushr は
        // r14 から r0 へ（push と同じく CC 不変）、popr は r0 から
        // r14 へ取り出す。r15（PC）は mask の対象外。
        Insn::Pushr => {
            let s = eval(b, f, pos, 0)?;
            let m = read(b, &s, Width::W)? as u32;
            for i in (0..=14u8).rev() {
                if m >> i & 1 != 0 {
                    push(b, u128::from(r_get(b, i)))?;
                }
            }
        }
        Insn::Popr => {
            let s = eval(b, f, pos, 0)?;
            let m = read(b, &s, Width::W)? as u32;
            let mut sp = r_get(b, reg::SP as u8);
            for i in 0..=14u8 {
                if m >> i & 1 != 0 {
                    let v = load(b, sp, 4)? as u32;
                    sp = sp.wrapping_add(4);
                    r_set(b, i, v);
                }
            }
            r_set(b, reg::SP as u8, sp);
        }
        // chm{x}: code を符号拡張して新モードのスタックへ積み、
        // 要求モードと現モードのうち特権の強い方へ写って SCB
        // 0x40+4*要求モード へ trap。スタックはモード別に切り替わ
        // るのが正本だが、このモデルは単一 SP —— 同一 SP への
        // push で近似し、実際の切り替えは trap を受けた
        // パーソナリティの仕事にする。PRV_MOD には旧 CUR_MOD が
        // 残る。CC は変えない。
        // Gap: GAP-0076 — 単一スタック近似。
        Insn::Chmk | Insn::Chme | Insn::Chms | Insn::Chmu => {
            let req = match f.insn {
                Insn::Chmk => 0,
                Insn::Chme => 1,
                Insn::Chms => 2,
                _ => 3,
            };
            let s = eval(b, f, pos, 0)?;
            let code = read(b, &s, Width::W)?;
            let cur = cur_mod(b);
            push(b, (sext_w(code, Width::W) as u32).into())?;
            let p = psl_get(b);
            let p = p & !(0x3 << psl::PRV_MOD | 0x3 << psl::CUR_MOD)
                | cur << psl::PRV_MOD
                | req.min(cur) << psl::CUR_MOD;
            psl_put(b, p);
            return Err(trap(scb::CHMK + 4 * req));
        }
        _ => return Err(InterpExit::Unimplemented(format!("{:?}", f.insn))),
    }
    Ok(())
}
