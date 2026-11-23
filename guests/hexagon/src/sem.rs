// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Hexagon の命令意味論。
//!
//! 具体値インタプリタ（`InterpBackend`）上で動く。HX4 は代表語彙
//! （nop・add/mov・load/store・jump/call/jumpr/callr・制御レジスタ
//! 転送・cmp 系・trap0）と全 duplex subinsn の意味論を持つ
//! （frame 系の deallocframe/dealloc_return/allocframe は HX7）。
//! 書き込みはパケット未確定域（pkt_*）に溜め、フェッチ層が
//! パケット終端で `commit` する（`.new` オペランドはこの一時値を
//! `r_new`/`p_new` で読む）。
//! Ref: SPEC-HEXAGON-PRM (V79).

use polyisa_engine::interp::{Ctrl, InterpBackend, InterpExit};
use polyisa_mem::{Access, AccessKind, Align, Endian};
use polyisa_sem::{Backend as _, StateRef, W8, W16, W32, W64};

use crate::{CpuState, Insn, cnum, extract_ops, packet};

/// `handle_trap` に渡る内部番号。trap0 の即値は 0-63 なので、
/// ぶつからない値を不正命令用に取る。
pub const TRAP_ILL: u64 = u64::MAX;

fn trap(code: u64) -> InterpExit {
    InterpExit::Exception(polyisa_sem::GuestException {
        kind: polyisa_sem::ExceptionKind::Trap,
        code,
        addr: None,
        in_delay_slot: false,
    })
}

/// 符号拡張（`bits` は元の幅）。
fn sext(v: u64, bits: u32) -> u32 {
    let sh = 64 - bits;
    (((v << sh) as i64) >> sh) as u32
}

/// データアクセス属性。整数の load/store は自然整列を要求する
/// （違反は例外）。
/// Ref: SPEC-HEXAGON-PRM (V79) memory access.
const DRD: Access = Access {
    endian: Endian::Le,
    align: Align::Natural,
    kind: AccessKind::DataRead,
};
const DWR: Access = Access {
    endian: Endian::Le,
    align: Align::Natural,
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
pub fn r_ref(i: u32) -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, r) + (i as usize) * 4)
}

/// 汎用レジスタ r_i の値（確定済み）。
#[must_use]
pub fn r_get(b: &InterpBackend, i: u32) -> u32 {
    get32(b, r_ref(i))
}

/// 汎用レジスタ r_i への代入（確定済み値の書き込み）。
pub fn r_set(b: &mut InterpBackend, i: u32, v: u32) {
    set32(b, r_ref(i), v);
}

/// 述語レジスタ P3:0 の面。
#[must_use]
pub fn p_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, p))
}

/// 述語レジスタ p_i の 8 ビット値。
#[must_use]
pub fn p_get(b: &InterpBackend, i: u32) -> u8 {
    (get32(b, p_ref()) >> (i * 8)) as u8
}

/// 述語 p_i への 8 ビット値の代入。
pub fn p_set(b: &mut InterpBackend, i: u32, v: u8) {
    let p = (get32(b, p_ref()) & !(0xff << (i * 8))) | (u32::from(v) << (i * 8));
    set32(b, p_ref(), p);
}

/// 述語 p_i の条件判定（LSB を見る。0xff/0x00 の比較結果と
/// バイト単位の値の両方で成り立つ）。
#[must_use]
pub fn pred(b: &InterpBackend, i: u32) -> bool {
    p_get(b, i) & 1 != 0
}

/// プログラムカウンタの面。
#[must_use]
pub fn pc_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, pc))
}

/// USR の面。
#[must_use]
pub fn usr_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, usr))
}

/// HW スレッド状態（hwt）の面。割り当ては `threads::hwt`。
/// Ref: SPEC-HEXAGON-PRM (V79) hardware threads.
#[must_use]
pub fn hwt_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, hwt))
}

/// 制御レジスタ番号 → CpuState 面。ユーザ可視分だけを持つ
/// （UPCYCLE/FRAMELIMIT/FRAMEKEY/PKTCOUNT/UTIMER 等の残りは
/// 後段の段階で拡張する）。
fn c_ref(i: u64) -> Option<StateRef<W32>> {
    use core::mem::offset_of as off;
    let a = u8::try_from(i).ok()?;
    let off = match a {
        cnum::SA0 => off!(CpuState, sa0),
        cnum::LC0 => off!(CpuState, lc0),
        cnum::SA1 => off!(CpuState, sa1),
        cnum::LC1 => off!(CpuState, lc1),
        cnum::P3_0 => off!(CpuState, p),
        cnum::M0 => off!(CpuState, m0),
        cnum::M1 => off!(CpuState, m1),
        cnum::USR => off!(CpuState, usr),
        cnum::PC => off!(CpuState, pc),
        cnum::UGP => off!(CpuState, ugp),
        cnum::GP => off!(CpuState, gp),
        cnum::CS0 => off!(CpuState, cs0),
        cnum::CS1 => off!(CpuState, cs1),
        _ => return None,
    };
    Some(StateRef::<W32>::from_offset(off))
}

/// 制御レジスタ c_i の値。未収録の番号は不正。
pub fn c_get(b: &InterpBackend, i: u64) -> Result<u32, InterpExit> {
    match c_ref(i) {
        Some(r) => Ok(get32(b, r)),
        None => Err(trap(TRAP_ILL)),
    }
}

/// 制御レジスタ c_i への代入。PC は書き込み不可（読み取り専用）。
pub fn c_set(b: &mut InterpBackend, i: u64, v: u32) -> Result<(), InterpExit> {
    if i == u64::from(cnum::PC) {
        return Err(trap(TRAP_ILL));
    }
    match c_ref(i) {
        Some(r) => {
            set32(b, r, v);
            Ok(())
        }
        None => Err(trap(TRAP_ILL)),
    }
}

// ---- パケットの未確定域（pkt_*） ----

fn pkt_r_ref(i: u32) -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, pkt_r) + (i as usize) * 4)
}

fn pkt_r_ok_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, pkt_r_ok))
}

fn pkt_p_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, pkt_p))
}

fn pkt_p_ok_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, pkt_p_ok))
}

fn pkt_prod_ref(pos: u32) -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, pkt_prod) + (pos as usize) * 4)
}

fn nv_pos_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, nv_pos))
}

// ---- HX9: HVX の状態アクセス ----
// ベクトル幅は V73 系の 128B 固定（u32 32 ワード）。
const VL: usize = 32;

fn v_lane(i: u32, j: usize) -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, v) + i as usize * (VL * 4) + j * 4)
}

fn pkt_v_lane(i: u32, j: usize) -> StateRef<W32> {
    StateRef::<W32>::from_offset(
        core::mem::offset_of!(CpuState, pkt_v) + i as usize * (VL * 4) + j * 4,
    )
}

fn pkt_vok_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, pkt_v_ok))
}

fn pkt_qok_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, pkt_q_ok))
}

fn vcsr_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, vcsr))
}

/// ベクトルレジスタ v_i の確定値（パケット開始時の値）。
fn v_get(b: &InterpBackend, i: u32) -> [u32; VL] {
    let mut a = [0u32; VL];
    for (j, w) in a.iter_mut().enumerate() {
        *w = get32(b, v_lane(i, j));
    }
    a
}

/// ベクトル述語 q_i（要素ごとの真偽ビット、128 ビット）。
fn q_get(b: &InterpBackend, i: u32) -> u128 {
    let off = core::mem::offset_of!(CpuState, q) + i as usize * 16;
    u128::from_le_bytes(b.state[off..off + 16].try_into().expect("q"))
}

/// ベクトルレジスタへの書き込み（pkt_r と同様に未確定域へ
/// 溜めて commit で確定する）。
fn pkt_vw(b: &mut InterpBackend, i: u32, a: &[u32; VL]) {
    for (j, w) in a.iter().enumerate() {
        set32(b, pkt_v_lane(i, j), *w);
    }
    set32(b, pkt_vok_ref(), get32(b, pkt_vok_ref()) | (1 << i));
}

/// ベクトル述語への書き込み。
fn pkt_qw(b: &mut InterpBackend, i: u32, a: u128) {
    let off = core::mem::offset_of!(CpuState, pkt_q) + i as usize * 16;
    b.state[off..off + 16].copy_from_slice(&a.to_le_bytes());
    set32(b, pkt_qok_ref(), get32(b, pkt_qok_ref()) | (1 << i));
}

/// `el` バイト要素の i 番目を符号拡張して取り出す。
fn vel(a: &[u32; VL], el: usize, i: usize) -> i64 {
    let b8 = el * 8;
    let x = (u64::from(a[i * el / 4]) >> ((i * el) % 4 * 8)) & ((1 << b8) - 1);
    ((x << (64 - b8)) as i64) >> (64 - b8)
}

/// `el` バイト要素の i 番目をゼロ拡張で取り出す。
fn velu(a: &[u32; VL], el: usize, i: usize) -> i64 {
    let b8 = el * 8;
    ((u64::from(a[i * el / 4]) >> ((i * el) % 4 * 8)) & ((1 << b8) - 1)) as i64
}

/// ベクトル要素 i へ `el` バイトで書き戻す。
fn vset(a: &mut [u32; VL], el: usize, i: usize, x: u64) {
    let b8 = el * 8;
    let sh = ((i * el) % 4) * 8;
    let m = if b8 >= 32 { u32::MAX } else { (1u32 << b8) - 1 };
    let w = i * el / 4;
    a[w] = (a[w] & !(m << sh)) | (((x as u32) & m) << sh);
}

/// スロット命令の r_i への書き込み。パケット終端の commit まで
/// 確定値（r）には反映されない。同じパケット内位置の最初の
/// 書き込みは `.new` ストア値の生産者として pkt_prod に記録
/// する。
pub fn pkt_w(b: &mut InterpBackend, i: u32, v: u32) {
    set32(b, pkt_r_ref(i), v);
    set32(b, pkt_r_ok_ref(), get32(b, pkt_r_ok_ref()) | (1 << i));
    let pos = get32(b, nv_pos_ref());
    if pos < 4 && get32(b, pkt_prod_ref(pos)) & 0x20 == 0 {
        set32(b, pkt_prod_ref(pos), i | 0x20);
    }
}

/// スロット命令の p_i への書き込み（8 ビット値）。
pub fn pkt_pw(b: &mut InterpBackend, i: u32, v: u8) {
    let p = (get32(b, pkt_p_ref()) & !(0xff << (i * 8))) | (u32::from(v) << (i * 8));
    set32(b, pkt_p_ref(), p);
    set32(b, pkt_p_ok_ref(), get32(b, pkt_p_ok_ref()) | (1 << i));
}

/// `.new` オペランドが読むパケット内の一時値。パケット内で
/// 生産済みならその値、なければ None。
#[must_use]
pub fn r_new(b: &InterpBackend, i: u32) -> Option<u32> {
    if get32(b, pkt_r_ok_ref()) >> i & 1 != 0 {
        Some(get32(b, pkt_r_ref(i)))
    } else {
        None
    }
}

/// `.new` 述語（pX.new）。パケット内で生産済みならその値。
#[must_use]
pub fn p_new(b: &InterpBackend, i: u32) -> Option<bool> {
    if get32(b, pkt_p_ok_ref()) >> i & 1 != 0 {
        Some(((get32(b, pkt_p_ref()) >> (i * 8)) as u8) & 1 != 0)
    } else {
        None
    }
}

/// `.new` ストア値（`memXX(...) = Rt.new`）のソース。`pos` は
/// 消費命令のパケット内位置、`nt` はエンコードされた生産距離。
/// 生産命令の最初の gpr 書き込みの未確定値を返す。距離が
/// 無効、生産命令が gpr を書かない、書き込みが未確定域に
/// ないときは illegal。
/// Ref: SPEC-HEXAGON-PRM (V79) new-value stores.
fn nv_src(b: &InterpBackend, pos: u32, nt: u64) -> Result<u32, InterpExit> {
    if nt == 0 || nt > u64::from(pos) {
        return Err(trap(TRAP_ILL));
    }
    let e = get32(b, pkt_prod_ref(pos - nt as u32));
    if e & 0x20 == 0 {
        return Err(trap(TRAP_ILL));
    }
    r_new(b, e & 0x1f).ok_or_else(|| trap(TRAP_ILL))
}

/// 現在のパケットがハードウェアループの終端かを保持する面
/// （bit0 = endloop0、bit1 = endloop1）。commit が LC 減算と
/// SA 復帰を行う。
#[must_use]
pub fn endloop_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, endloop))
}

/// 未確定域を捨てる（命令の失敗・illegal パケットで残った
/// 一時値を消す）。
pub fn pkt_clear(b: &mut InterpBackend) {
    set32(b, pkt_r_ok_ref(), 0);
    set32(b, pkt_p_ok_ref(), 0);
    set32(b, pkt_vok_ref(), 0);
    set32(b, pkt_qok_ref(), 0);
    for i in 0..4 {
        set32(b, pkt_prod_ref(i), 0);
    }
}

/// パケットの終わりで書き込みをまとめて反映する。pkt_*_ok の
/// ビットが立つ器だけ確定値へコピーし、未確定域をクリアする。
/// パケットがハードウェアループ終端（endloopN 標識）なら、
/// 対応する LC を検査して `if (LCn > 1) { LCn--; PC = SAn }`
/// を行い、戻り先アドレスを返す（なければ None）。LC<=1 の
/// 終端では減算せず次のパケットへ進む（ループ本体は回数
/// にかかわらず最低 1 回実行される）。両マーカのとき内側の
/// loop0 を先に検査する（loop0 が内側、loop1 が外側）。
/// Ref: SPEC-HEXAGON-PRM (V79) hardware loops.
pub fn commit(b: &mut InterpBackend) -> Result<Option<u32>, InterpExit> {
    let ok = get32(b, pkt_r_ok_ref());
    for i in 0..32 {
        if ok >> i & 1 != 0 {
            r_set(b, i, get32(b, pkt_r_ref(i)));
        }
    }
    set32(b, pkt_r_ok_ref(), 0);
    let pok = get32(b, pkt_p_ok_ref());
    if pok != 0 {
        let mut p = get32(b, p_ref());
        let pn = get32(b, pkt_p_ref());
        for i in 0..4 {
            if pok >> i & 1 != 0 {
                p = (p & !(0xff << (i * 8))) | (pn & 0xff << (i * 8));
            }
        }
        set32(b, p_ref(), p);
    }
    set32(b, pkt_p_ok_ref(), 0);
    // HX9: v/q の未確定域も確定値へコピーする。
    let vok = get32(b, pkt_vok_ref());
    if vok != 0 {
        let v0 = core::mem::offset_of!(CpuState, v);
        let p0 = core::mem::offset_of!(CpuState, pkt_v);
        for i in 0..32usize {
            if vok & (1 << i) != 0 {
                b.state
                    .copy_within(p0 + i * VL * 4..p0 + i * VL * 4 + VL * 4, v0 + i * VL * 4);
            }
        }
    }
    set32(b, pkt_vok_ref(), 0);
    let qok = get32(b, pkt_qok_ref());
    if qok != 0 {
        let q0 = core::mem::offset_of!(CpuState, q);
        let p0 = core::mem::offset_of!(CpuState, pkt_q);
        for i in 0..4usize {
            if qok & (1 << i) != 0 {
                b.state
                    .copy_within(p0 + i * 16..p0 + i * 16 + 16, q0 + i * 16);
            }
        }
    }
    set32(b, pkt_qok_ref(), 0);
    for i in 0..4 {
        set32(b, pkt_prod_ref(i), 0);
    }
    // ハードウェアループ終端の処理。endloop0 標識では LC0 を、
    // endloop1 標識では LC1 を検査する。内側 loop0 を先に評価
    // し、残りがあれば減算して SA への戻り先を返す。
    let el = get32(b, endloop_ref());
    if el & 1 != 0 {
        let lc = c_get(b, u64::from(cnum::LC0))?;
        if lc > 1 {
            c_set(b, u64::from(cnum::LC0), lc - 1)?;
            return Ok(Some(c_get(b, u64::from(cnum::SA0))?));
        }
    }
    if el & 2 != 0 {
        let lc = c_get(b, u64::from(cnum::LC1))?;
        if lc > 1 {
            c_set(b, u64::from(cnum::LC1), lc - 1)?;
            return Ok(Some(c_get(b, u64::from(cnum::SA1))?));
        }
    }
    Ok(None)
}

/// dot-if 修飾の述語条件。呼び出し側（フェッチ層）が命令語の
/// 述語選択桁から解釈して渡す。条件が偽なら意味論を実行しない
/// （qp 抑制に相当）。
#[derive(Clone, Copy, Debug)]
pub struct DotIf {
    /// 述語番号（p0-p3）。
    pub p: u8,
    /// 否定形（`if (!pX)`）。
    pub neg: bool,
    /// `.new` 条件（同一パケット内の一時値を読む）。
    pub new: bool,
}

/// 1 命令ぶんの実行文脈。フェッチ層がパケットから組み立てる。
#[derive(Clone, Copy, Debug, Default)]
pub struct Ctx {
    /// dot-if 修飾（なければ無条件）。
    pub cond: Option<DotIf>,
    /// 直前の constant extender が供給した 26 ビット即値。
    pub ext: Option<u32>,
    /// 現在のパケットの先頭アドレス（PC 相対の基底。extender 語を
    /// 含むパケット先頭）。
    pub pc: u32,
    /// 次のパケットのアドレス（call 系のリンク値）。
    pub next: u32,
    /// パケット内位置（pkt_prod の索引。`.new` ストア値の生産
    /// 距離 Nt の基準点）。
    pub pos: u32,
    /// dual jump で先に分岐が確定した（Section 9.7: 2 個目の
    /// 分岐命令はまるごと無視される。call の LR 更新・frame の
    /// 復帰・pred 書き込みもしない）。
    pub masked: bool,
}

/// extender 併合済みの即値。`raw` は extract_ops の値（zfill
/// 済みなら `shift` で生の桁値へ戻す）、`bits` は非拡張時の
/// 符号拡張幅。
/// Ref: SPEC-HEXAGON-PRM (V79) Section 10.9.
fn ximm(ext: Option<u32>, raw: u64, shift: u32, bits: u32) -> u32 {
    match ext {
        Some(e) => packet::apply_ext(e, (raw >> shift) as u32 & 0x3f),
        None => sext(raw, bits),
    }
}

// ---- HX6: ロード/ストアの共用ヘルパ ----

/// sz3 のバイト数 log2（ロード 0-4,6・ストア 0,2,3,4,6 で共通。
/// 0=b/ub 1=h/uh 2=w 3=d）。フィールド値ではなく実サイズの表。
fn sc3(sz: u64) -> u32 {
    match sz {
        0 | 1 => 0,
        2 | 3 => 1,
        4 => 2,
        6 => 3,
        _ => 0,
    }
}

/// sz2/sz2i/sz2r のバイト数 log2（0=b 1=h 2=w で値そのもの）。
fn sc2(sz: u64) -> u32 {
    (sz as u32) & 3
}

/// 符号付きスケール即値。拡張時は apply_ext の生値（バイト
/// オフセットそのもの）、非拡張時は `符号拡張(bits) << scale`。
fn offi(cx: &Ctx, raw: u64, bits: u32, scale: u32) -> u32 {
    match cx.ext {
        Some(e) => packet::apply_ext(e, raw as u32 & 0x3f),
        None => sext(raw, bits) << scale,
    }
}

/// 符号なしスケール即値（GP 相対・u6 オフセット・abs）。
fn offu(cx: &Ctx, raw: u64, scale: u32) -> u32 {
    match cx.ext {
        Some(e) => packet::apply_ext(e, raw as u32 & 0x3f),
        None => (raw as u32) << scale,
    }
}

/// M 修飾レジスタの値（mu1: 0=m0, 1=m1）。
fn mu(b: &InterpBackend, sel: u64) -> u32 {
    get32(b, c_ref(u64::from(cnum::M0) + sel).expect("m"))
}

/// 円環バッファ開始レジスタの値（mu 選択に追随する cs0/cs1）。
fn cs(b: &InterpBackend, sel: u64) -> u32 {
    get32(b, c_ref(u64::from(cnum::CS0) + sel).expect("cs"))
}

/// Mu の I フィールド（bits{31:28}=I[10:7] + bits{23:17}=I[6:0]
/// の 10 ビット符号なし。`Rx++I:circ(Mu)` の増分量）。
/// Ref: SPEC-HEXAGON-PRM (V79) modifier registers.
fn mu_i(b: &InterpBackend, sel: u64) -> u32 {
    let m = mu(b, sel);
    ((m >> 17) & 0x7f) | ((m >> 21) & 0x780)
}

/// circ_add: 円環バッファ内で rx + inc を折り返す。境界は
/// [cs, cs+length)。length=0 は折り返しなし。inc が length を
/// 超える入力も剰余で収める。
/// Ref: SPEC-HEXAGON-PRM (V79) circular addressing.
fn circ_add(b: &InterpBackend, rx: u32, inc: u32, sel: u64) -> u32 {
    let len = i64::from(mu(b, sel) & 0x1_ffff);
    let n = rx.wrapping_add(inc) as i64;
    if len == 0 {
        return n as u32;
    }
    let lo = i64::from(cs(b, sel));
    (lo + (n - lo).rem_euclid(len)) as u32
}

/// brev EA の下位 16 ビットのビット反転。
/// `EA = Rx.H + bit_reverse(Rx.L)`。
fn brev16(v: u32) -> u32 {
    u32::from((v as u16).reverse_bits())
}

// ---- HX9: HVX の意味論ヘルパ ----

/// vmem ロード。整列形（aligned=true）は ea がベクトル幅の
/// 倍数でないと illegal。vmemu 非整列形は任意アドレス。
fn v_ld(b: &mut InterpBackend, d: u32, ea: u32, aligned: bool) -> Result<(), InterpExit> {
    if aligned && ea & (VL as u32 * 4 - 1) != 0 {
        return Err(trap(TRAP_ILL));
    }
    let mut a = [0u32; VL];
    if aligned {
        for (j, w) in a.iter_mut().enumerate() {
            *w = b.load::<W32>(u64::from(ea.wrapping_add(j as u32 * 4)), DRD)?;
        }
    } else {
        // vmemu: バイト単位で集める（基底が非整列でもよい）。
        for j in 0..VL * 4 {
            let x = b.load::<W8>(u64::from(ea.wrapping_add(j as u32)), DRD)?;
            vset(&mut a, 1, j, u64::from(x));
        }
    }
    pkt_vw(b, d, &a);
    Ok(())
}

/// vmem ストア。`mask` はバイトごとの書き込み可否（述語
/// マスク付きストア。q のビット j がバイト j に対応する）。
fn v_st(
    b: &mut InterpBackend,
    ea: u32,
    s: u32,
    aligned: bool,
    mask: Option<u128>,
) -> Result<(), InterpExit> {
    if aligned && ea & (VL as u32 * 4 - 1) != 0 {
        return Err(trap(TRAP_ILL));
    }
    let a = v_get(b, s);
    match mask {
        Some(m) => {
            for j in 0..VL * 4 {
                if m >> j & 1 != 0 {
                    let x = (a[j / 4] >> (j % 4 * 8)) as u8;
                    b.store::<W8>(u64::from(ea.wrapping_add(j as u32)), x, DWR)?;
                }
            }
        }
        None if aligned => {
            for (j, w) in a.iter().enumerate() {
                b.store::<W32>(u64::from(ea.wrapping_add(j as u32 * 4)), *w, DWR)?;
            }
        }
        None => {
            // vmemu: バイト単位で書く。
            for j in 0..VL * 4 {
                let x = (a[j / 4] >> (j % 4 * 8)) as u8;
                b.store::<W8>(u64::from(ea.wrapping_add(j as u32)), x, DWR)?;
            }
        }
    }
    Ok(())
}

/// 二項のベクトル要素演算（`el` バイト要素、2 ソース）。
fn vop3(
    b: &mut InterpBackend,
    d: u32,
    u: u32,
    v: u32,
    el: usize,
    signed: bool,
    f: impl Fn(i64, i64) -> i64,
) {
    let a = v_get(b, u);
    let c = v_get(b, v);
    let mut r = [0u32; VL];
    for i in 0..VL * 4 / el {
        let (x, y) = if signed {
            (vel(&a, el, i), vel(&c, el, i))
        } else {
            (velu(&a, el, i), velu(&c, el, i))
        };
        vset(&mut r, el, i, f(x, y) as u64);
    }
    pkt_vw(b, d, &r);
}

/// 最小・最大（is_min=true が vmin）。
fn vminmax(b: &mut InterpBackend, d: u32, u: u32, v: u32, el: usize, signed: bool, is_min: bool) {
    vop3(b, d, u, v, el, signed, |x, y| {
        if is_min == (x < y) { x } else { y }
    });
}

/// 飽和加減算。飽和した要素があれば vcsr の sticky ビット
/// （bit0）を立てる。
fn vsat(b: &mut InterpBackend, d: u32, u: u32, v: u32, el: usize, signed: bool, sub: bool) {
    let b8 = (el * 8) as u32;
    let (lo, hi) = if signed {
        (-(1i64 << (b8 - 1)), (1i64 << (b8 - 1)) - 1)
    } else {
        (0i64, (1i64 << b8) - 1)
    };
    let a = v_get(b, u);
    let c = v_get(b, v);
    let mut r = [0u32; VL];
    let mut sat = false;
    for i in 0..VL * 4 / el {
        let (x, y) = if signed {
            (vel(&a, el, i), vel(&c, el, i))
        } else {
            (velu(&a, el, i), velu(&c, el, i))
        };
        let n = if sub { x - y } else { x + y };
        let c2 = n.clamp(lo, hi);
        sat |= c2 != n;
        vset(&mut r, el, i, c2 as u64);
    }
    if sat {
        // Gap: GAP-0071
        // vcsr は未確定域を経由しない（棄却パケットでも残る）。
        set32(b, vcsr_ref(), get32(b, vcsr_ref()) | 1);
    }
    pkt_vw(b, d, &r);
}

/// ペア出力の乗算（`ie` バイト要素 → 2*ie バイト要素。偶数側
/// に下位要素群）。`acc` は += 累積形（dd の現値に加算）。
fn vmpy(b: &mut InterpBackend, dd: u32, u: u32, v: u32, ie: usize, signed: bool, acc: bool) {
    let a = v_get(b, u);
    let c = v_get(b, v);
    let oe = ie * 2;
    let epv = VL * 4 / oe;
    let mut lo = v_get(b, dd);
    let mut hi = v_get(b, dd + 1);
    for i in 0..VL * 4 / ie {
        let p = if signed {
            vel(&a, ie, i).wrapping_mul(vel(&c, ie, i))
        } else {
            (velu(&a, ie, i) as u64).wrapping_mul(velu(&c, ie, i) as u64) as i64
        };
        let j = i % epv;
        let old = if acc {
            if i < epv {
                velu(&lo, oe, j)
            } else {
                velu(&hi, oe, j)
            }
        } else {
            0
        };
        let n = old.wrapping_add(p);
        if i < epv {
            vset(&mut lo, oe, j, n as u64);
        } else {
            vset(&mut hi, oe, j, n as u64);
        }
    }
    pkt_vw(b, dd, &lo);
    pkt_vw(b, dd + 1, &hi);
}

/// vcmp 系（`el` バイト要素ごとの比較結果を q の対応要素幅
/// ビット群に立てる。gt は符号付き）。
fn vcmp(b: &mut InterpBackend, qd: u32, u: u32, v: u32, el: usize, gt: bool) {
    let a = v_get(b, u);
    let c = v_get(b, v);
    let mut q: u128 = 0;
    for i in 0..VL * 4 / el {
        let hit = if gt {
            vel(&a, el, i) > vel(&c, el, i)
        } else {
            velu(&a, el, i) == velu(&c, el, i)
        };
        if hit {
            // 要素 i は `el` バイト分の q ビット（位置 i*el）を
            // 占有する。.b なら 1 要素 1 ビット、.w なら 4。
            q |= ((1u128 << el) - 1) << (i * el);
        }
    }
    pkt_qw(b, qd, q);
}

/// ロード実行（sz3: 0=memb 1=memub 2=memh 3=memuh 4=memw
/// 6=memd（対レジスタ。偶数側が下位））。
fn do_ld(b: &mut InterpBackend, d: u32, ea: u32, sz: u64) -> Result<(), InterpExit> {
    let ea = u64::from(ea);
    match sz {
        0 => {
            let v = sext(u64::from(b.load::<W8>(ea, DRD)?), 8);
            pkt_w(b, d, v);
        }
        1 => {
            let v = u32::from(b.load::<W8>(ea, DRD)?);
            pkt_w(b, d, v);
        }
        2 => {
            let v = sext(u64::from(b.load::<W16>(ea, DRD)?), 16);
            pkt_w(b, d, v);
        }
        3 => {
            let v = u32::from(b.load::<W16>(ea, DRD)?);
            pkt_w(b, d, v);
        }
        4 => {
            let v = b.load::<W32>(ea, DRD)?;
            pkt_w(b, d, v);
        }
        6 => {
            let v = b.load::<W64>(ea, DRD)?;
            pkt_w64(b, d & !1, v);
        }
        _ => return Err(trap(TRAP_ILL)),
    }
    Ok(())
}

/// ストア実行（sz3: 0=memb 2=memh 3=memh（Rt.H 上位半語）
/// 4=memw 6=memd）。
fn do_st(b: &mut InterpBackend, ea: u32, sz: u64, v: u64) -> Result<(), InterpExit> {
    let ea = u64::from(ea);
    match sz {
        0 => b.store::<W8>(ea, v as u8, DWR)?,
        2 => b.store::<W16>(ea, v as u16, DWR)?,
        3 => b.store::<W16>(ea, (v >> 16) as u16, DWR)?,
        4 => b.store::<W32>(ea, v as u32, DWR)?,
        6 => b.store::<W64>(ea, v, DWR)?,
        _ => return Err(trap(TRAP_ILL)),
    }
    Ok(())
}

/// sz2 ストア（ストア即値形・memop・`.new` 値形。0=b 1=h 2=w）。
fn do_st2(b: &mut InterpBackend, ea: u32, sz: u64, v: u64) -> Result<(), InterpExit> {
    let ea = u64::from(ea);
    match sz {
        0 => b.store::<W8>(ea, v as u8, DWR)?,
        1 => b.store::<W16>(ea, v as u16, DWR)?,
        2 => b.store::<W32>(ea, v as u32, DWR)?,
        _ => return Err(trap(TRAP_ILL)),
    }
    Ok(())
}

/// sz2i ロード（memop の RMW 読み側。ゼロ拡張）。
fn do_ld2(b: &mut InterpBackend, ea: u32, sz: u64) -> Result<u32, InterpExit> {
    let ea = u64::from(ea);
    Ok(match sz {
        0 => u32::from(b.load::<W8>(ea, DRD)?),
        1 => u32::from(b.load::<W16>(ea, DRD)?),
        2 => b.load::<W32>(ea, DRD)?,
        _ => return Err(trap(TRAP_ILL)),
    })
}

// ---- HX5: 整数意味論の共用ヘルパ ----

/// 対レジスタの値（偶数側が下位ワード、奇数側が上位ワード）。
fn r64(b: &InterpBackend, i: u32) -> u64 {
    u64::from(r_get(b, i)) | (u64::from(r_get(b, i + 1)) << 32)
}

/// ストア値。sz3=6（memd）のときソースは対レジスタ
/// r(t+1):r(t) の 64 ビット、それ以外は r_t の 32 ビット。
fn st_val(b: &InterpBackend, t: u32, sz: u64) -> u64 {
    if sz == 6 {
        r64(b, t)
    } else {
        u64::from(r_get(b, t))
    }
}

/// 対レジスタへの書き込み（パケット未確定域経由）。
fn pkt_w64(b: &mut InterpBackend, i: u32, v: u64) {
    pkt_w(b, i, v as u32);
    pkt_w(b, i + 1, (v >> 32) as u32);
}

/// USR.OVF（bit0）を立てる。:sat 系・sat 系で飽和が起きた
/// ときに粘着セットする。
fn ovf(b: &mut InterpBackend) {
    set32(b, usr_ref(), get32(b, usr_ref()) | 1);
}

/// 符号 n ビット飽和。クランプしたら USR.OVF を立てて
/// 飽和値を返し、収まれば値のまま返す。
fn satn(b: &mut InterpBackend, v: i64, n: u32) -> u64 {
    let hi = (1i64 << (n - 1)) - 1;
    let lo = -(1i64 << (n - 1));
    let mask = if n >= 64 { u64::MAX } else { (1u64 << n) - 1 };
    if v > hi {
        ovf(b);
        hi as u64
    } else if v < lo {
        ovf(b);
        (lo as u64) & mask
    } else {
        (v as u64) & mask
    }
}

/// 符号 n ビット飽和（USR.OVF を立てない内部用）。
fn satq(v: i64, n: u32) -> u64 {
    let hi = (1i64 << (n - 1)) - 1;
    let lo = -(1i64 << (n - 1));
    v.clamp(lo, hi) as u64
}

/// 符号なし n ビット飽和。クランプしたら USR.OVF を立てる。
fn usatn(b: &mut InterpBackend, v: i64, n: u32) -> u64 {
    let hi = (1i64 << n) - 1;
    if v > hi {
        ovf(b);
        hi as u64
    } else if v < 0 {
        ovf(b);
        0
    } else {
        v as u64
    }
}

/// 32 ビット符号飽和（sat_32）。
fn sat32(b: &mut InterpBackend, v: i64) -> u32 {
    satn(b, v, 32) as u32
}

/// 16 ビット符号飽和（sat_16）。
fn sat16(b: &mut InterpBackend, v: i64) -> u32 {
    satn(b, v, 16) as u32
}

/// 符号拡張 u32 → i64。
fn sx32(v: u32) -> i64 {
    i64::from(v as i32)
}

/// v の i 番目の符号付き半語（h[i]）。
fn sh(v: u32, i: u32) -> i64 {
    i64::from(((v >> (16 * i)) & 0xffff) as u16 as i16)
}

/// v の i 番目の符号なし半語（uh[i]）。
fn uh(v: u32, i: u32) -> i64 {
    i64::from((v >> (16 * i)) & 0xffff)
}

/// HX11: mpy(Rs.{h,l},Rt.{h,l}) 系の共用部。`sh`/`th` は
/// 被乗数・乗数の半語選択（0=.l / 1=.h）。積は符号付きで、
/// 対レジスタ形は符号拡張して 64 ビット、Rd 形は下位 32
/// ビットを書く。
fn mpyh(b: &mut InterpBackend, insn: Insn, ops: &[u64], sh_i: u32, th_i: u32) {
    let s = sh(r_get(b, ops[1] as u32), sh_i);
    let t = sh(r_get(b, ops[2] as u32), th_i);
    let prod = s.wrapping_mul(t) as u64;
    match insn {
        Insn::Mpyll | Insn::Mpylh | Insn::Mpyhl | Insn::Mpyhh => pkt_w64(b, ops[0] as u32, prod),
        Insn::MpyllA | Insn::MpylhA | Insn::MpyhlA | Insn::MpyhhA => {
            pkt_w64(b, ops[0] as u32, r64(b, ops[0] as u32).wrapping_add(prod))
        }
        Insn::MpyllNa | Insn::MpylhNa | Insn::MpyhlNa | Insn::MpyhhNa => {
            pkt_w64(b, ops[0] as u32, r64(b, ops[0] as u32).wrapping_sub(prod))
        }
        _ => pkt_w(b, ops[0] as u32, prod as u32),
    }
}

/// 64 ビット値の i 番目の符号付き半語。
fn sh64(v: u64, i: u32) -> i64 {
    i64::from(((v >> (16 * i)) & 0xffff) as u16 as i16)
}

/// 64 ビット値の i 番目の符号付きバイト。
fn sb64(v: u64, i: u32) -> i64 {
    i64::from(((v >> (8 * i)) & 0xff) as u8 as i8)
}

/// 64 ビット値の i 番目の符号なしバイト。
fn ub64(v: u64, i: u32) -> u64 {
    (v >> (8 * i)) & 0xff
}

/// 64 ビット値の i 番目の符号付きワード。
fn sw64(v: u64, i: u32) -> i64 {
    i64::from(((v >> (32 * i)) & 0xffff_ffff) as u32 as i32)
}

/// 64 ビット値の i 番目の符号なしワード。
fn uw64(v: u64, i: u32) -> u64 {
    (v >> (32 * i)) & 0xffff_ffff
}

/// 4 バイトをまとめて u32 にする。
fn pack4(b0: u64, b1: u64, b2: u64, b3: u64) -> u32 {
    (b0 as u32) | ((b1 as u32) << 8) | ((b2 as u32) << 16) | ((b3 as u32) << 24)
}

/// 述語値（真=0xff、偽=0x00）。
fn pval(v: bool) -> u8 {
    if v { 0xff } else { 0 }
}

/// シフト量（Rt の下位 7 ビットを符号拡張した -64..63）。
fn shamt(t: u32) -> i32 {
    ((t as i32) << 25) >> 25
}

/// 32 ビット asr（shamt>0 は算術右、それ以外は符号拡張しつつ左）。
fn f_asr32(v: u32, sh: i32) -> u32 {
    let x = i64::from(v as i32);
    if sh > 0 {
        (x >> sh.min(63)) as u32
    } else {
        (x << (-sh).min(63)) as u32
    }
}

/// 32 ビット asl（shamt>0 は符号拡張しつつ左、それ以外は算術右）。
fn f_asl32(v: u32, sh: i32) -> u32 {
    f_asr32(v, -sh)
}

/// 32 ビット lsr（shamt>0 は論理右、それ以外は論理左）。
fn f_lsr32(v: u32, sh: i32) -> u32 {
    let x = u64::from(v);
    if sh > 0 {
        (x >> sh.min(63)) as u32
    } else {
        (x << (-sh).min(63)) as u32
    }
}

/// 32 ビット lsl（shamt>0 は論理左、それ以外は論理右）。
fn f_lsl32(v: u32, sh: i32) -> u32 {
    f_lsr32(v, -sh)
}

/// 64 ビット asr（対レジスタ）。
fn f_asr64(v: u64, sh: i32) -> u64 {
    let x = v as i64;
    if sh > 0 {
        (x >> sh.min(63)) as u64
    } else {
        (x << (-sh).min(63)) as u64
    }
}

/// 64 ビット asl（対レジスタ）。
fn f_asl64(v: u64, sh: i32) -> u64 {
    f_asr64(v, -sh)
}

/// 64 ビット lsr（対レジスタ）。
fn f_lsr64(v: u64, sh: i32) -> u64 {
    if sh > 0 {
        v >> sh.min(63)
    } else {
        v << (-sh).min(63)
    }
}

/// 64 ビット lsl（対レジスタ）。
fn f_lsl64(v: u64, sh: i32) -> u64 {
    f_lsr64(v, -sh)
}

/// asr の :rnd（v + 2^(n-1)）>>n の算術シフト。n=0 は v そのまま。
fn f_rnd(v: i64, n: u32) -> i64 {
    if n == 0 {
        v
    } else {
        (v + (1i64 << (n - 1))) >> n
    }
}

/// cround 系の half-to-even 丸め。v を n ビット右へ、半端は偶数側。
fn f_crnd(v: i64, n: u32) -> i64 {
    if n == 0 {
        return v;
    }
    let r = f_rnd(v, n);
    let mask = (1i64 << n) - 1;
    let dropped = v & mask;
    if dropped == (1i64 << (n - 1)) && r & 1 == 1 {
        r - 1
    } else {
        r
    }
}

/// ビット interleave（Rdd = interleave(hi,lo)、out[2i]=lo[i]、
/// out[2i+1]=hi[i]）。
fn f_interleave(v: u64) -> u64 {
    let lo = v & 0xffff_ffff;
    let hi = v >> 32;
    let mut r = 0u64;
    for i in 0..32 {
        r |= ((lo >> i) & 1) << (2 * i);
        r |= ((hi >> i) & 1) << (2 * i + 1);
    }
    r
}

/// ビット deinterleave（偶数ビットを下位ワードに、奇数ビットを
/// 上位ワードに詰める）。
fn f_deinterleave(v: u64) -> u64 {
    let mut lo = 0u64;
    let mut hi = 0u64;
    for i in 0..32 {
        lo |= ((v >> (2 * i)) & 1) << i;
        hi |= ((v >> (2 * i + 1)) & 1) << i;
    }
    (hi << 32) | lo
}

/// duplex subinsn の 4 ビット部分集合符号 → 汎用レジスタ番号
/// （r0-7→0-7、r16-23→8-15）。
/// Ref: SPEC-HEXAGON-PRM (V79) sub-instructions.
fn dxr(c: u64) -> u32 {
    let c = c as u32;
    if c < 8 { c } else { c + 8 }
}

/// duplex subinsn の 3 ビット対レジスタ符号 → 偶数側の番号
/// （R1:0..R7:6→0-3、R17:16..R23:22→4-7）。
fn dxp(c: u64) -> u32 {
    let c = c as u32;
    if c < 4 { 2 * c } else { 2 * c + 8 }
}

/// subinsn のレジスタ符号 `i` の値（確定済み）。
fn dxr_get(b: &InterpBackend, i: u64) -> u32 {
    r_get(b, dxr(i))
}

/// 制御転送を記録する。パケット内の先勝ちはフェッチ層が裁く。
fn jump(b: &mut InterpBackend, target: u32) {
    b.ctrl = Ctrl::Jump(u64::from(target));
}

// ---- HX7: 分岐・frame の共用ヘルパ ----

/// 分岐内部の述語条件（`if ([!]Pu[.new])` qualifier）。真なら
/// 分岐側を実行する。
fn pq(b: &InterpBackend, p: u64, neg: u64, new: bool) -> bool {
    let v = if new {
        p_new(b, p as u32).unwrap_or_else(|| pred(b, p as u32))
    } else {
        pred(b, p as u32)
    };
    v != (neg != 0)
}

/// frame 記録の読み出し。Rs が指す 8 バイトを読み（下位ワードが
/// 保存 FP、上位ワードが保存 LR）、SP を Rs+8 に戻す。返値は
/// {LR,FP} の対（下位=FP、上位=LR）。FRAMEKEY による LR の
/// XOR スクランブルは、ユーザ空間の既定値 0 で省略する。
/// Ref: SPEC-HEXAGON-PRM (V79) software stack.
fn dealloc(b: &mut InterpBackend, s: u32) -> Result<u64, InterpExit> {
    let ea = r_get(b, s);
    let frame = b.load::<W64>(u64::from(ea), DRD)?;
    pkt_w(b, 29, ea.wrapping_add(8));
    Ok(frame)
}

/// deallocframe/dealloc_return の共通部。`dd` は書き込み先の
/// 対レジスタ（偶数側の番号）。`ret` なら復元 LR への分岐を
/// 記録する。
fn dealloc_to(b: &mut InterpBackend, dd: u32, s: u32, ret: bool) -> Result<(), InterpExit> {
    let frame = dealloc(b, s)?;
    pkt_w64(b, dd & !1, frame);
    if ret {
        jump(b, (frame >> 32) as u32);
    }
    Ok(())
}

/// `masked`（dual jump の先勝ち）でまるごと無視される分岐系
/// 命令か。call の LR 書き込み・dealloc_return の frame 復帰・
/// compare-jump の述語書き込みを抑止するために使う。
/// Ref: SPEC-HEXAGON-PRM (V79) Section 9.7.
fn branch_insn(insn: Insn) -> bool {
    matches!(
        insn,
        Insn::JumpPcrel
            | Insn::JumpPq
            | Insn::JumpPqn
            | Insn::CallPcrel
            | Insn::CallPq
            | Insn::Jumpr
            | Insn::JumprPq
            | Insn::JumprPqn
            | Insn::Callr
            | Insn::CallrPq
            | Insn::RcjNe
            | Insn::RcjGe
            | Insn::RcjEq
            | Insn::RcjLe
            | Insn::CjEqi
            | Insn::CjGti
            | Insn::CjGtui
            | Insn::CjEqi1
            | Insn::CjGti1
            | Insn::CjTst
            | Insn::CjEqr
            | Insn::CjGtr
            | Insn::CjGtur
            | Insn::NvjEqr
            | Insn::NvjGtr
            | Insn::NvjGtur
            | Insn::NvjGtrr
            | Insn::NvjGturr
            | Insn::NvjEqi
            | Insn::NvjGti
            | Insn::NvjGtui
            | Insn::NvjTst
            | Insn::NvjEqi1
            | Insn::NvjGti1
            | Insn::TjI
            | Insn::TjR
            | Insn::Deallocret
            | Insn::DeallocretPq
            | Insn::DeallocretPqn
            | Insn::DxL2Jumpr
            | Insn::DxL2Deallocret
    )
}

/// 1 命令ぶんの意味論。`word` は命令語（32 ビット語か 13 ビット
/// subinsn 語）。戻り値は意味論を実行したか（dot-if で抑制された
/// とき false）。
pub fn exec(b: &mut InterpBackend, insn: Insn, word: u128, cx: Ctx) -> Result<bool, InterpExit> {
    if let Some(c) = cx.cond {
        let v = if c.new {
            p_new(b, u32::from(c.p)).unwrap_or_else(|| pred(b, u32::from(c.p)))
        } else {
            pred(b, u32::from(c.p))
        };
        if v == c.neg {
            return Ok(false);
        }
    }
    // dual jump: 先の分岐が成立したあとの分岐命令はまるごと
    // 無視される（LR 更新・frame 復帰・述語書き込みもしない）。
    if cx.masked && branch_insn(insn) {
        return Ok(false);
    }
    set32(b, nv_pos_ref(), cx.pos);
    let ops = extract_ops(insn, word);
    let jump_off = |raw: u64, shift: u32, bits: u32| -> u32 { ximm(cx.ext, raw, shift, bits) };
    match insn {
        // ---- 32 ビット命令 ----
        Insn::Nop => {}
        Insn::AddRi => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[1] as u32).wrapping_add(ximm(cx.ext, ops[2], 0, 16)),
        ),
        Insn::AddRr => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[1] as u32).wrapping_add(r_get(b, ops[2] as u32)),
        ),
        Insn::EqS16 => pkt_w(b, ops[0] as u32, ximm(cx.ext, ops[1], 0, 16)),
        Insn::MovRr => pkt_w(b, ops[0] as u32, r_get(b, ops[1] as u32)),
        Insn::Immlo => {
            let x = ops[0] as u32;
            let v = (r_get(b, x) & 0xffff_0000) | (ximm(cx.ext, ops[1], 0, 16) & 0xffff);
            pkt_w(b, x, v);
        }
        Insn::Immhi => {
            let x = ops[0] as u32;
            let v = (r_get(b, x) & 0xffff) | (ximm(cx.ext, ops[1], 0, 16) << 16);
            pkt_w(b, x, v);
        }
        // ---- HX6: ロード ----
        Insn::LdRi => {
            let ea = r_get(b, ops[1] as u32).wrapping_add(offi(&cx, ops[3], 11, sc3(ops[2])));
            do_ld(b, ops[0] as u32, ea, ops[2])?;
        }
        Insn::LdPi => {
            let ea = r_get(b, ops[1] as u32);
            do_ld(b, ops[0] as u32, ea, ops[2])?;
            pkt_w(
                b,
                ops[1] as u32,
                ea.wrapping_add(offi(&cx, ops[3], 4, sc3(ops[2]))),
            );
        }
        Insn::LdPr => {
            let ea = r_get(b, ops[1] as u32);
            do_ld(b, ops[0] as u32, ea, ops[2])?;
            pkt_w(b, ops[1] as u32, ea.wrapping_add(mu(b, ops[3])));
        }
        Insn::LdPbr => {
            let rx = r_get(b, ops[1] as u32);
            let ea = (rx & 0xffff_0000) | brev16(rx);
            do_ld(b, ops[0] as u32, ea, ops[2])?;
            pkt_w(b, ops[1] as u32, rx.wrapping_add(mu(b, ops[3])));
        }
        Insn::LdPci => {
            let ea = r_get(b, ops[1] as u32);
            do_ld(b, ops[0] as u32, ea, ops[2])?;
            let inc = offi(&cx, ops[4], 4, sc3(ops[2]));
            pkt_w(b, ops[1] as u32, circ_add(b, ea, inc, ops[3]));
        }
        Insn::LdPcr => {
            let ea = r_get(b, ops[1] as u32);
            do_ld(b, ops[0] as u32, ea, ops[2])?;
            let inc = mu_i(b, ops[3]) << sc3(ops[2]);
            pkt_w(b, ops[1] as u32, circ_add(b, ea, inc, ops[3]));
        }
        Insn::LdGp => {
            // 非拡張は gp+#{u16<<scale}、extender 付きは ## 絶対。
            let ea = match cx.ext {
                Some(e) => packet::apply_ext(e, ops[2] as u32 & 0x3f),
                None => get32(b, c_ref(u64::from(cnum::GP)).expect("gp"))
                    .wrapping_add((ops[2] as u32) << sc3(ops[1])),
            };
            do_ld(b, ops[0] as u32, ea, ops[1])?;
        }
        Insn::LdAs => {
            // sa6 は ##imm の下位 6 ビット（バイトアドレスその
            // もの。scale しない）。
            let ea = offu(&cx, ops[3], 0);
            do_ld(b, ops[0] as u32, ea, ops[2])?;
            pkt_w(b, ops[1] as u32, ea);
        }
        Insn::LdSa => {
            let ea = offu(&cx, ops[4], 0).wrapping_add(r_get(b, ops[1] as u32) << ops[3]);
            do_ld(b, ops[0] as u32, ea, ops[2])?;
        }
        Insn::LdRro => {
            let ea = r_get(b, ops[1] as u32).wrapping_add(r_get(b, ops[2] as u32) << ops[4]);
            do_ld(b, ops[0] as u32, ea, ops[3])?;
        }
        Insn::LdPq => {
            let ea = r_get(b, ops[1] as u32).wrapping_add(offu(&cx, ops[3], sc3(ops[2])));
            do_ld(b, ops[0] as u32, ea, ops[2])?;
        }
        Insn::LdPqPi => {
            let ea = r_get(b, ops[1] as u32);
            do_ld(b, ops[0] as u32, ea, ops[2])?;
            pkt_w(
                b,
                ops[1] as u32,
                ea.wrapping_add(offi(&cx, ops[3], 4, sc3(ops[2]))),
            );
        }
        Insn::LdPqRo => {
            let ea = r_get(b, ops[1] as u32).wrapping_add(r_get(b, ops[2] as u32) << ops[4]);
            do_ld(b, ops[0] as u32, ea, ops[3])?;
        }
        Insn::LdPqAbs => {
            // u6a はバイトアドレスそのもの（scale しない）。
            let ea = offu(&cx, ops[2], 0);
            do_ld(b, ops[0] as u32, ea, ops[1])?;
        }
        // ---- HX6: ストア ----
        Insn::StRi => {
            let ea = r_get(b, ops[0] as u32).wrapping_add(offi(&cx, ops[3], 11, sc3(ops[2])));
            do_st(b, ea, ops[2], st_val(b, ops[1] as u32, ops[2]))?;
        }
        Insn::StPi => {
            let ea = r_get(b, ops[0] as u32);
            do_st(b, ea, ops[2], st_val(b, ops[1] as u32, ops[2]))?;
            pkt_w(
                b,
                ops[0] as u32,
                ea.wrapping_add(offi(&cx, ops[3], 4, sc3(ops[2]))),
            );
        }
        Insn::StPr => {
            let ea = r_get(b, ops[0] as u32);
            do_st(b, ea, ops[2], st_val(b, ops[1] as u32, ops[2]))?;
            pkt_w(b, ops[0] as u32, ea.wrapping_add(mu(b, ops[3])));
        }
        Insn::StPbr => {
            let rx = r_get(b, ops[0] as u32);
            let ea = (rx & 0xffff_0000) | brev16(rx);
            do_st(b, ea, ops[2], st_val(b, ops[1] as u32, ops[2]))?;
            pkt_w(b, ops[0] as u32, rx.wrapping_add(mu(b, ops[3])));
        }
        Insn::StPci => {
            let ea = r_get(b, ops[0] as u32);
            do_st(b, ea, ops[2], st_val(b, ops[1] as u32, ops[2]))?;
            let inc = offi(&cx, ops[4], 4, sc3(ops[2]));
            pkt_w(b, ops[0] as u32, circ_add(b, ea, inc, ops[3]));
        }
        Insn::StPcr => {
            let ea = r_get(b, ops[0] as u32);
            do_st(b, ea, ops[2], st_val(b, ops[1] as u32, ops[2]))?;
            let inc = mu_i(b, ops[3]) << sc3(ops[2]);
            pkt_w(b, ops[0] as u32, circ_add(b, ea, inc, ops[3]));
        }
        Insn::StGp => {
            let ea = match cx.ext {
                Some(e) => packet::apply_ext(e, ops[2] as u32 & 0x3f),
                None => get32(b, c_ref(u64::from(cnum::GP)).expect("gp"))
                    .wrapping_add((ops[2] as u32) << sc3(ops[1])),
            };
            do_st(b, ea, ops[1], st_val(b, ops[0] as u32, ops[1]))?;
        }
        Insn::StAs => {
            let ea = offu(&cx, ops[3], 0);
            do_st(b, ea, ops[2], st_val(b, ops[1] as u32, ops[2]))?;
            pkt_w(b, ops[0] as u32, ea);
        }
        Insn::StSa => {
            let ea = offu(&cx, ops[4], 0).wrapping_add(r_get(b, ops[0] as u32) << ops[3]);
            do_st(b, ea, ops[2], st_val(b, ops[1] as u32, ops[2]))?;
        }
        Insn::StRro => {
            let ea = r_get(b, ops[0] as u32).wrapping_add(r_get(b, ops[1] as u32) << ops[4]);
            do_st(b, ea, ops[3], st_val(b, ops[2] as u32, ops[3]))?;
        }
        Insn::StPq => {
            let ea = r_get(b, ops[0] as u32).wrapping_add(offu(&cx, ops[3], sc3(ops[2])));
            do_st(b, ea, ops[2], st_val(b, ops[1] as u32, ops[2]))?;
        }
        Insn::StPqPi => {
            let ea = r_get(b, ops[0] as u32);
            do_st(b, ea, ops[2], st_val(b, ops[1] as u32, ops[2]))?;
            pkt_w(
                b,
                ops[0] as u32,
                ea.wrapping_add(offi(&cx, ops[3], 4, sc3(ops[2]))),
            );
        }
        Insn::StPqRo => {
            let ea = r_get(b, ops[0] as u32).wrapping_add(r_get(b, ops[1] as u32) << ops[4]);
            do_st(b, ea, ops[3], st_val(b, ops[2] as u32, ops[3]))?;
        }
        Insn::StPqAbs => {
            let ea = offu(&cx, ops[2], 0);
            do_st(b, ea, ops[1], st_val(b, ops[0] as u32, ops[1]))?;
        }
        // ---- HX11: LL/SC（memw_locked）----
        Insn::LdLocked => {
            let ea = u64::from(r_get(b, ops[1] as u32));
            let v = b.load_reserved::<W32>(ea, DRD)?;
            pkt_w(b, ops[0] as u32, v);
        }
        Insn::StLocked => {
            let ea = u64::from(r_get(b, ops[0] as u32));
            let ok = b.store_conditional::<W32>(ea, r_get(b, ops[1] as u32), DWR)?;
            pkt_pw(b, ops[2] as u32, u8::from(ok));
        }
        // ---- HX6: ストア即値形・memop ----
        // stiu6 のオフセットは符号なし（#u6:scale）。
        Insn::StI => {
            // ## の extender は値側（si8）にだけ付く。オフセット
            // u6 は非拡張（HX11: musl ldso の `memw(r+#0)=##0x1505`
            // が r+0x1500 に書いていた実測バグ）。
            let ea = r_get(b, ops[0] as u32).wrapping_add((ops[2] as u32) << sc2(ops[1]));
            let v = ximm(cx.ext, ops[3], 0, 8);
            do_st2(b, ea, ops[1], u64::from(v))?;
        }
        Insn::StIp => {
            let ea = r_get(b, ops[0] as u32).wrapping_add((ops[2] as u32) << sc2(ops[1]));
            let v = ximm(cx.ext, ops[3], 0, 6);
            do_st2(b, ea, ops[1], u64::from(v))?;
        }
        Insn::MopI | Insn::MopR => {
            let ea = r_get(b, ops[0] as u32).wrapping_add(offu(&cx, ops[2], sc2(ops[1])));
            let old = do_ld2(b, ea, ops[1])?;
            // 即値形の演算子は {+=, -=, clrbit, setbit}、
            // レジスタ形は {+=, -=, &=, |=}。
            let v = if insn == Insn::MopI {
                // u5 は常に 5 ビット符号なし（extender は
                // アドレスの stiu6 側にだけ併合する）。
                let u = ops[4] as u32;
                match ops[3] {
                    0 => old.wrapping_add(u),
                    1 => old.wrapping_sub(u),
                    2 => old & !(1u32.wrapping_shl(u)),
                    _ => old | 1u32.wrapping_shl(u),
                }
            } else {
                let u = r_get(b, ops[4] as u32);
                match ops[3] {
                    0 => old.wrapping_add(u),
                    1 => old.wrapping_sub(u),
                    2 => old & u,
                    _ => old | u,
                }
            };
            do_st2(b, ea, ops[1], u64::from(v))?;
        }
        // ---- HX6: `.new` ストア値 ----
        Insn::StNt => {
            let v = nv_src(b, cx.pos, ops[3])?;
            let ea = r_get(b, ops[0] as u32).wrapping_add(offi(&cx, ops[4], 11, sc2(ops[2])));
            do_st2(b, ea, ops[2], u64::from(v))?;
        }
        Insn::StPiNt => {
            let v = nv_src(b, cx.pos, ops[3])?;
            let ea = r_get(b, ops[0] as u32);
            do_st2(b, ea, ops[2], u64::from(v))?;
            pkt_w(
                b,
                ops[0] as u32,
                ea.wrapping_add(offi(&cx, ops[4], 4, sc2(ops[2]))),
            );
        }
        Insn::StPrNt => {
            let v = nv_src(b, cx.pos, ops[3])?;
            let ea = r_get(b, ops[0] as u32);
            do_st2(b, ea, ops[2], u64::from(v))?;
            pkt_w(b, ops[0] as u32, ea.wrapping_add(mu(b, ops[4])));
        }
        Insn::StPbrNt => {
            let v = nv_src(b, cx.pos, ops[3])?;
            let rx = r_get(b, ops[0] as u32);
            let ea = (rx & 0xffff_0000) | brev16(rx);
            do_st2(b, ea, ops[2], u64::from(v))?;
            pkt_w(b, ops[0] as u32, rx.wrapping_add(mu(b, ops[4])));
        }
        Insn::StPciNt => {
            let v = nv_src(b, cx.pos, ops[3])?;
            let ea = r_get(b, ops[0] as u32);
            do_st2(b, ea, ops[2], u64::from(v))?;
            let inc = offi(&cx, ops[5], 4, sc2(ops[2]));
            pkt_w(b, ops[0] as u32, circ_add(b, ea, inc, ops[4]));
        }
        Insn::StPcrNt => {
            let v = nv_src(b, cx.pos, ops[3])?;
            let ea = r_get(b, ops[0] as u32);
            do_st2(b, ea, ops[2], u64::from(v))?;
            let inc = mu_i(b, ops[4]) << sc2(ops[2]);
            pkt_w(b, ops[0] as u32, circ_add(b, ea, inc, ops[4]));
        }
        Insn::StGpNt => {
            let v = nv_src(b, cx.pos, ops[2])?;
            let ea = match cx.ext {
                Some(e) => packet::apply_ext(e, ops[3] as u32 & 0x3f),
                None => get32(b, c_ref(u64::from(cnum::GP)).expect("gp"))
                    .wrapping_add((ops[3] as u32) << sc2(ops[1])),
            };
            do_st2(b, ea, ops[1], u64::from(v))?;
        }
        Insn::StPqNt => {
            let v = nv_src(b, cx.pos, ops[3])?;
            let ea = r_get(b, ops[0] as u32).wrapping_add(offu(&cx, ops[4], sc2(ops[2])));
            do_st2(b, ea, ops[2], u64::from(v))?;
        }
        Insn::StPqPiNt => {
            let v = nv_src(b, cx.pos, ops[3])?;
            let ea = r_get(b, ops[0] as u32);
            do_st2(b, ea, ops[2], u64::from(v))?;
            pkt_w(
                b,
                ops[0] as u32,
                ea.wrapping_add(offi(&cx, ops[4], 4, sc2(ops[2]))),
            );
        }
        Insn::StRoNt => {
            let v = nv_src(b, cx.pos, ops[4])?;
            let ea = r_get(b, ops[0] as u32).wrapping_add(r_get(b, ops[1] as u32) << ops[5]);
            do_st2(b, ea, ops[3], u64::from(v))?;
        }
        Insn::StPqRoNt => {
            let v = nv_src(b, cx.pos, ops[4])?;
            let ea = r_get(b, ops[0] as u32).wrapping_add(r_get(b, ops[1] as u32) << ops[5]);
            do_st2(b, ea, ops[3], u64::from(v))?;
        }
        Insn::StPqAbsNt => {
            let v = nv_src(b, cx.pos, ops[2])?;
            let ea = offu(&cx, ops[3], 0);
            do_st2(b, ea, ops[1], u64::from(v))?;
        }
        Insn::JumpPcrel => {
            let off = jump_off(ops[0], 2, 24);
            jump(b, cx.pc.wrapping_add(off));
        }
        Insn::CallPcrel => {
            pkt_w(b, 31, cx.next);
            let off = jump_off(ops[0], 2, 24);
            jump(b, cx.pc.wrapping_add(off));
        }
        Insn::Jumpr => jump(b, r_get(b, ops[0] as u32)),
        Insn::Callr => {
            pkt_w(b, 31, cx.next);
            jump(b, r_get(b, ops[0] as u32));
        }
        Insn::Hintjr => {}
        // pause(#u) は休眠要求を hwt に残すだけで建築状態を
        // 変えない（単スレッド経路では発行モデルが要求を見ない
        // ので no-op と同じ効果）。
        // Ref: SPEC-HEXAGON-PRM (V79) pause.
        Insn::Pause => {
            let h = get32(b, hwt_ref()) & !crate::threads::hwt::TID;
            set32(
                b,
                hwt_ref(),
                h | crate::threads::hwt::PAUSE | ((ops[0] as u32) << crate::threads::hwt::COUNT),
            );
        }
        // barrier/syncht はメモリ順序フェンス。逐次実行の単一
        // エンジンでは建築状態を変えない。
        Insn::Barrier | Insn::Syncht => {}
        // ---- HX7: 述語条件分岐 ----
        // `if ([!]Pu[.new]) jump/call`（ops = target, p, 否定）。
        // :t/:nt の予測桁は建築状態を変えない。
        Insn::JumpPq | Insn::JumpPqn => {
            let new = matches!(insn, Insn::JumpPqn);
            if pq(b, ops[1], ops[2], new) {
                let off = jump_off(ops[0], 2, 17);
                jump(b, cx.pc.wrapping_add(off));
            }
        }
        Insn::CallPq => {
            if pq(b, ops[1], ops[2], false) {
                pkt_w(b, 31, cx.next);
                let off = jump_off(ops[0], 2, 17);
                jump(b, cx.pc.wrapping_add(off));
            }
        }
        Insn::JumprPq | Insn::JumprPqn => {
            let new = matches!(insn, Insn::JumprPqn);
            if pq(b, ops[1], ops[2], new) {
                jump(b, r_get(b, ops[0] as u32));
            }
        }
        Insn::CallrPq => {
            if pq(b, ops[1], ops[2], false) {
                pkt_w(b, 31, cx.next);
                jump(b, r_get(b, ops[0] as u32));
            }
        }
        // `if (Rs {!=,>=,==,<=} #0) jump`（ops = s, target）。
        Insn::RcjNe => {
            if r_get(b, ops[0] as u32) != 0 {
                let off = jump_off(ops[1], 2, 15);
                jump(b, cx.pc.wrapping_add(off));
            }
        }
        Insn::RcjGe => {
            if r_get(b, ops[0] as u32) as i32 >= 0 {
                let off = jump_off(ops[1], 2, 15);
                jump(b, cx.pc.wrapping_add(off));
            }
        }
        Insn::RcjEq => {
            if r_get(b, ops[0] as u32) == 0 {
                let off = jump_off(ops[1], 2, 15);
                jump(b, cx.pc.wrapping_add(off));
            }
        }
        Insn::RcjLe => {
            if r_get(b, ops[0] as u32) as i32 <= 0 {
                let off = jump_off(ops[1], 2, 15);
                jump(b, cx.pc.wrapping_add(off));
            }
        }
        // 複合 compare-jump。比較結果の述語を書き、条件成立で
        // 分岐する（ops = s, 即値, pd, 否定, target）。
        Insn::CjEqi | Insn::CjGti | Insn::CjGtui => {
            // j4/j4t は部分集合符号（r0-7/r16-23）。
            let rs = dxr_get(b, ops[0]);
            let u = ops[1] as u32;
            let v = match insn {
                Insn::CjEqi => rs == u,
                Insn::CjGti => (rs as i32) > (u as i32),
                _ => rs > u,
            };
            pkt_pw(b, ops[2] as u32, pval(v));
            if v != (ops[3] != 0) {
                let off = jump_off(ops[4], 2, 11);
                jump(b, cx.pc.wrapping_add(off));
            }
        }
        // 固定即値形（ops = s, pd, 否定, target）。
        Insn::CjEqi1 | Insn::CjGti1 | Insn::CjTst => {
            let rs = dxr_get(b, ops[0]);
            let v = match insn {
                Insn::CjEqi1 => rs == u32::MAX,
                Insn::CjGti1 => (rs as i32) > -1,
                _ => rs & 1 != 0,
            };
            pkt_pw(b, ops[1] as u32, pval(v));
            if v != (ops[2] != 0) {
                let off = jump_off(ops[3], 2, 11);
                jump(b, cx.pc.wrapping_add(off));
            }
        }
        // レジスタ形（ops = s, t, pd, 否定, target）。
        Insn::CjEqr | Insn::CjGtr | Insn::CjGtur => {
            let rs = dxr_get(b, ops[0]);
            let rt = dxr_get(b, ops[1]);
            let v = match insn {
                Insn::CjEqr => rs == rt,
                Insn::CjGtr => (rs as i32) > (rt as i32),
                _ => rs > rt,
            };
            pkt_pw(b, ops[2] as u32, pval(v));
            if v != (ops[3] != 0) {
                let off = jump_off(ops[4], 2, 11);
                jump(b, cx.pc.wrapping_add(off));
            }
        }
        // new-value compare-jump（ops = nt3, t, 否定, target。
        // nt3 は生産距離の 2 倍）。述語は書かず比較だけで分岐する。
        Insn::NvjEqr
        | Insn::NvjGtr
        | Insn::NvjGtur
        | Insn::NvjGtrr
        | Insn::NvjGturr
        | Insn::NvjEqi
        | Insn::NvjGti
        | Insn::NvjGtui
        | Insn::NvjTst
        | Insn::NvjEqi1
        | Insn::NvjGti1 => {
            let nt3 = ops[0];
            if nt3 == 0 || nt3 & 1 != 0 {
                return Err(trap(TRAP_ILL));
            }
            let ns = nv_src(b, cx.pos, nt3 >> 1)?;
            let t = ops[1] as u32;
            let v = match insn {
                Insn::NvjEqr => ns == r_get(b, t),
                Insn::NvjGtr => (ns as i32) > (r_get(b, t) as i32),
                Insn::NvjGtur => ns > r_get(b, t),
                Insn::NvjGtrr => (r_get(b, t) as i32) > (ns as i32),
                Insn::NvjGturr => r_get(b, t) > ns,
                Insn::NvjEqi => ns == t,
                Insn::NvjGti => (ns as i32) > (t as i32),
                Insn::NvjGtui => ns > t,
                Insn::NvjTst => ns & 1 != 0,
                Insn::NvjEqi1 => ns == u32::MAX,
                _ => (ns as i32) > -1,
            };
            if v != (ops[2] != 0) {
                let off = jump_off(ops[3], 2, 11);
                jump(b, cx.pc.wrapping_add(off));
            }
        }
        // 転送ジャンプ（`Rd=#U6; jump` / `Rd=Rs; jump`）。
        Insn::TjI => {
            pkt_w(b, dxr(ops[0]), ops[1] as u32);
            let off = jump_off(ops[2], 2, 11);
            jump(b, cx.pc.wrapping_add(off));
        }
        Insn::TjR => {
            pkt_w(b, dxr(ops[1]), dxr_get(b, ops[0]));
            let off = jump_off(ops[2], 2, 11);
            jump(b, cx.pc.wrapping_add(off));
        }
        // ---- HX8: ハードウェアループ宣言 ----
        // loopN(start,count): SAn = 宣言パケット先頭 +
        // PC 相対オフセット（extender 併合時も 32 ビット
        // PC 相対のまま。jump と同じ規則）、LCn = U10 即値
        // または Rs。loop0 が内側、loop1 が外側。反復の進行
        // （LC 減算・SA 復帰）は終端パケットの commit が担う。
        // Ref: SPEC-HEXAGON-PRM (V79) hw loops.
        Insn::Loop0i | Insn::Loop1i | Insn::Loop0r | Insn::Loop1r => {
            let sa = cx.pc.wrapping_add(ximm(cx.ext, ops[0], 2, 9));
            let lc = if matches!(insn, Insn::Loop0i | Insn::Loop1i) {
                ops[1] as u32
            } else {
                r_get(b, ops[1] as u32)
            };
            let (s, l) = if matches!(insn, Insn::Loop0i | Insn::Loop0r) {
                (cnum::SA0, cnum::LC0)
            } else {
                (cnum::SA1, cnum::LC1)
            };
            c_set(b, u64::from(s), sa)?;
            c_set(b, u64::from(l), lc)?;
        }
        // frame の構築・解除・復帰。`masked` は冒頭で裁く。
        Insn::Allocframe => {
            let x = ops[0] as u32;
            let frame = ops[1] as u32;
            let ea = r_get(b, x).wrapping_sub(8);
            let pair = u64::from(r_get(b, 30)) | (u64::from(r_get(b, 31)) << 32);
            b.store::<W64>(u64::from(ea), pair, DWR)?;
            pkt_w(b, 30, ea);
            pkt_w(b, x, ea.wrapping_sub(frame));
        }
        Insn::Deallocframe => dealloc_to(b, ops[0] as u32, ops[1] as u32, false)?,
        Insn::Deallocret => dealloc_to(b, ops[0] as u32, ops[1] as u32, true)?,
        Insn::DeallocretPq | Insn::DeallocretPqn => {
            let new = matches!(insn, Insn::DeallocretPqn);
            if pq(b, ops[2], ops[3], new) {
                dealloc_to(b, ops[0] as u32, ops[1] as u32, true)?;
            }
        }
        Insn::Trap0 => return Err(trap(ops[0])),
        // trap1 は monitor 系のトラップ。ユーザモードでは例外と
        // して OS パーソナリティに委ねる（code = 0x100|u で
        // trap0 と区別。trap2 は PRM に存在しない）。
        Insn::Trap1 => return Err(trap(0x100 | ops[1])),
        Insn::Rdcr => pkt_w(b, ops[0] as u32, c_get(b, ops[1])?),
        Insn::Wrcr => c_set(b, ops[0], r_get(b, ops[1] as u32))?,
        Insn::CmpeqRr => {
            let v = r_get(b, ops[1] as u32) == r_get(b, ops[2] as u32);
            pkt_pw(b, ops[0] as u32, if v { 0xff } else { 0 });
        }
        Insn::CmpgtRr => {
            let v = (r_get(b, ops[1] as u32) as i32) > (r_get(b, ops[2] as u32) as i32);
            pkt_pw(b, ops[0] as u32, if v { 0xff } else { 0 });
        }

        // ---- HX5: ALU32 算術・論理 ----
        Insn::AddSatRr => {
            let v = sx32(r_get(b, ops[1] as u32)) + sx32(r_get(b, ops[2] as u32));
            let v = sat32(b, v);
            pkt_w(b, ops[0] as u32, v);
        }
        Insn::AndRr => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[1] as u32) & r_get(b, ops[2] as u32),
        ),
        Insn::AndnRr => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[1] as u32) & !r_get(b, ops[2] as u32),
        ),
        Insn::Andn2Rr => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[2] as u32) & !r_get(b, ops[1] as u32),
        ),
        Insn::OrRr => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[1] as u32) | r_get(b, ops[2] as u32),
        ),
        Insn::OrnRr => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[1] as u32) | !r_get(b, ops[2] as u32),
        ),
        Insn::Orn2Rr => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[2] as u32) | !r_get(b, ops[1] as u32),
        ),
        Insn::XorRr => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[1] as u32) ^ r_get(b, ops[2] as u32),
        ),
        Insn::SubRr => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[2] as u32).wrapping_sub(r_get(b, ops[1] as u32)),
        ),
        Insn::SubSatRr => {
            let v = sx32(r_get(b, ops[2] as u32)) - sx32(r_get(b, ops[1] as u32));
            let v = sat32(b, v);
            pkt_w(b, ops[0] as u32, v);
        }
        Insn::AndRi => {
            let v = r_get(b, ops[1] as u32) & ximm(cx.ext, ops[2], 0, 10);
            pkt_w(b, ops[0] as u32, v);
        }
        Insn::OrRi => {
            let v = r_get(b, ops[1] as u32) | ximm(cx.ext, ops[2], 0, 10);
            pkt_w(b, ops[0] as u32, v);
        }
        Insn::SubIr => {
            let v = ximm(cx.ext, ops[2], 0, 10).wrapping_sub(r_get(b, ops[1] as u32));
            pkt_w(b, ops[0] as u32, v);
        }
        // ---- 符号/ゼロ拡張・半語シフト ----
        Insn::Aslh => {
            let v = r_get(b, ops[1] as u32);
            pkt_w(b, ops[0] as u32, v << 16);
        }
        Insn::Asrh => {
            let v = r_get(b, ops[1] as u32);
            pkt_w(b, ops[0] as u32, ((v as i32) >> 16) as u32);
        }
        Insn::Sxtb => {
            let v = r_get(b, ops[1] as u32);
            pkt_w(b, ops[0] as u32, sext(u64::from(v), 8));
        }
        Insn::Sxth => {
            let v = r_get(b, ops[1] as u32);
            pkt_w(b, ops[0] as u32, sext(u64::from(v), 16));
        }
        Insn::Zxth => {
            let v = r_get(b, ops[1] as u32);
            pkt_w(b, ops[0] as u32, v & 0xffff);
        }
        // ---- 半語ベクトル（32 ビット）----
        Insn::VaddhRr
        | Insn::VaddhSatRr
        | Insn::VadduhSatRr
        | Insn::VavghRr
        | Insn::VavghRndRr
        | Insn::VnavghRr
        | Insn::VsubhRr
        | Insn::VsubhSatRr
        | Insn::VsubuhSatRr => {
            let s = r_get(b, ops[1] as u32);
            let t = r_get(b, ops[2] as u32);
            let mut r = 0u32;
            for i in 0..2 {
                let v = match insn {
                    Insn::VaddhRr => sh(s, i).wrapping_add(sh(t, i)) & 0xffff,
                    Insn::VaddhSatRr => {
                        i64::from(satn(b, sh(s, i) + sh(t, i), 16) as u32 as i32) & 0xffff
                    }
                    Insn::VadduhSatRr => {
                        i64::from(usatn(b, uh(s, i) + uh(t, i), 16) as u32) & 0xffff
                    }
                    Insn::VavghRr => ((sh(s, i) + sh(t, i)) >> 1) & 0xffff,
                    Insn::VavghRndRr => ((sh(s, i) + sh(t, i) + 1) >> 1) & 0xffff,
                    Insn::VnavghRr => ((sh(t, i) - sh(s, i)) >> 1) & 0xffff,
                    Insn::VsubhRr => sh(t, i).wrapping_sub(sh(s, i)) & 0xffff,
                    Insn::VsubhSatRr => {
                        i64::from(satn(b, sh(t, i) - sh(s, i), 16) as u32 as i32) & 0xffff
                    }
                    Insn::VsubuhSatRr => {
                        i64::from(usatn(b, uh(t, i) - uh(s, i), 16) as u32) & 0xffff
                    }
                    _ => unreachable!(),
                };
                r |= ((v as u32) & 0xffff) << (16 * i);
            }
            pkt_w(b, ops[0] as u32, r);
        }
        // ---- combine・packhl・mux ----
        Insn::CombineRr => {
            let v = u64::from(r_get(b, ops[2] as u32)) | (u64::from(r_get(b, ops[1] as u32)) << 32);
            pkt_w64(b, ops[0] as u32, v);
        }
        Insn::CombHh | Insn::CombHl | Insn::CombLh | Insn::CombLl => {
            let s = r_get(b, ops[1] as u32);
            let t = r_get(b, ops[2] as u32);
            let (th, sl) = match insn {
                Insn::CombHh => (t >> 16, s >> 16),
                Insn::CombHl => (t >> 16, s & 0xffff),
                Insn::CombLh => (t & 0xffff, s >> 16),
                _ => (t & 0xffff, s & 0xffff),
            };
            pkt_w(b, ops[0] as u32, (th << 16) | sl);
        }
        Insn::CombRi => {
            let v =
                u64::from(ximm(cx.ext, ops[2], 0, 8)) | (u64::from(r_get(b, ops[1] as u32)) << 32);
            pkt_w64(b, ops[0] as u32, v);
        }
        Insn::CombIr => {
            let v =
                u64::from(r_get(b, ops[1] as u32)) | (u64::from(ximm(cx.ext, ops[2], 0, 8)) << 32);
            pkt_w64(b, ops[0] as u32, v);
        }
        Insn::CombIi => {
            let v = u64::from(ximm(cx.ext, ops[2], 0, 8))
                | (u64::from(ximm(cx.ext, ops[1], 0, 8)) << 32);
            pkt_w64(b, ops[0] as u32, v);
        }
        Insn::CombIu6 => {
            let v = u64::from(ops[2] as u32) | (u64::from(ximm(cx.ext, ops[1], 0, 8)) << 32);
            pkt_w64(b, ops[0] as u32, v);
        }
        Insn::Packhl => {
            let s = r_get(b, ops[1] as u32);
            let t = r_get(b, ops[2] as u32);
            let lo = (t & 0xffff) | ((s & 0xffff) << 16);
            let hi = (t >> 16) | (s & 0xffff_0000);
            pkt_w64(b, ops[0] as u32, (u64::from(hi) << 32) | u64::from(lo));
        }
        // ---- HX11: `if ([!]Pu[.new])` 条件付き ALU ----
        // 条件は exec 冒頭の DotIf が裁く（偽ならここに来ない）。
        Insn::CandRr => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[1] as u32) & r_get(b, ops[2] as u32),
        ),
        Insn::CorRr => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[1] as u32) | r_get(b, ops[2] as u32),
        ),
        Insn::CxorRr => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[1] as u32) ^ r_get(b, ops[2] as u32),
        ),
        Insn::CaddRr => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[1] as u32).wrapping_add(r_get(b, ops[2] as u32)),
        ),
        Insn::CsubRr => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[2] as u32).wrapping_sub(r_get(b, ops[1] as u32)),
        ),
        Insn::CcombRr => {
            let v = u64::from(r_get(b, ops[2] as u32)) | (u64::from(r_get(b, ops[1] as u32)) << 32);
            pkt_w64(b, ops[0] as u32, v);
        }
        Insn::CaddRi => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[1] as u32).wrapping_add(ximm(cx.ext, ops[2], 0, 8)),
        ),
        Insn::CmovI => pkt_w(b, ops[0] as u32, ximm(cx.ext, ops[1], 0, 12)),
        // ---- HX11: mpy 系 ----
        // 半語積（符号付き s16×s16 → s64 で対レジスタへ）。
        Insn::Mpyi => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[1] as u32).wrapping_mul(ximm(cx.ext, ops[2], 0, 8)),
        ),
        Insn::Mpyin => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[1] as u32)
                .wrapping_mul(ximm(cx.ext, ops[2], 0, 8))
                .wrapping_neg(),
        ),
        Insn::Mpyia => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[0] as u32)
                .wrapping_add(r_get(b, ops[1] as u32).wrapping_mul(ximm(cx.ext, ops[2], 0, 8))),
        ),
        Insn::Mpyina => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[0] as u32)
                .wrapping_sub(r_get(b, ops[1] as u32).wrapping_mul(ximm(cx.ext, ops[2], 0, 8))),
        ),
        // Rd = add(#s6,mpyi(Rs,Rt))（複合積和）。
        Insn::AddMpyi => pkt_w(
            b,
            ops[0] as u32,
            ximm(cx.ext, ops[3], 0, 6)
                .wrapping_add(r_get(b, ops[1] as u32).wrapping_mul(r_get(b, ops[2] as u32))),
        ),
        Insn::Mpy => pkt_w64(
            b,
            ops[0] as u32,
            (r_get(b, ops[1] as u32) as i32 as i64)
                .wrapping_mul(r_get(b, ops[2] as u32) as i32 as i64) as u64,
        ),
        Insn::Mpyu => pkt_w64(
            b,
            ops[0] as u32,
            u64::from(r_get(b, ops[1] as u32)) * u64::from(r_get(b, ops[2] as u32)),
        ),
        Insn::MpyA => pkt_w64(
            b,
            ops[0] as u32,
            r64(b, ops[0] as u32).wrapping_add(
                (r_get(b, ops[1] as u32) as i32 as i64)
                    .wrapping_mul(r_get(b, ops[2] as u32) as i32 as i64) as u64,
            ),
        ),
        Insn::MpyNa => pkt_w64(
            b,
            ops[0] as u32,
            r64(b, ops[0] as u32).wrapping_sub(
                (r_get(b, ops[1] as u32) as i32 as i64)
                    .wrapping_mul(r_get(b, ops[2] as u32) as i32 as i64) as u64,
            ),
        ),
        Insn::MpyuA => pkt_w64(
            b,
            ops[0] as u32,
            r64(b, ops[0] as u32).wrapping_add(
                u64::from(r_get(b, ops[1] as u32)) * u64::from(r_get(b, ops[2] as u32)),
            ),
        ),
        Insn::Mpy32 | Insn::MpyiRr => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[1] as u32).wrapping_mul(r_get(b, ops[2] as u32)),
        ),
        // mpyu Rd = 積の上位 32 ビット（musl の除算定数展開
        // `r1 = mpyu(r0,##0xCCCCCCCD); lsr r1,#3` が証拠。
        // mpyi/mpy の Rd 形は下位 32 ビット）。Ref:
        // SPEC-HEXAGON-PRM — ALU32/MULT mpyu。
        Insn::Mpyu32 => pkt_w(
            b,
            ops[0] as u32,
            ((u64::from(r_get(b, ops[1] as u32)) * u64::from(r_get(b, ops[2] as u32))) >> 32)
                as u32,
        ),
        // Rx ±= mpyi(Rs,Rt)（積の下位 32 ビットの累積/減算）。
        Insn::MpyiaRr => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[0] as u32)
                .wrapping_add(r_get(b, ops[1] as u32).wrapping_mul(r_get(b, ops[2] as u32))),
        ),
        Insn::MpyinaRr => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[0] as u32)
                .wrapping_sub(r_get(b, ops[1] as u32).wrapping_mul(r_get(b, ops[2] as u32))),
        ),
        Insn::Mpyll | Insn::MpyllA | Insn::MpyllNa | Insn::Mpy32ll => mpyh(b, insn, &ops, 0, 0),
        Insn::Mpylh | Insn::MpylhA | Insn::MpylhNa | Insn::Mpy32lh => mpyh(b, insn, &ops, 0, 1),
        Insn::Mpyhl | Insn::MpyhlA | Insn::MpyhlNa | Insn::Mpy32hl => mpyh(b, insn, &ops, 1, 0),
        Insn::Mpyhh | Insn::MpyhhA | Insn::MpyhhNa | Insn::Mpy32hh => mpyh(b, insn, &ops, 1, 1),
        Insn::MuxRr => {
            let v = if pred(b, ops[1] as u32) {
                r_get(b, ops[2] as u32)
            } else {
                r_get(b, ops[3] as u32)
            };
            pkt_w(b, ops[0] as u32, v);
        }
        Insn::MuxRi => {
            let v = if pred(b, ops[1] as u32) {
                r_get(b, ops[2] as u32)
            } else {
                ximm(cx.ext, ops[3], 0, 8)
            };
            pkt_w(b, ops[0] as u32, v);
        }
        Insn::MuxIr => {
            let v = if pred(b, ops[1] as u32) {
                ximm(cx.ext, ops[3], 0, 8)
            } else {
                r_get(b, ops[2] as u32)
            };
            pkt_w(b, ops[0] as u32, v);
        }
        Insn::MuxIi => {
            let v = if pred(b, ops[1] as u32) {
                ximm(cx.ext, ops[2], 0, 8)
            } else {
                ximm(cx.ext, ops[3], 0, 8)
            };
            pkt_w(b, ops[0] as u32, v);
        }
        // ---- 比較 → 述語 ----
        Insn::CmpgtuRr => pkt_pw(
            b,
            ops[0] as u32,
            pval(r_get(b, ops[1] as u32) > r_get(b, ops[2] as u32)),
        ),
        Insn::CmpeqnRr => pkt_pw(
            b,
            ops[0] as u32,
            pval(r_get(b, ops[1] as u32) != r_get(b, ops[2] as u32)),
        ),
        Insn::CmpgtnRr => pkt_pw(
            b,
            ops[0] as u32,
            pval((r_get(b, ops[1] as u32) as i32) <= (r_get(b, ops[2] as u32) as i32)),
        ),
        Insn::CmpgtunRr => pkt_pw(
            b,
            ops[0] as u32,
            pval(r_get(b, ops[1] as u32) <= r_get(b, ops[2] as u32)),
        ),
        Insn::CmpeqI => pkt_pw(
            b,
            ops[0] as u32,
            pval(r_get(b, ops[1] as u32) == ximm(cx.ext, ops[2], 0, 10)),
        ),
        Insn::CmpgtI => pkt_pw(
            b,
            ops[0] as u32,
            pval((r_get(b, ops[1] as u32) as i32) > (ximm(cx.ext, ops[2], 0, 10) as i32)),
        ),
        Insn::CmpgtuI => pkt_pw(
            b,
            ops[0] as u32,
            pval(r_get(b, ops[1] as u32) > ximm(cx.ext, ops[2], 0, 9)),
        ),
        Insn::CmpeqnI => pkt_pw(
            b,
            ops[0] as u32,
            pval(r_get(b, ops[1] as u32) != ximm(cx.ext, ops[2], 0, 10)),
        ),
        Insn::CmpgtnI => pkt_pw(
            b,
            ops[0] as u32,
            pval((r_get(b, ops[1] as u32) as i32) <= (ximm(cx.ext, ops[2], 0, 10) as i32)),
        ),
        Insn::CmpgtunI => pkt_pw(
            b,
            ops[0] as u32,
            pval(r_get(b, ops[1] as u32) <= ximm(cx.ext, ops[2], 0, 9)),
        ),
        Insn::CmpeqRdRr => pkt_w(
            b,
            ops[0] as u32,
            u32::from(r_get(b, ops[1] as u32) == r_get(b, ops[2] as u32)),
        ),
        Insn::CmpeqnRdRr => pkt_w(
            b,
            ops[0] as u32,
            u32::from(r_get(b, ops[1] as u32) != r_get(b, ops[2] as u32)),
        ),
        Insn::CmpeqRdI => pkt_w(
            b,
            ops[0] as u32,
            u32::from(r_get(b, ops[1] as u32) == ximm(cx.ext, ops[2], 0, 8)),
        ),
        Insn::CmpeqnRdI => pkt_w(
            b,
            ops[0] as u32,
            u32::from(r_get(b, ops[1] as u32) != ximm(cx.ext, ops[2], 0, 8)),
        ),
        // ---- バイト・半語比較 ----
        Insn::CmpbEq
        | Insn::CmpbGt
        | Insn::CmpbGtu
        | Insn::CmphEq
        | Insn::CmphGt
        | Insn::CmphGtu => {
            let s = r_get(b, ops[1] as u32);
            let t = r_get(b, ops[2] as u32);
            let v = match insn {
                Insn::CmpbEq => s & 0xff == t & 0xff,
                Insn::CmpbGt => (s & 0xff) as u8 as i8 > (t & 0xff) as u8 as i8,
                Insn::CmpbGtu => s & 0xff > t & 0xff,
                Insn::CmphEq => s & 0xffff == t & 0xffff,
                Insn::CmphGt => (s & 0xffff) as u16 as i16 > (t & 0xffff) as u16 as i16,
                _ => s & 0xffff > t & 0xffff,
            };
            pkt_pw(b, ops[0] as u32, pval(v));
        }
        Insn::CmpbEqI
        | Insn::CmpbGtI
        | Insn::CmpbGtuI
        | Insn::CmphEqI
        | Insn::CmphGtI
        | Insn::CmphGtuI => {
            let s = r_get(b, ops[1] as u32);
            let imm8 = ops[2] as u32;
            let v = match insn {
                Insn::CmpbEqI => s & 0xff == imm8 & 0xff,
                Insn::CmpbGtI => (s & 0xff) as u8 as i8 > (sext(ops[2], 8) & 0xff) as u8 as i8,
                Insn::CmpbGtuI => s & 0xff > imm8 & 0x7f,
                Insn::CmphEqI => s & 0xffff == imm8 & 0xffff,
                Insn::CmphGtI => {
                    (s & 0xffff) as u16 as i16 > (sext(ops[2], 8) & 0xffff) as u16 as i16
                }
                _ => s & 0xffff > imm8 & 0x7f,
            };
            pkt_pw(b, ops[0] as u32, pval(v));
        }
        // ---- 述語演算・転送 ----
        Insn::Pand => pkt_pw(
            b,
            ops[0] as u32,
            p_get(b, ops[2] as u32) & p_get(b, ops[1] as u32),
        ),
        Insn::Por => pkt_pw(
            b,
            ops[0] as u32,
            p_get(b, ops[2] as u32) | p_get(b, ops[1] as u32),
        ),
        Insn::Pxor => pkt_pw(
            b,
            ops[0] as u32,
            p_get(b, ops[1] as u32) ^ p_get(b, ops[2] as u32),
        ),
        Insn::Pandn => pkt_pw(
            b,
            ops[0] as u32,
            p_get(b, ops[2] as u32) & !p_get(b, ops[1] as u32),
        ),
        Insn::Porn => pkt_pw(
            b,
            ops[0] as u32,
            p_get(b, ops[2] as u32) | !p_get(b, ops[1] as u32),
        ),
        Insn::Pnot => pkt_pw(b, ops[0] as u32, !p_get(b, ops[1] as u32)),
        Insn::Pfc9 | Insn::Pfc9n => {
            // tmp.h[0]=tmp.h[1]=(Ps<<8)|Pt; 9 回の AND 縮退で
            // 「9 連続ビットが立つか」を検出する。
            let v = ((u64::from(p_get(b, ops[1] as u32)) << 8)
                | u64::from(p_get(b, ops[2] as u32)))
                * 0x1_0001;
            let mut v = v;
            for _ in 1..9 {
                v &= v >> 1;
            }
            pkt_pw(b, ops[0] as u32, pval((v != 0) ^ (insn == Insn::Pfc9n)));
        }
        Insn::Pany8 => pkt_pw(b, ops[0] as u32, pval(p_get(b, ops[1] as u32) != 0)),
        Insn::Pall8 => pkt_pw(b, ops[0] as u32, pval(p_get(b, ops[1] as u32) == 0xff)),
        Insn::PandA
        | Insn::PandO
        | Insn::PorA
        | Insn::PorO
        | Insn::PandAn
        | Insn::PandOn
        | Insn::PorAn
        | Insn::PorOn => {
            let (s, t, u) = (
                p_get(b, ops[1] as u32),
                p_get(b, ops[2] as u32),
                p_get(b, ops[3] as u32),
            );
            let un = matches!(
                insn,
                Insn::PandAn | Insn::PandOn | Insn::PorAn | Insn::PorOn
            );
            let u2 = if un { !u } else { u };
            let inner = if matches!(insn, Insn::PandA | Insn::PandAn | Insn::PorA | Insn::PorAn) {
                t & u2
            } else {
                t | u2
            };
            let outer = if matches!(
                insn,
                Insn::PandA | Insn::PandO | Insn::PandAn | Insn::PandOn
            ) {
                s & inner
            } else {
                s | inner
            };
            pkt_pw(b, ops[0] as u32, outer);
        }
        Insn::RdPs => pkt_w(b, ops[0] as u32, u32::from(p_get(b, ops[1] as u32))),
        Insn::PdRs => pkt_pw(b, ops[0] as u32, r_get(b, ops[1] as u32) as u8),

        // ---- HX5: XTYPE 64 ビット対レジスタ演算 ----
        Insn::Add64 => pkt_w64(
            b,
            ops[0] as u32,
            r64(b, ops[1] as u32).wrapping_add(r64(b, ops[2] as u32)),
        ),
        Insn::Add64Sat => {
            let v = (r64(b, ops[1] as u32) as i64 as i128) + (r64(b, ops[2] as u32) as i64 as i128);
            let v = if v > i64::MAX as i128 {
                ovf(b);
                i64::MAX as u64
            } else if v < i64::MIN as i128 {
                ovf(b);
                i64::MIN as u64
            } else {
                v as u64
            };
            pkt_w64(b, ops[0] as u32, v);
        }
        Insn::Add64RawLo => pkt_w64(
            b,
            ops[0] as u32,
            r64(b, ops[1] as u32).wrapping_add(r64(b, ops[2] as u32)) & 0xffff_ffff,
        ),
        Insn::Add64RawHi => pkt_w64(
            b,
            ops[0] as u32,
            r64(b, ops[1] as u32).wrapping_add(r64(b, ops[2] as u32)) & 0xffff_ffff_0000_0000,
        ),
        Insn::Sub64 => pkt_w64(
            b,
            ops[0] as u32,
            r64(b, ops[2] as u32).wrapping_sub(r64(b, ops[1] as u32)),
        ),
        Insn::And64 => pkt_w64(
            b,
            ops[0] as u32,
            r64(b, ops[1] as u32) & r64(b, ops[2] as u32),
        ),
        Insn::Andn64 => pkt_w64(
            b,
            ops[0] as u32,
            r64(b, ops[2] as u32) & !r64(b, ops[1] as u32),
        ),
        Insn::Or64 => pkt_w64(
            b,
            ops[0] as u32,
            r64(b, ops[1] as u32) | r64(b, ops[2] as u32),
        ),
        Insn::Orn64 => pkt_w64(
            b,
            ops[0] as u32,
            r64(b, ops[2] as u32) | !r64(b, ops[1] as u32),
        ),
        Insn::Xor64 => pkt_w64(
            b,
            ops[0] as u32,
            r64(b, ops[1] as u32) ^ r64(b, ops[2] as u32),
        ),
        Insn::Not64 => pkt_w64(b, ops[0] as u32, !r64(b, ops[1] as u32)),
        Insn::Neg64 => pkt_w64(
            b,
            ops[0] as u32,
            (r64(b, ops[1] as u32) as i64).wrapping_neg() as u64,
        ),
        Insn::Abs64 => {
            let v = r64(b, ops[1] as u32) as i64;
            pkt_w64(b, ops[0] as u32, v.unsigned_abs());
        }
        Insn::Abs => {
            let v = r_get(b, ops[1] as u32) as i32;
            pkt_w(b, ops[0] as u32, v.unsigned_abs());
        }
        Insn::AbsSat | Insn::NegSat => {
            let v = r_get(b, ops[1] as u32) as i32;
            let v = if v == i32::MIN {
                ovf(b);
                i32::MAX
            } else if insn == Insn::AbsSat {
                v.abs()
            } else {
                -v
            };
            pkt_w(b, ops[0] as u32, v as u32);
        }
        Insn::Sxtw => pkt_w64(
            b,
            ops[0] as u32,
            r_get(b, ops[1] as u32) as i32 as i64 as u64,
        ),
        Insn::Modwrap => {
            let s = r_get(b, ops[1] as u32);
            let t = r_get(b, ops[2] as u32);
            let v = if (s as i32) < 0 {
                s.wrapping_add(t)
            } else if s >= t {
                s - t
            } else {
                s
            };
            pkt_w(b, ops[0] as u32, v);
        }
        // ---- キャリー付き加減算 ----
        Insn::AddCarry | Insn::SubCarry => {
            let p = ops[1] as u32;
            let s = r64(b, ops[2] as u32);
            let t = r64(b, ops[3] as u32);
            let c = u64::from(p_get(b, p) & 1);
            let (v, carry) = if insn == Insn::AddCarry {
                let (v, c1) = s.overflowing_add(t);
                let (v, c2) = v.overflowing_add(c);
                (v, c1 | c2)
            } else {
                let t = !t;
                let (v, c1) = s.overflowing_add(t);
                let (v, c2) = v.overflowing_add(c);
                (v, c1 | c2)
            };
            pkt_w64(b, ops[0] as u32, v);
            pkt_pw(b, p, pval(carry));
        }
        // ---- min/max ----
        Insn::Max => pkt_w(
            b,
            ops[0] as u32,
            (r_get(b, ops[1] as u32) as i32).max(r_get(b, ops[2] as u32) as i32) as u32,
        ),
        Insn::Maxu => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[1] as u32).max(r_get(b, ops[2] as u32)),
        ),
        Insn::Min => pkt_w(
            b,
            ops[0] as u32,
            (r_get(b, ops[2] as u32) as i32).min(r_get(b, ops[1] as u32) as i32) as u32,
        ),
        Insn::Minu => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[2] as u32).min(r_get(b, ops[1] as u32)),
        ),
        Insn::Max64 => pkt_w64(
            b,
            ops[0] as u32,
            (r64(b, ops[1] as u32) as i64).max(r64(b, ops[2] as u32) as i64) as u64,
        ),
        Insn::Maxu64 => pkt_w64(
            b,
            ops[0] as u32,
            r64(b, ops[1] as u32).max(r64(b, ops[2] as u32)),
        ),
        Insn::Min64 => pkt_w64(
            b,
            ops[0] as u32,
            (r64(b, ops[2] as u32) as i64).min(r64(b, ops[1] as u32) as i64) as u64,
        ),
        Insn::Minu64 => pkt_w64(
            b,
            ops[0] as u32,
            r64(b, ops[2] as u32).min(r64(b, ops[1] as u32)),
        ),
        // ---- 64 ビット比較 ----
        Insn::Cmp64Eq => pkt_pw(
            b,
            ops[0] as u32,
            pval(r64(b, ops[1] as u32) == r64(b, ops[2] as u32)),
        ),
        Insn::Cmp64Gt => pkt_pw(
            b,
            ops[0] as u32,
            pval((r64(b, ops[1] as u32) as i64) > (r64(b, ops[2] as u32) as i64)),
        ),
        Insn::Cmp64Gtu => pkt_pw(
            b,
            ops[0] as u32,
            pval(r64(b, ops[1] as u32) > r64(b, ops[2] as u32)),
        ),
        // ---- 半語加減算 ----
        Insn::AddLl
        | Insn::AddLh
        | Insn::AddLlSat
        | Insn::AddLhSat
        | Insn::AddLlS16
        | Insn::AddLhS16
        | Insn::AddHlS16
        | Insn::AddHhS16
        | Insn::AddLlSatS16
        | Insn::AddLhSatS16
        | Insn::AddHlSatS16
        | Insn::AddHhSatS16
        | Insn::SubLl
        | Insn::SubLh
        | Insn::SubLlSat
        | Insn::SubLhSat
        | Insn::SubLlS16
        | Insn::SubLhS16
        | Insn::SubHlS16
        | Insn::SubHhS16
        | Insn::SubLlSatS16
        | Insn::SubLhSatS16
        | Insn::SubHlSatS16
        | Insn::SubHhSatS16 => {
            let s = r_get(b, ops[1] as u32);
            let t = r_get(b, ops[2] as u32);
            // 半語選択: {t_half, s_half, shift16, sat}。s の H 選択は
            // *_lh/_hh 系のみ（t は L の _l_ 系と H の _h_ 系）。
            let (th, sh_, s16, is_sat, is_sub) = match insn {
                Insn::AddLl | Insn::AddLlSat | Insn::AddLlS16 | Insn::AddLlSatS16 => (
                    0,
                    0,
                    insn != Insn::AddLl && insn != Insn::AddLlSat,
                    insn != Insn::AddLl && insn != Insn::AddLlS16,
                    false,
                ),
                Insn::AddLh | Insn::AddLhSat | Insn::AddLhS16 | Insn::AddLhSatS16 => (
                    0,
                    1,
                    insn != Insn::AddLh && insn != Insn::AddLhSat,
                    insn != Insn::AddLh && insn != Insn::AddLhS16,
                    false,
                ),
                Insn::AddHlS16 => (1, 0, true, false, false),
                Insn::AddHhS16 => (1, 1, true, false, false),
                Insn::AddHlSatS16 => (1, 0, true, true, false),
                Insn::AddHhSatS16 => (1, 1, true, true, false),
                Insn::SubLl | Insn::SubLlSat | Insn::SubLlS16 | Insn::SubLlSatS16 => (
                    0,
                    0,
                    insn != Insn::SubLl && insn != Insn::SubLlSat,
                    insn != Insn::SubLl && insn != Insn::SubLlS16,
                    true,
                ),
                Insn::SubLh | Insn::SubLhSat | Insn::SubLhS16 | Insn::SubLhSatS16 => (
                    0,
                    1,
                    insn != Insn::SubLh && insn != Insn::SubLhSat,
                    insn != Insn::SubLh && insn != Insn::SubLhS16,
                    true,
                ),
                Insn::SubHlS16 => (1, 0, true, false, true),
                Insn::SubHhS16 => (1, 1, true, false, true),
                Insn::SubHlSatS16 => (1, 0, true, true, true),
                _ => (1, 1, true, true, true),
            };
            let a = sh(t, th);
            let b_ = sh(s, sh_);
            let v = if is_sub { a - b_ } else { a + b_ };
            let v = if is_sat {
                let c = v.clamp(-0x8000, 0x7fff);
                if c != v {
                    ovf(b);
                }
                c
            } else {
                v
            };
            let v = if s16 { (v as u32) << 16 } else { v as u32 };
            let v = if !s16 {
                sext(u64::from(v & 0xffff), 16)
            } else {
                v
            };
            pkt_w(b, ops[0] as u32, v);
        }
        // ---- シフト（即値形）----
        Insn::AsrI => pkt_w(
            b,
            ops[0] as u32,
            f_asr32(r_get(b, ops[1] as u32), ops[2] as u32 as i32),
        ),
        Insn::LsrI => pkt_w(
            b,
            ops[0] as u32,
            f_lsr32(r_get(b, ops[1] as u32), ops[2] as u32 as i32),
        ),
        Insn::AslI => pkt_w(
            b,
            ops[0] as u32,
            f_asl32(r_get(b, ops[1] as u32), ops[2] as u32 as i32),
        ),
        Insn::AslISat => {
            let v = sx32(r_get(b, ops[1] as u32)) << (ops[2] as u32);
            let v = sat32(b, v);
            pkt_w(b, ops[0] as u32, v);
        }
        Insn::RolI => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[1] as u32).rotate_left(ops[2] as u32),
        ),
        Insn::AsrIRnd => {
            let v = f_rnd(sx32(r_get(b, ops[1] as u32)), ops[2] as u32);
            pkt_w(b, ops[0] as u32, v as u32);
        }
        Insn::Asr64I => pkt_w64(
            b,
            ops[0] as u32,
            f_asr64(r64(b, ops[1] as u32), ops[2] as u32 as i32),
        ),
        Insn::Lsr64I => pkt_w64(
            b,
            ops[0] as u32,
            f_lsr64(r64(b, ops[1] as u32), ops[2] as u32 as i32),
        ),
        Insn::Asl64I => pkt_w64(
            b,
            ops[0] as u32,
            f_asl64(r64(b, ops[1] as u32), ops[2] as u32 as i32),
        ),
        Insn::Rol64I => pkt_w64(
            b,
            ops[0] as u32,
            r64(b, ops[1] as u32).rotate_left(ops[2] as u32),
        ),
        // ベクトル即値シフト。w 形は各 32 ビット要素、
        // h 形は各 16 ビット要素を imm だけ独立にシフト。
        Insn::VasrwI | Insn::VlsrwI | Insn::VaslwI => {
            let ss = r64(b, ops[1] as u32);
            let sh = ops[2] as u32 & 31;
            let lo = (ss & 0xffff_ffff) as u32;
            let hi = (ss >> 32) as u32;
            let f: fn(u32, u32) -> u32 = match insn {
                Insn::VasrwI => |v, s| ((v as i32) >> s.min(31)) as u32,
                Insn::VlsrwI => |v, s| v >> s,
                Insn::VaslwI => |v, s| v.wrapping_shl(s),
                _ => unreachable!(),
            };
            pkt_w64(
                b,
                ops[0] as u32,
                u64::from(f(hi, sh)) << 32 | u64::from(f(lo, sh)),
            );
        }
        Insn::VasrhI | Insn::VlsrhI | Insn::VaslhI => {
            let ss = r64(b, ops[1] as u32);
            let sh = ops[2] as u32 & 15;
            let f: fn(u16, u32) -> u16 = match insn {
                Insn::VasrhI => |v, s| ((v as i16) >> s.min(15)) as u16,
                Insn::VlsrhI => |v, s| v >> s,
                Insn::VaslhI => |v, s| v.wrapping_shl(s),
                _ => unreachable!(),
            };
            let mut out = 0u64;
            for i in 0..4 {
                out |= u64::from(f((ss >> (i * 16)) as u16, sh)) << (i * 16);
            }
            pkt_w64(b, ops[0] as u32, out);
        }
        Insn::Asr64IRnd => {
            let v = f_rnd(r64(b, ops[1] as u32) as i64, ops[2] as u32);
            pkt_w64(b, ops[0] as u32, v as u64);
        }
        // ---- シフト（レジスタ形）----
        Insn::AsrRr => pkt_w(
            b,
            ops[0] as u32,
            f_asr32(r_get(b, ops[1] as u32), shamt(r_get(b, ops[2] as u32))),
        ),
        Insn::AslRr => pkt_w(
            b,
            ops[0] as u32,
            f_asl32(r_get(b, ops[1] as u32), shamt(r_get(b, ops[2] as u32))),
        ),
        Insn::LsrRr => pkt_w(
            b,
            ops[0] as u32,
            f_lsr32(r_get(b, ops[1] as u32), shamt(r_get(b, ops[2] as u32))),
        ),
        Insn::LslRr => pkt_w(
            b,
            ops[0] as u32,
            f_lsl32(r_get(b, ops[1] as u32), shamt(r_get(b, ops[2] as u32))),
        ),
        Insn::AslRrSat | Insn::AsrRrSat => {
            let v = r_get(b, ops[1] as u32);
            let sh = shamt(r_get(b, ops[2] as u32));
            let r = if insn == Insn::AslRrSat {
                if sh > 0 {
                    sat32(b, sx32(v) << sh)
                } else {
                    f_asl32(v, sh)
                }
            } else if sh > 0 {
                f_asr32(v, sh)
            } else {
                sat32(b, sx32(v) << (-sh))
            };
            pkt_w(b, ops[0] as u32, r);
        }
        Insn::Asr64Rr => pkt_w64(
            b,
            ops[0] as u32,
            f_asr64(r64(b, ops[1] as u32), shamt(r_get(b, ops[2] as u32))),
        ),
        Insn::Asl64Rr => pkt_w64(
            b,
            ops[0] as u32,
            f_asl64(r64(b, ops[1] as u32), shamt(r_get(b, ops[2] as u32))),
        ),
        Insn::Lsr64Rr => pkt_w64(
            b,
            ops[0] as u32,
            f_lsr64(r64(b, ops[1] as u32), shamt(r_get(b, ops[2] as u32))),
        ),
        Insn::Lsl64Rr => pkt_w64(
            b,
            ops[0] as u32,
            f_lsl64(r64(b, ops[1] as u32), shamt(r_get(b, ops[2] as u32))),
        ),
        // ---- ベクトルシフト（ワード/ハーフ要素、レジスタシフト量）----
        // vlslw/vlsrw/vasrw: 各 32 ビット要素を Rt[4:0] だけ独立に
        // シフト。vlslh/vlsrh/vasrh: 各 16 ビット要素を Rt[3:0] だけ。
        // vasl* は算術左シフト（飽和あり、HX11 実機値照合は未検証で
        // 飽和は行わず単純シフトとする）。
        Insn::Vasrw | Insn::Vlsrw | Insn::Vaslw | Insn::Vlslw => {
            let ss = r64(b, ops[1] as u32);
            let sh = r_get(b, ops[2] as u32) & 31;
            let lo = (ss & 0xffff_ffff) as u32;
            let hi = (ss >> 32) as u32;
            let f: fn(u32, u32) -> u32 = match insn {
                Insn::Vasrw => |v, s| ((v as i32) >> s.min(31)) as u32,
                Insn::Vlsrw => |v, s| v >> s,
                Insn::Vaslw | Insn::Vlslw => |v, s| v.wrapping_shl(s),
                _ => unreachable!(),
            };
            pkt_w64(
                b,
                ops[0] as u32,
                u64::from(f(hi, sh)) << 32 | u64::from(f(lo, sh)),
            );
        }
        Insn::Vasrh | Insn::Vlsrh | Insn::Vaslh | Insn::Vlslh => {
            let ss = r64(b, ops[1] as u32);
            let sh = r_get(b, ops[2] as u32) & 15;
            let f: fn(u16, u32) -> u16 = match insn {
                Insn::Vasrh => |v, s| ((v as i16) >> s.min(15)) as u16,
                Insn::Vlsrh => |v, s| v >> s,
                Insn::Vaslh | Insn::Vlslh => |v, s| v.wrapping_shl(s),
                _ => unreachable!(),
            };
            let mut out = 0u64;
            for i in 0..4 {
                out |= u64::from(f((ss >> (i * 16)) as u16, sh)) << (i * 16);
            }
            pkt_w64(b, ops[0] as u32, out);
        }
        Insn::LslIr => {
            // s は 32 ビット値として zxt してから論理シフトする。
            let s = u64::from(sext(ops[1], 6));
            let sh = shamt(r_get(b, ops[2] as u32));
            let v = if sh > 0 {
                (s << sh.min(63)) as u32
            } else {
                (s >> (-sh).min(63)) as u32
            };
            pkt_w(b, ops[0] as u32, v);
        }
        Insn::Addasl => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[2] as u32)
                .wrapping_add(r_get(b, ops[1] as u32).wrapping_shl(ops[3] as u32)),
        ),
        // ---- シフト累積（32/64、即値/レジスタ）----
        Insn::AddAsrI
        | Insn::AddLsrI
        | Insn::AddAslI
        | Insn::AddRolI
        | Insn::SubAsrI
        | Insn::SubLsrI
        | Insn::SubAslI
        | Insn::SubRolI
        | Insn::AndAsrI
        | Insn::AndLsrI
        | Insn::AndAslI
        | Insn::AndRolI
        | Insn::OrAsrI
        | Insn::OrLsrI
        | Insn::OrAslI
        | Insn::OrRolI
        | Insn::XorLsrI
        | Insn::XorAslI
        | Insn::XorRolI => {
            let x = ops[0] as u32;
            let s = r_get(b, ops[1] as u32);
            let n = ops[2] as u32 as i32;
            let v = match insn {
                Insn::AddAsrI | Insn::SubAsrI | Insn::AndAsrI | Insn::OrAsrI => f_asr32(s, n),
                Insn::AddLsrI | Insn::SubLsrI | Insn::AndLsrI | Insn::OrLsrI | Insn::XorLsrI => {
                    f_lsr32(s, n)
                }
                Insn::AddAslI | Insn::SubAslI | Insn::AndAslI | Insn::OrAslI | Insn::XorAslI => {
                    f_asl32(s, n)
                }
                _ => s.rotate_left(n as u32),
            };
            let old = r_get(b, x);
            let r = match insn {
                Insn::AddAsrI | Insn::AddLsrI | Insn::AddAslI | Insn::AddRolI => {
                    old.wrapping_add(v)
                }
                Insn::SubAsrI | Insn::SubLsrI | Insn::SubAslI | Insn::SubRolI => {
                    old.wrapping_sub(v)
                }
                Insn::AndAsrI | Insn::AndLsrI | Insn::AndAslI | Insn::AndRolI => old & v,
                Insn::OrAsrI | Insn::OrLsrI | Insn::OrAslI | Insn::OrRolI => old | v,
                _ => old ^ v,
            };
            pkt_w(b, x, r);
        }
        Insn::Add64AsrI
        | Insn::Add64LsrI
        | Insn::Add64AslI
        | Insn::Add64RolI
        | Insn::Sub64AsrI
        | Insn::Sub64LsrI
        | Insn::Sub64AslI
        | Insn::Sub64RolI
        | Insn::And64AsrI
        | Insn::And64LsrI
        | Insn::And64AslI
        | Insn::And64RolI
        | Insn::Or64AsrI
        | Insn::Or64LsrI
        | Insn::Or64AslI
        | Insn::Or64RolI
        | Insn::Xor64LsrI
        | Insn::Xor64AslI
        | Insn::Xor64RolI => {
            let x = ops[0] as u32;
            let s = r64(b, ops[1] as u32);
            let n = ops[2] as u32 as i32;
            let v = match insn {
                Insn::Add64AsrI | Insn::Sub64AsrI | Insn::And64AsrI | Insn::Or64AsrI => {
                    f_asr64(s, n)
                }
                Insn::Add64LsrI
                | Insn::Sub64LsrI
                | Insn::And64LsrI
                | Insn::Or64LsrI
                | Insn::Xor64LsrI => f_lsr64(s, n),
                Insn::Add64AslI
                | Insn::Sub64AslI
                | Insn::And64AslI
                | Insn::Or64AslI
                | Insn::Xor64AslI => f_asl64(s, n),
                _ => s.rotate_left(n as u32),
            };
            let old = r64(b, x);
            let r = match insn {
                Insn::Add64AsrI | Insn::Add64LsrI | Insn::Add64AslI | Insn::Add64RolI => {
                    old.wrapping_add(v)
                }
                Insn::Sub64AsrI | Insn::Sub64LsrI | Insn::Sub64AslI | Insn::Sub64RolI => {
                    old.wrapping_sub(v)
                }
                Insn::And64AsrI | Insn::And64LsrI | Insn::And64AslI | Insn::And64RolI => old & v,
                Insn::Or64AsrI | Insn::Or64LsrI | Insn::Or64AslI | Insn::Or64RolI => old | v,
                _ => old ^ v,
            };
            pkt_w64(b, x, r);
        }
        Insn::AddAsr
        | Insn::AddLsr
        | Insn::AddAsl
        | Insn::AddLsl
        | Insn::SubAsr
        | Insn::SubLsr
        | Insn::SubAsl
        | Insn::SubLsl
        | Insn::OrAsr
        | Insn::OrLsr
        | Insn::OrAsl
        | Insn::OrLsl
        | Insn::AndAsr
        | Insn::AndLsr
        | Insn::AndAsl
        | Insn::AndRol => {
            let x = ops[0] as u32;
            let s = r_get(b, ops[1] as u32);
            let sh = shamt(r_get(b, ops[2] as u32));
            let v = match insn {
                Insn::AddAsr | Insn::SubAsr | Insn::OrAsr | Insn::AndAsr => f_asr32(s, sh),
                Insn::AddLsr | Insn::SubLsr | Insn::OrLsr | Insn::AndLsr => f_lsr32(s, sh),
                Insn::AddAsl | Insn::SubAsl | Insn::OrAsl | Insn::AndAsl => f_asl32(s, sh),
                Insn::AndRol => s.rotate_left((sh & 31) as u32),
                _ => f_lsl32(s, sh),
            };
            let old = r_get(b, x);
            let r = if matches!(
                insn,
                Insn::AddAsr | Insn::AddLsr | Insn::AddAsl | Insn::AddLsl
            ) {
                old.wrapping_add(v)
            } else if matches!(
                insn,
                Insn::SubAsr | Insn::SubLsr | Insn::SubAsl | Insn::SubLsl
            ) {
                old.wrapping_sub(v)
            } else if matches!(
                insn,
                Insn::AndAsr | Insn::AndLsr | Insn::AndAsl | Insn::AndRol
            ) {
                old & v
            } else {
                old | v
            };
            pkt_w(b, x, r);
        }
        Insn::Add64Asr
        | Insn::Add64Lsr
        | Insn::Add64Asl
        | Insn::Add64Lsl
        | Insn::Sub64Asr
        | Insn::Sub64Lsr
        | Insn::Sub64Asl
        | Insn::Sub64Lsl
        | Insn::Or64Asr
        | Insn::Or64Lsr
        | Insn::Or64Asl
        | Insn::Or64Lsl => {
            let x = ops[0] as u32;
            let s = r64(b, ops[1] as u32);
            let sh = shamt(r_get(b, ops[2] as u32));
            let v = match insn {
                Insn::Add64Asr | Insn::Sub64Asr | Insn::Or64Asr => f_asr64(s, sh),
                Insn::Add64Lsr | Insn::Sub64Lsr | Insn::Or64Lsr => f_lsr64(s, sh),
                Insn::Add64Asl | Insn::Sub64Asl | Insn::Or64Asl => f_asl64(s, sh),
                _ => f_lsl64(s, sh),
            };
            let old = r64(b, x);
            let r = if matches!(
                insn,
                Insn::Add64Asr | Insn::Add64Lsr | Insn::Add64Asl | Insn::Add64Lsl
            ) {
                old.wrapping_add(v)
            } else if matches!(
                insn,
                Insn::Sub64Asr | Insn::Sub64Lsr | Insn::Sub64Asl | Insn::Sub64Lsl
            ) {
                old.wrapping_sub(v)
            } else {
                old | v
            };
            pkt_w64(b, x, r);
        }
        // ---- 加減算・論理の累積 ----
        Insn::AddAcc => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[0] as u32)
                .wrapping_add(r_get(b, ops[1] as u32).wrapping_add(r_get(b, ops[2] as u32))),
        ),
        Insn::SubAcc => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[0] as u32)
                .wrapping_sub(r_get(b, ops[1] as u32).wrapping_add(r_get(b, ops[2] as u32))),
        ),
        Insn::AddsubAcc => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[0] as u32)
                .wrapping_add(r_get(b, ops[2] as u32).wrapping_sub(r_get(b, ops[1] as u32))),
        ),
        Insn::AddAccI => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[0] as u32)
                .wrapping_add(r_get(b, ops[1] as u32).wrapping_add(ximm(cx.ext, ops[2], 0, 8))),
        ),
        Insn::SubAccI => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[0] as u32)
                .wrapping_sub(r_get(b, ops[1] as u32).wrapping_add(ximm(cx.ext, ops[2], 0, 8))),
        ),
        Insn::AndAnd => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[0] as u32) & (r_get(b, ops[1] as u32) & r_get(b, ops[2] as u32)),
        ),
        Insn::AndAndn => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[0] as u32) & (r_get(b, ops[1] as u32) & !r_get(b, ops[2] as u32)),
        ),
        Insn::AndOr => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[0] as u32) & (r_get(b, ops[1] as u32) | r_get(b, ops[2] as u32)),
        ),
        Insn::AndXor => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[0] as u32) & (r_get(b, ops[1] as u32) ^ r_get(b, ops[2] as u32)),
        ),
        Insn::OrAnd => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[0] as u32) | (r_get(b, ops[1] as u32) & r_get(b, ops[2] as u32)),
        ),
        Insn::OrAndn => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[0] as u32) | (r_get(b, ops[1] as u32) & !r_get(b, ops[2] as u32)),
        ),
        Insn::OrOr => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[0] as u32) | (r_get(b, ops[1] as u32) | r_get(b, ops[2] as u32)),
        ),
        Insn::OrXor => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[0] as u32) | (r_get(b, ops[1] as u32) ^ r_get(b, ops[2] as u32)),
        ),
        Insn::XorAnd => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[0] as u32) ^ (r_get(b, ops[1] as u32) & r_get(b, ops[2] as u32)),
        ),
        Insn::XorOr => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[0] as u32) ^ (r_get(b, ops[1] as u32) | r_get(b, ops[2] as u32)),
        ),
        Insn::XorXor => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[0] as u32) ^ (r_get(b, ops[1] as u32) ^ r_get(b, ops[2] as u32)),
        ),
        Insn::XorAndn => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[0] as u32) ^ (r_get(b, ops[1] as u32) & !r_get(b, ops[2] as u32)),
        ),
        Insn::Xor64Xor => pkt_w64(
            b,
            ops[0] as u32,
            r64(b, ops[0] as u32) ^ (r64(b, ops[1] as u32) ^ r64(b, ops[2] as u32)),
        ),
        Insn::OrAndI => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[0] as u32) | (r_get(b, ops[1] as u32) & ximm(cx.ext, ops[2], 0, 10)),
        ),
        Insn::OrOrI => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[0] as u32) | (r_get(b, ops[1] as u32) | ximm(cx.ext, ops[2], 0, 10)),
        ),
        Insn::OrAc => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[1] as u32) | (r_get(b, ops[0] as u32) & ximm(cx.ext, ops[2], 0, 10)),
        ),
        // ---- 3 入力加算 ----
        Insn::Add3 => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[1] as u32)
                .wrapping_add(r_get(b, ops[2] as u32))
                .wrapping_add(ximm(cx.ext, ops[3], 0, 6)),
        ),
        Insn::Sub3 => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[1] as u32)
                .wrapping_sub(r_get(b, ops[2] as u32))
                .wrapping_add(ximm(cx.ext, ops[3], 0, 6)),
        ),
        // ---- 複合シフト即値形（Rx = op(#u8,{asl,lsr}(Rx,#U5))）----
        Insn::CaddAsl
        | Insn::CsubAsl
        | Insn::CandAsl
        | Insn::CorAsl
        | Insn::CaddLsr
        | Insn::CsubLsr
        | Insn::CandLsr
        | Insn::CorLsr => {
            let x = ops[0] as u32;
            let n = ops[1] as u32;
            let v = if matches!(
                insn,
                Insn::CaddAsl | Insn::CsubAsl | Insn::CandAsl | Insn::CorAsl
            ) {
                r_get(b, x).wrapping_shl(n)
            } else {
                r_get(b, x).wrapping_shr(n)
            };
            let imm = ops[2] as u32;
            let r = match insn {
                Insn::CaddAsl | Insn::CaddLsr => imm.wrapping_add(v),
                Insn::CsubAsl | Insn::CsubLsr => imm.wrapping_sub(v),
                Insn::CandAsl | Insn::CandLsr => imm & v,
                _ => imm | v,
            };
            pkt_w(b, x, r);
        }
        Insn::Addpc => pkt_w(
            b,
            ops[0] as u32,
            cx.pc.wrapping_add(ximm(cx.ext, ops[1], 0, 6)),
        ),
        // ---- ビット計数 ----
        Insn::Cl0 => pkt_w(b, ops[0] as u32, r_get(b, ops[1] as u32).leading_zeros()),
        Insn::Cl1 => pkt_w(b, ops[0] as u32, r_get(b, ops[1] as u32).leading_ones()),
        Insn::Clb => {
            let v = r_get(b, ops[1] as u32);
            let n = if (v as i32) < 0 {
                v.leading_ones()
            } else {
                v.leading_zeros()
            };
            pkt_w(b, ops[0] as u32, n);
        }
        Insn::Cl064 => pkt_w(b, ops[0] as u32, r64(b, ops[1] as u32).leading_zeros()),
        Insn::Cl164 => pkt_w(b, ops[0] as u32, r64(b, ops[1] as u32).leading_ones()),
        Insn::Clb64 => {
            let v = r64(b, ops[1] as u32);
            let n = if (v as i64) < 0 {
                v.leading_ones()
            } else {
                v.leading_zeros()
            };
            pkt_w(b, ops[0] as u32, n);
        }
        Insn::Normamt => {
            let v = r_get(b, ops[1] as u32);
            let n = if v == 0 {
                0
            } else {
                v.leading_zeros().max(v.leading_ones()) - 1
            };
            pkt_w(b, ops[0] as u32, n);
        }
        Insn::Normamt64 => {
            let v = r64(b, ops[1] as u32);
            let n = if v == 0 {
                0
            } else {
                v.leading_zeros().max(v.leading_ones()) - 1
            };
            pkt_w(b, ops[0] as u32, n);
        }
        Insn::Clbadd => {
            let v = r_get(b, ops[1] as u32);
            let n = v.leading_zeros().max(v.leading_ones());
            pkt_w(b, ops[0] as u32, n.wrapping_add(ximm(cx.ext, ops[2], 0, 6)));
        }
        Insn::Clbadd64 => {
            let v = r64(b, ops[1] as u32);
            let n = v.leading_zeros().max(v.leading_ones());
            pkt_w(b, ops[0] as u32, n.wrapping_add(ximm(cx.ext, ops[2], 0, 6)));
        }
        Insn::Ct0 => pkt_w(b, ops[0] as u32, r_get(b, ops[1] as u32).trailing_zeros()),
        Insn::Ct1 => pkt_w(b, ops[0] as u32, r_get(b, ops[1] as u32).trailing_ones()),
        Insn::Ct064 => pkt_w(b, ops[0] as u32, r64(b, ops[1] as u32).trailing_zeros()),
        Insn::Ct164 => pkt_w(b, ops[0] as u32, r64(b, ops[1] as u32).trailing_ones()),
        Insn::Popcount => pkt_w(b, ops[0] as u32, r64(b, ops[1] as u32).count_ones()),
        // ---- パリティ・ビット反転 ----
        Insn::Parity => pkt_w(
            b,
            ops[0] as u32,
            (r_get(b, ops[1] as u32) & r_get(b, ops[2] as u32)).count_ones() & 1,
        ),
        Insn::Parity64 => pkt_w(
            b,
            ops[0] as u32,
            (r64(b, ops[1] as u32) & r64(b, ops[2] as u32)).count_ones() & 1,
        ),
        Insn::Brev => pkt_w(b, ops[0] as u32, r_get(b, ops[1] as u32).reverse_bits()),
        Insn::Brev64 => pkt_w64(b, ops[0] as u32, r64(b, ops[1] as u32).reverse_bits()),
        Insn::Swiz => pkt_w(b, ops[0] as u32, r_get(b, ops[1] as u32).swap_bytes()),
        // ---- ビット検査・操作 ----
        Insn::TstbitI | Insn::TstbitnI => {
            let v = r_get(b, ops[1] as u32) & (1u32 << ops[2]) != 0;
            pkt_pw(b, ops[0] as u32, pval(v ^ (insn == Insn::TstbitnI)));
        }
        Insn::TstbitR | Insn::TstbitnR => {
            let sh = shamt(r_get(b, ops[2] as u32)).unsigned_abs().min(63);
            let v = (u64::from(r_get(b, ops[1] as u32)) & (1u64 << sh)) != 0;
            pkt_pw(b, ops[0] as u32, pval(v ^ (insn == Insn::TstbitnR)));
        }
        Insn::SetbitI => pkt_w(b, ops[0] as u32, r_get(b, ops[1] as u32) | (1u32 << ops[2])),
        Insn::ClrbitI => pkt_w(
            b,
            ops[0] as u32,
            r_get(b, ops[1] as u32) & !(1u32 << ops[2]),
        ),
        Insn::TogglebitI => pkt_w(b, ops[0] as u32, r_get(b, ops[1] as u32) ^ (1u32 << ops[2])),
        Insn::SetbitR | Insn::ClrbitR | Insn::TogglebitR => {
            let sh = shamt(r_get(b, ops[2] as u32)).unsigned_abs().min(63);
            let bit = 1u64 << sh;
            let s = u64::from(r_get(b, ops[1] as u32));
            let v = match insn {
                Insn::SetbitR => s | bit,
                Insn::ClrbitR => s & !bit,
                _ => s ^ bit,
            };
            pkt_w(b, ops[0] as u32, v as u32);
        }
        Insn::BitsclrR | Insn::BitsclrnR | Insn::BitssetR | Insn::BitssetnR => {
            let s = r_get(b, ops[1] as u32);
            let t = r_get(b, ops[2] as u32);
            let set = matches!(insn, Insn::BitssetR | Insn::BitssetnR);
            let neg = matches!(insn, Insn::BitsclrnR | Insn::BitssetnR);
            let v = if set { s & t == t } else { s & t == 0 };
            pkt_pw(b, ops[0] as u32, pval(v ^ neg));
        }
        Insn::BitsclrI | Insn::BitsclrnI => {
            let v = r_get(b, ops[1] as u32) & (ops[2] as u32) == 0;
            pkt_pw(b, ops[0] as u32, pval(v ^ (insn == Insn::BitsclrnI)));
        }
        // ---- ビットフィールド ----
        Insn::Extract | Insn::Extractu => {
            let s = r_get(b, ops[1] as u32);
            let width = ops[2].min(32);
            let off = ops[3] as u32;
            let v = if width == 0 {
                0
            } else {
                (u64::from(s) >> off.min(32)) & ((1u64 << width) - 1)
            };
            let v = if insn == Insn::Extract {
                if width >= 32 {
                    v as u32
                } else {
                    sext(v, width as u32)
                }
            } else {
                v as u32
            };
            pkt_w(b, ops[0] as u32, v);
        }
        Insn::Extract64 | Insn::Extractu64 => {
            let s = r64(b, ops[1] as u32);
            let width = ops[2].min(64);
            let off = ops[3].min(64) as u32;
            let v = if width == 0 {
                0
            } else {
                (s >> off)
                    & if width >= 64 {
                        u64::MAX
                    } else {
                        (1u64 << width) - 1
                    }
            };
            let v = if insn == Insn::Extract64 && width < 64 {
                let sh = 64 - width as u32;
                (((v << sh) as i64) >> sh) as u64
            } else {
                v
            };
            pkt_w64(b, ops[0] as u32, v);
        }
        Insn::ExtractR | Insn::ExtractuR | Insn::Extract64R | Insn::Extractu64R => {
            let s = r64(b, ops[1] as u32);
            let tt = r64(b, ops[2] as u32);
            let width = (tt >> 32) & 0x3f;
            let off = shamt(tt as u32);
            let is64 = matches!(insn, Insn::Extract64R | Insn::Extractu64R);
            let signed = matches!(insn, Insn::ExtractR | Insn::Extract64R);
            let s = if is64 { s } else { s & 0xffff_ffff };
            let v = if off > 0 {
                s >> off.min(63)
            } else {
                s << (-off).min(63)
            };
            let v = if width == 0 {
                0
            } else if width >= 64 {
                v
            } else {
                v & ((1u64 << width) - 1)
            };
            let v = if signed && width < 64 && width > 0 {
                let sh = 64 - width as u32;
                (((v << sh) as i64) >> sh) as u64
            } else {
                v
            };
            if is64 {
                pkt_w64(b, ops[0] as u32, v);
            } else {
                pkt_w(b, ops[0] as u32, v as u32);
            }
        }
        Insn::Insert | Insn::Insert64 => {
            let is64 = insn == Insn::Insert64;
            let s = if is64 {
                r64(b, ops[1] as u32)
            } else {
                u64::from(r_get(b, ops[1] as u32))
            };
            let x = ops[0] as u32;
            let old = if is64 {
                r64(b, x)
            } else {
                u64::from(r_get(b, x))
            };
            let width = ops[2].min(64);
            let off = ops[3].min(64) as u32;
            let v = if width == 0 {
                old
            } else {
                let mask = if width >= 64 {
                    u64::MAX
                } else {
                    ((1u64 << width) - 1) << off.min(63)
                };
                // (Rs & ((1<<width)-1)) << off
                let fmask = if width >= 64 {
                    u64::MAX
                } else {
                    (1u64 << width) - 1
                };
                (old & !mask) | ((s & fmask) << off.min(63))
            };
            if is64 {
                pkt_w64(b, x, v);
            } else {
                pkt_w(b, x, v as u32);
            }
        }
        Insn::InsertR | Insn::Insert64R => {
            let is64 = insn == Insn::Insert64R;
            let s = if is64 {
                r64(b, ops[1] as u32)
            } else {
                u64::from(r_get(b, ops[1] as u32))
            };
            let tt = r64(b, ops[2] as u32);
            let width = (tt >> 32) & 0x3f;
            let off = shamt(tt as u32);
            let x = ops[0] as u32;
            let old = if is64 {
                r64(b, x)
            } else {
                u64::from(r_get(b, x))
            };
            let v = if off < 0 {
                0
            } else {
                let fmask = if width >= 64 {
                    u64::MAX
                } else {
                    (1u64 << width) - 1
                };
                let off = off as u32;
                let mask = if off >= 63 { 0 } else { fmask << off.min(63) };
                (old & !mask) | ((s & fmask) << off.min(63))
            };
            if is64 {
                pkt_w64(b, x, v);
            } else {
                pkt_w(b, x, v as u32);
            }
        }
        Insn::BitsplitI | Insn::BitsplitR => {
            let s = r_get(b, ops[1] as u32);
            let n = if insn == Insn::BitsplitI {
                ops[2] as u32 & 0x1f
            } else {
                r_get(b, ops[2] as u32) & 0x1f
            };
            let hi = s >> n;
            let lo = s & ((1u32 << n) - 1);
            pkt_w64(b, ops[0] as u32, (u64::from(hi) << 32) | u64::from(lo));
        }
        Insn::Tableidxb | Insn::Tableidxh | Insn::Tableidxw | Insn::Tableidxd => {
            let x = ops[0] as u32;
            let s = r_get(b, ops[1] as u32);
            let width = ops[2] as u32;
            let adj = match insn {
                Insn::Tableidxb => 0,
                Insn::Tableidxh => 1,
                Insn::Tableidxw => 2,
                _ => 3,
            };
            let off = (sext(ops[3], 6) as i32 + adj).clamp(0, 31) as u32;
            let field = if width == 0 {
                0
            } else {
                (u64::from(s) >> off.min(31)) & ((1u64 << width.min(32)) - 1)
            };
            let mask = ((1u64 << width.min(32)) - 1) << adj;
            let v =
                (u64::from(r_get(b, x)) & !mask) | ((field & ((1u64 << width.min(32)) - 1)) << adj);
            pkt_w(b, x, v as u32);
        }
        // ---- 飽和・丸め・パック ----
        Insn::Sat => {
            let v = sat32(b, r64(b, ops[1] as u32) as i64);
            pkt_w(b, ops[0] as u32, v);
        }
        Insn::Sath => {
            // sat_16 の結果は 32 ビットに符号拡張して書き込む。
            let v = sext(u64::from(sat16(b, sx32(r_get(b, ops[1] as u32)))), 16);
            pkt_w(b, ops[0] as u32, v);
        }
        Insn::Satuh => {
            let v = usatn(b, sx32(r_get(b, ops[1] as u32)), 16) as u32;
            pkt_w(b, ops[0] as u32, v);
        }
        Insn::Satb => {
            let v = sext(satn(b, sx32(r_get(b, ops[1] as u32)), 8), 8);
            pkt_w(b, ops[0] as u32, v);
        }
        Insn::Satub => {
            let v = usatn(b, sx32(r_get(b, ops[1] as u32)), 8) as u32;
            pkt_w(b, ops[0] as u32, v);
        }
        Insn::RoundSat => {
            // tmp = sat64(Rss + 0x080000000); Rd = tmp.w[1]。
            let v = (r64(b, ops[1] as u32) as i64 as i128) + 0x8000_0000i128;
            let v = if v > i64::MAX as i128 {
                ovf(b);
                i64::MAX
            } else if v < i64::MIN as i128 {
                ovf(b);
                i64::MIN
            } else {
                v as i64
            };
            pkt_w(b, ops[0] as u32, (v >> 32) as u32);
        }
        Insn::RoundI | Insn::RoundR => {
            let s = sx32(r_get(b, ops[1] as u32));
            let n = if insn == Insn::RoundI {
                ops[2] as u32 & 0x1f
            } else {
                r_get(b, ops[2] as u32) & 0x1f
            };
            pkt_w(b, ops[0] as u32, f_rnd(s, n) as u32);
        }
        Insn::RoundISat | Insn::RoundRSat => {
            let s = sx32(r_get(b, ops[1] as u32));
            let n = if insn == Insn::RoundISat {
                ops[2] as u32 & 0x1f
            } else {
                r_get(b, ops[2] as u32) & 0x1f
            };
            let v = if n == 0 {
                s
            } else {
                sat32(b, s + (1i64 << (n - 1))) as i32 as i64
            };
            pkt_w(b, ops[0] as u32, (v >> n) as u32);
        }
        Insn::CroundI | Insn::CroundR => {
            let s = sx32(r_get(b, ops[1] as u32));
            let n = if insn == Insn::CroundI {
                ops[2] as u32 & 0x1f
            } else {
                r_get(b, ops[2] as u32) & 0x1f
            };
            pkt_w(b, ops[0] as u32, f_crnd(s, n) as u32);
        }
        Insn::Vsathub => {
            let s = r64(b, ops[1] as u32);
            let mut r = 0u32;
            for i in 0..4 {
                r |= ((usatn(b, sh64(s, i), 8) as u32) & 0xff) << (8 * i);
            }
            pkt_w(b, ops[0] as u32, r);
        }
        Insn::Vsathb => {
            let s = r64(b, ops[1] as u32);
            let mut r = 0u32;
            for i in 0..4 {
                r |= ((satn(b, sh64(s, i), 8) as u32) & 0xff) << (8 * i);
            }
            pkt_w(b, ops[0] as u32, r);
        }
        Insn::VsathubRs => {
            let s = r_get(b, ops[1] as u32);
            let r = (usatn(b, sh(s, 0), 8) as u32 & 0xff)
                | ((usatn(b, sh(s, 1), 8) as u32 & 0xff) << 8);
            pkt_w(b, ops[0] as u32, r);
        }
        Insn::VsathbRs => {
            let s = r_get(b, ops[1] as u32);
            let r =
                (satn(b, sh(s, 0), 8) as u32 & 0xff) | ((satn(b, sh(s, 1), 8) as u32 & 0xff) << 8);
            pkt_w(b, ops[0] as u32, r);
        }
        Insn::Vsatwh | Insn::Vsatwuh => {
            let s = r64(b, ops[1] as u32);
            let mut r = 0u32;
            for i in 0..2 {
                let v = if insn == Insn::Vsatwh {
                    satn(b, sw64(s, i), 16)
                } else {
                    usatn(b, sw64(s, i), 16)
                };
                r |= ((v as u32) & 0xffff) << (16 * i);
            }
            pkt_w(b, ops[0] as u32, r);
        }
        Insn::VsatwhP | Insn::VsatwuhP => {
            let s = r64(b, ops[1] as u32);
            let mut r = 0u64;
            for i in 0..2 {
                let v = if insn == Insn::VsatwhP {
                    satn(b, sw64(s, i), 16)
                } else {
                    usatn(b, sw64(s, i), 16)
                };
                r |= (v & 0xffff_ffff) << (32 * i);
            }
            pkt_w64(b, ops[0] as u32, r);
        }
        Insn::VsathubP | Insn::VsathbP => {
            let s = r64(b, ops[1] as u32);
            let mut r = 0u64;
            for i in 0..4 {
                let v = if insn == Insn::VsathubP {
                    usatn(b, sh64(s, i), 8)
                } else {
                    satn(b, sh64(s, i), 8)
                };
                r |= (v & 0xffff) << (16 * i);
            }
            pkt_w64(b, ops[0] as u32, r);
        }
        Insn::Vrndwh | Insn::VrndwhSat => {
            let s = r64(b, ops[1] as u32);
            let mut r = 0u32;
            for i in 0..2 {
                let v = sw64(s, i) + 0x8000;
                let v = if insn == Insn::VrndwhSat {
                    sat32(b, v) as i64
                } else {
                    v
                };
                r |= (((v >> 16) as u32) & 0xffff) << (16 * i);
            }
            pkt_w(b, ops[0] as u32, r);
        }
        Insn::VaddhubSat => {
            let s = r64(b, ops[1] as u32);
            let t = r64(b, ops[2] as u32);
            let mut r = 0u32;
            for i in 0..4 {
                r |= ((usatn(b, sh64(s, i) + sh64(t, i), 8) as u32) & 0xff) << (8 * i);
            }
            pkt_w(b, ops[0] as u32, r);
        }
        // ---- 64 ビットベクトル加減算・平均・min/max ----
        Insn::Vaddub64
        | Insn::Vaddub64Sat
        | Insn::Vaddh64
        | Insn::Vaddh64Sat
        | Insn::Vadduh64Sat
        | Insn::Vaddw64
        | Insn::Vaddw64Sat
        | Insn::Vsubub64
        | Insn::Vsubub64Sat
        | Insn::Vsubh64
        | Insn::Vsubh64Sat
        | Insn::Vsubuh64Sat
        | Insn::Vsubw64
        | Insn::Vsubw64Sat => {
            let s = r64(b, ops[1] as u32);
            let t = r64(b, ops[2] as u32);
            // t - s は vsub* 系（Rtt が被減数）、vadd は s + t。
            let mut r = 0u64;
            let byte = matches!(
                insn,
                Insn::Vaddub64 | Insn::Vaddub64Sat | Insn::Vsubub64 | Insn::Vsubub64Sat
            );
            let half = !byte
                && !matches!(
                    insn,
                    Insn::Vaddw64 | Insn::Vaddw64Sat | Insn::Vsubw64 | Insn::Vsubw64Sat
                );
            let n = if byte {
                8
            } else if half {
                4
            } else {
                2
            };
            for i in 0..n {
                let (av, bv, bits) = if byte {
                    (ub64(t, i) as i64, ub64(s, i) as i64, 8)
                } else if half {
                    (sh64(t, i), sh64(s, i), 16)
                } else {
                    (sw64(t, i), sw64(s, i), 32)
                };
                let is_sub = matches!(
                    insn,
                    Insn::Vsubub64
                        | Insn::Vsubub64Sat
                        | Insn::Vsubh64
                        | Insn::Vsubh64Sat
                        | Insn::Vsubuh64Sat
                        | Insn::Vsubw64
                        | Insn::Vsubw64Sat
                );
                let v = if is_sub { av - bv } else { bv + av };
                let sat = matches!(
                    insn,
                    Insn::Vaddub64Sat
                        | Insn::Vaddh64Sat
                        | Insn::Vadduh64Sat
                        | Insn::Vaddw64Sat
                        | Insn::Vsubub64Sat
                        | Insn::Vsubh64Sat
                        | Insn::Vsubuh64Sat
                        | Insn::Vsubw64Sat
                );
                let unsigned = matches!(
                    insn,
                    Insn::Vaddub64Sat | Insn::Vadduh64Sat | Insn::Vsubub64Sat | Insn::Vsubuh64Sat
                );
                let v = if sat {
                    if unsigned {
                        usatn(b, v, bits)
                    } else {
                        satn(b, v, bits)
                    }
                } else {
                    (v as u64) & ((1u64 << bits) - 1)
                };
                r |= (v & ((1u64 << bits) - 1)) << (bits * i);
            }
            pkt_w64(b, ops[0] as u32, r);
        }
        Insn::Vavgub64
        | Insn::Vavgub64Rnd
        | Insn::Vavguh64
        | Insn::Vavguh64Rnd
        | Insn::Vavgh64
        | Insn::Vavgh64Rnd
        | Insn::Vavgh64Crnd
        | Insn::Vavgw64
        | Insn::Vavgw64Rnd
        | Insn::Vavgw64Crnd
        | Insn::Vavguw64
        | Insn::Vavguw64Rnd
        | Insn::Vnavgh64
        | Insn::Vnavgh64RndSat
        | Insn::Vnavgh64CrndSat
        | Insn::Vnavgw64
        | Insn::Vnavgw64RndSat
        | Insn::Vnavgw64CrndSat => {
            let s = r64(b, ops[1] as u32);
            let t = r64(b, ops[2] as u32);
            let mut r = 0u64;
            let navg = matches!(
                insn,
                Insn::Vnavgh64
                    | Insn::Vnavgh64RndSat
                    | Insn::Vnavgh64CrndSat
                    | Insn::Vnavgw64
                    | Insn::Vnavgw64RndSat
                    | Insn::Vnavgw64CrndSat
            );
            let (n, bits, unsigned) = if matches!(
                insn,
                Insn::Vavgw64
                    | Insn::Vavgw64Rnd
                    | Insn::Vavgw64Crnd
                    | Insn::Vavguw64
                    | Insn::Vavguw64Rnd
                    | Insn::Vnavgw64
                    | Insn::Vnavgw64RndSat
                    | Insn::Vnavgw64CrndSat
            ) {
                (2, 32, matches!(insn, Insn::Vavguw64 | Insn::Vavguw64Rnd))
            } else if matches!(insn, Insn::Vavgub64 | Insn::Vavgub64Rnd) {
                (8, 8, true)
            } else {
                (4, 16, matches!(insn, Insn::Vavguh64 | Insn::Vavguh64Rnd))
            };
            let rnd = matches!(
                insn,
                Insn::Vavgub64Rnd
                    | Insn::Vavguh64Rnd
                    | Insn::Vavgh64Rnd
                    | Insn::Vavgw64Rnd
                    | Insn::Vavguw64Rnd
                    | Insn::Vnavgh64RndSat
                    | Insn::Vnavgw64RndSat
            );
            let crnd = matches!(
                insn,
                Insn::Vavgh64Crnd
                    | Insn::Vavgw64Crnd
                    | Insn::Vnavgh64CrndSat
                    | Insn::Vnavgw64CrndSat
            );
            let sat = matches!(
                insn,
                Insn::Vnavgh64RndSat
                    | Insn::Vnavgh64CrndSat
                    | Insn::Vnavgw64RndSat
                    | Insn::Vnavgw64CrndSat
            );
            for i in 0..n {
                let (av, bv) = if bits == 32 {
                    (
                        if unsigned {
                            uw64(t, i) as i64
                        } else {
                            sw64(t, i)
                        },
                        if unsigned {
                            uw64(s, i) as i64
                        } else {
                            sw64(s, i)
                        },
                    )
                } else if bits == 16 {
                    (
                        if unsigned {
                            (t >> (16 * i)) as u16 as i64
                        } else {
                            sh64(t, i)
                        },
                        if unsigned {
                            (s >> (16 * i)) as u16 as i64
                        } else {
                            sh64(s, i)
                        },
                    )
                } else {
                    (ub64(t, i) as i64, ub64(s, i) as i64)
                };
                let mut v = if navg { av - bv } else { av + bv };
                v = if crnd {
                    f_crnd(v, 1)
                } else {
                    (v + i64::from(rnd)) >> 1
                };
                let v = if sat {
                    satn(b, v, bits)
                } else {
                    v as u64 & ((1u64 << bits) - 1)
                };
                r |= (v & ((1u64 << bits) - 1)) << (bits * i);
            }
            pkt_w64(b, ops[0] as u32, r);
        }
        Insn::Vmaxub64
        | Insn::Vmaxb64
        | Insn::Vmaxuh64
        | Insn::Vmaxh64
        | Insn::Vmaxw64
        | Insn::Vmaxuw64
        | Insn::Vminub64
        | Insn::Vminb64
        | Insn::Vminuh64
        | Insn::Vminh64
        | Insn::Vminw64
        | Insn::Vminuw64 => {
            let s = r64(b, ops[1] as u32);
            let t = r64(b, ops[2] as u32);
            let mut r = 0u64;
            let (n, bits, unsigned, ismax) = match insn {
                Insn::Vmaxub64 => (8, 8, true, true),
                Insn::Vmaxb64 => (8, 8, false, true),
                Insn::Vmaxuh64 => (4, 16, true, true),
                Insn::Vmaxh64 => (4, 16, false, true),
                Insn::Vmaxw64 => (2, 32, false, true),
                Insn::Vmaxuw64 => (2, 32, true, true),
                Insn::Vminub64 => (8, 8, true, false),
                Insn::Vminb64 => (8, 8, false, false),
                Insn::Vminuh64 => (4, 16, true, false),
                Insn::Vminh64 => (4, 16, false, false),
                Insn::Vminw64 => (2, 32, false, false),
                _ => (2, 32, true, false),
            };
            for i in 0..n {
                let (av, bv) = if unsigned {
                    (
                        if bits == 8 {
                            ub64(t, i)
                        } else if bits == 16 {
                            (sh64(t, i) as u16) as u64
                        } else {
                            uw64(t, i)
                        },
                        if bits == 8 {
                            ub64(s, i)
                        } else if bits == 16 {
                            (sh64(s, i) as u16) as u64
                        } else {
                            uw64(s, i)
                        },
                    )
                } else {
                    (
                        if bits == 8 {
                            sb64(t, i) as u64
                        } else if bits == 16 {
                            sh64(t, i) as u64
                        } else {
                            sw64(t, i) as u64
                        },
                        if bits == 8 {
                            sb64(s, i) as u64
                        } else if bits == 16 {
                            sh64(s, i) as u64
                        } else {
                            sw64(s, i) as u64
                        },
                    )
                };
                let v = if unsigned {
                    if ismax { av.max(bv) } else { av.min(bv) }
                } else if ismax {
                    (av as i64).max(bv as i64) as u64
                } else {
                    (av as i64).min(bv as i64) as u64
                };
                r |= (v & ((1u64 << bits) - 1)) << (bits * i);
            }
            pkt_w64(b, ops[0] as u32, r);
        }
        // ---- 整列・交差・複製 ----
        Insn::Vmux => {
            let p = p_get(b, ops[1] as u32);
            let s = r64(b, ops[2] as u32);
            let t = r64(b, ops[3] as u32);
            let mut r = 0u64;
            for i in 0..8 {
                r |= (if p >> i & 1 != 0 {
                    ub64(s, i)
                } else {
                    ub64(t, i)
                }) << (8 * i);
            }
            pkt_w64(b, ops[0] as u32, r);
        }
        Insn::ValignbI => {
            let s = r64(b, ops[1] as u32);
            let t = r64(b, ops[2] as u32);
            let u = ops[3] as u32 & 7;
            let v = (s >> (u * 8)) | (t << ((8 - u) * 8));
            pkt_w64(b, ops[0] as u32, v);
        }
        Insn::ValignbP => {
            let s = r64(b, ops[2] as u32);
            let t = r64(b, ops[3] as u32);
            let u = u32::from(p_get(b, ops[1] as u32) & 7);
            let v = (s >> (u * 8)) | (t << ((8 - u) * 8));
            pkt_w64(b, ops[0] as u32, v);
        }
        Insn::VsplicebI => {
            let s = r64(b, ops[1] as u32);
            let t = r64(b, ops[2] as u32);
            let u = ops[3] as u32 & 7;
            let v = (t << (u * 8)) | (s & if u == 0 { 0 } else { (1u64 << (u * 8)) - 1 });
            pkt_w64(b, ops[0] as u32, v);
        }
        Insn::VsplicebP => {
            let s = r64(b, ops[2] as u32);
            let t = r64(b, ops[3] as u32);
            let u = u32::from(p_get(b, ops[1] as u32) & 7);
            let v = (t << (u * 8)) | (s & if u == 0 { 0 } else { (1u64 << (u * 8)) - 1 });
            pkt_w64(b, ops[0] as u32, v);
        }
        Insn::Vcnegh => {
            let s = r64(b, ops[1] as u32);
            let t = r_get(b, ops[2] as u32);
            let mut r = 0u64;
            for i in 0..4 {
                let v = if t >> i & 1 != 0 {
                    satq(-sh64(s, i), 16)
                } else {
                    sh64(s, i) as u64 & 0xffff
                };
                r |= (v & 0xffff) << (16 * i);
            }
            pkt_w64(b, ops[0] as u32, r);
        }
        Insn::Vrcnegh => {
            let x = ops[0] as u32;
            let s = r64(b, ops[1] as u32);
            let t = r_get(b, ops[2] as u32);
            let mut r = r64(b, x);
            for i in 0..4 {
                let v = if t >> i & 1 != 0 {
                    -sh64(s, i)
                } else {
                    sh64(s, i)
                };
                r = r.wrapping_add(v as u64);
            }
            pkt_w64(b, x, r);
        }
        Insn::Interleave => pkt_w64(b, ops[0] as u32, f_interleave(r64(b, ops[1] as u32))),
        Insn::Deinterleave => pkt_w64(b, ops[0] as u32, f_deinterleave(r64(b, ops[1] as u32))),
        Insn::Lfs => {
            let s = r64(b, ops[1] as u32);
            let t = r64(b, ops[2] as u32);
            let v = (s >> 1) | (u64::from((s & t).count_ones() & 1) << 63);
            pkt_w64(b, ops[0] as u32, v);
        }
        Insn::Vtrunehb => {
            let s = r64(b, ops[1] as u32);
            let r = pack4(ub64(s, 0), ub64(s, 2), ub64(s, 4), ub64(s, 6));
            pkt_w(b, ops[0] as u32, r);
        }
        Insn::Vtrunohb => {
            let s = r64(b, ops[1] as u32);
            let r = pack4(ub64(s, 1), ub64(s, 3), ub64(s, 5), ub64(s, 7));
            pkt_w(b, ops[0] as u32, r);
        }
        Insn::Vtrunewh => {
            let s = r64(b, ops[1] as u32);
            let t = r64(b, ops[2] as u32);
            let r = (t & 0xffff)
                | ((t >> 16) & 0xffff_0000_0000)
                | ((s & 0xffff) << 32)
                | ((s >> 16) & 0xffff_0000_0000_0000);
            pkt_w64(b, ops[0] as u32, r);
        }
        Insn::Vtrunowh => {
            let s = r64(b, ops[1] as u32);
            let t = r64(b, ops[2] as u32);
            let r = ((t >> 16) & 0xffff)
                | ((t >> 32) & 0xffff_0000)
                | ((s >> 16) & 0xffff_0000_0000)
                | ((s >> 48) & 0xffff) << 48;
            pkt_w64(b, ops[0] as u32, r);
        }
        Insn::VtrunehbP => {
            let s = r64(b, ops[1] as u32);
            let t = r64(b, ops[2] as u32);
            let lo = pack4(ub64(t, 0), ub64(t, 2), ub64(t, 4), ub64(t, 6));
            let hi = pack4(ub64(s, 0), ub64(s, 2), ub64(s, 4), ub64(s, 6));
            pkt_w64(b, ops[0] as u32, (u64::from(hi) << 32) | u64::from(lo));
        }
        Insn::VtrunohbP => {
            let s = r64(b, ops[1] as u32);
            let t = r64(b, ops[2] as u32);
            let lo = pack4(ub64(t, 1), ub64(t, 3), ub64(t, 5), ub64(t, 7));
            let hi = pack4(ub64(s, 1), ub64(s, 3), ub64(s, 5), ub64(s, 7));
            pkt_w64(b, ops[0] as u32, (u64::from(hi) << 32) | u64::from(lo));
        }
        Insn::Vsplatb => {
            let v = r_get(b, ops[1] as u32) & 0xff;
            pkt_w(b, ops[0] as u32, v * 0x0101_0101);
        }
        Insn::VsplatbP => {
            let v = r_get(b, ops[1] as u32) & 0xff;
            pkt_w64(b, ops[0] as u32, v as u64 * 0x0101_0101_0101_0101);
        }
        Insn::Vsplath => {
            let v = u64::from(r_get(b, ops[1] as u32) & 0xffff);
            pkt_w64(b, ops[0] as u32, v * 0x0001_0001_0001_0001);
        }
        Insn::Vsxtbh => {
            let s = r_get(b, ops[1] as u32);
            let mut r = 0u64;
            for i in 0..4 {
                r |= ((i64::from((s >> (8 * i)) as u8 as i8) as u64) & 0xffff) << (16 * i);
            }
            pkt_w64(b, ops[0] as u32, r);
        }
        Insn::Vsxthw => {
            let s = r_get(b, ops[1] as u32);
            let mut r = 0u64;
            for i in 0..2 {
                r |= ((i64::from(((s >> (16 * i)) & 0xffff) as u16 as i16) as u64) & 0xffff_ffff)
                    << (32 * i);
            }
            pkt_w64(b, ops[0] as u32, r);
        }
        Insn::Vzxtbh => {
            let s = r_get(b, ops[1] as u32);
            let mut r = 0u64;
            for i in 0..4 {
                r |= (u64::from((s >> (8 * i)) & 0xff)) << (16 * i);
            }
            pkt_w64(b, ops[0] as u32, r);
        }
        Insn::Vzxthw => {
            let s = r_get(b, ops[1] as u32);
            let mut r = 0u64;
            for i in 0..2 {
                r |= (u64::from((s >> (16 * i)) & 0xffff)) << (32 * i);
            }
            pkt_w64(b, ops[0] as u32, r);
        }

        // extender はフェッチ層で対結合済み。単独では来ない。
        Insn::Immext => return Err(trap(TRAP_ILL)),
        // ---- duplex subinsn（13 ビット語）----
        Insn::DxL1Memw => {
            let ea = dxr_get(b, ops[1]).wrapping_add((ops[2] as u32) << 2);
            let v = b.load::<W32>(u64::from(ea), DRD)?;
            pkt_w(b, dxr(ops[0]), v);
        }
        Insn::DxL1Memub => {
            let ea = dxr_get(b, ops[1]).wrapping_add(ops[2] as u32);
            let v = b.load::<W8>(u64::from(ea), DRD)?;
            pkt_w(b, dxr(ops[0]), u32::from(v));
        }
        Insn::DxL2Memh => {
            let ea = dxr_get(b, ops[1]).wrapping_add((ops[2] as u32) << 1);
            let v = b.load::<W16>(u64::from(ea), DRD)?;
            pkt_w(b, dxr(ops[0]), sext(u64::from(v), 16));
        }
        Insn::DxL2Memuh => {
            let ea = dxr_get(b, ops[1]).wrapping_add((ops[2] as u32) << 1);
            let v = b.load::<W16>(u64::from(ea), DRD)?;
            pkt_w(b, dxr(ops[0]), u32::from(v));
        }
        Insn::DxL2Memb => {
            let ea = dxr_get(b, ops[1]).wrapping_add(ops[2] as u32);
            let v = b.load::<W8>(u64::from(ea), DRD)?;
            pkt_w(b, dxr(ops[0]), sext(u64::from(v), 8));
        }
        Insn::DxL2Ldwsp => {
            let ea = r_get(b, 29).wrapping_add((ops[1] as u32) << 2);
            let v = b.load::<W32>(u64::from(ea), DRD)?;
            pkt_w(b, dxr(ops[0]), v);
        }
        Insn::DxL2Lddsp => {
            let ea = r_get(b, 29).wrapping_add((ops[1] as u32) << 3);
            let v = b.load::<W64>(u64::from(ea), DRD)?;
            let lo = dxp(ops[0]);
            pkt_w(b, lo, v as u32);
            pkt_w(b, lo + 1, (v >> 32) as u32);
        }
        Insn::DxL2Jumpr => jump(b, r_get(b, 31)),
        // frame 系（HX7）。duplex の deallocframe/dealloc_return は
        // `r31:30 = ...(r30)` 相当、allocframe は Rx=r29 固定。
        Insn::DxL2Deallocframe => dealloc_to(b, 30, 30, false)?,
        Insn::DxL2Deallocret => dealloc_to(b, 30, 30, true)?,
        Insn::DxS2Allocframe => {
            let frame = (ops[0] as u32) << 3;
            let ea = r_get(b, 29).wrapping_sub(8);
            let pair = u64::from(r_get(b, 30)) | (u64::from(r_get(b, 31)) << 32);
            b.store::<W64>(u64::from(ea), pair, DWR)?;
            pkt_w(b, 30, ea);
            pkt_w(b, 29, ea.wrapping_sub(frame));
        }
        Insn::DxS1Memw => {
            let ea = dxr_get(b, ops[0]).wrapping_add((ops[2] as u32) << 2);
            b.store::<W32>(u64::from(ea), dxr_get(b, ops[1]), DWR)?;
        }
        Insn::DxS1Memb => {
            let ea = dxr_get(b, ops[0]).wrapping_add(ops[2] as u32);
            b.store::<W8>(u64::from(ea), dxr_get(b, ops[1]) as u8, DWR)?;
        }
        Insn::DxS2Memh => {
            let ea = dxr_get(b, ops[0]).wrapping_add((ops[2] as u32) << 1);
            b.store::<W16>(u64::from(ea), dxr_get(b, ops[1]) as u16, DWR)?;
        }
        Insn::DxS2Stwsp => {
            let ea = r_get(b, 29).wrapping_add((ops[1] as u32) << 2);
            b.store::<W32>(u64::from(ea), dxr_get(b, ops[0]), DWR)?;
        }
        Insn::DxS2Stdsp => {
            let ea = r_get(b, 29).wrapping_add(sext(ops[1], 6) << 3);
            let lo = dxp(ops[0]);
            let v = u64::from(r_get(b, lo)) | (u64::from(r_get(b, lo + 1)) << 32);
            b.store::<W64>(u64::from(ea), v, DWR)?;
        }
        Insn::DxS2Stwi => {
            let ea = dxr_get(b, ops[0]).wrapping_add((ops[1] as u32) << 2);
            b.store::<W32>(u64::from(ea), ops[2] as u32, DWR)?;
        }
        Insn::DxS2Stbi => {
            let ea = dxr_get(b, ops[0]).wrapping_add(ops[1] as u32);
            b.store::<W8>(u64::from(ea), ops[2] as u8, DWR)?;
        }
        Insn::DxAAddi => {
            let x = dxr(ops[0]);
            pkt_w(b, x, r_get(b, x).wrapping_add(ximm(cx.ext, ops[1], 0, 7)));
        }
        Insn::DxAUimm => {
            let v = match cx.ext {
                Some(e) => packet::apply_ext(e, ops[1] as u32 & 0x3f),
                None => ops[1] as u32,
            };
            pkt_w(b, dxr(ops[0]), v);
        }
        Insn::DxASpadd => pkt_w(
            b,
            dxr(ops[0]),
            r_get(b, 29).wrapping_add((ops[1] as u32) << 2),
        ),
        Insn::DxAMov => pkt_w(b, dxr(ops[0]), dxr_get(b, ops[1])),
        Insn::DxAAdd1 => pkt_w(b, dxr(ops[0]), dxr_get(b, ops[1]).wrapping_add(1)),
        Insn::DxAAnd1 => pkt_w(b, dxr(ops[0]), dxr_get(b, ops[1]) & 1),
        Insn::DxASub1 => pkt_w(b, dxr(ops[0]), dxr_get(b, ops[1]).wrapping_sub(1)),
        Insn::DxASxth => pkt_w(b, dxr(ops[0]), sext(dxr_get(b, ops[1]) as u64, 16)),
        Insn::DxASxtb => pkt_w(b, dxr(ops[0]), sext(dxr_get(b, ops[1]) as u64, 8)),
        Insn::DxAZxth => pkt_w(b, dxr(ops[0]), dxr_get(b, ops[1]) & 0xffff),
        Insn::DxAZxtb => pkt_w(b, dxr(ops[0]), dxr_get(b, ops[1]) & 0xff),
        Insn::DxAAddr => {
            let d = dxr(ops[0]);
            pkt_w(b, d, r_get(b, d).wrapping_add(dxr_get(b, ops[1])));
        }
        Insn::DxACmpeq => {
            let v = dxr_get(b, ops[0]) == ops[1] as u32;
            pkt_pw(b, 0, if v { 0xff } else { 0 });
        }
        Insn::DxAClr => {
            // dprd=0 は無条件の `Rd=#-1`、述語選択形は条件クリア
            // （dot-if の判定は冒頭で済み）。
            let v = if ops[1] == 0 { u32::MAX } else { 0 };
            pkt_w(b, dxr(ops[0]), v);
        }
        Insn::DxACombi => {
            let lo = dxp(ops[0]);
            pkt_w(b, lo, ops[2] as u32);
            pkt_w(b, lo + 1, ops[1] as u32);
        }
        Insn::DxAComb0 => {
            let lo = dxp(ops[0]);
            pkt_w(b, lo, dxr_get(b, ops[1]));
            pkt_w(b, lo + 1, 0);
        }
        Insn::DxAComb1 => {
            let lo = dxp(ops[0]);
            pkt_w(b, lo, 0);
            pkt_w(b, lo + 1, dxr_get(b, ops[1]));
        }
        // ---- HX9: HVX 代表部分集合 ----
        // v/q の書き込みはパケット同時発行に合わせて未確定域へ
        // 溜める（pkt_v/pkt_q。commit で一括反映）。読みは常に
        // パケット開始時の確定値（vtmp/.new のベクトル前読みは
        // 語彙外）。Ref: 80-N2040-61 (HVX).
        Insn::HvldIo | Insn::HvldIont => {
            // EA = Rs + s4*ベクトル幅（128B）。
            let ea =
                r_get(b, ops[1] as u32).wrapping_add(sext(ops[2], 4).wrapping_mul(VL as u32 * 4));
            v_ld(b, ops[0] as u32, ea, true)?;
        }
        Insn::HvstIo | Insn::HvstIont => {
            let ea =
                r_get(b, ops[1] as u32).wrapping_add(sext(ops[2], 4).wrapping_mul(VL as u32 * 4));
            v_st(b, ea, ops[0] as u32, true, None)?;
        }
        Insn::HvlduIo => {
            v_ld(b, ops[0] as u32, r_get(b, ops[1] as u32), false)?;
        }
        Insn::HvstuIo => {
            v_st(b, r_get(b, ops[1] as u32), ops[0] as u32, false, None)?;
        }
        Insn::HvstIopq | Insn::HvstIopqnt => {
            // Qv の各ビットが対応バイトの書き込み可否。否定形
            // （if(!Qv)）はビット反転したマスクで書く。
            let mut m = q_get(b, ops[3] as u32);
            if ops[4] != 0 {
                m = !m;
            }
            let ea =
                r_get(b, ops[1] as u32).wrapping_add(sext(ops[2], 4).wrapping_mul(VL as u32 * 4));
            v_st(b, ea, ops[0] as u32, true, Some(m))?;
        }
        Insn::HvldPi => {
            let ea = r_get(b, ops[1] as u32);
            v_ld(b, ops[0] as u32, ea, true)?;
            pkt_w(
                b,
                ops[1] as u32,
                ea.wrapping_add(sext(ops[2], 3).wrapping_mul(VL as u32 * 4)),
            );
        }
        Insn::HvstPi => {
            let ea = r_get(b, ops[1] as u32);
            v_st(b, ea, ops[0] as u32, true, None)?;
            pkt_w(
                b,
                ops[1] as u32,
                ea.wrapping_add(sext(ops[2], 3).wrapping_mul(VL as u32 * 4)),
            );
        }
        Insn::HvldPr | Insn::HvldPrnt => {
            let ea = r_get(b, ops[1] as u32);
            v_ld(b, ops[0] as u32, ea, true)?;
            pkt_w(b, ops[1] as u32, ea.wrapping_add(mu(b, ops[2])));
        }
        Insn::HvstPr => {
            let ea = r_get(b, ops[1] as u32);
            v_st(b, ea, ops[0] as u32, true, None)?;
            pkt_w(b, ops[1] as u32, ea.wrapping_add(mu(b, ops[2])));
        }
        Insn::HvVaddB => vop3(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            1,
            false,
            |x, y| x + y,
        ),
        Insn::HvVaddH => vop3(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            2,
            false,
            |x, y| x + y,
        ),
        Insn::HvVaddW => vop3(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            4,
            false,
            |x, y| x + y,
        ),
        Insn::HvVsubB => vop3(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            1,
            false,
            |x, y| x - y,
        ),
        Insn::HvVsubH => vop3(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            2,
            false,
            |x, y| x - y,
        ),
        Insn::HvVsubW => vop3(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            4,
            false,
            |x, y| x - y,
        ),
        Insn::HvVand | Insn::HvVor | Insn::HvVxor => {
            let a = v_get(b, ops[1] as u32);
            let c = v_get(b, ops[2] as u32);
            let mut r = [0u32; VL];
            for i in 0..VL {
                r[i] = match insn {
                    Insn::HvVand => a[i] & c[i],
                    Insn::HvVor => a[i] | c[i],
                    _ => a[i] ^ c[i],
                };
            }
            pkt_vw(b, ops[0] as u32, &r);
        }
        Insn::HvVavgB => vop3(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            1,
            true,
            |x, y| (x + y) >> 1,
        ),
        Insn::HvVavgUb => vop3(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            1,
            false,
            |x, y| (x + y) >> 1,
        ),
        Insn::HvVavgH => vop3(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            2,
            true,
            |x, y| (x + y) >> 1,
        ),
        Insn::HvVavgUh => vop3(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            2,
            false,
            |x, y| (x + y) >> 1,
        ),
        Insn::HvVavghr => vop3(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            2,
            true,
            |x, y| (x + y + 1) >> 1,
        ),
        Insn::HvVnavgH => vop3(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            2,
            true,
            |x, y| (x - y) >> 1,
        ),
        Insn::HvVminB => vminmax(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            1,
            true,
            true,
        ),
        Insn::HvVminUb => vminmax(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            1,
            false,
            true,
        ),
        Insn::HvVminH => vminmax(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            2,
            true,
            true,
        ),
        Insn::HvVminUh => vminmax(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            2,
            false,
            true,
        ),
        Insn::HvVminW => vminmax(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            4,
            true,
            true,
        ),
        Insn::HvVmaxB => vminmax(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            1,
            true,
            false,
        ),
        Insn::HvVmaxUb => vminmax(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            1,
            false,
            false,
        ),
        Insn::HvVmaxH => vminmax(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            2,
            true,
            false,
        ),
        Insn::HvVmaxUh => vminmax(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            2,
            false,
            false,
        ),
        Insn::HvVmaxW => vminmax(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            4,
            true,
            false,
        ),
        Insn::HvVaddsB => vsat(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            1,
            true,
            false,
        ),
        Insn::HvVaddsUb => vsat(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            1,
            false,
            false,
        ),
        Insn::HvVaddsUh => vsat(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            2,
            false,
            false,
        ),
        Insn::HvVaddsH => vsat(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            2,
            true,
            false,
        ),
        Insn::HvVaddsW => vsat(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            4,
            true,
            false,
        ),
        Insn::HvVaddsUw => vsat(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            4,
            false,
            false,
        ),
        Insn::HvVsubsB => vsat(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            1,
            true,
            true,
        ),
        Insn::HvVsubsUb => vsat(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            1,
            false,
            true,
        ),
        Insn::HvVsubsUh => vsat(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            2,
            false,
            true,
        ),
        Insn::HvVsubsH => vsat(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            2,
            true,
            true,
        ),
        Insn::HvVsubsW => vsat(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            4,
            true,
            true,
        ),
        Insn::HvVmpyBb => vmpy(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            1,
            true,
            false,
        ),
        Insn::HvVmpyUb => vmpy(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            1,
            false,
            false,
        ),
        Insn::HvVmpyHh => vmpy(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            2,
            true,
            false,
        ),
        Insn::HvVmpyUh => vmpy(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            2,
            false,
            false,
        ),
        Insn::HvVmpyBbAcc => vmpy(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            1,
            true,
            true,
        ),
        Insn::HvVmpyUbAcc => vmpy(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            1,
            false,
            true,
        ),
        Insn::HvVmpyHhAcc => vmpy(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            2,
            true,
            true,
        ),
        Insn::HvVmpyUhAcc => vmpy(
            b,
            ops[0] as u32,
            ops[1] as u32,
            ops[2] as u32,
            2,
            false,
            true,
        ),
        Insn::HvVcombine => {
            // Vdd = {Vu 側が奇数（上位）、Vv 側が偶数（下位）}。
            pkt_vw(b, ops[0] as u32, &v_get(b, ops[2] as u32));
            pkt_vw(b, ops[0] as u32 + 1, &v_get(b, ops[1] as u32));
        }
        Insn::HvVmov => pkt_vw(b, ops[0] as u32, &v_get(b, ops[1] as u32)),
        Insn::HvVsplatB | Insn::HvVsplatH => {
            let el = if insn == Insn::HvVsplatB { 1 } else { 2 };
            let x = u64::from(r_get(b, ops[1] as u32)) & ((1 << (el * 8)) - 1);
            let mut r = [0u32; VL];
            for i in 0..VL * 4 / el {
                vset(&mut r, el, i, x);
            }
            pkt_vw(b, ops[0] as u32, &r);
        }
        Insn::HvVinsertW => {
            // Gap: GAP-0071
            // 語彙では `Vd.w = vinsert(Rs)`。要素 0 に Rs、残りを
            // 0 とする代表実装（正確な定義は語彙棚卸し参照）。
            let mut r = [0u32; VL];
            r[0] = r_get(b, ops[1] as u32);
            pkt_vw(b, ops[0] as u32, &r);
        }
        Insn::HvVandq => {
            // q の真偽ビットが立つバイト要素だけ Vs を残す。
            let q = q_get(b, ops[1] as u32);
            let a = v_get(b, ops[2] as u32);
            let mut r = [0u32; VL];
            for i in 0..VL {
                for e in 0..4 {
                    if q >> (i * 4 + e) & 1 != 0 {
                        r[i] |= a[i] & (0xff << (e * 8));
                    }
                }
            }
            pkt_vw(b, ops[0] as u32, &r);
        }
        Insn::HvVcmpeqB => vcmp(b, ops[0] as u32, ops[1] as u32, ops[2] as u32, 1, false),
        Insn::HvVcmpeqH => vcmp(b, ops[0] as u32, ops[1] as u32, ops[2] as u32, 2, false),
        Insn::HvVcmpeqW => vcmp(b, ops[0] as u32, ops[1] as u32, ops[2] as u32, 4, false),
        Insn::HvVcmpgtB => vcmp(b, ops[0] as u32, ops[1] as u32, ops[2] as u32, 1, true),
        Insn::HvVcmpgtH => vcmp(b, ops[0] as u32, ops[1] as u32, ops[2] as u32, 2, true),
        Insn::HvVcmpgtW => vcmp(b, ops[0] as u32, ops[1] as u32, ops[2] as u32, 4, true),
        Insn::HvQand => pkt_qw(
            b,
            ops[0] as u32,
            q_get(b, ops[1] as u32) & q_get(b, ops[2] as u32),
        ),
        Insn::HvQor => pkt_qw(
            b,
            ops[0] as u32,
            q_get(b, ops[1] as u32) | q_get(b, ops[2] as u32),
        ),
        Insn::HvQxor => pkt_qw(
            b,
            ops[0] as u32,
            q_get(b, ops[1] as u32) ^ q_get(b, ops[2] as u32),
        ),
        Insn::HvQorn => pkt_qw(
            b,
            ops[0] as u32,
            q_get(b, ops[1] as u32) | !q_get(b, ops[2] as u32),
        ),
        Insn::HvQandn => pkt_qw(
            b,
            ops[0] as u32,
            q_get(b, ops[1] as u32) & !q_get(b, ops[2] as u32),
        ),
        Insn::HvQnot => pkt_qw(b, ops[0] as u32, !q_get(b, ops[1] as u32)),
    }
    Ok(true)
}
