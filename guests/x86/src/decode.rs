// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! オペコード表デコーダ（`MapDec`）の結果から被演算子の置き場所を
//! 解決する。ModRM/SIB/変位・REX・アドレスサイズをまとめて扱い、
//! 意味論側は `Rm`（レジスタ直接 or 実効アドレス）だけを見る。
//!
//! Ref: SPEC-X86-INTEL-SDM (v093) Vol.2A 2.1.3-2.1.5.

use polyisa_sem::{Backend, Cmp, W8, W16, W32, W64};

use crate::MapDec;
use crate::sem::{Gpr, clear_hi, read64, write64};

/// `wseg` に詰める SS フラグ。実モードの 64K 折り返し・限界検査の
/// 対象アクセスで、アクセスのセグメントが SS なら bit32 を立てる
/// （限界超過の例外は SS なら #SS=12、他は #GP=13）。
pub const WSEG_SS: u64 = 1 << 32;

/// `wseg` に詰める 32 ビットアドレッシング（0x67）フラグ。
/// bit33 が立つとき生オフセットは下位 32 ビットの EA で、折り返し
/// 桁上げは存在しない。限界検査は「最終バイト > 0xFFFF」の単純な
/// 範囲比較になる（80386 実モードの実測規則）。
pub const WSEG_32: u64 = 1 << 33;

/// ModRM の r/m が指す被演算子。
pub enum Rm<V> {
    /// レジスタ直接（mod=11）。
    Reg(Gpr),
    /// メモリ。`a` は実効アドレス（セグメントベース加算済み、
    /// オフセットはアドレス幅で折り返し済み）。
    /// `wseg` が `Some` のとき実モードの限界検査対象で、値は
    /// (セグメントベース | [`WSEG_SS`] | [`WSEG_32`], 生オフセット)。
    /// 16 ビットアドレッシングでは生オフセットは折り返し前の
    /// EA 和で、8 ビットを超えるアクセスはオフセットを 64K で
    /// 折り返す（8086/80186）か限界例外（80286 以降、`seg_limit`
    /// パラメータ）。EA 和が 64K で桁上げしたとき 80286 の限界検査
    /// は発火しない（SST 80286 実測）ので検査には折り返し前の和を
    /// 使う。32 ビットアドレッシング（[`WSEG_32`]）では生オフセット
    /// は下位 32 ビットの EA で、検査は最終バイト > 0xFFFF の
    /// 単純比較（80386 実モード実測）。
    Mem { a: V, wseg: Option<(u64, V)> },
}

/// ModRM reg フィールドのレジスタ（REX.R + REX2/EVEX.map4 R4 込み）。
pub fn reg(d: &MapDec) -> Gpr {
    Gpr(((d.modrm >> 3) & 7) | (((d.rex >> 2) & 1) << 3) | (((d.rex2 >> 6) & 1) << 4))
}

/// ModRM r/m がレジスタ直接のときのレジスタ（REX.B + B4 込み）。
pub fn rm_reg(d: &MapDec) -> Gpr {
    Gpr((d.modrm & 7) | ((d.rex & 1) << 3) | (((d.rex2 >> 4) & 1) << 4))
}

/// ModRM reg フィールドのベクタレジスタ番号（REX.R + EVEX.R' + R4
/// 込み、0-31）。EVEX 項目の reg 被演算子に使う。map4 では P0.4
/// が R4 になるので rex2 側からも 4 ビット目を入れる（両者は
/// 排他なので OR でよい）。
pub fn reg_x5(d: &MapDec) -> u8 {
    ((d.modrm >> 3) & 7)
        | (((d.rex >> 2) & 1) << 3)
        | ((d.evex_r2 as u8) << 4)
        | (((d.rex2 >> 6) & 1) << 4)
}

/// ModRM r/m のベクタレジスタ番号（REX.B + EVEX.X + B4 込み、0-31）。
/// mod=11 でベクタレジスタを指すときだけ使う（GPR 形は `rm_reg`）。
pub fn rm_reg_x5(d: &MapDec) -> u8 {
    (d.modrm & 7) | ((d.rex & 1) << 3) | (((d.rex >> 1) & 1) << 4) | (((d.rex2 >> 4) & 1) << 4)
}

/// +r 形式のレジスタ（オペコード下位3ビット + REX.B + B4）。
/// push/pop などでは B4 が 16-31 を指す。
pub fn op_reg(d: &MapDec) -> Gpr {
    Gpr((d.opcode & 7) | ((d.rex & 1) << 3) | (((d.rex2 >> 4) & 1) << 4))
}

/// グループ選択の reg フィールド値（REX.R なし）。
pub fn group(d: &MapDec) -> u8 {
    (d.modrm >> 3) & 7
}

/// 8ビット被演算子で上位バイト（AH..BH）を指すか。REX があると
/// SPL/BPL/SIL/DIL/R8B-R15B になるので、REX なしの 4-7 のみ。
pub fn high8(d: &MapDec, g: Gpr) -> bool {
    d.rex == 0 && g.0 >= 4
}

/// 8ビット被演算子のエンコーディングを実レジスタと上位バイト選択に写像する。
/// REX なしで 4-7 は AH-DH、つまりベースレジスタ 0-3 の上位バイト。
/// `sem::read8`/`write8` は「そのレジスタの上位バイト」を扱うので、
/// ここで Gpr(4..8) を Gpr(0..4)+high に解決してから渡す。
pub fn reg8(d: &MapDec, g: Gpr) -> (Gpr, bool) {
    if high8(d, g) {
        (Gpr(g.0 - 4), true)
    } else {
        (g, false)
    }
}

/// ModRM/SIB/変位から実効アドレスを求める。mod=11 は `Rm::Reg`。
/// `seg` はセグメントベース（上書き接頭辞由来、なければ 0）。
/// `seg_ss` はそのアクセスの既定セグメントが SS か（実モードの
/// 限界例外の種別に使う）。`real16` は実モード実行かどうか。偽なら
/// 16 ビットアドレッシングでも 64K 折り返し・実モード限界検査は
/// 適用しない（保護モードの 0x67 でも `d.asize` は 16 になり得る）。
pub fn rm_of<B: Backend>(
    b: &mut B,
    d: &MapDec,
    next_rip: u64,
    seg: u64,
    seg_ss: bool,
    real16: bool,
) -> Rm<B::V<W64>> {
    let m = d.modrm;
    if m >> 6 == 3 {
        return Rm::Reg(rm_reg(d));
    }
    let rm = m & 7;
    let mut raw16 = None;
    let mut raw32 = None;
    let mut a: B::V<W64> = if d.asize == 16 {
        let (off, raw) = ea16(b, m, d.disp);
        raw16 = Some(raw);
        off
    } else if rm == 4 {
        ea_sib(b, m, d, next_rip)
    } else if m >> 6 == 0 && rm == 5 {
        // mod=00 r/m=101：RIP 相対（64）か絶対 disp32（32）。
        let base = if d.asize == 64 { next_rip } else { 0 };
        b.konst::<W64>((base as i64).wrapping_add(d.disp) as u64)
    } else {
        ea_base_disp(b, d.asize, rm, d.rex, d.rex2, d.disp)
    };
    if real16 && d.asize == 32 {
        // 0x67 の 32 ビット EA は 2^32 で折り返す（折り返し前の
        // 生オフセットとしてもこの値を使う）。
        let m32 = b.konst::<W64>(0xFFFF_FFFF);
        let t = b.and::<W64>(a, m32);
        raw32 = Some(t);
        a = t;
    }
    if seg != 0 {
        let s = b.konst::<W64>(seg);
        a = b.add::<W64>(a, s);
    }
    let wseg = if real16 {
        let seg = seg | if seg_ss { WSEG_SS } else { 0 };
        match d.asize {
            16 => Some((seg, raw16.unwrap())),
            32 => Some((seg | WSEG_32, raw32.unwrap())),
            _ => None,
        }
    } else {
        None
    };
    Rm::Mem { a, wseg }
}

/// 16ビットアドレッシング（実モード・286）。BX+SI 等の固定表。
/// 戻り値は (64K 折り返し済みのオフセット, 折り返し前の和)。和は
/// 16 ビット加算器のモデルで、変位は 16 ビットに切って足す
/// （disp8=-1 は 0xFFFF として加算）。桁上げの有無は後段の
/// セグメント限界検査が使う。
fn ea16<B: Backend>(b: &mut B, m: u8, disp: i64) -> (B::V<W64>, B::V<W64>) {
    let rm = m & 7;
    // (base, index) のレジスタ番号。None はなし。
    let (base, idx): (Option<u8>, Option<u8>) = match rm {
        0 => (Some(3), Some(6)),          // BX+SI
        1 => (Some(3), Some(7)),          // BX+DI
        2 => (Some(5), Some(6)),          // BP+SI
        3 => (Some(5), Some(7)),          // BP+DI
        4 => (None, Some(6)),             // SI
        5 => (None, Some(7)),             // DI
        6 if m >> 6 == 0 => (None, None), // disp16 のみ
        6 => (Some(5), None),             // BP
        _ => (Some(3), None),             // BX
    };
    let r16 = |b: &mut B, i: u8| -> B::V<W32> {
        let v: B::V<W32> = b.get(Gpr(i).state());
        let m = b.konst::<W32>(0xFFFF);
        b.and::<W32>(v, m)
    };
    let mut s = b.konst::<W32>(0);
    if let Some(i) = base {
        let t = r16(b, i);
        s = b.add::<W32>(s, t);
    }
    if let Some(i) = idx {
        let t = r16(b, i);
        s = b.add::<W32>(s, t);
    }
    let dv = b.konst::<W32>(disp as u16 as u32);
    s = b.add::<W32>(s, dv);
    let off = b.trunc::<W32, W16>(s);
    (b.zext::<W16, W64>(off), b.zext::<W32, W64>(s))
}

/// SIB 付き実効アドレス（32/64）。mod=00 base=101 は disp32 のみ。
/// APX では index=100b+X4 が r20/r28、base=101+B4 が r21 になる
/// （B4=1 のとき disp32 なしのベース付き形になる）。
fn ea_sib<B: Backend>(b: &mut B, m: u8, d: &MapDec, _next_rip: u64) -> B::V<W64> {
    let s = d.sib;
    let idx_raw = (s >> 3) & 7;
    let no_index = idx_raw == 4 && (d.rex >> 1) & 1 == 0 && (d.rex2 >> 5) & 1 == 0;
    let idx = idx_raw | (((d.rex >> 1) & 1) << 3) | (((d.rex2 >> 5) & 1) << 4);
    let base_raw = s & 7;
    let base_reg = Gpr(base_raw | ((d.rex & 1) << 3) | (((d.rex2 >> 4) & 1) << 4));
    // mod=00 base=101 は B4=0 のときだけベースなし+disp32。
    // B4=1 なら r21 をベースにした通常形（disp は mod どおり）。
    let no_base = m >> 6 == 0 && base_raw == 5 && (d.rex2 >> 4) & 1 == 0;
    let scale = s >> 6;
    let wide = d.asize == 64;
    let mut a = if no_base {
        b.konst::<W64>(d.disp as u64)
    } else if no_index && scale != 0 && !wide {
        // 386 の未定義 SIB 形式（index=100b かつ scale>0）では
        // スケールがベースレジスタに適用され、
        // EA = base << scale + disp になる（SST 80386 実測）。
        let bv = ea_base(b, wide, base_reg);
        let sh = b.konst::<W64>(u64::from(scale));
        let v: B::V<W32> = b.trunc::<W64, W32>(bv);
        let sh32: B::V<W32> = b.trunc::<W64, W32>(sh);
        let t = b.shl::<W32>(v, sh32);
        b.zext::<W32, W64>(t)
    } else {
        ea_base(b, wide, base_reg)
    };
    if !no_index {
        let iv = ea_base(b, wide, Gpr(idx));
        let sh = b.konst::<W64>(u64::from(scale));
        let iv = if wide {
            b.shl::<W64>(iv, sh)
        } else {
            let v: B::V<W32> = b.trunc::<W64, W32>(iv);
            let sh32: B::V<W32> = b.trunc::<W64, W32>(sh);
            let t = b.shl::<W32>(v, sh32);
            b.zext::<W32, W64>(t)
        };
        a = b.add::<W64>(a, iv);
    }
    if !no_base {
        let dv = b.konst::<W64>(d.disp as u64);
        a = b.add::<W64>(a, dv);
    }
    a
}

/// base+disp の実効アドレス（32/64、非 SIB・非 RIP 相対）。
fn ea_base_disp<B: Backend>(
    b: &mut B,
    asize: u8,
    rm: u8,
    rex: u8,
    rex2: u8,
    disp: i64,
) -> B::V<W64> {
    let base = Gpr(rm | ((rex & 1) << 3) | (((rex2 >> 4) & 1) << 4));
    let mut a = ea_base(b, asize == 64, base);
    let dv = b.konst::<W64>(disp as u64);
    a = b.add::<W64>(a, dv);
    a
}

/// レジスタ値をアドレス幅で読む。32 幅は下位のみで上位はゼロ。
fn ea_base<B: Backend>(b: &mut B, wide: bool, g: Gpr) -> B::V<W64> {
    if wide {
        read64(b, g)
    } else {
        let v: B::V<W32> = b.get(g.state());
        b.zext::<W32, W64>(v)
    }
}

/// VSIB メモリオペランド（gather 系）。戻り値は
/// (ベース値・なければ 0, スケール指数 0-3, 変位, ベクトルindex番号)。
/// mod=00 base=101 はベースなし+disp32。`Rm::Mem` の `a` は
/// index を GPR として計算したものなので、VSIB では使わず
/// この関数で要素ごとのアドレスを組み立てる。
pub fn vsib<B: Backend>(b: &mut B, d: &MapDec) -> (B::V<W64>, u8, i64, u8) {
    let s = d.sib;
    let scale = s >> 6;
    let idx = ((s >> 3) & 7) | (((d.rex >> 1) & 1) << 3) | (((d.rex2 >> 5) & 1) << 4);
    let base_raw = s & 7;
    let no_base = d.modrm >> 6 == 0 && base_raw == 5 && (d.rex2 >> 4) & 1 == 0;
    let base = if no_base {
        b.konst::<W64>(0)
    } else {
        ea_base(
            b,
            d.asize == 64,
            Gpr(base_raw | ((d.rex & 1) << 3) | (((d.rex2 >> 4) & 1) << 4)),
        )
    };
    (base, scale, d.disp, idx)
}

// ---- レジスタ・メモリの読み書き ----

/// `wseg` のうちアクセスを起こした側のセグメント種別に応じた
/// 限界超過例外を起こす（`seg_limit` = fault の世代。80286 以降の
/// 実モード）。SS 由来は `stack_fault` で #SS(12)/#GP(13) を選ぶ
/// （80286 はすべて #GP）。判定するオフセットは wrap 前の値で、
/// 最終バイトが 0xFFFF を越えるとき。
pub(crate) fn seg_limit_chk<B: Backend, W: Hw>(
    b: &mut B,
    off: B::V<W64>,
    wseg: u64,
) -> Result<(), B::Exit> {
    seg_limit_chk_n(b, off, wseg, u64::from(W::BITS / 8))
}

/// `nbytes` バイトのアクセスについて `wseg` の限界超過例外を起こす。
/// [`seg_limit_chk`] の幅非依存版（m80 などの奇数長アクセス用）。
pub fn seg_limit_chk_n<B: Backend>(
    b: &mut B,
    off: B::V<W64>,
    wseg: u64,
    nbytes: u64,
) -> Result<(), B::Exit> {
    use polyisa_sem::{ExceptionKind, GuestException};
    if b.param::<crate::SegLimitParam>() != crate::SEG_LIMIT_FAULT {
        return Ok(());
    }
    let over = if wseg & WSEG_32 != 0 {
        // 32 ビットアドレッシング: オフセットは折り返さないので
        // 単純に最終バイトが 0xFFFF を越えるかを見る
        // （off + nbytes - 1 > 0xFFFF ⟺ off > 0x1_0000 - nbytes）。
        let lim = b.konst::<W64>(0x1_0000 - nbytes);
        b.cmp::<W64>(Cmp::GtU, off, lim)
    } else if b.param::<crate::FaultAtomicParam>() == crate::FAULT_ATOMIC_ATOMIC {
        // 80386 以降: アクセスはまずオフセットを 64K で折り、その
        // 折り返し済みオフセットの最終バイトが 0xFFFF を越えるとき
        // 例外になる。EA 和の桁上げ（bp+si=0x1_FFFE 等）で 0xFFFF
        // 直上に着いたアクセスも跨ぎ判定になる（SST 80386 実測。
        // 80286 は桁上げ側を例外にしないので `fault_atomic` で分ける）。
        let m = b.konst::<W64>(0xFFFF);
        let offm = b.and::<W64>(off, m);
        let lim = b.konst::<W64>(0x1_0000 - nbytes);
        b.cmp::<W64>(Cmp::GtU, offm, lim)
    } else {
        // 最終バイトのオフセットが 0xFFFF を越えるか。閾値は
        // 0x1_0001 - size。ただしオフセット自身が 0xFFFF を越える
        // （EA 和の桁上げ）場合は例外にならない（SST 80286 実測）。
        // thr <= off <= 0xFFFF は off - thr <= size-2 と同値で
        // 1 回の比較で済む。
        let thr = b.konst::<W64>(0x1_0001 - nbytes);
        let dt = b.sub::<W64>(off, thr);
        let sp = b.konst::<W64>(nbytes.saturating_sub(2));
        b.cmp::<W64>(Cmp::LeU, dt, sp)
    };
    let ss_vec = if b.param::<crate::StackFaultParam>() == crate::STACK_FAULT_GP {
        13u8
    } else {
        12u8
    };
    let vec = u64::from(if wseg & WSEG_SS != 0 { ss_vec } else { 13u8 });
    b.if_then(over, |b| {
        Err(b.raise(GuestException {
            kind: ExceptionKind::Trap,
            code: vec,
            addr: None,
            in_delay_slot: false,
        }))
    })
}

/// `wseg` の 64K 折り返しで `off`（折り返し前の EA 和）から i バイト目の
/// 番地を返す。`wseg` が無いときは `a + i`。
/// 複数バイトアクセスは先に [`seg_limit_chk_n`] で限界を確認すること。
pub fn wseg_byte_addr<B: Backend>(
    b: &mut B,
    a: B::V<W64>,
    wseg: Option<(B::V<W64>, B::V<W64>)>,
    i: u64,
) -> B::V<W64> {
    let iv = b.konst::<W64>(i);
    let Some((off, sv)) = wseg else {
        return b.add::<W64>(a, iv);
    };
    let t = b.add::<W64>(off, iv);
    let lim = b.konst::<W64>(0xFFFF);
    let o = b.and::<W64>(t, lim);
    b.add::<W64>(o, sv)
}

/// `wseg` と折り返し済み番地 `a` から折り返し前の EA 和とセグメント
/// 基底を取り出す（`wseg_byte_addr`・`seg_limit_chk_n` の入力）。
/// `wseg` が無いときは `None`。
pub fn wseg_off<B: Backend>(
    b: &mut B,
    a: B::V<W64>,
    wseg: Option<(u64, B::V<W64>)>,
) -> Option<(B::V<W64>, B::V<W64>)> {
    let (seg, raw) = wseg?;
    let sv = b.konst::<W64>(seg & 0xFFFF_FFFF);
    let base = b.sub::<W64>(a, sv);
    if seg & WSEG_32 != 0 {
        // 32 ビット EA: 折り返しがないので `a - sv` がそのまま
        // オフセット（部分アクセスでも正しい生値になる）。
        let m = b.konst::<W64>(0xFFFF_FFFF);
        return Some((b.and::<W64>(base, m), sv));
    }
    let hm = b.konst::<W64>(!0xFFFFu64);
    let hi = b.and::<W64>(raw, hm);
    let off = b.add::<W64>(base, hi);
    Some((off, sv))
}

/// 実モードの 64K オフセット折り返しを考慮してメモリを読む。
/// `wseg` が `Some((seg, raw))` なら `off = a - seg + (raw の上位)` を
/// i バイト目は `seg + ((off + i) & 0xffff)` から読む。
/// `seg_limit` = fault の世代では先に限界検査を行う。
pub fn mem_load<B: Backend, W: Hw>(
    b: &mut B,
    a: B::V<W64>,
    wseg: Option<(u64, B::V<W64>)>,
) -> Result<B::V<W>, B::Exit> {
    // 16 ビット EA の単バイトアクセスは限界を越えられないので
    // 検査しないが、32 ビット EA（WSEG_32）はオフセット自体が
    // 限界を越え得るので 1 バイトでも検査する。
    let Some((seg, _)) = wseg.filter(|(s, _)| W::BITS > 8 || s & WSEG_32 != 0) else {
        return b.load::<W>(a, crate::sem::DATA_READ);
    };
    // 検査は折り返し前の EA 和に対して行う。`a` はオフセット折り
    // 返し済みなので raw の上位を足して部分アクセスの生オフセット
    // を復元する。番地計算は 16 ビットに折る（検査を通った範囲では
    // 折り返しは起きない）。
    let (off_raw, sv) = wseg_off(b, a, wseg).unwrap();
    let lim = b.konst::<W64>(0xFFFF);
    seg_limit_chk::<B, W>(b, off_raw, seg)?;
    let off = b.and::<W64>(off_raw, lim);
    let addr0 = b.add::<W64>(off, sv);
    let byte0 = b.load::<W8>(addr0, crate::sem::DATA_READ)?;
    let mut acc: B::V<W> = b.zext::<W8, W>(byte0);
    for i in 1..W::BITS / 8 {
        let iv = b.konst::<W64>(u64::from(i));
        let t = b.add::<W64>(off, iv);
        let oi = b.and::<W64>(t, lim);
        let addr = b.add::<W64>(oi, sv);
        let byte = b.load::<W8>(addr, crate::sem::DATA_READ)?;
        let bw: B::V<W> = b.zext::<W8, W>(byte);
        let sh = b.konst::<W>(W::from_u128(u128::from(i * 8)));
        let part = b.shl::<W>(bw, sh);
        acc = b.or::<W>(acc, part);
    }
    Ok(acc)
}

/// `mem_load` と同じ折り返し・限界規則でメモリに書く。
pub fn mem_store<B: Backend, W: Hw>(
    b: &mut B,
    a: B::V<W64>,
    wseg: Option<(u64, B::V<W64>)>,
    v: B::V<W>,
) -> Result<(), B::Exit> {
    let Some((seg, _)) = wseg.filter(|(s, _)| W::BITS > 8 || s & WSEG_32 != 0) else {
        return b.store::<W>(a, v, crate::sem::DATA_WRITE);
    };
    // mem_load と同じ折り返し・限界規則。
    let (off_raw, sv) = wseg_off(b, a, wseg).unwrap();
    let lim = b.konst::<W64>(0xFFFF);
    seg_limit_chk::<B, W>(b, off_raw, seg)?;
    let off = b.and::<W64>(off_raw, lim);
    {
        let addr = b.add::<W64>(off, sv);
        let byte = b.trunc::<W, W8>(v);
        b.store::<W8>(addr, byte, crate::sem::DATA_WRITE)?;
    }
    for i in 1..W::BITS / 8 {
        let iv = b.konst::<W64>(u64::from(i));
        let t = b.add::<W64>(off, iv);
        let oi = b.and::<W64>(t, lim);
        let addr = b.add::<W64>(oi, sv);
        let sh = b.konst::<W>(W::from_u128(u128::from(i * 8)));
        let t = b.shr_l::<W>(v, sh);
        let byte = b.trunc::<W, W8>(t);
        b.store::<W8>(addr, byte, crate::sem::DATA_WRITE)?;
    }
    Ok(())
}

/// 8ビットを読む。
pub fn rd8<B: Backend>(b: &mut B, rm: &Rm<B::V<W64>>, d: &MapDec) -> Result<B::V<W8>, B::Exit> {
    match rm {
        Rm::Reg(g) => {
            let (r8, hi) = reg8(d, *g);
            Ok(crate::sem::read8(b, r8, hi))
        }
        Rm::Mem { a, wseg } => mem_load::<B, W8>(b, *a, *wseg),
    }
}

/// 16ビットを読む。
pub fn rd16<B: Backend>(b: &mut B, rm: &Rm<B::V<W64>>) -> Result<B::V<W16>, B::Exit> {
    match rm {
        Rm::Reg(g) => {
            let v: B::V<W32> = b.get(g.state());
            Ok(b.trunc::<W32, W16>(v))
        }
        Rm::Mem { a, wseg } => mem_load::<B, W16>(b, *a, *wseg),
    }
}

/// 32ビットを読む。
pub fn rd32<B: Backend>(b: &mut B, rm: &Rm<B::V<W64>>) -> Result<B::V<W32>, B::Exit> {
    match rm {
        Rm::Reg(g) => Ok(b.get(g.state())),
        Rm::Mem { a, wseg } => mem_load::<B, W32>(b, *a, *wseg),
    }
}

/// 64ビットを読む。
pub fn rd64<B: Backend>(b: &mut B, rm: &Rm<B::V<W64>>) -> Result<B::V<W64>, B::Exit> {
    match rm {
        Rm::Reg(g) => Ok(read64(b, *g)),
        Rm::Mem { a, wseg } => mem_load::<B, W64>(b, *a, *wseg),
    }
}

/// 8ビットを書く。
pub fn wr8<B: Backend>(
    b: &mut B,
    rm: &Rm<B::V<W64>>,
    d: &MapDec,
    v: B::V<W8>,
) -> Result<(), B::Exit> {
    match rm {
        Rm::Reg(g) => {
            let (r8, hi) = reg8(d, *g);
            crate::sem::write8(b, r8, hi, v);
            Ok(())
        }
        Rm::Mem { a, wseg } => mem_store::<B, W8>(b, *a, *wseg, v),
    }
}

/// 16ビットを書く（上位は保存）。
pub fn wr16<B: Backend>(b: &mut B, rm: &Rm<B::V<W64>>, v: B::V<W16>) -> Result<(), B::Exit> {
    match rm {
        Rm::Reg(g) => {
            let cur: B::V<W32> = b.get(g.state());
            let mask = b.konst::<W32>(0xffff_0000);
            let kept = b.and::<W32>(cur, mask);
            let v32 = b.zext::<W16, W32>(v);
            let merged = b.or::<W32>(kept, v32);
            b.set(g.state(), merged);
            Ok(())
        }
        Rm::Mem { a, wseg } => mem_store::<B, W16>(b, *a, *wseg, v),
    }
}

/// 32ビットを書く（x86-64 では上位を消す）。
pub fn wr32<B: Backend>(b: &mut B, rm: &Rm<B::V<W64>>, v: B::V<W32>) -> Result<(), B::Exit> {
    match rm {
        Rm::Reg(g) => {
            b.set(g.state(), v);
            clear_hi(b, *g);
            Ok(())
        }
        Rm::Mem { a, wseg } => mem_store::<B, W32>(b, *a, *wseg, v),
    }
}

/// 64ビットを書く。
pub fn wr64<B: Backend>(b: &mut B, rm: &Rm<B::V<W64>>, v: B::V<W64>) -> Result<(), B::Exit> {
    match rm {
        Rm::Reg(g) => {
            write64(b, *g, v);
            Ok(())
        }
        Rm::Mem { a, wseg } => mem_store::<B, W64>(b, *a, *wseg, v),
    }
}

// ---- レジスタ直接の読み書き ----

/// 32ビットレジスタを読む。
pub fn grd32<B: Backend>(b: &mut B, g: Gpr) -> B::V<W32> {
    b.get(g.state())
}

/// 64ビットレジスタを読む。
pub fn grd64<B: Backend>(b: &mut B, g: Gpr) -> B::V<W64> {
    read64(b, g)
}

/// 8ビットレジスタを読む。
pub fn grd8<B: Backend>(b: &mut B, g: Gpr, d: &MapDec) -> B::V<W8> {
    let (r8, hi) = reg8(d, g);
    crate::sem::read8(b, r8, hi)
}

/// 16ビットレジスタを読む。
pub fn grd16<B: Backend>(b: &mut B, g: Gpr) -> B::V<W16> {
    let v: B::V<W32> = b.get(g.state());
    b.trunc::<W32, W16>(v)
}

/// 32ビットレジスタを書く（上位を消す）。
pub fn gwr32<B: Backend>(b: &mut B, g: Gpr, v: B::V<W32>) {
    b.set(g.state(), v);
    clear_hi(b, g);
}

/// 64ビットレジスタを書く。
pub fn gwr64<B: Backend>(b: &mut B, g: Gpr, v: B::V<W64>) {
    write64(b, g, v);
}

/// 16ビットレジスタを書く（上位は保存）。
pub fn gwr16<B: Backend>(b: &mut B, g: Gpr, v: B::V<W16>) {
    let cur: B::V<W32> = b.get(g.state());
    let mask = b.konst::<W32>(0xffff_0000);
    let kept = b.and::<W32>(cur, mask);
    let v32 = b.zext::<W16, W32>(v);
    let merged = b.or::<W32>(kept, v32);
    b.set(g.state(), merged);
}

/// 8ビットレジスタを書く。
pub fn gwr8<B: Backend>(b: &mut B, g: Gpr, d: &MapDec, v: B::V<W8>) {
    let (r8, hi) = reg8(d, g);
    crate::sem::write8(b, r8, hi, v);
}

/// 幅ごとのレジスタ読み書きを型で振り分ける。
pub trait Hw: polyisa_sem::Width {
    /// レジスタをこの幅で読む。
    fn get<B: Backend>(b: &mut B, g: Gpr, d: &MapDec) -> B::V<Self>;
    /// レジスタにこの幅で書く（部分幅の規則どおり上位を処理する）。
    fn put<B: Backend>(b: &mut B, g: Gpr, d: &MapDec, v: B::V<Self>);
}

impl Hw for W8 {
    fn get<B: Backend>(b: &mut B, g: Gpr, d: &MapDec) -> B::V<W8> {
        let (r8, hi) = reg8(d, g);
        crate::sem::read8(b, r8, hi)
    }
    fn put<B: Backend>(b: &mut B, g: Gpr, d: &MapDec, v: B::V<W8>) {
        let (r8, hi) = reg8(d, g);
        crate::sem::write8(b, r8, hi, v);
    }
}

impl Hw for W16 {
    fn get<B: Backend>(b: &mut B, g: Gpr, _d: &MapDec) -> B::V<W16> {
        let v: B::V<W32> = b.get(g.state());
        b.trunc::<W32, W16>(v)
    }
    fn put<B: Backend>(b: &mut B, g: Gpr, _d: &MapDec, v: B::V<W16>) {
        let cur: B::V<W32> = b.get(g.state());
        let mask = b.konst::<W32>(0xffff_0000);
        let kept = b.and::<W32>(cur, mask);
        let v32 = b.zext::<W16, W32>(v);
        let merged = b.or::<W32>(kept, v32);
        b.set(g.state(), merged);
    }
}

impl Hw for W32 {
    fn get<B: Backend>(b: &mut B, g: Gpr, _d: &MapDec) -> B::V<W32> {
        b.get(g.state())
    }
    fn put<B: Backend>(b: &mut B, g: Gpr, _d: &MapDec, v: B::V<W32>) {
        b.set(g.state(), v);
        clear_hi(b, g);
    }
}

impl Hw for W64 {
    fn get<B: Backend>(b: &mut B, g: Gpr, _d: &MapDec) -> B::V<W64> {
        read64(b, g)
    }
    fn put<B: Backend>(b: &mut B, g: Gpr, _d: &MapDec, v: B::V<W64>) {
        write64(b, g, v);
    }
}

/// `Rm` を幅 `W` で読む。
pub fn rd<B: Backend, W: Hw>(
    b: &mut B,
    rm: &Rm<B::V<W64>>,
    d: &MapDec,
) -> Result<B::V<W>, B::Exit> {
    match rm {
        Rm::Reg(g) => Ok(W::get(b, *g, d)),
        Rm::Mem { a, wseg } => mem_load::<B, W>(b, *a, *wseg),
    }
}

/// `Rm` に幅 `W` で書く。
pub fn wr<B: Backend, W: Hw>(
    b: &mut B,
    rm: &Rm<B::V<W64>>,
    d: &MapDec,
    v: B::V<W>,
) -> Result<(), B::Exit> {
    match rm {
        Rm::Reg(g) => {
            W::put(b, *g, d, v);
            Ok(())
        }
        Rm::Mem { a, wseg } => mem_store::<B, W>(b, *a, *wseg, v),
    }
}

/// ModRM/SIB の EA が既定で SS を使うか（BP/SP ベースか）。
/// 実モードの既定セグメント解決に使う。
pub fn ea_uses_ss(d: &MapDec) -> bool {
    if d.modrm >= 0xC0 {
        return false;
    }
    let md = d.modrm >> 6;
    let rm = d.modrm & 7;
    if d.asize == 16 {
        // BP+SI / BP+DI / [BP+disp]
        matches!(rm, 2 | 3) || (rm == 6 && md != 0)
    } else if rm == 4 {
        // SIB: base=EBP/RBP/R13(mod!=00) または base=ESP/RSP/R12。
        // B4 拡張の base=5 は r21 なので BP 既定にしない。
        let base = d.sib & 7;
        (base == 5 && md != 0 && (d.rex2 >> 4) & 1 == 0) || base == 4
    } else {
        // mod!=00 の r/m=101 は BP ベース（mod=00 は disp32/RIP）。
        // B4 拡張では r21 なので除外する。
        rm == 5 && md != 0 && (d.rex2 >> 4) & 1 == 0
    }
}
