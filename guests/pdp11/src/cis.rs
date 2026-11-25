// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! CIS（Commercial Instruction Set —— 076nnn 空間。KE44-A）の
//! 意味論。PD11。
//!
//! オペランドは 2 形式ある。レジスタ形は記述子を R0-R5 の固定枠
//! が持ち命令語だけで完結し、in-line 形は命令語に続く語列が
//! 記述子へのポインタ語と値語を持ちレジスタを変えない（検査系は
//! 結果を R0-R1 に返す）。記述子は 2 語で、文字列は
//! <長さ語・最上位文字のバイトアドレス語>、十進文字列は
//! <桁数<4:0>・表現型<14:12> の語・アドレス語>。L2D/L3D は
//! 指定レジスタの指すポインタ列から記述子を読み込む（r=PC は
//! 命令ストリームのポインタ語を消費する @(PC)+ 形）。
//!
//! 中断: 文字列命令は「1 ステップ = 1 単位（1 文字）」の反復
//! 近似で、単位の終わりに記述子（レジスタ形は R0-R5、in-line
//! 形は記述子メモリ）へ進行を書き戻し r7 を命令先頭に戻して
//! 再入する。MOVC/MOVRC は進行方向が記述子に乗らないので
//! `PartialInsn` の作業語に保持する。十進・変換命令は 1 ステップ
//! で完結する（VAX 十進と同じ近似 —— 中間点は持たない）。
//! 途中のバスエラーは記述子側の進行を残して fault し、ハンドラが
//! 命令先頭へ戻せば続きから再開できる。
// Ref: SPEC-PDP11-CIS（EK-KE44A-UG-002 附属 B）, SPEC-PDP11-ARCH83.
// 予約領域の決定的選択と単位ステップ近似。

use polyisa_decimal::PackedDec;
use polyisa_engine::interp::{InterpBackend, InterpExit};

use crate::specifier::Fetched;
use crate::{
    CpuState, Insn, PART_INSN_NONE, PartialInsn, psw, reg,
    sem::{cc_tst, fault, fetch_w, load_b, load_w, r_get, r_set, store_b, store_w, tv},
};

// ---- 部分実行器 ----

/// `CpuState.partial` を読む。
fn partial(b: &InterpBackend) -> PartialInsn {
    let base = core::mem::offset_of!(CpuState, partial);
    let io = base + core::mem::offset_of!(PartialInsn, insn);
    let wo = base + core::mem::offset_of!(PartialInsn, work);
    let mut work = [0u32; 4];
    for (k, w) in work.iter_mut().enumerate() {
        *w = u32::from_le_bytes(b.state[wo + 4 * k..wo + 4 * k + 4].try_into().expect("w32"));
    }
    PartialInsn {
        insn: u16::from_le_bytes(b.state[io..io + 2].try_into().expect("w16")),
        work,
    }
}

/// `CpuState.partial` を書く。
fn partial_save(b: &mut InterpBackend, p: &PartialInsn) {
    let base = core::mem::offset_of!(CpuState, partial);
    let io = base + core::mem::offset_of!(PartialInsn, insn);
    let wo = base + core::mem::offset_of!(PartialInsn, work);
    b.state[io..io + 2].copy_from_slice(&p.insn.to_le_bytes());
    for (k, w) in p.work.iter().enumerate() {
        b.state[wo + 4 * k..wo + 4 * k + 4].copy_from_slice(&w.to_le_bytes());
    }
}

/// 部分実行の開始。同じ命令語・同じ命令先頭の残りがあればその
/// 作業語を返し、なければ器を初期化する。work[0] は常に pc0
/// （同じ命令語が別場所で中断していた場合の衝突を除く）。
fn partial_begin(b: &mut InterpBackend, f: &Fetched, pc0: u16) -> Option<[u32; 4]> {
    let p = partial(b);
    if p.insn == f.word && p.work[0] == u32::from(pc0) {
        Some(p.work)
    } else {
        partial_save(
            b,
            &PartialInsn {
                insn: f.word,
                work: [u32::from(pc0), 0, 0, 0],
            },
        );
        None
    }
}

/// 部分実行の完了（器を空にする）。
fn partial_done(b: &mut InterpBackend) {
    partial_save(
        b,
        &PartialInsn {
            insn: PART_INSN_NONE,
            work: [0; 4],
        },
    );
}

/// 中断 —— 記述子に進行を残したうえで r7 を命令先頭に戻し、
/// 次のステップで同じ命令へ再入する。
fn suspend(b: &mut InterpBackend, pc0: u16) {
    r_set(b, reg::PC as u8, pc0);
}

// ---- 記述子 ----

/// 記述子の在処。レジスタ形は汎用レジスタ対（基底は偶数）、
/// in-line 形は命令語列のポインタ語が指すメモリ上の 2 語。
#[derive(Clone, Copy)]
enum Slot {
    /// レジスタ対（語1=slot、語2=slot+1）。
    Reg(u8),
    /// メモリの記述子アドレス。
    Mem(u16),
}

/// 文字列カーソル（記述子の現在値）。`len` は残り文字数、
/// `adr` は現在位置のバイトアドレス。
#[derive(Clone, Copy)]
struct Cur {
    len: u32,
    adr: u16,
}

/// in-line 形の命令語列の語 `i`（1 起算 —— 語 0 は命令語）。
/// 命令ストリームの語なのでフェッチ経路で読む。
fn iw(b: &mut InterpBackend, pc0: u16, i: u16) -> Result<u16, InterpExit> {
    fetch_w(b, pc0.wrapping_add(2 * i))
}

/// 文字列記述子（2 語）をスロットから読む。
fn cur_get(b: &mut InterpBackend, s: Slot) -> Result<Cur, InterpExit> {
    let (w1, w2) = match s {
        Slot::Reg(i) => (r_get(b, i), r_get(b, i + 1)),
        Slot::Mem(a) => (load_w(b, a)?, load_w(b, a.wrapping_add(2))?),
    };
    Ok(Cur {
        len: u32::from(w1),
        adr: w2,
    })
}

/// 文字列記述子をスロットへ書き戻す。
fn cur_put(b: &mut InterpBackend, s: Slot, c: Cur) -> Result<(), InterpExit> {
    match s {
        Slot::Reg(i) => {
            r_set(b, i, c.len as u16);
            r_set(b, i + 1, c.adr);
        }
        Slot::Mem(a) => {
            store_w(b, a, c.len as u16)?;
            store_w(b, a.wrapping_add(2), c.adr)?;
        }
    }
    Ok(())
}

/// 十進文字列記述子。語1 は <4:0>=桁数・<14:12>=表現型、
/// 語2 は最上位桁のバイトアドレス。
#[derive(Clone, Copy)]
struct DDsc {
    len: u8,
    ty: u8,
    adr: u16,
}

fn ddsc_get(b: &mut InterpBackend, s: Slot) -> Result<DDsc, InterpExit> {
    let (w1, w2) = match s {
        Slot::Reg(i) => (r_get(b, i), r_get(b, i + 1)),
        Slot::Mem(a) => (load_w(b, a)?, load_w(b, a.wrapping_add(2))?),
    };
    Ok(DDsc {
        len: (w1 & 0o37) as u8,
        ty: ((w1 >> 12) & 7) as u8,
        adr: w2,
    })
}

/// 記述子の表現型を命令群の領域へ畳む。数値群は型 0-5、パック群
/// は型 6-7 が定義域 —— 群外の型番を与えたときの挙動は正本の
/// 予約領域なので、数値群では 0（符号付きゾーン）、パック群では
/// 6（符号付きパック）へ畳む決定的な選択。
fn dty(ty: u8, packed: bool) -> u8 {
    if packed {
        if ty < 6 { 6 } else { ty }
    } else {
        if ty > 5 { 0 } else { ty }
    }
}

// ---- 条件コード ----

/// 16 ビット減算 `a - b` の条件コード（CMP の規則 —— MOVC 系の
/// 元の長さの比較と CMPC の文字比較に使う）。
fn cc_sub(b: &mut InterpBackend, a: u16, v: u16, w: crate::specifier::Width) {
    let (sign, mask) = if w == crate::specifier::Width::B {
        (0x80u16, 0xffu16)
    } else {
        (0x8000, 0xffff)
    };
    let (a, v) = (a & mask, v & mask);
    let r = a.wrapping_sub(v) & mask;
    sem_flag(b, psw::N, r & sign != 0);
    sem_flag(b, psw::Z, r == 0);
    sem_flag(b, psw::V, (a ^ v) & (a ^ r) & sign != 0);
    sem_flag(b, psw::C, a < v);
}

fn sem_flag(b: &mut InterpBackend, bit: u16, v: bool) {
    let p = crate::sem::psw_get(b);
    crate::sem::psw_put(b, if v { p | 1 << bit } else { p & !(1 << bit) });
}

/// 十進結果の CC（N=格納値が負・Z=格納値が零・V=有意桁あふれ・
/// C=0）。-0 は +0 と同じ扱いで N=0・Z=1。「格納値」は下位 len
/// 桁なので、あふれて全桁を失った負結果は -0 になる。
fn cc_dec(b: &mut InterpBackend, v: &PackedDec, len: usize, ovf: bool) {
    let stored_zero = v.digits.iter().rev().take(len).all(|&d| d == 0);
    sem_flag(b, psw::N, v.negative && !stored_zero);
    sem_flag(b, psw::Z, stored_zero);
    sem_flag(b, psw::V, ovf);
    sem_flag(b, psw::C, false);
}

// ---- 十進文字列 ----

/// 読んだ数字ニブルを 0-9 に飽和する（数字以外のニブルは正本の
/// 予約領域 —— 読み値をクランプする決定的な選択）。
fn zdig(v: u8) -> u8 {
    (v & 0xf).min(9)
}

/// オーバーパンチ符号バイトの復号。優先形（{ }=±0・A-I=+1..9・
/// J-R=-1..9）に代替形（0-9=正・[ ? =+0・] ! : =-0）を足す。
/// 予約バイトは数字を読み値・符号正に畳む決定的な選択。
// Ref: SPEC-PDP11-CIS（2.4.2 の表）.
fn ovp_dec(v: u8) -> (u8, bool) {
    match v {
        0x7b | 0x5b | 0x3f => (0, false),
        0x41..=0x49 => (v - 0x40, false),
        0x30..=0x39 => (v - 0x30, false),
        0x7d | 0x5d | 0x21 | 0x3a => (0, true),
        0x4a..=0x52 => (v - 0x49, true),
        _ => (zdig(v), false),
    }
}

/// オーバーパンチ符号バイトの優先形への符号化。
fn ovp_enc(digit: u8, neg: bool) -> u8 {
    let d = digit.min(9);
    match (neg, d) {
        (false, 0) => 0x7b,
        (true, 0) => 0x7d,
        (false, _) => 0x40 + d,
        (true, _) => 0x49 + d,
    }
}

/// 十進文字列を読んで `PackedDec` にする。`packed` は命令群の
/// 領域（数値群=false・パック群=true —— 型番は `dty` で畳む）。
fn dec_read(b: &mut InterpBackend, d: &DDsc, packed: bool) -> Result<PackedDec, InterpExit> {
    let n = usize::from(d.len);
    let ty = dty(d.ty, packed);
    let mut digits = Vec::with_capacity(n);
    let mut neg = false;
    match ty {
        // 0: 符号付きゾーン（最終バイト上位ニブルが符号）。
        // 1: 符号なしゾーン。
        0 | 1 => {
            for i in 0..n {
                digits.push(zdig(load_b(b, d.adr.wrapping_add(i as u16))?));
            }
            if ty == 0 && n != 0 {
                let sb = load_b(b, d.adr.wrapping_add(n as u16 - 1))?;
                neg = matches!(sb >> 4, 7 | 0xb | 0xd);
            }
        }
        // 2: 後置オーバーパンチ（最終バイトが符号+最下位桁）。
        2 => {
            for i in 0..n.saturating_sub(1) {
                digits.push(zdig(load_b(b, d.adr.wrapping_add(i as u16))?));
            }
            if n != 0 {
                let (dg, ng) = ovp_dec(load_b(b, d.adr.wrapping_add(n as u16 - 1))?);
                digits.push(dg);
                neg = ng;
            }
        }
        // 3: 前置オーバーパンチ（先頭バイトが符号+最上位桁）。
        3 => {
            if n != 0 {
                let (dg, ng) = ovp_dec(load_b(b, d.adr)?);
                digits.push(dg);
                neg = ng;
            }
            for i in 1..n {
                digits.push(zdig(load_b(b, d.adr.wrapping_add(i as u16))?));
            }
        }
        // 4: 後置分離符号（文字列の直後のバイト）。
        // 5: 前置分離符号（最上位桁の直前のバイト）。
        4 | 5 => {
            for i in 0..n {
                digits.push(zdig(load_b(b, d.adr.wrapping_add(i as u16))?));
            }
            let sa = if ty == 4 {
                d.adr.wrapping_add(n as u16)
            } else {
                d.adr.wrapping_sub(1)
            };
            neg = load_b(b, sa)? == 0x2d;
        }
        // 6|7: パック（len 桁が符号ニブルの直前に右詰め。偶数桁の
        // 先頭ニブルは埋め）。6 は符号付き（優先 C/D —— BcdEnv::
        // vax() と同じ受理集合）、7 は符号なし（ニブル F）。
        _ => {
            let nb = usize::from(d.len) / 2 + 1;
            for k in 0..n {
                let pos = n - 1 - k; // 符号に近い側から数える位置（0=最下位）
                let bi = nb - 1 - pos.div_ceil(2);
                let v = load_b(b, d.adr.wrapping_add(bi as u16))?;
                digits.push(zdig(if pos % 2 == 0 { v >> 4 } else { v & 0xf }));
            }
            if ty == 6 {
                let sb = load_b(b, d.adr.wrapping_add(nb as u16 - 1))?;
                neg = matches!(sb & 0xf, 0xb | 0xd);
            }
        }
    }
    Ok(PackedDec {
        digits,
        negative: neg,
    })
}

/// `PackedDec` を len 桁の十進文字列へ書く。値の下位 len 桁を右
/// 詰めで書き、有効桁が len を超えるとき true（V=1 —— あふれた
/// 上位桁は書かない）。符号は `v.negative` をそのまま出力する
/// （桁を全て失った負結果は符号つきの -0 になる）。
fn dec_write(
    b: &mut InterpBackend,
    d: &DDsc,
    packed: bool,
    v: &PackedDec,
) -> Result<bool, InterpExit> {
    let n = usize::from(d.len);
    let ty = dty(d.ty, packed);
    let ovf = v.digit_len() > n;
    // フィールド位置 i（0=最上位）の桁 = 値の下位 n 桁を右詰め。
    let dig = |i: usize| -> u8 {
        let back = n - i;
        if back > v.digits.len() {
            0
        } else {
            v.digits[v.digits.len() - back]
        }
    };
    match ty {
        0 | 1 => {
            for i in 0..n {
                let zone = if ty == 0 && i == n - 1 {
                    if v.negative { 0x70 } else { 0x30 }
                } else {
                    0x30
                };
                store_b(b, d.adr.wrapping_add(i as u16), zone | dig(i))?;
            }
        }
        2 => {
            for i in 0..n.saturating_sub(1) {
                store_b(b, d.adr.wrapping_add(i as u16), 0x30 | dig(i))?;
            }
            if n != 0 {
                store_b(
                    b,
                    d.adr.wrapping_add(n as u16 - 1),
                    ovp_enc(dig(n - 1), v.negative),
                )?;
            }
        }
        3 => {
            if n != 0 {
                store_b(b, d.adr, ovp_enc(dig(0), v.negative))?;
            }
            for i in 1..n {
                store_b(b, d.adr.wrapping_add(i as u16), 0x30 | dig(i))?;
            }
        }
        4 | 5 => {
            for i in 0..n {
                store_b(b, d.adr.wrapping_add(i as u16), 0x30 | dig(i))?;
            }
            let sa = if ty == 4 {
                d.adr.wrapping_add(n as u16)
            } else {
                d.adr.wrapping_sub(1)
            };
            store_b(b, sa, if v.negative { 0x2d } else { 0x2b })?;
        }
        _ => {
            let nb = n / 2 + 1;
            let mut out = vec![0u8; nb];
            for k in 0..n {
                let pos = n - 1 - k;
                let bi = nb - 1 - pos.div_ceil(2);
                if pos % 2 == 0 {
                    out[bi] |= dig(k) << 4;
                } else {
                    out[bi] |= dig(k);
                }
            }
            out[nb - 1] |= if ty == 7 {
                0x0f
            } else if v.negative {
                0x0d
            } else {
                0x0c
            };
            for (bi, &byte) in out.iter().enumerate() {
                store_b(b, d.adr.wrapping_add(bi as u16), byte)?;
            }
        }
    }
    Ok(ovf)
}

/// u64 の絶対値を数字列にする（十進変換の内部形）。
fn int_digits(mut v: u64) -> Vec<u8> {
    let mut d = Vec::new();
    loop {
        d.push((v % 10) as u8);
        v /= 10;
        if v == 0 {
            break;
        }
    }
    d.reverse();
    d
}

/// 数字列に 1 を足す（ASH 系の丸め繰り上げ）。
fn inc_digits(d: &mut Vec<u8>) {
    let mut i = d.len();
    loop {
        if i == 0 {
            d.insert(0, 1);
            return;
        }
        i -= 1;
        if d[i] == 9 {
            d[i] = 0;
        } else {
            d[i] += 1;
            return;
        }
    }
}

// ---- L2D/L3D ----

/// L2D/L3D: レジスタ r の指すポインタ列（2 個/3 個）から記述子を
/// R0-R3/R0-R5 へ読み込む。r=PC は命令ストリームのポインタ語を
/// 順に消費する（@(PC)+ —— 消費後の r7 は `insn_words` の長さと
/// 一致する）。r の書き戻しは記述子を読む先で、L2D は r>=4、
/// L3D は r>=6 のとき行う（それ未満は記述子の読み込み先そのもの）。
// Ref: SPEC-PDP11-CIS（L2Dr/L3Dr の項）.
fn lxd(b: &mut InterpBackend, f: &Fetched, pc0: u16) -> Result<(), InterpExit> {
    let r = (f.word & 7) as u8;
    let three = f.insn == Insn::L3d;
    let np = if three { 3usize } else { 2 };
    let mut temp = if r == 7 {
        pc0.wrapping_add(2)
    } else {
        r_get(b, r)
    };
    let mut ptrs = [0u16; 3];
    for p in ptrs.iter_mut().take(np) {
        *p = if r == 7 {
            fetch_w(b, temp)?
        } else {
            load_w(b, temp)?
        };
        temp = temp.wrapping_add(2);
    }
    if u32::from(r) >= if three { 6 } else { 4 } {
        r_set(b, r, temp);
    }
    for (k, &pa) in ptrs.iter().take(np).enumerate() {
        let w1 = load_w(b, pa)?;
        let w2 = load_w(b, pa.wrapping_add(2))?;
        r_set(b, (2 * k) as u8, w1);
        r_set(b, (2 * k + 1) as u8, w2);
    }
    Ok(())
}

// ---- MOVC/MOVRC/MOVTC ----

/// 文字列コピー系（MOVC・MOVRC・MOVTC と in-line 形）。
/// 1 単位 = 1 文字の格納。方向は「コピーで破壊されない向き」
/// （重なりの規則）を初回単位に決めて PartialInsn に保持する。
fn movc_like(b: &mut InterpBackend, f: &Fetched, pc0: u16) -> Result<(), InterpExit> {
    let inline = matches!(f.insn, Insn::Movci | Insn::Movrci | Insn::Movtci);
    let movrc = matches!(f.insn, Insn::Movrc | Insn::Movrci);
    let movtc = matches!(f.insn, Insn::Movtc | Insn::Movtci);
    let (s_slot, d_slot, fill, table) = if inline {
        (
            Slot::Mem(iw(b, pc0, 1)?),
            Slot::Mem(iw(b, pc0, 2)?),
            iw(b, pc0, 3)? & 0xff,
            if movtc { iw(b, pc0, 4)? } else { 0 },
        )
    } else {
        (
            Slot::Reg(0),
            Slot::Reg(2),
            r_get(b, 4) & 0xff,
            if movtc { r_get(b, 5) } else { 0 },
        )
    };
    let work = partial_begin(b, f, pc0);
    let mut src = cur_get(b, s_slot)?;
    let mut dst = cur_get(b, d_slot)?;
    let bwd = if let Some(w) = work {
        w[1] & 1 != 0
    } else {
        // 初回単位: CC は元の長さの CMP。方向はコピーで破壊され
        // ない向き —— MOVC は src.adr<dst.adr、MOVRC は末端の
        // 比較で後ろ向きにする。MOVRC は最下位文字合わせなので
        // src.len>dst.len では最上位側の超過分を指す位置へ進める。
        cc_sub(
            b,
            src.len as u16,
            dst.len as u16,
            crate::specifier::Width::W,
        );
        let end_s = src.adr.wrapping_add(src.len as u16).wrapping_sub(1);
        let end_d = dst.adr.wrapping_add(dst.len as u16).wrapping_sub(1);
        let bwd = if movrc {
            end_s < end_d
        } else {
            src.adr < dst.adr
        };
        if bwd {
            if movrc {
                src.adr = end_s;
            } else {
                // 最上位側 dst.len 文字を写す開始位置（長さ超過分は
                // 最下位側を落とす —— MOVC の切捨て規則）。
                src.adr = end_s.wrapping_sub(src.len.saturating_sub(dst.len) as u16);
            }
            dst.adr = end_d;
        } else {
            // MOVRC の右詰めでは最上位側の超過分を読み飛ばす。
            src.adr = src.adr.wrapping_add(if movrc {
                src.len.saturating_sub(dst.len) as u16
            } else {
                0
            });
        }
        // 調整済みの位置を記述子へ戻してから単位を走らせる ——
        // 中断・fault からの再入がこの調整をやり直さないようにする。
        cur_put(b, s_slot, src)?;
        cur_put(b, d_slot, dst)?;
        partial_save(
            b,
            &PartialInsn {
                insn: f.word,
                work: [u32::from(pc0), u32::from(bwd), 0, 0],
            },
        );
        bwd
    };
    // 1 単位（1 文字の格納）。
    if dst.len != 0 {
        let fill_phase = if bwd {
            // MOVC 後ろ向きは頭（最下位側）から埋める ——
            // src.len<dst.len の間だけ埋めてから逆順コピー。
            !movrc && src.len < dst.len
        } else {
            // MOVRC 前向きは最上位側を埋めてから正順コピー。
            movrc && src.len < dst.len
        };
        if fill_phase {
            store_b(b, dst.adr, fill as u8)?;
        } else {
            let byte = if src.len != 0 {
                let v = load_b(b, src.adr)?;
                let v = if movtc {
                    load_b(b, table.wrapping_add(u16::from(v)))?
                } else {
                    v
                };
                src.len -= 1;
                v
            } else {
                fill as u8
            };
            store_b(b, dst.adr, byte)?;
        }
        dst.len -= 1;
        if bwd {
            src.adr = if fill_phase {
                src.adr
            } else {
                src.adr.wrapping_sub(1)
            };
            dst.adr = dst.adr.wrapping_sub(1);
        } else {
            src.adr = if fill_phase {
                src.adr
            } else {
                src.adr.wrapping_add(1)
            };
            dst.adr = dst.adr.wrapping_add(1);
        }
        cur_put(b, s_slot, src)?;
        cur_put(b, d_slot, dst)?;
    }
    if dst.len != 0 {
        suspend(b, pc0);
        return Ok(());
    }
    partial_done(b);
    if !inline {
        // レジスタ形の完了規則: R0=残り src.len、R1-R3=0、
        // R4<7:0>=fill（上位は入力時から 0 —— 不変）、
        // MOVTC の R5=table.adr も不変。
        r_set(b, 1, 0);
        r_set(b, 2, 0);
        r_set(b, 3, 0);
    }
    Ok(())
}

// ---- CMPC ----

/// 文字列比較（CMPC/CMPCI）。1 単位 = 1 文字の消費。等しい間は
/// 両方進み、残りが片方だけなら fill と比べる。CC は最初の不一致
/// 位置の CMPB（最終まで一致なら fill 同士の比較 = 等しい）。
fn cmpc(b: &mut InterpBackend, f: &Fetched, pc0: u16) -> Result<(), InterpExit> {
    let inline = f.insn == Insn::Cmpci;
    let (s1, s2, fill) = if inline {
        (
            Slot::Mem(iw(b, pc0, 1)?),
            Slot::Mem(iw(b, pc0, 2)?),
            iw(b, pc0, 3)? & 0xff,
        )
    } else {
        (Slot::Reg(0), Slot::Reg(2), r_get(b, 4) & 0xff)
    };
    partial_begin(b, f, pc0);
    let mut c1 = cur_get(b, s1)?;
    let mut c2 = cur_get(b, s2)?;
    let mut fin: Option<(u8, u8)> = None;
    if c1.len != 0 && c2.len != 0 {
        let a = load_b(b, c1.adr)?;
        let d = load_b(b, c2.adr)?;
        if a == d {
            c1.len -= 1;
            c1.adr = c1.adr.wrapping_add(1);
            c2.len -= 1;
            c2.adr = c2.adr.wrapping_add(1);
        } else {
            fin = Some((a, d));
        }
    } else if c1.len != 0 {
        let a = load_b(b, c1.adr)?;
        if a == fill as u8 {
            c1.len -= 1;
            c1.adr = c1.adr.wrapping_add(1);
        } else {
            fin = Some((a, fill as u8));
        }
    } else if c2.len != 0 {
        let d = load_b(b, c2.adr)?;
        if d == fill as u8 {
            c2.len -= 1;
            c2.adr = c2.adr.wrapping_add(1);
        } else {
            fin = Some((fill as u8, d));
        }
    } else {
        fin = Some((fill as u8, fill as u8));
    }
    cur_put(b, s1, c1)?;
    cur_put(b, s2, c2)?;
    if let Some((a, d)) = fin {
        cc_sub(b, u16::from(a), u16::from(d), crate::specifier::Width::B);
        partial_done(b);
        Ok(())
    } else {
        suspend(b, pc0);
        Ok(())
    }
}

// ---- LOCC/SKPC/SCANC/SPANC/MATC ----

/// 文字列検査系。1 単位 = 1 位置の検査（MATC は 1 開始位置の
/// 照合）。結果は R0-R1 の残余記述子（見つからない/空なら
/// 空記述子 —— 長さ 0・アドレスは最下位文字の 1 つ先）。
/// CC は TST R0（N=R0<15>・Z=R0=0・V=0・C=0）。
fn search(b: &mut InterpBackend, f: &Fetched, pc0: u16) -> Result<(), InterpExit> {
    let ins = f.insn;
    let inline = matches!(
        ins,
        Insn::Locci | Insn::Skpci | Insn::Scanci | Insn::Spanci | Insn::Matci
    );
    let s_slot = if inline {
        Slot::Mem(iw(b, pc0, 1)?)
    } else {
        Slot::Reg(0)
    };
    // オペランド: char（R4<7:0>/語2）、set 記述子（R4:mask・R5:tbl/
    // 語2=記述子ポインタ）、obj 記述子（R2-R3/語2=ポインタ）。
    let ch = match ins {
        Insn::Locc | Insn::Skpc => r_get(b, 4) & 0xff,
        Insn::Locci | Insn::Skpci => iw(b, pc0, 2)? & 0xff,
        _ => 0,
    };
    let (mask, tbl) = match ins {
        Insn::Scanc | Insn::Spanc => (r_get(b, 4) & 0xff, r_get(b, 5)),
        Insn::Scanci | Insn::Spanci => {
            let pd = iw(b, pc0, 2)?;
            (load_w(b, pd)? & 0xff, load_w(b, pd.wrapping_add(2))?)
        }
        _ => (0, 0),
    };
    let obj = match ins {
        Insn::Matc => Some(cur_get(b, Slot::Reg(2))?),
        Insn::Matci => {
            let pd = iw(b, pc0, 2)?;
            Some(cur_get(b, Slot::Mem(pd))?)
        }
        _ => None,
    };
    partial_begin(b, f, pc0);
    let mut cur = cur_get(b, s_slot)?;
    let mut result: Option<Cur> = None;
    match ins {
        Insn::Locc | Insn::Locci => {
            if cur.len == 0 {
                result = Some(cur);
            } else {
                let c = load_b(b, cur.adr)?;
                if c == ch as u8 {
                    result = Some(cur);
                } else {
                    cur.len -= 1;
                    cur.adr = cur.adr.wrapping_add(1);
                    if cur.len == 0 {
                        result = Some(cur);
                    }
                }
            }
        }
        Insn::Skpc | Insn::Skpci => {
            if cur.len == 0 {
                result = Some(cur);
            } else {
                let c = load_b(b, cur.adr)?;
                if c == ch as u8 {
                    cur.len -= 1;
                    cur.adr = cur.adr.wrapping_add(1);
                    if cur.len == 0 {
                        result = Some(cur);
                    }
                } else {
                    result = Some(cur);
                }
            }
        }
        Insn::Scanc | Insn::Scanci | Insn::Spanc | Insn::Spanci => {
            if cur.len == 0 {
                result = Some(cur);
            } else {
                let c = load_b(b, cur.adr)?;
                let inset = load_b(b, tbl.wrapping_add(u16::from(c)))? & mask as u8 != 0;
                let stop = matches!(ins, Insn::Scanc | Insn::Scanci) == inset;
                if stop {
                    result = Some(cur);
                } else {
                    cur.len -= 1;
                    cur.adr = cur.adr.wrapping_add(1);
                    if cur.len == 0 {
                        result = Some(cur);
                    }
                }
            }
        }
        _ => {
            // MATC/MATCI: 現在位置で obj 全体と照合し、一致なら
            // その位置からの残余を返す。1 位置の照合は 1 単位。
            let obj = obj.expect("matc has obj");
            if cur.len == 0 {
                // 空の src は照合しない（vacant 結果は元の記述子）。
                result = Some(cur);
            } else if obj.len == 0 {
                // 空の obj は空でない src に照合する —— 正本の注記
                // を採る（形式的記述は while obj.len!=0 で照合自体を
                // 起こさない —— 両者の食い違いは の選択）。
                result = Some(cur);
            } else if cur.len < obj.len {
                result = Some(Cur {
                    len: 0,
                    adr: cur.adr.wrapping_add(cur.len as u16),
                });
            } else {
                let mut i = 0u32;
                while i < obj.len {
                    let a = load_b(b, cur.adr.wrapping_add(i as u16))?;
                    let d = load_b(b, obj.adr.wrapping_add(i as u16))?;
                    if a != d {
                        break;
                    }
                    i += 1;
                }
                if i == obj.len {
                    result = Some(cur);
                } else {
                    cur.len -= 1;
                    cur.adr = cur.adr.wrapping_add(1);
                    if cur.len < obj.len {
                        result = Some(Cur {
                            len: 0,
                            adr: cur.adr.wrapping_add(cur.len as u16),
                        });
                    }
                }
            }
        }
    }
    if let Some(r) = result {
        r_set(b, 0, r.len as u16);
        r_set(b, 1, r.adr);
        if !inline {
            // レジスタ形の完了規則: MATC 以外は R2-R5 を消す
            // （MATC は R2-R3 = obj.dscr のまま・R4-R5 = 0）。
            match ins {
                Insn::Matc => {
                    r_set(b, 4, 0);
                    r_set(b, 5, 0);
                }
                _ => {
                    for i in 2..6 {
                        r_set(b, i, 0);
                    }
                }
            }
        }
        // CC = TST R0。
        cc_tst(b, r.len as u16, crate::specifier::Width::W);
        partial_done(b);
        Ok(())
    } else {
        cur_put(b, s_slot, cur)?;
        suspend(b, pc0);
        Ok(())
    }
}

// ---- 十進命令 ----

/// 十進演算のスロット配置。3 記述子形は
/// （src1=R0-R1|ptr1, src2=R2-R3|ptr2, dst=R4-R5|ptr3）、
/// 2 記述子形は（src=R0-R1|ptr1, dst=R2-R3|ptr2）、CVTL 系は
/// （dst=R0-R1|ptr1, 長整数=R2-R3|ptr2）、ASH 系は
/// （src=R0-R1|ptr1, dst=R2-R3|ptr2, shift.dscr=R4|語3）。
fn dec_op(b: &mut InterpBackend, f: &Fetched, pc0: u16) -> Result<(), InterpExit> {
    let ins = f.insn;
    let packed = matches!(
        ins,
        Insn::Addp
            | Insn::Subp
            | Insn::Cmpp
            | Insn::Cvtpl
            | Insn::Mulp
            | Insn::Divp
            | Insn::Ashp
            | Insn::Cvtlp
            | Insn::Addpi
            | Insn::Subpi
            | Insn::Cmppi
            | Insn::Cvtpli
            | Insn::Mulpi
            | Insn::Divpi
            | Insn::Ashpi
            | Insn::Cvtlpi
    );
    let inline = matches!(
        ins,
        Insn::Addni
            | Insn::Subni
            | Insn::Cmpni
            | Insn::Cvtnli
            | Insn::Cvtpni
            | Insn::Cvtnpi
            | Insn::Ashni
            | Insn::Cvtlni
            | Insn::Addpi
            | Insn::Subpi
            | Insn::Cmppi
            | Insn::Cvtpli
            | Insn::Mulpi
            | Insn::Divpi
            | Insn::Ashpi
            | Insn::Cvtlpi
    );
    match ins {
        // 3 記述子形: dst <- src2 op src1（DIV は src2/src1）。
        Insn::Addn
        | Insn::Subn
        | Insn::Addp
        | Insn::Subp
        | Insn::Mulp
        | Insn::Divp
        | Insn::Addni
        | Insn::Subni
        | Insn::Addpi
        | Insn::Subpi
        | Insn::Mulpi
        | Insn::Divpi => {
            let s1 = if inline {
                Slot::Mem(iw(b, pc0, 1)?)
            } else {
                Slot::Reg(0)
            };
            let s2 = if inline {
                Slot::Mem(iw(b, pc0, 2)?)
            } else {
                Slot::Reg(2)
            };
            let ds = if inline {
                Slot::Mem(iw(b, pc0, 3)?)
            } else {
                Slot::Reg(4)
            };
            let d1 = ddsc_get(b, s1)?;
            let d2 = ddsc_get(b, s2)?;
            let dd = ddsc_get(b, ds)?;
            let v1 = dec_read(b, &d1, packed)?;
            let v2 = dec_read(b, &d2, packed)?;
            let (r, divz) = match ins {
                Insn::Addn | Insn::Addp | Insn::Addni | Insn::Addpi => (v2.add(&v1), false),
                Insn::Subn | Insn::Subp | Insn::Subni | Insn::Subpi => (v2.sub(&v1), false),
                Insn::Mulp | Insn::Mulpi => (v2.mul(&v1), false),
                _ => match v2.divmod(&v1) {
                    Ok((q, _)) => (q, false),
                    Err(_) => (
                        PackedDec {
                            digits: vec![0],
                            negative: false,
                        },
                        true,
                    ),
                },
            };
            if divz {
                // 0 除算: dst と N/Z は不定 —— dst を書かず
                // N=Z=0・V=1・C=1 に決定的に畳む。
                sem_flag(b, psw::N, false);
                sem_flag(b, psw::Z, false);
                sem_flag(b, psw::V, true);
                sem_flag(b, psw::C, true);
            } else {
                let ovf = dec_write(b, &dd, packed, &r)?;
                cc_dec(b, &r, usize::from(dd.len), ovf);
            }
            if !inline {
                for i in 0..4 {
                    r_set(b, i, 0);
                }
            }
            Ok(())
        }
        // 比較: src1 - src2 の符号で CC（V=C=0）。
        Insn::Cmpn | Insn::Cmpp | Insn::Cmpni | Insn::Cmppi => {
            let s1 = if inline {
                Slot::Mem(iw(b, pc0, 1)?)
            } else {
                Slot::Reg(0)
            };
            let s2 = if inline {
                Slot::Mem(iw(b, pc0, 2)?)
            } else {
                Slot::Reg(2)
            };
            let d1 = ddsc_get(b, s1)?;
            let d2 = ddsc_get(b, s2)?;
            let v1 = dec_read(b, &d1, packed)?;
            let v2 = dec_read(b, &d2, packed)?;
            use core::cmp::Ordering::*;
            let (n, z) = match v1.cmp(&v2) {
                Less => (true, false),
                Equal => (false, true),
                Greater => (false, false),
            };
            sem_flag(b, psw::N, n);
            sem_flag(b, psw::Z, z);
            sem_flag(b, psw::V, false);
            sem_flag(b, psw::C, false);
            if !inline {
                for i in 0..4 {
                    r_set(b, i, 0);
                }
            }
            Ok(())
        }
        // 十進 → 長整数。結果はレジスタ形 R2=s|high・R3=low、
        // in-line 形は ptr→low・ptr+2→s|high。C は src<0 かつ
        // 結果非零、V は 32 ビット符号付きに収まらないとき。
        Insn::Cvtnl | Insn::Cvtpl | Insn::Cvtnli | Insn::Cvtpli => {
            let s1 = if inline {
                Slot::Mem(iw(b, pc0, 1)?)
            } else {
                Slot::Reg(0)
            };
            let d1 = ddsc_get(b, s1)?;
            let v = dec_read(b, &d1, packed)?;
            let neg = v.negative && !v.is_zero();
            let mut acc = 0u64;
            let mut mag = 0u64;
            for &d in &v.digits {
                acc = acc.wrapping_mul(10).wrapping_add(u64::from(d));
                mag = mag.saturating_mul(10).saturating_add(u64::from(d));
            }
            let lim = if neg { 0x8000_0000u64 } else { 0x7fff_ffff };
            let ovf = mag > lim;
            let dst = if neg {
                0u32.wrapping_sub(acc as u32)
            } else {
                acc as u32
            };
            if inline {
                let ptr = iw(b, pc0, 2)?;
                store_w(b, ptr, dst as u16)?;
                store_w(b, ptr.wrapping_add(2), (dst >> 16) as u16)?;
            } else {
                r_set(b, 0, 0);
                r_set(b, 1, 0);
                r_set(b, 2, (dst >> 16) as u16);
                r_set(b, 3, dst as u16);
            }
            sem_flag(b, psw::N, dst & 0x8000_0000 != 0);
            sem_flag(b, psw::Z, dst == 0);
            sem_flag(b, psw::V, ovf);
            sem_flag(b, psw::C, neg && dst != 0);
            Ok(())
        }
        // 長整数 → 十進。レジスタ形は R2=s|high・R3=low、in-line
        // 形は ptr→low・ptr+2→s|high（メモリの長整数は語順が逆）。
        Insn::Cvtln | Insn::Cvtlp | Insn::Cvtlni | Insn::Cvtlpi => {
            let ds = if inline {
                Slot::Mem(iw(b, pc0, 1)?)
            } else {
                Slot::Reg(0)
            };
            let dd = ddsc_get(b, ds)?;
            let sv = if inline {
                let ptr = iw(b, pc0, 2)?;
                let lo = load_w(b, ptr)?;
                let hi = load_w(b, ptr.wrapping_add(2))?;
                i32::from_le_bytes([lo as u8, (lo >> 8) as u8, hi as u8, (hi >> 8) as u8])
            } else {
                (u32::from(r_get(b, 2)) << 16 | u32::from(r_get(b, 3))) as i32
            };
            let v = PackedDec {
                digits: int_digits(sv.unsigned_abs() as u64),
                negative: sv < 0,
            };
            let ovf = dec_write(b, &dd, packed, &v)?;
            cc_dec(b, &v, usize::from(dd.len), ovf);
            if !inline {
                r_set(b, 2, 0);
                r_set(b, 3, 0);
            }
            Ok(())
        }
        // 表現変換（CVTNP: 数値→パック、CVTPN: パック→数値）。
        Insn::Cvtnp | Insn::Cvtpn | Insn::Cvtnpi | Insn::Cvtpni => {
            let src_packed = matches!(ins, Insn::Cvtpn | Insn::Cvtpni);
            let s1 = if inline {
                Slot::Mem(iw(b, pc0, 1)?)
            } else {
                Slot::Reg(0)
            };
            let ds = if inline {
                Slot::Mem(iw(b, pc0, 2)?)
            } else {
                Slot::Reg(2)
            };
            let d1 = ddsc_get(b, s1)?;
            let dd = ddsc_get(b, ds)?;
            let v = dec_read(b, &d1, src_packed)?;
            let ovf = dec_write(b, &dd, !src_packed, &v)?;
            cc_dec(b, &v, usize::from(dd.len), ovf);
            if !inline {
                r_set(b, 0, 0);
                r_set(b, 1, 0);
            }
            Ok(())
        }
        // 算術シフト: shift.dscr<7:0> 符号付き桁移動（正=左=桁追加、
        // 負=右=下位桁除去 + <11:8> の丸め桁で四捨五入）。
        Insn::Ashn | Insn::Ashp | Insn::Ashni | Insn::Ashpi => {
            let s1 = if inline {
                Slot::Mem(iw(b, pc0, 1)?)
            } else {
                Slot::Reg(0)
            };
            let ds = if inline {
                Slot::Mem(iw(b, pc0, 2)?)
            } else {
                Slot::Reg(2)
            };
            let d1 = ddsc_get(b, s1)?;
            let dd = ddsc_get(b, ds)?;
            let v = dec_read(b, &d1, packed)?;
            let shw = if inline { iw(b, pc0, 3)? } else { r_get(b, 4) };
            let cnt = (shw as u8) as i8 as i32;
            let rnd = u32::from((shw >> 8) & 0xf);
            let mut digits = v.digits;
            if cnt > 0 {
                digits.extend(core::iter::repeat_n(0, cnt as usize));
            } else if cnt < 0 {
                let dropn = (-cnt) as usize;
                let kept = digits.len().saturating_sub(dropn);
                let dropped = digits.split_off(kept);
                let dms = dropped.first().copied().unwrap_or(0);
                if u32::from(dms) + rnd >= 10 {
                    inc_digits(&mut digits);
                }
                if digits.is_empty() {
                    digits.push(0);
                }
            }
            let r = PackedDec {
                digits,
                negative: v.negative,
            };
            let ovf = dec_write(b, &dd, packed, &r)?;
            cc_dec(b, &r, usize::from(dd.len), ovf);
            if !inline {
                r_set(b, 0, 0);
                r_set(b, 1, 0);
                r_set(b, 4, 0);
            }
            Ok(())
        }
        _ => Err(fault(tv::ILL)),
    }
}

/// CIS 命令の実行。`Insn` が CIS のものだけを受ける。
// Ref: SPEC-PDP11-CIS.
pub fn exec(b: &mut InterpBackend, f: &Fetched, pc0: u16) -> Result<(), InterpExit> {
    match f.insn {
        Insn::L2d | Insn::L3d => lxd(b, f, pc0),
        Insn::Movc | Insn::Movci | Insn::Movrc | Insn::Movrci | Insn::Movtc | Insn::Movtci => {
            movc_like(b, f, pc0)
        }
        Insn::Cmpc | Insn::Cmpci => cmpc(b, f, pc0),
        Insn::Locc
        | Insn::Locci
        | Insn::Skpc
        | Insn::Skpci
        | Insn::Scanc
        | Insn::Scanci
        | Insn::Spanc
        | Insn::Spanci
        | Insn::Matc
        | Insn::Matci => search(b, f, pc0),
        _ => dec_op(b, f, pc0),
    }
}
