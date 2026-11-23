// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! VAX の十進文字列命令（VX10）。パック十進（movp/cmpp/addp/subp/
//! mulp/divp/ashp）、long との変換（cvtpl/cvtlp）、3 つの数値文字列
//! 形式との変換（cvtps/cvtsp/cvtpt/cvttp）、パターン駆動の
//! editpc を扱う。
//!
//! 共通規則（正本の十進文字列章）:
//! - 文字列は (桁数 len.rw, 先頭バイトアドレス .ab) の対で指定。
//!   桁数は 0-31。パック形式は len/2+1 バイト、trailing numeric は
//!   len バイト、leading separate は len+1 バイト（符号先行）。
//! - len が 31 を越えると予約オペランド abort（fault、命令先頭に復帰）。
//! - 符号ニブル: 正 {A,C,E,F}（優先 C）・負 {B,D}（優先 D）=
//!   `bcd::BcdEnv::vax()`。CVTSP/CVTTP だけが入力バイトを検査する
//!   （不正は abort）。それ以外の命令はソースを検査しない —
//!   不正ニブルは UNPREDICTABLE なので、ここではニブル値をそのまま
//!   数字として読む決定的な選択を取る。
//! - 十進オーバーフロー: 結果が目的桁数に収まらないとき、正しい
//!   符号つきの下位桁を書いて V=1。PSL<DV>=1 なら算術 trap 型 6。
//!   値 0 の結果は常に正符号（CVTPT は例外 —— -0 を直さない）。
//! - 完了時レジスタ: r0-r3（または r0-r5）に制御ブロック —
//!   偶数番は 0、奇数番は「最上位桁を含むバイト」のアドレス
//!   = 各文字列オペランドの先頭アドレス。
//! - 中断: 実機は数字走査の途中で割込み可能（FPD）。ここでは
//!   editpc だけパターン演算子 1 個 = 1 ステップの部分実行を実装
//!   （状態は r0-r5 と NZVC に全部載る）。算術系は 1 ステップで
//!   完結させる近似（GAP 記録）。
//! Gap: GAP-0078
//! Ref: SPEC-VAX-ARM（データ型・十進文字列命令・例外の章）.

use polyisa_decimal::PackedDec;
use polyisa_engine::interp::{InterpBackend, InterpExit};

use crate::sem::{
    cc_nzvc, eval, eval_a, eval_r, fault, iv_trap, load, partial_done, partial_resume,
    partial_save, psl_flag, psl_flag_set, r_get, r_set, scb, store, trap, write,
};
use crate::specifier::{Fetched, Width};
use crate::{Insn, psl, reg};

/// パック十進 len 桁が占めるバイト数。
fn pbytes(len: u32) -> u32 {
    len / 2 + 1
}

/// 桁数オペランドの検査（0-31 以外は予約オペランド abort）。
fn check_len(len: u32) -> Result<(), InterpExit> {
    if len > 31 {
        return Err(fault(scb::RESERVED_OPERAND, None));
    }
    Ok(())
}

/// パック十進文字列を読む（緩い復号: 数字ニブルは値そのまま
/// 0-15、符号は {B,D} だけ負。不正ニブルは UNPREDICTABLE の
/// 決定的な選択 —— CVTSP/CVTTP 以外は検査しない規則）。
fn read_packed(b: &mut InterpBackend, addr: u32, len: u32) -> Result<PackedDec, InterpExit> {
    // Gap: GAP-0078
    let n = pbytes(len) as usize;
    let mut raw = vec![0u8; n];
    for (i, byte) in raw.iter_mut().enumerate() {
        *byte = load(b, addr.wrapping_add(i as u32), 1)? as u8;
    }
    // 数字は符号ニブルの直前 len 個に右詰め。偶数桁では先頭ニブルは
    // 埋め 0 で数字ではない。
    let sign_pos = n * 2 - 1;
    let mut digits = Vec::with_capacity(len as usize);
    for k in 0..len as usize {
        let p = sign_pos - 1 - (len as usize - 1 - k);
        let byte = raw[p / 2];
        digits.push(if p.is_multiple_of(2) {
            byte >> 4
        } else {
            byte & 0xf
        });
    }
    let neg = matches!(raw[n - 1] & 0xf, 0xb | 0xd);
    Ok(PackedDec {
        digits,
        negative: neg,
    })
}

/// 数字列を len 桁のパック形式で書く。右詰め・上位は 0 埋め、
/// 符号は優先形（C/D）。桁が収まらないときは下位 len 桁を書いて
/// `Ok(true)`（十進オーバーフロー）。
fn write_packed(
    b: &mut InterpBackend,
    addr: u32,
    len: u32,
    digits: &[u8],
    neg: bool,
) -> Result<bool, InterpExit> {
    let n = pbytes(len) as usize;
    let mut out = vec![0u8; n];
    let sign_pos = n * 2 - 1;
    let overflow = digits.len() > len as usize;
    for k in 0..len as usize {
        let p = sign_pos - 1 - k;
        let d = if k < digits.len() {
            digits[digits.len() - 1 - k]
        } else {
            0
        };
        if p.is_multiple_of(2) {
            out[p / 2] |= d << 4;
        } else {
            out[p / 2] |= d;
        }
    }
    let last = n - 1;
    out[last] = (out[last] & 0xf0) | if neg { 0xd } else { 0xc };
    for (i, &byte) in out.iter().enumerate() {
        store(b, addr.wrapping_add(i as u32), 1, u128::from(byte))?;
    }
    Ok(overflow)
}

/// 値 `v`（十進文字列としての結果）で条件コードを立てる:
/// N=負（-0 は正と同じ扱いで N=0）・Z=零・V=あふれ・C=0。
fn cc_dec(b: &mut InterpBackend, v: &PackedDec, overflow: bool) {
    cc_nzvc(b, v.negative && !v.is_zero(), v.is_zero(), overflow, false);
}

/// 十進オーバーフローの trap: V=1 かつ PSL<DV>=1 のとき算術 trap
/// 型 6（DECOVF）。KA660 等 dv_hw=false のモデル差は VX11 で扱う
/// —— ここでは PSL の桁どおりに振る舞う。
fn dv_trap(b: &InterpBackend) -> Result<(), InterpExit> {
    if psl_flag(b, psl::V) && psl_flag(b, psl::DV) {
        return Err(trap(scb::arith(scb::at::DEC_OVERFLOW)));
    }
    Ok(())
}

/// 読み出した値を `neg` 強制の PackedDec にする（0 は符号を正に）。
fn norm(v: &PackedDec) -> PackedDec {
    let mut d = v.digits.clone();
    while d.len() > 1 && d[0] == 0 {
        d.remove(0);
    }
    PackedDec {
        negative: v.negative && !v.is_zero(),
        digits: d,
    }
}

/// 整数値を数字列にする（符号なし絶対値）。
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

/// len.rw オペランドを読んで 0-31 を検査する。
fn dec_len(
    b: &mut InterpBackend,
    f: &Fetched,
    pos: &[(u32, u32)],
    i: usize,
) -> Result<u32, InterpExit> {
    let len = eval_r(b, f, pos, i, Width::W)? as u32;
    check_len(len)?;
    Ok(len)
}

/// 文字列オペランドの先頭アドレス（.ab）。
fn dec_addr(
    b: &mut InterpBackend,
    f: &Fetched,
    pos: &[(u32, u32)],
    i: usize,
) -> Result<u32, InterpExit> {
    eval_a(b, f, pos, i)
}

/// 制御ブロックの終了レジスタ（r0-r3）: 偶数番は 0、奇数番は
/// 「最上位桁を含むバイト」のアドレス = 各文字列の先頭。
fn set_cb3(b: &mut InterpBackend, a1: u32, a3: u32) {
    r_set(b, 0, 0);
    r_set(b, 1, a1);
    r_set(b, 2, 0);
    r_set(b, 3, a3);
}

/// 6 オペランド形式の制御ブロック（r0-r5）。
fn set_cb5(b: &mut InterpBackend, a1: u32, a3: u32, a5: u32) {
    set_cb3(b, a1, a3);
    r_set(b, 4, 0);
    r_set(b, 5, a5);
}

// ---- 移動・比較・四則 ----

pub fn movp(b: &mut InterpBackend, f: &Fetched, pos: &[(u32, u32)]) -> Result<(), InterpExit> {
    let len = dec_len(b, f, pos, 0)?;
    let s = dec_addr(b, f, pos, 1)?;
    let d = dec_addr(b, f, pos, 2)?;
    let n = pbytes(len);
    // 生バイトのまま写す（MOVP は符号ニブルを正規化しない）。
    for i in 0..n {
        let v = load(b, s.wrapping_add(i), 1)?;
        store(b, d.wrapping_add(i), 1, v)?;
    }
    // -0 のソースは結果 +0: 符号ニブルを優先の正に直す。
    let v = read_packed(b, s, len)?;
    if v.is_zero() && v.negative {
        let last = d.wrapping_add(n - 1);
        let cur = load(b, last, 1)? & 0xf0;
        store(b, last, 1, cur | 0xc)?;
    }
    set_cb3(b, s, d);
    cc_dec(b, &v, false);
    Ok(())
}

pub fn cmpp(b: &mut InterpBackend, f: &Fetched, pos: &[(u32, u32)]) -> Result<(), InterpExit> {
    let (len1, s1, len2, s2) = if f.insn == Insn::Cmpp3 {
        let len = dec_len(b, f, pos, 0)?;
        (len, dec_addr(b, f, pos, 1)?, len, dec_addr(b, f, pos, 2)?)
    } else {
        (
            dec_len(b, f, pos, 0)?,
            dec_addr(b, f, pos, 1)?,
            dec_len(b, f, pos, 2)?,
            dec_addr(b, f, pos, 3)?,
        )
    };
    let v1 = read_packed(b, s1, len1)?;
    let v2 = read_packed(b, s2, len2)?;
    let ord = v1.cmp(&v2);
    set_cb3(b, s1, s2);
    cc_nzvc(
        b,
        ord == core::cmp::Ordering::Less,
        ord == core::cmp::Ordering::Equal,
        false,
        false,
    );
    Ok(())
}

/// addp/subp/mulp/divp の共通骨格。`two_src` が真なら 6 項形式。
fn arithp(b: &mut InterpBackend, f: &Fetched, pos: &[(u32, u32)]) -> Result<(), InterpExit> {
    let six = matches!(f.insn, Insn::Addp6 | Insn::Subp6 | Insn::Mulp | Insn::Divp);
    // オペランド順: (a_len,a_addr),(b_len,b_addr),(dst_len,dst_addr)
    let (la, aa) = (dec_len(b, f, pos, 0)?, dec_addr(b, f, pos, 1)?);
    let (lb, ab, ld, ad) = if six {
        (
            dec_len(b, f, pos, 2)?,
            dec_addr(b, f, pos, 3)?,
            dec_len(b, f, pos, 4)?,
            dec_addr(b, f, pos, 5)?,
        )
    } else {
        let ld = dec_len(b, f, pos, 2)?;
        let ad = dec_addr(b, f, pos, 3)?;
        (ld, ad, ld, ad)
    };
    let va = read_packed(b, aa, la)?;
    let vb = read_packed(b, ab, lb)?;
    let r = match f.insn {
        Insn::Addp4 | Insn::Addp6 => vb.add(&va),
        Insn::Subp4 | Insn::Subp6 => vb.sub(&va),
        Insn::Mulp => vb.mul(&va),
        Insn::Divp => {
            if va.is_zero() {
                // 十進ゼロ除算は trap（型 4）。dst・レジスタ・CC は
                // UNPREDICTABLE —— 何も書かない決定的な選択。
                return Err(trap(scb::arith(scb::at::FLT_DIV_ZERO)));
            }
            let (q, _rem) = vb
                .divmod(&va)
                .map_err(|_| trap(scb::arith(scb::at::FLT_DIV_ZERO)))?;
            q
        }
        _ => unreachable!(),
    };
    if f.insn == Insn::Divp {
        // DIVP は実行中に (SP)-16..(SP)-1 の 16 バイトの作業場を
        // 使い、終了時に SP を戻す。中身は UNPREDICTABLE —— 0 で
        // 埋める決定的な選択。
        let sp = r_get(b, reg::SP as u8);
        for i in 0..16u32 {
            store(b, sp.wrapping_sub(16).wrapping_add(i), 1, 0)?;
        }
    }
    let r = norm(&r);
    let ovf = write_packed(b, ad, ld, &r.digits, r.negative)?;
    if six {
        set_cb5(b, aa, ab, ad);
    } else {
        set_cb3(b, aa, ad);
    }
    cc_dec(b, &r, ovf);
    dv_trap(b)
}

// ---- 整数 ↔ パック ----

pub fn cvtpl(b: &mut InterpBackend, f: &Fetched, pos: &[(u32, u32)]) -> Result<(), InterpExit> {
    let len = dec_len(b, f, pos, 0)?;
    let s = dec_addr(b, f, pos, 1)?;
    let d = eval(b, f, pos, 2)?;
    let v = read_packed(b, s, len)?;
    // 絶対値 mod 2^32 と範囲検査（正確な 64 ビットで）。
    let mut mag: u64 = 0;
    let mut acc: u64 = 0;
    for &dg in &v.digits {
        mag = mag.saturating_mul(10).saturating_add(u64::from(dg));
        acc = acc.wrapping_mul(10).wrapping_add(u64::from(dg));
    }
    let sv = if v.negative {
        -(mag as i128)
    } else {
        mag as i128
    };
    let ovf = sv < i128::from(i32::MIN) || sv > i128::from(i32::MAX);
    let low = if v.negative {
        (0u32).wrapping_sub(acc as u32)
    } else {
        acc as u32
    };
    // レジスタは dst 格納の前に更新される（dst に r0-r3 が使える）。
    set_cb3(b, s, 0);
    write(b, &d, Width::L, u128::from(low))?;
    cc_nzvc(b, (low as i32) < 0, low == 0, ovf, false);
    iv_trap(b)
}

pub fn cvtlp(b: &mut InterpBackend, f: &Fetched, pos: &[(u32, u32)]) -> Result<(), InterpExit> {
    let sv = eval_r(b, f, pos, 0, Width::L)? as u32 as i32 as i64;
    let ld = dec_len(b, f, pos, 1)?;
    let ad = dec_addr(b, f, pos, 2)?;
    let neg = sv < 0;
    let digits = int_digits(sv.unsigned_abs());
    let ovf = write_packed(b, ad, ld, &digits, neg && sv != 0)?;
    set_cb3(b, 0, ad);
    cc_nzvc(b, neg, sv == 0, ovf, false);
    dv_trap(b)
}

// ---- 数値文字列 ↔ パック（3 形式）----

/// cvtps: packed → leading separate（符号バイト + ASCII 数字）。
pub fn cvtps(b: &mut InterpBackend, f: &Fetched, pos: &[(u32, u32)]) -> Result<(), InterpExit> {
    let ls = dec_len(b, f, pos, 0)?;
    let saddr = dec_addr(b, f, pos, 1)?;
    let ld = dec_len(b, f, pos, 2)?;
    let daddr = dec_addr(b, f, pos, 3)?;
    let v = norm(&read_packed(b, saddr, ls)?);
    let ovf = v.digits.len() > ld as usize;
    // 符号バイト（値 0 は '+'）+ 下位 ld 桁の ASCII。
    let sign = if v.negative { b'-' } else { b'+' };
    store(b, daddr, 1, u128::from(sign))?;
    for k in 0..ld as usize {
        let d = if k < v.digits.len() {
            v.digits[v.digits.len() - 1 - k]
        } else {
            0
        };
        store(
            b,
            daddr + 1 + (ld as usize - 1 - k) as u32,
            1,
            u128::from(b'0' + d.min(9)),
        )?;
    }
    set_cb3(b, saddr, daddr);
    cc_dec(b, &v, ovf);
    dv_trap(b)
}

/// cvtsp: leading separate → packed。入力は検査する（不正は abort）。
pub fn cvtsp(b: &mut InterpBackend, f: &Fetched, pos: &[(u32, u32)]) -> Result<(), InterpExit> {
    let ls = dec_len(b, f, pos, 0)?;
    let saddr = dec_addr(b, f, pos, 1)?;
    let ld = dec_len(b, f, pos, 2)?;
    let daddr = dec_addr(b, f, pos, 3)?;
    let sb = load(b, saddr, 1)? as u8;
    let neg = match sb {
        b'+' | b' ' => false,
        b'-' => true,
        _ => return Err(fault(scb::RESERVED_OPERAND, None)),
    };
    let mut digits = Vec::with_capacity(ls as usize);
    for i in 0..ls {
        let c = load(b, saddr + 1 + i, 1)? as u8;
        if !(c.is_ascii_digit()) {
            return Err(fault(scb::RESERVED_OPERAND, None));
        }
        digits.push(c - b'0');
    }
    let v = norm(&PackedDec {
        digits,
        negative: neg,
    });
    let ovf = write_packed(b, daddr, ld, &v.digits, v.negative)?;
    set_cb3(b, saddr, daddr);
    cc_dec(b, &v, ovf);
    dv_trap(b)
}

/// cvtpt: packed → trailing numeric（下位バイトは 256 バイト表で
/// 符号+最下位桁を変換。-0 は +0 に直さない）。
pub fn cvtpt(b: &mut InterpBackend, f: &Fetched, pos: &[(u32, u32)]) -> Result<(), InterpExit> {
    let ls = dec_len(b, f, pos, 0)?;
    let saddr = dec_addr(b, f, pos, 1)?;
    let tbl = dec_addr(b, f, pos, 2)?;
    let ld = dec_len(b, f, pos, 3)?;
    let daddr = dec_addr(b, f, pos, 4)?;
    let v = read_packed(b, saddr, ls)?;
    let ovf = v.digit_len() > ld as usize;
    if ld > 0 {
        // 最終バイト（符号+LSD）は表引き。
        let last_src = load(b, saddr.wrapping_add(pbytes(ls) - 1), 1)?;
        let last_dst = load(b, tbl.wrapping_add(last_src as u32), 1)?;
        store(b, daddr + (ld - 1), 1, last_dst)?;
        // 残りは右詰めの ASCII 数字（先頭は '0' 埋め）。
        for k in 1..ld as usize {
            let d = if k < v.digits.len() {
                v.digits[v.digits.len() - 1 - k]
            } else {
                0
            };
            store(
                b,
                daddr + (ld as usize - 1 - k) as u32,
                1,
                u128::from(b'0' + d.min(9)),
            )?;
        }
    }
    set_cb3(b, saddr, daddr);
    cc_dec(b, &v, ovf);
    dv_trap(b)
}

/// cvttp: trailing numeric → packed。表引きと入力検査つき。
pub fn cvttp(b: &mut InterpBackend, f: &Fetched, pos: &[(u32, u32)]) -> Result<(), InterpExit> {
    let ls = dec_len(b, f, pos, 0)?;
    let saddr = dec_addr(b, f, pos, 1)?;
    let tbl = dec_addr(b, f, pos, 2)?;
    let ld = dec_len(b, f, pos, 3)?;
    let daddr = dec_addr(b, f, pos, 4)?;
    let v = if ls == 0 {
        // 長さ 0: 表は参照せず、dst は +0。
        PackedDec::from_digits(&[0], false).unwrap()
    } else {
        let mut digits = Vec::with_capacity(ls as usize);
        for i in 0..ls - 1 {
            let c = load(b, saddr + i, 1)? as u8;
            if !c.is_ascii_digit() {
                return Err(fault(scb::RESERVED_OPERAND, None));
            }
            digits.push(c & 0xf);
        }
        // 最終バイトは表引き → パックの (LSD, 符号) ニブル。
        let last = load(b, saddr + (ls - 1), 1)?;
        let tb = load(b, tbl.wrapping_add(last as u32), 1)? as u8;
        let (dig, sig) = (tb >> 4, tb & 0xf);
        let plus = matches!(sig, 0xa | 0xc | 0xe | 0xf);
        let minus = matches!(sig, 0xb | 0xd);
        if dig > 9 || !(plus || minus) {
            return Err(fault(scb::RESERVED_OPERAND, None));
        }
        digits.push(dig);
        norm(&PackedDec {
            digits,
            negative: minus,
        })
    };
    let ovf = write_packed(b, daddr, ld, &v.digits, v.negative)?;
    set_cb3(b, saddr, daddr);
    cc_dec(b, &v, ovf);
    dv_trap(b)
}

// ---- ashp ----

/// ashp: cnt.rb, srclen.rw, src.ab, round.rb, dstlen.rw, dst.ab。
/// cnt>0 は 10^cnt 倍、cnt<0 は捨てる桁の最上位に round(3:0) を
/// 十進加算して桁上げを伝搬する丸め。
pub fn ashp(b: &mut InterpBackend, f: &Fetched, pos: &[(u32, u32)]) -> Result<(), InterpExit> {
    let cnt = eval_r(b, f, pos, 0, Width::B)? as u8 as i8 as i32;
    let ls = dec_len(b, f, pos, 1)?;
    let saddr = dec_addr(b, f, pos, 2)?;
    let round = (eval_r(b, f, pos, 3, Width::B)? & 0xf) as u8;
    let ld = dec_len(b, f, pos, 4)?;
    let daddr = dec_addr(b, f, pos, 5)?;
    let v = read_packed(b, saddr, ls)?;
    let mut digits = v.digits.clone();
    while digits.len() > 1 && digits[0] == 0 {
        digits.remove(0);
    }
    let result = if cnt >= 0 {
        let mut d = digits;
        d.extend(std::iter::repeat_n(0, cnt as usize));
        PackedDec {
            digits: d,
            negative: v.negative,
        }
    } else {
        let m = (-cnt) as usize;
        let mut kept: Vec<u8> = if m < digits.len() {
            digits[..digits.len() - m].to_vec()
        } else {
            vec![0]
        };
        // 捨てる桁の最上位 + round → >=10 なら kept に桁上げ。
        let top = if m <= digits.len() {
            digits[digits.len() - m]
        } else {
            0
        };
        if u16::from(top) + u16::from(round) >= 10 {
            let mut carry = 1u8;
            for d in kept.iter_mut().rev() {
                let s = *d + carry;
                *d = s % 10;
                carry = s / 10;
            }
            if carry != 0 {
                kept.insert(0, 1);
            }
        }
        PackedDec {
            digits: kept,
            negative: v.negative,
        }
    };
    let result = norm(&result);
    let ovf = write_packed(b, daddr, ld, &result.digits, result.negative)?;
    set_cb3(b, saddr, daddr);
    cc_dec(b, &result, ovf);
    dv_trap(b)
}

// ---- editpc ----

/// fill レジスタ（r2<7:0>）/ sign レジスタ（r2<15:8>）。
fn fill_get(b: &InterpBackend) -> u8 {
    r_get(b, 2) as u8
}
fn sign_get(b: &InterpBackend) -> u8 {
    (r_get(b, 2) >> 8) as u8
}
fn fill_set(b: &mut InterpBackend, c: u8) {
    r_set(b, 2, (r_get(b, 2) & !0xff) | u32::from(c));
}
fn sign_set(b: &mut InterpBackend, c: u8) {
    r_set(b, 2, (r_get(b, 2) & !0xff00) | (u32::from(c) << 8));
}

/// STORE(char): (r5) <- c; r5 <- r5+1。
fn edit_store(b: &mut InterpBackend, c: u8) -> Result<(), InterpExit> {
    let a = r_get(b, 5);
    store(b, a, 1, u128::from(c))?;
    r_set(b, 5, a.wrapping_add(1));
    Ok(())
}

/// READ(): ソースの次の数字ニブル。r0<0（上位 16 ビットが負の
/// 補数カウント）なら補充の 0 を返す。r0==0 なら予約オペランド
/// abort（r0<- -1、r3 は演算子の位置のまま）。
fn edit_read(b: &mut InterpBackend) -> Result<u8, InterpExit> {
    let r0 = r_get(b, 0) as i32;
    if r0 < 0 {
        r_set(b, 0, (r0 as u32).wrapping_add(0x1_0000));
        return Ok(0);
    }
    if r0 == 0 {
        r_set(b, 0, u32::MAX);
        return Err(fault(scb::RESERVED_OPERAND, None));
    }
    let r1 = r_get(b, 1);
    let byte = load(b, r1, 1)? as u8;
    let nib = if r0 & 1 == 1 { byte >> 4 } else { byte & 0xf };
    r_set(b, 0, r0 as u32 - 1);
    if (r0 - 1) & 1 == 1 {
        r_set(b, 1, r1.wrapping_add(1));
    }
    Ok(nib)
}

/// MOVE/FLOAT の共通部: 数字を 1 個読み、有意性（PSW(C)）を
/// 見て fill か ASCII 数字を書く。float なら初めての非零数字で
/// sign を先に書く。
fn edit_move(b: &mut InterpBackend, float: bool) -> Result<(), InterpExit> {
    let tmp = edit_read(b)?;
    let mut c = psl_flag(b, psl::C);
    if tmp != 0 {
        if float && !c {
            let s = sign_get(b);
            edit_store(b, s)?;
        }
        psl_flag_set(b, psl::Z, false);
        c = true;
        psl_flag_set(b, psl::C, true);
    }
    if c {
        edit_store(b, b'0' + tmp)?;
    } else {
        let fl = fill_get(b);
        edit_store(b, fl)?;
    }
    Ok(())
}

/// editpc: srclen.rw, src.ab, pattern.ab, dst.ab。パターン演算子を
/// 1 個 1 ステップで解釈する —— 状態は r0-r5 と NZVC に全部載る
/// （正本の制御ブロックどおり）ので FPD 中断・再開が自然に効く。
/// work = [元の srclen, srcaddr]（完了時の r0/r1 復元用）。
pub fn editpc(
    b: &mut InterpBackend,
    f: &Fetched,
    pos: &[(u32, u32)],
    pc0: u32,
) -> Result<(), InterpExit> {
    const OPC: u16 = 0x38;
    let work = match partial_resume(b, OPC) {
        Some(w) => w,
        None => {
            let srclen = dec_len(b, f, pos, 0)?;
            let saddr = dec_addr(b, f, pos, 1)?;
            let pat = dec_addr(b, f, pos, 2)?;
            let daddr = dec_addr(b, f, pos, 3)?;
            let v = read_packed(b, saddr, srclen)?;
            psl_flag_set(b, psl::V, false);
            psl_flag_set(b, psl::C, false);
            psl_flag_set(b, psl::Z, true);
            psl_flag_set(b, psl::N, v.negative);
            r_set(b, 0, srclen);
            r_set(b, 1, saddr);
            // sign = '+'が負なら '-'、正なら空白。fill = 空白。
            let sign = if v.negative { b'-' } else { b' ' };
            r_set(b, 2, (u32::from(sign) << 8) | u32::from(b' '));
            r_set(b, 3, pat);
            r_set(b, 4, 0);
            r_set(b, 5, daddr);
            [srclen, saddr, 0, 0]
        }
    };
    let mut r3 = r_get(b, 3);
    let op = load(b, r3, 1)? as u8;
    let rep = op & 0x0f;
    // 予約パターン演算子 → 予約オペランド fault。FPD を立てて
    // 現在の制御ブロックを残す（続行可能な fault）。
    let reserved = |b: &mut InterpBackend, work: [u32; 4]| -> InterpExit {
        partial_save(b, OPC, work, pc0);
        fault(scb::RESERVED_OPERAND, None)
    };
    let mut done = false;
    match op {
        0x00 => {
            // EO$END: 残り数字があれば abort（r3 = EO$END の位置）。
            if r_get(b, 0) != 0 {
                return Err(fault(scb::RESERVED_OPERAND, None));
            }
            done = true;
            r_set(b, 0, work[0]);
            r_set(b, 1, work[1]);
            r_set(b, 2, 0);
            r_set(b, 4, 0);
            if psl_flag(b, psl::Z) {
                psl_flag_set(b, psl::N, false);
            }
        }
        0x01 => {
            // EO$END_FLOAT: 有意性がなければ sign を置いて有意にする。
            if !psl_flag(b, psl::C) {
                let s = sign_get(b);
                edit_store(b, s)?;
                psl_flag_set(b, psl::C, true);
            }
            r3 = r3.wrapping_add(1);
        }
        0x02 => {
            psl_flag_set(b, psl::C, false);
            r3 = r3.wrapping_add(1);
        }
        0x03 => {
            psl_flag_set(b, psl::C, true);
            r3 = r3.wrapping_add(1);
        }
        0x04 => {
            let s = sign_get(b);
            edit_store(b, s)?;
            r3 = r3.wrapping_add(1);
        }
        0x40..=0x47 => {
            let ch = load(b, r3.wrapping_add(1), 1)? as u8;
            match op {
                0x40 => fill_set(b, ch),
                0x41 => sign_set(b, ch),
                0x42 => {
                    if !psl_flag(b, psl::N) {
                        sign_set(b, ch);
                    }
                }
                0x43 => {
                    if psl_flag(b, psl::N) {
                        sign_set(b, ch);
                    }
                }
                0x44 => {
                    if psl_flag(b, psl::C) {
                        edit_store(b, ch)?;
                    } else {
                        let fl = fill_get(b);
                        edit_store(b, fl)?;
                    }
                }
                0x45 => {
                    // EO$BLANK_ZERO: 値が零なら直前 len バイトを fill。
                    if ch == 0 {
                        return Err(fault(scb::RESERVED_OPERAND, None));
                    }
                    if psl_flag(b, psl::Z) {
                        r_set(b, 5, r_get(b, 5).wrapping_sub(u32::from(ch)));
                        for _ in 0..ch {
                            let fl = fill_get(b);
                            edit_store(b, fl)?;
                        }
                    }
                }
                0x46 => {
                    // EO$REPLACE_SIGN: 値が零なら len 前のバイトを fill。
                    if ch == 0 {
                        return Err(fault(scb::RESERVED_OPERAND, None));
                    }
                    if psl_flag(b, psl::Z) {
                        let a = r_get(b, 5).wrapping_sub(u32::from(ch));
                        store(b, a, 1, u128::from(fill_get(b)))?;
                    }
                }
                _ => {
                    // EO$ADJUST_INPUT: 入力桁数を len に合わせる。
                    if ch == 0 || ch > 31 {
                        return Err(fault(scb::RESERVED_OPERAND, None));
                    }
                    let lo = r_get(b, 0) & 0xffff;
                    if lo > u32::from(ch) {
                        // 多い → 上位の余分を読み捨て。非零を捨てたら
                        // Z=0・C=1・V=1。
                        for _ in 0..lo - u32::from(ch) {
                            if edit_read(b)? != 0 {
                                psl_flag_set(b, psl::Z, false);
                                psl_flag_set(b, psl::C, true);
                                psl_flag_set(b, psl::V, true);
                            }
                        }
                    } else {
                        // 少ない → 上位 16 ビットに負の補充数。
                        let adj = (lo as i32 - i32::from(ch)) as u32;
                        r_set(b, 0, (adj << 16) | lo);
                    }
                }
            }
            r3 = r3.wrapping_add(2);
        }
        0x81..=0x8f => {
            for _ in 0..rep {
                let fl = fill_get(b);
                edit_store(b, fl)?;
            }
            r3 = r3.wrapping_add(1);
        }
        0x91..=0x9f => {
            for _ in 0..rep {
                edit_move(b, false)?;
            }
            r3 = r3.wrapping_add(1);
        }
        0xa1..=0xaf => {
            for _ in 0..rep {
                edit_move(b, true)?;
            }
            r3 = r3.wrapping_add(1);
        }
        _ => return Err(reserved(b, work)),
    }
    r_set(b, 3, r3);
    if done {
        partial_done(b);
        dv_trap(b)?;
    } else {
        partial_save(b, OPC, work, pc0);
    }
    Ok(())
}

/// exec からの入口。
pub fn exec(
    b: &mut InterpBackend,
    f: &Fetched,
    pos: &[(u32, u32)],
    pc0: u32,
) -> Result<(), InterpExit> {
    match f.insn {
        Insn::Movp => movp(b, f, pos),
        Insn::Cmpp3 | Insn::Cmpp4 => cmpp(b, f, pos),
        Insn::Addp4 | Insn::Addp6 | Insn::Subp4 | Insn::Subp6 | Insn::Mulp | Insn::Divp => {
            arithp(b, f, pos)
        }
        Insn::Cvtpl => cvtpl(b, f, pos),
        Insn::Cvtlp => cvtlp(b, f, pos),
        Insn::Cvtps => cvtps(b, f, pos),
        Insn::Cvtsp => cvtsp(b, f, pos),
        Insn::Cvtpt => cvtpt(b, f, pos),
        Insn::Cvttp => cvttp(b, f, pos),
        Insn::Ashp => ashp(b, f, pos),
        Insn::Editpc => editpc(b, f, pos, pc0),
        _ => unreachable!(),
    }
}
