// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! m68k の実効アドレス（EA）の評価。
//!
//! 命令は16ビットの先頭ワードと、EA が要求する拡張語からなる
//! （1つの EA は最大2語、MOVE は両 EA で最大4語。68020+ の
//! full 形式拡張語は未対応）。
//! 先頭ワードは生成デコーダが Insn に解き、ここでは先頭ワード中の
//! EA フィールド（mode[5:3]・reg[2:0]）をオペランドに解釈する。
//! 拡張語は命令フェッチとして `ext` 以降の偶数アドレスから backend
//! 経由で読み、消費した語数を返す。命令長は 2 + 拡張語数×2 となる。
//!
//! 出典は SPEC-M68K-PRM (M68000PM/AD Rev 1) §Effective Addressing。
//! Ref: SPEC-M68K-PRM (Rev 1).

use polyisa_mem::{Access, AccessKind, Align, Endian};
use polyisa_sem::{Backend, Cmp, ExceptionKind, GuestException, StateArray, W8, W16, W32, W64};

use super::sem::{self, Ssp, Usp};

/// 拡張語の読み出しに使うアクセス属性（BE・命令フェッチ）。
pub(crate) const FETCH: Access = Access {
    endian: Endian::Be,
    align: Align::Natural,
    kind: AccessKind::Fetch,
};

/// `konst` の短い包み（他ゲストの `k`/`k32` と同じ形）。
fn k16<B: Backend>(b: &mut B, v: u16) -> B::V<W16> {
    b.konst::<W16>(v)
}

fn k32<B: Backend>(b: &mut B, v: u32) -> B::V<W32> {
    b.konst::<W32>(v)
}

fn k64<B: Backend>(b: &mut B, v: u64) -> B::V<W64> {
    b.konst::<W64>(v)
}

/// full 形式拡張語（ext1 の bit8=1）が消費する総語数（ext1 自身を
/// 含む）。BD は bits[5:4]（00/01→0、10→1 語、11→2 語）、I/IS
/// bits[1:0] の OD サイズ（2→1 語、3→2 語）が続く。
// Ref: SPEC-M68K-UM (MC68020) §Brief/Full Format Extension Word.
pub const fn full_ext_words(e1: u16) -> u32 {
    let bd = match (e1 >> 4) & 3 {
        0b10 => 1,
        0b11 => 2,
        _ => 0,
    };
    // iis!=0 のときメモリインダイレクト。bits[1:0] は OD サイズ
    // （0/1=なし、2=語、3=long）。
    let od = match e1 & 3 {
        2 => 1,
        3 => 2,
        _ => 0,
    };
    1 + bd + od
}

/// モデル依存を含む拡張語総数。`peek(i)` は `pc+2+2i`（0 始まり）の
/// 語を読む。`gen020` が立つとき、mode 6/mode 7 reg 3 の EA が
/// full 形式（ext1 の bit8=1）なら `full_ext_words` で語数を足し直し、
/// 分岐の disp バイト 0xFF は 32 ビット変位語 2 つとして数える。
// Ref: SPEC-M68K-UM (MC68020) §Instruction Format.
#[must_use]
pub fn insn_ext_dyn(
    insn: super::Insn,
    w: u64,
    gen020: bool,
    bdisp32: bool,
    peek: impl Fn(u32) -> Option<u16>,
) -> Option<u32> {
    use super::Insn::*;
    // 分岐は disp バイトで語数が決まる（68000 では 0xFF も disp8）。
    if matches!(insn, Bra | Bsr | Bcc) {
        return match w & 0xFF {
            0 => Some(1),
            0xFF if bdisp32 => Some(2),
            _ => Some(0),
        };
    }
    let base = insn_ext_words(insn, w)?;
    if !gen020 {
        return Some(base);
    }
    // full 形式が起きうるのは mode 6 / mode 7 reg 3 の EA スロットのみ。
    // `ea_words` はオフセット off にあるスロットの実語数を返す
    // （full なら ext1 から算出、そうでなければ静的値 st に一致する）。
    let ea_words = |off: u32, mode: u8, reg: u8, st: u32| -> u32 {
        if st == 1
            && (mode == 6 || (mode == 7 && reg == 3))
            && let Some(e1) = peek(off)
            && e1 & 0x100 != 0
        {
            return full_ext_words(e1);
        }
        st
    };
    let (em, er) = (ea_mode(w), ea_reg(w));
    match insn {
        // 先頭が EA スロットの命令: st=1 のものだけ差し替わる。
        super::Insn::MoveaW
        | super::Insn::MoveaL
        | super::Insn::Add
        | super::Insn::AddDn
        | super::Insn::AddaL
        | super::Insn::Sub
        | super::Insn::SubDn
        | super::Insn::SubaL
        | super::Insn::Cmp
        | super::Insn::CmpaL
        | super::Insn::Addq
        | super::Insn::Subq
        | super::Insn::Or
        | super::Insn::OrBDn
        | super::Insn::OrWDn
        | super::Insn::OrLDn
        | super::Insn::And
        | super::Insn::AndBDn
        | super::Insn::AndWDn
        | super::Insn::AndLDn
        | super::Insn::Eor
        | super::Insn::Not
        | super::Insn::Clr
        | super::Insn::Tst
        | super::Insn::Neg
        | super::Insn::Negx
        | super::Insn::Jmp
        | super::Insn::Jsr
        | super::Insn::Scc
        | super::Insn::Lea
        | super::Insn::Pea
        | super::Insn::Mulu
        | super::Insn::Muls
        | super::Insn::Divu
        | super::Insn::Divs
        | super::Insn::Nbcd
        | super::Insn::Chk
        | super::Insn::Mv2ccr
        | super::Insn::Mv2sr
        | super::Insn::Mvfrsr
        | super::Insn::Btst
        | super::Insn::Bchg
        | super::Insn::Bclr
        | super::Insn::Bset
        | super::Insn::AsrM
        | super::Insn::AslM
        | super::Insn::LsrM
        | super::Insn::LslM
        | super::Insn::RoxrM
        | super::Insn::RoxlM
        | super::Insn::RorM
        | super::Insn::RolM => Some(ea_words(0, em, er, base)),
        // 即値語が先に来る命令: EA スロットは iw 語後。
        super::Insn::Addi | super::Insn::Subi | super::Insn::Cmpi => {
            let iw = if qsz(w) == 2 { 2 } else { 1 };
            Some(iw + ea_words(iw, em, er, base - iw))
        }
        super::Insn::Ori | super::Insn::Andi | super::Insn::Eori => {
            if em == 7 && er == 4 {
                return Some(base);
            }
            let iw = if qsz(w) == 2 { 2 } else { 1 };
            Some(iw + ea_words(iw, em, er, base - iw))
        }
        // 即値ビット操作はビット番号語、movem はマスク語、
        // ビットフィールドは offset/width 語が先。
        super::Insn::BtstI
        | super::Insn::BchgI
        | super::Insn::BclrI
        | super::Insn::BsetI
        | super::Insn::Bftst
        | super::Insn::Bfextu
        | super::Insn::Bfchg
        | super::Insn::Bfexts
        | super::Insn::Bfclr
        | super::Insn::Bfffo
        | super::Insn::Bfset
        | super::Insn::Bfins
        | super::Insn::Mull
        | super::Insn::Divl
        | super::Insn::Casb
        | super::Insn::Casw
        | super::Insn::Casl
        | super::Insn::MovrmW
        | super::Insn::MovrmL
        | super::Insn::MrmemW
        | super::Insn::MrmemL => Some(1 + ea_words(1, em, er, base - 1)),
        // move.<b|w|l>: dst スロットは src の実語数の後。
        super::Insn::MoveB | super::Insn::MoveW | super::Insn::MoveL => {
            let size = move_size(insn);
            let s_st = ext_words(em, er, size).unwrap_or(0);
            let s = ea_words(0, em, er, s_st);
            let (dm, dr) = (dest_mode(w), dest_reg(w));
            let d_st = ext_words(dm, dr, size).unwrap_or(0);
            Some(s + ea_words(s, dm, dr, d_st))
        }
        _ => Some(base),
    }
}

/// EA の評価結果。レジスタ直接は番号、メモリは実効アドレスを持つ。
pub enum Ea<B: Backend> {
    /// データレジスタ直接（mode 0）。番号は 0〜7。
    D(u8),
    /// アドレスレジスタ直接（mode 1）。番号は 0〜7 で、7 は
    /// 実行時の SR.S に応じた USP/SSP を指す。
    A(u8),
    /// メモリ実効アドレス（indirect・ディスプレイスメント・
    /// 絶対・PC 相対）。
    Addr(B::V<W64>),
    /// 即値（mode 7 reg 4 のみ）。書き込み先には使えない。
    Imm(B::V<W32>),
}

/// EA が消費する拡張語数を、先頭ワードの情報だけから求める。
/// `size` はオペランドのバイト数（1/2/4、無検証・それ以外は
/// 呼び出し側の前提違反）。mode 7 reg 5〜7 のような未定義の
/// 組み合わせは拡張語を消費しないので 0 —— illegal の判定は
/// `eval`/`mode7` 側の責任で、ここでは語数の契約だけ扱う。
// Ref: SPEC-M68K-PRM (Rev 1).
#[must_use]
pub const fn ext_words(mode: u8, reg: u8, size: u32) -> Option<u32> {
    match mode {
        5 | 6 => Some(1),
        7 => match reg {
            0 | 2 | 3 => Some(1),
            1 => Some(2),
            4 => Some(if size > 2 { 2 } else { 1 }),
            _ => Some(0),
        },
        _ => Some(0),
    }
}

/// 先頭ワードの source EA フィールド（mode[5:3]）。
#[must_use]
pub const fn ea_mode(w: u64) -> u8 {
    ((w >> 3) & 7) as u8
}

/// 先頭ワードの source EA フィールド（reg[2:0]）。
#[must_use]
pub const fn ea_reg(w: u64) -> u8 {
    (w & 7) as u8
}

/// 先頭ワードの destination EA フィールド（mode[8:6]）。
#[must_use]
pub const fn dest_mode(w: u64) -> u8 {
    ((w >> 6) & 7) as u8
}

/// 先頭ワードの destination EA フィールド（reg[11:9]）。
#[must_use]
pub const fn dest_reg(w: u64) -> u8 {
    ((w >> 9) & 7) as u8
}

/// 命令全体が消費する拡張語数。命令長は 2 + 戻り値×2。
///
/// EA フィールドの位置とサイズは命令の仕様ごとに違うので、ここが
/// Insn から `ext_words` への振り分けの契約点になる。F0 形式の
/// 固定ワード命令は EA を持たないので 0。
// Ref: SPEC-M68K-PRM (Rev 1).
#[must_use]
pub const fn insn_ext_words(insn: super::Insn, w: u64) -> Option<u32> {
    match insn {
        // move.<b|w|l>: source と destination の EA がそれぞれ語を
        // 消費しうる。
        super::Insn::MoveB | super::Insn::MoveW | super::Insn::MoveL => {
            let size = move_size(insn);
            let Some(s) = ext_words(ea_mode(w), ea_reg(w), size) else {
                return None;
            };
            let Some(d) = ext_words(dest_mode(w), dest_reg(w), size) else {
                return None;
            };
            Some(s + d)
        }
        // movea: destination は An 直なので source だけが語を消費する。
        super::Insn::MoveaW | super::Insn::MoveaL => {
            let size = move_size(insn);
            ext_words(ea_mode(w), ea_reg(w), size)
        }
        // add/sub/cmp 系: EA は一つ。オペランドサイズは opm
        // （bits[8:6]）で決まる（0,4→b、1,3,5→w、2,6,7→l）。
        super::Insn::Add
        | super::Insn::AddDn
        | super::Insn::AddaL
        | super::Insn::Sub
        | super::Insn::SubDn
        | super::Insn::SubaL
        | super::Insn::Cmp
        | super::Insn::CmpaL => {
            let opm = dest_mode(w);
            let size = match opm {
                0 | 4 => 1,
                1 | 3 | 5 => 2,
                _ => 4,
            };
            ext_words(ea_mode(w), ea_reg(w), size)
        }
        // addq/subq: EA は一つ。サイズは qsz（bits[7:6]）。
        super::Insn::Addq | super::Insn::Subq => {
            let size = 1u32 << qsz(w);
            ext_words(ea_mode(w), ea_reg(w), size)
        }
        // addi/subi/cmpi: 即値の拡張語 + EA の拡張語。
        super::Insn::Addi | super::Insn::Subi | super::Insn::Cmpi => {
            let size = 1u32 << qsz(w);
            let iw = if qsz(w) == 2 { 2 } else { 1 };
            let Some(e) = ext_words(ea_mode(w), ea_reg(w), size) else {
                return None;
            };
            Some(e + iw)
        }
        // or/and/eor 系: EA は一つ。サイズは opm で add/sub と同じ写像。
        super::Insn::Or
        | super::Insn::OrBDn
        | super::Insn::OrWDn
        | super::Insn::OrLDn
        | super::Insn::And
        | super::Insn::AndBDn
        | super::Insn::AndWDn
        | super::Insn::AndLDn
        | super::Insn::Eor => {
            let opm = dest_mode(w);
            let size = match opm {
                0 | 4 => 1,
                1 | 3 | 5 => 2,
                _ => 4,
            };
            ext_words(ea_mode(w), ea_reg(w), size)
        }
        // not/clr/tst: qsz サイズの EA は一つ。
        super::Insn::Not
        | super::Insn::Clr
        | super::Insn::Tst
        | super::Insn::Neg
        | super::Insn::Negx => {
            let size = 1u32 << qsz(w);
            ext_words(ea_mode(w), ea_reg(w), size)
        }
        // 分岐: disp8=0 のみ 16bit 変位語を消費。
        super::Insn::Bra | super::Insn::Bsr | super::Insn::Bcc => {
            if w & 0xFF == 0 {
                Some(1)
            } else {
                Some(0)
            }
        }
        // jmp/jsr: 制御 EA の語数。
        super::Insn::Jmp | super::Insn::Jsr => ext_words(ea_mode(w), ea_reg(w), 4),
        // rts/rtr/mvusp: 拡張語なし（F0 表に含めずここで扱う）。
        super::Insn::Rts | super::Insn::Rtr | super::Insn::Mv2usp | super::Insn::Mvfrusp => Some(0),
        // stop は直後に即値語 1 語を取る。
        super::Insn::Stop => Some(1),
        // scc: EA のみ。dbcc: 変位語1つ。
        super::Insn::Scc => ext_words(ea_mode(w), ea_reg(w), 1),
        super::Insn::Dbcc | super::Insn::Link => Some(1),
        // EA・即値語を持たない命令は明示的に 0。
        super::Insn::ExgDd
        | super::Insn::ExgAa
        | super::Insn::ExgDa
        | super::Insn::Swap
        | super::Insn::ExtW
        | super::Insn::ExtL
        | super::Insn::ExtbL => Some(0),
        super::Insn::Lea | super::Insn::Pea => ext_words(ea_mode(w), ea_reg(w), 4),
        super::Insn::Mulu | super::Insn::Muls | super::Insn::Divu | super::Insn::Divs => {
            ext_words(ea_mode(w), ea_reg(w), 2)
        }
        super::Insn::AbcdR | super::Insn::AbcdM | super::Insn::SbcdR | super::Insn::SbcdM => {
            Some(0)
        }
        super::Insn::Nbcd => ext_words(ea_mode(w), ea_reg(w), 1),
        super::Insn::Trap | super::Insn::Trapv | super::Insn::Linea | super::Insn::Linef => Some(0),
        // addx/subx は2レジスタ形式のみで拡張語を持たない。
        super::Insn::AddxD | super::Insn::AddxM | super::Insn::SubxD | super::Insn::SubxM => {
            Some(0)
        }
        // cas は Du/Dc の拡張語1つ + EA 拡張語。
        super::Insn::Casb | super::Insn::Casw | super::Insn::Casl => {
            match ext_words(ea_mode(w), ea_reg(w), 4) {
                Some(n) => Some(n + 1),
                None => None,
            }
        }
        super::Insn::Chk | super::Insn::Mv2ccr | super::Insn::Mv2sr | super::Insn::Mvfrsr => {
            ext_words(ea_mode(w), ea_reg(w), 2)
        }
        // movem はマスク語（pc+2）+ EA 拡張語、movep は変位語1つ。
        super::Insn::MovrmW | super::Insn::MovrmL | super::Insn::MrmemW | super::Insn::MrmemL => {
            match ext_words(ea_mode(w), ea_reg(w), 4) {
                Some(n) => Some(n + 1),
                None => None,
            }
        }
        super::Insn::MovepWm
        | super::Insn::MovepLm
        | super::Insn::MovepWr
        | super::Insn::MovepLr => Some(1),
        // レジスタビット操作: EA のみ（Dn なら拡張語なし）。
        super::Insn::Btst | super::Insn::Bchg | super::Insn::Bclr | super::Insn::Bset => {
            ext_words(ea_mode(w), ea_reg(w), 1)
        }
        // 即値ビット操作: ビット番号語 + EA 語。
        super::Insn::BtstI | super::Insn::BchgI | super::Insn::BclrI | super::Insn::BsetI => {
            match ext_words(ea_mode(w), ea_reg(w), 1) {
                Some(n) => Some(1 + n),
                None => None,
            }
        }
        // ビットフィールド操作: offset/width 語 + EA 語。
        super::Insn::Bftst
        | super::Insn::Bfextu
        | super::Insn::Bfchg
        | super::Insn::Bfexts
        | super::Insn::Bfclr
        | super::Insn::Bfffo
        | super::Insn::Bfset
        | super::Insn::Bfins => match ext_words(ea_mode(w), ea_reg(w), 4) {
            Some(n) => Some(1 + n),
            None => None,
        },
        // mull/divl: 拡張語 1 語 + 32bit EA。
        super::Insn::Mull | super::Insn::Divl => match ext_words(ea_mode(w), ea_reg(w), 4) {
            Some(n) => Some(1 + n),
            None => None,
        },
        // メモリシフト: word サイズの EA は一つ。
        super::Insn::AsrM
        | super::Insn::AslM
        | super::Insn::LsrM
        | super::Insn::LslM
        | super::Insn::RoxrM
        | super::Insn::RoxlM
        | super::Insn::RorM
        | super::Insn::RolM => ext_words(ea_mode(w), ea_reg(w), 2),
        // ori/andi/eori: EA フィールドが #imm（to CCR/to SR の特殊
        // 符号化）なら即値語のみ。通常は即値語 + EA 語。
        super::Insn::Ori | super::Insn::Andi | super::Insn::Eori => {
            let size = 1u32 << qsz(w);
            let iw = if qsz(w) == 2 { 2 } else { 1 };
            if ea_mode(w) == 7 && ea_reg(w) == 4 {
                return Some(iw);
            }
            let Some(e) = ext_words(ea_mode(w), ea_reg(w), size) else {
                return None;
            };
            Some(e + iw)
        }
        // 拡張語を取らない残り（網羅 match: 宣言だけ追加した命令は
        // ここでコンパイルエラーになり語数契約を忘れない）。
        super::Insn::Asl
        | super::Insn::Asr
        | super::Insn::Cmpm
        | super::Insn::Illegal
        | super::Insn::Lsl
        | super::Insn::Lsr
        | super::Insn::Moveq
        | super::Insn::Nop
        | super::Insn::Reset
        | super::Insn::Rol
        | super::Insn::Ror
        | super::Insn::Roxl
        | super::Insn::Roxr
        | super::Insn::Rte
        | super::Insn::Unlk => Some(0),
    }
}

/// 先頭ワードのサイズフィールド（bits[7:6]）。
#[must_use]
pub const fn qsz(w: u64) -> u8 {
    ((w >> 6) & 3) as u8
}

/// move 系命令のオペランドサイズ（バイト）。
/// move/movea 以外の呼び出しは前提違反。
#[must_use]
pub const fn move_size(insn: super::Insn) -> u32 {
    match insn {
        super::Insn::MoveB => 1,
        super::Insn::MoveW | super::Insn::MoveaW => 2,
        super::Insn::MoveL | super::Insn::MoveaL => 4,
        _ => panic!("move_size: not a move"),
    }
}

/// EA を評価し、オペランドと消費した拡張語数を返す。
///
/// `mode`/`reg` は先頭ワードの EA フィールド、`size` はオペランドの
/// バイト数（1/2/4）、`ext` はこの EA の最初の拡張語の仮想アドレス
/// （命令先頭 + 2 + 先行する EA の消費分）。`(An)+`/`-(An)` はここで
/// An を更新する。
///
/// 合法性のうち文脈依存のものは呼び出し側の責任。具体的には
/// mode 1 の byte サイズ（illegal）、宛先としての PC 相対・即値
/// （不可）、An 直接の alterability などは命令の仕様から呼び出し側が
/// 弾く。
// Ref: SPEC-M68K-PRM (Rev 1).
pub fn eval<B: Backend>(
    b: &mut B,
    mode: u8,
    reg: u8,
    size: u32,
    ext: u64,
) -> Result<(Ea<B>, u32), B::Exit> {
    let (e, n, _cnt) = eval_full(b, mode, reg, size, ext)?;
    Ok((e, n))
}

/// `eval` と同じだが、消費語数をシンボリックにも返す。
/// 68020+ の full 形式 EA は ext1 の内容で語数が変わるため、
/// (評価結果 EA, 静的語数, 動的語数) の戻り型。
type EaFull<B> = Result<(Ea<B>, u32, <B as Backend>::V<W32>), <B as Backend>::Exit>;

/// jmp/jsr のリンク先のように「命令末尾」が必要な呼び出し側は
/// こちらを使う。
pub fn eval_full<B: Backend>(b: &mut B, mode: u8, reg: u8, size: u32, ext: u64) -> EaFull<B> {
    let extv = k64(b, ext);
    eval_full_v(b, mode, reg, size, extv)
}

/// `eval_full` のシンボリック拡張語基底版。src EA の消費語数が
/// 動的な `move` の宛先 EA など、命令末尾がシンボリックな
/// 場合に使う。
pub fn eval_full_v<B: Backend>(
    b: &mut B,
    mode: u8,
    reg: u8,
    size: u32,
    ext: B::V<W64>,
) -> EaFull<B> {
    debug_assert!(matches!(size, 1 | 2 | 4));
    macro_rules! done {
        ($e:expr, $n:expr) => {
            return Ok(($e, $n, k32(b, $n)))
        };
    }
    match mode {
        0 => done!(Ea::D(reg), 0),
        1 => done!(Ea::A(reg), 0),
        2 => {
            let v = sem::areg(b, reg);
            done!(Ea::Addr(b.zext::<W32, W64>(v)), 0)
        }
        // (An)+: 読み出し後に An を size 分進める。A7 の byte だけ
        // 2 語境界を保つため 2 進める。
        3 => {
            let old = sem::areg(b, reg);
            let step = k32(b, an_step(reg, size));
            let new = b.add(old, step);
            sem::set_areg(b, reg, new)?;
            done!(Ea::Addr(b.zext::<W32, W64>(old)), 0)
        }
        // -(An): An を size 分下げてから読み出す。
        4 => {
            let old = sem::areg(b, reg);
            let step = k32(b, an_step(reg, size));
            let new = b.sub(old, step);
            sem::set_areg(b, reg, new)?;
            done!(Ea::Addr(b.zext::<W32, W64>(new)), 0)
        }
        // d16(An): 拡張語の16ビット変位を符号拡張して An に足す。
        5 => {
            let d = extw_v(b, ext, 0)?;
            let disp = b.sext::<W16, W32>(d);
            let base = sem::areg(b, reg);
            let addr = b.add(base, disp);
            done!(Ea::Addr(b.zext::<W32, W64>(addr)), 1)
        }
        // d8(An,Xn): 68000/68010 は簡易拡張語のみ、68020+ は ext1 の
        // bit8 で full 形式（BD/OD・メモリインダイレクト）に分岐。
        6 => indexed(b, reg, size, ext, false),
        7 => mode7(b, reg, size, ext),
        _ => Err(illegal(b)),
    }
}

/// mode 7（絶対・PC 相対・即値）の reg 細分。
fn mode7<B: Backend>(b: &mut B, reg: u8, size: u32, ext: B::V<W64>) -> EaFull<B> {
    macro_rules! done {
        ($e:expr, $n:expr) => {
            return Ok(($e, $n, k32(b, $n)))
        };
    }
    match reg {
        // (xxx).W: 16ビット絶対アドレスを32ビットに符号拡張。
        0 => {
            let w = extw_v(b, ext, 0)?;
            let a32 = b.sext::<W16, W32>(w);
            done!(Ea::Addr(b.zext::<W32, W64>(a32)), 1)
        }
        // (xxx).L: 32ビット絶対アドレス（2語）。
        1 => {
            let hi = extw_v(b, ext, 0)?;
            let lo = extw_v(b, ext, 2)?;
            let hi_ext = b.zext::<W16, W64>(hi);
            let shift = k64(b, 16);
            let hi64 = b.shl(hi_ext, shift);
            let lo64 = b.zext::<W16, W64>(lo);
            done!(Ea::Addr(b.or(hi64, lo64)), 2)
        }
        // d16(PC): 拡張語自身のアドレスに16ビット変位を足す。
        // アドレス空間は32ビットなので W32 で加算して折り返す。
        2 => {
            let w = extw_v(b, ext, 0)?;
            let base = b.trunc::<W64, W32>(ext);
            let disp = b.sext::<W16, W32>(w);
            let addr = b.add(base, disp);
            done!(Ea::Addr(b.zext::<W32, W64>(addr)), 1)
        }
        // d8(PC,Xn): mode 6 と同じ拡張語形式で基底が ext のアドレス。
        3 => indexed(b, reg, size, ext, true),
        // #imm: byte/word は1語（下位に値）、long は2語。
        // byte は拡張語の下位バイトなので上位を捨てる。
        4 => {
            let w0 = extw_v(b, ext, 0)?;
            if size > 2 {
                let w1 = extw_v(b, ext, 2)?;
                let hi_ext = b.zext::<W16, W32>(w0);
                let shift = k32(b, 16);
                let hi = b.shl(hi_ext, shift);
                let lo = b.zext::<W16, W32>(w1);
                done!(Ea::Imm(b.or(hi, lo)), 2)
            } else {
                let v = b.zext::<W16, W32>(w0);
                let mask = k32(b, (1u32 << (size * 8)) - 1);
                done!(Ea::Imm(b.and(v, mask)), 1)
            }
        }
        _ => Err(illegal(b)),
    }
}

/// (An)+ / -(An) の増減量。A7 は byte でも語境界を保つため 2。
// Ref: SPEC-M68K-PRM (Rev 1) §Address Register Indirect.
const fn an_step(reg: u8, size: u32) -> u32 {
    if reg == 7 && size == 1 { 2 } else { size }
}

/// 拡張語を `addr` から命令フェッチとして読む。
pub(crate) fn ext_w16_v<B: Backend>(b: &mut B, addr: B::V<W64>) -> Result<B::V<W16>, B::Exit> {
    b.load::<W16>(addr, FETCH)
}

pub(crate) fn ext_w16<B: Backend>(b: &mut B, addr: u64) -> Result<B::V<W16>, B::Exit> {
    let a = k64(b, addr);
    ext_w16_v(b, a)
}

/// シンボリック基底 `base` + ホストオフセット `off` の拡張語読み。
fn extw_v<B: Backend>(b: &mut B, base: B::V<W64>, off: u64) -> Result<B::V<W16>, B::Exit> {
    let k = k64(b, off);
    let a = b.add(base, k);
    ext_w16_v(b, a)
}

/// `extw_v` の 32 ビット版。
fn extw32_v<B: Backend>(b: &mut B, base: B::V<W64>, off: u64) -> Result<B::V<W32>, B::Exit> {
    let hi = extw_v(b, base, off)?;
    let lo = extw_v(b, base, off + 2)?;
    let hi32 = b.zext::<W16, W32>(hi);
    let sh = k32(b, 16);
    let hi_s = b.shl(hi32, sh);
    let lo32 = b.zext::<W16, W32>(lo);
    Ok(b.or(hi_s, lo32))
}

/// mode 6 / mode 7 reg 3 の索引 EA。68000/68010 は簡易拡張語
/// （索引 + 8 ビット変位）のみだが、68020+ は索引にスケールが掛かり、
/// ext1 の bit8=1 で full 形式（BD/OD・メモリインダイレクト）になる。
/// `pc_rel` が真なら基底は拡張語自身のアドレス（d8(PC,Xn) 等）、
/// 偽なら An（d8(An,Xn)）。返る語数の第 3 項はシンボリックで、
/// full 形式のとき実際の消費語数になる。
// Ref: SPEC-M68K-UM (MC68020) §Brief/Full Format Extension Word.
fn indexed<B: Backend>(b: &mut B, reg: u8, _size: u32, ext: B::V<W64>, pc_rel: bool) -> EaFull<B> {
    let e1 = extw_v(b, ext, 0)?;
    let (index, disp8) = brief_index(b, e1);
    let index = scale_index(b, e1, index);
    let d32 = b.sext::<W8, W32>(disp8);
    let off = b.add(index, d32);
    let base = if pc_rel {
        b.trunc::<W64, W32>(ext)
    } else {
        sem::areg(b, reg)
    };
    let mut ea32 = b.add(base, off);
    let mut cnt = k32(b, 1);
    if b.param::<super::EaFullParam>() {
        let bit8 = k16(b, 0x100);
        let m = b.and(e1, bit8);
        let z = k16(b, 0);
        let is_full = b.cmp(Cmp::Ne, m, z);
        b.if_then_else(
            is_full,
            |bb| {
                let base = if pc_rel {
                    bb.trunc::<W64, W32>(ext)
                } else {
                    sem::areg(bb, reg)
                };
                let (a, n) = full_index(bb, e1, ext, base)?;
                ea32 = a;
                cnt = n;
                Ok(())
            },
            |_| Ok(()),
        )?;
    }
    Ok((Ea::Addr(b.zext::<W32, W64>(ea32)), 1, cnt))
}

/// 索引値にスケール（bits[10:9]）を掛ける。68000/68010 では
/// 常に ×1（これらのビットは使われない）。full/brief どちらの
/// 形式でも 68020+ では有効。
fn scale_index<B: Backend>(b: &mut B, e1: B::V<W16>, index: B::V<W32>) -> B::V<W32> {
    if !b.param::<super::EaFullParam>() {
        return index;
    }
    let nine = k16(b, 9);
    let shr = b.shr_l(e1, nine);
    let m3 = k16(b, 3);
    let sh16 = b.and(shr, m3);
    let sh = b.zext::<W16, W32>(sh16);
    b.shl(index, sh)
}

/// e1 の bit n が立つかの条件値。
fn bit<B: Backend>(b: &mut B, e1: B::V<W16>, n: u16) -> B::B {
    let mask = k16(b, 1 << n);
    let m = b.and(e1, mask);
    let z = k16(b, 0);
    b.cmp(Cmp::Ne, m, z)
}

/// full 形式拡張語の評価。BS/IS・BD（16/32 ビット）・索引
/// （W/L・スケール）・メモリインダイレクト（pre/postindexed・OD）
/// を ext+2 以降の語と組み合わせて 32 ビットの実効アドレスと
/// 消費語数（ext1 を含む）を返す。
/// I/IS フィールド: 000=インダイレクトなし。非 0 はメモリ
/// インダイレクトで、bits[1:0]=OD サイズ（0/1=なし、2=語、3=long）、
/// bit2=postindexed（0=preindexed）。索引抑制は IS（bit6）。
// Ref: SPEC-M68K-UM (MC68020) §Full Format Extension Word.
/// (実効アドレス/ベース, 動的語数) の戻り型。
type IdxRes<B> = Result<(<B as Backend>::V<W32>, <B as Backend>::V<W32>), <B as Backend>::Exit>;

fn full_index<B: Backend>(b: &mut B, e1: B::V<W16>, ext: B::V<W64>, base: B::V<W32>) -> IdxRes<B> {
    let zero = k32(b, 0);
    let one = k32(b, 1);
    // 索引値（full 形式ではスケールは常に有効）。IS で抑制。
    let (index_raw, _d8) = brief_index(b, e1);
    let nine = k16(b, 9);
    let shr = b.shr_l(e1, nine);
    let m3 = k16(b, 3);
    let sh16 = b.and(shr, m3);
    let sh = b.zext::<W16, W32>(sh16);
    let index_raw = b.shl(index_raw, sh);
    let is_is = bit(b, e1, 6);
    let index = b.select(is_is, zero, index_raw);
    // 基底抑制（BS）。
    let is_bs = bit(b, e1, 7);
    let base_v = b.select(is_bs, zero, base);
    // BD: bits[5:4]=10→語、11→long。長さも同時に覚える。
    let four = k16(b, 4);
    let shr4 = b.shr_l(e1, four);
    let m3b = k16(b, 3);
    let bd_sz = b.and(shr4, m3b);
    let two16 = k16(b, 2);
    let three16 = k16(b, 3);
    let mut bd = zero;
    let mut bdw = zero;
    let is_bw = b.cmp(Cmp::Eq, bd_sz, two16);
    b.if_then_else(
        is_bw,
        |bb| {
            let ew = extw_v(bb, ext, 2)?;
            bd = bb.sext::<W16, W32>(ew);
            bdw = k32(bb, 1);
            Ok(())
        },
        |_| Ok(()),
    )?;
    let is_bl = b.cmp(Cmp::Eq, bd_sz, three16);
    b.if_then_else(
        is_bl,
        |bb| {
            bd = extw32_v(bb, ext, 2)?;
            bdw = k32(bb, 2);
            Ok(())
        },
        |_| Ok(()),
    )?;
    // I/IS（bits[2:0]）: 0=インダイレクトなし。非 0 は
    // メモリインダイレクトで、bits[1:0] が OD サイズ
    // （0/1=なし、2=語、3=long）、bit2 が postindexed
    // （索引を間接読み出しの後に足す）。
    let m7 = k16(b, 7);
    let iis = b.and(e1, m7);
    let z16 = k16(b, 0);
    let memind = b.cmp(Cmp::Ne, iis, z16);
    let post = bit(b, e1, 2);
    // OD: BD の後の語から読む（アドレスは bdw に依存）。
    // bits[1:0]=2 なら 1 語（符号拡張）、3 なら 2 語。
    let m3c = k16(b, 3);
    let odsz16 = b.and(e1, m3c);
    let odsz = b.zext::<W16, W32>(odsz16);
    let mut od = zero;
    let mut odw = zero;
    // ext+2+bdw*2 の語を読むヘルパー相当を if_then_else 内で展開。
    let od_at_least_w = {
        let two = k32(b, 2);
        b.cmp(Cmp::GeU, odsz, two)
    };
    b.if_then_else(
        od_at_least_w,
        |bb| {
            let shift = k32(bb, 1);
            let offw = bb.shl(bdw, shift);
            let off64 = bb.zext::<W32, W64>(offw);
            let two64 = k64(bb, 2);
            let kb = bb.add(ext, two64);
            let a64 = bb.add(kb, off64);
            let w0 = bb.load::<W16>(a64, FETCH)?;
            let sgn = bb.sext::<W16, W32>(w0);
            // 既定は語 OD（符号拡張・1 語）。long なら 2 語読み直す。
            od = sgn;
            odw = k32(bb, 1);
            let is_long = {
                let three = k32(bb, 3);
                bb.cmp(Cmp::Eq, odsz, three)
            };
            bb.if_then_else(
                is_long,
                |bbb| {
                    let two64b = k64(bbb, 2);
                    let a64b = bbb.add(a64, two64b);
                    let w1 = bbb.load::<W16>(a64b, FETCH)?;
                    let hi = bbb.zext::<W16, W32>(w0);
                    let s16 = k32(bbb, 16);
                    let hi_sh = bbb.shl(hi, s16);
                    let lo32 = bbb.zext::<W16, W32>(w1);
                    od = bbb.or(hi_sh, lo32);
                    odw = k32(bbb, 2);
                    Ok(())
                },
                |_| Ok(()),
            )
        },
        |_| Ok(()),
    )?;
    // inner = base + bd。索引は IS で抑制済みの `index`。
    // preindexed（bit2=0）は索引を間接読み出しの前に足し、
    // postindexed（bit2=1）は後に足す。iis==0 はインダイレクト
    // なしで索引を直接加算（post と同じ構えで扱える）。
    let bbd = b.add(base_v, bd);
    let idx_pre = b.select(post, zero, index);
    let inner_addr = b.add(bbd, idx_pre);
    // memind: 中間アドレスから 32 ビットをデータ読み。
    let mut memed = inner_addr;
    b.if_then_else(
        memind,
        |bb| {
            let a64 = bb.zext::<W32, W64>(inner_addr);
            let acc = sem::drd(bb);
            memed = bb.load::<W32>(a64, acc)?;
            Ok(())
        },
        |_| Ok(()),
    )?;
    let with_od = b.add(memed, od);
    let idx_post = b.select(post, index, zero);
    let addr = b.add(with_od, idx_post);
    let ob = b.add(one, bdw);
    let words = b.add(ob, odw);
    Ok((addr, words))
}

/// 簡易拡張語から索引の値と8ビット変位を取り出す。
/// bit15=D/A、14-12=番号、11=W/L、7-0=8ビット変位。
/// bits 10-8 は 68000 では使われず無視する（68020+ のスケール・
/// full 形式の判別はここでは扱わない）。
fn brief_index<B: Backend>(b: &mut B, w: B::V<W16>) -> (B::V<W32>, B::V<W8>) {
    let hi_bit = k16(b, 0x8000);
    let masked = b.and(w, hi_bit);
    let zero = k16(b, 0);
    let is_a = b.cmp(Cmp::Ne, masked, zero);
    let n12 = k16(b, 12);
    let shifted = b.shr_l(w, n12);
    let m7 = k16(b, 7);
    let num16 = b.and(shifted, m7);
    let num = b.zext::<W16, W32>(num16);
    let n11 = k16(b, 11);
    let l_sh = b.shr_l(w, n11);
    let one = k16(b, 1);
    let l_bit = b.and(l_sh, one);
    let is_l = b.cmp(Cmp::Ne, l_bit, zero);
    // 索引の値。D はデータレジスタ、A はアドレスレジスタ（A7 は SP）。
    let dv = b.get_indexed(d_array(), num);
    let av = areg_dyn(b, num);
    let idx_val = b.select(is_a, av, dv);
    // W/L: W なら下位16ビットを符号拡張、L ならそのまま。
    let w_part = b.trunc::<W32, W16>(idx_val);
    let sign_ext = b.sext::<W16, W32>(w_part);
    let index = b.select(is_l, idx_val, sign_ext);
    let disp = b.trunc::<W16, W8>(w);
    (index, disp)
}

/// データレジスタ配列を指す。
pub(crate) fn d_array() -> StateArray<W32> {
    StateArray::<W32>::from_layout(core::mem::offset_of!(super::CpuState, d), 4)
}

/// アドレスレジスタを実行時の番号で読む（7 なら SR.S で USP/SSP）。
/// 番号が実行時に決まるので配列参照と条件選択で組み立てる。
fn areg_dyn<B: Backend>(b: &mut B, num: B::V<W32>) -> B::V<W32> {
    let seven = k32(b, 7);
    let is7 = b.cmp(Cmp::Eq, num, seven);
    let a = StateArray::<W32>::from_layout(core::mem::offset_of!(super::CpuState, a), 4);
    // num=7 のときは索引を a[0] に丸めて a の範囲内だけを読み、
    // 結果は下の select で SP に差し替える。
    let z0 = k32(b, 0);
    let idx = b.select(is7, z0, num);
    let low = b.get_indexed(a, idx);
    let s = b.get(sem::sr_ref());
    let mask = k32(b, 1 << sem::sr_bit::S);
    let masked_s = b.and(s, mask);
    let z32 = k32(b, 0);
    let sup = b.cmp(Cmp::Ne, masked_s, z32);
    let ssp = b.get(Ssp.state());
    let usp = b.get(Usp.state());
    let sp = b.select(sup, ssp, usp);
    b.select(is7, sp, low)
}

/// 未定義の EA 組み合わせを illegal instruction（ベクタ 4）にする。
fn illegal<B: Backend>(b: &mut B) -> B::Exit {
    b.raise(GuestException {
        kind: ExceptionKind::Trap,
        code: 4,
        addr: None,
        in_delay_slot: false,
    })
}
