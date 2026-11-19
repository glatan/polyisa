//! MC68000 の命令実行時間（バスサイクル）モデル。
//!
//! 値は命令の基本時間・EA 算出時間・バスアクセス時間の和として計算する。
//! 拡張語のフェッチは EA 時間に含まれる。オペランド転送や内部計算と
//! フェッチの重なりは命令ごとの基本時間に畳み込まれる。
//!
//! 時間は命令によって値依存（シフト回数・乗算の被乗数・条件分岐）で、
//! [`Rt`] で実行時情報を受け取る。情報がない場合は SST の代表値で
//! 較正した既定値を使う（`SPEC-M68K-PRM` §8 および `TEST-SINGLESTEP-68000`
//! で照合）。`None` は現在のカバー範囲外（68020+ 命令・値依存の除算
//! など）を表し、呼び出し側のフォールバックで扱う。

use crate::Insn;
use crate::ea::{dest_mode, dest_reg, ea_mode, ea_reg};

/// DBcc の実行時の分岐経路。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dbcc {
    /// 条件成立 → 分岐せず次命令へ。
    CondTrue,
    /// 条件不成立・カウンタ残あり → 分岐。
    Branch,
    /// 条件不成立・カウンタ 0 → 次命令へ。
    Expired,
}

/// 値によって実行時間が変わる命令へ渡す実行時情報。
///
/// 各フィールドは該当命令でのみ使われる。
#[derive(Debug, Clone, Copy, Default)]
pub struct Rt {
    /// 条件の成立（Bcc・Scc・TRAPV・CHK の成否）。
    pub cond: Option<bool>,
    /// DBcc の分岐経路。
    pub dbcc: Option<Dbcc>,
    /// シフト・ローテートの回数（レジスタ指定時は Dn mod 64 適用後）。
    pub count: Option<u64>,
    /// MUL 系のソースオペランド（<ea> の下位 16 ビット）。
    pub mul_src: Option<u16>,
    /// 動的（レジスタ指定）ビット命令のビット番号 mod 32。
    /// 16 以上で +2 サイクル。即値指定は `ext` から読む。
    pub bit: Option<u32>,
}

/// EA の算出＋アクセス時間（`.b`/`.w` 列）。
fn ea_bw(mode: u8, reg: u8) -> Option<u64> {
    Some(match mode {
        0 | 1 => 0,
        2 => 4,
        3 => 4,
        4 => 6,
        5 => 8,
        6 => 10,
        7 => match reg {
            0 => 8,
            1 => 12,
            2 => 8,
            3 => 10,
            4 => 4,
            _ => return None,
        },
        _ => return None,
    })
}

/// EA の算出＋アクセス時間（`.l` 列）。
///
/// メモリモードは `.w` 列 +4（2 語分のバスアクセス）。加減算・
/// 論理演算系は `.l` でも同じ列を使い、代わりに基本時間の `**`
/// 脚注（reg-direct/即値で +2）で調整する。
fn ea_l(mode: u8, reg: u8) -> Option<u64> {
    if mode <= 1 {
        return ea_bw(mode, reg);
    }
    Some(ea_bw(mode, reg)? + 4)
}

/// MOVEM 用のアドレス計算時間。オペランド転送（4n/8n）は別計上なので
/// 拡張語フェッチ＋アドレス計算だけを表す。
fn ea_calc(mode: u8, reg: u8) -> Option<u64> {
    Some(match mode {
        2..=4 => 0,
        5 => 4,
        6 => 6,
        7 => match reg {
            0 => 4,
            1 => 8,
            2 => 4,
            3 => 6,
            _ => return None,
        },
        _ => return None,
    })
}

/// JMP の宛先 EA 時間。
fn jmp_ea(mode: u8, reg: u8) -> Option<u64> {
    Some(match mode {
        2 => 8,
        5 => 10,
        6 => 14,
        7 => match reg {
            0 | 2 => 10,
            1 => 12,
            3 => 14,
            _ => return None,
        },
        _ => return None,
    })
}

/// JSR の宛先 EA 時間。
fn jsr_ea(mode: u8, reg: u8) -> Option<u64> {
    Some(match mode {
        2 => 16,
        5 => 18,
        6 => 22,
        7 => match reg {
            0 | 2 => 18,
            1 => 20,
            3 => 22,
            _ => return None,
        },
        _ => return None,
    })
}

/// LEA の宛先 EA 時間。
fn lea_ea(mode: u8, reg: u8) -> Option<u64> {
    Some(match mode {
        2 => 4,
        5 => 8,
        6 => 12,
        7 => match reg {
            0 | 2 => 8,
            1 | 3 => 12,
            _ => return None,
        },
        _ => return None,
    })
}

/// PEA の宛先 EA 時間。
fn pea_ea(mode: u8, reg: u8) -> Option<u64> {
    Some(match mode {
        2 => 12,
        5 => 16,
        6 => 20,
        7 => match reg {
            0 => 16,
            1 => 20,
            2 => 16,
            3 => 20,
            _ => return None,
        },
        _ => return None,
    })
}

/// 宛先 EA の書き込み時間。
fn wr_ea(mode: u8, reg: u8, size: u32) -> Option<u64> {
    if size == 4 {
        ea_l(mode, reg)
    } else {
        ea_bw(mode, reg)
    }
}

/// MOVE 宛先の書き込み時間。`-(An)` は書き戻しが次のプリフェッチと
/// 重なり、通常の書き込み列より 2 小さい（`.b`/`.w`=4、`.l`=8）。
fn mv_wr_ea(mode: u8, reg: u8, size: u32) -> Option<u64> {
    if mode == 4 {
        Some(if size == 4 { 8 } else { 4 })
    } else {
        wr_ea(mode, reg, size)
    }
}

/// 転送系・参照系のソース EA 読み出し時間。`.l` は 2 語分のバスアクセス。
fn rd_ea(mode: u8, reg: u8, size: u32) -> Option<u64> {
    if size == 4 {
        ea_l(mode, reg)
    } else {
        ea_bw(mode, reg)
    }
}

/// ADD/SUB/AND/OR・ADDA/SUBA の <ea>→Dn/An の時間。
///
/// `.b`/`.w` は 4+EA。`.l` は基本時間 6+EA で、EA が reg-direct
/// または即値のとき `**` 脚注により基本時間が 8 になる。
/// CMP/CMPA は `**` 脚注がないので対象外。
fn alu_dst_dn(mode: u8, reg: u8, size: u32) -> Option<u64> {
    if size == 4 {
        let base = if mode <= 1 || (mode == 7 && reg == 4) {
            8
        } else {
            6
        };
        Some(base + rd_ea(mode, reg, size)?)
    } else {
        Some(4 + ea_bw(mode, reg)?)
    }
}

/// MULS の n: 被乗数に LSB として 0 を連結した 17 ビット値の
/// 隣接ビット遷移（01/10 パターン）数。
fn muls_n(src: u16) -> u64 {
    u64::from(((u32::from(src) << 1 ^ u32::from(src)) & 0xffff).count_ones())
}

/// 命令の実行時間（サイクル）。`Insn`・第 1 語 `w`・第 1 拡張語 `ext`
/// ・実行時情報 `rt` から計算する。
///
/// `ext` は第 1 拡張語で、MOVEM のレジスタマスクと即値ビット命令の
/// ビット番号に使われる。`rt` が `Default` の場合は DBcc 終了・
/// 条件不成立・回数 8 などの代表的な値を仮定する。カバー範囲外
/// （68020+ 命令・DIVU/DIVS）は `None` を返す。
#[must_use]
pub fn insn_cycles(insn: Insn, w: u64, ext: u16, rt: &Rt) -> Option<u64> {
    let em = ea_mode(w);
    let er = ea_reg(w);
    let dm = dest_mode(w);
    let dr = dest_reg(w);
    let osz = 1u64 << ((w >> 6) & 3);
    Some(match insn {
        Insn::MoveB | Insn::MoveW | Insn::MoveL => {
            let size = match insn {
                Insn::MoveB => 1,
                Insn::MoveW => 2,
                _ => 4,
            };
            // MOVE の宛先 EA は mode=bits[8:6]、reg=bits[11:9]。
            4 + rd_ea(em, er, size)? + mv_wr_ea(dm, dr, size)?
        }
        Insn::MoveaW => 4 + rd_ea(em, er, 2)?,
        Insn::MoveaL => 4 + rd_ea(em, er, 4)?,
        Insn::Moveq => 4,
        Insn::Add | Insn::Sub | Insn::And | Insn::Or => {
            if dm <= 3 {
                // opm<=2 は <ea>→Dn、opm==3 は ADDA.w/SUBA.w。
                let size = 1u32 << dm;
                if dm == 3 {
                    8 + rd_ea(em, er, 2)?
                } else {
                    alu_dst_dn(em, er, size)?
                }
            } else {
                let size = 1u32 << (dm - 4);
                (if size == 4 { 12 } else { 8 }) + wr_ea(em, er, size)?
            }
        }
        Insn::AddDn
        | Insn::SubDn
        | Insn::AndBDn
        | Insn::AndWDn
        | Insn::AndLDn
        | Insn::OrBDn
        | Insn::OrWDn
        | Insn::OrLDn
        | Insn::Eor => {
            let size = 1u32 << (dm - 4);
            (if size == 4 { 12 } else { 8 }) + wr_ea(em, er, size)?
        }
        Insn::AddaL | Insn::SubaL => alu_dst_dn(em, er, 4)?,
        Insn::Cmp => {
            if dm == 3 {
                // CMPA.w
                6 + rd_ea(em, er, 2)?
            } else {
                let size = 1u32 << dm;
                // CMP/CMPA には `**` 脚注がなく .l は全モード base 6。
                (if size == 4 { 6 } else { 4 }) + rd_ea(em, er, size)?
            }
        }
        Insn::CmpaL => 6 + rd_ea(em, er, 4)?,
        Insn::Cmpm => match osz {
            4 => 20,
            _ => 12,
        },
        Insn::Addi | Insn::Subi | Insn::Cmpi => {
            if em == 0 {
                if matches!(insn, Insn::Cmpi) {
                    if osz == 4 { 14 } else { 8 }
                } else if osz == 4 {
                    16
                } else {
                    8
                }
            } else if em == 1 || (em == 7 && er == 4) {
                // An 直・即値の宛先は未定義エンコード。
                return None;
            } else {
                // CMPI は書き戻しがないので読み出し側の時間を使う。
                let (base, ea) = if matches!(insn, Insn::Cmpi) {
                    (if osz == 4 { 12 } else { 8 }, rd_ea(em, er, osz as u32)?)
                } else {
                    (if osz == 4 { 20 } else { 12 }, wr_ea(em, er, osz as u32)?)
                };
                base + ea
            }
        }
        Insn::Andi | Insn::Ori | Insn::Eori => {
            if em == 7 && er == 4 {
                // ANDI/ORI/EORI to CCR/SR。
                20
            } else if em == 0 {
                if osz == 4 { 16 } else { 8 }
            } else if em == 1 {
                return None;
            } else {
                (if osz == 4 { 20 } else { 12 }) + wr_ea(em, er, osz as u32)?
            }
        }
        Insn::Addq | Insn::Subq => {
            if em == 0 {
                if osz == 4 { 8 } else { 4 }
            } else if em == 1 {
                8
            } else {
                (if osz == 4 { 12 } else { 8 }) + wr_ea(em, er, osz as u32)?
            }
        }
        Insn::AddxD | Insn::SubxD => {
            if osz == 4 {
                8
            } else {
                4
            }
        }
        Insn::AddxM | Insn::SubxM => {
            if osz == 4 {
                30
            } else {
                18
            }
        }
        Insn::AbcdR | Insn::SbcdR => 6,
        Insn::AbcdM | Insn::SbcdM => 18,
        Insn::Neg | Insn::Negx | Insn::Not | Insn::Clr => {
            if em <= 1 {
                if osz == 4 { 6 } else { 4 }
            } else {
                (if osz == 4 { 12 } else { 8 }) + wr_ea(em, er, osz as u32)?
            }
        }
        Insn::Nbcd => {
            if em == 0 {
                6
            } else {
                8 + wr_ea(em, er, 1)?
            }
        }
        Insn::Tst => {
            if em <= 1 {
                4
            } else {
                4 + rd_ea(em, er, osz as u32)?
            }
        }
        Insn::Mulu => {
            let n = rt.mul_src.map(|s| u64::from(s.count_ones())).unwrap_or(8);
            38 + 2 * n + ea_bw(em, er)?
        }
        Insn::Muls => {
            let n = rt.mul_src.map(muls_n).unwrap_or(8);
            38 + 2 * n + ea_bw(em, er)?
        }
        Insn::Divu | Insn::Divs => {
            // 除数・被除数に依存（SST 実測で ~76-150）。較正は F2 の対象。
            return None;
        }
        Insn::Asl
        | Insn::Asr
        | Insn::Lsl
        | Insn::Lsr
        | Insn::Rol
        | Insn::Ror
        | Insn::Roxl
        | Insn::Roxr => {
            let n = if w & 0x20 != 0 {
                // レジスタ指定: Dn mod 64（呼び出し側が供給）。
                rt.count.unwrap_or(8)
            } else {
                // 即値指定: bits[11:9]（0 は 8 回）。
                let c = (w >> 9) & 7;
                if c == 0 { 8 } else { c }
            };
            (if osz == 4 { 8 } else { 6 }) + 2 * n
        }
        Insn::AslM
        | Insn::AsrM
        | Insn::LslM
        | Insn::LsrM
        | Insn::RolM
        | Insn::RorM
        | Insn::RoxlM
        | Insn::RoxrM => 8 + ea_bw(em, er)?,
        Insn::Btst => {
            if em == 0 {
                6
            } else {
                4 + rd_ea(em, er, 1)?
            }
        }
        Insn::Bchg | Insn::Bset => {
            if em == 0 {
                // ビット番号 mod 32 が 16 以上で +2。
                if rt.bit.unwrap_or(0) >= 16 { 8 } else { 6 }
            } else {
                8 + wr_ea(em, er, 1)?
            }
        }
        Insn::Bclr => {
            if em == 0 {
                if rt.bit.unwrap_or(0) >= 16 { 10 } else { 8 }
            } else {
                8 + wr_ea(em, er, 1)?
            }
        }
        Insn::BtstI => {
            if em == 0 {
                10
            } else {
                8 + rd_ea(em, er, 1)?
            }
        }
        Insn::BchgI | Insn::BsetI => {
            if em == 0 {
                if ext >= 16 { 12 } else { 10 }
            } else {
                12 + wr_ea(em, er, 1)?
            }
        }
        Insn::BclrI => {
            if em == 0 {
                if ext >= 16 { 14 } else { 12 }
            } else {
                12 + wr_ea(em, er, 1)?
            }
        }
        Insn::Bcc => {
            if rt.cond.unwrap_or(false) {
                10
            } else {
                // disp8=8 / disp16=12。
                if (w & 0xff) == 0 { 12 } else { 8 }
            }
        }
        Insn::Bra => 10,
        Insn::Bsr => 18,
        Insn::Dbcc => match rt.dbcc.unwrap_or(Dbcc::Expired) {
            Dbcc::CondTrue => 12,
            Dbcc::Branch => 10,
            Dbcc::Expired => 14,
        },
        Insn::Scc => {
            if em == 0 {
                if rt.cond.unwrap_or(false) { 6 } else { 4 }
            } else {
                8 + ea_bw(em, er)?
            }
        }
        Insn::Jmp => jmp_ea(em, er)?,
        Insn::Jsr => jsr_ea(em, er)?,
        Insn::Lea => lea_ea(em, er)?,
        Insn::Pea => pea_ea(em, er)?,
        Insn::Link => 16,
        Insn::Unlk => 12,
        Insn::Rts => 16,
        Insn::Rtr => 20,
        Insn::Rte => 20,
        Insn::Nop => 4,
        Insn::Reset => 132,
        Insn::Stop => 4,
        Insn::Swap => 4,
        Insn::ExtW | Insn::ExtL => 4,
        Insn::ExgDd | Insn::ExgAa | Insn::ExgDa => 6,
        Insn::Trap => 38,
        Insn::Trapv => {
            if rt.cond.unwrap_or(false) {
                34
            } else {
                4
            }
        }
        Insn::Illegal | Insn::Linea | Insn::Linef => 34,
        Insn::Chk => {
            // cond=Some(false) は範囲外（トラップ経路）。
            let base = if rt.cond.unwrap_or(true) { 10 } else { 44 };
            base + rd_ea(em, er, 2)?
        }
        Insn::Mv2ccr | Insn::Mv2sr => 12 + rd_ea(em, er, 2)?,
        Insn::Mvfrsr => {
            if em == 0 {
                6
            } else {
                8 + wr_ea(em, er, 2)?
            }
        }
        Insn::Mv2usp | Insn::Mvfrusp => 4,
        Insn::MovrmW | Insn::MovrmL | Insn::MrmemW | Insn::MrmemL => {
            let n = u64::from(ext.count_ones());
            let (base, per) = match insn {
                Insn::MovrmW | Insn::MovrmL => (8, n),
                _ => (12, n),
            };
            base + per
                * if matches!(insn, Insn::MovrmL | Insn::MrmemL) {
                    8
                } else {
                    4
                }
                + ea_calc(em, er)?
        }
        Insn::MovepWm | Insn::MovepWr => 16,
        Insn::MovepLm | Insn::MovepLr => 24,
        // 68020+（CAS・BF・MULL・DIVL・EXTB.L）はカバー範囲外。
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt() -> Rt {
        Rt::default()
    }

    // MOVE: SST 実測値で検証。
    #[test]
    fn move_() {
        // MOVE.l A6,D3 = 4
        assert_eq!(insn_cycles(Insn::MoveL, 0x260e, 0, &rt()), Some(4));
        // MOVE.l (d8,A0,Xn),(d16,A2) = 4 + 14 + 12 = 30
        assert_eq!(insn_cycles(Insn::MoveL, 0x2570, 0, &rt()), Some(30));
        // MOVE.l (A7),D3 = 4 + 8 = 12
        assert_eq!(insn_cycles(Insn::MoveL, 0x2617, 0, &rt()), Some(12));
        // MOVE.l D7,(A7) = 4 + 8 = 12
        assert_eq!(insn_cycles(Insn::MoveL, 0x2e87, 0, &rt()), Some(12));
        // MOVE.l (xxx).w,-(A6) = 4 + 12 + 8 = 24（宛先 -(An) は -2）
        assert_eq!(insn_cycles(Insn::MoveL, 0x2d38, 0, &rt()), Some(24));
        // MOVE.l D4,-(A0) = 4 + 8 = 12
        assert_eq!(insn_cycles(Insn::MoveL, 0x2104, 0, &rt()), Some(12));
        // MOVE.l -(A7),-(A1) = 4 + 10 + 8 = 22
        assert_eq!(insn_cycles(Insn::MoveL, 0x2327, 0, &rt()), Some(22));
        // MOVE.w (A0)+,D7 = 4 + 4 = 8
        assert_eq!(insn_cycles(Insn::MoveW, 0x3e18, 0, &rt()), Some(8));
        // MOVE.w #,-(A6) = 4 + 4 + 4 = 12
        assert_eq!(insn_cycles(Insn::MoveW, 0x3d3c, 0, &rt()), Some(12));
        // MOVE.w -(A0),-(A0) = 4 + 6 + 4 = 14
        assert_eq!(insn_cycles(Insn::MoveW, 0x3120, 0, &rt()), Some(14));
        // MOVE.w #,(d16,A0) = 4 + 4 + 8 = 16
        assert_eq!(insn_cycles(Insn::MoveW, 0x317c, 0, &rt()), Some(16));
    }

    #[test]
    fn arith() {
        // ADD.l D6,D4 = 8
        assert_eq!(insn_cycles(Insn::Add, 0xd886, 0, &rt()), Some(8));
        // ADD.l (A2)+,D6 = 8 + 6 = 14
        assert_eq!(insn_cycles(Insn::Add, 0xdc9a, 0, &rt()), Some(14));
        // ADD.l -(A3),D7 = 8 + 8 = 16
        assert_eq!(insn_cycles(Insn::Add, 0xdea3, 0, &rt()), Some(16));
        // ADD.l D0,(d8,A0,Xn) = 12 + 14 = 26
        assert_eq!(insn_cycles(Insn::AddDn, 0xd1b0, 0, &rt()), Some(26));
        // ADD.w (d16,A4),D0 = 4 + 8 = 12
        assert_eq!(insn_cycles(Insn::Add, 0xd06c, 0, &rt()), Some(12));
        // AND.l -(A1),D3 = 8 + 8 = 16
        assert_eq!(insn_cycles(Insn::And, 0xc6a1, 0, &rt()), Some(16));
        // AND.l D3,(A7) = 12 + 8 = 20
        assert_eq!(insn_cycles(Insn::AndLDn, 0xc797, 0, &rt()), Some(20));
        // CMP.l (A6)+,D1 = 8 + 6 = 14
        assert_eq!(insn_cycles(Insn::Cmp, 0xb29e, 0, &rt()), Some(14));
        // CMP.l (d8,A5,Xn),D7 = 8 + 12 = 20
        assert_eq!(insn_cycles(Insn::Cmp, 0xbeb5, 0, &rt()), Some(20));
        // CMPM.l = 20
        assert_eq!(insn_cycles(Insn::Cmpm, 0xbd89, 0, &rt()), Some(20));
        // SUB.l D4,-(A6) = 12 + 10 = 22
        assert_eq!(insn_cycles(Insn::SubDn, 0x99a6, 0, &rt()), Some(22));
        // SUBQ.l #5,(A6)+ = 12 + 8 = 20
        assert_eq!(insn_cycles(Insn::Subq, 0x5b9e, 0, &rt()), Some(20));
    }

    #[test]
    fn movem() {
        // MOVEM.w (d8,A2,Xn),# n=9 → 12+36+6 = 54
        assert_eq!(insn_cycles(Insn::MrmemW, 0x4cb2, 0x9aad, &rt()), Some(54));
        // MOVEM.w (d16,A0),# n=7 → 12+28+4 = 44
        assert_eq!(insn_cycles(Insn::MrmemW, 0x4ca8, 0xe6a0, &rt()), Some(44));
        // MOVEM.w (A3)+,# n=9 → 12+36+0 = 48
        assert_eq!(insn_cycles(Insn::MrmemW, 0x4c9b, 0x1b9d, &rt()), Some(48));
        // MOVEM.w (xxx).l,# n=7 → 12+28+8 = 48
        assert_eq!(insn_cycles(Insn::MrmemW, 0x4cb9, 0x813b, &rt()), Some(48));
        // MOVEM.w #,(A7) n=10 → 8+40+0 = 48
        assert_eq!(insn_cycles(Insn::MovrmW, 0x4897, 0xded2, &rt()), Some(48));
        // MOVEM.w #,(d8,A2,Xn) n=8 → 8+32+6 = 46
        assert_eq!(insn_cycles(Insn::MovrmW, 0x48b2, 0xccb2, &rt()), Some(46));
        // MOVEM.w #,-(A1) n=9 → 8+36+0 = 44
        assert_eq!(insn_cycles(Insn::MovrmW, 0x48a1, 0x4acf, &rt()), Some(44));
        // MOVEM.w #,(d16,A3) n=7 → 8+28+4 = 40
        assert_eq!(insn_cycles(Insn::MovrmW, 0x48ab, 0x3a4c, &rt()), Some(40));
        // MOVEM.l #,-(A2) n=8 → 8+64+0 = 72
        assert_eq!(insn_cycles(Insn::MovrmL, 0x48e2, 0x93c6, &rt()), Some(72));
        // MOVEM.l #,(xxx).l n=9 → 8+72+8 = 88
        assert_eq!(insn_cycles(Insn::MovrmL, 0x48f9, 0x83f3, &rt()), Some(88));
        // MOVEM.l #,(d16,A1) n=5 → 8+40+4 = 52
        assert_eq!(insn_cycles(Insn::MovrmL, 0x48e9, 0x2107, &rt()), Some(52));
        // MOVEM.l #,(A7) n=4 → 8+32+0 = 40
        assert_eq!(insn_cycles(Insn::MovrmL, 0x48d7, 0x1111, &rt()), Some(40));
        // MOVEM.l (d8,A4,Xn),# n=8 → 12+64+6 = 82
        assert_eq!(insn_cycles(Insn::MrmemL, 0x4cf4, 0xaea1, &rt()), Some(82));
    }

    #[test]
    fn control() {
        // JSR idx=22, (An)=16, absL=20
        assert_eq!(insn_cycles(Insn::Jsr, 0x4eb1, 0, &rt()), Some(22));
        assert_eq!(insn_cycles(Insn::Jsr, 0x4e96, 0, &rt()), Some(16));
        assert_eq!(insn_cycles(Insn::Jsr, 0x4eb9, 0, &rt()), Some(20));
        // JMP (An)=8, d16=10, idx=14
        assert_eq!(insn_cycles(Insn::Jmp, 0x4ed2, 0, &rt()), Some(8));
        assert_eq!(insn_cycles(Insn::Jmp, 0x4eed, 0, &rt()), Some(10));
        assert_eq!(insn_cycles(Insn::Jmp, 0x4ef7, 0, &rt()), Some(14));
        // LEA idx=12, d16=8, (An)=4
        assert_eq!(insn_cycles(Insn::Lea, 0x41f2, 0, &rt()), Some(12));
        assert_eq!(insn_cycles(Insn::Lea, 0x43ee, 0, &rt()), Some(8));
        assert_eq!(insn_cycles(Insn::Lea, 0x4dd0, 0, &rt()), Some(4));
        // PEA idx=20, absW=16, d16=16
        assert_eq!(insn_cycles(Insn::Pea, 0x4875, 0, &rt()), Some(20));
        assert_eq!(insn_cycles(Insn::Pea, 0x4878, 0, &rt()), Some(16));
        assert_eq!(insn_cycles(Insn::Pea, 0x486e, 0, &rt()), Some(16));
        // RTS=16, LINK=16, UNLK=12, BSR=18
        assert_eq!(insn_cycles(Insn::Rts, 0x4e75, 0, &rt()), Some(16));
        assert_eq!(insn_cycles(Insn::Link, 0x4e51, 0, &rt()), Some(16));
        assert_eq!(insn_cycles(Insn::Unlk, 0x4e58, 0, &rt()), Some(12));
        assert_eq!(insn_cycles(Insn::Bsr, 0x61ec, 0, &rt()), Some(18));
        // Bcc taken=10
        let taken = Rt {
            cond: Some(true),
            ..Rt::default()
        };
        assert_eq!(insn_cycles(Insn::Bcc, 0x6db0, 0, &taken), Some(10));
    }

    #[test]
    fn misc() {
        // TST.l D7=4, (A3)+=12
        assert_eq!(insn_cycles(Insn::Tst, 0x4a87, 0, &rt()), Some(4));
        assert_eq!(insn_cycles(Insn::Tst, 0x4a9b, 0, &rt()), Some(12));
        // CLR.l D2=6, (A5)+=20
        assert_eq!(insn_cycles(Insn::Clr, 0x4282, 0, &rt()), Some(6));
        assert_eq!(insn_cycles(Insn::Clr, 0x429d, 0, &rt()), Some(20));
        // LSL.l #8,D3 = 8+16 = 24
        assert_eq!(insn_cycles(Insn::Lsl, 0xe18b, 0, &rt()), Some(24));
        // MULU D7,D6: n=ones(0xbc95)=9 → 38+18 = 56
        let rtu = Rt {
            mul_src: Some(0xbc95),
            ..Rt::default()
        };
        assert_eq!(insn_cycles(Insn::Mulu, 0xccc7, 0, &rtu), Some(56));
        // DBcc: expired=14, cond-true=12, branch=10
        assert_eq!(insn_cycles(Insn::Dbcc, 0x59ce, 0, &rt()), Some(14));
        let r = Rt {
            dbcc: Some(Dbcc::Branch),
            ..Rt::default()
        };
        assert_eq!(insn_cycles(Insn::Dbcc, 0x52ca, 0, &r), Some(10));
        let r = Rt {
            dbcc: Some(Dbcc::CondTrue),
            ..Rt::default()
        };
        assert_eq!(insn_cycles(Insn::Dbcc, 0x52ca, 0, &r), Some(12));
    }

    // レビュー対応で確定した SST 実測値。
    #[test]
    fn calibrated() {
        // CMP.l Dn/An は base 6（`**` 脚注なし）。
        assert_eq!(insn_cycles(Insn::Cmp, 0xb684, 0, &rt()), Some(6));
        assert_eq!(insn_cycles(Insn::Cmp, 0xb48a, 0, &rt()), Some(6));
        // CMPA.l (An),An = 6 + 8 = 14
        assert_eq!(insn_cycles(Insn::CmpaL, 0xb1d4, 0, &rt()), Some(14));
        // ADDA.l/SUBA.l (An),An = 6 + 8 = 14（`**` は reg-direct/imm のみ）
        assert_eq!(insn_cycles(Insn::AddaL, 0xd5d3, 0, &rt()), Some(14));
        assert_eq!(insn_cycles(Insn::SubaL, 0x97de, 0, &rt()), Some(14));
        // ADDA.l Dn,An = 8（reg-direct で base+2）
        assert_eq!(insn_cycles(Insn::AddaL, 0xddc7, 0, &rt()), Some(8));
        // ADD.l #imm,D5 = 8 + 8 = 16（imm で base+2）
        assert_eq!(insn_cycles(Insn::Add, 0xdabc, 0, &rt()), Some(16));
        // ADD.l (A1)+,D0 = 6 + 8 = 14（alu_dst_dn: 非脚注 EA は base 6）
        // → 上の arith テストで (A2)+ = 14 を検証済み。
        // NBCD Dn = 6、NBCD (A5) = 8 + 4 = 12
        assert_eq!(insn_cycles(Insn::Nbcd, 0x4800, 0, &rt()), Some(6));
        assert_eq!(insn_cycles(Insn::Nbcd, 0x4815, 0, &rt()), Some(12));
        assert_eq!(insn_cycles(Insn::Nbcd, 0x482b, 0, &rt()), Some(16));
        // PEA (d16,PC) = 16、PEA (d8,PC,Xn) = 20
        assert_eq!(insn_cycles(Insn::Pea, 0x487a, 0, &rt()), Some(16));
        assert_eq!(insn_cycles(Insn::Pea, 0x487b, 0, &rt()), Some(20));
        // 即値シフト: .b/.w も 6 + 2n（LSL.b #6,D0 = 18、ASR.w #4,D5 = 14）
        assert_eq!(insn_cycles(Insn::Lsl, 0xed08, 0, &rt()), Some(18));
        assert_eq!(insn_cycles(Insn::Asr, 0xe845, 0, &rt()), Some(14));
        // ビット命令: BTST dyn Dn = 6、static Dn = 10
        assert_eq!(insn_cycles(Insn::Btst, 0x0b06, 0, &rt()), Some(6));
        assert_eq!(insn_cycles(Insn::BtstI, 0x0806, 4, &rt()), Some(10));
        // dyn は bit>=16 で +2: BCHG 6/8、BSET 6/8、BCLR 8/10
        let lo = Rt {
            bit: Some(3),
            ..Rt::default()
        };
        let hi = Rt {
            bit: Some(20),
            ..Rt::default()
        };
        assert_eq!(insn_cycles(Insn::Bchg, 0x0b40, 0, &lo), Some(6));
        assert_eq!(insn_cycles(Insn::Bchg, 0x0b40, 0, &hi), Some(8));
        assert_eq!(insn_cycles(Insn::Bset, 0x0bc0, 0, &lo), Some(6));
        assert_eq!(insn_cycles(Insn::Bset, 0x0bc0, 0, &hi), Some(8));
        assert_eq!(insn_cycles(Insn::Bclr, 0x0b80, 0, &lo), Some(8));
        assert_eq!(insn_cycles(Insn::Bclr, 0x0b80, 0, &hi), Some(10));
        // static は ext>=16 で +2: BSET #,D1 = 10（ext=1）
        assert_eq!(insn_cycles(Insn::BsetI, 0x08c1, 1, &rt()), Some(10));
        // TRAP = 38、ORI to CCR = 20
        assert_eq!(insn_cycles(Insn::Trap, 0x4e40, 0, &rt()), Some(38));
        assert_eq!(insn_cycles(Insn::Ori, 0x003c, 0, &rt()), Some(20));
        assert_eq!(insn_cycles(Insn::Andi, 0x023c, 0, &rt()), Some(20));
        // ビット命令メモリ: BCLR D3,(A1)+ = 8 + 4 = 12
        assert_eq!(insn_cycles(Insn::Bclr, 0x0799, 0, &rt()), Some(12));
        // CHK (A4)+,D1 = 10 + 4 = 14
        assert_eq!(insn_cycles(Insn::Chk, 0x439c, 0, &rt()), Some(14));
    }
}
