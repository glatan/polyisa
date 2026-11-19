// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! m68k 最小の命令意味論。バックエンドに対して総称的に書く。
//!
//! CPU 状態の参照・EA 評価・命令ごとの意味論を持つ。spec の宣言に
//! 従って命令群を段階的に実装している。
//!
//! 出典は SPEC-M68K-PRM (M68000PM/AD Rev 1) である。
//! Ref: SPEC-M68K-PRM (Rev 1).

use polyisa_mem::{Access, AccessKind, Align, Endian};
use polyisa_sem::{Backend, Cmp, ExceptionKind, Flow, GuestException, StateRef, W8, W16, W32, W64};

use super::CpuState;
use super::ea::{self, Ea};

/// データアクセスの整列要求。`odd_access` が `allow` のモデル
/// （68020 以降）では奇数アドレスの word/long アクセスを許す。
/// 命令フェッチは全世代で偶数のみなので FETCH 側は変えない。
// Ref: SPEC-M68K-UM (MC68020) §Bus Operation.
pub(crate) fn data_align<B: Backend>(b: &mut B) -> Align {
    if b.param::<super::OddAccessParam>() == 1 {
        Align::Unaligned
    } else {
        Align::Natural
    }
}

/// データ読み出しのアクセス属性（BE）。
pub(crate) fn drd<B: Backend>(b: &mut B) -> Access {
    Access {
        endian: Endian::Be,
        align: data_align(b),
        kind: AccessKind::DataRead,
    }
}

/// データ書き込みのアクセス属性（BE）。
pub(crate) fn dwr<B: Backend>(b: &mut B) -> Access {
    Access {
        endian: Endian::Be,
        align: data_align(b),
        kind: AccessKind::DataWrite,
    }
}

/// データレジスタ番号（D0〜D7）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct D(pub u8);

/// アドレスレジスタ番号（A0〜A6）。A7 は `Usp`/`Ssp` で指す。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct A(pub u8);

/// ユーザースタックポインタ（A7、SR.S=0 のとき有効）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Usp;

/// スーパーバイザスタックポインタ（A7、SR.S=1 のとき有効）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ssp;

/// 浮動小数点データレジスタ番号（FP0〜FP7）。96 ビット拡張形式は
/// `CpuState.fp` に 3 語の不透明イメージとして保持する
///（OS の Line-F 補完が往復する領域。算術は未実装）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fp(pub u8);

/// FP 制御レジスタ（FPCR）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fpcr;

/// FP ステータスレジスタ（FPSR）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fpsr;

/// FP 命令アドレスレジスタ（FPIAR）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fpiar;

impl Fp {
    /// 96 ビットイメージの `j` 語目（0〜2）を指す。
    /// `w(0)` は符号/指数と埋め、`w(1..3)` は 64 ビット仮数。
    #[must_use]
    pub const fn w(self, j: u8) -> StateRef<W32> {
        StateRef::<W32>::from_offset(
            core::mem::offset_of!(CpuState, fp) + self.0 as usize * 12 + j as usize * 4,
        )
    }
}

impl Fpcr {
    /// FPCR を指す。
    #[must_use]
    pub const fn state() -> StateRef<W32> {
        StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, fpcr))
    }
}

impl Fpsr {
    /// FPSR を指す。
    #[must_use]
    pub const fn state() -> StateRef<W32> {
        StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, fpsr))
    }
}

impl Fpiar {
    /// FPIAR を指す。
    #[must_use]
    pub const fn state() -> StateRef<W32> {
        StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, fpiar))
    }
}

impl D {
    /// CPU 状態の対応する要素を指す。
    #[must_use]
    pub const fn state(self) -> StateRef<W32> {
        StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, d) + self.0 as usize * 4)
    }
}

impl A {
    /// CPU 状態の対応する要素を指す。
    ///
    /// A7 は `a` 配列にない。`Usp`/`Ssp` を SR.S で選んで使うこと。
    #[must_use]
    pub const fn state(self) -> StateRef<W32> {
        assert!(self.0 < 7, "A7 は Usp/Ssp で指す");
        StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, a) + self.0 as usize * 4)
    }
}

impl Usp {
    /// CPU 状態の対応する要素を指す。
    #[must_use]
    pub const fn state(self) -> StateRef<W32> {
        StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, usp))
    }
}

impl Ssp {
    /// CPU 状態の対応する要素を指す。
    #[must_use]
    pub const fn state(self) -> StateRef<W32> {
        StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, ssp))
    }
}

/// pc を指す。
#[must_use]
pub const fn pc_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, pc))
}

/// SR 全体を指す（システムバイト: T/S/IPL、ユーザーバイト: CCR）。
#[must_use]
pub const fn sr_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, sr))
}

/// CCR（SR のユーザーバイト。X N Z V C）を指す。
#[must_use]
pub const fn ccr_ref() -> StateRef<W8> {
    StateRef::<W8>::from_offset(core::mem::offset_of!(CpuState, sr))
}

/// アドレスレジスタ `n`（0〜7）を読む。n=7 は SR.S で USP/SSP を選ぶ。
pub fn areg<B: Backend>(b: &mut B, n: u8) -> B::V<W32> {
    debug_assert!(n < 8);
    if n == 7 {
        let s = b.get(sr_ref());
        let mask = b.konst::<W32>(1 << sr_bit::S);
        let masked = b.and(s, mask);
        let zero = b.konst::<W32>(0);
        let sup = b.cmp(Cmp::Ne, masked, zero);
        let ssp = b.get(Ssp.state());
        let usp = b.get(Usp.state());
        b.select(sup, ssp, usp)
    } else {
        b.get(A(n).state())
    }
}

/// アドレスレジスタ `n`（0〜7）に書く。n=7 は SR.S で USP/SSP を選ぶ。
/// 保持先が実行時に決まるので `if_then_else` で書き分ける。
pub fn set_areg<B: Backend>(b: &mut B, n: u8, v: B::V<W32>) -> Flow<B> {
    debug_assert!(n < 8);
    if n == 7 {
        let s = b.get(sr_ref());
        let mask = b.konst::<W32>(1 << sr_bit::S);
        let masked = b.and(s, mask);
        let zero = b.konst::<W32>(0);
        let sup = b.cmp(Cmp::Ne, masked, zero);
        b.if_then_else(
            sup,
            |b| {
                b.set(Ssp.state(), v);
                Ok(())
            },
            |b| {
                b.set(Usp.state(), v);
                Ok(())
            },
        )
    } else {
        b.set(A(n).state(), v);
        Ok(())
    }
}

/// SR の各ビット位置。
// Ref: SPEC-M68K-PRM (Rev 1) §Status Register.
pub mod sr_bit {
    /// キャリー（C）。
    pub const C: u32 = 0;
    /// オーバーフロー（V）。
    pub const V: u32 = 1;
    /// ゼロ（Z）。
    pub const Z: u32 = 2;
    /// 負（N）。
    pub const N: u32 = 3;
    /// 拡張（X）。
    pub const X: u32 = 4;
    /// 割り込みマスクの下位ビット（I0）。I0〜I2 が bit 8-10。
    pub const I0: u32 = 8;
    /// スーパーバイザ状態（S）。
    pub const S: u32 = 13;
    /// トレース（T）。
    pub const T: u32 = 15;
}

/// 命令を振り分ける。
///
/// `insn` は生成デコーダの結果、`w` は命令ワード。`pc` は命令の先頭
/// アドレス。発生した例外は `deliver` がベクタへ配送する（trace/割り込みと
/// アドレスエラーの 14 バイトフレームは未接続）。reset の外部通知は
/// バス経路の接続待ち。
pub fn exec<B: Backend>(b: &mut B, insn: super::Insn, w: u64, pc: u64) -> Flow<B> {
    match insn {
        super::Insn::Nop => Ok(()),
        super::Insn::MoveB => move_(b, w, pc, 1, false),
        super::Insn::MoveW => move_(b, w, pc, 2, false),
        super::Insn::MoveL => move_(b, w, pc, 4, false),
        super::Insn::MoveaW => move_(b, w, pc, 2, true),
        super::Insn::MoveaL => move_(b, w, pc, 4, true),
        super::Insn::Moveq => moveq(b, w),
        super::Insn::Add | super::Insn::AddDn | super::Insn::AddaL => arith(b, w, pc, false),
        super::Insn::Sub | super::Insn::SubDn | super::Insn::SubaL => arith(b, w, pc, true),
        super::Insn::AddxD | super::Insn::AddxM => addx_subx(b, w, pc, false),
        super::Insn::SubxD | super::Insn::SubxM => addx_subx(b, w, pc, true),
        super::Insn::Casb => cas(b, w, pc, 1),
        super::Insn::Casw => cas(b, w, pc, 2),
        super::Insn::Casl => cas(b, w, pc, 4),
        super::Insn::Cmp | super::Insn::CmpaL => cmp_(b, w, pc),
        super::Insn::Cmpm => cmpm(b, w, pc),
        super::Insn::Addq => addq(b, w, pc, false),
        super::Insn::Subq => addq(b, w, pc, true),
        super::Insn::Addi => imm_arith(b, w, pc, ImmOp::Add),
        super::Insn::Subi => imm_arith(b, w, pc, ImmOp::Sub),
        super::Insn::Cmpi => imm_arith(b, w, pc, ImmOp::Cmp),
        super::Insn::Or | super::Insn::OrBDn | super::Insn::OrWDn | super::Insn::OrLDn => {
            logic(b, w, pc, LogicOp::Or)
        }
        super::Insn::And | super::Insn::AndBDn | super::Insn::AndWDn | super::Insn::AndLDn => {
            logic(b, w, pc, LogicOp::And)
        }
        super::Insn::Eor => logic(b, w, pc, LogicOp::Eor),
        super::Insn::Ori => imm_logic(b, w, pc, LogicOp::Or),
        super::Insn::Andi => imm_logic(b, w, pc, LogicOp::And),
        super::Insn::Eori => imm_logic(b, w, pc, LogicOp::Eor),
        super::Insn::Not => unary(b, w, pc, UnOp::Not),
        super::Insn::Clr => unary(b, w, pc, UnOp::Clr),
        super::Insn::Tst => unary(b, w, pc, UnOp::Tst),
        super::Insn::Asr => shift_reg(b, w, pc, ShOp::As, true),
        super::Insn::Asl => shift_reg(b, w, pc, ShOp::As, false),
        super::Insn::Lsr => shift_reg(b, w, pc, ShOp::Ls, true),
        super::Insn::Lsl => shift_reg(b, w, pc, ShOp::Ls, false),
        super::Insn::Roxr => shift_reg(b, w, pc, ShOp::Rox, true),
        super::Insn::Roxl => shift_reg(b, w, pc, ShOp::Rox, false),
        super::Insn::Ror => shift_reg(b, w, pc, ShOp::Ro, true),
        super::Insn::Rol => shift_reg(b, w, pc, ShOp::Ro, false),
        super::Insn::AsrM => shift_mem(b, w, pc, ShOp::As, true),
        super::Insn::AslM => shift_mem(b, w, pc, ShOp::As, false),
        super::Insn::LsrM => shift_mem(b, w, pc, ShOp::Ls, true),
        super::Insn::LslM => shift_mem(b, w, pc, ShOp::Ls, false),
        super::Insn::RoxrM => shift_mem(b, w, pc, ShOp::Rox, true),
        super::Insn::RoxlM => shift_mem(b, w, pc, ShOp::Rox, false),
        super::Insn::RorM => shift_mem(b, w, pc, ShOp::Ro, true),
        super::Insn::RolM => shift_mem(b, w, pc, ShOp::Ro, false),
        super::Insn::Btst => bit_op(b, w, pc, BitOp::Tst, false),
        super::Insn::Bchg => bit_op(b, w, pc, BitOp::Chg, false),
        super::Insn::Bclr => bit_op(b, w, pc, BitOp::Clr, false),
        super::Insn::Bset => bit_op(b, w, pc, BitOp::Set, false),
        super::Insn::BtstI => bit_op(b, w, pc, BitOp::Tst, true),
        super::Insn::BchgI => bit_op(b, w, pc, BitOp::Chg, true),
        super::Insn::BclrI => bit_op(b, w, pc, BitOp::Clr, true),
        super::Insn::BsetI => bit_op(b, w, pc, BitOp::Set, true),
        super::Insn::Bra => branch_rel(b, w, pc, None, false),
        super::Insn::Bsr => branch_rel(b, w, pc, None, true),
        super::Insn::Bcc => branch_rel(b, w, pc, Some(((w >> 8) & 0xF) as u8), false),
        super::Insn::Jmp => jmp_jsr(b, w, pc, false),
        super::Insn::Jsr => jmp_jsr(b, w, pc, true),
        super::Insn::Rts => rts(b),
        super::Insn::Rtr => rtr(b),
        super::Insn::Scc => scc(b, w, pc),
        super::Insn::Dbcc => dbcc(b, w, pc),
        super::Insn::Lea => lea(b, w, pc),
        super::Insn::Pea => pea(b, w, pc),
        super::Insn::Link => link(b, w, pc),
        super::Insn::Unlk => unlk(b, w, pc),
        super::Insn::ExgDd => exg(b, w, false, false),
        super::Insn::ExgAa => exg(b, w, true, true),
        super::Insn::ExgDa => exg(b, w, false, true),
        super::Insn::Swap => swap_(b, w),
        super::Insn::ExtW => ext_(b, w, false),
        super::Insn::ExtL => ext_(b, w, true),
        super::Insn::MovrmW => movem_r2m(b, w, pc, 2),
        super::Insn::MovrmL => movem_r2m(b, w, pc, 4),
        super::Insn::MrmemW => movem_m2r(b, w, pc, 2),
        super::Insn::MrmemL => movem_m2r(b, w, pc, 4),
        super::Insn::MovepWm => movep(b, w, pc, 2, true),
        super::Insn::MovepLm => movep(b, w, pc, 4, true),
        super::Insn::MovepWr => movep(b, w, pc, 2, false),
        super::Insn::MovepLr => movep(b, w, pc, 4, false),
        super::Insn::Mulu => muldiv(b, w, pc, MulDiv::Mulu),
        super::Insn::Muls => muldiv(b, w, pc, MulDiv::Muls),
        super::Insn::Divu => muldiv(b, w, pc, MulDiv::Divu),
        super::Insn::Divs => muldiv(b, w, pc, MulDiv::Divs),
        super::Insn::AbcdR => bcd_reg(b, w, true),
        super::Insn::AbcdM => bcd_mem(b, w, pc, true),
        super::Insn::SbcdR => bcd_reg(b, w, false),
        super::Insn::SbcdM => bcd_mem(b, w, pc, false),
        super::Insn::Nbcd => nbcd(b, w, pc),
        super::Insn::Trap => Err(b.raise(GuestException {
            kind: ExceptionKind::Trap,
            // trap #n → ベクタ 32+n。
            code: 32 + (w & 0xF),
            addr: None,
            in_delay_slot: false,
        })),
        super::Insn::Trapv => trapv(b),
        super::Insn::Linea => Err(b.raise(GuestException {
            kind: ExceptionKind::Trap,
            code: 10,
            addr: None,
            in_delay_slot: false,
        })),
        super::Insn::Linef => Err(b.raise(GuestException {
            kind: ExceptionKind::Trap,
            code: 11,
            addr: None,
            in_delay_slot: false,
        })),
        super::Insn::Chk => chk(b, w, pc),
        super::Insn::Mv2ccr => mv2ccr(b, w, pc),
        super::Insn::Mv2sr => mv2sr(b, w, pc),
        super::Insn::Mvfrsr => mvfrsr(b, w, pc),
        super::Insn::Reset => reset(b),
        super::Insn::Rte => rte(b),
        super::Insn::Stop => stop(b, w, pc),
        super::Insn::Mv2usp => mvusp(b, w, true),
        super::Insn::Mvfrusp => mvusp(b, w, false),
        super::Insn::Neg => neg_(b, w, pc, false),
        super::Insn::Negx => neg_(b, w, pc, true),
        super::Insn::Mull => mull(b, w, pc),
        super::Insn::Divl => divl(b, w, pc),
        super::Insn::ExtbL => extb_l(b, w),
        super::Insn::Bftst => bf(b, w, pc, BfOp::Tst),
        super::Insn::Bfchg => bf(b, w, pc, BfOp::Chg),
        super::Insn::Bfclr => bf(b, w, pc, BfOp::Clr),
        super::Insn::Bfset => bf(b, w, pc, BfOp::Set),
        super::Insn::Bfextu => bf(b, w, pc, BfOp::Extu),
        super::Insn::Bfexts => bf(b, w, pc, BfOp::Exts),
        super::Insn::Bfffo => bf(b, w, pc, BfOp::Ffo),
        super::Insn::Bfins => bf(b, w, pc, BfOp::Ins),
        super::Insn::Illegal => Err(b.raise(GuestException {
            kind: ExceptionKind::Trap,
            // m68k の例外ベクタ番号 4（Illegal Instruction）。
            code: 4,
            addr: None,
            in_delay_slot: false,
        })),
    }
}

/// illegal instruction（例外ベクタ 4）を発生させる。
// Ref: SPEC-M68K-PRM (Rev 1) §Exception Processing.
fn illegal<B: Backend>(b: &mut B) -> B::Exit {
    b.raise(GuestException {
        kind: ExceptionKind::Trap,
        code: 4,
        addr: None,
        in_delay_slot: false,
    })
}

/// `v` を `size` バイトに零拡張して返す。
fn mask<B: Backend>(b: &mut B, v: B::V<W32>, size: u32) -> B::V<W32> {
    match size {
        1 => {
            let m = b.konst::<W32>(0xFF);
            b.and(v, m)
        }
        2 => {
            let m = b.konst::<W32>(0xFFFF);
            b.and(v, m)
        }
        _ => v,
    }
}

/// EA オペランドから `size` バイトの値を読む（零拡張した W32）。
fn read_ea<B: Backend>(b: &mut B, e: &Ea<B>, size: u32) -> Result<B::V<W32>, B::Exit> {
    match e {
        Ea::D(n) => {
            let v = b.get(D(*n).state());
            Ok(mask(b, v, size))
        }
        Ea::A(n) => {
            let v = areg(b, *n);
            Ok(mask(b, v, size))
        }
        Ea::Addr(a) => match size {
            1 => {
                let __da0 = drd(b);
                let v = b.load::<W8>(*a, __da0)?;
                Ok(b.zext::<W8, W32>(v))
            }
            2 => {
                let __da0 = drd(b);
                let v = b.load::<W16>(*a, __da0)?;
                Ok(b.zext::<W16, W32>(v))
            }
            // 68000 のバスは16ビットで、long は上位→下位の word アクセス
            // 2回（偶数整列のみ必須。4バイト整列ではない）。
            _ => {
                let __da0 = drd(b);
                let hi = b.load::<W16>(*a, __da0)?;
                let two = b.konst::<W64>(2);
                let a2 = b.add(*a, two);
                let __da0 = drd(b);
                let lo = b.load::<W16>(a2, __da0)?;
                let hi32 = b.zext::<W16, W32>(hi);
                let shift = b.konst::<W32>(16);
                let hi_sh = b.shl(hi32, shift);
                let lo32 = b.zext::<W16, W32>(lo);
                Ok(b.or(hi_sh, lo32))
            }
        },
        Ea::Imm(v) => Ok(*v),
    }
}

/// EA オペランドに `size` バイトの値を書く。Dn 宛ての byte/word は
/// 上位ビットを保持する。An 直・即値宛てはここでは illegal。
fn write_ea<B: Backend>(b: &mut B, e: &Ea<B>, size: u32, v: B::V<W32>) -> Flow<B> {
    match e {
        Ea::D(n) => {
            match size {
                4 => b.set(D(*n).state(), v),
                _ => {
                    let keep = if size == 1 { !0xFFu32 } else { !0xFFFFu32 };
                    let old = b.get(D(*n).state());
                    let km = b.konst::<W32>(keep);
                    let hi = b.and(old, km);
                    let lo = mask(b, v, size);
                    let nv = b.or(hi, lo);
                    b.set(D(*n).state(), nv);
                }
            }
            Ok(())
        }
        Ea::Addr(a) => match size {
            1 => {
                let v8 = b.trunc::<W32, W8>(v);
                let __da0 = dwr(b);
                b.store::<W8>(*a, v8, __da0)
            }
            2 => {
                let v16 = b.trunc::<W32, W16>(v);
                let __da0 = dwr(b);
                b.store::<W16>(*a, v16, __da0)
            }
            // long は上位→下位の word アクセス2回（偶数整列のみ必須）。
            _ => {
                let shift = b.konst::<W32>(16);
                let hi32 = b.shr_l(v, shift);
                let hi = b.trunc::<W32, W16>(hi32);
                let __da0 = dwr(b);
                b.store::<W16>(*a, hi, __da0)?;
                let lo = b.trunc::<W32, W16>(v);
                let two = b.konst::<W64>(2);
                let a2 = b.add(*a, two);
                let __da0 = dwr(b);
                b.store::<W16>(a2, lo, __da0)
            }
        },
        // An 直・即値は move の宛先に使えない。
        Ea::A(_) | Ea::Imm(_) => Err(illegal(b)),
    }
}

/// 結果に応じて CCR の N/Z を更新し V/C をクリアする（X は保持）。
fn set_nzvc<B: Backend>(b: &mut B, v: B::V<W32>, size: u32) {
    let ccr = b.get(ccr_ref());
    // X（bit4）と予約上位だけ残す。
    let km = b.konst::<W8>(1 << sr_bit::X | 0xE0);
    let keep = b.and(ccr, km);
    let mv = mask(b, v, size);
    let msb = 1u32 << (size * 8 - 1);
    let km32 = b.konst::<W32>(msb);
    let n_part = b.and(mv, km32);
    let zero = b.konst::<W32>(0);
    let is_n = b.cmp(Cmp::Ne, n_part, zero);
    let is_z = b.cmp(Cmp::Eq, mv, zero);
    let nk = b.konst::<W8>(1 << sr_bit::N);
    let zk = b.konst::<W8>(1 << sr_bit::Z);
    let z8 = b.konst::<W8>(0);
    let n8 = b.select(is_n, nk, z8);
    let z8 = b.select(is_z, zk, z8);
    let nz = b.or(n8, z8);
    let out = b.or(keep, nz);
    b.set(ccr_ref(), out);
}

/// move/movea の source 読み出し → destination 書き込み。
/// movea は word source を 32 ビットに符号拡張し、旗を更新しない。
// Ref: SPEC-M68K-PRM (Rev 1) §MOVE/MOVEA.
fn move_<B: Backend>(b: &mut B, w: u64, pc: u64, size: u32, is_movea: bool) -> Flow<B> {
    // 宛先の legality は静的に決まるので先に弾く（実機は EA の
    // 副作用・バスアクセスより先に illegal を取る）。
    let dmode = ea::dest_mode(w);
    let dreg = ea::dest_reg(w);
    if !is_movea && dmode == 7 && dreg >= 2 {
        return Err(illegal(b));
    }
    let extv = b.konst::<W64>(pc + 2);
    let (src, _n1, cnt1) = ea::eval_full_v(b, ea::ea_mode(w), ea::ea_reg(w), size, extv)?;
    let v = read_ea(b, &src, size)?;
    if is_movea {
        let vv = if size == 2 {
            let lo = b.trunc::<W32, W16>(v);
            b.sext::<W16, W32>(lo)
        } else {
            v
        };
        return set_areg(b, dreg, vv);
    }
    // full 形式 EA は語数が動的なので、宛先拡張語の位置は
    // シンボリック語数から計算する（ext + cnt*2）。
    let c1_64 = b.zext::<W32, W64>(cnt1);
    let two = b.konst::<W64>(2);
    let cbytes = b.mul(c1_64, two);
    let dext = b.add(extv, cbytes);
    let (dst, _n2, _c2) = ea::eval_full_v(b, dmode, dreg, size, dext)?;
    write_ea(b, &dst, size, v)?;
    set_nzvc(b, v, size);
    Ok(())
}

/// moveq: 8 ビット即値を符号拡張して Dn に置く。旗は N/Z 更新・V/C 0。
// Ref: SPEC-M68K-PRM (Rev 1) §MOVEQ.
fn moveq<B: Backend>(b: &mut B, w: u64) -> Flow<B> {
    let dreg = ea::dest_reg(w);
    let imm = b.konst::<W8>((w & 0xFF) as u8);
    let v = b.sext::<W8, W32>(imm);
    b.set(D(dreg).state(), v);
    set_nzvc(b, v, 4);
    Ok(())
}

// ---- C2: 加減算・比較系 ----

/// `size` バイトのマスク値。
const fn size_mask(size: u32) -> u32 {
    match size {
        1 => 0xFF,
        2 => 0xFFFF,
        _ => 0xFFFF_FFFF,
    }
}

/// 加減算・比較の旗を更新する。`d`・`s`・`r` は W32 の生値で、
/// ここで `size` にマスクしてから判定する。
/// `sub`: 減算なら真（C は借り、V の式が変わる）。
/// `acc_z`: 真なら Z は「結果非零でクリア、零で保持」（BCD 系の複数語連鎖用）。
/// `set_x`: 真なら X も C に同期する（cmp 系以外）。
// Ref: SPEC-M68K-PRM (Rev 1) §Condition Codes.
#[allow(clippy::too_many_arguments)]
fn set_arith_flags<B: Backend>(
    b: &mut B,
    d: B::V<W32>,
    s: B::V<W32>,
    r: B::V<W32>,
    size: u32,
    sub: bool,
    acc_z: bool,
    set_x: bool,
) {
    let m = b.konst::<W32>(size_mask(size));
    let dm = b.and(d, m);
    let sm = b.and(s, m);
    let rm = b.and(r, m);
    let sign = b.konst::<W32>(1u32 << (size * 8 - 1));
    let zero = b.konst::<W32>(0);
    let ds = b.xor(dm, sm);
    let dr = b.xor(dm, rm);
    // V: 減算は被演算子の符号が違い結果が被減数と違う、加算は
    // 被演算子の符号が同じで結果と違う。
    let v_bits = if sub {
        b.and(ds, dr)
    } else {
        let nds = b.not(ds);
        b.and(nds, dr)
    };
    let v_at = b.and(v_bits, sign);
    let is_v = b.cmp(Cmp::Ne, v_at, zero);
    // C: 減算は dm < sm（借り）、加算は rm < dm（繰り上がり）。
    let is_c = if sub {
        b.cmp(Cmp::LtU, dm, sm)
    } else {
        b.cmp(Cmp::LtU, rm, dm)
    };
    let n_at = b.and(rm, sign);
    let is_n = b.cmp(Cmp::Ne, n_at, zero);
    let is_z = b.cmp(Cmp::Eq, rm, zero);
    let ccr = b.get(ccr_ref());
    let km = b.konst::<W8>(0xE0 | u8::from(!set_x) << sr_bit::X);
    let keep = b.and(ccr, km);
    let nk = b.konst::<W8>(1 << sr_bit::N);
    let zk = b.konst::<W8>(1 << sr_bit::Z);
    let vk = b.konst::<W8>(1 << sr_bit::V);
    let ck = b.konst::<W8>(1 << sr_bit::C);
    let z8 = b.konst::<W8>(0);
    let n8 = b.select(is_n, nk, z8);
    let v8 = b.select(is_v, vk, z8);
    let c8 = b.select(is_c, ck, z8);
    // acc_z なら結果零のとき Z は旧値を保持する。
    let zsel = if acc_z { b.and(ccr, zk) } else { zk };
    let zf = b.select(is_z, zsel, z8);
    let nv = b.or(n8, v8);
    let nvc = b.or(nv, c8);
    let nvcz = b.or(nvc, zf);
    let out0 = b.or(keep, nvcz);
    // X は C に同期する（set_x のときだけ）。
    let x8 = if set_x {
        let xk = b.konst::<W8>(1 << sr_bit::X);
        b.select(is_c, xk, z8)
    } else {
        z8
    };
    let out = b.or(out0, x8);
    b.set(ccr_ref(), out);
}

/// add/sub（opm 0-2: <ea> op Dn、opm 3/7: <ea> op An、opm 4-6:
/// Dn op <ea>）。宛先 An は旗を更新しない。
// Ref: SPEC-M68K-PRM (Rev 1) §ADD/SUB.
fn arith<B: Backend>(b: &mut B, w: u64, pc: u64, sub: bool) -> Flow<B> {
    let opm = ea::dest_mode(w);
    let reg = ea::dest_reg(w);
    let emode = ea::ea_mode(w);
    let ereg = ea::ea_reg(w);
    match opm {
        0..=2 => {
            let size = 1u32 << opm;
            // byte サイズの An オペランドは未割当。
            if emode == 1 && size == 1 {
                return Err(illegal(b));
            }
            let (e, _n) = ea::eval(b, emode, ereg, size, pc + 2)?;
            let s = read_ea(b, &e, size)?;
            let d = b.get(D(reg).state());
            let r = if sub { b.sub(d, s) } else { b.add(d, s) };
            set_arith_flags(b, d, s, r, size, sub, false, true);
            write_ea(b, &Ea::D(reg), size, r)
        }
        3 | 7 => {
            // adda/suba: word オペランドは32ビットに符号拡張。旗は不変。
            let size = if opm == 3 { 2 } else { 4 };
            let (e, _n) = ea::eval(b, emode, ereg, size, pc + 2)?;
            let s0 = read_ea(b, &e, size)?;
            let s = if opm == 3 {
                let lo = b.trunc::<W32, W16>(s0);
                b.sext::<W16, W32>(lo)
            } else {
                s0
            };
            let a = areg(b, reg);
            let r = if sub { b.sub(a, s) } else { b.add(a, s) };
            set_areg(b, reg, r)
        }
        _ => {
            // Dn op <ea>。宛先は alterable（An 直・PC 相対・即値は不可。
            // emode 0/1 は addx/subx の空間として decode で弾かれる）。
            let size = 1u32 << (opm - 4);
            if emode == 1 || (emode == 7 && ereg >= 2) {
                return Err(illegal(b));
            }
            let (e, _n) = ea::eval(b, emode, ereg, size, pc + 2)?;
            let s = read_ea(b, &e, size)?;
            let d0 = b.get(D(reg).state());
            let d = mask(b, d0, size);
            // sub は <ea> - Dn（被減数は EA 側）。
            let r = if sub { b.sub(s, d) } else { b.add(s, d) };
            set_arith_flags(b, s, d, r, size, sub, false, true);
            write_ea(b, &e, size, r)
        }
    }
}

/// cmp/cmpa（Dn - <ea> または An - <ea>）。旗は N/Z/V/C、
/// Z は累積、X は不変。
// Ref: SPEC-M68K-PRM (Rev 1) §CMP/CMPA.
fn cmp_<B: Backend>(b: &mut B, w: u64, pc: u64) -> Flow<B> {
    let opm = ea::dest_mode(w);
    let reg = ea::dest_reg(w);
    let emode = ea::ea_mode(w);
    let ereg = ea::ea_reg(w);
    if opm == 3 || opm == 7 {
        // cmpa: word オペランドは32ビットに符号拡張。
        let size = if opm == 3 { 2 } else { 4 };
        let (e, _n) = ea::eval(b, emode, ereg, size, pc + 2)?;
        let s0 = read_ea(b, &e, size)?;
        let s = if opm == 3 {
            let lo = b.trunc::<W32, W16>(s0);
            b.sext::<W16, W32>(lo)
        } else {
            s0
        };
        let d = areg(b, reg);
        let r = b.sub(d, s);
        set_arith_flags(b, d, s, r, 4, true, false, false);
        return Ok(());
    }
    let size = 1u32 << opm;
    if emode == 1 && size == 1 {
        return Err(illegal(b));
    }
    let (e, _n) = ea::eval(b, emode, ereg, size, pc + 2)?;
    let s = read_ea(b, &e, size)?;
    let d0 = b.get(D(reg).state());
    let d = mask(b, d0, size);
    let r = b.sub(d, s);
    set_arith_flags(b, d, s, r, size, true, false, false);
    Ok(())
}

/// cmpm: (Ay)+ - (Ax)+。両方 postincrement で進む。
// Ref: SPEC-M68K-PRM (Rev 1) §CMPM.
fn cmpm<B: Backend>(b: &mut B, w: u64, _pc: u64) -> Flow<B> {
    let size = 1u32 << ea::qsz(w);
    let xr = ea::dest_reg(w);
    let yr = ea::ea_reg(w);
    let (es, _n) = ea::eval(b, 3, yr, size, 0)?;
    let s = read_ea(b, &es, size)?;
    let (ed, _n) = ea::eval(b, 3, xr, size, 0)?;
    let d = read_ea(b, &ed, size)?;
    let r = b.sub(d, s);
    set_arith_flags(b, d, s, r, size, true, false, false);
    Ok(())
}

/// addx/subx: X 込みの多倍長加減。Dn↔Dn（emode=0）と
/// -(Ay),-(Ax)（emode=1）の2形式。借り・桁上げは X 込みの
/// 演算から出る（s+x が W32 を溢れる角があるため W64 で求める）。
/// Z は結果零なら旧値を保持する累積更新。X は C に同期する。
// Ref: SPEC-M68K-PRM (Rev 1) §ADDX/SUBX.
fn addx_subx<B: Backend>(b: &mut B, w: u64, pc: u64, sub: bool) -> Flow<B> {
    let size = 1u32 << ea::qsz(w);
    let dx = ea::dest_reg(w);
    let dy = ea::ea_reg(w);
    let (es, ed) = if ea::ea_mode(w) == 1 {
        let (es, _n1) = ea::eval(b, 4, dy, size, pc + 2)?;
        let (ed, _n2) = ea::eval(b, 4, dx, size, pc + 2)?;
        (es, ed)
    } else {
        (Ea::D(dy), Ea::D(dx))
    };
    let s = read_ea(b, &es, size)?;
    let d = read_ea(b, &ed, size)?;
    let x = x_flag(b);
    let mk = b.konst::<W32>(size_mask(size));
    let dm = b.and(d, mk);
    let sm = b.and(s, mk);
    let dm64 = b.zext::<W32, W64>(dm);
    let sm64 = b.zext::<W32, W64>(sm);
    let x64 = b.zext::<W32, W64>(x);
    let (r64, is_c) = if sub {
        let t = b.add(sm64, x64);
        let is_c = b.cmp(Cmp::LtU, dm64, t);
        (b.sub(dm64, t), is_c)
    } else {
        let t0 = b.add(dm64, sm64);
        let t = b.add(t0, x64);
        let m64 = b.konst::<W64>(u64::from(size_mask(size)));
        let is_c = b.cmp(Cmp::GtU, t, m64);
        (t, is_c)
    };
    let r = b.trunc::<W64, W32>(r64);
    // N/Z/V は set_arith_flags と同じ式だが、C は X 込みで外部
    // 計算した値を使い X にも写すので自前で組み立てる。
    let rm = b.and(r, mk);
    let sign = b.konst::<W32>(1u32 << (size * 8 - 1));
    let zero = b.konst::<W32>(0);
    let ds = b.xor(dm, sm);
    let dr = b.xor(dm, rm);
    let v_bits = if sub {
        b.and(ds, dr)
    } else {
        let nds = b.not(ds);
        b.and(nds, dr)
    };
    let v_at = b.and(v_bits, sign);
    let is_v = b.cmp(Cmp::Ne, v_at, zero);
    let n_at = b.and(rm, sign);
    let is_n = b.cmp(Cmp::Ne, n_at, zero);
    let is_z = b.cmp(Cmp::Eq, rm, zero);
    let ccr = b.get(ccr_ref());
    let km = b.konst::<W8>(0xE0);
    let keep = b.and(ccr, km);
    let z8 = b.konst::<W8>(0);
    let nk = b.konst::<W8>(1 << sr_bit::N);
    let zk = b.konst::<W8>(1 << sr_bit::Z);
    let vk = b.konst::<W8>(1 << sr_bit::V);
    let ck = b.konst::<W8>(1 << sr_bit::C);
    let xk = b.konst::<W8>(1 << sr_bit::X);
    let n8 = b.select(is_n, nk, z8);
    // 累積 Z: 結果が零なら旧値を維持、非零ならクリア。
    let zsel = b.and(ccr, zk);
    let zf = b.select(is_z, zsel, z8);
    let v8 = b.select(is_v, vk, z8);
    let c8 = b.select(is_c, ck, z8);
    let x8 = b.select(is_c, xk, z8);
    let o1 = b.or(n8, zf);
    let o2 = b.or(v8, c8);
    let o3 = b.or(x8, keep);
    let o12 = b.or(o1, o2);
    let out = b.or(o12, o3);
    b.set(ccr_ref(), out);
    write_ea(b, &ed, size, r)
}

/// cas: アトミックな比較交換（68020+）。Dc と <ea> を比較し、
/// 等しければ Du を <ea> に書き、違えば <ea> の値を Dc に入れる。
/// 旗は Dc - <ea> の cmp 相当（X は不変）。拡張語は
/// bits[8:6]=Du、bits[2:0]=Dc。
// Ref: SPEC-M68K-PRM (Rev 1) §CAS.
fn cas<B: Backend>(b: &mut B, w: u64, pc: u64, size: u32) -> Flow<B> {
    let emode = ea::ea_mode(w);
    let ereg = ea::ea_reg(w);
    // <ea> はメモリの control alterable。Dn/An 直・PC 相対・即値は不可。
    if !(matches!(emode, 2..=6) || (emode == 7 && ereg <= 1)) {
        return Err(illegal(b));
    }
    let ext = ea::ext_w16(b, pc + 2)?;
    let e32 = b.zext::<W16, W32>(ext);
    let du_n = ext_reg(b, e32, 6);
    let dc_n = ext_reg(b, e32, 0);
    let (e, _n) = ea::eval(b, emode, ereg, size, pc + 4)?;
    let mem = read_ea(b, &e, size)?;
    let dcv = get_dx(b, dc_n);
    let dc = mask(b, dcv, size);
    let du = get_dx(b, du_n);
    // <ea> - Dc の比較旗（PRM: destination operand minus compare
    // operand。cmp と同じ N/Z/V/C だが被減数はメモリ側、X 不変）。
    let r = b.sub(mem, dc);
    set_arith_flags(b, mem, dc, r, size, true, false, false);
    let eq = b.cmp(Cmp::Eq, dc, mem);
    b.if_then_else(
        eq,
        |bb| write_ea(bb, &e, size, du),
        |bb| {
            // Dc のオペランドサイズ分だけ <ea> の値で置き換える
            // （上位ビットは保持）。
            let full = get_dx(bb, dc_n);
            let km = bb.konst::<W32>(size_mask(size));
            let nm = bb.not(km);
            let hi = bb.and(full, nm);
            let lo = bb.and(mem, km);
            let merged = bb.or(hi, lo);
            bb.set_indexed(ea::d_array(), dc_n, merged);
            Ok(())
        },
    )
}

/// addq/subq: 3ビット即値（0 は 8）を EA に加減する。
/// 宛先 An は旗を更新せず 32 ビット全体を書き換える。
// Ref: SPEC-M68K-PRM (Rev 1) §ADDQ/SUBQ.
fn addq<B: Backend>(b: &mut B, w: u64, pc: u64, sub: bool) -> Flow<B> {
    let size = 1u32 << ea::qsz(w);
    let emode = ea::ea_mode(w);
    let ereg = ea::ea_reg(w);
    let q = ea::dest_reg(w);
    let v = if q == 0 { 8 } else { u32::from(q) };
    let s = b.konst::<W32>(v);
    // byte の An 宛ては未割当。PC 相対・即値宛ては不可。
    if emode == 1 && size == 1 {
        return Err(illegal(b));
    }
    if emode == 7 && ereg >= 2 {
        return Err(illegal(b));
    }
    if emode == 1 {
        // An 宛て: 旗は不変、サイズに関係なく32ビット全体。
        let a = areg(b, ereg);
        let r = if sub { b.sub(a, s) } else { b.add(a, s) };
        return set_areg(b, ereg, r);
    }
    let (e, _n) = ea::eval(b, emode, ereg, size, pc + 2)?;
    let d = read_ea(b, &e, size)?;
    let r = if sub { b.sub(d, s) } else { b.add(d, s) };
    set_arith_flags(b, d, s, r, size, sub, false, true);
    write_ea(b, &e, size, r)
}

/// 即値系の演算種別。
enum ImmOp {
    Add,
    Sub,
    Cmp,
}

/// addi/subi/cmpi: 拡張語の即値と EA の演算。cmpi は書き戻さない。
// Ref: SPEC-M68K-PRM (Rev 1) §ADDI/SUBI/CMPI.
fn imm_arith<B: Backend>(b: &mut B, w: u64, pc: u64, op: ImmOp) -> Flow<B> {
    let size = 1u32 << ea::qsz(w);
    let emode = ea::ea_mode(w);
    let ereg = ea::ea_reg(w);
    // 宛先の合法性: 68000 は即値系の EA を宛先オペランドとして厳密に
    // デコードするため、cmpi でも An 直・PC 相対・即値はすべて illegal
    // （68020+ で緩和された制約）。
    if emode == 1 || (emode == 7 && ereg >= 2) {
        return Err(illegal(b));
    }
    let (imm_e, ni) = ea::eval(b, 7, 4, size, pc + 2)?;
    let s = match imm_e {
        Ea::Imm(v) => v,
        _ => unreachable!("mode7 reg4 は Imm"),
    };
    let ext = pc + 2 + u64::from(ni) * 2;
    let (e, _n) = ea::eval(b, emode, ereg, size, ext)?;
    let d = read_ea(b, &e, size)?;
    match op {
        ImmOp::Cmp => {
            let r = b.sub(d, s);
            set_arith_flags(b, d, s, r, size, true, false, false);
            Ok(())
        }
        ImmOp::Add | ImmOp::Sub => {
            let sub = matches!(op, ImmOp::Sub);
            let r = if sub { b.sub(d, s) } else { b.add(d, s) };
            set_arith_flags(b, d, s, r, size, sub, false, true);
            write_ea(b, &e, size, r)
        }
    }
}

/// or/and/eor の演算種別。
enum LogicOp {
    Or,
    And,
    Eor,
}

/// 論理演算 `d op s`（値は `size` バイトにマスク済みを想定）。
fn combine<B: Backend>(b: &mut B, op: LogicOp, d: B::V<W32>, s: B::V<W32>) -> B::V<W32> {
    match op {
        LogicOp::Or => b.or(d, s),
        LogicOp::And => b.and(d, s),
        LogicOp::Eor => b.xor(d, s),
    }
}

/// or/and/eor。opm 0-2 は `<ea> op Dn`、4-6 は `Dn op <ea>`
/// （eor は後者のみ）。旗は N/Z を結果に従い V/C=0、X は保持。
// Ref: SPEC-M68K-PRM (Rev 1) §OR/AND/EOR.
fn logic<B: Backend>(b: &mut B, w: u64, pc: u64, op: LogicOp) -> Flow<B> {
    let opm = ea::dest_mode(w);
    let reg = ea::dest_reg(w);
    let emode = ea::ea_mode(w);
    let ereg = ea::ea_reg(w);
    if opm <= 2 {
        // <ea> op Dn。byte の An ソースは未割当。
        let size = 1u32 << opm;
        if emode == 1 && size == 1 {
            return Err(illegal(b));
        }
        let (e, _n) = ea::eval(b, emode, ereg, size, pc + 2)?;
        let s = read_ea(b, &e, size)?;
        let d0 = b.get(D(reg).state());
        let d = mask(b, d0, size);
        let r = combine(b, op, d, s);
        set_nzvc(b, r, size);
        write_ea(b, &Ea::D(reg), size, r)
    } else {
        // Dn op <ea>。宛先は data alterable（An 直・PC 相対・即値は不可）。
        let size = 1u32 << (opm - 4);
        if emode == 1 || (emode == 7 && ereg >= 2) {
            return Err(illegal(b));
        }
        let (e, _n) = ea::eval(b, emode, ereg, size, pc + 2)?;
        let s = read_ea(b, &e, size)?;
        let d0 = b.get(D(reg).state());
        let d = mask(b, d0, size);
        let r = combine(b, op, d, s);
        set_nzvc(b, r, size);
        write_ea(b, &e, size, r)
    }
}

/// not/clr/tst の演算種別。
enum UnOp {
    Not,
    Clr,
    Tst,
}

/// not/clr/tst。EA は data alterable（An 直・PC 相対・即値は illegal。
/// tst も 68000 では宛先オペランドとして厳密にデコードされる）。
/// 旗は N/Z を結果に従い V/C=0、X は保持。clr は Z=1。
// Ref: SPEC-M68K-PRM (Rev 1) §NOT/CLR/TST.
fn unary<B: Backend>(b: &mut B, w: u64, pc: u64, op: UnOp) -> Flow<B> {
    let size = 1u32 << ea::qsz(w);
    let emode = ea::ea_mode(w);
    let ereg = ea::ea_reg(w);
    // CLR/NOT/NEG/NEGX: data alterable のみ。TST は 68020+ で
    // An 直・PC 相対・即値も合法（byte 即値は常に不可）。
    let tst = matches!(op, UnOp::Tst) && b.param::<super::EaFullParam>();
    let ok = if tst {
        match emode {
            1 => size > 1,
            7 if ereg == 4 => size > 1,
            7 => ereg <= 3,
            _ => true,
        }
    } else {
        emode != 1 && !(emode == 7 && ereg >= 2)
    };
    if !ok {
        return Err(illegal(b));
    }
    let (e, _n) = ea::eval(b, emode, ereg, size, pc + 2)?;
    let z = b.konst::<W32>(0);
    match op {
        UnOp::Tst => {
            let d = read_ea(b, &e, size)?;
            set_nzvc(b, d, size);
            Ok(())
        }
        UnOp::Clr => {
            set_nzvc(b, z, size);
            write_ea(b, &e, size, z)
        }
        UnOp::Not => {
            let d = read_ea(b, &e, size)?;
            let n = b.not(d);
            let r = mask(b, n, size);
            set_nzvc(b, r, size);
            write_ea(b, &e, size, r)
        }
    }
}

/// ori/andi/eori。EA が #imm（emode7 ereg4）のとき to CCR（byte）/
/// to SR（word）の特殊符号化になる。to SR はスーパーバイザ必須。
// Ref: SPEC-M68K-PRM (Rev 1) §ANDI/ORI/EORI to CCR/SR.
fn imm_logic<B: Backend>(b: &mut B, w: u64, pc: u64, op: LogicOp) -> Flow<B> {
    let size = 1u32 << ea::qsz(w);
    let emode = ea::ea_mode(w);
    let ereg = ea::ea_reg(w);
    if emode == 7 && ereg == 4 {
        let (imm_e, _ni) = ea::eval(b, 7, 4, size, pc + 2)?;
        let s = match imm_e {
            Ea::Imm(v) => v,
            _ => unreachable!("mode7 reg4 は Imm"),
        };
        return match size {
            1 => {
                // to CCR: 即値の下位バイトで演算。書き込み可能なのは
                // 旗5ビットのみ（上位3ビットはハードウェア上 0）。
                let old = b.get(ccr_ref());
                let im = b.trunc::<W32, W8>(s);
                let r = match op {
                    LogicOp::Or => b.or(old, im),
                    LogicOp::And => b.and(old, im),
                    LogicOp::Eor => b.xor(old, im),
                };
                let km = b.konst::<W8>(0x1F);
                let rm = b.and(r, km);
                b.set(ccr_ref(), rm);
                Ok(())
            }
            2 => {
                // to SR: スーパーバイザ必須（違反はベクタ 8）。
                let old = b.get(sr_ref());
                let sm = b.konst::<W32>(1 << sr_bit::S);
                let sv = b.and(old, sm);
                let z = b.konst::<W32>(0);
                let is_s = b.cmp(Cmp::Ne, sv, z);
                b.if_then_else(
                    is_s,
                    |bb| {
                        let im = mask(bb, s, 2);
                        let r = combine(bb, op, old, im);
                        // SR の書き込み可能ビットは T|S|IPL|CCR = 0xA71F。
                        let km = bb.konst::<W32>(0xA71F);
                        let rm = bb.and(r, km);
                        bb.set(sr_ref(), rm);
                        Ok(())
                    },
                    |bb| {
                        Err(bb.raise(GuestException {
                            kind: ExceptionKind::Trap,
                            code: 8,
                            addr: None,
                            in_delay_slot: false,
                        }))
                    },
                )
            }
            _ => Err(illegal(b)),
        };
    }
    // 宛先は data alterable（An 直・PC 相対・即値は illegal）。
    if emode == 1 || (emode == 7 && ereg >= 2) {
        return Err(illegal(b));
    }
    let (imm_e, ni) = ea::eval(b, 7, 4, size, pc + 2)?;
    let s = match imm_e {
        Ea::Imm(v) => v,
        _ => unreachable!("mode7 reg4 は Imm"),
    };
    let ext = pc + 2 + u64::from(ni) * 2;
    let (e, _n) = ea::eval(b, emode, ereg, size, ext)?;
    let d = read_ea(b, &e, size)?;
    let r = combine(b, op, d, s);
    set_nzvc(b, r, size);
    write_ea(b, &e, size, r)
}

/// シフト/ローテートの演算種別。
#[derive(Clone, Copy)]
enum ShOp {
    /// 算術シフト。
    As,
    /// 論理シフト。
    Ls,
    /// X 拡張ローテート。
    Rox,
    /// ローテート。
    Ro,
}

/// 条件を 0/1 の V<W32> にする。
fn bit_of<B: Backend>(b: &mut B, c: B::B) -> B::V<W32> {
    let one = b.konst::<W32>(1);
    let z = b.konst::<W32>(0);
    b.select(c, one, z)
}

/// `v` の `k` ビット目を 0/1 で取り出す。
fn bitk<B: Backend>(b: &mut B, v: B::V<W32>, k: B::V<W32>) -> B::V<W32> {
    let one = b.konst::<W32>(1);
    let s = b.shr_l(v, k);
    b.and(s, one)
}

/// CCR から X ビットを 0/1 の V<W32> で取り出す。
fn read_x<B: Backend>(b: &mut B) -> B::V<W32> {
    let ccr = b.get(ccr_ref());
    let xk = b.konst::<W8>(1 << sr_bit::X);
    let x8 = b.and(ccr, xk);
    let x32 = b.zext::<W8, W32>(x8);
    let k = b.konst::<W32>(4);
    b.shr_l(x32, k)
}

/// シフト結果の旗を更新する。`co`/`vo`/`xo` は 0/1 の生値で、
/// X は常に `xo` に書き換える（保持が必要な場面では呼び出し側が
/// 旧値を渡す）。N/Z は結果から、V/C は引数のまま。
fn set_shift_flags<B: Backend>(
    b: &mut B,
    r: B::V<W32>,
    size: u32,
    co: B::V<W32>,
    vo: B::V<W32>,
    xo: B::V<W32>,
) {
    let ccr = b.get(ccr_ref());
    let km = b.konst::<W8>(0xE0);
    let keep = b.and(ccr, km);
    let keep32 = b.zext::<W8, W32>(keep);
    let mv = mask(b, r, size);
    let msb = 1u32 << (size * 8 - 1);
    let mk = b.konst::<W32>(msb);
    let np = b.and(mv, mk);
    let z = b.konst::<W32>(0);
    let pn = b.cmp(Cmp::Ne, np, z);
    let pz = b.cmp(Cmp::Eq, mv, z);
    let nn = bit_of(b, pn);
    let zz = bit_of(b, pz);
    let k3 = b.konst::<W32>(3);
    let k2 = b.konst::<W32>(2);
    let k1 = b.konst::<W32>(1);
    let k4 = b.konst::<W32>(4);
    let n8 = b.shl(nn, k3);
    let z8 = b.shl(zz, k2);
    let v8 = b.shl(vo, k1);
    let x8 = b.shl(xo, k4);
    let o1 = b.or(keep32, x8);
    let o2 = b.or(o1, n8);
    let o3 = b.or(o2, z8);
    let o4 = b.or(o3, v8);
    let out32 = b.or(o4, co);
    let out = b.trunc::<W32, W8>(out32);
    b.set(ccr_ref(), out);
}

/// `shift_core` の戻り値。(結果, C, V, X) で旗ビットはすべて 0/1。
type ShOut<B> = (
    <B as Backend>::V<W32>,
    <B as Backend>::V<W32>,
    <B as Backend>::V<W32>,
    <B as Backend>::V<W32>,
);

/// シフト/ローテートのコア。`d` は `size` バイトにマスク済みの値、
/// `c` はカウント（0〜63）、`xin` は 0/1 の X。
// Ref: SPEC-M68K-PRM (Rev 1) §Condition Code Computation.
fn shift_core<B: Backend>(
    b: &mut B,
    d: B::V<W32>,
    c: B::V<W32>,
    size: u32,
    op: ShOp,
    right: bool,
    xin: B::V<W32>,
) -> ShOut<B> {
    let wb = size * 8;
    let z = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let wk = b.konst::<W32>(wb);
    let c0 = b.cmp(Cmp::Eq, c, z);
    let cbig = b.cmp(Cmp::GeU, c, wk);
    match (op, right) {
        (ShOp::Ls, true) => {
            // lsr: c>=wb なら 0。C = bit(c-1)（1<=c<=wb）。
            let r0 = b.shr_l(d, c);
            let r = b.select(cbig, z, r0);
            let cm1 = b.sub(c, one);
            let k = b.select(c0, z, cm1);
            let raw = bitk(b, d, k);
            let cle = b.cmp(Cmp::LeU, c, wk);
            let cmid = b.select(cle, raw, z);
            let cout = b.select(c0, z, cmid);
            let xo = b.select(c0, xin, cout);
            (r, cout, z, xo)
        }
        (ShOp::Ls, false) | (ShOp::As, false) => {
            // lsl/asl: c>=wb なら 0。C = bit(wb-c)（1<=c<=wb）。
            let s = b.shl(d, c);
            let r0 = mask(b, s, size);
            let r = b.select(cbig, z, r0);
            let wmc = b.sub(wk, c);
            let raw = bitk(b, d, wmc);
            let cle = b.cmp(Cmp::LeU, c, wk);
            let cmid = b.select(cle, raw, z);
            let cout = b.select(c0, z, cmid);
            let xo = b.select(c0, xin, cout);
            // asl の V はシフト中に MSB が変化すれば 1。
            // c<wb: 上位 c+1 ビットが全部同じでなければ 1。
            // c>=wb: d != 0。
            let v = if let ShOp::As = op {
                let w1 = b.konst::<W32>(wb - 1);
                let k = b.sub(w1, c);
                let seg = b.shr_l(d, k);
                let cp1 = b.add(c, one);
                // cp1=wb のとき shl が overshift → 0 の契約に乗る
                //（interp/JIT とも「幅以上→0」）。その場合 smask は
                // 全 1 となり seg との比較は正しい。
                let m1 = b.shl(one, cp1);
                let smask = b.sub(m1, one);
                let p0 = b.cmp(Cmp::Ne, seg, z);
                let p1 = b.cmp(Cmp::Ne, seg, smask);
                let b0 = bit_of(b, p0);
                let b1 = bit_of(b, p1);
                let vs = b.and(b0, b1);
                let pd = b.cmp(Cmp::Ne, d, z);
                let v2 = bit_of(b, pd);
                let vv = b.select(cbig, v2, vs);
                b.select(c0, z, vv)
            } else {
                z
            };
            (r, cout, v, xo)
        }
        (ShOp::As, true) => {
            // asr: 符号複製。c>=wb でも全符号ビットで埋まる。
            let w64s = b.konst::<W64>(u64::from(64 - wb));
            let d64 = b.zext::<W32, W64>(d);
            let t = b.shl(d64, w64s);
            let ds = b.shr_a(t, w64s);
            let c64 = b.zext::<W32, W64>(c);
            let ra = b.shr_a(ds, c64);
            let r32 = b.trunc::<W64, W32>(ra);
            let r = mask(b, r32, size);
            // C = bit(min(c,wb)-1)（c>=1）。c>wb は符号ビット。
            let cmid = b.select(cbig, wk, c);
            let cm1 = b.sub(cmid, one);
            let k = b.select(c0, z, cm1);
            let raw = bitk(b, d, k);
            let cout = b.select(c0, z, raw);
            let xo = b.select(c0, xin, cout);
            (r, cout, z, xo)
        }
        (ShOp::Rox, _) => {
            // rox: {X, d} の wb+1 ビット鎖を W64 で回す。
            let wb1 = wb + 1;
            let wk64 = b.konst::<W64>(u64::from(wb));
            let w64k = b.konst::<W64>(u64::from(wb1));
            let mm = b.konst::<W64>((1u64 << wb1) - 1);
            let d64 = b.zext::<W32, W64>(d);
            let x64 = b.zext::<W32, W64>(xin);
            let xs = b.shl(x64, wk64);
            let comb = b.or(xs, d64);
            let c64 = b.zext::<W32, W64>(c);
            let e = b.urem(c64, w64k);
            let r64 = if right {
                let lo = b.shr_l(comb, e);
                let bk = b.sub(w64k, e);
                let hi = b.shl(comb, bk);
                let him = b.and(hi, mm);
                b.or(lo, him)
            } else {
                let hi0 = b.shl(comb, e);
                let him = b.and(hi0, mm);
                let bk = b.sub(w64k, e);
                let lo = b.shr_l(comb, bk);
                b.or(him, lo)
            };
            let r32 = b.trunc::<W64, W32>(r64);
            let r = mask(b, r32, size);
            let xs2 = b.shr_l(r64, wk64);
            let xo32 = b.trunc::<W64, W32>(xs2);
            let xo = b.and(xo32, one);
            // ROXx は c=0 でも C=X（= xin と同値）。
            (r, xo, z, xo)
        }
        (ShOp::Ro, _) => {
            // rol/ror: wb ビット回転。e = c mod wb。
            let e = b.urem(c, wk);
            let e0 = b.cmp(Cmp::Eq, e, z);
            let bk = b.sub(wk, e);
            let r = if right {
                let lo = b.shr_l(d, e);
                let hi0 = b.shl(d, bk);
                let him = mask(b, hi0, size);
                let hi = b.select(e0, z, him);
                let t = b.or(lo, hi);
                mask(b, t, size)
            } else {
                let hi0 = b.shl(d, e);
                let hi = mask(b, hi0, size);
                let lo0 = b.shr_l(d, bk);
                let lo = b.select(e0, z, lo0);
                let t = b.or(hi, lo);
                mask(b, t, size)
            };
            // C = c>0 なら最後に出たビット（ror は結果 MSB、rol は結果 bit0）。
            let k = if right {
                b.konst::<W32>(wb - 1)
            } else {
                b.konst::<W32>(0)
            };
            let mb = bitk(b, r, k);
            let cout = b.select(c0, z, mb);
            (r, cout, z, xin)
        }
    }
}

/// レジスタシフト。カウントは imm（0 は 8）または Dn mod 64。
// Ref: SPEC-M68K-PRM (Rev 1) §ASx/LSx/ROXx/ROx.
fn shift_reg<B: Backend>(b: &mut B, w: u64, _pc: u64, op: ShOp, right: bool) -> Flow<B> {
    // qsz=3 はメモリ形の空間で、デコード側で排他済み。
    debug_assert!(ea::qsz(w) != 3);
    let size = 1u32 << ea::qsz(w);
    let n = ea::ea_reg(w);
    let cn = ea::dest_reg(w);
    let c = if (w >> 5) & 1 == 0 {
        let k = if cn == 0 { 8 } else { u32::from(cn) };
        b.konst::<W32>(k)
    } else {
        let v = b.get(D(cn).state());
        let m = b.konst::<W32>(63);
        b.and(v, m)
    };
    let d0 = b.get(D(n).state());
    let d = mask(b, d0, size);
    let xin = read_x(b);
    let (r, co, vo, xo) = shift_core(b, d, c, size, op, right, xin);
    set_shift_flags(b, r, size, co, vo, xo);
    write_ea(b, &Ea::D(n), size, r)
}

/// メモリシフト。word サイズ・カウント 1 固定。EA はメモリ alterable
/// のみ（Dn/An 直・PC 相対・即値は illegal）。
// Ref: SPEC-M68K-PRM (Rev 1) §ASx/LSx/ROXx/ROx.
fn shift_mem<B: Backend>(b: &mut B, w: u64, pc: u64, op: ShOp, right: bool) -> Flow<B> {
    let emode = ea::ea_mode(w);
    let ereg = ea::ea_reg(w);
    if emode < 2 || (emode == 7 && ereg >= 2) {
        return Err(illegal(b));
    }
    let (e, _n) = ea::eval(b, emode, ereg, 2, pc + 2)?;
    let d = read_ea(b, &e, 2)?;
    let c = b.konst::<W32>(1);
    let xin = read_x(b);
    let (r, co, vo, xo) = shift_core(b, d, c, 2, op, right, xin);
    set_shift_flags(b, r, 2, co, vo, xo);
    write_ea(b, &e, 2, r)
}

/// ビット操作の演算種別。
enum BitOp {
    /// btst（読み取りのみ、PC 相対・即値 EA も許可）。
    Tst,
    /// bchg。
    Chg,
    /// bclr。
    Clr,
    /// bset。
    Set,
}

/// btst/bchg/bclr/bset。Dn 宛は 32 ビット、メモリはバイト。
/// ビット番号は imm 形が拡張語、reg 形が Dn（それぞれ mod wb）。
/// Z = テストしたビットの否定。他の旗は不変。
// Ref: SPEC-M68K-PRM (Rev 1) §BTST/BCHG/BCLR/BSET.
fn bit_op<B: Backend>(b: &mut B, w: u64, pc: u64, op: BitOp, imm_form: bool) -> Flow<B> {
    let emode = ea::ea_mode(w);
    let ereg = ea::ea_reg(w);
    // An は不可（reg 形は MOVEP 空間として宣言で排他済みだが、
    // imm 形は実行時に弾く）。
    if emode == 1 {
        return Err(illegal(b));
    }
    let write = !matches!(op, BitOp::Tst);
    // emode 7: btst は #imm（reg4）まで可、書き込み系は abs.l（reg1）まで。
    let lim = if write { 1 } else { 4 };
    if emode == 7 && ereg > lim {
        return Err(illegal(b));
    }
    let dsz = if emode == 0 { 4 } else { 1 };
    let ea_pc;
    let n = if imm_form {
        // ビット番号は 16 ビット拡張語。
        let (e, ni) = ea::eval(b, 7, 4, 2, pc + 2)?;
        ea_pc = pc + 2 + u64::from(ni) * 2;
        match e {
            Ea::Imm(v) => v,
            _ => unreachable!("mode7 reg4 は Imm"),
        }
    } else {
        ea_pc = pc + 2;
        b.get(D(ea::dest_reg(w)).state())
    };
    let (e, _n) = ea::eval(b, emode, ereg, dsz, ea_pc)?;
    let d = read_ea(b, &e, dsz)?;
    let one = b.konst::<W32>(1);
    let mk = b.konst::<W32>(if emode == 0 { 31 } else { 7 });
    let bn = b.and(n, mk);
    let s = b.shr_l(d, bn);
    let bit = b.and(s, one);
    // Z = !bit。
    let nb = b.xor(bit, one);
    let k2 = b.konst::<W32>(2);
    let nbs = b.shl(nb, k2);
    let ccr8 = b.get(ccr_ref());
    let km = b.konst::<W8>(0xFB);
    let keep = b.and(ccr8, km);
    let nb8 = b.trunc::<W32, W8>(nbs);
    let out = b.or(keep, nb8);
    b.set(ccr_ref(), out);
    if !write {
        return Ok(());
    }
    let bm = b.shl(one, bn);
    let r = match op {
        BitOp::Chg => b.xor(d, bm),
        BitOp::Clr => {
            let nm = b.not(bm);
            b.and(d, nm)
        }
        BitOp::Set => b.or(d, bm),
        BitOp::Tst => unreachable!(),
    };
    write_ea(b, &e, dsz, r)
}

/// 変位の評価。disp8=0 は 16bit 拡張語、それ以外は sext8
///（0xFF は byte 変位 -1。32bit 変位は 020 以降の仕様）。
/// 戻り値は (符号付き変位, 消費拡張語数)。
// Ref: SPEC-M68K-PRM (Rev 1) §BRA/BSR/Bcc.
fn disp_val<B: Backend>(b: &mut B, w: u64, pc: u64) -> Result<(B::V<W32>, u32), B::Exit> {
    let d8 = (w & 0xFF) as u8;
    if d8 == 0 {
        let (e, ni) = ea::eval(b, 7, 4, 2, pc + 2)?;
        let v = match e {
            Ea::Imm(v) => v,
            _ => unreachable!("mode7 reg4 は Imm"),
        };
        // 符号拡張は W32 内で 16 ビット左→算術右。
        let k = b.konst::<W32>(16);
        let s = b.shl(v, k);
        let sv = b.shr_a(s, k);
        Ok((sv, ni))
    } else if d8 == 0xFF && b.param::<super::Bdisp32Param>() {
        // 68020+: 32 ビット変位（2 拡張語）。
        let (e, ni) = ea::eval(b, 7, 4, 4, pc + 2)?;
        let v = match e {
            Ea::Imm(v) => v,
            _ => unreachable!("mode7 reg4 は Imm"),
        };
        Ok((v, ni))
    } else {
        let sv = b.konst::<W32>((d8 as i8) as i32 as u32);
        Ok((sv, 0))
    }
}

/// 条件評価。cc=0/1 は T/F（常に真/偽）、2..15 は C/V/Z/N の論理合成。
// Ref: SPEC-M68K-PRM (Rev 1) §Condition Code Computation.
fn cond_eval<B: Backend>(b: &mut B, cc: u8) -> B::B {
    // bcc では 2..=15、scc/dbcc では 0（T=真）と 1（F=偽）も来る。
    if cc < 2 {
        // cc=0 は常に真、cc=1 は常に偽。
        let c = b.konst::<W32>(u32::from(1 - cc));
        let z = b.konst::<W32>(0);
        return b.cmp(Cmp::Ne, c, z);
    }
    let ccr = b.get(ccr_ref());
    let c32 = b.zext::<W8, W32>(ccr);
    let one = b.konst::<W32>(1);
    let bit = |b: &mut B, k: u32| {
        let kk = b.konst::<W32>(k);
        let s = b.shr_l(c32, kk);
        b.and(s, one)
    };
    let c0 = bit(b, sr_bit::C);
    let v1 = bit(b, sr_bit::V);
    let z2 = bit(b, sr_bit::Z);
    let n3 = bit(b, sr_bit::N);
    let nc = b.xor(c0, one);
    let nv = b.xor(v1, one);
    let nz = b.xor(z2, one);
    let nn = b.xor(n3, one);
    // n==v は n^v の否定。
    let nxv = b.xor(n3, v1);
    let eqnv = b.xor(nxv, one);
    let cv = match cc {
        2 => b.and(nc, nz),    // hi: !c && !z
        3 => b.or(c0, z2),     // ls: c || z
        4 => nc,               // cc/hs: !c
        5 => c0,               // cs/lo: c
        6 => nz,               // ne
        7 => z2,               // eq
        8 => nv,               // vc
        9 => v1,               // vs
        10 => nn,              // pl
        11 => n3,              // mi
        12 => eqnv,            // ge: n==v
        13 => nxv,             // lt: n!=v
        14 => b.and(eqnv, nz), // gt: n==v && !z
        _ => b.or(z2, nxv),    // le: z || n!=v
    };
    let zero = b.konst::<W32>(0);
    b.cmp(Cmp::Ne, cv, zero)
}

/// スタックに long を積む（A7 先行デクリメント）。
fn push_l<B: Backend>(b: &mut B, v: B::V<W32>) -> Flow<B> {
    let sp0 = areg(b, 7);
    let k4 = b.konst::<W32>(4);
    let sp = b.sub(sp0, k4);
    let v64 = b.zext::<W32, W64>(v);
    // 68000 の long 書き込みは word アクセス×2。
    let s16 = b.konst::<W64>(16);
    let hi64 = b.shr_l(v64, s16);
    let hi = b.trunc::<W64, W16>(hi64);
    let lo = b.trunc::<W64, W16>(v64);
    let sp64 = b.zext::<W32, W64>(sp);
    let __da0 = dwr(b);
    b.store::<W16>(sp64, hi, __da0)?;
    let two = b.konst::<W64>(2);
    let a2 = b.add(sp64, two);
    let __da0 = dwr(b);
    b.store::<W16>(a2, lo, __da0)?;
    set_areg(b, 7, sp)
}

/// スタックから `size` バイト（2 or 4）を取る。4 は word×2。
fn pop<B: Backend>(b: &mut B, size: u32) -> Result<B::V<W32>, B::Exit> {
    let sp0 = areg(b, 7);
    let sp64 = b.zext::<W32, W64>(sp0);
    let v = if size == 2 {
        let __da0 = drd(b);
        let w16 = b.load::<W16>(sp64, __da0)?;
        b.zext::<W16, W32>(w16)
    } else {
        let __da0 = drd(b);
        let hi = b.load::<W16>(sp64, __da0)?;
        let two = b.konst::<W64>(2);
        let a2 = b.add(sp64, two);
        let __da0 = drd(b);
        let lo = b.load::<W16>(a2, __da0)?;
        let hi32 = b.zext::<W16, W32>(hi);
        let lo32 = b.zext::<W16, W32>(lo);
        let s = b.konst::<W32>(16);
        let h = b.shl(hi32, s);
        b.or(h, lo32)
    };
    let kn = b.konst::<W32>(size);
    let sp = b.add(sp0, kn);
    set_areg(b, 7, sp)?;
    Ok(v)
}

/// bra/bsr/bcc。分岐先は pc+2+変位（32bit 折り返し）。
/// bsr は戻りアドレス（命令の次）を push してから飛ぶ。
// Ref: SPEC-M68K-PRM (Rev 1) §BRA/BSR/Bcc.
fn branch_rel<B: Backend>(b: &mut B, w: u64, pc: u64, cc: Option<u8>, link: bool) -> Flow<B> {
    let (dv, ni) = disp_val(b, w, pc)?;
    let base = b.konst::<W32>(pc.wrapping_add(2) as u32);
    let t32 = b.add(base, dv);
    let t64 = b.zext::<W32, W64>(t32);
    if link {
        let ret = b.konst::<W32>(pc.wrapping_add(2 + u64::from(ni) * 2) as u32);
        push_l(b, ret)?;
    }
    if let Some(cc) = cc {
        let c = cond_eval(b, cc);
        b.if_then_else(
            c,
            |bb| {
                bb.jump(t64);
                Ok(())
            },
            |_| Ok(()),
        )
    } else {
        b.jump(t64);
        Ok(())
    }
}

/// jmp/jsr。EA は制御モードのみ（indirect/disp/絶対/PC 相対）。
// Ref: SPEC-M68K-PRM (Rev 1) §JMP/JSR.
fn jmp_jsr<B: Backend>(b: &mut B, w: u64, pc: u64, link: bool) -> Flow<B> {
    let emode = ea::ea_mode(w);
    let ereg = ea::ea_reg(w);
    let ctrl = emode == 2 || emode == 5 || emode == 6 || (emode == 7 && ereg <= 3);
    if !ctrl {
        return Err(illegal(b));
    }
    let extv = b.konst::<W64>(pc + 2);
    let (e, _ni, cnt) = ea::eval_full_v(b, emode, ereg, 4, extv)?;
    let a = match e {
        Ea::Addr(a) => a,
        _ => unreachable!("制御 EA は Addr"),
    };
    if link {
        // リンク先は命令末尾。full 形式 EA で語数が動的なので
        // シンボリック語数から求める。
        let two = b.konst::<W32>(2);
        let nbytes = b.mul(cnt, two);
        let base = b.konst::<W32>((pc + 2) as u32);
        let ret = b.add(base, nbytes);
        push_l(b, ret)?;
    }
    b.jump(a);
    Ok(())
}

/// rts。(SP)+ の long を PC へ。
// Ref: SPEC-M68K-PRM (Rev 1) §RTS.
fn rts<B: Backend>(b: &mut B) -> Flow<B> {
    let v = pop(b, 4)?;
    let v64 = b.zext::<W32, W64>(v);
    b.jump(v64);
    Ok(())
}

/// rtr。(SP)+ の word を CCR へ、続く long を PC へ。
// Ref: SPEC-M68K-PRM (Rev 1) §RTR.
fn rtr<B: Backend>(b: &mut B) -> Flow<B> {
    let cc = pop(b, 2)?;
    let cc8 = b.trunc::<W32, W8>(cc);
    // CCR は 5 ビットのみ実装。スタックの上位 3 ビットは捨てる。
    let m = b.konst::<W8>(0x1F);
    let v = b.and(cc8, m);
    b.set(ccr_ref(), v);
    let v = pop(b, 4)?;
    let v64 = b.zext::<W32, W64>(v);
    b.jump(v64);
    Ok(())
}

/// scc。条件が真なら EA byte=0xFF、偽なら 0x00。旗不変。
/// EA は data alterable（emode=1 は dbcc 空間として decode で排他済み）。
// Ref: SPEC-M68K-PRM (Rev 1) §Scc.
fn scc<B: Backend>(b: &mut B, w: u64, pc: u64) -> Flow<B> {
    let emode = ea::ea_mode(w);
    let ereg = ea::ea_reg(w);
    debug_assert!(emode != 1);
    if emode == 7 && ereg >= 2 {
        return Err(illegal(b));
    }
    let (e, _n) = ea::eval(b, emode, ereg, 1, pc + 2)?;
    let c = cond_eval(b, ((w >> 8) & 0xF) as u8);
    let ff = b.konst::<W32>(0xFF);
    let zz = b.konst::<W32>(0);
    let v = b.select(c, ff, zz);
    write_ea(b, &e, 1, v)
}

/// dbcc。条件が真なら何もしない。偽なら Dn の下位 word を 1 減らし、
/// 結果が 0xFFFF でなければ pc+2+disp16 へ分岐する。
// Ref: SPEC-M68K-PRM (Rev 1) §DBcc.
fn dbcc<B: Backend>(b: &mut B, w: u64, pc: u64) -> Flow<B> {
    let rn = ea::ea_reg(w);
    let (e, _i) = ea::eval(b, 7, 4, 2, pc + 2)?;
    let v = match e {
        Ea::Imm(v) => v,
        _ => unreachable!("mode7 reg4 は Imm"),
    };
    let k = b.konst::<W32>(16);
    let s = b.shl(v, k);
    let disp = b.shr_a(s, k);
    let c = cond_eval(b, ((w >> 8) & 0xF) as u8);
    let base = b.konst::<W32>(pc.wrapping_add(2) as u32);
    let t32 = b.add(base, disp);
    let t64 = b.zext::<W32, W64>(t32);
    b.if_then_else(
        c,
        |_| Ok(()),
        |bb| {
            let d = bb.get(D(rn).state());
            let mk = bb.konst::<W32>(0xFFFF);
            let hik = bb.konst::<W32>(0xFFFF_0000);
            let hi = bb.and(d, hik);
            let lo = bb.and(d, mk);
            let one = bb.konst::<W32>(1);
            let lm1 = bb.sub(lo, one);
            let lo1 = bb.and(lm1, mk);
            let d2 = bb.or(hi, lo1);
            bb.set(D(rn).state(), d2);
            let not_ff = bb.cmp(Cmp::Ne, lo1, mk);
            bb.if_then_else(
                not_ff,
                |bbb| {
                    bbb.jump(t64);
                    Ok(())
                },
                |_| Ok(()),
            )
        },
    )
}

/// C8: 制御 EA（jmp/jsr と同じ集合）のアドレスを評価する。
fn ctrl_ea<B: Backend>(b: &mut B, w: u64, pc: u64) -> Result<B::V<W64>, B::Exit> {
    let emode = ea::ea_mode(w);
    let ereg = ea::ea_reg(w);
    if !(emode == 2 || emode == 5 || emode == 6 || (emode == 7 && ereg <= 3)) {
        return Err(illegal(b));
    }
    let (e, _n) = ea::eval(b, emode, ereg, 4, pc + 2)?;
    match e {
        Ea::Addr(a) => Ok(a),
        _ => unreachable!("制御 EA は Addr"),
    }
}

/// lea。制御 EA のアドレスを An へ。旗不変。
// Ref: SPEC-M68K-PRM (Rev 1) §LEA.
fn lea<B: Backend>(b: &mut B, w: u64, pc: u64) -> Flow<B> {
    let a = ctrl_ea(b, w, pc)?;
    let a32 = b.trunc::<W64, W32>(a);
    set_areg(b, ea::dest_reg(w), a32)
}

/// pea。制御 EA のアドレスを long で push する。
// Ref: SPEC-M68K-PRM (Rev 1) §PEA.
fn pea<B: Backend>(b: &mut B, w: u64, pc: u64) -> Flow<B> {
    let a = ctrl_ea(b, w, pc)?;
    let a32 = b.trunc::<W64, W32>(a);
    push_l(b, a32)
}

/// link An,#d16: SP-=4; [SP]=An; An=SP; SP+=d16（符号付き）。
// Ref: SPEC-M68K-PRM (Rev 1) §LINK.
fn link<B: Backend>(b: &mut B, w: u64, pc: u64) -> Flow<B> {
    let (e, _i) = ea::eval(b, 7, 4, 2, pc + 2)?;
    let v = match e {
        Ea::Imm(v) => v,
        _ => unreachable!("mode7 reg4 は Imm"),
    };
    let rn = ea::ea_reg(w);
    let an = areg(b, rn);
    push_l(b, an)?;
    let sp = areg(b, 7);
    set_areg(b, rn, sp)?;
    let k = b.konst::<W32>(16);
    let sv = b.shl(v, k);
    let d = b.shr_a(sv, k);
    let sp2 = b.add(sp, d);
    set_areg(b, 7, sp2)
}

/// unlk An: SP=An; An=[SP]+。rn=7 は最後の書き込み（pop 値）が残る。
// Ref: SPEC-M68K-PRM (Rev 1) §UNLK.
fn unlk<B: Backend>(b: &mut B, w: u64, _pc: u64) -> Flow<B> {
    let rn = ea::ea_reg(w);
    let an = areg(b, rn);
    set_areg(b, 7, an)?;
    let v = pop(b, 4)?;
    set_areg(b, rn, v)
}

/// C9: exg。32 ビット全体を交換する。旗不変。
// Ref: SPEC-M68K-PRM (Rev 1) §EXG.
fn exg<B: Backend>(b: &mut B, w: u64, src_is_a: bool, dst_is_a: bool) -> Flow<B> {
    let rn = ea::ea_reg(w);
    let dn = ea::dest_reg(w);
    let (sx, dx) = if src_is_a && dst_is_a {
        (areg(b, dn), areg(b, rn))
    } else if dst_is_a {
        (b.get(D(dn).state()), areg(b, rn))
    } else {
        (b.get(D(dn).state()), b.get(D(rn).state()))
    };
    if src_is_a {
        set_areg(b, dn, dx)?;
    } else {
        b.set(D(dn).state(), dx);
    }
    if dst_is_a {
        set_areg(b, rn, sx)
    } else {
        b.set(D(rn).state(), sx);
        Ok(())
    }
}

/// swap Dn。上位 word と下位 word を交換。N/Z 更新・V/C 0・X 不変。
// Ref: SPEC-M68K-PRM (Rev 1) §SWAP.
fn swap_<B: Backend>(b: &mut B, w: u64) -> Flow<B> {
    let rn = ea::ea_reg(w);
    let d = b.get(D(rn).state());
    let k = b.konst::<W32>(16);
    let hi = b.shl(d, k);
    let lo = b.shr_l(d, k);
    let r = b.or(hi, lo);
    b.set(D(rn).state(), r);
    set_nzvc(b, r, 4);
    Ok(())
}

/// ext.w/ext.l。byte→word / word→long の符号拡張。
/// ext.w は上位 word を保持する。N/Z 更新・V/C 0・X 不変。
// Ref: SPEC-M68K-PRM (Rev 1) §EXT.
fn ext_<B: Backend>(b: &mut B, w: u64, long: bool) -> Flow<B> {
    let rn = ea::ea_reg(w);
    let d = b.get(D(rn).state());
    let r = if long {
        let lo = b.trunc::<W32, W16>(d);
        b.sext::<W16, W32>(lo)
    } else {
        let lo = b.trunc::<W32, W8>(d);
        let sw = b.sext::<W8, W16>(lo);
        let zw = b.zext::<W16, W32>(sw);
        let mk = b.konst::<W32>(0xFFFF_0000);
        let hi = b.and(d, mk);
        b.or(hi, zw)
    };
    b.set(D(rn).state(), r);
    set_nzvc(b, r, if long { 4 } else { 2 });
    Ok(())
}

/// マスクビット i に対応するレジスタ値（i<8 なら D、8-15 なら A）。
fn mask_reg<B: Backend>(b: &mut B, i: u8) -> B::V<W32> {
    if i < 8 {
        b.get(D(i).state())
    } else {
        areg(b, i - 8)
    }
}

/// マスクビット i に対応するレジスタへ書く。
fn set_mask_reg<B: Backend>(b: &mut B, i: u8, v: B::V<W32>) -> Flow<B> {
    if i < 8 {
        b.set(D(i).state(), v);
        Ok(())
    } else {
        set_areg(b, i - 8, v)
    }
}

/// 拡張語のレジスタマスクを読む（命令語の直後、EA 拡張語より先）。
fn movem_mask<B: Backend>(b: &mut B, pc: u64) -> Result<B::V<W32>, B::Exit> {
    let (e, _x) = ea::eval(b, 7, 4, 2, pc + 2)?;
    match e {
        Ea::Imm(v) => Ok(v),
        _ => unreachable!("mode7 reg4 は Imm"),
    }
}

/// C10: movem reg→mem。EA は (An),-(An),d16(An),d8(An,Xn),abs のみ。
/// -(An) ではマスクを反転解釈（bit0=A7…bit15=D0）し、1語ごとに
/// アドレスを減らしながら書く。終了時に An を更新する。旗不変。
// Ref: SPEC-M68K-PRM (Rev 1) §MOVEM.
fn movem_r2m<B: Backend>(b: &mut B, w: u64, pc: u64, size: u32) -> Flow<B> {
    let emode = ea::ea_mode(w);
    let ereg = ea::ea_reg(w);
    let legal = matches!(emode, 2 | 4 | 5 | 6) || (emode == 7 && ereg <= 1);
    if !legal {
        return Err(illegal(b));
    }
    // -(An) の EA 評価には An の自動デクリメント副作用があるが、
    // movem は転送全体を自前で進めるため副作用なしの mode2 で
    // 基底を読む（格納される An 自身の値も減算前のものになる）。
    let (e, _ni) = ea::eval(b, if emode == 4 { 2 } else { emode }, ereg, 4, pc + 4)?;
    let base = match e {
        Ea::Addr(a) => a,
        _ => unreachable!("memory EA は Addr"),
    };
    let mask = movem_mask(b, pc)?;
    // アドレス列を純演算で先に決め、ビットごとの probe で全範囲の
    // アクセス可否を確かめてから書き込む（例外一貫性規約）。
    let mut sets = Vec::with_capacity(16);
    let mut addrs = Vec::with_capacity(16);
    let mut addr = base;
    for i in 0..16u8 {
        let bit = b.konst::<W32>(1 << i);
        let bi = b.and(mask, bit);
        let z = b.konst::<W32>(0);
        let set = b.cmp(Cmp::Ne, bi, z);
        let sz = b.konst::<W64>(u64::from(size));
        let z64 = b.konst::<W64>(0);
        let dv = b.select(set, sz, z64);
        if emode == 4 {
            addr = b.sub(addr, dv);
            addrs.push(addr);
        } else {
            addrs.push(addr);
            addr = b.add(addr, dv);
        }
        sets.push(set);
    }
    for i in 0..16usize {
        b.if_then_else(
            sets[i],
            |bb| {
                let __da0 = dwr(bb);
                bb.probe(addrs[i], size, __da0)?;
                Ok(())
            },
            |_| Ok(()),
        )?;
    }
    for i in 0..16usize {
        let rn = if emode == 4 { 15 - i as u8 } else { i as u8 };
        // -(An) で基底の An がマスクに含まれるとき、68000/68010 は
        // 初期値を、68020 以降は初期値 - オペランドサイズを格納する
        // （movem_base パラメータ）。An の更新は転送後に行うため
        // mask_reg で読める値はどちらの世代でも初期値。
        // Ref: SPEC-M68K-PRM (Rev 1) §MOVEM.
        let rv = if emode == 4 && rn == ereg + 8 && b.param::<super::MovemBaseParam>() == 1 {
            let sz = b.konst::<W64>(u64::from(size));
            let v = b.sub(base, sz);
            b.trunc::<W64, W32>(v)
        } else {
            mask_reg(b, rn)
        };
        let a = addrs[i];
        b.if_then_else(
            sets[i],
            |bb| {
                if size == 2 {
                    let v = bb.trunc::<W32, W16>(rv);
                    let __da0 = dwr(bb);
                    bb.store::<W16>(a, v, __da0)
                } else {
                    let sh = bb.konst::<W32>(16);
                    let hi32 = bb.shr_l(rv, sh);
                    let hi = bb.trunc::<W32, W16>(hi32);
                    let __da0 = dwr(bb);
                    bb.store::<W16>(a, hi, __da0)?;
                    let lo = bb.trunc::<W32, W16>(rv);
                    let two = bb.konst::<W64>(2);
                    let a2 = bb.add(a, two);
                    let __da0 = dwr(bb);
                    bb.store::<W16>(a2, lo, __da0)
                }
            },
            |_| Ok(()),
        )?;
    }
    if emode == 4 {
        let a32 = b.trunc::<W64, W32>(addr);
        set_areg(b, ereg, a32)?;
    }
    Ok(())
}

/// C10: movem mem→reg。EA は (An),(An)+,d16,d8,abs,PC相対。
/// .w は word を符号拡張して格納する。(An)+ は終了時に An を更新。
// Ref: SPEC-M68K-PRM (Rev 1) §MOVEM.
fn movem_m2r<B: Backend>(b: &mut B, w: u64, pc: u64, size: u32) -> Flow<B> {
    let emode = ea::ea_mode(w);
    let ereg = ea::ea_reg(w);
    let legal = matches!(emode, 2 | 3 | 5 | 6) || (emode == 7 && ereg <= 3);
    if !legal {
        return Err(illegal(b));
    }
    // (An)+ も同じく自動インクリメントの副作用を避けて mode2 で読む。
    let (e, _ni) = ea::eval(b, if emode == 3 { 2 } else { emode }, ereg, 4, pc + 4)?;
    let base = match e {
        Ea::Addr(a) => a,
        _ => unreachable!("memory EA は Addr"),
    };
    let mask = movem_mask(b, pc)?;
    // ロードをすべて先に済ませてからレジスタを書く（例外一貫性規約）。
    let mut sets = Vec::with_capacity(16);
    let mut addrs = Vec::with_capacity(16);
    let mut addr = base;
    for i in 0..16u8 {
        let bit = b.konst::<W32>(1 << i);
        let bi = b.and(mask, bit);
        let z = b.konst::<W32>(0);
        let set = b.cmp(Cmp::Ne, bi, z);
        let sz = b.konst::<W64>(u64::from(size));
        let z64 = b.konst::<W64>(0);
        let dv = b.select(set, sz, z64);
        addrs.push(addr);
        sets.push(set);
        addr = b.add(addr, dv);
    }
    let zero = b.konst::<W32>(0);
    let mut vals = [zero; 16];
    for i in 0..16usize {
        let a = addrs[i];
        b.if_then_else(
            sets[i],
            |bb| {
                vals[i] = if size == 2 {
                    let __da0 = drd(bb);
                    let w16 = bb.load::<W16>(a, __da0)?;
                    bb.sext::<W16, W32>(w16)
                } else {
                    let __da0 = drd(bb);
                    let hi = bb.load::<W16>(a, __da0)?;
                    let two = bb.konst::<W64>(2);
                    let a2 = bb.add(a, two);
                    let __da0 = drd(bb);
                    let lo = bb.load::<W16>(a2, __da0)?;
                    let hi32 = bb.zext::<W16, W32>(hi);
                    let sh = bb.konst::<W32>(16);
                    let hs = bb.shl(hi32, sh);
                    let lo32 = bb.zext::<W16, W32>(lo);
                    bb.or(hs, lo32)
                };
                Ok(())
            },
            |_| Ok(()),
        )?;
    }
    for i in 0..16usize {
        let v = vals[i];
        b.if_then_else(sets[i], |bb| set_mask_reg(bb, i as u8, v), |_| Ok(()))?;
    }
    if emode == 3 {
        let a32 = b.trunc::<W64, W32>(addr);
        set_areg(b, ereg, a32)?;
    }
    Ok(())
}

/// C10: movep。交互 byte 転送（a+0,+2,+4,+6 の byte アクセス）。
/// .w は Dx の下位 word のみ、.l は全体。旗不変。
// Ref: SPEC-M68K-PRM (Rev 1) §MOVEP.
fn movep<B: Backend>(b: &mut B, w: u64, pc: u64, size: u32, mem_to_reg: bool) -> Flow<B> {
    let dx = ea::dest_reg(w);
    let ay = ea::ea_reg(w);
    let (e, _i) = ea::eval(b, 7, 4, 2, pc + 2)?;
    let dv = match e {
        Ea::Imm(v) => v,
        _ => unreachable!("mode7 reg4 は Imm"),
    };
    let k = b.konst::<W32>(16);
    let sv = b.shl(dv, k);
    let sd = b.shr_a(sv, k);
    let base = areg(b, ay);
    let ea32 = b.add(base, sd);
    let addr = b.zext::<W32, W64>(ea32);
    let d = b.get(D(dx).state());
    if mem_to_reg {
        let mut acc = if size == 2 {
            let mk = b.konst::<W32>(0xFFFF_0000);
            b.and(d, mk)
        } else {
            b.konst::<W32>(0)
        };
        for i in 0..size {
            let off = b.konst::<W64>(u64::from(i) * 2);
            let a = b.add(addr, off);
            let __da0 = drd(b);
            let byte = b.load::<W8>(a, __da0)?;
            let b32 = b.zext::<W8, W32>(byte);
            let sh = b.konst::<W32>((size - 1 - i) * 8);
            let part = b.shl(b32, sh);
            acc = b.or(acc, part);
        }
        b.set(D(dx).state(), acc);
        Ok(())
    } else {
        for i in 0..size {
            let sh = b.konst::<W32>((size - 1 - i) * 8);
            let v = b.shr_l(d, sh);
            let v8 = b.trunc::<W32, W8>(v);
            let off = b.konst::<W64>(u64::from(i) * 2);
            let a = b.add(addr, off);
            let __da0 = dwr(b);
            b.store::<W8>(a, v8, __da0)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum MulDiv {
    Mulu,
    Muls,
    Divu,
    Divs,
}

/// C11: 乗除算。source EA は data アドレッシング（An 直は illegal）。
/// divu は Dn.l ÷ ea.w → 商:下位 word・剰余:上位 word。商が 16 ビットに
/// 収まらなければ V=1 で Dn は変わらない。divs は符号付き同様。
/// 0 除算は例外ベクタ 5。N/Z は商に対して、V/C は演算規約どおり。
// Ref: SPEC-M68K-PRM (Rev 1) §MULU/MULS/DIVU/DIVS.
fn muldiv<B: Backend>(b: &mut B, w: u64, pc: u64, kind: MulDiv) -> Flow<B> {
    let emode = ea::ea_mode(w);
    let ereg = ea::ea_reg(w);
    if emode == 1 || (emode == 7 && ereg >= 5) {
        return Err(illegal(b));
    }
    let (e, _n) = ea::eval(b, emode, ereg, 2, pc + 2)?;
    let v = read_ea(b, &e, 2)?;
    let dn = ea::dest_reg(w);
    let d = b.get(D(dn).state());
    match kind {
        MulDiv::Mulu | MulDiv::Muls => {
            let p = match kind {
                MulDiv::Mulu => {
                    let mk = b.konst::<W32>(0xFFFF);
                    let dl = b.and(d, mk);
                    b.mul(dl, v)
                }
                _ => {
                    let d16 = b.trunc::<W32, W16>(d);
                    let v16 = b.trunc::<W32, W16>(v);
                    let ds = b.sext::<W16, W32>(d16);
                    let vs = b.sext::<W16, W32>(v16);
                    b.mul(ds, vs)
                }
            };
            b.set(D(dn).state(), p);
            set_nzvc(b, p, 4);
            Ok(())
        }
        MulDiv::Divu | MulDiv::Divs => {
            let z = b.konst::<W32>(0);
            let is0 = b.cmp(Cmp::Eq, v, z);
            b.if_then_else(
                is0,
                |bb| {
                    Err(bb.raise(GuestException {
                        kind: ExceptionKind::Trap,
                        // m68k 例外ベクタ 5（ゼロ除算）。
                        code: 5,
                        addr: None,
                        in_delay_slot: false,
                    }))
                },
                |bb| div_core(bb, d, v, dn, matches!(kind, MulDiv::Divs)),
            )
        }
    }
}

/// 除算本体（除数 0 以外）。商の範囲外なら V=1 で Dn を変えない。
fn div_core<B: Backend>(b: &mut B, d: B::V<W32>, v: B::V<W32>, dn: u8, signed: bool) -> Flow<B> {
    let (q, r) = if signed {
        let vs = {
            let v16 = b.trunc::<W32, W16>(v);
            b.sext::<W16, W32>(v16)
        };
        (b.sdiv(d, vs), b.srem(d, vs))
    } else {
        (b.udiv(d, v), b.urem(d, v))
    };
    // 商が符号付き/符号なし16ビットに収まるか。
    let ovf = if signed {
        let off = b.konst::<W32>(32768);
        let adj = b.add(q, off);
        let lim = b.konst::<W32>(65535);
        b.cmp(Cmp::GtU, adj, lim)
    } else {
        let lim = b.konst::<W32>(0xFFFF);
        b.cmp(Cmp::GtU, q, lim)
    };
    b.if_then_else(
        ovf,
        |bb| {
            // 68000 のオーバーフロー規約: V=1, N=1, Z=0, C=0
            // （Dn は変わらない）。
            let ccr = bb.get(ccr_ref());
            let km = bb.konst::<W8>((1 << sr_bit::X) | 0xE0);
            let keep = bb.and(ccr, km);
            let nv = bb.konst::<W8>((1 << sr_bit::N) | (1 << sr_bit::V));
            let out = bb.or(keep, nv);
            bb.set(ccr_ref(), out);
            Ok(())
        },
        |bb| {
            let sh = bb.konst::<W32>(16);
            let rs = bb.shl(r, sh);
            let qm = bb.konst::<W32>(0xFFFF);
            let ql = bb.and(q, qm);
            let res = bb.or(rs, ql);
            bb.set(D(dn).state(), res);
            set_nzvc(bb, ql, 2);
            Ok(())
        },
    )
}

/// X フラグの値（0/1）。
fn x_flag<B: Backend>(b: &mut B) -> B::V<W32> {
    let ccr = b.get(ccr_ref());
    let x8 = {
        let km = b.konst::<W8>(1 << sr_bit::X);
        b.and(ccr, km)
    };
    let x32 = b.zext::<W8, W32>(x8);
    let sh = b.konst::<W32>(4);
    b.shr_l(x32, sh)
}

/// BCD フラグ: X=C=十進キャリー、Z は累積（結果が0でなければクリア）、
/// N=結果の bit7、V は呼び出し側で算出した値。
fn bcd_flags<B: Backend>(b: &mut B, res8: B::V<W32>, c: B::B, v: B::B) {
    let ccr = b.get(ccr_ref());
    // 上位予約のみ保持（X も十進キャリーで上書き）。
    let km = b.konst::<W8>(0xE0);
    let keep = b.and(ccr, km);
    let msb = b.konst::<W32>(0x80);
    let np = b.and(res8, msb);
    let z32 = b.konst::<W32>(0);
    let is_n = b.cmp(Cmp::Ne, np, z32);
    let is_z = b.cmp(Cmp::Eq, res8, z32);
    let z8 = b.konst::<W8>(0);
    let nk = b.konst::<W8>(1 << sr_bit::N);
    let zk = b.konst::<W8>(1 << sr_bit::Z);
    let vk = b.konst::<W8>(1 << sr_bit::V);
    let xck = b.konst::<W8>((1 << sr_bit::X) | (1 << sr_bit::C));
    // Z は「旧 Z && 結果==0」の累積。値域で AND する。
    let zsel = b.select(is_z, zk, z8);
    let old_z = {
        let zmk = b.konst::<W8>(1 << sr_bit::Z);
        b.and(ccr, zmk)
    };
    let new_z = b.and(old_z, zsel);
    let n8 = b.select(is_n, nk, z8);
    let v8 = b.select(v, vk, z8);
    let xc8 = b.select(c, xck, z8);
    let nz = b.or(n8, new_z);
    let vx = b.or(v8, xc8);
    let fl = b.or(nz, vx);
    let out = b.or(keep, fl);
    b.set(ccr_ref(), out);
}

/// C12: abcd/sbcd のレジスタ形。byte 演算、Dn の上位は保持。
// Ref: SPEC-M68K-PRM (Rev 1) §ABCD/SBCD.
fn bcd_reg<B: Backend>(b: &mut B, w: u64, add: bool) -> Flow<B> {
    let dn = ea::dest_reg(w);
    let rn = ea::ea_reg(w);
    let src = {
        let v = b.get(D(rn).state());
        let m = b.konst::<W32>(0xFF);
        b.and(v, m)
    };
    let dst_full = b.get(D(dn).state());
    let dst = {
        let m = b.konst::<W32>(0xFF);
        b.and(dst_full, m)
    };
    let x = x_flag(b);
    let (res8, c, v) = if add {
        bcd_add(b, src, dst, x)
    } else {
        bcd_sub(b, dst, src, x)
    };
    let km = b.konst::<W32>(0xFFFF_FF00);
    let hi = b.and(dst_full, km);
    let nv = b.or(hi, res8);
    b.set(D(dn).state(), nv);
    bcd_flags(b, res8, c, v);
    Ok(())
}

/// C12: abcd/sbcd のメモリ形 -(Ay),-(Ax)。
/// Ay==Ax のとき評価順で2回デクリメントされる。
fn bcd_mem<B: Backend>(b: &mut B, w: u64, pc: u64, add: bool) -> Flow<B> {
    let ax = ea::dest_reg(w);
    let ay = ea::ea_reg(w);
    let (se, _n1) = ea::eval(b, 4, ay, 1, pc + 2)?;
    let src = read_ea(b, &se, 1)?;
    let (de, _n2) = ea::eval(b, 4, ax, 1, pc + 2)?;
    let dst = read_ea(b, &de, 1)?;
    let x = x_flag(b);
    let (res8, c, v) = if add {
        bcd_add(b, src, dst, x)
    } else {
        bcd_sub(b, dst, src, x)
    };
    write_ea(b, &de, 1, res8)?;
    bcd_flags(b, res8, c, v);
    Ok(())
}

/// C13: trapv。V 旗が立っていればベクタ 7。
// Ref: SPEC-M68K-PRM (Rev 1) §TRAPV.
fn trapv<B: Backend>(b: &mut B) -> Flow<B> {
    let sr = b.get(sr_ref());
    let vm = b.konst::<W32>(1 << sr_bit::V);
    let vb = b.and(sr, vm);
    let z = b.konst::<W32>(0);
    let has_v = b.cmp(Cmp::Ne, vb, z);
    b.if_then_else(
        has_v,
        |bb| {
            Err(bb.raise(GuestException {
                kind: ExceptionKind::Trap,
                code: 7,
                addr: None,
                in_delay_slot: false,
            }))
        },
        |_| Ok(()),
    )
}

/// 特権違反（ベクタ 8）を発生させる。
// Ref: SPEC-M68K-PRM (Rev 1) §Exception Processing.
fn privilege<B: Backend>(b: &mut B) -> B::Exit {
    b.raise(GuestException {
        kind: ExceptionKind::Trap,
        code: 8,
        addr: None,
        in_delay_slot: false,
    })
}

/// S 旗が立っているかを返す。
fn is_super<B: Backend>(b: &mut B) -> B::B {
    let sr = b.get(sr_ref());
    let sm = b.konst::<W32>(1 << sr_bit::S);
    let sb = b.and(sr, sm);
    let z = b.konst::<W32>(0);
    b.cmp(Cmp::Ne, sb, z)
}

/// C13: reset。特権命令。ユーザモードではベクタ 8。
/// S=1 では外部リセット線を下げるが、CPU 状態への影響はない。
// Ref: SPEC-M68K-PRM (Rev 1) §RESET.
fn reset<B: Backend>(b: &mut B) -> Flow<B> {
    let sup = is_super(b);
    b.if_then_else(sup, |_| Ok(()), |bb| Err(privilege(bb)))
}

/// C13: chk <ea>,Dn。Dn の下位 word を符号付きで上限と比較する。
/// Dn<0 なら N=1 でベクタ 6、Dn>上限なら N=0 でベクタ 6。
// Ref: SPEC-M68K-PRM (Rev 1) §CHK.
fn chk<B: Backend>(b: &mut B, w: u64, pc: u64) -> Flow<B> {
    let emode = ea::ea_mode(w);
    let ereg = ea::ea_reg(w);
    if emode == 1 {
        return Err(illegal(b));
    }
    let dn = ea::dest_reg(w);
    let (e, _n) = ea::eval(b, emode, ereg, 2, pc + 2)?;
    let ub16 = read_ea(b, &e, 2)?;
    let dw = {
        let v = b.get(D(dn).state());
        let m = b.konst::<W32>(0xFFFF);
        b.and(v, m)
    };
    let ubw = b.trunc::<W32, W16>(ub16);
    let ub = b.sext::<W16, W32>(ubw);
    let d16 = b.trunc::<W32, W16>(dw);
    let d = b.sext::<W16, W32>(d16);
    let z = b.konst::<W32>(0);
    let neg = b.cmp(Cmp::LtS, d, z);
    let over = b.cmp(Cmp::GtS, d, ub);
    // SST 実測: CHK は通過・トラップに関わらず NZVC=0 にし、
    // Dn<0 のときだけ N=1 になる（トラップ時に積まれる SR も
    // この値）。X のみ保持する。
    let ccr = b.get(ccr_ref());
    let xm = b.konst::<W8>(1 << sr_bit::X);
    let kept = b.and(ccr, xm);
    let nk = b.konst::<W8>(1 << sr_bit::N);
    let zw = b.konst::<W8>(0);
    let nbit = b.select(neg, nk, zw);
    let out = b.or(kept, nbit);
    b.set(ccr_ref(), out);
    b.if_then_else(
        neg,
        |bb| {
            Err(bb.raise(GuestException {
                kind: ExceptionKind::Trap,
                // m68k 例外ベクタ 6（CHK）。
                code: 6,
                addr: None,
                in_delay_slot: false,
            }))
        },
        |bb| {
            bb.if_then_else(
                over,
                |cb| {
                    Err(cb.raise(GuestException {
                        kind: ExceptionKind::Trap,
                        code: 6,
                        addr: None,
                        in_delay_slot: false,
                    }))
                },
                |_| Ok(()),
            )
        },
    )
}

/// C13: move <ea>,ccr。ソース byte の下位5ビットを CCR へ。
// Ref: SPEC-M68K-PRM (Rev 1) §MOVE to CCR.
fn mv2ccr<B: Backend>(b: &mut B, w: u64, pc: u64) -> Flow<B> {
    let emode = ea::ea_mode(w);
    let ereg = ea::ea_reg(w);
    if emode == 1 {
        return Err(illegal(b));
    }
    // 実機は word 読み（奇数 EA でアドレスエラー）。下位 byte のみ使う。
    let (e, _n) = ea::eval(b, emode, ereg, 2, pc + 2)?;
    let v = read_ea(b, &e, 2)?;
    let m = b.konst::<W32>(0x1F);
    let v5 = b.and(v, m);
    let ccr = b.get(ccr_ref());
    let km = b.konst::<W8>(0xE0);
    let keep = b.and(ccr, km);
    let v8 = b.trunc::<W32, W8>(v5);
    let out = b.or(keep, v8);
    b.set(ccr_ref(), out);
    Ok(())
}

/// C13: move <ea>,sr。特権命令。S=1 なら word を SR へ（実装ビットのみ）。
// Ref: SPEC-M68K-PRM (Rev 1) §MOVE to SR.
fn mv2sr<B: Backend>(b: &mut B, w: u64, pc: u64) -> Flow<B> {
    let emode = ea::ea_mode(w);
    let ereg = ea::ea_reg(w);
    // An 上限の illegal は特権検査より先（エミュレータ慣習の
    // デコード時判定に合わせる。実機の例外優先順位は SST 非検証）。
    if emode == 1 {
        return Err(illegal(b));
    }
    let sup = is_super(b);
    b.if_then_else(
        sup,
        |bb| {
            let (e, _n) = ea::eval(bb, emode, ereg, 2, pc + 2)?;
            let v = read_ea(bb, &e, 2)?;
            let m = bb.konst::<W32>(0xA71F);
            let out = bb.and(v, m);
            bb.set(sr_ref(), out);
            Ok(())
        },
        |bb| Err(privilege(bb)),
    )
}

/// C14: rte。特権命令。スタックから [sr][pc] を復元する。
/// 実装ビットのみ復元（0xA71F）。復元後の SR.S で A7 が切り替わる。
// Ref: SPEC-M68K-PRM (Rev 1) §RTE.
fn rte<B: Backend>(b: &mut B) -> Flow<B> {
    let sup = is_super(b);
    b.if_then_else(
        sup,
        |bb| {
            let ssp = bb.get(Ssp.state());
            let a = bb.zext::<W32, W64>(ssp);
            let __da0 = drd(bb);
            let sr16 = bb.load::<W16>(a, __da0)?;
            let two = bb.konst::<W64>(2);
            let a2 = bb.add(a, two);
            let __da0 = drd(bb);
            let phi = bb.load::<W16>(a2, __da0)?;
            let four = bb.konst::<W64>(4);
            let a4 = bb.add(a, four);
            let __da0 = drd(bb);
            let plo = bb.load::<W16>(a4, __da0)?;
            let six = bb.konst::<W32>(6);
            let ns = bb.add(ssp, six);
            bb.set(Ssp.state(), ns);
            let sr32 = bb.zext::<W16, W32>(sr16);
            let m = bb.konst::<W32>(0xA71F);
            let sr = bb.and(sr32, m);
            bb.set(sr_ref(), sr);
            let phi32 = bb.zext::<W16, W32>(phi);
            let sh = bb.konst::<W32>(16);
            let hi_sh = bb.shl(phi32, sh);
            let plo32 = bb.zext::<W16, W32>(plo);
            let pc = bb.or(hi_sh, plo32);
            let pc64 = bb.zext::<W32, W64>(pc);
            bb.jump(pc64);
            Ok(())
        },
        |bb| Err(privilege(bb)),
    )
}

/// C14: stop #imm。特権命令。即値語を SR に読み込み CPU を停止する。
/// 停止は pc を進めないことで表す（割り込みで目覚める経路は OS 層）。
// Ref: SPEC-M68K-PRM (Rev 1) §STOP.
fn stop<B: Backend>(b: &mut B, _w: u64, pc: u64) -> Flow<B> {
    let sup = is_super(b);
    b.if_then_else(
        sup,
        |bb| {
            let a = bb.konst::<W64>(pc + 2);
            let imm = bb.load::<W16>(a, ea::FETCH)?;
            let imm32 = bb.zext::<W16, W32>(imm);
            let m = bb.konst::<W32>(0xA71F);
            let out = bb.and(imm32, m);
            bb.set(sr_ref(), out);
            let h64 = bb.konst::<W64>(pc);
            bb.jump(h64);
            Ok(())
        },
        |bb| Err(privilege(bb)),
    )
}

/// C14: move usp,An / move An,usp。特権命令。`to_usp` なら An→USP。
/// An=7 は実行時の SR.S が選ぶ側（S=1 で来るので SSP）を指す。
// Ref: SPEC-M68K-PRM (Rev 1) §MOVE USP.
fn mvusp<B: Backend>(b: &mut B, w: u64, to_usp: bool) -> Flow<B> {
    let sup = is_super(b);
    b.if_then_else(
        sup,
        |bb| {
            let n = ea::ea_reg(w);
            if to_usp {
                let v = areg(bb, n);
                bb.set(Usp.state(), v);
            } else {
                let v = bb.get(Usp.state());
                set_areg(bb, n, v)?;
            }
            Ok(())
        },
        |bb| Err(privilege(bb)),
    )
}

/// 例外配送: 6 バイトフレーム [sr][pc hi][pc lo] を SSP に積み、
/// S=1/T=0 にしてベクタを読みハンドラへジャンプする。
/// `exec` が `Err(Trap)` で返したときドライバが呼ぶ。
/// 積み PC はベクタ番号で規則が分かれる:
///   5（ゼロ除算）/6（CHK）/7（TRAPV）/32-47（TRAP）→ 次命令先頭
///   4（illegal）/8（特権）/10-11（line）→ 命令自身の先頭
/// 上記以外のベクタ（trace=9・割り込み 24-31 等）も実機では次命令
/// 先頭だが、それらを発生させる経路はまだない。アドレスエラー
/// （14 バイトフレーム）は未接続。
// Ref: SPEC-M68K-PRM (Rev 1) §Exception Processing.
pub fn deliver<B: Backend>(b: &mut B, code: u32, head: u64, len: u64) -> Flow<B> {
    let stacked = if matches!(code, 5 | 6 | 7 | 32..=47) {
        head + len
    } else {
        head
    };
    let sr = b.get(sr_ref());
    let ssp = b.get(Ssp.state());
    let six = b.konst::<W32>(6);
    let ns = b.sub(ssp, six);
    let na = b.zext::<W32, W64>(ns);
    let sr16 = b.trunc::<W32, W16>(sr);
    let __da0 = dwr(b);
    b.store::<W16>(na, sr16, __da0)?;
    let sp64 = b.konst::<W64>(stacked);
    let sixteen = b.konst::<W64>(16);
    let phi64 = b.shr_l(sp64, sixteen);
    let phi = b.trunc::<W64, W16>(phi64);
    let two = b.konst::<W64>(2);
    let a2 = b.add(na, two);
    let __da0 = dwr(b);
    b.store::<W16>(a2, phi, __da0)?;
    let plo = b.trunc::<W64, W16>(sp64);
    let four = b.konst::<W64>(4);
    let a4 = b.add(na, four);
    let __da0 = dwr(b);
    b.store::<W16>(a4, plo, __da0)?;
    b.set(Ssp.state(), ns);
    // 例外エントリは S=1・T=0（フレームには配送前の sr を積んだ）。
    let tm = b.konst::<W32>(0xFFFF & !0x8000);
    let cleared = b.and(sr, tm);
    let sm = b.konst::<W32>(0x2000);
    let new_sr = b.or(cleared, sm);
    b.set(sr_ref(), new_sr);
    // ベクタ読み出し（code*4、68000 は word×2）。
    let vc = b.konst::<W64>(u64::from(code) * 4);
    let __da0 = drd(b);
    let vhi = b.load::<W16>(vc, __da0)?;
    let vc2 = b.add(vc, two);
    let __da0 = drd(b);
    let vlo = b.load::<W16>(vc2, __da0)?;
    let vhi32 = b.zext::<W16, W32>(vhi);
    let sh = b.konst::<W32>(16);
    let hi_sh = b.shl(vhi32, sh);
    let vlo32 = b.zext::<W16, W32>(vlo);
    let target = b.or(hi_sh, vlo32);
    let t64 = b.zext::<W32, W64>(target);
    b.jump(t64);
    Ok(())
}

/// C13: move sr,<ea>。68000 ではユーザでも可。実装ビットのみ書き出す。
// Ref: SPEC-M68K-PRM (Rev 1) §MOVE from SR.
fn mvfrsr<B: Backend>(b: &mut B, w: u64, pc: u64) -> Flow<B> {
    let emode = ea::ea_mode(w);
    let ereg = ea::ea_reg(w);
    if emode == 1 || (emode == 7 && ereg >= 2) {
        return Err(illegal(b));
    }
    // 68010 以降は特権命令（mvfrsr_priv）。68000 ではユーザでも読める。
    if b.param::<super::MvfrsrPrivParam>() {
        let sup = is_super(b);
        return b.if_then_else(sup, |bb| mvfrsr_move(bb, w, pc), |bb| Err(privilege(bb)));
    }
    mvfrsr_move(b, w, pc)
}

fn mvfrsr_move<B: Backend>(b: &mut B, w: u64, pc: u64) -> Flow<B> {
    let emode = ea::ea_mode(w);
    let ereg = ea::ea_reg(w);
    let sr = b.get(sr_ref());
    let m = b.konst::<W32>(0xA71F);
    let v = b.and(sr, m);
    let (e, _n) = ea::eval(b, emode, ereg, 2, pc + 2)?;
    write_ea(b, &e, 2, v)?;
    Ok(())
}

/// BCD 加算: src+dst+x の10進補正。戻り値は (結果 byte, キャリー, オーバーフロー)。
/// TODO(cpu-models): V の算出式は 68000 固有。68020+ では Param で切り替える。
/// 補正規則は SST (実機) で検証済み:
///   lo>9 → lo+=6、res>0x9F → +0x60 かつ C/X=1、V=(res & ~raw) & 0x80。
fn bcd_add<B: Backend>(
    b: &mut B,
    src: B::V<W32>,
    dst: B::V<W32>,
    x: B::V<W32>,
) -> (B::V<W32>, B::B, B::B) {
    let lm = b.konst::<W32>(0x0F);
    let sl = b.and(src, lm);
    let dl = b.and(dst, lm);
    let slx = b.add(sl, x);
    let lo = b.add(slx, dl);
    let nine = b.konst::<W32>(9);
    let lgt = b.cmp(Cmp::GtU, lo, nine);
    let six = b.konst::<W32>(6);
    let z = b.konst::<W32>(0);
    let adj = b.select(lgt, six, z);
    let lo2 = b.add(lo, adj);
    let hm = b.konst::<W32>(0xF0);
    let sh = b.and(src, hm);
    let dh = b.and(dst, hm);
    let t = b.add(sh, dh);
    let res = b.add(t, lo2);
    let n9f = b.konst::<W32>(0x9F);
    let c = b.cmp(Cmp::GtU, res, n9f);
    let c60 = b.konst::<W32>(0x60);
    let adj2 = b.select(c, c60, z);
    let res2 = b.add(res, adj2);
    let mm = b.konst::<W32>(0xFF);
    let res8 = b.and(res2, mm);
    // V = 補正後の bit7 が生和の bit7 と異なって立つ: res & ~raw & 0x80。
    let sx = b.add(src, x);
    let raw = {
        let t = b.add(sx, dst);
        b.and(t, mm)
    };
    let nraw = b.not(raw);
    let t2 = b.and(res8, nraw);
    let mk = b.konst::<W32>(0x80);
    let msb = b.and(t2, mk);
    let v = b.cmp(Cmp::Ne, msb, z);
    (res8, c, v)
}

/// BCD 減算: dst-src-x の10進補正。戻り値は (結果 byte, キャリー, オーバーフロー)。
/// TODO(cpu-models): V の算出式は 68000 固有。68020+ では Param で切り替える。
/// 補正規則は SST (実機) で検証済み:
///   bc=(dst^src^res)&0x110 の bit4 で -6、bit8 で -0x60、
///   C/X = 補正後 res<0、V=(~res & raw) & 0x80。
fn bcd_sub<B: Backend>(
    b: &mut B,
    dst: B::V<W32>,
    src: B::V<W32>,
    x: B::V<W32>,
) -> (B::V<W32>, B::B, B::B) {
    let dsx = b.sub(dst, x);
    let res0 = b.sub(dsx, src);
    let mm = b.konst::<W32>(0xFF);
    let raw = b.and(res0, mm);
    let m1ff = b.konst::<W32>(0x1FF);
    let res9 = b.and(res0, m1ff);
    let xs = b.xor(dst, src);
    let xf = b.xor(xs, res9);
    let m110 = b.konst::<W32>(0x110);
    let bc = b.and(xf, m110);
    let bm = b.konst::<W32>(0x10);
    let lb = b.and(bc, bm);
    let z = b.konst::<W32>(0);
    let bor = b.cmp(Cmp::Ne, lb, z);
    let six = b.konst::<W32>(6);
    let adj = b.select(bor, six, z);
    let res = b.sub(res0, adj);
    let hm = b.konst::<W32>(0x100);
    let hb = b.and(bc, hm);
    let hbz = b.cmp(Cmp::Ne, hb, z);
    let c60 = b.konst::<W32>(0x60);
    let adj2 = b.select(hbz, c60, z);
    let res2 = b.sub(res, adj2);
    let c = b.cmp(Cmp::LtS, res2, z);
    let res8 = b.and(res2, mm);
    // V = 補正後の bit7 が下がり生差では立つ: ~res & raw & 0x80。
    let nres = b.not(res8);
    let t2 = b.and(nres, raw);
    let mk = b.konst::<W32>(0x80);
    let msb = b.and(t2, mk);
    let v = b.cmp(Cmp::Ne, msb, z);
    (res8, c, v)
}

/// C12: nbcd <ea>。0 - dst - X の10進補正。EA は data alterable。
// Ref: SPEC-M68K-PRM (Rev 1) §NBCD.
fn nbcd<B: Backend>(b: &mut B, w: u64, pc: u64) -> Flow<B> {
    let emode = ea::ea_mode(w);
    let ereg = ea::ea_reg(w);
    if emode == 1 || (emode == 7 && ereg >= 2) {
        return Err(illegal(b));
    }
    let (e, _n) = ea::eval(b, emode, ereg, 1, pc + 2)?;
    let dst = read_ea(b, &e, 1)?;
    let x = x_flag(b);
    let z = b.konst::<W32>(0);
    let (res8, c, v) = bcd_sub(b, z, dst, x);
    write_ea(b, &e, 1, res8)?;
    bcd_flags(b, res8, c, v);
    Ok(())
}

// ---- D2: 68020+ 追加分 ----

/// B 値の選択（select が V<W> のみを取るため W32 経由）。
fn bsel<B: Backend>(b: &mut B, c: B::B, t: B::B, f: B::B) -> B::B {
    let one = b.konst::<W32>(1);
    let zero = b.konst::<W32>(0);
    let tv = b.select(t, one, zero);
    let fv = b.select(f, one, zero);
    let v = b.select(c, tv, fv);
    b.cmp(Cmp::Ne, v, zero)
}

/// B 値の否定。
fn bnot<B: Backend>(b: &mut B, x: B::B) -> B::B {
    let one = b.konst::<W32>(1);
    let zero = b.konst::<W32>(0);
    let v = b.select(x, zero, one);
    b.cmp(Cmp::Ne, v, zero)
}

/// 条件付き副作用の糖衣（else なし）。
fn if_then<B: Backend, F: FnOnce(&mut B) -> Result<(), B::Exit>>(
    b: &mut B,
    c: B::B,
    f: F,
) -> Result<(), B::Exit> {
    b.if_then_else(c, f, |_bb| Ok(()))
}

/// neg/negx <ea>。0 - dst または 0 - dst - X。
/// NEG の C は dst≠0、NEGX の borrow は dst≠0 または X=1
/// （被減数 d|x ≠ 0）。Z は NEGX で累積、X は NEGX で C と同値。
// Ref: SPEC-M68K-PRM (Rev 1) §NEG/NEGX.
fn neg_<B: Backend>(b: &mut B, w: u64, pc: u64, with_x: bool) -> Flow<B> {
    let size = 1u32 << ea::qsz(w);
    let emode = ea::ea_mode(w);
    let ereg = ea::ea_reg(w);
    if emode == 1 || (emode == 7 && ereg >= 2) {
        return Err(illegal(b));
    }
    let (e, _n) = ea::eval(b, emode, ereg, size, pc + 2)?;
    let d = read_ea(b, &e, size)?;
    let m = b.konst::<W32>(size_mask(size));
    let dm = b.and(d, m);
    let x = if with_x { x_flag(b) } else { b.konst::<W32>(0) };
    let z = b.konst::<W32>(0);
    let r0 = b.sub(z, dm);
    let r = b.sub(r0, x);
    let rm = b.and(r, m);
    write_ea(b, &e, size, rm)?;
    // flags
    let sign = b.konst::<W32>(1u32 << (size * 8 - 1));
    let zero = b.konst::<W32>(0);
    // borrow: (d | x) != 0。d=0xFF.. で x=1 の境界でも borrow
    // が残る点に注意（masked 比較）。
    let dx = b.or(dm, x);
    let is_c = b.cmp(Cmp::Ne, dx, zero);
    let n_at = b.and(rm, sign);
    let is_n = b.cmp(Cmp::Ne, n_at, zero);
    let is_z = b.cmp(Cmp::Eq, rm, zero);
    // V: Dm ∧ Rm（オペランドと結果がともに最小負数）。negx では
    // X=1 のとき 0x7F.. から 0x80.. になり得るがそれは非溢出。
    let v_at = {
        let t = b.and(dm, rm);
        b.and(t, sign)
    };
    let is_v = b.cmp(Cmp::Ne, v_at, zero);
    let ccr = b.get(ccr_ref());
    let km0 = b.konst::<W8>(0xE0);
    let keep = b.and(ccr, km0);
    let nk = b.konst::<W8>(1 << sr_bit::N);
    let zk = b.konst::<W8>(1 << sr_bit::Z);
    let vk = b.konst::<W8>(1 << sr_bit::V);
    let ck = b.konst::<W8>(1 << sr_bit::C);
    let z8 = b.konst::<W8>(0);
    let n8 = b.select(is_n, nk, z8);
    let v8 = b.select(is_v, vk, z8);
    let c8 = b.select(is_c, ck, z8);
    // NEGX では Z は累積（結果非零ならクリア、零なら保持）。
    let zsel = if with_x { b.and(ccr, zk) } else { zk };
    let zf = b.select(is_z, zsel, z8);
    let nv = b.or(n8, v8);
    let nvc = b.or(nv, c8);
    let nvcz = b.or(nvc, zf);
    let out0 = b.or(keep, nvcz);
    // X は C と同値（NEGX のみ。NEG は X を保持）。
    let x8 = if with_x {
        let xk = b.konst::<W8>(1 << sr_bit::X);
        b.select(is_c, xk, z8)
    } else {
        let xk2 = b.konst::<W8>(1 << sr_bit::X);
        b.and(ccr, xk2)
    };
    let out = b.or(out0, x8);
    b.set(ccr_ref(), out);
    Ok(())
}

/// 拡張語の 3 ビットフィールド（シフト `sh`）を取り出す。
fn ext_reg<B: Backend>(b: &mut B, ext: B::V<W32>, sh: u32) -> B::V<W32> {
    let s = b.konst::<W32>(sh);
    let t = b.shr_l(ext, s);
    let m = b.konst::<W32>(7);
    b.and(t, m)
}

/// 拡張語のビット `sh` を B 値として取り出す。
fn ext_bit<B: Backend>(b: &mut B, ext: B::V<W32>, sh: u32) -> B::B {
    let s = b.konst::<W32>(sh);
    let t = b.shr_l(ext, s);
    let o = b.konst::<W32>(1);
    let b1 = b.and(t, o);
    let z = b.konst::<W32>(0);
    b.cmp(Cmp::Ne, b1, z)
}

/// ext の 3 ビット番号で Dn を読む。
fn get_dx<B: Backend>(b: &mut B, num: B::V<W32>) -> B::V<W32> {
    b.get_indexed(ea::d_array(), num)
}

/// mull（0x4C00 + ext）。32x32→32 または 64 ビット積。
/// ext[15:12]=Dl（積下位・32 ビット宛先）、ext[11]=符号、
/// ext[10]=64 ビット形式、ext[2:0]=Dh（積上位）。68020+。
// Ref: SPEC-M68K-PRM (Rev 1) §MULS.L/MULU.L.
fn mull<B: Backend>(b: &mut B, w: u64, pc: u64) -> Flow<B> {
    let emode = ea::ea_mode(w);
    let ereg = ea::ea_reg(w);
    // <ea> は data（An 直は不可。PC 相対・即値は可）。
    if emode == 1 || (emode == 7 && ereg >= 5) {
        return Err(illegal(b));
    }
    let ext = ea::ext_w16(b, pc + 2)?;
    let e32 = b.zext::<W16, W32>(ext);
    // ext[15:12]=Dl（積の下位・32 ビット形式の宛先）、
    // ext[2:0]=Dh（64 ビット積の上位）。
    let dl_n = ext_reg(b, e32, 12);
    let dh_n = ext_reg(b, e32, 0);
    let is_signed = ext_bit(b, e32, 11);
    let is64 = ext_bit(b, e32, 10);
    let (e, _n) = ea::eval(b, emode, ereg, 4, pc + 4)?;
    let src = read_ea(b, &e, 4)?;
    let dl = get_dx(b, dl_n);
    let a64u = b.zext::<W32, W64>(src);
    let b64u = b.zext::<W32, W64>(dl);
    let a64s = b.sext::<W32, W64>(src);
    let b64s = b.sext::<W32, W64>(dl);
    let a64 = b.select(is_signed, a64s, a64u);
    let b64 = b.select(is_signed, b64s, b64u);
    let prod = b.mul(a64, b64);
    let hi64 = {
        let s = b.konst::<W64>(32);
        b.shr_l(prod, s)
    };
    let hi = b.trunc::<W64, W32>(hi64);
    let lo = b.trunc::<W64, W32>(prod);
    // N/Z: 64 ビット形式は積全体、32 ビット形式は下位のみ。
    let zero64 = b.konst::<W64>(0);
    let z0 = b.cmp(Cmp::Eq, prod, zero64);
    let k0a = b.konst::<W32>(0);
    let z1 = b.cmp(Cmp::Eq, lo, k0a);
    let is_z = bsel(b, is64, z0, z1);
    let n64 = {
        let s = b.konst::<W64>(63);
        let t = b.shr_l(prod, s);
        b.cmp(Cmp::Ne, t, zero64)
    };
    let n32 = {
        let m = b.konst::<W32>(0x8000_0000);
        let t = b.and(lo, m);
        let z = b.konst::<W32>(0);
        b.cmp(Cmp::Ne, t, z)
    };
    let is_n = bsel(b, is64, n64, n32);
    // V: 32 ビット形式で上位に情報が残るとき（mulu: hi≠0、
    // muls: hi が lo の符号拡張と一致しない）。64 では常に 0。
    let k0b = b.konst::<W32>(0);
    let hinz = b.cmp(Cmp::Ne, hi, k0b);
    let losx = b.sext::<W32, W64>(lo);
    let losx_hi = {
        let s = b.konst::<W64>(32);
        b.shr_l(losx, s)
    };
    let sdif = b.cmp(Cmp::Ne, hi64, losx_hi);
    let v32 = bsel(b, is_signed, sdif, hinz);
    let kz = b.konst::<W64>(0);
    let ko = b.konst::<W64>(1);
    let v64 = b.cmp(Cmp::Ne, kz, ko); // 常に false
    let is_v = bsel(b, is64, v64, v32);
    if_then(b, is64, |bb| {
        bb.set_indexed(ea::d_array(), dh_n, hi);
        Ok(())
    })?;
    b.set_indexed(ea::d_array(), dl_n, lo);
    // flags: N/Z 更新、V 上記、C=0。
    let ccr = b.get(ccr_ref());
    let km0 = b.konst::<W8>(0xF0);
    let keep = b.and(ccr, km0);
    let nk = b.konst::<W8>(1 << sr_bit::N);
    let zk = b.konst::<W8>(1 << sr_bit::Z);
    let vk = b.konst::<W8>(1 << sr_bit::V);
    let z8 = b.konst::<W8>(0);
    let n8 = b.select(is_n, nk, z8);
    let v8 = b.select(is_v, vk, z8);
    let zf = b.select(is_z, zk, z8);
    let nv = b.or(n8, v8);
    let nvz = b.or(nv, zf);
    let out = b.or(keep, nvz);
    b.set(ccr_ref(), out);
    Ok(())
}

/// divl（0x4C40 + ext）。32/32→商→Dq・余り→Dr（32 ビット形式）
/// または 64/32（64 ビット形式、被除数は Dr:Dq）。
/// ext[15:12]=Dq（被除数・商）、ext[11]=符号、ext[10]=64
/// ビット被除数、ext[2:0]=Dr（剰余）。68020+。
// Ref: SPEC-M68K-PRM (Rev 1) §DIVS.L/DIVSL.L/DIVU.L/DIVUL.L.
fn divl<B: Backend>(b: &mut B, w: u64, pc: u64) -> Flow<B> {
    let emode = ea::ea_mode(w);
    let ereg = ea::ea_reg(w);
    if emode == 1 || (emode == 7 && ereg >= 5) {
        return Err(illegal(b));
    }
    let ext = ea::ext_w16(b, pc + 2)?;
    let e32 = b.zext::<W16, W32>(ext);
    // ext[15:12]=Dq（被除数・商）、ext[2:0]=Dr（剰余・64 ビット
    // 被除数の上位）。
    let dq_n = ext_reg(b, e32, 12);
    let dr_n = ext_reg(b, e32, 0);
    let is_signed = ext_bit(b, e32, 11);
    let is64 = ext_bit(b, e32, 10);
    let (e, _n) = ea::eval(b, emode, ereg, 4, pc + 4)?;
    let src = read_ea(b, &e, 4)?;
    let dqv = get_dx(b, dq_n);
    let drv = get_dx(b, dr_n);
    let zero = b.konst::<W32>(0);
    let is_z = b.cmp(Cmp::Eq, src, zero);
    // 0 除算はベクタ 5。
    b.if_then_else(
        is_z,
        |bb| {
            Err(bb.raise(GuestException {
                kind: ExceptionKind::Trap,
                code: 5,
                addr: None,
                in_delay_slot: false,
            }))
        },
        |_bb| Ok(()),
    )?;
    // 除数は常に 32 ビット（符号形式では i32→i64）。
    let src64u = b.zext::<W32, W64>(src);
    let src64s = b.sext::<W32, W64>(src);
    // 被除数: 32 ビット形式は Dq（符号形式は i32→i64）、
    // 64 ビット形式は Dr:Dq の結合値。
    let dq64u = b.zext::<W32, W64>(dqv);
    let dq64s = b.sext::<W32, W64>(dqv);
    let dq64 = b.select(is_signed, dq64s, dq64u);
    let hi64 = {
        let s = b.konst::<W64>(32);
        let v = b.zext::<W32, W64>(drv);
        b.shl(v, s)
    };
    let dvd64 = b.or(hi64, dq64u);
    let dvd = b.select(is64, dvd64, dq64);
    let qu = b.udiv(dvd, src64u);
    let qs = b.sdiv(dvd, src64s);
    let q64 = b.select(is_signed, qs, qu);
    let ru = b.urem(dvd, src64u);
    let rs = b.srem(dvd, src64s);
    let r64 = b.select(is_signed, rs, ru);
    let q32 = b.trunc::<W64, W32>(q64);
    let r32 = b.trunc::<W64, W32>(r64);
    // V: 商が 32 ビットに収まらない。符号なしは上位 32 ビットが
    // 非零、符号付きは i32 に切ると元に戻らない。
    let qhi = {
        let s = b.konst::<W64>(32);
        b.shr_l(q64, s)
    };
    let kz64 = b.konst::<W64>(0);
    let vu = b.cmp(Cmp::Ne, qhi, kz64);
    let qs32 = b.sext::<W32, W64>(q32);
    let vs = b.cmp(Cmp::Ne, qs32, q64);
    let is_v = bsel(b, is_signed, vs, vu);
    // flags: N/Z は商、V 上記、C=0。V=1 のとき商・余りは書かない。
    let sm32 = b.konst::<W32>(0x8000_0000);
    let n_at = b.and(q32, sm32);
    let is_n = b.cmp(Cmp::Ne, n_at, zero);
    let is_qz = b.cmp(Cmp::Eq, q32, zero);
    let ccr = b.get(ccr_ref());
    let km0 = b.konst::<W8>(0xF0);
    let keep = b.and(ccr, km0);
    let nk = b.konst::<W8>(1 << sr_bit::N);
    let zk = b.konst::<W8>(1 << sr_bit::Z);
    let vk = b.konst::<W8>(1 << sr_bit::V);
    let z8 = b.konst::<W8>(0);
    let n8 = b.select(is_n, nk, z8);
    let v8 = b.select(is_v, vk, z8);
    let zf = b.select(is_qz, zk, z8);
    let nv = b.or(n8, v8);
    let nvz = b.or(nv, zf);
    let out = b.or(keep, nvz);
    let not_v = bnot(b, is_v);
    if_then(b, not_v, |bb| {
        bb.set_indexed(ea::d_array(), dq_n, q32);
        bb.set_indexed(ea::d_array(), dr_n, r32);
        Ok(())
    })?;
    b.set(ccr_ref(), out);
    Ok(())
}

/// extb.l dn（0x49C0+n）。byte→long 符号拡張。68020+。
// Ref: SPEC-M68K-UM (MC68020) §EXTB.
fn extb_l<B: Backend>(b: &mut B, w: u64) -> Flow<B> {
    let rn = ea::ea_reg(w);
    let d = b.get(D(rn).state());
    let lo = b.trunc::<W32, W8>(d);
    let r = b.sext::<W8, W32>(lo);
    b.set(D(rn).state(), r);
    set_nzvc(b, r, 4);
    Ok(())
}

// ---- D2: 68020 ビットフィールド命令 ----

/// ビットフィールド命令の動作種別。
#[derive(Clone, Copy)]
enum BfOp {
    Tst,
    Chg,
    Clr,
    Set,
    Extu,
    Exts,
    Ffo,
    Ins,
}

/// ext 語からフィールドの offset/width を取り出す。
/// ext[11]=Do（offset が Dn[ext[8:6]]）、ext[5]=Dw（width が
/// Dn[ext[2:0]]）。即値 width 0 は 32。レジスタ width は mod 32
/// で 0 → 32。offset のレジスタ指定は Dn 全体。
// Ref: SPEC-M68K-UM (MC68020) §Bit Field Instructions.
fn bf_ow<B: Backend>(b: &mut B, ew: B::V<W16>) -> (B::V<W32>, B::V<W32>) {
    let e32 = b.zext::<W16, W32>(ew);
    let off_imm = {
        let s = b.konst::<W32>(6);
        let t = b.shr_l(e32, s);
        let m = b.konst::<W32>(31);
        b.and(t, m)
    };
    let off_rn = {
        let s = b.konst::<W32>(6);
        let t = b.shr_l(e32, s);
        let m = b.konst::<W32>(7);
        b.and(t, m)
    };
    let off_rv = b.get_indexed(ea::d_array(), off_rn);
    let is_do = ext_bit(b, e32, 11);
    let off = b.select(is_do, off_rv, off_imm);
    let wid_imm = {
        let m = b.konst::<W32>(31);
        b.and(e32, m)
    };
    let wid_rn = {
        let m = b.konst::<W32>(7);
        b.and(e32, m)
    };
    let wid_rv0 = b.get_indexed(ea::d_array(), wid_rn);
    let wmask = b.konst::<W32>(31);
    let wid_rv = b.and(wid_rv0, wmask);
    let is_dw = ext_bit(b, e32, 5);
    let wid0 = b.select(is_dw, wid_rv, wid_imm);
    let wz = b.konst::<W32>(0);
    let is_w0 = b.cmp(Cmp::Eq, wid0, wz);
    let w32 = b.konst::<W32>(32);
    let wid = b.select(is_w0, w32, wid0);
    (off, wid)
}

/// `wid` ビット幅の下位マスク。shl が全幅シフトを 0 と定義する
/// ため wid==32 で (1<<32)-1 = 0-1 = 全 1。
fn bf_mask<B: Backend>(b: &mut B, wid: B::V<W32>) -> B::V<W32> {
    let one = b.konst::<W32>(1);
    let s = b.shl(one, wid);
    let o = b.konst::<W32>(1);
    b.sub(s, o)
}

/// 32 ビット左ローテート。`c` は 0..31。
fn rol32<B: Backend>(b: &mut B, v: B::V<W32>, c: B::V<W32>) -> B::V<W32> {
    let l = b.shl(v, c);
    let w = b.konst::<W32>(32);
    let rc = b.sub(w, c);
    let r = b.shr_l(v, rc);
    b.or(l, r)
}

/// 32 ビット右ローテート。`c` は 0..31。
fn ror32<B: Backend>(b: &mut B, v: B::V<W32>, c: B::V<W32>) -> B::V<W32> {
    let r = b.shr_l(v, c);
    let w = b.konst::<W32>(32);
    let lc = b.sub(w, c);
    let l = b.shl(v, lc);
    b.or(r, l)
}

/// `v` の MSB（bit31）が立っているか。
fn msb_of<B: Backend>(b: &mut B, v: B::V<W32>) -> B::B {
    let m = b.konst::<W32>(0x8000_0000);
    let t = b.and(v, m);
    let z = b.konst::<W32>(0);
    b.cmp(Cmp::Ne, t, z)
}

/// ext[14:12] の Dn に値を書き込む。
fn set_dst<B: Backend>(b: &mut B, ew: B::V<W32>, v: B::V<W32>) {
    let n = ext_reg(b, ew, 12);
    b.set_indexed(ea::d_array(), n, v);
}

/// `x` の MSB からの先頭 0 ビット数（x==0 で 32）。
fn clz32<B: Backend>(b: &mut B, mut x: B::V<W32>) -> B::V<W32> {
    // 二分探索: 上位 (32 - sh) ビットが 0 なら sh を加算して
    // x を sh 左シフト。
    let mut n = b.konst::<W32>(0);
    for sh in [16u32, 8, 4, 2, 1] {
        let shv = b.konst::<W32>(32 - sh);
        let hi = b.shr_l(x, shv);
        let z = b.konst::<W32>(0);
        let empty = b.cmp(Cmp::Eq, hi, z);
        let kv = b.konst::<W32>(sh);
        let n1 = b.select(empty, kv, z);
        n = b.add(n, n1);
        let sl = b.konst::<W32>(sh);
        let xs = b.shl(x, sl);
        x = b.select(empty, xs, x);
    }
    n
}

/// フィールド値（下位右詰め）の先頭ゼロ数をフィールド先頭からの
/// 相対位置に直す。
fn ffo_val<B: Backend>(b: &mut B, field: B::V<W32>, wid: B::V<W32>) -> B::V<W32> {
    let clz = clz32(b, field);
    // フィールドは上位 wid ビットに左詰めされているので、
    // clz(field) からフィールド外の (32 - width) を引く。
    let w = b.konst::<W32>(32);
    let pad = b.sub(w, wid);
    b.sub(clz, pad)
}

/// 回転後レジスタ値 `old`（MSB 左詰めフィールド形式）の上位
/// `wid` ビットを `new` で置き換える。
fn merge_field<B: Backend>(b: &mut B, old: B::V<W32>, new: B::V<W32>, wid: B::V<W32>) -> B::V<W32> {
    // 保存部: old を wid 左へ、その後 wid 右へ戻す（上位 wid
    // ビットを 0 クリア）。shl が全幅シフトを全域 0 と定義する
    // ため wid==32 でも正しく 0 になる。
    let t = b.shl(old, wid);
    let kept = b.shr_l(t, wid);
    b.or(new, kept)
}

/// BFINS の挿入フィールドを Dn の下位 wid ビットから作る
/// （MSB 左詰め形式）。
fn field_ins<B: Backend>(b: &mut B, v: B::V<W32>, wid: B::V<W32>) -> B::V<W32> {
    let m = bf_mask(b, wid);
    let vm = b.and(v, m);
    let w = b.konst::<W32>(32);
    let sh = b.sub(w, wid);
    b.shl(vm, sh)
}

/// bf 系の旗をフィールド値（MSB 左詰め・width ビット）から
/// 更新する。N=フィールド MSB、Z=フィールド==0、V/C=0、X 不変。
fn bf_flags<B: Backend>(b: &mut B, field: B::V<W32>, wid: B::V<W32>) {
    let m = bf_mask(b, wid);
    let w = b.konst::<W32>(32);
    let sh = b.sub(w, wid);
    let fv = b.shr_l(field, sh);
    let fm = b.and(fv, m);
    let z = b.konst::<W32>(0);
    let is_z = b.cmp(Cmp::Eq, fm, z);
    let is_n = msb_of(b, field);
    let ccr = b.get(ccr_ref());
    // N/Z 更新、V/C 0、X と上位予約は保持。
    let keep = {
        let km = b.konst::<W8>(0x1F & !(0b0111));
        b.and(ccr, km)
    };
    let nk = b.konst::<W8>(1 << sr_bit::N);
    let zk = b.konst::<W8>(1 << sr_bit::Z);
    let z8 = b.konst::<W8>(0);
    let n8 = b.select(is_n, nk, z8);
    let zf = b.select(is_z, zk, z8);
    let nz = b.or(n8, zf);
    let out = b.or(keep, nz);
    b.set(ccr_ref(), out);
}

/// bf 系 8 命令。<ea> は Dn またはメモリ（An 直・即値は不可。
/// Tst/Extu/Exts/Ffo は PC 相対可）。
// Ref: SPEC-M68K-UM (MC68020) §Bit Field Instructions.
fn bf<B: Backend>(b: &mut B, w: u64, pc: u64, op: BfOp) -> Flow<B> {
    let emode = ea::ea_mode(w);
    let ereg = ea::ea_reg(w);
    let ok = match op {
        BfOp::Tst | BfOp::Extu | BfOp::Exts | BfOp::Ffo => emode != 1 && !(emode == 7 && ereg == 4),
        _ => emode != 1 && !(emode == 7 && ereg >= 2),
    };
    if !ok {
        return Err(illegal(b));
    }
    let ew16 = ea::ext_w16(b, pc + 2)?;
    let ew = b.zext::<W16, W32>(ew16);
    let (off, wid) = bf_ow(b, ew16);
    let msk = bf_mask(b, wid);
    if emode == 0 {
        // ---- Dn 形式: フィールドは off mod 32 から wid ビット ----
        let rn = ereg;
        let regv = b.get(D(rn).state());
        let k31 = b.konst::<W32>(31);
        let ro = b.and(off, k31);
        // フィールド抽出: rol(regv, ro) の上位 wid ビット。
        let rol = rol32(b, regv, ro);
        let w32c = b.konst::<W32>(32);
        let fw = b.sub(w32c, wid);
        let field = b.shr_l(rol, fw);
        let fmsb = b.shl(field, fw);
        bf_flags(b, fmsb, wid);
        match op {
            BfOp::Tst => {}
            BfOp::Extu => set_dst(b, ew, field),
            BfOp::Exts => {
                // フィールド MSB が立つときだけ符号拡張。
                let fsgn = msb_of(b, fmsb);
                let nm = b.not(msk);
                let sx = b.or(field, nm);
                let v = b.select(fsgn, sx, field);
                set_dst(b, ew, v);
            }
            BfOp::Chg | BfOp::Clr | BfOp::Set | BfOp::Ins => {
                let newf = match op {
                    BfOp::Chg => {
                        let nf = b.not(field);
                        b.and(nf, msk)
                    }
                    BfOp::Clr => b.konst::<W32>(0),
                    BfOp::Set => msk,
                    BfOp::Ins => {
                        let src_n = ext_reg(b, ew, 12);
                        let sv = b.get_indexed(ea::d_array(), src_n);
                        let v = b.and(sv, msk);
                        // 旗は挿入フィールドから。
                        let f = field_ins(b, sv, wid);
                        bf_flags(b, f, wid);
                        v
                    }
                    _ => unreachable!(),
                };
                // MSB 左詰めにして差し替え、逆回転で元位置へ。
                let newf_msb = {
                    let s = b.sub(w32c, wid);
                    b.shl(newf, s)
                };
                let newv = merge_field(b, rol, newf_msb, wid);
                let rv = ror32(b, newv, ro);
                b.set(D(rn).state(), rv);
            }
            BfOp::Ffo => {
                // 結果 = フィールドオフセット + フィールド内位置。
                let rel = ffo_val(b, field, wid);
                let fv = b.add(off, rel);
                let z = b.konst::<W32>(0);
                let is_f0 = b.cmp(Cmp::Eq, field, z);
                // 全 0 → offset + width。
                let sum = b.add(off, wid);
                let v = b.select(is_f0, sum, fv);
                set_dst(b, ew, v);
            }
        }
        return Ok(());
    }
    // ---- メモリ形式: バイト単位 ----
    let (e, _n) = ea::eval(b, emode, ereg, 1, pc + 4)?;
    let ea64 = match e {
        Ea::Addr(a) => a,
        _ => unreachable!("bf メモリ形式は Addr"),
    };
    // バイトオフセット = off >> 3（符号付き）。
    let three = b.konst::<W32>(3);
    let boff = b.shr_a(off, three);
    let boff64 = b.sext::<W32, W64>(boff);
    let base = b.add(ea64, boff64);
    let sbit = {
        let k7 = b.konst::<W32>(7);
        b.and(off, k7)
    };
    // nbytes = ceil((sbit + wid) / 8) — 最大 5。
    let nbytes = {
        let t = b.add(sbit, wid);
        let k7 = b.konst::<W32>(7);
        let t2 = b.add(t, k7);
        let k3 = b.konst::<W32>(3);
        b.shr_l(t2, k3)
    };
    // 最大 5 バイト読んで左詰め 40 ビットバッファにする。
    let rd = drd(b);
    let mut buf = b.konst::<W64>(0);
    for i in 0..5u32 {
        let iv = b.konst::<W64>(u64::from(i));
        let ai = b.add(base, iv);
        let byte8 = b.load::<W8>(ai, rd)?;
        let bv = b.zext::<W8, W64>(byte8);
        let sh8 = b.konst::<W64>(8 * u64::from(4 - i));
        let sv = b.shl(bv, sh8);
        buf = b.or(buf, sv);
    }
    // 抽出: shamt = 40 - sbit - wid（左詰め表現）。
    let k40 = b.konst::<W64>(40);
    let sbit64 = b.zext::<W32, W64>(sbit);
    let wid64 = b.zext::<W32, W64>(wid);
    let tmp = b.sub(k40, sbit64);
    let shamt = b.sub(tmp, wid64);
    let f64 = b.shr_l(buf, shamt);
    let msk64 = {
        let one = b.konst::<W64>(1);
        let s = b.shl(one, wid64);
        let o = b.konst::<W64>(1);
        b.sub(s, o)
    };
    let fv64 = b.and(f64, msk64);
    let field = b.trunc::<W64, W32>(fv64);
    let fmsb = {
        let w = b.konst::<W32>(32);
        let s = b.sub(w, wid);
        b.shl(field, s)
    };
    bf_flags(b, fmsb, wid);
    match op {
        BfOp::Tst => {}
        BfOp::Extu => set_dst(b, ew, field),
        BfOp::Exts => {
            let fsgn = msb_of(b, fmsb);
            let nm = b.not(msk);
            let sx = b.or(field, nm);
            let v = b.select(fsgn, sx, field);
            set_dst(b, ew, v);
        }
        BfOp::Ffo => {
            let rel = ffo_val(b, field, wid);
            let fv = b.add(off, rel);
            let z = b.konst::<W32>(0);
            let is_f0 = b.cmp(Cmp::Eq, field, z);
            let sum = b.add(off, wid);
            let v = b.select(is_f0, sum, fv);
            set_dst(b, ew, v);
        }
        BfOp::Chg | BfOp::Clr | BfOp::Set | BfOp::Ins => {
            let newf = match op {
                BfOp::Chg => {
                    let nf = b.not(field);
                    b.and(nf, msk)
                }
                BfOp::Clr => b.konst::<W32>(0),
                BfOp::Set => msk,
                BfOp::Ins => {
                    let src_n = ext_reg(b, ew, 12);
                    let sv = b.get_indexed(ea::d_array(), src_n);
                    let v = b.and(sv, msk);
                    let f = field_ins(b, sv, wid);
                    bf_flags(b, f, wid);
                    v
                }
                _ => unreachable!(),
            };
            // buf の [sbit, sbit+wid) を newf に置き換えて書き戻す。
            let newf64 = b.zext::<W32, W64>(newf);
            let nf_pos = b.shl(newf64, shamt);
            let mpos = b.shl(msk64, shamt);
            let keep_mask = b.not(mpos);
            let kept = b.and(buf, keep_mask);
            let nbuf = b.or(kept, nf_pos);
            // nbytes バイトだけ書き戻す。
            let wr = dwr(b);
            for i in 0..5u32 {
                let sh64 = b.konst::<W64>(8 * u64::from(4 - i));
                let bshift = b.shr_l(nbuf, sh64);
                let byte8 = b.trunc::<W64, W8>(bshift);
                let iv = b.konst::<W64>(u64::from(i));
                let ai = b.add(base, iv);
                let take = {
                    let k = b.konst::<W32>(i);
                    b.cmp(Cmp::LtU, k, nbytes)
                };
                if_then(b, take, |bb| {
                    bb.store::<W8>(ai, byte8, wr)?;
                    Ok(())
                })?;
            }
        }
    }
    Ok(())
}
