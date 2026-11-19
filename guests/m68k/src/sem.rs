// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! m68k 最小の命令意味論。バックエンドに対して総称的に書く。
//!
//! 骨格の段階なので、ここでは CPU 状態の参照と、16ビット固定命令の
//! 振り分けだけを持つ。EA モードの解釈はデコード方式の決定後に足す。
//!
//! 出典は SPEC-M68K-PRM (M68000PM/AD Rev 1) である。
//! Ref: SPEC-M68K-PRM (Rev 1).

use polyisa_mem::{Access, AccessKind, Align, Endian};
use polyisa_sem::{Backend, Cmp, ExceptionKind, Flow, GuestException, StateRef, W8, W16, W32, W64};

use super::CpuState;
use super::ea::{self, Ea};

/// データ読み出しのアクセス属性（BE・自然整列）。
const DRD: Access = Access {
    endian: Endian::Be,
    align: Align::Natural,
    kind: AccessKind::DataRead,
};

/// データ書き込みのアクセス属性（BE・自然整列）。
const DWR: Access = Access {
    endian: Endian::Be,
    align: Align::Natural,
    kind: AccessKind::DataWrite,
};

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

/// 骨格の16ビット固定命令を振り分ける。
///
/// `insn` は生成デコーダの結果、`w` は命令ワード。`pc` は命令の先頭
/// アドレス。nop と illegal だけを処理し、残りは未実装として
/// `Undefined` に落とす。rts/rtr/rte のスタック復帰と reset の外部
/// 通知は EA・例外処理の経路と一緒に足す。
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
        super::Insn::Illegal => Err(b.raise(GuestException {
            kind: ExceptionKind::Trap,
            // m68k の例外ベクタ番号 4（Illegal Instruction）。
            code: 4,
            addr: None,
            in_delay_slot: false,
        })),
        _ => Err(b.raise(GuestException {
            kind: ExceptionKind::Undefined,
            // 診断のため命令ワードを残す。
            code: w,
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
                let v = b.load::<W8>(*a, DRD)?;
                Ok(b.zext::<W8, W32>(v))
            }
            2 => {
                let v = b.load::<W16>(*a, DRD)?;
                Ok(b.zext::<W16, W32>(v))
            }
            // 68000 のバスは16ビットで、long は上位→下位の word アクセス
            // 2回（偶数整列のみ必須。4バイト整列ではない）。
            _ => {
                let hi = b.load::<W16>(*a, DRD)?;
                let two = b.konst::<W64>(2);
                let a2 = b.add(*a, two);
                let lo = b.load::<W16>(a2, DRD)?;
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
                b.store::<W8>(*a, v8, DWR)
            }
            2 => {
                let v16 = b.trunc::<W32, W16>(v);
                b.store::<W16>(*a, v16, DWR)
            }
            // long は上位→下位の word アクセス2回（偶数整列のみ必須）。
            _ => {
                let shift = b.konst::<W32>(16);
                let hi32 = b.shr_l(v, shift);
                let hi = b.trunc::<W32, W16>(hi32);
                b.store::<W16>(*a, hi, DWR)?;
                let lo = b.trunc::<W32, W16>(v);
                let two = b.konst::<W64>(2);
                let a2 = b.add(*a, two);
                b.store::<W16>(a2, lo, DWR)
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
    let (src, n1) = ea::eval(b, ea::ea_mode(w), ea::ea_reg(w), size, pc + 2)?;
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
    let ext = pc + 2 + u64::from(n1) * 2;
    let (dst, _n2) = ea::eval(b, dmode, dreg, size, ext)?;
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
    if emode == 1 || (emode == 7 && ereg >= 2) {
        return Err(illegal(b));
    }
    let (e, _n) = ea::eval(b, emode, ereg, size, pc + 2)?;
    match op {
        UnOp::Tst => {
            let d = read_ea(b, &e, size)?;
            set_nzvc(b, d, size);
            Ok(())
        }
        UnOp::Clr => {
            let z = b.konst::<W32>(0);
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
