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
