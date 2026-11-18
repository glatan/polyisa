// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 記録した IR を `Backend` の上で実行する解釈器。
//!
//! JIT のテストのオラクル兼、ホストに JIT がない環境の実行路。
//! `Concrete` は `V<W>`・`B`・`Exit` と素直な値の相互変換だけを
//! 求める薄い性質で、`InterpBackend` が engine 側で実装する。

use polyisa_sem::GuestException;
use polyisa_sem::{
    Backend, Cmp, F16, F32, F64, StateArray, StateRef, W8, W16, W32, W64, W128, Width,
};

use crate::inst::{BinOp, Cvt, Ext, FpCmp, Inst, Ir, TriOp, UnOp, Wid};

/// `Backend` の値表現を 128 ビットの具体値と相互に変換できるもの。
pub trait Concrete: Backend {
    /// `V<W>` を 128 ビット整数にする。幅より上は 0。
    fn v_to_u128<W: Width>(v: Self::V<W>) -> u128;
    /// 128 ビット整数から `V<W>` にする。幅より上は切り捨てる。
    fn v_from_u128<W: Width>(v: u128) -> Self::V<W>;
    /// `B` を `bool` にする。
    fn b_to_bool(v: Self::B) -> bool;
    /// `bool` から `B` にする。
    fn b_from_bool(v: bool) -> Self::B;
    /// `raise`/メモリ失敗/`call` が返す脱出を IR の終端に写す。
    fn exit_class(e: Self::Exit) -> ExitClass;
}

/// `Concrete::exit_class` の写し先。
#[derive(Clone, Debug)]
pub enum ExitClass {
    Raise(GuestException),
    Unimpl,
}

/// `exec` が返すブロックの終わり方。
#[derive(Clone, Debug)]
pub enum IrOutcome {
    /// 次の fetch 先。`fall` か `Jump`/`Branch` の決めた番地。
    Next(u64),
    /// 例外で抜けた。`pc` は例外を起こした命令、`next` はその直後。
    Raise {
        e: GuestException,
        pc: u64,
        next: u64,
    },
    /// 未実装の操作に当たった。
    Unimpl { pc: u64 },
}

/// `ir` を `b` の上で実行する。`fall` はどの出口も取らなかったときの
/// 既定の次（記録した `Recorded::fall`）。
pub fn exec<B: Concrete>(ir: &Ir, b: &mut B, fall: u64) -> IrOutcome {
    let mut vals = vec![0u128; ir.wids.len()];
    let mut ctrl = fall;
    match exec_ops(&ir.ops, ir, b, &mut vals, &mut ctrl) {
        Some(o) => o,
        None => IrOutcome::Next(ctrl),
    }
}

/// `Err(IrOutcome)` はブロックを抜ける点（例外・未実装）。
fn exec_ops<B: Concrete>(
    ops: &[Inst],
    _ir: &Ir,
    b: &mut B,
    vals: &mut Vec<u128>,
    ctrl: &mut u64,
) -> Option<IrOutcome> {
    for i in ops {
        match *i {
            Inst::Const { d, w: _, v } => vals[d as usize] = v,
            Inst::Get { d, off, w } => vals[d as usize] = get_w(b, off, w),
            Inst::Set { off, w, v } => set_w(b, off, w, vals[v as usize]),
            Inst::GetIx {
                d,
                base,
                stride,
                ix,
                w,
            } => vals[d as usize] = get_ix(b, base, stride, vals[ix as usize] as u32, w),
            Inst::SetIx {
                base,
                stride,
                ix,
                v,
                w,
            } => set_ix(
                b,
                base,
                stride,
                vals[ix as usize] as u32,
                vals[v as usize],
                w,
            ),
            Inst::Un { d, op, a, w } => {
                vals[d as usize] = una(b, op, w, vals[a as usize]);
            }
            Inst::Bin { d, op, a, b: y, w } => {
                vals[d as usize] = alu(b, op, w, vals[a as usize], vals[y as usize]);
            }
            Inst::Tri {
                d,
                op,
                a,
                b: y,
                c,
                w,
            } => {
                let (x, y2, z) = (vals[a as usize], vals[y as usize], vals[c as usize]);
                vals[d as usize] = match op {
                    TriOp::Fmadd => fma(b, w, x, y2, z),
                };
            }
            Inst::Adc {
                d,
                dc,
                dv,
                a,
                b: y,
                c,
                w,
            } => {
                let (r, ca, ov) = adc(b, w, vals[a as usize], vals[y as usize], vals[c as usize]);
                vals[d as usize] = r;
                vals[dc as usize] = u128::from(ca);
                vals[dv as usize] = u128::from(ov);
            }
            Inst::Cmp { d, op, a, b: y, w } => {
                let r = cmp_w(b, op, w, vals[a as usize], vals[y as usize]);
                vals[d as usize] = u128::from(r);
            }
            Inst::FpCmp { d, op, a, b: y, w } => {
                let r = fpcmp(b, op, w, vals[a as usize], vals[y as usize]);
                vals[d as usize] = u128::from(r);
            }
            Inst::Sel { d, c, t, f, w } => {
                let c = vals[c as usize] != 0;
                vals[d as usize] = sel_w(b, w, c, vals[t as usize], vals[f as usize]);
            }
            Inst::Ext { d, op, a, from, to } => {
                vals[d as usize] = ext_w(b, op, from, to, vals[a as usize])
            }
            Inst::Cvt {
                d,
                op,
                a,
                from,
                to,
                rm,
            } => vals[d as usize] = cvt_w(b, op, from, to, vals[a as usize], rm),
            Inst::Load {
                d,
                addr,
                w,
                acc,
                pc,
                next,
            } => match load_w(b, w, vals[addr as usize] as u64, acc) {
                Ok(v) => vals[d as usize] = v,
                Err(e) => return Some(exit_of(e, pc, next)),
            },
            Inst::Store {
                addr,
                v,
                w,
                acc,
                pc,
                next,
            } => {
                let (a, x) = (vals[addr as usize] as u64, vals[v as usize]);
                if let Err(e) = store_w(b, w, a, x, acc) {
                    return Some(exit_of(e, pc, next));
                }
            }
            Inst::Probe {
                addr,
                len,
                acc,
                pc,
                next,
            } => {
                let a = vals[addr as usize] as u64;
                if let Err(e) = b.probe(B::v_from_u128::<W64>(u128::from(a)), len, acc) {
                    return Some(exit_of(B::exit_class(e), pc, next));
                }
            }
            Inst::Cmpx {
                d,
                addr,
                old,
                new,
                w,
                acc,
                pc,
                next,
            } => {
                let (a, o, n) = (
                    vals[addr as usize] as u64,
                    vals[old as usize],
                    vals[new as usize],
                );
                match cmpx_w(b, w, a, o, n, acc) {
                    Ok(v) => vals[d as usize] = v,
                    Err(e) => return Some(exit_of(e, pc, next)),
                }
            }
            Inst::LdRes {
                d,
                addr,
                w,
                acc,
                pc,
                next,
            } => match ldres_w(b, w, vals[addr as usize] as u64, acc) {
                Ok(v) => vals[d as usize] = v,
                Err(e) => return Some(exit_of(e, pc, next)),
            },
            Inst::StCond {
                d,
                addr,
                v,
                w,
                acc,
                pc,
                next,
            } => {
                let (a, x) = (vals[addr as usize] as u64, vals[v as usize]);
                match stcond_w(b, w, a, x, acc) {
                    Ok(ok) => vals[d as usize] = u128::from(ok),
                    Err(e) => return Some(exit_of(e, pc, next)),
                }
            }
            Inst::If { c, ref t, ref f } => {
                let inner = if vals[c as usize] != 0 { t } else { f };
                if let Some(o) = exec_ops(inner, _ir, b, vals, ctrl) {
                    return Some(o);
                }
            }
            Inst::Jump { v } => *ctrl = vals[v as usize] as u64,
            Inst::Branch { c, target } => {
                if vals[c as usize] != 0 {
                    *ctrl = target;
                }
            }
            Inst::Exit { e, pc, next } => {
                return Some(IrOutcome::Raise { e, pc, next });
            }
            Inst::Unimpl { pc } => return Some(IrOutcome::Unimpl { pc }),
            Inst::Hint { .. } => {}
        }
    }
    None
}

/// メモリ失敗・例外の `ExitClass` を `IrOutcome` にする。
fn exit_of(c: ExitClass, pc: u64, next: u64) -> IrOutcome {
    match c {
        ExitClass::Raise(e) => IrOutcome::Raise { e, pc, next },
        ExitClass::Unimpl => IrOutcome::Unimpl { pc },
    }
}

// ---- 幅ごとの `Backend` 呼び出し ----

macro_rules! with_w {
    ($w:expr, $W:ident, $e:expr) => {
        match $w {
            Wid::W8 => {
                type $W = W8;
                $e
            }
            Wid::W16 => {
                type $W = W16;
                $e
            }
            Wid::W32 => {
                type $W = W32;
                $e
            }
            Wid::W64 => {
                type $W = W64;
                $e
            }
            Wid::W128 => {
                type $W = W128;
                $e
            }
            Wid::W1 => unreachable!("W1 の値は 8 ビットとして持たない"),
        }
    };
}

/// 浮動小数点の幅を `F32`/`F64` に写す。
macro_rules! with_f {
    ($w:expr, $F:ident, $e:expr) => {
        match $w {
            Wid::W32 => {
                type $F = F32;
                $e
            }
            Wid::W64 => {
                type $F = F64;
                $e
            }
            _ => unreachable!("浮動小数点の幅"),
        }
    };
}

pub fn get_w<B: Concrete>(b: &mut B, off: u32, w: Wid) -> u128 {
    with_w!(w, W, {
        B::v_to_u128::<W>(b.get(StateRef::<W>::from_offset(off as usize)))
    })
}

pub fn set_w<B: Concrete>(b: &mut B, off: u32, w: Wid, v: u128) {
    with_w!(w, W, {
        b.set(
            StateRef::<W>::from_offset(off as usize),
            B::v_from_u128::<W>(v),
        );
    })
}

pub fn get_ix<B: Concrete>(b: &mut B, base: u32, stride: u32, ix: u32, w: Wid) -> u128 {
    let ix = B::v_from_u128::<W32>(u128::from(ix));
    with_w!(w, W, {
        B::v_to_u128::<W>(b.get_indexed(
            StateArray::<W>::from_layout(base as usize, stride as usize),
            ix,
        ))
    })
}

pub fn set_ix<B: Concrete>(b: &mut B, base: u32, stride: u32, ix: u32, v: u128, w: Wid) {
    let ix = B::v_from_u128::<W32>(u128::from(ix));
    with_w!(w, W, {
        b.set_indexed(
            StateArray::<W>::from_layout(base as usize, stride as usize),
            ix,
            B::v_from_u128::<W>(v),
        );
    })
}

pub fn alu<B: Concrete>(b: &mut B, op: BinOp, w: Wid, x: u128, y: u128) -> u128 {
    use BinOp as O;
    if matches!(
        op,
        O::Fadd
            | O::Fsub
            | O::Fmul
            | O::Fdiv
            | O::Fmin
            | O::Fmax
            | O::Fsgnj
            | O::Fsgnjn
            | O::Fsgnjx
    ) {
        return falu(b, op, w, x, y);
    }
    with_w!(w, W, {
        let a = B::v_from_u128::<W>(x);
        let c = B::v_from_u128::<W>(y);
        B::v_to_u128::<W>(match op {
            O::Add => b.add::<W>(a, c),
            O::Sub => b.sub::<W>(a, c),
            O::And => b.and::<W>(a, c),
            O::Or => b.or::<W>(a, c),
            O::Xor => b.xor::<W>(a, c),
            O::Shl => b.shl::<W>(a, c),
            O::ShrL => b.shr_l::<W>(a, c),
            O::ShrA => b.shr_a::<W>(a, c),
            O::Udiv => b.udiv::<W>(a, c),
            O::Urem => b.urem::<W>(a, c),
            O::Mul => b.mul::<W>(a, c),
            O::Mulh => b.mulh::<W>(a, c),
            O::Mulhsu => b.mulhsu::<W>(a, c),
            O::Mulhu => b.mulhu::<W>(a, c),
            O::Sdiv => b.sdiv::<W>(a, c),
            O::Srem => b.srem::<W>(a, c),
            _ => unreachable!("整数の演算"),
        })
    })
}

pub fn falu<B: Concrete>(b: &mut B, op: BinOp, w: Wid, x: u128, y: u128) -> u128 {
    use BinOp as O;
    with_f!(w, F, {
        let a = B::v_from_u128::<F>(x);
        let c = B::v_from_u128::<F>(y);
        B::v_to_u128::<F>(match op {
            O::Fadd => b.fadd::<F>(a, c),
            O::Fsub => b.fsub::<F>(a, c),
            O::Fmul => b.fmul::<F>(a, c),
            O::Fdiv => b.fdiv::<F>(a, c),
            O::Fmin => b.fmin::<F>(a, c),
            O::Fmax => b.fmax::<F>(a, c),
            O::Fsgnj => b.fsgnj::<F>(a, c),
            O::Fsgnjn => b.fsgnjn::<F>(a, c),
            O::Fsgnjx => b.fsgnjx::<F>(a, c),
            _ => unreachable!("浮動小数点の演算"),
        })
    })
}

pub fn fma<B: Concrete>(b: &mut B, w: Wid, x: u128, y: u128, z: u128) -> u128 {
    with_f!(w, F, {
        B::v_to_u128::<F>(b.fmadd::<F>(
            B::v_from_u128::<F>(x),
            B::v_from_u128::<F>(y),
            B::v_from_u128::<F>(z),
        ))
    })
}

pub fn una<B: Concrete>(b: &mut B, op: UnOp, w: Wid, x: u128) -> u128 {
    match op {
        UnOp::Not => with_w!(w, W, {
            B::v_to_u128::<W>(b.not::<W>(B::v_from_u128::<W>(x)))
        }),
        UnOp::Fsqrt => with_f!(w, F, {
            B::v_to_u128::<F>(b.fsqrt::<F>(B::v_from_u128::<F>(x)))
        }),
        UnOp::Fclass => with_f!(w, F, {
            B::v_to_u128::<W32>(b.fclass::<F>(B::v_from_u128::<F>(x)))
        }),
    }
}

pub fn adc<B: Concrete>(b: &mut B, w: Wid, x: u128, y: u128, c: u128) -> (u128, bool, bool) {
    with_w!(w, W, {
        let (r, ca, ov) = b.add_with_carry::<W>(
            B::v_from_u128::<W>(x),
            B::v_from_u128::<W>(y),
            B::b_from_bool(c != 0),
        );
        (B::v_to_u128::<W>(r), B::b_to_bool(ca), B::b_to_bool(ov))
    })
}

pub fn cmp_w<B: Concrete>(b: &mut B, op: Cmp, w: Wid, x: u128, y: u128) -> bool {
    with_w!(w, W, {
        B::b_to_bool(b.cmp::<W>(op, B::v_from_u128::<W>(x), B::v_from_u128::<W>(y)))
    })
}

pub fn fpcmp<B: Concrete>(b: &mut B, op: FpCmp, w: Wid, x: u128, y: u128) -> bool {
    with_f!(w, F, {
        let (a, c) = (B::v_from_u128::<F>(x), B::v_from_u128::<F>(y));
        B::b_to_bool(match op {
            FpCmp::Feq => b.feq::<F>(a, c),
            FpCmp::Flt => b.flt::<F>(a, c),
            FpCmp::Fle => b.fle::<F>(a, c),
        })
    })
}

pub fn sel_w<B: Concrete>(b: &mut B, w: Wid, c: bool, t: u128, f: u128) -> u128 {
    with_w!(w, W, {
        B::v_to_u128::<W>(b.select::<W>(
            B::b_from_bool(c),
            B::v_from_u128::<W>(t),
            B::v_from_u128::<W>(f),
        ))
    })
}

/// 幅の変換。(from, to) の有効な組み合わせだけを持つ。
pub fn ext_w<B: Concrete>(b: &mut B, op: Ext, from: Wid, to: Wid, x: u128) -> u128 {
    macro_rules! m {
        ($F:ty, $T:ty) => {{
            let a = B::v_from_u128::<$F>(x);
            B::v_to_u128::<$T>(match op {
                Ext::Zext => b.zext::<$F, $T>(a),
                Ext::Sext => b.sext::<$F, $T>(a),
                Ext::Trunc => b.trunc::<$F, $T>(a),
            })
        }};
    }
    match (from, to) {
        (Wid::W8, Wid::W16) => m!(W8, W16),
        (Wid::W8, Wid::W32) => m!(W8, W32),
        (Wid::W8, Wid::W64) => m!(W8, W64),
        (Wid::W8, Wid::W128) => m!(W8, W128),
        (Wid::W16, Wid::W32) => m!(W16, W32),
        (Wid::W16, Wid::W64) => m!(W16, W64),
        (Wid::W16, Wid::W128) => m!(W16, W128),
        (Wid::W32, Wid::W64) => m!(W32, W64),
        (Wid::W32, Wid::W128) => m!(W32, W128),
        (Wid::W64, Wid::W128) => m!(W64, W128),
        // trunc は from > to。
        (Wid::W16, Wid::W8) => m!(W16, W8),
        (Wid::W32, Wid::W8) => m!(W32, W8),
        (Wid::W32, Wid::W16) => m!(W32, W16),
        (Wid::W64, Wid::W8) => m!(W64, W8),
        (Wid::W64, Wid::W16) => m!(W64, W16),
        (Wid::W64, Wid::W32) => m!(W64, W32),
        (Wid::W128, Wid::W8) => m!(W128, W8),
        (Wid::W128, Wid::W16) => m!(W128, W16),
        (Wid::W128, Wid::W32) => m!(W128, W32),
        (Wid::W128, Wid::W64) => m!(W128, W64),
        _ => unreachable!("幅の変換 {from:?} -> {to:?}"),
    }
}

/// 浮動小数点の変換。
pub fn cvt_w<B: Concrete>(b: &mut B, op: Cvt, from: Wid, to: Wid, x: u128, rm: u8) -> u128 {
    use Cvt as C;
    match op {
        C::S32 => with_f!(from, F, {
            B::v_to_u128::<W32>(b.fcvt_s32::<F>(B::v_from_u128::<F>(x), rm))
        }),
        C::U32 => with_f!(from, F, {
            B::v_to_u128::<W32>(b.fcvt_u32::<F>(B::v_from_u128::<F>(x), rm))
        }),
        C::S64 => with_f!(from, F, {
            B::v_to_u128::<W64>(b.fcvt_s64::<F>(B::v_from_u128::<F>(x), rm))
        }),
        C::U64 => with_f!(from, F, {
            B::v_to_u128::<W64>(b.fcvt_u64::<F>(B::v_from_u128::<F>(x), rm))
        }),
        C::FromS32 => with_f!(to, F, {
            B::v_to_u128::<F>(b.fcvt_from_s32::<F>(B::v_from_u128::<W32>(x), rm))
        }),
        C::FromU32 => with_f!(to, F, {
            B::v_to_u128::<F>(b.fcvt_from_u32::<F>(B::v_from_u128::<W32>(x), rm))
        }),
        C::FromS64 => with_f!(to, F, {
            B::v_to_u128::<F>(b.fcvt_from_s64::<F>(B::v_from_u128::<W64>(x), rm))
        }),
        C::FromU64 => with_f!(to, F, {
            B::v_to_u128::<F>(b.fcvt_from_u64::<F>(B::v_from_u128::<W64>(x), rm))
        }),
        C::Ff => match (from, to) {
            (Wid::W16, Wid::W32) => {
                B::v_to_u128::<F32>(b.fcvt_ff::<F16, F32>(B::v_from_u128::<F16>(x), rm))
            }
            (Wid::W32, Wid::W16) => {
                B::v_to_u128::<F16>(b.fcvt_ff::<F32, F16>(B::v_from_u128::<F32>(x), rm))
            }
            (Wid::W32, Wid::W64) => {
                B::v_to_u128::<F64>(b.fcvt_ff::<F32, F64>(B::v_from_u128::<F32>(x), rm))
            }
            (Wid::W64, Wid::W32) => {
                B::v_to_u128::<F32>(b.fcvt_ff::<F64, F32>(B::v_from_u128::<F64>(x), rm))
            }
            (Wid::W32, Wid::W32) => {
                B::v_to_u128::<F32>(b.fcvt_ff::<F32, F32>(B::v_from_u128::<F32>(x), rm))
            }
            (Wid::W64, Wid::W64) => {
                B::v_to_u128::<F64>(b.fcvt_ff::<F64, F64>(B::v_from_u128::<F64>(x), rm))
            }
            _ => unreachable!("浮動小数点間の変換"),
        },
    }
}

pub fn load_w<B: Concrete>(
    b: &mut B,
    w: Wid,
    addr: u64,
    acc: polyisa_mem::Access,
) -> Result<u128, ExitClass> {
    let a = B::v_from_u128::<W64>(u128::from(addr));
    with_w!(w, W, {
        b.load::<W>(a, acc)
            .map(B::v_to_u128::<W>)
            .map_err(B::exit_class)
    })
}

pub fn store_w<B: Concrete>(
    b: &mut B,
    w: Wid,
    addr: u64,
    v: u128,
    acc: polyisa_mem::Access,
) -> Result<(), ExitClass> {
    let a = B::v_from_u128::<W64>(u128::from(addr));
    with_w!(w, W, {
        b.store::<W>(a, B::v_from_u128::<W>(v), acc)
            .map_err(B::exit_class)
    })
}

pub fn cmpx_w<B: Concrete>(
    b: &mut B,
    w: Wid,
    addr: u64,
    old: u128,
    new: u128,
    acc: polyisa_mem::Access,
) -> Result<u128, ExitClass> {
    let a = B::v_from_u128::<W64>(u128::from(addr));
    with_w!(w, W, {
        b.cmpxchg::<W>(a, B::v_from_u128::<W>(old), B::v_from_u128::<W>(new), acc)
            .map(B::v_to_u128::<W>)
            .map_err(B::exit_class)
    })
}

pub fn ldres_w<B: Concrete>(
    b: &mut B,
    w: Wid,
    addr: u64,
    acc: polyisa_mem::Access,
) -> Result<u128, ExitClass> {
    let a = B::v_from_u128::<W64>(u128::from(addr));
    with_w!(w, W, {
        b.load_reserved::<W>(a, acc)
            .map(B::v_to_u128::<W>)
            .map_err(B::exit_class)
    })
}

pub fn stcond_w<B: Concrete>(
    b: &mut B,
    w: Wid,
    addr: u64,
    v: u128,
    acc: polyisa_mem::Access,
) -> Result<bool, ExitClass> {
    let a = B::v_from_u128::<W64>(u128::from(addr));
    with_w!(w, W, {
        b.store_conditional::<W>(a, B::v_from_u128::<W>(v), acc)
            .map(B::b_to_bool)
            .map_err(B::exit_class)
    })
}
