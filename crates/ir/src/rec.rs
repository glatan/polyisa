// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 意味論を IR に写す記録バックエンド。
//!
//! `Backend` の各操作は `Inst` をブロックへ足し、値として新しい
//! `Id` を返す。`if_then_else` は両側を子列に記録して `If` を足す。
//! `raise`・メモリ操作の失敗・`call` の未実装は `IrExit` を返し、
//! `if_then_else` がその子列の終端として `Exit`/`Unimpl` を足す。
//! トップレベルでは呼び出し側（`record` を回す翻訳器）が `abort`
//! で同じ処理をする。

use polyisa_mem::Access;
use polyisa_sem::GuestException;
use polyisa_sem::{Backend, Cmp, Helper, HintKey, Param, StateArray, StateRef, W32, W64, Width};

use crate::inst::{BinOp, Cvt, Ext, FpCmp, Id, Inst, Ir, TriOp, UnOp, Wid};

/// 記録側の値。SSA の値番号。
pub type IrVal = Id;
/// 記録側の真偽値。`W1` の値番号。
pub type IrCond = Id;

/// 記録中に意味論が返した「抜ける」理由。`if_then_else` と
/// `record` が `Exit`/`Unimpl` ノードへ写す。
#[derive(Clone, Debug)]
pub enum IrExit {
    Raise(GuestException),
    Unimpl,
}

/// `Backend` を実装する記録器。
pub struct IrBackend {
    /// 出来上がりのブロック。
    pub ir: Ir,
    /// 記録中の命令のアドレス。メモリ操作と例外の出口情報に入れる。
    pub cur_pc: u64,
    /// 記録中の命令の直後のアドレス。
    pub cur_next: u64,
    /// `if_then_else` の記録中の子列。末尾が現在の追記先。
    stack: Vec<Vec<Inst>>,
}

impl IrBackend {
    #[must_use]
    pub fn new() -> Self {
        Self {
            ir: Ir::default(),
            cur_pc: 0,
            cur_next: 0,
            stack: Vec::new(),
        }
    }

    /// 現在の追記先（`If` の記録中はその子列）。
    fn ops_mut(&mut self) -> &mut Vec<Inst> {
        match self.stack.last_mut() {
            Some(s) => s,
            None => &mut self.ir.ops,
        }
    }

    /// 操作を足す。
    fn emit(&mut self, i: Inst) {
        self.ops_mut().push(i);
    }

    /// 値を作ってその操作を足し、`Id` を返す。
    fn def_emit(&mut self, w: Wid, make: impl FnOnce(Id) -> Inst) -> Id {
        let d = self.ir.def(w);
        let i = make(d);
        self.emit(i);
        d
    }

    /// `IrExit` を現在の列の終端操作として足す。
    /// `if_then_else` の子列と `record` の終端で共通。
    pub fn abort(&mut self, e: IrExit) {
        let (pc, next) = (self.cur_pc, self.cur_next);
        let i = match e {
            IrExit::Raise(g) => Inst::Exit { e: g, pc, next },
            IrExit::Unimpl => Inst::Unimpl { pc },
        };
        self.emit(i);
    }

    /// 状態読み出しの `Get` を足す。
    fn get_w<W: Width>(&mut self, off: usize) -> Id {
        let w = Wid::of::<W>();
        self.def_emit(w, |d| Inst::Get {
            d,
            off: off as u32,
            w,
        })
    }

    fn bin<W: Width>(&mut self, op: BinOp, a: Id, b: Id) -> Id {
        let w = Wid::of::<W>();
        self.def_emit(w, |d| Inst::Bin { d, op, a, b, w })
    }

    fn fbin<F: Width>(&mut self, op: BinOp, a: Id, b: Id) -> Id {
        self.bin::<F>(op, a, b)
    }

    fn mem<W: Width>(&mut self, mk: impl FnOnce(Id, u64, u64) -> Inst) -> Result<Id, IrExit> {
        let w = Wid::of::<W>();
        let (pc, next) = (self.cur_pc, self.cur_next);
        let d = self.ir.def(w);
        let i = mk(d, pc, next);
        self.emit(i);
        Ok(d)
    }
}

impl Default for IrBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for IrBackend {
    type V<W: Width> = IrVal;
    type B = IrCond;
    type Exit = IrExit;

    fn konst<W: Width>(&mut self, v: W::Repr) -> IrVal {
        let w = Wid::of::<W>();
        self.def_emit(w, |d| Inst::Const {
            d,
            w,
            v: W::to_u128(v) & w.mask(),
        })
    }

    fn get<W: Width>(&mut self, r: StateRef<W>) -> IrVal {
        self.get_w::<W>(r.offset())
    }

    fn set<W: Width>(&mut self, r: StateRef<W>, v: IrVal) {
        let w = Wid::of::<W>();
        self.emit(Inst::Set {
            off: r.offset() as u32,
            w,
            v,
        });
    }

    fn get_indexed<W: Width>(&mut self, a: StateArray<W>, i: IrVal) -> IrVal {
        let w = Wid::of::<W>();
        self.def_emit(w, |d| Inst::GetIx {
            d,
            base: a.offset() as u32,
            stride: a.stride() as u32,
            ix: i,
            w,
        })
    }

    fn set_indexed<W: Width>(&mut self, a: StateArray<W>, i: IrVal, v: IrVal) {
        let w = Wid::of::<W>();
        self.emit(Inst::SetIx {
            base: a.offset() as u32,
            stride: a.stride() as u32,
            ix: i,
            v,
            w,
        });
    }

    fn add<W: Width>(&mut self, a: IrVal, b: IrVal) -> IrVal {
        self.bin::<W>(BinOp::Add, a, b)
    }
    fn sub<W: Width>(&mut self, a: IrVal, b: IrVal) -> IrVal {
        self.bin::<W>(BinOp::Sub, a, b)
    }
    fn and<W: Width>(&mut self, a: IrVal, b: IrVal) -> IrVal {
        self.bin::<W>(BinOp::And, a, b)
    }
    fn or<W: Width>(&mut self, a: IrVal, b: IrVal) -> IrVal {
        self.bin::<W>(BinOp::Or, a, b)
    }
    fn xor<W: Width>(&mut self, a: IrVal, b: IrVal) -> IrVal {
        self.bin::<W>(BinOp::Xor, a, b)
    }
    fn not<W: Width>(&mut self, a: IrVal) -> IrVal {
        let w = Wid::of::<W>();
        self.def_emit(w, |d| Inst::Un {
            d,
            op: UnOp::Not,
            a,
            w,
        })
    }
    fn shl<W: Width>(&mut self, a: IrVal, n: IrVal) -> IrVal {
        self.bin::<W>(BinOp::Shl, a, n)
    }
    fn shr_l<W: Width>(&mut self, a: IrVal, n: IrVal) -> IrVal {
        self.bin::<W>(BinOp::ShrL, a, n)
    }
    fn shr_a<W: Width>(&mut self, a: IrVal, n: IrVal) -> IrVal {
        self.bin::<W>(BinOp::ShrA, a, n)
    }
    fn add_with_carry<W: Width>(
        &mut self,
        a: IrVal,
        b: IrVal,
        c: IrCond,
    ) -> (IrVal, IrCond, IrCond) {
        let w = Wid::of::<W>();
        let d = self.ir.def(w);
        let dc = self.ir.def(Wid::W1);
        let dv = self.ir.def(Wid::W1);
        self.emit(Inst::Adc {
            d,
            dc,
            dv,
            a,
            b,
            c,
            w,
        });
        (d, dc, dv)
    }
    fn udiv<W: Width>(&mut self, a: IrVal, b: IrVal) -> IrVal {
        self.bin::<W>(BinOp::Udiv, a, b)
    }
    fn urem<W: Width>(&mut self, a: IrVal, b: IrVal) -> IrVal {
        self.bin::<W>(BinOp::Urem, a, b)
    }
    fn mul<W: Width>(&mut self, a: IrVal, b: IrVal) -> IrVal {
        self.bin::<W>(BinOp::Mul, a, b)
    }
    fn mulh<W: Width>(&mut self, a: IrVal, b: IrVal) -> IrVal {
        self.bin::<W>(BinOp::Mulh, a, b)
    }
    fn mulhsu<W: Width>(&mut self, a: IrVal, b: IrVal) -> IrVal {
        self.bin::<W>(BinOp::Mulhsu, a, b)
    }
    fn mulhu<W: Width>(&mut self, a: IrVal, b: IrVal) -> IrVal {
        self.bin::<W>(BinOp::Mulhu, a, b)
    }
    fn sdiv<W: Width>(&mut self, a: IrVal, b: IrVal) -> IrVal {
        self.bin::<W>(BinOp::Sdiv, a, b)
    }
    fn srem<W: Width>(&mut self, a: IrVal, b: IrVal) -> IrVal {
        self.bin::<W>(BinOp::Srem, a, b)
    }

    fn fadd<F: Width>(&mut self, a: IrVal, b: IrVal) -> IrVal {
        self.fbin::<F>(BinOp::Fadd, a, b)
    }
    fn fsub<F: Width>(&mut self, a: IrVal, b: IrVal) -> IrVal {
        self.fbin::<F>(BinOp::Fsub, a, b)
    }
    fn fmul<F: Width>(&mut self, a: IrVal, b: IrVal) -> IrVal {
        self.fbin::<F>(BinOp::Fmul, a, b)
    }
    fn fmadd<F: Width>(&mut self, a: IrVal, b: IrVal, c: IrVal) -> IrVal {
        let w = Wid::of::<F>();
        self.def_emit(w, |d| Inst::Tri {
            d,
            op: TriOp::Fmadd,
            a,
            b,
            c,
            w,
        })
    }
    fn fdiv<F: Width>(&mut self, a: IrVal, b: IrVal) -> IrVal {
        self.fbin::<F>(BinOp::Fdiv, a, b)
    }
    fn fsqrt<F: Width>(&mut self, a: IrVal) -> IrVal {
        let w = Wid::of::<F>();
        self.def_emit(w, |d| Inst::Un {
            d,
            op: UnOp::Fsqrt,
            a,
            w,
        })
    }
    fn fmin<F: Width>(&mut self, a: IrVal, b: IrVal) -> IrVal {
        self.fbin::<F>(BinOp::Fmin, a, b)
    }
    fn fmax<F: Width>(&mut self, a: IrVal, b: IrVal) -> IrVal {
        self.fbin::<F>(BinOp::Fmax, a, b)
    }
    fn fsgnj<F: Width>(&mut self, a: IrVal, b: IrVal) -> IrVal {
        self.fbin::<F>(BinOp::Fsgnj, a, b)
    }
    fn fsgnjn<F: Width>(&mut self, a: IrVal, b: IrVal) -> IrVal {
        self.fbin::<F>(BinOp::Fsgnjn, a, b)
    }
    fn fsgnjx<F: Width>(&mut self, a: IrVal, b: IrVal) -> IrVal {
        self.fbin::<F>(BinOp::Fsgnjx, a, b)
    }
    fn feq<F: Width>(&mut self, a: IrVal, b: IrVal) -> IrCond {
        let w = Wid::of::<F>();
        self.def_emit(Wid::W1, |d| Inst::FpCmp {
            d,
            op: FpCmp::Feq,
            a,
            b,
            w,
        })
    }
    fn flt<F: Width>(&mut self, a: IrVal, b: IrVal) -> IrCond {
        let w = Wid::of::<F>();
        self.def_emit(Wid::W1, |d| Inst::FpCmp {
            d,
            op: FpCmp::Flt,
            a,
            b,
            w,
        })
    }
    fn fle<F: Width>(&mut self, a: IrVal, b: IrVal) -> IrCond {
        let w = Wid::of::<F>();
        self.def_emit(Wid::W1, |d| Inst::FpCmp {
            d,
            op: FpCmp::Fle,
            a,
            b,
            w,
        })
    }
    fn fclass<F: Width>(&mut self, a: IrVal) -> IrVal {
        let w = Wid::of::<F>();
        self.def_emit(Wid::W32, |d| Inst::Un {
            d,
            op: UnOp::Fclass,
            a,
            w,
        })
    }
    fn fcvt_s32<F: Width>(&mut self, a: IrVal, rm: u8) -> IrVal {
        self.cvt::<F, W32>(Cvt::S32, a, rm)
    }
    fn fcvt_u32<F: Width>(&mut self, a: IrVal, rm: u8) -> IrVal {
        self.cvt::<F, W32>(Cvt::U32, a, rm)
    }
    fn fcvt_s64<F: Width>(&mut self, a: IrVal, rm: u8) -> IrVal {
        self.cvt::<F, W64>(Cvt::S64, a, rm)
    }
    fn fcvt_u64<F: Width>(&mut self, a: IrVal, rm: u8) -> IrVal {
        self.cvt::<F, W64>(Cvt::U64, a, rm)
    }
    fn fcvt_from_s32<F: Width>(&mut self, a: IrVal, rm: u8) -> IrVal {
        self.cvt::<W32, F>(Cvt::FromS32, a, rm)
    }
    fn fcvt_from_u32<F: Width>(&mut self, a: IrVal, rm: u8) -> IrVal {
        self.cvt::<W32, F>(Cvt::FromU32, a, rm)
    }
    fn fcvt_from_s64<F: Width>(&mut self, a: IrVal, rm: u8) -> IrVal {
        self.cvt::<W64, F>(Cvt::FromS64, a, rm)
    }
    fn fcvt_from_u64<F: Width>(&mut self, a: IrVal, rm: u8) -> IrVal {
        self.cvt::<W64, F>(Cvt::FromU64, a, rm)
    }
    fn fcvt_ff<F: Width, T: Width>(&mut self, a: IrVal, rm: u8) -> IrVal {
        self.cvt::<F, T>(Cvt::Ff, a, rm)
    }
    /// `fp_flags` は実行時の値を返すので記録できない。例外フラグの
    /// 読み出しに依存するゲスト（riscv の fcsr）は JIT と差が出る。
    /// aarch64/arm/x86 の意味論は読まない。GAP-0027 系の未処理。
    fn fp_flags(&mut self) -> u8 {
        0
    }
    fn zext<F: Width, T: Width>(&mut self, a: IrVal) -> IrVal {
        self.ext::<F, T>(Ext::Zext, a)
    }
    fn sext<F: Width, T: Width>(&mut self, a: IrVal) -> IrVal {
        self.ext::<F, T>(Ext::Sext, a)
    }
    fn trunc<F: Width, T: Width>(&mut self, a: IrVal) -> IrVal {
        self.ext::<F, T>(Ext::Trunc, a)
    }
    fn cmp<W: Width>(&mut self, op: Cmp, a: IrVal, b: IrVal) -> IrCond {
        let w = Wid::of::<W>();
        self.def_emit(Wid::W1, |d| Inst::Cmp { d, op, a, b, w })
    }
    fn select<W: Width>(&mut self, c: IrCond, t: IrVal, f: IrVal) -> IrVal {
        let w = Wid::of::<W>();
        self.def_emit(w, |d| Inst::Sel { d, c, t, f, w })
    }

    fn load<W: Width>(&mut self, addr: IrVal, acc: Access) -> Result<IrVal, IrExit> {
        self.mem::<W>(|d, pc, next| Inst::Load {
            d,
            addr,
            w: Wid::of::<W>(),
            acc,
            pc,
            next,
        })
    }
    fn store<W: Width>(&mut self, addr: IrVal, v: IrVal, acc: Access) -> Result<(), IrExit> {
        let (pc, next) = (self.cur_pc, self.cur_next);
        self.emit(Inst::Store {
            addr,
            v,
            w: Wid::of::<W>(),
            acc,
            pc,
            next,
        });
        Ok(())
    }
    fn probe(&mut self, addr: IrVal, len: u32, acc: Access) -> Result<(), IrExit> {
        let (pc, next) = (self.cur_pc, self.cur_next);
        self.emit(Inst::Probe {
            addr,
            len,
            acc,
            pc,
            next,
        });
        Ok(())
    }
    fn cmpxchg<W: Width>(
        &mut self,
        addr: IrVal,
        old: IrVal,
        new: IrVal,
        acc: Access,
    ) -> Result<IrVal, IrExit> {
        self.mem::<W>(|d, pc, next| Inst::Cmpx {
            d,
            addr,
            old,
            new,
            w: Wid::of::<W>(),
            acc,
            pc,
            next,
        })
    }
    fn load_reserved<W: Width>(&mut self, addr: IrVal, acc: Access) -> Result<IrVal, IrExit> {
        self.mem::<W>(|d, pc, next| Inst::LdRes {
            d,
            addr,
            w: Wid::of::<W>(),
            acc,
            pc,
            next,
        })
    }
    fn store_conditional<W: Width>(
        &mut self,
        addr: IrVal,
        v: IrVal,
        acc: Access,
    ) -> Result<IrCond, IrExit> {
        let (pc, next) = (self.cur_pc, self.cur_next);
        let d = self.ir.def(Wid::W1);
        self.emit(Inst::StCond {
            d,
            addr,
            v,
            w: Wid::of::<W>(),
            acc,
            pc,
            next,
        });
        Ok(d)
    }

    /// 両側を子列として記録し、`If` ノード 1 つを足す。
    /// 片側から抜けた（例外・未実装）ときはその子列の終端に
    /// `Exit`/`Unimpl` を置く。条件がどちらに転んでも残りの列は
    /// 実行される点に注意（`Jump`/`Branch` は「抜ける」ではない）。
    fn if_then_else<F, G>(&mut self, c: IrCond, then: F, els: G) -> Result<(), IrExit>
    where
        F: FnOnce(&mut Self) -> Result<(), IrExit>,
        G: FnOnce(&mut Self) -> Result<(), IrExit>,
    {
        self.stack.push(Vec::new());
        if let Err(e) = then(self) {
            self.abort(e);
        }
        let t = self.stack.pop().expect("then 列");
        self.stack.push(Vec::new());
        if let Err(e) = els(self) {
            self.abort(e);
        }
        let f = self.stack.pop().expect("else 列");
        self.emit(Inst::If { c, t, f });
        Ok(())
    }

    fn jump(&mut self, target: IrVal) {
        self.emit(Inst::Jump { v: target });
    }
    fn branch(&mut self, c: IrCond, target: u64) {
        self.emit(Inst::Branch { c, target });
    }
    /// `Exit` ノードはここでは足さない。`if_then_else` の子列か
    /// `record` の終端で `abort` が足す（例外の記録位置を揃えるため）。
    fn raise(&mut self, e: GuestException) -> IrExit {
        IrExit::Raise(e)
    }

    /// ヘルパーは型付き引数を IR に写す決まった形がない。
    /// 呼び出しを `Unimpl` で抜ける点として記録する。
    /// ゲスト側は helper を段階 9 の時点では使っていない。
    fn call<H: Helper>(&mut self, _args: H::Args<Self>) -> Result<H::Ret<Self>, IrExit>
    where
        Self: Sized,
    {
        Err(IrExit::Unimpl)
    }
    /// `param` はインタプリタも panic するので同じに揃える（GAP-0027）。
    fn param<P: Param>(&mut self) -> P::Value {
        panic!("param: 挙動パラメータは CPU モデルの結び付け後に読む")
    }
    /// タイミングの手がかりは記録だけしておく（実行時の効果なし）。
    fn timing_hint(&mut self, key: HintKey, v: IrVal) {
        self.emit(Inst::Hint { key: key.0, v });
    }
}

impl IrBackend {
    fn cvt<F: Width, T: Width>(&mut self, op: Cvt, a: IrVal, rm: u8) -> IrVal {
        let (from, to) = (Wid::of::<F>(), Wid::of::<T>());
        self.def_emit(to, |d| Inst::Cvt {
            d,
            op,
            a,
            from,
            to,
            rm,
        })
    }

    fn ext<F: Width, T: Width>(&mut self, op: Ext, a: IrVal) -> IrVal {
        let (from, to) = (Wid::of::<F>(), Wid::of::<T>());
        self.def_emit(to, |d| Inst::Ext { d, op, a, from, to })
    }
}
