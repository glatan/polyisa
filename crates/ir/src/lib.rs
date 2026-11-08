//! 中間表現。IR のバックエンド、最適化は後の段階で足す。
//!
//! ここでは値の番号と、バックエンドの殻だけを提供する。

#![forbid(unsafe_code)]

use polyisa_sem::{
    Access, Backend, Cmp, GuestException, Helper, HintKey, Param, StateArray, StateRef,
};
use polyisa_sem::{W32, W64, Width};

/// IR の値の番号。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct IrVal(pub u32);

/// IR の真偽値。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct IrCond(pub u32);

/// IR の退出理由。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IrExit(pub String);

/// 記録中の IR。
#[derive(Debug, Default)]
pub struct Ir {
    next: u32,
}

/// IR を作るバックエンド。具体的な実行はせず、値の番号だけを返す殻である。
#[derive(Debug, Default)]
pub struct IrBackend {
    ir: Ir,
}

impl IrBackend {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn fresh<W: Width>(&mut self) -> IrVal {
        let v = IrVal(self.ir.next);
        self.ir.next += 1;
        let _ = core::marker::PhantomData::<W>;
        v
    }
}

impl Backend for IrBackend {
    type V<W: Width> = IrVal;
    type B = IrCond;
    type Exit = IrExit;

    fn konst<W: Width>(&mut self, _v: W::Repr) -> Self::V<W> {
        self.fresh::<W>()
    }

    fn get<W: Width>(&mut self, _r: StateRef<W>) -> Self::V<W> {
        self.fresh::<W>()
    }

    fn set<W: Width>(&mut self, _r: StateRef<W>, _v: Self::V<W>) {}

    fn get_indexed<W: Width>(&mut self, _a: StateArray<W>, _i: Self::V<W32>) -> Self::V<W> {
        self.fresh::<W>()
    }

    fn set_indexed<W: Width>(&mut self, _a: StateArray<W>, _i: Self::V<W32>, _v: Self::V<W>) {}

    fn add<W: Width>(&mut self, _a: Self::V<W>, _b: Self::V<W>) -> Self::V<W> {
        self.fresh::<W>()
    }

    fn add_with_carry<W: Width>(
        &mut self,
        _a: Self::V<W>,
        _b: Self::V<W>,
        _c: Self::B,
    ) -> (Self::V<W>, Self::B, Self::B) {
        (
            self.fresh::<W>(),
            IrCond(self.ir.next),
            IrCond(self.ir.next + 1),
        )
    }

    fn shl<W: Width>(&mut self, _a: Self::V<W>, _n: Self::V<W>) -> Self::V<W> {
        self.fresh::<W>()
    }

    fn udiv<W: Width>(&mut self, _a: Self::V<W>, _b: Self::V<W>) -> Self::V<W> {
        self.fresh::<W>()
    }

    fn zext<F: Width, T: Width>(&mut self, _a: Self::V<F>) -> Self::V<T> {
        self.fresh::<T>()
    }

    fn sext<F: Width, T: Width>(&mut self, _a: Self::V<F>) -> Self::V<T> {
        self.fresh::<T>()
    }

    fn trunc<F: Width, T: Width>(&mut self, _a: Self::V<F>) -> Self::V<T> {
        self.fresh::<T>()
    }

    fn cmp<W: Width>(&mut self, _op: Cmp, _a: Self::V<W>, _b: Self::V<W>) -> Self::B {
        IrCond(self.ir.next)
    }

    fn select<W: Width>(&mut self, _c: Self::B, _t: Self::V<W>, _f: Self::V<W>) -> Self::V<W> {
        self.fresh::<W>()
    }

    fn load<W: Width>(
        &mut self,
        _addr: Self::V<W64>,
        _acc: Access,
    ) -> Result<Self::V<W>, Self::Exit> {
        Ok(self.fresh::<W>())
    }

    fn store<W: Width>(
        &mut self,
        _addr: Self::V<W64>,
        _v: Self::V<W>,
        _acc: Access,
    ) -> Result<(), Self::Exit> {
        Ok(())
    }

    fn probe(&mut self, _addr: Self::V<W64>, _len: u32, _acc: Access) -> Result<(), Self::Exit> {
        Ok(())
    }

    fn cmpxchg<W: Width>(
        &mut self,
        _addr: Self::V<W64>,
        _old: Self::V<W>,
        _new: Self::V<W>,
        _acc: Access,
    ) -> Result<Self::V<W>, Self::Exit> {
        Ok(self.fresh::<W>())
    }

    fn if_then<F>(&mut self, _c: Self::B, _then: F) -> Result<(), Self::Exit>
    where
        F: FnOnce(&mut Self) -> Result<(), Self::Exit>,
    {
        Ok(())
    }

    fn jump(&mut self, _target: Self::V<W64>) {}

    fn branch(&mut self, _c: Self::B, _target: u64) {}

    fn raise(&mut self, _e: GuestException) -> Self::Exit {
        IrExit("raise".to_string())
    }

    fn call<H: Helper>(&mut self, _args: H::Args<Self>) -> Result<H::Ret<Self>, Self::Exit>
    where
        Self: Sized,
    {
        todo!("helper call")
    }

    fn param<P: Param>(&mut self) -> P::Value {
        todo!("param")
    }

    fn timing_hint(&mut self, _key: HintKey, _v: Self::V<W64>) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_sem::W32;

    #[test]
    fn fresh_values_differ() {
        let mut b = IrBackend::new();
        let a: IrVal = b.konst::<W32>(1);
        let c: IrVal = b.konst::<W32>(2);
        assert_ne!(a, c);
    }
}
