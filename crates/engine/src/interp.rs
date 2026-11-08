//! インタプリタのバックエンド。具体的な整数でその場で実行する。
//!
//! 境界条件は全域で定義する。シフト量が幅以上の論理シフトは 0、
//! 除数が 0 の `udiv` は全ビット 1 を返す。ISA ごとの切り詰めは意味論側で書く。

use polyisa_mem::{Access, AddressSpace, MemError, VirtAddr};
use polyisa_sem::{
    Backend, Cmp, GuestException, Helper, HintKey, Param, StateArray, StateRef, W32, W64, Width,
};

/// インタプリタの退出理由。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum InterpExit {
    Exception(GuestException),
    Unimplemented(String),
}

/// 実行の続き。分岐の記録に使う。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Ctrl {
    #[default]
    Fallthrough,
    Jump(u64),
}

/// 具体的な値で実行するバックエンド。
pub struct InterpBackend {
    /// CPU 状態の素直なバイト列。配置は生成コードの `StateRef` に従う。
    pub state: Vec<u8>,
    /// ゲストメモリ。所有する単純な構成で、共有は後の段階で足す。
    pub mem: AddressSpace,
    /// 直前の制御。`jump` と `branch` が更新する。
    pub ctrl: Ctrl,
}

impl InterpBackend {
    #[must_use]
    pub fn new(state_bytes: usize) -> Self {
        Self {
            state: vec![0u8; state_bytes],
            mem: AddressSpace::new(),
            ctrl: Ctrl::Fallthrough,
        }
    }

    fn state_range<W: Width>(&self, r: StateRef<W>) -> Option<(usize, usize)> {
        let n = (W::BITS / 8) as usize;
        let off = r.offset();
        self.state.get(off..off + n).map(|_| (off, n))
    }
}

impl Backend for InterpBackend {
    type V<W: Width> = W::Repr;
    type B = bool;
    type Exit = InterpExit;

    fn konst<W: Width>(&mut self, v: W::Repr) -> Self::V<W> {
        v
    }

    fn get<W: Width>(&mut self, r: StateRef<W>) -> Self::V<W> {
        let (off, n) = self.state_range(r).expect("state offset");
        let mut buf = [0u8; 16];
        buf[..n].copy_from_slice(&self.state[off..off + n]);
        W::from_u128(u128::from_le_bytes(buf))
    }

    fn set<W: Width>(&mut self, r: StateRef<W>, v: Self::V<W>) {
        let (off, n) = self.state_range(r).expect("state offset");
        let buf = W::to_u128(v).to_le_bytes();
        self.state[off..off + n].copy_from_slice(&buf[..n]);
    }

    fn get_indexed<W: Width>(&mut self, a: StateArray<W>, i: Self::V<W32>) -> Self::V<W> {
        let off = a.offset() + (i as usize) * a.stride();
        self.get(StateRef::<W>::from_offset(off))
    }

    fn set_indexed<W: Width>(&mut self, a: StateArray<W>, i: Self::V<W32>, v: Self::V<W>) {
        let off = a.offset() + (i as usize) * a.stride();
        self.set(StateRef::<W>::from_offset(off), v);
    }

    fn add<W: Width>(&mut self, a: Self::V<W>, b: Self::V<W>) -> Self::V<W> {
        W::from_u128(W::to_u128(a).wrapping_add(W::to_u128(b)))
    }

    fn add_with_carry<W: Width>(
        &mut self,
        a: Self::V<W>,
        b: Self::V<W>,
        c: Self::B,
    ) -> (Self::V<W>, Self::B, Self::B) {
        let (r, carry, overflow) =
            polyisa_bits::add_carry(to_u64::<W>(a), to_u64::<W>(b), c, W::BITS);
        (from_u64::<W>(r), carry, overflow)
    }

    fn shl<W: Width>(&mut self, a: Self::V<W>, n: Self::V<W>) -> Self::V<W> {
        let shift = to_u64::<W>(n);
        if shift >= u64::from(W::BITS) {
            from_u64::<W>(0)
        } else {
            from_u64::<W>(to_u64::<W>(a) << shift)
        }
    }

    fn udiv<W: Width>(&mut self, a: Self::V<W>, b: Self::V<W>) -> Self::V<W> {
        match to_u64::<W>(a).checked_div(to_u64::<W>(b)) {
            Some(q) => from_u64::<W>(q),
            None => from_u64::<W>(mask_bits(W::BITS)),
        }
    }

    fn zext<F: Width, T: Width>(&mut self, a: Self::V<F>) -> Self::V<T> {
        from_u128::<T>(F::to_u128(a))
    }

    fn sext<F: Width, T: Width>(&mut self, a: Self::V<F>) -> Self::V<T> {
        from_u128::<T>(polyisa_bits::sign_extend(to_u64::<F>(a), F::BITS) as u128)
    }

    fn trunc<F: Width, T: Width>(&mut self, a: Self::V<F>) -> Self::V<T> {
        from_u128::<T>(F::to_u128(a))
    }

    fn cmp<W: Width>(&mut self, op: Cmp, a: Self::V<W>, b: Self::V<W>) -> Self::B {
        let (a, b) = (to_u64::<W>(a), to_u64::<W>(b));
        match op {
            Cmp::Eq => a == b,
            Cmp::Ne => a != b,
            Cmp::LtU => a < b,
            Cmp::LtS => (a as i64) < (b as i64),
            Cmp::GtU => a > b,
            Cmp::GtS => (a as i64) > (b as i64),
            Cmp::LeU => a <= b,
            Cmp::LeS => (a as i64) <= (b as i64),
            Cmp::GeU => a >= b,
            Cmp::GeS => (a as i64) >= (b as i64),
        }
    }

    fn select<W: Width>(&mut self, c: Self::B, t: Self::V<W>, f: Self::V<W>) -> Self::V<W> {
        if c { t } else { f }
    }

    fn load<W: Width>(
        &mut self,
        addr: Self::V<W64>,
        acc: Access,
    ) -> Result<Self::V<W>, Self::Exit> {
        let bytes = (W::BITS / 8) as usize;
        self.mem
            .read_value(VirtAddr(addr), bytes, acc)
            .map(from_u64::<W>)
            .map_err(|e| self.mem_exit(addr, e, acc))
    }

    fn store<W: Width>(
        &mut self,
        addr: Self::V<W64>,
        v: Self::V<W>,
        acc: Access,
    ) -> Result<(), Self::Exit> {
        let bytes = (W::BITS / 8) as usize;
        self.mem
            .write_value(VirtAddr(addr), to_u64::<W>(v), bytes, acc)
            .map_err(|e| self.mem_exit(addr, e, acc))
    }

    fn probe(&mut self, addr: Self::V<W64>, len: u32, acc: Access) -> Result<(), Self::Exit> {
        // 全範囲の可否を確かめるため、読み出して捨てる。
        let mut tmp = vec![0u8; len as usize];
        self.mem
            .read(VirtAddr(addr), &mut tmp, acc)
            .map_err(|e| self.mem_exit(addr, e, acc))
    }

    fn cmpxchg<W: Width>(
        &mut self,
        addr: Self::V<W64>,
        old: Self::V<W>,
        new: Self::V<W>,
        acc: Access,
    ) -> Result<Self::V<W>, Self::Exit> {
        // 単一ホストスレッドの前提では読み書きの組で正しい。
        let cur: Self::V<W> = self.load::<W>(addr, acc)?;
        if to_u64::<W>(cur) == to_u64::<W>(old) {
            self.store::<W>(addr, new, acc)?;
        }
        Ok(cur)
    }

    fn if_then<F>(&mut self, c: Self::B, then: F) -> Result<(), Self::Exit>
    where
        F: FnOnce(&mut Self) -> Result<(), Self::Exit>,
    {
        if c {
            then(self)?;
        }
        Ok(())
    }

    fn jump(&mut self, target: Self::V<W64>) {
        self.ctrl = Ctrl::Jump(target);
    }

    fn branch(&mut self, c: Self::B, target: u64) {
        if c {
            self.ctrl = Ctrl::Jump(target);
        }
    }

    fn raise(&mut self, e: GuestException) -> Self::Exit {
        InterpExit::Exception(e)
    }

    fn call<H: Helper>(&mut self, _args: H::Args<Self>) -> Result<H::Ret<Self>, Self::Exit>
    where
        Self: Sized,
    {
        Err(InterpExit::Unimplemented("helper".to_string()))
    }

    fn param<P: Param>(&mut self) -> P::Value {
        panic!("param: 挙動パラメータは CPU モデルの結び付け後に読む")
    }

    fn timing_hint(&mut self, _key: HintKey, _v: Self::V<W64>) {}
}

impl InterpBackend {
    fn mem_exit(&self, addr: u64, e: MemError, acc: Access) -> InterpExit {
        match e {
            MemError::NotAligned => InterpExit::Exception(GuestException {
                kind: polyisa_sem::ExceptionKind::Align,
                code: 0,
                addr: Some(addr),
                in_delay_slot: false,
            }),
            MemError::PageFault | MemError::OutOfMemory => {
                let _ = acc;
                InterpExit::Exception(GuestException {
                    kind: polyisa_sem::ExceptionKind::PageFault,
                    code: 0,
                    addr: Some(addr),
                    in_delay_slot: false,
                })
            }
        }
    }
}

fn to_u64<W: Width>(v: W::Repr) -> u64 {
    // 128 ビットの値は下位 64 ビットだけを見る。
    // `W128` の全幅の意味論は後の段階で足す。
    W::to_u128(v) as u64
}

fn from_u64<W: Width>(v: u64) -> W::Repr {
    from_u128::<W>(u128::from(v))
}

fn from_u128<W: Width>(v: u128) -> W::Repr {
    W::from_u128(v & mask_u128(W::BITS))
}

const fn mask_bits(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

const fn mask_u128(bits: u32) -> u128 {
    if bits >= 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_mem::{AccessKind, Align, Endian, Perms};
    use polyisa_sem::{W32, W64};

    fn backend() -> InterpBackend {
        InterpBackend::new(64)
    }

    #[test]
    fn total_ops() {
        let mut b = backend();
        // 幅以上のシフトは 0。
        assert_eq!(b.shl::<W32>(0xffff_ffff, 32), 0);
        // ゼロ除算は全ビット 1。
        assert_eq!(b.udiv::<W32>(1, 0), 0xffff_ffff);
        // 通常の演算。
        assert_eq!(b.add::<W32>(0xffff_ffff, 1), 0);
    }

    #[test]
    fn state_roundtrip() {
        let mut b = backend();
        let r = StateRef::<W64>::from_offset(8);
        b.set(r, 0x1234_5678_9abc_def0);
        assert_eq!(b.get(r), 0x1234_5678_9abc_def0);
    }

    #[test]
    fn mem_load_store() {
        let mut b = backend();
        b.mem.map(VirtAddr(0x1000), 1, Perms::RW).unwrap();
        let acc = Access {
            endian: Endian::Le,
            align: Align::Natural,
            kind: AccessKind::DataRead,
        };
        b.store::<W32>(0x1000, 0xdead_beef, acc).unwrap();
        let v: u32 = b.load::<W32>(0x1000, acc).unwrap();
        assert_eq!(v, 0xdead_beef);
        // 整列違反は例外。
        assert!(b.load::<W32>(0x1001, acc).is_err());
    }

    #[test]
    fn cmpxchg_semantics() {
        let mut b = backend();
        b.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
        let acc = Access {
            endian: Endian::Le,
            align: Align::Natural,
            kind: AccessKind::AtomicRw,
        };
        b.store::<W32>(0x2000, 1, acc).unwrap();
        let cur = b.cmpxchg::<W32>(0x2000, 1, 2, acc).unwrap();
        assert_eq!(cur, 1);
        let cur = b.cmpxchg::<W32>(0x2000, 1, 3, acc).unwrap();
        assert_eq!(cur, 2);
    }
}
