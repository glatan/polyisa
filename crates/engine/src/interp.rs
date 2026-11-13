// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! インタプリタのバックエンド。具体的な整数でその場で実行する。
//!
//! 境界条件は全域で定義する。シフト量が幅以上の論理シフトは 0、
//! 除数が 0 の `udiv` は全ビット 1 を返す。ISA ごとの切り詰めは意味論側で書く。

use polyisa_mem::{Access, AddressSpace, MemError, VirtAddr};
use polyisa_sem::{
    Backend, Cmp, GuestException, Helper, HintKey, Param, StateArray, StateRef, W32, W64, Width,
};
use polyisa_softfloat::{F32 as SF32, F64 as SF64, Rm as FpRm};

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
#[derive(Clone)]
pub struct InterpBackend {
    /// CPU 状態の素直なバイト列。配置は生成コードの `StateRef` に従う。
    pub state: Vec<u8>,
    /// ゲストメモリ。所有する単純な構成で、共有は後の段階で足す。
    pub mem: AddressSpace,
    /// 直前の制御。`jump` と `branch` が更新する。
    pub ctrl: Ctrl,
    /// 予約付きロードの予約。条件付きストアとゲストスレッドの切り替えで解除する。
    pub reservation: polyisa_mem::Reservation,
    /// 蓄積した浮動小数点例外フラグ。sem が読み出して fcsr に積む。
    pub fp_flags: u8,
    /// ゲストアドレスに掛けるマスク。32 ビットゲストは実効アドレスが
    /// 32 ビットで折り返すので、意味論が 64 ビットで組み立てたアドレスを
    /// アクセス直前に切る。JIT 経路はこの層を通らないため別途対応が要る。
    pub addr_mask: u64,
}

impl InterpBackend {
    #[must_use]
    pub fn new(state_bytes: usize) -> Self {
        Self {
            state: vec![0u8; state_bytes],
            mem: AddressSpace::new(),
            ctrl: Ctrl::Fallthrough,
            reservation: polyisa_mem::Reservation::empty(),
            fp_flags: 0,
            addr_mask: u64::MAX,
        }
    }

    fn state_range<W: Width>(&self, r: StateRef<W>) -> Option<(usize, usize)> {
        let n = (W::BITS / 8) as usize;
        let off = r.offset();
        self.state.get(off..off + n).map(|_| (off, n))
    }

    /// 書き込みによる予約の解除。重なる範囲への書き込みで予約を失う。
    fn break_reservation(&mut self, addr: u64, len: u32) {
        let r = self.reservation;
        if r.valid && addr < r.addr.0 + u64::from(r.len) && r.addr.0 < addr + u64::from(len) {
            self.reservation.valid = false;
        }
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

    fn sub<W: Width>(&mut self, a: Self::V<W>, b: Self::V<W>) -> Self::V<W> {
        W::from_u128(W::to_u128(a).wrapping_sub(W::to_u128(b)))
    }

    fn and<W: Width>(&mut self, a: Self::V<W>, b: Self::V<W>) -> Self::V<W> {
        W::from_u128(W::to_u128(a) & W::to_u128(b))
    }

    fn or<W: Width>(&mut self, a: Self::V<W>, b: Self::V<W>) -> Self::V<W> {
        W::from_u128(W::to_u128(a) | W::to_u128(b))
    }

    fn xor<W: Width>(&mut self, a: Self::V<W>, b: Self::V<W>) -> Self::V<W> {
        W::from_u128(W::to_u128(a) ^ W::to_u128(b))
    }

    fn not<W: Width>(&mut self, a: Self::V<W>) -> Self::V<W> {
        from_u128::<W>(!W::to_u128(a))
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
        // 全域定義：幅以上のシフトは 0。
        if W::to_u128(n) >= u128::from(W::BITS) {
            from_u128::<W>(0)
        } else {
            from_u128::<W>(W::to_u128(a) << W::to_u128(n))
        }
    }

    fn shr_l<W: Width>(&mut self, a: Self::V<W>, n: Self::V<W>) -> Self::V<W> {
        // 全域定義：幅以上のシフトは 0。
        if W::to_u128(n) >= u128::from(W::BITS) {
            from_u128::<W>(0)
        } else {
            from_u128::<W>(W::to_u128(a) >> W::to_u128(n))
        }
    }

    fn shr_a<W: Width>(&mut self, a: Self::V<W>, n: Self::V<W>) -> Self::V<W> {
        // 全域定義：幅以上のシフトは符号ビットで埋める。
        let w = W::BITS;
        let ext = ((W::to_u128(a) << (128 - w)) as i128) >> (128 - w);
        let s = W::to_u128(n);
        if s >= 128 {
            from_u128::<W>(if ext < 0 { u128::MAX } else { 0 })
        } else {
            from_u128::<W>((ext >> s) as u128)
        }
    }

    fn udiv<W: Width>(&mut self, a: Self::V<W>, b: Self::V<W>) -> Self::V<W> {
        match W::to_u128(a).checked_div(W::to_u128(b)) {
            Some(q) => from_u128::<W>(q),
            // 全域定義：0 除算は全ビット 1。
            None => from_u128::<W>(mask_u128(W::BITS)),
        }
    }

    fn urem<W: Width>(&mut self, a: Self::V<W>, b: Self::V<W>) -> Self::V<W> {
        match W::to_u128(a).checked_rem(W::to_u128(b)) {
            Some(r) => from_u128::<W>(r),
            // 全域定義：0 除算の剰余は被除数。
            None => from_u128::<W>(W::to_u128(a)),
        }
    }

    fn mul<W: Width>(&mut self, a: Self::V<W>, b: Self::V<W>) -> Self::V<W> {
        from_u128::<W>(W::to_u128(a).wrapping_mul(W::to_u128(b)))
    }

    fn mulh<W: Width>(&mut self, a: Self::V<W>, b: Self::V<W>) -> Self::V<W> {
        // 符号付き×符号付きの上位。128 ビットに収まらない幅は後の段階で足す。
        let w = W::BITS;
        let ah = sext_to_i128(W::to_u128(a), w);
        let bh = sext_to_i128(W::to_u128(b), w);
        from_u128::<W>(((ah.wrapping_mul(bh) >> w) & mask_i128(w)) as u128)
    }

    fn mulhsu<W: Width>(&mut self, a: Self::V<W>, b: Self::V<W>) -> Self::V<W> {
        // 符号付き×符号なしの上位。64 ビット以下では積が 128 ビットに収まる。
        let w = W::BITS;
        let ah = sext_to_i128(W::to_u128(a), w);
        let bh = W::to_u128(b) as i128;
        from_u128::<W>((ah.wrapping_mul(bh) >> w) as u128)
    }

    fn mulhu<W: Width>(&mut self, a: Self::V<W>, b: Self::V<W>) -> Self::V<W> {
        let w = W::BITS;
        from_u128::<W>((W::to_u128(a).wrapping_mul(W::to_u128(b)) >> w) & mask_u128(w))
    }

    fn sdiv<W: Width>(&mut self, a: Self::V<W>, b: Self::V<W>) -> Self::V<W> {
        let w = W::BITS;
        let sa = sext_to_i128(W::to_u128(a), w);
        let sb = sext_to_i128(W::to_u128(b), w);
        match sb {
            // 全域定義：0 除算は全ビット 1、最小値の -1 除算は最小値。
            0 => from_u128::<W>(mask_u128(w)),
            _ => from_u128::<W>(sa.wrapping_div(sb) as u128),
        }
    }

    fn srem<W: Width>(&mut self, a: Self::V<W>, b: Self::V<W>) -> Self::V<W> {
        let w = W::BITS;
        let sa = sext_to_i128(W::to_u128(a), w);
        let sb = sext_to_i128(W::to_u128(b), w);
        match sb {
            // 全域定義：0 除算の剰余は被除数。
            0 => from_u128::<W>(W::to_u128(a)),
            _ => from_u128::<W>(sa.wrapping_rem(sb) as u128),
        }
    }

    // 浮動小数点演算は softfloat に委譲する。F32 と F64 で分岐する。
    fn fadd<F: Width>(&mut self, a: Self::V<F>, b: Self::V<F>) -> Self::V<F> {
        let (v, f) = fbin::<F>(F::to_u128(a), F::to_u128(b), SF32::add, SF64::add);
        self.fp_flags |= f;
        F::from_u128(v)
    }

    fn fsub<F: Width>(&mut self, a: Self::V<F>, b: Self::V<F>) -> Self::V<F> {
        let (v, f) = fbin::<F>(F::to_u128(a), F::to_u128(b), SF32::sub, SF64::sub);
        self.fp_flags |= f;
        F::from_u128(v)
    }

    fn fmul<F: Width>(&mut self, a: Self::V<F>, b: Self::V<F>) -> Self::V<F> {
        let (v, f) = fbin::<F>(F::to_u128(a), F::to_u128(b), SF32::mul, SF64::mul);
        self.fp_flags |= f;
        F::from_u128(v)
    }

    fn fmadd<F: Width>(&mut self, a: Self::V<F>, b: Self::V<F>, c: Self::V<F>) -> Self::V<F> {
        let (v, f) = ftri::<F>(
            F::to_u128(a),
            F::to_u128(b),
            F::to_u128(c),
            SF32::fmadd,
            SF64::fmadd,
        );
        self.fp_flags |= f;
        F::from_u128(v)
    }

    fn fdiv<F: Width>(&mut self, a: Self::V<F>, b: Self::V<F>) -> Self::V<F> {
        let (v, f) = fbin::<F>(F::to_u128(a), F::to_u128(b), SF32::div, SF64::div);
        self.fp_flags |= f;
        F::from_u128(v)
    }

    fn fsqrt<F: Width>(&mut self, a: Self::V<F>) -> Self::V<F> {
        let (v, f) = funa::<F>(F::to_u128(a), SF32::sqrt, SF64::sqrt);
        self.fp_flags |= f;
        F::from_u128(v)
    }

    fn fmin<F: Width>(&mut self, a: Self::V<F>, b: Self::V<F>) -> Self::V<F> {
        let (v, f) = fbin::<F>(F::to_u128(a), F::to_u128(b), SF32::fmin, SF64::fmin);
        self.fp_flags |= f;
        F::from_u128(v)
    }

    fn fmax<F: Width>(&mut self, a: Self::V<F>, b: Self::V<F>) -> Self::V<F> {
        let (v, f) = fbin::<F>(F::to_u128(a), F::to_u128(b), SF32::fmax, SF64::fmax);
        self.fp_flags |= f;
        F::from_u128(v)
    }

    fn fsgnj<F: Width>(&mut self, a: Self::V<F>, b: Self::V<F>) -> Self::V<F> {
        F::from_u128(fsgn::<F>(F::to_u128(a), F::to_u128(b), false, false))
    }

    fn fsgnjn<F: Width>(&mut self, a: Self::V<F>, b: Self::V<F>) -> Self::V<F> {
        F::from_u128(fsgn::<F>(F::to_u128(a), F::to_u128(b), true, false))
    }

    fn fsgnjx<F: Width>(&mut self, a: Self::V<F>, b: Self::V<F>) -> Self::V<F> {
        F::from_u128(fsgn::<F>(F::to_u128(a), F::to_u128(b), false, true))
    }

    fn feq<F: Width>(&mut self, a: Self::V<F>, b: Self::V<F>) -> Self::B {
        let (v, f) = fcmp::<F>(F::to_u128(a), F::to_u128(b), SF32::eq, SF64::eq);
        self.fp_flags |= f;
        v
    }

    fn flt<F: Width>(&mut self, a: Self::V<F>, b: Self::V<F>) -> Self::B {
        let (v, f) = fcmp::<F>(F::to_u128(a), F::to_u128(b), SF32::lt, SF64::lt);
        self.fp_flags |= f;
        v
    }

    fn fle<F: Width>(&mut self, a: Self::V<F>, b: Self::V<F>) -> Self::B {
        let (v, f) = fcmp::<F>(F::to_u128(a), F::to_u128(b), SF32::le, SF64::le);
        self.fp_flags |= f;
        v
    }

    fn fclass<F: Width>(&mut self, a: Self::V<F>) -> Self::V<W32> {
        let (e, m) = if F::BITS == 32 {
            (8u32, 23u32)
        } else {
            (11u32, 52u32)
        };
        fclass_bits(F::to_u128(a) as u64, e, m)
    }

    fn fcvt_s32<F: Width>(&mut self, a: Self::V<F>, rm: u8) -> Self::V<W32> {
        let rm = FpRm::from_bits(rm);
        let (v, f) = match F::BITS {
            32 => SF32::from_bits(F::to_u128(a) as u64).to_i32(rm),
            _ => SF64::from_bits(F::to_u128(a) as u64).to_i32(rm),
        };
        self.fp_flags |= f;
        v as u32
    }

    fn fcvt_u32<F: Width>(&mut self, a: Self::V<F>, rm: u8) -> Self::V<W32> {
        let rm = FpRm::from_bits(rm);
        let (v, f) = match F::BITS {
            32 => SF32::from_bits(F::to_u128(a) as u64).to_u32(rm),
            _ => SF64::from_bits(F::to_u128(a) as u64).to_u32(rm),
        };
        self.fp_flags |= f;
        v
    }

    fn fcvt_s64<F: Width>(&mut self, a: Self::V<F>, rm: u8) -> Self::V<W64> {
        let (v, f) = fcvti::<F>(F::to_u128(a), FpRm::from_bits(rm));
        self.fp_flags |= f;
        v as u64
    }

    fn fcvt_u64<F: Width>(&mut self, a: Self::V<F>, rm: u8) -> Self::V<W64> {
        let (v, f) = fcvtu::<F>(F::to_u128(a), FpRm::from_bits(rm));
        self.fp_flags |= f;
        v
    }

    fn fcvt_from_s32<F: Width>(&mut self, a: Self::V<W32>, rm: u8) -> Self::V<F> {
        let v = a as i32 as i64;
        let rm = FpRm::from_bits(rm);
        F::from_u128(match F::BITS {
            32 => {
                let (r, f) = SF32::from_i64(v, rm);
                self.fp_flags |= f;
                u128::from(r.bits())
            }
            _ => {
                let (r, f) = SF64::from_i64(v, rm);
                self.fp_flags |= f;
                u128::from(r.bits())
            }
        })
    }

    fn fcvt_from_u32<F: Width>(&mut self, a: Self::V<W32>, rm: u8) -> Self::V<F> {
        let v = a as u64;
        let rm = FpRm::from_bits(rm);
        F::from_u128(match F::BITS {
            32 => {
                let (r, f) = SF32::from_u64(v, rm);
                self.fp_flags |= f;
                u128::from(r.bits())
            }
            _ => {
                let (r, f) = SF64::from_u64(v, rm);
                self.fp_flags |= f;
                u128::from(r.bits())
            }
        })
    }

    fn fcvt_from_s64<F: Width>(&mut self, a: Self::V<W64>, rm: u8) -> Self::V<F> {
        let rm = FpRm::from_bits(rm);
        F::from_u128(match F::BITS {
            32 => {
                let (r, f) = SF32::from_i64(a as i64, rm);
                self.fp_flags |= f;
                u128::from(r.bits())
            }
            _ => {
                let (r, f) = SF64::from_i64(a as i64, rm);
                self.fp_flags |= f;
                u128::from(r.bits())
            }
        })
    }

    fn fcvt_from_u64<F: Width>(&mut self, a: Self::V<W64>, rm: u8) -> Self::V<F> {
        let rm = FpRm::from_bits(rm);
        match F::BITS {
            32 => {
                let (r, f) = SF32::from_u64(a, rm);
                self.fp_flags |= f;
                F::from_u128(u128::from(r.bits()))
            }
            _ => {
                let (r, f) = SF64::from_u64(a, rm);
                self.fp_flags |= f;
                F::from_u128(u128::from(r.bits()))
            }
        }
    }

    fn fcvt_ff<F: Width, T: Width>(&mut self, a: Self::V<F>, rm: u8) -> Self::V<T> {
        let v = F::to_u128(a);
        let rm = FpRm::from_bits(rm);
        let out: u128 = match (F::BITS, T::BITS) {
            (32, 64) => {
                let (r, f) = SF32::from_bits(v as u64).to_f64(rm);
                self.fp_flags |= f;
                u128::from(r.bits())
            }
            (64, 32) => {
                let (r, f) = SF64::from_bits(v as u64).to_f32(rm);
                self.fp_flags |= f;
                u128::from(r.bits())
            }
            (32, 32) | (64, 64) => v,
            _ => unimplemented!("float conversion"),
        };
        T::from_u128(out)
    }

    fn fp_flags(&mut self) -> u8 {
        let f = self.fp_flags;
        self.fp_flags = 0;
        f
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
        // 128ビット幅は u128 で直接比べる（to_u64 では上位が落ち、64-BITS が負になる）。
        if W::BITS > 64 {
            let (x, y) = (W::to_u128(a), W::to_u128(b));
            // 符号付きは最上位ビットを符号とみなす。W128 では as i128 でよい。
            let (sx, sy) = (x as i128, y as i128);
            return match op {
                Cmp::Eq => x == y,
                Cmp::Ne => x != y,
                Cmp::LtU => x < y,
                Cmp::LtS => sx < sy,
                Cmp::GtU => x > y,
                Cmp::GtS => sx > sy,
                Cmp::LeU => x <= y,
                Cmp::LeS => sx <= sy,
                Cmp::GeU => x >= y,
                Cmp::GeS => sx >= sy,
            };
        }
        let (a, b) = (to_u64::<W>(a), to_u64::<W>(b));
        // 符号付き比較は幅の最上位ビットを符号とみなす。
        // ゼロ拡張のまま `as i64` すると W32 の負値が正とみなされる。
        let shift = 64 - W::BITS;
        let (sa, sb) = (
            ((a << shift) as i64) >> shift,
            ((b << shift) as i64) >> shift,
        );
        match op {
            Cmp::Eq => a == b,
            Cmp::Ne => a != b,
            Cmp::LtU => a < b,
            Cmp::LtS => sa < sb,
            Cmp::GtU => a > b,
            Cmp::GtS => sa > sb,
            Cmp::LeU => a <= b,
            Cmp::LeS => sa <= sb,
            Cmp::GeU => a >= b,
            Cmp::GeS => sa >= sb,
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
        let addr = addr & self.addr_mask;
        let bytes = (W::BITS / 8) as usize;
        if bytes <= 8 {
            return self
                .mem
                .read_value(VirtAddr(addr), bytes, acc)
                .map(from_u64::<W>)
                .map_err(|e| self.mem_exit(addr, e, acc));
        }
        // 128ビットのような幅広アクセスは生読みして u128 に組む。
        let mut buf = vec![0u8; bytes];
        self.mem
            .read(VirtAddr(addr), &mut buf, acc)
            .map_err(|e| self.mem_exit(addr, e, acc))?;
        let mut v: u128 = 0;
        match acc.endian {
            polyisa_mem::Endian::Le => {
                for (i, b) in buf.iter().enumerate() {
                    v |= (*b as u128) << (8 * i);
                }
            }
            polyisa_mem::Endian::Be => {
                for b in buf.iter() {
                    v = (v << 8) | (*b as u128);
                }
            }
        }
        Ok(from_u128::<W>(v))
    }

    fn store<W: Width>(
        &mut self,
        addr: Self::V<W64>,
        v: Self::V<W>,
        acc: Access,
    ) -> Result<(), Self::Exit> {
        let addr = addr & self.addr_mask;
        let bytes = (W::BITS / 8) as usize;
        self.break_reservation(addr, bytes as u32);
        if bytes <= 8 {
            return self
                .mem
                .write_value(VirtAddr(addr), to_u64::<W>(v), bytes, acc)
                .map_err(|e| self.mem_exit(addr, e, acc));
        }
        // 128ビットのような幅広アクセスは u128 から生書きする。
        let mut buf = vec![0u8; bytes];
        let v128 = W::to_u128(v);
        match acc.endian {
            polyisa_mem::Endian::Le => {
                for (i, b) in buf.iter_mut().enumerate() {
                    *b = ((v128 >> (8 * i)) & 0xff) as u8;
                }
            }
            polyisa_mem::Endian::Be => {
                for (i, b) in buf.iter_mut().enumerate() {
                    *b = ((v128 >> (8 * (bytes - 1 - i))) & 0xff) as u8;
                }
            }
        }
        self.mem
            .write(VirtAddr(addr), &buf)
            .map_err(|e| self.mem_exit(addr, e, acc))
    }

    fn probe(&mut self, addr: Self::V<W64>, len: u32, acc: Access) -> Result<(), Self::Exit> {
        let addr = addr & self.addr_mask;
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

    fn load_reserved<W: Width>(
        &mut self,
        addr: Self::V<W64>,
        acc: Access,
    ) -> Result<Self::V<W>, Self::Exit> {
        let addr = addr & self.addr_mask;
        let v: Self::V<W> = self.load::<W>(addr, acc)?;
        self.reservation = polyisa_mem::Reservation {
            addr: VirtAddr(addr),
            len: W::BITS / 8,
            valid: true,
        };
        Ok(v)
    }

    fn store_conditional<W: Width>(
        &mut self,
        addr: Self::V<W64>,
        v: Self::V<W>,
        acc: Access,
    ) -> Result<Self::B, Self::Exit> {
        let addr = addr & self.addr_mask;
        let r = self.reservation;
        // 条件付きストアの実行で予約は解除される。
        self.reservation.valid = false;
        let ok = r.valid && r.addr.0 == addr && r.len == W::BITS / 8;
        if ok {
            self.store::<W>(addr, v, acc)?;
        }
        Ok(ok)
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

const fn mask_u128(bits: u32) -> u128 {
    if bits >= 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    }
}

/// `w` ビットの値を `i128` に符号拡張する。M 拡張は 64 ビット以下で使う。
fn sext_to_i128(v: u128, w: u32) -> i128 {
    (((v & mask_u128(w)) << (128 - w)) as i128) >> (128 - w)
}

/// 二項の浮動小数点演算を `F32` と `F64` に振り分ける。
fn fbin<F: Width>(
    a: u128,
    b: u128,
    f32op: fn(SF32, SF32) -> (SF32, u8),
    f64op: fn(SF64, SF64) -> (SF64, u8),
) -> (u128, u8) {
    match F::BITS {
        32 => {
            let (v, f) = f32op(SF32::from_bits(a as u64), SF32::from_bits(b as u64));
            (u128::from(v.bits()), f)
        }
        _ => {
            let (v, f) = f64op(SF64::from_bits(a as u64), SF64::from_bits(b as u64));
            (u128::from(v.bits()), f)
        }
    }
}

/// 単項の浮動小数点演算を振り分ける。
fn funa<F: Width>(
    a: u128,
    f32op: fn(SF32) -> (SF32, u8),
    f64op: fn(SF64) -> (SF64, u8),
) -> (u128, u8) {
    match F::BITS {
        32 => {
            let (v, f) = f32op(SF32::from_bits(a as u64));
            (u128::from(v.bits()), f)
        }
        _ => {
            let (v, f) = f64op(SF64::from_bits(a as u64));
            (u128::from(v.bits()), f)
        }
    }
}

/// 浮動小数点の三項演算を振り分ける。
fn ftri<F: Width>(
    a: u128,
    b: u128,
    c: u128,
    f32op: fn(SF32, SF32, SF32) -> (SF32, u8),
    f64op: fn(SF64, SF64, SF64) -> (SF64, u8),
) -> (u128, u8) {
    match F::BITS {
        32 => {
            let (v, f) = f32op(
                SF32::from_bits(a as u64),
                SF32::from_bits(b as u64),
                SF32::from_bits(c as u64),
            );
            (u128::from(v.bits()), f)
        }
        _ => {
            let (v, f) = f64op(
                SF64::from_bits(a as u64),
                SF64::from_bits(b as u64),
                SF64::from_bits(c as u64),
            );
            (u128::from(v.bits()), f)
        }
    }
}

/// 浮動小数点の比較を振り分ける。
fn fcmp<F: Width>(
    a: u128,
    b: u128,
    f32op: fn(SF32, SF32) -> (bool, u8),
    f64op: fn(SF64, SF64) -> (bool, u8),
) -> (bool, u8) {
    match F::BITS {
        32 => f32op(SF32::from_bits(a as u64), SF32::from_bits(b as u64)),
        _ => f64op(SF64::from_bits(a as u64), SF64::from_bits(b as u64)),
    }
}

/// 符号注入。`neg` で反転、`xor` で排他的論理和を取る。
fn fsgn<F: Width>(a: u128, b: u128, neg: bool, xor: bool) -> u128 {
    let sign_bit: u128 = 1 << (F::BITS - 1);
    let mag_mask = sign_bit - 1;
    let mut sign = (b >> (F::BITS - 1)) & 1;
    if xor {
        sign ^= (a >> (F::BITS - 1)) & 1;
    }
    if neg {
        sign ^= 1;
    }
    ((sign << (F::BITS - 1)) | (a & mag_mask)) & mask_u128(F::BITS)
}

/// 符号つき整数への変換。飽和は呼び出し側で行う。
fn fcvti<F: Width>(a: u128, rm: FpRm) -> (i64, u8) {
    match F::BITS {
        32 => SF32::from_bits(a as u64).to_i64(rm),
        _ => SF64::from_bits(a as u64).to_i64(rm),
    }
}

/// 符号なし整数への変換。飽和は呼び出し側で行う。
fn fcvtu<F: Width>(a: u128, rm: FpRm) -> (u64, u8) {
    match F::BITS {
        32 => SF32::from_bits(a as u64).to_u64(rm),
        _ => SF64::from_bits(a as u64).to_u64(rm),
    }
}

/// RISC-V の分類ビット。0: -inf、1: -normal、2: -subnormal、3: -0、
/// 4: +0、5: +subnormal、6: +normal、7: +inf、8: sNaN、9: qNaN。
fn fclass_bits(v: u64, e: u32, m: u32) -> u32 {
    let exp_all = (1u64 << e) - 1;
    let exp = (v >> m) & exp_all;
    let frac = v & ((1u64 << m) - 1);
    let neg = (v >> (e + m)) & 1 == 1;
    let cls = if exp == exp_all {
        if frac == 0 {
            if neg { 0 } else { 7 }
        } else if frac >> (m - 1) & 1 == 1 {
            9
        } else {
            8
        }
    } else if exp == 0 {
        if frac == 0 {
            if neg { 3 } else { 4 }
        } else if neg {
            2
        } else {
            5
        }
    } else if neg {
        1
    } else {
        6
    };
    1u32 << cls
}

const fn mask_i128(bits: u32) -> i128 {
    if bits >= 128 {
        -1
    } else {
        ((1u128 << bits) - 1) as i128
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
