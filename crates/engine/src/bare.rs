// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 裸実行環境。OS パーソナリティなしで vCPU とアドレス空間だけを動かす。
//!
//! 命令の検証に使う。CPU 状態の形はゲスト ISA クレートが決め、
//! ここではメモリの用意と実行の反復の土台だけを提供する。

use polyisa_mem::{AddressSpace, Perms, VirtAddr};

use crate::interp::{Ctrl, InterpBackend, InterpExit};

/// 裸実行の harness。`state_len` はゲストの CPU 状態のバイト数。
#[derive(Clone)]
pub struct BareEnv {
    pub backend: InterpBackend,
    /// 次に実行する仮想アドレス。テストが設定する。
    pub pc: u64,
    /// 実行したステップ数。
    pub steps: u64,
}

impl BareEnv {
    #[must_use]
    pub fn new(state_len: usize) -> Self {
        Self {
            backend: InterpBackend::new(state_len),
            pc: 0,
            steps: 0,
        }
    }

    /// 読み書き可のページを写像する。範囲はページ境界に整列しているとする。
    pub fn map_rw(&mut self, base: u64, count: u64) -> Result<(), polyisa_mem::MemError> {
        self.backend.mem.map(VirtAddr(base), count, Perms::RW)
    }

    /// アドレス空間を取り出す。
    #[must_use]
    pub fn mem(&self) -> &AddressSpace {
        &self.backend.mem
    }

    /// 意味論の断片を 1 ステップとして実行する。`f` が `Ctrl::Jump` を残せば分岐する。
    pub fn step<F>(&mut self, f: F) -> Result<(), InterpExit>
    where
        F: FnOnce(&mut InterpBackend) -> Result<(), InterpExit>,
    {
        self.backend.ctrl = Ctrl::Fallthrough;
        f(&mut self.backend)?;
        match self.backend.ctrl {
            Ctrl::Fallthrough => {}
            Ctrl::Jump(target) => self.pc = target,
        }
        self.steps += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_mem::{Access, AccessKind, Align, Endian};
    use polyisa_sem::{Backend, StateRef, W32, W64};

    const PC: StateRef<W64> = StateRef::<W64>::from_offset(0);

    #[test]
    fn add_semantics_runs_bare() {
        // RISC-V の `add` 相当を意味論の形で書き、裸実行で確かめる。
        // 値の選択はテスト独自のもので、仕様の定数を使わない。
        let mut env = BareEnv::new(8);
        env.map_rw(0x1_0000, 1).unwrap();
        env.backend.set(PC, 0x1_0000u64);

        let rs1 = StateRef::<W32>::from_offset(0);
        let rs2 = StateRef::<W32>::from_offset(4);
        env.backend.set(rs1, 40u32);
        env.backend.set(rs2, 2u32);

        env.step(|b| {
            let x: u32 = b.get(rs1);
            let y: u32 = b.get(rs2);
            let s = b.add::<W32>(x, y);
            b.set(rs1, s);
            Ok(())
        })
        .unwrap();

        assert_eq!(env.backend.get(rs1), 42u32);
        assert_eq!(env.steps, 1);
    }

    #[test]
    fn load_store_roundtrip() {
        let mut env = BareEnv::new(8);
        env.map_rw(0x2_0000, 1).unwrap();
        let acc = Access {
            endian: Endian::Le,
            align: Align::Natural,
            kind: AccessKind::DataRead,
        };
        env.step(|b| b.store::<W32>(0x2_0000, 0xcafe_f00du32, acc).map(|_| ()))
            .unwrap();
        let mut got = 0u32;
        env.step(|b| {
            got = b.load::<W32>(0x2_0000, acc)?;
            Ok(())
        })
        .unwrap();
        assert_eq!(got, 0xcafe_f00d);
    }
}
