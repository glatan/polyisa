// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! AArch32 の入口。`svc #0x123456`（A32）/`svc #0xab`（T32）で
//! `r0` の演算番号・`r1` のパラメータを取る。結果は `r0` へ戻す。
//! `TrapHandler` は `SemiA32` に実装する（A64 側との型衝突を
//! 避ける newtype）。

use super::{Reply, Semi, WordSize};
use polyisa_engine::bare::BareEnv;
use polyisa_engine::run::{TrapHandler, TrapOutcome};
use polyisa_guest_arm::sem::Gpr;
use polyisa_sem::Backend;
use std::ops::{Deref, DerefMut};

/// AArch32 用の semihosting 処理器。
pub struct SemiA32(pub Semi);

impl SemiA32 {
    /// 中身の演算機械を作る。`root` は `Semi::new` と同じ。
    #[must_use]
    pub fn new(root: &str) -> Self {
        Self(Semi::new(root))
    }
}

impl Deref for SemiA32 {
    type Target = Semi;
    fn deref(&self) -> &Semi {
        &self.0
    }
}

impl DerefMut for SemiA32 {
    fn deref_mut(&mut self) -> &mut Semi {
        &mut self.0
    }
}

impl TrapHandler for SemiA32 {
    /// HEAPINFO の heap_base として像の末尾を報告する。
    /// heap_limit・stack 系の 3 語は時計同様 0 のまま。
    fn init_brk(&mut self, image_end: u64) {
        self.0.heap_info[0] = image_end;
    }

    fn handle_trap(&mut self, env: &mut BareEnv, _code: u32) -> TrapOutcome {
        let op = env.backend.get(Gpr(0).state());
        let param = u64::from(env.backend.get(Gpr(1).state()));
        match self.0.call(env, op, param, WordSize::W32) {
            Reply::Ret(v) => {
                env.backend.set(Gpr(0).state(), v as u32);
                TrapOutcome::Handled
            }
            Reply::Exit(c) => TrapOutcome::Exit(c as u32),
            Reply::Unimpl => TrapOutcome::Unimplemented,
        }
    }
}
