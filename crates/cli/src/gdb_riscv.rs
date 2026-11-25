// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `run -g <ポート>`：rv64 のデバッグ対象と RSP サーバの入口。
//!
//! `RiscvDebugEnv` は `DebugTarget` を `BareEnv` + `step_rv` +
//! `os_linux::rv64::sys::Linux`（ecall 処理）+ `Breakpoints` で実装する。
//! レジスタの転送は `RISCV64_REGS` の順（x0–x31・pc・f0–f31・fcsr）で、
//! pc は実行ループが見る `BareEnv::pc`（CpuState の pc 欄ではない）を
//! 読み書きする。対象は linux パーソナリティの rv64 ELF のみ。

use polyisa_engine::bare::BareEnv;
use polyisa_engine::obs::NoObserver;
use polyisa_engine::run::{Breakpoints, Outcome};
use polyisa_gdbstub::riscv::RISCV64_REGS;
use polyisa_gdbstub::target::{DebugTarget, MemError, Stop};
use polyisa_guest_riscv::CpuState;
use polyisa_guest_riscv::sem::{Fpr, Gpr};
use polyisa_mem::{Access, AccessKind, Align, Endian, VirtAddr};
use polyisa_sem::{Backend as _, StateRef, W64};

use crate::run_riscv::{STEP_LIMIT, load_elf_env, step_rv};

/// fcsr（CSR 0x003）の状態での位置。
const FCSR: StateRef<W64> =
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, csr) + 3 * 8);

const GDB_READ: Access = Access {
    endian: Endian::Le,
    align: Align::Unaligned,
    kind: AccessKind::DataRead,
};

/// `run -g <port>` の入口。env 構築は `run_elf_handler` と同じ
/// （`load_elf_env` の ELF 配置・初期スタック・sp 設定まで）で、そのあと
/// `127.0.0.1:<port>` で接続を 1 つ待ち `serve` に対象を渡す。戻り値は
/// ゲストの終了コード（デバッガが殺した・切り離したときは 0）。
pub fn run_elf_gdb(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    port: u16,
) -> Result<u64, String> {
    let (mut env, entry) = load_elf_env(path, argv)?;
    env.pc = entry;
    let listener = std::net::TcpListener::bind(("127.0.0.1", port))
        .map_err(|e| format!("bind 127.0.0.1:{port}: {e}"))?;
    // 0 を渡されたときは割り当てられた実ポートを報告する。
    let addr = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?;
    eprintln!(
        "polyisa: gdb の接続を {addr} で待つ（`target remote :{}`）",
        addr.port()
    );
    let mut target = RiscvDebugEnv::new(env, sel.map_or(0, |s| s.feats));
    polyisa_gdbstub::server::serve(&listener, &mut target).map_err(|e| format!("gdb 接続: {e}"))?;
    Ok(target.exit_code())
}

/// rv64 の `DebugTarget` 実装。
pub struct RiscvDebugEnv {
    env: BareEnv,
    sys: polyisa_os_linux::rv64::sys::Linux,
    bps: Breakpoints,
    feats: u128,
    xml: String,
    exit: Option<u64>,
}

impl RiscvDebugEnv {
    /// 初期化済みの `env`（ELF 配置・スタック・`env.pc` 設定済み）から作る。
    #[must_use]
    pub fn new(env: BareEnv, feats: u128) -> Self {
        Self {
            env,
            sys: polyisa_os_linux::rv64::sys::Linux::default(),
            bps: Breakpoints::new(),
            feats,
            xml: polyisa_gdbstub::riscv::target_xml(RISCV64_REGS),
            exit: None,
        }
    }

    /// 接続が閉じたあとのプロセスの終了コード。
    #[must_use]
    pub fn exit_code(&self) -> u64 {
        self.exit.unwrap_or(0)
    }

    /// `idx` のレジスタを u64 で読む。x0 は常に 0（`Gpr::is_zero` の契約）。
    fn reg_get(&mut self, idx: usize) -> Option<u64> {
        match idx {
            0 => Some(0),
            i @ 1..=31 => Some(self.env.backend.get(Gpr(i as u8).state())),
            32 => Some(self.env.pc),
            i @ 33..=64 => Some(self.env.backend.get(Fpr((i - 33) as u8).state())),
            65 => Some(self.env.backend.get(FCSR)),
            _ => None,
        }
    }

    /// `idx` のレジスタに `v` を書く。x0 への書き込みは捨てる。
    fn reg_put(&mut self, idx: usize, v: u64) -> bool {
        match idx {
            0 => {}
            i @ 1..=31 => self.env.backend.set(Gpr(i as u8).state(), v),
            32 => self.env.pc = v,
            i @ 33..=64 => self.env.backend.set(Fpr((i - 33) as u8).state(), v),
            65 => self.env.backend.set(FCSR, v),
            _ => return false,
        }
        true
    }

    /// 退出した `Outcome` を `Stop` に写す。終了は終了コードを記録する。
    fn outcome_stop(&mut self, o: Outcome) -> Stop {
        match o {
            Outcome::Exit(c) => {
                self.exit = Some(c);
                Stop::Exit(c)
            }
            Outcome::Breakpoint { pc } => Stop::Breakpoint(pc),
            Outcome::Unimplemented { pc, .. } => Stop::Trap(pc),
            Outcome::StepLimit { pc } => Stop::Step(pc),
            Outcome::Deadlock => Stop::Trap(self.env.pc),
        }
    }
}

impl DebugTarget for RiscvDebugEnv {
    fn target_xml(&self) -> &str {
        &self.xml
    }

    fn reg_bytes(&self) -> usize {
        RISCV64_REGS.iter().map(|r| usize::from(r.bits / 8)).sum()
    }

    fn reg_size(&self, idx: usize) -> usize {
        RISCV64_REGS.get(idx).map_or(0, |r| usize::from(r.bits / 8))
    }

    fn read_regs(&mut self, buf: &mut [u8]) {
        let mut off = 0;
        for i in 0..RISCV64_REGS.len() {
            let n = self.reg_size(i);
            let v = self.reg_get(i).unwrap_or(0);
            buf[off..off + n].copy_from_slice(&v.to_le_bytes()[..n]);
            off += n;
        }
    }

    fn write_regs(&mut self, buf: &[u8]) {
        let mut off = 0;
        for i in 0..RISCV64_REGS.len() {
            let n = self.reg_size(i);
            let mut v = [0u8; 8];
            v[..n].copy_from_slice(&buf[off..off + n]);
            self.reg_put(i, u64::from_le_bytes(v));
            off += n;
        }
    }

    fn read_reg(&mut self, idx: usize, buf: &mut [u8]) -> bool {
        let n = self.reg_size(idx);
        let Some(v) = self.reg_get(idx) else {
            return false;
        };
        if buf.len() != n {
            return false;
        }
        buf.copy_from_slice(&v.to_le_bytes()[..n]);
        true
    }

    fn write_reg(&mut self, idx: usize, buf: &[u8]) -> bool {
        let n = self.reg_size(idx);
        if n == 0 || buf.len() != n {
            return false;
        }
        let mut v = [0u8; 8];
        v[..n].copy_from_slice(buf);
        self.reg_put(idx, u64::from_le_bytes(v))
    }

    fn read_mem(&mut self, addr: u64, buf: &mut [u8]) -> Result<(), MemError> {
        self.env
            .backend
            .mem
            .read(VirtAddr(addr), buf, GDB_READ)
            .map_err(|_| MemError)
    }

    fn write_mem(&mut self, addr: u64, buf: &[u8]) -> Result<(), MemError> {
        self.env
            .backend
            .mem
            .write(VirtAddr(addr), buf)
            .map_err(|_| MemError)
    }

    fn pc(&self) -> u64 {
        self.env.pc
    }

    fn step(&mut self) -> Stop {
        let feats = self.feats;
        match step_rv(&mut self.env, &mut self.sys, false, feats) {
            Ok(()) => Stop::Step(self.env.pc),
            Err(o) => self.outcome_stop(o),
        }
    }

    fn resume(&mut self) -> Stop {
        let feats = self.feats;
        let o = polyisa_engine::run::run_observed(
            &mut self.env,
            &mut self.sys,
            STEP_LIMIT,
            |env| env.pc,
            |env, sys| step_rv(env, sys, false, feats),
            self.bps.as_set(),
            &mut NoObserver,
        );
        self.outcome_stop(o)
    }

    fn kill(&mut self) {
        self.exit = Some(self.exit.unwrap_or(0));
    }

    fn detach(&mut self) {
        // 接続を閉じるだけ。対象を動かし続ける形は GD6 の残件。
    }

    fn add_bp(&mut self, addr: u64) -> bool {
        self.bps.insert(addr)
    }

    fn remove_bp(&mut self, addr: u64) -> bool {
        self.bps.remove(addr)
    }
}
