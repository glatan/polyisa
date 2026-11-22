// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! IA-64 Linux の syscall 機械（段階21 IA10）。
//!
//! 発行点は `break 0x100000`（run::step が即値を code に載せて
//! `handle_trap` へ渡す）とゲートページの入口呼出。ゲートは
//! `install_gate_page` が `gate::CODE` に実バンドルを書く形で
//! 供給する（IP フックでなく命令列を置く選択: ia64 のゲートは
//! 固定領域の実行コードで、br.call/br.ret b6 の規約をそのまま
//! 再現できる。via_epc は epc の特権移行だけを差し替えて
//! via_break と同じ形に畳む近似 — Gap: GAP-0068）。
//! 番号は r15−`NR_BASE`、引数は現在フレームの out0–out5
//! （`sem::out_get`。epc 呼出では br.call で sol=0 になった新
//! フレームの先頭に呼出側の引数が写るので、両経路で同じ
//! 読み方が成立する）。結果は r8・r10。単一プロセス・単一
//! スレッド模型で、番号表の本体は IA11 が実装する。
//! Ref: SRC-LINUX-66 — kernel/entry.S, kernel/gate.S.

use std::io::Write as _;

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::InterpBackend;
use polyisa_guest_ia64::{bundle, encode_br_ret, encode_break_m, encode_nop_i, sem};
use polyisa_kernel::FdTable;
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};

use crate::ia64::{NR_BASE, NR_SYSCALLS, brk, errno, gate, nr};
use crate::{TrapHandler, TrapOutcome};

/// write が集めたバイト（テストが読む）。
#[derive(Default)]
pub struct Ia64Io {
    /// 標準出力。
    pub stdout: Vec<u8>,
    /// 標準エラー。
    pub stderr: Vec<u8>,
}

/// IA-64 Linux の syscall 状態機械（IA10 の骨格。fd 表だけ持ち、
/// 状態の残りは表実装の IA11 が足す）。
pub struct Linux {
    /// 標準出力・標準エラーの捕獲。
    pub io: Ia64Io,
    /// 開いたファイルの表（ゲスト fd 3 以降）。
    fds: FdTable,
}

impl Default for Linux {
    fn default() -> Self {
        Self::new()
    }
}

enum WriteFd {
    Stdout,
    Stderr,
    File,
}

impl Linux {
    #[must_use]
    pub fn new() -> Self {
        Self {
            io: Ia64Io::default(),
            fds: FdTable::default(),
        }
    }

    fn acc(&self) -> Access {
        Access {
            endian: Endian::Le,
            align: Align::Unaligned,
            kind: AccessKind::DataRead,
        }
    }

    fn get_bytes(&self, env: &mut BareEnv, addr: u64, n: usize) -> Result<Vec<u8>, u64> {
        let mut buf = vec![0u8; n.min(1 << 22)];
        env.backend
            .mem
            .read(VirtAddr(addr), &mut buf, self.acc())
            .map_err(|_| errno::EFAULT)?;
        Ok(buf)
    }

    /// 書き込み先の分類。
    fn writer(&mut self, fd: u32) -> Result<WriteFd, u64> {
        match fd {
            1 => Ok(WriteFd::Stdout),
            2 => Ok(WriteFd::Stderr),
            _ if self.fds.get(fd).is_some() => Ok(WriteFd::File),
            _ => Err(errno::EBADF),
        }
    }

    fn sys_write(&mut self, env: &mut BareEnv, fd: u32, buf: u64, len: u64) -> Result<u64, u64> {
        let data = self.get_bytes(env, buf, len as usize)?;
        match self.writer(fd)? {
            WriteFd::Stdout => {
                self.io.stdout.extend_from_slice(&data);
                let _ = std::io::stdout().write_all(&data);
                Ok(data.len() as u64)
            }
            WriteFd::Stderr => {
                self.io.stderr.extend_from_slice(&data);
                let _ = std::io::stderr().write_all(&data);
                Ok(data.len() as u64)
            }
            WriteFd::File => match self.fds.get_mut(fd).unwrap().write(&data) {
                Ok(n) => Ok(n as u64),
                Err(_) => Err(errno::EIO),
            },
        }
    }

    /// 表番号 `n` の実装本体。IA11 が表に従って補完する。
    fn dispatch(&mut self, env: &mut BareEnv, n: u64, a: [u64; 6]) -> Result<u64, u64> {
        match n {
            nr::WRITE => self.sys_write(env, a[0] as u32, a[1], a[2]),
            _ => Err(errno::ENOSYS),
        }
    }

    /// 戻り値規約: 成功は r8=値・r10=0、失敗は r8=errno・r10=-1。
    /// r8/r10 の NaT は落とす。
    /// Ref: SRC-LINUX-66 — kernel/entry.S（strace_error の
    /// 反転と r10 設定の規約）.
    fn ret(b: &mut InterpBackend, r: Result<u64, u64>) {
        let (r8, r10) = match r {
            Ok(v) => (v, 0),
            Err(e) => (e, u64::MAX),
        };
        sem::gr_set(b, 8, r8);
        sem::nat_set(b, 8, false);
        sem::gr_set(b, 10, r10);
        sem::nat_set(b, 10, false);
    }

    /// r15 の番号と out0–out5 の引数を読んで dispatch し、
    /// r8/r10 に結果を書く。
    fn syscall(&mut self, env: &mut BareEnv) -> TrapOutcome {
        let b = &mut env.backend;
        // 範囲検査は `n = r15 - NR_BASE` が 0..NR_SYSCALLS。epc
        // 入口の `tnat.nz p10` に倣い r15 が NaT なら EINVAL
        // （break 経路にも同じ近似を適用 — Gap: GAP-0068）。
        if sem::nat_get(b, 15) {
            Self::ret(b, Err(errno::EINVAL));
            return TrapOutcome::Handled;
        }
        let n = sem::gr_get(b, 15).wrapping_sub(NR_BASE);
        let a = [
            sem::out_get(b, 0),
            sem::out_get(b, 1),
            sem::out_get(b, 2),
            sem::out_get(b, 3),
            sem::out_get(b, 4),
            sem::out_get(b, 5),
        ];
        if n == nr::EXIT || n == nr::EXIT_GROUP {
            return TrapOutcome::Exit((a[0] & 0xff) as u32);
        }
        let r = if n < NR_SYSCALLS {
            self.dispatch(env, n, a)
        } else {
            Err(errno::ENOSYS)
        };
        Self::ret(&mut env.backend, r);
        TrapOutcome::Handled
    }
}

impl TrapHandler for Linux {
    fn handle_trap(&mut self, env: &mut BareEnv, code: u32) -> TrapOutcome {
        // __IA64_BREAK_SYSCALL 以外の break 値（KDB/KPROBE は
        // ユーザモードで到達しない）と TRAP_ILL 等の内部番号は
        // 未実装に畳む。
        if code != brk::SYSCALL {
            return TrapOutcome::Unimplemented;
        }
        self.syscall(env)
    }
}

/// ゲート領域を写像し、コードページに via_break/via_epc 入口の
/// バンドルを書く。
///
/// 両入口とも `{ .mib break 0x100000; nop.i 0; br.ret.sptk.many b6 }`
/// （正本 gate.S の __kernel_syscall_via_break と同じ形）。
/// __kernel_syscall_via_epc は epc の特権移行で syscall 本体を
/// 呼ぶが、ユーザに観測される規約（r15/out 引数・r8/r10 戻り・
/// b6 経由の復帰）は同一なので同じバンドルに畳む
/// （Gap: GAP-0068）。`gate::SIGTRAMP` は位置の予約のみで、
/// 中身はシグナル配送の実装時に置く。`gate::ADDR` 側は
/// AT_SYSINFO_EHDR が指す ELF ヘッダページの置き場として
/// 読み出し専用に開ける（中身は IA11 が供給する）。
// Ref: SRC-LINUX-66 — kernel/gate.S, kernel/mm-init.c.
pub fn install_gate_page(env: &mut BareEnv) -> Result<(), String> {
    let brk_w = encode_break_m(&[0, u64::from(brk::SYSCALL)]).ok_or("encode break.m")? as u64;
    let nop_w = encode_nop_i(&[0, 0]).ok_or("encode nop.i")? as u64;
    let ret_w = encode_br_ret(&[0, 6]).ok_or("encode br.ret")? as u64;
    let b = bundle::pack_bundle(8, false, brk_w, nop_w, ret_w);
    let mem = &mut env.backend.mem;
    mem.map(VirtAddr(gate::ADDR), 1, Perms::R)
        .map_err(|e| format!("gate ehdr: {e:?}"))?;
    mem.map(VirtAddr(gate::CODE), 1, Perms::RW)
        .map_err(|e| format!("gate code: {e:?}"))?;
    for addr in [gate::SYSCALL_VIA_BREAK, gate::SYSCALL_VIA_EPC] {
        mem.write(VirtAddr(addr), &b.to_le_bytes())
            .map_err(|e| format!("gate write: {e:?}"))?;
    }
    // コードページは PAGE_GATE（実行専用）に合わせる。
    mem.protect(VirtAddr(gate::CODE), 1, Perms::X)
        .map_err(|e| format!("gate protect: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_engine::run::Outcome;
    use polyisa_guest_ia64::{CpuState, FEAT_ITANIUM, FEAT_ITANIUM2, cfm_bit, encode_nop_b, run};
    use polyisa_sem::Backend as _;

    const CPU: u128 = FEAT_ITANIUM | FEAT_ITANIUM2;
    const BASE: u64 = 0x40_0000;
    const DATA: u64 = 0x50_0000;

    fn env() -> BareEnv {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        env.backend
            .mem
            .map(VirtAddr(BASE), 1, Perms(0b111))
            .unwrap();
        env.backend.mem.map(VirtAddr(DATA), 1, Perms::RW).unwrap();
        env
    }

    fn put_bundle(env: &mut BareEnv, addr: u64, b: u128) {
        env.backend
            .mem
            .write(VirtAddr(addr), &b.to_le_bytes())
            .unwrap();
    }

    /// `{ .mib <slot0>; nop.i; <slot2 B> }`（stop 付き）。
    fn mib(stop: bool, s0: u64, s1: u64, s2: u64) -> u128 {
        bundle::pack_bundle(8, stop, s0, s1, s2)
    }

    /// 現在フレーム（sof, sol）に設定する。
    fn set_frame(env: &mut BareEnv, sof: u64, sol: u64) {
        env.backend.set(sem::cfm_ref(), sof | (sol << cfm_bit::SOL));
    }

    fn break_w() -> u64 {
        encode_break_m(&[0, u64::from(brk::SYSCALL)]).unwrap() as u64
    }

    fn nop_i() -> u64 {
        encode_nop_i(&[0, 0]).unwrap() as u64
    }

    /// break で write(fd=1, buf, len) を発行して次命令群へ戻る。
    /// 引数は現在フレームの out0–out2（sol>0 のフレームで
    /// フレーム位置の解決も兼ねて確かめる）。
    #[test]
    fn break_syscall_write_and_resume() {
        let mut env = env();
        let mut sys = Linux::new();
        // sof=10, sol=4 → out0.. は仮想 r36..。
        set_frame(&mut env, 10, 4);
        sem::gr_set(&mut env.backend, 15, NR_BASE + nr::WRITE);
        for (i, v) in [1u64, DATA, 2].iter().enumerate() {
            sem::gr_set(&mut env.backend, (32 + 4 + i) as u32, *v);
        }
        env.backend.mem.write(VirtAddr(DATA), b"hi").unwrap();
        let nop_b = encode_nop_b(&[0, 0]).unwrap() as u64;
        put_bundle(&mut env, BASE, mib(true, break_w(), nop_i(), nop_b));
        env.pc = BASE;
        run::step(&mut env, &mut sys, CPU).unwrap();
        // r8 = 書いたバイト数、r10 = 0（成功旗）。
        assert_eq!(sem::gr_get(&env.backend, 8), 2);
        assert_eq!(sem::gr_get(&env.backend, 10), 0);
        assert!(!sem::nat_get(&env.backend, 8));
        assert_eq!(sys.io.stdout, b"hi");
        // Handled の復帰は break の次のスロット（戻り先規約）。
        assert_eq!(env.pc, BASE | 1);
        // 残りスロットを進めると次のバンドルへ。
        run::step(&mut env, &mut sys, CPU).unwrap();
        assert_eq!(env.pc, BASE + 16);
    }

    /// 未知番号は ENOSYS（r8=errno・r10=-1）。
    #[test]
    fn unknown_nr_returns_enosys() {
        let mut env = env();
        let mut sys = Linux::new();
        set_frame(&mut env, 8, 0);
        sem::gr_set(&mut env.backend, 15, NR_BASE + NR_SYSCALLS);
        put_bundle(&mut env, BASE, mib(true, break_w(), nop_i(), 0));
        env.pc = BASE;
        run::step(&mut env, &mut sys, CPU).unwrap();
        assert_eq!(sem::gr_get(&env.backend, 8), errno::ENOSYS);
        assert_eq!(sem::gr_get(&env.backend, 10), u64::MAX);
    }

    /// r15 が NaT なら EINVAL（epc 入口の tnat.nz と同じ判定）。
    #[test]
    fn nat_nr_returns_einval() {
        let mut env = env();
        let mut sys = Linux::new();
        set_frame(&mut env, 8, 0);
        sem::gr_set(&mut env.backend, 15, NR_BASE + nr::WRITE);
        sem::nat_set(&mut env.backend, 15, true);
        put_bundle(&mut env, BASE, mib(true, break_w(), nop_i(), 0));
        env.pc = BASE;
        run::step(&mut env, &mut sys, CPU).unwrap();
        assert_eq!(sem::gr_get(&env.backend, 8), errno::EINVAL);
        assert_eq!(sem::gr_get(&env.backend, 10), u64::MAX);
        assert_eq!(sys.io.stdout, Vec::<u8>::new());
    }

    /// syscall 以外の break 値はパーソナリティの未実装（
    /// `Outcome::Unimplemented` に写る）。
    #[test]
    fn non_syscall_break_is_unimplemented() {
        let mut env = env();
        let mut sys = Linux::new();
        let kdb = encode_break_m(&[0, 0x80100]).unwrap() as u64;
        put_bundle(&mut env, BASE, mib(true, kdb, nop_i(), 0));
        env.pc = BASE;
        let r = run::step(&mut env, &mut sys, CPU);
        assert!(matches!(r, Err(Outcome::Unimplemented { .. })));
    }

    /// exit_group は TrapOutcome::Exit → Outcome::Exit に写る。
    #[test]
    fn exit_group_exits() {
        let mut env = env();
        let mut sys = Linux::new();
        set_frame(&mut env, 8, 0);
        sem::gr_set(&mut env.backend, 15, NR_BASE + nr::EXIT_GROUP);
        sem::gr_set(&mut env.backend, 32, 42);
        put_bundle(&mut env, BASE, mib(true, break_w(), nop_i(), 0));
        env.pc = BASE;
        let r = run::step(&mut env, &mut sys, CPU);
        assert!(matches!(r, Err(Outcome::Exit(42))));
    }

    /// ゲートページ経由（epc 入口への br.call）でも同じ規約で
    /// syscall が往復し、br.ret b6 で呼出側へ戻る。
    #[test]
    fn gate_epc_call_roundtrip() {
        let mut env = env();
        let mut sys = Linux::new();
        install_gate_page(&mut env).unwrap();
        // { .mib nop.m; nop.i; br.call b6=b2 } → ゲート入口へ。
        env.backend.set(sem::br_ref(2), gate::SYSCALL_VIA_EPC);
        let nop_m = polyisa_guest_ia64::encode_nop_m(&[0, 0]).unwrap() as u64;
        let call = polyisa_guest_ia64::encode_br_call_ind(&[0, 6, 2]).unwrap() as u64;
        put_bundle(&mut env, BASE, mib(true, nop_m, nop_i(), call));
        // 呼出側のフレームに引数を用意（br.call で新フレームの
        // r32.. に写る）。
        set_frame(&mut env, 10, 4);
        sem::gr_set(&mut env.backend, 15, NR_BASE + nr::WRITE);
        for (i, v) in [1u64, DATA, 3].iter().enumerate() {
            sem::gr_set(&mut env.backend, (32 + 4 + i) as u32, *v);
        }
        env.backend.mem.write(VirtAddr(DATA), b"epc").unwrap();
        env.pc = BASE;
        run::step(&mut env, &mut sys, CPU).unwrap();
        assert_eq!(env.pc, gate::SYSCALL_VIA_EPC);
        // ゲートのバンドル: break → Handled（復帰は次スロット）。
        run::step(&mut env, &mut sys, CPU).unwrap();
        assert_eq!(env.pc, gate::SYSCALL_VIA_EPC | 1);
        // 残りスロット: nop.i → br.ret b6 で呼出側へ戻る。
        run::step(&mut env, &mut sys, CPU).unwrap();
        assert_eq!(env.pc, BASE + 16);
        assert_eq!(sem::gr_get(&env.backend, 8), 3);
        assert_eq!(sem::gr_get(&env.backend, 10), 0);
        assert_eq!(sys.io.stdout, b"epc");
        // br.ret b6 で呼出側フレームに復帰（sol=4 が戻る）。
        assert_eq!(env.backend.get(sem::cfm_ref()) >> cfm_bit::SOL & 0x7f, 4);
    }

    /// via_break 入口も同じバンドル形で syscall を往復する。
    #[test]
    fn gate_via_break_roundtrip() {
        let mut env = env();
        let mut sys = Linux::new();
        install_gate_page(&mut env).unwrap();
        env.backend.set(sem::br_ref(2), gate::SYSCALL_VIA_BREAK);
        let nop_m = polyisa_guest_ia64::encode_nop_m(&[0, 0]).unwrap() as u64;
        let call = polyisa_guest_ia64::encode_br_call_ind(&[0, 6, 2]).unwrap() as u64;
        put_bundle(&mut env, BASE, mib(true, nop_m, nop_i(), call));
        set_frame(&mut env, 8, 0);
        sem::gr_set(&mut env.backend, 15, NR_BASE + nr::EXIT_GROUP);
        sem::gr_set(&mut env.backend, 32, 7);
        env.pc = BASE;
        run::step(&mut env, &mut sys, CPU).unwrap();
        let r = run::step(&mut env, &mut sys, CPU);
        assert!(matches!(r, Err(Outcome::Exit(7))));
    }
}
