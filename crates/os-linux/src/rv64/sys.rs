// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! RV64 Linux の syscall 処理。`cli` の実行ループから ecall を委譲される。
//!
//! `TrapHandler` を実装し、`cli` 側の `EcallHandler` はここへ委ねる薄い
//! 適合に留まる。

use crate::TrapOutcome;
use polyisa_engine::bare::BareEnv;
use polyisa_guest_riscv::sem::Gpr;
use polyisa_sem::Backend as _;

fn reg(env: &mut BareEnv, r: u8) -> u64 {
    env.backend.get(Gpr(r).state())
}

/// RV64 Linux の syscall 状態機械。write（fd 1/2）と exit_group を受け、
/// ほかは番号を一度だけ報告して未対応とする。
#[derive(Default)]
pub struct Linux {
    reported: Vec<u64>,
}

type SysFn = fn(&mut Linux, &mut BareEnv) -> Option<TrapOutcome>;

const RV64_SYSCALLS: &[(&str, SysFn)] = &[
    ("write", sys_write),
    ("exit", sys_exit),
    ("exit_group", sys_exit_group),
];

fn sys_write(_sys: &mut Linux, env: &mut BareEnv) -> Option<TrapOutcome> {
    let fd = reg(env, 10);
    let buf = reg(env, 11);
    let len = reg(env, 12) as usize;
    let mut data = vec![0u8; len];
    let acc = polyisa_mem::Access {
        endian: polyisa_mem::Endian::Le,
        align: polyisa_mem::Align::Unaligned,
        kind: polyisa_mem::AccessKind::DataRead,
    };
    if env
        .backend
        .mem
        .read(polyisa_mem::VirtAddr(buf), &mut data, acc)
        .is_err()
    {
        return Some(TrapOutcome::Unimplemented);
    }
    let done = match fd {
        1 => std::io::Write::write(&mut std::io::stdout(), &data).unwrap_or(0),
        2 => std::io::Write::write(&mut std::io::stderr(), &data).unwrap_or(0),
        _ => return Some(TrapOutcome::Unimplemented),
    };
    env.backend.set(Gpr(10).state(), done as u64);
    Some(TrapOutcome::Handled)
}

fn sys_exit(_sys: &mut Linux, env: &mut BareEnv) -> Option<TrapOutcome> {
    Some(TrapOutcome::Exit(reg(env, 10) as u32))
}

fn sys_exit_group(sys: &mut Linux, env: &mut BareEnv) -> Option<TrapOutcome> {
    sys_exit(sys, env)
}

impl crate::TrapHandler for Linux {
    fn handle_trap(&mut self, env: &mut BareEnv, _code: u32) -> TrapOutcome {
        let nr = reg(env, 17);
        let name = crate::syscall_name(crate::GuestAbi::Rv64Linux, nr);
        if let Some(name) = name
            && let Some((_, handler)) = RV64_SYSCALLS.iter().find(|(n, _)| *n == name)
            && let Some(out) = handler(self, env)
        {
            return out;
        }
        // 未実装は既定で ENOSYS を返して続ける（設計: user-mode.md）。
        if !self.reported.contains(&nr) {
            self.reported.push(nr);
            eprintln!("run: unhandled syscall {nr} ({})", name.unwrap_or("?"));
        }
        env.backend
            .set(Gpr(10).state(), (-(crate::ENOSYS as i64)) as u64);
        TrapOutcome::Handled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TrapHandler;

    #[test]
    fn rv64_syscall_table_is_unique_and_named_in_os_linux() {
        let mut seen = std::collections::BTreeSet::new();
        let mut known = std::collections::BTreeSet::new();
        for nr in 0..4096 {
            if let Some(name) = crate::syscall_name(crate::GuestAbi::Rv64Linux, nr) {
                known.insert(name);
            }
        }
        for (name, _) in RV64_SYSCALLS {
            assert!(seen.insert(*name), "名前が重複している: {name}");
            assert!(known.contains(name), "{name} は rv64 の番号表にない");
        }
    }
    #[test]
    fn unimplemented_syscall_returns_enosys_and_continues() {
        use polyisa_sem::Backend as _;
        let mut sys = Linux::default();
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_riscv::CpuState>());
        env.backend.set(Gpr(17).state(), 9999);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(
            env.backend.get(Gpr(10).state()),
            (-(crate::ENOSYS as i64)) as u64
        );
    }
}
