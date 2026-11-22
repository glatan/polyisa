// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! IA-64（Itanium）Linux のシステムコール ABI 定数。
//!
//! 規約（正本 entry.S・gate.S）: 発行点は `break 0x100000`
//! （__IA64_BREAK_SYSCALL）かゲートページの入口呼出。r15 = 番号
//! （実番号 = syscall.tbl の番号 + 1024）、引数は呼出側フレームの
//! 出力 out0–out5（現在 CFM の out 域で r32+sol 起点に対応する
//! 物理位置）、戻り値は r8 とエラー旗 r10（成功 0、失敗 −1 で
//! r8=errno）。戻り先は break の次の命令位置。
//! ゲートページは RGN 5 の先頭（GATE_ADDR）から始まり、コード
//! ページは GATE_ADDR+PERCPU_PAGE_SIZE。auxv は AT_SYSINFO(32) が
//! __kernel_syscall_via_epc 入口、AT_SYSINFO_EHDR(33) が
//! GATE_ADDR を指す。
//! Ref: SRC-LINUX-66 — uapi-asm/{break,auxvec}.h,
//! kernel-asm/{page,elf}.h, kernel/{entry,gate}.S, mm-init.c.

/// syscall 番号の基底。実番号 = tbl 番号 + BASE（`__NR_Linux`）。
// Ref: SRC-LINUX-66 — uapi-asm/unistd.h.
pub const NR_BASE: u64 = 1024;

/// v6.6 の syscall.tbl の表番号の上限 + 1（0–452、435・447 は
/// ia64 では予約）。範囲検査に使う。
// Ref: SRC-LINUX-66 — syscall.tbl.
pub const NR_SYSCALLS: u64 = 453;

/// auxv の種別（`uapi/asm/auxvec.h`）。
// Ref: SRC-LINUX-66 — uapi-asm/auxvec.h, kernel-asm/elf.h.
pub mod at {
    /// `AT_SYSINFO`（32）。値は __kernel_syscall_via_epc の入口
    /// 番地（`gate::SYSCALL_VIA_EPC`）。
    pub const SYSINFO: u64 = 32;
    /// `AT_SYSINFO_EHDR`（33）。値はゲート領域の ELF ヘッダ番地
    /// （`gate::ADDR`）。
    pub const SYSINFO_EHDR: u64 = 33;
}

/// `break` の即値（`uapi/asm/break.h` の __IA64_BREAK_*）。
/// __IA64_BREAK_KDB（0x80100）・__IA64_BREAK_KPROBE
/// （0x81000–0x81fff）はカーネル内のデバッグ経路で、ユーザ
/// モードからは到達しない（パーソナリティは未実装に畳む）。
// Ref: SRC-LINUX-66 — uapi-asm/break.h.
pub mod brk {
    /// __IA64_BREAK_SYSCALL。Linux syscall の発行点。
    pub const SYSCALL: u32 = 0x10_0000;
}

/// ゲート領域の配置。領域先頭とコードページの位置は正本の
/// 事実（page.h/mm-init.c）、コードページ内の入口配置は
/// パーソナリティの供給物に付随する選択で、
/// `sys::install_gate_page` が同じ値で命令列を書く。
// Ref: SRC-LINUX-66 — kernel-asm/page.h, kernel/mm-init.c.
pub mod gate {
    /// ゲート領域の先頭（`RGN_BASE(RGN_GATE)` = 5<<61）。
    /// AT_SYSINFO_EHDR が指す ELF ヘッダページの位置でもある。
    pub const ADDR: u64 = 0xa000_0000_0000_0000;
    /// per-CPU 領域のサイズ（`PERCPU_PAGE_SIZE`）。コード
    /// ページは ADDR+SIZE（非 BUGGY_SEGREL の配置）。
    pub const PERCPU_PAGE_SIZE: u64 = 1 << 18;
    /// ゲートコードページの先頭。
    pub const CODE: u64 = ADDR + PERCPU_PAGE_SIZE;
    /// `__kernel_syscall_via_break` の入口（CODE 先頭）。
    pub const SYSCALL_VIA_BREAK: u64 = CODE;
    /// `__kernel_sigtramp` の入口（位置の予約のみ。シグナル
    /// 配送は未実装 — Gap: GAP-0068）。
    pub const SIGTRAMP: u64 = CODE + 0x100;
    /// `__kernel_syscall_via_epc` の入口。AT_SYSINFO が指す値。
    pub const SYSCALL_VIA_EPC: u64 = CODE + 0x200;
}

/// errno。ia64 は asm-generic の値そのまま。IA10 の機械に
/// 必要な分だけ（IA11 が番号表と共に補完する）。
pub mod errno {
    pub const EIO: u64 = 5;
    pub const EBADF: u64 = 9;
    pub const EFAULT: u64 = 14;
    pub const EINVAL: u64 = 22;
    pub const ENOSYS: u64 = 38;
}

/// syscall 番号（`syscall.tbl` の表番号。実番号は +`NR_BASE`）。
/// IA10 は機械と往復テストに必要な分だけ（IA11 が表を実装する）。
// Ref: SRC-LINUX-66 — syscall.tbl.
pub mod nr {
    pub const EXIT: u64 = 1;
    pub const WRITE: u64 = 3;
    pub const EXIT_GROUP: u64 = 212;
}

/// IA-64 の Linux syscall 処理。`guest-ia64` 機能で有効になる。
#[cfg(feature = "guest-ia64")]
pub mod sys;
