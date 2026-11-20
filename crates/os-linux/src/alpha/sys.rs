// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Alpha の Linux syscall 処理（段階16-10/11）。
//!
//! `call_pal` の関数番号で振り分ける: `callsys`(0x83) が syscall
//! で、番号は v0、引数は a0–a5、戻り値は v0、a3=1 が失敗印。
//! `rduniq`/`wruniq` はスレッドポインタの転送。`imb`/`cflush`/
//! `draina` は順序付き実行のインタプリタでは何もしない。
//! syscall 表の充実は段階16-11（本段階は経路と基本 syscall）。
// Ref: SRC-LINUX (7.3), SPEC-ALPHA-ARM.

use polyisa_engine::bare::BareEnv;
use polyisa_engine::run::{TrapHandler, TrapOutcome};
use polyisa_guest_alpha::sem;
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};
use polyisa_sem::Backend as _;

use crate::alpha::{errno, name, nr};

/// `call_pal` の PAL 関数番号（Linux がユーザから使うもの）。
// Ref: SRC-LINUX (7.3) — arch/alpha/include/uapi/asm/pal.h.
mod pal {
    /// PAL_cflush: キャッシュフラッシュ。no-op。
    pub const CFLUSH: u32 = 0x01;
    /// PAL_draina: 命令キューの排出。no-op。
    pub const DRAINA: u32 = 0x02;
    /// PAL_callsys: Linux syscall 発行点。
    pub const CALLSYS: u32 = 0x83;
    /// PAL_imb: I-cache の一貫化。インタプリタでは no-op。
    pub const IMB: u32 = 0x86;
    /// PAL_rduniq: v0 ← スレッドユニーク値。
    pub const RDUNIQ: u32 = 0x9e;
    /// PAL_wruniq: スレッドユニーク値 ← a0。
    pub const WRUNIQ: u32 = 0x9f;
}

/// 整数レジスタの読み出し（v0=0, a0=16 .. a5=21, a3=19, ra=26, sp=30）。
fn reg(env: &mut BareEnv, n: u8) -> u64 {
    env.backend.get(sem::Gpr(n).state())
}

fn set_reg(env: &mut BareEnv, n: u8, v: u64) {
    sem::Gpr(n).set(&mut env.backend, v);
}

fn trace() -> bool {
    std::env::var_os("POLYISA_ALPHA_SYSCALLS").is_some()
}

/// 標準入出力の捕獲。テストが読む。
#[derive(Default)]
pub struct AlphaIo {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Alpha Linux の syscall 状態機械。v0=番号、a0–a5=引数。
pub struct Linux {
    /// 標準入出力の capture。
    pub io: AlphaIo,
    /// 標準入力へ供給するバイト。
    pub stdin_buf: Vec<u8>,
    /// /proc/self/exe の readlink が返す絶対パス。ローダが置く。
    pub exe_path: String,
    stdin_pos: usize,
    /// プログラムブレーク。0 は未初期化。
    heap_end: u64,
    /// `brk` が下げられない下限（exec 時点のブレーク）。
    brk_start: u64,
    /// 報告済みの未実装番号（一度だけ出す）。
    reported: Vec<u64>,
    /// ホストから見たプロセス識別子。
    pid: u64,
}

impl Default for Linux {
    fn default() -> Self {
        Self::new()
    }
}

impl Linux {
    /// Alpha Linux の状態機械を作る。
    #[must_use]
    pub fn new() -> Self {
        Self {
            io: AlphaIo::default(),
            stdin_buf: Vec::new(),
            exe_path: String::new(),
            stdin_pos: 0,
            heap_end: 0,
            brk_start: 0,
            reported: Vec::new(),
            pid: 0,
        }
    }

    /// ゲストから見た pid。単一プロセスの模型なので常に 1（init）
    /// を返す（QEMU はホストの pid を返すが、ここでは再現性を優先）。
    fn pid(&mut self) -> u64 {
        if self.pid == 0 {
            self.pid = 1;
        }
        self.pid
    }

    /// 引数 `i`（0 起算）を取り出す。a0–a5 = $16–$21。
    // Ref: SRC-LINUX (7.3) — syscall(2) の Alpha 規約。
    fn arg(&self, env: &mut BareEnv, i: usize) -> u64 {
        if i < 6 { reg(env, 16 + i as u8) } else { 0 }
    }

    /// LE/整列のデータアクセス属性。
    fn acc(kind: AccessKind) -> Access {
        Access {
            endian: Endian::Le,
            align: Align::Natural,
            kind,
        }
    }

    /// ゲストメモリからバイト列を読む。
    fn read_bytes(&mut self, env: &mut BareEnv, addr: u64, len: usize) -> Option<Vec<u8>> {
        let mut v = vec![0u8; len];
        env.backend
            .mem
            .read(VirtAddr(addr), &mut v, Self::acc(AccessKind::DataRead))
            .ok()?;
        Some(v)
    }

    /// ゲストメモリへバイト列を書く。
    fn write_bytes(&mut self, env: &mut BareEnv, addr: u64, data: &[u8]) -> bool {
        env.backend.mem.write(VirtAddr(addr), data).is_ok()
    }

    /// `brk` の状態遷移。`sys_brk` が要求を適用して現在値を返し、
    /// `sys_osf_brk` は要求と不一致なら -ENOMEM に写す。つまり
    /// 下限未満の要求と写像失敗は a3=1 の ENOMEM になる。
    /// 内部の写像粒度はエミュレータのページ（4096。ゲストの
    /// getpagesize=8192 とは別物）。
    // Ref: SRC-LINUX (7.3) — sys_brk, sys_osf_brk (arch/alpha/kernel/osf_sys.c)。
    fn sys_brk(&mut self, env: &mut BareEnv, addr: u64) -> Result<u64, u32> {
        if addr == 0 {
            return Ok(self.heap_end);
        }
        if addr < self.brk_start {
            return Err(errno::ENOMEM);
        }
        if addr > self.heap_end {
            // 旧ブレークを含む部分ページは既に写像済みなので、
            // その次のページからだけを新規に確保する。
            let lo = self.heap_end.div_ceil(4096) * 4096;
            let hi = addr.div_ceil(4096) * 4096;
            if hi > lo
                && env
                    .backend
                    .mem
                    .map(VirtAddr(lo), (hi - lo) / 4096, Perms::RW)
                    .is_err()
            {
                return Err(errno::ENOMEM);
            }
        }
        self.heap_end = addr;
        Ok(addr)
    }

    /// `write`。fd1/2 は capture に、それ以外は EBADF。
    /// fd の検査は len==0 の早期リターンより先（vfs_write と同順）。
    fn sys_write(&mut self, env: &mut BareEnv, fd: u64, buf: u64, len: u64) -> Result<u64, u32> {
        if fd != 1 && fd != 2 {
            return Err(errno::EBADF);
        }
        if len == 0 {
            return Ok(0);
        }
        let n = usize::try_from(len).unwrap_or(1 << 20).min(1 << 20);
        let data = self.read_bytes(env, buf, n).ok_or(errno::EFAULT)?;
        match fd {
            1 => {
                self.io.stdout.extend_from_slice(&data);
                let _ = std::io::Write::write_all(&mut std::io::stdout(), &data);
                Ok(n as u64)
            }
            2 => {
                self.io.stderr.extend_from_slice(&data);
                let _ = std::io::Write::write_all(&mut std::io::stderr(), &data);
                Ok(n as u64)
            }
            _ => Err(errno::EBADF),
        }
    }

    /// `read`。fd0 は stdin_buf を順送り、それ以外は EBADF。
    fn sys_read(&mut self, env: &mut BareEnv, fd: u64, buf: u64, len: u64) -> Result<u64, u32> {
        if fd != 0 {
            return Err(errno::EBADF);
        }
        let rest = &self.stdin_buf[self.stdin_pos.min(self.stdin_buf.len())..];
        let n = rest.len().min(usize::try_from(len).unwrap_or(usize::MAX));
        if n == 0 {
            return Ok(0);
        }
        let chunk = rest[..n].to_vec();
        if !self.write_bytes(env, buf, &chunk) {
            return Err(errno::EFAULT);
        }
        self.stdin_pos += n;
        Ok(n as u64)
    }

    /// `uname`。Linux の utsname を 6 個の 65 バイト領域に書く。
    // Ref: SRC-LINUX (7.3) — struct new_utsname。
    fn sys_uname(&mut self, env: &mut BareEnv, addr: u64) -> Result<u64, u32> {
        // Alpha の machine 名は "alpha"。
        const FIELDS: [&str; 6] = ["Linux", "polyisa", "7.3.0", "#1 polyisa", "alpha", "(none)"];
        let mut image = [0u8; 65 * 6];
        for (i, s) in FIELDS.iter().enumerate() {
            let b = s.as_bytes();
            image[65 * i..65 * i + b.len()].copy_from_slice(b);
        }
        if !self.write_bytes(env, addr, &image) {
            return Err(errno::EFAULT);
        }
        Ok(0)
    }

    /// `getpagesize`。Alpha Linux のページは 8KiB。
    // Ref: SRC-LINUX (7.3) — arch/alpha/include/asm/page.h.
    fn sys_getpagesize(&mut self) -> u64 {
        0x2000
    }

    /// 番号で振り分ける。戻り値は (v0, a3) の組または終了。
    fn dispatch(&mut self, env: &mut BareEnv, n: u64) -> AlphaResult {
        let args: [u64; 6] = std::array::from_fn(|i| self.arg(env, i));
        match n {
            nr::EXIT | nr::EXIT_GROUP => AlphaResult::Exit((args[0] & 0xff) as u32),
            nr::WRITE => self.sys_write(env, args[0], args[1], args[2]).into(),
            nr::READ => self.sys_read(env, args[0], args[1], args[2]).into(),
            nr::BRK => self.sys_brk(env, args[0]).into(),
            nr::CLOSE => AlphaResult::Value(0),
            nr::UNAME => self.sys_uname(env, args[0]).into(),
            nr::GETPAGESIZE => AlphaResult::Value(self.sys_getpagesize()),
            nr::GETXPID => AlphaResult::Value(self.pid()),
            nr::SET_TID_ADDRESS => AlphaResult::Value(self.pid()),
            _ => AlphaResult::Unimpl,
        }
    }
}

/// syscall 内部戻り値。`(v0, a3)` に写すか、Exit で終了するか。
enum AlphaResult {
    /// v0 に値、a3=0。
    Value(u64),
    /// a3=1 で v0 が errno。
    Fail(u32),
    /// 終了コード。
    Exit(u32),
    /// 未実装番号。
    Unimpl,
}

impl From<Result<u64, u32>> for AlphaResult {
    fn from(r: Result<u64, u32>) -> Self {
        match r {
            Ok(v) => AlphaResult::Value(v),
            Err(e) => AlphaResult::Fail(e),
        }
    }
}

impl TrapHandler for Linux {
    /// `brk` の初期値。ローダが像の末尾を渡す。カーネルは
    /// ELF_PAGEALIGN（Alpha は 8KiB）で切り上げる。
    fn init_brk(&mut self, image_end: u64) {
        let b = image_end.next_multiple_of(0x2000);
        self.heap_end = b;
        self.brk_start = b;
    }

    fn handle_trap(&mut self, env: &mut BareEnv, code: u32) -> TrapOutcome {
        match code {
            pal::CALLSYS => {}
            pal::RDUNIQ => {
                let v = env.backend.get(sem::uniq_ref());
                set_reg(env, 0, v);
                return TrapOutcome::Handled;
            }
            pal::WRUNIQ => {
                let v = reg(env, 16);
                env.backend.set(sem::uniq_ref(), v);
                return TrapOutcome::Handled;
            }
            // 順序付き実行のインタプリタではキャッシュ・キューの
            // 実効動作がないので imb/cflush/draina は no-op。
            pal::IMB | pal::CFLUSH | pal::DRAINA => return TrapOutcome::Handled,
            // halt/bpt/bugchk/gentrap とその他の PAL 関数はこの段階
            // では未実装（呼び出し側が Unimplemented に写す）。
            _ => return TrapOutcome::Unimplemented,
        }
        let nr_val = reg(env, 0);
        if trace() {
            let nm = name(nr_val).unwrap_or("?");
            eprintln!(
                "sys {nr_val} {nm} a0={:#x} a1={:#x}",
                reg(env, 16),
                reg(env, 17)
            );
        }
        match self.dispatch(env, nr_val) {
            AlphaResult::Value(v) => {
                set_reg(env, 0, v);
                set_reg(env, 19, 0);
                TrapOutcome::Handled
            }
            AlphaResult::Fail(e) => {
                set_reg(env, 0, u64::from(e));
                set_reg(env, 19, 1);
                TrapOutcome::Handled
            }
            AlphaResult::Exit(c) => TrapOutcome::Exit(c),
            AlphaResult::Unimpl => {
                let nm = name(nr_val).unwrap_or("?");
                if !self.reported.contains(&nr_val) {
                    self.reported.push(nr_val);
                    eprintln!("alpha: unimplemented syscall {nr_val} ({nm})");
                }
                set_reg(env, 0, u64::from(errno::ENOSYS));
                set_reg(env, 19, 1);
                TrapOutcome::Handled
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> BareEnv {
        BareEnv::new(core::mem::size_of::<polyisa_guest_alpha::CpuState>())
    }

    fn callsys(sys: &mut Linux, env: &mut BareEnv, n: u64, args: [u64; 6]) -> TrapOutcome {
        set_reg(env, 0, n);
        for (i, a) in args.iter().enumerate() {
            set_reg(env, 16 + i as u8, *a);
        }
        sys.handle_trap(env, pal::CALLSYS)
    }

    #[test]
    fn callsys_write_captures_stdout() {
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x8000), 1, Perms::RW).unwrap();
        env.backend.mem.write(VirtAddr(0x8000), b"hi\n").unwrap();
        let mut sys = Linux::new();
        match callsys(&mut sys, &mut env, nr::WRITE, [1, 0x8000, 3, 0, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), 3);
        assert_eq!(reg(&mut env, 19), 0);
        assert_eq!(sys.io.stdout, b"hi\n");
    }

    #[test]
    fn callsys_write_bad_fd_sets_a3() {
        let mut env = env();
        env.backend.mem.map(VirtAddr(0x8000), 1, Perms::RW).unwrap();
        env.backend.mem.write(VirtAddr(0x8000), b"hi").unwrap();
        let mut sys = Linux::new();
        match callsys(&mut sys, &mut env, nr::WRITE, [9, 0x8000, 2, 0, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        // Alpha の失敗規約は a3=1 で v0 が正の errno。
        assert_eq!(reg(&mut env, 0), u64::from(errno::EBADF));
        assert_eq!(reg(&mut env, 19), 1);
    }

    #[test]
    fn callsys_exit_group_returns_exit() {
        let mut env = env();
        let mut sys = Linux::new();
        match callsys(&mut sys, &mut env, nr::EXIT_GROUP, [7, 0, 0, 0, 0, 0]) {
            TrapOutcome::Exit(7) => {}
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn callsys_unknown_nr_is_enosys() {
        let mut env = env();
        let mut sys = Linux::new();
        match callsys(&mut sys, &mut env, 9999, [0; 6]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        // Alpha の ENOSYS は 78（汎用の 38 ではない）。
        assert_eq!(reg(&mut env, 0), u64::from(errno::ENOSYS));
        assert_eq!(reg(&mut env, 19), 1);
    }

    #[test]
    fn callsys_brk_grows_and_maps() {
        let mut env = env();
        let mut sys = Linux::new();
        sys.init_brk(0x1_0000);
        // 照会は現在値を返す。
        match callsys(&mut sys, &mut env, nr::BRK, [0; 6]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), 0x1_0000);
        // 伸長すると新ブレークを返し、範囲は写像される。
        match callsys(&mut sys, &mut env, nr::BRK, [0x2_0000, 0, 0, 0, 0, 0]) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), 0x2_0000);
        assert!(
            env.backend
                .mem
                .is_mapped(polyisa_mem::PageNo(0x1_0000 / 4096))
        );
        let data = [0xaa; 8];
        env.backend.mem.write(VirtAddr(0x1_8000), &data).unwrap();
    }

    #[test]
    fn pal_rduniq_wruniq_roundtrip() {
        let mut env = env();
        let mut sys = Linux::new();
        // wruniq a0 → 保持域へ。
        set_reg(&mut env, 16, 0xdead_beef);
        match sys.handle_trap(&mut env, pal::WRUNIQ) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(env.backend.get(sem::uniq_ref()), 0xdead_beef);
        // rduniq → v0 に戻る。
        set_reg(&mut env, 0, 0);
        match sys.handle_trap(&mut env, pal::RDUNIQ) {
            TrapOutcome::Handled => {}
            o => panic!("{o:?}"),
        }
        assert_eq!(reg(&mut env, 0), 0xdead_beef);
    }

    #[test]
    fn pal_imb_cflush_draina_are_noop() {
        let mut env = env();
        let mut sys = Linux::new();
        for code in [pal::IMB, pal::CFLUSH, pal::DRAINA] {
            match sys.handle_trap(&mut env, code) {
                TrapOutcome::Handled => {}
                o => panic!("{code:#x}: {o:?}"),
            }
        }
    }

    #[test]
    fn pal_unknown_code_is_unimplemented() {
        let mut env = env();
        let mut sys = Linux::new();
        // PAL_halt（0x00）や未割当番号はこの段階では未実装。
        for code in [0x00, 0x81, 0xaa, 0xbe] {
            match sys.handle_trap(&mut env, code) {
                TrapOutcome::Unimplemented => {}
                o => panic!("{code:#x}: {o:?}"),
            }
        }
    }
}
