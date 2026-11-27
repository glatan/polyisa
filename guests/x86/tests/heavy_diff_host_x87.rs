// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! ホスト x87 との実行差分（層: diff、E2）。
//!
//! まず masked exception の有限正規数について、FADD/FMUL/FDIV の
//! 80 ビット結果と例外フラグを比較する。ホスト側は FLD x2、単一算術
//! 命令、FSTP、FNSTSW を実行し、polyisa 側は同じレジスタ命令を直接
//! 実行する。TOP は両側で初期状態が違うため比較しない。

#![allow(unsafe_code)]

#[cfg(all(target_arch = "x86_64", unix))]
mod imp {
    use polyisa_cli::run_x86::{self, Outcome, TrapHandler, TrapOutcome};
    use polyisa_engine::bare::BareEnv;
    use polyisa_guest_x86::CpuState;
    use polyisa_host::exec_mem::ExecMem;
    use polyisa_mem::{Perms, VirtAddr};
    use polyisa_sem::Backend as _;

    const CODE_VA: u64 = 0x1000;
    const EXCEPTION_MASK: u16 = 0x3f;

    struct NoTrap;

    impl TrapHandler for NoTrap {
        fn handle_trap(&mut self, _env: &mut BareEnv, _code: u32) -> TrapOutcome {
            TrapOutcome::Unimplemented
        }
    }

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
    }

    fn put_movabs(code: &mut Vec<u8>, reg: u8, value: u64) {
        // mov r64,imm64。reg は rdi/rsi/rdx/rcx の index + 0xb8。
        code.push(0x48);
        code.push(0xb8 + reg);
        code.extend_from_slice(&value.to_le_bytes());
    }

    fn host_op(input0: (u64, u16), input1: (u64, u16), op: [u8; 2], fcw: u16) -> ((u64, u16), u16) {
        let mut in0 = [0u8; 16];
        let mut in1 = [0u8; 16];
        let mut cw = 0u16;
        let mut sw = 0u16;
        in0[..8].copy_from_slice(&input0.0.to_le_bytes());
        in0[8..10].copy_from_slice(&input0.1.to_le_bytes());
        in1[..8].copy_from_slice(&input1.0.to_le_bytes());
        in1[8..10].copy_from_slice(&input1.1.to_le_bytes());

        let mut code = Vec::new();
        put_movabs(&mut code, 2, (&mut cw as *mut u16) as u64); // mov rdx,cw
        code.extend_from_slice(&[0x48, 0xb9]);
        code.extend_from_slice(&((&mut sw as *mut u16) as u64).to_le_bytes()); // mov rcx,sw
        put_movabs(&mut code, 7, (&mut in0 as *mut [u8; 16]) as u64); // mov rdi,in0
        put_movabs(&mut code, 6, (&mut in1 as *mut [u8; 16]) as u64); // mov rsi,in1
        code.extend_from_slice(&[0xdb, 0xe3]); // fninit
        code.extend_from_slice(&[0x66, 0xb8]);
        code.extend_from_slice(&fcw.to_le_bytes()); // mov ax,fcw
        code.extend_from_slice(&[0x66, 0x89, 0x02]); // mov [rdx],ax
        code.extend_from_slice(&[0xd9, 0x2a]); // fldcw [rdx]
        code.extend_from_slice(&[0xdb, 0x2e]); // fld tbyte [rsi]
        code.extend_from_slice(&[0xdb, 0x2f]); // fld tbyte [rdi]
        code.extend_from_slice(&op);
        code.extend_from_slice(&[0xdb, 0x3f]); // fstp tbyte [rdi]
        code.extend_from_slice(&[0xdf, 0xe0]); // fnstsw ax
        code.extend_from_slice(&[0x66, 0x89, 0x01]); // mov [rcx],ax
        code.push(0xc3); // ret

        let mut mem = ExecMem::new(code.len()).expect("map rw");
        mem.write(&code).expect("write code");
        let mem = mem.finalize().expect("make rx");
        let f: extern "C" fn() = unsafe { core::mem::transmute(mem.ptr()) };
        f();
        let sig = u64::from_le_bytes(in0[..8].try_into().unwrap());
        let exp = u16::from_le_bytes(in0[8..10].try_into().unwrap());
        ((sig, exp), sw)
    }

    fn poly_op(input0: (u64, u16), input1: (u64, u16), op: [u8; 2], fcw: u16) -> ((u64, u16), u16) {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        env.backend
            .mem
            .map(
                VirtAddr(CODE_VA),
                1,
                Perms(Perms::R.0 | Perms::W.0 | Perms::X.0),
            )
            .unwrap();
        env.backend.mem.write(VirtAddr(CODE_VA), &op).unwrap();
        env.backend.set(polyisa_guest_x86::sem::fcw_ref(), fcw);
        env.backend.set(polyisa_guest_x86::sem::top_ref(), 0u16);
        env.backend
            .set(polyisa_guest_x86::sem::st_sig_ref(0), input0.0);
        env.backend
            .set(polyisa_guest_x86::sem::st_exp_ref(0), input0.1);
        env.backend
            .set(polyisa_guest_x86::sem::st_sig_ref(1), input1.0);
        env.backend
            .set(polyisa_guest_x86::sem::st_exp_ref(1), input1.1);
        env.backend
            .set(polyisa_guest_x86::sem::ftw_ref(), 0xfff0u16);
        let out = run_x86::run_mode(&mut env, CODE_VA as u32, &mut NoTrap, 1, true);
        assert!(
            matches!(out, Outcome::StepLimit { .. }),
            "poly outcome {out:?}"
        );
        (
            (
                env.backend.get(polyisa_guest_x86::sem::st_sig_ref(0)),
                env.backend.get(polyisa_guest_x86::sem::st_exp_ref(0)),
            ),
            env.backend.get(polyisa_guest_x86::sem::fsw_ref()),
        )
    }

    fn operand(rng: &mut Rng) -> (u64, u16) {
        let sig = (1u64 << 63) | rng.next();
        let center = 0x3fffi32;
        let disp = (rng.next() % 17) as i32 - 8;
        let mut exp = (center + disp) as u16;
        if rng.next() & 1 != 0 {
            exp |= 0x8000;
        }
        (sig, exp)
    }

    pub fn run() {
        let ops = [
            ([0xd8, 0xc1], "fadd"),
            ([0xd8, 0xc9], "fmul"),
            ([0xd8, 0xf1], "fdiv"),
        ];
        let mut rng = Rng(0x87D1_FF01);
        let mut reports = Vec::new();
        for i in 0..512 {
            let op = ops[(rng.next() % ops.len() as u64) as usize];
            let input0 = operand(&mut rng);
            let input1 = operand(&mut rng);
            let fcw = 0x037f;
            let (hv, hsw) = host_op(input0, input1, op.0, fcw);
            let (pv, psw) = poly_op(input0, input1, op.0, fcw);
            if hv != pv || (hsw & EXCEPTION_MASK) != (psw & EXCEPTION_MASK) {
                reports.push(format!(
                    "case {i} {}: in0={:x}/{:04x} in1={:x}/{:04x} host={:x}/{:04x},sw{:04x} poly={:x}/{:04x},sw{:04x}",
                    op.1, input0.0, input0.1, input1.0, input1.1,
                    hv.0, hv.1, hsw, pv.0, pv.1, psw
                ));
                if reports.len() >= 20 {
                    break;
                }
            }
        }
        assert!(reports.is_empty(), "host x87 diff:\n{}", reports.join("\n"));
    }
}

#[test]
fn diff_host_x87_arithmetic() {
    #[cfg(all(target_arch = "x86_64", unix))]
    imp::run();
}
