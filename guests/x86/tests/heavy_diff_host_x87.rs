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

    fn host_unary(input: (u64, u16), op: [u8; 2], fcw: u16) -> ((u64, u16), u16) {
        let mut in0 = [0u8; 16];
        let mut cw = 0u16;
        let mut sw = 0u16;
        in0[..8].copy_from_slice(&input.0.to_le_bytes());
        in0[8..10].copy_from_slice(&input.1.to_le_bytes());
        let mut code = Vec::new();
        put_movabs(&mut code, 2, (&mut cw as *mut u16) as u64);
        code.extend_from_slice(&[0x48, 0xb9]);
        code.extend_from_slice(&((&mut sw as *mut u16) as u64).to_le_bytes());
        put_movabs(&mut code, 7, (&mut in0 as *mut [u8; 16]) as u64);
        code.extend_from_slice(&[0xdb, 0xe3, 0x66, 0xb8]);
        code.extend_from_slice(&fcw.to_le_bytes());
        code.extend_from_slice(&[0x66, 0x89, 0x02, 0xd9, 0x2a, 0xdb, 0x2f]);
        code.extend_from_slice(&op);
        code.extend_from_slice(&[0xdb, 0x3f, 0xdf, 0xe0, 0x66, 0x89, 0x01, 0xc3]);
        let mut mem = ExecMem::new(code.len()).expect("map rw");
        mem.write(&code).expect("write code");
        let mem = mem.finalize().expect("make rx");
        let f: extern "C" fn() = unsafe { core::mem::transmute(mem.ptr()) };
        f();
        (
            (
                u64::from_le_bytes(in0[..8].try_into().unwrap()),
                u16::from_le_bytes(in0[8..10].try_into().unwrap()),
            ),
            sw,
        )
    }

    fn host_push_pair(input: (u64, u16), op: [u8; 2], fcw: u16) -> ((u64, u16), (u64, u16), u16) {
        let mut in0 = [0u8; 16];
        let mut out1 = [0u8; 16];
        let mut cw = 0u16;
        let mut sw = 0u16;
        in0[..8].copy_from_slice(&input.0.to_le_bytes());
        in0[8..10].copy_from_slice(&input.1.to_le_bytes());
        let mut code = Vec::new();
        put_movabs(&mut code, 2, (&mut cw as *mut u16) as u64);
        code.extend_from_slice(&[0x48, 0xb9]);
        code.extend_from_slice(&((&mut sw as *mut u16) as u64).to_le_bytes());
        put_movabs(&mut code, 7, (&mut in0 as *mut [u8; 16]) as u64);
        put_movabs(&mut code, 6, (&mut out1 as *mut [u8; 16]) as u64);
        code.extend_from_slice(&[0xdb, 0xe3, 0x66, 0xb8]);
        code.extend_from_slice(&fcw.to_le_bytes());
        code.extend_from_slice(&[0x66, 0x89, 0x02, 0xd9, 0x2a, 0xdb, 0x2f]);
        code.extend_from_slice(&op);
        code.extend_from_slice(&[0xdb, 0x3f, 0xdb, 0x3e, 0xdf, 0xe0, 0x66, 0x89, 0x01, 0xc3]);
        let mut mem = ExecMem::new(code.len()).expect("map rw");
        mem.write(&code).expect("write code");
        let mem = mem.finalize().expect("make rx");
        let f: extern "C" fn() = unsafe { core::mem::transmute(mem.ptr()) };
        f();
        let rd = |b: &[u8; 16]| {
            (
                u64::from_le_bytes(b[..8].try_into().unwrap()),
                u16::from_le_bytes(b[8..10].try_into().unwrap()),
            )
        };
        (rd(&in0), rd(&out1), sw)
    }

    fn tag_bits(sig: u64, exp: u16) -> u16 {
        let ef = exp & 0x7fff;
        if ef == 0 && sig == 0 {
            1
        } else if ef != 0 && ef != 0x7fff && sig & (1u64 << 63) != 0 {
            0
        } else {
            2
        }
    }

    fn poly_push_pair(input: (u64, u16), op: [u8; 2], fcw: u16) -> ((u64, u16), (u64, u16), u16) {
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
            .set(polyisa_guest_x86::sem::st_sig_ref(0), input.0);
        env.backend
            .set(polyisa_guest_x86::sem::st_exp_ref(0), input.1);
        let tags = 0xfff0u16 | tag_bits(input.0, input.1);
        env.backend.set(polyisa_guest_x86::sem::ftw_ref(), tags);
        let out = run_x86::run_mode(&mut env, CODE_VA as u32, &mut NoTrap, 1, true);
        assert!(matches!(out, Outcome::StepLimit { .. }));
        let top: u16 = env.backend.get(polyisa_guest_x86::sem::top_ref());
        let mut rd = |logical: u16| {
            let physical = usize::from((top + logical) & 7);
            (
                env.backend
                    .get(polyisa_guest_x86::sem::st_sig_ref(physical)),
                env.backend
                    .get(polyisa_guest_x86::sem::st_exp_ref(physical)),
            )
        };
        (
            rd(0),
            rd(1),
            env.backend.get(polyisa_guest_x86::sem::fsw_ref()),
        )
    }

    fn within_ext_ulp(a: (u64, u16), b: (u64, u16), ulp: u64) -> bool {
        if a == b {
            return true;
        }
        if (a.1 & 0x8000) != (b.1 & 0x8000) {
            return false;
        }
        let ae = a.1 & 0x7fff;
        let be = b.1 & 0x7fff;
        if ae == 0x7fff || be == 0x7fff || ae == 0 || be == 0 {
            return false;
        }
        if ae == be {
            return a.0.abs_diff(b.0) <= ulp;
        }
        let ((lo_sig, lo_exp), (hi_sig, hi_exp)) = if ae < be {
            ((a.0, ae), (b.0, be))
        } else {
            ((b.0, be), (a.0, ae))
        };
        hi_exp == lo_exp + 1 && lo_sig == u64::MAX && hi_sig == 1u64 << 63
    }

    fn trans_value_matches(host: (u64, u16), poly: (u64, u16)) -> bool {
        // x87 transcendental は IEEE 四則と違って正確丸めを要求されず、
        // Intel 仕様も round-to-nearest で 1 ulp 未満の近似を許す。
        // rounding boundary では真値の上下どちらにも丸め得るため、
        // 通常有限値だけ 1 ulp まで許容し、特殊値と例外フラグは厳密に見る。
        host == poly || within_ext_ulp(host, poly, 1)
    }

    fn trans_value_matches_wide(host: (u64, u16), poly: (u64, u16)) -> bool {
        host == poly || within_ext_ulp(host, poly, 2)
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
        let tags = 0xfff0u16 | tag_bits(input0.0, input0.1) | (tag_bits(input1.0, input1.1) << 2);
        env.backend.set(polyisa_guest_x86::sem::ftw_ref(), tags);
        let out = run_x86::run_mode(&mut env, CODE_VA as u32, &mut NoTrap, 1, true);
        assert!(
            matches!(out, Outcome::StepLimit { .. }),
            "poly outcome {out:?}"
        );
        let top: u16 = env.backend.get(polyisa_guest_x86::sem::top_ref());
        let st0 = usize::from(top & 7);
        (
            (
                env.backend.get(polyisa_guest_x86::sem::st_sig_ref(st0)),
                env.backend.get(polyisa_guest_x86::sem::st_exp_ref(st0)),
            ),
            env.backend.get(polyisa_guest_x86::sem::fsw_ref()),
        )
    }

    fn poly_unary(input: (u64, u16), op: [u8; 2], fcw: u16) -> ((u64, u16), u16) {
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
            .set(polyisa_guest_x86::sem::st_sig_ref(0), input.0);
        env.backend
            .set(polyisa_guest_x86::sem::st_exp_ref(0), input.1);
        let tags = 0xfff0u16 | tag_bits(input.0, input.1);
        env.backend.set(polyisa_guest_x86::sem::ftw_ref(), tags);
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
        let sign = if rng.next() & 1 != 0 { 0x8000 } else { 0 };
        match rng.next() % 12 {
            // 通常の正規数。指数は中心付近に寄せる。
            0..=5 => {
                let sig = (1u64 << 63) | rng.next();
                let disp = (rng.next() % 17) as i32 - 8;
                (sig, ((0x3fff + disp) as u16) | sign)
            }
            // overflow/underflow 境界に寄せた正規数。
            6..=7 => {
                let sig = (1u64 << 63) | rng.next();
                let exp = if rng.next() & 1 != 0 {
                    1 + (rng.next() % 8) as u16
                } else {
                    0x7ffe - (rng.next() % 8) as u16
                };
                (sig, exp | sign)
            }
            // 正規化済み denormal / pseudo-denormal。
            8 => {
                let sig = rng.next() | (if rng.next() & 1 != 0 { 1u64 << 63 } else { 1 });
                (sig, sign)
            }
            // ±0。
            9 => (0, sign),
            // ±infinity。
            10 => (1u64 << 63, 0x7fff | sign),
            // QNaN/SNaN。payload の下位は乱択する。
            _ => {
                let quiet = if rng.next() & 1 != 0 { 1u64 << 62 } else { 0 };
                let payload = (rng.next() & ((1u64 << 61) - 1)) | 1;
                ((1u64 << 63) | quiet | payload, 0x7fff | sign)
            }
        }
    }

    pub fn run() {
        let ops = [
            ([0xd8, 0xc1], "fadd"),
            ([0xd8, 0xc9], "fmul"),
            ([0xd8, 0xe1], "fsub"),
            ([0xd8, 0xf1], "fdiv"),
            ([0xd9, 0xf5], "fprem1"),
            ([0xd9, 0xf8], "fprem"),
            ([0xd9, 0xfd], "fscale"),
        ];
        let mut rng = Rng(0x87D1_FF01);
        let mut reports = Vec::new();
        let fcws = [0x007f, 0x027f, 0x037f, 0x077f, 0x0b7f, 0x0f7f];
        for i in 0..1024 {
            let op = ops[(rng.next() % ops.len() as u64) as usize];
            let input0 = operand(&mut rng);
            let input1 = operand(&mut rng);
            let fcw = fcws[(rng.next() % fcws.len() as u64) as usize];
            let (hv, hsw) = host_op(input0, input1, op.0, fcw);
            let (pv, psw) = poly_op(input0, input1, op.0, fcw);
            if hv != pv || (hsw & EXCEPTION_MASK) != (psw & EXCEPTION_MASK) {
                reports.push(format!(
                    "case {i} {} fcw={fcw:04x}: in0={:x}/{:04x} in1={:x}/{:04x} host={:x}/{:04x},sw{:04x} poly={:x}/{:04x},sw{:04x}",
                    op.1, input0.0, input0.1, input1.0, input1.1,
                    hv.0, hv.1, hsw, pv.0, pv.1, psw
                ));
                if reports.len() >= 20 {
                    break;
                }
            }
        }
        let unary_ops = [([0xd9, 0xfa], "fsqrt"), ([0xd9, 0xfc], "frndint")];
        for i in 0..512 {
            let op = unary_ops[(rng.next() % unary_ops.len() as u64) as usize];
            let input = operand(&mut rng);
            let fcw = fcws[(rng.next() % fcws.len() as u64) as usize];
            let (hv, hsw) = host_unary(input, op.0, fcw);
            let (pv, psw) = poly_unary(input, op.0, fcw);
            if hv != pv || (hsw & EXCEPTION_MASK) != (psw & EXCEPTION_MASK) {
                reports.push(format!(
                    "unary {i} {} fcw={fcw:04x}: in={:x}/{:04x} host={:x}/{:04x},sw{:04x} poly={:x}/{:04x},sw{:04x}",
                    op.1, input.0, input.1, hv.0, hv.1, hsw, pv.0, pv.1, psw
                ));
                if reports.len() >= 20 {
                    break;
                }
            }
        }
        assert!(reports.is_empty(), "host x87 diff:\n{}", reports.join("\n"));
    }
    /// transcendental 用の valid-range oracle。x87 transcendental は
    /// 正確丸めを要求されないため、通常有限値は 1 ulp まで許容し、
    /// 特殊値と例外フラグは host と厳密に比較する。
    pub fn run_transcendental_accuracy() {
        let unary_ops = [
            ([0xd9, 0xf0], "f2xm1"),
            ([0xd9, 0xfe], "fsin"),
            ([0xd9, 0xff], "fcos"),
        ];
        let mut rng = Rng(0x87D1_77AA);
        let fcws = [0x007f, 0x027f, 0x037f, 0x077f, 0x0b7f, 0x0f7f];
        let mut reports = Vec::new();
        for i in 0..256 {
            let op = unary_ops[(rng.next() % unary_ops.len() as u64) as usize];
            let sign = if rng.next() & 1 != 0 { 0x8000 } else { 0 };
            let sig = (1u64 << 63) | rng.next();
            let disp = if op.1 == "f2xm1" {
                (rng.next() % 16) as i32 - 16
            } else {
                (rng.next() % 79) as i32 - 16
            };
            let input = (sig, ((0x3fff + disp) as u16) | sign);
            let fcw = fcws[(rng.next() % fcws.len() as u64) as usize];
            let (hv, hsw) = host_unary(input, op.0, fcw);
            let (pv, psw) = poly_unary(input, op.0, fcw);
            if !trans_value_matches(hv, pv) || (hsw & EXCEPTION_MASK) != (psw & EXCEPTION_MASK) {
                reports.push(format!(
                    "trans {i} {} fcw={fcw:04x}: in={:x}/{:04x} host={:x}/{:04x},sw{:04x} poly={:x}/{:04x},sw{:04x}",
                    op.1, input.0, input.1, hv.0, hv.1, hsw, pv.0, pv.1, psw
                ));
                if reports.len() >= 20 {
                    break;
                }
            }
        }
        let push_ops = [([0xd9, 0xfb], "fsincos"), ([0xd9, 0xf2], "fptan")];
        for i in 0..128 {
            let op = push_ops[(rng.next() % push_ops.len() as u64) as usize];
            let sign = if rng.next() & 1 != 0 { 0x8000 } else { 0 };
            let sig = (1u64 << 63) | rng.next();
            let disp = (rng.next() % 79) as i32 - 16;
            let input = (sig, ((0x3fff + disp) as u16) | sign);
            let fcw = fcws[(rng.next() % fcws.len() as u64) as usize];
            let (h0, h1, hsw) = host_push_pair(input, op.0, fcw);
            let (p0, p1, psw) = poly_push_pair(input, op.0, fcw);
            let values_match = if op.1 == "fptan" {
                h0 == p0 && trans_value_matches_wide(h1, p1)
            } else {
                trans_value_matches_wide(h0, p0) && trans_value_matches_wide(h1, p1)
            };
            if !values_match || (hsw & EXCEPTION_MASK) != (psw & EXCEPTION_MASK) {
                reports.push(format!(
                    "trans-push {i} {} fcw={fcw:04x}: in={:x}/{:04x} host={:x}/{:04x},{:x}/{:04x},sw{:04x} poly={:x}/{:04x},{:x}/{:04x},sw{:04x}",
                    op.1, input.0, input.1,
                    h0.0, h0.1, h1.0, h1.1, hsw,
                    p0.0, p0.1, p1.0, p1.1, psw
                ));
                if reports.len() >= 20 {
                    break;
                }
            }
        }
        let binary_ops = [
            ([0xd9, 0xf1], "fyl2x"),
            ([0xd9, 0xf3], "fpatan"),
            ([0xd9, 0xf9], "fyl2xp1"),
        ];
        for i in 0..256 {
            let op = binary_ops[(rng.next() % binary_ops.len() as u64) as usize];
            let small = |rng: &mut Rng, positive: bool| {
                let sign = if !positive && rng.next() & 1 != 0 {
                    0x8000
                } else {
                    0
                };
                let sig = (1u64 << 63) | rng.next();
                let disp = (rng.next() % 8) as i32 - 7;
                (sig, ((0x3fff + disp) as u16) | sign)
            };
            let mut input0 = if op.1 == "fyl2x" {
                small(&mut rng, true)
            } else {
                small(&mut rng, false)
            };
            if op.1 == "fyl2xp1" && input0.1 & 0x7fff > 0x3ffc {
                input0.1 = (input0.1 & 0x8000) | 0x3ffc;
            }
            let input1 = small(&mut rng, false);
            let fcw = fcws[(rng.next() % fcws.len() as u64) as usize];
            let (hv, hsw) = host_op(input0, input1, op.0, fcw);
            let (pv, psw) = poly_op(input0, input1, op.0, fcw);
            if !trans_value_matches(hv, pv) || (hsw & EXCEPTION_MASK) != (psw & EXCEPTION_MASK) {
                reports.push(format!(
                    "trans-bin {i} {} fcw={fcw:04x}: in0={:x}/{:04x} in1={:x}/{:04x} host={:x}/{:04x},sw{:04x} poly={:x}/{:04x},sw{:04x}",
                    op.1, input0.0, input0.1, input1.0, input1.1,
                    hv.0, hv.1, hsw, pv.0, pv.1, psw
                ));
                if reports.len() >= 20 {
                    break;
                }
            }
        }
        let fpatan_vals = [
            (0, 0u16),
            (0, 0x8000u16),
            (1u64 << 63, 0x3fff),
            (1u64 << 63, 0xbfff),
            (1u64 << 63, 0x7fff),
            (1u64 << 63, 0xffff),
        ];
        for (xi, x) in fpatan_vals.iter().enumerate() {
            for (yi, y) in fpatan_vals.iter().enumerate() {
                let fcw = fcws[(xi + yi) % fcws.len()];
                let (hv, hsw) = host_op(*x, *y, [0xd9, 0xf3], fcw);
                let (pv, psw) = poly_op(*x, *y, [0xd9, 0xf3], fcw);
                if hv != pv || (hsw & EXCEPTION_MASK) != (psw & EXCEPTION_MASK) {
                    reports.push(format!(
                        "fpatan-special x{xi} y{yi} fcw={fcw:04x}: x={:x}/{:04x} y={:x}/{:04x} host={:x}/{:04x},sw{:04x} poly={:x}/{:04x},sw{:04x}",
                        x.0, x.1, y.0, y.1, hv.0, hv.1, hsw, pv.0, pv.1, psw
                    ));
                }
            }
        }
        let maxfin = (u64::MAX, 0x7ffeu16);
        let four = (1u64 << 63, 0x4001u16);
        let overflow_cases = [
            (four, maxfin, 0x037fu16, "nearest"),
            (
                four,
                (maxfin.0, maxfin.1 | 0x8000),
                0x037fu16,
                "nearest-neg",
            ),
            (four, maxfin, 0x0f7fu16, "truncate"),
        ];
        for (x, y, fcw, name) in overflow_cases {
            let (hv, hsw) = host_op(x, y, [0xd9, 0xf1], fcw);
            let (pv, psw) = poly_op(x, y, [0xd9, 0xf1], fcw);
            if hv != pv || (hsw & EXCEPTION_MASK) != (psw & EXCEPTION_MASK) {
                reports.push(format!(
                    "trans-overflow {name}: in0={:x}/{:04x} in1={:x}/{:04x} host={:x}/{:04x},sw{:04x} poly={:x}/{:04x},sw{:04x}",
                    x.0, x.1, y.0, y.1, hv.0, hv.1, hsw, pv.0, pv.1, psw
                ));
            }
        }
        let two = (1u64 << 63, 0x4000u16);
        let underflow_cases = [
            (two, (1u64, 0u16), "one-min"),
            (four, (1u64, 0u16), "two-min"),
            (two, (0x4000_0000_0000_0000u64, 0u16), "one-mid"),
        ];
        for (x, y, name) in underflow_cases {
            let (hv, hsw) = host_op(x, y, [0xd9, 0xf1], 0x037f);
            let (pv, psw) = poly_op(x, y, [0xd9, 0xf1], 0x037f);
            if hv != pv || (hsw & EXCEPTION_MASK) != (psw & EXCEPTION_MASK) {
                reports.push(format!(
                    "trans-underflow {name}: in0={:x}/{:04x} in1={:x}/{:04x} host={:x}/{:04x},sw{:04x} poly={:x}/{:04x},sw{:04x}",
                    x.0, x.1, y.0, y.1, hv.0, hv.1, hsw, pv.0, pv.1, psw
                ));
            }
        }
        let fpatan_extreme_cases = [
            (maxfin, (1u64 << 63, 0x3fffu16), "tiny-ratio"),
            (
                (maxfin.0, maxfin.1 | 0x8000),
                (1u64 << 63, 0x3fffu16),
                "tiny-ratio-negx",
            ),
            ((1u64, 0u16), maxfin, "huge-ratio"),
        ];
        for (x, y, name) in fpatan_extreme_cases {
            let (hv, hsw) = host_op(x, y, [0xd9, 0xf3], 0x037f);
            let (pv, psw) = poly_op(x, y, [0xd9, 0xf3], 0x037f);
            if hv != pv || (hsw & EXCEPTION_MASK) != (psw & EXCEPTION_MASK) {
                reports.push(format!(
                    "fpatan-extreme {name}: in0={:x}/{:04x} in1={:x}/{:04x} host={:x}/{:04x},sw{:04x} poly={:x}/{:04x},sw{:04x}",
                    x.0, x.1, y.0, y.1, hv.0, hv.1, hsw, pv.0, pv.1, psw
                ));
            }
        }
        for (idx, input) in [(1u64, 0u16), (0x4000_0000_0000_0000u64, 0x8000u16)]
            .iter()
            .enumerate()
        {
            for op in unary_ops {
                let fcw = 0x037f;
                let (hv, hsw) = host_unary(*input, op.0, fcw);
                let (pv, psw) = poly_unary(*input, op.0, fcw);
                if hv != pv || (hsw & EXCEPTION_MASK) != (psw & EXCEPTION_MASK) {
                    reports.push(format!(
                        "trans-denormal {idx} {}: in={:x}/{:04x} host={:x}/{:04x},sw{:04x} poly={:x}/{:04x},sw{:04x}",
                        op.1, input.0, input.1, hv.0, hv.1, hsw, pv.0, pv.1, psw
                    ));
                }
            }
        }
        let one = (1u64 << 63, 0x3fffu16);
        let dn = (1u64, 0u16);
        for op in binary_ops {
            let (x, y) = if op.1 == "fyl2x" {
                (dn, one)
            } else if op.1 == "fpatan" {
                (one, dn)
            } else {
                (dn, one)
            };
            let (hv, hsw) = host_op(x, y, op.0, 0x037f);
            let (pv, psw) = poly_op(x, y, op.0, 0x037f);
            if hv != pv || (hsw & EXCEPTION_MASK) != (psw & EXCEPTION_MASK) {
                reports.push(format!(
                    "trans-bin-denormal {}: in0={:x}/{:04x} in1={:x}/{:04x} host={:x}/{:04x},sw{:04x} poly={:x}/{:04x},sw{:04x}",
                    op.1, x.0, x.1, y.0, y.1, hv.0, hv.1, hsw, pv.0, pv.1, psw
                ));
            }
        }
        let exact_cases = [
            ([0xd9, 0xf1], "fyl2x", (1u64 << 63, 0x3fffu16), one),
            ([0xd9, 0xf1], "fyl2x", (1u64 << 63, 0x4000u16), one),
            ([0xd9, 0xf1], "fyl2x", (1u64 << 63, 0x4000u16), (0u64, 0u16)),
            (
                [0xd9, 0xf1],
                "fyl2x",
                (1u64 << 63, 0x4000u16),
                (1u64 << 63, 0x7fffu16),
            ),
            (
                [0xd9, 0xf1],
                "fyl2x",
                (1u64 << 63, 0x4001u16),
                (1u64 << 63, 0x3ffeu16),
            ),
            ([0xd9, 0xf9], "fyl2xp1", (0u64, 0u16), one),
            ([0xd9, 0xf9], "fyl2xp1", one, one),
        ];
        for (op, name, x, y) in exact_cases {
            let (hv, hsw) = host_op(x, y, op, 0x037f);
            let (pv, psw) = poly_op(x, y, op, 0x037f);
            if hv != pv || (hsw & EXCEPTION_MASK) != (psw & EXCEPTION_MASK) {
                reports.push(format!(
                    "trans-exact {name}: in0={:x}/{:04x} in1={:x}/{:04x} host={:x}/{:04x},sw{:04x} poly={:x}/{:04x},sw{:04x}",
                    x.0, x.1, y.0, y.1, hv.0, hv.1, hsw, pv.0, pv.1, psw
                ));
            }
        }
        assert!(
            reports.is_empty(),
            "host x87 binary transcendental diff:
{}",
            reports.join(
                "
"
            )
        );
    }
}

#[test]
fn diff_host_x87_arithmetic() {
    #[cfg(all(target_arch = "x86_64", unix))]
    imp::run();
}

#[test]
fn diff_host_x87_transcendental_accuracy() {
    #[cfg(all(target_arch = "x86_64", unix))]
    imp::run_transcendental_accuracy();
}
