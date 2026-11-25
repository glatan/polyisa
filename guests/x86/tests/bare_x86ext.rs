// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! x86 の世代差の命令単位テスト（裸実行環境）。
//!
//! 対象は 8086/80186/80286/80386 の挙動パラメータ（cpu-models.md の
//! `param` 句）が切り替える世代ごとの振る舞いで、SST の実測に基づく
//! 値をモデル別に pin する。段階13で追加した拡張命令の意味論は
//! `bare_x86run`（run64_xop / run64_apx / run64_amx / run64_avx10 /
//! run64_sse4a 等）にあり、ここには置かない。x87 の世代差は
//! の未実装の範囲。

use polyisa_cli::run_x86::{self, Outcome, TrapHandler, TrapOutcome};
use polyisa_engine::bare::BareEnv;
use polyisa_guest_x86::CpuState;
use polyisa_guest_x86::sem::{self, Gpr};
use polyisa_mem::{Access, Perms, VirtAddr};
use polyisa_sem::Backend as _;

struct X64Exit;

impl TrapHandler for X64Exit {
    fn handle_trap(&mut self, env: &mut BareEnv, _code: u32) -> TrapOutcome {
        let nr = sem::read64(&mut env.backend, Gpr(0));
        if nr == 60 {
            TrapOutcome::Exit(sem::read64(&mut env.backend, Gpr(7)) as u32)
        } else {
            TrapOutcome::Unimplemented
        }
    }
}

/// 実モード用の env。`entry` は IP。セグメントは個別に sregs へ設定する。
fn env16(prog: &[u8], entry: u32) -> BareEnv {
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0), 16, rwx).unwrap();
    env.backend
        .mem
        .map(VirtAddr(0x1_0000), 8, Perms::RW)
        .unwrap();
    env.backend.mem.write(VirtAddr(entry as u64), prog).unwrap();
    env
}

/// `model` 名で m16 を回す。
fn run16m(env: &mut BareEnv, entry: u32, model: &str, limit: u64) -> Outcome {
    let mut sys = X64Exit;
    run_x86::run_m16_ex(
        env,
        entry,
        &mut sys,
        limit,
        polyisa_guest_x86::model_feats(model),
        &polyisa_guest_x86::model_params(model),
    )
}

/// SS:SP = 0x8000、割り込みベクタ `v` を CS:IP=0000:0400 に向ける。
fn setup_stack_ivt(env: &mut BareEnv, v: u8) {
    env.backend.set(sem::sreg_ref(2), 0); // SS
    env.step(|b| {
        sem::write64(b, Gpr(4), 0x8000);
        Ok(())
    })
    .unwrap();
    env.backend
        .mem
        .write(VirtAddr(u64::from(v) * 4), &[0x00, 0x04, 0x00, 0x00])
        .unwrap();
}

fn ax(env: &mut BareEnv) -> u64 {
    u64::from(env.backend.get(Gpr(0).state()) & 0xFFFF)
}

// ---- op82: 0x82 は 0x80 の別名（8086-386 系。386EX でも残る）----

#[test]
fn ext_op82_alias_executes() {
    // 82 C0 05 = add al,5（0x82 は 0x80 /0 の別名）。
    for model in ["i8088", "i186", "i286", "i386"] {
        let mut env = env16(&[0x82, 0xC0, 0x05], 0x1000);
        let out = run16m(&mut env, 0x1000, model, 1);
        assert_eq!(out, Outcome::StepLimit { pc: 0x1003 }, "{model}");
        assert_eq!(ax(&mut env) & 0xFF, 5, "{model}");
    }
}

// ---- insn_len: 286 は 10 バイト超で #GP ----

#[test]
fn ext_insn_len_286_gp() {
    // 3E ×8 + mov ax,0x1234 = 11 バイトの 1 命令（セグメント
    // 接頭辞は全世代で有効。66/67 は世代によって意味が違う）。
    let mut prog = vec![0x3Eu8; 8];
    prog.extend([0xB8, 0x34, 0x12]);
    // i286: #GP(13) へ飛び、積まれる IP は命令先頭。
    let mut env = env16(&prog, 0x1000);
    setup_stack_ivt(&mut env, 13);
    let out = run16m(&mut env, 0x1000, "i286", 1);
    assert_eq!(out, Outcome::StepLimit { pc: 0x400 });
    let mut f = [0u8; 6];
    env.backend
        .mem
        .read(VirtAddr(0x7FFA), &mut f, Access::DATA_LE)
        .unwrap();
    // int_real は FLAGS→CS→IP の順に積むので、SP-2 が IP。
    assert_eq!(&f[0..2], &[0x00, 0x10], "fault ip");
    assert_eq!(&f[2..4], &[0x00, 0x00], "fault cs");
    assert_eq!(&f[4..6], &[0x00, 0x00], "fault flags");
    // i386（15 バイト制限）: 普通に実行される。
    let mut env = env16(&prog, 0x1000);
    let out = run16m(&mut env, 0x1000, "i386", 1);
    assert_eq!(out, Outcome::StepLimit { pc: 0x100B });
    assert_eq!(ax(&mut env), 0x1234);
}

// ---- bcd: AAA/DAA/AAS の補正手続きは 8086/88 と 286+ で違う ----

#[test]
fn ext_bcd_aaa_generation() {
    // AL=0xFB, AF=0: 補正は両世代で発火するが、286+ は AX+0x106 の
    // 桁上げが AH に伝搬し、8086/88 は AH+1 が独立（SST 実測）。
    for (model, want_ax) in [("i8088", 0x0101u64), ("i286", 0x0201)] {
        let mut env = env16(&[0x37], 0x1000); // aaa
        env.step(|b| {
            sem::write64(b, Gpr(0), 0xFB);
            b.set(sem::eflags_ref(), 0x0002);
            Ok(())
        })
        .unwrap();
        let out = run16m(&mut env, 0x1000, model, 1);
        assert_eq!(out, Outcome::StepLimit { pc: 0x1001 }, "{model}");
        assert_eq!(ax(&mut env), want_ax, "{model}");
    }
}

#[test]
fn ext_bcd_daa_generation() {
    // AL=0x9A, AF=1: 第2補正の判定が世代差。8086/88 は
    // AL+(AF?0:6)>0x9F（=AL>0x9F）で不補正、286+ は AL>0x99 で補正。
    for (model, want_al, want_cf) in [("i8088", 0xA0u64, 0u64), ("i286", 0x00, 1)] {
        let mut env = env16(&[0x27], 0x1000); // daa
        env.step(|b| {
            sem::write64(b, Gpr(0), 0x9A);
            b.set(sem::eflags_ref(), 0x0012); // AF=1
            Ok(())
        })
        .unwrap();
        let out = run16m(&mut env, 0x1000, model, 1);
        assert_eq!(out, Outcome::StepLimit { pc: 0x1001 }, "{model}");
        let fl = env.backend.get(sem::eflags_ref());
        assert_eq!(ax(&mut env) & 0xFF, want_al, "{model} al");
        assert_eq!(u64::from(fl & 1), want_cf, "{model} cf");
    }
}

#[test]
fn ext_bcd_aas_generation() {
    // AL=0x05, AF=1: AAS も AAA と同じ補正経路。286+ は AX-0x106 の
    // 借りが AH に伝搬し、8086/88 は AH-1 が独立。
    for (model, want_ax) in [("i8088", 0xFF0Fu64), ("i286", 0xFE0F)] {
        let mut env = env16(&[0x3F], 0x1000); // aas
        env.step(|b| {
            sem::write64(b, Gpr(0), 0x05);
            b.set(sem::eflags_ref(), 0x0012); // AF=1
            Ok(())
        })
        .unwrap();
        let out = run16m(&mut env, 0x1000, model, 1);
        assert_eq!(out, Outcome::StepLimit { pc: 0x1001 }, "{model}");
        assert_eq!(ax(&mut env), want_ax, "{model}");
    }
}

// ---- idiv8: 商の境界（8086/88 の CORD は ±128 で常に #DE）----

#[test]
fn ext_idiv8_cord_boundary() {
    // idiv cl: AX=0xFF80(-128), CL=1 → 商 -128。
    let prog = &[0xF6, 0xF9];
    // i286: 商 -128 を許容 → AL=0x80, AH=0。
    let mut env = env16(prog, 0x1000);
    env.step(|b| {
        sem::write64(b, Gpr(0), 0xFF80);
        sem::write64(b, Gpr(1), 0x0001);
        Ok(())
    })
    .unwrap();
    let out = run16m(&mut env, 0x1000, "i286", 1);
    assert_eq!(out, Outcome::StepLimit { pc: 0x1002 });
    assert_eq!(ax(&mut env), 0x0080, "i286 quot");
    // i8088: 商マグニチュード 128 で常に #DE（割り込み 0）。
    let mut env = env16(prog, 0x1000);
    env.step(|b| {
        sem::write64(b, Gpr(0), 0xFF80);
        sem::write64(b, Gpr(1), 0x0001);
        Ok(())
    })
    .unwrap();
    setup_stack_ivt(&mut env, 0);
    let out = run16m(&mut env, 0x1000, "i8088", 1);
    assert_eq!(out, Outcome::StepLimit { pc: 0x400 });
}

// ---- addr_wrap: 8086/88 は実アドレスを 20 ビットで折り返す ----

#[test]
fn ext_addr_wrap_m20() {
    // DS=0xFFFF, BX=0x10 → 線形 0x100000。
    // i8088 は 1 MiB で折り返して実効 0x0 を読む。i286（24 ビット）は
    // 0x100000 を読む。
    let prog = &[0x8A, 0x07]; // mov al,[bx]
    let mut env = env16(prog, 0x1000);
    env.backend.mem.write(VirtAddr(0), &[0x42]).unwrap();
    env.backend.set(sem::sreg_ref(3), 0xFFFF); // DS
    env.step(|b| {
        sem::write64(b, Gpr(3), 0x0010);
        Ok(())
    })
    .unwrap();
    let out = run16m(&mut env, 0x1000, "i8088", 1);
    assert_eq!(out, Outcome::StepLimit { pc: 0x1002 });
    assert_eq!(ax(&mut env) & 0xFF, 0x42, "m20 wrap");
    // i286: 0x100000 の実バイト。
    let mut env = env16(prog, 0x1000);
    env.backend
        .mem
        .map(VirtAddr(0x10_0000), 1, Perms::RW)
        .unwrap();
    env.backend.mem.write(VirtAddr(0x10_0000), &[0x99]).unwrap();
    env.backend.set(sem::sreg_ref(3), 0xFFFF);
    env.step(|b| {
        sem::write64(b, Gpr(3), 0x0010);
        Ok(())
    })
    .unwrap();
    let out = run16m(&mut env, 0x1000, "i286", 1);
    assert_eq!(out, Outcome::StepLimit { pc: 0x1002 });
    assert_eq!(ax(&mut env) & 0xFF, 0x99, "m24 no wrap");
}

// ---- seg_limit: 64K 越えは 286+ で例外、8086/88 は折り返す ----

#[test]
fn ext_seg_limit_wrap_vs_fault() {
    // mov ax,[bx] BX=0xFFFF: 2 バイト読みがオフセットをまたぐ。
    let prog = &[0x8B, 0x07];
    // i8088: オフセット 0xFFFF と 0x0000 を読む。
    let mut env = env16(prog, 0x1000);
    env.backend.set(sem::sreg_ref(3), 0); // DS
    env.backend.mem.write(VirtAddr(0xFFFF), &[0x12]).unwrap();
    env.backend.mem.write(VirtAddr(0x0000), &[0x34]).unwrap();
    env.step(|b| {
        sem::write64(b, Gpr(3), 0xFFFF);
        Ok(())
    })
    .unwrap();
    let out = run16m(&mut env, 0x1000, "i8088", 1);
    assert_eq!(out, Outcome::StepLimit { pc: 0x1002 });
    assert_eq!(ax(&mut env), 0x3412, "wrap");
    // i286: #GP(13)。
    let mut env = env16(prog, 0x1000);
    env.backend.set(sem::sreg_ref(3), 0);
    env.step(|b| {
        sem::write64(b, Gpr(3), 0xFFFF);
        Ok(())
    })
    .unwrap();
    setup_stack_ivt(&mut env, 13);
    let out = run16m(&mut env, 0x1000, "i286", 1);
    assert_eq!(out, Outcome::StepLimit { pc: 0x400 });
}

// ---- stack_fault: SS 由来の限界超過は 286 が #GP、386+ が #SS ----

#[test]
fn ext_stack_fault_gp_vs_ss() {
    // mov ax, ss:[bx] BX=0xFFFF: SS 由来の 64K 越えは 286 が #GP(13)、
    // 386+ が #SS(12)、8086/88 はオフセットを折り返して読む。
    let prog = &[0x36, 0x8B, 0x07];
    for (model, want_pc) in [("i286", 0x600u64), ("i386", 0x400)] {
        let mut env = env16(prog, 0x1000);
        env.backend.set(sem::sreg_ref(2), 0); // SS
        env.step(|b| {
            sem::write64(b, Gpr(3), 0xFFFF);
            sem::write64(b, Gpr(4), 0x8000);
            Ok(())
        })
        .unwrap();
        // IVT[12] → 0x400、IVT[13] → 0x600 で区別する。
        env.backend
            .mem
            .write(VirtAddr(0x30), &[0x00, 0x04, 0x00, 0x00])
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x34), &[0x00, 0x06, 0x00, 0x00])
            .unwrap();
        let out = run16m(&mut env, 0x1000, model, 1);
        assert_eq!(out, Outcome::StepLimit { pc: want_pc }, "{model}");
    }
    // 8086/88 は折り返して 0xFFFF|0x0000 の 2 バイトを読む。
    let mut env = env16(prog, 0x1000);
    env.backend.set(sem::sreg_ref(2), 0);
    env.backend.mem.write(VirtAddr(0xFFFF), &[0x12]).unwrap();
    env.backend.mem.write(VirtAddr(0x0000), &[0x34]).unwrap();
    env.step(|b| {
        sem::write64(b, Gpr(3), 0xFFFF);
        sem::write64(b, Gpr(4), 0x8000);
        Ok(())
    })
    .unwrap();
    let out = run16m(&mut env, 0x1000, "i8088", 1);
    assert_eq!(out, Outcome::StepLimit { pc: 0x1003 });
    assert_eq!(ax(&mut env), 0x3412, "8088 wrap");
}

// ---- shift8_over: 386 は回数が 8 の倍数のとき端ビットを残す ----

#[test]
fn ext_shift8_over_edge() {
    // shl al,cl: AL=0x81, CL=16。回数が 8 の倍数のとき CF に
    // 被演算子バイトの端ビット（SHL は bit0）が残る。
    let prog = &[0xB0, 0x81, 0xB1, 0x10, 0xD2, 0xE0];
    let mut env = env16(prog, 0x1000);
    let out = run16m(&mut env, 0x1000, "i386", 3);
    assert_eq!(out, Outcome::StepLimit { pc: 0x1006 });
    let fl = u64::from(env.backend.get(sem::eflags_ref()));
    assert_eq!(ax(&mut env) & 0xFF, 0);
    assert_eq!(fl & 1, 1, "edge cf");
    // shift8_over=zero の世代（i286、既定値を継ぐ i8088）は CF=0。
    for model in ["i286", "i8088"] {
        let mut env = env16(prog, 0x1000);
        let out = run16m(&mut env, 0x1000, model, 3);
        assert_eq!(out, Outcome::StepLimit { pc: 0x1006 }, "{model}");
        let fl = u64::from(env.backend.get(sem::eflags_ref()));
        assert_eq!(fl & 1, 0, "{model} zero cf");
    }
}
