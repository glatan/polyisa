// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! IA-64 骨格の最小テスト。CpuState の構成と定数レジスタ
//! （r0・p0）・NaT ビットの規則を確かめる。
//! 出典は SPEC-IA64-SDM Rev 2.3 (2010-05) である。
//! Ref: SPEC-IA64-SDM (Rev 2.3).

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::InterpExit;
use polyisa_guest_ia64::{CpuState, IP_SLOT_MASK, Insn, sem};

fn env() -> BareEnv {
    BareEnv::new(core::mem::size_of::<CpuState>())
}

#[test]
fn state_layout_pinned() {
    assert_eq!(core::mem::offset_of!(CpuState, gr), 0);
    assert_eq!(core::mem::offset_of!(CpuState, gr_nat), 128 * 8);
    let pr = 128 * 8 + 2 * 8;
    assert_eq!(core::mem::offset_of!(CpuState, pr), pr);
    assert_eq!(core::mem::offset_of!(CpuState, br), pr + 8);
    let ip = pr + 8 + 8 * 8;
    assert_eq!(core::mem::offset_of!(CpuState, ip), ip);
    let pfs = ip + 8;
    assert_eq!(core::mem::offset_of!(CpuState, pfs), pfs);
    assert_eq!(core::mem::offset_of!(CpuState, lc), pfs + 8);
    assert_eq!(core::mem::offset_of!(CpuState, ec), pfs + 16);
    assert_eq!(core::mem::offset_of!(CpuState, bsp), pfs + 24);
    assert_eq!(core::mem::offset_of!(CpuState, bspstore), pfs + 32);
    assert_eq!(core::mem::offset_of!(CpuState, rnat), pfs + 40);
    assert_eq!(core::mem::offset_of!(CpuState, unat), pfs + 48);
    assert_eq!(core::mem::offset_of!(CpuState, ccv), pfs + 56);
    assert_eq!(core::mem::offset_of!(CpuState, fpsr), pfs + 64);
    assert_eq!(core::mem::offset_of!(CpuState, rsc), pfs + 72);
    assert_eq!(core::mem::offset_of!(CpuState, itc), pfs + 80);
    let cfm = pfs + 88;
    assert_eq!(core::mem::offset_of!(CpuState, cfm), cfm);
    assert_eq!(core::mem::offset_of!(CpuState, rse_dirty), cfm + 8);
    assert_eq!(core::mem::offset_of!(CpuState, alat), cfm + 16);
    assert_eq!(
        core::mem::offset_of!(CpuState, alat_valid),
        cfm + 16 + 32 * 8
    );
    assert_eq!(core::mem::size_of::<CpuState>(), cfm + 16 + 32 * 8 + 8);
}

#[test]
fn gr0_and_p0_are_constant() {
    let mut env = env();
    sem::gr_set(&mut env.backend, 0, !0);
    sem::gr_set(&mut env.backend, 1, 42);
    assert_eq!(sem::gr_get(&env.backend, 0), 0);
    assert_eq!(sem::gr_get(&env.backend, 1), 42);
    // p0 は既定でも書き込んでも常に 1。
    assert!(sem::pred(&env.backend, 0));
    assert!(!sem::pred(&env.backend, 3));
    sem::pr_set(&mut env.backend, 1 << 3);
    assert!(sem::pred(&env.backend, 0));
    assert!(sem::pred(&env.backend, 3));
    sem::pr_set(&mut env.backend, 0);
    assert!(sem::pred(&env.backend, 0));
    assert!(!sem::pred(&env.backend, 3));
}

#[test]
fn nat_bits_per_gr() {
    let mut env = env();
    assert!(!sem::nat_get(&env.backend, 5));
    assert!(!sem::nat_get(&env.backend, 70));
    sem::nat_set(&mut env.backend, 5, true);
    sem::nat_set(&mut env.backend, 70, true);
    assert!(sem::nat_get(&env.backend, 5));
    assert!(sem::nat_get(&env.backend, 70));
    assert!(!sem::nat_get(&env.backend, 6));
    sem::nat_set(&mut env.backend, 5, false);
    assert!(!sem::nat_get(&env.backend, 5));
}

#[test]
fn ip_slot_field() {
    // ip の下位 4 ビットがバンドル内のスロット番号。
    assert_eq!(IP_SLOT_MASK, 0xf);
}

#[test]
fn exec_is_unimplemented() {
    let mut env = env();
    let e = sem::exec(&mut env.backend, Insn::Bad, 0, 0).unwrap_err();
    assert!(matches!(e, InterpExit::Unimplemented(_)));
}
