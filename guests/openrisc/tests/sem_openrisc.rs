// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! OpenRISC の意味論検査（段階20 OR5-OR8）。BareEnv 上で
//! `sem::exec` を直接駆動し、整数・旗・メモリ・分岐・SPR・
//! MAC・FP の各群と、実行ループが担う遅延スロットの前進を見る。
//! 出典は SPEC-OPENRISC-1000 §5.3-5.5。

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::InterpExit;
use polyisa_guest_openrisc::{CpuState, Insn, encode, fpcsr_bit, sem, sr_bit};
use polyisa_mem::{Perms, VirtAddr};
use polyisa_sem::Backend as _;

fn enc(i: Insn, ops: &[u64]) -> u32 {
    encode(i, ops).unwrap() as u32
}

fn env() -> BareEnv {
    let mut e = BareEnv::new(core::mem::size_of::<CpuState>());
    e.backend.mem.map(VirtAddr(0x1000), 4, Perms::RW).unwrap();
    e.backend.mem.map(VirtAddr(0x8000), 4, Perms::RW).unwrap();
    e
}

fn rget(e: &mut BareEnv, i: u32) -> u64 {
    e.backend.get(sem::r_ref(i))
}

fn exec1(e: &mut BareEnv, i: Insn, w: u32, pc: u64) -> Result<bool, InterpExit> {
    e.step(|b| sem::exec(b, i, w, pc, true))
}

#[test]
fn alu_and_flags() {
    let mut e = env();
    // l.addi r3,r0,-1 → r3=0xffffffff、CY=0・OV=0。
    exec1(
        &mut e,
        Insn::LAddi,
        enc(Insn::LAddi, &[3, 0, 0xffff]),
        0x1000,
    )
    .unwrap();
    assert_eq!(rget(&mut e, 3), 0xffff_ffff);
    // l.addi r4,r3,1 → r4=0、CY=1、OV=0。
    exec1(&mut e, Insn::LAddi, enc(Insn::LAddi, &[4, 3, 1]), 0x1004).unwrap();
    assert_eq!(rget(&mut e, 4), 0);
    let sr = e.backend.get(sem::sr_ref());
    assert_ne!(sr & (1 << sr_bit::CY), 0);
    assert_eq!(sr & (1 << sr_bit::OV), 0);
    // l.add r5,r7,r7: r7=0x7fffffff → 0xfffffffe、CY=0・OV=1（正+正で負）。
    e.backend.set(sem::r_ref(7), 0x7fff_ffff);
    exec1(&mut e, Insn::LAdd, enc(Insn::LAdd, &[5, 7, 7]), 0x1008).unwrap();
    assert_eq!(rget(&mut e, 5), 0xffff_fffe);
    let sr = e.backend.get(sem::sr_ref());
    assert_eq!(sr & (1 << sr_bit::CY), 0);
    assert_ne!(sr & (1 << sr_bit::OV), 0);
    // l.sub r6,r0,r3 → r6=1、CY=1（借り）、OV=1（0-(-1) は正のまま→OV=0?）→
    // 0 - 0xffffffff = 1 mod 2^32、借りあり。signed: 0 - (-1) = 1 → OV=0。
    e.backend.set(sem::sr_ref(), 0);
    exec1(&mut e, Insn::LSub, enc(Insn::LSub, &[6, 0, 3]), 0x100c).unwrap();
    assert_eq!(rget(&mut e, 6), 1);
    let sr = e.backend.get(sem::sr_ref());
    assert_ne!(sr & (1 << sr_bit::CY), 0);
    assert_eq!(sr & (1 << sr_bit::OV), 0);
    // r0 は常に 0: l.add r0,... も捨てる。
    exec1(&mut e, Insn::LAddi, enc(Insn::LAddi, &[0, 0, 7]), 0x1010).unwrap();
    assert_eq!(e.backend.get(sem::r_ref(0)), 0);
}

#[test]
fn movhi_ori_const() {
    let mut e = env();
    // l.movhi r3,0x1234 / l.ori r3,r3,0x5678 → 0x12345678。
    exec1(
        &mut e,
        Insn::LMovhi,
        enc(Insn::LMovhi, &[3, 0x1234]),
        0x1000,
    )
    .unwrap();
    assert_eq!(rget(&mut e, 3), 0x1234_0000);
    exec1(&mut e, Insn::LOri, enc(Insn::LOri, &[3, 3, 0x5678]), 0x1004).unwrap();
    assert_eq!(rget(&mut e, 3), 0x1234_5678);
    // l.xori は符号拡張: r3 ^ 0xffff_8000。
    exec1(
        &mut e,
        Insn::LXori,
        enc(Insn::LXori, &[4, 3, 0x8000]),
        0x1008,
    )
    .unwrap();
    assert_eq!(rget(&mut e, 4), 0x1234_5678 ^ 0xffff_8000);
}

#[test]
fn sf_compares() {
    let mut e = env();
    e.backend.set(sem::r_ref(3), 5);
    // l.sfgtui r3,4 → F=1。
    exec1(&mut e, Insn::LSfgtui, enc(Insn::LSfgtui, &[3, 4]), 0x1000).unwrap();
    assert_ne!(e.backend.get(sem::sr_ref()) & (1 << sr_bit::F), 0);
    // l.sfgtui r3,6 → F=0。
    exec1(&mut e, Insn::LSfgtui, enc(Insn::LSfgtui, &[3, 6]), 0x1000).unwrap();
    assert_eq!(e.backend.get(sem::sr_ref()) & (1 << sr_bit::F), 0);
    // l.sfltsi r3,10 → signed 5<10 → F=1。
    exec1(&mut e, Insn::LSfltsi, enc(Insn::LSfltsi, &[3, 10]), 0x1000).unwrap();
    assert_ne!(e.backend.get(sem::sr_ref()) & (1 << sr_bit::F), 0);
    // l.sfeq r3,r4: r4=5 で F=1。
    e.backend.set(sem::r_ref(4), 5);
    exec1(&mut e, Insn::LSfeq, enc(Insn::LSfeq, &[3, 4]), 0x1000).unwrap();
    assert_ne!(e.backend.get(sem::sr_ref()) & (1 << sr_bit::F), 0);
    // 即値の符号拡張: l.sfgesi r3,-1（5 >= -1 → F=1）。
    exec1(
        &mut e,
        Insn::LSfgesi,
        enc(Insn::LSfgesi, &[3, 0xffff]),
        0x1000,
    )
    .unwrap();
    assert_ne!(e.backend.get(sem::sr_ref()) & (1 << sr_bit::F), 0);
    // unsigned では -1 は 0xffffffff → F=0。
    exec1(
        &mut e,
        Insn::LSfgeui,
        enc(Insn::LSfgeui, &[3, 0xffff]),
        0x1000,
    )
    .unwrap();
    assert_eq!(e.backend.get(sem::sr_ref()) & (1 << sr_bit::F), 0);
}

#[test]
fn loads_stores_be() {
    let mut e = env();
    // l.sw 0(r4),r3 → BE で 0xdeadbeef。
    e.backend.set(sem::r_ref(3), 0xdead_beef);
    e.backend.set(sem::r_ref(4), 0x8000);
    exec1(&mut e, Insn::LSw, enc(Insn::LSw, &[0, 4, 3]), 0x1000).unwrap();
    let mut buf = [0u8; 4];
    e.backend
        .mem
        .read(VirtAddr(0x8000), &mut buf, acc())
        .unwrap();
    assert_eq!(buf, [0xde, 0xad, 0xbe, 0xef]);
    // l.lwz/l.lws/l.lhs/l.lbz/l.lbs/l.lhz。
    exec1(&mut e, Insn::LLwz, enc(Insn::LLwz, &[5, 4, 0]), 0x1000).unwrap();
    assert_eq!(rget(&mut e, 5), 0xdead_beef);
    exec1(&mut e, Insn::LLhs, enc(Insn::LLhs, &[5, 4, 0]), 0x1000).unwrap();
    assert_eq!(rget(&mut e, 5), 0xffff_dead);
    exec1(&mut e, Insn::LLhz, enc(Insn::LLhz, &[5, 4, 2]), 0x1000).unwrap();
    assert_eq!(rget(&mut e, 5), 0xbeef);
    exec1(&mut e, Insn::LLbs, enc(Insn::LLbs, &[5, 4, 0]), 0x1000).unwrap();
    assert_eq!(rget(&mut e, 5), 0xffff_ffde);
    exec1(&mut e, Insn::LLbz, enc(Insn::LLbz, &[5, 4, 1]), 0x1000).unwrap();
    assert_eq!(rget(&mut e, 5), 0xad);
    // 負の変位: l.lwz r5,-4(r4) は 0x7ffc から読む（未写像→Err）。
    // l.sb/l.sh。
    exec1(&mut e, Insn::LSb, enc(Insn::LSb, &[4, 4, 3]), 0x1000).unwrap();
    let mut b1 = [0u8; 1];
    e.backend
        .mem
        .read(VirtAddr(0x8004), &mut b1, acc())
        .unwrap();
    assert_eq!(b1[0], 0xef);
}

fn acc() -> polyisa_mem::Access {
    polyisa_mem::Access {
        endian: polyisa_mem::Endian::Be,
        align: polyisa_mem::Align::Natural,
        kind: polyisa_mem::AccessKind::DataRead,
    }
}

#[test]
fn shifts_and_ext() {
    let mut e = env();
    e.backend.set(sem::r_ref(3), 0x8000_0001);
    exec1(&mut e, Insn::LSrai, enc(Insn::LSrai, &[4, 3, 1]), 0x1000).unwrap();
    assert_eq!(rget(&mut e, 4), 0xc000_0000);
    exec1(&mut e, Insn::LSrli, enc(Insn::LSrli, &[4, 3, 1]), 0x1000).unwrap();
    assert_eq!(rget(&mut e, 4), 0x4000_0000);
    exec1(&mut e, Insn::LRori, enc(Insn::LRori, &[4, 3, 1]), 0x1000).unwrap();
    assert_eq!(rget(&mut e, 4), 0xc000_0000);
    e.backend.set(sem::r_ref(3), 0x1234_80ff);
    exec1(&mut e, Insn::LExtbs, enc(Insn::LExtbs, &[4, 3, 0]), 0x1000).unwrap();
    assert_eq!(rget(&mut e, 4), 0xffff_ffff);
    exec1(&mut e, Insn::LExthz, enc(Insn::LExthz, &[4, 3, 0]), 0x1000).unwrap();
    assert_eq!(rget(&mut e, 4), 0x80ff);
    exec1(&mut e, Insn::LFf1, enc(Insn::LFf1, &[4, 3, 0]), 0x1000).unwrap();
    assert_eq!(rget(&mut e, 4), 1);
    exec1(&mut e, Insn::LFl1, enc(Insn::LFl1, &[4, 3, 0]), 0x1000).unwrap();
    assert_eq!(rget(&mut e, 4), 29);
    // レジスタシフト量は下位 5 ビット。
    e.backend.set(sem::r_ref(5), 33);
    exec1(&mut e, Insn::LSll, enc(Insn::LSll, &[4, 3, 5]), 0x1000).unwrap();
    assert_eq!(rget(&mut e, 4), 0x1234_80ff << 1 & 0xffff_ffff);
}

#[test]
fn mul_div_family() {
    let mut e = env();
    e.backend.set(sem::r_ref(3), 0xffff_fffe); // -2
    e.backend.set(sem::r_ref(4), 3);
    exec1(&mut e, Insn::LMul, enc(Insn::LMul, &[5, 3, 4]), 0x1000).unwrap();
    assert_eq!(rget(&mut e, 5), (-6i32) as u32 as u64);
    exec1(&mut e, Insn::LMulu, enc(Insn::LMulu, &[5, 3, 4]), 0x1000).unwrap();
    assert_eq!(rget(&mut e, 5), (0xffff_fffeu64 * 3) & 0xffff_ffff);
    assert_ne!(e.backend.get(sem::sr_ref()) & (1 << sr_bit::CY), 0);
    exec1(&mut e, Insn::LDiv, enc(Insn::LDiv, &[5, 3, 4]), 0x1000).unwrap();
    assert_eq!(rget(&mut e, 5), 0); // -2/3 = 0
    e.backend.set(sem::r_ref(3), 0xffff_fff8); // -8
    exec1(&mut e, Insn::LDiv, enc(Insn::LDiv, &[5, 3, 4]), 0x1000).unwrap();
    assert_eq!(rget(&mut e, 5), (-2i32) as u32 as u64);
    exec1(&mut e, Insn::LDivu, enc(Insn::LDivu, &[5, 3, 4]), 0x1000).unwrap();
    assert_eq!(rget(&mut e, 5), 0xffff_fff8 / 3);
    // 0 除算: l.div は OV、l.divu は CY。
    e.backend.set(sem::r_ref(4), 0);
    e.backend.set(sem::sr_ref(), 0);
    exec1(&mut e, Insn::LDiv, enc(Insn::LDiv, &[5, 3, 4]), 0x1000).unwrap();
    assert_ne!(e.backend.get(sem::sr_ref()) & (1 << sr_bit::OV), 0);
    e.backend.set(sem::sr_ref(), 0);
    exec1(&mut e, Insn::LDivu, enc(Insn::LDivu, &[5, 3, 4]), 0x1000).unwrap();
    assert_ne!(e.backend.get(sem::sr_ref()) & (1 << sr_bit::CY), 0);
}

#[test]
fn mac_family() {
    let mut e = env();
    e.backend
        .set(sem::r_ref(3), 0x1_0000_0000_u64 & 0xffff_ffff);
    e.backend.set(sem::r_ref(3), 0);
    e.backend.set(sem::r_ref(3), 0x7fff_ffff);
    e.backend.set(sem::r_ref(4), 2);
    // l.mac r3,r4 → MAC = +0xfffffffe（machi=0）。
    exec1(&mut e, Insn::LMac, enc(Insn::LMac, &[3, 4]), 0x1000).unwrap();
    assert_eq!(e.backend.get(sem::maclo_ref()), 0xffff_fffe);
    assert_eq!(e.backend.get(sem::machi_ref()), 0);
    // l.macu r3,r4 → 0x7fffffff*2 = 0xfffffffe を加算（下位）。
    exec1(&mut e, Insn::LMacu, enc(Insn::LMacu, &[3, 4]), 0x1000).unwrap();
    assert_eq!(e.backend.get(sem::maclo_ref()), 0xffff_fffc);
    // l.msb r3,r4 → MAC -= 0xfffffffe → 0x0000_0000_ffff_fffe。
    exec1(&mut e, Insn::LMsb, enc(Insn::LMsb, &[3, 4]), 0x1000).unwrap();
    assert_eq!(e.backend.get(sem::maclo_ref()), 0xffff_fffe);
    assert_eq!(e.backend.get(sem::machi_ref()), 0);
    // l.muld → MAC 直置き。0x7fffffff*2。
    exec1(&mut e, Insn::LMuld, enc(Insn::LMuld, &[3, 4]), 0x1000).unwrap();
    assert_eq!(e.backend.get(sem::maclo_ref()), 0xffff_fffe);
    assert_eq!(e.backend.get(sem::machi_ref()), 0);
    // l.macrc → r5 = MACLO、アキュムレータは 0。
    exec1(&mut e, Insn::LMacrc, enc(Insn::LMacrc, &[5]), 0x1000).unwrap();
    assert_eq!(rget(&mut e, 5), 0xffff_fffe);
    assert_eq!(e.backend.get(sem::maclo_ref()), 0);
    // l.maci r3,-2 → MAC = 0x7fffffff * -2 = 0xffff_ffff_0000_0002。
    exec1(&mut e, Insn::LMaci, enc(Insn::LMaci, &[3, 0xfffe]), 0x1000).unwrap();
    assert_eq!(e.backend.get(sem::maclo_ref()), 2);
    assert_eq!(e.backend.get(sem::machi_ref()), 0xffff_ffff);
}

#[test]
fn spr_access() {
    let mut e = env();
    // l.mfspr r3,r0,SR → sr の観測値（FO=1 を含む）。
    e.backend.set(sem::sr_ref(), 0x200);
    exec1(&mut e, Insn::LMfspr, enc(Insn::LMfspr, &[3, 0, 17]), 0x1000).unwrap();
    assert_eq!(rget(&mut e, 3) & 0x8000, 0x8000); // FO
    assert_eq!(rget(&mut e, 3) & 0x200, 0x200); // F
    // l.mtspr r0,r3,SR → ユーザ可書ビットのみ従う。
    e.backend.set(sem::r_ref(4), 0xffff_ffff);
    exec1(&mut e, Insn::LMtspr, enc(Insn::LMtspr, &[0, 4, 17]), 0x1000).unwrap();
    let sr = e.backend.get(sem::sr_ref());
    assert_eq!(sr & 0xe00, 0xe00); // F・CY・OV のみ 0xffffffff に追従
    assert_eq!(sr & !0xe00, 0x8000); // 残りは FO のみ（保持）
    // l.mfspr r3,r0,CPUCFGR。
    e.backend.set(sem::cpucfgr_ref(), 0x200);
    exec1(&mut e, Insn::LMfspr, enc(Insn::LMfspr, &[3, 0, 2]), 0x1000).unwrap();
    assert_eq!(rget(&mut e, 3), 0x200);
    // 分割即値: l.mtspr rA,rB,K の K は [25:21]|[10:0]。
    // FPCSR（= 0|20）への書き込み。
    e.backend.set(sem::r_ref(4), 0xdead_beef);
    exec1(&mut e, Insn::LMtspr, enc(Insn::LMtspr, &[0, 4, 20]), 0x1000).unwrap();
    assert_eq!(e.backend.get(sem::fpcsr_ref()), 0xdead_beef);
    // l.mfspr で GPR 写像（グループ 0 番号 1024+n）を読む。
    e.backend.set(sem::r_ref(7), 0x1234_5678);
    exec1(
        &mut e,
        Insn::LMfspr,
        enc(Insn::LMfspr, &[3, 0, 1024 + 7]),
        0x1000,
    )
    .unwrap();
    assert_eq!(rget(&mut e, 3), 0x1234_5678);
}

#[test]
fn branches_and_link() {
    let mut e = env();
    // l.j +8 → taken、npc = pc + 8<<2 = 0x1020。
    let taken = exec1(&mut e, Insn::LJ, enc(Insn::LJ, &[8]), 0x1000).unwrap();
    assert!(taken);
    assert_eq!(e.backend.get(sem::npc_ref()), 0x1020);
    // 負の変位: l.j -2 → 0x1000 - 8。
    let taken = exec1(&mut e, Insn::LJ, enc(Insn::LJ, &[0x3ff_fffe]), 0x1000).unwrap();
    assert!(taken);
    assert_eq!(e.backend.get(sem::npc_ref()), 0xff8);
    // l.jal はリンクを書く（遅延構成は pc+8）。
    let taken = exec1(&mut e, Insn::LJal, enc(Insn::LJal, &[4]), 0x1000).unwrap();
    assert!(taken);
    assert_eq!(e.backend.get(sem::r_ref(9)), 0x1008);
    // l.bf/l.bnf は SR[F] 条件。
    e.backend.set(sem::sr_ref(), 0x200); // F=1
    assert!(exec1(&mut e, Insn::LBf, enc(Insn::LBf, &[1]), 0x1000).unwrap());
    assert!(!exec1(&mut e, Insn::LBnf, enc(Insn::LBnf, &[1]), 0x1000).unwrap());
    // l.jalr r9 → npc=r9、リンクは pc+8。
    e.backend.set(sem::r_ref(5), 0x4000);
    let taken = exec1(&mut e, Insn::LJalr, enc(Insn::LJalr, &[5]), 0x2000).unwrap();
    assert!(taken);
    assert_eq!(e.backend.get(sem::npc_ref()), 0x4000);
    assert_eq!(e.backend.get(sem::r_ref(9)), 0x2008);
    // 無遅延構成のリンクは pc+4。
    e.step(|b| sem::exec(b, Insn::LJalr, enc(Insn::LJalr, &[5]), 0x2000, false))
        .unwrap();
    assert_eq!(e.backend.get(sem::r_ref(9)), 0x2004);
    // l.adrp r3,1 → r3 = (pc & -8192) + 0x2000。
    exec1(&mut e, Insn::LAdrp, enc(Insn::LAdrp, &[3, 1]), 0x1234).unwrap();
    assert_eq!(rget(&mut e, 3), 0x2000);
    exec1(&mut e, Insn::LAdrp, enc(Insn::LAdrp, &[3, 0x7ffff]), 0x4000).unwrap();
    assert_eq!(rget(&mut e, 3), 0x4000 - 0x2000);
}

#[test]
fn sys_trap_boundary() {
    let mut e = env();
    // l.sys → Trap(code=0xc00)。
    let r = exec1(&mut e, Insn::LSys, enc(Insn::LSys, &[0]), 0x1000);
    match r {
        Err(InterpExit::Exception(g)) => {
            assert_eq!(g.code, sem::TRAP_SYS);
        }
        _ => panic!("l.sys は trap"),
    }
    // l.trap → Trap(code=0xe00)。
    let r = exec1(&mut e, Insn::LTrap, enc(Insn::LTrap, &[0]), 0x1000);
    match r {
        Err(InterpExit::Exception(g)) => assert_eq!(g.code, sem::TRAP_TRAP),
        _ => panic!("l.trap は trap"),
    }
    // l.rfe・l.cust1 は未実装として止まる。
    assert!(matches!(
        exec1(&mut e, Insn::LRfe, enc(Insn::LRfe, &[]), 0x1000),
        Err(InterpExit::Unimplemented(_))
    ));
    assert!(matches!(
        exec1(&mut e, Insn::LCust1, 0x1c << 26, 0x1000),
        Err(InterpExit::Unimplemented(_))
    ));
}

#[test]
fn lwa_swa_atomic() {
    let mut e = env();
    e.backend.set(sem::r_ref(4), 0x8000);
    e.backend
        .mem
        .write(VirtAddr(0x8000), &0xa5a5_0001u32.to_be_bytes())
        .unwrap();
    // l.lwa r3,0(r4) → 値と予約。
    exec1(&mut e, Insn::LLwa, enc(Insn::LLwa, &[3, 4, 0]), 0x1000).unwrap();
    assert_eq!(rget(&mut e, 3), 0xa5a5_0001);
    // l.swa 0(r4),r5 → 成功し F=1。
    e.backend.set(sem::r_ref(5), 0xbeef_0000);
    exec1(&mut e, Insn::LSwa, enc(Insn::LSwa, &[0, 4, 5]), 0x1000).unwrap();
    assert_ne!(e.backend.get(sem::sr_ref()) & (1 << sr_bit::F), 0);
    let mut buf = [0u8; 4];
    e.backend
        .mem
        .read(VirtAddr(0x8000), &mut buf, acc())
        .unwrap();
    assert_eq!(u32::from_be_bytes(buf), 0xbeef_0000);
}

#[test]
fn fp_single() {
    let mut e = env();
    // r3=1.5f、r4=2.25f のビットパターン。
    e.backend.set(sem::r_ref(3), u64::from(1.5f32.to_bits()));
    e.backend.set(sem::r_ref(4), u64::from(2.25f32.to_bits()));
    // lf.add.s r5,r3,r4 → 3.75。
    e.step(|b| sem::exec(b, Insn::LfAddS, enc(Insn::LfAddS, &[5, 3, 4]), 0x1000, true))
        .unwrap();
    assert_eq!(rget(&mut e, 5) as u32, 3.75f32.to_bits());
    // lf.sfgt.s r4,r3 → 2.25>1.5 → F=1。
    e.step(|b| sem::exec(b, Insn::LfSfgtS, enc(Insn::LfSfgtS, &[4, 3]), 0x1000, true))
        .unwrap();
    assert_ne!(e.backend.get(sem::sr_ref()) & (1 << sr_bit::F), 0);
    // lf.sflt.s r4,r3 → F=0。
    e.step(|b| sem::exec(b, Insn::LfSfltS, enc(Insn::LfSfltS, &[4, 3]), 0x1000, true))
        .unwrap();
    assert_eq!(e.backend.get(sem::sr_ref()) & (1 << sr_bit::F), 0);
    // NaN で unordered: lf.sfun.s は立ち、lf.sfeq.s は立たない。
    e.backend.set(sem::r_ref(6), 0x7fc0_0000);
    e.step(|b| sem::exec(b, Insn::LfSfunS, enc(Insn::LfSfunS, &[6, 3]), 0x1000, true))
        .unwrap();
    assert_ne!(e.backend.get(sem::sr_ref()) & (1 << sr_bit::F), 0);
    e.step(|b| sem::exec(b, Insn::LfSfeqS, enc(Insn::LfSfeqS, &[6, 3]), 0x1000, true))
        .unwrap();
    assert_eq!(e.backend.get(sem::sr_ref()) & (1 << sr_bit::F), 0);
    // lf.sfueq.s は unordered でも立つ。
    e.step(|b| {
        sem::exec(
            b,
            Insn::LfSfueqS,
            enc(Insn::LfSfueqS, &[6, 3]),
            0x1000,
            true,
        )
    })
    .unwrap();
    assert_ne!(e.backend.get(sem::sr_ref()) & (1 << sr_bit::F), 0);
    // lf.ftoi.s/lf.itof.s の往復（既定 RNE）。
    e.backend.set(sem::r_ref(7), u64::from(2.7f32.to_bits()));
    e.step(|b| sem::exec(b, Insn::LfFtoiS, enc(Insn::LfFtoiS, &[8, 7]), 0x1000, true))
        .unwrap();
    assert_eq!(rget(&mut e, 8), 3);
    e.step(|b| sem::exec(b, Insn::LfItofS, enc(Insn::LfItofS, &[9, 8]), 0x1000, true))
        .unwrap();
    assert_eq!(rget(&mut e, 9) as u32, 3.0f32.to_bits());
}

#[test]
fn fp_double_pair() {
    let mut e = env();
    // {r3,r4}=1.5（big-endian pair: r3 が上位語）、{r5,r6}=2.25。
    e.backend
        .set(sem::r_ref(3), (1.5f64.to_bits() >> 32) & 0xffff_ffff);
    e.backend.set(sem::r_ref(4), 1.5f64.to_bits() & 0xffff_ffff);
    e.backend
        .set(sem::r_ref(5), (2.25f64.to_bits() >> 32) & 0xffff_ffff);
    e.backend
        .set(sem::r_ref(6), 2.25f64.to_bits() & 0xffff_ffff);
    // lf.add.d {r7,r8},{r3,r4},{r5,r6}: oo=0 → +1 ペア。
    e.step(|b| {
        sem::exec(
            b,
            Insn::LfAddD,
            enc(Insn::LfAddD, &[7, 3, 5, 0]),
            0x1000,
            true,
        )
    })
    .unwrap();
    let bits = (rget(&mut e, 7) << 32) | rget(&mut e, 8);
    assert_eq!(bits, 3.75f64.to_bits());
    // lf.sfeq.d {r3,r4},{r5,r6} → F=0、lf.sflt.d → F=1。
    e.step(|b| {
        sem::exec(
            b,
            Insn::LfSfltD,
            enc(Insn::LfSfltD, &[3, 5, 0]),
            0x1000,
            true,
        )
    })
    .unwrap();
    assert_ne!(e.backend.get(sem::sr_ref()) & (1 << sr_bit::F), 0);
    e.step(|b| {
        sem::exec(
            b,
            Insn::LfSfeqD,
            enc(Insn::LfSfeqD, &[3, 5, 0]),
            0x1000,
            true,
        )
    })
    .unwrap();
    assert_eq!(e.backend.get(sem::sr_ref()) & (1 << sr_bit::F), 0);
    // lf.stod.d {r9,r10},r3 → r3（1.5f の単精度語）を倍精度へ。
    e.backend.set(sem::r_ref(11), u64::from(1.5f32.to_bits()));
    e.step(|b| {
        sem::exec(
            b,
            Insn::LfStodD,
            enc(Insn::LfStodD, &[9, 11, 0]),
            0x1000,
            true,
        )
    })
    .unwrap();
    let bits = (rget(&mut e, 9) << 32) | rget(&mut e, 10);
    assert_eq!(bits, 1.5f64.to_bits());
    // lf.dtos.d r12,{r3,r4} → 単精度へ戻す。oo bit9 は A2=+1。
    e.step(|b| {
        sem::exec(
            b,
            Insn::LfDtosD,
            enc(Insn::LfDtosD, &[12, 3, 0]),
            0x1000,
            true,
        )
    })
    .unwrap();
    assert_eq!(rget(&mut e, 12) as u32, 1.5f32.to_bits());
}

#[test]
fn delay_slot_advance() {
    // 実行ループと同じ前進規約を検査する: 分岐成立で npc に着地点、
    // 次命令（スロット）実行後に着地点へ。
    let mut e = env();
    let pc = 0x1000u64;
    let taken = e
        .step(|b| sem::exec(b, Insn::LJ, enc(Insn::LJ, &[4]), pc, true))
        .unwrap();
    assert!(taken);
    let target = e.backend.get(sem::npc_ref());
    assert_eq!(target, 0x1010);
    // スロット命令（pc+4）を実行してから着地点へ進む規約。
    let slot_pc = pc + 4;
    let taken2 = e
        .step(|b| sem::exec(b, Insn::LNop, enc(Insn::LNop, &[0]), slot_pc, true))
        .unwrap();
    assert!(!taken2);
    // l.jal のリンクは pc+8（遅延構成）。
    let pc = 0x2000u64;
    e.step(|b| sem::exec(b, Insn::LJal, enc(Insn::LJal, &[0]), pc, true))
        .unwrap();
    assert_eq!(e.backend.get(sem::r_ref(9)), pc + 8);
}

/// MED-3 回帰: l.mac/l.maci/l.msb は加減算段の符号あり桁溢れを
/// SR[OV] へ「代入」し（非桁溢れで落ちる）、l.macu/l.msbu は
/// 符号なし桁溢れ（キャリー/ボロー）を SR[CY] へ代入する。
/// Ref: SPEC-OPENRISC-1000 §5.3（各項の 32-bit Implementation）.
#[test]
fn mac_flag_assignments() {
    let mut e = env();
    e.backend.set(sem::r_ref(3), 1);
    e.backend.set(sem::r_ref(4), 1);
    // acc = i64::MAX に積 +1 を足すと符号あり加算が桁溢れ → OV=1。
    e.backend.set(sem::machi_ref(), 0x7fff_ffff);
    e.backend.set(sem::maclo_ref(), 0xffff_ffff);
    exec1(&mut e, Insn::LMac, enc(Insn::LMac, &[3, 4]), 0x1000).unwrap();
    assert_ne!(e.backend.get(sem::sr_ref()) & (1 << sr_bit::OV), 0);
    // 続く非桁溢れの l.mac は OV を落とす（代入）。
    e.backend.set(sem::machi_ref(), 0);
    e.backend.set(sem::maclo_ref(), 1);
    exec1(&mut e, Insn::LMac, enc(Insn::LMac, &[3, 4]), 0x1000).unwrap();
    assert_eq!(e.backend.get(sem::sr_ref()) & (1 << sr_bit::OV), 0);
    // l.msb: acc = i64::MIN、積=1 → MIN-1 で符号あり桁溢れ → OV=1。
    e.backend.set(sem::machi_ref(), 0x8000_0000);
    e.backend.set(sem::maclo_ref(), 0);
    exec1(&mut e, Insn::LMsb, enc(Insn::LMsb, &[3, 4]), 0x1000).unwrap();
    assert_ne!(e.backend.get(sem::sr_ref()) & (1 << sr_bit::OV), 0);
    // 続く非桁溢れの l.msb は OV を落とす。
    e.backend.set(sem::machi_ref(), 0);
    e.backend.set(sem::maclo_ref(), 5);
    exec1(&mut e, Insn::LMsb, enc(Insn::LMsb, &[3, 4]), 0x1000).unwrap();
    assert_eq!(e.backend.get(sem::sr_ref()) & (1 << sr_bit::OV), 0);
    // l.maci も OV を代入する（acc=i64::MAX + 正の積）。
    e.backend.set(sem::machi_ref(), 0x7fff_ffff);
    e.backend.set(sem::maclo_ref(), 0xffff_ffff);
    exec1(&mut e, Insn::LMaci, enc(Insn::LMaci, &[3, 1]), 0x1000).unwrap();
    assert_ne!(e.backend.get(sem::sr_ref()) & (1 << sr_bit::OV), 0);
    // l.macu: acc = u64::MAX + 1 → キャリーで CY=1。
    e.backend.set(sem::machi_ref(), 0xffff_ffff);
    e.backend.set(sem::maclo_ref(), 0xffff_ffff);
    exec1(&mut e, Insn::LMacu, enc(Insn::LMacu, &[3, 4]), 0x1000).unwrap();
    assert_ne!(e.backend.get(sem::sr_ref()) & (1 << sr_bit::CY), 0);
    // 続く非桁溢れで CY=0（代入）。
    e.backend.set(sem::machi_ref(), 0);
    e.backend.set(sem::maclo_ref(), 1);
    exec1(&mut e, Insn::LMacu, enc(Insn::LMacu, &[3, 4]), 0x1000).unwrap();
    assert_eq!(e.backend.get(sem::sr_ref()) & (1 << sr_bit::CY), 0);
    // l.msbu: acc=0 - 1 → ボローで CY=1。
    e.backend.set(sem::machi_ref(), 0);
    e.backend.set(sem::maclo_ref(), 0);
    exec1(&mut e, Insn::LMsbu, enc(Insn::LMsbu, &[3, 4]), 0x1000).unwrap();
    assert_ne!(e.backend.get(sem::sr_ref()) & (1 << sr_bit::CY), 0);
    // 続く非ボローで CY=0（代入）。
    e.backend.set(sem::machi_ref(), 0);
    e.backend.set(sem::maclo_ref(), 5);
    exec1(&mut e, Insn::LMsbu, enc(Insn::LMsbu, &[3, 4]), 0x1000).unwrap();
    assert_eq!(e.backend.get(sem::sr_ref()) & (1 << sr_bit::CY), 0);
}

/// LOW 回帰: l.div は SR[OV] ← (rB==0) のみを代入し、
/// INT_MIN/-1 では OV を立てず CY にも触れない。l.divu は
/// SR[CY] ← (rB==0) の代入で OV に触れない。
/// Ref: SPEC-OPENRISC-1000 §5.3（l.div/l.divu）.
#[test]
fn div_flag_edges() {
    let mut e = env();
    e.backend.set(sem::r_ref(3), 0x8000_0000); // INT_MIN
    e.backend.set(sem::r_ref(4), 0xffff_ffff); // -1
    // CY=1 を前置し l.div が CY を不変にするか見る。
    e.backend.set(sem::sr_ref(), 1 << sr_bit::CY);
    exec1(&mut e, Insn::LDiv, enc(Insn::LDiv, &[5, 3, 4]), 0x1000).unwrap();
    let sr = e.backend.get(sem::sr_ref());
    assert_eq!(sr & (1 << sr_bit::OV), 0, "INT_MIN/-1 は OV を立てない");
    assert_ne!(sr & (1 << sr_bit::CY), 0, "l.div は CY に触れない");
    assert_eq!(rget(&mut e, 5), 0x8000_0000, "商はラップ結果");
    // 通常除算でも OV=0 のまま。
    e.backend.set(sem::r_ref(4), 2);
    e.backend.set(sem::sr_ref(), 1 << sr_bit::OV);
    exec1(&mut e, Insn::LDiv, enc(Insn::LDiv, &[5, 3, 4]), 0x1000).unwrap();
    assert_eq!(e.backend.get(sem::sr_ref()) & (1 << sr_bit::OV), 0);
    assert_eq!(rget(&mut e, 5), 0xc000_0000, "INT_MIN/2 = -0x40000000");
    // l.divu の 0 除算は CY=1 で OV を触らない。
    e.backend.set(sem::r_ref(4), 0);
    e.backend.set(sem::sr_ref(), 1 << sr_bit::OV);
    exec1(&mut e, Insn::LDivu, enc(Insn::LDivu, &[5, 3, 4]), 0x1000).unwrap();
    let sr = e.backend.get(sem::sr_ref());
    assert_ne!(sr & (1 << sr_bit::CY), 0);
    assert_ne!(sr & (1 << sr_bit::OV), 0, "l.divu は OV に触れない");
    // l.divu の正常除算は CY を落とす。
    e.backend.set(sem::r_ref(4), 2);
    exec1(&mut e, Insn::LDivu, enc(Insn::LDivu, &[5, 3, 4]), 0x1000).unwrap();
    assert_eq!(e.backend.get(sem::sr_ref()) & (1 << sr_bit::CY), 0);
}

/// LOW 回帰: lf.sf*.s の FPCSR 例外。無限入力は全比較で INF。
/// IVF は順序付き比較のみ: sfeq/sfne は signaling NaN、sflt 系は
/// 任意の NaN で立つ。sfu*/sfun は IVF を立てない。
/// Ref: SPEC-OPENRISC-1000 §18（lf.sf*.s 各項の Exceptions）.
#[test]
fn fp_cmp_fpcsr_flags() {
    let mut e = env();
    const INF32: u64 = 0x7f80_0000;
    const QNAN: u64 = 0x7fc0_0000;
    const SNAN: u64 = 0x7f80_0001;
    const ONE: u64 = 0x3f80_0000;
    fn run(e: &mut BareEnv, i: Insn) -> u64 {
        exec1(e, i, enc(i, &[3, 4]), 0x1000).unwrap();
        e.backend.get(sem::fpcsr_ref())
    }
    // 無限入力 → INF（順序付き・unordered 共通）。
    e.backend.set(sem::r_ref(3), INF32);
    e.backend.set(sem::r_ref(4), ONE);
    e.backend.set(sem::fpcsr_ref(), 0);
    assert_ne!(run(&mut e, Insn::LfSfeqS) & (1 << fpcsr_bit::INF), 0);
    e.backend.set(sem::fpcsr_ref(), 0);
    assert_ne!(run(&mut e, Insn::LfSfunS) & (1 << fpcsr_bit::INF), 0);
    // 非無限・非 NaN なら INF は立たない。
    e.backend.set(sem::r_ref(3), ONE);
    e.backend.set(sem::fpcsr_ref(), 0);
    assert_eq!(run(&mut e, Insn::LfSfeqS) & (1 << fpcsr_bit::INF), 0);
    // quiet NaN + sfeq → IVF なし（sNaN のみが対象）。
    e.backend.set(sem::r_ref(3), QNAN);
    e.backend.set(sem::fpcsr_ref(), 0);
    assert_eq!(run(&mut e, Insn::LfSfeqS) & (1 << fpcsr_bit::IVF), 0);
    // signaling NaN + sfeq → IVF。
    e.backend.set(sem::r_ref(3), SNAN);
    e.backend.set(sem::fpcsr_ref(), 0);
    assert_ne!(run(&mut e, Insn::LfSfeqS) & (1 << fpcsr_bit::IVF), 0);
    // quiet NaN + sflt（順序付き大小比較）→ IVF。
    e.backend.set(sem::r_ref(3), QNAN);
    e.backend.set(sem::fpcsr_ref(), 0);
    assert_ne!(run(&mut e, Insn::LfSfltS) & (1 << fpcsr_bit::IVF), 0);
    // signaling NaN + sfueq（unordered）→ IVF なし。
    e.backend.set(sem::r_ref(3), SNAN);
    e.backend.set(sem::fpcsr_ref(), 0);
    assert_eq!(run(&mut e, Insn::LfSfueqS) & (1 << fpcsr_bit::IVF), 0);
    // sfun は NaN 入力で F=1。
    e.backend.set(sem::sr_ref(), 0);
    run(&mut e, Insn::LfSfunS);
    assert_ne!(e.backend.get(sem::sr_ref()) & (1 << sr_bit::F), 0);
}
