// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! s390 の裸実行テスト（層2・bare、S11-4）。
//!
//! OS 人格を通さず BareEnv の解釈実行だけで、手で組み立てた可変長命令
//! プログラムを回す。z/Architecture 64 ビット有効アドレスと ESA/390 の
//! 31 ビット有効アドレス（amask=0x7fffffff）の両モードを同じプログラム
//! で検査する。
//! 出典は SPEC-S390-ZARCH-POP（SA22-7832）と SPEC-S390-ESA390-POP
//! （SA22-7201）である。
//!
//! テストデータは使わない。

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::Ctrl;
use polyisa_guest_s390::sem::Gpr;
use polyisa_guest_s390::{Insn, decode_model_ex, sem};
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};
use polyisa_sem::Backend;

/// プログラム: r1=5 から 1 まで合計して [r3] へ書き、r5 への自己
/// ループ分岐で停止する。
///
/// ```text
/// 0x1000  lghi %r1,5         a7 19 00 05
/// 0x1004  lghi %r2,0         a7 29 00 00
/// 0x1008  ar   %r2,%r1       1a 21          ; sum += r1
/// 0x100a  ahi  %r1,-1        a7 1a ff ff
/// 0x100e  cghi %r1,0         a7 1f 00 00
/// 0x1012  brc  2,0x1008      a7 24 ff fb    ; r1>0 の間ループ（CC2）
/// 0x1016  stg  %r2,0(%r3)    e3 20 30 00 00 24
/// 0x101c  larl %r5,0x1022    c0 50 00 00 00 03
/// 0x1022  br   %r5           07 f5          ; 自己ループ＝停止番
/// ```
const PROG: &[(u64, &[u8])] = &[(
    0x1000,
    &[
        0xa7, 0x19, 0x00, 0x05, 0xa7, 0x29, 0x00, 0x00, 0x1a, 0x21, 0xa7, 0x1a, 0xff, 0xff, 0xa7,
        0x1f, 0x00, 0x00, 0xa7, 0x24, 0xff, 0xfb, 0xe3, 0x20, 0x30, 0x00, 0x00, 0x24, 0xc0, 0x50,
        0x00, 0x00, 0x00, 0x03, 0x07, 0xf5,
    ],
)];

const HALT: u64 = 0x1022;

/// EX の検査用プログラム。`ex %r1,0(%r10)` が 0x1080 の `stc %r0,0(%r12)`
/// の第 2 バイトを r1 下位バイト（=0x30）で OR 修飾し、`stc %r3,0(%r12)`
/// として実行する。メモリ上の命令バイトは変化しない。
/// 修飾は第 2 バイト全体（RX では上位ニブルが r1、下位が x2）に掛かるので、
/// r1 フィールドに 3 を立てるには修飾値 0x30 が必要。
///
/// ```text
/// 0x1000  lghi %r1,0x30      a7 19 00 30
/// 0x1004  lghi %r10,0x1080   a7 a9 10 80
/// 0x1008  lghi %r3,0xab      a7 39 00 ab
/// 0x100c  ex   %r1,0(%r10)   44 10 a0 00
/// 0x1010  larl %r5,0x1022    c0 50 00 00 00 09
/// 0x1016  br   %r5           07 f5
/// 0x1080  stc  %r0,0(%r12)   42 00 c0 00    ; EX 対象（実行経路では踏まない）
/// ```
const EX_PROG: &[(u64, &[u8])] = &[
    (
        0x1000,
        &[
            0xa7, 0x19, 0x00, 0x30, 0xa7, 0xa9, 0x10, 0x80, 0xa7, 0x39, 0x00, 0xab, 0x44, 0x10,
            0xa0, 0x00, 0xc0, 0x50, 0x00, 0x00, 0x00, 0x09, 0x07, 0xf5,
        ],
    ),
    (0x1080, &[0x42, 0x00, 0xc0, 0x00]),
];

/// 同じ対象を EXRL（PC 相対）で打つ版。`exrl %r1,0x1080` の i2 は
/// 対象 − 命令位置の半ワード数 (0x1080-0x1008)/2 = 0x3c。
///
/// ```text
/// 0x1000  lghi %r1,0x30      a7 19 00 30
/// 0x1004  lghi %r3,0xab      a7 39 00 ab
/// 0x1008  exrl %r1,0x1080    c6 10 00 00 00 3c
/// 0x100e  larl %r5,0x1022    c0 50 00 00 00 0a
/// 0x1014  br   %r5           07 f5
/// 0x1080  stc  %r0,0(%r12)   42 00 c0 00
/// ```
const EXRL_PROG: &[(u64, &[u8])] = &[
    (
        0x1000,
        &[
            0xa7, 0x19, 0x00, 0x30, 0xa7, 0x39, 0x00, 0xab, 0xc6, 0x10, 0x00, 0x00, 0x00, 0x3c,
            0xc0, 0x50, 0x00, 0x00, 0x00, 0x0a, 0x07, 0xf5,
        ],
    ),
    (0x1080, &[0x42, 0x00, 0xc0, 0x00]),
];

fn env(amask: u64, prog: &[(u64, &[u8])]) -> BareEnv {
    let mut e = BareEnv::new(core::mem::size_of::<polyisa_guest_s390::CpuState>());
    e.backend
        .mem
        .map(
            VirtAddr(0x1000),
            1,
            Perms(Perms::R.0 | Perms::W.0 | Perms::X.0),
        )
        .unwrap();
    e.map_rw(0x2000, 1).unwrap();
    e.backend.set(sem::amask_ref(), amask);
    for &(a, bytes) in prog {
        e.backend.mem.write(VirtAddr(a), bytes).unwrap();
    }
    e.pc = 0x1000;
    e
}

/// run_s390 と同じ規約で、先頭バイトから長さを決めて右詰め u64 に畳み、
/// decode → exec → 分岐反映を行う。
fn step(e: &mut BareEnv) -> Result<(), polyisa_engine::interp::InterpExit> {
    let acc = Access {
        endian: Endian::Be,
        align: Align::Natural,
        kind: AccessKind::Fetch,
    };
    let pc = e.pc;
    let mut b0 = [0u8; 1];
    e.backend
        .mem
        .read(VirtAddr(pc), &mut b0, acc)
        .map_err(|e2| polyisa_engine::interp::InterpExit::Unimplemented(format!("{e2:?}")))?;
    let len = match b0[0] >> 6 {
        0 => 2u64,
        1 | 2 => 4,
        _ => 6,
    };
    let mut bytes = [0u8; 6];
    bytes[0] = b0[0];
    e.backend
        .mem
        .read(VirtAddr(pc + 1), &mut bytes[1..len as usize], acc)
        .map_err(|e2| polyisa_engine::interp::InterpExit::Unimplemented(format!("{e2:?}")))?;
    let mut word = 0u64;
    for &x in &bytes[..len as usize] {
        word = (word << 8) | u64::from(x);
    }
    let insn: Insn =
        decode_model_ex(u128::from(word), (len * 8) as u32, true, 0).ok_or_else(|| {
            polyisa_engine::interp::InterpExit::Unimplemented(format!("word {word:#x}"))
        })?;
    if insn == Insn::Ex || insn == Insn::Exrl {
        return step_ex(e, insn, word, pc, len);
    }
    e.step(|b| sem::exec(b, insn, word, pc))?;
    if e.backend.ctrl == Ctrl::Fallthrough {
        e.pc += len;
    }
    Ok(())
}

/// EX/EXRL（run_s390::step_ex と同じ規約）。対象命令をフェッチし、r1 の
/// 下位バイトで第 2 バイトを修飾してから実行する。メモリは書き換えない。
fn step_ex(
    e: &mut BareEnv,
    insn: Insn,
    word: u64,
    pc: u64,
    len: u64,
) -> Result<(), polyisa_engine::interp::InterpExit> {
    let unimpl =
        |w: u64| polyisa_engine::interp::InterpExit::Unimplemented(format!("ex word {w:#x}"));
    let acc = Access {
        endian: Endian::Be,
        align: Align::Natural,
        kind: AccessKind::Fetch,
    };
    let amask = e.backend.get(sem::amask_ref());
    let mut regs = [0u64; 16];
    for (i, v) in regs.iter_mut().enumerate() {
        *v = e.backend.get(Gpr(i as u8).state());
    }
    let (taddr, r1) = sem::execute_target(insn, word, pc, |i| regs[i as usize], amask);
    let modifier = if r1 == 0 {
        0
    } else {
        (regs[r1 as usize] & 0xff) as u8
    };
    let mut b0 = [0u8; 1];
    e.backend
        .mem
        .read(VirtAddr(taddr), &mut b0, acc)
        .map_err(|_| unimpl(word))?;
    let tlen = match b0[0] >> 6 {
        0 => 2u64,
        1 | 2 => 4,
        _ => 6,
    };
    let mut tbytes = [0u8; 6];
    tbytes[0] = b0[0];
    e.backend
        .mem
        .read(VirtAddr(taddr + 1), &mut tbytes[1..tlen as usize], acc)
        .map_err(|_| unimpl(word))?;
    let mut tword = 0u64;
    for &x in &tbytes[..tlen as usize] {
        tword = (tword << 8) | u64::from(x);
    }
    tword = sem::resolve_execute(tword, tlen as u8, modifier);
    let tinsn = decode_model_ex(u128::from(tword), (tlen * 8) as u32, true, 0)
        .ok_or_else(|| unimpl(tword))?;
    if tinsn == Insn::Ex || tinsn == Insn::Exrl {
        return Err(unimpl(tword));
    }
    e.step(|b| sem::exec(b, tinsn, tword, taddr))?;
    if e.backend.ctrl == Ctrl::Fallthrough {
        e.pc += len;
    }
    Ok(())
}

fn run_to_halt(e: &mut BareEnv, limit: u64) {
    let mut n = 0u64;
    while e.pc != HALT {
        step(e).expect("step");
        n += 1;
        assert!(n < limit, "命令ステップ上限超過 pc={:#x}", e.pc);
    }
}

fn mem64(e: &mut BareEnv, a: u64) -> u64 {
    let mut buf = [0u8; 8];
    e.backend
        .mem
        .read(
            VirtAddr(a),
            &mut buf,
            Access {
                endian: Endian::Be,
                align: Align::Natural,
                kind: AccessKind::DataRead,
            },
        )
        .unwrap();
    u64::from_be_bytes(buf)
}

#[test]
fn bare_loop_sum_zarch64() {
    let mut e = env(u64::MAX, PROG);
    e.backend.set(Gpr(3).state(), 0x2000);
    run_to_halt(&mut e, 1000);
    // 5+4+3+2+1 = 15 が [0x2000] にビッグエンディアンで入る。
    assert_eq!(mem64(&mut e, 0x2000), 15);
}

#[test]
fn bare_esa_31bit_amask() {
    // ESA/390: amask=0x7fffffff。ベースレジスタの上位 32 ビットは
    // 有効アドレス計算で捨てられる。
    let mut e = env(0x7fff_ffff, PROG);
    e.backend.set(Gpr(3).state(), 0xffff_ffff_0000_2000);
    run_to_halt(&mut e, 1000);
    assert_eq!(mem64(&mut e, 0x2000), 15);
}

#[test]
fn bare_zarch64_full_address_faults() {
    // 同じベース値を 64 ビットモードで使うと巨大アドレスになり、
    // 未写像でフォールトする。ESA 側との対比。
    let mut e = env(u64::MAX, PROG);
    e.backend.set(Gpr(3).state(), 0xffff_ffff_0000_2000);
    let mut err = None;
    let mut n = 0u64;
    while e.pc != HALT && n < 1000 {
        if let Err(x) = step(&mut e) {
            err = Some(x);
            break;
        }
        n += 1;
    }
    assert!(err.is_some(), "64 ビットモードで未写像アクセスが無視された");
}

#[test]
fn bare_ex_executes_modified_target() {
    // C2: `ex %r1,0(%r10)` が対象 `stc %r0,0(%r12)` の第 2 バイトを
    // r1=0x30 で OR 修飾し、`stc %r3,0(%r12)` として走る。
    let mut e = env(u64::MAX, EX_PROG);
    e.backend.set(Gpr(12).state(), 0x2008);
    run_to_halt(&mut e, 1000);
    // stc が r3 の下位バイト 0xab を [0x2008] に書く。
    assert_eq!(mem64(&mut e, 0x2008), 0xab00_0000_0000_0000);
    // 対象命令のメモリ上のバイト列は修飾されない（PoP: コピーを実行）。
    assert_eq!(mem64(&mut e, 0x1080), 0x4200_c000_0000_0000);
}

#[test]
fn bare_exrl_executes_modified_target() {
    // C2: `exrl %r1,0x1080` も対象第 2 バイトを r1 下位バイトで OR 修飾する。
    let mut e = env(u64::MAX, EXRL_PROG);
    e.backend.set(Gpr(12).state(), 0x2008);
    run_to_halt(&mut e, 1000);
    assert_eq!(mem64(&mut e, 0x2008), 0xab00_0000_0000_0000);
    assert_eq!(mem64(&mut e, 0x1080), 0x4200_c000_0000_0000);
}

#[test]
fn bare_esa_amask_via_la() {
    // `la` は 31 ビットモードでは下位 32 ビットのみ書き換える。
    // stg が通ることを含め、小さな往復で確認する。
    let mut e = env(0x7fff_ffff, PROG);
    e.backend.set(Gpr(3).state(), 0x2000);
    run_to_halt(&mut e, 1000);
    assert_eq!(mem64(&mut e, 0x2000), 15);
}
