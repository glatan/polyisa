// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! SuperH の命令語単位のデコード検査と interp バックエンドでの
//! 裸実行検査（段階18-6・SH4 行）。
//!
//! 前半は生成デコーダがリテラル語を正しく分類すること（16 ビット語と
//! SH-2A の 32 ビット語・機能ゲート）。後半は `sem::exec` を
//! `BareEnv` に乗せて、転送・算術・遅延 `bra`・遅延 `rts`・
//! 条件分岐の遅延スロット規則を確かめる。遅延スロットの遷移は
//! `run_superh` の step と同じ規則をテスト側で回す。
//! 出典は SPEC-SUPERH-SH2・SPEC-SUPERH-SH3・SPEC-SUPERH-SH4・
//! SPEC-SUPERH-SH2A・SPEC-SUPERH-JCORE である。
//! Ref: SPEC-SUPERH-SH2, SPEC-SUPERH-SH3, SPEC-SUPERH-SH4,
//! SPEC-SUPERH-SH2A, SPEC-SUPERH-JCORE.

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::{Ctrl, InterpExit};
use polyisa_guest_superh::{
    CpuState, FEAT_JCORE, FEAT_SH2, FEAT_SH2A, FEAT_SH3, FEAT_SH4, Insn, decode_model_ex, sem,
};
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};
use polyisa_sem::{Backend as _, ExceptionKind};

const SH2: u128 = FEAT_SH2 | FEAT_SH3 | FEAT_SH4;
const SH2A: u128 = SH2 | FEAT_SH2A;
const ALL: u128 = SH2A
    | FEAT_JCORE
    | polyisa_guest_superh::FEAT_FPU
    | polyisa_guest_superh::FEAT_FPUD
    | polyisa_guest_superh::FEAT_SH4A;

fn dec(word: u16) -> Option<Insn> {
    decode_model_ex(u128::from(word), 16, false, ALL)
}

fn dec32(word: u32) -> Option<Insn> {
    decode_model_ex(u128::from(word), 32, false, ALL)
}

#[test]
fn decode_core() {
    // mov #imm8,Rn / mov Rm,Rn。
    assert_eq!(dec(0xe105), Some(Insn::MovImm));
    assert_eq!(dec(0x6213), Some(Insn::MovReg));
    // add #imm8,Rn / add Rm,Rn。
    assert_eq!(dec(0x7103), Some(Insn::AddImm));
    assert_eq!(dec(0x312c), Some(Insn::Add));
    // 分岐。
    assert_eq!(dec(0xa000), Some(Insn::Bra));
    assert_eq!(dec(0xb004), Some(Insn::Bsr));
    assert_eq!(dec(0x000b), Some(Insn::Rts));
    assert_eq!(dec(0x0009), Some(Insn::Nop));
    assert_eq!(dec(0x402b), Some(Insn::Jmp));
    assert_eq!(dec(0x400b), Some(Insn::Jsr));
    assert_eq!(dec(0x0023), Some(Insn::Braf));
    assert_eq!(dec(0x0003), Some(Insn::Bsrf));
    // 条件分岐は 4 形式とも別の命令として出る。
    assert_eq!(dec(0x8b00), Some(Insn::Bf));
    assert_eq!(dec(0x8900), Some(Insn::Bt));
    assert_eq!(dec(0x8f00), Some(Insn::Bfs));
    assert_eq!(dec(0x8d00), Some(Insn::Bts));
    // データ転送。
    assert_eq!(dec(0x6122), Some(Insn::MovLLd));
    assert_eq!(dec(0x2122), Some(Insn::MovLSt));
    assert_eq!(dec(0x9f10), Some(Insn::MovWPcl));
    assert_eq!(dec(0xdf10), Some(Insn::MovLPcl));
    assert_eq!(dec(0xc310), Some(Insn::Trapa));
    assert_eq!(dec(0x0018), Some(Insn::Sett));
    assert_eq!(dec(0x0008), Some(Insn::Clrt));
    assert_eq!(dec(0x0029), Some(Insn::Movt));
}

#[test]
fn decode_sh2a_32bit() {
    // movi20 #{i4}{i16}, Rn: 先頭パーセル `0000 nnnn iiii 0000`、
    // 次パーセルが imm16。SH-2A 機能でのみ解読できる。
    let w = 0x0310_2345;
    assert_eq!(dec32(w), Some(Insn::Movi20));
    assert_eq!(dec32(0x0321_ffff), Some(Insn::Movi20s));
    // 先頭パーセルだけでは 16 ビット語彙に入らない。
    assert_eq!(dec(0x0310), None);
    // SH-2A 機能を外すと 32 ビット語彙も解読できない。
    assert_eq!(decode_model_ex(u128::from(w), 32, false, SH2), None);
    // disp12 の mov。`mov.b @(disp12,Rm),Rn` = `0011 nmmm 0001 0000` + d12。
    assert_eq!(dec32(0x3201_4123), Some(Insn::MovBD12Ld));
}

#[test]
fn decode_feature_gating() {
    // SH-3/SH-4 追加分（clrs/ldtlb）は SH-2 だけでは解読できない。
    assert_eq!(dec(0x0048), Some(Insn::Clrs));
    assert_eq!(decode_model_ex(0x0048, 16, false, FEAT_SH2), None);
    assert_eq!(dec(0x0038), Some(Insn::Ldtlb));
    assert_eq!(decode_model_ex(0x0038, 16, false, FEAT_SH2), None);
    // SH-4 の movca/ocbi。
    assert_eq!(dec(0x04c3), Some(Insn::Movca));
    assert_eq!(decode_model_ex(0x04c3, 16, false, FEAT_SH2), None);
    // J-core の cas.l。
    assert_eq!(dec(0x2123), Some(Insn::CasL));
    assert_eq!(decode_model_ex(0x2123, 16, false, SH2), None);
    // SH-2A の rts/n。
    assert_eq!(dec(0x006b), Some(Insn::Rtsn));
    assert_eq!(decode_model_ex(0x006b, 16, false, SH2), None);
}

#[test]
fn decode_sh4a_gating() {
    // SH-4A 追加分は sh4a 機能だけで解読できる（0x00ab は SH-4 では
    // 未割当。BE BusyBox が SH-4A バイナリで synco を踏む経路）。
    // Ref: SPEC-SUPERH-SH4A.
    let sh4 = SH2; // sh1+sh2+sh3+sh4 相当（sh4a 無し）
    assert_eq!(dec(0x00ab), Some(Insn::Synco));
    assert_eq!(decode_model_ex(0x00ab, 16, false, sh4), None);
    // movli.l @r4, r0 / movco.l r0, @r4。
    assert_eq!(dec(0x0463), Some(Insn::Movli));
    assert_eq!(dec(0x0473), Some(Insn::Movco));
    assert_eq!(decode_model_ex(0x0463, 16, false, sh4), None);
    assert_eq!(decode_model_ex(0x0473, 16, false, sh4), None);
    // icbi/prefi/dbr 系も同じく sh4a ゲート。
    assert_eq!(decode_model_ex(0x04e3, 16, false, sh4), None); // icbi @r4
    assert_eq!(decode_model_ex(0x04d3, 16, false, sh4), None); // prefi @r4
    assert_eq!(decode_model_ex(0x00fa, 16, false, sh4), None); // stc dbr, r0
    // movua.l は sh4a と sh2a の両方で解読できる。
    assert_eq!(dec(0x40a9), Some(Insn::MovuaL));
    assert_eq!(decode_model_ex(0x40a9, 16, false, sh4), None);
    assert_eq!(
        decode_model_ex(0x40a9, 16, false, SH2 | FEAT_SH2A),
        Some(Insn::MovuaL)
    );
}

// ---- 裸実行検査 ----

fn bare() -> BareEnv {
    BareEnv::new(core::mem::size_of::<CpuState>())
}

/// コードページを RWX で写像する（フェッチは X 権限を要求する）。
fn map_code(env: &mut BareEnv, base: u64) {
    env.backend
        .mem
        .map(
            VirtAddr(base),
            1,
            Perms(Perms::R.0 | Perms::W.0 | Perms::X.0),
        )
        .unwrap();
}

fn gpr(env: &mut BareEnv, n: u8) -> u32 {
    env.backend.get(sem::R(n).state())
}

fn set_gpr(env: &mut BareEnv, n: u8, v: u32) {
    env.backend.set(sem::R(n).state(), v);
}

fn sr(env: &mut BareEnv) -> u32 {
    env.backend.get(sem::sr_ref())
}

fn fetch16(env: &BareEnv, pc: u64, endian: Endian) -> Option<u16> {
    let mut b = [0u8; 2];
    let acc = Access {
        endian,
        align: Align::Natural,
        kind: AccessKind::Fetch,
    };
    env.backend.mem.read(VirtAddr(pc), &mut b, acc).ok()?;
    Some(match endian {
        Endian::Le => u16::from_le_bytes(b),
        Endian::Be => u16::from_be_bytes(b),
    })
}

/// `pc` の命令を解読する。（命令, 語, バイト長）を返す。
fn fetch_insn(env: &BareEnv, pc: u64, endian: Endian) -> Option<(Insn, u32, u64)> {
    let p1 = fetch16(env, pc, endian)?;
    if let Some(insn) = decode_model_ex(u128::from(p1), 16, false, ALL) {
        return Some((insn, u32::from(p1), 2));
    }
    let p2 = fetch16(env, pc + 2, endian)?;
    let w = (u32::from(p1) << 16) | u32::from(p2);
    let insn = decode_model_ex(u128::from(w), 32, false, ALL)?;
    Some((insn, w, 4))
}

/// 分岐系命令か（遅延スロット中の禁止対象と、ターゲット転移の対象）。
fn is_branch(insn: Insn) -> bool {
    matches!(
        insn,
        Insn::Bra
            | Insn::Bsr
            | Insn::Braf
            | Insn::Bsrf
            | Insn::Bf
            | Insn::Bfs
            | Insn::Bt
            | Insn::Bts
            | Insn::Jmp
            | Insn::Jsr
            | Insn::Rts
            | Insn::Rtsn
            | Insn::Rtvn
            | Insn::JsrnMem
            | Insn::JsrnTbr
    )
}

/// 1 命令ぶん。遅延スロットを含む分岐の遷移もここで行い、
/// 次に実行する pc を返す。`run_superh` の step と同じ規則。
fn step(env: &mut BareEnv, endian: Endian) -> Result<u64, String> {
    let pc = env.pc;
    let (insn, word, len) = fetch_insn(env, pc, endian).ok_or("undecoded")?;
    // 遅延スロットを持つか。スロットは常に実行される（annul 無し）。
    // bf/bt は遅延スロットを持たない通常の条件分岐。
    let delayed = matches!(
        insn,
        Insn::Bra
            | Insn::Bsr
            | Insn::Braf
            | Insn::Bsrf
            | Insn::Jmp
            | Insn::Jsr
            | Insn::Rts
            | Insn::Bfs
            | Insn::Bts
    );
    let direct = matches!(
        insn,
        Insn::Rtsn | Insn::Rtvn | Insn::JsrnMem | Insn::JsrnTbr
    );
    env.backend.ctrl = Ctrl::Fallthrough;
    let ok =
        sem::exec(&mut env.backend, insn, word, pc, endian).map_err(|e| format!("exec: {e:?}"))?;
    assert!(ok, "insn {word:#x} unimplemented");
    let target = match env.backend.ctrl {
        Ctrl::Jump(t) => Some(t),
        Ctrl::Fallthrough => None,
    };
    if direct {
        return Ok(target.expect("direct branch has target"));
    }
    if delayed {
        // 遅延スロット（pc+2 の 16 ビット命令）。
        let spc = pc + 2;
        let (sinsn, sword, slen) = fetch_insn(env, spc, endian).ok_or("delay slot undecoded")?;
        assert_eq!(slen, 2, "32-bit insn in delay slot");
        assert!(!is_branch(sinsn), "branch in delay slot");
        env.backend.ctrl = Ctrl::Fallthrough;
        let ok = sem::exec(&mut env.backend, sinsn, sword, spc, endian)
            .map_err(|e| format!("slot exec: {e:?}"))?;
        assert!(ok);
        assert!(matches!(env.backend.ctrl, Ctrl::Fallthrough), "slot jumped");
        return Ok(target.unwrap_or(pc + 4));
    }
    Ok(target.unwrap_or(pc + len))
}

/// `pc` から `trapa`（例外）か `limit` 命令ぶんまで回す。
fn run(env: &mut BareEnv, endian: Endian, limit: u64) -> Result<(), InterpExit> {
    for _ in 0..limit {
        let pc = env.pc;
        match step(env, endian) {
            Ok(next) => env.pc = next,
            Err(e) => {
                // step 内の例外は trapa だけ（テストの終端）。
                let (_, word, _) = fetch_insn(env, pc, endian)
                    .unwrap_or_else(|| panic!("fetched pc={pc:#x} err={e}"));
                let insn = decode_model_ex(u128::from(word & 0xffff), 16, false, ALL);
                assert_eq!(insn, Some(Insn::Trapa), "step failed at pc={pc:#x}: {e}");
                let r = sem::exec(&mut env.backend, Insn::Trapa, word, pc, endian);
                return r.map(|_| ());
            }
        }
    }
    Ok(())
}

/// メモリに 16 ビット語を書く。
fn poke16(env: &mut BareEnv, addr: u64, w: u16, endian: Endian) {
    let b = match endian {
        Endian::Le => w.to_le_bytes(),
        Endian::Be => w.to_be_bytes(),
    };
    env.backend.mem.write(VirtAddr(addr), &b).unwrap();
}

/// メモリに 32 ビット語を書く（パーセル順。上位語が先）。
fn poke32(env: &mut BareEnv, addr: u64, w: u32, endian: Endian) {
    poke16(env, addr, (w >> 16) as u16, endian);
    poke16(env, addr + 2, w as u16, endian);
}

#[test]
fn exec_mov_add() {
    let mut env = bare();
    map_code(&mut env, 0x1000);
    let pc = 0x1000;
    // mov #5, r1; mov #3, r2; add r2, r1; add #-1, r1; trapa #0。
    let prog = [0xe105, 0xe203, 0x312c, 0x71ff, 0xc300];
    for (i, w) in prog.iter().enumerate() {
        poke16(&mut env, pc + 2 * i as u64, *w, Endian::Le);
    }
    env.pc = pc;
    run(&mut env, Endian::Le, 8).unwrap_err();
    assert_eq!(gpr(&mut env, 1), 5 + 3 - 1);
    assert_eq!(gpr(&mut env, 2), 3);
}

#[test]
fn exec_mov_memory() {
    let mut env = bare();
    map_code(&mut env, 0x1000);
    env.map_rw(0x2000, 1).unwrap();
    // mov #0x34, r1; mov.l r1, @r2; mov.l @r2, r3; trapa。
    let prog = [0xe134, 0x2212, 0x6322, 0xc300];
    for (i, w) in prog.iter().enumerate() {
        poke16(&mut env, 0x1000 + 2 * i as u64, *w, Endian::Le);
    }
    set_gpr(&mut env, 2, 0x2000);
    env.pc = 0x1000;
    run(&mut env, Endian::Le, 8).unwrap_err();
    assert_eq!(gpr(&mut env, 3), 0x34);
    // 実メモリにも書かれている（リトルエンディアン）。
    let mut b = [0u8; 4];
    let acc = Access {
        endian: Endian::Le,
        align: Align::Natural,
        kind: AccessKind::DataRead,
    };
    env.backend.mem.read(VirtAddr(0x2000), &mut b, acc).unwrap();
    assert_eq!(u32::from_le_bytes(b), 0x34);
}

#[test]
fn exec_delayed_bra() {
    let mut env = bare();
    map_code(&mut env, 0x1000);
    // bra +1（target=pc+6）; mov #1, r1（遅延スロット）;
    // mov #2, r2; mov #3, r3; trapa。
    // bra の後、r1 は必ず実行される（遅延スロット）。
    let prog = [0xa001, 0xe101, 0xe202, 0xe303, 0xc300];
    for (i, w) in prog.iter().enumerate() {
        poke16(&mut env, 0x1000 + 2 * i as u64, *w, Endian::Le);
    }
    env.pc = 0x1000;
    run(&mut env, Endian::Le, 8).unwrap_err();
    assert_eq!(gpr(&mut env, 1), 1, "delay slot ran");
    assert_eq!(gpr(&mut env, 2), 0, "pc+4 skipped by bra");
    assert_eq!(gpr(&mut env, 3), 3, "target ran");
}

#[test]
fn exec_delayed_rts() {
    let mut env = bare();
    map_code(&mut env, 0x1000);
    // bsr +2（target=pc+8、PR=pc+4）; mov #9, r1（遅延スロット）;
    // mov #8, r2; rts; mov #7, r3（rts の遅延スロット）;
    // mov #6, r4（帰り先）; trapa。
    let prog = [0xb002, 0xe109, 0xe208, 0x000b, 0xe307, 0xe406, 0xc300];
    for (i, w) in prog.iter().enumerate() {
        poke16(&mut env, 0x1000 + 2 * i as u64, *w, Endian::Le);
    }
    env.pc = 0x1000;
    run(&mut env, Endian::Le, 8).unwrap_err();
    assert_eq!(gpr(&mut env, 1), 9, "bsr delay slot ran");
    assert_eq!(gpr(&mut env, 2), 0, "pc+4 skipped by bsr");
    assert_eq!(gpr(&mut env, 3), 7, "rts delay slot ran");
    assert_eq!(gpr(&mut env, 4), 6, "return target ran");
    // PR は pc+4（bsr の次の次）。
    assert_eq!(env.backend.get(sem::pr_ref()), 0x1004);
}

#[test]
fn exec_bf_bt_slot_rules() {
    // bf/bt は遅延スロットを持たない（不成立なら pc+2、成立なら
    // 即ターゲット）。bf.s/bt.s は遅延スロットを持ち、成立・不成立
    // にかかわらずスロットを実行する（annul は無い）。
    let mut env = bare();
    map_code(&mut env, 0x1000);
    // sett; bf +2（不成立・T=1）;
    // mov #1, r1（pc+2・普通に実行される）;
    // mov #8, r2; mov #9, r3; trapa。
    let prog = [0x0018, 0x8b02, 0xe101, 0xe208, 0xe309, 0xc300];
    for (i, w) in prog.iter().enumerate() {
        poke16(&mut env, 0x1000 + 2 * i as u64, *w, Endian::Le);
    }
    env.pc = 0x1000;
    run(&mut env, Endian::Le, 8).unwrap_err();
    assert_eq!(gpr(&mut env, 1), 1, "bf not taken: next insn runs");
    assert_eq!(gpr(&mut env, 2), 8, "not taken: fall through");
    assert_eq!(gpr(&mut env, 3), 9);

    // bf 成立: pc+2 の命令を飛ばしてターゲットへ（遅延スロットなし）。
    let mut env = bare();
    map_code(&mut env, 0x1000);
    // clrt; bf +1（成立・T=0、target=pc+4+2=pc+8）; mov #1, r1（飛ばす）;
    // mov #8, r2（飛ばす）; mov #9, r3; trapa。
    let prog = [0x0008, 0x8b01, 0xe101, 0xe208, 0xe309, 0xc300];
    for (i, w) in prog.iter().enumerate() {
        poke16(&mut env, 0x1000 + 2 * i as u64, *w, Endian::Le);
    }
    env.pc = 0x1000;
    run(&mut env, Endian::Le, 8).unwrap_err();
    assert_eq!(gpr(&mut env, 1), 0, "bf taken: pc+2 skipped");
    assert_eq!(gpr(&mut env, 2), 0, "bf taken: pc+4 skipped");
    assert_eq!(gpr(&mut env, 3), 9, "bf target ran");

    // bf.s 不成立: スロットは実行されるが pc は pc+4。
    let mut env = bare();
    map_code(&mut env, 0x1000);
    // sett; bf/s +2（不成立・T=1、次は pc+4）; mov #1, r1（スロット・走る）;
    // mov #8, r2; mov #9, r3; trapa。
    let prog = [0x0018, 0x8f02, 0xe101, 0xe208, 0xe309, 0xc300];
    for (i, w) in prog.iter().enumerate() {
        poke16(&mut env, 0x1000 + 2 * i as u64, *w, Endian::Le);
    }
    env.pc = 0x1000;
    run(&mut env, Endian::Le, 8).unwrap_err();
    assert_eq!(gpr(&mut env, 1), 1, "bf/s slot always runs");
    assert_eq!(gpr(&mut env, 2), 8, "not taken: continues after slot");
    assert_eq!(gpr(&mut env, 3), 9);

    // bf.s 成立: スロットを実行してターゲットへ。
    let mut env = bare();
    map_code(&mut env, 0x1000);
    // clrt; bf/s +1（成立・target=pc+2+4+2=pc+8）; mov #1, r1（スロット）;
    // mov #8, r2; mov #9, r3; trapa。
    let prog = [0x0008, 0x8f01, 0xe101, 0xe208, 0xe309, 0xc300];
    for (i, w) in prog.iter().enumerate() {
        poke16(&mut env, 0x1000 + 2 * i as u64, *w, Endian::Le);
    }
    env.pc = 0x1000;
    run(&mut env, Endian::Le, 8).unwrap_err();
    assert_eq!(gpr(&mut env, 1), 1, "bf/s taken: slot ran");
    assert_eq!(gpr(&mut env, 2), 0, "pc+6 skipped");
    assert_eq!(gpr(&mut env, 3), 9, "target ran");
}

#[test]
fn exec_big_endian_fetch() {
    // 同一プログラムをビッグエンディアンのパーセル並びで実行する。
    let mut env = bare();
    map_code(&mut env, 0x1000);
    // mov #5, r1; mov #3, r2; add r2, r1; bra +1;
    // mov #9, r3（スロット）; mov #5, r4（飛ばす）; trapa。
    let prog = [0xe105, 0xe203, 0x312c, 0xa001, 0xe309, 0xe405, 0xc300];
    for (i, w) in prog.iter().enumerate() {
        poke16(&mut env, 0x1000 + 2 * i as u64, *w, Endian::Be);
    }
    env.pc = 0x1000;
    run(&mut env, Endian::Be, 8).unwrap_err();
    assert_eq!(gpr(&mut env, 1), 8);
    assert_eq!(gpr(&mut env, 3), 9, "delay slot ran under BE fetch");
    assert_eq!(gpr(&mut env, 4), 0, "BE bra skipped pc+8");
}

#[test]
fn exec_movi20() {
    let mut env = bare();
    map_code(&mut env, 0x1000);
    // movi20 #0x12345, r3; trapa。
    poke32(&mut env, 0x1000, 0x0310_2345, Endian::Le);
    poke16(&mut env, 0x1004, 0xc300, Endian::Le);
    env.pc = 0x1000;
    run(&mut env, Endian::Le, 4).unwrap_err();
    assert_eq!(gpr(&mut env, 3), 0x12345);
}

#[test]
fn exec_trapa_raises() {
    let mut env = bare();
    let r = sem::exec(&mut env.backend, Insn::Trapa, 0xc37f, 0x1000, Endian::Le);
    match r {
        Err(InterpExit::Exception(e)) => {
            assert_eq!(e.kind, ExceptionKind::Trap);
            assert_eq!(e.code, 0x7f);
        }
        _ => panic!("trapa should raise"),
    }
}

#[test]
fn exec_cmp_str() {
    // cmp/str は一致バイトがあれば T=1。
    let mut env = bare();
    set_gpr(&mut env, 1, 0x1122_3344);
    set_gpr(&mut env, 2, 0x5566_3344);
    let ok = sem::exec(&mut env.backend, Insn::CmpStr, 0x3124, 0x1000, Endian::Le).unwrap();
    assert!(ok);
    assert_eq!(sr(&mut env) & sem::SR_T, 1);
}

#[test]
fn exec_div1_div0u_unsigned_divide() {
    // r1:r2 / r0 の教科書的な 64:32 無符号除算。
    // `div0u; (rotcl r2; div1 r0,r1)×32; rotcl r2` で商が r2 に
    // 集約される（各 rotcl が T に配って次の div1 の代入元にし、
    // 帰ってきた商ビットを r2 の LSB に拾う）。
    // div1 の Q 更新は `Q' = MSB(Rn) ^ M ^ (add: carry | sub: borrow)`、
    // T'=(Q'==M) でなければならず、ずれると商が化ける（glibc の udiv
    // 経路で観測した回帰）。Ref: SPEC-SUPERH-SH4, SPEC-SUPERH-JCORE.
    for &(dividend, divisor) in [
        (5u32, 0x1000u32),
        (0x6e14d005, 0x1000),
        (0xdeadbeef, 3),
        (0xffff_ffff, 1),
        (0, 7),
        (1, 1),
        (0x8000_0000, 2),
        (0xffff_fffe, 3),
        (123456789, 1000),
    ]
    .iter()
    {
        let mut env = bare();
        set_gpr(&mut env, 0, divisor);
        set_gpr(&mut env, 1, 0);
        set_gpr(&mut env, 2, dividend);
        sem::exec(&mut env.backend, Insn::Div0u, 0x0019, 0x1000, Endian::Le).unwrap();
        for _ in 0..32 {
            // rotcl r2 = 4n24、div1 r0,r1 = 3nm4。
            sem::exec(&mut env.backend, Insn::Rotcl, 0x4224, 0x1000, Endian::Le).unwrap();
            sem::exec(&mut env.backend, Insn::Div1, 0x3104, 0x1000, Endian::Le).unwrap();
        }
        sem::exec(&mut env.backend, Insn::Rotcl, 0x4224, 0x1000, Endian::Le).unwrap();
        assert_eq!(
            gpr(&mut env, 2),
            dividend.wrapping_div(divisor),
            "{dividend:#x} / {divisor:#x}"
        );
    }
}

#[test]
fn exec_movli_movco() {
    // SH-4A の load-reserved / store-conditional 対。単発なら
    // movco は必ず成功して T=1。Ref: SPEC-SUPERH-SH4A.
    let mut env = bare();
    env.map_rw(0x2000, 1).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0xdead_beefu32.to_le_bytes())
        .unwrap();
    set_gpr(&mut env, 4, 0x2000);
    // movli.l @r4, r0。
    sem::exec(&mut env.backend, Insn::Movli, 0x0463, 0x1000, Endian::Le).unwrap();
    assert_eq!(gpr(&mut env, 0), 0xdead_beef);
    // movco.l r0, @r4。
    set_gpr(&mut env, 0, 0x1234_5678);
    sem::exec(&mut env.backend, Insn::Movco, 0x0473, 0x1000, Endian::Le).unwrap();
    assert_eq!(sr(&mut env) & sem::SR_T, 1, "movco should succeed");
    let mut b = [0u8; 4];
    env.backend
        .mem
        .read(
            VirtAddr(0x2000),
            &mut b,
            Access {
                endian: Endian::Le,
                align: Align::Natural,
                kind: AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u32::from_le_bytes(b), 0x1234_5678);
}
