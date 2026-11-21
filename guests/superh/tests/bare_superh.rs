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

// ---- 段階18 回帰（レビュー指摘由来） ----

/// データ読み書き用の既定 Access。
fn dacc(endian: Endian) -> Access {
    Access {
        endian,
        align: Align::Natural,
        kind: AccessKind::DataRead,
    }
}

/// メモリに 32 ビット値をエンディアンに従って書く。
fn store32(env: &mut BareEnv, addr: u64, v: u32, endian: Endian) {
    let b = match endian {
        Endian::Le => v.to_le_bytes(),
        Endian::Be => v.to_be_bytes(),
    };
    env.backend.mem.write(VirtAddr(addr), &b).unwrap();
}

/// メモリから 32 ビット値をエンディアンに従って読む。
fn load32(env: &mut BareEnv, addr: u64, endian: Endian) -> u32 {
    let mut b = [0u8; 4];
    env.backend
        .mem
        .read(VirtAddr(addr), &mut b, dacc(endian))
        .unwrap();
    match endian {
        Endian::Le => u32::from_le_bytes(b),
        Endian::Be => u32::from_be_bytes(b),
    }
}

#[test]
fn exec_fmov_pair_sz1() {
    // SZ=1 の fmov.s は 8 バイトの対転送。@Rm+ は +8、@-Rn は -8。
    // メモリ語順はエンディアン不変: mem[ea]→ペア先頭 FR(2i)、
    // mem[ea+4]→FR(2i+1)（各 32 ビット半分が独立にエンディアン
    // 変換される。SH-4 §8.6 の pair access 図は LE/BE ともこの写像）。
    // Ref: SPEC-SUPERH-SH4 §6（fmov の post-increment/pre-decrement
    // は SZ=1 で 8）・§8.6.
    for endian in [Endian::Le, Endian::Be] {
        let mut env = bare();
        env.map_rw(0x2000, 2).unwrap();
        store32(&mut env, 0x2000, 0x1111_1111, endian);
        store32(&mut env, 0x2004, 0x2222_2222, endian);
        set_gpr(&mut env, 4, 0x2000);
        env.backend.set(sem::fpscr_ref(), sem::FPSCR_SZ);
        // fmov.s @r4+, fr6 = 0xF649。n=6 偶数 → DR6={FR6,FR7}。
        sem::exec(&mut env.backend, Insn::FmovSLdp, 0xF649, 0x1000, endian).unwrap();
        assert_eq!(gpr(&mut env, 4), 0x2008, "{endian:?}: @Rm+ is +8");
        assert_eq!(env.backend.get(sem::fr_ref(6)), 0x1111_1111, "{endian:?}");
        assert_eq!(env.backend.get(sem::fr_ref(7)), 0x2222_2222, "{endian:?}");
        // fmov.s fr6, @-r4 = 0xF46B。SZ=1 なら先行減算は -8。
        env.backend.set(sem::fr_ref(6), 0xaaaa_aaaa);
        env.backend.set(sem::fr_ref(7), 0xbbbb_bbbb);
        set_gpr(&mut env, 4, 0x3000);
        sem::exec(&mut env.backend, Insn::FmovSStp, 0xF46B, 0x1000, endian).unwrap();
        assert_eq!(gpr(&mut env, 4), 0x2ff8, "{endian:?}: @-Rn is -8");
        assert_eq!(load32(&mut env, 0x2ff8, endian), 0xaaaa_aaaa, "{endian:?}");
        assert_eq!(load32(&mut env, 0x2ffc, endian), 0xbbbb_bbbb, "{endian:?}");
    }
}

#[test]
fn exec_fmov_pair_xd_bank() {
    // SZ=1 でフィールドの奇数側は XD（反対バンク）のペア。
    // FR=0 のとき奇数フィールドは XF バンクを読み書きし、
    // FR=1 では FR/XF が入れ替わる。DRm→XDn のクロスバンク対転送も
    // 単一の fmov で起きる。Ref: SPEC-SUPERH-SH4A §10.3（load_quad
    // の XD[n>>1]）.
    let mut env = bare();
    env.map_rw(0x2000, 1).unwrap();
    store32(&mut env, 0x2000, 0x1111_1111, Endian::Le);
    store32(&mut env, 0x2004, 0x2222_2222, Endian::Le);
    set_gpr(&mut env, 4, 0x2000);
    env.backend.set(sem::fpscr_ref(), sem::FPSCR_SZ);
    // fmov.s @r4+, fr7 = 0xF749。n=7 奇数 → XD6={XF6,XF7}。
    sem::exec(&mut env.backend, Insn::FmovSLdp, 0xF749, 0x1000, Endian::Le).unwrap();
    assert_eq!(
        env.backend.get(sem::xf_ref(6)),
        0x1111_1111,
        "odd field -> XD pair"
    );
    assert_eq!(env.backend.get(sem::xf_ref(7)), 0x2222_2222);
    assert_eq!(env.backend.get(sem::fr_ref(6)), 0, "FR bank untouched");
    assert_eq!(env.backend.get(sem::fr_ref(7)), 0);
    // fmov fr6, fr7 (0xF76C) + SZ=1: DR6={FR6,FR7} → XD6={XF6,XF7}
    // のクロスバンク対転送。
    env.backend.set(sem::fr_ref(6), 0x3333_3333);
    env.backend.set(sem::fr_ref(7), 0x4444_4444);
    sem::exec(&mut env.backend, Insn::FmovReg, 0xF76C, 0x1000, Endian::Le).unwrap();
    assert_eq!(env.backend.get(sem::xf_ref(6)), 0x3333_3333);
    assert_eq!(env.backend.get(sem::xf_ref(7)), 0x4444_4444);
    // FR=1 でバンクが入れ替わる: m=6 偶数は XF の DR6、n=7 奇数は
    // FR の XD6。XF6/XF7 → FR6/FR7 の対転送になる。
    env.backend
        .set(sem::fpscr_ref(), sem::FPSCR_SZ | sem::FPSCR_FR);
    env.backend.set(sem::fr_ref(6), 0);
    env.backend.set(sem::fr_ref(7), 0);
    sem::exec(&mut env.backend, Insn::FmovReg, 0xF76C, 0x1000, Endian::Le).unwrap();
    assert_eq!(env.backend.get(sem::fr_ref(6)), 0x3333_3333);
    assert_eq!(env.backend.get(sem::fr_ref(7)), 0x4444_4444);
}

#[test]
fn exec_fldi_single_precision() {
    // FLDI0/FLDI1 は PR に依らず FRn へ単精度定数を書く
    // （PR=1 で実行しても DR ペアにはならない）。
    // Ref: SPEC-SUPERH-SH4A §10.3.8/§10.3.9.
    let mut env = bare();
    env.backend.set(sem::fpscr_ref(), sem::FPSCR_PR);
    // fldi1 fr5 = 0xF59D。
    sem::exec(&mut env.backend, Insn::Fldi1, 0xF59D, 0x1000, Endian::Le).unwrap();
    assert_eq!(
        env.backend.get(sem::fr_ref(5)),
        0x3f80_0000,
        "FLDI1 writes single"
    );
    assert_eq!(env.backend.get(sem::fr_ref(6)), 0, "no DR pair write");
    // fldi0 fr5 = 0xF58D。
    sem::exec(&mut env.backend, Insn::Fldi0, 0xF58D, 0x1000, Endian::Le).unwrap();
    assert_eq!(env.backend.get(sem::fr_ref(5)), 0);
    assert_eq!(env.backend.get(sem::fr_ref(6)), 0);
}

#[test]
fn decode_and_exec_bset() {
    // SH-2A の BSET。レジスタ形式 `10000110nnnn1iii` と disp12 形式
    // `0011nnnn0iii1001 0001dddddddddddd`。
    // Ref: SPEC-SUPERH-SH2A §6.3.8.
    assert_eq!(dec(0x863d), Some(Insn::BsetReg)); // bset #5, r3
    assert_eq!(dec32(0x3239_1055), Some(Insn::BsetD12)); // bset.b #3, @(0x55,r2)
    let mut env = bare();
    set_gpr(&mut env, 3, 0);
    sem::exec(&mut env.backend, Insn::BsetReg, 0x863d, 0x1000, Endian::Le).unwrap();
    assert_eq!(gpr(&mut env, 3), 1 << 5);
    // disp12 形式はバイトを読み、imm3 ビットを立てて書き戻す。
    env.map_rw(0x2000, 1).unwrap();
    env.backend.mem.write(VirtAddr(0x2055), &[0x00u8]).unwrap();
    set_gpr(&mut env, 2, 0x2000);
    sem::exec(
        &mut env.backend,
        Insn::BsetD12,
        0x3239_1055,
        0x1000,
        Endian::Le,
    )
    .unwrap();
    let mut b = [0u8; 1];
    env.backend
        .mem
        .read(VirtAddr(0x2055), &mut b, dacc(Endian::Le))
        .unwrap();
    assert_eq!(b[0], 1 << 3);
}

#[test]
fn exec_bst_writes_t() {
    // BST は T を対象ビットへ書き込む。T=0 ならクリア、T=1 なら
    // セット（「セットのみ」では T=0 の書き込みを表せない）。
    // Ref: SPEC-SUPERH-SH2A §6.3.9.
    let mut env = bare();
    set_gpr(&mut env, 3, 0xff);
    // clrt; bst #5, r3（0x8735）→ T=0 なのでビット 5 はクリア。
    sem::exec(&mut env.backend, Insn::Clrt, 0x0008, 0x1000, Endian::Le).unwrap();
    sem::exec(&mut env.backend, Insn::BstReg, 0x8735, 0x1000, Endian::Le).unwrap();
    assert_eq!(gpr(&mut env, 3), 0xff & !(1 << 5), "bst with T=0 clears");
    // sett; bst #4, r3（0x8734）→ ビット 4 も立つ。
    set_gpr(&mut env, 3, 0);
    sem::exec(&mut env.backend, Insn::Sett, 0x0018, 0x1000, Endian::Le).unwrap();
    sem::exec(&mut env.backend, Insn::BstReg, 0x8734, 0x1000, Endian::Le).unwrap();
    assert_eq!(gpr(&mut env, 3), 1 << 4, "bst with T=1 sets");
}

#[test]
fn exec_bank_transfer() {
    // LDBANK/STBANK は R0 の 1 語だけをバンクエントリとやり取り
    // する（メモリを触らない）。エントリは Rn の値で指す
    // （bank=Rn[15:7], entry=Rn[6:2]）。モデルは bank0 の
    // R0_BANK–R7_BANK 相当のみで、範囲外は読めば 0・書き込みは
    // 捨てる。Ref: SPEC-SUPERH-SH2A §6.3.17/§6.3.35, §7.4.2.
    // Gap: GAP-0061
    let mut env = bare();
    set_gpr(&mut env, 0, 0xcafe_f00d);
    set_gpr(&mut env, 5, 3 << 2); // bank0, entry3 → rbank[3]
    // stbank r0, @r5 = 0x45E1。
    sem::exec(&mut env.backend, Insn::Stbank, 0x45e1, 0x1000, Endian::Le).unwrap();
    assert_eq!(env.backend.get(sem::rbank_ref(3)), 0xcafe_f00d);
    assert_eq!(gpr(&mut env, 0), 0xcafe_f00d, "stbank does not clear R0");
    // ldbank @r5, r0 = 0x45E5。
    set_gpr(&mut env, 0, 0);
    sem::exec(&mut env.backend, Insn::Ldbank, 0x45e5, 0x1000, Endian::Le).unwrap();
    assert_eq!(gpr(&mut env, 0), 0xcafe_f00d);
    // 範囲外バンク: 書き込みは捨て、読みは 0。
    set_gpr(&mut env, 5, 1 << 7); // bank1, entry0
    set_gpr(&mut env, 0, 0xaaaa_aaaa);
    sem::exec(&mut env.backend, Insn::Stbank, 0x45e1, 0x1000, Endian::Le).unwrap();
    set_gpr(&mut env, 0, 0);
    sem::exec(&mut env.backend, Insn::Ldbank, 0x45e5, 0x1000, Endian::Le).unwrap();
    assert_eq!(gpr(&mut env, 0), 0);
}

#[test]
fn exec_divs_divu() {
    // SH-2A の DIVS/DIVU（R0 が除数、商のみ）。0 除算は 0 除算例外、
    // DIVS の INT_MIN ÷ -1 はオーバーフロー例外。T は変化しない。
    // Ref: SPEC-SUPERH-SH2A §6.3.13/§6.3.14.
    let mut env = bare();
    set_gpr(&mut env, 2, 100);
    set_gpr(&mut env, 0, 7);
    // divs r0, r2 = 0x4294。
    sem::exec(&mut env.backend, Insn::Divs, 0x4294, 0x1000, Endian::Le).unwrap();
    assert_eq!(gpr(&mut env, 2), 14);
    // 負数の商は 0 方向切捨て。
    set_gpr(&mut env, 2, (-100i32) as u32);
    sem::exec(&mut env.backend, Insn::Divs, 0x4294, 0x1000, Endian::Le).unwrap();
    assert_eq!(gpr(&mut env, 2) as i32, -14);
    // divu r0, r2 = 0x4284。
    set_gpr(&mut env, 2, 0xffff_ffff);
    sem::exec(&mut env.backend, Insn::Divu, 0x4284, 0x1000, Endian::Le).unwrap();
    assert_eq!(gpr(&mut env, 2), 0xffff_ffff / 7);
    // T は変化しない（事前に T=1 を立てても残る）。
    sem::exec(&mut env.backend, Insn::Sett, 0x0018, 0x1000, Endian::Le).unwrap();
    set_gpr(&mut env, 2, 10);
    sem::exec(&mut env.backend, Insn::Divu, 0x4284, 0x1000, Endian::Le).unwrap();
    assert_eq!(sr(&mut env) & sem::SR_T, 1, "divu leaves T alone");
    // 0 除算は DivZero 例外。
    set_gpr(&mut env, 0, 0);
    match sem::exec(&mut env.backend, Insn::Divu, 0x4284, 0x1000, Endian::Le) {
        Err(InterpExit::Exception(e)) => assert_eq!(e.kind, ExceptionKind::DivZero),
        r => panic!("divu by zero: {r:?}"),
    }
    match sem::exec(&mut env.backend, Insn::Divs, 0x4294, 0x1000, Endian::Le) {
        Err(InterpExit::Exception(e)) => assert_eq!(e.kind, ExceptionKind::DivZero),
        r => panic!("divs by zero: {r:?}"),
    }
    // INT_MIN / -1 はオーバーフロー例外。
    set_gpr(&mut env, 0, 0xffff_ffff);
    set_gpr(&mut env, 2, 0x8000_0000);
    match sem::exec(&mut env.backend, Insn::Divs, 0x4294, 0x1000, Endian::Le) {
        Err(InterpExit::Exception(e)) => assert_eq!(e.kind, ExceptionKind::DivZero),
        r => panic!("divs overflow: {r:?}"),
    }
}
