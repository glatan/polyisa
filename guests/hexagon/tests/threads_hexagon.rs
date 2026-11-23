// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Hexagon の HW スレッド交互実行モデル（`threads::Core`）の検証。
//! ラウンドロビンの発行列・単一スレッド退化・pause の休眠/復帰・
//! スレッド独立の状態と共有メモリ・trap の引き継ぎと待ちを確かめる。
//! 出典は SPEC-HEXAGON-PRM V79 (80-N2040-60 Rev AB) である。
//! Ref: SPEC-HEXAGON-PRM (V79).

use polyisa_engine::bare::BareEnv;
use polyisa_engine::run::{Outcome, TrapHandler, TrapOutcome};
use polyisa_guest_hexagon::threads::Core;
use polyisa_guest_hexagon::{Insn, encode, sem};
use polyisa_mem::{Perms, VirtAddr};
use polyisa_sem::Backend as _;

const BASE: u64 = 0x1_0000;

/// トラップを捌かないハンドラ。
struct NoSys;

impl TrapHandler for NoSys {
    fn handle_trap(&mut self, _env: &mut BareEnv, _code: u32) -> TrapOutcome {
        TrapOutcome::Unimplemented
    }
}

fn with_pp(word: u32, pp: u32) -> u32 {
    (word & !0xc000) | ((pp & 3) << 14)
}

/// `n` スレッドのコア。コード領域を RWX で写像する。
fn core(n: usize) -> Core {
    let mut c = Core::new(n, 0);
    c.env_mut()
        .backend
        .mem
        .map(VirtAddr(BASE), 1, Perms(Perms::RW.0 | Perms::X.0))
        .unwrap();
    c
}

/// 命令語列を書き込む。
fn put(c: &mut Core, addr: u64, words: &[u32]) {
    let mut b = Vec::new();
    for w in words {
        b.extend_from_slice(&w.to_le_bytes());
    }
    c.env_mut().backend.mem.write(VirtAddr(addr), &b).unwrap();
}

/// 1 語パケット `Rd = add(Rs,#imm)`（終端印付き）。
fn addi(d: u64, s: u64, i: u64) -> u32 {
    with_pp(encode(Insn::AddRi, &[d, s, i]).unwrap() as u32, 3)
}

/// 1 語パケット `pause(#u)`（終端印付き）。
fn pause(u: u64) -> u32 {
    with_pp(encode(Insn::Pause, &[u]).unwrap() as u32, 3)
}

/// 1 語パケット `trap0(#u)`（終端印付き）。
fn trap0(u: u64) -> u32 {
    with_pp(encode(Insn::Trap0, &[u]).unwrap() as u32, 3)
}

#[test]
fn round_robin_schedule() {
    // 3 スレッドがパケット単位で交互に発行される。
    let mut c = core(3);
    for t in 0..3u64 {
        let addr = BASE + 0x40 * t;
        put(&mut c, addr, &[addi(1, 1, 1), addi(1, 1, 1), addi(1, 1, 1)]);
        c.with_thread(t as usize, |env| env.pc = addr);
    }
    let mut order = Vec::new();
    for _ in 0..9 {
        order.push(c.step(&mut NoSys).unwrap());
    }
    assert_eq!(
        order,
        vec![
            Some(0),
            Some(1),
            Some(2),
            Some(0),
            Some(1),
            Some(2),
            Some(0),
            Some(1),
            Some(2),
        ]
    );
    // 各スレッドの r1 は独立に 3 加算された。
    for t in 0..3usize {
        assert_eq!(c.issued(t), 3);
        assert_eq!(c.with_thread(t, |env| sem::r_get(&env.backend, 1)), 3);
    }
    assert_eq!(c.now().0, 9);
}

#[test]
fn single_thread_runs_like_step() {
    // n=1 の退化形は run::step と同じパケット列を辿る。
    let mut c = core(1);
    put(&mut c, BASE, &[addi(1, 0, 5), addi(2, 1, 7)]);
    c.with_thread(0, |env| env.pc = BASE);
    assert_eq!(c.step(&mut NoSys), Ok(Some(0)));
    assert_eq!(c.step(&mut NoSys), Ok(Some(0)));
    c.with_thread(0, |env| {
        assert_eq!(sem::r_get(&env.backend, 1), 5);
        assert_eq!(sem::r_get(&env.backend, 2), 12);
        assert_eq!(env.pc, BASE + 8);
    });
    assert_eq!(c.issued(0), 2);
}

#[test]
fn pause_suspends_and_resumes() {
    // pause(#0) の発行から次の発行まで 8 発行枠の休眠
    // （正本の #u+8 サイクル）。
    let mut c = core(2);
    put(&mut c, BASE, &[pause(0), addi(1, 1, 1)]);
    let w = addi(2, 2, 1);
    put(&mut c, BASE + 0x40, &[w; 8]);
    c.with_thread(0, |env| env.pc = BASE);
    c.with_thread(1, |env| env.pc = BASE + 0x40);
    let mut seq = Vec::new();
    for _ in 0..10 {
        seq.push(c.step(&mut NoSys).unwrap());
    }
    assert_eq!(
        seq,
        vec![
            Some(0), // pause を発行して休眠へ
            Some(1),
            Some(1),
            Some(1),
            Some(1),
            Some(1),
            Some(1),
            Some(1), // 休眠中は t1 が枠を埋める
            Some(0), // 8 枠後に復帰
            Some(1),
        ]
    );
    assert_eq!(c.issued(0), 2);
    assert_eq!(c.issued(1), 8);
}

#[test]
fn all_asleep_gives_idle_slots() {
    // 唯一スレッドが pause(#3) すると 3+8 枠後に復帰するまで
    // アイドル枠（None）が返る。
    let mut c = core(1);
    put(&mut c, BASE, &[pause(3), addi(1, 1, 1)]);
    c.with_thread(0, |env| env.pc = BASE);
    assert_eq!(c.step(&mut NoSys), Ok(Some(0)));
    for _ in 0..10 {
        assert_eq!(c.step(&mut NoSys), Ok(None));
    }
    assert_eq!(c.step(&mut NoSys), Ok(Some(0)));
    assert_eq!(c.issued(0), 2);
    assert_eq!(c.now().0, 12);
}

#[test]
fn threads_share_memory_keep_own_state() {
    // メモリは共有: t0 のストアを t1 がロードで読む。
    // レジスタはスレッドごとに独立。
    let mut c = core(2);
    const SHARED: u64 = BASE + 0x200;
    // t0: memw(r4+#0) = r5。t1: r3 = memw(r4+#0)。
    let st = with_pp(encode(Insn::StRi, &[4, 5, 4, 0]).unwrap() as u32, 3);
    let ld = with_pp(encode(Insn::LdRi, &[3, 4, 4, 0]).unwrap() as u32, 3);
    put(&mut c, BASE, &[st]);
    put(&mut c, BASE + 0x40, &[ld]);
    c.with_thread(0, |env| {
        env.pc = BASE;
        sem::r_set(&mut env.backend, 4, SHARED as u32);
        sem::r_set(&mut env.backend, 5, 0xdead);
        sem::r_set(&mut env.backend, 1, 0x1111);
    });
    c.with_thread(1, |env| {
        env.pc = BASE + 0x40;
        sem::r_set(&mut env.backend, 4, SHARED as u32);
        sem::r_set(&mut env.backend, 1, 0x2222);
    });
    assert_eq!(c.step(&mut NoSys), Ok(Some(0)));
    assert_eq!(c.step(&mut NoSys), Ok(Some(1)));
    assert_eq!(c.with_thread(1, |env| sem::r_get(&env.backend, 3)), 0xdead);
    // 同名レジスタはスレッドごとに別々。
    assert_eq!(c.with_thread(0, |env| sem::r_get(&env.backend, 1)), 0x1111);
    assert_eq!(c.with_thread(1, |env| sem::r_get(&env.backend, 1)), 0x2222);
}

/// trap の即値と報告したスレッド番号を記録し、Exit を別スレッドへ
/// 引き継ぐハンドラ。
struct TakeExit {
    traps: Vec<(u32, u32)>,
}

impl TrapHandler for TakeExit {
    fn handle_trap(&mut self, env: &mut BareEnv, code: u32) -> TrapOutcome {
        let tid = env.backend.get(sem::hwt_ref()) & polyisa_guest_hexagon::threads::hwt::TID;
        self.traps.push((tid, code));
        TrapOutcome::Exit(code)
    }

    fn take_exit(&mut self, _env: &mut BareEnv, _code: u32) -> bool {
        true
    }
}

#[test]
fn exit_hands_off_to_remaining_threads() {
    // trap0 → Exit は引き取られるとそのスレッドだけが終わる。
    // 全スレッドの終了で最後のコードの Exit が返る。
    let mut c = core(2);
    put(&mut c, BASE, &[trap0(7)]);
    put(&mut c, BASE + 0x40, &[trap0(9)]);
    c.with_thread(0, |env| env.pc = BASE);
    c.with_thread(1, |env| env.pc = BASE + 0x40);
    let mut sys = TakeExit { traps: Vec::new() };
    // 各スレッドが自分の番号で trap する（hwt 下位のモデル識別）。
    assert_eq!(c.step(&mut sys), Ok(Some(0)));
    assert_eq!(c.step(&mut sys), Ok(Some(1)));
    assert_eq!(sys.traps, vec![(0, 7), (1, 9)]);
    // 全スレッド終了 → 最後の終了コードの Exit。
    assert_eq!(c.step(&mut sys), Err(Outcome::Exit(9)));
}

/// 待ち（Blocked）を報告するハンドラ。on_block で他スレッドへの
/// 切替えを許す。
struct Blocker;

impl TrapHandler for Blocker {
    fn handle_trap(&mut self, _env: &mut BareEnv, _code: u32) -> TrapOutcome {
        TrapOutcome::Blocked
    }

    fn on_block(&mut self, _env: &mut BareEnv) -> bool {
        true
    }
}

#[test]
fn blocked_thread_waits_until_wake() {
    // t0 の trap0 が Blocked を返すと t0 は待ちに置かれ、
    // wake で復帰するまで t1 だけが発行する。
    let mut c = core(2);
    put(&mut c, BASE, &[trap0(0), addi(1, 1, 1)]);
    let w = addi(2, 2, 1);
    put(&mut c, BASE + 0x40, &[w; 4]);
    c.with_thread(0, |env| env.pc = BASE);
    c.with_thread(1, |env| env.pc = BASE + 0x40);
    let mut sys = Blocker;
    assert_eq!(c.step(&mut sys), Ok(Some(0))); // trap → 待ちへ
    assert_eq!(c.step(&mut sys), Ok(Some(1)));
    assert_eq!(c.step(&mut sys), Ok(Some(1)));
    c.wake(0);
    // 復帰は次のパケット（trap 済みの pc は先へ進んでいる）。
    assert_eq!(c.step(&mut sys), Ok(Some(0)));
    c.with_thread(0, |env| assert_eq!(env.pc, BASE + 8));
    assert_eq!(c.with_thread(0, |env| sem::r_get(&env.backend, 1)), 1);
}
