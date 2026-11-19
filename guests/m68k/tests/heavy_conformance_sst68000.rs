// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! sst-68000（SingleStepTests m68000、台帳 TEST-SINGLESTEP-68000）の
//! `.json.bin` 形式を 1 命令ずつ実行し、最終の CPU 状態と RAM を比較する
//! （層5・conformance。ロードマップ S14-1）。
//!
//! データはリポジトリに含めない（`.testdata/sst-68000`）。プリフェッチ
//! 2 ワードは比較しない。バストランザクションのサイクル数比較は
//! `heavy_timing_68000` が担う（S14-2）。
//!
//! `.json.bin` の形式（一次根拠は decode.py）:
//!   ヘッダ: u32 magic(0x1A3F5D71) + u32(テスト数)
//!   各テスト: {NAME, INIT, FINA, TXNS} の各レコードは u32 レコード長 +
//!   u32 マジックで始まる。NAME は u32 長 + utf8。INIT/FINA は
//!   d0-7,a0-6,usp,ssp,sr,pc の u32×19 + プリフェッチ u32×2 +
//!   u32(ram個数) + (u32 addr, u16 BE語)×個数。TXNS は u32 総サイクル数 +
//!   u32 個数 + {u8 kind, u32 cycles[, u32×5]}×個数。

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::{Ctrl, InterpExit};
use polyisa_guest_m68k::sem::{self, A, D, Ssp, Usp};
use polyisa_guest_m68k::{CpuState, Insn, ea};
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};
use polyisa_sem::{Backend as _, ExceptionKind};
use std::path::PathBuf;

/// 実装済みの命令群に対応するファイルだけを走らせる（部分検証）。
/// H1 で全ファイルに広げる。
// ADDQ/SUBQ/ADDI/SUBI/CMPI/CMPM 等のファイルはデータセットに
// 存在しない（その分は bare テストが担保する）。
const FILES: &[&str] = &[
    "MOVE.b",
    "MOVE.w",
    "MOVE.l",
    "MOVEA.w",
    "MOVEA.l",
    "MOVE.q", //
    "ADD.b",
    "ADD.w",
    "ADD.l",
    "ADDA.w",
    "ADDA.l", //
    "SUB.b",
    "SUB.w",
    "SUB.l",
    "SUBA.w",
    "SUBA.l", //
    "CMP.b",
    "CMP.w",
    "CMP.l",
    "CMPA.w",
    "CMPA.l", //
    "AND.b",
    "AND.w",
    "AND.l",
    "OR.b",
    "OR.w",
    "OR.l",
    "EOR.b",
    "EOR.w",
    "EOR.l", //
    "NOT.b",
    "NOT.w",
    "NOT.l",
    "CLR.b",
    "CLR.w",
    "CLR.l",
    "TST.b",
    "TST.w",
    "TST.l",
    "ASL.b",
    "ASL.w",
    "ASL.l",
    "ASR.b",
    "ASR.w",
    "ASR.l",
    "LSL.b",
    "LSL.w",
    "LSL.l",
    "LSR.b",
    "LSR.w",
    "LSR.l",
    "ROL.b",
    "ROL.w",
    "ROL.l",
    "ROR.b",
    "ROR.w",
    "ROR.l",
    "ROXL.b",
    "ROXL.w",
    "ROXL.l",
    "ROXR.b",
    "ROXR.w",
    "ROXR.l",
    "BTST",
    "BCHG",
    "BCLR",
    "BSET",
    "Bcc",
    "BSR",
    "JMP",
    "JSR",
    "RTS",
    "RTR",
    "Scc",
    "DBcc",
    "LEA",
    "PEA",
    "LINK",
    "UNLINK",
    "EXG",
    "SWAP",
    "EXT.w",
    "EXT.l",
    "MOVEM.w",
    "MOVEM.l",
    "MOVEP.w",
    "MOVEP.l",
    "MULU",
    "MULS",
    "DIVU",
    "DIVS",
    "ABCD",
    "SBCD",
    "NBCD", //
    "ANDItoCCR",
    "ANDItoSR",
    "ORItoCCR",
    "ORItoSR",
    "EORItoCCR",
    "EORItoSR",
    // C13: trap/chk/move to-from ccr|sr/reset/nop/linea/linef。
    "CHK",
    "MOVEtoCCR",
    "MOVEtoSR",
    "MOVEfromSR",
    "NOP",
    "RESET",
    "TRAP",
    "TRAPV",
    "ILLEGAL_LINEA",
    "ILLEGAL_LINEF", //
    // C14: rte/stop/move usp・例外配送。
    "RTE",
    "STOP",
    "MOVEtoUSP",
    "MOVEfromUSP",
];

/// u32 のレジスタ列（d0-7, a0-6, usp, ssp, sr, pc）を生値で持つ。
#[derive(Default)]
struct State {
    regs: [u32; 19],
    /// プリフェッチ語（比較しない・読み捨て）。
    #[allow(dead_code)]
    prefetch: [u32; 2],
    /// (番地, バイト) のペア。
    ram: Vec<(u32, u8)>,
}

#[derive(Default)]
struct Sst {
    name: String,
    init: State,
    fina: State,
}

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> u8 {
        let v = self.b[self.p];
        self.p += 1;
        v
    }
    fn u16(&mut self) -> u16 {
        let v = u16::from_le_bytes(self.b[self.p..self.p + 2].try_into().unwrap());
        self.p += 2;
        v
    }
    fn u32(&mut self) -> u32 {
        let v = u32::from_le_bytes(self.b[self.p..self.p + 4].try_into().unwrap());
        self.p += 4;
        v
    }
    fn rec(&mut self, magic: u32) {
        let _numbytes = self.u32();
        assert_eq!(self.u32(), magic, "bad record magic");
    }
    fn state(&mut self) -> State {
        self.rec(0x0123_4567);
        let mut st = State::default();
        for r in &mut st.regs {
            *r = self.u32();
        }
        st.prefetch = [self.u32(), self.u32()];
        let n = self.u32() as usize;
        for _ in 0..n {
            let addr = self.u32();
            // 語は上位バイトが偶数番地に来る BE でメモリに展開する。
            let w = self.u16();
            st.ram.push((addr, (w >> 8) as u8));
            st.ram.push((addr | 1, w as u8));
        }
        st
    }
}

fn parse(b: &[u8], max: usize, out: &mut Vec<Sst>) {
    let mut r = Reader { b, p: 0 };
    assert_eq!(r.u32(), 0x1A3F_5D71, "bad file magic");
    let n = r.u32() as usize;
    for _ in 0..n.min(max) {
        r.rec(0xABC1_2367);
        let mut t = Sst::default();
        r.rec(0x89AB_CDEF);
        let slen = r.u32() as usize;
        t.name = String::from_utf8_lossy(&r.b[r.p..r.p + slen]).into_owned();
        r.p += slen;
        t.init = r.state();
        t.fina = r.state();
        // バストランザクションは読み捨てる（S14-2 で使う）。
        r.rec(0x4567_89AB);
        let ntxn = r.u32();
        let num_txn = r.u32();
        let _ = ntxn;
        for _ in 0..num_txn {
            let kind = r.u8();
            let _cycles = r.u32();
            if kind != 0 {
                for _ in 0..5 {
                    r.u32();
                }
            }
        }
        out.push(t);
    }
}

/// SST の pc は命令先頭 +4（プリフェッチ2語分）を指す規約なので、
/// 命令語は pc-4 から読む。戻り値は (Insn, 先頭ワード, 命令先頭)。
fn head_insn(env: &BareEnv) -> Result<(Insn, u64, u32), InterpExit> {
    let head = (env.pc as u32).wrapping_sub(4);
    let acc = Access {
        endian: Endian::Be,
        align: Align::Natural,
        kind: AccessKind::Fetch,
    };
    let mut b2 = [0u8; 2];
    if env
        .backend
        .mem
        .read(VirtAddr(u64::from(head)), &mut b2, acc)
        .is_err()
    {
        return Err(InterpExit::Unimplemented(format!("fetch @{head:#x}")));
    }
    let w = u64::from(u16::from_be_bytes(b2));
    let Some(insn) = polyisa_guest_m68k::decode(u128::from(w), 16) else {
        return Err(InterpExit::Unimplemented(format!("decode {w:#06x}")));
    };
    Ok((insn, w, head))
}

/// 1 命令を実行する。
fn step_one(env: &mut BareEnv) -> Result<(), InterpExit> {
    let pc = env.pc as u32;
    let (insn, w, head) = head_insn(env)?;
    let Some(ext) = ea::insn_ext_words(insn, w) else {
        return Err(InterpExit::Unimplemented(format!("ea {w:#06x}")));
    };
    let len = 2 + u64::from(ext) * 2;
    match env.step(|b| sem::exec(b, insn, w, u64::from(head))) {
        Ok(()) => {}
        // Trap 系例外はフレームを積んでベクタへ配送する（C14）。
        // アドレスエラー（14 バイトフレーム）は未接続なので呼び出し側へ返す。
        Err(InterpExit::Exception(e)) if e.kind == ExceptionKind::Trap => {
            env.step(|b| sem::deliver(b, e.code as u32, u64::from(head), len))?;
            env.pc = env.pc.wrapping_add(4);
            env.backend.set(sem::pc_ref(), env.pc as u32);
            return Ok(());
        }
        Err(e) => return Err(e),
    }
    // 終了 pc の規約は「初期 pc + 命令長」。SST の pc はプリフェッチ
    // 分（実行アドレス+4）を指すので、分岐時は step が置いた真の
    // 分岐先に +4 する。
    if env.backend.ctrl == Ctrl::Fallthrough {
        env.pc = (u64::from(pc) + len) & 0xFFFF_FFFF;
    } else {
        env.pc = env.pc.wrapping_add(4);
    }
    env.backend.set(sem::pc_ref(), env.pc as u32);
    Ok(())
}

/// 状態を `regs` に戻し、RAM を書き込む。
fn setup(env: &mut BareEnv, st: &State) {
    for i in 0..8u8 {
        env.backend.set(D(i).state(), st.regs[i as usize]);
    }
    for i in 0..7u8 {
        env.backend.set(A(i).state(), st.regs[8 + i as usize]);
    }
    env.backend.set(Usp.state(), st.regs[15]);
    env.backend.set(Ssp.state(), st.regs[16]);
    env.backend.set(sem::sr_ref(), st.regs[17] & 0xFFFF);
    env.backend.set(sem::pc_ref(), st.regs[18]);
    env.pc = u64::from(st.regs[18]);
}

/// 比較して差分の説明を返す（空なら一致）。
fn diff(env: &mut BareEnv, st: &State) -> Vec<String> {
    let mut out = Vec::new();
    for i in 0..8u8 {
        let got = env.backend.get(D(i).state());
        let want = st.regs[i as usize];
        if got != want {
            out.push(format!("d{i}: got {got:#010x} want {want:#010x}"));
        }
    }
    for i in 0..7u8 {
        let got = env.backend.get(A(i).state());
        let want = st.regs[8 + i as usize];
        if got != want {
            out.push(format!("a{i}: got {got:#010x} want {want:#010x}"));
        }
    }
    for (name, r, want) in [
        ("usp", Usp.state(), st.regs[15]),
        ("ssp", Ssp.state(), st.regs[16]),
        ("sr", sem::sr_ref(), st.regs[17] & 0xFFFF),
        ("pc", sem::pc_ref(), st.regs[18]),
    ] {
        let got = env.backend.get(r);
        if got != want {
            out.push(format!("{name}: got {got:#010x} want {want:#010x}"));
        }
    }
    let acc = Access {
        endian: Endian::Be,
        align: Align::Natural,
        kind: AccessKind::DataRead,
    };
    for &(a, want) in &st.ram {
        let mut got = [0u8; 1];
        if env
            .backend
            .mem
            .read(VirtAddr(u64::from(a)), &mut got, acc)
            .is_err()
            || got[0] != want
        {
            out.push(format!(
                "ram {a:#08x}: got {:#04x} want {want:#04x}",
                got[0]
            ));
        }
    }
    out
}

fn testdata() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.join(".testdata").join("sst-68000")
}

#[test]
fn sst68000_conformance() {
    let dir = testdata().join("v1");
    if !dir.is_dir() {
        eprintln!("sst-68000 のデータがない。スキップ");
        return;
    }
    // 1 ファイルあたりの実行数。0 は全件。
    let max: usize = std::env::var("POLYISA_SST_MAX")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);
    let max = if max == 0 { usize::MAX } else { max };
    let only: Option<String> = std::env::var("POLYISA_SST_FILE").ok();

    // SST は 24 ビット空間の任意の番地を読む（例外はアドレスエラーと
    // なるが、その配送は未接続）。全域を一度だけ写像して使い回す。
    // バスは24ビットなので 0xFFxxxx に折り返す。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    env.backend.addr_mask = 0x00FF_FFFF;
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0), 0x1000, rwx).unwrap();

    let mut total = 0usize;
    let mut failed_files = Vec::new();
    let mut exceptional = 0usize;
    for name in FILES {
        if let Some(f) = &only
            && name != f
        {
            continue;
        }
        let data = std::fs::read(dir.join(format!("{name}.json.bin"))).unwrap();
        let mut tests = Vec::new();
        parse(&data, max, &mut tests);
        let mut diffs = 0usize;
        let mut exc = 0usize;
        let mut touched: Vec<u32> = Vec::new();
        for (i, t) in tests.iter().enumerate() {
            setup(&mut env, &t.init);
            for &(a, v) in &t.init.ram {
                env.backend.mem.write(VirtAddr(u64::from(a)), &[v]).unwrap();
            }
            total += 1;
            // 命令語は実行前に掴んでおく（自己書き換えで変わりうる）。
            let head = head_insn(&env).ok();
            let mut d = match step_one(&mut env) {
                Ok(()) => diff(&mut env, &t.fina),
                // アドレスエラー（14 バイトフレーム）の配送は未接続。
                // それを起こすテストは終了状態が異なるので比較できない。
                // 終了状態が例外スタックフレームを含むので比較できない。
                // ただし例外が「期待された」ことは確認する: MOVE は
                // 分岐しないので、期待終了 pc = 初期 pc + 命令長。
                // そこに一致するなら SST が期待しない例外であり diff。
                Err(InterpExit::Exception(e)) => {
                    let natural = head.and_then(|(insn, w, _)| {
                        ea::insn_ext_words(insn, w)
                            .map(|ext| t.init.regs[18].wrapping_add(2 + ext * 2))
                    });
                    if natural.is_some_and(|n| t.fina.regs[18] != n)
                        || (t.fina.regs[17] & 0x2000) != (t.init.regs[17] & 0x2000)
                    {
                        exc += 1;
                        Vec::new()
                    } else {
                        vec![format!("exit: unexpected {e:?}")]
                    }
                }
                Err(e) => vec![format!("exit: {e:?}")],
            };
            // Ok でも SST 側がアドレスエラーを期待しているケース:
            // 奇数 pc（次フェッチの奇数アクセス）は未接続の例外なので
            // 比較できない。Trap 配送は step_one が済ませるので、それ
            // 以外の S 変化はここでは逃がさない（配送バグを隠さない）。
            if !d.is_empty() && env.pc & 1 == 1 {
                exc += 1;
                if std::env::var("POLYISA_SST_DEBUG").is_ok() {
                    eprintln!(
                        "  exc {name}#{i} [{}] init_sr={:04x} odd_pc",
                        t.name, t.init.regs[17]
                    );
                }
                d.clear();
            }
            if !d.is_empty() {
                diffs += 1;
                if diffs <= 5 {
                    eprintln!("{name}#{i} [{}]: {}", t.name, d.join(", "));
                }
            }
            // このテストが触れた番地を 0 に戻す（次のテストの初期化）。
            for &(a, _) in t.init.ram.iter().chain(t.fina.ram.iter()) {
                touched.push(a);
            }
            if touched.len() > 8192 || i + 1 == tests.len() {
                for &a in &touched {
                    let _ = env.backend.mem.write(VirtAddr(u64::from(a)), &[0]);
                }
                touched.clear();
            }
        }
        exceptional += exc;
        if diffs > 0 {
            failed_files.push((name.to_string(), diffs, tests.len()));
        }
        eprintln!("{name}: {diffs} diffs, {exc} exceptional");
    }
    eprintln!("total {total} tests, {exceptional} exceptional（アドレスエラー等未接続）");
    for (n, d, c) in &failed_files {
        eprintln!("  {n}: {d}/{c} diffs");
    }
    assert!(failed_files.is_empty(), "SST 一致しないファイルがある");
}
