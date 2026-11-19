// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! sst-68000（SingleStepTests m68000、台帳 TEST-SINGLESTEP-68000）の
//! 各テストケースの総サイクル数と `timing::insn_cycles` の予測値を
//! 比較する（層: timing、ロードマップ S14-2）。
//!
//! バストランザクションを持つケースで、例外経路（アドレスエラー・
//! ベクタ空間アクセス）を含むものは通常実行の時間モデルの対象外
//! なので除外する。DIVU/DIVS は値依存で未較正のため対象外。
//!
//! `.json.bin` の形式は `heavy_conformance_sst68000.rs` と同じ。

use polyisa_guest_m68k::timing::{self, Dbcc, Rt};
use polyisa_guest_m68k::{Insn, ea};
use std::collections::HashMap;
use std::path::PathBuf;

/// `heavy_conformance_sst68000` の対象に ADDX/SUBX/NEG/NEGX を加え、
/// 未較正の DIVU/DIVS と未宣言の TAS を除く。
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
    "ADDA.l",
    "ADDX.b",
    "ADDX.w",
    "ADDX.l", //
    "SUB.b",
    "SUB.w",
    "SUB.l",
    "SUBA.w",
    "SUBA.l",
    "SUBX.b",
    "SUBX.w",
    "SUBX.l", //
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
    "NEG.b",
    "NEG.w",
    "NEG.l",
    "NEGX.b",
    "NEGX.w",
    "NEGX.l",
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
    "ABCD",
    "SBCD",
    "NBCD", //
    "ANDItoCCR",
    "ANDItoSR",
    "ORItoCCR",
    "ORItoSR",
    "EORItoCCR",
    "EORItoSR", //
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
    "RTE",
    "STOP",
    "MOVEtoUSP",
    "MOVEfromUSP",
];

/// データセットにあるがモデルの対象外（比較しない）。新しいファイルが
/// 増えたら FILES かここへ振り分ける。
/// - DIVU/DIVS: 値依存で未較正（insn_cycles が None）。
/// - TAS: Insn::Tas が spec 未宣言で decode できない。
const EXCLUDED: &[&str] = &["DIVU", "DIVS", "TAS"];

/// d0-7, a0-6, usp, ssp, sr, pc。
#[derive(Default)]
struct State {
    regs: [u32; 19],
    /// プリフェッチ語（比較しない・読み捨て）。
    #[allow(dead_code)]
    prefetch: [u32; 2],
    ram: Vec<(u32, u8)>,
}

#[derive(Default)]
struct Sst {
    name: String,
    init: State,
    /// TXN ブロックの総サイクル数。
    cycles: u32,
    /// 例外経路を含まない（アドレスエラー・ベクタ空間アクセスなし）。
    clean: bool,
}

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

impl Reader<'_> {
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
        let _fina = r.state();
        // 総サイクル数と例外経路の有無だけを拾う。
        r.rec(0x4567_89AB);
        t.cycles = r.u32();
        let num_txn = r.u32();
        let mut clean = true;
        for _ in 0..num_txn {
            // kind: 0=n(idle), 1=w, 2=r, 3=t(TAS rmw),
            // 4=re, 5=we（addr err、decode.py の列挙）。
            let kind = r.u8();
            let _cycles = r.u32();
            if kind != 0 {
                let _fc = r.u32();
                let ab = r.u32();
                let _db = r.u32();
                let _uds = r.u32();
                let _lds = r.u32();
                // kind 4/5 はアドレスエラー、0x400 未満はベクタ空間。
                if kind >= 4 || ab < 0x400 {
                    clean = false;
                }
            }
        }
        t.clean = clean;
        out.push(t);
    }
}

fn w16(ram: &HashMap<u32, u8>, a: u32) -> u32 {
    let a = a & 0xFF_FFFF;
    let hi = ram.get(&a).copied().unwrap_or(0);
    let lo = ram
        .get(&(a.wrapping_add(1) & 0xFF_FFFF))
        .copied()
        .unwrap_or(0);
    (u32::from(hi) << 8) | u32::from(lo)
}

fn cc_eval(cc: u32, sr: u32) -> bool {
    let n = sr & 8 != 0;
    let z = sr & 4 != 0;
    let v = sr & 2 != 0;
    let c = sr & 1 != 0;
    match cc {
        0 => true,
        1 => false,
        2 => !c && !z,
        3 => c || z,
        4 => !c,
        5 => c,
        6 => !z,
        7 => z,
        8 => !v,
        9 => v,
        10 => !n,
        11 => n,
        12 => n == v,
        13 => n != v,
        14 => n == v && !z,
        _ => n != v || z,
    }
}

fn sext8(v: u32) -> u32 {
    (v as u8) as i8 as i32 as u32
}
fn sext16(v: u32) -> u32 {
    (v as u16) as i16 as i32 as u32
}

/// An の値。A7 は S フラグで USP/SSP を切り替える。
fn areg(st: &State, r: u8) -> u32 {
    if r == 7 {
        st.regs[if st.regs[17] & 0x2000 != 0 { 16 } else { 15 }]
    } else {
        st.regs[8 + usize::from(r)]
    }
}

/// 68000 形式の index ワード（`ext`）を評価する。戻り値は
/// （ディスプレイスメントを含む）オフセット。
fn idx_offset(ext: u16, st: &State) -> u32 {
    let i = usize::from(ext >> 12);
    let x = if i < 8 {
        st.regs[i]
    } else {
        areg(st, (i - 8) as u8)
    };
    let x = if ext & 0x0800 != 0 { x } else { sext16(x) };
    sext8(u32::from(ext)).wrapping_add(x)
}

/// `d16(An)` / index / 絶対 / PC 相対 EA の番地を計算する。
/// `pc` は命令先頭 +4（SST の規約）。ワードサイズのオペランドを仮定。
fn ea_addr(
    mode: u8,
    reg: u8,
    st: &State,
    ram: &HashMap<u32, u8>,
    pc: u32,
    ext: u16,
) -> Option<u32> {
    Some(
        match mode {
            2 | 3 => areg(st, reg),
            4 => areg(st, reg).wrapping_sub(2),
            5 => areg(st, reg).wrapping_add(sext16(u32::from(ext))),
            6 => areg(st, reg).wrapping_add(idx_offset(ext, st)),
            7 => match reg {
                0 => sext16(u32::from(ext)),
                1 => (u32::from(ext) << 16) | w16(ram, pc),
                // PC 相対は拡張語の番地が基準。
                2 => pc.wrapping_sub(2).wrapping_add(sext16(u32::from(ext))),
                3 => pc.wrapping_sub(2).wrapping_add(idx_offset(ext, st)),
                _ => return None,
            },
            _ => return None,
        } & 0xFF_FFFF,
    )
}

/// MUL 系のソースオペランド（下位 16 ビット）。
fn mul_src(
    mode: u8,
    reg: u8,
    st: &State,
    ram: &HashMap<u32, u8>,
    pc: u32,
    ext: u16,
) -> Option<u16> {
    Some(match mode {
        0 => (st.regs[usize::from(reg)] & 0xffff) as u16,
        1 => (areg(st, reg) & 0xffff) as u16,
        2..=6 => w16(ram, ea_addr(mode, reg, st, ram, pc, ext)?) as u16,
        7 if reg < 4 => w16(ram, ea_addr(mode, reg, st, ram, pc, ext)?) as u16,
        // 即値は拡張語そのもの。
        7 => ext,
        _ => return None,
    })
}

fn build_rt(insn: Insn, w: u64, ext: u16, st: &State, ram: &HashMap<u32, u8>) -> Rt {
    let cc = ((w >> 8) & 0xF) as u32;
    let sr = st.regs[17];
    let em = ea::ea_mode(w);
    let er = ea::ea_reg(w);
    let pc = st.regs[18];
    let mut rt = Rt::default();
    match insn {
        Insn::Bcc | Insn::Scc => rt.cond = Some(cc_eval(cc, sr)),
        Insn::Trapv => rt.cond = Some(sr & 2 != 0),
        Insn::Dbcc => {
            rt.dbcc = Some(if cc_eval(cc, sr) {
                Dbcc::CondTrue
            } else if st.regs[(w & 7) as usize] & 0xffff == 0 {
                Dbcc::Expired
            } else {
                Dbcc::Branch
            });
        }
        Insn::Chk => rt.cond = Some(true), // clean なケースは不成立でない
        Insn::Asl
        | Insn::Asr
        | Insn::Lsl
        | Insn::Lsr
        | Insn::Rol
        | Insn::Ror
        | Insn::Roxl
        | Insn::Roxr => {
            if w & 0x20 != 0 {
                // レジスタ指定: bits[11:9] の Dn mod 64。
                rt.count = Some(u64::from(st.regs[((w >> 9) & 7) as usize] & 63));
            }
        }
        Insn::Mulu | Insn::Muls => {
            rt.mul_src = mul_src(em, er, st, ram, pc, ext);
        }
        Insn::Bchg | Insn::Bclr | Insn::Bset if em == 0 => {
            rt.bit = Some(st.regs[((w >> 9) & 7) as usize] & 31);
        }
        _ => {}
    }
    rt
}

fn testdata() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.join(".testdata").join("sst-68000")
}

#[test]
fn sst68000_timing() {
    let dir = testdata().join("v1");
    if !dir.is_dir() {
        eprintln!("sst-68000 のデータがない。スキップ");
        return;
    }
    let max: usize = std::env::var("POLYISA_SST_MAX")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);
    let max = if max == 0 { usize::MAX } else { max };
    let only: Option<String> = std::env::var("POLYISA_SST_FILE").ok();

    // FILES ∪ EXCLUDED がデータセット全体を被うことを確認する
    // （新しいファイル・存在しない登録の取りこぼしを検出する）。
    let mut known: std::collections::BTreeSet<String> = FILES
        .iter()
        .chain(EXCLUDED)
        .map(|s| s.to_string())
        .collect();
    let mut unknown = Vec::new();
    for e in std::fs::read_dir(&dir).unwrap() {
        let n = e.unwrap().file_name().into_string().unwrap();
        if let Some(stem) = n.strip_suffix(".json.bin")
            && !known.remove(stem)
        {
            unknown.push(stem.to_owned());
        }
    }
    assert!(
        unknown.is_empty(),
        "未分類の SST ファイルがある: {unknown:?}"
    );
    assert!(known.is_empty(), "データセットに無い登録がある: {known:?}");

    let mut total = 0usize;
    let mut filtered = 0usize;
    let mut uncovered = 0usize;
    let mut bad = 0usize;
    let mut bad_files: Vec<String> = Vec::new();
    let mut all_filtered: Vec<String> = Vec::new();
    for name in FILES {
        if let Some(f) = &only
            && name != f
        {
            continue;
        }
        let data = std::fs::read(dir.join(format!("{name}.json.bin"))).unwrap();
        let mut tests = Vec::new();
        parse(&data, max, &mut tests);
        let mut file_bad = 0usize;
        let mut file_uncov = 0usize;
        let mut file_checked = 0usize;
        for (i, t) in tests.iter().enumerate() {
            total += 1;
            if !t.clean {
                filtered += 1;
                continue;
            }
            file_checked += 1;
            let ram: HashMap<u32, u8> = t.init.ram.iter().copied().collect();
            let pc = t.init.regs[18];
            // SST の pc は命令先頭 +4 を指す規約（conformance と同じ）。
            let w = u64::from(w16(&ram, pc.wrapping_sub(4)) as u16);
            let ext = w16(&ram, pc.wrapping_sub(2)) as u16;
            let Some(insn) = polyisa_guest_m68k::decode(u128::from(w), 16) else {
                file_uncov += 1;
                uncovered += 1;
                if file_uncov <= 3 {
                    eprintln!("{name}#{i} [{}] decode failed: w={w:#06x}", t.name);
                }
                continue;
            };
            let rt = build_rt(insn, w, ext, &t.init, &ram);
            let Some(got) = timing::insn_cycles(insn, w, ext, &rt) else {
                file_uncov += 1;
                uncovered += 1;
                if file_uncov <= 3 {
                    eprintln!("{name}#{i} [{}] uncovered: w={w:#06x}", t.name);
                }
                continue;
            };
            if got != u64::from(t.cycles) {
                bad += 1;
                file_bad += 1;
                if file_bad <= 3 {
                    eprintln!(
                        "{name}#{i} [{}] w={w:#06x} ext={ext:#06x}: model {got} vs sst {}",
                        t.name, t.cycles
                    );
                }
            }
        }
        if file_bad > 0 || file_uncov > 0 {
            bad_files.push(format!("{name}: bad={file_bad} uncov={file_uncov}"));
        }
        if file_checked == 0 && !tests.is_empty() {
            all_filtered.push(name.to_string());
        }
    }
    eprintln!("total {total}, filtered {filtered}, uncovered {uncovered}, mismatches {bad}");
    eprintln!("all-filtered（例外経路のみ）: {all_filtered:?}");
    for b in &bad_files {
        eprintln!("  {b}");
    }
    assert_eq!(uncovered, 0, "{uncovered} cases not covered by the model");
    assert_eq!(bad, 0, "{bad} cycle mismatches");
}
