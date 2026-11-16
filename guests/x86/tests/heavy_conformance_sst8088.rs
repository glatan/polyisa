// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! sst-8088（SingleStepTests 8088、台帳 TEST-SINGLESTEP-8088）の MOO v2 形式を
//! `run_m16` で 1 命令ずつ実行し、最終の CPU 状態とメモリを比較する
//! （層5・conformance。ロードマップ S13-1）。
//!
//! データはリポジトリに含めない（`.testdata/sst-8088`）。プリフェッチ
//! キューとバスサイクルは比較しない（サイクル一致は S13-4）。
//!
//! MOO v2 の形式:
//!   ヘッダ: 'MOO ' + u32 + u32 + u32(テスト数) + cpu(4B)
//!   各テスト: 'TEST' + u32 len + {NAME, BYTS, INIT, FINA, CYCL, HASH}
//!   NAME: u32 名長 + 名。BYTS/QUEU/RAM: u32 個数 + 配列。
//!   REGS: u16 ビットマスク + 立っているビット分の u16 値。
//!   RAM の要素: (u32 番地, u8 値)。残りのメモリは 0 で埋める。
//!
//! レジスタの順序（ビットマスクの添字）: ax,bx,cx,dx,cs,ss,ds,es,
//! sp,bp,si,di,ip,flags の 14 本。

use polyisa_cli::run_x86::{self, Outcome, TrapHandler, TrapOutcome};
use polyisa_engine::bare::BareEnv;
use polyisa_guest_x86::CpuState;
use polyisa_guest_x86::sem::{self, Gpr};
use polyisa_mem::{Access, Perms, VirtAddr};
use polyisa_sem::Backend as _;
use std::path::PathBuf;

const REG_NAMES: [&str; 14] = [
    "ax", "bx", "cx", "dx", "cs", "ss", "ds", "es", "sp", "bp", "si", "di", "ip", "flags",
];

/// まだ対応しないオペコード（ファイル名の拡張子なし）。
/// 差分は既知なので個数を数えずに済ませる。
const SKIP: &[&str] = &[];

#[derive(Default)]
struct Sst {
    name: String,
    regs: [u16; 14],
    ram: Vec<(u32, u8)>,
    fina_mask: u16,
    fina_regs: [u16; 14],
    fina_ram: Vec<(u32, u8)>,
    /// BYTS チャンクの命令バイト列。
    byts: Vec<u8>,
    /// CYCL の IOR 記録から取ったポート読み値（ポート番号, バイト）。
    port_reads: Vec<(u16, u8)>,
    /// CYCL の IOW 記録から取った期待されるポート書き込み。
    port_writes: Vec<(u16, u8)>,
}

struct Rd<'a> {
    d: &'a [u8],
    p: usize,
}

impl<'a> Rd<'a> {
    fn new(d: &'a [u8]) -> Self {
        Self { d, p: 0 }
    }
    fn u8(&mut self) -> u8 {
        let v = self.d[self.p];
        self.p += 1;
        v
    }
    fn u16(&mut self) -> u16 {
        let v = u16::from_le_bytes(self.d[self.p..self.p + 2].try_into().unwrap());
        self.p += 2;
        v
    }
    fn u32(&mut self) -> u32 {
        let v = u32::from_le_bytes(self.d[self.p..self.p + 4].try_into().unwrap());
        self.p += 4;
        v
    }
    fn tag(&mut self) -> [u8; 4] {
        let t: [u8; 4] = self.d[self.p..self.p + 4].try_into().unwrap();
        self.p += 4;
        t
    }
}

/// 'TEST' チャンク列を `tests` へ読む。戻り値はテスト数。
fn parse(data: &[u8], max: usize, tests: &mut Vec<Sst>) {
    assert_eq!(&data[..4], b"MOO ");
    let mut rd = Rd::new(&data[20..]);
    while rd.p + 8 <= rd.d.len() && tests.len() < max {
        assert_eq!(rd.tag(), *b"TEST");
        let end = rd.p + 4 + rd.u32() as usize;
        let _flags = rd.u32();
        let mut t = Sst::default();
        while rd.p < end {
            let tag = rd.tag();
            let cend = rd.p + 4 + rd.u32() as usize;
            match &tag {
                b"NAME" => {
                    let n = rd.u32() as usize;
                    t.name = String::from_utf8_lossy(&rd.d[rd.p..rd.p + n]).into_owned();
                }
                b"BYTS" => {
                    let n = rd.u32() as usize;
                    t.byts = rd.d[rd.p..rd.p + n].to_vec();
                }
                b"INIT" | b"FINA" => {
                    let fina = &tag == b"FINA";
                    while rd.p < cend {
                        let stag = rd.tag();
                        let send = rd.p + 4 + rd.u32() as usize;
                        match &stag {
                            b"REGS" => {
                                let mask = rd.u16();
                                for i in 0..14 {
                                    if mask >> i & 1 != 0 {
                                        let v = rd.u16();
                                        if fina {
                                            t.fina_mask |= 1 << i;
                                            t.fina_regs[i] = v;
                                        } else {
                                            t.regs[i] = v;
                                        }
                                    }
                                }
                            }
                            b"RAM " => {
                                let n = rd.u32() as usize;
                                for _ in 0..n {
                                    let a = rd.u32();
                                    let v = rd.u8();
                                    if fina {
                                        t.fina_ram.push((a, v));
                                    } else {
                                        t.ram.push((a, v));
                                    }
                                }
                            }
                            _ => {}
                        }
                        rd.p = send;
                    }
                }
                b"CYCL" => {
                    // エントリは 15 バイト。bus_status は [11]、
                    // io_status は [7]、data_bus は [9:11]、addr は [1:5]。
                    // IOR/IOW の T1 でポート番号を掴み、T3（io の R/W
                    // ビットが立つ PASV）で data_bus の下位バイトを読む。
                    let n = rd.u32() as usize;
                    let mut pin: Option<u16> = None;
                    let mut pout: Option<u16> = None;
                    for _ in 0..n {
                        let e = &rd.d[rd.p..rd.p + 15];
                        let addr = u32::from_le_bytes(e[1..5].try_into().unwrap());
                        let data = e[9];
                        let bus = e[11];
                        let ts = e[12];
                        if ts == 1 && bus == 1 {
                            pin = Some(addr as u16);
                        }
                        if ts == 1 && bus == 2 {
                            pout = Some(addr as u16);
                        }
                        if bus != 1 && bus != 2 {
                            if let Some(p) = pin.take() {
                                t.port_reads.push((p, data));
                            }
                            if let Some(p) = pout.take() {
                                t.port_writes.push((p, data));
                            }
                        }
                        rd.p += 15;
                    }
                }
                _ => {}
            }
            rd.p = cend;
        }
        rd.p = end;
        tests.push(t);
    }
}

fn get(env: &mut BareEnv, i: usize) -> u32 {
    match i {
        0 => env.backend.get(Gpr(0).state()),
        1 => env.backend.get(Gpr(3).state()),
        2 => env.backend.get(Gpr(1).state()),
        3 => env.backend.get(Gpr(2).state()),
        4 => u32::from(env.backend.get(sem::sreg_ref(1))),
        5 => u32::from(env.backend.get(sem::sreg_ref(2))),
        6 => u32::from(env.backend.get(sem::sreg_ref(3))),
        7 => u32::from(env.backend.get(sem::sreg_ref(0))),
        8 => env.backend.get(Gpr(4).state()),
        9 => env.backend.get(Gpr(5).state()),
        10 => env.backend.get(Gpr(6).state()),
        11 => env.backend.get(Gpr(7).state()),
        12 => env.backend.get(sem::eip_ref()) & 0xFFFF,
        _ => env.backend.get(sem::eflags_ref()) & 0xFFFF,
    }
}

fn set(env: &mut BareEnv, i: usize, v: u16) {
    let v32 = u32::from(v);
    match i {
        0 => env.backend.set(Gpr(0).state(), v32),
        1 => env.backend.set(Gpr(3).state(), v32),
        2 => env.backend.set(Gpr(1).state(), v32),
        3 => env.backend.set(Gpr(2).state(), v32),
        4 => env.backend.set(sem::sreg_ref(1), v),
        5 => env.backend.set(sem::sreg_ref(2), v),
        6 => env.backend.set(sem::sreg_ref(3), v),
        7 => env.backend.set(sem::sreg_ref(0), v),
        8 => env.backend.set(Gpr(4).state(), v32),
        9 => env.backend.set(Gpr(5).state(), v32),
        10 => env.backend.set(Gpr(6).state(), v32),
        11 => env.backend.set(Gpr(7).state(), v32),
        12 => env.backend.set(sem::eip_ref(), v32),
        _ => env.backend.set(sem::eflags_ref(), v32),
    }
}

struct NoSys;
impl TrapHandler for NoSys {
    fn handle_trap(&mut self, _env: &mut BareEnv, _code: u32) -> TrapOutcome {
        TrapOutcome::Unimplemented
    }
}

/// 1 テストを実行して差分を返す（空なら一致）。
fn run_one(env: &mut BareEnv, t: &Sst) -> Vec<String> {
    if std::env::var("POLYISA_SST_DUMP").is_ok() {
        eprintln!(
            "dump [{}] init={:04x?} fina_mask={:04x} fina={:04x?} ram={:x?} fram={:x?}",
            t.name, t.regs, t.fina_mask, t.fina_regs, t.ram, t.fina_ram
        );
    }
    for &(a, v) in &t.ram {
        env.backend.mem.write(VirtAddr(u64::from(a)), &[v]).unwrap();
    }
    for &(p, v) in &t.port_reads {
        env.backend.ports[usize::from(p)] = v;
    }
    for (i, &v) in t.regs.iter().enumerate() {
        set(env, i, v);
    }
    let mut sys = NoSys;
    let mut out = run_x86::run_m16(env, u32::from(t.regs[12]), &mut sys, 1);
    // REP 接頭辞付き文字列命令は 1 反復ごとに IP が命令先頭へ戻る。
    // 建築的な完了（CX=0 や ZF 条件）まで 1 ステップずつ継続する。
    // REP のない命令で IP が命令先頭に戻る場合（#DE の IVT 着地点が
    // 命令アドレスと一致する等）は継続しない。
    let has_rep = t
        .byts
        .iter()
        .take_while(|&&b| matches!(b, 0x26 | 0x2E | 0x36 | 0x3E | 0xF0 | 0xF2 | 0xF3))
        .any(|&b| b == 0xF2 || b == 0xF3);
    let mut steps = 1u32;
    while has_rep
        && matches!(out, Outcome::StepLimit { .. })
        && get(env, 12) == u32::from(t.regs[12])
        && steps < 0x1_0002
    {
        out = run_x86::run_m16(env, u32::from(t.regs[12]), &mut sys, 1);
        steps += 1;
    }
    let mut diffs = Vec::new();
    if !matches!(out, Outcome::StepLimit { .. }) {
        diffs.push(format!("outcome {out:?}"));
    }
    for (i, name) in REG_NAMES.iter().enumerate() {
        let exp = if t.fina_mask >> i & 1 != 0 {
            t.fina_regs[i]
        } else {
            t.regs[i]
        };
        let got = get(env, i) as u16;
        if got != exp {
            diffs.push(format!("{name}: exp {exp:04x} got {got:04x}"));
        }
    }
    for &(a, v) in &t.fina_ram {
        let mut b = [0u8; 1];
        env.backend
            .mem
            .read(VirtAddr(u64::from(a)), &mut b, Access::DATA_LE)
            .unwrap();
        if b[0] != v {
            diffs.push(format!("mem {a:05x}: exp {v:02x} got {:02x}", b[0]));
        }
    }
    for &(p, v) in &t.port_writes {
        let got = env.backend.ports[usize::from(p)];
        if got != v {
            diffs.push(format!("port {p:04x}: exp {v:02x} got {got:02x}"));
        }
    }
    diffs
}

fn testdata() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.join(".testdata").join("sst-8088")
}

#[test]
fn sst8088_conformance() {
    let dir = testdata();
    if !dir.is_dir() {
        eprintln!("sst-8088 のデータがない。スキップ");
        return;
    }
    // 1 ファイルあたりの実行数。0 は全件。
    let max: usize = std::env::var("POLYISA_SST_MAX")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);
    let max = if max == 0 { usize::MAX } else { max };
    let only: Option<String> = std::env::var("POLYISA_SST_FILE").ok();

    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0), 256, rwx).unwrap();

    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| {
            let n = e.unwrap().file_name().into_string().unwrap();
            n.strip_suffix(".MOO").map(str::to_owned)
        })
        .collect();
    names.sort();

    let mut total = 0usize;
    let mut failed_files = Vec::new();
    let mut skipped = 0usize;
    for name in &names {
        if let Some(f) = &only
            && name != f
        {
            continue;
        }
        if SKIP.contains(&name.as_str()) {
            skipped += 1;
            continue;
        }
        let data = std::fs::read(dir.join(format!("{name}.MOO"))).unwrap();
        let mut tests = Vec::new();
        parse(&data, max, &mut tests);
        let mut diffs = 0usize;
        let mut touched: Vec<u32> = Vec::new();
        for (i, t) in tests.iter().enumerate() {
            let d = run_one(&mut env, t);
            total += 1;
            if !d.is_empty() {
                diffs += 1;
                if diffs <= 5 {
                    eprintln!("{name}#{i} [{}]: {}", t.name, d.join(", "));
                }
            }
            // このテストが触れた番地を 0 に戻す（次のテストの初期化）。
            for &(a, _) in t.ram.iter().chain(t.fina_ram.iter()) {
                touched.push(a);
            }
            if touched.len() > 4096 || i + 1 == tests.len() {
                for &a in &touched {
                    env.backend.mem.write(VirtAddr(u64::from(a)), &[0]).unwrap();
                }
                touched.clear();
            }
        }
        if diffs > 0 {
            failed_files.push((name.clone(), diffs, tests.len()));
        }
    }
    eprintln!("total {total} tests, skipped files {skipped}");
    for (n, d, c) in &failed_files {
        eprintln!("  {n}: {d}/{c} diffs");
    }
    assert!(
        failed_files.is_empty(),
        "{} files with diffs",
        failed_files.len()
    );
}
