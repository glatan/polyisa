// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! sst-8088（SingleStepTests 8088、台帳 TEST-SINGLESTEP-8088）の
//! CYCL チャンク（バスサイクル列）と、`timing::I8088` モデルの
//! T-state 数を比較する（層: timing、ロードマップ S13-4、E4b）。
//!
//! CYCL は命令のファーストバイト読み取りから次命令のファースト
//! バイト読み取りまでの T-state 列なので、件数がそのまま比較値。
//! `classify_8088` が未対応の命令はスキップして件数を報告する。
//!
//! MOO v2 の形式:
//!   ヘッダ: 'MOO ' + u32 + u32 + u32(テスト数) + cpu(4B)
//!   各テスト: 'TEST' + u32 len + {NAME, BYTS, INIT, FINA, CYCL, HASH}
//!   NAME: u32 名長 + 名。BYTS/QUEU/RAM: u32 個数 + 配列。
//!   REGS: u16 ビットマスク + 立っているビット分の u16 値。
//!   CYCL: u32 個数。
//!
//! レジスタの順序（ビットマスクの添字）: ax,bx,cx,dx,cs,ss,ds,es,
//! sp,bp,si,di,ip,flags の 14 本。

use polyisa_guest_x86::timing::{I8088, classify_8088};
use polyisa_guest_x86::{DEFAULT_FEATS, INSNS, decode_map};
use std::path::PathBuf;

#[derive(Default)]
struct Sst {
    name: String,
    byts: Vec<u8>,
    queu: Option<Vec<u8>>,
    cycl: usize,
    /// ax,bx,cx,dx,cs,ss,ds,es,sp,bp,si,di,ip,flags
    regs: [u16; 14],
}

struct Rd<'a> {
    d: &'a [u8],
    p: usize,
}

impl<'a> Rd<'a> {
    fn u32(&mut self) -> u32 {
        let v = u32::from_le_bytes(self.d[self.p..self.p + 4].try_into().unwrap());
        self.p += 4;
        v
    }
    fn u16(&mut self) -> u16 {
        let v = u16::from_le_bytes(self.d[self.p..self.p + 2].try_into().unwrap());
        self.p += 2;
        v
    }
    fn tag(&mut self) -> [u8; 4] {
        let t: [u8; 4] = self.d[self.p..self.p + 4].try_into().unwrap();
        self.p += 4;
        t
    }
}

fn parse(data: &[u8], max: usize, tests: &mut Vec<Sst>) {
    assert_eq!(&data[..4], b"MOO ");
    let mut rd = Rd {
        d: &data[20..],
        p: 0,
    };
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
                b"INIT" => {
                    while rd.p < cend {
                        let stag = rd.tag();
                        let send = rd.p + 4 + rd.u32() as usize;
                        match &stag {
                            b"REGS" => {
                                let mask = rd.u16();
                                for (i, r) in t.regs.iter_mut().enumerate() {
                                    if mask >> i & 1 != 0 {
                                        *r = rd.u16();
                                    }
                                }
                            }
                            b"QUEU" => {
                                let n = rd.u32() as usize;
                                t.queu = Some(rd.d[rd.p..rd.p + n].to_vec());
                            }
                            _ => {}
                        }
                        rd.p = send;
                    }
                }
                b"CYCL" => {
                    t.cycl = rd.u32() as usize;
                }
                _ => {}
            }
            rd.p = cend;
        }
        rd.p = end;
        tests.push(t);
    }
}

fn testdata() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.join(".testdata").join("sst-8088")
}

/// jcc の成立を初期 flags から評価する。
fn jcc_taken(op: u8, f: u16) -> bool {
    let (cf, pf, zf, sf, of) = (f & 1, f >> 2 & 1, f >> 6 & 1, f >> 7 & 1, f >> 11 & 1);
    match op & 0xF {
        0x0 => of != 0,
        0x1 => of == 0,
        0x2 => cf != 0,
        0x3 => cf == 0,
        0x4 => zf != 0,
        0x5 => zf == 0,
        0x6 => cf | zf != 0,
        0x7 => cf | zf == 0,
        0x8 => sf != 0,
        0x9 => sf == 0,
        0xA => pf != 0,
        0xB => pf == 0,
        0xC => (sf ^ of) != 0,
        0xD => (sf ^ of) == 0,
        0xE => zf | (sf ^ of) != 0,
        _ => zf | (sf ^ of) == 0,
    }
}

#[test]
fn sst8088_cycles() {
    let dir = testdata();
    if !dir.is_dir() {
        eprintln!("sst-8088 のデータがない。スキップ");
        return;
    }
    let max: usize = std::env::var("POLYISA_SST_MAX")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    let max = if max == 0 { usize::MAX } else { max };
    let only: Option<String> = std::env::var("POLYISA_SST_FILE").ok();

    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| {
            let n = e.unwrap().file_name().into_string().unwrap();
            n.strip_suffix(".MOO").map(str::to_owned)
        })
        .collect();
    names.sort();

    let mut total = 0usize;
    let mut covered = 0usize;
    let mut bad = 0usize;
    let mut bad_files: Vec<String> = Vec::new();
    for name in &names {
        if let Some(f) = &only
            && name != f
        {
            continue;
        }
        // 60-6F は 80186+ の命令領域で 8088 では未定義動作。
        if name.len() == 2 && u8::from_str_radix(name, 16).is_ok_and(|v| (0x60..=0x6F).contains(&v))
        {
            continue;
        }
        let data = std::fs::read(dir.join(format!("{name}.MOO"))).unwrap();
        let mut tests = Vec::new();
        parse(&data, max, &mut tests);
        let mut file_bad = 0usize;
        for (i, t) in tests.iter().enumerate() {
            total += 1;
            let Some(d) = decode_map(&t.byts, 0, DEFAULT_FEATS) else {
                continue;
            };
            let flags = t.regs[13];
            let cx = t.regs[2];
            let name = INSNS[d.insn as usize].name;
            let op = d.opcode;
            let taken = match name {
                _ if name.starts_with("jcxz") => cx == 0,
                _ if name.starts_with("loopne") => cx != 1 && flags & 0x40 == 0,
                _ if name.starts_with("loope") => cx != 1 && flags & 0x40 != 0,
                _ if name.starts_with("loop") => cx != 1,
                _ if name.starts_with('j') => jcc_taken(op, flags),
                _ => false,
            };
            let Some(x) = classify_8088(&d, &t.byts, taken, cx as u8) else {
                continue;
            };
            covered += 1;
            let mut m = I8088::init(t.queu.as_ref().map_or(0, |q| q.len() as u8));
            let got = m.run(&x);
            if got as usize != t.cycl {
                bad += 1;
                file_bad += 1;
                if file_bad <= 3 {
                    eprintln!(
                        "{name}#{i} [{}] byts={:02x?} queu={:?}: model {got} vs sst {}",
                        t.name, t.byts, t.queu, t.cycl
                    );
                }
            }
        }
        if file_bad > 0 {
            bad_files.push(format!("{name}:{file_bad}/{}", tests.len()));
        }
    }
    eprintln!("total {total}, classified {covered}, mismatches {bad}");
    for b in &bad_files {
        eprintln!("  {b}");
    }
    assert_eq!(bad, 0, "{bad} cycle mismatches");
}
