// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! パケットの振り分けと応答。接続 1 本につき `serve_conn` を 1 回呼ぶ。
//!
//! 対応パケット: `?`、`qSupported`、`qXfer:features:read`、`qAttached`、
//! `qC`、`qfThreadInfo`/`qsThreadInfo`、`g`/`G`、`p`/`P`、`m`/`M`、
//! `c`/`C`、`s`/`S`、`Z0`/`z0`、`H`、`T`、`D`、`k`、`vCont?`/`vCont`、
//! `vMustReplyEmpty`、`vKill`。それ以外は空応答。Ref: SPEC-GDB-RSP.

use std::io::{self, Read, Write};
use std::net::TcpListener;

use crate::rsp;
use crate::target::{DebugTarget, Stop};

/// 1 接続を捌く。`D`・`k`・`vKill` か相手の切断で戻る。
pub fn serve_conn(conn: &mut (impl Read + Write), target: &mut impl DebugTarget) -> io::Result<()> {
    while let Some(pkt) = rsp::read_packet(conn)? {
        match dispatch(&pkt, target) {
            Act::Reply(d) => rsp::write_packet(conn, &d)?,
            Act::ReplyEnd(d) => {
                rsp::write_packet(conn, &d)?;
                return Ok(());
            }
        }
    }
    Ok(())
}

/// リスナで 1 接続を受けて捌く。
pub fn serve(listener: &TcpListener, target: &mut impl DebugTarget) -> io::Result<()> {
    let (mut conn, _) = listener.accept()?;
    serve_conn(&mut conn, target)
}

enum Act {
    Reply(Vec<u8>),
    /// 応答を書いてから接続を閉じる。
    ReplyEnd(Vec<u8>),
}

fn rep(s: impl Into<Vec<u8>>) -> Act {
    Act::Reply(s.into())
}

fn ok() -> Act {
    rep(b"OK".to_vec())
}

fn err() -> Act {
    rep(b"E01".to_vec())
}

fn empty() -> Act {
    rep(Vec::new())
}

fn dispatch(pkt: &[u8], target: &mut impl DebugTarget) -> Act {
    let Some(&b0) = pkt.first() else {
        return empty();
    };
    match b0 {
        // 停止理由。T05 = シグナル 5（trap）。Ref: SPEC-GDB-RSP.
        b'?' => rep("T05"),
        b'g' => {
            let mut buf = vec![0u8; target.reg_bytes()];
            target.read_regs(&mut buf);
            rep(rsp::to_hex(&buf))
        }
        b'G' => match rsp::from_hex(&pkt[1..]) {
            Some(d) if d.len() == target.reg_bytes() => {
                target.write_regs(&d);
                ok()
            }
            _ => err(),
        },
        b'p' => match rsp::parse_hex(&pkt[1..]) {
            Some(idx) => {
                let n = target.reg_size(idx as usize);
                if n == 0 || n > 32 {
                    return err();
                }
                let mut buf = vec![0u8; n];
                if target.read_reg(idx as usize, &mut buf) {
                    rep(rsp::to_hex(&buf))
                } else {
                    err()
                }
            }
            None => err(),
        },
        b'P' => {
            let Some(eq) = pkt.iter().position(|&b| b == b'=') else {
                return err();
            };
            let Some(idx) = rsp::parse_hex(&pkt[1..eq]) else {
                return err();
            };
            let Some(d) = rsp::from_hex(&pkt[eq + 1..]) else {
                return err();
            };
            if target.write_reg(idx as usize, &d) {
                ok()
            } else {
                err()
            }
        }
        b'm' => {
            let Some((addr, len)) = pair(&pkt[1..]) else {
                return err();
            };
            let Ok(len) = usize::try_from(len) else {
                return err();
            };
            if len > rsp::MAX_DATA / 2 {
                return err();
            }
            let mut buf = vec![0u8; len];
            if target.read_mem(addr, &mut buf).is_ok() {
                rep(rsp::to_hex(&buf))
            } else {
                err()
            }
        }
        b'M' => {
            let Some(colon) = pkt.iter().position(|&b| b == b':') else {
                return err();
            };
            let Some((addr, len)) = pair(&pkt[1..colon]) else {
                return err();
            };
            let Some(d) = rsp::from_hex(&pkt[colon + 1..]) else {
                return err();
            };
            if d.len() as u64 != len {
                return err();
            }
            if target.write_mem(addr, &d).is_ok() {
                ok()
            } else {
                err()
            }
        }
        // `c`/`C`（継続。引数は見ない）と `s`/`S`（1 ステップ）。
        b'c' | b'C' => stop_reply(target.resume()),
        b's' | b'S' => stop_reply(target.step()),
        b'Z' => set_bp(&pkt[1..], true, target),
        b'z' => set_bp(&pkt[1..], false, target),
        // スレッドの選択は受理だけする（単一スレッド）。
        b'H' => ok(),
        // `T<tid>` はスレッドの生存確認。空応答は「死」を意味するので OK。
        b'T' => ok(),
        b'D' => {
            target.detach();
            Act::ReplyEnd(b"OK".to_vec())
        }
        b'k' => {
            target.kill();
            Act::ReplyEnd(b"OK".to_vec())
        }
        b'q' => query(pkt, target),
        b'v' => v_packet(pkt, target),
        _ => empty(),
    }
}

/// 停止理由の応答。T05 = SIGTRAP、T09 = トラップ系の仮の番号、
/// W = 終了、X = シグナルでの終了。ブレークポイントは `swbreak` の
/// 停止理由（r は空）を付ける。n:r 対の n は 16 進のレジスタ番号か
/// 定義済みの名前だけなので、ここではレジスタを載せず gdb の `g`
/// 要求に任せる。Ref: SPEC-GDB-RSP.
fn stop_reply(stop: Stop) -> Act {
    match stop {
        Stop::Breakpoint(..) => rep("T05swbreak:;"),
        Stop::Step(..) => rep("T05"),
        Stop::Trap(..) => rep("T09"),
        Stop::Exit(code) => rep(format!("W{:02x}", code & 0xff)),
        Stop::Signal(sig) => rep(format!("X{sig:02x}")),
    }
}

/// `Z<型>,<addr>,<種別>` / `z<型>,<addr>,<種別>`。型 0（ソフト）だけを
/// 扱い、他の型は空応答で未対応を伝える。Ref: SPEC-GDB-RSP.
fn set_bp(arg: &[u8], add: bool, target: &mut impl DebugTarget) -> Act {
    let mut it = arg.split(|&b| b == b',');
    let (Some(ty), Some(adr), Some(_kind)) = (it.next(), it.next(), it.next()) else {
        return empty();
    };
    if ty != b"0" {
        return empty();
    }
    let Some(addr) = rsp::parse_hex(adr) else {
        return err();
    };
    let done = if add {
        target.add_bp(addr)
    } else {
        target.remove_bp(addr)
    };
    if done { ok() } else { err() }
}

fn query(pkt: &[u8], target: &mut impl DebugTarget) -> Act {
    if pkt.starts_with(b"qSupported") {
        // 要求側の列（multiprocess 等）は受理だけして自前の応答を返す。
        return rep("PacketSize=4000;qXfer:features:read+;swbreak+;hwbreak-");
    }
    if let Some(arg) = pkt.strip_prefix(b"qXfer:features:read:") {
        return xfer(arg, target);
    }
    if pkt.starts_with(b"qAttached") {
        // 既にあるプロセスへの接続。
        return rep("1");
    }
    if pkt == b"qC" {
        return rep("QC1");
    }
    if pkt == b"qfThreadInfo" {
        return rep("m1");
    }
    if pkt == b"qsThreadInfo" {
        return rep("l");
    }
    empty()
}

/// `qXfer:features:read:<annex>:<off>,<len>`。annex は target.xml のみ。
/// 部分転送の終端は `l`、中間は `m` を先頭に付ける。Ref: SPEC-GDB-RSP.
fn xfer(arg: &[u8], target: &mut impl DebugTarget) -> Act {
    let Some(colon) = arg.iter().position(|&b| b == b':') else {
        return err();
    };
    if &arg[..colon] != b"target.xml" {
        return err();
    }
    let Some((off, len)) = pair(&arg[colon + 1..]) else {
        return err();
    };
    let (Ok(off), Ok(len)) = (usize::try_from(off), usize::try_from(len)) else {
        return err();
    };
    let xml = target.target_xml().as_bytes();
    if off > xml.len() {
        return err();
    }
    let end = off.saturating_add(len).min(xml.len());
    let mut d = Vec::with_capacity(end - off + 1);
    d.push(if end >= xml.len() { b'l' } else { b'm' });
    d.extend_from_slice(&xml[off..end]);
    Act::Reply(d)
}

fn v_packet(pkt: &[u8], target: &mut impl DebugTarget) -> Act {
    if pkt == b"vCont?" {
        return rep("vCont;c;s");
    }
    if pkt == b"vMustReplyEmpty" {
        return empty();
    }
    if let Some(rest) = pkt.strip_prefix(b"vCont;") {
        // 単一スレッドなので最初の動作だけを見る。c/C = 継続、s/S = 1 歩。
        return match rest.first() {
            Some(b'c') | Some(b'C') => stop_reply(target.resume()),
            Some(b's') | Some(b'S') => stop_reply(target.step()),
            _ => empty(),
        };
    }
    if pkt.starts_with(b"vKill") {
        target.kill();
        return Act::ReplyEnd(b"OK".to_vec());
    }
    empty()
}

/// `<hex>,<hex>` の形を読む。
fn pair(s: &[u8]) -> Option<(u64, u64)> {
    let comma = s.iter().position(|&b| b == b',')?;
    Some((
        rsp::parse_hex(&s[..comma])?,
        rsp::parse_hex(&s[comma + 1..])?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rsp::pipe::Pipe;
    use crate::target::MemError;
    use std::collections::{BTreeMap, BTreeSet, VecDeque};

    /// 4 本の 8 バイトレジスタ（3 番目が pc）を持つ擬似対象。
    struct FakeTarget {
        xml: String,
        regs: Vec<u8>,
        mem: BTreeMap<u64, u8>,
        stops: VecDeque<Stop>,
        bps: BTreeSet<u64>,
        killed: bool,
        detached: bool,
    }

    impl FakeTarget {
        fn new() -> Self {
            let mut regs = vec![0u8; 32];
            regs[24..32].copy_from_slice(&0x80000u64.to_le_bytes());
            Self {
                xml: "<target/>".to_string(),
                regs,
                mem: BTreeMap::new(),
                stops: VecDeque::new(),
                bps: BTreeSet::new(),
                killed: false,
                detached: false,
            }
        }
    }

    impl DebugTarget for FakeTarget {
        fn target_xml(&self) -> &str {
            &self.xml
        }
        fn reg_bytes(&self) -> usize {
            self.regs.len()
        }
        fn reg_size(&self, idx: usize) -> usize {
            if idx < self.regs.len() / 8 { 8 } else { 0 }
        }
        fn read_regs(&mut self, buf: &mut [u8]) {
            buf.copy_from_slice(&self.regs);
        }
        fn write_regs(&mut self, buf: &[u8]) {
            self.regs.copy_from_slice(buf);
        }
        fn read_reg(&mut self, idx: usize, buf: &mut [u8]) -> bool {
            let Some(s) = self.regs.get(idx * 8..idx * 8 + 8) else {
                return false;
            };
            if buf.len() != 8 {
                return false;
            }
            buf.copy_from_slice(s);
            true
        }
        fn write_reg(&mut self, idx: usize, buf: &[u8]) -> bool {
            let Some(s) = self.regs.get_mut(idx * 8..idx * 8 + 8) else {
                return false;
            };
            if buf.len() != 8 {
                return false;
            }
            s.copy_from_slice(buf);
            true
        }
        fn read_mem(&mut self, addr: u64, buf: &mut [u8]) -> Result<(), MemError> {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = *self.mem.get(&(addr + i as u64)).ok_or(MemError)?;
            }
            Ok(())
        }
        fn write_mem(&mut self, addr: u64, buf: &[u8]) -> Result<(), MemError> {
            for (i, &b) in buf.iter().enumerate() {
                self.mem.insert(addr + i as u64, b);
            }
            Ok(())
        }
        fn pc(&self) -> u64 {
            u64::from_le_bytes(self.regs[24..32].try_into().unwrap())
        }
        fn step(&mut self) -> Stop {
            self.stops.pop_front().unwrap_or(Stop::Step(self.pc() + 4))
        }
        fn resume(&mut self) -> Stop {
            self.stops
                .pop_front()
                .unwrap_or(Stop::Breakpoint(self.pc()))
        }
        fn kill(&mut self) {
            self.killed = true;
        }
        fn detach(&mut self) {
            self.detached = true;
        }
        fn add_bp(&mut self, addr: u64) -> bool {
            self.bps.insert(addr)
        }
        fn remove_bp(&mut self, addr: u64) -> bool {
            self.bps.remove(&addr)
        }
    }

    /// 入力列を組み立てる。
    fn wire(pkts: &[&[u8]]) -> Vec<u8> {
        let mut v = Vec::new();
        for p in pkts {
            rsp::write_packet(&mut v, p).unwrap();
        }
        v
    }

    /// 期待する出力。各パケットの ACK `+` と応答フレームの並び。
    fn expect(replies: &[&[u8]]) -> Vec<u8> {
        let mut v = Vec::new();
        for r in replies {
            v.push(b'+');
            rsp::write_packet(&mut v, r).unwrap();
        }
        v
    }

    fn run(input: Vec<u8>, target: &mut FakeTarget) -> Vec<u8> {
        let mut conn = Pipe::new(input);
        serve_conn(&mut conn, target).unwrap();
        conn.out
    }

    #[test]
    fn stop_reason_and_kill() {
        let mut t = FakeTarget::new();
        let out = run(wire(&[b"?", b"k"]), &mut t);
        assert_eq!(out, expect(&[b"T05", b"OK"]));
        assert!(t.killed);
    }

    #[test]
    fn supported_and_attached() {
        let mut t = FakeTarget::new();
        let out = run(
            wire(&[
                b"qSupported:multiprocess+;xmlRegisters+",
                b"qAttached",
                b"D",
            ]),
            &mut t,
        );
        assert_eq!(
            out,
            expect(&[
                b"PacketSize=4000;qXfer:features:read+;swbreak+;hwbreak-",
                b"1",
                b"OK"
            ])
        );
        assert!(t.detached);
    }

    #[test]
    fn xfer_annex() {
        let mut t = FakeTarget::new();
        let out = run(
            wire(&[
                b"qXfer:features:read:target.xml:0,4",
                b"qXfer:features:read:target.xml:4,ff",
                b"qXfer:features:read:other.xml:0,4",
                b"D",
            ]),
            &mut t,
        );
        // "<target/>" の [0..4) = "<tar"、終端まで残りは l。
        assert_eq!(out, expect(&[b"m<tar", b"lget/>", b"E01", b"OK"]));
    }

    #[test]
    fn regs_read_write() {
        let mut t = FakeTarget::new();
        // reg1 = 2 を仕込む。
        t.regs[8..16].copy_from_slice(&2u64.to_le_bytes());
        let all = rsp::to_hex(&t.regs);
        let mut new_regs = vec![7u8; 32];
        new_regs[24..32].copy_from_slice(&0x90000u64.to_le_bytes());
        let g_pkt = format!("G{}", rsp::to_hex(&new_regs));
        let out = run(
            wire(&[
                b"g",
                b"p1",
                b"p9",
                g_pkt.as_bytes(),
                b"P0=2a00000000000000",
                b"D",
            ]),
            &mut t,
        );
        assert_eq!(
            out,
            expect(&[
                all.as_bytes(),
                b"0200000000000000",
                b"E01",
                b"OK",
                b"OK",
                b"OK"
            ])
        );
        assert_eq!(u64::from_le_bytes(t.regs[0..8].try_into().unwrap()), 0x2a);
        // G で書き込んだ pc
        assert_eq!(
            u64::from_le_bytes(t.regs[24..32].try_into().unwrap()),
            0x90000
        );
    }

    #[test]
    fn mem_read_write() {
        let mut t = FakeTarget::new();
        for (i, &b) in [0xaau8, 0xbb, 0xcc, 0xdd].iter().enumerate() {
            t.mem.insert(0x100 + i as u64, b);
        }
        let out = run(wire(&[b"m100,4", b"m200,2", b"M100,2:1122", b"D"]), &mut t);
        assert_eq!(out, expect(&[b"aabbccdd", b"E01", b"OK", b"OK"]));
        assert_eq!(t.mem[&0x100], 0x11);
        assert_eq!(t.mem[&0x101], 0x22);
    }

    #[test]
    fn run_stop_and_breakpoints() {
        let mut t = FakeTarget::new();
        t.stops.extend([
            Stop::Breakpoint(0x80004),
            Stop::Step(0x80008),
            Stop::Trap(0x80010),
            Stop::Exit(7),
            Stop::Signal(11),
        ]);
        let out = run(
            wire(&[
                b"Z0,9000,4",
                b"c",
                b"s",
                b"vCont?",
                b"vCont;c",
                b"vCont;s",
                b"c",
                b"z0,9000,4",
                b"Z1,9000,0",
                b"qFoo",
                b"vMustReplyEmpty",
                b"H",
                b"T1",
                b"D",
            ]),
            &mut t,
        );
        assert_eq!(
            out,
            expect(&[
                b"OK",
                b"T05swbreak:;",
                b"T05",
                b"vCont;c;s",
                b"T09",
                b"W07",
                b"X0b",
                b"OK",
                b"",
                b"",
                b"",
                b"OK",
                b"OK",
                b"OK"
            ])
        );
        assert!(t.bps.is_empty());
    }
}
