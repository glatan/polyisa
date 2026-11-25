// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! RSP のパケット層。`$<data>#<ck>` の形の送受信と `+`/`-` の確認応答、
//! データ部の `}` エスケープを扱う。Ref: SPEC-GDB-RSP.

use std::io::{self, Read, Write};

/// データ部の最大長。これを超える入力は壊れたパケットとして捨てる。
pub const MAX_DATA: usize = 0x4000;

const HEX: &[u8; 16] = b"0123456789abcdef";

/// チェックサム。data の各バイトの合計を 256 で割った余り。
/// Ref: SPEC-GDB-RSP.
#[must_use]
pub fn checksum(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |a, &b| a.wrapping_add(b))
}

/// 送信側のエスケープ。`$` `#` `}` `*` は `}` と `byte ^ 0x20` の
/// 2 バイトにする。Ref: SPEC-GDB-RSP.
#[must_use]
pub fn escape(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for &b in data {
        if matches!(b, b'$' | b'#' | b'}' | b'*') {
            out.push(b'}');
            out.push(b ^ 0x20);
        } else {
            out.push(b);
        }
    }
    out
}

/// 1 パケットを書く。`$` + escape(data) + `#` + 16 進 2 桁のチェックサム。
/// チェックサムはワイヤに出るエスケープ後のバイト列に対して計算する。
/// Ref: SPEC-GDB-RSP.
pub fn write_packet(w: &mut impl Write, data: &[u8]) -> io::Result<()> {
    let body = escape(data);
    let mut out = Vec::with_capacity(body.len() + 8);
    out.push(b'$');
    out.extend_from_slice(&body);
    out.push(b'#');
    let ck = checksum(&body);
    out.push(HEX[(ck >> 4) as usize]);
    out.push(HEX[(ck & 0xf) as usize]);
    w.write_all(&out)?;
    w.flush()
}

enum Body {
    Packet(Vec<u8>),
    /// チェックサムの不一致や形式の破損。`-` を送って次を読む。
    Bad,
    /// パケットの途中で接続が切れた。
    Eof,
}

/// 1 パケットを読む。受け取れたら `+` を送ってデータ部を返し、壊れて
/// いれば `-` を送って次の `$` を待つ。`+`/`-`/割込み文字などパケット外の
/// バイトは読み飛ばす。接続が切れたら `None`。Ref: SPEC-GDB-RSP.
pub fn read_packet(conn: &mut (impl Read + Write)) -> io::Result<Option<Vec<u8>>> {
    loop {
        match read_byte(conn)? {
            None => return Ok(None),
            Some(b'$') => match read_body(conn)? {
                Body::Packet(d) => {
                    conn.write_all(b"+")?;
                    conn.flush()?;
                    return Ok(Some(d));
                }
                Body::Bad => {
                    conn.write_all(b"-")?;
                    conn.flush()?;
                }
                Body::Eof => return Ok(None),
            },
            Some(_) => {}
        }
    }
}

fn read_byte(conn: &mut (impl Read + Write)) -> io::Result<Option<u8>> {
    let mut b = [0u8; 1];
    loop {
        return match conn.read(&mut b) {
            Ok(0) => Ok(None),
            Ok(_) => Ok(Some(b[0])),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => Err(e),
        };
    }
}

fn read_body(conn: &mut (impl Read + Write)) -> io::Result<Body> {
    let mut data = Vec::new();
    // チェックサムは復号前のワイヤ上のバイト列に対して和を取る
    // （`}` とエスケープ済みの第 2 バイトをそのまま数える）。
    let mut sum = 0u8;
    loop {
        let Some(c) = read_byte(conn)? else {
            return Ok(Body::Eof);
        };
        match c {
            b'#' => break,
            b'}' => {
                let Some(e) = read_byte(conn)? else {
                    return Ok(Body::Eof);
                };
                sum = sum.wrapping_add(b'}').wrapping_add(e);
                data.push(e ^ 0x20);
            }
            _ => {
                sum = sum.wrapping_add(c);
                data.push(c);
            }
        }
        if data.len() > MAX_DATA {
            return Ok(Body::Bad);
        }
    }
    let Some(a) = read_byte(conn)? else {
        return Ok(Body::Eof);
    };
    let Some(b) = read_byte(conn)? else {
        return Ok(Body::Eof);
    };
    let Some(ck) = hex_val(a).zip(hex_val(b)).map(|(h, l)| h << 4 | l) else {
        return Ok(Body::Bad);
    };
    if ck == sum {
        Ok(Body::Packet(data))
    } else {
        Ok(Body::Bad)
    }
}

/// バイト列を小文字の 16 進文字列にする。
#[must_use]
pub fn to_hex(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for &b in data {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

/// 16 進文字列をバイト列にする。奇数長・非 16 進文字は `None`。
#[must_use]
pub fn from_hex(s: &[u8]) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_chunks::<2>()
        .0
        .iter()
        .map(|p| Some(hex_val(p[0])? * 16 + hex_val(p[1])?))
        .collect()
}

/// 16 進文字列を u64 にする。空・非 16 進文字・桁溢れは `None`。
#[must_use]
pub fn parse_hex(s: &[u8]) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    s.iter().try_fold(0u64, |a, &b| {
        a.checked_mul(16)?.checked_add(u64::from(hex_val(b)?))
    })
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
pub(crate) mod pipe {
    use std::io::{Cursor, Read, Result, Write};

    /// 読み側に仕込んだ列を読み、書き側は `out` に貯める擬似接続。
    pub(crate) struct Pipe {
        rx: Cursor<Vec<u8>>,
        pub(crate) out: Vec<u8>,
    }

    impl Pipe {
        pub(crate) fn new(input: Vec<u8>) -> Self {
            Self {
                rx: Cursor::new(input),
                out: Vec::new(),
            }
        }
    }

    impl Read for Pipe {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            self.rx.read(buf)
        }
    }

    impl Write for Pipe {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            self.out.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rsp::pipe::Pipe;

    fn framed(data: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        write_packet(&mut v, data).unwrap();
        v
    }

    #[test]
    fn checksum_is_sum_mod_256() {
        assert_eq!(checksum(b""), 0);
        assert_eq!(checksum(b"OK"), 0x9a);
        assert_eq!(checksum(&[0xff; 2]), 0xfe);
    }

    #[test]
    fn write_packet_frames() {
        assert_eq!(framed(b"OK"), b"$OK#9a");
        assert_eq!(framed(b""), b"$#00");
    }

    #[test]
    fn escape_marks_four_bytes() {
        // $ # } * は } + (byte ^ 0x20)。
        assert_eq!(escape(b"a$#}*b"), b"a}\x04}\x03}\x5d}\x0ab");
        assert_eq!(escape(b"plain"), b"plain");
    }

    #[test]
    fn read_packet_acks_and_unescapes() {
        // 手で組んだエスケープ入りパケット "a}\x0a" -> データ "a*"（0x0a^0x20=0x2a）。
        // チェックサムは復号前の "a}\x0a" に対して取る: 0x61+0x7d+0x0a = 0xe8。
        let mut wire = b"$a}\x0a#".to_vec();
        wire.extend_from_slice(b"e8");
        wire.extend_from_slice(&framed(b"OK"));
        let mut conn = Pipe::new(wire);
        assert_eq!(read_packet(&mut conn).unwrap(), Some(b"a*".to_vec()));
        assert_eq!(read_packet(&mut conn).unwrap(), Some(b"OK".to_vec()));
        assert_eq!(conn.out, b"++");
    }

    #[test]
    fn roundtrip_with_escaped_bytes() {
        // エスケープ対象の $ # } * をすべて含むデータが往復する。
        // 受け側が復号後ではなくワイヤ上のバイト列で和を検査しないと
        // この列はチェックサム不一致になる。
        let data: &[u8] = b"a$b#c}d*e";
        let mut conn = Pipe::new(framed(data));
        assert_eq!(read_packet(&mut conn).unwrap(), Some(data.to_vec()));
        assert_eq!(conn.out, b"+");
    }

    #[test]
    fn nak_on_bad_checksum_then_retransmit() {
        let mut wire = b"$Bad#00".to_vec();
        wire.extend_from_slice(&framed(b"Bad"));
        let mut conn = Pipe::new(wire);
        assert_eq!(read_packet(&mut conn).unwrap(), Some(b"Bad".to_vec()));
        assert_eq!(conn.out, b"-+");
    }

    #[test]
    fn skips_noise_and_eof() {
        let mut wire = b"+noise\x03".to_vec();
        wire.extend_from_slice(&framed(b"m0,1"));
        let mut conn = Pipe::new(wire);
        assert_eq!(read_packet(&mut conn).unwrap(), Some(b"m0,1".to_vec()));
        assert_eq!(read_packet(&mut conn).unwrap(), None);
        let mut conn = Pipe::new(Vec::new());
        assert_eq!(read_packet(&mut conn).unwrap(), None);
    }

    #[test]
    fn truncated_packet_is_eof() {
        let mut conn = Pipe::new(b"$abc".to_vec());
        assert_eq!(read_packet(&mut conn).unwrap(), None);
    }

    #[test]
    fn hex_helpers() {
        assert_eq!(to_hex(&[0xde, 0xad]), "dead");
        assert_eq!(from_hex(b"dead"), Some(vec![0xde, 0xad]));
        assert_eq!(from_hex(b"dea"), None);
        assert_eq!(from_hex(b"zz"), None);
        assert_eq!(parse_hex(b"1f"), Some(31));
        assert_eq!(parse_hex(b""), None);
        assert_eq!(parse_hex(b"gg"), None);
    }
}
