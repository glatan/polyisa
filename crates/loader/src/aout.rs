// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! a.out の解析。ヘッダの解読のみ —— セグメントの仮想アドレス・
//! ファイル内オフセット・写像権限の方針は OS パーソナリティが決める。
//!
//! `exec` ヘッダは先頭から magic・text・data・bss・syms・entry の
//! 6 項目が共通で、語幅が対象機種で違う。PDP-11 は 16 ビット語
//! （16 バイト、末尾は a_unused・a_flag）、VAX は 32 ビット語
//! （32 バイト、末尾は a_trsize・a_drsize）。
//!
//! 出典は下記の確認済みの版である。数値・配置の事実のみを自前の表現で使う。

// Ref: SPEC-UNIX-V7 §5 a.out — PDP-11 の exec 形式。
// Ref: SPEC-BSD-43 a.out(5) — VAX の exec 形式と N_TXTOFF。

#![forbid(unsafe_code)]

/// テキストが書き込み可能な impure 形式。
pub const OMAGIC: u16 = 0o407;
/// 読み出し専用テキストの pure 形式。
pub const NMAGIC: u16 = 0o410;
/// I 空間と D 空間を分離する形式（PDP-11）。
pub const SEPMAGIC: u16 = 0o411;
/// デマンドロード形式（VAX。テキストは 1024 バイト境界から）。
pub const ZMAGIC: u16 = 0o413;

/// a.out の語構成。対象機種ごとにヘッダの語幅が違う。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Arch {
    /// PDP-11: 16 ビット語 ×8。ヘッダは 16 バイト。
    Pdp11,
    /// VAX: 32 ビット語 ×8。ヘッダは 32 バイト。
    Vax,
}

/// 解析の失敗。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// 短すぎてヘッダが読めない。
    Truncated,
    /// magic が a.out の既知の値ではない。
    BadMagic,
}

/// ヘッダのバイト長（PDP-11 は 16、VAX は 32）。
const PDP11_HDR_LEN: u64 = 16;
const VAX_HDR_LEN: u64 = 32;

/// a.out ヘッダ。項目値は語幅によらず u64 に正規化する。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Header {
    /// 解読に使った語構成。
    pub arch: Arch,
    /// `a_magic`（`OMAGIC`・`NMAGIC`・`SEPMAGIC`・`ZMAGIC`）。
    pub magic: u16,
    /// `a_text`（テキストのバイト数）。
    pub text: u64,
    /// `a_data`（初期化データのバイト数）。
    pub data: u64,
    /// `a_bss`（未初期化データのバイト数）。
    pub bss: u64,
    /// `a_syms`（シンボル表のバイト数）。
    pub syms: u64,
    /// `a_entry`（エントリポイント）。
    pub entry: u64,
    /// 7 番目の語。VAX は `a_trsize`（テキスト再配置のバイト数）、
    /// PDP-11 は `a_unused`。
    pub trsize: u64,
    /// 8 番目の語。VAX は `a_drsize`（データ再配置のバイト数）、
    /// PDP-11 は `a_flag`（再配置情報が取り除かれたことを示す旗。
    /// 0 以外なら除去済みで、再配置項目はファイルにない）。
    pub drsize: u64,
    /// ヘッダのバイト長（`arch` に一致する 16 または 32）。
    pub hdr_len: u64,
}

/// 先頭 2 バイトの magic を読む。a.out の magic は対象機種にかかわらず
/// リトルエンディアンの 16 ビット値として先頭に置かれる。
#[must_use]
pub fn probe_magic(bytes: &[u8]) -> Option<u16> {
    let b = bytes.get(0..2)?;
    let magic = u16::from_le_bytes([b[0], b[1]]);
    matches!(magic, OMAGIC | NMAGIC | SEPMAGIC | ZMAGIC).then_some(magic)
}

/// `arch` の語幅で `exec` ヘッダを解読する。`a_magic` 自体も対象の
/// 語幅の項目なので、VAX では上位 16 ビットが 0 でなければならない。
pub fn parse(bytes: &[u8], arch: Arch) -> Result<Header, Error> {
    match arch {
        Arch::Pdp11 => {
            let h = bytes
                .get(0..PDP11_HDR_LEN as usize)
                .ok_or(Error::Truncated)?;
            let w = |i: usize| u16::from_le_bytes([h[2 * i], h[2 * i + 1]]);
            let magic = w(0);
            if !matches!(magic, OMAGIC | NMAGIC | SEPMAGIC | ZMAGIC) {
                return Err(Error::BadMagic);
            }
            Ok(Header {
                arch,
                magic,
                text: u64::from(w(1)),
                data: u64::from(w(2)),
                bss: u64::from(w(3)),
                syms: u64::from(w(4)),
                entry: u64::from(w(5)),
                trsize: u64::from(w(6)),
                drsize: u64::from(w(7)),
                hdr_len: PDP11_HDR_LEN,
            })
        }
        Arch::Vax => {
            let h = bytes.get(0..VAX_HDR_LEN as usize).ok_or(Error::Truncated)?;
            let w =
                |i: usize| u32::from_le_bytes([h[4 * i], h[4 * i + 1], h[4 * i + 2], h[4 * i + 3]]);
            let magic = w(0);
            let Ok(magic16) = u16::try_from(magic) else {
                return Err(Error::BadMagic);
            };
            if !matches!(magic16, OMAGIC | NMAGIC | SEPMAGIC | ZMAGIC) {
                return Err(Error::BadMagic);
            }
            Ok(Header {
                arch,
                magic: magic16,
                text: u64::from(w(1)),
                data: u64::from(w(2)),
                bss: u64::from(w(3)),
                syms: u64::from(w(4)),
                entry: u64::from(w(5)),
                trsize: u64::from(w(6)),
                drsize: u64::from(w(7)),
                hdr_len: VAX_HDR_LEN,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pdp11_header(magic: u16, fields: [u16; 7]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&magic.to_le_bytes());
        for f in fields {
            v.extend_from_slice(&f.to_le_bytes());
        }
        v
    }

    fn vax_header(magic: u16, fields: [u32; 7]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&u32::from(magic).to_le_bytes());
        for f in fields {
            v.extend_from_slice(&f.to_le_bytes());
        }
        v
    }

    #[test]
    fn pdp11_nmagic() {
        // V7 bin/cat 相当の形: text 0xd40・data 0x76・bss 0x2c・entry 0。
        let b = pdp11_header(NMAGIC, [0xd40, 0x76, 0x2c, 0, 0, 0, 1]);
        let h = parse(&b, Arch::Pdp11).unwrap();
        assert_eq!(h.magic, NMAGIC);
        assert_eq!(h.text, 0xd40);
        assert_eq!(h.data, 0x76);
        assert_eq!(h.bss, 0x2c);
        assert_eq!(h.entry, 0);
        assert_eq!(h.drsize, 1); // a_flag = 再配置情報除去済み
        assert_eq!(h.hdr_len, 16);
    }

    #[test]
    fn vax_zmagic() {
        let b = vax_header(ZMAGIC, [0x1000, 0x200, 0x40, 0x300, 0, 0x10, 0x20]);
        let h = parse(&b, Arch::Vax).unwrap();
        assert_eq!(h.magic, ZMAGIC);
        assert_eq!(h.text, 0x1000);
        assert_eq!(h.trsize, 0x10);
        assert_eq!(h.drsize, 0x20);
        assert_eq!(h.hdr_len, 32);
    }

    #[test]
    fn truncated_is_error() {
        let b = pdp11_header(NMAGIC, [0; 7]);
        assert_eq!(parse(&b[..8], Arch::Pdp11), Err(Error::Truncated));
        let b = vax_header(ZMAGIC, [0; 7]);
        assert_eq!(parse(&b[..20], Arch::Vax), Err(Error::Truncated));
    }

    #[test]
    fn bad_magic_is_error() {
        assert_eq!(probe_magic(&[0x7f, b'E']), None);
        let mut b = pdp11_header(NMAGIC, [0; 7]);
        b[0..2].copy_from_slice(&[0x7f, b'E']);
        assert_eq!(parse(&b, Arch::Pdp11), Err(Error::BadMagic));
        assert_eq!(parse(&[0u8; 32], Arch::Vax), Err(Error::BadMagic));
    }

    #[test]
    fn all_magics_probe() {
        for m in [OMAGIC, NMAGIC, SEPMAGIC, ZMAGIC] {
            assert_eq!(probe_magic(&m.to_le_bytes()), Some(m));
        }
    }

    #[test]
    fn pdp11_magics_parse() {
        // V7 が使う 3 形式はいずれも解読できる（配置はパーソナリティの判断）。
        for m in [OMAGIC, NMAGIC, SEPMAGIC] {
            let b = pdp11_header(m, [0x100, 0x40, 0x20, 0, 0, 0, 1]);
            let h = parse(&b, Arch::Pdp11).unwrap();
            assert_eq!(h.magic, m);
            assert_eq!(h.arch, Arch::Pdp11);
        }
    }

    #[test]
    fn vax_magic_high_half_is_bad() {
        // a_magic は VAX で 32 ビット項目 —— 上位 16 ビットが立つものは拒否する。
        let mut b = vax_header(ZMAGIC, [0; 7]);
        b[2] = 1;
        assert_eq!(parse(&b, Arch::Vax), Err(Error::BadMagic));
    }
}
