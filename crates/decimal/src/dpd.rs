// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 密パック十進（DPD）の符号化。10 ビットのデクレットと BCD 3 桁を相互変換する。
//! 変換はブール演算だけで書ける（符号化の事実のみ自前の表現で使う）。
// Ref: SPEC-DECIMAL-ARITH (DPD 符号化).

/// 3 桁の BCD（12 ビット、各ニブル 0〜9）を 10 ビットのデクレットに圧縮する。
/// 入力の各ニブルが 9 以下であること（呼び出し側の責務）。
#[must_use]
pub fn bcd_to_dpd(bcd: u16) -> u16 {
    let bit = |n: u32| (bcd >> n) & 1 != 0;
    // 各桁のビット（最上位から a..m）。ニブル番号は左の桁から。
    let (a, b, c, d) = (bit(11), bit(10), bit(9), bit(8));
    let (e, f, g, h) = (bit(7), bit(6), bit(5), bit(4));
    let (i, j, k, m) = (bit(3), bit(2), bit(1), bit(0));
    let p = b || (a && j) || (a && f && i);
    let q = c || (a && k) || (a && g && i);
    let r = d;
    let s = (f && (!a || !i)) || (!a && e && j) || (e && i);
    let t = g || (!a && e && k) || (a && i);
    let u = h;
    let v = a || e || i;
    let w = a || (e && i) || (!e && j);
    let x = e || (a && i) || (!a && k);
    let y = m;
    (u16::from(p) << 9)
        | (u16::from(q) << 8)
        | (u16::from(r) << 7)
        | (u16::from(s) << 6)
        | (u16::from(t) << 5)
        | (u16::from(u) << 4)
        | (u16::from(v) << 3)
        | (u16::from(w) << 2)
        | (u16::from(x) << 1)
        | u16::from(y)
}

/// 10 ビットのデクレットを 3 桁の BCD（12 ビット）に展開する。
/// 全 1024 パターンを受理し、非正規パターンは規定の 8/9 列に写す。
#[must_use]
pub fn dpd_to_bcd(dpd: u16) -> u16 {
    let bit = |n: u32| (dpd >> n) & 1 != 0;
    let (p, q, r, s, t, u, v, w, x, y) = (
        bit(9),
        bit(8),
        bit(7),
        bit(6),
        bit(5),
        bit(4),
        bit(3),
        bit(2),
        bit(1),
        bit(0),
    );
    let a = v && w && (!s || t || !x);
    let b = p && (!v || !w || (s && !t && x));
    let c = q && (!v || !w || (s && !t && x));
    let d = r;
    let e = v && ((!w && x) || (!t && x) || (s && x));
    let f = (s && (!v || !x)) || (p && !s && t && v && w && x);
    let g = (t && (!v || !x)) || (q && !s && t && w);
    let h = u;
    let i = v && ((!w && !x) || (w && x && (s || t)));
    let j = (!v && w) || (s && v && !w && x) || (p && w && (!x || (!s && !t)));
    let k = (!v && x) || (t && !w && x) || (q && v && w && (!x || (!s && !t)));
    let m = y;
    (u16::from(a) << 11)
        | (u16::from(b) << 10)
        | (u16::from(c) << 9)
        | (u16::from(d) << 8)
        | (u16::from(e) << 7)
        | (u16::from(f) << 6)
        | (u16::from(g) << 5)
        | (u16::from(h) << 4)
        | (u16::from(i) << 3)
        | (u16::from(j) << 2)
        | (u16::from(k) << 1)
        | u16::from(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_1000() {
        for i in 0..1000u16 {
            let bcd = ((i / 100) << 8) | (((i / 10) % 10) << 4) | (i % 10);
            let dpd = bcd_to_dpd(bcd);
            assert!(dpd < 1024);
            assert_eq!(dpd_to_bcd(dpd), bcd, "i={i}");
        }
    }

    #[test]
    fn known_values() {
        // 000→0, 999→0x3ff（規定値）。055/101 などは資料の例に合わせる。
        assert_eq!(bcd_to_dpd(0x000), 0x000);
        assert_eq!(bcd_to_dpd(0x999), 0x0ff);
        assert_eq!(bcd_to_dpd(0x055), 0x055);
        assert_eq!(bcd_to_dpd(0x101), 0x081);
        assert_eq!(bcd_to_dpd(0x005), 0x005);
        assert_eq!(bcd_to_dpd(0x009), 0x009);
    }
}
