//! ELF の解析。配置の方針は OS パーソナリティが決める.
//!
//! 出典は下記の確認済みの版である。数値・配置の事実のみを自前の表現で使う。
//! 条文・図表の複製はしない。
//!
//! 段階 1 の範囲はリトルエンディアンに限り、ヘッダとプログラムヘッダを読む。
//! 32 ビットと 64 ビットの両方を受け付ける。ビッグエンディアン、
//! セクションの解釈は後の段階で足す。

// Ref: SPEC-ELF-GABI (Edition 4.1＋2001-04-24 DRAFT).

#![forbid(unsafe_code)]

use polyisa_bits as bits;

/// ELF の識別子。`e_ident[EI_MAG0..EI_MAG3]` は `0x7F,'E','L','F'` である。
pub const MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// 64 ビットの対象であることを示す `EI_CLASS` の値。
pub const CLASS_64: u8 = 2;

/// 32 ビットの対象であることを示す `EI_CLASS` の値。
pub const CLASS_32: u8 = 1;

/// リトルエンディアンを示す `EI_DATA` の値。
pub const DATA_LE: u8 = 1;

/// 解析の失敗。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// 短すぎてヘッダが読めない。
    Truncated,
    /// 識別子が ELF ではない。
    BadMagic,
    /// リトルエンディアンではない、または 32/64 ビットのいずれでもない。
    Unsupported,
}

/// ELF ヘッダ（64 ビット）。必要な項目だけを持つ。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ehdr {
    /// 対象のバイト順。
    pub little: bool,
    /// ファイルの種別（`ET_*`）。
    pub file_type: u16,
    /// 要求する ABI の版（`e_flags`）。
    pub flags: u32,
    /// エントリポイントの仮想アドレス。
    pub entry: u64,
    /// プログラムヘッダ表のファイル内位置。
    pub phoff: u64,
    /// プログラムヘッダの項目数。
    pub phnum: u16,
}

/// プログラムヘッダ（64 ビット）。セグメントの写像に使う項目だけを持つ。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Phdr {
    /// セグメントの種類（`PT_*`）。
    pub seg_type: u32,
    /// セグメントのファイル内位置。
    pub offset: u64,
    /// 配置する仮想アドレス。
    pub vaddr: u64,
    /// ファイル中の大きさ。
    pub filesz: u64,
    /// メモリ上の大きさ。
    pub memsz: u64,
    /// 読み書き実行の許可（`PF_*`）。
    pub flags: u32,
    /// 整列。
    pub align: u64,
}

fn u16_of(bytes: &[u8], little: bool) -> Option<u16> {
    if little {
        bits::read_le(bytes, 2).map(|v| v as u16)
    } else {
        bits::read_be(bytes, 2).map(|v| v as u16)
    }
}

fn u32_of(bytes: &[u8], little: bool) -> Option<u32> {
    if little {
        bits::read_le(bytes, 4).map(|v| v as u32)
    } else {
        bits::read_be(bytes, 4).map(|v| v as u32)
    }
}

fn u64_of(bytes: &[u8], little: bool) -> Option<u64> {
    if little {
        bits::read_le(bytes, 8)
    } else {
        bits::read_be(bytes, 8)
    }
}

/// ELF ヘッダを読む。64 ビットのリトルエンディアンだけを受け付ける。
pub fn parse_ehdr(bytes: &[u8]) -> Result<Ehdr, Error> {
    if bytes.len() < 64 {
        return Err(Error::Truncated);
    }
    if bytes[0..4] != MAGIC {
        return Err(Error::BadMagic);
    }
    if bytes[4] != CLASS_64 || bytes[5] != DATA_LE {
        return Err(Error::Unsupported);
    }
    let little = true;
    let get16 = |off: usize| u16_of(&bytes[off..off + 2], little).ok_or(Error::Truncated);
    let get32 = |off: usize| u32_of(&bytes[off..off + 4], little).ok_or(Error::Truncated);
    let get64 = |off: usize| u64_of(&bytes[off..off + 8], little).ok_or(Error::Truncated);
    // ヘッダと項目の大きさが想定どおりであることを確かめる。
    if get16(52)? != 64 || get16(54)? != 56 {
        return Err(Error::Unsupported);
    }
    Ok(Ehdr {
        little,
        file_type: get16(16)?,
        flags: get32(48)?,
        entry: get64(24)?,
        phoff: get64(32)?,
        phnum: get16(56)?,
    })
}

/// ELF ヘッダを読む。32 ビットのリトルエンディアンだけを受け付ける。
/// 32 ビットの値は 64 ビットにゼロ拡張して `Ehdr` に入れる。
pub fn parse_ehdr32(bytes: &[u8]) -> Result<Ehdr, Error> {
    if bytes.len() < 52 {
        return Err(Error::Truncated);
    }
    if bytes[0..4] != MAGIC {
        return Err(Error::BadMagic);
    }
    if bytes[4] != CLASS_32 || bytes[5] != DATA_LE {
        return Err(Error::Unsupported);
    }
    let little = true;
    let get16 = |off: usize| u16_of(&bytes[off..off + 2], little).ok_or(Error::Truncated);
    let get32 = |off: usize| u32_of(&bytes[off..off + 4], little).ok_or(Error::Truncated);
    // ヘッダと項目の大きさが想定どおりであることを確かめる。
    if get16(40)? != 52 || get16(42)? != 32 {
        return Err(Error::Unsupported);
    }
    Ok(Ehdr {
        little,
        file_type: get16(16)?,
        flags: get32(36)?,
        entry: u64::from(get32(24)?),
        phoff: u64::from(get32(28)?),
        phnum: get16(44)?,
    })
}

/// プログラムヘッダ表を読む。32 ビット形式（1 件 32 バイト）用。
/// `ehdr` は `parse_ehdr32` で読んだものとする。
pub fn parse_phdrs32(bytes: &[u8], ehdr: &Ehdr) -> Result<Vec<Phdr>, Error> {
    let mut out = Vec::new();
    let mut off = ehdr.phoff as usize;
    for _ in 0..ehdr.phnum as usize {
        if bytes.len() < off + 32 {
            return Err(Error::Truncated);
        }
        let get32 =
            |at: usize| u32_of(&bytes[off + at..off + at + 4], ehdr.little).ok_or(Error::Truncated);
        out.push(Phdr {
            seg_type: get32(0)?,
            offset: u64::from(get32(4)?),
            vaddr: u64::from(get32(8)?),
            filesz: u64::from(get32(16)?),
            memsz: u64::from(get32(20)?),
            flags: get32(24)?,
            align: u64::from(get32(28)?),
        });
        off += 32;
    }
    Ok(out)
}

/// プログラムヘッダ表を読む。`ehdr` は同じバイト列から読んだものとする。
pub fn parse_phdrs(bytes: &[u8], ehdr: &Ehdr) -> Result<Vec<Phdr>, Error> {
    let mut out = Vec::new();
    let mut off = ehdr.phoff as usize;
    for _ in 0..ehdr.phnum as usize {
        if bytes.len() < off + 56 {
            return Err(Error::Truncated);
        }
        let get32 =
            |at: usize| u32_of(&bytes[off + at..off + at + 4], ehdr.little).ok_or(Error::Truncated);
        let get64 =
            |at: usize| u64_of(&bytes[off + at..off + at + 8], ehdr.little).ok_or(Error::Truncated);
        out.push(Phdr {
            seg_type: get32(0)?,
            flags: get32(4)?,
            offset: get64(8)?,
            vaddr: get64(16)?,
            filesz: get64(32)?,
            memsz: get64(40)?,
            align: get64(48)?,
        });
        off += 56;
    }
    Ok(out)
}

/// PT_INTERP の指す動的リンカのパスを読む。なければ None。
/// 文字列はファイル内の NUL 終端とみなす。
// Ref: SPEC-ELF-GABI (Edition 4.1＋2001-04-24 DRAFT).
#[must_use]
pub fn parse_interp(bytes: &[u8], phdrs: &[Phdr]) -> Option<String> {
    for ph in phdrs {
        if ph.seg_type != 3 {
            continue;
        }
        let end = ph.offset.checked_add(ph.filesz)? as usize;
        let raw = bytes.get(ph.offset as usize..end)?;
        let end = raw.iter().position(|&b| b == 0)?;
        return String::from_utf8(raw[..end].to_vec()).ok();
    }
    None
}

/// PT_LOAD セグメントをアドレス空間に配置する。段階1の範囲。
/// `bytes` はファイル全体、`phdrs` は `parse_phdrs` の結果とする。
/// 書き込み可能な写像で配置し、ファイル範囲外はゼロのままにする。
pub fn load_segments(
    bytes: &[u8],
    phdrs: &[Phdr],
    mem: &mut polyisa_mem::AddressSpace,
) -> Result<(), Error> {
    use polyisa_mem::{PAGE_SIZE, Perms, VirtAddr};
    for ph in phdrs {
        if ph.seg_type != 1 {
            continue;
        }
        if ph.memsz < ph.filesz {
            return Err(Error::Unsupported);
        }
        let end_off = ph.offset.checked_add(ph.filesz).ok_or(Error::Truncated)?;
        if bytes.len() < end_off as usize {
            return Err(Error::Truncated);
        }
        let mut perms = Perms::NONE;
        if ph.flags & 4 != 0 {
            perms = Perms(perms.0 | Perms::R.0);
        }
        if ph.flags & 2 != 0 {
            perms = Perms(perms.0 | Perms::W.0);
        }
        if ph.flags & 1 != 0 {
            perms = Perms(perms.0 | Perms::X.0);
        }
        // ロード時の書き込みのため W を足す。権限の絞り込みは後の段階で足す。
        perms = Perms(perms.0 | Perms::W.0);
        let base = ph.vaddr & !(PAGE_SIZE - 1);
        let end = ph.vaddr.checked_add(ph.memsz).ok_or(Error::Truncated)?;
        let end_aligned =
            end.checked_add(PAGE_SIZE - 1).ok_or(Error::Truncated)? & !(PAGE_SIZE - 1);
        let count = (end_aligned - base) / PAGE_SIZE;
        if count == 0 {
            continue;
        }
        mem.map(VirtAddr(base), count, perms)
            .map_err(|_| Error::Truncated)?;
        if ph.filesz > 0 {
            let src = &bytes[ph.offset as usize..end_off as usize];
            mem.write(VirtAddr(ph.vaddr), src)
                .map_err(|_| Error::Truncated)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 最小の ELF64（ヘッダ＋LOAD 1 件）を手で組み立てる。
    fn minimal() -> Vec<u8> {
        let mut v = vec![0u8; 64 + 56];
        v[0..4].copy_from_slice(&MAGIC);
        v[4] = CLASS_64;
        v[5] = DATA_LE;
        v[6] = 1; // EI_VERSION
        // e_type = ET_EXEC (2)
        v[16..18].copy_from_slice(&2u16.to_le_bytes());
        // e_entry = 0x10000
        v[24..32].copy_from_slice(&0x1_0000u64.to_le_bytes());
        // e_phoff = 64
        v[32..40].copy_from_slice(&64u64.to_le_bytes());
        // e_ehsize = 64, e_phentsize = 56, e_phnum = 1
        v[52..54].copy_from_slice(&64u16.to_le_bytes());
        v[54..56].copy_from_slice(&56u16.to_le_bytes());
        v[56..58].copy_from_slice(&1u16.to_le_bytes());
        let p = 64;
        // p_type = PT_LOAD (1), p_flags = R|X (5)
        v[p..p + 4].copy_from_slice(&1u32.to_le_bytes());
        v[p + 4..p + 8].copy_from_slice(&5u32.to_le_bytes());
        // p_offset = 0, p_vaddr = 0x10000
        v[p + 16..p + 24].copy_from_slice(&0x1_0000u64.to_le_bytes());
        // p_filesz = p_memsz = 0x1000, p_align = 0x1000
        v[p + 32..p + 40].copy_from_slice(&0x1000u64.to_le_bytes());
        v[p + 40..p + 48].copy_from_slice(&0x1000u64.to_le_bytes());
        v[p + 48..p + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        v
    }

    #[test]
    fn header_and_phdr() {
        let bytes = minimal();
        let ehdr = parse_ehdr(&bytes).unwrap();
        assert_eq!(ehdr.entry, 0x1_0000);
        assert_eq!(ehdr.phnum, 1);
        let phdrs = parse_phdrs(&bytes, &ehdr).unwrap();
        assert_eq!(phdrs.len(), 1);
        assert_eq!(phdrs[0].seg_type, 1);
        assert_eq!(phdrs[0].vaddr, 0x1_0000);
        assert_eq!(phdrs[0].flags, 5);
    }

    /// 最小の ELF32（ヘッダ＋LOAD 1 件）を手で組み立てる。
    fn minimal32() -> Vec<u8> {
        let mut v = vec![0u8; 52 + 32];
        v[0..4].copy_from_slice(&MAGIC);
        v[4] = CLASS_32;
        v[5] = DATA_LE;
        v[6] = 1; // EI_VERSION
        // e_type = ET_EXEC (2)
        v[16..18].copy_from_slice(&2u16.to_le_bytes());
        // e_entry = 0x80000000
        v[24..28].copy_from_slice(&0x8000_0000u32.to_le_bytes());
        // e_phoff = 52
        v[28..32].copy_from_slice(&52u32.to_le_bytes());
        // e_ehsize = 52, e_phentsize = 32, e_phnum = 1
        v[40..42].copy_from_slice(&52u16.to_le_bytes());
        v[42..44].copy_from_slice(&32u16.to_le_bytes());
        v[44..46].copy_from_slice(&1u16.to_le_bytes());
        // e_flags = 0
        v[36..40].copy_from_slice(&0u32.to_le_bytes());
        let p = 52;
        // p_type = PT_LOAD (1)
        v[p..p + 4].copy_from_slice(&1u32.to_le_bytes());
        // p_offset = 0, p_vaddr = 0x80000000
        v[p + 4..p + 8].copy_from_slice(&0u32.to_le_bytes());
        v[p + 8..p + 12].copy_from_slice(&0x8000_0000u32.to_le_bytes());
        // p_filesz = p_memsz = 0x1000
        v[p + 16..p + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        v[p + 20..p + 24].copy_from_slice(&0x1000u32.to_le_bytes());
        // p_flags = R|X (5)
        v[p + 24..p + 28].copy_from_slice(&5u32.to_le_bytes());
        v
    }

    #[test]
    fn header32_and_phdr32() {
        let bytes = minimal32();
        let ehdr = parse_ehdr32(&bytes).unwrap();
        assert_eq!(ehdr.entry, 0x8000_0000);
        assert_eq!(ehdr.phnum, 1);
        let phdrs = parse_phdrs32(&bytes, &ehdr).unwrap();
        assert_eq!(phdrs.len(), 1);
        assert_eq!(phdrs[0].seg_type, 1);
        assert_eq!(phdrs[0].vaddr, 0x8000_0000);
        assert_eq!(phdrs[0].flags, 5);
        assert_eq!(phdrs[0].memsz, 0x1000);
    }

    #[test]
    fn rejects() {
        assert_eq!(parse_ehdr(&[]), Err(Error::Truncated));
        let mut bad = minimal();
        bad[0] = 0;
        assert_eq!(parse_ehdr(&bad), Err(Error::BadMagic));
        let mut be = minimal();
        be[5] = 2; // EI_DATA = big endian
        assert_eq!(parse_ehdr(&be), Err(Error::Unsupported));
        let mut cut = minimal();
        cut.truncate(100);
        let ehdr = parse_ehdr(&cut).unwrap();
        assert_eq!(parse_phdrs(&cut, &ehdr), Err(Error::Truncated));
        // ヘッダや項目の大きさが想定と違えば受け付けない。
        let mut esz = minimal();
        esz[52..54].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(parse_ehdr(&esz), Err(Error::Unsupported));
        let mut psz = minimal();
        psz[54..56].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(parse_ehdr(&psz), Err(Error::Unsupported));
        let mut esz32 = minimal32();
        esz32[40..42].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(parse_ehdr32(&esz32), Err(Error::Unsupported));
        let mut psz32 = minimal32();
        psz32[42..44].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(parse_ehdr32(&psz32), Err(Error::Unsupported));
    }

    #[test]
    fn interp_path_or_none() {
        let bytes = minimal();
        let ehdr = parse_ehdr(&bytes).unwrap();
        let phdrs = parse_phdrs(&bytes, &ehdr).unwrap();
        assert_eq!(parse_interp(&bytes, &phdrs), None);
        let path = b"/lib/ld-linux-riscv64-lp64d.so.1\0";
        let ph = Phdr {
            seg_type: 3,
            offset: 0,
            vaddr: 0,
            filesz: path.len() as u64,
            memsz: path.len() as u64,
            flags: 4,
            align: 1,
        };
        assert_eq!(
            parse_interp(path, &[ph]),
            Some("/lib/ld-linux-riscv64-lp64d.so.1".to_string())
        );
    }

    #[test]
    fn probe_kind_unknown_for_empty() {
        // 空の入力は ELF ではない。
        assert_eq!(
            super::super::probe_kind(&[]),
            super::super::FileKind::Unknown
        );
    }

    #[test]
    fn load_maps_and_copies() {
        use polyisa_mem::{Access, AccessKind, Align, Endian, VirtAddr};
        let mut bytes = minimal();
        bytes.resize(0x200, 0);
        // ファイル先頭に目印を置き、LOAD の写像先から読めることを確かめる。
        bytes[0x100] = 0xAB;
        bytes[0x101] = 0xCD;
        let ehdr = parse_ehdr(&bytes).unwrap();
        let mut phdrs = parse_phdrs(&bytes, &ehdr).unwrap();
        // テスト用にファイル範囲を先頭 0x200 バイト、配置先は 0x10000 とする。
        phdrs[0].offset = 0;
        phdrs[0].filesz = 0x200;
        phdrs[0].memsz = 0x1000;
        let mut mem = polyisa_mem::AddressSpace::new();
        load_segments(&bytes, &phdrs, &mut mem).unwrap();
        let mut buf = [0u8; 2];
        let acc = Access {
            endian: Endian::Le,
            align: Align::Natural,
            kind: AccessKind::DataRead,
        };
        mem.read(VirtAddr(0x1_0100), &mut buf, acc).unwrap();
        assert_eq!(buf, [0xAB, 0xCD]);
        // BSS 部分はゼロである。
        let mut z = [0xFFu8; 4];
        mem.read(VirtAddr(0x1_0800), &mut z, acc).unwrap();
        assert_eq!(z, [0; 4]);
    }
}
