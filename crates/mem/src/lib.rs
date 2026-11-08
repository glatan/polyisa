// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! ゲストメモリ。ソフトウェアページ表、ページフレーム、ソフトウェア TLB。
//!
//! 詳しくは [ゲストメモリ](../../docs/design/memory.md) を見る。

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::Arc;

/// 管理の単位。ゲストのページはこの整数倍として扱う。
pub const PAGE_SIZE: u64 = 4096;
/// ページ内オフセットのマスク。
pub const PAGE_MASK: u64 = PAGE_SIZE - 1;

/// ゲストの仮想アドレス。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct VirtAddr(pub u64);

/// ページ番号（アドレスを [`PAGE_SIZE`] で割った値）。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct PageNo(pub u64);

impl VirtAddr {
    /// ページ番号とページ内オフセットに分ける。
    #[must_use]
    pub const fn split(self) -> (PageNo, u32) {
        (PageNo(self.0 / PAGE_SIZE), (self.0 % PAGE_SIZE) as u32)
    }
}

/// バイト列の解釈。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Endian {
    Le,
    Be,
}

/// アライメントの扱い。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Align {
    /// 自然な境界を要求する。違反は例外になる。
    Natural,
    /// 要求しない。境界をまたぐ場合は両ページの許可を確かめる。
    Unaligned,
}

/// アクセスの種類。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AccessKind {
    DataRead,
    DataWrite,
    Fetch,
    AtomicRw,
    LoadReserved,
    StoreConditional,
}

/// 意味論がアクセスごとに指定する属性。デコード時に決まる。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Access {
    pub endian: Endian,
    pub align: Align,
    pub kind: AccessKind,
}

impl Access {
    pub const DATA_LE: Self = Self {
        endian: Endian::Le,
        align: Align::Natural,
        kind: AccessKind::DataRead,
    };
}

/// 読み書き実行の許可。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Perms(pub u8);

impl Perms {
    pub const NONE: Self = Self(0);
    pub const R: Self = Self(1);
    pub const W: Self = Self(2);
    pub const X: Self = Self(4);
    pub const RW: Self = Self(1 | 2);
    pub const RX: Self = Self(1 | 4);

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

/// 4 KiB のゲストのデータ。複数のアドレス空間で共有できる。
#[derive(Clone, Debug)]
pub struct PageFrame {
    data: Arc<Vec<u8>>,
    /// デコード済みのブロックを含む。書き込みは低速経路を通る。
    pub has_code: bool,
    /// 共有のファイル写像に属する。書き戻しの対象になる。
    pub shared_file: bool,
}

impl PageFrame {
    /// ゼロ埋めのフレームを作る。
    #[must_use]
    pub fn zeroed() -> Self {
        Self {
            data: Arc::new(vec![0u8; PAGE_SIZE as usize]),
            has_code: false,
            shared_file: false,
        }
    }

    /// 内容を指定して作る。長さは [`PAGE_SIZE`] とする。
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != PAGE_SIZE as usize {
            return None;
        }
        Some(Self {
            data: Arc::new(bytes.to_vec()),
            has_code: false,
            shared_file: false,
        })
    }

    /// 読み出し専用のバイト列。
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// 書き込み用に取り出す。共有されているときは複製する（COW）。
    pub fn make_mut(&mut self) -> &mut Vec<u8> {
        self.has_code = false;
        Arc::make_mut(&mut self.data)
    }

    /// 共有の参照数。COW の判定に使う。
    #[must_use]
    pub fn strong_count(&self) -> usize {
        Arc::strong_count(&self.data)
    }
}

/// ページ表の項目。
#[derive(Clone, Debug)]
struct Entry {
    frame: PageFrame,
    perms: Perms,
    cow: bool,
}

/// 疎なアドレス空間。ページ番号から項目への写像を持つ。
#[derive(Clone, Debug, Default)]
pub struct AddressSpace {
    pages: BTreeMap<PageNo, Entry>,
    /// 確保済みフレーム総量の上限。`None` は無制限。
    pub frame_limit: Option<u64>,
}

impl AddressSpace {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// ページ数を数える。
    #[must_use]
    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    /// 範囲を写像する。範囲はページ境界に整列しているとする。
    pub fn map(&mut self, base: VirtAddr, count: u64, perms: Perms) -> Result<(), MemError> {
        if !base.0.is_multiple_of(PAGE_SIZE) {
            return Err(MemError::NotAligned);
        }
        if let Some(limit) = self.frame_limit
            && (self.pages.len() as u64) + count > limit
        {
            return Err(MemError::OutOfMemory);
        }
        for i in 0..count {
            let no = PageNo(base.0 / PAGE_SIZE + i);
            self.pages.insert(
                no,
                Entry {
                    frame: PageFrame::zeroed(),
                    perms,
                    cow: false,
                },
            );
        }
        Ok(())
    }

    /// 範囲の写像を外す。
    pub fn unmap(&mut self, base: VirtAddr, count: u64) {
        for i in 0..count {
            self.pages.remove(&PageNo(base.0 / PAGE_SIZE + i));
        }
    }

    /// 写像済み範囲の許可を変える（mprotect 相当）。範囲はページ境界に
    /// 整列しているとする。未写像のページがあれば `PageFault` で失敗し、
    /// そのページより前の変更は残る。OS パーソナリティの mprotect 実装と、
    /// PMP のない M モードを模すテストハーネスが使う。
    pub fn protect(&mut self, base: VirtAddr, count: u64, perms: Perms) -> Result<(), MemError> {
        if !base.0.is_multiple_of(PAGE_SIZE) {
            return Err(MemError::NotAligned);
        }
        for i in 0..count {
            let entry = self
                .pages
                .get_mut(&PageNo(base.0 / PAGE_SIZE + i))
                .ok_or(MemError::PageFault)?;
            entry.perms = perms;
        }
        Ok(())
    }

    /// バイト列を読む。未写像や許可不足ではエラーを返す。
    pub fn read(&self, addr: VirtAddr, buf: &mut [u8], acc: Access) -> Result<(), MemError> {
        let kind_perm = match acc.kind {
            AccessKind::DataRead | AccessKind::AtomicRw | AccessKind::LoadReserved => Perms::R,
            AccessKind::Fetch => Perms::X,
            AccessKind::DataWrite | AccessKind::StoreConditional => Perms::R,
        };
        let mut off = 0;
        while off < buf.len() {
            let (no, page_off) = VirtAddr(addr.0 + off as u64).split();
            let entry = self.pages.get(&no).ok_or(MemError::PageFault)?;
            if !entry.perms.contains(kind_perm) {
                return Err(MemError::PageFault);
            }
            let n = ((PAGE_SIZE as usize) - (page_off as usize)).min(buf.len() - off);
            buf[off..off + n]
                .copy_from_slice(&entry.frame.as_slice()[page_off as usize..page_off as usize + n]);
            off += n;
        }
        Ok(())
    }

    /// バイト列を書く。COW の複製はここで行う。
    pub fn write(&mut self, addr: VirtAddr, buf: &[u8]) -> Result<(), MemError> {
        let mut off = 0;
        while off < buf.len() {
            let (no, page_off) = VirtAddr(addr.0 + off as u64).split();
            let entry = self.pages.get_mut(&no).ok_or(MemError::PageFault)?;
            if !entry.perms.contains(Perms::W) {
                return Err(MemError::PageFault);
            }
            let n = ((PAGE_SIZE as usize) - (page_off as usize)).min(buf.len() - off);
            let frame = entry.frame.make_mut();
            frame[page_off as usize..page_off as usize + n].copy_from_slice(&buf[off..off + n]);
            entry.cow = false;
            off += n;
        }
        Ok(())
    }

    /// 多バイト値を読む。`acc` のエンディアンで変換し、整列を検査する。
    pub fn read_value(
        &self,
        addr: VirtAddr,
        width_bytes: usize,
        acc: Access,
    ) -> Result<u64, MemError> {
        if width_bytes == 0 || width_bytes > 8 {
            return Err(MemError::NotAligned);
        }
        if acc.align == Align::Natural && !addr.0.is_multiple_of(width_bytes as u64) {
            return Err(MemError::NotAligned);
        }
        let mut buf = [0u8; 8];
        self.read(addr, &mut buf[..width_bytes], acc)?;
        let v = match acc.endian {
            Endian::Le => polyisa_bits::read_le(&buf[..width_bytes], width_bytes),
            Endian::Be => polyisa_bits::read_be(&buf[..width_bytes], width_bytes),
        };
        v.ok_or(MemError::PageFault)
    }

    /// 多バイト値を書く。`read_value` と対称の変換と検査を行う。
    pub fn write_value(
        &mut self,
        addr: VirtAddr,
        value: u64,
        width_bytes: usize,
        acc: Access,
    ) -> Result<(), MemError> {
        if width_bytes == 0 || width_bytes > 8 {
            return Err(MemError::NotAligned);
        }
        if acc.align == Align::Natural && !addr.0.is_multiple_of(width_bytes as u64) {
            return Err(MemError::NotAligned);
        }
        // 書き込み権限の検査は `write` が行う。ここでは変換だけして渡す。
        let mut buf = [0u8; 8];
        let ok = match acc.endian {
            Endian::Le => polyisa_bits::write_le(&mut buf[..width_bytes], value, width_bytes),
            Endian::Be => polyisa_bits::write_be(&mut buf[..width_bytes], value, width_bytes),
        };
        if !ok {
            return Err(MemError::NotAligned);
        }
        self.write(addr, &buf[..width_bytes])
    }

    /// `fork` のための複製。書き込み可のページを COW にする。
    ///
    /// 親子でページフレームの `Arc` を共有し、最初の書き込みで
    /// [`PageFrame::make_mut`] が複製する。親側の印の付け替えは不要である。
    #[must_use]
    pub fn fork(&self) -> Self {
        let mut child = Self {
            pages: BTreeMap::new(),
            frame_limit: self.frame_limit,
        };
        for (no, e) in &self.pages {
            let cow = e.perms.contains(Perms::W);
            child.pages.insert(
                *no,
                Entry {
                    frame: e.frame.clone(),
                    perms: e.perms,
                    cow,
                },
            );
        }
        // 書き込み時の複製は `PageFrame::make_mut`（`Arc::make_mut`）が行う。
        // `cow` 印は将来の低速経路の分岐のために残す。
        child
    }

    /// 指定のページにコード印を付ける。
    pub fn mark_code(&mut self, addr: VirtAddr) {
        let (no, _) = addr.split();
        if let Some(e) = self.pages.get_mut(&no) {
            e.frame.has_code = true;
        }
    }
}

/// メモリ操作の失敗。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MemError {
    PageFault,
    NotAligned,
    OutOfMemory,
}

/// vCPU ごとの変換キャッシュ。直接写像の小さな表として持つ。
#[derive(Clone, Debug)]
pub struct Tlb {
    entries: Vec<Option<TlbEntry>>,
}

#[derive(Clone, Debug)]
struct TlbEntry {
    tag: PageNo,
    frame: PageFrame,
    perms: Perms,
}

impl Tlb {
    #[must_use]
    pub fn new(size: usize) -> Self {
        Self {
            entries: vec![None; size.max(1)],
        }
    }

    /// 添字を計算する。タグの比較は呼び出し側で行う。
    #[must_use]
    pub fn index(&self, no: PageNo) -> usize {
        (no.0 as usize) % self.entries.len()
    }

    /// 項目を更新する。
    pub fn insert(&mut self, no: PageNo, frame: PageFrame, perms: Perms) {
        let i = self.index(no);
        self.entries[i] = Some(TlbEntry {
            tag: no,
            frame,
            perms,
        });
    }

    /// 項目を探す。タグが一致しなければ `None`。
    #[must_use]
    pub fn lookup(&self, no: PageNo) -> Option<(&PageFrame, Perms)> {
        let i = self.index(no);
        match &self.entries[i] {
            Some(e) if e.tag == no => Some((&e.frame, e.perms)),
            _ => None,
        }
    }

    /// すべて無効化する。写像の変更、ブロックの無効化で呼ぶ。
    pub fn invalidate_all(&mut self) {
        for e in self.entries.iter_mut() {
            *e = None;
        }
    }
}

/// 予約付きロードの予約。vCPU ごとに一つ持つ。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Reservation {
    pub addr: VirtAddr,
    pub len: u32,
    pub valid: bool,
}

impl Reservation {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            addr: VirtAddr(0),
            len: 0,
            valid: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_read_write() {
        let mut aspace = AddressSpace::new();
        aspace.map(VirtAddr(0x1000), 1, Perms::RW).unwrap();
        aspace.write(VirtAddr(0x1000), &[1, 2, 3, 4]).unwrap();
        let mut buf = [0u8; 4];
        aspace
            .read(VirtAddr(0x1000), &mut buf, Access::DATA_LE)
            .unwrap();
        assert_eq!(buf, [1, 2, 3, 4]);
    }

    #[test]
    fn unmapped_is_fault() {
        let aspace = AddressSpace::new();
        let mut buf = [0u8; 1];
        assert_eq!(
            aspace.read(VirtAddr(0x0), &mut buf, Access::DATA_LE),
            Err(MemError::PageFault)
        );
    }

    #[test]
    fn endian_values_and_align() {
        let mut aspace = AddressSpace::new();
        aspace.map(VirtAddr(0x1000), 1, Perms::RW).unwrap();
        let le = Access {
            endian: Endian::Le,
            align: Align::Natural,
            kind: AccessKind::DataRead,
        };
        aspace
            .write_value(VirtAddr(0x1000), 0x1234_5678, 4, le)
            .unwrap();
        assert_eq!(
            aspace.read_value(VirtAddr(0x1000), 4, le).unwrap(),
            0x1234_5678
        );
        let be = Access {
            endian: Endian::Be,
            ..le
        };
        aspace
            .write_value(VirtAddr(0x1000), 0x1234_5678, 4, be)
            .unwrap();
        assert_eq!(
            aspace.read_value(VirtAddr(0x1000), 4, be).unwrap(),
            0x1234_5678
        );
        // 自然整列の違反。
        assert_eq!(
            aspace.read_value(VirtAddr(0x1001), 4, le),
            Err(MemError::NotAligned)
        );
        // 非整列可なら通る。
        let un = Access {
            align: Align::Unaligned,
            ..le
        };
        assert!(aspace.read_value(VirtAddr(0x1001), 4, un).is_ok());
    }

    #[test]
    fn fork_shares_frame() {
        let mut parent = AddressSpace::new();
        parent.map(VirtAddr(0x0), 1, Perms::RW).unwrap();
        parent.write(VirtAddr(0x0), &[9]).unwrap();
        let mut child = parent.fork();
        let mut buf = [0u8; 1];
        child
            .read(VirtAddr(0x0), &mut buf, Access::DATA_LE)
            .unwrap();
        assert_eq!(buf, [9]);
        child.write(VirtAddr(0x0), &[7]).unwrap();
        child
            .read(VirtAddr(0x0), &mut buf, Access::DATA_LE)
            .unwrap();
        assert_eq!(buf, [7]);
        parent
            .read(VirtAddr(0x0), &mut buf, Access::DATA_LE)
            .unwrap();
        assert_eq!(buf, [9]);
    }

    #[test]
    fn protect_changes_perms() {
        let mut aspace = AddressSpace::new();
        aspace.map(VirtAddr(0x1000), 2, Perms::RW).unwrap();
        let fetch = Access {
            endian: Endian::Le,
            align: Align::Natural,
            kind: AccessKind::Fetch,
        };
        // X なしでは fetch が失敗する。
        let mut buf = [0u8; 1];
        assert_eq!(
            aspace.read(VirtAddr(0x1000), &mut buf, fetch),
            Err(MemError::PageFault)
        );
        // 許可を足すと通る。未写像には失敗する。
        aspace
            .protect(
                VirtAddr(0x1000),
                2,
                Perms(Perms::R.0 | Perms::W.0 | Perms::X.0),
            )
            .unwrap();
        assert!(aspace.read(VirtAddr(0x1000), &mut buf, fetch).is_ok());
        assert_eq!(
            aspace.protect(VirtAddr(0x3000), 1, Perms::R),
            Err(MemError::PageFault)
        );
        // 非整列の base は拒否する。
        assert_eq!(
            aspace.protect(VirtAddr(0x1001), 1, Perms::R),
            Err(MemError::NotAligned)
        );
    }

    #[test]
    fn tlb_insert_lookup_invalidate() {
        let mut tlb = Tlb::new(8);
        let f = PageFrame::zeroed();
        tlb.insert(PageNo(3), f, Perms::R);
        assert!(tlb.lookup(PageNo(3)).is_some());
        assert!(tlb.lookup(PageNo(4)).is_none());
        tlb.invalidate_all();
        assert!(tlb.lookup(PageNo(3)).is_none());
    }
}
