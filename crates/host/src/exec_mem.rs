// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 実行可能メモリ。JIT が生成したコードを置く領域。
//!
//! 書き込み中は RW、公開時に RX へ変える（W^X を同時には持たない、
//! docs/design/jit.md「実行可能メモリ」）。命令キャッシュの同期は
//! ホスト命令が x86-64 の間は不要（他アーチの JIT はまだ持たない）。

/// コード置き場。`new` で確保し、`write` で機械語を置き、
/// `finalize` で実行可能にする。
pub struct ExecMem {
    ptr: *mut u8,
    len: usize,
    cap: usize,
}

impl ExecMem {
    /// `cap` バイトの書き込み可能な領域を確保する。
    /// ホストが実行可能メモリを持てないなら `None`。
    #[must_use]
    pub fn new(cap: usize) -> Option<Self> {
        let ptr = imp::map_rw(cap)?;
        if ptr.is_null() {
            return None;
        }
        Some(Self { ptr, len: 0, cap })
    }

    /// `code` を領域へ書く。`finalize` 前だけ書ける。
    pub fn write(&mut self, code: &[u8]) -> Option<()> {
        if code.len() > self.cap {
            return None;
        }
        // SAFETY: ptr は cap バイトの RW 領域で code はその内側に収まる。
        unsafe {
            core::ptr::copy_nonoverlapping(code.as_ptr(), self.ptr, code.len());
        }
        self.len = code.len();
        Some(())
    }

    /// 領域を読み取り・実行専用に変える。以後 `write` は失敗する。
    pub fn finalize(self) -> Option<FinalMem> {
        imp::make_rx(self.ptr, self.cap)?;
        imp::sync_icache(self.ptr, self.len);
        let m = FinalMem {
            ptr: self.ptr,
            len: self.len,
            cap: self.cap,
        };
        // Drop で解除しないよう所有権を FinalMem へ移す。
        core::mem::forget(self);
        Some(m)
    }
}

impl Drop for ExecMem {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            imp::unmap(self.ptr, self.cap);
        }
    }
}

/// 実行可能になった領域。`ptr` から `len` バイトが機械語。
pub struct FinalMem {
    ptr: *mut u8,
    len: usize,
    cap: usize,
}

// SAFETY: 領域は独立に確保され、内容はコードだけ。
unsafe impl Send for FinalMem {}
// SAFETY: 読み取りと実行だけが可能で、中身の書き換え経路は持たない。
unsafe impl Sync for FinalMem {}

impl FinalMem {
    /// 先頭のアドレス（エントリポイント）。
    #[must_use]
    pub fn ptr(&self) -> *const u8 {
        self.ptr.cast_const()
    }

    /// 置いたコードのバイト数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// 中身が空か。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Drop for FinalMem {
    fn drop(&mut self) {
        imp::unmap(self.ptr, self.cap);
    }
}

#[cfg(unix)]
mod imp {
    use std::ffi::c_void;

    const PROT_READ: i32 = 1;
    const PROT_WRITE: i32 = 2;
    const PROT_EXEC: i32 = 4;
    const MAP_PRIVATE: i32 = 2;
    #[cfg(target_os = "linux")]
    const MAP_ANON: i32 = 0x20;
    #[cfg(not(target_os = "linux"))]
    const MAP_ANON: i32 = 0x1000;

    unsafe extern "C" {
        // SAFETY: これらは OS の ABI に従う libc の関数。
        fn mmap(
            addr: *mut c_void,
            len: usize,
            prot: i32,
            flags: i32,
            fd: i32,
            off: i64,
        ) -> *mut c_void;
        fn mprotect(addr: *mut c_void, len: usize, prot: i32) -> i32;
        fn munmap(addr: *mut c_void, len: usize) -> i32;
    }

    /// 匿名の RW 領域を `cap` バイト確保する。
    pub fn map_rw(cap: usize) -> Option<*mut u8> {
        let cap = cap.max(1);
        // SAFETY: addr=None,fd=-1 の匿名写像。返り値は検査する。
        let p = unsafe {
            mmap(
                core::ptr::null_mut(),
                cap,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANON,
                -1,
                0,
            )
        };
        if p.is_null() || p as isize == -1 {
            None
        } else {
            Some(p.cast())
        }
    }

    /// `ptr` の `len` を R|X に変える。
    pub fn make_rx(ptr: *mut u8, len: usize) -> Option<()> {
        // SAFETY: ptr,len は map_rw が確保した範囲。
        let r = unsafe { mprotect(ptr.cast(), len, PROT_READ | PROT_EXEC) };
        if r == 0 { Some(()) } else { None }
    }

    pub fn unmap(ptr: *mut u8, len: usize) {
        // SAFETY: ptr,len は map_rw が確保した範囲。
        unsafe { munmap(ptr.cast(), len.max(1)) };
    }

    /// 命令キャッシュの同期。x86-64 ホストでは不要。
    /// 他アーチのホストに JIT を持たせるときに実装する。
    pub fn sync_icache(_ptr: *mut u8, _len: usize) {}
}

#[cfg(not(unix))]
mod imp {
    /// Unix 以外は v1 では実行可能メモリを持たない。
    pub fn map_rw(_cap: usize) -> Option<*mut u8> {
        None
    }
    pub fn make_rx(_ptr: *mut u8, _len: usize) -> Option<()> {
        None
    }
    pub fn unmap(_ptr: *mut u8, _len: usize) {}
    pub fn sync_icache(_ptr: *mut u8, _len: usize) {}
}
