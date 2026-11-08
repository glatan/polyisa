//! Linux パーソナリティ。仮想カーネルの上で Linux の規約を実装する.
//!
//! 番号表は Linux カーネルの UAPI 由来の事実を自前表現で書く。
//! 条文・コードの複製はしない.

// Ref: SRC-LINUX (7.3).

#![forbid(unsafe_code)]

/// 対応するゲスト ABI の名前。段階1は RV64 のみ。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GuestAbi {
    Unknown,
    Rv64Linux,
}

/// 段階1で使うシステムコール番号（RISC-V・asm-generic）。
/// 値はカーネルの UAPI 表由来の事実である。
pub mod rv64 {
    pub const READ: u64 = 63;
    pub const WRITE: u64 = 64;
    pub const CLOSE: u64 = 57;
    pub const MMAP: u64 = 222;
    pub const MPROTECT: u64 = 226;
    pub const MUNMAP: u64 = 215;
    pub const BRK: u64 = 214;
    pub const EXIT: u64 = 93;
    pub const EXIT_GROUP: u64 = 94;
    pub const UNAME: u64 = 160;
    pub const SET_TID_ADDRESS: u64 = 96;
    pub const CLOCK_GETTIME: u64 = 113;
    pub const GETRANDOM: u64 = 278;
    pub const OPENAT: u64 = 56;
    // 段階2（ファイル操作・動的リンク）。
    pub const LSEEK: u64 = 62;
    pub const GETDENTS64: u64 = 61;
    pub const GETCWD: u64 = 17;
    pub const DUP3: u64 = 24;
    pub const FCNTL: u64 = 25;
    pub const IOCTL: u64 = 29;
    pub const PREAD64: u64 = 67;
    pub const READLINKAT: u64 = 78;
    pub const NEWFSTATAT: u64 = 79;
    pub const FSTAT: u64 = 80;
    pub const STATX: u64 = 291;
}

/// ABI と番号から名前を引く。段階1の範囲のみ。
#[must_use]
pub fn syscall_name(abi: GuestAbi, nr: u64) -> Option<&'static str> {
    match abi {
        GuestAbi::Rv64Linux => match nr {
            rv64::READ => Some("read"),
            rv64::WRITE => Some("write"),
            rv64::CLOSE => Some("close"),
            rv64::MMAP => Some("mmap"),
            rv64::MPROTECT => Some("mprotect"),
            rv64::MUNMAP => Some("munmap"),
            rv64::BRK => Some("brk"),
            rv64::EXIT => Some("exit"),
            rv64::EXIT_GROUP => Some("exit_group"),
            rv64::UNAME => Some("uname"),
            rv64::SET_TID_ADDRESS => Some("set_tid_address"),
            rv64::CLOCK_GETTIME => Some("clock_gettime"),
            rv64::GETRANDOM => Some("getrandom"),
            rv64::OPENAT => Some("openat"),
            rv64::LSEEK => Some("lseek"),
            rv64::GETDENTS64 => Some("getdents64"),
            rv64::GETCWD => Some("getcwd"),
            rv64::DUP3 => Some("dup3"),
            rv64::FCNTL => Some("fcntl"),
            rv64::IOCTL => Some("ioctl"),
            rv64::PREAD64 => Some("pread64"),
            rv64::READLINKAT => Some("readlinkat"),
            rv64::NEWFSTATAT => Some("newfstatat"),
            rv64::FSTAT => Some("fstat"),
            rv64::STATX => Some("statx"),
            _ => None,
        },
        GuestAbi::Unknown => None,
    }
}

/// 初期スタックの写像を作る。`top` はスタック上端（16B整列）で、戻り値は
/// （配置するバイト列，初期SP）である。引数・環境はNUL終端文字列として置く。
/// 配置の規約は psABI と Linux の慣行に従う.
// Ref: SPEC-RISCV-PSABI (v1.0).
#[must_use]
pub fn build_initial_stack(
    top: u64,
    args: &[Vec<u8>],
    env: &[Vec<u8>],
    auxv: &[(u64, u64)],
) -> (Vec<u8>, u64) {
    fn w64(out: &mut [u8], off: usize, v: u64) {
        out[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }
    let strings_len: usize = args.iter().map(|a| a.len() + 1).sum::<usize>()
        + env.iter().map(|e| e.len() + 1).sum::<usize>();
    let arrays_len: usize = 8 * (1 + (args.len() + 1) + (env.len() + 1)) + 16 * (auxv.len() + 1);
    let total = arrays_len + strings_len;
    let aligned = total.next_multiple_of(16);
    let sp = top - aligned as u64;
    let mut img = vec![0u8; aligned];
    let str_base = sp + (aligned - strings_len) as u64;
    // 文字列を詰める。
    let mut pos = 0usize;
    let mut addrs = Vec::new();
    for s in args.iter().chain(env.iter()) {
        let addr = str_base + pos as u64;
        img[aligned - strings_len + pos..aligned - strings_len + pos + s.len()].copy_from_slice(s);
        pos += s.len() + 1; // NUL は vec 初期値の 0 のまま.
        addrs.push(addr);
    }
    // 配列部。
    let mut off = 0usize;
    w64(&mut img, off, args.len() as u64);
    off += 8;
    for addr in addrs.iter().take(args.len()) {
        w64(&mut img, off, *addr);
        off += 8;
    }
    off += 8; // argv NULL.
    for i in 0..env.len() {
        w64(&mut img, off, addrs[args.len() + i]);
        off += 8;
    }
    off += 8; // envp NULL.
    for (k, v) in auxv {
        w64(&mut img, off, *k);
        w64(&mut img, off + 8, *v);
        off += 16;
    }
    // AT_NULL 終端。img はゼロ初期化済みなので off を進めるだけ.
    off += 16;
    debug_assert_eq!(off, arrays_len);
    let _ = pos;
    (img, sp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rv64_stage1_numbers() {
        // 代表的な番号が asm-generic と一致する。
        assert_eq!(rv64::WRITE, 64);
        assert_eq!(rv64::EXIT_GROUP, 94);
        assert_eq!(rv64::MMAP, 222);
        assert_eq!(rv64::BRK, 214);
        assert_eq!(syscall_name(GuestAbi::Rv64Linux, 64), Some("write"));
        assert_eq!(syscall_name(GuestAbi::Rv64Linux, 291), Some("statx"));
        assert_eq!(syscall_name(GuestAbi::Rv64Linux, 61), Some("getdents64"));
        assert_eq!(syscall_name(GuestAbi::Rv64Linux, 9999), None);
    }

    #[test]
    fn initial_stack_layout() {
        let top = 0x7fff_0000u64;
        let args = [b"prog".to_vec(), b"hi".to_vec()];
        let env: [Vec<u8>; 0] = [];
        let (img, sp) = build_initial_stack(top, &args, &env, &[(6, 0x1000)]);
        assert_eq!(sp % 16, 0);
        let r64 = |off: usize| u64::from_le_bytes(img[off..off + 8].try_into().unwrap());
        assert_eq!(r64(0), 2);
        let a0 = r64(8);
        let a1 = r64(16);
        assert_eq!(r64(24), 0);
        assert_eq!(r64(32), 0);
        // auxv.
        assert_eq!(r64(40), 6);
        assert_eq!(r64(48), 0x1000);
        assert_eq!(r64(56), 0);
        assert_eq!(r64(64), 0);
        // 文字列の解決。
        let at = |addr: u64| (addr - sp) as usize;
        assert_eq!(&img[at(a0)..at(a0) + 4], b"prog");
        assert_eq!(&img[at(a1)..at(a1) + 2], b"hi");
        assert_eq!(syscall_name(GuestAbi::Unknown, 64), None);
    }
}
