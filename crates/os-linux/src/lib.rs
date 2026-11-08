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
            _ => None,
        },
        GuestAbi::Unknown => None,
    }
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
        assert_eq!(syscall_name(GuestAbi::Rv64Linux, 9999), None);
        assert_eq!(syscall_name(GuestAbi::Unknown, 64), None);
    }
}
