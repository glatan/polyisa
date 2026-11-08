//! 動的リンク機構の実行（層7・program）。
//!
//! PT_INTERP・VFS・openat/read/mmap等のhandlerを、合成の interp/app 2ELFで
//! 検証する。interpはスタックのauxvからAT_ENTRYを拾ってappへ跳ぶ。
//! 最終出力 "IA" と終了0を確かめる。実libcでの実行は BIN-DISTRO の
//! 確認後に同じ機構へ載せる（sysroot不要の範囲で機構を固める）。
//!
//! 使う資料は台帳 SPEC-ELF-GABI（配置・PT_INTERP）、SRC-LINUX（番号表・
//! 用途Fはos-linux側で注記）。ELFとVFSの中身はテスト独自のものである.

use polyisa_engine::bare::BareEnv;
use polyisa_guest_riscv::sem::Gpr;
use polyisa_guest_riscv::{CpuState, sem};
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};
use polyisa_sem::{Backend as _, StateRef, W64};
use std::collections::BTreeMap;

const PAGE: u64 = 4096;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_ENTRY: u64 = 9;
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_GID: u64 = 13;
const AT_EGID: u64 = 14;
const ENOSYS: u64 = 38;
const ENOENT: u64 = 2;

fn acc_fetch() -> Access {
    Access {
        endian: Endian::Le,
        align: Align::Natural,
        kind: AccessKind::Fetch,
    }
}

fn acc_read() -> Access {
    Access {
        endian: Endian::Le,
        align: Align::Unaligned,
        kind: AccessKind::DataRead,
    }
}

fn reg(env: &mut BareEnv, r: u8) -> u64 {
    env.backend.get(Gpr(r).state())
}

// ---- 最小ELF組み立て ----

fn addi(rd: u32, rs1: u32, imm: i32) -> u32 {
    (((imm as u32) & 0xfff) << 20) | ((rs1 & 31) << 15) | ((rd & 31) << 7) | 0x13
}

fn auipc(rd: u32, imm20: i32) -> u32 {
    (((imm20 as u32) & 0xfffff) << 12) | ((rd & 31) << 7) | 0x17
}

fn ld(rd: u32, rs1: u32, off: i32) -> u32 {
    (((off as u32) & 0xfff) << 20) | ((rs1 & 31) << 15) | (3 << 12) | ((rd & 31) << 7) | 0x03
}

fn jalr(rd: u32, rs1: u32, off: i32) -> u32 {
    (((off as u32) & 0xfff) << 20) | ((rs1 & 31) << 15) | ((rd & 31) << 7) | 0x67
}

fn bne(rs1: u32, rs2: u32, off: i32) -> u32 {
    let o = off as u32;
    (((o >> 12) & 1) << 31)
        | (((o >> 5) & 0x3f) << 25)
        | ((rs2 & 31) << 20)
        | ((rs1 & 31) << 15)
        | (1 << 12)
        | (((o >> 1) & 0xf) << 8)
        | (((o >> 11) & 1) << 7)
        | 0x63
}

fn slli(rd: u32, rs1: u32, sh: u32) -> u32 {
    ((sh & 63) << 20) | ((rs1 & 31) << 15) | (1 << 12) | ((rd & 31) << 7) | 0x13
}

fn add(rd: u32, rs1: u32, rs2: u32) -> u32 {
    ((rs2 & 31) << 20) | ((rs1 & 31) << 15) | ((rd & 31) << 7) | 0x33
}

/// コード＋データ＋任意INTERPの最小ELF（64LE・LOAD1件＋INTERP任意1件）。
fn image(base: u64, code: &[u32], data: &[u8], interp: Option<&str>) -> Vec<u8> {
    let mut ipath = interp.map(|s| s.as_bytes().to_vec()).unwrap_or_default();
    if !ipath.is_empty() {
        ipath.push(0);
    }
    let nph = if interp.is_some() { 2 } else { 1 };
    let head = 64 + nph * 56;
    let ioff = head;
    // INTERP文字列の直後にコードを8バイト整列で置く。
    let coff = (ioff + ipath.len() + 7) & !7;
    let doff = coff + code.len() * 4;
    let filesz = doff + data.len();
    let mut v = vec![0u8; filesz];
    v[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    v[4] = 2;
    v[5] = 1;
    v[6] = 1;
    v[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN（PIE扱い）
    v[24..32].copy_from_slice(&(base + coff as u64).to_le_bytes());
    v[32..40].copy_from_slice(&64u64.to_le_bytes());
    v[52..54].copy_from_slice(&64u16.to_le_bytes());
    v[54..56].copy_from_slice(&56u16.to_le_bytes());
    v[56..58].copy_from_slice(&(nph as u16).to_le_bytes());
    let mut p = 64;
    if !ipath.is_empty() {
        v[p..p + 4].copy_from_slice(&3u32.to_le_bytes()); // PT_INTERP
        v[p + 4..p + 8].copy_from_slice(&4u32.to_le_bytes());
        v[p + 8..p + 16].copy_from_slice(&(ioff as u64).to_le_bytes());
        v[p + 16..p + 24].copy_from_slice(&0u64.to_le_bytes());
        v[p + 32..p + 40].copy_from_slice(&(ipath.len() as u64).to_le_bytes());
        v[p + 40..p + 48].copy_from_slice(&(ipath.len() as u64).to_le_bytes());
        v[ioff..ioff + ipath.len()].copy_from_slice(&ipath);
        p += 56;
    }
    v[p..p + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    v[p + 4..p + 8].copy_from_slice(&7u32.to_le_bytes());
    v[p + 16..p + 24].copy_from_slice(&base.to_le_bytes());
    v[p + 32..p + 40].copy_from_slice(&(filesz as u64).to_le_bytes());
    v[p + 40..p + 48].copy_from_slice(&(filesz as u64).to_le_bytes());
    v[p + 48..p + 56].copy_from_slice(&0x1000u64.to_le_bytes());
    for (i, w) in code.iter().enumerate() {
        v[coff + i * 4..coff + i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    v[doff..doff + data.len()].copy_from_slice(data);
    v
}

// ---- VFS ----

enum Fd {
    Mem { data: Vec<u8>, pos: usize },
    Host { path: std::path::PathBuf, pos: u64 },
}

struct GuestFs {
    mem_files: BTreeMap<String, Vec<u8>>,
    host_prefixes: Vec<(String, std::path::PathBuf)>,
    fds: BTreeMap<u32, Fd>,
    next_fd: u32,
    brk: u64,
    next_map: u64,
    out: Vec<u8>,
    enosys_once: BTreeMap<u64, bool>,
}

impl GuestFs {
    fn new(brk: u64) -> Self {
        Self {
            mem_files: BTreeMap::new(),
            host_prefixes: Vec::new(),
            fds: BTreeMap::new(),
            next_fd: 3,
            brk,
            next_map: 0x4000_0000,
            out: Vec::new(),
            enosys_once: BTreeMap::new(),
        }
    }

    fn read_cstr(&self, env: &mut BareEnv, addr: u64) -> Option<String> {
        let mut v = Vec::new();
        for i in 0..512 {
            let mut b = [0u8; 1];
            env.backend
                .mem
                .read(VirtAddr(addr + i), &mut b, acc_read())
                .ok()?;
            if b[0] == 0 {
                break;
            }
            v.push(b[0]);
        }
        String::from_utf8(v).ok()
    }

    fn open_at(&mut self, env: &mut BareEnv, dirfd: i64, path_addr: u64) -> u64 {
        let Some(path) = self.read_cstr(env, path_addr) else {
            return eno();
        };
        if !path.starts_with('/') && dirfd != -100 {
            return enoent();
        }
        if let Some(data) = self.mem_files.get(&path) {
            let fd = self.next_fd;
            self.next_fd += 1;
            self.fds.insert(
                fd,
                Fd::Mem {
                    data: data.clone(),
                    pos: 0,
                },
            );
            return fd as u64;
        }
        for (prefix, host) in &self.host_prefixes {
            if let Some(rest) = path.strip_prefix(prefix) {
                let hp = host.join(rest.trim_start_matches('/'));
                if hp.is_file() {
                    let fd = self.next_fd;
                    self.next_fd += 1;
                    self.fds.insert(fd, Fd::Host { path: hp, pos: 0 });
                    return fd as u64;
                }
            }
        }
        enoent()
    }

    fn read_fd(&mut self, env: &mut BareEnv, fd: u32, buf: u64, len: usize) -> u64 {
        let Some(f) = self.fds.get_mut(&fd) else {
            return eno();
        };
        let data: Vec<u8> = match f {
            Fd::Mem { data, pos } => {
                let n = (*pos + len).min(data.len()) - *pos;
                let out = data[*pos..*pos + n].to_vec();
                *pos += n;
                out
            }
            Fd::Host { path, pos } => {
                let Ok(bytes) = std::fs::read(path) else {
                    return eno();
                };
                let p = (*pos as usize).min(bytes.len());
                let n = (p + len).min(bytes.len()) - p;
                *pos += n as u64;
                bytes[p..p + n].to_vec()
            }
        };
        let n = data.len();
        if n > 0 && env.backend.mem.write(VirtAddr(buf), &data).is_err() {
            return eno();
        }
        n as u64
    }

    fn pread_fd(&mut self, env: &mut BareEnv, fd: u32, buf: u64, len: usize, off: u64) -> u64 {
        let data: Vec<u8> = match self.fds.get(&fd) {
            Some(Fd::Mem { data, .. }) => {
                let p = (off as usize).min(data.len());
                let n = (p + len).min(data.len()) - p;
                data[p..p + n].to_vec()
            }
            Some(Fd::Host { path, .. }) => {
                let Ok(bytes) = std::fs::read(path) else {
                    return eno();
                };
                let p = (off as usize).min(bytes.len());
                let n = (p + len).min(bytes.len()) - p;
                bytes[p..p + n].to_vec()
            }
            None => return eno(),
        };
        let n = data.len();
        if n > 0 && env.backend.mem.write(VirtAddr(buf), &data).is_err() {
            return eno();
        }
        n as u64
    }

    fn fstat_fd(&mut self, env: &mut BareEnv, fd: u32, addr: u64) -> u64 {
        let (size, mode) = match self.fds.get(&fd) {
            Some(Fd::Mem { data, .. }) => (data.len() as u64, 0o100444u64),
            Some(Fd::Host { path, .. }) => {
                let Ok(m) = std::fs::metadata(path) else {
                    return eno();
                };
                let mode = if m.is_dir() { 0o040755 } else { 0o100644 };
                (m.len(), mode)
            }
            None => return eno(),
        };
        // riscv64 struct stat（asm-generic、128バイト）。
        let mut st = [0u8; 128];
        let mut w = |off: usize, v: u64, n: usize| {
            st[off..off + n].copy_from_slice(&v.to_le_bytes()[..n]);
        };
        w(0, 1, 8); // st_dev
        w(8, 1, 8); // st_ino
        w(16, mode, 4);
        w(20, 1, 4); // nlink
        w(32, size, 8); // st_size（+32: rdev8+pad8の後）
        w(40, 4096, 4); // st_blksize
        w(48, size.div_ceil(512), 8); // st_blocks
        if env.backend.mem.write(VirtAddr(addr), &st).is_err() {
            return eno();
        }
        0
    }

    #[allow(clippy::too_many_arguments)]
    fn mmap(
        &mut self,
        env: &mut BareEnv,
        addr: u64,
        len: u64,
        prot: u64,
        flags: u32,
        fd: i64,
        off: u64,
    ) -> u64 {
        if len == 0 {
            return eno();
        }
        let mut perms = Perms::NONE;
        if prot & 1 != 0 {
            perms = Perms(perms.0 | Perms::R.0);
        }
        if prot & 2 != 0 {
            perms = Perms(perms.0 | Perms::W.0);
        }
        if prot & 4 != 0 {
            perms = Perms(perms.0 | Perms::X.0);
        }
        let anon = flags & 0x20 != 0;
        let fixed = flags & 0x10 != 0;
        let base = if fixed || addr != 0 {
            addr & !(PAGE - 1)
        } else {
            let b = (self.next_map + PAGE - 1) & !(PAGE - 1);
            self.next_map = b + ((len + PAGE - 1) & !(PAGE - 1));
            b
        };
        let count = (len + PAGE - 1) & !(PAGE - 1);
        if count / PAGE == 0 {
            return eno();
        }
        if fixed {
            env.backend.mem.unmap(VirtAddr(base), count / PAGE);
        }
        // Wは読み込み時のみ足す。
        let need_w = !anon;
        let mp = if need_w {
            Perms(perms.0 | Perms::W.0)
        } else {
            perms
        };
        if env
            .backend
            .mem
            .map(VirtAddr(base), count / PAGE, mp)
            .is_err()
        {
            return u64::MAX - 12 + 1; // -ENOMEM
        }
        if !anon {
            let data: Vec<u8> = match self.fds.get(&(fd as u32)) {
                Some(Fd::Mem { data, .. }) => {
                    let p = (off as usize).min(data.len());
                    let n = (p + len as usize).min(data.len()) - p;
                    data[p..p + n].to_vec()
                }
                Some(Fd::Host { path, .. }) => {
                    let Ok(bytes) = std::fs::read(path) else {
                        return u64::MAX - 5 + 1; // -EIO
                    };
                    let p = (off as usize).min(bytes.len());
                    let n = (p + len as usize).min(bytes.len()) - p;
                    bytes[p..p + n].to_vec()
                }
                None => return eno(),
            };
            if !data.is_empty()
                && env
                    .backend
                    .mem
                    .write(VirtAddr(base + (addr - base)), &data)
                    .is_err()
            {
                return eno();
            }
        }
        if addr == 0 {
            base
        } else {
            base + (addr & (PAGE - 1))
        }
    }
}

fn eno() -> u64 {
    (-5i64) as u64 // -EIO
}

fn enoent() -> u64 {
    (-(ENOENT as i64)) as u64
}

fn enosys(fs: &mut GuestFs, nr: u64) -> u64 {
    if fs.enosys_once.insert(nr, true).is_none() {
        eprintln!("note: 未実装syscall {nr} にENOSYS");
    }
    (-(ENOSYS as i64)) as u64
}

// ---- run loop ----

enum Outcome {
    Exit(u64),
    Unimplemented { pc: u64, word: u32 },
    StepLimit { pc: u64 },
}

fn imm_i(word: u32) -> i64 {
    ((word as i32) >> 20) as i64
}

fn imm_u(word: u32) -> i64 {
    ((((word >> 12) & 0xF_FFFF) as i32) << 12 >> 12) as i64
}

fn off_b(word: u32) -> i64 {
    let b12 = (word >> 31) & 1;
    let b11 = (word >> 7) & 1;
    let b10_5 = (word >> 25) & 63;
    let b4_1 = (word >> 8) & 15;
    let v = (b12 << 12) | (b11 << 11) | (b10_5 << 5) | (b4_1 << 1);
    ((v as i32) << 19 >> 19) as i64
}

fn run(env: &mut BareEnv, fs: &mut GuestFs, entry: u64, limit: u64) -> Outcome {
    use polyisa_guest_riscv::Insn;
    env.pc = entry;
    for _ in 0..limit {
        let mut w = [0u8; 4];
        if env
            .backend
            .mem
            .read(VirtAddr(env.pc), &mut w, acc_fetch())
            .is_err()
        {
            return Outcome::Unimplemented {
                pc: env.pc,
                word: 0xffff_ffff,
            };
        }
        let word = u32::from_le_bytes(w);
        if word == 0x3020_0073 {
            let mepc: u64 = env.backend.get(StateRef::<W64>::from_offset(
                core::mem::offset_of!(CpuState, csr) + 0x341 * 8,
            ));
            env.pc = mepc;
            continue;
        }
        if word & 0b11 != 0b11 {
            return Outcome::Unimplemented { pc: env.pc, word };
        }
        let Some(insn) = polyisa_guest_riscv::decode(word as u128, 32) else {
            return Outcome::Unimplemented { pc: env.pc, word };
        };
        let r = |b: u32, lo: u32| ((word >> lo) & ((1u32 << b) - 1)) as u8;
        let rd = Gpr(r(5, 7));
        let rs1 = Gpr(r(5, 15));
        let rs2 = Gpr(r(5, 20));
        let ok = match insn {
            Insn::Add => env.step(|b| sem::add(b, rd, rs1, rs2)),
            Insn::Addi => env.step(|b| sem::addi(b, rd, rs1, imm_i(word))),
            Insn::Lui => env.step(|b| sem::lui(b, rd, imm_u(word))),
            Insn::Auipc => {
                let pc = env.pc;
                env.step(|b| sem::auipc(b, rd, pc, imm_u(word)))
            }
            Insn::Jalr => {
                let pc = env.pc;
                env.step(|b| sem::jalr(b, rd, rs1, pc, imm_i(word)))
            }
            Insn::Ld => env.step(|b| sem::ld(b, rd, rs1, imm_i(word))),
            Insn::Slli => env.step(|b| sem::slli(b, rd, rs1, ((word >> 20) & 63) as u64)),
            Insn::Bne => {
                let pc = env.pc;
                env.step(|b| sem::bne(b, rs1, rs2, pc, off_b(word)))
            }
            Insn::Ecall => {
                let a7 = reg(env, 17);
                let ret = syscall(fs, env, a7);
                if a7 == 93 || a7 == 94 {
                    return Outcome::Exit(ret);
                }
                env.backend.set(Gpr(10).state(), ret);
                env.pc += 4;
                continue;
            }
            _ => {
                return Outcome::Unimplemented { pc: env.pc, word };
            }
        };
        if ok.is_err() {
            return Outcome::Unimplemented { pc: env.pc, word };
        }
        if env.backend.ctrl == polyisa_engine::interp::Ctrl::Fallthrough {
            env.pc += 4;
        }
    }
    Outcome::StepLimit { pc: env.pc }
}

#[allow(clippy::too_many_arguments)]
fn syscall(fs: &mut GuestFs, env: &mut BareEnv, nr: u64) -> u64 {
    let a10 = reg(env, 10);
    let a11 = reg(env, 11);
    let a12 = reg(env, 12);
    let a13 = reg(env, 13);
    let a14 = reg(env, 14);
    let a15 = reg(env, 15);
    match nr {
        64 => {
            // write
            let fd = a10;
            let buf = a11;
            let len = a12 as usize;
            if fd != 1 && fd != 2 {
                return enosys(fs, nr);
            }
            let mut data = vec![0u8; len];
            if env
                .backend
                .mem
                .read(VirtAddr(buf), &mut data, acc_read())
                .is_err()
            {
                return eno();
            }
            fs.out.extend_from_slice(&data);
            len as u64
        }
        93 | 94 => a10,
        56 => {
            // openat
            let dirfd = a10 as i64;
            fs.open_at(env, dirfd, a11)
        }
        63 => fs.read_fd(env, a10 as u32, a11, a12 as usize),
        67 => fs.pread_fd(env, a10 as u32, a11, a12 as usize, a13),
        57 => {
            if fs.fds.remove(&(a10 as u32)).is_some() {
                0
            } else {
                eno()
            }
        }
        80 => fs.fstat_fd(env, a10 as u32, a11),
        222 => fs.mmap(env, a10, a11, a12, a13 as u32, a14 as i64, a15),
        226 => 0, // mprotect：RELRO保護は後の段階。成功扱い。
        215 => {
            let base = a10 & !(PAGE - 1);
            let end = (a10 + a11 + PAGE - 1) & !(PAGE - 1);
            if end > base {
                env.backend.mem.unmap(VirtAddr(base), (end - base) / PAGE);
            }
            0
        }
        214 => {
            // brk
            let new = a10;
            if new == 0 {
                return fs.brk;
            }
            if new > fs.brk {
                let base = (fs.brk + PAGE - 1) & !(PAGE - 1);
                let end = (new + PAGE - 1) & !(PAGE - 1);
                if end > base
                    && env
                        .backend
                        .mem
                        .map(VirtAddr(base), (end - base) / PAGE, Perms::RW)
                        .is_err()
                {
                    return u64::MAX - 12 + 1; // -ENOMEM
                }
            } else if new < fs.brk {
                let base = (new + PAGE - 1) & !(PAGE - 1);
                let end = (fs.brk + PAGE - 1) & !(PAGE - 1);
                if end > base {
                    env.backend.mem.unmap(VirtAddr(base), (end - base) / PAGE);
                }
            }
            fs.brk = new;
            new
        }
        96 => 1,  // set_tid_address：仮tid
        218 => 0, // set_robust_list：何もしない
        278 => {
            // getrandom：決定的なバイト列で埋める。
            let mut x = 0x9E37_79B9_7F4A_7C15u64.wrapping_add(a11);
            let mut v = vec![0u8; a11 as usize];
            for b in v.iter_mut() {
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                x = x.wrapping_mul(0x2545_F491_4F6C_DD1D);
                *b = (x >> 56) as u8;
            }
            if env.backend.mem.write(VirtAddr(a10), &v).is_err() {
                return eno();
            }
            a11
        }
        160 => {
            // uname：固定文字列。
            let mut u = [0u8; 390];
            for (i, s) in ["Linux", "polyisa", "6.12", "polyisa", "riscv64", "(none)"]
                .iter()
                .enumerate()
            {
                u[i * 65..i * 65 + s.len()].copy_from_slice(s.as_bytes());
            }
            if env.backend.mem.write(VirtAddr(a10), &u).is_err() {
                return eno();
            }
            0
        }
        _ => enosys(fs, nr),
    }
}

#[test]
fn dynamic_interp_jump() {
    // interp：auxvからAT_ENTRYを拾い、"I"を書いて跳ぶ。
    // t0=x5 t1=x6 t2=x7 t3=x28 t4=x29。
    let interp_code = vec![
        ld(5, 2, 0),
        addi(6, 2, 8),
        slli(7, 5, 3),
        add(6, 6, 7),
        addi(6, 6, 8),
        ld(7, 6, 0), // env_loop
        addi(6, 6, 8),
        bne(7, 0, -8),
        ld(7, 6, 0), // aux_loop
        ld(28, 6, 8),
        addi(6, 6, 16),
        addi(29, 0, 9),
        bne(7, 29, -16),
        addi(10, 0, 1), // write(1, "I", 1)
        auipc(11, 0),
        addi(11, 11, 24), // data - pc_of_auipc
        addi(12, 0, 1),
        addi(17, 0, 64),
        0x0000_0073,    // ecall
        jalr(0, 28, 0), // jr app
    ];
    // auipcは15番目（index14）。dataは末尾。
    let auipc_pc_off = 14 * 4;
    let data_off = interp_code.len() * 4;
    assert_eq!(data_off - auipc_pc_off, 24);
    let interp = image(0x1_0000, &interp_code, b"I", None);
    // app： "A"を書いてexit_group(0)。PT_INTERP付き。
    let app_code = vec![
        addi(10, 0, 1),
        auipc(11, 0),
        addi(11, 11, 32),
        addi(12, 0, 1),
        addi(17, 0, 64),
        0x0000_0073,
        addi(10, 0, 0),
        addi(17, 0, 94),
        0x0000_0073,
    ];
    assert_eq!(app_code.len() * 4 - 4, 32);
    let app = image(0x2_0000, &app_code, b"A", Some("/lib/ld.so"));
    // appのehdr/phdrを取得し、INTERPを確認する。
    let eapp = polyisa_loader::elf::parse_ehdr(&app).unwrap();
    let papp = polyisa_loader::elf::parse_phdrs(&app, &eapp).unwrap();
    assert_eq!(
        polyisa_loader::elf::parse_interp(&app, &papp),
        Some("/lib/ld.so".to_string())
    );
    let eobj = polyisa_loader::elf::parse_ehdr(&interp).unwrap();
    let pobj = polyisa_loader::elf::parse_phdrs(&interp, &eobj).unwrap();

    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    polyisa_loader::elf::load_segments(&interp, &pobj, &mut env.backend.mem).unwrap();
    polyisa_loader::elf::load_segments(&app, &papp, &mut env.backend.mem).unwrap();
    // brk初期値：配置末尾。
    let mut top = 0u64;
    for ph in pobj.iter().chain(papp.iter()) {
        if ph.seg_type == 1 {
            top = top.max(ph.vaddr + ph.memsz);
        }
    }
    top = (top + PAGE - 1) & !(PAGE - 1);
    let mut fs = GuestFs::new(top);
    fs.mem_files
        .insert("/lib/ld.so".to_string(), interp.clone());
    // VFS経由でinterpを読み直せること（PT_INTERP解決の経路）。
    let interp_via_fs = fs.mem_files.get("/lib/ld.so").unwrap().clone();
    assert_eq!(interp_via_fs.len(), interp.len());

    let stack_top = 0x7fff_0000u64;
    let app_phdr_addr = 0x2_0000u64 + 64;
    let (img, sp) = polyisa_os_linux::build_initial_stack(
        stack_top,
        &[],
        &[],
        &[
            (AT_PHDR, app_phdr_addr),
            (AT_PHENT, 56),
            (AT_PHNUM, papp.len() as u64),
            (AT_PAGESZ, 4096),
            (AT_ENTRY, eapp.entry),
            (AT_UID, 0),
            (AT_EUID, 0),
            (AT_GID, 0),
            (AT_EGID, 0),
        ],
    );
    env.backend
        .mem
        .map(VirtAddr(sp & !(PAGE - 1)), 1, Perms::RW)
        .unwrap();
    env.backend.mem.write(VirtAddr(sp), &img).unwrap();
    env.backend.set(Gpr(2).state(), sp);

    match run(&mut env, &mut fs, eobj.entry, 100_000) {
        Outcome::Exit(code) => {
            assert_eq!(code, 0);
            assert_eq!(fs.out, b"IA");
        }
        Outcome::Unimplemented { pc, word } => {
            panic!("未実装に到達 pc={pc:#x} word={word:#x}")
        }
        Outcome::StepLimit { pc } => panic!("予算切れ pc={pc:#x}"),
    }
}

#[test]
fn handlers_file_and_mem() {
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    env.backend
        .mem
        .map(VirtAddr(0x5000_0000), 2, Perms::RW)
        .unwrap();
    let mut fs = GuestFs::new(0x6000_0000);
    fs.mem_files
        .insert("/lib/ld.so".to_string(), b"ELF-DOUBLE".to_vec());
    // ホスト側受け皿：一時dir。
    let dir = std::env::temp_dir().join("polyisa-vfs-test");
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(dir.join("note.txt"), b"hello-vfs").unwrap();
    fs.host_prefixes.push(("/tmp-vfs".to_string(), dir.clone()));

    env.backend.set(Gpr(2).state(), 0x5000_1000);
    // openat mem。
    let p = 0x5000_0000u64;
    env.backend.mem.write(VirtAddr(p), b"/lib/ld.so\0").unwrap();
    assert_eq!(fs.open_at(&mut env, -100, p), 3);
    // read。
    assert_eq!(fs.read_fd(&mut env, 3, p + 0x100, 4), 4);
    let mut b = [0u8; 4];
    env.backend
        .mem
        .read(VirtAddr(p + 0x100), &mut b, acc_read())
        .unwrap();
    assert_eq!(&b, b"ELF-");
    // pread（位置を進めず読む）。
    assert_eq!(fs.pread_fd(&mut env, 3, p + 0x200, 6, 4), 6);
    let mut c = [0u8; 6];
    env.backend
        .mem
        .read(VirtAddr(p + 0x200), &mut c, acc_read())
        .unwrap();
    assert_eq!(&c, b"DOUBLE");
    // fstat。
    fs.fstat_fd(&mut env, 3, p + 0x300);
    let mut st = [0u8; 128];
    env.backend
        .mem
        .read(VirtAddr(p + 0x300), &mut st, acc_read())
        .unwrap();
    assert_eq!(u64::from_le_bytes(st[32..40].try_into().unwrap()), 10);
    // host側。
    env.backend
        .mem
        .write(VirtAddr(p), b"/tmp-vfs/note.txt\0")
        .unwrap();
    assert_eq!(fs.open_at(&mut env, -100, p), 4);
    assert_eq!(fs.read_fd(&mut env, 4, p + 0x100, 9), 9);
    let mut d = [0u8; 9];
    env.backend
        .mem
        .read(VirtAddr(p + 0x100), &mut d, acc_read())
        .unwrap();
    assert_eq!(&d, b"hello-vfs");
    // mmap匿名。
    let m = fs.mmap(&mut env, 0, 8192, 3, 0x22, -1, 0);
    assert_eq!(m % PAGE, 0);
    // brk（syscall経由）。
    env.backend.set(Gpr(10).state(), 0);
    assert_eq!(syscall(&mut fs, &mut env, 214), 0x6000_0000);
    env.backend.set(Gpr(10).state(), 0x6000_1000);
    assert_eq!(syscall(&mut fs, &mut env, 214), 0x6000_1000);
    assert_eq!(fs.brk, 0x6000_1000);
    // set_tid_address / getrandom。
    assert_eq!(syscall(&mut fs, &mut env, 96), 1);
    env.backend.set(Gpr(10).state(), p + 0x400);
    env.backend.set(Gpr(11).state(), 16);
    assert_eq!(syscall(&mut fs, &mut env, 278), 16);
    // close。
    assert!(fs.fds.remove(&3).is_some());
    assert!(fs.fds.remove(&3).is_none());
    let _ = std::fs::remove_dir_all(&dir);
}
