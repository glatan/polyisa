// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Gap: GAP-0030
//! QEMU user-mode との RV64 実行差分（層: diff、E3）。
//!
//! RV64I に加え、M/A/C 拡張、幅違いロード、条件分岐/JAL で作った
//! 64 ビット値を静的 ELF から stdout へ書き、同じ ELF を polyisa と
//! `qemu-riscv64` で実行して出力と終了コードを比較する。
//! qemu-riscv64 がなければスキップする。

use std::process::Command;

use polyisa_cli::run_riscv::{EcallHandler, EcallOutcome, reg, run_elf_handler};
use polyisa_engine::bare::BareEnv;
use polyisa_guest_riscv::sem::Gpr;
use polyisa_mem::{Access, AccessKind, Align, Endian, VirtAddr};
use polyisa_sem::Backend as _;

const BASE: u64 = 0x1_0000;

fn addi(rd: u32, rs1: u32, imm: i32) -> u32 {
    (((imm as u32) & 0xfff) << 20) | ((rs1 & 31) << 15) | ((rd & 31) << 7) | 0x13
}

fn lui(rd: u32, imm20: u32) -> u32 {
    (imm20 << 12) | ((rd & 31) << 7) | 0x37
}

fn rtype(funct7: u32, rs2: u32, rs1: u32, funct3: u32, rd: u32) -> u32 {
    ((funct7 & 0x7f) << 25)
        | ((rs2 & 31) << 20)
        | ((rs1 & 31) << 15)
        | ((funct3 & 7) << 12)
        | ((rd & 31) << 7)
        | 0x33
}

fn shiftimm(rd: u32, rs1: u32, shamt: u32, funct3: u32, high: u32) -> u32 {
    ((high & 0x3f) << 26)
        | ((shamt & 0x3f) << 20)
        | ((rs1 & 31) << 15)
        | ((funct3 & 7) << 12)
        | ((rd & 31) << 7)
        | 0x13
}

fn stype(imm: i32, rs2: u32, rs1: u32, funct3: u32) -> u32 {
    let i = (imm as u32) & 0xfff;
    ((i >> 5) << 25)
        | ((rs2 & 31) << 20)
        | ((rs1 & 31) << 15)
        | ((funct3 & 7) << 12)
        | ((i & 31) << 7)
        | 0x23
}

fn itype(rd: u32, rs1: u32, imm: i32, funct3: u32, opcode: u32) -> u32 {
    (((imm as u32) & 0xfff) << 20)
        | ((rs1 & 31) << 15)
        | ((funct3 & 7) << 12)
        | ((rd & 31) << 7)
        | opcode
}

fn load(rd: u32, rs1: u32, imm: i32, funct3: u32) -> u32 {
    itype(rd, rs1, imm, funct3, 0x03)
}

fn rtypew(funct7: u32, rs2: u32, rs1: u32, funct3: u32, rd: u32) -> u32 {
    ((funct7 & 0x7f) << 25)
        | ((rs2 & 31) << 20)
        | ((rs1 & 31) << 15)
        | ((funct3 & 7) << 12)
        | ((rd & 31) << 7)
        | 0x3b
}

fn branch(funct3: u32, rs1: u32, rs2: u32, imm: i32) -> u32 {
    let i = (imm as u32) & 0x1fff;
    (((i >> 12) & 1) << 31)
        | (((i >> 5) & 0x3f) << 25)
        | ((rs2 & 31) << 20)
        | ((rs1 & 31) << 15)
        | ((funct3 & 7) << 12)
        | (((i >> 1) & 0xf) << 8)
        | (((i >> 11) & 1) << 7)
        | 0x63
}

fn jal(rd: u32, imm: i32) -> u32 {
    let i = (imm as u32) & 0x1f_ffff;
    (((i >> 20) & 1) << 31)
        | (((i >> 1) & 0x3ff) << 21)
        | (((i >> 11) & 1) << 20)
        | (((i >> 12) & 0xff) << 12)
        | ((rd & 31) << 7)
        | 0x6f
}

fn amo(funct5: u32, rs2: u32, rs1: u32, rd: u32) -> u32 {
    ((funct5 & 31) << 27)
        | ((rs2 & 31) << 20)
        | ((rs1 & 31) << 15)
        | (3 << 12) // .d
        | ((rd & 31) << 7)
        | 0x2f
}

fn emit_li32(code: &mut Vec<u32>, rd: u32, x: i32) {
    // 32 ビット即値を LUI+ADDI で作る。ADDI の low 12 ビットは
    // 符号付きなので、0x800 以上なら上位側を 1 繰り上げる。
    let hi = x.wrapping_add(0x800) >> 12;
    let lo = x.wrapping_sub(hi << 12);
    code.push(lui(rd, (hi as u32) & 0xf_ffff));
    code.push(addi(rd, rd, lo));
}

fn patch_branch(code: &mut [u32], at: usize, target: usize, funct3: u32, rs1: u32, rs2: u32) {
    code[at] = branch(funct3, rs1, rs2, ((target - at) * 4) as i32);
}

fn patch_jal(code: &mut [u32], at: usize, target: usize, rd: u32) {
    code[at] = jal(rd, ((target - at) * 4) as i32);
}

fn sx32(x: u32) -> u64 {
    x as i32 as i64 as u64
}

fn expected() -> [u64; 8] {
    let mut t0 = 0x1234_5000u64;
    t0 = t0.wrapping_add(0x678);
    t0 <<= 32;
    let mut t1 = 0x7654_3000u64;
    t1 = t1.wrapping_sub(1024);
    t0 |= t1;
    t0 ^= 73;
    let left = t0 << 3;
    let right = t0 >> 5;
    t0 = left.wrapping_sub(right);
    t0 &= (-123i64) as u64;
    let q0 = t0;

    let a = -0x4000_0001i64;
    let b = 0x3000_0001i64;
    let low = a.wrapping_mul(b) as u64;
    let sh = (((a as i128) * (b as i128)) >> 64) as u64;
    let hsu = (((a as i128) * ((b as u64) as i128)) >> 64) as u64;
    let hu = ((((a as u64) as u128) * ((b as u64) as u128)) >> 64) as u64;
    let q1 = low ^ sh ^ hsu ^ hu;

    let divs = a.wrapping_div(b) as u64;
    let rems = a.wrapping_rem(b) as u64;
    let divu = (a as u64) / (b as u64);
    let remu = (a as u64) % (b as u64);
    let dz_q = u64::MAX;
    let dz_r = a as u64;
    let q2 = divs ^ rems ^ divu ^ remu ^ dz_q ^ dz_r;

    let aw = i32::MIN;
    let bw = -1i32;
    let divw = sx32(aw as u32);
    let remw = sx32(0);
    let mulw = sx32((aw as u32).wrapping_mul(bw as u32));
    let divuw = sx32((aw as u32) / (bw as u32));
    let remuw = sx32((aw as u32) % (bw as u32));
    let q3 = divw ^ remw ^ mulw ^ divuw ^ remuw;

    let w = 0x80ff_7f01u32;
    let bytes = w.to_le_bytes();
    let lb = bytes[0] as i8 as i64 as u64;
    let lbu = u64::from(bytes[2]);
    let lh = i16::from_le_bytes([bytes[2], bytes[3]]) as i64 as u64;
    let lhu = u64::from(u16::from_le_bytes([bytes[2], bytes[3]]));
    let lw = w as i32 as i64 as u64;
    let lwu = u64::from(w);
    let q4 = lb ^ lbu ^ lh ^ lhu ^ lw ^ lwu;

    let sc_success = 0u64;
    let q5 = 5u64 ^ 12u64 ^ sc_success ^ 7u64;
    let q6 = 3u64;
    let q7 = 15u64;
    [q0, q1, q2, q3, q4, q5, q6, q7]
}

/// コード列と、結果・メモリ実験用のデータを含む 1 セグメント ELF。
fn image() -> Vec<u8> {
    let auipc_index = 0usize;
    let mut code = vec![
        0x0000_0597, // auipc a1,0
        0,           // addi a1,a1,out（後で差し替え）
    ];

    // q0: RV64I の整数演算（従来の差分列）。
    code.extend([
        lui(5, 0x12345),
        addi(5, 5, 0x678),
        shiftimm(5, 5, 32, 1, 0),
        lui(6, 0x76543),
        addi(6, 6, -1024),
        rtype(0, 6, 5, 6, 5),
        addi(7, 0, 73),
        rtype(0, 7, 5, 4, 5),
        shiftimm(6, 5, 3, 1, 0),
        shiftimm(7, 5, 5, 5, 0),
        rtype(0x20, 7, 6, 0, 5),
        addi(6, 0, -123),
        rtype(0, 6, 5, 7, 5),
        stype(0, 5, 11, 3),
    ]);

    // q1: M 拡張の乗算下半分と 3 種の上半分。
    emit_li32(&mut code, 5, -0x4000_0001);
    emit_li32(&mut code, 6, 0x3000_0001);
    code.extend([
        rtype(1, 6, 5, 0, 7),
        rtype(1, 6, 5, 1, 28),
        rtype(1, 6, 5, 2, 29),
        rtype(1, 6, 5, 3, 30),
        rtype(0, 28, 7, 4, 7),
        rtype(0, 29, 7, 4, 7),
        rtype(0, 30, 7, 4, 7),
        stype(8, 7, 11, 3),
    ]);

    // q2: 符号・符号なし除算/剰余と 0 除算規則。
    code.extend([
        rtype(1, 6, 5, 4, 7),
        rtype(1, 6, 5, 6, 28),
        rtype(1, 6, 5, 5, 29),
        rtype(1, 6, 5, 7, 30),
        addi(6, 0, 0),
        rtype(1, 6, 5, 4, 31),
        rtype(1, 6, 5, 6, 8),
        rtype(0, 28, 7, 4, 7),
        rtype(0, 29, 7, 4, 7),
        rtype(0, 30, 7, 4, 7),
        rtype(0, 31, 7, 4, 7),
        rtype(0, 8, 7, 4, 7),
        stype(16, 7, 11, 3),
    ]);

    // q3: RV64M の word 形。INT32_MIN / -1 と 32 ビット符号拡張を見る。
    emit_li32(&mut code, 5, i32::MIN);
    emit_li32(&mut code, 6, -1);
    code.extend([
        rtypew(1, 6, 5, 4, 7),
        rtypew(1, 6, 5, 6, 28),
        rtypew(1, 6, 5, 0, 29),
        rtypew(1, 6, 5, 5, 30),
        rtypew(1, 6, 5, 7, 31),
        rtype(0, 28, 7, 4, 7),
        rtype(0, 29, 7, 4, 7),
        rtype(0, 30, 7, 4, 7),
        rtype(0, 31, 7, 4, 7),
        stype(24, 7, 11, 3),
    ]);

    // q4: バイト・ハーフ・ワードの符号/ゼロ拡張ロード。
    emit_li32(&mut code, 5, 0x80ff_7f01u32 as i32);
    code.extend([
        stype(128, 5, 11, 2),
        load(7, 11, 128, 0),
        load(28, 11, 130, 4),
        load(29, 11, 130, 1),
        load(30, 11, 130, 5),
        load(31, 11, 128, 2),
        load(8, 11, 128, 6),
        rtype(0, 28, 7, 4, 7),
        rtype(0, 29, 7, 4, 7),
        rtype(0, 30, 7, 4, 7),
        rtype(0, 31, 7, 4, 7),
        rtype(0, 8, 7, 4, 7),
        stype(32, 7, 11, 3),
    ]);

    // q5: AMOADD.D/LR.D/SC.D の単一スレッド往復。
    code.extend([
        addi(5, 0, 5),
        stype(136, 5, 11, 3),
        addi(12, 11, 136),
        addi(6, 0, 7),
        amo(0, 6, 12, 7),  // amoadd.d t2,t1,(a2)
        amo(2, 0, 12, 28), // lr.d t3,(a2)
        amo(3, 6, 12, 29), // sc.d t4,t1,(a2)
        load(30, 12, 0, 3),
        rtype(0, 28, 7, 4, 7),
        rtype(0, 29, 7, 4, 7),
        rtype(0, 30, 7, 4, 7),
        stype(40, 7, 11, 3),
    ]);

    // q6: 条件分岐と JAL。成立/不成立の両方を通して最後は 3。
    code.push(addi(5, 0, 1));
    let beq_at = code.len();
    code.push(0);
    code.push(addi(5, 5, 1));
    let bne_at = code.len();
    code.push(0);
    code.push(addi(5, 0, 0));
    let after_bne = code.len();
    patch_branch(&mut code, bne_at, after_bne, 1, 5, 0);
    let blt_at = code.len();
    code.push(0);
    code.push(addi(5, 0, 0));
    let after_blt = code.len();
    patch_branch(&mut code, blt_at, after_blt, 4, 0, 5);
    code.push(addi(6, 0, -1));
    let bltu_at = code.len();
    code.push(0);
    code.push(addi(5, 0, 0));
    let after_bltu = code.len();
    patch_branch(&mut code, bltu_at, after_bltu, 6, 5, 6);
    let jal_at = code.len();
    code.push(0);
    code.push(addi(5, 0, 0));
    let after_jal = code.len();
    patch_jal(&mut code, jal_at, after_jal, 0);
    code.extend([addi(5, 5, 1), stype(48, 5, 11, 3)]);
    // 最初の BEQ は不成立（次へ進む）ことを固定する。ターゲットは
    // 次の ADDI の後ろだが、条件が偽なので通らない。
    patch_branch(&mut code, beq_at, beq_at + 2, 0, 5, 0);

    // q7: C 拡張。4 個の 16 ビット命令を 2 ワードへ詰め、
    // c.li/c.addi/c.add で 15 を作る。
    code.extend([
        0x040D_4415, // c.li s0,5; c.addi s0,3
        0x9426_449D, // c.li s1,7; c.add s0,s1
        stype(56, 8, 11, 3),
    ]);

    // write(1,out,64); exit_group(0)
    code.extend([
        addi(10, 0, 1),
        addi(12, 0, 64),
        addi(17, 0, 64),
        0x0000_0073,
        addi(10, 0, 0),
        addi(17, 0, 94),
        0x0000_0073,
    ]);

    // out を 8 バイト境界へ揃える。code はここですでに syscall 列まで
    // 含む。コード開始 VA は 8 バイト境界なので、総命令数が奇数なら
    // syscall 列の直前へ NOP を足す。
    let syscall_len = 7;
    if code.len() % 2 == 1 {
        let at = code.len() - syscall_len;
        code.insert(at, addi(0, 0, 0));
    }
    let auipc_file_off = 64 + 56 + auipc_index * 4;
    let out_file_off = 64 + 56 + code.len() * 4;
    code[auipc_index + 1] = addi(11, 11, (out_file_off - auipc_file_off) as i32);

    let filesz = out_file_off + 144;
    let mut v = vec![0u8; filesz];
    v[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    v[4] = 2; // ELFCLASS64
    v[5] = 1; // little endian
    v[6] = 1;
    v[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    v[18..20].copy_from_slice(&243u16.to_le_bytes()); // EM_RISCV
    v[20..24].copy_from_slice(&1u32.to_le_bytes());
    v[24..32].copy_from_slice(&(BASE + 120).to_le_bytes());
    v[32..40].copy_from_slice(&64u64.to_le_bytes());
    v[52..54].copy_from_slice(&64u16.to_le_bytes());
    v[54..56].copy_from_slice(&56u16.to_le_bytes());
    v[56..58].copy_from_slice(&1u16.to_le_bytes());
    let p = 64;
    v[p..p + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    v[p + 4..p + 8].copy_from_slice(&7u32.to_le_bytes()); // RWX
    v[p + 8..p + 16].copy_from_slice(&0u64.to_le_bytes());
    v[p + 16..p + 24].copy_from_slice(&BASE.to_le_bytes());
    v[p + 24..p + 32].copy_from_slice(&BASE.to_le_bytes());
    v[p + 32..p + 40].copy_from_slice(&(filesz as u64).to_le_bytes());
    v[p + 40..p + 48].copy_from_slice(&(filesz as u64).to_le_bytes());
    v[p + 48..p + 56].copy_from_slice(&0x1000u64.to_le_bytes());
    let mut off = 64 + 56;
    for w in code {
        v[off..off + 4].copy_from_slice(&w.to_le_bytes());
        off += 4;
    }
    v
}

struct Capture {
    out: Vec<u8>,
}

impl EcallHandler for Capture {
    fn handle_ecall(&mut self, env: &mut BareEnv, _word: u32) -> EcallOutcome {
        let nr = reg(env, 17);
        if nr == polyisa_os_linux::rv64::WRITE {
            let fd = reg(env, 10);
            let buf = reg(env, 11);
            let len = reg(env, 12) as usize;
            if fd != 1 {
                return EcallOutcome::Unimplemented;
            }
            let mut data = vec![0u8; len];
            let acc = Access {
                endian: Endian::Le,
                align: Align::Unaligned,
                kind: AccessKind::DataRead,
            };
            if env.backend.mem.read(VirtAddr(buf), &mut data, acc).is_err() {
                return EcallOutcome::Unimplemented;
            }
            env.backend.set(Gpr(10).state(), len as u64);
            self.out.extend_from_slice(&data);
            return EcallOutcome::Handled;
        }
        if nr == polyisa_os_linux::rv64::EXIT_GROUP || nr == polyisa_os_linux::rv64::EXIT {
            return EcallOutcome::Exit(reg(env, 10));
        }
        EcallOutcome::Unimplemented
    }
}

fn qemu_path() -> Option<&'static str> {
    ["qemu-riscv64", "/usr/bin/qemu-riscv64"]
        .into_iter()
        .find(|c| {
            Command::new(c)
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        })
}

#[test]
fn diff_qemu_rv64imac_program() {
    let Some(qemu) = qemu_path() else {
        eprintln!("qemu-riscv64 がない。スキップ");
        return;
    };
    let dir = std::env::temp_dir().join(format!("polyisa-qemu-rv64-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let elf = dir.join("rv64diff");
    std::fs::write(&elf, image()).unwrap();
    // qemu-user はインタプリタとして読むが、実行ビットがない ELF は
    // 失敗させる。ホストの umask に依存しないよう明示する。
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&elf, std::fs::Permissions::from_mode(0o755)).unwrap();

    let qout = Command::new(qemu).arg(&elf).output().expect("qemu-riscv64");
    assert!(
        qout.status.success(),
        "qemu status {:?}: {}",
        qout.status,
        String::from_utf8_lossy(&qout.stderr)
    );

    let mut cap = Capture { out: Vec::new() };
    let argv = vec![elf.to_str().unwrap().to_string()];
    let code = run_elf_handler(elf.to_str().unwrap(), &argv, None, &mut cap).expect("polyisa run");
    assert_eq!(code, 0, "poly exit");
    assert_eq!(qout.stdout.len(), 64, "qemu stdout len");
    assert_eq!(cap.out.len(), 64, "poly stdout len");
    assert_eq!(cap.out, qout.stdout, "qemu/poly stdout");
    for (i, want) in expected().into_iter().enumerate() {
        let got = u64::from_le_bytes(cap.out[i * 8..i * 8 + 8].try_into().unwrap());
        assert_eq!(got, want, "independent integer expectation q{i}");
    }
}

#[test]
fn rv64diff_image_layout() {
    let bytes = image();
    let ehdr = polyisa_loader::elf::parse_ehdr(&bytes).unwrap();
    assert_eq!(ehdr.machine, 243);
    assert_eq!(ehdr.entry, BASE + 120);
}
