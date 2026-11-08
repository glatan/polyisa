// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! riscv-tests の RV64UI 実行（層5・conformance）。
//!
//! `.testdata/riscv-tests` の1件を clang＋rust-lld でビルドし、製品の
//! run loop（`polyisa-cli::run`、fetch/decode/dispatch）で実行して合否を見る。
//! 終了規約は `ecall`（a7=93）の a0（0=成功）である（`env/p/riscv_test.h` の
//! RVTEST_PASS/FAIL）。
//!
//! 使う外部ツールは台帳 TOOL-LLVM（clang）と rust-lld
//! （Rust 配布物、用途X・確認済み）。テストデータは台帳 TEST-RISCV-TESTS
//! （用途T・確認済み、リポジトリに含めない）.

use polyisa_cli::run::{EcallHandler, EcallOutcome, Outcome, run};
use polyisa_engine::bare::BareEnv;
use polyisa_guest_riscv::CpuState;
use polyisa_mem::VirtAddr;
use polyisa_sem::{Backend as _, StateRef, W64};
use std::path::{Path, PathBuf};
use std::process::Command;

fn testdata() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.join(".testdata").join("riscv-tests")
}

fn bin(candidates: &[&str]) -> Option<String> {
    for c in candidates {
        if Command::new(c).arg("--version").output().is_ok() {
            return Some(c.to_string());
        }
    }
    None
}

/// rustc の sysroot から rust-lld を探す。
fn rust_lld() -> Option<String> {
    let sysroot = Command::new("rustc")
        .arg("--print")
        .arg("sysroot")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())?;
    let host = Command::new("rustc")
        .arg("-vV")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())?
        .lines()
        .find_map(|l| l.strip_prefix("host: ").map(str::to_string))?;
    let p = Path::new(&sysroot)
        .join("lib")
        .join("rustlib")
        .join(&host)
        .join("bin")
        .join("rust-lld");
    if p.exists() {
        return p.to_str().map(str::to_string);
    }
    // フォールバック：ツールチェーン下を探索する。
    let home = std::env::var("HOME").ok()?;
    let mut found = None;
    for e in walkdir(&Path::new(&home).join(".rustup/toolchains")) {
        if e.ends_with("rust-lld") {
            found = Some(e);
            break;
        }
    }
    found.and_then(|p| p.to_str().map(str::to_string))
}

fn walkdir(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walkdir(&p));
        } else {
            out.push(p);
        }
    }
    out
}

/// 1件をビルドして ELF のバイト列を返す。道具がなければ None。
fn build_elf_in(sub: &str, name: &str) -> Option<Vec<u8>> {
    let root = testdata();
    let src = root.join("isa").join(sub).join(format!("{name}.S"));
    if !src.exists() {
        return None;
    }
    let cc = bin(&["clang", "/usr/sbin/clang", "/usr/bin/clang"])?;
    let lld = rust_lld()?;
    // RV32 と RV64 でツールチェインの指定を切り替える。
    let rv32 = sub.starts_with("rv32");
    let (target, march, abi, emul) = if rv32 {
        ("riscv32-unknown-elf", "rv32g", "ilp32d", "elf32lriscv")
    } else {
        ("riscv64-unknown-elf", "rv64g", "lp64d", "elf64lriscv")
    };
    let dir = std::env::temp_dir().join("polyisa-riscv-tests");
    let _ = std::fs::create_dir_all(&dir);
    let obj = dir.join(format!("{sub}_{name}.o"));
    let elf = dir.join(format!("{sub}_{name}.elf"));
    let st = Command::new(&cc)
        .args([
            &format!("--target={target}"),
            &format!("-march={march}"),
            &format!("-mabi={abi}"),
            "-mcmodel=medany",
            "-fvisibility=hidden",
            "-nostdlib",
            "-nostartfiles",
            "-I",
            root.join("env/p").to_str()?,
            "-I",
            root.join("isa/macros/scalar").to_str()?,
            "-c",
            src.to_str()?,
            "-o",
            obj.to_str()?,
        ])
        .output()
        .ok()?;
    if !st.status.success() {
        return None;
    }
    let st = Command::new(&lld)
        .args([
            "-flavor",
            "gnu",
            "-m",
            emul,
            "-T",
            root.join("env/p/link.ld").to_str()?,
            obj.to_str()?,
            "-o",
            elf.to_str()?,
        ])
        .output()
        .ok()?;
    if !st.status.success() {
        return None;
    }
    std::fs::read(&elf).ok()
}

fn check_one_in(sub: &str, name: &str) {
    /// riscv-tests ハーネスの ecall 処理。a7=93（RVTEST_PASS/FAIL）の
    /// 終了規約だけを受け、a0 を終了コードとして返す。
    struct TestEcall;
    impl EcallHandler for TestEcall {
        fn handle_ecall(&mut self, env: &mut BareEnv, _word: u32) -> EcallOutcome {
            let a7 = polyisa_cli::run::reg(env, 17);
            if a7 == 93 {
                return EcallOutcome::Exit(polyisa_cli::run::reg(env, 10));
            }
            EcallOutcome::Unimplemented
        }
    }
    let root = testdata();
    if !root.join(format!("isa/{sub}/{name}.S")).exists() {
        eprintln!("skip: .testdata/riscv-tests がないため未実行");
        return;
    }
    let rv32 = sub.starts_with("rv32");
    let Some(bytes) = build_elf_in(sub, name) else {
        eprintln!("skip: 組み立て器がないため未実行");
        return;
    };
    let (ehdr, phdrs) = if rv32 {
        let ehdr = polyisa_loader::elf::parse_ehdr32(&bytes).expect("ELFヘッダ");
        let phdrs = polyisa_loader::elf::parse_phdrs32(&bytes, &ehdr).expect("PHDR");
        (ehdr, phdrs)
    } else {
        let ehdr = polyisa_loader::elf::parse_ehdr(&bytes).expect("ELFヘッダ");
        let phdrs = polyisa_loader::elf::parse_phdrs(&bytes, &ehdr).expect("PHDR");
        (ehdr, phdrs)
    };
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    // riscv-tests のハーネスは M モードで動く。特権レベルを M (3) に置く。
    env.backend.set(
        StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, priv_level)),
        3,
    );
    polyisa_loader::elf::load_segments(&bytes, &phdrs, &mut env.backend.mem).expect("配置");
    // PMP のない M モードでは、写像済みメモリはすべて fetch 可能である。
    // fence_i の自己書き換え先（.data 等の RW セグメント）への分岐を通す。
    {
        use polyisa_mem::{PAGE_SIZE, Perms};
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        for ph in phdrs.iter().filter(|ph| ph.seg_type == 1) {
            let base = ph.vaddr & !(PAGE_SIZE - 1);
            let end = ph.vaddr.checked_add(ph.memsz).expect("PHDR範囲");
            let aligned = end.checked_add(PAGE_SIZE - 1).expect("PHDR範囲") & !(PAGE_SIZE - 1);
            let count = (aligned - base) / PAGE_SIZE;
            if count > 0 {
                env.backend
                    .mem
                    .protect(VirtAddr(base), count, rwx)
                    .expect("権限付与");
            }
        }
    }
    match run(&mut env, ehdr.entry, rv32, &mut TestEcall) {
        Outcome::Exit(code) => assert_eq!(code, 0, "{name} が失敗"),
        Outcome::Unimplemented { pc, word } => {
            panic!("{name}: 未実装に到達 pc={pc:#x} word={word:#x}")
        }
        Outcome::StepLimit { pc } => panic!("{name}: 予算切れ pc={pc:#x}"),
    }
}

fn check_one(name: &str) {
    check_one_in("rv64ui", name);
}

fn check_rv32i(name: &str) {
    check_one_in("rv32ui", name);
}

fn check_rv32m(name: &str) {
    check_one_in("rv32um", name);
}

fn check_rv32f(name: &str) {
    check_one_in("rv32uf", name);
}

fn check_rv32d(name: &str) {
    check_one_in("rv32ud", name);
}

fn check_rv32c(name: &str) {
    check_one_in("rv32uc", name);
}

fn check_rv32a(name: &str) {
    check_one_in("rv32ua", name);
}

fn check_um(name: &str) {
    check_one_in("rv64um", name);
}

fn check_uf(name: &str) {
    check_one_in("rv64uf", name);
}

fn check_ud(name: &str) {
    check_one_in("rv64ud", name);
}

fn check_uc(name: &str) {
    check_one_in("rv64uc", name);
}

fn check_ua(name: &str) {
    check_one_in("rv64ua", name);
}

#[test]
fn rv64ui_p_addi() {
    check_one("addi");
}

#[test]
fn rv64ui_p_add() {
    check_one("add");
}

#[test]
fn rv64ui_p_sub() {
    check_one("sub");
}

#[test]
fn rv64ui_p_lw() {
    check_one("lw");
}

#[test]
fn rv64ui_p_sw() {
    check_one("sw");
}

#[test]
fn rv64ui_p_beq() {
    check_one("beq");
}

#[test]
fn rv64ui_p_jal() {
    check_one("jal");
}

#[test]
fn rv64ui_p_jalr() {
    check_one("jalr");
}

#[test]
fn rv64ui_p_sll() {
    check_one("sll");
}

#[test]
fn rv64ui_p_sra() {
    check_one("sra");
}

#[test]
fn rv64ui_p_and() {
    check_one("and");
}

#[test]
fn rv64ui_p_or() {
    check_one("or");
}

#[test]
fn rv64ui_p_xor() {
    check_one("xor");
}

#[test]
fn rv64ui_p_slt() {
    check_one("slt");
}

#[test]
fn rv64ui_p_sltu() {
    check_one("sltu");
}

#[test]
fn rv64ui_p_srli() {
    check_one("srli");
}

#[test]
fn rv64ui_p_srai() {
    check_one("srai");
}

#[test]
fn rv64ui_p_bne() {
    check_one("bne");
}

#[test]
fn rv64ui_p_blt() {
    check_one("blt");
}

#[test]
fn rv64ui_p_lui() {
    check_one("lui");
}

#[test]
fn rv64ui_p_auipc() {
    check_one("auipc");
}

#[test]
fn rv64ui_p_lb() {
    check_one("lb");
}

#[test]
fn rv64ui_p_sh() {
    check_one("sh");
}

#[test]
fn rv64um_p_mul() {
    check_um("mul");
}

#[test]
fn rv64um_p_div() {
    check_um("div");
}

#[test]
fn rv64um_p_rem() {
    check_um("rem");
}

#[test]
fn rv64um_p_mulh() {
    check_um("mulh");
}

#[test]
fn rv64um_p_divu() {
    check_um("divu");
}

#[test]
fn rv64uf_p_fadd() {
    check_uf("fadd");
}

#[test]
fn rv64uf_p_fclass() {
    check_uf("fclass");
}

#[test]
fn rv64uf_p_fcmp() {
    check_uf("fcmp");
}

#[test]
fn rv64uf_p_fcvt() {
    check_uf("fcvt");
}

#[test]
fn rv64uf_p_fcvt_w() {
    check_uf("fcvt_w");
}

#[test]
fn rv64uf_p_fdiv() {
    check_uf("fdiv");
}

#[test]
fn rv64uf_p_fmadd() {
    check_uf("fmadd");
}

#[test]
fn rv64uf_p_fmin() {
    check_uf("fmin");
}

#[test]
fn rv64uf_p_ldst() {
    check_uf("ldst");
}

#[test]
fn rv64uf_p_move() {
    check_uf("move");
}

#[test]
fn rv64uf_p_recoding() {
    check_uf("recoding");
}

#[test]
fn rv64ud_p_fadd() {
    check_ud("fadd");
}

#[test]
fn rv64ud_p_fclass() {
    check_ud("fclass");
}

#[test]
fn rv64ud_p_fcmp() {
    check_ud("fcmp");
}

#[test]
fn rv64ud_p_fcvt() {
    check_ud("fcvt");
}

#[test]
fn rv64ud_p_fcvt_w() {
    check_ud("fcvt_w");
}

#[test]
fn rv64ud_p_fdiv() {
    check_ud("fdiv");
}

#[test]
fn rv64ud_p_fmadd() {
    check_ud("fmadd");
}

#[test]
fn rv64ud_p_fmin() {
    check_ud("fmin");
}

#[test]
fn rv64ud_p_ldst() {
    check_ud("ldst");
}

#[test]
fn rv64ud_p_move() {
    check_ud("move");
}

#[test]
fn rv64ud_p_recoding() {
    check_ud("recoding");
}

#[test]
fn rv64ud_p_structural() {
    check_ud("structural");
}

// rv32ui のうち ma_data（非整列アクセス）は対象外。
// fence_i は PMP のない M モードの写像で通る（ロードマップ注記）。
#[test]
fn rv32ui_p_ma_data() {
    check_rv32i("ma_data");
}

#[test]
fn rv32ui_p_add() {
    check_rv32i("add");
}

#[test]
fn rv32ui_p_addi() {
    check_rv32i("addi");
}

#[test]
fn rv32ui_p_and() {
    check_rv32i("and");
}

#[test]
fn rv32ui_p_andi() {
    check_rv32i("andi");
}

#[test]
fn rv32ui_p_auipc() {
    check_rv32i("auipc");
}

#[test]
fn rv32ui_p_beq() {
    check_rv32i("beq");
}

#[test]
fn rv32ui_p_bge() {
    check_rv32i("bge");
}

#[test]
fn rv32ui_p_bgeu() {
    check_rv32i("bgeu");
}

#[test]
fn rv32ui_p_blt() {
    check_rv32i("blt");
}

#[test]
fn rv32ui_p_bltu() {
    check_rv32i("bltu");
}

#[test]
fn rv32ui_p_bne() {
    check_rv32i("bne");
}

#[test]
fn rv32ui_p_jal() {
    check_rv32i("jal");
}

#[test]
fn rv32ui_p_jalr() {
    check_rv32i("jalr");
}

#[test]
fn rv32ui_p_lb() {
    check_rv32i("lb");
}

#[test]
fn rv32ui_p_lbu() {
    check_rv32i("lbu");
}

#[test]
fn rv32ui_p_lh() {
    check_rv32i("lh");
}

#[test]
fn rv32ui_p_lhu() {
    check_rv32i("lhu");
}

#[test]
fn rv32ui_p_lui() {
    check_rv32i("lui");
}

#[test]
fn rv32ui_p_lw() {
    check_rv32i("lw");
}

#[test]
fn rv32ui_p_or() {
    check_rv32i("or");
}

#[test]
fn rv32ui_p_ori() {
    check_rv32i("ori");
}

#[test]
fn rv32ui_p_sb() {
    check_rv32i("sb");
}

#[test]
fn rv32ui_p_sh() {
    check_rv32i("sh");
}

#[test]
fn rv32ui_p_sll() {
    check_rv32i("sll");
}

#[test]
fn rv32ui_p_slli() {
    check_rv32i("slli");
}

#[test]
fn rv32ui_p_slt() {
    check_rv32i("slt");
}

#[test]
fn rv32ui_p_slti() {
    check_rv32i("slti");
}

#[test]
fn rv32ui_p_sltiu() {
    check_rv32i("sltiu");
}

#[test]
fn rv32ui_p_sltu() {
    check_rv32i("sltu");
}

#[test]
fn rv32ui_p_sra() {
    check_rv32i("sra");
}

#[test]
fn rv32ui_p_srai() {
    check_rv32i("srai");
}

#[test]
fn rv32ui_p_srl() {
    check_rv32i("srl");
}

#[test]
fn rv32ui_p_srli() {
    check_rv32i("srli");
}

#[test]
fn rv32ui_p_sub() {
    check_rv32i("sub");
}

#[test]
fn rv32ui_p_sw() {
    check_rv32i("sw");
}

#[test]
fn rv32ui_p_xor() {
    check_rv32i("xor");
}

#[test]
fn rv32ui_p_xori() {
    check_rv32i("xori");
}

#[test]
fn rv32ui_p_fence_i() {
    check_rv32i("fence_i");
}

#[test]
fn rv32ui_p_simple() {
    check_rv32i("simple");
}

#[test]
fn rv32ui_p_ld_st() {
    check_rv32i("ld_st");
}

#[test]
fn rv32ui_p_st_ld() {
    check_rv32i("st_ld");
}

#[test]
fn rv32um_p_mul() {
    check_rv32m("mul");
}

#[test]
fn rv32um_p_mulh() {
    check_rv32m("mulh");
}

#[test]
fn rv32um_p_mulhsu() {
    check_rv32m("mulhsu");
}

#[test]
fn rv32um_p_mulhu() {
    check_rv32m("mulhu");
}

#[test]
fn rv32um_p_div() {
    check_rv32m("div");
}

#[test]
fn rv32um_p_divu() {
    check_rv32m("divu");
}

#[test]
fn rv32um_p_rem() {
    check_rv32m("rem");
}

#[test]
fn rv32um_p_remu() {
    check_rv32m("remu");
}

#[test]
fn rv32uf_p_fadd() {
    check_rv32f("fadd");
}

#[test]
fn rv32uf_p_fclass() {
    check_rv32f("fclass");
}

#[test]
fn rv32uf_p_fcmp() {
    check_rv32f("fcmp");
}

#[test]
fn rv32uf_p_fcvt() {
    check_rv32f("fcvt");
}

#[test]
fn rv32uf_p_fcvt_w() {
    check_rv32f("fcvt_w");
}

#[test]
fn rv32uf_p_fdiv() {
    check_rv32f("fdiv");
}

#[test]
fn rv32uf_p_fmadd() {
    check_rv32f("fmadd");
}

#[test]
fn rv32uf_p_fmin() {
    check_rv32f("fmin");
}

#[test]
fn rv32uf_p_ldst() {
    check_rv32f("ldst");
}

#[test]
fn rv32uf_p_move() {
    check_rv32f("move");
}

#[test]
fn rv32uf_p_recoding() {
    check_rv32f("recoding");
}

#[test]
fn rv32uc_p_rvc() {
    check_rv32c("rvc");
}

#[test]
fn rv32ud_p_fadd() {
    check_rv32d("fadd");
}

#[test]
fn rv32ud_p_fclass() {
    check_rv32d("fclass");
}

#[test]
fn rv32ud_p_fcmp() {
    check_rv32d("fcmp");
}

#[test]
fn rv32ud_p_fcvt() {
    check_rv32d("fcvt");
}

#[test]
fn rv32ud_p_fcvt_w() {
    check_rv32d("fcvt_w");
}

#[test]
fn rv32ud_p_fdiv() {
    check_rv32d("fdiv");
}

#[test]
fn rv32ud_p_fmadd() {
    check_rv32d("fmadd");
}

#[test]
fn rv32ud_p_fmin() {
    check_rv32d("fmin");
}

#[test]
fn rv32ud_p_ldst() {
    check_rv32d("ldst");
}

#[test]
fn rv32ud_p_move() {
    check_rv32d("move");
}

#[test]
fn rv32ud_p_recoding() {
    check_rv32d("recoding");
}

#[test]
fn rv64uc_p_rvc() {
    check_uc("rvc");
}

#[test]
fn rv32ua_p_amoadd_w() {
    check_rv32a("amoadd_w");
}

#[test]
fn rv32ua_p_amoand_w() {
    check_rv32a("amoand_w");
}

#[test]
fn rv32ua_p_amomax_w() {
    check_rv32a("amomax_w");
}

#[test]
fn rv32ua_p_amomaxu_w() {
    check_rv32a("amomaxu_w");
}

#[test]
fn rv32ua_p_amomin_w() {
    check_rv32a("amomin_w");
}

#[test]
fn rv32ua_p_amominu_w() {
    check_rv32a("amominu_w");
}

#[test]
fn rv32ua_p_amoor_w() {
    check_rv32a("amoor_w");
}

#[test]
fn rv32ua_p_amoswap_w() {
    check_rv32a("amoswap_w");
}

#[test]
fn rv32ua_p_amoxor_w() {
    check_rv32a("amoxor_w");
}

#[test]
fn rv32ua_p_lrsc() {
    check_rv32a("lrsc");
}

#[test]
fn rv64ua_p_amoadd_w() {
    check_ua("amoadd_w");
}

#[test]
fn rv64ua_p_amoadd_d() {
    check_ua("amoadd_d");
}

#[test]
fn rv64ua_p_amoand_w() {
    check_ua("amoand_w");
}

#[test]
fn rv64ua_p_amoand_d() {
    check_ua("amoand_d");
}

#[test]
fn rv64ua_p_amomax_w() {
    check_ua("amomax_w");
}

#[test]
fn rv64ua_p_amomax_d() {
    check_ua("amomax_d");
}

#[test]
fn rv64ua_p_amomaxu_w() {
    check_ua("amomaxu_w");
}

#[test]
fn rv64ua_p_amomaxu_d() {
    check_ua("amomaxu_d");
}

#[test]
fn rv64ua_p_amomin_w() {
    check_ua("amomin_w");
}

#[test]
fn rv64ua_p_amomin_d() {
    check_ua("amomin_d");
}

#[test]
fn rv64ua_p_amominu_w() {
    check_ua("amominu_w");
}

#[test]
fn rv64ua_p_amominu_d() {
    check_ua("amominu_d");
}

#[test]
fn rv64ua_p_amoor_w() {
    check_ua("amoor_w");
}

#[test]
fn rv64ua_p_amoor_d() {
    check_ua("amoor_d");
}

#[test]
fn rv64ua_p_amoswap_w() {
    check_ua("amoswap_w");
}

#[test]
fn rv64ua_p_amoswap_d() {
    check_ua("amoswap_d");
}

#[test]
fn rv64ua_p_amoxor_w() {
    check_ua("amoxor_w");
}

#[test]
fn rv64ua_p_amoxor_d() {
    check_ua("amoxor_d");
}

#[test]
fn rv64ua_p_lrsc() {
    check_ua("lrsc");
}

// rv64ui 残件（W接尾辞・LD/SD・LWU・残りのI命令）。
// fence_i は PMP のない M モードの写像で通る。
// ma_data は非整列を許す実装（DATA_READ/WRITE の Unaligned）で通す。
#[test]
fn rv64ui_p_ma_data() {
    check_one("ma_data");
}

#[test]
fn rv64ui_p_addiw() {
    check_one("addiw");
}

#[test]
fn rv64ui_p_addw() {
    check_one("addw");
}

#[test]
fn rv64ui_p_andi() {
    check_one("andi");
}

#[test]
fn rv64ui_p_bge() {
    check_one("bge");
}

#[test]
fn rv64ui_p_bgeu() {
    check_one("bgeu");
}

#[test]
fn rv64ui_p_bltu() {
    check_one("bltu");
}

#[test]
fn rv64ui_p_lbu() {
    check_one("lbu");
}

#[test]
fn rv64ui_p_ld() {
    check_one("ld");
}

#[test]
fn rv64ui_p_ld_st() {
    check_one("ld_st");
}

#[test]
fn rv64ui_p_lh() {
    check_one("lh");
}

#[test]
fn rv64ui_p_lhu() {
    check_one("lhu");
}

#[test]
fn rv64ui_p_lwu() {
    check_one("lwu");
}

#[test]
fn rv64ui_p_ori() {
    check_one("ori");
}

#[test]
fn rv64ui_p_sb() {
    check_one("sb");
}

#[test]
fn rv64ui_p_sd() {
    check_one("sd");
}

#[test]
fn rv64ui_p_fence_i() {
    check_one("fence_i");
}

#[test]
fn rv64ui_p_simple() {
    check_one("simple");
}

#[test]
fn rv64ui_p_slli() {
    check_one("slli");
}

#[test]
fn rv64ui_p_slliw() {
    check_one("slliw");
}

#[test]
fn rv64ui_p_sllw() {
    check_one("sllw");
}

#[test]
fn rv64ui_p_slti() {
    check_one("slti");
}

#[test]
fn rv64ui_p_sltiu() {
    check_one("sltiu");
}

#[test]
fn rv64ui_p_srl() {
    check_one("srl");
}

#[test]
fn rv64ui_p_srliw() {
    check_one("srliw");
}

#[test]
fn rv64ui_p_srlw() {
    check_one("srlw");
}

#[test]
fn rv64ui_p_st_ld() {
    check_one("st_ld");
}

#[test]
fn rv64ui_p_subw() {
    check_one("subw");
}

#[test]
fn rv64ui_p_xori() {
    check_one("xori");
}

#[test]
fn rv64ui_p_sraiw() {
    check_one("sraiw");
}

#[test]
fn rv64ui_p_sraw() {
    check_one("sraw");
}

#[test]
fn rv64um_p_divuw() {
    check_um("divuw");
}

#[test]
fn rv64um_p_divw() {
    check_um("divw");
}

#[test]
fn rv64um_p_mulhsu() {
    check_um("mulhsu");
}

#[test]
fn rv64um_p_mulhu() {
    check_um("mulhu");
}

#[test]
fn rv64um_p_mulw() {
    check_um("mulw");
}

#[test]
fn rv64um_p_remuw() {
    check_um("remuw");
}

#[test]
fn rv64um_p_remw() {
    check_um("remw");
}

#[test]
fn rv64um_p_remu() {
    check_um("remu");
}
