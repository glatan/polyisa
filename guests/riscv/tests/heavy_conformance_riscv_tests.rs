// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Gap: GAP-0010
//! riscv-arch-test（ACT4）の代表テスト実行（層5・conformance）。
//!
//! ACT4 は signature 生成用 ELF を Sail で実行し、その結果を期待値として
//! 自己検査 ELF へ埋め込む。ここでは全体フレームワークが要る特権テストや
//! coverage ではなく、RV64I/M の代表テストについて、この compile/link/
//! reference/self-check 経路を製品ランタイムへ接続する。
//!
//! 参照実装は TOOL-SAIL-RISCV、compiler は TOOL-LLVM と rust-lld、
//! テストデータは TEST-RISCV-ARCH-TEST を使う。

use polyisa_cli::run_riscv;
use std::path::{Path, PathBuf};
use std::process::Command;

fn testdata_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.join(".testdata")
}

fn act_root() -> PathBuf {
    testdata_root().join("riscv-arch-test")
}

fn qemu_dir() -> PathBuf {
    act_root().join("config").join("qemu").join("qemu-RVI20U64")
}

fn bin(candidates: &[&str]) -> Option<String> {
    for c in candidates {
        if Command::new(c).arg("--version").output().is_ok() {
            return Some((*c).to_string());
        }
    }
    None
}

fn rust_lld() -> Option<PathBuf> {
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
    if p.exists() { Some(p) } else { None }
}

fn run_tool(cmd: &mut Command, what: &str) -> Result<(), String> {
    let out = cmd.output().map_err(|e| format!("{what}: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    Err(format!(
        "{what}: status {:?}\n{stderr}{stdout}",
        out.status.code()
    ))
}

/// ACT4 の UDB 生成ヘッダに相当する最小構成。qemu-RVI20U64 の
/// implemented_extensions と、裸の I/M テストで参照される parameter を表す。
/// 全体フレームワークの UDB 依存を入れずに代表経路を固定するためのもので、
/// 特権テストへ広げるときは生成器または完全な写像へ置き換える。
const RVTEST_CONFIG: &str = r#"#ifndef RVTEST_CONFIG_H
#define RVTEST_CONFIG_H
#define I_SUPPORTED
#define M_SUPPORTED
#define ZMMUL_SUPPORTED
#define A_SUPPORTED
#define F_SUPPORTED
#define D_SUPPORTED
#define C_SUPPORTED
#define ZICCLSM_SUPPORTED
#define ZICNTR_SUPPORTED
#define ZICSR_SUPPORTED
#define ZIFENCEI_SUPPORTED
#define ZAAMO_SUPPORTED
#define ZALRSC_SUPPORTED
#define ZCA_SUPPORTED
#define ZCD_SUPPORTED
#define SM_SUPPORTED
#define UDB_MXLEN 64
#define UDB_MXLEN_64
#define UDB_NUM_PMP_ENTRIES 0
#define UDB_NUM_USABLE_PMP_ENTRIES 0
#define UDB_MTVEC_MODES_0
#define UDB_MTVEC_MODES_1
#define UDB_MTVEC_BASE_ALIGNMENT_DIRECT 4
#define UDB_MTVEC_BASE_ALIGNMENT_VECTORED 4
#define UDB_MCOUNTINHIBIT_IMPLEMENTED
#define UDB_TIME_CSR_IMPLEMENTED
#define UDB_MEI_INTR_IMPL
#define UDB_MSI_INTR_IMPL
#define UDB_MTI_INTR_IMPL
#define UDB_REPORT_ENCODING_IN_MTVAL_ON_ILLEGAL_INSTRUCTION
#endif
"#;

/// qemu-RVI20U64 の終了規約を保ち、UART だけを no-op にする。
/// polyisa は PC16550 を持たないが、自己検査 ELF の合否は semihosting の
/// 終了コードで分かる。console 出力は診断用なので落としてよい。
fn write_polyisa_rvmodel(work: &Path) -> Result<(), String> {
    let src = qemu_dir().join("rvmodel_macros.h");
    let text = std::fs::read_to_string(&src).map_err(|e| format!("read {src:?}: {e}"))?;
    let start = text
        .find("#define RVMODEL_IO_INIT")
        .ok_or("qemu rvmodel_macros.h に RVMODEL_IO_INIT がない")?;
    let end = text
        .find("##### Access Fault #####")
        .ok_or("qemu rvmodel_macros.h に Access Fault 節がない")?;
    let patched = format!(
        "{}#define RVMODEL_IO_INIT(_R1, _R2, _R3)\n\n#define RVMODEL_IO_WRITE_STR(_R1, _R2, _R3, _STR_PTR)\n\n{}",
        &text[..start],
        &text[end..]
    );
    let out = work.join("rvmodel_macros.h");
    std::fs::write(&out, patched).map_err(|e| format!("write {out:?}: {e}"))?;
    Ok(())
}

fn prepare_env(work: &Path) -> Result<PathBuf, String> {
    let env = work.join("env");
    std::fs::create_dir_all(&env).map_err(|e| format!("mkdir {env:?}: {e}"))?;
    let cfg = env.join("rvtest_config.h");
    std::fs::write(&cfg, RVTEST_CONFIG).map_err(|e| format!("write {cfg:?}: {e}"))?;
    write_polyisa_rvmodel(work)?;
    Ok(env)
}

/// pyjson5 形式の sail.json から platform device の base を読む。
/// ACT が生成する設定では十進数の整数なので、コメントの多い JSON5 を
/// 完全には parse せず、対象 device の直後にある最初の base だけを取る。
fn platform_base(config: &str, device: &str) -> Result<u64, String> {
    let key = format!("\"{device}\"");
    let pos = config
        .find(&key)
        .ok_or_else(|| format!("sail.json に {device} がない"))?;
    let rest = &config[pos..];
    let base = rest
        .find("\"base\"")
        .ok_or_else(|| format!("sail.json の {device} に base がない"))?;
    let after = &rest[base + "\"base\"".len()..];
    let colon = after
        .find(':')
        .ok_or_else(|| format!("sail.json の {device}.base が不正"))?;
    let digits: String = after[colon + 1..]
        .chars()
        .skip_while(char::is_ascii_whitespace)
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits
        .parse()
        .map_err(|e| format!("sail.json の {device}.base を読めない: {e}"))
}

/// テストヘッダの `MARCH:` を読む。ACT の生成テストでは YAML ヘッダに
/// 必ずある。
fn test_march(src: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(src).map_err(|e| format!("read {src:?}: {e}"))?;
    for line in text.lines() {
        let t = line.trim().trim_start_matches('#').trim();
        if let Some(v) = t.strip_prefix("MARCH:") {
            return Ok(v.trim().to_string());
        }
    }
    Err(format!("{src:?} に MARCH がない"))
}

fn flen_of_march(march: &str) -> u32 {
    let m = march.to_ascii_lowercase();
    let mut parts = m.split('_');
    let single = parts.next().unwrap_or("");
    let letters = single
        .strip_prefix("rv64")
        .or_else(|| single.strip_prefix("rv32"))
        .unwrap_or(single);
    let rest: Vec<&str> = parts.collect();
    if letters.contains('q') || rest.contains(&"q") {
        128
    } else if letters.contains('d') || letters.contains('g') || rest.contains(&"d") {
        64
    } else {
        32
    }
}

struct CompileAct<'a> {
    src: &'a Path,
    out: &'a Path,
    work: &'a Path,
    env: &'a Path,
    lld_dir: &'a Path,
    march: &'a str,
    signature: bool,
    result_file: Option<&'a Path>,
}

fn compile_act_test(input: &CompileAct<'_>) -> Result<(), String> {
    let CompileAct {
        src,
        out,
        work,
        env,
        lld_dir,
        march,
        signature,
        result_file,
    } = *input;
    let cc =
        bin(&["clang", "/usr/sbin/clang", "/usr/bin/clang"]).ok_or("clang がない（TOOL-LLVM）")?;
    let mut cmd = Command::new(cc);
    cmd.arg("--target=riscv64")
        .arg("-fuse-ld=lld")
        .arg(format!("-B{}", lld_dir.display()))
        .arg(format!("-I{}", work.display()))
        .arg(format!("-T{}", qemu_dir().join("link.ld").display()))
        .arg("-O0")
        .arg("-g")
        .arg("-mcmodel=medany")
        .arg("-nostdlib")
        .arg(format!(
            "-I{}",
            act_root().join("tests").join("env").display()
        ))
        .arg(format!("-I{}", env.display()))
        .arg("-Wl,--defsym=__stack_size=128")
        .arg("-o")
        .arg(out)
        .arg(format!("-march={march}"))
        .arg("-mabi=lp64");
    if march.contains("zibi") || march.contains("zabha") || march.contains("zacas") {
        cmd.arg("-menable-experimental-extensions");
    }
    if signature {
        let sail_json = std::fs::read_to_string(qemu_dir().join("sail.json"))
            .map_err(|e| format!("read sail.json: {e}"))?;
        let clint = platform_base(&sail_json, "clint")?;
        let siggen = platform_base(&sail_json, "simple_interrupt_generator")?;
        cmd.arg("-DSIGNATURE")
            .arg(format!("-DSAIL_CLINT_BASE_ADDRESS=0x{clint:x}"))
            .arg(format!(
                "-DSAIL_SIMPLE_INTERRUPT_GENERATOR_BASE_ADDRESS=0x{siggen:x}"
            ));
    } else {
        cmd.arg("-DRVTEST_SELFCHECK");
        if let Some(results) = result_file {
            cmd.arg(format!("-DSIGNATURE_FILE=\"{}\"", results.display()));
        } else {
            cmd.arg("-DRVTEST_NOSIG");
        }
        cmd.arg("-DXLEN=64");
    }
    cmd.arg(format!("-DTEST_FLEN={}", flen_of_march(march)))
        .arg(format!(
            "-DTEST_FILE=\"{}\"",
            src.file_name().and_then(|s| s.to_str()).unwrap_or("test.S")
        ))
        .arg(src);
    run_tool(&mut cmd, &format!("compile {src:?}"))
}

fn process_signature(sig: &Path, xlen: u32, corrupt_first: bool) -> Result<PathBuf, String> {
    let datatype = if xlen == 32 { ".word" } else { ".quad" };
    let (trap_canary, final_sig, final_trap) = if xlen == 32 {
        ("d3a91f6c", "4b8e2d17", "7a110ff5")
    } else {
        ("d3a91f6c8b47e25d", "4b8e2d17a6c0f953", "7a110ff5c0def00d")
    };
    let data = std::fs::read_to_string(sig).map_err(|e| format!("read {sig:?}: {e}"))?;
    let mut lines: Vec<String> = data
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_string)
        .collect();
    if lines.is_empty() {
        return Err(format!("{sig:?} が空"));
    }
    if corrupt_first {
        lines[0] = "0".repeat(lines[0].len());
    }
    let out = sig.with_extension("results");
    let mut text = String::new();
    for (i, line) in lines.iter().enumerate() {
        if i + 1 == lines.len() {
            text.push_str("sig_end_canary:\n");
        }
        text.push_str(&format!("{datatype} 0x{}\n", line.as_str()));
        if line.contains(final_sig) {
            text.push_str("final_sig_offset:\n");
        }
        if line.contains(final_trap) {
            text.push_str("final_trap_sig_offset:\n");
        }
        if line.contains(trap_canary) {
            text.push_str("trap_sigptr:\n");
        }
    }
    std::fs::write(&out, text).map_err(|e| format!("write {out:?}: {e}"))?;
    Ok(out)
}

fn build_and_run(test_rel: &str, corrupt_signature: bool) -> Result<(), String> {
    let root = act_root();
    let src = root.join("tests").join(test_rel);
    assert!(
        src.exists(),
        ".testdata/riscv-arch-test がない（未実行の決定は devtool test:plan が担う）"
    );
    let name = src
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or("テスト名が不正")?;
    let artifact = if corrupt_signature {
        format!("{name}-corrupt")
    } else {
        name.to_string()
    };
    let work = std::env::temp_dir().join("polyisa-act4").join(&artifact);
    let build = work.join("build");
    let elfs = work.join("elfs");
    std::fs::create_dir_all(&build).map_err(|e| format!("mkdir {build:?}: {e}"))?;
    std::fs::create_dir_all(&elfs).map_err(|e| format!("mkdir {elfs:?}: {e}"))?;
    let env = prepare_env(&work)?;

    // clang が rust-lld を ld.lld として見つけられるよう、作業場所へ
    // ld.lld 名で複製する。コンテナでは unversioned ld.lld もあるが、
    // ホストと同じ経路で動かすために常にこの -B を使う。
    let lld_dir = work.join("lldbin");
    std::fs::create_dir_all(&lld_dir).map_err(|e| format!("mkdir {lld_dir:?}: {e}"))?;
    let rust_lld = rust_lld().ok_or("rust-lld がない")?;
    let ld_lld = lld_dir.join("ld.lld");
    if !ld_lld.exists() {
        // rust-lld は 12 MiB ある。テストごとの複製で tmpfs を埋めないよう、
        // Unix では symlink、それ以外では複製にする。
        #[cfg(unix)]
        std::os::unix::fs::symlink(&rust_lld, &ld_lld)
            .map_err(|e| format!("symlink {rust_lld:?}: {e}"))?;
        #[cfg(not(unix))]
        std::fs::copy(&rust_lld, &ld_lld).map_err(|e| format!("copy {rust_lld:?}: {e}"))?;
    }

    let mut march = test_march(&src)?;
    if march.contains("zibi") {
        // LLVM は草案版 0.1 を `zibi0p1` としてだけ受け付ける。
        // ACT のYAMLは版なしなので、compile 用の文字列だけ版付きにする。
        march = march.replace("zibi", "zibi0p1");
    }
    let sig_elf = build.join(format!("{artifact}.sig.elf"));
    compile_act_test(&CompileAct {
        src: &src,
        out: &sig_elf,
        work: &work,
        env: &env,
        lld_dir: &lld_dir,
        march: &march,
        signature: true,
        result_file: None,
    })?;

    let sig = build.join(format!("{artifact}.sig"));
    let sail = bin(&["sail_riscv_sim", "/opt/sail-riscv/bin/sail_riscv_sim"])
        .ok_or("sail_riscv_sim がない（TOOL-SAIL-RISCV）")?;
    // qemu-RVI20U64 はプロファイル要件外の拡張をいくつか切っているが、
    // Sail 0.16 自体は実装している。参照実行だけが落ちないよう、
    // 対象拡張のテストでは作業領域の写しで有効化する。
    let mut sail_json = std::fs::read_to_string(qemu_dir().join("sail.json"))
        .map_err(|e| format!("read sail.json: {e}"))?;
    if test_rel.contains("/Zicond/") {
        sail_json = sail_json.replace(
            "\"Zicond\": {\n      \"supported\": false",
            "\"Zicond\": {\n      \"supported\": true",
        );
    }
    if test_rel.contains("/Zcb/")
        || test_rel.contains("/Zba/")
        || test_rel.contains("/Zbb/")
        || test_rel.contains("/Zbc/")
        || test_rel.contains("/Zbs/")
        || test_rel.contains("/Zimop/")
        || test_rel.contains("/Zcmop/")
        || test_rel.contains("/Zihintntl/")
        || test_rel.contains("/Zihintpause/")
        || test_rel.contains("/Zicntr/")
        || test_rel.contains("/Zicbom/")
        || test_rel.contains("/Zicbop/")
        || test_rel.contains("/Zicboz/")
        || test_rel.contains("/Zihpm/")
        || test_rel.contains("/Zibi/")
        || test_rel.contains("/Zabha/")
        || test_rel.contains("/Zacas/")
        || test_rel.contains("/Zbkc/")
        || test_rel.contains("/Zbkx/")
        || test_rel.contains("/Zknh/")
        || test_rel.contains("/Zksh/")
        || test_rel.contains("/Zksed/")
        || test_rel.contains("/Zkne/")
        || test_rel.contains("/Zknd/")
        || test_rel.contains("/Zfhmin/")
    {
        for ext in [
            "Zcb",
            "Zba",
            "Zbb",
            "Zbc",
            "Zbs",
            "Zimop",
            "Zcmop",
            "Zihintntl",
            "Zihintpause",
            "Zicntr",
            "Zicbom",
            "Zicbop",
            "Zicboz",
            "Zihpm",
            "Zibi",
            "Zabha",
            "Zacas",
            "Zbkc",
            "Zbkx",
            "Zknh",
            "Zksh",
            "Zksed",
            "Zkne",
            "Zknd",
            "Zfhmin",
            "Zaamo",
        ] {
            if !sail_json.contains(&format!("\"{ext}\"")) {
                sail_json = sail_json.replace(
                    "    \"Zicond\": {",
                    &format!(
                        "    \"{ext}\": {{\n      \"supported\": true\n    }},\n    \"Zicond\": {{"
                    ),
                );
            }
            sail_json = sail_json.replace(
                &format!("\"{ext}\": {{\n      \"supported\": false"),
                &format!("\"{ext}\": {{\n      \"supported\": true"),
            );
        }
    }
    let sail_cfg = work.join("sail.json");
    std::fs::write(&sail_cfg, sail_json).map_err(|e| format!("write {sail_cfg:?}: {e}"))?;
    let mut cmd = Command::new(sail);
    if test_rel.contains("/Zibi/") || test_rel.contains("/Zabha/") || test_rel.contains("/Zacas/") {
        cmd.arg("--enable-experimental-extensions");
    }
    cmd.arg("--config")
        .arg(&sail_cfg)
        .arg(format!("--test-signature={}", sig.display()))
        .arg("--signature-granularity")
        .arg("8")
        .arg(&sig_elf);
    run_tool(&mut cmd, &format!("sail {name}"))?;
    if !sig.exists() {
        return Err(format!("{}: signature が生成されなかった", sig.display()));
    }
    let results = process_signature(&sig, 64, corrupt_signature)?;

    let final_elf = elfs.join(format!("{artifact}.elf"));
    compile_act_test(&CompileAct {
        src: &src,
        out: &final_elf,
        work: &work,
        env: &env,
        lld_dir: &lld_dir,
        march: &march,
        signature: false,
        result_file: Some(&results),
    })?;

    let mut semi = run_riscv::SemiRv::new("", false);
    let add_feats: &[&str] = if test_rel.contains("/Zicond/") {
        &["zicond"]
    } else if test_rel.contains("/Zcb/")
        || test_rel.contains("/Zba/")
        || test_rel.contains("/Zbb/")
        || test_rel.contains("/Zbc/")
        || test_rel.contains("/Zbs/")
        || test_rel.contains("/Zimop/")
        || test_rel.contains("/Zcmop/")
        || test_rel.contains("/Zihintntl/")
        || test_rel.contains("/Zihintpause/")
        || test_rel.contains("/Zicntr/")
        || test_rel.contains("/Zicbom/")
        || test_rel.contains("/Zicbop/")
        || test_rel.contains("/Zicboz/")
        || test_rel.contains("/Zihpm/")
        || test_rel.contains("/Zibi/")
        || test_rel.contains("/Zabha/")
        || test_rel.contains("/Zacas/")
        || test_rel.contains("/Zbkc/")
        || test_rel.contains("/Zbkx/")
        || test_rel.contains("/Zknh/")
        || test_rel.contains("/Zksh/")
        || test_rel.contains("/Zksed/")
        || test_rel.contains("/Zkne/")
        || test_rel.contains("/Zknd/")
        || test_rel.contains("/Zfhmin/")
    {
        &[
            "zcb",
            "zba",
            "zbb",
            "zbc",
            "zbkx",
            "zknh",
            "zksh",
            "zksed",
            "zkne",
            "zknd",
            "zfhmin",
            "zbs",
            "zimop",
            "zcmop",
            "zihintntl",
            "zihintpause",
            "zicntr",
            "zicbom",
            "zicbop",
            "zicboz",
            "zihpm",
            "zibi",
            "zabha",
            "zacas",
        ]
    } else {
        &[]
    };
    let sel = if add_feats.is_empty() {
        None
    } else {
        Some(
            polyisa_isadl::select::resolve(
                polyisa_guest_riscv::MODEL_DEFS,
                polyisa_guest_riscv::FEATURE_DEFS,
                polyisa_guest_riscv::FEAT_BITS,
                "rv64gc",
                add_feats,
                &[],
            )
            .map_err(|e| format!("cpu select: {e}"))?,
        )
    };
    let argv: &[String] = &[];
    let path = final_elf
        .to_str()
        .ok_or_else(|| format!("{} が UTF-8 ではない", final_elf.display()))?;
    match run_riscv::run_elf_handler_mmode(path, argv, sel.as_ref(), &mut semi) {
        Ok(0) => Ok(()),
        Ok(code) => Err(format!("{name}: ACT が失敗コード {code} で終了")),
        Err(e) => Err(format!("{name}: {e}")),
    }
}

fn suite(dir: &str) {
    let base = act_root().join("tests").join(dir);
    let mut files: Vec<PathBuf> = std::fs::read_dir(&base)
        .unwrap_or_else(|e| panic!("read_dir {base:?}: {e}"))
        .map(|e| e.unwrap_or_else(|e| panic!("read_dir entry: {e}")).path())
        .filter(|p| p.extension().is_some_and(|x| x == "S"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "{base:?} にテストがない");

    let tests = act_root().join("tests");
    let mut failures = Vec::new();
    for file in files {
        let rel = file
            .strip_prefix(&tests)
            .unwrap_or_else(|_| panic!("{} が tests 下にない", file.display()))
            .to_str()
            .unwrap_or_else(|| panic!("{} が UTF-8 ではない", file.display()))
            .to_string();
        if let Err(e) = build_and_run(&rel, false) {
            failures.push(format!("{rel}: {e}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{dir} suite failures ({})
{}",
        failures.len(),
        failures.join(
            "
"
        )
    );
}

#[test]
fn act4_rv64i_suite() {
    suite("rv64i/I");
}

#[test]
fn act4_rv64m_suite() {
    suite("rv64i/M");
}

#[test]
fn act4_rv64zca_suite() {
    suite("rv64i/Zca");
}

#[test]
fn act4_rv64zaamo_suite() {
    suite("rv64i/Zaamo");
}

#[test]
fn act4_rv64zalrsc_suite() {
    suite("rv64i/Zalrsc");
}

#[test]
fn act4_rv64zicsr_suite() {
    suite("rv64i/Zicsr");
}

#[test]
fn act4_rv64zifencei_suite() {
    suite("rv64i/Zifencei");
}

#[test]
fn act4_rv64zicclsm_suite() {
    suite("rv64i/Zicclsm");
}

#[test]
fn act4_rv64f_suite() {
    suite("rv64i/F");
}

#[test]
fn act4_rv64d_suite() {
    suite("rv64i/D");
}

#[test]
fn act4_rv64zmmul_suite() {
    suite("rv64i/Zmmul");
}

#[test]
fn act4_rv64zcd_suite() {
    suite("rv64i/Zcd");
}

#[test]
fn act4_rv64zicond_suite() {
    suite("rv64i/Zicond");
}

#[test]
fn act4_rv64zcb_suite() {
    suite("rv64i/Zcb");
}

#[test]
fn act4_rv64zba_suite() {
    suite("rv64i/Zba");
}

#[test]
fn act4_rv64zbb_suite() {
    suite("rv64i/Zbb");
}

#[test]
fn act4_rv64zbc_suite() {
    suite("rv64i/Zbc");
}

#[test]
fn act4_rv64zbs_suite() {
    suite("rv64i/Zbs");
}

#[test]
fn act4_rv64zimop_suite() {
    suite("rv64i/Zimop");
}

#[test]
fn act4_rv64zcmop_suite() {
    suite("rv64i/Zcmop");
}

#[test]
fn act4_rv64zihintntl_suite() {
    suite("rv64i/Zihintntl");
}

#[test]
fn act4_rv64zihintpause_suite() {
    suite("rv64i/Zihintpause");
}

#[test]
fn act4_rv64zicntr_suite() {
    suite("rv64i/Zicntr");
}

#[test]
fn act4_rv64zicbom_suite() {
    suite("rv64i/Zicbom");
}

#[test]
fn act4_rv64zicbop_suite() {
    suite("rv64i/Zicbop");
}

#[test]
fn act4_rv64zicboz_suite() {
    suite("rv64i/Zicboz");
}

#[test]
fn act4_rv64zihpm_suite() {
    suite("rv64i/Zihpm");
}

#[test]
fn act4_rv64zibi_suite() {
    suite("rv64i/Zibi");
}

#[test]
fn act4_rv64zabha_suite() {
    suite("rv64i/Zabha");
}

#[test]
fn act4_rv64zacas_suite() {
    suite("rv64i/Zacas");
}

#[test]
fn act4_rv64zbkc_suite() {
    suite("rv64i/Zbkc");
}

#[test]
fn act4_rv64zbkx_suite() {
    suite("rv64i/Zbkx");
}

#[test]
fn act4_rv64zknh_suite() {
    suite("rv64i/Zknh");
}

#[test]
fn act4_rv64zksh_suite() {
    suite("rv64i/Zksh");
}

#[test]
fn act4_rv64zksed_suite() {
    suite("rv64i/Zksed");
}

#[test]
fn act4_rv64zkne_suite() {
    suite("rv64i/Zkne");
}

#[test]
fn act4_rv64zknd_suite() {
    suite("rv64i/Zknd");
}

#[test]
fn act4_rv64zfhmin_suite() {
    suite("rv64i/Zfhmin");
}

#[test]
fn act4_failure_is_nonzero() {
    let err = build_and_run("rv64i/I/I-add-00.S", true)
        .expect_err("壊した期待 signature を合格と判定してはいけない");
    assert!(
        err.contains("失敗コード 1"),
        "unexpected failure classification: {err}"
    );
}
