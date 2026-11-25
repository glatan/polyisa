// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `run -g <ポート>` の RSP サーバに TOOL-GDB で接続し、ブレークポイント・
//! 継続・単歩・レジスタの読み書き・逆アセンブルが動く（層7・program、S29-1）。
//!
//! clang（TOOL-LLVM）で `-g -O0 -nostdlib -static` の rv64 ELF を自前ビルドし、
//! 子プロセスで `polyisa run -g <ポート> <elf>` を起動、`gdb -batch` で
//! `target remote` → `break main` → `c` → `si` → レジスタ読み書き →
//! `x/2i` → `kill` の列を実行して出力を検査する。

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// rv64。asm-generic 番号（write=64・exit=93。出典は SRC-LINUX (7.3)）。
/// `main` は `-g` の DWARF で行番号とシンボルが解けるようにする。
const SRC: &str = r#"
typedef unsigned long u64;

static long sc3(long n, long a, long b, long c) {
    register long a7 __asm__("a7") = n;
    register long a0 __asm__("a0") = a;
    register long a1 __asm__("a1") = b;
    register long a2 __asm__("a2") = c;
    __asm__ volatile("ecall"
                     : "+r"(a0)
                     : "r"(a7), "r"(a1), "r"(a2)
                     : "memory");
    return a0;
}

static const char msg[] __attribute__((used)) = "gdb-hi\n";

__attribute__((noinline)) int main(void) {
    int s = 0;
    for (int i = 0; i < 10; i++) {
        s += i * 3;
    }
    sc3(64, 1, (long)msg, 7);
    return s;
}

void _start(void) {
    int r = main();
    sc3(93, r, 0, 0);
    for (;;) {}
}
"#;

fn have(cmd: &str) -> bool {
    Command::new(cmd).arg("--version").output().is_ok()
}

/// ホストの rust-lld。rustup 同梱の `gcc-ld/ld.lld` を探す。無ければ None。
fn lld() -> Option<PathBuf> {
    let out = Command::new("rustc").arg("-vV").output().ok()?;
    let info = String::from_utf8(out.stdout).ok()?;
    let host = info.lines().find_map(|l| l.strip_prefix("host: "))?;
    let out = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .ok()?;
    let sysroot = String::from_utf8(out.stdout).ok()?;
    let p = PathBuf::from(sysroot.trim()).join(format!("lib/rustlib/{host}/bin/gcc-ld/ld.lld"));
    p.is_file().then_some(p)
}

/// TOOL-GDB が riscv の対象記述を扱えるか。
fn gdb_has_riscv() -> bool {
    Command::new("gdb")
        .args(["-batch", "-ex", "set arch riscv:rv64"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn compile(dir: &Path, lld: &Path) -> PathBuf {
    let src = dir.join("gdb.c");
    let elf = dir.join("gdb.elf");
    std::fs::write(&src, SRC).unwrap();
    let status = Command::new("clang")
        .args([
            "--target=riscv64-linux-gnu",
            "-g",
            "-O0",
            "-nostdlib",
            "-static",
            "-fno-stack-protector",
            &format!("-fuse-ld={}", lld.display()),
            "-Wl,-e,_start",
            "-o",
        ])
        .arg(&elf)
        .arg(&src)
        .status()
        .expect("clang");
    assert!(status.success(), "clang riscv64 failed");
    elf
}

/// 直後に `run -g` が bind する空きポートを取る。
fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// `p/x` の出力 `$N = 0x...` の値の部分を取る。
fn dollar(text: &str, n: usize) -> Option<String> {
    let mark = format!("${n} = ");
    let at = text.find(&mark)? + mark.len();
    Some(text[at..].split_whitespace().next()?.to_string())
}

#[test]
fn gdb_break_step_regs() {
    if !have("clang") || !have("gdb") || !gdb_has_riscv() {
        eprintln!("clang か gdb（riscv 対応）がない。スキップ");
        return;
    }
    let Some(lld) = lld() else {
        eprintln!("rust-lld がない。スキップ");
        return;
    };
    let dir = std::env::temp_dir().join(format!("polyisa-gdbstub-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let elf = compile(&dir, &lld);
    let elf = elf.to_str().unwrap();

    // 接続の用意ができた合図は、子が stderr に出す待受けの行。
    let port = free_port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_polyisa-cli"))
        .args(["run", "-g", &port.to_string(), elf])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("polyisa");
    let mut banner = String::new();
    BufReader::new(child.stderr.take().unwrap())
        .read_line(&mut banner)
        .expect("banner");
    if !banner.contains("gdb") {
        let _ = child.kill();
        panic!("待受けの行がない: {banner}");
    }

    let script = [
        "set confirm off".to_string(),
        "set remotetimeout 30".to_string(),
        format!("target remote :{port}"),
        "break main".to_string(),
        "c".to_string(),
        "info registers pc x10".to_string(),
        "p/x $pc".to_string(),
        "si".to_string(),
        "p/x $pc".to_string(),
        "set $x10 = 0x5a".to_string(),
        "p/x $x10".to_string(),
        "x/2i $pc".to_string(),
        "kill".to_string(),
    ];
    let mut gdb = Command::new("gdb");
    gdb.arg("-batch");
    for s in &script {
        gdb.args(["-ex", s]);
    }
    let out = gdb.arg(elf).output().expect("gdb");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // gdb の kill を受けて serve が戻り exit するのを待ち、終了しなければ殺す。
    let mut st = None;
    for _ in 0..50 {
        if let Some(s) = child.try_wait().expect("child try_wait") {
            st = Some(s);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let st = match st {
        Some(s) => s,
        None => {
            let _ = child.kill();
            child.wait().expect("child wait")
        }
    };

    assert!(out.status.success(), "gdb が異常終了:\n{text}");
    assert!(st.success(), "polyisa が異常終了（{st}）:\n{text}");
    // target remote の直後に止まった枠（_start）が出て、
    // break main → c でブレークポイントに止まる。
    assert!(text.contains("_start"), "{text}");
    assert!(text.contains("Breakpoint 1"), "{text}");
    assert!(text.contains("main"), "{text}");
    // レジスタの読み出し（pc と x10 の行が出る）。
    assert!(text.contains("x10"), "{text}");
    // si の前後で pc が変わる。
    let (before, after) = (dollar(&text, 1), dollar(&text, 2));
    assert!(
        before.is_some() && after.is_some(),
        "pc の表示がない:\n{text}"
    );
    assert_ne!(before, after, "si で pc が変わっていない:\n{text}");
    // P パケットの書き込みが読み出しに戻る。
    assert_eq!(dollar(&text, 3).as_deref(), Some("0x5a"), "{text}");
    // 逆アセンブルの結果（`=>` は現在位置の印）。
    assert!(text.contains("=>"), "{text}");
}
