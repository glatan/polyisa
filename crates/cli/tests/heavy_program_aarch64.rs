// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! AArch64 の静的 ELF が write/exit_group で "hi\n" を返す（層7・program）。
//!
//! clang の aarch64-linux-gnu ターゲットで `-nostdlib -static` にコンパイルする。
//! 出典は TOOL-LLVM と SRC-LINUX (7.3) の asm-generic 番号（write=64、
//! exit_group=94）。

use std::path::{Path, PathBuf};
use std::process::Command;

use polyisa_cli::run_aarch64::{run_elf_aarch64_sys, run_elf_aarch64_sys_root};
use polyisa_os_linux::aarch64::sys::Linux;

const SRC: &str = r#"
const char msg[] __attribute__((used)) = "hi\n";

__attribute__((naked, noreturn)) void _start(void) {
    __asm__ volatile(
        "mov x8, #64\n"
        "mov x0, #1\n"
        "adr x1, msg\n"
        "mov x2, #3\n"
        "svc #0\n"
        "mov x8, #94\n"
        "mov x0, #0\n"
        "svc #0\n");
}
"#;

/// 再帰呼び出し・条件分岐・スタック操作を使う版。fib(10)=55 を十進で書く。
/// `stp`/`ldp`/`bl`/`ret`/`b.cond`/`subs`/`cbz` 系を通す。
const SRC_FIB: &str = r#"
long fib(long n) {
    if (n < 2) return n;
    return fib(n - 1) + fib(n - 2);
}

static int put(long n, char *p) {
    char tmp[24];
    int i = 0;
    if (n == 0) {
        *p++ = '0';
        return 1;
    }
    while (n) {
        tmp[i++] = '0' + (int)(n % 10);
        n /= 10;
    }
    int k = 0;
    while (i) *p++ = tmp[--i], k++;
    return k;
}

char buf[32];

void _start(void) {
    long v = fib(10);
    int n = put(v, buf);
    buf[n] = '\n';
    // %x0 の取り込みは先頭で行う（x8/x1 をあとで上書きするため）。
    __asm__ volatile(
        "mov x2, %x0\n"
        "mov x8, #64\n"
        "mov x0, #1\n"
        "adr x1, buf\n"
        "svc #0\n"
        "mov x8, #94\n"
        "mov x0, #0\n"
        "svc #0\n" ::"r"((long)(n + 1)));
}
"#;

fn lld() -> PathBuf {
    let out = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .expect("rustc");
    let sysroot = String::from_utf8(out.stdout).expect("sysroot utf-8");
    PathBuf::from(sysroot.trim()).join("lib/rustlib/x86_64-unknown-linux-gnu/bin/gcc-ld/ld.lld")
}

fn compile(dir: &Path, lld: &Path, name: &str, source: &str) -> PathBuf {
    let src = dir.join(format!("{name}.c"));
    let elf = dir.join(format!("{name}.elf"));
    std::fs::write(&src, source).unwrap();
    let status = Command::new("clang")
        .args([
            "--target=aarch64-linux-gnu",
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
    assert!(status.success(), "clang aarch64 failed");
    elf
}

#[test]
fn generic_prints_hi() {
    let lld = lld();
    assert!(
        lld.is_file(),
        "rust-lld が {} に必要。TOOL-RUST のリンカを使う。",
        lld.display()
    );
    let dir = std::env::temp_dir().join("polyisa-heavy-program-aarch64");
    std::fs::create_dir_all(&dir).unwrap();
    let elf = compile(&dir, &lld, "aarch64-hello", SRC);
    let mut sys = Linux::default();
    let code = run_elf_aarch64_sys(elf.to_str().unwrap(), &[], None, &mut sys)
        .unwrap_or_else(|e| panic!("aarch64: {e}"));
    assert_eq!(code, 0);
    assert_eq!(sys.io.stdout, b"hi\n");
}

#[test]
fn fib_recursion_prints_55() {
    let lld = lld();
    assert!(lld.is_file(), "rust-lld が必要。TOOL-RUST のリンカを使う。");
    let dir = std::env::temp_dir().join("polyisa-heavy-program-aarch64");
    std::fs::create_dir_all(&dir).unwrap();
    let elf = compile(&dir, &lld, "aarch64-fib", SRC_FIB);
    let mut sys = Linux::default();
    let code = run_elf_aarch64_sys(elf.to_str().unwrap(), &[], None, &mut sys)
        .unwrap_or_else(|e| panic!("aarch64 fib: {e}"));
    assert_eq!(code, 0);
    assert_eq!(sys.io.stdout, b"55\n");
}

/// 台帳 BIN-DISTRO-AARCH64（Alpine minirootfs、musl + BusyBox 1.37、動的）
/// のコマンド群をゲストルートで走らせる。PT_INTERP → ld-musl の経路、
/// 絶対シンボリックリンクの解決、getdents64 の位置管理を通る。
#[test]
fn distro_commands_via_guest_root() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.testdata/bin-distro-aarch64")
        .canonicalize()
        .unwrap_or_else(|e| panic!("bin-distro-aarch64: {e}"));
    assert!(
        root.join("bin/busybox").is_file() && root.join("lib/ld-musl-aarch64.so.1").is_file(),
        "BIN-DISTRO-AARCH64 を {} に置く。リポジトリには含めない。",
        root.display()
    );
    // root 指定時、ELF のパスはゲストの名前空間で解釈される。
    let bb = "/bin/busybox";
    let root_s = root.to_str().unwrap();
    // (引数, 出力に含めるはずの断片)。--help は stderr 側に出す
    // アプレットもあるので stdout+stderr をつないで探す。
    for (args, needle) in [
        (&["echo", "hi"][..], &b"hi\n"[..]),
        (&["uname", "-a"][..], b"polyisa aarch64"),
        (&["cat", "/etc/os-release"][..], b"ID=alpine"),
        (&["ls", "/bin"][..], b"busybox"),
        (&["--help"][..], b"BusyBox"),
    ] {
        let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let mut sys = Linux::default();
        let code = run_elf_aarch64_sys_root(bb, &argv, None, &mut sys, Some(root_s))
            .unwrap_or_else(|e| panic!("{}: {e}", args.join(" ")));
        assert_eq!(code, 0, "{}", args.join(" "));
        let mut both = sys.io.stdout.clone();
        both.extend_from_slice(&sys.io.stderr);
        assert!(
            both.windows(needle.len()).any(|w| w == needle),
            "{}: 出力に {:?} を含まない: {:?}",
            args.join(" "),
            String::from_utf8_lossy(needle),
            String::from_utf8_lossy(&both[..both.len().min(400)])
        );
    }
    // /bin/echo は /bin/busybox への絶対リンク。ゲストルート内で解決し、
    // argv[0] の basename から echo アプレットが起動する。
    let mut sys = Linux::default();
    let argv = vec!["via-link".to_string()];
    let code = run_elf_aarch64_sys_root("/bin/echo", &argv, None, &mut sys, Some(root_s))
        .unwrap_or_else(|e| panic!("echo: {e}"));
    assert_eq!(code, 0);
    assert_eq!(sys.io.stdout, b"via-link\n");
}
