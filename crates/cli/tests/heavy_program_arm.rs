// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! ARM（EABI・A32）の静的 ELF が write/exit_group で "hi\n" を返す
//! （層7・program、S7-1）。
//!
//! clang の armv7-linux-gnueabihf ターゲットで `-nostdlib -static` に
//! コンパイルする。配布物は台帳 BIN-DISTRO-ARMV5L / BIN-DISTRO-ARMV7L
//! （BusyBox 1.31.0、静的、musl）。
//! 出典は TOOL-LLVM と SRC-LINUX (7.3) の arm 番号（write=4、exit_group=248）。

use std::path::{Path, PathBuf};
use std::process::Command;

use polyisa_cli::run_arm::run_elf_arm_sys;
use polyisa_os_linux::arm::sys::Linux;

const SRC: &str = r#"
const char msg[] __attribute__((used)) = "hi\n";

__attribute__((naked, noreturn)) void _start(void) {
    __asm__ volatile(
        "mov r7, #4\n"
        "mov r0, #1\n"
        "ldr r1, =msg\n"
        "mov r2, #3\n"
        "svc #0\n"
        "mov r7, #248\n"
        "mov r0, #0\n"
        "svc #0\n");
}
"#;

/// 再帰・条件分岐・スタック・条件実行を使う版。fib(10)=55 を十進で書く。
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
    // -nostdlib では __aeabi_idiv が無いので除算は反復減算で書く。
    while (n) {
        long q = 0, r = n;
        while (r >= 10) {
            r -= 10;
            q++;
        }
        tmp[i++] = '0' + (int)r;
        n = q;
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
    register int len __asm__("r2") = n + 1;
    __asm__ volatile(
        "mov r7, #4\n"
        "mov r0, #1\n"
        "ldr r1, =buf\n"
        "svc #0\n"
        "mov r7, #248\n"
        "mov r0, #0\n"
        "svc #0\n" ::"r"(len));
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
            "--target=armv7-linux-gnueabihf",
            "-marm",
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
    assert!(status.success(), "clang arm failed");
    elf
}

fn busybox(dir_name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../.testdata/{dir_name}/busybox"))
}

#[test]
fn generic_prints_hi() {
    let lld = lld();
    assert!(
        lld.is_file(),
        "rust-lld が {} に必要。TOOL-RUST のリンカを使う。",
        lld.display()
    );
    let dir = std::env::temp_dir().join("polyisa-heavy-program-arm");
    std::fs::create_dir_all(&dir).unwrap();
    let elf = compile(&dir, &lld, "arm-hello", SRC);
    let mut sys = Linux::new();
    let code = run_elf_arm_sys(elf.to_str().unwrap(), &[], None, &mut sys)
        .unwrap_or_else(|e| panic!("arm: {e}"));
    assert_eq!(code, 0);
    assert_eq!(sys.io.stdout, b"hi\n");
}

#[test]
fn fib_recursion_prints_55() {
    let lld = lld();
    assert!(lld.is_file(), "rust-lld が必要。TOOL-RUST のリンカを使う。");
    let dir = std::env::temp_dir().join("polyisa-heavy-program-arm");
    std::fs::create_dir_all(&dir).unwrap();
    let elf = compile(&dir, &lld, "arm-fib", SRC_FIB);
    let mut sys = Linux::new();
    let code = run_elf_arm_sys(elf.to_str().unwrap(), &[], None, &mut sys)
        .unwrap_or_else(|e| panic!("arm fib: {e}"));
    assert_eq!(code, 0);
    assert_eq!(sys.io.stdout, b"55\n");
}

/// 台帳 BIN-DISTRO-ARMV5L / BIN-DISTRO-ARMV7L（BusyBox 1.31.0、musl 静的）
/// のコマンド群を走らせる。EABI（r7=番号・svc #0）、条件実行、
/// LDM/STM、VFP を通る。
#[test]
fn distro_commands() {
    for dir_name in ["bin-distro-armv5l", "bin-distro-armv7l"] {
        let bb = busybox(dir_name);
        assert!(
            bb.is_file(),
            "{dir_name} を {} に置く。リポジトリには含めない。",
            bb.display()
        );
        let bb = bb.to_str().unwrap();
        for (args, needle) in [
            (&["echo", "hi"][..], &b"hi\n"[..]),
            (&["uname", "-a"][..], b"polyisa"),
            (&["uname", "-m"][..], b"arm"),
            (&["true"][..], b""),
            (&["basename", "/usr/bin/test"][..], b"test\n"),
            (&["dirname", "/usr/bin/test"][..], b"/usr/bin\n"),
            (&["seq", "3"][..], b"1\n2\n3\n"),
            (&["id"][..], b"uid=0(root)"),
            (&["whoami"][..], b"root\n"),
        ] {
            let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
            let mut sys = Linux::new();
            let code = run_elf_arm_sys(bb, &argv, None, &mut sys)
                .unwrap_or_else(|e| panic!("{dir_name} {}: {e}", args.join(" ")));
            assert_eq!(code, 0, "{dir_name} {}", args.join(" "));
            let mut both = sys.io.stdout.clone();
            both.extend_from_slice(&sys.io.stderr);
            assert!(
                needle.is_empty() || both.windows(needle.len()).any(|w| w == needle),
                "{dir_name} {}: 出力に {:?} を含まない: {:?}",
                args.join(" "),
                String::from_utf8_lossy(needle),
                String::from_utf8_lossy(&both[..both.len().min(400)])
            );
        }
        // VFP（hard-float ABI）を通る awk の浮動小数点。
        let argv = vec![
            "awk".to_string(),
            "BEGIN{printf \"%.3f\\n\", 1.5*2}".to_string(),
        ];
        let mut sys = Linux::new();
        let code = run_elf_arm_sys(bb, &argv, None, &mut sys)
            .unwrap_or_else(|e| panic!("{dir_name} awk: {e}"));
        assert_eq!(code, 0, "{dir_name} awk");
        assert_eq!(sys.io.stdout, b"3.000\n", "{dir_name} awk");
    }
}
