// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Power（ppc64）の ELF が write/exit_group で "hi\n" を返す（層7・program、S8-1）。
//!
//! clang の powerpc64le-linux-gnu ターゲットで `-nostdlib -static` に
//! コンパイルする。ppc64 の Linux 番号は write=4、exit_group=234
//! （SRC-LINUX-POWERPC-UAPI の syscall.tbl 系番号）。
//! 配布物は台帳 BIN-DISTRO-POWERPC64（BusyBox 1.31.0、musl 静的、BE）と
//! BIN-DISTRO-POWERPC64LE（Alpine 3.21.0 の BusyBox 1.37.0、musl 動的、
//! ELFv2・LE）。後者は PT_INTERP 経路の検証に `--root` 越しで走らせる。

use std::path::{Path, PathBuf};
use std::process::Command;

use polyisa_cli::run_power::run_elf_power_sys_root;
use polyisa_mem::Endian;
use polyisa_os_linux::power::sys::Linux;

const SRC: &str = r#"
const char msg[] __attribute__((used)) = "hi\n";

__attribute__((naked, noreturn)) void _start(void) {
    __asm__ volatile(
        "li 0, 4\n"          // write
        "li 3, 1\n"
        "lis 4, msg@ha\n"
        "addi 4, 4, msg@l\n"
        "li 5, 3\n"
        "sc\n"
        "li 0, 234\n"        // exit_group
        "li 3, 0\n"
        "sc\n");
}
"#;

/// 再帰・条件分岐・スタックを使う版。fib(10)=55 を十進で書く。
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
    // r5 = 長さ（write の第3引数）。レジスタ固定にして "r" 制約の
    // 割付で r3（fd）と衝突しないようにする。
    register long len __asm__("5") = n + 1;
    __asm__ volatile(
        "li 0, 4\n"
        "li 3, 1\n"
        "lis 4, buf@ha\n"
        "addi 4, 4, buf@l\n"
        "mr 5, %0\n"
        "sc\n"
        "li 0, 234\n"
        "li 3, 0\n"
        "sc\n" ::"r"(len));
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
            "--target=powerpc64le-linux-gnu",
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
    assert!(status.success(), "clang ppc64le failed");
    elf
}

fn busybox(dir_name: &str, rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../.testdata/{dir_name}/{rel}"))
}

/// 静的 nostdlib ELF（LE）が write=4/exit_group=234 の ABI で "hi\n" を出す。
#[test]
fn generic_prints_hi() {
    let lld = lld();
    assert!(lld.is_file(), "rust-lld が {} に必要", lld.display());
    let dir = std::env::temp_dir().join("polyisa-heavy-program-power");
    std::fs::create_dir_all(&dir).unwrap();
    let elf = compile(&dir, &lld, "power-hello", SRC);
    let mut sys = Linux::new(Endian::Le);
    let code = run_elf_power_sys_root(elf.to_str().unwrap(), &[], None, &mut sys, None)
        .unwrap_or_else(|e| panic!("power: {e}"));
    assert_eq!(code, 0);
    assert_eq!(sys.io.stdout, b"hi\n");
}

#[test]
fn fib_recursion_prints_55() {
    let lld = lld();
    assert!(lld.is_file(), "rust-lld が必要");
    let dir = std::env::temp_dir().join("polyisa-heavy-program-power");
    std::fs::create_dir_all(&dir).unwrap();
    let elf = compile(&dir, &lld, "power-fib", SRC_FIB);
    let mut sys = Linux::new(Endian::Le);
    let code = run_elf_power_sys_root(elf.to_str().unwrap(), &[], None, &mut sys, None)
        .unwrap_or_else(|e| panic!("power fib: {e}"));
    assert_eq!(code, 0);
    assert_eq!(sys.io.stdout, b"55\n");
}

/// 台帳 BIN-DISTRO-POWERPC64（BusyBox 1.31.0、musl 静的、BE ELFv2）。
/// BE デコード・固定長フェッチ・legacy syscall 番号を通る。
#[test]
fn distro_commands_be_static() {
    let bb = busybox("bin-distro-powerpc64", "busybox");
    assert!(
        bb.is_file(),
        "bin-distro-powerpc64/busybox を {} に置く",
        bb.display()
    );
    let bb = bb.to_str().unwrap();
    for (args, needle) in [
        (&["echo", "hi"][..], &b"hi\n"[..]),
        (&["uname", "-a"][..], &b"polyisa"[..]),
        (&["true"][..], &b""[..]),
        (&["basename", "/usr/bin/test"][..], &b"test\n"[..]),
        (&["dirname", "/usr/bin/test"][..], &b"/usr/bin\n"[..]),
        (&["seq", "3"][..], &b"1\n2\n3\n"[..]),
        (&["whoami"][..], &b"root\n"[..]),
        (&["expr", "1", "+", "2"][..], &b"3\n"[..]),
        (&["cat", "/etc/os-release"][..], &b"NAME="[..]),
    ] {
        let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let mut sys = Linux::new(Endian::Be);
        let code = run_elf_power_sys_root(bb, &argv, None, &mut sys, None)
            .unwrap_or_else(|e| panic!("be {}: {e}", args.join(" ")));
        assert_eq!(code, 0, "be {}", args.join(" "));
        let mut both = sys.io.stdout.clone();
        both.extend_from_slice(&sys.io.stderr);
        assert!(
            needle.is_empty() || both.windows(needle.len()).any(|w| w == needle),
            "be {}: 出力に {:?} を含まない: {:?}",
            args.join(" "),
            String::from_utf8_lossy(needle),
            String::from_utf8_lossy(&both[..both.len().min(400)])
        );
    }
}

/// 台帳 BIN-DISTRO-POWERPC64LE（musl 動的、ELFv2・LE）。PT_INTERP の
/// 動的ローダ経路と ldso 内の libc を通る。guest root を経由して
/// /lib/ld-musl-powerpc64le.so.1 を解決する。
#[test]
fn distro_commands_le_dynamic() {
    let root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.testdata/bin-distro-powerpc64le");
    assert!(root.is_dir(), "bin-distro-powerpc64le を置く");
    let root = root.to_str().unwrap().to_string();
    let bb = "/bin/busybox";
    for (args, needle) in [
        (&["uname", "-a"][..], &b"polyisa"[..]),
        (&["uname", "-m"][..], &b"ppc64le"[..]),
        (&["true"][..], &b""[..]),
        (&["basename", "/usr/bin/test"][..], &b"test\n"[..]),
        (&["dirname", "/usr/bin/test"][..], &b"/usr/bin\n"[..]),
        (&["seq", "3"][..], &b"1\n2\n3\n"[..]),
        (&["whoami"][..], &b"root\n"[..]),
        (&["printf", "%f", "1.5"][..], &b"1.500000"[..]),
        (&["cat", "/etc/os-release"][..], &b"NAME="[..]),
        (&["head", "-1", "/etc/os-release"][..], &b"NAME="[..]),
        (&["ls", "/bin/busybox"][..], &b"/bin/busybox"[..]),
    ] {
        let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let mut sys = Linux::new(Endian::Le);
        let code = run_elf_power_sys_root(bb, &argv, None, &mut sys, Some(root.as_str()))
            .unwrap_or_else(|e| panic!("le {}: {e}", args.join(" ")));
        assert_eq!(code, 0, "le {}", args.join(" "));
        let mut both = sys.io.stdout.clone();
        both.extend_from_slice(&sys.io.stderr);
        assert!(
            needle.is_empty() || both.windows(needle.len()).any(|w| w == needle),
            "le {}: 出力に {:?} を含まない: {:?}",
            args.join(" "),
            String::from_utf8_lossy(needle),
            String::from_utf8_lossy(&both[..both.len().min(400)])
        );
    }
}
