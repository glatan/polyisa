// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! s390x の ELF が svc 0 の Linux ABI で "hi\n" を返す（層7・program、S11-2）。
//!
//! clang の s390x ターゲット（SystemZ バックエンド）で `-nostdlib -static`
//! にコンパイルする。s390x の Linux 番号は write=4、exit_group=248
//! （SRC-LINUX-S390-UAPI の syscall.tbl 系番号）で、呼出規約は
//! `svc 0`・番号 r1・引数 r2..r7・返り値 r2 である（SPEC-S390-ABI）。
//! 命令語・データともビッグエンディアンで可変長命令を通る。
//! 配布物は台帳 BIN-DISTRO-S390X（BusyBox 1.31.0、musl 静的、BE）。

use std::path::{Path, PathBuf};
use std::process::Command;

use polyisa_cli::run_s390::run_elf_s390_sys_root;
use polyisa_os_linux::s390::sys::Linux;

const SRC: &str = r#"
const char msg[] __attribute__((used)) = "hi\n";

__attribute__((naked, noreturn)) void _start(void) {
    __asm__ volatile(
        "lghi %r1,4\n"          // write
        "lghi %r2,1\n"
        "larl %r3,msg\n"
        "lghi %r4,3\n"
        "svc 0\n"
        "lghi %r1,248\n"        // exit_group
        "lghi %r2,0\n"
        "svc 0\n");
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
    register long len __asm__("4") = n + 1;
    __asm__ volatile(
        "lghi %%r1,4\n"
        "lghi %%r2,1\n"
        "larl %%r3,buf\n"
        "lgr %%r4,%0\n"
        "svc 0\n"
        "lghi %%r1,248\n"
        "lghi %%r2,0\n"
        "svc 0\n" ::"r"(len));
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
            "--target=s390x-ibm-linux-gnu",
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
    assert!(status.success(), "clang s390x failed");
    elf
}

fn busybox() -> PathBuf {
    // 台帳の配置は `.testdata/bin-distro-s390x`（ファイル直置き）。
    // argv[0] の basename がアプレット解決に使われるので、
    // `busybox` という名のシンボリックリンク経由で起動する。
    let real = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.testdata/bin-distro-s390x");
    assert!(
        real.is_file(),
        "bin-distro-s390x を {} に置く",
        real.display()
    );
    let dir = std::env::temp_dir().join("polyisa-heavy-program-s390");
    std::fs::create_dir_all(&dir).unwrap();
    let link = dir.join("busybox");
    if !link.exists() {
        polyisa_host::symlink(real.to_str().unwrap(), link.to_str().unwrap()).unwrap();
    }
    link
}

/// 静的 nostdlib ELF（BE）が write=4/exit_group=248 の ABI で "hi\n" を出す。
#[test]
fn generic_prints_hi() {
    let lld = lld();
    assert!(lld.is_file(), "rust-lld が {} に必要", lld.display());
    let dir = std::env::temp_dir().join("polyisa-heavy-program-s390");
    std::fs::create_dir_all(&dir).unwrap();
    let elf = compile(&dir, &lld, "s390-hello", SRC);
    let mut sys = Linux::new();
    let code = run_elf_s390_sys_root(elf.to_str().unwrap(), &[], None, &mut sys, None)
        .unwrap_or_else(|e| panic!("s390: {e}"));
    assert_eq!(code, 0);
    assert_eq!(sys.io.stdout, b"hi\n");
}

#[test]
fn fib_recursion_prints_55() {
    let lld = lld();
    assert!(lld.is_file(), "rust-lld が必要");
    let dir = std::env::temp_dir().join("polyisa-heavy-program-s390");
    std::fs::create_dir_all(&dir).unwrap();
    let elf = compile(&dir, &lld, "s390-fib", SRC_FIB);
    let mut sys = Linux::new();
    let code = run_elf_s390_sys_root(elf.to_str().unwrap(), &[], None, &mut sys, None)
        .unwrap_or_else(|e| panic!("s390 fib: {e}"));
    assert_eq!(code, 0);
    assert_eq!(sys.io.stdout, b"55\n");
}

/// 台帳 BIN-DISTRO-S390X（BusyBox 1.31.0、musl 静的、BE）。
/// 可変長フェッチ・BE メモリ・svc ABI・musl init を通る。
#[test]
fn distro_commands_static() {
    let bb = busybox();
    assert!(bb.is_file(), "bin-distro-s390x を {} に置く", bb.display());
    let bb = bb.to_str().unwrap();
    for (args, needle) in [
        (&["echo", "hi"][..], &b"hi\n"[..]),
        (&["uname", "-a"][..], &b"polyisa"[..]),
        (&["true"][..], &b""[..]),
        (&["basename", "/usr/bin/test"][..], &b"test\n"[..]),
        (&["dirname", "/usr/bin/test"][..], &b"/usr/bin\n"[..]),
        (&["whoami"][..], &b"root\n"[..]),
        (&["expr", "1", "+", "2"][..], &b"3\n"[..]),
        (&["cat", "/proc/sys/kernel/hostname"][..], &b""[..]),
        (&["wc", "-c", "/proc/version"][..], &b"/proc/version"[..]),
    ] {
        let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let mut sys = Linux::new();
        let code = run_elf_s390_sys_root(bb, &argv, None, &mut sys, None)
            .unwrap_or_else(|e| panic!("{}: {e}", args.join(" ")));
        assert_eq!(code, 0, "{}", args.join(" "));
        let mut both = sys.io.stdout.clone();
        both.extend_from_slice(&sys.io.stderr);
        assert!(
            needle.is_empty() || both.windows(needle.len()).any(|w| w == needle),
            "{}: 出力に {:?} を含まない: {:?}",
            args.join(" "),
            String::from_utf8_lossy(needle),
            String::from_utf8_lossy(&both[..both.len().min(400)])
        );
    }
}
