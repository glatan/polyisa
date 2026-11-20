// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! S15-1 の枠。sparc64/sparc32 の ELF が `ta 0x6d`/`ta 0x10` の
//! Linux ABI で正しい出力を返す（層7・program）。
//!
//! 前半は clang の sparc64 ターゲットで `-nostdlib -static` に
//! コンパイルする（lld は elf32_sparc のエミュレーションを持たない
//! ので裸プログラムは sparc64 だけ）。後半は配布物の BusyBox 群を
//! 走らせ、終了コードと標準出力を固定値と照合する。
//!
//! 配布物は台帳 BIN-DISTRO-SPARC64（Debian-ports busybox-static
//! 1.38.0-3、静的 glibc）と BIN-DISTRO-SPARC（BusyBox 公式
//! 1.26.2、静的）。バイナリはリポジトリに含めない。
//!
//! 通る道筋: ELF ロード・初期スタック・遅延スロット・
//! レジスタウィンドウ（afl れ・不足・flushw）・V9 の ldxa/
//! ASI_PNF・FP ブロック ASI（stdfa 64B 転送）・最適化
//! strcmp/strchr（sethi のゼロ拡張を前提にする）・
//! getdents 系のスタック成長。
//!
//! 既知の外れ値:
//! - sparc32 の 1.26.2 ビルドは ls が常時カラー出力する
//!   （CONFIG_FEATURE_LS_COLOR）。ピン留めの出力にエスケープ
//!   列を含める。
//! - 1.3 MB 級のファイルを wc 系に通すと解釈実行の速度で
//!   数十秒かかる。対象は小さい入力に絞る。

use std::path::{Path, PathBuf};
use std::process::Command;

use polyisa_cli::run_sparc::{run_elf_sparc_captured, run_elf_sparc_captured_in};

/// `ta 0x6d` で write(4)=fd・buf・len、exit(1) を呼ぶ最小 ELF。
/// sparc64 の syscall 規約は番号 %g1・引数 %o0..%o5・戻り値 %o0。
const SRC_HI64: &str = r#"
const char msg[] __attribute__((used)) = "hi\n";

__attribute__((naked, noreturn)) void _start(void) {
    __asm__ volatile(
        "mov 4, %g1\n"          // write
        "mov 1, %o0\n"
        "sethi %hi(msg), %o1\n"
        "or %o1, %lo(msg), %o1\n"
        "mov 3, %o2\n"
        "ta 0x6d\n"
        "mov 1, %g1\n"          // exit
        "clr %o0\n"
        "ta 0x6d\n");
}
"#;

/// save/restore とウィンドウのあふれ・不足を踏む再帰版。
/// fib(10)=55 を十進で書く。
const SRC_FIB64: &str = r#"
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
    long len = n + 1;
    __asm__ volatile(
        "mov 4, %%g1\n"
        "mov 1, %%o0\n"
        "sethi %%hi(buf), %%o1\n"
        "or %%o1, %%lo(buf), %%o1\n"
        "mov %0, %%o2\n"
        "ta 0x6d\n"
        "mov 1, %%g1\n"
        "clr %%o0\n"
        "ta 0x6d\n" ::"r"(len));
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

fn compile64(dir: &Path, lld: &Path, name: &str, source: &str) -> PathBuf {
    let src = dir.join(format!("{name}.c"));
    let elf = dir.join(format!("{name}.elf"));
    std::fs::write(&src, source).unwrap();
    let status = Command::new("clang")
        .args([
            "--target=sparc64-unknown-linux-gnu",
            "-nostdlib",
            "-static",
            // PIC を切る。GOT22/GOT10 のリロケーションは
            // -nostdlib では GOT が置かれず残る。
            "-fno-pic",
            "-fno-stack-protector",
            "-O1",
            &format!("-fuse-ld={}", lld.display()),
            "-Wl,-e,_start",
            "-o",
        ])
        .arg(&elf)
        .arg(&src)
        .status()
        .expect("clang");
    assert!(status.success(), "clang sparc64 failed");
    elf
}

fn busybox(dir: &str, bin: &str) -> PathBuf {
    let real = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.testdata")
        .join(dir);
    let real = real.join(bin);
    assert!(
        real.is_file(),
        "bin-distro-{dir} を {} に置く",
        real.display()
    );
    real
}

fn run(path: &str, args: &[&str]) -> (u64, Vec<u8>) {
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    run_elf_sparc_captured(path, &argv).unwrap_or_else(|e| panic!("{}: {e}", args.join(" ")))
}

/// 静的 nostdlib ELF（sparc64、BE）が `ta 0x6d` の ABI で
/// "hi\n" を出す。
#[test]
fn s64_generic_prints_hi() {
    let lld = lld();
    assert!(lld.is_file(), "rust-lld が {} に必要", lld.display());
    let dir = std::env::temp_dir().join("polyisa-heavy-program-sparc");
    std::fs::create_dir_all(&dir).unwrap();
    let elf = compile64(&dir, &lld, "sparc64-hello", SRC_HI64);
    let (code, out) = run_elf_sparc_captured(elf.to_str().unwrap(), &[]).unwrap();
    assert_eq!(code, 0);
    assert_eq!(out, b"hi\n");
}

/// save/restore・ウィンドウのあふれ・不足・flushw を通る再帰。
#[test]
fn s64_fib_recursion_prints_55() {
    let lld = lld();
    assert!(lld.is_file(), "rust-lld が必要");
    let dir = std::env::temp_dir().join("polyisa-heavy-program-sparc");
    std::fs::create_dir_all(&dir).unwrap();
    let elf = compile64(&dir, &lld, "sparc64-fib", SRC_FIB64);
    let (code, out) = run_elf_sparc_captured(elf.to_str().unwrap(), &[]).unwrap();
    assert_eq!(code, 0);
    assert_eq!(out, b"55\n");
}

/// (argv, 期待終了コード, 期待標準出力) の行。
type Case<'a> = (&'a [&'a str], u64, &'a [u8]);

fn pinned(path: &Path, cases: &[Case]) {
    let path = path.to_str().expect("utf-8 path");
    for (args, code, out) in cases {
        let (got_code, got_out) = run(path, args);
        assert_eq!(got_code, *code, "{}: 終了コード", args.join(" "));
        assert_eq!(
            got_out,
            *out,
            "{}: 標準出力 {:?}",
            args.join(" "),
            String::from_utf8_lossy(&got_out)
        );
    }
}

/// 両 arch 共通で値が同じもの。`uname -a` のマシン名だけ異なる
/// ので `uname_out` で渡す。
fn common_cases(uname_out: &'static [u8]) -> Vec<Case<'static>> {
    vec![
        (&["true"], 0, b""),
        (&["false"], 1, b""),
        (&["echo", "hi"], 0, b"hi\n"),
        (&["echo", "-n", "hi"], 0, b"hi"),
        (&["printf", "x%d\n", "42"], 0, b"x42\n"),
        (&["uname", "-a"], 0, uname_out),
        (&["hostname"], 0, b"polyisa\n"),
        (&["basename", "/a/b.c"], 0, b"b.c\n"),
        (&["dirname", "/a/b"], 0, b"/a\n"),
        (&["expr", "2", "+", "3"], 0, b"5\n"),
        (&["id"], 0, b"uid=0(root) gid=0(root)\n"),
        (&["env"], 0, b""),
        (&["test", "-n", "x"], 0, b""),
        (&["test", "-z", "x"], 1, b""),
        (&["find", "/dev/null"], 0, b"/dev/null\n"),
        (&["head", "-c", "0", "/dev/null"], 0, b""),
        (&["sort", "/dev/null"], 0, b""),
        (&["wc", "-c", "/dev/null"], 0, b"0 /dev/null\n"),
        (
            &["md5sum", "/dev/null"],
            0,
            b"d41d8cd98f00b204e9800998ecf8427e  /dev/null\n",
        ),
        (
            &["sha1sum", "/dev/null"],
            0,
            b"da39a3ee5e6b4b0d3255bfef95601890afd80709  /dev/null\n",
        ),
    ]
}

/// 台帳 BIN-DISTRO-SPARC64（busybox-static 1.38.0-3、静的 glibc、BE）。
/// 遅延スロット・ウィンドウ・`ta 0x6d` ABI・V9 の最適化
/// 文字列関数（ldxa ASI_PNF・stdfa ブロックストア・sethi ゼロ拡張
/// 依存の strcmp）を通る。
#[test]
fn sparc64_distro_commands_static() {
    let bb = busybox("bin-distro-sparc64", "busybox");
    let mut cases = common_cases(b"Linux polyisa 6.19.0 #1 polyisa sparc64 GNU/Linux\n");
    cases.extend([
        (&["uname", "-m"][..], 0, &b"sparc64\n"[..]),
        (&["ls", "/dev/null"][..], 0, &b"/dev/null\n"[..]),
    ]);
    pinned(&bb, &cases);
}

/// 台帳 BIN-DISTRO-SPARC（busybox 1.26.2、静的、BE）。sparc32 の
/// `ta 0x10` ABI・V8 ウィンドウ・32 ビット ELF ロードを通る。
/// このビルドの ls は常時カラー（CONFIG_FEATURE_LS_COLOR）で、
/// 素のファイル名は \x1b[0;0m..\x1b[0m、ディレクトリは
/// \x1b[1;34m..\x1b[0m、キャラクタデバイスは \x1b[1;35m..\x1b[0m
/// で囲まれる。
#[test]
fn sparc32_distro_commands_static() {
    let bb = busybox("bin-distro-sparc", "busybox");
    let mut cases = common_cases(b"Linux polyisa 6.19.0 #1 polyisa sparc GNU/Linux\n");
    cases.extend([
        (&["uname", "-m"][..], 0, &b"sparc\n"[..]),
        (
            &["ls", "/dev/null"][..],
            0,
            &b"\x1b[1;35m/dev/null\x1b[0m\n"[..],
        ),
    ]);
    pinned(&bb, &cases);
}

/// getopt32 のオプション照合（sparc64 glibc の最適化 strcmp は
/// `sethi %hi(0x80808080)` が上位 32 ビットをゼロ埋めすることを
/// 前提にする。ゼロ拡張でないと "ls -1" が --help と等価と誤判定
/// されて usage を返す）と getdents の出力を固定値と照合する。
#[test]
fn sparc64_ls_options_and_dents() {
    let dir = std::env::temp_dir().join("polyisa-heavy-sparc-ls");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("a"), b"").unwrap();
    std::fs::write(dir.join("b"), b"").unwrap();
    let bb = busybox("bin-distro-sparc64", "busybox");
    let bb = bb.to_str().unwrap();
    let d = dir.to_str().unwrap();
    for (args, out) in [
        (vec!["ls", "-1", d], b"a\nb\n".to_vec()),
        (vec!["ls", "-a", d], b".\n..\na\nb\n".to_vec()),
    ] {
        let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let (code, got) =
            run_elf_sparc_captured(bb, &argv).unwrap_or_else(|e| panic!("{args:?}: {e}"));
        assert_eq!(code, 0, "{args:?}");
        assert_eq!(got, out, "{args:?}");
    }
    // -l はサイズ 0 の空ファイルが total 0 の行を出す。inode や
    // 日付は環境で揺れるので先頭行だけ固定する。
    let argv: Vec<String> = ["ls", "-l", d].iter().map(|s| (*s).to_string()).collect();
    let (code, got) = run_elf_sparc_captured(bb, &argv).unwrap();
    assert_eq!(code, 0);
    assert!(
        got.starts_with(b"total 0\n"),
        "ls -l の先頭行: {:?}",
        String::from_utf8_lossy(&got)
    );
}

/// 標準入力経由の読み取り。`wc -l` は改行の数を数える。
#[test]
fn stdin_commands_match() {
    for dir in ["bin-distro-sparc64", "bin-distro-sparc"] {
        let bb = busybox(dir, "busybox");
        let bb = bb.to_str().unwrap();
        let argv: Vec<String> = ["wc", "-l"].iter().map(|s| (*s).to_string()).collect();
        let (code, out) = run_elf_sparc_captured_in(bb, &argv, b"a\nb\nc\n").unwrap();
        assert_eq!(code, 0);
        assert_eq!(out, b"3\n", "{dir}: wc -l stdin");
    }
}
