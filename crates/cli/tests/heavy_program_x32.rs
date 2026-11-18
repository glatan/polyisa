// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! x32（ILP32 の x86-64）静的 glibc バイナリを実行する（層7・program）。
//!
//! x32 の公式配布バイナリはないので、検証コンテナの GCC-X32
//! （TOOL-GCC-X32、`x86_64-linux-gnux32-gcc-14`）でテスト時にビルドする。
//! glibc の初期化は AT_RANDOM・AT_PAGESZ・AT_EXECFN を読み、x32 の
//! システムコール番号（`__X32_SYSCALL_BIT`）と ILP32 構造体を使う。

use std::path::{Path, PathBuf};
use std::process::Command;

const SRC: &str = r#"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/time.h>

int main(int argc, char **argv) {
    printf("x32-hello\n");
    printf("ptr=%zu long=%zu llong=%zu off=%zu\n",
           sizeof(void *), sizeof(long), sizeof(long long), sizeof(off_t));
    printf("argc=%d argv0=%s\n", argc, argv[0]);
    printf("getpid=%ld\n", syscall(SYS_getpid));
    char *buf = (char *)__builtin_alloca(64);
    memset(buf, 'A', 32);
    buf[32] = 0;
    printf("alloca=%s\n", buf);
    struct timeval tv;
    struct timezone tz;
    gettimeofday(&tv, &tz);
    printf("gtod=%ld\n", (long)tv.tv_sec);
    return 42;
}
"#;

fn gcc() -> &'static str {
    "x86_64-linux-gnux32-gcc-14"
}

fn compile(dir: &Path) -> PathBuf {
    let src = dir.join("x32prog.c");
    let elf = dir.join("x32prog");
    std::fs::write(&src, SRC).unwrap();
    let status = Command::new(gcc())
        .args(["-O2", "-mx32", "-static", "-o"])
        .arg(&elf)
        .arg(&src)
        .status()
        .expect("x32 gcc");
    assert!(status.success(), "{} failed", gcc());
    // 生成物が ELFCLASS32 + EM_X86_64 の x32 像であることを確認する。
    // x86-64 ELF ができていたらこのテストの前提が壊れる。
    let b = std::fs::read(&elf).unwrap();
    assert_eq!(b[4], 1, "ELFCLASS32");
    assert_eq!(u16::from_le_bytes([b[18], b[19]]), 62, "EM_X86_64");
    elf
}

/// 静的 glibc の x32 バイナリが初期化から終了まで通る。
/// ILP32 の幅・argv・getpid・alloca・gettimeofday を出力で pin する。
#[test]
fn static_glibc_x32_hello() {
    let dir = std::env::temp_dir().join(format!("polyisa-x32-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let elf = compile(&dir);
    let path = elf.to_str().unwrap();
    let argv: Vec<String> = vec!["arg".to_string()];
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_x32_captured(path, &argv)
        .unwrap_or_else(|e| panic!("run: {e}"));
    // argv[0] は実行パス、argc は実行パス+引数。gettimeofday の秒は
    // 仮想環境の固定時刻（946688400、実装が返す定数）。
    let expect = format!(
        "x32-hello\nptr=4 long=4 llong=8 off=8\nargc=2 argv0={path}\ngetpid=1\nalloca=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\ngtod=946688400\n"
    );
    assert_eq!(out, expect.into_bytes(), "stdout");
    assert_eq!(code, 42, "exit code");
}
