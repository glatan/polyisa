// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! S4-1 の枠。台帳の BIN-DISTRO（BusyBox 1.35.0、静的、x86_64、musl）の
//! `busybox --list` を読み、`df` を対象から外す。
//!
//! ゲストは空の環境変数で起動する。ホスト側の起動も環境変数を空にする。
//! アプレットの終了コードと標準出力は、このテストでは見ない。
//! バイナリはリポジトリに含めない。ファイルが無いときは失敗する。

use std::path::{Path, PathBuf};
use std::process::Command;

fn busybox() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.join(".testdata/bin-distro/busybox")
}

fn listed_applets(path: &Path) -> Vec<String> {
    let out = Command::new(path)
        .arg("--list")
        .env_clear()
        .output()
        .expect("busybox --list");
    assert!(
        out.status.success(),
        "busybox --list: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .expect("busybox --list は utf-8")
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

/// `--list` の全件から `df` だけを外した対象。件数は切り詰めない。
fn target_applets(listed: &[String]) -> Vec<&str> {
    listed
        .iter()
        .map(String::as_str)
        .filter(|name| *name != "df")
        .collect()
}

#[test]
fn list_excludes_only_df() {
    let path = busybox();
    assert!(
        path.is_file(),
        "BIN-DISTRO の BusyBox 1.35.0 を {} に置く。リポジトリには含めない。",
        path.display()
    );
    let listed = listed_applets(&path);
    assert_eq!(listed.len(), 402, "BIN-DISTRO 1.35.0 の --list は 402 件");
    assert_eq!(listed.iter().filter(|name| *name == "df").count(), 1);
    let target = target_applets(&listed);
    assert_eq!(target.len(), 401);
    assert!(target.iter().all(|name| *name != "df"));
}

#[test]
fn true_echo_uname_id_match() {
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let pinned: &[(&[&str], &[u8])] = &[
        (
            &["uname", "-a"],
            b"Linux localhost 6.0.0 #1 x86_64 GNU/Linux\n",
        ),
        (&["id"], b"uid=0(root) gid=0(root) groups=0(root)\n"),
    ];
    for (args, expect) in pinned {
        let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
            .unwrap_or_else(|e| panic!("{}: {e}", args.join(" ")));
        assert_eq!(code, 0, "{}", args.join(" "));
        assert_eq!(out.as_slice(), *expect, "{}", args.join(" "));
    }
    for args in [
        &["true"][..],
        &["echo", "hi"][..],
        &["basename", "/tmp/a"][..],
        &["dirname", "/tmp/a"][..],
    ] {
        let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
            .unwrap_or_else(|e| panic!("{}: {e}", args.join(" ")));
        let host = Command::new(path)
            .args(args)
            .env_clear()
            .output()
            .expect("host busybox");
        assert!(host.status.success(), "{}", args.join(" "));
        assert_eq!(code, 0, "{}", args.join(" "));
        assert_eq!(out.as_slice(), host.stdout.as_slice(), "{}", args.join(" "));
    }
}

#[test]
fn ls_one_file_matches_host() {
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let dir = std::env::temp_dir().join(format!("polyisa-ls-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("f"), b"ab\ncd\n").unwrap();
    let args = ["ls", dir.to_str().expect("utf-8")];
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("ls: {e}"));
    let host = Command::new(path)
        .args(args)
        .env_clear()
        .output()
        .expect("host ls");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(host.status.success());
    assert_eq!(code, 0);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
}

#[test]
fn wc_one_file_matches_host() {
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let dir = std::env::temp_dir().join(format!("polyisa-wc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let file = dir.join("f");
    std::fs::write(&file, b"ab\ncd\n").unwrap();
    let args = ["wc", file.to_str().expect("utf-8")];
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("wc: {e}"));
    let host = Command::new(path)
        .args(args)
        .env_clear()
        .output()
        .expect("host wc");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(host.status.success());
    assert_eq!(code, 0);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
}

#[test]
fn od_one_file_matches_host() {
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let dir = std::env::temp_dir().join(format!("polyisa-od-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let file = dir.join("f");
    std::fs::write(&file, b"ab\ncd\n").unwrap();
    let args = ["od", file.to_str().expect("utf-8")];
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("od: {e}"));
    let host = Command::new(path)
        .args(args)
        .env_clear()
        .output()
        .expect("host od");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(host.status.success());
    assert_eq!(code, 0);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
}

#[test]
fn sed_one_file_matches_host() {
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let dir = std::env::temp_dir().join(format!("polyisa-sed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let file = dir.join("f");
    std::fs::write(&file, b"ab\ncd\n").unwrap();
    let file_s = file.to_str().expect("utf-8");
    let args = ["sed", "s/a/A/", file_s];
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("sed: {e}"));
    let host = Command::new(path)
        .args(args)
        .env_clear()
        .output()
        .expect("host sed");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(host.status.success());
    assert_eq!(code, 0);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
}

#[test]
fn awk_print_matches_host() {
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let dir = std::env::temp_dir().join(format!("polyisa-awk-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let file = dir.join("f");
    std::fs::write(&file, b"ab\ncd\n").unwrap();
    let file_s = file.to_str().expect("utf-8");
    let args = ["awk", "{print}", file_s];
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("awk: {e}"));
    let host = Command::new(path)
        .args(args)
        .env_clear()
        .output()
        .expect("host awk");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(host.status.success());
    assert_eq!(code, 0);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
}

#[test]
fn xxd_one_file_matches_host() {
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let dir = std::env::temp_dir().join(format!("polyisa-xxd-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let file = dir.join("f");
    std::fs::write(&file, b"ab\ncd\n").unwrap();
    let args = ["xxd", file.to_str().expect("utf-8")];
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("xxd: {e}"));
    let host = Command::new(path)
        .args(args)
        .env_clear()
        .output()
        .expect("host xxd");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(host.status.success());
    assert_eq!(code, 0);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
}

#[test]
fn grep_one_file_matches_host() {
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let dir = std::env::temp_dir().join(format!("polyisa-grep-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let file = dir.join("f");
    std::fs::write(&file, b"ab\ncd\nab\n").unwrap();
    let file_s = file.to_str().expect("utf-8");
    let args = ["grep", "a", file_s];
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("grep: {e}"));
    let host = Command::new(path)
        .args(args)
        .env_clear()
        .output()
        .expect("host grep");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(host.status.success());
    assert_eq!(code, 0);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
}

#[test]
fn seq_one_to_three_matches_host() {
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let args = ["seq", "1", "3"];
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("seq: {e}"));
    let host = Command::new(path)
        .args(args)
        .env_clear()
        .output()
        .expect("host seq");
    assert!(host.status.success());
    assert_eq!(code, 0);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
}

#[test]
fn text_applets_match_host() {
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let dir = std::env::temp_dir().join(format!("polyisa-text-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let sub = dir.join("sub");
    std::fs::create_dir(&sub).unwrap();
    let file = dir.join("f");
    let other = dir.join("g");
    let tabs = dir.join("t");
    let bin = dir.join("bin");
    std::fs::write(&file, b"ab\ncd\nab\n").unwrap();
    std::fs::write(&other, b"ab\nxx\n").unwrap();
    std::fs::write(&tabs, b"hello world\n\thello\n").unwrap();
    std::fs::write(&bin, b"abc\0def\n").unwrap();
    std::fs::write(sub.join("f"), b"ab\ncd\nab\n").unwrap();
    let f = file.to_str().expect("utf-8");
    let g = other.to_str().expect("utf-8");
    let t = tabs.to_str().expect("utf-8");
    let binf = bin.to_str().expect("utf-8");
    let dir_s = dir.to_str().expect("utf-8");
    let copied = dir.join("copied");
    let touched = dir.join("touched");
    let trunc = dir.join("trunc");
    std::fs::write(&trunc, b"abcdef").unwrap();
    let trunc_s = trunc.to_str().expect("utf-8");
    let installed = dir.join("installed");
    let installed_s = installed.to_str().expect("utf-8");
    let dd_if = format!("if={f}");
    let copied_s = copied.to_str().expect("utf-8");
    let touched_s = touched.to_str().expect("utf-8");
    let link = dir.join("link");
    polyisa_host::symlink(f, link.to_str().expect("utf-8")).unwrap();
    let link_s = link.to_str().expect("utf-8");
    let cases: &[&[&str]] = &[
        &["cat", f],
        &["head", "-n", "2", f],
        &["tail", "-n", "1", f],
        &["uniq", f],
        &["cut", "-c1", f],
        &["cut", "-d", "a", "-f2", f],
        &["printf", "%s\n", "hi"],
        &["expr", "1", "+", "2"],
        &["rev", f],
        &["nl", f],
        &["paste", f, g],
        &["comm", f, g],
        &["expand", t],
        &["fold", "-w", "4", t],
        &["tac", f],
        &["cksum", f],
        &["sum", f],
        &["base64", f],
        &["strings", binf],
        &["md5sum", f],
        &["sha256sum", f],
        &["sha512sum", f],
        &["hexdump", "-C", f],
        &["find", dir_s, "-name", "f"],
        &["test", "-f", f],
        &["cmp", f, f],
        &["sort", f],
        &["fgrep", "ab", f],
        &["false"],
        &["pwd"],
        &["factor", "12"],
        &["unexpand", t],
        &["egrep", "a.", f],
        &["env"],
        &["sha1sum", f],
        &["wc", "-c", f],
        &["printf", "%x\n", "255"],
        &["arch"],
        &["uniq", "-c", f],
        &["sleep", "0"],
        &["nproc"],
        &["cp", f, copied_s],
        &["touch", touched_s],
        &["chmod", "644", f],
        &["wc", "-l", f],
        &["date", "-u", "-d", "@0", "+%s"],
        &["readlink", link_s],
        &["cmp", f, g],
        &["diff", "-q", f, g],
        &["cal", "1", "2000"],
        &["logname"],
        &["tty"],
        &["base32", f],
        &["crc32", f],
        &["hd", f],
        &["gzip", "-c", f],
        &["bzip2", "-c", f],
        &["dd", dd_if.as_str(), "bs=2", "count=2"],
        &["basename", f],
        &["dirname", f],
        &["getopt", "-o", "a", "--", "-a"],
        &["hostid"],
        &["usleep", "0"],
        &["bc"],
        &["sync"],
        &["sed", "/cd/d", f],
        &["printenv"],
        &["which", "true"],
        &["install", "-m", "644", f, installed_s],
        &["truncate", "-s", "2", trunc_s],
    ];
    for args in cases {
        let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
            .unwrap_or_else(|e| panic!("{}: {e}", args.join(" ")));
        let host = Command::new(path)
            .args(*args)
            .env_clear()
            .output()
            .unwrap_or_else(|e| panic!("host {}: {e}", args[0]));
        assert_eq!(
            code,
            host.status.code().unwrap_or(1) as u64,
            "{}",
            args.join(" ")
        );
        assert_eq!(out.as_slice(), host.stdout.as_slice(), "{}", args.join(" "));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn link_matches_host() {
    // ゲストとホストは別の木を変える。同じパスだと先に作った側が EEXIST になる。
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let root = std::env::temp_dir().join(format!("polyisa-link-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let guest_dir = root.join("guest");
    let host_dir = root.join("host");
    std::fs::create_dir_all(&guest_dir).unwrap();
    std::fs::create_dir_all(&host_dir).unwrap();
    let guest_src = guest_dir.join("f");
    let host_src = host_dir.join("f");
    std::fs::write(&guest_src, b"ab\n").unwrap();
    std::fs::write(&host_src, b"ab\n").unwrap();
    let guest_dst = guest_dir.join("hard");
    let host_dst = host_dir.join("hard");
    let args = [
        "link",
        guest_src.to_str().expect("utf-8"),
        guest_dst.to_str().expect("utf-8"),
    ];
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("link: {e}"));
    let host = Command::new(path)
        .args([
            "link",
            host_src.to_str().expect("utf-8"),
            host_dst.to_str().expect("utf-8"),
        ])
        .env_clear()
        .output()
        .expect("host link");
    assert_eq!(code, host.status.code().unwrap_or(1) as u64);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
    assert_eq!(std::fs::read(&guest_dst).unwrap(), b"ab\n");
    assert_eq!(std::fs::read(&host_dst).unwrap(), b"ab\n");
    let _ = std::fs::remove_dir_all(&root);
}
