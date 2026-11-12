// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! S4-1 の枠。台帳の BIN-DISTRO（BusyBox 1.35.0、静的、x86_64、musl）の
//! `busybox --list` を読み、`df` を対象から外す。
//!
//! ゲストは空の環境変数で起動する。ホスト側の起動も環境変数を空にする。
//! アプレットの終了コードと標準出力は、このテストでは見ない。
//! バイナリはリポジトリに含めない。ファイルが無いときは失敗する。

use std::io::Write;
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
    let dcprog = dir.join("dcprog");
    std::fs::write(&dcprog, b"2 3 + p\n").unwrap();
    let dcprog_s = dcprog.to_str().expect("utf-8");
    let b64 = dir.join("b64");
    std::fs::write(&b64, b"YWIK\n").unwrap();
    let b64_s = b64.to_str().expect("utf-8");
    let gz = dir.join("f.gz");
    let gz_out = Command::new(path)
        .args(["gzip", "-c", f])
        .env_clear()
        .output()
        .expect("host gzip");
    std::fs::write(&gz, &gz_out.stdout).unwrap();
    let gz_s = gz.to_str().expect("utf-8");
    let bz = dir.join("f.bz2");
    let bz_out = Command::new(path)
        .args(["bzip2", "-c", f])
        .env_clear()
        .output()
        .expect("host bzip2");
    std::fs::write(&bz, &bz_out.stdout).unwrap();
    let bz_s = bz.to_str().expect("utf-8");
    let lzo = dir.join("f.lzo");
    let lzo_out = Command::new(path)
        .args(["lzop", "-c", f])
        .env_clear()
        .output()
        .expect("host lzop");
    std::fs::write(&lzo, &lzo_out.stdout).unwrap();
    let lzo_s = lzo.to_str().expect("utf-8");
    // BusyBox 1.35 の xz / lzma は展開専用。同じ 9 バイトから作ったストリームを埋め込む。
    let xz = dir.join("f.xz");
    std::fs::write(
        &xz,
        [
            253, 55, 122, 88, 90, 0, 0, 4, 230, 214, 180, 70, 4, 192, 13, 9, 33, 1, 22, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 95, 79, 51, 228, 1, 0, 8, 97, 98, 10, 99, 100, 10, 97, 98, 10, 0, 0, 0,
            0, 109, 228, 144, 139, 163, 56, 240, 229, 0, 1, 41, 9, 100, 146, 28, 29, 31, 182, 243,
            125, 1, 0, 0, 0, 0, 4, 89, 90,
        ],
    )
    .unwrap();
    let xz_s = xz.to_str().expect("utf-8");
    let lz = dir.join("f.lzma");
    std::fs::write(
        &lz,
        [
            93, 0, 0, 128, 0, 255, 255, 255, 255, 255, 255, 255, 255, 0, 48, 152, 125, 69, 251, 49,
            19, 221, 58, 16, 89, 254, 123, 255, 255, 55, 160, 0, 0,
        ],
    )
    .unwrap();
    let lz_s = lz.to_str().expect("utf-8");
    let zip = dir.join("f.zip");
    std::fs::write(
        &zip,
        [
            80, 75, 3, 4, 20, 0, 0, 0, 0, 0, 64, 78, 108, 93, 240, 116, 203, 232, 9, 0, 0, 0, 9, 0,
            0, 0, 1, 0, 0, 0, 102, 97, 98, 10, 99, 100, 10, 97, 98, 10, 80, 75, 1, 2, 20, 3, 20, 0,
            0, 0, 0, 0, 64, 78, 108, 93, 240, 116, 203, 232, 9, 0, 0, 0, 9, 0, 0, 0, 1, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 164, 129, 0, 0, 0, 0, 102, 80, 75, 5, 6, 0, 0, 0, 0, 1, 0, 1, 0,
            47, 0, 0, 0, 40, 0, 0, 0, 0, 0,
        ],
    )
    .unwrap();
    let zip_s = zip.to_str().expect("utf-8");
    let tar_path = dir.join("f.tar");
    let tar_ok = Command::new("tar")
        .current_dir(&dir)
        .args(["-cf", "f.tar", "f"])
        .status()
        .expect("host tar")
        .success();
    assert!(tar_ok);
    let tar_s = tar_path.to_str().expect("utf-8");
    let ar_path = dir.join("f.a");
    let ar_ok = Command::new("ar")
        .current_dir(&dir)
        .args(["cr", "f.a", "f"])
        .status()
        .expect("host ar")
        .success();
    assert!(ar_ok);
    let ar_s = ar_path.to_str().expect("utf-8");
    let cin = dir.join("cin");
    std::fs::create_dir(&cin).unwrap();
    std::fs::write(cin.join("f"), b"ab\n").unwrap();
    let names = Command::new("find")
        .current_dir(&cin)
        .arg(".")
        .output()
        .expect("host find");
    assert!(names.status.success());
    let mut cpio_child = Command::new("cpio")
        .current_dir(&cin)
        .args(["-o", "-H", "newc"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("host cpio");
    cpio_child
        .stdin
        .take()
        .expect("cpio stdin")
        .write_all(&names.stdout)
        .expect("cpio names");
    let archived = cpio_child.wait_with_output().expect("cpio wait");
    assert!(archived.status.success());
    let cpio_path = dir.join("f.cpio");
    std::fs::write(&cpio_path, &archived.stdout).unwrap();
    let cpio_s = cpio_path.to_str().expect("utf-8");
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
        &["base64", "-d", b64_s],
        &["dc", dcprog_s],
        &["ascii"],
        &["clear"],
        &["less", f],
        &["ed", f],
        &["rdev"],
        &["script"],
        &["sha3sum", f],
        &["awk", "{print}", f],
        &["seq", "1", "3"],
        &["od", f],
        &["grep", "ab", f],
        &["ls", f],
        &["more", f],
        &["xxd", f],
        &["uuencode", f],
        &["cryptpw", "secret", "sa"],
        &["pgrep", "nosuchname123"],
        &["gunzip", "-c", gz_s],
        &["bzcat", bz_s],
        &["bunzip2", "-c", bz_s],
        &["lzop", "-c", f],
        &["lzopcat", lzo_s],
        &["unlzop", "-c", lzo_s],
        &["xzcat", xz_s],
        &["unxz", "-c", xz_s],
        &["lzcat", lz_s],
        &["unlzma", "-c", lz_s],
        &["tar", "-tf", tar_s],
        &["ar", "t", ar_s],
        &["lzma", "-d", "-c", lz_s],
        &["xz", "-d", "-c", xz_s],
        &["unzip", "-l", zip_s],
        &["shuf", "-e", "only"],
        &["killall", "-l"],
        &["pkill", "nosuchname123"],
        &["mkpasswd", "secret", "sa"],
        &["kill", "-l"],
        &["pidof", "nosuchname123"],
        &["stat", "-c", "%s", f],
        &["du", "-b", f],
        &["fsck"],
        &["ipcalc", "-n", "10.0.0.1/24"],
        &["printenv"],
        &["which", "true"],
        &["install", "-m", "644", f, installed_s],
        &["truncate", "-s", "2", trunc_s],
        &["mountpoint", "/"],
        &["[", "-f", "nosuch123", "]"],
        &["findfs", "LABEL=nope"],
        &["envdir", f, "true"],
        &["cpio", "-t", "-F", cpio_s],
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

#[test]
fn file_ops_match_host() {
    // ゲストとホストは別の木を変える。同じパスだと先に作った側が EEXIST になる。
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let root = std::env::temp_dir().join(format!("polyisa-fileops-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let guest_dir = root.join("guest");
    let host_dir = root.join("host");
    std::fs::create_dir_all(&guest_dir).unwrap();
    std::fs::create_dir_all(&host_dir).unwrap();
    let pair = |guest_args: &[&str], host_args: &[&str]| {
        let argv: Vec<String> = guest_args.iter().map(|s| (*s).to_string()).collect();
        let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
            .unwrap_or_else(|e| panic!("{}: {e}", guest_args.join(" ")));
        let host = Command::new(path)
            .args(host_args)
            .env_clear()
            .output()
            .unwrap_or_else(|e| panic!("host {}: {e}", host_args[0]));
        assert_eq!(
            code,
            host.status.code().unwrap_or(1) as u64,
            "{}",
            guest_args[0]
        );
        assert_eq!(out.as_slice(), host.stdout.as_slice(), "{}", guest_args[0]);
    };
    let guest_made = guest_dir.join("made");
    let host_made = host_dir.join("made");
    pair(
        &["mkdir", guest_made.to_str().expect("utf-8")],
        &["mkdir", host_made.to_str().expect("utf-8")],
    );
    assert!(guest_made.is_dir());
    assert!(host_made.is_dir());
    pair(
        &["rmdir", guest_made.to_str().expect("utf-8")],
        &["rmdir", host_made.to_str().expect("utf-8")],
    );
    assert!(!guest_made.exists());
    assert!(!host_made.exists());
    let guest_file = guest_dir.join("f");
    let host_file = host_dir.join("f");
    std::fs::write(&guest_file, b"ab\n").unwrap();
    std::fs::write(&host_file, b"ab\n").unwrap();
    pair(
        &["rm", guest_file.to_str().expect("utf-8")],
        &["rm", host_file.to_str().expect("utf-8")],
    );
    assert!(!guest_file.exists());
    assert!(!host_file.exists());
    std::fs::write(&guest_file, b"ab\n").unwrap();
    std::fs::write(&host_file, b"ab\n").unwrap();
    pair(
        &["unlink", guest_file.to_str().expect("utf-8")],
        &["unlink", host_file.to_str().expect("utf-8")],
    );
    assert!(!guest_file.exists());
    assert!(!host_file.exists());
    std::fs::write(&guest_file, b"ab\n").unwrap();
    std::fs::write(&host_file, b"ab\n").unwrap();
    let guest_moved = guest_dir.join("g");
    let host_moved = host_dir.join("g");
    pair(
        &[
            "mv",
            guest_file.to_str().expect("utf-8"),
            guest_moved.to_str().expect("utf-8"),
        ],
        &[
            "mv",
            host_file.to_str().expect("utf-8"),
            host_moved.to_str().expect("utf-8"),
        ],
    );
    assert_eq!(std::fs::read(&guest_moved).unwrap(), b"ab\n");
    assert_eq!(std::fs::read(&host_moved).unwrap(), b"ab\n");
    assert!(!guest_file.exists());
    assert!(!host_file.exists());
    std::fs::write(&guest_file, b"ab\n").unwrap();
    std::fs::write(&host_file, b"ab\n").unwrap();
    let guest_link = guest_dir.join("l");
    let host_link = host_dir.join("l");
    pair(
        &[
            "ln",
            "-s",
            guest_file.to_str().expect("utf-8"),
            guest_link.to_str().expect("utf-8"),
        ],
        &[
            "ln",
            "-s",
            host_file.to_str().expect("utf-8"),
            host_link.to_str().expect("utf-8"),
        ],
    );
    assert_eq!(
        std::fs::read_link(&guest_link).unwrap(),
        guest_file.as_os_str()
    );
    assert_eq!(
        std::fs::read_link(&host_link).unwrap(),
        host_file.as_os_str()
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn dos2unix_matches_host() {
    // 標準出力は空で、変換したファイルが一致する。別の木へ書く。
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let root = std::env::temp_dir().join(format!("polyisa-dos2unix-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let guest_dir = root.join("guest");
    let host_dir = root.join("host");
    std::fs::create_dir_all(&guest_dir).unwrap();
    std::fs::create_dir_all(&host_dir).unwrap();
    let guest_crlf = guest_dir.join("crlf");
    let host_crlf = host_dir.join("crlf");
    std::fs::write(&guest_crlf, b"ab\r\ncd\r\n").unwrap();
    std::fs::write(&host_crlf, b"ab\r\ncd\r\n").unwrap();
    let guest_lf = guest_dir.join("lf");
    let host_lf = host_dir.join("lf");
    std::fs::write(&guest_lf, b"ab\ncd\n").unwrap();
    std::fs::write(&host_lf, b"ab\ncd\n").unwrap();
    let guest_args = ["dos2unix", guest_crlf.to_str().expect("utf-8")];
    let argv: Vec<String> = guest_args.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("dos2unix: {e}"));
    let host = Command::new(path)
        .args(["dos2unix", host_crlf.to_str().expect("utf-8")])
        .env_clear()
        .output()
        .expect("host dos2unix");
    assert_eq!(code, host.status.code().unwrap_or(1) as u64);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
    assert_eq!(std::fs::read(&guest_crlf).unwrap(), b"ab\ncd\n");
    assert_eq!(std::fs::read(&host_crlf).unwrap(), b"ab\ncd\n");
    let guest_args = ["unix2dos", guest_lf.to_str().expect("utf-8")];
    let argv: Vec<String> = guest_args.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("unix2dos: {e}"));
    let host = Command::new(path)
        .args(["unix2dos", host_lf.to_str().expect("utf-8")])
        .env_clear()
        .output()
        .expect("host unix2dos");
    assert_eq!(code, host.status.code().unwrap_or(1) as u64);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
    assert_eq!(std::fs::read(&guest_lf).unwrap(), b"ab\r\ncd\r\n");
    assert_eq!(std::fs::read(&host_lf).unwrap(), b"ab\r\ncd\r\n");
    let _ = std::fs::remove_dir_all(&root);
}
