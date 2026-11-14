// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 一時プローブ: i386 BusyBox --list の全アプレットを無引数で走らせ、
//! 網羅率を測る。GAP-0022 の「網羅率を確認」用。

use std::path::PathBuf;
use std::process::Command;

fn busybox() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.join(".testdata/bin-distro-i386/busybox")
}

#[test]
fn applet_coverage_probe() {
    let path = busybox();
    assert!(path.is_file());
    let out = Command::new(&path)
        .arg("--list")
        .env_clear()
        .output()
        .expect("host --list");
    let applets: Vec<String> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    let mut ok = 0usize;
    let mut unimpl: Vec<(String, String)> = Vec::new();
    let mut limit: Vec<String> = Vec::new();
    let mut dead: Vec<String> = Vec::new();
    let mut other: Vec<(String, String)> = Vec::new();
    for name in &applets {
        let argv = [name.clone()];
        match polyisa_cli::run_x86::run_elf_x86_32_captured(path.to_str().unwrap(), &argv) {
            Ok(_) => ok += 1,
            Err(e) if e.starts_with("unimplemented") => unimpl.push((name.clone(), e)),
            Err(e) if e.starts_with("step limit") => limit.push(name.clone()),
            Err(e) if e == "deadlock" => dead.push(name.clone()),
            Err(e) => other.push((name.clone(), e)),
        }
    }
    eprintln!(
        "=== i386 applet coverage: {ok}/{} ran to exit ===",
        applets.len()
    );
    eprintln!("--- unimplemented ({}) ---", unimpl.len());
    for (n, e) in &unimpl {
        eprintln!("{n}: {e}");
    }
    eprintln!("--- step limit ({}) ---", limit.len());
    for n in &limit {
        eprintln!("{n}");
    }
    eprintln!("--- deadlock ({}) ---", dead.len());
    for n in &dead {
        eprintln!("{n}");
    }
    eprintln!("--- other ({}) ---", other.len());
    for (n, e) in &other {
        eprintln!("{n}: {e}");
    }
}
