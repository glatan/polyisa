// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! wasm32 ホストの実行検査（S28-4）。
//!
//! `polyisa-cli` を wasm32-wasip1・wasip2・wasip3 でビルドし、実行器の
//! wasmtime（TOOL-WASMTIME）上で `run` が RV64 ゲストをインタプリタで
//! 実行して標準出力まで届くことを確かめる。ツールやターゲットの
//! 標準ライブラリが無い環境では何もしない（用意した環境での判定）。
//!
//! 使う資料は台帳 SPEC-WASI-P1/P2/P3 と TOOL-WASMTIME。

use std::path::Path;
use std::process::Command;

const TARGETS: [&str; 3] = ["wasm32-wasip1", "wasm32-wasip2", "wasm32-wasip3"];

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
}

fn bin(names: &[&str]) -> Option<String> {
    names
        .iter()
        .copied()
        .find(|n| {
            Command::new(n)
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        })
        .map(String::from)
}

fn has_target(target: &str) -> bool {
    Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .ok()
        .map(|o| {
            let sys = String::from_utf8_lossy(&o.stdout).trim().to_string();
            Path::new(&sys)
                .join("lib/rustlib")
                .join(target)
                .join("lib")
                .exists()
        })
        .unwrap_or(false)
}

/// 手組み RV64 ELF（64LE・LOAD1件）。`write(1, "hi\n", 3)` と
/// `exit_group(0)` だけを行う。guests/riscv の heavy_program_hello と
/// 同じ命令列で、e_type・e_machine・e_version を正規の値に揃えたもの。
fn hello_elf() -> Vec<u8> {
    const BASE: u64 = 0x1_0000;
    let addi = |rd: u32, rs1: u32, imm: i32| -> u32 {
        (((imm as u32) & 0xfff) << 20) | ((rs1 & 31) << 15) | ((rd & 31) << 7) | 0x13
    };
    let code: [u32; 9] = [
        addi(10, 0, 1),
        0x0000_0597,
        0x0205_8593,
        addi(12, 0, 3),
        addi(17, 0, 64),
        0x0000_0073,
        addi(10, 0, 0),
        addi(17, 0, 94),
        0x0000_0073,
    ];
    let data = b"hi\n";
    let filesz = 64 + 56 + code.len() * 4 + data.len();
    let mut v = vec![0u8; filesz];
    v[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    v[4] = 2;
    v[5] = 1;
    v[6] = 1;
    v[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    v[18..20].copy_from_slice(&243u16.to_le_bytes()); // EM_RISCV
    v[20..24].copy_from_slice(&1u32.to_le_bytes()); // EV_CURRENT
    v[24..32].copy_from_slice(&(BASE + 120).to_le_bytes());
    v[32..40].copy_from_slice(&64u64.to_le_bytes());
    v[52..54].copy_from_slice(&64u16.to_le_bytes());
    v[54..56].copy_from_slice(&56u16.to_le_bytes());
    v[56..58].copy_from_slice(&1u16.to_le_bytes());
    let p = 64;
    v[p..p + 4].copy_from_slice(&1u32.to_le_bytes());
    v[p + 4..p + 8].copy_from_slice(&7u32.to_le_bytes());
    v[p + 16..p + 24].copy_from_slice(&BASE.to_le_bytes());
    v[p + 32..p + 40].copy_from_slice(&(filesz as u64).to_le_bytes());
    v[p + 40..p + 48].copy_from_slice(&(filesz as u64).to_le_bytes());
    v[p + 48..p + 56].copy_from_slice(&0x1000u64.to_le_bytes());
    let mut off = 64 + 56;
    for w in code {
        v[off..off + 4].copy_from_slice(&w.to_le_bytes());
        off += 4;
    }
    v[off..off + data.len()].copy_from_slice(data);
    v
}

#[test]
fn wasip_run_hello() {
    let Some(wasmtime) = bin(&["wasmtime"]) else {
        return;
    };
    let dir = std::env::temp_dir().join("polyisa-host-wasi");
    std::fs::create_dir_all(&dir).unwrap();
    let elf = dir.join("hello.elf");
    std::fs::write(&elf, hello_elf()).unwrap();
    for target in TARGETS {
        if !has_target(target) {
            continue;
        }
        let st = Command::new(env!("CARGO"))
            .args(["build", "-p", "polyisa-cli", "--target", target])
            .current_dir(root())
            .output()
            .unwrap();
        assert!(
            st.status.success(),
            "{target}: cargo build に失敗: {}",
            String::from_utf8_lossy(&st.stderr)
        );
        let wasm = root()
            .join("target")
            .join(target)
            .join("debug")
            .join("polyisa-cli.wasm");
        let guest = format!("{}::/tmp", dir.display());
        let st = Command::new(&wasmtime)
            .args([
                "run",
                "--dir",
                &guest,
                wasm.to_str().unwrap(),
                "run",
                "/tmp/hello.elf",
            ])
            .output()
            .unwrap();
        assert!(
            st.status.success(),
            "{target}: wasmtime run に失敗: {}",
            String::from_utf8_lossy(&st.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&st.stdout),
            "hi\n",
            "{target}: 出力が違う"
        );
    }
}
