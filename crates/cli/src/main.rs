// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `polyisa` コマンドの入口。機構は各クレートが持つ。

#![forbid(unsafe_code)]

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match polyisa_cli::parse_command(&args) {
        polyisa_cli::Command::Run => {
            // `run [--cpu <ファミリ>:<モデル>[,+機能,-機能]] <elf> [args...]`。
            // `--cpu` はゲストの引数と混ざらないよう elf の前に置く。
            let mut rest = &args[1..];
            let mut cpu = None;
            if let Some(v) = rest.first().and_then(|a| a.strip_prefix("--cpu=")) {
                cpu = Some(v.to_string());
                rest = &rest[1..];
            } else if rest.first().map(String::as_str) == Some("--cpu") {
                let Some(v) = rest.get(1) else {
                    eprintln!("usage: polyisa run [--cpu <ファミリ>:<モデル>] <elf> [args...]");
                    std::process::exit(2);
                };
                cpu = Some(v.clone());
                rest = &rest[2..];
            }
            let Some(path) = rest.first() else {
                eprintln!("usage: polyisa run [--cpu <ファミリ>:<モデル>] <elf> [args...]");
                std::process::exit(2);
            };
            match polyisa_cli::run_path_with(path, &rest[1..], cpu.as_deref()) {
                Ok(code) => std::process::exit(code as i32),
                Err(msg) => {
                    eprintln!("{msg}");
                    std::process::exit(1);
                }
            }
        }
        polyisa_cli::Command::Cpus => {
            for m in polyisa_guest_x86::MODELS {
                println!("x86:{m}");
            }
            for m in polyisa_guest_riscv::MODELS {
                println!("riscv:{m}");
            }
            for m in polyisa_guest_mips::MODELS {
                println!("mips:{m}");
            }
        }
        polyisa_cli::Command::Disasm => {
            let Some(word) = args.get(1).and_then(|s| polyisa_cli::parse_hex_word(s)) else {
                eprintln!("usage: polyisa disasm <hex-word>");
                std::process::exit(2);
            };
            match polyisa_cli::disassemble_riscv(word) {
                Some(s) => println!("{s}"),
                None => {
                    eprintln!("unknown instruction: {word:#x}");
                    std::process::exit(1);
                }
            }
        }
        polyisa_cli::Command::Help => {
            println!("usage: polyisa <run|cpus|disasm> [args]");
        }
    }
}
