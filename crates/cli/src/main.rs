// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `polyisa` コマンドの入口。機構は各クレートが持つ。

#![forbid(unsafe_code)]

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match polyisa_cli::parse_command(&args) {
        polyisa_cli::Command::Run => {
            // `run [--cpu <ファミリ>:<モデル>[,+機能,-機能]] [--root <dir>] <elf> [args...]`。
            // オプションはゲストの引数と混ざらないよう elf の前に置く。
            let mut rest = &args[1..];
            let mut cpu = None;
            let mut root = None;
            loop {
                if let Some(v) = rest.first().and_then(|a| a.strip_prefix("--cpu=")) {
                    cpu = Some(v.to_string());
                    rest = &rest[1..];
                } else if rest.first().map(String::as_str) == Some("--cpu") {
                    let Some(v) = rest.get(1) else {
                        eprintln!(
                            "usage: polyisa run [--cpu <ファミリ>:<モデル>] [--root <dir>] <elf> [args...]"
                        );
                        std::process::exit(2);
                    };
                    cpu = Some(v.clone());
                    rest = &rest[2..];
                } else if let Some(v) = rest.first().and_then(|a| a.strip_prefix("--root=")) {
                    root = Some(v.to_string());
                    rest = &rest[1..];
                } else if rest.first().map(String::as_str) == Some("--root") {
                    let Some(v) = rest.get(1) else {
                        eprintln!(
                            "usage: polyisa run [--cpu <ファミリ>:<モデル>] [--root <dir>] <elf> [args...]"
                        );
                        std::process::exit(2);
                    };
                    root = Some(v.clone());
                    rest = &rest[2..];
                } else {
                    break;
                }
            }
            let Some(path) = rest.first() else {
                eprintln!(
                    "usage: polyisa run [--cpu <ファミリ>:<モデル>] [--root <dir>] <elf> [args...]"
                );
                std::process::exit(2);
            };
            match polyisa_cli::run_path_opts(path, &rest[1..], cpu.as_deref(), root.as_deref()) {
                Ok(code) => std::process::exit(code as i32),
                Err(msg) => {
                    eprintln!("{msg}");
                    std::process::exit(1);
                }
            }
        }
        polyisa_cli::Command::Cpus => {
            #[cfg(feature = "guest-x86")]
            for m in polyisa_guest_x86::MODELS {
                println!("x86:{m}");
            }
            #[cfg(feature = "guest-riscv")]
            for m in polyisa_guest_riscv::MODELS {
                println!("riscv:{m}");
            }
            #[cfg(feature = "guest-mips")]
            for m in polyisa_guest_mips::MODELS {
                println!("mips:{m}");
            }
            #[cfg(feature = "guest-arm")]
            for m in polyisa_guest_arm::MODELS {
                println!("arm:{m}");
            }
            #[cfg(feature = "guest-aarch64")]
            for m in polyisa_guest_aarch64::MODELS {
                println!("aarch64:{m}");
            }
            #[cfg(feature = "guest-power")]
            for m in polyisa_guest_power::MODELS {
                println!("power:{m}");
            }
            #[cfg(feature = "guest-s390")]
            for m in polyisa_guest_s390::MODELS {
                println!("s390:{m}");
            }
            #[cfg(feature = "guest-sparc")]
            for m in polyisa_guest_sparc::MODELS {
                println!("sparc:{m}");
            }
            #[cfg(feature = "guest-alpha")]
            for m in polyisa_guest_alpha::MODELS {
                println!("alpha:{m}");
            }
            #[cfg(feature = "guest-parisc")]
            for m in polyisa_guest_parisc::MODELS {
                println!("parisc:{m}");
            }
            #[cfg(feature = "guest-superh")]
            for m in polyisa_guest_superh::MODELS {
                println!("superh:{m}");
            }
            #[cfg(feature = "guest-loongarch")]
            for m in polyisa_guest_loongarch::MODELS {
                println!("loongarch:{m}");
            }
            #[cfg(feature = "guest-openrisc")]
            for m in polyisa_guest_openrisc::MODELS {
                println!("openrisc:{m}");
            }
        }
        polyisa_cli::Command::Disasm => {
            #[cfg(feature = "guest-riscv")]
            {
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
            #[cfg(not(feature = "guest-riscv"))]
            {
                eprintln!("disasm は riscv ゲストを有効にしたビルドが必要");
                std::process::exit(1);
            }
        }
        polyisa_cli::Command::Help => {
            println!("usage: polyisa <run|cpus|disasm> [args]");
        }
    }
}
