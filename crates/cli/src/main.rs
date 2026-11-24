// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `polyisa` コマンドの入口。機構は各クレートが持つ。

#![forbid(unsafe_code)]

/// `cpus` の 1 行を組み立てる。`MODEL_TIMING` に行があるモデルは
/// 忠実度・エンジン・表名を添え、`approx_uncalibrated` は
/// 「未較正」を付ける（cpu-models.md の `timing` 句）。
fn cpus_line(family: &str, name: &str, timing: &[(&str, &str, &str, &str)]) -> String {
    match timing.iter().find(|r| r.0 == name) {
        Some((_, fidelity, engine, table)) => {
            let uncal = if *fidelity == "approx_uncalibrated" {
                " （未較正）"
            } else {
                ""
            };
            format!("{family}:{name} {fidelity} {engine} {table}{uncal}")
        }
        None => format!("{family}:{name}"),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match polyisa_cli::parse_command(&args) {
        polyisa_cli::Command::Run => {
            // `run [--cpu <ファミリ>:<モデル>[,+機能,-機能]] [--root <dir>] <elf> [args...]`。
            // オプションはゲストの引数と混ざらないよう elf の前に置く。
            let mut rest = &args[1..];
            let mut cpu = None;
            let mut root = None;
            let mut os = None;
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
                } else if let Some(v) = rest.first().and_then(|a| a.strip_prefix("--os=")) {
                    os = Some(v.to_string());
                    rest = &rest[1..];
                } else if rest.first().map(String::as_str) == Some("--os") {
                    let Some(v) = rest.get(1) else {
                        eprintln!(
                            "usage: polyisa run [--cpu <ファミリ>:<モデル>] [--root <dir>] [--os <linux|semihost>] <elf> [args...]"
                        );
                        std::process::exit(2);
                    };
                    os = Some(v.clone());
                    rest = &rest[2..];
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
            match polyisa_cli::run_path_opts(
                path,
                &rest[1..],
                cpu.as_deref(),
                root.as_deref(),
                os.as_deref(),
            ) {
                Ok(code) => std::process::exit(code as i32),
                Err(msg) => {
                    eprintln!("{msg}");
                    std::process::exit(1);
                }
            }
        }
        polyisa_cli::Command::Cpus => {
            #[cfg(feature = "guest-x86")]
            for &m in polyisa_guest_x86::MODELS {
                println!("{}", cpus_line("x86", m, polyisa_guest_x86::MODEL_TIMING));
            }
            #[cfg(feature = "guest-riscv")]
            for &m in polyisa_guest_riscv::MODELS {
                println!(
                    "{}",
                    cpus_line("riscv", m, polyisa_guest_riscv::MODEL_TIMING)
                );
            }
            #[cfg(feature = "guest-mips")]
            for &m in polyisa_guest_mips::MODELS {
                println!("{}", cpus_line("mips", m, polyisa_guest_mips::MODEL_TIMING));
            }
            #[cfg(feature = "guest-arm")]
            for &m in polyisa_guest_arm::MODELS {
                println!("{}", cpus_line("arm", m, polyisa_guest_arm::MODEL_TIMING));
            }
            #[cfg(feature = "guest-aarch64")]
            for &m in polyisa_guest_aarch64::MODELS {
                println!(
                    "{}",
                    cpus_line("aarch64", m, polyisa_guest_aarch64::MODEL_TIMING)
                );
            }
            #[cfg(feature = "guest-power")]
            for &m in polyisa_guest_power::MODELS {
                println!(
                    "{}",
                    cpus_line("power", m, polyisa_guest_power::MODEL_TIMING)
                );
            }
            #[cfg(feature = "guest-s390")]
            for &m in polyisa_guest_s390::MODELS {
                println!("{}", cpus_line("s390", m, polyisa_guest_s390::MODEL_TIMING));
            }
            #[cfg(feature = "guest-sparc")]
            for &m in polyisa_guest_sparc::MODELS {
                println!(
                    "{}",
                    cpus_line("sparc", m, polyisa_guest_sparc::MODEL_TIMING)
                );
            }
            #[cfg(feature = "guest-alpha")]
            for &m in polyisa_guest_alpha::MODELS {
                println!(
                    "{}",
                    cpus_line("alpha", m, polyisa_guest_alpha::MODEL_TIMING)
                );
            }
            #[cfg(feature = "guest-parisc")]
            for &m in polyisa_guest_parisc::MODELS {
                println!(
                    "{}",
                    cpus_line("parisc", m, polyisa_guest_parisc::MODEL_TIMING)
                );
            }
            #[cfg(feature = "guest-superh")]
            for &m in polyisa_guest_superh::MODELS {
                println!(
                    "{}",
                    cpus_line("superh", m, polyisa_guest_superh::MODEL_TIMING)
                );
            }
            #[cfg(feature = "guest-ia64")]
            for &m in polyisa_guest_ia64::MODELS {
                println!("{}", cpus_line("ia64", m, polyisa_guest_ia64::MODEL_TIMING));
            }
            #[cfg(feature = "guest-hexagon")]
            for &m in polyisa_guest_hexagon::MODELS {
                println!(
                    "{}",
                    cpus_line("hexagon", m, polyisa_guest_hexagon::MODEL_TIMING)
                );
            }
            #[cfg(feature = "guest-loongarch")]
            for &m in polyisa_guest_loongarch::MODELS {
                println!(
                    "{}",
                    cpus_line("loongarch", m, polyisa_guest_loongarch::MODEL_TIMING)
                );
            }
            #[cfg(feature = "guest-openrisc")]
            for &m in polyisa_guest_openrisc::MODELS {
                println!(
                    "{}",
                    cpus_line("openrisc", m, polyisa_guest_openrisc::MODEL_TIMING)
                );
            }
            #[cfg(feature = "guest-vax")]
            for &m in polyisa_guest_vax::MODELS {
                println!("{}", cpus_line("vax", m, polyisa_guest_vax::MODEL_TIMING));
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

#[cfg(test)]
mod tests {
    use super::cpus_line;

    #[test]
    fn cpus_line_marks_uncalibrated() {
        let timing = [
            ("u74", "approx_uncalibrated", "inorder", "sifive_u74"),
            ("e8", "approx", "ooo", "tbl"),
        ];
        assert_eq!(
            cpus_line("riscv", "u74", &timing),
            "riscv:u74 approx_uncalibrated inorder sifive_u74 （未較正）"
        );
        assert_eq!(cpus_line("riscv", "e8", &timing), "riscv:e8 approx ooo tbl");
        // `timing` 宣言のないモデルは名前だけ。
        assert_eq!(cpus_line("riscv", "other", &timing), "riscv:other");
    }
}
