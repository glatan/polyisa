//! `polyisa` コマンドの入口。機構は各クレートが持つ。

#![forbid(unsafe_code)]

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match polyisa_cli::parse_command(&args) {
        polyisa_cli::Command::Run => {
            eprintln!("run: 未実装（ユーザーモードの実装後に足す）");
            std::process::exit(2);
        }
        polyisa_cli::Command::Cpus => {
            for m in polyisa_guest_riscv::MODELS {
                println!("riscv:{m}");
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
