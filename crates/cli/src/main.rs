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
            println!("riscv");
        }
        polyisa_cli::Command::Disasm => {
            eprintln!("disasm: 未実装（逆アセンブラの生成後に足す）");
            std::process::exit(2);
        }
        polyisa_cli::Command::Help => {
            println!("usage: polyisa <run|cpus|disasm>");
        }
    }
}
