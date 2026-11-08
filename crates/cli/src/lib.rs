//! `polyisa` コマンド。実行の機構そのものは各クレートが持つ。

#![forbid(unsafe_code)]

/// `run`、`cpus`、`disasm` のいずれか。引数の解析は後の段階で足す。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Command {
    Run,
    Cpus,
    Disasm,
    Help,
}

/// 最初の引き数から命令を決める。外部クレートを使わず手で解析する。
#[must_use]
pub fn parse_command(args: &[String]) -> Command {
    match args.first().map(String::as_str) {
        Some("run") => Command::Run,
        Some("cpus") => Command::Cpus,
        Some("disasm") => Command::Disasm,
        _ => Command::Help,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch() {
        let run = ["run".to_string()];
        assert_eq!(parse_command(&run), Command::Run);
        let empty: [String; 0] = [];
        assert_eq!(parse_command(&empty), Command::Help);
    }
}
