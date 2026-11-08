//! polyisa 自身の診断ログ。ゲストのトレースは `trace` が扱う。

#![forbid(unsafe_code)]

/// 出力の水準。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
}

/// 環境変数 `POLYISA_LOG` で指定した水準が有効かどうか。
/// 値は `error`、`warn`、`info`、`debug` のいずれか。未設定は `warn` とする。
#[must_use]
pub fn enabled(level: Level) -> bool {
    fn rank(l: Level) -> u8 {
        match l {
            Level::Error => 0,
            Level::Warn => 1,
            Level::Info => 2,
            Level::Debug => 3,
        }
    }
    let want = std::env::var("POLYISA_LOG").unwrap_or_else(|_| "warn".to_string());
    let cur = match want.as_str() {
        "error" => 0,
        "warn" => 1,
        "info" => 2,
        "debug" => 3,
        _ => 1,
    };
    rank(level) <= cur
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_always_enabled() {
        assert!(enabled(Level::Error));
    }
}
