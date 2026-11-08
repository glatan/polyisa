//! JIT。IR からホストの機械語を生成し、実行する。後の段階で実装する。

#![forbid(unsafe_code)]

/// コンパイル済みの入口。機械語の生成は後の段階で足す。
#[derive(Debug, Default)]
pub struct Compiled {
    pub blocks: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty() {
        assert_eq!(Compiled::default().blocks, 0);
    }
}
