//! `when` 述語。機能と実行モードについての命題論理式。
//!
//! 全文法の構文解析は後の段階で足す。ここでは述語の値と、
//! 一意性検査のための保守的な両立判定を提供する。

/// 機能と実行モードについての述語。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Pred {
    True,
    False,
    /// 機能または実行モードの値が真であること。`!` は [`Pred::Not`] で表す。
    Flag(String),
    Not(Box<Pred>),
    All(Vec<Pred>),
    Any(Vec<Pred>),
}

/// 述語の評価に必要な真偽値の表。
pub trait PredCtx {
    fn flag(&self, name: &str) -> bool;
}

/// 述語の誤り。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ParseError {
    Empty,
    UnexpectedEnd,
    UnexpectedChar(char),
    TrailingInput,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => write!(f, "empty predicate"),
            Self::UnexpectedEnd => write!(f, "unexpected end"),
            Self::UnexpectedChar(c) => write!(f, "unexpected {c:?}"),
            Self::TrailingInput => write!(f, "trailing input"),
        }
    }
}

/// `when` の式を解析する。`!`、`&&`、`||`、括弧、旗の名前を扱う。
/// `&&` は `||` より強く結合する。
pub fn parse(s: &str) -> Result<Pred, ParseError> {
    let mut p = Parser {
        chars: s.chars().peekable(),
    };
    p.skip_ws();
    if p.peek().is_none() {
        return Err(ParseError::Empty);
    }
    let pred = p.or()?;
    p.skip_ws();
    if p.peek().is_some() {
        return Err(ParseError::TrailingInput);
    }
    Ok(pred)
}

struct Parser<'a> {
    chars: core::iter::Peekable<std::str::Chars<'a>>,
}

impl Parser<'_> {
    fn peek(&mut self) -> Option<char> {
        self.chars.peek().copied()
    }

    fn skip_ws(&mut self) {
        while self.peek().is_some_and(|c| c == ' ' || c == '\t') {
            self.chars.next();
        }
    }

    fn or(&mut self) -> Result<Pred, ParseError> {
        let mut acc = self.and()?;
        loop {
            self.skip_ws();
            if self.eat("||") {
                let rhs = self.and()?;
                acc = match acc {
                    Pred::Any(mut v) => {
                        v.push(rhs);
                        Pred::Any(v)
                    }
                    other => Pred::Any(vec![other, rhs]),
                };
            } else {
                return Ok(acc);
            }
        }
    }

    fn and(&mut self) -> Result<Pred, ParseError> {
        let mut acc = self.unary()?;
        loop {
            self.skip_ws();
            if self.eat("&&") {
                let rhs = self.unary()?;
                acc = match acc {
                    Pred::All(mut v) => {
                        v.push(rhs);
                        Pred::All(v)
                    }
                    other => Pred::All(vec![other, rhs]),
                };
            } else {
                return Ok(acc);
            }
        }
    }

    fn unary(&mut self) -> Result<Pred, ParseError> {
        self.skip_ws();
        match self.peek() {
            None => Err(ParseError::UnexpectedEnd),
            Some('!') => {
                self.chars.next();
                Ok(Pred::Not(Box::new(self.unary()?)))
            }
            Some('(') => {
                self.chars.next();
                let inner = self.or()?;
                self.skip_ws();
                match self.peek() {
                    Some(')') => {
                        self.chars.next();
                        Ok(inner)
                    }
                    Some(c) => Err(ParseError::UnexpectedChar(c)),
                    None => Err(ParseError::UnexpectedEnd),
                }
            }
            Some(c) if c.is_ascii_alphabetic() || c == '_' => Ok(Pred::Flag(self.flag())),
            Some(c) => Err(ParseError::UnexpectedChar(c)),
        }
    }

    fn flag(&mut self) -> String {
        let mut s = String::new();
        while let Some(c) = self.peek()
            && (c.is_ascii_alphanumeric() || c == '_')
        {
            s.push(c);
            self.chars.next();
        }
        s
    }

    fn eat(&mut self, op: &str) -> bool {
        let mut it = self.chars.clone();
        for want in op.chars() {
            if it.next() != Some(want) {
                return false;
            }
        }
        self.chars = it;
        true
    }
}

impl Pred {
    /// 述語を評価する。
    pub fn eval(&self, ctx: &impl PredCtx) -> bool {
        match self {
            Self::True => true,
            Self::False => false,
            Self::Flag(name) => ctx.flag(name),
            Self::Not(inner) => !inner.eval(ctx),
            Self::All(ps) => ps.iter().all(|p| p.eval(ctx)),
            Self::Any(ps) => ps.iter().any(|p| p.eval(ctx)),
        }
    }

    /// 二つの述語が同時に真になりうるかどうかを保守的に判定する。
    ///
    /// 明らかな矛盾（同じ旗の肯定と否定の直接の衝突）だけを `false` にし、
    /// それ以外は `true`（重なりうる）を返す。`implies` と `conflicts` を
    /// 使った厳密な判定は `isagen` の実装時に足す。
    #[must_use]
    pub fn maybe_both_true(&self, other: &Self) -> bool {
        let mut pos = Vec::new();
        let mut neg = Vec::new();
        collect(self, true, &mut pos, &mut neg);
        let mut opos = Vec::new();
        let mut oneg = Vec::new();
        collect(other, true, &mut opos, &mut oneg);
        // 直接の肯定同士の衝突はここでは扱わない（`conflicts` が要る）。
        // 片方で肯定、もう片方で否定されている旗があれば両立しない。
        if pos.iter().any(|f| oneg.contains(f)) {
            return false;
        }
        if opos.iter().any(|f| neg.contains(f)) {
            return false;
        }
        // `False` は何とも両立しない。
        if matches!(self, Self::False) || matches!(other, Self::False) {
            return false;
        }
        true
    }
}

/// 述語から肯定と否定の旗を集める。`All` の直下だけをたどる保守的な収集である。
fn collect(p: &Pred, polarity: bool, pos: &mut Vec<String>, neg: &mut Vec<String>) {
    match p {
        Pred::True | Pred::False => {}
        Pred::Flag(name) => {
            if polarity {
                pos.push(name.clone());
            } else {
                neg.push(name.clone());
            }
        }
        Pred::Not(inner) => collect(inner, !polarity, pos, neg),
        Pred::All(ps) if polarity => {
            for q in ps {
                collect(q, true, pos, neg);
            }
        }
        Pred::Any(ps) if !polarity => {
            for q in ps {
                collect(q, false, pos, neg);
            }
        }
        // `Any` の肯定と `All` の否定は、どちらかが真であればよいので、
        // 保守的に何も集めない（両立しうるとする）。
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct Map(BTreeMap<String, bool>);

    impl PredCtx for Map {
        fn flag(&self, name: &str) -> bool {
            self.0.get(name).copied().unwrap_or(false)
        }
    }

    fn ctx(pairs: &[(&str, bool)]) -> Map {
        Map(pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect())
    }

    #[test]
    fn eval_basic() {
        let p = Pred::All(vec![
            Pred::Flag("rv64".to_string()),
            Pred::Not(Box::new(Pred::Flag("mips_r6".to_string()))),
        ]);
        assert!(p.eval(&ctx(&[("rv64", true), ("mips_r6", false)])));
        assert!(!p.eval(&ctx(&[("rv64", true), ("mips_r6", true)])));
        assert!(!p.eval(&ctx(&[("rv64", false), ("mips_r6", false)])));
    }

    #[test]
    fn parse_cases() {
        assert_eq!(parse("rv64").unwrap(), Pred::Flag("rv64".to_string()));
        assert_eq!(
            parse("!mips_r6").unwrap(),
            Pred::Not(Box::new(Pred::Flag("mips_r6".to_string())))
        );
        // `&&` は `||` より強く結合する。
        assert_eq!(
            parse("a || b && !c").unwrap(),
            Pred::Any(vec![
                Pred::Flag("a".to_string()),
                Pred::All(vec![
                    Pred::Flag("b".to_string()),
                    Pred::Not(Box::new(Pred::Flag("c".to_string()))),
                ]),
            ])
        );
        assert_eq!(
            parse("(a || b) && c").unwrap(),
            Pred::All(vec![
                Pred::Any(vec![
                    Pred::Flag("a".to_string()),
                    Pred::Flag("b".to_string())
                ]),
                Pred::Flag("c".to_string()),
            ])
        );
    }

    #[test]
    fn parse_errors() {
        assert_eq!(parse(""), Err(ParseError::Empty));
        assert_eq!(parse("   "), Err(ParseError::Empty));
        assert!(matches!(parse("a &&"), Err(ParseError::UnexpectedEnd)));
        assert!(matches!(parse("(a"), Err(ParseError::UnexpectedEnd)));
        assert!(matches!(parse("a b"), Err(ParseError::TrailingInput)));
        assert!(matches!(parse("0x1"), Err(ParseError::UnexpectedChar(_))));
    }

    #[test]
    fn parse_roundtrip_eval() {
        let p = parse("rv64 && !mips_r6").unwrap();
        assert!(p.eval(&ctx(&[("rv64", true), ("mips_r6", false)])));
        assert!(!p.eval(&ctx(&[("rv64", true), ("mips_r6", true)])));
    }

    #[test]
    fn contradiction() {
        let a = Pred::Flag("mips_r6".to_string());
        let b = Pred::Not(Box::new(Pred::Flag("mips_r6".to_string())));
        assert!(!a.maybe_both_true(&b));
        let c = Pred::Flag("rv64".to_string());
        assert!(a.maybe_both_true(&c));
        assert!(!Pred::False.maybe_both_true(&Pred::True));
    }
}
