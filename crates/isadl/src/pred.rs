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
    fn contradiction() {
        let a = Pred::Flag("mips_r6".to_string());
        let b = Pred::Not(Box::new(Pred::Flag("mips_r6".to_string())));
        assert!(!a.maybe_both_true(&b));
        let c = Pred::Flag("rv64".to_string());
        assert!(a.maybe_both_true(&c));
        assert!(!Pred::False.maybe_both_true(&Pred::True));
    }
}
