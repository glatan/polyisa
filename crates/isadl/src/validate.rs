// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 静的検査。コード生成の前に違反があれば失敗させる。
//!
//! 設計文書の検査項目（`docs/design/isa-description.md` の「静的検査」）のうち、
//! この骨格で判定できる範囲を実装する。決定木の構築と厳密な充足可能性は後の段階で足す。

use super::model::{FieldKind, Model};
use std::collections::BTreeSet;

/// 検査の違反。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ValidationError {
    /// 同じ語に一致しうる命令の組。
    Ambiguous { first: String, second: String },
    /// どの CPU モデルでも一致しない命令。
    Unreachable { name: String },
    /// 形式の不明な参照。
    UnknownFormat { insn: String, format: String },
    /// フィールドの重なりや範囲外。
    BadField { format: String, field: String },
    /// 逆変換のないフック。
    MissingEncoder { field: String },
    /// 未定義の名前の参照。
    Unresolved { kind: String, name: String },
}

/// 検査の結果。警告は現段階では到達可能性のみである。
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Report {
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<ValidationError>,
}

/// モデルを検査する。
#[must_use]
pub fn validate(model: &Model) -> Report {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    let formats: BTreeSet<&str> = model.formats.iter().map(|f| f.name.as_str()).collect();
    let fields: std::collections::BTreeMap<&str, &crate::model::Field> =
        model.fields.iter().map(|f| (f.name.as_str(), f)).collect();
    let features: BTreeSet<&str> = model.features.iter().map(|f| f.name.as_str()).collect();
    let timing: BTreeSet<&str> = model.timing_classes.iter().map(|t| t.as_str()).collect();

    // 形式と名前解決の検査。
    for insn in &model.insns {
        if !formats.contains(insn.format.as_str()) {
            errors.push(ValidationError::UnknownFormat {
                insn: insn.name.clone(),
                format: insn.format.clone(),
            });
        }
        if !timing.contains(insn.timing.as_str()) {
            errors.push(ValidationError::Unresolved {
                kind: "timing".to_string(),
                name: insn.timing.clone(),
            });
        }
        if matches!(insn.when, crate::pred::Pred::False) {
            warnings.push(ValidationError::Unreachable {
                name: insn.name.clone(),
            });
        }
        for w in &insn.wheres {
            match fields.get(w.field.as_str()) {
                Some(f) => match f.kind {
                    crate::model::FieldKind::Bits { .. } => {}
                    _ => errors.push(ValidationError::Unresolved {
                        kind: "where-hook".to_string(),
                        name: w.field.clone(),
                    }),
                },
                None => errors.push(ValidationError::Unresolved {
                    kind: "where-field".to_string(),
                    name: w.field.clone(),
                }),
            }
        }
    }

    for feature in &model.features {
        for dep in feature.implies.iter().chain(feature.conflicts.iter()) {
            if !features.contains(dep.as_str()) {
                errors.push(ValidationError::Unresolved {
                    kind: "feature".to_string(),
                    name: dep.clone(),
                });
            }
        }
    }

    for format in &model.formats {
        let mut seen: Vec<(&str, u32, u32)> = Vec::new();
        for fname in &format.fields {
            let Some(f) = fields.get(fname.as_str()) else {
                errors.push(ValidationError::Unresolved {
                    kind: "field".to_string(),
                    name: fname.clone(),
                });
                continue;
            };
            match f.kind {
                FieldKind::Bits { hi, lo } => {
                    if lo > hi || hi >= 128 {
                        errors.push(ValidationError::BadField {
                            format: format.name.clone(),
                            field: fname.clone(),
                        });
                        continue;
                    }
                    for (other, ohi, olo) in &seen {
                        // 同じビット位置を二つのフィールドが使うのは誤りとする。
                        if lo <= *ohi && *olo <= hi {
                            errors.push(ValidationError::BadField {
                                format: format.name.clone(),
                                field: format!("{fname} overlaps {other}"),
                            });
                        }
                    }
                    seen.push((fname.as_str(), hi, lo));
                }
                FieldKind::Hook { has_encoder } => {
                    if !has_encoder {
                        errors.push(ValidationError::MissingEncoder {
                            field: fname.clone(),
                        });
                    }
                }
            }
        }
    }

    // デコードの一意性。長さが同じで重なり、述語が両立しうる組を誤りとする。
    // `where` が互いに排他なら重なりを許す。機能の排他も考慮する。
    let mut conflicts: Vec<(String, String)> = Vec::new();
    for f in &model.features {
        for c in &f.conflicts {
            conflicts.push((f.name.clone(), c.clone()));
        }
    }
    for (i, a) in model.insns.iter().enumerate() {
        for b in model.insns.iter().skip(i + 1) {
            if !a.pattern.overlaps(&b.pattern) {
                continue;
            }
            if !a.when.maybe_both_true(&b.when) {
                continue;
            }
            if wheres_disjoint(&a.wheres, &b.wheres) {
                continue;
            }
            if when_disjoint_by_conflict(&a.when, &b.when, &conflicts) {
                continue;
            }
            errors.push(ValidationError::Ambiguous {
                first: a.name.clone(),
                second: b.name.clone(),
            });
        }
    }

    Report { errors, warnings }
}

/// `where` 句の組が互いに排他かどうか。同一フィールドへの矛盾があれば真。
fn wheres_disjoint(a: &[crate::model::WhereClause], b: &[crate::model::WhereClause]) -> bool {
    use crate::model::WhereOp::{Eq, Ne};
    for x in a {
        for y in b {
            if x.field != y.field {
                continue;
            }
            match (x.op, y.op) {
                (Eq, Eq) if x.value != y.value => return true,
                (Eq, Ne) if x.value == y.value => return true,
                (Ne, Eq) if x.value == y.value => return true,
                _ => {}
            }
        }
    }
    false
}

/// 機能の排他宣言により `when` が両立しないかどうか。
/// 肯定側の旗の組に排他関係があれば真とする（保守的）。
fn when_disjoint_by_conflict(
    a: &crate::pred::Pred,
    b: &crate::pred::Pred,
    conflicts: &[(String, String)],
) -> bool {
    use crate::pred::Pred::{All, Flag};
    fn pos(p: &crate::pred::Pred, out: &mut Vec<String>) {
        match p {
            Flag(f) => out.push(f.clone()),
            All(ps) => {
                for q in ps {
                    pos(q, out);
                }
            }
            _ => {}
        }
    }
    let mut pa = Vec::new();
    let mut pb = Vec::new();
    pos(a, &mut pa);
    pos(b, &mut pb);
    for f in &pa {
        for g in &pb {
            if conflicts
                .iter()
                .any(|(x, y)| (x == f && y == g) || (x == g && y == f))
            {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    use crate::pattern::Pattern;
    use crate::pred::Pred;

    fn test_model() -> Model {
        let mut m = Model::new();
        m.timing_classes.push("alu".to_string());
        m.fields.push(Field {
            name: "rd".to_string(),
            kind: FieldKind::Bits { hi: 11, lo: 7 },
        });
        m.fields.push(Field {
            name: "rs1".to_string(),
            kind: FieldKind::Bits { hi: 19, lo: 15 },
        });
        m.formats.push(Format {
            name: "R".to_string(),
            fields: vec!["rd".to_string(), "rs1".to_string()],
            operands: vec![],
        });
        m.insns.push(Insn {
            name: "add".to_string(),
            format: "R".to_string(),
            pattern: Pattern::parse("0000000 ..... ..... 000 ..... 0110011").unwrap(),
            when: Pred::True,
            wheres: vec![],
            syntax: "add".to_string(),
            timing: "alu".to_string(),
        });
        m
    }

    #[test]
    fn valid_model_passes() {
        let r = validate(&test_model());
        assert!(r.errors.is_empty(), "{:?}", r.errors);
    }

    #[test]
    fn ambiguous_pair_fails() {
        let mut m = test_model();
        m.insns.push(Insn {
            name: "add_alias".to_string(),
            format: "R".to_string(),
            pattern: Pattern::parse("0000000 ..... ..... 000 ..... 0110011").unwrap(),
            when: Pred::True,
            wheres: vec![],
            syntax: "add".to_string(),
            timing: "alu".to_string(),
        });
        let r = validate(&m);
        assert!(
            r.errors
                .iter()
                .any(|e| matches!(e, ValidationError::Ambiguous { .. }))
        );
    }

    #[test]
    fn disjoint_when_passes() {
        let mut m = test_model();
        m.features.push(Feature {
            name: "mips_r6".to_string(),
            implies: vec![],
            conflicts: vec![],
        });
        m.insns[0].when = Pred::Not(Box::new(Pred::Flag("mips_r6".to_string())));
        m.insns.push(Insn {
            name: "bovc".to_string(),
            format: "R".to_string(),
            pattern: Pattern::parse("0000000 ..... ..... 000 ..... 0110011").unwrap(),
            when: Pred::Flag("mips_r6".to_string()),
            wheres: vec![],
            syntax: "bovc".to_string(),
            timing: "alu".to_string(),
        });
        let r = validate(&m);
        assert!(r.errors.is_empty(), "{:?}", r.errors);
    }

    #[test]
    fn where_disjoint_pair_passes() {
        use crate::model::{WhereClause, WhereOp};
        let mut m = test_model();
        m.fields.push(Field {
            name: "rs2".to_string(),
            kind: FieldKind::Bits { hi: 24, lo: 20 },
        });
        m.insns[0].wheres = vec![WhereClause {
            field: "rs2".to_string(),
            op: WhereOp::Eq,
            value: 0,
        }];
        m.insns.push(Insn {
            name: "add_alias".to_string(),
            format: "R".to_string(),
            pattern: Pattern::parse("0000000 ..... ..... 000 ..... 0110011").unwrap(),
            when: Pred::True,
            wheres: vec![WhereClause {
                field: "rs2".to_string(),
                op: WhereOp::Ne,
                value: 0,
            }],
            syntax: "add".to_string(),
            timing: "alu".to_string(),
        });
        let r = validate(&m);
        assert!(r.errors.is_empty(), "{:?}", r.errors);
    }

    #[test]
    fn conflict_declared_when_passes() {
        let mut m = test_model();
        for (name, conflicts) in [("rv64", vec!["rv32"]), ("rv32", vec!["rv64"])] {
            m.features.push(Feature {
                name: name.to_string(),
                implies: vec![],
                conflicts: conflicts.iter().map(|s| s.to_string()).collect(),
            });
        }
        m.insns[0].when = Pred::Flag("rv64".to_string());
        m.insns.push(Insn {
            name: "add32".to_string(),
            format: "R".to_string(),
            pattern: Pattern::parse("0000000 ..... ..... 000 ..... 0110011").unwrap(),
            when: Pred::Flag("rv32".to_string()),
            wheres: vec![],
            syntax: "add".to_string(),
            timing: "alu".to_string(),
        });
        let r = validate(&m);
        assert!(r.errors.is_empty(), "{:?}", r.errors);
    }

    #[test]
    fn unknown_format_and_missing_encoder() {
        let mut m = test_model();
        m.insns[0].format = "X".to_string();
        m.fields.push(Field {
            name: "ea".to_string(),
            kind: FieldKind::Hook { has_encoder: false },
        });
        m.formats[0].fields.push("ea".to_string());
        let r = validate(&m);
        assert!(
            r.errors
                .iter()
                .any(|e| matches!(e, ValidationError::UnknownFormat { .. }))
        );
        assert!(
            r.errors
                .iter()
                .any(|e| matches!(e, ValidationError::MissingEncoder { .. }))
        );
    }
}
