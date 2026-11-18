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
            let check = |name: &str, errors: &mut Vec<ValidationError>| match fields.get(name) {
                Some(f) => match f.kind {
                    crate::model::FieldKind::Bits { .. } => {}
                    _ => errors.push(ValidationError::Unresolved {
                        kind: "where-hook".to_string(),
                        name: name.to_string(),
                    }),
                },
                None => errors.push(ValidationError::Unresolved {
                    kind: "where-field".to_string(),
                    name: name.to_string(),
                }),
            };
            check(&w.field, &mut errors);
            if let crate::model::WhereRhs::Field(name) = &w.rhs {
                check(name, &mut errors);
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

    // `when` の旗名は宣言済みの機能か実行モードの旗でなければならない。
    // 綴りの誤りがあると命令が全モデルで解読されなくなる。
    let mut flag_names: BTreeSet<&str> = features.clone();
    let mut mode_enum_flags: Vec<String> = Vec::new();
    for mode in &model.modes {
        match &mode.ty {
            crate::model::ModeType::Bool => {
                flag_names.insert(mode.name.as_str());
            }
            // `Enum` の旗名は `モード_値`（`opd_o16` 等）。
            crate::model::ModeType::Enum(vars) => {
                for v in vars {
                    mode_enum_flags.push(format!("{}_{}", mode.name, v));
                }
            }
        }
    }
    let check_when = |when: &crate::pred::Pred, name: &str, errors: &mut Vec<ValidationError>| {
        let mut flags = Vec::new();
        collect_flag_names(when, &mut flags);
        for f in flags {
            // `rv32`/`rv64` は RISC-V の XLEN を表す予約名。
            if f == "rv32" || f == "rv64" {
                continue;
            }
            if !flag_names.contains(f.as_str()) && !mode_enum_flags.contains(&f) {
                errors.push(ValidationError::Unresolved {
                    kind: "when-flag".to_string(),
                    name: format!("{name}: {f}"),
                });
            }
        }
    };
    for insn in &model.insns {
        check_when(&insn.when, &insn.name, &mut errors);
        // 列挙経路のデコーダには modes 引数がないためモード旗を
        // 評価できない（`rv32`/`rv64` は is_rv64 で扱う予約名）。
        // 使うと生成時に UnsupportedWhen になるのでここで止める。
        let mut flags = Vec::new();
        collect_flag_names(&insn.when, &mut flags);
        for f in flags {
            let is_mode = model.modes.iter().any(|md| match &md.ty {
                crate::model::ModeType::Bool => md.name == f,
                crate::model::ModeType::Enum(vars) => {
                    vars.iter().any(|v| format!("{}_{v}", md.name) == f)
                }
            });
            if is_mode {
                errors.push(ValidationError::BadField {
                    format: "when".to_string(),
                    field: format!("{}: 列挙命令にモード旗 {f} は使えない", insn.name),
                });
            }
        }
    }
    for map in &model.maps {
        for item in &map.items {
            // Map 分岐の述語も when 旗と同じ解決規則で検査する。
            if let crate::model::MapItem::Map(_, name, when) = item {
                check_when(when, name, &mut errors);
            }
            if let crate::model::MapItem::Insn(_, mi) = item {
                check_when(&mi.when, &mi.name, &mut errors);
                // `group_rm` は mod=11 の副エンコーディング専用。
                // mod!=11 でも r/m バイトには意味があるので、
                // `group_mod = Some(true)` と併置することを要求する。
                if mi.group_rm.is_some_and(|rm| rm > 7) {
                    errors.push(ValidationError::BadField {
                        format: "map-insn".to_string(),
                        field: format!("{}: group_rm は 0-7", mi.name),
                    });
                }
                // `OpKind::Vv`（VEX/EVEX.vvvv）と `vex_rv` は接頭辞項目にだけ
                // 意味を持つ。
                if mi.vex.is_none()
                    && mi.evex.is_none()
                    && (mi.vex_rv || mi.ops.contains(&crate::model::OpKind::Vv))
                {
                    errors.push(ValidationError::BadField {
                        format: "map-insn".to_string(),
                        field: format!("{}: Vv/vex_rv には vex が要る", mi.name),
                    });
                }
                if mi.group_rm.is_some() && mi.group_mod != Some(true) {
                    errors.push(ValidationError::BadField {
                        format: "map-insn".to_string(),
                        field: format!("{}: group_rm には group_mod=Some(true) が要る", mi.name),
                    });
                }
                // `group_mod`/`group_rm` は ModRM を消費する項目にだけ
                // 意味を持つ。
                if (mi.group_mod.is_some() || mi.group_rm.is_some())
                    && mi.group.is_none()
                    && !mi.ops.iter().any(|o| {
                        matches!(
                            o,
                            crate::model::OpKind::Ea(_)
                                | crate::model::OpKind::Reg(_)
                                | crate::model::OpKind::RegS
                                | crate::model::OpKind::RegX
                                | crate::model::OpKind::RmX
                                | crate::model::OpKind::RegM
                                | crate::model::OpKind::RmM
                        )
                    })
                {
                    errors.push(ValidationError::BadField {
                        format: "map-insn".to_string(),
                        field: format!(
                            "{}: group_mod/group_rm には ModRM を使うオペランドが要る",
                            mi.name
                        ),
                    });
                }
            }
        }
    }

    // 識別情報とモデルの参照。
    for b in &model.ident_bits {
        if !features.contains(b.feature.as_str()) {
            errors.push(ValidationError::Unresolved {
                kind: "ident-bit-feature".to_string(),
                name: b.feature.clone(),
            });
        }
        if b.bit >= 32 {
            errors.push(ValidationError::BadField {
                format: "ident-bit".to_string(),
                field: format!("{}: bit {}", b.feature, b.bit),
            });
        }
    }
    let model_names: BTreeSet<&str> = model.models.iter().map(|d| d.name.as_str()).collect();
    for d in &model.models {
        if !d.parent.is_empty() && !model_names.contains(d.parent.as_str()) {
            errors.push(ValidationError::Unresolved {
                kind: "model-parent".to_string(),
                name: format!("{}: {}", d.name, d.parent),
            });
        }
        for f in d.add_features.iter().chain(d.remove_features.iter()) {
            if !features.contains(f.as_str()) {
                errors.push(ValidationError::Unresolved {
                    kind: "model-feature".to_string(),
                    name: format!("{}: {}", d.name, f),
                });
            }
        }
        // 親連鎖の循環は解決不能なので、ここで止める（生成側・実行側は
        // 打ち切りやエラーで挙動が分かれるため）。
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut cur = d;
        while !cur.parent.is_empty() {
            if !seen.insert(cur.name.as_str()) {
                errors.push(ValidationError::BadField {
                    format: "model".to_string(),
                    field: format!("{}: parent cycle", d.name),
                });
                break;
            }
            let Some(next) = model.models.iter().find(|m| m.name == cur.parent) else {
                break;
            };
            cur = next;
        }
    }

    // 挙動パラメータ。宣言の既定値とモデル側の上書き値を検査する。
    let mut param_names: BTreeSet<&str> = BTreeSet::new();
    for p in &model.params {
        if !param_names.insert(p.name.as_str()) {
            errors.push(ValidationError::BadField {
                format: "param".to_string(),
                field: format!("{}: duplicate", p.name),
            });
        }
        let value_ok = |v: &str| match &p.kind {
            crate::model::ParamKind::Bool => v == "true" || v == "false",
            crate::model::ParamKind::Enum(vs) => vs.iter().any(|x| x == v),
            crate::model::ParamKind::Int(max) => {
                v.parse::<u64>().is_ok_and(|n| n <= u64::from(*max))
            }
        };
        if !value_ok(&p.default) {
            errors.push(ValidationError::BadField {
                format: "param".to_string(),
                field: format!("{}: default {:?}", p.name, p.default),
            });
        }
    }
    for d in &model.models {
        for (k, v) in &d.params {
            let Some(p) = model.params.iter().find(|p| p.name == *k) else {
                errors.push(ValidationError::Unresolved {
                    kind: "model-param".to_string(),
                    name: format!("{}: {}", d.name, k),
                });
                continue;
            };
            let value_ok = match &p.kind {
                crate::model::ParamKind::Bool => v == "true" || v == "false",
                crate::model::ParamKind::Enum(vs) => vs.iter().any(|x| x == v),
                crate::model::ParamKind::Int(max) => {
                    v.parse::<u64>().is_ok_and(|n| n <= u64::from(*max))
                }
            };
            if !value_ok {
                errors.push(ValidationError::BadField {
                    format: "param".to_string(),
                    field: format!("{}: {} = {:?}", d.name, k, v),
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

    // オペコード表の検査。参照解決、キーの重複、名前の一意性を見る。
    validate_maps(model, &timing, &mut errors);

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

/// `map` の検査。表参照の解決、同一キーでの両立しうる命令、
/// 命令名とタイミング分類の一意性・存在を見る。
fn validate_maps(model: &Model, timing: &BTreeSet<&str>, errors: &mut Vec<ValidationError>) {
    use crate::model::{MapItem, PfxSel};
    if model.maps.is_empty() {
        return;
    }
    let map_names: BTreeSet<&str> = model.maps.iter().map(|m| m.name.as_str()).collect();
    if !map_names.contains("primary") {
        errors.push(ValidationError::Unresolved {
            kind: "map-entry".to_string(),
            name: "primary".to_string(),
        });
    }
    let mut insn_names: BTreeSet<&str> = model.insns.iter().map(|i| i.name.as_str()).collect();
    // `map` の命令は、同一の命令が複数のオペコード値（+r 系）に
    // 並びうる。同名の別定義は誤りとし、同一内容の重複は許す。
    let mut map_insn_defs: std::collections::BTreeMap<&str, &crate::model::MapInsn> =
        std::collections::BTreeMap::new();
    let mut conflicts: Vec<(String, String)> = Vec::new();
    for f in &model.features {
        for c in &f.conflicts {
            conflicts.push((f.name.clone(), c.clone()));
        }
    }
    let mut vex_codes: std::collections::BTreeMap<u8, &str> = std::collections::BTreeMap::new();
    for map in &model.maps {
        if let Some(v) = map.vex_code
            && let Some(first) = vex_codes.insert(v, map.name.as_str())
        {
            errors.push(ValidationError::Unresolved {
                kind: "map".to_string(),
                name: format!("{}: vex_code {} は {} と重複", map.name, v, first),
            });
        }
        // postop 表はレガシーパスの先読みでだけ到達する
        // （VEX/EVEX の mmmmm 選択では postop を処理しない）。
        if map.postop && map.vex_code.is_some() {
            errors.push(ValidationError::BadField {
                format: "map".to_string(),
                field: format!("{}: postop と vex_code は両立しない", map.name),
            });
        }
        for item in &map.items {
            match item {
                MapItem::Map(byte, name, _) => {
                    if map.postop {
                        errors.push(ValidationError::BadField {
                            format: "map".to_string(),
                            field: format!("{}: postop 表に副表 {name} は置けない", map.name),
                        });
                    }
                    if !map_names.contains(name.as_str()) {
                        errors.push(ValidationError::Unresolved {
                            kind: "map".to_string(),
                            name: format!("{name} (at {byte:#04x})"),
                        });
                    }
                }
                MapItem::Insn(_, mi) => {
                    // VEX と EVEX は同じ項目で同時に要求できない。
                    if mi.vex.is_some() && mi.evex.is_some() {
                        errors.push(ValidationError::BadField {
                            format: "map-insn".to_string(),
                            field: format!("{}: vex と evex は排他", mi.name),
                        });
                    }
                    // EVEX の L'L 許可マスク。0 は到達不能な項目、
                    // bit3 以上は予約済み L'L=3 を受理してしまう。
                    if let Some(mask) = mi.evex
                        && !(1..=0b111).contains(&mask)
                    {
                        errors.push(ValidationError::BadField {
                            format: "map-insn".to_string(),
                            field: format!("{}: evex の L'L マスクは 1-7", mi.name),
                        });
                    }
                    // EVEX 圧縮 disp8 のスケール指定は EVEX 項目にだけ意味がある。
                    if mi.edisp != 0 && mi.evex.is_none() {
                        errors.push(ValidationError::BadField {
                            format: "map-insn".to_string(),
                            field: format!("{}: edisp には evex が要る", mi.name),
                        });
                    }
                    // 埋め込み broadcast は EVEX 項目で、disp8 スケールに
                    // 要素バイト数が要る。
                    if mi.bcast && (mi.evex.is_none() || mi.edisp == 0) {
                        errors.push(ValidationError::BadField {
                            format: "map-insn".to_string(),
                            field: format!("{}: bcast には evex と edisp が要る", mi.name),
                        });
                    }
                    // {er} は EVEX 項目で、512 ビット形（L'L=2）が
                    // 宣言されていることが要る（b=1 で L'L は丸め指定）。
                    // また b=1 の扱いは r/m オペランドの形で決まるので
                    // ModRM 系の r/m オペランドが必須。
                    let has_rm = mi.ops.iter().any(|o| {
                        matches!(
                            o,
                            crate::model::OpKind::Ea(_)
                                | crate::model::OpKind::RmX
                                | crate::model::OpKind::RmM
                        )
                    });
                    if mi.er && !matches!(mi.evex, Some(m) if m & 0b100 != 0) {
                        errors.push(ValidationError::BadField {
                            format: "map-insn".to_string(),
                            field: format!("{}: er には evex の 512 ビット形が要る", mi.name),
                        });
                    }
                    if (mi.er || mi.bcast) && !has_rm {
                        errors.push(ValidationError::BadField {
                            format: "map-insn".to_string(),
                            field: format!("{}: er/bcast には r/m オペランドが要る", mi.name),
                        });
                    }
                    // postop 表の項目は ModRM を必ず消費する
                    // （照合バイトは ModRM の後ろに来る）。
                    let has_modrm_op = mi.group.is_some()
                        || mi.ops.iter().any(|o| {
                            matches!(
                                o,
                                crate::model::OpKind::Ea(_)
                                    | crate::model::OpKind::Reg(_)
                                    | crate::model::OpKind::RegS
                                    | crate::model::OpKind::RegX
                                    | crate::model::OpKind::RmX
                                    | crate::model::OpKind::RegM
                                    | crate::model::OpKind::RmM
                            )
                        });
                    if map.postop && !has_modrm_op {
                        errors.push(ValidationError::BadField {
                            format: "map-insn".to_string(),
                            field: format!(
                                "{}: postop 表の項目には ModRM オペランドが要る",
                                mi.name
                            ),
                        });
                    }
                    // W による項目選択は VEX/EVEX 項目にだけ意味がある。
                    if mi.wsel.is_some() && mi.vex.is_none() && mi.evex.is_none() {
                        errors.push(ValidationError::BadField {
                            format: "map-insn".to_string(),
                            field: format!("{}: wsel には vex/evex が要る", mi.name),
                        });
                    }
                    // VEX/EVEX 項目は `vex_code` のある表にだけ置ける
                    // （無い表からは接頭辞経路で到達しない）。
                    if (mi.vex.is_some() || mi.evex.is_some()) && map.vex_code.is_none() {
                        errors.push(ValidationError::BadField {
                            format: "map-insn".to_string(),
                            field: format!("{}: vex には表の vex_code が要る", mi.name),
                        });
                    }
                    if let Some(g) = mi.group
                        && g > 7
                    {
                        errors.push(ValidationError::Unresolved {
                            kind: "map-group".to_string(),
                            name: format!("{}: /{}", mi.name, g),
                        });
                    }
                    if let Some(first) = map_insn_defs.get(mi.name.as_str()) {
                        // group はスロットの番号であり命令の同一性ではない
                        // （例: /4 と /6 が同じ shl を指すエイリアス）。
                        // `when`・`pfx` は命令の同一性ではなく表項目の成立条件
                        // （例: 0x82 が非64ビットモードでだけ 0x80 のエイリアス、
                        // MOVBE が接頭辞なしと 0x66 の両方で有効）なので
                        // 比較から外す。
                        let same = first.ops == mi.ops
                            && first.syntax == mi.syntax
                            && first.timing == mi.timing;
                        if !same {
                            errors.push(ValidationError::Unresolved {
                                kind: "map-insn-name".to_string(),
                                name: mi.name.clone(),
                            });
                        }
                    } else {
                        map_insn_defs.insert(mi.name.as_str(), mi);
                        if !insn_names.insert(mi.name.as_str()) {
                            errors.push(ValidationError::Unresolved {
                                kind: "map-insn-name".to_string(),
                                name: mi.name.clone(),
                            });
                        }
                    }
                    if !timing.contains(mi.timing.as_str()) {
                        errors.push(ValidationError::Unresolved {
                            kind: "timing".to_string(),
                            name: mi.timing.clone(),
                        });
                    }
                    if matches!(mi.when, crate::pred::Pred::False) {
                        // map 命令の到達不能も警告相当だが、errors には含めない。
                    }
                }
            }
        }
    }
    // 同一キー（byte, group, pfx）での重なり。各選択を接頭辞状態
    // （NP, 66, F2, F3）の集合として積を取る。
    let pfx_states = |s: PfxSel| -> u8 {
        match s {
            PfxSel::Any => 0b1111,
            PfxSel::Plain => 0b0001,
            PfxSel::P66 => 0b0010,
            PfxSel::PF2 => 0b0100,
            PfxSel::PF3 => 0b1000,
            PfxSel::No66 => 0b1101,
            PfxSel::No66F3 => 0b0101,
            PfxSel::NoF2 => 0b1011,
            PfxSel::NoF3 => 0b0111,
            PfxSel::NoF2F3 => 0b0011,
        }
    };
    let pfx_overlap = |a: PfxSel, b: PfxSel| (pfx_states(a) & pfx_states(b)) != 0;
    let pfx_disjoint = |a: PfxSel, b: PfxSel| !pfx_overlap(a, b);
    for map in &model.maps {
        let insns: Vec<(u8, &crate::model::MapInsn)> = map
            .items
            .iter()
            .filter_map(|i| match i {
                MapItem::Insn(b, mi) => Some((*b, mi)),
                _ => None,
            })
            .collect();
        for (i, (ba, a)) in insns.iter().enumerate() {
            for (bb, b) in insns.iter().skip(i + 1) {
                if ba != bb || a.group != b.group || pfx_disjoint(a.pfx, b.pfx) {
                    continue;
                }
                // VEX・EVEX・レガシー項目は別エンコーディング経路なので
                // 同じ表の同じスロットを置いても衝突しない。
                if a.vex.is_some() != b.vex.is_some() || a.evex.is_some() != b.evex.is_some() {
                    continue;
                }
                // W 選択が両方指定されていて値が違えば、同じ
                // エンコードには一致しない。
                if a.wsel.is_some() && b.wsel.is_some() && a.wsel != b.wsel {
                    continue;
                }
                // EVEX 項目同士は L'L の許容集合が排他なら衝突しない。
                // ただし {er} 項目は b=1+reg で L'L が丸め指定になり
                // 全 L'L を受理するので、0b111 として扱う。
                if let (Some(x), Some(y)) = (a.evex, b.evex) {
                    let x = if a.er { 0b111 } else { x };
                    let y = if b.er { 0b111 } else { y };
                    if x & y == 0 {
                        continue;
                    }
                }
                // VEX 項目同士は VEX.L の許容範囲が排他なら衝突しない。
                if let (Some(x), Some(y)) = (a.vex, b.vex)
                    && !matches!(
                        (x, y),
                        (crate::model::VexL::Any, _)
                            | (_, crate::model::VexL::Any)
                            | (crate::model::VexL::L0, crate::model::VexL::L0)
                            | (crate::model::VexL::L1, crate::model::VexL::L1)
                    )
                {
                    continue;
                }
                // `group_mod` が mod で排他なら同じ modrm を選ばない。
                if let (Some(x), Some(y)) = (a.group_mod, b.group_mod)
                    && x != y
                {
                    continue;
                }
                // `group_rm` が r/m で排他なら同じ modrm を選ばない。
                if let (Some(x), Some(y)) = (a.group_rm, b.group_rm)
                    && x != y
                {
                    continue;
                }
                if !a.when.maybe_both_true(&b.when) {
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
    }
}

/// `when` 述語に現れる旗名をすべて集める。
fn collect_flag_names(pred: &crate::pred::Pred, out: &mut Vec<String>) {
    use crate::pred::Pred;
    match pred {
        Pred::Flag(name) => out.push(name.clone()),
        Pred::Not(inner) => collect_flag_names(inner, out),
        Pred::All(ps) | Pred::Any(ps) => {
            for p in ps {
                collect_flag_names(p, out);
            }
        }
        Pred::True | Pred::False => {}
    }
}

/// `where` 句の組が互いに排他かどうか。同一フィールドへの矛盾があれば真。
/// 右辺がフィールドの句は、同じフィールドの組への矛盾があれば真とする
/// （`rs < rt` と `rs >= rt`、`rs == rt` と `rs != rt` など）。
fn wheres_disjoint(a: &[crate::model::WhereClause], b: &[crate::model::WhereClause]) -> bool {
    use crate::model::{WhereOp, WhereRhs};
    use WhereOp::{Eq, Ge, Gt, Le, Lt, Ne};
    for x in a {
        for y in b {
            match (&x.rhs, &y.rhs) {
                (WhereRhs::Lit(v), WhereRhs::Lit(w)) if x.field == y.field => match (x.op, y.op) {
                    (Eq, Eq) if v != w => return true,
                    (Eq, Ne) | (Ne, Eq) if v == w => return true,
                    _ => {}
                },
                (WhereRhs::Field(g), WhereRhs::Field(h)) => {
                    // 同順の対（x: f1 R1 f2, y: f1 R2 f2）と
                    // 逆順の対（x: f1 R1 f2, y: f2 R2 f1）で、
                    // R1 ∧ R2 が充足不能なら排他。
                    let ops: &[(WhereOp, WhereOp)] = &[
                        (Eq, Ne),
                        (Eq, Lt),
                        (Eq, Gt),
                        (Lt, Gt),
                        (Lt, Ge),
                        (Le, Gt),
                        (Ge, Lt),
                        (Gt, Le),
                        (Gt, Lt),
                        (Ne, Eq),
                        (Lt, Eq),
                        (Gt, Eq),
                    ];
                    if x.field == y.field && g == h {
                        if ops.contains(&(x.op, y.op)) {
                            return true;
                        }
                    } else if x.field == *h && g == &y.field {
                        let rev: &[(WhereOp, WhereOp)] = &[
                            (Eq, Ne),
                            (Eq, Lt),
                            (Eq, Gt),
                            (Lt, Lt),
                            (Lt, Le),
                            (Le, Lt),
                            (Gt, Gt),
                            (Gt, Ge),
                            (Ge, Gt),
                            (Ne, Eq),
                            (Lt, Eq),
                            (Gt, Eq),
                        ];
                        if rev.contains(&(x.op, y.op)) {
                            return true;
                        }
                    }
                }
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
            rhs: WhereRhs::Lit(0),
        }];
        m.insns.push(Insn {
            name: "add_alias".to_string(),
            format: "R".to_string(),
            pattern: Pattern::parse("0000000 ..... ..... 000 ..... 0110011").unwrap(),
            when: Pred::True,
            wheres: vec![WhereClause {
                field: "rs2".to_string(),
                op: WhereOp::Ne,
                rhs: WhereRhs::Lit(0),
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

    #[test]
    fn unknown_when_flag_is_rejected() {
        let mut m = test_model();
        m.insns[0].when = Pred::Flag("nosuchflag".to_string());
        let r = validate(&m);
        assert!(
            r.errors.iter().any(
                |e| matches!(e, ValidationError::Unresolved { kind, .. } if kind == "when-flag")
            ),
            "{:?}",
            r.errors
        );
    }

    #[test]
    fn unknown_model_parent_is_rejected() {
        let mut m = test_model();
        m.models.push(crate::model::ModelDef {
            params: vec![],
            name: "child".to_string(),
            parent: "nosuchparent".to_string(),
            add_features: vec![],
            remove_features: vec![],
            ident: vec![],
        });
        let r = validate(&m);
        assert!(
            r.errors.iter().any(
                |e| matches!(e, ValidationError::Unresolved { kind, .. } if kind == "model-parent")
            ),
            "{:?}",
            r.errors
        );
    }

    #[test]
    fn model_parent_cycle_is_rejected() {
        let mut m = test_model();
        for (name, parent) in [("a", "b"), ("b", "a")] {
            m.models.push(crate::model::ModelDef {
                params: vec![],
                name: name.to_string(),
                parent: parent.to_string(),
                add_features: vec![],
                remove_features: vec![],
                ident: vec![],
            });
        }
        let r = validate(&m);
        assert!(
            r.errors
                .iter()
                .any(|e| matches!(e, ValidationError::BadField { field, .. }
                    if field.contains("parent cycle"))),
            "{:?}",
            r.errors
        );
    }

    #[test]
    fn param_defaults_and_overrides_are_checked() {
        use crate::model::{Param, ParamKind};
        let mut m = test_model();
        // 既定値が列挙に無い宣言は拒否する。
        m.params.push(Param {
            name: "p0".to_string(),
            kind: ParamKind::Enum(vec!["a".to_string(), "b".to_string()]),
            default: "zzz".to_string(),
            doc: String::new(),
        });
        // 同名の二重宣言は拒否する。
        m.params.push(Param {
            name: "p0".to_string(),
            kind: ParamKind::Bool,
            default: "true".to_string(),
            doc: String::new(),
        });
        // 宣言の無いパラメータをモデルが上書きするのは拒否する。
        m.models.push(crate::model::ModelDef {
            params: vec![("nosuch".to_string(), "a".to_string())],
            name: "mdl".to_string(),
            parent: String::new(),
            add_features: vec![],
            remove_features: vec![],
            ident: vec![],
        });
        // 型に合わない上書き値は拒否する。
        m.params.push(Param {
            name: "p1".to_string(),
            kind: ParamKind::Int(10),
            default: "3".to_string(),
            doc: String::new(),
        });
        m.models.push(crate::model::ModelDef {
            params: vec![("p1".to_string(), "99".to_string())],
            name: "mdl2".to_string(),
            parent: String::new(),
            add_features: vec![],
            remove_features: vec![],
            ident: vec![],
        });
        let r = validate(&m);
        assert!(
            r.errors
                .iter()
                .any(|e| matches!(e, ValidationError::BadField { format, field }
                    if format == "param" && field.contains("p0: duplicate"))),
            "{:?}",
            r.errors
        );
        assert!(
            r.errors
                .iter()
                .any(|e| matches!(e, ValidationError::BadField { format, field }
                    if format == "param" && field.contains("p0: default"))),
            "{:?}",
            r.errors
        );
        assert!(
            r.errors.iter().any(
                |e| matches!(e, ValidationError::Unresolved { kind, .. } if kind == "model-param")
            ),
            "{:?}",
            r.errors
        );
        assert!(
            r.errors
                .iter()
                .any(|e| matches!(e, ValidationError::BadField { format, field }
                    if format == "param" && field.contains("p1"))),
            "{:?}",
            r.errors
        );
    }

    #[test]
    fn unknown_model_feature_is_rejected() {
        let mut m = test_model();
        m.features.push(Feature {
            name: "base".to_string(),
            implies: vec![],
            conflicts: vec![],
        });
        m.models.push(crate::model::ModelDef {
            params: vec![],
            name: "parent".to_string(),
            parent: String::new(),
            add_features: vec![],
            remove_features: vec![],
            ident: vec![],
        });
        m.models.push(crate::model::ModelDef {
            params: vec![],
            name: "child".to_string(),
            parent: "parent".to_string(),
            add_features: vec!["nosuchfeat".to_string()],
            remove_features: vec![],
            ident: vec![],
        });
        let r = validate(&m);
        assert!(
            r.errors.iter().any(
                |e| matches!(e, ValidationError::Unresolved { kind, .. } if kind == "model-feature")
            ),
            "{:?}",
            r.errors
        );
    }

    #[test]
    fn bad_ident_bit_is_rejected() {
        let mut m = test_model();
        m.features.push(Feature {
            name: "f0".to_string(),
            implies: vec![],
            conflicts: vec![],
        });
        m.ident_bits.push(crate::model::IdentBit {
            feature: "f0".to_string(),
            leaf: 1,
            subleaf: 0,
            reg: "eax".to_string(),
            bit: 32,
        });
        m.ident_bits.push(crate::model::IdentBit {
            feature: "nosuchfeat".to_string(),
            leaf: 1,
            subleaf: 0,
            reg: "eax".to_string(),
            bit: 0,
        });
        let r = validate(&m);
        assert!(
            r.errors
                .iter()
                .any(|e| matches!(e, ValidationError::BadField { .. })),
            "{:?}",
            r.errors
        );
        assert!(
            r.errors
                .iter()
                .any(|e| matches!(e, ValidationError::Unresolved { kind, .. } if kind == "ident-bit-feature")),
            "{:?}",
            r.errors
        );
    }
}
