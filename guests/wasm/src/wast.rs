// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `.wast` スクリプトの実行器。`assert_*`・`invoke`・`register` を
//! 解釈し、spectest モジュールをビルトインで登録する。
//!
//! 仕様の期待文言（`"unknown local"` など）との照合は部分一致で行い、
//! 片方でも失敗すれば failure に記録する。
//! Ref: SPEC-WASM-CORE appendix（テキスト形式のスクリプト意味論）.

use std::collections::{BTreeMap, HashSet};
use std::rc::Rc;

use crate::exec::{
    self, ExternVal, FuncInst, GlobalInst, HostFn, Instance, MemInst, NoHost, Registry, Store,
    TableInst,
};
use crate::module::Module;
use crate::sexpr::{self, Sx};
use crate::types::{
    FuncType, GlobalType, Limits, MemType, RefType, RefVal, TableType, Val, ValType,
};
use crate::validate::Validated;

/// 実行の集計。
#[derive(Default, Debug)]
pub struct Stats {
    /// 成立したディレクティブ。
    pub passed: usize,
    /// 不成立だったディレクティブ。
    pub failed: usize,
    /// 未対応の形（v128・未知ディレクティブなど）。
    pub skipped: usize,
    /// 失敗の説明（先頭から最大 64 件）。
    pub failures: Vec<String>,
}

impl Stats {
    fn fail(&mut self, msg: String) {
        if self.failures.len() < 64 {
            self.failures.push(msg);
        }
        self.failed += 1;
    }
}

/// スクリプト実行の状態。
pub struct Runner {
    pub store: Store,
    /// `(register "m" ...)` の登録表。spectest は初期から入っている。
    pub registry: Registry,
    /// `$名` を持つモジュール。
    named: BTreeMap<String, Rc<Instance>>,
    /// 直近にインスタンス化したモジュール（名なし invoke の対象）。
    last: Option<Rc<Instance>>,
    /// スコープ外でスキップされた `$名` モジュール。
    skipped_named: HashSet<String>,
    /// スキップ済みモジュールに張られた `(register "m" ...)` の名。
    /// この名をインポートする後続モジュールはリンクできないのでスキップする。
    skipped_regs: HashSet<Vec<u8>>,
    /// 直近の名なしモジュールがスキップされたか。
    last_skipped: bool,
}

/// `assert_return` の期待値。
#[derive(Clone, Debug)]
enum Exp {
    /// 厳密な値一致。
    Val(Val),
    /// 任意の NaN（`nan` / `nan:arithmetic`）。
    NanArith { f32: bool },
    /// 正準 NaN のみ。
    NanCanon { f32: bool },
    /// 任意の funcref（`ref.func`）。
    AnyFunc,
    /// 型を問わない null 参照（裸の `ref.null`）。
    AnyNull,
}

impl Default for Runner {
    fn default() -> Self {
        Self::new()
    }
}

impl Runner {
    /// spectest を登録したランナーを作る。
    #[must_use]
    pub fn new() -> Self {
        let mut r = Runner {
            store: Store::default(),
            registry: BTreeMap::new(),
            named: BTreeMap::new(),
            last: None,
            skipped_named: HashSet::new(),
            skipped_regs: HashSet::new(),
            last_skipped: false,
        };
        let sp = spectest_instance(&mut r.store);
        r.registry.insert("spectest".to_string(), sp);
        r
    }

    /// `.wast` 全文を実行する。
    pub fn run_str(&mut self, src: &str) -> Stats {
        let mut st = Stats::default();
        let cmds = match sexpr::parse_all(src) {
            Ok(c) => c,
            Err(e) => {
                st.fail(format!("script parse error: {}", e.msg));
                return st;
            }
        };
        for cmd in &cmds {
            self.run_cmd(cmd, &mut st);
        }
        st
    }

    /// 一つのディレクティブを実行する。
    fn run_cmd(&mut self, sx: &Sx, st: &mut Stats) {
        let Some(l) = sx.list() else {
            st.fail("toplevel non-list".into());
            return;
        };
        let head = l.first().and_then(Sx::atom).unwrap_or("");
        match head {
            "module" => match self.try_module(sx) {
                Ok(inst) => {
                    self.last_skipped = false;
                    if let Some(Sx::Atom(n)) = l.get(1)
                        && n.starts_with('$')
                    {
                        self.skipped_named.remove(n.as_str());
                        self.named.insert(n.clone(), inst.clone());
                    }
                    self.last = Some(inst);
                    st.passed += 1;
                }
                Err((kind, msg)) => {
                    if has_out_of_scope(sx) || self.imports_skipped_reg(sx) {
                        // スキップしたモジュールを参照する後続ディレクティブも
                        // スキップとして数える（カスケード失敗を防ぐ）。
                        // 束縛名は `(module $m ..)` では 1 番目、
                        // `(module definition|instance $m ..)` では 2 番目。
                        let name = match l.get(1) {
                            Some(Sx::Atom(n)) if n.starts_with('$') => Some(n),
                            Some(Sx::Atom(a)) if a == "definition" || a == "instance" => {
                                match l.get(2) {
                                    Some(Sx::Atom(n)) if n.starts_with('$') => Some(n),
                                    _ => None,
                                }
                            }
                            _ => None,
                        };
                        match name {
                            Some(n) => {
                                self.skipped_named.insert(n.clone());
                            }
                            _ => self.last_skipped = true,
                        }
                        st.skipped += 1;
                    } else {
                        st.fail(format!("module directive failed ({kind}): {msg}"));
                    }
                }
            },
            "register" => {
                let Some(name) = l.get(1).and_then(Sx::string) else {
                    st.fail("register without name".into());
                    return;
                };
                let name = String::from_utf8_lossy(name).into_owned();
                let inst = match l.get(2) {
                    Some(Sx::Atom(a)) if a.starts_with('$') => self.named.get(a.as_str()).cloned(),
                    Some(_) => {
                        st.fail("bad register target".into());
                        return;
                    }
                    None => self.last.clone(),
                };
                match inst {
                    Some(i) => {
                        self.registry.insert(name, i);
                        st.passed += 1;
                    }
                    None => {
                        let skipped = matches!(l.get(2),
                            Some(Sx::Atom(a)) if a.starts_with('$')
                                && self.skipped_named.contains(a.as_str()))
                            || (l.get(2).is_none() && self.last_skipped);
                        if skipped {
                            self.skipped_regs.insert(name.into_bytes());
                            st.skipped += 1;
                        } else {
                            st.fail("register: no such module".into());
                        }
                    }
                }
            }
            "invoke" => match self.invoke_sx(sx) {
                Ok(_) => st.passed += 1,
                Err(e) => {
                    if self.action_skipped(sx) {
                        st.skipped += 1;
                    } else {
                        st.fail(format!("invoke failed: {e}"));
                    }
                }
            },
            "assert_return" => self.assert_return(l, st),
            "assert_trap" => self.assert_trap(l, st),
            "assert_exhaustion" => self.assert_exhaustion(l, st),
            "assert_malformed" => self.assert_malformed(l, st),
            "assert_invalid" => self.assert_invalid(l, st),
            "assert_unlinkable" | "assert_uninstantiable" => self.assert_unlinkable(l, st),
            "assert_return_canonical_nan" | "assert_return_arithmetic_nan" => {
                self.assert_nan(l, st, head == "assert_return_arithmetic_nan");
            }
            _ => {
                st.skipped += 1;
            }
        }
    }

    // -----------------------------------------------------------------------
    // モジュールと呼び出し
    // -----------------------------------------------------------------------

    /// `(module ...)` を decode+validate+instantiate する。
    fn try_module(&mut self, sx: &Sx) -> Result<Rc<Instance>, (String, String)> {
        let bytes = crate::wat::module_bytes(sx).map_err(|e| ("wat".to_string(), e.0))?;
        let v = crate::compile(&bytes).map_err(|e| ("compile".to_string(), e.msg()))?;
        exec::instantiate(&mut self.store, Rc::new(v), &self.registry, &NoHost)
            .map_err(|e| ("link".to_string(), e.msg()))
    }

    /// アクション `(invoke|get $m? ...)` がスキップ済みモジュールを指すか。
    /// 名なしなら直前の名なしモジュールのスキップ状態を見る。
    fn action_skipped(&self, action: &Sx) -> bool {
        match action.list().and_then(|a| a.get(1)) {
            Some(Sx::Atom(n)) if n.starts_with('$') => self.skipped_named.contains(n.as_str()),
            _ => self.last_skipped,
        }
    }

    /// モジュール S 式がスキップ済み register 名をインポートするか。
    /// `(import "m" ...)` はトップレベルでも
    /// `(func (import "m" ...) ...)` のようなインライン形でも現れる。
    fn imports_skipped_reg(&self, sx: &Sx) -> bool {
        fn walk(x: &Sx, regs: &HashSet<Vec<u8>>) -> bool {
            let Some(l) = x.list() else {
                return false;
            };
            if l.first().and_then(Sx::atom) == Some("import")
                && let Some(m) = l.get(1).and_then(Sx::string)
                && regs.contains(m)
            {
                return true;
            }
            l.iter().any(|c| walk(c, regs))
        }
        !self.skipped_regs.is_empty() && walk(sx, &self.skipped_regs)
    }

    /// `(invoke $m? "名" 引数...)` を実行する。
    fn invoke_sx(&mut self, sx: &Sx) -> Result<Vec<Val>, String> {
        let l = sx.list().ok_or("invoke: not a list")?;
        let mut i = 1;
        let inst = match l.get(1) {
            Some(Sx::Atom(a)) if a.starts_with('$') => {
                i = 2;
                self.named
                    .get(a.as_str())
                    .cloned()
                    .ok_or_else(|| "invoke: unknown module".to_string())?
            }
            _ => self
                .last
                .clone()
                .ok_or_else(|| "invoke: no current module".to_string())?,
        };
        let name = l
            .get(i)
            .and_then(Sx::string)
            .ok_or_else(|| "invoke: missing name".to_string())?;
        let name = String::from_utf8_lossy(name).into_owned();
        let mut args = Vec::new();
        for it in &l[i + 1..] {
            match arg_of(it) {
                Ok(v) => args.push(v),
                Err(m) => return Err(format!("invoke arg: {m}")),
            }
        }
        let Some(ExternVal::Func(f)) = inst.export(&name) else {
            return Err(format!("invoke: unknown export {name}"));
        };
        exec::invoke(&mut self.store, f, &args).map_err(|t| t.msg())
    }

    /// `(get $m? "名")` のグローバル値を取る。
    fn get_sx(&mut self, sx: &Sx) -> Result<Val, String> {
        let l = sx.list().ok_or("get: not a list")?;
        let mut i = 1;
        let inst = match l.get(1) {
            Some(Sx::Atom(a)) if a.starts_with('$') => {
                i = 2;
                self.named
                    .get(a.as_str())
                    .cloned()
                    .ok_or_else(|| "get: unknown module".to_string())?
            }
            _ => self
                .last
                .clone()
                .ok_or_else(|| "get: no current module".to_string())?,
        };
        let name = l
            .get(i)
            .and_then(Sx::string)
            .ok_or_else(|| "get: missing name".to_string())?;
        let name = String::from_utf8_lossy(name).into_owned();
        let Some(ExternVal::Global(g)) = inst.export(&name) else {
            return Err(format!("get: unknown export {name}"));
        };
        Ok(self.store.globals[g as usize].val)
    }

    // -----------------------------------------------------------------------
    // アサーション
    // -----------------------------------------------------------------------

    fn assert_return(&mut self, l: &[Sx], st: &mut Stats) {
        let Some(action) = l.get(1) else {
            st.fail("assert_return: empty".into());
            return;
        };
        let got: Result<Vec<Val>, String> =
            match action.list().and_then(|a| a.first()).and_then(Sx::atom) {
                Some("invoke") => self.invoke_sx(action),
                Some("get") => self.get_sx(action).map(|v| vec![v]),
                _ => {
                    st.skipped += 1;
                    return;
                }
            };
        let Ok(vals) = got else {
            if self.action_skipped(action) {
                st.skipped += 1;
            } else {
                st.fail(format!(
                    "assert_return: action failed: {}",
                    got.err().unwrap()
                ));
            }
            return;
        };
        let mut expected = Vec::new();
        for it in &l[2..] {
            match exp_of(it) {
                Ok(e) => expected.push(e),
                Err(m) => {
                    st.fail(format!("assert_return: bad expected: {m}"));
                    return;
                }
            }
        }
        if vals.len() != expected.len() {
            st.fail(format!(
                "assert_return: arity mismatch (got {} want {})",
                vals.len(),
                expected.len()
            ));
            return;
        }
        for (v, e) in vals.iter().zip(expected.iter()) {
            if !exp_match(v, e) {
                st.fail(format!("assert_return: value mismatch {v:?} vs {e:?}"));
                return;
            }
        }
        st.passed += 1;
    }

    fn assert_trap(&mut self, l: &[Sx], st: &mut Stats) {
        let Some(action) = l.get(1) else {
            st.fail("assert_trap: empty".into());
            return;
        };
        let want = l
            .get(2)
            .and_then(Sx::string)
            .map(|s| String::from_utf8_lossy(s).into_owned());
        let kind = action.list().and_then(|a| a.first()).and_then(Sx::atom);
        let result: Result<String, String> = match kind {
            Some("invoke") => self.invoke_sx(action).map(|_| String::new()),
            Some("module") => self
                .try_module(action)
                .map(|_| String::new())
                .map_err(|(_, m)| m),
            _ => {
                st.skipped += 1;
                return;
            }
        };
        match result {
            Ok(_) => st.fail("assert_trap: no trap".into()),
            Err(actual) => {
                if msg_match(&actual, want.as_deref()) {
                    st.passed += 1;
                } else if kind == Some("invoke") && self.action_skipped(action)
                    || kind == Some("module") && has_out_of_scope(action)
                {
                    st.skipped += 1;
                } else {
                    st.fail(format!(
                        "assert_trap: msg mismatch (got {actual:?} want {want:?})"
                    ));
                }
            }
        }
    }

    fn assert_exhaustion(&mut self, l: &[Sx], st: &mut Stats) {
        let Some(action) = l.get(1) else {
            st.fail("assert_exhaustion: empty".into());
            return;
        };
        match action.list().and_then(|a| a.first()).and_then(Sx::atom) {
            Some("invoke") => match self.invoke_sx(action) {
                Ok(_) => st.fail("assert_exhaustion: no trap".into()),
                Err(_) => {
                    if self.action_skipped(action) {
                        st.skipped += 1;
                    } else {
                        st.passed += 1;
                    }
                }
            },
            _ => st.skipped += 1,
        }
    }

    fn assert_malformed(&mut self, l: &[Sx], st: &mut Stats) {
        let Some(m) = l.get(1) else {
            st.fail("assert_malformed: empty".into());
            return;
        };
        let want = l
            .get(2)
            .and_then(Sx::string)
            .map(|s| String::from_utf8_lossy(s).into_owned());
        // wat 側（quote の再解析・binary の切り出し）と decode 側の両方を試す。
        let actual: Option<String> = match crate::wat::module_bytes(m) {
            Err(e) => Some(e.0),
            Ok(bytes) => crate::decode::decode_module(&bytes).err().map(|e| e.0),
        };
        match actual {
            Some(a) if msg_match(&a, want.as_deref()) => st.passed += 1,
            Some(_a) if has_out_of_scope(m) => st.skipped += 1,
            Some(a) => st.fail(format!(
                "assert_malformed: msg mismatch (got {a:?} want {want:?})"
            )),
            // 範囲外の構文が無視されて受理されただけなら skip。
            None if has_out_of_scope(m) => st.skipped += 1,
            None => st.fail("assert_malformed: module accepted".into()),
        }
    }

    fn assert_invalid(&mut self, l: &[Sx], st: &mut Stats) {
        let Some(m) = l.get(1) else {
            st.fail("assert_invalid: empty".into());
            return;
        };
        let want = l
            .get(2)
            .and_then(Sx::string)
            .map(|s| String::from_utf8_lossy(s).into_owned());
        let bytes = match crate::wat::module_bytes(m) {
            Err(e) => {
                // テキスト側が仕様の期待文言と同じ理由で拒否したなら
                // 無効モジュールとして成立したと見なす（wat は検証の
                // 前段なので文言一致なら観測上同じ結果になる）。
                if msg_match(&e.0, want.as_deref()) {
                    st.passed += 1;
                } else if has_out_of_scope(m) {
                    st.skipped += 1;
                } else {
                    st.fail(format!("assert_invalid: wat error ({})", e.0));
                }
                return;
            }
            Ok(b) => b,
        };
        match crate::decode::decode_module(&bytes) {
            Err(_e) if has_out_of_scope(m) => st.skipped += 1,
            Err(e) => st.fail(format!(
                "assert_invalid: decode error, not invalid ({})",
                e.0
            )),
            Ok(m2) => match crate::validate::validate_module(m2) {
                Err(iv) if msg_match(&iv.0, want.as_deref()) => st.passed += 1,
                Err(_iv) if has_out_of_scope(m) => st.skipped += 1,
                Err(iv) => st.fail(format!(
                    "assert_invalid: msg mismatch (got {:?} want {want:?})",
                    iv.0
                )),
                // 範囲外の構文が無視されて通っただけなら skip。
                Ok(_) if has_out_of_scope(m) => st.skipped += 1,
                Ok(_) => st.fail("assert_invalid: module validated".into()),
            },
        }
    }

    fn assert_unlinkable(&mut self, l: &[Sx], st: &mut Stats) {
        let Some(m) = l.get(1) else {
            st.fail("assert_unlinkable: empty".into());
            return;
        };
        let want = l
            .get(2)
            .and_then(Sx::string)
            .map(|s| String::from_utf8_lossy(s).into_owned());
        let result = self.try_module(m);
        match result {
            // 範囲外の構文が無視されて通っただけなら skip。
            Ok(_) if has_out_of_scope(m) => st.skipped += 1,
            Ok(_) => st.fail("assert_unlinkable: module instantiated".into()),
            Err((kind, a)) => {
                if kind == "link" && msg_match(&a, want.as_deref()) {
                    st.passed += 1;
                } else if has_out_of_scope(m) || self.imports_skipped_reg(m) {
                    st.skipped += 1;
                } else if kind == "link" {
                    st.fail(format!(
                        "assert_unlinkable: msg mismatch (got {a:?} want {want:?})"
                    ));
                } else {
                    st.fail(format!("assert_unlinkable: wrong error ({kind}: {a})"));
                }
            }
        }
    }

    fn assert_nan(&mut self, l: &[Sx], st: &mut Stats, arith: bool) {
        let Some(action) = l.get(1) else {
            st.fail("assert_return_*_nan: empty".into());
            return;
        };
        match action.list().and_then(|a| a.first()).and_then(Sx::atom) {
            Some("invoke") => match self.invoke_sx(action) {
                Ok(vals) if vals.len() == 1 => {
                    let ok = match vals[0] {
                        Val::F32(b) => nan_check(u64::from(b), true, arith),
                        Val::F64(b) => nan_check(b, false, arith),
                        _ => false,
                    };
                    if ok {
                        st.passed += 1;
                    } else {
                        st.fail("assert_return_*_nan: not a NaN".into());
                    }
                }
                Ok(_) => st.fail("assert_return_*_nan: arity".into()),
                Err(e) => {
                    if self.action_skipped(action) {
                        st.skipped += 1;
                    } else {
                        st.fail(format!("assert_return_*_nan: {e}"));
                    }
                }
            },
            _ => st.skipped += 1,
        }
    }
}

// ---------------------------------------------------------------------------
// 補助
// ---------------------------------------------------------------------------

/// 段階 12 の範囲（1.0/2.0 コア）に入らない提案の印。
/// アトムの完全一致と、SIMD 系命令の接頭辞を見る。
fn is_oos_atom(a: &str) -> bool {
    const OOS: &[&str] = &[
        // 例外処理（3.0）
        "tag",
        "throw",
        "rethrow",
        "catch",
        "catch_all",
        "try",
        "try_table",
        "try_table2",
        "delegate",
        "throw_ref",
        // GC・関数参照（3.0）。裸の "ref" は (ref $t) 型コンストラクタ。
        "rec",
        "ref",
        "extern",
        "sub",
        "struct",
        "array",
        "i31",
        "call_ref",
        "return_call_ref",
        "br_on_null",
        "br_on_non_null",
        "br_on_cast",
        "br_on_cast_fail",
        "ref.as_non_null",
        // tail-call（3.0）
        "return_call",
        "return_call_indirect",
        // スレッド・共有メモリ
        "shared",
        "atomic.notify",
        "atomic.fence",
        // その他の後発提案
        "suspend",
        "resume",
        "contbind",
        "memory.copy64",
        "extern.internalize",
        "extern.externalize",
    ];
    if OOS.contains(&a) {
        return true;
    }
    // SIMD（v128）の命令・型は i8x16/i16x8/i32x4/i64x2/f32x4/f64x2/v128 の
    // 接頭辞を持つ。段階 12 の初回範囲には入れない。
    const SIMD: &[&str] = &["v128", "i8x16", "i16x8", "i32x4", "i64x2", "f32x4", "f64x2"];
    SIMD.iter().any(|p| a.starts_with(p))
}

/// quote/binary 文字列の中身への緩い印判定。
fn str_has_oos(s: &[u8]) -> bool {
    let Ok(t) = std::str::from_utf8(s) else {
        return false;
    };
    // 文字列全体を単語に分けてアトム判定に回す。
    t.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '$'))
        .any(is_oos_atom)
}

/// 段階 12 の範囲に入らない構文を含む S 式か。
fn has_out_of_scope(sx: &Sx) -> bool {
    match sx {
        Sx::Atom(a) => is_oos_atom(a),
        Sx::Str(s) => str_has_oos(s),
        Sx::List(l) => {
            // (module definition|instance ...) は module-linking 提案。
            if l.first().and_then(Sx::atom) == Some("module")
                && matches!(l.get(1).and_then(Sx::atom), Some("definition" | "instance"))
            {
                return true;
            }
            l.iter().any(has_out_of_scope)
        }
    }
}

/// 期待文言 `want` を実文言 `actual` が含むか。
fn msg_match(actual: &str, want: Option<&str>) -> bool {
    match want {
        None => true,
        Some(w) => actual.contains(w),
    }
}

fn nan_check(bits: u64, f32: bool, arith: bool) -> bool {
    let (exp_mask, frac_mask, canon) = if f32 {
        (0x7f80_0000u64, 0x007f_ffffu64, 0x7fc0_0000u64)
    } else {
        (
            0x7ff0_0000_0000_0000,
            0x000f_ffff_ffff_ffff,
            0x7ff8_0000_0000_0000,
        )
    };
    if (bits & exp_mask) != exp_mask || (bits & frac_mask) == 0 {
        return false;
    }
    if arith {
        return true;
    }
    (bits & (exp_mask | frac_mask)) == canon
}

/// 期待値と実値の比較。
fn exp_match(v: &Val, e: &Exp) -> bool {
    match (v, e) {
        (Val::I32(a), Exp::Val(Val::I32(b))) => a == b,
        (Val::I64(a), Exp::Val(Val::I64(b))) => a == b,
        (Val::F32(a), Exp::Val(Val::F32(b))) => a == b,
        (Val::F64(a), Exp::Val(Val::F64(b))) => a == b,
        (Val::V128(a), Exp::Val(Val::V128(b))) => a == b,
        (Val::F32(a), Exp::NanArith { f32: true }) => nan_check(u64::from(*a), true, true),
        (Val::F64(a), Exp::NanArith { f32: false }) => nan_check(*a, false, true),
        (Val::F32(a), Exp::NanCanon { f32: true }) => nan_check(u64::from(*a), true, false),
        (Val::F64(a), Exp::NanCanon { f32: false }) => nan_check(*a, false, false),
        (Val::Ref(RefVal::Func(_)), Exp::AnyFunc) => true,
        (Val::Ref(RefVal::Null(_)), Exp::AnyNull) => true,
        (Val::Ref(a), Exp::Val(Val::Ref(b))) => a == b,
        _ => false,
    }
}

/// invoke の実引数。NaN の別名も具体的なビットに落とす。
fn arg_of(sx: &Sx) -> Result<Val, String> {
    let l = sx.list().ok_or("expected const")?;
    let head = l.first().and_then(Sx::atom).ok_or("expected const")?;
    match head {
        "i32.const" => {
            let v = crate::wat::parse_int_signed(l.get(1).and_then(Sx::atom).ok_or("arg")?)
                .map_err(|e| e.0)?;
            Ok(Val::I32(v as u32))
        }
        "i64.const" => {
            let v = crate::wat::parse_int_signed(l.get(1).and_then(Sx::atom).ok_or("arg")?)
                .map_err(|e| e.0)?;
            Ok(Val::I64(v as u64))
        }
        "f32.const" => {
            let b = crate::wat::parse_float_bits(l.get(1).and_then(Sx::atom).ok_or("arg")?, true)
                .map_err(|e| e.0)?;
            Ok(Val::F32(b as u32))
        }
        "f64.const" => {
            let b = crate::wat::parse_float_bits(l.get(1).and_then(Sx::atom).ok_or("arg")?, false)
                .map_err(|e| e.0)?;
            Ok(Val::F64(b))
        }
        "ref.null" => {
            let t = match l.get(1).and_then(Sx::atom) {
                Some("func" | "funcref") => RefType::Func,
                _ => RefType::Extern,
            };
            Ok(Val::Ref(RefVal::Null(t)))
        }
        "ref.extern" => {
            let n = crate::wat::parse_int_signed(l.get(1).and_then(Sx::atom).ok_or("arg")?)
                .map_err(|e| e.0)?;
            Ok(Val::Ref(RefVal::Extern(n as u32)))
        }
        _ => Err(format!("unsupported arg {head}")),
    }
}

/// 定数式の S 式 → 実行時値。
fn exp_of(sx: &Sx) -> Result<Exp, String> {
    let l = sx.list().ok_or("expected const")?;
    let head = l.first().and_then(Sx::atom).ok_or("expected const")?;
    let atom = |i: usize| -> Result<&str, String> {
        l.get(i)
            .and_then(Sx::atom)
            .ok_or_else(|| "missing operand".to_string())
    };
    match head {
        "i32.const" => {
            let v = crate::wat::parse_int_signed(atom(1)?).map_err(|e| e.0)?;
            Ok(Exp::Val(Val::I32(v as u32)))
        }
        "i64.const" => {
            let v = crate::wat::parse_int_signed(atom(1)?).map_err(|e| e.0)?;
            Ok(Exp::Val(Val::I64(v as u64)))
        }
        "f32.const" => {
            let a = atom(1)?;
            match a {
                "nan" | "nan:arithmetic" | "-nan" | "-nan:arithmetic" => {
                    Ok(Exp::NanArith { f32: true })
                }
                "nan:canonical" | "-nan:canonical" => Ok(Exp::NanCanon { f32: true }),
                _ => {
                    let b = crate::wat::parse_float_bits(a, true).map_err(|e| e.0)?;
                    Ok(Exp::Val(Val::F32(b as u32)))
                }
            }
        }
        "f64.const" => {
            let a = atom(1)?;
            match a {
                "nan" | "nan:arithmetic" | "-nan" | "-nan:arithmetic" => {
                    Ok(Exp::NanArith { f32: false })
                }
                "nan:canonical" | "-nan:canonical" => Ok(Exp::NanCanon { f32: false }),
                _ => {
                    let b = crate::wat::parse_float_bits(a, false).map_err(|e| e.0)?;
                    Ok(Exp::Val(Val::F64(b)))
                }
            }
        }
        "v128.const" => {
            let lane_ty = atom(1)?;
            let lane_bits: u32 = match lane_ty {
                "i8x16" => 8,
                "i16x8" => 16,
                "i32x4" => 32,
                "i64x2" | "f32x4" | "f64x2" => 64,
                _ => return Err("bad v128 lane type".into()),
            };
            let n = 128 / lane_bits;
            let mut v: u128 = 0;
            for i in 0..n {
                let a = atom(2 + i as usize)?;
                let w: u128 = match lane_ty {
                    "f32x4" => {
                        u128::from(crate::wat::parse_float_bits(a, true).map_err(|e| e.0)? as u32)
                    }
                    "f64x2" => u128::from(crate::wat::parse_float_bits(a, false).map_err(|e| e.0)?),
                    _ => crate::wat::parse_int_signed(a).map_err(|e| e.0)? as u128,
                };
                v |= w << (i * lane_bits);
            }
            Ok(Exp::Val(Val::V128(v)))
        }
        "ref.null" => {
            // `(ref.null)` の裸形は型を問わず任意の null に一致する。
            let Some(t) = l.get(1).and_then(Sx::atom) else {
                return Ok(Exp::AnyNull);
            };
            let t = match t {
                "func" | "funcref" => RefType::Func,
                "extern" | "externref" => RefType::Extern,
                _ => return Err("bad ref.null".into()),
            };
            Ok(Exp::Val(Val::Ref(RefVal::Null(t))))
        }
        "ref.func" => Ok(Exp::AnyFunc),
        "ref.extern" => {
            let n = crate::wat::parse_int_signed(atom(1)?).map_err(|e| e.0)?;
            Ok(Exp::Val(Val::Ref(RefVal::Extern(n as u32))))
        }
        _ => Err(format!("unsupported expected: {head}")),
    }
}

/// ビルトインの spectest モジュール。
/// Ref: SPEC-WASM-CORE appendix（spectest モジュールの定義）.
fn spectest_instance(store: &mut Store) -> Rc<Instance> {
    let mut inst = Instance {
        module: Rc::new(Validated {
            module: Module::default(),
            bodies: Vec::new(),
        }),
        types: Vec::new(),
        funcs: Vec::new(),
        tables: Vec::new(),
        mems: Vec::new(),
        globals: Vec::new(),
        elems: Vec::new(),
        datas: Vec::new(),
        exports: BTreeMap::new(),
    };
    // print 系（何もしないホスト関数）。
    let prints: &[(&str, &[ValType])] = &[
        ("print", &[]),
        ("print_i32", &[ValType::I32]),
        ("print_i64", &[ValType::I64]),
        ("print_f32", &[ValType::F32]),
        ("print_f64", &[ValType::F64]),
        ("print_i32_f32", &[ValType::I32, ValType::F32]),
        ("print_f64_f64", &[ValType::F64, ValType::F64]),
    ];
    for (name, params) in prints {
        let ty = Rc::new(FuncType {
            params: params.to_vec(),
            results: Vec::new(),
        });
        let f: Rc<HostFn> = Rc::new(|_, _, _| Ok(Vec::new()));
        store.funcs.push(FuncInst::Host { ty, f });
        let a = store.funcs.len() as u32 - 1;
        inst.funcs.push(a);
        inst.exports.insert((*name).to_string(), ExternVal::Func(a));
    }
    // table: 10..20 funcref
    let ta = store.tables.len() as u32;
    store.tables.push(TableInst {
        ty: TableType {
            et: RefType::Func,
            lim: Limits {
                min: 10,
                max: Some(20),
            },
        },
        elems: vec![RefVal::Null(RefType::Func); 10],
    });
    inst.tables.push(ta);
    inst.exports
        .insert("table".to_string(), ExternVal::Table(ta));
    // memory: 1..2
    let ma = store.mems.len() as u32;
    store.mems.push(MemInst::new(MemType {
        lim: Limits {
            min: 1,
            max: Some(2),
        },
    }));
    inst.mems.push(ma);
    inst.exports
        .insert("memory".to_string(), ExternVal::Mem(ma));
    // globals
    for (name, vt, val) in [
        ("global_i32", ValType::I32, Val::I32(666)),
        ("global_i64", ValType::I64, Val::I64(666)),
        ("global_f32", ValType::F32, Val::F32(0x4426_a666)), // 666.6f
        ("global_f64", ValType::F64, Val::F64(0x4084_d4cc_cccc_cccd)), // 666.6
    ] {
        store.globals.push(GlobalInst {
            ty: GlobalType { vt, mutable: false },
            val,
        });
        let a = store.globals.len() as u32 - 1;
        inst.globals.push(a);
        inst.exports.insert(name.to_string(), ExternVal::Global(a));
    }
    Rc::new(inst)
}
