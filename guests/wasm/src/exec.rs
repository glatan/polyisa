// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 実行エンジン。ストア（store）、インスタンス、フレーム積みの
//! オペランドスタックマシン。汎用 `Backend` とは独立した専用の
//! 構造化インタプリタとする（wasm の構造制御はレジスタモデルに合わない）。
//!
//! 値は `Val`、トラップは `Trap`。ホスト関数は `HostFn` として
//! ストアに割り当て、モジュールのインポート解決に使う。
//! Ref: SPEC-WASM-CORE 4.4–4.6（実行・インスタンス化）.

use std::collections::BTreeMap;
use std::rc::Rc;

use crate::instr::{Instr, LoadOp, StoreOp};
use crate::module::{DataMode, ElemItem, ElemMode, Import, ImportDesc};
use crate::types::*;
use crate::validate::{Body, Validated};

// ---------------------------------------------------------------------------
// トラップ
// ---------------------------------------------------------------------------

/// トラップの種類。`assert_trap` の照合は `msg()` の仕様文言で行う。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TrapKind {
    /// `unreachable`。
    Unreachable,
    /// 0 除算。
    DivByZero,
    /// 符号付き除算のオーバーフロー。
    DivOverflow,
    /// 変換不能（NaN や範囲外の `trunc`）。
    InvalidConv,
    /// メモリ範囲外アクセス。
    OobMemory,
    /// テーブル範囲外アクセス。
    OobTable,
    /// `call_indirect` の指標がテーブル範囲外（"undefined element"）。
    UndefElem,
    /// `call_indirect` の要素が null。
    IndirectNull,
    /// `call_indirect` の型不一致。
    IndirectType,
    /// 呼び出し深さ・ステップ上限。
    Exhaustion,
    /// ホスト側が返したトラップ（WASI の errno 変換不能など）。
    Host,
    /// `proc_exit` による正常終了。コードを保持する。
    Exited(u32),
}

/// 実行時トラップ。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Trap {
    pub kind: TrapKind,
    /// 補足（ホスト側の詳細など）。
    pub note: Option<String>,
}

impl Trap {
    fn new(kind: TrapKind) -> Trap {
        Trap { kind, note: None }
    }

    fn noted(kind: TrapKind, note: impl Into<String>) -> Trap {
        Trap {
            kind,
            note: Some(note.into()),
        }
    }

    pub fn host(msg: impl Into<String>) -> Trap {
        Trap {
            kind: TrapKind::Host,
            note: Some(msg.into()),
        }
    }

    pub fn exit(code: u32) -> Trap {
        Trap {
            kind: TrapKind::Exited(code),
            note: None,
        }
    }

    /// 仕様テストの文言に対応する正規メッセージ。
    #[must_use]
    pub fn msg(&self) -> String {
        match &self.kind {
            TrapKind::Unreachable => "unreachable".to_string(),
            TrapKind::DivByZero => "integer divide by zero".to_string(),
            TrapKind::DivOverflow => "integer overflow".to_string(),
            TrapKind::InvalidConv => "invalid conversion to integer".to_string(),
            TrapKind::OobMemory => "out of bounds memory access".to_string(),
            TrapKind::OobTable => "out of bounds table access".to_string(),
            TrapKind::UndefElem => "undefined element".to_string(),
            TrapKind::IndirectNull => self
                .note
                .clone()
                .unwrap_or_else(|| "uninitialized element".to_string()),
            TrapKind::IndirectType => "indirect call type mismatch".to_string(),
            TrapKind::Exhaustion => "call stack exhausted".to_string(),
            TrapKind::Host => self.note.clone().unwrap_or_else(|| "host trap".to_string()),
            TrapKind::Exited(c) => format!("proc_exit({c})"),
        }
    }
}

// ---------------------------------------------------------------------------
// ストア
// ---------------------------------------------------------------------------

/// モジュール外から提供される外部値。store 内のアドレス。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExternVal {
    Func(u32),
    Table(u32),
    Mem(u32),
    Global(u32),
}

/// ホスト関数。`caller` は呼び出し側モジュールのインスタンス
/// （トップレベルから直接呼ばれたときは `None`）。
pub type HostFn = dyn Fn(&mut Store, Option<&Rc<Instance>>, &[Val]) -> Result<Vec<Val>, Trap>;

/// 関数インスタンス。
pub enum FuncInst {
    /// モジュール定義関数。
    Wasm {
        ty: Rc<FuncType>,
        module: Rc<Instance>,
        body: Rc<Body>,
    },
    /// ホスト関数。
    Host { ty: Rc<FuncType>, f: Rc<HostFn> },
}

impl FuncInst {
    #[must_use]
    pub fn ty(&self) -> &Rc<FuncType> {
        match self {
            Self::Wasm { ty, .. } | Self::Host { ty, .. } => ty,
        }
    }
}

/// テーブルインスタンス。
#[derive(Clone)]
pub struct TableInst {
    pub ty: TableType,
    pub elems: Vec<RefVal>,
}

/// メモリインスタンス。`data` はアクセスに応じて遅延確保し、
/// `pages` は論理サイズを示す（大きな `memory.grow` で即死しないため）。
pub struct MemInst {
    pub ty: MemType,
    /// 論理ページ数。
    pub pages: u32,
    /// 確保済みの先頭領域。未確保の領域は 0 として読む。
    data: Vec<u8>,
}

/// メモリアクセス失敗（実行では OobMemory トラップ、WASI では EFAULT）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MemFault;

impl MemInst {
    /// 初期サイズ `ty.lim.min` ページのメモリを作る。
    #[must_use]
    pub fn new(ty: MemType) -> MemInst {
        MemInst {
            ty,
            pages: ty.lim.min,
            data: Vec::new(),
        }
    }

    /// 論理サイズ（バイト）。
    #[must_use]
    pub fn byte_len(&self) -> u64 {
        u64::from(self.pages) * PAGE
    }

    /// `end` までをカバーするよう確保する（ページ単位に切り上げ）。
    fn ensure(&mut self, end: u64) {
        if end <= self.data.len() as u64 {
            return;
        }
        let want = end.min(self.byte_len());
        let rounded = want.div_ceil(PAGE) * PAGE;
        let cap = rounded.min(self.byte_len()) as usize;
        self.data.resize(cap, 0);
    }

    /// `addr` から `buf.len()` バイトを読む。
    pub fn read(&mut self, addr: u64, buf: &mut [u8]) -> Result<(), MemFault> {
        let end = addr + buf.len() as u64;
        if end > self.byte_len() {
            return Err(MemFault);
        }
        if end > self.data.len() as u64 {
            // 未確保領域はゼロ。
            let avail = self.data.len() as u64;
            if addr < avail {
                let n = (avail - addr) as usize;
                buf[..n].copy_from_slice(&self.data[addr as usize..addr as usize + n]);
            }
            let start = (avail.saturating_sub(addr) as usize).min(buf.len());
            for b in &mut buf[start..] {
                *b = 0;
            }
            return Ok(());
        }
        buf.copy_from_slice(&self.data[addr as usize..end as usize]);
        Ok(())
    }

    /// `addr` に `bytes` を書く。
    pub fn write(&mut self, addr: u64, bytes: &[u8]) -> Result<(), MemFault> {
        let end = addr + bytes.len() as u64;
        if end > self.byte_len() {
            return Err(MemFault);
        }
        self.ensure(end);
        self.data[addr as usize..end as usize].copy_from_slice(bytes);
        Ok(())
    }

    /// `addr` から `n` バイトを `v` で埋める。
    pub fn fill(&mut self, addr: u64, v: u8, n: u64) -> Result<(), MemFault> {
        let end = addr + n;
        if end > self.byte_len() {
            return Err(MemFault);
        }
        self.ensure(end);
        self.data[addr as usize..end as usize].fill(v);
        Ok(())
    }

    /// 範囲コピー（memmove 相当）。
    pub fn copy_within(&mut self, dst: u64, src: u64, n: u64) -> Result<(), MemFault> {
        if src + n > self.byte_len() || dst + n > self.byte_len() {
            return Err(MemFault);
        }
        self.ensure((dst + n).max(src + n));
        self.data
            .copy_within(src as usize..(src + n) as usize, dst as usize);
        Ok(())
    }

    /// `n` ページ拡張する。成功で旧ページ数、失敗で -1。
    pub fn grow(&mut self, n: u32) -> i32 {
        let old = self.pages;
        let hard = self.ty.lim.max.unwrap_or(MAX_PAGES).min(MAX_PAGES);
        match old.checked_add(n) {
            Some(new) if new <= hard => {
                self.pages = new;
                old as i32
            }
            _ => -1,
        }
    }
}

/// グローバルインスタンス。
#[derive(Clone)]
pub struct GlobalInst {
    pub ty: GlobalType,
    pub val: Val,
}

/// エレメントインスタンス（init 済みの参照列。drop で空にする）。
pub struct ElemInst {
    pub ty: RefType,
    pub list: Vec<RefVal>,
}

/// データインスタンス。
pub struct DataInst {
    pub bytes: Vec<u8>,
}

/// ストア。全インスタンスの集まり。
#[derive(Default)]
pub struct Store {
    pub funcs: Vec<FuncInst>,
    pub tables: Vec<TableInst>,
    pub mems: Vec<MemInst>,
    pub globals: Vec<GlobalInst>,
    pub elems: Vec<ElemInst>,
    pub datas: Vec<DataInst>,
}

/// ホストのインポート解決。レジストリに無い名前を提供する。
pub trait Host {
    /// `(module, name)` のインポートに対応する外部値を返す。
    /// `want` はモジュールが要求する外部型。型が合わないものを
    /// 返してはいけない（呼び出し側で検査する）。
    fn provide(
        &self,
        store: &mut Store,
        module: &str,
        name: &str,
        want: &ExternType,
    ) -> Option<ExternVal>;
}

/// インポート解決なしのホスト（何も提供しない）。
pub struct NoHost;

impl Host for NoHost {
    fn provide(&self, _s: &mut Store, _m: &str, _n: &str, _w: &ExternType) -> Option<ExternVal> {
        None
    }
}

/// `(register "名" inst)` で登録されたモジュール群。
pub type Registry = BTreeMap<String, Rc<Instance>>;

/// モジュール全体のエラー。
#[derive(Debug)]
pub enum Error {
    Decode(crate::instr::DecodeError),
    Invalid(crate::validate::Invalid),
    Link(String),
    Trap(Trap),
}

impl Error {
    /// エラーの説明文。
    #[must_use]
    pub fn msg(&self) -> String {
        match self {
            Self::Decode(e) => e.0.clone(),
            Self::Invalid(e) => e.0.clone(),
            Self::Link(s) => s.clone(),
            Self::Trap(t) => t.msg(),
        }
    }
}

// ---------------------------------------------------------------------------
// インスタンス
// ---------------------------------------------------------------------------

/// モジュールインスタンス。
pub struct Instance {
    pub module: Rc<Validated>,
    /// 型指標 -> 関数型（`call_indirect` の照合用）。
    pub types: Vec<Rc<FuncType>>,
    pub funcs: Vec<u32>,
    pub tables: Vec<u32>,
    pub mems: Vec<u32>,
    pub globals: Vec<u32>,
    pub elems: Vec<u32>,
    pub datas: Vec<u32>,
    pub exports: BTreeMap<String, ExternVal>,
}

impl Instance {
    /// エクスポート名から外部値を引く。
    #[must_use]
    pub fn export(&self, name: &str) -> Option<ExternVal> {
        self.exports.get(name).copied()
    }

    /// メモリ 0 番。
    pub fn mem0(&self) -> Option<u32> {
        self.mems.first().copied()
    }
}

/// リミットの一致：実側 `a` が要求 `w` を満たすか。
fn limits_match(a: &Limits, w: &Limits) -> bool {
    if a.min < w.min {
        return false;
    }
    match w.max {
        None => true,
        Some(wm) => a.max.is_some_and(|am| am <= wm),
    }
}

/// インポート一致の検査。
fn extern_matches(store: &Store, v: ExternVal, want: &ExternType) -> bool {
    match (v, want) {
        (ExternVal::Func(a), ExternType::Func(ft)) => **store.funcs[a as usize].ty() == *ft,
        (ExternVal::Table(a), ExternType::Table(t)) => {
            // 外部型のリミットは現在サイズを下限とする（成長した実体を
            // 取り込めるようにするため宣言 min ではなく len を見る）。
            let at = &store.tables[a as usize];
            let al = Limits {
                min: at.elems.len() as u32,
                max: at.ty.lim.max,
            };
            at.ty.et == t.et && limits_match(&al, &t.lim)
        }
        (ExternVal::Mem(a), ExternType::Mem(t)) => {
            let am = &store.mems[a as usize];
            let al = Limits {
                min: am.pages,
                max: am.ty.lim.max,
            };
            limits_match(&al, &t.lim)
        }
        (ExternVal::Global(a), ExternType::Global(g)) => store.globals[a as usize].ty == *g,
        _ => false,
    }
}

/// インポート記述子が要求する外部型。
fn want_of(m: &crate::module::Module, imp: &Import) -> Option<ExternType> {
    Some(match &imp.desc {
        ImportDesc::Func(t) => ExternType::Func(m.types.get(*t as usize)?.clone()),
        ImportDesc::Table(t) => ExternType::Table(*t),
        ImportDesc::Mem(t) => ExternType::Mem(*t),
        ImportDesc::Global(g) => ExternType::Global(*g),
    })
}

/// インポートを解決する。レジストリ → ホストの順。
fn resolve_import(
    store: &mut Store,
    registry: &Registry,
    host: &dyn Host,
    m: &crate::module::Module,
    imp: &Import,
) -> Result<ExternVal, Error> {
    let want = want_of(m, imp).ok_or_else(|| Error::Link("incompatible import type".into()))?;
    let ev = registry
        .get(&imp.module)
        .and_then(|inst| inst.export(&imp.name))
        .or_else(|| host.provide(store, &imp.module, &imp.name, &want));
    let Some(ev) = ev else {
        return Err(Error::Link("unknown import".into()));
    };
    if !extern_matches(store, ev, &want) {
        return Err(Error::Link("incompatible import type".into()));
    }
    Ok(ev)
}

/// 定数式を評価する。
fn eval_const(store: &Store, inst: &Instance, e: &crate::module::ConstExpr) -> Result<Val, Trap> {
    let mut stack: Vec<Val> = Vec::new();
    for ins in &e.instrs {
        match *ins {
            Instr::I32Const(v) => stack.push(Val::I32(v as u32)),
            Instr::I64Const(v) => stack.push(Val::I64(v as u64)),
            Instr::F32Const(v) => stack.push(Val::F32(v)),
            Instr::F64Const(v) => stack.push(Val::F64(v)),
            Instr::RefNull(t) => stack.push(Val::Ref(RefVal::Null(t))),
            Instr::RefFunc(f) => stack.push(Val::Ref(RefVal::Func(inst.funcs[f as usize]))),
            Instr::GlobalGet(g) => {
                let addr = inst.globals[g as usize];
                stack.push(store.globals[addr as usize].val);
            }
            // extended const (2.0)
            Instr::I32Add | Instr::I32Sub | Instr::I32Mul => {
                let (Some(Val::I32(b)), Some(Val::I32(a))) = (stack.pop(), stack.pop()) else {
                    return Err(Trap::host("non-constant expression"));
                };
                stack.push(Val::I32(match *ins {
                    Instr::I32Add => a.wrapping_add(b),
                    Instr::I32Sub => a.wrapping_sub(b),
                    _ => a.wrapping_mul(b),
                }));
            }
            Instr::I64Add | Instr::I64Sub | Instr::I64Mul => {
                let (Some(Val::I64(b)), Some(Val::I64(a))) = (stack.pop(), stack.pop()) else {
                    return Err(Trap::host("non-constant expression"));
                };
                stack.push(Val::I64(match *ins {
                    Instr::I64Add => a.wrapping_add(b),
                    Instr::I64Sub => a.wrapping_sub(b),
                    _ => a.wrapping_mul(b),
                }));
            }
            Instr::End => {}
            _ => return Err(Trap::host("non-constant expression")),
        }
    }
    stack.pop().ok_or_else(|| Trap::host("empty const expr"))
}

/// モジュールをインスタンス化する。`registry` は `(register ...)` 済みの
/// モジュール、`host` が残りのインポートを提供する。
/// Ref: SPEC-WASM-CORE 4.5.5（instantiation）.
#[allow(clippy::too_many_lines)]
pub fn instantiate(
    store: &mut Store,
    v: Rc<Validated>,
    registry: &Registry,
    host: &dyn Host,
) -> Result<Rc<Instance>, Error> {
    let m = &v.module;
    // --- 1. インポート解決 ---
    let mut funcs: Vec<u32> = Vec::new();
    let mut tables: Vec<u32> = Vec::new();
    let mut mems: Vec<u32> = Vec::new();
    let mut globals: Vec<u32> = Vec::new();
    for imp in &m.imports {
        match resolve_import(store, registry, host, m, imp)? {
            ExternVal::Func(a) => funcs.push(a),
            ExternVal::Table(a) => tables.push(a),
            ExternVal::Mem(a) => mems.push(a),
            ExternVal::Global(a) => globals.push(a),
        }
    }
    // --- 2. 自モジュールのオブジェクトのアドレスを予約・確保 ---
    let base_func = store.funcs.len() as u32;
    for (i, _) in m.funcs.iter().enumerate() {
        funcs.push(base_func + i as u32);
    }
    for t in &m.tables {
        tables.push(store.tables.len() as u32);
        store.tables.push(TableInst {
            ty: *t,
            elems: vec![RefVal::Null(t.et); t.lim.min as usize],
        });
    }
    for t in &m.mems {
        mems.push(store.mems.len() as u32);
        store.mems.push(MemInst::new(*t));
    }
    let base_global = store.globals.len() as u32;
    for (i, _) in m.globals.iter().enumerate() {
        globals.push(base_global + i as u32);
    }
    let base_elem = store.elems.len() as u32;
    let elems: Vec<u32> = (0..m.elems.len()).map(|i| base_elem + i as u32).collect();
    let base_data = store.datas.len() as u32;
    let datas: Vec<u32> = (0..m.datas.len()).map(|i| base_data + i as u32).collect();
    // --- 3. インスタンスとエクスポート ---
    let mut exports = BTreeMap::new();
    for x in &m.exports {
        let ev = match x.kind {
            0 => ExternVal::Func(funcs[x.idx as usize]),
            1 => ExternVal::Table(tables[x.idx as usize]),
            2 => ExternVal::Mem(mems[x.idx as usize]),
            3 => ExternVal::Global(globals[x.idx as usize]),
            _ => continue,
        };
        exports.insert(x.name.clone(), ev);
    }
    let types: Vec<Rc<FuncType>> = m.types.iter().cloned().map(Rc::new).collect();
    let inst = Rc::new(Instance {
        module: Rc::clone(&v),
        types,
        funcs,
        tables,
        mems,
        globals,
        elems,
        datas,
        exports,
    });
    // --- 4. 定義関数の割当 ---
    for (i, tyidx) in m.funcs.iter().enumerate() {
        store.funcs.push(FuncInst::Wasm {
            ty: Rc::clone(&inst.types[*tyidx as usize]),
            module: Rc::clone(&inst),
            body: Rc::new(v.bodies[i].clone()),
        });
    }
    // --- 5. グローバル初期化 ---
    for g in &m.globals {
        let val = eval_const(store, &inst, &g.init).map_err(Error::Trap)?;
        store.globals.push(GlobalInst { ty: g.ty, val });
    }
    // --- 5b. テーブル初期化式（2.0 の `0x40 0x00` 形） ---
    for (i, init) in m.table_inits.iter().enumerate() {
        if let Some(e) = init {
            let val = eval_const(store, &inst, e).map_err(Error::Trap)?;
            if let Val::Ref(rv) = val {
                store.tables[inst.tables[i] as usize].elems.fill(rv);
            }
        }
    }
    // --- 6. エレメントの評価・格納 ---
    for e in &m.elems {
        let list: Vec<RefVal> = match &e.init {
            ElemItem::Funcs(fs) => fs
                .iter()
                .map(|f| RefVal::Func(inst.funcs[*f as usize]))
                .collect(),
            ElemItem::Exprs(es) => {
                let mut out = Vec::with_capacity(es.len());
                for ex in es {
                    match eval_const(store, &inst, ex).map_err(Error::Trap)? {
                        Val::Ref(r) => out.push(r),
                        _ => return Err(Error::Link("bad elem expr".into())),
                    }
                }
                out
            }
        };
        store.elems.push(ElemInst { ty: e.ty, list });
    }
    // --- 7. データ格納 ---
    for d in &m.datas {
        store.datas.push(DataInst {
            bytes: d.bytes.clone(),
        });
    }
    // --- 8. アクティブセグメントの適用 ---
    for (i, e) in m.elems.iter().enumerate() {
        if let ElemMode::Active { table, offset } = &e.mode {
            let off = match eval_const(store, &inst, offset).map_err(Error::Trap)? {
                Val::I32(v) => u64::from(v),
                _ => return Err(Error::Link("bad elem offset".into())),
            };
            let taddr = inst.tables[*table as usize] as usize;
            let len = store.elems[inst.elems[i] as usize].list.len() as u64;
            if off + len > store.tables[taddr].elems.len() as u64 {
                return Err(Error::Trap(Trap::new(TrapKind::OobTable)));
            }
            let list = std::mem::take(&mut store.elems[inst.elems[i] as usize].list);
            for (j, r) in list.iter().enumerate() {
                store.tables[taddr].elems[off as usize + j] = *r;
            }
            store.elems[inst.elems[i] as usize].list = list;
        }
    }
    for (i, d) in m.datas.iter().enumerate() {
        if let DataMode::Active { mem, offset } = &d.mode {
            let off = match eval_const(store, &inst, offset).map_err(Error::Trap)? {
                Val::I32(v) => u64::from(v),
                _ => return Err(Error::Link("bad data offset".into())),
            };
            let maddr = inst.mems[*mem as usize] as usize;
            let len = store.datas[inst.datas[i] as usize].bytes.len() as u64;
            if off + len > store.mems[maddr].byte_len() {
                return Err(Error::Trap(Trap::new(TrapKind::OobMemory)));
            }
            let bytes = std::mem::take(&mut store.datas[inst.datas[i] as usize].bytes);
            store.mems[maddr]
                .write(off, &bytes)
                .map_err(|_| Error::Trap(Trap::new(TrapKind::OobMemory)))?;
            store.datas[inst.datas[i] as usize].bytes = bytes;
            // アクティブセグメントは適用後に空になる。
            store.datas[inst.datas[i] as usize].bytes = Vec::new();
        }
    }
    // アクティブエレメントも同様に空にする。
    for (i, e) in m.elems.iter().enumerate() {
        if matches!(e.mode, ElemMode::Active { .. } | ElemMode::Declared) {
            store.elems[inst.elems[i] as usize].list = Vec::new();
        }
    }
    // --- 9. スタート関数 ---
    if let Some(s) = m.start {
        invoke(store, inst.funcs[s as usize], &[]).map_err(Error::Trap)?;
    }
    Ok(inst)
}

// ---------------------------------------------------------------------------
// インタプリタ
// ---------------------------------------------------------------------------

/// 呼び出し深さの上限（`assert_exhaustion` で尽きるのに十分小さく）。
const MAX_DEPTH: usize = 4096;
/// 一呼び出し当たりのステップ上限（暴走防止）。
const STEP_BUDGET: u64 = 1_000_000_000;

/// 実行中のラベル。
#[derive(Clone, Copy)]
struct Label {
    /// ジャンプ先の命令指標（block/if=End、loop=Loop+1）。
    target: usize,
    /// ラベルの arity。
    arity: usize,
    /// ブロック入力の下のスタック高さ。
    height: usize,
}

/// 呼び出しフレーム。
struct Frame {
    inst: Rc<Instance>,
    code: Rc<Body>,
    locals: Vec<Val>,
    pc: usize,
    /// 結果の個数。
    arity: usize,
    /// 共有オペランドスタック上のこのフレームの底。
    base: usize,
    labels: Vec<Label>,
}

fn block_arity(inst: &Instance, bt: BlockType) -> (usize, usize) {
    match bt {
        BlockType::Empty => (0, 0),
        BlockType::Val(_) => (0, 1),
        BlockType::Func(i) => {
            let ft = &inst.types[i as usize];
            (ft.params.len(), ft.results.len())
        }
    }
}

// 値スタックの取り出し（検証済みなので型は決まっている。防御的に既定値を返す）。
fn ppop(vals: &mut Vec<Val>) -> Val {
    vals.pop().unwrap_or(Val::I32(0))
}
fn pi32(vals: &mut Vec<Val>) -> u32 {
    match ppop(vals) {
        Val::I32(v) => v,
        _ => 0,
    }
}
fn pi64(vals: &mut Vec<Val>) -> u64 {
    match ppop(vals) {
        Val::I64(v) => v,
        _ => 0,
    }
}
fn pf32(vals: &mut Vec<Val>) -> f32 {
    match ppop(vals) {
        Val::F32(v) => f32::from_bits(v),
        _ => 0.0,
    }
}
fn pf64(vals: &mut Vec<Val>) -> f64 {
    match ppop(vals) {
        Val::F64(v) => f64::from_bits(v),
        _ => 0.0,
    }
}
fn pref(vals: &mut Vec<Val>) -> RefVal {
    match ppop(vals) {
        Val::Ref(r) => r,
        _ => RefVal::Null(RefType::Func),
    }
}

/// 呼び出し対象。借用を切るため `store.funcs` の参照ではなく所有値を使う。
enum CallTarget {
    Wasm {
        module: Rc<Instance>,
        ty: Rc<FuncType>,
        body: Rc<Body>,
    },
    Host(Rc<HostFn>),
}

/// 関数呼び出し。Wasm なら新フレーム、Host なら即呼んで結果を積む。
/// `vals` は共有オペランドスタック。
fn push_call(
    store: &mut Store,
    vals: &mut Vec<Val>,
    frames: &mut Vec<Frame>,
    faddr: u32,
    depth: usize,
) -> Result<(), Trap> {
    let Some(func) = store.funcs.get(faddr as usize) else {
        return Err(Trap::host("unknown function address"));
    };
    let nparams = func.ty().params.len();
    let target = match func {
        FuncInst::Wasm { ty, module, body } => CallTarget::Wasm {
            module: Rc::clone(module),
            ty: Rc::clone(ty),
            body: Rc::clone(body),
        },
        FuncInst::Host { f, .. } => CallTarget::Host(Rc::clone(f)),
    };
    let args: Vec<Val> = if vals.len() >= nparams {
        vals.split_off(vals.len() - nparams)
    } else {
        Vec::new()
    };
    match target {
        CallTarget::Wasm { module, ty, body } => {
            if depth >= MAX_DEPTH {
                return Err(Trap::new(TrapKind::Exhaustion));
            }
            let mut locals = args;
            locals.resize(nparams + body.locals.len(), Val::I32(0));
            // 宣言ローカルは型の既定値。
            for (i, t) in body.locals.iter().enumerate() {
                locals[nparams + i] = Val::zero(*t);
            }
            frames.push(Frame {
                inst: module,
                code: body,
                locals,
                pc: 0,
                arity: ty.results.len(),
                base: vals.len(),
                labels: Vec::new(),
            });
            Ok(())
        }
        CallTarget::Host(f) => {
            let caller = frames.last().map(|fr| Rc::clone(&fr.inst));
            let results = f(store, caller.as_ref(), &args)?;
            vals.extend(results);
            Ok(())
        }
    }
}

/// フレームを閉じて結果を呼び出し側へ返す。最後のフレームなら結果を返す。
fn return_frame(vals: &mut Vec<Val>, frames: &mut Vec<Frame>) -> Result<Option<Vec<Val>>, Trap> {
    let fr = frames.pop().ok_or_else(|| Trap::host("frame underflow"))?;
    let base = fr.base;
    let n = fr.arity.min(vals.len().saturating_sub(base));
    let results: Vec<Val> = vals.split_off(vals.len() - n);
    vals.truncate(base);
    if frames.is_empty() {
        return Ok(Some(results));
    }
    vals.extend(results);
    Ok(None)
}

/// `br`/`br_if`/`br_table` のジャンプ。フレーム外（関数ラベル）への
/// 分岐は関数からの脱出とする。
fn do_branch(
    vals: &mut Vec<Val>,
    frames: &mut Vec<Frame>,
    l: u32,
) -> Result<Option<Vec<Val>>, Trap> {
    let depth = frames.last().map_or(0, |f| f.labels.len());
    if l as usize >= depth {
        // 関数ラベル（最外）への分岐は return。
        return return_frame(vals, frames);
    }
    let fr = frames.last_mut().ok_or_else(|| Trap::host("no frame"))?;
    let lab = fr.labels[depth - 1 - l as usize];
    let a = lab.arity.min(vals.len().saturating_sub(lab.height));
    let start = vals.len() - a;
    // 結果を高さ `lab.height` へ移す。
    let tmp: Vec<Val> = vals[start..].to_vec();
    vals.truncate(lab.height);
    vals.extend(tmp);
    // ターゲットのラベルは残し、その内側を捨てる。
    fr.labels.truncate(depth - l as usize);
    fr.pc = lab.target;
    Ok(None)
}

/// メモリ 0 番のアドレスを取る。無ければホストトラップ（検証で防がれる）。
fn mem0(inst: &Instance) -> Result<u32, Trap> {
    inst.mem0().ok_or_else(|| Trap::new(TrapKind::OobMemory))
}

/// フレームのメインループ。
#[allow(clippy::too_many_lines)]
fn run(store: &mut Store, vals: &mut Vec<Val>, frames: &mut Vec<Frame>) -> Result<Vec<Val>, Trap> {
    let mut steps = STEP_BUDGET;
    loop {
        steps -= 1;
        if steps == 0 {
            return Err(Trap::new(TrapKind::Exhaustion));
        }
        let Some(fr) = frames.last_mut() else {
            return Err(Trap::host("no frame"));
        };
        let code = Rc::clone(&fr.code);
        let pc = fr.pc;
        fr.pc = pc + 1;
        let Some(ins) = code.instrs.get(pc) else {
            return Err(Trap::host("pc out of bounds"));
        };
        match ins {
            Instr::Unreachable => return Err(Trap::new(TrapKind::Unreachable)),
            Instr::Nop => {}
            Instr::Block { bt, end } => {
                let fr = frames.last_mut().unwrap();
                let (sin, sout) = block_arity(&fr.inst, *bt);
                fr.labels.push(Label {
                    target: *end as usize,
                    arity: sout,
                    height: vals.len() - sin,
                });
            }
            Instr::Loop { bt, .. } => {
                let fr = frames.last_mut().unwrap();
                let (sin, _) = block_arity(&fr.inst, *bt);
                fr.labels.push(Label {
                    target: fr.pc,
                    arity: sin,
                    height: vals.len() - sin,
                });
            }
            Instr::If { bt, els, end } => {
                let c = pi32(vals);
                let fr = frames.last_mut().unwrap();
                let (sin, sout) = block_arity(&fr.inst, *bt);
                fr.labels.push(Label {
                    target: *end as usize,
                    arity: sout,
                    height: vals.len() - sin,
                });
                if c == 0 {
                    // else 部の先頭から。else が無い（els==end）ときは End へ。
                    fr.pc = if els == end {
                        *end as usize
                    } else {
                        *els as usize + 1
                    };
                }
            }
            Instr::Else { end } => {
                frames.last_mut().unwrap().pc = *end as usize;
            }
            Instr::End => {
                let popped = frames.last_mut().and_then(|f| f.labels.pop());
                if popped.is_none()
                    && let Some(done) = return_frame(vals, frames)?
                {
                    return Ok(done);
                }
            }
            Instr::Br { l } => {
                if let Some(done) = do_branch(vals, frames, *l)? {
                    return Ok(done);
                }
            }
            Instr::BrIf { l } => {
                let c = pi32(vals);
                if c != 0
                    && let Some(done) = do_branch(vals, frames, *l)?
                {
                    return Ok(done);
                }
            }
            Instr::BrTable { ls, ln } => {
                let i = pi32(vals) as usize;
                let l = ls.get(i).copied().unwrap_or(*ln);
                if let Some(done) = do_branch(vals, frames, l)? {
                    return Ok(done);
                }
            }
            Instr::Return => {
                if let Some(done) = return_frame(vals, frames)? {
                    return Ok(done);
                }
            }
            Instr::Call { f } => {
                let faddr = frames.last().unwrap().inst.funcs[*f as usize];
                let depth = frames.len();
                push_call(store, vals, frames, faddr, depth)?;
            }
            Instr::CallIndirect { ty, table } => {
                let i = pi32(vals) as usize;
                let (taddr, want) = {
                    let fr = frames.last().unwrap();
                    (
                        fr.inst.tables[*table as usize] as usize,
                        Rc::clone(&fr.inst.types[*ty as usize]),
                    )
                };
                let Some(elem) = store.tables[taddr].elems.get(i) else {
                    return Err(Trap::new(TrapKind::UndefElem));
                };
                let faddr = match *elem {
                    RefVal::Null(_) => {
                        return Err(Trap::noted(
                            TrapKind::IndirectNull,
                            format!("uninitialized element {i}"),
                        ));
                    }
                    RefVal::Func(f) => f,
                    RefVal::Extern(_) => return Err(Trap::new(TrapKind::IndirectType)),
                };
                if **store.funcs[faddr as usize].ty() != *want {
                    return Err(Trap::new(TrapKind::IndirectType));
                }
                let depth = frames.len();
                push_call(store, vals, frames, faddr, depth)?;
            }
            Instr::Drop => {
                ppop(vals);
            }
            Instr::Select | Instr::SelectT(_) => {
                let c = pi32(vals);
                let v2 = ppop(vals);
                let v1 = ppop(vals);
                vals.push(if c != 0 { v1 } else { v2 });
            }
            Instr::LocalGet(x) => {
                let v = frames.last().unwrap().locals[*x as usize];
                vals.push(v);
            }
            Instr::LocalSet(x) => {
                let v = ppop(vals);
                frames.last_mut().unwrap().locals[*x as usize] = v;
            }
            Instr::LocalTee(x) => {
                let v = *vals.last().unwrap_or(&Val::I32(0));
                frames.last_mut().unwrap().locals[*x as usize] = v;
            }
            Instr::GlobalGet(g) => {
                let a = frames.last().unwrap().inst.globals[*g as usize] as usize;
                vals.push(store.globals[a].val);
            }
            Instr::GlobalSet(g) => {
                let a = frames.last().unwrap().inst.globals[*g as usize] as usize;
                store.globals[a].val = ppop(vals);
            }
            Instr::TableGet(t) => {
                let i = pi32(vals) as usize;
                let a = frames.last().unwrap().inst.tables[*t as usize] as usize;
                match store.tables[a].elems.get(i) {
                    Some(r) => vals.push(Val::Ref(*r)),
                    None => return Err(Trap::new(TrapKind::OobTable)),
                }
            }
            Instr::TableSet(t) => {
                let r = pref(vals);
                let i = pi32(vals) as usize;
                let a = frames.last().unwrap().inst.tables[*t as usize] as usize;
                match store.tables[a].elems.get_mut(i) {
                    Some(e) => *e = r,
                    None => return Err(Trap::new(TrapKind::OobTable)),
                }
            }
            Instr::TableSize(t) => {
                let a = frames.last().unwrap().inst.tables[*t as usize] as usize;
                vals.push(Val::I32(store.tables[a].elems.len() as u32));
            }
            Instr::TableGrow(t) => {
                let n = pi32(vals);
                let r = pref(vals);
                let a = frames.last().unwrap().inst.tables[*t as usize] as usize;
                let tab = &mut store.tables[a];
                let hard = tab.ty.lim.max.unwrap_or(u32::MAX);
                let old = tab.elems.len() as u32;
                match old.checked_add(n) {
                    Some(new) if new <= hard => {
                        tab.elems.resize(new as usize, r);
                        vals.push(Val::I32(old));
                    }
                    _ => vals.push(Val::I32(u32::MAX)),
                }
            }
            Instr::TableFill(t) => {
                let n = pi32(vals);
                let r = pref(vals);
                let i = pi32(vals) as usize;
                let a = frames.last().unwrap().inst.tables[*t as usize] as usize;
                let tab = &mut store.tables[a];
                if i as u64 + u64::from(n) > tab.elems.len() as u64 {
                    return Err(Trap::new(TrapKind::OobTable));
                }
                for e in &mut tab.elems[i..i + n as usize] {
                    *e = r;
                }
            }
            Instr::TableInit { table, elem } => {
                let n = pi32(vals);
                let s = pi32(vals);
                let d = pi32(vals);
                let (taddr, eaddr) = {
                    let fr = frames.last().unwrap();
                    (
                        fr.inst.tables[*table as usize] as usize,
                        fr.inst.elems[*elem as usize] as usize,
                    )
                };
                let tlen = store.tables[taddr].elems.len() as u64;
                let slen = store.elems[eaddr].list.len() as u64;
                if u64::from(s) + u64::from(n) > slen || u64::from(d) + u64::from(n) > tlen {
                    return Err(Trap::new(TrapKind::OobTable));
                }
                let src: Vec<RefVal> =
                    store.elems[eaddr].list[s as usize..(s + n) as usize].to_vec();
                for (j, r) in src.iter().enumerate() {
                    store.tables[taddr].elems[d as usize + j] = *r;
                }
            }
            Instr::ElemDrop(e) => {
                let a = frames.last().unwrap().inst.elems[*e as usize] as usize;
                store.elems[a].list.clear();
            }
            Instr::TableCopy { dst, src } => {
                let n = pi32(vals);
                let s = pi32(vals);
                let d = pi32(vals);
                let (da, sa) = {
                    let fr = frames.last().unwrap();
                    (
                        fr.inst.tables[*dst as usize] as usize,
                        fr.inst.tables[*src as usize] as usize,
                    )
                };
                let slen = store.tables[sa].elems.len() as u64;
                let dlen = store.tables[da].elems.len() as u64;
                if u64::from(s) + u64::from(n) > slen || u64::from(d) + u64::from(n) > dlen {
                    return Err(Trap::new(TrapKind::OobTable));
                }
                if da == sa {
                    store.tables[da]
                        .elems
                        .copy_within(s as usize..(s + n) as usize, d as usize);
                } else {
                    let tmp: Vec<RefVal> =
                        store.tables[sa].elems[s as usize..(s + n) as usize].to_vec();
                    store.tables[da].elems[d as usize..(d + n) as usize].copy_from_slice(&tmp);
                }
            }
            Instr::Load { op, off, .. } => {
                let maddr = mem0(&frames.last().unwrap().inst)? as usize;
                let width = load_width(*op);
                let a = u64::from(pi32(vals)) + *off;
                if a + width > store.mems[maddr].byte_len() {
                    return Err(Trap::new(TrapKind::OobMemory));
                }
                let mut b = [0u8; 8];
                store.mems[maddr]
                    .read(a, &mut b[..width as usize])
                    .map_err(|_| Trap::new(TrapKind::OobMemory))?;
                let v = match op {
                    LoadOp::I32 => Val::I32(u32::from_le_bytes(b[..4].try_into().unwrap())),
                    LoadOp::I64 => Val::I64(u64::from_le_bytes(b)),
                    LoadOp::F32 => Val::F32(u32::from_le_bytes(b[..4].try_into().unwrap())),
                    LoadOp::F64 => Val::F64(u64::from_le_bytes(b)),
                    LoadOp::I32x8S => Val::I32((b[0] as i8) as i32 as u32),
                    LoadOp::I32x8U => Val::I32(u32::from(b[0])),
                    LoadOp::I32x16S => {
                        Val::I32(i16::from_le_bytes(b[..2].try_into().unwrap()) as i32 as u32)
                    }
                    LoadOp::I32x16U => {
                        Val::I32(u32::from(u16::from_le_bytes(b[..2].try_into().unwrap())))
                    }
                    LoadOp::I64x8S => Val::I64((b[0] as i8) as i64 as u64),
                    LoadOp::I64x8U => Val::I64(u64::from(b[0])),
                    LoadOp::I64x16S => {
                        Val::I64(i16::from_le_bytes(b[..2].try_into().unwrap()) as i64 as u64)
                    }
                    LoadOp::I64x16U => {
                        Val::I64(u64::from(u16::from_le_bytes(b[..2].try_into().unwrap())))
                    }
                    LoadOp::I64x32S => {
                        Val::I64(i32::from_le_bytes(b[..4].try_into().unwrap()) as i64 as u64)
                    }
                    LoadOp::I64x32U => {
                        Val::I64(u64::from(u32::from_le_bytes(b[..4].try_into().unwrap())))
                    }
                };
                vals.push(v);
            }
            Instr::Store { op, off, .. } => {
                let width = store_width(*op);
                // 値が先（スタックの上）、アドレスが後。
                let bytes: [u8; 8] = match op {
                    StoreOp::I32 => {
                        let v = pi32(vals).to_le_bytes();
                        let mut b = [0u8; 8];
                        b[..4].copy_from_slice(&v);
                        b
                    }
                    StoreOp::I64 => pi64(vals).to_le_bytes(),
                    StoreOp::F32 => {
                        let v = pf32(vals).to_bits().to_le_bytes();
                        let mut b = [0u8; 8];
                        b[..4].copy_from_slice(&v);
                        b
                    }
                    StoreOp::F64 => pf64(vals).to_bits().to_le_bytes(),
                    StoreOp::I32x8 => {
                        let mut b = [0u8; 8];
                        b[0] = pi32(vals) as u8;
                        b
                    }
                    StoreOp::I32x16 => {
                        let mut b = [0u8; 8];
                        b[..2].copy_from_slice(&(pi32(vals) as u16).to_le_bytes());
                        b
                    }
                    StoreOp::I64x8 => {
                        let mut b = [0u8; 8];
                        b[0] = pi64(vals) as u8;
                        b
                    }
                    StoreOp::I64x16 => {
                        let mut b = [0u8; 8];
                        b[..2].copy_from_slice(&(pi64(vals) as u16).to_le_bytes());
                        b
                    }
                    StoreOp::I64x32 => {
                        let mut b = [0u8; 8];
                        b[..4].copy_from_slice(&(pi64(vals) as u32).to_le_bytes());
                        b
                    }
                };
                let maddr = mem0(&frames.last().unwrap().inst)? as usize;
                let a = u64::from(pi32(vals)) + *off;
                if a + width > store.mems[maddr].byte_len() {
                    return Err(Trap::new(TrapKind::OobMemory));
                }
                store.mems[maddr]
                    .write(a, &bytes[..width as usize])
                    .map_err(|_| Trap::new(TrapKind::OobMemory))?;
            }
            Instr::MemorySize => {
                let maddr = mem0(&frames.last().unwrap().inst)? as usize;
                vals.push(Val::I32(store.mems[maddr].pages));
            }
            Instr::MemoryGrow => {
                let n = pi32(vals);
                let maddr = mem0(&frames.last().unwrap().inst)? as usize;
                let r = store.mems[maddr].grow(n);
                vals.push(Val::I32(r as u32));
            }
            Instr::MemoryInit(seg) => {
                let n = u64::from(pi32(vals));
                let s = u64::from(pi32(vals));
                let d = u64::from(pi32(vals));
                let (maddr, daddr) = {
                    let fr = frames.last().unwrap();
                    (
                        mem0(&fr.inst)? as usize,
                        fr.inst.datas[*seg as usize] as usize,
                    )
                };
                let slen = store.datas[daddr].bytes.len() as u64;
                if s + n > slen || d + n > store.mems[maddr].byte_len() {
                    return Err(Trap::new(TrapKind::OobMemory));
                }
                let src: Vec<u8> = store.datas[daddr].bytes[s as usize..(s + n) as usize].to_vec();
                store.mems[maddr]
                    .write(d, &src)
                    .map_err(|_| Trap::new(TrapKind::OobMemory))?;
            }
            Instr::DataDrop(seg) => {
                let a = frames.last().unwrap().inst.datas[*seg as usize] as usize;
                store.datas[a].bytes.clear();
            }
            Instr::MemoryCopy => {
                let n = u64::from(pi32(vals));
                let s = u64::from(pi32(vals));
                let d = u64::from(pi32(vals));
                let maddr = mem0(&frames.last().unwrap().inst)? as usize;
                store.mems[maddr]
                    .copy_within(d, s, n)
                    .map_err(|_| Trap::new(TrapKind::OobMemory))?;
            }
            Instr::MemoryFill => {
                let n = u64::from(pi32(vals));
                let v = pi32(vals) as u8;
                let d = u64::from(pi32(vals));
                let maddr = mem0(&frames.last().unwrap().inst)? as usize;
                store.mems[maddr]
                    .fill(d, v, n)
                    .map_err(|_| Trap::new(TrapKind::OobMemory))?;
            }
            Instr::I32Const(v) => vals.push(Val::I32(*v as u32)),
            Instr::I64Const(v) => vals.push(Val::I64(*v as u64)),
            Instr::F32Const(v) => vals.push(Val::F32(*v)),
            Instr::F64Const(v) => vals.push(Val::F64(*v)),
            Instr::RefNull(t) => vals.push(Val::Ref(RefVal::Null(*t))),
            Instr::RefIsNull => {
                let r = pref(vals);
                vals.push(Val::I32(u32::from(matches!(r, RefVal::Null(_)))));
            }
            Instr::RefFunc(f) => {
                let a = frames.last().unwrap().inst.funcs[*f as usize];
                vals.push(Val::Ref(RefVal::Func(a)));
            }
            _ => numeric(ins, vals)?,
        }
    }
}

/// ロードのバイト幅。
fn load_width(op: LoadOp) -> u64 {
    match op {
        LoadOp::I32 | LoadOp::F32 | LoadOp::I64x32S | LoadOp::I64x32U => 4,
        LoadOp::I64 | LoadOp::F64 => 8,
        LoadOp::I32x8S | LoadOp::I32x8U | LoadOp::I64x8S | LoadOp::I64x8U => 1,
        LoadOp::I32x16S | LoadOp::I32x16U | LoadOp::I64x16S | LoadOp::I64x16U => 2,
    }
}

/// ストアのバイト幅。
fn store_width(op: StoreOp) -> u64 {
    match op {
        StoreOp::I32 | StoreOp::F32 | StoreOp::I64x32 => 4,
        StoreOp::I64 | StoreOp::F64 => 8,
        StoreOp::I32x8 | StoreOp::I64x8 => 1,
        StoreOp::I32x16 | StoreOp::I64x16 => 2,
    }
}

/// 数値命令一括。`run` から切り出したもの。
#[allow(clippy::too_many_lines)]
fn numeric(ins: &Instr, vals: &mut Vec<Val>) -> Result<(), Trap> {
    use Instr::*;
    macro_rules! un_i32 {
        ($f:expr) => {{
            let a = pi32(vals);
            vals.push(Val::I32(($f)(a)));
        }};
    }
    macro_rules! bin_i32 {
        ($f:expr) => {{
            let b = pi32(vals);
            let a = pi32(vals);
            vals.push(Val::I32(($f)(a, b)));
        }};
    }
    macro_rules! bin_i64 {
        ($f:expr) => {{
            let b = pi64(vals);
            let a = pi64(vals);
            vals.push(Val::I64(($f)(a, b)));
        }};
    }
    macro_rules! un_i64 {
        ($f:expr) => {{
            let a = pi64(vals);
            vals.push(Val::I64(($f)(a)));
        }};
    }
    macro_rules! un_f32 {
        ($f:expr) => {{
            let a = pf32(vals);
            vals.push(Val::F32(($f)(a).to_bits()));
        }};
    }
    macro_rules! bin_f32 {
        ($f:expr) => {{
            let b = pf32(vals);
            let a = pf32(vals);
            vals.push(Val::F32(($f)(a, b).to_bits()));
        }};
    }
    macro_rules! un_f64 {
        ($f:expr) => {{
            let a = pf64(vals);
            vals.push(Val::F64(($f)(a).to_bits()));
        }};
    }
    macro_rules! bin_f64 {
        ($f:expr) => {{
            let b = pf64(vals);
            let a = pf64(vals);
            vals.push(Val::F64(($f)(a, b).to_bits()));
        }};
    }
    macro_rules! cmp_i32 {
        ($f:expr) => {{
            let b = pi32(vals);
            let a = pi32(vals);
            vals.push(Val::I32(u32::from(($f)(a, b))));
        }};
    }
    macro_rules! cmp_i64 {
        ($f:expr) => {{
            let b = pi64(vals);
            let a = pi64(vals);
            vals.push(Val::I32(u32::from(($f)(a, b))));
        }};
    }
    macro_rules! cmp_f32 {
        ($f:expr) => {{
            let b = pf32(vals);
            let a = pf32(vals);
            vals.push(Val::I32(u32::from(($f)(a, b))));
        }};
    }
    macro_rules! cmp_f64 {
        ($f:expr) => {{
            let b = pf64(vals);
            let a = pf64(vals);
            vals.push(Val::I32(u32::from(($f)(a, b))));
        }};
    }
    match ins {
        // --- i32 比較 ---
        I32Eqz => un_i32!(|a| u32::from(a == 0)),
        I32Eq => cmp_i32!(|a, b| a == b),
        I32Ne => cmp_i32!(|a, b| a != b),
        I32LtS => cmp_i32!(|a: u32, b: u32| (a as i32) < (b as i32)),
        I32LtU => cmp_i32!(|a, b| a < b),
        I32GtS => cmp_i32!(|a: u32, b: u32| (a as i32) > (b as i32)),
        I32GtU => cmp_i32!(|a, b| a > b),
        I32LeS => cmp_i32!(|a: u32, b: u32| (a as i32) <= (b as i32)),
        I32LeU => cmp_i32!(|a, b| a <= b),
        I32GeS => cmp_i32!(|a: u32, b: u32| (a as i32) >= (b as i32)),
        I32GeU => cmp_i32!(|a, b| a >= b),
        // --- i64 比較 ---
        I64Eqz => {
            let a = pi64(vals);
            vals.push(Val::I32(u32::from(a == 0)));
        }
        I64Eq => cmp_i64!(|a, b| a == b),
        I64Ne => cmp_i64!(|a, b| a != b),
        I64LtS => cmp_i64!(|a: u64, b: u64| (a as i64) < (b as i64)),
        I64LtU => cmp_i64!(|a, b| a < b),
        I64GtS => cmp_i64!(|a: u64, b: u64| (a as i64) > (b as i64)),
        I64GtU => cmp_i64!(|a, b| a > b),
        I64LeS => cmp_i64!(|a: u64, b: u64| (a as i64) <= (b as i64)),
        I64LeU => cmp_i64!(|a, b| a <= b),
        I64GeS => cmp_i64!(|a: u64, b: u64| (a as i64) >= (b as i64)),
        I64GeU => cmp_i64!(|a, b| a >= b),
        // --- 浮動小数点比較 ---
        F32Eq => cmp_f32!(|a, b| a == b),
        F32Ne => cmp_f32!(|a, b| a != b),
        F32Lt => cmp_f32!(|a, b| a < b),
        F32Gt => cmp_f32!(|a, b| a > b),
        F32Le => cmp_f32!(|a, b| a <= b),
        F32Ge => cmp_f32!(|a, b| a >= b),
        F64Eq => cmp_f64!(|a, b| a == b),
        F64Ne => cmp_f64!(|a, b| a != b),
        F64Lt => cmp_f64!(|a, b| a < b),
        F64Gt => cmp_f64!(|a, b| a > b),
        F64Le => cmp_f64!(|a, b| a <= b),
        F64Ge => cmp_f64!(|a, b| a >= b),
        // --- i32 演算 ---
        I32Clz => un_i32!(|a: u32| a.leading_zeros()),
        I32Ctz => un_i32!(|a: u32| a.trailing_zeros()),
        I32Popcnt => un_i32!(|a: u32| a.count_ones()),
        I32Add => bin_i32!(|a: u32, b: u32| a.wrapping_add(b)),
        I32Sub => bin_i32!(|a: u32, b: u32| a.wrapping_sub(b)),
        I32Mul => bin_i32!(|a: u32, b: u32| a.wrapping_mul(b)),
        I32DivS => {
            let b = pi32(vals) as i32;
            let a = pi32(vals) as i32;
            if b == 0 {
                return Err(Trap::new(TrapKind::DivByZero));
            }
            if a == i32::MIN && b == -1 {
                return Err(Trap::new(TrapKind::DivOverflow));
            }
            vals.push(Val::I32(a.wrapping_div(b) as u32));
        }
        I32DivU => {
            let b = pi32(vals);
            let a = pi32(vals);
            if b == 0 {
                return Err(Trap::new(TrapKind::DivByZero));
            }
            vals.push(Val::I32(a / b));
        }
        I32RemS => {
            let b = pi32(vals) as i32;
            let a = pi32(vals) as i32;
            if b == 0 {
                return Err(Trap::new(TrapKind::DivByZero));
            }
            vals.push(Val::I32(a.wrapping_rem(b) as u32));
        }
        I32RemU => {
            let b = pi32(vals);
            let a = pi32(vals);
            if b == 0 {
                return Err(Trap::new(TrapKind::DivByZero));
            }
            vals.push(Val::I32(a % b));
        }
        I32And => bin_i32!(|a, b| a & b),
        I32Or => bin_i32!(|a, b| a | b),
        I32Xor => bin_i32!(|a, b| a ^ b),
        I32Shl => bin_i32!(|a: u32, b: u32| a.wrapping_shl(b)),
        I32ShrS => bin_i32!(|a: u32, b: u32| ((a as i32).wrapping_shr(b)) as u32),
        I32ShrU => bin_i32!(|a: u32, b: u32| a.wrapping_shr(b)),
        I32Rotl => bin_i32!(|a: u32, b: u32| a.rotate_left(b & 31)),
        I32Rotr => bin_i32!(|a: u32, b: u32| a.rotate_right(b & 31)),
        // --- i64 演算 ---
        I64Clz => un_i64!(|a: u64| u64::from(a.leading_zeros())),
        I64Ctz => un_i64!(|a: u64| u64::from(a.trailing_zeros())),
        I64Popcnt => un_i64!(|a: u64| u64::from(a.count_ones())),
        I64Add => bin_i64!(|a: u64, b: u64| a.wrapping_add(b)),
        I64Sub => bin_i64!(|a: u64, b: u64| a.wrapping_sub(b)),
        I64Mul => bin_i64!(|a: u64, b: u64| a.wrapping_mul(b)),
        I64DivS => {
            let b = pi64(vals) as i64;
            let a = pi64(vals) as i64;
            if b == 0 {
                return Err(Trap::new(TrapKind::DivByZero));
            }
            if a == i64::MIN && b == -1 {
                return Err(Trap::new(TrapKind::DivOverflow));
            }
            vals.push(Val::I64(a.wrapping_div(b) as u64));
        }
        I64DivU => {
            let b = pi64(vals);
            let a = pi64(vals);
            if b == 0 {
                return Err(Trap::new(TrapKind::DivByZero));
            }
            vals.push(Val::I64(a / b));
        }
        I64RemS => {
            let b = pi64(vals) as i64;
            let a = pi64(vals) as i64;
            if b == 0 {
                return Err(Trap::new(TrapKind::DivByZero));
            }
            vals.push(Val::I64(a.wrapping_rem(b) as u64));
        }
        I64RemU => {
            let b = pi64(vals);
            let a = pi64(vals);
            if b == 0 {
                return Err(Trap::new(TrapKind::DivByZero));
            }
            vals.push(Val::I64(a % b));
        }
        I64And => bin_i64!(|a, b| a & b),
        I64Or => bin_i64!(|a, b| a | b),
        I64Xor => bin_i64!(|a, b| a ^ b),
        I64Shl => bin_i64!(|a: u64, b: u64| a.wrapping_shl(b as u32)),
        I64ShrS => bin_i64!(|a: u64, b: u64| ((a as i64).wrapping_shr(b as u32)) as u64),
        I64ShrU => bin_i64!(|a: u64, b: u64| a.wrapping_shr(b as u32)),
        I64Rotl => bin_i64!(|a: u64, b: u64| a.rotate_left((b & 63) as u32)),
        I64Rotr => bin_i64!(|a: u64, b: u64| a.rotate_right((b & 63) as u32)),
        // --- f32 演算 ---
        F32Abs => {
            let a = pf32(vals);
            vals.push(Val::F32(a.to_bits() & 0x7fff_ffff));
        }
        F32Neg => {
            let a = pf32(vals);
            vals.push(Val::F32(a.to_bits() ^ 0x8000_0000));
        }
        F32Ceil => un_f32!(|a: f32| a.ceil()),
        F32Floor => un_f32!(|a: f32| a.floor()),
        F32Trunc => un_f32!(|a: f32| a.trunc()),
        F32Nearest => un_f32!(|a: f32| a.round_ties_even()),
        F32Sqrt => un_f32!(|a: f32| a.sqrt()),
        F32Add => bin_f32!(|a, b| a + b),
        F32Sub => bin_f32!(|a, b| a - b),
        F32Mul => bin_f32!(|a, b| a * b),
        F32Div => bin_f32!(|a, b| a / b),
        F32Min => bin_f32!(wasm_min_f32),
        F32Max => bin_f32!(wasm_max_f32),
        F32Copysign => {
            let b = pf32(vals);
            let a = pf32(vals);
            vals.push(Val::F32(
                (a.to_bits() & 0x7fff_ffff) | (b.to_bits() & 0x8000_0000),
            ));
        }
        // --- f64 演算 ---
        F64Abs => {
            let a = pf64(vals);
            vals.push(Val::F64(a.to_bits() & 0x7fff_ffff_ffff_ffff));
        }
        F64Neg => {
            let a = pf64(vals);
            vals.push(Val::F64(a.to_bits() ^ 0x8000_0000_0000_0000));
        }
        F64Ceil => un_f64!(|a: f64| a.ceil()),
        F64Floor => un_f64!(|a: f64| a.floor()),
        F64Trunc => un_f64!(|a: f64| a.trunc()),
        F64Nearest => un_f64!(|a: f64| a.round_ties_even()),
        F64Sqrt => un_f64!(|a: f64| a.sqrt()),
        F64Add => bin_f64!(|a, b| a + b),
        F64Sub => bin_f64!(|a, b| a - b),
        F64Mul => bin_f64!(|a, b| a * b),
        F64Div => bin_f64!(|a, b| a / b),
        F64Min => bin_f64!(wasm_min_f64),
        F64Max => bin_f64!(wasm_max_f64),
        F64Copysign => {
            let b = pf64(vals);
            let a = pf64(vals);
            vals.push(Val::F64(
                (a.to_bits() & 0x7fff_ffff_ffff_ffff) | (b.to_bits() & 0x8000_0000_0000_0000),
            ));
        }
        // --- 変換 ---
        I32WrapI64 => {
            let a = pi64(vals);
            vals.push(Val::I32(a as u32));
        }
        I32TruncF32S => {
            let a = pf64_f32(vals);
            let t = trunc_chk(a, -2147483648.0, 2147483648.0)?;
            vals.push(Val::I32(t as i32 as u32));
        }
        I32TruncF32U => {
            let a = pf64_f32(vals);
            let t = trunc_chk(a, 0.0, 4294967296.0)?;
            vals.push(Val::I32(t as u32));
        }
        I32TruncF64S => {
            let a = pf64(vals);
            let t = trunc_chk(a, -2147483648.0, 2147483648.0)?;
            vals.push(Val::I32(t as i32 as u32));
        }
        I32TruncF64U => {
            let a = pf64(vals);
            let t = trunc_chk(a, 0.0, 4294967296.0)?;
            vals.push(Val::I32(t as u32));
        }
        I64TruncF32S => {
            let a = pf64_f32(vals);
            let t = trunc_chk(a, -9223372036854775808.0, 9223372036854775808.0)?;
            vals.push(Val::I64(t as i64 as u64));
        }
        I64TruncF32U => {
            let a = pf64_f32(vals);
            let t = trunc_chk(a, 0.0, 18446744073709551616.0)?;
            vals.push(Val::I64(t as u64));
        }
        I64TruncF64S => {
            let a = pf64(vals);
            let t = trunc_chk(a, -9223372036854775808.0, 9223372036854775808.0)?;
            vals.push(Val::I64(t as i64 as u64));
        }
        I64TruncF64U => {
            let a = pf64(vals);
            let t = trunc_chk(a, 0.0, 18446744073709551616.0)?;
            vals.push(Val::I64(t as u64));
        }
        I64ExtendI32S => {
            let a = pi32(vals);
            vals.push(Val::I64((a as i32) as i64 as u64));
        }
        I64ExtendI32U => {
            let a = pi32(vals);
            vals.push(Val::I64(u64::from(a)));
        }
        F32ConvertI32S => {
            let a = pi32(vals);
            vals.push(Val::F32(((a as i32) as f32).to_bits()));
        }
        F32ConvertI32U => {
            let a = pi32(vals);
            vals.push(Val::F32((a as f32).to_bits()));
        }
        F32ConvertI64S => {
            let a = pi64(vals);
            vals.push(Val::F32(((a as i64) as f32).to_bits()));
        }
        F32ConvertI64U => {
            let a = pi64(vals);
            vals.push(Val::F32((a as f32).to_bits()));
        }
        F32DemoteF64 => {
            let a = pf64(vals);
            vals.push(Val::F32((a as f32).to_bits()));
        }
        F64ConvertI32S => {
            let a = pi32(vals);
            vals.push(Val::F64(f64::from(a as i32).to_bits()));
        }
        F64ConvertI32U => {
            let a = pi32(vals);
            vals.push(Val::F64(f64::from(a).to_bits()));
        }
        F64ConvertI64S => {
            let a = pi64(vals);
            vals.push(Val::F64(((a as i64) as f64).to_bits()));
        }
        F64ConvertI64U => {
            let a = pi64(vals);
            vals.push(Val::F64((a as f64).to_bits()));
        }
        F64PromoteF32 => {
            let a = pf32(vals);
            vals.push(Val::F64(f64::from(a).to_bits()));
        }
        I32ReinterpretF32 => {
            let a = pf32(vals);
            vals.push(Val::I32(a.to_bits()));
        }
        I64ReinterpretF64 => {
            let a = pf64(vals);
            vals.push(Val::I64(a.to_bits()));
        }
        F32ReinterpretI32 => {
            let a = pi32(vals);
            vals.push(Val::F32(a));
        }
        F64ReinterpretI64 => {
            let a = pi64(vals);
            vals.push(Val::F64(a));
        }
        I32Extend8S => un_i32!(|a: u32| (a as u8) as i8 as i32 as u32),
        I32Extend16S => un_i32!(|a: u32| (a as u16) as i16 as i32 as u32),
        I64Extend8S => un_i64!(|a: u64| (a as u8) as i8 as i64 as u64),
        I64Extend16S => un_i64!(|a: u64| (a as u16) as i16 as i64 as u64),
        I64Extend32S => un_i64!(|a: u64| (a as u32) as i32 as i64 as u64),
        // --- 飽和切り捨て ---
        I32TruncSatF32S => {
            let a = pf64_f32(vals);
            let t = tsat(a, -2147483648.0, 2147483647.0);
            vals.push(Val::I32(t as i32 as u32));
        }
        I32TruncSatF32U => {
            let a = pf64_f32(vals);
            let t = tsat(a, 0.0, 4294967295.0);
            vals.push(Val::I32(t as u32));
        }
        I32TruncSatF64S => {
            let a = pf64(vals);
            let t = tsat(a, -2147483648.0, 2147483647.0);
            vals.push(Val::I32(t as i32 as u32));
        }
        I32TruncSatF64U => {
            let a = pf64(vals);
            let t = tsat(a, 0.0, 4294967295.0);
            vals.push(Val::I32(t as u32));
        }
        I64TruncSatF32S => {
            let a = pf64_f32(vals);
            let t = tsat(a, -9223372036854775808.0, 9223372036854775807.0);
            vals.push(Val::I64(t as i64 as u64));
        }
        I64TruncSatF32U => {
            let a = pf64_f32(vals);
            let t = tsat(a, 0.0, 18446744073709551615.0);
            vals.push(Val::I64(t as u64));
        }
        I64TruncSatF64S => {
            let a = pf64(vals);
            let t = tsat(a, -9223372036854775808.0, 9223372036854775807.0);
            vals.push(Val::I64(t as i64 as u64));
        }
        I64TruncSatF64U => {
            let a = pf64(vals);
            let t = tsat(a, 0.0, 18446744073709551615.0);
            vals.push(Val::I64(t as u64));
        }
        _ => return Err(Trap::host("unhandled numeric instruction")),
    }
    Ok(())
}

/// `f32` を `f64` として取り出す（境界検査の精度のため）。
fn pf64_f32(vals: &mut Vec<Val>) -> f64 {
    f64::from(pf32(vals))
}

/// wasm の `min`（NaN 伝播、-0 < +0）。
fn wasm_min_f32(a: f32, b: f32) -> f32 {
    if a.is_nan() {
        return a;
    }
    if b.is_nan() {
        return b;
    }
    if a == b {
        // -0.0 と +0.0 が等しいときは負を取る。
        return if a.is_sign_negative() { a } else { b };
    }
    if a < b { a } else { b }
}

fn wasm_max_f32(a: f32, b: f32) -> f32 {
    if a.is_nan() {
        return a;
    }
    if b.is_nan() {
        return b;
    }
    if a == b {
        return if a.is_sign_positive() { a } else { b };
    }
    if a > b { a } else { b }
}

fn wasm_min_f64(a: f64, b: f64) -> f64 {
    if a.is_nan() {
        return a;
    }
    if b.is_nan() {
        return b;
    }
    if a == b {
        return if a.is_sign_negative() { a } else { b };
    }
    if a < b { a } else { b }
}

fn wasm_max_f64(a: f64, b: f64) -> f64 {
    if a.is_nan() {
        return a;
    }
    if b.is_nan() {
        return b;
    }
    if a == b {
        return if a.is_sign_positive() { a } else { b };
    }
    if a > b { a } else { b }
}

/// `trunc` の範囲検査。`x` は f64 に変換済み。`lo ≤ trunc(x) < hi`
/// （`hi` は開端。全て f64 で正確に表せる境界）なら整値を返す。
fn trunc_chk(x: f64, lo: f64, hi: f64) -> Result<f64, Trap> {
    if x.is_nan() {
        return Err(Trap::new(TrapKind::InvalidConv));
    }
    let t = x.trunc();
    if t < lo || t >= hi {
        return Err(Trap::new(TrapKind::DivOverflow));
    }
    Ok(t)
}

/// `trunc_sat`。NaN は 0、`trunc(x)` を `[mn, mx]` に飽和させる。
/// `mx` が f64 で表せない上限（i64::MAX 等）は隣接する f64 に丸まり、
/// その後の `as` 変換の飽和で正しい最大値になる。
fn tsat(x: f64, mn: f64, mx: f64) -> f64 {
    if x.is_nan() {
        return 0.0;
    }
    x.trunc().clamp(mn, mx)
}

/// エクスポート関数・テストからの呼び出し入口。
/// `args` の個数・型は呼び出し側で検査済みとする。
pub fn invoke(store: &mut Store, faddr: u32, args: &[Val]) -> Result<Vec<Val>, Trap> {
    let Some(func) = store.funcs.get(faddr as usize) else {
        return Err(Trap::host("unknown function address"));
    };
    if args.len() != func.ty().params.len() {
        return Err(Trap::host("argument count mismatch"));
    }
    match func {
        FuncInst::Host { f, .. } => {
            let f = Rc::clone(f);
            f(store, None, args)
        }
        FuncInst::Wasm { .. } => {
            let mut vals: Vec<Val> = args.to_vec();
            let mut frames: Vec<Frame> = Vec::new();
            push_call(store, &mut vals, &mut frames, faddr, 0)?;
            run(store, &mut vals, &mut frames)
        }
    }
}
