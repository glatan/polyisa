// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! モジュールの検証。オペランドスタックの型付けと制御フレームは
//! 仕様の付録のアルゴリズムに従う。`unreachable` の後はスタックを
//! 多相（`None`）にし、ボトム型としてあらゆる型に適合させる。
//!
//! 定数式・グローバル初期化・エレメント初期値・リミット・指標範囲・
//! `ref.func` の宣言済み集合・data count の有無もここで検査する。
//! Ref: SPEC-WASM-CORE 3.0 および付録の検証アルゴリズム.

use std::collections::{BTreeSet, HashSet};

use crate::instr::{self, Instr, LoadOp, StoreOp};
use crate::module::*;
use crate::types::*;

/// 検証エラー（仕様の invalid に相当）。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Invalid(pub String);

type V<T> = Result<T, Invalid>;

fn invalid(msg: &str) -> Invalid {
    Invalid(msg.to_string())
}

/// 検証済みモジュール。関数本体は解読済みの命令列を持つ。
#[derive(Debug)]
pub struct Validated {
    pub module: Module,
    /// 定義関数ごとの本体（`module.funcs` と同じ順）。
    pub bodies: Vec<Body>,
}

/// 検証・解読済みの関数本体。
#[derive(Clone, Debug)]
pub struct Body {
    /// 宣言ローカルの連長表現（個数, 型。パラメータは含まない）。
    /// 合計は `u32::MAX` に達し得るので展開済みの列は持たない。
    pub locals: Vec<(u32, ValType)>,
    pub instrs: Vec<Instr>,
}

/// オペランドの型。`None` はボトム（多相スタック上の未知型）。
type Vt = Option<ValType>;

const I32: Vt = Some(ValType::I32);
const I64: Vt = Some(ValType::I64);
const F32: Vt = Some(ValType::F32);
const F64: Vt = Some(ValType::F64);
const FUNCREF: Vt = Some(ValType::Ref(RefType::Func));
const BOT: Vt = None;

/// 制御フレーム。
#[derive(Clone, Debug)]
struct Ctrl {
    kind: CtrlKind,
    /// 入口で消費する型列（loop のラベル型はこちら）。
    start: Vec<ValType>,
    /// 出口で要求する型列（block/if のラベル型はこちら）。
    end: Vec<ValType>,
    /// このフレームが積まれた時点の値スタックの高さ。
    height: usize,
    unreachable: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CtrlKind {
    Block,
    Loop,
    If,
    Func,
}

/// 検証の文脈。モジュールの宣言を数えたもの。
/// 不変の宣言部は借用で持ち、関数ごとに使い回す（本体検証のたびに
/// 複製すると関数数×型ノード数の二乗コストになるため）。
struct Ctx<'m> {
    m: &'m Module,
    /// 全関数の型（インポート＋定義、funcidx 順）。
    funcs: &'m [FuncType],
    /// 全テーブルの型。
    tables: &'m [TableType],
    /// 全メモリの型。
    mems: &'m [MemType],
    /// 全グローバルの型。
    globals: &'m [GlobalType],
    /// `ref.func` が参照できる宣言済み関数指標。
    refs: &'m HashSet<u32>,
    vals: Vec<Vt>,
    ctrls: Vec<Ctrl>,
}

impl<'m> Ctx<'m> {
    fn push(&mut self, t: Vt) {
        self.vals.push(t);
    }

    fn push_all(&mut self, ts: &[ValType]) {
        for t in ts {
            self.push(Some(*t));
        }
    }

    fn pop(&mut self) -> V<Vt> {
        let frame = self
            .ctrls
            .last()
            .ok_or_else(|| invalid("control stack empty"))?;
        if self.vals.len() == frame.height {
            if frame.unreachable {
                return Ok(BOT);
            }
            return Err(invalid("type mismatch: stack underflow"));
        }
        Ok(self.vals.pop().unwrap_or(BOT))
    }

    fn pop_expect(&mut self, expect: Vt) -> V<Vt> {
        let actual = self.pop()?;
        if actual.is_none() {
            return Ok(expect);
        }
        if expect.is_none() {
            return Ok(actual);
        }
        if actual != expect {
            return Err(invalid("type mismatch"));
        }
        Ok(actual)
    }

    fn pop_all(&mut self, ts: &[ValType]) -> V<()> {
        for t in ts.iter().rev() {
            self.pop_expect(Some(*t))?;
        }
        Ok(())
    }

    /// `pop_expect` と同じ検査をしつつ、実際に取り出した型を返す
    /// （ボトムを取り出したときは BOT のまま）。`br_table` の
    /// 複数ラベル照合で「取り出したものを積み直す」ために使う。
    fn pop_actual(&mut self, expect: ValType) -> V<Vt> {
        let actual = self.pop()?;
        match actual {
            None => Ok(BOT),
            Some(a) if a == expect => Ok(actual),
            Some(_) => Err(invalid("type mismatch")),
        }
    }

    /// ブロックの入口：入力を消費し、フレームを開き、入力を積み直す。
    fn open_block(&mut self, kind: CtrlKind, start: Vec<ValType>, end: Vec<ValType>) -> V<()> {
        self.pop_all(&start)?;
        let height = self.vals.len();
        self.push_all(&start);
        self.ctrls.push(Ctrl {
            kind,
            start,
            end,
            height,
            unreachable: false,
        });
        Ok(())
    }

    fn close_ctrl(&mut self) -> V<Ctrl> {
        let Some(frame) = self.ctrls.last().cloned() else {
            return Err(invalid("control stack empty"));
        };
        self.pop_all(&frame.end)?;
        if self.vals.len() != frame.height {
            return Err(invalid("type mismatch: values remain after block"));
        }
        self.ctrls.pop();
        Ok(frame)
    }

    /// 現在のフレームを `unreachable` にし、値スタックをフレーム高さへ切る。
    fn unreachable(&mut self) -> V<()> {
        let Some(frame) = self.ctrls.last_mut() else {
            return Err(invalid("control stack empty"));
        };
        self.vals.truncate(frame.height);
        frame.unreachable = true;
        Ok(())
    }

    fn label_types(&self, l: u32) -> V<&[ValType]> {
        let depth = self.ctrls.len();
        if (l as usize) >= depth {
            return Err(invalid("unknown label"));
        }
        let frame = &self.ctrls[depth - 1 - l as usize];
        Ok(if frame.kind == CtrlKind::Loop {
            &frame.start
        } else {
            &frame.end
        })
    }

    fn func(&self, f: u32) -> V<&FuncType> {
        self.funcs
            .get(f as usize)
            .ok_or_else(|| invalid(&format!("unknown function {f}")))
    }

    fn table(&self, t: u32) -> V<&TableType> {
        self.tables
            .get(t as usize)
            .ok_or_else(|| invalid(&format!("unknown table {t}")))
    }

    fn mem0(&self) -> V<()> {
        if self.mems.is_empty() {
            return Err(invalid("unknown memory 0"));
        }
        Ok(())
    }

    /// memarg の memidx（multi-memory の `0x40` フラグ形）を検査する。
    /// 単一メモリの世界では `0` 以外は unknown。
    fn memidx(&self, mi: u32) -> V<()> {
        if mi != 0 || self.mems.is_empty() {
            return Err(invalid(&format!("unknown memory {mi}")));
        }
        Ok(())
    }

    fn global(&self, g: u32) -> V<&GlobalType> {
        self.globals
            .get(g as usize)
            .ok_or_else(|| invalid(&format!("unknown global {g}")))
    }

    fn block_sig(&self, bt: BlockType) -> V<(Vec<ValType>, Vec<ValType>)> {
        match bt {
            BlockType::Empty => Ok((Vec::new(), Vec::new())),
            BlockType::Val(t) => Ok((Vec::new(), vec![t])),
            BlockType::Func(i) => {
                let ft = self
                    .m
                    .types
                    .get(i as usize)
                    .ok_or_else(|| invalid("unknown type"))?;
                Ok((ft.params.clone(), ft.results.clone()))
            }
        }
    }
}

/// 数値系命令の静的シグネチャ。文脈不要な命令だけを返す。
fn static_sig(i: &Instr) -> Option<(&'static [Vt], &'static [Vt])> {
    use Instr::*;
    const Z: &[Vt] = &[];
    macro_rules! s {
        ($in:expr, $out:expr) => {
            ($in as &[Vt], $out as &[Vt])
        };
    }
    Some(match i {
        Nop => s!(Z, Z),
        Drop => return None,
        Select => return None,
        I32Const(_) => s!(Z, &[I32]),
        I64Const(_) => s!(Z, &[I64]),
        F32Const(_) => s!(Z, &[F32]),
        F64Const(_) => s!(Z, &[F64]),
        I32Eqz => s!(&[I32], &[I32]),
        I32Eq | I32Ne | I32LtS | I32LtU | I32GtS | I32GtU | I32LeS | I32LeU | I32GeS | I32GeU => {
            s!(&[I32, I32], &[I32])
        }
        I64Eqz => s!(&[I64], &[I32]),
        I64Eq | I64Ne | I64LtS | I64LtU | I64GtS | I64GtU | I64LeS | I64LeU | I64GeS | I64GeU => {
            s!(&[I64, I64], &[I32])
        }
        F32Eq | F32Ne | F32Lt | F32Gt | F32Le | F32Ge => s!(&[F32, F32], &[I32]),
        F64Eq | F64Ne | F64Lt | F64Gt | F64Le | F64Ge => s!(&[F64, F64], &[I32]),
        I32Clz | I32Ctz | I32Popcnt => s!(&[I32], &[I32]),
        I32Add | I32Sub | I32Mul | I32DivS | I32DivU | I32RemS | I32RemU | I32And | I32Or
        | I32Xor | I32Shl | I32ShrS | I32ShrU | I32Rotl | I32Rotr => {
            s!(&[I32, I32], &[I32])
        }
        I64Clz | I64Ctz | I64Popcnt => s!(&[I64], &[I64]),
        I64Add | I64Sub | I64Mul | I64DivS | I64DivU | I64RemS | I64RemU | I64And | I64Or
        | I64Xor | I64Shl | I64ShrS | I64ShrU | I64Rotl | I64Rotr => {
            s!(&[I64, I64], &[I64])
        }
        F32Abs | F32Neg | F32Ceil | F32Floor | F32Trunc | F32Nearest | F32Sqrt => {
            s!(&[F32], &[F32])
        }
        F32Add | F32Sub | F32Mul | F32Div | F32Min | F32Max | F32Copysign => {
            s!(&[F32, F32], &[F32])
        }
        F64Abs | F64Neg | F64Ceil | F64Floor | F64Trunc | F64Nearest | F64Sqrt => {
            s!(&[F64], &[F64])
        }
        F64Add | F64Sub | F64Mul | F64Div | F64Min | F64Max | F64Copysign => {
            s!(&[F64, F64], &[F64])
        }
        I32WrapI64 => s!(&[I64], &[I32]),
        I32TruncF32S | I32TruncF32U => s!(&[F32], &[I32]),
        I32TruncF64S | I32TruncF64U => s!(&[F64], &[I32]),
        I64ExtendI32S | I64ExtendI32U => s!(&[I32], &[I64]),
        I64TruncF32S | I64TruncF32U => s!(&[F32], &[I64]),
        I64TruncF64S | I64TruncF64U => s!(&[F64], &[I64]),
        F32ConvertI32S | F32ConvertI32U => s!(&[I32], &[F32]),
        F32ConvertI64S | F32ConvertI64U => s!(&[I64], &[F32]),
        F32DemoteF64 => s!(&[F64], &[F32]),
        F64ConvertI32S | F64ConvertI32U => s!(&[I32], &[F64]),
        F64ConvertI64S | F64ConvertI64U => s!(&[I64], &[F64]),
        F64PromoteF32 => s!(&[F32], &[F64]),
        I32ReinterpretF32 => s!(&[F32], &[I32]),
        I64ReinterpretF64 => s!(&[F64], &[I64]),
        F32ReinterpretI32 => s!(&[I32], &[F32]),
        F64ReinterpretI64 => s!(&[I64], &[F64]),
        I32Extend8S | I32Extend16S => s!(&[I32], &[I32]),
        I64Extend8S | I64Extend16S | I64Extend32S => s!(&[I64], &[I64]),
        I32TruncSatF32S | I32TruncSatF32U => s!(&[F32], &[I32]),
        I32TruncSatF64S | I32TruncSatF64U => s!(&[F64], &[I32]),
        I64TruncSatF32S | I64TruncSatF32U => s!(&[F32], &[I64]),
        I64TruncSatF64S | I64TruncSatF64U => s!(&[F64], &[I64]),
        _ => return None,
    })
}

/// `memarg.align`（指数）をバイト数にする。u32 超過は飽和。
fn al32(al: u32) -> u64 {
    1u64.checked_shl(al).unwrap_or(1 << 33)
}

/// load 系の自然アライメント（バイト）。
fn load_natural(op: LoadOp) -> u64 {
    match op {
        LoadOp::I32 | LoadOp::I64x32S | LoadOp::I64x32U | LoadOp::F32 => 4,
        LoadOp::I64 | LoadOp::F64 => 8,
        LoadOp::I32x8S | LoadOp::I32x8U | LoadOp::I64x8S | LoadOp::I64x8U => 1,
        LoadOp::I32x16S | LoadOp::I32x16U | LoadOp::I64x16S | LoadOp::I64x16U => 2,
    }
}

/// store 系の自然アライメント（バイト）。
fn store_natural(op: StoreOp) -> u64 {
    match op {
        StoreOp::I32 | StoreOp::I64x32 | StoreOp::F32 => 4,
        StoreOp::I64 | StoreOp::F64 => 8,
        StoreOp::I32x8 | StoreOp::I64x8 => 1,
        StoreOp::I32x16 | StoreOp::I64x16 => 2,
    }
}

fn load_sig(op: LoadOp) -> (&'static [Vt], &'static [Vt]) {
    match op {
        LoadOp::I32 | LoadOp::I32x8S | LoadOp::I32x8U | LoadOp::I32x16S | LoadOp::I32x16U => {
            (&[I32], &[I32])
        }
        LoadOp::I64
        | LoadOp::I64x8S
        | LoadOp::I64x8U
        | LoadOp::I64x16S
        | LoadOp::I64x16U
        | LoadOp::I64x32S
        | LoadOp::I64x32U => (&[I32], &[I64]),
        LoadOp::F32 => (&[I32], &[F32]),
        LoadOp::F64 => (&[I32], &[F64]),
    }
}

fn store_sig(op: StoreOp) -> (&'static [Vt], &'static [Vt]) {
    match op {
        StoreOp::I32 | StoreOp::I32x8 | StoreOp::I32x16 => (&[I32, I32], &[]),
        StoreOp::I64 | StoreOp::I64x8 | StoreOp::I64x16 | StoreOp::I64x32 => (&[I32, I64], &[]),
        StoreOp::F32 => (&[I32, F32], &[]),
        StoreOp::F64 => (&[I32, F64], &[]),
    }
}

/// 定数式として使える命令か（2.0 の範囲）。
fn const_op(i: &Instr) -> bool {
    matches!(
        i,
        Instr::I32Const(_)
            | Instr::I64Const(_)
            | Instr::F32Const(_)
            | Instr::F64Const(_)
            | Instr::RefNull(_)
            | Instr::RefFunc(_)
            | Instr::GlobalGet(_)
            // extended const (2.0): ganzzahlige Add/Sub/Mul
            | Instr::I32Add
            | Instr::I32Sub
            | Instr::I32Mul
            | Instr::I64Add
            | Instr::I64Sub
            | Instr::I64Mul
            | Instr::End
    )
}

/// 定数式の検証。結果型 `want` mit einem Element muss auf dem
/// Operanden-Stack bleiben. `global_bound` begrenzt `global.get`:
/// Global-Initialisierer sehen nur importierte Globals,
/// Elem/Data-Offsets dürfen auch definierte unveränderliche Globals
/// lesen (Aufrufer geben `global_types.len()` weiter).
fn const_expr_type(
    e: &ConstExpr,
    m: &Module,
    global_types: &[GlobalType],
    global_bound: usize,
    refs: &HashSet<u32>,
) -> V<ValType> {
    let mut stack: Vec<ValType> = Vec::new();
    for ins in &e.instrs {
        if !const_op(ins) {
            return Err(invalid("constant expression required"));
        }
        match *ins {
            Instr::I32Const(_) => stack.push(ValType::I32),
            Instr::I64Const(_) => stack.push(ValType::I64),
            Instr::F32Const(_) => stack.push(ValType::F32),
            Instr::F64Const(_) => stack.push(ValType::F64),
            Instr::RefNull(t) => stack.push(ValType::Ref(t)),
            Instr::RefFunc(f) => {
                if f as usize >= count_funcs(m) {
                    return Err(invalid(&format!("unknown function {f}")));
                }
                if !refs.contains(&f) {
                    return Err(invalid("undeclared function reference"));
                }
                stack.push(ValType::Ref(RefType::Func));
            }
            Instr::GlobalGet(g) => {
                if g as usize >= global_bound {
                    return Err(invalid(&format!("unknown global {g}")));
                }
                let gt = &global_types[g as usize];
                if gt.mutable {
                    return Err(invalid("constant expression required"));
                }
                stack.push(gt.vt);
            }
            Instr::I32Add | Instr::I32Sub | Instr::I32Mul => {
                if stack.pop() != Some(ValType::I32) || stack.pop() != Some(ValType::I32) {
                    return Err(invalid("type mismatch in constant expression"));
                }
                stack.push(ValType::I32);
            }
            Instr::I64Add | Instr::I64Sub | Instr::I64Mul => {
                if stack.pop() != Some(ValType::I64) || stack.pop() != Some(ValType::I64) {
                    return Err(invalid("type mismatch in constant expression"));
                }
                stack.push(ValType::I64);
            }
            Instr::End => {}
            _ => unreachable!(),
        }
    }
    if stack.len() != 1 {
        return Err(invalid("type mismatch in constant expression"));
    }
    Ok(stack[0])
}

fn count_funcs(m: &Module) -> usize {
    m.imports
        .iter()
        .filter(|i| matches!(i.desc, ImportDesc::Func(_)))
        .count()
        + m.funcs.len()
}

/// 定数式が null 参照を生むか。`end` 手前の命令が `ref.null` なら
/// 結果は nullable であり、non-null を要求する位置には置けない。
fn yields_null(e: &ConstExpr) -> bool {
    e.instrs
        .iter()
        .rev()
        .find(|x| !matches!(x, Instr::End))
        .is_some_and(|x| matches!(x, Instr::RefNull(_)))
}

/// `ref.func` が参照できる集合：関数本体の外に現れる関数指標。
/// Ref: SPEC-WASM-CORE 3.3.3（C.refs）。
fn collect_refs(m: &Module) -> HashSet<u32> {
    let mut refs = HashSet::new();
    // テーブル初期化式（`0x40 0x00` 形）の中の `ref.func` も宣言扱い。
    for e in m.table_inits.iter().flatten() {
        refs.extend(expr_func_refs(e));
    }
    for e in &m.elems {
        match &e.init {
            ElemItem::Funcs(fs) => refs.extend(fs.iter().copied()),
            ElemItem::Exprs(es) => {
                for ex in es {
                    refs.extend(expr_func_refs(ex));
                }
            }
        }
        if let ElemMode::Active { offset, .. } = &e.mode {
            refs.extend(expr_func_refs(offset));
        }
    }
    for g in &m.globals {
        refs.extend(expr_func_refs(&g.init));
    }
    for d in &m.datas {
        if let DataMode::Active { offset, .. } = &d.mode {
            refs.extend(expr_func_refs(offset));
        }
    }
    for x in &m.exports {
        if x.kind == 0 {
            refs.insert(x.idx);
        }
    }
    refs
}

fn expr_func_refs(e: &ConstExpr) -> impl Iterator<Item = u32> + '_ {
    e.instrs.iter().filter_map(|i| match i {
        Instr::RefFunc(f) => Some(*f),
        _ => None,
    })
}

/// リミットの検査。
fn check_limits(lim: &Limits, hard: u64, what: &str) -> V<()> {
    if u64::from(lim.min) > hard {
        return Err(invalid(&format!("{what} size exceeds limit")));
    }
    if let Some(max) = lim.max {
        if u64::from(max) > hard {
            return Err(invalid(&format!("{what} size exceeds limit")));
        }
        if max < lim.min {
            return Err(invalid(&format!(
                "{what} size minimum must not be greater than maximum"
            )));
        }
    }
    Ok(())
}

/// パラメータと連長表現の宣言ローカルを並べた列への索引。
/// 宣言個数の合計は `u32::MAX` に達し得るため、展開せずに
/// 連長区間をたどって型を返す。
struct LocalTypes<'a> {
    params: &'a [ValType],
    runs: &'a [(u32, ValType)],
}

impl LocalTypes<'_> {
    fn get(&self, i: u32) -> Option<ValType> {
        let nparams = self.params.len() as u64;
        if u64::from(i) < nparams {
            return Some(self.params[i as usize]);
        }
        let mut rest = u64::from(i) - nparams;
        for &(n, t) in self.runs {
            if rest < u64::from(n) {
                return Some(t);
            }
            rest -= u64::from(n);
        }
        None
    }
}

/// 関数本体の検証。`locals` はパラメータと宣言ローカルの連結。
fn validate_body(
    ctx: &mut Ctx,
    locals: &LocalTypes<'_>,
    results: &[ValType],
    body: &Body,
) -> V<()> {
    ctx.vals.clear();
    ctx.ctrls.clear();
    ctx.ctrls.push(Ctrl {
        kind: CtrlKind::Func,
        start: Vec::new(),
        end: results.to_vec(),
        height: 0,
        unreachable: false,
    });
    let instrs = &body.instrs;
    let mut i = 0usize;
    while i < instrs.len() {
        let ins = &instrs[i];
        if let Some((input, output)) = static_sig(ins) {
            for t in input.iter().rev() {
                ctx.pop_expect(*t)?;
            }
            for t in output {
                ctx.push(*t);
            }
            i += 1;
            continue;
        }
        match ins {
            Instr::Unreachable => ctx.unreachable()?,
            Instr::Block { bt, .. } => {
                let (sin, sout) = ctx.block_sig(*bt)?;
                ctx.open_block(CtrlKind::Block, sin, sout)?;
            }
            Instr::Loop { bt, .. } => {
                let (sin, sout) = ctx.block_sig(*bt)?;
                ctx.open_block(CtrlKind::Loop, sin, sout)?;
            }
            Instr::If { bt, els, end } => {
                ctx.pop_expect(I32)?;
                let (sin, sout) = ctx.block_sig(*bt)?;
                // else の無い if は、空の else 部が恒等になるよう
                // 入口型と出口型の一致を要求する。
                if els == end && sin != sout {
                    return Err(invalid("type mismatch: if without else"));
                }
                ctx.open_block(CtrlKind::If, sin, sout)?;
            }
            Instr::Else { .. } => {
                let frame = ctx.close_ctrl()?;
                if frame.kind != CtrlKind::If {
                    return Err(invalid("else without if"));
                }
                // else 側の入口は start を積み直すだけ（消費は if 入口で済み）。
                let start = frame.start.clone();
                ctx.ctrls.push(Ctrl {
                    kind: CtrlKind::If,
                    start: frame.start,
                    end: frame.end,
                    height: ctx.vals.len(),
                    unreachable: false,
                });
                ctx.push_all(&start);
            }
            Instr::End => {
                let frame = ctx.close_ctrl()?;
                // ブロックの結果は外側のフレームへ積み直す。
                ctx.push_all(&frame.end);
                if ctx.ctrls.is_empty() {
                    i += 1;
                    if i != instrs.len() {
                        return Err(invalid("trailing instructions after end"));
                    }
                    return Ok(());
                }
            }
            Instr::Br { l } => {
                let lt = ctx.label_types(*l)?.to_vec();
                ctx.pop_all(&lt)?;
                ctx.unreachable()?;
            }
            Instr::BrIf { l } => {
                ctx.pop_expect(I32)?;
                let lt = ctx.label_types(*l)?.to_vec();
                ctx.pop_all(&lt)?;
                ctx.push_all(&lt);
            }
            Instr::BrTable { ls, ln } => {
                ctx.pop_expect(I32)?;
                let mut arity: Option<usize> = None;
                for l in ls.iter().chain(std::iter::once(ln)) {
                    let lt = ctx.label_types(*l)?.to_vec();
                    match arity {
                        None => arity = Some(lt.len()),
                        Some(a) if a != lt.len() => {
                            return Err(invalid("type mismatch in br_table arity"));
                        }
                        _ => {}
                    }
                    // 取り出した型を積み直す。多相スタック由来の
                    // ボトムは BOT のまま戻るので、ラベル型が
                    // 互いに等しくなくても unreachable では通る。
                    let mut popped = Vec::with_capacity(lt.len());
                    for t in lt.iter().rev() {
                        popped.push(ctx.pop_actual(*t)?);
                    }
                    for v in popped.into_iter().rev() {
                        ctx.push(v);
                    }
                }
                let lt = ctx.label_types(*ln)?.to_vec();
                ctx.pop_all(&lt)?;
                ctx.unreachable()?;
            }
            Instr::Return => {
                let lt = ctx.ctrls[0].end.clone();
                ctx.pop_all(&lt)?;
                ctx.unreachable()?;
            }
            Instr::Call { f } => {
                let ft = ctx.func(*f)?.clone();
                ctx.pop_all(&ft.params)?;
                ctx.push_all(&ft.results);
            }
            Instr::CallIndirect { ty, table } => {
                let tt = ctx.table(*table)?;
                if tt.et != RefType::Func {
                    return Err(invalid("type mismatch: call_indirect table"));
                }
                let ft = ctx
                    .m
                    .types
                    .get(*ty as usize)
                    .ok_or_else(|| invalid("unknown type"))?
                    .clone();
                ctx.pop_expect(I32)?;
                ctx.pop_all(&ft.params)?;
                ctx.push_all(&ft.results);
            }
            Instr::Drop => {
                ctx.pop()?;
            }
            Instr::Select => {
                ctx.pop_expect(I32)?;
                let t1 = ctx.pop()?;
                let t2 = ctx.pop()?;
                // 数値型・v128 型のみ。いずれか Unknown なら他方に合わせる。
                let num = |t: Vt| {
                    matches!(
                        t,
                        Some(
                            ValType::I32
                                | ValType::I64
                                | ValType::F32
                                | ValType::F64
                                | ValType::V128
                        ) | None
                    )
                };
                if !num(t1) || !num(t2) {
                    return Err(invalid("type mismatch in select"));
                }
                match (t1, t2) {
                    (Some(a), Some(b)) if a != b => return Err(invalid("type mismatch in select")),
                    _ => {}
                }
                ctx.push(t1.or(t2));
            }
            Instr::SelectT(t) => {
                ctx.pop_expect(I32)?;
                ctx.pop_expect(Some(*t))?;
                ctx.pop_expect(Some(*t))?;
                ctx.push(Some(*t));
            }
            Instr::LocalGet(x) => {
                let t = locals.get(*x).ok_or_else(|| invalid("unknown local"))?;
                ctx.push(Some(t));
            }
            Instr::LocalSet(x) => {
                let t = locals.get(*x).ok_or_else(|| invalid("unknown local"))?;
                ctx.pop_expect(Some(t))?;
            }
            Instr::LocalTee(x) => {
                let t = locals.get(*x).ok_or_else(|| invalid("unknown local"))?;
                ctx.pop_expect(Some(t))?;
                ctx.push(Some(t));
            }
            Instr::GlobalGet(g) => {
                let t = ctx.global(*g)?.vt;
                ctx.push(Some(t));
            }
            Instr::GlobalSet(g) => {
                let gt = ctx.global(*g)?;
                if !gt.mutable {
                    return Err(invalid("immutable global"));
                }
                ctx.pop_expect(Some(gt.vt))?;
            }
            Instr::TableGet(t) => {
                let et = ctx.table(*t)?.et;
                ctx.pop_expect(I32)?;
                ctx.push(Some(ValType::Ref(et)));
            }
            Instr::TableSet(t) => {
                let et = ctx.table(*t)?.et;
                ctx.pop_expect(Some(ValType::Ref(et)))?;
                ctx.pop_expect(I32)?;
            }
            Instr::TableSize(t) => {
                ctx.table(*t)?;
                ctx.push(I32);
            }
            Instr::TableGrow(t) => {
                let et = ctx.table(*t)?.et;
                ctx.pop_expect(I32)?;
                ctx.pop_expect(Some(ValType::Ref(et)))?;
                ctx.push(I32);
            }
            Instr::TableFill(t) => {
                let et = ctx.table(*t)?.et;
                ctx.pop_expect(I32)?;
                ctx.pop_expect(Some(ValType::Ref(et)))?;
                ctx.pop_expect(I32)?;
            }
            Instr::TableInit { table, elem } => {
                let tt = ctx.table(*table)?;
                let e = ctx
                    .m
                    .elems
                    .get(*elem as usize)
                    .ok_or_else(|| invalid(&format!("unknown elem segment {elem}")))?;
                if e.ty != tt.et {
                    return Err(invalid("type mismatch in table.init"));
                }
                ctx.pop_expect(I32)?;
                ctx.pop_expect(I32)?;
                ctx.pop_expect(I32)?;
            }
            Instr::ElemDrop(e) => {
                ctx.m
                    .elems
                    .get(*e as usize)
                    .ok_or_else(|| invalid(&format!("unknown elem segment {e}")))?;
            }
            Instr::TableCopy { dst, src } => {
                let dt = ctx.table(*dst)?.et;
                let st = ctx.table(*src)?.et;
                if dt != st {
                    return Err(invalid("type mismatch in table.copy"));
                }
                ctx.pop_expect(I32)?;
                ctx.pop_expect(I32)?;
                ctx.pop_expect(I32)?;
            }
            Instr::Load { op, off, al, mi } => {
                ctx.memidx(*mi)?;
                // align は自然アライメント以下でなければ invalid。
                if al32(*al) > load_natural(*op) {
                    return Err(invalid("alignment must not be larger than natural"));
                }
                // オフセットのフィールドは u64（3.0 文法）だが、
                // 32 ビットメモリでは u32 の範囲に限る。
                if *off > u64::from(u32::MAX) {
                    return Err(invalid("offset out of range"));
                }
                let (input, output) = load_sig(*op);
                for t in input.iter().rev() {
                    ctx.pop_expect(*t)?;
                }
                for t in output {
                    ctx.push(*t);
                }
            }
            Instr::Store { op, off, al, mi } => {
                ctx.memidx(*mi)?;
                if al32(*al) > store_natural(*op) {
                    return Err(invalid("alignment must not be larger than natural"));
                }
                if *off > u64::from(u32::MAX) {
                    return Err(invalid("offset out of range"));
                }
                let (input, output) = store_sig(*op);
                for t in input.iter().rev() {
                    ctx.pop_expect(*t)?;
                }
                for t in output {
                    ctx.push(*t);
                }
            }
            Instr::MemoryInit(d) => {
                ctx.mem0()?;
                if ctx.m.data_count.is_none() {
                    return Err(invalid("data count section required"));
                }
                if *d as usize >= ctx.m.data_count.unwrap_or(0) as usize {
                    return Err(invalid(&format!("unknown data segment {d}")));
                }
                ctx.pop_expect(I32)?;
                ctx.pop_expect(I32)?;
                ctx.pop_expect(I32)?;
            }
            Instr::DataDrop(d) => {
                if ctx.m.data_count.is_none() {
                    return Err(invalid("data count section required"));
                }
                if *d as usize >= ctx.m.data_count.unwrap_or(0) as usize {
                    return Err(invalid(&format!("unknown data segment {d}")));
                }
            }
            Instr::MemorySize => {
                ctx.mem0()?;
                ctx.push(I32);
            }
            Instr::MemoryGrow => {
                ctx.mem0()?;
                ctx.pop_expect(I32)?;
                ctx.push(I32);
            }
            Instr::MemoryCopy | Instr::MemoryFill => {
                ctx.mem0()?;
                ctx.pop_expect(I32)?;
                ctx.pop_expect(I32)?;
                ctx.pop_expect(I32)?;
            }
            Instr::RefIsNull => {
                // オペランドは参照型に限る。多相スタック由来の
                // ボトム（`None`）は任意の型になり得るので許す。
                // 静的シグネチャの BOT ワイルドカードでは数値型まで
                // 通してしまうため、ここで個別に検査する。
                let t = ctx.pop()?;
                if let Some(v) = t
                    && !matches!(v, ValType::Ref(_))
                {
                    return Err(invalid("type mismatch"));
                }
                ctx.push(I32);
            }
            Instr::RefNull(t) => {
                // 具体型指標のヒープ型は範囲を検査してから Func に潰す。
                let t = match *t {
                    RefType::Idx(i) => {
                        if i as usize >= ctx.m.types.len() {
                            return Err(invalid("unknown type"));
                        }
                        RefType::Func
                    }
                    t => t,
                };
                ctx.push(Some(ValType::Ref(t)));
            }
            Instr::RefFunc(f) => {
                if *f as usize >= ctx.funcs.len() {
                    return Err(invalid(&format!("unknown function {f}")));
                }
                if !ctx.refs.contains(f) {
                    return Err(invalid("undeclared function reference"));
                }
                ctx.push(FUNCREF);
            }
            _ => return Err(invalid("unhandled instruction in validation")),
        }
        i += 1;
    }
    Err(invalid("function body does not end with end"))
}

/// モジュール全体を検証し、実行用の `Validated` を返す。
/// Ref: SPEC-WASM-CORE 3.4（モジュールの検証）.
#[allow(clippy::too_many_lines)]
pub fn validate_module(mut m: Module) -> Result<Validated, Invalid> {
    // --- 参照型の型指標（2.0 の `(ref (null) $t)`）の範囲検査 ---
    // 内部モデルはヒープ型の区別を持たないので、範囲内の指標は
    // Func に潰す。範囲外は "unknown type"。
    let ntypes = m.types.len();
    fn norm_ref(t: &mut RefType, n: usize) -> Result<(), Invalid> {
        if let RefType::Idx(i) = *t {
            if i as usize >= n {
                return Err(invalid("unknown type"));
            }
            *t = RefType::Func;
        }
        Ok(())
    }
    fn norm_vt(v: &mut ValType, n: usize) -> Result<(), Invalid> {
        if let ValType::Ref(t) = v {
            norm_ref(t, n)?;
        }
        Ok(())
    }
    for ft in &mut m.types {
        for v in ft.params.iter_mut().chain(ft.results.iter_mut()) {
            norm_vt(v, ntypes)?;
        }
    }
    for imp in &mut m.imports {
        match &mut imp.desc {
            ImportDesc::Table(t) => norm_ref(&mut t.et, ntypes)?,
            ImportDesc::Global(g) => norm_vt(&mut g.vt, ntypes)?,
            _ => {}
        }
    }
    for t in &mut m.tables {
        norm_ref(&mut t.et, ntypes)?;
    }
    for g in &mut m.globals {
        norm_vt(&mut g.ty.vt, ntypes)?;
    }
    for c in &mut m.code {
        for (_, v) in &mut c.locals {
            norm_vt(v, ntypes)?;
        }
    }
    for e in &mut m.elems {
        norm_ref(&mut e.ty, ntypes)?;
    }

    // --- インポート側の外部型を集める ---
    let mut funcs: Vec<FuncType> = Vec::new();
    let mut tables: Vec<TableType> = Vec::new();
    let mut mems: Vec<MemType> = Vec::new();
    let mut globals: Vec<GlobalType> = Vec::new();
    for imp in &m.imports {
        match &imp.desc {
            ImportDesc::Func(t) => {
                let ft = m
                    .types
                    .get(*t as usize)
                    .ok_or_else(|| invalid("unknown type"))?;
                funcs.push(ft.clone());
            }
            ImportDesc::Table(t) => {
                check_limits(&t.lim, u64::from(u32::MAX), "table")?;
                tables.push(*t);
            }
            ImportDesc::Mem(t) => {
                check_limits(&t.lim, u64::from(MAX_PAGES), "memory")?;
                mems.push(*t);
            }
            ImportDesc::Global(t) => globals.push(*t),
        }
    }
    let imported_globals = globals.len();
    for t in &m.tables {
        check_limits(&t.lim, u64::from(u32::MAX), "table")?;
        tables.push(*t);
    }
    for t in &m.mems {
        check_limits(&t.lim, u64::from(MAX_PAGES), "memory")?;
        mems.push(*t);
    }
    if mems.len() > 1 {
        return Err(invalid("multiple memories"));
    }
    for f in &m.funcs {
        funcs.push(
            m.types
                .get(*f as usize)
                .ok_or_else(|| invalid("unknown type"))?
                .clone(),
        );
    }
    for g in &m.globals {
        globals.push(g.ty);
    }

    let refs = collect_refs(&m);

    // --- テーブル初期化式（2.0 の `0x40 0x00` 形） ---
    // テーブル節は global 節より先に現れるため、仕様上ここで参照
    // できるのはインポート済みグローバルのみ。exec は定義済み
    // グローバルの確保後に初期化式を評価するが、定義グローバルを指す
    // 式はここで既に弾かれるので差異は生じない（elem/data の
    // オフセットは global 節より後なので定義済みも読める）。
    for (i, t) in m.tables.iter().enumerate() {
        let init = m.table_inits.get(i).and_then(Option::as_ref);
        let nn = m.table_nonnull.get(i).copied().unwrap_or(false);
        // non-null（`(ref ht)` = `0x64` 形）な要素型は既定値の null を
        // 持てないため初期化式が必須（table.wast の
        // `(table 0 (ref func))` → "type mismatch"）。
        if nn && init.is_none() {
            return Err(invalid("type mismatch"));
        }
        if let Some(e) = init {
            let vt = const_expr_type(e, &m, &globals, imported_globals, &refs)?;
            if vt != ValType::Ref(t.et) {
                return Err(invalid("type mismatch in table init"));
            }
            // non-null な要素型の初期化式が null を生むのは invalid。
            if nn && yields_null(e) {
                return Err(invalid("type mismatch in table init"));
            }
        }
    }

    // --- グローバル初期化式 ---
    // `global.get` darf importierte und zuvor definierte unveränderliche
    // Globals lesen (gebundener Index = imports + bisherige Definitionen).
    for (i, g) in m.globals.iter().enumerate() {
        let t = const_expr_type(&g.init, &m, &globals, imported_globals + i, &refs)?;
        if t != g.ty.vt {
            return Err(invalid("type mismatch in global initializer"));
        }
    }

    // --- エレメントセグメント ---
    let imported_tables = m
        .imports
        .iter()
        .filter(|im| matches!(im.desc, ImportDesc::Table(_)))
        .count();
    for e in &m.elems {
        if let ElemMode::Active { table, offset } = &e.mode {
            let tt = tables
                .get(*table as usize)
                .ok_or_else(|| invalid(&format!("unknown table {table}")))?;
            // non-null (`(ref ht)` = `0x64`) な要素型には nullable な
            // セグメント型を入れられない。インポートテーブルの nullability
            // は追跡しない（nullable として扱う）。
            let nn = (*table as usize)
                .checked_sub(imported_tables)
                .and_then(|i| m.table_nonnull.get(i).copied())
                .unwrap_or(false);
            // `(ref func)` セグメントは `(ref null func)` テーブルにも入る
            // （non-null <: nullable）が、逆は不可。
            if tt.et != e.ty || (nn && !e.nonnull) {
                return Err(invalid("type mismatch in elem segment"));
            }
            let t = const_expr_type(offset, &m, &globals, globals.len(), &refs)?;
            if t != ValType::I32 {
                return Err(invalid("type mismatch in elem offset"));
            }
        }
        match &e.init {
            ElemItem::Funcs(fs) => {
                for f in fs {
                    if *f as usize >= funcs.len() {
                        return Err(invalid(&format!("unknown function {f}")));
                    }
                }
            }
            ElemItem::Exprs(es) => {
                for ex in es {
                    let t = const_expr_type(ex, &m, &globals, globals.len(), &refs)?;
                    if t != ValType::Ref(e.ty) {
                        return Err(invalid("type mismatch in elem item"));
                    }
                    // non-null な `(ref ht)` セグメントに `ref.null` の
                    // 項目は置けない。
                    if e.nonnull && yields_null(ex) {
                        return Err(invalid("type mismatch in elem item"));
                    }
                }
            }
        }
    }

    // --- データセグメント ---
    for d in &m.datas {
        if let DataMode::Active { mem, offset } = &d.mode {
            if *mem as usize >= mems.len() {
                return Err(invalid(&format!("unknown memory {mem}")));
            }
            let t = const_expr_type(offset, &m, &globals, globals.len(), &refs)?;
            if t != ValType::I32 {
                return Err(invalid("type mismatch in data offset"));
            }
        }
    }
    // data count があれば実際のセグメント数と一致しなければならない。
    if let Some(dc) = m.data_count
        && dc as usize != m.datas.len()
    {
        return Err(invalid(
            "data count and data section have inconsistent lengths",
        ));
    }

    // --- スタート関数 ---
    if let Some(s) = m.start {
        let ft = funcs
            .get(s as usize)
            .ok_or_else(|| invalid(&format!("unknown function {s}")))?;
        if !ft.params.is_empty() || !ft.results.is_empty() {
            return Err(invalid("start function has wrong type"));
        }
    }

    // --- エクスポート ---
    let mut names = BTreeSet::new();
    for x in &m.exports {
        if !names.insert(x.name.clone()) {
            return Err(invalid("duplicate export name"));
        }
        let kind = match x.kind {
            0 => "function",
            1 => "table",
            2 => "memory",
            3 => "global",
            _ => "",
        };
        let ok = match x.kind {
            0 => (x.idx as usize) < funcs.len(),
            1 => (x.idx as usize) < tables.len(),
            2 => (x.idx as usize) < mems.len(),
            3 => (x.idx as usize) < globals.len(),
            _ => false,
        };
        if !ok {
            return Err(invalid(&format!("unknown {kind} {}", x.idx)));
        }
    }

    // --- 関数本体 ---
    // 宣言部を数えた文脈は不変なので一度だけ作り、本体ごとの
    // スタック状態（vals/ctrls）だけを `validate_body` の入口で
    // 初期化する。
    let mut ctx = Ctx {
        m: &m,
        funcs: &funcs,
        tables: &tables,
        mems: &mems,
        globals: &globals,
        refs: &refs,
        vals: Vec::new(),
        ctrls: Vec::new(),
    };
    let imported_funcs = m
        .imports
        .iter()
        .filter(|im| matches!(im.desc, ImportDesc::Func(_)))
        .count();
    let mut bodies = Vec::with_capacity(m.code.len());
    for (i, code) in m.code.iter().enumerate() {
        let fidx = imported_funcs + i;
        let ft = funcs
            .get(fidx)
            .ok_or_else(|| invalid(&format!("unknown function {fidx}")))?;
        let locals = LocalTypes {
            params: &ft.params,
            runs: &code.locals,
        };
        let instrs = instr::decode_body(&code.body).map_err(|e| invalid(&e.0))?;
        let body = Body {
            locals: code.locals.clone(),
            instrs,
        };
        validate_body(&mut ctx, &locals, &ft.results, &body)
            .map_err(|e| invalid(&format!("func {fidx}: {}", e.0)))?;
        bodies.push(body);
    }

    Ok(Validated { module: m, bodies })
}
