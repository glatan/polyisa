// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! ブロック内の局所最適化。定数畳み込み・コピー伝播・CSE・
//! 書き込み潰し・死んだ純粋操作の削除。
//!
//! 副作用の順序は動かさない（docs/design/jit.md「ブロック内の
//! 最適化」）。メモリ操作・`If`・終端操作の前後をまたいだ
//! 読み書きの先送りはしない（フォルト時の中間状態が変わるため）。

use std::collections::{HashMap, HashSet};

use polyisa_sem::Cmp;

use crate::inst::{BinOp, Cvt, Ext, FpCmp, Id, Inst, Ir, TriOp, UnOp, Wid};

/// ブロック内の最適化を全部行う。
pub fn optimize(ir: &mut Ir) {
    simplify(&mut ir.ops, &mut FoldCx::default());
    let mut table = HashMap::new();
    cse(&mut ir.ops, &mut table);
    dse(&mut ir.ops, &mut HashMap::new());
    dce(&mut ir.ops);
}

// ---- 定数畳み込み + コピー伝播 + store-load forwarding ----

/// 値の置き換え先。`K` は定数、`A` は別の値へのコピー。
#[derive(Clone, Copy)]
enum Val {
    K(u128),
    A(Id),
}

#[derive(Default)]
struct FoldCx {
    /// `Id` ごとの定数/コピー先。SSA なので枝を出ても有効。
    vals: HashMap<Id, Val>,
}

/// フィールド → 直近の無条件 `Set` の値。`If` などをまたいだ
/// 転送はしないので枝を出るときに消す。
type LastSet = HashMap<(u32, Wid), Id>;

impl FoldCx {
    /// `id` の置き換えをたどって最終の `Id` を返す。
    fn resolve(&self, mut id: Id) -> Id {
        for _ in 0..64 {
            match self.vals.get(&id) {
                Some(Val::A(n)) => id = *n,
                _ => return id,
            }
        }
        id
    }

    /// `id` の定数値。
    fn konst(&self, id: Id) -> Option<u128> {
        let id = self.resolve(id);
        match self.vals.get(&id) {
            Some(Val::K(v)) => Some(*v),
            _ => None,
        }
    }
}

/// 現在の列を走り、畳めるものを畳む。枝の中は再起し、
/// `last_set` の転送は枝内に閉じる。
fn simplify(ops: &mut Vec<Inst>, cx: &mut FoldCx) {
    let mut last: LastSet = HashMap::new();
    let mut out = Vec::with_capacity(ops.len());
    for i in ops.drain(..) {
        // オペランドの Id を置き換える。
        let mut i = i;
        remap_inst(&mut i, &mut |id| cx.resolve(id));
        match i {
            Inst::Const { d, w, v } => {
                cx.vals.insert(d, Val::K(v & w.mask()));
                out.push(Inst::Const {
                    d,
                    w,
                    v: v & w.mask(),
                });
            }
            Inst::Get { d, off, w } => {
                if let Some(&v) = last.get(&(off, w)) {
                    cx.vals.insert(d, Val::A(v));
                } else {
                    out.push(Inst::Get { d, off, w });
                }
            }
            Inst::Set { off, w, v } => {
                last.insert((off, w), v);
                out.push(Inst::Set { off, w, v });
            }
            Inst::Un { d, op, a, w } => match (op, cx.konst(a)) {
                (UnOp::Not, Some(x)) => {
                    let v = !x & w.mask();
                    cx.vals.insert(d, Val::K(v));
                    out.push(Inst::Const { d, w, v });
                }
                _ => out.push(Inst::Un { d, op, a, w }),
            },
            Inst::Bin { d, op, a, b, w } => match fold_bin(cx, op, w, a, b, d) {
                Some(i) => out.push(i),
                None => out.push(Inst::Bin { d, op, a, b, w }),
            },
            Inst::Tri { .. } => out.push(i),
            Inst::Adc {
                d,
                dc,
                dv,
                a,
                b,
                c,
                w,
            } => {
                if let (Some(x), Some(y), Some(z)) =
                    (cx.konst(a), cx.konst(b), cx.konst(c).map(|v| v != 0))
                {
                    let m = w.mask();
                    let (x, y) = (x & m, y & m);
                    let sum = x + y + u128::from(z);
                    let r = sum & m;
                    let sign = 1u128 << (w.bits() - 1);
                    let ca = (sum >> w.bits()) & 1 == 1;
                    let ov = ((x ^ r) & (y ^ r) & sign) != 0;
                    cx.vals.insert(d, Val::K(r));
                    cx.vals.insert(dc, Val::K(u128::from(ca)));
                    cx.vals.insert(dv, Val::K(u128::from(ov)));
                    out.push(Inst::Const { d, w, v: r });
                    out.push(Inst::Const {
                        d: dc,
                        w: Wid::W1,
                        v: u128::from(ca),
                    });
                    out.push(Inst::Const {
                        d: dv,
                        w: Wid::W1,
                        v: u128::from(ov),
                    });
                } else {
                    out.push(Inst::Adc {
                        d,
                        dc,
                        dv,
                        a,
                        b,
                        c,
                        w,
                    });
                }
            }
            Inst::Cmp { d, op, a, b, w } => {
                let (x, y) = (cx.konst(a), cx.konst(b));
                let v = match (x, y) {
                    (Some(x), Some(y)) => Some(u128::from(eval_cmp(op, w, x, y))),
                    _ if a == b => match op {
                        Cmp::Eq | Cmp::LeU | Cmp::LeS | Cmp::GeU | Cmp::GeS => Some(1),
                        Cmp::Ne | Cmp::LtU | Cmp::LtS | Cmp::GtU | Cmp::GtS => Some(0),
                    },
                    _ => None,
                };
                match v {
                    Some(v) => {
                        cx.vals.insert(d, Val::K(v));
                        out.push(Inst::Const { d, w: Wid::W1, v });
                    }
                    None => out.push(Inst::Cmp { d, op, a, b, w }),
                }
            }
            Inst::FpCmp { .. } => out.push(i),
            Inst::Sel { d, c, t, f, w } => {
                if let Some(c) = cx.konst(c) {
                    let pick = if c != 0 { t } else { f };
                    cx.vals.insert(d, Val::A(pick));
                } else if t == f {
                    cx.vals.insert(d, Val::A(t));
                } else {
                    out.push(Inst::Sel { d, c, t, f, w });
                }
            }
            Inst::Ext { d, op, a, from, to } => match cx.konst(a) {
                Some(x) => {
                    let v = eval_ext(op, from, to, x);
                    cx.vals.insert(d, Val::K(v));
                    out.push(Inst::Const { d, w: to, v });
                }
                None if from == to => {
                    cx.vals.insert(d, Val::A(a));
                }
                None => out.push(Inst::Ext { d, op, a, from, to }),
            },
            Inst::Cvt { .. } => out.push(i),
            Inst::GetIx { .. } | Inst::SetIx { .. } => {
                // 動的添字はどのフィールドにも当たり得るので転送を捨てる。
                last.clear();
                out.push(i);
            }
            Inst::If { c, t, f } => {
                if let Some(c) = cx.konst(c) {
                    // 条件が定数なら選ばれる側を展開する。
                    // （If の消去は dce でも起こるが、展開すると
                    // もう片側の副作用が消えるのでここでやる。）
                    let mut take = if c != 0 { t } else { f };
                    simplify(&mut take, cx);
                    // 展開した列の書き込みは無条件なので転送表に写す。
                    // 枝の中や抜け得る点では打ち切る。
                    for i in &take {
                        match i {
                            Inst::Set { off, w, v } => {
                                last.insert((*off, *w), *v);
                            }
                            Inst::If { .. } | Inst::GetIx { .. } | Inst::SetIx { .. } => {
                                last.clear()
                            }
                            x if x.can_leave() => last.clear(),
                            _ => {}
                        }
                    }
                    out.extend(take);
                } else {
                    let mut t = t;
                    let mut f = f;
                    simplify(&mut t, cx);
                    simplify(&mut f, cx);
                    // 枝内での書き込みは条件付きなので転送しない。
                    last.clear();
                    out.push(Inst::If { c, t, f });
                }
            }
            // ブロックを抜け得る操作は「その時点の状態」が見えるので、
            // 直前の書き込み転送を打ち切る（forwarding は Get だけに
            // 効くので、ここでは last を消すだけでよい）。
            ref i if i.can_leave() => {
                last.clear();
                out.push(i.clone());
            }
            _ => out.push(i),
        }
    }
    *ops = out;
}

/// 2 入力の畳み込み。畳めたら操作を返す（`Const` 化 or 畳めず素通しは None）。
fn fold_bin(cx: &mut FoldCx, op: BinOp, w: Wid, a: Id, b: Id, d: Id) -> Option<Inst> {
    let (x, y) = (cx.konst(a), cx.konst(b));
    let m = w.mask();
    // FP は丸め環と fp_flags を持つので畳まない。mulh 系の
    // W128 は eval_bin の >>128 がオーバーフローするので除く。
    let int_op = !matches!(
        op,
        BinOp::Fadd
            | BinOp::Fsub
            | BinOp::Fmul
            | BinOp::Fdiv
            | BinOp::Fmin
            | BinOp::Fmax
            | BinOp::Fsgnj
            | BinOp::Fsgnjn
            | BinOp::Fsgnjx
    ) && !(matches!(op, BinOp::Mulh | BinOp::Mulhsu | BinOp::Mulhu)
        && w.bits() == 128);
    let folded = match (op, x, y) {
        (_, Some(x), Some(y)) if int_op => Some(eval_bin(op, w, x, y)),
        (BinOp::Add | BinOp::Or | BinOp::Xor, _, Some(0)) => return alias(cx, d, a),
        (BinOp::Add | BinOp::Or | BinOp::Xor, Some(0), _) => return alias(cx, d, b),
        (BinOp::Sub, _, Some(0)) => return alias(cx, d, a),
        (BinOp::Sub | BinOp::Xor, _, _) if a == b => Some(0),
        (BinOp::And | BinOp::Or, _, _) if a == b => return alias(cx, d, a),
        (BinOp::And, _, Some(0)) | (BinOp::And, Some(0), _) => Some(0),
        (BinOp::Mul, _, Some(0)) | (BinOp::Mul, Some(0), _) => Some(0),
        (BinOp::Mul, _, Some(1)) => return alias(cx, d, a),
        (BinOp::Mul, Some(1), _) => return alias(cx, d, b),
        (BinOp::And, _, Some(y)) if y == m => return alias(cx, d, a),
        (BinOp::And, Some(x), _) if x == m => return alias(cx, d, b),
        (BinOp::Or, _, Some(y)) if y == m => Some(m),
        (BinOp::Or, Some(x), _) if x == m => Some(m),
        (BinOp::Shl | BinOp::ShrL | BinOp::ShrA, _, Some(0)) => return alias(cx, d, a),
        (BinOp::Shl | BinOp::ShrL, _, Some(n)) if n >= u128::from(w.bits()) => Some(0),
        (BinOp::Udiv, _, Some(1)) | (BinOp::Sdiv, _, Some(1)) => return alias(cx, d, a),
        (BinOp::Urem | BinOp::Srem, _, Some(1)) => Some(0),
        _ => None,
    };
    folded.map(|v| {
        cx.vals.insert(d, Val::K(v & m));
        Inst::Const { d, w, v: v & m }
    })
}

fn alias(cx: &mut FoldCx, d: Id, to: Id) -> Option<Inst> {
    cx.vals.insert(d, Val::A(to));
    None
}

/// `id` 参照を全部 `f` で置き換える。
fn remap_inst(i: &mut Inst, f: &mut impl FnMut(Id) -> Id) {
    match i {
        Inst::Const { .. } | Inst::Get { .. } => {}
        Inst::Set { v, .. } => *v = f(*v),
        Inst::GetIx { ix, .. } => *ix = f(*ix),
        Inst::SetIx { ix, v, .. } => {
            *ix = f(*ix);
            *v = f(*v);
        }
        Inst::Un { a, .. } => *a = f(*a),
        Inst::Bin { a, b, .. } | Inst::Cmp { a, b, .. } | Inst::FpCmp { a, b, .. } => {
            *a = f(*a);
            *b = f(*b);
        }
        Inst::Tri { a, b, c, .. } => {
            *a = f(*a);
            *b = f(*b);
            *c = f(*c);
        }
        Inst::Adc { a, b, c, .. } => {
            *a = f(*a);
            *b = f(*b);
            *c = f(*c);
        }
        Inst::Sel { c, t, f: fe, .. } => {
            *c = f(*c);
            *t = f(*t);
            *fe = f(*fe);
        }
        Inst::Ext { a, .. } | Inst::Cvt { a, .. } => *a = f(*a),
        Inst::Load { addr, .. } | Inst::Probe { addr, .. } => *addr = f(*addr),
        Inst::Store { addr, v, .. } => {
            *addr = f(*addr);
            *v = f(*v);
        }
        Inst::Cmpx { addr, old, new, .. } => {
            *addr = f(*addr);
            *old = f(*old);
            *new = f(*new);
        }
        Inst::LdRes { addr, .. } => *addr = f(*addr),
        Inst::StCond { addr, v, .. } => {
            *addr = f(*addr);
            *v = f(*v);
        }
        Inst::If { c, t, f: fe } => {
            *c = f(*c);
            for x in t.iter_mut().chain(fe.iter_mut()) {
                remap_inst(x, f);
            }
        }
        Inst::Jump { v } => *v = f(*v),
        Inst::Branch { c, .. } => *c = f(*c),
        Inst::Exit { .. } | Inst::Unimpl { .. } => {}
        Inst::Hint { v, .. } => *v = f(*v),
    }
}

// ---- 値の評価（インタプリタと同じ全域性）----

fn eval_bin(op: BinOp, w: Wid, x: u128, y: u128) -> u128 {
    let m = w.mask();
    let bits = w.bits();
    let (x, y) = (x & m, y & m);
    let sext = |v: u128| -> i128 { ((v << (128 - bits)) as i128) >> (128 - bits) };
    match op {
        BinOp::Add => x.wrapping_add(y) & m,
        BinOp::Sub => x.wrapping_sub(y) & m,
        BinOp::And => x & y,
        BinOp::Or => x | y,
        BinOp::Xor => x ^ y,
        BinOp::Shl => {
            if y >= u128::from(bits) {
                0
            } else {
                (x << y) & m
            }
        }
        BinOp::ShrL => {
            if y >= u128::from(bits) {
                0
            } else {
                x >> y
            }
        }
        BinOp::ShrA => {
            if y >= 128 {
                if sext(x) < 0 { m } else { 0 }
            } else {
                ((sext(x) >> y) as u128) & m
            }
        }
        BinOp::Udiv => x.checked_div(y).unwrap_or(m),
        BinOp::Urem => x.checked_rem(y).unwrap_or(x),
        BinOp::Mul => x.wrapping_mul(y) & m,
        BinOp::Mulh => ((sext(x).wrapping_mul(sext(y)) >> bits) as u128) & m,
        BinOp::Mulhsu => ((sext(x).wrapping_mul(y as i128) >> bits) as u128) & m,
        BinOp::Mulhu => ((x.wrapping_mul(y) >> bits) & m) & m,
        BinOp::Sdiv => {
            if y == 0 {
                m
            } else {
                (sext(x).wrapping_div(sext(y)) as u128) & m
            }
        }
        BinOp::Srem => {
            if y == 0 {
                x
            } else {
                (sext(x).wrapping_rem(sext(y)) as u128) & m
            }
        }
        _ => unreachable!("整数演算の畳み込み"),
    }
}

fn eval_cmp(op: Cmp, w: Wid, x: u128, y: u128) -> bool {
    let m = w.mask();
    let (x, y) = (x & m, y & m);
    let bits = w.bits();
    let (sx, sy) = (
        ((x << (128 - bits)) as i128) >> (128 - bits),
        ((y << (128 - bits)) as i128) >> (128 - bits),
    );
    match op {
        Cmp::Eq => x == y,
        Cmp::Ne => x != y,
        Cmp::LtU => x < y,
        Cmp::LtS => sx < sy,
        Cmp::GtU => x > y,
        Cmp::GtS => sx > sy,
        Cmp::LeU => x <= y,
        Cmp::LeS => sx <= sy,
        Cmp::GeU => x >= y,
        Cmp::GeS => sx >= sy,
    }
}

fn eval_ext(op: Ext, from: Wid, to: Wid, x: u128) -> u128 {
    let x = x & from.mask();
    match op {
        Ext::Zext | Ext::Trunc => x & to.mask(),
        Ext::Sext => {
            let b = from.bits();
            (((x << (128 - b)) as i128 >> (128 - b)) as u128) & to.mask()
        }
    }
}

// ---- CSE（同一式の再利用）----

/// `Cmp` は `Hash` を持たないので番号でキーにする。
fn cmp_code(op: Cmp) -> u8 {
    match op {
        Cmp::Eq => 0,
        Cmp::Ne => 1,
        Cmp::LtU => 2,
        Cmp::LtS => 3,
        Cmp::GtU => 4,
        Cmp::GtS => 5,
        Cmp::LeU => 6,
        Cmp::LeS => 7,
        Cmp::GeU => 8,
        Cmp::GeS => 9,
    }
}

#[derive(Clone, Hash, PartialEq, Eq)]
enum Key {
    K(Wid, u128),
    Un(UnOp, Wid, Id),
    Bin(BinOp, Wid, Id, Id),
    Tri(TriOp, Wid, Id, Id, Id),
    Adc(Wid, Id, Id, Id),
    Cmp(u8, Wid, Id, Id),
    FpCmp(FpCmp, Wid, Id, Id),
    Sel(Wid, Id, Id, Id),
    Ext(Ext, Wid, Wid, Id),
    Cvt(Cvt, Wid, Wid, Id, u8),
}

/// 同一式を 1 度だけ計算する。枝には外側の表を写して入り、
/// 枝でできた式は外へ出ない。
fn cse(ops: &mut Vec<Inst>, table: &mut HashMap<Key, Vec<Id>>) {
    let mut rename: HashMap<Id, Id> = HashMap::new();
    let mut out = Vec::with_capacity(ops.len());
    for i in ops.drain(..) {
        let mut i = i;
        remap_inst(&mut i, &mut |id| *rename.get(&id).unwrap_or(&id));
        let (key, outs): (Option<Key>, Vec<Id>) = match i {
            Inst::Const { d, w, v } => (Some(Key::K(w, v)), vec![d]),
            Inst::Un { d, op, a, w } => (Some(Key::Un(op, w, a)), vec![d]),
            Inst::Bin { d, op, a, b, w } => (Some(Key::Bin(op, w, a, b)), vec![d]),
            Inst::Tri { d, op, a, b, c, w } => (Some(Key::Tri(op, w, a, b, c)), vec![d]),
            Inst::Adc {
                d,
                dc,
                dv,
                a,
                b,
                c,
                w,
            } => (Some(Key::Adc(w, a, b, c)), vec![d, dc, dv]),
            Inst::Cmp { d, op, a, b, w } => (Some(Key::Cmp(cmp_code(op), w, a, b)), vec![d]),
            Inst::FpCmp { d, op, a, b, w } => (Some(Key::FpCmp(op, w, a, b)), vec![d]),
            Inst::Sel { d, c, t, f, w } => (Some(Key::Sel(w, c, t, f)), vec![d]),
            Inst::Ext { d, op, a, from, to } => (Some(Key::Ext(op, from, to, a)), vec![d]),
            Inst::Cvt {
                d,
                op,
                a,
                from,
                to,
                rm,
            } => (Some(Key::Cvt(op, from, to, a, rm)), vec![d]),
            Inst::If { c, t, f } => {
                let mut t = t;
                let mut f = f;
                cse(&mut t, &mut table.clone());
                cse(&mut f, &mut table.clone());
                out.push(Inst::If { c, t, f });
                continue;
            }
            _ => {
                out.push(i);
                continue;
            }
        };
        let key = key.expect("key");
        if let Some(prev) = table.get(&key) {
            for (d, p) in outs.iter().zip(prev.iter()) {
                rename.insert(*d, *p);
            }
            // 2 つ目の同じ式は落とす（operand の置き換えは rename が担う）。
            continue;
        }
        table.insert(key, outs);
        out.push(i);
    }
    *ops = out;
}

// ---- 直前の書き込み潰し（DSE）----

/// 同じ列のあとで同じ (off, w) に書く `Set` の前の `Set` は消す。
/// 状態が見える点（`Get`/終端操作/メモリ操作/`If`/動的添字）で区切る。
fn dse(ops: &mut Vec<Inst>, pending: &mut HashMap<(u32, Wid), usize>) {
    let mut kill = HashSet::new();
    let mut i = 0;
    while i < ops.len() {
        match &mut ops[i] {
            Inst::Set { off, w, .. } => {
                if let Some(&j) = pending.get(&(*off, *w)) {
                    kill.insert(j);
                }
                pending.insert((*off, *w), i);
            }
            Inst::Get { off, w, .. } => {
                let (a, b) = (*off as u64, *off as u64 + u64::from(w.bytes()));
                pending.retain(|(o, w2), _| {
                    let (x, y) = (*o as u64, *o as u64 + u64::from(w2.bytes()));
                    y <= a || b <= x
                });
            }
            Inst::If { t, f, .. } => {
                // 枝の中の書き込みは条件付き。表は使い回さず、枝を出たら捨てる。
                pending.clear();
                dse(t, &mut HashMap::new());
                dse(f, &mut HashMap::new());
            }
            // 動的添字はどのフィールドにも当たり得る。ブロックを
            // 抜け得る操作では、そこまでの書き込みが見える。
            Inst::GetIx { .. } | Inst::SetIx { .. } => pending.clear(),
            x if x.can_leave() => pending.clear(),
            _ => {}
        }
        i += 1;
    }
    if !kill.is_empty() {
        let mut n = 0;
        ops.retain(|_| {
            let keep = !kill.contains(&n);
            n += 1;
            keep
        });
    }
}

// ---- 死んだ純粋操作の削除（DCE）----

/// 操作が値を返すだけで副作用を持たないか。
fn is_pure(i: &Inst) -> bool {
    matches!(
        i,
        Inst::Const { .. }
            | Inst::Get { .. }
            | Inst::GetIx { .. }
            | Inst::Un { .. }
            | Inst::Bin { .. }
            | Inst::Tri { .. }
            | Inst::Adc { .. }
            | Inst::Cmp { .. }
            | Inst::FpCmp { .. }
            | Inst::Sel { .. }
            | Inst::Ext { .. }
            | Inst::Cvt { .. }
    )
}

/// 純粋な操作の出力 `Id` 一覧。
fn outs(i: &Inst) -> Vec<Id> {
    match *i {
        Inst::Adc { d, dc, dv, .. } => vec![d, dc, dv],
        _ => match i {
            Inst::Const { d, .. }
            | Inst::Get { d, .. }
            | Inst::GetIx { d, .. }
            | Inst::Un { d, .. }
            | Inst::Bin { d, .. }
            | Inst::Tri { d, .. }
            | Inst::Cmp { d, .. }
            | Inst::FpCmp { d, .. }
            | Inst::Sel { d, .. }
            | Inst::Ext { d, .. }
            | Inst::Cvt { d, .. }
            | Inst::Load { d, .. }
            | Inst::Cmpx { d, .. }
            | Inst::LdRes { d, .. }
            | Inst::StCond { d, .. } => vec![*d],
            _ => vec![],
        },
    }
}

/// `used` に `i` のオペランドを足す。
fn operand_ids(i: &Inst, used: &mut HashSet<Id>) {
    remap_ref(i, &mut |id| {
        used.insert(id);
    });
}

fn remap_ref(i: &Inst, f: &mut impl FnMut(Id)) {
    match i {
        Inst::Const { .. } | Inst::Get { .. } => {}
        Inst::Set { v, .. } => f(*v),
        Inst::GetIx { ix, .. } => f(*ix),
        Inst::SetIx { ix, v, .. } => {
            f(*ix);
            f(*v);
        }
        Inst::Un { a, .. } => f(*a),
        Inst::Bin { a, b, .. } | Inst::Cmp { a, b, .. } | Inst::FpCmp { a, b, .. } => {
            f(*a);
            f(*b);
        }
        Inst::Tri { a, b, c, .. } | Inst::Adc { a, b, c, .. } => {
            f(*a);
            f(*b);
            f(*c);
        }
        Inst::Sel { c, t, f: fe, .. } => {
            f(*c);
            f(*t);
            f(*fe);
        }
        Inst::Ext { a, .. } | Inst::Cvt { a, .. } => f(*a),
        Inst::Load { addr, .. } | Inst::Probe { addr, .. } | Inst::LdRes { addr, .. } => f(*addr),
        Inst::Store { addr, v, .. } | Inst::StCond { addr, v, .. } => {
            f(*addr);
            f(*v);
        }
        Inst::Cmpx { addr, old, new, .. } => {
            f(*addr);
            f(*old);
            f(*new);
        }
        Inst::If { c, t, f: fe } => {
            f(*c);
            for x in t.iter().chain(fe.iter()) {
                remap_ref(x, f);
            }
        }
        Inst::Jump { v } | Inst::Branch { c: v, .. } => f(*v),
        Inst::Exit { .. } | Inst::Unimpl { .. } => {}
        Inst::Hint { v, .. } => f(*v),
    }
}

/// 使われない純粋な操作を消す。`If` の中は再起する。
fn dce(ops: &mut Vec<Inst>) {
    for i in ops.iter_mut() {
        if let Inst::If { t, f, .. } = i {
            dce(t);
            dce(f);
        }
    }
    // 両側が空になった `If` は消せる。
    ops.retain(|i| !matches!(i, Inst::If { t, f, .. } if t.is_empty() && f.is_empty()));
    // 生存する値の収集を不動点まで回す。
    let mut used = HashSet::new();
    for i in ops.iter() {
        if !is_pure(i) {
            operand_ids(i, &mut used);
        }
    }
    let mut changed = true;
    while changed {
        changed = false;
        for i in ops.iter() {
            if is_pure(i) && outs(i).iter().any(|d| used.contains(d)) {
                let before = used.len();
                operand_ids(i, &mut used);
                changed |= used.len() != before;
            }
        }
    }
    ops.retain(|i| !is_pure(i) || outs(i).iter().any(|d| used.contains(d)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_mem::{Access, AccessKind, Align, Endian};

    /// `Ir` へ値と操作を足す小さな組み立て器。
    #[derive(Default)]
    struct Bld {
        ir: Ir,
    }

    impl Bld {
        fn new() -> Self {
            Self::default()
        }
        fn konst(&mut self, w: Wid, v: u128) -> Id {
            let d = self.ir.def(w);
            self.ir.ops.push(Inst::Const { d, w, v });
            d
        }
        fn bin(&mut self, op: BinOp, w: Wid, a: Id, b: Id) -> Id {
            let d = self.ir.def(w);
            self.ir.ops.push(Inst::Bin { d, op, a, b, w });
            d
        }
        fn get(&mut self, off: u32, w: Wid) -> Id {
            let d = self.ir.def(w);
            self.ir.ops.push(Inst::Get { d, off, w });
            d
        }
        fn set(&mut self, off: u32, w: Wid, v: Id) {
            self.ir.ops.push(Inst::Set { off, w, v });
        }
        fn push(&mut self, i: Inst) {
            self.ir.ops.push(i);
        }
    }

    #[test]
    fn fold_const_arith() {
        let mut b = Bld::new();
        let a = b.konst(Wid::W64, 3);
        let c = b.konst(Wid::W64, 4);
        let s = b.bin(BinOp::Add, Wid::W64, a, c);
        b.set(0, Wid::W64, s);
        optimize(&mut b.ir);
        // 7 = 3+4 の定数に畳まれ、Set だけが残る。
        assert!(
            b.ir.ops
                .iter()
                .all(|i| matches!(i, Inst::Const { v: 7, .. } | Inst::Set { .. })),
            "{:?}",
            b.ir.ops
        );
        let n_sets =
            b.ir.ops
                .iter()
                .filter(|i| matches!(i, Inst::Set { .. }))
                .count();
        assert_eq!(n_sets, 1);
    }

    #[test]
    fn fold_copy_prop() {
        // x + 0 は x のコピーになる。Set は a そのものを見る。
        let mut b = Bld::new();
        let a = b.get(8, Wid::W64);
        let z = b.konst(Wid::W64, 0);
        let s = b.bin(BinOp::Add, Wid::W64, a, z);
        b.set(0, Wid::W64, s);
        optimize(&mut b.ir);
        // Get と Set だけ残り、Set は Get の値をそのまま書く。
        let get_id =
            b.ir.ops
                .iter()
                .find_map(|i| match i {
                    Inst::Get { d, .. } => Some(*d),
                    _ => None,
                })
                .expect("Get が残る");
        assert!(
            b.ir.ops
                .iter()
                .any(|i| matches!(i, Inst::Set { v, .. } if *v == get_id)),
            "{:?}",
            b.ir.ops
        );
    }

    #[test]
    fn cse_dedups_same_expr() {
        let mut b = Bld::new();
        let a = b.get(8, Wid::W64);
        let c = b.get(16, Wid::W64);
        let s1 = b.bin(BinOp::Add, Wid::W64, a, c);
        let s2 = b.bin(BinOp::Add, Wid::W64, a, c);
        b.set(0, Wid::W64, s1);
        // s2 も使うので、dce ではなく cse が重複を消す。
        b.set(8, Wid::W64, s2);
        let n_bin =
            b.ir.ops
                .iter()
                .filter(|i| matches!(i, Inst::Bin { op: BinOp::Add, .. }))
                .count();
        assert_eq!(n_bin, 2, "最適化前");
        optimize(&mut b.ir);
        let n_bin =
            b.ir.ops
                .iter()
                .filter(|i| matches!(i, Inst::Bin { op: BinOp::Add, .. }))
                .count();
        assert_eq!(n_bin, 1, "{:?}", b.ir.ops);
        // 両方の Set が同じ Bin の値を書く。
        let bin_id =
            b.ir.ops
                .iter()
                .find_map(|i| match i {
                    Inst::Bin { d, .. } => Some(*d),
                    _ => None,
                })
                .expect("Bin が残る");
        assert!(
            b.ir.ops
                .iter()
                .filter(|i| matches!(i, Inst::Set { v, .. } if *v == bin_id))
                .count()
                == 2,
            "{:?}",
            b.ir.ops
        );
    }

    #[test]
    fn dse_kills_shadowed_set() {
        let mut b = Bld::new();
        let v1 = b.konst(Wid::W64, 1);
        b.set(0, Wid::W64, v1);
        let v2 = b.konst(Wid::W64, 2);
        b.set(0, Wid::W64, v2);
        optimize(&mut b.ir);
        let sets: Vec<&Inst> =
            b.ir.ops
                .iter()
                .filter(|i| matches!(i, Inst::Set { .. }))
                .collect();
        assert_eq!(sets.len(), 1, "{:?}", b.ir.ops);
    }

    #[test]
    fn dse_keeps_visible_set() {
        // Set → Get（読み出し）→ Set: 前の書き込みは読み出しに見える。
        // 部分重なりの Get は転送されずに残るので dse が保護する。
        let mut b = Bld::new();
        let v1 = b.konst(Wid::W64, 1);
        b.set(0, Wid::W64, v1);
        let g = b.get(4, Wid::W32);
        b.set(8, Wid::W32, g);
        let v2 = b.konst(Wid::W64, 2);
        b.set(0, Wid::W64, v2);
        optimize(&mut b.ir);
        let n =
            b.ir.ops
                .iter()
                .filter(|i| matches!(i, Inst::Set { off: 0, .. }))
                .count();
        assert_eq!(n, 2, "{:?}", b.ir.ops);
    }

    #[test]
    fn get_forwarded_then_dse_kills() {
        // 同じ (off, w) の Get は直前の Set の値に転送されるので、
        // 読み出しが消えた後の Set(0) は死に、dse が消す。
        let mut b = Bld::new();
        let v1 = b.konst(Wid::W64, 1);
        b.set(0, Wid::W64, v1);
        let g = b.get(0, Wid::W64);
        b.set(8, Wid::W64, g);
        let v2 = b.konst(Wid::W64, 2);
        b.set(0, Wid::W64, v2);
        optimize(&mut b.ir);
        let n =
            b.ir.ops
                .iter()
                .filter(|i| matches!(i, Inst::Set { off: 0, .. }))
                .count();
        assert_eq!(n, 1, "{:?}", b.ir.ops);
    }

    #[test]
    fn dse_keeps_set_across_exit_points() {
        // Set → Store（抜け得る）→ Set: メモリ操作の前の状態が
        // フォルト時に見えるので、前の書き込みは消せない。
        let mut b = Bld::new();
        let v1 = b.konst(Wid::W64, 1);
        b.set(0, Wid::W64, v1);
        let a = b.konst(Wid::W64, 0x2000);
        b.push(Inst::Store {
            addr: a,
            v: v1,
            w: Wid::W64,
            acc: Access {
                endian: Endian::Le,
                align: Align::Natural,
                kind: AccessKind::DataWrite,
            },
            pc: 0x100,
            next: 0x104,
        });
        let v2 = b.konst(Wid::W64, 2);
        b.set(0, Wid::W64, v2);
        optimize(&mut b.ir);
        let n =
            b.ir.ops
                .iter()
                .filter(|i| matches!(i, Inst::Set { off: 0, .. }))
                .count();
        assert_eq!(n, 2, "{:?}", b.ir.ops);
    }

    #[test]
    fn dce_removes_dead_pure() {
        let mut b = Bld::new();
        let a = b.konst(Wid::W64, 1);
        let c = b.konst(Wid::W64, 2);
        let _dead = b.bin(BinOp::Add, Wid::W64, a, c);
        let v = b.konst(Wid::W64, 9);
        b.set(0, Wid::W64, v);
        optimize(&mut b.ir);
        assert!(
            !b.ir.ops.iter().any(|i| matches!(i, Inst::Bin { .. })),
            "{:?}",
            b.ir.ops
        );
        assert_eq!(
            b.ir.ops
                .iter()
                .filter(|i| matches!(i, Inst::Set { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn dce_keeps_side_effects() {
        // 使わない値だけが消え、Set/Unimpl は残る。
        let mut b = Bld::new();
        let a = b.konst(Wid::W64, 1);
        let c = b.konst(Wid::W64, 2);
        let _dead = b.bin(BinOp::Add, Wid::W64, a, c);
        b.set(0, Wid::W64, a);
        b.push(Inst::Unimpl { pc: 0x100 });
        optimize(&mut b.ir);
        assert!(
            !b.ir.ops.iter().any(|i| matches!(i, Inst::Bin { .. })),
            "{:?}",
            b.ir.ops
        );
        assert!(b.ir.ops.iter().any(|i| matches!(i, Inst::Unimpl { .. })));
        assert!(b.ir.ops.iter().any(|i| matches!(i, Inst::Set { .. })));
    }

    #[test]
    fn if_const_cond_inlines_taken_side() {
        // 条件が定数 1 の If は then 側に展開される。
        let mut b = Bld::new();
        let one = b.konst(Wid::W1, 1);
        let v = b.konst(Wid::W64, 42);
        b.push(Inst::If {
            c: one,
            t: vec![Inst::Set {
                off: 0,
                w: Wid::W64,
                v,
            }],
            f: vec![Inst::Set {
                off: 8,
                w: Wid::W64,
                v,
            }],
        });
        optimize(&mut b.ir);
        assert!(
            !b.ir.ops.iter().any(|i| matches!(i, Inst::If { .. })),
            "{:?}",
            b.ir.ops
        );
        assert!(
            b.ir.ops
                .iter()
                .any(|i| matches!(i, Inst::Set { off: 0, .. })),
            "{:?}",
            b.ir.ops
        );
        assert!(
            !b.ir
                .ops
                .iter()
                .any(|i| matches!(i, Inst::Set { off: 8, .. })),
            "{:?}",
            b.ir.ops
        );
    }
}
