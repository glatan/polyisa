// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 生成コードから呼ぶ実行時関数。メモリ操作と重い演算を Rust で行う。
//!
//! すべて `unsafe extern "sysv64"`：生成コードが `RtCtx` への
//! ポインタと値スロットの番地を渡して呼ぶ。戻り値は多くが
//! 「0=継続、非 0=フォールト（例外情報は `exc_*` へ書き込み済み）」。
//!
//! # 安全性
//!
//! これらの関数は JIT が生成したコードからだけ呼ばれる。
//! `ctx` はブロック実行の間だけ有効な `RtCtx` を指し、
//! `backend`/`state` は同じく実行中の `InterpBackend`/状態を指す。
//! `out`/`io`/`v` のポインタは生成コードのフレーム内の値スロットを
//! 指し、渡された幅に対応するバイト数を持つ。

use polyisa_engine::interp::InterpBackend;
use polyisa_ir::exec::{self, ExitClass};
use polyisa_ir::{BinOp, Cvt, Ext, FpCmp, TriOp, UnOp, Wid};
use polyisa_mem::{Access, AccessKind, Align, Endian, VirtAddr};
use polyisa_sem::{Backend as _, Cmp};

use crate::ctx::{RtCtx, write_exc};

/// `ctx.backend` を `InterpBackend` として使う。
///
/// SAFETY: `RtCtx::backend` は実行中の `InterpBackend` を指す。
unsafe fn b<'a>(ctx: *mut RtCtx) -> &'a mut InterpBackend {
    unsafe { &mut *((*ctx).backend as *mut InterpBackend) }
}

/// 例外を `exc_*` に書き、フォールト用の戻り値 1 を返す。
fn fault(ctx: *mut RtCtx, c: ExitClass) -> u64 {
    match c {
        ExitClass::Raise(e) => {
            // SAFETY: ctx は実行中の RtCtx。
            unsafe { write_exc(&mut *ctx, e) };
            1
        }
        ExitClass::Unimpl => {
            // SAFETY: ctx は実行中の RtCtx。
            unsafe { (*ctx).code = 2 };
            1
        }
    }
}

/// `wid` は `Wid` の番号ではなくビット幅で受け取る。
fn wid(bits: u64) -> Wid {
    Wid::from_bits(bits as u32).unwrap_or(Wid::W8)
}

/// `Access` を 1 つの `u64` に詰める。`endian|align<<2|kind<<4`。
/// 生成コードは同じ規則で焼き込む。
pub fn pack_access(acc: Access) -> u64 {
    let e = match acc.endian {
        Endian::Le => 0u64,
        Endian::Be => 1,
    };
    let a = match acc.align {
        Align::Natural => 0u64,
        Align::Unaligned => 1,
    };
    let k = match acc.kind {
        AccessKind::DataRead => 0u64,
        AccessKind::DataWrite => 1,
        AccessKind::Fetch => 2,
        AccessKind::AtomicRw => 3,
        AccessKind::LoadReserved => 4,
        AccessKind::StoreConditional => 5,
    };
    e | (a << 2) | (k << 4)
}

fn unpack_access(v: u64) -> Access {
    Access {
        endian: if v & 1 == 0 { Endian::Le } else { Endian::Be },
        align: if v & 4 == 0 {
            Align::Natural
        } else {
            Align::Unaligned
        },
        kind: match (v >> 4) & 7 {
            1 => AccessKind::DataWrite,
            2 => AccessKind::Fetch,
            3 => AccessKind::AtomicRw,
            4 => AccessKind::LoadReserved,
            5 => AccessKind::StoreConditional,
            _ => AccessKind::DataRead,
        },
    }
}

/// `op` は各列挙の番号。x64.rs のコード生成と共有する表。
fn bin_op(op: u64) -> BinOp {
    use BinOp as O;
    match op {
        0 => O::Add,
        1 => O::Sub,
        2 => O::And,
        3 => O::Or,
        4 => O::Xor,
        5 => O::Shl,
        6 => O::ShrL,
        7 => O::ShrA,
        8 => O::Udiv,
        9 => O::Urem,
        10 => O::Mul,
        11 => O::Mulh,
        12 => O::Mulhsu,
        13 => O::Mulhu,
        14 => O::Sdiv,
        15 => O::Srem,
        16 => O::Fadd,
        17 => O::Fsub,
        18 => O::Fmul,
        19 => O::Fdiv,
        20 => O::Fmin,
        21 => O::Fmax,
        22 => O::Fsgnj,
        23 => O::Fsgnjn,
        _ => O::Fsgnjx,
    }
}

pub fn bin_code(op: BinOp) -> u64 {
    use BinOp as O;
    match op {
        O::Add => 0,
        O::Sub => 1,
        O::And => 2,
        O::Or => 3,
        O::Xor => 4,
        O::Shl => 5,
        O::ShrL => 6,
        O::ShrA => 7,
        O::Udiv => 8,
        O::Urem => 9,
        O::Mul => 10,
        O::Mulh => 11,
        O::Mulhsu => 12,
        O::Mulhu => 13,
        O::Sdiv => 14,
        O::Srem => 15,
        O::Fadd => 16,
        O::Fsub => 17,
        O::Fmul => 18,
        O::Fdiv => 19,
        O::Fmin => 20,
        O::Fmax => 21,
        O::Fsgnj => 22,
        O::Fsgnjn => 23,
        O::Fsgnjx => 24,
    }
}

fn un_op(op: u64) -> UnOp {
    match op {
        0 => UnOp::Not,
        1 => UnOp::Fsqrt,
        _ => UnOp::Fclass,
    }
}

pub fn un_code(op: UnOp) -> u64 {
    match op {
        UnOp::Not => 0,
        UnOp::Fsqrt => 1,
        UnOp::Fclass => 2,
    }
}

fn fcmp_op(op: u64) -> FpCmp {
    match op {
        0 => FpCmp::Feq,
        1 => FpCmp::Flt,
        _ => FpCmp::Fle,
    }
}

pub fn fcmp_code(op: FpCmp) -> u64 {
    match op {
        FpCmp::Feq => 0,
        FpCmp::Flt => 1,
        FpCmp::Fle => 2,
    }
}

fn cvt_op(op: u64) -> Cvt {
    match op {
        0 => Cvt::S32,
        1 => Cvt::U32,
        2 => Cvt::S64,
        3 => Cvt::U64,
        4 => Cvt::FromS32,
        5 => Cvt::FromU32,
        6 => Cvt::FromS64,
        7 => Cvt::FromU64,
        _ => Cvt::Ff,
    }
}

pub fn cvt_code(op: Cvt) -> u64 {
    match op {
        Cvt::S32 => 0,
        Cvt::U32 => 1,
        Cvt::S64 => 2,
        Cvt::U64 => 3,
        Cvt::FromS32 => 4,
        Cvt::FromU32 => 5,
        Cvt::FromS64 => 6,
        Cvt::FromU64 => 7,
        Cvt::Ff => 8,
    }
}

fn ext_op(op: u64) -> Ext {
    match op {
        0 => Ext::Zext,
        1 => Ext::Sext,
        _ => Ext::Trunc,
    }
}

pub fn ext_code(op: Ext) -> u64 {
    match op {
        Ext::Zext => 0,
        Ext::Sext => 1,
        Ext::Trunc => 2,
    }
}

fn cmp_op(op: u64) -> Cmp {
    match op {
        0 => Cmp::Eq,
        1 => Cmp::Ne,
        2 => Cmp::LtU,
        3 => Cmp::LtS,
        4 => Cmp::GtU,
        5 => Cmp::GtS,
        6 => Cmp::LeU,
        7 => Cmp::LeS,
        8 => Cmp::GeU,
        _ => Cmp::GeS,
    }
}

pub fn cmp_code(op: Cmp) -> u64 {
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

/// `addr` の書き込みがコードのページに当たるとき破棄要求を立てる。
/// `has_code`（コードとして使われた実績）か実行許可のどちらか。
fn code_write(ctx: *mut RtCtx, addr: u64) {
    // SAFETY: ctx は実行中の RtCtx。
    let b = unsafe { b(ctx) };
    if b.mem.may_contain_code(VirtAddr(addr)) {
        unsafe { (*ctx).invalidate = 1 };
    }
}

/// 各実行時関数を書く。`$c` は `RtCtx` ポインタ、`$b` は
/// `&mut InterpBackend` に束縛する名前（マクロ衛生のため呼び側が渡す）。
macro_rules! rt {
    ($name:ident($c:ident, $b:ident, $($arg:ident : $ty:ty),* $(,)?) -> u64, $body:expr) => {
        pub unsafe extern "sysv64" fn $name($c: *mut RtCtx $(, $arg: $ty)*) -> u64 {
            let $b = unsafe { b($c) };
            $body
        }
    };
}

rt!(
    rt_load(ctx, b, addr: u64, w: u64, acc: u64, out: *mut u128) -> u64,
    {
        match exec::load_w(b, wid(w), addr, unpack_access(acc)) {
            Ok(v) => {
                unsafe { *out = v };
                0
            }
            Err(c) => fault(ctx, c),
        }
    }
);

rt!(
    rt_store(ctx, b, addr: u64, w: u64, acc: u64, v: *const u128) -> u64,
    {
        code_write(ctx, addr);
        match exec::store_w(b, wid(w), addr, unsafe { *v }, unpack_access(acc)) {
            Ok(()) => 0,
            Err(c) => fault(ctx, c),
        }
    }
);

rt!(rt_probe(ctx, b, addr: u64, len: u64, acc: u64) -> u64, {
    match b.probe(addr, len as u32, unpack_access(acc)) {
        Ok(()) => 0,
        Err(e) => fault(ctx, <InterpBackend as polyisa_ir::Concrete>::exit_class(e)),
    }
});

// `io` は連続する 3 つの `u128`（`{old, new, out}`）。
rt!(
    rt_cmpx(ctx, b, addr: u64, w: u64, acc: u64, io: *mut u128) -> u64,
    {
        code_write(ctx, addr);
        let (old, new) = unsafe { (*io, *io.add(1)) };
        match exec::cmpx_w(b, wid(w), addr, old, new, unpack_access(acc)) {
            Ok(v) => {
                unsafe { *io.add(2) = v };
                0
            }
            Err(c) => fault(ctx, c),
        }
    }
);

rt!(
    rt_ldres(ctx, b, addr: u64, w: u64, acc: u64, out: *mut u128) -> u64,
    {
        match exec::ldres_w(b, wid(w), addr, unpack_access(acc)) {
            Ok(v) => {
                unsafe { *out = v };
                0
            }
            Err(c) => fault(ctx, c),
        }
    }
);

// `ok` には 0/1 を書く。
rt!(
    rt_stcond(ctx, b, addr: u64, w: u64, acc: u64, v: *const u128, ok: *mut u128) -> u64,
    {
        code_write(ctx, addr);
        match exec::stcond_w(b, wid(w), addr, unsafe { *v }, unpack_access(acc)) {
            Ok(v) => {
                unsafe { *ok = u128::from(v) };
                0
            }
            Err(c) => fault(ctx, c),
        }
    }
);

// ---- フォールトしない演算の委譲 ----

rt!(
    rt_alu(_ctx, bb, op: u64, w: u64, a: *const u128, b2: *const u128, out: *mut u128) -> u64,
    {
        unsafe { *out = exec::alu(bb, bin_op(op), wid(w), *a, *b2) };
        0
    }
);

rt!(
    rt_una(_ctx, bb, op: u64, w: u64, a: *const u128, out: *mut u128) -> u64,
    {
        unsafe { *out = exec::una(bb, un_op(op), wid(w), *a) };
        0
    }
);

rt!(
    rt_tri(
        _ctx,
        bb,
        w: u64,
        a: *const u128,
        b2: *const u128,
        c: *const u128,
        out: *mut u128,
    ) -> u64,
    {
        let _ = TriOp::Fmadd;
        unsafe { *out = exec::fma(bb, wid(w), *a, *b2, *c) };
        0
    }
);

// `out` は 3 つの `u128`（`{値, キャリー, オーバーフロー}`）。
rt!(
    rt_adc(_ctx, bb, w: u64, a: *const u128, b2: *const u128, c: u64, out: *mut u128) -> u64,
    {
        let (r, ca, ov) = exec::adc(bb, wid(w), unsafe { *a }, unsafe { *b2 }, u128::from(c));
        unsafe {
            *out = r;
            *out.add(1) = u128::from(ca);
            *out.add(2) = u128::from(ov);
        }
        0
    }
);

rt!(
    rt_cmp(_ctx, bb, op: u64, w: u64, a: *const u128, b2: *const u128) -> u64,
    {
        u64::from(exec::cmp_w(bb, cmp_op(op), wid(w), unsafe { *a }, unsafe {
            *b2
        }))
    }
);

rt!(
    rt_fcmp(_ctx, bb, op: u64, w: u64, a: *const u128, b2: *const u128) -> u64,
    {
        u64::from(exec::fpcmp(
            bb,
            fcmp_op(op),
            wid(w),
            unsafe { *a },
            unsafe { *b2 },
        ))
    }
);

// `of` は `op|from<<8|to<<16` に詰めた変換指定。
rt!(
    rt_ext(_ctx, bb, of: u64, a: *const u128, out: *mut u128) -> u64,
    {
        let (op, from, to) = (of & 0xff, (of >> 8) & 0xff, (of >> 16) & 0xff);
        unsafe { *out = exec::ext_w(bb, ext_op(op), wid(from), wid(to), *a) };
        0
    }
);

// `of` は `op|from<<8|to<<16|rm<<24` に詰めた変換指定。
rt!(
    rt_cvt(_ctx, bb, of: u64, a: *const u128, out: *mut u128) -> u64,
    {
        let (op, from, to, rm) = (
            of & 0xff,
            (of >> 8) & 0xff,
            (of >> 16) & 0xff,
            ((of >> 24) & 0xff) as u8,
        );
        unsafe { *out = exec::cvt_w(bb, cvt_op(op), wid(from), wid(to), *a, rm) };
        0
    }
);

// 生成コードが自分で足し算を組み立てないよう、添字アクセスもここで行う。
rt!(
    rt_get_ix(_ctx, bb, base: u64, stride: u64, ix: u64, w: u64, out: *mut u128) -> u64,
    {
        unsafe { *out = exec::get_ix(bb, base as u32, stride as u32, ix as u32, wid(w)) };
        0
    }
);

rt!(
    rt_set_ix(_ctx, bb, base: u64, stride: u64, ix: u64, w: u64, v: *const u128) -> u64,
    {
        exec::set_ix(
            bb,
            base as u32,
            stride as u32,
            ix as u32,
            unsafe { *v },
            wid(w),
        );
        0
    }
);
