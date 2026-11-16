// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `wasi_snapshot_preview1` のインポート解決。`exec::Host` を実装し、
//! 各関数名を `WasiCtx` の処理へ繋ぐ。
//!
//! 宣言された関数型が `canonical_sig` の正準シグネチャと一致しない
//! インポートは提供しない（`want` をそのまま複製すると
//! `extern_matches` が自明に通ってしまうため）。未対応の preview1 名は
//! errno 相当を返すスタブとして提供し、`unknown import` で落ちない
//! ようにする。`proc_exit` は `TrapKind::Exited` で運ぶ。
//! Ref: SPEC-WASI-P1 (wasi_snapshot_preview1).

use std::cell::RefCell;
use std::rc::Rc;

use polyisa_guest_wasm::exec::{self, ExternVal, FuncInst, HostFn, Instance, Store, Trap};
use polyisa_guest_wasm::types::{ExternType, FuncType, Val, ValType};

use crate::abi::errno;
use crate::ctx::WasiCtx;

/// `wasi_snapshot_preview1` / 旧名 `wasi_unstable` のインポートを
/// 提供するホスト。
pub struct Wasi {
    ctx: Rc<RefCell<WasiCtx>>,
}

/// preview1 の関数一覧のうち `WasiCtx::call` が実装しない名前。
/// すべて errno 1 個を返す形で ENOSYS に落とす。
const STUBS: &[&str] = &[
    "clock_res_get",
    "fd_advise",
    "fd_allocate",
    "fd_datasync",
    "fd_fdstat_set_flags",
    "fd_fdstat_set_rights",
    "fd_filestat_set_size",
    "fd_filestat_set_times",
    "fd_pread",
    "fd_pwrite",
    "fd_renumber",
    "fd_sync",
    "path_create_directory",
    "path_filestat_get",
    "path_filestat_set_times",
    "path_link",
    "path_readlink",
    "path_remove_directory",
    "path_rename",
    "path_symlink",
    "path_unlink_file",
    "poll_oneoff",
    "proc_raise",
    "sock_recv",
    "sock_send",
    "sock_shutdown",
];

impl Wasi {
    /// `ctx` を取り込んでホストを作る。
    #[must_use]
    pub fn new(ctx: WasiCtx) -> Self {
        Self {
            ctx: Rc::new(RefCell::new(ctx)),
        }
    }

    /// `Rc` で共有する形で作る（実行後に状態を検査したいとき）。
    #[must_use]
    pub fn shared(ctx: Rc<RefCell<WasiCtx>>) -> Self {
        Self { ctx }
    }

    /// 内部のコンテキスト。
    #[must_use]
    pub fn ctx(&self) -> Rc<RefCell<WasiCtx>> {
        Rc::clone(&self.ctx)
    }
}

impl exec::Host for Wasi {
    fn provide(
        &self,
        store: &mut Store,
        module: &str,
        name: &str,
        want: &ExternType,
    ) -> Option<ExternVal> {
        if module != "wasi_snapshot_preview1" && module != "wasi_unstable" {
            return None;
        }
        let ExternType::Func(ft) = want else {
            return None;
        };
        // 宣言型が preview1 の正準シグネチャと違うインポートは、
        // 存在しないインポートと同じく未解決にする。
        if canonical_sig(name).is_some_and(|c| c != *ft) {
            return None;
        }
        let ty = Rc::new(ft.clone());
        let ctx = Rc::clone(&self.ctx);
        let fname = name.to_string();
        let f: Rc<HostFn> =
            Rc::new(move |store, caller, args| call_one(&ctx, &fname, store, caller, args));
        store.funcs.push(FuncInst::Host { ty, f });
        Some(ExternVal::Func(store.funcs.len() as u32 - 1))
    }
}

/// 呼び出し側インスタンスのメモリ 0 番を引く。
fn caller_mem<'a>(
    store: &'a mut Store,
    caller: Option<&Rc<Instance>>,
) -> Result<&'a mut polyisa_guest_wasm::exec::MemInst, Trap> {
    let inst = caller.ok_or_else(|| Trap::host("wasi: no caller instance"))?;
    let mi = inst.mem0().ok_or_else(|| Trap::host("wasi: no memory"))?;
    store
        .mems
        .get_mut(mi as usize)
        .ok_or_else(|| Trap::host("wasi: bad memory address"))
}

/// 一つのホスト関数呼び出し。
fn call_one(
    ctx: &Rc<RefCell<WasiCtx>>,
    name: &str,
    store: &mut Store,
    caller: Option<&Rc<Instance>>,
    args: &[Val],
) -> Result<Vec<Val>, Trap> {
    if name == "proc_exit" {
        return Err(Trap::exit(args.first().map_or(0, Val::as_i32)));
    }
    if name == "sched_yield" {
        return Ok(vec![Val::I32(0)]);
    }
    if STUBS.contains(&name) {
        return Ok(vec![Val::I32(u32::from(errno::NOSYS))]);
    }
    let mem = caller_mem(store, caller)?;
    match ctx.borrow_mut().call(name, mem, args) {
        Some(r) => r.map_err(|e| Trap::host(format!("wasi {name}: errno {e}"))),
        None => Ok(vec![Val::I32(u32::from(errno::NOSYS))]),
    }
}

/// 要求型に合う戻り値の既定（errno 以外の多値向け。現状未使用）。
#[allow(dead_code)]
fn zero_results(ft: &FuncType) -> Vec<Val> {
    ft.results.iter().map(|t| Val::zero(*t)).collect()
}

/// preview1 の正準な関数型表。`provide` が宣言型の一致検査に使う。
pub fn canonical_sig(name: &str) -> Option<FuncType> {
    let i = ValType::I32;
    let l = ValType::I64;
    let sig = |p: &[ValType], r: &[ValType]| FuncType {
        params: p.to_vec(),
        results: r.to_vec(),
    };
    Some(match name {
        "args_sizes_get" | "environ_sizes_get" | "args_get" | "environ_get" => sig(&[i, i], &[i]),
        "clock_res_get" => sig(&[i, i], &[i]),
        "clock_time_get" => sig(&[i, l, i], &[i]),
        "fd_advise" => sig(&[i, l, l, i], &[i]),
        "fd_allocate" => sig(&[i, l, l], &[i]),
        "fd_close" => sig(&[i], &[i]),
        "fd_datasync" | "fd_sync" => sig(&[i], &[i]),
        "fd_fdstat_get" => sig(&[i, i], &[i]),
        "fd_fdstat_set_flags" => sig(&[i, i], &[i]),
        "fd_fdstat_set_rights" => sig(&[i, l, l], &[i]),
        "fd_filestat_get" => sig(&[i, i], &[i]),
        "fd_filestat_set_size" => sig(&[i, l], &[i]),
        "fd_filestat_set_times" => sig(&[i, l, l, i], &[i]),
        "fd_pread" | "fd_pwrite" => sig(&[i, i, i, l, i], &[i]),
        "fd_prestat_get" => sig(&[i, i], &[i]),
        "fd_prestat_dir_name" => sig(&[i, i, i], &[i]),
        "fd_read" | "fd_write" => sig(&[i, i, i, i], &[i]),
        "fd_readdir" => sig(&[i, i, i, l, i], &[i]),
        "fd_renumber" => sig(&[i, i], &[i]),
        "fd_seek" => sig(&[i, l, i, i], &[i]),
        "fd_tell" => sig(&[i, i], &[i]),
        "path_create_directory" => sig(&[i, i, i], &[i]),
        "path_filestat_get" => sig(&[i, i, i, i, i], &[i]),
        "path_filestat_set_times" => sig(&[i, i, i, i, i, l, l, i], &[i]),
        "path_link" => sig(&[i, i, i, i, i, i, i], &[i]),
        "path_open" => sig(&[i, i, i, i, i, l, l, i, i], &[i]),
        "path_readlink" => sig(&[i, i, i, i, i, i], &[i]),
        "path_remove_directory" | "path_unlink_file" => sig(&[i, i, i], &[i]),
        "path_rename" => sig(&[i, i, i, i, i, i], &[i]),
        "path_symlink" => sig(&[i, i, i, i, i], &[i]),
        "poll_oneoff" => sig(&[i, i, i, i], &[i]),
        "proc_exit" => sig(&[i], &[]),
        "proc_raise" => sig(&[i], &[i]),
        "sched_yield" => sig(&[], &[i]),
        "random_get" => sig(&[i, i], &[i]),
        "sock_recv" => sig(&[i, i, i, i, i, i], &[i]),
        "sock_send" => sig(&[i, i, i, i], &[i]),
        "sock_shutdown" => sig(&[i, i], &[i]),
        _ => return None,
    })
}
