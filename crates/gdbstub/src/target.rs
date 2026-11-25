// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! デバッグ対象との境界。
//!
//! `server` がパケットを捌くのに必要な最小の操作を `DebugTarget` に
//! 集める。実装側は `cli` の `run -g` が作る対象（BareEnv・エンジンの
//! 実行ループ・ブレークポイントの表）を想定する。

/// 実行が止まった理由。u64 を持つものは止まった時点の pc。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Stop {
    /// ブレークポイントの表にある pc に達した。命令は実行していない。
    Breakpoint(u64),
    /// 1 ステップを実行した。値は実行後の pc。
    Step(u64),
    /// 終了コード付きで対象が終わった。
    Exit(u64),
    /// シグナル番号付きで対象が終わった。
    Signal(u8),
    /// トラップや未実装の命令で止まった。
    Trap(u64),
}

/// メモリアクセスの失敗。失敗の理由の区別は持たない。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MemError;

/// `server` が要求する対象側の操作。
pub trait DebugTarget {
    /// `qXfer:features:read` で返すターゲット記述（target.xml）。
    fn target_xml(&self) -> &str;

    /// `g` が運ぶ全レジスタのバイト数。
    fn reg_bytes(&self) -> usize;

    /// レジスタ `idx` のバイト幅。無い番号は 0。
    fn reg_size(&self, idx: usize) -> usize;

    /// 全レジスタを `g` の順序・対象のエンディアンで `buf` に書き出す。
    /// `buf` の長さは `reg_bytes` と同じ。
    fn read_regs(&mut self, buf: &mut [u8]);

    /// `G` の内容を全レジスタに書き戻す。`buf` の長さは `reg_bytes` と同じ。
    fn write_regs(&mut self, buf: &[u8]);

    /// レジスタ `idx` を `buf` に書き出す。無い番号は偽。
    fn read_reg(&mut self, idx: usize, buf: &mut [u8]) -> bool;

    /// レジスタ `idx` に `buf` の内容を書く。無い番号は偽。
    fn write_reg(&mut self, idx: usize, buf: &[u8]) -> bool;

    /// メモリの読み出し。読めない場所は `Err(MemError)`。
    fn read_mem(&mut self, addr: u64, buf: &mut [u8]) -> Result<(), MemError>;

    /// メモリの書き込み。書けない場所は `Err(MemError)`。
    fn write_mem(&mut self, addr: u64, buf: &[u8]) -> Result<(), MemError>;

    /// 現在の pc。停止理由の応答に使う。
    fn pc(&self) -> u64;

    /// 1 命令を実行して止まる。
    fn step(&mut self) -> Stop;

    /// ブレークポイント・終了・割込みまで実行する。
    fn resume(&mut self) -> Stop;

    /// `k`・`vKill` の処理。対象を終わらせる。
    fn kill(&mut self);

    /// `D` の処理。デバッガを切り離す。
    fn detach(&mut self);

    /// ソフトブレークポイント `Z0` を登録する。ゲストのメモリは
    /// 書き換えず、実装側の表に登録する形（observability.md どおり）。
    /// 登録できなければ偽。
    fn add_bp(&mut self, addr: u64) -> bool;

    /// `z0` で登録を外す。無ければ偽。
    fn remove_bp(&mut self, addr: u64) -> bool;
}
