// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! SSA 形の IR。`sem` の `Backend` を実装した `IrBackend` が意味論を
//! ブロックとして記録し、`exec` が解釈実行、`opt` が局所最適化を行う。
//! 形は docs/architecture/execution.md の「IR」に従う。

#![forbid(unsafe_code)]

pub mod exec;
pub mod inst;
pub mod opt;
pub mod rec;

pub use exec::{Concrete, ExitClass, IrOutcome, exec};
pub use inst::{BinOp, Cvt, Ext, FpCmp, Id, Inst, Ir, Recorded, TriOp, UnOp, Wid};
pub use opt::optimize;
pub use rec::{IrBackend, IrCond, IrExit, IrVal};
