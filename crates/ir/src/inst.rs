// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! SSA 形 IR の定義。値は `Id`、幅は `Wid`、操作は `Inst`。
//!
//! 形は docs/design/jit.md の「IR」に従う。ブロックは `ops` の
//! 直列で、制御が動く操作（`Jump`/`Branch`/`Exit`/`Unimpl`）は
//! ブロックの「継続できなくなる点」として記録される。条件分岐は
//! 子列を持つ `If` 1 ノードで表し、グラフの辺は持たない。

use polyisa_mem::Access;
use polyisa_sem::GuestException;
use polyisa_sem::{Cmp, Width};

/// SSA 値の識別子。`Ir::wids` に対応する添字。
pub type Id = u32;

/// IR 値のビット幅。真偽値は `W1`。浮動小数点の値もビット幅で持つ。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Wid {
    W1,
    W8,
    W16,
    W32,
    W64,
    W128,
}

impl Wid {
    /// `Width` 型から `Wid` へ写す。
    #[must_use]
    pub fn of<W: Width>() -> Self {
        match W::BITS {
            8 => Self::W8,
            16 => Self::W16,
            32 => Self::W32,
            64 => Self::W64,
            128 => Self::W128,
            _ => unreachable!("幅"),
        }
    }

    /// ビット数。
    #[must_use]
    pub const fn bits(self) -> u32 {
        match self {
            Self::W1 => 1,
            Self::W8 => 8,
            Self::W16 => 16,
            Self::W32 => 32,
            Self::W64 => 64,
            Self::W128 => 128,
        }
    }

    /// バイト数。`W1` は 1。
    #[must_use]
    pub const fn bytes(self) -> u32 {
        self.bits().div_ceil(8)
    }

    /// `bits` から `Wid` を引く。真偽値には `W1` を使うので 1 は来ない。
    #[must_use]
    pub const fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            8 => Some(Self::W8),
            16 => Some(Self::W16),
            32 => Some(Self::W32),
            64 => Some(Self::W64),
            128 => Some(Self::W128),
            _ => None,
        }
    }

    /// この幅で有効なビットだけを立てるマスク。
    #[must_use]
    pub const fn mask(self) -> u128 {
        if self.bits() >= 128 {
            u128::MAX
        } else {
            (1 << self.bits()) - 1
        }
    }
}

/// 1 入力の演算。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum UnOp {
    Not,
    Fsqrt,
    Fclass,
}

/// 2 入力の演算。`F*` は浮動小数点で例外フラグを蓄積する。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum BinOp {
    Add,
    Sub,
    And,
    Or,
    Xor,
    Shl,
    ShrL,
    ShrA,
    Udiv,
    Urem,
    Mul,
    Mulh,
    Mulhsu,
    Mulhu,
    Sdiv,
    Srem,
    Fadd,
    Fsub,
    Fmul,
    Fdiv,
    Fmin,
    Fmax,
    Fsgnj,
    Fsgnjn,
    Fsgnjx,
}

/// 3 入力の演算。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum TriOp {
    Fmadd,
}

/// 浮動小数点の比較。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum FpCmp {
    Feq,
    Flt,
    Fle,
}

/// 幅の変換。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Ext {
    Zext,
    Sext,
    Trunc,
}

/// 浮動小数点の変換。`from`/`to` は `Inst::Cvt` の幅で表す。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Cvt {
    S32,
    U32,
    S64,
    U64,
    FromS32,
    FromU32,
    FromS64,
    FromU64,
    Ff,
}

/// 1 つの IR 操作。値を作るものは `d` に出力 ID を持つ。
///
/// `pc`/`next` を持つものは実行がここで止まり得る点で、
/// `pc` はその操作を記録した命令のアドレス、`next` はその命令の
/// 直後のアドレス（トラップ処理後の既定の再開点）を持つ。
#[derive(Clone, Debug)]
pub enum Inst {
    /// 定数。`v` の上位（w より上）は 0。
    Const { d: Id, w: Wid, v: u128 },
    /// 状態の読み出し（`StateRef` のオフセット）。
    Get { d: Id, off: u32, w: Wid },
    /// 状態への書き込み。
    Set { off: u32, w: Wid, v: Id },
    /// 状態配列の読み出し（基底 + 動的添字 × stride）。
    GetIx {
        d: Id,
        base: u32,
        stride: u32,
        ix: Id,
        w: Wid,
    },
    /// 状態配列への書き込み。
    SetIx {
        base: u32,
        stride: u32,
        ix: Id,
        v: Id,
        w: Wid,
    },
    /// 1 入力演算。`Fclass` の出力は `W32`。
    Un { d: Id, op: UnOp, a: Id, w: Wid },
    /// 2 入力演算。
    Bin {
        d: Id,
        op: BinOp,
        a: Id,
        b: Id,
        w: Wid,
    },
    /// 3 入力演算。
    Tri {
        d: Id,
        op: TriOp,
        a: Id,
        b: Id,
        c: Id,
        w: Wid,
    },
    /// 加算の {和, キャリー, オーバーフロー}。`dc`/`dv` は `W1`。
    Adc {
        d: Id,
        dc: Id,
        dv: Id,
        a: Id,
        b: Id,
        c: Id,
        w: Wid,
    },
    /// 整数比較。出力は `W1`。
    Cmp {
        d: Id,
        op: Cmp,
        a: Id,
        b: Id,
        w: Wid,
    },
    /// 浮動小数点比較。出力は `W1`。
    FpCmp {
        d: Id,
        op: FpCmp,
        a: Id,
        b: Id,
        w: Wid,
    },
    /// `c ? t : f`。
    Sel { d: Id, c: Id, t: Id, f: Id, w: Wid },
    /// 幅の変換。
    Ext {
        d: Id,
        op: Ext,
        a: Id,
        from: Wid,
        to: Wid,
    },
    /// 浮動小数点の変換。`rm` は rounding mode の番号。
    Cvt {
        d: Id,
        op: Cvt,
        a: Id,
        from: Wid,
        to: Wid,
        rm: u8,
    },
    /// メモリ読み出し。失敗時は `pc` の命令の例外として抜ける。
    Load {
        d: Id,
        addr: Id,
        w: Wid,
        acc: Access,
        pc: u64,
        next: u64,
    },
    /// メモリ書き込み。
    Store {
        addr: Id,
        v: Id,
        w: Wid,
        acc: Access,
        pc: u64,
        next: u64,
    },
    /// メモリの到達確認。
    Probe {
        addr: Id,
        len: u32,
        acc: Access,
        pc: u64,
        next: u64,
    },
    /// 比較して等しければ書き換え、読み出した値を返す。
    Cmpx {
        d: Id,
        addr: Id,
        old: Id,
        new: Id,
        w: Wid,
        acc: Access,
        pc: u64,
        next: u64,
    },
    /// 予約付き読み出し。
    LdRes {
        d: Id,
        addr: Id,
        w: Wid,
        acc: Access,
        pc: u64,
        next: u64,
    },
    /// 条件付き書き込み。出力（`W1`）は成功なら 1。
    StCond {
        d: Id,
        addr: Id,
        v: Id,
        w: Wid,
        acc: Access,
        pc: u64,
        next: u64,
    },
    /// 条件付きの操作列。`c` が真なら `t`、偽なら `f` を実行する。
    If { c: Id, t: Vec<Inst>, f: Vec<Inst> },
    /// 次の実行を `v` の番地へ移す。ブロックのそれ以降の操作も実行される。
    Jump { v: Id },
    /// `c` が真なら `target` へ移す。
    Branch { c: Id, target: u64 },
    /// 例外で抜ける。
    Exit {
        e: GuestException,
        pc: u64,
        next: u64,
    },
    /// 未実装の操作に当たって抜ける（ヘルパー呼び出し等）。
    Unimpl { pc: u64 },
    /// タイミングの手がかり。現在は実行時の効果を持たない記録だけ。
    Hint { key: u32, v: Id },
}

impl Inst {
    /// この操作がブロックの外へ抜け得るか。
    /// `Jump`/`Branch` は抜けない（継続点を動かすだけ）。
    #[must_use]
    pub fn can_leave(&self) -> bool {
        match self {
            Self::Exit { .. } | Self::Unimpl { .. } => true,
            Self::Load { .. }
            | Self::Store { .. }
            | Self::Probe { .. }
            | Self::Cmpx { .. }
            | Self::LdRes { .. }
            | Self::StCond { .. } => true,
            Self::If { t, f, .. } => t.iter().any(Self::can_leave) || f.iter().any(Self::can_leave),
            _ => false,
        }
    }

    /// ブロックを継続させる制御（`Jump`/`Branch`）を含むか。
    #[must_use]
    pub fn has_flow(&self) -> bool {
        match self {
            Self::Jump { .. } | Self::Branch { .. } => true,
            Self::If { t, f, .. } => t.iter().any(Self::has_flow) || f.iter().any(Self::has_flow),
            _ => false,
        }
    }
}

/// 1 ブロックぶんの IR。`wids[i]` は値 `i` の幅。
#[derive(Clone, Debug, Default)]
pub struct Ir {
    pub wids: Vec<Wid>,
    pub ops: Vec<Inst>,
}

impl Ir {
    /// 新しい値 ID を確保する。
    pub fn def(&mut self, w: Wid) -> Id {
        let d = self.wids.len() as Id;
        self.wids.push(w);
        d
    }

    /// 値 `i` の幅。
    #[must_use]
    pub fn wid(&self, i: Id) -> Wid {
        self.wids[i as usize]
    }

    /// 継続点を動かす操作を含むか。
    #[must_use]
    pub fn has_flow(&self) -> bool {
        self.ops.iter().any(Inst::has_flow)
    }

    /// 例外などで抜け得る操作を含むか。
    #[must_use]
    pub fn can_leave(&self) -> bool {
        self.ops.iter().any(Inst::can_leave)
    }
}

/// `entry` から記録したブロックと、どの出口も取らなかったときの
/// 既定の次（`fall`、最後の命令の直後）。
#[derive(Clone, Debug)]
pub struct Recorded {
    pub entry: u64,
    pub fall: u64,
    pub ir: Ir,
}
