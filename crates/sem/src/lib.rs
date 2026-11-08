//! 命令意味論の語彙。バックエンドトレイト、値の型、退出の型。
//!
//! 詳しくは [命令意味論](../../docs/design/semantics.md) を見る。

#![forbid(unsafe_code)]

pub use polyisa_mem::Access;

/// 値の幅。`W8`、`W16`、`W32`、`W64`、`W128` を用意する。
pub trait Width: Copy + 'static {
    const BITS: u32;
    type Repr: Copy + PartialEq + core::fmt::Debug;
    /// 実行時の値を 128 ビット整数にする。幅より上は 0。
    fn to_u128(v: Self::Repr) -> u128;
    /// 128 ビット整数から実行時の値にする。幅より上は切り捨てる。
    fn from_u128(v: u128) -> Self::Repr;
}

/// 8 ビット。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct W8;
/// 16 ビット。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct W16;
/// 32 ビット。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct W32;
/// 64 ビット。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct W64;
/// 128 ビット。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct W128;

impl Width for W8 {
    const BITS: u32 = 8;
    type Repr = u8;
    fn to_u128(v: Self::Repr) -> u128 {
        u128::from(v)
    }
    fn from_u128(v: u128) -> Self::Repr {
        v as u8
    }
}
impl Width for W16 {
    const BITS: u32 = 16;
    type Repr = u16;
    fn to_u128(v: Self::Repr) -> u128 {
        u128::from(v)
    }
    fn from_u128(v: u128) -> Self::Repr {
        v as u16
    }
}
impl Width for W32 {
    const BITS: u32 = 32;
    type Repr = u32;
    fn to_u128(v: Self::Repr) -> u128 {
        u128::from(v)
    }
    fn from_u128(v: u128) -> Self::Repr {
        v as u32
    }
}
impl Width for W64 {
    const BITS: u32 = 64;
    type Repr = u64;
    fn to_u128(v: Self::Repr) -> u128 {
        u128::from(v)
    }
    fn from_u128(v: u128) -> Self::Repr {
        v as u64
    }
}
impl Width for W128 {
    const BITS: u32 = 128;
    type Repr = u128;
    fn to_u128(v: Self::Repr) -> u128 {
        v
    }
    fn from_u128(v: u128) -> Self::Repr {
        v
    }
}

/// 比較の演算。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cmp {
    Eq,
    Ne,
    LtU,
    LtS,
    GtU,
    GtS,
    LeU,
    LeS,
    GeU,
    GeS,
}

/// ISA に依存しない例外の種類。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExceptionKind {
    Undefined,
    PageFault,
    Align,
    DivZero,
    Fp,
    Break,
    Trap,
}

/// 例外の情報。OS パーソナリティがシグナルに変換する。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GuestException {
    pub kind: ExceptionKind,
    /// ISA 固有のコード。
    pub code: u64,
    /// 関係するアドレス（フォールトアドレスなど）。
    pub addr: Option<u64>,
    /// 遅延スロット内の例外かどうか。
    pub in_delay_slot: bool,
}

/// CPU 状態の構造体の中のフィールドを指す。生成コードだけが作る。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StateRef<W: Width> {
    offset: usize,
    _width: core::marker::PhantomData<W>,
}

impl<W: Width> StateRef<W> {
    /// オフセットから作る。`offset_of!` で求めた値を渡す。
    #[must_use]
    pub const fn from_offset(offset: usize) -> Self {
        Self {
            offset,
            _width: core::marker::PhantomData,
        }
    }

    /// フィールドのオフセット。
    #[must_use]
    pub const fn offset(self) -> usize {
        self.offset
    }
}

/// CPU 状態の中の配列を指す。動的なレジスタ参照に使う。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StateArray<W: Width> {
    offset: usize,
    stride: usize,
    _width: core::marker::PhantomData<W>,
}

impl<W: Width> StateArray<W> {
    #[must_use]
    pub const fn from_layout(offset: usize, stride: usize) -> Self {
        Self {
            offset,
            stride,
            _width: core::marker::PhantomData,
        }
    }

    /// 配列の基底オフセット。
    #[must_use]
    pub const fn offset(self) -> usize {
        self.offset
    }

    /// 要素の間隔（バイト）。
    #[must_use]
    pub const fn stride(self) -> usize {
        self.stride
    }
}

/// ヘルパー。複雑な処理を具体的な値に対して行う普通の関数。
pub trait Helper {
    type Args<B: Backend>;
    type Ret<B: Backend>;
}

/// 挙動パラメータ。CPU モデルごとの値を表す型付きの値。
pub trait Param {
    type Value: Copy;
}

/// タイミングの手がかりの鍵。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct HintKey(pub u32);

/// 意味論の関数の戻り値。
pub type Flow<B> = Result<(), <B as Backend>::Exit>;

/// 命令意味論を受け取る側。インタプリタと IR が実装する。
pub trait Backend {
    /// `W` ビットの実行時の値。インタプリタでは整数、IR では値の番号。
    type V<W: Width>: Copy;
    /// 実行時の真偽値。
    type B: Copy;
    /// 命令を途中で抜ける理由。
    type Exit;

    // 定数
    fn konst<W: Width>(&mut self, v: W::Repr) -> Self::V<W>;

    // CPU 状態
    fn get<W: Width>(&mut self, r: StateRef<W>) -> Self::V<W>;
    fn set<W: Width>(&mut self, r: StateRef<W>, v: Self::V<W>);
    fn get_indexed<W: Width>(&mut self, a: StateArray<W>, i: Self::V<W32>) -> Self::V<W>;
    fn set_indexed<W: Width>(&mut self, a: StateArray<W>, i: Self::V<W32>, v: Self::V<W>);

    // 整数演算（抜粋。段階 0 は整数演算だけを使う）
    fn add<W: Width>(&mut self, a: Self::V<W>, b: Self::V<W>) -> Self::V<W>;
    fn sub<W: Width>(&mut self, a: Self::V<W>, b: Self::V<W>) -> Self::V<W>;
    fn and<W: Width>(&mut self, a: Self::V<W>, b: Self::V<W>) -> Self::V<W>;
    fn or<W: Width>(&mut self, a: Self::V<W>, b: Self::V<W>) -> Self::V<W>;
    fn xor<W: Width>(&mut self, a: Self::V<W>, b: Self::V<W>) -> Self::V<W>;
    fn not<W: Width>(&mut self, a: Self::V<W>) -> Self::V<W>;
    fn shl<W: Width>(&mut self, a: Self::V<W>, n: Self::V<W>) -> Self::V<W>;
    fn shr_l<W: Width>(&mut self, a: Self::V<W>, n: Self::V<W>) -> Self::V<W>;
    fn shr_a<W: Width>(&mut self, a: Self::V<W>, n: Self::V<W>) -> Self::V<W>;
    fn add_with_carry<W: Width>(
        &mut self,
        a: Self::V<W>,
        b: Self::V<W>,
        c: Self::B,
    ) -> (Self::V<W>, Self::B, Self::B);
    fn udiv<W: Width>(&mut self, a: Self::V<W>, b: Self::V<W>) -> Self::V<W>;
    fn urem<W: Width>(&mut self, a: Self::V<W>, b: Self::V<W>) -> Self::V<W>;
    fn mul<W: Width>(&mut self, a: Self::V<W>, b: Self::V<W>) -> Self::V<W>;
    fn mulh<W: Width>(&mut self, a: Self::V<W>, b: Self::V<W>) -> Self::V<W>;
    fn mulhsu<W: Width>(&mut self, a: Self::V<W>, b: Self::V<W>) -> Self::V<W>;
    fn mulhu<W: Width>(&mut self, a: Self::V<W>, b: Self::V<W>) -> Self::V<W>;
    fn sdiv<W: Width>(&mut self, a: Self::V<W>, b: Self::V<W>) -> Self::V<W>;
    fn srem<W: Width>(&mut self, a: Self::V<W>, b: Self::V<W>) -> Self::V<W>;
    fn zext<F: Width, T: Width>(&mut self, a: Self::V<F>) -> Self::V<T>;
    fn sext<F: Width, T: Width>(&mut self, a: Self::V<F>) -> Self::V<T>;
    fn trunc<F: Width, T: Width>(&mut self, a: Self::V<F>) -> Self::V<T>;
    fn cmp<W: Width>(&mut self, op: Cmp, a: Self::V<W>, b: Self::V<W>) -> Self::B;
    fn select<W: Width>(&mut self, c: Self::B, t: Self::V<W>, f: Self::V<W>) -> Self::V<W>;

    // メモリ
    fn load<W: Width>(&mut self, addr: Self::V<W64>, acc: Access)
    -> Result<Self::V<W>, Self::Exit>;
    fn store<W: Width>(
        &mut self,
        addr: Self::V<W64>,
        v: Self::V<W>,
        acc: Access,
    ) -> Result<(), Self::Exit>;
    fn probe(&mut self, addr: Self::V<W64>, len: u32, acc: Access) -> Result<(), Self::Exit>;
    fn cmpxchg<W: Width>(
        &mut self,
        addr: Self::V<W64>,
        old: Self::V<W>,
        new: Self::V<W>,
        acc: Access,
    ) -> Result<Self::V<W>, Self::Exit>;
    fn load_reserved<W: Width>(
        &mut self,
        addr: Self::V<W64>,
        acc: Access,
    ) -> Result<Self::V<W>, Self::Exit>;
    fn store_conditional<W: Width>(
        &mut self,
        addr: Self::V<W64>,
        v: Self::V<W>,
        acc: Access,
    ) -> Result<Self::B, Self::Exit>;

    // 制御
    fn if_then<F>(&mut self, c: Self::B, then: F) -> Result<(), Self::Exit>
    where
        F: FnOnce(&mut Self) -> Result<(), Self::Exit>;
    fn jump(&mut self, target: Self::V<W64>);
    fn branch(&mut self, c: Self::B, target: u64);
    fn raise(&mut self, e: GuestException) -> Self::Exit;

    // ヘルパー、CPU モデル、タイミング
    fn call<H: Helper>(&mut self, args: H::Args<Self>) -> Result<H::Ret<Self>, Self::Exit>
    where
        Self: Sized;
    fn param<P: Param>(&mut self) -> P::Value;
    fn timing_hint(&mut self, key: HintKey, v: Self::V<W64>);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widths() {
        assert_eq!(W8::BITS, 8);
        assert_eq!(W16::BITS, 16);
        assert_eq!(W32::BITS, 32);
        assert_eq!(W64::BITS, 64);
        assert_eq!(W128::BITS, 128);
    }

    #[test]
    fn state_ref_offset() {
        #[repr(C)]
        struct State {
            _pad: u32,
            x: u64,
        }
        let r = StateRef::<W64>::from_offset(core::mem::offset_of!(State, x));
        assert_eq!(r.offset(), 8);
    }
}
