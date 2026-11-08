# 命令意味論とバックエンド

この文書は、命令意味論の書き方と、意味論が使う操作の集合であるバックエンドトレイトを定める。意味論をバックエンドに対して総称的に書く理由は [ADR-0003](../adr/0003-semantics-generic-over-backend.md) にある。

## 意味論は誰がどう実行するか

命令意味論は、ゲスト ISA クレートの `sem` モジュールに置く Rust の関数であり、バックエンドトレイト `Backend` を実装した型を型引数に取る。意味論の関数は、CPU 状態とメモリを直接触らず、すべてバックエンドの操作を通して読み書きする。

バックエンドの実装は二つある。インタプリタのバックエンド（`engine` クレート）は、値を具体的な整数として持ち、操作をその場で実行する。IR のバックエンド（`ir` クレート）は、値を IR の値の番号として持ち、操作を IR の命令として記録する。記録した IR は最適化され、JIT が機械語に変換する。

意味論の関数は、バックエンドごとに単相化される。インタプリタのバックエンドでは、値の型が整数そのものであり、操作がインライン展開されるので、意味論を直接 Rust で書いた場合と同等のコードになることを期待している。この期待は、最初の ISA の実装時に、同じ命令を直接書いた版と比較するベンチマークで確認する（[ロードマップ](roadmap.md) の段階 1 の完了条件）。

## 意味論を書くときの規則

意味論の関数には、デコード時に決まる値と、実行時に決まる値の二種類が現れる。

- デコード時に決まる値：オペランドのフィールド（レジスタ番号、即値）、命令のアドレス、CPU モデルの挙動パラメータ。Rust の普通の値として受け取る。
- 実行時に決まる値：レジスタやメモリの内容と、それから計算した値。バックエンドの値の型 `B::V<W>` として扱う。

Rust の `if` や `match` で分岐してよいのは、デコード時に決まる値に対してだけである。実行時に決まる値による分岐は、バックエンドの `select`、`if_then`、`if_then_else` で書く。IR のバックエンドでは、デコード時の値による分岐は IR を作る時点で解決され、実行時の値による分岐だけが IR の分岐になる。この規則を守る限り、同じ関数がインタプリタでも IR でも正しく動く。

意味論の中で値の型を取り違えないように、値はビット幅を型引数に持つ。幅の異なる値の演算は、明示的な拡張（`zext`、`sext`）か切り詰め（`trunc`）を通さないとコンパイルできない。

## バックエンドトレイト

以下はトレイトの骨格であり、操作の全一覧ではない。操作の一覧は `sem` クレートの実装時に確定させる。

```rust
/// 値の幅。W8, W16, W32, W64, W128 を用意する。
pub trait Width: Copy + 'static {
    const BITS: u32;
    type Repr: Int; // u8, u16, u32, u64, u128
}

pub trait Backend {
    /// W ビットの実行時の値。インタプリタでは W::Repr、IR では値の番号。
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

    // 整数演算（抜粋）
    fn add<W: Width>(&mut self, a: Self::V<W>, b: Self::V<W>) -> Self::V<W>;
    fn add_with_carry<W: Width>(&mut self, a: Self::V<W>, b: Self::V<W>, c: Self::B)
        -> (Self::V<W>, Self::B, Self::B); // 結果、桁上げ、符号付きオーバーフロー
    fn shl<W: Width>(&mut self, a: Self::V<W>, n: Self::V<W>) -> Self::V<W>;
    fn udiv<W: Width>(&mut self, a: Self::V<W>, b: Self::V<W>) -> Self::V<W>;
    fn zext<F: Width, T: Width>(&mut self, a: Self::V<F>) -> Self::V<T>;
    fn sext<F: Width, T: Width>(&mut self, a: Self::V<F>) -> Self::V<T>;
    fn trunc<F: Width, T: Width>(&mut self, a: Self::V<F>) -> Self::V<T>;
    fn cmp<W: Width>(&mut self, op: Cmp, a: Self::V<W>, b: Self::V<W>) -> Self::B;
    fn select<W: Width>(&mut self, c: Self::B, t: Self::V<W>, f: Self::V<W>) -> Self::V<W>;

    // メモリ
    fn load<W: Width>(&mut self, addr: Self::V<W64>, acc: Access) -> Result<Self::V<W>, Self::Exit>;
    fn store<W: Width>(&mut self, addr: Self::V<W64>, v: Self::V<W>, acc: Access) -> Result<(), Self::Exit>;
    fn probe(&mut self, addr: Self::V<W64>, len: u32, acc: Access) -> Result<(), Self::Exit>;
    fn cmpxchg<W: Width>(&mut self, addr: Self::V<W64>, old: Self::V<W>, new: Self::V<W>, acc: Access)
        -> Result<Self::V<W>, Self::Exit>;

    // 制御
    fn if_then<F>(&mut self, c: Self::B, then: F) -> Result<(), Self::Exit>
    where F: FnOnce(&mut Self) -> Result<(), Self::Exit>;
    fn jump(&mut self, target: Self::V<W64>);
    fn branch(&mut self, c: Self::B, target: u64);
    fn raise(&mut self, e: GuestException) -> Self::Exit;

    // ヘルパー、CPU モデル、タイミング
    fn call<H: Helper>(&mut self, args: H::Args<Self>) -> Result<H::Ret<Self>, Self::Exit>;
    fn param<P: Param>(&mut self) -> P::Value;
    fn timing_hint(&mut self, key: HintKey, v: Self::V<W64>);
}
```

### 演算はすべて全域で定義する

バックエンドの演算は、すべての入力に対して結果を定義する。シフト量がビット幅以上の場合、論理シフトは 0、算術右シフトは符号ビットで埋めた値を返す。除算は除数が 0 の場合と符号付きのオーバーフローの場合に決まった値を返す。

この規則を置くのは、ISA ごとに異なる境界条件の扱い（x86 はシフト量を下位 5 ビットまたは 6 ビットに切り詰め、ARM のレジスタ指定シフトは下位 8 ビットを使い、RISC-V の除算は 0 除算で全ビット 1 を返す）を、意味論の側で明示的に書かせるためである。バックエンドの演算がホストの演算の未定義動作やトラップ（x86 ホストの `div` は 0 除算で例外を起こす）を引き継ぐと、境界条件の結果がホストによって変わる。JIT は、ホストの命令が全域で定義されていない演算について、境界条件の分岐を生成する。

### CPU 状態への参照

`StateRef<W>` は、CPU 状態の構造体の中のフィールドを、オフセットと幅で指す。CPU 状態の構造体は `#[repr(C)]` で定義し、`StateRef` は ISADL から生成したコードだけが `core::mem::offset_of!` を使って作れる。インタプリタのバックエンドは、このオフセットで CPU 状態を直接読み書きし、JIT は CPU 状態へのポインタからの相対アドレスでアクセスする。両者が同じ表現を使うので、CPU 状態の配置は一箇所で決まる。

オフセットによるアクセスは `unsafe` を伴う。安全性は、`StateRef` を作れるのが生成コードに限られることと、オフセットが `offset_of!` で求めたものであることから保たれる。デバッグビルドでは、インタプリタのバックエンドがオフセットの範囲とアライメントを検査する。

### 動的なレジスタ参照

レジスタの物理的な位置が実行時の CPU 状態で決まる ISA がある。SPARC のレジスタウィンドウは CWP で、IA-64 の回転レジスタは CFM の `rrb` で、x87 のスタックレジスタは TOP で位置が変わる。これらは `StateArray<W>`（CPU 状態の中の配列）と実行時の添字で参照する。添字の計算（ウィンドウの基底との加算や剰余）は、ISADL で `dynamic` と宣言したレジスタクラスに対応する Rust の関数として、意味論の中でバックエンドの演算を使って書く。

SPARC のウィンドウの切り替えは `SAVE` と `RESTORE` のたびに起こり、IA-64 の回転はループの各反復で起こる。位置の基底をブロックキーに含めてデコード結果を特殊化すると、基底が変わるたびにブロックを作り直すことになるので、基底は実行時の値として扱う。

## メモリアクセス

`Access` は、エンディアン、アライメントの扱い、アクセスの種類を組にしたアクセス属性である。定義は [ゲストメモリ](memory.md) にある。アクセス属性は意味論の中でデコード時に決まる値として渡すので、JIT はアクセスごとに特殊化したコードを生成できる。

ロードとストアは、ページフォールトやアライメント例外のときに `Exit` を返す。意味論は `?` で退出をそのまま返す。

## 例外と状態の一貫性

命令が例外で退出するとき、アーキテクチャ状態は次のいずれかでなければならない。

1. 命令の開始前の状態のまま変わっていない。
2. ISA が途中状態を規定している命令では、その規定どおりの途中状態になっている（x86 の `REP MOVS` の各反復の終了時、VAX の `MOVC3` の途中状態、s390 の `MVCL` の途中状態）。

1 を守るため、意味論は、例外を起こしうる操作（ロード、ストア、例外を返しうるヘルパー）をすべて終えてから CPU 状態を書く。複数のストアを行う命令（x86 のページ境界をまたぐ `PUSH`、68k の `MOVEM`、ARM の `STM`）では、最初のストアの前に `probe` で全範囲のアクセス可否を確かめる。ストアを途中まで行ったあとで例外を起こすと、メモリだけが更新された状態が残るからである。CSR 命令の権限検査（特権レベル、読み出し専用への書き込み）も、読み書きの前に行い、違反は状態を変えずに退出する。

例外の情報 `GuestException` は、ISA に依存しない種類（未定義命令、ページフォールト、アライメント、ゼロ除算、浮動小数点例外、ブレークポイント、トラップ命令など）と、ISA 固有のコード、関係するアドレスを持つ。OS パーソナリティは、種類とコードからシグナルを決める。

## ヘルパー

浮動小数点演算、ベクトル演算、x86 の `CPUID`、VAX の `EDITPC`、十進演算のように、バックエンドの操作で書くと長くなる処理は、ヘルパーとして書く。ヘルパーは、CPU 状態と、ヘルパー用のメモリアクセス口を受け取る普通の Rust 関数であり、具体的な値に対して実行する。

インタプリタはヘルパーを直接呼ぶ。JIT は、ヘルパーごとに生成した呼び出し規約の変換関数を経由して呼ぶ。ヘルパーは、読み書きする CPU 状態の範囲を宣言できる。宣言がなければ、JIT は呼び出しの前に、レジスタに保持していたゲストの状態をすべて CPU 状態へ書き戻す。

ヘルパーの中では、Rust の普通の制御構文を使ってよい。値が具体的だからである。そのかわり、ヘルパーの中の処理は IR の最適化の対象にならない。頻繁に実行され、最適化の余地が大きい処理（整数演算、条件フラグの計算、アドレス計算）は、ヘルパーにせず、バックエンドの操作で書く。

## ステップの構成

ステップは、ISA が不可分に実行する単位である。ゲスト ISA は、命令のデコード結果からステップを組み立てる関数を持つ。ステップの構成は ISA によって次のように異なる。

| 構成 | ISA | 組み立て方 |
|---|---|---|
| 1 命令 | 大半の ISA | デコードした 1 命令を実行する |
| 遅延スロット付きの分岐 | MIPS、SPARC、SuperH、PA-RISC、OpenRISC | 分岐の条件と飛び先を求め、遅延スロットの命令を実行してから、制御を移す。遅延スロットの無効化（SPARC の annul ビット、MIPS の branch likely）は `if_then` で書く |
| パケット | Hexagon | パケット内の全命令がパケット開始時の CPU 状態を読み、書き込みは一時値に集めて最後にまとめて反映する。`.new` オペランドは一時値を読む |
| バンドル | IA-64 | 3 つのスロットを順に実行する。述語レジスタが偽の命令は実行しない。分岐が成立したら残りのスロットを実行しない |
| 反復 | x86 の `REP` 付き命令、VAX の `MOVC3`、s390 の `MVCL` | 1 回または決まった回数の反復を 1 ステップとし、終わっていなければ同じ命令を次のステップでも実行する |

遅延スロットの命令が例外を起こした場合、例外の情報には「遅延スロット内」であることと分岐命令のアドレスを含める。MIPS の Linux は、この場合に EPC を分岐命令のアドレスにしてシグナルを配送するので、OS パーソナリティがこの情報を必要とする。

PA-RISC の無効化（nullification）は分岐に限らず、直後の任意の命令に及ぶ。そこで、無効化のフラグ（PSW の N ビット）を CPU 状態に持ち、ステップの先頭で調べる。

ステップの中で反復を書かせない（意味論の中にループを作らない）のは、IR の基本ブロックを非循環に保ち、JIT の実装を単純にするためである。反復の回数がデコード時に決まる場合（ARM の `LDM` のレジスタリスト）は、Rust のループで展開してよい。

## 条件フラグ

条件フラグの扱いは ISA ごとの実装方針として、CPU 状態の設計で決める。x86、s390、68k では、フラグを毎回計算せず、直前の演算の種類と入出力を CPU 状態に保存し、フラグを読む命令がそこから計算する（遅延評価）。ARM と Power では、フラグをビットごとに別のフィールドに持ち、計算を単純にする。

どちらの方式でも、フラグは CPU 状態のフィールドとして扱うので、バックエンドから見ると通常の `set` と `get` である。IR の最適化は、ブロック内で上書きされるだけで読まれないフィールドへの書き込みを削除し、遅延評価の保存処理や不要なフラグの計算を取り除く。

## 例

RISC-V の `add`、`beq`、`lw` の意味論は次のようになる。

```rust
pub type Flow<B> = Result<(), <B as Backend>::Exit>;

pub fn add<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = b.get(rs1.state());
    let y = b.get(rs2.state());
    let s = b.add(x, y);
    write_gpr(b, rd, s); // rd が x0 なら書かない（デコード時の値による分岐）
    Ok(())
}

pub fn beq<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, target: u64) -> Flow<B> {
    let x = b.get(rs1.state());
    let y = b.get(rs2.state());
    let c = b.cmp(Cmp::Eq, x, y);
    b.branch(c, target);
    Ok(())
}

pub fn lw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, imm: i64) -> Flow<B> {
    let base = b.get(rs1.state());
    let off = b.konst::<W64>(imm as u64);
    let addr = b.add(base, off);
    let v = b.load::<W32>(addr, Access::DATA_LE)?;
    let v = b.sext::<W32, W64>(v);
    write_gpr(b, rd, v);
    Ok(())
}
```

`write_gpr` の中の `if rd.is_zero()` は、デコード時に決まる値による分岐なので Rust の `if` で書ける。`lw` のロードがページフォールトを起こした場合、`?` で退出し、`rd` は書き換えられない。
