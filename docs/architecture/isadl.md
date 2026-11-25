# ISA 記述とコード生成（ISADL / isagen）

polyisa は、19 の ISA が持つ命令エンコーディング、オペランド、アセンブリ構文、機能集合、CPU モデル、挙動パラメータ、識別情報を `polyisa-isadl` の Rust モデル（`Model`）として一箇所に記述し、`polyisa-isagen` がビルド時に Rust コードを生成する。

## Rust DSL を記述面とする理由

各ゲスト ISA クレートの記述は `guests/<isa>/spec/*.rs` に置き、`build.rs` が `include!` で取り込んで `build_model() -> polyisa_isadl::Model` を実行する。

専用の `.isadl` テキスト言語とパーサを持たず Rust DSL を正規の記述面とした理由は、次の三点にある。

- 字句解析・構文解析・エラー表示といった言語処理系の実装と保守を省ける。記述ミスは `rustc` の型検査で即座に検出される。
- 命令の静的事実を 1 箇所に集約し、デコーダ・エンコーダ・逆アセンブラ・モデル表を単一ソースから生成してデコード一意性を静的検査するという目的を十分に満たす。
- 外部の機械可読仕様から変換器を書く場合も、テキスト構文を経由せず `Model` を組み立てる Rust コードを直接出力すれば済む。

命令意味論、複雑なヘルパー、CPU 状態の構造体、および可変長オペランドの複雑な手続き（m68k の実効アドレス、VAX・PDP-11 のオペランド指定子、x86 の ModRM/SIB 等）は Rust の通常コードとして実装する。

## `isadl::Model` の構成要素

`crates/isadl/src/model.rs` が定義する `Model` は、以下の要素を保持する。

| 要素 | 役割 |
|---|---|
| `isa: Option<Isa>` | ISA 名とフェッチ単位（`parcel_bits`） |
| `modes: Vec<Mode>` | 実行モード（`Bool` または `Enum`）。x86 の `m64`/`o16`/`o32`/`a16`/`a32`/`a64` 等 |
| `regclasses: Vec<RegClass>` | レジスタクラス名、動的参照フラグ（`dynamic`）、逆アセンブル接頭辞 |
| `fields: Vec<Field>` | フィールド抽出定義。単一ビット範囲（`Bits`）、連結＋下位 0 詰め（`Parts`）、Rust フック（`Hook`） |
| `formats: Vec<Format>` | 複数命令で共有するフィールド群と `Operand`（名前、フィールド名、レジスタクラス、読み書き種別） |
| `insns: Vec<Insn>` | ビットパターン照合型の命令（形式、`Pattern`、`when` 述語、`wheres` 制約、構文テンプレート、タイミング分類） |
| `maps: Vec<MapDecl>` | バイト値キーのオペコード表（x86 用）。接頭辞条件（`PfxSel`）、ModRM グループ（`/0`〜`/7`・`group_rm`）、VEX/EVEX/APX 昇格形（`promoted`・`ndd_req`・`zu`・`nf_ok`）、3DNow! の `postop`、REX2 の `rex2_map1` を表現する |
| `features: Vec<Feature>` | 機能名、`implies`（含意）、`conflicts`（排他） |
| `params: Vec<Param>` | 挙動パラメータ（`Bool`・`Enum`・`Int`）と既定値・説明 |
| `models: Vec<ModelDef>` | CPU モデル定義（親、機能追加・削除、パラメータ上書き、識別情報 `ident`、タイミング宣言 `timing`） |
| `ident_bits: Vec<IdentBit>` | 機能フラグから識別情報ビット（CPUID リーフ/サブリーフ/レジスタ/ビット位置）への対応 |
| `timing_classes: Vec<String>` | タイミング分類の宣言一覧 |

### 述語（`when`）とフィールド制約（`where`）

同じビットパターンが CPU モデルやフィールド値によって異なる命令になる場合、`when` と `where` で区別する。

- **`when: Pred`**：機能フラグや実行モードの論理式（`Flag`・`Not`・`All`・`Any`）。RISC-V の RV32/RV64 間の符号化重複（`C.FLW` と `C.LD` 等）や、MIPS Release 6 でのオペコード再割当てを区別する。
- **`wheres: Vec<WhereClause>`**：デコード後のフィールド値に対する比較制約（`Eq`・`Ne`・`Lt`・`Le`・`Gt`・`Ge`）。右辺には定数（`Lit`）だけでなく同一形式の別フィールド（`Field`）も指定でき、RISC-V C 拡張の JR 群や MIPS R6 のコンパクト分岐（`rs >= rt` 等）を記述できる。

## 静的検査（`isadl::validate`）

`isagen::generate` はコード生成の前に必ず `polyisa_isadl::validate` を実行し、エラーがあればビルドを失敗させる。主な検査項目は次のとおりである。

- **デコードの一意性**：固定ビットパターンが重なりうる命令の組について、`when` が `conflicts` により両立しないか、`wheres` が同一フィールド（またはフィールド対）に矛盾する制約を持つ場合に限り重複を許す。
- **参照整合性**：命令が参照する形式・フィールド・機能・実行モード・タイミング分類、およびモデルが参照する親・機能・パラメータ・列挙子の存在と型整合を検査する。
- **フィールド整合性**：ビット幅の整合と固定ビットとの非重複、およびエンコード逆変換の可否を検査する。

## `isagen` の生成物と現行の範囲

`isagen::generate` は `Generated` 構造体として次の 7 種類の Rust ソースを生成し、各ゲストクレートの `build.rs` が `OUT_DIR` に書き出す。

| 生成物 | 主な内容 |
|---|---|
| `insn_type` | `pub enum Insn`（パターン命令および `map` 命令の全列挙子） |
| `decoder` | ビットパターン命令の線形デコーダ（`decode`・`decode_model_ex` 等） |
| `map_decoder` | `maps` を持つ ISA（x86）向けのバイト列デコーダ（`decode_map`） |
| `disassembler` | 構文テンプレートによる逆アセンブル関数（`disasm_word` 等） |
| `encoder` | フィールド逆変換による `encode_*` 関数と、エンコード→デコード往復検証表（`ENCODE_ROUNDTRIP`） |
| `operands` | フィールド抽出関数（`extract_ops`・型付き `ops_*`） |
| `metadata` | `MODELS`・`MODEL_DEFS`・`FEATURE_DEFS`・`FEAT_BITS`・`IDENT_BITS`・`MODEL_TIMING`、および `Params` 構造体・`DEFAULT_PARAMS`・`model_params`・`Backend::param` マーカー型・`install_params` |

生成物は `task isagen:dump ISA=<isa>` で手元に書き出して確認できる。

### 現行の生成範囲の制限

次の生成物はまだ実装されておらず、各ゲスト側で手書きまたは線形比較のままになっている（[GAP-0023](../known-issues.md)）。

- デコーダは全命令との線形比較であり、決定木やバイト表への最適化はない。
- 意味論関数への自動ディスパッチ表は生成せず、各ゲストの `sem` や `cli` が手書き `match` で振り分ける。
- 命令属性表（分岐・メモリアクセス・実行ユニット等）、オペランドの読み書き表、レジスタ記述表（`offset_of!` や GDB 番号を含む）、実行モード表は生成していない。
- `disasm_word` は `map` 経路の命令をまだ返さない。
