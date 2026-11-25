# CPU モデルとバージョンの表現

同じ ISA ファミリ内の世代差、拡張の有無、ベンダー差は、すべて実行時に選択できる CPU モデルとして表現する。

## 5 種類の差と表現手段

| 差の種類 | 例 | 表現手段 |
|---|---|---|
| 命令の有無 | SSE2 の有無、MIPS R6 で削除された命令、VAX サブセット | 機能フラグ（`Feature`） |
| 同一符号化の意味の違い | x86 の `0F 05`、MIPS R6 の再割当て、RV32/RV64 の圧縮命令 | `when` 述語を条件とする別命令の宣言 |
| 同一命令の振る舞いの違い | x86 `BSF` の入力 0、PDP-11 付録 B のモデル差 | 挙動パラメータ（`Param`） |
| 識別情報 | x86 の CPUID、Alpha の `AMASK`/`IMPLVER`、LoongArch の `CPUCFG` | モデルの `ident` と機能からの `IDENT_BITS` 導出 |
| 実行時間 | レイテンシ、パイプライン構成、キャッシュ構成 | モデルの `timing` 宣言とタイミング表 |

この設計では、ISA のバージョン自体を特別な概念にしない。たとえば MIPS32 Release 2 や x86-64-v3 は、基準となる機能集合へ機能を追加・削除したモデル／プロファイルとして表現する。RV32 と RV64、MIPS32 と MIPS64 のようなアドレス幅の違いも、クレートを分けず機能フラグとして扱う。

## 機能とモデル継承

### 機能（`Feature`）

機能は ISA ごとに `Model.features` に宣言し、`isagen` が `FEATURE_DEFS` とビット位置定数 `FEAT_BITS` を生成する。機能同士の関係は次の二つで宣言する。

- `implies`：ある機能を有効にすると前提機能が自動的に有効になる（例：`lm` が `sse2`・`cmov` 等を含意）。
- `conflicts`：同時に有効にできない機能対を宣言する（例：`rv64` と `rv32`、PDP-11 の `fis` と `fp11`）。

実行時の機能解決（`polyisa_isadl::select::resolve`）は、指定されたモデルの親連鎖から機能集合を組み立て、`+機能`/`-機能` を反映したうえで `implies` 閉包を計算し、`conflicts` 違反があれば実行開始前にエラーで拒否する。

### CPU モデル（`ModelDef`）

CPU モデルは親（別のモデルまたは基準プロファイル）を一つ持ち、機能の追加・削除、挙動パラメータの上書き、識別情報（`ident`）、タイミング宣言（`timing`）を定義する。`polyisa cpus` は `MODELS` と `MODEL_TIMING` から利用可能なモデルとタイミング忠実度を表示する（未較正の `approx_uncalibrated` には `（未較正）` を添える）。

## 挙動パラメータ

ISA 仕様が未定義・実装定義とする振る舞いや世代固有の細かな差は、`Model::param` で型付きパラメータ（`Bool`・`Enum`・`Int`）として宣言する。

`isagen` は各ゲストに `Params` 構造体、列挙子定数、`DEFAULT_PARAMS`、親連鎖を解決済みの `model_params`、`Backend::param` 用のマーカー型、およびバックエンドへ値を流し込む `install_params` を生成する。`InterpBackend` と `IrBackend` はパラメータ型を鍵とする値表を持ち、意味論が `b.param::<P>()` で参照する。IR 記録時は定数として畳み込まれるため、JIT 生成コードに分岐を残さない。

## モデル差をデコード時に解決する方針

CPU モデルはゲストプロセスの実行中に変わらないため、命令実行ごとの分岐を避けてデコード時に一度だけ解決する方針を採っている。

1. **命令の有無と符号化の意味差**：デコーダ（`decode_model_ex`・`decode_map`）が解決済みの機能ビット集合 `feats` に対して `when` 述語を評価し、モデルにない命令は未定義命令として扱う。
2. **意味論内部の細かな振る舞い差**：挙動パラメータをバックエンド経由で読み出す。IR/JIT では定数畳み込みされる。

なお、命令単位で意味論関数ごと切り替える `sem match param.X` のデコード時切替、`--cpu` からの `param=値` 上書き構文、`guest::FeatureSet`/`CpuModel` との統合は未接続のまま残っている（[GAP-0027](../known-issues.md)）。

## 識別情報の導出

x86 の CPUID のように機能の有無をビットで報告する識別情報は、モデルの `ident`（ベンダー名・ファミリ・ステッピング等の固定値）と `IDENT_BITS`（機能フラグ → リーフ/サブリーフ/レジスタ/ビットの対応）に分離し、実行時に機能集合から導出する（例：x86 の `cpuid::derive`）。これにより、利用者が `--cpu` で機能を足し引きしても、ゲストが観測する識別情報と実行可能な命令が食い違わない。

## 実行時の選択（`--cpu`）

`polyisa run` では次の形式で CPU モデルを指定する（解析は `crates/cli/src/lib.rs` の `CpuSpec`）。

```text
--cpu <ISA ファミリ>:<CPU モデル>[,+<機能>][,-<機能>]
```

例：

```text
polyisa run --cpu x86:pentium_pro ./prog
polyisa run --cpu riscv:sifive_u74 ./prog
polyisa run --cpu pdp11:pdp11_70 ./a.out
```

`--cpu` を省略した場合、ELF バイナリではヘッダの `e_machine`・`EI_CLASS`・`e_flags` から既定モデルを自動選択する。a.out（PDP-11・VAX）はマジック番号だけでは ISA を一意に判定できないため、`--cpu pdp11:...` または `--cpu vax:...` の指定を要求する。ELF の要求機能と CPU モデルの不一致は実行拒否にせず、実機同様に未定義命令例外として再現する。
