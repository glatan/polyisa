# Alpha

## 概要と対応範囲

Alpha 21064〜21364 と拡張（BWX・FIX・CIX・MVI）を対象とし、整数 Operate・乗除・ロード／ストア（非整列を含む）・分岐・IEEE 浮動小数点一式を `guests/alpha` で実装している。`AMASK` と `IMPLVER` はモデル識別情報として返す。

- **CPU モデル**：`21064`、`21164`、`21164pc`、`21264`、`21264a`、`21364`（計 6 モデル）。

## 対応する OS・ABI と実行環境

- **Linux（`os-linux::alpha`）**：Alpha Linux ABI（8 KiB ページ、OSF errno・定数差を反映）。`CALL_PAL`（`callsys`・`rduniq`/`wruniq`）を Linux パーソナリティが処理し、`os-linux::sock`・`os-linux::wait` 正準層を接続済み。

## 実装の構造と特記事項

`guests/alpha/spec/alpha.rs` に 32 ビット固定長命令を記述し、`isagen` が生成する型付きオペランド抽出関数（`ops_*`）を `sem.rs` で使用している。

## 既知の簡略化と未対応範囲

- **CPU モデルの世代対応の誤り**：`21264`（EV6）が `cix` を持つが、CIX は 21264A（EV67）で追加された拡張である。`21264a` は追加機能を持たない空のモデルになっており、EV56（21164A。BWX を持ち MVI を持たない）は現行の世代列では表現できない。いずれも CPU モデル追加作業で世代対応を正す。
- **浮動小数点の未実装・簡略化**：
  - VAX F/G 形式命令（`ldf`/`ldg`/`stf`/`stg`、opcode `0x15` 群、`sqrtf`/`sqrtg`、`itoff`）は未実装で `Ok(false)` を返す（`softfloat::decfp` との接続は未着手）。
  - `/s`（ソフトウェア完了）・`/i`（inexact）修飾の例外モデルと FPCR 例外集約ビット更新は未実装（`mf_fpcr`/`mt_fpcr` はレジスタ読み書きのみ）。
  - `/d` 動的丸めは `Backend` 経由で FPCR を読めないため最近接偶数丸めに近似している。
  - `cvttq` は飽和変換であり、仕様の modulo 変換（符号なし変換用途）と範囲外値で差がある。`CVTQL/V` はデコード対象外。
  - FEN はユーザー空間実行で 1 固定。
- **仕様上の未定義動作・例外の扱い**：`ITOF` 系で `Rb != R31` の未定義符号化も受理して実行する。`R31`/`F31` 宛てロードは prefetch として完全 no-op 扱い、整数オーバーフロー例外の内部コードは `1` 固定。
- **Linux ABI の簡略化**：単一プロセス模型（`fork`/`vfork`/`clone`/`exec`・`preadv`/`pwritev`/`mremap`/`rt_sigreturn`・`osf_select(93)` は `ENOSYS`）。`dup*` の fd 0–2 付け替えなし、`nanosleep` は実時間待機なし、`statfs*`/`sysinfo`/`times` は合成値、`getdents64` は `.`/`..` を含めない、`MAP_FIXED` は既存写像の単純置換、`/proc` 合成は `/proc/self/exe` と `/proc/self/fd/<fd>` の `readlink` のみ。

## 検証手段

- **OS なし・単体**：`bare_alpha`
- **ABI・プログラム**：`heavy_abi_alpha`（`syscall.tbl` 照合）、`heavy_program_alpha`
