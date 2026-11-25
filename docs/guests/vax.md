# VAX

## 概要と対応範囲

VAX-11/780〜NVAX（MicroVAX サブセットを含む）のユーザーモード命令群（整数・論理・bitfield・分岐、`CALLS`/`CALLG`/`RET`、`PUSHR`/`POPR`、インターロックキュー、中断可能文字列命令、`CHM*`、F/D/G/H 浮動小数点と `POLY*`/`EMOD*`、パック十進・数値文字列・`EDITPC`、`INDEX`/`PROBER`/`PROBEW`）を `guests/vax` で実装している。

- **CPU モデル**：`vax11_780`、`microvax2`、`ka660`、`ka650`、`nvax`、`vax11_730`、`vax11_750`、`vax11_785`（計 8 モデル）。11/730–11/785 は詳細な実装群差が一次資料の確認待ちで、現状は 11/780 と同じ構成の器。サブセット機能フラグ（`decimal`・`hfp`・`string_ext`・`string_cmp`・`crc`・`editpc`・`compat`）で削られた命令は未実装補完経路へ渡る。
- **挙動パラメータ**：`emul_dispatch`（`hook` / `scb`）、`dv_hw`（KA660 での十進オーバーフロー扱い）。
- **タイミング**：VAX-11/780 の EBOX マイクロサイクル（200 ns）単位の専用モデル `timing::Vax780` を持つ（未較正の `approx_uncalibrated`）。

## 対応する OS・ABI と実行環境

- **4.3BSD-Reno（`os-bsd::vax`）**：a.out（OMAGIC/ZMAGIC、`a_entry + 2` 開始規約、`chmk` 規約）。`polyisa run --cpu vax:vax11_780 <a.out>` で実行できる（簡略化の一覧は [OS 層](../architecture/os-layer.md) を参照）。

## 実装の構造と特記事項

1 バイトまたは `0xFD`/`0xFE`/`0xFF` 接頭の 2 バイトオペコード語を生成デコーダで解き、続くオペランド指定子列（16 種のアドレッシングモード）の読み取り・長さ計算・再符号化・シグネチャ表を `guests/vax/src/specifier.rs` が担う。中断可能命令（文字列命令・`POLY*`・`EDITPC`）は 1 ステップ＝1 単位で `PSL<FPD>` を立てて再入し、進捗をアーキテクチャレジスタ（`r0`–`r5`）と最小限の作業領域に保持する。F/D/G/H 浮動小数点は `softfloat::decfp`、十進は `decimal` を使用する。

## 既知の簡略化と未対応範囲

- **特権命令と互換モード**：`REI`/`LDPCTX`/`SVPCTX`/`BUGW`/`BUGL` と PDP-11 互換モードは語彙宣言のみで意味論は未実装（`HALT` はユーザーモードで特権命令 fault、カーネル側で `Unimplemented`）。
- **意味論の近似**：
  - インターロックキュー（`INSQ*`/`REMQ*`）は単一スレッド前提でロック競合なし。中断可能文字列命令の中断粒度は 1 バイト単位、`POLY*` は 1 Horner 反復単位、十進算術（`EDITPC` を除く）は 1 ステップ完結の近似。
  - `CHM*` はモード別スタック切替を行わず単一 SP へコードを積んで SCB `0x40 + 4*mode` トラップとして OS パーソナリティへ委ねる。補完例外（SCB `0xC8`/`0xCC`）も指定子フレーム構築をパーソナリティ側へ委譲している。
  - `EDITPC` パターン演算子は主要 17 種に対応。十進演算の仕様上 `UNPREDICTABLE` 入力は決定的挙動へ正規化し、`DIVP` ゼロ除算は共用 `FLT_DIV_ZERO` を使う。
  - `PROBER`/`PROBEW` は両端バイトの読み出し可否で近似し、ページ保護・モード上限検査は省略している。
  - `nvax` と `ka650` の機能集合は一次資料の制約から近似定義を用いている。
- **4.3BSD 実行上の既知不具合**：`df -i` が D-float の reserved-operand fault を起こす（D-float 命令語彙側の残件）。
- **タイミングモデルの未較正**：`timing::Vax780` は Usenet の計測値をアンカーにした未較正近似であり、`vax11_780` 以外のモデル・キャッシュミス・例外時間は未モデル。

## 検証手段

- **OS なし・単体**：`bare_vax`（117 件）＋ lib 単体テスト
- **プログラム**：`heavy_program_bsdvax`（4.3BSD-Reno 配布物バイナリ）
