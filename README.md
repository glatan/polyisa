# polyisa

polyisa は、多数の CPU アーキテクチャのユーザープログラムを実行するエミュレータである。Rust で実装し、外部クレートに依存しない。

- 対象の ISA：x86（16/32/64 ビット）、ARM、AArch64、MIPS、RISC-V、Power、s390 系、WebAssembly、および 68k、VAX、PDP-11、SPARC、Alpha、PA-RISC、SuperH、LoongArch、OpenRISC、IA-64、Hexagon
- ISA のバージョン、拡張、CPU の世代を CPU モデルとして区別し、実行時に選ぶ
- ユーザーモードのエミュレーション。OS のサービスはプロセス内の仮想カーネルが提供する
- インタプリタから始め、同じ命令意味論から JIT を後で追加する
- CPU モデルごとに宣言した忠実度で、命令の実行サイクルを数える

## 状態

設計段階である。実装はまだない。

## 文書

設計は [docs/](docs/README.md) にある。最初に [設計概要](docs/design/overview.md) を読み、続きは [文書の一覧](docs/README.md) の順に読む。開発作業の手順は [開発作業とローカル検証](docs/design/dev-workflow.md) にある。

## ライセンス

未定である。ライセンスが決まるまでの扱いは [ADR-0009](docs/adr/0009-no-code-reuse-until-license.md) にある。参照する資料と外部のツールの利用条件は [参照資料の台帳](docs/references.md) で管理する。
