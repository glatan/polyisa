# 実装状況：mips

このファイルは `task status` が生成する。手で編集しない。

生成の元は `guests/mips/spec/mipsi.rs` である。

## CPU モデル

| 名前 | 親 | 足す機能 | 除く機能 |
|---|---|---|---|
| r3000 |  | mips1 |  |
| r6 |  | mips1、mips_r6 |  |

## 機能

- mips1
- mips_r6

## 命令

| ニーモニック | 記述 | 条件 | タイミング |
|---|---|---|---|
| addi | addi | !mips_r6 | alu |
| addiu | addiu | 真 | alu |
| addu | addu | 真 | alu |
| and | and | 真 | alu |
| beq | beq | 真 | branch |
| beqzalc | beqzalc | mips_r6 | branch |
| div | div | !mips_r6 | div |
| divu | divu | !mips_r6 | div |
| j | j | 真 | jump |
| lw | lw | 真 | load |
| mfhi | mfhi | !mips_r6 | alu |
| mflo | mflo | !mips_r6 | alu |
| mthi | mthi | !mips_r6 | alu |
| mtlo | mtlo | !mips_r6 | alu |
| mult | mult | !mips_r6 | mult |
| multu | multu | !mips_r6 | mult |
| or | or | 真 | alu |
| sll | sll | 真 | alu |
| subu | subu | 真 | alu |
| sw | sw | 真 | store |
