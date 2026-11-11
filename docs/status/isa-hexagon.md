# 実装状況：hexagon

このファイルは `task status` が生成する。手で編集しない。

生成の元は `guests/hexagon/spec/hexmin.rs` である。

## CPU モデル

| 名前 | 親 | 足す機能 | 除く機能 |
|---|---|---|---|
| generic |  | v73 |  |

## 機能

- v73

## 命令

| ニーモニック | 記述 | 条件 | タイミング |
|---|---|---|---|
| add | add | 真 | alu |
| and | and | 真 | alu |
| jump | jump | 真 | jump |
| mov_imm | mov_imm | 真 | alu |
| or | or | 真 | alu |
| sub | sub | 真 | alu |
