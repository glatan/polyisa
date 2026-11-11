# 実装状況：sparc

このファイルは `task status` が生成する。手で編集しない。

生成の元は `guests/sparc/spec/sparcv8.rs` である。

## CPU モデル

| 名前 | 親 | 足す機能 | 除く機能 |
|---|---|---|---|
| generic |  | v8 |  |

## 機能

- v8

## 命令

| ニーモニック | 記述 | 条件 | タイミング |
|---|---|---|---|
| add | add | 真 | alu |
| and | and | 真 | alu |
| ba | ba | 真 | branch |
| jmpl | jmpl | 真 | jump |
| ld | ld | 真 | load |
| or | or | 真 | alu |
| sethi | sethi | 真 | alu |
| sll | sll | 真 | alu |
| st | st | 真 | store |
| sub | sub | 真 | alu |
