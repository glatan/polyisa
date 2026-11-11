# 実装状況：wasm

このファイルは `task status` が生成する。手で編集しない。

生成の元は `guests/wasm/spec/wasmmin.rs` である。

## CPU モデル

| 名前 | 親 | 足す機能 | 除く機能 |
|---|---|---|---|
| generic |  | mvp |  |

## 機能

- mvp

## 命令

| ニーモニック | 記述 | 条件 | タイミング |
|---|---|---|---|
| br | br | 真 | branch |
| drop | drop | 真 | alu |
| i32.add | i32_add | 真 | alu |
| i32.const | i32_const | 真 | alu |
| local.get | local_get | 真 | alu |
| local.set | local_set | 真 | alu |
| nop | nop | 真 | alu |
| unreachable | unreachable | 真 | trap |
