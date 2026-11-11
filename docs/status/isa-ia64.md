# 実装状況：ia64

このファイルは `task status` が生成する。手で編集しない。

生成の元は `guests/ia64/spec/ia64min.rs` である。

## CPU モデル

| 名前 | 親 | 足す機能 | 除く機能 |
|---|---|---|---|
| generic |  | itanium |  |

## 機能

- itanium

## 命令

| ニーモニック | 記述 | 条件 | タイミング |
|---|---|---|---|
| add | add、add_pred | 真 | alu |
| add.rot | add_rot | 真 | alu |
| br | br | 真 | branch |
| nop | nop | 真 | alu |
| sub | sub | 真 | alu |
