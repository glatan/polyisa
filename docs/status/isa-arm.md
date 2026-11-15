# 実装状況：arm

このファイルは `task status` が生成する。手で編集しない。

生成の元は `guests/arm/spec/armi.rs` である。

## CPU モデル

| 名前 | 親 | 足す機能 | 除く機能 |
|---|---|---|---|
| armv5 |  |  |  |
| armv7 |  | v7 |  |

## 機能

- v7

## 命令

| ニーモニック | 記述 | 条件 | タイミング |
|---|---|---|---|
| b | b | 真 | branch |
| bl | bl | 真 | branch |
| blx_imm | blx_imm | 真 | branch |
| cp2_dp | cp2_dp | 真 | fp |
| cp2_ls | cp2_ls | 真 | fp |
| cp_dp | cp_dp | 真 | fp |
| cp_ls | cp_ls | 真 | fp |
| dp_imm | dp_imm | 真 | alu |
| dp_reg | dp_reg | 真 | alu |
| dp_sreg | dp_sreg | 真 | alu |
| els_d | els_d | 真 | load |
| els_h | els_h | 真 | load |
| excl | excl | 真 | load |
| ldm_stm | ldm_stm | 真 | load |
| ls_imm | ls_imm | 真 | load |
| ls_reg | ls_reg | 真 | load |
| media | media | 真 | alu |
| mul | mul | 真 | mult |
| mull | mull | 真 | mult |
| svc | svc | 真 | system |
| swp | swp | 真 | store |
| uncond_hint | uncond_hint | 真 | system |
