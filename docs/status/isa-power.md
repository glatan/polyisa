# 実装状況：power

このファイルは `task status` が生成する。手で編集しない。

生成の元は `guests/power/spec/poweri.rs` である。

## CPU モデル

| 名前 | 親 | 足す機能 | 除く機能 |
|---|---|---|---|
| generic |  | fp、altivec、vsx |  |

## 機能

- altivec
- fp
- vsx

## 命令

| ニーモニック | 記述 | 条件 | タイミング |
|---|---|---|---|
| addi | addi | 真 | alu |
| addic | addic | 真 | alu |
| addic_rc | addic_rc | 真 | alu |
| addis | addis | 真 | alu |
| andi_rc | andi_rc | 真 | alu |
| andis_rc | andis_rc | 真 | alu |
| b | b | 真 | branch |
| bc | bc | 真 | branch |
| cmpli | cmpli | 真 | alu |
| cmpwi | cmpwi | 真 | alu |
| lbz | lbz | 真 | load |
| lbzu | lbzu | 真 | load |
| lfd | lfd | 真 | load |
| lfdu | lfdu | 真 | load |
| lfs | lfs | 真 | load |
| lfsu | lfsu | 真 | load |
| lha | lha | 真 | load |
| lhau | lhau | 真 | load |
| lhz | lhz | 真 | load |
| lhzu | lhzu | 真 | load |
| lmw | lmw | 真 | load |
| lwz | lwz | 真 | load |
| lwzu | lwzu | 真 | load |
| mulli | mulli | 真 | mult |
| ori | ori | 真 | alu |
| oris | oris | 真 | alu |
| rlwimi | rlwimi | 真 | alu |
| rlwinm | rlwinm | 真 | alu |
| rlwnm | rlwnm | 真 | alu |
| sc | sc | 真 | system |
| stb | stb | 真 | store |
| stbu | stbu | 真 | store |
| stfd | stfd | 真 | store |
| stfdu | stfdu | 真 | store |
| stfs | stfs | 真 | store |
| stfsu | stfsu | 真 | store |
| sth | sth | 真 | store |
| sthu | sthu | 真 | store |
| stmw | stmw | 真 | store |
| stw | stw | 真 | store |
| stwu | stwu | 真 | store |
| subfic | subfic | 真 | alu |
| tdi | tdi | 真 | system |
| twi | twi | 真 | system |
| x19 | x19 | 真 | branch |
| x30 | x30 | 真 | alu |
| x31 | x31 | 真 | alu |
| x4 | x4 | 真 | vsx |
| x56 | x56 | 真 | load |
| x58 | x58 | 真 | load |
| x59 | x59 | 真 | fp |
| x60 | x60 | 真 | vsx |
| x61 | x61 | 真 | vsx |
| x62 | x62 | 真 | store |
| x63 | x63 | 真 | fp |
| xori | xori | 真 | alu |
| xoris | xoris | 真 | alu |
