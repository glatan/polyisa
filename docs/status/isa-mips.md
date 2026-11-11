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
| add | add | 真 | alu |
| addi | addi | !mips_r6 | alu |
| addiu | addiu | 真 | alu |
| addu | addu | 真 | alu |
| and | and | 真 | alu |
| andi | andi | 真 | alu |
| beq | beq | !mips_r6 | branch |
| beqzalc | beqzalc | mips_r6 | branch |
| bgez | bgez | !mips_r6 | branch |
| bgezal | bgezal | !mips_r6 | branch |
| bgtz | bgtz | !mips_r6 | branch |
| blez | blez | !mips_r6 | branch |
| bltz | bltz | !mips_r6 | branch |
| bltzal | bltzal | !mips_r6 | branch |
| bne | bne | !mips_r6 | branch |
| break | break | 真 | system |
| div | div | !mips_r6 | div |
| divu | divu | !mips_r6 | div |
| j | j | !mips_r6 | jump |
| jal | jal | !mips_r6 | jump |
| jalr | jalr | 真 | jump |
| jr | jr | !mips_r6 | jump |
| lb | lb | 真 | load |
| lbu | lbu | 真 | load |
| lh | lh | 真 | load |
| lhu | lhu | 真 | load |
| lui | lui | 真 | alu |
| lw | lw | 真 | load |
| lwl | lwl | !mips_r6 | load |
| lwr | lwr | !mips_r6 | load |
| mfhi | mfhi | !mips_r6 | alu |
| mflo | mflo | !mips_r6 | alu |
| mthi | mthi | !mips_r6 | alu |
| mtlo | mtlo | !mips_r6 | alu |
| mult | mult | !mips_r6 | mult |
| multu | multu | !mips_r6 | mult |
| nor | nor | 真 | alu |
| or | or | 真 | alu |
| ori | ori | 真 | alu |
| sb | sb | 真 | store |
| sh | sh | 真 | store |
| sll | sll | 真 | alu |
| sllv | sllv | 真 | alu |
| slt | slt | 真 | alu |
| slti | slti | 真 | alu |
| sltiu | sltiu | 真 | alu |
| sltu | sltu | 真 | alu |
| sra | sra | 真 | alu |
| srav | srav | 真 | alu |
| srl | srl | 真 | alu |
| srlv | srlv | 真 | alu |
| sub | sub | 真 | alu |
| subu | subu | 真 | alu |
| sw | sw | 真 | store |
| swl | swl | !mips_r6 | store |
| swr | swr | !mips_r6 | store |
| syscall | syscall | 真 | system |
| xor | xor | 真 | alu |
| xori | xori | 真 | alu |
