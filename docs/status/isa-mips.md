# 実装状況：mips

このファイルは `task status` が生成する。手で編集しない。

生成の元は `guests/mips/spec/mipsi.rs` である。

## CPU モデル

| 名前 | 親 | 足す機能 | 除く機能 |
|---|---|---|---|
| mips32r2 |  | mips1、mips32r2 |  |
| mips64r2 |  | mips1、mips32r2、mips64 |  |
| mips64r6 |  | mips1、mips32r2、mips64、mips_r6 |  |
| r3000 |  | mips1 |  |
| r6 |  | mips1、mips32r2、mips_r6 |  |

## 機能

- mips1
- mips32r2
- mips64
- mips_r6

## 命令

| ニーモニック | 記述 | 条件 | タイミング |
|---|---|---|---|
| add | add | !mips_r6 | alu |
| addi | addi | !mips_r6 | alu |
| addiu | addiu | 真 | alu |
| addiupc | addiupc | mips_r6 | alu |
| addu | addu | 真 | alu |
| align | align | mips_r6 | alu |
| aluipc | aluipc | mips_r6 | alu |
| and | and | 真 | alu |
| andi | andi | 真 | alu |
| aui | aui | mips_r6 | alu |
| auipc | auipc | mips_r6 | alu |
| bal | bal | mips_r6 | branch |
| balc | balc | mips_r6 | jump |
| bc | bc | mips_r6 | jump |
| beq | beq | !mips_r6 | branch |
| beqc | beqc | mips_r6 | branch |
| beqzalc | beqzalc | mips_r6 | branch |
| beqzc | beqzc | mips_r6 | branch |
| bgec | bgec | mips_r6 | branch |
| bgeuc | bgeuc | mips_r6 | branch |
| bgez | bgez | !mips_r6 | branch |
| bgezal | bgezal | !mips_r6 | branch |
| bgezalc | bgezalc | mips_r6 | branch |
| bgezc | bgezc | mips_r6 | branch |
| bgtz | bgtz | !mips_r6 | branch |
| bgtzalc | bgtzalc | mips_r6 | branch |
| bgtzc | bgtzc | mips_r6 | branch |
| bitswap | bitswap | mips_r6 | alu |
| blez | blez | !mips_r6 | branch |
| blezalc | blezalc | mips_r6 | branch |
| blezc | blezc | mips_r6 | branch |
| bltc | bltc | mips_r6 | branch |
| bltuc | bltuc | mips_r6 | branch |
| bltz | bltz | !mips_r6 | branch |
| bltzal | bltzal | !mips_r6 | branch |
| bltzalc | bltzalc | mips_r6 | branch |
| bltzc | bltzc | mips_r6 | branch |
| bne | bne | !mips_r6 | branch |
| bnec | bnec | mips_r6 | branch |
| bnezalc | bnezalc | mips_r6 | branch |
| bnezc | bnezc | mips_r6 | branch |
| bnvc | bnvc | mips_r6 | branch |
| bovc | bovc | mips_r6 | branch |
| break | break | 真 | system |
| clo | clo_r2 | mips32r2 && !mips_r6 | alu |
| clo | clo | mips_r6 | alu |
| clz | clz_r2 | mips32r2 && !mips_r6 | alu |
| clz | clz | mips_r6 | alu |
| dadd | dadd | mips64 && !mips_r6 | alu |
| daddi | daddi | mips64 && !mips_r6 | alu |
| daddiu | daddiu | mips64 | alu |
| daddu | daddu | mips64 | alu |
| dahi | dahi | mips_r6 && mips64 | alu |
| dalign | dalign | mips_r6 && mips64 | alu |
| dati | dati | mips_r6 && mips64 | alu |
| daui | daui | mips_r6 && mips64 | alu |
| dbitswap | dbitswap | mips_r6 && mips64 | alu |
| dclo | dclo_r2 | mips64 && !mips_r6 | alu |
| dclo | dclo | mips_r6 && mips64 | alu |
| dclz | dclz_r2 | mips64 && !mips_r6 | alu |
| dclz | dclz | mips_r6 && mips64 | alu |
| ddiv | ddiv | mips64 && !mips_r6 | div |
| ddiv | ddiv_r6 | mips_r6 && mips64 | div |
| ddivu | ddivu | mips64 && !mips_r6 | div |
| ddivu | ddivu_r6 | mips_r6 && mips64 | div |
| dext | dext | mips64 | alu |
| dextm | dextm | mips64 | alu |
| dextu | dextu | mips64 | alu |
| dins | dins | mips64 | alu |
| dinsm | dinsm | mips64 | alu |
| dinsu | dinsu | mips64 | alu |
| div | div | !mips_r6 | div |
| div | div_r6 | mips_r6 | div |
| divu | divu | !mips_r6 | div |
| divu | divu_r6 | mips_r6 | div |
| dlsa | dlsa | mips_r6 && mips64 | alu |
| dmod | dmod | mips_r6 && mips64 | div |
| dmodu | dmodu | mips_r6 && mips64 | div |
| dmuh | dmuh | mips_r6 && mips64 | mult |
| dmuhu | dmuhu | mips_r6 && mips64 | mult |
| dmul | dmul | mips_r6 && mips64 | mult |
| dmult | dmult | mips64 && !mips_r6 | mult |
| dmultu | dmultu | mips64 && !mips_r6 | mult |
| dmulu | dmulu | mips_r6 && mips64 | mult |
| dsbh | dsbh | mips64 | alu |
| dshd | dshd | mips64 | alu |
| dsll | dsll | mips64 | alu |
| dsll32 | dsll32 | mips64 | alu |
| dsllv | dsllv | mips64 | alu |
| dsra | dsra | mips64 | alu |
| dsra32 | dsra32 | mips64 | alu |
| dsrav | dsrav | mips64 | alu |
| dsrl | dsrl | mips64 | alu |
| dsrl32 | dsrl32 | mips64 | alu |
| dsrlv | dsrlv | mips64 | alu |
| dsub | dsub | mips64 && !mips_r6 | alu |
| dsubu | dsubu | mips64 | alu |
| ext | ext | mips32r2 | alu |
| ins | ins | mips32r2 | alu |
| j | j | 真 | jump |
| jal | jal | 真 | jump |
| jalr | jalr | 真 | jump |
| jialc | jialc | mips_r6 | jump |
| jic | jic | mips_r6 | jump |
| jr | jr | 真 | jump |
| lb | lb | 真 | load |
| lbu | lbu | 真 | load |
| ld | ld | mips64 | load |
| ldl | ldl | mips64 && !mips_r6 | load |
| ldpc | ldpc | mips_r6 && mips64 | load |
| ldr | ldr | mips64 && !mips_r6 | load |
| lh | lh | 真 | load |
| lhu | lhu | 真 | load |
| ll | ll | mips32r2 && !mips_r6 | load |
| ll | ll_r6 | mips_r6 | load |
| lld | lld | mips64 && !mips_r6 | load |
| lld | lld_r6 | mips_r6 && mips64 | load |
| lsa | lsa | mips_r6 | alu |
| lui | lui | 真 | alu |
| lw | lw | 真 | load |
| lwl | lwl | !mips_r6 | load |
| lwpc | lwpc | mips_r6 | load |
| lwr | lwr | !mips_r6 | load |
| lwu | lwu | mips64 | load |
| lwupc | lwupc | mips_r6 | load |
| madd | madd | mips32r2 && !mips_r6 | mult |
| maddu | maddu | mips32r2 && !mips_r6 | mult |
| mfhi | mfhi | !mips_r6 | alu |
| mflo | mflo | !mips_r6 | alu |
| mod | mod_ | mips_r6 | div |
| modu | modu | mips_r6 | div |
| movn | movn | mips32r2 | alu |
| movz | movz | mips32r2 | alu |
| msub | msub | mips32r2 && !mips_r6 | mult |
| msubu | msubu | mips32r2 && !mips_r6 | mult |
| mthi | mthi | !mips_r6 | alu |
| mtlo | mtlo | !mips_r6 | alu |
| muh | muh | mips_r6 | mult |
| muhu | muhu | mips_r6 | mult |
| mul | mul_r2 | mips32r2 && !mips_r6 | mult |
| mul | mul | mips_r6 | mult |
| mult | mult | !mips_r6 | mult |
| multu | multu | !mips_r6 | mult |
| mulu | mulu | mips_r6 | mult |
| nal | nal | mips_r6 | branch |
| nor | nor | 真 | alu |
| or | or | 真 | alu |
| ori | ori | 真 | alu |
| pref | pref | mips32r2 | load |
| rdhwr | rdhwr | mips32r2 | system |
| sb | sb | 真 | store |
| sc | sc | mips32r2 && !mips_r6 | store |
| sc | sc_r6 | mips_r6 | store |
| scd | scd | mips64 && !mips_r6 | store |
| scd | scd_r6 | mips_r6 && mips64 | store |
| sd | sd | mips64 | store |
| sdl | sdl | mips64 && !mips_r6 | store |
| sdr | sdr | mips64 && !mips_r6 | store |
| seb | seb | mips32r2 | alu |
| seh | seh | mips32r2 | alu |
| seleqz | seleqz | mips_r6 | alu |
| selnez | selnez | mips_r6 | alu |
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
| sub | sub | !mips_r6 | alu |
| subu | subu | 真 | alu |
| sw | sw | 真 | store |
| swl | swl | !mips_r6 | store |
| swr | swr | !mips_r6 | store |
| sync | sync | mips32r2 | system |
| synci | synci | mips32r2 | system |
| syscall | syscall | 真 | system |
| teq | teq | mips32r2 | system |
| wsbh | wsbh | mips32r2 | alu |
| xor | xor | 真 | alu |
| xori | xori | 真 | alu |
