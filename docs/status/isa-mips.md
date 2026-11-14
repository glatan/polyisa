# 実装状況：mips

このファイルは `task status` が生成する。手で編集しない。

生成の元は `guests/mips/spec/mipsi.rs` である。

## CPU モデル

| 名前 | 親 | 足す機能 | 除く機能 |
|---|---|---|---|
| mips32r2 |  | mips1、mips32r2、fpu |  |
| mips64r2 |  | mips1、mips32r2、mips64、fpu |  |
| mips64r6 |  | mips1、mips32r2、mips64、mips_r6、fpu |  |
| r3000 |  | mips1 |  |
| r6 |  | mips1、mips32r2、mips_r6、fpu |  |

## 機能

- fpu
- mips1
- mips32r2
- mips64
- mips_r6

## 命令

| ニーモニック | 記述 | 条件 | タイミング |
|---|---|---|---|
| abs.d | abs_d | fpu | alu |
| abs.s | abs_s | fpu | alu |
| add | add | !mips_r6 | alu |
| add.d | add_d | fpu | alu |
| add.s | add_s | fpu | alu |
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
| bc1f | bc1f | fpu | branch |
| bc1fl | bc1fl | fpu | branch |
| bc1t | bc1t | fpu | branch |
| bc1tl | bc1tl | fpu | branch |
| beq | beq | !mips_r6 | branch |
| beqc | beqc | mips_r6 | branch |
| beql | beql | !mips_r6 | branch |
| beqzalc | beqzalc | mips_r6 | branch |
| beqzc | beqzc | mips_r6 | branch |
| bgec | bgec | mips_r6 | branch |
| bgeuc | bgeuc | mips_r6 | branch |
| bgez | bgez | !mips_r6 | branch |
| bgezal | bgezal | !mips_r6 | branch |
| bgezalc | bgezalc | mips_r6 | branch |
| bgezall | bgezall | !mips_r6 | branch |
| bgezc | bgezc | mips_r6 | branch |
| bgezl | bgezl | !mips_r6 | branch |
| bgtz | bgtz | !mips_r6 | branch |
| bgtzalc | bgtzalc | mips_r6 | branch |
| bgtzc | bgtzc | mips_r6 | branch |
| bgtzl | bgtzl | !mips_r6 | branch |
| bitswap | bitswap | mips_r6 | alu |
| blez | blez | !mips_r6 | branch |
| blezalc | blezalc | mips_r6 | branch |
| blezc | blezc | mips_r6 | branch |
| blezl | blezl | !mips_r6 | branch |
| bltc | bltc | mips_r6 | branch |
| bltuc | bltuc | mips_r6 | branch |
| bltz | bltz | !mips_r6 | branch |
| bltzal | bltzal | !mips_r6 | branch |
| bltzalc | bltzalc | mips_r6 | branch |
| bltzall | bltzall | !mips_r6 | branch |
| bltzc | bltzc | mips_r6 | branch |
| bltzl | bltzl | !mips_r6 | branch |
| bne | bne | !mips_r6 | branch |
| bnec | bnec | mips_r6 | branch |
| bnel | bnel | !mips_r6 | branch |
| bnezalc | bnezalc | mips_r6 | branch |
| bnezc | bnezc | mips_r6 | branch |
| bnvc | bnvc | mips_r6 | branch |
| bovc | bovc | mips_r6 | branch |
| break | break | 真 | system |
| c.cond.d | ccond_d | fpu | alu |
| c.cond.s | ccond_s | fpu | alu |
| ceil_l.d | ceil_l_d | fpu | alu |
| ceil_l.s | ceil_l_s | fpu | alu |
| ceil_w.d | ceil_w_d | fpu | alu |
| ceil_w.s | ceil_w_s | fpu | alu |
| cfc1 | cfc1 | fpu | alu |
| clo | clo_r2 | mips32r2 && !mips_r6 | alu |
| clo | clo | mips_r6 | alu |
| clz | clz_r2 | mips32r2 && !mips_r6 | alu |
| clz | clz | mips_r6 | alu |
| ctc1 | ctc1 | fpu | alu |
| cvt.d.l | cvt_d_l | fpu | alu |
| cvt.d.s | cvt_d_s | fpu | alu |
| cvt.d.w | cvt_d_w | fpu | alu |
| cvt.l.d | cvt_l_d | fpu | alu |
| cvt.l.s | cvt_l_s | fpu | alu |
| cvt.l.w | cvt_l_w | fpu | alu |
| cvt.s.d | cvt_s_d | fpu | alu |
| cvt.s.l | cvt_s_l | fpu | alu |
| cvt.s.w | cvt_s_w | fpu | alu |
| cvt.w.d | cvt_w_d | fpu | alu |
| cvt.w.l | cvt_w_l | fpu | alu |
| cvt.w.s | cvt_w_s | fpu | alu |
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
| div.d | div_d | fpu | alu |
| div.s | div_s | fpu | alu |
| divu | divu | !mips_r6 | div |
| divu | divu_r6 | mips_r6 | div |
| dlsa | dlsa | mips_r6 && mips64 | alu |
| dmfc1 | dmfc1 | fpu | alu |
| dmod | dmod | mips_r6 && mips64 | div |
| dmodu | dmodu | mips_r6 && mips64 | div |
| dmtc1 | dmtc1 | fpu | alu |
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
| floor_l.d | floor_l_d | fpu | alu |
| floor_l.s | floor_l_s | fpu | alu |
| floor_w.d | floor_w_d | fpu | alu |
| floor_w.s | floor_w_s | fpu | alu |
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
| ldc1 | ldc1 | fpu | load |
| ldl | ldl | mips64 && !mips_r6 | load |
| ldpc | ldpc | mips_r6 && mips64 | load |
| ldr | ldr | mips64 && !mips_r6 | load |
| ldxc1 | ldxc1 | fpu | alu |
| lh | lh | 真 | load |
| lhu | lhu | 真 | load |
| ll | ll | mips32r2 && !mips_r6 | load |
| ll | ll_r6 | mips_r6 | load |
| lld | lld | mips64 && !mips_r6 | load |
| lld | lld_r6 | mips_r6 && mips64 | load |
| lle | lle | mips_r6 | load |
| llwp | llwp | mips_r6 | load |
| llwpe | llwpe | mips_r6 | load |
| lsa | lsa | mips_r6 | alu |
| lui | lui | 真 | alu |
| lw | lw | 真 | load |
| lwc1 | lwc1 | fpu | load |
| lwl | lwl | !mips_r6 | load |
| lwpc | lwpc | mips_r6 | load |
| lwr | lwr | !mips_r6 | load |
| lwu | lwu | mips64 | load |
| lwupc | lwupc | mips_r6 | load |
| lwxc1 | lwxc1 | fpu | alu |
| madd | madd | mips32r2 && !mips_r6 | mult |
| madd_d | madd_d | fpu | alu |
| madd_s | madd_s | fpu | alu |
| maddu | maddu | mips32r2 && !mips_r6 | mult |
| mfc1 | mfc1 | fpu | alu |
| mfhc1 | mfhc1 | fpu | alu |
| mfhi | mfhi | !mips_r6 | alu |
| mflo | mflo | !mips_r6 | alu |
| mod | mod_ | mips_r6 | div |
| modu | modu | mips_r6 | div |
| mov.d | mov_d | fpu | alu |
| mov.s | mov_s | fpu | alu |
| movcf.d | movcf_d | fpu | alu |
| movcf.s | movcf_s | fpu | alu |
| movn | movn | mips32r2 | alu |
| movn.d | movn_d | fpu | alu |
| movn.s | movn_s | fpu | alu |
| movz | movz | mips32r2 | alu |
| movz.d | movz_d | fpu | alu |
| movz.s | movz_s | fpu | alu |
| msub | msub | mips32r2 && !mips_r6 | mult |
| msub_d | msub_d | fpu | alu |
| msub_s | msub_s | fpu | alu |
| msubu | msubu | mips32r2 && !mips_r6 | mult |
| mtc1 | mtc1 | fpu | alu |
| mthc1 | mthc1 | fpu | alu |
| mthi | mthi | !mips_r6 | alu |
| mtlo | mtlo | !mips_r6 | alu |
| muh | muh | mips_r6 | mult |
| muhu | muhu | mips_r6 | mult |
| mul | mul_r2 | mips32r2 && !mips_r6 | mult |
| mul | mul | mips_r6 | mult |
| mul.d | mul_d | fpu | alu |
| mul.s | mul_s | fpu | alu |
| mult | mult | !mips_r6 | mult |
| multu | multu | !mips_r6 | mult |
| mulu | mulu | mips_r6 | mult |
| nal | nal | mips_r6 | branch |
| neg.d | neg_d | fpu | alu |
| neg.s | neg_s | fpu | alu |
| nmadd_d | nmadd_d | fpu | alu |
| nmadd_s | nmadd_s | fpu | alu |
| nmsub_d | nmsub_d | fpu | alu |
| nmsub_s | nmsub_s | fpu | alu |
| nor | nor | 真 | alu |
| or | or | 真 | alu |
| ori | ori | 真 | alu |
| pref | pref | mips32r2 | load |
| rdhwr | rdhwr | mips32r2 | system |
| recip.d | recip_d | fpu | alu |
| recip.s | recip_s | fpu | alu |
| round_l.d | round_l_d | fpu | alu |
| round_l.s | round_l_s | fpu | alu |
| round_w.d | round_w_d | fpu | alu |
| round_w.s | round_w_s | fpu | alu |
| rsqrt.d | rsqrt_d | fpu | alu |
| rsqrt.s | rsqrt_s | fpu | alu |
| sb | sb | 真 | store |
| sc | sc | mips32r2 && !mips_r6 | store |
| sc | sc_r6 | mips_r6 | store |
| scd | scd | mips64 && !mips_r6 | store |
| scd | scd_r6 | mips_r6 && mips64 | store |
| sce | sce | mips_r6 | store |
| scwp | scwp | mips_r6 | store |
| scwpe | scwpe | mips_r6 | store |
| sd | sd | mips64 | store |
| sdc1 | sdc1 | fpu | store |
| sdl | sdl | mips64 && !mips_r6 | store |
| sdr | sdr | mips64 && !mips_r6 | store |
| sdxc1 | sdxc1 | fpu | alu |
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
| sqrt.d | sqrt_d | fpu | alu |
| sqrt.s | sqrt_s | fpu | alu |
| sra | sra | 真 | alu |
| srav | srav | 真 | alu |
| srl | srl | 真 | alu |
| srlv | srlv | 真 | alu |
| sub | sub | !mips_r6 | alu |
| sub.d | sub_d | fpu | alu |
| sub.s | sub_s | fpu | alu |
| subu | subu | 真 | alu |
| sw | sw | 真 | store |
| swc1 | swc1 | fpu | store |
| swl | swl | !mips_r6 | store |
| swr | swr | !mips_r6 | store |
| swxc1 | swxc1 | fpu | alu |
| sync | sync | mips32r2 | system |
| synci | synci | mips32r2 | system |
| syscall | syscall | 真 | system |
| teq | teq | mips32r2 | system |
| trunc_l.d | trunc_l_d | fpu | alu |
| trunc_l.s | trunc_l_s | fpu | alu |
| trunc_w.d | trunc_w_d | fpu | alu |
| trunc_w.s | trunc_w_s | fpu | alu |
| wsbh | wsbh | mips32r2 | alu |
| xor | xor | 真 | alu |
| xori | xori | 真 | alu |
