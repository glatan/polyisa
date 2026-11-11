# 実装状況：riscv

このファイルは `task status` が生成する。手で編集しない。

生成の元は `guests/riscv/spec/rv64i.rs` である。

## CPU モデル

| 名前 | 親 | 足す機能 | 除く機能 |
|---|---|---|---|
| rv64gc |  | rv64、m、a、f、d、c、zicsr、zifencei |  |
| rv64imac | rv64gc |  | f、d |

## 機能

- a
- c
- d
- f
- m
- rv32
- rv64
- zicsr
- zifencei

## 命令

| ニーモニック | 記述 | 条件 | タイミング |
|---|---|---|---|
| add | add | 真 | alu |
| addi | addi | 真 | alu |
| addiw | addiw | rv64 | alu |
| addw | addw | rv64 | alu |
| amoadd_d | amoadd_d | rv64 | atomic |
| amoadd_w | amoadd_w | 真 | atomic |
| amoand_d | amoand_d | rv64 | atomic |
| amoand_w | amoand_w | 真 | atomic |
| amomax_d | amomax_d | rv64 | atomic |
| amomax_w | amomax_w | 真 | atomic |
| amomaxu_d | amomaxu_d | rv64 | atomic |
| amomaxu_w | amomaxu_w | 真 | atomic |
| amomin_d | amomin_d | rv64 | atomic |
| amomin_w | amomin_w | 真 | atomic |
| amominu_d | amominu_d | rv64 | atomic |
| amominu_w | amominu_w | 真 | atomic |
| amoor_d | amoor_d | rv64 | atomic |
| amoor_w | amoor_w | 真 | atomic |
| amoswap_d | amoswap_d | rv64 | atomic |
| amoswap_w | amoswap_w | 真 | atomic |
| amoxor_d | amoxor_d | rv64 | atomic |
| amoxor_w | amoxor_w | 真 | atomic |
| and | and | 真 | alu |
| andi | andi | 真 | alu |
| auipc | auipc | 真 | alu |
| beq | beq | 真 | branch |
| bge | bge | 真 | branch |
| bgeu | bgeu | 真 | branch |
| blt | blt | 真 | branch |
| bltu | bltu | 真 | branch |
| bne | bne | 真 | branch |
| c.add | c_add | 真 | alu |
| c.addi | c_addi | 真 | alu |
| c.addi4spn | c_addi4spn | 真 | alu |
| c.addiw | c_addiw | rv64 | alu |
| c.addw | c_addw | 真 | alu |
| c.and | c_and | 真 | alu |
| c.andi | c_andi | 真 | alu |
| c.beqz | c_beqz | 真 | branch |
| c.bnez | c_bnez | 真 | branch |
| c.ebreak | c_ebreak | 真 | system |
| c.fld | c_fld | 真 | load |
| c.fldsp | c_fldsp | 真 | load |
| c.flw | c_flw | rv32 | load |
| c.flwsp | c_flwsp | rv32 | load |
| c.fsd | c_fsd | 真 | store |
| c.fsdsp | c_fsdsp | 真 | store |
| c.fsw | c_fsw | rv32 | store |
| c.fswsp | c_fswsp | rv32 | store |
| c.j | c_j | 真 | jump |
| c.jal | c_jal | !rv64 | jump |
| c.jalr | c_jalr | 真 | jump |
| c.jr | c_jr | 真 | jump |
| c.ld | c_ld | rv64 | load |
| c.ldsp | c_ldsp | rv64 | load |
| c.li | c_li | 真 | alu |
| c.lui/addi16sp | c_lui_addi16sp | 真 | alu |
| c.lw | c_lw | 真 | load |
| c.lwsp | c_lwsp | 真 | load |
| c.mv | c_mv | 真 | alu |
| c.or | c_or | 真 | alu |
| c.sd | c_sd | rv64 | store |
| c.sdsp | c_sdsp | rv64 | store |
| c.slli | c_slli | 真 | alu |
| c.srai | c_srai | 真 | alu |
| c.srli | c_srli | 真 | alu |
| c.sub | c_sub | 真 | alu |
| c.subw | c_subw | 真 | alu |
| c.sw | c_sw | 真 | store |
| c.swsp | c_swsp | 真 | store |
| c.xor | c_xor | 真 | alu |
| csrrc | csrrc | 真 | system |
| csrrci | csrrci | 真 | system |
| csrrs | csrrs | 真 | system |
| csrrsi | csrrsi | 真 | system |
| csrrw | csrrw | 真 | system |
| csrrwi | csrrwi | 真 | system |
| div | div | 真 | div |
| divu | divu | 真 | div |
| divuw | divuw | rv64 | div |
| divw | divw | rv64 | div |
| ebreak | ebreak | 真 | system |
| ecall | ecall | 真 | system |
| fadd.d | fadd_d | 真 | fpu |
| fadd.s | fadd_s | 真 | fpu |
| fclass.d | fclass_d | 真 | fpu |
| fclass.s | fclass_s | 真 | fpu |
| fcvt.d.l | fcvt_d_l | 真 | fpu |
| fcvt.d.lu | fcvt_d_lu | 真 | fpu |
| fcvt.d.s | fcvt_d_s | 真 | fpu |
| fcvt.d.w | fcvt_d_w | 真 | fpu |
| fcvt.d.wu | fcvt_d_wu | 真 | fpu |
| fcvt.l.d | fcvt_l_d | 真 | fpu |
| fcvt.l.s | fcvt_l_s | 真 | fpu |
| fcvt.lu.d | fcvt_lu_d | 真 | fpu |
| fcvt.lu.s | fcvt_lu_s | 真 | fpu |
| fcvt.s.d | fcvt_s_d | 真 | fpu |
| fcvt.s.l | fcvt_s_l | 真 | fpu |
| fcvt.s.lu | fcvt_s_lu | 真 | fpu |
| fcvt.s.w | fcvt_s_w | 真 | fpu |
| fcvt.s.wu | fcvt_s_wu | 真 | fpu |
| fcvt.w.d | fcvt_w_d | 真 | fpu |
| fcvt.w.s | fcvt_w_s | 真 | fpu |
| fcvt.wu.d | fcvt_wu_d | 真 | fpu |
| fcvt.wu.s | fcvt_wu_s | 真 | fpu |
| fdiv.d | fdiv_d | 真 | fpu |
| fdiv.s | fdiv_s | 真 | fpu |
| fence | fence | 真 | system |
| fence.i | fence_i | 真 | system |
| feq.d | feq_d | 真 | fpu |
| feq.s | feq_s | 真 | fpu |
| fld | fld | 真 | load |
| fle.d | fle_d | 真 | fpu |
| fle.s | fle_s | 真 | fpu |
| flt.d | flt_d | 真 | fpu |
| flt.s | flt_s | 真 | fpu |
| flw | flw | 真 | load |
| fmadd.d | fmadd_d | 真 | fpu |
| fmadd.s | fmadd_s | 真 | fpu |
| fmax.d | fmax_d | 真 | fpu |
| fmax.s | fmax_s | 真 | fpu |
| fmin.d | fmin_d | 真 | fpu |
| fmin.s | fmin_s | 真 | fpu |
| fmsub.d | fmsub_d | 真 | fpu |
| fmsub.s | fmsub_s | 真 | fpu |
| fmul.d | fmul_d | 真 | fpu |
| fmul.s | fmul_s | 真 | fpu |
| fmv.d.x | fmv_d_x | 真 | fpu |
| fmv.w.x | fmv_w_x | 真 | fpu |
| fmv.x.d | fmv_x_d | 真 | fpu |
| fmv.x.w | fmv_x_w | 真 | fpu |
| fnmadd.d | fnmadd_d | 真 | fpu |
| fnmadd.s | fnmadd_s | 真 | fpu |
| fnmsub.d | fnmsub_d | 真 | fpu |
| fnmsub.s | fnmsub_s | 真 | fpu |
| fsd | fsd | 真 | store |
| fsgnj.d | fsgnj_d | 真 | fpu |
| fsgnj.s | fsgnj_s | 真 | fpu |
| fsgnjn.d | fsgnjn_d | 真 | fpu |
| fsgnjn.s | fsgnjn_s | 真 | fpu |
| fsgnjx.d | fsgnjx_d | 真 | fpu |
| fsgnjx.s | fsgnjx_s | 真 | fpu |
| fsqrt.d | fsqrt_d | 真 | fpu |
| fsqrt.s | fsqrt_s | 真 | fpu |
| fsub.d | fsub_d | 真 | fpu |
| fsub.s | fsub_s | 真 | fpu |
| fsw | fsw | 真 | store |
| jal | jal | 真 | jump |
| jalr | jalr | 真 | jump |
| lb | lb | 真 | load |
| lbu | lbu | 真 | load |
| ld | ld | rv64 | load |
| lh | lh | 真 | load |
| lhu | lhu | 真 | load |
| lr_d | lr_d | rv64 | atomic |
| lr_w | lr_w | 真 | atomic |
| lui | lui | 真 | alu |
| lw | lw | 真 | load |
| lwu | lwu | rv64 | load |
| mul | mul | 真 | mult |
| mulh | mulh | 真 | mult |
| mulhsu | mulhsu | 真 | mult |
| mulhu | mulhu | 真 | mult |
| mulw | mulw | rv64 | mult |
| or | or | 真 | alu |
| ori | ori | 真 | alu |
| rem | rem | 真 | div |
| remu | remu | 真 | div |
| remuw | remuw | rv64 | div |
| remw | remw | rv64 | div |
| sb | sb | 真 | store |
| sc_d | sc_d | rv64 | atomic |
| sc_w | sc_w | 真 | atomic |
| sd | sd | rv64 | store |
| sh | sh | 真 | store |
| sll | sll | 真 | alu |
| slli | slli | 真 | alu |
| slliw | slliw | rv64 | alu |
| sllw | sllw | rv64 | alu |
| slt | slt | 真 | alu |
| slti | slti | 真 | alu |
| sltiu | sltiu | 真 | alu |
| sltu | sltu | 真 | alu |
| sra | sra | 真 | alu |
| srai | srai | 真 | alu |
| sraiw | sraiw | rv64 | alu |
| sraw | sraw | rv64 | alu |
| srl | srl | 真 | alu |
| srli | srli | 真 | alu |
| srliw | srliw | rv64 | alu |
| srlw | srlw | rv64 | alu |
| sub | sub | 真 | alu |
| subw | subw | rv64 | alu |
| sw | sw | 真 | store |
| xor | xor | 真 | alu |
| xori | xori | 真 | alu |
