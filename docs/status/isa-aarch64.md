# 実装状況：aarch64

このファイルは `task status` が生成する。手で編集しない。

生成の元は `guests/aarch64/spec/a64i.rs` である。

## CPU モデル

| 名前 | 親 | 足す機能 | 除く機能 |
|---|---|---|---|
| generic |  | fp、asimd |  |
| generic_v81 | generic | lse |  |

## 機能

- asimd
- be
- fp
- lse

## 命令

| ニーモニック | 記述 | 条件 | タイミング |
|---|---|---|---|
| add | add_ext、add_imm、add_sh | 真 | alu |
| adds | adds_ext、adds_imm、adds_sh | 真 | alu |
| adr | adr | 真 | alu |
| adrp | adrp | 真 | alu |
| and | and_imm、and_sh | 真 | alu |
| ands | ands_imm、ands_sh | 真 | alu |
| asr | asrv | 真 | alu |
| b | b | 真 | branch |
| b.cond | b_cond | 真 | branch |
| bfm | bfm | 真 | alu |
| bic | bic_sh | 真 | alu |
| bics | bics_sh | 真 | alu |
| bl | bl | 真 | branch |
| blr | blr | 真 | branch |
| br | br | 真 | branch |
| brk | brk | 真 | system |
| cbnz | cbnz | 真 | branch |
| cbz | cbz | 真 | branch |
| ccmn | ccmn_imm、ccmn_reg | 真 | alu |
| ccmp | ccmp_imm、ccmp_reg | 真 | alu |
| cls | cls | 真 | alu |
| clz | clz | 真 | alu |
| csel | csel | 真 | alu |
| csinc | csinc | 真 | alu |
| csinv | csinv | 真 | alu |
| csneg | csneg | 真 | alu |
| dup | dup_gen | 真 | alu |
| eon | eon_sh | 真 | alu |
| eor | eor_imm、eor_sh | 真 | alu |
| extr | extr | 真 | alu |
| fccmp | fccmp | 真 | alu |
| fcmp | fcmp | 真 | alu |
| fcsel | fcsel | 真 | alu |
| fcvt | fcvt | 真 | alu |
| fcvta | fcvt_a | 真 | alu |
| fma | fma | 真 | alu |
| fmov | fmov_d_x、fmov_dhi_x、fmov_imm、fmov_s_w、fmov_w_s、fmov_x_d、fmov_x_dhi | 真 | alu |
| fp1 | fp1 | 真 | alu |
| fp3 | fp3 | 真 | alu |
| hlt | hlt | 真 | system |
| hvc | hvc | 真 | system |
| ins | ins_gen | 真 | alu |
| ldaxr | ldaxr_w、ldaxr_x | 真 | load |
| ldaxrb | ldaxrb | 真 | load |
| ldaxrh | ldaxrh | 真 | load |
| ldp | ldp_d_off、ldp_d_post、ldp_d_pre、ldp_q_off、ldp_q_post、ldp_q_pre、ldp_s_off、ldp_s_post、ldp_s_pre、ldp_w_off、ldp_w_post、ldp_w_pre、ldp_x_off、ldp_x_post、ldp_x_pre | 真 | load |
| ldr | ldr_b_post_v、ldr_b_pre_v、ldr_b_vu、ldr_d_post_v、ldr_d_pre_v、ldr_d_vu、ldr_h_post_v、ldr_h_pre_v、ldr_h_vu、ldr_post_w、ldr_post_x、ldr_pre_w、ldr_pre_x、ldr_q_post_v、ldr_q_pre_v、ldr_q_vu、ldr_reg_w、ldr_reg_x、ldr_s_post_v、ldr_s_pre_v、ldr_s_vu、ldr_u_w、ldr_u_x、ldr_w_lit、ldr_x_lit | 真 | load |
| ldrb | ldrb_post、ldrb_pre、ldrb_reg、ldrb_u | 真 | load |
| ldrh | ldrh_post、ldrh_pre、ldrh_reg、ldrh_u | 真 | load |
| ldrsb | ldrsb_post_w、ldrsb_post_x、ldrsb_pre_w、ldrsb_pre_x、ldrsb_reg_w、ldrsb_reg_x、ldrsb_u_w、ldrsb_u_x | 真 | load |
| ldrsh | ldrsh_post_w、ldrsh_post_x、ldrsh_pre_w、ldrsh_pre_x、ldrsh_reg_w、ldrsh_reg_x、ldrsh_u_w、ldrsh_u_x | 真 | load |
| ldrsw | ldrsw_lit、ldrsw_post、ldrsw_pre、ldrsw_reg、ldrsw_u | 真 | load |
| ldur | ldur_b、ldur_d、ldur_h、ldur_q、ldur_s、ldur_w、ldur_x | 真 | load |
| ldurb | ldurb | 真 | load |
| ldurh | ldurh | 真 | load |
| ldursb | ldursb_w、ldursb_x | 真 | load |
| ldursh | ldursh_w、ldursh_x | 真 | load |
| ldursw | ldursw | 真 | load |
| ldxr | ldxr_w、ldxr_x | 真 | load |
| ldxrb | ldxrb | 真 | load |
| ldxrh | ldxrh | 真 | load |
| lsl | lslv | 真 | alu |
| lsr | lsrv | 真 | alu |
| madd | madd | 真 | mult |
| movi/mvni/orr/bic | mod_imm | 真 | alu |
| movk | movk | 真 | alu |
| movn | movn | 真 | alu |
| movz | movz | 真 | alu |
| mrs | mrs | 真 | system |
| msr | msr | 真 | system |
| msub | msub | 真 | mult |
| orn | orn_sh | 真 | alu |
| orr | orr_imm、orr_sh | 真 | alu |
| prfm | prfm_lit | 真 | load |
| rbit | rbit | 真 | alu |
| ret | ret | 真 | branch |
| rev | rev | 真 | alu |
| rev16 | rev16 | 真 | alu |
| rev32 | rev32 | 真 | alu |
| rev64 | rev64 | 真 | alu |
| ror | rorv | 真 | alu |
| sbfm | sbfm | 真 | alu |
| sdiv | sdiv | 真 | div |
| smaddl | smaddl | 真 | mult |
| smc | smc | 真 | system |
| smsubl | smsubl | 真 | mult |
| smulh | smulh | 真 | mult |
| stlxr | stlxr_w、stlxr_x | 真 | store |
| stlxrb | stlxrb | 真 | store |
| stlxrh | stlxrh | 真 | store |
| stp | stp_d_off、stp_d_post、stp_d_pre、stp_q_off、stp_q_post、stp_q_pre、stp_s_off、stp_s_post、stp_s_pre、stp_w_off、stp_w_post、stp_w_pre、stp_x_off、stp_x_post、stp_x_pre | 真 | store |
| str | str_b_post_v、str_b_pre_v、str_b_vu、str_d_post_v、str_d_pre_v、str_d_vu、str_h_post_v、str_h_pre_v、str_h_vu、str_post_w、str_post_x、str_pre_w、str_pre_x、str_q_post_v、str_q_pre_v、str_q_vu、str_reg_w、str_reg_x、str_s_post_v、str_s_pre_v、str_s_vu、str_u_w、str_u_x | 真 | store |
| strb | strb_post、strb_pre、strb_reg、strb_u | 真 | store |
| strh | strh_post、strh_pre、strh_reg、strh_u | 真 | store |
| stur | stur_b、stur_d、stur_h、stur_q、stur_s、stur_w、stur_x | 真 | store |
| sturb | sturb | 真 | store |
| sturh | sturh | 真 | store |
| stxr | stxr_w、stxr_x | 真 | store |
| stxrb | stxrb | 真 | store |
| stxrh | stxrh | 真 | store |
| sub | sub_ext、sub_imm、sub_sh | 真 | alu |
| subs | subs_ext、subs_imm、subs_sh | 真 | alu |
| svc | svc | 真 | system |
| sys | sys | 真 | system |
| sysl | sysl | 真 | system |
| tbnz | tbnz | 真 | branch |
| tbz | tbz | 真 | branch |
| ubfm | ubfm | 真 | alu |
| udiv | udiv | 真 | div |
| umaddl | umaddl | 真 | mult |
| umov | umov | 真 | alu |
| umsubl | umsubl | 真 | mult |
| umulh | umulh | 真 | mult |
