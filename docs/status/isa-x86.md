# 実装状況：x86

このファイルは `task status` が生成する。手で編集しない。

生成の元は `guests/x86/spec/x86min.rs`・`guests/x86/spec/x86map.rs`・`guests/x86/spec/x86cpu.rs` である。

## CPU モデル

| 名前 | 親 | 足す機能 | 除く機能 |
|---|---|---|---|
| generic32 |  | i386 |  |
| i386 |  | fpu |  |
| i486 | i386 | cpuid、i486 |  |
| i8088 |  |  |  |
| pentium | i486 | vme、de、pse、tsc、msr、cx8、mce、apic、mmx |  |
| pentium_iii | pentium_pro | fxsr、sse、sep、pat |  |
| pentium_pro | pentium | cmov、pge、mca、pae、mtrr、pse36 |  |
| x86_64 |  | cpuid、fpu、vme、de、pse、tsc、msr、pae、mce、cx8、apic、sep、mtrr、pge、mca、cmov、pat、pse36、clfsh、mmx、fxsr、sse、sse2、sse3、ssse3、sse4_1、sse4_2、cx16、popcnt、rdtscp、syscall、nx、lm、lahf_lm、i486 |  |
| x86_64_v2 | x86_64 | cx16、popcnt |  |
| x86_64_v3 | x86_64_v2 | avx、avx2、bmi1、bmi2、f16c、fma、lzcnt、movbe、osxsave |  |
| x86_64_v4 | x86_64_v3 | avx512f、avx512bw、avx512cd、avx512dq、avx512vl |  |

## 機能

- adx
- aesni
- amx_bf16
- amx_int8
- amx_tile
- apic
- avx
- avx2
- avx512_fp16
- avx512bitalg
- avx512bw
- avx512cd
- avx512dq
- avx512er
- avx512f
- avx512ifma
- avx512pf
- avx512vbmi
- avx512vbmi2
- avx512vl
- avx512vnni
- avx512vpopcntdq
- bmi1
- bmi2
- cet_ibt
- cet_ss
- cldemote
- clflushopt
- clfsh
- clwb
- cmov
- cnxt_id
- cpuid
- cx16
- cx8
- dca
- de
- dnow
- dnowext
- ds_cpl
- dtes64
- eist
- enqcmd
- erms
- f16c
- fma
- fma4
- fpu
- fsgsbase
- fxsr
- gfni
- hle
- htt
- hypervisor
- i386
- i486
- invpcid
- lahf_lm
- lm
- lwp
- lzcnt
- mca
- mce
- misalignsse
- mmx
- mmxext
- monitor
- movbe
- movdir64b
- movdiri
- msr
- mtrr
- nx
- ospke
- osxsave
- pae
- pat
- pcid
- pclmulqdq
- pdcm
- pdpe1gb
- pge
- pks
- pku
- popcnt
- prefetchw
- prefetchwt1
- pse
- pse36
- rdpid
- rdrnd
- rdseed
- rdtscp
- rtm
- sdbg
- sep
- serialize
- sgx
- sha
- smap
- smep
- smx
- sse
- sse2
- sse3
- sse4_1
- sse4_2
- sse4a
- ssse3
- svm
- syscall
- tbm
- tm2
- tsc
- tsc_deadline
- uintr
- umip
- vaes
- vme
- vmx
- vpclmulqdq
- waitpkg
- x2apic
- xop
- xsave
- xtpr

## 命令

| ニーモニック | 記述 | 条件 | タイミング |
|---|---|---|---|
| aaa | aaa | !m64 | alu |
| aad | aad_ib | !m64 | alu |
| aam | aam_ib | !m64 | alu |
| aas | aas | !m64 | alu |
| adc | adc_eb_ib | !m64 | alu |
| adc | adc_al_ib、adc_al_imm、adc_eax_iz、adc_eb_gb、adc_eb_ib、adc_ev_gv、adc_ev_ib、adc_ev_iz、adc_gb_eb、adc_gv_ev、adc_m32_imm8_mem8、adc_m32_imm8_sibd、adc_m32_r32_mem32、adc_m32_r32_mem8、adc_m32_r32_sibd、adc_m32_r32_sibd32、adc_r_mem32、adc_r_mem8、adc_r_memnd、adc_r_rip、adc_r_sibabs、adc_r_sibd、adc_rm32、adc_rm32_imm、adc_rm_imm8 | 真 | alu |
| add | add_eb_ib | !m64 | alu |
| add | add_al_ib、add_eax、add_eax_iz、add_eb_gb、add_eb_ib、add_ev_gv、add_ev_ib、add_ev_iz、add_gb_eb、add_gv_ev、add_m16_imm_sib、add_m32_r32_mem32、add_m32_r32_mem8、add_m32_r32_memnd、add_m32_r32_rip、add_m32_r32_sib、add_m32_r32_sibabs、add_m32_r32_sibd、add_m32_r32_sibd32、add_r_mem32、add_r_mem8、add_r_memnd、add_r_rip、add_r_sib、add_r_sibabs、add_r_sibd、add_r_sibd32、add_rm16_imm、add_rm32、add_rm32_imm、add_rm32_imm8_rip、add_rm32_imm_mem32、add_rm32_imm_mem8、add_rm32_imm_sib、add_rm32_imm_sibd、add_rm32_rip、add_rm64_imm、add_rm8_imm_sib、add_rm8_imm_sibd、add_rm_imm8、add_rm_imm8_mem32、add_rm_imm8_mem8、add_rm_imm8_memnd、add_rm_imm8_sibd | 真 | alu |
| addpd | addpd_xv_wv | sse2 | alu |
| addps | addps_xv_wv | sse | alu |
| addsd | addsd、addsd_xv_wv | sse2 | alu |
| addsd | addsd_m64_sib、addsd_xmm_m64_mem32、addsd_xmm_m64_mem8、addsd_xmm_m64_memnd、addsd_xmm_m64_rip、addsd_xmm_m64_sibd | sse2 | load |
| addss | addss_xv_wv | sse | alu |
| addsubpd | addsubpd_xv_wv | sse3 | alu |
| addsubps | addsubps_xv_wv | sse3 | alu |
| and | and_eb_ib | !m64 | alu |
| and | and_al_ib、and_ax_imm16、and_eax、and_eax_iz、and_eb_gb、and_eb_ib、and_ev_gv、and_ev_ib、and_ev_iz、and_gb_eb、and_gv_ev、and_m32_r32_mem8、and_m32_r32_memnd、and_m32_r32_sib、and_m32_r32_sibd、and_m8_r8、and_m8_r8_mem8、and_r8_m8_mem32、and_r_mem32、and_r_mem8、and_r_memnd、and_r_rip、and_r_sib、and_r_sibd、and_r_sibd32、and_rm16_imm、and_rm16_imm_memnd、and_rm32、and_rm32_imm、and_rm32_imm_mem32、and_rm32_imm_mem8、and_rm32_imm_memnd、and_rm32_imm_sibd、and_rm32_rip、and_rm8_imm、and_rm8_imm_mem32、and_rm8_imm_mem8、and_rm8_imm_sibd、and_rm8_imm_sibd32、and_rm_imm8、and_rm_imm8_mem32、and_rm_imm8_mem8、and_rm_imm8_memnd、and_rm_imm8_rip、and_rm_imm8_sib、and_rm_imm8_sibd | 真 | alu |
| andnpd | andnpd_xv_wv | sse2 | alu |
| andnps | andnps_xv_wv | sse | alu |
| andpd | andpd、andpd_xv_wv | sse2 | alu |
| andpd | andpd_rip | sse2 | load |
| andps | andps_xv_wv | sse | alu |
| arpl | arpl_ew_gw | !m64 | alu |
| blendpd | blendpd_xv_wv_ib | sse4_1 | alu |
| blendps | blendps_xv_wv_ib | sse4_1 | alu |
| blendvpd_xv_wv | blendvpd_xv_wv | sse4_1 | alu |
| blendvps_xv_wv | blendvps_xv_wv | sse4_1 | alu |
| bsf | bsf_gv_ev、bsf_r_rm | 真 | alu |
| bsf | bsf_r_mem32、bsf_r_mem8、bsf_r_memnd、bsf_r_rip | 真 | load |
| bsr | bsr_gv_ev、bsr_r_rm | 真 | alu |
| bsr | bsr_r_mem32、bsr_r_mem8、bsr_r_memnd、bsr_r_rip | 真 | load |
| bswap | bswap、bswap_rv | i486 | alu |
| bt | bt_ev_gv、bt_ev_ib、bt_m32_imm、bt_m32_imm_sib、bt_m32_imm_sibd、bt_r32_imm、bt_r32_rm | 真 | alu |
| btc | btc_ev_gv、btc_ev_ib | 真 | alu |
| btr | btr_ev_gv、btr_ev_ib | 真 | alu |
| bts | bts_ev_gv、bts_ev_ib、bts_r32_imm、bts_r32_rm | 真 | alu |
| call | call_ev、call_jz、call_r_mem32、call_r_mem8、call_r_memnd、call_r_rip、call_r_rm、call_r_sib、call_r_sibabs、call_r_sibd、call_r_sibd32、call_rel32 | 真 | jump |
| callf | callf_ap | !m64 | jump |
| callf | callf_rm | 真 | jump |
| cbw/cwde/cdqe | cwde | 真 | alu |
| cdq | en_cdq | 真 | alu |
| clc | clc | 真 | alu |
| cld | cld、en_cld | 真 | alu |
| clflush | clflush_mb | clfsh | alu |
| cli | cli | 真 | system |
| cmc | cmc | 真 | alu |
| cmova | cmova | cmov | alu |
| cmovae | cmovae | cmov | alu |
| cmovae | cmovae_m64、cmovae_mem8 | cmov | load |
| cmovb | cmovb | cmov | alu |
| cmovbe | cmovbe | cmov | alu |
| cmovbe | cmovbe_mem8、cmovbe_memnd、cmovbe_r64_sibd、cmovbe_rip | cmov | load |
| cmovcc | cmovja_gv_ev、cmovjae_gv_ev、cmovjb_gv_ev、cmovjbe_gv_ev、cmovje_gv_ev、cmovjg_gv_ev、cmovjge_gv_ev、cmovjl_gv_ev、cmovjle_gv_ev、cmovjne_gv_ev、cmovjno_gv_ev、cmovjnp_gv_ev、cmovjns_gv_ev、cmovjo_gv_ev、cmovjp_gv_ev、cmovjs_gv_ev | cmov | alu |
| cmove | cmove | cmov | alu |
| cmove | cmove_m64、cmove_r64_sibd、cmove_rip | cmov | load |
| cmovg | cmovg | cmov | alu |
| cmovge | cmovge | cmov | alu |
| cmovge | cmovge_r32_sibd | cmov | load |
| cmovl | cmovl | cmov | alu |
| cmovl | cmovl_r32_sib | cmov | load |
| cmovle | cmovle | cmov | alu |
| cmovne | cmovne | cmov | alu |
| cmovne | cmovne_m64、cmovne_mem8、cmovne_r32_sibd32、cmovne_r64_sibd、cmovne_rip | cmov | load |
| cmovno | cmovno | cmov | alu |
| cmovnp | cmovnp | cmov | alu |
| cmovns | cmovns | cmov | alu |
| cmovo | cmovo | cmov | alu |
| cmovp | cmovp | cmov | alu |
| cmovs | cmovs | cmov | alu |
| cmovs | cmovs_r32_sib | cmov | load |
| cmp | cmp_eb_ib | !m64 | alu |
| cmp | cmp_al_ib、cmp_al_imm、cmp_ax_imm16、cmp_eax、cmp_eax_iz、cmp_eb_gb、cmp_eb_ib、cmp_ev_gv、cmp_ev_ib、cmp_ev_iz、cmp_gb_eb、cmp_gv_ev、cmp_m32_r32_sib、cmp_m32_r32_sibabs、cmp_m32_r32_sibd、cmp_m32_r32_sibd32、cmp_m8_r8、cmp_m8_r8_mem32、cmp_m8_r8_mem8、cmp_m8_r8_memnd、cmp_m8_r8_rip、cmp_m8_r8_sib、cmp_m8_r8_sibd、cmp_m8_r8_sibd32、cmp_r8_m8、cmp_r8_m8_mem32、cmp_r8_m8_mem8、cmp_r8_m8_memnd、cmp_r8_m8_sib、cmp_r8_m8_sibd、cmp_r8_m8_sibd32、cmp_r_mem32、cmp_r_mem8、cmp_r_memnd、cmp_r_rip、cmp_r_sib、cmp_r_sibabs、cmp_r_sibd、cmp_r_sibd32、cmp_rm16_imm、cmp_rm16_imm_mem8、cmp_rm32、cmp_rm32_imm、cmp_rm32_imm_mem32、cmp_rm32_imm_mem8、cmp_rm32_imm_memnd、cmp_rm32_imm_rip、cmp_rm32_imm_sib、cmp_rm32_imm_sibd、cmp_rm32_imm_sibd32、cmp_rm64_imm、cmp_rm8_imm、cmp_rm8_imm_mem32、cmp_rm8_imm_mem8、cmp_rm8_imm_memnd、cmp_rm8_imm_rip、cmp_rm8_imm_sib、cmp_rm8_imm_sibd、cmp_rm8_imm_sibd32、cmp_rm_imm8、cmp_rm_imm8_mem32、cmp_rm_imm8_memnd、cmp_rm_imm8_rip、cmp_rm_imm8_sib、cmp_rm_imm8_sibabs、cmp_rm_imm8_sibd、cmp_rm_imm8_sibd32、cmp_rm_imm8m8、cmp_rm_mem32、cmp_rm_mem8、cmp_rm_memnd、cmp_rm_rip | 真 | alu |
| cmppd | cmppd_xv_wv_ib | sse2 | alu |
| cmpps | cmpps_xv_wv_ib | sse | alu |
| cmps | cmps_v | 真 | alu |
| cmpsb | cmps_b | 真 | alu |
| cmpsd | cmpsd_xv_wv_ib | sse2 | alu |
| cmpss | cmpss_xv_wv_ib | sse | alu |
| cmpxchg | cmpxchg_eb_gb、cmpxchg_ev_gv、cmpxchg_r_mem32、cmpxchg_r_mem8、cmpxchg_r_memnd、cmpxchg_r_rip、cmpxchg_r_rm | i486 | alu |
| cmpxchg8b | cmpxchg8b_mq | cx8 && (cx16 || !cx16) | alu |
| comisd | comisd、comisd_xv_wv | sse2 | alu |
| comiss | comiss_xv_wv | sse | alu |
| cpuid | cpuid、en_cpuid | cpuid | system |
| crc32 | crc32_gv_eb、crc32_gv_ev | sse4_2 | alu |
| cvtpd2ps | cvtpd2ps_xv_wv | sse2 | alu |
| cvtps2pd | cvtps2pd_xv_wv | sse2 | alu |
| cvtsd2si | cvtsd2si_gv_wv | sse2 | alu |
| cvtsd2ss | cvtsd2ss、cvtsd2ss_xv_wv | sse2 | alu |
| cvtsi2sd | cvtsi2sd_xv_ev | sse2 | alu |
| cvtsi2sd | cvtsi2sd_m32_mem8、cvtsi2sd_m32_sib、cvtsi2sd_m32_sibd、cvtsi2sd_r64 | sse2 | load |
| cvtsi2ss | cvtsi2ss_xv_ev | sse | alu |
| cvtss2sd | cvtss2sd_xv_wv | sse2 | alu |
| cvtss2sd | cvtss2sd_m32 | sse2 | load |
| cvtss2si | cvtss2si_gv_wv | sse | alu |
| cvttsd2si | cvttsd2si_gv_wv | sse2 | alu |
| cvttsd2si | cvttsd2si_m64_sib、cvttsd2si_r64 | sse2 | load |
| cvttss2si | cvttss2si_gv_wv | sse | alu |
| cwd/cdq/cqo | cdq | 真 | alu |
| cwde | en_cwde | 真 | alu |
| daa | daa | !m64 | alu |
| das | das | !m64 | alu |
| dec | dec_rv | !m64 | alu |
| dec | dec_eax、dec_eb、dec_ebp、dec_ebx、dec_ecx、dec_edi、dec_edx、dec_esi、dec_esp、dec_ev、dec_m8_memnd、dec_r8、dec_rm、dec_rm_mem32、dec_rm_mem8、dec_rm_rip、dec_rm_sib、dec_rm_sibd、dec_rm_sibd32 | 真 | alu |
| div | div_rm32、div_rm32_mem8、div_rm32_sib、div_rm32_sibd、div_rm8 | 真 | div |
| div | div_eb、div_ev | 真 | mult |
| divpd | divpd_xv_wv | sse2 | alu |
| divps | divps_xv_wv | sse | alu |
| divsd | divsd、divsd_xv_wv | sse2 | alu |
| divsd | divsd_xmm_m64_rip | sse2 | load |
| divss | divss_xv_wv | sse | alu |
| dppd | dppd_xv_wv_ib | sse4_1 | alu |
| dpps | dpps_xv_wv_ib | sse4_1 | alu |
| emms | emms | mmx | alu |
| endbr | endbr | 真 | alu |
| endbr64 | endbr64 | 真 | alu |
| enter | enter_iw_ib | 真 | store |
| extractps | extractps_ed_xv | sse4_1 | store |
| fadd | fadd_st | 真 | alu |
| fbld | fbld_m80 | 真 | alu |
| fbstp | fbstp_m80 | 真 | alu |
| fcomi | fcomi_sti | 真 | alu |
| fild | fild_m16、fild_m32、fild_m32_sibd、fild_m64、fild_m64_sib、fild_m64_sibd | 真 | alu |
| fist | fist_m16、fist_m32 | 真 | alu |
| fistp | fistp_m16、fistp_m32、fistp_m64、fistp_m64_sibd | 真 | alu |
| fisttp | fisttp_m16、fisttp_m32、fisttp_m64 | 真 | alu |
| fld | fld_m32、fld_m32_rip、fld_m64、fld_m64_memnd、fld_m64_sib、fld_m80、fld_m80_rip、fld_m80_sib、fld_m80_sibd、fld_m80_sibd32、fld_st | 真 | alu |
| fldcw | fldcw_m16、fldcw_mem32、fldcw_mem8、fldcw_memnd、fldcw_sibd | 真 | alu |
| fldz | fldz | 真 | alu |
| fmul | fmul_m32_rip | 真 | alu |
| fmulp | fmulp_st | 真 | alu |
| fnstcw | fnstcw_m16、fnstcw_mem32、fnstcw_mem8、fnstcw_memnd、fnstcw_sibd | 真 | alu |
| fnstsw | fnstsw_m16 | 真 | alu |
| fst | fst_m32、fst_m64 | 真 | alu |
| fstp | fstp_m32、fstp_m64、fstp_m64_sibd、fstp_m80、fstp_m80_memnd、fstp_m80_sib、fstp_m80_sibd、fstp_m80_sibd32、fstp_st | 真 | alu |
| fsubp | fsubp_st | 真 | alu |
| fucomi | fucomi_st | 真 | alu |
| fucomip | fucomip_st | 真 | alu |
| fwait | fwait | 真 | system |
| fxch | fxch_st、fxch_sti | 真 | alu |
| haddpd | haddpd_xv_wv | sse3 | alu |
| haddps | haddps_xv_wv | sse3 | alu |
| hlt | en_hlt、hlt | 真 | system |
| hsubpd | hsubpd_xv_wv | sse3 | alu |
| hsubps | hsubps_xv_wv | sse3 | alu |
| idiv | idiv_rm32 | 真 | div |
| idiv | idiv_eb、idiv_ev | 真 | mult |
| imul | imul_r_imm、imul_r_imm8、imul_r_imm8_mem32、imul_r_imm8_mem8、imul_r_imm8_rip、imul_r_imm8_sib、imul_r_imm8_sibd、imul_r_imm_mem8、imul_r_imm_rip、imul_r_imm_sib、imul_r_imm_sibd、imul_r_rm、imul_rm_mem8、imul_rm_sibd | 真 | alu |
| imul | imul_r_mem32、imul_r_mem8、imul_r_memnd、imul_r_rip、imul_r_sibabs、imul_r_sibd | 真 | load |
| imul | imul_eb、imul_ev、imul_gv_ev、imul_gv_ev_ib、imul_gv_ev_iz、imul_rm32 | 真 | mult |
| in | in_al_dx、in_al_ib、in_ev_dx、in_ev_ib | 真 | system |
| inc | inc_rv | !m64 | alu |
| inc | inc_eax、inc_eb、inc_ebp、inc_ebx、inc_ecx、inc_edi、inc_edx、inc_esi、inc_esp、inc_ev、inc_m8_rip、inc_r8、inc_rm、inc_rm_mem32、inc_rm_mem8、inc_rm_memnd、inc_rm_rip、inc_rm_sib、inc_rm_sibd、inc_rm_sibd32 | 真 | alu |
| insertps | insertps_xv_wv_ib | sse4_1 | alu |
| int | int80、int_ib | 真 | system |
| int3 | int3 | 真 | system |
| into | into | !m64 | system |
| iret | iret | !m64 | jump |
| ja | ja、ja_rel32 | 真 | jump |
| jae | jae、jae_rel32 | 真 | jump |
| jb | jb、jb_rel32 | 真 | jump |
| jbe | jbe、jbe_rel32 | 真 | jump |
| jcc | ja_jb、ja_jz、jae_jb、jae_jz、jb_jb、jb_jz、jbe_jb、jbe_jz、je_jb、je_jz、jg_jb、jg_jz、jge_jb、jge_jz、jl_jb、jl_jz、jle_jb、jle_jz、jne_jb、jne_jz、jno_jb、jno_jz、jnp_jb、jnp_jz、jns_jb、jns_jz、jo_jb、jo_jz、jp_jb、jp_jz、js_jb、js_jz | 真 | jump |
| jcxz | jcxz | 真 | jump |
| je | je、je_rel32 | 真 | jump |
| jg | jg、jg_rel32 | 真 | jump |
| jge | jge、jge_rel32 | 真 | jump |
| jl | jl、jl_rel32 | 真 | jump |
| jle | jle、jle_rel32 | 真 | jump |
| jmp | jmp8、jmp_ev、jmp_jb、jmp_jz、jmp_r_mem32、jmp_r_mem8、jmp_r_memnd、jmp_r_rip、jmp_r_rm、jmp_r_sib、jmp_r_sibabs、jmp_rel32 | 真 | jump |
| jmpf | jmpf_ap | !m64 | jump |
| jmpf | jmpf_rm | 真 | jump |
| jne | jne、jne_rel32 | 真 | jump |
| jno | jno、jno_rel32 | 真 | jump |
| jnp | jnp、jnp_rel32 | 真 | jump |
| jns | jns、jns_rel32 | 真 | jump |
| jo | jo、jo_rel32 | 真 | jump |
| jp | jp、jp_rel32 | 真 | jump |
| js | js、js_rel32 | 真 | jump |
| lahf | lahf | !m64 || lahf_lm | alu |
| lddqu | lddqu_xv_mv | sse3 | load |
| ldmxcsr | ldmxcsr_md | sse | load |
| lds | lds_gv_mp | !m64 | load |
| lea | lea_abs、lea_gv_m、lea_m32、lea_m8、lea_mnd、lea_sib、lea_sibabs、lea_sibd、lea_sibd32 | 真 | alu |
| leave | en_leave、leave | 真 | alu |
| les | les_gv_mp | !m64 | load |
| lfence | lfence | sse2 | alu |
| lods | lods_v | 真 | load |
| lodsb | lods_b | 真 | load |
| loop | jcxz_jb、loop、loop_jb、loope_jb、loopne_jb | 真 | jump |
| maskmovdqu | maskmovdqu_xv_xv | sse2 | store |
| maskmovq | maskmovq_pv_qv | sse | store |
| maxpd | maxpd_xv_wv | sse2 | alu |
| maxps | maxps_xv_wv | sse | alu |
| maxsd | maxsd_xv_wv | sse2 | alu |
| maxss | maxss_xv_wv | sse | alu |
| mfence | mfence | sse2 | alu |
| minpd | minpd_xv_wv | sse2 | alu |
| minps | minps_xv_wv | sse | alu |
| minsd | minsd、minsd_xv_wv | sse2 | alu |
| minss | minss_xv_wv | sse | alu |
| monitor | monitor | monitor | system |
| mov | mov_ew_sr、mov_sr_ew | opd_o16 && adr_a16 | load |
| mov | mov_eb_ib、mov_ev_iz | opd_o16 && adr_a16 | store |
| mov | movaps_xv_wv、movss_xv_wv、movups_xv_wv | sse | load |
| mov | movaps_wv_xv、movss_wv_xv、movups_wv_xv | sse | store |
| mov | movapd_xv_wv、movsd_xv_wv、movupd_xv_wv | sse2 | load |
| mov | movapd_wv_xv、movsd_wv_xv、movupd_wv_xv | sse2 | store |
| mov | mov_mr32、mov_r32_imm、mov_r64_imm64、mov_rm16_imm_disp32、mov_rm16_imm_m32、mov_rm16_imm_mem8、mov_rm16_imm_memnd、mov_rm16_imm_rip、mov_rm16_imm_sib、mov_rm16_imm_sibd、mov_rm16_imm_sibd32、mov_rm32、mov_rm_imm、mov_rm_imm_m32、mov_rm_imm_m8、mov_rm_imm_memnd、mov_rm_imm_rip、mov_rm_imm_sib、mov_rm_imm_sibabs、mov_rm_imm_sibd、mov_rm_imm_sibd32、mov_sreg_r | 真 | alu |
| mov | mov_al_moffs、mov_al_ob、mov_eax_abs、mov_eax_mem32、mov_eax_mem8、mov_eax_memnd、mov_eax_moffs、mov_eax_ov、mov_eax_sib、mov_eax_sibabs、mov_eax_sibd、mov_eax_sibd32、mov_eb_gb、mov_ev_gv、mov_ew_sr、mov_gb_eb、mov_gv_ev、mov_r8_imm、mov_r8_m8、mov_r8_m8_mem32、mov_r8_m8_mem8、mov_r8_m8_memnd、mov_r8_m8_rip、mov_r8_m8_sib、mov_r8_m8_sibd、mov_r8_m8_sibd32、mov_rb_ib、mov_rv_iv、mov_sr_ew | 真 | load |
| mov | mov_abs_eax、mov_eb_ib、mov_ev_iz、mov_m8_r8、mov_m8_r8_mem32、mov_m8_r8_mem8、mov_m8_r8_memnd、mov_m8_r8_rip、mov_m8_r8_sib、mov_m8_r8_sibd、mov_m8_r8_sibd32、mov_mem_eax32、mov_mem_eax8、mov_memnd_eax、mov_moffs_al、mov_moffs_eax、mov_ob_al、mov_ov_eax、mov_rm8_imm_mem32、mov_rm8_imm_mem8、mov_rm8_imm_memnd、mov_rm8_imm_rip、mov_rm8_imm_sib、mov_rm8_imm_sibd、mov_rm8_imm_sibd32、mov_sib_eax、mov_sibabs_eax、mov_sibabs_r8、mov_sibd32_eax、mov_sibd_eax | 真 | store |
| movaps | movaps_load_mem32、movaps_load_mem8、movaps_load_memnd、movaps_load_rip、movaps_load_sibd、movaps_load_xmm | sse | load |
| movaps | movaps_store_mem32、movaps_store_mem8、movaps_store_memnd、movaps_store_rip、movaps_store_sib、movaps_store_sibd、movaps_store_sibd32 | sse | store |
| movbe | movbe_gv_mv | movbe | load |
| movbe | movbe_mv_gv | movbe | store |
| movd | movd_pv_ev | mmx | load |
| movd | movd_ev_pv | mmx | store |
| movd | movd_xmm、movd_xmm_m32、movd_xmm_rip、movd_xv_ev | sse2 | load |
| movd | movd_ev_xv | sse2 | store |
| movddup | movddup_xv_wv | sse3 | load |
| movdqa | movdqa_load_rip、movdqa_xv_wv | sse2 | load |
| movdqa | movdqa_wv_xv | sse2 | store |
| movdqu | movdqu_load_mem32、movdqu_load_mem8、movdqu_load_memnd、movdqu_load_sib、movdqu_load_xmm、movdqu_xv_wv | sse2 | load |
| movdqu | movdqu_store_mem32、movdqu_store_mem8、movdqu_store_memnd、movdqu_store_sib、movdqu_store_xmm、movdqu_wv_xv | sse2 | store |
| movhlps | movhlps_xv_xv | sse | alu |
| movhlps | movhlps_xv_xv | sse2 | alu |
| movhpd | movhpd_xv_wv | sse2 | load |
| movhpd | movhpd_wv_xv | sse2 | store |
| movhps | movhps_xmm_m64_mem8、movhps_xv_wv | sse | load |
| movhps | movhps_wv_xv | sse | store |
| movlhps | movlhps_xv_xv | sse | alu |
| movlhps | movlhps_xv_xv | sse2 | alu |
| movlpd | movlpd_xmm_m64_memnd、movlpd_xv_wv | sse2 | load |
| movlpd | movlpd_wv_xv | sse2 | store |
| movlps | movlps_xv_wv | sse | load |
| movlps | movlps_wv_xv | sse | store |
| movmskpd | movmskpd_gv_wv | sse2 | alu |
| movmskps | movmskps_gv_wv | sse | alu |
| movntdq | movntdq_store_mem8、movntdq_store_memnd | sse2 | store |
| movntdqa_xv_wv | movntdqa_xv_wv | sse4_1 | alu |
| movntq | movntq_qv_pv | sse | store |
| movq | movq_pv_qv | mmx | load |
| movq | movq_qv_pv | mmx | store |
| movq | movq_r64_xmm、movq_xmm_m64_mem8、movq_xmm_m64_rip、movq_xv_wv | sse2 | load |
| movq | movq_m64_xmm_mem32、movq_m64_xmm_mem8、movq_m64_xmm_memnd、movq_m64_xmm_rip、movq_wv_xv | sse2 | store |
| movs | movs_v | 真 | load |
| movsb | movs_b、movsb | 真 | load |
| movsd | movsd | 真 | load |
| movshdup | movshdup_xv_wv | sse3 | load |
| movsldup | movsldup_xv_wv | sse3 | load |
| movsx | movsx_gv_eb、movsx_gv_ew、movsx_r32_m16_mem8、movsx_r32_m16_sibd32、movsx_r32_m8_mem32、movsx_r32_m8_mem8、movsx_r32_m8_memnd、movsx_r32_m8_rip、movsx_r32_m8_sib、movsx_r32_m8_sibd、movsx_r32_m8_sibd32、movsx_r32_r16、movsx_r32_r8 | 真 | load |
| movsxd | movsxd_gv_ed | m64 | alu |
| movsxd | movsxd | 真 | alu |
| movsxd | movsxd_mem32、movsxd_mem8、movsxd_memnd、movsxd_rip、movsxd_sib、movsxd_sibd、movsxd_sibd32 | 真 | load |
| movups | movups_load_mem32、movups_load_mem8、movups_load_memnd、movups_load_rip、movups_load_sib、movups_load_sibabs、movups_load_sibd、movups_load_sibd32、movups_load_xmm | sse | load |
| movups | movups_store_mem32、movups_store_mem8、movups_store_memnd、movups_store_rip、movups_store_sib、movups_store_sibd、movups_store_sibd32、movups_store_xmm | sse | store |
| movzx | movzx_gv_eb、movzx_gv_ew、movzx_r32_m16_mem32、movzx_r32_m16_mem8、movzx_r32_m16_memnd、movzx_r32_m16_rip、movzx_r32_m16_sib、movzx_r32_m16_sibabs、movzx_r32_m16_sibd、movzx_r32_m16_sibd32、movzx_r32_m8_mem32、movzx_r32_m8_mem8、movzx_r32_m8_memnd、movzx_r32_m8_rip、movzx_r32_m8_sib、movzx_r32_m8_sibd、movzx_r32_m8_sibd32、movzx_r32_r16、movzx_r32_r8 | 真 | load |
| mpsadbw | mpsadbw_xv_wv_ib | sse4_1 | alu |
| mul | mul_eb、mul_ev、mul_rm32、mul_rm32_rip、mul_rm32_sib | 真 | mult |
| mulpd | mulpd_xv_wv | sse2 | alu |
| mulps | mulps_xv_wv | sse | alu |
| mulsd | mulsd、mulsd_xv_wv | sse2 | alu |
| mulsd | mulsd_m64_sib、mulsd_xmm_m64_mem32、mulsd_xmm_m64_rip、mulsd_xmm_m64_sibd | sse2 | load |
| mulss | mulss_xv_wv | sse | alu |
| mwait | mwait | monitor | system |
| neg | neg_rm32 | 真 | alu |
| neg | neg_eb、neg_ev | 真 | mult |
| nop | nop、nop_ev | 真 | alu |
| nopl | nopl、nopl_mem32、nopl_mem8、nopl_sib、nopl_sibd、nopl_sibd32 | 真 | alu |
| not | not_rm32 | 真 | alu |
| not | not_eb、not_ev | 真 | mult |
| or | or_eb_ib | !m64 | alu |
| or | or_al_ib、or_al_imm、or_ax_imm16、or_eax、or_eax_iz、or_eb_gb、or_eb_ib、or_ev_gv、or_ev_ib、or_ev_iz、or_gb_eb、or_gv_ev、or_m32_r32_mem32、or_m32_r32_mem8、or_m32_r32_memnd、or_m32_r32_sib、or_m32_r32_sibabs、or_m32_r32_sibd、or_m32_r32_sibd32、or_m8_r8、or_m8_r8_mem32、or_m8_r8_mem8、or_m8_r8_rip、or_m8_r8_sibd、or_m_rip、or_r8_m8_mem8、or_r8_r8、or_r_mem32、or_r_mem8、or_r_memnd、or_r_rip、or_r_sib、or_r_sibabs、or_r_sibd、or_r_sibd32、or_rm32、or_rm32_imm、or_rm32_imm_mem8、or_rm32_imm_memnd、or_rm32_imm_sib、or_rm32_imm_sibd、or_rm32_rip、or_rm8_imm、or_rm8_imm_mem32、or_rm8_imm_mem8、or_rm8_imm_memnd、or_rm8_imm_sib、or_rm8_imm_sibd、or_rm_imm8、or_rm_imm8_mem32、or_rm_imm8_mem8、or_rm_imm8_memnd、or_rm_imm8_rip、or_rm_imm8_sib、or_rm_imm8_sibd | 真 | alu |
| or | or_r8_m8_mem32、or_r8_m8_rip、or_r8_m8_sibd、or_r8_m8_sibd32 | 真 | load |
| orpd | orpd_xv_wv | sse2 | alu |
| orps | orps_xv_wv | sse | alu |
| out | out_dx_al、out_dx_ev、out_ib_al、out_ib_ev | 真 | system |
| pabsb_pv_qv | pabsb_pv_qv | ssse3 | alu |
| pabsb_xv_wv | pabsb_xv_wv | ssse3 | alu |
| pabsd_pv_qv | pabsd_pv_qv | ssse3 | alu |
| pabsd_xv_wv | pabsd_xv_wv | ssse3 | alu |
| pabsw_pv_qv | pabsw_pv_qv | ssse3 | alu |
| pabsw_xv_wv | pabsw_xv_wv | ssse3 | alu |
| packssdw | packssdw_pv_qv | mmx | alu |
| packsswb | packsswb_pv_qv | mmx | alu |
| packusdw_xv_wv | packusdw_xv_wv | sse4_1 | alu |
| packuswb | packuswb_pv_qv | mmx | alu |
| paddb | paddb_pv_qv | mmx | alu |
| paddb | paddb、paddb_xv_wv | sse2 | alu |
| paddd | paddd_pv_qv | mmx | alu |
| paddd | paddd_xv_wv | sse2 | alu |
| paddq | paddq_pv_qv、paddq_xv_wv | sse2 | alu |
| paddsb | paddsb_pv_qv | mmx | alu |
| paddsb | paddsb_xv_wv | sse2 | alu |
| paddsw | paddsw_pv_qv | mmx | alu |
| paddsw | paddsw_xv_wv | sse2 | alu |
| paddusb | paddusb_pv_qv | mmx | alu |
| paddusb | paddusb_xv_wv | sse2 | alu |
| paddusw | paddusw_pv_qv | mmx | alu |
| paddusw | paddusw_xv_wv | sse2 | alu |
| paddw | paddw_pv_qv | mmx | alu |
| paddw | paddw_xv_wv | sse2 | alu |
| palignr | palignr_pv_qv_ib、palignr_xv_wv_ib | ssse3 | alu |
| pand | pand_pv_qv | mmx | alu |
| pand | pand、pand_xv_wv | sse2 | alu |
| pandn | pandn_pv_qv | mmx | alu |
| pandn | pandn、pandn_xv_wv | sse2 | alu |
| pavgb | pavgb_pv_qv | sse | alu |
| pavgb | pavgb_xv_wv | sse2 | alu |
| pavgw | pavgw_pv_qv | sse | alu |
| pavgw | pavgw_xv_wv | sse2 | alu |
| pblendvb_xv_wv | pblendvb_xv_wv | sse4_1 | alu |
| pblendw | pblendw_xv_wv_ib | sse4_1 | alu |
| pcmpeqb | pcmpeqb_pv_qv | mmx | alu |
| pcmpeqb | pcmpeqb、pcmpeqb_xv_wv | sse2 | alu |
| pcmpeqb | pcmpeqb_mem32、pcmpeqb_mem8、pcmpeqb_memnd | sse2 | load |
| pcmpeqd | pcmpeqd_pv_qv | mmx | alu |
| pcmpeqd | pcmpeqd、pcmpeqd_xv_wv | sse2 | alu |
| pcmpeqq_xv_wv | pcmpeqq_xv_wv | sse4_1 | alu |
| pcmpeqw | pcmpeqw_pv_qv | mmx | alu |
| pcmpeqw | pcmpeqw_xv_wv | sse2 | alu |
| pcmpestri | pcmpestri_xv_wv_ib | sse4_2 | alu |
| pcmpestrm | pcmpestrm_xv_wv_ib | sse4_2 | alu |
| pcmpgtb | pcmpgtb_pv_qv | mmx | alu |
| pcmpgtb | pcmpgtb、pcmpgtb_xv_wv | sse2 | alu |
| pcmpgtd | pcmpgtd_pv_qv | mmx | alu |
| pcmpgtd | pcmpgtd_xv_wv | sse2 | alu |
| pcmpgtq_xv_wv | pcmpgtq_xv_wv | sse4_2 | alu |
| pcmpgtw | pcmpgtw_pv_qv | mmx | alu |
| pcmpgtw | pcmpgtw_xv_wv | sse2 | alu |
| pcmpistri | pcmpistri_xv_wv_ib | sse4_2 | alu |
| pcmpistrm | pcmpistrm_xv_wv_ib | sse4_2 | alu |
| pextrb | pextrb_eb_xv | sse4_1 | store |
| pextrd | pextrd_ed_xv | sse4_1 | store |
| pextrw | pextrw_gv_pv_ib | sse | alu |
| pextrw | pextrw_gv_wv_ib | sse2 | alu |
| pextrw | pextrw_ew_xv | sse4_1 | store |
| phaddd_pv_qv | phaddd_pv_qv | ssse3 | alu |
| phaddd_xv_wv | phaddd_xv_wv | ssse3 | alu |
| phaddsw_pv_qv | phaddsw_pv_qv | ssse3 | alu |
| phaddsw_xv_wv | phaddsw_xv_wv | ssse3 | alu |
| phaddw_pv_qv | phaddw_pv_qv | ssse3 | alu |
| phaddw_xv_wv | phaddw_xv_wv | ssse3 | alu |
| phminposuw_xv_wv | phminposuw_xv_wv | sse4_1 | alu |
| phsubd_pv_qv | phsubd_pv_qv | ssse3 | alu |
| phsubd_xv_wv | phsubd_xv_wv | ssse3 | alu |
| phsubsw_pv_qv | phsubsw_pv_qv | ssse3 | alu |
| phsubsw_xv_wv | phsubsw_xv_wv | ssse3 | alu |
| phsubw_pv_qv | phsubw_pv_qv | ssse3 | alu |
| phsubw_xv_wv | phsubw_xv_wv | ssse3 | alu |
| pinsrb | pinsrb_xv_eb_ib | sse4_1 | alu |
| pinsrd | pinsrd_xv_ed_ib | sse4_1 | alu |
| pinsrw | pinsrw_pv_ew_ib | sse | alu |
| pinsrw | pinsrw_xv_ew_ib | sse2 | alu |
| pmaddubsw_pv_qv | pmaddubsw_pv_qv | ssse3 | alu |
| pmaddubsw_xv_wv | pmaddubsw_xv_wv | ssse3 | alu |
| pmaddwd | pmaddwd_pv_qv | mmx | alu |
| pmaxsb_xv_wv | pmaxsb_xv_wv | sse4_1 | alu |
| pmaxsd_xv_wv | pmaxsd_xv_wv | sse4_1 | alu |
| pmaxsw | pmaxsw_pv_qv | sse | alu |
| pmaxsw | pmaxsw_xv_wv | sse2 | alu |
| pmaxub | pmaxub_pv_qv | sse | alu |
| pmaxub | pmaxub、pmaxub_xv_wv | sse2 | alu |
| pmaxud_xv_wv | pmaxud_xv_wv | sse4_1 | alu |
| pmaxuw_xv_wv | pmaxuw_xv_wv | sse4_1 | alu |
| pminsb_xv_wv | pminsb_xv_wv | sse4_1 | alu |
| pminsd_xv_wv | pminsd_xv_wv | sse4_1 | alu |
| pminsw | pminsw_pv_qv | sse | alu |
| pminsw | pminsw_xv_wv | sse2 | alu |
| pminub | pminub_pv_qv | sse | alu |
| pminub | pminub、pminub_xv_wv | sse2 | alu |
| pminub | pminub_mem32、pminub_mem8、pminub_memnd | sse2 | load |
| pminud_xv_wv | pminud_xv_wv | sse4_1 | alu |
| pminuw_xv_wv | pminuw_xv_wv | sse4_1 | alu |
| pmovmskb | pmovmskb_gv_qv | sse | alu |
| pmovmskb | pmovmskb_gv_wv | sse2 | alu |
| pmovmskb | pmovmskb | sse2 | load |
| pmovsxbd_xv_wv | pmovsxbd_xv_wv | sse4_1 | alu |
| pmovsxbq_xv_wv | pmovsxbq_xv_wv | sse4_1 | alu |
| pmovsxbw_xv_wv | pmovsxbw_xv_wv | sse4_1 | alu |
| pmovsxdq_xv_wv | pmovsxdq_xv_wv | sse4_1 | alu |
| pmovsxwd_xv_wv | pmovsxwd_xv_wv | sse4_1 | alu |
| pmovsxwq_xv_wv | pmovsxwq_xv_wv | sse4_1 | alu |
| pmovzxbd_xv_wv | pmovzxbd_xv_wv | sse4_1 | alu |
| pmovzxbq_xv_wv | pmovzxbq_xv_wv | sse4_1 | alu |
| pmovzxbw_xv_wv | pmovzxbw_xv_wv | sse4_1 | alu |
| pmovzxdq_xv_wv | pmovzxdq_xv_wv | sse4_1 | alu |
| pmovzxwd_xv_wv | pmovzxwd_xv_wv | sse4_1 | alu |
| pmovzxwq_xv_wv | pmovzxwq_xv_wv | sse4_1 | alu |
| pmuldq_xv_wv | pmuldq_xv_wv | sse4_1 | alu |
| pmulhrsw_pv_qv | pmulhrsw_pv_qv | ssse3 | alu |
| pmulhrsw_xv_wv | pmulhrsw_xv_wv | ssse3 | alu |
| pmulhuw | pmulhuw_pv_qv | sse | alu |
| pmulhw | pmulhw_pv_qv | mmx | alu |
| pmulld_xv_wv | pmulld_xv_wv | sse4_1 | alu |
| pmullw | pmullw_pv_qv | mmx | alu |
| pmullw | pmullw_xv_wv | sse2 | alu |
| pmuludq | pmuludq_pv_qv | sse2 | alu |
| pop | pop_ds、pop_es、pop_ss | !m64 | load |
| pop | pop_eax、pop_ebp、pop_ebx、pop_ecx、pop_edi、pop_edx、pop_esi、pop_esp、pop_ev、pop_fs、pop_gs、pop_m64_mem8、pop_rv | 真 | load |
| popa | popa | !m64 | load |
| popcnt | popcnt_gv_ev | popcnt | alu |
| popf | popf | 真 | load |
| por | por_pv_qv | mmx | alu |
| por | por、por_xv_wv | sse2 | alu |
| por | por_mem32、por_mem8、por_memnd、por_sibd32 | sse2 | load |
| psadbw | psadbw_pv_qv | sse | alu |
| pshufb_pv_qv | pshufb_pv_qv | ssse3 | alu |
| pshufb_xv_wv | pshufb_xv_wv | ssse3 | alu |
| pshufd | pshufd、pshufd_xv_wv_ib | sse2 | alu |
| pshufhw | pshufhw_xv_wv_ib | sse2 | alu |
| pshuflw | pshuflw_xv_wv_ib | sse2 | alu |
| pshufw | pshufw_pv_qv_ib | sse | alu |
| psignb_pv_qv | psignb_pv_qv | ssse3 | alu |
| psignb_xv_wv | psignb_xv_wv | ssse3 | alu |
| psignd_pv_qv | psignd_pv_qv | ssse3 | alu |
| psignd_xv_wv | psignd_xv_wv | ssse3 | alu |
| psignw_pv_qv | psignw_pv_qv | ssse3 | alu |
| psignw_xv_wv | psignw_xv_wv | ssse3 | alu |
| pslld | pslld_pv_qv、pslld_qv_ib | mmx | alu |
| pslld | pslld_wv_ib、pslld_xv_wv | sse2 | alu |
| pslldq | pslldq、pslldq_wv_ib | sse2 | alu |
| psllq | psllq_pv_qv、psllq_qv_ib | mmx | alu |
| psllq | psllq_wv_ib、psllq_xv_wv | sse2 | alu |
| psllw | psllw_pv_qv、psllw_qv_ib | mmx | alu |
| psllw | psllw_wv_ib、psllw_xv_wv | sse2 | alu |
| psrad | psrad_pv_qv、psrad_qv_ib | mmx | alu |
| psrad | psrad_wv_ib、psrad_xv_wv | sse2 | alu |
| psraw | psraw_pv_qv、psraw_qv_ib | mmx | alu |
| psraw | psraw_wv_ib、psraw_xv_wv | sse2 | alu |
| psrld | psrld_pv_qv、psrld_qv_ib | mmx | alu |
| psrld | psrld_wv_ib、psrld_xv_wv | sse2 | alu |
| psrldq | psrldq、psrldq_wv_ib | sse2 | alu |
| psrlq | psrlq_pv_qv、psrlq_qv_ib | mmx | alu |
| psrlq | psrlq_wv_ib、psrlq_xv_wv | sse2 | alu |
| psrlw | psrlw_pv_qv、psrlw_qv_ib | mmx | alu |
| psrlw | psrlw_wv_ib、psrlw_xv_wv | sse2 | alu |
| psubb | psubb_pv_qv | mmx | alu |
| psubb | psubb、psubb_xv_wv | sse2 | alu |
| psubd | psubd_pv_qv | mmx | alu |
| psubd | psubd_xv_wv | sse2 | alu |
| psubq | psubq_pv_qv、psubq_xv_wv | sse2 | alu |
| psubsb | psubsb_pv_qv | mmx | alu |
| psubsb | psubsb_xv_wv | sse2 | alu |
| psubsw | psubsw_pv_qv | mmx | alu |
| psubsw | psubsw_xv_wv | sse2 | alu |
| psubusb | psubusb_pv_qv | mmx | alu |
| psubusb | psubusb_xv_wv | sse2 | alu |
| psubusw | psubusw_pv_qv | mmx | alu |
| psubusw | psubusw_xv_wv | sse2 | alu |
| psubw | psubw_pv_qv | mmx | alu |
| psubw | psubw_xv_wv | sse2 | alu |
| ptest_xv_wv | ptest_xv_wv | sse4_1 | alu |
| punpckhbw | punpckhbw_pv_qv | mmx | alu |
| punpckhbw | punpckhbw_xv_wv | sse2 | alu |
| punpckhdq | punpckhdq_pv_qv | mmx | alu |
| punpckhdq | punpckhdq_xv_wv | sse2 | alu |
| punpckhqdq | punpckhqdq_xv_wv | sse2 | alu |
| punpckhwd | punpckhwd_pv_qv | mmx | alu |
| punpckhwd | punpckhwd_xv_wv | sse2 | alu |
| punpcklbw | punpcklbw_pv_qv | mmx | alu |
| punpcklbw | punpcklbw、punpcklbw_xv_wv | sse2 | alu |
| punpckldq | punpckldq_pv_qv | mmx | alu |
| punpckldq | punpckldq、punpckldq_xv_wv | sse2 | alu |
| punpcklqdq | punpcklqdq、punpcklqdq_xv_wv | sse2 | alu |
| punpcklwd | punpcklwd_pv_qv | mmx | alu |
| punpcklwd | punpcklwd、punpcklwd_xv_wv | sse2 | alu |
| push | push_cs、push_ds、push_es、push_ss | !m64 | store |
| push | push_eax、push_ebp、push_ebx、push_ecx、push_edi、push_edx、push_esi、push_esp、push_ev、push_fs、push_gs、push_ib、push_imm32、push_imm8、push_iz、push_rm_abs、push_rm_mem32、push_rm_mem8、push_rm_memnd、push_rm_sib、push_rm_sibabs、push_rm_sibd、push_rm_sibd32、push_rv | 真 | store |
| pusha | pusha | !m64 | store |
| pushf | pushf | 真 | store |
| pxor | pxor_pv_qv | mmx | alu |
| pxor | pxor、pxor_xv_wv | sse2 | alu |
| rcl | rcl_eb_1、rcl_eb_cl、rcl_eb_ib、rcl_ev_1、rcl_ev_cl、rcl_ev_ib | 真 | alu |
| rcr | rcr_eb_1、rcr_eb_cl、rcr_eb_ib、rcr_ev_1、rcr_ev_cl、rcr_ev_ib | 真 | alu |
| rdsspq | rdsspq | cet_ss | system |
| rdtsc | rdtsc | tsc | system |
| rdtscp | rdtscp | rdtscp | system |
| ret | en_ret、ret、ret_imm、ret_iw | 真 | jump |
| retf | retf、retf_iw | !m64 | jump |
| rol | rol_eb_1、rol_eb_cl、rol_eb_ib、rol_ev_1、rol_ev_cl、rol_ev_ib、rol_rm32_1、rol_rm32_cl、rol_rm32_imm8 | 真 | alu |
| ror | ror_eb_1、ror_eb_cl、ror_eb_ib、ror_ev_1、ror_ev_cl、ror_ev_ib、ror_rm32_1、ror_rm32_imm8 | 真 | alu |
| roundpd | roundpd_xv_wv_ib | sse4_1 | alu |
| roundps | roundps_xv_wv_ib | sse4_1 | alu |
| roundsd | roundsd_xv_wv_ib | sse4_1 | alu |
| roundss | roundss_xv_wv_ib | sse4_1 | alu |
| sahf | sahf | !m64 || lahf_lm | alu |
| salc | salc | !m64 | alu |
| sar | sar_eb_1、sar_eb_cl、sar_eb_ib、sar_ev_1、sar_ev_cl、sar_ev_ib、sar_rm32_1、sar_rm32_cl、sar_rm32_imm8 | 真 | alu |
| sbb | sbb_eb_ib | !m64 | alu |
| sbb | sbb_al_ib、sbb_eax_iz、sbb_eb_gb、sbb_eb_ib、sbb_ev_gv、sbb_ev_ib、sbb_ev_iz、sbb_gb_eb、sbb_gv_ev、sbb_m32_r32_mem8、sbb_m32_r32_sibd、sbb_r_mem32、sbb_r_mem8、sbb_r_memnd、sbb_r_rip、sbb_rm32、sbb_rm32_imm、sbb_rm_imm8、sbb_rm_imm8_sibd | 真 | alu |
| scas | scas_v | 真 | alu |
| scasb | scas_b | 真 | alu |
| seta | seta | 真 | alu |
| setae | setae | 真 | alu |
| setb | setb | 真 | alu |
| setbe | setbe | 真 | alu |
| setcc | setja_eb、setjae_eb、setjb_eb、setjbe_eb、setje_eb、setjg_eb、setjge_eb、setjl_eb、setjle_eb、setjne_eb、setjno_eb、setjnp_eb、setjns_eb、setjo_eb、setjp_eb、setjs_eb | 真 | alu |
| sete | sete、sete_m8_mem32、sete_m8_mem8、sete_m8_rip、sete_m8_sibd | 真 | alu |
| setg | setg | 真 | alu |
| setge | setge | 真 | alu |
| setl | setl | 真 | alu |
| setle | setle、setle_m8_mem32 | 真 | alu |
| setne | setne、setne_m8_mem32、setne_m8_sibd | 真 | alu |
| setno | setno | 真 | alu |
| setnp | setnp | 真 | alu |
| setns | setns | 真 | alu |
| seto | seto | 真 | alu |
| setp | setp | 真 | alu |
| sets | sets | 真 | alu |
| sfence | sfence | sse | alu |
| shl | shl_eb_1、shl_eb_cl、shl_eb_ib、shl_ev_1、shl_ev_cl、shl_ev_ib、shl_m32_imm8_mem8、shl_m8_1_mem32、shl_rm32_1、shl_rm32_cl、shl_rm32_imm8 | 真 | alu |
| shld | shld_ev_gv_cl、shld_ev_gv_ib、shld_r32_cl、shld_r32_imm8 | 真 | alu |
| shr | shr_eb_1、shr_eb_cl、shr_eb_ib、shr_ev_1、shr_ev_cl、shr_ev_ib、shr_rm32_1、shr_rm32_cl、shr_rm32_imm8、shr_rm8_1、shr_rm8_imm8 | 真 | alu |
| shrd | shrd_ev_gv_cl、shrd_ev_gv_ib、shrd_r32_cl、shrd_r32_imm8 | 真 | alu |
| shufpd | shufpd_xv_wv_ib | sse2 | alu |
| shufps | shufps_xv_wv_ib | sse | alu |
| sqrtpd | sqrtpd_xv_wv | sse2 | alu |
| sqrtps | sqrtps_xv_wv | sse | alu |
| sqrtsd | sqrtsd、sqrtsd_xv_wv | sse2 | alu |
| sqrtss | sqrtss_xv_wv | sse | alu |
| stc | stc | 真 | alu |
| std | en_std、std | 真 | alu |
| sti | sti | 真 | system |
| stmxcsr | stmxcsr_md | sse | store |
| stos | stos_v | 真 | store |
| stosb | stos_b、stosb | 真 | store |
| stosd | stosd | 真 | store |
| sub | sub_eb_ib | !m64 | alu |
| sub | sub_al_ib、sub_eax、sub_eax_iz、sub_eb_gb、sub_eb_ib、sub_ev_gv、sub_ev_ib、sub_ev_iz、sub_gb_eb、sub_gv_ev、sub_m32_imm8_sibd32、sub_m32_r32_mem32、sub_m32_r32_mem8、sub_m32_r32_sibd32、sub_m8_r8、sub_m8_r8_sib、sub_m_r_sibd、sub_r_mem32、sub_r_mem8、sub_r_memnd、sub_r_rip、sub_r_sib、sub_r_sibabs、sub_r_sibd、sub_r_sibd32、sub_rm32、sub_rm32_imm、sub_rm64_imm、sub_rm_imm8、sub_rm_imm8_mem32、sub_rm_imm8_mem8、sub_rm_imm8_memnd、sub_rm_imm8_rip、sub_rm_imm8_sibd | 真 | alu |
| subpd | subpd_xv_wv | sse2 | alu |
| subps | subps_xv_wv | sse | alu |
| subsd | subsd、subsd_xv_wv | sse2 | alu |
| subsd | subsd_xmm_m64_mem32、subsd_xmm_m64_mem8、subsd_xmm_m64_rip、subsd_xmm_m64_sibd、subsd_xmm_m64_sibd32 | sse2 | load |
| subss | subss_xv_wv | sse | alu |
| syscall | syscall | m64 && syscall | system |
| syscall | en_syscall | syscall | system |
| sysenter | sysenter | sep | system |
| sysexit | sysexit | sep | system |
| test | test_al_ib、test_al_imm、test_ax_imm16、test_eax_imm、test_eax_iz、test_eb_gb、test_ev_gv、test_m16_imm_mem8、test_m16_imm_memnd、test_m16_imm_rip、test_m8_imm_mem32、test_m8_imm_mem8、test_m8_imm_memnd、test_m8_imm_rip、test_m8_imm_sib、test_m8_imm_sibd、test_m8_imm_sibd32、test_m8_r8_mem32、test_m8_r8_mem8、test_m8_r8_memnd、test_m8_r8_sibd、test_r8_r8、test_r_mem32、test_r_mem8、test_r_sib、test_r_sibabs、test_r_sibd、test_r_sibd32、test_rm16_imm、test_rm32、test_rm32_imm、test_rm32_imm_mem8、test_rm32_imm_memnd、test_rm32_imm_rip、test_rm32_imm_sib、test_rm32_imm_sibd、test_rm32_memnd、test_rm8_imm | 真 | alu |
| test | test_eb_i、test_ev_i | 真 | mult |
| ucomisd | ucomisd、ucomisd_xv_wv | sse2 | alu |
| ucomisd | ucomisd_mem32、ucomisd_mem8、ucomisd_memnd、ucomisd_rip | sse2 | load |
| ucomiss | ucomiss_xv_wv | sse | alu |
| ud1 | ud1 | 真 | system |
| ud2 | ud2 | 真 | system |
| unpckhpd | unpckhpd_xv_wv | sse2 | alu |
| unpckhps | unpckhps_xv_wv | sse | alu |
| unpcklpd | unpcklpd_xv_wv | sse2 | alu |
| unpcklps | unpcklps_xv_wv | sse | alu |
| x87 | fadd_m32、fadd_m64、fcom_m32、fcom_m64、fcomp_m32、fcomp_m64、fdiv_m32、fdiv_m64、fdivr_m32、fdivr_m64、fiadd_m16、fiadd_m32、ficom_m16、ficom_m32、ficomp_m16、ficomp_m32、fidiv_m16、fidiv_m32、fidivr_m16、fidivr_m32、fimul_m16、fimul_m32、fisub_m16、fisub_m32、fisubr_m16、fisubr_m32、fmul_m32、fmul_m64、fsub_m32、fsub_m64、fsubr_m32、fsubr_m64、x87d9_4、x87d9_6、x87db_4、x87dd_4、x87dd_5、x87dd_6 | 真 | alu |
| xadd | xadd_eb_gb、xadd_ev_gv、xadd_r32_memnd、xadd_r32_rip | i486 | alu |
| xchg | xchg_eb_gb、xchg_ev_gv、xchg_r8、xchg_r_mem32、xchg_r_mem8、xchg_r_memnd、xchg_r_rip、xchg_r_rm、xchg_rbp_ax、xchg_rbx_ax、xchg_rcx_ax、xchg_rdi_ax、xchg_rdx_ax、xchg_rsi_ax、xchg_rsp_ax、xchg_rv_eax | 真 | alu |
| xlat | xlat | 真 | load |
| xor | xor_eb_ib | !m64 | alu |
| xor | xor_al_ib、xor_eax_iz、xor_eb_gb、xor_eb_ib、xor_ev_gv、xor_ev_ib、xor_ev_iz、xor_gb_eb、xor_gv_ev、xor_imm、xor_m32_r32_mem32、xor_m32_r32_mem8、xor_m32_r32_memnd、xor_m32_r32_sibd、xor_m8_r8、xor_m8_r8_sib、xor_r8_m8_memnd、xor_r_mem32、xor_r_mem8、xor_r_memnd、xor_r_rip、xor_r_sib、xor_r_sibd、xor_r_sibd32、xor_rm32、xor_rm32_imm、xor_rm32_imm_sibd、xor_rm8_imm、xor_rm8_imm_mem32、xor_rm8_imm_memnd、xor_rm8_imm_sib、xor_rm8_imm_sibd、xor_rm_imm8、xor_rm_imm8_mem32、xor_rm_imm8_mem8、xor_rm_imm8_memnd、xor_rm_imm8_sibd | 真 | alu |
| xorpd | xorpd_xv_wv | sse2 | alu |
| xorps | xorps、xorps_xv_wv | sse | alu |
