# x86 最小

段階4の最小。`SPEC-X86-INTEL-SDM` Combined v093 の確認済み項目を使う。
可変長（8/16/24/32/40ビット）のデコード入口を確かめる。ModRM/SIB フック（register-direct、
mod=01+disp8、SIB base+index 最小形、SIB+disp8 を除く）・EFLAGS(SF/OF/PF/AF)・
セグメント・64ビット・x87・SSE は本格実装で足す。
