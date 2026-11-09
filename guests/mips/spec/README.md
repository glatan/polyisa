# MIPS I 試作

段階3の最小。`SPEC-MIPS-IV` Rev 3.2、`SPEC-MIPS-R3000`、`SPEC-MIPS-ABI` o32 の確認済み項目を使う。
遅延スロットのステップ構成と HI/LO 乗除算を確かめる。ADD/SUB trap・R6・FPU・ロード遅延・branch likely・LE切替は本格実装で足す。div-by-zero は HI/LO 不変とする（挙動パラメータ化は本格実装）。R3000/ABI o32 は将来参照であり現試作に含めない。
