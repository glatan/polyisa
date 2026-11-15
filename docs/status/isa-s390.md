# 実装状況：s390

このファイルは `task status` が生成する。手で編集しない。

生成の元は `guests/s390/spec/zarch.rs` である。

## CPU モデル

| 名前 | 親 | 足す機能 | 除く機能 |
|---|---|---|---|
| esa390 |  |  | zarch |
| generic | z13 |  |  |
| z10ec | z9ec |  |  |
| z13 | zec12 |  |  |
| z196 | z10ec |  |  |
| z900 |  | zarch |  |
| z990 | z900 |  |  |
| z9ec | z990 | long-disp |  |
| zec12 | z196 |  |  |

## 機能

- dfp
- ext-imm
- hfp
- long-disp
- zarch

## 命令

| ニーモニック | 記述 | 条件 | タイミング |
|---|---|---|---|
| a | a | 真 | alu |
| ad | ad | 真 | fp |
| adr | adr | 真 | fp |
| ae | ae | 真 | fp |
| aer | aer | 真 | fp |
| afi | afi | 真 | alu |
| agfi | agfi | 真 | alu |
| aghi | aghi | 真 | alu |
| ah | ah | 真 | alu |
| ahi | ahi | 真 | alu |
| al | al | 真 | alu |
| alfi | alfi | 真 | alu |
| algfi | algfi | 真 | alu |
| alr | alr | 真 | alu |
| ap | ap | 真 | string |
| ar | ar | 真 | alu |
| au | au | 真 | fp |
| aw | aw | 真 | fp |
| awr | awr | 真 | fp |
| axr | axr | 真 | fp |
| b3 | b3 | 真 | fp |
| b9 | b9 | 真 | alu |
| bal | bal | 真 | branch |
| balr | balr | 真 | branch |
| bas | bas | 真 | branch |
| basr | basr | 真 | branch |
| bassm | bassm | 真 | branch |
| bc | bc | 真 | branch |
| bcr | bcr | 真 | branch |
| bct | bct | 真 | branch |
| bctr | bctr | 真 | branch |
| bras | bras | 真 | branch |
| brasl | brasl | 真 | branch |
| brc | brc | 真 | branch |
| brcl | brcl | 真 | branch |
| brct | brct | 真 | branch |
| brctg | brctg | 真 | branch |
| brh | brh | 真 | branch |
| brul | brul | 真 | branch |
| brxh | brxh | 真 | branch |
| brxle | brxle | 真 | branch |
| bsm | bsm | 真 | branch |
| bxh | bxh | 真 | branch |
| bxle | bxle | 真 | branch |
| c | c | 真 | alu |
| cd | cd | 真 | fp |
| cdr | cdr | 真 | fp |
| cds | cds | 真 | alu |
| ce | ce | 真 | fp |
| cer | cer | 真 | fp |
| cfi | cfi | 真 | alu |
| cgfi | cgfi | 真 | alu |
| cgfrl | cgfrl | 真 | alu |
| cghi | cghi | 真 | alu |
| cghrl | cghrl | 真 | alu |
| cgrl | cgrl | 真 | alu |
| ch | ch | 真 | alu |
| chi | chi | 真 | alu |
| chrl | chrl | 真 | alu |
| cl | cl | 真 | alu |
| clc | clc | 真 | string |
| clcl | clcl | 真 | string |
| clcle | clcle | 真 | string |
| clfi | clfi | 真 | alu |
| clgfi | clgfi | 真 | alu |
| clgfrl | clgfrl | 真 | alu |
| clghrl | clghrl | 真 | alu |
| clgrl | clgrl | 真 | alu |
| clhrl | clhrl | 真 | alu |
| cli | cli | 真 | alu |
| clm | clm | 真 | alu |
| clr | clr | 真 | alu |
| clrl | clrl | 真 | alu |
| cp | cp | 真 | string |
| cr | cr | 真 | alu |
| crl | crl | 真 | alu |
| cs | cs | 真 | alu |
| cvb | cvb | 真 | alu |
| cvd | cvd | 真 | alu |
| d | d | 真 | div |
| dd | dd | 真 | fp |
| ddr | ddr | 真 | fp |
| de | de | 真 | fp |
| der | der | 真 | fp |
| diag | diag | 真 | system |
| dp | dp | 真 | string |
| dr | dr | 真 | div |
| e3 | e3 | 真 | alu |
| e5 | e5 | 真 | system |
| e_misc | e_misc | 真 | system |
| eb | eb | 真 | alu |
| ec | ec | 真 | alu |
| ed | ed | 真 | string |
| edmk | edmk | 真 | string |
| ex | ex | 真 | system |
| exrl | exrl | 真 | system |
| hdr | hdr | 真 | fp |
| her | her | 真 | fp |
| ic | ic | 真 | load |
| icm | icm | 真 | load |
| iihf | iihf | 真 | alu |
| iilf | iilf | 真 | alu |
| l | l | 真 | load |
| la | la | 真 | alu |
| lae | lae | 真 | alu |
| lam | lam | 真 | load |
| larl | larl | 真 | alu |
| lcdr | lcdr | 真 | fp |
| lcer | lcer | 真 | fp |
| lcr | lcr | 真 | alu |
| ld | ld | 真 | load |
| ldr | ldr | 真 | fp |
| ldxr | ldxr | 真 | fp |
| le | le | 真 | load |
| ledr | ledr | 真 | fp |
| ler | ler | 真 | fp |
| lgfi | lgfi | 真 | alu |
| lgfrl | lgfrl | 真 | load |
| lghi | lghi | 真 | alu |
| lghrl | lghrl | 真 | load |
| lgrl | lgrl | 真 | load |
| lh | lh | 真 | load |
| lhi | lhi | 真 | alu |
| lhrl | lhrl | 真 | load |
| llgfrl | llgfrl | 真 | load |
| llghrl | llghrl | 真 | load |
| llhrl | llhrl | 真 | load |
| llihf | llihf | 真 | alu |
| llihh | llihh | 真 | alu |
| llihl | llihl | 真 | alu |
| llilf | llilf | 真 | alu |
| llilh | llilh | 真 | alu |
| llill | llill | 真 | alu |
| lm | lm | 真 | load |
| lndr | lndr | 真 | fp |
| lner | lner | 真 | fp |
| lnr | lnr | 真 | alu |
| lpdr | lpdr | 真 | fp |
| lper | lper | 真 | fp |
| lpr | lpr | 真 | alu |
| lr | lr | 真 | alu |
| lrl | lrl | 真 | load |
| ltdr | ltdr | 真 | fp |
| lter | lter | 真 | fp |
| ltr | ltr | 真 | alu |
| md | md | 真 | fp |
| mde | mde | 真 | fp |
| mdr | mdr | 真 | fp |
| mer | mer | 真 | fp |
| mghi | mghi | 真 | mult |
| mh | mh | 真 | mult |
| mhi | mhi | 真 | mult |
| mp | mp | 真 | string |
| mr | mr | 真 | mult |
| ms | ms | 真 | mult |
| msfi | msfi | 真 | alu |
| msgfi | msgfi | 真 | alu |
| mulw | mulw | 真 | mult |
| mvc | mvc | 真 | string |
| mvcl | mvcl | 真 | string |
| mvcle | mvcle | 真 | string |
| mvi | mvi | 真 | store |
| mvn | mvn | 真 | string |
| mvo | mvo | 真 | string |
| mvz | mvz | 真 | string |
| mxd | mxd | 真 | fp |
| mxdr | mxdr | 真 | fp |
| mxr | mxr | 真 | fp |
| n | n | 真 | alu |
| nc | nc | 真 | string |
| ni | ni | 真 | alu |
| nihf | nihf | 真 | alu |
| nihh | nihh | 真 | alu |
| nihl | nihl | 真 | alu |
| nilf | nilf | 真 | alu |
| nilh | nilh | 真 | alu |
| nill | nill | 真 | alu |
| nr | nr | 真 | alu |
| o | o | 真 | alu |
| oc | oc | 真 | string |
| oi | oi | 真 | alu |
| oihf | oihf | 真 | alu |
| oihh | oihh | 真 | alu |
| oihl | oihl | 真 | alu |
| oilf | oilf | 真 | alu |
| oilh | oilh | 真 | alu |
| oill | oill | 真 | alu |
| or | or | 真 | alu |
| pack | pack | 真 | string |
| rxe | rxe | 真 | fp |
| s | s | 真 | alu |
| s_b2 | s_b2 | 真 | system |
| sd | sd | 真 | fp |
| sdr | sdr | 真 | fp |
| se | se | 真 | fp |
| ser | ser | 真 | fp |
| sh | sh | 真 | alu |
| sl | sl | 真 | alu |
| sla | sla | 真 | alu |
| slda | slda | 真 | alu |
| sldl | sldl | 真 | alu |
| slfi | slfi | 真 | alu |
| slgfi | slgfi | 真 | alu |
| sll | sll | 真 | alu |
| slr | slr | 真 | alu |
| sp | sp | 真 | string |
| spm | spm | 真 | system |
| sr | sr | 真 | alu |
| sra | sra | 真 | alu |
| srda | srda | 真 | alu |
| srdl | srdl | 真 | alu |
| srl | srl | 真 | alu |
| srp | srp | 真 | system |
| st | st | 真 | store |
| stam | stam | 真 | store |
| stc | stc | 真 | store |
| stcm | stcm | 真 | store |
| std | std | 真 | store |
| ste | ste | 真 | store |
| stgrl | stgrl | 真 | store |
| sth | sth | 真 | store |
| sthrl | sthrl | 真 | store |
| stm | stm | 真 | store |
| stnsm | stnsm | 真 | system |
| stosm | stosm | 真 | system |
| strl | strl | 真 | store |
| su | su | 真 | fp |
| svc | svc | 真 | system |
| sw | sw | 真 | fp |
| swr | swr | 真 | fp |
| sxr | sxr | 真 | fp |
| tm | tm | 真 | alu |
| tmhh | tmhh | 真 | alu |
| tmhl | tmhl | 真 | alu |
| tmlh | tmlh | 真 | alu |
| tmll | tmll | 真 | alu |
| tr | tr | 真 | string |
| trt | trt | 真 | string |
| ts | ts | 真 | system |
| unpk | unpk | 真 | string |
| x | x | 真 | alu |
| x08 | x08 | 真 | system |
| x09 | x09 | 真 | system |
| x3e | x3e | 真 | alu |
| x3f | x3f | 真 | alu |
| xc | xc | 真 | string |
| xi | xi | 真 | alu |
| xihf | xihf | 真 | alu |
| xilf | xilf | 真 | alu |
| xr | xr | 真 | alu |
| zap | zap | 真 | string |
