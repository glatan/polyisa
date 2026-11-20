// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! llvm-mc とのデコーダ差分（層4・oracle、S15-3）。
//!
//! llvm-mc で組み立てた命令語を polyisa のデコーダで読み、正しい
//! クラスの Insn になることを確かめる。V7/V8 系は `-triple=sparc`、
//! V9/VIS 系は `-triple=sparcv9 -mcpu=ultrasparc3` を使う。
//! FP-ASI 形（`ldfa` 等）と VIS の `fcmp*16/32` は llvm-mc が組めない
//! ため、整数 ASI 形で代替する。
//! ツールがなければ `devtool test:plan` がこのバイナリを実行対象
//! から外す。
//!
//! 使う外部ツールは台帳 TOOL-LLVM（用途X・確認済み）。
//! テストデータは使わない。

use std::process::{Command, Stdio};

fn bin(candidates: &[&str]) -> Option<String> {
    for c in candidates {
        if Command::new(c).arg("--version").output().is_ok() {
            return Some(c.to_string());
        }
    }
    None
}

/// llvm-mc の `--show-encoding` 出力から `encoding: [...]` のバイト列を取り出す。
fn mc_encode(mc: &str, args: &[&str], asm: &str) -> Option<Vec<u8>> {
    let mut child = Command::new(mc)
        .args(args)
        .arg("--show-encoding")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    use std::io::Write as _;
    child.stdin.as_mut()?.write_all(asm.as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let start = text.find("encoding: [")?;
    let rest = &text[start + "encoding: [".len()..];
    let end = rest.find(']')?;
    let mut bytes = Vec::new();
    for tok in rest[..end].split(',') {
        let tok = tok.trim().trim_start_matches("0x");
        if tok.is_empty() {
            continue;
        }
        bytes.push(u8::from_str_radix(tok, 16).ok()?);
    }
    if bytes.is_empty() { None } else { Some(bytes) }
}

/// SPARC の命令はメモリではビッグエンディアンの 4 バイト。
/// `is64` は生成コードでは見ない（モデルは feats の v9 桁が決める）が、
/// 呼び出し側の意図を揃えるため渡す。
fn decode(bytes: &[u8], is64: bool, feats: u128) -> Option<polyisa_guest_sparc::Insn> {
    assert_eq!(bytes.len(), 4, "sparc の命令は 4 バイト");
    let word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    polyisa_guest_sparc::decode_model_ex(u128::from(word), 32, is64, feats)
}

#[test]
fn llvm_oracle_v8_spot_checks() {
    let mc = bin(&["llvm-mc", "/usr/sbin/llvm-mc", "/usr/bin/llvm-mc"])
        .expect("llvm-mc がない（未実行の決定は devtool test:plan が担う）");
    let args = ["-triple=sparc"];
    use polyisa_guest_sparc::Insn::*;
    let feats = polyisa_guest_sparc::FEAT_V7 | polyisa_guest_sparc::FEAT_V8;
    // 代表命令。リロケーションを含まない絶対オペランドだけ使う。
    for (asm, want) in [
        // 整数演算のレジスタ形・即値形・cc 設定形。
        ("add %g1,%g2,%g3\n", Add),
        ("add %g1,5,%g3\n", AddI),
        ("addcc %g1,%g2,%g3\n", Addcc),
        ("subcc %g1,5,%g3\n", SubccI),
        ("addx %g1,%g2,%g3\n", Addx),
        ("subx %g1,5,%g3\n", SubxI),
        ("and %g1,%g2,%g3\n", And),
        ("or %g1,7,%g3\n", OrI),
        ("xor %g1,%g2,%g3\n", Xor),
        ("andn %g1,%g2,%g3\n", Andn),
        ("orn %g1,3,%g3\n", OrnI),
        ("xnor %g1,%g2,%g3\n", Xnor),
        ("sll %g1,%g2,%g3\n", Sll),
        ("sll %g1,9,%g3\n", SllI),
        ("srl %g1,%g2,%g3\n", Srl),
        ("sra %g1,5,%g3\n", SraI),
        ("umul %g1,%g2,%g3\n", Umul),
        ("smulcc %g1,3,%g3\n", SmulccI),
        ("udiv %g1,%g2,%g3\n", Udiv),
        ("sdiv %g1,%g2,%g3\n", Sdiv),
        ("mulscc %g1,%g2,%g3\n", Mulscc),
        // ロード/ストア。
        ("ld [%g1+%g2],%g3\n", Ld),
        ("ld [%g1+8],%g3\n", LdI),
        ("ldub [%g1+1],%g2\n", LdubI),
        ("lduh [%g1],%g2\n", Lduh),
        ("ldd [%g1],%g2\n", Ldd),
        ("st %g3,[%g1+8]\n", StI),
        ("stb %g3,[%g1]\n", Stb),
        ("sth %g3,[%g1]\n", Sth),
        ("std %g2,[%g1]\n", Std),
        ("swap [%g1],%g2\n", Swap),
        ("ldstub [%g1],%g2\n", Ldstub),
        // 制御・分岐。
        ("sethi 0x12345,%g3\n", Sethi),
        ("nop\n", Sethi),
        ("ba 0x100\n", Bicc),
        ("bne 0x100\n", Bicc),
        ("jmpl %g1+%g2,%g3\n", Jmpl),
        ("rett %i7+8\n", RettI),
        ("save %g1,-64,%g2\n", SaveI),
        ("restore %g0,%g0,%g0\n", Restore),
        ("ta 0x10\n", TiccI),
        ("stbar\n", Stbar),
        ("flush %g1\n", Flush),
        ("unimp 0\n", Unimp),
        // 状態レジスタ。
        ("rd %y,%g1\n", Rdy),
        ("wr %g1,%g2,%y\n", Wry),
        ("rd %psr,%g1\n", Rdpsr),
        ("wr %g1,0,%psr\n", WrpsrI),
        ("rd %wim,%g1\n", Rdwim),
        ("rd %tbr,%g1\n", Rdtbr),
        // FPU。
        ("fadds %f0,%f2,%f4\n", Fadds),
        ("faddd %f0,%f2,%f4\n", Faddd),
        ("fmuls %f0,%f2,%f4\n", Fmuls),
        ("fdivd %f0,%f2,%f4\n", Fdivd),
        ("fsmuld %f0,%f2,%f4\n", Fsmuld),
        ("fitos %f0,%f2\n", Fitos),
        ("fstod %f0,%f2\n", Fstod),
        ("fcmps %f0,%f2\n", Fcmps),
        ("fcmped %f0,%f2\n", Fcmped),
        ("fbe 0x100\n", Fbfcc),
        ("ld [%g1],%f0\n", Ldf),
        ("ldd [%g1],%f0\n", Lddf),
        ("st %f0,[%g1]\n", Stf),
        ("std %f0,[%g1]\n", Stdf),
        ("ld [%g1],%fsr\n", Ldfsr),
        ("st %fsr,[%g1]\n", Stfsr),
    ] {
        let enc =
            mc_encode(&mc, &args, asm).unwrap_or_else(|| panic!("llvm-mc が {asm:?} を組めない"));
        let got = decode(&enc, false, feats).unwrap_or_else(|| panic!("{asm:?} 非受理: {enc:?}"));
        assert_eq!(got, want, "{asm:?} -> {got:?} want {want:?}");
    }
}

#[test]
fn llvm_oracle_v9_vis_spot_checks() {
    let mc = bin(&["llvm-mc", "/usr/sbin/llvm-mc", "/usr/bin/llvm-mc"])
        .expect("llvm-mc がない（未実行の決定は devtool test:plan が担う）");
    // llvm-mc の ultrasparc3 は VIS/VIS2 まで組める。
    let args = ["-triple=sparcv9", "-mcpu=ultrasparc3"];
    use polyisa_guest_sparc::Insn::*;
    use polyisa_guest_sparc::{FEAT_V7, FEAT_V8, FEAT_V9, FEAT_VIS, FEAT_VIS2};
    let feats = FEAT_V7 | FEAT_V8 | FEAT_V9 | FEAT_VIS | FEAT_VIS2;
    for (asm, want) in [
        // 64 ビット整数演算・シフト。
        ("mulx %g1,%g2,%g3\n", Mulx),
        ("udivx %g1,%g2,%g3\n", Udivx),
        ("sdivx %g1,5,%g3\n", SdivxI),
        ("sllx %g1,%g2,%g3\n", Sllx),
        ("srlx %g1,9,%g3\n", SrlxI),
        ("srax %g1,%g2,%g3\n", Srax),
        // 64 ビットロード/ストアと符号付き拡張形。
        ("ldx [%g1+%g2],%g3\n", Ldx),
        ("ldx [%g1+8],%g3\n", LdxI),
        ("stx %g3,[%g1+8]\n", StxI),
        ("ldsw [%g1],%g2\n", Ldsw),
        ("ldsh [%g1],%g2\n", Ldsh),
        ("ldsb [%g1],%g2\n", Ldsb),
        // V9 分岐・述語実行。アニュール（,a）はクラスを変えない。
        ("ba %icc,0x100\n", Bpcc),
        ("bne %xcc,0x100\n", Bpcc),
        ("bne,a %xcc,0x100\n", Bpcc),
        ("brz %g1,0x100\n", Bpr),
        ("brgez %g1,0x100\n", Bpr),
        ("brz,a %g1,0x100\n", Bpr),
        ("fbe %fcc1,0x100\n", Fbpfcc),
        ("fbe,a %fcc1,0x100\n", Fbpfcc),
        ("movne %xcc,%g1,%g3\n", Movcc),
        ("move %icc,7,%g3\n", MovccI),
        ("movrz %g1,5,%g3\n", MovrI),
        ("movrnz %g1,%g2,%g3\n", Movr),
        ("fmovsne %xcc,%f0,%f2\n", Fmovscc),
        ("fmovdn %xcc,%f0,%f2\n", Fmovdcc),
        ("fmovsge %fcc1,%f0,%f2\n", Fmovsfcc),
        ("fmovrsz %g1,%f0,%f2\n", Fmovrs),
        ("popc %g1,%g2\n", Popc),
        // アトミック・メモリバリア。
        ("casa [%g1]0x80,%g2,%g3\n", Casa),
        ("casxa [%g1]0x82,%g2,%g3\n", Casxa),
        ("membar #StoreStore\n", Membar),
        ("prefetch [%g1+%g2],2\n", Prefetch),
        ("prefetch [%g1],0\n", Prefetch),
        ("prefetch [%g1+4],2\n", PrefetchI),
        // ウィンドウ・特権。
        ("flushw\n", Flushw),
        ("saved\n", Saved),
        ("restored\n", Restored),
        ("return %i7+8\n", ReturnI),
        ("rdpr %pil,%g1\n", Rdpr),
        ("wrpr %g1,%g2,%pil\n", Wrpr),
        ("wrpr %g1,3,%pil\n", WrprI),
        ("done\n", Done),
        ("retry\n", Retry),
        // V9 トラップ。%xcc は Tccx、%icc は Ticc と同じ符号化。
        ("ta %xcc,%g1+%g2\n", Tccx),
        ("ta %xcc,%g1+0x20\n", TccxI),
        ("tn %icc,%g1\n", Ticc),
        // ASI 付きロード/ストア（整数形）。
        ("ldxa [%g1]0x80,%g2\n", Ldxa),
        ("stxa %g2,[%g1]0x80\n", Stxa),
        ("lduba [%g1]0x10,%g2\n", Lduba),
        ("stba %g2,[%g1]0x10\n", Stba),
        // 状態レジスタ。
        ("rd %pc,%g1\n", Rdpc),
        ("rd %ccr,%g1\n", Rdccr),
        ("wr %g1,%g2,%ccr\n", Wrccr),
        ("rd %asi,%g1\n", Rdasi),
        ("wr %g1,0,%asi\n", WrasiI),
        ("rd %fprs,%g1\n", Rdfprs),
        ("wr %g1,0,%fprs\n", WrfprsI),
        ("ldx [%g1],%fsr\n", Ldxfsr),
        ("stx %fsr,[%g1]\n", Stxfsr),
        // FPU 単項・変換。
        ("fmovs %f0,%f2\n", Fmovs),
        ("fnegs %f0,%f2\n", Fnegs),
        ("fabss %f0,%f2\n", Fabss),
        ("fsqrts %f0,%f2\n", Fsqrts),
        ("fxtos %f0,%f2\n", Fxtos),
        ("fdtox %f0,%f2\n", Fdtox),
        ("fdtos %f0,%f2\n", Fdtos),
        ("fstoi %f0,%f2\n", Fstoi),
        ("fitod %f0,%f2\n", Fitod),
        // VIS。
        ("fzeros %f0\n", Fzeros),
        ("fones %f4\n", Fones),
        ("fzero %f6\n", Fzero),
        ("fsrc1 %f0,%f2\n", Fsrc1),
        ("fnot1s %f0,%f2\n", Fnot1s),
        ("fpadd16 %f0,%f2,%f4\n", Fpadd16),
        ("fpadd16s %f0,%f2,%f4\n", Fpadd16s),
        ("fpadd32 %f0,%f2,%f4\n", Fpadd32),
        ("fpadd32s %f0,%f2,%f4\n", Fpadd32s),
        ("fpsub32 %f0,%f2,%f4\n", Fpsub32),
        ("fmul8x16 %f0,%f2,%f4\n", Fmul8x16),
        ("fmul8x16au %f0,%f2,%f4\n", Fmul8x16au),
        ("fmul8x16al %f0,%f2,%f4\n", Fmul8x16al),
        ("fmul8sux16 %f0,%f2,%f4\n", Fmul8sux16),
        ("fmuld8sux16 %f0,%f2,%f4\n", Fmuld8sux16),
        ("fpack32 %f0,%f2,%f4\n", Fpack32),
        ("fpack16 %f2,%f4\n", Fpack16),
        ("fpackfix %f0,%f2\n", Fpackfix),
        ("pdist %f0,%f2,%f4\n", Pdist),
        ("faligndata %f0,%f2,%f4\n", Faligndata),
        ("fpmerge %f0,%f2,%f4\n", Fpmerge),
        ("fexpand %f0,%f2\n", Fexpand),
        ("fnand %f0,%f2,%f4\n", Fnand),
        ("fxor %f0,%f2,%f4\n", Fxor),
        ("fnor %f0,%f2,%f4\n", Fnor),
        ("fands %f0,%f2,%f4\n", Fands),
        ("fornot2 %f0,%f2,%f4\n", Fornot2),
        ("edge8 %g1,%g2,%g3\n", Edge8cc),
        ("edge8l %g1,%g2,%g3\n", Edge8lcc),
        ("edge16 %g1,%g2,%g3\n", Edge16cc),
        ("edge32 %g1,%g2,%g3\n", Edge32cc),
        ("edge8n %g1,%g2,%g3\n", Edge8n),
        ("edge8ln %g1,%g2,%g3\n", Edge8ln),
        ("edge16n %g1,%g2,%g3\n", Edge16n),
        ("edge32n %g1,%g2,%g3\n", Edge32n),
        ("edge16ln %g1,%g2,%g3\n", Edge16ln),
        ("edge32ln %g1,%g2,%g3\n", Edge32ln),
        ("array8 %g1,%g2,%g3\n", Array8),
        ("array16 %g1,%g2,%g3\n", Array16),
        ("array32 %g1,%g2,%g3\n", Array32),
        ("alignaddr %g1,%g2,%g3\n", Alignaddr),
        ("alignaddrl %g1,%g2,%g3\n", Alignaddrl),
        ("bmask %g1,%g2,%g3\n", Bmask),
        ("bshuffle %f0,%f2,%f4\n", Bshuffle),
        ("rd %gsr,%g1\n", Rdgsr),
        ("wr %g1,%g2,%gsr\n", Wrgsr),
    ] {
        let enc =
            mc_encode(&mc, &args, asm).unwrap_or_else(|| panic!("llvm-mc が {asm:?} を組めない"));
        let got = decode(&enc, true, feats).unwrap_or_else(|| panic!("{asm:?} 非受理: {enc:?}"));
        assert_eq!(got, want, "{asm:?} -> {got:?} want {want:?}");
    }
    // V9 だけの命令は V8 モデルでは受理しない（例: mulx）。
    let enc = mc_encode(&mc, &args, "mulx %g1,%g2,%g3\n").unwrap();
    assert_eq!(decode(&enc, false, FEAT_V7 | FEAT_V8), None);
}
