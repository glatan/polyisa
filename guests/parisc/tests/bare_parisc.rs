// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! PA-RISC の命令語単位のデコード検査（段階17・PR3）。
//! 生成デコーダがリテラル語を正しく分類し、arch/MAX 完語で
//! ゲートされることを見る。即値や変位の復元は意味論側なので
//! ここでは命令種別だけを見る。末尾は interp バックエンドでの
//! 裸実行検査（定数形成・加算・分岐無効化・bv・ble）。
//! 出典は SPEC-PARISC-11・SPEC-PARISC-20 である。
//! Ref: SPEC-PARISC-11, SPEC-PARISC-20.

use polyisa_guest_parisc::*;

const ALL: u128 = FEAT_PA11 | FEAT_PA20 | FEAT_MAX1 | FEAT_MAX2;
const PA11: u128 = FEAT_PA11;
const PA11_MAX1: u128 = FEAT_PA11 | FEAT_MAX1;
// pa8000 モデルの機能集合（PA 2.0 + MAX-2、MAX-1 なし）。
const PA8000: u128 = FEAT_PA11 | FEAT_PA20 | FEAT_MAX2;

fn dec(word: u32) -> Option<Insn> {
    decode_model_ex(word as u128, 32, false, ALL)
}

fn decf(word: u32, feats: u128) -> Option<Insn> {
    decode_model_ex(word as u128, 32, false, feats)
}

#[test]
fn decode_core_arith() {
    // add r1,r2,r3（opcode 0x02、pos20-27=011000、d=0）。
    assert_eq!(dec(0x0822_0603), Some(Insn::Add));
    // and/or/xor/uxor/sub/cmpclr（同形式で拡張桁だけが違う）。
    assert_eq!(dec(0x0822_0203), Some(Insn::And));
    assert_eq!(dec(0x0822_0243), Some(Insn::Or));
    assert_eq!(dec(0x0822_0283), Some(Insn::Xor));
    assert_eq!(dec(0x0822_0383), Some(Insn::Uxor));
    assert_eq!(dec(0x0822_0403), Some(Insn::Sub));
    assert_eq!(dec(0x0822_0883), Some(Insn::Cmpclr));
    // add,c は sh=0 固定、0111 + sh!=0 は MAX-1 の hshladd。
    assert_eq!(dec(0x0822_0703), Some(Insn::AddC));
    assert_eq!(dec(0x0822_0743), Some(Insn::Hshladd));
    // MAX-1 半語演算（pos16-25 の拡張桁で区別）。
    assert_eq!(dec(0x0822_03c3), Some(Insn::Hadd));
    assert_eq!(dec(0x0822_02c3), Some(Insn::Havg));
    assert_eq!(dec(0x0822_01c3), Some(Insn::Hsub));
}

#[test]
fn decode_immediates() {
    // ldil L%0x123456,r1 / addil 2,r1 / ldo 4(r2),r3。
    assert_eq!(dec(0x2032_3456), Some(Insn::Ldil));
    assert_eq!(dec(0x2820_0002), Some(Insn::Addil));
    assert_eq!(dec(0x3443_0008), Some(Insn::Ldo));
    // addi 5,r4,r5 と ,tsv / subi / cmpiclr（11 ビット即値形）。
    assert_eq!(dec(0xb485_000a), Some(Insn::Addi));
    assert_eq!(dec(0xb485_080a), Some(Insn::AddiTsv));
    assert_eq!(dec(0x9485_000a), Some(Insn::Subi));
    assert_eq!(dec(0x9085_000a), Some(Insn::Cmpiclr));
}

#[test]
fn decode_memory() {
    // オフセット形式（opcode 0x10-0x1b の 14 ビット + sp）。
    assert_eq!(dec(0x4043_0000), Some(Insn::Ldb));
    assert_eq!(dec(0x4443_0000), Some(Insn::Ldh));
    assert_eq!(dec(0x4843_0000), Some(Insn::Ldw));
    assert_eq!(dec(0x4c43_0000), Some(Insn::Ldwm));
    assert_eq!(dec(0x6862_0000), Some(Insn::Stw));
    assert_eq!(dec(0x6c62_0000), Some(Insn::Stwm));
    // index 形式（opcode 0x03、pos19=0、pos22-25 が完語）。
    assert_eq!(dec(0x0c43_0084), Some(Insn::Ldx));
    assert_eq!(dec(0x0c43_01c4), Some(Insn::Ldcwx));
    // im5 形式（pos19=1）。
    assert_eq!(dec(0x0c43_1084), Some(Insn::Ldi));
    // stby/stdby（pos22-25=1100/1101）。
    assert_eq!(dec(0x0c43_3304), Some(Insn::Stby));
    assert_eq!(dec(0x0c43_3344), Some(Insn::Stdby));
    // FP の index/offset 形。
    assert_eq!(dec(0x2443_0004), Some(Insn::Fldwx));
    assert_eq!(dec(0x2c43_0004), Some(Insn::Flddx));
    assert_eq!(dec(0x5843_0000), Some(Insn::FldwO));
    assert_eq!(dec(0x5c43_0004), Some(Insn::Ldwm2));
    assert_eq!(dec(0x7c62_0004), Some(Insn::Stwm2));
    // PA 2.0 の 64 ビット形（0x14/0x1c、pos30 が 0/1）。
    assert_eq!(dec(0x5043_0000), Some(Insn::Ldd));
    assert_eq!(dec(0x5043_0002), Some(Insn::Fldd));
    assert_eq!(dec(0x7043_0000), Some(Insn::Std));
    assert_eq!(dec(0x7043_0002), Some(Insn::Fstd));
}

#[test]
fn decode_branches() {
    // be/ble（opcode 0x38/0x39）。
    assert_eq!(dec(0xe042_0010), Some(Insn::Be));
    assert_eq!(dec(0xe442_0010), Some(Insn::Ble));
    // bl/gate/bl,push/bl long（pos16-18 が形を分ける）。
    assert_eq!(dec(0xebe0_0008), Some(Insn::Bl));
    assert_eq!(dec(0xebe0_2008), Some(Insn::Gate));
    assert_eq!(dec(0xebe0_8008), Some(Insn::BlPush));
    assert_eq!(dec(0xe800_a010), Some(Insn::BlLong));
    // blr/bv/bve（pos16-18=010/110/111）。
    assert_eq!(dec(0xe849_4000), Some(Insn::Blr));
    assert_eq!(dec(0xe840_c000), Some(Insn::Bv));
    assert_eq!(dec(0xe840_d000), Some(Insn::Bve));
    assert_eq!(dec(0xe840_f000), Some(Insn::BveL));
    // 条件分岐（opcode で系統、pos30 が n）。
    assert_eq!(dec(0x8022_0004), Some(Insn::Cmpb));
    assert_eq!(dec(0x8822_0004), Some(Insn::CmpbF));
    assert_eq!(dec(0x8422_0004), Some(Insn::Cmpbi));
    assert_eq!(dec(0xa022_0004), Some(Insn::Addb));
    assert_eq!(dec(0xc822_0004), Some(Insn::Movb));
    assert_eq!(dec(0xcc22_0004), Some(Insn::Movbi));
    // bb（pos17 の 1 が条件判定ビット選択の固定桁）。
    assert_eq!(dec(0xc005_c000), Some(Insn::BbSar));
    assert_eq!(dec(0xc405_c000), Some(Insn::BbImm));
}

#[test]
fn decode_shift_extract_deposit() {
    // shrp（pos19-21 が SAR/imm/d 形を分ける）。
    assert_eq!(dec(0xd064_0005), Some(Insn::ShrpSar));
    assert_eq!(dec(0xd064_0205), Some(Insn::ShrpSar));
    assert_eq!(dec(0xd064_0805), Some(Insn::ShrpImm));
    assert_eq!(dec(0xd064_0c05), Some(Insn::ShrpImmD));
    // extr（pos19-20=10/11、pos22 が d=1 形の桁）。
    assert_eq!(dec(0xd064_1005), Some(Insn::ExtrSar));
    assert_eq!(dec(0xd064_1205), Some(Insn::ExtrSarD));
    assert_eq!(dec(0xd064_1805), Some(Insn::ExtrImm));
    assert_eq!(dec(0xd864_1805), Some(Insn::ExtrImmD));
    // dep/depi（opcode 0x35/0x3c/0x3d。pos19-20=bits12-11 が
    // SAR/imm/depi を分け、depi_sar は pos22 が d 選択）。
    assert_eq!(dec(0xd464_0005), Some(Insn::DepSar));
    assert_eq!(dec(0xd464_0205), Some(Insn::DepSarD));
    assert_eq!(dec(0xd464_0805), Some(Insn::DepImm));
    assert_eq!(dec(0xf064_1805), Some(Insn::DepImmD));
    assert_eq!(dec(0xd464_1005), Some(Insn::DepiSar));
    assert_eq!(dec(0xd464_1805), Some(Insn::DepiImm));
    assert_eq!(dec(0xf464_1c05), Some(Insn::DepiImmD));
}

#[test]
fn decode_system() {
    // opcode 0x00 の pos19-26 が副 opcode。
    assert_eq!(dec(0x0064_0000), Some(Insn::Break));
    assert_eq!(dec(0x0000_0400), Some(Insn::Sync));
    assert_eq!(dec(0x0004_1820), Some(Insn::Mtsp));
    assert_eq!(dec(0x0084_1840), Some(Insn::Mtctl));
    assert_eq!(dec(0x0004_1860), Some(Insn::Mtsm));
    assert_eq!(dec(0x0000_04a5), Some(Insn::Mfsp));
    assert_eq!(dec(0x0000_08a5), Some(Insn::Mfctl));
    assert_eq!(dec(0x0000_10a5), Some(Insn::Ldsid));
    assert_eq!(dec(0x0000_0e65), Some(Insn::Rsm));
    assert_eq!(dec(0x0000_0d65), Some(Insn::Ssm));
    assert_eq!(dec(0x0000_0c00), Some(Insn::Rfi));
    assert_eq!(dec(0x0000_0ca0), Some(Insn::RfiR));
    assert_eq!(dec(0x1400_0000), Some(Insn::Diag));
    // opcode 0x01 のメモリ管理。
    assert_eq!(dec(0x0440_3280), Some(Insn::Fdc));
    assert_eq!(dec(0x0440_1200), Some(Insn::Pxtlb));
    assert_eq!(dec(0x0440_1340), Some(Insn::Lpa));
}

#[test]
fn decode_fp() {
    // fid と class 0/1/2/3（opcode 0x0c。class 完語は
    // pos16-26＝bits15-5 に埋まる）。
    assert_eq!(dec(0x3000_0000), Some(Insn::FidF));
    assert_eq!(dec(0x3020_4002), Some(Insn::FcpyF));
    assert_eq!(dec(0x3020_4802), Some(Insn::FcpyD));
    assert_eq!(dec(0x3020_0a02), Some(Insn::FcnvDF));
    assert_eq!(dec(0x3022_0400), Some(Insn::FcmpF));
    assert_eq!(dec(0x3000_0420), Some(Insn::Ftest));
    assert_eq!(dec(0x3022_0603), Some(Insn::FaddF));
    // fmt は pos19-20＝bits12-11。
    assert_eq!(dec(0x3022_0e03), Some(Insn::FaddD));
    // fmpyadd/fmpysub（opcode 0x06/0x26、pos26＝bit5 が fmt）。
    assert_eq!(dec(0x1822_0020), Some(Insn::FmpyaddF));
    assert_eq!(dec(0x1822_0000), Some(Insn::FmpyaddD));
    assert_eq!(dec(0x9822_0020), Some(Insn::FmpysubF));
}

#[test]
fn decode_max2() {
    // hshl/mixh/permh（opcode 0x3e、MAX-2）。
    assert_eq!(dec(0xf800_8903), Some(Insn::Hshl));
    assert_eq!(dec(0xf820_8404), Some(Insn::MixhL));
    assert_eq!(dec(0xf822_6644), Some(Insn::Permh));
}

#[test]
fn feature_gates() {
    // PA 2.0 完語は pa20 が無いと解けない。
    for (word, want) in [
        (0x5043_0000, Insn::Ldd),
        (0x0c43_3344, Insn::Stdby),
        (0xe840_d000, Insn::Bve),
        (0xd064_0c05, Insn::ShrpImmD),
        (0x9c22_0004, Insn::CmpbD),
        (0xec22_0004, Insn::CmpbiD),
        (0x0000_14a5, Insn::Mfia),
        (0x0440_0800, Insn::Ixtlbt),
        (0x3020_4002, Insn::FcpyF),
    ] {
        assert_eq!(decf(word, ALL), Some(want), "{word:#x}");
    }
    // これらは PA 1.1 のみでは解けない。
    for word in [
        0x5043_0000u32,
        0x0c43_3344,
        0xe840_d000,
        0xd064_0c05,
        0x9c22_0004,
        0xec22_0004,
        0x0440_0800,
    ] {
        assert_eq!(decf(word, PA11), None, "{word:#x}");
    }
    // PA 2.0 付録C にのみある命令は PA 1.1 機では解けない。
    // mtsarcm / mfia / fdc / fic4f / bl,push / bl long /
    // fldw/fstw のオフセット形 / fneg,f / fcnv,uw,f。
    for (word, want) in [
        (0x0161_18c0u32, Insn::Mtsarcm),
        (0x0000_14a5, Insn::Mfia),
        (0x0440_3280, Insn::Fdc),
        (0x0442_13c0, Insn::Fic4f),
        (0xebe0_8008, Insn::BlPush),
        (0xe800_a010, Insn::BlLong),
        (0x5843_0000, Insn::FldwO),
        (0x7843_0000, Insn::FstwO),
        (0x3020_c002, Insn::FnegF),
        (0x3022_8202, Insn::FcnvUwF),
    ] {
        assert_eq!(decf(word, PA8000), Some(want), "{word:#x}");
        assert_eq!(decf(word, PA11), None, "{word:#x}");
    }
    // opcode 0x0e の PA 2.0 FP 形。
    assert_eq!(decf(0x3820_4002, ALL), Some(Insn::FcpyFw));
    assert_eq!(decf(0x3820_4002, PA11), None);
    // xmpyu は PA1.1 Table D-20 にもあるので PA 1.1 で解ける。
    assert_eq!(decf(0x3800_4700, ALL), Some(Insn::Xmpyu));
    assert_eq!(decf(0x3800_4700, PA11), Some(Insn::Xmpyu));
    // 半語加減算と PERMH は MAX-1 にも MAX-2 にもある。
    assert_eq!(decf(0x0822_03c3, PA11_MAX1), Some(Insn::Hadd));
    assert_eq!(decf(0x0822_03c3, PA8000), Some(Insn::Hadd));
    assert_eq!(decf(0x0822_03c3, PA11), None);
    assert_eq!(decf(0xf822_6644, PA8000), Some(Insn::Permh));
    assert_eq!(decf(0xf822_6644, PA11_MAX1), Some(Insn::Permh));
    assert_eq!(decf(0xf800_8903, ALL), Some(Insn::Hshl));
    assert_eq!(decf(0xf800_8903, PA11_MAX1), None);
    // PA1.x 専用の ixtlbx は pa20 機では解けない（ixtlbt は
    // 別の固定桁を持つのでフォールスルーしない）。
    assert_eq!(decf(0x0440_1000, PA11), Some(Insn::IxtlbxD));
    assert_eq!(decf(0x0440_1000, ALL), None);
    // 未定義語は落ちる。
    assert_eq!(dec(0xffff_ffff), None);
}

#[test]
fn extract_operands_regression() {
    // hshr の r は pos6-10（bits25-21）。hshl とは桁が違う。
    // hshr,s r9,4,r7。
    let w = 0xf920_cd07;
    assert_eq!(dec(w), Some(Insn::HshrS));
    assert_eq!(extract_ops(Insn::HshrS, w as u128), vec![9, 4, 7]);
    // 分岐変位は bit0（pos31）の符号素材まで届く。取出し値は
    // bits12-2<<1 | bit0。be で符号ビットを立てた形。
    let w = 0xe020_0555;
    assert_eq!(dec(w), Some(Insn::Be));
    let ops = extract_ops(Insn::Be, w as u128);
    assert_eq!(ops[3], 0x2ab);
    assert_eq!(ops[4], 0);
    // _s 形の sp は assemble_sr3x＝bits15-13 の 3 ビット
    // （sp2 なら上位 2 ビットしか取れない）。
    let w = 0x0422_a220;
    assert_eq!(decf(w, PA11), Some(Insn::PxtlbS));
    assert_eq!(extract_ops(Insn::PxtlbS, w as u128), vec![1, 2, 5, 1]);
    let w = 0x0464_c040;
    assert_eq!(decf(w, PA11), Some(Insn::IxtlbxI));
    assert_eq!(extract_ops(Insn::IxtlbxI, w as u128), vec![3, 4, 6, 1]);
    // fic（instruction MM）の s も Figure D-2/C-2 上 3 ビット
    // （bits16:18）。sp=5 は 2 ビットでは表せない。
    let w = 0x0441_a2a0;
    assert_eq!(dec(w), Some(Insn::Fic));
    assert_eq!(extract_ops(Insn::Fic, w as u128), vec![2, 1, 5, 1]);
    // break のレイアウトは spec の `00 im13 00 im5`（im13 =
    // bits25-13、im5 = bits4-0）。旧宣言の fa/fb（i3/i5）は
    // im13 の一部で、真の im5 桁は取れていなかった。
    // Ref: SPEC-PARISC-11 §BREAK, SPEC-PARISC-20 §7-18.
    let w = 0x0246_8005; // break 5,0x1234
    assert_eq!(dec(w), Some(Insn::Break));
    assert_eq!(extract_ops(Insn::Break, w as u128), vec![5, 0x1234]);
}

// ---- 裸実行検査（段階17・PR4）----
// IAOQ 前後キューと PSW.N/PSW.B を、cli の実行ループと同じ
// 規則でテスト側から遷移させる（SPEC-PARISC-11 §4/§5-4）。
use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::{Ctrl, InterpExit};
use polyisa_guest_parisc::sem;
use polyisa_sem::{Backend as _, ExceptionKind};

fn env() -> BareEnv {
    BareEnv::new(core::mem::size_of::<CpuState>())
}

fn gpr(env: &mut BareEnv, n: u8) -> u64 {
    env.backend.get(sem::Gr(n).state())
}

fn set_gpr(env: &mut BareEnv, n: u8, v: u64) {
    env.backend.set(sem::Gr(n).state(), v);
}

fn set_q(env: &mut BareEnv, front: u64) {
    env.backend.set(sem::iaoq_f_ref(), front);
    env.backend.set(sem::iaoq_b_ref(), front.wrapping_add(4));
}

fn iaoq_f(env: &mut BareEnv) -> u64 {
    env.backend.get(sem::iaoq_f_ref())
}

fn iaoq_b(env: &mut BareEnv) -> u64 {
    env.backend.get(sem::iaoq_b_ref())
}

/// 1 命令語を実行し、キュー遷移（run_parisc の step_parisc と同じ
/// 規則）を行う。PSW.N 時は実行せずキューだけ進める。
fn step(env: &mut BareEnv, word: u32) {
    let f = env.backend.get(sem::iaoq_f_ref());
    let bck = env.backend.get(sem::iaoq_b_ref());
    let psw = env.backend.get(sem::psw_ref());
    if psw & sem::PSW_N != 0 {
        env.backend
            .set(sem::psw_ref(), psw & !(sem::PSW_N | sem::PSW_B));
        env.backend.set(sem::iaoq_f_ref(), bck);
        env.backend.set(sem::iaoq_b_ref(), bck.wrapping_add(4));
        return;
    }
    env.backend.set(sem::psw_ref(), psw & !sem::PSW_N);
    let insn = decode_model_ex(u128::from(word), 32, false, ALL).unwrap();
    env.backend.ctrl = Ctrl::Fallthrough;
    let ok = sem::exec(&mut env.backend, insn, word, f).unwrap();
    assert!(ok, "insn {word:#x} unimplemented");
    let target = match env.backend.ctrl {
        Ctrl::Jump(t) => Some(t),
        Ctrl::Fallthrough => None,
    };
    let mut p = env.backend.get(sem::psw_ref());
    p = (p & !sem::PSW_B) | if target.is_some() { sem::PSW_B } else { 0 };
    env.backend.set(sem::psw_ref(), p);
    env.backend.set(sem::iaoq_f_ref(), bck);
    env.backend.set(
        sem::iaoq_b_ref(),
        target.unwrap_or_else(|| bck.wrapping_add(4)),
    );
}

#[test]
fn exec_ldil_ldo_forms_constant() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    // ldil L%1,r1 → GR[1] = 1<<11 = 0x800。
    step(&mut env, 0x2020_1000);
    assert_eq!(gpr(&mut env, 1), 0x800);
    // ldo 0x800(r1),r1 → GR[1] = 0x1000。
    step(&mut env, 0x3421_1000);
    assert_eq!(gpr(&mut env, 1), 0x1000);
    assert_eq!(iaoq_f(&mut env), 0x1008);
    assert_eq!(iaoq_b(&mut env), 0x100c);
}

#[test]
fn exec_add_sub_operand_order() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    set_gpr(&mut env, 1, 0x800); // r2 オペランド（fa）
    set_gpr(&mut env, 2, 1); // r1 オペランド（fb）
    // add r1,r2,r3（0x0822_0603）→ GR[3] = GR[2] + GR[1]。
    step(&mut env, 0x0822_0603);
    assert_eq!(gpr(&mut env, 3), 0x801);
    // sub r1,r2,r3（0x0822_0403）→ GR[3] = GR[2] - GR[1]
    // （r1 が被減数。逆順だと 0xffff...7ff にならず符号が違う）。
    step(&mut env, 0x0822_0403);
    assert_eq!(gpr(&mut env, 3), 1u64.wrapping_sub(0x800));
}

#[test]
fn exec_cmpb_taken_forward_nullifies_delay_slot() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    set_gpr(&mut env, 1, 5);
    set_gpr(&mut env, 2, 5);
    // comb,=,n r1,r2,+4 → c=1（"="は c=1。Table 5-3）、i フィールド=2
    // （変位 +4）、n=1、前方・成立 → 遅延スロット無効化。
    step(&mut env, 0x8022_200a);
    assert_eq!(iaoq_f(&mut env), 0x1004); // 遅延スロット番地
    assert_eq!(iaoq_b(&mut env), 0x100c); // pc+8+4
    // 遅延スロットの add は PSW.N で無効化され、GR[3] は変わらない。
    step(&mut env, 0x0822_0603);
    assert_eq!(gpr(&mut env, 3), 0);
    // 無効化を消費したので次は分岐先 0x100c から進む。
    assert_eq!(iaoq_f(&mut env), 0x100c);
    assert_eq!(iaoq_b(&mut env), 0x1010);
}

#[test]
fn exec_bv_indirect_jump() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    set_gpr(&mut env, 2, 0x2000);
    // bv 0(r2)（0xe840_c000: x=2、b=0）→ iaoq_b = GR[2]。
    step(&mut env, 0xe840_c000);
    assert_eq!(iaoq_f(&mut env), 0x1004);
    assert_eq!(iaoq_b(&mut env), 0x2000);
}

#[test]
fn exec_ble_links_and_jumps() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    set_gpr(&mut env, 2, 0x3000);
    // ble 0(sr0,r2)（0xe440_0000: b=2、w=0、sp=0、w1=0）。
    // → GR[31] = pc+8、iaoq_b = GR[2] + disp17(0)。
    step(&mut env, 0xe440_0000);
    assert_eq!(gpr(&mut env, 31), 0x1008);
    assert_eq!(iaoq_f(&mut env), 0x1004);
    assert_eq!(iaoq_b(&mut env), 0x3000);
}

// ---- 分岐監査の回帰（段階17・PR7）----
// `,n` 無効化は方向×条件成立の 4 象限で検査する。spec の規則は
// `if (n) { if (disp<0) PSW[N] ← !cond; else PSW[N] ← cond }` で、
// 前方成立・後方不成立のとき遅延スロットが無効化される。
// Ref: SPEC-PARISC-11 §5-67〜§5-81（BE/BLE/MOVB/MOVIB/COMB/
// COMIB/ADDB/ADDIB/BB Operation）、SPEC-PARISC-20 付録D
// Table D-3..D-15.

/// 遅延スロットは `ldo 5(r0),r6`。分岐命令や setup が触らない
/// レジスタ r6 の書き込み有無で無効化を観測する。
const DSLOT: u32 = 0x3406_000a;

/// `,n` 分岐の 4 象限。word_ft/word_ff は前方 +4、word_bt/word_bf
/// は後方 -4 の語（真/偽で即値桁が変わる族は別語を渡す）。
/// 後方 -4 は assemble_12 で i=-1：w=1（bit0）、w1=0x7FF
/// （bit2=w1{10}=1、bits3-12=0x3FF）、n=1（bit1）→ bits0-12=0x1FFF。
/// setup がレジスタを用意して条件の真偽を決める。
fn check_quadrants(
    word_ft: u32,
    word_ff: u32,
    word_bt: u32,
    word_bf: u32,
    setup_t: &dyn Fn(&mut BareEnv),
    setup_f: &dyn Fn(&mut BareEnv),
) {
    for (word, setup, nullify, want_b) in [
        (word_ft, setup_t, true, 0x100c_u64), // 前方・成立 → 無効化・pc+8+4
        (word_ff, setup_f, false, 0x1008),    // 前方・不成立 → 実行・pc+8
        (word_bt, setup_t, false, 0x1004),    // 後方・成立 → 実行・pc+8-4
        (word_bf, setup_f, true, 0x1008),     // 後方・不成立 → 無効化・pc+8
    ] {
        let mut env = env();
        set_q(&mut env, 0x1000);
        setup(&mut env);
        step(&mut env, word);
        assert_eq!(iaoq_b(&mut env), want_b, "branch {word:#x}");
        step(&mut env, DSLOT);
        let nulled = gpr(&mut env, 6) == 0;
        assert_eq!(nulled, nullify, "branch {word:#x} nullify={nullify}");
        // 無効化の消費後・通常実行後ともキューは want_b 側へ進む。
        assert_eq!(iaoq_f(&mut env), want_b, "branch {word:#x}");
    }
}

#[test]
fn exec_cond_branch_nullify_quadrants() {
    // comb,=,n r1,r2,±4（r1=GR2, r2=GR1）。`=`: r1==r2。
    check_quadrants(
        0x8022_200a,
        0x8022_200a,
        0x8022_3fff,
        0x8022_3fff,
        &|e| {
            set_gpr(e, 1, 5);
            set_gpr(e, 2, 5);
        },
        &|e| {
            set_gpr(e, 1, 5);
            set_gpr(e, 2, 7);
        },
    );
    // comib,=,n 8,r3,±4。`=`: imm==r → r3=8 で成立。
    check_quadrants(
        0x8470_200a,
        0x8470_200a,
        0x8470_3fff,
        0x8470_3fff,
        &|e| set_gpr(e, 3, 8),
        &|e| set_gpr(e, 3, 5),
    );
    // addb,=,n r1,r2,±4（r1=GR2, r2=GR1）。`=`: r1+r2==0。
    check_quadrants(
        0xa022_200a,
        0xa022_200a,
        0xa022_3fff,
        0xa022_3fff,
        &|e| {
            set_gpr(e, 1, u64::MAX);
            set_gpr(e, 2, 1);
        },
        &|e| {
            set_gpr(e, 1, 1);
            set_gpr(e, 2, 1);
        },
    );
    // addib,=,n 8,r3,±4。`=`: 8+r3==0 → r3=-8 で成立。
    check_quadrants(
        0xa470_200a,
        0xa470_200a,
        0xa470_3fff,
        0xa470_3fff,
        &|e| set_gpr(e, 3, u64::MAX - 7),
        &|e| set_gpr(e, 3, 1),
    );
    // movb,=,n r1,r2,±4（r1=GR2 が移し元）。`=`: 移した値==0。
    check_quadrants(
        0xca22_200a,
        0xca22_200a,
        0xca22_3fff,
        0xca22_3fff,
        &|e| set_gpr(e, 2, 0),
        &|e| set_gpr(e, 2, 9),
    );
    // movib,<,n i,r4,±4（条件は即値側にしか効かないので真偽で語を
    // 変える: -16 → `<` 成立、+1 → 不成立。im5 桁は bit0 が符号で
    // 1 → -16、2 → +1）。
    check_quadrants(
        0xcc81_400a,
        0xcc82_400a,
        0xcc81_5fff,
        0xcc82_5fff,
        &|_| {},
        &|_| {},
    );
    // bb,>=,n r3,0,±4（pos0 は語の最上位ビット＝LSB31）。
    // `>=`: ビットが 0 で成立。
    check_quadrants(
        0xc403_c00a,
        0xc403_c00a,
        0xc403_dfff,
        0xc403_dfff,
        &|e| set_gpr(e, 3, 0),
        &|e| set_gpr(e, 3, 0x8000_0000),
    );
    // bb,<,n r3,0,±4（`<`: ビットが 1 で成立）。
    check_quadrants(
        0xc403_400a,
        0xc403_400a,
        0xc403_5fff,
        0xc403_5fff,
        &|e| set_gpr(e, 3, 0x8000_0000),
        &|e| set_gpr(e, 3, 0),
    );
}

#[test]
fn exec_branch_link_privilege_and_n() {
    // bl 8,r5: GR[5] ← IAOQ_Back + 4（= pc+8）、分岐先 pc+8+8。
    // Ref: SPEC-PARISC-11 §5-62/§B.
    let mut env = env();
    set_q(&mut env, 0x1000);
    step(&mut env, 0xe8a0_0010);
    assert_eq!(gpr(&mut env, 5), 0x1008);
    assert_eq!(iaoq_b(&mut env), 0x1010);

    // bv r3(r2): target = GR[b] + (GR[x]<<3)。GR[b] の下位2ビット
    // が現特権より大きければターゲットの特権を降格（下位2ビット
    // 継承）。小さいときは現特権を維持。
    // Ref: SPEC-PARISC-11 §5-66, SPEC-PARISC-20 §7-19.
    set_gpr(&mut env, 2, 0x2001);
    set_gpr(&mut env, 3, 2);
    step(&mut env, 0xe843_c000);
    assert_eq!(iaoq_b(&mut env), 0x2011); // 0x2010 | priv 1
    set_gpr(&mut env, 2, 0x2000);
    step(&mut env, 0xe843_c000);
    assert_eq!(iaoq_b(&mut env), 0x2010);

    // ble 0(sr0,r2)@f=0x2011: GR[31] = pc+8 = 0x2019、
    // target = GR[b]+0 = 0x3003（priv 3 へ降格）。
    set_gpr(&mut env, 2, 0x3003);
    step(&mut env, 0xe440_0000);
    assert_eq!(gpr(&mut env, 31), 0x2019);
    assert_eq!(iaoq_b(&mut env), 0x3003);

    // be 4(sr0,r2)@f=0x2010: リンクなし。target = GR[b] + 4、
    // GR[b] の下位2ビットは 0 で現特権 0 を維持 → 0x3004。
    set_gpr(&mut env, 2, 0x3000);
    step(&mut env, 0xe040_0008);
    assert_eq!(iaoq_b(&mut env), 0x3004);

    // bv,n 0(r2)@f=0x3003: ,n で遅延スロットを無効化。pc の
    // 下位2ビットは 3 なのでターゲットは priv 3 を維持する。
    set_gpr(&mut env, 2, 0x4000);
    step(&mut env, 0xe840_c002);
    step(&mut env, DSLOT);
    assert_eq!(gpr(&mut env, 6), 0);
    assert_eq!(iaoq_f(&mut env), 0x4003);
}

#[test]
fn exec_mtsp_mfsp_assemble3() {
    // mtsp/mfsp の s 桁は `sr ← assemble_3(s)` で復元される
    // （cat(s{2},s{0..1}): s の bit0 が SR 番号の bit2）。
    // Ref: SPEC-PARISC-20 付録E Table E-1, §7-93/§7-102,
    // SPEC-PARISC-11 §5-147/§5-150.
    let mut env = env();
    set_q(&mut env, 0x1000);
    set_gpr(&mut env, 4, 0xdead_beef);
    // mtsp r4,sr2: sr2 の符号化 s = ((2&3)<<1)|(2>>2) = 4。
    // SR の格納は上位 32 ビット（PA 1.1 Level 1 モデル慣行）。
    step(&mut env, 0x0004_9820);
    assert_eq!(env.backend.get(sem::Sr(2).state()), 0xdead_beef_0000_0000);
    // mfsp sr2,r9 → r9 = 0xdead_beef。
    step(&mut env, 0x0000_84a9);
    assert_eq!(gpr(&mut env, 9), 0xdead_beef);
    // sr5 は符号化 3（assemble_3(3) = 5）。
    set_gpr(&mut env, 4, 0x1234_5678);
    step(&mut env, 0x0004_7820);
    assert_eq!(env.backend.get(sem::Sr(5).state()), 0x1234_5678_0000_0000);
    step(&mut env, 0x0000_64a9);
    assert_eq!(gpr(&mut env, 9), 0x1234_5678);
}

#[test]
fn exec_gate_in_delay_slot_traps() {
    // gate は遅延スロット（PSW.B）で illegal instruction trap。
    // Ref: SPEC-PARISC-11 §5-63/§GATE `if (PSW[B])
    // illegal_instruction_trap`, SPEC-PARISC-20 §B,GATE.
    let mut env = env();
    set_q(&mut env, 0x1000);
    set_gpr(&mut env, 2, 0x2000);
    // bv 0(r2) で PSW.B を立てて遅延スロット状態にする。
    step(&mut env, 0xe840_c000);
    // gate +0,r0（0xe800_2000）を遅延スロットとして実行 → トラップ。
    let insn = dec(0xe800_2000).unwrap();
    assert_eq!(insn, Insn::Gate);
    let f = iaoq_f(&mut env);
    let r = sem::exec(&mut env.backend, insn, 0xe800_2000, f);
    let Err(InterpExit::Exception(e)) = r else {
        panic!("gate in delay slot should trap: {r:?}");
    };
    assert_eq!(e.kind, ExceptionKind::Trap);
    assert_eq!(e.code, sem::TRAP_ILL);
}

// ---- shift/extract/deposit 意味論検査（段階17・Step0）----
// busybox の起動コードが extru/depi/zdepi を使う（0xd3351bf8 で
// 未実装停止したことから発覚）。位置は HP の左端起算で、語には
// 32-len（clen）や 31-p（cp）の形で入る。
// Ref: SPEC-PARISC-11 §5-122〜135, SPEC-PARISC-20 §7-38〜50・§7-122〜124.

fn set_sar(env: &mut BareEnv, v: u64) {
    env.backend.set(sem::Cr(11).state(), v);
}

fn fpr(env: &mut BareEnv, n: u8) -> u64 {
    env.backend.get(sem::Fpr(n).state())
}

fn set_fpr(env: &mut BareEnv, n: u8, v: u64) {
    env.backend.set(sem::Fpr(n).state(), v);
}

#[test]
fn exec_extru_imm_extracts_low_bits() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    set_gpr(&mut env, 5, 0xdead_beef);
    // extru r5,31,8,r6（0xd0a6_1bf8: pos=31、len=8 → 下位 8 ビット）。
    step(&mut env, 0xd0a6_1bf8);
    assert_eq!(gpr(&mut env, 6), 0xef);
    // busybox で停止していた実例語: extru r25,31,8,r21。
    set_gpr(&mut env, 25, 0x1234);
    step(&mut env, 0xd335_1bf8);
    assert_eq!(gpr(&mut env, 21), 0x34);
    // extrs の符号拡張: pos=8、len=4 でフィールド最上位が 1。
    set_gpr(&mut env, 5, 0x0400_0000);
    step(&mut env, 0xd0a6_1d1c);
    assert_eq!(gpr(&mut env, 6), 0xffff_fff8);
    // 同じ形で符号ビット 0 → 0 拡張。
    set_gpr(&mut env, 5, 0x0080_0000);
    step(&mut env, 0xd0a6_1d1c);
    assert_eq!(gpr(&mut env, 6), 1);
}

#[test]
fn exec_extru_cond_nullifies_next() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    set_gpr(&mut env, 5, 0);
    // extru,= r5,31,8,r6（c=1、"="は Table 5-7 の index 1）。
    // res==0 → PSW.N で次の add が無効化される。
    step(&mut env, 0xd0a6_3bf8);
    assert_eq!(gpr(&mut env, 6), 0);
    step(&mut env, 0x0822_0603); // add r1,r2,r3 → 無効化
    assert_eq!(gpr(&mut env, 3), 0);
}

#[test]
fn exec_extr_sar_forms() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    // ExtrSar（32 ビット可変）: pos=CR[11]&31。
    set_gpr(&mut env, 5, 0xdead_beef);
    set_sar(&mut env, 31);
    step(&mut env, 0xd0a6_1018); // extru r5,sar(len=8),r6
    assert_eq!(gpr(&mut env, 6), 0xef);
    // 左端を超える符号付き抽出は tlen=pos+1 で符号拡張する。
    // sar=2、len=8: r5 の bit31=1 が符号として上へ伸びる。
    set_gpr(&mut env, 5, 0x8000_0000);
    set_sar(&mut env, 2);
    step(&mut env, 0xd0a6_1418); // extrs r5,sar(len=8),r6
    assert_eq!(gpr(&mut env, 6), 0xffff_fffc);
    // ExtrSarD（64 ビット可変）: pos=CR[11]&63。
    set_gpr(&mut env, 5, 0xdead_beef_cafe);
    set_sar(&mut env, 63);
    step(&mut env, 0xd0a6_1218); // extrd,u r5,sar(len=8),r6
    assert_eq!(gpr(&mut env, 6), 0xfe);
}

#[test]
fn exec_extrd_imm() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    // extrd,u r5,32,8,r6（pos=32 → cpos6=cat(1,0)=32）。
    // HP 位置 32..39 は LSB の bits 31..38 → 下位語の先頭バイト。
    set_gpr(&mut env, 5, 0x1122_3344_5566_7788);
    step(&mut env, 0xd8a6_0818);
    assert_eq!(gpr(&mut env, 6), 0x88);
    // extrd,s: フィールド最上位が符号として全体へ伸びる。
    set_gpr(&mut env, 5, 0xffff_ffff_ffff_ff80);
    step(&mut env, 0xd8a6_0c18);
    assert_eq!(gpr(&mut env, 6), 0xffff_ffff_ffff_ffff);
    // 符号ビット 0 → 0 拡張（field=0x7f、bits 31..37）。
    set_gpr(&mut env, 5, 0x7f << 31);
    step(&mut env, 0xd8a6_0c18);
    assert_eq!(gpr(&mut env, 6), 0x7f);
}

#[test]
fn exec_shrp_forms() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    // ShrpSar（VSHD、32 ビット）: cat(r1{1..31},r2)>>sar の下位 32。
    set_gpr(&mut env, 1, 0xabcd_ef01);
    set_gpr(&mut env, 2, 0x2345_6789);
    set_sar(&mut env, 4);
    step(&mut env, 0xd041_0006); // shrp r2,r1,r6
    assert_eq!(gpr(&mut env, 6), 0x1234_5678);
    // 回転（r1=r2）でも同じ規則（32 ビットのローテート）。
    set_gpr(&mut env, 1, 0x1234_5678);
    set_gpr(&mut env, 2, 0x1234_5678);
    set_sar(&mut env, 8);
    step(&mut env, 0xd041_0006);
    assert_eq!(gpr(&mut env, 6), u64::from(0x1234_5678u32.rotate_right(8)));
    // ShrpSarD（SHRPD 可変）: cat(r1{1..63},r2)>>sar。
    set_gpr(&mut env, 1, 0x5555_5555_5555_5555);
    set_gpr(&mut env, 2, 0xaaaa_aaaa_aaaa_aaaa);
    set_sar(&mut env, 36);
    step(&mut env, 0xd041_0206);
    let want =
        (((0x5555_5555_5555_5555u128 & ((1 << 63) - 1)) << 64) | 0xaaaa_aaaa_aaaa_aaaau128) >> 36;
    assert_eq!(gpr(&mut env, 6), want as u64);
    // ShrpImm（SHD/SHRPW 固定）: sa=31-cpos。
    set_gpr(&mut env, 1, 0xf0f0_f0f0);
    set_gpr(&mut env, 2, 0x0f0f_0f0f);
    step(&mut env, 0xd041_0966); // shrp r2,r1,20,r6
    let want =
        ((((0xf0f0_f0f0u128 & ((1 << 31) - 1)) << 32) | 0x0f0f_0f0fu128) >> 20) & 0xffff_ffff;
    assert_eq!(gpr(&mut env, 6), want as u64);
    // ShrpImmD（SHRPD 固定）: sa=63-cpos6。
    step(&mut env, 0xd041_0766); // shrpd r2,r1,36,r6
    let want = (((0xf0f0_f0f0u128 & ((1 << 63) - 1)) << 64) | 0x0f0f_0f0fu128) >> 36;
    assert_eq!(gpr(&mut env, 6), want as u64);
}

#[test]
fn exec_dep_forms() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    // DepSar（VDEP、nz=1 併合）: tpos=sar=20 → 下位 8 ビットを
    // LSB 位置 31-20=11 に挿入。
    set_gpr(&mut env, 6, 0x1234_5678);
    set_gpr(&mut env, 1, 0xab);
    set_sar(&mut env, 20);
    step(&mut env, 0xd4c1_0418); // dep r1,sar(len=8),r6
    assert_eq!(gpr(&mut env, 6), 0x1234_5678 & !(0xff << 11) | 0xab << 11);
    // sar=3 → tpos<len-1 は上端切り詰め（src 下位 4 ビットが最上端へ）。
    set_gpr(&mut env, 6, 0x1234_5678);
    set_sar(&mut env, 3);
    step(&mut env, 0xd4c1_0418);
    assert_eq!(gpr(&mut env, 6), 0xb234_5678);
    // DepSarD（DEPD 可変）: tpos=sar=40 → shl=23。
    set_gpr(&mut env, 6, 0x1122_3344_5566_7788);
    set_sar(&mut env, 40);
    step(&mut env, 0xd4c1_0618); // depd r1,sar(len=8),r6
    assert_eq!(
        gpr(&mut env, 6),
        0x1122_3344_5566_7788 & !(0xff << 23) | 0xab << 23
    );
}

#[test]
fn exec_dep_imm_forms() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    // DepImm（DEP、nz=1）: p=11 → cpos=20 → 下位 8 ビットを
    // LSB 位置 20 に挿入。
    set_gpr(&mut env, 6, 0x1234_5678);
    set_gpr(&mut env, 1, 0xab);
    step(&mut env, 0xd4c1_0e98); // dep r1,11,8,r6
    assert_eq!(gpr(&mut env, 6), 0x1ab4_5678);
    // ZDEP（nz=0）は併合先を 0 化してから挿入。
    step(&mut env, 0xd4c1_0a98); // zdep r1,11,8,r6
    assert_eq!(gpr(&mut env, 6), 0xab << 20);
    // DepImmD（DEPD 固定）: pos=32 → cpos6=31 → 下位 8 ビットを
    // LSB 位置 31 に挿入。
    set_gpr(&mut env, 6, 0x1122_3344_5566_7788);
    step(&mut env, 0xf0c1_07f8); // depd r1,32,8,r6
    assert_eq!(
        gpr(&mut env, 6),
        0x1122_3344_5566_7788 & !(0xffu64 << 31) | 0xabu64 << 31
    );
}

#[test]
fn exec_depi_forms() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    // DepiSar（VDEPI、nz=1、d=0）: 符号拡張即値の下位 len を挿入。
    set_gpr(&mut env, 6, 0x1234_5678);
    set_sar(&mut env, 20);
    step(&mut env, 0xd4df_1418); // depi -1,sar(len=8),r6
    assert_eq!(gpr(&mut env, 6), 0x1234_5678 & !(0xff << 11) | 0xff << 11);
    // DepiImm nz=0（ZDEPI）: -1 の下位 16 ビットを p=8 に置く。
    step(&mut env, 0xd4df_1af0); // depi -1,8,16,r6
    assert_eq!(gpr(&mut env, 6), 0xff80_0000);
    // DepiImm nz=1（DEPI）: +5 を併合挿入。
    set_gpr(&mut env, 6, 0x00ff_ffff);
    step(&mut env, 0xd4ca_1ef0); // depi 5,8,16,r6
    assert_eq!(gpr(&mut env, 6), 0x00ff_ffff & !(0xffff << 23) | 5 << 23);
    // DepiImmD（DEPDI 固定）: +3 を pos=32（LSB 31）に。
    step(&mut env, 0xf4c6_03f8); // depdi 3,32,8,r6
    assert_eq!(gpr(&mut env, 6), 3u64 << 31);
}

// ---- stby/stdby・FP ロード/ストア検査（段階17・Step0）----
// memcpy が fldd/fstd と stby を使うので、ビット移動だけ実装する。
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};

const MEM_READ: Access = Access {
    endian: Endian::Be,
    align: Align::Natural,
    kind: AccessKind::DataRead,
};

fn mem_bytes(env: &mut BareEnv, addr: u64, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    env.backend
        .mem
        .read(VirtAddr(addr), &mut buf, MEM_READ)
        .unwrap();
    buf
}

#[test]
fn exec_stby_begin_end_bytes() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    // stby,b r2,0(r6): a=0、m=0。EA&3=1 → ワードの bytes 1..3 に
    // r2 の BE バイト 1..3 を書く。
    set_gpr(&mut env, 6, 0x2001);
    set_gpr(&mut env, 2, 0xaabb_ccdd);
    step(&mut env, 0x0cc2_1300);
    assert_eq!(mem_bytes(&mut env, 0x2000, 4), [0x00, 0xbb, 0xcc, 0xdd]);
    // stby,e r2,0(r6): a=1。ワード先頭から EA 直前まで → byte0 だけ。
    env.backend
        .mem
        .write(VirtAddr(0x2000), &[0, 0, 0, 0])
        .unwrap();
    step(&mut env, 0x0cc2_3300);
    assert_eq!(mem_bytes(&mut env, 0x2000, 4), [0xaa, 0, 0, 0]);
    // stby,b,m r2,4(r6): EA=更新前の r6、書き戻しは (r6+4)&~3。
    set_gpr(&mut env, 6, 0x2001);
    set_gpr(&mut env, 2, 0xaabb_ccdd);
    step(&mut env, 0x0cc2_1328);
    assert_eq!(gpr(&mut env, 6), 0x2004);
}

#[test]
fn exec_stdby_begin() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    // stdby,b r2,0(r6): EA&7=1 → ダブルワードの bytes 1..7。
    set_gpr(&mut env, 6, 0x2001);
    set_gpr(&mut env, 2, 0x1122_3344_5566_7788);
    step(&mut env, 0x0cc2_1340);
    assert_eq!(
        mem_bytes(&mut env, 0x2000, 8),
        [0x00, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
    );
}

#[test]
fn exec_fp_load_store_moves_bits() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    // fstd fr5,0(r6): 64 ビットをそのまま格納（busybox の memcpy
    // で実際に停止した語 0x2c30122c と同形式）。
    set_gpr(&mut env, 6, 0x2000);
    set_fpr(&mut env, 5, 0x1122_3344_5566_7788);
    step(&mut env, 0x2cc0_1205);
    assert_eq!(
        mem_bytes(&mut env, 0x2000, 8),
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
    );
    // fldd fr7,0(r6): 同じ内容を別レジスタへ読み戻す。
    step(&mut env, 0x2cc0_1007);
    assert_eq!(fpr(&mut env, 7), 0x1122_3344_5566_7788);
    // fstw fr4R,0(r6): opcode 0x09。右半分（下位 32 ビット）だけ
    // を書く（r64t = cat(bit6=1,t5=4) = 36 → 4R）。
    set_fpr(&mut env, 4, 0xaabb_ccdd_1122_3344);
    step(&mut env, 0x24c0_1244);
    assert_eq!(mem_bytes(&mut env, 0x2000, 4), [0x11, 0x22, 0x33, 0x44]);
    // fstw fr4L: 左半分（上位 32 ビット）。r64t=4。
    step(&mut env, 0x24c0_1204);
    assert_eq!(mem_bytes(&mut env, 0x2000, 4), [0xaa, 0xbb, 0xcc, 0xdd]);
    // fldw fr8R: メモリ 4 バイトを右半分に読む（左半分は保持）。
    set_fpr(&mut env, 8, 0xdead_beef_cafe_f00d);
    step(&mut env, 0x24c0_1048);
    assert_eq!(fpr(&mut env, 8), 0xdead_beef_aabb_ccdd);
    // flddx インデックス形式: EA = r6 + r7。
    env.backend
        .mem
        .write(VirtAddr(0x2008), &0xfeed_face_0bad_c0deu64.to_be_bytes())
        .unwrap();
    set_gpr(&mut env, 7, 0x8);
    step(&mut env, 0x2cc7_0009);
    assert_eq!(fpr(&mut env, 9), 0xfeed_face_0bad_c0de);
}

// ---- ds / dcor 意味論検査（段階17）----
// 出典: SPEC-PARISC-11 §5-111（DS）・§5-113/§5-114（DCOR/IDCOR）、
// SPEC-PARISC-20 §7-47（DS）・§7-36（DCOR）・§7-5（PSW C/B/V）。
// 語形は `02 r2 r1 c f 010001 0 t`（ds）、`02 r 0 c f 10111 e1 d t`
// （dcor: e1=2、dcor,i: e1=3）。

/// PSW[C/B] の桁キャリベクトル（cb 状態）を読む。
fn cb(env: &mut BareEnv) -> u64 {
    env.backend.get(sem::cb_ref())
}

/// PSW.V（除算訂正ビット）を読む。
fn psw_v(env: &mut BareEnv) -> u64 {
    env.backend.get(sem::psw_ref()) & sem::PSW_V
}

#[test]
fn exec_ds_add_path_consumes_cb8() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    // 語の桁キャリ C/B{8}（cb の bit28）を add で立てる:
    // 0x8000_0000 + 0x8000_0000 は bit32 へのキャリを生じる。
    set_gpr(&mut env, 4, 0x8000_0000);
    set_gpr(&mut env, 5, 0x8000_0000);
    step(&mut env, 0x0885_0606); // add r4,r5,r6
    assert_eq!(cb(&mut env), 1 << 28);
    // ds r2,r1,r3（PSW.V=0 → 加算側）。partial = (r1<<1)|cb8
    // = (4<<1)|1 = 9、dest = 9 + 2 = 0xB。
    set_gpr(&mut env, 1, 4);
    set_gpr(&mut env, 2, 2);
    step(&mut env, 0x0841_0443); // ds r2,r1,r3
    assert_eq!(gpr(&mut env, 3), 0xB);
    // x = 9 ^ 2 ^ 0xB = 0 → 桁キャリ列は 0。V ← 0 ^ r2{31}(=0) = 0。
    assert_eq!(cb(&mut env), 0);
    assert_eq!(psw_v(&mut env), 0);
}

#[test]
fn exec_ds_subtract_path_updates_v_and_cb() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    // まず V=1 を作る: cb8=0（初期 cb=0）、r2 の語符号ビットが 1。
    // partial = (0<<1)|0 = 0、V=0 → dest = 0 + 0x8000_0000。
    set_gpr(&mut env, 4, 0);
    set_gpr(&mut env, 5, 0x8000_0000);
    step(&mut env, 0x08a4_0443); // ds r5,r4,r3
    assert_eq!(gpr(&mut env, 3), 0x8000_0000);
    assert_eq!(cb(&mut env), 0);
    assert_ne!(psw_v(&mut env), 0); // V ← cb8_new(0) ^ r2{31}(1)
    // 次の ds は V=1 → 減算側。r1=0x20、cb8=0 → partial = 0x40。
    set_gpr(&mut env, 4, 0x20);
    step(&mut env, 0x08a4_0443); // ds r5,r4,r3
    // dest = 0x40 + ~0x8000_0000 + 1 = 0x40 - 0x8000_0000。
    assert_eq!(gpr(&mut env, 3), 0xffff_ffff_8000_0040u64);
    // x = 0x40 ^ ~0x8000_0000 ^ dest = 0xffff_ffff（語）→ 語の
    // 下位 7 桁にキャリ（bit0,4,...,24）。語の出口キャリは 0。
    assert_eq!(cb(&mut env), 0x0111_1111);
    // V ← cb8_new(0) ^ r2{31}(1) = 1（減算側が継続）。
    assert_ne!(psw_v(&mut env), 0);
}

#[test]
fn exec_ds_cond_nullifies_next() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    // ds,od（c=7,f=0 → cf=0xE）。V=0 の加算側: 結果が奇数なら
    // 次命令を無効化。partial = (5<<1)|0 = 0xA、dest = 0xA+3 = 0xD。
    set_gpr(&mut env, 5, 5);
    set_gpr(&mut env, 3, 3);
    step(&mut env, 0x0865_e443); // ds,od r3,r5,r3
    assert_eq!(gpr(&mut env, 3), 0xD);
    // PSW.N → 次の ldo は無効化される。
    step(&mut env, 0x3404_0040); // ldo 0x20(r0),r4
    assert_eq!(gpr(&mut env, 4), 0);
    // ds,tr（c=0,f=1 → cf=1）は常に次命令を無効化する。
    step(&mut env, 0x0865_1443); // ds,tr r3,r5,r3
    step(&mut env, 0x3404_0040); // ldo 0x20(r0),r4 → 無効化
    assert_eq!(gpr(&mut env, 4), 0);
}

#[test]
fn exec_dcor_bcd_chain() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    // SPEC-PARISC-20 §7-36 Programming Note の BCD 加算手順:
    // 1234 + 5678 + 1000 = 7912（BCD）。nines = 0x9999...。
    set_gpr(&mut env, 4, 0x9999_9999_9999_9999); // nines
    set_gpr(&mut env, 5, 0x1234); // ra
    set_gpr(&mut env, 6, 0x5678); // rb
    set_gpr(&mut env, 7, 0x1000); // rc
    // uaddcm r4,r5,r8 → r8 = ra + ~nines = 0x1234 + 0x6666..6。
    step(&mut env, 0x0885_0988);
    assert_eq!(gpr(&mut env, 8), 0x6666_6666_6666_789A);
    // add r6,r8,r8 → r8 += rb。桁 0: A+8=0x12、桁 1: 9+7+1=0x11
    // → C/B は桁 0・1 に立つ（cb = 0x11）。
    step(&mut env, 0x08c8_0608);
    assert_eq!(gpr(&mut env, 8), 0x6666_6666_6666_CF12);
    assert_eq!(cb(&mut env), 0x11);
    // dcor,i r8,r8 → 桁 0・1 に +6（バイアスを保つ訂正）。
    step(&mut env, 0x0900_0bc8);
    assert_eq!(gpr(&mut env, 8), 0x6666_6666_6666_CF78);
    // add r7,r8,r8 → r8 += rc = 0x1000。桁キャリなし → cb = 0。
    step(&mut env, 0x08e8_0608);
    assert_eq!(gpr(&mut env, 8), 0x6666_6666_6666_DF78);
    assert_eq!(cb(&mut env), 0);
    // dcor r8,r8 → C/B=0 の全桁に -6 → 最終 BCD 0x7912。
    step(&mut env, 0x0900_0b88);
    assert_eq!(gpr(&mut env, 8), 0x7912);
}

#[test]
fn exec_dcor_cond_nullifies_next() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    // cb = 0x0001_0001（桁 0 と 4 のキャリ）を add で作る:
    // 0x000F_000F + 0x0001_0001（桁 0: F+1、桁 4: F+1）。
    set_gpr(&mut env, 4, 0x000f_000f);
    set_gpr(&mut env, 5, 0x0001_0001);
    step(&mut env, 0x0885_0606); // add r4,r5,r6
    assert_eq!(cb(&mut env), 0x0001_0001);
    // dcor,nbz r8,r9（c=2,f=1 → cf=5）。C/B=0 の桁は -6、
    // C/B=1 の桁 0・4 はそのまま → res = r8 - 0x6666..6660_6660。
    // 語の全バイトが非零 → NBZ 成立 → 次命令を無効化。
    set_gpr(&mut env, 8, 0x1111_1111_1111_1111);
    step(&mut env, 0x0900_5b89);
    assert_eq!(gpr(&mut env, 9), 0xaaaa_aaaa_aab0_aab1u64);
    step(&mut env, 0x340a_0040); // ldo 0x20(r0),r10 → 無効化
    assert_eq!(gpr(&mut env, 10), 0);
    // dcor,i は +6 側: 桁 0・4 にのみ 0x6。
    set_gpr(&mut env, 8, 0x1111_1111_1111_1111);
    step(&mut env, 0x0900_0bc8); // dcor,i r8,r8
    assert_eq!(gpr(&mut env, 8), 0x1111_1111_1117_1117u64);
}

// ---- add,c / sub,b の桁キャリ消費と SAR 幅（段階17・PR5 レビュー #2）----
// cb 状態の語の桁キャリ C/B{8}（bit28）と dw の C/B{0}（bit60）を
// add で作り、add,c/sub,b が cin として正しく消費することを見る。
// add,c/sub,b は自身も cb を更新するので、消費側の直前には都度
// cb を立て直す。
// Ref: SPEC-PARISC-20 §7-5（C/B）・§7-3（ADDC/SUBB の Operation）.

/// cb 状態（PSW[C/B] ベクトル）を直接書くテスト用ヘルパ。
fn set_cb(env: &mut BareEnv, v: u64) {
    env.backend.set(sem::cb_ref(), v);
}

#[test]
fn exec_addc_subb_consume_cb() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    // 語の出口キャリ C/B{8} だけを add で立てる:
    // 0xFFFF_FFFF + 1 は bit32 へのキャリを生じるが 64 ビットの
    // キャリアウト（C/B{0}＝bit60）は立たない。
    set_gpr(&mut env, 4, 0xffff_ffff);
    set_gpr(&mut env, 5, 1);
    step(&mut env, 0x0885_0606); // add r4,r5,r6
    assert_eq!(cb(&mut env), 0x1111_1111);
    set_gpr(&mut env, 7, 5);
    set_gpr(&mut env, 8, 3);
    // add,c r7,r8,r9: cin = C/B{8} = 1 → 5+3+1 = 9。
    step(&mut env, 0x0907_0709);
    assert_eq!(gpr(&mut env, 9), 9);
    // sub,b r7,r8,r9: cin = 1 → borrow なしで 5-3-0 = 2。
    set_cb(&mut env, 1 << 28);
    step(&mut env, 0x0907_0509);
    assert_eq!(gpr(&mut env, 9), 2);
    // cin = 0 なら borrow が入る: 5-3-1 = 1。
    set_cb(&mut env, 0);
    step(&mut env, 0x0907_0509);
    assert_eq!(gpr(&mut env, 9), 1);
    // add,c も cin = 0 → 5+3+0 = 8。
    set_cb(&mut env, 0);
    step(&mut env, 0x0907_0709);
    assert_eq!(gpr(&mut env, 9), 8);
    // ,d 形は C/B{0}（bit60）を消費する。dw の出口キャリだけを
    // add で立てる: 0xFFFF_FFFF_0000_0000 どうしの和は 64 ビットの
    // キャリアウトを生じるが語の出口キャリ（bit32）は 0。
    set_gpr(&mut env, 4, 0xffff_ffff_0000_0000);
    set_gpr(&mut env, 5, 0xffff_ffff_0000_0000);
    step(&mut env, 0x0885_0606); // add r4,r5,r6
    assert_eq!(cb(&mut env), 0x1111_1111_0000_0000);
    // add,c,d → cin = C/B{0} = 1 で 5+3+1 = 9（語形なら 8）。
    step(&mut env, 0x0907_0729);
    assert_eq!(gpr(&mut env, 9), 9);
    // sub,b,d → borrow なしで 5-3-0 = 2。
    set_cb(&mut env, 1 << 60);
    step(&mut env, 0x0907_0529);
    assert_eq!(gpr(&mut env, 9), 2);
    // cin = 0 → 5-3-1 = 1。
    set_cb(&mut env, 0);
    step(&mut env, 0x0907_0529);
    assert_eq!(gpr(&mut env, 9), 1);
}

#[test]
fn exec_mtctl_mfctl_sar_widths() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    // mtctl r4,%sar: SAR は 6 ビットレジスタ（GR[r]{26..31}）。
    // 0x1BD & 63 = 61 が入る（6 ビットを超える桁は捨てる）。
    // Ref: SPEC-PARISC-20 §MTCTL/§MFCTL.
    set_gpr(&mut env, 4, 0x1bd);
    step(&mut env, 0x0164_1840);
    // mfctl,w %sar,r5 は SAR 全 6 ビット（61）、mfctl %sar,r6 は
    // 下位 5 ビット（61 & 31 = 29）。
    step(&mut env, 0x0160_48a5);
    assert_eq!(gpr(&mut env, 5), 61);
    step(&mut env, 0x0160_08a6);
    assert_eq!(gpr(&mut env, 6), 29);
    // 6 ビット保持は pos > 31 が見える消費側で観測できる:
    // extrd,u r5,sar(len=8),r6 は pos = sar&63 = 61 で LSB の
    // bits2-9 を取る（5 ビットに潰れていれば pos=29 で別値
    // 0xd1 になる）。
    set_gpr(&mut env, 5, 0x1122_3344_5566_7788);
    step(&mut env, 0xd0a6_1218);
    assert_eq!(gpr(&mut env, 6), 0xe2);
    // mtsarcm r4: ~GR[r]{26..31}。r4=2 → ~2 & 63 = 61。
    // Ref: SPEC-PARISC-20 §MTSARCM.
    set_gpr(&mut env, 4, 2);
    step(&mut env, 0x0164_18c0);
    step(&mut env, 0x0160_48a5); // mfctl,w %sar,r5
    assert_eq!(gpr(&mut env, 5), 61);
    // mfctl のユーザ不可読レジスタ（cr0）は特権操作トラップ。
    let insn = dec(0x0000_08a5).unwrap();
    assert_eq!(insn, Insn::Mfctl);
    let f = iaoq_f(&mut env);
    let r = sem::exec(&mut env.backend, insn, 0x0000_08a5, f);
    let Err(InterpExit::Exception(e)) = r else {
        panic!("mfctl %cr0 should trap: {r:?}");
    };
    assert_eq!(e.kind, ExceptionKind::Trap);
    assert_eq!(e.code, sem::TRAP_PRIV);
}

// mtsm は PSW システムマスクへの移動で最上位特権のみ。ユーザ
// モデルでは privileged operation trap になる（#6 対応）。
#[test]
fn exec_mtsm_traps_as_privileged() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    // mtsm r4（形式 000000 00000 r 000 11000011 00000 → 0x0004_1860）。
    let insn = dec(0x0004_1860).unwrap();
    assert_eq!(insn, Insn::Mtsm);
    let f = iaoq_f(&mut env);
    let r = sem::exec(&mut env.backend, insn, 0x0004_1860, f);
    let Err(InterpExit::Exception(e)) = r else {
        panic!("mtsm should trap: {r:?}");
    };
    assert_eq!(e.kind, ExceptionKind::Trap);
    assert_eq!(e.code, sem::TRAP_PRIV);
}

// ---- 絶対番地ロード/ストア・probe・break・diag（段階17・PR6）----
// ldaw/ldda/ldawx/lddax/stda は絶対番地かつ特権命令だが、本モデルは
// 特権遷移を持たないので Level 0 記述どおり通常ロード/ストアに
// 畳む（GAP-0055）。probe も access-right メタデータのない
// フラットメモリ近似（マップ済み＋要求許可なら 1）で検査する。
// Ref: SPEC-PARISC-11 §5-45/§5-39/§5-51/§5-154..§5-157,
// SPEC-PARISC-20 §7-78/§7-87/§7-138/§7-113/§7-114.

#[test]
fn exec_ldaw_ldda_short_forms() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0xdead_beefu32.to_be_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2008), &0x1122_3344_5566_7788u64.to_be_bytes())
        .unwrap();
    // ldaw r9,0(r6): 32 ビットの絶対ロード（通常 ldw と同じ動作）。
    set_gpr(&mut env, 6, 0x2000);
    step(&mut env, 0x0cc0_1189);
    assert_eq!(gpr(&mut env, 9), 0xdead_beef);
    assert_eq!(gpr(&mut env, 6), 0x2000); // 修飾なしなので基底不変。
    // ldaw,ma r9,4(r6): EA = 旧基底 0x2000、書戻し r6 = 0x2004。
    step(&mut env, 0x0cc8_11a9);
    assert_eq!(gpr(&mut env, 9), 0xdead_beef);
    assert_eq!(gpr(&mut env, 6), 0x2004);
    // ldaw,mb r9,-4(r6): 先に r6 = 0x2000 に更新してから読む。
    // im5 フィールドは (値<<1)|符号の配置で -4 は 25（0b11001）。
    step(&mut env, 0x0cd9_31a9);
    assert_eq!(gpr(&mut env, 9), 0xdead_beef);
    assert_eq!(gpr(&mut env, 6), 0x2000);
    // ldda r9,8(r6): 64 ビット形（PA 2.0）。im5=+8 はフィールド 16。
    step(&mut env, 0x0cd0_1109);
    assert_eq!(gpr(&mut env, 9), 0x1122_3344_5566_7788);
}

#[test]
fn exec_ldawx_lddax_indexed_forms() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0xcafe_babeu32.to_be_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2008), &0xfeed_0000_1111_2222u64.to_be_bytes())
        .unwrap();
    set_gpr(&mut env, 6, 0x2000);
    set_gpr(&mut env, 7, 8);
    // ldawx r7(r6),r9: u=0,m=0 → EA = r6 + r7 = 0x2008 の語。
    step(&mut env, 0x0cc7_0189);
    assert_eq!(gpr(&mut env, 9), 0xfeed_0000);
    // ldawx,s r7(r6),r9: u=1 → x<<2 で EA = 0x2000 + 32（語は
    // 0x2020 に無いので 0。先に書いておく）。
    env.backend
        .mem
        .write(VirtAddr(0x2020), &0x0000_4242u32.to_be_bytes())
        .unwrap();
    step(&mut env, 0x0cc7_2189);
    assert_eq!(gpr(&mut env, 9), 0x4242);
    assert_eq!(gpr(&mut env, 6), 0x2000); // m=0 なので基底不変。
    // ldawx,m r7(r6),r9: m=1 → EA = r6（0x2000）の語を読み、
    // 書戻し r6 += r7。
    step(&mut env, 0x0cc7_01a9);
    assert_eq!(gpr(&mut env, 9), 0xcafe_babe);
    assert_eq!(gpr(&mut env, 6), 0x2008);
    // lddax r7(r6),r9: 64 ビット index 形。EA = 0x2008+8 = 0x2010。
    env.backend
        .mem
        .write(VirtAddr(0x2010), &0xa5a5_5a5a_1234_5678u64.to_be_bytes())
        .unwrap();
    step(&mut env, 0x0cc7_0109);
    assert_eq!(gpr(&mut env, 9), 0xa5a5_5a5a_1234_5678);
    // lddax,s r1(r6),r9: u=1 → x<<3。r1=1 で EA = 0x2008+8 = 0x2010。
    set_gpr(&mut env, 1, 1);
    step(&mut env, 0x0cc1_2109);
    assert_eq!(gpr(&mut env, 9), 0xa5a5_5a5a_1234_5678);
}

#[test]
fn exec_staw_stda_short_forms() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    set_gpr(&mut env, 6, 0x2000);
    set_gpr(&mut env, 7, 0x1122_3344_5566_7788);
    // staw r7,0(r6): 32 ビットの絶対ストア（下位 32 ビットを書く）。
    step(&mut env, 0x0cc7_1380);
    assert_eq!(mem_bytes(&mut env, 0x2000, 4), [0x55, 0x66, 0x77, 0x88]);
    // stda r7,0(r6): 64 ビット形（PA 2.0）。
    step(&mut env, 0x0cc7_13c0);
    assert_eq!(
        mem_bytes(&mut env, 0x2000, 8),
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
    );
    // stda,ma r7,8(r6): EA = 旧基底、書戻し r6 += 8。
    step(&mut env, 0x0cc7_13f0);
    assert_eq!(gpr(&mut env, 6), 0x2008);
    assert_eq!(
        mem_bytes(&mut env, 0x2000, 8),
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
    );
}

// ---- 基底更新ロードで b == t の書き込み順（段階17・PR6 レビュー #1）----
// spec の Operation は基底更新（`GR[b] ← GR[b] + dx`）を先に行い
// `GR[t] ← mem_load(...)` を後に書くので、`,ma`/`,mb`/`,m`/`,sm` 完語
// で b == t のときロード値が書き戻し値に勝つ。
// Ref: SPEC-PARISC-11 §5-34/§5-42/§5-36/§5-39/§5-45/§5-40/§5-46
// （"If base register modification is specified and b = t, the value
// loaded is the …"）、SPEC-PARISC-20 §7-78/§7-87.

#[test]
fn exec_load_modify_base_eq_target_keeps_loaded() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    env.backend.mem.map(VirtAddr(0x1000), 2, Perms::RW).unwrap();
    // 0x1ff8 の qword 書込みの後で 0x1ffc の word 書込みが下位
    // 4 バイトを上書きするので、0x1ff8 の 64 ビットは
    // 0x9999_8888_aaaa_0001 になる。
    env.backend
        .mem
        .write(VirtAddr(0x1ff8), &0x9999_8888_7777_6666u64.to_be_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1ffc), &0xaaaa_0001u32.to_be_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0x1212_3434_5656_7878u64.to_be_bytes())
        .unwrap();
    set_gpr(&mut env, 7, 8);

    // オフセット形式（load_off 経路）: ldwm は常に基底更新。
    // ldwm -4(r9),r9（disp<0 → 事前更新、EA = 0x1ffc）。
    set_gpr(&mut env, 9, 0x2000);
    step(&mut env, 0x4d29_3ff9);
    assert_eq!(gpr(&mut env, 9), 0xaaaa_0001); // 0x1ffc ではない
    // Format 3 の ldd,mb r9,-8(r9)（EA = 0x1ff8 の 64 ビット。
    // 実メモリ値は上書き後の 0x9999_8888_aaaa_0001）。
    set_gpr(&mut env, 9, 0x2000);
    step(&mut env, 0x5129_3ffd);
    assert_eq!(gpr(&mut env, 9), 0x9999_8888_aaaa_0001);

    // im5 形式: ldw,ma r9,4(r9)（事後、EA = 旧 r9 = 0x2000）。
    set_gpr(&mut env, 9, 0x2000);
    step(&mut env, 0x0d28_10a9);
    assert_eq!(gpr(&mut env, 9), 0x1212_3434); // 0x2004 ではない
    // ldw,mb r9,-4(r9)（事前、EA = 0x1ffc）。
    set_gpr(&mut env, 9, 0x2000);
    step(&mut env, 0x0d39_30a9);
    assert_eq!(gpr(&mut env, 9), 0xaaaa_0001);

    // index 形式: ldbx,m r7(r9),r9（EA = r9、書戻しは r9+r7）。
    set_gpr(&mut env, 9, 0x2000);
    step(&mut env, 0x0d27_0029);
    assert_eq!(gpr(&mut env, 9), 0x12); // 先頭バイト
    // ldwx,m r7(r9),r9（u=0,m=1 → ,m 完語）。
    set_gpr(&mut env, 9, 0x2000);
    step(&mut env, 0x0d27_00a9);
    assert_eq!(gpr(&mut env, 9), 0x1212_3434); // 0x2008 ではない

    // 不可分ロード: ldcw,mb r9,-4(r9)（事前、EA = 0x1ffc、
    // ロードと 0 クリアは不可分）。
    set_gpr(&mut env, 9, 0x2000);
    step(&mut env, 0x0d39_31e9);
    assert_eq!(gpr(&mut env, 9), 0xaaaa_0001);
    assert_eq!(mem_bytes(&mut env, 0x1ffc, 4), [0, 0, 0, 0]);
    // ldcd,ma r9,8(r9)（事後、EA = 0x2000 の 64 ビット）。
    set_gpr(&mut env, 9, 0x2000);
    step(&mut env, 0x0d30_1169);
    assert_eq!(gpr(&mut env, 9), 0x1212_3434_5656_7878);
    // ldcwx,m r7(r9),r9 / ldcdx,m r7(r9),r9（index 形の ,m）。
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0xabcd_0000_1111_2222u64.to_be_bytes())
        .unwrap();
    set_gpr(&mut env, 9, 0x2000);
    step(&mut env, 0x0d27_01e9);
    assert_eq!(gpr(&mut env, 9), 0xabcd_0000);
    // ldcwx が 0x2000-0x2003 を 0 クリアしたので、ldcdx が読む
    // 64 ビットは上位 32 ビットが 0。
    set_gpr(&mut env, 9, 0x2000);
    step(&mut env, 0x0d27_0169);
    assert_eq!(gpr(&mut env, 9), 0x0000_0000_1111_2222);
    assert_eq!(mem_bytes(&mut env, 0x2000, 8), [0; 8]);

    // 絶対番地形: ldaw,ma r9,4(r9) / ldda,ma r9,8(r9)。
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0xabcd_0000_1111_2222u64.to_be_bytes())
        .unwrap();
    set_gpr(&mut env, 9, 0x2000);
    step(&mut env, 0x0d28_11a9);
    assert_eq!(gpr(&mut env, 9), 0xabcd_0000);
    set_gpr(&mut env, 9, 0x2000);
    step(&mut env, 0x0d30_1129);
    assert_eq!(gpr(&mut env, 9), 0xabcd_0000_1111_2222);
    // ldawx,m r7(r9),r9 / lddax,sm r7(r9),r9（,m / ,sm 完語）。
    set_gpr(&mut env, 9, 0x2000);
    step(&mut env, 0x0d27_01a9);
    assert_eq!(gpr(&mut env, 9), 0xabcd_0000);
    set_gpr(&mut env, 9, 0x2000);
    step(&mut env, 0x0d27_2129);
    assert_eq!(gpr(&mut env, 9), 0xabcd_0000_1111_2222);
}

#[test]
fn exec_probe_read_write() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.mem.map(VirtAddr(0x4000), 1, Perms::R).unwrap();
    // prober (r6),r3,r9: RW ページは読み可 → 1。
    // r3 の下位 2 ビットは検査対象特権だがフラットモデルでは結果に
    // 影響しない（GAP-0055）。
    set_gpr(&mut env, 6, 0x2000);
    set_gpr(&mut env, 3, 0xffff_fffd);
    step(&mut env, 0x04c3_1189);
    assert_eq!(gpr(&mut env, 9), 1);
    // probew (r6),r3,r9: 同じページは書き可 → 1。
    step(&mut env, 0x04c3_11c9);
    assert_eq!(gpr(&mut env, 9), 1);
    // R-only ページ: prober → 1、probew → 0。
    set_gpr(&mut env, 6, 0x4000);
    step(&mut env, 0x04c3_1189);
    assert_eq!(gpr(&mut env, 9), 1);
    set_gpr(&mut env, 9, 0xdead);
    step(&mut env, 0x04c3_11c9);
    assert_eq!(gpr(&mut env, 9), 0);
    // 未写像: prober/probew とも 0（spec ではハンドラが GR[t]←0
    // に畳むのと同じ観測結果）。
    set_gpr(&mut env, 6, 0x8000);
    set_gpr(&mut env, 9, 0xdead);
    step(&mut env, 0x04c3_1189);
    assert_eq!(gpr(&mut env, 9), 0);
    step(&mut env, 0x04c3_11c9);
    assert_eq!(gpr(&mut env, 9), 0);
    // proberi/probewi: bit13=1 で ri フィールドは 5 ビット即値
    // （その下位 2 ビットが検査対象特権）。番地は GR[b] のみ。
    set_gpr(&mut env, 6, 0x2000);
    step(&mut env, 0x04c3_3189); // proberi (r6),3,r9 → 1
    assert_eq!(gpr(&mut env, 9), 1);
    step(&mut env, 0x04c3_31c9); // probewi (r6),3,r9 → 1
    assert_eq!(gpr(&mut env, 9), 1);
    set_gpr(&mut env, 6, 0x4000);
    step(&mut env, 0x04c3_31c9); // probewi on R-only → 0
    assert_eq!(gpr(&mut env, 9), 0);
}

// break は break instruction trap を起こす。例外モデルは即値を
// 運ばないので種別 Break + code=0 で畳む。
// Ref: SPEC-PARISC-11 §BREAK, SPEC-PARISC-20 §7-18.
#[test]
fn exec_break_raises_break_trap() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    // break 1,2（000000 i5 i13 ... 00000000 ... → 0x0022_0000）。
    let insn = dec(0x0022_0000).unwrap();
    assert_eq!(insn, Insn::Break);
    let f = iaoq_f(&mut env);
    let r = sem::exec(&mut env.backend, insn, 0x0022_0000, f);
    let Err(InterpExit::Exception(e)) = r else {
        panic!("break should trap: {r:?}");
    };
    assert_eq!(e.kind, ExceptionKind::Break);
    assert_eq!(e.code, 0);
}

// diag は実装依存の診断命令で priv != 0 では特権操作トラップ。
// ユーザ専用モデルでは常に TRAP_PRIV。
// Ref: SPEC-PARISC-11 §DIAG, SPEC-PARISC-20 §7-46.
#[test]
fn exec_diag_traps_as_privileged() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    let insn = dec(0x1400_0000).unwrap();
    assert_eq!(insn, Insn::Diag);
    let f = iaoq_f(&mut env);
    let r = sem::exec(&mut env.backend, insn, 0x1400_0000, f);
    let Err(InterpExit::Exception(e)) = r else {
        panic!("diag should trap: {r:?}");
    };
    assert_eq!(e.kind, ExceptionKind::Trap);
    assert_eq!(e.code, sem::TRAP_PRIV);
}

// ---- FP 演算（段階17 PR9a）----
// 出典: SPEC-PARISC-11 §6 Table 6-5（RM）、§6-23（NaN/符号）、
// §6-49..§6-56（class 0/3）、Figure 6-6（FPSR フィールド）、
// SPEC-PARISC-20 §8 Table 8-1（frNL/frNR 規則）・§9。
// FPSR（f[0] の上位 32 ビット）のフラグは u64 の bits63..59
// （V,Z,O,U,I の順）、RM は bits42..41。

/// FPSR の丸めモードをセットする（その他の status ビットは 0）。
fn set_rm(env: &mut BareEnv, rm: u64) {
    set_fpr(env, 0, rm << 41);
}

/// FPSR 例外フラグ 5 個を [V,Z,O,U,I] の 0x10..0x01 として取り出す。
fn fpsr_flags(env: &mut BareEnv) -> u64 {
    (fpr(env, 0) >> 59) & 0x1f
}

// class 0（0C 形: `0C r 0 sub fmt 0 0 t`。`f` は左半分の単精度、
// `d` は全幅の倍精度）と class 3（`0C r1 r2 sub fmt 3 0 t`）。
#[test]
fn exec_fp_class0_nonarith_moves_bits() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    // fcpy,f fr4,fr5: 左半分だけコピーし右半分は保持。
    set_fpr(&mut env, 4, 0xbfc0_0000_1122_3344);
    set_fpr(&mut env, 5, 0xdead_beef_cafe_f00d);
    step(&mut env, 0x3080_4005);
    assert_eq!(fpr(&mut env, 5), 0xbfc0_0000_cafe_f00d);
    // fabs,f fr4,fr6: 符号ビットを落とす。
    step(&mut env, 0x3080_6006);
    assert_eq!(fpr(&mut env, 6) >> 32, 0x3fc0_0000);
    // fneg,f fr4,fr7: 符号を反転。
    step(&mut env, 0x3080_c007);
    assert_eq!(fpr(&mut env, 7) >> 32, 0x3fc0_0000);
    // fnegabs,f fr4,fr8: 符号を 1 にする。
    set_fpr(&mut env, 4, 0x3fc0_0000_0000_0000);
    step(&mut env, 0x3080_e008);
    assert_eq!(fpr(&mut env, 8) >> 32, 0xbfc0_0000);
    // fcpy,d は全 64 ビットをペイロード込みで写す（NaN でも
    // 例外を起こさずビットを保存する）。
    set_fpr(&mut env, 4, 0x7ff4_dead_beef_1234);
    step(&mut env, 0x3080_480b);
    assert_eq!(fpr(&mut env, 11), 0x7ff4_dead_beef_1234);
    // 非算術の符号操作は NaN 入力でも例外フラグを立てない。
    set_fpr(&mut env, 4, 0x7fc0_0000_0000_0000); // PA の通知型 NaN（fr4L）
    step(&mut env, 0x3080_600c); // fabs,f fr4,fr12
    step(&mut env, 0x3080_c00d); // fneg,f fr4,fr13
    step(&mut env, 0x3080_e010); // fnegabs,f fr4,fr16
    assert_eq!(fpsr_flags(&mut env), 0);
    assert_eq!(fpr(&mut env, 16) >> 32, 0xffc0_0000);
    // `,d`（fmt=01・全幅）の非算術 NaN でも同じ規則:
    // ペイロードを保存し例外フラグは立たない。
    set_fpr(&mut env, 4, 0xfff4_dead_beef_1234); // 負の通知型 NaN
    step(&mut env, 0x3080_680c); // fabs,d fr4,fr12
    assert_eq!(fpr(&mut env, 12), 0x7ff4_dead_beef_1234);
    step(&mut env, 0x3080_c80d); // fneg,d fr4,fr13
    assert_eq!(fpr(&mut env, 13), 0x7ff4_dead_beef_1234);
    step(&mut env, 0x3080_e810); // fnegabs,d fr4,fr16
    assert_eq!(fpr(&mut env, 16), 0xfff4_dead_beef_1234);
    assert_eq!(fpsr_flags(&mut env), 0);
}

// RM（FPSR bits42..41）ごとの算術結果。1/3 と -1/3 の無限二進
// 分数が 4 モードで IEEE どおりに分岐する。
#[test]
fn exec_fp_arith_rounding_modes() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    set_fpr(&mut env, 4, 0x3f80_0000_0000_0000); // fr4L = 1.0
    set_fpr(&mut env, 5, 0x4040_0000_0000_0000); // fr5L = 3.0
    // fdiv,f fr4,fr5,fr6 = 0x3085_6606。
    for (rm, want) in [
        (0u64, 0x3eaa_aaabu64), // 最近接
        (1, 0x3eaa_aaaa),       // 0 方向
        (2, 0x3eaa_aaab),       // +∞ 方向
        (3, 0x3eaa_aaaa),       // -∞ 方向
    ] {
        set_rm(&mut env, rm);
        step(&mut env, 0x3085_6606);
        assert_eq!(fpr(&mut env, 6) >> 32, want, "rm={rm}");
        assert_eq!(fpsr_flags(&mut env), 0x01, "rm={rm}: inexact");
    }
    // 負の商では +∞/-∞ が入れ替わる。
    set_fpr(&mut env, 4, 0xbf80_0000_0000_0000); // fr4L = -1.0
    for (rm, want) in [
        (0u64, 0xbeaa_aaabu64),
        (1, 0xbeaa_aaaa),
        (2, 0xbeaa_aaaa),
        (3, 0xbeaa_aaab),
    ] {
        set_rm(&mut env, rm);
        step(&mut env, 0x3085_6606);
        assert_eq!(fpr(&mut env, 6) >> 32, want, "neg rm={rm}");
    }
    // オーバーフローはモードで +∞ か最大有限値に分岐する。
    set_fpr(&mut env, 4, 0x7f7f_ffff_0000_0000); // fr4L = FLT_MAX
    set_fpr(&mut env, 5, 0x4000_0000_0000_0000); // fr5L = 2.0
    set_rm(&mut env, 0);
    step(&mut env, 0x3085_4606); // fmpy,f
    assert_eq!(fpr(&mut env, 6) >> 32, 0x7f80_0000); // +inf
    assert_eq!(fpsr_flags(&mut env), 0x04 | 0x01); // O + I
    set_fpr(&mut env, 0, 1 << 41); // RM = RTZ
    step(&mut env, 0x3085_4606);
    assert_eq!(fpr(&mut env, 6) >> 32, 0x7f7f_ffff); // 最大有限値
    assert_eq!(fpsr_flags(&mut env), 0x04 | 0x01);
}

// FRND は丸めて整数値の浮動小数点にする（SPEC-PARISC-11 §6-52）。
// 語形は fcpy と同じで sub=101。
#[test]
fn exec_fp_frnd_rounding_modes() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    set_fpr(&mut env, 4, 0x3fc0_0000_0000_0000); // fr4L = 1.5
    // frnd,f fr4,fr8 = 0x3080_a008。
    for (rm, want) in [
        (0u64, 0x4000_0000u64), // RNE → 2.0
        (1, 0x3f80_0000),       // RTZ → 1.0
        (2, 0x4000_0000),       // RUP → 2.0
        (3, 0x3f80_0000),       // RDN → 1.0
    ] {
        set_rm(&mut env, rm);
        step(&mut env, 0x3080_a008);
        assert_eq!(fpr(&mut env, 8) >> 32, want, "1.5 rm={rm}");
        assert_eq!(fpsr_flags(&mut env), 0x01, "1.5 rm={rm}: inexact");
    }
    // 同距離は偶数へ（2.5 → 2.0）。
    set_fpr(&mut env, 4, 0x4020_0000_0000_0000); // fr4L = 2.5
    set_rm(&mut env, 0);
    step(&mut env, 0x3080_a008);
    assert_eq!(fpr(&mut env, 8) >> 32, 0x4000_0000); // 2.0
    set_fpr(&mut env, 0, 2 << 41); // RUP
    step(&mut env, 0x3080_a008);
    assert_eq!(fpr(&mut env, 8) >> 32, 0x4040_0000); // 3.0
    // 0.5 は RNE で +0.0（偶数側）。RUP では +1.0。
    set_fpr(&mut env, 4, 0x3f00_0000_0000_0000);
    set_rm(&mut env, 0);
    step(&mut env, 0x3080_a008);
    assert_eq!(fpr(&mut env, 8) >> 32, 0);
    set_fpr(&mut env, 0, 2 << 41);
    step(&mut env, 0x3080_a008);
    assert_eq!(fpr(&mut env, 8) >> 32, 0x3f80_0000); // +1.0
    // -0.25 は RUP で -0.0（符号は保持）、RDN で -1.0。
    set_fpr(&mut env, 4, 0xbe80_0000_0000_0000);
    set_fpr(&mut env, 0, 2 << 41);
    step(&mut env, 0x3080_a008);
    assert_eq!(fpr(&mut env, 8) >> 32, 0x8000_0000); // -0.0
    set_fpr(&mut env, 0, 3 << 41);
    step(&mut env, 0x3080_a008);
    assert_eq!(fpr(&mut env, 8) >> 32, 0xbf80_0000); // -1.0
    // 既に整数の値（2.0）は正確に戻る。
    set_fpr(&mut env, 4, 0x4000_0000_0000_0000);
    set_rm(&mut env, 0);
    step(&mut env, 0x3080_a008);
    assert_eq!(fpr(&mut env, 8) >> 32, 0x4000_0000);
    assert_eq!(fpsr_flags(&mut env), 0);
}

// NaN の極性は IEEE 754-2008 と逆（仮数 b1=1 が通知型、0 が
// 静止型）。結果の NaN 選択は SPEC-PARISC-11 §6-23 の規則。
#[test]
fn exec_fp_nan_polarity_and_quieting() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    set_fpr(&mut env, 4, 0x3f80_0000_0000_0000); // fr4L = 1.0
    // PA 静止型 NaN（b1=0）は IEEE の通知型に見えるが、PA では
    // 例外なしにそのまま伝搬する。
    set_fpr(&mut env, 5, 0x7f80_0001_0000_0000); // fr5L = qNaN
    set_rm(&mut env, 0);
    step(&mut env, 0x3085_0606); // fadd,f fr4,fr5,fr6
    assert_eq!(fpr(&mut env, 6) >> 32, 0x7f80_0001);
    assert_eq!(fpsr_flags(&mut env), 0);
    // PA 通知型 NaN（b1=1）は静止化（b1→0。残り仮数が全 0 なら
    // b2→1）して V を立てる。
    set_fpr(&mut env, 5, 0x7fc0_0000_0000_0000); // fr5L = sNaN
    step(&mut env, 0x3085_0606);
    assert_eq!(fpr(&mut env, 6) >> 32, 0x7fa0_0000);
    assert_eq!(fpsr_flags(&mut env), 0x10); // V
    // 第 1 オペランド側の通知型も同じ静止化を受ける。
    set_fpr(&mut env, 4, 0x7fd0_0000_0000_0000); // fr4L = sNaN(残り仮数あり)
    set_fpr(&mut env, 5, 0x3f80_0000_0000_0000);
    step(&mut env, 0x3085_0606);
    assert_eq!(fpr(&mut env, 6) >> 32, 0x7f90_0000);
    // sNaN は qNaN より優先して選ばれる。
    set_fpr(&mut env, 4, 0x7f80_0001_0000_0000); // qNaN
    set_fpr(&mut env, 5, 0x7fc0_0000_0000_0000); // sNaN
    step(&mut env, 0x3085_0606);
    assert_eq!(fpr(&mut env, 6) >> 32, 0x7fa0_0000);
    // 非 NaN オペランドの無効演算（∞-∞、0×∞、0/0、sqrt(負)）は
    // 既定 NaN（b2=1、他は 0）と V フラグになる。
    set_fpr(&mut env, 4, 0x7f80_0000_0000_0000); // fr4L = +inf
    set_fpr(&mut env, 5, 0x7f80_0000_0000_0000); // fr5L = +inf
    set_fpr(&mut env, 0, 0); // フラグをクリアして確認しやすくする
    step(&mut env, 0x3085_2606); // fsub,f inf-inf
    assert_eq!(fpr(&mut env, 6) >> 32, 0x7fa0_0000);
    assert_eq!(fpsr_flags(&mut env), 0x10);
    set_fpr(&mut env, 5, 0x0000_0000_0000_0000); // fr5L = +0.0
    set_fpr(&mut env, 0, 0);
    step(&mut env, 0x3085_4606); // fmpy,f inf*0
    assert_eq!(fpr(&mut env, 6) >> 32, 0x7fa0_0000);
    assert_eq!(fpsr_flags(&mut env), 0x10);
    // 0/0 も無効演算。1/0 は 0 除算（Z）。
    set_fpr(&mut env, 4, 0x0000_0000_0000_0000);
    set_fpr(&mut env, 0, 0);
    step(&mut env, 0x3085_6606); // fdiv,f 0/0
    assert_eq!(fpr(&mut env, 6) >> 32, 0x7fa0_0000);
    assert_eq!(fpsr_flags(&mut env), 0x10);
    set_fpr(&mut env, 4, 0x3f80_0000_0000_0000); // 1.0
    set_fpr(&mut env, 0, 0);
    step(&mut env, 0x3085_6606); // fdiv,f 1.0/0.0
    assert_eq!(fpr(&mut env, 6) >> 32, 0x7f80_0000); // +inf
    assert_eq!(fpsr_flags(&mut env), 0x08); // Z
    // fsqrt(-1.0) → 既定 NaN + V。fsqrt(-0.0) は -0.0 のまま。
    set_fpr(&mut env, 4, 0xbf80_0000_0000_0000);
    set_fpr(&mut env, 0, 0);
    step(&mut env, 0x3080_8007); // fsqrt,f fr4,fr7
    assert_eq!(fpr(&mut env, 7) >> 32, 0x7fa0_0000);
    assert_eq!(fpsr_flags(&mut env), 0x10);
    set_fpr(&mut env, 4, 0x8000_0000_0000_0000);
    set_fpr(&mut env, 0, 0);
    step(&mut env, 0x3080_8007);
    assert_eq!(fpr(&mut env, 7) >> 32, 0x8000_0000);
    assert_eq!(fpsr_flags(&mut env), 0);
    // 倍精度でも同じ極性。fr4 = dbl sNaN。
    set_fpr(&mut env, 4, 0x7ff8_0000_0000_0000);
    set_fpr(&mut env, 5, 0x3ff0_0000_0000_0000); // 1.0
    set_fpr(&mut env, 0, 0);
    step(&mut env, 0x3085_0e06); // fadd,d
    assert_eq!(fpr(&mut env, 6), 0x7ff4_0000_0000_0000);
    assert_eq!(fpsr_flags(&mut env), 0x10);
}

// 非正規化数（denormal）はフル精度で扱う（D ビット高速モードは
// モデル化しない）。UF は「結果が微小かつ不正確」のときだけ立つ。
#[test]
fn exec_fp_denormals_and_underflow() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    set_rm(&mut env, 0);
    // 最小 denormal + denormal は正確な denormal（UF なし）。
    set_fpr(&mut env, 4, 0x0000_0001_0000_0000);
    set_fpr(&mut env, 5, 0x0000_0002_0000_0000);
    step(&mut env, 0x3085_0606); // fadd,f
    assert_eq!(fpr(&mut env, 6) >> 32, 0x0000_0003);
    assert_eq!(fpsr_flags(&mut env), 0);
    // denormal のまま最大値: 0x007fffff + 0x00000001。
    set_fpr(&mut env, 4, 0x007f_ffff_0000_0000);
    set_fpr(&mut env, 5, 0x0000_0001_0000_0000);
    step(&mut env, 0x3085_0606);
    assert_eq!(fpr(&mut env, 6) >> 32, 0x0080_0000); // 最小正規数
    // denormal × 0.75 → 0.75ulp → 1ulp に丸まるが微小かつ
    // 不正確なので U + I。
    set_fpr(&mut env, 4, 0x0000_0001_0000_0000);
    set_fpr(&mut env, 5, 0x3f40_0000_0000_0000); // 0.75
    set_fpr(&mut env, 0, 0);
    step(&mut env, 0x3085_4606); // fmpy,f
    assert_eq!(fpr(&mut env, 6) >> 32, 0x0000_0001);
    assert_eq!(fpsr_flags(&mut env), 0x02 | 0x01); // U + I
    // denormal × 0.5 は 0.5ulp → RNE では +0（タイを偶数側へ）。
    set_fpr(&mut env, 5, 0x3f00_0000_0000_0000); // 0.5
    set_fpr(&mut env, 0, 0);
    step(&mut env, 0x3085_4606);
    assert_eq!(fpr(&mut env, 6) >> 32, 0);
    assert_eq!(fpsr_flags(&mut env), 0x02 | 0x01); // U + I
    // フラグは sticky：直後の正確な演算では消えない。
    set_fpr(&mut env, 4, 0x3f80_0000_0000_0000);
    set_fpr(&mut env, 5, 0x3f80_0000_0000_0000);
    step(&mut env, 0x3085_0606); // 1.0 + 1.0 = 2.0 正確
    assert_eq!(fpr(&mut env, 6) >> 32, 0x4000_0000);
    assert_eq!(fpsr_flags(&mut env), 0x02 | 0x01); // U+I は保持
    // 非正規化オペランドの fsqrt も扱える。sqrt(0x00000002)
    // = sqrt(2·2^-149) = 2^-74（正規数、正確）。
    set_fpr(&mut env, 4, 0x0000_0002_0000_0000);
    set_fpr(&mut env, 0, 0);
    step(&mut env, 0x3080_8007); // fsqrt,f
    assert_eq!(fpr(&mut env, 7) >> 32, 0x1a80_0000);
    assert_eq!(fpsr_flags(&mut env), 0);
}

// L/R 半レジスタ選択（0E 形）。`fw` は 6 ビット番号（bit5=R）、
// `dw` は 5 ビット全レジスタ。0C の `,f` は左半分。
#[test]
fn exec_fp_lr_half_selection() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    set_rm(&mut env, 0);
    set_fpr(&mut env, 4, 0x3f80_0000_4000_0000); // fr4L=1.0 fr4R=2.0
    set_fpr(&mut env, 5, 0x4040_0000_4080_0000); // fr5L=3.0 fr5R=4.0
    set_fpr(&mut env, 6, 0xdead_beef_cafe_babe);
    // fadd,fw fr4R,fr5R,fr6R: 2.0+4.0=6.0 を右半分へ。左は保持。
    step(&mut env, 0x3885_16c6);
    assert_eq!(fpr(&mut env, 6), 0xdead_beef_40c0_0000);
    // fadd,fw fr4L,fr5L,fr6L: 1.0+3.0=4.0 を左半分へ。
    step(&mut env, 0x3885_0606);
    assert_eq!(fpr(&mut env, 6), 0x4080_0000_40c0_0000);
    // fcpy,fw fr4R,fr7L: 右→左の交差コピー。
    set_fpr(&mut env, 7, 0x1111_2222_3333_4444);
    step(&mut env, 0x3880_4087);
    assert_eq!(fpr(&mut env, 7), 0x4000_0000_3333_4444);
    // fsqrt,fw fr5R,fr9R: sqrt(4.0)=2.0。
    set_fpr(&mut env, 9, 0xa5a5_a5a5_5a5a_5a5a);
    step(&mut env, 0x38a0_80c9);
    assert_eq!(fpr(&mut env, 9), 0xa5a5_a5a5_4000_0000);
    // fmpy,fw fr4R,fr5R,fr8R: 2.0*4.0=8.0。
    set_fpr(&mut env, 8, 0x0123_4567_89ab_cdef);
    step(&mut env, 0x3885_56c8);
    assert_eq!(fpr(&mut env, 8), 0x0123_4567_4100_0000);
    // 0C の `,d` 形と 0E の `,dw` 形は同じ全幅演算。
    set_fpr(&mut env, 4, 0x3ff0_0000_0000_0000); // 1.0
    set_fpr(&mut env, 5, 0x4008_0000_0000_0000); // 3.0
    step(&mut env, 0x3085_0e06); // fadd,d
    assert_eq!(fpr(&mut env, 6), 0x4010_0000_0000_0000); // 4.0
    set_fpr(&mut env, 6, 0);
    step(&mut env, 0x3885_0e06); // fadd,dw
    assert_eq!(fpr(&mut env, 6), 0x4010_0000_0000_0000);
    // fcpy,dw fr4,fr11: 全 64 ビットのコピー。
    step(&mut env, 0x3880_480b);
    assert_eq!(fpr(&mut env, 11), 0x3ff0_0000_0000_0000);
    // fr0 は非 load/store のソースとして +0.0 を供給する。
    // fadd,f fr0,fr4,fr6（r1=0）→ fr6L = fr4L。
    set_fpr(&mut env, 4, 0x3f80_0000_1234_5678); // fr4L = 1.0
    set_fpr(&mut env, 6, 0);
    step(&mut env, 0x3004_0606);
    assert_eq!(fpr(&mut env, 6), 0x3f80_0000_0000_0000);
}

// FPSR（f[0] 上位）: FID の model/revision、fstd fr0 の T クリア、
// enable ビットはフラグ集約のみ（トラップ配送なし、GAP-0057）。
#[test]
fn exec_fp_status_register() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    // FID: model/revision 以外の status ビットは不定（モデルでは
    // 0）、model=0（ソフトウェアエミュレーション予約）・
    // revision=4。下位半分（例外レジスタ 1）は保持。
    set_fpr(&mut env, 0, 0xa5a5_a5a5_5a5a_5a5a);
    step(&mut env, 0x3000_0000); // fid
    assert_eq!(fpr(&mut env, 0), 0x0000_2000_5a5a_5a5a);
    // fstd fr0,0(r6): 格納される値は T 込みの現値で、完了後に
    // FPSR.T ← 0。
    set_fpr(
        &mut env,
        0,
        sem::FPSR_T | (2u64 << 41) | 0x0000_0000_1234_5678,
    );
    set_gpr(&mut env, 6, 0x2000);
    step(&mut env, 0x2cc0_1200); // fstd fr0,0(r6)
    assert_eq!(
        mem_bytes(&mut env, 0x2000, 8),
        [0x00, 0x00, 0x04, 0x40, 0x12, 0x34, 0x56, 0x78]
    );
    assert_eq!(fpr(&mut env, 0) & sem::FPSR_T, 0);
    // enable ビットが立っていても例外はフラグ集約のみ（トラップ
    // 配送経路がない設計判断）。
    set_fpr(&mut env, 0, sem::FPSR_ENA); // 全 enable = 1
    set_fpr(&mut env, 4, 0x0000_0000_0000_0000);
    set_fpr(&mut env, 5, 0x0000_0000_0000_0000);
    step(&mut env, 0x3085_6606); // fdiv,f 0/0
    assert_eq!(fpr(&mut env, 6) >> 32, 0x7fa0_0000);
    assert_eq!(
        fpr(&mut env, 0) & sem::FPSR_FLAG_V,
        sem::FPSR_FLAG_V,
        "enable でもフラグ集約のみ"
    );
    // fr0 宛の書き込みは非 load/store では捨てられる
    // （undefined op の決定的評価）。
    set_fpr(&mut env, 0, 0x5a5a_5a5a_5a5a_5a5a);
    set_fpr(&mut env, 4, 0x3f80_0000_0000_0000);
    step(&mut env, 0x3085_0600); // fadd,f fr4,fr5,fr0
    assert_eq!(fpr(&mut env, 0), 0x5a5a_5a5a_5a5a_5a5a);
}

// ---- FP 変換/比較/多重・融合演算（段階17 PR9b）----
// 出典: SPEC-PARISC-11 §6-45..§6-48（FCNV 系）・§6-23（NaN/
// 例外）・§6-19 Table 6-17（多重演算の半レジスタ指定）・
// §6-57..§6-59、SPEC-PARISC-20 §8-16 Table 8-11/8-12・
// Table 8-13..8-17・§9-4 FCMP・§9-16/§9-17 FMPYFADD/
// FMPYNFADD・§9-28 FTEST・§9-30 XMPYU・§10（例外結果）。
// エンコードは生成された encode() を使い、オペランド順は
// ISADL の extract_ops と同じ。

fn enc(i: Insn, ops: &[u64]) -> u32 {
    encode(i, ops).unwrap() as u32
}

// f32/d32 の相互変換と丸め・例外フラグ。
#[test]
fn exec_fcnv_float_float() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    // fcnv,d_f fr5,fr6: 1.5d → 0x3fc0_0000（正確、例外なし）。
    set_fpr(&mut env, 5, 0x3ff8_0000_0000_0000);
    step(&mut env, enc(Insn::FcnvDF, &[5, 6]));
    assert_eq!(fpr(&mut env, 6) >> 32, 0x3fc0_0000);
    assert_eq!(fpsr_flags(&mut env), 0);
    // fcnv,f_d fr6,fr7: 単精度→倍精度は常に正確。
    step(&mut env, enc(Insn::FcnvFD, &[6, 7]));
    assert_eq!(fpr(&mut env, 7), 0x3ff8_0000_0000_0000);
    assert_eq!(fpsr_flags(&mut env), 0);
    // 1+2^-52 を単精度へ: 最近接は 1.0、+∞ 方向は 1.0+ulp。
    // どちらも inexact。
    set_fpr(&mut env, 5, 0x3ff0_0000_0000_0001);
    set_rm(&mut env, 0);
    step(&mut env, enc(Insn::FcnvDF, &[5, 6]));
    assert_eq!(fpr(&mut env, 6) >> 32, 0x3f80_0000);
    assert_eq!(fpsr_flags(&mut env), 0x01);
    set_rm(&mut env, 2);
    step(&mut env, enc(Insn::FcnvDF, &[5, 6]));
    assert_eq!(fpr(&mut env, 6) >> 32, 0x3f80_0001);
    assert_eq!(fpsr_flags(&mut env), 0x01);
    // 2^130 は単精度の範囲外: 最近接は +∞（O+I）、0 方向は
    // 最大有限値 0x7f7f_ffff（O+I）。SPEC-PARISC-20 Table 10-7。
    set_fpr(&mut env, 5, 0x4810_0000_0000_0000);
    set_rm(&mut env, 0);
    step(&mut env, enc(Insn::FcnvDF, &[5, 6]));
    assert_eq!(fpr(&mut env, 6) >> 32, 0x7f80_0000);
    assert_eq!(fpsr_flags(&mut env), 0x04 | 0x01);
    set_rm(&mut env, 1);
    step(&mut env, enc(Insn::FcnvDF, &[5, 6]));
    assert_eq!(fpr(&mut env, 6) >> 32, 0x7f7f_ffff);
    assert_eq!(fpsr_flags(&mut env), 0x04 | 0x01);
    // NaN 変換: 倍精度通知 NaN（b1=1）→ 単精度では静止化
    // （b1→0・残り 0 なので b2=1）して V を立てる。
    // Ref: SPEC-PARISC-11 §6-23, SPEC-PARISC-20 §8-23.
    set_rm(&mut env, 0);
    set_fpr(&mut env, 5, 0x7ff8_0000_0000_0000);
    step(&mut env, enc(Insn::FcnvDF, &[5, 6]));
    assert_eq!(fpr(&mut env, 6) >> 32, 0x7fa0_0000);
    assert_eq!(fpsr_flags(&mut env), 0x10);
    // 逆方向でも同じ規則: 通知 NaN → 静止 NaN + V。
    set_fpr(&mut env, 0, 0);
    set_fpr(&mut env, 6, 0x7fc0_0000_dead_beef);
    step(&mut env, enc(Insn::FcnvFD, &[6, 7]));
    assert_eq!(fpr(&mut env, 7), 0x7ff4_0000_0000_0000);
    assert_eq!(fpsr_flags(&mut env), 0x10);
}

// 整数→浮動小数点（w/q/uw/uq）。
#[test]
fn exec_fcnv_int_to_float() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    set_rm(&mut env, 0);
    // fcnv,w_f fr4,fr6: fr4L の int 7 → 7.0f。
    set_fpr(&mut env, 4, 0x0000_0007_dead_beef);
    step(&mut env, enc(Insn::FcnvWF, &[4, 6]));
    assert_eq!(fpr(&mut env, 6) >> 32, 0x40e0_0000);
    // fcnv,w_d fr4,fr7: int -3 → -3.0d（符号つき）。
    set_fpr(&mut env, 4, 0xffff_fffd_0000_0000);
    step(&mut env, enc(Insn::FcnvWD, &[4, 7]));
    assert_eq!(fpr(&mut env, 7), 0xc008_0000_0000_0000);
    // fcnv,uw_d fr4,fr7: 0xffff_fffd を符号なしで 4294967293.0d。
    step(&mut env, enc(Insn::FcnvUwD, &[4, 7]));
    assert_eq!(fpr(&mut env, 7), 0x41ef_ffff_ffa0_0000);
    // fcnv,q_f fr5,fr6: i64 9 → 9.0f。
    set_fpr(&mut env, 5, 0x0000_0000_0000_0009);
    step(&mut env, enc(Insn::FcnvQF, &[5, 6]));
    assert_eq!(fpr(&mut env, 6) >> 32, 0x4110_0000);
    // fcnv,uq_d fr5,fr7: u64::MAX → 2^64 = 0x43f0...（inexact）。
    set_fpr(&mut env, 5, 0xffff_ffff_ffff_ffff);
    step(&mut env, enc(Insn::FcnvUqD, &[5, 7]));
    assert_eq!(fpr(&mut env, 7), 0x43f0_0000_0000_0000);
    assert_eq!(fpsr_flags(&mut env), 0x01);
    // fcnv,q_d fr5,fr7: -1 → -1.0d（符号つき 64 ビット）。
    step(&mut env, enc(Insn::FcnvQD, &[5, 7]));
    assert_eq!(fpr(&mut env, 7), 0xbff0_0000_0000_0000);
    // fcnv,uw_f fr4,fr6: u32::MAX → 2^32（inexact）。
    set_fpr(&mut env, 4, 0xffff_ffff_0000_0000);
    step(&mut env, enc(Insn::FcnvUwF, &[4, 6]));
    assert_eq!(fpr(&mut env, 6) >> 32, 0x4f80_0000);
    assert_eq!(fpsr_flags(&mut env), 0x01);
}

// 浮動小数点→整数（T 完語と符号なし形を含む）。
#[test]
fn exec_fcnv_float_to_int() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    // fcnv,f_w fr4,fr6: 2.5f は RM で分岐。
    set_fpr(&mut env, 4, 0x4020_0000_0000_0000);
    for (rm, want) in [(0u64, 2u64), (1, 2), (2, 3), (3, 2)] {
        set_rm(&mut env, rm);
        step(&mut env, enc(Insn::FcnvFW, &[4, 6]));
        assert_eq!(fpr(&mut env, 6) >> 32, want, "rm={rm}");
        assert_eq!(fpsr_flags(&mut env), 0x01, "rm={rm}: inexact");
    }
    // -2.5f の T 完語（fcnv_t_f_w）は RM に依らず -2。
    set_fpr(&mut env, 4, 0xc020_0000_0000_0000);
    for rm in [0u64, 1, 2, 3] {
        set_rm(&mut env, rm);
        step(&mut env, enc(Insn::FcnvTFW, &[4, 6]));
        assert_eq!(fpr(&mut env, 6) >> 32, 0xffff_fffe, "rm={rm}");
        assert_eq!(fpsr_flags(&mut env), 0x01);
    }
    // fcnv,d_q fr5,fr7: -3.7d を T 完語で i64 -3。
    set_fpr(&mut env, 5, 0xc00d_9999_9999_999a);
    set_rm(&mut env, 0);
    step(&mut env, enc(Insn::FcnvTDQ, &[5, 7]));
    assert_eq!(fpr(&mut env, 7), 0xffff_ffff_ffff_fffd);
    assert_eq!(fpsr_flags(&mut env), 0x01);
    // fcnv,f_uw fr4,fr6: 3.5f → 符号なし 4。
    set_fpr(&mut env, 4, 0x4060_0000_0000_0000);
    step(&mut env, enc(Insn::FcnvFUw, &[4, 6]));
    assert_eq!(fpr(&mut env, 6) >> 32, 4);
    // fcnv,d_uq fr5,fr7: 2.9d T 完語 → u64 2。
    set_fpr(&mut env, 5, 0x4007_3333_3333_3333);
    step(&mut env, enc(Insn::FcnvTDUq, &[5, 7]));
    assert_eq!(fpr(&mut env, 7), 2);
    // NaN→整数は invalid で「最大整数」を配達 + V フラグ。
    // Ref: SPEC-PARISC-20 Table 10-6。累積した inexact を
    // 先に掃いてから見る。
    set_fpr(&mut env, 0, 0);
    set_fpr(&mut env, 4, 0x7f80_0001_0000_0000); // PA 静止 NaN
    step(&mut env, enc(Insn::FcnvFW, &[4, 6]));
    assert_eq!(fpr(&mut env, 6) >> 32, 0x7fff_ffff);
    assert_eq!(fpsr_flags(&mut env), 0x10);
    // ±∞ → int も invalid + V（値は飽和）。
    set_fpr(&mut env, 0, 0);
    set_fpr(&mut env, 4, 0x7f80_0000_0000_0000); // +inf
    step(&mut env, enc(Insn::FcnvFW, &[4, 6]));
    assert_eq!(fpsr_flags(&mut env), 0x10);
}

// FCMP: キュー比較の C/CQ 更新・的付け CA 書き込み・
// unordered と invalid の扱い。
#[test]
fn exec_fcmp_queue_and_target() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    set_fpr(&mut env, 4, 0x3f80_0000_0000_0000); // fr4L = 1.0
    set_fpr(&mut env, 5, 0x4040_0000_0000_0000); // fr5L = 3.0
    // fcmp,f fr4,fr5,`<`=9（<、unordered で invalid）:
    // 1.0<3.0 なので C←1、CQ は右シフト。
    step(&mut env, enc(Insn::FcmpF, &[4, 5, 0, 9]));
    assert_ne!(fpr(&mut env, 0) & sem::FPSR_C, 0);
    assert_eq!(fpsr_flags(&mut env), 0);
    // 直後の fcmp,d fr6,fr7 `=`=4: 2.0==2.0 → C=1、CQ{0} に
    // 前の C=1 が入る（u64 bit53）。
    set_fpr(&mut env, 6, 0x4000_0000_0000_0000);
    set_fpr(&mut env, 7, 0x4000_0000_0000_0000);
    step(&mut env, enc(Insn::FcmpD, &[6, 7, 0, 4]));
    let s = fpr(&mut env, 0);
    assert_ne!(s & sem::FPSR_C, 0);
    assert_ne!(s & (1 << 53), 0, "CQ{{0}} ← 前 C");
    assert_eq!(fpsr_flags(&mut env), 0);
    // 今度は 1.0<3.0 に `>`=17（invalid 要求あり、gt のみ）:
    // 結果 0 で C=0、CQ{0}←前 C=1。
    step(&mut env, enc(Insn::FcmpF, &[4, 5, 0, 17]));
    let s = fpr(&mut env, 0);
    assert_eq!(s & sem::FPSR_C, 0);
    // unordered: qNaN 同士を `,<=`=13（lt|eq + invalid 要求）。
    // 結果は 0、V フラグが立つ。
    set_fpr(&mut env, 4, 0x7f80_0001_0000_0000); // PA 静止 NaN
    step(&mut env, enc(Insn::FcmpF, &[4, 4, 0, 13]));
    assert_eq!(fpr(&mut env, 0) & sem::FPSR_C, 0);
    assert_eq!(fpsr_flags(&mut env), 0x10);
    // `,?`=2（unordered のみ・invalid 要求なし）なら C=1、
    // V は立たない。
    set_fpr(&mut env, 0, 0);
    step(&mut env, enc(Insn::FcmpF, &[4, 4, 0, 2]));
    assert_ne!(fpr(&mut env, 0) & sem::FPSR_C, 0);
    assert_eq!(fpsr_flags(&mut env), 0);
    // `,!?`=28（ordered、invalid 要求なし）は unordered で
    // C=0・V なし。
    set_fpr(&mut env, 0, 0);
    step(&mut env, enc(Insn::FcmpF, &[4, 4, 0, 28]));
    assert_eq!(fpr(&mut env, 0) & sem::FPSR_C, 0);
    assert_eq!(fpsr_flags(&mut env), 0);
    // 的付け比較: y=1 → CA{0}（HP bit6=u64 bit57）に
    // `>=`=21 の結果。通知 NaN 入力なら V も立つ。
    set_fpr(&mut env, 0, 0);
    set_fpr(&mut env, 4, 0x7fc0_0000_0000_0000); // 通知 NaN
    step(&mut env, enc(Insn::FcmpF, &[4, 5, 1, 21]));
    assert_eq!(fpsr_flags(&mut env), 0x10, "sNaN は常に invalid");
    // 普通の値での的付け: 3.0>=1.0 → CA{0}=1。
    set_fpr(&mut env, 0, 0);
    set_fpr(&mut env, 4, 0x4040_0000_0000_0000);
    set_fpr(&mut env, 5, 0x3f80_0000_0000_0000);
    step(&mut env, enc(Insn::FcmpF, &[4, 5, 1, 21]));
    assert_ne!(fpr(&mut env, 0) & (1 << 57), 0, "CA{{0}}=1");
    assert_eq!(fpsr_flags(&mut env), 0);
}

// FTEST: キューテスト/的付けテストが PSW.N を立てる。
#[test]
fn exec_ftest_sets_psw_n() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    // C=1 を作ってから簡易テスト（c=0、y=1）→ PSW.N=1。
    set_fpr(&mut env, 4, 0x3f80_0000_0000_0000);
    set_fpr(&mut env, 5, 0x3f80_0000_0000_0000);
    step(&mut env, enc(Insn::FcmpF, &[4, 5, 0, 4])); // `=` → C=1
    step(&mut env, enc(Insn::Ftest, &[1, 0]));
    assert_ne!(
        env.backend.get(sem::psw_ref()) & sem::PSW_N,
        0,
        "Simple Test で PSW.N"
    );
    // ACC（c=1）: C=0 && CQ{0..10}==0 のとき真。
    // 直前の C は 1 なので、まず C=0 の比較を入れて CQ を
    // 進める: `,false?`=0 は必ず 0 → C=0、CQ{0}=1 が残り
    // ACC は偽のはず。
    step(&mut env, enc(Insn::FcmpF, &[4, 5, 0, 0]));
    step(&mut env, enc(Insn::Ftest, &[1, 1]));
    assert_eq!(env.backend.get(sem::psw_ref()) & sem::PSW_N, 0);
    // CQ を空にするため C=0 の比較を 12 回回してから ACC
    // （キューの古い C=1 が CQ{10} まで流れて排出される）。
    for _ in 0..12 {
        step(&mut env, enc(Insn::FcmpF, &[4, 5, 0, 0]));
    }
    step(&mut env, enc(Insn::Ftest, &[1, 1]));
    assert_ne!(env.backend.get(sem::psw_ref()) & sem::PSW_N, 0);
    // 的付けテスト: CA{0} に 1 を置く的付け比較（y=1）後、
    // y=0（xor(0+1,1)=0 で CA{0} を指す）の FTEST → N=1。
    // 直前の ACC テストで立った N はこの fcmp を nullify
    // するので、先に空ステップで消費しておく。
    step(&mut env, enc(Insn::FcmpF, &[4, 5, 0, 0])); // nullify 消費
    set_fpr(&mut env, 0, 0);
    step(&mut env, enc(Insn::FcmpF, &[4, 5, 1, 4])); // CA{0} ← (1.0==1.0)
    step(&mut env, enc(Insn::Ftest, &[0, 0]));
    assert_ne!(
        env.backend.get(sem::psw_ref()) & sem::PSW_N,
        0,
        "CA{{0}}=1 の的付けテスト"
    );
    // CA{2} が 0 なら対応する的付けテスト（y=(2+1)^1=2）は
    // N を立てない。ここでも立った N を空ステップで消費する。
    step(&mut env, enc(Insn::FcmpF, &[4, 5, 0, 0])); // nullify 消費
    set_fpr(&mut env, 0, 0);
    step(&mut env, enc(Insn::FcmpF, &[4, 5, 1, 4])); // CA{0}=1 のみ
    step(&mut env, enc(Insn::Ftest, &[2, 0]));
    assert_eq!(env.backend.get(sem::psw_ref()) & sem::PSW_N, 0);
}

// 多重演算（fmpyadd/fmpysub: 分解型）と融合 fmpyfadd。
#[test]
fn exec_fmpy_multi_and_fused() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    set_rm(&mut env, 0);
    // fmpyadd,f: 5 ビット指定子は上位 16 レジスタの半分選択
    // （Table 8-17: spec 0→16L, 16→16R, 1→17L …）。
    // rm1=0(fr16L=2.0f)*rm2=1(fr17L=3.0f) → tm=2(fr18L)=6.0f。
    // ta=3(fr19L=10.0f)+ra=4(fr20L=4.0f) → ta=14.0f。
    set_fpr(&mut env, 16, 0x4000_0000_1234_5678);
    set_fpr(&mut env, 17, 0x4040_0000_0000_0000);
    set_fpr(&mut env, 18, 0xdead_beef_dead_beef);
    set_fpr(&mut env, 19, 0x4120_0000_0000_0000);
    set_fpr(&mut env, 20, 0x4080_0000_0000_0000);
    step(&mut env, enc(Insn::FmpyaddF, &[0, 1, 3, 4, 2]));
    assert_eq!(fpr(&mut env, 18) >> 32, 0x40c0_0000, "tm=6.0");
    assert_eq!(fpr(&mut env, 19) >> 32, 0x4160_0000, "ta=14.0");
    assert_eq!(fpsr_flags(&mut env), 0);
    // spec 16 は右半分（fr16R）を選ぶ: rm1=16 → fr16R。
    set_fpr(&mut env, 16, 0x0000_0000_4000_0000); // fr16R = 2.0f
    step(&mut env, enc(Insn::FmpyaddF, &[16, 1, 3, 4, 2]));
    assert_eq!(fpr(&mut env, 18) >> 32, 0x40c0_0000);
    // fmpysub,d: 5 ビット指定子は全レジスタ。
    // rm1=5(4.0d)*rm2=6(2.0d) → tm=7 = 8.0d。
    // ta=8(20.0d)-ra=9(5.0d) → ta = 15.0d。
    set_fpr(&mut env, 5, 0x4010_0000_0000_0000);
    set_fpr(&mut env, 6, 0x4000_0000_0000_0000);
    set_fpr(&mut env, 7, 0);
    set_fpr(&mut env, 8, 0x4034_0000_0000_0000);
    set_fpr(&mut env, 9, 0x4014_0000_0000_0000);
    step(&mut env, enc(Insn::FmpysubD, &[5, 6, 8, 9, 7]));
    assert_eq!(fpr(&mut env, 7), 0x4020_0000_0000_0000, "tm=8.0");
    assert_eq!(fpr(&mut env, 8), 0x402e_0000_0000_0000, "ta=15.0");
    // fmpyadd,d も独立 2 演算: 積と和が別々に丸められる。
    // ta は直前の fmpysub で 15.0d に更新済みで、ra=20.0d を
    // 足して 35.0d。
    set_fpr(&mut env, 9, 0x4034_0000_0000_0000); // ra=20.0d
    step(&mut env, enc(Insn::FmpyaddD, &[5, 6, 8, 9, 7]));
    assert_eq!(fpr(&mut env, 7), 0x4020_0000_0000_0000);
    assert_eq!(fpr(&mut env, 8), 0x4041_8000_0000_0000, "ta=35.0");
    // fmpyfadd,f: 全オペランド 6 ビット半レジスタ指定。
    // r64 の 0-31 が各レジスタの左半分、32-63 が右半分。
    // rm1=4(fr4L=2.0f)*rm2=36(fr4R=3.0f)+ra3=10(fr10L=4.0f)
    // → t=12(fr12L) = 10.0f。
    set_fpr(&mut env, 4, 0x4000_0000_4040_0000);
    set_fpr(&mut env, 10, 0x4080_0000_0000_0000);
    set_fpr(&mut env, 12, 0);
    step(&mut env, enc(Insn::FmpyfaddF, &[4, 36, 10, 0, 12]));
    assert_eq!(fpr(&mut env, 12) >> 32, 0x4120_0000);
    // fmpyfadd,d は融合: 中間積は無限精度。
    // (2^53+1)*1.0 - 2^53 は、積を先に丸めると 0 だが融合では
    // 正確に 1.0。Ref: SPEC-PARISC-20 §9-16。
    set_fpr(&mut env, 5, 0x4330_0000_0000_0001); // 2^53+1
    set_fpr(&mut env, 6, 0x3ff0_0000_0000_0000); // 1.0
    set_fpr(&mut env, 7, 0xc330_0000_0000_0000); // -2^53
    step(&mut env, enc(Insn::FmpyfaddD, &[5, 6, 7, 0, 8]));
    assert_eq!(fpr(&mut env, 8), 0x3ff0_0000_0000_0000, "1.0");
    assert_eq!(fpsr_flags(&mut env), 0);
    // fmpynfadd,d（neg=1）は積の符号を反転:
    // -(4.0*0.5)+1.0 = -1.0。
    set_fpr(&mut env, 5, 0x4010_0000_0000_0000); // 4.0
    set_fpr(&mut env, 6, 0x3fe0_0000_0000_0000); // 0.5
    set_fpr(&mut env, 7, 0x3ff0_0000_0000_0000); // 1.0
    step(&mut env, enc(Insn::FmpyfaddD, &[5, 6, 7, 1, 8]));
    assert_eq!(fpr(&mut env, 8), 0xbff0_0000_0000_0000, "-1.0");
    // invalid 列挙: 0×∞ → 既定 NaN + V（フラグ経路の近似）。
    set_fpr(&mut env, 5, 0x0000_0000_0000_0000); // +0.0
    set_fpr(&mut env, 6, 0x7ff0_0000_0000_0000); // +inf
    set_fpr(&mut env, 7, 0x3ff0_0000_0000_0000);
    step(&mut env, enc(Insn::FmpyfaddD, &[5, 6, 7, 0, 8]));
    assert_eq!(fpr(&mut env, 8), 0x7ff4_0000_0000_0000);
    assert_eq!(fpsr_flags(&mut env), 0x10);
}

// XMPYU: 半レジスタの 32 ビットを符号なし乗算し全レジスタへ。
#[test]
fn exec_xmpyu() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    // fr4L=0xffff_ffff, fr5L=0xffff_ffff → 0xffff_fffe_0000_0001。
    set_fpr(&mut env, 4, 0xffff_ffff_1111_1111);
    set_fpr(&mut env, 5, 0xffff_ffff_2222_2222);
    step(&mut env, enc(Insn::Xmpyu, &[4, 5, 6]));
    assert_eq!(fpr(&mut env, 6), 0xffff_fffe_0000_0001);
    // 右半分も選べる: r64=36+... fr4R（r64=36）=0x1111_1111。
    step(&mut env, enc(Insn::Xmpyu, &[36, 5, 7]));
    assert_eq!(fpr(&mut env, 7), 0x1111_1110_eeee_eeef);
    // 例外フラグは立たない（固定小数点）。
    assert_eq!(fpsr_flags(&mut env), 0);
}

// ---- MAX-1/MAX-2 半語並列演算・再配置（段階17・PR9c）----
// 半語レーンは左（最上位）から 0..3。期待値は
// SPEC-PARISC-20 §6-5 Table 6-3/6-4（飽和規則）、§7-58..§7-64
// （hadd/havg/hsub/hshladd/hshradd/hshl/hshr）、§7-94/§7-95
// （mixh/mixw）、付録C Figure C-9/Table C-12（permh のエンコード
// と c0..c3）から出している。FRRR 系の ops は [r2,r1,t] で、
// spec 構文の第 1 オペランド r1 が fb 桁（= ops[1]）側。

// hadd/hsub の剰余演算とオペランド順（hsub は r1-r2）。
#[test]
fn exec_hadd_hsub_modular() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    // r1 側は GR2（fb 桁）、r2 側は GR1（fa 桁）。
    set_gpr(&mut env, 2, 0x0005_0006_0007_0008);
    set_gpr(&mut env, 1, 0x0001_0002_0003_0004);
    // hadd → (5+1)|(6+2)|(7+3)|(8+4)。
    step(&mut env, enc(Insn::Hadd, &[1, 2, 3]));
    assert_eq!(gpr(&mut env, 3), 0x0006_0008_000a_000c);
    // hsub → (5-1)|(6-2)|(7-3)|(8-4)。逆順なら負になるので
    // 被演算子順の検査になる。
    step(&mut env, enc(Insn::Hsub, &[1, 2, 3]));
    assert_eq!(gpr(&mut env, 3), 0x0004_0004_0004_0004);
    // 剰余演算はレーン内で回り込むだけで隣レーンを侵さない:
    // (ffff+1→0000)|(ffff+ffff→fffe)|(8000+8000→0000)|(0+ffff)。
    set_gpr(&mut env, 2, 0xffff_ffff_8000_0000);
    set_gpr(&mut env, 1, 0x0001_ffff_8000_ffff);
    step(&mut env, enc(Insn::Hadd, &[1, 2, 3]));
    assert_eq!(gpr(&mut env, 3), 0x0000_fffe_0000_ffff);
}

// ,ss 飽和（両オペランド符号あり、Table 6-3）。
#[test]
fn exec_hadd_hsub_signed_saturation() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    // hadd,ss → sat(7fff+1)|sat(7fff-1)|sat(-8000-1)|(0+0)
    //        = 7fff|7ffe|8000|0000。
    set_gpr(&mut env, 2, 0x7fff_7fff_8000_0000);
    set_gpr(&mut env, 1, 0x0001_ffff_ffff_0000);
    step(&mut env, enc(Insn::HaddSs, &[1, 2, 3]));
    assert_eq!(gpr(&mut env, 3), 0x7fff_7ffe_8000_0000);
    // hsub,ss → sat(-8000-1)|sat(7fff+1)|sat(0+8000)|sat(1-2)
    //        = 8000|7fff|7fff|ffff。
    set_gpr(&mut env, 2, 0x8000_7fff_0000_0001);
    set_gpr(&mut env, 1, 0x0001_ffff_8000_0002);
    step(&mut env, enc(Insn::HsubSs, &[1, 2, 3]));
    assert_eq!(gpr(&mut env, 3), 0x8000_7fff_7fff_ffff);
}

// ,us 飽和（r1 側は符号なし・r2 側は符号あり、結果は符号なし。
// Table 6-4）。
#[test]
fn exec_hadd_hsub_unsigned_saturation() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    // hadd,us → usat(ffff+1)|(1-1)|(0+1)|usat(5-16)
    //        = ffff|0000|0001|0000。
    set_gpr(&mut env, 2, 0xffff_0001_0000_0005);
    set_gpr(&mut env, 1, 0x0001_ffff_0001_fff0);
    step(&mut env, enc(Insn::HaddUs, &[1, 2, 3]));
    assert_eq!(gpr(&mut env, 3), 0xffff_0000_0001_0000);
    // hsub,us → usat(0-1)|usat(ffff+1)|(5-5)|(8000-(-7fff))
    //        = 0000|ffff|0000|ffff。
    set_gpr(&mut env, 2, 0x0000_ffff_0005_8000);
    set_gpr(&mut env, 1, 0x0001_ffff_0005_8001);
    step(&mut env, enc(Insn::HsubUs, &[1, 2, 3]));
    assert_eq!(gpr(&mut env, 3), 0x0000_ffff_0000_ffff);
}

// havg の桁上がり回し込みと非バイアス丸め。
#[test]
fn exec_havg_carry_and_rounding() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    // §7-59 Operation: sum の桁上がりを結果最上位へ回し、
    // new_lsb = sum{14}|sum{15} で奇数側へ寄せる。
    // (1+0→1)|(ffff+ffff=1fffe→ffff)|(ffff+1=10000→8000)|
    // (0+3=3→1)。
    set_gpr(&mut env, 2, 0x0001_ffff_ffff_0000);
    set_gpr(&mut env, 1, 0x0000_ffff_0001_0003);
    step(&mut env, enc(Insn::Havg, &[1, 2, 3]));
    assert_eq!(gpr(&mut env, 3), 0x0001_ffff_8000_0001);
    // 和がちょうど偶数なら丸めは効かない: (4+6)/2=5。
    set_gpr(&mut env, 2, 0x0004_0000_0000_0002);
    set_gpr(&mut env, 1, 0x0006_0000_0000_0002);
    step(&mut env, enc(Insn::Havg, &[1, 2, 3]));
    assert_eq!(gpr(&mut env, 3), 0x0005_0000_0000_0002);
}

// hshladd/hshradd のシフト＋符号飽和加算（FRRSH 形。
// ops は [r2,r1,sa,t]）。
#[test]
fn exec_hshladd_shift_and_add_saturation() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    // sa=1: 0x4000<<1 は 16 ビットに収まらず正側飽和、
    // 0x8000(-2^15)<<1 は負側飽和、収まるときは加算で判定。
    // → 7fff|(4000+1)|8000|sat(2+7fff)=7fff。
    set_gpr(&mut env, 2, 0x4000_2000_8000_0001);
    set_gpr(&mut env, 1, 0x0001_0001_0001_7fff);
    step(&mut env, enc(Insn::Hshladd, &[1, 2, 1, 3]));
    assert_eq!(gpr(&mut env, 3), 0x7fff_4001_8000_7fff);
    // sa=3: 0x1000<<3=0x8000 → 正側飽和。0xe000(-2^13)<<3
    // は負側飽和。7<<3+1=0x39、-1<<3+0=-8。
    set_gpr(&mut env, 2, 0x1000_e000_0007_ffff);
    set_gpr(&mut env, 1, 0x0000_0000_0001_0000);
    step(&mut env, enc(Insn::Hshladd, &[1, 2, 3, 3]));
    assert_eq!(gpr(&mut env, 3), 0x7fff_8000_0039_fff8);
}

#[test]
fn exec_hshradd_arith_shift_and_add() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    // sa=2: (-8000)>>2=-2000(-8192)、0x4001>>2=0x1000、
    // -8>>2=-2、0x7fff>>2=0x1fff。各 +1。
    // → e001|1001|ffff|2000。
    set_gpr(&mut env, 2, 0x8000_4001_fff8_7fff);
    set_gpr(&mut env, 1, 0x0001_0001_0001_0001);
    step(&mut env, enc(Insn::Hshradd, &[1, 2, 2, 3]));
    assert_eq!(gpr(&mut env, 3), 0xe001_1001_ffff_2000);
    // sa=1: 加算側の飽和 sat(3fff+7fff)=7fff、ちょうど
    // -2^15 に収まる (-4000)+(-4000)=-8000→8000、
    // (1>>1)+(-8000)=-8000→8000、2000+4000=6000。
    set_gpr(&mut env, 2, 0x7fff_8000_0001_4000);
    set_gpr(&mut env, 1, 0x7fff_c000_8000_4000);
    step(&mut env, enc(Insn::Hshradd, &[1, 2, 1, 3]));
    assert_eq!(gpr(&mut env, 3), 0x7fff_8000_8000_6000);
}

// hshl/hshr は MAX-2 の sa=0..15 シフト（hshl の r は fb 桁、
// hshr の r は fa 桁と違う）。
#[test]
fn exec_hshl_hshr_lane_shifts() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    set_gpr(&mut env, 1, 0x0001_8001_ffff_4000);
    // hshl sa=4 → 0010|0010|fff0|0000（境界越えのビットは捨てる）。
    step(&mut env, enc(Insn::Hshl, &[1, 4, 2]));
    assert_eq!(gpr(&mut env, 2), 0x0010_0010_fff0_0000);
    // sa=0 は恒等、sa=15 は最下位ビットだけが最上位へ残る。
    step(&mut env, enc(Insn::Hshl, &[1, 0, 2]));
    assert_eq!(gpr(&mut env, 2), 0x0001_8001_ffff_4000);
    step(&mut env, enc(Insn::Hshl, &[1, 15, 2]));
    assert_eq!(gpr(&mut env, 2), 0x8000_8000_8000_0000);
    // hshr,u は論理シフト、hshr,s は半語符号で拡張。
    step(&mut env, enc(Insn::HshrU, &[1, 4, 2]));
    assert_eq!(gpr(&mut env, 2), 0x0000_0800_0fff_0400);
    step(&mut env, enc(Insn::HshrS, &[1, 4, 2]));
    assert_eq!(gpr(&mut env, 2), 0x0000_f800_ffff_0400);
    step(&mut env, enc(Insn::HshrS, &[1, 15, 2]));
    assert_eq!(gpr(&mut env, 2), 0x0000_ffff_ffff_0000);
}

// mixh/mixw の左右選択（ops は [r2,r1,t]）。
#[test]
fn exec_mixh_mixw_lane_selection() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    // r1=GR2=aaaa|bbbb|cccc|dddd、r2=GR1=1111|2222|3333|4444。
    set_gpr(&mut env, 2, 0xaaaa_bbbb_cccc_dddd);
    set_gpr(&mut env, 1, 0x1111_2222_3333_4444);
    // mixh,l: r1{0..15}|r2{0..15}|r1{32..47}|r2{32..47}
    //      = aaaa|1111|cccc|3333。
    step(&mut env, enc(Insn::MixhL, &[1, 2, 3]));
    assert_eq!(gpr(&mut env, 3), 0xaaaa_1111_cccc_3333);
    // mixh,r: r1{16..31}|r2{16..31}|r1{48..63}|r2{48..63}
    //      = bbbb|2222|dddd|4444。
    step(&mut env, enc(Insn::MixhR, &[1, 2, 3]));
    assert_eq!(gpr(&mut env, 3), 0xbbbb_2222_dddd_4444);
    // mixw,l: r1{0..31}|r2{0..31} = aaaabbbb|11112222。
    step(&mut env, enc(Insn::MixwL, &[1, 2, 3]));
    assert_eq!(gpr(&mut env, 3), 0xaaaa_bbbb_1111_2222);
    // mixw,r: r1{32..63}|r2{32..63} = ccccdddd|33334444。
    step(&mut env, enc(Insn::MixwR, &[1, 2, 3]));
    assert_eq!(gpr(&mut env, 3), 0xcccc_dddd_3333_4444);
}

// permh の任意レーン置換（ops は [r1,r2,c0,c1,c2,c3,t]。
// spec では fa/fb 両桁に同じ r が入る）。
#[test]
fn exec_permh_lane_permutation() {
    let mut env = env();
    set_q(&mut env, 0x1000);
    // GR4 = aaaa|bbbb|cccc|dddd（半語番号 0|1|2|3）。
    set_gpr(&mut env, 4, 0xaaaa_bbbb_cccc_dddd);
    // c=3210 は逆順（§7-109 のプログラミングノートの図）。
    step(&mut env, enc(Insn::Permh, &[4, 4, 3, 2, 1, 0, 5]));
    assert_eq!(gpr(&mut env, 5), 0xdddd_cccc_bbbb_aaaa);
    // c=0123 は恒等、c=0000 は最上位半語の全レーン複製。
    step(&mut env, enc(Insn::Permh, &[4, 4, 0, 1, 2, 3, 5]));
    assert_eq!(gpr(&mut env, 5), 0xaaaa_bbbb_cccc_dddd);
    step(&mut env, enc(Insn::Permh, &[4, 4, 0, 0, 0, 0, 5]));
    assert_eq!(gpr(&mut env, 5), 0xaaaa_aaaa_aaaa_aaaa);
    // 任意順 c=1,3,0,2 → bbbb|dddd|aaaa|cccc。
    step(&mut env, enc(Insn::Permh, &[4, 4, 1, 3, 0, 2, 5]));
    assert_eq!(gpr(&mut env, 5), 0xbbbb_dddd_aaaa_cccc);
}
