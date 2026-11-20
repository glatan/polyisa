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
}

// ---- 裸実行検査（段階17・PR4）----
// IAOQ 前後キューと PSW.N/PSW.B を、cli の実行ループと同じ
// 規則でテスト側から遷移させる（SPEC-PARISC-11 §4/§5-4）。
use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::Ctrl;
use polyisa_guest_parisc::sem;
use polyisa_sem::Backend as _;

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
