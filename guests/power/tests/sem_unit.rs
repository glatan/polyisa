use polyisa_engine::bare::BareEnv;
use polyisa_guest_power::sem::{self, Gpr};
use polyisa_mem::{Perms, VirtAddr};
use polyisa_sem::Backend;

#[test]
fn std_ld_roundtrip_be() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    env.backend
        .mem
        .map(VirtAddr(0x10171000), 1, Perms::RW)
        .unwrap();
    env.backend.set(Gpr(2).state(), 0x10177f00u64);
    env.backend.set(Gpr(5).state(), 0x7fffffeefe90u64);
    // addi 9,2,-26168 → r9 = r2 - 26168 = 0x101718c8
    // std r5, 0(9): op62 xo0, rt=5 ra=9 ds=0 → word = 62<<26|5<<21|9<<16|0
    let addi = 14u32 << 26 | 9 << 21 | 2 << 16 | (-26168i32 as u16 as u32);
    env.step(|b| sem::addi(b, addi, 0x100, false)).unwrap();
    let r9: u64 = env.backend.get(Gpr(9).state());
    assert_eq!(r9, 0x101718c8);
    let stdw = 62u32 << 26 | 5 << 21 | 9 << 16;
    env.step(|b| sem::x62(b, stdw, 0x104, false)).unwrap();
    // ld r7, 0(9): op58 rt=7
    let ldw = 58u32 << 26 | 7 << 21 | 9 << 16;
    env.step(|b| sem::x58(b, ldw, 0x108, false)).unwrap();
    let r7: u64 = env.backend.get(Gpr(7).state());
    assert_eq!(r7, 0x7fffffeefe90);
}

#[test]
fn fcmpu_writes_cr0() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    // f1 = 1.0, f2 = 2.0（VSR の上位 64 ビットが FPR）。
    env.backend.set(
        polyisa_guest_power::sem::Vsr(1).state(),
        0x3ff0_0000_0000_0000u128 << 64,
    );
    env.backend.set(
        polyisa_guest_power::sem::Vsr(2).state(),
        0x4000_0000_0000_0000u128 << 64,
    );
    // fcmpu cr0, f1, f2: op63 xo10=0, bf=0(bits25:23), a=1, b=2
    let word = 63u32 << 26 | 1 << 16 | 2 << 11;
    env.step(|b| sem::x63(b, word, 0x100, false)).unwrap();
    let cr: u64 = env.backend.get(sem::cr_ref());
    assert_eq!((cr >> 28) & 0xf, 0x8, "CR0 should be LT(0x8): cr={cr:#x}");
}

#[test]
fn mfocrf_copies_selected_field() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    // 全フィールドが異なる既知値。フィールド i は cr>>(28-4i)。
    env.backend.set(sem::cr_ref(), 0x1234_5678u64);
    // mfocrf 9, 1: FXM=1（下位ビット）はフィールド7を選ぶ。
    // word = 31<<26 | 9<<21 | 1<<20 | 1<<12 | 19<<1 = 0x7d301026。
    env.step(|b| sem::x31(b, 0x7d30_1026, 0x100, false))
        .unwrap();
    let r9: u64 = env.backend.get(Gpr(9).state());
    // フィールド7 = 0x8 が下位ニブルへ。残りビットは 0。
    assert_eq!(r9, 0x8, "mfocrf 9,1: r9={r9:#x}");
}

#[test]
fn mfocrf_field1_goes_to_field1_position() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    env.backend.set(sem::cr_ref(), 0x1234_5678u64);
    // mfocrf 9, 0x40: FXM=0x40 はフィールド1を選ぶ → r9[4*1+32:4*1+35]（下位24 ビルトシフト位置）。
    let word = 31u32 << 26 | 9 << 21 | 1 << 20 | 0x40 << 12 | 19 << 1;
    env.step(|b| sem::x31(b, word, 0x100, false)).unwrap();
    let r9: u64 = env.backend.get(Gpr(9).state());
    // フィールド1 = 0x2 → r9 = 0x2 << 24。
    assert_eq!(r9, 0x0200_0000, "mfocrf 9,0x40: r9={r9:#x}");
}

#[test]
fn mfcr_copies_whole_cr() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    env.backend.set(sem::cr_ref(), 0x1234_5678u64);
    // mfcr 9: bit20=0 → CR 全体をコピー。
    let word = 31u32 << 26 | 9 << 21 | 19 << 1;
    env.step(|b| sem::x31(b, word, 0x100, false)).unwrap();
    let r9: u64 = env.backend.get(Gpr(9).state());
    assert_eq!(r9, 0x1234_5678, "mfcr 9: r9={r9:#x}");
}

#[test]
fn cmpwi_then_bt() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    env.backend.set(Gpr(9).state(), 0u64);
    // cmpwi cr0, r9, 0: op11, bf=0,L=0, ra=9, imm=0
    let word = 11u32 << 26 | 9 << 16;
    env.step(|b| sem::cmpwi(b, word, 0x100, false)).unwrap();
    let cr: u64 = env.backend.get(sem::cr_ref());
    assert_eq!((cr >> 28) & 0xf, 0x2, "CR0 should be EQ(0x2): cr={cr:#x}");
}

#[test]
fn subf_does_not_touch_ca() {
    // subf（XO 40）は CA を更新しない。subfc（XO 8）だけが書く。
    // 実害: `subfic`（CA=0）→ `subf` → `addze` の並びで、subf が CA を
    // 壊すと addze の結果が 1 ずれて printf のパディングが崩れる。
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    env.backend.set(Gpr(5).state(), 0x100u64);
    env.backend.set(Gpr(18).state(), 0x50u64);
    env.backend.set(Gpr(30).state(), 0x7u64);
    // subfic r8, 24, 0 → CA=0（42 > 0 なので借りる）。
    env.backend.set(Gpr(24).state(), 42u64);
    env.step(|b| sem::subfic(b, 8 << 21 | 24 << 16, 0x100, false))
        .unwrap();
    let xer: u64 = env.backend.get(sem::xer_ref());
    assert_eq!(xer & (1 << 29), 0, "subfic should clear CA: xer={xer:#x}");
    // subf r30, 18, 5 → r30 = r5 - r18 = 0xb0（キャリーは出るが CA は不変のはず）。
    let word = 31u32 << 26 | 30 << 21 | 18 << 16 | 5 << 11 | 40 << 1;
    env.step(|b| sem::x31(b, word, 0x100, false)).unwrap();
    let r30: u64 = env.backend.get(Gpr(30).state());
    assert_eq!(r30, 0xb0, "subf: r30={r30:#x}");
    let xer: u64 = env.backend.get(sem::xer_ref());
    assert_eq!(xer & (1 << 29), 0, "subf must not modify CA: xer={xer:#x}");
    // addze r10, 30 → r10 = r30 + CA = 0xb0 + 0。
    let word = 31u32 << 26 | 10 << 21 | 30 << 16 | 202 << 1;
    env.step(|b| sem::x31(b, word, 0x100, false)).unwrap();
    let r10: u64 = env.backend.get(Gpr(10).state());
    assert_eq!(r10, 0xb0, "addze: r10={r10:#x}");
}

#[test]
fn subfc_and_addc_set_ca() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    env.backend.set(Gpr(5).state(), 0x100u64);
    env.backend.set(Gpr(18).state(), 0x50u64);
    // subfc r30, 18, 5 → r30 = 0xb0、無 borrow なので CA=1。
    let word = 31u32 << 26 | 30 << 21 | 18 << 16 | 5 << 11 | 8 << 1;
    env.step(|b| sem::x31(b, word, 0x100, false)).unwrap();
    let xer: u64 = env.backend.get(sem::xer_ref());
    assert_ne!(xer & (1 << 29), 0, "subfc should set CA: xer={xer:#x}");
    // add r9, 5, 18 → r9 = 0x150、CA は変わらない。
    env.backend.set(Gpr(18).state(), 0u64);
    let word = 31u32 << 26 | 9 << 21 | 5 << 16 | 18 << 11 | 266 << 1;
    env.step(|b| sem::x31(b, word, 0x100, false)).unwrap();
    let r9: u64 = env.backend.get(Gpr(9).state());
    assert_eq!(r9, 0x100, "add: r9={r9:#x}");
    let xer: u64 = env.backend.get(sem::xer_ref());
    assert_ne!(xer & (1 << 29), 0, "add must not modify CA: xer={xer:#x}");
}

// ---- bcdadd./bcdsub.（十進整数）----
// FPR（= VSR 上位 64 ビット）は下位ニブルが符号、上位 15 ニブルが BCD 桁。
// PS=0 の優先符号は +0xC/-0xD、PS=1 は +0xF/-0xB。

/// n の BCD 桁に符号 s を付けた FPR 値を作る（n は十進文字列表記→BCD）。
fn bcd(n: u64, sign: u64) -> u128 {
    let mut v = 0u64;
    let mut m = n;
    let mut pos = 0;
    while m > 0 {
        v |= (m % 10) << (4 + 4 * pos);
        m /= 10;
        pos += 1;
    }
    (v | sign) as u128
}

fn set_fpr(env: &mut BareEnv, i: u8, fpr: u128) {
    env.backend.set(sem::Vsr(i).state(), fpr << 64);
}

fn fpr_of(env: &mut BareEnv, i: u8) -> u64 {
    let v: u128 = env.backend.get(sem::Vsr(i).state());
    (v >> 64) as u64
}

fn bcdword(t: u8, a: u8, b: u8, ps: u8, sub: u8) -> u32 {
    // 4<<26 | T<<21 | A<<16 | B<<11 | 512<<1 | ps<<9 | sub<<6 | 1
    4u32 << 26
        | (t as u32) << 21
        | (a as u32) << 16
        | (b as u32) << 11
        | 512 << 1
        | (ps as u32) << 9
        | (sub as u32) << 6
        | 1
}

#[test]
fn bcdadd_basic_and_cr() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    // +123 + +456 = +579 → 0x579C、CR0=GT。
    set_fpr(&mut env, 2, bcd(123, 0xc));
    set_fpr(&mut env, 3, bcd(456, 0xc));
    env.step(|b| sem::x4(b, bcdword(1, 2, 3, 0, 0), 0x100, false))
        .unwrap();
    assert_eq!(fpr_of(&mut env, 1), 0x579c, "bcdadd 123+456");
    let cr: u64 = env.backend.get(sem::cr_ref());
    assert_eq!((cr >> 28) & 0xf, 0x4, "CR0 should be GT: cr={cr:#x}");
}

#[test]
fn bcdadd_mixed_signs() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    // +500 + (-200) = +300。
    set_fpr(&mut env, 2, bcd(500, 0xc));
    set_fpr(&mut env, 3, bcd(200, 0xd));
    env.step(|b| sem::x4(b, bcdword(1, 2, 3, 0, 0), 0x100, false))
        .unwrap();
    assert_eq!(fpr_of(&mut env, 1), 0x300c);
    let cr: u64 = env.backend.get(sem::cr_ref());
    assert_eq!((cr >> 28) & 0xf, 0x4);
}

#[test]
fn bcdsub_negative_result() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    // -300 - +100 = -400 → 0x400D、CR0=LT。
    set_fpr(&mut env, 2, bcd(300, 0xd));
    set_fpr(&mut env, 3, bcd(100, 0xc));
    env.step(|b| sem::x4(b, bcdword(1, 2, 3, 0, 1), 0x100, false))
        .unwrap();
    assert_eq!(fpr_of(&mut env, 1), 0x400d);
    let cr: u64 = env.backend.get(sem::cr_ref());
    assert_eq!((cr >> 28) & 0xf, 0x8, "CR0 should be LT: cr={cr:#x}");
}

#[test]
fn bcdadd_zero_result() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    // +100 + (-100) = +0 → 0x000C、CR0=EQ。
    set_fpr(&mut env, 2, bcd(100, 0xc));
    set_fpr(&mut env, 3, bcd(100, 0xd));
    env.step(|b| sem::x4(b, bcdword(1, 2, 3, 0, 0), 0x100, false))
        .unwrap();
    assert_eq!(fpr_of(&mut env, 1), 0x000c);
    let cr: u64 = env.backend.get(sem::cr_ref());
    assert_eq!((cr >> 28) & 0xf, 0x2, "CR0 should be EQ: cr={cr:#x}");
}

#[test]
fn bcdadd_ps1_uses_f_sign() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    // PS=1 → 正の結果符号は 0xF、負は 0xB。
    set_fpr(&mut env, 2, bcd(7, 0xf));
    set_fpr(&mut env, 3, bcd(8, 0xf));
    env.step(|b| sem::x4(b, bcdword(1, 2, 3, 1, 0), 0x100, false))
        .unwrap();
    assert_eq!(fpr_of(&mut env, 1), 0x15f);
    set_fpr(&mut env, 2, bcd(8, 0xd));
    set_fpr(&mut env, 3, bcd(5, 0xc));
    env.step(|b| sem::x4(b, bcdword(1, 2, 3, 1, 0), 0x100, false))
        .unwrap();
    assert_eq!(fpr_of(&mut env, 1), 0x3b);
}

#[test]
fn bcdadd_invalid_operand_sets_so() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    // 0xA の数字ニブルは無効 → CR0=SO。
    set_fpr(&mut env, 2, 0xa1c); // 桁が 0xA
    set_fpr(&mut env, 3, bcd(1, 0xc));
    env.step(|b| sem::x4(b, bcdword(1, 2, 3, 0, 0), 0x100, false))
        .unwrap();
    let cr: u64 = env.backend.get(sem::cr_ref());
    assert_eq!((cr >> 28) & 0xf, 0x1, "CR0 should be SO: cr={cr:#x}");
    // 符号ニブルが 0xA 未満も無効。
    set_fpr(&mut env, 2, bcd(1, 0x9));
    env.step(|b| sem::x4(b, bcdword(1, 2, 3, 0, 0), 0x100, false))
        .unwrap();
    let cr: u64 = env.backend.get(sem::cr_ref());
    assert_eq!((cr >> 28) & 0xf, 0x1);
}

#[test]
fn bcdadd_overflow_sets_so() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    // 999999999999999 + 1 → 桁あふれ → CR0 に SO。
    set_fpr(&mut env, 2, bcd(999_999_999_999_999, 0xc));
    set_fpr(&mut env, 3, bcd(1, 0xc));
    env.step(|b| sem::x4(b, bcdword(1, 2, 3, 0, 0), 0x100, false))
        .unwrap();
    let cr: u64 = env.backend.get(sem::cr_ref());
    assert_ne!((cr >> 28) & 0xf & 0x1, 0, "CR0.SO expected: cr={cr:#x}");
    // 結果は 10^15 mod 桁数 → 0x000C（eq も立つ）。
    assert_eq!(fpr_of(&mut env, 1), 0x000c);
}

// ---- DFP64（decimal floating-point、opcode 59）----
// 値の組み立ては polyisa-decimal の DPD エンコーダ（decTest で検証済み）を使う。

use polyisa_decimal::dfp::{FMT_D64, encode};

/// 十進文字列を decimal64 のビット列にする。
fn d64(s: &str) -> u128 {
    let d = polyisa_decimal::dfp::Dec::parse(s).unwrap();
    (encode(FMT_D64, &d) as u64) as u128
}

fn fpscr(env: &mut BareEnv) -> u64 {
    env.backend.get(sem::fpscr_ref())
}

fn cr_hi(env: &mut BareEnv) -> u64 {
    env.backend.get(sem::cr_ref())
}

/// Z22 系: op59 | t<<21 | a<<16 | b<<11 | xo10<<1。
fn dfp3(t: u8, a: u8, b: u8, xo10: u32) -> u32 {
    59u32 << 26 | (t as u32) << 21 | (a as u32) << 16 | (b as u32) << 11 | xo10 << 1
}

/// BF 系: op59 | (bf<<2)<<21 | a<<16 | b<<11 | xo10<<1。
fn dfpbf(bf: u8, a: u8, b: u8, xo10: u32) -> u32 {
    dfp3(bf << 2, a, b, xo10)
}

/// Z23 系: op59 | t<<21 | a<<16 | b<<11 | rmc<<9 | xo8<<1。
fn dfpz23(t: u8, a: u8, b: u8, rmc: u8, xo8: u32) -> u32 {
    59u32 << 26
        | (t as u32) << 21
        | (a as u32) << 16
        | (b as u32) << 11
        | (rmc as u32) << 9
        | xo8 << 1
}

#[test]
fn dadd_basic() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    set_fpr(&mut env, 1, d64("1.5"));
    set_fpr(&mut env, 2, d64("2.25"));
    env.step(|b| sem::x59(b, dfp3(4, 1, 2, 2), 0x100, false))
        .unwrap();
    assert_eq!(fpr_of(&mut env, 4), d64("3.75") as u64, "dadd 1.5+2.25");
}

#[test]
fn dadd_aligns_exponents() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    // 指数差のある加算：1.5E+3 + 7 = 1507。
    set_fpr(&mut env, 1, d64("1.5E+3"));
    set_fpr(&mut env, 2, d64("7"));
    env.step(|b| sem::x59(b, dfp3(4, 1, 2, 2), 0x100, false))
        .unwrap();
    assert_eq!(fpr_of(&mut env, 4), d64("1507") as u64);
}

#[test]
fn dsub_basic() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    set_fpr(&mut env, 1, d64("5.5"));
    set_fpr(&mut env, 2, d64("2.25"));
    env.step(|b| sem::x59(b, dfp3(4, 1, 2, 514), 0x100, false))
        .unwrap();
    assert_eq!(fpr_of(&mut env, 4), d64("3.25") as u64, "dsub 5.5-2.25");
}

#[test]
fn dmul_basic() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    set_fpr(&mut env, 1, d64("1.5"));
    set_fpr(&mut env, 2, d64("4"));
    env.step(|b| sem::x59(b, dfp3(4, 1, 2, 34), 0x100, false))
        .unwrap();
    // ideal exponent = -1 + 0 = -1 → 60E-1 = "6.0"。
    assert_eq!(fpr_of(&mut env, 4), d64("6.0") as u64, "dmul 1.5*4");
}

#[test]
fn ddiv_basic() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    set_fpr(&mut env, 1, d64("7.5"));
    set_fpr(&mut env, 2, d64("2.5"));
    env.step(|b| sem::x59(b, dfp3(4, 1, 2, 546), 0x100, false))
        .unwrap();
    // IEEE の除算は係数を精度までパディングする → 3.000000000000000。
    let want = {
        let (d, _f) = polyisa_decimal::dfp::Dec::parse("7.5").unwrap().div(
            &polyisa_decimal::dfp::Dec::parse("2.5").unwrap(),
            &FMT_D64.ctx(),
        );
        encode(FMT_D64, &d) as u64
    };
    assert_eq!(fpr_of(&mut env, 4), want, "ddiv 7.5/2.5");
}

#[test]
fn ddiv_inexact_rounds_half_even() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    // 1/3 = 0.333… → 16 桁で丸め、XX|FI が立つ。
    set_fpr(&mut env, 1, d64("1"));
    set_fpr(&mut env, 2, d64("3"));
    env.step(|b| sem::x59(b, dfp3(4, 1, 2, 546), 0x100, false))
        .unwrap();
    assert_eq!(
        fpr_of(&mut env, 4),
        d64("0.3333333333333333") as u64,
        "ddiv 1/3"
    );
    assert_ne!(fpscr(&mut env) & (1 << 25), 0, "XX expected");
    assert_ne!(fpscr(&mut env) & (1 << 17), 0, "FI expected");
}

#[test]
fn ddiv_by_zero_sets_zx_and_inf() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    set_fpr(&mut env, 1, d64("1"));
    set_fpr(&mut env, 2, d64("0"));
    env.step(|b| sem::x59(b, dfp3(4, 1, 2, 546), 0x100, false))
        .unwrap();
    assert_eq!(fpr_of(&mut env, 4), 0x7800_0000_0000_0000, "1/0 -> +inf");
    assert_ne!(fpscr(&mut env) & (1 << 26), 0, "ZX expected");
}

#[test]
fn dadd_inf_minus_inf_invalid() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    set_fpr(&mut env, 1, 0x7800_0000_0000_0000u128); // +inf
    set_fpr(&mut env, 2, 0xf800_0000_0000_0000u128); // -inf
    env.step(|b| sem::x59(b, dfp3(4, 1, 2, 2), 0x100, false))
        .unwrap();
    assert_eq!(
        fpr_of(&mut env, 4) >> 58,
        0x1f,
        "inf + -inf -> NaN combination"
    );
    let f = fpscr(&mut env);
    assert_ne!(f & (1 << 29), 0, "VX expected: {f:#x}");
    assert_ne!(f & (1 << 23), 0, "VXISI expected: {f:#x}");
    assert_ne!(f & (1 << 31), 0, "FX expected: {f:#x}");
}

#[test]
fn dmul_inf_times_zero_invalid() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    set_fpr(&mut env, 1, 0x7800_0000_0000_0000u128); // +inf
    set_fpr(&mut env, 2, d64("0"));
    env.step(|b| sem::x59(b, dfp3(4, 1, 2, 34), 0x100, false))
        .unwrap();
    let f = fpscr(&mut env);
    assert_ne!(f & (1 << 20), 0, "VXIMZ expected: {f:#x}");
}

#[test]
fn dadd_snan_raises_vxsnan() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    set_fpr(&mut env, 1, 0x7e00_0000_0000_0000u128); // sNaN
    set_fpr(&mut env, 2, d64("1"));
    env.step(|b| sem::x59(b, dfp3(4, 1, 2, 2), 0x100, false))
        .unwrap();
    let f = fpscr(&mut env);
    assert_ne!(f & (1 << 24), 0, "VXSNAN expected: {f:#x}");
    // sNaN は quiet 化して返る（bit57 → 0）。
    let r = fpr_of(&mut env, 4);
    assert_eq!(r >> 58, 0x1f, "nan combination: {r:#x}");
    assert_eq!(r & (1 << 57), 0, "snan bit cleared: {r:#x}");
}

#[test]
fn dcmpu_lt_gt_eq() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    // dcmpu BF,FRA,FRB → XO10=642。
    set_fpr(&mut env, 1, d64("1.5"));
    set_fpr(&mut env, 2, d64("2.5"));
    env.step(|b| sem::x59(b, dfpbf(0, 1, 2, 642), 0x100, false))
        .unwrap();
    assert_eq!(cr_hi(&mut env) >> 28 & 0xf, 0x8, "dcmpu 1.5<2.5 -> LT");
    env.step(|b| sem::x59(b, dfpbf(0, 2, 1, 642), 0x100, false))
        .unwrap();
    assert_eq!(cr_hi(&mut env) >> 28 & 0xf, 0x4, "dcmpu 2.5>1.5 -> GT");
    env.step(|b| sem::x59(b, dfpbf(0, 1, 1, 642), 0x100, false))
        .unwrap();
    assert_eq!(cr_hi(&mut env) >> 28 & 0xf, 0x2, "dcmpu equal -> EQ");
    // FPCC（FPSCR bits12-15）にも反映。
    assert_eq!((fpscr(&mut env) >> 12) & 0xf, 0x2, "FPCC EQ");
}

#[test]
fn dcmpu_nan_gives_so_no_flag() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    set_fpr(&mut env, 1, 0x7c00_0000_0000_0000u128); // qNaN
    set_fpr(&mut env, 2, d64("1"));
    env.step(|b| sem::x59(b, dfpbf(0, 1, 2, 642), 0x100, false))
        .unwrap();
    assert_eq!(cr_hi(&mut env) >> 28 & 0xf, 0x1, "dcmpu NaN -> SO");
    // dcmpu は順序なし：qNaN ではフラグを立てない。
    assert_eq!(fpscr(&mut env) & (1 << 19), 0, "no VXVC for dcmpu");
}

#[test]
fn dcmpo_nan_sets_vxvc() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    set_fpr(&mut env, 1, 0x7c00_0000_0000_0000u128); // qNaN
    set_fpr(&mut env, 2, d64("1"));
    env.step(|b| sem::x59(b, dfpbf(0, 1, 2, 130), 0x100, false))
        .unwrap();
    assert_eq!(cr_hi(&mut env) >> 28 & 0xf, 0x1, "dcmpo NaN -> SO");
    assert_ne!(fpscr(&mut env) & (1 << 19), 0, "VXVC for dcmpo");
}

#[test]
fn dcmpu_signed_zero_is_eq() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    set_fpr(&mut env, 1, d64("0"));
    set_fpr(&mut env, 2, d64("-0"));
    env.step(|b| sem::x59(b, dfpbf(0, 1, 2, 642), 0x100, false))
        .unwrap();
    assert_eq!(cr_hi(&mut env) >> 28 & 0xf, 0x2, "+0 == -0");
}

#[test]
fn dtstdc_class_match() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    set_fpr(&mut env, 2, d64("1.5")); // normal 正値
    // DCM=0x08（normal）→ 一致 → crbf=0x2。
    let word = 59u32 << 26 | 2 << 16 | 0x08u32 << 10 | 194 << 1;
    env.step(|b| sem::x59(b, word, 0x100, false)).unwrap();
    assert_eq!(cr_hi(&mut env) >> 28 & 0xf, 0x2, "dtstdc normal match");
    // DCM=0x10（subnormal）→ 不一致 → 0x0。
    let word = 59u32 << 26 | 2 << 16 | 0x10u32 << 10 | 194 << 1;
    env.step(|b| sem::x59(b, word, 0x100, false)).unwrap();
    assert_eq!(
        cr_hi(&mut env) >> 28 & 0xf,
        0x0,
        "dtstdc subnormal no match"
    );
    // 負の normal → match 時は 0xA。
    set_fpr(&mut env, 2, d64("-3"));
    let word = 59u32 << 26 | 2 << 16 | 0x08u32 << 10 | 194 << 1;
    env.step(|b| sem::x59(b, word, 0x100, false)).unwrap();
    assert_eq!(cr_hi(&mut env) >> 28 & 0xf, 0xa, "dtstdc neg normal");
}

#[test]
fn dtstdc_nan_class() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    set_fpr(&mut env, 2, 0x7c00_0000_0000_0000u128); // qNaN
    let word = 59u32 << 26 | 2 << 16 | 0x02u32 << 10 | 194 << 1;
    env.step(|b| sem::x59(b, word, 0x100, false)).unwrap();
    assert_eq!(cr_hi(&mut env) >> 28 & 0xf, 0x2, "dtstdc qnan");
    set_fpr(&mut env, 2, 0x7e00_0000_0000_0000u128); // sNaN
    let word = 59u32 << 26 | 2 << 16 | 0x01u32 << 10 | 194 << 1;
    env.step(|b| sem::x59(b, word, 0x100, false)).unwrap();
    assert_eq!(cr_hi(&mut env) >> 28 & 0xf, 0x2, "dtstdc snan");
}

#[test]
fn dtstex_same_and_diff() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    set_fpr(&mut env, 1, d64("1.5"));
    set_fpr(&mut env, 2, d64("2.5")); // 指数同じ → EQ
    env.step(|b| sem::x59(b, dfpbf(0, 1, 2, 162), 0x100, false))
        .unwrap();
    assert_eq!(cr_hi(&mut env) >> 28 & 0xf, 0x2, "dtstex same exp");
    set_fpr(&mut env, 2, d64("25")); // 指数 -1 vs 0 → a.be < b.be → LT
    env.step(|b| sem::x59(b, dfpbf(0, 1, 2, 162), 0x100, false))
        .unwrap();
    assert_eq!(cr_hi(&mut env) >> 28 & 0xf, 0x8, "dtstex a.be < b.be");
}

#[test]
fn dtstsfi_sig_digits() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    set_fpr(&mut env, 3, d64("123")); // nsd=3
    // dtstsfi BF,UIM,FRB → UIM=5 > 3 → GT(0x4)。
    let word = 59u32 << 26 | 5u32 << 16 | 3 << 11 | 675 << 1;
    env.step(|b| sem::x59(b, word, 0x100, false)).unwrap();
    assert_eq!(cr_hi(&mut env) >> 28 & 0xf, 0x4, "dtstsfi 5>3");
    let word = 59u32 << 26 | 3u32 << 16 | 3 << 11 | 675 << 1;
    env.step(|b| sem::x59(b, word, 0x100, false)).unwrap();
    assert_eq!(cr_hi(&mut env) >> 28 & 0xf, 0x2, "dtstsfi 3==3");
}

#[test]
fn dxex_extracts_exponent() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    // 1.5 = 15E-1 → バイアス指数 397。
    set_fpr(&mut env, 2, d64("1.5"));
    env.step(|b| sem::x59(b, dfp3(4, 0, 2, 354), 0x100, false))
        .unwrap();
    assert_eq!(fpr_of(&mut env, 4), 397, "dxex 1.5 -> 397");
    // inf → -1。
    set_fpr(&mut env, 2, 0x7800_0000_0000_0000u128);
    env.step(|b| sem::x59(b, dfp3(4, 0, 2, 354), 0x100, false))
        .unwrap();
    assert_eq!(fpr_of(&mut env, 4), u64::MAX, "dxex inf -> -1");
}

#[test]
fn diex_replaces_exponent() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    // FRA はバイアス付き指数の整数値（398 → 10^0）。f7 の指数を差し替え。
    set_fpr(&mut env, 7, d64("1.5")); // be=397
    set_fpr(&mut env, 9, 398u128); // 新しい be=398
    env.step(|b| sem::x59(b, dfp3(5, 9, 7, 866), 0x100, false))
        .unwrap();
    assert_eq!(fpr_of(&mut env, 5), d64("15") as u64, "diex 1.5@e0 -> 15");
}

#[test]
fn diex_special_codes() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    set_fpr(&mut env, 9, (u64::MAX) as u128); // -1 → inf
    set_fpr(&mut env, 7, d64("1.5"));
    env.step(|b| sem::x59(b, dfp3(5, 9, 7, 866), 0x100, false))
        .unwrap();
    let r = fpr_of(&mut env, 5);
    assert_eq!(r >> 58, 0x1e, "diex -1 -> inf combination: {r:#x}");
    set_fpr(&mut env, 9, (u64::MAX - 2) as u128); // -3 → sNaN
    env.step(|b| sem::x59(b, dfp3(5, 9, 7, 866), 0x100, false))
        .unwrap();
    let r = fpr_of(&mut env, 5);
    assert_eq!(r >> 57, 0x3f, "diex -3 -> snan: {r:#x}");
}

#[test]
fn dquai_quantizes_to_te() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    // dquai TE,FRT,FRB,RMC → TE は a フィールド（pos11-15）。
    // 1.55 → TE=-1（×0.1 桁）…ではなく TE は指数指定：0 → 整数化。
    set_fpr(&mut env, 2, d64("1.5"));
    // TE=0, RMC=0(RNE): 1.5 → 2。
    env.step(|b| sem::x59(b, dfpz23(4, 0, 2, 0, 67), 0x100, false))
        .unwrap();
    assert_eq!(fpr_of(&mut env, 4), d64("2") as u64, "dquai 1.5@E0 -> 2");
}

#[test]
fn drintx_half_even() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    // drintx R,FRT,FRB,RMC → R=0(a フィールド), RMC=0 → RNE。
    set_fpr(&mut env, 2, d64("2.5"));
    env.step(|b| sem::x59(b, dfpz23(4, 0, 2, 0, 99), 0x100, false))
        .unwrap();
    assert_eq!(
        fpr_of(&mut env, 4),
        d64("2") as u64,
        "drintx 2.5 -> 2 (even)"
    );
    // inexact → XX|FI。
    assert_ne!(fpscr(&mut env) & (1 << 25), 0, "XX expected");
}

#[test]
fn drintn_no_inexact_flag() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    set_fpr(&mut env, 2, d64("2.5"));
    env.step(|b| sem::x59(b, dfpz23(4, 0, 2, 0, 227), 0x100, false))
        .unwrap();
    assert_eq!(fpr_of(&mut env, 4), d64("2") as u64, "drintn 2.5 -> 2");
    // drintn は XX を立てない。
    assert_eq!(fpscr(&mut env) & (1 << 25), 0, "no XX for drintn");
}

#[test]
fn dqua_uses_a_exponent() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    // a の指数に合わせる：a=0.1(be=397) → b=2.55 を 0.1 桁へ → 2.6? RNE: 2.55→2.6? 255→25.5 の最終桁 5 → 偶数側 26 → 2.6。
    set_fpr(&mut env, 7, d64("0.1"));
    set_fpr(&mut env, 9, d64("2.55"));
    env.step(|b| sem::x59(b, dfpz23(5, 7, 9, 0, 3), 0x100, false))
        .unwrap();
    assert_eq!(
        fpr_of(&mut env, 5),
        d64("2.6") as u64,
        "dqua 2.55@0.1 -> 2.6"
    );
}

#[test]
fn dscli_dscri_roundtrip() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    // dscli FRT,FRA,SH → SH は bits10-15。係数を左に 1 桁、指数 -1。
    set_fpr(&mut env, 2, d64("1.5"));
    let word = 59u32 << 26 | 4 << 21 | 2 << 16 | 1u32 << 10 | 578 << 1;
    env.step(|b| sem::x59(b, word, 0x100, false)).unwrap();
    assert_eq!(
        fpr_of(&mut env, 4),
        d64("1.50") as u64,
        "dscli 1.5 -> 15E-2"
    );
    // 戻す：右 1 桁 → 1.5。
    set_fpr(&mut env, 2, d64("1.50"));
    let word = 59u32 << 26 | 4 << 21 | 2 << 16 | 1u32 << 10 | 610 << 1;
    env.step(|b| sem::x59(b, word, 0x100, false)).unwrap();
    assert_eq!(fpr_of(&mut env, 4), d64("1.5") as u64, "dscri -> 1.5");
}

#[test]
fn denbcd_and_ddedpd() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    // denbcd S,FRT,FRB：S=1 で最下位ニブルが符号（0xC=+）。
    set_fpr(&mut env, 5, 0x1234_5678_9012_345cu128);
    env.step(|b| sem::x59(b, dfp3(3, 0, 5, 834) | 1 << 20, 0x100, false))
        .unwrap();
    let expect = d64("123456789012345") as u64;
    assert_eq!(fpr_of(&mut env, 3), expect, "denbcd +BCD");
    // 負符号 0xD。
    set_fpr(&mut env, 5, 0x1234_5678_9012_345du128);
    env.step(|b| sem::x59(b, dfp3(3, 0, 5, 834) | 1 << 20, 0x100, false))
        .unwrap();
    let expect = d64("-123456789012345") as u64;
    assert_eq!(fpr_of(&mut env, 3), expect, "denbcd -BCD");
    // ddedpd SP,FRT,FRA：SP=2 → 符号付き（正→0xC）。FRA は bb フィールド。
    set_fpr(&mut env, 2, d64("1234"));
    let word = 59u32 << 26 | 3 << 21 | 2 << 11 | 2u32 << 19 | 322 << 1;
    env.step(|b| sem::x59(b, word, 0x100, false)).unwrap();
    assert_eq!(
        fpr_of(&mut env, 3),
        0x0000_0000_0001_234c,
        "ddedpd sp=2 positive"
    );
    set_fpr(&mut env, 2, d64("-1234"));
    let word = 59u32 << 26 | 3 << 21 | 2 << 11 | 2u32 << 19 | 322 << 1;
    env.step(|b| sem::x59(b, word, 0x100, false)).unwrap();
    assert_eq!(
        fpr_of(&mut env, 3),
        0x0000_0000_0001_234d,
        "ddedpd sp=2 negative"
    );
}

#[test]
fn denbcd_invalid_sign_sets_vxcvi() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    set_fpr(&mut env, 5, 0x1234_5678_9012_3459u128); // 符号ニブル 0x9 は無効
    env.step(|b| sem::x59(b, dfp3(3, 0, 5, 834) | 1 << 20, 0x100, false))
        .unwrap();
    let f = fpscr(&mut env);
    assert_ne!(f & (1 << 8), 0, "VXCVI expected: {f:#x}");
}

#[test]
fn dctfix_converts_to_int() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    set_fpr(&mut env, 2, d64("42"));
    env.step(|b| sem::x59(b, dfp3(4, 0, 2, 290), 0x100, false))
        .unwrap();
    assert_eq!(fpr_of(&mut env, 4) as i64, 42, "dctfix 42");
    set_fpr(&mut env, 2, d64("-17"));
    env.step(|b| sem::x59(b, dfp3(4, 0, 2, 290), 0x100, false))
        .unwrap();
    assert_eq!(fpr_of(&mut env, 4) as i64, -17, "dctfix -17");
}

#[test]
fn dcffix_converts_int() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    set_fpr(&mut env, 2, 42u128);
    env.step(|b| sem::x59(b, dfp3(4, 0, 2, 802), 0x100, false))
        .unwrap();
    assert_eq!(fpr_of(&mut env, 4), d64("42") as u64, "dcffix 42");
    set_fpr(&mut env, 2, (-17i64) as u64 as u128);
    env.step(|b| sem::x59(b, dfp3(4, 0, 2, 802), 0x100, false))
        .unwrap();
    assert_eq!(fpr_of(&mut env, 4), d64("-17") as u64, "dcffix -17");
}

#[test]
fn dctdp_decodes_d32() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    // decimal32 の 1.5 → decimal64 1.5。
    let d32 = polyisa_decimal::dfp::encode(
        polyisa_decimal::dfp::FMT_D32,
        &polyisa_decimal::dfp::Dec::parse("1.5").unwrap(),
    ) as u32 as u64;
    set_fpr(&mut env, 2, d32 as u128);
    env.step(|b| sem::x59(b, dfp3(4, 0, 2, 258), 0x100, false))
        .unwrap();
    assert_eq!(fpr_of(&mut env, 4), d64("1.5") as u64, "dctdp 1.5");
}

#[test]
fn drsp_roundtrip() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    set_fpr(&mut env, 2, d64("123"));
    env.step(|b| sem::x59(b, dfp3(4, 0, 2, 770), 0x100, false))
        .unwrap();
    let w = fpr_of(&mut env, 4);
    let d32 = polyisa_decimal::dfp::encode(
        polyisa_decimal::dfp::FMT_D32,
        &polyisa_decimal::dfp::Dec::parse("123").unwrap(),
    ) as u32 as u64;
    assert_eq!(w & 0xffff_ffff, d32, "drsp low32 = decimal32 bits");
}

#[test]
fn drrnd_reduces_digits() {
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    // drrnd FRT,FRA,FRB,RMC → FRA の下位 6 ビットが参照桁数。
    set_fpr(&mut env, 7, 2u128); // ref=2 桁
    set_fpr(&mut env, 9, d64("1.55")); // nsd=3 → 2 桁へ
    env.step(|b| sem::x59(b, dfpz23(5, 7, 9, 0, 35), 0x100, false))
        .unwrap();
    // 1.55 → 有効 2 桁 → 1.6（RNE: 155→15.5、5 → 偶数 16）。
    assert_eq!(fpr_of(&mut env, 5), d64("1.6") as u64, "drrnd 1.55 -> 1.6");
}
