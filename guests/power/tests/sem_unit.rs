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
