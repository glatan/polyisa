//! PD13 —— モデル差分マトリクス。同一の語列・同一の初期状態を複数
//! モデルで走らせ、観測可能な結果がモデルによって分かれることを
//! 固定する。各ケースは ARCH83 付録 B の項目番号を背負う。
// Ref: SPEC-PDP11-ARCH83（付録 B）, SPEC-PDP11-J11, SPEC-PDP11-LSI11.

use polyisa_guest_pdp11::*;

use polyisa_engine::bare::BareEnv;
use polyisa_engine::run::{Outcome, TrapHandler, TrapOutcome};
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};
use polyisa_sem::{Backend, StateRef, W16};

struct NoSys;

impl TrapHandler for NoSys {
    fn handle_trap(&mut self, _env: &mut BareEnv, _code: u32) -> TrapOutcome {
        TrapOutcome::Unimplemented
    }
}

const SP0: u16 = 0o41000;

/// ベクタ領域＋語列＋スタックを写像した裸環境。`io` が true なら
/// I/O ページ先頭（0o160000）も写像する（MMIO 領域の読み書きが
/// 素通りするように）。
fn env_at(model: &str, base: u16, words: &[u16]) -> BareEnv {
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    env.backend.mem.map(VirtAddr(0), 1, Perms(0b111)).unwrap();
    env.backend
        .mem
        .map(VirtAddr(0o40000), 1, Perms::RW)
        .unwrap();
    env.backend
        .mem
        .map(VirtAddr(0o160000), 1, Perms::RW)
        .unwrap();
    let mut bytes = Vec::new();
    for w in words {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    env.backend
        .mem
        .write(VirtAddr(u64::from(base)), &bytes)
        .unwrap();
    install_params(&mut env.backend, &model_params(model));
    env.backend.addr_mask = 0xFFFF;
    env.pc = u64::from(base);
    sem::r_set(&mut env.backend, reg::SP as u8, SP0);
    env
}

fn step_m(env: &mut BareEnv, model: &str) -> Result<(), Outcome> {
    run::step(env, &mut NoSys, model_feats(model))
}

fn put16(env: &mut BareEnv, a: u16, v: u16) {
    env.backend
        .mem
        .write(VirtAddr(u64::from(a)), &v.to_le_bytes())
        .unwrap();
}

fn get16(env: &BareEnv, a: u16) -> u16 {
    let mut b = [0u8; 2];
    env.backend
        .mem
        .read(
            VirtAddr(u64::from(a)),
            &mut b,
            Access {
                endian: Endian::Le,
                align: Align::Unaligned,
                kind: AccessKind::DataRead,
            },
        )
        .unwrap();
    u16::from_le_bytes(b)
}

fn st_put(env: &mut BareEnv, off: usize, v: u16) {
    env.backend.set(StateRef::<W16>::from_offset(off), v);
}

const KSP: usize = core::mem::offset_of!(CpuState, ksp);
const USP: usize = core::mem::offset_of!(CpuState, usp);

/// カーネル APR 8 ページを恒等写像（I/D 両方）。`io_paf` は page7
/// の PAF（I/O ページの物理先頭ブロック）。
fn kernel_identity(env: &mut BareEnv, io_paf: u16) {
    for p in 0..8u16 {
        let paf = if p == 7 { io_paf } else { p * 0o200 };
        for sp in [mmu::Space::I, mmu::Space::D] {
            mmu::apr_put(&mut env.backend, mmu::apr_idx(0, sp, p), paf, 0o177406);
        }
    }
}

// ---- 項目 21: 奇数アドレスのワード参照 ----

#[test]
fn odd_addr_word_access() {
    // mov (r1), r0; r1=1 —— 奇数アドレスの語読み出し。
    for (model, trapped) in [
        ("pdp11_34", true),
        ("pdp11_70", true),
        ("pdp11_03", false),
        ("pdp11_23", false),
    ] {
        let mut env = env_at(model, 0o1000, &[0o011100]);
        put16(&mut env, 0o004, 0o3000);
        put16(&mut env, 0, 0o7777);
        sem::r_set(&mut env.backend, 1, 1);
        step_m(&mut env, model).unwrap();
        if trapped {
            assert_eq!(env.pc, 0o3000, "{model}");
        } else {
            assert_eq!(sem::r_get(&env.backend, 0), 0o7777, "{model}");
        }
    }
}

// ---- 項目 5: JMP/JSR のモード 0 宛先のトラップベクタ ----

#[test]
fn jmp_reg_trap_vector() {
    // jmp r0 —— 宛先モード 0 は違法指定。
    for (model, vec) in [
        ("pdp11_34", 0o010u16),
        ("pdp11_23", 0o010),
        ("pdp11_04", 0o010),
        ("pdp11_44", 0o004),
        ("pdp11_45", 0o004),
        ("pdp11_70", 0o004),
        ("pdp11_73", 0o004),
    ] {
        let mut env = env_at(model, 0o1000, &[0o000100]);
        put16(&mut env, vec, 0o3200);
        step_m(&mut env, model).unwrap();
        assert_eq!(env.pc, 0o3200, "{model}");
    }
}

// ---- 項目 11: RTI が立てた T の発火点 ----

#[test]
fn rti_tbit_timing() {
    // rti —— スタック: PC=0o1010, PSW=T(0o20)。その後ろに nop を置く。
    for (model, imm) in [
        ("pdp11_34", true),
        ("pdp11_23", true),
        ("pdp11_70", false),
        ("pdp11_73", false),
    ] {
        let mut env = env_at(model, 0o1000, &[0o000002, 0, 0, 0, 0o000240]);
        put16(&mut env, 0o014, 0o5000);
        put16(&mut env, SP0, 0o1010);
        put16(&mut env, SP0 + 2, 0o020);
        step_m(&mut env, model).unwrap();
        if imm {
            // RTI 直後に BPT —— PC はハンドラ。
            assert_eq!(env.pc, 0o5000, "{model}");
        } else {
            // 次の命令（0o1010）が走ってから BPT。
            assert_eq!(env.pc, 0o1010, "{model}");
            step_m(&mut env, model).unwrap();
            assert_eq!(env.pc, 0o5000, "{model}");
            let sp = sem::r_get(&env.backend, reg::SP as u8);
            assert_eq!(get16(&env, sp), 0o1012, "{model}");
        }
    }
}

// ---- 項目 18: PSW の 177776 写像 ----

#[test]
fn psw_mapping() {
    // mov @#177776, r0
    for model in ["pdp11_34", "pdp11_03"] {
        let mut env = env_at(model, 0o1000, &[0o013700, 0o177776]);
        put16(&mut env, 0o004, 0o3000);
        sem::psw_put(&mut env.backend, 0o217);
        step_m(&mut env, model).unwrap();
        match model {
            "pdp11_34" => assert_eq!(sem::r_get(&env.backend, 0), 0o217),
            _ => assert_eq!(env.pc, 0o3000), // 写像なし → 未搭載 → vec4
        }
    }
}

// ---- 項目 1・2: 同一レジスタの自増分 ----

#[test]
fn same_reg_autoinc() {
    // mov r0, (r0)+; r0=0o1000
    for (model, inc) in [
        ("pdp11_23", true),
        ("pdp11_60", true),
        ("pdp11_73", true),
        ("t11", true),
        ("pdp11_03", false),
        ("pdp11_04", false),
        ("pdp11_34", false),
        ("pdp11_44", false),
        ("pdp11_70", false),
    ] {
        let mut env = env_at(model, 0o1000, &[0o010020]);
        sem::r_set(&mut env.backend, 0, 0o1000);
        step_m(&mut env, model).unwrap();
        // inc: ソース読出し前に +2 → ソース値 0o1002 が (r0)+ の
        // EA 0o1002 へ入り r0 は計 +4。used は 0o1000 が 0o1000 番地へ。
        if inc {
            assert_eq!(sem::r_get(&env.backend, 0), 0o1004, "{model}");
            assert_eq!(get16(&env, 0o1002), 0o1002, "{model}");
        } else {
            assert_eq!(sem::r_get(&env.backend, 0), 0o1002, "{model}");
            assert_eq!(get16(&env, 0o1000), 0o1000, "{model}");
        }
    }
}

// ---- 項目 3: r7 を格納したときの値 ----

#[test]
fn pc_stored_value() {
    // mov r7, @#0o2000（0o1000 番地）
    for (model, want) in [
        ("pdp11_23", 0o1004u16),
        ("pdp11_60", 0o1004),
        ("pdp11_73", 0o1004),
        ("t11", 0o1004),
        ("pdp11_03", 0o1002),
        ("pdp11_04", 0o1002),
        ("pdp11_34", 0o1002),
        ("pdp11_44", 0o1002),
        ("pdp11_70", 0o1002),
    ] {
        let mut env = env_at(model, 0o1000, &[0o010737, 0o2000]);
        step_m(&mut env, model).unwrap();
        assert_eq!(get16(&env, 0o2000), want, "{model}");
    }
}

// ---- 項目 13: WAIT からの T ビット脱出 ----

#[test]
fn wait_tbit_escape() {
    // T=1 の状態で wait —— seq は命令として抜けて trace へ、hold は
    // 出ない（裸モデルでは終端）。
    let mut env = env_at("pdp11_04", 0o1000, &[0o000001, 0o000240]);
    put16(&mut env, 0o014, 0o5000);
    sem::psw_put(&mut env.backend, 1 << psw::T);
    step_m(&mut env, "pdp11_04").unwrap();
    assert_eq!(env.pc, 0o5000); // wait 完了でそのまま BPT ハンドラへ

    // hold 側は wait が T では出ない —— この命令単位では終端。
    for model in ["pdp11_03", "pdp11_70"] {
        let mut env = env_at(model, 0o1000, &[0o000001]);
        put16(&mut env, 0o014, 0o5000);
        sem::psw_put(&mut env.backend, 1 << psw::T);
        assert!(step_m(&mut env, model).is_err(), "{model}");
    }
}

// ---- 項目 43: 非カーネルの HALT ----

#[test]
fn halt_vector() {
    for (model, vec) in [
        ("pdp11_34", 0o010u16),
        ("pdp11_23", 0o010),
        ("pdp11_60", 0o010),
        ("pdp11_44", 0o004),
        ("pdp11_45", 0o004),
        ("pdp11_70", 0o004),
        ("pdp11_73", 0o004),
    ] {
        let mut env = env_at(model, 0o1000, &[0o000000]);
        st_put(&mut env, KSP, SP0);
        sem::psw_put(&mut env.backend, psw::USER << psw::CUR_MOD);
        put16(&mut env, vec, 0o3200);
        step_m(&mut env, model).unwrap_or_else(|e| panic!("{model}: {e:?}"));
        assert_eq!(env.pc, 0o3200, "{model}");
    }
}

// ---- 項目 20: スタックオーバーフロー ----

#[test]
fn stack_limit_modes() {
    // mov r0, -(sp) で sp=0o400 —— fixed(0o400 境界) は越境、
    // none は素通り。
    let mut env = env_at("pdp11_23", 0o1000, &[0o010046]);
    put16(&mut env, 0o004, 0o3000);
    sem::r_set(&mut env.backend, reg::SP as u8, 0o400);
    step_m(&mut env, "pdp11_23").unwrap();
    assert_eq!(env.pc, 0o3000); // vector 004 へ

    let mut env = env_at("pdp11_03", 0o1000, &[0o010046]);
    sem::r_set(&mut env.backend, reg::SP as u8, 0o400);
    step_m(&mut env, "pdp11_03").unwrap();
    assert_eq!(env.pc, 0o1002); // 検査なし

    // reg: 177774 に制限を書いた分だけ越境を検査する（11/34）。
    let mut env = env_at("pdp11_34", 0o1000, &[0o012737, 0o3000, 0o177774, 0o010046]);
    put16(&mut env, 0o004, 0o3000);
    sem::r_set(&mut env.backend, reg::SP as u8, 0o3400);
    step_m(&mut env, "pdp11_34").unwrap(); // stklim ← 0o3000
    step_m(&mut env, "pdp11_34").unwrap(); // push で 0o3376 < 0o3400 → vec4
    assert_eq!(env.pc, 0o3000);
    // 同じ書き込みでも fixed の 11/23 は 177774 を持たない ——
    // 書き込み自体がバスエラー（vector 004）になる。
    let mut env = env_at("pdp11_23", 0o1000, &[0o012737, 0o3000, 0o177774]);
    put16(&mut env, 0o004, 0o3000);
    sem::r_set(&mut env.backend, reg::SP as u8, 0o3400);
    step_m(&mut env, "pdp11_23").unwrap();
    assert_eq!(env.pc, 0o3000); // 越境ではなくアクセス失敗で 004 へ
}

// ---- MMU レジスタの有無（項目 38・47 系）----

#[test]
fn mmr0_presence() {
    // mov @#177572, r0 —— MMR0 は MMU モデルにのみ存在。
    for (model, has) in [("pdp11_34", true), ("pdp11_70", true), ("pdp11_03", false)] {
        let mut env = env_at(model, 0o1000, &[0o013700, 0o177572]);
        put16(&mut env, 0o004, 0o3000);
        step_m(&mut env, model).unwrap();
        if has {
            assert_eq!(sem::r_get(&env.backend, 0), 0, "{model}");
            assert_eq!(env.pc, 0o1004, "{model}");
        } else {
            assert_eq!(env.pc, 0o3000, "{model}");
        }
    }
}

// ---- 項目 37: MMR0<8> 保守モード桁 ----

#[test]
fn mmr0_maint_bit() {
    // mov #0o400, @#177572; mov @#177572, r0 —— <8> を立てて読む。
    let words = &[0o012737, 0o000400, 0o177572, 0o013700, 0o177572];
    for (model, maint) in [
        ("pdp11_34", true),
        ("pdp11_70", true),
        ("pdp11_23", false),
        ("pdp11_73", false),
    ] {
        let mut env = env_at(model, 0o1000, words);
        step_m(&mut env, model).unwrap();
        step_m(&mut env, model).unwrap();
        let want = if maint { 0o400 } else { 0 };
        assert_eq!(sem::r_get(&env.backend, 0), want, "{model}");
    }
}

// ---- 項目 48-50: MMR3 の実装範囲 ----

#[test]
fn mmr3_presence() {
    // mov @#172516, r0 —— MMR3。34・60 は未実装 → 未搭載メモリ扱い。
    for (model, has) in [
        ("pdp11_70", true),
        ("pdp11_23", true),
        ("pdp11_73", true),
        ("pdp11_34", false),
        ("pdp11_60", false),
    ] {
        let mut env = env_at(model, 0o1000, &[0o013700, 0o172516]);
        put16(&mut env, 0o004, 0o3000);
        step_m(&mut env, model).unwrap();
        if has {
            assert_eq!(env.pc, 0o1004, "{model}");
            assert_eq!(sem::r_get(&env.backend, 0), 0, "{model}");
        } else {
            assert_eq!(env.pc, 0o3000, "{model}");
        }
    }
    // 書き込みマスク: <5:4> は F-11・11/44・J-11 が持ち、<2:0> は
    // 11/70・11/44・J-11 が持つ。
    let words = &[0o012737, 0o000077, 0o172516, 0o013700, 0o172516];
    for (model, want) in [
        ("pdp11_23", 0o60u16),
        ("pdp11_70", 0o67),
        ("pdp11_73", 0o77),
    ] {
        let mut env = env_at(model, 0o1000, words);
        step_m(&mut env, model).unwrap();
        step_m(&mut env, model).unwrap();
        assert_eq!(sem::r_get(&env.backend, 0), want, "{model}");
    }
}

// ---- 項目 51: MMR2 のベクタ追跡 ----

#[test]
fn mmr2_tracks_vectors() {
    // mov (r0), r1 で未写像アドレスを読む —— バスエラー（vector
    // 004）の配送で 11/70 は MMR2 にベクタを記録する。34 では
    // 命令トラップ群・バスエラーともに記録せず、命令先頭簿記の
    // PC（0o1000）が残る。EMT 等の命令トラップは対象外なので
    // バスエラーで発火させる（付録 B 項目 51）。
    for (model, want) in [("pdp11_70", 0o004u16), ("pdp11_34", 0o1000)] {
        let mut env = env_at(model, 0o1000, &[0o011001]);
        kernel_identity(&mut env, 0o7600);
        mmu::mmr_put(&mut env.backend, 0, mmu::mmr0::ENABLE);
        put16(&mut env, 0o004, 0o3000);
        sem::r_set(&mut env.backend, 0, 0o20000); // PA 未写像
        step_m(&mut env, model).unwrap();
        assert_eq!(env.pc, 0o3000, "{model}");
        let mmr2 = mmu::mmr_val(&env.backend, 2);
        assert_eq!(mmr2, want, "{model}");
    }
}

// ---- 項目 39: PS<15:14> の予約値 ----

#[test]
fn reserved_mode_value() {
    // PSW<15:14>=2 で mov (r0), r1 —— F-11 はカーネルに畳む、
    // ku/ksu は MM トラップ、none は桁自体が無い。
    for model in ["pdp11_23", "pdp11_34", "pdp11_70", "pdp11_03"] {
        let mut env = env_at(model, 0o1000, &[0o011001]);
        if model != "pdp11_03" {
            kernel_identity(&mut env, 0o7600);
            mmu::mmr_put(&mut env.backend, 0, mmu::mmr0::ENABLE);
        }
        put16(&mut env, 0o250, 0o6000);
        put16(&mut env, 0o4000, 0o1234);
        sem::r_set(&mut env.backend, 0, 0o4000);
        sem::psw_put(&mut env.backend, 2 << psw::CUR_MOD);
        step_m(&mut env, model).unwrap();
        match model {
            "pdp11_23" | "pdp11_03" => {
                assert_eq!(sem::r_get(&env.backend, 1), 0o1234, "{model}")
            }
            _ => assert_eq!(env.pc, 0o6000, "{model}"),
        }
    }
}

// ---- 項目 40・41: MTPS/MFPS のユーザーモード写像（11/34）----

#[test]
fn mtps_mfps_user_mapping() {
    // ユーザーモードの MTPS —— 34 は PSW 写像（177776 のユーザー
    // D 変換）を経て未常駐なら vector 250、23 は直接アクセスで
    // PS<3:0> に効く。
    for model in ["pdp11_34", "pdp11_23"] {
        let mut env = env_at(model, 0o1000, &[0o106427, 0o7]); // mtps #7
        kernel_identity(&mut env, 0o7600);
        // ユーザー I page0 はフェッチ用に恒等写像。D page7 だけを
        // 未常駐にして MTPS の PSW 写像アクセスを割らせる。
        mmu::apr_put(
            &mut env.backend,
            mmu::apr_idx(2, mmu::Space::I, 0),
            0,
            0o177406,
        );
        mmu::apr_put(&mut env.backend, mmu::apr_idx(2, mmu::Space::D, 7), 0, 0);
        mmu::mmr_put(&mut env.backend, 3, mmu::mmr3::UDS);
        mmu::mmr_put(&mut env.backend, 0, mmu::mmr0::ENABLE);
        put16(&mut env, 0o250, 0o6000);
        st_put(&mut env, KSP, SP0);
        sem::psw_put(&mut env.backend, psw::USER << psw::CUR_MOD);
        step_m(&mut env, model).unwrap();
        match model {
            "pdp11_34" => assert_eq!(env.pc, 0o6000),
            _ => {
                assert_eq!(env.pc, 0o1004);
                assert_eq!(sem::psw_get(&env.backend) & 0o17, 0o7);
            }
        }
    }
}

// ---- 項目 52: MFPI %6 の前モード値 2 ----

#[test]
fn mfp_sp2_prev_mode() {
    // PSW<13:12>=2 で mfpi %6 —— J-11 はユーザー SP、他は不定
    // （カーネル枠に畳む）。
    for (model, want) in [("pdp11_73", 0o1111u16), ("pdp11_70", 0o2222)] {
        let mut env = env_at(model, 0o1000, &[0o006506]); // mfpi %6（modo 0 reg 6）
        st_put(&mut env, USP, 0o1111);
        st_put(&mut env, KSP, 0o2222);
        sem::psw_put(&mut env.backend, 2 << psw::PRV_MOD); // cur=kernel
        step_m(&mut env, model).unwrap();
        let sp = sem::r_get(&env.backend, reg::SP as u8);
        assert_eq!(get16(&env, sp), want, "{model}");
    }
}

// ---- 項目 47: MMR0<12> メモリ管理トラップ ----

#[test]
fn mm_trap_acf() {
    // カーネル D page1 の ACF=1（トラップ条件）。70 ではアクセスが
    // 通って MMR0<12> が立つ、34 では nonresident abort。データは
    // page1（ベクタ領域の page0 と分離 —— 配送のベクタ読み出しが
    // 同じ abort に潰れないように）。
    for (model, mmtr) in [("pdp11_70", true), ("pdp11_34", false)] {
        let mut env = env_at(model, 0o1000, &[0o011001]); // mov (r0), r1
        kernel_identity(&mut env, 0o7600);
        // PAR 0o400 で va 0o20000 → PA 0o40000（写像済み）へ写像。
        mmu::apr_put(
            &mut env.backend,
            mmu::apr_idx(0, mmu::Space::D, 1),
            0o400,
            0o177401,
        );
        mmu::mmr_put(&mut env.backend, 3, mmu::mmr3::KDS);
        mmu::mmr_put(&mut env.backend, 0, mmu::mmr0::ENABLE);
        put16(&mut env, 0o250, 0o6000);
        put16(&mut env, 0o40000, 0o1234);
        sem::r_set(&mut env.backend, 0, 0o20000);
        step_m(&mut env, model).unwrap();
        if mmtr {
            assert_eq!(sem::r_get(&env.backend, 1), 0o1234);
            assert_ne!(mmu::mmr_val(&env.backend, 0) & mmu::mmr0::TRAP, 0);
        } else {
            assert_eq!(env.pc, 0o6000);
        }
    }
}

// ---- 項目 46: PAR の実装桁 ----

#[test]
fn par_width_bits() {
    // カーネル PAR I0（172340）に全桁を書いて読む —— p12 モデルは
    // <15:12> が捨てられる。
    let words = &[0o012737, 0o177777, 0o172340, 0o013700, 0o172340];
    for (model, want) in [
        ("pdp11_34", 0o7777u16),
        ("pdp11_70", 0o177777),
        ("pdp11_23", 0o177777),
        ("pdp11_73", 0o177777),
    ] {
        let mut env = env_at(model, 0o1000, words);
        step_m(&mut env, model).unwrap();
        step_m(&mut env, model).unwrap();
        assert_eq!(sem::r_get(&env.backend, 0), want, "{model}");
    }
}

// ---- 項目 8・17 系: 命令の有無（機能旗）----

#[test]
fn feature_gated_insns() {
    // sob r0, -0（077000）。04 は SOB/MARK を持たない → vec010。
    for (model, has) in [("pdp11_03", true), ("pdp11_23", true), ("pdp11_04", false)] {
        let mut env = env_at(model, 0o1000, &[0o077000]);
        put16(&mut env, 0o010, 0o2400);
        sem::r_set(&mut env.backend, 0, 1);
        step_m(&mut env, model).unwrap();
        if has {
            assert_eq!(sem::r_get(&env.backend, 0), 0, "{model}");
        } else {
            assert_eq!(env.pc, 0o2400, "{model}");
        }
    }
    // sxt r0（006700）。同じく 04 では違法。
    for (model, has) in [("pdp11_03", true), ("pdp11_04", false)] {
        let mut env = env_at(model, 0o1000, &[0o006700]);
        put16(&mut env, 0o010, 0o2400);
        step_m(&mut env, model).unwrap();
        if has {
            assert_eq!(env.pc, 0o1002, "{model}");
        } else {
            assert_eq!(env.pc, 0o2400, "{model}");
        }
    }
    // mfpt（000007）—— 型番コードがモデルで分かれる。
    for (model, code) in [
        ("pdp11_44", 1u16),
        ("pdp11_23", 3),
        ("t11", 4),
        ("pdp11_73", 5),
    ] {
        let mut env = env_at(model, 0o1000, &[0o000007]);
        step_m(&mut env, model).unwrap();
        assert_eq!(sem::r_get(&env.backend, 0), code, "{model}");
    }
    let mut env = env_at("pdp11_04", 0o1000, &[0o000007]);
    put16(&mut env, 0o010, 0o2400);
    step_m(&mut env, "pdp11_04").unwrap();
    assert_eq!(env.pc, 0o2400);
    // mul（070000 = EIS）—— 04 は EIS を持たない。
    for (model, has) in [
        ("pdp11_44", true),
        ("pdp11_60", true),
        ("pdp11_70", true),
        ("pdp11_04", false),
    ] {
        let mut env = env_at(model, 0o1000, &[0o070001]); // mul r1 → r0:r1
        put16(&mut env, 0o010, 0o2400);
        sem::r_set(&mut env.backend, 0, 3);
        sem::r_set(&mut env.backend, 1, 4);
        step_m(&mut env, model).unwrap();
        if has {
            assert_eq!(sem::r_get(&env.backend, 0), 0, "{model}"); // 3*4=12 → R0=0,R1=12
            assert_eq!(sem::r_get(&env.backend, 1), 12, "{model}");
        } else {
            assert_eq!(env.pc, 0o2400, "{model}");
        }
    }
}

// ---- 項目 32・34: KEV11 の 075040-075377 ----

#[test]
fn kev11_opcode_window() {
    // 075100+r0 —— LSI-11+KEV11 は R0 の指す語を読んでから vec010。
    // 読み出しが失敗すれば vec004。他モデルは即 vec010。KEV11 は
    // オプションなので FEAT_FIS を足した集合で走らせる。
    // （075040-075077 は FIS 語として解けるので、未デコードの
    // 075100 を使う —— 付録 B 項目 32・34 の窓の実効範囲）。
    let kev11 = model_feats("pdp11_03") | FEAT_FIS;
    let mut env = env_at("pdp11_03", 0o1000, &[0o075100]);
    put16(&mut env, 0o010, 0o2400);
    put16(&mut env, 0o004, 0o3000);
    sem::r_set(&mut env.backend, 0, 0o6000); // 存在するアドレス
    put16(&mut env, 0o6000, 0o5555);
    run::step(&mut env, &mut NoSys, kev11).unwrap();
    assert_eq!(env.pc, 0o2400); // 読み出し成功 → location 10

    let mut env = env_at("pdp11_03", 0o1000, &[0o075100]);
    put16(&mut env, 0o010, 0o2400);
    put16(&mut env, 0o004, 0o3000);
    sem::r_set(&mut env.backend, 0, 0o20000); // 未写像
    run::step(&mut env, &mut NoSys, kev11).unwrap();
    assert_eq!(env.pc, 0o3000); // 読み出し失敗 → location 4

    let mut env = env_at("pdp11_04", 0o1000, &[0o075100]);
    put16(&mut env, 0o010, 0o2400);
    put16(&mut env, 0o004, 0o3000);
    sem::r_set(&mut env.backend, 0, 0o20000); // 未写像でも読まない
    step_m(&mut env, "pdp11_04").unwrap();
    assert_eq!(env.pc, 0o2400); // 即 location 10
}

// ---- 項目 14: T 桁の直接書き込み ----

#[test]
fn tbit_direct_write() {
    // mov #0o20, @#177776 —— 04 は T が立つ、34 は立たない。
    for (model, direct) in [("pdp11_04", true), ("pdp11_34", false), ("pdp11_70", false)] {
        let mut env = env_at(model, 0o1000, &[0o012737, 0o20, 0o177776]);
        step_m(&mut env, model).unwrap();
        assert_eq!(sem::psw_flag(&env.backend, psw::T), direct, "{model}");
    }
}

// ---- 項目 33: MAINT（LSI-11 の保守命令）----

#[test]
fn maint_insn() {
    // 000210 —— LSI-11 では保守命令（裸モデルでは NOP）、他は
    // 予約 → vec010。
    let mut env = env_at("pdp11_03", 0o1000, &[0o000210, 0o000240]);
    step_m(&mut env, "pdp11_03").unwrap();
    assert_eq!(env.pc, 0o1002); // NOP として通過

    let mut env = env_at("pdp11_04", 0o1000, &[0o000210]);
    put16(&mut env, 0o010, 0o2400);
    step_m(&mut env, "pdp11_04").unwrap();
    assert_eq!(env.pc, 0o2400);
}
