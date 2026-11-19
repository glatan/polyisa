// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! m68k Linux の Line-F（コプロセッサ ID 1 = 68881 系 FPU）補完。
//!
//! FPU 非搭載の実機系では、F-line 命令は Line-F 例外を起こし、
//! カーネルの math エミュレーション（`arch/m68k/math-emu`）が命令を
//! 補完する。このモジュールはその器に相当し、メモリ転送命令
//! （fmovem.x / fmovem.l / fmove.x のレジスタ間・メモリ間）だけを
//! 実装する。算術・分岐・fsave/frestore は対象外で、呼び出し側が
//! Line-F 例外のまま配送する（その先は未実装として落ちる）。
//!
//! FP レジスタの中身は 96 ビット拡張形式の不透明イメージとして
//! `CpuState.fp` を往復するだけで、値の解釈はしない。
//! Ref: SPEC-M68K-FPU (MC68881UM), SRC-LINUX (arch/m68k/math-emu).

use polyisa_engine::bare::BareEnv;
use polyisa_guest_m68k::ea::{self, Ea};
use polyisa_guest_m68k::sem::{self, Fp, Fpcr, Fpiar, Fpsr};
use polyisa_mem::{Access, AccessKind, Align, Endian, VirtAddr};
use polyisa_sem::{Backend as _, StateRef, W32};

/// 命令語のフェッチ属性（BE・非整列許容）。
const FT: Access = Access {
    endian: Endian::Be,
    align: Align::Unaligned,
    kind: AccessKind::Fetch,
};

/// データ読み出し属性（BE・非整列許容）。
const RD: Access = Access {
    endian: Endian::Be,
    align: Align::Unaligned,
    kind: AccessKind::DataRead,
};

/// `a` 位置の 16 ビット命令語をフェッチする。
fn word_at(env: &BareEnv, a: u64) -> Option<u16> {
    let mut b = [0u8; 2];
    env.backend.mem.read(VirtAddr(a), &mut b, FT).ok()?;
    Some(u16::from_be_bytes(b))
}

/// `a` から `size` バイトを BE の u32 として読む（size は 4 以下）。
fn load32(env: &BareEnv, a: u64, size: u64) -> Option<u32> {
    let mut b = [0u8; 4];
    env.backend
        .mem
        .read(VirtAddr(a), &mut b[..size as usize], RD)
        .ok()?;
    Some(u32::from_be_bytes(b) >> ((4 - size) * 8))
}

/// `v` の下位 `size` バイトを BE で `a` へ書く。
fn store32(env: &mut BareEnv, a: u64, v: u32, size: u64) -> Option<()> {
    let b = (v << ((4 - size) * 8)).to_be_bytes();
    env.backend.mem.write(VirtAddr(a), &b[..size as usize]).ok()
}

/// アドレスレジスタ `n`（n=7 は SR.S で USP/SSP を選ぶ）を読む。
fn areg(env: &mut BareEnv, n: u8) -> u32 {
    env.step(|b| Ok(sem::areg(b, n))).unwrap_or(0)
}

/// アドレスレジスタ `n` に書く。
fn set_areg(env: &mut BareEnv, n: u8, v: u32) -> Option<()> {
    env.step(|b| sem::set_areg(b, n, v)).ok()?;
    Some(())
}

/// `pc` 位置の F-line 命令をエミュレートする。扱えたら命令長
/// （バイト数）を返す。呼び出し側は `env.pc += 戻り値` で復帰する。
/// FPU 以外・算術系・対象外の形式は `None`。
pub fn emulate(env: &mut BareEnv, pc: u64) -> Option<u64> {
    let w = u64::from(word_at(env, pc)?);
    // 先頭語は `1111 001 000 <ea>`: cpid=1 かつ type 0 (cpGEN) のみ。
    // type 1 (fscc/fdbcc)・type 2/3 (fbcc)・type 4 (fsave)・
    // type 5 (frestore) は対象外として通常の Line-F 例外へ返す。
    if w & 0xFFC0 != 0xF200 {
        return None;
    }
    let ext = u64::from(word_at(env, pc + 2)?);
    let (mode, reg) = (((w >> 3) & 7) as u8, (w & 7) as u8);
    match (ext >> 13) & 7 {
        // fmovem.x（FP データレジスタ群 <-> メモリ）。
        0b111 | 0b110 => fmovem_x(env, pc, mode, reg, ext),
        // fmovem.l / fmove.l（FPCR/FPSR/FPIAR <-> EA/Dn/An/#imm）。
        0b100 | 0b101 => fmovem_l(env, pc, mode, reg, ext),
        // opclass 0 の一般形式（ext[14]=0）。コマンド 0 = fmove
        // （FPm -> FPn: ext[12:10]=src、ext[9:7]=dst）。このとき
        // 先頭語の EA フィールドは実機でも参照されない。
        // その他の算術命令は対象外。
        0b000 if ext & 0x7F == 0 => {
            let (src, dst) = ((ext >> 10) & 7, (ext >> 7) & 7);
            for j in 0..3u8 {
                let v = env.backend.get(Fp(src as u8).w(j));
                env.backend.set(Fp(dst as u8).w(j), v);
            }
            Some(4)
        }
        // fmove.<fmt> <ea>,fpn / fpn,<ea>。転送のみ対象で、
        // 形式変換を要さない .x（12 バイト）だけを扱う。
        0b010 | 0b011 if (ext >> 10) & 7 == 2 => {
            fmove_x(env, pc, mode, reg, ext, (ext >> 13) & 1 == 1)
        }
        _ => None,
    }
}

/// 転送の形状。`elems`×`size` が転送総量、`pre`/`post` は
/// `-(An)`/`(An)+` の合法性、`read` は EA が読み出し側かどうか
/// （書き込み側は制御変更可能な EA のみに限る）。
struct Xfer {
    elems: u32,
    size: u64,
    pre: bool,
    post: bool,
    read: bool,
}

/// EA を評価してメモリアドレスを返す。戻り値は
/// (先頭アドレス, EA 拡張語数)。レジスタ直接・即値は `None`。
/// `-(An)`/`(An)+` は転送総量で An を動かす
/// （fmovem は -(An) が書き込み側・(An)+ が読み出し側のみ合法だが、
/// fmove 単体では両方向とも両方が合法）。
fn ea_addr(env: &mut BareEnv, pc: u64, mode: u8, reg: u8, xf: Xfer) -> Option<(u64, u32)> {
    match mode {
        // -(An): An を転送総量ぶん下げてその先頭を使う。
        4 if xf.pre => {
            let total = u64::from(xf.elems) * xf.size;
            let base = u64::from(areg(env, reg)).wrapping_sub(total) & 0xFFFF_FFFF;
            set_areg(env, reg, base as u32)?;
            Some((base, 0))
        }
        // (An)+: 先頭を使ったあと An を転送総量ぶん進める。
        3 if xf.post => {
            let base = u64::from(areg(env, reg));
            let total = u64::from(xf.elems) * xf.size;
            set_areg(env, reg, (base + total) as u32)?;
            Some((base, 0))
        }
        0 | 1 | 4 | 3 => None,
        _ => {
            // 書き込み宛先は制御変更可能な EA のみ（PC 相対・即値不可）。
            if !xf.read && mode == 7 && reg >= 2 {
                return None;
            }
            let r = env.step(|b| ea::eval_full(b, mode, reg, 4, pc + 4)).ok()?;
            let (e, _n, dyn_n) = r;
            match e {
                Ea::Addr(a) => Some((a & 0xFFFF_FFFF, dyn_n)),
                _ => None,
            }
        }
    }
}

/// fmovem.x のデータレジスタ転送。`ext[13]` = 方向（1 = FP→メモリ）、
/// `ext[11]` = 1 ならマスクは Dn（レジスタ番号は `ext[6:4]`）、
/// 0 なら `ext[7:0]`。
///
/// マスクのビット並びは EA 形で決まる: `-(An)` では bit i = FPi、
/// それ以外では bit7 = FP0（NetBSD fpe・WinUAE と同じ規約）。
/// どちらの形式でも、選んだレジスタは番号昇順のパック配置で
/// メモリに連続して置かれる（最も小さい番号が最下位アドレス）。
fn fmovem_x(env: &mut BareEnv, pc: u64, mode: u8, reg: u8, ext: u64) -> Option<u64> {
    let write = (ext >> 13) & 1 == 1;
    let mask = if (ext >> 11) & 1 == 1 {
        env.backend.get(sem::D(((ext >> 4) & 7) as u8).state()) & 0xFF
    } else {
        (ext & 0xFF) as u32
    };
    // bit i -> FPi に正規化する（`-(An)` はそのまま、それ以外は反転）。
    let mask = if mode == 4 {
        mask as u8
    } else {
        (mask as u8).reverse_bits()
    };
    let n = mask.count_ones();
    // fmovem: -(An) は書き込み側、(An)+ は読み出し側のみ合法。
    let xf = Xfer {
        elems: n,
        size: 12,
        pre: write,
        post: !write,
        read: !write,
    };
    let (base, eaw) = ea_addr(env, pc, mode, reg, xf)?;
    let mut a = base;
    for i in 0..8u8 {
        if mask >> i & 1 == 0 {
            continue;
        }
        for j in 0..3u8 {
            if write {
                let v = env.backend.get(Fp(i).w(j));
                store32(env, a + u64::from(j) * 4, v, 4)?;
            } else {
                let v = load32(env, a + u64::from(j) * 4, 4)?;
                env.backend.set(Fp(i).w(j), v);
            }
        }
        a += 12;
    }
    Some(4 + u64::from(eaw) * 2)
}

/// 制御レジスタ選択の並び: (sel ビット, 状態参照, ロード時マスク)。
/// 昇順アドレスに FPCR・FPSR・FPIAR の順で置かれる。マスクは
/// 実機の実装ビットのみを通すためのもの（NetBSD fpe 準拠）。
fn ctrl_regs() -> [(u32, StateRef<W32>, u32); 3] {
    [
        (4, Fpcr::state(), 0x0000_FFF0),
        (2, Fpsr::state(), 0x0FFF_FFF8),
        (1, Fpiar::state(), 0xFFFF_FFFF),
    ]
}

/// fmovem.l / fmove.l の制御レジスタ転送。`ext[15:13]`:
/// 101 = レジスタ→EA、100 = EA→レジスタ。選択は `ext[12:10]` で
/// bit2=FPCR・bit1=FPSR・bit0=FPIAR（0 は実機では FPIAR 扱い）。
///
/// EA はレジスタ→EA 側ではモード 7 reg≥2 以外すべて、EA→レジスタ
/// 側ではモード 7 reg≥5 以外すべてが合法（#imm も可）。Dn は
/// 単一レジスタ選択のみ、An は FPIAR との間のみ合法。
fn fmovem_l(env: &mut BareEnv, pc: u64, mode: u8, reg: u8, ext: u64) -> Option<u64> {
    let write = (ext >> 13) & 1 == 1;
    let mut sel = ((ext >> 10) & 7) as u32;
    if sel == 0 {
        sel = 1;
    }
    let n = sel.count_ones();
    let ctrl = ctrl_regs();
    match mode {
        // Dn 直接: 単一レジスタ選択のみ。
        0 if n == 1 => {
            for (bit, s, m) in ctrl {
                if sel & bit == 0 {
                    continue;
                }
                if write {
                    let v = env.backend.get(s);
                    env.backend.set(sem::D(reg).state(), v);
                } else {
                    let v = env.backend.get(sem::D(reg).state());
                    env.backend.set(s, v & m);
                }
            }
            Some(4)
        }
        // An 直接: FPIAR との間のみ。
        1 if sel == 1 => {
            if write {
                let v = env.backend.get(Fpiar::state());
                set_areg(env, reg, v)?;
            } else {
                let v = areg(env, reg);
                env.backend.set(Fpiar::state(), v);
            }
            Some(4)
        }
        0 | 1 => None,
        // #imm: 読み側のみ。拡張語の直後に選択個数×4 バイトが続く。
        _ if mode == 7 && reg == 4 => {
            if write {
                return None;
            }
            let mut a = pc + 4;
            for (bit, s, m) in ctrl {
                if sel & bit == 0 {
                    continue;
                }
                env.backend.set(s, load32(env, a, 4)? & m);
                a += 4;
            }
            Some(4 + u64::from(n) * 4)
        }
        _ => {
            // 制御レジスタ転送は -(An)/(An)+ が両方向とも合法。
            let xf = Xfer {
                elems: n,
                size: 4,
                pre: true,
                post: true,
                read: !write,
            };
            let (base, eaw) = ea_addr(env, pc, mode, reg, xf)?;
            let mut a = base;
            for (bit, s, m) in ctrl {
                if sel & bit == 0 {
                    continue;
                }
                if write {
                    let v = env.backend.get(s);
                    store32(env, a, v, 4)?;
                } else {
                    env.backend.set(s, load32(env, a, 4)? & m);
                }
                a += 4;
            }
            Some(4 + u64::from(eaw) * 2)
        }
    }
}

/// fmove.x <ea>,fpn / fpn,<ea>。`ext[15:13]` = 010（読み）・
/// 011（書き）、`ext[12:10]` = fmt（010 = .x）、`ext[9:7]` = fpn。
fn fmove_x(env: &mut BareEnv, pc: u64, mode: u8, reg: u8, ext: u64, write: bool) -> Option<u64> {
    let fpn = ((ext >> 7) & 7) as u8;
    // #imm は読み側のみ（12 バイトの即値が拡張語の直後に続く）。
    if mode == 7 && reg == 4 {
        if write {
            return None;
        }
        for j in 0..3u8 {
            env.backend
                .set(Fp(fpn).w(j), load32(env, pc + 4 + u64::from(j) * 4, 4)?);
        }
        return Some(4 + 12);
    }
    // 単体 fmove は両方向とも -(An)/(An)+ が合法。
    let xf = Xfer {
        elems: 1,
        size: 12,
        pre: true,
        post: true,
        read: !write,
    };
    let (base, eaw) = ea_addr(env, pc, mode, reg, xf)?;
    for j in 0..3u8 {
        let a = base + u64::from(j) * 4;
        if write {
            let v = env.backend.get(Fp(fpn).w(j));
            store32(env, a, v, 4)?;
        } else {
            env.backend.set(Fp(fpn).w(j), load32(env, a, 4)?);
        }
    }
    Some(4 + u64::from(eaw) * 2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_guest_m68k::CpuState;
    use polyisa_guest_m68k::sem::A;
    use polyisa_mem::Perms;

    /// コードを 0x1000、データを 0x4000 に写像した環境。
    fn env_of(words: &[u16]) -> BareEnv {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        for base in [0x1000, 0x4000] {
            env.backend
                .mem
                .map(VirtAddr(base), 1, Perms(0b111))
                .unwrap();
        }
        let mut code = Vec::new();
        for w in words {
            code.extend_from_slice(&w.to_be_bytes());
        }
        env.backend.mem.write(VirtAddr(0x1000), &code).unwrap();
        env
    }

    fn mem32(env: &BareEnv, a: u64) -> u32 {
        load32(env, a, 4).unwrap()
    }

    /// fp0-fp7 に識別用のイメージを入れる（fp i の j 語 = 0xFPij0000）。
    fn seed_fp(env: &mut BareEnv) {
        for i in 0..8u8 {
            for j in 0..3u8 {
                env.backend.set(
                    Fp(i).w(j),
                    0xF000_0000 | (u32::from(i) << 20) | u32::from(j),
                );
            }
        }
    }

    /// fmovem.x fp0-fp7,60(a0) — `f228 f0ff 003c`（d16(a0) への退避）。
    #[test]
    fn fmovem_x_store_d16() {
        let mut env = env_of(&[0xF228, 0xF0FF, 0x003C]);
        env.backend.set(A(0).state(), 0x4000);
        seed_fp(&mut env);
        assert_eq!(emulate(&mut env, 0x1000), Some(6));
        for i in 0..8u64 {
            assert_eq!(mem32(&env, 0x403C + i * 12), 0xF000_0000 | (i as u32) << 20);
            assert_eq!(
                mem32(&env, 0x403C + i * 12 + 8),
                0xF000_0000 | ((i as u32) << 20) | 2
            );
        }
    }

    /// fmovem.x (a0)+,fp0-fp2 — `f218 d0e0`（非 predec は bit7=fp0）。
    /// 36 バイト読んで A0+=36。fp0 が最下位スロットに来る。
    #[test]
    fn fmovem_x_load_postinc() {
        let mut env = env_of(&[0xF218, 0xD0E0]);
        env.backend.set(A(0).state(), 0x4000);
        for i in 0..9u64 {
            store32(&mut env, 0x4000 + i * 4, 0x1000 + i as u32, 4).unwrap();
        }
        assert_eq!(emulate(&mut env, 0x1000), Some(4));
        assert_eq!(env.backend.get(A(0).state()), 0x4000 + 36);
        assert_eq!(env.backend.get(Fp(0).w(0)), 0x1000);
        assert_eq!(env.backend.get(Fp(0).w(2)), 0x1002);
        assert_eq!(env.backend.get(Fp(2).w(0)), 0x1006);
        // fp3 はマスク外で不変。
        assert_eq!(env.backend.get(Fp(3).w(0)), 0);
    }

    /// fmovem.x fp0-fp2,-(a0) — `f220 e007`（predec は bit i = FPi）。
    /// fp0 が最終アドレスの最低位に来る。
    #[test]
    fn fmovem_x_store_predec() {
        let mut env = env_of(&[0xF220, 0xE007]);
        env.backend.set(A(0).state(), 0x4100);
        seed_fp(&mut env);
        assert_eq!(emulate(&mut env, 0x1000), Some(4));
        assert_eq!(env.backend.get(A(0).state()), 0x4100 - 36);
        assert_eq!(mem32(&env, 0x4100 - 36), 0xF000_0000); // fp0.w0 が最低位
        assert_eq!(mem32(&env, 0x4100 - 36 + 24), 0xF020_0000); // fp2.w0
    }

    /// fmovem.x fp1/fp3,(a0) — `f210 f050`（非 predec: bit6=fp1・bit4=fp3）。
    /// スパースなマスクでも選択分だけ連続 12 バイトスロットに詰める。
    #[test]
    fn fmovem_x_store_sparse() {
        let mut env = env_of(&[0xF210, 0xF050]);
        env.backend.set(A(0).state(), 0x4000);
        seed_fp(&mut env);
        assert_eq!(emulate(&mut env, 0x1000), Some(4));
        assert_eq!(mem32(&env, 0x4000), 0xF010_0000); // fp1.w0 が最下位
        assert_eq!(mem32(&env, 0x400C), 0xF030_0000); // fp3.w0 が次スロット
    }

    /// fmovem.x d2,(a0) — `f210 f820`（動的マスク: レジスタ番号は ext[6:4]）。
    /// d2=0x50 は静的形式と同じく bit7=fp0 の並びで解釈される。
    #[test]
    fn fmovem_x_store_dyn() {
        let mut env = env_of(&[0xF210, 0xF820]);
        env.backend.set(A(0).state(), 0x4000);
        env.backend.set(sem::D(2).state(), 0x50); // fp1・fp3
        seed_fp(&mut env);
        assert_eq!(emulate(&mut env, 0x1000), Some(4));
        assert_eq!(mem32(&env, 0x4000), 0xF010_0000);
        assert_eq!(mem32(&env, 0x400C), 0xF030_0000);
    }

    /// fmovem.l fpcr/fpsr/fpiar,(a0) — `f210 bc00`（昇順に3語書く）。
    #[test]
    fn fmovem_l_store_ctrl() {
        let mut env = env_of(&[0xF210, 0xBC00]);
        env.backend.set(A(0).state(), 0x4000);
        env.backend.set(Fpcr::state(), 0xC0DE);
        env.backend.set(Fpsr::state(), 0x5EED);
        env.backend.set(Fpiar::state(), 0x1EA5);
        assert_eq!(emulate(&mut env, 0x1000), Some(4));
        assert_eq!(mem32(&env, 0x4000), 0xC0DE);
        assert_eq!(mem32(&env, 0x4004), 0x5EED);
        assert_eq!(mem32(&env, 0x4008), 0x1EA5);
    }

    /// fmove.l d2,fpcr / fpcr,d0 — `f202 9000`（d2→fpcr）と
    /// `f200 b000`（fpcr→d0）。Dn 直接は単一レジスタのみ合法。
    #[test]
    fn fmove_l_dreg() {
        let mut env = env_of(&[0xF202, 0x9000]);
        env.backend.set(sem::D(2).state(), 0xDEAD_BEEF);
        assert_eq!(emulate(&mut env, 0x1000), Some(4));
        // FPCR は実装ビット 0xFFF0 のみ取り込まれる。
        assert_eq!(env.backend.get(Fpcr::state()), 0xBEE0);

        let mut env = env_of(&[0xF200, 0xB000]);
        env.backend.set(Fpcr::state(), 0xC0DE);
        assert_eq!(emulate(&mut env, 0x1000), Some(4));
        assert_eq!(env.backend.get(sem::D(0).state()), 0xC0DE);

        // 複数選択 + Dn は不正 → 拒否。
        let mut env = env_of(&[0xF200, 0x9800]);
        assert_eq!(emulate(&mut env, 0x1000), None);
    }

    /// fmove.l a1,fpiar / fpiar,a1 — `f209 8400` と `f209 a400`。
    /// An 直接は FPIAR との間だけ合法。
    #[test]
    fn fmove_l_areg() {
        let mut env = env_of(&[0xF209, 0x8400]);
        env.backend.set(A(1).state(), 0x1234_5678);
        assert_eq!(emulate(&mut env, 0x1000), Some(4));
        assert_eq!(env.backend.get(Fpiar::state()), 0x1234_5678);

        let mut env = env_of(&[0xF209, 0xA400]);
        env.backend.set(Fpiar::state(), 0x1EA5);
        assert_eq!(emulate(&mut env, 0x1000), Some(4));
        assert_eq!(env.backend.get(A(1).state()), 0x1EA5);

        // An と FPCR の組み合わせは不正。
        let mut env = env_of(&[0xF209, 0x9000]);
        assert_eq!(emulate(&mut env, 0x1000), None);
    }

    /// fmove.l #imm,fpcr — `f23c 9000` + 4 バイト即値。
    #[test]
    fn fmove_l_imm() {
        let mut env = env_of(&[0xF23C, 0x9000, 0x1234, 0x5678]);
        assert_eq!(emulate(&mut env, 0x1000), Some(8));
        assert_eq!(env.backend.get(Fpcr::state()), 0x5670);
    }

    /// fmovem.l fpcr,(a0)+ — `f218 b000`（書き込み側でも postinc は合法）。
    #[test]
    fn fmovem_l_store_postinc() {
        let mut env = env_of(&[0xF218, 0xB000]);
        env.backend.set(A(0).state(), 0x4000);
        env.backend.set(Fpcr::state(), 0xC0DE);
        assert_eq!(emulate(&mut env, 0x1000), Some(4));
        assert_eq!(env.backend.get(A(0).state()), 0x4004);
        assert_eq!(mem32(&env, 0x4000), 0xC0DE);
    }

    /// fmove.x fp3,(a0) — `f210 6980`（12 バイト書く）。
    #[test]
    fn fmove_x_store() {
        let mut env = env_of(&[0xF210, 0x6980]);
        env.backend.set(A(0).state(), 0x4000);
        for j in 0..3u8 {
            env.backend.set(Fp(3).w(j), 0xAA00 + u32::from(j));
        }
        assert_eq!(emulate(&mut env, 0x1000), Some(4));
        assert_eq!(mem32(&env, 0x4000), 0xAA00);
        assert_eq!(mem32(&env, 0x4008), 0xAA02);
    }

    /// fmove.x fp3,fp5 — `f200 0e80`（ext[12:10]=src・ext[9:7]=dst）。
    /// 先頭語の EA フィールドは参照されない。
    #[test]
    fn fmove_x_regreg() {
        let mut env = env_of(&[0xF200, 0x0E80]);
        for j in 0..3u8 {
            env.backend.set(Fp(3).w(j), 0xAA00 + u32::from(j));
        }
        assert_eq!(emulate(&mut env, 0x1000), Some(4));
        assert_eq!(env.backend.get(Fp(5).w(0)), 0xAA00);
        assert_eq!(env.backend.get(Fp(5).w(2)), 0xAA02);
        assert_eq!(env.backend.get(Fp(3).w(0)), 0xAA00); // src は不変
    }

    /// 算術系（fadd 等）は対象外で None → 呼び出し側の Line-F 配送へ。
    #[test]
    fn arithmetic_declines() {
        // f228 0034: ext[15:13]=000 で op≠0 → 算術命令。
        let mut env = env_of(&[0xF228, 0x0034]);
        env.backend.set(A(0).state(), 0x4000);
        assert_eq!(emulate(&mut env, 0x1000), None);
        // cpid 違い（0xF028 = cpid 0）も対象外。
        let mut env = env_of(&[0xF028, 0x0000]);
        assert_eq!(emulate(&mut env, 0x1000), None);
        // fsave（type 4 = 0xF3xx）は type 0 ではないので拒否。
        let mut env = env_of(&[0xF300, 0xE0FF]);
        env.backend.set(A(0).state(), 0x4000);
        assert_eq!(emulate(&mut env, 0x1000), None);
    }
}
