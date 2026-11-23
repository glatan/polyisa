// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! PDP-11 のゲスト ISA。段階24。
//!
//! `CpuState`（r0-r7・PSW・オプション状態）と、ISADL から生成した
//! 命令集合・デコード・CPU モデル宣言の殻を提供する。命令語は
//! 16 ビット固定長で、語内のオペランド指定子（mode,reg の対）と
//! それが消費する拡張語の読み取りは `specifier`、実行ループは
//! `run`、指定子の実効評価と命令の意味論は `sem` が担う
//! （意味論本体は PD5 以降が育てる）。
//!
//! オプション命令群（EIS・FIS・FP11・CIS・MMU 系）とモデル間で
//! 実装が割れる命令（MTPS/MFPS・SPL・MFPT・CSM・TSTSET/WRTLCK）
//! の有無は機能旗で、振る舞いの差（奇数アドレストラップ・PSW
//! 写像・JMP/JSR モード 0 のベクタ等）は挙動パラメータで表す。
//! 出典は SPEC-PDP11-ARCH83 と SPEC-PDP11-LSI11・SPEC-PDP11-HANDBOOK・
//! SPEC-PDP11-J11 である。
//! Ref: SPEC-PDP11-ARCH83, SPEC-PDP11-LSI11, SPEC-PDP11-HANDBOOK,
//! SPEC-PDP11-J11.

#![forbid(unsafe_code)]

// ISADL モデルから生成した命令集合・デコード・逆アセンブルの殻。
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// オペランド指定子（mode,reg）のデコード・拡張語消費・評価と、
/// long/F/D の「3412」語順写像。
pub mod specifier;

/// CIS（076nnn 空間）の記述子評価と文字列・十進命令の意味論。
pub mod cis;

/// メモリ管理（PAR/PDR 再配置・I/D 空間・MMR0-3・I/O ページ写像）。
pub mod mmu;

/// 実行ループ（ワードフェッチ・トラップ境界の解決）。
pub mod run;

/// 命令意味論（指定子の実効評価・トラップ配送・命令本体）。
pub mod sem;

/// PDP-11 の ISA ファミリ名。
pub struct Pdp11;

impl polyisa_guest::GuestIsa for Pdp11 {
    fn family() -> &'static str {
        "pdp11"
    }
}

/// レジスタ番号の意味名。構文上 r6 は SP、r7 は PC と書く。
/// 別名アクセスは意味論側がこの番号で `r` を触る。
/// Ref: SPEC-PDP11-ARCH83（レジスタの章）.
pub mod reg {
    /// r6: スタックポインタ（現在モードの）。
    pub const SP: usize = 6;
    /// r7: プログラムカウンタ。
    pub const PC: usize = 7;
}

/// PSW（プロセッサ状態語）のビット位置。<3:0> が条件コード NZVC
/// の順ではなく C V Z N の順に下位から並ぶ。
/// Ref: SPEC-PDP11-ARCH83（PSW の章）.
pub mod psw {
    /// C 条件コード（桁上げ）。
    pub const C: u16 = 0;
    /// V 条件コード（オーバーフロー）。
    pub const V: u16 = 1;
    /// Z 条件コード（ゼロ）。
    pub const Z: u16 = 2;
    /// N 条件コード（負）。
    pub const N: u16 = 3;
    /// T（トレーストラップ有効）。
    pub const T: u16 = 4;
    /// 割込み優先度（<7:5>）。
    pub const PRI: u16 = 5;
    /// 汎用レジスタセット選択（<11>。dual_regset モデルのみ有効）。
    pub const RS: u16 = 11;
    /// 直前モード（<13:12>）。
    pub const PRV_MOD: u16 = 12;
    /// 現在モード（<15:14>）。
    pub const CUR_MOD: u16 = 14;
    /// 優先度桁（<7:5>）のマスク。
    pub const PRI_MASK: u16 = 0x7 << PRI;
    /// モード桁（2 ビット）の幅。
    pub const MOD_MASK: u16 = 0x3;
    /// モードの値: カーネル。
    pub const KERNEL: u16 = 0;
    /// モードの値: スーパーバイザ（sm モデルのみ）。
    pub const SUPERVISOR: u16 = 1;
    /// モードの値: ユーザー。
    pub const USER: u16 = 3;
    /// 裸実行の既定値: カーネルモード・優先度 0。
    pub const BARE: u16 = KERNEL << CUR_MOD;
}

/// `PartialInsn::insn` の「部分実行なし」の値。
pub const PART_INSN_NONE: u16 = 0xffff;

/// 中断可能命令の途中状態。CIS の文字列・十進命令のような長い
/// 命令が中断して同じ命令へ再入するときの進行情報の器（PDP-11
/// では進行は命令の規定する退避先＝記述子レジスタに残る。ここ
/// には退避先に乗らない内部形＝どの命令の部分実行かと命令固有の
/// 作業語を保持する）。内容の規則は PD11 で正本から写す。
/// Ref: SPEC-PDP11-ARCH83（CIS の章・中断の規則）.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct PartialInsn {
    /// 部分実行中の命令語（16 ビット）。`PART_INSN_NONE` は部分
    /// 実行なし。
    pub insn: u16,
    /// 反復をまたぐ命令固有の作業語。
    pub work: [u32; 4],
}

impl Default for PartialInsn {
    fn default() -> Self {
        Self {
            insn: PART_INSN_NONE,
            work: [0; 4],
        }
    }
}

/// CPU 状態。`#[repr(C)]` で配置を固定し、`StateRef` はここを指す。
/// オプションに対応する状態（FP11・MMU）は機能旗の有無に関わらず
/// 器として常に持ち、旗がないモデルでは読み書きされない。
/// Ref: SPEC-PDP11-ARCH83（レジスタ・PSW・浮動小数点・メモリ管理の
/// 各章）, SPEC-PDP11-J11（第1章）.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CpuState {
    /// 汎用レジスタ r0-r7。r6=SP・r7=PC の意味名は `reg`。
    pub r: [u16; 8],
    /// 第 2 汎用レジスタセット（r0′-r5′）。PSW<11> で現在の
    /// r0-r5 と入れ替わる。dual_regset モデルのみ意味を持つ。
    pub ralt: [u16; 6],
    /// カーネルモードの SP 退避先（mmu モデル。モード切替で
    /// r6 と入れ替わる）。
    pub ksp: u16,
    /// スーパーバイザモードの SP 退避先（sm モデルのみ意味を持つ）。
    pub ssp: u16,
    /// ユーザーモードの SP 退避先。
    pub usp: u16,
    /// プロセッサ状態語。ビット配置は `psw`。
    pub psw: u16,
    /// FP11 のアキュムレータ AC0-AC5（fp11 モデル。F 形式は上位
    /// 32 ビット、D 形式は全 64 ビット）。
    pub ac: [u64; 6],
    /// FP11 の浮動状態語（FPS。fp11 モデル）。
    pub fps: u16,
    /// FP11 の例外コード（FEC）。
    pub fec: u16,
    /// FP11 の例外アドレス（FEA）。
    pub fea: u16,
    /// MMU のページアドレスレジスタ（mmu モデル）。添字は
    /// `モード(0=kernel,1=supervisor,2=user)*16 + 空間(0=I,1=D)*8
    /// + ページ(0-7)`。
    pub par: [u16; 48],
    /// MMU のページ記述レジスタ。添字規則は `par` と同じ。
    pub pdr: [u16; 48],
    /// MMU 状態レジスタ MMR0-MMR3（先行モデルは MMR0-2 のみ）。
    pub mmr: [u16; 4],
    /// スタック制限レジスタ（stack_limit モデルのみ意味を持つ）。
    pub stklim: u16,
    /// 命令完了時に配送するトラップ（ベクタ。0=なし）。MMU の
    /// trap 条件（ACF 1/4/5）とカーネルスタックのイエローゾーンが
    /// 立て、step が命令の完結時に拾う。
    pub pendtrap: u16,
    /// 中断可能命令の途中状態（CIS。`PartialInsn`）。
    pub partial: PartialInsn,
}

// 32 要素を越える配列（PAR/PDR）を持つため `Default` は手書きする
// （全桁 0。PSW はカーネルモード・優先度 0 と一致する）。
impl Default for CpuState {
    fn default() -> Self {
        Self {
            r: [0; 8],
            ralt: [0; 6],
            ksp: 0,
            ssp: 0,
            usp: 0,
            psw: 0,
            ac: [0; 6],
            fps: 0,
            fec: 0,
            fea: 0,
            par: [0; 48],
            pdr: [0; 48],
            mmr: [0; 4],
            stklim: 0,
            pendtrap: 0,
            partial: PartialInsn::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_guest::GuestIsa;

    #[test]
    fn family_name() {
        assert_eq!(Pdp11::family(), "pdp11");
    }

    #[test]
    fn state_layout_pinned() {
        // 意味論側が依存する配置を固定する。末尾への追加は許すが、
        // 既存項目の移動は許さない。
        assert_eq!(core::mem::offset_of!(CpuState, r), 0);
        assert_eq!(core::mem::offset_of!(CpuState, ralt), 16);
        assert_eq!(core::mem::offset_of!(CpuState, ksp), 28);
        assert_eq!(core::mem::offset_of!(CpuState, ssp), 30);
        assert_eq!(core::mem::offset_of!(CpuState, usp), 32);
        assert_eq!(core::mem::offset_of!(CpuState, psw), 34);
        assert_eq!(core::mem::offset_of!(CpuState, ac), 40);
        assert_eq!(core::mem::offset_of!(CpuState, fps), 88);
        assert_eq!(core::mem::offset_of!(CpuState, fec), 90);
        assert_eq!(core::mem::offset_of!(CpuState, fea), 92);
        assert_eq!(core::mem::offset_of!(CpuState, par), 94);
        assert_eq!(core::mem::offset_of!(CpuState, pdr), 190);
        assert_eq!(core::mem::offset_of!(CpuState, mmr), 286);
        assert_eq!(core::mem::offset_of!(CpuState, stklim), 294);
        assert_eq!(core::mem::offset_of!(CpuState, pendtrap), 296);
        // `PartialInsn` の 4 バイト整列で 298 から 300 へ詰まる。
        assert_eq!(core::mem::offset_of!(CpuState, partial), 300);
    }

    #[test]
    fn register_aliases() {
        // r6/r7 の意味名は建築上のレジスタ番号そのもの。
        let mut cpu = CpuState::default();
        cpu.r[reg::PC] = 0o1000;
        cpu.r[reg::SP] = 0o177776;
        assert_eq!(cpu.r[7], 0o1000);
        assert_eq!(cpu.r[6], 0o177776);
    }

    #[test]
    fn psw_layout() {
        // 裸実行の既定はカーネルモード・優先度 0。
        let mut cpu = CpuState {
            psw: psw::BARE,
            ..Default::default()
        };
        assert_eq!(cpu.psw >> psw::CUR_MOD & psw::MOD_MASK, psw::KERNEL);
        assert_eq!(cpu.psw & psw::PRI_MASK, 0);
        // 条件コードは下位 4 ビットに C V Z N の順、T は <4>、
        // RS は <11>、モードは <13:12>・<15:14>。
        cpu.psw |= 1 << psw::Z | 1 << psw::T | 1 << psw::RS;
        assert_ne!(cpu.psw & 1 << psw::Z, 0);
        cpu.psw |= psw::USER << psw::PRV_MOD;
        assert_eq!(cpu.psw >> psw::PRV_MOD & psw::MOD_MASK, psw::USER);
    }

    #[test]
    fn partial_insn_vessel() {
        // 途中状態の器は既定で「部分実行なし」。
        let cpu = CpuState::default();
        assert_eq!(cpu.partial.insn, PART_INSN_NONE);
        assert_eq!(cpu.partial.work, [0; 4]);
    }
}
