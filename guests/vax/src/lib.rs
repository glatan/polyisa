// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! VAX のゲスト ISA。段階23 の骨格。
//!
//! `CpuState`（r0-r15・PSL・中断可能命令の途中状態）と、
//! ISADL から生成した命令集合・デコード・CPU モデル宣言の殻を
//! 提供する。命令の意味論と実行ループは後続の段階で足す。
//!
//! VAX の命令は可変長で、オペコード（1 バイト本体、または
//! 0xFD/0xFE/0xFF 接頭の 2 バイト）の後にオペランド指定子の
//! バイト列が続く。生成デコーダはオペコード部だけを見る
//! （`decode(word, 8|16)`、語はフェッチ順に下位ビットから詰める）。
//! MicroVAX 系のサブセット差は機能旗と挙動パラメータで表す。
//! 出典は SPEC-VAX-ARM と SPEC-VAX-MICROVAX である。
//! Ref: SPEC-VAX-ARM, SPEC-VAX-MICROVAX.

#![forbid(unsafe_code)]

// ISADL モデルから生成した命令集合・デコード・逆アセンブルの殻。
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// VAX の ISA ファミリ名。
pub struct Vax;

impl polyisa_guest::GuestIsa for Vax {
    fn family() -> &'static str {
        "vax"
    }
}

/// レジスタ番号の意味名。構文上 r12-r15 は AP/FP/SP/PC と書く。
/// 別名アクセスは意味論側がこの番号で `r` を触る。
/// Ref: SPEC-VAX-ARM（レジスタの章）.
pub mod reg {
    /// r12: 引数ポインタ（calls/callg が引数リストを指す）。
    pub const AP: usize = 12;
    /// r13: フレームポインタ（calls/callg が建てるフレームの基底）。
    pub const FP: usize = 13;
    /// r14: スタックポインタ（現在アクセスモードの）。
    pub const SP: usize = 14;
    /// r15: プログラムカウンタ。
    pub const PC: usize = 15;
}

/// PSL（プロセッサ状態語）のビット位置。下位 16 ビットが PSW
/// （条件コードとトラップ有効）で、上位は特権状態。
/// Ref: SPEC-VAX-ARM（PSL の章）.
pub mod psl {
    /// C 条件コード（桁上げ）。
    pub const C: u32 = 0;
    /// V 条件コード（オーバーフロー）。
    pub const V: u32 = 1;
    /// Z 条件コード（ゼロ）。
    pub const Z: u32 = 2;
    /// N 条件コード（負）。
    pub const N: u32 = 3;
    /// T（トレーストラップ有効）。
    pub const T: u32 = 4;
    /// IV（整数オーバーフロー トラップ有効）。
    pub const IV: u32 = 5;
    /// FU（浮動下桁 フォルト有効）。
    pub const FU: u32 = 6;
    /// DV（十進オーバーフロー トラップ有効）。実装差は `dv_hw`
    /// パラメータが担う。
    pub const DV: u32 = 7;
    /// IPL（割込み優先度、<20:16>）。
    pub const IPL: u32 = 16;
    /// PRV_MOD（直前のアクセスモード、<23:22>）。
    pub const PRV_MOD: u32 = 22;
    /// CUR_MOD（現在のアクセスモード、<25:24>）。
    pub const CUR_MOD: u32 = 24;
    /// IS（割込みスタックで実行中）。
    pub const IS: u32 = 26;
    /// FPD（first part done。中断可能命令の部分実行の標識。
    /// 補完経路の継続ベクタの振り分けにも使う）。
    pub const FPD: u32 = 27;
    /// TP（トレース保留）。
    pub const TP: u32 = 30;
    /// CM（PDP-11 互換モードで実行中）。
    pub const CM: u32 = 31;
    /// IPL 桁（<20:16>）のマスク。
    pub const IPL_MASK: u32 = 0x1f << IPL;
    /// アクセスモード桁（2 ビット）の幅。
    pub const MOD_MASK: u32 = 0x3;
    /// PSW として有効な桁（<7:0>。<15:8> は MBZ）。
    pub const PSW_MASK: u32 = 0xff;
    /// ユーザーモード相当（CUR_MOD=3・IS=0・CM=0）の初期値。
    pub const USER: u32 = 0x3 << CUR_MOD;
}

/// 中断可能命令の途中状態。文字列・十進文字列などの反復命令が
/// PSL<FPD>=1 で同じ命令へ再入するときの進行情報の器。
/// 建築上は中断点の進行が命令ごとに規定する退避先（多くは
/// r0-r5）に残る。ここには退避先に乗らない内部形（どの命令の
/// 部分実行かと、命令固有の作業語）を保持する。内容の規則は
/// 各命令の意味論が定める（後続段階で正本から写す）。
/// Ref: SPEC-VAX-ARM（例外と中断可能命令の章）.
#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct PartialInsn {
    /// 部分実行中の命令。`None` は部分実行なし（FPD=0 からの開始）。
    pub insn: Option<Insn>,
    /// 反復をまたぐ命令固有の作業語。建築上の退避レジスタに
    /// 乗らない分の器。
    pub work: [u32; 4],
}

/// CPU 状態。`#[repr(C)]` で配置を固定し、`StateRef` はここを指す。
/// Ref: SPEC-VAX-ARM（レジスタ・PSL の章）.
#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct CpuState {
    /// 汎用レジスタ r0-r15。r12-r15 の意味名は `reg`。
    pub r: [u32; 16],
    /// プロセッサ状態語。ビット配置は `psl`。
    pub psl: u32,
    /// 中断可能命令の途中状態（PSL<FPD> と対で使う）。
    pub partial: PartialInsn,
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_guest::GuestIsa;

    #[test]
    fn family_name() {
        assert_eq!(Vax::family(), "vax");
    }

    #[test]
    fn register_aliases() {
        // r12-r15 の意味名は建築上のレジスタ番号そのもの。
        let mut cpu = CpuState::default();
        cpu.r[reg::PC] = 0x200;
        cpu.r[reg::SP] = 0x7fff_0000;
        assert_eq!(cpu.r[15], 0x200);
        assert_eq!(cpu.r[14], 0x7fff_0000);
    }

    #[test]
    fn psl_layout() {
        // ユーザーモード相当の初期値は CUR_MOD=3 のみ。
        let mut cpu = CpuState {
            psl: psl::USER,
            ..Default::default()
        };
        assert_eq!(cpu.psl >> psl::CUR_MOD & psl::MOD_MASK, 0x3);
        assert_eq!(cpu.psl & (1 << psl::IS | 1 << psl::CM), 0);
        // 条件コードは下位 4 ビット。FPD は <27>。
        cpu.psl |= 1 << psl::Z | 1 << psl::FPD;
        assert_ne!(cpu.psl & 1 << psl::Z, 0);
        assert_ne!(cpu.psl & 1 << psl::FPD, 0);
        assert_eq!(psl::IPL_MASK, 0x1f << 16);
    }

    #[test]
    fn partial_insn_vessel() {
        // 途中状態の器は既定で「部分実行なし」。
        let cpu = CpuState::default();
        assert!(cpu.partial.insn.is_none());
        assert_eq!(cpu.partial.work, [0; 4]);
    }
}
