// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! OpenRISC のゲスト ISA。段階20 の骨格。
//!
//! `CpuState` と機能・モデル宣言、ISADL から生成した命令集合・
//! デコード・逆アセンブルの殻を提供する。命令の意味論は `sem`
//! 層として後続の段階で足す。
//!
//! 対象は ORBIS32（32 ビット基本命令集合）と ORFPX32（単精度
//! FP 拡張）・ORFPX64A32（GPR ペアの倍精度 FP 拡張）。
//! ORBIS64・ORVDX64 は機能旗の宣言のみで命令の割当てはない。
//! OpenRISC の配布物・Linux or1k ABI はビッグエンディアン
//! ELFCLASS32（EM_OPENRISC=92）である。
//! 出典は SPEC-OPENRISC-1000 である。
//! Ref: SPEC-OPENRISC-1000 §1（アーキテクチャ構成）, §17（ABI）.

#![forbid(unsafe_code)]

// ISADL モデルから生成した命令集合・デコード・逆アセンブルの殻。
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// OpenRISC の ISA ファミリ名。
pub struct Openrisc;

impl polyisa_guest::GuestIsa for Openrisc {
    fn family() -> &'static str {
        "openrisc"
    }
}

/// 特殊目的レジスタ（SPR）の番号。アドレスは 16 ビットで、上位
/// 5 ビットがグループ番号、下位 11 ビットがグループ内番号。
/// ユーザモードの l.mfspr/l.mtspr が触る範囲をここに集める。
/// Ref: SPEC-OPENRISC-1000 §4.3 表 4-1（SPR グループ）,
/// §4.4 表 4-2（グループ 0）.
pub mod spr {
    /// グループ番号をレジスタ番号と合成して SPR アドレスにする。
    pub const fn addr(group: u16, reg: u16) -> u16 {
        (group << 11) | (reg & 0x7ff)
    }

    /// 版レジスタ（読み取り専用）。
    pub const VR: u16 = 0;
    /// 実装ユニット提示（読み取り専用）。
    pub const UPR: u16 = 1;
    /// CPU 構成レジスタ（読み取り専用）。ND ビットが遅延スロットの有無。
    /// Ref: SPEC-OPENRISC-1000 §16.4.
    pub const CPUCFGR: u16 = 2;
    /// データ MMU 構成（未実装のため読み出し 0）。
    pub const DMMUCFGR: u16 = 3;
    /// 命令 MMU 構成。
    pub const IMMUCFGR: u16 = 4;
    /// データキャッシュ構成。
    pub const DCCFGR: u16 = 5;
    /// 命令キャッシュ構成。
    pub const ICCFGR: u16 = 6;
    /// デバッグ構成。
    pub const DCFGR: u16 = 7;
    /// 性能カウンタ構成。
    pub const PCCFGR: u16 = 8;
    /// 版レジスタ 2。
    pub const VR2: u16 = 9;
    /// アーキテクチャ版レジスタ。
    pub const AVR: u16 = 10;
    /// 例外ベクタ基址。
    pub const EVBAR: u16 = 11;
    /// 算術例外制御。
    pub const AECR: u16 = 12;
    /// 算術例外状態。
    pub const AESR: u16 = 13;
    /// NPC。次に実行する命令番地の SPR 写像。
    pub const NPC: u16 = 16;
    /// 監督レジスタ。
    /// Ref: SPEC-OPENRISC-1000 §4.6.
    pub const SR: u16 = 17;
    /// PPC。直前に実行した命令番地の SPR 写像。
    pub const PPC: u16 = 18;
    /// 浮動小数点制御状態レジスタ（ユーザ可読・可書）。
    /// Ref: SPEC-OPENRISC-1000 §4.12.
    pub const FPCSR: u16 = 20;
    /// 実装固有情報 ISR0-7 の先頭。
    pub const ISR0: u16 = 21;
    /// 例外 PC EPCR0-15 の先頭。
    pub const EPCR0: u16 = 32;
    /// 例外 EA EEAR0-15 の先頭。
    pub const EEAR0: u16 = 48;
    /// 例外 SR ESR0-15 の先頭。
    pub const ESR0: u16 = 64;
    /// コア識別子。
    pub const COREID: u16 = 128;
    /// コア数。
    pub const NUMCORES: u16 = 129;
    /// GPR0-GPR511 の SPR 写像の先頭（本実装は r0-r31 の範囲だけ有効）。
    pub const GPR0: u16 = 1024;
    /// MACLO（MAC 下位。グループ 5）。
    pub const MACLO: u16 = addr(5, 1);
    /// MACHI（MAC 上位）。
    pub const MACHI: u16 = addr(5, 2);
    /// FPMADDLO（FP 積和アキュムレータ下位）。
    /// Ref: SPEC-OPENRISC-1000 §5.4（lf.madd.*）.
    pub const FPMADDLO: u16 = addr(5, 3);
    /// FPMADDHI（FP 積和アキュムレータ上位）。
    pub const FPMADDHI: u16 = addr(5, 4);
    /// ティックタイマモード。
    pub const TTMR: u16 = addr(10, 0);
    /// ティックタイマカウント。
    pub const TTCR: u16 = addr(10, 1);
}

/// SR のビット位置。
/// Ref: SPEC-OPENRISC-1000 §4.6 表 4-9.
pub mod sr_bit {
    /// Supervisor Mode。ユーザモデルの近似では立てない。
    pub const SM: u32 = 0;
    /// 条件フラグ（l.sf*・lf.sf*・l.swa が書く）。
    pub const F: u32 = 9;
    /// キャリー旗（l.add/l.addc/l.sub/l.macu 等）。
    pub const CY: u32 = 10;
    /// オーバーフロー旗（l.add/l.sub/l.mul/l.div/l.mac 等）。
    pub const OV: u32 = 11;
    /// オーバーフロー例外許可（範囲例外の有効化。未使用）。
    pub const OVE: u32 = 12;
    /// 遅延スロット中の例外（DSX。ユーザモデルでは未使用）。
    pub const DSX: u32 = 13;
    /// Fixed One。常に 1。
    pub const FO: u32 = 15;
    /// ユーザモードで書き換えてよいビットのマスク
    /// （F・CY・OV。実装選択として SR 全体の可書を許さない。
    /// Gap: 特権レベルの SPR アクセス制限は未モデル化）。
    pub const USER_WRITABLE: u32 = (1 << F) | (1 << CY) | (1 << OV);
}

/// FPCSR のビット位置。
/// Ref: SPEC-OPENRISC-1000 §4.12 表 4-8.
pub mod fpcsr_bit {
    /// FP 例外許可。
    pub const FPEE: u32 = 0;
    /// 丸めモード [2:1]。0=最近接、1=零方向、2=+∞、3=-∞。
    pub const RM_SHIFT: u32 = 1;
    /// オーバーフロー。
    pub const OVF: u32 = 3;
    /// アンダーフロー。
    pub const UNF: u32 = 4;
    /// シグナリング NaN。
    pub const SNF: u32 = 5;
    /// クワイエット NaN。
    pub const QNF: u32 = 6;
    /// 零。
    pub const ZF: u32 = 7;
    /// 非正確。
    pub const IXF: u32 = 8;
    /// 無効演算。
    pub const IVF: u32 = 9;
    /// 無限大。
    pub const INF: u32 = 10;
    /// 零除算。
    pub const DZF: u32 = 11;
}

/// CPUCFGR のビット位置。
/// Ref: SPEC-OPENRISC-1000 §16.4 表 16-3.
pub mod cpucfgr_bit {
    /// 構成された GPR 数が 32 未満か（0=32 本）。
    pub const CGF_SHIFT: u32 = 0;
    /// オーバーフロー旗を立てる命令（l.add 等）の実装。
    pub const OF32S: u32 = 5;
    /// ORFPX32 実装。
    pub const OF32S_PRESENT: u32 = OF32S;
    /// ORFPX64A32 実装。
    pub const OF64A32S: u32 = 8;
    /// ORBIS32 実装。
    pub const OB32S: u32 = 9;
    /// No Delay slot。0=遅延スロットあり、1=なし。
    pub const ND: u32 = 10;
}

/// CPU 状態。`#[repr(C)]` で配置を固定し、`StateRef` はここを指す。
/// すべて u64 の格納で、下位 32 ビットが建築上の値
/// （OpenRISC 1000 の 32 ビット実装のみ対象。ORBIS64 は宣言のみ）。
/// Ref: SPEC-OPENRISC-1000 §4（レジスタ構成）.
#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct CpuState {
    /// 汎用レジスタ r0-r31。r0 は常に 0（実装選択: 読み出しで 0 を
    /// 返し、書き込みは捨てる。§4.1 はソフトウェア責任と述べるが
    /// 実機 or1200/mor1kx はハードワイヤ）。
    /// Ref: SPEC-OPENRISC-1000 §4.1.
    pub r: [u64; 32],
    /// 現在の命令番地（実行中の PC）。
    pub pc: u64,
    /// NPC。次に実行する命令番地。分岐はここを書き換え、
    /// 実行ループの commit が pc に移す。
    /// Ref: SPEC-OPENRISC-1000 §4.4 表 4-2（NPC/PPC）.
    pub npc: u64,
    /// PPC。直前に実行した命令番地（SPR からの観測用）。
    pub ppc: u64,
    /// 監督レジスタ SR。
    /// Ref: SPEC-OPENRISC-1000 §4.6.
    pub sr: u64,
    /// MAC アキュムレータ下位（SPR MACLO）。
    /// Ref: SPEC-OPENRISC-1000 §5.3（l.mac 系）.
    pub maclo: u64,
    /// MAC アキュムレータ上位（SPR MACHI）。
    pub machi: u64,
    /// FP 積和アキュムレータ下位（SPR FPMADDLO）。
    /// Ref: SPEC-OPENRISC-1000 §5.4（lf.madd.*）.
    pub fpmaddlo: u64,
    /// FP 積和アキュムレータ上位（SPR FPMADDHI）。
    pub fpmaddhi: u64,
    /// FP 制御状態レジスタ（SPR FPCSR = グループ 0 番号 20）。
    /// Ref: SPEC-OPENRISC-1000 §4.12.
    pub fpcsr: u64,
    /// 例外ベクタ基址（SPR EVBAR）。
    pub evbar: u64,
    /// ティックタイマカウント（SPR TTCR）。実行ループが
    /// 1 ステップ毎に進める決定論的な時計。
    /// Ref: SPEC-OPENRISC-1000 §15.5.
    pub ttcr: u64,
    /// 版レジスタ（SPR VR）。モデルが供給する読み取り専用値。
    pub vr: u64,
    /// 実装ユニット提示（SPR UPR）。モデルが供給する読み取り専用値。
    pub upr: u64,
    /// CPU 構成レジスタ（SPR CPUCFGR）。モデルが供給する
    /// 読み取り専用値。ND ビットは `dslot` 機能旗に連動する。
    /// Ref: SPEC-OPENRISC-1000 §16.4.
    pub cpucfgr: u64,
}
