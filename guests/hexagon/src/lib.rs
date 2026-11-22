// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Hexagon のゲスト ISA。段階22。
//!
//! Hexagon の命令語は 32 ビットで、1–4 語を束ねたパケットが
//! フェッチ・実行の単位。パケットの切り出し（Parse 桁）・
//! duplex 分解・constant extender の併合は実行側が担い、
//! ISADL から生成した命令集合は 32 ビット語に対して働く。
//! パケット内の命令は同時発行として扱い、書き込みは
//! `CpuState::pkt_*` の未確定域に溜めてパケット終端の commit で
//! 一括反映する（`.new` オペランドはこの一時値を読む）。
//! 対象は Linux ユーザモードの V73 系（配布物要件）と V79
//! （主正本の最新版）。HVX・複数ハードウェアスレッドの交互
//! 実行は後段の段階。
//! 出典は SPEC-HEXAGON-PRM V79 (80-N2040-60 Rev AB)。
//! Ref: SPEC-HEXAGON-PRM (V79), SPEC-HEXAGON-PRM-PREV.

#![forbid(unsafe_code)]

pub mod packet;
pub mod sem;

// ISADL モデルから生成した命令集合・デコード・逆アセンブルの殻。
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// Hexagon の ISA ファミリ名。
pub struct Hexagon;

impl polyisa_guest::GuestIsa for Hexagon {
    fn family() -> &'static str {
        "hexagon"
    }
}

/// 命令語の Parse 桁（bits[15:14]）の値。フェッチ層がパケットの
/// 確定に使う。
/// Ref: SPEC-HEXAGON-PRM (V79) instruction encoding.
pub mod parse {
    /// duplex 語（13 ビット subinsn 2 個）。パケットの終端。
    pub const DUPLEX: u32 = 0;
    /// パケットの非終端。
    pub const NEXT: u32 = 1;
    /// ハードウェアループ終端の標識（パケットの 1 語目が立てば
    /// loop0 終端、2 語目が立てば loop1 終端）。
    pub const ENDLOOP: u32 = 2;
    /// パケットの終端。
    pub const END: u32 = 3;
}

/// 制御レジスタ番号（c0-c31）。転送命令（`Rd = Cs` / `Cd = Rs`）
/// が触れる範囲の置き場を `CpuState` に持つ。
/// Ref: SPEC-HEXAGON-PRM (V79) registers.
pub mod cnum {
    /// ループ 0 開始アドレス。
    pub const SA0: u8 = 0;
    /// ループ 0 残り回数。
    pub const LC0: u8 = 1;
    /// ループ 1 開始アドレス。
    pub const SA1: u8 = 2;
    /// ループ 1 残り回数。
    pub const LC1: u8 = 3;
    /// 述語レジスタ P3:0。
    pub const P3_0: u8 = 4;
    /// 修飾レジスタ 0（auto-increment・円環/ビット反転）。
    pub const M0: u8 = 6;
    /// 修飾レジスタ 1。
    pub const M1: u8 = 7;
    /// ユーザ状態レジスタ。
    pub const USR: u8 = 8;
    /// プログラムカウンタ。
    pub const PC: u8 = 9;
    /// ユーザ汎用ポインタ。
    pub const UGP: u8 = 10;
    /// グローバルポインタ。
    pub const GP: u8 = 11;
    /// 円環バッファ開始 0。
    pub const CS0: u8 = 12;
    /// 円環バッファ開始 1。
    pub const CS1: u8 = 13;
    /// サイクルカウント（下位/上位、対で UPCYCLE）。
    pub const UPCYCLELO: u8 = 14;
    /// サイクルカウント上位。
    pub const UPCYCLEHI: u8 = 15;
    /// フレーム制限。
    pub const FRAMELIMIT: u8 = 16;
    /// フレーム鍵。
    pub const FRAMEKEY: u8 = 17;
    /// パケットカウント（下位/上位、対で PKTCOUNT）。
    pub const PKTCOUNTLO: u8 = 18;
    /// パケットカウント上位。
    pub const PKTCOUNTHI: u8 = 19;
    /// QTimer（下位/上位、対で UTIMER）。
    pub const UTIMERLO: u8 = 30;
    /// QTimer 上位。
    pub const UTIMERHI: u8 = 31;
}

/// USR のビット位置。
/// Ref: SPEC-HEXAGON-PRM (V79) user status register.
pub mod usr_bit {
    /// :sat 系の飽和 sticky（書き込みで明示解除するまで残る）。
    pub const OVF: u32 = 0;
    /// IEEE invalid sticky。
    pub const FPINVF: u32 = 1;
    /// IEEE divide-by-zero sticky。
    pub const FPDBZF: u32 = 2;
    /// IEEE overflow sticky。
    pub const FPOVFF: u32 = 3;
    /// IEEE underflow sticky。
    pub const FPUNFF: u32 = 4;
    /// IEEE inexact sticky。
    pub const FPINPF: u32 = 5;
    /// Not performance critical（スレッドの性能優先度）。
    pub const NPC: u32 = 6;
    /// ハードウェアループ構成（2 ビット、残り繰返しの早見）。
    pub const LPCFGE: u32 = 8;
    /// パケットカウントのモード別有効（user/guest/monitor）。
    pub const PCUME: u32 = 10;
    /// パケットカウント guest 有効。
    pub const PCGME: u32 = 11;
    /// パケットカウント monitor 有効。
    pub const PCMME: u32 = 12;
    /// L1 データ prefetch（2 ビット）。
    pub const HFD: u32 = 13;
    /// L1 命令 prefetch（2 ビット）。
    pub const HFI: u32 = 15;
    /// IEEE-754 動作制御（2 ビット）。
    pub const FPCOPROC: u32 = 20;
    /// FP 丸めモード（2 ビット）。
    pub const FPRND: u32 = 22;
    /// IEEE invalid 例外有効。
    pub const FPINVE: u32 = 25;
    /// IEEE divide-by-zero 例外有効。
    pub const FPDBZE: u32 = 26;
    /// IEEE overflow 例外有効。
    pub const FPOVFE: u32 = 27;
    /// IEEE underflow 例外有効。
    pub const FPUNFE: u32 = 28;
    /// IEEE inexact 例外有効。
    pub const FPINEE: u32 = 29;
    /// L2 prefetch 進行中（読み取り専用）。
    pub const PFA: u32 = 31;
}

/// CPU 状態。`#[repr(C)]` で配置を固定し、`StateRef` はここを指す。
/// すべて u32 の格納。
/// Ref: SPEC-HEXAGON-PRM (V79).
#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct CpuState {
    /// 汎用レジスタ r0-r31（対レジスタ Rdd は偶奇対）。
    pub r: [u32; 32],
    /// 述語レジスタ P3:0（p_i は 8 ビット値で、比較結果は
    /// 0xff/0x00、バイトごとの演算が全 8 ビットを使う）。
    pub p: u32,
    /// プログラムカウンタ（現在のパケットの先頭アドレス）。
    pub pc: u32,
    /// ハードウェアループ 0 の開始アドレス。
    pub sa0: u32,
    /// ハードウェアループ 0 の残り回数。
    pub lc0: u32,
    /// ハードウェアループ 1 の開始アドレス。
    pub sa1: u32,
    /// ハードウェアループ 1 の残り回数。
    pub lc1: u32,
    /// 修飾レジスタ 0（auto-increment・円環/ビット反転）。
    pub m0: u32,
    /// 修飾レジスタ 1。
    pub m1: u32,
    /// ユーザ状態レジスタ（ビット配置は `usr_bit`）。
    pub usr: u32,
    /// ユーザ汎用ポインタ。
    pub ugp: u32,
    /// グローバルポインタ。
    pub gp: u32,
    /// 円環バッファ開始 0。
    pub cs0: u32,
    /// 円環バッファ開始 1。
    pub cs1: u32,
    /// ハードウェアスレッド状態の置き場（交互実行モデルの
    /// スレッド番号・モデル識別。複数スレッドは HX10）。
    pub hwt: u32,
    /// 現在のパケットがハードウェアループの終端なら立つ
    /// （bit0 = endloop0、bit1 = endloop1）。
    pub endloop: u32,
    /// パケット内の未確定書き込み。スロット命令は r を直接
    /// 書かずここに溜め、パケット終端の commit で一括反映する
    /// （`.new` オペランドはこの一時値を読む）。pkt_r_ok の
    /// i ビット目が r_i の未確定書き込み。
    pub pkt_r: [u32; 32],
    /// pkt_r の有効マスク。
    pub pkt_r_ok: u32,
    /// P3:0 の未確定書き込み（pkt_p_ok の i ビット目が p_i）。
    pub pkt_p: u32,
    /// pkt_p の有効マスク。
    pub pkt_p_ok: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_guest::GuestIsa;

    #[test]
    fn family_name() {
        assert_eq!(Hexagon::family(), "hexagon");
    }

    #[test]
    fn cpu_models() {
        assert!(FEATURES.contains(&"v73"));
        assert!(FEATURES.contains(&"v79"));
        assert!(FEATURES.contains(&"tinycore"));
        assert!(FEATURES.contains(&"hvx"));
        assert!(MODELS.contains(&"generic"));
        assert!(MODELS.contains(&"v73"));
        assert!(MODELS.contains(&"v79"));
    }
}
