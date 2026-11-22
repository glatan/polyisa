// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! IA-64 のゲスト ISA。段階21 の骨格。
//!
//! IA-64 の命令は 41 ビットのスロット語で、3 個を束ねた 128 ビットの
//! バンドルをフェッチ単位とする。`CpuState` と機能・モデル宣言、
//! ISADL から生成した命令集合・デコード・逆アセンブルの殻を提供する。
//! 実命令のデコードは IA3、実行ループは IA4 で足す。
//! 対象は Linux ユーザモードの Itanium 系（版の範囲は Itanium から
//! Itanium 9700 系まで）。
//! 出典は SPEC-IA64-SDM Rev 2.3 (2010-05) である。
//! Ref: SPEC-IA64-SDM (Rev 2.3).

#![forbid(unsafe_code)]

pub mod bundle;
pub mod sem;

// ISADL モデルから生成した命令集合・デコード・逆アセンブルの殻。
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// IA-64 の ISA ファミリ名。
pub struct Ia64;

impl polyisa_guest::GuestIsa for Ia64 {
    fn family() -> &'static str {
        "ia64"
    }
}

/// アプリケーションレジスタ（AR）の番号。ユーザモードで観測・操作する
/// 範囲だけを `CpuState` に持つ。
/// Ref: SPEC-IA64-SDM (Rev 2.3).
pub mod ar {
    /// RSE 制御。
    pub const RSC: u8 = 16;
    /// バッキングストアポインタ。
    pub const BSP: u8 = 17;
    /// RSE の書き出し位置。
    pub const BSPSTORE: u8 = 18;
    /// RSE の NaT 集積。
    pub const RNAT: u8 = 19;
    /// cmpxchg の比較値。
    pub const CCV: u8 = 32;
    /// ユーザの NaT 集積。
    pub const UNAT: u8 = 36;
    /// FP 状態。
    pub const FPSR: u8 = 40;
    /// 区間タイマ（ユーザ読み取り可）。
    pub const ITC: u8 = 44;
    /// 旧フレーム状態。
    pub const PFS: u8 = 64;
    /// ループカウント。
    pub const LC: u8 = 65;
    /// エピローグカウント。
    pub const EC: u8 = 66;
}

/// CFM（現在フレームマーカ）のビット位置。`CpuState::cfm` は
/// 建築のビット配置で sof/sol/sor と rrb.{gr,fr,pr} を束ねる。
/// Ref: SPEC-IA64-SDM (Rev 2.3).
pub mod cfm_bit {
    /// Size of Frame [6:0]。
    pub const SOF: u32 = 0;
    /// Size of Locals [13:7]。
    pub const SOL: u32 = 7;
    /// Size of Rotating [17:14]。
    pub const SOR: u32 = 14;
    /// 回転基底 GR [25:19]。
    pub const RRB_GR: u32 = 19;
    /// 回転基底 FR [32:26]。
    pub const RRB_FR: u32 = 26;
    /// 回転基底 PR [38:33]。
    pub const RRB_PR: u32 = 33;
}

/// 命令ポインタの下位 4 ビット。バンドル内のスロット番号（0-2）が
/// 入る。上位ビットは 16 バイト整列のバンドルアドレス。
/// Ref: SPEC-IA64-SDM (Rev 2.3).
pub const IP_SLOT_MASK: u64 = 0xf;

/// ALAT の登録エントリ数。
/// Ref: SPEC-IA64-SDM (Rev 2.3).
pub const ALAT_ENTRIES: usize = 32;

/// CPU 状態。`#[repr(C)]` で配置を固定し、`StateRef` はここを指す。
/// すべて u64 の格納。
/// Ref: SPEC-IA64-SDM (Rev 2.3).
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CpuState {
    /// 汎用レジスタ r0-r127。r0 は定数 0（読み出し 0・書き込み破棄の
    /// 実装選択）。r32-r127 は回転・スタック域で、論理番号は CFM の
    /// rrb.gr とフレームで物理番号に解決する。
    pub gr: [u64; 128],
    /// 各 GR の NaT ビット。i 面の j ビット目が r_{64i+j} の NaT。
    pub gr_nat: [u64; 2],
    /// 述語レジスタ p0-p63 のビットマスク。p0 は定数 1。
    pub pr: u64,
    /// 分岐レジスタ b0-b7。
    pub br: [u64; 8],
    /// 命令ポインタ。下位 4 ビットはバンドル内のスロット番号
    /// （0-2）、上位はバンドルアドレス（16 バイト整列）。
    pub ip: u64,
    /// ar.pfs（旧フレーム状態。call で CFM を退避する）。
    pub pfs: u64,
    /// ar.lc（ループカウント）。
    pub lc: u64,
    /// ar.ec（エピローグカウント）。
    pub ec: u64,
    /// ar.bsp（バッキングストアポインタ）。
    pub bsp: u64,
    /// ar.bspstore（RSE の書き出し位置）。
    pub bspstore: u64,
    /// ar.rnat（RSE の NaT 集積）。
    pub rnat: u64,
    /// ar.unat（ユーザの NaT 集積）。
    pub unat: u64,
    /// ar.ccv（cmpxchg の比較値）。
    pub ccv: u64,
    /// ar.fpsr（FP 状態レジスタ）。
    pub fpsr: u64,
    /// ar.rsc（RSE 制御）。
    pub rsc: u64,
    /// ar.itc（区間タイマ。ユーザ読み取り可）。
    pub itc: u64,
    /// CFM（現在フレームマーカ。ビット位置は `cfm_bit`）。
    pub cfm: u64,
    /// RSE の汚れレジスタの追跡（バッキングストアへの書き出し制御。
    /// 追跡の粒度は IA8 で確定する）。
    pub rse_dirty: u64,
    /// ALAT の登録表。advanced load の登録・照合・無効化の器
    /// （エントリの保持内容は IA6 で確定する）。
    pub alat: [u64; ALAT_ENTRIES],
    /// ALAT の有効エントリのビットマスク。
    pub alat_valid: u64,
}

impl Default for CpuState {
    fn default() -> Self {
        Self {
            gr: [0; 128],
            gr_nat: [0; 2],
            pr: 0,
            br: [0; 8],
            ip: 0,
            pfs: 0,
            lc: 0,
            ec: 0,
            bsp: 0,
            bspstore: 0,
            rnat: 0,
            unat: 0,
            ccv: 0,
            fpsr: 0,
            rsc: 0,
            itc: 0,
            cfm: 0,
            rse_dirty: 0,
            alat: [0; ALAT_ENTRIES],
            alat_valid: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_guest::GuestIsa;

    #[test]
    fn family_name() {
        assert_eq!(Ia64::family(), "ia64");
    }

    #[test]
    fn cpu_models() {
        assert!(FEATURES.contains(&"itanium"));
        assert!(FEATURES.contains(&"itanium2"));
        assert!(MODELS.contains(&"generic"));
        assert!(MODELS.contains(&"itanium2"));
    }
}
