// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! MIPS I の整数命令。遅延スロット、符号付き溢れ、非整列ロードを裸実行で確かめる。
//!
//! R6 は遅延スロット付きの分岐とジャンプ、非整列ロード、HI/LO 乗除算を復号しない。
//! BEQZALC だけが R6 側の命令である。ロード遅延は R3000 の実行ループだけが持つ。
//! フェッチとデータのエンディアンは実行ループのモデルが持つ。o32 は後の回で足す。

#![forbid(unsafe_code)]

pub mod sem;

// 空のモデルから生成した殻。ISADL 記述の追加後に中身が増える。
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// MIPS の ISA ファミリ名。
pub struct Mips;

impl polyisa_guest::GuestIsa for Mips {
    fn family() -> &'static str {
        "mips"
    }
}

/// CPU 状態。`#[repr(C)]` で配置を固定する。
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CpuState {
    /// 整数レジスタ $0〜$31。$0 は読むと 0、書き込みは捨てる。
    /// 32ビットで包んだ値を下位に持つ（RV64 の GPR と同じ約束）。
    pub g: [u64; 32],
    /// プログラムカウンタ。
    pub pc: u64,
    /// 次のプログラムカウンタ（遅延スロットの実行先）。
    pub npc: u64,
    /// HI レジスタ（乗除算の上位。下位32ビットを使う）。
    pub hi: u64,
    /// LO レジスタ（乗除算の下位・商。下位32ビットを使う）。
    pub lo: u64,
    /// 0 除算の挙動。0 は HI/LO を保つ。0 以外は HI と LO に 0 を書く。
    /// ゼロ埋めの裸実行は 0 なので、従来の「不変」と同じになる。
    /// Ref: SPEC-MIPS-IV (Rev 3.2) の DIV の UNPREDICTABLE。
    pub div_zero_writes_zero: u64,
    /// ユーザーモードの HW レジスタ（RDHWR $0〜$3）。`$3` は TLS ポインタで、
    /// `set_thread_area` が書く。`$0` は CPU 番号、`$1` は SYNCI 単位、`$2` は CC。
    /// CC の読み出しはカウントレジスタの代わりにステップ数を使う。
    /// Ref: SRC-LINUX (7.3) の `arch/mips/kernel/traps.c` の HW レジスタ。
    pub hwr: [u64; 4],
    /// branch-likely 命令が不成立だったとき 1。遅延スロットを実行せず
    /// pc を pc+8 に進める。成立時・通常命令では 0。
    pub nullify: u64,
    /// 64 ビットモデルなら 1。32 ビット命令の結果は MIPS64 では
    /// 符号拡張して GPR に置く決まりがあるため、意味論が正規化に使う。
    pub is64: u64,
}

impl Default for CpuState {
    fn default() -> Self {
        Self {
            g: [0; 32],
            pc: 0,
            npc: 4,
            hi: 0,
            lo: 0,
            div_zero_writes_zero: 0,
            hwr: [0; 4],
            nullify: 0,
            is64: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_guest::GuestIsa;

    #[test]
    fn family_name() {
        assert_eq!(Mips::family(), "mips");
    }

    #[test]
    fn state_layout_pinned() {
        assert_eq!(core::mem::offset_of!(CpuState, g), 0);
        assert_eq!(core::mem::offset_of!(CpuState, pc), 32 * 8);
        assert_eq!(core::mem::offset_of!(CpuState, npc), 32 * 8 + 8);
        assert_eq!(core::mem::offset_of!(CpuState, hi), 32 * 8 + 16);
        assert_eq!(core::mem::offset_of!(CpuState, lo), 32 * 8 + 24);
        assert_eq!(
            core::mem::offset_of!(CpuState, div_zero_writes_zero),
            32 * 8 + 32
        );
        assert_eq!(core::mem::offset_of!(CpuState, hwr), 32 * 8 + 40);
    }

    #[test]
    fn insn_count() {
        // MIPS I + MIPS32r2 + MIPS64 + Release 6（コンパクト分岐・
        // EVA・語対の LL/SC・branch-likely 含む）。nop は sll $0,$0,0 の別名。
        assert_eq!(INSNS.len(), 199);
    }

    #[test]
    fn decode_spot_checks() {
        // 命令語はビット配置から手で組み立てる。Ref: SPEC-MIPS-IV。
        assert_eq!(decode(0x0043_0821, 32), Some(Insn::Addu));
        assert_eq!(decode(0x0043_0823, 32), Some(Insn::Subu));
        assert_eq!(decode(0x0043_0824, 32), Some(Insn::And));
        assert_eq!(decode(0x0043_0825, 32), Some(Insn::Or));
        assert_eq!(decode(0x0003_0880, 32), Some(Insn::Sll));
        assert_eq!(decode(0x0022_0018, 32), Some(Insn::Mult));
        assert_eq!(decode(0x0022_0019, 32), Some(Insn::Multu));
        assert_eq!(decode(0x0022_001a, 32), Some(Insn::Div));
        assert_eq!(decode(0x0022_001b, 32), Some(Insn::Divu));
        assert_eq!(decode(0x0000_0810, 32), Some(Insn::Mfhi));
        assert_eq!(decode(0x0000_0812, 32), Some(Insn::Mflo));
        assert_eq!(decode(0x0020_0011, 32), Some(Insn::Mthi));
        assert_eq!(decode(0x0020_0013, 32), Some(Insn::Mtlo));
        // nop は sll $0,$0,0 の別名であり、Sll に解釈する。
        assert_eq!(decode(0x0000_0000, 32), Some(Insn::Sll));
        assert_eq!(decode(0x8c41_0010, 32), Some(Insn::Lw));
        assert_eq!(decode(0xac41_0010, 32), Some(Insn::Sw));
        assert_eq!(decode(0x1022_0004, 32), Some(Insn::Beq));
        assert_eq!(decode(0x0800_0400, 32), Some(Insn::J));
        // R6 の割り当て直し：op=001000 は pre-R6 では ADDI。
        // Ref: SPEC-MIPS-R6 (Rev 6.06).
        assert_eq!(decode(0x2043_0010, 32), Some(Insn::Addi));
        // R6 では rs==0 && rt!=0 の符号化が BEQZALC になる。
        assert_eq!(decode(0x2001_0004, 32), Some(Insn::Addi));
        // ADDIU は R6 でも残る。
        assert_eq!(decode(0x2443_0010, 32), Some(Insn::Addiu));
        assert_eq!(
            decode_model_ex(0x2443_0010, 32, true, FEAT_MIPS_R6),
            Some(Insn::Addiu)
        );
        // HI/LO 乗除算は R6 で削除される（MUL/MUH/MOD 系は本格実装）。
        assert_eq!(decode(0x0022_0018, 32), Some(Insn::Mult));
        assert_eq!(decode_model_ex(0x0022_0018, 32, true, FEAT_MIPS_R6), None);
        assert_eq!(
            decode_model_ex(0x2001_0004, 32, true, FEAT_MIPS_R6),
            Some(Insn::Beqzalc)
        );
        // R6 では 001000 が BOVC/BEQZALC/BEQC。0x2043 は rs=2<rt=3 で BEQC。
        assert_eq!(
            decode_model_ex(0x2043_0010, 32, true, FEAT_MIPS_R6),
            Some(Insn::Beqc)
        );
        // Release 6 は遅延スロット付きの BEQ を外す。LUI は残る。
        assert_eq!(decode(0x3c01_0001, 32), Some(Insn::Lui));
        assert_eq!(decode(0x1022_0004, 32), Some(Insn::Beq));
        assert_eq!(decode_model_ex(0x1022_0004, 32, true, FEAT_MIPS_R6), None);
        assert_eq!(decode(0xffff_ffff, 32), None);
    }

    #[test]
    fn cpu_models() {
        assert!(FEATURES.contains(&"mips1"));
        assert!(FEATURES.contains(&"mips32r2"));
        assert!(FEATURES.contains(&"mips64"));
        assert!(FEATURES.contains(&"mips_r6"));
        assert!(MODELS.contains(&"r3000"));
        assert!(MODELS.contains(&"mips32r2"));
        assert!(MODELS.contains(&"r6"));
        assert!(MODELS.contains(&"mips64r2"));
        assert!(MODELS.contains(&"mips64r6"));
    }

    /// Release 2 / MIPS64 / Release 6 の追加命令の復号。
    /// 命令語はビット配置から手で組み立てる。Ref: SPEC-MIPS-IV, SPEC-MIPS-R6。
    /// r2/MIPS64r2 拡張の一次根拠は台帳の SPEC-MIPS32R2・SPEC-MIPS64（未確認）。
    #[test]
    fn decode_release_ext() {
        let f = |w: u32, feats: u64| decode_model_ex(u128::from(w), 32, true, feats);
        const R2: u64 = FEAT_MIPS32R2;
        const M64: u64 = FEAT_MIPS32R2 | FEAT_MIPS64;
        const R6: u64 = FEAT_MIPS32R2 | FEAT_MIPS_R6;
        const M64R6: u64 = FEAT_MIPS32R2 | FEAT_MIPS64 | FEAT_MIPS_R6;

        // R2 で残る命令（r6 のモデルでも有効）。
        assert_eq!(f(0x0022_180a, R2), Some(Insn::Movz));
        assert_eq!(f(0x0022_180b, R2), Some(Insn::Movn));
        assert_eq!(f(0x0022_48f4, R2), Some(Insn::Teq));
        assert_eq!(f(0x0000_000f, R2), Some(Insn::Sync));
        assert_eq!(f(0x7c22_2880, R2), Some(Insn::Ext));
        assert_eq!(f(0x7c22_2884, R2), Some(Insn::Ins));
        assert_eq!(f(0x7c02_183b, R2), Some(Insn::Rdhwr));
        assert_eq!(f(0x7c02_1c20, R2), Some(Insn::Seb));
        assert_eq!(f(0x7c02_1e20, R2), Some(Insn::Seh));
        assert_eq!(f(0x7c02_18a0, R2), Some(Insn::Wsbh));
        assert_eq!(f(0xc041_0010, R2), Some(Insn::Ll));
        assert_eq!(f(0xe041_0010, R2), Some(Insn::Sc));
        assert_eq!(f(0xcc41_0010, R2), Some(Insn::Pref));
        // SPECIAL2（r6 では除去される）。
        assert_eq!(f(0x7022_1802, R2), Some(Insn::MulR2));
        assert_eq!(f(0x7022_0000, R2), Some(Insn::Madd));
        assert_eq!(f(0x7022_0001, R2), Some(Insn::Maddu));
        assert_eq!(f(0x7022_0004, R2), Some(Insn::Msub));
        assert_eq!(f(0x7022_0005, R2), Some(Insn::Msubu));
        assert_eq!(f(0x7020_1820, R2), Some(Insn::ClzR2));
        assert_eq!(f(0x7020_1821, R2), Some(Insn::CloR2));
        assert_eq!(f(0x7022_1802, R6), None);
        // MIPS64 の演算とロード/ストア。
        assert_eq!(f(0x0022_182d, M64), Some(Insn::Daddu));
        assert_eq!(f(0x0022_182f, M64), Some(Insn::Dsubu));
        assert_eq!(f(0x0022_182c, M64), Some(Insn::Dadd));
        assert_eq!(f(0x0022_182e, M64), Some(Insn::Dsub));
        assert_eq!(f(0x0022_1814, M64), Some(Insn::Dsllv));
        assert_eq!(f(0x0002_19b8, M64), Some(Insn::Dsll));
        assert_eq!(f(0x0002_19fb, M64), Some(Insn::Dsra));
        assert_eq!(f(0x0002_19fc, M64), Some(Insn::Dsll32));
        assert_eq!(f(0x6441_0010, M64), Some(Insn::Daddiu));
        assert_eq!(f(0x6041_0010, M64), Some(Insn::Daddi));
        assert_eq!(f(0x0022_001c, M64), Some(Insn::Dmult));
        assert_eq!(f(0x0022_001d, M64), Some(Insn::Dmultu));
        assert_eq!(f(0x0022_001e, M64), Some(Insn::Ddiv));
        assert_eq!(f(0x0022_001f, M64), Some(Insn::Ddivu));
        assert_eq!(f(0xdc41_0010, M64), Some(Insn::Ld));
        assert_eq!(f(0x9c41_0010, M64), Some(Insn::Lwu));
        assert_eq!(f(0xd041_0010, M64), Some(Insn::Lld));
        assert_eq!(f(0xfc41_0010, M64), Some(Insn::Sd));
        assert_eq!(f(0xf041_0010, M64), Some(Insn::Scd));
        assert_eq!(f(0x6841_0010, M64), Some(Insn::Ldl));
        assert_eq!(f(0x6c41_0010, M64), Some(Insn::Ldr));
        assert_eq!(f(0xb041_0010, M64), Some(Insn::Sdl));
        assert_eq!(f(0xb441_0010, M64), Some(Insn::Sdr));
        assert_eq!(f(0x7c22_50c2, M64), Some(Insn::Dext));
        assert_eq!(f(0x7c22_50c1, M64), Some(Insn::Dextm));
        assert_eq!(f(0x7c22_50c3, M64), Some(Insn::Dextu));
        assert_eq!(f(0x7c22_50c6, M64), Some(Insn::Dins));
        assert_eq!(f(0x7c22_50c5, M64), Some(Insn::Dinsm));
        assert_eq!(f(0x7c22_50c7, M64), Some(Insn::Dinsu));
        assert_eq!(f(0x7c02_18a4, M64), Some(Insn::Dsbh));
        assert_eq!(f(0x7c02_1964, M64), Some(Insn::Dshd));
        assert_eq!(f(0x7020_1824, M64), Some(Insn::DclzR2));
        // R6 の乗除算・選択・シフト加算。
        assert_eq!(f(0x0022_1898, R6), Some(Insn::Mul));
        assert_eq!(f(0x0022_1899, R6), Some(Insn::Mulu));
        assert_eq!(f(0x0022_189a, R6), Some(Insn::DivR6));
        assert_eq!(f(0x0022_189b, R6), Some(Insn::DivuR6));
        assert_eq!(f(0x0022_18d8, R6), Some(Insn::Muh));
        assert_eq!(f(0x0022_18d9, R6), Some(Insn::Muhu));
        assert_eq!(f(0x0022_18da, R6), Some(Insn::Mod));
        assert_eq!(f(0x0022_18db, R6), Some(Insn::Modu));
        assert_eq!(f(0x0022_1835, R6), Some(Insn::Seleqz));
        assert_eq!(f(0x0022_1837, R6), Some(Insn::Selnez));
        assert_eq!(f(0x0022_1805, R6), Some(Insn::Lsa));
        assert_eq!(f(0x0022_18c5, R6), Some(Insn::Lsa));
        assert_eq!(f(0x0020_1850, R6), Some(Insn::Clz));
        assert_eq!(f(0x0020_1851, R6), Some(Insn::Clo));
        assert_eq!(f(0x0022_189c, M64R6), Some(Insn::Dmul));
        assert_eq!(f(0x0022_18dc, M64R6), Some(Insn::Dmuh));
        assert_eq!(f(0x0022_189e, M64R6), Some(Insn::DdivR6));
        assert_eq!(f(0x0022_18de, M64R6), Some(Insn::Dmod));
        assert_eq!(f(0x0020_1852, M64R6), Some(Insn::Dclz));
        assert_eq!(f(0x0020_1853, M64R6), Some(Insn::Dclo));
        assert_eq!(f(0x0022_1815, M64R6), Some(Insn::Dlsa));
        // R6 のビット操作と PC 相対。
        assert_eq!(f(0x7c22_18a0, R6), Some(Insn::Align));
        assert_eq!(f(0x7c22_1924, M64R6), Some(Insn::Dalign));
        assert_eq!(f(0x7c02_1820, R6), Some(Insn::Bitswap));
        assert_eq!(f(0x7c02_1824, M64R6), Some(Insn::Dbitswap));
        assert_eq!(f(0xec5e_0000, R6), Some(Insn::Auipc));
        assert_eq!(f(0xec5f_0000, R6), Some(Insn::Aluipc));
        assert_eq!(f(0xec41_2345, R6), Some(Insn::Addiupc));
        assert_eq!(f(0xec48_0000, R6), Some(Insn::Lwpc));
        assert_eq!(f(0xec50_0000, R6), Some(Insn::Lwupc));
        assert_eq!(f(0xec58_0000, M64R6), Some(Insn::Ldpc));
        assert_eq!(f(0xec58_0000, R6), None);
        // R6 の遅延スロットなし制御。
        assert_eq!(f(0xc800_0004, R6), Some(Insn::Bc));
        assert_eq!(f(0xe800_0004, R6), Some(Insn::Balc));
        assert_eq!(f(0xd840_0004, R6), Some(Insn::Jic));
        assert_eq!(f(0xd841_0000, R6), Some(Insn::Beqzc));
        assert_eq!(f(0xf840_0004, R6), Some(Insn::Jialc));
        assert_eq!(f(0xf841_0000, R6), Some(Insn::Bnezc));
        // R6 のコンパクト分岐。フィールド間比較で分解する。
        // 001000: rs>=rt は BOVC、0<rs<rt は BEQC、rs=0&rt!=0 は BEQZALC。
        assert_eq!(f(0x2062_0004, R6), Some(Insn::Bovc));
        assert_eq!(f(0x2042_0004, R6), Some(Insn::Bovc));
        assert_eq!(f(0x2043_0004, R6), Some(Insn::Beqc));
        assert_eq!(f(0x2001_0004, R6), Some(Insn::Beqzalc));
        assert_eq!(f(0x2020_0004, R6), Some(Insn::Bovc));
        // 011000: BNVC / BNEC / BNEZALC。
        assert_eq!(f(0x6062_0004, R6), Some(Insn::Bnvc));
        assert_eq!(f(0x6043_0004, R6), Some(Insn::Bnec));
        assert_eq!(f(0x6001_0004, R6), Some(Insn::Bnezalc));
        // 000110: rs=0 は BLEZALC、rs=rt は BGEZALC、その他は BGEUC。
        // rt=0 は R6 では復号しない。
        assert_eq!(f(0x1803_0004, R6), Some(Insn::Blezalc));
        assert_eq!(f(0x1842_0004, R6), Some(Insn::Bgezalc));
        assert_eq!(f(0x1823_0004, R6), Some(Insn::Bgeuc));
        assert_eq!(f(0x1800_0004, R6), None);
        // 000111: BGTZALC / BLTZALC / BLTUC。
        assert_eq!(f(0x1c03_0004, R6), Some(Insn::Bgtzalc));
        assert_eq!(f(0x1c42_0004, R6), Some(Insn::Bltzalc));
        assert_eq!(f(0x1c23_0004, R6), Some(Insn::Bltuc));
        assert_eq!(f(0x1c00_0004, R6), None);
        // 010110: BLEZC / BGEZC / BGEC。
        assert_eq!(f(0x5803_0004, R6), Some(Insn::Blezc));
        assert_eq!(f(0x5842_0004, R6), Some(Insn::Bgezc));
        assert_eq!(f(0x5823_0004, R6), Some(Insn::Bgec));
        assert_eq!(f(0x5800_0004, R6), None);
        // 010111: BGTZC / BLTZC / BLTC。
        assert_eq!(f(0x5c03_0004, R6), Some(Insn::Bgtzc));
        assert_eq!(f(0x5c42_0004, R6), Some(Insn::Bltzc));
        assert_eq!(f(0x5c23_0004, R6), Some(Insn::Bltc));
        assert_eq!(f(0x5c00_0004, R6), None);
        // R6 でなければコンパクト分岐は復号しない（001000 は ADDI）。
        assert_eq!(f(0x2043_0004, R2), Some(Insn::Addi));
        // 64 ビット命令は 32 ビットモデルでは復号しない。
        assert_eq!(f(0x0022_182d, R2), None);
        assert_eq!(f(0xdc41_0010, R6), None);
        // R6 でも J/JAL/JR は残る（遅延スロット付きのまま）。
        assert_eq!(f(0x0800_0400, R6), Some(Insn::J));
        assert_eq!(f(0x0c00_0400, R6), Some(Insn::Jal));
        assert_eq!(f(0x03e0_0008, R6), Some(Insn::Jr));
        // R6 の SPECIAL3 LL/SC（offset9）。旧主オペコードは R6 では復号しない。
        assert_eq!(f(0x7c43_0836, R6), Some(Insn::LlR6));
        assert_eq!(f(0x7c43_0826, R6), Some(Insn::ScR6));
        assert_eq!(f(0x7c43_0837, M64R6), Some(Insn::LldR6));
        assert_eq!(f(0x7c43_0827, M64R6), Some(Insn::ScdR6));
        assert_eq!(f(0x7c43_0837, R6), None);
        assert_eq!(f(0xc041_0010, R6), None);
        assert_eq!(f(0x7c43_0836, R2), None);
        // R6 の EVA 版と語対の LL/SC。語対形は bit6=1 で [15:11] が第二レジスタ。
        assert_eq!(f(0x7c43_082e, R6), Some(Insn::Lle));
        assert_eq!(f(0x7c43_081e, R6), Some(Insn::Sce));
        assert_eq!(f(0x7c43_5076, R6), Some(Insn::Llwp));
        assert_eq!(f(0x7c43_5066, R6), Some(Insn::Scwp));
        assert_eq!(f(0x7c43_506e, R6), Some(Insn::Llwpe));
        assert_eq!(f(0x7c43_505e, R6), Some(Insn::Scwpe));
        // bit6=1 の符号化は単独形では復号しない（語対として読む）。
        assert_eq!(f(0x7c43_0876, R6), Some(Insn::Llwp));
        // R6 の REGIMM 系と上位即値。NAL/BAL は rs=0 固定。
        assert_eq!(f(0x0410_0010, R6), Some(Insn::Nal));
        assert_eq!(f(0x0411_0010, R6), Some(Insn::Bal));
        assert_eq!(f(0x3c43_1234, R6), Some(Insn::Aui));
        assert_eq!(f(0x7443_1234, M64R6), Some(Insn::Daui));
        assert_eq!(f(0x0446_1234, M64R6), Some(Insn::Dahi));
        assert_eq!(f(0x045e_1234, M64R6), Some(Insn::Dati));
        // pre-R6 ではそれぞれ旧命令側（BLTZAL/BGEZAL）か予約。
        assert_eq!(f(0x0410_0010, R2), Some(Insn::Bltzal));
        assert_eq!(f(0x0411_0010, R2), Some(Insn::Bgezal));
        assert_eq!(f(0x3c43_1234, R2), None);
        assert_eq!(f(0x7443_1234, M64), None);
        // SYNCI は r2 から有効で R6 でも残る。
        assert_eq!(f(0x045f_0010, R2), Some(Insn::Synci));
        assert_eq!(f(0x045f_0010, R6), Some(Insn::Synci));
    }
}
