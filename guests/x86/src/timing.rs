//! 80486 / Pentium (P5) の命令クロックモデル。
//!
//! `MapDec`（map デコーダの結果）を命令属性 `InsnTiming` に分類し、
//! プロセッサごとの発行モデル（`I486` / `Pentium`）に流す。
//! 汎用タイミング抽象は `polyisa-timing` クレートが持ち、ここは
//! x86 固有の ISA 別モデルとして命令の形から属性を引く層。
//! クロック値・パイプ属性は下記参照に基づく。
//!
//! Ref: SPEC-X86-I486 (Intel486 PRM, 240486) — 基本クロック、AGI、接頭辞ペナルティ。
//! Ref: SPEC-X86-PENTIUM (Pentium Family Developer's Manual, 241428/241430)
//!      — U/V パイプのペアリング規則、命令クロック、D-cache バンク競合。
//!
//! 対象は 486 世代の汎用命令に限る。x87・文字列・I/O・特権命令、
//! セグメント push/pop、SETcc、Moffs 形、BT 系のメモリ形や、値依存の
//! MUL/IMUL（486）・BSF/BSR は `classify` が `None` または
//! `c486: None` を返す。486 の複雑 EA 加算（index ペナルティ）は
//! 現時点ではモデル化していない。

use crate::INSNS;
use crate::MapDec;
use crate::decode::{op_reg, reg, rm_reg};
use crate::sem::Gpr;

/// Pentium のパイプ属性（241430 附属書の UV/PU/PV/NP 分類）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pipe {
    /// U/V どちらでも発行・ペア可。
    Uv,
    /// ペアでは U 側のみ（CF 依存の ADC/SBB、シフト系など）。
    Pu,
    /// ペアでは V 側のみ（分岐・CALL/JMP）。
    Pv,
    /// ペア不可（常に U、複数クロック）。
    Np,
}

/// 命令のタイミング属性。`None` のクロックは「値依存・未採録」。
pub struct InsnTiming {
    /// 486 基本クロック（分岐命令は成否込みで確定済み）。
    pub c486: Option<u16>,
    /// P5 基本クロック。
    pub c5: Option<u16>,
    /// P5 パイプ属性。
    pub pipe: Pipe,
    /// 読む GPR のビット集合（EA の base/index を含む）。
    pub uses: u64,
    /// 書く GPR のビット集合。
    pub defs: u64,
    /// メモリオペランドの EA で使う base/index。
    pub ea: u64,
    /// flags を書く。
    pub wflags: bool,
    /// flags を読む。
    pub rflags: bool,
    /// 条件分岐（P5 では flags を書く U 側とのペアが例外的に許される）。
    pub branch: bool,
    /// メモリオペランドを持つ。
    pub mem: bool,
    /// 接頭辞バイト数（66/67/seg/rep/lock）。
    pub prefixes: u8,
}

fn bit(g: Gpr) -> u64 {
    1u64 << g.0
}

const EAX: u64 = 1;
const ECX: u64 = 1 << 1;
const EDX: u64 = 1 << 2;
const EBX: u64 = 1 << 3;
const ESP: u64 = 1 << 4;

/// メモリ形 EA の base/index レジスタ集合。
fn ea_regs(d: &MapDec, mem: bool) -> u64 {
    if !mem {
        return 0;
    }
    let m = d.modrm >> 6;
    let rm = d.modrm & 7;
    let bb = ((d.rex & 1) << 3) | (((d.rex2 >> 4) & 1) << 4);
    let xb = (((d.rex >> 1) & 1) << 3) | (((d.rex2 >> 5) & 1) << 4);
    match d.asize {
        16 => {
            // a16: rm → base(+index)。mod=0 rm=6 は disp16 のみ。
            const T: [u64; 8] = [
                EBX | (1 << 6),
                EBX | (1 << 7),
                (1 << 5) | (1 << 6),
                (1 << 5) | (1 << 7),
                1 << 6,
                1 << 7,
                1 << 5,
                EBX,
            ];
            if m == 0 && rm == 6 { 0 } else { T[rm as usize] }
        }
        _ => {
            if rm == 4 && d.has_sib {
                let idx = (d.sib >> 3) & 7;
                let base = d.sib & 7;
                let mut r = 0;
                // index=100 はなし（REX.X/X4 があれば eSP/16+ になる）。
                if idx != 4 || xb != 0 {
                    r |= 1u64 << (idx | xb);
                }
                if !(m == 0 && base == 5) || bb != 0 {
                    r |= 1u64 << (base | bb);
                }
                r
            } else if m == 0 && rm == 5 && bb == 0 {
                0 // disp32 / RIP-relative
            } else {
                1u64 << (rm | bb)
            }
        }
    }
}

/// `MapDec` をタイミング属性へ分類。未採録命令は `None`。
/// `taken` は jcc/jcxz/loop 系の分岐成立を渡す（486 の成否別クロック）。
pub fn classify(d: &MapDec, taken: bool) -> Option<InsnTiming> {
    let name = INSNS[d.insn as usize].name;
    let (m, ops) = name.split_once('_').unwrap_or((name, ""));
    let t: Vec<&str> = ops.split('_').filter(|s| !s.is_empty()).collect();
    let t0 = t.first().copied().unwrap_or("");
    let t1 = t.get(1).copied().unwrap_or("");
    let t2 = t.get(2).copied().unwrap_or("");
    let mem = d.has_modrm && (d.modrm >> 6) != 3;
    let is_ea = |s: &str| matches!(s, "e" | "eb" | "ew" | "ed" | "ev" | "ep" | "m");
    let is_reg = |s: &str| s.starts_with('g');
    let is_imm = |s: &str| s.starts_with('i') || s == "jb" || s == "jz";
    let is_acc = |s: &str| matches!(s, "al" | "ax" | "eax");
    let rm_op = if mem {
        ea_regs(d, true)
    } else {
        bit(rm_reg(d))
    };
    let rg = bit(reg(d));
    let prefixes = u8::from(d.p66)
        + u8::from(d.p67)
        + u8::from(d.rep != 0)
        + u8::from(d.lock)
        + u8::from(d.seg != 0);
    // 即値+変位の同時存在は P5 でペア不可（PENTIUM: "not pairable if
    // there is a displacement and immediate"）。
    let disp_imm = mem && d.disp_bits > 0 && t.iter().any(|s| is_imm(s));
    let mut x = InsnTiming {
        c486: None,
        c5: None,
        pipe: Pipe::Np,
        uses: 0,
        defs: 0,
        ea: ea_regs(d, mem),
        wflags: false,
        rflags: false,
        branch: false,
        mem,
        prefixes,
    };
    let mm = mem as usize;
    // [reg 形, mem 形]
    macro_rules! xt {
        ($c486:expr, $c5:expr, $pipe:expr) => {{
            x.c486 = Some($c486[mm]);
            x.c5 = Some($c5[mm]);
            x.pipe = if disp_imm { Pipe::Np } else { $pipe };
        }};
    }
    match m {
        // ---- ALU2（CF 非参照）----
        "add" | "or" | "and" | "sub" | "xor" => {
            x.wflags = true;
            if is_ea(t0) && is_reg(t1) {
                x.uses = rm_op | rg;
                x.defs = if mem { 0 } else { rm_op };
                xt!([1, 3], [1, 3], Pipe::Uv);
            } else if is_reg(t0) && is_ea(t1) {
                x.uses = rm_op | rg;
                x.defs = rg;
                xt!([1, 2], [1, 2], Pipe::Uv);
            } else if is_ea(t0) && is_imm(t1) {
                x.uses = rm_op;
                x.defs = if mem { 0 } else { rm_op };
                xt!([1, 3], [1, 3], Pipe::Uv);
            } else if is_acc(t0) && is_imm(t1) {
                x.uses = EAX;
                x.defs = EAX;
                xt!([1, 1], [1, 1], Pipe::Uv);
            } else {
                return None;
            }
        }
        // ---- ALU2（CF 参照: P5 では PU、reg,mem 形は 4）----
        "adc" | "sbb" => {
            x.wflags = true;
            x.rflags = true;
            if is_ea(t0) && is_reg(t1) {
                x.uses = rm_op | rg;
                x.defs = if mem { 0 } else { rm_op };
                xt!([1, 3], [1, 3], Pipe::Pu);
            } else if is_reg(t0) && is_ea(t1) {
                x.uses = rm_op | rg;
                x.defs = rg;
                xt!([1, 2], [1, 4], Pipe::Pu);
            } else if is_ea(t0) && is_imm(t1) {
                x.uses = rm_op;
                x.defs = if mem { 0 } else { rm_op };
                xt!([1, 3], [1, 3], Pipe::Pu);
            } else if is_acc(t0) && is_imm(t1) {
                x.uses = EAX;
                x.defs = EAX;
                xt!([1, 1], [1, 1], Pipe::Pu);
            } else {
                return None;
            }
        }
        // ---- CMP/TEST（宛先なし。mem 形は RMW でないので 2）----
        "cmp" | "test" => {
            x.wflags = true;
            if is_ea(t0) && is_reg(t1) || is_reg(t0) && is_ea(t1) {
                x.uses = rm_op | rg;
                xt!([1, 2], [1, 2], Pipe::Uv);
            } else if is_ea(t0) && is_imm(t1) {
                x.uses = rm_op;
                xt!([1, 2], [1, 2], Pipe::Uv);
            } else if is_acc(t0) && is_imm(t1) {
                x.uses = EAX;
                xt!([1, 1], [1, 1], Pipe::Uv);
            } else {
                return None;
            }
        }
        "mov" => {
            if is_ea(t0) && is_reg(t1) {
                x.uses = rm_op | rg;
                xt!([1, 1], [1, 1], Pipe::Uv);
            } else if is_reg(t0) && is_ea(t1) {
                x.uses = rm_op;
                x.defs = rg;
                xt!([1, 1], [1, 1], Pipe::Uv);
            } else if is_ea(t0) && is_imm(t1) {
                x.uses = if mem { x.ea } else { 0 };
                x.defs = if mem { 0 } else { rm_op };
                xt!([1, 1], [1, 1], Pipe::Uv);
            } else if t0.starts_with('r') && is_imm(t1) {
                // mov_rv_iv / mov_rb_ib（+r 即値形）
                let rv = bit(op_reg(d));
                x.defs = rv;
                xt!([1, 1], [1, 1], Pipe::Uv);
            } else {
                return None; // sreg/moffs/特殊形
            }
        }
        "movzx" | "movsx" => {
            x.uses = rm_op;
            x.defs = rg;
            xt!([3, 3], [3, 3], Pipe::Np);
        }
        "xchg" => {
            if t0 == "rv" {
                // +r 形（0x90 は xchg eax,eax＝NOP 扱いしない）
                let rv = bit(op_reg(d));
                x.uses = rv | EAX;
                x.defs = rv | EAX;
                xt!([3, 3], [2, 2], Pipe::Np);
            } else {
                x.uses = rm_op | rg;
                x.defs = (if mem { 0 } else { rm_op }) | rg;
                xt!([3, 5], [3, 3], Pipe::Np);
            }
        }
        "inc" | "dec" => {
            x.wflags = true;
            if t0 == "rv" {
                let rv = bit(op_reg(d));
                x.uses = rv;
                x.defs = rv;
                xt!([1, 1], [1, 1], Pipe::Uv);
            } else {
                x.uses = rm_op;
                x.defs = if mem { 0 } else { rm_op };
                xt!([1, 3], [1, 3], Pipe::Uv);
            }
        }
        "neg" => {
            x.wflags = true;
            x.uses = rm_op;
            x.defs = if mem { 0 } else { rm_op };
            xt!([1, 3], [1, 3], Pipe::Np);
        }
        "not" => {
            x.uses = rm_op;
            x.defs = if mem { 0 } else { rm_op };
            xt!([1, 3], [1, 3], Pipe::Np);
        }
        "lea" => {
            if !mem {
                return None;
            }
            // LEA は D-cache を参照しないが EA 計算で AGI を受ける。
            x.uses = x.ea;
            x.mem = false;
            x.defs = rg;
            xt!([1, 1], [1, 1], Pipe::Uv);
        }
        "nop" => {
            xt!([1, 1], [1, 1], Pipe::Uv);
        }
        "xlat" => {
            x.uses = EAX | EBX;
            x.defs = EAX;
            xt!([4, 4], [4, 4], Pipe::Np);
        }
        "bswap" => {
            let rv = if t0 == "rv" { bit(op_reg(d)) } else { rm_op };
            x.uses = rv;
            x.defs = rv;
            xt!([1, 1], [1, 1], Pipe::Np);
        }
        "cbw" | "cwde" => {
            x.uses = EAX;
            x.defs = EAX;
            xt!([3, 3], [3, 3], Pipe::Np);
        }
        "cwd" | "cdq" => {
            x.uses = EAX;
            x.defs = EAX | EDX;
            xt!([2, 2], [2, 2], Pipe::Np);
        }
        "lahf" => {
            x.rflags = true;
            x.defs = EAX;
            xt!([2, 2], [2, 2], Pipe::Np);
        }
        "sahf" => {
            x.wflags = true;
            x.uses = EAX;
            xt!([3, 3], [2, 2], Pipe::Np);
        }
        "clc" | "stc" | "cld" | "std" | "cmc" => {
            x.wflags = true;
            xt!([2, 2], [2, 2], Pipe::Np);
        }
        // ---- シフト（grp2）----
        "rol" | "ror" | "rcl" | "rcr" | "shl" | "sal" | "shr" | "sar" => {
            x.wflags = true;
            x.uses = rm_op;
            x.defs = if mem { 0 } else { rm_op };
            x.rflags = matches!(m, "rcl" | "rcr"); // rcl/rcr は常に CF を通す
            if t1 == "cl" {
                x.uses |= ECX;
                xt!([2, 4], [4, 4], Pipe::Np);
            } else if matches!(m, "rcl" | "rcr") && d.imm_bits > 0 && d.imm != 1 {
                // rcl/rcr の imm>1 は NP（PU は by-1 のみ）
                xt!([2, 4], [4, 4], Pipe::Np);
            } else {
                // 1 または imm8
                xt!([2, 4], [1, 3], Pipe::Pu);
            }
        }
        "shld" | "shrd" => {
            x.wflags = true;
            x.uses = rm_op | rg;
            x.defs = if mem { 0 } else { rm_op };
            if t2 == "cl" {
                x.uses |= ECX;
                xt!([2, 3], [4, 5], Pipe::Np);
            } else {
                xt!([2, 3], [4, 4], Pipe::Np);
            }
        }
        // ---- BT 系 ----
        "bt" => {
            x.wflags = true;
            x.uses = rm_op | (if is_reg(t1) { rg } else { 0 });
            if mem {
                return None; // メモリ形は未採録
            }
            xt!([3, 0], [4, 0], Pipe::Np);
        }
        "bts" | "btr" | "btc" => {
            x.wflags = true;
            x.uses = rm_op | (if is_reg(t1) { rg } else { 0 });
            x.defs = rm_op;
            if mem {
                return None; // メモリ形は未採録
            }
            xt!([6, 0], [4, 0], Pipe::Np);
        }
        "cmpxchg" => {
            x.wflags = true;
            x.uses = rm_op | rg | EAX;
            x.defs = (if mem { 0 } else { rm_op }) | EAX;
            xt!([6, 7], [5, 6], Pipe::Np);
        }
        "xadd" => {
            x.wflags = true;
            x.uses = rm_op | rg;
            x.defs = (if mem { 0 } else { rm_op }) | rg;
            xt!([4, 7], [3, 4], Pipe::Np);
        }
        // ---- 乗除算 ----
        "mul" | "imul" if t1.is_empty() => {
            // F7 /4,/5 一被演算子形・imul_gv_ev 系は下で拾う
            x.wflags = true;
            x.uses = rm_op | EAX;
            x.defs = if t0 == "eb" { EAX } else { EAX | EDX };
            // 486: MUL/IMUL は値依存（13-42）→ c486 未採録。P5 は固定。
            x.c5 = Some(if t0 != "eb" && d.osize == 32 { 10 } else { 11 });
            x.pipe = Pipe::Np;
        }
        "div" | "idiv" if t1.is_empty() => {
            x.wflags = true;
            x.uses = rm_op | EAX | (if t0 == "eb" { 0 } else { EDX });
            x.defs = if t0 == "eb" { EAX } else { EAX | EDX };
            let i = if t0 == "eb" {
                0
            } else if d.osize == 16 {
                1
            } else {
                2
            };
            let (a, b) = if m == "div" {
                ([16u16, 24, 40], [17u16, 25, 41])
            } else {
                ([19u16, 27, 43], [22u16, 30, 46])
            };
            x.c486 = Some(a[i]);
            x.c5 = Some(b[i]);
            x.pipe = Pipe::Np;
        }
        "imul" => {
            // 2/3 被演算子形（0F AF・69・6B）
            x.wflags = true;
            x.uses = rm_op | if t2.is_empty() { rg } else { 0 };
            x.defs = rg;
            x.c5 = Some(10);
            x.pipe = Pipe::Np; // 486 は値依存
        }
        // ---- スタック ----
        "push" => {
            x.uses = ESP;
            x.defs = ESP;
            if t0 == "rv" {
                x.uses |= bit(op_reg(d));
                xt!([1, 1], [1, 1], Pipe::Uv);
            } else if is_ea(t0) {
                x.uses |= rm_op;
                // reg 直（mod=3）は "PUSH r"、mem 形のみ NP。
                x.c486 = Some(if mem { 4 } else { 1 });
                x.c5 = Some(if mem { 2 } else { 1 });
                x.pipe = if mem { Pipe::Np } else { Pipe::Uv };
            } else if is_imm(t0) {
                // imm（P5 表では NP）
                xt!([1, 1], [1, 1], Pipe::Np);
            } else {
                return None; // sreg
            }
        }
        "pop" => {
            x.uses = ESP;
            x.defs = ESP;
            if t0 == "rv" {
                x.defs |= bit(op_reg(d));
                xt!([1, 1], [1, 1], Pipe::Uv);
            } else if is_ea(t0) {
                x.defs |= if mem { 0 } else { rm_op };
                x.c486 = Some(if mem { 5 } else { 1 });
                x.c5 = Some(if mem { 3 } else { 1 });
                x.pipe = if mem { Pipe::Np } else { Pipe::Uv };
            } else {
                return None; // sreg
            }
        }
        "pusha" => {
            x.uses = ESP | 0xFF;
            x.defs = ESP;
            x.c486 = Some(11);
            x.c5 = Some(5);
            x.pipe = Pipe::Np;
        }
        "popa" => {
            x.uses = ESP;
            x.defs = ESP | 0xFF;
            x.c486 = Some(9);
            x.c5 = Some(5);
            x.pipe = Pipe::Np;
        }
        "pushf" => {
            x.uses = ESP;
            x.defs = ESP;
            x.c486 = Some(4);
            x.pipe = Pipe::Np;
        }
        "popf" => {
            x.uses = ESP;
            x.defs = ESP;
            x.c486 = Some(6);
            x.c5 = Some(6);
            x.pipe = Pipe::Np;
        }
        // ---- 制御移転 ----
        "call" => {
            x.uses = ESP;
            x.defs = ESP;
            if is_ea(t0) {
                x.uses |= rm_op;
                xt!([5, 5], [2, 4], Pipe::Np);
            } else {
                xt!([3, 3], [1, 1], Pipe::Pv);
            }
        }
        "ret" => {
            x.uses = ESP;
            x.defs = ESP;
            if t0 == "iw" {
                xt!([5, 5], [4, 4], Pipe::Np);
            } else {
                xt!([5, 5], [2, 2], Pipe::Np);
            }
        }
        "jmp" => {
            if is_ea(t0) {
                x.uses = rm_op;
                xt!([5, 5], [2, 2], Pipe::Np);
            } else {
                xt!([3, 3], [1, 1], Pipe::Pv);
            }
        }
        "jcxz" => {
            x.uses = ECX;
            x.branch = true;
            x.c486 = Some(if taken { 8 } else { 5 });
            x.pipe = Pipe::Np;
        }
        "loop" => {
            x.uses = ECX;
            x.defs = ECX;
            x.branch = true;
            x.c486 = Some(if taken { 7 } else { 6 });
            x.pipe = Pipe::Np;
        }
        "loope" | "loopne" => {
            x.uses = ECX;
            x.defs = ECX;
            x.rflags = true;
            x.branch = true;
            x.c486 = Some(if taken { 9 } else { 6 });
            x.pipe = Pipe::Np;
        }
        _ => {
            // jcc（ja/jae/jb/..._jb/_jz）
            if m.starts_with('j') && (t0 == "jb" || t0 == "jz") {
                x.rflags = true;
                x.branch = true;
                x.c486 = Some(if taken { 3 } else { 1 });
                x.c5 = Some(1);
                x.pipe = Pipe::Pv;
            } else {
                return None;
            }
        }
    }
    Some(x)
}

/// 80486 発行モデル。基本クロック + AGI + 接頭辞ペナルティ。
/// Ref: SPEC-X86-I486 — AGI は直前命令が書いた reg を EA が
/// 使うと +1 クロック。接頭辞は 1 バイトごとに +1 クロック。
#[derive(Default)]
pub struct I486 {
    /// 累積クロック。
    pub time: u64,
    prev_defs: u64,
}

impl I486 {
    pub fn new() -> Self {
        Self::default()
    }

    /// 1 命令進め、加算したクロックを返す。`x.c486` 必須。
    pub fn step(&mut self, x: &InsnTiming) -> u64 {
        let agi = u64::from(x.ea & self.prev_defs != 0);
        let c = u64::from(x.c486.expect("486 unclassified")) + agi + u64::from(x.prefixes);
        self.prev_defs = x.defs;
        self.time += c;
        c
    }
}

/// Pentium (P5) U/V パイプ発行モデル。
/// Ref: SPEC-X86-PENTIUM (241430 附属書のペアリング規則)
/// - U 側がペア可（UV/PU）かつ次命令が V 可（UV/PV）なら同時発行。
/// - RAW/WAW の reg 依存はペア禁止。ただし flags を書く U に続く
///   分岐（jcc）は例外的にペア可。
/// - 両方がメモリ参照し D-cache バンク（addr[4:2]）が衝突すれば
///   V は 1 クロック遅れる（ここでは非ペアとして扱う）。
/// - AGI（直前の書き込み先を EA が使う）は +1 クロック。
#[derive(Default)]
pub struct Pentium {
    /// 累積クロック。
    pub time: u64,
    u_slot: Option<InsnTiming>,
    u_addr: Option<u64>,
    last_defs: u64,
}

impl Pentium {
    pub fn new() -> Self {
        Self::default()
    }

    /// 1 命令供給し、この呼び出しで加算したクロックを返す。
    /// `addr` はメモリオペランドの実アドレス（バンク判定用、不要なら `None`）。
    pub fn step(&mut self, x: InsnTiming, addr: Option<u64>) -> u64 {
        let before = self.time;
        self.step_inner(x, addr);
        self.time - before
    }

    fn step_inner(&mut self, x: InsnTiming, addr: Option<u64>) {
        // AGI: 直前発行命令の書き込み先を EA が使うと 1 クロック遅延。
        if x.ea & self.last_defs != 0 {
            self.time += 1;
        }
        if let Some(u) = self.u_slot.take()
            && self.pairable(&u, &x)
        {
            // V に発行。ペアの消費は max(u, v)（U は支払い済み）。
            // D-cache バンク衝突なら V は 1 クロック遅れる。
            let bank = u64::from(u.mem && x.mem && self.bank_conflict(addr));
            let v = u64::from(x.c5.expect("P5 unclassified")) + bank;
            self.time += v.saturating_sub(u64::from(u.c5.expect("P5 unclassified")));
            self.last_defs = x.defs | u.defs;
            return;
        }
        // U 側に発行（コストは即時加算、次命令のペア機会を残す）。
        let cost = u64::from(x.c5.expect("P5 unclassified")) + u64::from(x.prefixes);
        self.time += cost;
        self.last_defs = x.defs;
        // ペア可（UV/PU）なら次命令の V 発行機会を残す。複数クロックの
        // U 側とも V は初クロックに並走する。
        if matches!(x.pipe, Pipe::Uv | Pipe::Pu) {
            self.u_slot = Some(x);
            self.u_addr = addr;
        }
    }

    /// 依存関係・パイプ属性上のペア可否。バンク衝突は `bank_conflict`
    /// で別途扱う（ペア自体は成立し V が 1 クロック遅れる）。
    fn pairable(&self, u: &InsnTiming, v: &InsnTiming) -> bool {
        if !matches!(v.pipe, Pipe::Uv | Pipe::Pv) {
            return false;
        }
        // 接頭辞付き命令は V パイプに入れない（近距離 jcc を除く）。
        if v.prefixes > 0 && !v.branch {
            return false;
        }
        // reg 依存（RAW/WAW）。flags 依存は分岐のみ免除。
        if (v.uses | v.ea) & u.defs != 0 || v.defs & u.defs != 0 {
            return false;
        }
        if v.rflags && u.wflags && !v.branch {
            return false;
        }
        true
    }

    /// 両方がメモリ参照し D-cache バンク（addr[4:2]）が衝突するか。
    fn bank_conflict(&self, v_addr: Option<u64>) -> bool {
        matches!((self.u_addr, v_addr), (Some(a), Some(b)) if (a >> 2) & 7 == (b >> 2) & 7)
    }
}
