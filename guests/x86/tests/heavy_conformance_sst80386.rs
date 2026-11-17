// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! sst-80386（SingleStepTests 80386、台帳 TEST-SINGLESTEP-80386）の MOO v1.1
//! 形式を `run_m16_ex`（モデル i386）で 1 命令ずつ実行し、最終の CPU 状態と
//! メモリを比較する（層5・conformance。ロードマップ S13-2）。
//!
//! データはリポジトリに含めない（`.testdata/sst-80386`、`.MOO.gz` を
//! 解凍した `.MOO`）。コーパスは 386EX（16 ビットバス）の実モード採取で、
//! プリフェッチキューとバスサイクルは比較しない。RM32 の未定義ビットは
//! 両側を覆って比較する。EXCP があるテストでは、例外時に積まれた
//! EFLAGS の双語を flags 用マスクで覆って比較する。
//!
//! MOO v1.1 の形式（チャンクはすべて 4B タグ + u32 長 + ペイロード）:
//!   'MOO ' + u32 長 + {u8 主版, u8 副版, 2B 予約, u32 テスト数, cpu(4B)}
//!   トップレベル: META / RM32（任意）/ TEST…
//!   TEST: u32 index + {NAME, BYTS, INIT, FINA, CYCL, EXCP, HASH}
//!   INIT/FINA: {RG32, RM32, EA32, RAM , QUEU}
//!   RG32/RM32: u32 ビットマスク + 立っているビット分の u32 値。
//!   RAM の要素: (u32 番地, u8 値)。残りのメモリは 0 で埋める。
//!   CYCL の要素は 15B。80386 のバス状態は IOR=2 / IOW=3、
//!   t_state は T1=1 / T2=2。BHE は pin_bitfield0 の bit1。
//!
//! レジスタの順序（ビットマスクの添字）: cr0,cr3,eax,ebx,ecx,edx,esi,
//! edi,ebp,esp,cs,ds,es,fs,gs,ss,eip,eflags,dr6,dr7 の 20 本。
//! cr0/cr3/dr6/dr7 はモデル化していないので比較しない。

use polyisa_cli::run_x86::{self, Outcome, TrapHandler, TrapOutcome};
use polyisa_engine::bare::BareEnv;
use polyisa_guest_x86::CpuState;
use polyisa_guest_x86::sem::{self, Gpr};
use polyisa_mem::{Access, Perms, VirtAddr};
use polyisa_sem::Backend as _;
use std::path::PathBuf;

const REG_NAMES: [&str; 20] = [
    "cr0", "cr3", "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "cs", "ds", "es", "fs",
    "gs", "ss", "eip", "eflags", "dr6", "dr7",
];
/// モデル化していないレジスタ（cr0/cr3/dr6/dr7）。比較から外す。
const UNMODELED: u32 = (1 << 0) | (1 << 1) | (1 << 18) | (1 << 19);

/// コーパス由来の既知の不一致テスト（ファイル名, テスト番号）。
const SKIP_TESTS: &[(&str, usize)] = &[
    // `repne outsd`。実バス記録では ds:esi = 0x106548..0x106748 の
    // 読み出しが 1 MiB で折り返され 0x6548..0x6748 に現れ、初期 RAM も
    // 折り返し先にしか置かれていない。同じファイル内の他の 124 件
    // （ds=0xffff 系を含む）は 1 MiB 超をそのまま読んでおり、コーパス
    // 全体で折り返すのはこの 1 件だけなので、採取時に A20 が
    // マスクされていた単発の環境異常とみなして除く。
    ("666F", 253),
];

#[derive(Default)]
struct Sst {
    name: String,
    regs: [u32; 20],
    ram: Vec<(u32, u8)>,
    fina_mask: u32,
    fina_regs: [u32; 20],
    fina_ram: Vec<(u32, u8)>,
    /// BYTS チャンクの命令バイト列。
    byts: Vec<u8>,
    /// CYCL の IOW 記録から取った期待されるポート書き込み。
    port_writes: Vec<(u16, u8)>,

    /// FINA の RM32。未定義ビットの位置を持つ（既定 0xFFFF_FFFF = 全定義）。
    rmsk: [u32; 20],
    /// TEST に RM32 チャンクがあったか。0xFFFF_FFFF というセンチネルでは
    /// 「マスク未掲載」と「全ビット定義の明示」を区別できないので別途持つ。
    has_rmsk: bool,
    /// EXCP の EFLAGS スタック番地（例外を起こしたテストだけ）。
    excp_flag_addr: Option<u32>,
}

impl Sst {
    fn new() -> Self {
        Self {
            rmsk: [0xFFFF_FFFF; 20],
            ..Self::default()
        }
    }
}

struct Rd<'a> {
    d: &'a [u8],
    p: usize,
}

impl<'a> Rd<'a> {
    fn new(d: &'a [u8]) -> Self {
        Self { d, p: 0 }
    }
    fn u8(&mut self) -> u8 {
        let v = self.d[self.p];
        self.p += 1;
        v
    }
    fn u32(&mut self) -> u32 {
        let v = u32::from_le_bytes(self.d[self.p..self.p + 4].try_into().unwrap());
        self.p += 4;
        v
    }
    fn tag(&mut self) -> [u8; 4] {
        let t: [u8; 4] = self.d[self.p..self.p + 4].try_into().unwrap();
        self.p += 4;
        t
    }
}

/// RG32/RM32 のビットマスク＋値列を読む。`dst[i]` にビット i の値を入れる。
/// 戻り値は FINA の RG32 用の立ちビット（他は既定のままにするため）。
fn read_masked32(rd: &mut Rd, end: usize, dst: &mut [u32; 20]) -> u32 {
    let mask = rd.u32();
    for (i, slot) in dst.iter_mut().enumerate() {
        if mask >> i & 1 != 0 {
            *slot = rd.u32();
        }
    }
    rd.p = end;
    mask
}

/// INIT/FINA の中身を読む。
fn read_state(rd: &mut Rd, end: usize, t: &mut Sst, fina: bool) {
    while rd.p < end {
        let stag = rd.tag();
        let send = rd.p + 4 + rd.u32() as usize;
        match &stag {
            b"RG32" => {
                let mask = if fina {
                    read_masked32(rd, send, &mut t.fina_regs)
                } else {
                    read_masked32(rd, send, &mut t.regs)
                };
                if fina {
                    t.fina_mask = mask;
                }
            }
            b"RM32" => {
                let mut m = [0xFFFF_FFFFu32; 20];
                read_masked32(rd, send, &mut m);
                t.rmsk = m;
                t.has_rmsk = true;
            }
            b"RAM " => {
                let n = rd.u32() as usize;
                for _ in 0..n {
                    let a = rd.u32();
                    let v = rd.u8();
                    if fina {
                        t.fina_ram.push((a, v));
                    } else {
                        t.ram.push((a, v));
                    }
                }
            }
            _ => {}
        }
        rd.p = send;
    }
    rd.p = end;
}

/// 'TEST' チャンク列を `tests` へ読む。戻り値はファイル全体の RM32。
fn parse(data: &[u8], max: usize, tests: &mut Vec<Sst>, file_rmsk: &mut [u32; 20]) {
    assert_eq!(&data[..4], b"MOO ");
    let mut rd = Rd::new(&data[8..]);
    let major = rd.u8();
    let minor = rd.u8();
    assert_eq!((major, minor), (1, 1), "MOO v1.1 だけを扱う");
    rd.u8();
    rd.u8(); // reserved
    let count = rd.u32() as usize;
    assert_eq!(&rd.tag(), b"386E");
    let mut seen = 0usize;
    while rd.p + 8 <= rd.d.len() && seen < count && tests.len() < max {
        let tag = rd.tag();
        let end = rd.p + 4 + rd.u32() as usize;
        match &tag {
            b"TEST" => {
                seen += 1;
                rd.u32(); // index
                let mut t = Sst::new();
                while rd.p < end {
                    let stag = rd.tag();
                    let send = rd.p + 4 + rd.u32() as usize;
                    match &stag {
                        b"NAME" => {
                            let n = rd.u32() as usize;
                            t.name = String::from_utf8_lossy(&rd.d[rd.p..rd.p + n]).into_owned();
                        }
                        b"BYTS" => {
                            let n = rd.u32() as usize;
                            t.byts = rd.d[rd.p..rd.p + n].to_vec();
                        }
                        b"INIT" => read_state(&mut rd, send, &mut t, false),
                        b"FINA" => read_state(&mut rd, send, &mut t, true),
                        b"CYCL" => {
                            // 80386 のバス状態: IOW=3。IOW のサイクルは
                            // address_latch がポート番地、data_bus が書き込み
                            // データを持つ（T2 レコードで確定。後続の Ti
                            // レコードは番地 0xFF_FFFF の残骸なので外す）。
                            // 有効レーンはポートの奇偶と BHE で決まる:
                            // 奇数ポートは上位レーン、偶数ポートで BHE 有効
                            // （pin0 bit1 = 0）は語転送で両レーン、BHE 無効
                            // は下位レーンのみ（SST 80386 実測）。
                            let n = rd.u32() as usize;
                            for _ in 0..n {
                                let e = &rd.d[rd.p..rd.p + 15];
                                let bus = e[11];
                                let t_state = e[12];
                                if bus == 3 && t_state == 2 {
                                    let port =
                                        u32::from_le_bytes(e[1..5].try_into().unwrap()) as u16;
                                    let data = u16::from_le_bytes(e[9..11].try_into().unwrap());
                                    let bhe = e[0] & 2 == 0;
                                    if port & 1 == 0 {
                                        t.port_writes.push((port, data as u8));
                                        if bhe {
                                            t.port_writes
                                                .push((port.wrapping_add(1), (data >> 8) as u8));
                                        }
                                    } else {
                                        t.port_writes.push((port, (data >> 8) as u8));
                                    }
                                }
                                rd.p += 15;
                            }
                        }
                        b"EXCP" => {
                            let _number = rd.u8();
                            t.excp_flag_addr = Some(rd.u32());
                        }
                        _ => {}
                    }
                    rd.p = send;
                }
                rd.p = end;
                tests.push(t);
            }
            // ファイル全体の RM32 は各テストの既定として適用する。
            b"RM32" => {
                let mut m = [0xFFFF_FFFFu32; 20];
                read_masked32(&mut rd, end, &mut m);
                *file_rmsk = m;
            }
            _ => {}
        }
        rd.p = end;
    }
}

fn get(env: &mut BareEnv, i: usize) -> u32 {
    match i {
        2 => env.backend.get(Gpr(0).state()),
        3 => env.backend.get(Gpr(3).state()),
        4 => env.backend.get(Gpr(1).state()),
        5 => env.backend.get(Gpr(2).state()),
        6 => env.backend.get(Gpr(6).state()),
        7 => env.backend.get(Gpr(7).state()),
        8 => env.backend.get(Gpr(5).state()),
        9 => env.backend.get(Gpr(4).state()),
        10 => u32::from(env.backend.get(sem::sreg_ref(1))),
        11 => u32::from(env.backend.get(sem::sreg_ref(3))),
        12 => u32::from(env.backend.get(sem::sreg_ref(0))),
        13 => u32::from(env.backend.get(sem::sreg_ref(4))),
        14 => u32::from(env.backend.get(sem::sreg_ref(5))),
        15 => u32::from(env.backend.get(sem::sreg_ref(2))),
        16 => env.backend.get(sem::eip_ref()),
        17 => env.backend.get(sem::eflags_ref()),
        _ => 0,
    }
}

fn set(env: &mut BareEnv, i: usize, v: u32) {
    match i {
        2 => env.backend.set(Gpr(0).state(), v),
        3 => env.backend.set(Gpr(3).state(), v),
        4 => env.backend.set(Gpr(1).state(), v),
        5 => env.backend.set(Gpr(2).state(), v),
        6 => env.backend.set(Gpr(6).state(), v),
        7 => env.backend.set(Gpr(7).state(), v),
        8 => env.backend.set(Gpr(5).state(), v),
        9 => env.backend.set(Gpr(4).state(), v),
        10 => env.backend.set(sem::sreg_ref(1), v as u16),
        11 => env.backend.set(sem::sreg_ref(3), v as u16),
        12 => env.backend.set(sem::sreg_ref(0), v as u16),
        13 => env.backend.set(sem::sreg_ref(4), v as u16),
        14 => env.backend.set(sem::sreg_ref(5), v as u16),
        15 => env.backend.set(sem::sreg_ref(2), v as u16),
        16 => env.backend.set(sem::eip_ref(), v),
        17 => env.backend.set(sem::eflags_ref(), v),
        _ => {}
    }
}

struct NoSys;
impl TrapHandler for NoSys {
    fn handle_trap(&mut self, _env: &mut BareEnv, _code: u32) -> TrapOutcome {
        TrapOutcome::Unimplemented
    }
}

/// 80386 の接頭辞（セグメント 6 種・操作数/番地幅・LOCK・REP）。
fn is_prefix(b: u8) -> bool {
    matches!(
        b,
        0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3
    )
}

/// ip が指すバイト列のオペコード位置（接頭辞を読み飛ばした先の番地）。
fn opaddr(env: &mut BareEnv, ip: u32) -> u32 {
    let cs = u64::from(env.backend.get(sem::sreg_ref(1)));
    let mut a = ((cs << 4) + u64::from(ip)) & env.backend.addr_mask;
    loop {
        let mut b = [0u8; 1];
        env.backend
            .mem
            .read(VirtAddr(a), &mut b, Access::DATA_LE)
            .unwrap();
        if !is_prefix(b[0]) {
            return a as u32;
        }
        a = (a + 1) & env.backend.addr_mask;
    }
}

fn byte_at(env: &mut BareEnv, a: u32) -> u8 {
    let mut b = [0u8; 1];
    env.backend
        .mem
        .read(VirtAddr(u64::from(a)), &mut b, Access::DATA_LE)
        .unwrap();
    b[0]
}

/// BYTS の先頭命令が制御移転（条件付きを含む）かどうか。
/// 移転先の最初のフェッチには終端用の HLT が注入される（コーパス規約）。
/// 条件分岐が不成立なら着地点は命令直後の HLT なので、どちらでも
/// 注入 HLT の実行で同じ結果になる。
fn is_flow(env: &mut BareEnv, ip: u32) -> bool {
    let a = opaddr(env, ip);
    let op = byte_at(env, a);
    let next = ((u64::from(a) + 1) & env.backend.addr_mask) as u32;
    match op {
        0x70..=0x7F
        | 0x9A
        | 0xC2
        | 0xC3
        | 0xCA
        | 0xCB
        | 0xCC
        | 0xCD
        | 0xCE
        | 0xCF
        | 0xE0..=0xE3
        | 0xE8
        | 0xE9
        | 0xEA
        | 0xEB
        | 0xF1 => true,
        // 0F マップでは 0x80-0x8F の Jcc 近距離が移転。
        0x0F => matches!(byte_at(env, next), 0x80..=0x8F),
        // FF の /2 call・/3 callf・/4 jmp・/5 jmpf。
        0xFF => matches!((byte_at(env, next) >> 3) & 7, 2..=5),
        _ => false,
    }
}

/// 注入 HALT を 1 発実行する。コーパスは制御移転・例外の後、飛び先の
/// 最初のコードフェッチに HLT を差し込む。メモリ上の値に関係なく F4 が
/// フェッチされるので、一時的に F4 を書いて実行してから戻す。
fn inject_hlt(
    env: &mut BareEnv,
    ip: u32,
    sys: &mut impl TrapHandler,
    feats: u64,
    params: &polyisa_guest_x86::Params,
) -> Outcome {
    let cs = u64::from(env.backend.get(sem::sreg_ref(1)));
    let a = ((cs << 4) + u64::from(ip)) & env.backend.addr_mask;
    let mut old = [0u8; 1];
    env.backend
        .mem
        .read(VirtAddr(a), &mut old, Access::DATA_LE)
        .unwrap();
    env.backend.mem.write(VirtAddr(a), &[0xF4]).unwrap();
    let out = run_x86::run_m16_ex(env, ip, sys, 1, feats, params);
    env.backend.mem.write(VirtAddr(a), &old).unwrap();
    out
}

/// 1 テストを実行して差分を返す（空なら一致）。
fn run_one(
    env: &mut BareEnv,
    t: &Sst,
    feats: u64,
    params: &polyisa_guest_x86::Params,
    f_umask: u16,
) -> Vec<String> {
    if std::env::var("POLYISA_SST_DUMP").is_ok() {
        eprintln!(
            "dump [{}] init={:08x?} fina_mask={:05x} fina={:08x?} rmsk={:08x?} ram={:x?} fram={:x?}",
            t.name, t.regs, t.fina_mask, t.fina_regs, t.rmsk, t.ram, t.fina_ram
        );
    }
    for &(a, v) in &t.ram {
        env.backend.mem.write(VirtAddr(u64::from(a)), &[v]).unwrap();
    }
    // テストリグのポートはほぼフローティングバス（0xFF）だが、
    // 0x22/0x23 には実デバイスがあり 0x7F/0x42 を返す（採取値で
    // 全 in テストと整合。SST 80386 実測）。
    env.backend.ports.fill(0xFF);
    env.backend.ports[0x22] = 0x7F;
    env.backend.ports[0x23] = 0x42;
    for (i, &v) in t.regs.iter().enumerate() {
        set(env, i, v);
    }
    let mut sys = NoSys;
    // コーパスは命令の後ろに終端用 HLT を 1 バイト置く（BYTS の末尾）。
    // 普通の命令は HLT を実行して止まる（IP は終端 HLT の後）。
    // 制御移転・例外では飛び先の最初のフェッチに HLT が注入される。
    let base_ip = t.regs[16];
    let byts_end = base_ip + t.byts.len() as u32;
    // REP 文字列命令は反復中に命令を再フェッチしない（実機では
    // プリフェッチ済みのデコードが反復全体に効く）。要素ストアが
    // 命令自身を上書きしても実行は元のバイトで続くので、同じ IP
    // に戻った反復では BYTS の命令分を書き戻す（末尾の HLT は
    // 除く）。
    let insn = &t.byts[..t.byts.len().saturating_sub(1)];
    let rep_str = insn.len() >= 2
        && insn[..insn.len() - 1]
            .iter()
            .any(|&b| b == 0xF2 || b == 0xF3)
        && insn
            .last()
            .is_some_and(|&op| matches!(op, 0xA4..=0xAF | 0x6C..=0x6F));
    let mut steps = 0u32;
    let mut prev_ip: Option<u32> = None;
    let mut self_ret = false;
    let mut out = Outcome::StepLimit { pc: 0 };
    loop {
        if !matches!(out, Outcome::StepLimit { .. }) || steps >= 0x1_0002 {
            break;
        }
        let ip = get(env, 16);
        if steps > 0 && !(base_ip..byts_end).contains(&ip) {
            // 制御移転・例外の着地点。注入された HLT を 1 発実行して終わる。
            out = inject_hlt(env, ip, &mut sys, feats, params);
            break;
        }
        // REP 文字列命令が命令外の番地へ進んだら、実行はそこで
        // 終わり（反復完了・例外とも）。次のフェッチには注入 HLT が
        // 差し込まれる。反復の格納が終端 HLT 自身を上書きしても
        // メモリの内容は見ない。
        if rep_str && steps > 0 && ip != base_ip {
            out = inject_hlt(env, ip, &mut sys, feats, params);
            break;
        }
        // 命令窓の退避。復元した命令バイトはフェッチにだけ見せたい
        // ので、ステップ後にデータへ戻す。
        let mut restore: Option<(u64, Vec<u8>)> = None;
        if rep_str && prev_ip == Some(ip) {
            let cs = u64::from(env.backend.get(sem::sreg_ref(1)));
            let pa = ((cs << 4) + u64::from(ip)) & env.backend.addr_mask;
            let mut saved = vec![0u8; insn.len()];
            env.backend
                .mem
                .read(VirtAddr(pa), &mut saved, Access::DATA_LE)
                .unwrap();
            for (k, &b) in insn.iter().enumerate() {
                env.backend
                    .mem
                    .write(VirtAddr(pa + k as u64), &[b])
                    .unwrap();
            }
            restore = Some((pa, saved));
        }
        // 自己参照（移転先が命令自身）は実機でも命令を再実行する
        // が（pop した IP が命令の EIP と一致する RET 等）、真の
        // 無限ループ（jmp $ 等）は進展しない。1 回の再実行だけを
        // 許し、さらに同じ IP に戻ったら注入 HLT で締める。
        if !rep_str && prev_ip == Some(ip) {
            if self_ret {
                out = inject_hlt(env, ip, &mut sys, feats, params);
                break;
            }
            self_ret = true;
        }
        let oa = opaddr(env, ip);
        let op = byte_at(env, oa);
        // 制御移転かどうかは実行前に判定する（far 移転で CS が
        // 変わると、実行後の走査は着地点を読んでしまう）。
        let flow = steps == 0 && is_flow(env, base_ip);
        out = run_x86::run_m16_ex(env, ip, &mut sys, 1, feats, params);
        steps += 1;
        prev_ip = Some(ip);
        // ステップで格納されなかった命令窓のバイトを実データに戻す
        // （格納が命令自身を上書きした分はそのまま残す）。
        // 既知の近似: 実行した命令が元の命令バイトと同じ値を窓内に
        // 書いた場合も退避値へ戻してしまう。コーパスでは該当なし。
        if let Some((pa, saved)) = restore {
            for (k, &b) in insn.iter().enumerate() {
                let cur = &mut [0u8];
                env.backend
                    .mem
                    .read(VirtAddr(pa + k as u64), cur, Access::DATA_LE)
                    .unwrap();
                if cur[0] == b {
                    env.backend
                        .mem
                        .write(VirtAddr(pa + k as u64), &[saved[k]])
                        .unwrap();
                }
            }
        }
        // HLT を実行したらその時点で終端（HALT で記録が終わる）。
        // フェッチ位置が CS 限界を越えていると F4 の実行自体が #GP に
        // なる（例外配送で eip が飛ぶ）ので、実行できた時だけ抜ける。
        if op == 0xF4 && get(env, 16) == ip.wrapping_add(1) {
            break;
        }
        // 制御移転は着地点に関係なく注入 HLT で締める（far 移転の
        // 着地点や条件分岐が BYTS 窓内に戻る場合を含む）。ただし
        // 命令自身へのリターン（pop した IP が命令の EIP と一致する
        // RET 等）は実機でも命令が再実行されるので再ステップする。
        if steps == 1 && flow && matches!(out, Outcome::StepLimit { .. }) && get(env, 16) != base_ip
        {
            let ip = get(env, 16);
            out = inject_hlt(env, ip, &mut sys, feats, params);
            break;
        }
    }
    let mut diffs = Vec::new();
    if !matches!(out, Outcome::StepLimit { .. }) {
        diffs.push(format!("outcome {out:?}"));
    }
    // FINA が空（RG32 マスク 0・RAM なし）のテストは、分岐先が命令
    // 自身に重なる自己参照移転で、コーパスが検証可能な最終状態を
    // 記録していない（バストレースのみ）。状態比較は行わない。
    let state_check = !(t.fina_mask == 0 && t.fina_ram.is_empty());
    for (i, name) in REG_NAMES.iter().enumerate() {
        if !state_check {
            break;
        }
        if UNMODELED >> i & 1 != 0 {
            continue;
        }
        let exp = if t.fina_mask >> i & 1 != 0 {
            t.fina_regs[i]
        } else {
            t.regs[i]
        };
        let mut m = t.rmsk[i];
        if i == 17 {
            // f_umask（コーパス CSV）: 下位 16 ビットの未定義フラグは比較しない。
            m &= 0xFFFF_0000 | u32::from(f_umask);
        }
        let got = get(env, i);
        if got & m != exp & m {
            diffs.push(format!(
                "{name}: exp {exp:08x} got {got:08x} (mask {m:08x})"
            ));
        }
    }
    // EXCP の EFLAGS 双語は flags 用マスクで覆う（未定義ビットのため）。
    let flag_addr = t.excp_flag_addr;
    let flags_mask = t.rmsk[17] & (0xFFFF_0000 | u32::from(f_umask));
    for &(a, v) in &t.fina_ram {
        let mut b = [0u8; 1];
        env.backend
            .mem
            .read(VirtAddr(u64::from(a)), &mut b, Access::DATA_LE)
            .unwrap();
        let mut got = b[0];
        let mut exp = v;
        if let Some(fa) = flag_addr
            && a >= fa
            && a < fa + 4
        {
            let shift = (a - fa) * 8;
            let m = (flags_mask >> shift) as u8;
            got &= m;
            exp &= m;
        }
        if got != exp {
            diffs.push(format!("mem {a:06x}: exp {v:02x} got {:02x}", b[0]));
        }
    }
    if std::env::var("POLYISA_SST_DUMP").is_ok() {
        eprintln!("ports exp={:x?}", t.port_writes);
    }
    // 同一ポートへの反復書き込みは最終値だけを比較する
    // （バックエンドはポートごとの最終値しか保持しない）。
    let mut last_writes: std::collections::BTreeMap<u16, u8> = std::collections::BTreeMap::new();
    for &(p, v) in &t.port_writes {
        last_writes.insert(p, v);
    }
    for (p, v) in last_writes {
        let got = env.backend.ports[usize::from(p)];
        if got != v {
            diffs.push(format!("port {p:04x}: exp {v:02x} got {got:02x}"));
        }
    }
    diffs
}

fn testdata() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.join(".testdata").join("sst-80386")
}

#[test]
fn sst80386_conformance() {
    let dir = testdata();
    if !dir.is_dir() {
        eprintln!("sst-80386 のデータがない。スキップ");
        return;
    }
    // 1 ファイルあたりの実行数。0 は全件。
    let max: usize = std::env::var("POLYISA_SST_MAX")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);
    let max = if max == 0 { usize::MAX } else { max };
    let only: Option<String> = std::env::var("POLYISA_SST_FILE").ok();

    // コーパスは 386EX で採取。D8-DF の ESC 命令はファイルにない。
    let feats = polyisa_guest_x86::model_feats("i386");
    let params = polyisa_guest_x86::model_params("i386");

    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    // 実アドレスは 24 ビットまで届く（386EX の採取範囲は 16 MiB）。
    env.backend.mem.map(VirtAddr(0), 4096, rwx).unwrap();

    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| {
            let n = e.unwrap().file_name().into_string().unwrap();
            n.strip_suffix(".MOO").map(str::to_owned)
        })
        .collect();
    names.sort();

    // コーパス CSV の f_umask（命令が未定義にするフラグの逆マスク）を
    // 読み込む。キーは (オペコード, グループ拡張)。
    let mut f_umask_map: std::collections::HashMap<(u16, Option<u8>), u16> =
        std::collections::HashMap::new();
    if let Ok(csv) = std::fs::read_to_string(dir.join("80386.csv")) {
        for line in csv.lines().skip(1) {
            let f: Vec<&str> = line.split(',').collect();
            if f.len() < 40 {
                continue;
            }
            let Ok(op) = u16::from_str_radix(f[0], 16) else {
                continue;
            };
            let ex = f[4].parse::<u8>().ok();
            let um = f[39]
                .trim()
                .strip_prefix("0x")
                .and_then(|s| u16::from_str_radix(s, 16).ok())
                .unwrap_or(0xFFFF);
            f_umask_map
                .entry((op, ex))
                .and_modify(|m| *m &= um)
                .or_insert(um);
        }
    }

    let mut total = 0usize;
    let mut failed_files = Vec::new();
    let only_set: Option<Vec<String>> = only.map(|f| f.split(',').map(str::to_owned).collect());
    for name in &names {
        if let Some(f) = &only_set
            && !f.iter().any(|x| x == name)
        {
            continue;
        }
        // ファイル名から (op, ex) を引く。先頭の 66/67/F2/F3 は接頭辞。
        let mut base = name.as_str();
        while base.len() > 2 && matches!(&base[..2], "66" | "67" | "F2" | "F3") {
            base = &base[2..];
        }
        let (op_s, ex_s) = base.split_once('.').unwrap_or((base, ""));
        let f_umask = u16::from_str_radix(op_s, 16)
            .ok()
            .map(|op| {
                let ex = ex_s.parse::<u8>().ok();
                f_umask_map
                    .get(&(op, ex))
                    .or_else(|| f_umask_map.get(&(op, None)))
                    .copied()
                    .unwrap_or(0xFFFF)
            })
            .unwrap_or(0xFFFF);
        let data = std::fs::read(dir.join(format!("{name}.MOO"))).unwrap();
        let mut tests = Vec::new();
        let mut file_rmsk = [0xFFFF_FFFFu32; 20];
        parse(&data, max, &mut tests, &mut file_rmsk);
        let mut diffs = 0usize;
        let mut touched: Vec<u32> = Vec::new();
        let n_tests = tests.len();
        for (i, t) in tests.iter_mut().enumerate() {
            // テスト側に RM32 がなければファイル共通のマスクを使う。
            if !t.has_rmsk {
                t.rmsk = file_rmsk;
            }
            if SKIP_TESTS.contains(&(name.as_str(), i)) {
                continue;
            }
            let d = run_one(&mut env, t, feats, &params, f_umask);
            total += 1;
            if !d.is_empty() {
                diffs += 1;
                if diffs <= 5 {
                    eprintln!("{name}#{i} [{}]: {}", t.name, d.join(", "));
                }
            }
            // このテストが触れた番地を 0 に戻す（次のテストの初期化）。
            for &(a, _) in t.ram.iter().chain(t.fina_ram.iter()) {
                touched.push(a);
            }
            if touched.len() > 4096 || i + 1 == n_tests {
                for &a in &touched {
                    env.backend.mem.write(VirtAddr(u64::from(a)), &[0]).unwrap();
                }
                touched.clear();
            }
        }
        if diffs > 0 {
            failed_files.push((name.clone(), diffs, tests.len()));
        }
    }
    eprintln!("total {total} tests");
    for (n, d, c) in &failed_files {
        eprintln!("  {n}: {d}/{c} diffs");
    }
    assert!(
        failed_files.is_empty(),
        "{} files with diffs",
        failed_files.len()
    );
}
