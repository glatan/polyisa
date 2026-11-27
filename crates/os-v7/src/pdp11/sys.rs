// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Unix V7 パーソナリティの実装。a.out の配置、初期スタック、
//! `trap` のシステムコール機械、ファイル系・`brk`・`exit`。
//!
//! プロセスはユーザーモードで走り、仮想アドレスは PAR/PDR を
//! 通る。PAR は仮想ページと同じ物理位置を指す（VA=PA の恒等
//! 写像）ので、パーソナリティがゲストの仮想アドレスをそのまま
//! 物理メモリにアクセスできる。
//!
//! 引数規約は `pdp11` モジュールの文書のとおり。`sys indir` の
//! テンプレはデータ空間にある —— 分離 I/D では D 空間側の語だが
//! VA=PA なので同じ読み方になる。
//! Ref: SPEC-UNIX-V7.
// 単一プロセス・root 模型の意図的な簡略化
// （fork なし・シグナル配送なし・特権系は EPERM）。

use std::collections::HashMap;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

use polyisa_engine::bare::BareEnv;
use polyisa_engine::run::{TrapHandler, TrapOutcome};
use polyisa_guest_pdp11::{mmu, psw, reg, sem};
use polyisa_loader::aout;
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};

use super::{SYSENT, errno, sig};

/// ユーザ空間の上端（64 KiB）。スタックはここから下へ育つ。
const USPACE_TOP: u64 = 0x1_0000;

/// a.out の magic 0407（impure。text+data が連続し全域書込可）。
const OMAGIC: u16 = aout::OMAGIC;
/// 0410（pure text。data は text 以降の 8 KiB 境界）。
const NMAGIC: u16 = aout::NMAGIC;
/// 0411（分離 I/D。data は D 空間の 0 から）。
const SEPMAGIC: u16 = aout::SEPMAGIC;

/// 0410 のデータ先頭に使う境界（PAR 粒度 = 8 KiB）。
const SEG_SIZE: u64 = 0o20000;

/// 物理メモリとして用意する量（VA=PA。64 KiB のユーザ空間の
/// 2 倍を写像して余裕を持たせる）。
const PHYS_MAP: u64 = 0x4_0000;

/// `write` 系で捕まえた標準出力と標準エラー、標準入力の供給列。
#[derive(Default)]
pub struct V7Io {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// 標準入力に返す列。`read(0)` はこれを `stdin_pos` から出す。
    pub stdin: Vec<u8>,
    /// `stdin` の消費済み先頭位置。
    pub stdin_pos: usize,
    /// fd 0-2 が close 済みか。V7 は fd を最小の空きから割る
    /// ので `close(0)` の次の `open` が fd 0 を返す —— 追跡が要る。
    pub closed: [bool; 3],
    /// stdio を複写した fd → 複写元の stdio 番号（`dup(1)` が
    /// fd 5 を返したとき 5→1。実体が置かれた fd ≤2 も入る）。
    alias: HashMap<u32, u32>,
}

/// ディレクトリ fd の合成内容（V7 の direct 項目列）と読み位置。
struct DirFd {
    ents: Vec<u8>,
    pos: u64,
    /// stat/fstat 用のホストパス。
    path: String,
}

/// パイプの読み側（`kernel::PipeTable` の id）。
struct PipeEnd {
    id: u64,
    read: bool,
}

/// Unix V7（PDP-11）の syscall 状態機械。
pub struct V7 {
    /// 標準入出力の capture。テストが読む。
    pub io: V7Io,
    /// ゲスト fd 3 以降のホストファイル表。
    fds: polyisa_kernel::FdTable,
    /// fd 0-2 に置かれたホストファイル（`close(0)` の後の
    /// `open` など。FdTable は fd 3 起点なので別に持つ）。
    low_files: [Option<std::fs::File>; 3],
    /// ディレクトリ fd の合成表。
    dirs: HashMap<u32, DirFd>,
    /// パイプ端の表。
    pipes: HashMap<u32, PipeEnd>,
    pipe_tab: polyisa_kernel::PipeTable,
    /// ゲストルートのホストパス。空はホストの `cwd` 起点。
    root: String,
    /// ゲストの作業ディレクトリ。
    cwd: String,
    /// プログラムブレーク（仮想アドレス）。
    brk: u16,
    /// データの先頭（brk の下限）。
    data_lo: u16,
    /// 0411 の分離 I/D。
    sep_id: bool,
    /// 0411 のデータが置かれた物理先頭（64B 単位の PAR 値）。
    /// D 空間 PAR の再配置ベースに使う。
    d_base_par: u16,
    /// 写像済みのスタック下端の PAR 番号（7 から下へ育つ）。
    stack_lo: u16,
    /// `signal` が記録した処置（番号→関数。0=DFL・1=IGN・他=関数）。
    sigact: [u16; 17],
    /// getpid が返す識別子。
    pid: u16,
    /// `umask` の現値。
    umask: u16,
    /// 一度だけ報告した未実装 syscall。
    reported: Vec<u8>,
}

impl Default for V7 {
    fn default() -> Self {
        Self::new("")
    }
}

/// dispatch の戻り。
#[derive(Debug)]
enum Disp {
    /// r0 に置く値（成功）。
    Ret(u16),
    /// r0・r1 に置く 2 語の値（r0 が上位語）。
    Ret2(u16, u16),
    /// errno で失敗。
    Fail(u16),
    /// プロセス終了。
    Exit(u32),
    /// スタック成長後の命令再試行。
    Retry,
}

impl V7 {
    /// パーソナリティを作る。`root` はゲストパスを引くホスト側の
    /// ルート（空ならルート閉じ込めなし）。
    #[must_use]
    pub fn new(root: &str) -> Self {
        Self {
            io: V7Io::default(),
            fds: polyisa_kernel::FdTable::default(),
            low_files: [None, None, None],
            dirs: HashMap::new(),
            pipes: HashMap::new(),
            pipe_tab: polyisa_kernel::PipeTable::default(),
            root: root.to_string(),
            cwd: "/".to_string(),
            brk: 0,
            data_lo: 0,
            sep_id: false,
            d_base_par: 0,
            stack_lo: 8,
            sigact: [0; 17],
            pid: 42,
            umask: 0o22,
            reported: Vec::new(),
        }
    }

    // ---- メモリアクセス ----
    // ユーザの仮想アドレスはモード 2（user）の APR を通して物理に
    // 写す。0411 ではデータ側が D 空間（別物理）・syscall の語
    // テンプレートが I 空間（テキスト側）と空間が分かれる。

    fn acc(kind: AccessKind) -> Access {
        Access {
            endian: Endian::Le,
            align: Align::Unaligned,
            kind,
        }
    }

    /// ユーザ APR（`sp` 空間）で VA を物理に写す。PDR の ACF が
    /// 実効アクセスを許さなければ None（wr は書き込み側の検査）。
    /// PAR が立たないページは未写像として None。
    fn pa_of(env: &BareEnv, sp: mmu::Space, va: u16, wr: bool) -> Option<u64> {
        let i = mmu::apr_idx(2, sp, va >> 13);
        let acf = Self::pdr_of(env, i) & mmu::pdr::ACF;
        let ok = if wr { acf == 6 } else { acf != 0 };
        if !ok {
            return None;
        }
        let par = u32::from(Self::par_of(env, i));
        Some(u64::from(
            (par + u32::from((va >> 6) & 0o177)) << 6 | u32::from(va & 0o77),
        ))
    }

    /// データ空間の VA→PA（0411 では D、それ以外は I —— ユーザの
    /// ポインタはすべてこちら側を指す）。
    fn dpa(&self, env: &BareEnv, va: u16, wr: bool) -> Option<u64> {
        let sp = if self.sep_id {
            mmu::Space::D
        } else {
            mmu::Space::I
        };
        Self::pa_of(env, sp, va, wr)
    }

    /// 命令空間の VA→PA（`sys` の語とその続きの引数語はテキスト
    /// 側にある —— 実機のカーネルも prev-I で読む）。
    fn ipa(env: &BareEnv, va: u16) -> Option<u64> {
        Self::pa_of(env, mmu::Space::I, va, false)
    }

    /// ユーザ・データ空間のワード読み出し。
    fn r16(&self, env: &BareEnv, va: u64) -> Option<u16> {
        let pa = self.dpa(env, va as u16, false)?;
        let mut b = [0u8; 2];
        env.backend
            .mem
            .read(VirtAddr(pa), &mut b, Self::acc(AccessKind::DataRead))
            .ok()?;
        Some(u16::from_le_bytes(b))
    }

    /// ユーザ・命令空間のワード読み出し（テンプレート用）。
    fn r16i(env: &BareEnv, va: u16) -> Option<u16> {
        let pa = Self::ipa(env, va)?;
        let mut b = [0u8; 2];
        env.backend
            .mem
            .read(VirtAddr(pa), &mut b, Self::acc(AccessKind::DataRead))
            .ok()?;
        Some(u16::from_le_bytes(b))
    }

    /// ユーザ・データ空間のワード書き込み。
    fn w16(&self, env: &mut BareEnv, va: u64, v: u16) -> bool {
        let Some(pa) = self.dpa(env, va as u16, true) else {
            return false;
        };
        env.backend
            .mem
            .write(VirtAddr(pa), &v.to_le_bytes())
            .is_ok()
    }

    /// 物理アドレスへの直接書き込み（イメージ・スタック構築用）。
    fn pw16(env: &mut BareEnv, pa: u64, v: u16) -> bool {
        env.backend
            .mem
            .write(VirtAddr(pa), &v.to_le_bytes())
            .is_ok()
    }

    /// ユーザ・データ空間のバイト列読み出し（PAR ブロック境界を
    /// またぐたびに変換し直す）。
    fn read_bytes(&self, env: &BareEnv, a: u64, n: usize) -> Result<Vec<u8>, u16> {
        let mut out = Vec::with_capacity(n);
        let mut va = a;
        let mut left = n;
        while left > 0 {
            let v = va as u16;
            let chunk = left.min(usize::from(0o100 - (v & 0o77)));
            let pa = self.dpa(env, v, false).ok_or(errno::EFAULT)?;
            let mut buf = vec![0u8; chunk];
            env.backend
                .mem
                .read(VirtAddr(pa), &mut buf, Self::acc(AccessKind::DataRead))
                .map_err(|_| errno::EFAULT)?;
            out.extend_from_slice(&buf);
            va += chunk as u64;
            left -= chunk;
        }
        Ok(out)
    }

    /// ユーザ・データ空間のバイト列書き込み。
    fn write_bytes(&self, env: &mut BareEnv, a: u64, data: &[u8]) -> Result<(), u16> {
        let mut va = a;
        let mut off = 0usize;
        while off < data.len() {
            let v = va as u16;
            let chunk = (data.len() - off).min(usize::from(0o100 - (v & 0o77)));
            let pa = self.dpa(env, v, true).ok_or(errno::EFAULT)?;
            env.backend
                .mem
                .write(VirtAddr(pa), &data[off..off + chunk])
                .map_err(|_| errno::EFAULT)?;
            va += chunk as u64;
            off += chunk;
        }
        Ok(())
    }

    fn read_cstr(&self, env: &BareEnv, a: u64) -> Result<String, u16> {
        let mut out = Vec::new();
        for i in 0..4096u64 {
            let v = a.wrapping_add(i) as u16;
            let pa = self.dpa(env, v, false).ok_or(errno::EFAULT)?;
            let mut b = [0u8; 1];
            if env
                .backend
                .mem
                .read(VirtAddr(pa), &mut b, Self::acc(AccessKind::DataRead))
                .is_err()
            {
                return Err(errno::EFAULT);
            }
            if b[0] == 0 {
                return String::from_utf8(out).map_err(|_| errno::EINVAL);
            }
            out.push(b[0]);
        }
        Err(errno::EINVAL)
    }

    // ---- パス解決（root 閉じ込め） ----

    fn resolve(&self, path: &str) -> Option<String> {
        let g = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("{}/{}", self.cwd.trim_end_matches('/'), path)
        };
        let mut segs: Vec<&str> = Vec::new();
        for s in g.split('/') {
            match s {
                "" | "." => {}
                ".." => {
                    // ルートの上の `..` はルートに留まる
                    // （Unix の `..` は / で飽和する）。
                    let _ = segs.pop();
                }
                _ => segs.push(s),
            }
        }
        let joined = segs.join("/");
        Some(if self.root.is_empty() {
            format!("/{joined}")
        } else {
            format!("{}/{joined}", self.root.trim_end_matches('/'))
        })
    }

    /// ゲストパスをホスト側に解決する（`open` 系の入口）。
    fn host_path(&self, env: &BareEnv, addr: u64) -> Result<String, u16> {
        let g = self.read_cstr(env, addr)?;
        self.resolve(&g).ok_or(errno::EACCES)
    }

    // ---- fd ----

    /// 次に使える fd。V7 は最小の空きを返す —— close 済みの
    /// stdio 番号も候補になる。NOFILE=15 の範囲内。
    fn alloc_fd(&mut self) -> Option<u32> {
        (0u32..15).find(|&fd| !self.fd_used(fd))
    }

    /// fd が使用中か（0-2 は stdio の開閉・実体の有無も見る）。
    fn fd_used(&self, fd: u32) -> bool {
        self.fds.ent(fd).is_some()
            || self.dirs.contains_key(&fd)
            || self.pipes.contains_key(&fd)
            || self.io.alias.contains_key(&fd)
            || match fd {
                0..=2 => self.low_files[fd as usize].is_some() || !self.io.closed[fd as usize],
                _ => false,
            }
    }

    /// fd に対応するホストファイル（0-2 なら low_files、それ
    /// 以降は FdTable）。
    fn file_for(&mut self, fd: u32) -> Option<&mut std::fs::File> {
        match fd {
            0..=2 => self.low_files[fd as usize].as_mut(),
            _ => self.fds.file_mut(fd),
        }
    }

    /// fd が指す stdio 番号。実体なしで stdio が有効なとき、
    /// または stdio を写した alias のときだけ Some（閉じた
    /// stdio・未使用の fd は None）。
    fn stdio_of(&self, fd: u32) -> Option<u32> {
        if let Some(&s) = self.io.alias.get(&fd) {
            return Some(s);
        }
        match fd {
            0..=2 if !self.io.closed[fd as usize] => Some(fd),
            _ => None,
        }
    }

    // ---- V7 struct stat（30 バイト） ----

    fn write_stat(&self, env: &mut BareEnv, md: &polyisa_host::Stat, buf: u64) -> Disp {
        let size = md.size.min(u64::from(u32::MAX)) as u32;
        let mut st = [0u8; 30];
        let mut w = |off: usize, v: u16| st[off..off + 2].copy_from_slice(&v.to_le_bytes());
        w(0, 1); // st_dev —— 単一の仮想ボリューム
        w(2, (md.ino & 0xffff) as u16);
        // V7 の st_mode 上位はホストの S_IFMT と同じ配置。
        w(4, (md.mode & 0o177777) as u16);
        w(6, md.nlink.min(0xffff) as u16);
        w(8, (md.uid & 0xffff) as u16);
        w(10, (md.gid & 0xffff) as u16);
        w(12, (md.rdev & 0xffff) as u16);
        // PDP-11 の long は上位語が先。
        w(14, (size >> 16) as u16);
        w(16, (size & 0xffff) as u16);
        w(18, (md.atime.max(0) as u32 >> 16) as u16);
        w(20, (md.atime.max(0) as u32 & 0xffff) as u16);
        w(22, (md.mtime.max(0) as u32 >> 16) as u16);
        w(24, (md.mtime.max(0) as u32 & 0xffff) as u16);
        w(26, (md.ctime.max(0) as u32 >> 16) as u16);
        w(28, (md.ctime.max(0) as u32 & 0xffff) as u16);
        match self.write_bytes(env, buf, &st) {
            Ok(()) => Disp::Ret(0),
            Err(e) => Disp::Fail(e),
        }
    }

    /// ディレクトリの V7 direct 項目列（{ino, name[14]}）を合成する。
    /// V7 のディレクトリは `.`・`..` を先頭に持つ。
    fn dir_ents(path: &str) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let mut dot = |ino: u64, name: &[u8]| {
            out.extend_from_slice(&(ino as u16).to_le_bytes());
            out.extend_from_slice(name);
            out.resize(out.len() + 14 - name.len(), 0);
        };
        let here = polyisa_host::stat(path).map(|s| s.ino).unwrap_or(0);
        dot(here, b".");
        // `..` の inode は親 —— ルートの親は自分。
        let parent = polyisa_host::stat(&format!("{path}/.."))
            .map(|s| s.ino)
            .unwrap_or(here);
        dot(parent, b"..");
        for e in std::fs::read_dir(path).ok()? {
            let e = e.ok()?;
            let ino = (polyisa_host::dirent_ino(&e) & 0xffff) as u16;
            let name = e.file_name().into_encoded_bytes();
            let name = &name[..name.len().min(14)];
            out.extend_from_slice(&ino.to_le_bytes());
            out.extend_from_slice(name);
            out.resize(out.len() + 14 - name.len(), 0);
        }
        Some(out)
    }

    // ---- syscall 実体 ----

    fn sys_read(&mut self, env: &mut BareEnv, a: &[u16]) -> Disp {
        // fd は r0、buf・count は u.u_arg。カーネルの getf は
        // fd を 077 で切り詰める。
        let (fd, buf, n) = (
            u32::from(sem::r_get(&env.backend, 0)) & 0o77,
            u64::from(a[0]),
            usize::from(a[1]),
        );
        // 無効 fd はバッファ検査より先（rdwr は getf → EBADF）。
        if !self.fd_used(fd) {
            return Disp::Fail(errno::EBADF);
        }
        // 実体（dir・パイプ・ファイル）を先に解決する —— close
        // 済みの stdio 番号にも open/dup で実体が乗りうる。
        if let Some(d) = self.dirs.get_mut(&fd) {
            let rest = &d.ents[d.pos.min(d.ents.len() as u64) as usize..];
            let got = rest.len().min(n);
            let rest = rest[..got].to_vec();
            if self.write_bytes(env, buf, &rest).is_err() {
                return Disp::Fail(errno::EFAULT);
            }
            self.dirs.get_mut(&fd).unwrap().pos += got as u64;
            return Disp::Ret(got as u16);
        }
        if let Some(p) = self.pipes.get(&fd) {
            if !p.read {
                return Disp::Fail(errno::EBADF);
            }
            let id = p.id;
            match self.pipe_tab.read(id, n) {
                polyisa_kernel::PipeRead::Bytes(data) => {
                    let k = data.len();
                    return if self.write_bytes(env, buf, &data).is_err() {
                        Disp::Fail(errno::EFAULT)
                    } else {
                        Disp::Ret(k as u16)
                    };
                }
                polyisa_kernel::PipeRead::Eof => return Disp::Ret(0),
                // 単一プロセスでは書き手のブロックが起きない
                // （Empty = 書き手が残りバッファ空 = この時点で
                // データを待つ余地がない → EOF と同じ 0 を返す
                // 近似。fork が入ったら Blocked に写す）。
                polyisa_kernel::PipeRead::Empty => return Disp::Ret(0),
            }
        }
        if let Some(f) = self.file_for(fd) {
            let mut tmp = vec![0u8; n.min(1 << 16)];
            return match f.read(&mut tmp) {
                Ok(got) => {
                    if self.write_bytes(env, buf, &tmp[..got]).is_err() {
                        Disp::Fail(errno::EFAULT)
                    } else {
                        Disp::Ret(got as u16)
                    }
                }
                Err(e) => Disp::Fail(host_err(e.raw_os_error())),
            };
        }
        // stdio（または stdio を写した fd）だけが残る。
        if self.stdio_of(fd) != Some(0) {
            return Disp::Fail(errno::EBADF);
        }
        // 標準入力は io.stdin から出す（テストの供給口）。
        let rest = &self.io.stdin[self.io.stdin_pos.min(self.io.stdin.len())..];
        let got = rest.len().min(n);
        if self.write_bytes(env, buf, &rest[..got]).is_err() {
            return Disp::Fail(errno::EFAULT);
        }
        self.io.stdin_pos += got;
        Disp::Ret(got as u16)
    }

    fn sys_write(&mut self, env: &mut BareEnv, a: &[u16]) -> Disp {
        let (fd, buf, n) = (
            u32::from(sem::r_get(&env.backend, 0)) & 0o77,
            u64::from(a[0]),
            usize::from(a[1]),
        );
        // 無効 fd はバッファ検査より先（rdwr は getf → EBADF）。
        if !self.fd_used(fd) {
            return Disp::Fail(errno::EBADF);
        }
        let data = match self.read_bytes(env, buf, n) {
            Ok(d) => d,
            Err(e) => return Disp::Fail(e),
        };
        if let Some(p) = self.pipes.get(&fd) {
            if p.read {
                return Disp::Fail(errno::EBADF);
            }
            return match self.pipe_tab.write_unbounded(p.id, &data) {
                Some(k) => Disp::Ret(k as u16),
                None => Disp::Fail(errno::EPIPE),
            };
        }
        if self.dirs.contains_key(&fd) {
            return Disp::Fail(errno::EBADF);
        }
        if let Some(f) = self.file_for(fd) {
            return match f.write_all(&data) {
                Ok(()) => Disp::Ret(n as u16),
                Err(e) => Disp::Fail(host_err(e.raw_os_error())),
            };
        }
        match self.stdio_of(fd) {
            Some(1) => {
                self.io.stdout.extend_from_slice(&data);
                let _ = std::io::stdout().write_all(&data);
                Disp::Ret(n as u16)
            }
            Some(2) => {
                self.io.stderr.extend_from_slice(&data);
                let _ = std::io::stderr().write_all(&data);
                Disp::Ret(n as u16)
            }
            _ => Disp::Fail(errno::EBADF),
        }
    }

    /// exec(name, argp) / exece(name, argp, envp)。成功したら戻ら
    /// ない —— アドレス空間を組み替えてエントリへ跳ぶ。fd・シグ
    /// ナル処置のうち IGN は持ち越す（捕捉設定は DFL に戻す）。
    /// envp の語は読むだけ（V7 の environ は crt0 側の仕事）。
    fn sys_exec(&mut self, env: &mut BareEnv, a: &[u16]) -> Disp {
        let path = match self.host_path(env, u64::from(a[0])) {
            Ok(p) => p,
            Err(e) => return Disp::Fail(e),
        };
        // argp が指す char *argv[]（NULL 終端）を読む。上限は
        // 暴走防止だけ —— カーネルは NULL まで読み切る。
        let mut argv: Vec<String> = Vec::new();
        for i in 0..2048u64 {
            let Some(p) = self.r16(env, u64::from(a[1]) + 2 * i) else {
                return Disp::Fail(errno::EFAULT);
            };
            if p == 0 {
                break;
            }
            match self.read_cstr(env, u64::from(p)) {
                Ok(s) => argv.push(s),
                Err(e) => return Disp::Fail(e),
            }
        }
        // 実行ビットが無ければ EACCES（V7 の exec と同じ検査）。
        match polyisa_host::stat(&path) {
            Ok(m) if m.mode & 0o111 != 0 => {}
            Ok(_) => return Disp::Fail(errno::EACCES),
            Err(e) => return Disp::Fail(host_err(e.raw_os_error())),
        }
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => return Disp::Fail(host_err(e.raw_os_error())),
        };
        // 形式の検査は差し替え前に済ませる（壊した空間のまま
        // 死ぬのは V7 どおりだが、起こし得る失敗は先に弾く）。
        if aout::parse(&bytes, aout::Arch::Pdp11).is_err() {
            return Disp::Fail(errno::ENOEXEC);
        }
        if argv.is_empty() {
            // argv[0] の既定は呼ばれたプログラム名（ゲスト側の
            // 文字列 —— 解決済みのホストパスを見せない）。
            argv.push(self.read_cstr(env, u64::from(a[0])).unwrap_or_default());
        }
        // 既存の空間を外して組み替え直す。ユーザ APR・MMR を
        // 全消去してから load_exec に張り直させる。
        env.backend
            .mem
            .unmap(VirtAddr(0), PHYS_MAP / polyisa_mem::PAGE_SIZE);
        for p in 0..8u16 {
            for sp in [mmu::Space::I, mmu::Space::D] {
                mmu::apr_put(&mut env.backend, mmu::apr_idx(2, sp, p), 0, 0);
            }
        }
        mmu::mmr_put(&mut env.backend, 0, 0);
        mmu::mmr_put(&mut env.backend, 1, 0);
        mmu::mmr_put(&mut env.backend, 2, 0);
        mmu::mmr_put(&mut env.backend, 3, 0);
        match self.load_exec(env, &bytes, &argv) {
            Ok(entry) => {
                // 捕捉されたシグナル処置は exec で DFL に戻る
                // （IGN は残る）。
                for s in &mut self.sigact {
                    if *s > 1 {
                        *s = 0;
                    }
                }
                let e = u64::from(entry);
                env.pc = e;
                sem::r_set(&mut env.backend, reg::PC as u8, entry);
                Disp::Ret(0)
            }
            Err(_) => Disp::Fail(errno::ENOEXEC),
        }
    }

    fn sys_open(&mut self, env: &BareEnv, a: &[u16], creat: bool) -> Disp {
        let path = match self.host_path(env, u64::from(a[0])) {
            Ok(p) => p,
            Err(e) => return Disp::Fail(e),
        };
        let mode = if creat { 1 } else { a[1] };
        let Some(fd) = self.alloc_fd() else {
            return Disp::Fail(errno::EMFILE);
        };
        // creat の mode は新規作成時だけ効く（既存の truncate
        // では許可ビットを変えない）。
        let existed = polyisa_host::stat(&path).is_ok();
        // V7: 0=read・1=write・2=read+write。カーネルの open1 は
        // fmode & 3 に切り詰める —— 3 以上は EINVAL ではなく 2。
        let mut o = std::fs::OpenOptions::new();
        match mode & 3 {
            0 => {
                o.read(true);
            }
            1 => {
                o.write(true);
            }
            2 => {
                o.read(true).write(true);
            }
            _ => unreachable!(),
        }
        if creat {
            o.create(true).truncate(true);
        }
        if std::fs::metadata(&path)
            .map(|m| m.is_dir())
            .unwrap_or(false)
        {
            // V7 ではディレクトリも普通に open して read する。
            if mode != 0 {
                return Disp::Fail(errno::EISDIR);
            }
            let Some(ents) = Self::dir_ents(&path) else {
                return Disp::Fail(errno::EIO);
            };
            self.dirs.insert(fd, DirFd { ents, pos: 0, path });
            return Disp::Ret(fd as u16);
        }
        match o.open(&path) {
            Ok(f) => {
                if fd <= 2 {
                    self.low_files[fd as usize] = Some(f);
                } else {
                    self.fds.place_close(fd, polyisa_kernel::FdTarget::File(f));
                }
                if creat && !existed {
                    let perm = u32::from(a[1]) & 0o777 & !u32::from(self.umask);
                    let _ = polyisa_host::chmod(&path, perm);
                }
                Disp::Ret(fd as u16)
            }
            Err(e) => Disp::Fail(host_err(e.raw_os_error())),
        }
    }

    fn sys_close(&mut self, env: &BareEnv, a: &[u16]) -> Disp {
        let _ = a;
        let fd = u32::from(sem::r_get(&env.backend, 0));
        if !self.fd_used(fd) {
            return Disp::Fail(errno::EBADF);
        }
        self.fds.clear(fd);
        self.dirs.remove(&fd);
        if let Some(p) = self.pipes.remove(&fd) {
            self.pipe_tab.close(p.id, p.read);
        }
        self.io.alias.remove(&fd);
        if fd <= 2 {
            self.low_files[fd as usize] = None;
            self.io.closed[fd as usize] = true;
        }
        Disp::Ret(0)
    }

    fn sys_seek(&mut self, env: &mut BareEnv, a: &[u16]) -> Disp {
        let fd = u32::from(sem::r_get(&env.backend, 0)) & 0o77;
        // PDP-11 の long は上位語が先。下位語は符号拡張しない
        // （0x8000 超の正の変位を負にしない）。
        let off = (i32::from(a[0] as i16) << 16) | i32::from(a[1]);
        let whence = a[2];
        if let Some(d) = self.dirs.get_mut(&fd) {
            let base: i64 = match whence {
                0 => 0,
                1 => i64::try_from(d.pos).unwrap_or(0),
                2 => i64::try_from(d.ents.len()).unwrap_or(0),
                _ => return Disp::Fail(errno::EINVAL),
            };
            let np = base + i64::from(off);
            if !(0..=i64::try_from(d.ents.len()).unwrap_or(0)).contains(&np) {
                return Disp::Fail(errno::EINVAL);
            }
            d.pos = np as u64;
            return Disp::Ret2((np >> 16) as u16, (np & 0xffff) as u16);
        }
        let Some(f) = self.file_for(fd) else {
            return if self.fd_used(fd) {
                Disp::Fail(errno::ESPIPE)
            } else {
                Disp::Fail(errno::EBADF)
            };
        };
        let pos = match whence {
            0 => SeekFrom::Start(off.max(0) as u64),
            1 => SeekFrom::Current(i64::from(off)),
            2 => SeekFrom::End(i64::from(off)),
            _ => return Disp::Fail(errno::EINVAL),
        };
        match f.seek(pos) {
            Ok(np) => Disp::Ret2((np >> 16) as u16, (np & 0xffff) as u16),
            Err(_) => Disp::Fail(errno::EIO),
        }
    }

    fn sys_sbreak(&mut self, env: &mut BareEnv, a: &[u16]) -> Disp {
        // 上限はスタック下端、下限はデータ先頭（カーネルは下限
        // 未満を 0 サイズに飽和させる —— 失敗ではなく丸める）。
        let new = a[0].max(self.data_lo);
        if u64::from(new) >= u64::from(self.stack_lo) << 13 {
            return Disp::Fail(errno::ENOMEM);
        }
        // 新しく写像が要るページを有効にする（データ側の PAR を
        // 延ばす —— VA=PA、物理は全面写像済み）。
        let top_page = u64::from(new.saturating_sub(1)) >> 13;
        let space = if self.sep_id {
            mmu::Space::D
        } else {
            mmu::Space::I
        };
        let d_first = self.data_lo >> 13;
        for p in d_first..=top_page as u16 {
            let i = mmu::apr_idx(2, space, p);
            // 未写像のページにだけ PAR/PDR を立てる（書き込み可・全域）。
            if Self::pdr_of(env, i) & mmu::pdr::ACF == 0 {
                let par = self
                    .d_base_par
                    .wrapping_add(p.wrapping_sub(d_first).wrapping_mul(0o200));
                mmu::apr_put(&mut env.backend, i, par, pdr_rw_full());
            }
        }
        self.brk = new;
        Disp::Ret(0)
    }

    /// APR 添字 i の PAR を読む（CpuState の par 配列）。
    fn par_of(env: &BareEnv, i: usize) -> u16 {
        let off = core::mem::offset_of!(polyisa_guest_pdp11::CpuState, par) + i * 2;
        u16::from_le_bytes([env.backend.state[off], env.backend.state[off + 1]])
    }

    /// APR 添字 i の PDR を読む（CpuState の pdr 配列）。
    fn pdr_of(env: &BareEnv, i: usize) -> u16 {
        // par/pdr は CpuState のフィールド —— mmu::apr_put と同じ
        // 添字規則で state を直接読む。
        let off = core::mem::offset_of!(polyisa_guest_pdp11::CpuState, pdr) + i * 2;
        u16::from_le_bytes([env.backend.state[off], env.backend.state[off + 1]])
    }

    fn sys_stat(&mut self, env: &mut BareEnv, a: &[u16], fstat: bool) -> Disp {
        // stat: uarg=[name,buf]。fstat: fd は r0 で uarg=[buf]。
        let buf = u64::from(a[usize::from(!fstat)]);
        let md = if fstat {
            let fd = u32::from(sem::r_get(&env.backend, 0)) & 0o77;
            if let Some(d) = self.dirs.get(&fd) {
                match polyisa_host::stat(&d.path) {
                    Ok(m) => m,
                    Err(_) => return Disp::Fail(errno::EIO),
                }
            } else {
                match self.file_for(fd).map(|f| polyisa_host::fstat(f)) {
                    Some(Ok(m)) => m,
                    Some(Err(_)) => return Disp::Fail(errno::EIO),
                    None => {
                        // stdio はキャラクタデバイスとして報告しない
                        // （ENOTTY 側へ寄せる —— /dev/null 相当の
                        // 最小属性）。閉じた番号は EBADF。
                        if !self.fd_used(fd) {
                            return Disp::Fail(errno::EBADF);
                        }
                        match polyisa_host::stat("/dev/null") {
                            Ok(m) => m,
                            Err(_) => return Disp::Fail(errno::EBADF),
                        }
                    }
                }
            }
        } else {
            let path = match self.host_path(env, u64::from(a[0])) {
                Ok(p) => p,
                Err(e) => return Disp::Fail(e),
            };
            match polyisa_host::stat(&path) {
                Ok(m) => m,
                Err(e) => return Disp::Fail(host_err(e.raw_os_error())),
            }
        };
        self.write_stat(env, &md, buf)
    }

    fn sys_pipe(&mut self, env: &mut BareEnv, a: &[u16]) -> Disp {
        let _ = a;
        let _ = env;
        let r = self.alloc_fd().filter(|&f| !self.fd_used(f));
        let Some(r) = r else {
            return Disp::Fail(errno::EMFILE);
        };
        // 読み側を先に確保してから書き側の fd を探す。
        self.pipes.insert(r, PipeEnd { id: 0, read: true });
        let w = (r + 1..15).find(|&f| !self.fd_used(f));
        let Some(w) = w else {
            self.pipes.remove(&r);
            return Disp::Fail(errno::EMFILE);
        };
        // `open` は読み端・書き端を 1 つずつ持つので数の調整は不要。
        let id = self.pipe_tab.open();
        self.pipes.get_mut(&r).unwrap().id = id;
        self.pipes.insert(w, PipeEnd { id, read: false });
        // 結果は r0=読み側・r1=書き側（スタブが呼出し側の配列に
        // 書き戻す）。
        Disp::Ret2(r as u16, w as u16)
    }

    fn sys_signal(&mut self, a: &[u16]) -> Disp {
        let s = a[0] as usize;
        // V7: 0・NSIG 以上・SIGKILL は EINVAL。
        if s == 0 || s >= self.sigact.len() || s == usize::from(sig::KILL) {
            return Disp::Fail(errno::EINVAL);
        }
        let old = self.sigact[s];
        self.sigact[s] = a[1];
        Disp::Ret(old)
    }

    /// シグナルによる終了。V7 の wait 状態（低位 = 番号、0200 = コア）。
    fn die(s: u8) -> Disp {
        Disp::Exit(u32::from(s) | sig::CORE)
    }

    /// MMU fault の処理。ユーザーモードの PL/NR fault で、
    /// フォールトページが現スタック下端より下かつヒープより上なら
    /// スタック PAR を下へ伸ばして再試行する。それ以外は SIGSEGV。
    fn mm_fault(&mut self, env: &mut BareEnv) -> Disp {
        let b = &mut env.backend;
        let m0 = mmu::mmr_val(b, 0);
        let err = m0 & mmu::mmr0::FREEZE;
        // MMR0<6:1> は {mode<6:5>, ds<4>, page<3:1>} の並び ——
        // page だけ取るには下位 3 桁を拾う。
        let page = (m0 >> 1) & 0o7;
        let mode = (m0 >> 5) & 0o3;
        let ds = (m0 >> 4) & 1 != 0;
        // MMR0 の凍結桁を戻す（エラーの記録を残し、凍結だけ解く）。
        mmu::mmr_put(b, 0, m0 & !(mmu::mmr0::FREEZE | mmu::mmr0::TRAP));
        let can_grow = mode == psw::USER
            && err & (mmu::mmr0::NR | mmu::mmr0::PL) != 0
            // スタックが住む空間の fault だけを成長させる（0411
            // の I 空間 fault で D 頁を育てても再 fault する）。
            && ds == self.sep_id
            && page < self.stack_lo
            && u64::from(page) << 13 >= u64::from(self.brk);
        if !can_grow {
            return Self::die(sig::SEGV);
        }
        let space = if self.sep_id {
            mmu::Space::D
        } else {
            mmu::Space::I
        };
        for p in page..self.stack_lo {
            let i = mmu::apr_idx(2, space, p);
            mmu::apr_put(b, i, p.wrapping_mul(0o200), pdr_rw_full());
        }
        self.stack_lo = page;
        // 命令の途中で変わったレジスタ（オート増減）を戻してから
        // やり直す（GAP-0085(f) の実装）。
        mmu::reg_unwind(b);
        Disp::Retry
    }
}

/// 書き込み可・全域有効の PDR（ACF=6・PLF=127・ED なし）。
fn pdr_rw_full() -> u16 {
    0o177 << mmu::pdr::PLF_V | 6
}

/// ホスト errno を V7 errno に写す。
fn host_err(e: Option<i32>) -> u16 {
    match e.unwrap_or(errno::EIO as i32) {
        1 => errno::EPERM,
        2 => errno::ENOENT,
        3 => errno::ESRCH,
        4 => errno::EINTR,
        5 => errno::EIO,
        9 => errno::EBADF,
        11 => errno::EAGAIN,
        12 => errno::ENOMEM,
        13 => errno::EACCES,
        14 => errno::EFAULT,
        16 => errno::EBUSY,
        17 => errno::EEXIST,
        18 => errno::EXDEV,
        19 => errno::ENODEV,
        20 => errno::ENOTDIR,
        21 => errno::EISDIR,
        22 => errno::EINVAL,
        23 | 24 => errno::EMFILE,
        25 => errno::ENOTTY,
        27 => errno::EFBIG,
        28 => errno::ENOSPC,
        29 => errno::ESPIPE,
        30 => errno::EROFS,
        31 => errno::EMLINK,
        32 => errno::EPIPE,
        _ => errno::EIO,
    }
}

/// トレースの出力口（環境変数で有効化）。
fn trace() -> bool {
    std::env::var_os("POLYISA_V7_TRACE").is_some()
}

impl V7 {
    /// syscall 番号を拾って引数を取り出し、実体に振り分ける。
    /// `pc` は trap の次の語（`handle_trap` の env.pc）。
    fn dispatch(&mut self, env: &mut BareEnv, pc: u16) -> Disp {
        let Some(w) = Self::r16i(env, pc.wrapping_sub(2)) else {
            return Disp::Fail(errno::EFAULT);
        };
        // 番号は trap の語の下位 6 桁（カーネルの &077 と同じ）。
        let n = usize::from(w & 0o77);
        let Some(ent) = SYSENT.get(n) else {
            return Disp::Fail(errno::EINVAL);
        };
        // `u.u_arg[]` は `sys` の語の後に続く語 —— 直接形では
        // trap の次の語、indir ではテンプレの `sys n` の次の語。
        // レジスタ引数（fd の r0・dup の r1 等）はここに入らず、
        // 実装が `r_get` で読む。
        let mut args = [0u16; 8];
        let n = if n == 0 {
            // indir: 次の語はテンプレを指す。
            let Some(ptr) = Self::r16i(env, pc) else {
                return Disp::Fail(errno::EFAULT);
            };
            let Some(w2) = self.r16(env, u64::from(ptr)) else {
                return Disp::Fail(errno::EFAULT);
            };
            // テンプレの先頭語は `sys n`（01044nn）でなければ
            // ならない —— 違う形はカーネルでは 077（nosys）に
            // 化けて SIGSYS で死ぬ。
            let n2 = if w2 & !0o77 == 0o104400 {
                usize::from(w2 & 0o77)
            } else {
                63
            };
            let ent2 = SYSENT.get(n2);
            let Some(ent2) = ent2 else {
                return Disp::Fail(errno::EINVAL);
            };
            for i in 0..usize::from(ent2.args.min(8)) {
                let Some(v) = self.r16(env, u64::from(ptr.wrapping_add(2 + 2 * i as u16))) else {
                    return Disp::Fail(errno::EFAULT);
                };
                args[i] = v;
            }
            // ポインタ語を飛び越して次の命令へ。
            let np = pc.wrapping_add(2);
            sem::r_set(&mut env.backend, reg::PC as u8, np);
            env.pc = u64::from(np);
            n2
        } else {
            // 直接形: 引数語は trap の次の語に続く（V6 系の
            // `sys n; args` 形 —— V7 の libc スタブは使わないが
            // 手書きコードでは現れる）。
            let inline = usize::from(ent.args.min(8));
            for (i, a) in args.iter_mut().enumerate().take(inline) {
                let Some(v) = Self::r16i(env, pc.wrapping_add(2 * i as u16)) else {
                    return Disp::Fail(errno::EFAULT);
                };
                *a = v;
            }
            if inline > 0 {
                let np = pc.wrapping_add(2 * inline as u16);
                sem::r_set(&mut env.backend, reg::PC as u8, np);
                env.pc = u64::from(np);
            }
            n
        };
        let ent = SYSENT[n];
        if trace() {
            eprintln!(
                "v7 sys {}({:?})",
                ent.name,
                &args[..usize::from(ent.args).min(8)]
            );
        }
        let disp = match n {
            // exit: {1,1} —— 状態は r0。
            1 => Disp::Exit(u32::from(sem::r_get(&env.backend, 0)) & 0o377),
            // fork: 単一プロセス模型 —— V7 の「プロセスが作れない」
            // 側の errno（EAGAIN = no more processes）。
            2 => Disp::Fail(errno::EAGAIN),
            3 => self.sys_read(env, &args),
            4 => self.sys_write(env, &args),
            5 => self.sys_open(env, &args, false),
            6 => self.sys_close(env, &args),
            7 => Disp::Fail(errno::ECHILD),
            8 => self.sys_open(env, &args, true),
            9 => {
                let from = match self.host_path(env, u64::from(args[0])) {
                    Ok(p) => p,
                    Err(e) => return Disp::Fail(e),
                };
                let to = match self.host_path(env, u64::from(args[1])) {
                    Ok(p) => p,
                    Err(e) => return Disp::Fail(e),
                };
                match std::fs::hard_link(&from, &to) {
                    Ok(()) => Disp::Ret(0),
                    Err(e) => Disp::Fail(host_err(e.raw_os_error())),
                }
            }
            10 => {
                let path = match self.host_path(env, u64::from(args[0])) {
                    Ok(p) => p,
                    Err(e) => return Disp::Fail(e),
                };
                // V7 の unlink はディレクトリに EPERM。
                if std::fs::metadata(&path)
                    .map(|m| m.is_dir())
                    .unwrap_or(false)
                {
                    return Disp::Fail(errno::EPERM);
                }
                match std::fs::remove_file(&path) {
                    Ok(()) => Disp::Ret(0),
                    Err(e) => Disp::Fail(host_err(e.raw_os_error())),
                }
            }
            11 | 59 => self.sys_exec(env, &args),
            12 => {
                let path = match self.host_path(env, u64::from(args[0])) {
                    Ok(p) => p,
                    Err(e) => return Disp::Fail(e),
                };
                match std::fs::metadata(&path) {
                    Ok(m) if m.is_dir() => {
                        let g = self
                            .read_cstr(env, u64::from(args[0]))
                            .unwrap_or_else(|_| "/".into());
                        self.cwd = if g.starts_with('/') {
                            g
                        } else {
                            format!("{}/{}", self.cwd.trim_end_matches('/'), g)
                        };
                        Disp::Ret(0)
                    }
                    Ok(_) => Disp::Fail(errno::ENOTDIR),
                    Err(e) => Disp::Fail(host_err(e.raw_os_error())),
                }
            }
            13 => {
                let t = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as u32)
                    .unwrap_or(0);
                Disp::Ret2((t >> 16) as u16, (t & 0xffff) as u16)
            }
            15 => {
                let path = match self.host_path(env, u64::from(args[0])) {
                    Ok(p) => p,
                    Err(e) => return Disp::Fail(e),
                };
                match polyisa_host::chmod(&path, u32::from(args[1])) {
                    Ok(()) => Disp::Ret(0),
                    Err(e) => Disp::Fail(host_err(e.raw_os_error())),
                }
            }
            16 => {
                // chown: 実行はホストの権限内。root モデルでは
                // 成功扱い（ホスト側の chown は権限が要る）。
                // 存在の検査はする（V7 と同じ ENOENT）。
                let path = match self.host_path(env, u64::from(args[0])) {
                    Ok(p) => p,
                    Err(e) => return Disp::Fail(e),
                };
                match polyisa_host::stat(&path) {
                    Ok(_) => Disp::Ret(0),
                    Err(e) => Disp::Fail(host_err(e.raw_os_error())),
                }
            }
            // mknod: デバイスノードはホスト権限外 —— 通常ファイル
            // （型桁 0）だけ作り、残りは V7 の EPERM。
            14 => {
                let path = match self.host_path(env, u64::from(args[0])) {
                    Ok(p) => p,
                    Err(e) => return Disp::Fail(e),
                };
                if args[1] & 0o170000 != 0 {
                    return Disp::Fail(errno::EPERM);
                }
                match std::fs::File::create(&path) {
                    Ok(_) => Disp::Ret(0),
                    Err(e) => Disp::Fail(host_err(e.raw_os_error())),
                }
            }
            17 => self.sys_sbreak(env, &args),
            18 => self.sys_stat(env, &args, false),
            19 => self.sys_seek(env, &args),
            20 => Disp::Ret(self.pid),
            // mount/umount/ptrace/profil/acct/phys/lock/mpx —— 特権
            // または模型の外。V7 は非特権に EPERM を返す。
            21 | 22 | 26 | 44 | 51 | 52 | 53 | 56 => Disp::Fail(errno::EPERM),
            // 実表は nullsys（静かに成功）—— nosys ではない。
            38 | 39 => Disp::Ret(0),
            // pause: シグナル配送経路がないためシグナルは来ない ——
            // 唯一の定義済み戻りである EINTR を返す。
            29 => Disp::Fail(errno::EINTR),
            23 | 46 => Disp::Ret(0), // setuid/setgid —— root モデル
            24 => Disp::Ret2(0, 0),  // getuid —— root モデル
            25 => Disp::Ret(0),      // stime —— 時計は書かない
            27 => Disp::Ret(0),      // alarm —— タイマなし
            28 => self.sys_stat(env, &args, true),
            30 => {
                // utime: 時刻更新は省略。存在の検査はする。
                let path = match self.host_path(env, u64::from(args[0])) {
                    Ok(p) => p,
                    Err(e) => return Disp::Fail(e),
                };
                match polyisa_host::stat(&path) {
                    Ok(_) => Disp::Ret(0),
                    Err(e) => Disp::Fail(host_err(e.raw_os_error())),
                }
            }
            33 => {
                // access(path, mode): R_OK=4・W_OK=2・X_OK=1。V7 は
                // ルートでも X_OK に実行ビットを要求する。
                let path = match self.host_path(env, u64::from(args[0])) {
                    Ok(p) => p,
                    Err(e) => return Disp::Fail(e),
                };
                match polyisa_host::stat(&path) {
                    Ok(md) => {
                        if args[1] & 1 != 0 && md.mode & 0o111 == 0 {
                            Disp::Fail(errno::EACCES)
                        } else {
                            Disp::Ret(0)
                        }
                    }
                    Err(e) => Disp::Fail(host_err(e.raw_os_error())),
                }
            }
            34 => Disp::Ret(0), // nice
            35 => {
                // ftime: struct timeb {time(4)・millitm(2)・timezone(2)・dstflag(2)}
                let tp = u64::from(args[0]);
                let t = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                let sec = t.as_secs() as u32;
                let ok = self.w16(env, tp, (sec >> 16) as u16)
                    && self.w16(env, tp + 2, (sec & 0xffff) as u16)
                    && self.w16(env, tp + 4, (t.subsec_millis()) as u16)
                    && self.w16(env, tp + 6, 0)
                    && self.w16(env, tp + 8, 0);
                if ok {
                    Disp::Ret(0)
                } else {
                    Disp::Fail(errno::EFAULT)
                }
            }
            36 => Disp::Ret(0), // sync
            37 => {
                // kill(pid, sig): {2,1} —— pid は r0、sig は
                // u.u_arg[1]（args[0]）。自プロセスへの配送のみ。
                // V7 は sig の範囲を対象プロセスの照合の中で見る
                // —— 対象なしは sig に関係なく ESRCH が先。
                let pid = u32::from(sem::r_get(&env.backend, 0));
                if pid != u32::from(self.pid) && pid != 0 {
                    return Disp::Fail(errno::ESRCH);
                }
                let s = args[0];
                if s >= 17 {
                    return Disp::Fail(errno::EINVAL);
                }
                if s == 0 {
                    // sig=0 は存在確認 —— 対象があれば成功。
                    return Disp::Ret(0);
                }
                match self.sigact[s as usize] {
                    // SIG_IGN は無効化 —— 落とさない。
                    1 => Disp::Ret(0),
                    // DFL・ハンドラ設定済み —— ハンドラ配送は
                    // OS4 の範囲で、現状は既定動作どおり終了。
                    _ => Self::die(s as u8),
                }
            }
            40 => {
                // tell: fd は r0（getf どおり 077 で切り詰める）。
                let fd = u32::from(sem::r_get(&env.backend, 0)) & 0o77;
                if let Some(d) = self.dirs.get(&fd) {
                    let p = d.pos;
                    return Disp::Ret2((p >> 16) as u16, (p & 0xffff) as u16);
                }
                match self.file_for(fd).map(|f| f.stream_position()) {
                    Some(Ok(p)) => Disp::Ret2((p >> 16) as u16, (p & 0xffff) as u16),
                    Some(Err(_)) => Disp::Fail(errno::EIO),
                    None => {
                        if self.fd_used(fd) {
                            Disp::Fail(errno::ESPIPE)
                        } else {
                            Disp::Fail(errno::EBADF)
                        }
                    }
                }
            }
            41 => {
                // dup(fdes[, fdes2]): {2,2} —— fdes は r0、fdes2
                // は r1。fdes の上位桁（0100）が立つときだけ dup2
                // で、コピー先は fdes2 が指定する番号。
                let coded = u32::from(sem::r_get(&env.backend, 0));
                let fd = coded & 0o77;
                if !self.fd_used(fd) {
                    return Disp::Fail(errno::EBADF);
                }
                let nf = if coded & 0o100 != 0 {
                    let fd2 = u32::from(sem::r_get(&env.backend, 1));
                    if fd2 >= 15 {
                        return Disp::Fail(errno::EBADF);
                    }
                    if fd2 != fd {
                        // 先送り先が開いていれば閉じる（V7 の
                        // dup2 相当の動作）。
                        self.dirs.remove(&fd2);
                        if let Some(p) = self.pipes.remove(&fd2) {
                            self.pipe_tab.close(p.id, p.read);
                        }
                        self.fds.clear(fd2);
                        self.io.alias.remove(&fd2);
                        if fd2 <= 2 {
                            self.low_files[fd2 as usize] = None;
                            self.io.closed[fd2 as usize] = true;
                        }
                    }
                    fd2
                } else {
                    match self.alloc_fd() {
                        Some(f) => f,
                        None => return Disp::Fail(errno::EMFILE),
                    }
                };
                if nf == fd {
                    return Disp::Ret(nf as u16);
                }
                if let Some(d) = self.dirs.get(&fd) {
                    // ディレクトリの dup は同じ項目列を別位置で持つ
                    // （V7 の実装も別の open file description になる）。
                    let nd = DirFd {
                        ents: d.ents.clone(),
                        pos: 0,
                        path: d.path.clone(),
                    };
                    self.dirs.insert(nf, nd);
                    return Disp::Ret(nf as u16);
                }
                if let Some(p) = self.pipes.get(&fd) {
                    let (id, read) = (p.id, p.read);
                    self.pipe_tab.dup(id, read);
                    self.pipes.insert(nf, PipeEnd { id, read });
                    return Disp::Ret(nf as u16);
                }
                if let Some(f) = self.file_for(fd) {
                    return match f.try_clone() {
                        Ok(n) => {
                            if nf <= 2 {
                                self.low_files[nf as usize] = Some(n);
                            } else {
                                self.fds.place_close(nf, polyisa_kernel::FdTarget::File(n));
                            }
                            Disp::Ret(nf as u16)
                        }
                        Err(_) => Disp::Fail(errno::EIO),
                    };
                }
                // 複写元が stdio —— alias を張って stdio 側へ
                // 写す（実体ファイルはないので記録で足す）。
                let s = self.io.alias.get(&fd).copied().unwrap_or(fd);
                if s > 2 {
                    return Disp::Fail(errno::EBADF);
                }
                self.io.alias.insert(nf, s);
                Disp::Ret(nf as u16)
            }
            42 => self.sys_pipe(env, &args),
            43 => {
                // times(buf): tms の 4 語（long ×4）は使わない 0 で埋める。
                let buf = u64::from(args[0]);
                let ok = (0..8).all(|i| self.w16(env, buf + 2 * i, 0));
                if ok {
                    Disp::Ret(0)
                } else {
                    Disp::Fail(errno::EFAULT)
                }
            }
            47 => Disp::Ret2(0, 0), // getgid —— root モデル
            48 => self.sys_signal(&args),
            54 => Disp::Fail(errno::ENOTTY), // ioctl —— tty なし
            31 | 32 => Disp::Fail(errno::ENOTTY), // stty/gtty —— tty なし
            60 => {
                let old = self.umask;
                self.umask = args[0] & 0o777;
                Disp::Ret(old)
            }
            61 => {
                // chroot: ルートを張り替える（resolve は `..` を
                // ルートで飽和させるので閉じ込めは保たれる）。
                let path = match self.host_path(env, u64::from(args[0])) {
                    Ok(p) => p,
                    Err(e) => return Disp::Fail(e),
                };
                match std::fs::metadata(&path) {
                    Ok(m) if m.is_dir() => {
                        self.root = path;
                        self.cwd = "/".to_string();
                        Disp::Ret(0)
                    }
                    Ok(_) => Disp::Fail(errno::ENOTDIR),
                    Err(e) => Disp::Fail(host_err(e.raw_os_error())),
                }
            }
            _ => {
                if !self.reported.contains(&(n as u8)) {
                    self.reported.push(n as u8);
                    eprintln!("v7: 未実装の syscall {}（{}）", n, ent.name);
                }
                Self::die(sig::SYS)
            }
        };
        // 失敗・終了だけを補足する（成功の戻りは遡る必要がない）。
        if trace() && matches!(disp, Disp::Fail(_) | Disp::Exit(_)) {
            eprintln!("v7 -> {disp:?}");
        }
        disp
    }
}

impl V7 {
    /// a.out を読み、プロセスの仮想アドレス空間・MMU・初期
    /// スタックを組み立てて、エントリポイントを返す。
    ///
    /// 配置（Ref: SPEC-UNIX-V7 §5 a.out）:
    /// - 0407: text @0・data が text に連続、全域 R/W
    /// - 0410: text @0（RO）・data @text 以降の 8 KiB 境界（R/W）
    /// - 0411: text @0 I 空間・data @0 D 空間
    ///
    /// bss は零埋め済み（疎メモリ）、brk は data+bss の終端。
    /// スタックはユーザ空間上端に文字列を置き、
    /// [argc][argv][0][envp][0] のポインタ表を組む —— V7 の
    /// exec が積む形（crt0 が sp から読む）。
    /// ユーザーモードの PAR は仮想ページと同じ物理位置を指す
    /// 恒等写像にする。
    pub fn load_exec(
        &mut self,
        env: &mut BareEnv,
        bytes: &[u8],
        argv: &[String],
    ) -> Result<u16, String> {
        let h = aout::parse(bytes, aout::Arch::Pdp11).map_err(|e| format!("a.out: {e:?}"))?;
        if h.magic == aout::ZMAGIC {
            return Err("PDP-11 には ZMAGIC はない".to_string());
        }
        let text = h.text as usize;
        let data = h.data as usize;
        let hdr = h.hdr_len as usize;
        let text_bytes = bytes
            .get(hdr..hdr + text)
            .ok_or_else(|| "a.out: text が切れている".to_string())?;
        let data_bytes = bytes
            .get(hdr + text..hdr + text + data)
            .ok_or_else(|| "a.out: data が切れている".to_string())?;
        if h.entry >= USPACE_TOP {
            return Err("entry がユーザ空間を外れる".to_string());
        }

        // 物理メモリ（VA=PA）。全域 RWX —— 権限の強制は PAR/PDR 側。
        let perms = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend
            .mem
            .map(VirtAddr(0), PHYS_MAP / polyisa_mem::PAGE_SIZE, perms)
            .map_err(|e| format!("mem: {e:?}"))?;

        let b = &mut env.backend;
        let sep = h.magic == SEPMAGIC;
        self.sep_id = sep;
        // text は vaddr 0。data のユーザ側 vaddr は magic で決まる。
        let data_va: u64 = match h.magic {
            OMAGIC => h.text,
            NMAGIC => h.text.next_multiple_of(SEG_SIZE),
            SEPMAGIC => 0,
            _ => unreachable!(),
        };
        // 物理上のデータ先頭。0411 は D 空間が別物理 —— テキストの
        // 直後（PAR 粒度の 64B 境界）に置き、ユーザ D PAR で
        // D VA 0 に再配置する。それ以外は VA=PA の恒等。
        let d_phys = if sep {
            h.text.next_multiple_of(0o100)
        } else {
            data_va
        };
        let d_first_par = (data_va >> 13) as u16;
        // d_base_par = データ最初頁の PAR。0411 は別物理、
        // それ以外は VA=PA 恒等（data_va が頁内にずれていても
        // PAR は頁頭の物理 —— 0407 の非頁整列で誤差が出る）。
        self.d_base_par = if sep {
            (d_phys >> 6) as u16
        } else {
            d_first_par * 0o200
        };
        let bss_lo = data_va + h.data;
        self.data_lo = data_va as u16;
        self.brk = (bss_lo + h.bss) as u16;
        if bss_lo + h.bss >= USPACE_TOP {
            return Err("data+bss がユーザ空間を超える".to_string());
        }

        // 内容の配置（物理 = 仮想）。
        b.mem
            .write(VirtAddr(0), text_bytes)
            .map_err(|e| format!("text: {e:?}"))?;
        b.mem
            .write(VirtAddr(d_phys), data_bytes)
            .map_err(|e| format!("data: {e:?}"))?;

        // PAR/PDR: テキストのページ（0410/0411 は RO）とデータ
        // 側のページ（RW）をユーザーモードに立てる。
        let t_pages = h.text.div_ceil(SEG_SIZE) as u16;
        let t_pdr = if h.magic == OMAGIC {
            pdr_rw_full()
        } else {
            0o177 << mmu::pdr::PLF_V | 2 // RO
        };
        for p in 0..t_pages {
            mmu::apr_put(b, mmu::apr_idx(2, mmu::Space::I, p), p * 0o200, t_pdr);
        }
        let (d_va, d_space) = if sep {
            (0u64, mmu::Space::D)
        } else {
            (data_va, mmu::Space::I)
        };
        let d_first = (d_va >> 13) as u16;
        let d_last = ((bss_lo + h.bss + SEG_SIZE - 1) >> 13) as u16;
        for p in d_first..d_last.max(d_first) {
            // PAR = データ最初頁の PAR + データ起点からの頁距離
            // （0411 は d_base_par=別物理・d_first=0、その他は
            // 恒等で p*0o200）。
            let par = self.d_base_par.wrapping_add((p - d_first) * 0o200);
            mmu::apr_put(b, mmu::apr_idx(2, d_space, p), par, pdr_rw_full());
        }

        // 初期スタック: 文字列を上端から下へ、続いてポインタ表。
        // envp は空（V7 の exec は env なしでも組める）。
        let mut sp: u64 = USPACE_TOP;
        let mut strs: Vec<u16> = Vec::new();
        {
            let bb = &mut env.backend;
            for a in argv.iter().rev() {
                // crt0 が `clr -2(r0)`（argv0 の語の手前を消す）を
                // 打つ —— 各文字列の先頭を偶数に揃える。
                sp = (sp - a.len() as u64 - 1) & !1;
                bb.mem
                    .write(VirtAddr(sp), a.as_bytes())
                    .map_err(|e| format!("argv: {e:?}"))?;
                strs.push(sp as u16);
            }
            strs.reverse();
        }
        sp &= !1;
        // envp の終端 0、envp なし、argv の終端 0、argv、argc。
        sp -= 2;
        Self::pw16(env, sp, 0); // envp 終端
        sp -= 2;
        Self::pw16(env, sp, 0); // argv 終端
        for a in strs.iter().rev() {
            sp -= 2;
            Self::pw16(env, sp, *a);
        }
        sp -= 2;
        Self::pw16(env, sp, strs.len() as u16);

        // スタックの PAR: 上端 8 KiB のページ（page 7）を有効に
        // する。下端への成長は fault 駆動。
        self.stack_lo = 7;
        mmu::apr_put(
            &mut env.backend,
            mmu::apr_idx(2, d_space, 7),
            7 * 0o200,
            pdr_rw_full(),
        );

        // レジスタと PSW: r0-r5 = 0、r6 = sp、r7 = entry。
        // cur=prv=user、pri=0。
        for i in 0..6u8 {
            sem::r_set(&mut env.backend, i, 0);
        }
        sem::r_set(&mut env.backend, reg::SP as u8, sp as u16);
        sem::r_set(&mut env.backend, reg::PC as u8, h.entry as u16);
        sem::psw_put(
            &mut env.backend,
            psw::USER << psw::CUR_MOD | psw::USER << psw::PRV_MOD,
        );
        // MMU を有効にする。0411 はユーザの D 空間を許可。
        mmu::mmr_put(&mut env.backend, 3, if sep { mmu::mmr3::UDS } else { 0 });
        mmu::mmr_put(&mut env.backend, 0, mmu::mmr0::ENABLE);
        Ok(h.entry as u16)
    }
}

impl TrapHandler for V7 {
    fn handle_trap(&mut self, env: &mut BareEnv, code: u32) -> TrapOutcome {
        let vec = code as u16;
        if trace() && vec != sem::tv::TRAP {
            eprintln!(
                "v7 trap vec={vec:o} pc={:o} r6={:o} mmr0={:o} mmr2={:o} mmr3={:o}",
                env.pc,
                sem::r_get(&env.backend, reg::SP as u8),
                mmu::mmr_val(&env.backend, 0),
                mmu::mmr_val(&env.backend, 2),
                mmu::mmr_val(&env.backend, 3),
            );
            for i in 0..8 {
                eprint!("r{i}={:o} ", sem::r_get(&env.backend, i));
            }
            eprintln!("psw={:o}", sem::psw_get(&env.backend));
        }
        let disp = match vec {
            sem::tv::TRAP => self.dispatch(env, env.pc as u16),
            sem::tv::MMU => self.mm_fault(env),
            sem::tv::BPT => Self::die(sig::TRACE),
            sem::tv::IOT => Self::die(sig::IOT),
            sem::tv::EMT => Self::die(sig::EMT),
            sem::tv::BUS => Self::die(sig::BUS),
            sem::tv::ILL => Self::die(sig::ILL),
            sem::tv::FPP => Self::die(sig::FPE),
            _ => return TrapOutcome::Unimplemented,
        };
        match disp {
            Disp::Exit(c) => TrapOutcome::Exit(c),
            Disp::Retry => TrapOutcome::Handled,
            Disp::Ret(v) => {
                sem::r_set(&mut env.backend, 0, v);
                let p = sem::psw_get(&env.backend) & !1;
                sem::psw_put(&mut env.backend, p);
                TrapOutcome::Handled
            }
            Disp::Ret2(hi, lo) => {
                sem::r_set(&mut env.backend, 0, hi);
                sem::r_set(&mut env.backend, 1, lo);
                let p = sem::psw_get(&env.backend) & !1;
                sem::psw_put(&mut env.backend, p);
                TrapOutcome::Handled
            }
            Disp::Fail(e) => {
                sem::r_set(&mut env.backend, 0, e);
                let p = sem::psw_get(&env.backend) | 1;
                sem::psw_put(&mut env.backend, p);
                TrapOutcome::Handled
            }
        }
    }

    fn handle_unimpl(&mut self, env: &mut BareEnv, pc: u64, word: u64) -> TrapOutcome {
        // FP11 を持たないモデルでは 17xxxx の語彙が解読に失敗する。
        // V7 の kernel は FP シミュレータを持ち、crt0 が無条件で
        // 実行する `setd` はここでモード設定の no-op として済ませる
        // （setf/seti/setd/setl の 4 語。算術命令の模倣は残り）。
        const FP_MODE_OPS: [u64; 4] = [0o170001, 0o170002, 0o170011, 0o170012];
        if FP_MODE_OPS.contains(&word) {
            let next = (pc as u16).wrapping_add(2);
            env.pc = u64::from(next);
            sem::r_set(&mut env.backend, reg::PC as u8, next);
            return TrapOutcome::Handled;
        }
        TrapOutcome::Unimplemented
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 0411（分離 I/D）バイナリの exec 配置 —— データが D 空間
    /// 側の別物理に乗り、I 空間のテキストと同居しないこと、
    /// PAR/PDR と MMR3 が立つことを fixture（/bin/sort）で見る。
    #[test]
    fn load_sep_magic_layout() {
        let root = "../../.testdata/bin-distro-unixv7";
        let bytes = std::fs::read(format!("{root}/bin/sort")).unwrap();
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_pdp11::CpuState>());
        let model = polyisa_guest_pdp11::model_params("pdp11_70");
        polyisa_guest_pdp11::install_params(&mut env.backend, &model);
        env.backend.addr_mask = 0xFFFF;
        let mut v7 = V7::new(root);
        let argv = vec!["/bin/sort".to_string()];
        let entry = v7.load_exec(&mut env, &bytes, &argv).unwrap();
        assert_eq!(entry, 0);
        assert!(v7.sep_id);
        // MMR3: ユーザ D 空間が有効。
        assert_eq!(
            mmu::mmr_val(&env.backend, 3) & mmu::mmr3::UDS,
            mmu::mmr3::UDS
        );
        // テキストは I 空間、データは D 空間で正しく読める。
        let ts = u16::from_le_bytes(bytes[2..4].try_into().unwrap()) as usize;
        let ds = u16::from_le_bytes(bytes[4..6].try_into().unwrap()) as usize;
        let text = &bytes[16..16 + ts];
        let data = &bytes[16 + ts..16 + ts + ds];
        for off in [0u16, 2, 0o40] {
            let want = u16::from_le_bytes([text[off as usize], text[off as usize + 1]]);
            assert_eq!(V7::r16i(&env, off), Some(want), "text +{off:o}");
        }
        for off in [0u16, 2, 0o100] {
            let want = u16::from_le_bytes([data[off as usize], data[off as usize + 1]]);
            assert_eq!(v7.r16(&env, u64::from(off)), Some(want), "data +{off:o}");
        }
        // D 空側のデータ先頭はテキストの後ろの別物理（PA!=VA）にある
        // —— I 空間の語を上書きしていないことの裏付け。
        let dp = V7::pa_of(&env, mmu::Space::D, 2, false).unwrap();
        assert_ne!(dp, 2);
    }
}
