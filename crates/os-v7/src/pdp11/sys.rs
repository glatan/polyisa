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

/// `write` 系で捕まえた標準出力と標準エラー。
#[derive(Default)]
pub struct V7Io {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
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
    sigact: [u16; 16],
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
            sigact: [0; 16],
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
                    segs.pop()?;
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

    /// 次に使える fd（0..2 は stdio）。NOFILE=15 の範囲内。
    fn alloc_fd(&mut self) -> Option<u32> {
        (3u32..15).find(|&fd| {
            self.fds.get(fd).is_none()
                && !self.dirs.contains_key(&fd)
                && !self.pipes.contains_key(&fd)
        })
    }

    /// fd が使用中か。
    fn fd_used(&self, fd: u32) -> bool {
        fd <= 2
            || self.fds.get(fd).is_some()
            || self.dirs.contains_key(&fd)
            || self.pipes.contains_key(&fd)
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
    fn dir_ents(path: &str) -> Option<Vec<u8>> {
        let mut out = Vec::new();
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
        // fd は r0、buf・count は u.u_arg。
        let (fd, buf, n) = (
            u32::from(sem::r_get(&env.backend, 0)),
            u64::from(a[0]),
            usize::from(a[1]),
        );
        match fd {
            0 => {
                // 標準入力は空（EOF）。
                Disp::Ret(0)
            }
            1 | 2 => Disp::Fail(errno::EBADF),
            _ => {
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
                let Some(f) = self.fds.get_mut(fd) else {
                    return Disp::Fail(errno::EBADF);
                };
                let mut tmp = vec![0u8; n.min(1 << 16)];
                match f.read(&mut tmp) {
                    Ok(got) => {
                        if self.write_bytes(env, buf, &tmp[..got]).is_err() {
                            Disp::Fail(errno::EFAULT)
                        } else {
                            Disp::Ret(got as u16)
                        }
                    }
                    Err(_) => Disp::Fail(errno::EIO),
                }
            }
        }
    }

    fn sys_write(&mut self, env: &mut BareEnv, a: &[u16]) -> Disp {
        let (fd, buf, n) = (
            u32::from(sem::r_get(&env.backend, 0)),
            u64::from(a[0]),
            usize::from(a[1]),
        );
        let data = match self.read_bytes(env, buf, n) {
            Ok(d) => d,
            Err(e) => return Disp::Fail(e),
        };
        match fd {
            0 => Disp::Fail(errno::EBADF),
            1 => {
                self.io.stdout.extend_from_slice(&data);
                let _ = std::io::stdout().write_all(&data);
                Disp::Ret(n as u16)
            }
            2 => {
                self.io.stderr.extend_from_slice(&data);
                let _ = std::io::stderr().write_all(&data);
                Disp::Ret(n as u16)
            }
            _ => {
                if let Some(p) = self.pipes.get(&fd) {
                    if p.read {
                        return Disp::Fail(errno::EBADF);
                    }
                    return match self.pipe_tab.write(p.id, &data) {
                        Some(k) => Disp::Ret(k as u16),
                        None => Disp::Fail(errno::EPIPE),
                    };
                }
                if self.dirs.contains_key(&fd) {
                    return Disp::Fail(errno::EBADF);
                }
                let Some(f) = self.fds.get_mut(fd) else {
                    return Disp::Fail(errno::EBADF);
                };
                match f.write_all(&data) {
                    Ok(()) => Disp::Ret(n as u16),
                    Err(_) => Disp::Fail(errno::EIO),
                }
            }
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
        // V7: 0=read・1=write・2=read+write。
        let mut o = std::fs::OpenOptions::new();
        match mode {
            0 => {
                o.read(true);
            }
            1 => {
                o.write(true);
            }
            2 => {
                o.read(true).write(true);
            }
            _ => return Disp::Fail(errno::EINVAL),
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
                self.fds.place(fd, Some(f));
                self.fds.remember_path(fd, path);
                Disp::Ret(fd as u16)
            }
            Err(e) => Disp::Fail(host_err(e.raw_os_error())),
        }
    }

    fn sys_close(&mut self, env: &BareEnv, a: &[u16]) -> Disp {
        let _ = a;
        let fd = u32::from(sem::r_get(&env.backend, 0));
        match fd {
            0..=2 => Disp::Ret(0),
            _ => {
                let mut was = self.fds.get(fd).is_some() | self.dirs.remove(&fd).is_some();
                if let Some(p) = self.pipes.remove(&fd) {
                    self.pipe_tab.close(p.id, p.read);
                    was = true;
                }
                self.fds.clear(fd);
                if was {
                    Disp::Ret(0)
                } else {
                    Disp::Fail(errno::EBADF)
                }
            }
        }
    }

    fn sys_seek(&mut self, env: &mut BareEnv, a: &[u16]) -> Disp {
        let fd = u32::from(sem::r_get(&env.backend, 0));
        // PDP-11 の long は上位語が先。
        let off = (i32::from(a[0] as i16) << 16) | i32::from(a[1] as i16);
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
        let Some(f) = self.fds.get_mut(fd) else {
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
        let new = a[0];
        // 上限はスタック下端、下限はデータ先頭。
        if new < self.data_lo || u64::from(new) >= u64::from(self.stack_lo) << 13 {
            return Disp::Fail(errno::ENOMEM);
        }
        // 新しく写像が要るページを有効にする（データ側の PAR を
        // 延ばす —— VA=PA、物理は全面写像済み）。
        let top_page = u64::from(new.wrapping_sub(1)) >> 13;
        let space = if self.sep_id {
            mmu::Space::D
        } else {
            mmu::Space::I
        };
        let d_first = self.data_lo >> 13;
        for p in 0..=top_page as u16 {
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
            let fd = u32::from(sem::r_get(&env.backend, 0));
            if let Some(d) = self.dirs.get(&fd) {
                match polyisa_host::stat(&d.path) {
                    Ok(m) => m,
                    Err(_) => return Disp::Fail(errno::EIO),
                }
            } else {
                match self.fds.get(fd).map(polyisa_host::fstat) {
                    Some(Ok(m)) => m,
                    Some(Err(_)) => return Disp::Fail(errno::EIO),
                    None => {
                        // stdio はキャラクタデバイスとして報告しない
                        // （ENOTTY 側へ寄せる —— /dev/null 相当の
                        // 最小属性）。
                        let zero_md = match polyisa_host::stat("/dev/null") {
                            Ok(m) => m,
                            Err(_) => return Disp::Fail(errno::EBADF),
                        };
                        if fd > 2 && !self.pipes.contains_key(&fd) {
                            return Disp::Fail(errno::EBADF);
                        }
                        zero_md
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
        if s == 0 || s >= self.sigact.len() {
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
        let page = (m0 & mmu::mmr0::PAGE) >> 1;
        let mode = (m0 >> 5) & 0o3;
        // MMR0 の凍結桁を戻す（エラーの記録を残し、凍結だけ解く）。
        mmu::mmr_put(b, 0, m0 & !(mmu::mmr0::FREEZE | mmu::mmr0::TRAP));
        let can_grow = mode == psw::USER
            && err & (mmu::mmr0::NR | mmu::mmr0::PL) != 0
            && page < self.stack_lo
            && u64::from(page) << 13 >= u64::from(self.data_lo);
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
        let n = usize::from(w & 0o377);
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
            let w2 = self.r16(env, u64::from(ptr));
            if trace() {
                eprintln!("indir ptr={ptr:o} w2={w2:?}");
            }
            let Some(w2) = w2 else {
                return Disp::Fail(errno::EFAULT);
            };
            let n2 = usize::from(w2 & 0o377);
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
        match n {
            1 => Disp::Exit(u32::from(args[0])),
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
                match std::fs::remove_file(&path).or_else(|_| std::fs::remove_dir(&path)) {
                    Ok(()) => Disp::Ret(0),
                    Err(e) => Disp::Fail(host_err(e.raw_os_error())),
                }
            }
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
                Disp::Ret(0)
            }
            17 => self.sys_sbreak(env, &args),
            18 => self.sys_stat(env, &args, false),
            19 => self.sys_seek(env, &args),
            20 => Disp::Ret(self.pid),
            23 | 46 => Disp::Ret(0), // setuid/setgid —— root モデル
            24 => Disp::Ret2(0, 0),  // getuid —— root モデル
            25 => Disp::Ret(0),      // stime —— 時計は書かない
            27 => Disp::Ret(0),      // alarm —— タイマなし
            28 => self.sys_stat(env, &args, true),
            30 => Disp::Ret(0), // utime —— 時刻更新は省略
            33 => {
                let path = match self.host_path(env, u64::from(args[0])) {
                    Ok(p) => p,
                    Err(e) => return Disp::Fail(e),
                };
                match std::fs::metadata(&path) {
                    Ok(_) => Disp::Ret(0),
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
                // kill(pid, sig): pid は r0、sig は u.u_arg[0]。
                // 自プロセスへの配送のみ。
                if sem::r_get(&env.backend, 0) == self.pid || sem::r_get(&env.backend, 0) == 0 {
                    let s = args[1] as u8;
                    if (1..16).contains(&s) && s != sig::KILL {
                        let d = self.sigact[s as usize];
                        if d > 1 {
                            // ハンドラ配送は OS4 の範囲。
                            return Self::die(s);
                        }
                    }
                    Self::die(s.min(15))
                } else {
                    Disp::Fail(errno::ESRCH)
                }
            }
            40 => {
                // tell: fd は r0。
                let fd = u32::from(sem::r_get(&env.backend, 0));
                if let Some(d) = self.dirs.get(&fd) {
                    let p = d.pos;
                    return Disp::Ret2((p >> 16) as u16, (p & 0xffff) as u16);
                }
                match self.fds.get_mut(fd).map(|f| f.stream_position()) {
                    Some(Ok(p)) => Disp::Ret2((p >> 16) as u16, (p & 0xffff) as u16),
                    Some(Err(_)) => Disp::Fail(errno::EIO),
                    None => Disp::Fail(errno::ESPIPE),
                }
            }
            41 => {
                // dup(fd[, fd2]): fd は r0、dup2 先は r1。fd2 が
                // 指されていて fd と違うなら、そこを閉じてから写す
                // （V7 の dup は r1 の指定を見る）。
                let fd = u32::from(sem::r_get(&env.backend, 0));
                let fd2 = u32::from(sem::r_get(&env.backend, 1));
                let nf = if fd2 != 0 && fd2 != fd && fd2 < 15 {
                    if !self.fd_used(fd) {
                        return Disp::Fail(errno::EBADF);
                    }
                    if self.fd_used(fd2) {
                        self.dirs.remove(&fd2);
                        if let Some(p) = self.pipes.remove(&fd2) {
                            self.pipe_tab.close(p.id, p.read);
                        }
                        self.fds.clear(fd2);
                    }
                    fd2
                } else {
                    match self.alloc_fd() {
                        Some(f) => f,
                        None => return Disp::Fail(errno::EMFILE),
                    }
                };
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
                let Some(f) = self.fds.get_mut(fd) else {
                    return Disp::Fail(errno::EBADF);
                };
                match f.try_clone() {
                    Ok(n) => {
                        self.fds.place(nf, Some(n));
                        Disp::Ret(nf as u16)
                    }
                    Err(_) => Disp::Fail(errno::EIO),
                }
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
            48 => self.sys_signal(&args),
            54 => Disp::Fail(errno::ENOTTY), // ioctl —— tty なし
            60 => {
                let old = self.umask;
                self.umask = args[0] & 0o777;
                Disp::Ret(old)
            }
            _ => {
                if !self.reported.contains(&(n as u8)) {
                    self.reported.push(n as u8);
                    eprintln!("v7: 未実装の syscall {}（{}）", n, ent.name);
                }
                Self::die(sig::SYS)
            }
        }
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
        self.d_base_par = (d_phys >> 6) as u16;
        let bss_lo = data_va + h.data;
        self.data_lo = data_va as u16;
        self.brk = bss_lo as u16;
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
            // PAR = データ物理先頭 + データ起点からの頁距離
            // （0411 は d_base_par=別物理・d_first=0、その他は
            // 恒等で d_base_par=d_first*0o200）。
            let par = self.d_base_par.wrapping_add((p - d_first) * 0o200);
            mmu::apr_put(b, mmu::apr_idx(2, d_space, p), par, pdr_rw_full());
        }
        if sep {
            // I 空間は text のみ、D 空間は data+stack。
            // data は vaddr 0 からの D 空間 —— 物理は同じ場所。
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

    fn init_brk(&mut self, image_end: u64) {
        self.brk = image_end as u16;
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
