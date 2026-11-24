// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! ファイル記述子。fd が指す対象を一つの多態な型で表す表と、
//! 対象の準備状態を集める機構。
//!
//! fd の対象は `FdTarget` で表し、表 `FdTable` が fd 番号（3 以降）から
//! 対象へ写す。パイプ・カーネル内ソケット対・eventfd・timerfd・
//! signalfd・epoll・memfd は仮想カーネル内の対象として `Rc` で共有し、
//! `dup`/`fork` で表の複製が同じ対象を指す。ホストのソケットは
//! `HostSock` として表に載る。
//!
//! fd 0-2（標準入出力）は各 OS パーソナリティの模型が担い、この表の
//! 範囲外である。

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;

/// ゲストプロセス間で共有するパイプのバッファ。
#[derive(Debug, Default)]
pub struct PipeTable {
    next: u64,
    pipes: Vec<Pipe>,
}

#[derive(Debug)]
struct Pipe {
    id: u64,
    data: VecDeque<u8>,
    readers: u32,
    writers: u32,
    /// 読み端・書き端の記述子が持つ O_NONBLOCK。dup で複製した端は
    /// 同じ記述を指すので旗はパイプ側に置く。
    rd_nonblock: bool,
    wr_nonblock: bool,
}

/// パイプからの読み出し。
#[derive(Debug, PartialEq, Eq)]
pub enum PipeRead {
    /// 取り出したバイト列。
    Bytes(Vec<u8>),
    /// 書き手がなく、バッファも空。
    Eof,
    /// 書き手が残っていて、バッファが空。
    Empty,
}

impl PipeTable {
    /// 読み端と書き端を一つずつ持つパイプを作る。
    pub fn open(&mut self) -> u64 {
        self.next += 1;
        let id = self.next;
        self.pipes.push(Pipe {
            id,
            data: VecDeque::new(),
            readers: 1,
            writers: 1,
            rd_nonblock: false,
            wr_nonblock: false,
        });
        id
    }

    /// fork で端を複製したときに数を増やす。
    pub fn dup(&mut self, id: u64, read: bool) {
        if let Some(pipe) = self.get_mut(id) {
            if read {
                pipe.readers += 1;
            } else {
                pipe.writers += 1;
            }
        }
    }

    /// 端を閉じる。返り値は（閉じた端が書き端で読み手が残る=読み側の
    /// 待ちを解除する目、閉じた端が読み端で書き手が残る=書き側を
    /// エラーにする目）の（id, 読み解除, 書き解除）。
    pub fn close(&mut self, id: u64, read: bool) -> (bool, bool) {
        let Some(pipe) = self.get_mut(id) else {
            return (false, false);
        };
        if read {
            pipe.readers = pipe.readers.saturating_sub(1);
            (false, pipe.readers == 0 && pipe.writers > 0)
        } else {
            pipe.writers = pipe.writers.saturating_sub(1);
            (pipe.writers == 0 && pipe.readers > 0, false)
        }
    }

    /// 最大 `max` バイト読む。
    pub fn read(&mut self, id: u64, max: usize) -> PipeRead {
        let Some(pipe) = self.get_mut(id) else {
            return PipeRead::Eof;
        };
        if pipe.data.is_empty() {
            if pipe.writers == 0 {
                PipeRead::Eof
            } else {
                PipeRead::Empty
            }
        } else {
            let n = max.min(pipe.data.len());
            PipeRead::Bytes(pipe.data.drain(..n).collect())
        }
    }

    /// 書き手が読む相手を失っていれば `None`。
    pub fn write(&mut self, id: u64, bytes: &[u8]) -> Option<usize> {
        let pipe = self.get_mut(id)?;
        if pipe.readers == 0 {
            return None;
        }
        pipe.data.extend(bytes);
        Some(bytes.len())
    }

    /// 端の O_NONBLOCK。
    #[must_use]
    pub fn nonblock(&self, id: u64, read: bool) -> bool {
        self.get(id)
            .map(|pipe| {
                if read {
                    pipe.rd_nonblock
                } else {
                    pipe.wr_nonblock
                }
            })
            .unwrap_or(false)
    }

    /// 端の O_NONBLOCK を立てる/下ろす。対象がなければ偽。
    pub fn set_nonblock(&mut self, id: u64, read: bool, on: bool) -> bool {
        let Some(pipe) = self.get_mut(id) else {
            return false;
        };
        if read {
            pipe.rd_nonblock = on;
        } else {
            pipe.wr_nonblock = on;
        }
        true
    }

    /// 準備状態（読み端・書き端ごと）。対象がなければ hup のみ。
    #[must_use]
    pub fn ready(&self, id: u64, read: bool) -> Ready {
        let Some(pipe) = self.get(id) else {
            return Ready {
                hup: true,
                ..Ready::default()
            };
        };
        if read {
            Ready {
                read: !pipe.data.is_empty(),
                write: false,
                hup: pipe.writers == 0,
                err: false,
            }
        } else {
            Ready {
                read: false,
                write: pipe.readers > 0,
                hup: false,
                err: pipe.readers == 0,
            }
        }
    }

    fn get(&self, id: u64) -> Option<&Pipe> {
        self.pipes.iter().find(|pipe| pipe.id == id)
    }

    fn get_mut(&mut self, id: u64) -> Option<&mut Pipe> {
        self.pipes.iter_mut().find(|pipe| pipe.id == id)
    }
}

/// カーネル内ソケット対の端。socketpair(AF_UNIX) が作る全二重の器。
/// バイト流（SOCK_STREAM）では `in_*` が相手から届いたバイト列、
/// メッセージ（SOCK_DGRAM）ではメッセージ列である。
#[derive(Debug)]
pub struct PairSock {
    /// end A が読む箱。
    a_in: SockBox,
    /// end B が読む箱。
    b_in: SockBox,
    /// 各端を指す記述子の数。dup で増え、close で減る。
    a_open: u32,
    b_open: u32,
    a_nonblock: bool,
    b_nonblock: bool,
    /// shutdown(SHUT_RD/SHUT_WR) の状態。read は相手方向への
    /// 受け取りを止め、write は自分方向の送出を止める。
    a_rd_shut: bool,
    a_wr_shut: bool,
    b_rd_shut: bool,
    b_wr_shut: bool,
}

/// 一方向の中身。
#[derive(Debug)]
enum SockBox {
    /// バイト流。
    Stream(VecDeque<u8>),
    /// メッセージ境界を保つ列。
    Dgram(VecDeque<Vec<u8>>),
}

/// ソケット対のどちらの端か。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PairEnd {
    A,
    B,
}

impl PairEnd {
    fn peer(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

impl PairSock {
    /// 両端の開いた対を作る。`dgram` は SOCK_DGRAM。
    #[must_use]
    pub fn new(dgram: bool) -> Self {
        let box_ = || {
            if dgram {
                SockBox::Dgram(VecDeque::new())
            } else {
                SockBox::Stream(VecDeque::new())
            }
        };
        Self {
            a_in: box_(),
            b_in: box_(),
            a_open: 1,
            b_open: 1,
            a_nonblock: false,
            b_nonblock: false,
            a_rd_shut: false,
            a_wr_shut: false,
            b_rd_shut: false,
            b_wr_shut: false,
        }
    }

    fn inbox(&self, end: PairEnd) -> &SockBox {
        match end {
            PairEnd::A => &self.a_in,
            PairEnd::B => &self.b_in,
        }
    }

    fn inbox_mut(&mut self, end: PairEnd) -> &mut SockBox {
        match end {
            PairEnd::A => &mut self.a_in,
            PairEnd::B => &mut self.b_in,
        }
    }

    fn open(&self, end: PairEnd) -> bool {
        match end {
            PairEnd::A => self.a_open > 0,
            PairEnd::B => self.b_open > 0,
        }
    }

    fn nonblock(&self, end: PairEnd) -> bool {
        match end {
            PairEnd::A => self.a_nonblock,
            PairEnd::B => self.b_nonblock,
        }
    }

    /// 端を閉じる。dup 済みの端は残り数を減らすだけ。
    fn close(&mut self, end: PairEnd) {
        match end {
            PairEnd::A => self.a_open = self.a_open.saturating_sub(1),
            PairEnd::B => self.b_open = self.b_open.saturating_sub(1),
        }
    }

    /// 端の複製（dup・fork）。残り数を増やす。
    pub fn dup(&mut self, end: PairEnd) {
        match end {
            PairEnd::A => self.a_open += 1,
            PairEnd::B => self.b_open += 1,
        }
    }

    /// shutdown(how)。0=SHUT_RD、1=SHUT_WR、2=SHUT_RDWR。
    /// 範囲外は false。
    pub fn shutdown(&mut self, end: PairEnd, how: u32) -> bool {
        if how > 2 {
            return false;
        }
        let (rd, wr) = match end {
            PairEnd::A => (&mut self.a_rd_shut, &mut self.a_wr_shut),
            PairEnd::B => (&mut self.b_rd_shut, &mut self.b_wr_shut),
        };
        if how != 1 {
            *rd = true;
        }
        if how != 0 {
            *wr = true;
        }
        true
    }

    /// 端の O_NONBLOCK。
    #[must_use]
    pub fn is_nonblock(&self, end: PairEnd) -> bool {
        self.nonblock(end)
    }

    /// 端の O_NONBLOCK を変える。
    pub fn set_nonblock(&mut self, end: PairEnd, on: bool) {
        match end {
            PairEnd::A => self.a_nonblock = on,
            PairEnd::B => self.b_nonblock = on,
        }
    }

    /// 端から読む。相手が閉じて箱も空なら Eof、空なら Empty。
    /// SHUT_RD 済みでも既に届いた分は読める。
    #[must_use]
    pub fn recv(&mut self, end: PairEnd, max: usize) -> PipeRead {
        // Linux は len=0 の recv を即 0 で返す。Empty にすると
        // 呼び出し側が阻止待ちにする。
        if max == 0 {
            return PipeRead::Bytes(Vec::new());
        }
        let rd_shut = match end {
            PairEnd::A => self.a_rd_shut,
            PairEnd::B => self.b_rd_shut,
        };
        let peer_open = self.open(end.peer());
        let inbox = self.inbox_mut(end);
        let empty = match inbox {
            SockBox::Stream(q) => q.is_empty(),
            SockBox::Dgram(q) => q.is_empty(),
        };
        if empty && (rd_shut || !peer_open) {
            return PipeRead::Eof;
        }
        let got = match inbox {
            SockBox::Stream(q) => {
                let n = max.min(q.len());
                q.drain(..n).collect()
            }
            SockBox::Dgram(q) => match q.pop_front() {
                Some(msg) => {
                    let n = max.min(msg.len());
                    msg[..n].to_vec()
                }
                None => Vec::new(),
            },
        };
        if got.is_empty() {
            PipeRead::Empty
        } else {
            PipeRead::Bytes(got)
        }
    }

    /// 端から相手へ送る。相手が閉じているか相手が受け取りを
    /// 止めていれば（SHUT_RD）None（EPIPE）。
    pub fn send(&mut self, end: PairEnd, bytes: &[u8]) -> Option<usize> {
        let wr_shut = match end {
            PairEnd::A => self.a_wr_shut,
            PairEnd::B => self.b_wr_shut,
        };
        let peer_rd_shut = match end.peer() {
            PairEnd::A => self.a_rd_shut,
            PairEnd::B => self.b_rd_shut,
        };
        if wr_shut || peer_rd_shut || !self.open(end.peer()) {
            return None;
        }
        match self.inbox_mut(end.peer()) {
            SockBox::Stream(q) => {
                q.extend(bytes.iter().copied());
                Some(bytes.len())
            }
            SockBox::Dgram(q) => {
                q.push_back(bytes.to_vec());
                Some(bytes.len())
            }
        }
    }

    /// 端の準備状態。
    #[must_use]
    pub fn ready(&self, end: PairEnd) -> Ready {
        let data = match self.inbox(end) {
            SockBox::Stream(q) => !q.is_empty(),
            SockBox::Dgram(q) => !q.is_empty(),
        };
        let wr_shut = match end {
            PairEnd::A => self.a_wr_shut,
            PairEnd::B => self.b_wr_shut,
        };
        let peer_rd_shut = match end.peer() {
            PairEnd::A => self.a_rd_shut,
            PairEnd::B => self.b_rd_shut,
        };
        let peer_open = self.open(end.peer());
        Ready {
            read: data,
            write: peer_open && !wr_shut && !peer_rd_shut,
            hup: !peer_open,
            err: false,
        }
    }
}

/// eventfd の共有状態。dup・fork で同じカウンタを指す。
#[derive(Debug)]
pub struct EventState {
    /// カウンタ。
    pub count: Cell<u64>,
    /// EFD_SEMAPHORE。読みが全量ではなく 1 だけ減らす。
    pub semaphore: bool,
    /// EFD_NONBLOCK。
    pub nonblock: Cell<bool>,
}

/// timerfd の共有状態。時計は呼び出し側の単調時計に対する
/// deadline として保持する（`now` を渡して readiness を判定する）。
#[derive(Debug)]
pub struct TimerState {
    /// 次の満了（ナノ秒、単調時計起点から）。None は停止。
    pub deadline: Option<u64>,
    /// 周期（ナノ秒）。0 は一回限り。
    pub interval: u64,
    /// 満了回数の累積。read はこの数を返して 0 に戻す。
    pub expirations: u64,
    /// TFD_NONBLOCK。
    pub nonblock: bool,
}

impl TimerState {
    /// 満了を `now`（同じ時計の今、ナノ秒）まで数えて溜める。
    /// 周期タイマは追いついた分だけ回数を足す。
    pub fn catch_up(&mut self, now: u64) {
        let Some(dl) = self.deadline else {
            return;
        };
        if now < dl {
            return;
        }
        if self.interval == 0 {
            self.expirations = self.expirations.saturating_add(1);
            self.deadline = None;
            return;
        }
        let n = (now - dl) / self.interval + 1;
        self.expirations = self.expirations.saturating_add(n);
        self.deadline = Some(dl + n * self.interval);
    }

    /// 準備状態。`now` は `catch_up` と同じ時計の今。
    #[must_use]
    pub fn ready(&mut self, now: u64) -> Ready {
        self.catch_up(now);
        Ready {
            read: self.expirations > 0,
            ..Ready::default()
        }
    }
}

/// epoll の登録集合。登録は監視対象の `FdTarget` の複製（dup 相当）
/// と興味イベントとユーザデータを持つ。`epoll_wait` は登録ごとに
/// 準備状態を再評価するレベルトリガとして動く。
///
/// 登録の追加は `FdTable::dup_of` で得た対象を `regs` に入れ、
/// 削除は `FdTable::epoll_del`（対象を閉じる）で行う。`regs` から
/// 直接抜くだけでは端数が減らず漏れる。
// 段階26 残件: EPOLLET・EPOLLONESHOT は LT 相当の近似。
#[derive(Debug, Default)]
pub struct EpollSet {
    /// （鍵 = 登録時の fd と同一対象を判別する印、監視対象、events、data）。
    pub regs: Vec<EpollReg>,
}

/// epoll_ctl で登録する一項目。
#[derive(Debug)]
pub struct EpollReg {
    /// 識別の鍵。dup で共有する対象は同じ鍵を持つ。
    pub key: u64,
    /// 監視対象。登録元の fd が閉じても対象自体は生きる。
    /// `FdTable::dup_of` で複製したものを置く。
    pub target: FdTarget,
    /// EPOLL* の興味イベント。
    pub events: u32,
    /// ユーザデータ（epoll_event.data）。
    pub data: u64,
}

/// signalfd の共有状態。dup・fork で同じマスクを指す。
#[derive(Debug, Default)]
pub struct SignalState {
    /// 興味のあるシグナルのビット集合。
    pub mask: Cell<u64>,
    /// SFD_NONBLOCK。
    pub nonblock: Cell<bool>,
}

/// memfd の共有状態。dup・fork で同じ中身とオフセットを指す。
// 段階26 残件: mmap による写像・F_ADD_SEALS は未実装。
#[derive(Debug, Default)]
pub struct MemFile {
    /// 中身。
    pub data: Vec<u8>,
    /// 共有オフセット（dup は同じ記述を指す規約）。
    pub pos: u64,
    /// O_NONBLOCK。メモリ上の対象なので意味はないが、F_GETFL が
    /// 正しく報告できるよう記録だけする。
    pub nonblock: bool,
}

/// ホストのソケット記述子とゲスト側の共有状態。ホストの fd は
/// 常に非阻止に保ち（ABI が阻止動作を待ちへ写す）、ゲストが
/// 見る O_NONBLOCK は `nonblock` に写す。dup では `Rc` を共有
/// するので非阻止旗も記述の規約どおり共有される。
#[cfg(unix)]
#[derive(Debug)]
pub struct HostSockEnt {
    /// ホストのソケット。
    pub sock: polyisa_host::SockFd,
    /// ゲストが見る O_NONBLOCK。
    pub nonblock: Cell<bool>,
    /// 非阻止 connect が進行中。再入は connect を呼ばず
    /// SO_ERROR で完了を読む（Linux の EALREADY 規約）。
    pub connecting: Cell<bool>,
}

/// fd が指す対象。一つの表が全種類を保持する。
///
/// `FdTarget` 自体は `Drop` で端数を減らさない。表の外に置いた
/// 複製（標準 fd の付け替え先、epoll の登録など）は、捨てる側が
/// `FdTable::close_target` を呼んで閉じる規約。
#[derive(Debug)]
pub enum FdTarget {
    /// ホストのファイル・ディレクトリ。
    File(std::fs::File),
    /// カーネル内パイプの端。バッファは `FdTable` が持つ `PipeTable`。
    PipeEnd { id: u64, read: bool },
    /// カーネル内 socketpair の端。
    PairSock {
        pair: Rc<RefCell<PairSock>>,
        end: PairEnd,
    },
    /// ホストのソケット。AF_UNIX パス・AF_INET/INET6 はこちら。
    /// `Rc` の中の `HostSockEnt` が dup で共有される（ファイル
    /// 記述の規約）。
    #[cfg(unix)]
    HostSock(Rc<HostSockEnt>),
    /// eventfd の共有カウンタ。
    EventFd(Rc<EventState>),
    /// timerfd の共有状態。
    TimerFd(Rc<RefCell<TimerState>>),
    /// signalfd。読みは ABI の保留集合との照合なので器は
    /// マスクと O_NONBLOCK だけを持つ。dup で共有する。
    SignalFd(Rc<SignalState>),
    /// epoll の登録集合。
    Epoll(Rc<RefCell<EpollSet>>),
    /// memfd の共有中身。
    MemFd(Rc<RefCell<MemFile>>),
    /// 端末（/dev/tty）。中身は O_NONBLOCK。
    Terminal(Rc<Cell<bool>>),
    /// 番号だけを占有する場所取り。対象の実体は呼び出し側が別に
    /// 持つ（os-wasi の Dir/Preopen スロット）。dup は Reserved
    /// のまま番号を増やすだけで実体は複製しない。
    Reserved,
}

/// fd の対象種別。`fstat` の st_mode の種別ビットに使う。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FdKind {
    File,
    Dir,
    Fifo,
    Socket,
    Anon,
    Char,
}

impl FdTarget {
    /// 種別。
    #[must_use]
    pub fn kind(&self) -> FdKind {
        match self {
            Self::File(f) => {
                if f.metadata().map(|m| m.is_dir()).unwrap_or(false) {
                    FdKind::Dir
                } else {
                    FdKind::File
                }
            }
            Self::PipeEnd { .. } => FdKind::Fifo,
            Self::PairSock { .. } => FdKind::Socket,
            #[cfg(unix)]
            Self::HostSock(_) => FdKind::Socket,
            Self::EventFd(_) | Self::TimerFd(_) | Self::SignalFd(_) | Self::Epoll(_) => {
                FdKind::Anon
            }
            Self::MemFd(_) => FdKind::File,
            Self::Terminal(_) => FdKind::Char,
            Self::Reserved => FdKind::Anon,
        }
    }

    /// epoll 登録の識別鍵。同一の対象は同じ鍵を持つ
    /// （dup しても変わらない。File はホストの dev:ino）。
    #[must_use]
    pub fn epoll_key(&self) -> u64 {
        // 型ごとにキーの名前空間を分ける（パイプ id・ホスト fd・
        // inode・ポインタが同じ数域で衝突しないように上位ビットで
        // タグを付ける）。
        const TAG_PIPE: u64 = 1 << 60;
        const TAG_HOST: u64 = 2 << 60;
        const TAG_PTR: u64 = 3 << 60;
        const PTR_MASK: u64 = !(0xF << 60);
        match self {
            Self::File(f) => polyisa_host::fstat(f)
                .map(|s| (s.dev << 32) | s.ino)
                .unwrap_or(0),
            Self::PipeEnd { id, read } => TAG_PIPE | ((*id << 1) | u64::from(!read)),
            Self::PairSock { pair, end } => {
                let base = Rc::as_ptr(pair) as usize as u64 & PTR_MASK;
                TAG_PTR | (base << 1) | u64::from(*end == PairEnd::B)
            }
            #[cfg(unix)]
            Self::HostSock(s) => TAG_HOST | s.sock.raw() as u64,
            Self::EventFd(s) => TAG_PTR | Rc::as_ptr(s) as usize as u64 & PTR_MASK,
            Self::TimerFd(s) => TAG_PTR | Rc::as_ptr(s) as usize as u64 & PTR_MASK,
            Self::SignalFd(s) => TAG_PTR | Rc::as_ptr(s) as usize as u64 & PTR_MASK,
            Self::Epoll(s) => TAG_PTR | Rc::as_ptr(s) as usize as u64 & PTR_MASK,
            Self::MemFd(s) => TAG_PTR | Rc::as_ptr(s) as usize as u64 & PTR_MASK,
            Self::Terminal(n) => TAG_PTR | Rc::as_ptr(n) as usize as u64 & PTR_MASK,
            Self::Reserved => 0,
        }
    }
}

/// 準備状態。`poll` の revents に写す。
#[derive(Clone, Copy, Default, Debug)]
pub struct Ready {
    /// 読み可（POLLIN）。
    pub read: bool,
    /// 書き可（POLLOUT）。
    pub write: bool,
    /// 切断（POLLHUP）。
    pub hup: bool,
    /// エラー（POLLERR）。
    pub err: bool,
}

/// fd のスロット。対象と、記述子ごとの旗と、覚えたパスを持つ。
#[derive(Debug)]
pub struct FdEnt {
    /// 対象。
    pub target: FdTarget,
    /// openat が開いたホストパス（getdents/readlink のため）。
    pub path: Option<String>,
    /// FD_CLOEXEC。execve で掃討する。
    pub cloexec: bool,
}

/// `read` の結果。
#[derive(Debug)]
pub enum FdRead {
    /// 読めたバイト列（空は `max == 0` のときだけ来る。EOF は `Eof`）。
    Bytes(Vec<u8>),
    /// カウンタ系対象の読み出し値（eventfd・timerfd）。
    /// バイト列への直列化はゲストのエンディアンを知る呼び出し側が行う。
    Count(u64),
    /// 末端。
    Eof,
    /// データなし。非阻止なら EAGAIN、阻止なら待ち。
    Empty,
    /// ディレクトリに対する read（EISDIR）。
    IsDir,
    /// 読み取りの向きでない fd（EBADF）。
    BadFd,
    /// この対象は read を受けない（EINVAL。epoll 等）。
    Inval,
    /// ホスト側のエラー（errno に写す値は呼び出し側で決める）。
    Host(std::io::Error),
}

/// `write` の結果。
#[derive(Debug)]
pub enum FdWrite {
    /// 書けたバイト数。
    Done(usize),
    /// 相手がいない（EPIPE）。
    Pipe,
    /// これ以上受け取れない。非阻止なら EAGAIN、阻止なら待ち。
    Full,
    /// 書き込みの向きでない fd（EBADF）。
    BadFd,
    /// この対象は write を受けない（EINVAL）。
    Inval,
    /// ホスト側のエラー。
    Host(std::io::Error),
}

/// `lseek` の結果。
#[derive(Debug)]
pub enum FdSeek {
    /// 新しいオフセット。
    Pos(u64),
    /// シークできない対象（ESPIPE）。
    Pipe,
    /// whence や結果位置の不正（EINVAL）。
    Inval,
    /// ホスト側のエラー。
    Host(std::io::Error),
}

/// fd が指す対象を多態な型で保持する表。ゲスト fd 3 以降に対応する。
/// パイプのバッファは表の内部に `Rc<RefCell>` で持ち、fork/dup で
/// 対象を共有する。標準入出力 (0/1/2) は含まない。
///
/// 表そのものが捨てられるときは `Drop` が各対象を閉じる。
/// `Drop`/`clear` の経路では閉じた結果としての待ち解除（他の
/// 表で眠る読み手・書き手の起床）は行わない。解除が要るときは
/// `take` で外して `close_target` の返り値を見ること。
#[derive(Debug)]
pub struct FdTable {
    ents: Vec<Option<FdEnt>>,
    /// パイプのバッファ。表の複製（fork）と共有する。
    pipes: Rc<RefCell<PipeTable>>,
}

impl Drop for FdTable {
    /// 表ごと捨てる経路（止めたスレッドの解放など）でも端数を減らす。
    fn drop(&mut self) {
        let ents = std::mem::take(&mut self.ents);
        for slot in ents.into_iter().flatten() {
            self.close_target(&slot.target);
        }
    }
}

impl Default for FdTable {
    fn default() -> Self {
        Self {
            ents: Vec::new(),
            pipes: Rc::new(RefCell::new(PipeTable::default())),
        }
    }
}

impl FdTable {
    /// ゲスト fd に対応する配列添字。3 未満は範囲外として扱う.
    fn index(fd: u32) -> Option<usize> {
        fd.checked_sub(3).map(|i| i as usize)
    }

    /// パイプのバッファ表。
    #[must_use]
    pub fn pipes(&self) -> Rc<RefCell<PipeTable>> {
        Rc::clone(&self.pipes)
    }

    /// 開いているスロット数（空きを含む）。
    pub fn len(&self) -> usize {
        self.ents.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ents.is_empty()
    }

    /// エントリ。
    #[must_use]
    pub fn ent(&self, fd: u32) -> Option<&FdEnt> {
        Self::index(fd)
            .and_then(|i| self.ents.get(i))
            .and_then(|e| e.as_ref())
    }

    /// エントリ（可変）。
    pub fn ent_mut(&mut self, fd: u32) -> Option<&mut FdEnt> {
        Self::index(fd)
            .and_then(|i| self.ents.get_mut(i))
            .and_then(|e| e.as_mut())
    }

    /// 対象。
    #[must_use]
    pub fn target(&self, fd: u32) -> Option<&FdTarget> {
        self.ent(fd).map(|e| &e.target)
    }

    /// 対象（可変）。
    pub fn target_mut(&mut self, fd: u32) -> Option<&mut FdTarget> {
        self.ent_mut(fd).map(|e| &mut e.target)
    }

    /// 対象がホストのファイルならその参照。
    #[must_use]
    pub fn file(&self, fd: u32) -> Option<&std::fs::File> {
        match self.target(fd) {
            Some(FdTarget::File(f)) => Some(f),
            _ => None,
        }
    }

    /// 対象がホストのファイルならその可変参照。
    pub fn file_mut(&mut self, fd: u32) -> Option<&mut std::fs::File> {
        match self.target_mut(fd) {
            Some(FdTarget::File(f)) => Some(f),
            _ => None,
        }
    }

    /// 最下位の空きスロットに置き、ゲスト fd を返す。
    pub fn alloc(&mut self, target: FdTarget) -> u32 {
        self.alloc_ent(FdEnt {
            target,
            path: None,
            cloexec: false,
        })
    }

    /// エントリごと置く版。
    pub fn alloc_ent(&mut self, ent: FdEnt) -> u32 {
        match self.ents.iter().position(|e| e.is_none()) {
            Some(i) => {
                self.ents[i] = Some(ent);
                (3 + i) as u32
            }
            None => {
                self.ents.push(Some(ent));
                (3 + self.ents.len() - 1) as u32
            }
        }
    }

    /// ホストのファイルを置く版（従来の `alloc(Some(f))` 相当）。
    pub fn alloc_file(&mut self, f: std::fs::File) -> u32 {
        self.alloc(FdTarget::File(f))
    }

    /// 最初の空きスロットの添字（`free` が真のものだけ）。
    /// EMFILE の検査や並列表との調整に使う。
    #[must_use]
    pub fn first_hole_where(&self, mut free: impl FnMut(usize) -> bool) -> Option<usize> {
        self.ents
            .iter()
            .enumerate()
            .find(|(i, e)| e.is_none() && free(*i))
            .map(|(i, _)| i)
    }

    /// 空きスロットを `free` が真を返すものだけ使って置く
    /// （`F_DUPFD` の下限や呼び出し側の並列表との調整用）。
    /// 既存の穴に合うものがなければ、`free` が真になる番号まで
    /// 空きを詰めてから置く。
    pub fn alloc_where(&mut self, target: FdTarget, mut free: impl FnMut(usize) -> bool) -> u32 {
        let pos = self
            .ents
            .iter()
            .enumerate()
            .position(|(i, e)| e.is_none() && free(i));
        let i = match pos {
            Some(i) => i,
            None => {
                while !free(self.ents.len()) {
                    self.ents.push(None);
                }
                self.ents.push(None);
                self.ents.len() - 1
            }
        };
        self.ents[i] = Some(FdEnt {
            target,
            path: None,
            cloexec: false,
        });
        (3 + i) as u32
    }

    /// 指定のゲスト fd に置く。足りない分は空きで伸ばし、
    /// もともと入っていたエントリ（あれば）を返す。呼び出し側は
    /// 返されたパイプ端等に応じて待ちの解除を行う（dup2 規約）。
    /// 3 未満は何もしない.
    pub fn place(&mut self, fd: u32, target: FdTarget) -> Option<FdEnt> {
        self.place_ent(
            fd,
            FdEnt {
                target,
                path: None,
                cloexec: false,
            },
        )
    }

    /// `place` と同じだが、置き換えられた対象はその場で閉じる。
    /// パイプ端の待ち解除が要る呼び出し側は `take` + `close_target`
    /// + `place` を使う。
    pub fn place_close(&mut self, fd: u32, target: FdTarget) {
        if let Some(old) = self.place(fd, target) {
            let _ = self.close_target(&old.target);
        }
    }

    /// エントリごと置く版。
    pub fn place_ent(&mut self, fd: u32, ent: FdEnt) -> Option<FdEnt> {
        let i = Self::index(fd)?;
        while self.ents.len() <= i {
            self.ents.push(None);
        }
        self.ents[i].replace(ent)
    }

    /// epoll の入れ子を辿る深さの上限（Linux の EP_MAX_NESTS 相当）。
    const EPOLL_MAX_DEPTH: u8 = 5;

    /// 指定のゲスト fd を外す。中身を返すので、呼び出し側は
    /// `close_target` でパイプ端の端数減らしと待ち解除を行う。
    pub fn take(&mut self, fd: u32) -> Option<FdEnt> {
        let i = Self::index(fd)?;
        self.ents.get_mut(i)?.take()
    }

    /// `take` して対象の後始末まで済ませる版。
    /// パイプ端の待ち解除が要る呼び出し側は `take` + `close_target`
    /// を使う。
    pub fn clear(&mut self, fd: u32) {
        if let Some(ent) = self.take(fd) {
            let _ = self.close_target(&ent.target);
        }
    }

    /// FD_CLOEXEC（F_GETFD の FD_CLOEXEC に対応）。
    #[must_use]
    pub fn cloexec(&self, fd: u32) -> bool {
        self.ent(fd).map(|e| e.cloexec).unwrap_or(false)
    }

    /// FD_CLOEXEC を立てる/下ろす（F_SETFD）。対象がなければ偽。
    pub fn set_cloexec(&mut self, fd: u32, on: bool) -> bool {
        match self.ent_mut(fd) {
            Some(ent) => {
                ent.cloexec = on;
                true
            }
            None => false,
        }
    }

    /// FD_CLOEXEC の立ったエントリをすべて外す（execve）。
    /// 対象は `close_target` していないので、呼び出し側が閉じる。
    pub fn take_cloexec(&mut self) -> Vec<FdTarget> {
        let mut out = Vec::new();
        for slot in &mut self.ents {
            if slot.as_ref().is_some_and(|e| e.cloexec)
                && let Some(old) = slot.take()
            {
                out.push(old.target);
            }
        }
        out
    }

    /// ゲスト fd にホストパスを覚える。3 未満は何もしない.
    pub fn remember_path(&mut self, fd: u32, path: String) {
        if let Some(ent) = self.ent_mut(fd) {
            ent.path = Some(path);
        }
    }

    /// ゲスト fd のパスを捨てる。範囲外と 3 未満は何もしない.
    pub fn forget_path(&mut self, fd: u32) {
        if let Some(ent) = self.ent_mut(fd) {
            ent.path = None;
        }
    }

    /// ゲスト fd に覚えたホストパス.
    pub fn path_of(&self, fd: u32) -> Option<&str> {
        self.ent(fd).and_then(|e| e.path.as_deref())
    }

    /// `take` などで外した対象を閉じる。パイプ端・ソケット対の端は
    /// 端数を減らし、epoll 集合なら登録されている対象も再帰的に
    /// 閉じる。返り値は閉じたパイプ端ごとの（パイプ id, 読み側を
    /// 起こす, 書き側を起こす）の列。
    pub fn close_target(&self, target: &FdTarget) -> Vec<(u64, bool, bool)> {
        let mut wakes = Vec::new();
        self.close_target_at(target, 0, &mut wakes);
        wakes
    }

    /// `close_target` の再帰。epoll 集合の中身を辿る深さは
    /// `EPOLL_MAX_DEPTH` で止める（循環・深すぎる入れ子は登録側が
    /// 拒否する規約だが、閉じる側でも暴走しない）。
    fn close_target_at(&self, target: &FdTarget, depth: u8, wakes: &mut Vec<(u64, bool, bool)>) {
        match target {
            FdTarget::PipeEnd { id, read } => {
                let (wr, ww) = self.pipes.borrow_mut().close(*id, *read);
                wakes.push((*id, wr, ww));
            }
            FdTarget::PairSock { pair, end } => {
                pair.borrow_mut().close(*end);
            }
            FdTarget::Epoll(set) if depth < Self::EPOLL_MAX_DEPTH && Rc::strong_count(set) == 1 => {
                // 集合の解体は最後の参照が閉じるときだけ行う。dup・
                // fork・他 epoll への登録で生きている間は保持する。
                let regs = std::mem::take(&mut set.borrow_mut().regs);
                for reg in regs {
                    self.close_target_at(&reg.target, depth + 1, wakes);
                }
            }
            _ => {}
        }
    }

    /// epoll 集合から鍵 `key` の登録を一つ外し、その対象を閉じる
    /// （EPOLL_CTL_DEL）。見つかれば真。
    pub fn epoll_del(&self, set: &Rc<RefCell<EpollSet>>, key: u64) -> bool {
        let reg = {
            let mut set = set.borrow_mut();
            let Some(i) = set.regs.iter().position(|r| r.key == key) else {
                return false;
            };
            set.regs.remove(i)
        };
        let _ = self.close_target(&reg.target);
        true
    }

    /// 開ファイルの複製を持つ表。fork した子の初期状態に使う.
    /// 複製に失敗した対象は空きスロットとして扱う.
    #[must_use]
    pub fn try_clone(&self) -> Self {
        let pipes = Rc::clone(&self.pipes);
        let ents = self
            .ents
            .iter()
            .map(|e| {
                e.as_ref().and_then(|ent| {
                    dup_target(&ent.target, &pipes).map(|target| FdEnt {
                        target,
                        path: ent.path.clone(),
                        cloexec: ent.cloexec,
                    })
                })
            })
            .collect();
        Self { ents, pipes }
    }

    /// fd を別の fd に複製する（dup/dup2/dup3・F_DUPFD）。
    /// 複製に失敗した対象は None。
    #[must_use]
    pub fn dup_target(&self, fd: u32) -> Option<FdTarget> {
        self.target(fd).and_then(|t| dup_target(t, &self.pipes))
    }

    /// 表の外（標準 fd など）にある対象を、この表の共有空間で
    /// 複製する。パイプ端は端数を増やす。
    #[must_use]
    pub fn dup_of(&self, t: &FdTarget) -> Option<FdTarget> {
        dup_target(t, &self.pipes)
    }

    /// パイプの一対を作る。（読み端, 書き端）の対象を返す。
    /// 呼び出し側が `alloc` してゲスト fd にする。
    pub fn pipe_pair(&mut self) -> (FdTarget, FdTarget) {
        let id = self.pipes.borrow_mut().open();
        (
            FdTarget::PipeEnd { id, read: true },
            FdTarget::PipeEnd { id, read: false },
        )
    }

    /// カーネル内ソケット対（socketpair(AF_UNIX)）の両端。
    /// `dgram` は SOCK_DGRAM。呼び出し側が `alloc` する。
    pub fn socket_pair(&mut self, dgram: bool) -> (FdTarget, FdTarget) {
        let pair = Rc::new(RefCell::new(PairSock::new(dgram)));
        (
            FdTarget::PairSock {
                pair: Rc::clone(&pair),
                end: PairEnd::A,
            },
            FdTarget::PairSock {
                pair,
                end: PairEnd::B,
            },
        )
    }

    /// eventfd。`init` は初期値、`semaphore` は EFD_SEMAPHORE。
    pub fn eventfd(&self, init: u64, semaphore: bool) -> FdTarget {
        FdTarget::EventFd(Rc::new(EventState {
            count: Cell::new(init),
            semaphore,
            nonblock: Cell::new(false),
        }))
    }

    /// timerfd。deadline/interval は `TimerState` を直接入れる。
    pub fn timerfd(&self) -> FdTarget {
        FdTarget::TimerFd(Rc::new(RefCell::new(TimerState {
            deadline: None,
            interval: 0,
            expirations: 0,
            nonblock: false,
        })))
    }

    /// signalfd。`mask` は興味のあるシグナルのビット集合。
    pub fn signalfd(&self, mask: u64) -> FdTarget {
        FdTarget::SignalFd(Rc::new(SignalState {
            mask: Cell::new(mask),
            nonblock: Cell::new(false),
        }))
    }

    /// signalfd のマスクを入れ替える（signalfd(fd, mask) の更新経路）。
    /// 対象が signalfd でなければ偽。
    pub fn signalfd_mask(&mut self, fd: u32, mask: u64) -> bool {
        match self.target(fd) {
            Some(FdTarget::SignalFd(s)) => {
                s.mask.set(mask);
                true
            }
            _ => false,
        }
    }

    /// ホストソケットの対象。`sock` は `host::sock::socket` 等で
    /// 非阻止化済みのもの。`nonblock` はゲストが見る初期の
    /// O_NONBLOCK（SOCK_NONBLOCK 指定など）。
    #[cfg(unix)]
    pub fn host_sock(&self, sock: polyisa_host::SockFd, nonblock: bool) -> FdTarget {
        FdTarget::HostSock(Rc::new(HostSockEnt {
            sock,
            nonblock: Cell::new(nonblock),
            connecting: Cell::new(false),
        }))
    }

    /// fd が指すホストソケットの共有記述子。socket 系 syscall の
    /// 正準層が bind/connect/send 等を呼ぶために使う。
    #[cfg(unix)]
    #[must_use]
    pub fn host_sock_of(&self, fd: u32) -> Option<Rc<HostSockEnt>> {
        match self.target(fd) {
            Some(FdTarget::HostSock(s)) => Some(Rc::clone(s)),
            _ => None,
        }
    }

    /// fd が指すカーネル内ソケット対の端（pair と端の向き）。
    /// socketpair の送受・shutdown の正準層が使う。
    #[must_use]
    pub fn pair_of(&self, fd: u32) -> Option<(Rc<RefCell<PairSock>>, PairEnd)> {
        match self.target(fd) {
            Some(FdTarget::PairSock { pair, end }) => Some((Rc::clone(pair), *end)),
            _ => None,
        }
    }

    /// epoll_create。
    pub fn epoll(&self) -> FdTarget {
        FdTarget::Epoll(Rc::new(RefCell::new(EpollSet::default())))
    }

    /// memfd_create。
    pub fn memfd(&self) -> FdTarget {
        FdTarget::MemFd(Rc::new(RefCell::new(MemFile::default())))
    }

    /// epoll 集合へ登録する（EPOLL_CTL_ADD/MOD。`target` は
    /// `dup_of` で複製済みのもの）。自分自身や循環になる登録は
    /// 偽を返す（このとき `target` はその場で閉じる）。
    pub fn epoll_add(
        &self,
        set: &Rc<RefCell<EpollSet>>,
        key: u64,
        target: FdTarget,
        events: u32,
        data: u64,
    ) -> bool {
        // 循環: 登録対象が epoll なら、その中（推移的）にこの集合が
        // 現れてはいけない。
        if let FdTarget::Epoll(inner) = &target
            && (Rc::ptr_eq(inner, set) || epoll_holds(inner, set, 0))
        {
            let _ = self.close_target(&target);
            return false;
        }
        let mut set = set.borrow_mut();
        if let Some(reg) = set.regs.iter_mut().find(|r| r.key == key) {
            // 同じ鍵は MOD 相当。対象は登録時のものを保つので、
            // 新しく渡された複製は閉じる。
            reg.events = events;
            reg.data = data;
            drop(set);
            let _ = self.close_target(&target);
            return true;
        }
        set.regs.push(EpollReg {
            key,
            target,
            events,
            data,
        });
        true
    }

    /// epoll_wait の一回分: 登録のうち準備のあるものを
    /// （events, data）で返す。レベルトリガ相当の再評価なので
    /// 毎回同じ並び（登録順）で同じ結果を返す。
    /// `now`/`pending` は `ready` と同じ時計・保留マスク。
    #[must_use]
    pub fn epoll_collect(
        &self,
        set: &Rc<RefCell<EpollSet>>,
        now: u64,
        pending: u64,
        max: usize,
    ) -> Vec<(u32, u64)> {
        let set = set.borrow();
        let mut out = Vec::new();
        for reg in &set.regs {
            let r = target_ready(&reg.target, &self.pipes, now, pending, 0);
            // LT 近似: events は興味側の値をそのまま、実際の成立は
            // read/write/err/hup に応じて POLL* ビットへ写す。
            let mut fired = 0u32;
            if r.read {
                fired |= 1; // POLLIN
            }
            if r.write {
                fired |= 4; // POLLOUT
            }
            if r.err {
                fired |= 8; // POLLERR
            }
            if r.hup {
                fired |= 0x10; // POLLHUP
            }
            if reg_events_match(reg.events, r) {
                out.push((fired & (reg.events | 8 | 0x10), reg.data));
                if out.len() >= max {
                    break;
                }
            }
        }
        out
    }

    /// fd が指す epoll 集合。epoll_ctl/epoll_wait の正準層が使う。
    #[must_use]
    pub fn epoll_of(&self, fd: u32) -> Option<Rc<RefCell<EpollSet>>> {
        match self.target(fd) {
            Some(FdTarget::Epoll(s)) => Some(Rc::clone(s)),
            _ => None,
        }
    }

    /// fd 待ちに使う最速の期限（ナノ秒）。TimerFd の deadline を
    /// 返し、epoll 集合は登録対象の期限の最小値を返す。
    /// 他の対象・無い fd では None。
    #[must_use]
    pub fn wait_deadline(&self, fd: u32) -> Option<u64> {
        self.deadline_of(self.target(fd)?, 0)
    }

    /// 対象の期限。epoll 集合は登録対象の期限を深さ制限つきで
    /// 再帰的にたどり、最小値を返す。
    fn deadline_of(&self, target: &FdTarget, depth: u8) -> Option<u64> {
        match target {
            FdTarget::TimerFd(s) => s.borrow().deadline,
            FdTarget::Epoll(set) if depth < Self::EPOLL_MAX_DEPTH => set
                .borrow()
                .regs
                .iter()
                .filter_map(|r| self.deadline_of(&r.target, depth + 1))
                .min(),
            _ => None,
        }
    }

    /// fd 待ちでホスト側を poll すべき生 fd の列。HostSock は
    /// `ev`（POLLIN/POLLOUT 値の興味ビット）をそのまま返し、
    /// epoll 集合は登録対象を興味イベントつきで展開する。
    /// それ以外の対象は空。
    #[cfg(unix)]
    #[must_use]
    pub fn host_watches(&self, fd: u32, ev: u32) -> Vec<(polyisa_host::RawFd, i16)> {
        let mut out = Vec::new();
        if let Some(t) = self.target(fd) {
            target_host_watches(t, ev, 0, &mut out);
        }
        out
    }

    /// ftruncate。File はホストの `set_len`、MemFd は中身の長さを
    /// 変える（伸びた分は 0）。対象外は偽。
    pub fn truncate(&mut self, fd: u32, len: u64) -> bool {
        match self.target(fd) {
            Some(FdTarget::File(f)) => f.set_len(len).is_ok(),
            Some(FdTarget::MemFd(m)) => {
                let mut m = m.borrow_mut();
                m.data.resize(len as usize, 0);
                if m.pos > len {
                    m.pos = len;
                }
                true
            }
            _ => false,
        }
    }

    /// fd の O_NONBLOCK。対象種別ごとの置き場所を見る。
    /// ホストのファイルには記録しない（通常ファイルでは読み書きに
    /// 影響しないため、旗だけ持っても読み出せない場所がない）。
    #[must_use]
    pub fn nonblock(&self, fd: u32) -> bool {
        match self.target(fd) {
            Some(FdTarget::PipeEnd { id, read }) => self.pipes.borrow().nonblock(*id, *read),
            Some(FdTarget::PairSock { pair, end }) => pair.borrow().is_nonblock(*end),
            #[cfg(unix)]
            Some(FdTarget::HostSock(s)) => s.nonblock.get(),
            Some(FdTarget::EventFd(s)) => s.nonblock.get(),
            Some(FdTarget::TimerFd(s)) => s.borrow().nonblock,
            Some(FdTarget::SignalFd(s)) => s.nonblock.get(),
            Some(FdTarget::MemFd(m)) => m.borrow().nonblock,
            Some(FdTarget::Terminal(n)) => n.get(),
            _ => false,
        }
    }

    /// fd の O_NONBLOCK を変える。対象がなければ偽。
    /// ホストのファイルは成功として扱うが記録しない（上記）。
    pub fn set_nonblock(&mut self, fd: u32, on: bool) -> bool {
        match self.target(fd) {
            Some(FdTarget::PipeEnd { id, read }) => {
                let (id, read) = (*id, *read);
                self.pipes.borrow_mut().set_nonblock(id, read, on)
            }
            Some(FdTarget::PairSock { pair, end }) => {
                pair.borrow_mut().set_nonblock(*end, on);
                true
            }
            #[cfg(unix)]
            Some(FdTarget::HostSock(s)) => {
                s.nonblock.set(on);
                true
            }
            Some(FdTarget::EventFd(s)) => {
                s.nonblock.set(on);
                true
            }
            Some(FdTarget::TimerFd(s)) => {
                s.borrow_mut().nonblock = on;
                true
            }
            Some(FdTarget::SignalFd(s)) => {
                s.nonblock.set(on);
                true
            }
            Some(FdTarget::MemFd(m)) => {
                m.borrow_mut().nonblock = on;
                true
            }
            Some(FdTarget::Terminal(n)) => {
                n.set(on);
                true
            }
            Some(FdTarget::File(_)) => true,
            _ => false,
        }
    }

    /// 準備状態を集める。`now` は単調時計の今（ナノ秒。timerfd の
    /// 判定に使う。使わないなら任意の値）、`pending` は ABI の
    /// 保留シグナル集合（signalfd の判定に使う）。
    #[must_use]
    pub fn ready(&self, fd: u32, now: u64, pending: u64) -> Ready {
        match self.target(fd) {
            None => Ready::default(),
            Some(FdTarget::File(_)) | Some(FdTarget::MemFd(_)) => Ready {
                read: true,
                write: true,
                ..Ready::default()
            },
            Some(FdTarget::Terminal(_)) => Ready {
                read: true,
                write: true,
                ..Ready::default()
            },
            Some(FdTarget::PipeEnd { id, read }) => self.pipes.borrow().ready(*id, *read),
            Some(FdTarget::PairSock { pair, end }) => pair.borrow().ready(*end),
            #[cfg(unix)]
            Some(FdTarget::HostSock(s)) => sock_ready(s.sock.ready()),
            Some(FdTarget::EventFd(s)) => {
                let count = s.count.get();
                Ready {
                    read: count > 0,
                    write: count < u64::MAX - 1,
                    ..Ready::default()
                }
            }
            Some(FdTarget::TimerFd(s)) => s.borrow_mut().ready(now),
            Some(FdTarget::SignalFd(s)) => Ready {
                read: pending & s.mask.get() != 0,
                ..Ready::default()
            },
            Some(FdTarget::Reserved) => Ready::default(),
            Some(FdTarget::Epoll(set)) => {
                let set = set.borrow();
                let any = set.regs.iter().any(|reg| {
                    let r = target_ready(&reg.target, &self.pipes, now, pending, 0);
                    reg_events_match(reg.events, r)
                });
                Ready {
                    read: any,
                    ..Ready::default()
                }
            }
        }
    }

    /// `read` の対象別実装。`max` は読む上限。
    /// Signalfd は ABI 側の保留照合が要るので `Inval` を返し、
    /// 呼び出し側で扱う。
    pub fn read(&mut self, fd: u32, max: usize) -> FdRead {
        if matches!(self.target(fd), Some(FdTarget::File(_))) {
            return self.read_file(fd, max);
        }
        let Some(target) = self.target(fd) else {
            return FdRead::BadFd;
        };
        match target {
            FdTarget::File(_) => unreachable!(),
            FdTarget::PipeEnd { id, read } => {
                if !*read {
                    return FdRead::BadFd;
                }
                let (id, max) = (*id, max);
                match self.pipes.borrow_mut().read(id, max) {
                    PipeRead::Bytes(b) => FdRead::Bytes(b),
                    PipeRead::Eof => FdRead::Eof,
                    PipeRead::Empty => FdRead::Empty,
                }
            }
            FdTarget::PairSock { pair, end } => {
                let (pair, end) = (Rc::clone(pair), *end);
                match pair.borrow_mut().recv(end, max) {
                    PipeRead::Bytes(b) => FdRead::Bytes(b),
                    PipeRead::Eof => FdRead::Eof,
                    PipeRead::Empty => FdRead::Empty,
                }
            }
            #[cfg(unix)]
            FdTarget::HostSock(s) => match s.sock.recv(max.min(65536)) {
                Ok(b) if b.is_empty() => FdRead::Eof,
                Ok(b) => FdRead::Bytes(b),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => FdRead::Empty,
                Err(e) => FdRead::Host(e),
            },
            FdTarget::EventFd(s) => {
                if max < 8 {
                    return FdRead::Inval;
                }
                let count = s.count.get();
                if count == 0 {
                    return FdRead::Empty;
                }
                if s.semaphore {
                    s.count.set(count - 1);
                    FdRead::Count(1)
                } else {
                    s.count.set(0);
                    FdRead::Count(count)
                }
            }
            FdTarget::TimerFd(s) => {
                if max < 8 {
                    return FdRead::Inval;
                }
                // `now` は呼び出し側の時計に依るので read では
                // catch_up を呼び出し側に任せる。ここでは溜まった
                // 回数だけを読む（catch_up 済み前提）。
                let mut st = s.borrow_mut();
                if st.expirations == 0 {
                    FdRead::Empty
                } else {
                    let n = st.expirations;
                    st.expirations = 0;
                    FdRead::Count(n)
                }
            }
            FdTarget::SignalFd(_) | FdTarget::Epoll(_) => FdRead::Inval,
            FdTarget::Reserved => FdRead::BadFd,
            FdTarget::MemFd(m) => {
                let mut m = m.borrow_mut();
                if m.pos as usize >= m.data.len() {
                    return FdRead::Eof;
                }
                let n = max.min(m.data.len() - m.pos as usize);
                let buf = m.data[m.pos as usize..m.pos as usize + n].to_vec();
                m.pos += n as u64;
                FdRead::Bytes(buf)
            }
            FdTarget::Terminal(_) => {
                use std::io::Read as _;
                let mut buf = vec![0u8; max.min(4096)];
                match std::io::stdin().read(&mut buf) {
                    Ok(0) => FdRead::Eof,
                    Ok(n) => {
                        buf.truncate(n);
                        FdRead::Bytes(buf)
                    }
                    Err(e) => FdRead::Host(e),
                }
            }
        }
    }

    /// ホストファイルの read。
    fn read_file(&mut self, fd: u32, max: usize) -> FdRead {
        use std::io::Read as _;
        let Some(file) = self.file_mut(fd) else {
            return FdRead::BadFd;
        };
        if file.metadata().map(|m| m.is_dir()).unwrap_or(false) {
            return FdRead::IsDir;
        }
        let mut buf = vec![0u8; max.min(65536)];
        match file.read(&mut buf) {
            Ok(0) => FdRead::Eof,
            Ok(n) => {
                buf.truncate(n);
                FdRead::Bytes(buf)
            }
            Err(e) => FdRead::Host(e),
        }
    }

    /// `write` の対象別実装。
    pub fn write(&mut self, fd: u32, bytes: &[u8]) -> FdWrite {
        if matches!(self.target(fd), Some(FdTarget::File(_))) {
            return self.write_file(fd, bytes);
        }
        let Some(target) = self.target(fd) else {
            return FdWrite::BadFd;
        };
        match target {
            FdTarget::File(_) => unreachable!(),
            FdTarget::PipeEnd { id, read } => {
                if *read {
                    return FdWrite::BadFd;
                }
                let id = *id;
                match self.pipes.borrow_mut().write(id, bytes) {
                    Some(n) => FdWrite::Done(n),
                    None => FdWrite::Pipe,
                }
            }
            FdTarget::PairSock { pair, end } => {
                let (pair, end) = (Rc::clone(pair), *end);
                match pair.borrow_mut().send(end, bytes) {
                    Some(n) => FdWrite::Done(n),
                    None => FdWrite::Pipe,
                }
            }
            #[cfg(unix)]
            FdTarget::HostSock(s) => match s.sock.send(bytes) {
                Ok(n) => FdWrite::Done(n),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => FdWrite::Full,
                Err(e) => FdWrite::Host(e),
            },
            FdTarget::EventFd(_) => {
                // カウンタの復元はゲストのエンディアンを知る
                // 呼び出し側の仕事。`write_eventfd` を使う。
                FdWrite::Inval
            }
            FdTarget::MemFd(m) => {
                let mut m = m.borrow_mut();
                let pos = m.pos as usize;
                let end = pos.saturating_add(bytes.len());
                if pos > m.data.len() {
                    m.data.resize(pos, 0);
                }
                if end > m.data.len() {
                    m.data.resize(end, 0);
                }
                m.data[pos..end].copy_from_slice(bytes);
                m.pos = end as u64;
                FdWrite::Done(bytes.len())
            }
            FdTarget::TimerFd(_) | FdTarget::SignalFd(_) | FdTarget::Epoll(_) => FdWrite::Inval,
            FdTarget::Reserved => FdWrite::BadFd,
            FdTarget::Terminal(_) => {
                use std::io::Write as _;
                match std::io::stdout().write(bytes) {
                    Ok(n) => FdWrite::Done(n),
                    Err(e) => FdWrite::Host(e),
                }
            }
        }
    }

    /// eventfd への加算。値 `v` は呼び出し側がゲストのエンディアンで
    /// 復元済みのもの。対象が eventfd でなければ `BadFd`。
    pub fn write_eventfd(&mut self, fd: u32, v: u64) -> FdWrite {
        match self.target(fd) {
            Some(FdTarget::EventFd(s)) => {
                let cur = s.count.get();
                // 0xFFFF_FFFF_FFFF_FFFF の書き込み自体は EINVAL。
                // 合計が MAX に達する書き込みは EAGAIN/待ち。
                if v == u64::MAX {
                    return FdWrite::Inval;
                }
                if cur.saturating_add(v) == u64::MAX {
                    return FdWrite::Full;
                }
                s.count.set(cur + v);
                FdWrite::Done(8)
            }
            Some(_) => FdWrite::BadFd,
            None => FdWrite::BadFd,
        }
    }

    /// ホストファイルの write。
    fn write_file(&mut self, fd: u32, bytes: &[u8]) -> FdWrite {
        use std::io::Write as _;
        let Some(file) = self.file_mut(fd) else {
            return FdWrite::BadFd;
        };
        match file.write(bytes) {
            Ok(n) => FdWrite::Done(n),
            Err(e) => FdWrite::Host(e),
        }
    }

    /// `lseek` の対象別実装。whence は 0=SET/1=CUR/2=END。
    pub fn seek(&mut self, fd: u32, off: i64, whence: u32) -> FdSeek {
        use std::io::{Seek as _, SeekFrom};
        if matches!(self.target(fd), Some(FdTarget::File(_))) {
            let from = match whence {
                0 => SeekFrom::Start(off as u64),
                1 => SeekFrom::Current(off),
                2 => SeekFrom::End(off),
                _ => return FdSeek::Inval,
            };
            let Some(file) = self.file_mut(fd) else {
                return FdSeek::Pipe;
            };
            return match file.seek(from) {
                Ok(p) => FdSeek::Pos(p),
                Err(e) => FdSeek::Host(e),
            };
        }
        match self.target(fd) {
            Some(FdTarget::MemFd(m)) => {
                let mut m = m.borrow_mut();
                let base: i128 = match whence {
                    0 => 0,
                    1 => m.pos as i128,
                    2 => m.data.len() as i128,
                    _ => return FdSeek::Inval,
                };
                let pos = base + off as i128;
                if pos < 0 {
                    return FdSeek::Inval;
                }
                m.pos = pos as u64;
                FdSeek::Pos(m.pos)
            }
            Some(_) => FdSeek::Pipe,
            None => FdSeek::Pipe,
        }
    }
}

/// 対象の複製。dup・fork の表複製が使う。
/// 複製できない対象（ホストファイルの複製失敗）は None。
#[must_use]
fn dup_target(target: &FdTarget, pipes: &Rc<RefCell<PipeTable>>) -> Option<FdTarget> {
    match target {
        FdTarget::File(f) => f.try_clone().ok().map(FdTarget::File),
        FdTarget::PipeEnd { id, read } => {
            pipes.borrow_mut().dup(*id, *read);
            Some(FdTarget::PipeEnd {
                id: *id,
                read: *read,
            })
        }
        FdTarget::PairSock { pair, end } => {
            pair.borrow_mut().dup(*end);
            Some(FdTarget::PairSock {
                pair: Rc::clone(pair),
                end: *end,
            })
        }
        #[cfg(unix)]
        FdTarget::HostSock(s) => Some(FdTarget::HostSock(Rc::clone(s))),
        FdTarget::EventFd(s) => Some(FdTarget::EventFd(Rc::clone(s))),
        FdTarget::TimerFd(s) => Some(FdTarget::TimerFd(Rc::clone(s))),
        FdTarget::SignalFd(s) => Some(FdTarget::SignalFd(Rc::clone(s))),
        FdTarget::Epoll(s) => Some(FdTarget::Epoll(Rc::clone(s))),
        FdTarget::MemFd(s) => Some(FdTarget::MemFd(Rc::clone(s))),
        FdTarget::Terminal(n) => Some(FdTarget::Terminal(Rc::clone(n))),
        FdTarget::Reserved => Some(FdTarget::Reserved),
    }
}

/// 単独の対象の準備状態（epoll が登録対象を評価するときに使う）。
#[must_use]
fn target_ready(
    target: &FdTarget,
    pipes: &Rc<RefCell<PipeTable>>,
    now: u64,
    pending: u64,
    depth: u8,
) -> Ready {
    match target {
        FdTarget::File(_) | FdTarget::MemFd(_) => Ready {
            read: true,
            write: true,
            ..Ready::default()
        },
        FdTarget::Terminal(_) => Ready {
            read: true,
            write: true,
            ..Ready::default()
        },
        FdTarget::PipeEnd { id, read } => pipes.borrow().ready(*id, *read),
        FdTarget::PairSock { pair, end } => pair.borrow().ready(*end),
        #[cfg(unix)]
        FdTarget::HostSock(s) => sock_ready(s.sock.ready()),
        FdTarget::EventFd(s) => {
            let count = s.count.get();
            Ready {
                read: count > 0,
                write: count < u64::MAX - 1,
                ..Ready::default()
            }
        }
        FdTarget::TimerFd(s) => s.borrow_mut().ready(now),
        FdTarget::SignalFd(s) => Ready {
            read: pending & s.mask.get() != 0,
            ..Ready::default()
        },
        FdTarget::Reserved => Ready::default(),
        FdTarget::Epoll(set) => {
            if depth >= FdTable::EPOLL_MAX_DEPTH {
                return Ready::default();
            }
            let set = set.borrow();
            let any = set.regs.iter().any(|reg| {
                reg_events_match(
                    reg.events,
                    target_ready(&reg.target, pipes, now, pending, depth + 1),
                )
            });
            Ready {
                read: any,
                ..Ready::default()
            }
        }
    }
}

/// 一つの対象について、ホスト側を poll すべき生 fd を `out` へ
/// 足す。epoll 集合は登録ごとの興味イベントで再帰展開する。
/// `ev` は POLLIN/POLLOUT 値の興味ビット。
#[cfg(unix)]
fn target_host_watches(
    target: &FdTarget,
    ev: u32,
    depth: u8,
    out: &mut Vec<(polyisa_host::RawFd, i16)>,
) {
    if depth > FdTable::EPOLL_MAX_DEPTH {
        return;
    }
    match target {
        FdTarget::HostSock(s) => out.push((s.sock.raw(), ev as i16)),
        FdTarget::Epoll(set) => {
            for reg in &set.borrow().regs {
                // EPOLLIN/PRI/RDNORM/RDBAND/RDHUP → POLLIN、
                // EPOLLOUT/WRNORM/WRBAND → POLLOUT。ERR/HUP は
                // ホストの poll が興味無しでも報告する。
                let ev = (u32::from(reg.events & 0x20C3 != 0))
                    | (u32::from(reg.events & 0x304 != 0) << 2);
                target_host_watches(&reg.target, ev, depth + 1, out);
            }
        }
        _ => {}
    }
}

/// `hay` の登録の中に `needle` の epoll 集合が（推移的に）含まれるか。
/// epoll_add の循環検査に使う。
fn epoll_holds(hay: &Rc<RefCell<EpollSet>>, needle: &Rc<RefCell<EpollSet>>, depth: u8) -> bool {
    if depth >= FdTable::EPOLL_MAX_DEPTH {
        return false;
    }
    hay.borrow().regs.iter().any(|reg| match &reg.target {
        FdTarget::Epoll(inner) => {
            Rc::ptr_eq(inner, needle) || epoll_holds(inner, needle, depth + 1)
        }
        _ => false,
    })
}

/// epoll の興味イベントと準備状態の照合。ERR・HUP は興味に
/// 無くても常に起こす。読み系は
/// IN/PRI/RDNORM/RDBAND/RDHUP=0x20C3、書き系は
/// OUT/WRNORM/WRBAND=0x304（asm-generic の値）。
fn reg_events_match(events: u32, r: Ready) -> bool {
    r.err || r.hup || (r.read && events & 0x20C3 != 0) || (r.write && events & 0x304 != 0)
}

/// ホストの準備状態をこちらの型に写す。
#[cfg(unix)]
fn sock_ready(r: polyisa_host::SockReady) -> Ready {
    Ready {
        read: r.read,
        write: r.write,
        hup: r.hup,
        err: r.err,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_state(semaphore: bool) -> Rc<EventState> {
        Rc::new(EventState {
            count: Cell::new(0),
            semaphore,
            nonblock: Cell::new(false),
        })
    }

    #[test]
    fn pipe_write_read_then_eof_when_writer_closes() {
        let mut t = FdTable::default();
        let (rd, wr) = t.pipe_pair();
        let r = t.alloc(rd);
        let w = t.alloc(wr);
        assert!(matches!(t.write(w, b"hi"), FdWrite::Done(2)));
        assert!(matches!(t.read(r, 4), FdRead::Bytes(b) if b == b"hi"));
        assert!(matches!(t.read(r, 1), FdRead::Empty));
        t.clear(w);
        assert!(matches!(t.read(r, 1), FdRead::Eof));
    }

    #[test]
    fn pipe_dup_end_holds_count_until_last_close() {
        let mut t = FdTable::default();
        let (rd, wr) = t.pipe_pair();
        let r = t.alloc(rd);
        let w = t.alloc(wr);
        let w2 = t.alloc(t.dup_target(w).unwrap());
        t.clear(w);
        // 複製した書き端が残る限り読み側に EOF は来ない。
        assert!(!t.ready(r, 0, 0).hup);
        assert!(matches!(t.write(w2, b"x"), FdWrite::Done(1)));
        t.clear(w2);
        assert!(t.ready(r, 0, 0).hup);
    }

    #[test]
    fn pairsock_dup_end_survives_original_close() {
        let mut t = FdTable::default();
        let pair = Rc::new(RefCell::new(PairSock::new(false)));
        let a = t.alloc(FdTarget::PairSock {
            pair: Rc::clone(&pair),
            end: PairEnd::A,
        });
        let b = t.alloc(FdTarget::PairSock {
            pair: Rc::clone(&pair),
            end: PairEnd::B,
        });
        let a2 = t.alloc(t.dup_target(a).unwrap());
        t.clear(a);
        // 複製が残るので B からはまだ送れる。
        assert!(matches!(t.write(b, b"x"), FdWrite::Done(1)));
        t.clear(a2);
        assert!(matches!(t.write(b, b"x"), FdWrite::Pipe));
    }

    #[test]
    fn pairsock_peer_shut_rd_makes_send_pipe() {
        let mut t = FdTable::default();
        let pair = Rc::new(RefCell::new(PairSock::new(false)));
        let b = t.alloc(FdTarget::PairSock {
            pair: Rc::clone(&pair),
            end: PairEnd::B,
        });
        pair.borrow_mut().shutdown(PairEnd::A, 0);
        assert!(matches!(t.write(b, b"x"), FdWrite::Pipe));
    }

    #[test]
    fn eventfd_count_read_and_semaphore() {
        let mut t = FdTable::default();
        let e = t.alloc(FdTarget::EventFd(event_state(false)));
        assert!(matches!(t.write_eventfd(e, 5), FdWrite::Done(8)));
        assert!(matches!(t.read(e, 8), FdRead::Count(5)));
        assert!(matches!(t.read(e, 8), FdRead::Empty));
        // 8 バイト未満は EINVAL。
        assert!(matches!(t.read(e, 4), FdRead::Inval));

        let s = t.alloc(FdTarget::EventFd(event_state(true)));
        let _ = t.write_eventfd(s, 3);
        assert!(matches!(t.read(s, 8), FdRead::Count(1)));
        assert!(matches!(t.read(s, 8), FdRead::Count(1)));
    }

    #[test]
    fn timerfd_catch_up_one_shot_and_periodic() {
        let mut one = TimerState {
            deadline: Some(100),
            interval: 0,
            expirations: 0,
            nonblock: false,
        };
        one.catch_up(50);
        assert_eq!(one.expirations, 0);
        one.catch_up(150);
        assert_eq!(one.expirations, 1);
        assert_eq!(one.deadline, None);

        let mut per = TimerState {
            deadline: Some(100),
            interval: 10,
            expirations: 0,
            nonblock: false,
        };
        per.catch_up(145);
        assert_eq!(per.expirations, 5);
        assert_eq!(per.deadline, Some(150));
    }

    #[test]
    fn memfd_write_seek_read() {
        let mut t = FdTable::default();
        let m = t.alloc(FdTarget::MemFd(Rc::new(RefCell::new(MemFile::default()))));
        assert!(matches!(t.write(m, b"hello"), FdWrite::Done(5)));
        assert!(matches!(t.seek(m, 0, 0), FdSeek::Pos(0)));
        assert!(matches!(t.read(m, 8), FdRead::Bytes(b) if b == b"hello"));
        assert!(matches!(t.seek(m, -1, 2), FdSeek::Pos(4)));
        assert!(matches!(t.read(m, 8), FdRead::Bytes(b) if b == b"o"));
    }

    #[test]
    fn alloc_where_pads_until_free() {
        let mut t = FdTable::default();
        let fd = t.alloc_where(FdTarget::Reserved, |i| 3 + i >= 100);
        assert_eq!(fd, 100);
        assert!(t.ent(100).is_some());
    }

    #[test]
    fn take_cloexec_takes_only_marked() {
        let mut t = FdTable::default();
        let keep = t.alloc(FdTarget::Reserved);
        let drop_ = t.alloc(FdTarget::Reserved);
        assert!(t.set_cloexec(drop_, true));
        let taken = t.take_cloexec();
        assert_eq!(taken.len(), 1);
        assert!(t.ent(keep).is_some());
        assert!(t.ent(drop_).is_none());
    }

    #[test]
    fn try_clone_shares_pipe_counts() {
        let mut t = FdTable::default();
        let (rd, wr) = t.pipe_pair();
        let r = t.alloc(rd);
        let w = t.alloc(wr);
        assert!(matches!(t.write(w, b"hi"), FdWrite::Done(2)));
        let mut child = t.try_clone();
        // 親が読み端を閉じても、子の複製がある限り書ける。
        t.clear(r);
        assert!(matches!(child.write(w, b"!"), FdWrite::Done(1)));
        assert!(matches!(child.read(r, 8), FdRead::Bytes(b) if b == b"hi!"));
    }

    #[test]
    fn place_close_closes_displaced_reader() {
        let mut t = FdTable::default();
        let (rd, wr) = t.pipe_pair();
        let r = t.alloc(rd);
        let w = t.alloc(wr);
        t.place_close(r, FdTarget::Reserved);
        assert!(matches!(t.write(w, b"x"), FdWrite::Pipe));
    }

    #[test]
    fn epoll_del_closes_registered_target() {
        let mut t = FdTable::default();
        let set = Rc::new(RefCell::new(EpollSet::default()));
        let (rd, wr) = t.pipe_pair();
        let key = rd.epoll_key();
        let w = t.alloc(wr);
        // 登録は dup 相当。表の読み端とは別に数を持つ。
        set.borrow_mut().regs.push(EpollReg {
            key,
            target: t.dup_of(&rd).unwrap(),
            events: 1,
            data: 0,
        });
        let r = t.alloc(rd);
        assert!(t.epoll_del(&set, key));
        assert!(!t.epoll_del(&set, key));
        // 登録分は閉じたが表の読み端が残るのでまだ書ける。
        assert!(matches!(t.write(w, b"x"), FdWrite::Done(1)));
        t.clear(r);
        assert!(matches!(t.write(w, b"x"), FdWrite::Pipe));
    }

    #[test]
    fn close_target_returns_pipe_wake_for_reader_loss() {
        let mut t = FdTable::default();
        let (rd, wr) = t.pipe_pair();
        let id = match &rd {
            FdTarget::PipeEnd { id, .. } => *id,
            _ => unreachable!(),
        };
        let _w = t.alloc(wr);
        let r = t.alloc(rd);
        let ent = t.take(r).unwrap();
        let wakes = t.close_target(&ent.target);
        assert!(wakes.iter().any(|&(i, _r, w)| i == id && w));
    }
}
