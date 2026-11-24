// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! ホストの fd に対する待ちを請け負う作業用ホストスレッド `HostIo`。
//!
//! ゲストスレッドがホストのソケット（非阻止）を待つとき、ABI 側は
//! 監視集合を `set_watches` で渡し、全ゲストスレッドが待ちに沈んだ
//! ときだけ主スレッドが `wait_done` で受信を待つ。作業スレッドは
//! 制御ソケットと監視集合を host `poll` で待ち、準備が立った fd を
//! イベントとして返す。実行可能なゲストがいる間は主スレッドはここを
//! 呼ばないので、通常経路の決定性は変わらない。
//!
//! `set_watches` の一回の呼び出しは「一回の腕（arm）」として働く。
//! 立った監視は集合が更新されるまで再送しないので、ABI 側は
//! イベントを受け取って待ちを張り直すたびに `set_watches` を
//! 呼び直す（同じ集合でもよい）。
//!
//! 作業スレッドを作れない環境では `spawn` が `None` を返す。そのとき
//! ABI 側は `polyisa_host::poll` を主スレッドで直接使う。

use std::io;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use polyisa_host::RawFd;

/// `poll` の POLLIN。
const POLLIN: i16 = 0x0001;
/// `poll` の POLLERR。
const POLLERR: i16 = 0x0008;
/// `poll` の POLLHUP。
const POLLHUP: i16 = 0x0010;
/// `poll` の POLLNVAL。
const POLLNVAL: i16 = 0x0020;

/// 作業スレッドへ渡す監視要求（世代番号つき。`set_watches` ごとに増える）。
type WatchReq = (u64, WatchList);

/// 監視するホスト fd と興味イベント（`poll` の events 欄）。
type WatchList = Vec<(RawFd, i16)>;

/// 作業スレッドから返る準備済みイベント。
/// （ホスト fd, `poll` の revents）。
pub type HostEvent = Vec<(RawFd, i16)>;

/// 作業用ホストスレッドへの窓口。`Rc` で各 `Linux` 状態が共有する
/// （queue 共有と同じ配線。プロセス系で一つ）。
#[derive(Debug)]
pub struct HostIo {
    /// 制御ソケット（socketpair の送信側）。1 バイトで作業スレッドを起こす。
    kick: polyisa_host::SockFd,
    /// 最新の監視要求。作業スレッドが周回ごとに読む。
    watches: Arc<Mutex<WatchReq>>,
    /// 完了イベントの受信口。
    done: mpsc::Receiver<HostEvent>,
}

impl HostIo {
    /// 作業スレッドを起こす。失敗したら `None`。
    pub fn spawn() -> Option<Self> {
        // AF_UNIX SOCK_STREAM の対を制御経路にする。
        let (kick, ctrl) = polyisa_host::sock::socketpair(1, 1, 0).ok()?;
        // どちらも非阻止: kick は満杯でも 1 バイト捨てればよい、
        // ctrl は読み切り判定に WouldBlock を使う。
        kick.set_nonblock(true).ok()?;
        ctrl.set_nonblock(true).ok()?;
        let watches: Arc<Mutex<WatchReq>> = Arc::new(Mutex::new((0, Vec::new())));
        let (tx, rx) = mpsc::channel::<HostEvent>();
        let thread_watches = Arc::clone(&watches);
        std::thread::Builder::new()
            .name("polyisa-hostio".to_string())
            .spawn(move || worker(ctrl, thread_watches, tx))
            .ok()?;
        Some(Self {
            kick,
            watches,
            done: rx,
        })
    }

    /// 監視集合を更新して作業スレッドを起こす。世代を一つ進め、
    /// この世代の準備イベントを一度だけ受け取れるように腕を張る。
    pub fn set_watches(&self, watches: &[(RawFd, i16)]) {
        {
            let mut w = self.watches.lock().unwrap_or_else(|e| e.into_inner());
            w.0 = w.0.wrapping_add(1);
            w.1 = watches.to_vec();
        }
        // 1 バイト書けば起きる。満杯（EAGAIN）は既に起きているので無視。
        let _ = self.kick.send(b"\0");
    }

    /// 完了イベントを受け取る。`timeout` は上限（None は無期限）。
    /// 期限切れ・未着は `None`。
    pub fn wait_done(&self, timeout: Option<Duration>) -> Option<HostEvent> {
        match timeout {
            Some(t) => self.done.recv_timeout(t).ok(),
            None => self.done.recv().ok(),
        }
    }
}

/// 作業スレッド。制御ソケットと監視集合を `poll` で待ち、
/// 準備が立った fd を done チャネルへ流す。制御ソケットが EOF
/// （`HostIo` が捨てられた）なら終わる。発射済みの世代では
/// 制御ソケットだけを待って再送を抑える。
fn worker(
    ctrl: polyisa_host::SockFd,
    watches: Arc<Mutex<WatchReq>>,
    done: mpsc::Sender<HostEvent>,
) {
    let mut fired_gen: Option<u64> = None;
    loop {
        let (generation, list) = {
            let w = watches.lock().unwrap_or_else(|e| e.into_inner());
            (w.0, w.1.clone())
        };
        let mut fds: WatchList = vec![(ctrl.raw(), POLLIN)];
        // この世代で既に発射済みなら、次の set_watches（制御ソケットへの
        // 書き込み）だけを待つ。そうでなければ監視集合も待つ。
        let armed = Some(generation) != fired_gen;
        if armed {
            fds.extend_from_slice(&list);
        }
        // 無期限待ち。失敗したら抜ける（fd が閉じられた等）。
        if polyisa_host::sock::poll(&mut fds, -1).is_err() {
            return;
        }
        if fds[0].1 & (POLLIN | POLLERR | POLLHUP | POLLNVAL) != 0 {
            // 制御経路を読み切る。EOF/エラーは終了、EAGAIN は次周回。
            loop {
                match ctrl.recv(64) {
                    Ok(b) if b.is_empty() => return,
                    Ok(_) => continue,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => return,
                }
            }
            continue;
        }
        // armed のときだけ監視集合の結果がある（armed=false では
        // fds は制御ソケットだけなのでここには来ない）。
        let ready: HostEvent = fds[1..]
            .iter()
            .filter(|&&(_, rev)| rev != 0)
            .copied()
            .collect();
        if !ready.is_empty() {
            if done.send(ready).is_err() {
                return;
            }
            fired_gen = Some(generation);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// 監視したホスト fd に書き込みが届くとイベントが返る。
    /// 発射後は世代を張り直すまで再送しない。
    #[test]
    fn fires_once_per_arm() {
        let Some(io) = HostIo::spawn() else {
            return; // ソケット対を作れない環境
        };
        let (a, b) = polyisa_host::sock::socketpair(1, 1, 0).unwrap();
        a.set_nonblock(true).unwrap();
        io.set_watches(&[(a.raw(), POLLIN)]);
        // まだデータがないのでイベントもない。
        assert!(io.wait_done(Some(Duration::from_millis(50))).is_none());
        b.send(b"x").unwrap();
        let ev = io.wait_done(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].0, a.raw());
        assert_ne!(ev[0].1 & POLLIN, 0);
        // 張り直さない限り同じ世代の再送はない。
        assert!(io.wait_done(Some(Duration::from_millis(50))).is_none());
        // 張り直せば（まだ読めるので）もう一度届く。
        io.set_watches(&[(a.raw(), POLLIN)]);
        let ev = io.wait_done(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].0, a.raw());
        assert_ne!(ev[0].1 & POLLIN, 0);
    }
}
