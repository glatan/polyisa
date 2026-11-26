# 仮想カーネル・ローダ・OS パーソナリティ

ユーザーモードの OS サービスは、ホスト OS へシステムコールを素通しせず、プロセス内の仮想カーネル（`kernel`）、実行ファイルローダ（`loader`）、および 5 つの OS パーソナリティ（`os-linux`・`os-v7`・`os-bsd`・`os-wasi`・`os-semihost`）で提供する。

## プロセス内仮想カーネルを採る理由

QEMU ユーザーモードのようにシステムコールをホスト Linux へ直接変換する方式は、ホストを Linux に限定し、ホストのスレッドスケジューリングに依存して決定性を失い、膨大な FFI 宣言も必要になる。polyisa はホスト移植性・外部依存ゼロ・決定性・複数 OS 対応（Linux 以外の Unix V7・4.3BSD・WASI・Semihosting）を満たすため、プロセス・スレッド・fd・パイプ・futex をプロセス内の仮想カーネルで管理し、ホスト資源は標準ライブラリと最小限の `host` FFI 経由で扱う。

## 構成と役割分担

| クレート | 役割 |
|---|---|
| `loader` | ELF（32/64 ビット、LE/BE）と a.out（PDP-11 0407/0410/0411、VAX OMAGIC/ZMAGIC）の形式判定（`probe_kind`）とヘッダ・セグメント解析 |
| `kernel` | OS 非依存の共通機構。プロセス表・スレッド表、単一ホストスレッドの決定的スケジューラ、多態ファイル記述子表（`FdTable` / `FdTarget`）、ホスト I/O 監視作業スレッド（`HostIo`）、パイプ、futex |
| `os-linux` | 16 ISA の Linux ゲスト ABI（番号表・構造体・errno・定数）、`sock`/`wait` 正準層、`guest_path` パス解決 |
| `os-v7` | PDP-11 向け Unix V7 パーソナリティ（`trap` 規約、`SYSENT`、a.out 配置、分離 I/D の PAR/PDR 設定） |
| `os-bsd` | VAX 向け 4.3BSD-Reno パーソナリティ（`chmk` 規約、a.out 配置、`a_entry + 2` 開始規約） |
| `os-wasi` | WebAssembly 向け WASI preview1（`wasi_snapshot_preview1` / `wasi_unstable`） |
| `os-semihost` | ベアメタルデバッグ向け Semihosting 2.0（aarch64 `hlt #0xf000`、arm `svc #0x123456`/`#0xab`、riscv ebreak 標識列）。仮想カーネルを介さずホスト入出力へ直結する |

## 仮想カーネルの機構（`kernel`）

### 単一ホストスレッドによる決定的スケジューリング

すべてのゲストスレッドは単一のホストスレッド上でステップ境界ごとに多重化する。スケジューラは仮想時間（タイミング無効時は実行ステップ数）が最小の実行可能スレッドを選び、実行予算ぶん進める。パイプや futex で待つスレッドは仮想カーネル内の待ち行列へ移し、全スレッドが待ち状態になりタイマーもホスト I/O 待ちもない場合はデッドロックとして停止する。

### 多態ファイル記述子表と `HostIo`

`kernel::FdTable` はすべての fd 対象を単一の列挙型 `FdTarget`（`File`・`MemFd`・`EventFd`・`TimerFd`・`SignalFd`・`Epoll`・`PipeEnd`・`PairSock`・`HostSock`・`Terminal`・`Reserved`）で管理する。パイプ表は `Rc<RefCell<...>>` で `fork`/`dup` 間に共有する。

ホストソケットなどのブロッキング I/O は、ゲスト命令を実行しない専用の作業スレッド `kernel::HostIo` に監視集合を渡し、準備イベントを `mpsc` 経由で受け取る。ホストスレッドを持たない環境（wasm32-wasi 等）では `HostIo::spawn` が `None` を返し、呼び出し側で直接フォールバックする。

## Linux パーソナリティ（`os-linux`）

### 共通正準層と ABI ごとのモジュール

Linux のシステムコール実装は、ISA ごとの ABI モジュール（`aarch64`・`alpha`・`arm`・`hexagon`・`ia64`・`loongarch`・`m68k`・`mips`・`openrisc`・`parisc`・`power`・`rv64`・`s390`・`sparc`・`superh`・`x86`）と、ABI 間で共有する正準層から成る。

- **`os-linux::sock`**：`SockAbi` でポインタ幅・エンディアン・errno・`SO_*`/`O_*` 定数差と `socketcall` 副番号を吸収し、`AF_UNIX`・`AF_INET`（stream/datagram）のホストソケットおよび `socketpair` を提供する。`AF_INET6` や netlink 等は `EAFNOSUPPORT` を返す。
- **`os-linux::wait`**：`WaitAbi` で時刻幅・`epoll_event` 配置差を吸収し、`select`/`pselect6`・`poll`/`ppoll`・`epoll_*`・`eventfd*`・`timerfd_*`・`memfd_create`・`signalfd*` を提供する。
- **`os-linux::guest_path`**：`--root` 指定時にシンボリックリンクを含めてゲストルート外への脱出を防ぐパス解決を行う。

`sock`・`wait` の正準層は `rv64` を除く 15 ISA の Linux ABI に接続済みである（接続状況の自動集計は [実装状況](../status.md) を参照）。未実装のシステムコールは既定で一度だけログ出力したうえで `ENOSYS` を返し、実行を継続する。

### 現行の横断的な制限（Linux）

- **ゲストルート（`--root`）と仮想ファイルシステム**：`--root` の完全な名前空間閉じ込めは一部 ABI（aarch64・ppc64・s390x・loongarch・openrisc・hexagon 等）に限られ、x86 を含む古い経路ではホストパスへ直接アクセスする箇所が残る。`/proc/self/maps`・`/proc/cpuinfo`・`/dev` の統一的な合成も未実装である（[GAP-0002](../known-issues.md)）。
- **マルチプロセス・マルチスレッド**：`clone`/`fork`/`execve`/`wait4` と `HostIo` 経由の非同期待ちは x86 が最も進んでおり、他の多くの Linux ABI は単一プロセス・単一スレッド模型（`fork`/`clone` は `ENOSYS`、待ち合わせは主スレッド消化）で動作する。
- **シグナル**：x86-64/i386/x32 で `rt_sigaction`/`rt_sigprocmask`/`rt_sigpending`/`rt_sigreturn`/`sigaltstack`、自分宛ての rt フレーム配送、CPU 例外からの同期シグナル変換と既定動作終了を実装しているが、汎用機構の `kernel` 移管、他スレッド配送、タイマ由来シグナルは未実装である（[GAP-0026](../known-issues.md)）。
- **ABI 構造の共通化とメモリ syscall**：`x86` をはじめ ABI ごとに状態構造体と振り分け表が重複している（[GAP-0032](../known-issues.md)）。また、一部 ABI では `munmap` が写像を解除せず、`brk` がページ整列値を保持する暫定実装になっている（[GAP-0034](../known-issues.md)）。

## その他の OS パーソナリティの現行仕様と簡略化

### Unix V7（`os-v7`・PDP-11）

`trap` 命令のコード語でシステムコール番号と引数個数を受け取り、`SYSENT`（64 項目）経由でディスパッチする。単一プロセス・root 模型であり、次の簡略化がある。

- `fork` は `EAGAIN`、`wait` は `ECHILD`、`pause` は `EINTR` を返す。`exec`/`exece` は同一アドレス空間の組み替えで実装する（`sh` が `fork` 失敗をリトライする経路は未対応）。
- `mount`/`umount`/`ptrace`/`profil`/`acct`/`phys`/`lock`/`mpx` は `EPERM`、`stty`/`gtty`/`ioctl` は `ENOTTY`。
- `kill` は自分宛ての既定終了のみ、`signal` は処置の記録のみでハンドラ配送は行わない。`time`/`ftime` はホスト実時間、uid/gid は固定値、`chown`/`utime` は存在検査のみ。
- ディレクトリ `read` は `.`・`..` を先頭に合成する。stdio fd（0〜2）の `close` と最小空き番号からの再割当てに対応する。

### 4.3BSD-Reno（`os-bsd`・VAX）

`chmk` 命令でユーザースタックに積まれたコード語からディスパッチし、`a.out`（OMAGIC/ZMAGIC）を `a_entry + 2` から開始する。単一プロセス・root 模型であり、次の簡略化がある。

- `fork`/`vfork` は `EAGAIN`、`wait`/`wait4` は `ECHILD`、`pause`/`sigsuspend` は `EINTR` を返す。`execv`/`execve`/`exece` はアドレス空間の組み替えで実装する。
- シグナル系（`ssig`/`sigvec`/`sigblock`/`sigsetmask`/`sigstack`）は登録・マスク記録のみでハンドラ配送を持たず、`kill`/`killpg` は自分宛てのみ既定動作で終了する。
- 特権系（`mount`/`ptrace`/`setgroups`/`swapon` 等）は `EPERM`、端末 ioctl は `ENOTTY`、未実装のソケット・`mmap`・`select` 等は 4.3BSD の `nosys` 規約に従い `EINVAL` を返す。
- `getdirentries`・`stat`（64B）・`statfs`/`getfsstat`（擬 UFS 128B）・`break`/`sbrk`・`pipe`・stdio fd 置換を実装している。

### WASI preview1（`os-wasi`・WebAssembly）

`wasi_snapshot_preview1`（および旧名 `wasi_unstable`）のインポート関数を正準シグネチャ検証付きで提供し、`--root` をプリオープン `/` として割り当てる。`WasiCtx::call` で主要 I/O・引数・環境変数・時計・乱数・`proc_exit` を処理し、未実装の preview1 関数（`clock_res_get`・`fd_pread`/`pwrite`・`path_rename`/`unlink_file`・`poll_oneoff`・`sock_*` 等 26 関数）は `ENOSYS` を返すスタブとして登録する。

### Semihosting 2.0（`os-semihost`・AArch64 / ARM / RISC-V）

`polyisa run --os semihost` で有効になり、ISA 中立の `Semi::call` が `SYS_*` 演算を処理する。単一プロセス模型であり、次の簡略化がある。

- `SYS_SYSTEM` はホストシェルへ渡さず常に `-1`、`CLOCK`/`ELAPSED` は `0`、`TICKFREQ` は `100` 固定、`TIME` はホスト実時間、`ERRNO` はホストの errno を返す。
- stdio は fd 0〜2 固定（`SYS_OPEN` の採番は 4 から）、`HEAPINFO` は `heap_base` のみ設定、`TMPNAM` は `:tmpNNNN` を連番生成する。`--root` 指定時はファイル演算をその配下に閉じ込める。
