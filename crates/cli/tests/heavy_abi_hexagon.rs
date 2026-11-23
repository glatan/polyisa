// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! hexagon の ABI 表とカーネル UAPI の突き合わせ（層6・abi、S22-2）。
//!
//! hexagon はアーチ固有の tbl を持たず、共通表 `scripts/syscall.tbl`
//! からアーチ別の opt-in で `unistd_32.h` が生成される（
//! `uapi/asm/Kbuild` の `syscall-y += unistd_32.h`）。hexagon が
//! 使う行は abi ∈ {common, 32, hexagon, time32, stat64, rlimit,
//! renameat}（`arch/hexagon/kernel/Makefile.syscalls` の
//! `syscall_abis_32 += hexagon time32 stat64 rlimit renameat` が
//! common/32 と合わせて opt-in する。v7.3 の tbl に abi=hexagon の
//! 行はない）。同じ番号に 32 系と 64 系の行が並ぶときは 32 系を
//! 取る（25 は fcntl64、62 は llseek、79/80 は fstatat64/fstat64、
//! 222 は mmap2）。アーチ固有の改名で
//! `uapi/asm/unistd.h` が `__NR_sync_file_range2`=84 を定義して
//! `__NR_sync_file_range` を消すため、畳んだ表の 84 は
//! `sync_file_range2` になる。カーネル側の入口点差替え
//! （`kernel/syscalltab.c` の `sys_mmap2→sys_mmap_pgoff`・
//! `sys_fadvise64_64→sys_hexagon_fadvise64_64`・
//! `sys_sync_file_range→sys_sync_file_range2`）は名表に現れないが
//! 根拠として固定する。呼出規約（trap0(#1)・番号 r6・引数 r0-r5・
//! 戻り値 r0・失敗は -errno）は `kernel-asm/syscall.h` で固定する。
//! 出典は `.testdata/uapi-hexagon`（台帳
//! SRC-LINUX-HEXAGON-UAPI・用途T）。データがなければ devtool
//! test:plan が外す。

use std::collections::HashMap;
use std::path::PathBuf;

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.testdata/uapi-hexagon")
}

fn have_data() -> bool {
    data_dir().join("syscall.tbl").is_file()
}

fn need_data() {
    assert!(
        have_data(),
        "SRC-LINUX-HEXAGON-UAPI を {} に置く。リポジトリには含めない。",
        data_dir().display()
    );
}

/// `syscall.tbl` を番号→名に畳む。4 列は 番号・abi・名・入口点。
/// hexagon は abi ∈ {common, 32, hexagon, time32, stat64, rlimit,
/// renameat} の行だけを載せ、畳んだ表では番号が一意になる（同番号に
/// 32 系と 64 系が並ぶ行は 64 系が落ちる）。最後に
/// `uapi/asm/unistd.h` の改名（84 `sync_file_range` →
/// `sync_file_range2`）を写す。
fn tbl_names(path: &PathBuf) -> HashMap<u64, String> {
    const HEXAGON_ABIS: &[&str] = &[
        "common", "32", "hexagon", "time32", "stat64", "rlimit", "renameat",
    ];
    let text = std::fs::read_to_string(path).expect("syscall.tbl を読む");
    let mut map = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut cols = line.split_whitespace();
        let (num, abi, name) = match (cols.next(), cols.next(), cols.next()) {
            (Some(n), Some(a), Some(nm)) => (n, a, nm),
            _ => panic!("tbl の行が読めない: {line:?}"),
        };
        if !HEXAGON_ABIS.contains(&abi) {
            continue;
        }
        let n: u64 = num
            .parse()
            .unwrap_or_else(|_| panic!("tbl の番号: {line:?}"));
        if let Some(prev) = map.insert(n, name.to_string()) {
            panic!("tbl で hexagon の番号 {n} が重複する（{prev} と {name}）");
        }
    }
    // `uapi/asm/unistd.h`: `#define __NR_sync_file_range2 84` +
    // `#undef __NR_sync_file_range` の改名を畳んだ表へ写す。
    assert_eq!(
        map.get(&84).map(String::as_str),
        Some("sync_file_range"),
        "tbl の 84 が sync_file_range ではない（改名の前提が崩れた）"
    );
    map.insert(84, String::from("sync_file_range2"));
    map
}

/// `Makefile.syscalls` の opt-in と `uapi/asm/Kbuild` の生成対象を
/// 確認し、選択規則 {common, 32, hexagon, time32, stat64, rlimit,
/// renameat} の根拠を固定する。v7.3 の tbl に abi=hexagon の行が
/// ないこともここで固定する。
#[test]
fn makefile_syscalls_selects_hexagon_abis() {
    need_data();
    let mk = data_dir().join("kernel/Makefile.syscalls");
    let text = std::fs::read_to_string(&mk).expect("Makefile.syscalls を読む");
    assert!(
        text.contains("syscall_abis_32 += hexagon time32 stat64 rlimit renameat"),
        "hexagon の 32 ビット ABI opt-in が見えない"
    );
    let kb = data_dir().join("uapi-asm/Kbuild");
    let text = std::fs::read_to_string(&kb).expect("uapi-asm/Kbuild を読む");
    assert!(
        text.contains("syscall-y += unistd_32.h"),
        "hexagon の unistd_32.h 生成が見えない"
    );
    // v7.3 の tbl には abi=hexagon の行がない（opt-in は将来のための
    // 枠）。行が増えたら畳み方と名表の見直しが要る。
    let text = std::fs::read_to_string(data_dir().join("syscall.tbl")).expect("syscall.tbl を読む");
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        assert_ne!(
            line.split_whitespace().nth(1),
            Some("hexagon"),
            "v7.3 の tbl に abi=hexagon の行がある: {line:?}"
        );
    }
}

/// `uapi/asm/unistd.h` の nr84 改名と `kernel/syscalltab.c` の
/// 入口点差替えを固定する。
#[test]
fn unistd_h_and_syscalltab_renames_match() {
    need_data();
    let uh = data_dir().join("uapi-asm/unistd.h");
    let text = std::fs::read_to_string(&uh).expect("uapi-asm/unistd.h を読む");
    assert!(
        text.contains("#define __NR_sync_file_range2 84"),
        "uapi-asm/unistd.h の __NR_sync_file_range2=84 が見えない"
    );
    assert!(
        text.contains("#undef __NR_sync_file_range"),
        "uapi-asm/unistd.h の __NR_sync_file_range 抹消が見えない"
    );
    let st = data_dir().join("kernel/syscalltab.c");
    let text = std::fs::read_to_string(&st).expect("kernel/syscalltab.c を読む");
    for sub in [
        "#define sys_mmap2 sys_mmap_pgoff",
        "#define sys_fadvise64_64 sys_hexagon_fadvise64_64",
        "#define sys_sync_file_range sys_sync_file_range2",
    ] {
        assert!(
            text.contains(sub),
            "kernel/syscalltab.c に {sub} が見えない"
        );
    }
}

/// `kernel-asm/syscall.h` の呼出規約（番号 r06・引数 r00-r05・
/// 戻り値 r00・失敗は IS_ERR_VALUE(r00)＝-errno）を固定する。
#[test]
fn syscall_h_pins_trap0_convention() {
    need_data();
    let sh = data_dir().join("kernel-asm/syscall.h");
    let text = std::fs::read_to_string(&sh).expect("kernel-asm/syscall.h を読む");
    for sub in [
        "return regs->r06;",
        "regs->r06 = nr;",
        "memcpy(args, &(&regs->r00)[0], 6 * sizeof(args[0]));",
        "IS_ERR_VALUE(regs->r00)",
        "return regs->r00;",
    ] {
        assert!(
            text.contains(sub),
            "kernel-asm/syscall.h に {sub} が見えない"
        );
    }
}

#[test]
fn syscall_numbers_match_uapi_hexagon() {
    need_data();
    let names = tbl_names(&data_dir().join("syscall.tbl"));
    let want_nr = |name: &str| -> u64 {
        *names
            .iter()
            .find(|(_, v)| v.as_str() == name)
            .map(|(n, _)| n)
            .unwrap_or_else(|| panic!("tbl に {name} がない"))
    };
    use polyisa_os_linux::hexagon::nr as a;
    for (name, want) in [
        ("fsetxattr", a::FSETXATTR),
        ("getcwd", a::GETCWD),
        ("dup", a::DUP),
        ("dup3", a::DUP3),
        ("fcntl64", a::FCNTL64),
        ("ioctl", a::IOCTL),
        ("ioprio_set", a::IOPRIO_SET),
        ("flock", a::FLOCK),
        ("mknodat", a::MKNODAT),
        ("mkdirat", a::MKDIRAT),
        ("unlinkat", a::UNLINKAT),
        ("symlinkat", a::SYMLINKAT),
        ("linkat", a::LINKAT),
        ("renameat", a::RENAMEAT),
        ("statfs64", a::STATFS64),
        ("fstatfs64", a::FSTATFS64),
        ("truncate64", a::TRUNCATE64),
        ("ftruncate64", a::FTRUNCATE64),
        ("faccessat", a::FACCESSAT),
        ("chdir", a::CHDIR),
        ("fchdir", a::FCHDIR),
        ("fchmod", a::FCHMOD),
        ("fchmodat", a::FCHMODAT),
        ("fchownat", a::FCHOWNAT),
        ("fchown", a::FCHOWN),
        ("openat", a::OPENAT),
        ("close", a::CLOSE),
        ("vhangup", a::VHANGUP),
        ("pipe2", a::PIPE2),
        ("getdents64", a::GETDENTS64),
        ("llseek", a::LLSEEK),
        ("read", a::READ),
        ("write", a::WRITE),
        ("readv", a::READV),
        ("writev", a::WRITEV),
        ("pread64", a::PREAD64),
        ("pwrite64", a::PWRITE64),
        ("sendfile64", a::SENDFILE64),
        ("pselect6", a::PSELECT6),
        ("ppoll", a::PPOLL),
        ("readlinkat", a::READLINKAT),
        ("fstatat64", a::FSTATAT64),
        ("fstat64", a::FSTAT64),
        ("sync", a::SYNC),
        ("fsync", a::FSYNC),
        ("fdatasync", a::FDATASYNC),
        ("sync_file_range2", a::SYNC_FILE_RANGE2),
        ("utimensat", a::UTIMENSAT),
        ("personality", a::PERSONALITY),
        ("exit", a::EXIT),
        ("exit_group", a::EXIT_GROUP),
        ("waitid", a::WAITID),
        ("set_tid_address", a::SET_TID_ADDRESS),
        ("futex", a::FUTEX),
        ("set_robust_list", a::SET_ROBUST_LIST),
        ("get_robust_list", a::GET_ROBUST_LIST),
        ("nanosleep", a::NANOSLEEP),
        ("clock_settime", a::CLOCK_SETTIME),
        ("clock_gettime", a::CLOCK_GETTIME),
        ("clock_getres", a::CLOCK_GETRES),
        ("clock_nanosleep", a::CLOCK_NANOSLEEP),
        ("sched_setparam", a::SCHED_SETPARAM),
        ("sched_setscheduler", a::SCHED_SETSCHEDULER),
        ("sched_getscheduler", a::SCHED_GETSCHEDULER),
        ("sched_getparam", a::SCHED_GETPARAM),
        ("sched_setaffinity", a::SCHED_SETAFFINITY),
        ("sched_getaffinity", a::SCHED_GETAFFINITY),
        ("sched_yield", a::SCHED_YIELD),
        ("sched_get_priority_max", a::SCHED_GET_PRIORITY_MAX),
        ("sched_get_priority_min", a::SCHED_GET_PRIORITY_MIN),
        ("sched_rr_get_interval", a::SCHED_RR_GET_INTERVAL),
        ("restart_syscall", a::RESTART_SYSCALL),
        ("kill", a::KILL),
        ("tkill", a::TKILL),
        ("tgkill", a::TGKILL),
        ("sigaltstack", a::SIGALTSTACK),
        ("rt_sigaction", a::RT_SIGACTION),
        ("rt_sigprocmask", a::RT_SIGPROCMASK),
        ("rt_sigpending", a::RT_SIGPENDING),
        ("rt_sigtimedwait", a::RT_SIGTIMEDWAIT),
        ("rt_sigreturn", a::RT_SIGRETURN),
        ("setpriority", a::SETPRIORITY),
        ("getpriority", a::GETPRIORITY),
        ("reboot", a::REBOOT),
        ("setregid", a::SETREGID),
        ("setgid", a::SETGID),
        ("setreuid", a::SETREUID),
        ("setuid", a::SETUID),
        ("setresuid", a::SETRESUID),
        ("getresuid", a::GETRESUID),
        ("setresgid", a::SETRESGID),
        ("getresgid", a::GETRESGID),
        ("setfsuid", a::SETFSUID),
        ("setfsgid", a::SETFSGID),
        ("times", a::TIMES),
        ("setpgid", a::SETPGID),
        ("getpgid", a::GETPGID),
        ("getsid", a::GETSID),
        ("setsid", a::SETSID),
        ("getgroups", a::GETGROUPS),
        ("setgroups", a::SETGROUPS),
        ("uname", a::UNAME),
        ("sethostname", a::SETHOSTNAME),
        ("setdomainname", a::SETDOMAINNAME),
        ("getrlimit", a::GETRLIMIT),
        ("setrlimit", a::SETRLIMIT),
        ("getrusage", a::GETRUSAGE),
        ("umask", a::UMASK),
        ("prctl", a::PRCTL),
        ("getcpu", a::GETCPU),
        ("gettimeofday", a::GETTIMEOFDAY),
        ("getpid", a::GETPID),
        ("getppid", a::GETPPID),
        ("getuid", a::GETUID),
        ("geteuid", a::GETEUID),
        ("getgid", a::GETGID),
        ("getegid", a::GETEGID),
        ("gettid", a::GETTID),
        ("sysinfo", a::SYSINFO),
        ("brk", a::BRK),
        ("munmap", a::MUNMAP),
        ("mremap", a::MREMAP),
        ("clone", a::CLONE),
        ("execve", a::EXECVE),
        ("mmap2", a::MMAP2),
        ("fadvise64_64", a::FADVISE64_64),
        ("mprotect", a::MPROTECT),
        ("msync", a::MSYNC),
        ("mlock", a::MLOCK),
        ("munlock", a::MUNLOCK),
        ("mlockall", a::MLOCKALL),
        ("munlockall", a::MUNLOCKALL),
        ("mincore", a::MINCORE),
        ("madvise", a::MADVISE),
        ("remap_file_pages", a::REMAP_FILE_PAGES),
        ("wait4", a::WAIT4),
        ("prlimit64", a::PRLIMIT64),
        ("getrandom", a::GETRANDOM),
        ("memfd_create", a::MEMFD_CREATE),
        ("execveat", a::EXECVEAT),
        ("copy_file_range", a::COPY_FILE_RANGE),
        ("statx", a::STATX),
        ("rseq", a::RSEQ),
        ("clock_gettime64", a::CLOCK_GETTIME64),
        ("clock_settime64", a::CLOCK_SETTIME64),
        ("clock_getres_time64", a::CLOCK_GETRES_TIME64),
        ("clock_nanosleep_time64", a::CLOCK_NANOSLEEP_TIME64),
        ("futex_time64", a::FUTEX_TIME64),
        ("clone3", a::CLONE3),
        ("close_range", a::CLOSE_RANGE),
        ("openat2", a::OPENAT2),
        ("faccessat2", a::FACCESSAT2),
        ("fchmodat2", a::FCHMODAT2),
    ] {
        let got = want_nr(name);
        assert_eq!(got, want, "__NR_{name} の番号が UAPI と食い違う");
    }
}

#[test]
fn name_table_covers_uapi_hexagon() {
    need_data();
    let names = tbl_names(&data_dir().join("syscall.tbl"));
    // 実装の全エントリが tbl の同じ番号の名と一致すること。
    for (nr, got) in polyisa_os_linux::hexagon::SYSCALLS {
        let Some(want) = names.get(nr) else {
            panic!("実装が hexagon の UAPI にない番号 {nr}({got}) を持つ");
        };
        assert_eq!(got, want, "name({nr}) が UAPI と食い違う");
    }
    // tbl の hexagon ABI 全集の全番号が実装に載っていること
    // （UAPI 側の漏れ検出）。
    for (nr, want) in &names {
        assert!(
            polyisa_os_linux::hexagon::name(*nr).is_some(),
            "UAPI の {nr}({want}) が実装にない"
        );
    }
    // UAPI の最大番号を超える実装エントリがないこと。
    let max = names.keys().copied().max().unwrap_or(0);
    assert_eq!(
        polyisa_os_linux::hexagon::SYSCALLS
            .iter()
            .map(|(n, _)| *n)
            .max(),
        Some(max),
        "実装表の最大番号が UAPI と食い違う"
    );
    assert!(
        polyisa_os_linux::hexagon::name(max + 1).is_none(),
        "UAPI の最大番号を超える実装エントリがある"
    );
}
