// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! ソケットと待ち合わせを使うプログラム（層7・program、S26-1）。
//!
//! x86-64・i386（socketcall 経路）・aarch64 の三系統で、
//! socketpair・TCP ループバック・poll/ppoll・epoll・eventfd・
//! timerfd・memfd を通す。clang で `-nostdlib -static` にコンパイルする。
//! 出典は SRC-LINUX (7.3) の番号と socketcall 副番号（include/linux/net.h）。

use std::path::{Path, PathBuf};
use std::process::Command;

fn lld() -> PathBuf {
    let out = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .expect("rustc");
    let sysroot = String::from_utf8(out.stdout).expect("sysroot utf-8");
    PathBuf::from(sysroot.trim()).join("lib/rustlib/x86_64-unknown-linux-gnu/bin/gcc-ld/ld.lld")
}

fn compile(dir: &Path, lld: &Path, target: &str, name: &str, source: &str) -> PathBuf {
    let src = dir.join(format!("{name}.c"));
    let elf = dir.join(format!("{name}.elf"));
    std::fs::write(&src, source).unwrap();
    let status = Command::new("clang")
        .args([
            &format!("--target={target}"),
            "-nostdlib",
            "-static",
            "-fno-stack-protector",
            &format!("-fuse-ld={}", lld.display()),
            "-Wl,-e,_start",
            "-o",
        ])
        .arg(&elf)
        .arg(&src)
        .status()
        .expect("clang");
    assert!(status.success(), "clang {target} failed");
    elf
}

/// x86-64。番号は SRC-LINUX (7.3)：
/// read=0 write=1 poll=7 socket=41 connect=42 accept=43 sendto=44 recvfrom=45
/// socketpair=53 bind=49 listen=50 getsockname=51 accept4=288
/// epoll_ctl=233 epoll_wait=232 epoll_create1=291 eventfd2=290
/// timerfd_create=283 timerfd_settime=286 memfd_create=319 exit_group=231
const SRC_X64: &str = r#"
typedef unsigned long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef int i32;

static long sc(long n, long a, long b, long c, long d, long e, long f) {
    long r;
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    __asm__ volatile("syscall"
                     : "=a"(r)
                     : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return r;
}

static void out(const char *s, int n) { sc(1, 1, (long)s, n, 0, 0, 0); }
static void ch(char c) { out(&c, 1); }

struct pollfd { i32 fd; u16 ev, rev; };
struct sockaddr_in { u16 fam, port; u32 addr; char zero[8]; };
struct itimerspec64 { u64 isec, insec, vsec, vnsec; };
struct ep_ev { u32 ev; u64 data; } __attribute__((packed));

char buf[64];

void _start(void) {
    // a: socketpair + write/read
    int sv[2];
    if (sc(53, 1, 1, 0, (long)sv, 0, 0) < 0) { ch('!'); goto done; }
    sc(1, sv[0], (long)"X", 1, 0, 0, 0);
    sc(0, sv[1], (long)buf, 8, 0, 0, 0);
    if (buf[0] != 'X') { ch('?'); goto done; }
    ch('a');

    // b: eventfd + poll + read
    long efd = sc(290, 0, 0, 0, 0, 0, 0);
    if (efd < 0) { ch('!'); goto done; }
    { u64 one = 1; sc(1, efd, (long)&one, 8, 0, 0, 0); }
    struct pollfd pf = { (i32)efd, 1, 0 };
    if (sc(7, (long)&pf, 1, 0, 0, 0, 0) != 1 || !(pf.rev & 1)) { ch('?'); goto done; }
    { u64 v = 0; sc(0, efd, (long)&v, 8, 0, 0, 0); if (v != 1) { ch('?'); goto done; } }
    ch('b');

    // c: timerfd 50ms + poll + read
    long tfd = sc(283, 1, 0, 0, 0, 0, 0);
    if (tfd < 0) { ch('!'); goto done; }
    struct itimerspec64 its = { 0, 0, 0, 50000000 };
    sc(286, tfd, 0, (long)&its, 0, 0, 0);
    struct pollfd tp = { (i32)tfd, 1, 0 };
    if (sc(7, (long)&tp, 1, 3000, 0, 0, 0) != 1 || !(tp.rev & 1)) { ch('?'); goto done; }
    { u64 v = 0; sc(0, tfd, (long)&v, 8, 0, 0, 0); if (v < 1) { ch('?'); goto done; } }
    ch('c');

    // d: memfd + write + lseek + read
    long mfd = sc(319, (long)"m", 0, 0, 0, 0, 0);
    if (mfd < 0) { ch('!'); goto done; }
    sc(1, mfd, (long)"AB", 2, 0, 0, 0);
    sc(8, mfd, 0, 0, 0, 0, 0); // lseek SET 0
    buf[0] = 0;
    if (sc(0, mfd, (long)buf, 2, 0, 0, 0) != 2 || buf[0] != 'A') { ch('?'); goto done; }
    ch('d');

    // e: epoll over socketpair end
    long ep = sc(291, 0, 0, 0, 0, 0, 0);
    if (ep < 0) { ch('!'); goto done; }
    struct ep_ev ev = { 1, (u64)sv[0] };
    sc(233, ep, 1, sv[0], (long)&ev, 0, 0);
    sc(1, sv[1], (long)"Y", 1, 0, 0, 0);
    struct ep_ev evs[4];
    if (sc(232, ep, (long)evs, 4, -1, 0, 0) != 1) { ch('?'); goto done; }
    ch('e');

    // f: TCP loopback bind port0 + connect + accept4 + send/recv
    long ls = sc(41, 2, 1, 0, 0, 0, 0);
    if (ls < 0) { ch('!'); goto done; }
    struct sockaddr_in sa = { 2, 0, 0x0100007f, {0} };
    if (sc(49, ls, (long)&sa, 16, 0, 0, 0) != 0) { ch('!'); goto done; }
    u32 alen = 16;
    if (sc(51, ls, (long)&sa, (long)&alen, 0, 0, 0) != 0) { ch('!'); goto done; }
    if (sc(50, ls, 4, 0, 0, 0, 0) != 0) { ch('!'); goto done; }
    long cs = sc(41, 2, 1, 0, 0, 0, 0);
    if (cs < 0) { ch('!'); goto done; }
    if (sc(42, cs, (long)&sa, 16, 0, 0, 0) != 0) { ch('!'); goto done; }
    long as = sc(288, ls, 0, 0, 0, 0, 0);
    if (as < 0) { ch('!'); goto done; }
    sc(44, cs, (long)"PING", 4, 0, 0, 0);
    buf[0] = 0;
    sc(45, as, (long)buf, 8, 0, 0, 0);
    if (buf[0] != 'P' || buf[1] != 'I') { ch('?'); goto done; }
    sc(44, as, (long)"PONG", 4, 0, 0, 0);
    buf[0] = 0;
    sc(45, cs, (long)buf, 8, 0, 0, 0);
    if (buf[0] != 'P' || buf[1] != 'O') { ch('?'); goto done; }
    ch('f');

    out(" NET-OK\n", 8);
done:
    sc(231, 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
"#;

/// i386。直接番号は int 0x80、ソケット系は socketcall=102 の副番号。
/// read=3 write=4 poll=168 epoll_wait=256 epoll_ctl=255 eventfd2=328
/// epoll_create1=329 timerfd_create=324 timerfd_settime=325 memfd_create=356
/// exit_group=252 socketcall=102。副番号 socket=1 bind=2 connect=3 listen=4
/// accept=5 getsockname=6 socketpair=8 send=9 recv=10 accept4=18。
const SRC_I386: &str = r#"
typedef unsigned int u32;
typedef unsigned short u16;
typedef int i32;

void *memset(void *p, int c, unsigned n) {
    char *q = (char *)p;
    while (n--) *q++ = (char)c;
    return p;
}
void *memcpy(void *d, const void *s, unsigned n) {
    char *q = (char *)d;
    const char *r = (const char *)s;
    while (n--) *q++ = *r++;
    return d;
}

static long sc(long n, long a, long b, long c, long d, long e) {
    long r;
    __asm__ volatile("int $0x80"
                     : "=a"(r)
                     : "a"(n), "b"(a), "c"(b), "d"(c), "S"(d), "D"(e)
                     : "memory");
    return r;
}

static long scc(long sub, u32 *args) { return sc(102, sub, (long)args, 0, 0, 0); }

static void out(const char *s, int n) { sc(4, 1, (long)s, n, 0, 0); }
static void ch(char c) { out(&c, 1); }

struct pollfd { i32 fd; u16 ev, rev; };
struct sockaddr_in { u16 fam, port; u32 addr; char zero[8]; };
struct itimerspec32 { u32 isec, insec, vsec, vnsec; };
struct ep_ev { u32 ev; u32 data_lo, data_hi; } __attribute__((packed));

char buf[64];

void _start(void) {
    // a: socketpair(AF_UNIX,SOCK_STREAM) + write/read
    int sv[2];
    { u32 a[4] = { 1, 1, 0, (u32)sv }; if (scc(8, a) < 0) { ch('!'); goto done; } }
    sc(4, sv[0], (long)"X", 1, 0, 0);
    sc(3, sv[1], (long)buf, 8, 0, 0);
    if (buf[0] != 'X') { ch('?'); goto done; }
    ch('a');

    // b: eventfd2 + poll + read
    long efd = sc(328, 0, 0, 0, 0, 0);
    if (efd < 0) { ch('!'); goto done; }
    { u32 one[2] = { 1, 0 }; sc(4, efd, (long)one, 8, 0, 0); }
    struct pollfd pf = { (i32)efd, 1, 0 };
    if (sc(168, (long)&pf, 1, 0, 0, 0) != 1 || !(pf.rev & 1)) { ch('?'); goto done; }
    { u32 v[2] = { 0, 0 }; sc(3, efd, (long)v, 8, 0, 0); if (v[0] != 1) { ch('?'); goto done; } }
    ch('b');

    // c: timerfd 50ms + poll + read
    long tfd = sc(324, 1, 0, 0, 0, 0);
    if (tfd < 0) { ch('!'); goto done; }
    struct itimerspec32 its = { 0, 0, 0, 50000000 };
    sc(325, tfd, 0, (long)&its, 0, 0);
    struct pollfd tp = { (i32)tfd, 1, 0 };
    if (sc(168, (long)&tp, 1, 3000, 0, 0) != 1 || !(tp.rev & 1)) { ch('?'); goto done; }
    { u32 v[2] = { 0, 0 }; sc(3, tfd, (long)v, 8, 0, 0); if (v[0] < 1) { ch('?'); goto done; } }
    ch('c');

    // d: memfd + write + lseek + read
    long mfd = sc(356, (long)"m", 0, 0, 0, 0);
    if (mfd < 0) { ch('!'); goto done; }
    sc(4, mfd, (long)"AB", 2, 0, 0);
    sc(19, mfd, 0, 0, 0, 0); // lseek SET 0
    buf[0] = 0;
    if (sc(3, mfd, (long)buf, 2, 0, 0) != 2 || buf[0] != 'A') { ch('?'); goto done; }
    ch('d');

    // e: epoll over socketpair end（i386 の epoll_event は 12B 詰め）
    long ep = sc(329, 0, 0, 0, 0, 0);
    if (ep < 0) { ch('!'); goto done; }
    struct ep_ev ev = { 1, (u32)sv[0], 0 };
    sc(255, ep, 1, sv[0], (long)&ev, 0);
    sc(4, sv[1], (long)"Y", 1, 0, 0);
    struct ep_ev evs[4];
    if (sc(256, ep, (long)evs, 4, -1, 0) != 1) { ch('?'); goto done; }
    ch('e');

    // f: TCP loopback（socketcall）
    { u32 a[3] = { 2, 1, 0 }; long ls = scc(1, a); if (ls < 0) { ch('!'); goto done; }
      struct sockaddr_in sa = { 2, 0, 0x0100007f, {0} };
      { u32 b2[3] = { (u32)ls, (u32)&sa, 16 }; if (scc(2, b2) != 0) { ch('!'); goto done; } }
      u32 alen = 16;
      { u32 g[3] = { (u32)ls, (u32)&sa, (u32)&alen }; if (scc(6, g) != 0) { ch('!'); goto done; } }
      { u32 l[2] = { (u32)ls, 4 }; if (scc(4, l) != 0) { ch('!'); goto done; } }
      { u32 a2[3] = { 2, 1, 0 }; long cs = scc(1, a2); if (cs < 0) { ch('!'); goto done; }
        { u32 c[3] = { (u32)cs, (u32)&sa, 16 }; if (scc(3, c) != 0) { ch('!'); goto done; } }
        { u32 ac[4] = { (u32)ls, 0, 0, 0 }; long as = scc(18, ac); if (as < 0) { ch('!'); goto done; }
          { u32 s[4] = { (u32)cs, (u32)"PING", 4, 0 }; scc(9, s); }
          buf[0] = 0;
          { u32 r[4] = { (u32)as, (u32)buf, 8, 0 }; scc(10, r); }
          if (buf[0] != 'P' || buf[1] != 'I') { ch('?'); goto done; }
          { u32 s2[4] = { (u32)as, (u32)"PONG", 4, 0 }; scc(9, s2); }
          buf[0] = 0;
          { u32 r2[4] = { (u32)cs, (u32)buf, 8, 0 }; scc(10, r2); }
          if (buf[0] != 'P' || buf[1] != 'O') { ch('?'); goto done; }
        }
      }
    }
    ch('f');

    out(" NET-OK\n", 8);
done:
    sc(252, 0, 0, 0, 0, 0);
    for (;;) {}
}
"#;

/// aarch64。asm-generic 番号：read=63 write=64 ppoll=73 epoll_create1=20
/// epoll_ctl=21 epoll_pwait=22 socket=198 socketpair=199 bind=200 listen=201
/// connect=203 getsockname=204 sendto=206 recvfrom=207 accept4=242
/// eventfd2=19 timerfd_create=85 timerfd_settime=86 memfd_create=279
/// exit_group=94。
const SRC_A64: &str = r#"
typedef unsigned long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef int i32;

static long sc(long n, long a, long b, long c, long d, long e) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4)
                     : "memory");
    return x0;
}

static void out(const char *s, int n) { sc(64, 1, (long)s, n, 0, 0); }
static void ch(char c) { out(&c, 1); }

struct pollfd { i32 fd; u16 ev, rev; };
struct sockaddr_in { u16 fam, port; u32 addr; char zero[8]; };
struct timespec64 { u64 sec, nsec; };
struct itimerspec64 { struct timespec64 it_i, it_v; };
struct ep_ev { u32 ev, pad; u64 data; };

char buf[64];

void _start(void) {
    // a: socketpair + write/read
    int sv[2];
    if (sc(199, 1, 1, 0, (long)sv, 0) < 0) { ch('!'); goto done; }
    sc(64, sv[0], (long)"X", 1, 0, 0);
    sc(63, sv[1], (long)buf, 8, 0, 0);
    if (buf[0] != 'X') { ch('?'); goto done; }
    ch('a');

    // b: eventfd + ppoll + read
    long efd = sc(19, 0, 0, 0, 0, 0);
    if (efd < 0) { ch('!'); goto done; }
    { u64 one = 1; sc(64, efd, (long)&one, 8, 0, 0); }
    struct pollfd pf = { (i32)efd, 1, 0 };
    struct timespec64 zt = { 0, 0 };
    if (sc(73, (long)&pf, 1, (long)&zt, 0, 8) != 1 || !(pf.rev & 1)) { ch('?'); goto done; }
    { u64 v = 0; sc(63, efd, (long)&v, 8, 0, 0); if (v != 1) { ch('?'); goto done; } }
    ch('b');

    // c: timerfd 50ms + ppoll + read
    long tfd = sc(85, 1, 0, 0, 0, 0);
    if (tfd < 0) { ch('!'); goto done; }
    struct itimerspec64 its = { {0, 0}, {0, 50000000} };
    sc(86, tfd, 0, (long)&its, 0, 0);
    struct pollfd tp = { (i32)tfd, 1, 0 };
    struct timespec64 tmo = { 3, 0 };
    if (sc(73, (long)&tp, 1, (long)&tmo, 0, 8) != 1 || !(tp.rev & 1)) { ch('?'); goto done; }
    { u64 v = 0; sc(63, tfd, (long)&v, 8, 0, 0); if (v < 1) { ch('?'); goto done; } }
    ch('c');

    // d: memfd + write + lseek + read
    long mfd = sc(279, (long)"m", 0, 0, 0, 0);
    if (mfd < 0) { ch('!'); goto done; }
    sc(64, mfd, (long)"AB", 2, 0, 0);
    sc(62, mfd, 0, 0, 0, 0); // lseek SET 0
    buf[0] = 0;
    if (sc(63, mfd, (long)buf, 2, 0, 0) != 2 || buf[0] != 'A') { ch('?'); goto done; }
    ch('d');

    // e: epoll over socketpair end
    long ep = sc(20, 0, 0, 0, 0, 0);
    if (ep < 0) { ch('!'); goto done; }
    struct ep_ev ev = { 1, 0, (u64)sv[0] };
    sc(21, ep, 1, sv[0], (long)&ev, 0);
    sc(64, sv[1], (long)"Y", 1, 0, 0);
    struct ep_ev evs[4];
    if (sc(22, ep, (long)evs, 4, 2000, 0) != 1) { ch('?'); goto done; }
    ch('e');

    // f: TCP loopback
    long ls = sc(198, 2, 1, 0, 0, 0);
    if (ls < 0) { ch('!'); goto done; }
    struct sockaddr_in sa = { 2, 0, 0x0100007f, {0} };
    if (sc(200, ls, (long)&sa, 16, 0, 0) != 0) { ch('!'); goto done; }
    u32 alen = 16;
    if (sc(204, ls, (long)&sa, (long)&alen, 0, 0) != 0) { ch('!'); goto done; }
    if (sc(201, ls, 4, 0, 0, 0) != 0) { ch('!'); goto done; }
    long cs = sc(198, 2, 1, 0, 0, 0);
    if (cs < 0) { ch('!'); goto done; }
    if (sc(203, cs, (long)&sa, 16, 0, 0) != 0) { ch('!'); goto done; }
    long as = sc(242, ls, 0, 0, 0, 0);
    if (as < 0) { ch('!'); goto done; }
    sc(206, cs, (long)"PING", 4, 0, 0);
    buf[0] = 0;
    sc(207, as, (long)buf, 8, 0, 0);
    if (buf[0] != 'P' || buf[1] != 'I') { ch('?'); goto done; }
    sc(206, as, (long)"PONG", 4, 0, 0);
    buf[0] = 0;
    sc(207, cs, (long)buf, 8, 0, 0);
    if (buf[0] != 'P' || buf[1] != 'O') { ch('?'); goto done; }
    ch('f');

    out(" NET-OK\n", 8);
done:
    sc(94, 0, 0, 0, 0, 0);
    for (;;) {}
}
"#;

#[test]
fn net_x86_64() {
    if Command::new("clang").arg("--version").output().is_err() {
        eprintln!("clang がない。スキップ");
        return;
    }
    let lld = lld();
    assert!(lld.is_file(), "rust-lld が必要。TOOL-RUST のリンカを使う。");
    let dir = std::env::temp_dir().join(format!("polyisa-net64-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let elf = compile(&dir, &lld, "x86_64-linux-gnu", "net64", SRC_X64);
    let argv: Vec<String> = vec![elf.to_str().unwrap().to_string()];
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(elf.to_str().unwrap(), &argv)
        .unwrap_or_else(|e| panic!("x86-64 net: {e}"));
    let out_s = String::from_utf8_lossy(&out);
    assert_eq!(code, 0, "x86-64 net exit {code}, out={out_s}");
    assert_eq!(out_s, "abcdef NET-OK\n", "x86-64 net out={out_s}");
}

#[test]
fn net_i386_socketcall() {
    if Command::new("clang").arg("--version").output().is_err() {
        eprintln!("clang がない。スキップ");
        return;
    }
    let lld = lld();
    assert!(lld.is_file(), "rust-lld が必要。TOOL-RUST のリンカを使う。");
    let dir = std::env::temp_dir().join(format!("polyisa-net32-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let elf = compile(&dir, &lld, "i386-linux-gnu", "net32", SRC_I386);
    let argv: Vec<String> = vec![elf.to_str().unwrap().to_string()];
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_32_captured(elf.to_str().unwrap(), &argv)
        .unwrap_or_else(|e| panic!("i386 net: {e}"));
    let out_s = String::from_utf8_lossy(&out);
    assert_eq!(code, 0, "i386 net exit {code}, out={out_s}");
    assert_eq!(out_s, "abcdef NET-OK\n", "i386 net out={out_s}");
}

#[test]
fn net_aarch64() {
    if Command::new("clang").arg("--version").output().is_err() {
        eprintln!("clang がない。スキップ");
        return;
    }
    let lld = lld();
    assert!(lld.is_file(), "rust-lld が必要。TOOL-RUST のリンカを使う。");
    let dir = std::env::temp_dir().join(format!("polyisa-neta64-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let elf = compile(&dir, &lld, "aarch64-linux-gnu", "neta64", SRC_A64);
    let mut sys = polyisa_os_linux::aarch64::sys::Linux::default();
    let argv: Vec<String> = vec![elf.to_str().unwrap().to_string()];
    let code =
        polyisa_cli::run_aarch64::run_elf_aarch64_sys(elf.to_str().unwrap(), &argv, None, &mut sys)
            .unwrap_or_else(|e| panic!("aarch64 net: {e}"));
    let out_s = String::from_utf8_lossy(&sys.io.stdout);
    assert_eq!(code, 0, "aarch64 net exit {code}, out={out_s}");
    assert_eq!(out_s, "abcdef NET-OK\n", "aarch64 net out={out_s}");
}
