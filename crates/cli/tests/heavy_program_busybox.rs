// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! S4-1 の枠。台帳の BIN-DISTRO（BusyBox 1.35.0、静的、x86_64、musl）の
//! `busybox --list` を読み、`df` を対象から外す。
//!
//! ゲストは空の環境変数で起動する。ホスト側の起動も環境変数を空にする。
//! アプレットの終了コードと標準出力は、このテストでは見ない。
//! バイナリはリポジトリに含めない。ファイルが無いときは失敗する。

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

fn busybox() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.join(".testdata/bin-distro/busybox")
}

fn listed_applets(path: &Path) -> Vec<String> {
    let out = Command::new(path)
        .arg("--list")
        .env_clear()
        .output()
        .expect("busybox --list");
    assert!(
        out.status.success(),
        "busybox --list: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .expect("busybox --list は utf-8")
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

/// `--list` の全件から `df` だけを外した対象。件数は切り詰めない。
fn target_applets(listed: &[String]) -> Vec<&str> {
    listed
        .iter()
        .map(String::as_str)
        .filter(|name| *name != "df")
        .collect()
}

#[test]
fn list_excludes_only_df() {
    let path = busybox();
    assert!(
        path.is_file(),
        "BIN-DISTRO の BusyBox 1.35.0 を {} に置く。リポジトリには含めない。",
        path.display()
    );
    let listed = listed_applets(&path);
    assert_eq!(listed.len(), 402, "BIN-DISTRO 1.35.0 の --list は 402 件");
    assert_eq!(listed.iter().filter(|name| *name == "df").count(), 1);
    let target = target_applets(&listed);
    assert_eq!(target.len(), 401);
    assert!(target.iter().all(|name| *name != "df"));
}

#[test]
fn true_echo_uname_id_match() {
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let pinned: &[(&[&str], &[u8])] = &[
        (
            &["uname", "-a"],
            b"Linux localhost 6.0.0 #1 x86_64 GNU/Linux\n",
        ),
        (&["id"], b"uid=0(root) gid=0(root) groups=0(root)\n"),
    ];
    for (args, expect) in pinned {
        let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
            .unwrap_or_else(|e| panic!("{}: {e}", args.join(" ")));
        assert_eq!(code, 0, "{}", args.join(" "));
        assert_eq!(out.as_slice(), *expect, "{}", args.join(" "));
    }
    for args in [
        &["true"][..],
        &["echo", "hi"][..],
        &["basename", "/tmp/a"][..],
        &["dirname", "/tmp/a"][..],
    ] {
        let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
            .unwrap_or_else(|e| panic!("{}: {e}", args.join(" ")));
        let host = Command::new(path)
            .args(args)
            .env_clear()
            .output()
            .expect("host busybox");
        assert!(host.status.success(), "{}", args.join(" "));
        assert_eq!(code, 0, "{}", args.join(" "));
        assert_eq!(out.as_slice(), host.stdout.as_slice(), "{}", args.join(" "));
    }
    // 外部の echo は動的リンクなので、静的な BusyBox 自身を実行する。
    let setsid = ["setsid", path, "echo", "hi"];
    let argv: Vec<String> = setsid.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("setsid: {e}"));
    let host = Command::new(path)
        .args(setsid)
        .env_clear()
        .output()
        .expect("host setsid");
    assert_eq!(code, host.status.code().unwrap_or(1) as u64);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
    assert_eq!(out.as_slice(), b"hi\n");
    let nice = ["nice", "-n", "0", path, "echo", "hi"];
    let argv: Vec<String> = nice.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("nice: {e}"));
    let host = Command::new(path)
        .args(nice)
        .env_clear()
        .output()
        .expect("host nice");
    assert_eq!(code, host.status.code().unwrap_or(1) as u64);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
    assert_eq!(out.as_slice(), b"hi\n");
    let chrt = ["chrt", "-o", "0", path, "echo", "hi"];
    let argv: Vec<String> = chrt.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("chrt: {e}"));
    let host = Command::new(path)
        .args(chrt)
        .env_clear()
        .output()
        .expect("host chrt");
    assert_eq!(code, host.status.code().unwrap_or(1) as u64);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
    assert_eq!(out.as_slice(), b"hi\n");
    let nohup = ["nohup", path, "echo", "hi"];
    let argv: Vec<String> = nohup.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("nohup: {e}"));
    let host = Command::new(path)
        .args(nohup)
        .env_clear()
        .output()
        .expect("host nohup");
    assert_eq!(code, host.status.code().unwrap_or(1) as u64);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
    assert_eq!(out.as_slice(), b"hi\n");
    for (name, args) in [
        ("linux64", ["linux64", path, "echo", "hi"].as_slice()),
        ("linux32", ["linux32", path, "echo", "hi"].as_slice()),
        ("env", ["env", path, "echo", "hi"].as_slice()),
    ] {
        let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let host = Command::new(path)
            .args(args)
            .env_clear()
            .output()
            .unwrap_or_else(|e| panic!("host {name}: {e}"));
        assert_eq!(code, host.status.code().unwrap_or(1) as u64);
        assert_eq!(out.as_slice(), host.stdout.as_slice());
        assert_eq!(out.as_slice(), b"hi\n");
    }
    let taskset = ["taskset", "-c", "0", path, "echo", "hi"];
    let argv: Vec<String> = taskset.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("taskset: {e}"));
    let host = Command::new(path)
        .args(taskset)
        .env_clear()
        .output()
        .expect("host taskset");
    assert_eq!(code, host.status.code().unwrap_or(1) as u64);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
    assert_eq!(out.as_slice(), b"hi\n");
    let ionice = ["ionice", "-c", "3", path, "echo", "hi"];
    let argv: Vec<String> = ionice.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("ionice: {e}"));
    let host = Command::new(path)
        .args(ionice)
        .env_clear()
        .output()
        .expect("host ionice");
    assert_eq!(code, host.status.code().unwrap_or(1) as u64);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
    assert_eq!(out.as_slice(), b"hi\n");
    for (name, args) in [
        ("softlimit", ["softlimit", path, "echo", "hi"].as_slice()),
        (
            "softlimit -m",
            ["softlimit", "-m", "1000000000", path, "echo", "hi"].as_slice(),
        ),
        (
            "envuidgid",
            ["envuidgid", "0:0", path, "echo", "hi"].as_slice(),
        ),
        ("chpst", ["chpst", path, "echo", "hi"].as_slice()),
        ("setpriv", ["setpriv", path, "echo", "hi"].as_slice()),
        ("unshare", ["unshare", path, "echo", "hi"].as_slice()),
        ("nsenter", ["nsenter", path, "echo", "hi"].as_slice()),
        (
            "setarch linux64",
            ["setarch", "linux64", path, "echo", "hi"].as_slice(),
        ),
        (
            "setarch linux32",
            ["setarch", "linux32", path, "echo", "hi"].as_slice(),
        ),
    ] {
        let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let host = Command::new(path)
            .args(args)
            .env_clear()
            .output()
            .unwrap_or_else(|e| panic!("host {name}: {e}"));
        assert_eq!(code, host.status.code().unwrap_or(1) as u64);
        assert_eq!(out.as_slice(), host.stdout.as_slice());
        assert_eq!(out.as_slice(), b"hi\n");
    }
    // 権限がなく失敗する。標準出力は空、終了コードは 1。
    for (name, args) in [
        (
            "setuidgid",
            ["setuidgid", "65534", path, "echo", "hi"].as_slice(),
        ),
        ("chroot", ["chroot", "/", path, "echo", "hi"].as_slice()),
    ] {
        let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let host = Command::new(path)
            .args(args)
            .env_clear()
            .output()
            .unwrap_or_else(|e| panic!("host {name}: {e}"));
        assert_eq!(code, host.status.code().unwrap_or(1) as u64);
        assert_eq!(out.as_slice(), host.stdout.as_slice());
        assert_eq!(code, 1);
        assert!(out.is_empty());
    }
    let killall5 = ["killall5", "-l"];
    let argv: Vec<String> = killall5.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("killall5 -l: {e}"));
    let host = Command::new(path)
        .args(killall5)
        .env_clear()
        .output()
        .expect("host killall5 -l");
    assert_eq!(code, host.status.code().unwrap_or(1) as u64);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
    assert!(out.starts_with(b" 1) HUP\n"));
    // free は sysinfo と合成 /proc/meminfo の固定値。ホストとは比べない。
    let free = ["free"];
    let argv: Vec<String> = free.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("free: {e}"));
    assert_eq!(code, 0);
    assert_eq!(
        out.as_slice(),
        concat!(
            "              total        used        free      shared  buff/cache   available\n",
            "Mem:        1048576      524288      524288           0           0      524288\n",
            "-/+ buffers/cache:       524288      524288\n",
            "Swap:             0           0           0\n",
        )
        .as_bytes()
    );
    // 偽の比較は終了コード 1、標準出力は空。
    for (name, args) in [
        ("[", ["[", "1", "-eq", "2", "]"].as_slice()),
        ("[[", ["[[", "1", "-eq", "2", "]]"].as_slice()),
    ] {
        let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let host = Command::new(path)
            .args(args)
            .env_clear()
            .output()
            .unwrap_or_else(|e| panic!("host {name}: {e}"));
        assert_eq!(code, host.status.code().unwrap_or(1) as u64);
        assert_eq!(out.as_slice(), host.stdout.as_slice());
        assert_eq!(code, 1);
        assert!(out.is_empty());
    }
    // groups はゲストを root とみなす合成値。
    let groups = ["groups"];
    let argv: Vec<String> = groups.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("groups: {e}"));
    assert_eq!(code, 0);
    assert_eq!(out.as_slice(), b"root\n");
    let losetup = ["losetup", "-f"];
    let argv: Vec<String> = losetup.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("losetup -f: {e}"));
    let host = Command::new(path)
        .args(losetup)
        .env_clear()
        .output()
        .expect("host losetup -f");
    assert_eq!(code, host.status.code().unwrap_or(1) as u64);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
    assert!(out.starts_with(b"/dev/loop"));
    // reboot は EPERM。-f で直接 reboot を呼ぶ。標準出力は空、終了コードは 1。
    for (name, args) in [
        ("halt -f", ["halt", "-f"].as_slice()),
        ("poweroff -f", ["poweroff", "-f"].as_slice()),
        ("reboot -f", ["reboot", "-f"].as_slice()),
    ] {
        let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let host = Command::new(path)
            .args(args)
            .env_clear()
            .output()
            .unwrap_or_else(|e| panic!("host {name}: {e}"));
        assert_eq!(code, host.status.code().unwrap_or(1) as u64);
        assert_eq!(out.as_slice(), host.stdout.as_slice());
        assert_eq!(code, 1);
        assert!(out.is_empty());
    }
    // uptime は sysinfo と CLOCK_REALTIME の固定値。ホストとは比べない。
    let uptime = ["uptime"];
    let argv: Vec<String> = uptime.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("uptime: {e}"));
    assert_eq!(code, 0);
    assert_eq!(
        out.as_slice(),
        b" 01:00:00 up  1:00,  0 users,  load average: 0.00, 0.00, 0.00\n"
    );
    // whoami / hostname はゲストの固定値（root / localhost）。
    let whoami = ["whoami"];
    let argv: Vec<String> = whoami.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("whoami: {e}"));
    assert_eq!(code, 0);
    assert_eq!(out.as_slice(), b"root\n");
    let hostname = ["hostname"];
    let argv: Vec<String> = hostname.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("hostname: {e}"));
    assert_eq!(code, 0);
    assert_eq!(out.as_slice(), b"localhost\n");
    // dmesg は syslog の固定 1 行。ホストとは比べない。
    let dmesg = ["dmesg"];
    let argv: Vec<String> = dmesg.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("dmesg: {e}"));
    assert_eq!(code, 0);
    assert_eq!(out.as_slice(), b"[    0.000000] polyisa\n");
    // ホストと揃う。hwclock / rpm2cpio は失敗で標準出力が空。
    for (name, args) in [
        ("hwclock", ["hwclock"].as_slice()),
        ("rpm2cpio", ["rpm2cpio"].as_slice()),
        ("users", ["users"].as_slice()),
        ("w", ["w"].as_slice()),
        (
            "blockdev",
            ["blockdev", "--getsize64", "/dev/null"].as_slice(),
        ),
        ("volname", ["volname"].as_slice()),
        ("dumpkmap", ["dumpkmap"].as_slice()),
        ("loadkmap", ["loadkmap"].as_slice()),
        ("eject", ["eject"].as_slice()),
        ("fbset", ["fbset"].as_slice()),
        ("kbdrate", ["kbdrate"].as_slice()),
        ("pipesz", ["pipesz"].as_slice()),
        ("lspci", ["lspci"].as_slice()),
        ("pmap", ["pmap", "1"].as_slice()),
        ("pwdx", ["pwdx", "1"].as_slice()),
        ("add-shell", ["add-shell"].as_slice()),
        ("depmod", ["depmod"].as_slice()),
        ("dumpleases", ["dumpleases"].as_slice()),
        ("fgconsole", ["fgconsole"].as_slice()),
        ("hdparm", ["hdparm"].as_slice()),
        ("kbd_mode", ["kbd_mode"].as_slice()),
        ("last", ["last"].as_slice()),
        ("loadfont", ["loadfont"].as_slice()),
        ("mesg", ["mesg"].as_slice()),
        ("readprofile", ["readprofile"].as_slice()),
        ("remove-shell", ["remove-shell"].as_slice()),
        ("runlevel", ["runlevel"].as_slice()),
        ("setconsole", ["setconsole"].as_slice()),
        ("setlogcons", ["setlogcons"].as_slice()),
        ("showkey", ["showkey"].as_slice()),
        ("stty", ["stty"].as_slice()),
        ("tunctl", ["tunctl"].as_slice()),
        ("uncompress", ["uncompress"].as_slice()),
        ("uudecode", ["uudecode"].as_slice()),
        ("vlock", ["vlock"].as_slice()),
        ("addgroup", ["addgroup", "nosuch"].as_slice()),
        ("adduser", ["adduser", "-D", "nosuch"].as_slice()),
        ("delgroup", ["delgroup", "nosuch"].as_slice()),
        ("deluser", ["deluser", "nosuch"].as_slice()),
        ("crontab", ["crontab", "-l"].as_slice()),
        ("devmem", ["devmem", "0"].as_slice()),
        ("mt", ["mt"].as_slice()),
        ("mt status", ["mt", "status"].as_slice()),
        ("rmmod", ["rmmod", "x"].as_slice()),
        ("modprobe", ["modprobe", "x"].as_slice()),
        ("modprobe -r", ["modprobe", "-r", "x"].as_slice()),
        (
            "start-stop-daemon",
            ["start-stop-daemon", "-K", "-x", "/bin/true"].as_slice(),
        ),
        ("svok", ["svok", "/"].as_slice()),
        ("ipcrm -M", ["ipcrm", "-M", "1"].as_slice()),
        ("ipcrm -Q", ["ipcrm", "-Q", "1"].as_slice()),
        ("ipcrm -S", ["ipcrm", "-S", "1"].as_slice()),
        ("resize", ["resize"].as_slice()),
        ("chvt", ["chvt", "1"].as_slice()),
        ("deallocvt", ["deallocvt", "1"].as_slice()),
        ("openvt", ["openvt", "true"].as_slice()),
        ("renice", ["renice", "0", "1"].as_slice()),
        ("cttyhack", ["cttyhack"].as_slice()),
        ("login", ["login", "-h", "x"].as_slice()),
        ("lpd", ["lpd"].as_slice()),
        ("sendmail", ["sendmail"].as_slice()),
        ("popmaildir", ["popmaildir"].as_slice()),
        ("vconfig", ["vconfig", "rem", "eth0.1"].as_slice()),
        ("lpq", ["lpq"].as_slice()),
        ("lpr", ["lpr"].as_slice()),
        ("rdate", ["rdate", "-p", "127.0.0.1"].as_slice()),
        ("nc", ["nc"].as_slice()),
        ("arping", ["arping"].as_slice()),
        ("nslookup", ["nslookup", "localhost"].as_slice()),
        ("traceroute", ["traceroute", "127.0.0.1"].as_slice()),
        ("httpd", ["httpd"].as_slice()),
        ("dnsd", ["dnsd"].as_slice()),
        ("sulogin", ["sulogin"].as_slice()),
        ("traceroute6", ["traceroute6", "::1"].as_slice()),
        ("ping", ["ping", "-c1", "127.0.0.1"].as_slice()),
        ("ping6", ["ping6", "-c1", "::1"].as_slice()),
        ("telnet", ["telnet", "127.0.0.1"].as_slice()),
        ("conspy", ["conspy"].as_slice()),
        ("mim", ["mim"].as_slice()),
        ("wget", ["wget", "http://127.0.0.1/"].as_slice()),
        ("rx", ["rx", "-h"].as_slice()),
        ("[[", ["[["].as_slice()),
        ("arp", ["arp", "-h"].as_slice()),
        ("ifconfig", ["ifconfig", "-h"].as_slice()),
        ("tc", ["tc", "-h"].as_slice()),
        ("dpkg", ["dpkg", "-l"].as_slice()),
        ("hexedit", ["hexedit", "/tmp"].as_slice()),
        ("nameif", ["nameif", "eth9", "00:00:00:00:00:00"].as_slice()),
        ("ifenslave", ["ifenslave", "eth0", "eth1"].as_slice()),
        ("mkfifo", ["mkfifo", "/tmp/no/fifo"].as_slice()),
        ("mknod", ["mknod", "/tmp/no/node", "c", "1", "1"].as_slice()),
        ("fsync", ["fsync", "/no/such"].as_slice()),
        ("runsv", ["runsv", "/no"].as_slice()),
        (
            "whois",
            ["whois", "-h", "127.0.0.1", "example.com"].as_slice(),
        ),
        ("ash", ["ash", "-c", "exit 2"].as_slice()),
        ("sh", ["sh", "-c", "exit 2"].as_slice()),
        ("setfattr", ["setfattr", "-n", "user.x", "/no"].as_slice()),
        (
            "mount",
            ["mount", "-t", "ext4", "/etc/passwd", "/tmp"].as_slice(),
        ),
        (
            "switch_root",
            ["switch_root", "/no", "/bin/true"].as_slice(),
        ),
        ("run-init", ["run-init", "/no", "/bin/true"].as_slice()),
        ("ssl_client", ["ssl_client", "-s", "127.0.0.1"].as_slice()),
        (
            "ftpget",
            ["ftpget", "-u", "x", "127.0.0.1", "/tmp/x", "/x"].as_slice(),
        ),
        ("zcip", ["zcip", "eth0", "/tmp/zcip"].as_slice()),
        ("tcpsvd", ["tcpsvd", "127.0.0.1", "9", "true"].as_slice()),
        ("udpsvd", ["udpsvd", "127.0.0.1", "9", "true"].as_slice()),
        ("dhcprelay", ["dhcprelay", "eth0", "127.0.0.1"].as_slice()),
        ("ifplugd", ["ifplugd", "-i", "lo", "-n"].as_slice()),
        ("syslogd", ["syslogd", "-n"].as_slice()),
        ("crond", ["crond", "-f", "-L", "/dev/null"].as_slice()),
        ("telnetd", ["telnetd", "-F"].as_slice()),
        (
            "i2ctransfer",
            ["i2ctransfer", "-y", "0", "w1@0x48"].as_slice(),
        ),
        ("svlogd", ["svlogd", "/no"].as_slice()),
        ("pscan", ["pscan", "-p", "1-2", "127.0.0.1"].as_slice()),
        ("acpid", ["acpid", "-d"].as_slice()),
        ("udhcpc", ["udhcpc", "-n", "-q", "-i", "lo"].as_slice()),
        ("hush", ["hush", "-c", "exit 3"].as_slice()),
        ("wall", ["wall", "hello"].as_slice()),
        (
            "ftpput",
            ["ftpput", "-u", "x", "127.0.0.1", "/x", "/etc/passwd"].as_slice(),
        ),
        (
            "nbd-client",
            ["nbd-client", "127.0.0.1", "1024", "/dev/null"].as_slice(),
        ),
    ] {
        let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let host = Command::new(path)
            .args(args)
            .env_clear()
            .output()
            .unwrap_or_else(|e| panic!("host {name}: {e}"));
        assert_eq!(code, host.status.code().unwrap_or(1) as u64);
        assert_eq!(out.as_slice(), host.stdout.as_slice());
    }
}

#[test]
fn chgrp_unknown_group_matches_host() {
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let dir = std::env::temp_dir().join(format!("polyisa-chgrp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let f = dir.join("f");
    std::fs::write(&f, b"x").unwrap();
    let args = ["chgrp", "nogroup", f.to_str().expect("utf-8")];
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("chgrp: {e}"));
    let host = Command::new(path)
        .args(args)
        .env_clear()
        .output()
        .expect("host chgrp");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(code, host.status.code().unwrap_or(1) as u64);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
    assert_eq!(code, 1);
    assert!(out.is_empty());
}

#[test]
fn chown_unknown_user_matches_host() {
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let dir = std::env::temp_dir().join(format!("polyisa-chown-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let f = dir.join("f");
    std::fs::write(&f, b"x").unwrap();
    let args = ["chown", "nosuchuser", f.to_str().expect("utf-8")];
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("chown: {e}"));
    let host = Command::new(path)
        .args(args)
        .env_clear()
        .output()
        .expect("host chown");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(code, host.status.code().unwrap_or(1) as u64);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
    assert_eq!(code, 1);
    assert!(out.is_empty());
}

#[test]
fn device_and_fs_fail_matches_host() {
    // 通常ファイルやディレクトリに対して失敗し、標準出力は空のまま揃うもの。
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let dir = std::env::temp_dir().join(format!("polyisa-fsfail-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let f = dir.join("f");
    std::fs::write(&f, b"hello\n").unwrap();
    let put_old = dir.join("put_old");
    std::fs::create_dir(&put_old).unwrap();
    let f = f.to_str().expect("utf-8");
    let d = dir.to_str().expect("utf-8");
    let put_old = put_old.to_str().expect("utf-8");
    let flash_out = format!("{d}/flashcp-out");
    for (name, args) in [
        ("chattr", ["chattr", "-V", f].as_slice()),
        ("mkswap", ["mkswap", f].as_slice()),
        ("rpm", ["rpm", "-qp", f].as_slice()),
        ("fatattr", ["fatattr", f].as_slice()),
        ("blkdiscard", ["blkdiscard", f].as_slice()),
        ("partprobe", ["partprobe", f].as_slice()),
        ("fsck.minix", ["fsck.minix", f].as_slice()),
        ("mkfs.minix", ["mkfs.minix", f].as_slice()),
        ("mkfs.vfat", ["mkfs.vfat", f].as_slice()),
        ("mkdosfs", ["mkdosfs", f].as_slice()),
        ("fsfreeze", ["fsfreeze", "--freeze", d].as_slice()),
        ("fstrim", ["fstrim", d].as_slice()),
        ("setfont", ["setfont", f].as_slice()),
        ("fdformat", ["fdformat", f].as_slice()),
        ("insmod", ["insmod", f].as_slice()),
        ("swapon", ["swapon", f].as_slice()),
        ("swapoff", ["swapoff", f].as_slice()),
        ("pivot_root", ["pivot_root", d, put_old].as_slice()),
        ("flash_unlock", ["flash_unlock", f].as_slice()),
        ("flash_eraseall", ["flash_eraseall", f].as_slice()),
        ("flashcp", ["flashcp", f, flash_out.as_str()].as_slice()),
        ("i2cdump", ["i2cdump", "0", "0x50"].as_slice()),
        ("i2cget", ["i2cget", "0", "0x50"].as_slice()),
        ("i2cset", ["i2cset", "0", "0x50", "0", "0"].as_slice()),
        ("mke2fs", ["mke2fs", f].as_slice()),
        ("mkfs.ext2", ["mkfs.ext2", f].as_slice()),
        ("mktemp", ["mktemp", f].as_slice()),
        ("mpstat", ["mpstat", f].as_slice()),
        ("su", ["su", f].as_slice()),
        ("ipaddr", ["ipaddr", f].as_slice()),
        ("iplink", ["iplink", f].as_slice()),
        ("ipneigh", ["ipneigh", f].as_slice()),
        ("iproute", ["iproute", f].as_slice()),
        ("iprule", ["iprule", f].as_slice()),
        ("iptunnel", ["iptunnel", f].as_slice()),
        ("slattach", ["slattach", f].as_slice()),
        ("brctl", ["brctl", f].as_slice()),
        ("fdisk", ["fdisk", f].as_slice()),
        ("losetup file", ["losetup", f].as_slice()),
        ("mkfs.reiser", ["mkfs.reiser", f].as_slice()),
        ("dpkg-deb", ["dpkg-deb", f].as_slice()),
        ("makedevs", ["makedevs", f].as_slice()),
        ("scriptreplay", ["scriptreplay", f].as_slice()),
        ("fbsplash", ["fbsplash", "-s", f].as_slice()),
        ("fdflush", ["fdflush", f].as_slice()),
        ("freeramdisk", ["freeramdisk", f].as_slice()),
        ("raidautorun", ["raidautorun", f].as_slice()),
        ("resume", ["resume", f].as_slice()),
        ("setkeycodes", ["setkeycodes", "0", "0"].as_slice()),
        ("umount", ["umount", f].as_slice()),
        ("flock", ["flock", "-u", f].as_slice()),
        ("flash_lock", ["flash_lock", f, "0", "1"].as_slice()),
        ("microcom", ["microcom", f].as_slice()),
    ] {
        let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let host = Command::new(path)
            .args(args)
            .env_clear()
            .output()
            .unwrap_or_else(|e| panic!("host {name}: {e}"));
        assert_eq!(code, host.status.code().unwrap_or(1) as u64, "{name}");
        assert_eq!(out.as_slice(), host.stdout.as_slice(), "{name}");
        assert!(out.is_empty(), "{name}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ls_one_file_matches_host() {
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let dir = std::env::temp_dir().join(format!("polyisa-ls-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("f"), b"ab\ncd\n").unwrap();
    let args = ["ls", dir.to_str().expect("utf-8")];
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("ls: {e}"));
    let host = Command::new(path)
        .args(args)
        .env_clear()
        .output()
        .expect("host ls");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(host.status.success());
    assert_eq!(code, 0);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
}

#[test]
fn wc_one_file_matches_host() {
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let dir = std::env::temp_dir().join(format!("polyisa-wc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let file = dir.join("f");
    std::fs::write(&file, b"ab\ncd\n").unwrap();
    let args = ["wc", file.to_str().expect("utf-8")];
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("wc: {e}"));
    let host = Command::new(path)
        .args(args)
        .env_clear()
        .output()
        .expect("host wc");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(host.status.success());
    assert_eq!(code, 0);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
}

#[test]
fn od_one_file_matches_host() {
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let dir = std::env::temp_dir().join(format!("polyisa-od-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let file = dir.join("f");
    std::fs::write(&file, b"ab\ncd\n").unwrap();
    let args = ["od", file.to_str().expect("utf-8")];
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("od: {e}"));
    let host = Command::new(path)
        .args(args)
        .env_clear()
        .output()
        .expect("host od");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(host.status.success());
    assert_eq!(code, 0);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
}

#[test]
fn sed_one_file_matches_host() {
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let dir = std::env::temp_dir().join(format!("polyisa-sed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let file = dir.join("f");
    std::fs::write(&file, b"ab\ncd\n").unwrap();
    let file_s = file.to_str().expect("utf-8");
    let args = ["sed", "s/a/A/", file_s];
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("sed: {e}"));
    let host = Command::new(path)
        .args(args)
        .env_clear()
        .output()
        .expect("host sed");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(host.status.success());
    assert_eq!(code, 0);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
}

#[test]
fn awk_print_matches_host() {
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let dir = std::env::temp_dir().join(format!("polyisa-awk-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let file = dir.join("f");
    std::fs::write(&file, b"ab\ncd\n").unwrap();
    let file_s = file.to_str().expect("utf-8");
    let args = ["awk", "{print}", file_s];
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("awk: {e}"));
    let host = Command::new(path)
        .args(args)
        .env_clear()
        .output()
        .expect("host awk");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(host.status.success());
    assert_eq!(code, 0);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
}

#[test]
fn xxd_one_file_matches_host() {
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let dir = std::env::temp_dir().join(format!("polyisa-xxd-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let file = dir.join("f");
    std::fs::write(&file, b"ab\ncd\n").unwrap();
    let args = ["xxd", file.to_str().expect("utf-8")];
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("xxd: {e}"));
    let host = Command::new(path)
        .args(args)
        .env_clear()
        .output()
        .expect("host xxd");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(host.status.success());
    assert_eq!(code, 0);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
}

#[test]
fn grep_one_file_matches_host() {
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let dir = std::env::temp_dir().join(format!("polyisa-grep-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let file = dir.join("f");
    std::fs::write(&file, b"ab\ncd\nab\n").unwrap();
    let file_s = file.to_str().expect("utf-8");
    let args = ["grep", "a", file_s];
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("grep: {e}"));
    let host = Command::new(path)
        .args(args)
        .env_clear()
        .output()
        .expect("host grep");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(host.status.success());
    assert_eq!(code, 0);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
}

#[test]
fn seq_one_to_three_matches_host() {
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let args = ["seq", "1", "3"];
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("seq: {e}"));
    let host = Command::new(path)
        .args(args)
        .env_clear()
        .output()
        .expect("host seq");
    assert!(host.status.success());
    assert_eq!(code, 0);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
}

#[test]
fn text_applets_match_host() {
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let dir = std::env::temp_dir().join(format!("polyisa-text-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let sub = dir.join("sub");
    std::fs::create_dir(&sub).unwrap();
    let file = dir.join("f");
    let other = dir.join("g");
    let tabs = dir.join("t");
    let bin = dir.join("bin");
    std::fs::write(&file, b"ab\ncd\nab\n").unwrap();
    std::fs::write(&other, b"ab\nxx\n").unwrap();
    std::fs::write(&tabs, b"hello world\n\thello\n").unwrap();
    std::fs::write(&bin, b"abc\0def\n").unwrap();
    std::fs::write(sub.join("f"), b"ab\ncd\nab\n").unwrap();
    let f = file.to_str().expect("utf-8");
    let g = other.to_str().expect("utf-8");
    let t = tabs.to_str().expect("utf-8");
    let binf = bin.to_str().expect("utf-8");
    let dir_s = dir.to_str().expect("utf-8");
    let copied = dir.join("copied");
    let touched = dir.join("touched");
    let trunc = dir.join("trunc");
    std::fs::write(&trunc, b"abcdef").unwrap();
    let trunc_s = trunc.to_str().expect("utf-8");
    let installed = dir.join("installed");
    let installed_s = installed.to_str().expect("utf-8");
    let dd_if = format!("if={f}");
    let dcprog = dir.join("dcprog");
    std::fs::write(&dcprog, b"2 3 + p\n").unwrap();
    let dcprog_s = dcprog.to_str().expect("utf-8");
    let b64 = dir.join("b64");
    std::fs::write(&b64, b"YWIK\n").unwrap();
    let b64_s = b64.to_str().expect("utf-8");
    let gz = dir.join("f.gz");
    let gz_out = Command::new(path)
        .args(["gzip", "-c", f])
        .env_clear()
        .output()
        .expect("host gzip");
    std::fs::write(&gz, &gz_out.stdout).unwrap();
    let gz_s = gz.to_str().expect("utf-8");
    let bz = dir.join("f.bz2");
    let bz_out = Command::new(path)
        .args(["bzip2", "-c", f])
        .env_clear()
        .output()
        .expect("host bzip2");
    std::fs::write(&bz, &bz_out.stdout).unwrap();
    let bz_s = bz.to_str().expect("utf-8");
    let lzo = dir.join("f.lzo");
    let lzo_out = Command::new(path)
        .args(["lzop", "-c", f])
        .env_clear()
        .output()
        .expect("host lzop");
    std::fs::write(&lzo, &lzo_out.stdout).unwrap();
    let lzo_s = lzo.to_str().expect("utf-8");
    // BusyBox 1.35 の xz / lzma は展開専用。同じ 9 バイトから作ったストリームを埋め込む。
    let xz = dir.join("f.xz");
    std::fs::write(
        &xz,
        [
            253, 55, 122, 88, 90, 0, 0, 4, 230, 214, 180, 70, 4, 192, 13, 9, 33, 1, 22, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 95, 79, 51, 228, 1, 0, 8, 97, 98, 10, 99, 100, 10, 97, 98, 10, 0, 0, 0,
            0, 109, 228, 144, 139, 163, 56, 240, 229, 0, 1, 41, 9, 100, 146, 28, 29, 31, 182, 243,
            125, 1, 0, 0, 0, 0, 4, 89, 90,
        ],
    )
    .unwrap();
    let xz_s = xz.to_str().expect("utf-8");
    let lz = dir.join("f.lzma");
    std::fs::write(
        &lz,
        [
            93, 0, 0, 128, 0, 255, 255, 255, 255, 255, 255, 255, 255, 0, 48, 152, 125, 69, 251, 49,
            19, 221, 58, 16, 89, 254, 123, 255, 255, 55, 160, 0, 0,
        ],
    )
    .unwrap();
    let lz_s = lz.to_str().expect("utf-8");
    let zip = dir.join("f.zip");
    std::fs::write(
        &zip,
        [
            80, 75, 3, 4, 20, 0, 0, 0, 0, 0, 64, 78, 108, 93, 240, 116, 203, 232, 9, 0, 0, 0, 9, 0,
            0, 0, 1, 0, 0, 0, 102, 97, 98, 10, 99, 100, 10, 97, 98, 10, 80, 75, 1, 2, 20, 3, 20, 0,
            0, 0, 0, 0, 64, 78, 108, 93, 240, 116, 203, 232, 9, 0, 0, 0, 9, 0, 0, 0, 1, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 164, 129, 0, 0, 0, 0, 102, 80, 75, 5, 6, 0, 0, 0, 0, 1, 0, 1, 0,
            47, 0, 0, 0, 40, 0, 0, 0, 0, 0,
        ],
    )
    .unwrap();
    let zip_s = zip.to_str().expect("utf-8");
    let tar_path = dir.join("f.tar");
    let tar_ok = Command::new("tar")
        .current_dir(&dir)
        .args(["-cf", "f.tar", "f"])
        .status()
        .expect("host tar")
        .success();
    assert!(tar_ok);
    let tar_s = tar_path.to_str().expect("utf-8");
    let ar_path = dir.join("f.a");
    let ar_ok = Command::new("ar")
        .current_dir(&dir)
        .args(["cr", "f.a", "f"])
        .status()
        .expect("host ar")
        .success();
    assert!(ar_ok);
    let ar_s = ar_path.to_str().expect("utf-8");
    let cin = dir.join("cin");
    std::fs::create_dir(&cin).unwrap();
    std::fs::write(cin.join("f"), b"ab\n").unwrap();
    let names = Command::new("find")
        .current_dir(&cin)
        .arg(".")
        .output()
        .expect("host find");
    assert!(names.status.success());
    let mut cpio_child = Command::new("cpio")
        .current_dir(&cin)
        .args(["-o", "-H", "newc"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("host cpio");
    cpio_child
        .stdin
        .take()
        .expect("cpio stdin")
        .write_all(&names.stdout)
        .expect("cpio names");
    let archived = cpio_child.wait_with_output().expect("cpio wait");
    assert!(archived.status.success());
    let cpio_path = dir.join("f.cpio");
    std::fs::write(&cpio_path, &archived.stdout).unwrap();
    let cpio_s = cpio_path.to_str().expect("utf-8");
    let copied_s = copied.to_str().expect("utf-8");
    let touched_s = touched.to_str().expect("utf-8");
    let link = dir.join("link");
    polyisa_host::symlink(f, link.to_str().expect("utf-8")).unwrap();
    let link_s = link.to_str().expect("utf-8");
    let cases: &[&[&str]] = &[
        &["cat", f],
        &["head", "-n", "2", f],
        &["tail", "-n", "1", f],
        &["uniq", f],
        &["cut", "-c1", f],
        &["cut", "-d", "a", "-f2", f],
        &["printf", "%s\n", "hi"],
        &["expr", "1", "+", "2"],
        &["rev", f],
        &["nl", f],
        &["paste", f, g],
        &["comm", f, g],
        &["expand", t],
        &["fold", "-w", "4", t],
        &["tac", f],
        &["cksum", f],
        &["sum", f],
        &["base64", f],
        &["strings", binf],
        &["md5sum", f],
        &["sha256sum", f],
        &["sha512sum", f],
        &["hexdump", "-C", f],
        &["find", dir_s, "-name", "f"],
        &["test", "-f", f],
        &["cmp", f, f],
        &["sort", f],
        &["fgrep", "ab", f],
        &["false"],
        &["pwd"],
        &["factor", "12"],
        &["unexpand", t],
        &["egrep", "a.", f],
        &["env"],
        &["sha1sum", f],
        &["wc", "-c", f],
        &["printf", "%x\n", "255"],
        &["arch"],
        &["uniq", "-c", f],
        &["sleep", "0"],
        &["nproc"],
        &["cp", f, copied_s],
        &["touch", touched_s],
        &["chmod", "644", f],
        &["wc", "-l", f],
        &["date", "-u", "-d", "@0", "+%s"],
        &["readlink", link_s],
        &["readlink", "-f", f],
        &["realpath", f],
        &["cmp", f, g],
        &["diff", "-q", f, g],
        &["cal", "1", "2000"],
        &["logname"],
        &["tty"],
        &["base32", f],
        &["crc32", f],
        &["hd", f],
        &["gzip", "-c", f],
        &["bzip2", "-c", f],
        &["dd", dd_if.as_str(), "bs=2", "count=2"],
        &["basename", f],
        &["dirname", f],
        &["getopt", "-o", "a", "--", "-a"],
        &["hostid"],
        &["usleep", "0"],
        &["bc"],
        &["sync"],
        &["sed", "/cd/d", f],
        &["base64", "-d", b64_s],
        &["dc", dcprog_s],
        &["ascii"],
        &["clear"],
        &["less", f],
        &["ed", f],
        &["rdev"],
        &["script"],
        &["sha3sum", f],
        &["awk", "{print}", f],
        &["seq", "1", "3"],
        &["od", f],
        &["grep", "ab", f],
        &["ls", f],
        &["more", f],
        &["xxd", f],
        &["uuencode", f],
        &["cryptpw", "secret", "sa"],
        &["pgrep", "nosuchname123"],
        &["gunzip", "-c", gz_s],
        &["zcat", gz_s],
        &["bzcat", bz_s],
        &["bunzip2", "-c", bz_s],
        &["lzop", "-c", f],
        &["lzopcat", lzo_s],
        &["unlzop", "-c", lzo_s],
        &["xzcat", xz_s],
        &["unxz", "-c", xz_s],
        &["lzcat", lz_s],
        &["unlzma", "-c", lz_s],
        &["tar", "-tf", tar_s],
        &["ar", "t", ar_s],
        &["lzma", "-d", "-c", lz_s],
        &["xz", "-d", "-c", xz_s],
        &["unzip", "-l", zip_s],
        &["shuf", "-e", "only"],
        &["killall", "-l"],
        &["pkill", "nosuchname123"],
        &["mkpasswd", "secret", "sa"],
        &["kill", "-l"],
        &["pidof", "nosuchname123"],
        &["stat", "-c", "%s", f],
        &["du", "-b", f],
        &["fsck"],
        &["ipcalc", "-n", "10.0.0.1/24"],
        &["printenv"],
        &["which", "true"],
        &["install", "-m", "644", f, installed_s],
        &["truncate", "-s", "2", trunc_s],
        &["mountpoint", "/"],
        &["[", "-f", "nosuch123", "]"],
        &["findfs", "LABEL=nope"],
        &["envdir", f, "true"],
        &["cpio", "-t", "-F", cpio_s],
        &["lsattr", f],
    ];
    for args in cases {
        let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
            .unwrap_or_else(|e| panic!("{}: {e}", args.join(" ")));
        let host = Command::new(path)
            .args(*args)
            .env_clear()
            .output()
            .unwrap_or_else(|e| panic!("host {}: {e}", args[0]));
        assert_eq!(
            code,
            host.status.code().unwrap_or(1) as u64,
            "{}",
            args.join(" ")
        );
        assert_eq!(out.as_slice(), host.stdout.as_slice(), "{}", args.join(" "));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn link_matches_host() {
    // ゲストとホストは別の木を変える。同じパスだと先に作った側が EEXIST になる。
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let root = std::env::temp_dir().join(format!("polyisa-link-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let guest_dir = root.join("guest");
    let host_dir = root.join("host");
    std::fs::create_dir_all(&guest_dir).unwrap();
    std::fs::create_dir_all(&host_dir).unwrap();
    let guest_src = guest_dir.join("f");
    let host_src = host_dir.join("f");
    std::fs::write(&guest_src, b"ab\n").unwrap();
    std::fs::write(&host_src, b"ab\n").unwrap();
    let guest_dst = guest_dir.join("hard");
    let host_dst = host_dir.join("hard");
    let args = [
        "link",
        guest_src.to_str().expect("utf-8"),
        guest_dst.to_str().expect("utf-8"),
    ];
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("link: {e}"));
    let host = Command::new(path)
        .args([
            "link",
            host_src.to_str().expect("utf-8"),
            host_dst.to_str().expect("utf-8"),
        ])
        .env_clear()
        .output()
        .expect("host link");
    assert_eq!(code, host.status.code().unwrap_or(1) as u64);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
    assert_eq!(std::fs::read(&guest_dst).unwrap(), b"ab\n");
    assert_eq!(std::fs::read(&host_dst).unwrap(), b"ab\n");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn file_ops_match_host() {
    // ゲストとホストは別の木を変える。同じパスだと先に作った側が EEXIST になる。
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let root = std::env::temp_dir().join(format!("polyisa-fileops-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let guest_dir = root.join("guest");
    let host_dir = root.join("host");
    std::fs::create_dir_all(&guest_dir).unwrap();
    std::fs::create_dir_all(&host_dir).unwrap();
    let pair = |guest_args: &[&str], host_args: &[&str]| {
        let argv: Vec<String> = guest_args.iter().map(|s| (*s).to_string()).collect();
        let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
            .unwrap_or_else(|e| panic!("{}: {e}", guest_args.join(" ")));
        let host = Command::new(path)
            .args(host_args)
            .env_clear()
            .output()
            .unwrap_or_else(|e| panic!("host {}: {e}", host_args[0]));
        assert_eq!(
            code,
            host.status.code().unwrap_or(1) as u64,
            "{}",
            guest_args[0]
        );
        assert_eq!(out.as_slice(), host.stdout.as_slice(), "{}", guest_args[0]);
    };
    let guest_made = guest_dir.join("made");
    let host_made = host_dir.join("made");
    pair(
        &["mkdir", guest_made.to_str().expect("utf-8")],
        &["mkdir", host_made.to_str().expect("utf-8")],
    );
    assert!(guest_made.is_dir());
    assert!(host_made.is_dir());
    pair(
        &["rmdir", guest_made.to_str().expect("utf-8")],
        &["rmdir", host_made.to_str().expect("utf-8")],
    );
    assert!(!guest_made.exists());
    assert!(!host_made.exists());
    let guest_file = guest_dir.join("f");
    let host_file = host_dir.join("f");
    std::fs::write(&guest_file, b"ab\n").unwrap();
    std::fs::write(&host_file, b"ab\n").unwrap();
    pair(
        &["rm", guest_file.to_str().expect("utf-8")],
        &["rm", host_file.to_str().expect("utf-8")],
    );
    assert!(!guest_file.exists());
    assert!(!host_file.exists());
    std::fs::write(&guest_file, b"ab\n").unwrap();
    std::fs::write(&host_file, b"ab\n").unwrap();
    pair(
        &["unlink", guest_file.to_str().expect("utf-8")],
        &["unlink", host_file.to_str().expect("utf-8")],
    );
    assert!(!guest_file.exists());
    assert!(!host_file.exists());
    std::fs::write(&guest_file, b"ab\n").unwrap();
    std::fs::write(&host_file, b"ab\n").unwrap();
    let guest_moved = guest_dir.join("g");
    let host_moved = host_dir.join("g");
    pair(
        &[
            "mv",
            guest_file.to_str().expect("utf-8"),
            guest_moved.to_str().expect("utf-8"),
        ],
        &[
            "mv",
            host_file.to_str().expect("utf-8"),
            host_moved.to_str().expect("utf-8"),
        ],
    );
    assert_eq!(std::fs::read(&guest_moved).unwrap(), b"ab\n");
    assert_eq!(std::fs::read(&host_moved).unwrap(), b"ab\n");
    assert!(!guest_file.exists());
    assert!(!host_file.exists());
    std::fs::write(&guest_file, b"ab\n").unwrap();
    std::fs::write(&host_file, b"ab\n").unwrap();
    let guest_link = guest_dir.join("l");
    let host_link = host_dir.join("l");
    pair(
        &[
            "ln",
            "-s",
            guest_file.to_str().expect("utf-8"),
            guest_link.to_str().expect("utf-8"),
        ],
        &[
            "ln",
            "-s",
            host_file.to_str().expect("utf-8"),
            host_link.to_str().expect("utf-8"),
        ],
    );
    assert_eq!(
        std::fs::read_link(&guest_link).unwrap(),
        guest_file.as_os_str()
    );
    assert_eq!(
        std::fs::read_link(&host_link).unwrap(),
        host_file.as_os_str()
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn more_file_results_match_host() {
    // 標準出力は空で、ファイルの結果が一致する。別の木へ書く。
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let root = std::env::temp_dir().join(format!("polyisa-morefiles-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let guest_dir = root.join("guest");
    let host_dir = root.join("host");
    std::fs::create_dir_all(&guest_dir).unwrap();
    std::fs::create_dir_all(&host_dir).unwrap();
    let pair = |guest_args: &[&str], host_args: &[&str]| {
        let argv: Vec<String> = guest_args.iter().map(|s| (*s).to_string()).collect();
        let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
            .unwrap_or_else(|e| panic!("{}: {e}", guest_args.join(" ")));
        let host = Command::new(path)
            .args(host_args)
            .env_clear()
            .output()
            .unwrap_or_else(|e| panic!("host {}: {e}", host_args[0]));
        assert_eq!(
            code,
            host.status.code().unwrap_or(1) as u64,
            "{}",
            guest_args[0]
        );
        assert_eq!(out.as_slice(), host.stdout.as_slice(), "{}", guest_args[0]);
    };
    let g = guest_dir.join("ln");
    let h = host_dir.join("ln");
    std::fs::create_dir_all(&g).unwrap();
    std::fs::create_dir_all(&h).unwrap();
    let gsrc = g.join("a");
    let hsrc = h.join("a");
    std::fs::write(&gsrc, b"ab\n").unwrap();
    std::fs::write(&hsrc, b"ab\n").unwrap();
    pair(
        &[
            "ln",
            gsrc.to_str().expect("utf-8"),
            g.join("b").to_str().expect("utf-8"),
        ],
        &[
            "ln",
            hsrc.to_str().expect("utf-8"),
            h.join("b").to_str().expect("utf-8"),
        ],
    );
    assert_eq!(std::fs::read(g.join("b")).unwrap(), b"ab\n");
    assert_eq!(std::fs::read(h.join("b")).unwrap(), b"ab\n");

    let g = guest_dir.join("gz");
    let h = host_dir.join("gz");
    std::fs::create_dir_all(&g).unwrap();
    std::fs::create_dir_all(&h).unwrap();
    std::fs::write(g.join("f"), b"ab\ncd\n").unwrap();
    std::fs::write(h.join("f"), b"ab\ncd\n").unwrap();
    pair(
        &["gzip", g.join("f").to_str().expect("utf-8")],
        &["gzip", h.join("f").to_str().expect("utf-8")],
    );
    assert!(!g.join("f").exists());
    assert_eq!(
        std::fs::read(g.join("f.gz")).unwrap(),
        std::fs::read(h.join("f.gz")).unwrap()
    );

    let g = guest_dir.join("bz");
    let h = host_dir.join("bz");
    std::fs::create_dir_all(&g).unwrap();
    std::fs::create_dir_all(&h).unwrap();
    std::fs::write(g.join("f"), b"ab\ncd\n").unwrap();
    std::fs::write(h.join("f"), b"ab\ncd\n").unwrap();
    pair(
        &["bzip2", g.join("f").to_str().expect("utf-8")],
        &["bzip2", h.join("f").to_str().expect("utf-8")],
    );
    assert!(!g.join("f").exists());
    assert_eq!(
        std::fs::read(g.join("f.bz2")).unwrap(),
        std::fs::read(h.join("f.bz2")).unwrap()
    );

    let g = guest_dir.join("sed");
    let h = host_dir.join("sed");
    std::fs::create_dir_all(&g).unwrap();
    std::fs::create_dir_all(&h).unwrap();
    std::fs::write(g.join("f"), b"ab\ncd\n").unwrap();
    std::fs::write(h.join("f"), b"ab\ncd\n").unwrap();
    pair(
        &["sed", "-i", "/cd/d", g.join("f").to_str().expect("utf-8")],
        &["sed", "-i", "/cd/d", h.join("f").to_str().expect("utf-8")],
    );
    assert_eq!(std::fs::read(g.join("f")).unwrap(), b"ab\n");
    assert_eq!(std::fs::read(h.join("f")).unwrap(), b"ab\n");

    let g = guest_dir.join("mk");
    let h = host_dir.join("mk");
    pair(
        &["mkdir", "-p", g.join("a/b").to_str().expect("utf-8")],
        &["mkdir", "-p", h.join("a/b").to_str().expect("utf-8")],
    );
    assert!(g.join("a/b").is_dir());
    assert!(h.join("a/b").is_dir());

    let g = guest_dir.join("rm");
    let h = host_dir.join("rm");
    std::fs::create_dir_all(g.join("a/b")).unwrap();
    std::fs::create_dir_all(h.join("a/b")).unwrap();
    std::fs::write(g.join("a/b/c"), b"x\n").unwrap();
    std::fs::write(h.join("a/b/c"), b"x\n").unwrap();
    pair(
        &["rm", "-r", g.join("a").to_str().expect("utf-8")],
        &["rm", "-r", h.join("a").to_str().expect("utf-8")],
    );
    assert!(!g.join("a").exists());
    assert!(!h.join("a").exists());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn tar_extract_matches_host() {
    // 標準出力は空で、展開したファイルが一致する。別の木へ書く。
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let root = std::env::temp_dir().join(format!("polyisa-tarxf-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let src = root.join("src");
    std::fs::create_dir_all(src.join("tree/sub")).unwrap();
    std::fs::write(src.join("tree/f"), b"ab\ncd\n").unwrap();
    std::fs::write(src.join("tree/sub/g"), b"zz\n").unwrap();
    let arc = root.join("arc.tar");
    let made = Command::new(path)
        .args([
            "tar",
            "-cf",
            arc.to_str().expect("utf-8"),
            "-C",
            src.to_str().expect("utf-8"),
            "tree",
        ])
        .env_clear()
        .status()
        .expect("host tar create");
    assert!(made.success());
    let guest_dir = root.join("guest");
    let host_dir = root.join("host");
    std::fs::create_dir_all(&guest_dir).unwrap();
    std::fs::create_dir_all(&host_dir).unwrap();
    std::fs::copy(&arc, guest_dir.join("arc.tar")).unwrap();
    std::fs::copy(&arc, host_dir.join("arc.tar")).unwrap();
    let guest_args = [
        "tar".to_string(),
        "-xf".to_string(),
        guest_dir.join("arc.tar").to_str().unwrap().to_string(),
        "-C".to_string(),
        guest_dir.to_str().unwrap().to_string(),
    ];
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &guest_args)
        .unwrap_or_else(|e| panic!("tar: {e}"));
    let host = Command::new(path)
        .args([
            "tar",
            "-xf",
            host_dir.join("arc.tar").to_str().unwrap(),
            "-C",
            host_dir.to_str().unwrap(),
        ])
        .env_clear()
        .output()
        .expect("host tar");
    assert_eq!(code, host.status.code().unwrap_or(1) as u64);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
    assert_eq!(
        std::fs::read(guest_dir.join("tree/f")).unwrap(),
        std::fs::read(host_dir.join("tree/f")).unwrap()
    );
    assert_eq!(
        std::fs::read(guest_dir.join("tree/sub/g")).unwrap(),
        b"zz\n"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn cp_recursive_matches_host() {
    // 標準出力は空で、コピーした木が一致する。別の木へ書く。
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let root = std::env::temp_dir().join(format!("polyisa-cpr-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let guest_dir = root.join("guest");
    let host_dir = root.join("host");
    std::fs::create_dir_all(guest_dir.join("tree/sub")).unwrap();
    std::fs::create_dir_all(host_dir.join("tree/sub")).unwrap();
    std::fs::write(guest_dir.join("tree/f"), b"ab\n").unwrap();
    std::fs::write(host_dir.join("tree/f"), b"ab\n").unwrap();
    std::fs::write(guest_dir.join("tree/sub/g"), b"zz\n").unwrap();
    std::fs::write(host_dir.join("tree/sub/g"), b"zz\n").unwrap();
    let guest_args = [
        "cp".to_string(),
        "-r".to_string(),
        guest_dir.join("tree").to_str().unwrap().to_string(),
        guest_dir.join("copy").to_str().unwrap().to_string(),
    ];
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &guest_args)
        .unwrap_or_else(|e| panic!("cp: {e}"));
    let host = Command::new(path)
        .args([
            "cp",
            "-r",
            host_dir.join("tree").to_str().unwrap(),
            host_dir.join("copy").to_str().unwrap(),
        ])
        .env_clear()
        .output()
        .expect("host cp");
    assert_eq!(code, host.status.code().unwrap_or(1) as u64);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
    assert_eq!(
        std::fs::read(guest_dir.join("copy/f")).unwrap(),
        std::fs::read(host_dir.join("copy/f")).unwrap()
    );
    assert_eq!(
        std::fs::read(guest_dir.join("copy/sub/g")).unwrap(),
        b"zz\n"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn cp_archive_link_symlink_match_host() {
    // cp -a はシンボリックリンクを保ち、cp -l はハードリンク、cp -s はリンクを作る。
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let root = std::env::temp_dir().join(format!("polyisa-cpa-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let guest = root.join("guest");
    let host = root.join("host");
    std::fs::create_dir_all(guest.join("tree/sub")).unwrap();
    std::fs::create_dir_all(host.join("tree/sub")).unwrap();
    std::fs::write(guest.join("tree/f"), b"ab\n").unwrap();
    std::fs::write(host.join("tree/f"), b"ab\n").unwrap();
    std::fs::write(guest.join("tree/sub/g"), b"zz\n").unwrap();
    std::fs::write(host.join("tree/sub/g"), b"zz\n").unwrap();
    polyisa_host::symlink("f", guest.join("tree/link").to_str().unwrap()).unwrap();
    polyisa_host::symlink("f", host.join("tree/link").to_str().unwrap()).unwrap();
    let guest_args = [
        "cp".to_string(),
        "-a".to_string(),
        guest.join("tree").to_str().unwrap().to_string(),
        guest.join("copy").to_str().unwrap().to_string(),
    ];
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &guest_args)
        .unwrap_or_else(|e| panic!("cp -a: {e}"));
    let host_out = Command::new(path)
        .args([
            "cp",
            "-a",
            host.join("tree").to_str().unwrap(),
            host.join("copy").to_str().unwrap(),
        ])
        .env_clear()
        .output()
        .expect("host cp -a");
    assert_eq!(code, host_out.status.code().unwrap_or(1) as u64);
    assert_eq!(out.as_slice(), host_out.stdout.as_slice());
    assert_eq!(
        std::fs::read(guest.join("copy/f")).unwrap(),
        std::fs::read(host.join("copy/f")).unwrap()
    );
    assert_eq!(std::fs::read(guest.join("copy/sub/g")).unwrap(), b"zz\n");
    assert_eq!(
        std::fs::read_link(guest.join("copy/link")).unwrap(),
        std::fs::read_link(host.join("copy/link")).unwrap()
    );

    std::fs::write(guest.join("src"), b"ab\n").unwrap();
    std::fs::write(host.join("src"), b"ab\n").unwrap();
    let guest_args = [
        "cp".to_string(),
        "-l".to_string(),
        guest.join("src").to_str().unwrap().to_string(),
        guest.join("hard").to_str().unwrap().to_string(),
    ];
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &guest_args)
        .unwrap_or_else(|e| panic!("cp -l: {e}"));
    let host_out = Command::new(path)
        .args([
            "cp",
            "-l",
            host.join("src").to_str().unwrap(),
            host.join("hard").to_str().unwrap(),
        ])
        .env_clear()
        .output()
        .expect("host cp -l");
    assert_eq!(code, host_out.status.code().unwrap_or(1) as u64);
    assert_eq!(out.as_slice(), host_out.stdout.as_slice());
    std::fs::write(guest.join("hard"), b"zz\n").unwrap();
    assert_eq!(std::fs::read(guest.join("src")).unwrap(), b"zz\n");
    std::fs::write(host.join("hard"), b"zz\n").unwrap();
    assert_eq!(std::fs::read(host.join("src")).unwrap(), b"zz\n");

    std::fs::write(guest.join("src2"), b"ab\n").unwrap();
    std::fs::write(host.join("src2"), b"ab\n").unwrap();
    let guest_args = [
        "cp".to_string(),
        "-s".to_string(),
        guest.join("src2").to_str().unwrap().to_string(),
        guest.join("sym").to_str().unwrap().to_string(),
    ];
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &guest_args)
        .unwrap_or_else(|e| panic!("cp -s: {e}"));
    let host_out = Command::new(path)
        .args([
            "cp",
            "-s",
            host.join("src2").to_str().unwrap(),
            host.join("sym").to_str().unwrap(),
        ])
        .env_clear()
        .output()
        .expect("host cp -s");
    assert_eq!(code, host_out.status.code().unwrap_or(1) as u64);
    assert_eq!(out.as_slice(), host_out.stdout.as_slice());
    // 絶対パスのリンクになるので、それぞれの src2 を指していることだけ見る。
    assert_eq!(
        std::fs::read_link(guest.join("sym")).unwrap(),
        guest.join("src2")
    );
    assert_eq!(
        std::fs::read_link(host.join("sym")).unwrap(),
        host.join("src2")
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn shred_zero_and_unlink_match_host() {
    // -n 0 -z は中身を 0 にし、-u -n 0 は消す。乱数上書きの内容は比べない。
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let root = std::env::temp_dir().join(format!("polyisa-shred-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let guest = root.join("guest");
    let host = root.join("host");
    std::fs::create_dir_all(&guest).unwrap();
    std::fs::create_dir_all(&host).unwrap();
    std::fs::write(guest.join("z"), b"ab\ncd\n").unwrap();
    std::fs::write(host.join("z"), b"ab\ncd\n").unwrap();
    let guest_args = [
        "shred".to_string(),
        "-n".to_string(),
        "0".to_string(),
        "-z".to_string(),
        guest.join("z").to_str().unwrap().to_string(),
    ];
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &guest_args)
        .unwrap_or_else(|e| panic!("shred -z: {e}"));
    let host_out = Command::new(path)
        .args(["shred", "-n", "0", "-z", host.join("z").to_str().unwrap()])
        .env_clear()
        .output()
        .expect("host shred -z");
    assert_eq!(code, host_out.status.code().unwrap_or(1) as u64);
    assert_eq!(out.as_slice(), host_out.stdout.as_slice());
    assert_eq!(std::fs::read(guest.join("z")).unwrap(), vec![0u8; 6]);
    assert_eq!(std::fs::read(host.join("z")).unwrap(), vec![0u8; 6]);

    std::fs::write(guest.join("u"), b"ab\ncd\n").unwrap();
    std::fs::write(host.join("u"), b"ab\ncd\n").unwrap();
    let guest_args = [
        "shred".to_string(),
        "-u".to_string(),
        "-n".to_string(),
        "0".to_string(),
        guest.join("u").to_str().unwrap().to_string(),
    ];
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &guest_args)
        .unwrap_or_else(|e| panic!("shred -u: {e}"));
    let host_out = Command::new(path)
        .args(["shred", "-u", "-n", "0", host.join("u").to_str().unwrap()])
        .env_clear()
        .output()
        .expect("host shred -u");
    assert_eq!(code, host_out.status.code().unwrap_or(1) as u64);
    assert_eq!(out.as_slice(), host_out.stdout.as_slice());
    assert!(!guest.join("u").exists());
    assert!(!host.join("u").exists());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn envdir_printenv_matches_host() {
    // ディレクトリ内の MSG ファイルを環境変数にして printenv する。
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let root = std::env::temp_dir().join(format!("polyisa-envdir-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let guest = root.join("guest");
    let host = root.join("host");
    std::fs::create_dir_all(&guest).unwrap();
    std::fs::create_dir_all(&host).unwrap();
    std::fs::write(guest.join("MSG"), b"hi\n").unwrap();
    std::fs::write(host.join("MSG"), b"hi\n").unwrap();
    let guest_args = [
        "envdir".to_string(),
        guest.to_str().unwrap().to_string(),
        path.to_string(),
        "printenv".to_string(),
        "MSG".to_string(),
    ];
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &guest_args)
        .unwrap_or_else(|e| panic!("envdir: {e}"));
    let host_out = Command::new(path)
        .args(["envdir", host.to_str().unwrap(), path, "printenv", "MSG"])
        .env_clear()
        .output()
        .expect("host envdir");
    assert_eq!(code, host_out.status.code().unwrap_or(1) as u64);
    assert_eq!(out.as_slice(), host_out.stdout.as_slice());
    assert_eq!(out.as_slice(), b"hi\n");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn run_parts_test_lists_match_host() {
    // --test は実行せず名前だけ出す。パスが違うので DIR に置き換えて比べる。
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let root = std::env::temp_dir().join(format!("polyisa-rp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let guest = root.join("guest");
    let host = root.join("host");
    std::fs::create_dir_all(&guest).unwrap();
    std::fs::create_dir_all(&host).unwrap();
    std::fs::write(guest.join("a"), b"#!/bin/true\n").unwrap();
    std::fs::write(host.join("a"), b"#!/bin/true\n").unwrap();
    // crates/ では std::os を使えないので chmod で実行ビットを付ける。
    for p in [guest.join("a"), host.join("a")] {
        Command::new("chmod")
            .args(["755", p.to_str().unwrap()])
            .status()
            .expect("chmod");
    }
    let guest_args = [
        "run-parts".to_string(),
        "--test".to_string(),
        guest.to_str().unwrap().to_string(),
    ];
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &guest_args)
        .unwrap_or_else(|e| panic!("run-parts: {e}"));
    let host_out = Command::new(path)
        .args(["run-parts", "--test", host.to_str().unwrap()])
        .env_clear()
        .output()
        .expect("host run-parts");
    assert_eq!(code, host_out.status.code().unwrap_or(1) as u64);
    let guest_text = String::from_utf8_lossy(&out).replace(guest.to_str().unwrap(), "DIR");
    let host_text =
        String::from_utf8_lossy(&host_out.stdout).replace(host.to_str().unwrap(), "DIR");
    assert_eq!(guest_text, host_text);
    assert_eq!(guest_text, "DIR/a\n");
    let _ = std::fs::remove_dir_all(&root);
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

/// 圧縮しない ZIP。BusyBox の unzip が展開できる最小の形。
fn stored_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in files {
        let crc = crc32(data);
        let local_at = u32::try_from(out.len()).unwrap();
        let size = u32::try_from(data.len()).unwrap();
        let name_len = u16::try_from(name.len()).unwrap();
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);
        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&name_len.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&local_at.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let cd_at = u32::try_from(out.len()).unwrap();
    let cd_len = u32::try_from(central.len()).unwrap();
    let count = u16::try_from(files.len()).unwrap();
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&cd_len.to_le_bytes());
    out.extend_from_slice(&cd_at.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

#[test]
fn unzip_matches_host() {
    // 標準出力は書庫のパスを含む。パスを置き換えてから、展開結果と一緒に比べる。
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let root = std::env::temp_dir().join(format!("polyisa-unzip-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let guest_dir = root.join("guest");
    let host_dir = root.join("host");
    std::fs::create_dir_all(&guest_dir).unwrap();
    std::fs::create_dir_all(&host_dir).unwrap();
    let zip = stored_zip(&[("tree/f", b"ab\ncd\n"), ("tree/sub/g", b"zz\n")]);
    let guest_zip = guest_dir.join("a.zip");
    let host_zip = host_dir.join("a.zip");
    std::fs::write(&guest_zip, &zip).unwrap();
    std::fs::write(&host_zip, &zip).unwrap();
    let guest_args = [
        "unzip".to_string(),
        "-o".to_string(),
        guest_zip.to_str().unwrap().to_string(),
        "-d".to_string(),
        guest_dir.to_str().unwrap().to_string(),
    ];
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &guest_args)
        .unwrap_or_else(|e| panic!("unzip: {e}"));
    let host = Command::new(path)
        .args([
            "unzip",
            "-o",
            host_zip.to_str().unwrap(),
            "-d",
            host_dir.to_str().unwrap(),
        ])
        .env_clear()
        .output()
        .expect("host unzip");
    assert_eq!(code, host.status.code().unwrap_or(1) as u64);
    let guest_msg = String::from_utf8(out)
        .unwrap()
        .replace(guest_zip.to_str().unwrap(), "ARCHIVE");
    let host_msg = String::from_utf8(host.stdout)
        .unwrap()
        .replace(host_zip.to_str().unwrap(), "ARCHIVE");
    assert_eq!(guest_msg, host_msg);
    assert_eq!(
        std::fs::read(guest_dir.join("tree/f")).unwrap(),
        b"ab\ncd\n"
    );
    assert_eq!(std::fs::read(host_dir.join("tree/f")).unwrap(), b"ab\ncd\n");
    assert_eq!(
        std::fs::read(guest_dir.join("tree/sub/g")).unwrap(),
        b"zz\n"
    );
    assert_eq!(std::fs::read(host_dir.join("tree/sub/g")).unwrap(), b"zz\n");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn dos2unix_matches_host() {
    // 標準出力は空で、変換したファイルが一致する。別の木へ書く。
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let root = std::env::temp_dir().join(format!("polyisa-dos2unix-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let guest_dir = root.join("guest");
    let host_dir = root.join("host");
    std::fs::create_dir_all(&guest_dir).unwrap();
    std::fs::create_dir_all(&host_dir).unwrap();
    let guest_crlf = guest_dir.join("crlf");
    let host_crlf = host_dir.join("crlf");
    std::fs::write(&guest_crlf, b"ab\r\ncd\r\n").unwrap();
    std::fs::write(&host_crlf, b"ab\r\ncd\r\n").unwrap();
    let guest_lf = guest_dir.join("lf");
    let host_lf = host_dir.join("lf");
    std::fs::write(&guest_lf, b"ab\ncd\n").unwrap();
    std::fs::write(&host_lf, b"ab\ncd\n").unwrap();
    let guest_args = ["dos2unix", guest_crlf.to_str().expect("utf-8")];
    let argv: Vec<String> = guest_args.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("dos2unix: {e}"));
    let host = Command::new(path)
        .args(["dos2unix", host_crlf.to_str().expect("utf-8")])
        .env_clear()
        .output()
        .expect("host dos2unix");
    assert_eq!(code, host.status.code().unwrap_or(1) as u64);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
    assert_eq!(std::fs::read(&guest_crlf).unwrap(), b"ab\ncd\n");
    assert_eq!(std::fs::read(&host_crlf).unwrap(), b"ab\ncd\n");
    let guest_args = ["unix2dos", guest_lf.to_str().expect("utf-8")];
    let argv: Vec<String> = guest_args.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("unix2dos: {e}"));
    let host = Command::new(path)
        .args(["unix2dos", host_lf.to_str().expect("utf-8")])
        .env_clear()
        .output()
        .expect("host unix2dos");
    assert_eq!(code, host.status.code().unwrap_or(1) as u64);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
    assert_eq!(std::fs::read(&guest_lf).unwrap(), b"ab\r\ncd\r\n");
    assert_eq!(std::fs::read(&host_lf).unwrap(), b"ab\r\ncd\r\n");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn uudecode_matches_host() {
    // 標準出力は空で、復元したファイルが一致する。別の木へ書く。
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let root = std::env::temp_dir().join(format!("polyisa-uudecode-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let guest_dir = root.join("guest");
    let host_dir = root.join("host");
    std::fs::create_dir_all(&guest_dir).unwrap();
    std::fs::create_dir_all(&host_dir).unwrap();
    let src = root.join("src");
    std::fs::write(&src, b"ab\ncd\n").unwrap();
    let encoded = Command::new(path)
        .args(["uuencode", src.to_str().expect("utf-8"), "name"])
        .env_clear()
        .output()
        .expect("host uuencode");
    assert!(encoded.status.success());
    let guest_uu = guest_dir.join("f.uu");
    let host_uu = host_dir.join("f.uu");
    std::fs::write(&guest_uu, &encoded.stdout).unwrap();
    std::fs::write(&host_uu, &encoded.stdout).unwrap();
    let guest_out = guest_dir.join("out");
    let host_out = host_dir.join("out");
    let guest_args = [
        "uudecode",
        "-o",
        guest_out.to_str().expect("utf-8"),
        guest_uu.to_str().expect("utf-8"),
    ];
    let argv: Vec<String> = guest_args.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("uudecode: {e}"));
    let host = Command::new(path)
        .args([
            "uudecode",
            "-o",
            host_out.to_str().expect("utf-8"),
            host_uu.to_str().expect("utf-8"),
        ])
        .env_clear()
        .output()
        .expect("host uudecode");
    assert_eq!(code, host.status.code().unwrap_or(1) as u64);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
    assert_eq!(std::fs::read(&guest_out).unwrap(), b"ab\ncd\n");
    assert_eq!(std::fs::read(&host_out).unwrap(), b"ab\ncd\n");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn patch_matches_host() {
    // 標準出力は適用先のパスを含む。ファイルの中身と終了コードを別の木で比べる。
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let root = std::env::temp_dir().join(format!("polyisa-patch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let guest_dir = root.join("guest");
    let host_dir = root.join("host");
    std::fs::create_dir_all(&guest_dir).unwrap();
    std::fs::create_dir_all(&host_dir).unwrap();
    let diff = root.join("p.diff");
    std::fs::write(&diff, b"--- a\n+++ b\n@@ -1,2 +1,2 @@\n ab\n-cd\n+xx\n").unwrap();
    let guest_f = guest_dir.join("f");
    let host_f = host_dir.join("f");
    std::fs::write(&guest_f, b"ab\ncd\n").unwrap();
    std::fs::write(&host_f, b"ab\ncd\n").unwrap();
    let guest_args = [
        "patch",
        guest_f.to_str().expect("utf-8"),
        diff.to_str().expect("utf-8"),
    ];
    let argv: Vec<String> = guest_args.iter().map(|s| (*s).to_string()).collect();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
        .unwrap_or_else(|e| panic!("patch: {e}"));
    let host = Command::new(path)
        .args([
            "patch",
            host_f.to_str().expect("utf-8"),
            diff.to_str().expect("utf-8"),
        ])
        .env_clear()
        .output()
        .expect("host patch");
    assert_eq!(code, host.status.code().unwrap_or(1) as u64);
    let guest_msg = String::from_utf8(out)
        .unwrap()
        .replace(guest_f.to_str().unwrap(), "FILE");
    let host_msg = String::from_utf8(host.stdout)
        .unwrap()
        .replace(host_f.to_str().unwrap(), "FILE");
    assert_eq!(guest_msg, host_msg);
    assert_eq!(std::fs::read(&guest_f).unwrap(), b"ab\nxx\n");
    assert_eq!(std::fs::read(&host_f).unwrap(), b"ab\nxx\n");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn tr_and_tee_match_host() {
    // 標準入力のバイトを変換し、tee は同じバイトをファイルへも書く。
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let input = b"ab\ncd\n";
    let root = std::env::temp_dir().join(format!("polyisa-tee-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let input_path = root.join("in");
    std::fs::write(&input_path, input).unwrap();
    let argv = ["tr", "a-z", "A-Z"]
        .iter()
        .map(|s| (*s).to_string())
        .collect::<Vec<_>>();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured_in(path, &argv, input)
        .unwrap_or_else(|e| panic!("tr: {e}"));
    let host = Command::new(path)
        .args(["tr", "a-z", "A-Z"])
        .env_clear()
        .stdin(std::fs::File::open(&input_path).unwrap())
        .output()
        .expect("host tr");
    assert_eq!(code, host.status.code().unwrap_or(1) as u64);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
    assert_eq!(out.as_slice(), b"AB\nCD\n");
    let guest_dir = root.join("guest");
    let host_dir = root.join("host");
    std::fs::create_dir_all(&guest_dir).unwrap();
    std::fs::create_dir_all(&host_dir).unwrap();
    let guest_f = guest_dir.join("out");
    let host_f = host_dir.join("out");
    let guest_args = ["tee", guest_f.to_str().expect("utf-8")]
        .iter()
        .map(|s| (*s).to_string())
        .collect::<Vec<_>>();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured_in(path, &guest_args, input)
        .unwrap_or_else(|e| panic!("tee: {e}"));
    let host = Command::new(path)
        .args(["tee", host_f.to_str().expect("utf-8")])
        .env_clear()
        .stdin(std::fs::File::open(&input_path).unwrap())
        .output()
        .expect("host tee");
    assert_eq!(code, host.status.code().unwrap_or(1) as u64);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
    assert_eq!(std::fs::read(&guest_f).unwrap(), b"ab\ncd\n");
    assert_eq!(std::fs::read(&host_f).unwrap(), b"ab\ncd\n");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn split_matches_host() {
    // 標準出力は空で、分割したファイルが一致する。作業ディレクトリを分けて書く。
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let root = std::env::temp_dir().join(format!("polyisa-split-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let guest_dir = root.join("guest");
    let host_dir = root.join("host");
    std::fs::create_dir_all(&guest_dir).unwrap();
    std::fs::create_dir_all(&host_dir).unwrap();
    std::fs::write(guest_dir.join("f"), b"ab\ncd\nef\n").unwrap();
    std::fs::write(host_dir.join("f"), b"ab\ncd\nef\n").unwrap();
    let argv = ["split", "-l", "1", "f"]
        .iter()
        .map(|s| (*s).to_string())
        .collect::<Vec<_>>();
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured_dir(
        path,
        &argv,
        guest_dir.to_str().expect("utf-8"),
    )
    .unwrap_or_else(|e| panic!("split: {e}"));
    let host = Command::new(path)
        .args(["split", "-l", "1", "f"])
        .env_clear()
        .current_dir(&host_dir)
        .output()
        .expect("host split");
    assert_eq!(code, host.status.code().unwrap_or(1) as u64);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
    for name in ["xaa", "xab", "xac"] {
        assert_eq!(
            std::fs::read(guest_dir.join(name)).unwrap(),
            std::fs::read(host_dir.join(name)).unwrap(),
            "{name}"
        );
    }
    assert_eq!(std::fs::read(guest_dir.join("xaa")).unwrap(), b"ab\n");
    assert_eq!(std::fs::read(guest_dir.join("xac")).unwrap(), b"ef\n");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn pipe_progress_matches_host() {
    // 標準入力をそのまま標準出力へ写す。
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let input = b"abcd";
    let argv = ["pipe_progress".to_string()];
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured_in(path, &argv, input)
        .unwrap_or_else(|e| panic!("pipe_progress: {e}"));
    let input_path = std::env::temp_dir().join(format!("polyisa-pipe-{}", std::process::id()));
    std::fs::write(&input_path, input).unwrap();
    let host = Command::new(path)
        .args(["pipe_progress"])
        .env_clear()
        .stdin(std::fs::File::open(&input_path).unwrap())
        .output()
        .expect("host pipe_progress");
    let _ = std::fs::remove_file(&input_path);
    assert_eq!(code, host.status.code().unwrap_or(1) as u64);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
    assert_eq!(out.as_slice(), b"abcd");
}

#[test]
fn mkfifo_matches_host() {
    // 標準出力は空で、作った名前付きパイプの種別と許可が一致する。
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let root = std::env::temp_dir().join(format!("polyisa-fifo-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let guest_dir = root.join("guest");
    let host_dir = root.join("host");
    std::fs::create_dir_all(&guest_dir).unwrap();
    std::fs::create_dir_all(&host_dir).unwrap();
    let pairs = [
        (
            vec![
                "mkfifo".to_string(),
                guest_dir.join("p").to_str().unwrap().to_string(),
            ],
            vec![
                "mkfifo".to_string(),
                host_dir.join("p").to_str().unwrap().to_string(),
            ],
            guest_dir.join("p"),
            host_dir.join("p"),
        ),
        (
            vec![
                "mknod".to_string(),
                guest_dir.join("n").to_str().unwrap().to_string(),
                "p".to_string(),
            ],
            vec![
                "mknod".to_string(),
                host_dir.join("n").to_str().unwrap().to_string(),
                "p".to_string(),
            ],
            guest_dir.join("n"),
            host_dir.join("n"),
        ),
    ];
    for (guest_args, host_args, guest_f, host_f) in pairs {
        let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &guest_args)
            .unwrap_or_else(|e| panic!("{}: {e}", guest_args[0]));
        let host = Command::new(path)
            .args(&host_args)
            .env_clear()
            .output()
            .expect("host fifo");
        assert_eq!(code, host.status.code().unwrap_or(1) as u64);
        assert_eq!(out.as_slice(), host.stdout.as_slice());
        let guest_kind = std::process::Command::new("stat")
            .args(["-c", "%F %a", guest_f.to_str().unwrap()])
            .output()
            .unwrap();
        let host_kind = std::process::Command::new("stat")
            .args(["-c", "%F %a", host_f.to_str().unwrap()])
            .output()
            .unwrap();
        assert_eq!(guest_kind.stdout, host_kind.stdout);
        assert!(guest_kind.stdout.starts_with(b"fifo "));
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn fallocate_matches_host() {
    // 標準出力は空で、確保した長さが一致する。
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let root = std::env::temp_dir().join(format!("polyisa-fallocate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let guest_dir = root.join("guest");
    let host_dir = root.join("host");
    std::fs::create_dir_all(&guest_dir).unwrap();
    std::fs::create_dir_all(&host_dir).unwrap();
    let guest_f = guest_dir.join("f");
    let host_f = host_dir.join("f");
    let guest_args = [
        "fallocate".to_string(),
        "-l".to_string(),
        "8".to_string(),
        guest_f.to_str().unwrap().to_string(),
    ];
    let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &guest_args)
        .unwrap_or_else(|e| panic!("fallocate: {e}"));
    let host = Command::new(path)
        .args(["fallocate", "-l", "8", host_f.to_str().unwrap()])
        .env_clear()
        .output()
        .expect("host fallocate");
    assert_eq!(code, host.status.code().unwrap_or(1) as u64);
    assert_eq!(out.as_slice(), host.stdout.as_slice());
    assert_eq!(
        std::fs::metadata(&guest_f).unwrap().len(),
        std::fs::metadata(&host_f).unwrap().len()
    );
    assert_eq!(std::fs::metadata(&guest_f).unwrap().len(), 8);
    let _ = std::fs::remove_dir_all(&root);
}
