// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `run_path` の振り分け試験。一時ファイルに置いた ELF を実行する。

use std::io::Write as _;

fn write_temp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("polyisa-{name}-{}", std::process::id()));
    let mut f = std::fs::File::create(&p).unwrap();
    f.write_all(bytes).unwrap();
    p
}

fn hello_x86_32() -> Vec<u8> {
    let code: &[u8] = &[
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1
        0x50, // push eax
        0x5B, // pop ebx
        0xB8, 0x27, 0x00, 0x01, 0x00, // mov eax,0x10027
        0x50, // push eax
        0x59, // pop ecx
        0xB8, 0x0D, 0x00, 0x00, 0x00, // mov eax,13
        0x50, // push eax
        0x5A, // pop edx
        0xB8, 0x04, 0x00, 0x00, 0x00, // mov eax,4 (write)
        0xCD, 0x80, // int 0x80
        0x31, 0xC0, // xor eax,eax
        0x50, // push eax
        0x5B, // pop ebx
        0xB8, 0xFC, 0x00, 0x00, 0x00, // mov eax,252 (exit_group)
        0xCD, 0x80, // int 0x80
    ];
    let msg = b"Hello, poly!\n";
    assert_eq!(code.len(), 0x27);
    let mut f = Vec::new();
    f.extend_from_slice(&[0x7f, b'E', b'L', b'F', 1, 1, 1, 0]);
    f.extend_from_slice(&[0u8; 8]);
    f.extend_from_slice(&2u16.to_le_bytes());
    f.extend_from_slice(&3u16.to_le_bytes());
    f.extend_from_slice(&1u32.to_le_bytes());
    f.extend_from_slice(&0x10000u32.to_le_bytes());
    f.extend_from_slice(&52u32.to_le_bytes());
    f.extend_from_slice(&0u32.to_le_bytes());
    f.extend_from_slice(&0u32.to_le_bytes());
    f.extend_from_slice(&52u16.to_le_bytes());
    f.extend_from_slice(&32u16.to_le_bytes());
    f.extend_from_slice(&1u16.to_le_bytes());
    f.extend_from_slice(&0u16.to_le_bytes());
    f.extend_from_slice(&0u16.to_le_bytes());
    f.extend_from_slice(&0u16.to_le_bytes());
    let seg_len = (code.len() + msg.len()) as u32;
    f.extend_from_slice(&1u32.to_le_bytes());
    f.extend_from_slice(&84u32.to_le_bytes());
    f.extend_from_slice(&0x10000u32.to_le_bytes());
    f.extend_from_slice(&0x10000u32.to_le_bytes());
    f.extend_from_slice(&seg_len.to_le_bytes());
    f.extend_from_slice(&seg_len.to_le_bytes());
    f.extend_from_slice(&5u32.to_le_bytes());
    f.extend_from_slice(&0x1000u32.to_le_bytes());
    f.extend_from_slice(code);
    f.extend_from_slice(msg);
    f
}

#[cfg(feature = "guest-x86")]
#[test]
fn run_path_executes_x86_32_hello() {
    let path = write_temp("hello386", &hello_x86_32());
    let r = polyisa_cli::run_path(&path.to_string_lossy(), &[]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(r, Ok(0));
}

#[test]
fn run_path_rejects_non_elf() {
    let path = write_temp("notelf", b"not an elf");
    let r = polyisa_cli::run_path(&path.to_string_lossy(), &[]);
    let _ = std::fs::remove_file(&path);
    assert!(r.is_err());
}

#[test]
fn run_path_rejects_unknown_machine() {
    // ELF32 だが EM_386 ではない (EM_ARM=40)。
    let mut img = hello_x86_32();
    img[18] = 40;
    img[19] = 0;
    let path = write_temp("badmachine", &img);
    let r = polyisa_cli::run_path(&path.to_string_lossy(), &[]);
    let _ = std::fs::remove_file(&path);
    assert!(r.is_err());
}

#[cfg(feature = "guest-x86")]
fn hello_x86_64() -> Vec<u8> {
    // REX.W 最小形だけの静的 x86-64 バイナリ。write(1, msg, 13) して exit(7)。
    let code: &[u8] = &[
        0x48, 0x8D, 0x35, 0x27, 0x00, 0x00, 0x00, // lea rsi,[rip+msg]
        0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00, // mov rdi,1
        0x48, 0xC7, 0xC2, 0x0D, 0x00, 0x00, 0x00, // mov rdx,13
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, // mov rax,1 (write)
        0x0F, 0x05, // syscall
        0x48, 0xC7, 0xC7, 0x07, 0x00, 0x00, 0x00, // mov rdi,7
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60 (exit)
        0x0F, 0x05, // syscall
    ];
    let msg = b"Hello, poly!\n";
    assert_eq!(code.len(), 0x2E);
    // msg はコード直後。lea の disp32 = msg - next_rip。
    assert_eq!(0x27, code.len() as u8 - 7);
    let mut f = Vec::new();
    f.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
    f.extend_from_slice(&[0u8; 8]);
    f.extend_from_slice(&2u16.to_le_bytes());
    f.extend_from_slice(&62u16.to_le_bytes());
    f.extend_from_slice(&1u32.to_le_bytes());
    f.extend_from_slice(&0x400000u64.to_le_bytes());
    f.extend_from_slice(&64u64.to_le_bytes());
    f.extend_from_slice(&0u64.to_le_bytes());
    f.extend_from_slice(&0u32.to_le_bytes());
    f.extend_from_slice(&64u16.to_le_bytes());
    f.extend_from_slice(&56u16.to_le_bytes());
    f.extend_from_slice(&1u16.to_le_bytes());
    f.extend_from_slice(&0u16.to_le_bytes());
    f.extend_from_slice(&0u16.to_le_bytes());
    f.extend_from_slice(&0u16.to_le_bytes());
    let seg_len = (code.len() + msg.len()) as u64;
    f.extend_from_slice(&1u32.to_le_bytes());
    f.extend_from_slice(&5u32.to_le_bytes());
    f.extend_from_slice(&120u64.to_le_bytes());
    f.extend_from_slice(&0x400000u64.to_le_bytes());
    f.extend_from_slice(&0x400000u64.to_le_bytes());
    f.extend_from_slice(&seg_len.to_le_bytes());
    f.extend_from_slice(&seg_len.to_le_bytes());
    f.extend_from_slice(&0x1000u64.to_le_bytes());
    f.extend_from_slice(code);
    f.extend_from_slice(msg);
    f
}

#[cfg(feature = "guest-x86")]
#[test]
fn run_path_executes_x86_64_hello() {
    let path = write_temp("hello64", &hello_x86_64());
    let r = polyisa_cli::run_path(&path.to_string_lossy(), &[]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(r, Ok(7));
}

#[cfg(feature = "guest-aarch64")]
fn hello_aarch64() -> Vec<u8> {
    // 手組みの AArch64 命令列。write(1, msg, 3) して exit_group(7)。
    // 出典: SRC-LINUX (7.3) の asm-generic 番号（write=64、exit_group=94）。
    let code: &[u8] = &[
        0x08, 0x08, 0x80, 0xd2, // movz x8, #64 (write)
        0x20, 0x00, 0x80, 0xd2, // movz x0, #1
        0xc1, 0x00, 0x00, 0x10, // adr x1, #24 (msg)
        0x62, 0x00, 0x80, 0xd2, // movz x2, #3
        0x01, 0x00, 0x00, 0xd4, // svc #0
        0xc8, 0x0b, 0x80, 0xd2, // movz x8, #94 (exit_group)
        0xe0, 0x00, 0x80, 0xd2, // movz x0, #7
        0x01, 0x00, 0x00, 0xd4, // svc #0
    ];
    let msg = b"hi\n";
    assert_eq!(code.len(), 32);
    let mut f = Vec::new();
    f.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
    f.extend_from_slice(&[0u8; 8]);
    f.extend_from_slice(&2u16.to_le_bytes());
    f.extend_from_slice(&183u16.to_le_bytes()); // EM_AARCH64
    f.extend_from_slice(&1u32.to_le_bytes());
    f.extend_from_slice(&0x400000u64.to_le_bytes());
    f.extend_from_slice(&64u64.to_le_bytes());
    f.extend_from_slice(&0u64.to_le_bytes());
    f.extend_from_slice(&0u32.to_le_bytes());
    f.extend_from_slice(&64u16.to_le_bytes());
    f.extend_from_slice(&56u16.to_le_bytes());
    f.extend_from_slice(&1u16.to_le_bytes());
    f.extend_from_slice(&0u16.to_le_bytes());
    f.extend_from_slice(&0u16.to_le_bytes());
    f.extend_from_slice(&0u16.to_le_bytes());
    let seg_len = (code.len() + msg.len()) as u64;
    f.extend_from_slice(&1u32.to_le_bytes());
    f.extend_from_slice(&5u32.to_le_bytes());
    f.extend_from_slice(&120u64.to_le_bytes());
    f.extend_from_slice(&0x400000u64.to_le_bytes());
    f.extend_from_slice(&0x400000u64.to_le_bytes());
    f.extend_from_slice(&seg_len.to_le_bytes());
    f.extend_from_slice(&seg_len.to_le_bytes());
    f.extend_from_slice(&0x1000u64.to_le_bytes());
    f.extend_from_slice(code);
    f.extend_from_slice(msg);
    f
}

#[cfg(feature = "guest-aarch64")]
#[test]
fn run_path_executes_aarch64_hello() {
    let path = write_temp("hello_aarch64", &hello_aarch64());
    let r = polyisa_cli::run_path(&path.to_string_lossy(), &[]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(r, Ok(7));
}

#[cfg(feature = "guest-aarch64")]
fn be_aarch64(code: &[u8], data: &[u8]) -> Vec<u8> {
    // ビッグエンディアンの AArch64 ELF。EI_DATA=2 で全ての多バイト
    // フィールドを BE にする。命令列そのものは AArch64 の規約で
    // 常にリトルエンディアン。
    let mut f = Vec::new();
    f.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 2, 1, 0]);
    f.extend_from_slice(&[0u8; 8]);
    f.extend_from_slice(&2u16.to_be_bytes());
    f.extend_from_slice(&183u16.to_be_bytes()); // EM_AARCH64
    f.extend_from_slice(&1u32.to_be_bytes());
    f.extend_from_slice(&0x400000u64.to_be_bytes());
    f.extend_from_slice(&64u64.to_be_bytes());
    f.extend_from_slice(&0u64.to_be_bytes());
    f.extend_from_slice(&0u32.to_be_bytes());
    f.extend_from_slice(&64u16.to_be_bytes());
    f.extend_from_slice(&56u16.to_be_bytes());
    f.extend_from_slice(&1u16.to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes());
    let seg_len = (code.len() + data.len()) as u64;
    f.extend_from_slice(&1u32.to_be_bytes());
    f.extend_from_slice(&7u32.to_be_bytes()); // RWX
    f.extend_from_slice(&120u64.to_be_bytes());
    f.extend_from_slice(&0x400000u64.to_be_bytes());
    f.extend_from_slice(&0x400000u64.to_be_bytes());
    f.extend_from_slice(&seg_len.to_be_bytes());
    f.extend_from_slice(&seg_len.to_be_bytes());
    f.extend_from_slice(&0x1000u64.to_be_bytes());
    f.extend_from_slice(code);
    f.extend_from_slice(data);
    f
}

#[cfg(feature = "guest-aarch64")]
#[test]
fn run_path_executes_aarch64_be_data_access() {
    // BE のデータ読み出し: ldr x0, [x1] が 0x07 を返し exit(7) になる。
    // LE として読むと 0x0700_0000_0000_0000 になり終了コードは 0。
    let code: &[u8] = &[
        0x81, 0x00, 0x00, 0x10, // adr x1, #16
        0x20, 0x00, 0x40, 0xf9, // ldr x0, [x1]
        0xc8, 0x0b, 0x80, 0xd2, // movz x8, #94 (exit_group)
        0x01, 0x00, 0x00, 0xd4, // svc #0
    ];
    let data: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 7]; // BE の u64 = 7
    let path = write_temp("be_aarch64", &be_aarch64(code, data));
    let r = polyisa_cli::run_path(&path.to_string_lossy(), &[]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(r, Ok(7));
}

#[cfg(feature = "guest-aarch64")]
#[test]
fn run_path_executes_aarch64_be_initial_stack() {
    // 初期スタックも BE で書かれる: ldr x0, [sp] が argc=1 を読み exit(1)。
    let code: &[u8] = &[
        0xe0, 0x03, 0x40, 0xf9, // ldr x0, [sp]
        0xc8, 0x0b, 0x80, 0xd2, // movz x8, #94 (exit_group)
        0x01, 0x00, 0x00, 0xd4, // svc #0
    ];
    let path = write_temp("be_aarch64_stack", &be_aarch64(code, &[]));
    let r = polyisa_cli::run_path(&path.to_string_lossy(), &[]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(r, Ok(1));
}
