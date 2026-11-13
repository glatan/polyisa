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

#[test]
fn run_path_executes_x86_64_hello() {
    let path = write_temp("hello64", &hello_x86_64());
    let r = polyisa_cli::run_path(&path.to_string_lossy(), &[]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(r, Ok(7));
}
