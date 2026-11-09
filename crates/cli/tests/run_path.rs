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

fn hello_i386() -> Vec<u8> {
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
fn run_path_executes_i386_hello() {
    let path = write_temp("hello386", &hello_i386());
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
    let mut img = hello_i386();
    img[18] = 40;
    img[19] = 0;
    let path = write_temp("badmachine", &img);
    let r = polyisa_cli::run_path(&path.to_string_lossy(), &[]);
    let _ = std::fs::remove_file(&path);
    assert!(r.is_err());
}
