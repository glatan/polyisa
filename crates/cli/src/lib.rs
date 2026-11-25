// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `polyisa` コマンド。実行の機構そのものは各クレートが持つ。

#![forbid(unsafe_code)]

#[cfg(feature = "guest-aarch64")]
pub mod run_aarch64;
#[cfg(feature = "guest-alpha")]
pub mod run_alpha;
#[cfg(feature = "guest-arm")]
pub mod run_arm;
#[cfg(feature = "guest-hexagon")]
pub mod run_hexagon;
#[cfg(feature = "guest-ia64")]
pub mod run_ia64;
#[cfg(feature = "guest-loongarch")]
pub mod run_loongarch;
#[cfg(feature = "guest-m68k")]
pub mod run_m68k;
#[cfg(feature = "guest-mips")]
pub mod run_mips;
#[cfg(feature = "guest-openrisc")]
pub mod run_openrisc;
#[cfg(feature = "guest-parisc")]
pub mod run_parisc;
#[cfg(feature = "guest-pdp11")]
pub mod run_pdp11;
#[cfg(feature = "guest-power")]
pub mod run_power;

#[cfg(feature = "guest-riscv")]
pub mod gdb_riscv;
#[cfg(feature = "guest-riscv")]
pub mod run_riscv;
#[cfg(feature = "guest-s390")]
pub mod run_s390;
#[cfg(feature = "guest-sparc")]
pub mod run_sparc;
#[cfg(feature = "guest-superh")]
pub mod run_superh;
#[cfg(feature = "guest-vax")]
pub mod run_vax;
#[cfg(feature = "guest-wasm")]
pub mod run_wasm;
#[cfg(feature = "guest-x86")]
pub mod run_x86;

/// ELF 入口がパーソナリティに要求する初期化面。`TrapHandler` と
/// 合わせて `run_elf_*_impl` が使う。実装しないパーソナリティは
/// 既定（何もしない）のままでよい。
pub trait ElfSys: polyisa_engine::run::TrapHandler {
    /// `--root` のゲストルート（パス解決の閉じ込め）。
    fn set_guest_root(&mut self, _root: &str) {}
    /// 実行ファイルのゲスト側パス。
    fn set_exe_path(&mut self, _path: &str) {}
    /// データアクセスのエンディアン（ELF の EI_DATA）。
    fn set_endian(&mut self, _endian: polyisa_mem::Endian) {}
}

#[cfg(feature = "guest-aarch64")]
impl ElfSys for polyisa_os_linux::aarch64::sys::Linux {
    fn set_guest_root(&mut self, root: &str) {
        polyisa_os_linux::aarch64::sys::Linux::set_guest_root(self, root);
    }
    fn set_exe_path(&mut self, path: &str) {
        self.exe_path = path.to_string();
    }
    fn set_endian(&mut self, endian: polyisa_mem::Endian) {
        polyisa_os_linux::aarch64::sys::Linux::set_endian(self, endian);
    }
}

#[cfg(feature = "guest-arm")]
impl ElfSys for polyisa_os_linux::arm::sys::Linux {
    fn set_exe_path(&mut self, path: &str) {
        self.exe_path = path.to_string();
    }
}

#[cfg(feature = "guest-aarch64")]
impl ElfSys for polyisa_os_semihost::SemiA64 {
    fn set_guest_root(&mut self, root: &str) {
        self.0.set_root(root);
    }
    fn set_endian(&mut self, endian: polyisa_mem::Endian) {
        self.0.set_endian(endian);
    }
}

#[cfg(feature = "guest-arm")]
impl ElfSys for polyisa_os_semihost::SemiA32 {
    fn set_guest_root(&mut self, root: &str) {
        self.0.set_root(root);
    }
    fn set_endian(&mut self, endian: polyisa_mem::Endian) {
        self.0.set_endian(endian);
    }
}

/// ELF を選んで実行する。`EI_CLASS` と `e_machine` で RISC-V、x86、MIPS、
/// AArch64 を振り分ける。
/// 番号表の出典は各 `run_elf_*` 側にある。RV32 を含むそれ以外の組み合わせは
/// 未対応として拒否する（従来の `run_elf` も RV32 を受け付けない）。
pub fn run_path(path: &str, argv: &[String]) -> Result<u64, String> {
    run_path_with(path, argv, None)
}

/// `--cpu` の指定。文法は cpu-models.md の「実行時の選択」:
/// `<ISA ファミリ>:<CPU モデル>[,+<機能>][,-<機能>][,<パラメータ>=<値>]`。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CpuSpec {
    pub family: String,
    pub model: String,
    pub add: Vec<String>,
    pub remove: Vec<String>,
    /// `パラメータ=値`。`param=` の上書きは未接続（GAP-0027）。
    pub params: Vec<(String, String)>,
}

/// `--cpu` の値を解析する。`+機能`、`-機能`、`パラメータ=値` を列に分ける。
pub fn parse_cpu_spec(s: &str) -> Result<CpuSpec, String> {
    let Some((family, rest)) = s.split_once(':') else {
        return Err(format!("--cpu は <ファミリ>:<モデル> の形: {s}"));
    };
    let mut it = rest.split(',');
    let model = it.next().unwrap_or_default().to_string();
    let mut spec = CpuSpec {
        family: family.to_string(),
        model,
        add: Vec::new(),
        remove: Vec::new(),
        params: Vec::new(),
    };
    for item in it {
        if let Some(f) = item.strip_prefix('+') {
            spec.add.push(f.to_string());
        } else if let Some(f) = item.strip_prefix('-') {
            spec.remove.push(f.to_string());
        } else if let Some((k, v)) = item.split_once('=') {
            spec.params.push((k.to_string(), v.to_string()));
        } else {
            return Err(format!(
                "--cpu の項は +機能、-機能、パラメータ=値 の形: {item}"
            ));
        }
    }
    Ok(spec)
}

/// モデル名と機能の足し引きを、そのファミリの生成表で `CpuSel` に解決する。
#[cfg(any(
    feature = "guest-aarch64",
    feature = "guest-alpha",
    feature = "guest-arm",
    feature = "guest-hexagon",
    feature = "guest-ia64",
    feature = "guest-m68k",
    feature = "guest-mips",
    feature = "guest-parisc",
    feature = "guest-power",
    feature = "guest-riscv",
    feature = "guest-s390",
    feature = "guest-sparc",
    feature = "guest-loongarch",
    feature = "guest-superh",
    feature = "guest-x86"
))]
fn resolve_sel(
    family: &str,
    models: &[polyisa_isadl::select::ModelRow],
    features: &[polyisa_isadl::select::FeatureRow],
    feat_bits: &[(&str, u128)],
    spec: &CpuSpec,
) -> Result<polyisa_isadl::select::CpuSel, String> {
    if !spec.params.is_empty() {
        let (k, _) = &spec.params[0];
        return Err(format!(
            "挙動パラメータの `param=` 上書きは未接続（GAP-0027）: {k}"
        ));
    }
    let add: Vec<&str> = spec.add.iter().map(String::as_str).collect();
    let remove: Vec<&str> = spec.remove.iter().map(String::as_str).collect();
    polyisa_isadl::select::resolve(models, features, feat_bits, &spec.model, &add, &remove)
        .map_err(|e| format!("{family}: {e}"))
}

#[cfg(feature = "guest-x86")]
fn run_x86_32_elf(path: &str, argv: &[String], spec: Option<&CpuSpec>) -> Result<u64, String> {
    // `--cpu` 省略時も既定モデルを解決し、CPUID の識別情報を導出できる
    // ようにする。
    let default = CpuSpec {
        family: "x86".to_string(),
        model: String::new(),
        add: Vec::new(),
        remove: Vec::new(),
        params: Vec::new(),
    };
    let sel = resolve_sel(
        "x86",
        polyisa_guest_x86::MODEL_DEFS,
        polyisa_guest_x86::FEATURE_DEFS,
        polyisa_guest_x86::FEAT_BITS,
        spec.unwrap_or(&default),
    )?;
    run_x86::run_elf_x86_32_sel(path, argv, Some(&sel))
}

#[cfg(not(feature = "guest-x86"))]
fn run_x86_32_elf(_path: &str, _argv: &[String], _spec: Option<&CpuSpec>) -> Result<u64, String> {
    Err("この polyisa は x86 ゲストなしでビルドされた".to_string())
}

/// ELFCLASS32 + EM_X86_64 の x32（ILP32）ELF を実行する。
#[cfg(feature = "guest-x86")]
fn run_x86_x32_elf(path: &str, argv: &[String], spec: Option<&CpuSpec>) -> Result<u64, String> {
    let default = CpuSpec {
        family: "x86".to_string(),
        model: String::new(),
        add: Vec::new(),
        remove: Vec::new(),
        params: Vec::new(),
    };
    let sel = resolve_sel(
        "x86",
        polyisa_guest_x86::MODEL_DEFS,
        polyisa_guest_x86::FEATURE_DEFS,
        polyisa_guest_x86::FEAT_BITS,
        spec.unwrap_or(&default),
    )?;
    run_x86::run_elf_x86_x32_sel(path, argv, Some(&sel))
}

#[cfg(not(feature = "guest-x86"))]
fn run_x86_x32_elf(_path: &str, _argv: &[String], _spec: Option<&CpuSpec>) -> Result<u64, String> {
    Err("この polyisa は x86 ゲストなしでビルドされた".to_string())
}

#[cfg(feature = "guest-x86")]
fn run_x86_64_elf(path: &str, argv: &[String], spec: Option<&CpuSpec>) -> Result<u64, String> {
    let default = CpuSpec {
        family: "x86".to_string(),
        model: String::new(),
        add: Vec::new(),
        remove: Vec::new(),
        params: Vec::new(),
    };
    let sel = resolve_sel(
        "x86",
        polyisa_guest_x86::MODEL_DEFS,
        polyisa_guest_x86::FEATURE_DEFS,
        polyisa_guest_x86::FEAT_BITS,
        spec.unwrap_or(&default),
    )?;
    run_x86::run_elf_x86_64_sel(path, argv, Some(&sel))
}

#[cfg(not(feature = "guest-x86"))]
fn run_x86_64_elf(_path: &str, _argv: &[String], _spec: Option<&CpuSpec>) -> Result<u64, String> {
    Err("この polyisa は x86 ゲストなしでビルドされた".to_string())
}

#[cfg(feature = "guest-mips")]
fn run_mips_elf(path: &str, argv: &[String], spec: Option<&CpuSpec>) -> Result<u64, String> {
    let sel = spec
        .map(|s| {
            resolve_sel(
                "mips",
                polyisa_guest_mips::MODEL_DEFS,
                polyisa_guest_mips::FEATURE_DEFS,
                polyisa_guest_mips::FEAT_BITS,
                s,
            )
        })
        .transpose()?;
    run_mips::run_elf_mips_sel(path, argv, sel.as_ref())
}

#[cfg(not(feature = "guest-mips"))]
fn run_mips_elf(_path: &str, _argv: &[String], _spec: Option<&CpuSpec>) -> Result<u64, String> {
    Err("この polyisa は mips ゲストなしでビルドされた".to_string())
}

#[cfg(feature = "guest-m68k")]
fn run_m68k_elf(path: &str, argv: &[String], spec: Option<&CpuSpec>) -> Result<u64, String> {
    let sel = spec
        .map(|s| {
            resolve_sel(
                "m68k",
                polyisa_guest_m68k::MODEL_DEFS,
                polyisa_guest_m68k::FEATURE_DEFS,
                polyisa_guest_m68k::FEAT_BITS,
                s,
            )
        })
        .transpose()?;
    let _ = sel;
    run_m68k::run_elf_m68k(path, argv)
}

#[cfg(not(feature = "guest-m68k"))]
fn run_m68k_elf(_path: &str, _argv: &[String], _spec: Option<&CpuSpec>) -> Result<u64, String> {
    Err("この polyisa は m68k ゲストなしでビルドされた".to_string())
}

#[cfg(feature = "guest-sparc")]
fn run_sparc_elf(path: &str, argv: &[String], spec: Option<&CpuSpec>) -> Result<u64, String> {
    let sel = spec
        .map(|s| {
            resolve_sel(
                "sparc",
                polyisa_guest_sparc::MODEL_DEFS,
                polyisa_guest_sparc::FEATURE_DEFS,
                polyisa_guest_sparc::FEAT_BITS,
                s,
            )
        })
        .transpose()?;
    let _ = sel;
    run_sparc::run_elf_sparc(path, argv)
}

#[cfg(not(feature = "guest-sparc"))]
fn run_sparc_elf(_path: &str, _argv: &[String], _spec: Option<&CpuSpec>) -> Result<u64, String> {
    Err("この polyisa は sparc ゲストなしでビルドされた".to_string())
}

#[cfg(feature = "guest-ia64")]
fn run_ia64_elf(path: &str, argv: &[String], spec: Option<&CpuSpec>) -> Result<u64, String> {
    let sel = spec
        .map(|s| {
            resolve_sel(
                "ia64",
                polyisa_guest_ia64::MODEL_DEFS,
                polyisa_guest_ia64::FEATURE_DEFS,
                polyisa_guest_ia64::FEAT_BITS,
                s,
            )
        })
        .transpose()?;
    run_ia64::run_elf_ia64_sel(path, argv, sel.as_ref())
}

#[cfg(not(feature = "guest-ia64"))]
fn run_ia64_elf(_path: &str, _argv: &[String], _spec: Option<&CpuSpec>) -> Result<u64, String> {
    Err("この polyisa は ia64 ゲストなしでビルドされた".to_string())
}

#[cfg(feature = "guest-alpha")]
fn run_alpha_elf(path: &str, argv: &[String], spec: Option<&CpuSpec>) -> Result<u64, String> {
    let sel = spec
        .map(|s| {
            resolve_sel(
                "alpha",
                polyisa_guest_alpha::MODEL_DEFS,
                polyisa_guest_alpha::FEATURE_DEFS,
                polyisa_guest_alpha::FEAT_BITS,
                s,
            )
        })
        .transpose()?;
    run_alpha::run_elf_alpha_sys(
        path,
        argv,
        sel.as_ref(),
        &mut polyisa_os_linux::alpha::sys::Linux::new(),
    )
}

#[cfg(not(feature = "guest-alpha"))]
fn run_alpha_elf(_path: &str, _argv: &[String], _spec: Option<&CpuSpec>) -> Result<u64, String> {
    Err("この polyisa は alpha ゲストなしでビルドされた".to_string())
}

#[cfg(feature = "guest-parisc")]
fn run_parisc_elf(path: &str, argv: &[String], spec: Option<&CpuSpec>) -> Result<u64, String> {
    let sel = spec
        .map(|s| {
            resolve_sel(
                "parisc",
                polyisa_guest_parisc::MODEL_DEFS,
                polyisa_guest_parisc::FEATURE_DEFS,
                polyisa_guest_parisc::FEAT_BITS,
                s,
            )
        })
        .transpose()?;
    run_parisc::run_elf_parisc_sel(path, argv, sel.as_ref())
}

#[cfg(not(feature = "guest-parisc"))]
fn run_parisc_elf(_path: &str, _argv: &[String], _spec: Option<&CpuSpec>) -> Result<u64, String> {
    Err("この polyisa は parisc ゲストなしでビルドされた".to_string())
}

#[cfg(feature = "guest-superh")]
fn run_superh_elf(path: &str, argv: &[String], spec: Option<&CpuSpec>) -> Result<u64, String> {
    let sel = spec
        .map(|s| {
            resolve_sel(
                "superh",
                polyisa_guest_superh::MODEL_DEFS,
                polyisa_guest_superh::FEATURE_DEFS,
                polyisa_guest_superh::FEAT_BITS,
                s,
            )
        })
        .transpose()?;
    run_superh::run_elf_superh_sel(path, argv, sel.as_ref())
}

#[cfg(not(feature = "guest-superh"))]
fn run_superh_elf(_path: &str, _argv: &[String], _spec: Option<&CpuSpec>) -> Result<u64, String> {
    Err("この polyisa は superh ゲストなしでビルドされた".to_string())
}

#[cfg(feature = "guest-loongarch")]
fn run_loongarch_elf(
    path: &str,
    argv: &[String],
    spec: Option<&CpuSpec>,
    root: Option<&str>,
) -> Result<u64, String> {
    let sel = spec
        .map(|s| {
            resolve_sel(
                "loongarch",
                polyisa_guest_loongarch::MODEL_DEFS,
                polyisa_guest_loongarch::FEATURE_DEFS,
                polyisa_guest_loongarch::FEAT_BITS,
                s,
            )
        })
        .transpose()?;
    run_loongarch::run_elf_loongarch_root(path, argv, sel.as_ref(), root)
}

#[cfg(not(feature = "guest-loongarch"))]
fn run_loongarch_elf(
    _path: &str,
    _argv: &[String],
    _spec: Option<&CpuSpec>,
    _root: Option<&str>,
) -> Result<u64, String> {
    Err("この polyisa は loongarch ゲストなしでビルドされた".to_string())
}

#[cfg(feature = "guest-openrisc")]
fn run_openrisc_elf(
    path: &str,
    argv: &[String],
    spec: Option<&CpuSpec>,
    root: Option<&str>,
) -> Result<u64, String> {
    let sel = spec
        .map(|s| {
            resolve_sel(
                "openrisc",
                polyisa_guest_openrisc::MODEL_DEFS,
                polyisa_guest_openrisc::FEATURE_DEFS,
                polyisa_guest_openrisc::FEAT_BITS,
                s,
            )
        })
        .transpose()?;
    run_openrisc::run_elf_openrisc_root(path, argv, sel.as_ref(), root)
}

#[cfg(not(feature = "guest-openrisc"))]
fn run_openrisc_elf(
    _path: &str,
    _argv: &[String],
    _spec: Option<&CpuSpec>,
    _root: Option<&str>,
) -> Result<u64, String> {
    Err("この polyisa は openrisc ゲストなしでビルドされた".to_string())
}

#[cfg(feature = "guest-hexagon")]
fn run_hexagon_elf(
    path: &str,
    argv: &[String],
    spec: Option<&CpuSpec>,
    root: Option<&str>,
) -> Result<u64, String> {
    let sel = spec
        .map(|s| {
            resolve_sel(
                "hexagon",
                polyisa_guest_hexagon::MODEL_DEFS,
                polyisa_guest_hexagon::FEATURE_DEFS,
                polyisa_guest_hexagon::FEAT_BITS,
                s,
            )
        })
        .transpose()?;
    run_hexagon::run_elf_hexagon_root(path, argv, sel.as_ref(), root)
}

#[cfg(not(feature = "guest-hexagon"))]
fn run_hexagon_elf(
    _path: &str,
    _argv: &[String],
    _spec: Option<&CpuSpec>,
    _root: Option<&str>,
) -> Result<u64, String> {
    Err("この polyisa は hexagon ゲストなしでビルドされた".to_string())
}

#[cfg(feature = "guest-arm")]
fn run_arm_elf(
    path: &str,
    argv: &[String],
    spec: Option<&CpuSpec>,
    root: Option<&str>,
    semi: bool,
) -> Result<u64, String> {
    let sel = spec
        .map(|s| {
            resolve_sel(
                "arm",
                polyisa_guest_arm::MODEL_DEFS,
                polyisa_guest_arm::FEATURE_DEFS,
                polyisa_guest_arm::FEAT_BITS,
                s,
            )
        })
        .transpose()?;
    if semi {
        let mut semi = polyisa_os_semihost::SemiA32::new(root.unwrap_or(""));
        semi.set_cmdline(&cmdline(path, argv));
        return run_arm::run_elf_arm_semi(path, argv, sel.as_ref(), &mut semi);
    }
    run_arm::run_elf_arm_sel(path, argv, sel.as_ref())
}

#[cfg(not(feature = "guest-arm"))]
fn run_arm_elf(
    _path: &str,
    _argv: &[String],
    _spec: Option<&CpuSpec>,
    _root: Option<&str>,
    _semi: bool,
) -> Result<u64, String> {
    Err("この polyisa は arm ゲストなしでビルドされた".to_string())
}

#[cfg(feature = "guest-aarch64")]
fn run_aarch64_elf(
    path: &str,
    argv: &[String],
    spec: Option<&CpuSpec>,
    root: Option<&str>,
    semi: bool,
) -> Result<u64, String> {
    let sel = spec
        .map(|s| {
            resolve_sel(
                "aarch64",
                polyisa_guest_aarch64::MODEL_DEFS,
                polyisa_guest_aarch64::FEATURE_DEFS,
                polyisa_guest_aarch64::FEAT_BITS,
                s,
            )
        })
        .transpose()?;
    if semi {
        let mut semi = polyisa_os_semihost::SemiA64::new(root.unwrap_or(""));
        semi.set_cmdline(&cmdline(path, argv));
        return run_aarch64::run_elf_aarch64_semi(path, argv, sel.as_ref(), &mut semi, root);
    }
    run_aarch64::run_elf_aarch64_root(path, argv, sel.as_ref(), root)
}

#[cfg(not(feature = "guest-aarch64"))]
fn run_aarch64_elf(
    _path: &str,
    _argv: &[String],
    _spec: Option<&CpuSpec>,
    _root: Option<&str>,
    _semi: bool,
) -> Result<u64, String> {
    Err("この polyisa は aarch64 ゲストなしでビルドされた".to_string())
}

#[cfg(feature = "guest-power")]
fn run_power_elf(
    path: &str,
    argv: &[String],
    spec: Option<&CpuSpec>,
    root: Option<&str>,
) -> Result<u64, String> {
    let sel = spec
        .map(|s| {
            resolve_sel(
                "power",
                polyisa_guest_power::MODEL_DEFS,
                polyisa_guest_power::FEATURE_DEFS,
                polyisa_guest_power::FEAT_BITS,
                s,
            )
        })
        .transpose()?;
    run_power::run_elf_power_root(path, argv, sel.as_ref(), root)
}

#[cfg(not(feature = "guest-power"))]
fn run_power_elf(
    _path: &str,
    _argv: &[String],
    _spec: Option<&CpuSpec>,
    _root: Option<&str>,
) -> Result<u64, String> {
    Err("この polyisa は power ゲストなしでビルドされた".to_string())
}

#[cfg(feature = "guest-s390")]
fn run_s390_elf(
    path: &str,
    argv: &[String],
    spec: Option<&CpuSpec>,
    root: Option<&str>,
) -> Result<u64, String> {
    let sel = spec
        .map(|s| {
            resolve_sel(
                "s390",
                polyisa_guest_s390::MODEL_DEFS,
                polyisa_guest_s390::FEATURE_DEFS,
                polyisa_guest_s390::FEAT_BITS,
                s,
            )
        })
        .transpose()?;
    run_s390::run_elf_s390_root(path, argv, sel.as_ref(), root)
}

#[cfg(not(feature = "guest-s390"))]
fn run_s390_elf(
    _path: &str,
    _argv: &[String],
    _spec: Option<&CpuSpec>,
    _root: Option<&str>,
) -> Result<u64, String> {
    Err("この polyisa は s390 ゲストなしでビルドされた".to_string())
}

#[cfg(feature = "guest-riscv")]
fn run_riscv_elf(
    path: &str,
    argv: &[String],
    spec: Option<&CpuSpec>,
    root: Option<&str>,
    semi: bool,
) -> Result<u64, String> {
    let sel = spec
        .map(|s| {
            resolve_sel(
                "riscv",
                polyisa_guest_riscv::MODEL_DEFS,
                polyisa_guest_riscv::FEATURE_DEFS,
                polyisa_guest_riscv::FEAT_BITS,
                s,
            )
        })
        .transpose()?;
    if semi {
        let mut semi = run_riscv::SemiRv::new(root.unwrap_or(""), false);
        semi.semi.set_cmdline(&cmdline(path, argv));
        return run_riscv::run_elf_handler(path, argv, sel.as_ref(), &mut semi);
    }
    run_riscv::run_elf_sel(path, argv, sel.as_ref())
}

#[cfg(not(feature = "guest-riscv"))]
fn run_riscv_elf(
    _path: &str,
    _argv: &[String],
    _spec: Option<&CpuSpec>,
    _root: Option<&str>,
    _semi: bool,
) -> Result<u64, String> {
    Err("この polyisa は riscv ゲストなしでビルドされた".to_string())
}

/// `run -g <port>` の rv64 経路。linux パーソナリティのみ。
#[cfg(feature = "guest-riscv")]
fn run_riscv_gdb(
    path: &str,
    argv: &[String],
    spec: Option<&CpuSpec>,
    port: u16,
) -> Result<u64, String> {
    // `-g` は rv64 ELF のみを受け付ける（他 ISA は GD6 の残件）。
    // EM_RISCV=243。`load_elf_env` でも確かめるが、`-g` 向けに早く弾く。
    const EM_RISCV: u16 = 243;
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let Ok(ehdr) = polyisa_loader::elf::parse_ehdr(&bytes) else {
        return Err("-g は現状 rv64 の ELF のみ対応".to_string());
    };
    if !ehdr.little || ehdr.machine != EM_RISCV {
        return Err("-g は現状 rv64 の ELF のみ対応".to_string());
    }
    match spec {
        Some(s) if s.family != "riscv" => {
            return Err(format!(
                "--cpu のファミリ {} は -g（riscv）と合わない",
                s.family
            ));
        }
        _ => {}
    }
    let sel = spec
        .map(|s| {
            resolve_sel(
                "riscv",
                polyisa_guest_riscv::MODEL_DEFS,
                polyisa_guest_riscv::FEATURE_DEFS,
                polyisa_guest_riscv::FEAT_BITS,
                s,
            )
        })
        .transpose()?;
    gdb_riscv::run_elf_gdb(path, argv, sel.as_ref(), port)
}

#[cfg(not(feature = "guest-riscv"))]
fn run_riscv_gdb(
    _path: &str,
    _argv: &[String],
    _spec: Option<&CpuSpec>,
    _port: u16,
) -> Result<u64, String> {
    Err("この polyisa は riscv ゲストなしでビルドされた".to_string())
}

#[cfg(feature = "guest-wasm")]
fn run_wasm_mod(
    bytes: &[u8],
    path: &str,
    argv: &[String],
    root: Option<&str>,
) -> Result<u64, String> {
    run_wasm::run_wasm_prog(bytes, path, argv, root)
}

#[cfg(not(feature = "guest-wasm"))]
fn run_wasm_mod(
    _bytes: &[u8],
    _path: &str,
    _argv: &[String],
    _root: Option<&str>,
) -> Result<u64, String> {
    Err("この polyisa は wasm ゲストなしでビルドされた".to_string())
}

/// PDP-11 の a.out を Unix V7 パーソナリティで実行する。
/// V7 の実機が MMU（分離 I/D 可）を持つ 11/70 級なので、
/// `--cpu` のモデル省略時は `pdp11_70`。
#[cfg(feature = "guest-pdp11")]
fn run_pdp11_aout(
    bytes: &[u8],
    path: &str,
    argv: &[String],
    spec: &CpuSpec,
    root: Option<&str>,
) -> Result<u64, String> {
    let model = if spec.model.is_empty() {
        "pdp11_70"
    } else {
        spec.model.as_str()
    };
    let mut sys = polyisa_os_v7::pdp11::sys::V7::new(root.unwrap_or(""));
    feed_stdin(&mut sys.io.stdin);
    run_pdp11::run_aout_v7_sys(bytes, path, argv, model, &mut sys)
}

/// VAX の a.out を 4.3BSD パーソナリティで実行する。
/// 4.3BSD の実機がフル VAX なので、`--cpu` のモデル省略時は
/// `vax`。
#[cfg(feature = "guest-vax")]
fn run_vax_aout(
    bytes: &[u8],
    path: &str,
    argv: &[String],
    spec: &CpuSpec,
    root: Option<&str>,
) -> Result<u64, String> {
    let model = if spec.model.is_empty() {
        "vax"
    } else {
        spec.model.as_str()
    };
    let mut sys = polyisa_os_bsd::vax::sys::Bsd::new(root.unwrap_or(""));
    feed_stdin(&mut sys.io.stdin);
    run_vax::run_aout_bsd_sys(bytes, path, argv, model, &mut sys)
}

/// ホスト stdin がパイプなら全部読んでゲストの stdin 列へ
/// 渡す（対話 tty では読まない —— ブロックするので）。
fn feed_stdin(dst: &mut Vec<u8>) {
    use std::io::IsTerminal;
    use std::io::Read;
    if std::io::stdin().is_terminal() {
        return;
    }
    let mut buf = Vec::new();
    if std::io::stdin().read_to_end(&mut buf).is_ok() {
        *dst = buf;
    }
}

/// semihosting の SYS_GET_CMDLINE に渡す `[実行ファイル, 引数...]`。
fn cmdline(path: &str, argv: &[String]) -> Vec<String> {
    let mut v = vec![path.to_string()];
    v.extend(argv.iter().cloned());
    v
}

/// `run_path` に `--cpu` の指定を加える。`cpu` は `parse_cpu_spec` の
/// 入力と同じ文字列。ファミリが ELF の `e_machine` と合わなければ拒否する。
pub fn run_path_with(path: &str, argv: &[String], cpu: Option<&str>) -> Result<u64, String> {
    run_path_opts(path, argv, cpu, None, None)
}

/// `run_path_with` に `--root` のゲストルートを添える。
/// 現状は aarch64 のみが `root` を解釈する（PT_INTERP とパス解決）。
/// `root` 指定時は `path` をゲストの名前空間（chroot と同じ規則）で解決する。
pub fn run_path_opts(
    path: &str,
    argv: &[String],
    cpu: Option<&str>,
    root: Option<&str>,
    os: Option<&str>,
) -> Result<u64, String> {
    use polyisa_loader::elf::{CLASS_32, CLASS_64, MAGIC};
    let spec = cpu.map(parse_cpu_spec).transpose()?;
    // `--os` は既定の linux と semihost のみ。semihost は
    // aarch64・arm・riscv の ELF でだけ意味を持つ。
    match os {
        None | Some("linux") | Some("semihost") => {}
        Some(o) => return Err(format!("--os {o} は未対応（linux・semihost）")),
    }
    let semi = os == Some("semihost");
    // wasm バイナリ（`\0asm` + version 1）は WASI preview1 で実行する。
    // `--root` はプリオープン `/` として渡るだけで、モジュールファイル
    // 自体はホストのパスから読む（wasmtime の `--dir` と同じ規則）。
    if let Ok(mut f) = std::fs::File::open(path) {
        use std::io::Read;
        let mut head = [0u8; 8];
        if f.read_exact(&mut head).is_ok()
            && head[0..4] == *b"\0asm"
            && head[4..8] == 1u32.to_le_bytes()
        {
            if let Some(s) = &spec
                && s.family != "wasm"
            {
                return Err(format!("--cpu のファミリ {} は wasm と合わない", s.family));
            }
            if os.is_some() {
                return Err("--os は ELF のみ対応".to_string());
            }
            let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
            return run_wasm_mod(&bytes, path, argv, root);
        }
    }
    // e_machine の嗅探も root 内のパス解決を通る（run_aarch64 側と同じ規則）。
    let host_path = match root {
        Some(root) => polyisa_os_linux::guest_path::resolve_guest_path_links(root, "/", path)
            .ok_or_else(|| format!("{path}: ゲストルートの外を指す"))?,
        None => path.to_string(),
    };
    let bytes = std::fs::read(&host_path).map_err(|e| format!("read {path}: {e}"))?;
    if bytes.len() < 6 || bytes[0..4] != MAGIC {
        // a.out の magic は機種を同定しない —— `--cpu` の
        // ファミリで振り分ける。
        if os.is_some() {
            return Err("--os は ELF のみ対応".to_string());
        }
        if polyisa_loader::probe_kind(&bytes) == polyisa_loader::FileKind::Aout {
            match spec.as_ref().map(|s| s.family.as_str()) {
                #[cfg(feature = "guest-pdp11")]
                Some("pdp11") => {
                    return run_pdp11_aout(&bytes, path, argv, spec.as_ref().unwrap(), root);
                }
                #[cfg(feature = "guest-vax")]
                Some("vax") => {
                    return run_vax_aout(&bytes, path, argv, spec.as_ref().unwrap(), root);
                }
                Some(f) => {
                    return Err(format!("--cpu {f} では a.out を実行できない"));
                }
                None => {
                    return Err("a.out の実行には --cpu（pdp11 など）が要る".to_string());
                }
            }
        }
        return Err(format!("{path} は ELF でも a.out でもない"));
    }
    let check = |want: &str| match &spec {
        Some(s) if s.family != want => Err(format!(
            "--cpu のファミリ {} は ELF の {want} と合わない",
            s.family
        )),
        _ => Ok(()),
    };
    match bytes[4] {
        CLASS_32 => {
            let ehdr =
                polyisa_loader::elf::parse_ehdr32(&bytes).map_err(|e| format!("ehdr: {e:?}"))?;
            if semi && ehdr.machine != 40 {
                return Err("--os semihost は aarch64・arm・riscv のみ対応".to_string());
            }
            if root.is_some() && !matches!(ehdr.machine, 92 | 164) {
                return Err(
                    "--root は現状 aarch64・ppc64・s390x・loongarch・openrisc・hexagon のみ対応"
                        .to_string(),
                );
            }
            // EM_386=3。Ref: SRC-LINUX (7.3).
            if ehdr.machine == 3 {
                check("x86")?;
                run_x86_32_elf(path, argv, spec.as_ref())
            } else if ehdr.machine == 62 {
                // ELFCLASS32 + EM_X86_64 は x32（ILP32）。Ref: SRC-LINUX (7.3)。
                check("x86")?;
                run_x86_x32_elf(path, argv, spec.as_ref())
            } else if ehdr.machine == 40 {
                // EM_ARM（AArch32・ARM 状態）。Ref: AAELF32 §4.1。
                check("arm")?;
                run_arm_elf(path, argv, spec.as_ref(), root, semi)
            } else if ehdr.machine == 4 {
                // EM_68K=4。Ref: SRC-LINUX (include/uapi/linux/elf-em.h)。
                check("m68k")?;
                run_m68k_elf(path, argv, spec.as_ref())
            } else if ehdr.machine == 8 {
                // EM_MIPS。Ref: SRC-LINUX (7.3)。アーキテクチャとエンディアンは ELF ヘッダから取る。
                check("mips")?;
                run_mips_elf(path, argv, spec.as_ref())
            } else if matches!(ehdr.machine, 2 | 18) {
                // EM_SPARC=2 / EM_SPARC32PLUS=18。Ref: SRC-LINUX (include/uapi/linux/elf-em.h)。
                check("sparc")?;
                run_sparc_elf(path, argv, spec.as_ref())
            } else if ehdr.machine == 15 {
                // EM_PARISC=15。Ref: SRC-LINUX (include/uapi/linux/elf-em.h)。
                check("parisc")?;
                run_parisc_elf(path, argv, spec.as_ref())
            } else if ehdr.machine == 42 {
                // EM_SH=42。Ref: SRC-LINUX (include/uapi/linux/elf-em.h)。
                check("superh")?;
                run_superh_elf(path, argv, spec.as_ref())
            } else if ehdr.machine == 92 {
                // EM_OPENRISC=92。Ref: SRC-LINUX (include/uapi/linux/elf-em.h)。
                check("openrisc")?;
                run_openrisc_elf(path, argv, spec.as_ref(), root)
            } else if ehdr.machine == 164 {
                // EM_HEXAGON=164（EM_QDSP6）。
                // Ref: SRC-LINUX-HEXAGON-UAPI — kernel-asm/elf.h.
                check("hexagon")?;
                run_hexagon_elf(path, argv, spec.as_ref(), root)
            } else if ehdr.machine == 258 {
                // EM_LOONGARCH=258・ELFCLASS32 は LA32。
                // Ref: SRC-LINUX (include/uapi/linux/elf-em.h).
                check("loongarch")?;
                run_loongarch_elf(path, argv, spec.as_ref(), None)
            } else {
                Err(format!("未対応の e_machine: {}", ehdr.machine))
            }
        }
        CLASS_64 => {
            let ehdr =
                polyisa_loader::elf::parse_ehdr(&bytes).map_err(|e| format!("ehdr: {e:?}"))?;
            if semi && !matches!(ehdr.machine, 183 | 243) {
                return Err("--os semihost は aarch64・arm・riscv のみ対応".to_string());
            }
            if root.is_some() && !matches!(ehdr.machine, 183 | 21 | 22 | 258) {
                return Err(
                    "--root は現状 aarch64・ppc64・s390x・loongarch・openrisc のみ対応".to_string(),
                );
            }
            // EM_RISCV=243。Ref: SPEC-RISCV-PSABI (v1.0).
            if ehdr.machine == 243 {
                check("riscv")?;
                run_riscv_elf(path, argv, spec.as_ref(), root, semi)
            } else if ehdr.machine == 62 {
                // EM_X86_64。Ref: SRC-LINUX (7.3)。
                check("x86")?;
                run_x86_64_elf(path, argv, spec.as_ref())
            } else if ehdr.machine == 8 {
                // EM_MIPS の 64 ビット（n64 ABI）。Ref: SRC-LINUX (7.3)。
                check("mips")?;
                run_mips_elf(path, argv, spec.as_ref())
            } else if ehdr.machine == 183 {
                // EM_AARCH64。Ref: SPEC-AARCH64-ELF（AAELF64）§4.2。
                check("aarch64")?;
                run_aarch64_elf(path, argv, spec.as_ref(), root, semi)
            } else if ehdr.machine == 21 {
                // EM_PPC64。Ref: SPEC-POWER-ABI (ELFv2 r1.5)。
                check("power")?;
                run_power_elf(path, argv, spec.as_ref(), root)
            } else if ehdr.machine == 22 {
                // EM_S390（s390x）。Ref: SPEC-S390-ABI。
                check("s390")?;
                run_s390_elf(path, argv, spec.as_ref(), root)
            } else if ehdr.machine == 43 {
                // EM_SPARCV9=43（sparc64）。Ref: SRC-LINUX (include/uapi/linux/elf-em.h)。
                check("sparc")?;
                run_sparc_elf(path, argv, spec.as_ref())
            } else if ehdr.machine == 0x9026 {
                // EM_ALPHA=0x9026。Ref: SRC-LINUX (include/uapi/linux/elf-em.h)。
                check("alpha")?;
                run_alpha_elf(path, argv, spec.as_ref())
            } else if ehdr.machine == 50 {
                // EM_IA_64=50。Ref: SRC-LINUX-66
                // (kernel-asm/elf.h elf_check_arch)。
                check("ia64")?;
                run_ia64_elf(path, argv, spec.as_ref())
            } else if ehdr.machine == 258 {
                // EM_LOONGARCH=258（LA64）。Ref: SRC-LINUX
                // (include/uapi/linux/elf-em.h).
                check("loongarch")?;
                run_loongarch_elf(path, argv, spec.as_ref(), root)
            } else {
                Err(format!("未対応の e_machine: {}", ehdr.machine))
            }
        }
        _ => Err(format!("{path} は未知の ELF クラスである")),
    }
}

/// `run -g <port>`：GDB リモートシリアルプロトコルのサーバを開き、
/// GDB の接続を待ってからゲストを始める（observability.md「GDB の接続」）。
/// 現状は linux パーソナリティの rv64 ELF のみを受け付ける。
pub fn run_path_gdb(
    path: &str,
    argv: &[String],
    cpu: Option<&str>,
    root: Option<&str>,
    os: Option<&str>,
    port: u16,
) -> Result<u64, String> {
    match os {
        None | Some("linux") => {}
        Some(o) => {
            return Err(format!(
                "-g と併用できる --os は linux のみ（{o} は未対応）"
            ));
        }
    }
    if root.is_some() {
        return Err("-g と --root の併用は未対応".to_string());
    }
    let spec = cpu.map(parse_cpu_spec).transpose()?;
    run_riscv_gdb(path, argv, spec.as_ref(), port)
}

/// `run`、`cpus`、`disasm` のいずれか。引数の解析は後の段階で足す。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Command {
    Run,
    Cpus,
    Disasm,
    Help,
}

/// 最初の引き数から命令を決める。外部クレートを使わず手で解析する。
#[must_use]
pub fn parse_command(args: &[String]) -> Command {
    match args.first().map(String::as_str) {
        Some("run") => Command::Run,
        Some("cpus") => Command::Cpus,
        Some("disasm") => Command::Disasm,
        _ => Command::Help,
    }
}

/// 16進の1語を逆アセンブルする。長さは下位2ビットで判定する
///（`0b11` 以外は16ビット）。RISC-V のみ。`guest-riscv` 機能で有効になる。
#[cfg(feature = "guest-riscv")]
#[must_use]
pub fn disassemble_riscv(word: u128) -> Option<String> {
    let len = if word & 0b11 == 0b11 { 32 } else { 16 };
    polyisa_guest_riscv::disasm_word(word, len)
}

/// `disasm` の引数（16進文字列）を語に直す。`0x` 接頭辞の有無は問わない。
#[must_use]
pub fn parse_hex_word(s: &str) -> Option<u128> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if s.is_empty() || s.len() > 32 {
        return None;
    }
    let mut v = 0u128;
    for c in s.chars() {
        let d = c.to_digit(16)? as u128;
        v = v * 16 + d;
    }
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch() {
        let run = ["run".to_string()];
        assert_eq!(parse_command(&run), Command::Run);
        let empty: [String; 0] = [];
        assert_eq!(parse_command(&empty), Command::Help);
    }

    #[cfg(feature = "guest-riscv")]
    #[test]
    fn disasm_add_and_c_addi() {
        // add x1,x2,x3 と c.addi x1,1（SPEC-RISCV-UNPRIV の符号化）。
        assert_eq!(
            disassemble_riscv(0x0031_00b3).as_deref(),
            Some("add x1, x2, x3")
        );
        // c.addi は形式 R を共有し、{imm} は宣言オペランドがないので残る。
        assert_eq!(
            disassemble_riscv(0x0085).as_deref(),
            Some("c.addi x1, {imm}")
        );
        assert_eq!(disassemble_riscv(0xffff_ffff), None);
    }

    #[test]
    fn cpu_spec_parses() {
        let s = parse_cpu_spec("riscv:rv64gc,+zba,-d,foo=1").unwrap();
        assert_eq!(s.family, "riscv");
        assert_eq!(s.model, "rv64gc");
        assert_eq!(s.add, ["zba"]);
        assert_eq!(s.remove, ["d"]);
        assert_eq!(s.params, [("foo".to_string(), "1".to_string())]);
        assert!(parse_cpu_spec("nocolon").is_err());
        assert!(parse_cpu_spec("x86:generic32,bad").is_err());
    }

    #[test]
    fn hex_parses() {
        assert_eq!(parse_hex_word("0x0085"), Some(0x85));
        assert_eq!(parse_hex_word("003100B3"), Some(0x0031_00b3));
        assert_eq!(parse_hex_word(""), None);
        assert_eq!(parse_hex_word("0xzz"), None);
    }
}
