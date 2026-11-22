// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 重いテストバイナリが必要とする外部のものの表。
//!
//! `devtool test:plan` がテストの実行前に調べ、揃わないバイナリを
//! nextest の対象から外す（未実行として報告する）。重いテストを
//! 足したら、外部のものを必要とする限りここにも足す。

use std::path::Path;

/// テストバイナリが必要とする外部のもの。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Req {
    /// コマンド。名前のほか `/usr/sbin`、`/usr/bin` も探す。
    Tool(&'static str),
    /// ワークスペース相対のパス（`.testdata/...`）。
    Data(&'static str),
}

/// テストバイナリ名（`tests/<名前>.rs`）と必要なものの対応。
#[derive(Clone, Copy, Debug)]
pub struct TestBinary {
    pub binary: &'static str,
    pub needs: &'static [Req],
}

/// `heavy_` テストバイナリの要件一覧。
/// 手で組み立てたデータだけで動くバイナリは書かない。
pub const TEST_REQUIREMENTS: &[TestBinary] = &[
    TestBinary {
        binary: "heavy_abi_alpha",
        needs: &[Req::Data(".testdata/uapi-alpha")],
    },
    TestBinary {
        binary: "heavy_abi_aarch64",
        needs: &[Req::Tool("clang")],
    },
    TestBinary {
        binary: "heavy_abi_arm",
        needs: &[Req::Data(".testdata/uapi-arm")],
    },
    TestBinary {
        binary: "heavy_abi_m68k",
        needs: &[Req::Data(".testdata/uapi-m68k")],
    },
    TestBinary {
        binary: "heavy_abi_parisc",
        needs: &[Req::Data(".testdata/uapi-hppa")],
    },
    TestBinary {
        binary: "heavy_abi_power",
        needs: &[Req::Data(".testdata/uapi-powerpc")],
    },
    TestBinary {
        binary: "heavy_abi_s390",
        needs: &[Req::Data(".testdata/uapi-s390")],
    },
    TestBinary {
        binary: "heavy_abi_sparc",
        needs: &[Req::Data(".testdata/uapi-sparc")],
    },
    TestBinary {
        binary: "heavy_abi_uapi",
        needs: &[Req::Tool("clang")],
    },
    TestBinary {
        binary: "heavy_conformance_dectest",
        needs: &[Req::Data(".testdata/dectest")],
    },
    TestBinary {
        binary: "heavy_conformance_riscv_tests",
        needs: &[
            Req::Data(".testdata/riscv-tests"),
            Req::Data(".testdata/riscv-arch-test"),
        ],
    },
    TestBinary {
        binary: "heavy_conformance_rv64ui",
        needs: &[Req::Data(".testdata/riscv-tests"), Req::Tool("clang")],
    },
    TestBinary {
        binary: "heavy_conformance_sst8088",
        needs: &[Req::Data(".testdata/sst-8088")],
    },
    TestBinary {
        binary: "heavy_timing_8088",
        needs: &[Req::Data(".testdata/sst-8088")],
    },
    TestBinary {
        binary: "heavy_conformance_sst68000",
        needs: &[Req::Data(".testdata/sst-68000")],
    },
    TestBinary {
        binary: "heavy_timing_68000",
        needs: &[Req::Data(".testdata/sst-68000")],
    },
    TestBinary {
        binary: "heavy_conformance_sst80286",
        needs: &[Req::Data(".testdata/sst-80286")],
    },
    TestBinary {
        binary: "heavy_conformance_testfloat",
        needs: &[Req::Data(".testdata/testfloat")],
    },
    TestBinary {
        binary: "heavy_jit_diff",
        needs: &[Req::Tool("clang")],
    },
    TestBinary {
        binary: "heavy_oracle_llvm",
        needs: &[Req::Tool("llvm-mc")],
    },
    TestBinary {
        binary: "heavy_diff_sde",
        needs: &[Req::Tool("sde64")],
    },
    TestBinary {
        binary: "heavy_oracle_xed",
        needs: &[Req::Tool("xed")],
    },
    TestBinary {
        binary: "heavy_oracle_power",
        needs: &[Req::Tool("llvm-mc")],
    },
    TestBinary {
        binary: "heavy_oracle_s390",
        needs: &[Req::Tool("llvm-mc")],
    },
    TestBinary {
        binary: "heavy_program_busybox",
        needs: &[Req::Data(".testdata/bin-distro/busybox")],
    },
    TestBinary {
        binary: "heavy_program_busybox_i386",
        needs: &[Req::Data(".testdata/bin-distro-i386/busybox")],
    },
    TestBinary {
        binary: "heavy_program_i386_applet_probe",
        needs: &[Req::Data(".testdata/bin-distro-i386/busybox")],
    },
    TestBinary {
        binary: "heavy_program_aarch64",
        needs: &[
            Req::Tool("clang"),
            Req::Data(".testdata/bin-distro-aarch64"),
        ],
    },
    TestBinary {
        binary: "heavy_program_arm",
        needs: &[
            Req::Tool("clang"),
            Req::Data(".testdata/bin-distro-armv5l/busybox"),
            Req::Data(".testdata/bin-distro-armv7l/busybox"),
        ],
    },
    TestBinary {
        binary: "heavy_program_m68k",
        needs: &[Req::Data(".testdata/bin-distro-m68k/busybox")],
    },
    TestBinary {
        binary: "heavy_program_mips",
        needs: &[Req::Tool("clang")],
    },
    TestBinary {
        binary: "heavy_program_power",
        needs: &[
            Req::Tool("clang"),
            Req::Data(".testdata/bin-distro-powerpc64/busybox"),
            Req::Data(".testdata/bin-distro-powerpc64le"),
        ],
    },
    TestBinary {
        binary: "heavy_program_s390",
        needs: &[Req::Tool("clang"), Req::Data(".testdata/bin-distro-s390x")],
    },
    TestBinary {
        binary: "heavy_program_sparc",
        needs: &[
            Req::Tool("clang"),
            Req::Data(".testdata/bin-distro-sparc/busybox"),
            Req::Data(".testdata/bin-distro-sparc64/busybox"),
        ],
    },
    TestBinary {
        binary: "heavy_program_alpha",
        needs: &[Req::Data(".testdata/bin-distro-alpha/busybox")],
    },
    TestBinary {
        binary: "heavy_program_ia64",
        needs: &[Req::Data(".testdata/bin-distro-ia64")],
    },
    TestBinary {
        binary: "heavy_abi_ia64",
        needs: &[Req::Data(".testdata/uapi-ia64")],
    },
    TestBinary {
        binary: "heavy_abi_superh",
        needs: &[Req::Data(".testdata/uapi-sh")],
    },
    TestBinary {
        binary: "heavy_program_superh",
        needs: &[
            Req::Data(".testdata/bin-distro-sh4/busybox"),
            Req::Data(".testdata/bin-distro-sh4eb/busybox"),
        ],
    },
    TestBinary {
        binary: "heavy_program_parisc",
        needs: &[Req::Data(".testdata/bin-distro-hppa/busybox")],
    },
    TestBinary {
        binary: "heavy_abi_openrisc",
        needs: &[Req::Data(".testdata/uapi-openrisc")],
    },
    TestBinary {
        binary: "heavy_program_openrisc",
        needs: &[Req::Data(".testdata/bin-distro-or1k")],
    },
    TestBinary {
        binary: "heavy_abi_loongarch",
        needs: &[Req::Data(".testdata/uapi-loongarch")],
    },
    TestBinary {
        binary: "heavy_oracle_loongarch",
        needs: &[
            Req::Tool("llvm-objdump"),
            Req::Data(".testdata/bin-distro-loongarch"),
        ],
    },
    TestBinary {
        binary: "heavy_program_loongarch",
        needs: &[Req::Data(".testdata/bin-distro-loongarch")],
    },
    TestBinary {
        binary: "heavy_program_x32",
        needs: &[Req::Tool("x86_64-linux-gnux32-gcc-14")],
    },
    TestBinary {
        binary: "heavy_program_x86ext",
        needs: &[Req::Tool("clang")],
    },
    TestBinary {
        binary: "heavy_conformance_wasm_spec",
        needs: &[Req::Data(".testdata/wasm-spec")],
    },
    TestBinary {
        binary: "heavy_diff_wasmtime",
        needs: &[Req::Tool("wasmtime")],
    },
    // wasi-sdk/clang が無い環境ではテスト内の手組モジュールで検証
    // するため、外部要件は持たない。
    TestBinary {
        binary: "heavy_program_wasi",
        needs: &[],
    },
];

/// コマンドが使えるかを `--version` で調べる。
fn tool_available(name: &str) -> bool {
    // sde64 は /opt/sde/sde64 に展開される（/opt/sde64 ではない）。
    let mut cands = vec![
        name.to_string(),
        format!("/usr/sbin/{name}"),
        format!("/usr/bin/{name}"),
        format!("/opt/{name}/bin/{name}"),
    ];
    if name == "sde64" {
        cands.push("/opt/sde/sde64".to_string());
    }
    cands.iter().any(|c| {
        std::process::Command::new(c)
            .arg("--version")
            .output()
            .is_ok()
    })
}

/// 要件が `root`（ワークスペース）で揃うかを返す。
#[must_use]
pub fn req_available(root: &Path, req: Req) -> bool {
    match req {
        Req::Tool(name) => tool_available(name),
        Req::Data(path) => root.join(path).exists(),
    }
}

/// 要件が揃わないバイナリと理由（バイナリごとに最初の不足）を返す。
#[must_use]
pub fn unavailable(root: &Path) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    for tb in TEST_REQUIREMENTS {
        for req in tb.needs {
            if !req_available(root, *req) {
                let why = match req {
                    Req::Tool(name) => format!("コマンド {name} がない"),
                    Req::Data(path) => format!("{path} がない"),
                };
                out.push((tb.binary, why));
                break;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requirements_cover_heavy_binaries() {
        // 表に載る名前は実在する tests/heavy_*.rs と一致するはずだが、
        // クレートをまたぐ探索はここでは行わず、表の形だけを見る。
        for tb in TEST_REQUIREMENTS {
            assert!(tb.binary.starts_with("heavy_"), "{}", tb.binary);
        }
    }

    #[test]
    fn data_paths_are_workspace_relative() {
        for tb in TEST_REQUIREMENTS {
            for req in tb.needs {
                if let Req::Data(p) = req {
                    assert!(p.starts_with(".testdata/"), "{p}");
                }
            }
        }
    }
}
