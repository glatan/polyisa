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
        binary: "heavy_abi_aarch64",
        needs: &[Req::Tool("clang")],
    },
    TestBinary {
        binary: "heavy_abi_arm",
        needs: &[Req::Data(".testdata/uapi-arm")],
    },
    TestBinary {
        binary: "heavy_abi_power",
        needs: &[Req::Data(".testdata/uapi-powerpc")],
    },
    TestBinary {
        binary: "heavy_abi_uapi",
        needs: &[Req::Tool("clang")],
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
        binary: "heavy_conformance_testfloat",
        needs: &[Req::Data(".testdata/testfloat")],
    },
    TestBinary {
        binary: "heavy_oracle_llvm",
        needs: &[Req::Tool("llvm-mc")],
    },
    TestBinary {
        binary: "heavy_oracle_power",
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
];

/// コマンドが使えるかを `--version` で調べる。
fn tool_available(name: &str) -> bool {
    [
        name.to_string(),
        format!("/usr/sbin/{name}"),
        format!("/usr/bin/{name}"),
    ]
    .iter()
    .any(|c| {
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
            assert!(!tb.needs.is_empty(), "{}", tb.binary);
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
