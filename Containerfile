# polyisa の開発・検証環境。task check / task test / task test:full など
# すべての検証がホストに依存せずコンテナ内で完結する。
#
# ビルドと実行は Taskfile 経由（podman を直接叩かない）:
#   task container:build
#   task container -- task check
#
# ツールの版は docs/references.md の TOOL-* エントリと対応する。

FROM docker.io/library/debian:trixie@sha256:bfc36aecdece0387418759dba474aa856c026ca8087da3606b41b90ab0509c99

ARG DEBIAN_FRONTEND=noninteractive

# 基本パッケージと LLVM 23（apt.llvm.org 公式リポジトリ）を入れる。
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    gnupg \
    xz-utils \
    build-essential \
    python3 \
    binutils \
    gdb \
    cpio \
    file \
    qemu-user \
    qemu-system-x86 \
    gcc-x86-64-linux-gnux32 \
    libc6-dev-x32-cross \
    binutils-x86-64-linux-gnux32 \
    && curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key \
        | gpg --dearmor -o /usr/share/keyrings/llvm-snapshot.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/llvm-snapshot.gpg] https://apt.llvm.org/trixie/ llvm-toolchain-trixie-23 main" \
        > /etc/apt/sources.list.d/llvm.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        clang-23 \
        lld-23 \
        llvm-23 \
    && rm -rf /var/lib/apt/lists/*

# unversioned 名で呼ぶためのリンク。
RUN for tool in clang clang++ llvm-mc llvm-objdump llvm-mca ld.lld; do \
        name=$(ls /usr/bin/${tool}-23 2>/dev/null || ls /usr/lib/llvm-23/bin/${tool} 2>/dev/null); \
        ln -sf "$name" "/usr/local/bin/${tool}"; \
    done

# Rust ツールチェーン（台帳 TOOL-RUST に対応）。
ARG RUST_VERSION=1.100.0
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/opt/sde:/opt/xed/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain "${RUST_VERSION}" --profile minimal \
    && rustup component add rustfmt clippy \
    && rustup target add \
        powerpc64-unknown-linux-gnu \
        i686-unknown-linux-gnu \
        wasm32-unknown-unknown

# バイナリ配布のツール（台帳 TOOL-NEXTEST / TOOL-TASK / TOOL-WASMTIME に対応）。
ARG NEXTEST_VERSION=0.9.151
ARG TASK_VERSION=3.54.0
ARG WASMTIME_VERSION=50.0.1
RUN curl -fsSL "https://get.nexte.st/${NEXTEST_VERSION}/linux" \
        | tar -xz -C /usr/local/bin \
    && curl -fsSL "https://github.com/go-task/task/releases/download/v${TASK_VERSION}/task_linux_amd64.tar.gz" \
        | tar -xz -C /usr/local/bin task \
    && curl -fsSL "https://github.com/bytecodealliance/wasmtime/releases/download/v${WASMTIME_VERSION}/wasmtime-v${WASMTIME_VERSION}-x86_64-linux.tar.xz" \
        | tar -xJ -C /tmp \
    && mv "/tmp/wasmtime-v${WASMTIME_VERSION}-x86_64-linux/wasmtime" /usr/local/bin/ \
    && rm -rf "/tmp/wasmtime-v${WASMTIME_VERSION}-x86_64-linux"

# Intel XED（台帳 TOOL-XED に対応）。mbuild でソースビルドする。
ARG XED_VERSION=v2026.08.23
RUN git clone --depth 1 --branch "${XED_VERSION}" https://github.com/intelxed/mbuild.git /build/mbuild \
    && git clone --depth 1 --branch "${XED_VERSION}" https://github.com/intelxed/xed.git /build/xed \
    && cd /build/xed \
    && python3 ./mfile.py --share --install-dir /opt/xed examples install \
    && rm -rf /build

# Intel SDE（台帳 TOOL-INTEL-SDE に対応）。公式配布物をそのまま展開する。
ARG SDE_VERSION=10.13.1-2026-07-28
RUN curl -fsSL -o /tmp/sde.tar.xz \
        "https://downloadmirror.intel.com/924984/sde-external-${SDE_VERSION}-lin.tar.xz" \
    && tar -xJ -C /opt -f /tmp/sde.tar.xz \
    && mv "/opt/sde-external-${SDE_VERSION}-lin" /opt/sde \
    && rm /tmp/sde.tar.xz

# 導入確認（ビルド時スモークテスト）。
RUN rustc --version && cargo --version && rustup target list --installed \
    && task --version && cargo nextest --version \
    && clang --version && llvm-mc --version && wasmtime --version \
    && xed -version | head -1 && sde64 -version | head -1 \
    && x86_64-linux-gnux32-gcc-14 --version | head -1
