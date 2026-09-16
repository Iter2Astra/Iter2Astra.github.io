---
title: "搭建 AI Agent 驱动的二进制分析与 Fuzz Docker 镜像"
published: 2026-09-09
description: 整合 AFL++、radare2 + r2ghidra、pwndbg、pwntools 与 Claude Code 的二进制安全分析 Docker 镜像，内置本地知识库与练手靶标，为多智能体自动化 Fuzz 框架打基础。
tags: [Docker, Fuzzing, 二进制安全]
category: 环境搭建
---

## 背景

最近学了 afl++，想搭建一个多智能体的自动化 fuzz 加上 gdb 调试的框架，结果发现没有合适的 docker 工具，就想着整合一个 docker 镜像，所以做一下记录。

## 工具列表

暂时计划的工具列表如下：

| 工具 | 版本 | 用途 |
| --- | --- | --- |
| AFL++ | apt 安装 | fuzzing 主力，配 afl-clang-fast 插桩编译器 |
| Ghidra Headless | 反编译 | 静态分析/逆向；支持 Java/Python 脚本 (analyzeHeadless)，方便批量导出 Pseudo-C |
| gdb + pwndbg | git 主线 | 动态调试，pwndbg 挂进 gdb 提供堆/栈可视化 |
| pwntools | 4.14.0 | 写 exploit 的 Python 库（含 checksec） |
| ROPgadget / ropper | pip 安装 | ROP 链 gadget 搜索 |

**编译工具链**：

- gcc / clang / lld / llvm（build-essential 全套），支持 `-fsanitize=address` 和 `-fsanitize=fuzzer`

**基础系统工具**：

- file、binutils（objdump/readelf 等）、strace/ltrace（系统调用跟踪）、tmux（长时 fuzz 后台）、ripgrep、jq、curl/wget、git、python3-pip、nodejs/npm

**Agent 工具**：

- claude-code 2.1.98，宿主机通过 `docker exec` 调它干活

**本地知识库**（`/home/analyst/knowledges/`，约定 grep 本地、不联网）：

- **hacktricks**（综合利用技术）、**how2heap**（堆利用代码全集）

总大小约 2.5GB。

其他需要注意的小点：需要做一下免密 sudo 的设置，ubuntu 需要换一下国内的下载源。

## Dockerfile

```dockerfile
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# ------------------------------------------------------------------------------
# 1. 替换清华镜像源并安装基础编译、Java 与系统工具链
# ------------------------------------------------------------------------------
RUN sed -i 's/archive.ubuntu.com/mirrors.tuna.tsinghua.edu.cn/g' /etc/apt/sources.list && \
    sed -i 's/security.ubuntu.com/mirrors.tuna.tsinghua.edu.cn/g' /etc/apt/sources.list

RUN apt-get update && apt-get install -y \
    build-essential gcc g++ clang lld llvm \
    afl++ \
    gdb \
    file binutils strace ltrace tmux ripgrep jq curl wget git unzip \
    python3 python3-pip python3-dev \
    nodejs npm \
    openjdk-17-jdk openjdk-17-jre \
    cmake pkg-config libssl-dev libffi-dev libgmp-dev sudo \
    && rm -rf /var/lib/apt/lists/*

# 配置 pip 与 npm 国内镜像（仅加快 PyPI/NPM 包下载）
RUN pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple && \
    npm config set registry https://registry.npmmirror.com

# ------------------------------------------------------------------------------
# 2. 安装 Python 工具库与 Claude-Code Agent
# ------------------------------------------------------------------------------
RUN pip3 install --progress-bar on \
    pwntools==4.14.0 \
    ROPgadget \
    ropper

RUN npm install -g --loglevel info @anthropic-ai/claude-code@2.1.98

# ------------------------------------------------------------------------------
# 3. 从本地压缩包安装 Ghidra Headless
# ------------------------------------------------------------------------------
COPY ghidra.zip /tmp/ghidra.zip
RUN unzip -q /tmp/ghidra.zip -d /opt && \
    mv /opt/ghidra_11.1.2_PUBLIC /opt/ghidra && \
    rm /tmp/ghidra.zip

ENV GHIDRA_INSTALL_DIR=/opt/ghidra
ENV PATH="${GHIDRA_INSTALL_DIR}/support:${PATH}"

# ------------------------------------------------------------------------------
# 4. 从本地 zip 包安装 Pwndbg（无任何 Git 代理，直连 GitHub）
# ------------------------------------------------------------------------------
COPY pwndbg.zip /tmp/pwndbg.zip
RUN mkdir -p /opt/pwndbg && \
    unzip -q /tmp/pwndbg.zip -d /opt/pwndbg && \
    rm /tmp/pwndbg.zip && \
    if [ -d "/opt/pwndbg/pwndbg" ]; then mv /opt/pwndbg/pwndbg/* /opt/pwndbg/ 2>/dev/null || true; fi && \
    if [ -d "/opt/pwndbg/pwndbg-dev" ]; then mv /opt/pwndbg/pwndbg-dev/* /opt/pwndbg/ 2>/dev/null || true; fi && \
    cd /opt/pwndbg && \
    ./setup.sh

# ------------------------------------------------------------------------------
# 5. 创建无密码 analyst 用户并解压离线知识库
# ------------------------------------------------------------------------------
RUN useradd -m -s /bin/bash analyst && \
    echo "analyst ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/analyst && \
    chmod 0440 /etc/sudoers.d/analyst

USER analyst
WORKDIR /home/analyst

COPY --chown=analyst:analyst hacktricks.zip /tmp/hacktricks.zip
COPY --chown=analyst:analyst how2heap.zip /tmp/how2heap.zip

RUN mkdir -p /home/analyst/knowledges && \
    unzip -q /tmp/hacktricks.zip -d /home/analyst/knowledges/ && \
    if [ -d "/home/analyst/knowledges/hacktricks-master" ]; then mv /home/analyst/knowledges/hacktricks-master /home/analyst/knowledges/hacktricks; fi && \
    unzip -q /tmp/how2heap.zip -d /home/analyst/knowledges/ && \
    if [ -d "/home/analyst/knowledges/how2heap-master" ]; then mv /home/analyst/knowledges/how2heap-master /home/analyst/knowledges/how2heap; fi && \
    rm /tmp/*.zip

WORKDIR /workspace

CMD ["/bin/bash"]
```

镜像仓库里还有几个配套文件：`demo/vuln_demo.c`、`demo/fuzz_target.c` 两个练手靶标的源码和 `verify.sh` 自检脚本，篇幅所限不贴出。

## AGENTS.md（容器内环境简报）

```markdown
# 环境介绍
* 你在 Ubuntu 24.04 二进制安全分析容器中，当前用户 analyst（非 root），需要 root 权限时用 sudo（已免密）
* 当前目录 /home/analyst/workspace 是工作空间：exploit 脚本、扫描输出、日志都放这里，宿主机会直接读取该目录

# 工具清单
* 静态分析：r2（radare2，已装 r2ghidra 插件）
    * r2 -q -A -c "pdf @ main" ./bin          # 快速反汇编
    * r2 -q -A -c "pdg @ sym.main" ./bin      # Ghidra 质量反编译（超 50 行写入文件）
    * r2 -q -A -c "ii; iz" ./bin              # 导入表 / 字符串
* 动态调试：gdb + pwndbg（非交互用 batch 模式：gdb -batch -ex 'b main' -ex run -ex 'info registers' -ex quit ./bin）
* fuzz：AFL++（afl-clang-fast 插桩编译目标）、clang -fsanitize=fuzzer,address（libFuzzer）
* exploit：pwntools（含 checksec）、ROPgadget、ropper
* 编译：gcc / clang（ASan：-fsanitize=address）

# 本地知识库（先 grep 再动手，不要联网）
* /home/analyst/knowledges/hacktricks      # 综合利用技术，二进制在 binary-exploitation 目录
* /home/analyst/knowledges/how2heap        # 堆利用技术代码全集，代码即文档
* /home/analyst/knowledges/CTF-pwn-tips    # pwn 常用技巧速查

# 练手靶标
* /home/analyst/targets/vuln_demo      # 栈溢出 demo（无保护，源码同目录 vuln_demo.c）
* /home/analyst/targets/fuzz_target    # AFL++ 插桩的崩溃 demo（源码 fuzz_target.c）

# 长时任务约定（重要）
* fuzzing 是小时级任务，禁止前台等待。必须放 tmux 后台：
    tmux new-session -d -s fuzz-1 'AFL_SKIP_CPUFREQ=1 afl-fuzz -i seeds -o out -- ./target'
* 启动后立即返回结论："fuzzer 在 tmux 会话 fuzz-1，进度文件 out/default/fuzzer_stats"
* 后续只读取 fuzzer_stats 和 out/default/crashes/ 判断进度与产出，不要 attach 干等

# 输出落盘
* 反编译结果、长输出写入文件再引用，不要整段贴进结论
* 结论只讲确认的事实与证据位置（文件路径、寄存器、崩溃地址）

# AFL++ 常用环境变量（容器内直接带，不要问为什么）
AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
```

## build.sh（一键构建 + 自检）

```bash
#!/usr/bin/env bash
# 一键构建 + 自检
# 用法: bash build.sh
set -euo pipefail
cd "$(dirname "$0")"

IMAGE="${IMAGE:-fuzz-lab}"

echo ">>> 构建镜像 $IMAGE（首次约 10~15 分钟，国内源）"
docker build -t "$IMAGE" .

echo
echo ">>> 构建完成，运行自检"
docker run --rm "$IMAGE" verify.sh

echo
echo ">>> 全部通过。下一步: 复制 .env.example 为 .env 填入 API 配置，然后 bash run_agent.sh"
```

后续如果添加了工具会继续更新一下，至于多智能体的设计，还在考虑中。
