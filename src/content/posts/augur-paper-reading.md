---
title: "【论文阅读】Augur: Dynamic Taint Analysis for Asynchronous JavaScript"
published: 2026-09-07
description: 基于 GraalVM/NodeProf 的异步 JavaScript 动态污点分析工具，通过 VM 支持的插桩与扩展抽象机语义，实现跨事件循环的污点传播。
tags: [污点追踪, 网络安全, 学术论文]
category: 论文阅读
series: "论文阅读"
seriesOrder: 3
---

《Augur: Dynamic Taint Analysis for Asynchronous JavaScript》（发表于 ASE 2022）是一篇针对现代 JavaScript 异步特性与高性能需求提出的动态污点分析（Dynamic Taint Analysis, DTA）工具论文。

这篇论文较短，读完后感觉更多是介绍了工具的一些特性，将原来的污点分析框架与最新的 JavaScript 的特性做了结合，没有更多理论的创新。（不过读都读了，也记录一下）

## 背景

**JavaScript 的普及与安全隐患**：JavaScript（尤其是 Node.js）广泛应用于服务端与前端，命令注入（Command Injection）、代码注入（Eval Injection）和 DOM-XSS 等漏洞频发。

**传统 DTA 技术在面对 JS 的局限**：

- **静态分析失效**：JavaScript 的高度动态性（反射、动态类型、自由函数作用域等）导致静态分析精度和覆盖率低。
- **性能开销极大**：传统的 JavaScript 动态污点分析工具往往会导致极高的运行延迟（通常高达数十甚至数百倍），无法适应现代化 JIT 编译器的优化。
- **对异步机制支持差**：ES6/ES7 引入的 `Promise`、`async/await` 改变了代码的执行栈与控制流，导致传统基于同步调用栈（Call Stack）的污点追踪机制失效。
- **维护成本高**：许多先前的 DTA 工具通过直接修改 JavaScript 虚拟机（VM）引擎内部实现，一旦 JS 引擎更新（如 V8/SpiderMonkey），分析工具就会破裂失效。

> DTA 对 JavaScript 特别有效，因为该语言的动态特性使得静态地确定这些漏洞变得困难。然而，JavaScript 的设计为 DTA 带来了一些独特的挑战。现代 JavaScript 采用即时编译（JIT）并进行优化。这极大地提升了性能，但使得利用底层的 x86 二进制 DTA 变得不可行。这需要一种更高级的 instrumentation 机制。然而，JavaScript 代码使用了一个由原生代码实现的庞大标准库，这意味着任何 DTA 实现都需要精确地追踪 JavaScript 和原生代码中的数据流。现有的 JavaScript DTA 将 instrumentation 实现方式分为两种：要么通过程序重写，要么通过虚拟机（VM）修改，而大多数（除了 TruffleTaint）都不支持 JavaScript ES6 和 ES7 中引入的异步特性。

## Augur 的核心设计

Augur 的核心理念是**基于 VM 支持的插桩（VM-supported instrumentation）**与**扩展的抽象机（Abstract Machine）异步污点传播**。

### 借助虚拟机稳定 API 实现高效插桩

基于 GraalVM 的 **NodeProf** 动态分析框架构建。通过 VM 暴露的稳定接口挂钩（Hooks），无需直接修改底层 VM 引擎，既保持了高效的运行性能（适应 JIT 优化），又确保了对 JavaScript 语言标准演进的兼容性。

### 支持异步 JavaScript 控制流（Promise / async / await）

Augur 扩展了经典的抽象栈机（Abstract Machine）语义，构建了一套可以跨越事件循环（Event Loop）和微任务队列（Microtask Queue）传递污点信息的模型。它将 `async/await` 的挂起与恢复过程转化为可预测的栈操作序列，精准追踪异步回调间的数据流传递。

### 原生函数与建模（Native Modeling & Polyfills）

对于底层 C/C++ 实现的原生 API（如 `fs.readFileSync`），Augur 采用轻量级的 **Native Models** 或 JS 编写的 **Polyfills**，避开对 Native 代码的深度插桩，仅建模其数据输入输出的污点转移关系，极大地提升了分析效率。

### 高度可定制的抽象分析

提供三种粒度的污点追踪模式：

- `Boolean`：仅跟踪值是否受到污点污染（最快）。
- `SourcedBoolean`：记录污点来源（Source）以及引入行号（实用安全分析）。
- `Expression`：完全记录全程序表达式图谱，支持任意数据流分析（极度详细但开销较大）。
