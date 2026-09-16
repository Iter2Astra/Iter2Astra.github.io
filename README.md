# 远山 · 个人博客

基于 [Firefly](https://github.com/CuteLeaf/Firefly) 模板构建的个人博客，技术栈为 Astro 7 + Svelte 5 + Tailwind CSS 4，构建产物为纯静态站点。

## 项目结构

```
Firefly/
├── src/
│   ├── config/        # 站点全部配置（一功能一文件：站点信息、导航、壁纸、评论、字体、特效等）
│   ├── types/         # 与 src/config 一一对应的类型定义
│   ├── content/       # 内容集合
│   │   ├── posts/     # 博客文章（Markdown + 配图，文件名即文章 URL）
│   │   └── dynamic/   # 动态（说说）
│   ├── components/    # 组件（layout 布局 / controls 控件 / widget 小部件 / features 特效 / comment 评论等）
│   ├── plugins/       # Markdown 扩展（remark/rehype 插件：代码卡片、图表、阅读时长等）
│   ├── layouts/       # 页面布局（Layout / MainGridLayout）
│   ├── pages/         # 路由页面（文章、归档、分类、标签、搜索、RSS 等）
│   ├── utils/         # 工具函数
│   ├── i18n/          # 多语言 UI 文案
│   └── constants/     # 构建产物（LQIP 占位图、图标数据），随内容变更自动更新
├── scripts/           # 构建辅助脚本（LQIP 生成、字体子集化、Pagefind 索引等）
├── public/            # 静态资源（不参与构建优化）
├── dist/              # 构建产物，Web 服务器实际提供服务的目录
└── astro.config.mjs   # Astro 配置（集成、Markdown 管线、sitemap）
```

## 常用指令

环境要求：Node.js ≥ 22，pnpm ≥ 11。

| 指令 | 说明 |
| --- | --- |
| `pnpm install` | 安装依赖 |
| `pnpm dev` | 本地开发服务器（localhost:4321，内存小的机器容易 OOM，慎用） |
| `pnpm build` | 构建站点到 `dist/` |
| `pnpm preview` | 本地预览构建产物 |
| `pnpm check` | Astro 诊断（.astro/.ts 语法检查） |
| `pnpm type-check` | TypeScript 类型检查 |
| `pnpm new-post 文件名` | 新建文章 |
| `pnpm new-d 内容` | 新建一条动态 |

## 构建与部署

### 构建

```bash
pnpm install
NODE_OPTIONS="--max-old-space-size=1280" pnpm build
```

构建流程包含：生成 GitHub 卡片数据 → LQIP 占位图 → VNDB 封面 → Astro 构建（含 OG 分享图）→ 裁剪看板娘资源 → 字体子集化 → 压缩内联脚本 → Pagefind 搜索索引。

> 小内存机器（≤2GB）必须带 `NODE_OPTIONS="--max-old-space-size=1280"` 限制 Node 堆上限，否则构建会被系统 OOM 杀掉。

### 部署（systemd + serve）

`dist/` 是纯静态目录，用任意静态服务器托管即可。当前使用 systemd 托管 `serve`（`/etc/systemd/system/firefly-web.service`，监听 3000 端口，开机自启、崩溃自动拉起）：

```ini
[Unit]
Description=Firefly static blog (serve dist)
After=network-online.target

[Service]
User=ubuntu
ExecStart=<node/bin目录>/serve --listen tcp:0.0.0.0:3000 /home/ubuntu/Firefly/dist
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

### 日常发文流程

1. `pnpm new-post 文件名` 创建文章并编写内容（或直接改 `src/content/posts/` 下的 md）
2. `NODE_OPTIONS="--max-old-space-size=1280" pnpm build`
3. 无需重启服务，刷新页面即生效（静态服务器按请求读取 `dist/`）

### 迁移到新服务器

```bash
git clone https://gitee.com/ck_0ff/astro_-blog.git ~/Firefly && cd ~/Firefly
pnpm install
NODE_OPTIONS="--max-old-space-size=1280" pnpm build
# 再复制/重建 systemd 服务即可
```

注意：`src/config/siteConfig.ts` 中的 `site_url` 需改为实际部署域名，它影响 RSS、sitemap 和分享图的链接。

## 致谢

- 本站基于 [Firefly](https://github.com/CuteLeaf/Firefly) 模板（作者 [CuteLeaf](https://github.com/CuteLeaf)）搭建与定制，感谢其出色的设计与持续维护；
- Firefly 基于 [fuwari](https://github.com/saicaca/fuwari)（作者 [saicaca](https://github.com/saicaca)）二次开发，同样致谢；
- 项目遵循 MIT 协议，相关许可声明见 [LICENSE](./LICENSE)。
