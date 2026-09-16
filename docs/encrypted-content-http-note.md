# 加密内容的临时 HTTP 方案（待 HTTPS 后还原）

> 记录时间：2026-09-15
> 状态：临时方案，等域名审核通过、部署 HTTPS 后应还原为 Web Crypto 实现。

## 背景

博客加密功能（文章 frontmatter 的 `password` / `passwordHint`，以及相册的 `password`）
采用"构建时加密 + 浏览器端解密"：

- 构建时：`src/utils/crypto-utils.ts` 用 PBKDF2-SHA256（100000 次迭代）派生密钥，
  AES-256-GCM 加密正文 HTML，输出 `base64(salt[16] + iv[12] + authTag[16] + ciphertext)`。
- 浏览器端：`src/components/features/EncryptedContent.astro` 的内联脚本用 Web Crypto API
  （`crypto.subtle`）解密。

问题：**`crypto.subtle` 只在安全上下文（HTTPS 或 localhost）暴露**。站点目前没有 HTTPS、
通过域名走纯 HTTP 访问，`crypto.subtle` 为 `undefined`，输入密码后解密直接失败，
表现为提交后无反应。本地 `pnpm dev`（localhost）不受影响，所以开发时发现不了。

## 临时修改（当前状态）

- 新增依赖：`@noble/hashes`、`@noble/ciphers`（纯 JS 实现，不依赖安全上下文）。
- 修改文件：`src/components/features/EncryptedContent.astro`
  - `<script is:inline>` 改为普通 `<script>`（让 Astro 打包 npm import）；
  - 解密改用 `pbkdf2Async` + `gcm`（异步、不阻塞主线程）；
  - 算法、迭代次数、密文格式与 `crypto-utils.ts` 完全一致，**构建端无需任何改动**，
    新旧密文互通。
- 代码中留有 `TODO(HTTPS)` 标记，可全局搜索定位。

## 还原步骤（部署 HTTPS 后）

1. 搜索 `TODO(HTTPS)` 定位 `EncryptedContent.astro` 中的脚本。
2. 把 noble 的解密实现改回 Web Crypto：

   ```ts
   async function decrypt(encryptedData: string, pwd: string): Promise<string> {
       const raw = base64ToBytes(encryptedData);
       const salt = raw.slice(0, SALT_LEN);
       const iv = raw.slice(SALT_LEN, SALT_LEN + IV_LEN);
       const authTag = raw.slice(SALT_LEN + IV_LEN, SALT_LEN + IV_LEN + TAG_LEN);
       const ciphertext = raw.slice(SALT_LEN + IV_LEN + TAG_LEN);

       const combined = new Uint8Array(ciphertext.length + TAG_LEN);
       combined.set(ciphertext);
       combined.set(authTag, ciphertext.length);

       const enc = new TextEncoder();
       const keyMaterial = await crypto.subtle.importKey(
           "raw", enc.encode(pwd), "PBKDF2", false, ["deriveKey"],
       );
       const key = await crypto.subtle.deriveKey(
           { name: "PBKDF2", salt, iterations: ITERATIONS, hash: "SHA-256" },
           keyMaterial,
           { name: "AES-GCM", length: 256 },
           false,
           ["decrypt"],
       );
       const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, combined);
       return new TextDecoder().decode(decrypted);
   }
   ```

   （`base64ToBytes` / `showContent` / sessionStorage 缓存逻辑不变。）

3. 移除 `import { gcm } ...`、`import { pbkdf2Async } ...`、`import { sha256 } ...`，
   删除顶部的 `TODO(HTTPS)` 注释。
4. 卸载依赖：`pnpm remove @noble/hashes @noble/ciphers`。
5. 删除本文档，提交时注明 "还原 Web Crypto 解密（已部署 HTTPS）"。

## 验证方式（HTTP 环境实测）

1. `pnpm build && pnpm preview --host`
2. 用 **局域网 IP**（非 localhost，复现非安全上下文）访问带密码的页面，例如
   `http://<局域网IP>:4321/gallery/encrypted-test`（相册示例密码：123456），
   输入密码应能正常解密；错误密码应显示错误提示。
