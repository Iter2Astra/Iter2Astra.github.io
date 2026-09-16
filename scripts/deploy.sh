#!/usr/bin/env bash
# 构建并把产物发布到本机 nginx 站点目录 /var/www/astro-blog
set -euo pipefail

cd "$(dirname "$0")/.."

pnpm build
sudo rsync -a --delete dist/ /var/www/astro-blog/

echo "已发布到 /var/www/astro-blog（nginx 直接对外服务，无需重启）"
