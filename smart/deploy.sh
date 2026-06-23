#!/bin/bash
# ============================================================
# 部署 sub-smart 到 Fly.io（免费）
# 首次运行需要: brew install flyctl && flyctl auth signup
# ============================================================
set -e
cd "$(dirname "$0")"

echo "📦 部署 proxy-press 后端到 Fly.io..."
flyctl deploy --ha=false

echo ""
echo "✅ 部署完成！后端地址: https://proxy-press.fly.dev"
echo ""
echo "⚠️  接下来去 GitHub 仓库更新 sub-web/.env.gh-pages："
echo "   VITE_SUBCONVERTER_DEFAULT_BACKEND = \"https://proxy-press.fly.dev/sub?\""
