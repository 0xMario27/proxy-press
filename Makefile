.PHONY: up down restart status build rebuild logs clean help

# 加载 .env 文件（如果存在）
-include .env
export CLOUDFLARE_API_TOKEN

up:
	@echo "🚀 启动..."
	docker compose up -d
	@$(MAKE) status

down:
	@echo "🛑 停止..."
	docker compose down

restart:
	@echo "🔄 重启..."
	docker compose restart
	@$(MAKE) status

status:
	@echo "📊 服务:"
	@docker ps --filter "name=sub" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || echo "  无"
	@echo ""
	@echo "🌐 http://localhost:58080"

build:
	@echo "🔨 构建..."
	docker compose build --no-cache --parallel

build-web:
	@echo "🔨 重建前端..."
	docker compose build --no-cache sub-web
	@echo "✅ make restart-web"

rebuild:
	@echo "🔨 重建 & 部署..."
	docker compose build --no-cache --parallel
	docker compose up -d --force-recreate
	@$(MAKE) status

restart-web:
	docker compose up -d --force-recreate sub-web

restart-backend:
	docker compose up -d --force-recreate sub-smart-js

logs:
	docker compose logs -f --tail=50

logs-web:
	docker logs -f --tail=50 sub-web

logs-backend:
	docker logs -f --tail=50 sub-smart-js

clean:
	docker compose down -v

clean-all: clean
	docker rmi sub-web-local:latest 2>/dev/null; true

sync:
	@python3 scripts/sync-worker.py
	@node --check worker/worker.js && echo '✅ Worker syntax OK'

deploy-worker:
	@echo '🚀 推送 Worker 到 Cloudflare...'
	cd worker && npx wrangler deploy

deploy: sync deploy-worker

update-rules:
	@echo "📥 从 ACL4SSR 上游同步规则文件..."
	@git remote get-url upstream 2>/dev/null || git remote add upstream https://github.com/ACL4SSR/ACL4SSR.git
	@git fetch upstream master
	@git checkout upstream/master -- Clash/ Acl/ Tool/ 2>/dev/null
	@cp -r Clash/* backend/Clash/ 2>/dev/null || true
	@cp -r Acl/* rules/Acl/ 2>/dev/null || true
	@cp -r Tool/* rules/Tool/ 2>/dev/null || true
	@rm -rf Clash/ Acl/ Tool/
	@echo "✅ 规则已更新（backend/Clash/ rules/Acl/ rules/Tool/）"
	@echo "⚠️  检查 git diff 后 commit 即可"

help:
	@echo "make up / down / restart / status / logs"
	@echo "make build / rebuild / build-web / restart-web / restart-backend"
	@echo "make logs-web / logs-backend"
	@echo "make sync        — 同步生成 worker/worker.js"
	@echo "make deploy-worker — 推送 Worker 到 Cloudflare"
	@echo "make deploy      — sync + deploy 一键推送"
	@echo "make update-rules — 从上游同步规则文件"
	@echo "make clean / clean-all"
