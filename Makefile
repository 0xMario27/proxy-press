.PHONY: up down restart status build rebuild logs clean help

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
	docker compose build --parallel

build-web:
	@echo "🔨 重建前端..."
	docker compose build --no-cache sub-web
	@echo "✅ make restart-web"

rebuild:
	@echo "🔨 重建 & 部署..."
	docker compose build --parallel
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
	@python3 scripts/sync-parser.py
	@node --check worker/worker.js && echo '✅ Syntax OK'

help:
	@echo "make up / down / restart / status / logs"
	@echo "make build / rebuild / build-web / restart-web / restart-backend"
	@echo "make logs-web / logs-backend"
	@echo "make clean / clean-all"
