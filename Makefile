# AgentGuard task runner (Unix / CI). Windows users: use `.\tasks.ps1` instead.
COMPOSE := docker compose -f infra/docker-compose.yml
API_DIR := apps/api
WEB_DIR := apps/web
PY := $(API_DIR)/.venv/bin/python

.DEFAULT_GOAL := help
.PHONY: help infra-up infra-down infra-clean infra-logs infra-ps up down \
        api-install api-dev api-test api-lint web-install web-dev fmt \
        db-migrate db-check db-downgrade db-seed events-migrate

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

infra-up: ## Start backing services
	$(COMPOSE) up -d
infra-down: ## Stop backing services
	$(COMPOSE) down
infra-clean: ## Stop backing services and delete volumes (wipes data)
	$(COMPOSE) down -v
infra-logs: ## Tail backing-service logs
	$(COMPOSE) logs -f
infra-ps: ## Show backing-service status
	$(COMPOSE) ps

up: ## Build + run everything in containers
	$(COMPOSE) --profile apps up --build -d
down: ## Stop all containers
	$(COMPOSE) --profile apps down

api-install: ## Create API venv and install deps
	cd $(API_DIR) && python -m venv .venv && \
		.venv/bin/python -m pip install --upgrade pip && \
		.venv/bin/python -m pip install -e ../../packages/policy-engine && \
		.venv/bin/python -m pip install -e ".[dev]"
api-dev: ## Run the API locally with reload
	cd $(API_DIR) && .venv/bin/python -m uvicorn agentguard_api.main:app --reload --port $(or $(API_PORT),8010)
api-test: ## Run the API test suite
	cd $(API_DIR) && .venv/bin/python -m pytest
api-lint: ## Ruff lint + format check
	cd $(API_DIR) && .venv/bin/python -m ruff check . && .venv/bin/python -m ruff format --check .
fmt: ## Auto-format Python
	cd $(API_DIR) && .venv/bin/python -m ruff format . && .venv/bin/python -m ruff check --fix .

db-migrate: ## Apply Postgres migrations
	cd $(API_DIR) && .venv/bin/python -m alembic upgrade head
db-check: ## Fail if models drifted from migrations
	cd $(API_DIR) && .venv/bin/python -m alembic check
db-downgrade: ## Roll back the last migration
	cd $(API_DIR) && .venv/bin/python -m alembic downgrade -1
db-seed: ## Seed RBAC catalog + plans (idempotent)
	cd $(API_DIR) && .venv/bin/python -m agentguard_api.rbac.seed
events-migrate: ## Apply the ClickHouse event-store schema
	cd $(API_DIR) && .venv/bin/python -m agentguard_api.events.migrate

web-install: ## Install web deps
	cd $(WEB_DIR) && npm install
web-dev: ## Run the web dashboard locally
	cd $(WEB_DIR) && npm run dev
