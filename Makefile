.PHONY: help install install-dev install-tools setup lint format typecheck
.PHONY: test test-unit test-security test-integration test-all coverage
.PHONY: run run-sse run-dev inspect clean doctor
.PHONY: docker-build docker-up docker-down docker-logs docker-shell
.PHONY: docker-lab docker-full docker-pentest docker-agent docker-agent-haiku docker-agent-sonnet docker-agent-logs docker-clean
.PHONY: docker-agent-bg docker-agent-haiku-bg docker-agent-sonnet-bg docker-agent-stop
.PHONY: docker-rebuild docker-rebuild-tengu docker-reset

# ============================================================
# CONFIGURATION
# ============================================================
PYTHON := uv run python
PYTEST := uv run pytest
PROJECT := tengu

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ============================================================
# INSTALLATION & SETUP
# ============================================================
install: ## Install project dependencies
	uv sync

install-dev: ## Install dev dependencies (tests, lint, types)
	uv sync --extra dev

install-tools: ## Install external pentesting tools (use scripts/install-tools.sh --<category> for selective install)
	chmod +x scripts/install-tools.sh
	./scripts/install-tools.sh --all

setup: install-dev ## Full setup (Python)
	@echo "Tengu setup complete! Run 'make install-tools' to install pentesting tools."

# ============================================================
# CODE QUALITY
# ============================================================
lint: ## Lint with ruff
	uv run ruff check src/ tests/

format: ## Format with ruff
	uv run ruff format src/ tests/

typecheck: ## Type-check with mypy
	uv run mypy src/

check: lint typecheck ## Lint + typecheck

# ============================================================
# TESTS
# ============================================================
test: test-unit test-security ## Fast tests (unit + security)

test-unit: ## Unit tests
	$(PYTEST) tests/unit -v

test-security: ## Security tests (command injection, input validation)
	$(PYTEST) tests/security -v

test-integration: ## Integration tests (requires tools installed)
	$(PYTEST) tests/integration -v

test-all: ## All tests
	$(PYTEST) tests/ -v

coverage: ## Tests with coverage report
	$(PYTEST) tests/ --cov=src/$(PROJECT) --cov-report=html --cov-report=term-missing
	@echo "HTML report at htmlcov/index.html"

# ============================================================
# RUNNING
# ============================================================
run: ## Start MCP server (stdio transport)
	uv run tengu

run-sse: ## Start MCP server (SSE transport, binds 0.0.0.0 for remote access)
	uv run tengu --transport sse --host 0.0.0.0

run-dev: ## Start with debug logging
	TENGU_LOG_LEVEL=DEBUG uv run tengu

inspect: ## Open MCP Inspector to test tools interactively
	npx @modelcontextprotocol/inspector uv run tengu

# ============================================================
# TOOLS
# ============================================================
doctor: ## Check which pentesting tools are installed
	$(PYTHON) -c "import asyncio; from tengu.executor.registry import check_all; asyncio.run(check_all())"

# ============================================================
# CLEANUP
# ============================================================
clean: ## Remove build artifacts and cache
	rm -rf dist/ build/ .pytest_cache/ htmlcov/ .mypy_cache/ .ruff_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

# ============================================================
# DOCKER
# ============================================================
TENGU_TIER ?= core

docker-build: ## Build Docker image (TENGU_TIER=core|full|minimal)
	docker compose build --build-arg TENGU_TIER=$(TENGU_TIER)

docker-up: ## Start Tengu in Docker
	docker compose up -d

docker-down: ## Stop Tengu Docker containers
	docker compose down

docker-logs: ## Tail Tengu Docker logs
	docker compose logs -f tengu

docker-shell: ## Open shell in Tengu container
	docker compose exec tengu bash

docker-lab: ## Start Tengu + lab targets (Juice Shop, DVWA)
	docker compose --profile lab up -d

docker-full: ## Start everything (Tengu + MSF + ZAP + labs)
	docker compose --profile exploit --profile proxy --profile lab up -d

docker-pentest: ## Start Tengu + MSF + ZAP for real-world pentests (no lab targets)
	docker compose --profile exploit --profile proxy up -d

docker-agent: ## Run autonomous agent (requires .env with ANTHROPIC_API_KEY and TENGU_AGENT_TARGET)
	docker compose --profile agent run --rm tengu-agent

docker-agent-haiku: ## Run autonomous agent with claude-haiku-4-5 (cheaper, faster)
	TENGU_AGENT_MODEL=claude-haiku-4-5 TENGU_AGENT_MAX_TOKENS=1024 \
		docker compose --profile agent run --rm tengu-agent

docker-agent-sonnet: ## Run autonomous agent with claude-sonnet-4-6 (default, balanced)
	TENGU_AGENT_MODEL=claude-sonnet-4-6 TENGU_AGENT_MAX_TOKENS=4096 \
		docker compose --profile agent run --rm tengu-agent

docker-agent-bg: ## Run autonomous agent in background (TARGET=juice-shop make docker-agent-bg)
	TENGU_AGENT_TARGET=${TARGET} \
		docker compose --profile agent run --rm -d tengu-agent

docker-agent-haiku-bg: ## Run agent with haiku in background (TARGET=juice-shop make docker-agent-haiku-bg)
	TENGU_AGENT_MODEL=claude-haiku-4-5 TENGU_AGENT_MAX_TOKENS=1024 \
	TENGU_AGENT_TARGET=${TARGET} \
		docker compose --profile agent run --rm -d tengu-agent

docker-agent-sonnet-bg: ## Run agent with sonnet in background (TARGET=juice-shop make docker-agent-sonnet-bg)
	TENGU_AGENT_MODEL=claude-sonnet-4-6 TENGU_AGENT_MAX_TOKENS=4096 \
	TENGU_AGENT_TARGET=${TARGET} \
		docker compose --profile agent run --rm -d tengu-agent

docker-agent-stop: ## Stop all running agent containers (leaves tengu server and lab intact)
	docker ps --filter "name=tengu-agent" -q | xargs -r docker stop

docker-agent-logs: ## Tail logs from the most recent running agent container
	@AGENT_ID=$$(docker ps --filter "name=tengu-agent" --latest -q); \
	if [ -z "$$AGENT_ID" ]; then echo "[error] No agent container running. Start one with: make docker-agent-haiku-bg TARGET=<host>"; exit 1; fi; \
	echo "[logs] Following agent container: $$(docker ps --filter id=$$AGENT_ID --format '{{.Names}}')"; \
	docker logs -f $$AGENT_ID

docker-reports: ## List reports generated inside Docker (stored in tengu-output volume)
	docker run --rm -v tengu-output:/app/output alpine ls -lh /app/output/

docker-report: ## Cat a specific report (REPORT=filename.md)
	docker run --rm -v tengu-output:/app/output alpine cat /app/output/$(REPORT)

docker-clean: ## Remove Docker images and volumes
	docker compose down -v --rmi local

# ── Rebuild targets ──────────────────────────────────────────────────────────

docker-rebuild: ## Full no-cache rebuild (use after Dockerfile or dep changes)
	docker compose build --no-cache --build-arg TENGU_TIER=$(TENGU_TIER)

docker-rebuild-tengu: ## Rebuild only the tengu service (fast, after src/ changes)
	docker compose build --no-cache --build-arg TENGU_TIER=$(TENGU_TIER) tengu

docker-reset: ## Destroy all containers/volumes/images and rebuild from scratch (TENGU_TIER=core|full|minimal)
	docker compose down -v --rmi local
	docker compose build --no-cache --build-arg TENGU_TIER=$(TENGU_TIER)
	docker compose up -d
