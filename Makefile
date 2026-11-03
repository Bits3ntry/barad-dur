# Barad-dûr — build, test, and dev automation

.PHONY: help install deps backend-test backend-run backend-migrate \
        frontend-dev frontend-build frontend-preview cli-test cli-run \
        db-reset all test clean lint docker-up docker-down \
        qa-stack qa-stack-seed qa-smoke qa-e2e qa

# Default: run everything (backend tests + CLI tests + frontend build)
all: deps backend-test cli-test frontend-build

# ---------------------------------------------------------------------------
# Setup & dependencies
# ---------------------------------------------------------------------------
install:
	$(eval BIN := $(shell test -x .venv/bin/pip && echo .venv/bin/pip || echo pip3))
	$(BIN) install -r requirements.txt
	$(BIN) install -r requirements-dev.txt
	npm install --prefix frontend

deps: install

# ---------------------------------------------------------------------------
# Backend
# ---------------------------------------------------------------------------
backend-test:
	cd backend && PYTHONPATH= ./.venv/bin/pytest -q

backend-run:
	cd backend && ./.venv/bin/uvicorn backend.app.main:app --reload --port 8000

backend-migrate:
	cd backend && ./.venv/bin/alembic upgrade head

db-reset:
	cd backend && ./.venv/bin/alembic downgrade head && ./.venv/bin/alembic upgrade head

# ---------------------------------------------------------------------------
# QA (see docs/qa/plan.md)
# ---------------------------------------------------------------------------
qa-stack:
	cd . && ./.venv/bin/python scripts/e2e_stack.py --port 8099

qa-stack-seed:
	cd . && ./.venv/bin/python scripts/e2e_stack.py --port 8099 --seed

# Contract gate against a running stack: make qa-smoke K=<api key> [URL=...]
qa-smoke:
	@test -n "$(K)" || (echo "usage: make qa-smoke K=<api key> [URL=http://127.0.0.1:8099]" && exit 2)
	./.venv/bin/python scripts/qa_smoke.py --url $(or $(URL),http://127.0.0.1:8099) --key "$(K)"

qa-e2e:
	./.venv/bin/python scripts/demo_v0.py

# Everything that does not need a browser or a human.
qa: backend-test frontend-build qa-e2e

# ---------------------------------------------------------------------------
# Frontend
# ---------------------------------------------------------------------------
frontend-dev:
	npm run dev --prefix frontend

frontend-build:
	npm run build --prefix frontend

frontend-preview:
	npm run preview --prefix frontend

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
cli-test:
	cd tests && ./.venv/bin/pytest -q

cli-run:
	cd cli && ./.venv/bin/barad --help

# ---------------------------------------------------------------------------
# Full stack
# ---------------------------------------------------------------------------
docker-up:
	docker compose up -d

docker-down:
	docker compose down

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
clean:
	rm -rf frontend/dist
	cd backend && find . -name "*.pyc" -delete -o -name "__pycache__" -type d -delete
	cd tests && find . -name "*.pyc" -delete -o -name "__pycache__" -type d -delete
	find . -name "*.pyc" -delete -o -name "__pycache__" -type d -delete

lint:
	cd backend && ./.venv/bin/rustfmt --check src/backend/app
	cd frontend && npm run lint

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
help:
	@echo "Barad-dûr — build & test automation"
	@echo ""
	@echo "Setup:"
	@echo "  make install      Install Python + Node dependencies"
	@echo ""
	@echo "Backend:"
	@echo "  make backend-test Run backend test suite"
	@echo "  make backend-run  Start backend (uvicorn, dev mode)"
	@echo "  make backend-migrate Run Alembic migrations"
	@echo ""
	@echo "Frontend:"
	@echo "  make frontend-dev       Start Vite dev server"
	@echo "  make frontend-build     Production build"
	@echo "  make frontend-preview   Preview production build"
	@echo ""
	@echo "CLI:"
	@echo "  make cli-test   Run CLI test suite"
	@echo "  make cli-run    Run barad CLI (help)"
	@echo ""
	@echo "Full stack:"
	@echo "  make docker-up     Start PostgreSQL + console (docker compose)"
	@echo ""
	@echo "Utilities:"
	@echo "  make db-reset     Reset database to current migration"
	@echo "  make clean        Remove build artifacts"
	@echo "  make lint         Run linters"
	@echo "  make help         Show this help"
