.PHONY: help install dev-install format lint type-check security check-all clean pre-commit setup-dev dev viewer wheel tui-build tui-test tui-lint

TUI_BINARY := build/sidecar/strix-tui$(if $(filter Windows_NT,$(OS)),.exe)

help:
	@echo "Available commands:"
	@echo "  setup-dev     - Install all development dependencies and setup pre-commit"
	@echo "  install       - Install production dependencies"
	@echo "  dev-install   - Install development dependencies"
	@echo ""
	@echo "Code Quality:"
	@echo "  format        - Format code with ruff"
	@echo "  lint          - Lint code with ruff"
	@echo "  type-check    - Run type checking with mypy and pyright"
	@echo "  security      - Run security checks with bandit"
	@echo "  check-all     - Run all code quality checks"
	@echo ""
	@echo "Development:"
	@echo "  pre-commit    - Run pre-commit hooks on all files"
	@echo "  viewer        - Rebuild the local-viewer SPA (commit the output)"
	@echo "  wheel         - Build a platform wheel with the bundled Go sidecar"
	@echo "  clean         - Clean up cache files and artifacts"
	@echo "  tui-build     - Build the Bubble Tea TUI"
	@echo "  tui-test      - Test the Bubble Tea TUI"
	@echo "  tui-lint      - Vet and format-check the Bubble Tea TUI"

install:
	uv sync --no-dev

dev-install:
	uv sync

setup-dev: dev-install
	uv run pre-commit install
	@echo "✅ Development environment setup complete!"
	@echo "Run 'make check-all' to verify everything works correctly."

format:
	@echo "🎨 Formatting code with ruff..."
	uv run ruff format .
	@echo "✅ Code formatting complete!"

lint:
	@echo "🔍 Linting code with ruff..."
	uv run ruff check . --fix
	@echo "✅ Linting complete!"

type-check:
	@echo "🔍 Type checking with mypy..."
	uv run mypy strix/
	@echo "🔍 Type checking with pyright..."
	uv run pyright strix/
	@echo "✅ Type checking complete!"

security:
	@echo "🔒 Running security checks with bandit..."
	uv run bandit -r strix/ -c pyproject.toml
	@echo "✅ Security checks complete!"

check-all: format lint type-check security
	@echo "✅ All code quality checks passed!"

pre-commit:
	@echo "🔧 Running pre-commit hooks..."
	uv run pre-commit run --all-files
	@echo "✅ Pre-commit hooks complete!"

clean:
	@echo "🧹 Cleaning up cache files..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	@echo "✅ Cleanup complete!"

viewer:
	@echo "🖥️  Building the local-viewer SPA..."
	cd strix/interface/viewer/frontend && npm ci && npm run build
	@echo "✅ Viewer built to strix/interface/viewer/static/ (commit the changes)."

wheel:
	uv build --wheel

dev: format lint type-check
	@echo "✅ Development cycle complete!"

tui-build:
	mkdir -p build/sidecar
	cd strix/interface/tui && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ../../../$(TUI_BINARY) ./cmd/strix-tui

tui-test:
	cd strix/interface/tui && go test -race ./...

tui-lint:
	cd strix/interface/tui && test -z "$$(gofmt -l .)" && go vet ./...
