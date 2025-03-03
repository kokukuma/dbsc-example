# DBSC Example Makefile

.PHONY: all
all: run

.PHONY: run
run:
	go run cmd/server/server.go

.PHONY: build
build:
	go build -o bin/dbsc-server cmd/server/server.go

.PHONY: clean
clean:
	rm -rf bin

.PHONY: install-deps
install-deps:
	go mod download

.PHONY: tunnel
tunnel:
	@command -v ngrok >/dev/null 2>&1 || { echo >&2 "ngrok is not installed. Aborting."; exit 1; }
	ngrok http 8080

.PHONY: help
help:
	@echo "DBSC Example - Makefile Targets"
	@echo ""
	@echo "Available targets:"
	@echo "  make run              - Run the DBSC server"
	@echo "  make build            - Build the DBSC server executable"
	@echo "  make clean            - Remove build artifacts"
	@echo "  make install-deps     - Install Go dependencies"
	@echo "  make tunnel           - Start ngrok tunnel for remote testing (requires ngrok)"
	@echo "  make help             - Show this help message"
	@echo ""
	@echo "Access the application at http://localhost:8080"