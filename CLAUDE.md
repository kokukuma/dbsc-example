# DBSC Example Project Guidelines

## Build Commands
- `make run` - Run the DBSC server locally
- `make build` - Build server executable to bin/dbsc-server
- `make clean` - Remove build artifacts
- `make install-deps` - Install Go dependencies
- `make tunnel` - Start ngrok tunnel for remote testing
- `go test ./...` - Run all tests
- `go test ./internal/server -v` - Run server tests verbosely

## Code Style Guidelines
- **Formatting**: Use `gofmt`/`goimports` for consistent formatting
- **Naming**: PascalCase for exported, camelCase for private; capitalize acronyms (JWT, DBSC)
- **Error Handling**: Check errors immediately; log and return for handlers; no naked returns
- **Concurrency**: Use mutex (RLock/Lock) for concurrent map access
- **Documentation**: Comment all exported functions and types; add inline explanations for complex logic
- **Security**: Use HTTP-only cookies, SameSite policies, secure flags for HTTPS
- **Imports**: Group standard library, third-party, and internal imports with blank lines
- **Models**: Define clear structs with JSON struct tags; keep data models in models.go

## Project Structure
- `cmd/` - Entry points (server/client)
- `internal/` - Private implementation code
- `internal/server/` - Core server functionality with separate responsibility files

## Must read
* DBSC Spec is in ./DBSC.md
