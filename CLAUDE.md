# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
make build      # Build binary to ./cftunn
make clean      # Remove built binary
go mod tidy     # Install/update dependencies
```

## Architecture

cftunn is a CLI tool that simplifies Cloudflare Tunnel creation. It wraps `cloudflared` to provide zero-config tunnel setup with custom domains.

### Entry Point
- `main.go` → `cmd.Execute()` - Standard Cobra CLI pattern

### Core Logic (cmd/root.go)
The tool operates in two authentication modes:

1. **API Mode** (`runAPIMode`): Used when `CLOUDFLARE_API_TOKEN` env var is set
   - Uses cloudflare-go SDK to manage tunnels and DNS via API
   - Creates/recreates tunnels to rotate secrets
   - Manages CNAME records programmatically

2. **Wrapper Mode** (`runWrapperMode`): Used when `~/.cloudflared/cert.pem` exists
   - Delegates tunnel management to `cloudflared` CLI commands
   - Reuses existing tunnels when possible by fetching tokens

### Key Dependencies
- `github.com/cloudflare/cloudflare-go` - Cloudflare API client
- `github.com/spf13/cobra` - CLI framework
- `github.com/manifoldco/promptui` - Interactive prompts

### Tunnel Naming Convention
Tunnels are named `cftunn-{domain-with-dashes}` (e.g., `cftunn-dev-example-com` for `dev.example.com`).

### Debug Logging
Use `--debug` or `-D` flag to enable verbose output. Debug messages use `[DEBUG]` prefix via the `debugLog()` helper function. Add debug logging at key failure points when troubleshooting issues.
