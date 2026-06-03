# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
make build      # Build binary to ./cftunn
make clean      # Remove built binary
go mod tidy     # Install/update dependencies
```

## Releasing (do this on every change merged to `main`)

Releases are **run locally** with GoReleaser (no CI). On a `vX.Y.Z` tag, `make release`
builds binaries, publishes a GitHub Release, and updates the Homebrew formula in
`thatjuan/homebrew-tap`. The version is injected at build time via ldflags from the tag —
no version constant to edit.

Prereqs: `goreleaser` installed (`brew install goreleaser`) and `gh` authenticated
(`gh auth status`). The Makefile passes `gh auth token` as `GITHUB_TOKEN`, which has write
access to both `cftunn` and `homebrew-tap`, so no PAT is needed.

**After committing changes to `main`, cut a new release:**

1. Pick the next [SemVer](https://semver.org/) version based on what changed:
   - `patch` (`v0.5.0` → `v0.5.1`) — bug fixes, internal changes
   - `minor` (`v0.5.0` → `v0.6.0`) — new flags/commands/features, backward-compatible
   - `major` (`v0.5.0` → `v1.0.0`) — breaking changes to CLI behavior/flags
2. Confirm `main` is pushed and the build passes: `make build`.
   Optionally dry-run the full release pipeline: `make release-check`.
3. Create and push the tag (check latest first: `git tag | sort -V | tail -1`):
   ```bash
   git tag -a vX.Y.Z -m "vX.Y.Z: <short summary>"
   git push origin vX.Y.Z
   ```
4. Run the release:
   ```bash
   make release
   ```
5. Verify: GitHub Release exists, and `Formula/cftunn.rb` was updated in
   `thatjuan/homebrew-tap`.

Never reuse or move an existing tag. If a release fails, fix forward with a new patch tag.

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
