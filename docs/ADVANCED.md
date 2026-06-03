# Advanced

Back to the [README](../README.md).

## Install from source

Requires [Go](https://go.dev/doc/install) 1.20+.

```bash
go install github.com/thatjuan/cftunn@latest
```

Or clone and build:

```bash
git clone https://github.com/thatjuan/cftunn.git
cd cftunn
make build      # → ./cftunn
```

## Mint a token via CLI

If you already hold a **bootstrap token** with `API Tokens Write` (from the dashboard's *Create Additional Tokens* template), `cftunn` can mint its own correctly-scoped token:

```bash
export CLOUDFLARE_API_TOKEN=<bootstrap-token>

cftunn auth create-token                                            # first account, all zones
cftunn auth create-token --zone example.com --account <id> --name cftunn-prod
```

The new token prints once. Export it for subsequent runs:

```bash
export CLOUDFLARE_API_TOKEN=<new-token>
```

There is no fully zero-state path: Cloudflare's `POST /user/tokens` requires an existing privileged token, and there's no public OAuth flow or `cloudflared` subcommand for first-time issuance. The dashboard step in the [README](../README.md#api-token) is required for the very first token.

Refs: [Create tokens via API](https://developers.cloudflare.com/fundamentals/api/how-to/create-via-api/), [Permission groups](https://developers.cloudflare.com/fundamentals/api/reference/permissions/).

## Development

```bash
git clone https://github.com/thatjuan/cftunn.git
cd cftunn
go mod tidy
make build
```

Testing is currently manual — the tool hits the real Cloudflare API. Adding interfaces around the API client to enable unit tests is a welcome contribution.

## Contributing

PRs welcome. Open an issue first for anything substantial.

Bug reports should include:

1. OS version.
2. The command you ran.
3. Error output (redact tokens/secrets).
4. `cloudflared --version`.
