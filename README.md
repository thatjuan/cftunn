# cftunn

**Expose localhost on your own domain in one command.**

```bash
cftunn 3000 dev.example.com
```

`cftunn` wraps [Cloudflare Tunnel](https://www.cloudflare.com/products/tunnel/) and collapses tunnel creation, DNS routing, and ingress config into a single command. Your local server on port 3000 is now live at `https://dev.example.com`, behind Cloudflare's network.

## Why not just `cloudflared`?

Raw `cloudflared` makes you create a tunnel, manage its UUID and credentials file, write an ingress YAML, and add a CNAME by hand — every time. `cftunn` does all of that from `cftunn <port> <domain>`.

Why not `ngrok`? **Custom, durable domains.** Your URL is `dev.example.com`, not a random subdomain that changes on restart. Same hostname every run, served over Cloudflare.

- **One command** — no YAML, no UUIDs, no credentials juggling.
- **Automatic DNS** — manages the CNAME for you, confirms before overwriting.
- **Dual auth** — uses your existing `cloudflared` login *or* a `CLOUDFLARE_API_TOKEN` (CI-friendly).
- **Self-healing** — rotates credentials on existing named tunnels to guarantee a clean connect.

## Install

**Homebrew (macOS):**

```bash
brew install thatjuan/tap/cftunn
```

**curl (macOS/Linux):**

```bash
curl -fsSL https://raw.githubusercontent.com/thatjuan/cftunn/main/install.sh | bash
```

Re-run either command to update. [Install from source →](docs/ADVANCED.md#install-from-source)

## Setup

**1. Install `cloudflared`** (the daemon `cftunn` drives):

```bash
brew install cloudflared   # macOS
```

Linux: [install guide](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation).

**2. Authenticate** with Cloudflare — pick one:

- **Interactive login** (recommended):

  ```bash
  cloudflared tunnel login
  ```

  Opens a browser, writes `~/.cloudflared/cert.pem`. Done once per machine.

- **API token** (CI/CD):

  ```bash
  export CLOUDFLARE_API_TOKEN=<token>
  ```

  Token needs `Cloudflare Tunnel:Edit` (Account), `DNS:Edit` and `Zone:Read` (Zone). [How to create one →](#api-token)

You also need the domain on Cloudflare (its nameservers pointed at Cloudflare).

## Usage

```bash
cftunn 3000 dev.example.com               # expose localhost:3000
cftunn 8080 dev.example.com --host 1.2.3.4 # expose another host (VM/container)
```

What it does: finds or creates a tunnel named `cftunn-dev-example-com`, points `dev.example.com` at it (asking before overwriting an existing record), then forwards traffic to your port.

```text
Flags:
  -d, --domain string   Domain to expose (e.g. dev.example.com)
  -p, --port int        Local port to tunnel to
  -H, --host string     Target host (default: localhost)
  -y, --yes             Auto-confirm prompts (non-interactive/CI)
  -D, --debug           Verbose output for troubleshooting
  -v, --version         Print version
```

Hitting problems? Run with `--debug` for auth detection, `cloudflared` commands, and API call traces.

## API token

Skip this if you use interactive login. For API-token auth, mint a token with these scopes:

| Scope   | Permission              | Why                                |
| ------- | ----------------------- | ---------------------------------- |
| Account | `Cloudflare Tunnel:Edit` | Create/delete tunnels.            |
| Zone    | `DNS:Edit`              | Manage the CNAME.                  |
| Zone    | `Zone:Read`             | Resolve your domain's zone ID.     |

1. Open [dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens).
2. **Create Token → Create Custom Token**.
3. Add the three permissions above.
4. **Account Resources**: Include → your account. **Zone Resources**: Include → All zones (or one zone).
5. **Continue → Create Token**, copy it.
6. `export CLOUDFLARE_API_TOKEN=<token>` and verify: `cftunn auth whoami`.

> `cftunn` can also mint its own scoped token from a privileged bootstrap token — see [Advanced](docs/ADVANCED.md#mint-a-token-via-cli). The dashboard step above is unavoidable for your *first* token: Cloudflare has no zero-state token API.

## More

- [Install from source, development, contributing →](docs/ADVANCED.md)
- License: [MIT](LICENSE)

> Community project, not affiliated with Cloudflare. Use at your own risk.
