# cftunn

> **Zero-config Cloudflare Tunnels for Developers.**  
> Expose localhost to the world in seconds with a custom domain.

`cftunn` is a lightweight CLI tool that automates the creation of [Cloudflare Tunnels](https://www.cloudflare.com/products/tunnel/). It abstracts away the complexity of creating tunnels, routing DNS, and configuring ingress rules into a single command.

Designed for developers who want the ease of `ngrok` but with their own custom domains and the security/performance of Cloudflare.

## ✨ Features

*   **One-Command Setup**: No YAML configs, no UUID management. Just `cftunn <port> <domain>`.
*   **Automatic DNS**: Automatically manages CNAME records for your domain.
*   **Smart Auth**: seamlessly integrates with your existing `cloudflared` login or API tokens.
*   **Self-Healing**: Automatically cleans up or rotates credentials for existing named tunnels to ensure a successful connection.
*   **Safe**: Prompts for confirmation before overwriting existing DNS records.
*   **Cross-Platform**: Works on macOS and Linux.

## 🚀 Installation

### Homebrew (Recommended)

```bash
brew install thatjuan/tap/cftunn
```

### Automatic

Install the latest binary for your OS/Arch:

```bash
curl -fsSL https://raw.githubusercontent.com/thatjuan/cftunn/main/install.sh | bash
```

### From Source

You need [Go](https://go.dev/doc/install) 1.20+ installed.

```bash
go install github.com/thatjuan/cftunn@latest
```

Or clone the repo:

```bash
git clone https://github.com/thatjuan/cftunn.git
cd cftunn
make install
```

## 🔄 Updating

To update to the latest version, simply run the installation command again.

**Homebrew:**
```bash
brew upgrade cftunn
```

**Automatic:**
```bash
curl -fsSL https://raw.githubusercontent.com/thatjuan/cftunn/main/install.sh | bash
```

**From Source:**
```bash
go install github.com/thatjuan/cftunn@latest
```

### Prerequisites

**1. cloudflared**  
This tool relies on the official Cloudflare Tunnel daemon.
*   **macOS**: `brew install cloudflared`
*   **Linux**: [Installation Instructions](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation)

**2. Authentication**  
You need to be authenticated with Cloudflare.

*   **Method A: Interactive Login (Recommended)**  
    Run this once to authorize your machine:
    ```bash
    cloudflared tunnel login
    ```
    This will open your browser and generate a `cert.pem` file.

*   **Method B: API Token (CI/CD friendly)**  
    Set the environment variable:
    ```bash
    export CLOUDFLARE_API_TOKEN=your_api_token
    ```
    See [Creating an API Token](#-creating-an-api-token) below for the required permissions and step-by-step instructions.

## 🔑 Creating an API Token

`cftunn` needs an API token with these permissions:

| Scope    | Permission              | Why                                                 |
| -------- | ----------------------- | --------------------------------------------------- |
| Account  | `Cloudflare Tunnel:Edit` | Create/delete tunnels and read account info.        |
| Zone     | `DNS:Edit`              | Create/update the CNAME pointing to your tunnel.    |
| Zone     | `Zone:Read`             | Look up the zone ID for your domain.                |

### Option 1: Cloudflare Dashboard (Recommended)

1.  Open [https://dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens).
2.  Click **Create Token** → **Create Custom Token** → **Get started**.
3.  Set **Token name** (e.g. `cftunn`).
4.  Under **Permissions**, add the three rows above.
5.  Under **Account Resources**, select **Include → \<your account\>**.
6.  Under **Zone Resources**, select **Include → All zones** (or pin to a specific zone).
7.  Click **Continue to summary** → **Create Token**.
8.  Copy the token and export it:
    ```bash
    export CLOUDFLARE_API_TOKEN=<paste-here>
    ```
9.  Verify it works:
    ```bash
    cftunn auth whoami
    ```

### Option 2: Mint via `cftunn auth create-token` (Advanced)

If you already hold a **bootstrap token** with the `API Tokens Write` permission (created from the dashboard's *Create Additional Tokens* template), `cftunn` can mint a properly scoped token for itself:

```bash
# Export the bootstrap token first
export CLOUDFLARE_API_TOKEN=<bootstrap-token>

# Mint a cftunn-scoped token (uses first accessible account, all zones)
cftunn auth create-token

# Or pin to a specific zone and account
cftunn auth create-token --zone example.com --account <account-id> --name cftunn-prod
```

The new token's value is printed once. Export it for subsequent `cftunn` runs:

```bash
export CLOUDFLARE_API_TOKEN=<new-token>
```

> **Note:** There is no fully zero-state automation path. Cloudflare's `POST /user/tokens` requires an existing privileged token, and there is no public OAuth flow or `cloudflared` subcommand for first-time token issuance — so the dashboard step (Option 1) is unavoidable for the very first token.

References: [Create tokens via API](https://developers.cloudflare.com/fundamentals/api/how-to/create-via-api/), [Permission groups](https://developers.cloudflare.com/fundamentals/api/reference/permissions/).

## 📖 Usage

### Basic Example

Expose your local server running on port `3000` to `dev.example.com`:

```bash
cftunn 3000 dev.example.com
```

### Advanced Usage

Tunnel to a specific host (e.g., a container or VM):

```bash
cftunn 8080 dev.example.com --host 192.168.1.100
```

### What happens next?
1.  `cftunn` checks for the tunnel `cftunn-dev-example-com`.
2.  If it doesn't exist, it creates it.
3.  It checks if `dev.example.com` exists in your DNS.
4.  It routes the tunnel to that hostname (prompting if it needs to overwrite).
5.  It starts the tunnel, forwarding traffic to `localhost:3000`.

### Flags

```text
Usage:
  cftunn [PORT] [DOMAIN] [flags]

Flags:
  -D, --debug           Enable debug output for troubleshooting
  -d, --domain string   Domain to expose (e.g. dev.example.com)
  -h, --help            help for cftunn
  -H, --host string     Target host to tunnel to (default: localhost)
  -p, --port int        Local port to tunnel to
  -v, --version         version for cftunn
```

### Troubleshooting

If you encounter issues during tunnel setup, use the `--debug` flag to get detailed output:

```bash
cftunn 3000 dev.example.com --debug
```

This will show:
- Authentication method detection (API token vs cert.pem)
- cloudflared commands being executed
- API calls and responses
- Zone and DNS record lookups
- Tunnel creation/deletion operations

## 🛠️ Development & Contributing

We welcome contributions!

### Setup

1.  Fork the repository.
2.  Clone your fork:
    ```bash
    git clone https://github.com/thatjuan/cftunn.git
    cd cftunn
    ```
3.  Install dependencies:
    ```bash
    go mod tidy
    ```

### Building

Use the included Makefile:

```bash
make build
# Output binary is ./cftunn
```

### Testing

Currently, manual testing is required due to the integration nature of the tool (requires real Cloudflare API).
*   **Mocking**: Future improvements should include interfaces for the Cloudflare API to allow unit testing.

### Reporting Bugs

Please open an issue on GitHub with:
1.  Your OS version.
2.  The command you ran.
3.  The error output (redacted of any tokens/secrets).
4.  Output of `cloudflared --version`.

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.

## Disclaimer

This is a community project and is not affiliated with Cloudflare. Use it at your own risk.
