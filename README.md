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

### Automatic (Recommended)

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
    *Required Permissions*: `Zone:DNS:Edit`, `Account:Cloudflare Tunnel:Edit`.

## 📖 Usage

### Basic Example

Expose your local server running on port `3000` to `dev.example.com`:

```bash
cftunn 3000 dev.example.com
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
  -h, --help     help for cftunn
```

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
