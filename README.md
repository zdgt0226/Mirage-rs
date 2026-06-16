# Mirage-rs

High-performance proxy engine.

## Installation

### For Regular Users (Pre-compiled Binaries)
The easiest way to install Mirage-rs is to use our pre-compiled binaries built via GitHub Actions.
You can run our automated installation script:

```bash
sudo bash install.sh
```

The script will automatically set up the FHS standard directories, create `systemd` services, and configure the engine as either a `client` or `server`.

### Commands
Once installed, Mirage-rs acts as a unified single-file binary with specific mode commands:

- Run as Client: `mirage client -c config_client.json`
- Run as Server: `mirage server -c config_server.json`

---

## For Developers (Compile from Source)

If you want to compile Mirage-rs from source, follow these steps.

### Prerequisites

1. **Install Rust & Cargo**:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source $HOME/.cargo/env
   ```

2. **Install Build Dependencies**:
   ```bash
   # Debian/Ubuntu
   sudo apt-get install -y build-essential pkg-config libssl-dev gcc-aarch64-linux-gnu
   ```

### Building

To compile the release binary:

```bash
cargo build --release
```

The compiled binary will be located at `target/release/mirage`.

### Cross-Compilation

We use `cross` and `musl` toolchains to cross-compile standalone static binaries for different architectures:

1. Install `cross`:
   ```bash
   cargo install cross
   ```
2. Build for `x86_64`:
   ```bash
   cross build --target x86_64-unknown-linux-musl --release
   ```
3. Build for `aarch64` (ARM64):
   ```bash
   cross build --target aarch64-unknown-linux-musl --release
   ```

## Configuration
Check `config.json` for all available fields.

### Web Dashboard (GUI)

- **Default Listen Address**: `127.0.0.1:9090`
- **API Security**: No bearer-token authentication is included. Security against CSRF relies on strict `X-Requested-With: XMLHttpRequest` header requirements for all mutating endpoints. Standard web browsers cannot spoof this header without CORS preflight. Missing `Origin` headers are strictly rejected unless the request is explicitly identified as coming from local CLI tools (e.g. `curl`).
- **WARNING**: If you intend to expose the dashboard to a LAN or the public internet, you **MUST** configure a reverse proxy (like Nginx or Caddy) with proper authentication. Otherwise, your proxy node will be vulnerable to unauthorized control, as anyone with access to the port can send valid AJAX requests.

### Telemetry (Traffic Monitoring)
Note on mixed client-server nodes (where the node acts both as a pyreality inbound server and a pyreality outbound client): traffic metrics (`GLOBAL_UP` and `GLOBAL_DOWN`) are tracked independently at the connection boundary. A connection relayed through such a mixed node will be counted twice (once when received as a server, once when sent as a client). This is intentional and accurately reflects the local socket byte usage.

## Brutal Congestion Control (Optional)

To enable Hysteria2-style Brutal CC for max throughput:

1. Install the kernel module:
   ```bash
   git clone https://github.com/apernet/tcp-brutal
   cd tcp-brutal && make && sudo make install
   sudo modprobe tcp_brutal
   ```

2. (Linux 6.4+) Verify no `TCP_FASTOPEN` conflict in your kernel — kernel ≤ 6.3 confirmed working.

3. Set the target rate in config:
   ```json
   "outbounds": [{
       "type": "pyreality",
       // ...
       "brutal_rate_bps": 8000000
   }]
   ```

If the module is not installed, mirage-rs falls back to default CC (cubic/bbr) with a warning logged once.
