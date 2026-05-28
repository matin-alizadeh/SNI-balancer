# xray-balancer

Automatically tests a list of Xray proxy configs by download speed and keeps the fastest one running as a local SOCKS5 proxy — accessible to any device on your LAN.

No dependency on v2rayN or any other GUI client.

## How it works

1. Reads configs from `configs.txt` (one URI per line, or subscription URLs)
2. Spins up a temporary Xray instance per config on a private port
3. Downloads a test file through each one and measures MB/s
4. Launches a persistent Xray instance with the fastest config on a SOCKS5 port
5. Re-tests on a configurable interval and switches if a faster config is found

## Requirements

- Python 3.8+
- `curl` (pre-installed on macOS)
- Xray binary (see setup below)

## Setup

**1. Clone the repo**
```bash
git clone https://github.com/yourname/xray-balancer.git
cd xray-balancer
```

**2. Install Python dependencies**
```bash
pip3 install -r requirements.txt
```

**3. Add the Xray binary**

Download the Xray binary for your platform from [XTLS/Xray-core releases](https://github.com/XTLS/Xray-core/releases) and place it in the project folder:

```bash
# macOS example
cp /path/to/xray ./xray
chmod +x ./xray
```

**4. Create `configs.txt`**

Add your proxy URIs, one per line. Supports `vless://` and `trojan://` URIs, and subscription URLs (plain or base64-encoded):

```
vless://uuid@host:port?...#name
trojan://password@host:port?...#name
https://your-subscription-url.com/sub
```

Empty lines are ignored. Any address/port in the URI is automatically normalized to `127.0.0.1:40443` in the generated Xray config.

## Usage

**Test all configs without launching Xray:**
```bash
python3 balancer.py --dry-run
```

**Run normally (test, launch best, re-test every 10 minutes):**
```bash
python3 balancer.py
```

**Custom interval (e.g. every 5 minutes):**
```bash
python3 balancer.py --interval 300
```

**Custom SOCKS port:**
```bash
python3 balancer.py --port 1080
```

**Custom configs file:**
```bash
python3 balancer.py --configs /path/to/myconfigs.txt
```

## Connecting other devices

Once running, point any device on your LAN to:

```
SOCKS5  <mac-ip>:10808
```

To find your Mac's LAN IP:
```bash
ipconfig getifaddr en0
```

## Configuration

All tuneable constants are at the top of `balancer.py`:

| Constant | Default | Description |
|---|---|---|
| `SOCKS_PORT` | `10808` | SOCKS5 proxy port |
| `SOCKS_LISTEN` | `0.0.0.0` | Listen address (`0.0.0.0` = all interfaces) |
| `SNI_PORT` | `40443` | Upstream proxy port |
| `TEST_URL` | cachefly 10MB | URL used for speed testing |
| `TEST_TIMEOUT` | `15` | Max seconds per speed test |
| `CHECK_INTERVAL` | `600` | Seconds between re-tests |
| `BASE_TEST_PORT` | `19000` | Starting port for temporary test instances |

## Supported protocols

- `vless` over WebSocket or XHTTP with TLS
- `trojan` over WebSocket or XHTTP with TLS

## Notes

- `xray`, `xrayconfig.json`, and `configs.txt` are in `.gitignore` — never commit your configs or binary
- The script manages its own Xray process independently of v2rayN or any other client
- Press `CTRL+C` to stop cleanly
