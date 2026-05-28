import subprocess
import time
import json
import os
import sys
import signal
import atexit
import tempfile
import argparse
import urllib.parse

import requests
from colorama import Fore, Style, init

init(autoreset=True)

_xray_name   = "xray.exe" if sys.platform == "win32" else "xray"
XRAY         = os.path.join(os.path.dirname(os.path.abspath(__file__)), _xray_name)
CONFIGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "configs.txt")
XRAY_CONFIG  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "xrayconfig.json")

SOCKS_PORT     = 4567
SOCKS_LISTEN   = "0.0.0.0"
SNI_PORT       = 40443
BASE_TEST_PORT = 19000
TEST_URL       = "https://cachefly.cachefly.net/1mb.test"
TEST_TIMEOUT   = 15
CHECK_INTERVAL = 30 * 60


# ── Cleanup: always kill Xray on exit ─────────────────────────────────────────

_active_proc = None

def _set_active_proc(proc):
    global _active_proc
    _active_proc = proc

def _cleanup():
    if _active_proc and _active_proc.poll() is None:
        print(Fore.YELLOW + "\nStopping Xray...")
        _active_proc.terminate()
        try:
            _active_proc.wait(timeout=3)
        except Exception:
            _active_proc.kill()
        print(Fore.GREEN + "Xray stopped.")

atexit.register(_cleanup)

if sys.platform != "win32":
    def _sigterm_handler(signum, frame):
        sys.exit(0)
    signal.signal(signal.SIGTERM, _sigterm_handler)


# ── Parsers ────────────────────────────────────────────────────────────────────

def _build_stream(params):
    network = params.get("type", "tcp")
    security = params.get("security", "none")

    sni = params.get("sni", "")
    fp = params.get("fp", "")
    pbk = params.get("pbk", "")
    sid = params.get("sid", "")
    flow = params.get("flow", "")
    host = params.get("host", "")
    path = urllib.parse.unquote(params.get("path", "/"))
    service_name = params.get("serviceName", "")
    authority = params.get("authority", "")
    mode = params.get("mode", "auto")

    alpn_raw = params.get("alpn", "")
    alpn = alpn_raw.split(",") if alpn_raw else []

    allow_insecure = params.get("insecure", "0") == "1"

    stream = {
        "network": network,
        "security": security
    }

    if security == "tls":
        tls_settings = {
            "serverName": sni,
            "allowInsecure": allow_insecure
        }

        if fp:
            tls_settings["fingerprint"] = fp

        if alpn:
            tls_settings["alpn"] = alpn

        stream["tlsSettings"] = tls_settings

    elif security == "reality":
        reality_settings = {
            "serverName": sni,
            "fingerprint": fp or "chrome",
            "publicKey": pbk,
            "shortId": sid
        }

        stream["realitySettings"] = reality_settings

    if network == "ws":
        stream["wsSettings"] = {
            "path": path,
            "headers": {
                "Host": host
            }
        }

    elif network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": service_name,
            "authority": authority,
            "multiMode": False
        }

    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {
            "path": path,
            "host": host
        }

    elif network == "xhttp":
        stream["xhttpSettings"] = {
            "path": path,
            "host": host,
            "mode": mode,
            "extra": {
                "xPaddingBytes": "100-1000",
                "scMaxEachPostBytes": "1000000"
            }
        }

    elif network == "splithttp":
        stream["splithttpSettings"] = {
            "path": path,
            "host": host
        }

    if flow:
        if "vnext" in params:
            params["vnext"]["users"][0]["flow"] = flow

    return stream


def parse_vless(uri, name):
    parsed = urllib.parse.urlparse(uri)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    return {
        "name": name,
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": "127.0.0.1",
                "port": SNI_PORT,
                "users": [{"id": parsed.username, "encryption": "none", "level": 0}]
            }]
        },
        "streamSettings": _build_stream(params)
    }


def parse_trojan(uri, name):
    parsed = urllib.parse.urlparse(uri)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    return {
        "name": name,
        "protocol": "trojan",
        "settings": {
            "servers": [{
                "address": "127.0.0.1",
                "port": SNI_PORT,
                "password": urllib.parse.unquote(parsed.username),
                "level": 1
            }]
        },
        "streamSettings": _build_stream(params)
    }


def parse_uri(uri):
    uri = uri.strip()
    fragment = ""
    if "#" in uri:
        uri, fragment = uri.rsplit("#", 1)
    name = urllib.parse.unquote(fragment) if fragment else uri[:40]

    if uri.startswith("vless://"):
        return parse_vless(uri, name)
    if uri.startswith("trojan://"):
        return parse_trojan(uri, name)
    return None


# ── Config loading ─────────────────────────────────────────────────────────────

def fetch_subscription(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        content = response.text.strip()

        if "vless://" not in content and "trojan://" not in content:
            try:
                import base64
                padding = len(content) % 4
                if padding:
                    content += "=" * (4 - padding)
                content = base64.b64decode(content).decode("utf-8")
            except Exception:
                pass

        return [line.strip() for line in content.splitlines() if line.strip()]
    except Exception as e:
        print(Fore.RED + f"Failed to fetch subscription {url}: {e}")
        return []


def load_configs(path):
    if not os.path.exists(path):
        print(Fore.RED + f"Error: configs file not found at {path}")
        sys.exit(1)

    servers = []
    skipped = 0

    with open(path, "r") as f:
        lines = [line.strip() for line in f if line.strip()]

    for line in lines:
        if line.startswith("http://") or line.startswith("https://"):
            print(Fore.CYAN + f"Fetching subscription: {line}")
            sub_lines = fetch_subscription(line)
            for sub_line in sub_lines:
                server = parse_uri(sub_line)
                if server:
                    servers.append(server)
                else:
                    skipped += 1
        else:
            server = parse_uri(line)
            if server:
                servers.append(server)
            else:
                skipped += 1

    if skipped:
        print(Fore.YELLOW + f"Warning: {skipped} line(s) skipped (unsupported protocol)")
    if not servers:
        print(Fore.RED + "Error: no valid configs found")
        sys.exit(1)

    print(Fore.GREEN + f"Loaded {len(servers)} configs\n")
    time.sleep(2)
    return servers


# ── Xray process management ────────────────────────────────────────────────────

def build_xray_config(server):
    return {
        "log": {
            "loglevel": "warning"
        },

        "dns": {
            "servers": [
                {
                    "address": "https://1.1.1.1/dns-query",
                    "skipFallback": False
                },
                {
                    "address": "8.8.8.8",
                    "skipFallback": False
                }
            ]
        },

        "inbounds": [
            {
                "tag": "socks",
                "port": SOCKS_PORT,
                "listen": SOCKS_LISTEN,
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": True
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": [
                        "http",
                        "tls",
                        "quic"
                    ]
                }
            }
        ],

        "outbounds": [
            {
                "tag": "proxy",
                "protocol": server["protocol"],
                "settings": server["settings"],
                "streamSettings": server["streamSettings"],
                "mux": {
                    "enabled": False,
                    "concurrency": -1
                }
            },

            {
                "tag": "direct",
                "protocol": "freedom"
            },

            {
                "tag": "block",
                "protocol": "blackhole"
            }
        ],

        "routing": {
            "domainStrategy": "IPIfNonMatch",

            "rules": [

                {
                    "type": "field",
                    "ip": [
                        "127.0.0.0/8",
                        "10.0.0.0/8",
                        "172.16.0.0/12",
                        "192.168.0.0/16",
                        "::1/128",
                        "fc00::/7"
                    ],
                    "outboundTag": "direct"
                },

                {
                    "type": "field",
                    "network": "udp",
                    "port": "443",
                    "outboundTag": "block"
                }
            ]
        }
    }


def build_test_config(server, port):
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "tag": "socks",
            "port": port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False}
        }],
        "outbounds": [{
            "tag": "proxy",
            "protocol": server["protocol"],
            "settings": server["settings"],
            "streamSettings": server["streamSettings"],
            "mux": {"enabled": False, "concurrency": -1}
        }]
    }


def launch_xray(server, current_proc):
    if current_proc and current_proc.poll() is None:
        current_proc.terminate()
        try:
            current_proc.wait(timeout=3)
        except Exception:
            current_proc.kill()
        time.sleep(1)

    if server:
        config = build_xray_config(server)
        with open(XRAY_CONFIG, "w") as f:
            json.dump(config, f, indent=2)

    proc = subprocess.Popen(
        [XRAY, "run", "-c", XRAY_CONFIG],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    _set_active_proc(proc)
    print(Fore.GREEN + f"Xray launched — PID {proc.pid} — SOCKS on {SOCKS_LISTEN}:{SOCKS_PORT}")
    return proc


# ── Speed testing ──────────────────────────────────────────────────────────────

def measure_speed(port):
    try:
        result = subprocess.run(
            ["curl", "-s", "-o", "/dev/null",
             "-w", "%{speed_download}",
             "--proxy", f"socks5h://127.0.0.1:{port}",
             "--connect-timeout", "5",
             "--max-time", str(TEST_TIMEOUT),
             TEST_URL],
            capture_output=True, text=True, timeout=TEST_TIMEOUT + 3
        )
        return float(result.stdout.strip()) / 1024 / 1024
    except Exception:
        return 0.0


def test_server(server, port):
    cfg = build_test_config(server, port)
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    json.dump(cfg, tmp)
    tmp.close()

    proc = subprocess.Popen(
        [XRAY, "run", "-c", tmp.name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(1.5)
    speed = measure_speed(port)
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except Exception:
        proc.kill()
    os.unlink(tmp.name)
    return speed


def run_tests(servers):
    results = []
    for i, server in enumerate(servers):
        port = BASE_TEST_PORT + i
        print(f"  Testing {server['name']}...", end=" ", flush=True)
        speed = test_server(server, port)
        if speed == 0:
            print(Fore.RED + "failed")
        else:
            print(Fore.YELLOW + f"{speed:.2f} MB/s")
        results.append((server, speed))
    results.sort(key=lambda x: x[1], reverse=True)
    return results


def print_results(ranked):
    print(Fore.YELLOW + "\n--- Results ---")
    for i, (s, spd) in enumerate(ranked):
        if spd > 0:
            marker = Fore.GREEN + " ✓ BEST" + Style.RESET_ALL if i == 0 else ""
            print(f"  {i+1}. {s['name']}: {spd:.2f} MB/s{marker}")
        # else:
        #     print(Fore.RED + f"  {i+1}. {s['name']}: failed")


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Xray speed-based proxy balancer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python3 balancer.py --dry-run\n"
            "  python3 balancer.py --interval 300\n"
            "  python3 balancer.py --configs /path/to/configs.txt\n"
            "  python3 balancer.py --port 1080"
        )
    )
    parser.add_argument("--dry-run",  action="store_true", help="Test configs and print results, do not launch Xray")
    parser.add_argument("--interval", type=int, default=CHECK_INTERVAL, help=f"Seconds between re-tests (default: {CHECK_INTERVAL})")
    parser.add_argument("--configs",  type=str, default=CONFIGS_FILE,   help="Path to configs.txt")
    parser.add_argument("--port",     type=int, default=SOCKS_PORT,     help=f"SOCKS proxy port (default: {SOCKS_PORT})")
    args = parser.parse_args()

    SOCKS_PORT = args.port
    servers    = load_configs(args.configs)
    proc       = None

    if args.dry_run:
        print(Fore.YELLOW + "=== DRY RUN — Xray will not be launched ===\n")
        ranked = run_tests(servers)
        print_results(ranked)
    else:
        try:
            current_best = None
            if os.path.exists(XRAY_CONFIG) and os.path.getsize(XRAY_CONFIG) > 0:
                    print(Fore.GREEN + f"Xray config exists, starting xray---> ")
                    proc = launch_xray(None, proc)
            else:
                print(Fore.YELLOW + "Xray config missing, will start xray after running test--->")

            while True:
                print(Fore.YELLOW + "\n---------- Speed Test ----------")
                ranked = run_tests(servers)
                print_results(ranked)

                best_server, best_speed = ranked[0]

                if best_speed > 0 and best_server["name"] != current_best:
                    print(Fore.GREEN + f"\nSwitching to {best_server['name']}...")
                    proc = launch_xray(best_server, proc)
                    current_best = best_server["name"]
                elif best_server["name"] == current_best:
                    print(Fore.YELLOW + f"\nKeeping current best: {current_best}")
                else:
                    print(Fore.RED + "\nAll configs failed, keeping current config.")

                print(Fore.YELLOW + f"\nNext check in {args.interval // 60}m {args.interval % 60}s...")
                time.sleep(args.interval)

        except KeyboardInterrupt:
            print(Fore.RED + "\n\nCTRL+C detected.")
            sys.exit(0)
