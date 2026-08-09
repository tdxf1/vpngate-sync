#!/usr/bin/env python3
"""Fetch free OpenVPN servers from the VPN Gate API and convert them into a
mihomo (Clash Meta) `openvpn` proxy list.

Single endpoint used: http://www.vpngate.net/api/iphone/
Every request rotates User-Agent + Cookie (and a cache-busting query string)
to avoid hitting a cached/identical response, since VPN Gate returns a
randomized subset of its server pool per request.

No third-party dependencies (stdlib only) so it runs on a bare
ubuntu-latest + actions/setup-python runner with no pip install step.
"""

from __future__ import annotations

import base64
import concurrent.futures
import os
import random
import re
import shutil
import string
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

BASE_URL = "http://www.vpngate.net/api/iphone/"

# Matches the rotation set used by vpngate-meridian's randomizer.go
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
]

TOTAL_REQUESTS = int(os.environ.get("TOTAL_REQUESTS", "60"))
WORKER_COUNT = int(os.environ.get("WORKER_COUNT", "10"))
REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "20"))
OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", "."))
OVPN_DIR = OUTPUT_DIR / "ovpn"
MIHOMO_OUTPUT = OUTPUT_DIR / "mihomo_openvpn.yaml"
MIHOMO_KR_OUTPUT = OUTPUT_DIR / "mihomo_openvpn_kr.yaml"


# --------------------------------------------------------------------------
# Request building — random headers per call
# --------------------------------------------------------------------------

def random_string(n: int) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def random_cookie() -> str:
    return f"vid={random_string(12)}; sessionId={random_string(16)}; visited=true"


def build_headers() -> dict:
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Cookie": random_cookie(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
    }


def fetch_once() -> str | None:
    params = {
        "t": str(int(time.time() * 1000)),
        "nonce": random_string(10),
        "r": f"{random.random():.6f}",
    }
    url = f"{BASE_URL}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers=build_headers())
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001 - skip a bad request, don't kill the run
        print(f"  fetch failed: {exc}", file=sys.stderr)
        return None


# --------------------------------------------------------------------------
# CSV parsing (VPN Gate's iphone API is a raw CSV dump)
# --------------------------------------------------------------------------

def parse_csv(text: str) -> list[dict]:
    servers = []
    for line in text.splitlines():
        if not line or line.startswith("*") or line.startswith("#"):
            continue
        fields = line.split(",")
        if len(fields) < 15:
            continue
        # Base64 config is always the last field; using [-1]/[0]/[1]/[5]/[6]
        # keeps this safe even if a stray comma ever shows up in a middle
        # field (e.g. the free-text "Message" column).
        b64 = fields[-1].strip()
        if not b64:
            continue
        servers.append(
            {
                "hostname": fields[0].strip(),
                "ip": fields[1].strip(),
                "country_long": fields[5].strip(),
                "country_short": fields[6].strip(),
                "config_b64": b64,
            }
        )
    return servers


def fetch_all() -> list[dict]:
    print(f"Fetching {TOTAL_REQUESTS} requests with {WORKER_COUNT} workers...")
    all_servers: list[dict] = []
    ok = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKER_COUNT) as pool:
        futures = [pool.submit(fetch_once) for _ in range(TOTAL_REQUESTS)]
        for i, fut in enumerate(concurrent.futures.as_completed(futures), 1):
            text = fut.result()
            if text:
                ok += 1
                all_servers.extend(parse_csv(text))
            print(f"\r  {i}/{TOTAL_REQUESTS} requests done ({ok} ok)", end="", file=sys.stderr)
    print(file=sys.stderr)
    return all_servers


def dedupe(servers: list[dict]) -> list[dict]:
    seen: dict[str, dict] = {}
    for s in servers:
        key = s["hostname"] or s["ip"]
        if key and key not in seen:
            seen[key] = s
    return list(seen.values())


def is_korea(server: dict) -> bool:
    short = server["country_short"].strip().upper()
    long_ = server["country_long"].strip().lower()
    return short == "KR" or "korea" in long_


# --------------------------------------------------------------------------
# .ovpn parsing -> mihomo `openvpn` proxy fields
# --------------------------------------------------------------------------

def extract_block(config_text: str, tag: str) -> str:
    m = re.search(rf"<{tag}>\s*\r?\n(.*?)\r?\n\s*</{tag}>", config_text, re.DOTALL)
    return m.group(1).strip() if m else ""


def parse_ovpn(config_text: str) -> dict:
    info = {
        "host": "", "port": 1194, "proto": "udp", "cipher": "", "auth": "",
        "key_direction": "",
    }
    for line in config_text.splitlines():
        line = line.strip()
        if line.startswith("remote "):
            parts = line.split()
            if len(parts) >= 2:
                info["host"] = parts[1]
            if len(parts) >= 3 and parts[2].isdigit():
                info["port"] = int(parts[2])
        elif line.startswith("proto "):
            proto = line.split(None, 1)[1].strip().lower()
            info["proto"] = "tcp" if proto.startswith("tcp") else "udp"
        elif line.startswith("cipher "):
            info["cipher"] = line.split(None, 1)[1].strip()
        elif line.startswith("auth "):
            info["auth"] = line.split(None, 1)[1].strip()
        elif line.startswith("key-direction"):
            parts = line.split()
            if len(parts) >= 2:
                info["key_direction"] = parts[1].strip()

    info["ca"] = extract_block(config_text, "ca")
    info["cert"] = extract_block(config_text, "cert")
    info["key"] = extract_block(config_text, "key")
    info["tls_auth"] = extract_block(config_text, "tls-auth")
    info["tls_crypt"] = extract_block(config_text, "tls-crypt")
    return info


def yaml_block(field: str, text: str, indent: str = "    ") -> str:
    out = [f"{indent}{field}: |-\n"]
    for line in text.splitlines():
        out.append(f"{indent}  {line}\n")
    return "".join(out)


def safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)


def render_proxy_entry(s: dict, info: dict) -> str:
    country = s["country_short"] or "XX"
    name = f"{country} {s['hostname'] or s['ip']}"

    parts = [
        f'  - name: "{name}"\n',
        "    type: openvpn\n",
        f'    server: "{info["host"]}"\n',
        f'    port: {info["port"]}\n',
        f'    proto: {info["proto"]}\n',
        f'    udp: {"true" if info["proto"] == "udp" else "false"}\n',
    ]
    if info["cipher"]:
        parts.append(f'    cipher: {info["cipher"]}\n')
    if info["auth"]:
        parts.append(f'    auth: {info["auth"]}\n')
    parts.append(yaml_block("ca", info["ca"]))
    if info["cert"]:
        parts.append(yaml_block("cert", info["cert"]))
    if info["key"]:
        parts.append(yaml_block("key", info["key"]))
    # tls-crypt and tls-auth are mutually exclusive in mihomo; VPN Gate
    # configs typically ship tls-auth, so prefer tls-crypt only if present.
    if info["tls_crypt"]:
        parts.append(yaml_block("tls-crypt", info["tls_crypt"]))
    elif info["tls_auth"]:
        parts.append(yaml_block("tls-auth", info["tls_auth"]))
        if info["key_direction"]:
            parts.append(f'    key-direction: "{info["key_direction"]}"\n')
    return "".join(parts)


def write_mihomo_yaml(entries: list[tuple[dict, dict]], path: Path) -> int:
    """Write a mihomo `proxies:` yaml file for the given (server, info) pairs.

    Writes `proxies: []` when there are no entries, since a bare `proxies:`
    key with nothing under it parses as YAML null, not an empty list, and
    mihomo expects a list.
    """
    if not entries:
        path.write_text("proxies: []\n", encoding="utf-8")
        return 0

    yaml_parts = ["proxies:\n"]
    for s, info in entries:
        yaml_parts.append(render_proxy_entry(s, info))
    path.write_text("".join(yaml_parts), encoding="utf-8")
    return len(entries)


def build_outputs(servers: list[dict]) -> None:
    if OVPN_DIR.exists():
        shutil.rmtree(OVPN_DIR)
    OVPN_DIR.mkdir(parents=True, exist_ok=True)

    usable: list[tuple[dict, dict]] = []

    for s in servers:
        try:
            raw = base64.b64decode(s["config_b64"])
        except Exception:
            continue
        config_text = raw.decode("utf-8", errors="replace")

        fname = safe_name(s["hostname"] or s["ip"]) + ".ovpn"
        (OVPN_DIR / fname).write_text(config_text, encoding="utf-8")

        info = parse_ovpn(config_text)
        # mihomo requires server + ca at minimum; skip anything unusable.
        if not info["host"] or not info["ca"]:
            continue

        usable.append((s, info))

    all_written = write_mihomo_yaml(usable, MIHOMO_OUTPUT)
    kr_entries = [(s, info) for s, info in usable if is_korea(s)]
    kr_written = write_mihomo_yaml(kr_entries, MIHOMO_KR_OUTPUT)

    ovpn_count = len(list(OVPN_DIR.glob("*.ovpn")))
    print(f"Wrote {all_written} proxies to {MIHOMO_OUTPUT} "
          f"({len(servers)} unique servers, {ovpn_count} .ovpn files)")
    print(f"Wrote {kr_written} Korea-only proxies to {MIHOMO_KR_OUTPUT}")


def main() -> None:
    raw = fetch_all()
    print(f"Parsed {len(raw)} server rows from all responses")
    unique = dedupe(raw)
    print(f"{len(unique)} unique servers after hostname/IP dedupe")
    if not unique:
        print("No servers found in any response, aborting without touching "
              "output files.", file=sys.stderr)
        sys.exit(1)
    build_outputs(unique)


if __name__ == "__main__":
    main()
