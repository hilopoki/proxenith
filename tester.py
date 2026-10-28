#!/usr/bin/env python3
"""Xray subscription tester + chained load-balancer service.

Reads subscription URLs from a YAML config, fetches + decodes each into share
links (vmess/vless/trojan/ss), builds ONE xray config with a dedicated socks
inbound per link, runs xray, probes each tunnel CONCURRENTLY (ThreadPool), and
writes the list of working links to results dir.

Additionally generates `chained-config.json`: all working links as a balancer
(balancer field, round-robin), chained via a `dialerProxy`-style relay to a
user-provided second xray config (e.g. their own paid server), served on a
local mixed (http+socks) inbound port.

Usage: tester.py [config.yaml]   (default: config.yaml next to this script)
"""
import asyncio
import base64
import copy
import json
from collections import Counter
import re
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
BASE_PORT = 11001
PROBE_URLS = (
    "https://www.apple.com/library/test/success.html",
)
OK_CODES = {"200", "204", "403"}  # any real HTTP answer = conclusive


def load_cfg(path: Path) -> dict:
    cfg = yaml.safe_load(path.read_text()) or {}
    cfg.setdefault("subscriptions", [])
    cfg.setdefault("min_code", "200")
    cfg.setdefault("probe_timeout", 8)
    cfg.setdefault("retries", 1)
    cfg.setdefault("concurrency", 64)  # probes run in parallel; one thread per (link, url)
    # chained load-balancer service
    cfg.setdefault("listen_port", 10888)   # local mixed (http+socks) inbound
    cfg.setdefault("upstream_config", "")  # path to the manual second xray config
    cfg.setdefault("upstream_tag", "up")   # tag used for its outbound inside chained config
    return cfg


NO_PROXY_ENV = {k: v for k, v in __import__("os").environ.items()
                if "proxy" not in k.lower() and "PROXY" not in k}
"""Proxy env vars (http_proxy/https_proxy/all_proxy/ALL_PROXY/no_proxy, both
cases) must be IGNORED for everything this tool does: fetching subscriptions
and probing tunnels must go straight through the network interface."""


def fetch_sub(url: str) -> str:
    # curl (not urllib) + scrubbed proxy env: fetching the subscription itself
    # must NOT go through any local proxy. Retries for slow first attempts.
    last_err = None
    for attempt in range(3):
        r = subprocess.run(["curl", "-sL", "--max-time", "60", "-A", "v2rayN/6.0", url],
                           capture_output=True, text=True, env=NO_PROXY_ENV)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout
        last_err = f"curl exit {r.returncode}"
        time.sleep(2)
    raise RuntimeError(last_err or "empty response")


def b64pad(s: str) -> str:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "replace")


def extract_links(raw: str) -> list[str]:
    raw = raw.strip()
    links = []
    prefixes = ("vmess://", "vless://", "trojan://", "ss://", "socks://", "socks4://",
                "socks5://", "http://", "https://")
    if raw.startswith(("http://", "https://")) or "\n" in raw:
        # plain list of links, one per line
        links = [l.strip() for l in raw.splitlines() if l.strip().startswith(prefixes)]
    if not links:
        # try whole-body base64 (standard subscription format)
        try:
            decoded = b64pad(raw)
            links = [l.strip() for l in decoded.splitlines()
                     if l.strip().startswith(prefixes)]
        except Exception:
            pass
    return links


def parse_ss_userinfo(raw: str) -> tuple[str, str] | None:
    """SIP002: method:pass, possibly base64-encoded. Returns (method, password)
    or None if it doesn't look like a valid method:password pair at all."""
    s = urllib.parse.unquote(raw)
    if ":" in s:
        m = s.split(":", 1)[0]
        if m.lower() in SS_CIPHERS:
            return s.split(":", 1)
    # try base64
    try:
        d = b64pad(raw)
        if ":" in d and d.split(":", 1)[0].lower() in SS_CIPHERS:
            return d.split(":", 1)
    except Exception:
        pass
    return None


def parse_uri(uri: str):
    """Return dict with scheme, secret, host, port, q params."""
    scheme, rest = uri.split("://", 1)
    frag = ""
    if "#" in rest:
        rest, frag = rest.split("#", 1)
    q = {}
    if "?" in rest:
        rest, qs = rest.split("?", 1)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(qs).items()}
    scheme = scheme.lower()
    if scheme == "vmess":
        j = json.loads(b64pad(rest))
        return {"scheme": scheme, "secret": j["id"], "host": j["add"], "port": int(j["port"]),
                "q": {"net": j.get("net", "tcp"), "path": j.get("path", "/"), "host": j.get("host", ""),
                      "tls": j.get("tls", ""), "sni": j.get("sni", ""), "fp": j.get("fp", ""),
                      "type": j.get("type", "none")}, "frag": j.get("fm", "")}
    # userinfo@host:port?query  (userinfo optional — plain socks links have none)
    if "@" in rest:
        userinfo, hostport = rest.rsplit("@", 1)
    else:
        userinfo, hostport = "", rest
    host, port = hostport.rsplit(":", 1)
    return {"scheme": scheme, "secret": urllib.parse.unquote(userinfo),
            "host": host, "port": int(port), "q": q, "frag": q.get("fm", "")}


SS_CIPHERS = {
    "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305",
    "xchacha20-poly1305", "xchacha20-ietf-poly1305", "none", "plain",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
}


def will_xray_reject(link: dict) -> str | None:
    """Predict xray >=26.9 rejections so we pre-drop instead of a slow -test loop.

    xray refuses vless/trojan without TLS (or vless encryption) to public
    addresses, and ss with unknown ciphers. No env var bypass exists (upstream
    refuses to add one), so these configs are unusable with modern xray.
    """
    s, host, q = link["scheme"], link["host"], link["q"]
    sec = q.get("security") or ("tls" if q.get("tls") in ("tls", "true", "True") else "none")
    if sec in ("tls", "reality"):
        return None
    if s == "vless" and (q.get("encryption", "none") in ("none", "")):
        return "plaintext-vless"
    if s == "trojan":
        return "plaintext-trojan"
    if s == "ss":
        parsed_ss = parse_ss_userinfo(link["secret"])
        if parsed_ss is None or parsed_ss[0].lower() not in SS_CIPHERS:
            return "bad-ss-cipher"
    return None


def build_outbound(i: int, link: dict) -> tuple[dict, dict, dict] | None:
    """Returns (inbound, outbound, extra_outbound_or_None) or None to skip."""
    s, host, port, q = link["scheme"], link["host"], link["port"], link["q"]
    net = q.get("net") or q.get("type") or "tcp"  # 'type' key is tcp headerType for real URIs; net wins
    header_type = q.get("headerType") or (q.get("type") if "net" in q or link["scheme"] == "vmess" else "none")
    stream: dict = {"network": net if net in ("ws", "xhttp", "grpc", "httpupgrade") else "tcp"}
    if stream["network"] == "ws":
        ws = {"path": urllib.parse.unquote(q.get("path", "/"))}
        if q.get("host"):
            ws["headers"] = {"Host": q["host"]}
        stream["wsSettings"] = ws
    elif stream["network"] in ("xhttp", "httpupgrade"):
        st = {"path": urllib.parse.unquote(q.get("path", "/"))}
        if q.get("host"):
            st["host"] = q["host"]
        key = "xhttpSettings" if stream["network"] == "xhttp" else "httpupgradeSettings"
        stream[key] = st
    elif stream["network"] == "grpc":
        stream["grpcSettings"] = {"serviceName": q.get("serviceName", "")}
    elif stream["network"] == "tcp":
        hdr = {"type": header_type}
        if header_type == "http":
            hdr["request"] = {
                "version": "1.1", "method": "GET",
                "path": [urllib.parse.unquote(q.get("path", "/"))],
                "headers": {"Host": q.get("host", "")}}
        stream["tcpSettings"] = {"header": hdr}

    sec = q.get("security") or ("tls" if q.get("tls") in ("tls", "true", "True") else "none")
    if sec in ("tls", "reality"):
        tls = {"serverName": q.get("sni", host)}
        if q.get("fp"):
            tls["fingerprint"] = q["fp"]
        if q.get("alpn"):
            tls["alpn"] = [urllib.parse.unquote(q["alpn"])]
        if sec == "reality":
            # modern xray: security="reality" + realitySettings — putting
            # publicKey in tlsSettings is silently ignored and the handshake dies
            tls["publicKey"] = q.get("pbk", "")
            tls["shortId"] = q.get("sid", "")
            if q.get("spx"):
                tls["spiderX"] = urllib.parse.unquote(q["spx"])
            stream["security"] = "reality"
            stream["realitySettings"] = tls
        else:
            stream["security"] = "tls"
            stream["tlsSettings"] = tls
    else:
        stream["security"] = "none"

    if s in ("socks", "socks4", "socks5"):
        # xray socks outbound speaks SOCKS4/4a/5; auth only if userinfo present
        server: dict = {"address": host, "port": port}
        if link["secret"] and ":" in link["secret"]:
            user, pwd = link["secret"].split(":", 1)
            server["users"] = [{"user": user, "pass": pwd}]
        out = {"tag": f"o{i}", "protocol": "socks",
               "settings": {"servers": [server]},
               "streamSettings": stream}
    elif s in ("http", "https"):
        # plain HTTP proxies (https:// lists mean CONNECT-capable; xray's http
        # outbound doesn't do TLS to the proxy itself, same treatment as v2rayN)
        server = {"address": host, "port": port}
        if link["secret"] and ":" in link["secret"]:
            user, pwd = link["secret"].split(":", 1)
            server["users"] = [{"user": user, "pass": pwd}]
        out = {"tag": f"o{i}", "protocol": "http",
               "settings": {"servers": [server]},
               "streamSettings": stream}
    elif s == "trojan":
        out = {"tag": f"o{i}", "protocol": "trojan",
               "settings": {"servers": [{"address": host, "port": port, "password": link["secret"]}]},
               "streamSettings": stream}
    elif s == "vless":
        user = {"id": link["secret"], "encryption": q.get("encryption", "none")}
        if q.get("flow"):
            user["flow"] = q["flow"]
        out = {"tag": f"o{i}", "protocol": "vless",
               "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
               "streamSettings": stream}
    elif s == "vmess":
        out = {"tag": f"o{i}", "protocol": "vmess",
               "settings": {"vnext": [{"address": host, "port": port,
                                       "users": [{"id": link["secret"],
                                                  "security": q.get("scy", "auto")}]}]},
               "streamSettings": stream}
    elif s == "ss":
        parsed_ss = parse_ss_userinfo(link["secret"])
        if parsed_ss is None:
            return None
        method, password = parsed_ss
        out = {"tag": f"o{i}", "protocol": "shadowsocks",
               "settings": {"servers": [{"address": host, "port": port,
                                         "method": method,
                                         "password": password}]},
               "streamSettings": stream}
    else:
        return None

    extra = None
    if link["frag"]:
        extra = {"tag": f"f{i}", "protocol": "freedom",
                 "settings": {"domainStrategy": "AsIs",
                              "fragment": {"packets": "tlshello", "length": "1-104", "interval": "0-1"}}}
        # dial through the fragment outbound (sockopt form — modern xray)
        stream.setdefault("sockopt", {})["dialerProxy"] = f"f{i}"
    inbound = {"listen": "127.0.0.1", "port": BASE_PORT + i, "protocol": "socks",
               "settings": {"auth": "noauth", "udp": False}, "tag": f"p{i}"}
    return inbound, out, extra


def probe(port: int, url: str, timeout: int, tries: int) -> str:
    best = "000"
    for _ in range(tries):
        r = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "--max-time", str(timeout), "-x", f"socks5h://127.0.0.1:{port}", url],
            capture_output=True, text=True, env=NO_PROXY_ENV)
        best = r.stdout.strip() or "000"
        if best in OK_CODES:
            break
    return best


def fetch_all_subs(subs: list[str]) -> list[tuple[str, str]]:
    """Fetch all subscriptions in parallel. Returns [(url, raw)]."""
    out = []
    with ThreadPoolExecutor(max_workers=min(16, max(1, len(subs)))) as ex:
        futs = {ex.submit(fetch_sub, s): s for s in subs}
        for f in futs:
            s = futs[f]
            try:
                out.append((s, f.result()))
            except Exception as e:
                print(f"fetch failed: {s}: {e}", file=sys.stderr)
    return out


def build_chained_config(results: list[dict], cfg: dict, out_path: Path) -> tuple[int, str]:
    """Build chained-config.json and write it to out_path.

    Two modes:
    - upstream set: working links -> balancer over chained paths -> EXIT = the
      user's upstream server (each path dials the upstream through one link)
    - no upstream: pure load-balancer over the working links (exit = the links)

    Also writes chained-meta.json (tag -> tester-inbound port) so chain-runner
    can health-check each link individually.
    Returns (count, mode) where mode is "chained" or "lb".
    """
    good = [r for r in results if r["ok"]]
    if not good:
        print("chained config: no working links, skipping", file=sys.stderr)
        return 0, "none"
    up_path = Path(cfg.get("upstream_config", "")).expanduser()
    has_upstream = bool(cfg.get("upstream_config", "")) and up_path.exists()
    up_outs = []
    if has_upstream:
        up = json.loads(up_path.read_text())
        # pull the user's outbound(s) + their stream settings as-is
        up_outs = up.get("outbounds", [])
        if not up_outs:
            has_upstream = False

    mode = "chained" if has_upstream else "lb"
    up_log = json.loads(up_path.read_text()).get("log", {"loglevel": "warning"}) if has_upstream \
        else {"loglevel": "warning"}
    frag_outs, pool, paths, meta = [], [], [], []
    seen_keys: set[tuple] = set()
    for j, r in enumerate(good):
        try:
            parsed = parse_uri(r["uri"])
        except Exception:
            continue
        key = config_key(parsed)
        if key in seen_keys:
            continue  # duplicate config in results (same proxy, different label)
        seen_keys.add(key)
        built = build_outbound(j, parsed)
        if not built:
            continue
        ib, ob, extra = built
        ob["tag"] = f"w{j}"
        if extra:
            extra["tag"] = f"f{j}"
            frag_outs.append(extra)
        pool.append(ob)
        if mode == "chained":
            # one chained path per working link: the user's upstream dials
            # THROUGH this link, so the FINAL exit is always the upstream server.
            # MUST deepcopy: a shallow copy shares streamSettings with
            # up_outs[0], so every path would end up with the SAME dialerProxy
            # (the last w tag) instead of its own — the LB silently becomes
            # a single fixed link and dies with it.
            path = copy.deepcopy(up_outs[0])
            path["tag"] = f"p{j}"
            path.setdefault("streamSettings", {}).setdefault(
                "sockopt", {})["dialerProxy"] = f"w{j}"
            paths.append(path)
        # record the tester-side inbound port for this link so chain-runner
        # can health-check it independently of the chained instance
        meta.append({"tag": f"w{j}", "port": ib["port"]})

    # in chained mode the balancer rotates the PATHS (exit = upstream);
    # in lb mode it rotates the working links directly
    bal_selector = ["p"] if mode == "chained" else ["w"]
    # NOTE: leastLoad/leastPing + observatory look tempting but xray's leastLoad
    # ignores the balancer selector and tunnels through arbitrary outbounds
    # (observed: user requests exited via a free w link instead of the p path).
    # roundRobin + periodic pruning by chain-runner is the reliable combo.
    chained = {
        "log": up_log,
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": int(cfg["listen_port"]),
            "protocol": "mixed",
            "settings": {"auth": "noauth", "udp": True},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
        }],
        "outbounds": [
            *pool, *frag_outs, *paths,
            {"tag": "direct", "protocol": "freedom"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "balancers": [{
                "tag": "lb",
                "selector": bal_selector,
                "strategy": {"type": "roundRobin"},
            }],
            "rules": [
                {"type": "field", "inboundTag": ["mixed-in"], "balancerTag": "lb"},
            ],
        },
    }
    chained["inbounds"][0]["tag"] = "mixed-in"
    out_path.write_text(json.dumps(chained, indent=1))
    out_path.with_name("chained-meta.json").write_text(json.dumps(meta, indent=1))
    if mode == "chained":
        print(f"chained config: {len(paths)} paths (upstream via each of {len(pool)} links) "
              f"-> balancer on 127.0.0.1:{cfg['listen_port']} -> {out_path}")
    else:
        print(f"chained config: pure load-balancer over {len(pool)} links (no upstream) "
              f"on 127.0.0.1:{cfg['listen_port']} -> {out_path}")
    return len(paths) if mode == "chained" else len(pool), mode


SOCKS_FAMILY = {"socks", "socks4", "socks5"}
HTTP_FAMILY = {"http", "https"}


def config_key(parsed: dict) -> tuple:
    """Canonical identity of a config: same server/creds/transport = same proxy,
    regardless of URI encoding, param order or #fragment name. socks4/socks5
    map to one family and http/https to one (same node in free lists)."""
    q = parsed["q"]
    s = parsed["scheme"]
    if s in SOCKS_FAMILY:
        s = "socks"
    elif s in HTTP_FAMILY:
        s = "http"
    return (s, parsed["host"], parsed["port"], parsed["secret"],
            q.get("net") or q.get("type") or "tcp",
            urllib.parse.unquote(q.get("path", "/")),
            q.get("security") or q.get("tls") or "", q.get("sni", ""),
            q.get("host", ""), q.get("flow", ""), q.get("pbk", ""), q.get("sid", ""))


# ---- async probing (replaces per-probe curl spawns) ----

PROBE_TLS = ssl.create_default_context()


PROBE_URL_HOST = "www.apple.com"
PROBE_URL_PORT = 443
PROBE_URL_PATH = "/library/test/success.html"


async def _socks5_get(xray_port: int, timeout: float) -> str | None:
    """Minimal asyncio SOCKS5 client: CONNECT through local xray inbound, TLS,
    GET the probe URL, return the HTTP status line (e.g. '200') or None."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", xray_port), timeout)
        writer.write(b"\x05\x01\x00")  # no auth
        await writer.drain()
        if (await asyncio.wait_for(reader.readexactly(2), timeout)) != b"\x05\x00":
            return None
        addr = PROBE_URL_HOST.encode()
        writer.write(b"\x05\x01\x00\x03" + bytes([len(addr)]) + addr
                     + PROBE_URL_PORT.to_bytes(2, "big"))
        await writer.drain()
        hdr = await asyncio.wait_for(reader.readexactly(4), timeout)
        if hdr[1] != 0:  # REP != succeeded
            return None
        atyp = hdr[3]
        if atyp == 1:
            await asyncio.wait_for(reader.readexactly(4 + 2), timeout)
        elif atyp == 3:
            n = (await asyncio.wait_for(reader.readexactly(1), timeout))[0]
            await asyncio.wait_for(reader.readexactly(n + 2), timeout)
        elif atyp == 4:
            await asyncio.wait_for(reader.readexactly(16 + 2), timeout)
        else:
            return None
        # upgrade to TLS toward the probe URL host (start_tls upgrades the
        # existing reader/writer IN PLACE and returns None — don't unpack it)
        await asyncio.wait_for(
            writer.start_tls(PROBE_TLS, server_hostname=PROBE_URL_HOST), timeout)
        writer.write(
            f"GET {PROBE_URL_PATH} HTTP/1.1\r\nHost: {PROBE_URL_HOST}\r\n"
            f"User-Agent: xsub-tester\r\nConnection: close\r\n\r\n".encode())
        await writer.drain()
        status = await asyncio.wait_for(reader.readline(), timeout)
        writer.close()
        return status.split()[1].decode() if status.split() else None
    except Exception:
        return None


async def _tcp_one(host: str, port: int, sem: asyncio.Semaphore, timeout: float) -> bool:
    async with sem:
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            return False


async def tcp_scan(targets: set, timeout: float, concurrency: int,
                   progress_every: int = 0) -> set:
    """Fast TCP-connect liveness prescan. Returns alive {(host, port)}."""
    sem = asyncio.Semaphore(concurrency)
    tasks = {asyncio.ensure_future(_tcp_one(h, p, sem, timeout)): (h, p) for h, p in targets}
    alive: set = set()
    done = 0
    pending = set(tasks)
    while pending:
        done_now, pending = await asyncio.wait(pending, timeout=1,
                                               return_when=asyncio.FIRST_COMPLETED)
        for fut in done_now:
            h, p = tasks[fut]
            done += 1
            if fut.result():
                alive.add((h, p))
        if progress_every and done % progress_every == 0:
            _progress(stage="prescan", prescanned=done, alive=len(alive), total=len(tasks))
    return alive


PROGRESS_PATH = Path.home() / ".local/share/xray-sub-tester/progress.json"


def _progress(**kw) -> None:
    """Write live progress for the webui (atomic, throttled by caller)."""
    PROGRESS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = PROGRESS_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps({"ts": time.time(), **kw}))
    tmp.replace(PROGRESS_PATH)


def run(cfg_path: Path, xray_bin: str) -> Path:
    t0 = time.monotonic()
    cfg = load_cfg(cfg_path)
    links, seen = [], set()
    for sub, raw in fetch_all_subs(cfg["subscriptions"]):
        for l in extract_links(raw):
            if l in seen:  # big lists (80k+) repeat across subs/protocols
                continue
            seen.add(l)
            links.append({"uri": l, "sub": sub})
    print(f"got {len(links)} unique links from {len(cfg['subscriptions'])} subscriptions "
          f"in {time.monotonic() - t0:.1f}s")
    _progress(stage="building", found=len(links))

    entries = []  # (index, parsed)
    skips = Counter()
    seen_keys: set = set()
    for i, entry in enumerate(links):
        try:
            parsed = parse_uri(entry["uri"])
        except Exception:
            skips["parse-error"] += 1
            continue
        key = config_key(parsed)
        if key in seen_keys:
            skips["duplicate"] += 1
            continue
        seen_keys.add(key)
        if (reason := will_xray_reject(parsed)) is not None:
            skips[reason] += 1
            continue
        entries.append((i, parsed))
    for reason, n in skips.most_common():
        print(f"skipped {n} links: {reason}", file=sys.stderr)

    # ---- stage 1: fast TCP prescan (asyncio, no curl) kills the dead bulk ----
    targets = {(p["host"], p["port"]) for _, p in entries}
    tcp_timeout = float(cfg.get("tcp_prescan_timeout", 3))
    tcp_conc = int(cfg.get("tcp_prescan_concurrency", 1000))
    _progress(stage="prescan", prescanned=0, alive=0, total=len(targets))
    alive_targets = asyncio.run(tcp_scan(targets, tcp_timeout, tcp_conc,
                                         progress_every=250))
    entries = [(i, p) for i, p in entries if (p["host"], p["port"]) in alive_targets]
    print(f"tcp prescan: {len(alive_targets)}/{len(targets)} endpoints alive "
          f"-> {len(entries)} configs to probe")

    # ---- stage 2: build SHARDED xray instances (one inbound per alive link) ----
    shards = max(1, int(cfg.get("shards", 8)))
    shard_stride = 20000  # shard s uses ports BASE_PORT + s*stride + j
    cfg_dir = Path("/tmp/xray-sub-tester")
    cfg_dir.mkdir(exist_ok=True)
    shard_procs = []
    shard_map = []  # (shard_idx, xray_inbound_port, entry_index)
    for s in range(shards):
        chunk = entries[s::shards]
        if not chunk:
            continue
        # a single invalid outbound must not cost the whole shard: bisect out
        # the offending config and keep the rest (same loop as the old batch)
        inbounds, outbounds, rules = [], [], []
        kept = []  # (j, i, parsed, ib_port)
        for j, (i, parsed) in enumerate(chunk):
            built = build_outbound(j, parsed)
            if not built:
                continue
            ib, ob, extra = built
            ib["port"] = BASE_PORT + s * shard_stride + j
            kept.append((j, i, parsed, ib["port"], ib, ob, extra))
        scfg = cfg_dir / f"shard{s}.json"
        for _ in range(200):
            inbounds = [k[4] for k in kept]
            outbounds = [k[5] for k in kept] + [k[6] for k in kept if k[6]]
            rules = [{"type": "field", "inboundTag": [f"p{k[0]}"], "outboundTag": f"o{k[0]}"}
                     for k in kept]
            scfg.write_text(json.dumps({
                "log": {"loglevel": "error"},
                "inbounds": inbounds, "outbounds": outbounds,
                "routing": {"domainStrategy": "AsIs", "rules": rules},
            }))
            t = subprocess.run([xray_bin, "run", "-test", "-c", str(scfg)],
                               capture_output=True, text=True)
            if t.returncode == 0:
                break
            m = re.search(r"tag (o\d+)", t.stdout + t.stderr)
            if not m:
                raise SystemExit(f"shard {s} config invalid and unfixable:\n"
                                 f"{(t.stdout + t.stderr).strip()[-300:]}")
            bad_j = int(m.group(1)[1:])
            print(f"shard {s}: dropping invalid config o{bad_j}", file=sys.stderr)
            kept = [k for k in kept if k[0] != bad_j]
            if not kept:
                break
        if not kept:
            continue
        shard_map.extend((s, k[3], k[1]) for k in kept)
        shard_procs.append(subprocess.Popen(
            [xray_bin, "run", "-c", str(scfg)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=NO_PROXY_ENV))

    _progress(stage="testing", found=len(links), total=len(shard_map), tested=0, ok=0)
    results = []
    try:
        time.sleep(2)

        # ---- stage 3: async probes through every shard inbound ----
        async def probe_all() -> dict:
            """Worker-pool: PROBE_CONCURRENCY coroutines pull (xport, entry_idx)
            jobs from a queue; each does socks5 CONNECT + TLS GET. Returns
            {entry_idx: status}."""
            jobs: "asyncio.Queue" = asyncio.Queue()
            for _, xport, entry_idx in shard_map:
                jobs.put_nowait((xport, entry_idx))
            ok_map: dict = {}

            async def worker() -> None:
                while True:
                    try:
                        xport, entry_idx = jobs.get_nowait()
                    except asyncio.QueueEmpty:
                        return
                    status = await _socks5_get(xport, cfg["probe_timeout"] + 2)
                    ok_map[entry_idx] = status or "000"
                    done = len(ok_map)
                    if done % 200 == 0:
                        ok_n = sum(1 for v in ok_map.values() if v in OK_CODES)
                        _progress(stage="testing", found=len(links), total=len(shard_map),
                                  tested=done, ok=ok_n)
                    jobs.task_done()

            workers = [asyncio.create_task(worker())
                       for _ in range(int(cfg.get("probe_concurrency", 500)))]
            await jobs.join()
            for w in workers:
                w.cancel()
            return ok_map

        ok_map = asyncio.run(probe_all())
        entry_by_idx = {i: pp for i, pp in entries}
        for _, xport, entry_idx in shard_map:
            p = entry_by_idx[entry_idx]
            code = ok_map.get(entry_idx) or "000"
            ok = code in OK_CODES
            label = f"{p['scheme']}://{p['host']}:{p['port']}"
            results.append({"label": label, "codes": [code], "ok": ok,
                            "uri": links[entry_idx]["uri"]})
    finally:
        for pr in shard_procs:
            pr.terminate()
        for pr in shard_procs:
            try:
                pr.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pr.kill()

    out_dir = Path(cfg.get("results_dir", "~/.local/share/xray-sub-tester")).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    # working-links output must be duplicate-free: same config can appear under
    # several labels; dedupe by canonical identity, keep the first label
    good, seen_good = [], set()
    for r in results:
        if not r["ok"]:
            continue
        try:
            k = config_key(parse_uri(r["uri"]))
        except Exception:
            continue
        if k in seen_good:
            continue
        seen_good.add(k)
        good.append(r)
    stamp = time.strftime("%Y-%m-%d_%H-%M")
    (out_dir / f"results-{stamp}.json").write_text(json.dumps(results, indent=1))
    (out_dir / "working-links.txt").write_text(
        "\n".join(r["uri"] for r in good) + ("\n" if good else ""))
    print(f"done: {len(good)}/{len(results)} unique working in {time.monotonic() - t0:.1f}s "
          f"-> {out_dir / 'working-links.txt'}")
    _progress(stage="done", found=len(links), total=len(results), tested=len(results), ok=len(good))
    build_chained_config(results, cfg, out_dir / "chained-config.json")
    return out_dir / "working-links.txt"


if __name__ == "__main__":
    cfg = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd() / "config.yaml"
    if not cfg.exists():
        cfg = Path.home() / ".config/xray-subscription-tester/config.yaml"
    xray = sys.argv[2] if len(sys.argv) > 2 else "xray"
    run(cfg, xray)
