#!/usr/bin/env python3
"""Web UI for proxenith.

Manages subscription URLs, triggers test runs, and serves results
(working links / full JSON report) over a small stdlib HTTP server.

Two modes:
  * nix/script mode (default): manages chain via systemd --user unit
  * bundle mode (frozen binary / `--bundle`): runs tester in-process and
    chain-runner as a subprocess of this same executable, no systemd needed

Usage: webui.py [--port 8765] [--config config.yaml] [--xray /path/to/xray]
       webui.py --chain <chained-config.json>   (internal, bundle mode)
"""
import hashlib
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
RESULTS_DIR = Path.home() / ".local/share/proxenith"
BUNDLE = getattr(sys, "frozen", False) or "--bundle" in sys.argv

# defaults, overridden by main() / args
CONFIG_PATH = None
XRAY_BIN = "xray"


def _default_config_path() -> Path:
    p = Path.cwd() / "config.yaml"
    if p.exists():
        return p
    return Path.home() / ".config/proxenith/config.yaml"


CONFIG_PATH = _default_config_path()
TESTER = shutil.which("proxenith") or str(HERE / "tester.py")
STATE = {"running": False, "last_started": None, "last_finished": None, "last_error": None, "log_tail": []}

# bind localhost only by default
HOST = "127.0.0.1"

UPSTREAM_PATH = Path.home() / ".local/share/proxenith/upstream.json"
AUTH_PATH = RESULTS_DIR / "auth.json"

# tester.py (same dir) provides parse_uri/build_outbound for share links
sys.path.insert(0, str(HERE))
import tester as _tester  # noqa: E402


def tester_cmd() -> list:
    """Command that runs a full test (script mode)."""
    return [TESTER, str(CONFIG_PATH)]


def chain_cmd(cfg: Path) -> list:
    """Command that runs the chain guardian."""
    if BUNDLE:
        return [sys.executable, "--chain", str(cfg), XRAY_BIN]
    runner = shutil.which("proxenith-chain-runner") or str(HERE / "chain-runner.py")
    return [sys.executable, runner, str(cfg), XRAY_BIN]


def parse_upstream_paste(text: str) -> list[dict]:
    """Accept either a full xray JSON config or share link(s) (one per line,
    vmess:// vless:// trojan:// ss://). Return list of usable outbounds."""
    text = text.strip()
    if not text:
        raise ValueError("empty input")
    if text.startswith("{"):
        u = json.loads(text)
        outs = [o for o in u.get("outbounds", []) if o.get("tag") not in ("direct", "block", "api")]
        if not outs:
            raise ValueError("no usable outbound in pasted config")
        for o in outs:
            o.pop("dialerProxy", None)  # never chain the upstream itself
        return outs
    # share links
    links = [l.strip() for l in text.splitlines() if l.strip()]
    outs = []
    for j, uri in enumerate(links):
        p = _tester.parse_uri(uri)
        built = _tester.build_outbound(j, p)
        if not built:
            raise ValueError(f"unsupported link: {uri[:60]}")
        ib, ob, extra = built
        ob["tag"] = f"up{j}"
        ob.pop("dialerProxy", None)
        outs.append(ob)
    if not outs:
        raise ValueError("no links parsed")
    return outs


def save_upstream(text: str) -> str:
    """Validate and store the pasted manual config (JSON or share links);
    returns preview or raises."""
    outs = parse_upstream_paste(text)
    UPSTREAM_PATH.parent.mkdir(parents=True, exist_ok=True)
    UPSTREAM_PATH.write_text(json.dumps({"outbounds": outs}, indent=1))
    o = outs[0]
    proto = o.get("protocol", "?")
    addr = ""
    try:
        addr = o["settings"].get("servers", o["settings"].get("vnext", [{}]))[0].get("address", "")
    except Exception:
        pass
    return f"{o.get('tag', '?')}: {proto} {addr}".strip()


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text("subscriptions: []\n")
    return yaml.safe_load(CONFIG_PATH.read_text()) or {}


def save_config(cfg: dict) -> None:
    CONFIG_PATH.write_text(yaml.safe_dump(cfg, sort_keys=False, allow_unicode=True))


def run_tester_async():
    """Run a test in-process (bundle mode) or via subprocess (script mode)."""
    def worker():
        STATE["running"] = True
        STATE["last_started"] = time.strftime("%Y-%m-%d %H:%M:%S")
        STATE["last_error"] = None
        try:
            if BUNDLE:
                _tester.run(CONFIG_PATH, XRAY_BIN)
                STATE["log_tail"] = ["test finished"]
            else:
                p = subprocess.run(
                    tester_cmd(),
                    capture_output=True, text=True, timeout=3600)
                STATE["log_tail"] = (p.stdout + p.stderr).splitlines()[-200:]
                if p.returncode != 0:
                    STATE["last_error"] = p.stderr[-500:]
        except Exception as e:
            STATE["last_error"] = str(e)
        finally:
            STATE["running"] = False
            STATE["last_finished"] = time.strftime("%Y-%m-%d %H:%M:%S")
    threading.Thread(target=worker, daemon=True).start()


def list_results() -> list[dict]:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = []
    for f in sorted(RESULTS_DIR.glob("results-*.json"), reverse=True):
        try:
            data = json.loads(f.read_text())
            out.append({"file": f.name,
                        "stamp": f.name.removeprefix("results-").removesuffix(".json"),
                        "total": len(data),
                        "ok": sum(1 for r in data if r.get("ok")),
                        "mtime": f.stat().st_mtime})
        except Exception:
            continue
    return out


RUNNER_UNIT = "xray-chain-runner.service"

# bundle mode: chain guardian runs as our child process
CHAIN_PROC: subprocess.Popen | None = None


def _start_chain(cfg: Path):
    global CHAIN_PROC
    _stop_chain()
    CHAIN_PROC = subprocess.Popen(
        chain_cmd(cfg),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0)


def _stop_chain():
    global CHAIN_PROC
    if CHAIN_PROC and CHAIN_PROC.poll() is None:
        try:
            CHAIN_PROC.terminate()
            try:
                CHAIN_PROC.wait(timeout=5)
            except subprocess.TimeoutExpired:
                CHAIN_PROC.kill()
        except Exception:
            pass
    CHAIN_PROC = None


def regenerate_chained() -> str:
    """Rebuild chained-config.json from the LAST test results + current
    upstream (no full test needed). Works with or without an upstream:
    no upstream = pure load-balancer over the working links.
    Returns a short status message."""
    files = sorted(RESULTS_DIR.glob("results-*.json"))
    if not files:
        return "no test results yet — run a test first"
    results = json.loads(files[-1].read_text())
    cfg = load_config()
    ok, mode = _tester.build_chained_config(results, cfg, RESULTS_DIR / "chained-config.json")
    if ok:
        what = "chained paths (exit = upstream)" if mode == "chained" \
            else "load-balanced links (no upstream)"
        return f"rebuilt: {ok} {what}"
    return "rebuild skipped (no working links in last test)"


PROGRESS_PATH = Path.home() / ".local/share/proxenith/progress.json"


def _read_progress() -> dict:
    try:
        return json.loads(PROGRESS_PATH.read_text())
    except Exception:
        return {}


def _port_open(port: int, timeout: float = 2.0) -> bool:
    """Cross-platform TCP connect check (works on Windows/mac too)."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


def _cf_trace(port: int):
    """Fetch the cloudflare trace THROUGH the chain (exit IP + colo).
    Uses curl when available, falls back to urllib via the HTTP inbound."""
    proxy = f"http://127.0.0.1:{port}"
    if shutil.which("curl"):
        env = {k: v for k, v in os.environ.items()
               if not k.lower().endswith("_proxy")}
        t = subprocess.run(
            ["curl", "-s", "--max-time", "12", "-w", "\n%{http_code} %{time_total}",
             "-x", proxy, "https://cloudflare.com/cdn-cgi/trace"],
            capture_output=True, text=True, timeout=20, env=env)
        out = t.stdout.strip()
        if t.returncode == 0 and "ip=" in out:
            body, _, meta = out.rpartition("\n")
            trace = dict(line.split("=", 1) for line in body.strip().splitlines() if "=" in line)
            trace["_http"], trace["_time"] = meta.split()
            return trace, None
        if t.returncode != 0:
            err = {28: "timeout — chain accepts connections but no data flows "
                       "(upstream or path is dead)",
                   35: "TLS handshake failed through the chain "
                       "(dead/failed path, fallback not possible)",
                   56: "connection reset through the chain (path died mid-request)",
                   7: "could not connect to the chain inbound"}.get(
                       t.returncode, f"curl exit {t.returncode}")
            return None, err
        return None, f"unexpected response: {out[:80]!r}"
    # no curl (e.g. bare Windows): urllib speaks plain HTTP proxy natively
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        r = opener.open("https://cloudflare.com/cdn-cgi/trace", timeout=12)
        trace = dict(line.split("=", 1) for line in r.read().decode().strip().splitlines() if "=" in line)
        return trace, None
    except Exception as e:
        return None, f"trace failed: {e}"


def service_status() -> dict:
    """Status of the chain service: unit state, inbound port liveness."""
    if BUNDLE:
        state = "active" if (CHAIN_PROC and CHAIN_PROC.poll() is None) else "inactive"
    else:
        def run(*args):
            return subprocess.run(["systemctl", "--user", *args],
                                  capture_output=True, text=True).stdout.strip()
        state = run("is-active", RUNNER_UNIT) or "unknown"
    mtime = None
    cfg = RESULTS_DIR / "chained-config.json"
    if cfg.exists():
        mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(cfg.stat().st_mtime))
    port_open = False
    listen_port = None
    try:
        chained = json.loads(cfg.read_text())
        listen_port = chained["inbounds"][0]["port"]
    except Exception:
        pass
    if listen_port:
        port_open = _port_open(listen_port)
    # exit-IP trace through the chain; report WHY on failure instead of
    # hiding the box — a silent empty box is confusing.
    cf_trace = None
    cf_error = None
    if port_open:
        cf_trace, cf_error = _cf_trace(listen_port)
    elif state == "active":
        cf_error = "chain unit active but inbound port not open"
    # recent runner log
    if BUNDLE:
        log = ""
    else:
        log = subprocess.run(["journalctl", "--user", "-u", RUNNER_UNIT,
                              "--no-pager", "-n", "8", "--output=cat"],
                             capture_output=True, text=True).stdout
    return {"unit": state, "config_mtime": mtime,
            "listen_port": listen_port, "port_open": port_open,
            "cf_trace": cf_trace, "cf_error": cf_error,
            "log_tail": log.splitlines()[-8:] if log else []}


# ---------------------------------------------------------------- auth ----

def _load_auth() -> dict | None:
    try:
        return json.loads(AUTH_PATH.read_text())
    except Exception:
        return None


def _hash_pw(salt: str, pw: str) -> str:
    return hashlib.sha256((salt + pw).encode()).hexdigest()


def setup_password(pw: str) -> str:
    """First-run: create the stored password. Returns the session token."""
    salt = secrets.token_hex(8)
    token = secrets.token_hex(32)
    AUTH_PATH.parent.mkdir(parents=True, exist_ok=True)
    AUTH_PATH.write_text(json.dumps(
        {"salt": salt, "hash": _hash_pw(salt, pw), "token": token}))
    try:
        AUTH_PATH.chmod(0o600)
    except Exception:
        pass
    return token


def check_password(pw: str) -> str | None:
    a = _load_auth()
    if not a:
        return None
    if secrets.compare_digest(a["hash"], _hash_pw(a["salt"], pw)):
        return a["token"]
    return None


def check_token(tok: str | None) -> bool:
    a = _load_auth()
    return bool(a and tok and secrets.compare_digest(a["token"], tok))


def auth_state() -> dict:
    a = _load_auth()
    if not a:
        return {"setup_required": True, "auth_required": False}
    return {"setup_required": False, "auth_required": True}


# ---------------------------------------------------------------- assets ---

FAVICON = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
<rect width="64" height="64" rx="14" fill="#0f1117"/>
<rect x="1.5" y="1.5" width="61" height="61" rx="12.5" fill="none" stroke="#2c3040" stroke-width="3"/>
<path d="M36 8 L16 36 h12 L26 56 L48 26 H34 Z" fill="#3b82f6" stroke="#60a5fa" stroke-width="2" stroke-linejoin="round"/>
</svg>"""


def _pac(port: int) -> str:
    return ("function FindProxyForURL(url, host) {\n"
            "  if (isPlainHostName(host) || shExpMatch(host, 'localhost', '127.*', '[::1]'))\n"
            "    return 'DIRECT';\n"
            f"  return 'SOCKS5 127.0.0.1:{port}; PROXY 127.0.0.1:{port}; DIRECT;';\n"
            "}\n")


PAGE = """<!doctype html>
<html lang="en" dir="ltr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<title>proxenith</title>
<style>
:root { color-scheme: dark; }
body { font-family: system-ui, sans-serif; background: #0f1117; color: #e2e2e2;
       max-width: 1280px; margin: 2rem auto; padding: 0 1rem; }
h1 { font-size: 1.4rem; }
/* two-column layout: left = subs + chain settings, right = service + results */
.columns { display: flex; gap: 1rem; align-items: flex-start; }
.columns > div { flex: 1 1 0; min-width: 0; }
@media (max-width: 900px) { .columns { flex-direction: column; } }
.results-scroll { max-height: 420px; overflow-y: auto; }
/* English-data inputs stay LTR inside the RTL page */
textarea, input { width: 100%; background: #1a1d26; color: #e2e2e2; border: 1px solid #2c3040;
       border-radius: 6px; padding: .5rem; font-family: monospace; font-size: .85rem;
       direction: ltr; text-align: left; unicode-bidi: plaintext; box-sizing: border-box; }
textarea { min-height: 140px; }
label.status input { display: inline-block; width: auto; }
label.status textarea { display: block; margin-top: .3rem; }
code, pre { direction: ltr; text-align: left; }
button { background: #3b82f6; color: white; border: 0; border-radius: 6px;
         padding: .5rem 1.2rem; cursor: pointer; margin: .3rem .2rem; }
button:disabled { background: #475569; cursor: wait; }
button.gray { background: #374151; }
button.ghost { background: transparent; border: 1px solid #2c3040; color: #94a3b8; }
table { width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: .9rem; }
th, td { text-align: left; padding: .4rem .6rem; border-bottom: 1px solid #2c3040; }
a { color: #60a5fa; }
.ok { color: #4ade80; } .bad { color: #f87171; }
.status { font-size: .85rem; color: #94a3b8; margin: .5rem 0; }
pre { background: #1a1d26; padding: .6rem; border-radius: 6px; font-size: .78rem;
      max-height: 200px; overflow: auto; white-space: pre-wrap; }
.card { background: #161923; border: 1px solid #2c3040; border-radius: 8px; padding: 1rem; margin: 1rem 0; }
details.adv { border-top: 1px dashed #2c3040; margin-top: .8rem; padding-top: .6rem; }
details.adv summary { cursor: pointer; color: #94a3b8; font-size: .85rem; user-select: none; }
/* overlays: setup + login */
.overlay { position: fixed; inset: 0; background: rgba(6,8,12,.92); display: flex;
           align-items: center; justify-content: center; z-index: 50; }
.overlay .card { max-width: 380px; width: 90%; }
.overlay h3 { margin-top: 0; }
/* toast */
#toasts { position: fixed; bottom: 1rem; inset-inline-end: 1rem; z-index: 60;
          display: flex; flex-direction: column; gap: .4rem; max-width: 360px; }
.toast { background: #1a1d26; border: 1px solid #2c3040; border-inline-start: 3px solid #3b82f6;
         border-radius: 6px; padding: .6rem .9rem; font-size: .85rem; opacity: 0;
         transition: opacity .25s; }
.toast.show { opacity: 1; }
.toast.err { border-inline-start-color: #f87171; }
.toast.okm { border-inline-start-color: #4ade80; }
/* QR modal */
.modal { position: fixed; inset: 0; background: rgba(6,8,12,.92); z-index: 55;
         display: flex; align-items: center; justify-content: center; }
.modal .qbox { background: #161923; border: 1px solid #2c3040; border-radius: 8px;
               padding: 1.2rem; max-width: 480px; width: 92%; max-height: 85vh; overflow: auto; }
.modal .qlist { display: flex; flex-wrap: wrap; gap: .6rem; }
.modal figure { margin: 0; text-align: center; }
.modal img { background: #fff; border-radius: 6px; padding: 4px; width: 128px; height: 128px; }
.modal figcaption { font-size: .65rem; color: #94a3b8; max-width: 128px;
                    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
                    direction: ltr; cursor: pointer; }
/* language toggle */
#langBtn { position: absolute; top: 1rem; inset-inline-end: 1rem; }
.hidden { display: none !important; }
.wizard textarea { min-height: 90px; }
.step { color: #94a3b8; font-size: .85rem; margin: .6rem 0; }
.step b { color: #e2e2e2; }
</style>
</head>
<body>
<button id="langBtn" class="ghost" onclick="toggleLang()">فارسی</button>
<h1>proxenith</h1>

<!-- first-run wizard: only shown while there are no subscriptions and no results -->
<div id="wizard" class="card wizard hidden">
  <h3 data-i18n="wiz_title"></h3>
  <div class="step"><b data-i18n="wiz_step1"></b> <span data-i18n="wiz_step1b"></span></div>
  <textarea id="wizSubs" placeholder="https://provider.example/sub"></textarea>
  <div>
    <button id="wizBtn" onclick="wizardRun()" data-i18n="wiz_test"></button>
    <span class="status" id="wizStatus"></span>
  </div>
  <div id="wizProgress" style="display:none">
    <div class="status" id="wizProgText"></div>
    <div style="background:#1a1d26; border-radius:6px; height:8px; overflow:hidden">
      <div id="wizProgBar" style="background:#3b82f6; height:100%; width:0%; transition:width .5s"></div>
    </div>
  </div>
  <div class="step" id="wizDone" data-i18n="wiz_done" style="display:none"></div>
</div>

<div id="main" class="columns hidden">
<div>
<div class="card">
  <h3 data-i18n="subs_title"></h3>
  <textarea id="subs" placeholder="https://..."></textarea>
  <div>
    <button onclick="save()" data-i18n="save"></button>
    <button id="runBtn" onclick="run()" data-i18n="test_now"></button>
    <span class="status" id="status"></span>
  </div>
  <div id="progressBox" style="display:none">
    <div class="status" id="progressText"></div>
    <div style="background:#1a1d26; border-radius:6px; height:8px; overflow:hidden">
      <div id="progressBar" style="background:#3b82f6; height:100%; width:0%; transition:width .5s"></div>
    </div>
  </div>
  <pre id="log"></pre>
</div>

<div class="card">
  <h3 data-i18n="chain_title"></h3>
  <div class="step" data-i18n="chain_help"></div>
  <label class="status"><span data-i18n="local_port"></span>
    <input id="port" style="width:110px" type="number" value="10888">
  </label>
  <div class="step"><b data-i18n="up_label"></b></div>
  <textarea id="upLink" style="min-height:64px"
            placeholder="vless://… / vmess://… / trojan://… / ss://"></textarea>
  <details class="adv">
    <summary data-i18n="up_advanced"></summary>
    <label class="status"><span data-i18n="up_adv_help"></span>
      <textarea id="upstreamJson" style="min-height:100px"
                placeholder='{"outbounds":[...]}'></textarea>
    </label>
  </details>
  <div class="status" id="upPreview"></div>
  <div class="status"><span data-i18n="chain_output"></span> <code>~/.local/share/proxenith/chained-config.json</code></div>
</div>
</div>

<div>
<div class="card">
  <h3 data-i18n="svc_title"></h3>
  <div class="status"><span data-i18n="svc_runner"></span>: <span id="svcRunner">…</span> &nbsp;|&nbsp; <span data-i18n="svc_xray"></span>: <span id="svcXray">…</span> &nbsp;|&nbsp; <span data-i18n="svc_inbound"></span> <span id="svcPort">…</span></div>
  <div>
    <button class="gray" onclick="svc('status')" data-i18n="refresh"></button>
    <button class="gray" onclick="svc('restart')" data-i18n="restart"></button>
  </div>
  <div class="status" id="cfBox" style="display:none"></div>
  <pre id="svcLog">…</pre>
</div>

<div class="card" id="connectCard">
  <h3 data-i18n="connect_title"></h3>
  <div class="step" id="connectHow" data-i18n="connect_none"></div>
</div>

<div class="card">
  <h3 data-i18n="results_title"></h3>
  <div class="status" id="exportRow">
    <button class="gray" onclick="copyAll()" data-i18n="copy_all"></button>
    <button class="gray" onclick="showQr()" data-i18n="qr_all"></button>
    <a href="/api/working/latest" id="latestLink" data-i18n="latest_txt"></a>
  </div>
  <div class="results-scroll">
  <table id="results"><thead><tr><th data-i18n="th_run"></th><th data-i18n="th_working"></th><th data-i18n="th_total"></th><th data-i18n="th_links"></th><th data-i18n="th_report"></th></tr></thead>
  <tbody></tbody></table>
  </div>
</div>
</div>
</div>

<!-- auth overlays -->
<div id="setupOv" class="overlay hidden"><div class="card">
  <h3 data-i18n="setup_title"></h3>
  <div class="step" data-i18n="setup_help"></div>
  <input id="setupPw" type="password">
  <div><button onclick="doSetup()" data-i18n="setup_btn"></button></div>
  <div class="status" id="setupErr"></div>
</div></div>
<div id="loginOv" class="overlay hidden"><div class="card">
  <h3 data-i18n="login_title"></h3>
  <input id="loginPw" type="password">
  <div><button onclick="doLogin()" data-i18n="login_btn"></button></div>
  <div class="status" id="loginErr"></div>
</div></div>

<div id="qrModal" class="modal hidden" onclick="if(event.target===this)this.classList.add('hidden')">
  <div class="qbox">
    <div class="status" data-i18n="qr_scan"></div>
    <div class="qlist" id="qrList"></div>
    <div><button class="gray" onclick="document.getElementById('qrModal').classList.add('hidden')" data-i18n="close"></button></div>
  </div>
</div>

<div id="toasts"></div>

<script src="/assets/qrcode.min.js"></script>
<script>
const I18N = {
en: {
 wiz_title:"Welcome — set up in steps", wiz_step1:"1.", wiz_step1b:"Paste your subscription URL(s), one per line.",
 wiz_test:"Save & start test", wiz_done:"✓ Test started — results appear below when it finishes.",
 subs_title:"Subscription URLs", save:"Save", test_now:"Test now",
 chain_title:"Exit server (optional)", chain_help:"Want every connection to exit from YOUR server? Paste the share link(s) of your own server below. Leave empty for a plain load-balancer.",
 local_port:"Local proxy port:", up_label:"Your server link(s):", up_advanced:"Advanced: paste raw xray JSON instead",
 up_adv_help:"Full xray config (JSON) — its outbounds are used as the upstream:", chain_output:"Config file:",
 svc_title:"Service", svc_runner:"Guardian", svc_xray:"xray chain", svc_inbound:"inbound",
 refresh:"Refresh status", restart:"Restart with latest config",
 connect_title:"How to connect", connect_none:"Run a test first — once the proxy is up, connection steps appear here.",
 results_title:"Results", copy_all:"Copy all working links", qr_all:"QR codes",
 latest_txt:"download latest working links", th_run:"Run", th_working:"Working", th_total:"Total",
 th_links:"Links", th_report:"Report",
 setup_title:"Create your dashboard password", setup_help:"This page is only reachable from this computer. Pick a password to protect your subscription list.",
 setup_btn:"Save password", login_title:"Password required", login_btn:"Unlock",
 qr_scan:"Scan with your proxy client (v2rayNG, Streisand, …):", close:"Close",
 toast_saved:"Saved ✓", toast_run_started:"Test started", toast_copied:"Links copied to clipboard ✓",
 toast_no_links:"No working links yet — run a test first", toast_auth_bad:"Wrong password",
 test:"Testing", prescan:"Prescan", building:"Building configs", found:"found", alive:"alive",
 working_so_far:"working so far", running_since:"Running since", last_run:"Last run", never:"never",
 copied_one:"copied ✓", stopped:"stopped", running:"running"
},
fa: {
 wiz_title:"خوش آمدید — راه‌اندازی گام‌به‌گام", wiz_step1:"۱.", wiz_step1b:"لینک اشتراک (subscription) خود را بچسبانید، هر خط یکی.",
 wiz_test:"ذخیره و شروع تست", wiz_done:"✓ تست شروع شد — نتایج بعد از اتمام اینجا نمایش داده می‌شود.",
 subs_title:"لینک‌های اشتراک", save:"ذخیره", test_now:"تست کن",
 chain_title:"سرور خروجی (اختیاری)", chain_help:"می‌خواهید همه‌ی اتصال‌ها از سرور خودتان خارج شوند؟ لینک سرور خودتان را بچسبانید. خالی بگذارید = فقط لودبالانسر.",
 local_port:"پورت پروکسی محلی:", up_label:"لینک سرور شما:", up_advanced:"پیشرفته: به‌جای لینک، JSON خام xray بچسبانید",
 up_adv_help:"کانفیگ کامل xray (JSON) — خروجی‌های آن به‌عنوان upstream استفاده می‌شوند:", chain_output:"فایل کانفیگ:",
 svc_title:"سرویس", svc_runner:"نگهبان", svc_xray:"زنجیره xray", svc_inbound:"پورت ورودی",
 refresh:"بروزرسانی وضعیت", restart:"ری‌استارت با کانفیگ جدید",
 connect_title:"چطور وصل شوم؟", connect_none:"اول یک تست اجرا کنید — بعد از بالا آمدن پروکسی، راهنمای اتصال اینجا می‌آید.",
 results_title:"نتایج", copy_all:"کپی همه لینک‌های سالم", qr_all:"کد QR",
 latest_txt:"دانلود آخرین لینک‌های سالم", th_run:"اجرای تست", th_working:"سالم", th_total:"کل",
 th_links:"لینک‌ها", th_report:"گزارش",
 setup_title:"رمز داشبورد را بسازید", setup_help:"این صفحه فقط از این کامپیوتر در دسترس است. برای محافظت از لیست اشتراک‌هایتان یک رمز بگذارید.",
 setup_btn:"ذخیره رمز", login_title:"رمز لازم است", login_btn:"باز کردن",
 qr_scan:"با کلاینت پروکسی خود اسکن کنید (v2rayNG، Streisand، …):", close:"بستن",
 toast_saved:"ذخیره شد ✓", toast_run_started:"تست شروع شد", toast_copied:"لینک‌ها کپی شدند ✓",
 toast_no_links:"هنوز لینک سالمی نیست — اول تست بگیرید", toast_auth_bad:"رمز اشتباه است",
 test:"در حال تست", prescan:"پیش‌اسکن", building:"ساخت کانفیگ‌ها", found:"یافت شد", alive:"زنده",
 working_so_far:"سالم تا اینجا", running_since:"در حال اجرا از", last_run:"آخرین تست", never:"هرگز",
 copied_one:"کپی شد ✓", stopped:"قطع", running:"فعال"
}};
let LANG = localStorage.getItem('px_lang') ||
  (navigator.language && navigator.language.startsWith('fa') ? 'fa' : 'en');
function t(k){ return I18N[LANG][k] || I18N.en[k] || k; }
function applyLang() {
  const L = I18N[LANG];
  document.documentElement.lang = LANG;
  document.documentElement.dir = LANG === 'fa' ? 'rtl' : 'ltr';
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const v = L[el.dataset.i18n];
    if (v !== undefined) el.textContent = v;
  });
  document.getElementById('langBtn').textContent = LANG === 'fa' ? 'English' : 'فارسی';
}
function toggleLang() {
  LANG = LANG === 'fa' ? 'en' : 'fa';
  localStorage.setItem('px_lang', LANG);
  applyLang(); refreshMain(lastState); refreshSvc();
}

// ---- toast ---------------------------------------------------------------
function toast(msg, kind) {
  const d = document.createElement('div');
  d.className = 'toast ' + (kind || '');
  d.textContent = msg;
  document.getElementById('toasts').appendChild(d);
  requestAnimationFrame(() => d.classList.add('show'));
  setTimeout(() => { d.classList.remove('show'); setTimeout(() => d.remove(), 300); }, 3500);
}

async function j(url, opt) {
  const r = await fetch(url, opt);
  if (r.status === 401) { showAuth(true); throw new Error('unauthorized'); }
  const body = await r.json().catch(() => ({}));
  if (!r.ok && body.error) toast(body.error, 'err');
  return body;
}
function showAuth(isLogin) {
  document.getElementById('loginOv').classList.toggle('hidden', !isLogin);
  if (isLogin) document.getElementById('loginPw').focus();
}
async function doSetup() {
  const pw = document.getElementById('setupPw').value;
  if (!pw) return;
  const r = await j('/api/setup', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({password: pw})});
  if (r.ok) { document.getElementById('setupOv').classList.add('hidden'); refresh(); }
  else document.getElementById('setupErr').textContent = r.error || 'error';
}
async function doLogin() {
  const pw = document.getElementById('loginPw').value;
  const r = await j('/api/login', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({password: pw})});
  if (r.ok) { document.getElementById('loginOv').classList.add('hidden'); refresh(); }
  else document.getElementById('loginErr').textContent = t('toast_auth_bad');
}

// ---- progress render (shared by wizard + main) ---------------------------
function renderProgress(p, running, txtEl, barEl, boxEl) {
  if (running && ['prescan', 'building', 'testing'].includes(p.stage)) {
    boxEl.style.display = 'block';
    if (p.stage === 'building') {
      txtEl.textContent = '⚙ ' + t('building') + '… ' + (p.found || 0) + ' ' + t('found');
      barEl.style.width = '10%';
    } else if (p.stage === 'prescan') {
      const pc = p.total ? Math.round(p.prescanned / p.total * 100) : 0;
      txtEl.textContent = '📡 ' + t('prescan') + ': ' + (p.prescanned || 0) + '/' + (p.total || 0) +
        ' (' + pc + '%) — ' + (p.alive || 0) + ' ' + t('alive');
      barEl.style.width = Math.max(5, pc) + '%';
    } else {
      const total = p.total || 0, tested = p.tested || 0;
      const pct = total ? Math.round(tested / total * 100) : 0;
      txtEl.textContent = '🧪 ' + t('test') + ': ' + tested + '/' + total + ' (' + pct + '%) — ' +
        (p.ok || 0) + ' ' + t('working_so_far');
      barEl.style.width = Math.max(5, pct) + '%';
    }
  } else boxEl.style.display = 'none';
}

// ---- main refresh --------------------------------------------------------
let lastState = null;
async function refresh() {
  const s = await j('/api/state');
  if (s.setup_required) { document.getElementById('setupOv').classList.remove('hidden'); return; }
  if (s.auth_required) { showAuth(true); return; }
  lastState = s;
  const isFresh = !(s.subscriptions || []).length && !(s.results || []).length;
  document.getElementById('wizard').classList.toggle('hidden', !isFresh);
  document.getElementById('main').classList.toggle('hidden', isFresh);
  if (isFresh) {
    const p = s.progress || {};
    renderProgress(p, s.running, document.getElementById('wizProgText'),
      document.getElementById('wizProgBar'), document.getElementById('wizProgress'));
    if (!s.running && (s.last_finished || (s.results || []).length))
      document.getElementById('wizDone').style.display = 'block';
    if ((s.results || []).length) refreshMain(s);
    return;
  }
  refreshMain(s);
}
function refreshMain(s) {
  document.getElementById('status').textContent =
    s.running ? t('running_since') + ' ' + s.last_started
              : t('last_run') + ': ' + (s.last_finished || t('never'));
  document.getElementById('runBtn').disabled = s.running;
  document.getElementById('log').textContent = (s.log_tail || []).join('\\n');
  const subsEl = document.getElementById('subs');
  if (document.activeElement !== subsEl && !subsEl.value.trim() && (s.subscriptions || []).length)
    subsEl.value = s.subscriptions.join('\\n');
  if (document.activeElement !== document.getElementById('port'))
    document.getElementById('port').value = s.listen_port || 10888;
  document.getElementById('upPreview').textContent =
    s.upstream_preview ? 'Upstream: ' + s.upstream_preview
                       : (LANG === 'fa' ? 'هنوز سرور خروجی تنظیم نشده' : 'No upstream configured');
  const p = s.progress || {};
  renderProgress(p, s.running, document.getElementById('progressText'),
    document.getElementById('progressBar'), document.getElementById('progressBox'));
  // results table
  const tb = document.getElementById('results').querySelector('tbody');
  tb.innerHTML = '';
  for (const r of (s.results || [])) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${r.stamp}</td><td class="ok">${r.ok}</td><td>${r.total}</td>` +
      `<td><a href="/api/working/${encodeURIComponent(r.stamp)}">${t('th_links')}</a></td>` +
      `<td><a href="/api/report/${encodeURIComponent(r.file)}">json</a></td>`;
    tb.appendChild(tr);
  }
  // connect card
  const how = document.getElementById('connectHow');
  if (s.port_open && s.listen_port) {
    const pac = location.origin + '/proxy.pac';
    how.innerHTML =
      '<div>' + t('local_port') + ' <code>127.0.0.1:' + s.listen_port + '</code> — ' +
      '<span class="ok">● ' + t('running') + '</span></div>' +
      '<div style="margin-top:.5rem">HTTP + SOCKS5 — ' +
      (LANG === 'fa'
        ? 'پروکسی سیستم/مرورگر را روی <code>127.0.0.1:' + s.listen_port + '</code> بگذارید'
        : 'point your OS/browser proxy at <code>127.0.0.1:' + s.listen_port + '</code>') + '</div>' +
      '<div style="margin-top:.4rem">PAC: <a href="' + pac + '">' + pac + '</a></div>';
  } else {
    how.textContent = t('connect_none');
  }
}

// ---- wizard actions ------------------------------------------------------
async function wizardRun() {
  const v = document.getElementById('wizSubs').value.split('\\n').map(s=>s.trim()).filter(Boolean);
  if (!v.length) return;
  const r = await j('/api/config', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({subscriptions: v})});
  if (r.ok) { await j('/api/run', {method:'POST'}); toast(t('toast_run_started'), 'okm'); refresh(); }
}
document.getElementById('wizSubs').addEventListener('keydown', e => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); wizardRun(); }
});

// dirty flags: only send edited fields so a save can't wipe the other card
document.getElementById('upstreamJson').addEventListener('input', function() { this.dataset.dirty = '1'; });
document.getElementById('upLink').addEventListener('input', function() { this.dataset.dirty = '1'; });

async function save() {
  const body = {listen_port: document.getElementById('port').value};
  const upEl = document.getElementById('upstreamJson');
  const linkEl = document.getElementById('upLink');
  if (linkEl.dataset.dirty === '1') body.upstream_links = linkEl.value;
  else if (upEl.dataset.dirty === '1') {
    body.upstream_json = upEl.value;
    body.upstream_clear = !upEl.value.trim();
  }
  const subsEl = document.getElementById('subs');
  if (subsEl.value.trim() || subsEl.dataset.loaded === '1')
    body.subscriptions = subsEl.value.split('\\n').map(s=>s.trim()).filter(Boolean);
  const r = await j('/api/config', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify(body)});
  if (r.ok) {
    toast(t('toast_saved') + (r.chain_msg ? ' — ' + r.chain_msg : ''), 'okm');
    linkEl.dataset.dirty = '0'; upEl.dataset.dirty = '0';
    refresh();
  }
}
async function run() { await j('/api/run', {method:'POST'}); toast(t('toast_run_started'), 'okm'); refresh(); }
async function svc(action) {
  if (action === 'restart') {
    const b = event.target; b.disabled = true;
    await j('/api/service/restart', {method:'POST'});
    b.disabled = false;
  }
  await refreshSvc(); refresh();
}
async function refreshSvc() {
  try {
    const s = await j('/api/service');
    const runnerEl = document.getElementById('svcRunner');
    runnerEl.textContent = s.unit;
    runnerEl.className = s.unit === 'active' ? 'ok' : 'bad';
    const xrayEl = document.getElementById('svcXray');
    xrayEl.textContent = s.port_open ? t('running') : t('stopped');
    xrayEl.className = s.port_open ? 'ok' : 'bad';
    document.getElementById('svcPort').textContent = (s.listen_port || '?') + (s.config_mtime ? ' (' + s.config_mtime + ')' : '');
    const box = document.getElementById('cfBox');
    box.style.display = 'block';
    if (s.cf_trace) {
      const t2 = s.cf_trace;
      box.innerHTML = '🌐 ' + (LANG === 'fa' ? 'خروجی: ' : 'Exit: ') + '<b class="ok">' + (t2.ip || '?') + '</b>' +
        ' — ' + (t2.loc || '?') + ' (' + (t2.colo || '?') + ')' +
        ' — warp: ' + (t2.warp || '?') + ' — ' + (t2._time || '') + 's';
    } else if (s.cf_error) {
      box.innerHTML = '<span class="bad">⛔ ' + s.cf_error + '</span>';
    } else {
      box.innerHTML = '<span class="status">…</span>';
    }
    document.getElementById('svcLog').textContent = (s.log_tail || []).join('\\n');
  } catch (e) { /* status fetch can fail during restart */ }
}

// ---- export helpers ------------------------------------------------------
async function copyAll() {
  const r = await fetch('/api/working/latest');
  if (!r.ok) { toast(t('toast_no_links'), 'err'); return; }
  const txt = await r.text();
  if (!txt.trim()) { toast(t('toast_no_links'), 'err'); return; }
  await navigator.clipboard.writeText(txt);
  toast(t('toast_copied'), 'okm');
}
async function showQr() {
  const r = await fetch('/api/working/latest');
  if (!r.ok) { toast(t('toast_no_links'), 'err'); return; }
  const links = (await r.text()).split('\\n').filter(Boolean);
  if (!links.length) { toast(t('toast_no_links'), 'err'); return; }
  const list = document.getElementById('qrList');
  list.innerHTML = '';
  for (const uri of links.slice(0, 24)) {
    const fig = document.createElement('figure');
    try {
      const qr = qrcode(0, 'L');
      qr.addData(uri);
      qr.make();
      const img = document.createElement('img');
      img.src = qr.createDataURL(4, 0);
      fig.appendChild(img);
      const cap = document.createElement('figcaption');
      cap.textContent = uri.slice(0, 40) + '…';
      cap.title = uri;
      cap.onclick = () => { navigator.clipboard.writeText(uri); toast(t('copied_one'), 'okm'); };
      fig.appendChild(cap);
    } catch (e) { /* link too long for QR */ }
    list.appendChild(fig);
  }
  document.getElementById('qrModal').classList.remove('hidden');
}

applyLang();
setInterval(refresh, 3000);
setInterval(refreshSvc, 5000);
refresh();
refreshSvc();
</script>
</body>
</html>"""


def _asset(name: str) -> bytes:
    p = HERE / "assets" / name
    if p.exists():
        return p.read_bytes()
    # PyInstaller frozen: data files land under sys._MEIPASS
    base = Path(getattr(sys, "_MEIPASS", "."))
    return (base / "assets" / name).read_bytes()


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json", headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200, headers=None):
        self._send(code, json.dumps(obj).encode(), headers=headers)

    def _authorized(self) -> bool:
        a = _load_auth()
        if not a:
            return True  # no password configured yet → setup flow
        tok = None
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "pxs":
                tok = v
        return check_token(tok)

    def do_GET(self):
        path = self.path.split("?")[0]
        # public endpoints (before the auth gate)
        if path == "/api/session":
            self._json(auth_state())
        elif path in ("/favicon.ico", "/favicon.svg"):
            self._send(200, FAVICON.encode(), "image/svg+xml")
        elif path == "/assets/qrcode.min.js":
            self._send(200, _asset("qrcode.min.js"), "application/javascript")
        elif not self._authorized():
            self._json({"error": "unauthorized"}, 401)
        elif path == "/" or path == "/index.html":
            self._send(200, PAGE.encode(), "text/html; charset=utf-8")
        elif path == "/proxy.pac":
            cfg = load_config()
            self._send(200, _pac(cfg.get("listen_port", 10888)).encode(),
                       "application/x-ns-proxy-autoconfig")
        elif path == "/api/state":
            cfg = load_config()
            up_out = None
            up_text = ""
            if UPSTREAM_PATH.exists():
                try:
                    u = json.loads(UPSTREAM_PATH.read_text())
                    up_text = json.dumps(u, indent=1, ensure_ascii=False)
                    for o in u.get("outbounds", []):
                        if o.get("tag") not in ("direct", "block", "api"):
                            up_out = o.get("tag") + ": " + o.get("protocol", "?")
                            break
                except Exception:
                    up_out = "unreadable"
            st = {**{k: v for k, v in STATE.items()},
                  "setup_required": False, "auth_required": False,
                  "subscriptions": cfg.get("subscriptions", []),
                  "listen_port": cfg.get("listen_port", 10888),
                  "results": list_results(),
                  "upstream_set": UPSTREAM_PATH.exists(),
                  "upstream_preview": up_out,
                  "upstream_text": up_text,
                  "progress": _read_progress()}
            self._json(st)
        elif path == "/api/service":
            self._json(service_status())
        elif path == "/api/results":
            self._json(list_results())
        elif path.startswith("/api/working/"):
            # working links as of that run; URL is /api/working/<stamp> (no .json)
            # "latest" always serves the newest run
            stamp = path.rsplit("/", 1)[1].removesuffix(".json")
            if stamp == "latest":
                files = sorted(RESULTS_DIR.glob("results-*.json"))
                if not files:
                    self._json({"error": "no results yet"}, 404)
                    return
                stamp = files[-1].name.removeprefix("results-").removesuffix(".json")
            f = RESULTS_DIR / f"results-{stamp}.json"
            try:
                data = json.loads(f.read_text())
                good = [r["uri"] for r in data if r.get("ok")]
                self._send(200, "\n".join(good).encode(), "text/plain; charset=utf-8")
            except FileNotFoundError:
                self._json({"error": "not found"}, 404)
        elif path.startswith("/api/report/"):
            fname = path.rsplit("/", 1)[1]
            f = RESULTS_DIR / fname
            if f.exists() and f.parent == RESULTS_DIR:
                self._send(200, f.read_bytes(), "application/json")
            else:
                self._json({"error": "not found"}, 404)
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n)) if n else {}
        if self.path == "/api/setup":
            if _load_auth():
                self._json({"ok": False, "error": "already set up"}, 400)
                return
            pw = (body.get("password") or "").strip()
            if len(pw) < 4:
                self._json({"ok": False, "error": "password too short (min 4)"}, 400)
                return
            tok = setup_password(pw)
            self._json({"ok": True}, headers={
                "Set-Cookie": f"pxs={tok}; Path=/; HttpOnly; SameSite=Strict; Max-Age=31536000"})
        elif self.path == "/api/login":
            tok = check_password(body.get("password") or "")
            if tok:
                self._json({"ok": True}, headers={
                    "Set-Cookie": f"pxs={tok}; Path=/; HttpOnly; SameSite=Strict; Max-Age=31536000"})
            else:
                self._json({"ok": False, "error": "wrong password"}, 403)
        elif not self._authorized():
            self._json({"error": "unauthorized"}, 401)
        elif self.path == "/api/config":
            cfg = load_config()
            # partial-safe: only overwrite fields that were actually sent, so
            # saving one card can't wipe the other card's data
            if "subscriptions" in body:
                cfg["subscriptions"] = body.get("subscriptions", [])
            if "listen_port" in body:
                try:
                    cfg["listen_port"] = int(body["listen_port"])
                except (TypeError, ValueError):
                    pass
            cfg.pop("upstream_config", None)
            preview = None
            chain_msg = ""
            links = (body.get("upstream_links") or "").strip()
            up_json = (body.get("upstream_json") or "").strip()
            if links:
                try:
                    preview = save_upstream(links)
                except Exception as e:
                    self._json({"ok": False, "error": f"invalid upstream link(s): {e}"}, 400)
                    return
            elif up_json:
                try:
                    preview = save_upstream(up_json)
                except Exception as e:
                    self._json({"ok": False, "error": f"invalid upstream config: {e}"}, 400)
                    return
            elif body.get("upstream_clear"):
                # user deliberately emptied the field → actually remove it
                UPSTREAM_PATH.unlink(missing_ok=True)
                preview = ""
                chain_msg = "upstream removed"
            cfg["upstream_config"] = str(UPSTREAM_PATH) if UPSTREAM_PATH.exists() else ""
            save_config(cfg)
            # apply immediately: rebuild chained config from last results
            # (works in both modes — with upstream = chained, without = pure LB)
            chain_msg = regenerate_chained()
            if BUNDLE and (RESULTS_DIR / "chained-config.json").exists():
                # keep the running chain in sync with the new config
                _start_chain(RESULTS_DIR / "chained-config.json")
            self._json({"ok": True, "count": len(cfg["subscriptions"]),
                        "upstream_preview": preview, "chain_msg": chain_msg})
        elif self.path == "/api/run":
            if STATE["running"]:
                self._json({"ok": False, "error": "already running"})
            else:
                run_tester_async()
                self._json({"ok": True})
        elif self.path == "/api/service":
            self._json(service_status())
        elif self.path == "/api/service/restart":
            # "restart with latest config" must actually REBUILD the chained
            # config from last results + current upstream, then bounce it
            try:
                msg = regenerate_chained()
            except Exception as e:
                msg = f"rebuild failed: {e}"
            if BUNDLE:
                cfgf = RESULTS_DIR / "chained-config.json"
                if cfgf.exists():
                    _start_chain(cfgf)
                    self._json({"ok": True, "rebuild": msg})
                else:
                    self._json({"ok": False, "rebuild": msg, "error": "no chained config yet"})
                return
            r = subprocess.run(["systemctl", "--user", "restart", RUNNER_UNIT],
                               capture_output=True, text=True, timeout=30)
            self._json({"ok": r.returncode == 0, "rebuild": msg,
                        "error": r.stderr.strip() or None})
        else:
            self._json({"error": "not found"}, 404)

    def log_message(self, *a):
        pass


def _run_subcommand(kind: str, cfg: Path, xray: str):
    """Frozen-bundle internal sub-commands."""
    if kind == "test":
        _tester.run(cfg, xray)
    elif kind == "chain":
        import chain_runner
        chain_runner.main.__globals__["sys"].argv = ["chain-runner", str(cfg), xray]
        chain_runner.main()


def main(port: int | None = None, config: Path | None = None,
         xray: str | None = None, serve_only: bool = False):
    global CONFIG_PATH, XRAY_BIN
    args = sys.argv[1:]
    # internal sub-commands used by the frozen bundle itself
    for flag in ("--test", "--chain"):
        if flag in args:
            i = args.index(flag)
            cfg = Path(args[i + 1])
            x = args[i + 2] if len(args) > i + 2 else "xray"
            _run_subcommand(flag.lstrip("-"), cfg, x)
            return
    if "--port" in args and port is None:
        port = int(args[args.index("--port") + 1])
    if "--config" in args and config is None:
        config = Path(args[args.index("--config") + 1]).expanduser().resolve()
    if "--xray" in args and xray is None:
        xray = args[args.index("--xray") + 1]
    if port is None:
        port = 8765
    if config:
        CONFIG_PATH = config
    if xray:
        XRAY_BIN = xray
    if BUNDLE:
        # keep the last results' chain alive from the start
        cfgf = RESULTS_DIR / "chained-config.json"
        if cfgf.exists():
            threading.Thread(target=_start_chain, args=(cfgf,), daemon=True).start()
    srv = ThreadingHTTPServer((HOST, port), Handler)
    print(f"serving on http://{HOST}:{port}", flush=True)
    if serve_only:
        srv.serve_forever()
    else:
        threading.Thread(target=srv.serve_forever, daemon=True).start()


if __name__ == "__main__":
    main(serve_only=True)
