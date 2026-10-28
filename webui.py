#!/usr/bin/env python3
"""Web UI for proxenith.

Manages subscription URLs, triggers test runs, and serves results
(working links / full JSON report) over a small stdlib HTTP server.

Usage: webui.py [--port 8765] [--config config.yaml]
"""
import json
import shutil
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

# tester.py (same dir) provides parse_uri/build_outbound for share links
sys.path.insert(0, str(HERE))
import tester as _tester  # noqa: E402


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
    def worker():
        STATE["running"] = True
        STATE["last_started"] = time.strftime("%Y-%m-%d %H:%M:%S")
        STATE["last_error"] = None
        try:
            p = subprocess.run(
                [TESTER, str(CONFIG_PATH)],
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


def service_status() -> dict:
    """Status of the chain service: unit state, xray pid, inbound port liveness."""
    def run(*args):
        return subprocess.run(["systemctl", "--user", *args],
                              capture_output=True, text=True).stdout.strip()

    state = run("is-active", RUNNER_UNIT) or "unknown"
    mtime = None
    cfg = RESULTS_DIR / "chained-config.json"
    if cfg.exists():
        mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(cfg.stat().st_mtime))
    # is the mixed inbound actually listening?
    port_open = False
    listen_port = None
    try:
        chained = json.loads(cfg.read_text())
        listen_port = chained["inbounds"][0]["port"]
    except Exception:
        pass
    if listen_port:
        s = subprocess.run(["bash", "-c", f"exec 3<>/dev/tcp/127.0.0.1/{listen_port} && echo open"],
                           capture_output=True, text=True, timeout=5)
        port_open = s.stdout.strip() == "open"
    # fetch cloudflare trace THROUGH the chain (exit IP + colo). On failure
    # report WHY instead of hiding the box — a silent empty box is confusing.
    cf_trace = None
    cf_error = None
    if port_open:
        t = subprocess.run(
            ["curl", "-s", "--max-time", "12", "-w", "\n%{http_code} %{time_total}",
             "-x", f"http://127.0.0.1:{listen_port}", "https://cloudflare.com/cdn-cgi/trace"],
            capture_output=True, text=True,
            env={"PATH": "/usr/bin:/bin", "HOME": str(Path.home())})
        out = t.stdout.strip()
        if t.returncode == 0 and "ip=" in out:
            body, _, meta = out.rpartition("\n")
            cf_trace = dict(line.split("=", 1) for line in body.strip().splitlines() if "=" in line)
            cf_trace["_http"], cf_trace["_time"] = meta.split()
        elif t.returncode != 0:
            curl_err = {28: "timeout — chain accepts connections but no data flows "
                             "(upstream or path is dead)",
                        35: "TLS handshake failed through the chain "
                            "(dead/failed path, fallback not possible)",
                        56: "connection reset through the chain (path died mid-request)",
                        7: "could not connect to the chain inbound"}.get(t.returncode, f"curl exit {t.returncode}")
            cf_error = curl_err
        else:
            cf_error = f"unexpected response: {out[:80]!r}"
    elif state == "active":
        cf_error = "chain unit active but inbound port not open"
    # recent runner log
    log = subprocess.run(["journalctl", "--user", "-u", RUNNER_UNIT,
                          "--no-pager", "-n", "8", "--output=cat"],
                         capture_output=True, text=True).stdout
    return {"unit": state, "config_mtime": mtime,
            "listen_port": listen_port, "port_open": port_open,
            "cf_trace": cf_trace, "cf_error": cf_error,
            "log_tail": log.splitlines()[-8:] if log else []}


FAVICON = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
<rect width="64" height="64" rx="14" fill="#0f1117"/>
<rect x="1.5" y="1.5" width="61" height="61" rx="12.5" fill="none" stroke="#2c3040" stroke-width="3"/>
<path d="M36 8 L16 36 h12 L26 56 L48 26 H34 Z" fill="#3b82f6" stroke="#60a5fa" stroke-width="2" stroke-linejoin="round"/>
</svg>"""

PAGE = """<!doctype html>
<html lang="en" dir="ltr">
<head>
<meta charset="utf-8">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<title>Xray Subscription Tester</title>
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
       direction: ltr; text-align: left; unicode-bidi: plaintext; }
textarea { min-height: 140px; }
label.status input { display: inline-block; width: auto; }
label.status textarea { display: block; margin-top: .3rem; }
code, pre { direction: ltr; text-align: left; }
button { background: #3b82f6; color: white; border: 0; border-radius: 6px;
         padding: .5rem 1.2rem; cursor: pointer; margin: .3rem .2rem; }
button:disabled { background: #475569; cursor: wait; }
button.gray { background: #374151; }
table { width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: .9rem; }
th, td { text-align: left; padding: .4rem .6rem; border-bottom: 1px solid #2c3040; }
a { color: #60a5fa; }
.ok { color: #4ade80; } .bad { color: #f87171; }
.status { font-size: .85rem; color: #94a3b8; margin: .5rem 0; }
pre { background: #1a1d26; padding: .6rem; border-radius: 6px; font-size: .78rem;
      max-height: 200px; overflow: auto; white-space: pre-wrap; }
.card { background: #161923; border: 1px solid #2c3040; border-radius: 8px; padding: 1rem; margin: 1rem 0; }
.saved-ok { color: #4ade80 !important; font-weight: 600; }
</style>
</head>
<body>
<h1>Xray Subscription Tester</h1>

<div class="columns">
<div>
<div class="card">
  <h3>Subscription URLs</h3>
  <textarea id="subs" placeholder="https://..."></textarea>
  <div>
    <button onclick="save()">Save</button>
    <button id="runBtn" onclick="run()">Test now</button>
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
  <h3>Chained load-balancer</h3>
  <label class="status">Local mixed inbound port:
    <input id="port" style="width:110px" type="number" value="10888">
  </label>
  <label class="status">Second (manual) config — full JSON or share link(s) (vmess:// / vless:// / trojan:// / ss://), one per line:
    <textarea id="upstreamJson" placeholder='{"outbounds":[...]}  or  vless://uuid@host:443?...'></textarea>
  </label>
  <div class="status" id="upPreview"></div>
  <div class="status">Output: <code id="chainPath">~/.local/share/proxenith/chained-config.json</code> — served by chain-runner on the port above.</div>
</div>
</div>

<div>
<div class="card">
  <h3>Chain service</h3>
  <div class="status">chain-runner: <span id="svcRunner">…</span> &nbsp;|&nbsp; xray chain instance: <span id="svcXray">…</span> &nbsp;|&nbsp; inbound <span id="svcPort">…</span></div>
  <div>
    <button class="gray" onclick="svc('status')">Refresh status</button>
    <button class="gray" onclick="svc('restart')">Restart with latest config</button>
  </div>
  <div class="status" id="cfBox" style="display:none"></div>
  <pre id="svcLog">…</pre>
</div>

<div class="card">
  <h3>Results</h3>
  <div class="status">📥 Always-latest working links: <a href="/api/working/latest" id="latestLink">/api/working/latest</a></div>
  <div class="results-scroll">
  <table id="results"><thead><tr><th>Run</th><th>Working</th><th>Total</th><th>Links</th><th>Report</th></tr></thead>
  <tbody></tbody></table>
  </div>
</div>
</div>
</div>

<script>
async function j(url, opt) { const r = await fetch(url, opt); return r.json(); }
async function refresh() {
  const s = await j('/api/state');
  document.getElementById('status').textContent =
    s.running ? 'Running since ' + s.last_started : 'Last run: ' + (s.last_finished || 'never');
  document.getElementById('runBtn').disabled = s.running;
  document.getElementById('log').textContent = (s.log_tail || []).join(String.fromCharCode(10));
  if (!document.activeElement || document.activeElement.id !== 'subs') {
    const subsEl = document.getElementById('subs');
    if (document.activeElement !== subsEl) {
      subsEl.value = (s.subscriptions || []).join(String.fromCharCode(10));
      subsEl.dataset.loaded = '1';
    }
  }
  if (!document.activeElement || document.activeElement.id !== 'port')
    document.getElementById('port').value = s.listen_port || 10888;
  document.getElementById('upPreview').textContent =
    s.upstream_preview ? 'Upstream outbound: ' + s.upstream_preview : 'No upstream config pasted yet';
  // keep the saved upstream JSON visible (unless user is typing in it)
  const upEl = document.getElementById('upstreamJson');
  if (upEl !== document.activeElement && !upEl.value.trim() && s.upstream_text)
    upEl.value = s.upstream_text;
  // live progress while a run is going
  const p = s.progress || {};
  const box = document.getElementById('progressBox');
  const bar = document.getElementById('progressBar');
  const txt = document.getElementById('progressText');
  if (s.running && ['prescan', 'building', 'testing'].includes(p.stage)) {
    box.style.display = 'block';
    if (p.stage === 'building') {
      txt.textContent = '⚙ Building configs… found ' + (p.found || 0) + ' links';
      bar.style.width = '10%';
    } else if (p.stage === 'prescan') {
      const pc = p.total ? Math.round(p.prescanned / p.total * 100) : 0;
      txt.textContent = '📡 TCP prescan: ' + (p.prescanned || 0) + '/' + (p.total || 0) +
        ' (' + pc + '%) — ' + (p.alive || 0) + ' alive';
      bar.style.width = Math.max(5, pc) + '%';
    } else {
      const total = p.total || 0, tested = p.tested || 0;
      const pct = total ? Math.round(tested / total * 100) : 0;
      txt.textContent =
        '🧪 Testing: ' + tested + '/' + total + ' (' + pct + '%) — ' + (p.ok || 0) + ' working so far';
      bar.style.width = Math.max(5, pct) + '%';
    }
  } else {
    box.style.display = 'none';
  }
  const res = await j('/api/results');
  const tb = document.getElementById('results').querySelector('tbody');
  tb.innerHTML = '';
  for (const r of res) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${r.stamp}</td><td class="ok">${r.ok}</td><td>${r.total}</td>` +
      `<td><a href="/api/working/${encodeURIComponent(r.stamp)}">working links</a></td>` +
      `<td><a href="/api/report/${encodeURIComponent(r.file)}">json</a></td>`;
    tb.appendChild(tr);
  }
}
// dirty flag: only send upstream_json when the user actually edited the field,
// so clearing it = deliberate removal, and an untouched page can't wipe anything
document.getElementById('upstreamJson').addEventListener('input', function() {
  this.dataset.dirty = '1';
});
async function save() {
  const body = {listen_port: document.getElementById('port').value};
  const upEl = document.getElementById('upstreamJson');
  if (upEl.dataset.dirty === '1') {
    body.upstream_json = upEl.value;
    body.upstream_clear = !upEl.value.trim();
  }
  const subsEl = document.getElementById('subs');
  // only include subscriptions if the box was actually loaded with data
  // (protects against wiping the list on a fresh page)
  if (subsEl.dataset.loaded === '1')
    body.subscriptions = subsEl.value.split(String.fromCharCode(10)).map(s=>s.trim()).filter(Boolean);
  const r = await j('/api/config', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify(body)});
  if (r.ok) {
    const note = document.getElementById('upPreview');
    note.textContent = r.chain_msg
      ? 'Upstream outbound: ' + (r.upstream_preview || 'removed') + ' — ' + r.chain_msg
      : 'Saved';
    note.classList.add('saved-ok');
    setTimeout(() => note.classList.remove('saved-ok'), 4000);
    upEl.dataset.dirty = '0';  // canonical content now matches
  }
  // repopulate the textarea with the canonical saved JSON so refresh keeps it
  const st = await j('/api/state');
  upEl.value = st.upstream_text || '';
  refresh();
}
async function run() { await j('/api/run', {method:'POST'}); refresh(); }
async function svc(action) {
  if (action === 'restart') {
    const b = event.target; b.disabled = true; b.textContent = 'Restarting…';
    const r = await j('/api/service/restart', {method:'POST'});
    b.disabled = false; b.textContent = 'Restart with latest config';
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
    xrayEl.textContent = s.port_open ? 'listening' : 'NOT listening';
    xrayEl.className = s.port_open ? 'ok' : 'bad';
    document.getElementById('svcPort').textContent = (s.listen_port || '?') + (s.config_mtime ? ' (config: ' + s.config_mtime + ')' : '');
    const box = document.getElementById('cfBox');
    box.style.display = 'block';
    if (s.cf_trace) {
      const t = s.cf_trace;
      box.innerHTML = '🌐 Exit via chain: <b class="ok">' + (t.ip || '?') + '</b>' +
        ' — ' + (t.loc || '?') + ' (' + (t.colo || '?') + ')' +
        ' — warp: ' + (t.warp || '?') + ' — TLS: ' + (t.tls || '?') +
        ' — ' + (t._time || '') + 's';
    } else if (s.cf_error) {
      box.innerHTML = '<span class="bad">⛔ Trace failed: ' + s.cf_error + '</span>';
    } else {
      box.innerHTML = '<span class="status">No trace yet…</span>';
    }
    document.getElementById('svcLog').textContent = (s.log_tail || []).join(String.fromCharCode(10));
  } catch (e) { /* status fetch can fail during restart */ }
}
refresh(); setInterval(refresh, 3000); setInterval(refreshSvc, 5000);
</script>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj).encode())

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self._send(200, PAGE.encode(), "text/html; charset=utf-8")
        elif self.path in ("/favicon.ico", "/favicon.svg"):
            self._send(200, FAVICON.encode(), "image/svg+xml")
        elif self.path == "/api/state":
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
            self._json({**{k: v for k, v in STATE.items()},
                        "subscriptions": cfg.get("subscriptions", []),
                        "listen_port": cfg.get("listen_port", 10888),
                        "upstream_set": UPSTREAM_PATH.exists(),
                        "upstream_preview": up_out,
                        "upstream_text": up_text,
                        "progress": _read_progress()})
        elif self.path == "/api/service":
            self._json(service_status())
        elif self.path == "/api/results":
            self._json(list_results())
        elif self.path.startswith("/api/working/"):
            # working links as of that run; URL is /api/working/<stamp> (no .json)
            # "latest" always serves the newest run
            stamp = self.path.rsplit("/", 1)[1].removesuffix(".json")
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
        elif self.path.startswith("/api/report/"):
            fname = self.path.rsplit("/", 1)[1]
            f = RESULTS_DIR / fname
            if f.exists() and f.parent == RESULTS_DIR:
                self._send(200, f.read_bytes(), "application/json")
            else:
                self._json({"error": "not found"}, 404)
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        if self.path == "/api/config":
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n))
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
            up_json = (body.get("upstream_json") or "").strip()
            chain_msg = ""
            if up_json:
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
            # config from last results + current upstream, then bounce the unit
            try:
                msg = regenerate_chained()
            except Exception as e:
                msg = f"rebuild failed: {e}"
            r = subprocess.run(["systemctl", "--user", "restart", RUNNER_UNIT],
                               capture_output=True, text=True, timeout=30)
            self._json({"ok": r.returncode == 0, "rebuild": msg,
                        "error": r.stderr.strip() or None})
        else:
            self._json({"error": "not found"}, 404)

    def log_message(self, *a):
        pass


def main():
    port = 8765
    args = sys.argv[1:]
    if "--port" in args:
        port = int(args[args.index("--port") + 1])
    if "--config" in args:
        global CONFIG_PATH
        CONFIG_PATH = Path(args[args.index("--config") + 1]).expanduser().resolve()
    srv = ThreadingHTTPServer((HOST, port), Handler)
    print(f"serving on http://{HOST}:{port}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
