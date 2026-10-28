#!/usr/bin/env python3
"""Keeps the chained load-balancer xray instance running and healthy.

Jobs:
1. Watch chained-config.json; whenever it changes, restart xray.
2. Every health_interval seconds, build a TEMPORARY probe xray instance with
   one socks inbound per pool link (ports 21000+i), probe each link directly,
   and prune dead links (and their chained paths) from chained-config.json —
   so the LB never sends traffic to a corpse between full test runs.

Usage: chain-runner.py [chained-config.json] [xray-binary]
"""
import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

DEFAULT_CFG = Path.home() / ".local/share/proxenith/chained-config.json"
PROBE_URL = "https://www.google.com/generate_204"
PROBE_PORT_BASE = 21000  # separate range from the tester's 11000+


def probe_config(cfg: dict) -> tuple[dict, list[str]]:
    """Build a temp config: same pool links (w*), each with its own socks
    inbound on a private port, so each link can be probed independently.
    Returns (config, tags) where tags[i] is the real tag on port BASE+i —
    tags are NOT assumed contiguous (earlier prunes leave gaps)."""
    inbounds, outbounds, rules = [], [], []
    tags: list[str] = []
    for o in cfg.get("outbounds", []):
        tag = o.get("tag", "")
        if not tag.startswith("w"):
            continue
        idx = len(tags)
        tags.append(tag)
        inbounds.append({"listen": "127.0.0.1", "port": PROBE_PORT_BASE + idx, "protocol": "socks",
                         "settings": {"auth": "noauth", "udp": False}, "tag": f"probe{idx}"})
        outbounds.append(o)
        rules.append({"type": "field", "inboundTag": [f"probe{idx}"], "outboundTag": tag})
    return {"log": {"loglevel": "error"}, "inbounds": inbounds, "outbounds": outbounds,
            "routing": {"domainStrategy": "AsIs", "rules": rules}}, tags


def health_check(cfg: dict, xray_bin: str, timeout: int = 10) -> tuple[set[str], int]:
    """Probe every w* link through a temporary xray instance.
    Returns (alive_tags, total) using the REAL tag names."""
    probe, tags = probe_config(cfg)
    total = len(tags)
    if not total:
        return set(), 0
    pfile = Path("/tmp/xray-chain-probe.json")
    pfile.write_text(json.dumps(probe))
    t = subprocess.run([xray_bin, "run", "-test", "-c", str(pfile)], capture_output=True, text=True)
    if t.returncode != 0:
        print(f"health: probe config invalid: {t.stderr[-200:]}", flush=True)
        return set(), total
    proc = subprocess.Popen([xray_bin, "run", "-c", str(pfile)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(2)
        alive: set[str] = set()

        def one(i: int) -> str | None:
            tag = tags[i]
            r = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "--max-time", str(timeout), "-x",
                 f"socks5h://127.0.0.1:{PROBE_PORT_BASE + i}", PROBE_URL],
                capture_output=True, text=True)
            return tag if r.stdout.strip() in ("200", "204", "403") else None

        with ThreadPoolExecutor(max_workers=min(32, total)) as ex:
            for f in as_completed([ex.submit(one, i) for i in range(total)]):
                t2 = f.result()
                if t2:
                    alive.add(t2)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    return alive, total


def prune_dead(cfg: dict, alive: set[str], total: int) -> bool:
    """Remove dead pool outbounds AND their chained paths (pN for wN)."""
    if not alive or len(alive) == total:
        return False
    dead = [o["tag"] for o in cfg.get("outbounds", [])
            if o.get("tag", "").startswith("w") and o["tag"] not in alive]
    if not dead:
        return False
    dead_tags = set(dead) | {f"p{t[1:]}" for t in dead}  # wN → also its path pN
    before = len(cfg["outbounds"])
    cfg["outbounds"] = [o for o in cfg["outbounds"] if o.get("tag") not in dead_tags]
    # safety net: drop any chained path whose dialerProxy target no longer exists
    w_tags = {o["tag"] for o in cfg["outbounds"] if o.get("tag", "").startswith("w")}
    def _dangling(o: dict) -> bool:
        ss = o.get("streamSettings") or {}
        dp = (ss.get("sockopt") or {}).get("dialerProxy")
        return bool(dp and dp not in w_tags)
    cfg["outbounds"] = [o for o in cfg["outbounds"]
                        if not (o.get("tag", "").startswith("p") and _dangling(o))]
    changed = len(cfg["outbounds"]) != before
    if changed:
        print(f"health: pruned {len(dead)} dead links (+paths): {dead}; "
              f"{len(alive)}/{total} still alive", flush=True)
    return changed


def write_cfg(cfg_path: Path, cfg: dict) -> None:
    tmp = cfg_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=1))
    tmp.replace(cfg_path)  # mtime bump → main loop restarts xray


def main() -> None:
    cfg_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_CFG
    xray_bin = sys.argv[2] if len(sys.argv) > 2 else "xray"
    print(f"chain-runner watching {cfg_path}")
    proc = None
    last_mtime = None
    last_health = 0.0  # 0 → first prune fires right after xray starts
    health_interval = 60  # free links die fast; prune often
    while True:
        try:
            mtime = cfg_path.stat().st_mtime
        except FileNotFoundError:
            mtime = None
        if mtime != last_mtime:
            last_mtime = mtime
            if proc is not None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                proc = None
            if mtime is not None:
                t = subprocess.run([xray_bin, "run", "-test", "-c", str(cfg_path)],
                                   capture_output=True, text=True)
                if t.returncode == 0:
                    proc = subprocess.Popen(
                        [xray_bin, "run", "-c", str(cfg_path)],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    print(f"started xray with {cfg_path} (pid {proc.pid})", flush=True)
                    last_health = time.monotonic()
                else:
                    print(f"invalid chained config, not starting:\n{t.stderr[-300:]}", flush=True)
            else:
                print("no chained config yet, waiting...", flush=True)
        if proc is not None and proc.poll() is not None:
            print("xray exited unexpectedly, restarting", flush=True)
            last_mtime = None

        now = time.monotonic()
        if proc is not None and mtime is not None and now - last_health >= health_interval:
            last_health = now
            try:
                cfg = json.loads(cfg_path.read_text())
                alive, total = health_check(cfg, xray_bin)
                if total == 0:
                    continue
                if prune_dead(cfg, alive, total):
                    t = subprocess.run([xray_bin, "run", "-test", "-c", str(cfg_path)],
                                       capture_output=True, text=True)
                    if t.returncode == 0:
                        write_cfg(cfg_path, cfg)
                        last_mtime = None
                    else:
                        print("health: pruned config invalid, keeping old", flush=True)
                else:
                    print(f"health: {len(alive)}/{total} links alive (no prune needed)",
                          flush=True)
            except Exception as e:
                print(f"health check error: {e}", flush=True)
        time.sleep(5)


if __name__ == "__main__":
    main()
