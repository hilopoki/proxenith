# proxenith

Tests xray share links from subscription URLs at scale (TCP prescan +
sharded xray instances + async probing), keeps the alive ones, and serves
them as a load-balanced local proxy on one mixed inbound port — optionally
chained through a manual upstream config so the exit is always your server.

## Features

- fetch subscriptions (raw or base64), parse vmess / vless (incl. reality +
  flow) / trojan / shadowsocks, ws / grpc / httpheader / httpupgrade transports
- TCP prescan of every endpoint, then parallel probing through sharded xray
  instances (tens of thousands of links in minutes)
- working links become a round-robin load-balancer on a single local port
  (http + socks)
- optional second-hop config (JSON or share link) pasted via the web UI: every
  balancer path dials the upstream through one of the alive links
- background guardian service health-probes the pool every 60s and prunes
  dead links automatically
- built-in web UI (dark, RTL-aware): manage subscriptions, trigger test runs
  with live progress, paste the upstream config, watch the chain exit IP,
  restart the service, download results

## Usage

1. Edit `config.yaml` — add your subscription URLs (plain list of links or
   base64-encoded, both supported).
2. Run:
   ```
   nix run .
   ```
   or after `nix build`:
   ```
   result/bin/proxenith [config.yaml] [xray-binary]
   ```
3. `nix build .#webui` gives the web UI (`proxenith-webui --port 8768
   --config config.yaml`), `.#chain-runner` gives the guardian
   (`proxenith-chain-runner <chained-config.json> [xray-binary]`).

Defaults: `config.yaml` next to the script, `xray` from PATH (the wrapper
puts nix xray + curl on PATH). Data lives in `~/.local/share/proxenith/`.

A link counts as working if the probe answers with any real HTTP code
(200/204/403 — a 403 from Google endpoints means the tunnel answered but the
exit IP is rate-limited, not dead).

## Supported links

vmess (base64 JSON), vless (incl. reality), trojan, shadowsocks;
ws / tcp(+http header) / grpc / xhttp / httpupgrade transports; `fm=`
fragment parameter (clamped to xray-valid ranges, like common client
exports).
