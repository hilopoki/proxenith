#!/usr/bin/env python3
"""proxenith — one-command entry point (used by the frozen binary).

On first run it:
  1. creates ~/.local/share/proxenith/ and a default config if missing
  2. downloads the right xray build for this OS/arch if no xray on PATH
  3. starts the web UI (http://127.0.0.1:8765) and opens the browser
"""
import os
import shutil
import stat
import sys
import urllib.request
import webbrowser
import zipfile
from pathlib import Path

DATA_DIR = Path.home() / ".local/share/proxenith"
XRAY_DIR = DATA_DIR / "xray"
DEFAULT_PORT = 8765

# XTLS/Xray-core release asset names per platform
_ASSETS = {
    ("linux", "x86_64"): "Xray-linux-64.zip",
    ("linux", "aarch64"): "Xray-linux-arm64-v8a.zip",
    ("darwin", "x86_64"): "Xray-macos-64.zip",
    ("darwin", "arm64"): "Xray-macos-arm64-v8a.zip",
    ("win32", "AMD64"): "Xray-windows-64.zip",
    ("win32", "ARM64"): "Xray-windows-arm64-v8a.zip",
}


def _machine() -> str:
    m = os.uname().machine if hasattr(os, "uname") else os.environ.get("PROCESSOR_ARCHITEW6465", "")
    m = (m or "AMD64").lower()
    return {"amd64": "x86_64", "x86_64": "x86_64", "arm64": "aarch64",
            "aarch64": "aarch64"}.get(m, m)


def xray_binary() -> str | None:
    """Find a usable xray: PATH first, then our data dir."""
    w = shutil.which("xray") or shutil.which("xray.exe")
    if w:
        return w
    name = "xray.exe" if sys.platform == "win32" else "xray"
    p = XRAY_DIR / name
    return str(p) if p.exists() else None


def download_xray() -> str | None:
    key = (sys.platform, _machine())
    asset = _ASSETS.get(key)
    if not asset:
        print(f"no prebuilt xray for {key}; put an 'xray' binary on PATH",
              file=sys.stderr)
        return None
    url = f"https://github.com/XTLS/Xray-core/releases/latest/download/{asset}"
    XRAY_DIR.mkdir(parents=True, exist_ok=True)
    zip_path = XRAY_DIR / asset
    print(f"downloading xray: {url}")
    urllib.request.urlretrieve(url, zip_path)
    with zipfile.ZipFile(zip_path) as z:
        for n in z.namelist():
            if Path(n).name.lower() in ("xray", "xray.exe"):
                z.extract(n, XRAY_DIR)
                bin_path = XRAY_DIR / Path(n).name
                break
        else:
            raise RuntimeError("xray binary not found in archive")
    zip_path.unlink(missing_ok=True)
    if sys.platform != "win32":
        bin_path.chmod(bin_path.stat().st_mode | stat.S_IEXEC)
    print(f"xray ready: {bin_path}")
    return str(bin_path)


def main():
    port = DEFAULT_PORT
    if "--port" in sys.argv:
        port = int(sys.argv[sys.argv.index("--port") + 1])
    if "--no-browser" not in sys.argv:
        # open AFTER the server answers (give it a moment)
        import threading
        threading.Timer(1.2, lambda: webbrowser.open(f"http://127.0.0.1:{port}")).start()
    xray = xray_binary() or download_xray() or "xray"
    import webui
    webui.main(port=port, xray=xray, serve_only=True)


if __name__ == "__main__":
    main()
