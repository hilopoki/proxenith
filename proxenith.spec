# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for the proxenith all-in-one binary.
# Build: pyinstaller proxenith.spec
block_cipher = None

a = Analysis(
    ["proxenith.py"],
    pathex=["."],
    binaries=[],
    datas=[("assets/qrcode.min.js", "assets")],
    hiddenimports=["tester", "chain_runner", "yaml"],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(
    pyz, a.scripts, a.binaries, a.zipfiles, a.datas, [],
    name="proxenith",
    console=True,
    exclude_binaries=False,
    upx=False,
)
