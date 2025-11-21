# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

import os
project_root = Path(os.getcwd()).resolve()

block_cipher = None

pathex = [
    str(project_root),
    str(project_root / "pymes_ui"),
    str(project_root / "truslan" / "src"),
    str(project_root / "trusClamAV" / "src"),
    str(project_root / "trusMITRE" / "src"),
]

from PyInstaller.utils.hooks import collect_all

datas = [
    (str(project_root / "trusMITRE" / "analytics"), "trusMITRE/analytics"),
]
binaries = []
hiddenimports = [
    "truslan",
    "trusClamAV",
    "trustmitre",
    "jinja2",
    "tqdm",
    "yaml",
    "tkinter",
    "pydantic",
    "pydantic_settings",
    "dotenv",
    "typer",
    "click",
    "shellingham",
    "rich",
    "xmltodict",
    "bs4",
    "requests",
]

# Collect all for trustmitre and pydantic_settings to ensure everything is included
tmp_ret = collect_all('trustmitre')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('pydantic_settings')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('typer')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('rich')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]

a = Analysis(
    ["pymes_ui/main.py"],
    pathex=pathex,
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="TrustPYMEs",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(project_root / "assets" / "icon.ico"),
)
