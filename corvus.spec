# LEGACY: PyInstaller build spec — kept for reference.
# Project now builds with Nuitka via build.bat.
# PyInstaller fallback: pip install pyinstaller && pyinstaller --clean corvus.spec
# -*- mode: python ; coding: utf-8 -*-

import os

# ---------------------------------------------------------------------------
# Version Info - Helps reduce VirusTotal false positives by adding
# proper Windows PE metadata (CompanyName, FileDescription, etc.)
# ---------------------------------------------------------------------------
version_info = None
try:
    from PyInstaller.utils.win32.versioninfo import (
        VSVersionInfo, FixedFileInfo, StringFileInfo, StringTable,
        StringStruct, VarFileInfo, VarStruct,
    )
    version_info = VSVersionInfo(
        ffi=FixedFileInfo(
            filevers=(2, 0, 0, 0),
            prodvers=(2, 0, 0, 0),
            mask=0x3f,
            flags=0x0,
            OS=0x40004,
            fileType=0x1,
            subtype=0x0,
            date=(0, 0),
        ),
        kids=[
            StringFileInfo([
                StringTable(
                    '040904B0',
                    [
                        StringStruct('CompanyName', 'Security Scanner'),
                        StringStruct('FileDescription', 'Endpoint Security Scanner - Offline Threat Detection'),
                        StringStruct('FileVersion', '2.0.0.0'),
                        StringStruct('InternalName', 'scanner'),
                        StringStruct('LegalCopyright', 'Copyright (c) 2026'),
                        StringStruct('OriginalFilename', 'scanner.exe'),
                        StringStruct('ProductName', 'Endpoint Security Scanner'),
                        StringStruct('ProductVersion', '2.0.0.0'),
                    ],
                ),
            ]),
            VarFileInfo([VarStruct('Translation', [1033, 1200])]),
        ],
    )
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
a = Analysis(
    [os.path.join('src', 'main.py')],
    pathex=['src'],
    binaries=[],
    datas=[('iocs', 'iocs'), ('yara_rules', 'yara_rules'), ('config.json', '.')],
    hiddenimports=[
        'yara',
        'tqdm',
        # scanner_core package
        'scanner_core',
        'scanner_core.models',
        'scanner_core.utils',
        'scanner_core.config',
        'scanner_core.logger',
        # scanners package
        'scanners',
        'scanners.file_scanner',
        'scanners.network_scanner',
        'scanners.persistence_scanner',
        'scanners.process_scanner',
        'scanners.vulnerability_scanner',
        'scanners.service_scanner',
        'scanners.eventlog_scanner',
        'scanners.security_config_scanner',
        'scanners.dns_scanner',
        'scanners.port_scanner',
        'scanners.memory_scanner',
        'scanners.hosts_scanner',
        'scanners.ads_scanner',
        'scanners.pipe_scanner',
        'scanners.dll_hijack_scanner',
        'scanners.amcache_scanner',
        'scanners.prefetch_scanner',
        'scanners.powershell_history_scanner',
        'scanners.credential_scanner',
        'scanners.browser_scanner',
        # report package
        'report',
        'report.html_report',
        'report.json_report',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Exclude unused stdlib modules to reduce binary size & AV noise
        'tkinter', '_tkinter', 'unittest', 'pydoc', 'doctest',
        'xmlrpc', 'ftplib', 'imaplib', 'smtplib', 'nntplib',
        'curses', 'lib2to3', 'test', 'idlelib',
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

# ---------------------------------------------------------------------------
# EXE - UPX disabled (reduces false positives), version_info added
# ---------------------------------------------------------------------------
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='scanner',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,             # UPX packing triggers more AV false positives
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version=version_info,  # Windows PE version info metadata
)
