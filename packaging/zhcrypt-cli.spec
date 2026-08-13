# -*- mode: python ; coding: utf-8 -*-
# zhcrypt CLI 打包配置 (Python 3.13 + PyInstaller 6)

a = Analysis(
    ['../cli.py'],
    pathex=['..'],
    binaries=[],
    datas=[],
    hiddenimports=[
        'secretsharing',
        'certpin',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'setuptools', 'pkg_resources', 'wheel', 'distutils',
        'bcrypt', 'tkinter', 'plyer', 'ctypes',
        'multiprocessing', 'decimal', 'xml', 'sqlite3',
        'pydoc', 'unittest', 'doctest', 'pdb', 'lib2to3',
        'ensurepip', 'pip',
    ],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='zhcrypt',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    version='version_info_cli.txt',
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name='zhcrypt_cli',
)
