#!/usr/bin/env python3
# coding: utf8

from chrome_content import __software__ as ff_proxy_name
from chrome_content import __version__ as ff_proxy_version
from chrome_content import __author__ as ff_proxy_author
from chrome_content import __license__ as ff_proxy_license

from cx_Freeze import setup, Executable

base = None

executables = [
    Executable(
        "chrome_content.py",
        base=base,
        copyright=f"Licensed under {ff_proxy_license} by {ff_proxy_author}",
    )
]

packages = [
    "idna", "colorama", "plyer", "undetected_chromedriver", "selenium",
    "psutil", "win32api", "pefile", "os", "argparse", "codecs", "datetime",
    "re", "logging", "sys", "time", "hashlib", "collections", "json", "random",
    "signal", "base64", "socket", "urllib"
]

options = {
    'build_exe': {
        'packages': packages,
        "excludes": ["tkinter"]
    },
}

setup(name=ff_proxy_name,
      options=options,
      version=ff_proxy_version,
      description='An experimental "proxy" for fanfiction.net',
      executables=executables)
