#!/usr/bin/env python3
# coding: utf8

from chrome_content import __software__ as ff_proxy_name
from chrome_content import __version__ as ff_proxy_version
from chrome_content import __author__ as ff_proxy_author
from chrome_content import __email__ as ff_proxy_authormail
from chrome_content import __license__ as ff_proxy_license

from cx_Freeze import setup, Executable

base = "Console"

executables = [
    Executable(
        "chrome_content.py",
        base=base,
        copyright=f"Licensed under {ff_proxy_license} by {ff_proxy_author}",
        icon="icon/icon.ico")
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
        "excludes": ["tkinter"],
        "include_msvcr": True,
        "optimize": 1,
    },
}

setup(name=ff_proxy_name,
      author=ff_proxy_author,
      author_email=ff_proxy_authormail,
      options=options,
      version=ff_proxy_version,
      description='An experimental "proxy" for fanfiction.net',
      executables=executables)
