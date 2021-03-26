#!/usr/bin/env python3
# coding: utf8

import argparse
import codecs
import datetime
import logging
import os
import re
import time
import sys
import platform
import collections
import hashlib
from selenium import webdriver


__author__ = "Nicolas SAPA"
__license__ = "CECILL-2.1"
__version__ = "0.1"
__maintainer__ = "Nicolas SAPA"
__email__ = "nico@byme.at"
__status__ = "Alpha"

if __name__ == "__main__":
    p = argparse.ArgumentParser()

    p.add_argument('--verbose',
                   action='store_true',
                   help='Enable debug output')

    args = p.parse_args()

    # Setup logging
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    log_format = {
        'fmt': '%(asctime)s %(levelname)s %(name)s %(message)s',
        'datefmt': '%Y-%m-%d %H:%M:%S.%f %Z'
    }
    log_formatter = CustomFormatter(**log_format)

    log_level = logging.DEBUG if args.verbose else logging.INFO

    log_stdout_handler = logging.StreamHandler(sys.stdout)
    log_stdout_handler.setLevel(log_level)
    log_stdout_handler.setFormatter(log_formatter)
    root_logger.addHandler(log_stdout_handler)

    log_file_handler = logging.FileHandler('pgo2mbox.log', 'a', 'utf-8')
    log_file_handler.setFormatter(log_formatter)
    root_logger.addHandler(log_file_handler)

    logging.info("selenium-firefox-proxy version %s by %s <%s>", __version__,
                     __author__, __email__)
    logging.info("This %s software is licensed under %s", __status__,
                     __license__)

    logging.info('Initializing Firefox...')

