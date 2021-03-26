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


def prepare_firefox():
    logger = logging.getLogger(name="prepare_firefox")
    try:
        driver = webdriver.Firefox()
    except Exception as e:
        logger.error("Failed to initialize Firefox: %s", e.message)
        return False

    logger.debug('Firefox %s on %s have started (pid = %i)',
                 driver.capabilities['browserVersion'],
                 driver.capabilities['platformName'],
                 driver.capabilities['moz:processID'])

    try:
        addon_id = driver.install_addon(os.path.abspath(extension_path))
    except Exception as e:
        logger.error('Failed to install Privacy Pass: %s', e.message)
        return False
    else:
        logger.debug('Successfully installed Privacy Pass (id = %s)', addon_id)

    try:
        driver.get('https://www.hcaptcha.com/privacy-pass')
    except Exception as e:
        logger.error('Cannot navigate to hcaptcha: %s', e.message)
        return False

    input('Please resolve some captcha to get credits then press enter')

    return driver


class CustomFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        if '%f' in datefmt:
            datefmt = datefmt.replace('%f', '%03d' % record.msecs)
        return logging.Formatter.formatTime(self, record, datefmt)


if __name__ == "__main__":
    p = argparse.ArgumentParser()

    p.add_argument('--verbose',
                   action='store_true',
                   help='Enable debug output')

    p.add_argument('--write-log',
                   action='store_true',
                   help='Append output to the logfile')

    p.add_argument('--log-filename', help='Path to the log file')

    p.add_argument('--extension-path', help='Path to the XPI of Privacy Pass')

    args = p.parse_args()

    # Defaults value
    log_level = logging.DEBUG if args.verbose else logging.INFO
    if args.write_log:
        log_filename = 'selenium-firefox-proxy.log'
        if args.log_filename is not None:
            log_filename = args.log_filename

    extension_path = './privacy_pass-2.0.8-fx.xpi'
    if args.extension_path is not None:
        extension_path = args.extension_path

    # Setup logging
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    log_format = {
        'fmt': '%(asctime)s %(levelname)s %(name)s %(message)s',
        'datefmt': '%Y-%m-%d %H:%M:%S.%f %Z'
    }
    log_formatter = CustomFormatter(**log_format)

    log_stdout_handler = logging.StreamHandler(sys.stdout)
    log_stdout_handler.setLevel(log_level)
    log_stdout_handler.setFormatter(log_formatter)
    root_logger.addHandler(log_stdout_handler)

    if args.write_log:
        log_file_handler = logging.FileHandler(log_filename, 'a', 'utf-8')
        log_file_handler.setFormatter(log_formatter)
        root_logger.addHandler(log_file_handler)

    logging.info("selenium-firefox-proxy version %s by %s <%s>", __version__,
                 __author__, __email__)
    logging.info("This %s software is licensed under %s", __status__,
                 __license__)

    driver = prepare_firefox()
    if driver is False:
        logging.error('Initializing Firefox failed, exiting')
        exit(1)

    logging.info('Break here')
