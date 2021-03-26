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
import json
import signal
import random
import socket
from selenium import webdriver
from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

__author__ = "Nicolas SAPA"
__license__ = "CECILL-2.1"
__version__ = "0.1"
__maintainer__ = "Nicolas SAPA"
__email__ = "nico@byme.at"
__status__ = "Alpha"

stay_in_mainloop = 1


def prepare_firefox():
    # Initialize Firefox, load the cookie store, install Privacy Pass, ask the user to do some captcha
    logger = logging.getLogger(name="prepare_firefox")

    service_log_path = './geckodriver.log' if args.verbose else '/dev/null'

    try:
        driver = webdriver.Firefox(service_log_path=service_log_path)
    except Exception as e:
        logger.error("Failed to initialize Firefox: %s", e.message)
        return False

    logger.debug('Firefox %s on %s have started (pid = %i)',
                 driver.capabilities['browserVersion'],
                 driver.capabilities['platformName'],
                 driver.capabilities['moz:processID'])

    try:
        driver.get('http://www.example.com')
    except Exception as e:
        logger.error('Cannot navigate to example.com: %s', e.message)
        return False

    cookies = list()
    try:
        with open(cookie_store, 'r') as cookie_file:
            cookies = json.load(codecs.getwriter('utf-8')(cookie_file))
    except:
        logger.debug('No cookie to import...')
    else:
        for cookie in cookies:
            prefix = "http://"
            if cookie['domain'].startswith('.'):
                prefix = "http://www"

            driver.get('{}{}'.format(prefix, cookie['domain']))
            driver.add_cookie(cookie)
        logger.debug('Added %i cookie(s)', len(cookies))
    """ Don't seem to work
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
    """
    return driver


def cookie_dump():
    # Export as a json the cookie stored in the browser
    logger = logging.getLogger(name="cookie_dump")

    with open(cookie_store, 'wb') as cookie_file:
        logger.debug('Dumping cookies to %s', cookie_store)
        json.dump(driver.get_cookies(),
                  codecs.getwriter('utf-8')(cookie_file),
                  ensure_ascii=False,
                  indent=4)

    return


def cleanup():
    # Try to close properly the driven browser
    logger = logging.getLogger(name="cleanup")
    try:
        driver.quit()
    except Exception as e:
        logger.error('Cleanup failed: %s', e.message)
    return


def sigint_handler(signal, frame):
    logger = logging.getLogger(name="signal_handler")
    logger.info('Got SIGINT, breaking the main loop...')
    global stay_in_mainloop
    stay_in_mainloop = 0
    return


def cloudfare_clickcaptcha():
    # Try to validate hCaptcha
    logger = logging.getLogger(name="cloudfare_clickcaptcha")

    input("Complete the captcha then press enter")

    timeout = 10
    try:
        # FIXME: hardcoded element for fanfiction.net
        element_present = EC.presence_of_element_located((By.ID, 'storytext'))
        WebDriverWait(driver, timeout).until(element_present)
    except TimeoutException:
        logger.error('Failed to load the story text')

    try:
        driver.switch_to.alert.accept()
    except:
        pass

    logger.info('Found the storytext!')
    return True


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

    p.add_argument('--cookie-filename', help='Path to the cookie store')

    p.add_argument('--extension-path', help='Path to the XPI of Privacy Pass')

    p.add_argument('--port', type=int, default=8888, help='TCP port listened')

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

    cookie_store = './cookie.json'
    if args.cookie_filename is not None:
        cookie_store = args.cookie_filename

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

    signal.signal(signal.SIGINT, sigint_handler)

    logging.info('Will listen on port %i', args.port)

    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        serversocket.bind(('127.0.0.1', args.port))
    except Exception as e:
        logging.error('Bind failed: %s', e.message)
        exit(3)
    serversocket.listen(5)

    time_last_cookie_dump = time.monotonic()

    while (stay_in_mainloop):
        if (time.monotonic() - time_last_cookie_dump) > 60:
            cookie_dump()
            time_last_cookie_dump = time.monotonic()

        (clientsocket, s_address) = serversocket.accept()

        chunks = []
        bytes_recd = 0
        MSGLEN = 4096  #Should be enough for any URL
        while bytes_recd < MSGLEN:
            chunk = clientsocket.recv(min(MSGLEN - bytes_recd, 2048))
            if chunk == b'':
                logging.debug('Connection closed by the client %s:%i',
                              s_address[0], s_address[1])
                break
            chunks.append(chunk)
            bytes_recd = bytes_recd + len(chunk)
        data_from_client = b''.join(chunks)

        logging.debug('Received data from client: %s', repr(data_from_client))
        new_url = data_from_client.decode("utf-8").strip('\n')

        driver.get(new_url)

        try:
            driver.refresh()
        except UnexpectedAlertPresentException:
            driver.switch_to.alert.accept()

        try:
            logging.info('Current URL = %s, page title = %s',
                         driver.current_url, driver.title)
        except UnexpectedAlertPresentException:
            driver.switch_to.alert.accept()

        if driver.title.startswith('Attention Required!'):
            if cloudfare_clickcaptcha():
                driver.get(new_url)
                try:
                    logging.info('Current URL = %s, page title = %s',
                                 driver.current_url, driver.title)
                except UnexpectedAlertPresentException:
                    driver.switch_to.alert.accept()
                    logging.debug('Accepted an alert')
                cookie_dump()

        clientsocket.send(driver.page_source.encode('utf-8'))
        clientsocket.close()

        time.sleep(2)

    serversocket.close()
    cleanup()
    exit()
