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
import base64
from selenium import webdriver
from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

__author__ = "Nicolas SAPA"
__license__ = "CECILL-2.1"
__software__ = "fanfictionnet_ff_proxy"
__version__ = "0.1"
__maintainer__ = "Nicolas SAPA"
__email__ = "nico@byme.at"
__status__ = "Alpha"

stay_in_mainloop = 1
exit_triggered = 0


def prepare_firefox():
    # Initialize Firefox & load the cookie store
    logger = logging.getLogger(name="prepare_firefox")

    service_log_path = './geckodriver.log' if args.verbose else '/dev/null'

    try:
        logging.info('Initializing Firefox...')
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
    logger.info('Trying to load existing cookie...')
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
            if cookie['domain'].startswith('.www.'):  #Yes, it happened...
                prefix = "http://"
                cookie['domain'] = cookie['domain'].replace('.www.', 'www.')

            driver.get('{}{}'.format(prefix, cookie['domain']))
            driver.add_cookie(cookie)
        logger.debug('Added %i cookie(s)', len(cookies))

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
    global exit_triggered
    global stay_in_mainloop

    logger = logging.getLogger(name="signal_handler")

    if exit_triggered == 1:
        logger.info('Got SIGINT a second time, exiting')
        sys.exit(4)

    logger.info('Got SIGINT, breaking the main loop...')

    stay_in_mainloop = 0
    exit_triggered = 1

    return True


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


def get_image_content_as_bytes(driver, uri):
    logger = logging.getLogger(name="get_image_content_as_bytes")
    # From https://stackoverflow.com/questions/47424245/how-to-download-an-image-with-python-3-selenium-if-the-url-begins-with-blob/47425305#47425305
    result = driver.execute_async_script(
        """
    var uri = arguments[0];
    var callback = arguments[1];
    var toBase64 = function(buffer){for(var r,n=new Uint8Array(buffer),t=n.length,a=new Uint8Array(4*Math.ceil(t/3)),i=new Uint8Array(64),o=0,c=0;64>c;++c)i[c]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charCodeAt(c);for(c=0;t-t%3>c;c+=3,o+=4)r=n[c]<<16|n[c+1]<<8|n[c+2],a[o]=i[r>>18],a[o+1]=i[r>>12&63],a[o+2]=i[r>>6&63],a[o+3]=i[63&r];return t%3===1?(r=n[t-1],a[o]=i[r>>2],a[o+1]=i[r<<4&63],a[o+2]=61,a[o+3]=61):t%3===2&&(r=(n[t-2]<<8)+n[t-1],a[o]=i[r>>10],a[o+1]=i[r>>4&63],a[o+2]=i[r<<2&63],a[o+3]=61),new TextDecoder("ascii").decode(a)};
    var xhr = new XMLHttpRequest();
    xhr.responseType = 'arraybuffer';
    xhr.onload = function(){ callback(toBase64(xhr.response)) };
    xhr.onerror = function(){ callback(xhr.status) };
    xhr.open('GET', uri);
    xhr.send();
    """, uri)
    if type(result) == int:
        logger.error("Failed to grab file content with status %s" % result)
        return False
    return base64.b64decode(result)


def get_document_content_type(driver):
    logger = logging.getLogger(name="get_file_content_as_bytes")
    result = driver.execute_script('return document.contentType;')
    if type(result) != str:
        logger.error('Failed to get document.contentType')
        return False
    return result


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

    p.add_argument('--port', type=int, default=8888, help='TCP port listened')

    args = p.parse_args()

    # Defaults value
    log_level = logging.DEBUG if args.verbose else logging.INFO
    if args.write_log:
        log_filename = '{}.log'.format(__software__)
        if args.log_filename is not None:
            log_filename = args.log_filename

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

    logging.info("%s version %s by %s <%s>", __software__, __version__,
                 __author__, __email__)
    logging.info("This %s software is licensed under %s", __status__,
                 __license__)

    driver = prepare_firefox()
    if driver is False:
        logging.error('Initializing Firefox failed, exiting')
        exit(1)
    logging.info('Firefox is initialized & ready to works')

    signal.signal(signal.SIGINT, sigint_handler)

    logging.info('Will listen on port %i', args.port)

    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        serversocket.bind(('127.0.0.1', args.port))
    except Exception as e:
        logging.error('Bind failed: %s', e.message)
        exit(3)
    serversocket.listen(5)
    logging.info('Ready to accept command!')

    time_last_cookie_dump = time.monotonic()

    while (stay_in_mainloop):
        if (time.monotonic() - time_last_cookie_dump) > 60:
            cookie_dump()
            time_last_cookie_dump = time.monotonic()

        (clientsocket, s_address) = serversocket.accept()

        buffer_length = 1024
        message_complete = False
        while not message_complete:
            data_from_client = clientsocket.recv(buffer_length)
            if len(data_from_client) < buffer_length:
                break

        logging.debug('Received data from client %s:%i: %s', s_address[0],
                      s_address[1], repr(data_from_client))
        new_url = data_from_client.decode("utf-8").strip('\n')
        url_type = None

        driver.get(new_url)

        try:
            driver.refresh()
        except UnexpectedAlertPresentException:
            driver.switch_to.alert.accept()

        url_type = get_document_content_type(driver)

        try:
            logging.info('Current URL = %s, page title = %s, mimetype = %s',
                         driver.current_url, driver.title, url_type)
        except UnexpectedAlertPresentException:
            driver.switch_to.alert.accept()

        if driver.title.startswith('Attention Required!'):
            if cloudfare_clickcaptcha():
                driver.get(new_url)
                url_type = get_document_content_type(driver)
                try:
                    logging.info(
                        'Current URL = %s, page title = %s, mimetype = %s',
                        driver.current_url, driver.title, url_type)
                except UnexpectedAlertPresentException:
                    driver.switch_to.alert.accept()
                    logging.debug('Accepted an alert')
                cookie_dump()

        document_type = 'binary'
        if url_type == 'text/html':
            document_type = 'text'
            document_as_bytes = driver.page_source.encode('utf-8')
        if url_type.startswith('image/'):
            document_type = 'image'
            document_as_bytes = get_image_content_as_bytes(
                driver, driver.current_url)

        clientsocket.send(
            str(len(document_as_bytes)).encode('utf-8') + b'||' +
            document_type.encode('utf-8') + b"$END_OF_HEADER$")  #len
        clientsocket.sendall(document_as_bytes)
        clientsocket.close()

        time.sleep(2)

    serversocket.close()
    cleanup()
    sys.exit(0)
