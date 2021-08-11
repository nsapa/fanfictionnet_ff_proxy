#!/usr/bin/env python3
# coding: utf8

import argparse
import codecs
import colorama
import datetime
import logging
import os
import re
import time
import sys
import platform
import psutil
import plyer
import collections
import hashlib
import json
import signal
import random
import socket
import base64

# CECILL-2.1 5.3.4 have a compatibility clause with GPL-3.0
import undetected_chromedriver.v2 as uc

from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException, WebDriverException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

__author__ = "Nicolas SAPA"
__license__ = "CECILL-2.1"
__software__ = "fanfictionnet_ff_proxy"
__version__ = "0.5.2"
__maintainer__ = "Nicolas SAPA"
__email__ = "nico@byme.at"
__status__ = "Alpha"

stay_in_mainloop = 1
exit_triggered = 0
time_last_cookie_dump = time.monotonic()


class ChromeVersionFinder:
    def __init__(self, chrome_path=None):
        import subprocess

        if chrome_path is not None:
            self.path = chrome_path
        else:
            try:
                self.path = uc.find_chrome_executable()
            except Exception as e:
                # Should not happen
                error = f'Cannot auto-detect Chrome path: {str(e)}'
                raise Exception(error)
            if self.path is None:
                raise Exception('Cannot auto-detect Chrome path')

        try:
            ver_str = subprocess.check_output([self.path, '--version'])
        except Exception as e:
            error = f'Execution of {self.path} --version failed: {str(e)}'
            raise Exception(error)

        try:
            version = int(ver_str.split()[1].decode().split('.')[0])
        except Exception as e:
            error = f'Cannot extract version: {str(e)}'
            raise Exception(error)

        self.version = version


class ProxiedBrowser:
    def __init__(self, chrome_path=None, verbose=False, chrome_version=None):
        self.chrome_path = chrome_path
        self.verbose = verbose
        self.pid = {}
        self.driver = None

        # Initialize Chrome & load the cookie store
        logger = logging.getLogger(name="ProxiedBrowser(init)")

        service_log_path = './chrome_service_log.log' if self.verbose else os.devnull

        options = uc.ChromeOptions()

        if self.chrome_path is not None:
            logger.debug('Forcing binary path to %s', chrome_path)
            options.binary_location = self.chrome_path

        try:
            self.driver = driver = uc.Chrome(service_log_path=service_log_path,
                                             options=options,
                                             version_main=chrome_version)
        except Exception as e:
            logger.error("Failed to initialize Chrome: %s", str(e))
            raise e

        logger.info(
            colorama.Style.BRIGHT + 'Chrome %s on %s' +
            colorama.Style.RESET_ALL + ' started',
            driver.capabilities['browserVersion'],
            driver.capabilities['platformName'] if
            driver.capabilities['platformName'] != '' else 'unknow platform')

        # Store Chrome' pid for last ressort cleanup
        self.pid['chromedriver'] = driver.service.process.pid
        self.pid['chrome'] = driver.browser.pid

        logger.info(
            'chromedriver version %s running as pid ' + colorama.Style.BRIGHT +
            '%i' + colorama.Style.RESET_ALL +
            ', Chrome version %s running as pid ' + colorama.Style.BRIGHT +
            '%i' + colorama.Style.RESET_ALL,
            driver.capabilities['chrome']['chromedriverVersion'],
            self.pid['chromedriver'], driver.capabilities['browserVersion'],
            self.pid['chrome'])

        try:
            driver.get('chrome://version')
        except Exception as e:
            logger.error(
                'Cannot navigate to internal page. Something is REALLY broken; %s',
                str(e))
            raise e

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
                    cookie['domain'] = cookie['domain'].replace(
                        '.www.', 'www.')

                driver.get('{}{}'.format(prefix, cookie['domain']))
                if 'sameSite' in cookie:
                    if cookie['sameSite'] == 'None':
                        cookie['sameSite'] = 'Strict'
                driver.add_cookie(cookie)
            logger.debug('Added %i cookie(s)', len(cookies))

    def cookie_dump(self):
        # Export as a json the cookie stored in the browser
        logger = logging.getLogger(name="ProxiedBrowser(cookie_dump)")

        with open(cookie_store, 'wb') as cookie_file:
            logger.debug('Dumping cookies to %s', cookie_store)
            json.dump(self.driver.get_cookies(),
                      codecs.getwriter('utf-8')(cookie_file),
                      ensure_ascii=False,
                      indent=4)
        return

    # Some wrappers
    def get(self, url):
        return self.driver.get(url)

    def current_url(self):
        return self.driver.current_url

    def title(self):
        return self.driver.title

    def page_source(self):
        return self.driver.page_source

    def execute_async_script(self, code, uri):
        return self.driver.execute_async_script(code, uri)

    def execute_script(self, code):
        return self.driver.execute_async_script(code)

    def get_image_content_as_bytes(self, uri):
        logger = logging.getLogger(
            name="ProxiedBrowser(get_image_content_as_bytes)")
        # From https://stackoverflow.com/questions/47424245/how-to-download-an-image-with-python-3-selenium-if-the-url-begins-with-blob/47425305#47425305
        # This function is licensed under Creative Commons Attribution-ShareAlike 3.0 Unported (CC BY-SA 3.0)
        # Original author: Florent B. // https://stackoverflow.com/users/2887618/florent-b
        result = self.driver.execute_async_script(
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

    def get_document_content_type(self):
        logger = logging.getLogger(
            name="ProxiedBrowser(get_file_content_as_bytes)")
        result = self.driver.execute_script('return document.contentType;')
        if type(result) != str:
            logger.error('Failed to get document.contentType')
            return False
        return result

    def suicide(self):
        # Kill this instance
        logger = logging.getLogger(name="ProxiedBrowser(suicide)")
        driver = self.driver
        try:
            driver.close()
            driver.quit()
        except Exception as e:
            logging.error('Quitting selenium failed: %s', str(e))
            if type(self.pid['chrome']) == int:
                logger.info(
                    colorama.Style.BRIGHT + 'Killing Chrome with pid %i' +
                    colorama.Style.NORMAL + ' as last ressort cleanup.',
                    self.pid['chrome'])
                os.kill(self.pid['chrome'], signal.SIGTERM)
            if type(self.pid['chromedriver']) == int:
                logger.info(
                    colorama.Style.BRIGHT +
                    'Killing chrome driver with pid %i' +
                    colorama.Style.NORMAL + ' as last ressort cleanup.',
                    self.pid['chromedriver'])
                os.kill(self.pid['chromedriver'], signal.SIGTERM)


def unix_exit_handler(mysignal, myframe):
    global exit_triggered
    global stay_in_mainloop

    logger = logging.getLogger(name="unix_exit_handler")

    if exit_triggered == 1:
        logger.info('Got %s a second time, exiting',
                    signal.strsignal(mysignal))
        sys.exit(4)

    logger.info('Got %s, telling the main loop to exit...',
                signal.strsignal(mysignal))
    stay_in_mainloop = 0
    exit_triggered = 1

    logging.info(colorama.Style.BRIGHT + 'Forcing' + colorama.Style.NORMAL +
                 ' the server socket to close.')
    serversocket.close()

    logging.getLogger('urllib3.connectionpool').setLevel(
        logging.CRITICAL)  #Don't show error from selenium

    return True


def win32_exit_handler(mysignal):
    #Fake a SIGINT
    unix_exit_handler(signal.SIGINT, None)

    return True


def cloudfare_clickcaptcha():
    # Try to validate hCaptcha
    logger = logging.getLogger(name="cloudfare_clickcaptcha")

    notify_user(
        'Captcha detected by {}'.format(__software__),
        'Please complete the captcha in Chrome then press Enter in the python console'
    )
    logger.info(colorama.Fore.RED +
                'Waiting for user to resolve the captcha: press ' +
                colorama.Style.BRIGHT + 'Enter' + colorama.Style.NORMAL +
                ' to continue' + colorama.Style.RESET_ALL)
    input()

    return True


def notify_user(title, message):
    plyer.notification.notify(title, message, timeout=999)
    return


def mainloop(driver):
    global time_last_cookie_dump
    logger = logging.getLogger(name="mainloop")

    if (time.monotonic() - time_last_cookie_dump) > 60:
        driver.cookie_dump()
        time_last_cookie_dump = time.monotonic()

    (clientsocket, s_address) = serversocket.accept()
    clientsocket.setblocking(False)
    clientsocket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

    #Code from https://code.activestate.com/recipes/408859/
    #Licenced under PSF by John Nielsen

    total_data = []
    data = ''
    begin = time.time()
    timeout = 2
    while True:
        #if you got some data, then break after wait sec
        if total_data and time.time() - begin > timeout:
            break
        #if you got no data at all, wait a little longer
        elif time.time() - begin > timeout * 2:
            break
        try:
            data = clientsocket.recv(8192)
            if data:
                total_data.append(data)
                begin = time.time()
            else:
                time.sleep(0.1)
        except:
            pass

    #End of Code from https://code.activestate.com/recipes/408859/

    data_from_client = b''.join(total_data).decode("utf-8")

    logger.debug('Received data from client %s:%i: %s', s_address[0],
                 s_address[1], repr(data_from_client))

    new_url = data_from_client.strip('\n')
    url_type = None

    try:
        driver.get(new_url)
    except TimeoutException as e:
        logger.error(
            'TimeOut while getting %s, resetting renderer with an internal page',
            new_url)
        driver.get('chrome://version')
    finally:
        driver.get(new_url)

    url_type = driver.get_document_content_type()

    logger.info(
        'Current URL = ' + colorama.Style.BRIGHT + '%s' +
        colorama.Style.NORMAL + ', page title = ' + colorama.Style.BRIGHT +
        '%s' + colorama.Style.NORMAL + ', mimetype = ' +
        colorama.Style.BRIGHT + '%s' + colorama.Style.RESET_ALL,
        driver.current_url(), driver.title(), url_type)

    if driver.title().startswith('Attention Required!'):
        if cloudfare_clickcaptcha():
            driver.get(new_url)
            url_type = driver.get_document_content_type()

            logger.info(
                'Current URL = ' + colorama.Style.BRIGHT + '%s' +
                colorama.Style.NORMAL + ', page title = ' +
                colorama.Style.BRIGHT + '%s' + colorama.Style.NORMAL +
                ', mimetype = ' + colorama.Style.BRIGHT +
                '%s' + colorama.Style.RESET_ALL, driver.current_url(),
                driver.title(), url_type)
            driver.cookie_dump()

    document_type = 'binary'
    if url_type == 'text/html':
        if encodeb64:
            document_type = 'text-b64'
            document_as_bytes = base64.standard_b64encode(
                driver.page_source().encode('utf-8'))
        else:
            document_type = 'text'
            document_as_bytes = driver.page_source().encode('utf-8')

    if url_type.startswith('image/'):
        document_type = 'image'
        document_as_bytes = driver.get_image_content_as_bytes(
            driver.current_url())

    clientsocket.setblocking(True)
    clientsocket.send(
        str(len(document_as_bytes)).encode('utf-8') + b'||' +
        document_type.encode('utf-8') + b"$END_OF_HEADER$")  #len
    clientsocket.sendall(document_as_bytes)
    clientsocket.close()

    clientsocket = None

    time.sleep(2)
    return


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

    p.add_argument('--chrome-path',
                   help='Path to the Chrome binary (default autodetect)')

    p.add_argument('--chrome-version', type=int, help='Force Chrome version')

    p.add_argument('--address',
                   default='127.0.0.1',
                   help='Listen on address (default 127.0.0.1)')

    p.add_argument('--port',
                   type=int,
                   default=8888,
                   help='Listen on tcp port (default 8888)')

    p.add_argument('--base64',
                   action='store_true',
                   help='Base64-encode the HTML source code')

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

    encodeb64 = False
    if args.base64:
        encodeb64 = True

    # Load colorama (it will patch some function on Windows)
    colorama.init()

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
    logging.info('Running on %s', platform.platform())

    chrome_path = None
    if args.chrome_path is not None:
        chrome_path = args.chrome_path

    chrome_version = None
    if args.chrome_version is not None:
        chrome_version = args.chrome_version
    else:
        try:
            cvf = ChromeVersionFinder(chrome_path)
        except Exception as e:
            logging.error(
                'Failed to detect Chrome version: %s. Use ' +
                colorama.Style.BRIGHT + '--chrome-path ' +
                colorama.Style.NORMAL + 'to specify Chrome path.', str(e))
            exit(2)
        chrome_version = cvf.version
        logging.debug('ChromeVersionFinder returned %i for %s', cvf.version,
                      cvf.path)

    driver = ProxiedBrowser(chrome_path, args.verbose, chrome_version)
    if driver is False:
        logging.error('Initializing Chrome failed, exiting')
        exit(1)
    logging.info('Chrome is initialized & ready to works')

    ## Signals handler
    # Windows is different
    if platform.system() == 'Windows':
        import win32api  #not used anywhere else

        try:
            win32api.SetConsoleCtrlHandler(win32_exit_handler, True)
        except Exception as e:
            logging.error('Call to SetConsoleCtrlHandler failed: %s', str(e))
    else:
        # On Unix, Control + C is SIGINT
        try:
            signal.signal(signal.SIGINT, unix_exit_handler)
        except Exception as e:
            logging.error('Failed to install SIGINT handler: %s', str(e))
        # Someone closed the terminal
        try:
            signal.signal(signal.SIGHUP, unix_exit_handler)
        except Exception as e:
            logging.error('Failed to install SIGHUP handler: %s', str(e))

    ## Time to create the server socket
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except Exception as e:
        logging.error('Failed to set SO_REUSEADDR on the server socket: %s',
                      str(e))

    try:
        serversocket.bind((args.address, args.port))
    except Exception as e:
        logging.error('Cannot create a TCP server: %s', str(e))
        #Try to keep the user computer clean without any lingering geckodriver
        driver.suicide()
        exit(3)

    # Configure the socket backlog
    serversocket.listen(5)

    logging.info(
        'Listening on ' + colorama.Style.BRIGHT + '%s:%i' +
        colorama.Style.RESET_ALL,
        serversocket.getsockname()[0],
        serversocket.getsockname()[1])

    if encodeb64:
        logging.info('Base64-encoding of HTML source code is ' +
                     colorama.Style.BRIGHT + 'ENABLED' +
                     colorama.Style.RESET_ALL)

    while (stay_in_mainloop):
        try:
            mainloop(driver)
        except WebDriverException as e:
            logging.error(
                colorama.Style.BRIGHT + 'Unrecoverable error' +
                colorama.Style.NORMAL +
                ' from Selenium: %s. Killing this instance...', e.msg)
            driver.suicide()
            driver = ProxiedBrowser(chrome_path, args.verbose,
                                    args.chrome_version)
            if driver is False:
                logging.error('Reinitialisation' + colorama.Style.BRIGHT +
                              ' failed' + colorama.Style.NORMAL +
                              '. Exiting :(')
                serversocket.close()
                exit(6)
            else:
                logging.info('Look like we are ' + colorama.Style.BRIGHT +
                             'operational' + colorama.Style.NORMAL +
                             ' again. Retry your request :)')
                continue

        except Exception as e:
            if exit_triggered:
                #The way we quit is ... not the python way.
                logging.debug('Exception in the main loop during exit (%s)',
                              str(e))
                break
            else:
                logging.error(
                    'Exception ' + colorama.Style.BRIGHT + '%s' +
                    colorama.Style.RESET_ALL + ' in the main loop (%s)',
                    e.__class__.__name__, str(e))
                # Try to reset the renderer with an internal page
                driver.get('chrome://version')
                continue

    try:
        serversocket.close()  #Should already have happened
    except Exception as e:
        logging.error('Failed to close server socket (%s', str(e))

    logging.info('Quitting selenium ...')
    driver.suicide()
    driver = None

    logging.info('Exiting...')
    sys.exit(0)
