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
import undetected_chromedriver as uc
try:
    uc.install()
except Exception as e:
    print('Failed to initialize Undetected Chrome: %s' % str(e))
    sys.exit(5)

from selenium import webdriver
from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException, WebDriverException
from selenium.webdriver.chrome.options import Options as SeleniumChromeOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

__author__ = "Nicolas SAPA"
__license__ = "CECILL-2.1"
__software__ = "fanfictionnet_ff_proxy"
__version__ = "0.4"
__maintainer__ = "Nicolas SAPA"
__email__ = "nico@byme.at"
__status__ = "Alpha"

stay_in_mainloop = 1
exit_triggered = 0
time_last_cookie_dump = time.monotonic()
Chrome_pid = None


def prepare_Chrome(chrome_path):
    global Chrome_pid
    # Initialize Chrome & load the cookie store
    logger = logging.getLogger(name="prepare_Chrome")

    service_log_path = './chrome_service_log.log' if args.verbose else os.devnull

    options = SeleniumChromeOptions()

    if chrome_path is not None:
        logger.debug('Forcing binary path to %s', chrome_path)
        options.binary_location = chrome_path

    try:
        driver = webdriver.Chrome(service_log_path=service_log_path,
                                  chrome_options=options)
    except Exception as e:
        logger.error("Failed to initialize Chrome: %s", str(e))
        return False

    logger.info(
        colorama.Style.BRIGHT + 'Chrome %s on %s' + colorama.Style.RESET_ALL +
        ' started', driver.capabilities['browserVersion'],
        driver.capabilities['platformName'])

    # Store Chrome' pid for last ressort cleanup
    chromedriver_pid = driver.service.process.pid
    Chrome_pid = psutil.Process(chromedriver_pid).children()[0].pid

    logger.info(
        'chromedriver version %s running as pid ' + colorama.Style.BRIGHT +
        '%i' + colorama.Style.RESET_ALL + ', Chrome running as pid ' +
        colorama.Style.BRIGHT + '%i' + colorama.Style.RESET_ALL,
        uc.ChromeDriverManager().get_release_version_number().vstring,
        chromedriver_pid, Chrome_pid)

    try:
        driver.get('http://www.example.com')
    except Exception as e:
        logger.error('Cannot navigate to example.com: %s', str(e))
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
    # This function is licensed under Creative Commons Attribution-ShareAlike 3.0 Unported (CC BY-SA 3.0)
    # Original author: Florent B. // https://stackoverflow.com/users/2887618/florent-b
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


def notify_user(title, message):
    plyer.notification.notify(title, message, timeout=999)
    return


def mainloop():
    global time_last_cookie_dump
    logger = logging.getLogger(name="mainloop")

    if (time.monotonic() - time_last_cookie_dump) > 60:
        cookie_dump()
        time_last_cookie_dump = time.monotonic()

    (clientsocket, s_address) = serversocket.accept()
    clientsocket.setblocking(True)

    buffer_length = 1024
    message_complete = False
    while not message_complete:
        data_from_client = clientsocket.recv(buffer_length)
        if len(data_from_client) < buffer_length:
            break

    logger.debug('Received data from client %s:%i: %s', s_address[0],
                 s_address[1], repr(data_from_client))
    new_url = data_from_client.decode("utf-8").strip('\n')
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

    try:
        driver.refresh()
    except UnexpectedAlertPresentException:
        driver.switch_to.alert.accept()

    url_type = get_document_content_type(driver)

    try:
        logger.info(
            'Current URL = ' + colorama.Style.BRIGHT + '%s' +
            colorama.Style.NORMAL + ', page title = ' + colorama.Style.BRIGHT +
            '%s' + colorama.Style.NORMAL + ', mimetype = ' +
            colorama.Style.BRIGHT + '%s' + colorama.Style.RESET_ALL,
            driver.current_url, driver.title, url_type)
    except UnexpectedAlertPresentException:
        driver.switch_to.alert.accept()

    if driver.title.startswith('Attention Required!'):
        if cloudfare_clickcaptcha():
            driver.get(new_url)
            url_type = get_document_content_type(driver)
            try:
                logger.info(
                    'Current URL = ' + colorama.Style.BRIGHT + '%s' +
                    colorama.Style.NORMAL + ', page title = ' +
                    colorama.Style.BRIGHT + '%s' + colorama.Style.NORMAL +
                    ', mimetype = ' + colorama.Style.BRIGHT + '%s' +
                    colorama.Style.RESET_ALL, driver.current_url, driver.title,
                    url_type)
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
        document_as_bytes = get_image_content_as_bytes(driver,
                                                       driver.current_url)

    clientsocket.send(
        str(len(document_as_bytes)).encode('utf-8') + b'||' +
        document_type.encode('utf-8') + b"$END_OF_HEADER$")  #len
    clientsocket.sendall(document_as_bytes)
    clientsocket.close()

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

    p.add_argument('--address',
                   default='127.0.0.1',
                   help='Listen on address (default 127.0.0.1)')
    p.add_argument('--port',
                   type=int,
                   default=8888,
                   help='Listen on tcp port (default 8888)')

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

    driver = prepare_Chrome(chrome_path)
    if driver is False:
        logging.error('Initializing Chrome failed, exiting')
        exit(1)
    logging.info('Chrome is initialized & ready to works')

    ## Signals handler
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

    # Windows is different
    if platform.system() == 'Windows':
        import win32api  #not used anywhere else

        try:
            win32api.SetConsoleCtrlHandler(win32_exit_handler, True)
        except Exception as e:
            logging.error('Call to SetConsoleCtrlHandler failed: %s', str(e))

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
        driver.quit()
        exit(3)

    # Configure the socket backlog
    serversocket.listen(5)

    logging.info(
        'Listening on ' + colorama.Style.BRIGHT + '%s:%i' +
        colorama.Style.RESET_ALL,
        serversocket.getsockname()[0],
        serversocket.getsockname()[1])

    while (stay_in_mainloop):
        try:
            mainloop()
        except WebDriverException as e:
            logging.error('Unrecoverable error from Selenium: %s', e.msg)
            serversocket.close()
            sys.exit(6)
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
    try:
        driver.close()
        driver.quit()
    except Exception as e:
        logging.error('Quitting selenium failed: %s', str(e))
        if type(Chrome_pid) == int:
            logging.info('Killing pid %i as last ressort cleanup.', Chrome_pid)
            os.kill(Chrome_pid, signal.SIGTERM)

    logging.info('Exiting...')
    sys.exit(0)
