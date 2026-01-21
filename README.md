# fanfictionnet_ff_proxy: an experimental "proxy" for fanfiction.net
> [!WARNING]
> Very hacky/buggy code - USE WITH CAUTION

This python3 script help FanFicFare bypass the Cloudflare challenge on FanFiction.net by 
making the user manually resolve the captcha.

## INSTALLATION
First, check the docs folder. If the documentation for your platform is missing, try:
1. Create a new python virtual env in ~/temp/ffproxy with ``python -m venv ~/temp/ffproxy``
2. Update pip in the venv: ``~/temp/ffproxy/bin/python -m pip install --upgrade pip``
3. Install the requirements in the venv: ``~/temp/ffproxy/bin/python -m pip install -r requirements.txt``

### FanFicFare Configuration
You need to edit FanFicFare' ``personal.ini`` to enable this proxy.
Change the :

```INI
[www.fanfiction.net]
use_nsapa_proxy:true
use_cloudscraper:false
```

## USAGE
* Run ``~/temp/ffproxy/bin/python ./chrome_content.py``
* Wait until you see ``Listening on 127.0.0.1:8888``
* You can now use FanFicFare with this proxy :)

## TESTING
Run in FanFicFare folder:
```Shell
PYTHONPATH=.
export PYTHONPATH
python3 ./fanficfare/cli.py -c personnal.ini -d 'https://www.fanfiction.net/s/12266465/1/' 
```
> [!IMPORTANT]
> If you see ``Complete the captcha then press enter``, switch to the Chromium window and do the captcha. \
> Press Enter when you're done, the page will reload and FanFicFare should be able to download the fiction.


