### Installing on macOS
This was tested on macOS Catalina.

* Open the terminal and install [Homebrew](https://brew.sh/):
  ```
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  ```

* Install Python 3
  ```
  brew install python3
  ```

* Quit and relaunch the terminal

* Run ``which python3``, you should ``/usr/local/bin/python3``. If not, [Homebrew](https://brew.sh/) failed to install Python 3. Stop here.

* If [Google Chrome](https://www.google.com/chrome/) is not already installed, install [Ungoogled Chromium](https://github.com/Eloston/ungoogled-chromium)
  ```
  brew install --cask eloston-chromium
  ```

* Download the software in ~/Dev
  ```
  mkdir ~/Dev
  cd ~/Dev
  git clone https://github.com/nsapa/fanfictionnet_ff_proxy
  ```

* Install the required Python dependancy
  ```
  cd fanfictionnet_ff_proxy
  pip3 install --user -r requirements.txt 
  ```

* If you have installed [Ungoogled Chromium](https://github.com/Eloston/ungoogled-chromium), lauch the `macos_chromium.sh` script: you should see `Listening on 127.0.0.1:8888`
  ```
  ./macos_chromium.sh 
  ```
