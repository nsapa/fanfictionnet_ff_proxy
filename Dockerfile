FROM debian:10.10

ENV HOME /opt/proxy
ENV DEBIAN_FRONTEND noninteractive
ENV LC_ALL C.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US.UTF-8

RUN adduser --disabled-password --gecos "proxy user" proxy_user
RUN adduser --disabled-password --gecos "gui user" gui_user
RUN mkdir -p /opt/proxy/code /opt/proxy/workdir
RUN chown proxy_user /opt/proxy/workdir

WORKDIR /opt/proxy/workdir

RUN apt-get update
RUN apt-get -y full-upgrade 
RUN apt-get -y install xserver-xorg-video-dummy x11vnc xdotool wget tar supervisor net-tools fluxbox gnupg2 python3-numpy x11-xserver-utils python3-pip procps curl x11vnc



RUN echo 'deb http://download.opensuse.org/repositories/home:/ungoogled_chromium/Debian_Buster/ /' | tee /etc/apt/sources.list.d/home-ungoogled_chromium.list
RUN curl 'https://download.opensuse.org/repositories/home:/ungoogled_chromium/Debian_Buster/Release.key' | gpg --dearmor | tee /etc/apt/trusted.gpg.d/home-ungoogled_chromium.gpg > /dev/null
RUN apt-get update
RUN apt-get -y install ungoogled-chromium

ADD requirements.txt .
RUN su proxy_user -c "python3 -m pip install --user -U pip"
RUN su proxy_user -c "python3 -m pip install --user -r requirements.txt"

RUN wget -O - -nv https://github.com/novnc/noVNC/archive/refs/tags/v1.2.0.tar.gz | tar -xz -C /opt/proxy/workdir/ && mv /opt/proxy/workdir/noVNC-1.2.0 /opt/proxy/code/novnc && ln -s /opt/proxy/code/novnc/vnc_lite.html /opt/proxy/code/novnc/index.html
RUN wget -O - -nv https://github.com/novnc/websockify/archive/refs/tags/v0.10.0.tar.gz | tar -xz -C /opt/proxy/workdir/ && mv /opt/proxy/workdir/websockify-0.10.0 /opt/proxy/code/novnc/utils/websockify

WORKDIR /tmp
RUN rm -rf /opt/proxy/workdir
RUN apt-get clean

ADD docker_files/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
ADD docker_files/xorg.conf /opt/proxy/code/xorg.conf
ADD chrome_content.py /opt/proxy/code/chrome_content.py

EXPOSE 8888
EXPOSE 8080
ENV DISPLAY :0

CMD ["/usr/bin/supervisord"]
