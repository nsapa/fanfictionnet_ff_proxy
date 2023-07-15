FROM fedora:38

ENV HOME /opt/proxy
ENV LC_ALL C.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US.UTF-8

RUN adduser -c "proxy user" proxy_user
RUN adduser -c "gui user" gui_user
RUN mkdir -p /opt/proxy/code /opt/proxy/workdir && chown proxy_user /opt/proxy/workdir

WORKDIR /opt/proxy/workdir

RUN dnf -y --refresh upgrade && dnf -y --setopt=install_weak_deps=False install xorg-x11-drivers x11vnc xdotool xorg-x11-xinit xorg-x11-xauth mesa-dri-drivers wget tar supervisor net-tools fluxbox gnupg2 python3-numpy python3-pip python3-pip procps-ng chromium fedora-chromium-config tini


ADD requirements.txt .
RUN su proxy_user -c "python3 -m pip install --user -U pip"
RUN su proxy_user -c "python3 -m pip install --user -r requirements.txt"

RUN wget -O - -nv https://github.com/novnc/noVNC/archive/refs/tags/v1.4.0.tar.gz | tar -xz -C /opt/proxy/workdir/ && mv /opt/proxy/workdir/noVNC-1.4.0 /opt/proxy/code/novnc && ln -s /opt/proxy/code/novnc/vnc_lite.html /opt/proxy/code/novnc/index.html
RUN wget -O - -nv https://github.com/novnc/websockify/archive/refs/tags/v0.11.0.tar.gz | tar -xz -C /opt/proxy/workdir/ && mv /opt/proxy/workdir/websockify-0.11.0 /opt/proxy/code/novnc/utils/websockify

WORKDIR /tmp
RUN rm -rf /opt/proxy/workdir && dnf -y clean all

ADD docker_files/supervisord.conf /opt/proxy/code/supervisord.conf
ADD docker_files/xorg.conf /etc/X11/xorg.conf
ADD chrome_content.py /opt/proxy/code/chrome_content.py

RUN echo "allowed_users=anybody" > /etc/X11/Xwrapper.config

EXPOSE 8888
EXPOSE 8080
ENV DISPLAY :0

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/bin/sh", "-c", "/usr/bin/supervisord -c /opt/proxy/code/supervisord.conf && su proxy_user -c '/usr/bin/python3 /opt/proxy/code/chrome_content.py --chrome-path /usr/bin/chromium-browser --disable-console-title --address 0.0.0.0'"]
