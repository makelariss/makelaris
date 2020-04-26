FROM python:2.7

ENV DEBIAN_FRONTEND noninteractive

# Install system dependencies
RUN apt-get update && apt-get install supervisor unzip default-mysql-server -yqq

# Install google chrome
RUN wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add -
RUN sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list'
RUN apt-get update -y
RUN apt-get install google-chrome-stable -yqq

WORKDIR /tmp

# Install chromedriver
RUN wget -O chromedriver.zip http://chromedriver.storage.googleapis.com/`curl -sS chromedriver.storage.googleapis.com/LATEST_RELEASE`/chromedriver_linux64.zip
RUN unzip chromedriver.zip chromedriver -d /usr/local/bin/

# install phantomjs
RUN wget https://bitbucket.org/ariya/phantomjs/downloads/phantomjs-2.1.1-linux-x86_64.tar.bz2 
RUN tar -jxf phantomjs-2.1.1-linux-x86_64.tar.bz2 && cp phantomjs-2.1.1-linux-x86_64/bin/phantomjs /usr/bin/phantomjs

# Upgrade pip
RUN python -m pip install --upgrade pip

# Install dependencies
RUN pip install pycurl selenium Flask Pillow pymysql

# Set display port to avoid crash
ENV OPENSSL_CONF /etc/ssl/
ENV DISPLAY=:99

# Setup app
RUN mkdir -p /app
WORKDIR /app

# Add application & flag
COPY challenge .
RUN mv flag flag_`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1`

# Clean up
RUN apt-get clean && rm -rf /var/lib/apt/lists/* && rm -rf /tmp/*

# Setup supervisor
COPY config/supervisord.conf /etc/supervisord.conf

# Expose port the server is reachable on
EXPOSE 1337

# Run mysql as root
RUN echo '[mysqld]\nuser=root' > /etc/mysql/my.cnf

# Copy database initialisation script
COPY entrypoint.sh /entrypoint.sh

# Run supervisord
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]