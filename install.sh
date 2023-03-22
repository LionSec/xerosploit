#!/bin/bash

DIRECTORY=$(pwd)

# install deps
sudo apt install nmap hping3 build-essential ruby-dev libpcap-dev libgmp3-dev

# ruby deps for xettercap
sudo gem install bettercap

# install virtualenv
sudo python3 -m pip install virtualenv

# create virualenv
python3 -m virtualenv .venv --python=2

# active env
source ${DIRECTORY}/.venv/bin/activate

# install requirement
python -m pip install tabulate terminaltables

sudo ln -s ${DIRECTORY}/run.sh /bin/xerosploit
echo [+] create link xerosploit

XETTERCAP="${DIRECTORY}/tools/bettercap/bin/xettercap"

sudo chmod +x $XETTERCAP
echo [+] make xettercap executable

sudo ln -s ${XETTERCAP} /bin/xettercap
echo [+] create xettercap link

echo install finish
