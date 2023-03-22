#!/bin/bash

directory=$(pwd)

sudo ln -s ${directory}/run.sh /bin/xerosploit
echo [+] create link xerosploit

xettercap="${directory}/tools/bettercap/bin/xettercap"

sudo chmod +x $xettercap
echo [+] make xettercap executable

sudo ln -s ${xettercap} /bin/xettercap
echo [+] create xettercap link

echo install finish
