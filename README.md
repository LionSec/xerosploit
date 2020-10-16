
[![Version](https://img.shields.io/badge/Xerosploit-Version_1.0-brightgreen.svg?maxAge=259200)]()
[![PyPI](https://img.shields.io/badge/Python-2.7-blue.svg)]()
[![Build](https://img.shields.io/badge/Supported_OS-linux-orange.svg)]()
[![AUR](https://img.shields.io/aur/license/yaourt.svg)]()

Xerosploit (This is a Fork to fix Terminaltables Error and other Installation Issues on Latest Operating Systems)
=
Xerosploit is a penetration testing toolkit whose goal is to perform man in the middle attacks for testing purposes. It brings various modules that allow to realise efficient attacks, and also allows to carry out denial of service attacks and port scanning.
Powered by <a href="https://www.bettercap.org"> bettercap</a> and <a href="https://www.bettercap.org"> nmap</a>.

![](http://i.imgur.com/bbr48Ep.png)

Dependencies
=

- nmap 
- hping3 
- build-essential 
- ruby-dev 
- libpcap-dev 
- libgmp3-dev
- tabulate 
- terminaltables




Instalation
=
Dependencies will be automatically installed.

    Add Debian Repository:
    $ sudo nano /etc/apt/sources.list
    
    Add this:
    deb http://deb.debian.org/debian/ buster main
    
    git clone https://github.com/LionSec/xerosploit
    cd xerosploit && sudo python install.py
    sudo xerosploit
    
    
    
    
Manual Setup (If in any case above mathod does't work for you, try following steps):
=   
    Add Debian Repository:
    $ sudo nano /etc/apt/sources.list

    Add following link to "sources.list" file:
    deb http://deb.debian.org/debian/ buster main

    Install Dependencies:
    $ sudo apt update && sudo apt install python-pip-whl=18.1-5 python-all-dev python-setuptools python-wheel python-pip

    Download and Run Official Packages:
    $ git clone https://github.com/LionSec/xerosploit
    $ cd xerosploit && sudo python install.py
    $ sudo apt install python3-terminaltables
    $ sudo xerosploit


Issues:
=
    Real-time Sniffing logs doesn't work out of the box, you need to run this command each time to monitor real-time logs:

    See Logs File:
    $ ls /opt/xerosploit/xerosniff

    Monitor Logs in Real-Time: (change file name to your log file)
    $ sudo tail -f /opt/xerosploit/xerosniff/LOG_FILE.log
    
    
Tested on
=

<table>
    <tr>
        <td>Kali Linux</td>
        <td>2020.2 , 2020.3</td>
    </tr>
</table>



Features 
=
- Port scanning
- Network mapping
- Dos attack
- Html code injection
- Javascript code injection
- Download intercaption and replacement
- Sniffing
- Dns spoofing
- Background audio reproduction
- Images replacement
- Drifnet
- Webpage defacement and more ...

Demonstration
=
https://www.youtube.com/watch?v=35QUrtZEV9U

I have some questions!
=

Please visit https://github.com/LionSec/xerosploit/issues


