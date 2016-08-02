#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import sys

if not os.geteuid() == 0:
    sys.exit("""\033[1;91m\n[!] Xerosploit installer must be run as root. ¯\_(ツ)_/¯\n\033[1;m""")

print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                     Xerosploit Installer                     █
█                                                              █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")

def main():

	print("\033[1;34m\n[++] Please choose your operative system.\033[1;m")

	print("""
1) Ubuntu / Kali linux / Others
2) Parrot OS
""")
	system0 = raw_input(">>> ")
	if system0 == "1":
		print("\033[1;34m\n[++] Installing Xerosploit ... \033[1;m")
		install = os.system("apt-get update && apt-get install -y nmap hping3 build-essential python-pip ruby-dev git libpcap-dev libgmp3-dev && pip install tabulate terminaltables")

		install1 = os.system("""cd tools/bettercap/ && gem build bettercap.* && sudo gem install xettercap-* && rm xettercap-* && cd ../../ && mkdir -p /opt/xerosploit && cp -R tools/ /opt/xerosploit/ && cp xerosploit.py /opt/xerosploit/xerosploit.py && cp banner.py /opt/xerosploit/banner.py && cp run.sh /usr/bin/xerosploit && chmod +x /usr/bin/xerosploit && tput setaf 34; echo "Xerosploit has been sucessfuly instaled. Execute 'xerosploit' in your terminal." """)	
	elif system0 == "2":
		print("\033[1;34m\n[++] Installing Xerosploit ... \033[1;m")

		bet_un = os.system("apt-get remove bettercap") # Remove bettercap to avoid some problems . Installed by default with apt-get .
		bet_re_ins = os.system("gem install bettercap") # Reinstall bettercap with gem.

		install = os.system("apt-get update && apt-get install -y nmap hping3 build-essential python-pip ruby-dev git libpcap-dev libgmp3-dev && pip install tabulate terminaltables")

		install1 = os.system("""cd tools/bettercap/ && gem build bettercap.* && sudo gem install xettercap-* && rm xettercap-* && cd ../../ && mkdir -p /opt/xerosploit && cp -R tools/ /opt/xerosploit/ && cp xerosploit.py /opt/xerosploit/xerosploit.py && cp banner.py /opt/xerosploit/banner.py && cp run.sh /usr/bin/xerosploit && chmod +x /usr/bin/xerosploit && tput setaf 34; echo "Xerosploit has been sucessfuly instaled. Execute 'xerosploit' in your terminal." """)
		

	else:
		print("Please select the option 1 or 2")
		main()
main()
