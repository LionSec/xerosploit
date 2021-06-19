#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

int main(){

	int id, opt;

	id = getuid();
	if(id!=0){
		printf("\033[1;31m[!]Xerosploit installer must be run as root. ¯\\_(ツ)_/¯\033[0m \n");
		exit(1);

	}
	else{
		printf("\033[0;36m┌══════════════════════════════════════════════════════════════┐\n█                                                              █\n█                     Xerosploit Installer                     █\n█                                                              █\n└══════════════════════════════════════════════════════════════┘\033[0m\n\n\n");

		printf("\033[0;34m4Please choose your operating system.\033[0m\n\n");
		printf("1) Parrot OS (apt)\n2) Debian (apt)\n3) Red Hat/Fedora (dnf)\n4) Arch (pacman)\n\n>>>");
		scanf("%d",&opt);
		
		switch(opt){
			case 1:
				printf("\033[0;31mInstalling Xerosploit ...\033[0m\n\n");
				//Remove bettercap to avoid SOME problems. Installed by default with apt-get
				system("apt-get install python3");
				system("apt-get remove bettercap");
				//Reinstall bettercap with gem.
				system("gem install bettercap");
				system("apt-get update && apt-get install -y nmap hping3 net-tools rudy-dev git libpcap-dev libgmp3-dev python3-tabulate python3-terminaltables");
				system("cd tools/bettercap/ && gem build bettercap.* && sudo gem install xettercap-* && rm xettercap-* && cd ../../ && mkdir -p /opt/xerosploit && cp -R tools/ /opt/xerosploit/ && cp xerosploit.py /opt/xerosploit/xerosploit.py && cp banner.py /opt/xerosploit/banner.py && cp run.sh /usr/bin/xerosploit && chmod +x /usr/bin/xerosploit && tput setaf 34; echo \"Xerosploit has been sucessfuly installed. Execute 'xerosploit' in your terminal.\" ");
				break;

			case 2:
				printf("\033[0;31mInstalling Xerosploit ...\033[0m\n\n");
				system("apt-get install python3");
				system("apt-get update && apt-get install -y nmap hping3 build-essential net-tools python3-pip ruby-dev git libpcap-dev libgmp3-dev && pip3 install tabulate terminaltables");
				system("cd tools/bettercap/ && gem build bettercap.* && sudo gem install xettercap-* && rm xettercap-* && cd ../../ && mkdir -p /opt/xerosploit && cp -R tools/ /opt/xerosploit/ && cp xerosploit.py /opt/xerosploit/xerosploit.py && cp banner.py /opt/xerosploit/banner.py && cp run.sh /usr/bin/xerosploit && chmod +x /usr/bin/xerosploit && tput setaf 34; echo \"Xerosploit has been sucessfuly installed. Execute 'xerosploit' in your terminal.\" ");
				break;

			case 3:
				printf("\033[0;31mInstalling Xerosploit ...\033[0m\n\n");
				system("dnf install python3");
				system("dnf update && dnf install -y nmap hping3 python3-pip net-tools ruby-devel.x86_64 git libpcap-devel.x86_64 && pip3 install tabulate terminaltables");
				system("cd tools/bettercap/ && gem build bettercap.* && sudo gem install xettercap-* && rm xettercap-* && cd ../../ && mkdir -p /opt/xerosploit && cp -R tools/ /opt/xerosploit/ && cp xerosploit.py /opt/xerosploit/xerosploit.py && cp banner.py /opt/xerosploit/banner.py && cp run.sh /usr/bin/xerosploit && chmod +x /usr/bin/xerosploit && tput setaf 34; echo \"Xerosploit has been sucessfuly installed. Execute 'xerosploit' in your terminal.\" ");
				break;

			case 4:
				printf("\033[0;31mInstalling Xerosploit ...\033[0m\n\n");
				printf("\033[0;31mThis feature will be coming soon...\033[0m\n\n");
				break;

			default:
				printf("Please select the correct option\n");
		}
	printf("\033[0mExiting Program...\n");
	}

	return 0;
}
