CC = gcc
CFLAGS = -g
RM = rm -rf

default: install

clean:
	$(RM) install

install:
	chmod 755 banner.py
	chmod 755 install.c
	chmod 755 run.sh
	chmod 755 xerosploit.py
	mkdir -p $(DESTDIR)/opt/xerosploit/
	mkdir -p $(DESTDIR)/usr/share/doc/xerosploit/
	mkdir -p $(DESTDIR)/opt/xerosploit/tools/
	mkdir -p $(DESTDIR)/usr/bin/
	cp banner.py $(DESTDIR)/opt/xerosploit/
	$(CC) $(CFLAGS) -o install install.c
	cp install.c $(DESTDIR)/opt/xerosploit/
	cp LICENSE $(DESTDIR)/opt/xerosploit/
	cp Makefile $(DESTDIR)/opt/xerosploit/
	cp README.md $(DESTDIR)/opt/xerosploit/
	cp README.md $(DESTDIR)/usr/share/doc/xerosploit/
	cp run.sh $(DESTDIR)/opt/xerosploit/
	cp run.sh $(DESTDIR)/usr/bin/
	cp xerosploit.py $(DESTDIR)/opt/xerosploit/
	cp -r tools $(DESTDIR)/opt/xerosploit/
	./install
