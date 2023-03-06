all: novpn novpng

novpng: $(srcdir)novpn.c
	gcc  -g -flto -Wall -DDEBUG -o novpng $(srcdir)novpn.c

novpn: $(srcdir)novpn.c
	gcc  -O3 -flto -Wall -o novpn $(srcdir)novpn.c && strip $(srcdir)novpn

setcap: novpn
	setcap  cap_net_admin=ep novpn

install:
	mkdir -p $(DESTDIR)/usr/sbin $(DESTDIR)/etc/systemd/system
	cp novpn $(DESTDIR)/usr/sbin/
	cp $(srcdir)novpn-client.service $(DESTDIR)/etc/systemd/system/

.PHONY: all install setcap
