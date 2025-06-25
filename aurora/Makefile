PACKAGE_NAME = m.fedyarov.wireguard

CFLAGS = `pkg-config --cflags dbus-1 glib-2.0` -fPIC -shared -DCONNMAN_PLUGIN
LDFLAGS = `pkg-config --libs dbus-1 glib-2.0`

WIREGUARD_CONNMAN_PLUGIN_SOURCES = wireguard-plugin.c
WIREGUARD_TOOLS_SOURCES = ../wireguard-tools/src/encoding.c \
	../wireguard-tools/src/curve25519.c

all: wireguard-plugin stub-main

install: wireguard-plugin stub-main
	mkdir -p $(DESTDIR)/usr/lib/connman/plugins-vpn
	mv wireguard.so $(DESTDIR)/usr/lib/connman/plugins-vpn/

	mkdir -p $(DESTDIR)/usr/bin
	mv stub-main $(DESTDIR)/usr/bin/$(PACKAGE_NAME)

wireguard-plugin:
	gcc $(CFLAGS) $(LDFLAGS) \
		$(WIREGUARD_CONNMAN_PLUGIN_SOURCES) \
		$(WIREGUARD_TOOLS_SOURCES) \
		-o wireguard.so

stub-main:
	gcc -fPIC stub-main.c -o stub-main
