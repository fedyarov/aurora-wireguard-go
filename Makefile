
all: wireguard-plugin

install: wireguard-plugin
	$(MAKE) install -C aurora

wireguard-plugin:
	$(MAKE) -C aurora
