gdbus call -y -d net.connman.vpn \
	-o /net/connman/vpn/connection/255_255_255_255_mfedyarov \
	-m net.connman.vpn.Connection.SetProperty \
	WireGuard.Peer.1.AllowedIP \<\'217.67.177.58/32\'\> \

