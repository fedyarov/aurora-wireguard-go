gdbus call -y \
	-d net.connman.vpn \
	-o / \
	-m net.connman.vpn.Manager.Create \
	"{'Type': <'wireguard'>, \
	'Name': <'wireguard'>, \
	'Domain': <'mfedyarov'>, \
	'Host': <'255.255.255.255'>, \
	'WireGuard.DNS': <'1.1.1.1 8.8.8.8'>, \
	'WireGuard.Address': <'192.168.15.2/24'>, \
	'WireGuard.PrivateKey': <'base64'>, \
	'WireGuard.Peer.1.Endpoint': <'255.255.255.255:51820'>, \
	'WireGuard.Peer.1.PublicKey': <'base64'>}"
