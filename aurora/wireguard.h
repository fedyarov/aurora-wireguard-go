
/* I hope 255 peers is enough */
#define MAX_PEER_NUM 255

enum opt_type {
    OPT_STRING = 0,
};

struct {
    const char *cm_opt;
    enum opt_type opt_type;
} wg_options[] = {
    { "WireGuard.ListenPort", OPT_STRING },
    { "WireGuard.PrivateKey", OPT_STRING },
    { "WireGuard.Address", OPT_STRING },
    { "WireGuard.DNS", OPT_STRING } // nameservers delimetered by space, e.g "1.1.1.1 2.2.2.2 3.3.3.3"
};

struct {
    const char *cm_opt;
    enum opt_type opt_type;
} wg_peer_options[] = {
    { "Endpoint", OPT_STRING },
    { "PublicKey", OPT_STRING },
    { "AllowedIP", OPT_STRING } // addresses delimetered by comma, e.g "217.67.177.58/32,77.88.44.242/32"
};
