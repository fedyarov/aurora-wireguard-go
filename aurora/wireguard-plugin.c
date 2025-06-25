#include "wireguard.h"

#include "../wireguard-tools/src/ipc-uapi.h"
#include "../wireguard-tools/src/containers.h"
#include "../wireguard-tools/src/encoding.h"

#define CONNMAN_API_SUBJECT_TO_CHANGE

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/if_tun.h>

#include <glib-2.0/glib.h>
#include <dbus-1.0/dbus/dbus.h>

#include <connman/plugin.h>
#include <connman/task.h>
#include <connman/log.h>
#include <connman/dbus.h>
#include <connman/ipconfig.h>
#include <connman/inet.h>
#include <connman/agent.h>
#include <connman/setting.h>
#include <connman/vpn-dbus.h>
#include <connman/vpn/plugins/vpn.h>
#include <connman/vpn/vpn-agent.h>

#define UNUSED(x) (void)(x)

#define PLUGIN_NAME "wireguard"
#define BIN_PATH "/usr/bin/m.fedyarov.wireguard-go"

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

static DBusConnection *connection;

typedef struct {
    struct vpn_provider *provider;
    struct connman_task *task;
    char *dbus_sender;
    char *if_name;
    vpn_provider_connect_cb_t cb;
    void *user_data;
	bool disconnecting;
} WgPrivateData;

static void
wg_connect_done(WgPrivateData *data,
                int err)
{
    if (data && data->cb) {
        vpn_provider_connect_cb_t cb = data->cb;
        void *user_data = data->user_data;

        data->cb = NULL;
        data->user_data = NULL;
        cb(data->provider, user_data, err);
    }
}

static void
free_private_data(WgPrivateData *data)
{
    if (vpn_provider_get_plugin_data(data->provider) == data)
        vpn_provider_set_plugin_data(data->provider, NULL);

    vpn_provider_unref(data->provider);

    g_free(data->dbus_sender);
    g_free(data->if_name);
    g_free(data);
}

static void
wg_died(struct connman_task *task,
        int exit_code,
        void *user_data)
{
    connman_info("[Wireguard] Task died (exit code %d)", exit_code);
    WgPrivateData *data = user_data;

    if (data->disconnecting) {
        data->disconnecting = false;
    } else {
        vpn_provider_add_error(data->provider, VPN_PROVIDER_ERROR_CONNECT_FAILED);
    }

    vpn_died(task, exit_code, data->provider);
    free_private_data(data);
}

static int
run_task(WgPrivateData *data)
{
    struct connman_task *task = data->task;
    struct vpn_provider *provider = data->provider;

    char *data_dir = vpn_provider_get_data_directory(provider);
	if (!data_dir) {
		connman_error("[Wireguard] Failed to get data dir for VPN");
		return -EBADF;
	}

	/* ipc-uapi-unix.h global variable */
	socket_dir = data_dir;
    connman_task_add_variable(task, "LOG_LEVEL", "verbose");
    connman_task_add_variable(task, "AURORA_VPN_DATA_DIR", data_dir);
    connman_task_add_argument(task, "--foreground", NULL);
    connman_task_add_argument(task, data->if_name, NULL);

    int err = connman_task_run(task, wg_died, data, NULL, NULL, NULL);
    if (err < 0) {
        data->cb = NULL;
        data->user_data = NULL;
        connman_error("[Wireguard] Failed to start %s", BIN_PATH);
        return err;
    }

    return -EINPROGRESS;
}

#define MAX_CONNECTION_ERRORS 1

static int
wg_connect(struct vpn_provider *provider,
           struct connman_task *task,
           const char *if_name,
           vpn_provider_connect_cb_t cb, 
           const char *dbus_sender, 
           void *user_data)
{
    connman_info("[Wireguard] Connect");

    int errors = vpn_provider_get_connection_errors(provider);
    if (errors >= MAX_CONNECTION_ERRORS) {
        connman_info("[Wireguard] Max connection errors exceeded");
        return -ECANCELED;
    }

    WgPrivateData *data = g_try_new0(WgPrivateData, 1);
    if (!data)
        return -ENOMEM;

    vpn_provider_set_plugin_data(provider, data);
    data->provider = vpn_provider_ref(provider);
    data->task = task;
    data->dbus_sender = g_strdup(dbus_sender);
    data->if_name = g_strdup(if_name);
    data->cb = cb;
    data->user_data = user_data;

    return run_task(data);
}

void
wg_disconnect(struct vpn_provider *provider)
{
    connman_info("[Wireguard] Disconnect");
    if (!provider) {
        connman_error("[Wireguard] No provider found");
        return;
    }

    WgPrivateData *data = vpn_provider_get_plugin_data(provider);
    data->disconnecting = true;
}

static int
prefix_to_mask(int prefix_len, char *mask_str) {
    if (prefix_len < 0 || prefix_len > 32) {
        return -1;
    }

    uint32_t mask = (prefix_len == 0) ? 0 : ~((1 << (32 - prefix_len)) - 1);

    struct in_addr addr;
    addr.s_addr = htonl(mask);

    if (inet_ntop(AF_INET, &addr, mask_str, INET_ADDRSTRLEN) == NULL) {
        return -1;
    }

    return 0;
}

static int
configure_with_provider_options(struct vpn_provider *provider)
{
    WgPrivateData *data = vpn_provider_get_plugin_data(provider);
    struct wgdevice *device = g_new0(struct wgdevice, 1);
    struct connman_ipaddress *ipaddress = connman_ipaddress_alloc(AF_INET);
    char *gateways[MAX_PEER_NUM] = { 0 };

    if (!data || !device || !ipaddress) {
        connman_error("[WireGuard] Failed to allocate structs to configure");
        return -1;
    }

    strncpy(device->name, data->if_name, IFNAMSIZ-1);

    const char *option = vpn_provider_get_string(provider, "WireGuard.ListenPort");
    if (option) {
        device->flags |= WGDEVICE_HAS_LISTEN_PORT;
        device->listen_port = htons(atoi(option));
    }

    option = vpn_provider_get_string(provider, "WireGuard.PrivateKey");
    if (!option) {
        connman_error("[Wireguard] Private key is missing");
        goto cleanup;
    }

    connman_info("[Wireguard] Decoding keys");
    device->flags |= WGDEVICE_HAS_PRIVATE_KEY;
    int r = key_from_base64(device->private_key, option);
    if (!r) {
        connman_error("[Wireguard] Failed to decode private key");
        goto cleanup;
    };

    option = vpn_provider_get_string(provider, "WireGuard.DNS");
    if (!option) {
        connman_warn("[WireGuard] DNS is missing"); 
    } else {
       vpn_provider_set_nameservers(provider, option);
    }

    unsigned route_count = 1;
    bool split_routing = false;
    for (unsigned peer_num = 1; peer_num <= MAX_PEER_NUM; peer_num++) {
        g_autofree gchar *endpoint = g_strdup_printf("WireGuard.Peer.%d.Endpoint", peer_num);
        option = vpn_provider_get_string(provider, endpoint);
        if (!option) {
            if (peer_num == 1) {
                connman_error("[Wireguard] Peer is missing");
                goto cleanup;
            } else {
                connman_info("[Wireguard] Have %d peers. Continue", peer_num-1);
                break;
            }
        }

        g_auto(GStrv) endpoint_split = g_strsplit(option, ":", 2);
        if (!endpoint_split[0] || !endpoint_split[1]) {
            connman_error("[Wireguard] Failed to parse peer %d endpoint", peer_num);
            goto cleanup;
        }
        struct wgpeer *peer = g_new0(struct wgpeer, 1); 
        peer->endpoint.addr4.sin_family = AF_INET;
        peer->endpoint.addr4.sin_addr.s_addr = inet_addr(endpoint_split[0]);
        peer->endpoint.addr4.sin_port = htons(atoi(endpoint_split[1]));

        g_autofree gchar *allowedip = g_strdup_printf("WireGuard.Peer.%d.AllowedIP", peer_num);
        option = vpn_provider_get_string(provider, allowedip);
        if (!option) {
            connman_warn("[Wireguard] AllowedIP is missing. Assume any address");
            option = "0.0.0.0/0";
        }

        if (g_strcmp0(option, "0.0.0.0/0") == 0) {
            split_routing = false;

            peer->first_allowedip = g_new0(struct wgallowedip, 1);
            peer->first_allowedip->family = AF_INET;
            peer->first_allowedip->ip4.s_addr = inet_addr("0.0.0.0");
        } else {
            split_routing = true;

            g_auto(GStrv) allowedip_split = g_strsplit(option, ",", 255);
            for (unsigned i = 0; allowedip_split[i]; i++) {
                g_auto(GStrv) route_split = g_strsplit(allowedip_split[i], "/", 2);
                if (!route_split[0] || !route_split[1]) {
                    connman_error("[Wireguard] Failed to parse allowedip %s, skip", allowedip_split[i]);
                    continue;
                }

                char mask[INET_ADDRSTRLEN];
                if (prefix_to_mask(atoi(route_split[1]), &mask) < 0) {
                    connman_error("[Wireguard] Failed to parse allowedip address mask %s, skip", allowedip_split[i]);
                    continue;
                }
                g_autofree gchar *addr_str = g_strdup_printf("addr_%d", route_count);
                g_autofree gchar *mask_str = g_strdup_printf("mask_%d", route_count);
                g_autofree gchar *gate_str = g_strdup_printf("gate_%d", route_count);
                vpn_provider_append_route(provider, addr_str, route_split[0]);
                vpn_provider_append_route(provider, mask_str, mask);
                vpn_provider_append_route(provider, gate_str, endpoint_split[0]);
                route_count++;

                struct wgallowedip *allowedip = g_new0(struct wgallowedip, 1);
                allowedip->family = AF_INET;
                allowedip->ip4.s_addr = inet_addr(route_split[0]);
                allowedip->cidr = htons(atoi(route_split[1]));
                
                if (!peer->first_allowedip) {
                    peer->first_allowedip = allowedip;
                    peer->last_allowedip = allowedip;
                } else {
                    peer->last_allowedip->next_allowedip = allowedip;
                    peer->last_allowedip = allowedip;
                }
            }
        }

        g_autofree gchar *public_key = g_strdup_printf("WireGuard.Peer.%d.PublicKey", peer_num);
        option = vpn_provider_get_string(provider, public_key);
        if (!option) {
            connman_error("[Wireguard] Peer %d public key is missing", peer_num);
            goto cleanup;
        }
        device->flags |= WGPEER_HAS_PUBLIC_KEY;
        r = key_from_base64(peer->public_key, option);
        if (!r) {
            connman_error("[Wireguard] Failed to decode peer %d public key", peer_num);
            goto cleanup;
        }

        if (!device->first_peer) {
            device->first_peer = peer;
            device->last_peer = peer;
            vpn_provider_set_string(provider, "Gateway", endpoint_split[0]);

            option = vpn_provider_get_string(provider, "WireGuard.Address");
            if (!option) {
                connman_error("[Wireguard] Interface address is missing");
                goto cleanup;
            }
            g_auto(GStrv) address_split = g_strsplit(option, "/", 2);
            if (!address_split[0] || !address_split[1]) {
                connman_error("[Wireguard] Failed to parse interface address %s", option);
                goto cleanup;
            }

            char mask[INET_ADDRSTRLEN];
            if (prefix_to_mask(atoi(address_split[1]), &mask) < 0) {
                connman_error("[Wireguard] Failed to parse interface address mask");
                goto cleanup;
            }

            connman_ipaddress_set_ipv4(ipaddress,
                                    address_split[0],
                                    mask,
                                    endpoint_split[0]);

            connman_ipaddress_set_p2p(ipaddress, true);
            connman_ipaddress_set_peer(ipaddress, NULL);
            vpn_provider_set_ipaddress(provider, ipaddress);

            vpn_provider_set_boolean(provider, "SplitRouting", split_routing, false);
        } else {
            device->last_peer->next_peer = peer;
            device->last_peer = peer;
            gateways[peer_num] = g_strdup(endpoint_split[0]);
        }
    }

    vpn_provider_set_boolean(provider, "SplitRouting", split_routing, false);
    vpn_provider_append_gateways(provider, gateways);

    connman_info("[Wireguard] Set device");
    r = userspace_set_device(device);
    if (r < 0) {
        connman_error("[Wireguard] Failed to set device: %d", r);
        goto cleanup;
    }

cleanup:
    free_wgdevice(device);
    connman_ipaddress_clear(ipaddress);
    for (unsigned i=0; gateways[i]; i++)
        free(gateways[i]);
    return 0;
}

static int
wg_notify(DBusMessage *msg,
          struct vpn_provider *provider)
{
    connman_info("[Wireguard] Notify");
    if (!provider) {
        connman_error("[Wireguard] No provider found");
        return VPN_STATE_AUTH_FAILURE;
    }

    DBusMessageIter iter;
    const char *reason;

    dbus_message_iter_init(msg, &iter);
    dbus_message_iter_get_basic(&iter, &reason);
    dbus_message_iter_next(&iter);

    WgPrivateData *data = vpn_provider_get_plugin_data(provider);
    if (g_strcmp0(reason, "up")) {
        goto out;
    }

    if (configure_with_provider_options(provider) < 0) {
        connman_error("[WireGuard] Failed to configure with provider options");
        goto out;
    }

    wg_connect_done(data, 0);
    connman_warn("[Wireguard] Connected");

    return VPN_STATE_CONNECT;

out:
    wg_connect_done(data, EIO);
    return VPN_STATE_AUTH_FAILURE;
}

static int
wg_error_code(struct vpn_provider *provider, 
              int exit_code)
{
    UNUSED(provider);

    connman_info("[Wireguard] Got exit_code %d", exit_code);

    switch (exit_code) {
    case 0:
        return VPN_PROVIDER_ERROR_UNKNOWN;
    default:
        return VPN_PROVIDER_ERROR_CONNECT_FAILED;
    }
}

static int
wg_save(struct vpn_provider *provider, 
        GKeyFile *keyfile)
{
    connman_info("[Wireguard] Save");

    for (unsigned i = 0; i < (int)ARRAY_SIZE(wg_options); i++) {
        if (g_str_has_prefix(wg_options[i].cm_opt, "WireGuard.")) {
            const char *option = vpn_provider_get_string(provider, wg_options[i].cm_opt);
            if (!option)
                continue;

            g_key_file_set_string(keyfile,
                                  vpn_provider_get_save_group(provider),
                                  wg_options[i].cm_opt,
                                  option);
        }
    }

    for (unsigned peer = 1; peer < MAX_PEER_NUM; peer++) {
        for (unsigned opt = 0; opt < (int)ARRAY_SIZE(wg_peer_options); opt++) {
            g_autofree gchar *name = g_strdup_printf("WireGuard.Peer.%d.%s",
                                                     peer,
                                                     wg_peer_options[opt]);
            const char *option = vpn_provider_get_string(provider, name);
            g_key_file_set_string(keyfile,
                                  vpn_provider_get_save_group(provider),
                                  name,
                                  option);
        }
    }

    return 0;
}

static int
wg_device_flags(struct vpn_provider *provider)
{
    connman_info("[Wireguard] Device flags");
    return IFF_TUN;
}

static int
wg_route_env_parse(struct vpn_provider *provider,
                   const char *key,
                   int *family,
                   unsigned long *idx,
                   enum vpn_provider_route_type *type)
{
    UNUSED(provider);

    connman_info("[Wireguard] Route env parse");

    char *end;
    const char *start;
    
    if (g_str_has_prefix(key, "addr_")) {
        start = key + strlen("addr_");
        *type = VPN_PROVIDER_ROUTE_TYPE_ADDR;
    } else if (g_str_has_prefix(key, "mask_")) {
        start = key + strlen("mask_");
        *type = VPN_PROVIDER_ROUTE_TYPE_MASK;
    } else if (g_str_has_prefix(key, "gate_")) {
        start = key + strlen("gate_");
        *type = VPN_PROVIDER_ROUTE_TYPE_GW;
    } else {
        return -EINVAL;
    }

    *family = AF_INET;
    *idx = g_ascii_strtoull(start, &end, 10);

    connman_info("[Wireguard] idx is %d", *idx);

    return 0;
}

static struct vpn_driver vpn_driver = {
    .connect         = wg_connect,
    .disconnect      = wg_disconnect,
    .notify          = wg_notify,
    .error_code      = wg_error_code,
    .save            = wg_save,
    .device_flags    = wg_device_flags,
    .route_env_parse = wg_route_env_parse,
};

static int wg_init(void)
{
    int r = vpn_register(PLUGIN_NAME, &vpn_driver, BIN_PATH);

    return r;
}

static void wg_exit(void)
{
    vpn_unregister(PLUGIN_NAME);
}

CONNMAN_PLUGIN_DEFINE(wireguard,
                      "Wireguard ConnMan VPN plugin", 
                      CONNMAN_VERSION,
                      CONNMAN_PLUGIN_PRIORITY_DEFAULT, 
                      wg_init, 
                      wg_exit);
