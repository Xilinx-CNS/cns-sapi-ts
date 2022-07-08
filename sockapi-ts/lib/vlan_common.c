/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Implementation of auxilliary functions incapsulating some common actions
 * needed for VLAN test purposes.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#include "te_config.h"

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include "te_defs.h"
#include "tapi_cfg.h"
#include "rcf_rpc.h"

#include "tapi_sockaddr.h"
#include "tapi_rpc_socket.h"
#include "tapi_test.h"
#include "sockapi-ts.h"

#include "vlan_common.h"

/* See the description in vlan_common.h */
void
create_vlan_pair(struct rcf_rpc_server *pco_iut,
                 struct rcf_rpc_server *pco_tst,
                 const struct if_nameindex *iut_if,
                 const struct if_nameindex *tst_if,
                 cfg_handle *new_net_handle,
                 cfg_handle *iut_addr_handle,
                 cfg_handle *tst_addr_handle,
                 struct sockaddr **iut_addr,
                 struct sockaddr **tst_addr,
                 struct if_nameindex **iut_vlan_if,
                 struct if_nameindex **tst_vlan_if,
                 int vlan_id,
                 te_bool *iut_is_configured,
                 te_bool *tst_is_configured)
{
    cfg_handle      net_handle;
    cfg_handle      iut_addr_handle_aux;
    cfg_handle      tst_addr_handle_aux;
    char           *net_oid = NULL;
    cfg_val_type    val_type;
    unsigned int    net_prefix;
    char           *iut_vlan_if_name;
    char           *tst_vlan_if_name;
    uint16_t       *port_ptr = NULL;

    CHECK_RC(tapi_cfg_alloc_ip4_net(&net_handle));
    if (new_net_handle != NULL)
        *new_net_handle = net_handle;
    CHECK_RC(cfg_get_oid_str(net_handle, &net_oid));
    val_type = CVT_INTEGER;
    CHECK_RC(cfg_get_instance_fmt(&val_type, &net_prefix,
                                  "%s/prefix:", net_oid));

    CREATE_CONFIGURE_VLAN_EXT(pco_iut, net_handle, iut_addr_handle_aux,
                              *iut_addr, net_prefix, iut_if, vlan_id,
                              iut_vlan_if_name, *iut_is_configured, TRUE);
    if (iut_addr_handle != NULL)
        *iut_addr_handle = iut_addr_handle_aux;
    CREATE_CONFIGURE_VLAN_EXT(pco_tst, net_handle, tst_addr_handle_aux,
                              *tst_addr, net_prefix, tst_if, vlan_id,
                              tst_vlan_if_name, *tst_is_configured, TRUE);
    if (tst_addr_handle != NULL)
        *tst_addr_handle = tst_addr_handle_aux;

    GET_NAMEINDEX(pco_iut, *iut_vlan_if, iut_vlan_if_name);
    GET_NAMEINDEX(pco_tst, *tst_vlan_if, tst_vlan_if_name);

    CHECK_NOT_NULL(port_ptr = te_sockaddr_get_port_ptr(*iut_addr));
    CHECK_RC(tapi_allocate_port_htons(pco_iut, port_ptr));
    CHECK_NOT_NULL(port_ptr = te_sockaddr_get_port_ptr(*tst_addr));
    CHECK_RC(tapi_allocate_port_htons(pco_tst, port_ptr));
}

/* See the description in vlan_common.h */
void
create_net_channel(struct rcf_rpc_server *pco_iut,
                   struct rcf_rpc_server *pco_tst,
                   const struct if_nameindex *iut_if,
                   const struct if_nameindex *tst_if,
                   cfg_handle *new_net_handle,
                   cfg_handle *iut_addr_handle,
                   cfg_handle *tst_addr_handle,
                   struct sockaddr **iut_addr,
                   struct sockaddr **tst_addr,
                   const struct sockaddr *mcast_addr,
                   sockts_socket_func sock_func,
                   int *iut_s,
                   int *tst_s,
                   te_bool iut_rcv,
                   te_bool is_vlan,
                   struct if_nameindex **iut_vlan_if,
                   struct if_nameindex **tst_vlan_if,
                   int vlan_id,
                   te_bool *iut_is_configured,
                   te_bool *tst_is_configured)
{
    uint16_t       *port_ptr = NULL;

    int rc;
    int opt_val;

    struct if_nameindex *cur_iut_if = (struct if_nameindex *)iut_if;
    struct if_nameindex *cur_tst_if = (struct if_nameindex *)tst_if;

    struct if_nameindex *if_snd;

    struct rcf_rpc_server *rpc_snd;
    struct rcf_rpc_server *rpc_rcv;
    struct sockaddr       *addr_snd;
    struct sockaddr        aux_addr;
    int                    snd_s;
    int                    rcv_s;

    struct tarpc_mreqn     mreq;

    if (is_vlan)
    {
        create_vlan_pair(pco_iut, pco_tst, iut_if, tst_if,
                         new_net_handle, iut_addr_handle,
                         tst_addr_handle, iut_addr, tst_addr,
                         iut_vlan_if, tst_vlan_if, vlan_id,
                         iut_is_configured, tst_is_configured);

        cur_iut_if = *iut_vlan_if;
        cur_tst_if = *tst_vlan_if;
    }
    else
    {
        if (iut_is_configured != NULL)
            *iut_is_configured = FALSE;

        if (tst_is_configured != NULL)
            *tst_is_configured = FALSE;
    }

    if (iut_s != NULL)
        *iut_s = sockts_socket(sock_func, pco_iut,
                               rpc_socket_domain_by_addr(*iut_addr),
                               RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    *tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(*tst_addr),
                        RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    if (!iut_rcv)
    {
        rpc_snd = pco_iut;
        rpc_rcv = pco_tst;
        if_snd = cur_iut_if;
        addr_snd = *iut_addr;
        snd_s = *iut_s;
        rcv_s = *tst_s;
    }
    else
    {
        rpc_snd = pco_tst;
        rpc_rcv = pco_iut;
        if_snd = cur_tst_if;
        addr_snd = *tst_addr;
        snd_s = *tst_s;
        if (iut_s != NULL)
            rcv_s = *iut_s;
        else
            rcv_s = -1;
    }

    memset(&mreq, 0, sizeof(mreq));
    memcpy(&mreq.multiaddr, te_sockaddr_get_netaddr(mcast_addr),
           sizeof(struct in_addr));
    mreq.type = OPT_MREQN;

    mreq.ifindex =if_snd->if_index;
    RPC_AWAIT_IUT_ERROR(rpc_snd);
    rc = rpc_setsockopt(rpc_snd, snd_s, RPC_IP_MULTICAST_IF, &mreq);
    if (rc == -1)
        TEST_FAIL("rpc_setsockopt() with RPC_IP_MULTICAST_IF returned"
                  " -1 on %s for %s interface", rpc_snd->name,
                  if_snd->if_index);

    if (is_vlan)
    {
        CHECK_NOT_NULL(port_ptr = te_sockaddr_get_port_ptr(addr_snd));
        CHECK_RC(tapi_allocate_port_htons(rpc_snd, port_ptr));
    }
    rpc_bind(rpc_snd, snd_s, addr_snd);

    if (rcv_s != -1)
    {
        opt_val = 1;
        rpc_setsockopt(rpc_rcv, rcv_s, RPC_SO_REUSEADDR, &opt_val);
        memcpy(&aux_addr, mcast_addr, te_sockaddr_get_size(mcast_addr));
        te_sockaddr_set_wildcard(&aux_addr);
        rpc_bind(rpc_rcv, rcv_s, &aux_addr);
    }
}

/* See the description in vlan_common.h */
char *
get_name_by_addr(struct sockaddr *addr, peer_name_t *names)
{
#define MAX_NAME 1000
#define STR_CNT 5

        int          i = 0;
        static int   cur_num = -1;
        static char  name[STR_CNT][MAX_NAME];
        char        *same_port_peer = NULL;

        cur_num++;
        if (cur_num == STR_CNT)
            cur_num = 0;

        for (i = 0; names[i].addr != NULL; i++)
        {
            if (te_sockaddrcmp(SA(addr), te_sockaddr_get_size(addr),
                               SA(*(names[i].addr)),
                               te_sockaddr_get_size(
                                            SA(*(names[i].addr)))) == 0)
            {
                snprintf(name[cur_num], MAX_NAME, "%s", names[i].name);
                break;
            }
            else if (te_sockaddr_get_port(addr) ==
                              te_sockaddr_get_port(*(names[i].addr)))
            {
                same_port_peer = names[i].name;
            }
        }

        if (names[i].addr == NULL)
        {
            if (same_port_peer == NULL)
                snprintf(name[cur_num], MAX_NAME, "unknown peer");
            else
                snprintf(name[cur_num], MAX_NAME, "unknown peer "
                         "with the same port as in %s", same_port_peer);
        }

        return name[cur_num];
#undef MAX_NAME
#undef STR_CNT
}

/* See the description in vlan_common.h */
char *
get_name_by_sock(int s, rcf_rpc_server *pco, sock_name_t *names)
{
    int i = 0;

    for (i = 0; names[i].name != NULL; i++)
    {
        if (*(names[i].sock) == s && *(names[i].pco) == pco)
            return names[i].name;
    }

    return "unknown socket";
}
