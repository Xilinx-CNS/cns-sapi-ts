/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Implementation of Test API to process test arguments and environment
 *
 * Implementation of test API to process common test arguments and
 * environments along with accompanying API like common functions for
 * connection estblishment.
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

/* User name of the library which is used in logging. */
#define TE_LGR_USER     "sapi-ts env"

#include "te_config.h"
#include "sockapi-test.h"

/* See description in sockapi-ts_env.h */
rpc_socket_type
sock_type_sockts2rpc(sockts_socket_type sock_type)
{
    switch (sock_type)
    {
        case SOCKTS_SOCK_TCP_ACTIVE:
        case SOCKTS_SOCK_TCP_PASSIVE:
        case SOCKTS_SOCK_TCP_PASSIVE_CL:
            return RPC_SOCK_STREAM;

        case SOCKTS_SOCK_UDP:
        case SOCKTS_SOCK_UDP_NOTCONN:
            return RPC_SOCK_DGRAM;
    }

    return RPC_SOCK_UNKNOWN;
}

/**
 * Set environment for connection with socket on IUT bound to remote
 * address
 *
 * @param pco_iut  PCO on IUT
 * @param iut_addr Address to bind the socket to
 * @param iut_s    Socket on @p pco_iut
 * @param pco_tst  Tester PCO
 * @param tst_addr Address on @p pco_tst
 * @param gw       Address on IUT
 */
static void
sockts_set_transparent(rcf_rpc_server *pco_iut,
                       const struct sockaddr *iut_addr,
                       int iut_s, rcf_rpc_server *pco_tst,
                       const struct sockaddr *tst_addr,
                       const struct sockaddr *gw)
{
    rpc_socket_domain       domain;
    int                     af;
    int                     route_prefix;
    char                    dst_addr_str[INET6_ADDRSTRLEN];
    char                    route_inst_name[1024];
    cfg_handle              p_handle;

    memset(route_inst_name, 0, sizeof(route_inst_name));

    domain = rpc_socket_domain_by_addr(iut_addr);
    af = addr_family_rpc2h(domain);
    route_prefix = te_netaddr_get_size(addr_family_rpc2h(domain)) * 8;
    inet_ntop(af, te_sockaddr_get_netaddr(iut_addr),
              dst_addr_str, sizeof(dst_addr_str));
    snprintf(route_inst_name, sizeof(route_inst_name),
             "%s|%d", dst_addr_str, route_prefix);

    if (cfg_find_fmt(&p_handle, "/agent:%s/route:%s",
                     pco_tst->ta, route_inst_name) != 0)
    {
        CHECK_RC(tapi_cfg_add_route(pco_tst->ta, af,
                        te_sockaddr_get_netaddr(iut_addr), route_prefix,
                        te_sockaddr_get_netaddr(gw),
                        NULL, te_sockaddr_get_netaddr(tst_addr),
                        0, 0, 0, 0, 0, 0, NULL));
    }

    rpc_setsockopt_int(pco_iut, iut_s, RPC_IP_TRANSPARENT, 1);
}

/* See decription in sockapi-ts_env.h */
void
sockts_connection(rcf_rpc_server *pco_iut, rcf_rpc_server *pco_tst,
                  const struct sockaddr *iut_addr,
                  const struct sockaddr *tst_addr,
                  sockts_socket_type sock_type, te_bool bind_wildcard,
                  te_bool use_existing_socks,
                  const struct sockaddr *gw_addr, int *iut_s, int *tst_s,
                  int *iut_l,
                  sockts_socket_func iut_sock_func)
{
    rcf_rpc_server *pco_cl = pco_tst;
    rcf_rpc_server *pco_srv = pco_iut;

    const struct sockaddr *addr_cl = tst_addr;
    const struct sockaddr *addr_srv = iut_addr;
    const struct sockaddr *addr_srv_wild;
    struct sockaddr       *addr_wild = NULL;

    int sock_cl = -1;
    int sock_srv = -1;
    int listener = -1;
    int rc;

    sockts_socket_func srv_sock_func = iut_sock_func;
    sockts_socket_func cl_sock_func = SOCKTS_SOCK_FUNC_SOCKET;

    rpc_socket_type rpc_sock_type = sock_type_sockts2rpc(sock_type);

    if (gw_addr != NULL && rpc_sock_type == RPC_SOCK_STREAM &&
        sock_type != SOCKTS_SOCK_TCP_ACTIVE)
    {
        TEST_FAIL("GW address is specified what enables IP_TRANSPARENT "
                  "testing, but this option is supported only for active "
                  "TCP connections.");
    }

    if (sock_type == SOCKTS_SOCK_TCP_ACTIVE)
    {
        pco_cl = pco_iut;
        pco_srv = pco_tst;
        addr_cl = iut_addr;
        addr_srv = tst_addr;
        cl_sock_func = iut_sock_func;
        srv_sock_func = SOCKTS_SOCK_FUNC_SOCKET;
    }

    if (use_existing_socks)
    {
        if (sock_type == SOCKTS_SOCK_TCP_ACTIVE)
        {
            sock_cl = *iut_s;
            sock_srv = *tst_s;
        }
        else
        {
            sock_cl = *tst_s;
            sock_srv = *iut_s;
        }
    }

    addr_srv_wild = addr_srv;
    if (bind_wildcard)
    {
        addr_wild = tapi_sockaddr_clone_typed(iut_addr,
                                              TAPI_ADDRESS_WILDCARD);
        if (sock_type == SOCKTS_SOCK_TCP_ACTIVE)
            addr_cl = addr_wild;
        else
            addr_srv_wild = addr_wild;
    }

    if (sock_srv < 0)
    {
        sock_srv = sockts_socket(srv_sock_func, pco_srv,
                                 rpc_socket_domain_by_addr(addr_cl),
                                 rpc_sock_type, RPC_PROTO_DEF);
    }

    if (sock_cl < 0)
    {
        sock_cl = sockts_socket(cl_sock_func, pco_cl,
                                rpc_socket_domain_by_addr(addr_cl),
                                rpc_sock_type, RPC_PROTO_DEF);
    }

    if (rpc_sock_type == RPC_SOCK_STREAM && gw_addr != NULL &&
        addr_cl != NULL)
    {
        sockts_set_transparent(pco_cl, addr_cl, sock_cl, pco_srv,
                               addr_srv, gw_addr);
    }

    rpc_bind(pco_srv, sock_srv, addr_srv_wild);
    rpc_bind(pco_cl, sock_cl, addr_cl);

    if (rpc_sock_type == RPC_SOCK_DGRAM)
    {
        if (!bind_wildcard && sock_type != SOCKTS_SOCK_UDP_NOTCONN)
            rpc_connect(pco_srv, sock_srv, addr_cl);

        rpc_connect(pco_cl, sock_cl, addr_srv);
    }
    else
    {
        listener = sock_srv;
        sock_srv = -1;
        rpc_listen(pco_srv, listener, SOCKTS_BACKLOG_DEF);

        RPC_AWAIT_ERROR(pco_cl);
        rc = rpc_connect(pco_cl, sock_cl, addr_srv);
        if (rc < 0)
        {
            TEST_VERDICT("connect() failed with errno %r",
                         RPC_ERRNO(pco_cl));
        }

        RPC_AWAIT_ERROR(pco_srv);
        sock_srv = rpc_accept(pco_srv, listener, NULL, NULL);
        if (sock_srv < 0)
        {
            TEST_VERDICT("accept() failed with errno %r",
                         RPC_ERRNO(pco_srv));
        }

        if (sock_type != SOCKTS_SOCK_TCP_PASSIVE)
        {
            RPC_CLOSE(pco_srv, listener);
        }
        else if (iut_l == NULL)
        {
            free(addr_wild);
            TEST_FAIL("Specified socket type 'tcp_passive' assumes keeping "
                      "listener socket open. Argument 'iut_l' must not "
                      "be NULL in this case.");
        }
        else
        {
            *iut_l = listener;
        }
    }

    if (sock_type == SOCKTS_SOCK_TCP_ACTIVE)
    {
        *iut_s = sock_cl;
        *tst_s = sock_srv;
    }
    else
    {
        *iut_s = sock_srv;
        *tst_s = sock_cl;
    }

    free(addr_wild);
}
