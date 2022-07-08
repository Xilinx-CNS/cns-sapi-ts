/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-ip_multicast_if_no_route Usage of IP_MULTICAST_IF socket option without matching route results
 *
 * @objective Check that if a socket is bound to an interface with
 *            @c IP_MULTICAST_IF socket option, multicasting packets are
 *            received successfully on an interface with an address
 *            belonging a different network.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * @param iut_if        Network interface on IUT
 * @param tst_if        Network interface on TESTER
 * @param tst_addr      Address on @p tst_if interface
 * @param mcast_addr    Multicast address
 * @param method        Multicast group joining method
 *
 * @par Test sequence:
 *
 * -# Allocate new network @p net_handle, get free IP address
 *    @p new_addr belonging to it. Assign this address to @p iut_if
 *    interface.
 * -# Create a route to @p new_addr via @p tst_if on TESTER.
 * -# Clean ARP cache on IUT for @p iut_if.
 * -# Create @c SOCK_DGRAM socket @p iut_s on @p pco_iut,
 *    bind it to @p iut_if interface using @b setsockopt(@c
 *    IP_MULTICAST_IF).
 * -# Create @c SOCK_DGRAM socket @p tst_s on @p pco_tst,
 *    bind it to @p tst_if interface using @b setsockopt(@c
 *    IP_MULTICAST_IF), @b bind() it to wildcard address with
 *    a port set to the same value as in @p mcast_addr and
 *    join it to @p mcast_addr multicast group.
 * -# @c PACKETS_TO_SEND times send a UDP packet from @p iut_s
 *    to @p mcast_addr and receive it on @p tst_s.
 * -# Check that all the packets were received successfully and
 *    from the @p tst_if interface.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/ip_multicast_if_no_route"

#include "sockapi-test.h"
#include "tapi_ip4.h"
#include "mcast_lib.h"
#include "multicast.h"
#include "iomux.h"

#define PACKETS_TO_SEND 10

#define CHECK_RECEIVED(_n) \
    do {                                                                \
        num = mcast_listen_stop(pco_tst, listener, NULL);               \
        if (num == 0)                                                   \
        {                                                               \
            is_failed = TRUE;                                           \
            ERROR_VERDICT("Packets are not observed on expected "       \
                          "interface");                                 \
        }                                                               \
        else if (num != (_n))                                           \
        {                                                               \
            is_failed = TRUE;                                           \
            ERROR_VERDICT("Number of packets observed on expected "     \
                          "interface is %d %s than expected one",       \
                          abs(num - (_n)),                              \
                          num > (_n) ? "greater" : "less");             \
        }                                                               \
    } while (0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut  = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;
    int             i;
    unsigned int    num;
    te_bool         is_failed = FALSE;

    struct sockaddr            *new_addr;
    cfg_handle                  new_addr_handle;
    cfg_handle                  added_addr_handle;
    cfg_handle                  net_handle;
    cfg_handle                  route_handle;
    int                         net_prefix;
    cfg_val_type                val_type;
    char                       *net_oid;
    rpc_socket_addr_family      family;

    const struct if_nameindex *iut_if;
    const struct if_nameindex *tst_if;
    const struct sockaddr     *tst_addr = NULL;
    const struct sockaddr     *mcast_addr = NULL;
    struct sockaddr            tst_bind_addr;
    tarpc_joining_method       method;
    struct tarpc_mreqn         mreq;
    mcast_listener_t           listener = NULL;

    void    *tst_buf;
    void    *iut_buf;
    size_t   buf_len;

    struct sockaddr    *saved_addrs = NULL;
    int                *saved_prefixes = NULL;
    te_bool            *saved_broadcasts = NULL;
    int                 saved_count = 0;
    te_bool             saved_all = FALSE;
    te_bool             listener_created = FALSE;
    te_bool             route_added = FALSE;
    te_bool             ip4_net_allocated = FALSE;
    te_bool             ip4_addr_allocated = FALSE;
    te_bool             tst_s_joined = FALSE;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);

    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_MCAST_METHOD(method);

    CHECK_NOT_NULL(iut_buf = sockts_make_buf_dgram(&buf_len));
    CHECK_NOT_NULL(tst_buf = calloc(1, buf_len));

    CHECK_RC(tapi_cfg_save_del_if_ip4_addresses(pco_iut->ta,
                                                iut_if->if_name,
                                                NULL, FALSE,
                                                &saved_addrs,
                                                &saved_prefixes,
                                                &saved_broadcasts,
                                                &saved_count));
    saved_all = TRUE;

    CHECK_RC(tapi_cfg_alloc_ip4_net(&net_handle));
    ip4_net_allocated = TRUE;
    CHECK_RC(cfg_get_oid_str(net_handle, &net_oid));
    val_type = CVT_INTEGER;
    CHECK_RC(cfg_get_instance_fmt(&val_type, &net_prefix,
                                  "%s/prefix:", net_oid));

    CHECK_RC(tapi_cfg_alloc_net_addr(net_handle, &new_addr_handle,
                                     &new_addr));
    ip4_addr_allocated = TRUE;

    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta,
                                           iut_if->if_name,
                                           new_addr, net_prefix, TRUE,
                                           &added_addr_handle));

    family = sockts_domain2family(rpc_socket_domain_by_addr(new_addr));

    CHECK_RC(tapi_cfg_add_route(
                        pco_tst->ta, addr_family_rpc2h(family),
                        te_sockaddr_get_netaddr(new_addr),
                        te_netaddr_get_size(addr_family_rpc2h(family)) * 8,
                        NULL, tst_if->if_name,
                        te_sockaddr_get_netaddr(tst_addr),
                        0, 0, 0, 0, 0, 0,
                        &route_handle));
    route_added = TRUE;

    CHECK_RC(tapi_cfg_del_neigh_dynamic(pco_iut->ta, iut_if->if_name));

    CFG_WAIT_CHANGES;

    listener = mcast_listener_init(pco_tst, tst_if, mcast_addr, NULL, 1);
    listener_created = TRUE;

    memset(&tst_bind_addr, 0, sizeof(tst_bind_addr));
    SIN(&tst_bind_addr)->sin_port = SIN(mcast_addr)->sin_port;
    tst_bind_addr.sa_family = mcast_addr->sa_family;

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(new_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(mcast_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, &tst_bind_addr);

    if (rpc_mcast_join(pco_tst, tst_s, mcast_addr, tst_if->if_index,
                       method))
        TEST_FAIL("Failed to add 'tst_s' socket to 'mcast_addr' "
                  "multicast group");
    tst_s_joined = TRUE;

    memset(&mreq, 0, sizeof(mreq));    
    mreq.type = OPT_MREQN;
    mreq.ifindex = iut_if->if_index;
    rpc_setsockopt(pco_iut, iut_s, RPC_IP_MULTICAST_IF, &mreq);
    mreq.ifindex = tst_if->if_index;
    rpc_setsockopt(pco_tst, tst_s, RPC_IP_MULTICAST_IF, &mreq);

    mcast_listen_start(pco_tst, listener);

    TAPI_WAIT_NETWORK;
    for (i = 0; i < PACKETS_TO_SEND; i++)
    {
        rpc_sendto(pco_iut, iut_s, iut_buf, buf_len, 0, mcast_addr);

        rc = iomux_call_default_simple(pco_tst, tst_s, EVT_RD, NULL,
                                       pco_tst->def_timeout / 2);

        if (rc != 1)
        {
            if (rc > 1)
                TEST_FAIL("poll() returns strange result");
            else
            {
                is_failed = TRUE;
                ERROR_VERDICT("Packet %d was not received", i + 1);
            }
        }
        else
        {
            rc = rpc_recv(pco_tst, tst_s, tst_buf, buf_len, 0);

            if (rc != (int)buf_len ||
                memcmp(iut_buf, tst_buf, buf_len) != 0)
            {
                ERROR_VERDICT("Incorrect data was received in "
                              "%d packet", i + 1);
                is_failed = TRUE;
            }
        }
    }

    CHECK_RECEIVED(PACKETS_TO_SEND);

    if (is_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    free(tst_buf);
    free(iut_buf);

    if (tst_s_joined)
        mcast_leave(pco_tst, tst_s, mcast_addr, tst_if->if_index);

    if (listener_created)
        mcast_listener_fini(pco_tst, listener);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (saved_all)
    {
        tapi_cfg_save_del_if_ip4_addresses(pco_iut->ta,
                                           iut_if->if_name,
                                           NULL, FALSE,
                                           NULL, NULL, NULL, NULL);

        tapi_cfg_restore_if_ip4_addresses(pco_iut->ta, iut_if->if_name,
                                          saved_addrs, saved_prefixes,
                                          saved_broadcasts, saved_count);
    }

    if (route_added)
        tapi_cfg_del_route(&route_handle);

    if (ip4_addr_allocated)
        tapi_cfg_free_entry(&new_addr_handle);
    if (ip4_net_allocated)
        tapi_cfg_free_entry(&net_handle);

    TEST_END;
}
