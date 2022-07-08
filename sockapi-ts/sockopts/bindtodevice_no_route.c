/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page sockopts-bindtodevice_no_route Usage of SO_BINDTODEVICE socket option without matching route results
 *
 * @objective Check that if a socket is bound to an interface with
 *            @c SO_BINDTODEVICE socket option, UDP packets are sent
 *            successfully to an address belonging to a different
 *            network.
 *
 * @type conformance
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_peer2peer
 *                      - @ref arg_types_env_peer2peer_tst
 *                      - @ref arg_types_env_peer2peer_ipv6
 *                      - @ref arg_types_env_peer2peer_tst_ipv6
 *
 * @par Test sequence:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/bindtodevice_no_route"

#include "sockapi-test.h"
#include "tapi_ip_common.h"

#define PACKETS_TO_SEND 10

#define CHECK_RECEIVED(_n) \
    do {                                                                \
        if (tapi_tad_trrecv_stop(pco_tst->ta, sid, csap, NULL, &num))   \
        {                                                               \
            is_failed = TRUE;                                           \
            ERROR_VERDICT("Failed to receive packets via CSAP");        \
        }                                                               \
        else if (num == 0)                                              \
        {                                                               \
            is_failed = TRUE;                                           \
            ERROR_VERDICT("Packets are not observed on expected "       \
                          "interface");                                 \
        }                                                               \
        else if (num != (_n))                                           \
        {                                                               \
            is_failed = TRUE;                                           \
            ERROR_VERDICT("Number of packets observed on expected "     \
                          "interface is %s than expected one",          \
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
    int                         sid;
    csap_handle_t               csap = CSAP_INVALID_HANDLE;

    const struct if_nameindex *iut_if;
    const struct if_nameindex *tst_if;
    const struct sockaddr     *tst_addr;
    int                        af = AF_INET;
    struct sockaddr_storage    tst_bind_addr;
    te_bool                    readable = FALSE;

    char     tst_buf[SOCKTS_MSG_DGRAM_MAX];
    char     iut_buf[SOCKTS_MSG_DGRAM_MAX];
    size_t   buf_len;

    struct sockaddr    *saved_addrs = NULL;
    int                *saved_prefixes = NULL;
    te_bool            *saved_broadcasts = NULL;
    int                 saved_count = 0;
    te_bool             saved_all = FALSE;
    te_bool             csap_created = FALSE;
    te_bool             route_added = FALSE;
    te_bool             net_allocated = FALSE;
    te_bool             addr_allocated = FALSE;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);

    TEST_GET_ADDR(pco_tst, tst_addr);

    TEST_STEP("Remove all addresses of the checked address family "
              "from @p iut_if.");
    af = tst_addr->sa_family;
    CHECK_RC(tapi_cfg_save_del_if_addresses(pco_iut->ta,
                                            iut_if->if_name,
                                            NULL, FALSE,
                                            &saved_addrs,
                                            &saved_prefixes,
                                            &saved_broadcasts,
                                            &saved_count, af));
    saved_all = TRUE;

    TEST_STEP("Allocate new network @b net_handle, get free IP address "
              "@b new_addr belonging to it. Assign this address to "
              "@p iut_if interface.");

    CHECK_RC(tapi_cfg_alloc_net(af, &net_handle));

    net_allocated = TRUE;
    CHECK_RC(cfg_get_oid_str(net_handle, &net_oid));
    val_type = CVT_INTEGER;
    CHECK_RC(cfg_get_instance_fmt(&val_type, &net_prefix,
                                  "%s/prefix:", net_oid));

    CHECK_RC(tapi_cfg_alloc_net_addr(net_handle, &new_addr_handle,
                                     &new_addr));
    addr_allocated = TRUE;

    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta,
                                           iut_if->if_name,
                                           new_addr, net_prefix, TRUE,
                                           &added_addr_handle));

    TEST_STEP("On Tester add a route to @b new_addr via @p tst_if "
              "interface.");
    CHECK_RC(tapi_cfg_add_route(
                        pco_tst->ta, af,
                        te_sockaddr_get_netaddr(new_addr),
                        te_netaddr_get_bitsize(af),
                        NULL, tst_if->if_name,
                        te_sockaddr_get_netaddr(tst_addr),
                        0, 0, 0, 0, 0, 0,
                        &route_handle));
    route_added = TRUE;

    TEST_STEP("Clear neighbor cache on @p iut_if.");
    CHECK_RC(tapi_cfg_del_neigh_dynamic(pco_iut->ta, iut_if->if_name));

    CFG_WAIT_CHANGES;

    TEST_STEP("Create a CSAP on Tester to capture UDP packets "
              "received over @p tst_if interface.");
    CHECK_RC(rcf_ta_create_session(pco_tst->ta, &sid));
    CHECK_RC(tapi_ip_eth_csap_create(pco_tst->ta, sid, tst_if->if_name,
                                     TAD_ETH_RECV_DEF |
                                     TAD_ETH_RECV_NO_PROMISC, NULL, NULL,
                                     af,
                                     te_sockaddr_get_netaddr(tst_addr),
                                     te_sockaddr_get_netaddr(new_addr),
                                     IPPROTO_UDP, &csap));
    csap_created = TRUE;

    tapi_sockaddr_clone_exact(tst_addr, &tst_bind_addr);
    te_sockaddr_set_wildcard(SA(&tst_bind_addr));

    TEST_STEP("Create @c SOCK_DGRAM socket @b iut_s on @p pco_iut, "
              "bind it to @p iut_if interface using "
              "@b setsockopt(@c SO_BINDTODEVICE).");

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(new_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind_to_device(pco_iut, iut_s, iut_if->if_name);

    TEST_STEP("Create @c SOCK_DGRAM socket @b tst_s on @p pco_tst, "
              "bind it to @p tst_if interface using "
              "@b setsockopt(@c SO_BINDTODEVICE), @b bind() it to "
              "wildcard address with a port set to the same value "
              "as in @p tst_addr.");

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, SA(&tst_bind_addr));

    rpc_bind_to_device(pco_tst, tst_s, tst_if->if_name);

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, sid, csap, NULL,
                                   TAD_TIMEOUT_INF, PACKETS_TO_SEND,
                                   RCF_TRRECV_PACKETS));

    TEST_STEP("@c PACKETS_TO_SEND times send a UDP packet from @b iut_s "
              "to @p tst_addr and receive it on @b tst_s.");
    for (i = 0; i < PACKETS_TO_SEND; i++)
    {
        buf_len = rand_range(1, sizeof(iut_buf));
        te_fill_buf(iut_buf, buf_len);

        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_sendto(pco_iut, iut_s, iut_buf, buf_len, 0, tst_addr);
        if (rc < 0)
        {
            TEST_VERDICT("Sending %s packet from IUT socket failed with %r",
                         (i == 0 ? "the first" : "a non-first"),
                         RPC_ERRNO(pco_iut));
        }
        else if (rc != (int)buf_len)
        {
            TEST_VERDICT("sendto() returned unexpected value");
        }

        RPC_GET_READABILITY(readable, pco_tst, tst_s, TAPI_WAIT_NETWORK_DELAY);
        if (!readable)
        {
            TEST_VERDICT("Tester socket did not become readable after "
                         "sending a packet from IUT");
        }

        rc = rpc_recv(pco_tst, tst_s, tst_buf, buf_len, 0);
        if (rc != (int)buf_len || memcmp(iut_buf, tst_buf, buf_len) != 0)
            TEST_VERDICT("Incorrect data was received on Tester");
    }

    TEST_STEP("Check that all the packets were captured by CSAP on "
              "@p tst_if interface");
    CHECK_RECEIVED(PACKETS_TO_SEND);

    if (is_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    if (csap_created)
        tapi_tad_csap_destroy(pco_tst->ta, sid, csap);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (saved_all)
    {
        tapi_cfg_save_del_if_addresses(pco_iut->ta,
                                       iut_if->if_name,
                                       NULL, FALSE,
                                       NULL, NULL, NULL, NULL, af);

        tapi_cfg_restore_if_addresses(pco_iut->ta, iut_if->if_name,
                                      saved_addrs, saved_prefixes,
                                      saved_broadcasts, saved_count);
    }

    if (route_added)
        tapi_cfg_del_route(&route_handle);

    if (addr_allocated)
        tapi_cfg_free_entry(&new_addr_handle);
    if (net_allocated)
        tapi_cfg_free_entry(&net_handle);

    if (af == AF_INET6)
    {
        /*
         * This is done to avoid FAILED neighbor entries on IPv6.
         * They can break network for the next tests.
         */
        CLEANUP_CHECK_RC(tapi_cfg_base_if_down_up(pco_iut->ta,
                                                  iut_if->if_name));
        CLEANUP_CHECK_RC(tapi_cfg_base_if_down_up(pco_tst->ta,
                                                  tst_if->if_name));
        CLEANUP_CHECK_RC(sockts_wait_for_if_up(pco_iut,
                                               iut_if->if_name));
        CLEANUP_CHECK_RC(sockts_wait_for_if_up(pco_tst,
                                               tst_if->if_name));
    }

    TEST_END;
}
