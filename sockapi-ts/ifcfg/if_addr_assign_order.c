/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Routing table
 */

/** @page ifcfg-if_addr_assign_order Add IP address before or after bringing interface up
 *
 * @objective Assign an IP address to the interface before or after bringing
 *            that interface up, check data transmission.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on @p IUT
 * @param pco_tst       PCO on @p TESTER
 * @param assign_first  Assign an address to the interface before or after
 *                      bringing it up
 *
 * @par Test sequence:
 *
 * -# Remove all IPv4 addresses and routes via @p iut_if interface;
 * -# Bring @p iut_if interface down;
 * -# Perform the following steps in different order according to
 *    @p assign_first value:
 *    - Assign an address/network to the @p iut_if interface;
 *    - Bring @p iut_if interface up;
 * -# Restore routes via @p iut_if interface;
 * -# Create @c SOCK_STREAM connection between @p pco_iut and @p pco_tst;
 * -# Check that data could be successfully sent and received.
 * -# Bring @p iut_if interface down and up again;
 * -# Check that connection is alive;
 * -# Close the connection;
 *
 * @author Nikita Rastegaev <Nikita.Rastegaev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ifcfg/if_addr_assign_order"

#include "sockapi-test.h"
#include "tapi_cfg_base.h"


int
main(int argc, char *argv[])
{
    tapi_env_net          *net = NULL;

    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_iut_thread = NULL;
    rcf_rpc_server        *pco_tst = NULL;

    const struct if_nameindex *iut_if = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    int                    iut_s = -1;
    int                    tst_s = -1;

    uint64_t               received = 0;
    uint64_t               sent     = 0;

    struct sockaddr       *saved_addrs = NULL;
    int                   *saved_prefixes = NULL;
    te_bool               *saved_broadcasts = NULL;
    int                    saved_count = 0;
    te_bool                saved_all = FALSE;

    te_bool                assign_first;

    tapi_rt_entry_t       *iut_rt_tbl;
    unsigned int           n;
    unsigned int           i;

    int                    af;
    rpc_socket_domain      domain;

    cfg_handle             addr_handle = CFG_HANDLE_INVALID;
    cfg_handle             route_handle = CFG_HANDLE_INVALID;

    TEST_START;

    TEST_GET_NET(net);

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_IF(iut_if);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    TEST_GET_BOOL_PARAM(assign_first);

    CHECK_RC(rcf_rpc_server_thread_create(pco_iut, "pco_iut_thread",
                                          &pco_iut_thread));

    domain = rpc_socket_domain_by_addr(iut_addr);
    af = addr_family_rpc2h(sockts_domain2family(domain));

    CHECK_RC(tapi_cfg_get_route_table(pco_iut->ta, af, &iut_rt_tbl, &n));

    for (i = 0; i < n; i++)
        if ((strcmp(iut_rt_tbl[i].dev, iut_if->if_name) == 0) &&
            (iut_rt_tbl[i].table == TAPI_RT_TABLE_MAIN))
            CHECK_RC(tapi_cfg_del_route(&(iut_rt_tbl[i].hndl)));

    CHECK_RC(tapi_cfg_save_del_if_ip4_addresses(pco_iut->ta,
                                                iut_if->if_name,
                                                NULL, FALSE,
                                                &saved_addrs,
                                                &saved_prefixes,
                                                &saved_broadcasts,
                                                &saved_count));
    saved_all = TRUE;

    CHECK_RC(tapi_cfg_base_if_down(pco_iut->ta, iut_if->if_name));
    CFG_WAIT_CHANGES;

    if (!assign_first)
    {
        CHECK_RC(tapi_cfg_base_if_up(pco_iut->ta, iut_if->if_name));
        CHECK_RC(sockts_wait_for_if_up(pco_iut_thread, iut_if->if_name));
    }

    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if->if_name,
                                           iut_addr, net->ip4pfx, FALSE,
                                           &addr_handle));
    CFG_WAIT_CHANGES;

    if (assign_first)
    {
        CHECK_RC(tapi_cfg_base_if_up(pco_iut->ta, iut_if->if_name));
        CHECK_RC(sockts_wait_for_if_up(pco_iut_thread, iut_if->if_name));
    }

    for (i = 0; i < n; i++)
        if ((strcmp(iut_rt_tbl[i].dev, iut_if->if_name) == 0) &&
            (iut_rt_tbl[i].table == TAPI_RT_TABLE_MAIN))
            CHECK_RC(tapi_cfg_modify_route(pco_iut->ta, AF_INET,
                                           te_sockaddr_get_netaddr(
                                                SA(&iut_rt_tbl[i].dst)),
                                           iut_rt_tbl[i].prefix,
                                           SA(&iut_rt_tbl[i].gw),
                                           iut_rt_tbl[i].dev,
                                           te_sockaddr_get_netaddr(
                                                SA(&iut_rt_tbl[i].src)),
                                           iut_rt_tbl[i].flags,
                                           iut_rt_tbl[i].metric, 0,
                                           iut_rt_tbl[i].mtu,
                                           iut_rt_tbl[i].win,
                                           iut_rt_tbl[i].irtt,
                                           &(route_handle)));
    CFG_WAIT_CHANGES;

    GEN_CONNECTION(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   tst_addr, iut_addr, &tst_s, &iut_s);

#define SEND_AND_RECEIVE        \
    do {                                                                \
        if (rpc_simple_sender(pco_iut, iut_s, 1, 10, 0, 0, 10000, 0, 2, \
                              &sent, 0) < 0)                            \
            TEST_VERDICT("Failed to send data via interface, errno=%s", \
                         errno_rpc2str(RPC_ERRNO(pco_iut)));            \
        if (rpc_simple_receiver(pco_tst, tst_s, 0, &received) < 0)      \
            TEST_FAIL("Simple receiver failure");                       \
        if (sent != received)                                           \
            TEST_FAIL("Data corrupted");                                \
    } while (0)

    SEND_AND_RECEIVE;

    CHECK_RC(tapi_cfg_base_if_down(pco_iut->ta, iut_if->if_name));
    CFG_WAIT_CHANGES;

    CHECK_RC(tapi_cfg_base_if_up(pco_iut->ta, iut_if->if_name));
    CHECK_RC(sockts_wait_for_if_up(pco_iut_thread, iut_if->if_name));

    SEND_AND_RECEIVE;

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_thread));

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

    TEST_END;
}

