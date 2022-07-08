/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Reliability of Socket API in Normal Use
 */

/** @page usecases-ipv6_del_ll_addrs_transmit Transmitting data after removal of link-local IPv6 addresses and neighbor entries
 *
 * @objective Check that connection can be established and/or data can be
 *            transmitted after removal of link-local IPv6 addresses and
 *            neighbor entries from tested interfaces.
 *
 * @type use case
 *
 * @param env               Testing environment:
 *                          - @ref arg_types_env_peer2peer_ipv6
 *                          - @ref arg_types_env_peer2peer_tst_ipv6
 *                          - @ref arg_types_env_peer2peer_lo_ipv6
 * @param sock_type         Socket type
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME    "usecases/ipv6_del_ll_addrs_transmit"

#include "sockapi-test.h"

/**
 * Remove and/or count all the IPv6 link-local addresses on a given
 * interface.
 *
 * @param ta        Test Agent name.
 * @param if_name   Interface name.
 * @param remove    Whether link-local addresses should be removed.
 *
 * @return Count of link-local addresses.
 */
static unsigned int
remove_count_ll_addrs(const char *ta, const char *if_name,
                      te_bool remove)
{
    cfg_handle                 *addrs = NULL;
    unsigned int                addr_num = 0;
    unsigned int                i;
    unsigned int                count = 0;

    char                       *addr_str = NULL;
    struct sockaddr_storage     addr;

    CHECK_RC(cfg_synchronize_fmt(TRUE, "/agent:%s/interface:%s",
                                 ta, if_name));
    CHECK_RC(cfg_find_pattern_fmt(&addr_num, &addrs,
                                  "/agent:%s/interface:%s/net_addr:*",
                                  ta, if_name));

    for (i = 0; i < addr_num; i++)
    {
        CHECK_RC(cfg_get_inst_name(addrs[i], &addr_str));
        CHECK_RC(te_sockaddr_netaddr_from_string(addr_str, SA(&addr)));

        if (addr.ss_family != AF_INET6)
        {
            free(addr_str);
            continue;
        }

        if (IN6_IS_ADDR_LINKLOCAL(&SIN6(&addr)->sin6_addr))
        {
            if (remove)
            {
                CHECK_RC(cfg_del_instance(addrs[i], FALSE));
            }
            else
            {
                RING("Found link-local IPv6 address %s on "
                     "/agent:%s/interface:%s", addr_str, ta, if_name);
            }

            count++;
        }
        free(addr_str);
    }

    free(addrs);
    return count;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *tst_if = NULL;

    sockts_socket_type  sock_type;
    int                 iut_s = -1;
    int                 iut_l = -1;
    int                 tst_s = -1;
    te_errno            rc1 = 0;
    te_errno            rc2 = 0;
    unsigned int        count = 0;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    SOCKTS_GET_SOCK_TYPE(sock_type);

    TEST_STEP("Remove all IPv6 link-local addresses from @p iut_if "
              "and @p tst_if.");
    (void)remove_count_ll_addrs(pco_iut->ta, iut_if->if_name, TRUE);
    (void)remove_count_ll_addrs(pco_tst->ta, tst_if->if_name, TRUE);

    TEST_STEP("Remove all dynamic neighbor entries for @p iut_if and "
              "@p tst_if.");
    CHECK_RC(tapi_cfg_del_neigh_dynamic(pco_iut->ta, iut_if->if_name));
    CHECK_RC(tapi_cfg_del_neigh_dynamic(pco_tst->ta, tst_if->if_name));

    CFG_WAIT_CHANGES;

    TEST_STEP("Create sockets @b iut_s on IUT and @b tst_s on Tester, "
              "establish connection according to @p sock_type.");
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr,
                      sock_type, &iut_s, &tst_s, &iut_l);

    TEST_STEP("Check that data can be sent from @b iut_s and received "
              "on @b tst_s.");
    rc1 = sockts_test_send(pco_iut, iut_s, pco_tst, tst_s,
                           NULL,
                           (sock_type == SOCKTS_SOCK_UDP_NOTCONN ?
                                                       tst_addr : NULL),
                           RPC_PF_UNKNOWN,
                           (sock_type_sockts2rpc(sock_type) ==
                                                        RPC_SOCK_DGRAM),
                           "Sending data from IUT");

    TEST_STEP("Check that data can be sent from @b tst_s and received "
              "on @b iut_s.");
    rc2 = sockts_test_send(pco_tst, tst_s, pco_iut, iut_s,
                           NULL, iut_addr, RPC_PF_UNKNOWN,
                           (sock_type_sockts2rpc(sock_type) ==
                                                        RPC_SOCK_DGRAM),
                           "Sending data from Tester");

    /*
     * It's better to close sockets before interfaces restart, otherwise
     * the next iteration may fail on pure Linux with EHOSTUNREACH in
     * connect() on Tester.
     */
    TEST_STEP("Close the checked sockets.");
    RPC_CLOSE(pco_iut, iut_s);
    if (iut_l >= 0)
        RPC_CLOSE(pco_iut, iut_l);
    RPC_CLOSE(pco_tst, tst_s);

    TEST_STEP("Set down/up checked interfaces to bring link-local "
              "addresses back. Check that after that the IUT interface "
              "has link-local IPv6 address.");
    CHECK_RC(sockts_ifs_down_up(pco_iut, iut_if, pco_tst, tst_if,
                                NULL));

    count = remove_count_ll_addrs(pco_iut->ta, iut_if->if_name, FALSE);
    if (count == 0)
    {
        TEST_VERDICT("IPv6 link-local address did not reappear on "
                     "the IUT interface");
    }
    else if (count > 1)
    {
        RING_VERDICT("More than one IPv6 link-local address appeared on "
                     "the IUT interface after setting it down/up");
    }

    if (rc1 != 0 || rc2 != 0)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_l);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
