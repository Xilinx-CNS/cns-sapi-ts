/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Routing table
 */

/** @page ifcfg-if_loopback_conn TCP loopback connection in various environment
 *
 * @objective Establish TCP loopback connection using different (in dependence
 *            on the iteration) binding addresses: the same or different
 *            interfaces, the same or different subnet. Also sockets can
 *            belong to single or different threads or processes.
 *
 * @type conformance
 *
 * @param pco1       PCO on @p IUT/TESTER
 * @param pco2       PCO on IUT/TESTER
 * @param iut_if1    Network interface name on @p IUT
 * @param iut_if2    Network interface name on @p IUT (can be the same as
 *                   @p iut_if1 or can be different)
 * @param iut_addr1  Network address not assigned to any interface
 * @param iut_addr2  Network address not assigned to any interface from
 *                   different subnetwork than @p iut_addr1
 *
 * @par Test sequence:
 *
 * -# Add @p iut_addr1 network address to @p IUT interface @p iut_if1;
 * -# Add @p iut_addr2 network address to @p IUT interface @p iut_if2;
 * -# Create a connection between @p iut_addr1 and @p iut_addr2;
 * -# Check that the connection is created;
 * -# Destroy the connection.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ifcfg/if_loopback_conn"

#include "sockapi-test.h"
#include "tapi_cfg_base.h"

int
main(int argc, char *argv[])
{
    tapi_env_net          *net1 = NULL;
    tapi_env_net          *net2 = NULL;
    rcf_rpc_server        *pco1 = NULL;
    rcf_rpc_server        *pco2 = NULL;

    const struct if_nameindex *if1 = NULL;
    const struct if_nameindex *if2 = NULL;

    struct sockaddr       *addr1 = NULL;
    struct sockaddr       *addr2 = NULL;

    int s1 = -1;
    int s2 = -1;

    TEST_START;

    TEST_GET_NET(net1);
    TEST_GET_NET(net2);
    TEST_GET_PCO(pco1);
    TEST_GET_PCO(pco2);
    TEST_GET_IF(if1);
    TEST_GET_IF(if2);

    CHECK_RC(tapi_env_allocate_addr(net1, AF_INET, &addr1, NULL));
    CHECK_RC(tapi_env_allocate_addr(net2, AF_INET, &addr2, NULL));

    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco1->ta, if1->if_name, addr1,
                                           net1->ip4pfx, FALSE, NULL));
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco2->ta, if2->if_name, addr2,
                                           net2->ip4pfx,  FALSE, NULL));
    CFG_WAIT_CHANGES;

    GEN_CONNECTION(pco1, pco2, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   addr1, addr2, &s1, &s2);
    sockts_test_connection(pco1, s1, pco2, s2);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco1, s1);
    CLEANUP_RPC_CLOSE(pco2, s2);
    TEST_END;
}
