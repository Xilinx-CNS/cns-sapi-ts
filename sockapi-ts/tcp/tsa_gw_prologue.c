/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Prologue to configure gateway for CSAP_GW mode
 * in TSA library.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "tcp/tsa_gw_prologue"

#include "sockapi-test.h"
#include "tapi_route_gw.h"

int
main(int argc, char *argv[])
{
    tapi_env_pco *env_pco_gw = NULL;

    const struct sockaddr *tst_fake_addr = NULL;

    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;

    tapi_route_gateway gateway;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_ADDR(pco_tst, tst_fake_addr);

    TAPI_INIT_ROUTE_GATEWAY(gateway);

    tapi_route_gateway_configure(&gateway);

    /*
     * Configure additional route for @p tst_fake_addr which is
     * an IP address not assigned to any host. It is preferable
     * to use such address for CSAP TCP socket emulation.
     */

    CHECK_RC(tapi_cfg_add_route_via_gw(
                   pco_iut->ta,
                   tst_fake_addr->sa_family,
                   te_sockaddr_get_netaddr(tst_fake_addr),
                   te_netaddr_get_size(tst_fake_addr->sa_family) * 8,
                   te_sockaddr_get_netaddr(gw_iut_addr)));

    /*
     * We need to add IPv6 neighbors entries manually because there are
     * cases when Linux can not re-resolve FAILED entries for gateway
     * routes. See bug 9774.
     */
    if (tst_fake_addr->sa_family == AF_INET6)
    {
        CHECK_RC(tapi_update_arp(pco_gw->ta, gw_tst_if->if_name,
                                 pco_tst->ta, tst_if->if_name,
                                 tst_fake_addr, NULL, FALSE));
    }

    CFG_WAIT_CHANGES;

    CHECK_RC(rc = cfg_synchronize("/:", TRUE));

    env_pco_gw = (tapi_env_pco *)tapi_env_rpcs2pco(&env, pco_gw);
    if (env_pco_gw == NULL)
        TEST_FAIL("Failed to find environment structure for pco_gw");

    /*
     * This makes this prologue not to remove @p pco_gw in cleanup,
     * so that for all tests in the same session @p pco_gw is
     * preexisting, and they do not try to create it at the beginning
     * and destroy it in cleanup, reusing it instead. This makes things
     * faster.
     */
    env_pco_gw->created = FALSE;

    TEST_SUCCESS;

cleanup:

    TEST_END;
}
