/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Epilogue used to reset interfaces after different gateway settings.
 *
 * @author Roman Zhukov <Roman.Zhukov@oktetlabs.ru>
 */

#define TE_TEST_NAME "gateways_epilogue"

#include "sockapi-test.h"
#include "tapi_route_gw.h"

int
main(int argc, char *argv[])
{
    tapi_route_gateway gw;
    int af_xdp_zc = 0;
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;

    TAPI_INIT_ROUTE_GATEWAY(gw);

    /*
     * Tests with IPv6 gateways require reset all interfaces in gateway
     * connection. Only after this other tests will be able to resolve IPv6
     * neighbors without problems.
     */
    CHECK_RC(tapi_route_gateway_down_up_ifaces(&gw));

    CHECK_RC(sockts_wait_for_if_up(pco_iut, iut_if->if_name));
    CHECK_RC(sockts_wait_for_if_up(pco_tst, tst_if->if_name));
    CHECK_RC(sockts_wait_for_if_up(pco_gw, gw_iut_if->if_name));
    CHECK_RC(sockts_wait_for_if_up(pco_gw, gw_tst_if->if_name));

    if (tapi_sh_env_get_int(pco_iut, "EF_AF_XDP_ZEROCOPY", &af_xdp_zc) == 0 &&
        af_xdp_zc == 1)
    {
        sockts_recreate_onload_stack(pco_iut);
        rcf_rpc_server_restart(pco_iut);
    }

    TEST_SUCCESS;

cleanup:

    TEST_END;
}
