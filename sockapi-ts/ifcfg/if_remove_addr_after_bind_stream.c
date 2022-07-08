/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Network interface related tests
 */

/** @page ifcfg-if_remove_addr_after_bind_stream Remove IP address after TCP socket binding, try to connect the socket
 *
 * @objective Check that connect() on a bound TCP socket fails if local
 *            address is removed. But the socket can be connected when the
 *            address is back.
 *
 * @type conformance
 *
 * @param pco_iut   PCO on @p IUT
 * @param pco_tst   PCO on @p TESTER
 *
 * @par Test sequence:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ifcfg/if_remove_addr_after_bind_stream"

#include "sockapi-test.h"
#include "tapi_cfg_base.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    const struct sockaddr *tst_addr = NULL;
    tapi_env_net          *net1;
    struct sockaddr       *iut_addr;
    cfg_handle             iut_addr_handle = CFG_HANDLE_INVALID;

    const struct if_nameindex *iut_if = NULL;

    int iut_s = -1;
    int tst_s = -1;
    int acc_s = -1;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_NET(net1);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);

    TEST_STEP("Add IP address on IUT interface.");
    CHECK_RC(tapi_env_allocate_addr(net1, AF_INET, &iut_addr, NULL));
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if->if_name,
                                           iut_addr, net1->ip4pfx, FALSE,
                                           &iut_addr_handle));
    CFG_WAIT_CHANGES;

    TEST_STEP("Create and bind TCP socket on IUT.");
    iut_s = rpc_socket(pco_iut, RPC_AF_INET, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr);

    TEST_STEP("Create listener socket on tester.");
    tst_s = rpc_socket(pco_tst, RPC_AF_INET, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);
    rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);

    TEST_STEP("Delete added address from IUT interface.");
    CHECK_RC(cfg_del_instance(iut_addr_handle, FALSE));
    iut_addr_handle = CFG_HANDLE_INVALID;
    CFG_WAIT_CHANGES;

    TEST_STEP("Check that connection attempt from IUT socket fails with "
              "errno @c EINVAL.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_connect(pco_iut, iut_s, tst_addr);
    if (rc != -1)
    {
        TEST_VERDICT("Connect() from removed IP address returns %d", rc);
    }
    /* More about errno codes read in ST-1844. */
    else if (RPC_ERRNO(pco_iut) != RPC_EINVAL &&
             RPC_ERRNO(pco_iut) != RPC_ENETUNREACH)
    {
        RING_VERDICT("Connect() from removed IP address failed with "
                     "unexpected errno %r instead of %r or %r",
                     RPC_ERRNO(pco_iut), RPC_EINVAL, RPC_ENETUNREACH);
    }

    TEST_STEP("Add the address back to IUT interface.");
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if->if_name,
                                           iut_addr, net1->ip4pfx, FALSE,
                                           &iut_addr_handle));
    CFG_WAIT_CHANGES;

    TEST_STEP("Connect from the IUT socket again.");
    rpc_connect(pco_iut, iut_s, tst_addr);

    TEST_STEP("Accept connection on tester this time.");
    acc_s = rpc_accept(pco_tst, tst_s, NULL, NULL);

    TEST_STEP("Check data transmission in both directions.");
    sockts_test_connection(pco_iut, iut_s, pco_tst, acc_s);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, acc_s);

    if (iut_addr_handle != CFG_HANDLE_INVALID)
    {
        CLEANUP_CHECK_RC(cfg_del_instance(iut_addr_handle, FALSE));
        CFG_WAIT_CHANGES;
    }

    TEST_END;
}
