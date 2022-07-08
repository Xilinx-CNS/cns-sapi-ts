/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 */

/** @page sendrecv-recv_dontwait_peer_close MSG_DONTWAIT flag when peer closes its socket
 *
 * @objective Check that @c MSG_DONTWAIT flag is supported for receiving
 *            and works fine when peer closes its socket.
 *
 * @type conformance
 *
 * @reference @ref STEVENS section 13.3
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 *                  - @ref arg_types_env_peer2peer_fake
 * @param func      Function to be used in the test to receive data:
 *                  - @ref arg_types_recv_func_with_flags
 *
 * @par Scenario:
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/recv_dontwait_peer_close"

#include "sockapi-test.h"
#include "rpc_sendrecv.h"


int
main(int argc, char *argv[])
{
    /* Environment variables */
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_tst = NULL;
    const char         *func = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int                     iut_s = -1;
    int                     tst_s = -1;
    char                    rx_buf[10];

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(func);

    TEST_STEP("Create a pair of connected TCP sockets on IUT and Tester.");
    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                        tst_addr, iut_addr, &tst_s, &iut_s);

    TEST_STEP("Close the Tester socket and wait for a while so that @c FIN "
              "reaches IUT.");
    RPC_CLOSE(pco_tst, tst_s);

    TAPI_WAIT_NETWORK;

    TEST_STEP("Call @p func with @c MSG_DONTWAIT, check that it "
              "returns @c 0.");
    RPC_AWAIT_ERROR(pco_iut);
    rc = recv_by_func(func, pco_iut, iut_s, rx_buf, sizeof(rx_buf),
                      RPC_MSG_DONTWAIT);
    if (rc < 0)
    {
        TEST_VERDICT("Receiving function failed with errno " RPC_ERROR_FMT,
                     RPC_ERROR_ARGS(pco_iut));
    }
    else if (rc != 0)
    {
        TEST_VERDICT("Receiving function called with MSG_DONTWAIT flag "
                     "returned nonzero after peer closed connection");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    CHECK_CLEAR_TRANSPARENT(iut_addr, pco_tst, tst_addr);

    TEST_END;
}
