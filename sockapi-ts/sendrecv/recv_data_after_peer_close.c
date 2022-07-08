/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 */

/** @page sendrecv-recv_data_after_peer_close Receive data after peer close
 *
 * @objective Check that receiving functions return correct data after peer close.
 *
 * @type conformance
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 *                  - @ref arg_types_env_peer2peer_fake
 *                  - @ref arg_types_env_peer2peer_fake_ipv6
 * @param data      If value is @c TRUE send data from IUT before peer
 *                  close. If value is @c FALSE don't send data.
 * @param func      Function to be used in the test to receive data:
 *                  - @ref arg_types_recv_func_with_flags
 *
 * @par Scenario:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/recv_data_after_peer_close"

#include "sockapi-test.h"
#include "rpc_sendrecv.h"

#define BUF_SIZE      4096

static char tx_buf[BUF_SIZE];
static char rx_buf[BUF_SIZE + 1];

int
main(int argc, char *argv[])
{
    /* Environment variables */
    const char         *func;
    te_bool             data;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int     iut_s = -1;
    int     tst_s = -1;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(data);
    TEST_GET_STRING_PARAM(func);

    TEST_STEP("Create a pair of connected TCP sockets on IUT and Tester.");
    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                        tst_addr, iut_addr, &tst_s, &iut_s);

    TEST_STEP("If @p data is @c TRUE, send some data from the IUT "
              "socket.");
    if (data)
        RPC_SEND(rc, pco_iut, iut_s, tx_buf, BUF_SIZE, 0);

    TEST_STEP("Send some data from the Tester socket.");
    te_fill_buf(tx_buf, BUF_SIZE);
    RPC_SEND(rc, pco_tst, tst_s, tx_buf, BUF_SIZE, 0);

    TEST_STEP("Wait for a while to let data from Tester reach IUT.");
    TAPI_WAIT_NETWORK;

    TEST_STEP("Close the Tester socket and wait for some time again, so "
              "that @c FIN or @c RST reaches IUT.");
    RPC_CLOSE(pco_tst, tst_s);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Call @p func on the IUT socket, check that it successfully "
              "returns data sent from Tester.");
    RPC_AWAIT_ERROR(pco_iut);
    rc = recv_by_func(func, pco_iut, iut_s, rx_buf, sizeof(rx_buf), 0);
    if (rc < 0)
    {
        TEST_VERDICT("Receive function called after peer socket closing "
                     "failed with error " RPC_ERROR_FMT,
                     RPC_ERROR_ARGS(pco_iut));
    }
    else if (rc == 0)
    {
        TEST_VERDICT("The first call of receiving function returned zero "
                     "bytes");
    }
    SOCKTS_CHECK_RECV_EXT(pco_iut, tx_buf, rx_buf, BUF_SIZE, rc,
                          "The first call of receiving function");

    TEST_STEP("Call @p func on the IUT socket again. Check that if "
              "@p data is @c TRUE, it fails with @c ECONNRESET ("
              "since @c RST is sent from the Tester socket); otherwise "
              "check that it returns @c 0.");
    RPC_AWAIT_ERROR(pco_iut);
    rc = recv_by_func(func, pco_iut, iut_s, rx_buf, sizeof(rx_buf), 0);
    if (data)
    {
        if (rc >= 0)
        {
            TEST_VERDICT("The second call of receiving function succeded "
                         "unexpectedly");
        }
        CHECK_RPC_ERRNO(pco_iut, RPC_ECONNRESET,
                        "the second call of receiving function failed, "
                        "but");
    }
    else if (rc != 0)
    {
        if (rc < 0)
        {
            TEST_VERDICT("The second call of receiving function failed "
                         "unexpectedly with error " RPC_ERROR_FMT,
                         RPC_ERROR_ARGS(pco_iut));
        }
        else
        {
            TEST_VERDICT("The second call of receiving function returned "
                         "positive number");
        }
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CHECK_CLEAR_TRANSPARENT(iut_addr, pco_tst, tst_addr);

    TEST_END;
}
