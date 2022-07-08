/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Network interface related tests
 */

/** @page ifcfg-if_remove_addr_after_many_conns Remove IP address while there are a few established TCP connections, send data
 *
 * @objective Establish a few TCP connections then remove local IP address.
 *            Send data using the connections - all data should be buffered.
 *            Add the address back, all data should be retransmitted and
 *            delivered.
 *
 * @type conformance
 *
 * @param pco_iut   PCO on @p IUT
 * @param pco_tst   PCO on @p TESTER
 * @param n_cons    Number of connections to create
 *
 * @par Test sequence:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ifcfg/if_remove_addr_after_many_conns"

#include "sockapi-test.h"
#include "tapi_cfg_base.h"
#include "tapi_mem.h"

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

    size_t  tx_buflen = 1024;
    void   *rx_buf = NULL;
    void   *tx_buf = NULL;
    int     iut_s = -1;
    int    *tst_s = NULL;
    int    *acc_s = NULL;
    int     conn  = 0;
    int     i;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_NET(net1);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_INT_PARAM(conn);

    if (conn <= 0)
        TEST_FAIL("Invalid parameter conn %d, should be positive", conn);

    rx_buf = te_make_buf_by_len(SOCKTS_MSG_STREAM_MAX);
    tx_buf = sockts_make_buf_stream(&tx_buflen);
    tst_s = tapi_calloc(conn + 1, sizeof(int));
    acc_s = tapi_calloc(conn + 1, sizeof(int));

    TEST_STEP("Add IP address on IUT interface.");
    CHECK_RC(tapi_env_allocate_addr(net1, AF_INET, &iut_addr, NULL));
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if->if_name,
                                           iut_addr, net1->ip4pfx, FALSE,
                                           &iut_addr_handle));
    CFG_WAIT_CHANGES;

    TEST_STEP("Create listener socket on IUT.");
    iut_s = rpc_socket(pco_iut, RPC_AF_INET, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    TAPI_SET_NEW_PORT(pco_iut, iut_addr);
    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    TEST_STEP("Establish number @p conn TCP connections.");
    for (i = 0; i < conn; i++)
    {
        tst_s[i] = rpc_socket(pco_tst, RPC_AF_INET,
                              RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_connect(pco_tst, tst_s[i], iut_addr);
        acc_s[i] = rpc_accept(pco_iut, iut_s, NULL, NULL);
    }

    TEST_STEP("Delete added address from IUT interface.");
    CHECK_RC(cfg_del_instance(iut_addr_handle, FALSE));
    iut_addr_handle = CFG_HANDLE_INVALID;
    CFG_WAIT_CHANGES;

    TEST_STEP("Send some data from all sockets.");
    for (i = 0; i < conn; i++)
    {
        rpc_send(pco_tst, tst_s[i], tx_buf, tx_buflen, 0);
        rpc_send(pco_iut, acc_s[i], tx_buf, tx_buflen, 0);
    }

    TAPI_WAIT_NETWORK;

    TEST_STEP("Check no data is received by tester and IUT.");
    for (i = 0; i < conn; i++)
    {
        RPC_CHECK_READABILITY(pco_iut, acc_s[i], FALSE);
        RPC_CHECK_READABILITY(pco_tst, tst_s[i], FALSE);
    }

    TEST_STEP("Add the address back to IUT interface.");
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if->if_name,
                                           iut_addr, net1->ip4pfx, FALSE,
                                           &iut_addr_handle));

    TEST_STEP("Receive and check all sent data.");
    for (i = 0; i < conn; i++)
    {
        rc = rpc_read(pco_iut, acc_s[i], rx_buf, SOCKTS_MSG_STREAM_MAX);
        SOCKTS_CHECK_RECV(pco_iut, tx_buf, rx_buf, tx_buflen, rc);
        rc = rpc_read(pco_tst, tst_s[i], rx_buf, SOCKTS_MSG_STREAM_MAX);
        SOCKTS_CHECK_RECV(pco_tst, tx_buf, rx_buf, tx_buflen, rc);
    }

    TEST_STEP("Establish new connection using the same IUT listener socket.");
    tst_s[conn] = rpc_socket(pco_tst, RPC_AF_INET,
                             RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_connect(pco_tst, tst_s[conn], iut_addr);
    acc_s[conn] = rpc_accept(pco_iut, iut_s, NULL, NULL);
    conn++;

    TEST_STEP("Check data transmission in both directions.");
    for (i = 0; i < conn; i++)
        sockts_test_connection(pco_iut, acc_s[i], pco_tst, tst_s[i]);

    TEST_SUCCESS;
cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    if (tst_s != NULL)
    {   for (i = 0; i < conn; i++)
            CLEANUP_RPC_CLOSE(pco_tst, *(tst_s + i));
    }
    free(tst_s);

    if (acc_s != NULL)
    {
        for (i = 0; i < conn; i++)
            CLEANUP_RPC_CLOSE(pco_iut, *(acc_s + i));
    }
    free(acc_s);

    if (iut_addr_handle != CFG_HANDLE_INVALID)
    {
        CLEANUP_CHECK_RC(cfg_del_instance(iut_addr_handle, FALSE));
        CFG_WAIT_CHANGES;
    }

    TEST_END;
}
