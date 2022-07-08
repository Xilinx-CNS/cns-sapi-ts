/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Level5-specific test reproducing run out of hardware resources
 *
 * $Id$
 */

/** @page level5-out_of_resources-out_of_hw_filters_tcp Hardware filters exhaustion caused by bind() and connect() operations on TCP sockets
 *
 * @objective Check that Level5 library does not return error
 *            when there are no more TCP hardware filters available
 *            when creating and connecting TCP sockets.
 *
 * @type conformance, robustness
 *
 * @param pco_aux           PCO on IUT
 * @param pco_tst           PCO on Tester
 * @param iut_addr          Local address on IUT
 * @param tst_addr          Remote address for IUT
 * @param ef_no_fail        Whether EF_NO_FAIL is enabled
 *
 * @par Scenario:
 *
 * @author Alexander Kukuta <Alexander.Kukuta@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/out_of_resources/out_of_hw_filters_tcp"

#include "out_of_resources.h"

#define TIMEOUT 120000

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_aux = NULL;
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    rcf_rpc_server         *pco_tst_aux = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    int                     hw_filters_max;
    te_bool                 bind;
    te_bool                 ef_no_fail;

    int iut_s_1;
    int iut_s_2;
    int tst_s;
    int tst_s_2;
    int tst_s_1;
    int req_num;
    int sock_num;
    int acc;
    int err;
    int loglevel;

    struct sockaddr_storage addr1;
    struct sockaddr_storage addr2;
    socklen_t               addr_len;
    int                     i;
    int                     accept_num;
    rpc_ptr                 accept_handle = RPC_NULL;
    te_bool                 found = FALSE;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_aux);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    TEST_GET_BOOL_PARAM(bind);
    TEST_GET_BOOL_PARAM(ef_no_fail);

    TAPI_SYS_LOGLEVEL_DEBUG(pco_iut, &loglevel);

    hw_filters_max = get_hw_filters_limit(pco_aux);
    req_num = hw_filters_max * HW_FILTERS_MULT;

    TEST_STEP("Increase RTLIMIT and create aux processes to close sockets by "
              "closing the aux processes.");
    prepare_parent_pco(pco_aux, 3 * hw_filters_max);
    CHECK_RC(rcf_rpc_server_fork(pco_aux, "child", &pco_iut));
    CHECK_RC(rcf_rpc_server_exec(pco_iut));
    prepare_parent_pco(pco_tst, 3 * hw_filters_max);
    CHECK_RC(rcf_rpc_server_fork(pco_tst, "tst_child", &pco_tst_aux));

    TEST_STEP("Create listener socket on tester.");
    tst_s = rpc_socket(pco_tst_aux, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM, RPC_IPPROTO_TCP);
    rpc_bind(pco_tst_aux, tst_s, tst_addr);
    rpc_listen(pco_tst_aux, tst_s, -1);

    rpc_fcntl(pco_tst_aux, tst_s, RPC_F_SETFL, RPC_O_NONBLOCK);

    TEST_STEP("Accept connections on tester in the loop.");
    pco_tst_aux->timeout = TIMEOUT;
    pco_tst_aux->op = RCF_RPC_CALL;
    rpc_many_accept(pco_tst_aux, tst_s, req_num + 3000, 0, 0, &tst_s_1,
                    &tst_s_2, &accept_handle);

    TEST_STEP("In the loop create socket on IUT, bind and connect it. Calculate "
              "number of created and accelerated after all sockets.");
    pco_iut->timeout = TIMEOUT;
    sock_num = rpc_out_of_hw_filters_do(pco_iut, bind, iut_addr, tst_addr,
        RPC_SOCK_STREAM, RPC_OOR_CONNECT, req_num, &acc, &err, &iut_s_1,
        &iut_s_2);

    RING("Created sockets number %d/%d/%d/%d", req_num, sock_num, acc, err);

    accept_num = rpc_many_accept(pco_tst_aux, tst_s, req_num + 3000, 0, 0,
                                 &tst_s_1, &tst_s_2, &accept_handle);
    if (accept_num != sock_num - err)
        TEST_VERDICT("Unexpected sockets number were accepted");

    rpc_fcntl(pco_tst_aux, tst_s, RPC_F_SETFL, 0);

    /*
     * Sometimes the last socket returned by rpc_many_accept() is
     * not the peer of the last IUT socket, but of some earlier
     * IUT socket.
     */

    addr_len = sizeof(addr1);
    rpc_getsockname(pco_iut, iut_s_2, SA(&addr1), &addr_len);
    addr_len = sizeof(addr2);
    rpc_getpeername(pco_tst_aux, tst_s_2, SA(&addr2), &addr_len);

    if (tapi_sockaddr_cmp(SA(&addr1), SA(&addr2)) != 0)
    {
        WARN("The last socket returned by accept() on Tester is not "
             "a peer of the last socket returned by "
             "out_of_hw_filters_do() on IUT");

        if (accept_num > 1)
        {
            for (i = accept_num - 2; i >= 0; i--)
            {
                rpc_get_socket_from_array(pco_tst_aux, accept_handle,
                                          (unsigned int)i, &tst_s_2);

                addr_len = sizeof(addr2);
                rpc_getpeername(pco_tst_aux, tst_s_2,
                                SA(&addr2), &addr_len);
                if (tapi_sockaddr_cmp(SA(&addr1), SA(&addr2)) == 0)
                {
                    found = TRUE;
                    break;
                }
            }
        }

        if (!found)
            TEST_VERDICT("Failed to find accepted socket which is "
                         "a peer of the last socket returned by "
                         "out_of_hw_filters_do()");
    }

    TEST_STEP("Check that the last and the first sockets can send/receive data.");
    sockts_test_connection(pco_iut, iut_s_1, pco_tst_aux, tst_s_1);
    sockts_test_connection(pco_iut, iut_s_2, pco_tst_aux, tst_s_2);

    TEST_STEP("Check requested, opened and accelerated sockets numbers.");
    hw_filters_check_results(ef_no_fail, req_num, sock_num, acc, err,
                             hw_filters_max, -1);

    TEST_SUCCESS;

cleanup:
    rpc_many_close(pco_tst_aux, accept_handle, req_num + 3000);
    rcf_rpc_server_destroy(pco_tst_aux);
    TAPI_WAIT_NETWORK;
    TAPI_SYS_LOGLEVEL_CANCEL_DEBUG(pco_iut, loglevel);
    rcf_rpc_server_destroy(pco_iut);

    TEST_END;
}
