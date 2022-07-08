/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Level5-specific test reproducing run out of hardware resources
 *
 * $Id$
 */

/** @page level5-out_of_resources-out_of_hw_filters_udp_bind_connect Hardware filters exhaustion caused by bind() and connect() operations on UDP sockets
 *
 * @objective Check that Level5 library does not return error
 *            when there are no more UDP hardware filters available
 *            when creating, binding and connecting UDP sockets.
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

#define TE_TEST_NAME \
    "level5/out_of_resources/out_of_hw_filters_udp_bind_connect"

#include "out_of_resources.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_aux = NULL;
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *iut_if2 = NULL;
    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;
    
    struct sockaddr_storage tmp;
    socklen_t               tmplen = sizeof(tmp);

    int                     hw_filters = -1;
    int                     hw_filters_max;
    int                     req_num;
    int                     sock_num;
    te_bool                 bind;
    te_bool                 bind_only;
    te_bool                 wild;
    te_bool                 ef_no_fail;

    int loglevel = 0;
    int iut_s_1;
    int iut_s_2;
    int iut_s;
    int tst_s = -1;
    int acc;
    int err;

    TEST_START;

    TEST_GET_PCO(pco_aux);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    TEST_GET_BOOL_PARAM(bind);
    TEST_GET_BOOL_PARAM(bind_only);
    TEST_GET_BOOL_PARAM(wild);
    TEST_GET_BOOL_PARAM(ef_no_fail);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(iut_if2);

    TAPI_SYS_LOGLEVEL_DEBUG(pco_aux, &loglevel);

    hw_filters_max = get_hw_filters_limit(pco_aux);

    req_num = hw_filters_max * HW_FILTERS_MULT;

    if (wild)
        te_sockaddr_set_wildcard(SA(iut_addr));

    TEST_STEP("Increase RTLIMIT and create child process.");
    CHECK_RC(rcf_rpc_server_fork(pco_aux, "child", &pco_iut));
    prepare_parent_pco(pco_iut, 2 * hw_filters_max);
    CHECK_RC(rcf_rpc_server_exec(pco_iut));


    pco_iut->timeout = 100000;

    TEST_STEP("In the loop create socket, bind and connect it. Calculate number of "
              "created and accelerated after all sockets.");
    sock_num = rpc_out_of_hw_filters_do(pco_iut, bind, iut_addr, tst_addr,
        RPC_SOCK_DGRAM, bind_only ? RPC_OOR_BIND : RPC_OOR_CONNECT, req_num,
        &acc, &err, &iut_s_1, &iut_s_2);

    RING("Created sockets number %d/%d/%d/%d", req_num, sock_num, acc, err);

    TEST_STEP("Check that the last and the first sockets can send/receive data.");
    if (!bind_only)
    {
        for (iut_s = iut_s_1; TRUE; iut_s = iut_s_2)
        {
            tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                               RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
            rpc_bind(pco_tst, tst_s, tst_addr);
            rpc_getsockname(pco_iut, iut_s, (struct sockaddr *)&tmp, &tmplen);
            rpc_connect(pco_tst, tst_s, SA(&tmp));
            sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);
            RPC_CLOSE(pco_tst, tst_s);
            if (iut_s == iut_s_2)
                break;
        }
    }
    /*
     * If @p wild is @c TRUE number of accelerated sockets
     * cannot be used to check the total number of observed HW filters
     * because the distribution of filters between sockets is unequal.
     */
    if (wild && bind_only)
        hw_filters = get_wild_sock_hw_filters_num(pco_aux);

    TEST_STEP("Check requested, opened and accelerated sockets numbers.");
    hw_filters_check_results(ef_no_fail, req_num, sock_num, acc, err,
                             hw_filters_max, hw_filters);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    rcf_rpc_server_destroy(pco_iut);

    TAPI_SYS_LOGLEVEL_CANCEL_DEBUG(pco_aux, loglevel);

    TEST_END;
}
