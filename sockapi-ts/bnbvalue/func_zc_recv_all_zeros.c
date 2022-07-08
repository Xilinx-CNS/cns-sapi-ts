/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_zc_recv_all_zeros Using onload_zc_recv() function with all the arguments except socket fd equal to zero (NULL)
 *
 * @objective Check that @b onload_zc_recv() function successfully completes 
 *            when it is called with all the arguments except socket fd
 *            equal to zero (NULL).
 *
 * @type conformance, robustness
 *
 * @param pco_iut   PCO on IUT
 * @param pco_tst   PCO on TESTER
 * @param iut_addr  Network address on IUT
 * @param tst_addr  Network address on TESTER
 *
 * @par Scenario:
 *
 * -# Create @c SOCK_DGRAM socket @p iut_s on @p pco_iut.
 * -# Call @b onload_zc_recv(@p iut_s, @c NULL).
 * -# Check that the function returns @c 0 and does not update @b errno
 *    variable.
 * 
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_zc_recv_all_zeros"

#include "sockapi-test.h"

#define BUF_LEN 512
int 
main(int argc, char *argv[]) 
{ 
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    te_bool     op_done;
    char       *data_buf = NULL; 

    TEST_START; 
    
    /* Preambule */ 
    TEST_GET_PCO(pco_iut); 
    TEST_GET_PCO(pco_tst); 
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    data_buf = te_make_buf_by_len(BUF_LEN);

    iut_s = rpc_socket(pco_iut, RPC_PF_INET, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr);
    tst_s = rpc_socket(pco_tst, RPC_PF_INET, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    pco_iut->op = RCF_RPC_CALL;
    rpc_simple_zc_recv_null(pco_iut, iut_s); 

    SLEEP(1);

    rc = rcf_rpc_server_is_op_done(pco_iut, &op_done);

    if (TE_RC_GET_ERROR(rc) == TE_ERPCDEAD)
    {
        iut_s = -1;
        rcf_rpc_server_restart(pco_iut);
        TEST_VERDICT("RPC server is dead after onload_zc_recv() call");
    }
    else if (!op_done)
    {
        RING_VERDICT("onload_zc_recv() blocks");
        rpc_sendto(pco_tst, tst_s, data_buf, BUF_LEN, 0, iut_addr);
        TAPI_WAIT_NETWORK;
        rc = rcf_rpc_server_is_op_done(pco_iut, &op_done);

        if (TE_RC_GET_ERROR(rc) == TE_ERPCDEAD)
        {
            iut_s = -1;
            rcf_rpc_server_restart(pco_iut);
            TEST_VERDICT("RPC server is dead after trying to unblock "
                         "onload_zc_recv() call");
        } else if (!op_done)
        {
            iut_s = -1;
            rcf_rpc_server_restart(pco_iut);
            TEST_VERDICT("onload_zc_recv() cannot be unblocked "
                         "by incoming traffic");
        }
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    pco_iut->op = RCF_RPC_WAIT;
    rc = rpc_simple_zc_recv_null(pco_iut, iut_s); 
    if (rc == -1)
    {
        int err = RPC_ERRNO(pco_iut);
        
        TEST_VERDICT("onload_zc_recv() returns (-1) and "
                     "errno is set to %s",
                     errno_rpc2str(err));
    }
    if (rc != 0)
         TEST_FAIL("onload_zc_recv() returns not 0 (%d)", rc);

    TEST_SUCCESS; 
 
cleanup:

    free(data_buf);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END; 
}
