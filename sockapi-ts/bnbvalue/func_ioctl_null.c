/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_ioctl_null IOCTL requests in case of NULL argument
 *
 * @objective Check the behavior of @p ioctl() requests with @c NULL
 *            argument.
 * 
 * @type conformance
 *
 * @param pco_iut               PCO on IUT
 * @param pco_tst               PCO on TESTER (used if @p rcvd_data)
 * @param iut_addr              IUT network address (used if @p rcvd_data)
 * @param tst_addr              TESTER network address (used if
 *                              @p rcvd_data)
 * @param sock_type             Socket type (@c SOCK_STREAM or
 *                              @c SOCK_DGRAM)
 * @param req                   Name of the used 
 *                              @ref bnbvalue_func_ioctl_null_req_to_test 
 *                              request
 * @param rcvd_data             Whether some data should be received on
 *                              a socket or not
 *
 * @par Test sequence:
 * -# Create socket @p iut_s @p sock_type type on @b pco_iut. Establish
 *    connection with a peer and send data to @p iut_s if @p rcvd_data.
 * -# Call @b ioctl() with @p req request and @c NULL argument on @p iut_s 
 *    socket.
 * -# Check that @p ioctl() returns @c -1 and the error code is @c ENOENT in
 *    case of @c SIOCGSTAMP or @c SIOCGSTAMP requests and @c EFAULT
 *    otherwise.
 * 
 * @par
 * @anchor bnbvalue_func_ioctl_null_req_to_test
 * Perform this test for the following requests:
 * - @c SIOCGPGRP
 * - @c SIOCSPGRP
 * - @c SIOCATMARK
 * - @c SIOCGSTAMP
 * - @c SIOCGSTAMPNS
 * - @c FIOASYNC
 * - @c FIONBIO
 * - @c FIONREAD
 * - @c SIOCINQ
 * - @c SIOCGIFCONF
 * - @c SIOCGIFFLAGS
 * - @c SIOCSIFFLAGS
 * - @c SIOCGIFADDR
 * - @c SIOCSIFADDR
 * - @c SIOCGIFNETMASK
 * - @c SIOCSIFNETMASK
 * - @c SIOCGIFBRDADDR
 * - @c SIOCSIFBRDADDR
 * - @c SIOCGIFDSTADDR
 * - @c SIOCSIFDSTADDR
 * - @c SIOCGIFHWADDR
 * - @c SIOCGIFMTU
 * - @c SIOCSIFMTU
 *   
 * @author Georgij Volfson <Georgij.Volfson@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_ioctl_null"

#include "sockapi-test.h"

#define BUF_SIZE 1024

int
main(int argc, char *argv[])
{
    rpc_socket_type         sock_type;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    int                     iut_s = -1;
    int                     tst_s = -1;
    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    rpc_ioctl_code          req;
    te_bool                 rcvd_data;
    te_bool                 op_done;

    te_bool                 passive = FALSE;
    char    tx_buf[BUF_SIZE];

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(passive);
    TEST_GET_IOCTL_REQ(req);
    TEST_GET_BOOL_PARAM(rcvd_data);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);


    if (!rcvd_data)
    {
        iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                           sock_type, RPC_PROTO_DEF);
    }
    else
    {
        if (passive)
            GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                           iut_addr, tst_addr, &iut_s, &tst_s);
        else
            GEN_CONNECTION(pco_tst, pco_iut, sock_type, RPC_PROTO_DEF,
                           tst_addr, iut_addr, &tst_s, &iut_s);
        if (sock_type == RPC_SOCK_STREAM)
        {
            /* This may be useful to test @c SIOCATMARK */
            rpc_send(pco_tst, tst_s, tx_buf, BUF_SIZE, RPC_MSG_OOB);
            TAPI_WAIT_NETWORK;
        }
        rpc_send(pco_tst, tst_s, tx_buf, BUF_SIZE, 0);
        TAPI_WAIT_NETWORK;
    }

    pco_iut->op = RCF_RPC_CALL;
    rpc_ioctl(pco_iut, iut_s, req, NULL);

    SLEEP(1);

    if (!rcf_rpc_server_is_alive(pco_iut))
    {
        rcf_rpc_server_restart(pco_iut);
        iut_s = -1;
        TEST_VERDICT("ioctl() call results in untimely death "
                     "of RPC server");
    }
    else
    {
        rcf_rpc_server_is_op_done(pco_iut, &op_done);
        if (!op_done)
        {
            rcf_rpc_server_restart(pco_iut);
            iut_s = -1;
            TEST_VERDICT("ioctl() call blocks");
        }
    }

    pco_iut->op = RCF_RPC_WAIT;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_ioctl(pco_iut, iut_s, req, NULL);

    if (rc != -1)
        TEST_VERDICT("ioctl() returns %d, but expected value is -1", rc);

    CHECK_RPC_ERRNO(pco_iut,
                    (req != RPC_SIOCGSTAMP && req != RPC_SIOCGSTAMPNS) ?
                        RPC_EFAULT : RPC_ENOENT,
                    "ioctl() function called on IUT "
                    "returned -1, but");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    if (rcvd_data)
        CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}

