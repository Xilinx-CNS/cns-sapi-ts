/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests 
 * 
 * $Id$
 */

/** @page ioctls-siocgstamp_null SIOCGSTAMP IOCTL request in case of NULL argument
 *
 * @objective Check the behavior of @c SIOCGSTAMP @p ioctl() requests with 
 *            @c NULL argument.
 * 
 * @type conformance
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst           PCO on TST
 * 
 * @param is_null           If @c TRUE, the first IOCTL request is calling with
 *                          @c NULL argument and the second - with non-NULL, 
 *                          otherwise - inside out
 *
 * @par Test sequence:
 * -# Create network connection of sockets of the @c SOCK_DGRAM type 
 *    by means of @c GEN_CONNECTION, obtain sockets @p iut_s on @b pco_iut and
 *    @p tst_s on @b pco_tst;
 * -# Send datagram via @p tst_s.
 * -# Receive it on @p iut_s.
 * -# If @p is_null is @c TRUE - call @b ioctl() with @c SIOCGSTAMP request on 
 *    @p iut_s twice: first time with @c NULL argument and second time - with 
 *    non-NULL.
 * -# Check, that first call returned @c -1 and the error code is @c EFAULT,
 *    while the second returned @c 0. 
 * -# If @p is_null is @c FALSE - call @b ioctl() with @c SIOCGSTAMP request on 
 *    @p iut_s twice: first time with non-NULL argument and second time - with 
 *    @c NULL.
 * -# Check, that first call returned @c 0, while the second returned @c -1 and 
 *    the error code is @c EFAULT.
 * -# Close @p iut_s and @p tst_s sokets.   
 *
 * @author Georgij Volfson <Georgij.Volfson@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/siocgstamp_null"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    int                     iut_s = -1;
    int                     tst_s = -1;


    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    void                   *tx_buf;
    void                   *rx_buf;

    size_t                  tx_buf_len;
    size_t                  rx_buf_len;

    tarpc_timeval           req_val;

    te_bool                 is_null;

    rpc_ioctl_code          req;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(is_null);
    TEST_GET_IOCTL_REQ(req);

    GEN_CONNECTION_WILD(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_PROTO_DEF,
                        iut_addr, tst_addr, &iut_s, &tst_s, TRUE);

    CHECK_NOT_NULL(tx_buf = sockts_make_buf_dgram(&tx_buf_len));
    rx_buf = te_make_buf_min(tx_buf_len, &rx_buf_len);

    rpc_send(pco_tst, tst_s, tx_buf, tx_buf_len, 0);
    rpc_recv(pco_iut, iut_s, rx_buf, rx_buf_len, 0);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_ioctl(pco_iut, iut_s, req,
                   is_null ? NULL : &req_val);
    if (is_null)
    {
        if (rc != -1)
            TEST_FAIL("ioctl returns %d, but expected value is -1", rc);

        CHECK_RPC_ERRNO(pco_iut, RPC_EFAULT, "ioctl(%s) called "
                        "on IUT returned -1, but", ioctl_rpc2str(req));


        rpc_ioctl(pco_iut, iut_s, req, &req_val);
    }
    else
    {
        if (rc != 0)
            TEST_VERDICT("ioctl(%s) unexpectedly failed with "
                         "errno %s", ioctl_rpc2str(req),
                         errno_rpc2str(RPC_ERRNO(pco_iut)));

        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_ioctl(pco_iut, iut_s, req, NULL);
        if (rc != -1)
            TEST_FAIL("ioctl returns %d, but expected value is -1", rc);

        CHECK_RPC_ERRNO(pco_iut, RPC_EFAULT, "ioctl() function called on IUT "
                        "returned -1, but");
    }
    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}

