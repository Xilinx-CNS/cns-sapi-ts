/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/**
 * Socket API Test Suite
 * IOCTL Requests
 *
 * $Id$
 */

/** @page ioctls-fionread_listening Behaviour of FIONREAD request on listening socket
 * 
 * @objective Check that @c FIONREAD @b ioctl() call cannot be applied
 *            to listening socket.
 *
 * @type conformance
 * 
 * @param pco_iut        PCO on IUT
 * @param iut_addr       IUT address
 * @param req            @b ioctl() request used in the test
 *                       (@c "FIONREAD" or @c "SIOCINQ")
 *
 * @note @c SIOCINQ request is an alias for @c FIONREAD
 * 
 * @par Test sequence:
 *
 * -# Open @c SOCK_STREAM socket @p iut_s on @p pco_iut.
 * -# Bind it to the @p iut_addr address.
 * -# Check that the socket buffer is empty using @p req @b ioctl() request.
 * -# Call @b listen() on @p iut_s.
 * -# Make @p req @b ioctl() call on @p iut_s.
 *    It should return -1 and set errno to @c EINVAL.
 * 
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/fionread_listening"

#include "sockapi-test.h"

int
main(int argc, char *argv[]) 
{
    rcf_rpc_server            *pco_iut = NULL;
    const struct sockaddr     *iut_addr = NULL;
    int                        iut_s = -1;
    int                        bytes_queued;
    rpc_ioctl_code             req;
    int                        ret;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_IOCTL_REQ(req);

    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                       RPC_IPPROTO_TCP, TRUE, FALSE,
                                       iut_addr);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    ret = rpc_ioctl(pco_iut, iut_s, req, &bytes_queued,
                    sizeof(bytes_queued));
    if (ret != 0)
    {
        TEST_VERDICT("ioctl(%s) unexpectedly failed with errno %s",
                     ioctl_rpc2str(req),
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    if (bytes_queued != 0)
    {
        TEST_FAIL("Initially %d bytes in the buffer", bytes_queued);
    }

    rpc_listen(pco_iut, iut_s, 1);
    RPC_AWAIT_IUT_ERROR(pco_iut);

    rc = rpc_ioctl(pco_iut, iut_s, req, &bytes_queued,
                   sizeof(bytes_queued));

    if (rc == 0)
        TEST_VERDICT("Unexpected ioctl() success on listening socket. "
                     "%d bytes to read.", bytes_queued);
        
    CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL,
                    "ioctl() failed as expected");
    
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    TEST_END;
}

