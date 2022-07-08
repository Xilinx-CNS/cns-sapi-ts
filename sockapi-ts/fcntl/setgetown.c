/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * IOCTL Requests
 *
 * $Id: setgetown.c 29545 2006-06-26 10:14:58Z yuran $
 */

/** @page fcntl-setgetown Check socket owner's PID
 *
 * @objective Check that socket owner's PID can be correctly
 *            set using @b fcntl() function and that it is
 *            reset to 0 after socket was recreated.
 * 
 * @param pco_iut PCO on IUT
 *
 * @par Test sequence
 *
 * -# Create @p iut_s socket of @c SOCK_STREAM type on @p pco_iut;
 * -# Get owner of the @p iut_s on @p pco_iut by means of @b fcntl()
 *    with command @c F_GETOWN;
 * -# Check that @b fcntl() returns 0;
 * -# Set owner of the @p iut_s on @p pco_iut by means of @b fcntl()
 *    with process id of @p pco_iut;
 * -# Get owner of the @p iut_s on @p pco_iut by means of @b fcntl()
 *    with command @c F_GETOWN;
 * -# Check that @b fcntl() returns the process id of @p pco_iut;
 * -# Close @p iut_s socket and create it again
 * -# Get owner of the @p iut_s on @p pco_iut by means of @b fcntl()
 *    with command @c F_GETOWN;
 * -# Check that @b fcntl() returns 0;
 *
 * @author Konstantin Petrov <Konstantin.Petrov@oktetlabs.ru>
 */

#include "sockapi-test.h"
#include "onload.h"

#define TE_TEST_NAME  "fcntl/setgetown"

int
main(int argc, char *argv[])
{

    rcf_rpc_server        *pco_iut = NULL;

    int                    iut_s = -1;

    pid_t                  iut_owner;
    pid_t                  pco_iut_pid;

    const char *object;

    te_bool                use_getown_ex = FALSE;
    struct rpc_f_owner_ex  foex;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(object);
    TEST_GET_BOOL_PARAM(use_getown_ex);

    memset(&foex, 0, sizeof(foex));
    pco_iut_pid = rpc_getpid(pco_iut);

    iut_s = tapi_onload_object_create(pco_iut, object);

    if (use_getown_ex)
    {
        rpc_fcntl(pco_iut, iut_s, RPC_F_GETOWN_EX, &foex);
        iut_owner = foex.pid;
    }
    else
        iut_owner = rpc_fcntl(pco_iut, iut_s, RPC_F_GETOWN, 0);
    if (iut_owner != 0)
        TEST_VERDICT("Newly created socket unexpectedly "
                  "has unknown owner's PID - %d", iut_owner);

    if (use_getown_ex)
    {
        foex.pid = pco_iut_pid;
        rc = rpc_fcntl(pco_iut, iut_s, RPC_F_SETOWN_EX, &foex);
    }
    else
        rc = rpc_fcntl(pco_iut, iut_s, RPC_F_SETOWN, pco_iut_pid);

    if (use_getown_ex)
    {
        rpc_fcntl(pco_iut, iut_s, RPC_F_GETOWN_EX, &foex);
        iut_owner = foex.pid;
    }
    else
        iut_owner = rpc_fcntl(pco_iut, iut_s, RPC_F_GETOWN, 0);

    if (iut_owner != pco_iut_pid)
        TEST_VERDICT("Owner's PID is not set properly");

    rpc_close(pco_iut, iut_s);

    iut_s = tapi_onload_object_create(pco_iut, object);

    if (use_getown_ex)
    {
        rpc_fcntl(pco_iut, iut_s, RPC_F_GETOWN_EX, &foex);
        iut_owner = foex.pid;
    }
    else
        iut_owner = rpc_fcntl(pco_iut, iut_s, RPC_F_GETOWN, 0);

    if (iut_owner == pco_iut_pid)
        TEST_VERDICT("Recreated socket unespectedly "
                     "remembered owner's PID");
    else if (iut_owner != 0)
        TEST_VERDICT("Recreated socket unespectedly has "
                     "unknown owner's PID");

    TEST_SUCCESS;

cleanup:
    
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
