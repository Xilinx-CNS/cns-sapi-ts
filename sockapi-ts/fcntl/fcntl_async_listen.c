/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * IOCTL Requests
 *
 * $Id$
 */

/** @page fcntl-fcntl_async_listen Usage of fcntl() functionality on listening TCP socket
 *
 * @objective Check possibilty provided by @b fcntl() for signal controlled
 *            input/output on listening TCP sockets.
 *
 * @type conformance
 *
 * @param pco_iut1   PCO on IUT thread #1
 * @param pco_iut2   PCO on IUT thread #2
 * @param pco_tst    Auxiliary PCO on TST
 *
 * @par Test sequence:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#include "sockapi-test.h"

#define TE_TEST_NAME  "fcntl/fcntl_async_listen"

int
main(int argc, char *argv[])
{

    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;

    int                    iut_s = -1;
    int                    tst_s = -1;

    pid_t                  iut_owner;
    int                    old_flag = -1;

    struct sockaddr_storage wildcard_addr;
    DEFINE_RPC_STRUCT_SIGACTION(old_act);
    te_bool                 restore_signal_handler = FALSE;
    rpc_sigset_p            iut_sigmask = RPC_NULL;

    pid_t pco_iut_pid;

    te_bool                 use_getown_ex = FALSE;
    struct rpc_f_owner_ex   foex;
    te_bool                 use_fioasync = FALSE;
    te_bool                 use_siocspgrp = FALSE;

    int                     req_val;

    TEST_START;

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_BOOL_PARAM(use_getown_ex);
    TEST_GET_BOOL_PARAM(use_fioasync);
    TEST_GET_BOOL_PARAM(use_siocspgrp);

    memset(&foex, 0, sizeof(foex));
    pco_iut_pid = rpc_getpid(pco_iut);

    CHECK_RC(tapi_sigaction_simple(pco_iut, RPC_SIGIO,
                                   SIGNAL_REGISTRAR, &old_act));
    restore_signal_handler = TRUE;

    TEST_STEP("Create two @c SOCK_STREAM socktes: @p iut_s on @p pco_iut and @p tst_s "
              "on @p pco_tst");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    TEST_STEP("Bind @p iut_s socket to wildcard address and @p tst_s to @p tst_s "
              "address");
    memset(&wildcard_addr, 0, sizeof(wildcard_addr));
    wildcard_addr.ss_family = iut_addr->sa_family;
    te_sockaddr_set_port(SA(&wildcard_addr),
                         te_sockaddr_get_port(iut_addr));
    rpc_bind(pco_iut, iut_s, SA(&wildcard_addr));
    rpc_bind(pco_tst, tst_s, tst_addr);

    TEST_STEP("Call @b listen() on @p iut_s");
    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    TEST_STEP("Set @c SIOCSPGRP or @c F_SETOWN accroding to @p use_siocspgrp and "
              "@p use_getown_ex parameters to id of @p pco_iut");
    if (use_getown_ex)
    {
        rpc_fcntl(pco_iut, iut_s, RPC_F_GETOWN_EX, &foex);
        iut_owner = foex.pid;
    }
    else
        iut_owner = rpc_fcntl(pco_iut, iut_s, RPC_F_GETOWN, 0);
    if (iut_owner != 0)
        TEST_VERDICT("Unexpected non-zero initial owner");

    if (use_siocspgrp)
        rpc_ioctl(pco_iut, iut_s, RPC_SIOCSPGRP, &pco_iut_pid);
    else
    {
        if (use_getown_ex)
        {
            memset(&foex, 0, sizeof(foex));
            foex.pid = pco_iut_pid;
            rc = rpc_fcntl(pco_iut, iut_s, RPC_F_SETOWN_EX, &foex);
        }
        else
            rc = rpc_fcntl(pco_iut, iut_s, RPC_F_SETOWN, pco_iut_pid);

        if (use_getown_ex)
        {
            memset(&foex, 0, sizeof(foex));
            rpc_fcntl(pco_iut, iut_s, RPC_F_GETOWN_EX, &foex);
            iut_owner = foex.pid;
        }
        else
            iut_owner = rpc_fcntl(pco_iut, iut_s, RPC_F_GETOWN, 0);

        if (iut_owner != pco_iut_pid)
            TEST_FAIL("Owner ids are not the same");
    }

    TEST_STEP("Set asynchronous mode on @p iut_s using @c FIOASYNC or @c F_SETFL "
              "according to @p use_fioasync_first parameter");
    old_flag = rpc_fcntl(pco_iut, iut_s, RPC_F_GETFL, 0);
    RING("Current flags set on the 'iut_s' are %x", old_flag);
    if (use_fioasync)
    {
        req_val = 1;
        rpc_ioctl(pco_iut, iut_s, RPC_FIOASYNC, &req_val);
    }
    else
    {
        rc = rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, RPC_O_ASYNC);
    }

    TEST_STEP("Call @c connect() on @p tst_s socket with @p iut_addr");
    rpc_connect(pco_tst, tst_s, iut_addr);
    /* We need some timeout to be sure that ACK was received on IUT side. */
    TAPI_WAIT_NETWORK;

    TEST_STEP("Check that the signal is delivered to the process");
    iut_sigmask = rpc_sigreceived(pco_iut);
    rc = rpc_sigismember(pco_iut, iut_sigmask, RPC_SIGIO);
    if (rc == FALSE)
        TEST_VERDICT("SIGIO signal was not received");

    TEST_SUCCESS;

cleanup:
    if (restore_signal_handler)
        CLEANUP_RPC_SIGACTION(pco_iut, RPC_SIGIO, &old_act,
                              SIGNAL_REGISTRAR);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
