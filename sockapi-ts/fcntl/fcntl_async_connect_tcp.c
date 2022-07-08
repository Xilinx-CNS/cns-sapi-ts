/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * IOCTL Requests
 *
 * $Id$
 */

/** @page fcntl-fcntl_async_connect_tcp Usage of fcntl() functionality with connect() on TCP socket
 *
 * @objective Check possibilty provided by @b fcntl() for signal controlled
 *            input/output on TCP socket with @b connect() function.
 *
 * @type conformance
 *
 * @param pco_iut        PCO on IUT
 * @param pco_tst        PCO on TESTER
 * @param use_fioasync   Use @c FIOASYNC or @c SET_FL
 * @param use_siocspgrp  Use @c SIOCSPGRP or @c F_SETOWN
 * @param use_getown_ex  Use @c F_GETOWN_EX or @c F_GETOWN
 * @param connect_before Call connect before or after setting asyncronious
 *                       mode
 * @param send_data      Send or do not send the data from Tester after
 *                       @b connect()
 *
 * @par Test sequence:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#include "sockapi-test.h"

#define TE_TEST_NAME  "fcntl/fcntl_async_connect_tcp"

int
main(int argc, char *argv[])
{

    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;

    int                    iut_s = -1;
    int                    tst_s = -1;
    int                    acc_s = -1;

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
    te_bool                 connect_before = FALSE;
    te_bool                 send_data = FALSE;
    te_bool                 use_wildcard = FALSE;

    int                     req_val;

    void                   *tx_buf = NULL;
    size_t                  buf_len;

    TEST_START;

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_BOOL_PARAM(use_getown_ex);
    TEST_GET_BOOL_PARAM(use_fioasync);
    TEST_GET_BOOL_PARAM(use_siocspgrp);
    TEST_GET_BOOL_PARAM(connect_before);
    TEST_GET_BOOL_PARAM(send_data);
    TEST_GET_BOOL_PARAM(use_wildcard);

    memset(&foex, 0, sizeof(foex));
    pco_iut_pid = rpc_getpid(pco_iut);

    CHECK_NOT_NULL((tx_buf = sockts_make_buf_stream(&buf_len)));

    CHECK_RC(tapi_sigaction_simple(pco_iut, RPC_SIGIO,
                                   SIGNAL_REGISTRAR, &old_act));
    restore_signal_handler = TRUE;

    TEST_STEP("Create two @c SOCK_STREAM socktes: @p iut_s on @p pco_iut and @p tst_s "
              "on @p pco_tst");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    TEST_STEP("Bind @p iut_s socket according to @p use_wildcard parameter and "
              "@p tst_s to @p tst_s address");
    memset(&wildcard_addr, 0, sizeof(wildcard_addr));
    wildcard_addr.ss_family = iut_addr->sa_family;
    te_sockaddr_set_port(SA(&wildcard_addr),
                         te_sockaddr_get_port(iut_addr));
    rpc_bind(pco_iut, iut_s, use_wildcard ? SA(&wildcard_addr) : iut_addr);
    rpc_bind(pco_tst, tst_s, tst_addr);

    TEST_STEP("Call @b listen() on @p tst_s");
    rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);

    TEST_STEP("Call @c connect() on @p iut_s socket with @p tst_addr if "
              "@p connect_before is @c TRUE");
    if (connect_before)
        rpc_connect(pco_iut, iut_s, tst_addr);

    TEST_STEP("Set @c SIOCSPGRP or @c F_SETOWN according to @p use_siocspgrp and "
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

    TEST_STEP("Call @c connect() on @p iut_s socket with @p tst_addr if "
              "@p connect_before is @c FALSE and check that the signal is "
              "delivered to the process");
    if (!connect_before)
    {
        rpc_connect(pco_iut, iut_s, tst_addr);

        iut_sigmask = rpc_sigreceived(pco_iut);
        rc = rpc_sigismember(pco_iut, iut_sigmask, RPC_SIGIO);
        if (rc == FALSE)
            TEST_VERDICT("SIGIO signal was not received");
        if (send_data)
            rpc_sigdelset(pco_iut, iut_sigmask, RPC_SIGIO);
    }

    TEST_STEP("Send data from @p pco_tst to @p iut_s socket and check that the "
              "signal is delivered to the process");
    if (send_data)
    {
        acc_s = rpc_accept(pco_tst, tst_s, NULL, NULL);

        RPC_SEND(rc, pco_tst, acc_s, tx_buf, buf_len, 0);
        TAPI_WAIT_NETWORK;
        iut_sigmask = rpc_sigreceived(pco_iut);
        rc = rpc_sigismember(pco_iut, iut_sigmask, RPC_SIGIO);
        if (rc == FALSE)
            TEST_VERDICT("SIGIO signal was not received");
    }

    TEST_SUCCESS;

cleanup:
    if (restore_signal_handler)
        CLEANUP_RPC_SIGACTION(pco_iut, RPC_SIGIO, &old_act,
                              SIGNAL_REGISTRAR);

    rpc_signal_registrar_cleanup(pco_iut);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, acc_s);

    TEST_END;
}
