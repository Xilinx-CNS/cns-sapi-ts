/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page ext_stackname-move_epoll_fd Call @b onload_move_fd() on an epoll fd
 *
 * @objective Check that if we call @b onload_move_fd() on an
 *            @b epoll_create() fd, it fails not influencing this fd.
 *
 * @type use case
 *
 * @param pco_iut              PCO on IUT
 * @param system_fd            Whether we should to call
 *                             @b onload_move_fd() on an Onload
 *                             epoll fd or system one
 * @param iomux                @b epoll() or @b epoll_pwait()
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/move_epoll_fd"

#include "sockapi-test.h"

#include "onload.h"
#include "extensions.h"

#include "move_fd_helpers.h"
#include "iomux.h"

#define STACK_NAME "foo"
#define DATA_SIZE 256

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;
    int                     iut_s = -1;
    int                     tst_s = -1;
    int                     epoll_fd = -1;
    struct rpc_epoll_event  events[1];
    te_bool                 system_fd = FALSE;
    iomux_call_type         iomux;
    char                    buf[DATA_SIZE];

    te_bool                 test_failed = FALSE;
    char                   *init_stack_name;
    te_bool                 restore_stack_name = FALSE;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(system_fd);
    TEST_GET_IOMUX_FUNC(iomux);

    init_stack_name = tapi_onload_get_cur_stackname(pco_iut);

    TEST_STEP("Create a pair of connected sockets of type @c SOCK_STREAM -  "
              "@p iut_s on @p pco_iut and @p tst_s on @p pco_tst.");
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM,
                   RPC_PROTO_DEF, iut_addr, tst_addr, &iut_s,
                   &tst_s);

    TEST_STEP("Create @p epoll_fd, add @p iut_s to epoll set to wait for "
              "available data on it.");
    if (system_fd)
        pco_iut->use_libc_once = TRUE;
    epoll_fd = rpc_epoll_create(pco_iut, 1);

    rpc_epoll_ctl_simple(pco_iut, epoll_fd, RPC_EPOLL_CTL_ADD,
                         iut_s, RPC_EPOLLIN);

    TEST_STEP("Try to move a epoll fd to a new stack; check that it fails.");
    tapi_rpc_onload_set_stackname_create(pco_iut, ONLOAD_ALL_THREADS,
                                         ONLOAD_SCOPE_PROCESS, STACK_NAME,
                                         FALSE, NULL);
    restore_stack_name = TRUE;

    if (!tapi_rpc_onload_move_fd_check(
                                 pco_iut, epoll_fd,
                                 TAPI_MOVE_FD_FAILURE_EXPECTED, STACK_NAME,
                                 "Calling onload_move_fd() on an epoll fd"))
        test_failed = TRUE;

    TEST_STEP("Send some data to @p iut_s and check that @b epoll_wait() (or "
              "@b epoll_pwait() returns correct result.");
    rpc_send(pco_tst, tst_s, buf, DATA_SIZE, 0);
    rc = iomux_epoll_call(iomux, pco_iut, epoll_fd, events, 1, -1);
    if (rc != 1 || events[0].events != RPC_EPOLLIN ||
        events[0].data.fd != iut_s)
        TEST_VERDICT("Waiting on epoll fd after calling @b onload_move_fd() "
                     "produced unexpected result");

    if (test_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    if (restore_stack_name)
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, init_stack_name);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, epoll_fd);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
