/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page ext_stackname-iomux_move_fd Call @b onload_move_fd() on a socket while I/O multiplexing function is called on it
 *
 * @objective Check that calling @b onload_move_fd() does not influence
 *            I/O multiplexing function called on the socket.
 *
 * @type use case
 *
 * @param pco_iut              PCO on IUT
 * @param pco_tst              PCO on TESTER
 * @param iut_addr             Network address on IUT
 * @param tst_addr             Network address on TESTER
 * @param iomux                I/O multiplexing function to be used
 * @param existing_stack       Whether Onload stack should already exist
 *                             or not when we try to move a socket fd to it
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/iomux_move_fd"

#include "sockapi-test.h"

#include "onload.h"
#include "extensions.h"

#include "move_fd_helpers.h"
#include "iomux.h"

#define STACK_NAME "foo"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_iut_child = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;
    te_bool                 existing_stack = FALSE;
    iomux_call_type         iomux = IC_UNKNOWN;
    iomux_evt_fd            events;

    int                     iut_s = -1;
    int                     iut_s_listening = -1;
    int                     iut_s_aux = -1;
    int                     tst_s = -1;

    te_bool                 op_done = FALSE;
    te_bool                 test_failed = FALSE;
    te_bool                 bool_rc = FALSE;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_BOOL_PARAM(existing_stack);

    TEST_STEP("Establish TCP connection; @p iut_s socket is returned "
              "by @b accept().");
    bool_rc = 
        gen_tcp_conn_with_sock(pco_iut, iut_addr,
                               pco_tst, tst_addr,
                               TRUE, TRUE, FALSE, TRUE,
                               &iut_s_listening, &iut_s,
                               &tst_s, NULL);
    if (!bool_rc)
        TEST_STOP;

    CHECK_RC(rcf_rpc_server_thread_create(pco_iut,
                                          "pco_iut_child",
                                          &pco_iut_child));

    events.fd = iut_s;
    events.events = EVT_RD | EVT_EXC;
    pco_iut_child->op = RCF_RPC_CALL;
    iomux_call(iomux, pco_iut_child, &events, 1, NULL);

    TEST_STEP("Move TCP socket to a new stack.");

    tapi_rpc_onload_set_stackname_create(pco_iut, ONLOAD_ALL_THREADS,
                                         ONLOAD_SCOPE_PROCESS, STACK_NAME,
                                         existing_stack, &iut_s_aux);
    bool_rc = tapi_rpc_onload_move_fd_check(
                            pco_iut, iut_s,
                            TAPI_MOVE_FD_SUCCESS_EXPECTED, STACK_NAME,
                            NULL);
    test_failed = test_failed || !bool_rc;

    /* Check that @b onload_move_fd() does not influence @p iomux function
     * called on the socket previously. */
    rcf_rpc_server_is_op_done(pco_iut_child, &op_done);
    if (op_done)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut_child);
        pco_iut_child->op = RCF_RPC_WAIT;
        rc = iomux_call(iomux, pco_iut_child, &events, 1, NULL);
        if (rc < 0)
        {
            ERROR_VERDICT("iomux() call failed with errno %s immediately "
                          "after calling onload_move_fd()",
                          errno_rpc2str(RPC_ERRNO(pco_iut_child)));
            test_failed = TRUE;
        }
        else if (rc == 0)
        {
            ERROR_VERDICT("iomux() call unexpectedly terminated after "
                          "calling onload_move_fd(); no events were "
                          "returned");
            test_failed = TRUE;
       
        }
        else
        {
            ERROR_VERDICT("iomux() call unexpectedly terminated after "
                          "calling onload_move_fd(); rc = %d, returned events "
                          "are %s",
                          rc, iomux_event_rpc2str(events.revents));
            test_failed = TRUE;
        }
    }

    TEST_STEP("Check that socket is still usable.");
    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);

    TEST_STEP("Check that finally @p iomux call terminated when data arrived "
              "on the socket.");
    if (!op_done)
    {
        rcf_rpc_server_is_op_done(pco_iut_child, &op_done);
        if (op_done)
        {
            RPC_AWAIT_IUT_ERROR(pco_iut_child);
            pco_iut_child->op = RCF_RPC_WAIT;
            rc = iomux_call(iomux, pco_iut_child, &events, 1, NULL);
            if (rc < 0)
            {
                ERROR_VERDICT("iomux() call failed with errno %s instead "
                              "of receiving expected events",
                              errno_rpc2str(RPC_ERRNO(pco_iut_child)));
                test_failed = TRUE;
            }
            else if (rc == 0)
            {
                ERROR_VERDICT("iomux() call terminated receiving no events "
                              "instead of expected ones",
                              errno_rpc2str(RPC_ERRNO(pco_iut_child)));
                test_failed = TRUE;
            }
            else if (events.revents != EVT_RD)
            {
                ERROR_VERDICT("iomux() call returned unexpected events %s",
                              iomux_event_rpc2str(events.revents));
                test_failed = TRUE;
            }
            if (rc > 1)
            {
                ERROR_VERDICT("iomux() call returned strange value %d",
                              rc);
                test_failed = TRUE;
            }
        }
        else
        {
            ERROR_VERDICT("iomux() call did not terminate");
            test_failed = TRUE;
        }
    }

    if (test_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_listening);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_aux);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_child));

    TEST_END;
}
