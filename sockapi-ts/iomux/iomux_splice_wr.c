/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * I/O Multiplexing
 *
 * $Id$
 */

/** @page iomux-iomux_splice_wr The splice() operation and iomux function on pipe read end
 *
 * @objective Test that @b iomux function correctly reports write event
 *            generated via @b splice() operation.
 *
 * @type conformance, compatibilit
 *
 * @par Scenario:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "iomux/iomux_splice_wr"

#include "sockapi-test.h"
#include "extensions.h"
#include "iomux.h"

#define DATA_LEN 4096

int
main(int argc, char *argv[])
{
    iomux_call_type         iomux;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rcf_rpc_server *pco_aux = NULL;
    int             tst_s = -1;
    int             iut_s = -1;
    void           *rx_buf = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    iomux_evt_fd            event;

    int             fds[2];
    te_bool         set_move = FALSE;
    int             flags = 0;
    te_bool         diff_stacks = FALSE;
    te_bool         iomux_nonblock;
    te_bool         splice_before_recv;
    tarpc_timeval   tv = { 0, 0 };

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(set_move);
    TEST_GET_BOOL_PARAM(diff_stacks);
    TEST_GET_BOOL_PARAM(iomux_nonblock);
    TEST_GET_BOOL_PARAM(splice_before_recv);
    TEST_GET_IOMUX_FUNC(iomux);

    if (!iomux_nonblock)
        CHECK_RC(rcf_rpc_server_thread_create(pco_iut, "iut_thread",
                                              &pco_aux));

    rx_buf = te_make_buf_by_len(DATA_LEN);
    flags = set_move ? RPC_SPLICE_F_MOVE : 0;

    TEST_STEP("Generate connection between @p pco_iut and @p pco_tst: @p iut_s "
              "and @p tst_s sockets");
    GEN_CONNECTION(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   tst_addr, iut_addr, &tst_s, &iut_s);
    TEST_STEP("Change stack according to @p diff_stacks parameter");
    if (diff_stacks)
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, "test");

    TEST_STEP("Create pipe");
    rpc_pipe(pco_iut, fds);


    TEST_STEP("Overfill pipe and connection");
    rpc_overfill_fd(pco_iut, fds[1], NULL);
    rpc_overfill_buffers(pco_iut, iut_s, NULL);

    TEST_STEP("Call @b iomux function with read event and pipe read end if @c "
              "iomux_nonblock is @c TRUE");
    event.fd = fds[1];
    event.events = EVT_WR;
    if (!iomux_nonblock)
    {
        pco_iut->op = RCF_RPC_CALL;
        rc = iomux_call(iomux, pco_iut, &event, 1, NULL);
    }

    TAPI_WAIT_NETWORK;
    if (splice_before_recv)
    {
        if(pco_aux)
            pco_aux->op = RCF_RPC_CALL;
        else
            pco_iut->op = RCF_RPC_CALL;
        TEST_STEP("Call @b splice() with @p iut_s socket and with read end of the "
                  "pipe()");
        rpc_splice(pco_aux == NULL ? pco_iut : pco_aux, fds[0], NULL, iut_s,
                   NULL, DATA_LEN, flags);
        TAPI_WAIT_NETWORK;
    }

    TEST_STEP("Receive some data from on @p tst_s socket");
    do {
        RPC_AWAIT_IUT_ERROR(pco_tst);
        rc = rpc_recv(pco_tst, tst_s, rx_buf, DATA_LEN, RPC_MSG_DONTWAIT);
        if (rc < 0)
        {
            if (RPC_ERRNO(pco_tst) != RPC_EAGAIN)
                TEST_VERDICT("Read failed with unexpected errno %r",
                             RPC_ERRNO(pco_tst));
        }
    } while (rc > 0);

    TAPI_WAIT_NETWORK;

    if (splice_before_recv)
    {
        if(pco_aux)
            pco_aux->op = RCF_RPC_WAIT;
        else
            pco_iut->op = RCF_RPC_WAIT;
    }
    rpc_splice(pco_aux == NULL ? pco_iut : pco_aux, fds[0], NULL, iut_s,
               NULL, DATA_LEN, flags);

    TEST_STEP("Call @b iomux function with read event and pipe read end if @c "
              "iomux_nonblock is @c FALSE");
    if (!iomux_nonblock)
    {
        pco_iut->op = RCF_RPC_WAIT;
        rc = iomux_call(iomux, pco_iut, &event, 1, NULL);
    }
    else
        rc = iomux_call(iomux, pco_iut, &event, 1, &tv);

    TEST_STEP("Check that @b iomux function reports event");
    if (rc != 1)
            TEST_FAIL("iomux function returned %d instead 1", rc);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, fds[0]);
    CLEANUP_RPC_CLOSE(pco_iut, fds[1]);
    free(rx_buf);
    if (pco_aux)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_aux));

    TEST_END;
}
