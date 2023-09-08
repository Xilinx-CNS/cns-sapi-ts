/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * I/O Multiplexing
 *
 * $Id$
 */

/** @page iomux-iomux_splice_rd The splice() operation and iomux function on pipe read end
 *
 * @objective Test that @b iomux function correctly reports event generated
 *            via @b splice() operation.
 *
 * @type conformance, compatibilit
 *
 * @par Scenario:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "iomux/iomux_splice_rd"

#include "sockapi-test.h"
#include "extensions.h"
#include "iomux.h"

#define CHECK_DATA(_buf, _buf_len, _got_buf, _got_buf_len) \
do {                                             \
    if (_got_buf_len != _buf_len)                \
        TEST_FAIL("Only part of data received"); \
    if (memcmp(_buf, _got_buf, _buf_len))        \
            TEST_FAIL("Invalid data received");  \
} while(0);

int
main(int argc, char *argv[])
{
    iomux_call_type         iomux;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rcf_rpc_server *pco_aux = NULL;
    int             tst_s = -1;
    int             iut_s = -1;
    void           *tx_buf = NULL;
    size_t          tx_buf_len;
    void           *rx_buf = NULL;
    size_t          rx_buf_len;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    iomux_evt_fd            event;

    te_bool         splice_before_data = FALSE;
    int             fds[2];
    te_bool         set_move = FALSE;
    te_bool         set_nonblock = FALSE;
    int             flags = 0;
    te_bool         diff_stacks = FALSE;
    te_bool         iomux_nonblock;
    tarpc_timeval   tv = { 0, 0 };

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(splice_before_data);
    TEST_GET_BOOL_PARAM(set_move);
    TEST_GET_BOOL_PARAM(set_nonblock);
    TEST_GET_BOOL_PARAM(diff_stacks);
    TEST_GET_BOOL_PARAM(iomux_nonblock);
    TEST_GET_IOMUX_FUNC(iomux);

    if (!iomux_nonblock)
        CHECK_RC(rcf_rpc_server_thread_create(pco_iut, "iut_thread",
                                              &pco_aux));

    tx_buf = sockts_make_buf_stream(&tx_buf_len);
    rx_buf = te_make_buf_min(tx_buf_len, &rx_buf_len);
    flags = set_move ? RPC_SPLICE_F_MOVE : 0;
    if (set_nonblock)
        flags |= RPC_SPLICE_F_NONBLOCK;

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

    TEST_STEP("Call @b splice() with @p iut_s socket and with write end of the "
              "pipe() if @p splice_before_data is @c TRUE");
    if (splice_before_data)
    {
        if(pco_aux)
        {
            pco_aux->op = RCF_RPC_CALL;
            rpc_splice(pco_aux, iut_s, NULL,
                       fds[1], NULL, tx_buf_len, flags);
        }
        else
        {
            pco_iut->op = RCF_RPC_CALL;
            rpc_splice(pco_iut, iut_s, NULL,
                       fds[1], NULL, tx_buf_len, flags);
        }
        TAPI_WAIT_NETWORK;
    }

    TEST_STEP("Call @b iomux function with read event and pipe read end if @c "
              "iomux_nonblock is @c TRUE");
    event.fd = fds[0];
    event.events = EVT_RD;
    if (!iomux_nonblock)
    {
        pco_iut->op = RCF_RPC_CALL;
        rc = iomux_call(iomux, pco_iut, &event, 1, NULL);
    }

    TEST_STEP("Send some data from @p pco_tst to @p pco_iut");
    RPC_SEND(rc, pco_tst, tst_s, tx_buf, tx_buf_len, 0);

    TAPI_WAIT_NETWORK;

    TEST_STEP("Call @b splice() with @p iut_s socket and with write end of the "
              "pipe() if @p splice_before_data is @c FALSE");
    if (splice_before_data)
    {
        if(pco_aux)
            pco_aux->op = RCF_RPC_WAIT;
        else
            pco_iut->op = RCF_RPC_WAIT;
    }
    rpc_splice(pco_aux == NULL ? pco_iut : pco_aux, iut_s, NULL, fds[1],
               NULL, tx_buf_len, flags);

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

    TEST_STEP("Read all data from the last pipe and check that it is correct");
    rc = rpc_read(pco_iut, fds[0], rx_buf, rx_buf_len);
    CHECK_DATA(tx_buf, rc, rx_buf, (int)tx_buf_len);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, fds[0]);
    CLEANUP_RPC_CLOSE(pco_iut, fds[1]);
    free(tx_buf);
    free(rx_buf);
    if (pco_aux)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_aux));

    sockts_kill_zombie_stacks_if_many(pco_iut);

    TEST_END;
}
