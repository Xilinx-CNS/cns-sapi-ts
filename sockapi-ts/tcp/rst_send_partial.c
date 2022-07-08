/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP
 */

/**
 * @page tcp-rst_send_partial send() behaviour after receiving RST packet
 *
 * @objective Check that after receiving RST packet blocked send() finishes
 *            correctly
 *
 * @param env      Testing environment:
 *      - @ref arg_types_env_peer2peer
 *      - @ref arg_types_env_peer2peer_ipv6
 * @param partial  should @b send() be partial?
 *
 * @par Scenario:
 *
 * @author Vasilij Ivanov <Vasilij.Ivanov@oktetlabs.ru>
 */

#define TE_TEST_NAME "tcp/rst_send_partial"

#include "sockapi-test.h"
#include "te_dbuf.h"
#include "tapi_sockets.h"

#define NEW_BUF_SIZE 1000

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    int                     iut_s = -1;
    int                     tst_s = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    uint8_t                 *send_buf = NULL;
    uint8_t                 *recv_buf = NULL;

    uint64_t                iut_sent_len;
    int                     send_size = 100 * NEW_BUF_SIZE;

    tarpc_linger opt_val;

    te_bool                 partial;
    te_bool                 done;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(partial);

    TEST_STEP("Establish a TCP connection actively from IUT");
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr,
                      SOCKTS_SOCK_TCP_ACTIVE,
                      &iut_s, &tst_s, NULL);

    TEST_STEP("Set @c SO_LINGER with zero value on Tester socket, so that "
              "it would send RST packet after @b close()");

    opt_val.l_onoff = 1;
    opt_val.l_linger = 0;

    rpc_setsockopt(pco_tst, tst_s, RPC_SO_LINGER, &opt_val);

    TEST_STEP("Reduce SNDBUF on IUT socket and RCVBUF on TST socket");
    rpc_setsockopt_int(pco_iut, iut_s, RPC_SO_SNDBUF, NEW_BUF_SIZE);
    rpc_setsockopt_int(pco_tst, tst_s, RPC_SO_RCVBUF, NEW_BUF_SIZE);

    TEST_STEP("Overfill IUT send buffer");
    rpc_overfill_buffers(pco_iut, iut_s, &iut_sent_len);

    TEST_STEP("Try to send more data from IUT, "
              "ensure that the send() call hangs");
    send_buf = te_make_buf_by_len(send_size);
    pco_iut->op = RCF_RPC_CALL;
    rc = rpc_send(pco_iut, iut_s, send_buf, send_size, 0);
    TAPI_WAIT_NETWORK;

    CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));
    if (done)
    {
        TEST_VERDICT("@b send() is not hanging");
    }

    if (partial)
    {
        TEST_STEP("If @p partial is @c TRUE:");
        TEST_SUBSTEP("Receive part of data on the TST socket");
        recv_buf = te_make_buf_by_len(iut_sent_len);
        rpc_recv(pco_tst, tst_s, recv_buf, iut_sent_len, 0);

        TEST_SUBSTEP("Wait enough time to let TST send ACK packets "
                     "on received data");
        SLEEP(5);
    }

    TEST_STEP("Call @b close() on TST socket to send RST packet");
    RPC_CLOSE(pco_tst, tst_s);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Wait for hanging @b send() termination on IUT. "
              "Check that if @p partial is @c TRUE, @b send() succeeds "
              "but reports less data sent than requested. "
              "And if @p partial is @c FALSE, "
              "check that @b send() fails with @c ECONNRESET.");
    RPC_AWAIT_ERROR(pco_iut);
    pco_iut->op = RCF_RPC_WAIT;
    rc = rpc_send(pco_iut, iut_s, send_buf, send_size, 0);

    if (rc < 0)
    {
        if (partial)
        {
            TEST_VERDICT("send() unexpectedly failed with errno %r", RPC_ERRNO(pco_iut));
        }
        else if (RPC_ERRNO(pco_iut) != RPC_ECONNRESET)
        {
            TEST_VERDICT("send() failed with unexpected errno %r", RPC_ERRNO(pco_iut));
        }
    }
    else
    {
        if (partial)
        {
            if (rc >= send_size)
                TEST_VERDICT("send() sent all the data");
        }
        else
        {
            TEST_VERDICT("send() unexpectedly succeeded");
        }
    }

    TEST_SUCCESS;

cleanup:
    free(send_buf);
    free(recv_buf);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
