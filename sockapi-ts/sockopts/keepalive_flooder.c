/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 * 
 * $Id$
 */

/** @page sockopts-keepalive_flooder Robustness of SO_KEEPALIVE option on connected TCP sockets
 *
 * @objective Test @c SO_KEEPALIVE socket option with connected
 *            @c SOCK_STREAM socket with many receiving and transmitting
 *            operations.
 *
 * @type stress
 *
 * @requirement REQ-4, REQ-6
 *
 * @param pco_iut       PCO on IUT
 * @param iut_addr      Address/port to be used to connect to @p pco_iut
 * @param pco_tst       Auxiliary PCO
 * @param tst_addr      Address/port to be used to connect to @p pco_tst
 * @param time2run      How long run the test
 * @param func_aux      Which function should be used to create @p pco_aux
 * @param keepcnt       Value of @c TCP_KEEPCNT
 * @param keepidle      Value of @c TCP_KEEPIDLE
 * @param keepintvl     Value of @c TCP_KEEPINTVL
 *
 * @par Scenario:
 * -# Create connection between @p pco_iut and @p pco_tst using
 *    @ref lib-gen_connection algorithm with the following parameters:
 *      - @a srvr: @p pco_iut;
 *      - @a clnt: @p pco_tst;
 *      - @a sock_type: @c SOCK_STREAM;
 *      - @a proto: @c 0;
 *      - @a srvr_addr: @p iut_addr;
 *      - @a clnt_addr: @p tst_addr;
 *      - @a srvr_s: stored in @p iut_s;
 *      - @a clnt_s: stored in @p tst_s;
 * -# Use @p func_aux to create @p pco_aux;
 * -# Set @c TCP_KEEPCNT, @c TCP_KEEPIDLE and @c TCP_KEEPINTVL to
 *    @p keepcnt, @p keepidle and @p keepintvl values respectively on
 *    @p iut_s and @p tst_s sockets. Switch on @c SO_KEEPALIVE socket
 *    option.
 * -# Simultaneously run @ref iomux-flooder on @p pco_iut and @p iut_aux and
 *    @ref iomux-echoer on @p pco_tst PCO with the following parameters:
 *      - @p pco_iut, { @p iut_s }, { @p iut_s }, @c 1000, @c 300,
 *        @c IC_DEFAULT;
 *      - @p pco_aux, { @p iut_s }, { @p iut_s }, @c 1200, @c 300,
 *        @c IC_DEFAULT;
 *      - @p pco_tst, { @p tst_s }, @c 300, @b select();
 * -# Destroy @b iut_aux PCO;
 * -# Close @p iut_s and @p tst_s sockets.
 * 
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/keepalive_flooder"

#include "sockapi-test.h"
#include "iomux.h"

#define SET_KEEPALIVE_PARAMS(_pco, _s) \
do {                                                      \
    int optval;                                           \
    optval = keepcnt;                                     \
    rpc_setsockopt(_pco, _s, RPC_TCP_KEEPCNT, &optval);   \
    optval = keepidle;                                    \
    rpc_setsockopt(_pco, _s, RPC_TCP_KEEPIDLE, &optval);  \
    optval = keepintvl;                                   \
    rpc_setsockopt(_pco, _s, RPC_TCP_KEEPINTVL, &optval); \
    optval = 1;                                           \
    rpc_setsockopt(_pco, _s, RPC_SO_KEEPALIVE, &optval);  \
} while (0);

int
main(int argc, char *argv[])
{
    int                     time2run;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_aux = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    const char             *func_aux;

    int                     iut_s = -1;
    int                     tst_s = -1;

    uint64_t                parent_tx = 0;
    uint64_t                parent_rx = 0;
    uint64_t                aux_tx = 0;
    uint64_t                aux_rx = 0;
    uint64_t                echo_tx = 0;
    uint64_t                echo_rx = 0;
    uint64_t                tx;
    uint64_t                rx;

    int                     keepcnt;
    int                     keepidle;
    int                     keepintvl;

    /* Preambule */
    TEST_START;
    TEST_GET_INT_PARAM(time2run);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(func_aux);
    TEST_GET_INT_PARAM(keepcnt);
    TEST_GET_INT_PARAM(keepidle);
    TEST_GET_INT_PARAM(keepintvl);

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    SET_KEEPALIVE_PARAMS(pco_iut, iut_s);
    SET_KEEPALIVE_PARAMS(pco_tst, tst_s);

    if (strcmp(func_aux, "thread") == 0)
        CHECK_RC(rcf_rpc_server_thread_create(pco_iut,
                                              "child_thread", &pco_aux));
    else
        CHECK_RC(rcf_rpc_server_fork(pco_iut, "child_proc", &pco_aux));

    pco_iut->timeout = TE_SEC2MS(2 * time2run + 60);
    pco_iut->op = RCF_RPC_CALL;
    if (rpc_iomux_flooder(pco_iut, &iut_s, 1, &iut_s, 1, 1000, time2run, 1,
                          IC_DEFAULT, &parent_tx, &parent_rx) != 0)
    {
        TEST_FAIL("Unexpected rpc_iomux_flooder() failure on pco_iut");
    }

    pco_aux->timeout = TE_SEC2MS(2 * time2run + 60);
    pco_aux->op = RCF_RPC_CALL;
    if (rpc_iomux_flooder(pco_aux, &iut_s, 1, &iut_s, 1, 1200,
                          time2run, 1, IC_DEFAULT, &aux_tx, &aux_rx) != 0)
    {
        TEST_FAIL("Unexpected rpc_iomux_flooder() failure on pco_aux");
    }

    MSLEEP(10000);
    if (rpc_iomux_echoer(pco_tst, &tst_s, 1, time2run, IC_DEFAULT,
                         &echo_tx, &echo_rx) != 0)
    {
        TEST_FAIL("Unexpected rpc_iomux_echoer() failure on pco_tst");
    }

    pco_iut->op = RCF_RPC_WAIT;
    if (rpc_iomux_flooder(pco_iut, &iut_s, 1, &iut_s, 1, 1000, time2run, 1,
                          IC_DEFAULT, &parent_tx, &parent_rx) != 0)
    {
        TEST_FAIL("Unexpected rpc_iomux_flooder() failure on pco_iut");
    }

    MSLEEP(10000);
    RPC_AWAIT_IUT_ERROR(pco_aux);
    pco_aux->op = RCF_RPC_WAIT;
    if (rpc_iomux_flooder(pco_aux, &iut_s, 1, &iut_s, 1, 1200, 
                          time2run, 1, IC_DEFAULT, &aux_tx, &aux_rx) != 0)
    {
        TEST_FAIL("Unexpected rpc_iomux_flooder() failure on pco_iut");
    }

    tx = parent_tx + aux_tx;
    rx = parent_rx + aux_rx;

    if (tx != echo_rx)
    {
        ERROR("Part of data sent from parent and child are lost "
              "on echo receiver: %u(%u + %u) vs %u, lost %d",
              tx, (unsigned int)parent_tx, (unsigned int)aux_tx,
              (unsigned int)echo_rx, (int)(tx - echo_rx));
        TEST_VERDICT("Part of data sent from parent and child are lost "
                     "on echo receiver");
    }
    if (echo_rx != echo_tx)
    {
        INFO("Part of data are lost by echoer: %u vs %u, lost %d",
             (unsigned int)echo_rx, (unsigned int)echo_tx,
             (int)(echo_rx - echo_tx));
    }
    if (rx != echo_tx)
    {
        ERROR("Part of data sent from echo transmitter to parent "
              "and child are lost: %u vs %u(%u + %u), lost %d",
              (unsigned int)echo_tx, (unsigned int)rx,
              (unsigned int)parent_rx, (unsigned int)aux_rx,
              (int)(echo_tx - rx));
        TEST_VERDICT("Part of data sent from echo transmitter to parent "
                     "and child are lost");
    }

    TEST_SUCCESS;

cleanup:
    if (pco_aux != NULL)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_aux));

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
