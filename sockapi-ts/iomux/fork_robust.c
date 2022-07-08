/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * I/O Multiplexing
 * 
 * $Id$
 */

/** @page iomux-fork_robust Robustness against fork() call
 *
 * @objective Test robustness of the I/O multiplexing usage when
 *            a socket is owned by two processes after @b fork().
 *
 * @type stress
 *
 * @requirement REQ-4, REQ-6
 *
 * @param sock_type     Type of the socket (@c SOCK_DGRAM, @c SOCK_STREAM, etc)
 * @param pco_iut       PCO on IUT
 * @param iut_addr      Address/port to be used to connect to @p pco_iut
 * @param pco_tst       Auxiliary PCO
 * @param tst_addr      Address/port to be used to connect to @p pco_tst
 * @param iomux1        I/O multiplexing function to be tested in parent
 * @param iomux2        I/O multiplexing function to be tested in child
 * @param time2run      How long run the test
 *
 * @par Scenario:
 * -# Create connection between @p pco_iut and @p pco_tst using
 *    @ref lib-gen_connection algorithm with the following parameters:
 *      - @a srvr: @p pco_iut;
 *      - @a clnt: @p pco_tst;
 *      - @a sock_type: @p sock_type;
 *      - @a proto: @c 0;
 *      - @a srvr_addr: @p iut_addr;
 *      - @a clnt_addr: @p tst_addr;
 *      - @a srvr_s: stored in @p iut_s;
 *      - @a clnt_s: stored in @p tst_s;
 * -# @b fork() @p pco_iut PCO (Child is referred as @b iut_child below);
 * -# Simultaneously run @ref iomux-flooder on @p pco_iut and @p iut_child and
 *    @ref iomux-echoer on @p pco_tst PCO with the following parameters:
 *      - @p pco_iut, { @p iut_s }, { @p iut_s }, @c 1000, @c 300, @p iomux1;
 *      - @p iut_child, { @p iut_s }, { @p iut_s }, @c 1200, @c 300,
 *        @p iomux2;
 *      - @p pco_tst, { @p tst_s }, @c 300, @b select();
 * -# Destroy @b iut_child PCO;
 * -# Close @p iut_s and @p tst_s sockets.
 *
 * @note Numeric results of the test are not clear, since it depends
 *       on scheduling and similar factors.
 * 
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "iomux/fork_robust"

#include "sockapi-test.h"
#include "iomux.h"


int
main(int argc, char *argv[])
{
    
    rpc_socket_type         sock_type;
    iomux_call_type         iomux1;
    iomux_call_type         iomux2;

    int                     time2run;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *iut_child = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    
    rpc_socket_domain       domain;
    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    const char             *method;

    int                     iut_s = -1;
    int                     tst_s = -1;
    int                     child_s = -1;

    uint64_t                parent_tx = 0;
    uint64_t                parent_rx = 0;
    uint64_t                child_tx = 0;
    uint64_t                child_rx = 0;
    uint64_t                echo_tx = 0;
    uint64_t                echo_rx = 0;
    uint64_t                tx;
    uint64_t                rx;


    /* Preambule */
    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_IOMUX_FUNC(iomux1);
    TEST_GET_IOMUX_FUNC(iomux2);
    TEST_GET_INT_PARAM(time2run);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    domain = rpc_socket_domain_by_addr(iut_addr);
    TEST_GET_STRING_PARAM(method);

    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    rpc_create_child_process_socket(method, pco_iut, iut_s, domain,
                                    sock_type, &iut_child, &child_s);

    pco_iut->timeout = TE_SEC2MS(2 * time2run + 60);
    pco_iut->op = RCF_RPC_CALL;
    if (rpc_iomux_flooder(pco_iut, &iut_s, 1, &iut_s, 1, 1000, time2run, 1,
                          iomux1, &parent_tx, &parent_rx) != 0)
    {
        TEST_FAIL("Unexpected rpc_iomux_flooder() failure on pco_iut");
    }

    iut_child->timeout = TE_SEC2MS(2 * time2run + 60);
    iut_child->op = RCF_RPC_CALL;
    if (rpc_iomux_flooder(iut_child, &child_s, 1, &child_s, 1, 1200, 
                          time2run, 1, iomux2, &child_tx, &child_rx) != 0)
    {
        TEST_FAIL("Unexpected rpc_iomux_flooder() failure on iut_child");
    }
    
    MSLEEP(10000);
    if (rpc_iomux_echoer(pco_tst, &tst_s, 1, time2run, IC_DEFAULT,
                         &echo_tx, &echo_rx) != 0)
    {
        TEST_FAIL("Unexpected rpc_iomux_echoer() failure on pco_tst");
    }
    
    pco_iut->op = RCF_RPC_WAIT;
    if (rpc_iomux_flooder(pco_iut, &iut_s, 1, &iut_s, 1, 1000, time2run, 1,
                          iomux1, &parent_tx, &parent_rx) != 0)
    {
        TEST_FAIL("Unexpected rpc_iomux_flooder() failure on pco_iut");
    }

    MSLEEP(10000);
    RPC_AWAIT_IUT_ERROR(iut_child);
    iut_child->op = RCF_RPC_WAIT;
    if (rpc_iomux_flooder(iut_child, &child_s, 1, &child_s, 1, 1200, 
                          time2run, 1, iomux2, &child_tx, &child_rx) != 0)
    {
        TEST_FAIL("Unexpected rpc_iomux_flooder() failure on iut_child");
    }

    tx = parent_tx + child_tx;
    rx = parent_rx + child_rx;
    
    if (sock_type == RPC_SOCK_STREAM)
    {
        if (tx != echo_rx)
        {
            TEST_FAIL("Part of data sent from parent and child are lost "
                      "on echo receiver: %u(%u + %u) vs %u, lost %d",
                      tx, (unsigned int)parent_tx, (unsigned int)child_tx,
                      (unsigned int)echo_rx, (int)(tx - echo_rx));
        }
        if (echo_rx != echo_tx)
        {
            INFO("Part of data are lost by echoer: %u vs %u, lost %d",
                 (unsigned int)echo_rx, (unsigned int)echo_tx,
                 (int)(echo_rx - echo_tx));
        }
        if (rx != echo_tx)
        {
            TEST_FAIL("Part of data sent from echo transmitter to parent "
                      "and child are lost: %u vs %u(%u + %u), lost %d",
                      (unsigned int)echo_tx, (unsigned int)rx,
                      (unsigned int)parent_rx, (unsigned int)child_rx,
                      (int)(echo_tx - rx));
        }
    }
    else
    {
        if (tx != echo_rx)
        {
            INFO("Part of data sent from parent and child are lost "
                 "on echo receiver: %u(%u + %u) vs %u, lost %d",
                 (unsigned int)tx, (unsigned int)parent_tx,
                 (unsigned int)child_tx, (unsigned int)echo_rx,
                 (int)(tx - echo_rx));
        }
        if (echo_rx != echo_tx)
        {
            INFO("Part of data are lost by echoer: %u vs %u, lost %d",
                 (unsigned int)echo_rx, (unsigned int)echo_tx,
                 (int)(echo_rx - echo_tx));
        }
        if (rx != echo_tx)
        {
            INFO("Part of data sent from echo transmitter to parent "
                 "and child are lost: %u vs %u(%u + %u), lost %d",
                 (unsigned int)echo_tx, (unsigned int)rx,
                 (unsigned int)parent_rx, (unsigned int)child_rx,
                 (int)(echo_tx - rx));
        }
    }

    TEST_SUCCESS;

cleanup:
    if ((iut_child != NULL) &&
        (rcf_rpc_server_destroy(iut_child) != 0))
    {
        ERROR("rcf_rpc_server_destroy() failed");
    }

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
