/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-two_accept_blocked accept() blocked in different child processes on the same server socket
 *
 * @objective Check a possibility to retrieve new connections by means of
 *            @b accept() blocked in different child processes on the
 *            same server socket.
 *
 * @type Conformance, compatibility
 *
 * @param env   Private test environments similar to
 *              @ref arg_types_env_peer2peer and
 *              @ref arg_types_env_peer2peer_ipv6
 *              but with two Tester processes.
 * @param do_fork   fork() new process on IUT if @c TRUE, else create thread.
 * @param method    Determines what exactly to do creating new process:
 *                  - unspecified: used for @p do_fork = @c FALSE;
 *                  - inherit: used for @p do_fork = @c TRUE, means just
 *                             calling @b fork().
 *
 * @par Scenario:
 *
 * -# Create @p tst1_s socket of @c SOCK_STREAM type on @p pco_tst1;
 * -# @b bind() @p tst1_s to @p tst1_addr;
 *  \n @htmlonly &nbsp; @endhtmlonly
 * -# Create @p tst2_s socket of @c SOCK_STREAM type on @p pco_tst2;
 * -# @b bind() @p tst2_s to @p tst2_addr;
 *  \n @htmlonly &nbsp; @endhtmlonly
 * -# Create @p iut_s socket of @c SOCK_STREAM type on @p pco_iut;
 * -# @b bind() @p iut_s to the @p iut_addr;
 * -# @b listen() on @p iut_s;
 *  \n @htmlonly &nbsp; @endhtmlonly
 * -# Split process @p iut_aux from @p pco_iut2 with @b fork();
 * -# Call blocking @b accept() on @p iut_s on @p pco_iut;
 * -# Call blocking @b accept() on @p iut_s on @p iut_aux;
 *  \n @htmlonly &nbsp; @endhtmlonly
 * -# @b connect() @p tst1_s to @p iut_s;
 * -# Check that one of blocked @b accept() has unblocked and retrived
 *    new @p acc1_s socket descriptor;
 * -# @b connect() @p tst2_s to @p iut_s;
 * -# Check that @b accept() blocked in another child process retrives
 *    new @p acc2_s socket descriptor;
 * -# Check that @b accept() in different child processes return
 *    socket descriptors of different TCP connections;
 * -# Check that obtained state of both @p acc1_s and @p acc2_s 
 *    is @c STATE_CONNECTED;
 *  \n @htmlonly &nbsp; @endhtmlonly
 * -# @b close() all sockets.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/two_accept_blocked"

#include "sockapi-test.h"
#include "iomux.h"

#define TST_BUF_LEN         4096

int
main(int argc, char *argv[])
{

    rcf_rpc_server         *pco_tst1 = NULL;
    rcf_rpc_server         *pco_tst2 = NULL;
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *iut_aux = NULL;
    
    rpc_socket_domain       domain;
    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst1_addr;
    const struct sockaddr  *tst2_addr;
    const char             *method;

    struct sockaddr_storage acc1_addr;
    socklen_t               acc1_addrlen = sizeof(acc1_addr);
    struct sockaddr_storage acc2_addr;
    socklen_t               acc2_addrlen = sizeof(acc2_addr);

    int                     iut_s = -1;
    int                     acc1_s = -1;
    int                     acc2_s = -1;
    int                     tst1_s = -1;
    int                     tst2_s = -1;
    int                     first_accepted;
    int                     child_s = -1;

    te_bool                 iut1_done = FALSE;
    te_bool                 iut_aux_done = FALSE;
    te_bool                 do_fork = FALSE;

    uint8_t                 tx_buf[TST_BUF_LEN] = { 0, };
    uint8_t                 rx_buf[TST_BUF_LEN] = { 0, };
    int                     sent;
    int                     rcv;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    domain = rpc_socket_domain_by_addr(iut_addr);
    TEST_GET_BOOL_PARAM(do_fork);
    TEST_GET_STRING_PARAM(method);

    memset(&acc1_addr, 0, acc1_addrlen);
    memset(&acc2_addr, 0, acc2_addrlen);

    te_fill_buf(tx_buf, TST_BUF_LEN);

    tst1_s = rpc_socket(pco_tst1, rpc_socket_domain_by_addr(tst1_addr), 
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst1, tst1_s, tst1_addr);

    tst2_s = rpc_socket(pco_tst2, rpc_socket_domain_by_addr(tst2_addr), 
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst2, tst2_s, tst2_addr);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_listen(pco_iut, iut_s, 5);

    if (do_fork)
    {
        rpc_create_child_process_socket(method, pco_iut, iut_s, domain,
                                        RPC_SOCK_STREAM, &iut_aux,
                                        &child_s);
    }
    else
    {
        CHECK_RC(rcf_rpc_server_thread_create(pco_iut, "iut_thread",
                                              &iut_aux));
        child_s = iut_s;
    }
    
    pco_iut->op = RCF_RPC_CALL;
    acc1_s = rpc_accept(pco_iut, iut_s, SA(&acc1_addr), &acc1_addrlen);
    
    iut_aux->op = RCF_RPC_CALL;
    acc2_s = rpc_accept(iut_aux, child_s, SA(&acc2_addr), &acc2_addrlen);

    rpc_connect(pco_tst1, tst1_s, iut_addr);

    /* Sleep a bit to become more confident that accept is unblocked */
    TAPI_WAIT_NETWORK;
    
    /* Check that one of accept() operations is done */
    CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &iut1_done));
    CHECK_RC(rcf_rpc_server_is_op_done(iut_aux, &iut_aux_done));

    if (iut1_done && iut_aux_done)
    {
        TEST_FAIL("Both of blocked accept() has been unblocked");
    }

    if (!iut1_done && !iut_aux_done)
    {
        TEST_FAIL("No one of blocked accept() has been unblocked");
    }

    if (iut1_done)
    {
        RING("accept() called on pco_iut is unblocked");
        pco_iut->op = RCF_RPC_WAIT;
        acc1_s = rpc_accept(pco_iut, iut_s,
                            SA(&acc1_addr), &acc1_addrlen);
        first_accepted = acc1_s;
    }

    if (iut_aux_done)
    {
        RING("accept() called on iut_aux_done is unblocked");
        iut_aux->op = RCF_RPC_WAIT;
        acc2_s = rpc_accept(iut_aux, child_s,
                            SA(&acc2_addr), &acc2_addrlen);
        first_accepted = acc2_s;
    }

    RPC_SEND(sent, pco_tst1, tst1_s, tx_buf, TST_BUF_LEN, 0);

    if (iut1_done)
        sockts_read_check_fd(pco_iut, acc1_s, tx_buf, rx_buf, TST_BUF_LEN);
    else
        sockts_read_check_fd(iut_aux, acc2_s, tx_buf, rx_buf, TST_BUF_LEN);

    rpc_connect(pco_tst2, tst2_s, iut_addr);

    RING("Attempt to retrive next TCP connection descriptor");

    if (!iut1_done)
    {
        RING("accept() called on pco_iut is unblocked");
        pco_iut->op = RCF_RPC_WAIT;
        acc1_s = rpc_accept(pco_iut, iut_s,
                            SA(&acc1_addr), &acc1_addrlen);
    }

    if (!iut_aux_done)
    {
        RING("accept() called on iut_aux_done is unblocked");
        iut_aux->op = RCF_RPC_WAIT;
        acc2_s = rpc_accept(iut_aux, child_s,
                            SA(&acc2_addr), &acc2_addrlen);
    }

    if (te_sockaddrcmp(SA(&acc1_addr), acc1_addrlen,
                       SA(&acc2_addr), acc2_addrlen) == 0)
    {
        TEST_FAIL("Both returned connection have the "
                  "same remote peer address");
    }

    if (first_accepted == acc1_s)
    {
        CHECK_SOCKET_STATE(pco_iut, acc1_s, pco_tst1,
                           tst1_s, STATE_CONNECTED);
        CHECK_SOCKET_STATE(iut_aux, acc2_s, pco_tst2,
                           tst2_s, STATE_CONNECTED);
    }
    else
    {
        CHECK_SOCKET_STATE(pco_iut, acc1_s, pco_tst2,
                           tst2_s, STATE_CONNECTED);
        CHECK_SOCKET_STATE(iut_aux, acc2_s, pco_tst1,
                           tst1_s, STATE_CONNECTED);
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, acc1_s);
    CLEANUP_RPC_CLOSE(iut_aux, acc2_s);

    if (iut_aux)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(iut_aux));

    TEST_END;
}
