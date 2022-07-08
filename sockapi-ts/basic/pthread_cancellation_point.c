/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/**
 * @page basic-pthread_cancellation_point Test that cancellation point for thread works correctly
 *
 * @objective Perform @b pthread_cancel() while thread is blocked in function which is
 *            cancellation point and check that thread is cancelled
 *
 * @param env   Testing environment:
 *      - @ref arg_types_env_peer2peer
 *      - @ref arg_types_env_peer2peer_ipv6
 * @param state Cancellation state to set on agent:
 *      - disable for @c RPC_PTHREAD_CANCEL_DISABLE
 *      - enable for @c RPC_PTHREAD_CANCEL_ENABLE
 * @param type  Cancellation type to set on agent:
 *      - deferred for @c RPC_PTHREAD_CANCEL_DEFERRED
 *      - async for @c RPC_PTHREAD_CANCEL_ASYNCHRONOUS
 * @param func  Function to be tested:
 *      - accept
 *      - read
 *      - readv
 *      - recv
 *      - recvfrom
 *
 * @par Scenario:
 *
 * @author Vasilij Ivanov <Vasilij.Ivanov@oktetlabs.ru>
 */

#define TE_TEST_NAME "basic/pthread_cancellation_point"

#include "sockapi-test.h"

#define DATA_BULK       200

#define CANCEL_STATES \
    {"disable", RPC_PTHREAD_CANCEL_DISABLE},   \
    {"enable", RPC_PTHREAD_CANCEL_ENABLE}

#define CANCEL_TYPES \
    {"deferred", RPC_PTHREAD_CANCEL_DEFERRED},   \
    {"async", RPC_PTHREAD_CANCEL_ASYNCHRONOUS}

void
test_call_preparation(rcf_rpc_server *pco_aux, rcf_rpc_server *pco_tst,
                      int iut_s, int tst_s, int *acc_s,
                      const struct sockaddr *conn_addr, const char *func)
{
    if (strcmp(func, "accept") == 0)
    {
        rpc_listen(pco_aux, iut_s, SOCKTS_BACKLOG_DEF);
    }
    if ((strcmp(func, "read") == 0) ||
        (strcmp(func, "readv") == 0) ||
        (strcmp(func, "recv") == 0) ||
        (strcmp(func, "recvfrom") == 0))
    {
        rpc_listen(pco_aux, iut_s, SOCKTS_BACKLOG_DEF);

        rpc_connect(pco_tst, tst_s, conn_addr);
        *acc_s = rpc_accept(pco_aux, iut_s, NULL, NULL);
    }
}

void
test_call_check(rcf_rpc_server *rpcs, int res, const char *func,
                void *sendbuf, void* recvbuf)
{
    if (res < 0)
    {
        TEST_VERDICT("Error occurred during testing function, errno: %r",
                     RPC_ERRNO(rpcs));
    }
    else
    {
        if ((strcmp(func, "read") == 0) ||
            (strcmp(func, "readv") == 0) ||
            (strcmp(func, "recv") == 0) ||
            (strcmp(func, "recvfrom") == 0))
        {
            if (res != DATA_BULK)
            {
                TEST_VERDICT("Unexpected amount of data was received");
            }
            else if (memcmp(sendbuf, recvbuf, DATA_BULK))
            {
                TEST_VERDICT("Invalid data received");
            }
        }
    }
}

void
test_call(rcf_rpc_server *rpcs, int iut_s, int acc_s, void *sendbuf,
          void *recvbuf, int buflen, const struct sockaddr *conn_addr,
          const char *func, te_bool check)
{
    int rc = 0;
    socklen_t addrlen = sizeof(*conn_addr);

    if (check)
        RPC_AWAIT_ERROR(rpcs);

    if (strcmp(func, "accept") == 0)
    {
        rc = rpc_accept(rpcs, iut_s, NULL, NULL);
    }
    if (strcmp(func, "read") == 0)
    {
        rc = rpc_read(rpcs, acc_s, recvbuf, buflen);
    }
    if (strcmp(func, "readv") == 0)
    {
        rc = rpc_recv_func_sys_readv(rpcs, acc_s, recvbuf, buflen, 0);
    }
    if (strcmp(func, "recv") == 0)
    {
        rc = rpc_recv(rpcs, acc_s, recvbuf, buflen, 0);
    }
    if (strcmp(func, "recvfrom") == 0)
    {
        rc = rpc_recvfrom(rpcs, acc_s, recvbuf,
                          buflen, 0, SA(conn_addr), &addrlen);
    }

    if (check)
    {
        test_call_check(rpcs, rc, func, sendbuf, recvbuf);
    }
}

void
test_call_complete(rcf_rpc_server *rpcs, int tst_s, void *buf,
                   int buflen, const struct sockaddr *conn_addr,
                   const char *func)
{
    if (strcmp(func, "accept") == 0)
    {
        rpc_connect(rpcs, tst_s, conn_addr);
    }
    if ((strcmp(func, "read") == 0) ||
        (strcmp(func, "readv") == 0) ||
        (strcmp(func, "recv") == 0) ||
        (strcmp(func, "recvfrom") == 0))
    {
        rpc_write(rpcs, tst_s, buf, buflen);
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_tst = NULL;
    rcf_rpc_server     *pco_aux = NULL;

    int                 iut_s = -1;
    int                 tst_s = -1;
    int                 accepted = -1;

    rpc_pthread_cancelstate   state;
    rpc_pthread_canceltype    type;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    te_bool             done;

    tarpc_pthread_t     tid;

    uint8_t              sendbuf[DATA_BULK];
    uint8_t              recvbuf[DATA_BULK];

    const char         *func;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ENUM_PARAM(state, CANCEL_STATES);
    TEST_GET_ENUM_PARAM(type, CANCEL_TYPES);
    TEST_GET_STRING_PARAM(func);

    te_fill_buf(sendbuf, DATA_BULK);

    TEST_STEP("Create @b pco_aux thread on IUT");
    CHECK_RC(rcf_rpc_server_thread_create(pco_iut, "child_thread",
                                          &pco_aux));

    TEST_STEP("Create and bind sockets on IUT and Tester");
    iut_s = rpc_socket(pco_aux, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_bind(pco_aux, iut_s, iut_addr);
    rpc_bind(pco_tst, tst_s, tst_addr);

    TEST_STEP("Set thread cancelability state for @b pco_aux to @p state.");
    rpc_pthread_setcancelstate(pco_aux, state, NULL);

    TEST_STEP("Set thread cancelability type for @b pco_aux to @p type.");
    rpc_pthread_setcanceltype(pco_aux, type, NULL);

    tid = rpc_pthread_self(pco_aux);

    TEST_STEP("If @p func is @c accept, make IUT socket listener; "
              "otherwise establish TCP connection between IUT "
              "and Tester sockets.");
    test_call_preparation(pco_aux, pco_tst, iut_s, tst_s,
                          &accepted, iut_addr, func);

    TEST_STEP("Call @p func with @c RCF_RPC_CALL on pco_aux. "
              "Check that it hangs.");
    pco_aux->op = RCF_RPC_CALL;
    test_call(pco_aux, iut_s, accepted, sendbuf, recvbuf,
              DATA_BULK, iut_addr, func, FALSE);
    TAPI_WAIT_NETWORK;

    CHECK_RC(rcf_rpc_server_is_op_done(pco_aux, &done));
    if (done)
        TEST_VERDICT("func is not hanging");

    TEST_STEP("@b pthread_cancel pco_aux thread");
    rpc_pthread_cancel(pco_iut, tid);

    if (state == RPC_PTHREAD_CANCEL_ENABLE)
    {
        TEST_STEP("If @p state is RPC_PTHREAD_CANCEL_ENABLE call "
                  "@b pthread_join and check that thread really finished");
        RPC_AWAIT_ERROR(pco_iut);
        if (rpc_pthread_join(pco_iut, tid, NULL) != 0)
        {
            TEST_VERDICT("thread was not finished after cancelling "
                         "with RPC_PTHREAD_CANCEL_ENABLE state, "
                         "ptread_join failed with errno: %r",
                         RPC_ERRNO(pco_iut));
        }
        else
        {
            rcf_rpc_server_finished(pco_aux);
        }
    }

    TEST_STEP("If @p func is @c accept, call @b connect() from Tester; "
              "otherwise send from Tester some data.");
    test_call_complete(pco_tst, tst_s, sendbuf, DATA_BULK, iut_addr, func);

    if (state == RPC_PTHREAD_CANCEL_ENABLE)
    {
        TEST_STEP("If @p state is @c RPC_PTHREAD_CANCEL_ENABLE "
                  "call @p func on @b pco_iut and check what it returns.");
        RPC_AWAIT_ERROR(pco_iut);
        test_call(pco_iut, iut_s, accepted, sendbuf, recvbuf,
                  DATA_BULK, iut_addr, func, TRUE);
    }
    else
    {
        TEST_STEP("If @p state is @c RPC_PTHREAD_CANCEL_DISABLE "
                  "check what @p func returned on @b pco_aux.");
        RPC_AWAIT_ERROR(pco_aux);
        test_call(pco_aux, iut_s, accepted, sendbuf, recvbuf,
                  DATA_BULK, iut_addr, func, TRUE);
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_aux));

    RPC_CLOSE(pco_iut, iut_s);
    RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
