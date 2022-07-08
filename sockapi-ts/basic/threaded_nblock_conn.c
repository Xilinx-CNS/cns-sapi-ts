/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-threaded_nblock_conn  Non-blocking connect and data transmission with multithreading
 *
 * @objective  Perform non-blocking connect and try to send/recive data
 *             packets while child threads repeatedly call iomux function.
 *
 * @type conformance
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param func          Tested function which should be called in threads:
 *                      - poll
 *                      - epoll
 *                      - select
 * @param threads_num   Threads number:
 *                      - 10
 * @param sock_type     Socket type:
 *                      - SOCK_STREAM
 *                      - SOCK_DGRAM
 * @param write         Send data from IUT if @c TRUE, else - from tester.
 * @param bind_iut      Bind IUT socket if @c TRUE.
 * @param wildcard      Bind IUT socket to @c INADDR_ANY if @c TRUE, it makes
 *                      sense only if @p bind_iut is @c TRUE.
 *
 * @par Test sequence:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/threaded_nblock_conn"

#include "sockapi-test.h"

/* Duration of data transmission. */
#define DURATION 5000

/* Maximum number of iomux states */
#define IOMUX_MAX_STATES 15

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server        **pco_iut_thr = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    struct sockaddr_storage wcard_addr;
    rpc_socket_type         sock_type;
    te_bool                 write;
    int                     threads_num;
    int                     epoll_st_num;
    te_bool                 wildcard;
    te_bool                 bind_iut;
    const char             *func;
    tarpc_iomux_state       iomux_states[IOMUX_MAX_STATES];

    DEFINE_RPC_STRUCT_SIGACTION(old_act);
    char name[32];
    int fdflags;
    int iut_s = -1;
    int tst_s = -1;
    int tst_aux = -1;
    int i;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(func);
    TEST_GET_BOOL_PARAM(write);
    TEST_GET_INT_PARAM(threads_num);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(wildcard);
    TEST_GET_BOOL_PARAM(bind_iut);

    if (wildcard)
    {
        tapi_sockaddr_clone_exact(iut_addr, SS(&wcard_addr));
        te_sockaddr_set_wildcard(SA(&wcard_addr));
    }

    /* SIGPIPE signal can be received by the writer side. */
    CHECK_RC(tapi_sigaction_simple(write ? pco_iut : pco_tst, RPC_SIGPIPE,
                                   SIGNAL_REGISTRAR, &old_act));

    TEST_STEP("Create TCP or UDP socket on tester and bind it.");
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       sock_type, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    if (sock_type == RPC_SOCK_STREAM)
    {
        TEST_STEP("Make it listener if TCP is tested.");
        rpc_listen(pco_tst, tst_s, -1);
    }
    else if (!write)
    {
        TEST_STEP("Otherwise perform connect() to IUT address if tester is writer.");
        rpc_connect(pco_tst, tst_s, iut_addr);
    }

    TEST_STEP("Create TCP or UDP socket on IUT.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                       sock_type, RPC_PROTO_DEF);

    TEST_STEP("Bind it if @p bind_iut is @c TRUE to @c INADDR_ANY address "
              "if @p wildcard is @c TRUE.");
    if (bind_iut)
    {
        rpc_bind(pco_iut, iut_s, wildcard ? CONST_SA(&wcard_addr) :
                                            iut_addr);
    }

    TEST_STEP("Make IUT socket non-blocking.");
    fdflags = rpc_fcntl(pco_iut, iut_s, RPC_F_GETFL, RPC_O_NONBLOCK);
    rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, fdflags | RPC_O_NONBLOCK);

    for (epoll_st_num = 0; epoll_st_num < threads_num; epoll_st_num++)
    {
        CHECK_RC(rpc_iomux_create_state(pco_iut, str2iomux(func),
                                        &iomux_states[epoll_st_num]));
    }

    pco_iut_thr = te_calloc_fill(threads_num, sizeof(*pco_iut_thr), 0);

    TEST_STEP("Start @p threads_num new threads.");
    for (i = 0; i < threads_num; i++)
    {
        snprintf(name, sizeof(name), "thread%d", i);
        CHECK_RC(rcf_rpc_server_thread_create(pco_iut, name, &pco_iut_thr[i]));
    }

    TEST_STEP("Repeatedly call function @p func.");
    for (i = 0; i < threads_num; i++)
    {
        pco_iut_thr[i]->op = RCF_RPC_CALL;
        rpc_multiple_iomux_wait(pco_iut_thr[i], iut_s, str2iomux(func),
                                iomux_states[i], RPC_POLLIN | RPC_POLLOUT,
                                -1, -1, 1, NULL, NULL, NULL);
    }

    TAPI_WAIT_NETWORK;

    TEST_STEP("Call non-blocking connect() on the IUT socket.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rpc_connect(pco_iut, iut_s, tst_addr);

    TEST_STEP("Accept connection if TCP is tested.");
    if (sock_type == RPC_SOCK_STREAM)
    {
        int tmp;

        tst_aux = rpc_accept(pco_tst, tst_s, NULL, NULL);
        tmp = tst_s;
        tst_s = tst_aux;
        tst_aux = tmp;
    }

    TEST_STEP("Make tester socket non-blocking.");
    fdflags = rpc_fcntl(pco_tst, tst_s, RPC_F_GETFL, RPC_O_NONBLOCK);
    rpc_fcntl(pco_tst, tst_s, RPC_F_SETFL, fdflags | RPC_O_NONBLOCK);

    TEST_STEP("Send or receive packets in dependence on @p write.");
    if (write)
    {
        pco_tst->op = RCF_RPC_CALL;
        rpc_many_recv(pco_tst, tst_s, 100, -1, DURATION, NULL, 0, TRUE, NULL);
        rpc_many_send_num(pco_iut, iut_s, 100, -1, DURATION,
                          sock_type == RPC_SOCK_DGRAM, TRUE, NULL);
        rpc_many_recv(pco_tst, tst_s, 100, -1, DURATION, NULL, 0, TRUE, NULL);
    }
    else
    {
        pco_iut->op = RCF_RPC_CALL;
        rpc_many_recv(pco_iut, iut_s, 100, -1, DURATION, NULL, 0, TRUE, NULL);
        rpc_many_send_num(pco_tst, tst_s, 100, -1, DURATION,
                          sock_type == RPC_SOCK_DGRAM, TRUE, NULL);
        rpc_many_recv(pco_iut, iut_s, 100, -1, DURATION, NULL, 0, TRUE, NULL);
    }

    TEST_STEP("Stop the child threads.");
    for (i = 0; i < threads_num; i++)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_thr[i]));

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_aux);

    rpc_sigaction(write ? pco_iut : pco_tst, RPC_SIGPIPE, &old_act, NULL);
    rpc_sigaction_release(write ? pco_iut : pco_tst, &old_act);

    for (i = 0; i < epoll_st_num; i++)
        rpc_iomux_close_state(pco_iut, str2iomux(func), iomux_states[i]);

    free(pco_iut_thr);

    /* It's a temporary solution to avoid problems due to resource leak
     * after thread cancellation in reuse_pco mode (Bug 9286) */
    rcf_rpc_server_restart(pco_iut);

    TEST_END;
}
