/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * @param ioctl_func    Function to call (usual @b Ioctl())
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-threaded_busy_socket  Exercise multithreading with busy socket
 *
 * @objective  Repeatedly call function in child threads, in that time try
 *             to do actions (bind, listen or connect)  which can lead to
 *             the socket handover.
 *
 * @type conformance
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param func          Tested function which should be called in threads:
 *                      - poll
 *                      - epoll
 *                      - select
 *                      - recv
 *                      - send
 * @param process       Create new process to call connect() in it if @c TRUE.
 * @param threads_num   Threads number:
 *                      - 10
 * @param sock_type     Socket type:
 *                      - SOCK_STREAM
 *                      - SOCK_DGRAM
 * @param connect       Call connect() in the main thread if @c TRUE, else
 *                      listen and accept socket on IUT in case of
 *                      @c SOCK_STREAM testing.
 * @param bind_iut      Bind IUT socket if @c TRUE.
 * @param wildcard      Bind IUT socket to @c INADDR_ANY if @c TRUE, it makes
 *                      sense only if @p bind_iut is @c TRUE.
 *
 * @par Test sequence:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/threaded_busy_socket"

#include "sockapi-test.h"

/* Duration of calling function in child threads. */
#define DURATION 3000

/* Packet data length */
#define DATA_BULK 100

/* Last packet data buffer */
static char last_packet[DATA_BULK];

/**
 * Call one of supported actions to load threads.
 * 
 * @param pco_iut_thr   Threads array
 * @param threads_num   The array length
 * @param iut_s         Socket
 * @param func          Function to be repeatedly called
 * @param call          Determines if it is _CALL (if @c TRUE) or _WAIT
 *                      operation
 * @param sock_type     Socket type
 */
static void
call_rpc_action(rcf_rpc_server **pco_iut_thr, int threads_num, int iut_s,
                const char *func, te_bool call, rpc_socket_type sock_type)
{
    int i;

    for (i = 0; i < threads_num; i++)
    {
        if (call)
            pco_iut_thr[i]->op = RCF_RPC_CALL;
        else 
            pco_iut_thr[i]->timeout = DURATION * 2;

        if (strcmp(func, "recv") == 0)
            rpc_many_recv(pco_iut_thr[i], iut_s, DATA_BULK, -1, DURATION,
                          last_packet, DATA_BULK, TRUE, NULL);
        else if (strcmp(func, "send") == 0)
            rpc_many_send_num(pco_iut_thr[i], iut_s, DATA_BULK, -1,
                              DURATION, sock_type == RPC_SOCK_DGRAM, TRUE,
                              NULL);
        else
        {
            /* The RPC can fail since argument exp_rc can be not satisfied
             * with the results.  */
            if (!call)
                RPC_AWAIT_IUT_ERROR(pco_iut_thr[i]);
            rpc_multiple_iomux(pco_iut_thr[i], iut_s, str2iomux(func),
                               RPC_POLLIN | RPC_POLLOUT, -1, DURATION, 1,
                               NULL, NULL, NULL);
        }
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_iut_aux = NULL;
    rcf_rpc_server        **pco_iut_thr = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    struct sockaddr_storage wcard_addr;
    rpc_socket_type         sock_type;
    const char             *func;
    te_bool                 connect;
    int                     threads_num;
    te_bool                 wildcard;
    te_bool                 bind_iut;
    te_bool                 process;

    te_bool fail = TRUE;
    te_bool bound = FALSE;
    DEFINE_RPC_STRUCT_SIGACTION(old_act);
    char name[32];
    int iut_s = -1;
    int tst_s = -1;
    int acc_s = -1;
    int i;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(func);
    TEST_GET_INT_PARAM(threads_num);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(connect);
    TEST_GET_BOOL_PARAM(wildcard);
    TEST_GET_BOOL_PARAM(bind_iut);
    TEST_GET_BOOL_PARAM(process);

    if (wildcard)
    {
        tapi_sockaddr_clone_exact(iut_addr, SS(&wcard_addr));
        te_sockaddr_set_wildcard(SA(&wcard_addr));
    }

    if (strcmp(func, "send") == 0)
        CHECK_RC(tapi_sigaction_simple(pco_iut, RPC_SIGPIPE,
                                       SIGNAL_REGISTRAR, &old_act));

    TEST_STEP("Create TCP or UDP socket on tester, prepare it to establish "
              "connection with IUT.");
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       sock_type, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);
    if (sock_type == RPC_SOCK_STREAM && connect)
        rpc_listen(pco_tst, tst_s, -1);
    if (sock_type == RPC_SOCK_DGRAM)
        rpc_connect(pco_tst, tst_s, iut_addr);

    TEST_STEP("Create TCP or UDP socket on IUT.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                       sock_type, RPC_PROTO_DEF);

    TEST_STEP("Start aux process if @p process is @c TRUE.");
    if (process)
        CHECK_RC(rcf_rpc_server_fork(pco_iut, "aux_proc", &pco_iut_aux));
    else
        pco_iut_aux = pco_iut;

    pco_iut_thr = te_calloc_fill(threads_num, sizeof(*pco_iut_thr), 0);

    TEST_STEP("Start @p threads_num new threads.");
    for (i = 0; i < threads_num; i++)
    {
        snprintf(name, sizeof(name), "thread%d", i);
        CHECK_RC(rcf_rpc_server_thread_create(pco_iut, name, &pco_iut_thr[i]));
    }

    if (sock_type == RPC_SOCK_DGRAM && !bind_iut && strcmp(func, "recv") == 0)
        rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, RPC_O_NONBLOCK);

    TEST_STEP("Repeatedly call function @p func.");
    call_rpc_action(pco_iut_thr, threads_num, iut_s, func, TRUE, sock_type);
    TAPI_WAIT_NETWORK;

    /* Linux binds socket before attempt to connect. */
    if (sock_type == RPC_SOCK_DGRAM && strcmp(func, "send") == 0)
    {
        struct sockaddr_storage iut_aux_addr;
        socklen_t               addrlen = sizeof(iut_aux_addr);

        memset(&iut_aux_addr, 0, sizeof(iut_aux_addr));
        rpc_getsockname(pco_iut_aux, iut_s, SA(&iut_aux_addr), &addrlen);
        if (te_sockaddr_get_port(SA(&iut_aux_addr)) != 0)
            bound = TRUE;
    }

    TEST_STEP("Bind IUT socket if @p bind_iut is @c TRUE to @c INADDR_ANY address "
              "if @p wildcard is @c TRUE.");
    if (bind_iut && !bound)
    {
        rpc_bind(pco_iut_aux, iut_s, wildcard ? CONST_SA(&wcard_addr) :
                                                iut_addr);
    }

    TEST_STEP("Call connect() on the socket if @p connect is @c TRUE, accept "
              "connection on the tester side.");
    if (connect)
    {
        rpc_connect(pco_iut_aux, iut_s, tst_addr);
        if (sock_type == RPC_SOCK_STREAM)
        {
            acc_s = rpc_accept(pco_tst, tst_s, NULL, NULL);
            RPC_CLOSE(pco_tst, tst_s);
            tst_s = acc_s;
            acc_s = -1;
        }
    }

    TEST_STEP("Call listen() and accept connection on IUT if @p connect "
              "is @c FALSE.");
    if (!connect && sock_type == RPC_SOCK_STREAM)
    {
        rpc_listen(pco_iut_aux, iut_s, 0);
        if (bind_iut)
        {
            rpc_connect(pco_tst, tst_s, iut_addr);
            acc_s = rpc_accept(pco_iut_aux, iut_s, NULL, NULL);
        }
    }

    TEST_STEP("Send some packets from tester if IUT is waiting for packets.");
    if (strcmp(func, "recv") == 0 || strcmp(func, "poll") == 0)
    {
        if (sock_type == RPC_SOCK_DGRAM ||
            (sock_type == RPC_SOCK_STREAM && (connect || bind_iut)))
        {
            for (i = 0; i < threads_num * 5; i++)
            {
                RPC_AWAIT_IUT_ERROR(pco_tst);
                rpc_send(pco_tst, tst_s, last_packet, DATA_BULK, 0);
            }
        }
    }

    if (strcmp(func, "send") != 0)
    {
        call_rpc_action(pco_iut_thr, threads_num, iut_s, func, FALSE,
                        sock_type);
    }

    TEST_STEP("Stop the child threads.");
    for (i = 0; i < threads_num; i++)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_thr[i]));

    fail = FALSE;

    TEST_SUCCESS;

cleanup:
    if (fail)
        rcf_rpc_server_restart(pco_iut);
    else
    {
        CLEANUP_RPC_CLOSE(pco_iut_aux, iut_s);
        CLEANUP_RPC_CLOSE(pco_iut_aux, acc_s);
        if (pco_iut_aux != pco_iut)
            CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    }
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (process)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_aux));

    if (strcmp(func, "send") == 0)
    {
        rpc_sigaction(pco_iut, RPC_SIGPIPE, &old_act, NULL);
        rpc_sigaction_release(pco_iut, &old_act);
    }

    free(pco_iut_thr);

    TEST_END;
}
