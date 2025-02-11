/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 *
 * $Id$
 */

/** @page basic-send_recv_shutdown Terminating of sending/receiving via TCP connection by shutdown(RDWR) from another process or thread
 *
 * @objective Check that sending/receiving data using TCP socket is
 *            terminated correctly when @b shutdown(@c RDWR) is called
 *            on the socket from another process or thread.
 *
 * @type stress
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst           PCO on TST
 * @param iut_addr          Network address on IUT
 * @param tst_addr          Network address on TST
 * @param conn_num          Number of TCP connections to test
 * @param use_threads       If @c TRUE, create threads instead of
 *                          child processes
 * @param send_func         Send function to use on IUT:
 *                          - @c send
 *                          - @c onload_zc_send
 *                          - @c onload_zc_send_user_buf
 * @param send_chunk_min    Minimum chunk of data to send
 * @param send_chunk_max    Maximum chunk of data to send
 *
 * @par Scenario:
 * -# Create @p conn_num TCP connections between @p pco_iut and @p pco_tst.
 * -# For each TCP connection, create three child processes (or threads if
 *    @p use_threads is @c TRUE) from @p pco_iut and two ones from @p
 *    pco_tst.
 * -# For each TCP connection, start sending some long pattern from the
 *    first process or thread created for it on @p pco_iut and from the
 *    second process created for it on @p pco_tst. Start receiving and
 *    checking for correctness sent data on peers.
 * -# Wait for some time, and then for each TCP connection call
 *    @b shutdown(@c RDWR) from the third thread or process created for
 *    the connection on IUT.
 * -# Check what was returned by sending/receiving functions.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/send_recv_shutdown"

#include "sockapi-test.h"
#include "tapi_tcp.h"
#include "tapi_mem.h"

#define SEND_TIME 5
#define RECV_TIME 10 /* 8 works for me, but let's be safe - Sasha */

#define TEST_GET_SHUTDOWN_HOW(var_name_) \
    TEST_GET_ENUM_PARAM(var_name_, RPC_SHUTDOWN_HOW)

#define TA_IOMUX_MAPPING_LIST \
    { "select",        FUNC_SELECT },       \
    { "pselect",       FUNC_PSELECT },      \
    { "poll",          FUNC_POLL },         \
    { "ppoll",         FUNC_PPOLL },        \
    { "epoll",         FUNC_EPOLL },        \
    { "epoll_pwait",   FUNC_EPOLL_PWAIT },  \
    { "epoll_pwait2",  FUNC_EPOLL_PWAIT2 }, \
    { "default_iomux", FUNC_DEFAULT_IOMUX },\
    { "no_iomux",      FUNC_NO_IOMUX }

#define TEST_GET_TA_IOMUX_FUNC(var_name_) \
    TEST_GET_ENUM_PARAM(var_name_, TA_IOMUX_MAPPING_LIST)

/** Maximum length of send function wrapper's name. */
#define MAX_SEND_WRAPPER_LEN 512

/**
 * Configure ZC buffer and completion queue for checking onload_zc_send()
 * with user buffer.
 *
 * ZC buffer is configured to be big enough to contain all the
 * unacknowledged data onload_zc_send() may queue.
 *
 * @param pco_iut           RPC server on IUT.
 * @param iut_s             IUT socket FD.
 * @param pco_tst           RPC server on Tester.
 * @param tst_s             Tester socket FD.
 * @param send_func_ctx     RPC pointer to sending function context.
 */
static void
configure_zc_user_buf(rcf_rpc_server *pco_iut, int iut_s,
                      rcf_rpc_server *pco_tst, int tst_s,
                      rpc_ptr send_func_ctx)
{
    int iut_sndbuf = 0;
    int tst_rcvbuf = 0;

    /*
     * I do not know how onload_zc_send() with user buffers determines
     * that no more data can be queued right now. So I allocate at least
     * 2000000 bytes, and not less than 50 times the space in send buffer
     * on our side and receive buffer on peer. Hopefully this should be
     * enough.
     */
    const int min_total_size = 2000000;
    const int bufs_len_multiplier = 50;

    int total_size;

    rpc_getsockopt(pco_iut, iut_s, RPC_SO_SNDBUF, &iut_sndbuf);
    rpc_getsockopt(pco_tst, tst_s, RPC_SO_RCVBUF, &tst_rcvbuf);

    total_size = MAX(min_total_size,
                     (iut_sndbuf + tst_rcvbuf) * bufs_len_multiplier);

    rpc_sockts_send_func_ctx_init_zc_buf(pco_iut, send_func_ctx, iut_s,
                                         total_size);
}

/**
 * Check whether receiving completion events in an auxiliary
 * function failed with ECONNRESET on TA - this is fine for
 * onload_zc_send() with user buffers.
 *
 * @param rpcs        RPC server
 *
 * @return @c TRUE if expected error occurred, @c FALSE otherwise.
 */
static te_bool
check_zc_completion_fail(rcf_rpc_server *rpcs)
{
    if (RPC_ERRNO(rpcs) == TE_RC(TE_TA_UNIX, TE_ECONNRESET) &&
        strcmp(
            RPC_ERROR_MSG(rpcs),
            "recvmsg() failed when getting completion event") == 0)
    {
        return TRUE;
    }

    return FALSE;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    struct sockaddr_storage  iut_addr_aux;
    struct sockaddr_storage  tst_addr_aux;

    const struct if_nameindex *tst_if = NULL;

    int                 i = 0;
    int                 j = 0;
    int                 conn_num = 0;
    int                *iut_socks = NULL;
    int                *tst_socks = NULL;
    rcf_rpc_server    **iut_pcos = NULL;
    rcf_rpc_server    **tst_pcos = NULL;
    rpc_ptr            *iut_send_ctxts = NULL;
    te_bool             use_threads = FALSE;
    char                rpc_name[RCF_MAX_NAME];
    uint64_t            sent;
    uint64_t            received;
    int                 send_chunk_min;
    int                 send_chunk_max;

    rcf_rpc_server *pco_send;
    rcf_rpc_server *pco_recv;
    int             sock_send;
    int             sock_recv;
    char           *recv_name;
    char           *send_name;
    int             recv_num;
    int             send_num;
    te_bool         func_failed;
    te_bool         is_failed = FALSE;
    rpc_shut_how    shut_how;
    iomux_func      iomux;

    uint64_t    sndbuf_len;
    uint64_t    rcvbuf_len;
    uint64_t    may_lost;

    tarpc_pat_gen_arg *lcg_arg = NULL;

    tapi_pat_sender   *sender_ctxts = NULL;
    tapi_pat_receiver *receiver_ctxts = NULL;

    const char *send_func = NULL;
    char        send_wrapper[MAX_SEND_WRAPPER_LEN] = "";
    te_bool     zc_send_user_buf = FALSE;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(conn_num);
    TEST_GET_BOOL_PARAM(use_threads);
    TEST_GET_IF(tst_if);
    TEST_GET_SHUTDOWN_HOW(shut_how);
    TEST_GET_TA_IOMUX_FUNC(iomux);
    TEST_GET_STRING_PARAM(send_func);
    TEST_GET_INT_PARAM(send_chunk_min);
    TEST_GET_INT_PARAM(send_chunk_max);

    if (strcmp(send_func, "send") != 0)
    {
        TE_SPRINTF(send_wrapper, "tarpc_send_func_%s", send_func);

        if (strcmp(send_func, "onload_zc_send_user_buf") == 0)
        {
            /*
             * When onload_zc_send() is used with registered ZC buffers,
             * for each sent buffer completion message arrives on the
             * same socket via MSG_ERRQUEUE, and POLLERR is reported when
             * such completion message is available. In such case
             * rpc_pattern_sender() and rpc_pattern_receiver() running in
             * parallel should ignore POLLERR arrived instead of POLLIN
             * or POLLOUT instead of terminating prematurely because of it.
             */
            zc_send_user_buf = TRUE;
        }
    }

    sender_ctxts = tapi_calloc(conn_num * 2, sizeof(*sender_ctxts));
    receiver_ctxts = tapi_calloc(conn_num * 2, sizeof(*receiver_ctxts));
    iut_send_ctxts = tapi_calloc(conn_num, sizeof(*iut_send_ctxts));

    iut_socks = TE_ALLOC(sizeof(int) * conn_num);
    tst_socks = TE_ALLOC(sizeof(int) * conn_num);
    for (i = 0; i < conn_num; i++)
    {
        CHECK_RC(tapi_sockaddr_clone(pco_iut, iut_addr,
                                     &iut_addr_aux));
        CHECK_RC(tapi_sockaddr_clone(pco_tst, tst_addr,
                                     &tst_addr_aux));
        GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM,
                       RPC_PROTO_DEF, SA(&iut_addr_aux),
                       SA(&tst_addr_aux),
                       iut_socks + i, tst_socks + i);
    }

    iut_pcos = TE_ALLOC(sizeof(void *) * conn_num * 3);
    tst_pcos = TE_ALLOC(sizeof(void *) * conn_num * 2);

    /* Initialize pattern generator coefficients to send
     * different data on different connections and directions.
     * Using pattern a[n] = coef2*a[n-1] + coef3, with a[0]=coef1.
     * coef2 must be odd.
     * See @ref RPC_PATTERN_GEN_LCG
     */
    for (i = 0; i < conn_num * 2; ++i)
    {
        tapi_pat_sender_init(&sender_ctxts[i]);
        sender_ctxts[i].gen_func = RPC_PATTERN_GEN_LCG;
        tapi_rand_gen_set(&sender_ctxts[i].size,
                          send_chunk_min, send_chunk_max, 0);
        sender_ctxts[i].duration_sec = SEND_TIME;
        sender_ctxts[i].sent_ptr = &sent;
        sender_ctxts[i].send_failed_ptr = &func_failed;

        tapi_pat_receiver_init(&receiver_ctxts[i]);
        receiver_ctxts[i].gen_func = RPC_PATTERN_GEN_LCG;
        receiver_ctxts[i].duration_sec = RECV_TIME;
        receiver_ctxts[i].received_ptr = &received;
        receiver_ctxts[i].recv_failed_ptr = &func_failed;

        lcg_arg = &sender_ctxts[i].gen_arg;
        receiver_ctxts[i].gen_arg_ptr = lcg_arg;

        lcg_arg->offset = 0;
        lcg_arg->coef1 = rand_range(0, RAND_MAX);
        lcg_arg->coef2 = rand_range(0, RAND_MAX) | 1;
        lcg_arg->coef3 = rand_range(0, RAND_MAX);
    }

    for (i = 0; i < conn_num * 3; i++)
    {
        snprintf(rpc_name, RCF_MAX_NAME, "iut_child_%d", i);
        if (use_threads)
            rcf_rpc_server_thread_create(pco_iut, rpc_name,
                                         iut_pcos + i);
        else
            rcf_rpc_server_fork(pco_iut, rpc_name, iut_pcos + i);
    }

    for (i = 0; i < conn_num * 2; i++)
    {
        snprintf(rpc_name, RCF_MAX_NAME, "tst_child_%d", i);
        if (use_threads)
            rcf_rpc_server_thread_create(pco_tst, rpc_name,
                                         tst_pcos + i);
        else
            rcf_rpc_server_fork(pco_tst, rpc_name, tst_pcos + i);
    }

    if (send_wrapper[0] != '\0')
    {
        for (i = 0; i < conn_num; i++)
        {
            iut_send_ctxts[i] =
                  rpc_sockts_alloc_send_func_ctx(iut_pcos[3 * i]);

            if (zc_send_user_buf)
            {
                configure_zc_user_buf(iut_pcos[3 * i], iut_socks[i],
                                      tst_pcos[2 * i], tst_socks[i],
                                      iut_send_ctxts[i]);
            }
        }
    }

    for (i = 0; i < conn_num; i++)
    {
        sender_ctxts[2 * i].iomux = iomux;
        sender_ctxts[2 * i].snd_wrapper = send_wrapper;
        sender_ctxts[2 * i].snd_wrapper_ctx = iut_send_ctxts[i];
        if (zc_send_user_buf)
        {
            sender_ctxts[2 * i].pollerr_handler =
                                  "tarpc_zc_send_pollerr_handler";
            sender_ctxts[2 * i].pollerr_handler_data =
                                        iut_send_ctxts[i];
        }
        iut_pcos[3 * i]->op = RCF_RPC_CALL;
        /* Use extra 30s timeout value (instead of default 10s),
         * it helps to avoid errors in some cases: see ST-2000 */
        iut_pcos[3 * i]->timeout = TE_SEC2MS(SEND_TIME + 30);
        rpc_pattern_sender(iut_pcos[3 * i], iut_socks[i],
                           &sender_ctxts[2 * i]);

        tst_pcos[2 * i]->op = RCF_RPC_CALL;
        tst_pcos[2 * i]->timeout = (RECV_TIME + 1) * 1000;
        rpc_pattern_receiver(tst_pcos[2 * i], tst_socks[i],
                             &receiver_ctxts[2 * i]);

        tst_pcos[2 * i + 1]->op = RCF_RPC_CALL;
        /* Use extra 30s timeout value (instead of default 10s),
         * it helps to avoid errors in some cases: see ST-2000 */
        tst_pcos[2 * i + 1]->timeout = TE_SEC2MS(SEND_TIME + 30);
        rpc_pattern_sender(tst_pcos[2 * i + 1], tst_socks[i],
                           &sender_ctxts[2 * i + 1]);

        receiver_ctxts[2 * i + 1].iomux = iomux;
        receiver_ctxts[2 * i + 1].ignore_pollerr = zc_send_user_buf;
        iut_pcos[3 * i + 1]->op = RCF_RPC_CALL;
        iut_pcos[3 * i + 1]->timeout = (RECV_TIME + 1) * 1000;
        rpc_pattern_receiver(iut_pcos[3 * i + 1], iut_socks[i],
                             &receiver_ctxts[2 * i + 1]);
    }

    SLEEP(1);

    for (i = 0; i < conn_num; i++)
        rpc_shutdown(iut_pcos[3 * i + 2], iut_socks[i], shut_how);

    for (i = 0; i < conn_num * 2; i++)
    {
        j = i / 2;
        pco_send = (i % 2 == 0) ? iut_pcos[3 * j] : tst_pcos[2 * j + 1];
        pco_recv = (i % 2 == 0) ? tst_pcos[2 * j] : iut_pcos[3 * j + 1];
        send_name = (i % 2 == 0) ? "IUT" : "TST";
        recv_name = (i % 2 == 0) ? "TST" : "IUT";
        send_num = (i % 2 == 0) ? 3 * j + 1 : 2 * j + 2;
        recv_num = (i % 2 == 0) ? 2 * j + 1 : 3 * j + 2;
        sock_send = (i % 2 == 0) ? iut_socks[j] : tst_socks[j];
        sock_recv = (i % 2 == 0) ? tst_socks[j] : iut_socks[j];

        pco_send->op = RCF_RPC_WAIT;
        RPC_AWAIT_ERROR(pco_send);
        rc = rpc_pattern_sender(pco_send, sock_send,
                                &sender_ctxts[i]);
        if (rc < 0 &&
              (!func_failed ||
               (RPC_ERRNO(pco_send) != RPC_EPIPE &&
                RPC_ERRNO(pco_send) != RPC_ECONNRESET)) &&
              !(zc_send_user_buf && check_zc_completion_fail(pco_send)))
        {
            is_failed = TRUE;
            if (func_failed)
            {
                ERROR_VERDICT("%s sending function failed with "
                              "error " RPC_ERROR_FMT, send_name,
                              RPC_ERROR_ARGS(pco_send));
            }
            else
            {
                ERROR_VERDICT("%s pattern_sender() "
                              "failed with unexpected error "
                              RPC_ERROR_FMT, send_name,
                              RPC_ERROR_ARGS(pco_send));
            }
        }

        pco_recv->op = RCF_RPC_WAIT;
        RPC_AWAIT_ERROR(pco_recv);
        rc = rpc_pattern_receiver(pco_recv, sock_recv,
                                  &receiver_ctxts[i]);
        if (rc < 0 && (!func_failed ||
                       (RPC_ERRNO(pco_recv) != RPC_EPIPE &&
                        RPC_ERRNO(pco_recv) != RPC_ECONNRESET)))
        {
            is_failed = TRUE;
            if (rc == -2)
            {
                ERROR_VERDICT("Incorrect data received by "
                              "%s pattern_receiver()",
                              recv_name);
            }
            else if (func_failed)
            {
                ERROR_VERDICT("%s recv() failed with error "
                              RPC_ERROR_FMT, recv_name,
                              RPC_ERROR_ARGS(pco_recv));
            }
            else
            {
                ERROR_VERDICT("%s pattern_receiver() "
                              "failed with unexpected error "
                              RPC_ERROR_FMT, recv_name,
                              RPC_ERROR_ARGS(pco_recv));
            }
        }

        RING("In connection %d, from %s %llu bytes are sent, "
             "on %s %llu bytes are received",
             i / 2 + 1, send_name,
             (long long unsigned int)sent,
             recv_name,
             (long long unsigned int)received);

        /* When IUT is sender and shutdown type is WR. */
        if (shut_how == RPC_SHUT_WR && i % 2 == 0)
        {
            /* Check that TESTER received all data sent by IUT. */
            if (received < sent)
            {
                is_failed = TRUE;
                ERROR_VERDICT("%s received less than %s send",
                              recv_name, send_name);
            }

            /* Check that last recv() call returned zero. */
            if (func_failed)
            {
                is_failed = TRUE;
                ERROR_VERDICT("recv() on %s PCO failed with errno %s",
                              recv_name, errno_rpc2str(RPC_ERRNO(pco_recv)));
            }
        }

        /*
         * On IUT some data may be not received if it didn't arrive before
         * we call shutdown(RDWR).
         * On TESTER some data may be not received if it was in IUT socket
         * sending buffer when some data arrived from TESTER after
         * shutdown(RDWR), resulting in RST sent from IUT.
         */
        if (received != sent)
        {
            if (received > sent)
            {
                is_failed = TRUE;
                ERROR_VERDICT("Amount of data received by %s PCO %d is "
                              "greater than amount of data sent by %s "
                              "PCO %d",
                              recv_name, recv_num,
                              send_name, send_num);
            }
            else
            {
                sndbuf_len = 0;
                rcvbuf_len = 0;
                rpc_getsockopt(pco_send, sock_send, RPC_SO_SNDBUF,
                               &sndbuf_len);

                if (shut_how == RPC_SHUT_RDWR)
                {
                    rpc_getsockopt(pco_recv, sock_recv, RPC_SO_RCVBUF,
                                   &rcvbuf_len);
                    may_lost = sndbuf_len + rcvbuf_len;
                }
                else
                {
                    may_lost = sndbuf_len;
                }

                /* no_iomux non-blocking send violated SO_SNDBUF
                 * limitation, both Linux and Onload */
                if (sender_ctxts[i].iomux == FUNC_NO_IOMUX)
                    sndbuf_len += send_chunk_max;

                if (sent - received > may_lost)
                {
                    is_failed = TRUE;
                    ERROR_VERDICT("Amount of data missed by %s PCO %d "
                                  "is more than size of sending buffer "
                                  "on %s PCO %d",
                                  recv_name, recv_num,
                                  send_name, send_num);
                    TEST_ARTIFACT("Missed data = %lu, "
                                  "sending buffer size = %lu",
                                  sent - received, sndbuf_len);
                }
            }
        }
    }

    if (zc_send_user_buf)
    {
        int rpcs_num;

        for (i = 0; i < conn_num; i++)
        {
            rpcs_num = 3 * i;
            RPC_AWAIT_ERROR(iut_pcos[rpcs_num]);
            rc = rpc_sockts_send_func_ctx_clean_zc_buf(
                                                  iut_pcos[rpcs_num],
                                                  iut_send_ctxts[i],
                                                  iut_socks[i],
                                                  TAPI_WAIT_NETWORK_DELAY);
            if (rc < 0)
            {
                is_failed = TRUE;
                ERROR_VERDICT("rpc_sockts_send_func_ctx_clean_zc_buf() "
                              "failed on IUT PCO %d with error "
                              RPC_ERROR_FMT, rpcs_num,
                              RPC_ERROR_ARGS(iut_pcos[rpcs_num]));
            }
        }
    }


    if (is_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    for (i = 0; i < conn_num; i++)
    {
        CLEANUP_RPC_CLOSE(pco_iut, iut_socks[i]);
        CLEANUP_RPC_CLOSE(pco_tst, tst_socks[i]);
    }

    free(iut_socks);
    free(tst_socks);

    if (send_wrapper[0] != '\0' && iut_send_ctxts != NULL &&
        use_threads)
    {
        for (i = 0; i < conn_num; i++)
        {
            rpc_free(pco_iut, iut_send_ctxts[i]);
        }
    }

    if (iut_pcos != NULL)
        for (i = 0; i < conn_num * 3; i++)
            if (iut_pcos[i] != NULL)
                rcf_rpc_server_destroy(iut_pcos[i]);
    if (tst_pcos != NULL)
        for (i = 0; i < conn_num * 2; i++)
            if (tst_pcos[i] != NULL)
                rcf_rpc_server_destroy(tst_pcos[i]);

    free(iut_pcos);
    free(tst_pcos);
    free(sender_ctxts);
    free(receiver_ctxts);
    free(iut_send_ctxts);

    TEST_END;
}
