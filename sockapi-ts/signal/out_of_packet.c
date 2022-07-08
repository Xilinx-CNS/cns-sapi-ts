/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Signals + Socket API
 *
 * $Id$
 */

/** @page signal-out_of_packet Check signal handling in out of packet condition
 *
 * @objective Check that in case of out of packet condition signals are
 *            handled correctly.
 *
 * @type conformance
 *
 * @param pco_iut            PCO with IUT
 * @param pco_killer         PCO on the same host as @b pco_iut
 * @param pco_tst            Tester PCO
 * @param install_sighandler Install or do not install handler for
 *                           @c SIGUSR1
 * @param restart            Set or not @c SA_RESTART for the first signal
 *
 * @reference @ref STEVENS
 *
 * @par Scenario:
 * -# Set @c EF_UDP_RCVBUF environment veriable to
 *    @c 32 * @c 1025 * @c 1024 on @p pco_iut.
 * -# Create @c SOCK_DRAM socket on @p pco_tst and bind it to @p tst_addr.
 * -# Do the following steps untill @b sendto() with large packet hangs:
 *      - Create new process.
 *      - If @c install_sighandler is @c TRUE install
 *        @c sighandler_createfile for the process.
 *      - Create @c DGRAM_SOCK sock in new process,
 *        bind it to @p pco_iut and with new unused port.
 *      - Set @c RPC_SO_RCVBUF to @c 32 * @c 1025 * @c 1024.
 *      - Overfill receive buffer of the socket
 *      - Call @b sendto() on the socket with packet of @c 60 * @c 1024
 *        length.
 * -# Send @c SIGUSR1 signal to the last created process.
 * -# If @p install_sighandler is @c TRUE check that
 *    @c sighandler_createfile was called.
 * -# Unblock @b sendto() function and check returning value.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 * -# 
 */

#define TE_TEST_NAME  "signal/out_of_packet"

#include "sockapi-test.h"
#include "ts_signal.h"

#define MAX_SOCKS 1024
#define SND_TIMEO 5
#define AUX_BUF_LEN 1024

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_killer = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    rcf_rpc_server         *child[MAX_SOCKS];
    rcf_rpc_server         *aux_thread[MAX_SOCKS];

    int                     sock[MAX_SOCKS];
    int                     tst_s = -1;
    int                     i = 0;

    const struct sockaddr     *iut_addr;
    const struct sockaddr     *tst_addr;
    struct sockaddr_storage    iut_addr_aux;

    char                    name[64];

    int                     rcvbuf = 32 * 1024 * 1024;
    int                     datalen = 10;
    int                     big_buf_len = 60 * 1024;
    int                     val;

    tarpc_timeval           tv;
    DEFINE_RPC_STRUCT_SIGACTION(sig_act);

    void                   *iut_buf = NULL;
    void                   *tst_buf = NULL;
    char                    aux_buf[AUX_BUF_LEN];

    uint64_t                sent;
    te_bool                 op_done = FALSE;

    char                    val_buf[16];

    pid_t           child_pid;
    tarpc_pthread_t child_tid;
    int             count;

    te_bool                 install_sighandler = FALSE;
    te_bool                 restart = FALSE;
    te_bool                 is_recieved = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_killer);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR_NO_PORT(iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(install_sighandler);
    TEST_GET_BOOL_PARAM(restart);

    CHECK_NOT_NULL(tst_buf = te_make_buf_by_len(datalen));
    CHECK_NOT_NULL(iut_buf = te_make_buf_by_len(big_buf_len));

    memset(child, 0, sizeof(child));
    memset(aux_thread, 0, sizeof(aux_thread));
    memset(val_buf, 0, sizeof(val_buf));

    CHECK_RC(rcf_rpc_server_restart(pco_iut));
    sprintf(val_buf, "%d", rcvbuf);
    CHECK_RC(tapi_sh_env_set(pco_iut, "EF_UDP_RCVBUF", val_buf, TRUE,
                             TRUE));

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    rc = 0;
    while (i < MAX_SOCKS && rc >= 0)
    {
        if (i != 0)
        {
            memset(name, 0, sizeof(name));
            sprintf(name, "child_%d", i);
            CHECK_RC(rcf_rpc_server_fork_exec(pco_iut, name,
                                              &child[i]));
            if (install_sighandler)
            {
                rpc_sighandler_createfile_cleanup(child[i], RPC_SIGUSR1);
                tapi_set_sighandler(child[i], RPC_SIGUSR1,
                                    "sighandler_createfile",
                                    "sigaction", restart, &sig_act);
                memset(name, 0, sizeof(name));
                sprintf(name, "aux_thread_%d", i);
                CHECK_RC(rcf_rpc_server_thread_create(child[i], name,
                                                      &aux_thread[i]));
            }
        }
        else
            child[i] = pco_iut;
        child_pid = rpc_getpid(child[i]);
        child_tid = rpc_pthread_self(child[i]);
        sock[i] = rpc_socket(child[i],
                             rpc_socket_domain_by_addr(iut_addr),
                             RPC_SOCK_DGRAM, RPC_PROTO_DEF);
        CHECK_RC(tapi_sockaddr_clone(pco_iut, iut_addr, &iut_addr_aux));
        rpc_bind(child[i], sock[i], SA(&iut_addr_aux));
        rpc_setsockopt(child[i], sock[i], RPC_SO_RCVBUF, &rcvbuf);
        rpc_getsockopt(child[i], sock[i], RPC_SO_RCVBUF, &val);

        if ((val > (rcvbuf * 2)) || (val < rcvbuf))
        {
            ERROR("Incorrect value has been set for SO_RCVBUF "
                  "option.");
            TEST_VERDICT("Failed to get 'out of packet' condition");
        }

        pco_tst->timeout = 1000000;
        rpc_many_sendto(pco_tst, (val / datalen), tst_s, datalen, 0,
                        SA(&iut_addr_aux), &sent);
        TAPI_WAIT_NETWORK;
        RPC_CHECK_READABILITY(child[i], sock[i], TRUE);

        if (i != 0)
        {
            if (!restart)
            {
                tv.tv_sec = SND_TIMEO;
                tv.tv_usec = 0;
                rpc_setsockopt(child[i], sock[i], RPC_SO_SNDTIMEO, &tv);
                tv.tv_sec = tv.tv_usec = 0;
                rpc_getsockopt(child[i], sock[i], RPC_SO_SNDTIMEO, &tv);
                if (tv.tv_sec != SND_TIMEO || tv.tv_usec != 0)
                    TEST_FAIL("Incorrect value of SO_SNDTIMEO option");
            }
            RPC_AWAIT_IUT_ERROR(child[i]);
            (child[i])->timeout = 100000;
            (child[i])->op = RCF_RPC_CALL;
            rc = rpc_sendto(child[i], sock[i], iut_buf, big_buf_len, 0,
                            tst_addr);

            count = 0;
            op_done = FALSE;
            while (count < (SND_TIMEO + 2) && !op_done)
            {
                SLEEP(1);
                CHECK_RC(rcf_rpc_server_is_op_done(child[i], &op_done));
                count++;
            }

            if (op_done)
            {
                (child[i])->op = RCF_RPC_WAIT;
                rc = rpc_sendto(child[i], sock[i], iut_buf, big_buf_len, 0,
                                tst_addr);
            }
            else
            {
                if (!restart || !install_sighandler)
                    RING_VERDICT("sendto() have not been unblocked in "
                                 "spite of SO_SNDTIMEO was set");
                rpc_kill(pco_killer, child_pid,  RPC_SIGUSR1);
                if (restart)
                {
                    SLEEP(1);
                    CHECK_RC(rcf_rpc_server_is_op_done(child[i], &op_done));
                    if (op_done)
                    {
                        RPC_AWAIT_IUT_ERROR(child[i]);
                        (child[i])->op = RCF_RPC_WAIT;
                        rc = rpc_sendto(child[i], sock[i], iut_buf,
                                        big_buf_len, 0, tst_addr);
                        RING_VERDICT("sendto() with big packet returned "
                                     "%d with %s in case of SA_RESTART"
                                     "is set",
                                     errno_rpc2str(RPC_ERRNO(pco_iut)));
                    }
                }
                else if (install_sighandler)
                {
                    SLEEP(1);
                    CHECK_RC(rcf_rpc_server_is_op_done(child[i], &op_done));
                    if (!op_done)
                        RING_VERDICT("sendto() with big packet still "
                                     "hanging when SA_RESTART is not set");
                }
                else
                    TEST_SUCCESS;

                is_recieved =
                    rpc_thrd_sighnd_crtfile_exists_unlink(pco_killer,
                                                          RPC_SIGUSR1,
                                                          child_pid,
                                                          child_tid);
                if (!is_recieved)
                    RING_VERDICT("The signal is not recieved in case of "
                                 "out-of-packet condition");
                if (!op_done)
                {
                    rc = 0;
                    while(rc >= 0)
                    {
                        RPC_AWAIT_IUT_ERROR(aux_thread[i]);
                        rc = rpc_recv(aux_thread[i], sock[i], aux_buf,
                                      AUX_BUF_LEN, RPC_MSG_DONTWAIT);
                    }
                }

                if (!is_recieved &&
                    !rpc_thrd_sighnd_crtfile_exists_unlink(pco_killer,
                                                          RPC_SIGUSR1,
                                                          child_pid,
                                                          child_tid))
                    RING_VERDICT("The signal is not recieved after "
                                 "unblocking out-of-packet condition");
                CHECK_RC(rcf_rpc_server_is_op_done(child[i], &op_done));
                if (op_done)
                {
                    (child[i])->op = RCF_RPC_WAIT;
                    rpc_sendto(child[i], sock[i], iut_buf, big_buf_len, 0,
                               tst_addr);
                }
                else
                    RING_VERDICT("sendto() is still hanging after"
                                 "unblocking out-of-packet condition");
            }
        }
        i++;
    }

    TEST_SUCCESS;

cleanup:
    SLEEP(1);
    i = 1;
    while(child[i] != NULL)
    {
        rcf_rpc_server_destroy(child[i]);
        i++;
    }
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_CHECK_RC(tapi_sh_env_unset(pco_iut, "EF_UDP_RCVBUF", TRUE,
                                       TRUE));
    free(iut_buf);
    free(tst_buf);

    TEST_END;
}
