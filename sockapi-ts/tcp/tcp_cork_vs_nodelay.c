/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Tests
 * This test package contains tests for special cases of TCP protocol, such
 * as ICMP and routing table handling, small and zero window, fragmentation
 * of TCP packets, etc.
 */

/**
 * @page tcp-tcp_cork_vs_nodelay Combined using of options TCP_NODELAY and TCP_CORK
 *
 * @objective Send data when various combinations of options TCP_NODELAY and
 *            TCP_CORK are used, check that both options can be used to
 *            trigger data transmission.
 *
 * @param sock_type          Connection establishment way:
 *      - active
 *      - passive close
 * @param send_data_before   Send some data in both directions before the
 *                           main loop.
 * @param nonblock           Use non-blocking socket mode to send data.
 * @param tcp_nodelay_before Enable @c TCP_NODELAY before setting @c TCP_CORK.
 * @param send_nodelay       Trigger send using TCP_NODELAY or TCP_CORK.
 * @param send_usleep        Sleep between send calls, microseconds:
 *      - @c -1 (don't sleep)
 *      - @c 3000
 * @param size_min           Minimum data amount to send by one call:
 *      - @c 1
 * @param size_max           Maximum data amount to send by one call:
 *      - @c 2000
 * @param packets_num        How many packets should be sent by one iteration:
 *      - @c 1
 *      - @c 3
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME "tcp/tcp_cork_vs_nodelay"

#include "sockapi-test.h"
#include "tapi_route_gw.h"
#include "tapi_proc.h"

/* The main loop iterations number. */
#define TEST_ITERATIONS_NUM 30

/* Maximum acceptable delay for data reading, microseconds. */
#define READ_DELAY_MAX 50000

int
main(int argc, char *argv[])
{
    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *tst_if = NULL;
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;
    sockts_socket_type      sock_type;
    te_bool                 send_data_before;
    te_bool                 nonblock;
    te_bool                 tcp_nodelay_before;
    te_bool                 send_nodelay;
    int                     send_usleep;
    int                     size_min;
    int                     size_max;
    int                     packets_num;

    int                       i;
    uint64_t                  send_len;
    uint64_t                  duration = 0;
    te_bool                   bad_duration_reported = FALSE;

    int                       iut_s = -1;
    int                       tst_s = -1;
    struct sockaddr_storage   iut_addr_aux;
    struct sockaddr_storage   tst_addr_aux;
    int                       iut_s_aux = -1;
    int                       tst_s_aux = -1;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(send_data_before);
    TEST_GET_BOOL_PARAM(nonblock);
    TEST_GET_BOOL_PARAM(tcp_nodelay_before);
    TEST_GET_BOOL_PARAM(send_nodelay);
    TEST_GET_INT_PARAM(send_usleep);
    TEST_GET_INT_PARAM(size_min);
    TEST_GET_INT_PARAM(size_max);
    TEST_GET_INT_PARAM(packets_num);

    CHECK_RC(tapi_sockaddr_clone(pco_iut, iut_addr,
                                 &iut_addr_aux));
    CHECK_RC(tapi_sockaddr_clone(pco_tst, tst_addr,
                                 &tst_addr_aux));

    sockts_connection(pco_iut, pco_tst,
                      SA(&iut_addr_aux), SA(&tst_addr_aux),
                      SOCKTS_SOCK_UDP, FALSE, FALSE, NULL,
                      &iut_s_aux, &tst_s_aux, NULL,
                      SOCKTS_SOCK_FUNC_SOCKET);

    TEST_STEP("Establish TCP connection keeping in the mind @p sock_type.");
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr, sock_type,
                      &iut_s, &tst_s, NULL);

    TEST_STEP("Set IUT socket to non-blocking mode if @p nonblock is @c TRUE.");
    if (nonblock)
        rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, RPC_O_NONBLOCK);

    TEST_STEP("If @p tcp_nodelay_before is @c TRUE");
    TEST_SUBSTEP("setsockopt(TCP_NODELAY, 1).");
    if (tcp_nodelay_before)
        rpc_setsockopt_int(pco_iut, iut_s, RPC_TCP_NODELAY, 1);

    TEST_STEP("Send a data packet in both directions if @p send_data_before "
              "is @c TRUE");
    if (send_data_before)
        sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);

    TEST_STEP("setsockopt(TCP_CORK, 1).");
    rpc_setsockopt_int(pco_iut, iut_s, RPC_TCP_CORK, 1);

    TEST_STEP("In a loop @c 30 times");
    for (i = 0; i < TEST_ITERATIONS_NUM; i++)
    {
        send_len = rand_range(size_min * packets_num,
                              size_max * packets_num);

        pco_tst->op = RCF_RPC_CALL;
        rpc_recv_timing(pco_tst, tst_s, tst_s_aux, send_len, &duration);

        TEST_SUBSTEP("On the IUT side, call the RPC function which does: "
                     "-# in a loop number @p packets_num times: "
                     "-# send(size = random [ @p size_min; @p size_max ]); "
                     "-# usleep(@p send_usleep); "
                     "-# setsockopt(TCP_NODELAY, 1) or setsockopt(TCP_CORK, 0) in "
                     "dependence on @p send_nodelay.");
        rpc_many_send_cork(pco_iut, iut_s, iut_s_aux, size_min, size_max,
                           packets_num, send_len, send_usleep,
                           send_nodelay, FALSE);

        TEST_SUBSTEP("With help of rpc_recv_timing() receive data on Tester, "
                     "measuring time it took to receive it. Check that expected "
                     "number of bytes was received.");
        RPC_AWAIT_ERROR(pco_tst);
        rc = rpc_recv_timing(pco_tst, tst_s, tst_s_aux,
                             send_len, &duration);
        if (rc < 0)
            TEST_VERDICT("rpc_recv_timing() failed with errno %r",
                         RPC_ERRNO(pco_tst));
        else if (rc != (int)send_len)
            TEST_VERDICT("rpc_recv_timing() returned unexpected value");

        RING("Total call durations: tester read %" TE_PRINTF_64
             "u, IUT send %" TE_PRINTF_64 "u",
             duration, pco_iut->duration);

        TEST_SUBSTEP("Check that it took no more that @c READ_DELAY_MAX microseconds "
                     "to receive data than it took to send it.");
        if (duration > pco_iut->duration + READ_DELAY_MAX)
        {
            if (!bad_duration_reported)
            {
                RING_VERDICT("Read call was delayed for too long time");
                bad_duration_reported = TRUE;
            }
            else
            {
                ERROR("Read call was delayed for too long time");
            }
        }

        TEST_SUBSTEP("If @p send_nodelay is @c FALSE "
                     "-# setsockopt(TCP_CORK, 1).");
        if (!send_nodelay)
            rpc_setsockopt_int(pco_iut, iut_s, RPC_TCP_CORK, 1);
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_aux);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s_aux);

    TEST_END;
}
