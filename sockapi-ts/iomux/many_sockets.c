/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Siute
 * Reliability Socket API in Normal Use
 *
 * $Id:
 */

/** @page iomux-many_sockets The iomux functionality for large number of sockets from different processes
 *
 * @objective Test the iomux functionality for large number of sockets from different processes
 *
 * @type use case
 *
 * @param iomux                         iomux function for testing
 * @param sockets_number                number of sockets
 * @param fork_or_exec_calls_number     number of @b fork() or exec() calls
 * @param sock_type                     RPC_SOCK_STREAM or RPC_SOCK_DGRAM
 * @param use_exec                      TRUE or FALSE
 * @param socket_to_test                which socket ("first" - the first one,
 *                                          "last" - the last one, "middle" -
 *                                           the (int) (sockets_number / 2))th
 *                                           one) must be tested.
 *
 * @par Scenario:
 *
 * -# Create @p tst_socket on the @p pco_tst.
 * -# Create array @a sks of @p sockets_number sockets on the @p IUT side.
 *    Call @b fork() (or @b exec() if use_exec == TRUE) @p
 *    fork_or_exec_calls_number times during the process of socket's
 *    creation, process of creation goes on only in new process every time
 *    @b fork()/exec() is called.
 * -# Call @b bind() for each socket in array after creation of this socket.
 * -# If TCP is used, call @b listen() just after @b bind() during process
 *    of array's creation.
 * -# After creation of array, call @b iomux() with iomux set including all
 *    the sockets in the array.
 * -# If TCP is used, connect @p tst_socket to socket tested and check
 *    whether iomux() returns with EVT_RD for the last one. Then @b accept()
 *    on the socket tested and call @b iomux() again for the same set of
 *    sockets plus accepted one to ensure that accepted socket is writable.
 *    Call @b rpc_overfill_buffers() for accepted socket and call @b iomux()
 *    again with iomux set including all the sockets in array and accepted
 *    one. Read data from @p tst_socket and check whether @b iomux()
 *    returns with EVT_WR for accepted socket.
 * -# If UDP is used, send some data through @p tst_socket. Check if @b
 *    iomux() returns with EVT_RD for the socket tested. Then call @b
 *    iomux() again for the same set of sockets and check whether it
 *    returns with EVT_WR for all the sockets in array.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "iomux/many_sockets"

#include "sockapi-test.h"
#include "iomux.h"

#define MAX_SOCKETS_COUNT 1000
#define MAX_SOCK_ERR_STR_LEN MAX_SOCKETS_COUNT * 7
#define RECEIVED_DATA_SIZE 32000
#define SENT_DATA_SIZE 256
#define MAX_NAME_LEN 100

/**
 * Call iomux with RCF_RPC_CALL and check rc.
 *
 * @param iomux         iomux function to call
 * @param pco_iomux     RPC server handle
 * @param events        Array of event request records
 * @param count         Length of @a events
 * @param timeout       Timeout of operation, may be NULL
 */
#define CHECK_IOMUX_CALL(iomux, pco_iomux, events, count, timeout) \
    do {                                                           \
        pco_iomux->op = RCF_RPC_CALL;                              \
        rc = iomux_call(iomux, pco_iomux, events, count, timeout); \
        if (rc < 0)                                                \
            TEST_FAIL("iomux_call of %s failed.",                  \
                      iomux_call_en2str(iomux));                   \
    } while (0)

/**
 * Call iomux with RCF_RPC_WAIT and check rc and state of socket tested.
 *
 * @param iomux         iomux function to call
 * @param pco_iomux     RPC server handle
 * @param events        Array of event request records
 * @param count         Length of @a events
 * @param index_to_test Index of element in @a events to be checked
 * @param timeout       Timeout of operation, may be NULL
 * @param event         event to be checked
 * @param msg           Message printed by TEST_FAIL if event is not
 *                          occured for socket to be tested.
 */
#define CHECK_IOMUX_WAIT(iomux, pco_iomux, events, count, index_to_test, \
                         timeout, event, msg...)                         \
    do {                                                                 \
        pco_iomux->op = RCF_RPC_WAIT;                                    \
        rc = iomux_call(iomux, pco_iomux, events,                        \
                        count, NULL);                                    \
        if (rc < 0)                                                      \
            TEST_FAIL("iomux_call of %s failed.",                        \
                      iomux_call_en2str(iomux));                         \
        if (!(events[index_to_test].revents & event))                    \
            TEST_VERDICT(msg);                                           \
    } while (0)

#define CHECK_ALL_WRITTABLE(iomux, pco_iomux, events, count, msg...) \
    do {                                                             \
        int k;                                                       \
        int err_detected = 0;                                        \
        char err_string[MAX_SOCK_ERR_STR_LEN];                       \
        int err_str_len = 0;                                         \
        CHECK_IOMUX_CALL(iomux, pco_iomux, events, count, NULL);     \
        pco_iomux->op = RCF_RPC_WAIT;                                \
        rc = iomux_call(iomux, pco_iomux, events,                    \
                        count, NULL);                                \
        if (rc < 0)                                                  \
            TEST_FAIL("iomux_call of %s failed.",                    \
                      iomux_call_en2str(iomux));                     \
        memset(err_string, 0, MAX_SOCK_ERR_STR_LEN);                 \
        for (k = 0; k < count; k++)                                  \
        {                                                            \
            if (!(events[k].revents & EVT_WR))                       \
            {                                                        \
                if (err_detected == 0)                               \
                {                                                    \
                    RING("Some sockets are not writable: ");         \
                }                                                    \
                err_detected = 1;                                    \
                err_str_len += snprintf(err_string + err_str_len,    \
                                        MAX_SOCK_ERR_STR_LEN -       \
                                        err_str_len, "%d ",          \
                                        events[k].fd);               \
            }                                                        \
        }                                                            \
        if (err_detected == 1)                                       \
        {                                                            \
            RING("%s.", err_string);                                 \
            TEST_VERDICT(msg);                                       \
        }                                                            \
    } while (0)

int
main (int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *all_proc[MAX_SOCKETS_COUNT];
    rcf_rpc_server         *pco_iomux = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    iomux_call_type         iomux = IC_UNKNOWN;
    iomux_evt_fd            events[MAX_SOCKETS_COUNT + 1];
    int                     sockets_number;
    int                     fork_or_exec_calls_number = 0;
    const char             *socket_to_test = NULL;
    te_bool                 use_exec = FALSE;
    int                     tst_socket = -1;
    int                     iut_accepted_socket = -1;
    int                     sks[MAX_SOCKETS_COUNT] = {-1, };
    int                     stack_interval;
    int                     next_stack_point;
    int                     i;
    int                     last_proc_number;
    int                     iut_socket_to_test = 0;
    char                    chld_name[MAX_NAME_LEN];
    char                    data[RECEIVED_DATA_SIZE];
    uint64_t                total_filled;
    rpc_socket_type         sock_type;
    int                     first_stack_point;
    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;
    struct sockaddr         iut_sockets_addr;

    te_bool use_wildcard = FALSE;
    struct sockaddr_storage wildcard_addr;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_INT_PARAM(sockets_number);
    TEST_GET_INT_PARAM(fork_or_exec_calls_number);
    TEST_GET_STRING_PARAM(socket_to_test);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(use_exec);
    TEST_GET_BOOL_PARAM(use_wildcard);

    if (fork_or_exec_calls_number > MAX_SOCKETS_COUNT - 1)
        TEST_FAIL("Too many stacks are requested.");

    if (sockets_number > MAX_SOCKETS_COUNT)
        TEST_FAIL("Too many sockets are requested.");

    if (strcmp(socket_to_test, "first") == 0)
        iut_socket_to_test = 0;
    else if (strcmp(socket_to_test, "middle") == 0)
        iut_socket_to_test = sockets_number / 2;
    else if (strcmp(socket_to_test, "last") == 0)
        iut_socket_to_test = sockets_number - 1;
    else
        TEST_FAIL("Unknown value of socket_to_test parameter.");

    stack_interval = sockets_number / (fork_or_exec_calls_number + 1);
    next_stack_point = stack_interval + sockets_number %
                       (fork_or_exec_calls_number + 1);
    first_stack_point = next_stack_point;
    all_proc[0] = pco_iut;
    last_proc_number = 0;

    tst_socket = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                            sock_type, RPC_PROTO_DEF);

    for (i = 0; i < sockets_number; i++)
    {
        sks[i] = rpc_socket(all_proc[last_proc_number],
                            rpc_socket_domain_by_addr(iut_addr),
                            sock_type, RPC_PROTO_DEF);

        if (i == iut_socket_to_test)
        {
            assert(sizeof(wildcard_addr) >= te_sockaddr_get_size(iut_addr));
            memcpy(&wildcard_addr, iut_addr,
                   te_sockaddr_get_size(iut_addr));
            te_sockaddr_set_wildcard(SA(&wildcard_addr));
            rpc_bind(all_proc[last_proc_number], sks[iut_socket_to_test],
                     use_wildcard ? SA(&wildcard_addr) : iut_addr);

            if (sock_type == RPC_SOCK_STREAM)
                rpc_listen(all_proc[last_proc_number],
                           sks[iut_socket_to_test], SOCKTS_BACKLOG_DEF);
        }
        else
        {
            memset(&iut_sockets_addr, 0, sizeof(struct sockaddr));
            iut_sockets_addr.sa_family = iut_addr->sa_family;
            rpc_bind(all_proc[last_proc_number], sks[i], &iut_sockets_addr);

            if (sock_type == RPC_SOCK_STREAM)
                rpc_listen(all_proc[last_proc_number], sks[i],
                           SOCKTS_BACKLOG_DEF);
        }

        events[i].fd = sks[i];
        events[i].events = EVT_RD | EVT_EXC;

        if (i >= next_stack_point)
        {
            snprintf(chld_name, MAX_NAME_LEN, "child_%d",
                     last_proc_number + 1);

            if (!use_exec)
            {
                rcf_rpc_server_fork(all_proc[last_proc_number], chld_name,
                                    all_proc + last_proc_number + 1);
                last_proc_number++;
            }
            else
                rcf_rpc_server_exec(all_proc[last_proc_number]);

            next_stack_point += stack_interval;
        }
    }

    pco_iomux = all_proc[last_proc_number];

    if (sock_type == RPC_SOCK_STREAM)
    {
        CHECK_IOMUX_CALL(iomux, pco_iomux, events, sockets_number, NULL);
        rpc_connect(pco_tst, tst_socket, iut_addr);
        CHECK_IOMUX_WAIT(iomux, pco_iomux, events, sockets_number,
                         iut_socket_to_test, NULL, EVT_RD,
                         "Incorrect event on socket tested");

        iut_accepted_socket = rpc_accept(pco_iomux,
                                         sks[iut_socket_to_test],
                                         NULL, NULL);
        events[sockets_number].fd = iut_accepted_socket;
        events[sockets_number].events = EVT_RDWR | EVT_EXC;
        CHECK_IOMUX_CALL(iomux, pco_iomux, events, sockets_number + 1, NULL);
        CHECK_IOMUX_WAIT(iomux, pco_iomux, events, sockets_number + 1,
                         sockets_number, NULL, EVT_WR,
                         "Incorrect event on socket tested");

        rpc_overfill_buffers_gen(pco_iomux, iut_accepted_socket,
                                 &total_filled,
                                 iomux == IC_OO_EPOLL ? IC_EPOLL : iomux);

        CHECK_IOMUX_CALL(iomux, pco_iomux, events, sockets_number + 1, NULL);

        while (1)
        {
            RPC_AWAIT_IUT_ERROR(pco_tst);
            rc = rpc_recv(pco_tst, tst_socket, data, RECEIVED_DATA_SIZE,
                          RPC_MSG_DONTWAIT);

            if (rc <= 0)
                break;
        }

        CHECK_IOMUX_WAIT(iomux, pco_iomux, events, sockets_number + 1,
                         sockets_number, NULL, EVT_WR, "Socket isn't "
                         "writable after data is read from overfilled "
                         "buffer.");

        events[sockets_number].fd = iut_accepted_socket;
        events[sockets_number].events = EVT_RD | EVT_EXC;

        for (i = 0; i < sockets_number; i++)
        {
            events[i].events = EVT_RD | EVT_EXC;
        }

        CHECK_IOMUX_CALL(iomux, pco_iomux, events, sockets_number + 1, NULL);
        rpc_send(pco_tst, tst_socket, data, SENT_DATA_SIZE, 0);
        CHECK_IOMUX_WAIT(iomux, pco_iomux, events, sockets_number + 1,
                         sockets_number, NULL, EVT_RD, "Socket isn't "
                         "readable after data is sent from pco_tst.");
    }
    else
    {
        CHECK_IOMUX_CALL(iomux, pco_iomux, events, sockets_number, NULL);
        rpc_sendto(pco_tst, tst_socket, data, SENT_DATA_SIZE, 0,
                   iut_addr);
        CHECK_IOMUX_WAIT(iomux, pco_iomux, events, sockets_number,
                         iut_socket_to_test, NULL, EVT_RD,
                         "Socket isn't readable after data is sent "
                         "from pco_tst.");

        for (i = 0; i < sockets_number; i++)
        {
            events[i].events = EVT_WR | EVT_EXC;
        }

        CHECK_ALL_WRITTABLE(iomux, pco_iomux, events, sockets_number,
                            "Not all sockets are marked as writable "
                            "by iomux() call");
    }

    TEST_SUCCESS;

cleanup:

    /*
     * Destroy children processes in reverse order.
     */

    for (i = last_proc_number; i > 0; i--)
    {
        rcf_rpc_server_destroy(all_proc[i]);
    }

    /*
     * Close all the sockets created in main rpc server.
     */

    for (i = 0; i <= first_stack_point; i++)
    {
        rpc_close(all_proc[0], sks[i]);
    }

    if (iut_accepted_socket != -1 && pco_iut == pco_iomux)
        rpc_close(pco_iut, iut_accepted_socket);

    rpc_close(pco_tst, tst_socket);

    rcf_rpc_server_restart(all_proc[0]);

    TEST_END;
}
