/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reuseport
 *
 * $Id$
 */

/** @page reuseport-reuseport_load_tcp Connection requests distribution with SO_REUSEPORT
 *
 * @objective  Test connection requests distribution with SO_REUSEPORT
 *             option.
 *
 * @param pco_iut        PCO on IUT.
 * @param pco_tst        PCO on TST.
 * @param listeners_num  Listeners sockets number.
 * @param clients_num    Clients number to establish connection, @c 0 to
 *                       create connection until each listener has at least
 *                       one connection.
 * @param use_ef_force   Use env EF_UDP_FORCE_REUSEPORT to share port.
 * @param thread_process Create aux processes/threads or not.
 * 
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "reuseport/reuseport_load_tcp"

#include "sockapi-test.h"
#include "reuseport.h"

/** Packet size to transmit */
#define PACKET_SIZE 500

/** Connections limit */
#define MAX_CONNECTIONS_NUMBER 4000

/**
 * Socket context
 */
typedef struct socket_ctx {
    rcf_rpc_server *rpcs;  /**< RPC server */
    int sock;              /**< Socket */
    int idx;               /**< Stream index */
    te_bool accept;        /**< Does socket accept at least one
                                connection */
    te_bool skip;          /**< Don't accept connections */
} socket_ctx;

/** Listener sockets number */
static int listeners_num = 0;
/** Client sockets number */
static int clients_num;
/** Listeners sockets array */
static socket_ctx *listeners = NULL;
/** Number listener sockets which should not accept connections. */
static int skip = 0;

/** Established connections number */
static int streams_num_real = 0;
/** Array with accepted sockets */
static socket_ctx *accepted = NULL;
/** Array with tester sockets */
static socket_ctx *clients = NULL;

/**
 * Determine when stop create connections.
 * 
 * @param clients_num  Required clients number
 * @param iteration    Iteration number
 * 
 * @return @c FALSE if finish condition is achieved
 */
static te_bool
test_finish_reached(int clients_num, int iteration)
{
    int i;

    if (iteration == MAX_CONNECTIONS_NUMBER)
    {
        RING_VERDICT("Connections number limit %d was reached",
                     MAX_CONNECTIONS_NUMBER);
        return FALSE;
    }

    if (clients_num != 0)
    {
        if (iteration < clients_num)
            return TRUE;

        return FALSE;
    }

    if (iteration < listeners_num)
        return TRUE;

    for (i = 0; i < listeners_num; i++)
        if (!listeners[i].accept)
            return TRUE;

    return FALSE;
}

/**
 * Create listeners sockets.
 * 
 * @param pco_iut         IUT RPC server
 * @param iut_addr        IUT address
 * @param use_ef_force    Option EF_TCP_FORCE_REUSEPORT was set
 * @param thread_process  Create aux processes/threads or not
 */
static void
create_listeners(rcf_rpc_server *pco_iut, const struct sockaddr *iut_addr,
                 te_bool use_ef_force, thread_process_type thread_process)
{
    rcf_rpc_server **rpcs = NULL;
    int sock;
    int i;
    int backlog = 1;

    if (skip > 0)
        backlog = 0.8 * clients_num / listeners_num * 5;

    listeners = te_calloc_fill(listeners_num, sizeof(*listeners), 0);
    rpcs = te_calloc_fill(listeners_num, sizeof(*rpcs), 0);

    for (i = 0; i < listeners_num; i++)
    {
        init_aux_rpcs(pco_iut, &rpcs[i], thread_process);

        sockts_inc_rlimit(rpcs[i], RPC_RLIMIT_NOFILE,
                          MAX_CONNECTIONS_NUMBER + 500);
    }

    for (i = 0; i < listeners_num; i++)
    {
        listeners[i].rpcs = rpcs[rand_range(0, listeners_num - 1)]; 

        sock = rpc_socket(listeners[i].rpcs, rpc_socket_domain_by_addr(iut_addr),
                          RPC_SOCK_STREAM, RPC_PROTO_DEF);
        if (!use_ef_force)
            rpc_setsockopt_int(listeners[i].rpcs, sock, RPC_SO_REUSEPORT, 1);
        rpc_fcntl(listeners[i].rpcs, sock, RPC_F_SETFL, RPC_O_NONBLOCK);
        rpc_bind(listeners[i].rpcs, sock, iut_addr);
        rpc_listen(listeners[i].rpcs, sock, backlog);

        listeners[i].sock = sock;
        listeners[i].idx = i;
    }

    free(rpcs);
}

/**
 * Search listener socket which received connect request to accept
 * connection.
 * 
 * @param idx   Connection number
 * 
 * @return @c TRUE if connection was accepted
 */
static void
perform_accept(int idx)
{
    int sock;
    int i;
    int thrice;

    accepted[idx].rpcs = NULL;
    accepted[idx].sock = -1;
    accepted[idx].idx = -1;
    accepted[idx].skip = FALSE;

    for (thrice = 0; thrice < 3; thrice++)
    {
        if (thrice > 0)
            usleep(10000);
        for (i = 0; i < listeners_num; i++)
        {
            if (listeners[i].skip)
                continue;

            RPC_AWAIT_IUT_ERROR(listeners[i].rpcs);
            sock = rpc_accept(listeners[i].rpcs, listeners[i].sock, NULL, 0);
            if (sock < 0)
            {
                if (RPC_ERRNO(listeners[i].rpcs) == RPC_EAGAIN)
                    continue;
                TEST_FAIL("accept() failed with unexpected errno: %r",
                          RPC_ERRNO(listeners[i].rpcs));
            }

            accepted[idx].sock = sock;
            accepted[idx].idx = listeners[i].idx;
            accepted[idx].rpcs = listeners[i].rpcs;
            listeners[i].accept = TRUE;
            return;
        }
    }

    if (skip == 0 && sock < 0)
        TEST_VERDICT("Unaccepted connection request!");
    accepted[idx].skip = TRUE;
}

/**
 * Get next unused socket.
 * 
 * @param idx  Previous not used socket index
 * @param num  Sockets limit
 */
static int
get_next_empty_sock(int idx, int num)
{
    int i;

    for (i = idx; i <  num; i++)
    {
        if (accepted[i].sock == -1)
            return i;
    }

    TEST_VERDICT("Accepted sockets number overheads array size");
    return -1;
}

/**
 * Accept connections on the 'skipped' sockets.
 * 
 * @param  Sockets limit
 */
static void
accept_skipped(int streams_num)
{
    int sock;
    int i;
    int idx = 0;

    for (i = 0; i < listeners_num; i++)
    {
        if (!listeners[i].skip)
            continue;

        do {
            RPC_AWAIT_IUT_ERROR(listeners[i].rpcs);
            sock = rpc_accept(listeners[i].rpcs, listeners[i].sock, NULL, 0);
            if (sock < 0)
            {
                if (RPC_ERRNO(listeners[i].rpcs) == RPC_EAGAIN)
                    break;
                TEST_FAIL("accept() failed with unexpected errno: %r",
                          RPC_ERRNO(listeners[i].rpcs));
            }

            idx = get_next_empty_sock(idx, streams_num);
            accepted[idx].sock = sock;
            accepted[idx].idx = listeners[i].idx;
            accepted[idx].rpcs = listeners[i].rpcs;
            listeners[i].accept = TRUE;
        } while (TRUE);
    }
}

/**
 * Calculate and print statistics.
 */
static void
calc_stats(void)
{
    int skipped = 0;
    size_t buflen = streams_num_real * 20 + 40;
    char *buf = te_calloc_fill(buflen, 1, 0);
    int *cnt = te_calloc_fill(listeners_num, sizeof(*cnt), 0);
    size_t offt = 0;
    int res;
    int il;
    int ic;

    RING("Total connections number %d", streams_num_real);

    res = snprintf(buf, buflen, "Stream   Accepted sockets number\n");
    if (res < 0)
        TEST_FAIL("Failed write to buffer.");
    offt += res;

    for (il = 0; il < listeners_num; il++)
    {
        for (ic = 0; ic < streams_num_real; ic++)
            if (listeners[il].idx == accepted[ic].idx)
                cnt[il]++;

        if (cnt[il] == 0)
            skipped++;
        res = snprintf(buf + offt, buflen - offt, "%-8d %d%s\n", il + 1,
                       cnt[il], listeners[il].skip ? " (skipped)" : "");
        if (res < 0 || (size_t)res > buflen - offt)
            TEST_FAIL("Failed write to buffer.");
        offt += res;
    }

    RING("%s", buf);
    RING("Average connections number per listener socket: %d",
         streams_num_real / listeners_num);

    if (skipped > 0 )
        RING_VERDICT("%d/%d listener sockets do not accept connections",
                     skipped, listeners_num);

    free(cnt);
    free(buf);
}

/**
 * Establish TCP connections.
 * 
 * @param pco_tst       Tester RPC
 * @param clients_num   Required clients number or @c 0
 * @param iut_addr      IUT address
 */
static void
create_connections(rcf_rpc_server *pco_tst, int clients_num,
                   const struct sockaddr *iut_addr)
{
    int streams_num;
    int sock;
    int i;

    if (clients_num != 0)
        streams_num = clients_num;
    else
        streams_num = listeners_num;

    accepted = calloc(streams_num, sizeof(*accepted));
    clients = calloc(streams_num, sizeof(*clients));

    for (i = 0; test_finish_reached(clients_num, i); i++)
    {
        if (clients_num != 0 && clients_num == i)
            TEST_FAIL("Extra iteration");

        if (streams_num == i)
        {
            streams_num *= 2;
            accepted = realloc(accepted, streams_num * sizeof(*accepted));
            clients = realloc(clients, streams_num * sizeof(*clients));
        }

        sock = rpc_socket(pco_tst, rpc_socket_domain_by_addr(iut_addr),
                          RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_connect(pco_tst, sock, iut_addr);

        perform_accept(i);
        clients[i].sock = sock;
        clients[i].idx = listeners[i].idx;
        clients[i].rpcs = pco_tst;

        streams_num_real = i + 1;
    }

    accept_skipped(streams_num);

    calc_stats();
}

/**
 * Perform packets transmission across each created connection.
 */
static void
transmit_packets(void)
{
    char recvbuf[PACKET_SIZE] = {0,};
    char sendbuf[PACKET_SIZE];
    int  i;

    for (i = 0; i < streams_num_real; i++)
    {
        if (accepted[i].skip || accepted[i].rpcs == NULL)
            continue;

        memset(sendbuf, 0xFF - i, PACKET_SIZE);
        if (rpc_send(clients[i].rpcs, clients[i].sock, sendbuf, PACKET_SIZE,
                     0) != PACKET_SIZE)
            TEST_FAIL("Client passed a part of packet");
        memset(recvbuf, 0, PACKET_SIZE);
        if (rpc_recv(accepted[i].rpcs, accepted[i].sock, recvbuf,
                     PACKET_SIZE, 0) != PACKET_SIZE)
            TEST_FAIL("Server received a part of packet");
        if (memcmp(sendbuf, recvbuf, PACKET_SIZE) != 0)
            TEST_FAIL("Received data differs from sent");
    }
}

/**
 * Close all opened sockets and destroy aux threads/processes.
 * 
 * @param thread_process    Determines are there aux threads or processes
 */
static void
close_sockets(void)
{
    int result;
    int i;
    UNUSED(result);

    if (listeners == NULL)
        return;

    for (i = 0; i < listeners_num; i++)
        RPC_CLOSE(listeners[i].rpcs, listeners[i].sock);

    if (clients == NULL || accepted == NULL)
        return;

    for (i = 0; i < streams_num_real; i++)
    {
        CLEANUP_RPC_CLOSE(clients[i].rpcs, clients[i].sock);
        CLEANUP_RPC_CLOSE(accepted[i].rpcs, accepted[i].sock);
    }
}

/**
 * Chose listener sockets to skip accepting connections in the main loop.
 * 
 * @param skip  Number of the skipped sockets
 */
static void
set_skiping_sockets(int skip)
{
    int i;
    int num;

    if (listeners_num <= skip)
        TEST_FAIL("Listeners number %d must not be less skip number %d",
                  listeners_num, skip);

    for (i = 0; i < skip; i++)
    {
        do {
            num = rand_range(0, listeners_num - 1);
            if (!listeners[num].skip)
            {
                listeners[num].skip = TRUE;
                break;
            }
        } while (1);
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_tst = NULL;
    rcf_rpc_server *pco_iut = NULL;
    const struct sockaddr *iut_addr = NULL;
    thread_process_type thread_process;
    te_bool             use_ef_force;
    int                 init_cluster_sz;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_INT_PARAM(listeners_num);
    TEST_GET_INT_PARAM(skip);
    TEST_GET_INT_PARAM(clients_num);
    TEST_GET_BOOL_PARAM(use_ef_force);
    TEST_GET_ENUM_PARAM(thread_process, THREAD_PROCESS);

    if (use_ef_force)
        CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_TCP_FORCE_REUSEPORT",
                       ntohs(te_sockaddr_get_port(iut_addr)), TRUE, FALSE));
    CHECK_RC(tapi_sh_env_save_set_int(pco_iut, "EF_CLUSTER_SIZE", listeners_num,
                                      TRUE, NULL, &init_cluster_sz));

    sockts_inc_rlimit(pco_tst, RPC_RLIMIT_NOFILE,
                      MAX_CONNECTIONS_NUMBER + 500);

    TEST_STEP("Create number @p listeners_num non blocking sockets and move them to "
              "listen state. All sockets are bound to the same address:port with "
              "SO_REUSEPORT option.");
    create_listeners(pco_iut, iut_addr, use_ef_force, thread_process);

    set_skiping_sockets(skip);

    TEST_STEP("Create client sockets on tester and call connect() to establish "
              "connections with IUT. If number @p clients_num > 0 than "
              "this number of connections sould be created. If it is @c 0 than "
              "connections will be created until each IUT listener takes at least "
              "one connection. IUT side calls accept() for each connect request.");
    create_connections(pco_tst, clients_num, iut_addr);

    TEST_STEP("Transmit packet via each established connection.");
    transmit_packets();

    TEST_SUCCESS;

cleanup:
    close_sockets();
    free(listeners);
    free(accepted);
    free(clients);

    CLEANUP_CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_CLUSTER_SIZE",
                                         init_cluster_sz, TRUE, TRUE));

    TEST_END;
}
