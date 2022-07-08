/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Reuseport
 */

/** @page reuseport-reuseport_del_addr Removing bind address of sockets with SO_REUSEPORT
 *
 * @objective Check what happens when network address is removed
 *            while sockets with SO_REUSEPORT set are bound to it.
 *
 * @type use case
 *
 * @param sock_type       Socket type (@c SOCK_STREAM or @c SOCK_DGRAM).
 * @param set_reuseport   Whether to set @c SO_REUSEPORT.
 * @param single_process  If @c TRUE, both sockets bound to a tested
 *                        network address should be created in the same
 *                        process; otherwise create them in different
 *                        processes.
 * @param remove_addr     Which of three network addresses should be
 *                        removed (@c 1, @c 2 or @c 3).
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "reuseport/reuseport_del_addr"

#include "sockapi-test.h"
#include "reuseport.h"

/** Number of network addresses to be added. */
#define ADDRS_NUM 3

/** Number of sockets per tested address. */
#define SOCKS_PER_ADDR 2

/** Packet length to be used in testing. */
#define PKT_LEN 1024

/**
 * How long to wait until network operation is completed,
 * milliseconds.
 */
#define NETWORK_TIMEOUT 500

/**
 * How long to wait until TCP connection is established,
 * in case of testing with SO_REUSEPORT set,
 * milliseconds.
 */
#define REUSEPORT_CONN_TIMEOUT 2000

/** Listen backlog value used in this test. */
#define LISTEN_BACKLOG 10

/** IP network where addresses should be allocated. */
tapi_env_net              *net = NULL;
/** Network interface on Tester. */
const struct if_nameindex *tst_if = NULL;
/** Network interface on IUT. */
const struct if_nameindex *iut_if = NULL;

/**
 * Maximum number of addresses to allocate on Tester.
 */
#define MAX_TST_ADDRS 30

/** Configuration handles for addresses added on Tester. */
static cfg_handle   tst_addr_handles[MAX_TST_ADDRS];
/** Total number of addresses added on Tester. */
static int          tst_addrs_num = 0;

/** Testing results for a pair of TCP sockets. */
typedef struct sock_pair_results_tcp {
    te_bool first_connect;    /**< Was connect to the first
                                   listener successful? */
    te_bool second_connect;   /**< Was connect to the second
                                   listener successful? */
    te_bool first_transmit;   /**< Was data transmit over
                                   the first connection
                                   successful? */
    te_bool second_transmit;  /**< Was data transmit over
                                   the second connection
                                   successful? */
} sock_pair_results_tcp;

/** Testing results for a pair of UDP sockets. */
typedef struct sock_pair_results_udp {
    te_bool first_receive;    /**< Was data received on
                                   the first socket? */
    te_bool second_receive;   /**< Was data received on
                                   the second socket? */
    te_bool first_send;       /**< Was data sent from the
                                   first socket? */
    te_bool second_send;      /**< Was data sent from the
                                   second socket? */
} sock_pair_results_udp;

/** Testing results for a pair of sockets. */
typedef struct sock_pair_results {
    rpc_socket_type         sock_type;  /**< Socket type. */
    union {
        sock_pair_results_tcp   tcp;    /**< Results in case of TCP. */
        sock_pair_results_udp   udp;    /**< Results in case of UDP. */
    } u; /**< Union with results specific to socket type. */
} sock_pair_results;

/**
 * Check whether all results are passed.
 *
 * @param results   Testing results.
 *
 * @return TRUE if all results are passed, FALSE otherwise.
 */
static te_bool
results_all_passed(sock_pair_results *results)
{
    if (results->sock_type == RPC_SOCK_DGRAM)
    {
        return (results->u.udp.first_receive &&
                results->u.udp.second_receive &&
                results->u.udp.first_send &&
                results->u.udp.second_send);
    }
    else
    {
        return (results->u.tcp.first_connect &&
                results->u.tcp.second_connect &&
                results->u.tcp.first_transmit &&
                results->u.tcp.second_transmit);
    }
}

/**
 * Check whether all results are failed.
 *
 * @param results   Testing results.
 *
 * @return TRUE if all results are failed, FALSE otherwise.
 */
static te_bool
results_all_failed(sock_pair_results *results)
{
    if (results->sock_type == RPC_SOCK_DGRAM)
    {
        return !(results->u.udp.first_receive ||
                 results->u.udp.second_receive ||
                 results->u.udp.first_send ||
                 results->u.udp.second_send);
    }
    else
    {
        return !(results->u.tcp.first_connect ||
                 results->u.tcp.second_connect ||
                 results->u.tcp.first_transmit ||
                 results->u.tcp.second_transmit);
    }
}

/**
 * Get string representation of testing results.
 *
 * @param results     Testing results.
 * @param str         Where to save string representation.
 */
static void
sock_pair_results2str(sock_pair_results *results,
                      te_string *str)
{
#define RES2STR(val_) \
    (val_ ? "pass" : "fail")

    te_string_reset(str);

    if (results->sock_type == RPC_SOCK_DGRAM)
        te_string_append(
             str,
             "first_recv:%s second_recv:%s "
             "first_send:%s second_send:%s",
             RES2STR(results->u.udp.first_receive),
             RES2STR(results->u.udp.second_receive),
             RES2STR(results->u.udp.first_send),
             RES2STR(results->u.udp.second_send));
    else
        te_string_append(
             str,
             "first_connect:%s second_connect:%s "
             "first_transmit:%s second_transmit:%s",
             RES2STR(results->u.tcp.first_connect),
             RES2STR(results->u.tcp.second_connect),
             RES2STR(results->u.tcp.first_transmit),
             RES2STR(results->u.tcp.second_transmit));
}

/**
 * Initialize testing results.
 *
 * @param results     Testing results.
 * @param sock_type   Socket type.
 */
static void
sock_pair_results_init(sock_pair_results *results,
                       rpc_socket_type sock_type)
{
    results->sock_type = sock_type;

    if (sock_type == RPC_SOCK_DGRAM)
    {
        results->u.udp.first_receive = FALSE;
        results->u.udp.second_receive = FALSE;
        results->u.udp.first_send = FALSE;
        results->u.udp.second_send = FALSE;
    }
    else
    {
        results->u.tcp.first_connect = FALSE;
        results->u.tcp.second_connect = FALSE;
        results->u.tcp.first_transmit = FALSE;
        results->u.tcp.second_transmit = FALSE;
    }
}

/**
 * Create a socket on IUT.
 *
 * @param s               Socket context.
 * @param sock_type       Socket type.
 * @param set_reuseport   Whether to set SO_REUSEPORT.
 * @param bind_wildcard   Whether to bind to wildcard address.
 */
static void
sock_pair_create_sock(reuseport_socket_ctx *s,
                      rpc_socket_type sock_type,
                      te_bool set_reuseport,
                      te_bool bind_wildcard)
{
    struct sockaddr_storage iut_bind_addr;

    tapi_sockaddr_clone_exact(s->iut_addr, &iut_bind_addr);
    if (bind_wildcard)
        te_sockaddr_set_wildcard(SA(&iut_bind_addr));

    s->iut_acc = -1;
    s->iut_s = reuseport_create_bind_socket(s->pco_iut, sock_type,
                                            SA(&iut_bind_addr),
                                            set_reuseport);

    if (sock_type == RPC_SOCK_DGRAM)
    {
        CHECK_RC(tapi_allocate_set_port(s->pco_tst, s->tst_addr));
        s->tst_s = rpc_create_and_bind_socket(s->pco_tst, RPC_SOCK_DGRAM,
                                              RPC_PROTO_DEF, FALSE, FALSE,
                                              s->tst_addr);
    }
    else
    {
        s->tst_s = -1;
        rpc_listen(s->pco_iut, s->iut_s, LISTEN_BACKLOG);
    }
}

/**
 * Check that a packet can be sent from a socket and
 * received on its peer.
 *
 * @param rpcs1     Source RPC server.
 * @param s1        Source socket.
 * @param rpcs2     Destination RPC server.
 * @param s2        Destination socket.
 * @param s2_addr   Destination address.
 *
 * @return 0 on success, negative value on failure.
 */
static int
check_transmit_one_way(rcf_rpc_server *rpcs1,
                       int s1,
                       rcf_rpc_server *rpcs2,
                       int s2,
                       const struct sockaddr *s2_addr)
{
    char snd_buf[PKT_LEN];
    char rcv_buf[PKT_LEN];

    te_bool readable;

    int rc;

    te_fill_buf(snd_buf, PKT_LEN);

    RPC_AWAIT_ERROR(rpcs1);
    rc = rpc_sendto(rpcs1, s1, snd_buf, PKT_LEN, 0, s2_addr);
    if (rc != PKT_LEN)
    {
        ERROR("Failed to send expected data");
        return -1;
    }

    RPC_GET_READABILITY(readable, rpcs2, s2, NETWORK_TIMEOUT);
    if (!readable)
    {
        ERROR("Failed to wait for expected data");
        return -1;
    }

    RPC_AWAIT_ERROR(rpcs2);
    rc = rpc_recv(rpcs2, s2, rcv_buf, PKT_LEN, 0);
    if (rc != PKT_LEN)
    {
        ERROR("Failed to receive expected data");
        return -1;
    }

    if (memcmp(snd_buf, rcv_buf, PKT_LEN) != 0)
        TEST_FAIL("Received data does not match sent data");

    return 0;
}

/**
 * Check that data can be transmitted between a TCP socket and its peer
 * in both directions.
 *
 * @param s   Socket context.
 *
 * @return 0 on success, or a negative value in case of failure.
 */
static int
check_transmit_tcp(reuseport_socket_ctx *s)
{
    int rc;

    rc = check_transmit_one_way(s->pco_iut, s->iut_acc,
                                s->pco_tst, s->tst_s, NULL);
    if (rc < 0)
        return rc;

    return check_transmit_one_way(s->pco_tst, s->tst_s,
                                  s->pco_iut, s->iut_acc, NULL);
}

/**
 * Receive data sent to two UDP sockets bound to the same address
 * and port with SO_REUSEPORT.
 *
 * @param s1              Context of the first socket in socket pair.
 * @param s2              Context of the second socket in socket pair.
 * @param buf             Buffer where to save received data.
 * @param len             Length of buffer.
 * @param first_received  On success will be set to TRUE if the first socket
 *                        received data, and to FALSE otherwise.
 *
 * @return Number of bytes received on success, negative value
 *         on failure.
 */
static int
udp_recv_data_reuseport(reuseport_socket_ctx *s1,
                        reuseport_socket_ctx *s2,
                        char *buf,
                        size_t len,
                        te_bool *first_received)
{
    struct timeval tv_start;
    struct timeval tv_cur;

    te_bool readable;

    CHECK_RC(gettimeofday(&tv_start, NULL));

    while (TRUE)
    {
        s1->pco_iut->silent = TRUE;
        RPC_GET_READABILITY(readable, s1->pco_iut, s1->iut_s, 0);
        if (readable)
        {
            *first_received = TRUE;
            return rpc_recv(s1->pco_iut, s1->iut_s, buf, len, 0);
        }

        s2->pco_iut->silent = TRUE;
        RPC_GET_READABILITY(readable, s2->pco_iut, s2->iut_s, 0);
        if (readable)
        {
            *first_received = FALSE;
            return rpc_recv(s2->pco_iut, s2->iut_s, buf, len, 0);
        }

        CHECK_RC(gettimeofday(&tv_cur, NULL));
        if (TIMEVAL_SUB(tv_cur, tv_start) > TE_MS2US(NETWORK_TIMEOUT))
            return -TE_RC(TE_TAPI, TE_ETIMEDOUT);
    }

    return -1;
}

/**
 * Check that UDP socket bound with SO_REUSEPORT
 * can receive data from peer.
 *
 * @param s1            Context of the first socket in pair.
 * @param s2            Context of the second socket in pair.
 * @param check_first   Check that the first socket can receive
 *                      data if TRUE, check the second socket
 *                      otherwise.
 *
 * @return 0 on success, negative value on failure.
 */
static int
check_udp_recv_reuseport(reuseport_socket_ctx *s1,
                         reuseport_socket_ctx *s2,
                         te_bool check_first)
{
    reuseport_socket_ctx *s;
    te_bool               first_received;

    char snd_buf[PKT_LEN];
    char rcv_buf[PKT_LEN];
    int  rc;

    if (check_first)
        s = s1;
    else
        s = s2;

    do {
        te_fill_buf(snd_buf, PKT_LEN);

        RPC_AWAIT_ERROR(s->pco_tst);
        rc = rpc_sendto(s->pco_tst, s->tst_s, snd_buf, PKT_LEN, 0,
                        s->iut_addr);
        if (rc != PKT_LEN)
        {
            ERROR("Failed to send expected data");
            return -1;
        }

        rc = udp_recv_data_reuseport(s1, s2, rcv_buf, PKT_LEN,
                                     &first_received);
        if (rc != PKT_LEN)
        {
            ERROR("Failed to receive expected data");
            return -1;
        }

        if (memcmp(snd_buf, rcv_buf, PKT_LEN) != 0)
            TEST_FAIL("Received data does not match sent data");

        if (first_received != check_first)
        {
            if (tst_addrs_num == MAX_TST_ADDRS)
            {
                ERROR("Too much addresses were tried on Tester");
                return -1;
            }

            /*
             * IP address on Tester is changed here because on IUT
             * decision which UPD socket receives data is based on
             * hash of source and remote addresses.
             */

            rpc_close(s->pco_tst, s->tst_s);

            s->tst_s = reuseport_create_tst_udp_sock(
                                s->pco_tst,
                                tst_if, net,
                                (struct sockaddr_storage *)s->tst_addr,
                                &tst_addr_handles[tst_addrs_num]);
            tst_addrs_num++;
            CHECK_RC(tapi_remove_arp(s->pco_iut->ta, iut_if, s->tst_addr));
        }
        else
        {
            break;
        }

    } while (TRUE);

    return 0;
}

/**
 * Try to accept incoming connection.
 *
 * @param rpcs    RPC server handle.
 * @param s       Listener socket.
 *
 * @return Accepted socket on success, negative value on failure.
 */
static int
try_accept(rcf_rpc_server *rpcs,
           int s)
{
    te_bool readable;

    RPC_GET_READABILITY(readable, rpcs, s, NETWORK_TIMEOUT);
    if (!readable)
        return -1;

    return rpc_accept(rpcs, s, NULL, NULL);
}

/**
 * Call nonblocking connect() on Tester.
 *
 * @param s     Socket context.
 *
 * @return 0 on success, negative value on failure.
 */
static int
tcp_nonblock_connect(reuseport_socket_ctx *s)
{
    int rc;

    if (s->iut_acc >= 0)
    {
        rpc_close(s->pco_iut, s->iut_acc);
        s->iut_acc = -1;
    }

    if (s->tst_s >= 0)
    {
        rpc_close(s->pco_tst, s->tst_s);
        s->tst_s = -1;
    }

    /**
     * It is necessary to change port every time to ensure
     * that eventually our connect will be handled by right
     * IUT listener (because choice is based on hash of IP addresses
     * and ports)
     */
    CHECK_RC(tapi_allocate_set_port(s->pco_tst, s->tst_addr));
    s->tst_s = reuseport_create_bind_socket(s->pco_tst, RPC_SOCK_STREAM,
                                            s->tst_addr, FALSE);

    rpc_fcntl(s->pco_tst, s->tst_s, RPC_F_SETFL, RPC_O_NONBLOCK);

    RPC_AWAIT_ERROR(s->pco_tst);
    rc = rpc_connect(s->pco_tst, s->tst_s, s->iut_addr);
    if (rc < 0 && RPC_ERRNO(s->pco_tst) != RPC_EINPROGRESS)
    {
        ERROR("connect() returned unexpected errno");
        rpc_fcntl(s->pco_tst, s->tst_s, RPC_F_SETFL, 0);
        return -1;
    }
    rpc_fcntl(s->pco_tst, s->tst_s, RPC_F_SETFL, 0);

    return 0;
}

/**
 * Establish TCP connection between TCP socket (bound
 * without SO_REUSEPORT) and its peer.
 *
 * @param s     Socket context.
 *
 * @return 0 on success, -1 on failure.
 */
static int
open_tcp_conn(reuseport_socket_ctx *s)
{
    if (tcp_nonblock_connect(s) < 0)
        return -1;

    s->iut_acc = try_accept(s->pco_iut, s->iut_s);
    if (s->iut_acc < 0)
        return -1;

    return 0;
}

/**
 * Try to accept connection on one of two listeners
 * bound to the same address and port with SO_REUSEPORT.
 *
 * @param s1              Context of the first listener.
 * @param s2              Context of the second listener.
 * @param timeout         Timeout, in milliseconds.
 * @param first_accepted  On success will be set to TRUE if
 *                        the first listener accepted connection,
 *                        and to FALSE otherwise.
 *
 * @return 0 on success, negative value on failure.
 */
static int
try_accept_reuseport(reuseport_socket_ctx *s1,
                     reuseport_socket_ctx *s2,
                     int timeout,
                     te_bool *first_accepted)
{
    struct timeval tv_start;
    struct timeval tv_cur;

    te_bool readable;

    rcf_rpc_server *rpcs;
    int             fd;

    te_bool check_first = TRUE;

    CHECK_RC(gettimeofday(&tv_start, NULL));

    while (TRUE)
    {
        if (check_first)
        {
            fd = s1->iut_s;
            rpcs = s1->pco_iut;
        }
        else
        {
            fd = s2->iut_s;
            rpcs = s2->pco_iut;
        }

        rpcs->silent = TRUE;
        RPC_GET_READABILITY(readable, rpcs, fd, 0);
        if (readable)
        {
            *first_accepted = check_first;

            return rpc_accept(rpcs, fd, NULL, NULL);
        }

        CHECK_RC(gettimeofday(&tv_cur, NULL));
        if (TIMEVAL_SUB(tv_cur, tv_start) > TE_MS2US(timeout))
            return -1;

        check_first = !check_first;
    }

    return -1;
}

/**
 * Check that any of two TCP listeners (bound to the same
 * address and port with SO_REUSEPORT) can accept connection.
 *
 * @param s1              Context of the first listener.
 * @param s2              Context of the second listener.
 * @param connect_first   If TRUE, check that the first listener
 *                        can accept connection; otherwise
 *                        check the second listener.
 *
 * @return 0 on success, negative value in case of failure.
 */
static int
check_tcp_conn_reuseport(reuseport_socket_ctx *s1,
                         reuseport_socket_ctx *s2,
                         te_bool connect_first)
{

    struct timeval tv_start;
    struct timeval tv_cur;

    int     iut_acc;
    te_bool first_accepted = FALSE;

    CHECK_RC(gettimeofday(&tv_start, NULL));

    do {
        if (tcp_nonblock_connect(connect_first ? s1 : s2) < 0)
            return -1;

        iut_acc = try_accept_reuseport(s1, s2, NETWORK_TIMEOUT,
                                       &first_accepted);
        if (iut_acc < 0)
            return -1;

        if (connect_first != first_accepted)
        {
            rpc_close((first_accepted ? s1->pco_iut : s2->pco_iut),
                      iut_acc);
        }
        else
        {
            if (connect_first)
                s1->iut_acc = iut_acc;
            else
                s2->iut_acc = iut_acc;

            return 0;
        }

        CHECK_RC(gettimeofday(&tv_cur, NULL));
        if (TIMEVAL_SUB(tv_cur, tv_start) >
                            TE_MS2US(REUSEPORT_CONN_TIMEOUT))
            return -TE_RC(TE_TAPI, TE_ETIMEDOUT);
    } while (TRUE);

    return -1;
}

/**
 * Accept and close TCP connections not established in time
 * because of network address removal.
 *
 * @param s       Listener context.
 */
static void
accept_close_delayed(reuseport_socket_ctx *s)
{
    int iut_acc;

    while (TRUE)
    {
        iut_acc = try_accept(s->pco_iut, s->iut_s);
        if (iut_acc >= 0)
            rpc_close(s->pco_iut, iut_acc);
        else
            break;
    }
}

/**
 * Perform tests on a pair of sockets bound to the same
 * network address.
 *
 * @param s1              Context of the first socket.
 * @param s2              Context of the second socket.
 * @param sock_type       Socket type (SOCK_DGRAM or SOCK_STREAM).
 * @param reuseport_used  Was SO_REUSEPORT used to bind both
 *                        sockets to the same port?
 * @param results         Where to save testing results.
 */
static void
sock_pair_test(reuseport_socket_ctx *s1,
               reuseport_socket_ctx *s2,
               rpc_socket_type sock_type,
               te_bool reuseport_used,
               sock_pair_results *results)
{
    sock_pair_results_init(results, sock_type);

    if (sock_type == RPC_SOCK_DGRAM)
    {
        if (reuseport_used)
        {
            if (check_udp_recv_reuseport(s1, s2, TRUE) == 0)
                results->u.udp.first_receive = TRUE;

            if (check_udp_recv_reuseport(s1, s2, FALSE) == 0)
                results->u.udp.second_receive = TRUE;
        }
        else
        {
            if (check_transmit_one_way(s1->pco_tst,
                                       s1->tst_s,
                                       s1->pco_iut,
                                       s1->iut_s,
                                       s1->iut_addr) == 0)
                results->u.udp.first_receive = TRUE;

            if (check_transmit_one_way(s2->pco_tst,
                                       s2->tst_s,
                                       s2->pco_iut,
                                       s2->iut_s,
                                       s2->iut_addr) == 0)
                results->u.udp.second_receive = TRUE;
        }

        if (check_transmit_one_way(s1->pco_iut,
                                   s1->iut_s,
                                   s1->pco_tst,
                                   s1->tst_s,
                                   s1->tst_addr) == 0)
            results->u.udp.first_send = TRUE;

        if (check_transmit_one_way(s2->pco_iut,
                                   s2->iut_s,
                                   s2->pco_tst,
                                   s2->tst_s,
                                   s2->tst_addr) == 0)
            results->u.udp.second_send = TRUE;
    }
    else
    {
        if (reuseport_used)
        {
            if (check_tcp_conn_reuseport(s1, s2, TRUE) == 0)
                results->u.tcp.first_connect = TRUE;

            if (check_tcp_conn_reuseport(s1, s2, FALSE) == 0)
                results->u.tcp.second_connect = TRUE;
        }
        else
        {
            if (open_tcp_conn(s1) == 0)
                results->u.tcp.first_connect = TRUE;

            if (open_tcp_conn(s2) == 0)
                results->u.tcp.second_connect = TRUE;
        }

        if (check_transmit_tcp(s1) == 0)
            results->u.tcp.first_transmit = TRUE;

        if (check_transmit_tcp(s2) == 0)
            results->u.tcp.second_transmit = TRUE;
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_iut2 = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    struct sockaddr *iut_addr_aux;

    struct sockaddr_storage   iut_addrs[ADDRS_NUM][SOCKS_PER_ADDR];
    struct sockaddr_storage   tst_addrs[ADDRS_NUM][SOCKS_PER_ADDR];
    reuseport_socket_ctx      sock_pairs[ADDRS_NUM][SOCKS_PER_ADDR];
    cfg_handle                iut_addr_handles[ADDRS_NUM];

    rpc_socket_type   sock_type;
    te_bool           set_reuseport;
    te_bool           single_process;
    int               remove_addr;

    sock_pair_results results;
    te_string         results_str = TE_STRING_INIT;

    int i;

    TEST_START;
    TEST_GET_NET(net);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(set_reuseport);
    TEST_GET_BOOL_PARAM(single_process);
    TEST_GET_INT_PARAM(remove_addr);

    for (i = 0; i < ADDRS_NUM; i++)
    {
        iut_addr_handles[i] = CFG_HANDLE_INVALID;
    }
    for (i = 0; i < MAX_TST_ADDRS; i++)
    {
        tst_addr_handles[i] = CFG_HANDLE_INVALID;
    }

    TEST_STEP("If @p single_process is @c FALSE, create additional RPC server "
              "on IUT.");

    if (single_process)
        pco_iut2 = pco_iut;
    else
        CHECK_RC(rcf_rpc_server_fork(pco_iut, "pco_iut_child", &pco_iut2));

    TEST_STEP("Add @c ADDRS_NUM addresses on IUT network interface.");
    for (i = 0; i < ADDRS_NUM; i++)
    {
        CHECK_RC(tapi_env_allocate_addr(net, AF_INET,
                                        &iut_addr_aux, NULL));
        tapi_sockaddr_clone_exact(iut_addr_aux, &iut_addrs[i][0]);
        free(iut_addr_aux);

        CHECK_RC(tapi_cfg_base_if_add_net_addr(
                                            pco_iut->ta, iut_if->if_name,
                                            SA(&iut_addrs[i][0]),
                                            net->ip4pfx,
                                            FALSE, &iut_addr_handles[i]));
        CHECK_RC(tapi_remove_arp(pco_tst->ta, tst_if->if_name,
                                 SA(&iut_addrs[i][0])));

        CHECK_RC(tapi_allocate_set_port(pco_iut, SA(&iut_addrs[i][0])));
        tapi_sockaddr_clone_exact(SA(&iut_addrs[i][0]), &iut_addrs[i][1]);

        if (!set_reuseport)
            CHECK_RC(tapi_allocate_set_port(pco_iut, SA(&iut_addrs[i][1])));

        tapi_sockaddr_clone_exact(tst_addr, &tst_addrs[i][0]);
        tapi_sockaddr_clone_exact(tst_addr, &tst_addrs[i][1]);
    }

    CFG_WAIT_CHANGES;

    TEST_STEP("For each address create a pair of sockets of @p sock_type "
              "type, taking into account @p single_process and "
              "@p set_reuseport.");
    for (i = 0; i < ADDRS_NUM; i++)
    {
        reuseport_init_socket_ctx(pco_iut, pco_tst,
                                  SA(&iut_addrs[i][0]),
                                  SA(&tst_addrs[i][0]),
                                  &sock_pairs[i][0]);

        sock_pair_create_sock(&sock_pairs[i][0], sock_type,
                              set_reuseport,
                              (i == 0 ? TRUE : FALSE));

        reuseport_init_socket_ctx(pco_iut2, pco_tst,
                                  SA(&iut_addrs[i][1]),
                                  SA(&tst_addrs[i][1]),
                                  &sock_pairs[i][1]);

        sock_pair_create_sock(&sock_pairs[i][1], sock_type,
                              set_reuseport,
                              (i == 0 ? TRUE : FALSE));
    }

    TEST_STEP("Check that both sockets in each pair can be used "
              "to accept connections (for @c SOCK_STREAM sockets) "
              "or receive and send data (for @c SOCK_DGRAM sockets). "
              "For @c SOCK_STREAM sockets check also that data "
              "can be transmitted in both directions via accepted "
              "connections.");

    for (i = 0; i < ADDRS_NUM; i++)
    {
        sock_pair_test(&sock_pairs[i][0],
                       &sock_pairs[i][1],
                       sock_type, set_reuseport, &results);

        sock_pair_results2str(&results, &results_str);
        RING("Initial testing of sockets pair %d: %s",
             i + 1, results_str.ptr);

        if (!results_all_passed(&results))
            TEST_VERDICT("Initial test for address %d failed: %s",
                         i + 1, results_str.ptr);
    }

    TEST_STEP("Remove network address specified by @p remove_address.");
    CHECK_RC(cfg_del_instance(iut_addr_handles[remove_addr - 1],
                              FALSE));
    iut_addr_handles[remove_addr - 1] = CFG_HANDLE_INVALID;
    CFG_WAIT_CHANGES;

    TEST_STEP("Perform the same checks for all sockets again to verify "
              "that only for sockets bound to removed address they fail.");
    for (i = 0; i < ADDRS_NUM; i++)
    {
        sock_pair_test(&sock_pairs[i][0],
                       &sock_pairs[i][1],
                       sock_type, set_reuseport,
                       &results);

        sock_pair_results2str(&results, &results_str);
        RING("Testing of sockets pair %d after removing address %d : %s",
             i + 1, remove_addr, results_str.ptr);

        if (i != remove_addr - 1)
        {
            if (!results_all_passed(&results))
                TEST_VERDICT("After removing address %d "
                             "test failed for address %d: %s",
                             remove_addr, i + 1, results_str.ptr);
        }
        else
        {
            if (i == 0 && sock_type == RPC_SOCK_DGRAM)
            {
                if (!(!results.u.udp.first_receive &&
                      !results.u.udp.second_receive &&
                      results.u.udp.first_send &&
                      results.u.udp.second_send))
                    TEST_VERDICT("Unexpected results obtained "
                                 "when IUT UDP socket is bound to "
                                 "wildcard address and one of "
                                 "addresses is removed: %s",
                                 results_str.ptr);
            }
            else
            {
                if (!results_all_failed(&results))
                    TEST_VERDICT("After removing address %d "
                                 "some tests passed for sockets "
                                 "bound to it: %s",
                                 remove_addr, results_str.ptr);
            }
        }
    }

    TEST_STEP("Restore previously removed network address.");
    CHECK_RC(
      tapi_cfg_base_if_add_net_addr(
                                 pco_iut->ta, iut_if->if_name,
                                 SA(&iut_addrs[remove_addr - 1][0]),
                                 net->ip4pfx,
                                 FALSE,
                                 &iut_addr_handles[remove_addr - 1]));
    CHECK_RC(tapi_remove_arp(pco_tst->ta, tst_if->if_name,
                             SA(&iut_addrs[remove_addr - 1][0])));
    CFG_WAIT_CHANGES;

    if (sock_type == RPC_SOCK_STREAM)
    {
        accept_close_delayed(&sock_pairs[remove_addr - 1][0]);
        accept_close_delayed(&sock_pairs[remove_addr - 1][1]);
    }

    TEST_STEP("Perform the same checks on sockets the final time to verify "
              "that all works OK now for all sockets.");
    for (i = 0; i < ADDRS_NUM; i++)
    {
        sock_pair_test(&sock_pairs[i][0],
                       &sock_pairs[i][1],
                       sock_type, set_reuseport,
                       &results);

        sock_pair_results2str(&results, &results_str);
        RING("Final testing of sockets pair %d: %s",
             i + 1, results_str.ptr);

        if (!results_all_passed(&results))
            TEST_VERDICT("Final test for address %d failed: %s",
                         i + 1, results_str.ptr);
    }

    TEST_SUCCESS;

cleanup:

    for (i = 0; i < ADDRS_NUM; i++)
    {
        reuseport_close_pair(&sock_pairs[i][0],
                             &sock_pairs[i][1]);

        if (iut_addr_handles[i] != CFG_HANDLE_INVALID)
            CLEANUP_CHECK_RC(cfg_del_instance(iut_addr_handles[i],
                                              FALSE));
    }

    for (i = 0; i < tst_addrs_num; i++)
    {
        if (tst_addr_handles[i] != CFG_HANDLE_INVALID)
            CLEANUP_CHECK_RC(cfg_del_instance(tst_addr_handles[i],
                                              FALSE));
    }

    if (!single_process && pco_iut2 != NULL)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut2));

    te_string_free(&results_str);

    TEST_END;
}
