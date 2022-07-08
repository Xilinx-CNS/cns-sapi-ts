/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 *
 * Socket API Test Suite
 * Reuseport
 */

/** @page reuseport-several_clusters Coexistence of a few TCP and UDP clusters
 *
 * @objective Create several clusters binding TCP listener and UDP
 *            sockets to different ports.
 *
 * @type use case
 *
 * @param env                   Testing environment.
 *                              - @ref arg_types_env_peer2peer
 * @param clusters_num          Number of UDP and TCP socket pairs -
 *                              two sockets bound to the same address:port.
 * @param bind_to               IUT sockets binding address type.
 *                              - @c specific: bind all sockets to specific
 *                                             address.
 *                              - @c wildcard: bind all sockets to
 *                                             @c INADDR_ANY.
 *                              - @c random: for each socket pair choose
 *                                           randomly whether to bind to
 *                                           specific address or to
 *                                           @c INADDR_ANY.
 * @param tp                    Create aux processes/threads or not.
 *                              - @c none: create sockets in the same
 *                                         thread.
 *                              - @c thread: create sockets in different
 *                                           threads.
 *                              - @c process: create sockets in
 *                                            different processes.
 * @param personal_thread       If @p tp is @c thread or @c process - create
 *                              personal thread/process for a cluster or
 *                              for each individual IUT socket.
 *                              - @c TRUE: each socket is in its personal
 *                                         thread or process, inapplicable
 *                                         with @p tp=none.
 *                              - @c FALSE: each socket cluster is in its
 *                                          personal thread or process
 *                                          (if required by @p tp).
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "reuseport/several_clusters"

#include "sockapi-test.h"
#include "reuseport.h"
#include "tapi_mem.h"

/**
 * Type of the address to which to bind a socket.
 */
enum {
    BIND_TO_SPECIFIC = 1,   /**< Specific address. */
    BIND_TO_WILDCARD,       /**< @c INADDR_ANY. */
    BIND_TO_RANDOM,         /**< Choose randomly between
                                 specific and wildcard. */
};

/**
 * Bind address types array to be passed to
 * TEST_GET_ENUM_PARAM().
 */
#define BIND_TO  \
    { "specific", BIND_TO_SPECIFIC },   \
    { "wildcard", BIND_TO_WILDCARD },   \
    { "random", BIND_TO_RANDOM }

/**
 * A structure storing a pair of IUT sockets (cluster) bound to the same
 * address:port with SO_REUSEPORT, and related sockets, addresses, etc.
 */
typedef struct cluster_ctx {
    reuseport_socket_ctx      s1;            /**< The first IUT socket
                                                  and related sockets
                                                  and addresses. */
    reuseport_socket_ctx      s2;            /**< The second IUT socket
                                                  and related sockets
                                                  and addresses. */
    rpc_socket_type           sock_type;     /**< Type of sockets. */
    struct sockaddr_storage   iut_conn_addr; /**< Address to which Tester
                                                  sockets should connect. */
    struct sockaddr_storage   iut_bind_addr; /**< Address to which IUT
                                                  sockets should bind. */
} cluster_ctx;

/**
 * A structure used to store two IUT socket pairs (clusters), where
 * sockets from each pair are bound to its own address:port using
 * SO_REUSEPORT.
 */
typedef struct cluster_pair {
    cluster_ctx             c1;   /**< The first cluster. */
    cluster_ctx             c2;   /**< The second cluster. */
} cluster_pair;

/**
 * Construct two address/port pairs on IUT, one for bind(),
 * another one for connect() from a peer.
 *
 * @note Address/port for bind() may be different from
 *       address/port for connect() if we bind to @c INADDR_ANY.
 *
 * @param pco_iut         RPC server.
 * @param bind_to         Bind address type (BIND_TO_SPECIFIC,
 *                        BIND_TO_WILDCARD or BIND_TO_RANDOM).
 * @param iut_addr        Network address to use.
 * @param iut_conn_addr   Address to which to connect a peer.
 * @param iut_bind_addr   Address to which to bind IUT socket.
 */
static void
alloc_iut_addrs(rcf_rpc_server *pco_iut,
                int bind_to,
                const struct sockaddr *iut_addr,
                struct sockaddr_storage *iut_conn_addr,
                struct sockaddr_storage *iut_bind_addr)
{
    tapi_sockaddr_clone_exact(iut_addr, iut_conn_addr);
    CHECK_RC(tapi_allocate_set_port(pco_iut, SA(iut_conn_addr)));
    tapi_sockaddr_clone_exact(SA(iut_conn_addr),
                              iut_bind_addr);
    if (bind_to == BIND_TO_WILDCARD ||
        (bind_to == BIND_TO_RANDOM && rand() % 2 == 1))
        te_sockaddr_set_wildcard(SA(iut_bind_addr));
}

/**
 * Initialize two socket contexts (where IUT sockets
 * are bound to the same address:port).
 *
 * @param pco_iut           RPC server on IUT.
 * @param pco_tst           RPC server on Tester.
 * @param tp                @c TP_NONE, @c TP_THREAD or
 *                          @c TP_PROCESS.
 * @param personal_thread   If @c TRUE, a new thread/process
 *                          will be created for every IUT
 *                          socket; otherwise it will be done
 *                          for every pair of IUT sockets bound
 *                          to the same address/port. This parameter
 *                          has effect only if @p tp is not @c TP_NONE.
 * @param tst_addr          Network address on Tester.
 * @param conn_addr         Address to which Tester sockets should connect.
 * @param bind_addr         Address to which IUT sockets should bind.
 * @param s1                The first socket context.
 * @param s2                The second socket context.
 */
static void
init_socket_pair(rcf_rpc_server *pco_iut,
                 rcf_rpc_server *pco_tst,
                 thread_process_type tp,
                 te_bool personal_thread,
                 rpc_socket_type sock_type,
                 const struct sockaddr *tst_addr,
                 const struct sockaddr *conn_addr,
                 const struct sockaddr *bind_addr,
                 reuseport_socket_ctx *s1,
                 reuseport_socket_ctx *s2)
{
    rcf_rpc_server *pco_iut_aux = NULL;

    init_aux_rpcs(pco_iut, &pco_iut_aux, tp);
    reuseport_init_socket_ctx(pco_iut_aux, pco_tst,
                              conn_addr, tst_addr, s1);
    s1->iut_addr_bind = bind_addr;

    if (personal_thread)
        init_aux_rpcs(pco_iut, &pco_iut_aux, tp);
    reuseport_init_socket_ctx(pco_iut_aux, pco_tst,
                              conn_addr, tst_addr, s2);
    s2->iut_addr_bind = bind_addr;

    s1->iut_s = reuseport_create_bind_socket(s1->pco_iut, sock_type,
                                             s1->iut_addr_bind, TRUE);
    s2->iut_s = reuseport_create_bind_socket(s2->pco_iut, sock_type,
                                             s2->iut_addr_bind, TRUE);

    if (sock_type == RPC_SOCK_STREAM)
    {
        rpc_listen(s1->pco_iut, s1->iut_s, SOCKTS_BACKLOG_DEF);
        rpc_listen(s2->pco_iut, s2->iut_s, SOCKTS_BACKLOG_DEF);
    }
}

/**
 * Check that data can be transmitted in both directions
 * via a given connection.
 *
 * @param sock_type       Socket type.
 * @param s               Socket context.
 */
static void
test_connection(rpc_socket_type sock_type,
                reuseport_socket_ctx *s)
{
    sockts_test_connection_ext(s->pco_iut,
                               (sock_type == RPC_SOCK_STREAM ?
                                          s->iut_acc : s->iut_s),
                               s->pco_tst, s->tst_s,
                               s->tst_addr,
                               (sock_type == RPC_SOCK_DGRAM ?
                                  SOCKTS_SOCK_UDP_NOTCONN :
                                  SOCKTS_SOCK_TCP_PASSIVE));
}

/**
 * Check data transmission in both directions via two
 * connections; after that close connected sockets
 * (in case of TCP) or Tester sockets (in case of UDP).
 *
 * @param sock_type     Socket type.
 * @param s1            The first socket context.
 * @param s2            The second socket context.
 */
static void
reuseport_check_close_pair(rpc_socket_type sock_type,
                           reuseport_socket_ctx *s1,
                           reuseport_socket_ctx *s2)
{
    test_connection(sock_type, s1);
    test_connection(sock_type, s2);

    if (sock_type == RPC_SOCK_STREAM)
    {
        reuseport_close_tcp_conn(s1);
        reuseport_close_tcp_conn(s2);
    }
    else
    {
        RPC_CLOSE(s1->pco_tst, s1->tst_s);
        RPC_CLOSE(s2->pco_tst, s2->tst_s);
    }
}

/**
 * Check data transmission if connection already exists.
 * Close connected sockets (in case of TCP) or Tester sockets
 * (in case of UDP). Establish new connection to each of IUT
 * sockets creating new sockets on Tester. Check data transmission
 * via newly established connections.
 *
 * @param sock_type         Socket type.
 * @param tst_if            Network interface on Tester.
 * @param net               Network to allocate new addresses
 *                          on Tester (required for UDP).
 * @param s1                The first socket context.
 * @param s2                The second socket context.
 */
static void
reuseport_check_pair(rpc_socket_type sock_type,
                     const struct if_nameindex *tst_if,
                     tapi_env_net *net,
                     reuseport_socket_ctx *s1,
                     reuseport_socket_ctx *s2)
{
    if (s1->tst_s >= 0)
        reuseport_check_close_pair(sock_type, s1, s2);

    if (sock_type == RPC_SOCK_STREAM)
        try_connect_pair(s1, s2);
    else
        try_connect_udp_pair(tst_if, net,
                             s1, s2, FALSE);

    test_connection(sock_type, s1);
    test_connection(sock_type, s2);
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server          *pco_iut = NULL;
    rcf_rpc_server          *pco_tst = NULL;
    const struct sockaddr   *iut_addr = NULL;
    const struct sockaddr   *tst_addr = NULL;
    tapi_env_net            *net = NULL;

    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *tst_if = NULL;

    int           clusters_num;
    int           bind_to;
    int           tp;
    te_bool       personal_thread;

    cluster_pair *cluster_pairs = NULL;
    int           i;
    int           j;

    TEST_START;
    TEST_GET_NET(net);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(clusters_num);
    TEST_GET_ENUM_PARAM(bind_to, BIND_TO);
    TEST_GET_BOOL_PARAM(personal_thread);
    TEST_GET_ENUM_PARAM(tp, THREAD_PROCESS);

    TEST_STEP("Do @p clusters_num times: "
              "- Create a new UDP cluster and a new TCP cluster. Each "
              "cluster consists of two IUT sockets bound to the "
              "same address/port with SO_REUSEPORT (listener sockets "
              "in case of TCP). "
              "- Choose randomly whether UDP or TCP cluster should "
              "be created firstly. "
              "- Choose address to bind sockets according to @p bind_to. "
              "- Use different port for each cluster.");

    cluster_pairs = tapi_calloc(clusters_num, sizeof(*cluster_pairs));

    for (i = 0; i < clusters_num; i++)
    {
        alloc_iut_addrs(pco_iut, bind_to, iut_addr,
                        &cluster_pairs[i].c1.iut_conn_addr,
                        &cluster_pairs[i].c1.iut_bind_addr);
        alloc_iut_addrs(pco_iut, bind_to, iut_addr,
                        &cluster_pairs[i].c2.iut_conn_addr,
                        &cluster_pairs[i].c2.iut_bind_addr);

        if (rand() % 2 == 0)
        {
            cluster_pairs[i].c1.sock_type = RPC_SOCK_STREAM;
            cluster_pairs[i].c2.sock_type = RPC_SOCK_DGRAM;
        }
        else
        {
            cluster_pairs[i].c1.sock_type = RPC_SOCK_DGRAM;
            cluster_pairs[i].c2.sock_type = RPC_SOCK_STREAM;
        }

        init_socket_pair(pco_iut, pco_tst, tp, personal_thread,
                         cluster_pairs[i].c1.sock_type,
                         tst_addr,
                         SA(&cluster_pairs[i].c1.iut_conn_addr),
                         SA(&cluster_pairs[i].c1.iut_bind_addr),
                         &cluster_pairs[i].c1.s1, &cluster_pairs[i].c1.s2);

        init_socket_pair(pco_iut, pco_tst, tp, personal_thread,
                         cluster_pairs[i].c2.sock_type,
                         tst_addr,
                         SA(&cluster_pairs[i].c2.iut_conn_addr),
                         SA(&cluster_pairs[i].c2.iut_bind_addr),
                         &cluster_pairs[i].c2.s1, &cluster_pairs[i].c2.s2);
    }

    TEST_STEP("Check that all clusters work correctly: "
              "- For every TCP cluster, check that both listeners "
              "can accept connection, and data can be transmitted "
              "in both directions via such connection. "
              "- For every UDP cluster, check that both IUT sockets "
              "can receive packets from Tester, and can send packets "
              "back to Tester sockets.");

    for (i = 0; i < clusters_num; i++)
    {
        reuseport_check_pair(cluster_pairs[i].c1.sock_type,
                             tst_if, net,
                             &cluster_pairs[i].c1.s1,
                             &cluster_pairs[i].c1.s2);

        reuseport_check_pair(cluster_pairs[i].c2.sock_type,
                             tst_if, net,
                             &cluster_pairs[i].c2.s1,
                             &cluster_pairs[i].c2.s2);
    }

    TEST_STEP("Destroy clusters one by one, closing all the IUT "
              "and Tester sockets associated with each cluster. "
              "After destroying a cluster, check that all the remaining "
              "clusters work correctly.");
    for (i = 0; i < clusters_num; i++)
    {
        if (cluster_pairs[i].c1.sock_type == RPC_SOCK_STREAM)
        {
            reuseport_close_tcp_conn(&cluster_pairs[i].c1.s1);
            reuseport_close_tcp_conn(&cluster_pairs[i].c1.s2);
        }
        reuseport_close_sockets(&cluster_pairs[i].c1.s1, FALSE);
        reuseport_close_sockets(&cluster_pairs[i].c1.s2, FALSE);

        if (cluster_pairs[i].c2.sock_type == RPC_SOCK_STREAM)
        {
            reuseport_close_tcp_conn(&cluster_pairs[i].c2.s1);
            reuseport_close_tcp_conn(&cluster_pairs[i].c2.s2);
        }
        reuseport_close_sockets(&cluster_pairs[i].c2.s1, FALSE);
        reuseport_close_sockets(&cluster_pairs[i].c2.s2, FALSE);

        for (j = i + 1; j < clusters_num; j++)
        {
            reuseport_check_pair(cluster_pairs[j].c1.sock_type,
                                 tst_if, net,
                                 &cluster_pairs[j].c1.s1,
                                 &cluster_pairs[j].c1.s2);

            reuseport_check_pair(cluster_pairs[j].c2.sock_type,
                                 tst_if, net,
                                 &cluster_pairs[j].c2.s1,
                                 &cluster_pairs[j].c2.s2);
        }
    }

    TEST_SUCCESS;

cleanup:

    for (i = 0; i < clusters_num; i++)
    {
        reuseport_close_pair(&cluster_pairs[i].c1.s1,
                             &cluster_pairs[i].c1.s2);
        reuseport_close_pair(&cluster_pairs[i].c2.s1,
                             &cluster_pairs[i].c2.s2);
    }

    free(cluster_pairs);

    /*
     * This is done to get rid of ARP entries for removed
     * addresses, see ST-2407.
     */
    CLEANUP_CHECK_RC(sockts_ifs_down_up(pco_iut, iut_if, NULL));

    TEST_END;
}
