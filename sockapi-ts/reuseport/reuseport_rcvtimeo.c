/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reuseport
 *
 * $Id$
 */

/** @page reuseport-reuseport_rcvtimeo Connections distribution on listener sockets with option SO_RCVTIMEO
 *
 * @objective  Check connections distribution on a few listener sockets
 *             which use socket option SO_RCVTIMEO.
 *
 * @param pco_iut        PCO on IUT.
 * @param pco_tst1       PCO on Agt_B.
 * @param pco_tst2       PCO on Agt_C.
 * @param listeners_num  Listeners sockets number.
 * @param same_tst       Bind all sockets to the same address:port couple.
 * @param same_port      Bind all sockets to the port, address is different
 *                       if @p same_tst is @c FALSE.
 * 
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "reuseport/reuseport_rcvtimeo"

#include "sockapi-test.h"
#include "reuseport.h"

/* Maximum connection attempts number. */
#define MAX_ATTEMPTS 30

/* Possible events number. */
#define EVENTS_NUM 1

/* Listener sockets timeout. */
#define RCVTIMEO_VAL 3

/**
 * Socket context.
 */
typedef struct socket_ctx {
    te_bool iface;               /**< Interface switcher */
    int     l;                   /**< Listener Socket */
    int     a;                   /**< Accepted socket */
    const struct sockaddr *addr; /**< Local address */
    rcf_rpc_server *pco_iut;     /**< IUT RPC server handler */
    rcf_rpc_server *pco_tst;     /**< Tester RPC server handler */
    te_bool accepted;            /**< The listener socket has accepted at
                                      least one connection */
} socket_ctx;

/**
 * Try to accept connection at one of listener sockets.
 * 
 * @param sock      Sockets context array
 * @param num       The array length
 * @param idxc      Index of a socket context, which was used to initiate
 *                  the connection
 * 
 * @return Pointer to the socket context, which received the connection.
 */
static socket_ctx *
accept_connection(socket_ctx *sock, int  num, int idxc)
{
    te_bool failed = FALSE;
    int i;

    for (i = 0; i < num; i++)
    {
        if (sockts_is_op_done(sock[i].pco_iut))
        { 
            RPC_AWAIT_IUT_ERROR(sock[i].pco_iut);
            sock[i].a = rpc_accept(sock[i].pco_iut, sock[i].l, NULL, 0);
            if (sock[i].a < 0)
            {
                if (RPC_ERRNO(sock[i].pco_iut) == RPC_EAGAIN)
                {
                    if (failed)
                        TEST_VERDICT("Accept failed twice in a row");

                    sock[i].pco_iut->op = RCF_RPC_CALL;
                    rpc_accept(sock[i].pco_iut, sock[i].l, NULL, NULL);
                    TAPI_WAIT_NETWORK;

                    i--;
                    failed = TRUE;
                    continue;
                }
                TEST_VERDICT("Accept failed with unexpected error: %r",
                             RPC_ERRNO(sock[i].pco_iut));
            }

        if (sock[i].pco_tst != sock[idxc].pco_tst ||
            *te_sockaddr_get_port_ptr(sock[i].addr) !=
            *te_sockaddr_get_port_ptr(sock[idxc].addr))
            TEST_VERDICT("Connection request was received by a wrong "
                         "socket");

            sock[i].accepted = TRUE;
            return sock + i;
        }
        failed = FALSE;
    }

    return NULL;
}

/**
 * Check if each listener socket received at least one connection.
 * 
 * @param sock      Sockets context array
 * @param num       The array length
 * 
 * @return @c TRUE if each listener received at least one connetion.
 */
te_bool
finish_testing(socket_ctx *sock, int num)
{
    int i;

    for (i = 0; i < num; i++)
        if (!sock[i].accepted)
            return FALSE;

    return TRUE;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_tst1 = NULL;
    rcf_rpc_server *pco_tst2 = NULL;
    rcf_rpc_server *pco_iut = NULL;

    const struct sockaddr  *iut_addr1 = NULL;
    const struct sockaddr  *iut_addr2 = NULL;
    int     listeners_num;
    te_bool same_port;
    te_bool same_tst;

    tarpc_timeval timeout = {.tv_sec = RCVTIMEO_VAL, .tv_usec = 0};

    pthread_t    *thread;
    socket_ctx   *sock = NULL;
    socket_ctx   *sock_a = NULL;
    int tst_s = -1;
    int idxc;
    int i;
    int init_cluster_sz;

    char name[32];

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_INT_PARAM(listeners_num);
    TEST_GET_BOOL_PARAM(same_tst);
    TEST_GET_BOOL_PARAM(same_port);

    TEST_STEP("Set Onload cluster size.");
    CHECK_RC(tapi_sh_env_save_set_int(pco_iut, "EF_CLUSTER_SIZE",
                                      same_port && same_tst ? listeners_num :
                                                              listeners_num / 2,
                                      TRUE, NULL, &init_cluster_sz));

    sock = te_calloc_fill(listeners_num, sizeof(*sock), 0);
    thread = te_calloc_fill(listeners_num, sizeof(*thread), 0);

    TEST_STEP("Use the same IUT address for all listener sockets if "
              "@p same_tst is @c TRUE, i.e. only one tester is involved.");
    if (same_tst)
    {
        pco_tst2 = pco_tst1;
        te_sockaddr_set_netaddr((struct sockaddr *)iut_addr2,
                                te_sockaddr_get_netaddr(iut_addr1));
    }

    TEST_STEP("Use the same port in both IUT addresses if @p same_port "
              "is @c TRUE.");
    if (same_port)
    {
        uint16_t *port_ptr;

        port_ptr = te_sockaddr_get_port_ptr(SA(iut_addr2));
        *port_ptr = *te_sockaddr_get_port_ptr(SA(iut_addr1));
    }

    TEST_STEP("Create @p listeners_num TCP sockets, each socket in its thread. "
              "Bind sockets, set socket options @c SO_REUSEPORT and "
              "@c SO_RCVIMEO, call listen().");
    for (i = 0; i < listeners_num; i++)
    {
        TEST_STEP("Sockets are bound alternately to addresses @p iut_addr1 and "
                  "@p iut_addr2");
        sock[i].iface = i % 2;
        sock[i].addr = sock[i].iface ? iut_addr2 : iut_addr1;
        sock[i].pco_tst = sock[i].iface ? pco_tst2 : pco_tst1;
        sock[i].l = sock[i].a = -1;

        snprintf(name, sizeof(name), "iut_handler_%d", i);
        rcf_rpc_server_thread_create(pco_iut, name, &sock[i].pco_iut);

        sock[i].l = rpc_socket(sock[i].pco_iut,
                               rpc_socket_domain_by_addr(sock[i].addr),
                               RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_setsockopt_int(sock[i].pco_iut, sock[i].l, RPC_SO_REUSEPORT, 1);
        rpc_setsockopt(sock[i].pco_iut, sock[i].l, RPC_SO_RCVTIMEO, &timeout);
        RPC_AWAIT_IUT_ERROR(sock[i].pco_iut);
        rc = rpc_bind(sock[i].pco_iut, sock[i].l, sock[i].addr);
        if (rc != 0)
            TEST_VERDICT("bind() failed with %r",
                         RPC_ERRNO(sock[i].pco_iut));
        rpc_listen(sock[i].pco_iut, sock[i].l, -1);
    }

    TEST_STEP("Call blocking accept() for each listener socket.");
    for (i = 0; i < listeners_num; i++)
    {
        sock[i].pco_iut->op = RCF_RPC_CALL;
        rpc_accept(sock[i].pco_iut, sock[i].l, NULL, NULL);
    }

    TEST_STEP("In the loop: "
              "-# Create TCP socket on one of testers. "
              "-# Connect the socket to appropriate IUT address. "
              "-# Accept connection on one of the listener sockets.");
    for (i = 0; i < MAX_ATTEMPTS; i++)
    {
        idxc = i % listeners_num;
        tst_s = rpc_socket(sock[idxc].pco_tst,
                           rpc_socket_domain_by_addr(sock[idxc].addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_connect(sock[idxc].pco_tst, tst_s, sock[idxc].addr);
        TAPI_WAIT_NETWORK;

        sock_a = accept_connection(sock, listeners_num, idxc);
        if (sock_a == NULL)
            TEST_VERDICT("Listener sockets did not receive connection");

        sockts_test_connection(sock_a->pco_iut, sock_a->a,
                               sock[idxc].pco_tst, tst_s);
        RPC_CLOSE(sock_a->pco_iut, sock_a->a);
        RPC_CLOSE(sock[idxc].pco_tst, tst_s);

        TEST_STEP("Each listener socket must receive at least one connection for "
                  "success.");
        if (finish_testing(sock, listeners_num))
            break;

        sock_a->pco_iut->op = RCF_RPC_CALL;
        rpc_accept(sock_a->pco_iut, sock_a->l, NULL, NULL);
    }

    RING("Iterations number %d", i);

    for (i = 0; i < listeners_num; i++)
    {
        if (sock[i].pco_iut->op != RCF_RPC_WAIT)
            continue;

        RPC_AWAIT_IUT_ERROR(sock[i].pco_iut);
        rc = rpc_accept(sock[i].pco_iut, sock[i].l, NULL, NULL);
        if (rc != -1 || RPC_ERRNO(sock[i].pco_iut) != RPC_EAGAIN)
            TEST_VERDICT("Accept returned unexpected code or errno");
    }

    if (i == MAX_ATTEMPTS)
        TEST_VERDICT("Attempts limit has been reached");

    TEST_SUCCESS;

cleanup:

    if (sock != NULL)
    {
        for (i = 0; i < listeners_num; i++)
        {
            if (sock[i].pco_iut == NULL)
                break;

            if (sock[i].pco_iut->op == RCF_RPC_WAIT)
            {
                RPC_AWAIT_IUT_ERROR(sock[i].pco_iut);
                rpc_accept(sock[i].pco_iut, sock[i].l, NULL, NULL);
            }
            CLEANUP_RPC_CLOSE(sock[i].pco_iut, sock[i].l);

            CLEANUP_CHECK_RC(rcf_rpc_server_destroy(sock[i].pco_iut));
        }
    }
    free(sock);
    free(thread);

    CLEANUP_CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_CLUSTER_SIZE",
                                         init_cluster_sz, TRUE, TRUE));

    TEST_END;
}
