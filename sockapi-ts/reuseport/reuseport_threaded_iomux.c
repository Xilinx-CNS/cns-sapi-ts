/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reuseport
 *
 * $Id$
 */

/** @page reuseport-reuseport_threaded_iomux Using sockets with a shared port in different iomux functions
 *
 * @objective  Using sockets with a shared port in a few blocked
 *             simultaneously called iomux functions.
 *
 * @param pco_iut        PCO on IUT.
 * @param pco_tst1       PCO on Agt_B.
 * @param pco_tst2       PCO on Agt_C.
 * @param listeners_num  Listeners sockets number.
 * @param iomux          Iomux function name.
 * @param late_iomux     Call iomux funtion after all sockets are listeners.
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

#define TE_TEST_NAME  "reuseport/reuseport_threaded_iomux"

#include "sockapi-test.h"
#include "reuseport.h"
#include "iomux.h"

/* Maximum connection attempts number. */
#define MAX_ATTEMPTS 1000

/* Possible events number. */
#define EVENTS_NUM 1

/**
 * Socket context.
 */
typedef struct socket_ctx {
    te_bool iface;                   /**< Interface switcher */
    int     l;                       /**< Listener Socket */
    int     a;                       /**< Accepted socket */
    const struct sockaddr *addr;     /**< IUT address */
    const struct sockaddr *tst_addr; /**< Tester address */
    rcf_rpc_server *pco_iut;         /**< IUT RPC server handler */
    rcf_rpc_server *pco_tst;         /**< Tester RPC server handler */
    te_bool accepted;                /**< The listener socket has accepted at
                                          least one connection */
    iomux_state iomux_st;
} socket_ctx;

/**
 * Call iomux function.
 * 
 * @param iomux     Iomux function type
 * @param sock      The socket context
 * @param events    Events set which size is equal to @p EVENTS_NUM or
 *                  @c NULL
 * 
 * @return Iomux function return code.
 *  
 */
static int
iomux_call_test(iomux_call_type iomux, socket_ctx *sock,
                iomux_evt_fd *events)
{
    iomux_evt_fd ev[EVENTS_NUM];

    if (events == NULL)
        events = ev;

    events->fd = sock->l;
    events->events = EVT_RDWR;
    events->revents = 0;
    iomux_switch_state(&sock->iomux_st);

    return iomux_call(iomux, sock->pco_iut, events, EVENTS_NUM, NULL);
}

/**
 * Open TCP socket, set SO_REUSEPORT, bind it and call listen() function.
 * 
 * @param sock      Socket context
 * @param bound     Another listener socket already bound on the sock->addr.
 */
static void
create_listener(socket_ctx *sock, te_bool bound)
{
    int rc;

    sock->l = rpc_socket(sock->pco_iut, rpc_socket_domain_by_addr(sock->addr),
                         RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_setsockopt_int(sock->pco_iut, sock->l, RPC_SO_REUSEPORT, 1);
    rpc_bind(sock->pco_iut, sock->l, sock->addr);

    RPC_AWAIT_IUT_ERROR(sock->pco_iut);
    rc = rpc_listen(sock->pco_iut, sock->l, -1);
    if (rc < 0 && RPC_ERRNO(sock->pco_iut) == RPC_EADDRINUSE && bound)
        TEST_VERDICT("Unable to bind two listener sockets on the same stack");
    else if (rc < 0)
        TEST_VERDICT("listen call failed with %r", RPC_ERRNO(sock->pco_iut));

    rpc_fcntl(sock->pco_iut, sock->l, RPC_F_SETFL, RPC_O_NONBLOCK);
}

/**
 * Try to accept connection at one of listener sockets.
 * 
 * @param sock      Sockets context array
 * @param num       The array length
 * @param iomux     Iomux function type
 * @param idxc      Index of a socket context, which was used to initiate
 *                  the connection
 * 
 * @return Pointer to the socket context, which received the connection.
 */
static socket_ctx *
accept_connection(socket_ctx *sock, int  num, iomux_call_type iomux,
                  int idxc)
{
    iomux_evt_fd events[EVENTS_NUM];
    int rc;
    int i;

    for (i = 0; i < num; i++)
    {
        if (sock[i].accepted)
        {
            RING("sock[%d].accepted", i);
            continue;
        }

        if (sockts_is_op_done(sock[i].pco_iut))
        {
            RING("op is done %d, socket %d", i, sock[i].l);
            rc = iomux_call_test(iomux, sock + i, events);
            if (rc != 1)
                TEST_VERDICT("iomux call returned unexpected result %d", rc);
            if (events->revents != EVT_RD)
                TEST_VERDICT("iomux call returned unexpected event %s",
                             iomux_event_rpc2str(events->revents));
            if (events->fd != sock[i].l)
                TEST_VERDICT("iomux call returned unexpected fd");
            if (sock[i].addr != sock[idxc].addr)
                TEST_VERDICT("Connection request was received by a wrong "
                             "socket");

            sock[i].a = rpc_accept(sock[i].pco_iut, sock[i].l, NULL, 0);
            sock[i].accepted = TRUE;

            return sock + i;
        }
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
    const struct sockaddr  *tst1_addr = NULL;
    const struct sockaddr  *tst2_addr = NULL;
    iomux_call_type         iomux = IC_UNKNOWN;
    int     listeners_num;
    te_bool late_iomux;
    te_bool same_port;
    te_bool same_tst;

    socket_ctx   *sock = NULL;
    socket_ctx   *sock_a = NULL;
    int tst_s = -1;
    int i;
    int idxc;
    int init_cluster_sz;

    char name[32];

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    TEST_GET_INT_PARAM(listeners_num);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_BOOL_PARAM(late_iomux);
    TEST_GET_BOOL_PARAM(same_tst);
    TEST_GET_BOOL_PARAM(same_port);

    TEST_STEP("Set Onload cluster size.");
    CHECK_RC(tapi_sh_env_save_set_int(pco_iut, "EF_CLUSTER_SIZE",
                                      same_port && same_tst ? listeners_num :
                                                              listeners_num / 2,
                                      TRUE, NULL, &init_cluster_sz));


    sock = te_calloc_fill(listeners_num, sizeof(*sock), 0);

    if (same_tst)
    {
        TEST_STEP("Use the same IUT address for all sockets and only one tester "
                  "if @p same_tst is @c TRUE.");
        pco_tst2 = pco_tst1;
        iut_addr2 = iut_addr1;
    }
    else if (same_port)
    {
        uint16_t *port_ptr;

        TEST_STEP("Use the same port in both IUT addresses if @p same_port "
                  "is @c TRUE.");
        port_ptr = te_sockaddr_get_port_ptr(SA(iut_addr2));
        *port_ptr = *te_sockaddr_get_port_ptr(SA(iut_addr1));
    }

    TEST_STEP("Create @p listeners_num listener sockets, each socket in its thread. "
              "Bind sockets, set socket option @c SO_REUSEPORT. Call blocking "
              "iomux function if @p late_iomux is @c FALSE.");
    for (i = 0; i < listeners_num; i++)
    {
        TEST_STEP("Sockets are bound alternately to addresses @p iut_addr1 and "
                  "@p iut_addr2");
        sock[i].iface = i % 2;
        sock[i].addr = sock[i].iface ? iut_addr2 : iut_addr1;
        sock[i].pco_tst = sock[i].iface ? pco_tst2 : pco_tst1;
        if (same_tst)
            sock[i].tst_addr = tst1_addr;
        else
            sock[i].tst_addr = sock[i].iface ? tst2_addr : tst1_addr;
        sock[i].l = sock[i].a = -1;

        snprintf(name, sizeof(name), "iut_handler_%d", i);
        rcf_rpc_server_thread_create(pco_iut, name, &sock[i].pco_iut);

        create_listener(sock + i, same_tst && i > 0 || i > 1);

        if (!late_iomux)
        {
            sock[i].pco_iut->op = RCF_RPC_CALL;
            iomux_call_test(iomux, sock + i, NULL);
        }

    }

    if (late_iomux)
    {
        TEST_STEP("Call blocking iomux function if @p late_iomux is @c TRUE");
        for (i = 0; i < listeners_num; i++)
        {
            sock[i].pco_iut->op = RCF_RPC_CALL;
            iomux_call_test(iomux, sock + i, NULL);
        }
    }

    TAPI_WAIT_NETWORK;

    TEST_STEP("Connect to IUT listener sockets from tester hosts.");
    for (i = 0; i < MAX_ATTEMPTS; i++)
    {
        idxc = i % listeners_num;
        tst_s = rpc_socket(sock[idxc].pco_tst,
                           rpc_socket_domain_by_addr(sock[idxc].addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
        TAPI_SET_NEW_PORT(sock[idxc].pco_tst, sock[idxc].tst_addr);
        rpc_bind(sock[idxc].pco_tst, tst_s, sock[idxc].tst_addr);
        rpc_connect(sock[idxc].pco_tst, tst_s, sock[idxc].addr);
        TAPI_WAIT_NETWORK;

        sock_a = accept_connection(sock, listeners_num, iomux, idxc);
        if (sock_a != NULL)
        {
            sockts_test_connection(sock_a->pco_iut, sock_a->a,
                                   sock[idxc].pco_tst, tst_s);
            RPC_CLOSE(sock_a->pco_iut, sock_a->a);
        }
        RPC_CLOSE(sock[idxc].pco_tst, tst_s);

        TEST_STEP("Each listener socket must receive at least one connection for "
                  "success.");
        if (finish_testing(sock, listeners_num))
            break;
    }

    RING("Iterations number %d", i);

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

            if (sockts_is_op_done(sock[i].pco_iut))
            {
                CLEANUP_RPC_CLOSE(sock[i].pco_iut, sock[i].l);
                CLEANUP_RPC_CLOSE(sock[i].pco_iut, sock[i].a);
            }
            CLEANUP_CHECK_RC(rcf_rpc_server_destroy(sock[i].pco_iut));
        }
    }
    free(sock);

    CLEANUP_CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_CLUSTER_SIZE",
                                         init_cluster_sz, TRUE, TRUE));

    TEST_END;
}
