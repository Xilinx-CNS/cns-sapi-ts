/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reuseport
 *
 * $Id$
 */

/** @page reuseport-reuseport_iomux Port sharing with blocking iomux
 *
 * @objective  Share port with SO_REUSEPORT option between a few sockets and
 *             use blocking iomux to wait connection requests.
 *
 * @param pco_iut        PCO on IUT.
 * @param pco_tst1       PCO on TST.
 * @param listeners_num  Listeners sockets number.
 * @param iomux          Iomux function name.
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

#define TE_TEST_NAME  "reuseport/reuseport_iomux"

#include "sockapi-test.h"
#include "reuseport.h"
#include "iomux.h"

#define MAX_SOCKETS 4

/**
 * Socket context.
 */
typedef struct socket_ctx {
    te_bool iface;               /**< Interface switcher */
    int     l;                   /**< Listener Socket */
    int     a[MAX_SOCKETS];      /**< Accepted sockets */
    int     cnt;                 /**< Accepted sockets counter */
    rcf_rpc_server *pco_tst;     /**< RPC server */
    const struct sockaddr *addr; /**< Address */
} socket_ctx;

/**
 * Set events array.
 * 
 * @param sock      Sockets list
 * @param events    Events array
 * @param num       Sockets number
 */
static void
set_events(socket_ctx *sock, iomux_evt_fd *events, int num)
{
    int i;

    for (i = 0; i < num; i++)
    {
        events[i].fd = sock[i].l;
        events[i].events = events[i].revents = EVT_RDWR;
    }
}

/**
 * Get socket contex in accordance to returned event.
 * 
 * @param events    Events array
 * @param sock      Sockets array
 * @param num       Sockets array length
 * 
 * @return Pointer to the socket context
 */
static socket_ctx *
get_socket_ctx(iomux_evt_fd *events, socket_ctx *sock, int num)
{
    int fd = -1;
    int i;

    for (i = 0; i < num; i++)
    {
        if (events[i].revents == EVT_RD)
        {
            fd = events[i].fd;
            break;
        }
    }

    for (i = 0; i < num; i++)
        if (sock[i].l == fd)
            return sock + i;

    TEST_VERDICT("Unknown fd was returned");
    return NULL;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_tst1 = NULL;
    rcf_rpc_server *pco_tst2 = NULL;
    rcf_rpc_server *pco_iut = NULL;
    const struct sockaddr  *iut_addr1 = NULL;
    const struct sockaddr  *iut_addr2 = NULL;
    iomux_call_type         iomux = IC_UNKNOWN;
    te_bool                 same_tst;
    te_bool                 same_port;
    int listeners_num;
    int init_cluster_sz;

    socket_ctx   *sock = NULL;
    socket_ctx   *acc = NULL;
    iomux_evt_fd *events = NULL;
    int tst_s;
    int i;
    int j;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_INT_PARAM(listeners_num);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_BOOL_PARAM(same_tst);
    TEST_GET_BOOL_PARAM(same_port);

    if (MAX_SOCKETS > listeners_num)
        TEST_FAIL("listeners_num must not exceed %d or limit should be "
                  "increased", MAX_SOCKETS);

    TEST_STEP("Set env EF_CLUSTER_SIZE equal to number of listener sockets.");
    CHECK_RC(tapi_sh_env_save_set_int(pco_iut, "EF_CLUSTER_SIZE",
                                      same_port && same_tst ? listeners_num :
                                                              listeners_num / 2,
                                      TRUE, NULL, &init_cluster_sz));

    sock = te_calloc_fill(listeners_num, sizeof(*sock), 0);
    events = te_calloc_fill(listeners_num, sizeof(*events), 0);

    if (same_tst)
    {
        TEST_STEP("Use the same IUT address for all sockets and only one tester.");
        pco_tst2 = pco_tst1;
        iut_addr2 = iut_addr1;
    }
    else if (same_port)
    {
        uint16_t *port_ptr;

        TEST_STEP("Assign to the second IUT address the same port number as the "
                  "first one has if @p same_port is @c TRUE.");
        port_ptr = te_sockaddr_get_port_ptr(SA(iut_addr2));
        *port_ptr = *te_sockaddr_get_port_ptr(SA(iut_addr1));
    }

    TEST_STEP("Open, bind and make non-blocking listener sockets.");
    for (i = 0; i < listeners_num; i++)
    {
        sock[i].iface = i % 2; 
        sock[i].addr = sock[i].iface ? iut_addr2 : iut_addr1;
        sock[i].pco_tst = sock[i].iface ? pco_tst2 : pco_tst1;

        sock[i].l = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr1),
                               RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_setsockopt_int(pco_iut, sock[i].l, RPC_SO_REUSEPORT, 1);

        rpc_bind(pco_iut, sock[i].l, sock[i].addr);
        rpc_listen(pco_iut, sock[i].l, 1);
        rpc_fcntl(pco_iut, sock[i].l, RPC_F_SETFL, RPC_O_NONBLOCK);
    }

    TEST_STEP("Set iomux events.");
    set_events(sock, events, listeners_num);

    TEST_STEP("Do the following steps @p listeners_num times:");
    for (i = 0; i < listeners_num; i++)
    {
        pco_iut->op = RCF_RPC_CALL;

        TEST_STEP("Call blocking iomux function.");
        iomux_call(iomux, pco_iut, events, listeners_num, NULL);

        TEST_STEP("Create tester socket and connect it to one of IUT addresses.");
        tst_s = rpc_socket(sock[i].pco_tst,
                           rpc_socket_domain_by_addr(sock[i].addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_connect(sock[i].pco_tst, tst_s, sock[i].addr);

        TEST_STEP("Determine which listener received connection with iomux.");
        rc = iomux_call(iomux, pco_iut, events, listeners_num, NULL);
        if (rc != 1)
            TEST_VERDICT("iomux call returned unexpected result %d", rc);
        acc = get_socket_ctx(events, sock, listeners_num);
        if (acc->pco_tst != sock[i].pco_tst)
            TEST_VERDICT("Socket accepted with wrong rpcs");

        TEST_STEP("Accept the connection.");
        acc->a[acc->cnt] = rpc_accept(pco_iut, acc->l, NULL, 0);
        sockts_test_connection(pco_iut, acc->a[acc->cnt], sock[i].pco_tst, tst_s);
        acc->cnt++;
        RPC_CLOSE(sock[i].pco_tst, tst_s);
    }

    TEST_SUCCESS;

cleanup:
    for (i = 0; i < listeners_num; i++)
    {
        CLEANUP_RPC_CLOSE(pco_iut, sock[i].l);

        for (j = 0; j < sock[i].cnt; j++)
            CLEANUP_RPC_CLOSE(pco_iut, sock[i].a[j]);
    }

    free(sock);
    free(events);

    CLEANUP_CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_CLUSTER_SIZE",
                                         init_cluster_sz, TRUE, TRUE));

    TEST_END;
}
