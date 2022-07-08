/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * IOCTL Requests
 *
 * $Id$
 */

/** @page sockopts-reuseaddr_tcp_2 Usage of SO_REUSEADDR socket option with TCP client sockets
 *
 * @objective Check that @c SO_REUSEADDR socket option allows two TCP 
 *            clients be bound to the same local address as soon as 
 *            one of them connects to a peer.
 *
 * @type conformance
 *
 * @reference @ref XNS5 section 8.1, @ref STEVENS
 *
 * @param pco_iut1  PCO on IUT
 * @param pco_iut2  PCO on IUT
 * @param pco_tst   PCO on TESTER
 *
 * @par Test sequence:
 * -# Create @p tst_srv1 socket of type @c SOCK_STREAM on @p pco_tst.
 * -# Create @p tst_srv2 socket of type @c SOCK_STREAM on @p pco_tst.
 * -# @b bind() @p tst_srv1 socket to @p srv_addr1.
 * -# @b bind() @p tst_srv2 socket to @p srv_addr2.
 * -# Call @b listen() on @p tst_srv1 and @p tst_srv2 sockets.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Create @p iut1_s socket of type @c SOCK_STREAM on @p pco_iut1.
 * -# Create @p iut2_s socket of type @c SOCK_STREAM on @p pco_iut2.
 * -# Call @b setsockopt() enabling @c SO_REUSEADDR socket option on
 *    @p iut1_s and @p pco_iut2 sockets.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# @b bind() @p iut1_s socket to a local address @p iut_addr
 *    (network address  and port).
 * -# @b connect @p iut1_s socket to @p srv_addr1 address using needed 
 *    function.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# @b bind() @p iut2_s socket to @p iut_addr, the same address as
 *    @p iut1_s socket is bound to.
 * -# Check that the function returns @c 0
 *    (since @p iut1_s socket is connected, it is allowed to bind another
 *    socket to the same address).
 * -# @b connect @p iut2_s socket to @p srv_addr1 address using needed 
 *    function.
 * -# Check that the function returns @c -1 and sets @b errno to
 *    @c EADDRINUSE (@c EADDRNOTAVAIL in Linux).
 * -# @b connect @p iut2_s socket to @p srv_addr2 address using needed 
 *    function.
 * -# Check that the function returns @c 0.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b accept() with location for peer name on @p tst_srv1 socket.
 * -# Check that it returns a new socket descriptor @p tst_acc1.
 * -# Call @b accept() with location for peer name on @p tst_srv2 socket.
 * -# Check that it returns a new socket descriptor @p tst_acc2.
 * -# Check that peer names are the same.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Create a buffer @p tx_buf1 of @p buf1_len.
 * -# Create a buffer @p tx_buf2 of @p buf2_len.
 * -# Create a buffer @p rx_buf1 of @p buf1_len.
 * -# Create a buffer @p rx_buf2 of @p buf2_len.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b send(@p tst_acc1, @p tx_buf1, @p buf1_len, 0).
 * -# Let socket receiving data be @p iut_conn1, and another IUT socket
 *    be @p iut_conn2.
 * -# Call @b send(@p tst_acc2, @p tx_buf2, @p buf2_len, 0).
 * -# Call @b recv(@p iut_conn1, @p rx_buf1, @p buf1_len, 0).
 * -# Call @b recv(@p iut_conn2, @p rx_buf2, @p buf2_len, 0).
 * -# Check that the content of @p tx_buf1 and @p rx_buf1 buffers 
 *    are the same.
 * -# Check that the content of @p tx_buf2 and @p rx_buf2 buffers 
 *    are the same.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Delete all the buffers.
 * -# Close all the sockets.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 * @author Dmitrij Komoltsev <Dmitrij.Komoltsev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/reuseaddr_tcp_2"

#include "sockapi-test.h"
#include "tapi_cfg.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut1 = NULL;
    rcf_rpc_server *pco_iut2 = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rcf_rpc_server *pco_iut_conn1 = NULL;
    rcf_rpc_server *pco_iut_conn2 = NULL;

    int             iut1_s = -1;
    int             iut2_s = -1;
    int             tst_srv1 = -1;
    int             tst_srv2 = -1;
    int             tst_acc1 = -1;
    int             tst_acc2 = -1;
    int             iut_conn1 = -1;
    int             iut_conn2 = -1;
    int             opt_val = 1;
    void           *tx_buf1 = NULL;
    void           *tx_buf2 = NULL;
    void           *rx_buf1 = NULL;
    void           *rx_buf2 = NULL;
    size_t          buf1_len;
    size_t          buf2_len;

    const struct sockaddr   *iut_addr = NULL;
    const struct sockaddr   *srv_addr1 = NULL;
    const struct sockaddr   *srv_addr2 = NULL;

    struct sockaddr_storage  name1;
    struct sockaddr_storage  name2;
    socklen_t                name1len = sizeof(name1);
    socklen_t                name2len = sizeof(name2);

    te_bool route_added = FALSE;

    rpc_socket_domain domain;

    int                      ret;

    te_bool     is_failed = FALSE;
    te_bool     is_readable = FALSE;
    te_bool     first_readable = FALSE;
    te_bool     both_conn_same_srv = FALSE;
    

    TEST_START;
    TEST_GET_PCO(pco_iut1);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut1, iut_addr);
    TEST_GET_ADDR(pco_tst, srv_addr1);
    TEST_GET_ADDR(pco_tst, srv_addr2);
    
    
    domain = rpc_socket_domain_by_addr(iut_addr);

    /* Don't add route if tst and iut are on same host */
    if (strcmp(pco_tst->ta, pco_iut1->ta))
    {
        /** @todo Temporary solution is to add a route */
        if (tapi_cfg_add_route_via_gw(pco_iut1->ta,
                addr_family_rpc2h(sockts_domain2family(domain)),
                te_sockaddr_get_netaddr(srv_addr2),
                te_netaddr_get_size(addr_family_rpc2h(
                                       sockts_domain2family(domain))) * 8,
                te_sockaddr_get_netaddr(srv_addr1)) != 0)
            {
                TEST_FAIL("Cannot add route");
            }
        route_added = TRUE;
    }
    CFG_WAIT_CHANGES;

    tst_srv1 = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_srv2 = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_bind(pco_tst, tst_srv1, srv_addr1);
    rpc_bind(pco_tst, tst_srv2, srv_addr2);

    rpc_listen(pco_tst, tst_srv1, SOCKTS_BACKLOG_DEF);
    rpc_listen(pco_tst, tst_srv2, SOCKTS_BACKLOG_DEF);

    iut1_s = rpc_socket(pco_iut1, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    iut2_s = rpc_socket(pco_iut2, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_setsockopt(pco_iut1, iut1_s, RPC_SO_REUSEADDR, &opt_val);
    rpc_setsockopt(pco_iut2, iut2_s, RPC_SO_REUSEADDR, &opt_val);

    rpc_bind(pco_iut1, iut1_s, iut_addr);

    rpc_connect(pco_iut1, iut1_s, srv_addr1);

    RPC_AWAIT_IUT_ERROR(pco_iut2);
    ret = rpc_bind(pco_iut2, iut2_s, iut_addr);
    if (ret != 0)
    {
        TEST_VERDICT("bind() of the second socket to the same "
                     "address/port fails with errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut2)));
    }
    rpc_getsockname(pco_iut2, iut2_s, SA(&name2), &name2len);
    if (te_sockaddrcmp(iut_addr, te_sockaddr_get_size(iut_addr),
                       SA(&name2), name2len) != 0)
    {
        TEST_VERDICT("Local address/port is not not the same as "
                     "the socket has just been bound to");
    }

    /* To get ETIMEDOUT reliably >3min */
    pco_iut2->timeout = (5 * 60 * 1000);
    RPC_AWAIT_IUT_ERROR(pco_iut2);

    rc = rpc_connect(pco_iut2, iut2_s, srv_addr1);
    if (rc >= 0)
    {
        ERROR_VERDICT("It is possible to connect two sockets "
                      "bound to the same local address to the "
                      "same remote address");
        is_failed = TRUE;
        both_conn_same_srv = TRUE;
    } 
    else
    {
        if (RPC_ERRNO(pco_iut2) == RPC_EADDRINUSE)
        {
            /* It is the most logical and expected behaviour */
        }
        else if (RPC_ERRNO(pco_iut2) == RPC_EADDRNOTAVAIL)
        {
            RING_VERDICT("Attempt to create one more connection with "
                         "the same parameters failed with errno "
                         "EADDRNOTAVAIL");
        }
        else
        {
            TEST_VERDICT("Attempt to create one more connection with "
                         "the same parameters failed with unexpected "
                         "errno %s",
                         errno_rpc2str(RPC_ERRNO(pco_iut2)));
        }

        rpc_getsockname(pco_iut2, iut2_s, SA(&name2), &name2len);
        if (te_sockaddrcmp(iut_addr, te_sockaddr_get_size(iut_addr),
                           SA(&name2), name2len) != 0)
        {
            TEST_VERDICT("connect() which failed because of used "
                         "address changed local address/port "
                         "the socket is bound to");
        }

        rpc_connect(pco_iut2, iut2_s, srv_addr2);
    }

    tst_acc1 = rpc_accept(pco_tst, tst_srv1, SA(&name1), &name1len);
    tst_acc2 = rpc_accept(pco_tst, both_conn_same_srv ? tst_srv1 : tst_srv2,
                          SA(&name2), &name2len);

    if (te_sockaddrcmp(SA(&name1), name1len, SA(&name2), name2len) != 0)
        TEST_VERDICT("Peer name of 'tst_acc1' is not the same as "
                     "peer name of 'tst_acc2'");

    CHECK_NOT_NULL(tx_buf1 = sockts_make_buf_stream(&buf1_len));
    CHECK_NOT_NULL(tx_buf2 = sockts_make_buf_stream(&buf2_len));
    CHECK_NOT_NULL(rx_buf1 = calloc(1, buf1_len));
    CHECK_NOT_NULL(rx_buf2 = calloc(1, buf2_len));

    RPC_SEND(rc, pco_tst, tst_acc1, tx_buf1, buf1_len, 0);
    TAPI_WAIT_NETWORK;

    /*
     * The following renaming of IUT sockets is done since
     * accept() order cannot be trusted.
     */
    RPC_GET_READABILITY(is_readable, pco_iut1, iut1_s, 1000);
    if (is_readable)
    {
        iut_conn1 = iut1_s;
        pco_iut_conn1 = pco_iut1;
        iut_conn2 = iut2_s;
        pco_iut_conn2 = pco_iut2;
        first_readable = TRUE;
    }
    else
    {
        iut_conn1 = iut2_s;
        pco_iut_conn1 = pco_iut2;
        iut_conn2 = iut1_s;
        pco_iut_conn2 = pco_iut1;
        first_readable = FALSE;
    }

    RPC_GET_READABILITY(is_readable, pco_iut_conn2, iut_conn2, 1000);
    if (is_readable && first_readable)
        TEST_VERDICT("We sent data only via the first accepted "
                     "connection but both peer sockets received "
                     "something");
    else if (!is_readable && !first_readable)
        TEST_VERDICT("No one peer socket can receive data");

    RPC_SEND(rc, pco_tst, tst_acc2, tx_buf2, buf2_len, 0);
    TAPI_WAIT_NETWORK;

    rc = rpc_recv(pco_iut_conn1, iut_conn1, rx_buf1, buf1_len, 0);
    if (rc != (int)buf1_len)
    {
        ERROR_VERDICT("Peer of the firstly accepted connection "
                      "received unexpected amount of data");
        is_failed = TRUE;
    }
    rc = rpc_recv(pco_iut_conn2, iut_conn2, rx_buf2, buf2_len, 0);
    if (rc != (int)buf2_len)
    {
        ERROR_VERDICT("Peer of the secondly accepted connection "
                      "received unexpected amount of data");
        is_failed = TRUE;
    }

    if (memcmp(tx_buf1, rx_buf1, buf1_len) != 0)
    {
        ERROR_VERDICT("Peer of the firstly accepted connection "
                      "received incorrect data");
        is_failed = TRUE;
    }
    if (memcmp(tx_buf2, rx_buf2, buf2_len) != 0)
    {
        ERROR_VERDICT("Peer of the secondly accepted connection "
                      "received incorrect data");
        is_failed = TRUE;
    }

    RPC_SEND(rc, pco_iut_conn1, iut_conn1, tx_buf1, buf1_len, 0);
    RPC_SEND(rc, pco_iut_conn2, iut_conn2, tx_buf2, buf2_len, 0);

    rc = rpc_recv(pco_tst, tst_acc1, rx_buf1, buf1_len, 0);
    if (rc != (int)buf1_len)
    {   
        ERROR_VERDICT("Incorrect amount of data is received from a peer "
                      "of the firstly accepted connection");
        is_failed = TRUE;
    }

    rc = rpc_recv(pco_tst, tst_acc2, rx_buf2, buf2_len, 0);
    if (rc != (int)buf2_len)
    {   
        ERROR_VERDICT("Incorrect amount of data is received from a peer "
                      "of the secondly accepted connection");
        is_failed = TRUE;
    }

    if (memcmp(tx_buf1, rx_buf1, buf1_len) != 0)
    {
        ERROR_VERDICT("From the firstly accepted connection "
                      "incorrect data is received");
        is_failed = TRUE;
    }
    if (memcmp(tx_buf2, rx_buf2, buf2_len) != 0)
    {
        ERROR_VERDICT("From the secondly accepted connection "
                      "incorrect data is received");
        is_failed = TRUE;
    }

    if (is_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:
    free(tx_buf1);
    free(tx_buf2);
    free(rx_buf1);
    free(rx_buf2);

    CLEANUP_RPC_CLOSE(pco_iut1, iut1_s);
    CLEANUP_RPC_CLOSE(pco_iut2, iut2_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_srv1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_srv2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_acc1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_acc2);

    if (route_added)
    {
        /** @todo Temporary solution is to add a route */
        if (tapi_cfg_del_route_via_gw(pco_iut1->ta,
                addr_family_rpc2h(
                sockts_domain2family(domain)),
                te_sockaddr_get_netaddr(srv_addr2),
                te_netaddr_get_size(addr_family_rpc2h(
                    sockts_domain2family(domain))) * 8,
                te_sockaddr_get_netaddr(srv_addr1)) != 0)
        {
            ERROR("Cannot delete earlier added route");
            result = EXIT_FAILURE;
        }
    }

    TEST_END;
}

