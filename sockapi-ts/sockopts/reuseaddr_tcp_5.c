/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page sockopts-reuseaddr_tcp_5 
 *
 * @objective Check that @c SO_REUSEADDR socket option allows binding two
 *            sockets to the same port but different addresses.
 *
 * @type conformance
 *
 * @reference @ref XNS5 section 8.1, @ref STEVENS
 *
 * @param pco_iut1      PCO on IUT
 * @param pco_iut2      PCO on IUT
 * @param iut_addr1     Network address assigned to one of interfaces on IUT
 * @param iut_addr2     Another network address assigned to one of interfaces
 *                      on IUT
 * @param one_wcard     Whether one of addresses should be wildcard or not
 * @param first_wcard   If one should be wildcard, should it be bound first
 * @param reuse_addr1   Set @c SO_REUSEADDR socket option on @p iut1_s socket
 * @param reuse_addr2   Set @c SO_REUSEADDR socket option on @p iut2_s socket
 *
 * @par Test sequence:
 * -# Create @p iut1_s socket of type @c SOCK_STREAM on @p pco_iut1.
 * -# Create @p iut2_s socket of type @c SOCK_STREAM on @p pco_iut2.
 * -# If @p reuse_addr1 is TRUE, Call @b setsockopt() enabling 
 *    @c SO_REUSEADDR socket option on @p iut1_s socket.
 * -# If @p reuse_addr2 is TRUE, Call @b setsockopt() enabling
 *    @c SO_REUSEADDR socket option on @p iut2_s socket.
 * -# @b bind() @p iut1_s socket to @p iut_addr1 address. Check that
 *    the function returns @c 0.
 * -# @b bind() @p iut2_s socket to @p iut_addr2 address. If
 *    @p reuse_addr1 is @c FALSE or @p reuse_addr2 is @c FALSE:
 *      - Check that it returns @c -1 and sets @b errno to @c EADDRINUSE;
 *      - Finish the test with success;
 *    else:
 *      - Check that it returns @c 0.
 * -# Call @b listen() on @p iut1_s. Check that it returns @c 0.
 * -# Call @b listen() on @p iut2_s. Check that it returns @c 0.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Establish connections with these two servers and check that they
 *    succeed.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close @p iut1_s and @p iut2_s sockets.
 * 
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/reuseaddr_tcp_5"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut1 = NULL;
    rcf_rpc_server *pco_iut2 = NULL;
    rcf_rpc_server *pco_tst1 = NULL;
    rcf_rpc_server *pco_tst2 = NULL;

    int             iut1_s = -1;
    int             iut2_s = -1;
    int             tst1_s = -1;
    int             tst2_s = -1;
    int             acc1_s = -1;
    int             acc2_s = -1;
    int             opt_val = 1;
    
    const struct sockaddr *iut_addr1 = NULL;
    const struct sockaddr *iut_addr2 = NULL;

    const struct sockaddr *first_addr = NULL;
    const struct sockaddr *second_addr = NULL;

    struct sockaddr_storage  name1;
    struct sockaddr_storage  name2;
    socklen_t                name1len = sizeof(name1);
    socklen_t                name2len = sizeof(name2);

    struct sockaddr_storage  wcadr_addr;

    te_bool                  one_wcard;
    te_bool                  wcard_first = FALSE;
    te_bool                  reuse_addr1;
    te_bool                  reuse_addr2;
    
    rpc_socket_domain domain;

    TEST_START;
    TEST_GET_PCO(pco_iut1);
    TEST_GET_PCO(pco_iut2);    
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);    
    TEST_GET_ADDR(pco_iut1, iut_addr1);
    TEST_GET_ADDR(pco_iut2, iut_addr2);

    TEST_GET_BOOL_PARAM(reuse_addr1);
    TEST_GET_BOOL_PARAM(reuse_addr2);

    TEST_GET_BOOL_PARAM(one_wcard);
    
    domain = rpc_socket_domain_by_addr(iut_addr1);
    
    if (one_wcard)
    {
        /* 
         * One of the addresses should be wildcard. should we bind wildcard
         * first?
         */
        TEST_GET_BOOL_PARAM(wcard_first);
        
        if (te_sockaddr_get_size(iut_addr1) > sizeof(wcadr_addr))
        {
            TEST_FAIL("The length of 'iut_addr1' is too short");
        }
        memcpy(&wcadr_addr, iut_addr1, te_sockaddr_get_size(iut_addr1));
        te_sockaddr_set_wildcard(SA(&wcadr_addr));
    }
    /* Copy port number of 'iut_addr1' to the port of 'iut_addr2' */
    /* FIXME Discard 'const' */
    te_sockaddr_set_port(SA(iut_addr2), te_sockaddr_get_port(iut_addr1));

    iut1_s = rpc_socket(pco_iut1, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    iut2_s = rpc_socket(pco_iut2, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
   
    if (reuse_addr1)
    {
        rpc_setsockopt(pco_iut1, iut1_s, RPC_SO_REUSEADDR, &opt_val);
    }
    if (reuse_addr2)
    {
        rpc_setsockopt(pco_iut2, iut2_s, RPC_SO_REUSEADDR, &opt_val);
    }

    if (one_wcard)
    {
        first_addr = wcard_first ? SA(&wcadr_addr) : iut_addr1;
        second_addr = !wcard_first ? SA(&wcadr_addr) : iut_addr2;
    }
    else
    {
        first_addr =iut_addr1;
        second_addr = iut_addr2;
    }

    rpc_bind(pco_iut1, iut1_s, first_addr);

    RPC_AWAIT_IUT_ERROR(pco_iut2);
    rc = rpc_bind(pco_iut2, iut2_s, second_addr);
    if (!one_wcard || (reuse_addr1 && reuse_addr2))
    {
        if (rc != 0)
        {
            TEST_VERDICT("Both sockets enable SO_REUSEADDR socket option "
                         "but bind() of the second socket fails with "
                         "errno %s", errno_rpc2str(RPC_ERRNO(pco_iut2)));
        }
    }
    else
    {
        if (rc != -1)
        {
            TEST_VERDICT("The first socket has %sabled SO_REUSEADDR "
                         "socket option and bound to %s address, "
                         "the second socket has %sabled SO_REUSEADDR "
                         "socket option, but bind() to %s address "
                         "returns success instead of expected failure "
                         "with EADDRINUSE errno",
                         reuse_addr1 ? "en" : "dis",
                         wcard_first ? "wildcard" : "unicast",
                         reuse_addr2 ? "en" : "dis",
                         !wcard_first ? "wildcard" : "unicast");
        }
        CHECK_RPC_ERRNO(pco_iut2, RPC_EADDRINUSE,
                        "The first socket has %sabled SO_REUSEADDR "
                        "socket option and bound to %s address, "
                        "the second socket has %sabled SO_REUSEADDR "
                        "socket option, bind() of the second socket "
                        "to %s address fails",
                        reuse_addr1 ? "en" : "dis",
                        wcard_first ? "wildcard" : "unicast",
                        reuse_addr2 ? "en" : "dis",
                        !wcard_first ? "wildcard" : "unicast");

        /* 
         * We do not use SO_REUSEADDR for the second socket so that 
         * no more actions can be done here, stop the test with success.
         */        
        TEST_SUCCESS;
    }

    RPC_AWAIT_IUT_ERROR(pco_iut1);
    rpc_listen(pco_iut1, iut1_s, SOCKTS_BACKLOG_DEF);
    if (rc == 0)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut2);
        rc = rpc_listen(pco_iut2, iut2_s, SOCKTS_BACKLOG_DEF);
    }
    if (rc != 0)
    {
        if (one_wcard)
        {
            TEST_VERDICT("Both sockets enable SO_REUSEADDR socket option, "
                         "one is bound to wildcard address, "
                         "but listen() fails with errno %s",
                         errno_rpc2str(RPC_ERRNO(pco_iut2)));
        }
        else
        {
            TEST_VERDICT("Sockets are bound to different IP addresses "
                         "and the same port, "
                         "but listen() fails with errno %s",
                         errno_rpc2str(RPC_ERRNO(pco_iut2)));
        }
    }

    /* Try to connect client sockets to the servers */
    tst1_s = rpc_socket(pco_tst1, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst2_s = rpc_socket(pco_tst2, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    
    /* To get ETIMEDOUT reliably >3min */
    pco_tst1->timeout = (5 * 60 * 1000);
    RPC_AWAIT_IUT_ERROR(pco_tst1);
    rc = rpc_connect(pco_tst1, tst1_s, iut_addr1);
    if (rc != 0)
    {
        TEST_VERDICT("connect() to the first address from peer "
                     "unexpectedly failed with errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_tst1)));
    }

    TAPI_WAIT_NETWORK;
    RPC_CHECK_READABILITY(pco_iut1, iut1_s, TRUE);
    RPC_CHECK_READABILITY(pco_iut2, iut2_s, FALSE);

    /* To get ETIMEDOUT reliably >3min */
    pco_tst2->timeout = (5 * 60 * 1000);
    RPC_AWAIT_IUT_ERROR(pco_tst2);
    rc = rpc_connect(pco_tst2, tst2_s, iut_addr2);
    if (rc != 0)
    {
        TEST_VERDICT("connect() to the second address from peer "
                     "unexpectedly failed with errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_tst2)));
    }

    TAPI_WAIT_NETWORK;
    RPC_CHECK_READABILITY(pco_iut1, iut1_s, TRUE);
    RPC_CHECK_READABILITY(pco_iut2, iut2_s, TRUE);

    /* Check that both sockets accept connection */
    /* Check which client socket is bound to which server */

    acc1_s = rpc_accept(pco_iut1, iut1_s, SA(&name1), &name1len);
    rpc_getsockname(pco_tst1, tst1_s, SA(&name2), &name2len);
    if (te_sockaddrcmp(SA(&name1), name1len, SA(&name2), name2len) != 0)
    {
        TEST_FAIL("Peer name of 'acc1_s' is not the same as "
                  "the name of 'tst1_s'");
    }

    acc2_s = rpc_accept(pco_iut2, iut2_s, SA(&name1), &name1len);
    rpc_getsockname(pco_tst2, tst2_s, SA(&name2), &name2len);
    if (te_sockaddrcmp(SA(&name1), name1len, SA(&name2), name2len) != 0)
    {
        TEST_FAIL("Peer name of 'acc2_s' is not the same as "
                  "the name of 'tst2_s'");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);
    CLEANUP_RPC_CLOSE(pco_iut1, iut1_s);
    CLEANUP_RPC_CLOSE(pco_iut2, iut2_s);
    CLEANUP_RPC_CLOSE(pco_iut1, acc1_s);
    CLEANUP_RPC_CLOSE(pco_iut2, acc2_s);

    TEST_END;
}

