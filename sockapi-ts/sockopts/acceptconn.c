/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * IOCTL Requests
 *
 * $Id$
 */

/** @page sockopts-acceptconn Usage of SO_ACCEPTCONN socket option
 *
 * @objective Check that @c SO_ACCEPTCONN socket option is read-only, and it
 * is enabled only on listening sockets.
 *
 * @type conformance
 *
 * @reference @ref XNS5 section 8.1, @ref STEVENS
 *
 * @param sock_type     Type of socket used in the test
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * 
 * @par Test sequence:
 * -# Create @p iut_s socket of type @p sock_type on @b pco_iut.
 * -# Create @p tst_s socket of type @p sock_type on @b pco_tst.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b setsockopt() with @c SO_ACCEPTCONN socket option on @p iut_s 
 *    socket passing as the value of @a option_value parameter pointer to 
 *    the memory containing @c 0 and @c 1.
 * -# Check that the function returns @c -1 and sets @b errno to 
 *    @c ENOPROTOOPT for both values (it is read-only option).
 * -# Call @b getsockopt() with @c SO_ACCEPTCONN socket option on 
 *    @p iut_s socket.
 * -# Check that the function returns @c 0, and updates @a option_value 
 *    parameter with @c 0 (does not accept incoming
 *    connections).
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# @b bind() @p iut_s socket to a local address.
 * -# Call @b getsockopt() with @c SO_ACCEPTCONN socket option on
 *    @p iut_s socket.
 * -# Check that the function returns @c 0, and updates @a option_value
 *    parameter with @c 0.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# The following steps should be performed if @p sock_type parameter
 *    equals to @c SOCK_STREAM:
 *        -# Call @b listen() on @p iut_s socket;
 *        -# Call @b getsockopt() with @c SO_ACCEPTCONN socket option 
 *           on @p iut_s socket;
 *        -# Check that the function returns @c 0 and updates 
 *           @a option_value parameter with @c 1 (the socket accepts
 *           incoming connections);
 *        -# Call @b setsockopt() with @c SO_ACCEPTCONN socket option 
 *           on @p iut_s socket passing as the value of @a option_value 
 *           parameter pointer to the memory containing @c 0 and @c 1;
 *        -# Check that the function returns @c -1 and sets @b errno to 
 *           @c ENOPROTOOPT for both values (it is read-only option);
 *           \n @htmlonly &nbsp; @endhtmlonly
 *        -# @b connect() @p tst_s socket to @p iut_s socket;
 *        -# Call @b accept() on @p iut_s socket to get a new @p accepted_s 
 *           socket;
 *        -# Call @b getsockopt() with @c SO_ACCEPTCONN socket option on
 *           @p accepted_s socket;
 *        -# Check that the function returns @c 0, and updates 
 *           @a option_value parameter with 0;
 *        -# Call @b getsockopt() with @c SO_ACCEPTCONN socket option on
 *           @p iut_s socket;
 *        -# Check that the function returns @c 0, and updates 
 *           @a option_value parameter with 1 (the value of the option on
 *           listening socket is not changed after @b accept()).
 *           \n @htmlonly &nbsp; @endhtmlonly
 *        .
 * -# Close @p iut_s, @p accepted_s, and @p tst_s sockets.
 *    
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/acceptconn"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;
    int             accepted_s = -1;

    rpc_socket_type          sock_type;
    const struct sockaddr   *iut_addr;
    const struct sockaddr   *tst_addr;
    struct sockaddr_storage  wildcard_addr;
    int                    opt_val;
    int                    listen_opt_val;
    unsigned int           i;

    int opt_val_to_set[] = { -1, 0, 1, 2 };

    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                       sock_type, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                       sock_type, RPC_PROTO_DEF);

    for (i = 0; i < sizeof(opt_val_to_set) / sizeof(opt_val_to_set[0]); i++)
    {
        opt_val = opt_val_to_set[i];

        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_setsockopt(pco_iut, iut_s, RPC_SO_ACCEPTCONN, &opt_val);
        if (rc != -1)
        {
            TEST_FAIL("setsockopt(SOL_SOCKET, SO_ACCEPTCONN, %d) "
                      "returns %d, but it is expected to return -1",
                      opt_val, rc);
        }
        CHECK_RPC_ERRNO(pco_iut, RPC_ENOPROTOOPT,
                "setsockopt(SOL_SOCKET, SO_ACCEPTCONN, %d) returns -1");
    }

    rpc_getsockopt(pco_iut, iut_s, RPC_SO_ACCEPTCONN, &opt_val);
    if (opt_val != 0)
    {
        TEST_FAIL("SO_ACCEPTCONN option value on non listening socket "
                  "is %d, but it is expected to be 0", opt_val);
    }

    memcpy(&wildcard_addr, iut_addr, te_sockaddr_get_size(iut_addr));
    te_sockaddr_set_wildcard(SA(&wildcard_addr));
    rpc_bind(pco_iut, iut_s, SA(&wildcard_addr));
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_ACCEPTCONN, &opt_val);
    if (opt_val != 0)
    {
        TEST_FAIL("SO_ACCEPTCONN option value after bind() is changed "
                  "to %d, but it is expected to be 0", opt_val);
    }

    if (sock_type == RPC_SOCK_STREAM)
    {
        rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
        rpc_getsockopt(pco_iut, iut_s, RPC_SO_ACCEPTCONN, &listen_opt_val);
        if (listen_opt_val == 0)
        {
            TEST_FAIL("SO_ACCEPTCONN option value on listening socket "
                      "is 0, but it is expected to be non-zero");
        }
        else if (listen_opt_val != 1)
        {
            RING_VERDICT("SO_ACCEPTCONN option value on listening "
                         "socket is %d", listen_opt_val);
        }
    
        /* Try to set up SO_ACCEPTCONN option on listening socket */
        for (i = 0;
             i < sizeof(opt_val_to_set) / sizeof(opt_val_to_set[0]);
             i++)
        {
            opt_val = opt_val_to_set[i];
            
            RPC_AWAIT_IUT_ERROR(pco_iut);
            rc = rpc_setsockopt(pco_iut, iut_s, RPC_SO_ACCEPTCONN, &opt_val);
            if (rc != -1)
            {
                TEST_FAIL("setsockopt(SOL_SOCKET, SO_ACCEPTCONN, %d) "
                      "on listening socket returns %d, but it is expected "
                      "to return -1", opt_val, rc);
            }
            CHECK_RPC_ERRNO(pco_iut, RPC_ENOPROTOOPT,
                    "setsockopt(SOL_SOCKET, SO_ACCEPTCONN, %d) returns -1");
        }    
        
        rpc_connect(pco_tst, tst_s, iut_addr);
        accepted_s = rpc_accept(pco_iut, iut_s, NULL, NULL);
    
        rpc_getsockopt(pco_iut, accepted_s, RPC_SO_ACCEPTCONN, &opt_val);
        if (opt_val != 0)
        {
            TEST_FAIL("SO_ACCEPTCONN option value on non listening socket "
                      "is %d, but it is expected to be 0", opt_val);
        }
        rpc_getsockopt(pco_iut, iut_s, RPC_SO_ACCEPTCONN, &opt_val);
        if (opt_val != listen_opt_val)
        {
            TEST_FAIL("SO_ACCEPTCONN option value on listening socket is "
                      "changed after calling accept() to %d, but it is "
                      "expected to be %d", opt_val, listen_opt_val);
        }
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, accepted_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    
    TEST_END;
}
 
