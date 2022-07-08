/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page sockopts-reuseaddr_tcp_4 Usage of SO_REUSEADDR socket option with TCP server sockets
 *
 * @objective Check that @c SO_REUSEADDR socket option can be used for server
 *            sockets allowing them quick restart after closing.
 *
 * @type conformance
 *
 * @reference @ref XNS5 section 8.1, @ref STEVENS
 *
 * @param pco_iut1  PCO on IUT
 * @param pco_iut2  PCO on IUT
 * @param pco_tst   PCO on TESTER
 *
 * @param reuse_addr1  Set @c SO_REUSEADDR socket option on @p iut1_s socket
 * @param reuse_addr2  Set @c SO_REUSEADDR socket option on @p iut2_s socket
 * @param connections  Number of accepted connections
 *
 * @par Test sequence:
 * -# Create @p tst_s socket of type @c SOCK_STREAM on @p pco_tst.
 * -# Create @p iut1_s socket of type @c SOCK_STREAM on @p pco_iut1.
 * -# Create @p iut2_s socket of type @c SOCK_STREAM on @p pco_iut2.
 * -# According with @p reuse_addr1 and @p reuse_addr2 parameters, 
 *    call @b setsockopt() enabling @c SO_REUSEADDR socket option on 
 *    @p iut1_s and @p iut2_s sockets.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# @b bind() @p iut1_s socket to a local address @p iut_addr 
 *    (network address and port).
 * -# Call @b listen() on @p iut1_s socket.
 * -# Connect @p connections sockets from @p pco_tst to @p iut1_s.
 * -# Connect one loopback socket from @pco_iut2 to @p iut1_s.
 * -# Call @b bind() on @p iut2_s socket specifying @p iut_addr as the 
 *    value of @a address parameter.
 * -# Check that the function returns @c -1 and sets @b errno to @c EADDRINUSE.
 * -# Close @p iut1_s socket - server socket.
 * -# Call @b bind() on @p iut2_s socket specifying @p iut_addr as the 
 *    value of @a address parameter.
 * -# Depending on @p reuse_addr1 and @p reuse_addr2 parameters expect
 *    either success or fail. Finish test in case of fail.
 * -# In case of success on previous step, call @b listen() on
 *    @p iut2_s socket.
 * -# Check that the function returns @c 0.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b getsockname() on @p iut2_s and socket and soccket accepted
 *    on @p pco_iut1.
 * -# Check that they have the same addresses.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Connect one more socket from both @p pco_iut1 and @pco_tst.
 *    Check the connection.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close sockets.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/reuseaddr_tcp_4"

#include "sockapi-test.h"

/* Number of bytes used in send/receive buffer */
#define DATA_BULK   200
/* Maximum number of accepted connections */
#define MAX_CONN    256

static inline te_bool
is_loop4(rcf_rpc_server *pco)
{
    int loop_mode;
    int rc = 0;

    rc = tapi_sh_env_get_int(pco, "EF_TCP_CLIENT_LOOPBACK", &loop_mode);

    return rc == 0 && loop_mode == 4;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut1 = NULL;
    rcf_rpc_server        *pco_iut2 = NULL;
    rcf_rpc_server        *pco_tst  = NULL;
    int                    iut1_s = -1; /* Socket on pco_iut1 */
    int                    iut2_s = -1; /* Socket on pco_iut2 */
    int                    tst_s[MAX_CONN]; /* Sockets on pco_tst */
    int                    acc1_s[MAX_CONN]; /* Sockets accepted on
                                              * pco_iut1 */
    int                    acc2_s[2]; /* Sockets accepted on pco_iut2 */
    int                    iut1_lb_s = -1; /* Socket on pco_iut1 for loopback
                                            * connection */
    int                    iut2_lb_s = -1; /* Socket on pco_iut2 for loopback
                                            * connection */
    int                    aux_s1 = -1;
    int                    aux_s2 = -1;

    int                    opt_val;
    const struct sockaddr *iut_addr;
    unsigned char         *tx_buf = NULL;
    unsigned char         *rx_buf = NULL;
    size_t                 buf_len = DATA_BULK;

    struct sockaddr_storage iut2_s_addr;
    socklen_t               iut2_s_addrlen = sizeof(iut2_s_addr);
    struct sockaddr_storage acc_s_addr;
    socklen_t               acc_s_addrlen = sizeof(acc_s_addr);

    te_bool                reuse_addr1;
    te_bool                reuse_addr2;
    int                    connections;
    int                    loglevel = -1;
    te_bool                done;

    int                    i = 0; /* Number of currently accepted sockets */

    TEST_START;
    TEST_GET_PCO(pco_iut1);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_tst);
    TEST_GET_BOOL_PARAM(reuse_addr1);
    TEST_GET_BOOL_PARAM(reuse_addr2);
    TEST_GET_INT_PARAM(connections);
    TEST_GET_ADDR(pco_iut1, iut_addr);

    /*
     * ST-2054:
     * - loop4
     * - connections=210
     * - loopback env
     * results in a lot of logging on the serial console. Disable it.
     */
    if (connections > 200 &&
        is_loop4(pco_iut1) &&
        tapi_get_addr_type(&env, "iut_addr") == TAPI_ENV_ADDR_LOOPBACK)
    {
        TEST_STEP("Decrease console log level");
        TAPI_SYS_LOGLEVEL_DEBUG(pco_iut1, &loglevel);
    }

    iut1_s = rpc_socket(pco_iut1, rpc_socket_domain_by_addr(iut_addr),
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);
    iut2_s = rpc_socket(pco_iut2, rpc_socket_domain_by_addr(iut_addr),
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);
    iut1_lb_s = rpc_socket(pco_iut1, rpc_socket_domain_by_addr(iut_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
    iut2_lb_s = rpc_socket(pco_iut2, rpc_socket_domain_by_addr(iut_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
    aux_s2 = rpc_socket(pco_iut2, rpc_socket_domain_by_addr(iut_addr),
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);
    acc2_s[0] = acc2_s[1] = -1;

    CHECK_NOT_NULL(tx_buf = te_make_buf_by_len(buf_len));
    CHECK_NOT_NULL(rx_buf = te_make_buf_by_len(buf_len));

    opt_val = 1;
    if (reuse_addr1)
    {
        rpc_setsockopt(pco_iut1, iut1_s, RPC_SO_REUSEADDR, &opt_val);
    }
    if (reuse_addr2)
    {
        rpc_setsockopt(pco_iut2, iut2_s, RPC_SO_REUSEADDR, &opt_val);
    }


    /* Switch 'iut1_s' socket in listening state */
    rpc_bind(pco_iut1, iut1_s, iut_addr);
    rpc_listen(pco_iut1, iut1_s, SOCKTS_BACKLOG_DEF);

    /* Create connections */
    for ( i = 0; i < connections; i++)
    {
        tst_s[i] = rpc_socket(pco_tst, rpc_socket_domain_by_addr(iut_addr),
                              RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_connect(pco_tst, tst_s[i], iut_addr);
        acc1_s[i] = rpc_accept(pco_iut1, iut1_s, NULL, 0);
    }
    aux_s1 = rpc_socket(pco_tst, rpc_socket_domain_by_addr(iut_addr),
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_connect(pco_iut2, iut2_lb_s, iut_addr);
    tst_s[i] = -1;
    acc1_s[i++] = rpc_accept(pco_iut1, iut1_s, NULL, 0);

    /*
     * Try to bind 'iut2_s' socket to 'iut_addr': at the moment there is 
     * a server socket listening on 'iut_addr' address, so that even with
     * SO_REUSEADDR socket optnio enabled this operation should fail.
     */
    RPC_AWAIT_IUT_ERROR(pco_iut2);
    rc = rpc_bind(pco_iut2, iut2_s, iut_addr);
    if (rc != -1)
    {
        TEST_VERDICT("bind() on 'iut2_s' socket to 'iut_addr' returns %d "
                     "instead of -1", rc);
    }
    CHECK_RPC_ERRNO(pco_iut2, RPC_EADDRINUSE, "bind() on 'iut2_s' "
                    "socket to 'iut_addr' returns -1, but");

    /* Close 'iut1_s' - server socket */
    RPC_CLOSE(pco_iut1, iut1_s);

    RPC_AWAIT_IUT_ERROR(pco_tst);
    pco_tst->op = RCF_RPC_CALL;
    rpc_connect(pco_tst, aux_s1, iut_addr);
    TAPI_WAIT_NETWORK;
    rcf_rpc_server_is_op_done(pco_tst, &done);
    if (!done)
        TEST_VERDICT("connect() to unused port is hanging.");
    RPC_AWAIT_IUT_ERROR(pco_tst);
    pco_tst->op = RCF_RPC_WAIT;
    rc = rpc_connect(pco_tst, aux_s1, iut_addr);
    if (rc != -1)
        TEST_VERDICT("connect() to unused port returned strange error.");
    CHECK_RPC_ERRNO(pco_tst, RPC_ECONNREFUSED, "connect() to unused "
                    "port returned -1");

    RPC_AWAIT_IUT_ERROR(pco_iut2);
    rpc_connect(pco_iut2, aux_s2, iut_addr);
    if (rc != -1)
        TEST_VERDICT("connect() to unused port via loopback returned "
                     "strange error.");
    CHECK_RPC_ERRNO(pco_tst, RPC_ECONNREFUSED, "connect() to unused "
                    "port via loopback returned -1");

    /* Try to bind 'iut2_s' socket to 'iut_addr' once again */
    RPC_AWAIT_IUT_ERROR(pco_iut2);
    rc = rpc_bind(pco_iut2, iut2_s, iut_addr);
    if (reuse_addr1 && reuse_addr2)
    {
        if (rc != 0)
        {
            TEST_VERDICT("bind() on 'iut2_s' socket to 'iut_addr' "
                         "returns %d instead of 0, although 'iut1_s' "
                         "has already been closed", rc);
        }
    }
    else
    {
        if (rc != -1)
        {
            TEST_VERDICT("Second bind unexepectedly succeed without "
                         "SO_REUSEADDR option being set on both sockets");
        }
        CHECK_RPC_ERRNO(pco_iut2, RPC_EADDRINUSE,
                        "Second bind failed, but");
        TEST_SUCCESS;
    }

    RPC_AWAIT_IUT_ERROR(pco_iut2);
    rc = rpc_listen(pco_iut2, iut2_s, SOCKTS_BACKLOG_DEF);
    if (rc != 0)
    {
        TEST_FAIL("listen() on 'iut2_s' socket to 'iut_addr' "
                  "returns %d instead of 0, although bind() "
                  "successfully completes", rc);
    }

    /* Compare addresses of iut2_s and acc1_s sockats */
    rpc_getsockname(pco_iut2, iut2_s, SA(&iut2_s_addr), &iut2_s_addrlen);
    rpc_getsockname(pco_iut1, acc1_s[0], SA(&acc_s_addr), &acc_s_addrlen);
    if (te_sockaddrcmp(SA(&iut2_s_addr), iut2_s_addrlen,
                       SA(&acc_s_addr), acc_s_addrlen) != 0)
    {
        TEST_FAIL("Local addresses of 'iut2_s' and 'acc_s' are different");
    }

/**
 * Macro for testing the connection between @p _sock1 and @p _sock2 by
 * sending some data.
 */
#define CHECK_CONNECTION(_pco1, _sock1, _pco2, _sock2)  \
do {                                                                    \
    RPC_SEND(rc, _pco2, _sock2, tx_buf, buf_len, 0);                    \
    rc = rpc_recv(_pco1, _sock1, rx_buf, buf_len, 0);                   \
                                                                        \
    if ((rc != (int)buf_len) || (memcmp(tx_buf, rx_buf, buf_len) != 0)) \
    {                                                                   \
        TEST_FAIL("Some data was corrupted while sending from"          \
                  "%s to %s", #_pco2, #_pco1);                          \
    }                                                                   \
} while (0)

    /* Create more connections, test them */
    tst_s[i] = rpc_socket(pco_tst, rpc_socket_domain_by_addr(iut_addr),
                          RPC_SOCK_STREAM, RPC_PROTO_DEF);

    RPC_AWAIT_IUT_ERROR(pco_tst);
    rc = rpc_connect(pco_tst, tst_s[i], iut_addr);
    if (rc != 0)
        TEST_VERDICT("connect() failed with errno %s at iteration %d",
                     errno_rpc2str(RPC_ERRNO(pco_tst)), i);
    acc1_s[i++] = -1;
    acc2_s[0] = rpc_accept(pco_iut2, iut2_s, NULL, 0);

    CHECK_CONNECTION(pco_iut2, acc2_s[0], pco_tst, tst_s[i-1]);

    rpc_connect(pco_iut1, iut1_lb_s, iut_addr);
    acc2_s[1] = rpc_accept(pco_iut2, iut2_s, NULL, 0);

    CHECK_CONNECTION(pco_iut2, acc2_s[1], pco_iut1, iut1_lb_s);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut1, iut1_s);
    CLEANUP_RPC_CLOSE(pco_iut2, iut2_s);
    CLEANUP_RPC_CLOSE(pco_iut1, iut1_lb_s);
    CLEANUP_RPC_CLOSE(pco_iut2, iut2_lb_s);

    CLEANUP_RPC_CLOSE(pco_iut2, acc2_s[0]);
    CLEANUP_RPC_CLOSE(pco_iut2, acc2_s[1]);

    CLEANUP_RPC_CLOSE(pco_tst, aux_s1);
    CLEANUP_RPC_CLOSE(pco_iut2, aux_s2);

    for ( i--; i >= 0; i--)
    {
        CLEANUP_RPC_CLOSE(pco_iut1, acc1_s[i]);
        CLEANUP_RPC_CLOSE(pco_tst, tst_s[i]);
    }

    free(tx_buf);
    free(rx_buf);

    if (loglevel != -1)
        TAPI_SYS_LOGLEVEL_CANCEL_DEBUG(pco_iut1, loglevel);

    TEST_END;
}

