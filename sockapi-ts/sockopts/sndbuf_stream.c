/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-sndbuf_stream Influence SO_SNDBUF option on actual send buffer size
 *
 * @objective Explore the possibility to change send buffer size by means of
 *            setsockopt(SO_SNDBUF) and influence new value on actual
 *            buffer size.
 *
 * @type conformance
 *
 * @param pco_iut                   PCO on IUT
 * @param pco_tst                   PCO on TESTER
 * @param server                    IUT opens connection as
 *                                  TRUE/FALSE - server/client
 * @param sndbuf_new                The value to set by means of
 *                                  setsockopt(SO_SNDBUF) on IUT side
 *                                  socket
 * @param proper_sequence           If @c TRUE set send buffer size option
 *                                  before connection, else - after. This
 *                                  should not have any effect.
 * @param force                     If @c TRUE, use SO_SNDBUFFORCE on IUT.
 *
 * @par Test sequence:
 * -# Create @p iut_s socket of type @c SOCK_STREAM on @p pco_iut;
 * -# Create @p tst_s socket of type @c SOCK_STREAM on @p pco_tst;
 * -# bind() @p iut_s socket to a local address and port;
 * -# bind() @p tst_s socket to a local address and port;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# In accordance with @p server value:
 *       - create server on IUT or TESTER;
 *       - connect() client to server and accept() new connection;
 * -# Set send buffer size option and check the new value:
 *   -# Call @b getsockopt(SO_SNDBUF) on IUT side socket
 *      (one side of new connection) to log default value;
 *   -# Call @b setsockopt(SO_SNDBUF) on IUT side socket
 *      passing a new value of send buffer;
 *   -# Call @b getsockopt(SO_SNDBUF) on IUT side socket to retrieve
 *      value of current send buffer size and log it;
 *      \n @htmlonly &nbsp; @endhtmlonly
 * -# Send intensive data flow between IUT and TST to get more accurate
 *    results;
 * -# Write maximum number of bytes to the both send buffer of IUT side
 *    socket and receive buffer of TST side socket to check the actual
 *    buffer size of IUT side socket and log it;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close opened sockets and free allocated resources.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/sndbuf_stream"

#include "sockapi-test.h"
#include "iomux.h"

#define ONLOAD_PACKET_SIZE 2048

/**
 * Deviation degree
 */
typedef enum bufs_match {
    few,
    exact,
    much,
} bufs_match;

/**
 * Determine deviation of actual buffer size from the set value
 * 
 * @param sndbuf     Set option value
 * @param data_size  Amount of data which fit to the buffer
 * 
 * @return Deviation degree
 */
static bufs_match
match_bufs(int sndbuf, int data_size)
{
    if (sndbuf <= ONLOAD_PACKET_SIZE * 2 && data_size >= 0 &&
        data_size < ONLOAD_PACKET_SIZE * 2)
        return exact;

    /* For Linux 1.5 could be instead of 2 */
    if (data_size < sndbuf * 2 && data_size > sndbuf * 0.7)
        return exact;
    else if (data_size > sndbuf)
        return much;
    else
        return few;
}

/**
 * Send and receive data flow
 * 
 * @param pco_iut   IUT RPC sserver
 * @param pco_tst   Tester RPC server
 * @param iut_s     IUT socket
 * @param tst_s     Tester socket
 */
static void
send_recv_data_flow(rcf_rpc_server *pco_iut, rcf_rpc_server *pco_tst,
                    int iut_s, int tst_s)
{
    int buf_len = 2000;
    char buf[buf_len];
    int res;

    pco_iut->op = RCF_RPC_CALL;
    rpc_iomux_flooder(pco_iut, &iut_s, 1, NULL, 0,
                      buf_len, 3, 1, IC_DEFAULT, NULL, NULL);

    rpc_iomux_flooder(pco_tst, NULL, 0, &tst_s, 1,
                      buf_len, 3, 1, IC_DEFAULT, NULL, NULL);

    pco_iut->op = RCF_RPC_WAIT;
    rpc_iomux_flooder(pco_iut, &iut_s, 1, NULL, 0,
                      buf_len, 3, 1, IC_DEFAULT, NULL, NULL);

    /* Make sure that buffers are empty */
    TAPI_WAIT_NETWORK;
    RPC_AWAIT_IUT_ERROR(pco_tst);
    while((res = rpc_recv(pco_tst, tst_s, buf, buf_len,
                          RPC_MSG_DONTWAIT)) > 0)
    {
        RPC_AWAIT_IUT_ERROR(pco_tst);
        TAPI_WAIT_NETWORK;
    }
}

/**
 * Set a SO_SNDBUF socket option, check it is set properly
 * 
 * @param pco_iut       IUT RPC server
 * @param iut_s         IUT socket
 * @param sndbuf_new    Value to set
 * @param sndbuf_val    Location for the read value after setting
 * @param force         If @c TRUE, use SO_SNDBUFFORCE
 */
static void
set_sndbuf(rcf_rpc_server *pco_iut, int iut_s, int sndbuf_new,
           int *sndbuf_val, te_bool force)
{
    int optval_def;

    rpc_getsockopt(pco_iut, iut_s, RPC_SO_SNDBUF, &optval_def);
    RING("Default value of SO_SNDBUF socket option is %d", optval_def);

    sndbuf_new = sndbuf_new;
    rpc_setsockopt(pco_iut, iut_s,
                   (force ? RPC_SO_SNDBUFFORCE : RPC_SO_SNDBUF),
                   &sndbuf_new);
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_SNDBUF, sndbuf_val);
    if (*sndbuf_val == optval_def)
        TEST_VERDICT("setsockopt() does NOT update the value "
                     "of SO_SNDBUF socket option");

    if (*sndbuf_val != sndbuf_new * 2)
        RING_VERDICT("SO_SNDBUF has been set to %d, but got value is %d",
                     sndbuf_new, *sndbuf_val);
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;
    int             accept_s = -1;
    te_bool         server;
    te_bool         proper_sequence;
    te_bool         force;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;
    int                     tst_rcvbuf_filled;
    int                     sndbuf_new = 0;
    int                     sndbuf_val = 0;
    int                     opt_val = 0;
    uint64_t                total = 0;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(server);
    TEST_GET_BOOL_PARAM(proper_sequence);
    TEST_GET_BOOL_PARAM(force);
    TEST_GET_INT_PARAM(sndbuf_new);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    if (proper_sequence)
        set_sndbuf(pco_iut, iut_s, sndbuf_new, &sndbuf_val, force);

    if (server)
    {
        rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
        rpc_connect(pco_tst, tst_s, iut_addr);
        accept_s = rpc_accept(pco_iut, iut_s, NULL, NULL);
        RPC_CLOSE(pco_iut, iut_s);
        iut_s = accept_s;
    }
    else
    {
        rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);
        rpc_connect(pco_iut, iut_s, tst_addr);
        accept_s = rpc_accept(pco_tst, tst_s, NULL, NULL);
        RPC_CLOSE(pco_tst, tst_s);
        tst_s = accept_s;
    }

    if (!proper_sequence)
        set_sndbuf(pco_iut, iut_s, sndbuf_new, &sndbuf_val, force);

    send_recv_data_flow(pco_iut, pco_tst, iut_s, tst_s);
    rpc_overfill_buffers(pco_iut, iut_s, &total);
    TAPI_WAIT_NETWORK;

    /* Get the actual number of bytes in 'tst_s' receive queue */
    rpc_ioctl(pco_tst, tst_s, RPC_FIONREAD, &tst_rcvbuf_filled);
    RING("Send buffer of %d bytes keeps %d (%llu - %d) bytes of data",
         sndbuf_val, (int)total - tst_rcvbuf_filled, total,
         tst_rcvbuf_filled);
    /* Check socket options */
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_ioctl(pco_iut, iut_s, RPC_SIOCOUTQ, &opt_val);
    if (rc != 0 || opt_val != (int)total - tst_rcvbuf_filled)
        RING_VERDICT("ioctl SIOCOUTQ doesn't work properly");

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_ioctl(pco_iut, iut_s, RPC_TIOCOUTQ, &opt_val);
    if (rc != 0 || opt_val != (int)total - tst_rcvbuf_filled)
        RING_VERDICT("ioctl TIOCOUTQ doesn't work properly");

    RING("Stored data = %.2f * set buffer",
         (((double)total - (double)tst_rcvbuf_filled) /
            (double)sndbuf_val));
    switch (match_bufs(sndbuf_val, (int)total - tst_rcvbuf_filled))
    {
        case much:
            TEST_VERDICT("SO_SNDBUF setting is ignored, "
                         "too much data is stored");
            break;

        case few:
            TEST_VERDICT("SO_SNDBUF setting is ignored, "
                         "too small amount of data is stored");
            break;

        default:
            break;
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
