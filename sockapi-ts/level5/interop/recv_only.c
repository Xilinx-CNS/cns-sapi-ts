/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Interoperability of L5 stack with system stack.
 *
 * $Id$
 */

/** @page level5-interop-recv_only Usage of system receive calls with L5 socket
 *
 * @objective Check that it is possible to use system provided @b read()
 *            @b readv() functions with L5 socket.
 *
 * @type interop
 *
 * @param sock_type   Socket type used in the test
 * @param recv_func   Receive function to be used in the test
 * @param iut_serv    Whether @p iut_s should be obtained on the server
 *                    side or as a connection client
 *                    (only for @c SOCK_STREAM @p sock_type)
 * @param sys_first   Wheter a first piece of data should be sent via
 *                    system provided @p recv_func function or via L5
 * @param nonblock    If socket should be nonblocking
 *
 * @par Test sequence:
 * -# This step requires all necessary symbols (@b socket(), 
 *    @b connect(), etc.) to be resolved with L5 library.
 *    Create a connection of type @p sock_type between @p pco_iut and 
 *    @p pco_tst. As the result of this operation we will have two
 *    sockets: @p iut_s and @p tst_s.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# If @p nonblock - move socket to nonblocking mode
 * -# If @p nonblock - call @recv_func on the socket and check that
 *    it returns -1 (EAGAIN)
 * -# If not @p nonblock - call @recv_func on the socket with delayed
 *    result retrieval (to check that recv* will hang on the socket and
 *    wait for data)
 * -# Send @p N bytes from @p tst_s socket.
 * -# On @p pco_iut resolve @p recv_func depending on @p sys_first
 *    parameter:
 *    - @p sys_first - @c TRUE: Resolve with system (libc) library;
 *    - @p sys_first - @c FALSE: Resolev with L5 library.
 *    .
 * -# Call @p recv_func function on @p iut_s socket to 
 *    get @p N / 2 bytes of data;
 * -# On @p pco_iut resolve @p recv_func depending on @p sys_first
 *    parameter:
 *    - @p sys_first - @c TRUE: Resolev with L5 library;
 *    - @p sys_first - @c FALSE: Resolve with system (libc) library.
 *    .
 * -# In case @p sock_type is @c SOCK_STREAM, call @p recv_func 
 *    function on @p iut_s socket to get the rest @p N / 2 bytes of data;
 *    In case of @c SOCK_DGRAM we have nothing to read as we read out 
 *    the datagram on the previous step (the rest of the data is lost);
 * -# Check that data sent from @p tst_s socket is delivered to @p iut_s
 *    without any corruption.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close created sockets.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/interop/recv_only"

#include "sockapi-test.h"

#define N_RECVS  2
#define TST_VEC  3
#define BUF_LEN  169

#define CHECK_FUNCTION(func_name_, params_...) \
    do {                                                      \
        if (strcmp(recv_func, #func_name_) == 0)              \
        {                                                     \
            unknown_func = FALSE;                             \
            rc = rpc_ ## func_name_(pco_iut, iut_s, params_); \
        }                                                     \
    } while (0)

#define CHECK_FUNCTIONS \
    CHECK_FUNCTION(read, rx_buf + buff_offset, BUF_LEN);                 \
    CHECK_FUNCTION(recv, rx_buf + buff_offset, BUF_LEN, 0);              \
    CHECK_FUNCTION(recvfrom, rx_buf + buff_offset, BUF_LEN, 0, NULL, 0); \
    CHECK_FUNCTION(readv, rx_vector[i], TST_VEC);                        \
    CHECK_FUNCTION(recvmsg, &rx_msghdr[i], 0)


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rcf_rpc_server *serv_pco;
    rcf_rpc_server *clnt_pco;
    int             iut_s = -1;
    int             tst_s = -1;
    int            *serv_side_s;
    int            *clnt_side_s;

    rpc_socket_type        sock_type;
    te_bool                unknown_func = TRUE;
    const char            *recv_func;
    te_bool                iut_serv = TRUE;
    te_bool                sys_first = FALSE;
    te_bool                nonblock = FALSE;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    const struct sockaddr  *serv_addr;
    const struct sockaddr  *clnt_addr;

    struct sockaddr_storage remote_addr;
    
    unsigned int  j;
    unsigned int  i;

    uint8_t           rx_buf[BUF_LEN * TST_VEC * N_RECVS] = {};
    struct rpc_iovec  rx_vector[N_RECVS][TST_VEC];
    rpc_msghdr        rx_msghdr[N_RECVS];
    uint8_t          *tx_buf = NULL;
    size_t            tx_bytes = 0;
    size_t            rx_bytes = 0;
    size_t            buff_offset = 0;

    /*
     * Test preambule.
     */
    TEST_START;

    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(sys_first);
    TEST_GET_BOOL_PARAM(nonblock);
    TEST_GET_STRING_PARAM(recv_func);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    if (sock_type == RPC_SOCK_STREAM)
    {
        TEST_GET_BOOL_PARAM(iut_serv);
    }

    if (iut_serv)
    {
        serv_pco = pco_iut;
        clnt_pco = pco_tst;
        serv_side_s = &iut_s;
        clnt_side_s = &tst_s;
        serv_addr = iut_addr;
        clnt_addr = tst_addr;
    }
    else
    {
        serv_pco = pco_tst;
        clnt_pco = pco_iut;
        serv_side_s = &tst_s;
        clnt_side_s = &iut_s;
        serv_addr = tst_addr;
        clnt_addr = iut_addr;
    }

    GEN_CONNECTION(serv_pco, clnt_pco, sock_type, RPC_PROTO_DEF,
                   serv_addr, clnt_addr, serv_side_s, clnt_side_s);

    if (nonblock)
        rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, RPC_O_NONBLOCK);

    /* Prepare data to transmit */
    tx_buf = te_make_buf_by_len(sizeof(rx_buf));

    for (i = 0; i < N_RECVS; i++)
    {
        /* Create iovec for readv(), and recvmsg() */
        for (j = 0; j < TST_VEC; j++)
        {
            rx_vector[i][j].iov_base = 
                rx_buf + BUF_LEN * (i * TST_VEC + j);
            rx_vector[i][j].iov_len = rx_vector[i][j].iov_rlen = BUF_LEN;
        }

        /* recvmsg() */
        memset(&rx_msghdr[i], 0, sizeof(rx_msghdr[i]));
        rx_msghdr[i].msg_iovlen = rx_msghdr[i].msg_riovlen = TST_VEC;
        rx_msghdr[i].msg_iov = rx_vector[i];
        rx_msghdr[i].msg_name = &remote_addr;
        rx_msghdr[i].msg_namelen = rx_msghdr[i].msg_rnamelen = 
            sizeof(remote_addr);
    }


    /* Start main part of the test */

    tx_bytes = BUF_LEN * N_RECVS;
    if (strcmp(recv_func, "readv") == 0 ||
        strcmp(recv_func, "recvmsg") == 0)
    {
        tx_bytes *= TST_VEC;
    }

    /* first call */
    if (sys_first)
        pco_iut->use_libc_once = TRUE;

    /* this is important to be zero as it's used inside macro */
    i = 0;

    /* check that  */
    if (nonblock)
    {
        /*
         * Note that below only one function will be called so
         * we can set await error only once.
         */
        RPC_AWAIT_IUT_ERROR(pco_iut);
        CHECK_FUNCTIONS;

        if(rc == -1)
            CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN,
                            "%s retuned -1, but", recv_func);
        else
            TEST_VERDICT("%s() nonblocking call returned %d "
                         "instead of -1", recv_func, rc);

        /* now we should call/wait the functions */
    }

    if (!nonblock)
    {
        pco_iut->op = RCF_RPC_CALL;
        CHECK_FUNCTIONS;
    }

    /*
     * sleep here is because in bad case the function may actually
     * work slow and data is delivered before recv() hangs
     */
    TAPI_WAIT_NETWORK;

    RPC_WRITE(rc, pco_tst, tst_s, tx_buf, tx_bytes);
    TAPI_WAIT_NETWORK;


    for (i = 0; i < N_RECVS; i++)
    {
        buff_offset = i * (tx_bytes / N_RECVS);

        /* Prepare library name that should be used in symbol resolving */
        if ((sys_first && i == 0) || (!sys_first && i == 1))
            pco_iut->use_libc_once = TRUE;

        if (!nonblock && i == 0)
            pco_iut->op = RCF_RPC_WAIT;
        CHECK_FUNCTIONS;

        if (unknown_func)
            TEST_FAIL("Unknown 'recv_func' parameter %s", recv_func);

        rx_bytes = BUF_LEN;
        if (strcmp(recv_func, "readv") == 0 ||
            strcmp(recv_func, "recvmsg") == 0)
        {
            rx_bytes *= TST_VEC;
        }

        if (rc != (int)rx_bytes)
        {
            TEST_FAIL("%s() returns %d, but expected to return %d",
                      recv_func, rc, rx_bytes);
        }

        if (sock_type == RPC_SOCK_DGRAM)
        {
            /*
             * We read out a part of the datagram, so that the rest of
             * it inevitably lost.
             */

            RPC_CHECK_READABILITY(pco_iut, iut_s, FALSE);

            i = 1;
            break;
        }
    }

    if (memcmp(tx_buf, rx_buf, rx_bytes * i) != 0)
    {
        TEST_FAIL("Received data is corrupted");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
