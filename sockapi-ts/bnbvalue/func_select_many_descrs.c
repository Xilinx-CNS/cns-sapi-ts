/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_select_many_descrs Using maximum number of descriptors with select() function
 *
 * @objective Check that @b select() function successfully works with 
 *            maximum number descriptors opened by a process.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param connect_sockets   Whether to connect sockets or not
 * @param pco_iut           PCO on IUT
 * @param pco_tst           PCO on TESTER
 *
 * @note If @p connect_sockets is TRUE, create @c SOCK_STREAM socket 
 *       @p tst_aux_s on @p pco_tst and listen on it.
 *
 * @par Scenario:
 * -# Create a variable @p readfds of type @c fd_set and clear it with
 *    @b FD_ZERO();
 * -# Create @p iut_s socket of type @c SOCK_STREAM on @p pco_iut;
 * -# Create @p tst_s socket of type @c SOCK_STREAM on @p pco_tst;
 * -# Create @p tst_serv_s socket of type @c SOCK_STREAM on @p pco_tst;
 * -# Bind @p iut_s socket to a local address;
 * -# Call @b listen() on @p iut_s socket;
 * -# @b connect() @p tst_s socket to @p iut_s socket;
 * -# Call @b accept() on @p iut_s socket to get a new @p iut_acc_s socket;
 * -# \n @htmlonly &nbsp; @endhtmlonly
 * -# Bind @p tst_serv_s socket to a local address;
 * -# Call @b listen() on @p tst_serv_s socket;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Keep creating sockets on @p pco_iut, by @b socket() function, until it
 *    returns @c EMFILE;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# @b connect() the socket created on @p pco_iut with maximum descriptor to 
 *    @p tst_serv_s socket;
 * -# Call @b accept() on @p @p tst_serv_s socket to get a new 
 *    @p tst_acc_s socket;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Insert each socket created on @p pco_iut to @p readfds variable by
 *    @b FD_SET() (@p iut_s socket, @p iut_acc_s socket and all the created
 *    on @p pco_iut sockets);
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# If @p connect_sockets is TRUE, @b connect() all created sockets to
 *    @p tst_aux_s socket;
 * -# Send some data from @p tst_s socket;
 * -# Send some data from @p tstacc_s socket;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b select() with @p readfds variable used as @a readset parameter
 *    specifying @c NULL as @a timeout parameter;
 * -# Check that @b select() return @c 2, because @p iut_acc_s and 
 *    the socket with maximum descriptor become readable;
 * -# Check that @b FD_ISSET() returns @c 1 for @p iut_acc_s and for maximum
 *    client socket descriptors, and @c 0 for others;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close all the sockets.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME    "bnbvalue/func_select_many_descrs"

#include "sockapi-test.h"

#define BLK_BUF_SIZE 512

int
main(int argc, char *argv[])
{
    rcf_rpc_server    *pco_iut = NULL;
    rcf_rpc_server    *pco_tst = NULL;
    int                iut_s = -1;
    int                tst_aux_s = -1;
    int                tst_s = -1;
    int                tst_serv_s = -1;
    int                iut_acc_s = -1;
    int                tst_acc_s = -1;
    int                maxfd = 0;
    rpc_fd_set_p       readfds = RPC_NULL;
    void              *tx_buf = NULL;
    size_t             tx_buf_len;
    int                i;

    char        *old_ef_select_fast = NULL;
    const char  *ef_select_fast = NULL;
    cfg_handle   ef_select_fast_handle = CFG_HANDLE_INVALID;
    char        *old_ef_no_fail = NULL;
    const char  *ef_no_fail = NULL;
    cfg_handle   ef_no_fail_handle = CFG_HANDLE_INVALID;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    te_bool                connect_sockets;

    int *socks = NULL;
    int *acc_socks = NULL;
    int  socks_size = BLK_BUF_SIZE;
    int  socks_cur = 0;

    struct sockaddr_storage  aux_addr;


    /* Preambule */
    TEST_START;
    TEST_GET_BOOL_PARAM(connect_sockets);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(ef_select_fast);
    TEST_GET_STRING_PARAM(ef_no_fail);

    ef_select_fast_handle = sockts_set_env(pco_iut, "EF_SELECT_FAST",
                                           ef_select_fast,
                                           &old_ef_select_fast);
    ef_no_fail_handle = sockts_set_env(pco_iut, "EF_NO_FAIL", ef_no_fail,
                                           &old_ef_no_fail);
    TAPI_WAIT_NETWORK;

    if (connect_sockets)
    {
        /* Set up different ports on the same address */
        if (iut_addr == tst_addr)
        {
            tst_addr = malloc(sizeof(struct sockaddr_storage));
            memcpy((struct sockaddr *)tst_addr, iut_addr, te_sockaddr_get_size(iut_addr));
            TAPI_SET_NEW_PORT(pco_tst, tst_addr);
        }
        memcpy(&aux_addr, tst_addr, te_sockaddr_get_size(tst_addr));
        TAPI_SET_NEW_PORT(pco_tst, &aux_addr);

        /* Set up aux listening socket */
        tst_aux_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                               RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_bind(pco_tst, tst_aux_s, SA(&aux_addr));
        rpc_listen(pco_tst, tst_aux_s, 5);
    }

    /* Scenario */
    readfds = rpc_fd_set_new(pco_iut);
    
    CHECK_NOT_NULL(tx_buf = sockts_make_buf_stream(&tx_buf_len));
    
    rpc_do_fd_zero(pco_iut, readfds);

    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                       RPC_PROTO_DEF, TRUE, FALSE,
                                       iut_addr);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_serv_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                            RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
    rpc_connect(pco_tst, tst_s, iut_addr);
    iut_acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);
    
    rpc_bind(pco_tst, tst_serv_s, tst_addr);
    rpc_listen(pco_tst, tst_serv_s, SOCKTS_BACKLOG_DEF);

    maxfd = ((iut_s > iut_acc_s) ? iut_s : iut_acc_s);

    rpc_do_fd_set(pco_iut, iut_s, readfds);
    rpc_do_fd_set(pco_iut, iut_acc_s, readfds);

    CHECK_NOT_NULL(socks = (int *)malloc(socks_size * sizeof(*socks)));
    CHECK_NOT_NULL(acc_socks = (int *)malloc(socks_size * sizeof(*socks)));
    for (i = 0; i < socks_size; i++)
    {
        socks[i] = -1;
        acc_socks[i] = -1;
    }

    do {
        /* Realloc more space for fds if necessary */
        if (socks_cur == socks_size)
        {
            void *new_ptr;
            int new_sock_size = socks_size + BLK_BUF_SIZE;

            CHECK_NOT_NULL(new_ptr = realloc(socks,
                                             sizeof(*socks) *
                                             new_sock_size));
            socks = new_ptr;
            CHECK_NOT_NULL(new_ptr = realloc(acc_socks,
                                             sizeof(*socks) *
                                             new_sock_size));
            acc_socks = new_ptr;
            for (i = socks_size; i < new_sock_size; i++)
            {
                socks[i] = -1;
                acc_socks[i] = -1;
            }
            socks_size = new_sock_size;
        }

        /* Create a new socket */
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);

        socks[socks_cur] = rc;
        if (rc > 0)
        {
            rpc_do_fd_set(pco_iut, socks[socks_cur], readfds);
            if (maxfd < socks[socks_cur])
                maxfd = socks[socks_cur];
        }
        socks_cur++;
    } while (rc > 0);

    if (rc != -1)
    {
        TEST_FAIL("socket() on failure is expected to return -1, "
                  "but it returns %d", rc);
    }
    if (RPC_ERRNO(pco_iut) == RPC_ENOMEM)
        RING_VERDICT("socket() call failed with -1(errno=ENOMEM)");
    else
        CHECK_RPC_ERRNO(pco_iut, RPC_EMFILE, "When there is no available "
                        "file descriptors for the process socket() "
                        "returns -1, but");

    socks_cur--;
    if (socks_cur < 100)
        TEST_VERDICT("Failed to create at least 100 sockets");


    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_connect(pco_iut, maxfd, tst_addr);
    if (rc == -1)
        TEST_VERDICT("connect() with maxfd socket failed with %s error",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    tst_acc_s = rpc_accept(pco_tst, tst_serv_s, NULL, NULL);

    if (connect_sockets)
    {
        for (i = 0; i < socks_cur; i++)
        {
            if (socks[i] == maxfd)
                continue;

            pco_iut->timeout = TE_SEC2MS(30);
            RPC_AWAIT_IUT_ERROR(pco_iut);
            rc = rpc_connect(pco_iut, socks[i], SA(&aux_addr));
            if (rc == -1)
                TEST_VERDICT("connect() failed with %s error",
                             errno_rpc2str(RPC_ERRNO(pco_iut)));
            if (i < socks_cur - 3)
                acc_socks[i] = rpc_accept(pco_tst, tst_aux_s, NULL, NULL);
        }
    }

    RPC_SEND(rc, pco_tst, tst_s, tx_buf, tx_buf_len, 0);
    RPC_SEND(rc, pco_tst, tst_acc_s, tx_buf, tx_buf_len, 0);
    TAPI_WAIT_NETWORK;

    rc = rpc_select(pco_iut, maxfd + 1, readfds, RPC_NULL, RPC_NULL, NULL);
    if (!rpc_do_fd_isset(pco_iut, iut_acc_s, readfds))
    {
        TEST_FAIL("'iut_acc_s' is not set in 'readfds'");
    }
    if (!rpc_do_fd_isset(pco_iut, maxfd, readfds))
    {
        TEST_VERDICT("socket with maximum descriptor is not set in "
                     "'readfds'");
    }

    if (!connect_sockets && rc == 1 + socks_cur)
        RING_VERDICT("Just-created sockets are readable");
    else if (rc != 2)
         TEST_FAIL("select() called on IUT returns %d, instead of 2", rc);


    for (i = 0; i < socks_cur; i++)
    {
        int isset;

        if (socks[i] == maxfd)
            continue;

        isset = rpc_do_fd_isset(pco_iut, socks[i], readfds);
        if (rc == 2 && isset)
            TEST_FAIL("socket descriptor %d is set in 'readfds'");
        else if (rc > 2 && !isset)
            TEST_FAIL("socket descriptor %d is unset in 'readfds'");
    }

    TEST_SUCCESS;

cleanup:
    rpc_fd_set_delete(pco_iut, readfds);

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_serv_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_acc_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_acc_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_aux_s);

    while ((--socks_cur) >= 0)
    {
        CLEANUP_RPC_CLOSE(pco_iut, socks[socks_cur]);
        CLEANUP_RPC_CLOSE(pco_tst, acc_socks[socks_cur]);
    }
    free(socks);
    free(acc_socks);

    free(tx_buf);

    CLEANUP_CHECK_RC(sockts_restore_env(pco_iut, ef_select_fast_handle,
                                        old_ef_select_fast));
    CLEANUP_CHECK_RC(sockts_restore_env(pco_iut, ef_no_fail_handle,
                                        old_ef_no_fail));

    TEST_END;
}
