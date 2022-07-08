/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 *
 * $Id$
 */

/** @page epoll-epoll_ctl_del_after_exec Check epoll behaviour when socket is deleted from empty epoll set after exec()
 *
 * @objective Check that application doen't crash when socket id deleted
 *            from empty epoll set after @b exec()
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       Tester PCO
 * @param iut_addr      Network address on IUT
 * @param tst_addr      Network address on Tester
 * @param sock_type     Type of sockets used in the test
 *
 * @par Scenario:
 * -# Call @b socket() and @b epoll_create().
 * -# Call @b exec().
 * -# Call @b epoll_ctl(@c EPOLL_CTL_DEL).
 * -# Check that @b epoll_wait() returns 0 in the epoll fd.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/epoll_ctl_del_after_exec"

#include "sockapi-test.h"
#include "iomux.h"

#define DATA_LEN 500

#define CHECK_EPOLL(msg_, rc_) \
    do {                                                    \
        rc = rpc_send(pco_tst, tst_s, tx_buf, DATA_LEN, 0); \
        if (rc != DATA_LEN)                                 \
            TEST_FAIL("Data was not sent properly");        \
        rc = rpc_epoll_wait(pco_iut, epfd, &event, 1,       \
                            1000);                          \
        if (rc != (rc_) || ((rc_) > 0 &&                    \
                            (event.events != RPC_EPOLLIN || \
                             event.data.fd != iut_s)))      \
            TEST_VERDICT(msg_);                             \
        rc = rpc_recv(pco_iut, iut_s, rx_buf, DATA_LEN, 0); \
        if (rc != DATA_LEN)                                 \
            TEST_FAIL("Data was not received properly");    \
    } while (0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server  *pco_iut = NULL;
    rcf_rpc_server  *pco_tst = NULL;

    struct rpc_epoll_event event;
    rpc_socket_type        sock_type;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;

    int tst_s = -1;
    int iut_s = -1;
    int epfd = -1;

    char *tx_buf;
    char *rx_buf;

    te_bool use_wildcard;

    /* Test preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(use_wildcard);

    /* Scenario */
    tx_buf = te_make_buf_by_len(DATA_LEN);
    rx_buf = te_make_buf_by_len(DATA_LEN);

    /* Create epfd and socket; add socket to the set */
    GEN_CONNECTION_WILD(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                        iut_addr, tst_addr, &iut_s, &tst_s, use_wildcard);

    epfd = rpc_epoll_create(pco_iut, 1);
    rcf_rpc_server_exec(pco_iut);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_epoll_ctl(pco_iut, epfd, RPC_EPOLL_CTL_DEL, iut_s, NULL);
    if (rc != -1)
        TEST_VERDICT("Deleting socket from empty epfd doesn't fail");
    else
        CHECK_RPC_ERRNO(pco_iut, RPC_ENOENT,
                        "Deleting socket from empty epfd failed");
    CHECK_EPOLL("epoll_wait() after deleting the socket from epoll set "
                "returned incorrect result", 0);
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(tx_buf);
    free(rx_buf);

    TEST_END;
}

