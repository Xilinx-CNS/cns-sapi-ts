/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-threads_shutdown_diff_sock Shutdown on socket when two other threads or processes call the same function for two other sockets in blocking mode
 *
 * @objective Check that shutdown() on socket will not take too long time
 *            when two other threads or processes call the same function
 *            for two other sockets in blocking mode.
 *
 * @type Conformance, compatibility
 *
 *
 * @param env   Private environment. IUT and tester are located on two
 *              different hosts which are connected directly using @b SFC
 *              NICs. Both tester and IUT have by three IPv4/IPv6 addresses issued
 *              from the same subnet and assigned to the interfaces.
 * @param use_threads   Create threads if @c TRUE, else - child processes.
 * @param sock_type     Socket type:
 *                      - SOCK_STREAM
 *                      - SOCK_DGRAM
 * @param shutdown_how  Action which should be performed by @b shutdown():
 *                      - SHUT_RD
 *                      - SHUT_WR
 *                      - SHUT_RDWR
 * @param sendrecv_func Tested function (see the note below):
 *                      - recv()
 *                      - send()
 * @param iomux_func    Tested iomux (see the note below):
 *                      - select
 *                      - pselect
 *                      - poll
 *                      - ppoll
 *                      - epoll
 *                      - epoll_pwait
 *                      - epoll_pwait2
 * @param other_func    Other tested functions:
 *                      - connect()
 *                      - accept()
 *
 * @note Only one of parameters @p sendrecv_func, @p iomux_func,
 *       @p other_func is tested by an iteration.
 *
 * @par Scenario:
 *
 * -# Create three sockets on @p pco_iut and on @pco_tst (@p iut_s1,
 *    @p iut_s2, @p iut_s3, @p tst_s1, @p tst_s2, @p tst_s3 bound to
 *    @p iut_addr1, @p iut_addr2, @p iut_addr3, @p tst_addr1, @p tst_addr2,
 *    @p tst_addr3 correspondingly). Connect @p iut_s1 with @p tst_s1 and
 *    @p iut_s2 with @p tst_s2. if @p other_func is not set, connect
 *    @p iut_s3 with @p tst_s3.
 * -# Create two threads or child processes @p pco_iut1 and @p pco_iut2
 *    according to @p use_threads.
 * -# Call function specified by @p sendrecv_func or @p iomux_func or
 *    @p other_func for @p iut_s1 on @p pco_iut1 and for @p iut_s2
 *    on @p pco_iut2 so that it will block.
 * -# Call @b shutdown() for @p iut_s3 on @p pco_iut.
 * -# Check whether it will return in less than 0.5 sec.
 * -# Unblock functions blocked previously, perform cleanup.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@Oktetlabs.ru"
*/

#define TE_TEST_NAME  "basic/threads_shutdown_diff_sock"

#include "sockapi-test.h"
#include "iomux.h"
#include "sendrecv_call_wait.h"
#include "tapi_route_gw.h"

enum {
    FUNC_UNKNOWN = 0,
    FUNC_ACCEPT,
    FUNC_CONNECT
};

#define OTHER_FUNCS \
    {"accept", FUNC_ACCEPT}, \
    {"connect", FUNC_CONNECT}

#define TST_BUF_LEN     1024

#define TST_CALL_FUNC(_i) \
    CALL_SR_FUNC(pco_iut##_i, sendrecv_func, is_send,               \
                 iut_s##_i, iut_buf##_i, TST_BUF_LEN,               \
                 iut_buf##_i, TST_BUF_LEN)

#define TST_WAIT_FUNC(_i) \
    WAIT_SR_FUNC(pco_iut##_i, sendrecv_func, is_send,               \
                 iut_s##_i, iut_buf##_i, TST_BUF_LEN,               \
                 iut_buf##_i, TST_BUF_LEN, TST_BUF_LEN)

#define UNBLOCK_SEND(_i) \
    do {                                                    \
        int rcv;                                            \
                                                            \
        do {                                                \
           RPC_AWAIT_IUT_ERROR(pco_tst);                    \
           rcv = rpc_recv(pco_tst, tst_s##_i, tst_buf##_i,  \
                          TST_BUF_LEN, RPC_MSG_DONTWAIT);   \
        } while (rcv != -1);                                \
        CHECK_RPC_ERRNO(pco_tst, RPC_EAGAIN,                \
                        "recv() returns -1, but");          \
    } while(0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server  *pco_iut = NULL;
    rcf_rpc_server  *pco_iut1 = NULL;
    rcf_rpc_server  *pco_iut2 = NULL;
    rcf_rpc_server  *pco_tst = NULL;

    const struct sockaddr      *iut_addr1;
    const struct sockaddr      *iut_addr2;
    const struct sockaddr      *iut_addr3;
    const struct sockaddr      *tst_addr1;
    const struct sockaddr      *tst_addr2;
    const struct sockaddr      *tst_addr3;
    const void                 *alien_link_addr = NULL;

    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *tst_if = NULL;

    int              iut_s1 = -1;
    int              iut_s2 = -1;
    int              iut_s3 = -1;
    int              tst_s1 = -1;
    int              tst_s2 = -1;
    int              tst_s3 = -1;
    int              iut_acc1 = -1;
    int              iut_acc2 = -1;
    int              tst_acc1 = -1;
    int              tst_acc2 = -1;

    iomux_evt_fd     evt1;
    iomux_evt_fd     evt2;

    te_bool          use_threads = FALSE;
    rpc_shut_how     shutdown_how;
    rpc_socket_type  sock_type;

    void            *sendrecv_func = NULL;
    te_bool          is_send = FALSE;
    char            *iut_buf1 = NULL;
    char            *iut_buf2 = NULL;
    char            *tst_buf1 = NULL;
    char            *tst_buf2 = NULL;

    iomux_call_type  iomux_func = IC_UNKNOWN;
    int              other_func = FUNC_UNKNOWN;

    te_bool          done = FALSE;
    te_bool          is_failed = FALSE;

    iomux_state      imx_st;
    iomux_state     *imx_st_p = &imx_st;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_iut, iut_addr3);
    TEST_GET_ADDR(pco_tst, tst_addr1);
    TEST_GET_ADDR(pco_tst, tst_addr2);
    TEST_GET_ADDR(pco_tst, tst_addr3);
    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_SHUT_HOW(shutdown_how);
    TEST_GET_BOOL_PARAM(use_threads);
    TEST_GET_SOCK_TYPE(sock_type);

    iut_buf1 = te_make_buf_by_len(TST_BUF_LEN);
    iut_buf2 = te_make_buf_by_len(TST_BUF_LEN);
    tst_buf1 = te_make_buf_by_len(TST_BUF_LEN);
    tst_buf2 = te_make_buf_by_len(TST_BUF_LEN);

    memset(&imx_st, 0, sizeof(imx_st));

    if (test_get_param(argc, argv, "sendrecv_func") != NULL)
        TEST_GET_FUNC(sendrecv_func, is_send);
    else if (test_get_param(argc, argv, "iomux_func") != NULL)
        TEST_GET_IOMUX_FUNC(iomux_func);
    else if (test_get_param(argc, argv, "other_func") != NULL)
        TEST_GET_ENUM_PARAM(other_func, OTHER_FUNCS);
    else
        TEST_FAIL("Function to call was not specified");

    if (other_func == FUNC_UNKNOWN)
    {
        GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                       iut_addr1, tst_addr1, &iut_s1, &tst_s1);
        GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                       iut_addr2, tst_addr2, &iut_s2, &tst_s2);
    }
    else
    {
        iut_s1 = rpc_socket(pco_iut,
                            rpc_socket_domain_by_addr(iut_addr1),
                            sock_type, RPC_PROTO_DEF);
        iut_s2 = rpc_socket(pco_iut,
                            rpc_socket_domain_by_addr(iut_addr2),
                            sock_type, RPC_PROTO_DEF);
        tst_s1 = rpc_socket(pco_tst,
                            rpc_socket_domain_by_addr(tst_addr1),
                            sock_type, RPC_PROTO_DEF);
        tst_s2 = rpc_socket(pco_tst,
                            rpc_socket_domain_by_addr(tst_addr2),
                            sock_type, RPC_PROTO_DEF);

        rpc_bind(pco_iut, iut_s1, iut_addr1);
        rpc_bind(pco_iut, iut_s2, iut_addr2);
        rpc_bind(pco_tst, tst_s1, tst_addr1);
        rpc_bind(pco_tst, tst_s2, tst_addr2);
    }

    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr3, tst_addr3, &iut_s3, &tst_s3);

    if (!use_threads)
    {
        rcf_rpc_server_fork(pco_iut, "IUT_child_proc_1", &pco_iut1);
        rcf_rpc_server_fork(pco_iut, "IUT_child_proc_2", &pco_iut2);
    }
    else
    {
        rcf_rpc_server_thread_create(pco_iut, "IUT_thread_1",
                                     &pco_iut1);
        rcf_rpc_server_thread_create(pco_iut, "IUT_thread_2",
                                     &pco_iut2);
    }

    if (iomux_func != IC_UNKNOWN)
    {
        evt1.fd = iut_s1;
        evt1.events = EVT_RD;
        evt2.fd = iut_s2;
        evt2.events = EVT_RD;

        pco_iut1->op = RCF_RPC_CALL;
        iomux_call(iomux_func, pco_iut1, &evt1, 1, NULL);
        imx_st_p = iomux_switch_state(imx_st_p);
        pco_iut2->op = RCF_RPC_CALL;
        iomux_call(iomux_func, pco_iut2, &evt2, 1, NULL);
    }
    else if (sendrecv_func != NULL)
    {
        if (is_send)
        {
            /*
             * Overfill buffers so that sending data calls
             * will be blocking on IUT.
             */
            rpc_overfill_buffers(pco_iut1, iut_s1, NULL);
            rpc_overfill_buffers(pco_iut2, iut_s2, NULL);
        }

        TST_CALL_FUNC(1);
        TST_CALL_FUNC(2);
    }
    else
    {
        if (other_func == FUNC_CONNECT)
        {
            rpc_listen(pco_tst, tst_s1, SOCKTS_BACKLOG_DEF);
            rpc_listen(pco_tst, tst_s2, SOCKTS_BACKLOG_DEF);

            /*
             * Add ARP entries redirecting network packages to
             * incorrect @p alien_link_addr address on IUT, so that
             * @b connect() calls will be blocking.
             */
            CHECK_RC(tapi_update_arp(pco_iut1->ta, iut_if->if_name,
                                     NULL, NULL, tst_addr1,
                                     CVT_HW_ADDR(alien_link_addr),
                                     TRUE));

            CHECK_RC(tapi_update_arp(pco_iut2->ta, iut_if->if_name,
                                     NULL, NULL, tst_addr2,
                                     CVT_HW_ADDR(alien_link_addr),
                                     TRUE));

            CFG_WAIT_CHANGES;

            pco_iut1->op = RCF_RPC_CALL;
            rpc_connect(pco_iut1, iut_s1, tst_addr1);
            pco_iut2->op = RCF_RPC_CALL;
            rpc_connect(pco_iut2, iut_s2, tst_addr2);
        }
        else
        {
            rpc_listen(pco_iut, iut_s1, SOCKTS_BACKLOG_DEF);
            rpc_listen(pco_iut, iut_s2, SOCKTS_BACKLOG_DEF);
            pco_iut1->op = RCF_RPC_CALL;
            rpc_accept(pco_iut1, iut_s1, NULL, NULL);
            pco_iut2->op = RCF_RPC_CALL;
            rpc_accept(pco_iut2, iut_s2, NULL, NULL);
        }
    }

    if (pco_iut->timeout < 1000)
        pco_iut->timeout = 1000;

    pco_iut->op = RCF_RPC_CALL;
    rpc_shutdown(pco_iut, iut_s3, shutdown_how);

    MSLEEP(500);

    rcf_rpc_server_is_op_done(pco_iut, &done);
    if (!done)
    {
        is_failed = TRUE;
        RING_VERDICT("shutdown() call takes too long time");
    }

    pco_iut->op = RCF_RPC_WAIT;
    rpc_shutdown(pco_iut, iut_s3, shutdown_how);

    if (is_send)
    {
        /*
         * If we need to unblock sending data call,
         * receive data on the peer.
         */
        UNBLOCK_SEND(1);
        UNBLOCK_SEND(2);
    }
    else if (other_func == FUNC_UNKNOWN)
    {
        /*
         * If data receiving or iomux function call is blocked,
         * send some data from the peer to unblock it.
         */
        rpc_send(pco_tst, tst_s1, tst_buf1, TST_BUF_LEN, 0);
        rpc_send(pco_tst, tst_s2, tst_buf2, TST_BUF_LEN, 0);
    }

    /*
     * Obtain result of unblocked function call.
     */
    if (iomux_func != IC_UNKNOWN)
    {
        imx_st_p = iomux_switch_state(imx_st_p);
        pco_iut1->op = RCF_RPC_WAIT;
        iomux_call(iomux_func, pco_iut1, &evt1, 1, NULL);
        imx_st_p = iomux_switch_state(imx_st_p);
        pco_iut2->op = RCF_RPC_WAIT;
        iomux_call(iomux_func, pco_iut2, &evt2, 1, NULL);
    }
    else if (sendrecv_func != NULL)
    {
        TST_WAIT_FUNC(1);
        TST_WAIT_FUNC(2);
    }
    else if (other_func != FUNC_UNKNOWN)
    {
        if (other_func == FUNC_CONNECT)
        {
            /*
             * Update ARP entries to unblock
             * @b connect() calls on IUT.
             */
            CHECK_RC(tapi_update_arp(pco_iut1->ta, iut_if->if_name,
                                     pco_tst->ta, tst_if->if_name,
                                     tst_addr1, NULL, FALSE));

            CHECK_RC(tapi_update_arp(pco_iut2->ta, iut_if->if_name,
                                     pco_tst->ta, tst_if->if_name,
                                     tst_addr2, NULL, FALSE));

            CFG_WAIT_CHANGES;

            pco_iut1->op = RCF_RPC_WAIT;
            rpc_connect(pco_iut1, iut_s1, tst_addr1);
            pco_iut2->op = RCF_RPC_WAIT;
            rpc_connect(pco_iut2, iut_s2, tst_addr2);

            tst_acc1 = rpc_accept(pco_tst, tst_s1, NULL, NULL);
            tst_acc2 = rpc_accept(pco_tst, tst_s2, NULL, NULL);
        }
        else
        {
            rpc_connect(pco_tst, tst_s1, iut_addr1);
            rpc_connect(pco_tst, tst_s2, iut_addr2);

            pco_iut1->op = RCF_RPC_WAIT;
            iut_acc1 = rpc_accept(pco_iut1, iut_s1, NULL, NULL);
            pco_iut2->op = RCF_RPC_WAIT;
            iut_acc2 = rpc_accept(pco_iut2, iut_s2, NULL, NULL);
        }
    }

    if (is_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut1, iut_s1);
    CLEANUP_RPC_CLOSE(pco_iut2, iut_s2);
    CLEANUP_RPC_CLOSE(pco_iut1, iut_acc1);
    CLEANUP_RPC_CLOSE(pco_iut2, iut_acc2);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s3);
    CLEANUP_RPC_CLOSE(pco_tst, tst_acc1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_acc2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s3);

    if (!use_threads)
    {
        CLEANUP_RPC_CLOSE(pco_iut, iut_s1);
        CLEANUP_RPC_CLOSE(pco_iut, iut_s2);
    }

    rcf_rpc_server_destroy(pco_iut1);
    rcf_rpc_server_destroy(pco_iut2);

    free(iut_buf1);
    free(iut_buf2);
    free(tst_buf1);
    free(tst_buf2);

    sockts_kill_zombie_stacks_if_many(pco_iut);

    TEST_END;
}
