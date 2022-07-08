/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-close_sock_oth_thread Close socket in another thread
 *
 * @objective Check that closing socket in some thread do not
 *            cause crash if there is a blocking function
 *            call on this socket in another thread.
 *
 * @type Conformance, compatibility
 *
 * @param env   Private testing environment:
 *              - similar to @ref arg_types_env_peer2peer and
 *              @ref arg_types_env_peer2peer_ipv6 but with two threads on IUT.
 * @param sock_type Socket type:
 *                  - SOCK_STREAM
 *                  - SOCK_DGRAM
 * @param func      Blocking function:
 *                  - @p sock_type = SOCK_DGRAM
 *                      - recv
 *                  - @p sock_type = SOCK_STREAM
 *                      - recv
 *                      - send
 *                      - sendfile
 *                      - connect
 *                      - accept
 *                      - onload_zc_send
 *                      - template_send
 *                      - od_send
 *                      - od_send_raw
 * @param close_func    Tested function:
 *                      - close
 *                      - dup2
 *                      - dup3
 *
 * @par Scenario:
 * -# Create sockets @p iut_s on @p pco_iut1 and @p tst_s on @p pco_tst,
 *    both of type @p sock_type. Connect them if @p func is not @b
 *    connect() or @b accept().
 * -# Overfill buffers on @p iut_s if @p func is @b send() or
 *    @b sendfile() or add wrong neigh record if @p func is @b connect().
 * -# Call blocking function specified by @p func on @p iut_s.
 * -# Close @p iut_s in @p pco_iut2 thread.
 * -# Check whether blocking function call is terminated. If not,
 *    try to unblock it from @p pco_tst and check it again.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/close_sock_oth_thread"

#include "sockapi-test.h"
#include "sendfile_common.h"
#include "tapi_route_gw.h"

#define BUF_SIZE 1024 

#define FUNCS \
    {"recv", RECV_FUNC},                    \
    {"send", SEND_FUNC},                    \
    {"onload_zc_send", SEND_FUNC},          \
    {"onload_zc_send_user_buf", SEND_FUNC}, \
    {"template_send", SEND_FUNC},           \
    {"od_send", SEND_FUNC},                 \
    {"od_send_raw", SEND_FUNC},             \
    {"sendfile", SENDFILE_FUNC},            \
    {"connect", CONNECT_FUNC},              \
    {"accept", ACCEPT_FUNC}

enum {
    RECV_FUNC = 1,
    SEND_FUNC,
    SENDFILE_FUNC,
    CONNECT_FUNC,
    ACCEPT_FUNC,
};

#define CLOSE_FUNCS \
    {"close", CLOSE_FUNC},  \
    {"dup2", DUP2_FUNC},    \
    {"dup3", DUP3_FUNC}

enum {
    CLOSE_FUNC = 1,
    DUP2_FUNC,
    DUP3_FUNC,
};

#define CALL_FUNC \
    switch (func)                                                   \
    {                                                               \
        case CONNECT_FUNC:                                          \
            rc = rpc_connect(pco_iut1, iut_s, tst_addr);            \
            break;                                                  \
                                                                    \
        case ACCEPT_FUNC:                                           \
            rc = rpc_accept(pco_iut1, iut_s, NULL, NULL);           \
            break;                                                  \
                                                                    \
        case RECV_FUNC:                                             \
            rc = rpc_recv(pco_iut1, iut_s, rx_buf, BUF_SIZE, 0);    \
            break;                                                  \
                                                                    \
        case SEND_FUNC:                                             \
            rc = send_f(pco_iut1, iut_s, tx_buf, BUF_SIZE, 0);      \
            break;                                                  \
                                                                    \
        case SENDFILE_FUNC:                                         \
            rc = rpc_sendfile(pco_iut1, iut_s, file_fd, NULL,       \
                              file_length, FALSE);                  \
            break;                                                  \
    }

#define CALL_CLOSE_FUNC \
    switch (close_func)                          \
    {                                            \
        case CLOSE_FUNC:                         \
            rpc_close(pco_iut2, iut_s);          \
            break;                               \
                                                 \
        case DUP2_FUNC:                          \
            rpc_dup2(pco_iut2, dup_s, iut_s);    \
            break;                               \
                                                 \
        case DUP3_FUNC:                          \
            rpc_dup3(pco_iut2, dup_s, iut_s, 0); \
            break;                               \
    }

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut1 = NULL;
    rcf_rpc_server             *pco_iut2 = NULL;
    rcf_rpc_server             *pco_tst = NULL;

    const struct sockaddr      *iut_addr = NULL;
    const struct sockaddr      *tst_addr = NULL;
    const void                 *alien_link_addr = NULL;
    const struct if_nameindex  *iut_if = NULL;
    const char                 *func_str;

    int                         iut_s  = -1;
    int                         tst_s = -1;
    int                         acc_s = -1;
    int                         dup_s = -1;
    int                         aux_s = -1;
    uint64_t                    sent = 0;

    int                         file_fd = -1;
    const char                 *file_name = "sendfile.tmp";
    int                         file_length = BUF_SIZE + 1;

    uint8_t                     tx_buf[BUF_SIZE];
    uint8_t                     rx_buf[BUF_SIZE];

    int                         func = 0;
    rpc_send_f                  send_f = NULL;
    int                         close_func = 0;
    rpc_socket_type             sock_type;

    te_bool                     is_done = FALSE;
    te_bool                     is_failed = FALSE;
    te_bool                     neigh_added = FALSE;
    rpc_socket_domain           domain;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut1);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut1, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_ENUM_PARAM(func, FUNCS);
    TEST_GET_ENUM_PARAM(close_func, CLOSE_FUNCS);
    TEST_GET_SOCK_TYPE(sock_type);

    if (func == SEND_FUNC)
    {
        if ((func_str = test_get_param(argc, argv, "func")) == NULL || 
            (send_f = rpc_send_func_by_string(func_str)) == NULL)
            TEST_STOP;
    }

    domain = rpc_socket_domain_by_addr(iut_addr);

    dup_s = rpc_socket(pco_iut1, domain, sock_type, RPC_PROTO_DEF);
    iut_s = rpc_socket(pco_iut1, domain, sock_type, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, domain, sock_type, RPC_PROTO_DEF);
    rpc_bind(pco_iut1, iut_s, iut_addr);
    rpc_bind(pco_tst, tst_s, tst_addr);

    if (sock_type == RPC_SOCK_DGRAM)
    {
        rpc_connect(pco_iut1, iut_s, tst_addr);
        rpc_connect(pco_tst, tst_s, iut_addr);
    }
    else
    {
        if (func == CONNECT_FUNC)
        {
            CHECK_RC(tapi_update_arp(pco_iut1->ta, iut_if->if_name,
                                     NULL, NULL, tst_addr,
                                     CVT_HW_ADDR(alien_link_addr),
                                     TRUE));
            CFG_WAIT_CHANGES;
            neigh_added = TRUE;
            rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);
        }
        else if (func == ACCEPT_FUNC)
            rpc_listen(pco_iut1, iut_s, SOCKTS_BACKLOG_DEF);
        else
        {
            rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);
            rpc_connect(pco_iut1, iut_s, tst_addr);
            acc_s = rpc_accept(pco_tst, tst_s, NULL, NULL);
            aux_s = tst_s;
            tst_s = acc_s;
            acc_s = -1;
        
            if (func == SEND_FUNC || func == SENDFILE_FUNC)
            {
                rpc_overfill_buffers(pco_iut1, iut_s, &sent);

                if (func == SENDFILE_FUNC)
                {
                    PREPARE_REMOTE_FILE(pco_iut1->ta, file_length, 'A',
                                        file_name, file_name);
                    RPC_FOPEN_D(file_fd, pco_iut1, file_name,
                                RPC_O_RDONLY, 0);
                }
            }
        }
    }

    pco_iut1->op = RCF_RPC_CALL;
    CALL_FUNC;

    MSLEEP(500);
    rcf_rpc_server_is_op_done(pco_iut1, &is_done);
    if (is_done)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut1);
        CALL_FUNC;
        TEST_FAIL("Function call was not blocking really");
    }

    pco_iut2->op = RCF_RPC_CALL;
    CALL_CLOSE_FUNC;

    SLEEP(1);
    rcf_rpc_server_is_op_done(pco_iut2, &is_done);
    if (!is_done)
    {
        MSLEEP(pco_iut2->def_timeout / 2);
        rcf_rpc_server_is_op_done(pco_iut2, &is_done);
        if (!is_done)
            TEST_VERDICT("%s() called from another thread timed out",
                         close_func == CLOSE_FUNC ? "close" :
                            close_func == DUP2_FUNC ? "dup2" : "dup3");
    }

    pco_iut2->op = RCF_RPC_WAIT;
    CALL_CLOSE_FUNC;

    rcf_rpc_server_is_op_done(pco_iut1, &is_done);
    rc = 0;

    if (!is_done)
    {
        RING_VERDICT("Blocking function call was not terminated after "
                     "closing socket from another thread");

        RPC_AWAIT_IUT_ERROR(pco_tst);
        switch(func)
        {
            case CONNECT_FUNC:
                CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut1->ta,
                                                  iut_if->if_name,
                                                  tst_addr));
                rc = rpc_accept(pco_tst, tst_s, NULL, NULL);
                neigh_added = FALSE;
                break;

            case ACCEPT_FUNC:
                rc = rpc_connect(pco_tst, tst_s, iut_addr);
                break;

            case RECV_FUNC:
                rc = rpc_send(pco_tst, tst_s, rx_buf, BUF_SIZE, 0);
               break;

            case SEND_FUNC:
            case SENDFILE_FUNC:
                do {
                    RPC_AWAIT_IUT_ERROR(pco_tst);
                } while ((rc = rpc_recv(pco_tst, tst_s, tx_buf, BUF_SIZE,
                                        RPC_MSG_DONTWAIT) > 0));

                if (rc < 0 && RPC_ERRNO(pco_tst) != RPC_EAGAIN)
                {
                    RING_VERDICT("Nonblocking recv() on TESTER "
                                 "unexpectedly returned errno %s",
                                 errno_rpc2str(RPC_ERRNO(pco_tst)));
                    is_failed = TRUE;
                }

                rc = 0;
                break;
        }

        if (rc > 0 && func == CONNECT_FUNC)
        {
            aux_s = tst_s;
            tst_s = rc;
        }

        if (rc < 0)
            RING_VERDICT("%s() on TESTER returned %s errno",
                         func == ACCEPT_FUNC ? "connect" :
                         func == CONNECT_FUNC ? "accept" :
                                                "send",
                         errno_rpc2str(RPC_ERRNO(pco_tst)));

        TAPI_WAIT_NETWORK;
        rcf_rpc_server_is_op_done(pco_iut1, &is_done);
    }

    if (is_done)
    {
        RPC_AWAIT_ERROR(pco_iut1);
        CALL_FUNC;
        if (close_func != DUP2_FUNC && close_func != DUP3_FUNC)
            iut_s = -1;

        if (rc < 0)
        {
            TEST_VERDICT("Blocking function call on a socket closed from "
                         "another thread terminated with errno "
                         RPC_ERROR_FMT, RPC_ERROR_ARGS(pco_iut1));
        }
        else if (func == ACCEPT_FUNC)
        {
            acc_s = rc;
        }
        else if ((func == RECV_FUNC || func == SEND_FUNC) &&
                 rc != BUF_SIZE)
        {
            if (rc > BUF_SIZE)
                TEST_FAIL("Impossible is possible");

            RING_VERDICT("Blocking %s() returned %s",
                         func == RECV_FUNC ? "recv" : "send",
                         rc == 0 ? "0" : "less than expected",
                         BUF_SIZE);
        }
    }
    else
    {
        dup_s = -1;
        acc_s = -1;
        iut_s = -1;
        TEST_VERDICT("Blocking function call on a socket closed from "
                     "another thread was not terminated");
    }
    
    if (is_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, aux_s);
    CLEANUP_RPC_CLOSE(pco_iut1, dup_s);
    CLEANUP_RPC_CLOSE(pco_iut1, acc_s);
    CLEANUP_RPC_CLOSE(pco_iut1, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut1, file_fd);

    if (neigh_added)
    {
        tapi_cfg_del_neigh_entry(pco_iut1->ta,
                                 iut_if->if_name,
                                 tst_addr);
        CFG_WAIT_CHANGES;
    }

    TEST_END;
}
