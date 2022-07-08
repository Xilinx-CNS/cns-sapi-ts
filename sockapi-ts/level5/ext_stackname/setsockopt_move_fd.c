/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page ext_stackname-setsockopt_move_fd Call @b onload_move_fd() on a socket after @b setsockopt()
 *
 * @objective Check that calling @b onload_move_fd() does not change
 *            a socket option set before the call.
 *
 * @type use case
 *
 * @param pco_iut              PCO on IUT
 * @param pco_tst              PCO on TESTER
 * @param iut_addr             Network address on IUT
 * @param tst_addr             Network address on TESTER
 * @param sock_accepted        Whether a socket on which we test
 *                             funtions is returned by @b socket()
 *                             or @b accept().
 * @param opt_name             Name of a socket option to be tested
 * @param existing_stack1      Whether Onload stack should already exist
 *                             or not when we try to move a socket fd to it
 *                             firstly
 * @param existing_stack2      Whether Onload stack should already exist
 *                             or not when we try to move a socket fd to it
 *                             secondly
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/setsockopt_move_fd"

#include "sockapi-test.h"

#include "onload.h"
#include "extensions.h"

#include "move_fd_helpers.h"

#include <netinet/ip.h>

#define STACK_NAME1 "foo"
#define STACK_NAME2 "bar"

#define TST_OPTIONS_LEN  44
#define IP_TS_OPTS_LEN   12

te_bool
is_opt_boolean(rpc_sockopt opt)
{
    switch (opt)
    {
        case RPC_SO_BROADCAST:
        case RPC_SO_DEBUG:
        case RPC_SO_DONTROUTE:
        case RPC_SO_KEEPALIVE:
        case RPC_SO_OOBINLINE:
        case RPC_SO_REUSEADDR:
        case RPC_SO_TIMESTAMP:
        case RPC_SO_TIMESTAMPNS:
        case RPC_TCP_CORK:
        case RPC_TCP_DEFER_ACCEPT:
        case RPC_TCP_NODELAY:
        case RPC_TCP_QUICKACK:
        case RPC_IP_MTU_DISCOVER:
        case RPC_IP_OPTIONS:
        case RPC_IP_RECVERR:
            return TRUE;

        default:
            return FALSE;
    }

    return FALSE;
}

te_bool
is_opt_integer(rpc_sockopt opt)
{
    switch (opt)
    {
        case RPC_SO_PRIORITY:
        case RPC_SO_RCVBUF:
        case RPC_SO_RCVLOWAT:
        case RPC_SO_SNDBUF:
        case RPC_TCP_KEEPCNT:
        case RPC_TCP_KEEPIDLE:
        case RPC_TCP_KEEPINTVL:
        case RPC_TCP_MAXSEG:
        case RPC_IP_TTL:
        case RPC_SO_TIMESTAMPING:
            return TRUE;

        default:
            return FALSE;
    }

    return FALSE;
}

static inline te_bool
check_sockopt(rcf_rpc_server *rpcs,
              int s,
              rpc_sockopt opt_name,
              uint8_t *opts_buf_exp,
              socklen_t opts_buf_len_exp,
              rpc_sockopt_value *opt_val_exp,
              const char *err_msg)
{
    uint8_t             opts_buf[TST_OPTIONS_LEN];
    socklen_t           opts_buf_len;
    rpc_sockopt_value   opt_val;

    if (opt_name == RPC_IP_OPTIONS ||
        opt_name == RPC_SO_BINDTODEVICE)
    {
        memset(opts_buf, 0, sizeof(opts_buf)); 
        opts_buf_len = sizeof(opts_buf);
        rpc_getsockopt_raw(rpcs, s, opt_name,
                           opts_buf, &opts_buf_len);
        if (opts_buf_len_exp != opts_buf_len ||
            memcmp(opts_buf_exp, opts_buf, opts_buf_len) != 0)
        {
            ERROR_VERDICT("%s: Value of a socket option changed",
                          err_msg);
            return FALSE;
        }
    }
    else
    {
        memset(&opt_val, 0, sizeof(opt_val));
        rpc_getsockopt(rpcs, s, opt_name, &opt_val); 

        if (memcmp(opt_val_exp, &opt_val, sizeof(opt_val)) != 0)
        {
            ERROR_VERDICT("%s: Value of a socket option changed",
                          err_msg);
            return FALSE;
        }
    }

    return TRUE;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;
    te_bool                 existing_stack1 = FALSE;
    te_bool                 existing_stack2 = FALSE;

    int                     iut_s = -1;
    int                     iut_s_listening = -1;
    int                     iut_s_accepted = -1;
    int                     iut_s_aux = -1;
    int                     tst_s = -1;
    te_bool                 test_failed = FALSE;
    te_bool                 bool_rc;
    te_bool                 sock_accepted = FALSE;
    te_bool                 restore_stack_name = FALSE;
    char                   *init_stack_name;

    rpc_sockopt         opt_name;
    rpc_sockopt_value   opt_val;
    rpc_sockopt_value   opt_val_old;
    rpc_sockopt_value   opt_val_new;
    char                opts_buf[TST_OPTIONS_LEN];
    socklen_t           opts_len;
    uint8_t             opts_buf_old[TST_OPTIONS_LEN];
    socklen_t           opts_len_old;
    uint8_t             opts_buf_new[TST_OPTIONS_LEN];
    socklen_t           opts_len_new;

    const struct if_nameindex   *iut_if;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(sock_accepted);
    TEST_GET_SOCKOPT(opt_name);
    TEST_GET_BOOL_PARAM(existing_stack1);
    TEST_GET_BOOL_PARAM(existing_stack2);
    TEST_GET_IF(iut_if);

    init_stack_name = tapi_onload_get_cur_stackname(pco_iut);

    TEST_STEP("Obtain TCP socket returned ether by @b socket() or by @b accept(), "
              "according to @p sock_accepted parameter.");
    if (sock_accepted)
    {
        bool_rc =
            gen_tcp_conn_with_sock(pco_iut, iut_addr, pco_tst, tst_addr,
                                   TRUE, TRUE, FALSE, TRUE,
                                   &iut_s_listening, &iut_s,
                                   &tst_s, NULL);
        if (!bool_rc)
            TEST_STOP;
    }
    else
        iut_s = rpc_socket(pco_iut, RPC_AF_INET, RPC_SOCK_STREAM,
                           RPC_PROTO_DEF);

    TEST_STEP("Get initial @p opt_name socket option value and change it.");

    memset(&opt_val, 0, sizeof(opt_val));
    memset(&opt_val_new, 0, sizeof(opt_val));
    memset(&opt_val_old, 0, sizeof(opt_val));

    RPC_AWAIT_IUT_ERROR(pco_iut);
    if (opt_name == RPC_IP_OPTIONS ||
        opt_name == RPC_SO_BINDTODEVICE)
    {
        opts_len_old = sizeof(opts_buf_old);
        memset(opts_buf_old, 0, opts_len_old); 
        rc = rpc_getsockopt_raw(pco_iut, iut_s, opt_name,
                                opts_buf_old, &opts_len_old);
    }
    else
    {
        rc = rpc_getsockopt(pco_iut, iut_s,
                            opt_name, &opt_val_old);
        memcpy(&opt_val, &opt_val_old, sizeof(opt_val));
    }

    if (rc != 0)
        TEST_VERDICT("Failed to get an initial value of %s: errno %s",
                     sockopt_rpc2str(opt_name),
                     errno_rpc2str(RPC_ERRNO(pco_iut)));

    if (is_opt_boolean(opt_name))
        opt_val.v_int = !opt_val.v_int;
    else if (opt_name == RPC_SO_LINGER)
    {
        if (opt_val.v_linger.l_onoff)
        {
            opt_val.v_linger.l_onoff = 0;
            opt_val.v_linger.l_linger = 0;
        }
        else
        {
            opt_val.v_linger.l_onoff = 1;
            opt_val.v_linger.l_linger = 1;
        }
    }
    else if (is_opt_integer(opt_name))
        opt_val.v_int++;
    else if (opt_name == RPC_SO_RCVTIMEO ||
             opt_name == RPC_SO_SNDTIMEO)
        opt_val.v_tv.tv_sec++; 
    else if (opt_name == RPC_IP_OPTIONS ||
             opt_name == RPC_SO_BINDTODEVICE)
    {
        memset(&opts_buf, 0, sizeof(opts_buf));
        if (opts_len_old == 0)
        {
            if (opt_name == RPC_SO_BINDTODEVICE)
            {
                strcpy(opts_buf, iut_if->if_name);
                opts_len = strlen(opts_buf) + 1;
            }
            else
            {
                opts_buf[0] = IPOPT_TIMESTAMP;
                opts_buf[1] = IP_TS_OPTS_LEN;
                opts_buf[2] = 5;
                opts_len = IP_TS_OPTS_LEN;
            }
        }
        else
            opts_len = 0;
    }
    else if (opt_name == RPC_IP_TOS)
    {
        if (opt_val.v_int != IPTOS_RELIABILITY)
            opt_val.v_int = IPTOS_RELIABILITY;
        else
            opt_val.v_int = IPTOS_LOWDELAY;
    }
    else
        TEST_FAIL("Unknown option type");

    if (opt_name == RPC_IP_OPTIONS ||
        opt_name == RPC_SO_BINDTODEVICE)
    {
        rpc_setsockopt_raw(pco_iut, iut_s, opt_name,
                           opts_buf, opts_len);
        opts_len_new = sizeof(opts_buf_new);
        memset(opts_buf_new, 0, opts_len_new);
        rpc_getsockopt_raw(pco_iut, iut_s, opt_name,
                           opts_buf_new, &opts_len_new);
        if (opts_len_new == opts_len_old &&
            memcmp(opts_buf_new, opts_buf_old, opts_len_old) == 0)
            TEST_VERDICT("Failed to change a value for a socket option %s",
                         sockopt_rpc2str(opt_name));
    }
    else
    {
        rpc_setsockopt(pco_iut, iut_s, opt_name, &opt_val);
        rpc_getsockopt(pco_iut, iut_s, opt_name, &opt_val_new); 
        if (memcmp(&opt_val_new, &opt_val_old, sizeof(opt_val)) == 0)
            TEST_VERDICT("Failed to change a value for a socket option %s",
                         sockopt_rpc2str(opt_name));
    }

    TEST_STEP("Move TCP socket to a new stack.");

    tapi_rpc_onload_set_stackname_create(pco_iut, ONLOAD_ALL_THREADS,
                                         ONLOAD_SCOPE_PROCESS, STACK_NAME1,
                                         existing_stack1, &iut_s_aux);

    restore_stack_name = TRUE;

    bool_rc = tapi_rpc_onload_move_fd_check(
                                  pco_iut, iut_s,
                                  TAPI_MOVE_FD_SUCCESS_EXPECTED,
                                  STACK_NAME1,
                                  "The first call of onload_move_fd()");
    test_failed = test_failed || !bool_rc;

    TEST_STEP("Check that the value of @p opt_name socket option remained "
              "the same.");
    bool_rc = 
         check_sockopt(pco_iut, iut_s, opt_name,
                       opts_buf_new,
                       opts_len_new,
                       &opt_val_new,
                       "After the first call of onload_move_fd()");
    test_failed = test_failed || !bool_rc;

    TEST_STEP("Move TCP socket to a new stack the second time.");

    tapi_rpc_onload_set_stackname_create(pco_iut, ONLOAD_ALL_THREADS,
                                         ONLOAD_SCOPE_PROCESS, STACK_NAME2,
                                         existing_stack2, &iut_s_aux);

    bool_rc = tapi_rpc_onload_move_fd_check(
                          pco_iut, iut_s,
                          sock_accepted ? TAPI_MOVE_FD_FAILURE_EXPECTED :
                                          TAPI_MOVE_FD_SUCCESS_EXPECTED,
                          STACK_NAME2,
                          "The second call of onload_move_fd()");
    test_failed = test_failed || !bool_rc;

    TEST_STEP("Check that the value of @p opt_name socket option remained "
              "the same.");
    bool_rc = 
        check_sockopt(pco_iut, iut_s, opt_name,
                      opts_buf_new,
                      opts_len_new,
                      &opt_val_new,
                      "After the second call of onload_move_fd()");
    test_failed = test_failed || !bool_rc;

    TEST_STEP("Check that socket is still usable.");
    if (!sock_accepted)
    {
        bool_rc = 
             gen_tcp_conn_with_sock(pco_iut, iut_addr,
                                    pco_tst, tst_addr,
                                    FALSE, TRUE, FALSE, TRUE,
                                    &iut_s, &iut_s_accepted,
                                    &tst_s, NULL);
        if (!bool_rc)
            TEST_STOP;
    }

    sockts_test_connection(pco_iut,
                           sock_accepted ? iut_s : iut_s_accepted,
                           pco_tst, tst_s);

    if (test_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    if (restore_stack_name)
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, init_stack_name);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_listening);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_accepted);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_aux);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
