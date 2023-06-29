/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-reuseaddr_2msl Check that there is not a possibility for address reusing for 2MSL interval if SO_REUSEADDR options is not applied to the socket
 *
 * @objective  Check a possibility for address reusing for 2MSL interval
 *             by means of applying SO_REUSEADDR option to the socket.
 *
 * @type Conformance, compatibility
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TST
 * @param reuse         @c TRUE - apply @c SO_REUSEADDR option to the
 *                      socket; @c FALSE - carry out the test without
 *                      @c SO_REUSEADDR option set;
 * @param exec          Which socket to open after exec
 *                      (could be none, iut, aux)
 *
 * @par Test sequence:
 *
 * -# Create @p aux_s and @p iut_s socket of the @p SOCK_STREAM type 
 *    on @p pco_iut in the right order with exec() between them, if
 *    necessary according to @p exec parameter;
 * -# @b bind() @p iut_s to the @p iut_addr;
 * -# If @p reuse is @c TRUE set @c SO_REUSEADDR on @p iut_s;
 * -# Create @p tst_s socket of the @p SOCK_STREAM type on @p pco_tst;
 * -# @b bind() @p tst_s to the @p tst_addr;
 * -# Call @b listen() on @p tst_s;
 * -# @b connect() @p iut_s to the @p tst_s server socket;
 * -# @b accept() new @p acc_s connection on @p tst_s;
 * -# @b close() @p iut_s;
 * -# @b close() @p acc_s;
 * -# If @p reuse is @c FALSE:
 *       - @b bind() @p aux_s to the @p iut_addr;
 *       - Check that @b bind() returns -1 and @b errno set to EADDRINUSE;
 * -# Wait for 2MSL insterval to reuse @p iut_addr anew;
 * -# If @p reuse is @c TRUE set @c SO_REUSEADDR on @p aux_s;
 * -# @b bind() @p aux_s to the @p iut_addr;
 * -# @b connect() @p aux_s to the @p tst_s server socket;
 * -# @b accept() @p acc_s connection on @p tst_s;
 * -# @b close() created sockets.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/reuseaddr_2msl"

#include "sockapi-test.h"
#include "iomux.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut;
    rcf_rpc_server        *pco_tst;

    int                    iut_s = -1;
    int                    acc_s = -1;
    int                    tst_s = -1;
    int                    aux_s = -1;

    const struct sockaddr   *iut_addr;
    struct sockaddr_storage  bind_addr;
    const struct sockaddr   *tst_addr;

    int                    opt_val;
    te_bool                reuse = FALSE;
    const char            *exec;
    te_bool                pass_op = FALSE;
    te_bool                use_wildcard = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_BOOL_PARAM(reuse);
    TEST_GET_STRING_PARAM(exec);
    TEST_GET_BOOL_PARAM(pass_op);
    TEST_GET_BOOL_PARAM(use_wildcard);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    memcpy(&bind_addr, iut_addr, te_sockaddr_get_size(iut_addr));
    if (use_wildcard)
        te_sockaddr_set_wildcard(SA(&bind_addr));

    if (strcmp(exec, "none") == 0)
    {
        aux_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
        iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
    }
    else if (strcmp(exec, "iut") == 0)
    {
        aux_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rcf_rpc_server_exec(pco_iut);
        iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
    }
    else if (strcmp(exec, "aux") == 0)
    {
        iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rcf_rpc_server_exec(pco_iut);
        aux_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
    }
    else
        TEST_FAIL("Unexpected value of exec parameter, %s", exec);

    if (reuse == TRUE)
    {
        opt_val = 1;
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_REUSEADDR, &opt_val);
    }

    rpc_bind(pco_iut, iut_s, SA(&bind_addr));

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_bind(pco_tst, tst_s, tst_addr);

    if (pass_op)
    {
        rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

        rpc_connect(pco_tst, tst_s, iut_addr);
        acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);

        RPC_CLOSE(pco_iut, iut_s);

        RPC_CLOSE(pco_iut, acc_s);
    }
    else
    {
        rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);

        rpc_connect(pco_iut, iut_s, tst_addr);
        acc_s = rpc_accept(pco_tst, tst_s, NULL, NULL);

        RPC_CLOSE(pco_iut, iut_s);

        RPC_CLOSE(pco_tst, acc_s);
    }


    if (reuse == FALSE)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_bind(pco_iut, aux_s, SA(&bind_addr));
        if (rc != -1)
            TEST_VERDICT("bind() returns %d instead of -1 "
                         "(without SO_REUSEADDR applied)", rc);
        CHECK_RPC_ERRNO(pco_iut, RPC_EADDRINUSE,
                        "bind() returns -1, but");

        /*
         * Wait for 2MSL interval:
         * Stevens defined 4 minutes;
         * It seems Linux provides 60 seconds.
         */
        rc = iomux_call_default_simple(pco_tst, tst_s, 0, NULL,
                                       TE_SEC2MS(121));
        if (rc != 0)
            TEST_FAIL("select() returns %d instead of 0");
    }

    if (pass_op)
        RPC_CLOSE(pco_tst, tst_s);

    MSLEEP(100);

    if (reuse == TRUE)
    {
        opt_val = 1;
        rpc_setsockopt(pco_iut, aux_s, RPC_SO_REUSEADDR, &opt_val);
    }

    rpc_bind(pco_iut, aux_s, SA(&bind_addr));

    if (pass_op)
    {
        tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);

        rpc_listen(pco_iut, aux_s, SOCKTS_BACKLOG_DEF);

        rc = rpc_connect(pco_tst, tst_s, iut_addr);

        acc_s = rpc_accept(pco_iut, aux_s, NULL, NULL);
    }
    else
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_connect(pco_iut, aux_s, tst_addr);
        if (rc != 0)
            TEST_VERDICT("connect() returns %d and errno is set to %s",
                         rc, errno_rpc2str(RPC_ERRNO(pco_iut)));

        acc_s = rpc_accept(pco_tst, tst_s, NULL, NULL);
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(((pass_op) ? pco_iut : pco_tst), acc_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, aux_s);

    sockts_kill_zombie_stacks_if_many(pco_iut);

    TEST_END;
}
