/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-default_opts System wide default values preset of
 *                              socket options.
 *
 * @objective Check that default socket options are set according to
 *            system wide appropriate values.
 *
 * @type conformance
 *
 * @param pco_iut    PCO on IUT
 * @param sock_type  Socket type: @c SOCK_DGRAM or @c SOCK_STREAM
 * @param domain     Socket domain type: @c PF_INET or @c PF_INET6
 * @param opt_name   Option to be tested
 *
 * @par Test sequence:
 *
 * -# Disable Onload acceleration.
 * -# Create a socket with domain @p domain and type @p sock_type
 *    on IUT.
 * -# Call @b getsockopt() on the opened socket with appropriate @p opt_name
 *    and save option value.
 * -# Close the socket.
 * -# Enable Onload acceleration.
 * -# Create second socket with domain @p domain and type @p sock_type
 *    on @p pco_iut.
 * -# Call @b getsockopt() on the last opened socket with appropriate
 *    @p opt_name and save option value.
 * -# Close the second socket.
 * -# Check that obtained values of the socket option are equal.
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/default_opts"

#include "sockapi-test.h"
#include "onload.h"

#define TEST_SOCKOPT_BUF_LEN 128

/**
 * Open a socket and get a socket option value
 */
static int
default_opts_get_opt(rcf_rpc_server *rpcs, rpc_socket_domain domain,
                     rpc_socket_type sock_type, rpc_sockopt opt_name,
                     uint8_t *val_buf, socklen_t *val_buf_len,
                     te_errno *err)
{
    int   sock;
    int   ret;

    sock = rpc_socket(rpcs, domain, sock_type, RPC_PROTO_DEF);

    RPC_AWAIT_IUT_ERROR(rpcs);

    memset(val_buf, 0, *val_buf_len);

    switch(opt_name)
    {
        case RPC_IP_ADD_MEMBERSHIP:
        case RPC_IP_DROP_MEMBERSHIP:
        case RPC_IP_MULTICAST_IF:
            ((rpc_sockopt_value *)val_buf)->v_mreqn.type = OPT_MREQN;
            break;

        case RPC_IP_ADD_SOURCE_MEMBERSHIP:
        case RPC_IP_DROP_SOURCE_MEMBERSHIP:
        case RPC_IP_BLOCK_SOURCE:
        case RPC_IP_UNBLOCK_SOURCE:
            ((rpc_sockopt_value *)val_buf)->v_mreq_source.type =
                OPT_MREQ_SOURCE;
            break;

        default:
            ;
    }

    if (opt_name == RPC_SO_BINDTODEVICE || opt_name == RPC_IP_OPTIONS ||
        opt_name == RPC_IP_PKTOPTIONS)
        ret = rpc_getsockopt_raw(rpcs, sock, opt_name,
                                 val_buf, val_buf_len);
    else
        ret = rpc_getsockopt(rpcs, sock, opt_name, val_buf);

    if (err != NULL)
        *err = RPC_ERRNO(rpcs);

    RPC_CLOSE(rpcs, sock);

    return ret;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;

    rpc_socket_type     sock_type;
    rpc_socket_domain   domain;
    rpc_socklevel       opt_level;
    rpc_sockopt         opt_name;

    socklen_t           opt_len_iut = TEST_SOCKOPT_BUF_LEN;
    socklen_t           opt_len_def = TEST_SOCKOPT_BUF_LEN;
    uint8_t             opt_val_iut_buf[TEST_SOCKOPT_BUF_LEN];
    uint8_t             opt_val_def_buf[TEST_SOCKOPT_BUF_LEN];
    int                 res;
    int                 rc2;
    te_bool             onload_en = TRUE;
    te_errno            err;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_DOMAIN(domain);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_SOCKOPT(opt_name);

    opt_level = rpc_sockopt2level(opt_name);

    RPC_AWAIT_IUT_ERROR(pco_iut);

    tapi_onload_acc(pco_iut, FALSE);
    onload_en = FALSE;
    rc = default_opts_get_opt(pco_iut, domain, sock_type, opt_name,
                              opt_val_def_buf, &opt_len_def, &err);

    tapi_onload_acc(pco_iut, TRUE);
    onload_en = TRUE;
    rc2 = default_opts_get_opt(pco_iut, domain, sock_type, opt_name,
                               opt_val_iut_buf, &opt_len_iut, NULL);

    if (rc != 0 || rc2 != 0)
    {
        if (rc == rc2)
        {
            if (err == RPC_ERRNO(pco_iut))
                TEST_SUCCESS;
            TEST_VERDICT("Both pco_native and pco_iut failed to get "
                         "option %s but with different errno %s and %s",
                         sockopt_rpc2str(opt_name), errno_rpc2str(err),
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
        }

        if (rc != 0)
            TEST_VERDICT("Native socket failed to get option %s, but "
                         "Onload socket had success",
                         sockopt_rpc2str(opt_name));
        TEST_VERDICT("Onload socket failed to get option %s with errno %s",
                     sockopt_rpc2str(opt_name),
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    if (opt_len_iut != opt_len_def)
        res = -1;
    else
        res = memcmp(opt_val_iut_buf, opt_val_def_buf,
                     TEST_SOCKOPT_BUF_LEN);

    if (res != 0)
        TEST_VERDICT("Socket option %s, %s is not equal to default",
                     socklevel_rpc2str(opt_level),
                     sockopt_rpc2str(opt_name));

    TEST_SUCCESS;

cleanup:

    if (!onload_en)
        tapi_onload_acc(pco_iut, TRUE);

    TEST_END;
}
