/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-ip_mtu_inapprop_state Get IP_MTU or IPV6_MTU socket option in inappropriate state
 *
 * @objective Get @c IP_MTU or @c IPV6_MTU socket option on just
 *            created/bound/listening TCP socket or created/bound UDP
 *            socket.
 *
 * @type conformance
 *
 * @param pco_iut           PCO on IUT
 * @param state             Shows the socket state (created/bound/listening), 
 *                          when @p getsockopt() should be called
 * @param sock_type         @c SOCK_STREAM or @c SOCK_DGRAM
 * @param opt_name          @c IP_MTU or @c IPV6_MTU
 *
 * @par Test sequence:
 *
 * -# Create socket @p iut_s of @p sock_type type on @p pco_iut.
 * -# If @p state is "created", call @b getsockopt(SOL_IP, IP_MTU) and
 *    check, that it returned @c -1 with error code @c ENOTCONN, then finish 
 *    the test.
 * -# Bind socket @p iut_s to correst local address.
 * -# If @p state is "bound", call @b getsockopt(SOL_IP, IP_MTU) and
 *    check, that it returned @c -1 with error code @c ENOTCONN, then finish 
 *    the test.
 * -# If @p sock_type is @c SOCK_DGRAM - finish the test.   
 * -# Call @p listen() on @p pco_iut.
 * -# If @p state is "listening", call @b getsockopt(SOL_IP, IP_MTU) and check, 
 *    that it returned @c -1 with error code @c ENOTCONN.
 * -# Close socket @p iut_s.   
 *
 * @author Georgij Volfson <Georgij.Volfson@oktetlabs.ru>
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/ip_mtu_inapprop_state"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rpc_socket_type         sock_type;

    const char             *state = NULL;
    rpc_sockopt             opt_name;

    int                     iut_s = -1;

    const struct sockaddr  *iut_addr = NULL;

    int                     mtu_sock_saved = 0;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_STRING_PARAM(state);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_SOCKOPT(opt_name);

    do {
        TEST_STEP("Create socket @p iut_s of @p sock_type type"
                  "on @p pco_iut.");
        iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                           sock_type, RPC_PROTO_DEF);
        if (strcmp(state, "created") == 0)
            break;

        TEST_STEP("If state is not @c created bind socket @p iut_s "
                  "to correst local address");
        rpc_bind(pco_iut, iut_s, iut_addr);
        if (strcmp(state, "bound") == 0)
            break;

        if (sock_type == RPC_SOCK_DGRAM)
            TEST_FAIL("It's impossible to call listen on datagram socket");

        TEST_STEP("If state is @c listen call @p listen() on @p pco_iut.");
        rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
        if (strcmp(state, "listening") == 0)
            break;

        TEST_FAIL("The state is unsupported");
    } while (0);

    TEST_STEP("Call @b getsockopt(@p opt_name) and check, that it "
              "returns @c -1 with errno @c ENOTCONN");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getsockopt(pco_iut, iut_s, opt_name, &mtu_sock_saved);

    if (rc != -1)
        TEST_FAIL("ioctl returns %d, but expected value is -1", rc);

    CHECK_RPC_ERRNO(pco_iut, RPC_ENOTCONN,
                    "getsockopt() function called on IUT "
                    "returned -1, but");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    TEST_END;
}
