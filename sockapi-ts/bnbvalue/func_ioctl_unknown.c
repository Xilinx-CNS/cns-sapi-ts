/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_ioctl_unknown IOCTL requests in case of invalid ioctl number
 *
 * @objective Check the behavior of @p ioctl() requests with invalid ioctl
 *            number.
 *
 * @type conformance
 *
 * @param env            Testing environment
 *                         - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param sock_type      Socket type
 *                         - SOCK_STREAM
 *                         - SOCK_DGRAM
 * @param how            Determine test sequence.
 *                         - created
 *                         - bound
 *                         - listening
 *                         - connected
 *                         - client
 *                         - accepted
 *
 * @par Test sequence:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_ioctl_unknown"

#include "sockapi-test.h"


enum {
    HOW_CREATED = 0,
    HOW_BOUND,
    HOW_LISTENING,
    HOW_CONNECTED,
    HOW_CLIENT,
    HOW_ACCEPTED
};

#define HOW_VARIANTS \
    {"created", HOW_CREATED},     \
    {"bound", HOW_BOUND},         \
    {"listening", HOW_LISTENING}, \
    {"connected", HOW_CONNECTED}, \
    {"client", HOW_CLIENT},       \
    {"accepted", HOW_ACCEPTED}

int
main(int argc, char *argv[])
{
    rpc_socket_type         sock_type;
    rpc_socket_domain       domain;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    int                     how = 0;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr = NULL;
    struct sockaddr_storage wildcard_addr;

    int                     iut_s = -1;
    int                     tst_s = -1;
    int                     acc_s = -1;

    int                     req_val;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_ENUM_PARAM(how, HOW_VARIANTS);

    domain = rpc_socket_domain_by_addr(iut_addr);

    TEST_STEP("Create socket @b iut_s of @p sock_type type on @p pco_iut.");
    iut_s = rpc_socket(pco_iut, domain, sock_type, RPC_PROTO_DEF);

    assert(sizeof(wildcard_addr) >= te_sockaddr_get_size(iut_addr));
    memcpy(&wildcard_addr, iut_addr, te_sockaddr_get_size(iut_addr));
    te_sockaddr_set_wildcard(SA(&wildcard_addr));

    switch (how)
    {
        case HOW_CREATED:
            break;

        case HOW_BOUND:
            TEST_STEP("If @p how value is @c BOUND @b bind() @b iut_s socket "
                      "to @p iut_addr.");
            rpc_bind(pco_iut, iut_s, SA(&wildcard_addr));
            break;

        case HOW_LISTENING:
            TEST_STEP("If @p how value is @c LISTENING @b bind() @b iut_s "
                      "socket to @p iut_addr, call @b listen() on @b iut_s "
                      "socket.");
            rpc_bind(pco_iut, iut_s, SA(&wildcard_addr));
            rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
            break;

        case HOW_CLIENT:
            TEST_STEP("If @p how value is @c CLIENT create @b tst_s socket and "
                      "bind it to @p tst_addr, call @b listen() on @b tst_s "
                      "socket, call @p connect() on @b iut_s socket and call "
                      "@b accept() on @b tst_s socket. @b acc_s socket should "
                      "appear.");
            tst_s = rpc_socket(pco_tst, domain, sock_type, RPC_PROTO_DEF);
            rpc_bind(pco_tst, tst_s, tst_addr);
            rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);
            rpc_connect(pco_iut, iut_s, tst_addr);
            acc_s = rpc_accept(pco_tst, tst_s, NULL, NULL);
            break;

        case HOW_ACCEPTED:
            TEST_STEP("If @p how value is @c ACCEPTED create @b tst_s socket "
                      "and bind it to @p tst_addr, call @b listen() on "
                      "@b iut_s socket, call @p connect() on @b tst_s socket "
                      "and call @b accept() on @b iut_s socket. @b acc_s "
                      "socket should appear.");
            tst_s = rpc_socket(pco_tst, domain, sock_type, RPC_PROTO_DEF);
            rpc_bind(pco_tst, tst_s, tst_addr);
            rpc_bind(pco_iut, iut_s, SA(&wildcard_addr));
            rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
            rpc_connect(pco_tst, tst_s, iut_addr);
            acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);
            break;

        case HOW_CONNECTED:
            TEST_STEP("If @p how value is @c CONNECTED create @b tst_s socket "
                      "and bind it to @p tst_addr, @b connect() @b iut_s "
                      "socket to @b tst_s socket.");
            tst_s = rpc_socket(pco_tst, domain, sock_type, RPC_PROTO_DEF);
            rpc_bind(pco_tst, tst_s, tst_addr);
            rpc_connect(pco_iut, iut_s, tst_addr);
            break;

        default:
            TEST_FAIL("Parameter 'how' has invalid value");
    }

    TEST_STEP("Call @b ioctl() with @c SIOUNKNOWN request on @b iut_s socket "
              "or on @b acc_s socket if @p how value is @c ACCEPTED.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_ioctl(pco_iut, (how != HOW_ACCEPTED) ? iut_s : acc_s,
                   RPC_SIOUNKNOWN, &req_val);

    TEST_STEP("Check that @p ioctl() returns @c -1 and the error code is "
              "@c EINVAL.");
    if (rc != -1)
        TEST_FAIL("ioctl returns %d, but expected value is -1", rc);

    CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL,
                    "ioctl() function called on IUT "
                    "returned -1, but");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE((how == HOW_CLIENT) ? pco_tst : pco_iut, acc_s);

    TEST_END;
}
