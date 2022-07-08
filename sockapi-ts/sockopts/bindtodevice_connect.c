/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page sockopts-bindtodevice_connect Connecting TCP socket bound to an interface
 *
 * @objective Check that TCP socket bound to an interface can connect
 *            only to an address routable via this interface.
 *
 * @type conformance
 *
 * @reference MAN 7 socket
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_two_nets_all
 * @param blocking  If @c TRUE, socket FD is blocking;
 *                  otherwise it is not.
 *
 * @par Test sequence:
 *
 *
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/bindtodevice_connect"

#include "sockapi-test.h"

/** Maximum number of attempts to call connect(). */
#define MAX_ATTEMPTS 200

/**
 * Call connect(), check that it fails with expected errno.
 *
 * @param rpcs        RPC server.
 * @param s           Socket FD.
 * @param addr        Address to connect to.
 * @param exp_errno   Expected errno.
 * @param name        Name to use in verdicts.
 */
static void
check_connect(rcf_rpc_server *rpcs, int s,
              const struct sockaddr *addr,
              te_errno exp_errno, const char *name)
{
    te_errno rc;

    RPC_AWAIT_ERROR(rpcs);
    rc = rpc_connect(rpcs, s, addr);
    if (rc < 0)
    {
        if (RPC_ERRNO(rpcs) != exp_errno)
        {
            TEST_VERDICT("The %s connect() call failed "
                         "with %r instead of %r", name,
                         RPC_ERRNO(rpcs), exp_errno);
        }
    }
    else
    {
        TEST_VERDICT("The %s connect() call succeeded "
                     "unexpectedly", name);
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst1 = NULL;
    rcf_rpc_server             *pco_tst2 = NULL;
    int                         iut_s = -1;
    int                         tst1_s = -1;
    int                         tst2_s = -1;
    const struct if_nameindex  *iut_if2 = NULL;
    const struct sockaddr      *tst1_addr = NULL;
    const struct sockaddr      *tst2_addr = NULL;

    te_bool blocking;
    te_bool ipv6;
    int i;

    /* Test preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    TEST_GET_IF(iut_if2);
    TEST_GET_BOOL_PARAM(blocking);

    ipv6 = (tst1_addr->sa_family == AF_INET6);

    TEST_STEP("Create a TCP socket on IUT; use @c SOCK_NONBLOCK flag to "
              "make it nonblocking if @p blocking is @c FALSE.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(tst1_addr),
                       RPC_SOCK_STREAM | (blocking ? 0 : RPC_SOCK_NONBLOCK),
                       RPC_PROTO_DEF);

    TEST_STEP("Create TCP sockets on @p pco_tst1 and @p pco_tst2.");
    tst1_s = rpc_socket(pco_tst1, rpc_socket_domain_by_addr(tst1_addr),
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst2_s = rpc_socket(pco_tst2, rpc_socket_domain_by_addr(tst2_addr),
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);

    TEST_STEP("With @c SO_BINDTODEVICE bind the IUT socket to "
              "@p iut_if2 interface.");
    rpc_bind_to_device(pco_iut, iut_s, iut_if2->if_name);

    TEST_STEP("Bind the socket on @p pco_tst1 to @p tst1_addr.");
    rpc_bind(pco_tst1, tst1_s, tst1_addr);
    TEST_STEP("Bind the socket on @p pco_tst2 to @p tst2_addr.");
    rpc_bind(pco_tst2, tst2_s, tst2_addr);

    TEST_STEP("Call @b listen() on the Tester sockets.");
    rpc_listen(pco_tst1, tst1_s, 1);
    rpc_listen(pco_tst2, tst2_s, 1);

    if (blocking)
    {
        TEST_STEP("If @p blocking is @c TRUE, call @b connect() and check "
                  "that it fails with @c EHOSTUNREACH in case of IPv4 and "
                  "with @c ENETUNREACH in case of IPv6.");
        check_connect(pco_iut, iut_s, tst1_addr,
                      (ipv6 ? RPC_ENETUNREACH : RPC_EHOSTUNREACH),
                      "blocking");
    }
    else
    {
        TEST_STEP("If @p blocking is @c FALSE:");

        TEST_SUBSTEP("Call @b connect() the first time, check that it "
                     "fails with @c EINPROGRESS in case of IPv4 and "
                     "with @c ENETUNREACH in case of IPv6.");
        check_connect(pco_iut, iut_s, tst1_addr,
                      (ipv6 ? RPC_ENETUNREACH : RPC_EINPROGRESS),
                      "first nonblocking");

        if (RPC_ERRNO(pco_iut) == RPC_EINPROGRESS)
        {
            TEST_SUBSTEP("If @b connect() failed with @c EINPROGRESS, "
                         "call it in a loop until it fails with "
                         "@c EHOSTUNREACH. Check that it can fail "
                         "only with @c EALREADY before that.");

            for (i = 0; i < MAX_ATTEMPTS; i++)
            {
                TAPI_WAIT_NETWORK;

                RPC_AWAIT_ERROR(pco_iut);
                rc = rpc_connect(pco_iut, iut_s, tst1_addr);
                if (rc >= 0)
                {
                    TEST_VERDICT("Eventually nonblocking connect() "
                                 "succeeded");
                }
                else if (RPC_ERRNO(pco_iut) == RPC_EHOSTUNREACH)
                {
                    break;
                }
                else if (RPC_ERRNO(pco_iut) != RPC_EALREADY)
                {
                    TEST_VERDICT("Eventually nonblocking connect() "
                                 "failed with unexpected errno %r",
                                 RPC_ERRNO(pco_iut));
                }
            }

            if (i == MAX_ATTEMPTS)
            {
                TEST_VERDICT("connect() fails with EALREADY for too "
                             "long time");
            }
        }
    }

    RPC_CHECK_READABILITY(pco_tst1, tst1_s, FALSE);
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);

    TEST_END;
}
