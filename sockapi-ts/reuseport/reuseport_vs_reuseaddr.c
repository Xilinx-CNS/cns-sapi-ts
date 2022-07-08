/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Reuseport
 */

/** @page reuseport-reuseport_vs_reuseaddr SO_REUSEADDR does not grant privileges to use the same address
 *
 * @objective Bind two sockets using various combinations of SO_REUSEADDR
 *            and SO_REUSEPORT options, check that SO_REUSEADDR does not
 *            grant privileges to use the same address even if SO_REUSEPORT
 *            is set for one of sockets.
 *
 * @type use case
 *
 * @param sock_type         Socket type (@c SOCK_STREAM or @c SOCK_DGRAM).
 * @param reuseport_first   Whether to set SO_REUSEPORT for the first
 *                          or for the second socket.
 * @param reuseaddr_first   If @c TRUE, set SO_REUSEADDR for the first
 *                          socket.
 * @param reuseaddr_second  If @c TRUE, set SO_REUSEADDR for the second
 *                          socket.
 * @param wild_first        If @c TRUE, bind the first socket to
 *                          INADDR_ANY.
 * @param wild_second       If @c TRUE, bind the second socket to
 *                          INADDR_ANY.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "reuseport/reuseport_vs_reuseaddr"

#include "sockapi-test.h"
#include "reuseport.h"

/**
 * Call RPC, check results.
 *
 * @param func_       RPC to call.
 * @param rpcs_       RPC server handle.
 * @param name_       Name of RPC to be used in verdicts.
 * @param args_       Call arguments.
 */
#define CHECK_RPC(func_, rpcs_, name_, args_...) \
    do {                                                    \
        RPC_AWAIT_ERROR(rpcs_);                             \
        rc = func_(rpcs_, args_);                           \
        if (rc < 0 && !exp_failure)                         \
            TEST_VERDICT(name_ " failed with errno %r",     \
                          RPC_ERRNO(rpcs_));                \
                                                            \
        exp_failure = FALSE;                                \
    } while (0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    struct sockaddr_storage iut_wild_addr;

    int iut_s1 = -1;
    int iut_s2 = -1;

    te_bool exp_failure = FALSE;

    rpc_socket_type   sock_type;
    te_bool           reuseport_first;
    te_bool           reuseaddr_first;
    te_bool           reuseaddr_second;
    te_bool           wild_first;
    te_bool           wild_second;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(reuseport_first);
    TEST_GET_BOOL_PARAM(reuseaddr_first);
    TEST_GET_BOOL_PARAM(reuseaddr_second);
    TEST_GET_BOOL_PARAM(wild_first);
    TEST_GET_BOOL_PARAM(wild_second);

    TEST_STEP("Create two sockets on IUT.");
    iut_s1 = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                        sock_type, RPC_PROTO_DEF);
    iut_s2 = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                        sock_type, RPC_PROTO_DEF);

    TEST_STEP("Enable SO_REUSEPORT for the first or the second socket "
              "according to @p reuseport_first.");
    CHECK_RPC(rpc_setsockopt_int, pco_iut, "setsockopt(SO_REUSEPORT)",
              (reuseport_first ? iut_s1 : iut_s2),
              RPC_SO_REUSEPORT, 1);

    TEST_STEP("Enable SO_REUSEADDR for the first socket "
              "if @p reuseaddr_first is @c TRUE.");
    if (reuseaddr_first)
        CHECK_RPC(rpc_setsockopt_int, pco_iut,
                  "setsockopt(SO_REUSEADDR) for the first socket",
                  iut_s1, RPC_SO_REUSEADDR, 1);

    TEST_STEP("Enable SO_REUSEADDR for the second socket "
              "if @p reuseaddr_second is @c TRUE.");
    if (reuseaddr_second)
        CHECK_RPC(rpc_setsockopt_int, pco_iut,
                  "setsockopt(SO_REUSEADDR) for the second socket",
                  iut_s2, RPC_SO_REUSEADDR, 1);

    tapi_sockaddr_clone_exact(iut_addr, &iut_wild_addr);
    te_sockaddr_set_wildcard(SA(&iut_wild_addr));

    TEST_STEP("Bind the first socket using a specific address or INADDR_ANY, "
              "as specified with @p wild_first.");
    CHECK_RPC(rpc_bind, pco_iut,
              "bind() for the first socket",
              iut_s1, (wild_first ? SA(&iut_wild_addr) : iut_addr));

    TEST_STEP("Bind the second socket using a specific address or INADDR_ANY, "
              "as specified with @p wild_second. Unless both @p reuseaddr_first "
              "and @p reuseaddr_second are @c TRUE, the call should fail.");
    exp_failure = TRUE;
    CHECK_RPC(rpc_bind, pco_iut,
              "bind() for the second socket",
              iut_s2, (wild_second ? SA(&iut_wild_addr) : iut_addr));
    if (rc >= 0)
    {
        if (!(reuseaddr_first && reuseaddr_second))
            ERROR_VERDICT("bind() for the second socket "
                          "unexpectedly succeeded");
    }
    else
    {
        if (reuseaddr_first && reuseaddr_second)
            ERROR_VERDICT("bind() for the second socket failed "
                          "unexpectedly with errno %r", RPC_ERRNO(pco_iut));
        else if (RPC_ERRNO(pco_iut) != RPC_EADDRINUSE)
            ERROR_VERDICT("bind() for the second socket failed "
                          "with unexpected errno %r", RPC_ERRNO(pco_iut));

        TEST_SUCCESS;
    }

    TEST_STEP("If bind() calls were successful:");
    if (sock_type == RPC_SOCK_STREAM)
    {
        TEST_SUBSTEP("If @p sock_type is @c SOCK_STREAM, call listen() for both "
                     "sockets, check that it fails for the second one.");

        CHECK_RPC(rpc_listen, pco_iut,
                  "listen() for the first socket",
                  iut_s1, SOCKTS_BACKLOG_DEF);

        exp_failure = TRUE;
        CHECK_RPC(rpc_listen, pco_iut,
                  "listen() for the second socket",
                  iut_s2, SOCKTS_BACKLOG_DEF);
        if (rc >= 0)
        {
            TEST_VERDICT("listen() for the second socket succeeded");
        }
        else
        {
            if (RPC_ERRNO(pco_iut) != RPC_EADDRINUSE)
                ERROR_VERDICT("listen() for the second socket failed "
                              "with unexpected errno %r",
                              RPC_ERRNO(pco_iut));

            TEST_SUCCESS;
        }
    }
    else
    {
        TEST_SUBSTEP("If @p sock_type is @c SOCK_DGRAM, call connect() for both "
                     "sockets.");

        CHECK_RPC(rpc_connect, pco_iut,
                  "connect() for the first socket",
                  iut_s1, tst_addr);

        CHECK_RPC(rpc_connect, pco_iut,
                  "connect() for the second socket",
                  iut_s2, tst_addr);
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s1);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s2);

    TEST_END;
}
