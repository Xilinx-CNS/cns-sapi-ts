/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Reuseport
 */

/** @page reuseport-reuseport_tcp_time_wait Test SO_REUSEPORT option with TCP socket in TIME_WAIT state
 *
 * @objective  Test port sharing with SO_REUSEPORT with TCP socket in
 *             TIME_WAIT state.
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst           PCO on TST
 * @param reuseport_second  Set SO_REUSEPORT for the second socket
 * @param close_connection  Close established TCP connection if @c TRUE
 *
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "reuseport/reuseport_tcp_time_wait"

#include "sockapi-test.h"
#include "reuseport.h"
#include "onload.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    te_bool reuseport_second;
    te_bool close_connection;

    int       ef_cluster_restart = 0;
    te_errno  err;

    reuseport_socket_ctx s1 = REUSEPORT_SOCKET_CTX_INIT;
    reuseport_socket_ctx s2 = REUSEPORT_SOCKET_CTX_INIT;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(reuseport_second);
    TEST_GET_BOOL_PARAM(close_connection);

    if (tapi_onload_run())
    {
        /* Error is not checked here as it is fine if there is no such
         * environment variable. */
        tapi_sh_env_get_int(pco_iut, "EF_CLUSTER_RESTART",
                            &ef_cluster_restart);
    }

    TEST_STEP("Create two tcp connections.");
    reuseport_init_socket_ctx(pco_iut, pco_tst, iut_addr, tst_addr, &s1);
    reuseport_init_socket_ctx(pco_iut, pco_tst, iut_addr, tst_addr, &s2);
    reuseport_pair_connection(RPC_SOCK_STREAM, &s1, &s2);

    TEST_STEP("Close IUT listener sockets.");
    RPC_CLOSE(pco_iut, s1.iut_s);
    RPC_CLOSE(pco_iut, s2.iut_s);

    TEST_STEP("Completely close one of TCP connections.");
    RPC_CLOSE(pco_tst, s2.tst_s);
    RPC_CLOSE(pco_iut, s2.iut_acc);

    TEST_STEP("If @p close_connection is @c TRUE - close IUT sockets to reach "
              "@c TIME_WAIT state.");
    if (close_connection)
    {
        RPC_CLOSE(pco_iut, s1.iut_acc);
        RPC_CLOSE(pco_tst, s1.tst_s);
    }

    TEST_STEP("Create new socket on IUT.");
    s1.iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                          RPC_SOCK_STREAM, RPC_PROTO_DEF);

    TEST_STEP("Set SO_REUSEPORT in dependence on @p reuseport_second");
    if (reuseport_second)
        rpc_setsockopt_int(pco_iut, s1.iut_s, RPC_SO_REUSEPORT, 1);

    TEST_STEP("Try to bind IUT socket to the same address. @b bind() should pass if "
              "@c SO_REUSEPORT is set for the new socket, otherwise it should fail "
              "with @c EADDRINUSE.");
    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_bind(pco_iut, s1.iut_s, iut_addr);
    if (reuseport_second)
    {
        if (rc < 0)
            TEST_VERDICT("bind() failed unexpectely with errno %r",
                         RPC_ERRNO(pco_iut));
    }
    else
    {
        if (rc >= 0)
            TEST_VERDICT("bind() unexpectedly succeeded");
        else if (RPC_ERRNO(pco_iut) != RPC_EADDRINUSE)
            TEST_VERDICT("bind() failed with unexpected errno %r",
                         RPC_ERRNO(pco_iut));

        TEST_SUCCESS;
    }

    TEST_STEP("If @b bind() succeeded make the IUT socket listener and continue the "
              "test using steps below.");
    rpc_listen(pco_iut, s1.iut_s, 1);
    rpc_fcntl(pco_iut, s1.iut_s, RPC_F_SETFL, RPC_O_NONBLOCK);

    TEST_STEP("Create the second IUT listener socket, binding it with "
              "@c SO_REUSEPORT. Expect @b bind() to fail with ENOSPC if the test is "
              "run on Onload, EF_CLUSTER_RESTART is not set and @p close_connection "
              "is @c TRUE (since one of the sockets accepted before is in TIME_WAIT "
              "state in this case).");

    s2.iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                          RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_setsockopt_int(pco_iut, s2.iut_s, RPC_SO_REUSEPORT, 1);

    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_bind(pco_iut, s2.iut_s, iut_addr);
    err = RPC_ERRNO(pco_iut);

    if (tapi_onload_run() && !ef_cluster_restart && close_connection)
    {
        if (rc >= 0)
            TEST_VERDICT("bind() unexpectedly succeeded for "
                         "the last socket");
        else if (err != RPC_ENOSPC)
            TEST_VERDICT("bind() for the last socket failed with "
                         "unexpected errno %r", err);

        TEST_SUCCESS;
    }
    else
    {
        if (rc < 0)
            TEST_VERDICT("bind() for the last socket failed unexpectedly "
                         "with errno %r", err);
    }

    rpc_listen(pco_iut, s2.iut_s, 1);
    rpc_fcntl(pco_iut, s2.iut_s, RPC_F_SETFL, RPC_O_NONBLOCK);

    TEST_STEP("Establish connection with tester using both IUT listeners.");
    try_connect_pair(&s1, &s2);

    TEST_SUCCESS;

cleanup:
    reuseport_close_pair(&s1, &s2);

    TEST_END;
}
