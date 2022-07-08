/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * TCP
 * 
 * $Id$
 */

/** @page tcp-closing_time_wait Closing TCP socket in TIME_WAIT state
 *
 * @objective  Close TCP socket while it is in TIME_WAIT state.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * @param cache_socket  Create cached socket to be reused
 * 
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/closing_time_wait"

#include "sockapi-test.h"
#include "tcp_test_macros.h"
#include "onload.h"

/* Maxmim waiting time in seconds */
#define TIME_LIMIT 125

int
main(int argc, char *argv[])
{
    const struct if_nameindex *tst_if = NULL;
    const struct if_nameindex *iut_if = NULL;
    const struct sockaddr     *iut_addr;
    const struct sockaddr     *tst_addr;
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    opening_listener opening;
    te_bool cache_socket;
    te_bool onload;

    int iut_s = -1;
    int iut_l = -1;
    int iut_aux_s = -1;
    int tst_s = -1;
    int i = 0;
    int msl = 0;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(tst_if);
    TEST_GET_IF(iut_if);
    TEST_GET_BOOL_PARAM(cache_socket);
    TEST_GET_ENUM_PARAM(opening, OPENING_LISTENER);

    onload = tapi_onload_lib_exists(pco_iut->ta);

    CHECK_RC(tapi_sh_env_get_int(pco_iut, "EF_TCP_TCONST_MSL", &msl));

    TEST_STEP("Create connection between IUT and tester.");
    TEST_STEP("Open TCP socket.");
    if (opening == OL_ACTIVE)
    {
        sockts_create_cached_socket(pco_iut, pco_tst, iut_addr, tst_addr, -1,
                                    TRUE, cache_socket);

        tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
        iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);

        rpc_bind(pco_iut, iut_s, iut_addr);
        rpc_bind(pco_tst, tst_s, tst_addr);
        rpc_listen(pco_tst, tst_s, -1);

        rpc_connect(pco_iut, iut_s, tst_addr);

        iut_l = rpc_accept(pco_tst, tst_s, NULL, NULL);
        RPC_CLOSE(pco_tst, tst_s);
        tst_s = iut_l;
        iut_l = -1;
    }
    else
    {
        iut_l = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);

        rpc_bind(pco_iut, iut_l, iut_addr);
        rpc_listen(pco_iut, iut_l, -1);

        sockts_create_cached_socket(pco_iut, pco_tst, iut_addr, tst_addr, iut_l,
                                    FALSE, cache_socket);

        tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_connect(pco_tst, tst_s, iut_addr);

        iut_s = rpc_accept(pco_iut, iut_l, NULL, NULL);
        CLOSE_LISTENER(OL_PASSIVE_OPEN, iut_l);
    }

    TAPI_WAIT_NETWORK;
    TEST_STEP("Shutdown IUT socket.");
    rpc_shutdown(pco_iut, iut_s, RPC_SHUT_RDWR);
    TAPI_WAIT_NETWORK;

    CLOSE_LISTENER(OL_PASSIVE_CLOSE, iut_l);

    TEST_STEP("Close tester socket.");
    RPC_CLOSE(pco_tst, tst_s);

    TEST_STEP("Create aux socket to check if the bound IUT address is busy.");
    iut_aux_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    TEST_STEP("IUT address must be busy while the socket in the TIME_WAIT state.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_bind(pco_iut, iut_aux_s, iut_addr);
    if (rc < 0 && RPC_ERRNO(pco_iut) != RPC_EADDRINUSE)
        TEST_FAIL("Bind failed with unexpected errno %s",
                  strerror(RPC_ERRNO(pco_iut)));
    else if (rc != -1)
        TEST_FAIL("bind() must fail with EADDRINUSE");

    TEST_STEP("Close the IUT socket.");
    RPC_CLOSE(pco_iut, iut_s);

    TEST_STEP("Try to bind the new socket to the same address:port during "
              "@c TIME_LIMIT seconds.");
    do {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_bind(pco_iut, iut_aux_s, iut_addr);
        if (rc < 0)
        {
            if (RPC_ERRNO(pco_iut) != RPC_EADDRINUSE)
                TEST_FAIL("Bind failed with unexpected errno %s",
                          strerror(RPC_ERRNO(pco_iut)));
            SLEEP(1);
        }
        else
            break;

        i++;
        TEST_STEP("The first socket must be finally closed for Onload when timeout "
                  "value of double @c EF_TCP_TCONST_MSL seconds is expired.");
        if (onload && i > (msl * 2 + 2))
            TEST_VERDICT("Socket stay busy too long time");
    } while (i < TIME_LIMIT);

    if (i == TIME_LIMIT || (onload && i > (msl * 2 + 2)))
        TEST_VERDICT("The socket was not closed by timeout");
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_l);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_aux_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
