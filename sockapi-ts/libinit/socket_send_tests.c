/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Library _init() function tests
 *
 * $Id$
 */

/** @page libinit-socket_send_tests _init() function tests using sockets, test lib on sending side.
 *
 * @objective Check the behavior of several functions used
 *            in terms of user-defined _init() library function.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on Tester
 * @param lazy          Whether use @b dlopen() with RTLD_LAZY or RTLD_NOW.
 * @param data_size     Size of data to be transmitted.
 * @param sequence      Sequence name. For more information see
 *                      @ref libinit-sequences_and_iterations
 * @param iteration     Iteration name. For more information see
 *                      @ref libinit-sequences_and_iterations
 *
 * @par Test sequence:
 *
 * @author Nikita Rastegaev <Nikita.Rastegaev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "libinit/socket_send_tests"

#include "sockapi-test.h"

#include "init_lib.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    const char             *sequence;
    const char             *iteration;
    char                   *sequence_str;
    rpc_dlhandle            handle;
    te_bool                 lazy;
    int                     sock_type;
    int                     acc_s = -1;
    int                     tst_s = -1;
    char                    buf[INET_ADDRSTRLEN];
    char                   *rbuf;
    char                   *tbuf;
    int                     data_size;
    int                     n;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_BOOL_PARAM(lazy);
    TEST_GET_STRING_PARAM(sequence);
    TEST_GET_STRING_PARAM(iteration);

    /* Scenario */

    TEST_STEP("Set @c LD_PRELOAD environment variable on @b pco_iut");
    TEST_STEP("Configure test lib with @p sequence parameter to select "
              "current test scenario");
    sequence_str = (char *)malloc(strlen(sequence)+strlen(iteration)+2);
    sprintf(sequence_str, "%s %s", sequence, iteration);
    libinit_set_agent_env(pco_iut, sequence_str);
    free(sequence_str);

    TEST_STEP("Create socket on Tester of corresponding socket type taken "
              "from @b iteration parameter.");
    sock_type = (strstr(iteration, "STREAM") == NULL) ? RPC_SOCK_DGRAM :
                                                       RPC_SOCK_STREAM;

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       sock_type, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);
    if (sock_type == RPC_SOCK_STREAM)
    {
        rpc_listen(pco_tst, tst_s, 5);
        pco_tst->op = RCF_RPC_CALL;
        acc_s = rpc_accept(pco_tst, tst_s, NULL, NULL);
    }

    TEST_STEP("Configure @b pco_iut with address/port and data to be sent "
              "by test lib.");
    rpc_setenv(pco_iut, "LIBINIT_ADDR",
               inet_ntop(AF_INET, &(SIN(tst_addr)->sin_addr),
                         buf, INET_ADDRSTRLEN), 1);
    sprintf(buf, "%d", ntohs(SIN(tst_addr)->sin_port));
    rpc_setenv(pco_iut, "LIBINIT_PORT", buf, 1);
    rbuf = (char *)te_make_buf_by_len(data_size);
    tbuf = (char *)te_make_buf_by_len(data_size);
    rbuf[data_size - 1] = '\0';
    rpc_setenv(pco_iut, "LIBINIT_TEST_STR", rbuf, 1);

    TEST_STEP("Exec @b pco_iut for configuration changes to take effect. Note, "
              "that as @c LD_PRELOAD was updated simple restart via Configurator "
              "is not enough");
    CHECK_RC(rcf_rpc_server_exec(pco_iut));

    TEST_STEP("Call @b lt_do() function from libinit_test.so library on "
              "@b pco_iut. Check return code.");
    handle = libinit_dlopen(pco_iut, lazy);
    rc = rpc_dlsym_call(pco_iut, handle, "lt_do");

    TEST_STEP("For libinit scenarios that depend on the status of a child, "
              "take @b lt_do() rc as a child's pid and wait for it.");
     LIBINIT_WAIT_CHILD(pco_iut, sequence, iteration, rc);

    if(rc != 0)
        TEST_FAIL("lt_do() call returned %d", rc);

    TEST_STEP("If testing SOCK_STREAM socket, accept connection from test lib.");
    if (sock_type == RPC_SOCK_STREAM)
    {
        pco_tst->op = RCF_RPC_WAIT;
        acc_s = rpc_accept(pco_tst, tst_s, NULL, NULL);
        RPC_CLOSE(pco_tst, tst_s);
    }
    else
        acc_s = tst_s;

    TAPI_WAIT_NETWORK;

    TEST_STEP("Receive data sent from test lib, verify it, issue appropriate "
              "verdicts.");
    n = rpc_recv(pco_tst, acc_s, tbuf, data_size, 0);
    if (n <= 0)
        TEST_FAIL("Data transmission failed");
    tbuf[data_size - 1] = '\0';
    if (strcmp(rbuf, tbuf) != 0)
        TEST_FAIL("Some data was corrupted");

    TEST_SUCCESS;

cleanup:
    rpc_dlclose(pco_iut, handle);

    CLEANUP_RPC_CLOSE(pco_tst, acc_s);

    TEST_END;
}
