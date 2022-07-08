/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Library _init() function tests
 *
 * $Id$
 */

/** @page libinit-socket_recv_tests _init() function tests using sockets, test lib on receiving side.
 *
 * @objective Check the behavior of several functions used
 *            in terms of user-defined _init() library function.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on Tester
 * @param lazy          Whether use @b dlopen() with RTLD_LAZY or RTLD_NOW
 * @param data_size     Size of data to be transmitted
 * @param sequence      Sequence name. For more information see
 *                      @ref libinit-sequences_and_iterations
 * @param iteration     Iteration name. For more information see
 *                      @ref libinit-sequences_and_iterations
 *
 * @par Test sequence:
 *
 * @author Nikita Rastegaev <Nikita.Rastegaev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "libinit/socket_recv_tests"

#include "sockapi-test.h"

#include "init_lib.h"

#define TST_TIMING_DELAY    2

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
    te_bool                 sock_post;
    int                     tst_s = -1;
    char                    buf[INET_ADDRSTRLEN];
    char                   *rbuf;
    int                     data_size;
    int                     i = 0;

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

    TEST_STEP("Determine when the socket will be created (pre- or post-init) from "
              "@b iteration parameter and set @p sock_post variable accordingly.");
    sock_post = (strstr(iteration, "SOCK_POST") != NULL);

    TEST_STEP("Create socket on Tester of corresponding socket type taken "
              "from @b iteration parameter.");
    sock_type = (strstr(iteration, "STREAM") == NULL) ? RPC_SOCK_DGRAM :
                                                       RPC_SOCK_STREAM;
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       sock_type, RPC_PROTO_DEF);

    TEST_STEP("Configure @b pco_iut with address/port and data to be received "
              "by test lib.");
    rpc_setenv(pco_iut, "LIBINIT_ADDR",
               inet_ntop(AF_INET, &(SIN(iut_addr)->sin_addr),
                         buf, INET_ADDRSTRLEN), 1);
    sprintf(buf, "%d", ntohs(SIN(iut_addr)->sin_port));
    rpc_setenv(pco_iut, "LIBINIT_PORT", buf, 1);
    rbuf = (char *)te_make_buf_by_len(data_size);
    for (i = 0; i < data_size; i++)
        if (rbuf[i] == '\0' || rbuf[i] == '\n' || rbuf[i] == '=')
            rbuf[i] = '0';
    rbuf[data_size - 1] = '\0';
    rpc_setenv(pco_iut, "LIBINIT_TEST_STR", rbuf, 1);

    TEST_STEP("Exec @b pco_iut for configuration changes to take effect. Note, "
              "that as @c LD_PRELOAD was updated simple restart via Configurator "
              "is not enough");
    CHECK_RC(rcf_rpc_server_exec(pco_iut));
    CFG_WAIT_CHANGES;

#define AUX_PROC \
    do {                                                            \
        pco_iut->op = RCF_RPC_CALL_WAIT;                            \
        handle = libinit_dlopen(pco_iut, lazy);                     \
        pco_iut->op = RCF_RPC_CALL;                                 \
        rc = rpc_dlsym_call(pco_iut, handle, "lt_do");              \
    } while(0)

    TEST_STEP("If sock_post is @c TRUE call @b lt_do() function from "
              "libinit_test.so library on @b pco_iut.");
    if (sock_post)
        AUX_PROC;

    TEST_STEP("Connect socket on @b pco_tst to the socket which should "
              "be created in test library, send data.");
    i = 0;
    do
    {
        SLEEP(TST_TIMING_DELAY);
        RPC_AWAIT_IUT_ERROR(pco_tst);
        rc = rpc_connect(pco_tst, tst_s, iut_addr);
    } while ((rc == -1) && ((++i) < 10));

    if (rc < 0)
        TEST_FAIL("Connection failed, %s",
                  errno_rpc2str(RPC_ERRNO(pco_tst)));
    rpc_send(pco_tst, tst_s, rbuf, data_size, 0);
    SLEEP(TST_TIMING_DELAY);

    TEST_STEP("If sock_post is @c FALSE call @b lt_do() function from "
              "libinit_test.so on @b pco_iut.");
    if (!sock_post)
        AUX_PROC;

#undef AUX_PROC

    TEST_STEP("Wait for @b lt_do() return code, issue appropriate verdicts.");
    pco_iut->op = RCF_RPC_WAIT;
    rc = rpc_dlsym_call(pco_iut, handle, "lt_do");

    TEST_STEP("For libinit scenarios that depend on the status of a child, "
              "take @b lt_do() rc as a child's pid and wait for it.");
    LIBINIT_WAIT_CHILD(pco_iut, sequence, iteration, rc);

    if(rc != 0)
        TEST_FAIL("lt_do() call returned %d", rc);

    TEST_SUCCESS;

cleanup:
    rpc_dlclose(pco_iut, handle);

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
