/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Onload extensions
 *
 * $Id$
 */

/** @page extension-template_alloc_bnb Onload templates allocation with bad arguments
 *
 * @objective  Test Onload templates behavior allocation with bnbvalues
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TST
 * @param iovcnt        IOVs array length
 * @param total         Total amount of data to be passed by template
 * @param testcase      Case to test
 * 
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/extension/template_alloc_bnb"

#include "sockapi-test.h"
#include "template.h"
#include "onload.h"

/**
 * Test cases enumeration
 */
typedef enum {
    TC_NON_ACCELERATED_SOCKET = 0,  /**< Pass non-accelerated socket */
    TC_NON_SOCKET,                  /**< Use bad file descriptor (-1) */
    TC_NULL_HANDLE,                 /**< Use @c NULL as @p handle */
    TC_FLAGS,                       /**< Use bad flags (0xff) */
} test_case_t;

#define TEST_CASE \
    { "non_accelerated_socket", TC_NON_ACCELERATED_SOCKET }, \
    { "non_socket", TC_NON_SOCKET }, \
    { "null_handle", TC_NULL_HANDLE }, \
    { "flags", TC_FLAGS }

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    int                    testcase;

    rpc_onload_template_handle handle = 0;
    rpc_iovec *iov    = NULL;
    int        iut_s  = -1;
    int        tst_s  = -1;
    int        sock  = -1;
    char      *iovbuf  = NULL;
    char      *rcvbuf = NULL;
    int        iovcnt;
    int        total;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(iovcnt);
    TEST_GET_INT_PARAM(total);
    TEST_GET_ENUM_PARAM(testcase, TEST_CASE);

    sockts_kill_zombie_stacks(pco_iut);

    if (testcase == TC_NON_ACCELERATED_SOCKET)
        tapi_onload_acc(pco_iut, FALSE);

    TEST_STEP("Create TCP connection between IUT and tester.");
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    if (testcase == TC_NON_ACCELERATED_SOCKET &&
        tapi_onload_is_onload_fd(pco_iut, iut_s))
        TEST_VERDICT("IUT socket is accelerated.");

    TEST_STEP("Initialize a number @p iovcnt vectors with total payload length "
              "@p total.");
    iov = init_iovec(iovcnt, total, &iovbuf);

    if (testcase == TC_NON_SOCKET)
        sock = -1;
    else
        sock = iut_s;

    TEST_STEP("Try allocate Onload template with bad arguments.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_onload_msg_template_alloc(pco_iut, sock, iov, iovcnt,
                                       testcase == TC_NULL_HANDLE ? NULL :
                                                                    &handle,
                                       testcase == TC_FLAGS ? 0xFF : 0);

    TEST_STEP("Check allocation call results.");
    if (testcase != TC_FLAGS)
    {
        int exp;

        if (rc != -1)
            TEST_VERDICT("It was expected template allocation fail");

        switch (testcase)
        {
            case TC_NON_ACCELERATED_SOCKET:
            case TC_NON_SOCKET:
                exp = RPC_ESOCKTNOSUPPORT;
                break;
            
            default:
                exp = RPC_EINVAL;
        }
        if (RPC_ERRNO(pco_iut) != exp)
            TEST_VERDICT("It was expected template allocation fail with "
                         "errno %s, but errno is %s", errno_rpc2str(exp),
                         errno_rpc2str(RPC_ERRNO(pco_iut)));

        TEST_SUCCESS;
    }

    TEST_STEP("Send template if allocation succeeded.");
    rpc_onload_msg_template_update(pco_iut, iut_s, handle, NULL, 0,
                                   RPC_ONLOAD_TEMPLATE_FLAGS_SEND_NOW);

    rcvbuf = te_calloc_fill(1, total, 0);

    TEST_STEP("Read and verify the template data.");
    if (rpc_recv(pco_tst, tst_s, rcvbuf, total, 0) != total)
        TEST_VERDICT("Read wrong amount of data with template.");
    if (memcmp(rcvbuf, iovbuf, total) != 0)
        TEST_VERDICT("Send and received template data are not equal");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(rcvbuf);
    free(iovbuf);
    release_iovec(iov, iovcnt);

    if (testcase == TC_NON_ACCELERATED_SOCKET)
        tapi_onload_acc(pco_iut, TRUE);

    TEST_END;
}
