/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Onload extensions
 *
 * $Id$
 */

/** @page extension-template_abort_bnb Onload templates abort with bad arguments
 *
 * @objective  Test Onload templates abort function behavior with bnbvalues
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

#define TE_TEST_NAME  "level5/extension/template_abort_bnb"

#include "sockapi-test.h"
#include "template.h"
#include "onload.h"

/**
 * Test cases enumeration
 */
typedef enum {
    TC_NULL_HANDLE = 0,  /**< Use @c NULL as @p handle */
    TC_BAD_SOCKET,       /**< Pass bad file descriptor */
    TC_TWICE,            /**< Call abort twice */
    TC_AFTER_SENDING,    /**< Call abort after template sending */
} test_case_t;

#define TEST_CASE \
    { "null_handle", TC_NULL_HANDLE }, \
    { "bad_socket", TC_BAD_SOCKET }, \
    { "twice", TC_TWICE }, \
    { "after_sending", TC_AFTER_SENDING }

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
    char      *iovbuf  = NULL;
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

    TEST_STEP("Create TCP connection between IUT and tester.");
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Initialize a number @p iovcnt vectors with total payload length "
              "@p total.");
    iov = init_iovec(iovcnt, total, &iovbuf);

    TEST_STEP("Allocate Onload template.");
    rpc_onload_msg_template_alloc(pco_iut, iut_s, iov, iovcnt, &handle, 0);

    TEST_STEP("Call template abort with bad arguments.");
    if (testcase != TC_AFTER_SENDING)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_onload_msg_template_abort(pco_iut,
            testcase == TC_BAD_SOCKET ? -1 : iut_s,
            testcase == TC_NULL_HANDLE ? 0 : handle);
        if (testcase == TC_BAD_SOCKET)
        {
            if (rc != -1 || RPC_ERRNO(pco_iut) != RPC_ESOCKTNOSUPPORT)
                TEST_VERDICT("Abort fail with errno ESOCKTNOSUPPORT was "
                             "expected");
        }

        if (testcase == TC_TWICE)
        {
            RPC_AWAIT_IUT_ERROR(pco_iut);
            rpc_onload_msg_template_abort(pco_iut, iut_s, handle);
        }

        TEST_SUCCESS;
    }

    TEST_STEP("Send template if allocation succeeded.");
    rpc_onload_msg_template_update(pco_iut, iut_s, handle, NULL, 0,
                                   RPC_ONLOAD_TEMPLATE_FLAGS_SEND_NOW);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rpc_onload_msg_template_abort(pco_iut, iut_s, handle);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(iovbuf);
    release_iovec(iov, iovcnt);

    TEST_END;
}
