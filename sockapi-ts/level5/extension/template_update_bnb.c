/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Onload extensions
 *
 * $Id$
 */

/** @page extension-template_update_bnb Onload templates update with bad arguments
 *
 * @objective  Test Onload templates behavior update with bnbvalues
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

#define TE_TEST_NAME  "level5/extension/template_update_bnb"

#include "sockapi-test.h"
#include "template.h"

typedef enum {
    TC_NULL_HANDLE = 0,
    TC_NULL_UPDATES,
    TC_ULEN_ZERO,
    TC_BIG_OTMU_OFFSET,
    TC_OTMU_LEN_ZERO,
    TC_OTMU_FLAGS,
    TC_OTMU_BASE_NULL,
    TC_BAD_SOCKET,
    TC_FLAGS,
} test_case_t;

#define TEST_CASE \
    { "null_handle", TC_NULL_HANDLE }, \
    { "null_updates",  TC_NULL_UPDATES }, \
    { "ulen_zero", TC_ULEN_ZERO }, \
    { "big_otmu_offset", TC_BIG_OTMU_OFFSET }, \
    { "otmu_len_zero", TC_OTMU_LEN_ZERO }, \
    { "otmu_flags", TC_OTMU_FLAGS }, \
    { "otmu_base_null", TC_OTMU_BASE_NULL }, \
    { "bad_socket", TC_BAD_SOCKET }, \
    { "flags", TC_FLAGS }

static void
clean_updates(rpc_onload_template_msg_update_iovec *updates,
              int updates_len)
{
    int i;

    if (updates == NULL)
        return;

    for (i = 0; i < updates_len; i++)
        free(updates[i].otmu_base);
    free(updates);
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    int                    testcase;

    rpc_onload_template_msg_update_iovec *updates = NULL;
    int                                   updates_len;
    int                                   updates_len_r = 1;
    rpc_onload_template_handle handle = 0;
    rpc_iovec *iov    = NULL;
    int        iut_s  = -1;
    int        tst_s  = -1;
    char      *iovbuf  = NULL;
    char      *rcvbuf = NULL;
    int        iovcnt;
    int        total;
    int        exp;
    te_bool    second_update;
    int        idx = 0;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(iovcnt);
    TEST_GET_INT_PARAM(total);
    TEST_GET_ENUM_PARAM(testcase, TEST_CASE);
    TEST_GET_BOOL_PARAM(second_update);

    sockts_kill_zombie_stacks(pco_iut);

    TEST_STEP("Create TCP connection between IUT and tester.");
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Initialize a number @p iovcnt vectors with total payload length "
              "@p total.");
    iov = init_iovec(iovcnt, total, &iovbuf);

    TEST_STEP("Allocate Onload template.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rpc_onload_msg_template_alloc(pco_iut, iut_s, iov, iovcnt, &handle, 0);

    if (second_update)
        updates_len_r = 2;

    updates_len = updates_len_r;
    updates = te_calloc_fill(updates_len_r, sizeof(*updates), 0); 
    updates->otmu_offset = rand_range(0, total - 1);
    updates->otmu_len = updates->otmu_rlen =rand_range(1, total- updates->otmu_offset);
    updates->otmu_base = te_make_buf_by_len(updates->otmu_len);
    if (second_update)
    {
        idx = 1;
        memcpy(updates + idx, updates, sizeof(*updates));
        updates[idx].otmu_base = te_make_buf_by_len(updates->otmu_len);
        memcpy(iovbuf + updates->otmu_offset, updates->otmu_base,
               updates->otmu_len);
    }

    switch(testcase)
    {
        case TC_BIG_OTMU_OFFSET:
            updates[idx].otmu_offset = total + 10;
            break;

        case TC_OTMU_LEN_ZERO:
            updates[idx].otmu_len = 0;
            break;

        case TC_OTMU_FLAGS:
            updates[idx].otmu_flags = 0xff;
            memcpy(iovbuf + updates[idx].otmu_offset,
                   updates[idx].otmu_base, updates[idx].otmu_len);
            break;

        case TC_OTMU_BASE_NULL:
            updates[idx].otmu_rlen = 0;
            updates[idx].otmu_base = NULL;
            break;

        default:
            ;
    }

    TEST_STEP("Send template if allocation succeeded.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_onload_msg_template_update_gen(pco_iut,
        testcase == TC_BAD_SOCKET ? -1 : iut_s, 
        testcase == TC_NULL_HANDLE ? 0: handle,
        testcase == TC_NULL_UPDATES ? NULL : updates,
        testcase == TC_ULEN_ZERO ? 0 : updates_len,
        testcase == TC_NULL_UPDATES ? 0 : updates_len,
        testcase == TC_FLAGS ? 0xFF : 0);

    if (testcase != TC_ULEN_ZERO && testcase != TC_OTMU_FLAGS)
    {
        if (rc != -1)
            TEST_VERDICT("Template update had to fail.");

        switch (testcase)
        {
            case TC_BAD_SOCKET:
                exp = RPC_ESOCKTNOSUPPORT;
                break;

            default:
                exp = RPC_EINVAL;
        }

        if (RPC_ERRNO(pco_iut) != exp)
            TEST_VERDICT("It was expected template allocation fail with "
                         "errno %s, but errno is %s", errno_rpc2str(exp),
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    TEST_STEP("Send template.");
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
    clean_updates(updates, updates_len_r);

    TEST_END;
}
