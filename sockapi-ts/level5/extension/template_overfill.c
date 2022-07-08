/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Onload extensions
 *
 * $Id$
 */

/** @page extension-template_overfill Onload templates with overfilled buffers
 *
 * @objective  Test Onload templates when buffers are overfilled
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TST
 * @param iovcnt        IOVs array length
 * @param total         Total amount of data to be passed by template
 * 
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/extension/template_overfill"

#include "sockapi-test.h"
#include "template.h"

#define READ_DATA_LEN 20000

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    rpc_onload_template_handle handle = 0;
    rpc_iovec *iov    = NULL;
    int        iut_s  = -1;
    int        tst_s  = -1;
    char      *iovbuf  = NULL;
    char      *rcvbuf = NULL;
    int        iovcnt;
    int        total;

    int         tst_rcvbuf_filled;
    uint64_t    overfilled = 0;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(iovcnt);
    TEST_GET_INT_PARAM(total);

    rcvbuf = te_calloc_fill(1, READ_DATA_LEN, 0);

    TEST_STEP("Create TCP connection between IUT and tester.");
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Overfill send buffer on IUT.");
    rpc_overfill_buffers(pco_iut, iut_s, &overfilled);

    /** Get the actual number of bytes in tester receive queue to calculate
     * data amount in IUT send queue. */
    rpc_ioctl(pco_tst, tst_s, RPC_FIONREAD, &tst_rcvbuf_filled);
    RING("Send queue keeps %d (%" TE_PRINTF_64 "u - %d) bytes of data",
         (int)overfilled - tst_rcvbuf_filled, overfilled,
         tst_rcvbuf_filled);

    TEST_STEP("Initialize a number @p iovcnt vectors with total payload length "
              "@p total.");
    iov = init_iovec(iovcnt, total, &iovbuf);

    TEST_STEP("Allocate Onload template.");
    rpc_onload_msg_template_alloc(pco_iut, iut_s, iov, iovcnt, &handle, 0);

    TEST_STEP("Try to send template, attempt should fail because buffers are "
              "overfilled.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_onload_msg_template_update(pco_iut, iut_s, handle, NULL, 0,
                                        RPC_ONLOAD_TEMPLATE_FLAGS_SEND_NOW |
                                        RPC_ONLOAD_TEMPLATE_FLAGS_DONTWAIT);
    if (rc != -1 || RPC_ERRNO(pco_iut) != RPC_EAGAIN)
        TEST_VERDICT("IUT template sending must fail with errno EAGAIN");

    TEST_STEP("Read some data on tester which amount is enough to pass template "
              "into send queue on IUT.");
    overfilled -= sockts_tcp_read_part_of_send_buf(pco_tst, tst_s,
                                                   overfilled);

    rpc_ioctl(pco_tst, tst_s, RPC_FIONREAD, &tst_rcvbuf_filled);
    RING("Send queue keeps %d (%" TE_PRINTF_64 "u - %d) bytes of data",
         (int)overfilled - tst_rcvbuf_filled, overfilled,
         tst_rcvbuf_filled);

    TEST_STEP("Allocate new Onload template and send it. The new template "
              "allocation is required because template is freed after send attempt "
              "even if sending is failed.");
    rpc_onload_msg_template_alloc(pco_iut, iut_s, iov, iovcnt, &handle, 0);
    rpc_onload_msg_template_update(pco_iut, iut_s, handle, NULL, 0,
                                   RPC_ONLOAD_TEMPLATE_FLAGS_SEND_NOW);

    TEST_STEP("Receive all data which was sent to overfill buffers.");
    while (overfilled > 0)
        overfilled -= rpc_recv(pco_tst, tst_s, rcvbuf,
                               overfilled > READ_DATA_LEN ? READ_DATA_LEN :
                                                            overfilled, 0);

    TEST_STEP("Read and verify the template data.");
    if (rpc_recv(pco_tst, tst_s, rcvbuf, READ_DATA_LEN, 0) != total)
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

    TEST_END;
}
