/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Onload extensions
 *
 * $Id$
 */

/** @page extension-template_send Send template after calling usual send()
 *
 * @objective  Transmit some data with usual send() before sending a
 *             template.
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TST
 * @param iovcnt        IOVs array length
 * @param total         Total amount of data to be passed by template
 * @param data_amount   Total amount of data to be passed before template
 * 
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/extension/template_send"

#include "sockapi-test.h"
#include "template.h"

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
    char      *buf    = NULL;
    char      *iovbuf  = NULL;
    char      *rcvbuf = NULL;
    int        rcvbuf_len;
    int        iovcnt;
    int        total;
    int        data_amount;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(iovcnt);
    TEST_GET_INT_PARAM(total);
    TEST_GET_INT_PARAM(data_amount);

    sockts_kill_zombie_stacks(pco_iut);

    TEST_STEP("Create TCP connection between IUT and tester.");
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Initialize a number @p iovcnt vectors with total payload length "
              "@p total.");
    iov = init_iovec(iovcnt, total, &iovbuf);

    TEST_STEP("Allocate Onload template.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    if (rpc_onload_msg_template_alloc(pco_iut, iut_s, iov, iovcnt, &handle,
                                      0) != 0)
        TEST_VERDICT("Template allocation failed with errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));

    buf = te_make_buf_by_len(data_amount);

    RING("Pass %d bytes with usual send and %d with templates API",
         data_amount, total);

    TEST_STEP("Send some data with usual send().");
    rpc_send(pco_iut, iut_s, buf, data_amount, 0);

    TEST_STEP("Send template.");
    rpc_onload_msg_template_update(pco_iut, iut_s, handle, NULL, 0,
                                   RPC_ONLOAD_TEMPLATE_FLAGS_SEND_NOW);

    TEST_STEP("Receive all data and verify it.");
    rcvbuf_len = data_amount + total * 2;
    rcvbuf = te_make_buf_by_len(rcvbuf_len);
    if (rpc_recv(pco_tst, tst_s, rcvbuf, rcvbuf_len, 0) !=
                 data_amount + total)
        TEST_VERDICT("Tester received wrong amount of data");

    if (memcmp(rcvbuf, buf, data_amount) != 0 ||
        memcmp(rcvbuf + data_amount, iovbuf, total) != 0)
        TEST_VERDICT("Received data differs from sent");

    TEST_SUCCESS;

cleanup:
    free(buf);
    free(iovbuf);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    release_iovec(iov, iovcnt);

    TEST_END;
}
