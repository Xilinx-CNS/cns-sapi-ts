/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Onload extensions
 */

/** @page extension-template_hide_ack  Dont reply ACKs to sent data and template
 *
 * @objective  Dont transmit ACKs after receiving a data and template
 *
 * @param pco_iut   PCO on IUT
 * @param pco_tst   PCO on TST
 * @param iovcnt    IOVs array length
 * @param total     Total amount of data to be passed by template
 * 
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/extension/template_hide_ack"

#include "sockapi-test.h"
#include "template.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    const struct sockaddr *alien_link_addr = NULL;

    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *tst_if = NULL;

    rpc_onload_template_handle handle = 0;
    rpc_iovec *iov     = NULL;
    int        iut_s   = -1;
    int        tst_s   = -1;
    char      *buf     = NULL;
    int        buf_len = 5000;
    char      *iovbuf  = NULL;
    char      *rcvbuf  = NULL;
    int        rcvbuf_len;
    int        iovcnt;
    int        total;
    size_t     tst_read;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_INT_PARAM(iovcnt);
    TEST_GET_INT_PARAM(total);

    sockts_kill_zombie_stacks(pco_iut);

    TEST_STEP("Create TCP connection between IUT and tester.");
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Transmit a data flow from IUT to increase congestion and send "
              "TCP windows, the last one must fit all sending data (with and without "
              "templates).");
    sockts_extend_cong_window_req(pco_iut, iut_s, pco_tst, tst_s,
                                  buf_len + total);

    TEST_STEP("Set option O_NONBLOCK for tester socket.");
    rpc_fcntl(pco_tst, tst_s, RPC_F_SETFL, RPC_O_NONBLOCK);

    TEST_STEP("Initialize a number @p iovcnt vectors with total payload length "
              "@p total.");
    iov = init_iovec(iovcnt, total, &iovbuf);

    TEST_STEP("Allocate Onload template.");
    rpc_onload_msg_template_alloc(pco_iut, iut_s, iov, iovcnt, &handle, 0);

    buf = te_make_buf_by_len(buf_len);

    TEST_STEP("Prevent ACKs receiving by IUT.");
    update_arp(pco_tst, tst_if, NULL, NULL, iut_addr, alien_link_addr, TRUE);
    CFG_WAIT_CHANGES;

    TEST_STEP("Send some data with usual send().");
    rpc_send(pco_iut, iut_s, buf, buf_len, 0);

    TEST_STEP("Send template.");
    rpc_onload_msg_template_update(pco_iut, iut_s, handle, NULL, 0,
                                   RPC_ONLOAD_TEMPLATE_FLAGS_SEND_NOW);

    TEST_STEP("Receive all data and verify it.");
    rcvbuf_len = buf_len + total * 2;
    rpc_read_fd(pco_tst, tst_s, TAPI_WAIT_NETWORK_DELAY, rcvbuf_len,
                (void **)&rcvbuf, &tst_read);
    rcvbuf_len = tst_read;
    if (rcvbuf_len != buf_len + total)
        TEST_VERDICT("Tester received wrong amount of data");

    if (memcmp(rcvbuf, buf, buf_len) != 0 ||
        memcmp(rcvbuf + buf_len, iovbuf, total) != 0)
        TEST_VERDICT("Received data differs from sent");

    TEST_STEP("Allow ACKs receiving by IUT.");
    update_arp(pco_tst, tst_if, pco_iut, iut_if, iut_addr, NULL, FALSE);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Check that nothing is left in recv buffer on IUT.");
    RPC_AWAIT_IUT_ERROR(pco_tst);
    if ((rc = rpc_recv(pco_tst, tst_s, rcvbuf, rcvbuf_len, 0)) > 0 ||
        RPC_ERRNO(pco_tst) != RPC_EAGAIN)
        TEST_VERDICT("It is expected that second recv fails with EAGAIN");

    TEST_SUCCESS;

cleanup:
    free(buf);
    free(iovbuf);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    release_iovec(iov, iovcnt);

    TEST_END;
}
