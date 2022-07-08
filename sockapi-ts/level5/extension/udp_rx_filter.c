/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page extension-udp_rx_filter Simple usage of UDP-RX filter
 *
 * @objective Check that UDP-RX filter with callback that checks first
 *            n bytes works correctly for different amount of data.
 *
 * @type use case
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TST
 *
 * @par Scenario:
 *
 * -# Create @c SOCK_DGRAM socket @p iut_s on @p pco_iut and bind it to
 *    @p iut_addr.
 * -# Create @c SOCK_DGRAM socket @p tst_s on @p pco_tst, bind it to
 *    @p tst_addr and connect to @p iut_addr.
 * -# Set packet filtering according to @p pattern_len parameter.
 * -# If @p block_call is @c TRUE call @p recv_f function or @p iomux_f
 *    function according to @p use_iomux parameter.
 * -# Send some data from @p tst_s to @p iut_s accoreding to @p tx_msg
 *    parameter.
 * -# Sleep awile.
 * -# If @ block_call is @c FALSE call @p recv_f function or @p iomux_f
 *    function according to @p use_iomux parameter.
 * -# If @c use_iomux is @c TRUE check that @p iomux_f reports read event
 *    when @p tx_msg is @c match or doens't report read event is other
 *    cases.
 * -# If @c use_iomux is @c FALSE check that @p recv_f return correct
 *    number of bytes when @p tx_msg is @c match or hangs in other cases.
 * -# If @c use_iomux is @c FALSE and @p tx_msg isn't @p match send data to
 *    unblock @p recv_f function and check that it returns correct number
 *    of bytes.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/extension/udp_rx_filter"

#include "sockapi-test.h"
#include "iomux.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut;
    rcf_rpc_server        *pco_tst;

    int                    iut_s = -1;
    int                    tst_s = -1;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;

    size_t                 pattern_len = -1;
    void                  *pattern = NULL;
    void                  *tx_buf = NULL;
    void                  *rx_buf = NULL;
    size_t                 msg_len = 0;
    const char            *tx_msg;
    te_bool                use_iomux;

    iomux_call_type        iomux_f = IC_UNKNOWN;
    rpc_recv_f             recv_f;

    te_bool                block_call = FALSE;

    tarpc_timeval          timeout = { 0, 0 };

    te_bool                op_done = FALSE;

    iomux_evt_fd           event;
    char                   aux_buf[255];

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(pattern_len);
    TEST_GET_BOOL_PARAM(use_iomux);
    TEST_GET_BOOL_PARAM(block_call);
    if (use_iomux)
        TEST_GET_IOMUX_FUNC(iomux_f);
    else
        TEST_GET_RECV_FUNC(recv_f);
    TEST_GET_STRING_PARAM(tx_msg);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_bind(pco_tst, tst_s, tst_addr);
    rpc_connect(pco_tst, tst_s, iut_addr);
    
    rpc_write(pco_tst, tst_s, aux_buf, sizeof(aux_buf));
    rpc_read(pco_iut, iut_s, aux_buf, sizeof(aux_buf));

    pattern = te_make_buf_by_len(pattern_len);
    te_fill_buf(pattern, pattern_len);
    rpc_simple_set_recv_filter(pco_iut, iut_s, pattern, pattern_len, 0);
    if (strcmp(tx_msg, "match") == 0 || strcmp(tx_msg, "nonmatch") == 0)
    {
        msg_len = pattern_len + rand_range(1, pattern_len);
        tx_buf = te_make_buf_by_len(msg_len);
        te_fill_buf(tx_buf, msg_len);
        if (strcmp(tx_msg, "match") == 0)
            memcpy(tx_buf, pattern, pattern_len);
    }
    else if (strcmp(tx_msg, "short") == 0)
    {
        tx_buf = te_make_buf(1, pattern_len - 1, &msg_len);
        te_fill_buf(tx_buf, msg_len);
    }
    else if (strcmp(tx_msg, "zero") != 0)
        TEST_FAIL("Incorrect value of 'tx_msg' parameter");

    rx_buf = te_make_buf_by_len((msg_len < pattern_len) ? pattern_len :
                                                          msg_len);
    
    event.fd = iut_s;
    event.events = EVT_RD;
    if (block_call)
    {
        if (use_iomux)
        {
            timeout.tv_sec = 5;
            pco_iut->op = RCF_RPC_CALL;
            iomux_call(iomux_f, pco_iut, &event, 1, &timeout);
        }
        else
        { 
            pco_iut->op = RCF_RPC_CALL;
            recv_f(pco_iut, iut_s, rx_buf,
                   (msg_len < pattern_len) ? pattern_len : msg_len, 0);
        }
    }

    TAPI_WAIT_NETWORK;
    if (msg_len == 0)
        rpc_write(pco_tst, tst_s, "", 0);
    else
    {
        if (rpc_write(pco_tst, tst_s, tx_buf, msg_len) != (int)msg_len)
            TEST_FAIL("Only part of data was sent");
    }
    TAPI_WAIT_NETWORK;

    if (use_iomux)
    {
        rc = iomux_call(iomux_f, pco_iut, &event, 1, &timeout);
        if ((rc != 1 && strcmp(tx_msg, "match") == 0) ||
            (rc != 0 && strcmp(tx_msg, "match") != 0))
        {
            if (rc < 0)
                TEST_VERDICT("Sent message is '%s' but iomux_call() "
                             "returned %d with errno %s", tx_msg, rc,
                             errno_rpc2str(RPC_ERRNO(pco_iut)));
            else
                TEST_VERDICT("Sent message is '%s' but iomux_call() "
                             "returned %d", tx_msg, rc);
        }
    }
    else
    { 
        if (!block_call)
        {
            pco_iut->op = RCF_RPC_CALL;
            recv_f(pco_iut, iut_s, rx_buf,
                   (msg_len < pattern_len) ? pattern_len : msg_len, 0);
            TAPI_WAIT_NETWORK;
        }
        CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &op_done));
        if ((!op_done && strcmp(tx_msg, "match") == 0) ||
            (op_done && strcmp(tx_msg, "match") != 0))
            TEST_VERDICT("Sent message is '%s' but 'recv' operation is%s "
                         "already done", tx_msg, (op_done) ? "" : " not");
        if (!op_done)
        {
            if (rpc_write(pco_tst, tst_s, pattern, pattern_len) !=
                (int)pattern_len)
                TEST_FAIL("Only part of data was sent");
        }
        rc = recv_f(pco_iut, iut_s, rx_buf,
                    (msg_len < pattern_len) ? pattern_len : msg_len, 0);
        if ((rc != (int)msg_len && strcmp(tx_msg, "match") == 0) ||
            (rc != (int)pattern_len && strcmp(tx_msg, "match") != 0))
            TEST_VERDICT("Incorrect amount of data was recieved");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(tx_buf);
    free(rx_buf);
    free(pattern);

    TEST_END;
}
