/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-oobinline_recv_oob OOB data can not be got by recv() with MSG_OOB flag if SO_OOBINLINE set on socket
 *
 * @objective Check that @c OOB data should be retrieved by means of ordinary
 *            @c recv() if @c SO_OOBINLNE option set on socket.
 *
 * @type conformance
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param pco_rcv    Receiver
 * @param pco_snd    Sender
 * @param rcv_s      TCP socket on @p pco_rcv
 * @param snd_s      TCP socket on @p pco_snd
 * @param call_after If TRUE, @c SO_OOBINLINE should be enabled after
 *                   OOB data sending
 * @param buf_len    Length of buffer to be first sent with @c MSG_OOB flag
 *                   set (actually only the last byte of
 *                   the buffer is sent as out-of-band data)
 *
 * @pre Sockets @p rcv_s and @p snd_s are connected.
 *
 * @par Test sequence:
 * -# Create TCP connection between @p pco_rcv and @p pco_snd.
 * -# If @p call_after is @c FALSE enable @c SO_OOBINLINE option on @p rcv_s.
 * -# Send @p buffer of @p buf_len length with @c OOB data from @p pco_snd to
 *    @p pco_rcv.
 * -# If @p call_after is @c TRUE enable @c SO_OOBINLINE option on @p rcv_s.
 * -# Read sent data on @p pco_rcv;
 * -# Check that has been read the size(buffer) - 1 bytes on @p pco_rcv.
 * -# Check that SIOCATMARK @b ioctl() returns marker set.
 * -# Read one byte of OOB data by means of @b recv() with MSG_OOB as @p flag
 *    argument value.
 * -# Check that @b recv() returns -1 and @c errno set to @c EINVAL.
 * -# Read one byte of OOB data by means of @ recv() with @p flag argument
 *    set to @c 0.
 * -# Check that returned byte is the same as a last byte sent from @p pco_snd.
 * -# Close @p snd_s, and @p rcv_s sockets.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/oobinline_recv_oob"

#include "sockapi-test.h"

#define WAIT_FOR_RPC_IS_DONE SLEEP (2)

int
main(int argc, char *argv[])
{
    rcf_rpc_server              *pco_rcv = NULL;
    rcf_rpc_server              *pco_snd = NULL;

    const struct sockaddr       *rcv_addr = NULL;
    const struct sockaddr       *snd_addr = NULL;

    char                        *tx_buf = NULL;
    char                        *rx_buf = NULL;
    int                          buf_len;
    int                          rcv_s = -1;
    int                          snd_s = -1;

    int                          opt_val = TRUE;
    int                          req_val;
    int                          sent;
    int                          rcv;

    te_bool                      call_after = FALSE;
    te_bool                      done = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_rcv);
    TEST_GET_PCO(pco_snd);
    TEST_GET_ADDR(pco_rcv, rcv_addr);
    TEST_GET_ADDR(pco_snd, snd_addr);
    TEST_GET_INT_PARAM(buf_len);
    TEST_GET_BOOL_PARAM(call_after);

    /* Scenario */
    GEN_CONNECTION(pco_rcv, pco_snd, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                   rcv_addr, snd_addr, &rcv_s, &snd_s);
    rx_buf = te_make_buf_by_len(buf_len);
    tx_buf = te_make_buf_by_len(buf_len);
    te_fill_buf(tx_buf, buf_len);

    if (!call_after)
        rpc_setsockopt(pco_rcv, rcv_s, RPC_SO_OOBINLINE, &opt_val);

    RPC_SEND(sent, pco_snd, snd_s, tx_buf, buf_len, RPC_MSG_OOB);

    MSLEEP(10);

    if (call_after)
        rpc_setsockopt(pco_rcv, rcv_s, RPC_SO_OOBINLINE, &opt_val);

    rc = rpc_recv(pco_rcv, rcv_s, rx_buf, buf_len, 0);
    rcv = rc;

    rpc_ioctl(pco_rcv, rcv_s, RPC_SIOCATMARK, &req_val);
    if (req_val == 0)
    {
        TEST_FAIL("ioctl(SIOCATMARK) does not return out-of-band data marker");
    }


    if (rcv != sent - 1)
    {
        TEST_FAIL("Expected to recieve %d instead %d, because out-of-band "
                  " byte was sent", sent - 1, rcv);
    }

    /* try to retrieve OOB data with MSG_OOB flag set */
    RPC_AWAIT_IUT_ERROR(pco_rcv);
    rc = rpc_recv(pco_rcv, rcv_s, rx_buf + buf_len - 1, 1, RPC_MSG_OOB);
    if (rc != -1)
    {
        TEST_FAIL("It's expected to get -1, instead of %d, because SO_OOBINLINE "
                  "was applied to 'rcv_s' socket");
    }
    CHECK_RPC_ERRNO(pco_rcv, RPC_EINVAL, "recv() returns -1, but");

    /* retrieve OOB data as ordinary byte */
    pco_rcv->op = RCF_RPC_CALL;
    rc = rpc_recv(pco_rcv, rcv_s, rx_buf + buf_len - 1, 1, 0);
    WAIT_FOR_RPC_IS_DONE;

    CHECK_RC(rcf_rpc_server_is_op_done(pco_rcv, &done));

    if (!done)
    {
        CHECK_RC(rcf_rpc_server_restart(pco_rcv));
        TEST_VERDICT("recv() is blocked on IUT");
    }
    else
    {
        rc = rpc_recv(pco_rcv, rcv_s, rx_buf + buf_len - 1, 1, 0);
    }
    if (rc != 1)
    {
        TEST_FAIL("No OOB data has been returned");
    }

    if (memcmp(rx_buf, tx_buf, buf_len) != 0)
    {
        TEST_FAIL("Sent data do not match to received ones:\n%Tm\n%Tm", 
                  tx_buf, buf_len, rx_buf, buf_len);
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_rcv, rcv_s);
    CLEANUP_RPC_CLOSE(pco_snd, snd_s);

    free(rx_buf);
    free(tx_buf);

    TEST_END;
}

