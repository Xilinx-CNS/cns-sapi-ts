/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-sndbuf Usage of SO_SNDBUF socket option with connectionless sockets
 *
 * @objective Check that value returned by means of getsockopt(SO_SNDBUF)
 *            is effective send buffer length.
 *
 * @type conformance
 *
 * @reference @ref XNS5, @ref STEVENS, section 7.5
 *
 * @param pco_iut     PCO on IUT
 * @param pco_tst     PCO on TESTER
 * @param sndbuf_new  The value to be set with setsockopt(SO_SNDBUF)
 *                    on @p iut_s
 * @param force       If @c TRUE, use SO_SNDBUFFORCE on IUT
 *
 * @par Test sequence:
 *
 * -# Create @p iut_s socket of type @c SOCK_DGRAM on @p pco_iut;
 * -# Create @p tst_s socket of type @c SOCK_DGRAM on @p pco_tst;
 * -# @b bind() @p iut_s socket to @p iut_addr;
 *  # @b bind() @p tst_s socket to @p tst_addr;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b getsockopt(SO_SNDBUF) on @p iut_s socket to get initial
 *    value;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# @b setsockopt(SO_SNDBUF) on @p iut_s socket with a @p sndbuf_new value;
 * -# Call @b getsockopt(SO_SNDBUF) on @p iut_s socket to get effective
 *    send buffer length value;
 * -# Set @p tst_s socket receive buffer length to value equal or more than
 *    @p iut_s send buffer length;
 * -# @b sendto() 1 byte via @p iut_s to @p tst_s;
 * -# @b recv() 1 byte sent on previous step on @p tst_s;
 * -# sendto() datagram with length equal to effective send buffer length
 *    via @p iut_s to @p tst_s;
 * -# recv() datagram sent on previous step on @p tst_s and 
 *    check data validity;
 * -# If previous @b send() failed find the maximum size datagram
 *    to be @b sendto() through @p iut_s to @p tst_s and log
 *    it as effective send buffer size;
 * -# Close opened sockets and release allocated resources.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/sndbuf_dgram"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_route_gw.h"

#define TST_WAIT_AFTER_SEND  1000
#define TST_HDRS_LEN         28
#define TST_MAX_LEN          65536

//#undef RPC_ENOBUFS
//#define RPC_ENOBUFS  RPC_EAGAIN

//#define IPRNT(_arg...)  printf(_arg)
#define IPRNT(_arg...)

int
main(int argc, char *argv[])
{
    int             i;
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;

    const struct if_nameindex  *iut_if = NULL;
    const struct sockaddr      *tst_hwaddr = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    void                   *tx_buf = NULL;
    void                   *rx_buf = NULL;

    int                     sndbuf_def;
    int                     sndbuf_new;
    int                     sndbuf_effect;
    int                     rcvbuf_len;

    size_t                  dgram_len;
    int                     rx_bytes;
    int                     tx_bytes;
    int                     req_val;

    int                     step;
    ssize_t                 buf_len;
    ssize_t                 prev_buf_len = 0;
    te_bool                 overflow = TRUE;
    te_bool                 find_suitable = FALSE;
    te_bool                 change_step = FALSE;
    te_bool                 force = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(sndbuf_new);
    TEST_GET_LINK_ADDR(tst_hwaddr);
    TEST_GET_IF(iut_if);
    TEST_GET_BOOL_PARAM(force);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);
//    req_val = TRUE;
//    rpc_ioctl(pco_iut, iut_s, RPC_FIONBIO, &req_val);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    req_val = TRUE;
    rpc_ioctl(pco_tst, tst_s, RPC_FIONBIO, &req_val);

    rpc_bind(pco_tst, tst_s, tst_addr);
    rpc_bind(pco_iut, iut_s, iut_addr);

    CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if->if_name, NULL, NULL,
                             tst_addr, CVT_HW_ADDR(tst_hwaddr), TRUE));

    rpc_getsockopt(pco_iut, iut_s, RPC_SO_SNDBUF, &sndbuf_def);

    rpc_setsockopt(pco_iut, iut_s,
                   (force ? RPC_SO_SNDBUFFORCE : RPC_SO_SNDBUF),
                   &sndbuf_new);

    rpc_getsockopt(pco_iut, iut_s, RPC_SO_SNDBUF, &sndbuf_effect);

    /* Adjust receive side according to send side */
    rpc_getsockopt(pco_tst, tst_s, RPC_SO_RCVBUF, &rcvbuf_len);

    /* Provide appropriate peer socket receive length */
    for (i = 1; i < 3; i++)
    {
        if (rcvbuf_len < sndbuf_effect)
        {
            rcvbuf_len = sndbuf_effect * i;
            rpc_setsockopt(pco_tst, tst_s, RPC_SO_RCVBUF, &rcvbuf_len);

            rpc_getsockopt(pco_tst, tst_s, RPC_SO_RCVBUF, &rcvbuf_len);
        }
        else
            break;
    }

    if (rcvbuf_len < sndbuf_effect)
        TEST_FAIL("Wrong test conditions: rcvbuf < sndbuf");

    tx_buf = te_make_buf_by_len(sndbuf_effect);
    rx_buf = te_make_buf_by_len(sndbuf_effect);

    /* Level 5 specific step: first datagram goes through O/S stack */
    tx_bytes = rpc_sendto(pco_iut, iut_s, tx_buf, 1, 0, tst_addr);
    MSLEEP(TST_WAIT_AFTER_SEND);
    rx_bytes = rpc_recv(pco_tst, tst_s, rx_buf, 1, 0);

    /* Restrict datagram length to exclude EMSGSIZE error */
    if (sndbuf_effect >= (TST_MAX_LEN - TST_HDRS_LEN))
        dgram_len = TST_MAX_LEN - TST_HDRS_LEN - 1;
    else
        dgram_len = sndbuf_effect;

    /* Attempt to send dgram with max length */
    RPC_AWAIT_IUT_ERROR(pco_iut);
    tx_bytes = rpc_sendto(pco_iut, iut_s, tx_buf, dgram_len, 0, tst_addr);
    if (tx_bytes == -1)
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_ENOBUFS,
                        "sendto() called on a socket that "
                        "has unsuitable send buffer");
        find_suitable = TRUE;
    }
IPRNT("\n+++ sendto(%d) ret: %d ", dgram_len, tx_bytes);

    memset(rx_buf, 0, sndbuf_effect);
    MSLEEP(TST_WAIT_AFTER_SEND);
    RPC_AWAIT_IUT_ERROR(pco_tst);
    rx_bytes = rpc_recv(pco_tst, tst_s, rx_buf, sndbuf_effect, 0);
    if (find_suitable == TRUE)
    {
        if (rx_bytes != -1)
        {
            TEST_FAIL("Unexpected datagram %d length was received",
                      rx_bytes);
        }
        else
            CHECK_RPC_ERRNO(pco_tst, RPC_EAGAIN,
                            "recv() called when no data was expected ");
    }
    else
    {
        if (rx_bytes == -1)
        {
            TEST_FAIL("recv() unexpectedly returns error: %s instead "
                      "of datagram %d bytes length",
                      errno_rpc2str(RPC_ERRNO(pco_tst)), tx_bytes);
        }
        else
        {
            if (tx_bytes != rx_bytes)
                TEST_FAIL("datagram %d bytes length was received, but "
                          "%d bytes length was sent", rx_bytes, tx_bytes);
            if (memcmp(tx_buf, rx_buf, rx_bytes) != 0)
                TEST_FAIL("Invalid data was received");
        }
    }
IPRNT("... recv(%d) ret: %d \n", sndbuf_effect, rx_bytes);

    /* Attempt to find effective buffer size */
    buf_len = step = dgram_len;
    change_step = TRUE;
    while (find_suitable)
    {
        prev_buf_len = buf_len;
        if (change_step == TRUE)
            step = step / 2;

        buf_len = (overflow == TRUE) ? buf_len - step : buf_len + step;

IPRNT("\n*** OVERFLOW:%s step:%d, prev_len:%d, buf_len:%d, abs(%d)\n",
      (overflow ? "TRUE" : "FALSE"), step, prev_buf_len, buf_len,
      abs(prev_buf_len - buf_len));

        if (abs(prev_buf_len - buf_len) == 0)
        {
            dgram_len = buf_len;
            break;
        }

        RPC_AWAIT_IUT_ERROR(pco_iut);
        tx_bytes = rpc_sendto(pco_iut, iut_s, tx_buf, buf_len, 0, tst_addr);
IPRNT("    sendto(%d) ret: %d ", buf_len, tx_bytes);
        if (tx_bytes != -1)
        {
            if (tx_bytes != buf_len)
                TEST_FAIL("sendto() sent only part (%d) of datagram (%d)",
                          tx_bytes, buf_len);

            change_step = (overflow == FALSE) ? FALSE : TRUE;
            overflow = FALSE;
        }
        else
        {
            change_step = (overflow == TRUE) ? FALSE : TRUE;
            overflow = TRUE;
            CHECK_RPC_ERRNO(pco_iut, RPC_ENOBUFS,
                            "sendto() called on a socket that "
                            "has unsuitable buffer");
        }

        memset(rx_buf, 0, sndbuf_effect);
        MSLEEP(TST_WAIT_AFTER_SEND);
        RPC_AWAIT_IUT_ERROR(pco_tst);
        rx_bytes = rpc_recv(pco_tst, tst_s, rx_buf, buf_len, 0);
IPRNT("... recv(%d) ret: %d ", buf_len, rx_bytes);
        if (rx_bytes != -1)
        {
            if (rx_bytes != tx_bytes)
                TEST_FAIL("recv() received %d bytes instead of %d",
                          rx_bytes, tx_bytes);
            if (memcmp(tx_buf, rx_buf, rx_bytes) != 0)
                TEST_FAIL("Inconsistent data is received");
        }
        else
            CHECK_RPC_ERRNO(pco_tst, RPC_EAGAIN,
                            "recv() called when no data was expected ");
    };

IPRNT("\n ---- Effective send buffer length is %d, "
      "Max datagram payload length %d \n",
      sndbuf_effect, dgram_len);
    RING_VERDICT("Effective send buffer length is %d, "
                 "Max datagram payload length %d",
                 sndbuf_effect, dgram_len);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

   if (pco_iut != NULL && iut_if != NULL)
       CLEANUP_CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta,
                                                 iut_if->if_name,
                                                 tst_addr));
    free(tx_buf);
    free(rx_buf);

    TEST_END;
}
