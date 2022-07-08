/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Onload extensions
 */

/**
 * @page extension-zc_hlrx_pkts Receiving data with Onload ZC HLRX API
 *
 * @objective Check various usecases with @b onload_zc_hlrx_recv_zc() and
 *            @b onload_zc_hlrx_recv_copy(), such as reading the single
 *            packet with multiple calls, reading a packet and part of the
 *            next one with a single call, using both functions together.
 *
 * @type use case
 *
 * @param pkt_len       Packet length:
 *                      - @c 1024
 *                      - @c -1 (choose randomly for every new packet)
 * @param pkts_num      Number of packets to send:
 *                      - @c 5
 *                      - @c -1 (chosen randomly)
 * @param read_len      How many bytes to read by a single receiving call:
 *                      - @c 1500
 *                      - @c 700
 *                      - @c 100
 *                      - @c -1 (choose randomly each time)
 * @param func          With which function to read data:
 *                      - @c zc (@b onload_zc_hlrx_recv_zc())
 *                      - @c copy (@b onload_zc_hlrx_recv_copy())
 *                      - @c alternate (alternate both HLRX functions)
 *                      - @c random (choose randomly one of the HLRX
 *                        functions each time)
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "level5/extension/zc_hlrx_pkts"

#include "sockapi-test.h"
#include "onload.h"

/** Maximum length of data to send in a single call */
#define MAX_SEND_LEN 1400
/** Maximum length of data to read in a single call */
#define MAX_RECV_LEN (2 * MAX_SEND_LEN)
/** Maximum number of packets to send */
#define MAX_PKTS_NUM 25

/** Receiving functions to test */
enum {
    HLRX_FUNC_ZC,         /**< onload_zc_hlrx_recv_zc() */
    HLRX_FUNC_COPY,       /**< onload_zc_hlrx_recv_copy() */
    HLRX_FUNC_ALTERNATE,  /**< Alternate both HLRX functions */
    HLRX_FUNC_RANDOM,     /**< Choose receiving function randomly
                               for each new call */
};

/** List of values for "func" parameter */
#define HLRX_FUNCS \
    { "zc", HLRX_FUNC_ZC },               \
    { "copy", HLRX_FUNC_COPY },           \
    { "alternate", HLRX_FUNC_ALTERNATE }, \
    { "random", HLRX_FUNC_RANDOM }

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    int                     iut_s = -1;
    int                     tst_s = -1;

    int pkt_len;
    int pkts_num;
    int read_len;
    int func;

    int i;
    int cur_pkt_len;
    int cur_read_len;
    int exp_rc;

    char              tx_buf[MAX_SEND_LEN];
    char              rx_buf[MAX_RECV_LEN];
    rpc_recv_f        func_ptr = NULL;
    te_dbuf           tx_dbuf = TE_DBUF_INIT(0);
    te_dbuf           rx_dbuf = TE_DBUF_INIT(0);

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(pkt_len);
    TEST_GET_INT_PARAM(pkts_num);
    TEST_GET_INT_PARAM(read_len);
    TEST_GET_ENUM_PARAM(func, HLRX_FUNCS);

    if (pkt_len > MAX_SEND_LEN)
        TEST_FAIL("Too big pkt_len requested");
    if (read_len > MAX_RECV_LEN)
        TEST_FAIL("Too big read_len requested");

    TEST_STEP("If @p pkts_num is negative, choose for it a random "
              "positive value.");
    if (pkts_num < 0)
        pkts_num = rand_range(1, MAX_PKTS_NUM);

    TEST_STEP("Establish TCP connection between a socket on IUT and "
              "a socket on Tester.");
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Enable @c TCP_NODELAY socket option on Tester socket to "
              "ensure that packets of specified sizes are sent.");
    rpc_setsockopt_int(pco_tst, tst_s, RPC_TCP_NODELAY, 1);

    TEST_STEP("Send @p pkts_num packets from the Tester socket, choosing "
              "length of data to send according to @p pkt_len.");
    for (i = 0; i < pkts_num; i++)
    {
        if (pkt_len > 0)
            cur_pkt_len = pkt_len;
        else
            cur_pkt_len = rand_range(1, MAX_SEND_LEN);

        te_fill_buf(tx_buf, cur_pkt_len);
        RPC_SEND(rc, pco_tst, tst_s, tx_buf, cur_pkt_len, 0);
        CHECK_RC(te_dbuf_append(&tx_dbuf, tx_buf, cur_pkt_len));
        /* Wait to make sure a packet was really sent */
        MSLEEP(10);
    }

    TEST_STEP("On the IUT socket repeatedly call HLRX function chosen "
              "according to @p func to read a number of bytes chosen "
              "according to @p read_len, until all the sent data is read.");

    switch (func)
    {
        case HLRX_FUNC_ZC:
            func_ptr = &rpc_recv_func_hlrx_recv_zc;
            break;

        case HLRX_FUNC_COPY:
            func_ptr = &rpc_recv_func_hlrx_recv_copy;
            break;
    }

    while (rx_dbuf.len < tx_dbuf.len)
    {
        if (read_len > 0)
            cur_read_len = read_len;
        else
            cur_read_len = rand_range(1, MAX_RECV_LEN);

        if (func == HLRX_FUNC_RANDOM ||
            (func == HLRX_FUNC_ALTERNATE && func_ptr == NULL))
        {
            if (rand_range(1, 2) == 1)
                func_ptr = &rpc_recv_func_hlrx_recv_zc;
            else
                func_ptr = &rpc_recv_func_hlrx_recv_copy;
        }
        else if (func == HLRX_FUNC_ALTERNATE)
        {
            if (func_ptr == &rpc_recv_func_hlrx_recv_zc)
                func_ptr = &rpc_recv_func_hlrx_recv_copy;
            else
                func_ptr = &rpc_recv_func_hlrx_recv_zc;
        }

        exp_rc = MIN(tx_dbuf.len - rx_dbuf.len, cur_read_len);
        RPC_AWAIT_ERROR(pco_iut);
        rc = func_ptr(pco_iut, iut_s, rx_buf, cur_read_len, 0);
        if (rc < 0)
        {
            TEST_VERDICT("%s() failed unexpectedly with error "
                         RPC_ERROR_FMT, rpc_recv_func_name(func_ptr),
                         RPC_ERROR_ARGS(pco_iut));
        }
        else if (rc == 0)
        {
            TEST_VERDICT("%s() unexpectedly returned zero",
                         rpc_recv_func_name(func_ptr));
        }
        else if (rc != exp_rc)
        {
            ERROR("%d bytes returned instead of %d", rc, exp_rc);
            TEST_VERDICT("%s() returned unexpected number of bytes",
                         rpc_recv_func_name(func_ptr));
        }

        CHECK_RC(te_dbuf_append(&rx_dbuf, rx_buf, exp_rc));
    }
    assert(rx_dbuf.len == tx_dbuf.len);

    TEST_STEP("Check that expected data was received.");
    if (memcmp(rx_dbuf.ptr, tx_dbuf.ptr, rx_dbuf.len) != 0)
        TEST_VERDICT("Received data does not match sent data");

    TEST_SUCCESS;

cleanup:

    te_dbuf_free(&rx_dbuf);
    te_dbuf_free(&tx_dbuf);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
