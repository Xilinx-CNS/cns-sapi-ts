/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP test
 *
 * $Id$
 */

/** @page tcp-tcp_last_data Check tcpi_last_* fields in tcp_info.
 *
 * @objective Check the behaviour of @b tcp_info struct fields:
 *            tcpi_last_data_recv, tcpi_last_data_sent and
 *            tcpi_last_ack_recv.
 *
 * @type conformance
 *
 * @param pco_iut          PCO on IUT
 * @param pco_tst          Tester PCO
 * @param iut_addr         Network address on @p pco_iut
 * @param tst_addr         Network address on @p pco_tst
 * @param cache_socket     If @c TRUE, create cached socket to be reused.
 *
 * @par Scenario:
 *
 * -# If @p cache_socket is @c TRUE, create cached socket in this case.
 * -# Create TCP connection between @p pco_iut and @p pco_tst.
 * -# Save the field value @b tcpi_last_data_recv on @p pco_iut as
 *    @b iut_data_recv.
 * -# Check that @b tcpi_last_data_sent and @b tcpi_last_ack_recv on
 *    @p pco_iut are about @c 0.
 * -# Wait @b t1 ms.
 * -# Check that @b tcpi_last_data_sent and @b tcpi_last_ack_recv on
 *    @p pco_iut are about @b t1.
 * -# Check that @b tcpi_last_data_recv on @p pco_iut are about
 *    (@b iut_data_recv + @b t1).
 * -# Send a data from @p pco_iut.

 * -# Wait @b t2 ms.
 * -# Check that @b tcpi_last_data_sent and @b tcpi_last_ack_recv on
 *    @p pco_iut are about @b t2.
 * -# Check that @b tcpi_last_data_recv on @p pco_iut are about
 *    (@b iut_data_recv + @b t1 + @b t2).
 * -# Receive a data on @p pco_tst.

 * -# Wait @b t3 ms.
 * -# Check that @b tcpi_last_data_sent and @b tcpi_last_ack_recv on
 *    @p pco_iut are about (@b t2 + @b t3).
 * -# Check that @b tcpi_last_data_recv on @p pco_iut are about
 *    (@b iut_data_recv + @b t1 + @b t2 + @b t3).
 * -# Send a data from @p pco_tst.

 * -# Wait @b t4 ms.
 * -# Check that @b tcpi_last_data_recv and @b tcpi_last_ack_recv on
 *    @p pco_iut are about @b t4.
 * -# Check that @b tcpi_last_data_sent on @p pco_iut are about
 *    (@b t2 + @b t3 + @b t4).
 * -# Receive a data on @p pco_iut.

 * -# Wait @b t5 ms.
 * -# Check that @b tcpi_last_data_recv and @b tcpi_last_ack_recv on
 *    @p pco_iut are about (@b t4 + @b t5).
 * -# Check that @b tcpi_last_data_sent on @p pco_iut are about
 *    (@b t2 + @b t3 + @b t4 + @b t5).
 *
 * @author Oleg Sadakov <osadakov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/tcp_last_data"

#include "sockapi-test.h"
#include "tcp_test_macros.h"

#define TST_SENDRECV_FLAGS 0

/** Hides a message output in log */
#define HIDE_MESSAGE(args...)

/** Acceptable (absolute) inaccuracy in time measurement (in ms) */
#define TST_TIME_INACCURACY_MS (TST_TIME_INACCURACY / 1000)

/**
 * Check specified field in the struct @b tcp_info
 *
 * @param field     name of the specified field
 * @param value     expected value
 */
#define CHECK_FIELD_MS(field, value) \
    CHECK_CALL_DURATION_INT_GEN(                            \
        info.field, TST_TIME_INACCURACY_MS,                 \
        TST_TIME_INACCURACY_MULTIPLIER,                     \
        (value), (value),                                   \
        HIDE_MESSAGE, TEST_VERDICT,                         \
        "Unexpected value of " #field " (%u), "             \
        "expected %u",                                      \
        info.field, (value))

/**
 * Check specified fields in the struct @b tcp_info
 *
 * @param pco             RPC server handle
 * @param s               socket descriptor
 * @param data_sent       value of field @b tcpi_last_data_sent
 * @param data_recv       value of field @b tcpi_last_data_recv
 * @param ack_recv        value of field @b tcpi_last_ack_recv
 */
#define CHECK_FIELDS(pco, s, data_sent, data_recv, ack_recv)\
    do {                                                    \
        rpc_getsockopt((pco), (s), RPC_TCP_INFO, &info);    \
        CHECK_FIELD_MS(tcpi_last_data_sent, (data_sent));   \
        CHECK_FIELD_MS(tcpi_last_data_recv, (data_recv));   \
        CHECK_FIELD_MS(tcpi_last_ack_recv,  (ack_recv));    \
    } while (0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_tst = NULL;
    int                 iut_s = -1;
    int                 tst_s = -1;
    void               *tx_buf = NULL;
    size_t              tx_buf_len;
    void               *rx_buf = NULL;
    size_t              rx_buf_len;

    uint32_t            t1 = rand_range(500, 2500);
    uint32_t            t2 = rand_range(500, 2500);
    uint32_t            t3 = rand_range(500, 2500);
    uint32_t            t4 = rand_range(500, 2500);
    uint32_t            t5 = rand_range(500, 2500);
    uint32_t            iut_data_recv;
    struct rpc_tcp_info info;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    te_bool cache_socket;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(cache_socket);

    tx_buf = sockts_make_buf_stream(&tx_buf_len);
    rx_buf = te_make_buf_min(tx_buf_len, &rx_buf_len);

    TEST_STEP("If @p cache_socket is @c TRUE - create cached socket.");
    sockts_create_cached_socket(pco_iut, pco_tst, iut_addr, tst_addr, -1,
                                TRUE, cache_socket);

    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                        tst_addr, iut_addr, &tst_s, &iut_s);

    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_INFO, &info);
    iut_data_recv = info.tcpi_last_data_recv;

    CHECK_FIELDS(pco_iut, iut_s, 0, iut_data_recv, 0);

    MSLEEP(t1);
    CHECK_FIELDS(pco_iut, iut_s, t1, t1 + iut_data_recv, t1);

    RPC_SEND(rc, pco_iut, iut_s, tx_buf, tx_buf_len, TST_SENDRECV_FLAGS);

    MSLEEP(t2);
    CHECK_FIELDS(pco_iut, iut_s, t2, t2 + t1 + iut_data_recv, t2);

    rc = rpc_recv(pco_tst, tst_s, rx_buf, tx_buf_len, TST_SENDRECV_FLAGS);
    SOCKTS_CHECK_RECV(pco_tst, tx_buf, rx_buf, tx_buf_len, rc);

    MSLEEP(t3);
    CHECK_FIELDS(pco_iut, iut_s, t3 + t2, t3 + t2 + t1 + iut_data_recv,
        t3 + t2);

    RPC_SEND(rc, pco_tst, tst_s, tx_buf, tx_buf_len, TST_SENDRECV_FLAGS);

    MSLEEP(t4);
    CHECK_FIELDS(pco_iut, iut_s, t4 + t3 + t2, t4, t4);

    rc = rpc_recv(pco_iut, iut_s, rx_buf, tx_buf_len,
        TST_SENDRECV_FLAGS);
    SOCKTS_CHECK_RECV(pco_iut, tx_buf, rx_buf, tx_buf_len, rc);

    MSLEEP(t5);
    CHECK_FIELDS(pco_iut, iut_s, t5 + t4 + t3 + t2, t5 + t4, t5 + t4);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(tx_buf);
    free(rx_buf);

    CHECK_CLEAR_TRANSPARENT(iut_addr, pco_tst, tst_addr);

    TEST_END;
}
