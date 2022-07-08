/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/**
 * @page sockopts-tcp_info_retransmits Check some tcp_info fields with broken connection
 *
 * @objective Send data with broken connection and check that some tcp_info structure fields have increased
 *
 * @param env Network environment with gateway
 *
 * @par Scenario:
 *
 * @author Timofey Alekseev <Timofey.Alekseev@oktetlabs.ru>
 */

#define TE_TEST_NAME "sockopts/tcp_info_retransmits"

#include "sockapi-test.h"
#include "tapi_route_gw.h"

static uint32_t
get_tcpi_field_by_str(struct rpc_tcp_info *tcpi, char *field_name)
{
    if (strcmp(field_name, "tcpi_retransmits") == 0)
        return tcpi->tcpi_retransmits;
    else if (strcmp(field_name, "tcpi_retrans") == 0)
        return tcpi->tcpi_retrans;
    else if (strcmp(field_name, "tcpi_lost") == 0)
        return tcpi->tcpi_lost;
    else if (strcmp(field_name, "tcpi_backoff") == 0)
        return tcpi->tcpi_backoff;
    else if (strcmp(field_name, "tcpi_unacked") == 0)
        return tcpi->tcpi_unacked;
    else if (strcmp(field_name, "tcpi_rto") == 0)
        return tcpi->tcpi_rto;
    else
        TEST_FAIL("Test does not support field %s", field_name);
}

static te_bool
check_rto(int *rto_first, int rto_cur, te_bool rto_same, char *stage)
{
    te_bool fail = FALSE;

    if (*rto_first == -1)
    {
        *rto_first = rto_cur;
    }
    else if (rto_same)
    {
        if (rto_cur != *rto_first)
        {
            fail = TRUE;
            RING_VERDICT("%s: field tcpi_rto value must not change", stage);
        }
    }
    else if (rto_cur < *rto_first * 2 ||
             rto_cur > *rto_first * 2.2)
    {
        fail = TRUE;
        RING_VERDICT("%s: field tcpi_rto value must be close to "
                     "doubled starting value", stage);
    }

    return fail;
}

static void
check_fields(rcf_rpc_server *rpcs, int sock,
             char **fields, size_t fields_num, te_bool mustBnull,
             int *rto_first, te_bool rto_same, char *stage)
{
    size_t i;
    te_bool fail = FALSE;
    uint32_t field_val;
    struct rpc_tcp_info tcpi;

    rpc_getsockopt(rpcs, sock, RPC_TCP_INFO, &tcpi);

    for (i = 0; i < fields_num; i++)
    {
        field_val = get_tcpi_field_by_str(&tcpi, fields[i]);
        RING("%s: %u", fields[i], field_val);
        if (strcmp(fields[i], "tcpi_rto") == 0)
        {
            if (check_rto(rto_first, field_val, rto_same, stage))
                fail = TRUE;
        }
        else if (mustBnull && (field_val != 0))
        {
            fail = TRUE;
            RING_VERDICT("%s: field %s must be 0 but it is not",
                         stage, fields[i]);
        }
        else if (!mustBnull && (field_val == 0))
        {
            fail = TRUE;
            RING_VERDICT("%s: field %s must be greater than 0 but it is not",
                         stage, fields[i]);
        }
    }

    if (fail)
        TEST_FAIL("Incorrect values in tcp_info structure");
}

int
main(int argc, char *argv[])
{
    tapi_route_gateway gw;
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;

    char **tcpi_fields = NULL;
    int  tcpi_fields_num;

    int iut_s = -1;
    int tst_s = -1;

    void  *tx_buf;
    void  *rx_buf;
    size_t data_buf_len;

    int rto_first = -1;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_STRING_LIST_PARAM(tcpi_fields, tcpi_fields_num);

    tx_buf = sockts_make_buf_stream(&data_buf_len);
    rx_buf = tapi_malloc(data_buf_len);

    TAPI_INIT_ROUTE_GATEWAY(gw);
    CHECK_RC(tapi_route_gateway_configure(&gw));
    CFG_WAIT_CHANGES;

    TEST_STEP("Create a connection through a gateway");
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr,
                      SOCKTS_SOCK_TCP_ACTIVE,
                      &iut_s, &tst_s, NULL);

    TEST_STEP("Send some data from IUT socket and check tcp_info fields");
    RPC_SEND(rc, pco_iut, iut_s, tx_buf, data_buf_len, 0);

    rc = rpc_recv(pco_tst, tst_s, rx_buf, data_buf_len, 0);
    SOCKTS_CHECK_RECV(pco_tst, tx_buf, rx_buf, data_buf_len, rc);
    TAPI_WAIT_NETWORK;

    check_fields(pco_iut, iut_s, tcpi_fields, tcpi_fields_num, TRUE,
                 &rto_first, TRUE, "After connection establishment");

    TEST_STEP("Break connection on gateway");
    CHECK_RC(tapi_route_gateway_break_gw_tst(&gw));
    CFG_WAIT_CHANGES;

    TEST_STEP("Send some data from IUT socket and check tcpi_info fields");
    RPC_SEND(rc, pco_iut, iut_s, tx_buf, data_buf_len, 0);

    TAPI_WAIT_NETWORK;

    check_fields(pco_iut, iut_s, tcpi_fields, tcpi_fields_num, FALSE,
                 &rto_first, FALSE, "After connectivity break");

    TEST_STEP("Repair connection on gateway");
    CHECK_RC(tapi_route_gateway_repair_gw_tst(&gw));
    CFG_WAIT_CHANGES;

    TEST_STEP("Send some data from IUT socket and check tcpi_info fields");
    RPC_SEND(rc, pco_iut, iut_s, tx_buf, data_buf_len, 0);

    rc = rpc_recv(pco_tst, tst_s, rx_buf, data_buf_len, 0);
    SOCKTS_CHECK_RECV(pco_tst, tx_buf, rx_buf, data_buf_len, rc);
    TAPI_WAIT_NETWORK;

    check_fields(pco_iut, iut_s, tcpi_fields, tcpi_fields_num, TRUE,
                 &rto_first, TRUE, "After connectivity restore");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(tx_buf);
    free(rx_buf);

    TEST_END;
}
