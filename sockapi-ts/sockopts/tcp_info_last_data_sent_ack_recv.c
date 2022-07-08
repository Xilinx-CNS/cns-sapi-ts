/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/**
 * @page sockopts-tcp_info_last_data_sent_ack_recv Check tcp_info_last_data_sent and tcp_info_last_ack_recv values reported by TCP_INFO option
 *
 * @objective Check that @c TCP_INFO structure fields @b tcpi_last_data_sent and
 *            @b tcpi_last_ack_recv are changed correctly during connection
 *
 * @param env Testing environment:
 *      - @ref arg_types_env_peer2peer
 *      - @ref arg_types_env_peer2peer_ipv6
 *
 * @par Scenario:
 *
 * @author Vasilij Ivanov <Vasilij.Ivanov@oktetlabs.ru>
 */

#define TE_TEST_NAME "sockopts/tcp_info_last_data_sent_ack_recv"

#include "sockapi-test.h"
#include "tapi_tcp.h"

#define PRECISION 100
#define SLEEPING_TIME 2000

#define NOT_EQUAL_WITH_PRECISION(value1, value2) \
            abs((value1) - (value2)) > PRECISION

static void
check_field(int value, int exp_value, const char *field_name,
            const char *stage)
{
    RING("Obtained value of the field %s is %d, expected value is %d",
         field_name, value, exp_value);
    if (NOT_EQUAL_WITH_PRECISION(value, exp_value))
    {
        TEST_VERDICT("%s: %s value is significantly %s than expected",
                     stage, field_name,
                     (value < exp_value ? "smaller" : "bigger"));
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst = NULL;

    const struct sockaddr     *iut_addr = NULL;
    const struct sockaddr     *tst_addr = NULL;

    int                       iut_s = -1;
    int                       tst_s = -1;

    struct rpc_tcp_info       info;
    uint8_t                   *buf;
    uint32_t                  len;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    TEST_STEP("Establish TCP connection between a pair of sockets "
              "on IUT and Tester");
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr,
                      SOCKTS_SOCK_TCP_ACTIVE, &iut_s, &tst_s, NULL);

    TEST_STEP("Obtain @c TCP_INFO on the IUT socket and"
              "check that @b tcpi_last_data_sent "
              "and @b tcpi_last_ack_recv equal 0");
    memset(&info, 0, sizeof(info));
    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_INFO, &info);
    len = rand_range(1, info.tcpi_snd_mss);
    buf = te_make_buf_by_len(len);

    check_field(info.tcpi_last_data_sent, 0, "tcpi_last_data_sent",
                "After creation");

    check_field(info.tcpi_last_ack_recv, 0, "tcpi_last_ack_recv",
                "After creation");

    TEST_STEP("Wait 2 seconds");
    MSLEEP(SLEEPING_TIME);

    TEST_STEP("Check that @b tcpi_last_data_sent and @b tcpi_last_ack_recv "
              "increased by 2000");
    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_INFO, &info);

    check_field(info.tcpi_last_data_sent, SLEEPING_TIME, "tcpi_last_data_sent",
                "After sleeping after creation");

    check_field(info.tcpi_last_ack_recv, SLEEPING_TIME, "tcpi_last_ack_recv",
                "After sleeping after creation");

    TEST_STEP("Send data from IUT socket");
    rpc_send(pco_iut, iut_s, buf, len, 0);

    TEST_STEP("Check that @b tcpi_last_data_send equals 0");
    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_INFO, &info);

    check_field(info.tcpi_last_data_sent, 0, "tcpi_last_data_sent",
                "After sending");

    TEST_STEP("Receive data on the Tester socket");
    rpc_recv(pco_tst, tst_s, buf, len, 0);

    TEST_STEP("Check that @b tcpi_last_ack_recv equals 0");
    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_INFO, &info);

    check_field(info.tcpi_last_ack_recv, 0, "tcpi_last_ack_recv",
                "After sending");

    TEST_STEP("Wait 2 second");
    MSLEEP(SLEEPING_TIME);

    TEST_STEP("Check that @b tcpi_last_data_sent and @b tcpi_last_ack_recv "
              "increased by 2000");
    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_INFO, &info);

    check_field(info.tcpi_last_data_sent, SLEEPING_TIME, "tcpi_last_data_sent",
                "After sleeping after sending");

    check_field(info.tcpi_last_ack_recv, SLEEPING_TIME, "tcpi_last_ack_recv",
                "After sleeping after sending");

    TEST_SUCCESS;

cleanup:
    free(buf);
    TEST_END;
}
