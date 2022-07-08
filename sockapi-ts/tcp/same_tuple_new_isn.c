/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP tests
 */

/** @page tcp-same_tuple_new_isn TCP ISN selection for a new connection with the same addresses/ports
 *
 * @objective Check that if after closing of established TCP connection
 *            a new TCP connection with the same local and remote
 *            address/port is established actively from IUT, its ISN
 *            is chosen to be greater than the last SEQN from the previous
 *            connection.
 *
 * @param env               Testing environment:
 *                          - @ref arg_types_env_peer2peer
 *                          - @ref arg_types_env_peer2peer_ipv6
 * @param first_active      If @c TRUE, the first connection should be
 *                          established actively on IUT; otherwise
 *                          it should be established passively.
 * @param send_data         If @c TRUE, send a lot of data over the
 *                          first connection so that its last SEQN
 *                          will be significantly greater than ISN (and
 *                          possibly will outrun ISN counter).
 *
 * @par Test sequence:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "tcp/same_tuple_new_isn"

#include "sockapi-test.h"
#include "tapi_tcp.h"
#include "iomux.h"
#include "tcp_isn_check.h"

/** Maximum TCP SEQN */
#define MAX_TCP_SEQN 0xffffffff

/** Minimum period of ISN counter, in seconds */
#define MIN_ISN_WRAP_TIME (8 * 60)

/** How many bytes to send, if requested */
#define BYTES_TO_SEND   150000000LLU
/** Send timeout */
#define TIME_TO_SEND    30

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    const struct sockaddr      *iut_addr = NULL;
    const struct sockaddr      *tst_addr = NULL;
    const struct if_nameindex  *tst_if = NULL;
    const struct if_nameindex  *iut_if = NULL;

    const struct sockaddr  *iut_lladdr = NULL;
    const struct sockaddr  *tst_lladdr = NULL;

    te_bool                     first_active;
    te_bool                     send_data;
    int                         old_isn_passive = 0;
    te_bool                     isn_passive_existed = FALSE;

    uint32_t  isn1;
    uint32_t  last_seqn1;
    uint32_t  isn2;

    struct timeval isn1_tv;
    struct timeval isn2_tv;

    sockts_isn_conn conn = SOCKTS_ISN_CONN_INIT;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_LINK_ADDR(iut_lladdr);
    TEST_GET_LINK_ADDR(tst_lladdr);
    TEST_GET_IF(tst_if);
    TEST_GET_IF(iut_if);
    TEST_GET_BOOL_PARAM(first_active);
    TEST_GET_BOOL_PARAM(send_data);

    TEST_STEP("If @p first_active is @c FALSE, set "
              "@c EF_TCP_ISN_INCLUDE_PASSIVE environment variable to @c 1 "
              "on IUT.");
    if (!first_active)
    {
        CHECK_RC(tapi_sh_env_save_set_int(pco_iut,
                                          "EF_TCP_ISN_INCLUDE_PASSIVE",
                                          1, TRUE, &isn_passive_existed,
                                          &old_isn_passive));
    }

    sockts_isn_conn_init(pco_iut, pco_tst, iut_addr, tst_addr,
                         iut_lladdr, tst_lladdr,
                         iut_if, tst_if, &conn);

    TEST_STEP("Establish the first connection according to "
              "@p first_active. Capture ISN sent from IUT.");
    sockts_isn_conn_establish(&conn, !first_active);

    if (send_data)
    {
        TEST_STEP("If @p send_data is @c TRUE, send a lot of data from "
                  "IUT to Tester over the established connection.");
        sockts_isn_conn_send(&conn, BYTES_TO_SEND, TIME_TO_SEND);
    }
    else
    {
        TEST_STEP("If @p send_data is @c FALSE, wait for a while to let "
                  "ISN counter advance.");
        TAPI_WAIT_NETWORK;
    }

    TEST_STEP("Close the first TCP connection, initiating close from "
              "Tester side to avoid @c TIME_WAIT socket on IUT. Capture "
              "the last SEQN sent from IUT.");
    sockts_isn_conn_terminate(&conn);

    CHECK_RC(sockts_isn_conn_get_isn(&conn, &isn1));
    CHECK_RC(sockts_isn_conn_get_isn_ts(&conn, &isn1_tv));
    CHECK_RC(sockts_isn_conn_get_last_seqn(&conn, &last_seqn1));

    TEST_STEP("Establish the second TCP connection actively from IUT, "
              "with the same local and remote address/port values. "
              "Capture ISN sent from IUT.");
    sockts_isn_conn_establish(&conn, FALSE);

    CHECK_RC(sockts_isn_conn_get_isn(&conn, &isn2));
    CHECK_RC(sockts_isn_conn_get_isn_ts(&conn, &isn2_tv));

    RING("The first connection: ISN=%u, last SEQN=%u", isn1, last_seqn1);
    RING("The second connection: ISN=%u", isn2);
    RING("Time passed between IUT SYN packets of the connections: %f sec",
         TIMEVAL_SUB(isn2_tv, isn1_tv) / 1000000.0);

    TEST_STEP("If @p send_data is @c FALSE, determine speed of ISN "
              "counter: divide the difference between ISNs of the second "
              "and the first connections by time (in seconds) passed "
              "between @c SYN packets with these ISNs. Check that period "
              "of ISN counter is not less than 8 minutes.");
    if (!send_data)
    {
        double   speed;
        double   wrap_time;
        uint32_t isn_diff;

        isn_diff = isn2 - isn1;
        speed = (double)isn_diff / (double)TIMEVAL_SUB(isn2_tv, isn1_tv);
        speed *= 1000000.0;
        wrap_time = (MAX_TCP_SEQN + 1.0) / speed;
        RING("ISN counter speed %f bytes/second, counter will wrap "
             "in %f seconds", speed, wrap_time);

        if (wrap_time < MIN_ISN_WRAP_TIME)
        {
            RING_VERDICT("ISN counter will wrap in less than %u seconds",
                         MIN_ISN_WRAP_TIME);
        }
    }

    TEST_STEP("Check that IUT ISN of the second connection is greater "
              "than the last IUT SEQN of the first connection.");
    if (tapi_tcp_compare_seqn(isn2, last_seqn1) <= 0)
    {
        TEST_VERDICT("ISN of the second connection is not greater than "
                     "the last SEQN of the first connection");
    }

    TEST_SUCCESS;

cleanup:

    sockts_isn_conn_cleanup(&conn);

    if (!first_active)
    {
        CHECK_RC(tapi_sh_env_rollback_int(pco_iut,
                                          "EF_TCP_ISN_INCLUDE_PASSIVE",
                                          isn_passive_existed,
                                          old_isn_passive, TRUE));
    }

    TEST_END;
}
