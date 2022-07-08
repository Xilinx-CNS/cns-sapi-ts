/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 * 
 * $Id$
 */

/** @page tcp-tcp_flooder_mult Bidirectional data transmission between two peers
 *
 * @objective Stress test for loopback with bidirectional data transmission.
 *
 * @type stress, performance
 *
 * @param pco_iut      The first PCO on IUT
 * @param iut_addr     Address/port to be used to connect to @p pco_iut
 * @param pco_tst      The second PCO on IUT
 * @param tst_addr     Address/port to be used to connect to @p pco_tst
 *
 * @par Scenario:
 * -# Create socket @p iut_s_gen on @p pco_iut to receive connections
 * -# Start loop with iterations number @p iterations:
 * -#    Make TCP connection with sockets @p iut_s and @p tst_s on
 *       @p pco_iut and @p pco_tst accordingly;
 * -#    Call iomux flooders with the sockets @p iut_s and @p tst_s;
 * -#    Check data transmission results;
 * -#    Close sockets @p iut_s and @p tst_s
 *
 * @par Pass/Fail Criteria:
 * Volume of sent data from one peer should be equal volume of received data
 * on other.
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/tcp_flooder_mult"

#include "sockapi-test.h"
#include "iomux.h"

/** Data bulk size to send */
#define BULK_SIZE 1000

/**
 * Call two iomux flooders with @b select() function. Check transmission
 * results.
 */
static void
test_run_flooders(rcf_rpc_server *pco_iut, int iut_s,
                  rcf_rpc_server *pco_tst, int tst_s)
{
    int             time2run    = 1;
    int             time2wait   = 1;
    uint64_t        sent1       = 0;
    uint64_t        received1   = 0;
    uint64_t        sent2       = 0;
    uint64_t        received2   = 0;
    tarpc_timeval   tv          = {0, 0};

    rpc_gettimeofday(pco_iut, &tv, NULL);
    pco_iut->start = pco_tst->start =
        (tv.tv_sec + 2) * 1000 + tv.tv_usec / 1000;

    pco_iut->op = RCF_RPC_CALL;
    rpc_iomux_flooder(pco_iut, &iut_s, 1, &iut_s, 1, BULK_SIZE, time2run,
                      time2wait, IC_DEFAULT, &sent1, &received1);

    rpc_iomux_flooder(pco_tst, &tst_s, 1, &tst_s, 1, BULK_SIZE, time2run,
                      time2wait, IC_DEFAULT, &sent2, &received2);

    pco_iut->op = RCF_RPC_WAIT;
    rpc_iomux_flooder(pco_iut, &iut_s, 1, &iut_s, 1, BULK_SIZE, time2run,
                      time2wait, IC_DEFAULT, &sent1, &received1);

    if ((sent1 != received2) || (sent2 != received1))
    {
        TEST_FAIL("Part of data are lost: %u vs %u (lost %d), "
                  "%u vs %u (lost %d)",
                  (unsigned int)sent1, (unsigned int)received2,
                  (int)(sent1 - received2),
                  (unsigned int)sent2, (unsigned int)received1,
                  (int)(sent2 - received1));
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    int                     iut_s = -1;
    int                     iut_s_gen = -1;
    int                     tst_s = -1;

    int                     iter = 0;
    int                     iterations = 0;
    int                     old_tcp_syncookies = -1;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(iterations);

    /*
     * Test fails if net/ipv4/tcp_syncookies is disabled, due to kernel may
     * drop SYN requests, see ST-2107 for details.
     */
    rc = tapi_cfg_sys_ns_set_int(pco_iut->ta, 1, &old_tcp_syncookies,
                                 "net/ipv4/tcp_syncookies");
    if (rc != 0)
        TEST_VERDICT("Failed to enable tcp_syncookies (%r)", rc);

    iut_s_gen = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s_gen, iut_addr);
    rpc_listen(pco_iut, iut_s_gen, 0);

    for (iter = 0; iter < iterations; iter++)
    {
        tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_connect(pco_tst, tst_s, iut_addr);
        iut_s = rpc_accept(pco_iut, iut_s_gen, NULL, 0);

        test_run_flooders(pco_iut, iut_s, pco_tst, tst_s);

        RPC_CLOSE(pco_iut, iut_s);
        RPC_CLOSE(pco_tst, tst_s);
    }

    TEST_SUCCESS;

cleanup:

    if (old_tcp_syncookies != -1 && old_tcp_syncookies != 1)
    {
        CLEANUP_CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta,
                         old_tcp_syncookies, NULL, "net/ipv4/tcp_syncookies"));
    }

    CLEANUP_RPC_CLOSE(pco_iut, iut_s_gen);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
