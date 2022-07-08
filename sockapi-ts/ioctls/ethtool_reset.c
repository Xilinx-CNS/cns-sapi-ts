/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * IOCTL Requests
 */

/** @page ioctls-ethtool_reset Using of ETHTOOL_RESET request
 *
 * @objective Check that @c ETHTOOL_RESET request doesn't break connetion.
 *
 * @type conformance
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param pco_iut        PCO on IUT
 * @param pco_tst        PCO on TESTER
 *
 * @par Test sequence:
 * 
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/ethtool_reset"

#include "sockapi-test.h"
#include "onload.h"
#include "iomux.h"

/** Data bulk size to send */
#define BULK_SIZE 1000

/**
 * How long to wait after resetting NIC, in seconds. The constant
 * is obtained empirically (see ST-1770 and ST-2493).
 */
#define RESET_SLEEP 8

/**
 * How long to send flooders data, in seconds. The constant
 * is obtained empirically (see ST-1770 and ST-2238).
 */
#define FLOODERS_TIME2RUN   15

/**
 * How long to wait flooders data, in seconds. The constant
 * is obtained empirically (see ST-1770).
 * ST-2493: it should be big enough to avoid condition when rpc_iomux_flooder()
 * exits before interface is up. On some hosts, for instance ef100, the time of
 * setting interface up is about 10 sec, and the test should handle it.
 */
#define FLOODERS_TIME2WAIT  40

static void
test_run_flooders_call(rcf_rpc_server *pco_iut, int iut_s,
                       rcf_rpc_server *pco_tst, int tst_s)
{
    int             time2run    = FLOODERS_TIME2RUN;
    int             time2wait   = FLOODERS_TIME2WAIT;
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

    pco_tst->op = RCF_RPC_CALL;
    rpc_iomux_flooder(pco_tst, &tst_s, 1, &tst_s, 1, BULK_SIZE, time2run,
                      time2wait, IC_DEFAULT, &sent2, &received2);
}

static void
test_run_flooders_wait(rcf_rpc_server *pco_iut, int iut_s,
                       rcf_rpc_server *pco_tst, int tst_s)
{
    int             time2run    = FLOODERS_TIME2RUN;
    int             time2wait   = FLOODERS_TIME2WAIT;
    uint64_t        sent1       = 0;
    uint64_t        received1   = 0;
    uint64_t        sent2       = 0;
    uint64_t        received2   = 0;

    pco_tst->op = RCF_RPC_WAIT;
    pco_tst->timeout = pco_tst->def_timeout + TE_SEC2MS(time2run + time2wait);
    rpc_iomux_flooder(pco_tst, &tst_s, 1, &tst_s, 1, BULK_SIZE, time2run,
                      time2wait, IC_DEFAULT, &sent2, &received2);

    pco_iut->op = RCF_RPC_WAIT;
    pco_iut->timeout = pco_iut->def_timeout + TE_SEC2MS(time2run + time2wait);
    rpc_iomux_flooder(pco_iut, &iut_s, 1, &iut_s, 1, BULK_SIZE, time2run,
                      time2wait, IC_DEFAULT, &sent1, &received1);

    if ((sent1 != received2) || (sent2 != received1))
    {
        ERROR("Sent from IUT = %lu vs Received on Tester = %lu (lost %ld)",
              sent1, received2, sent1 - received2);
        ERROR("Sent from Tester = %lu vs Received on IUT = %lu (lost %ld)",
              sent2, received1, sent2 - received1);
        TEST_VERDICT("Part of data is lost");
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_aux = NULL;
    rcf_rpc_server     *pco_tst = NULL;
    rcf_rpc_server     *pco_iut_thread = NULL;
    int                 iut_s = -1;
    int                 tst_s = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    const struct if_nameindex   *iut_if = NULL;

    sockts_reset_mode   mode;
    te_bool             traffic = FALSE;
    int                 reset_num = 0;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_aux);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(traffic);
    TEST_GET_INT_PARAM(reset_num);
    TEST_GET_ENUM_PARAM(mode, SOCKTS_RESET_MODE);

    CHECK_RC(rcf_rpc_server_thread_create(pco_aux, "pco_iut_thread",
                                          &pco_iut_thread));

    GEN_CONNECTION(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   tst_addr, iut_addr, &tst_s, &iut_s);

    if (traffic)
    {
        test_run_flooders_call(pco_iut, iut_s, pco_tst, tst_s);
        SLEEP(1);
    }

    sockts_reset_interface(pco_aux->ta, iut_if->if_name, mode);
    CHECK_RC(sockts_wait_for_if_up(pco_iut_thread, iut_if->if_name));

    if (traffic)
    {
        TAPI_WAIT_NETWORK;
        while (--reset_num)
        {
            sockts_reset_interface(pco_aux->ta, iut_if->if_name, mode);
            CHECK_RC(sockts_wait_for_if_up(pco_iut_thread, iut_if->if_name));
            if (reset_num)
                /* Sleep timeout was increased to reduce complaints from
                 * net driver. */
                VSLEEP(3, "Sleep before next reset");
        }
        SLEEP(RESET_SLEEP);
        test_run_flooders_wait(pco_iut, iut_s, pco_tst, tst_s);
    }
    else
    {
        SLEEP(RESET_SLEEP);
    }

    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_thread));

    TEST_END;
}
