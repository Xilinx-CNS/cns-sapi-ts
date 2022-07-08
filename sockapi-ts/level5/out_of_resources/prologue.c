/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Prologue for level5/out_of_resources package
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

/** Logging subsystem entity name */
#define TE_TEST_NAME    "level5/out_of_resources/prologue"

#include "out_of_resources.h"
#include "onload.h"

/* FD table size */
#define FDTABLE_SIZE 30000

/* Expected minimum HW filters number. At the moment EF10 NICs have
 * about 4K and Siena NICs about 8K HW filters. */
#define HW_FILTERS_MIN 3500

/* Minimum (requested) sockets number to create. */
#define SOCKETS_MIN 9000

#define LINUX_FILTERS_NUM 8000

/* Maximum waiting time to exhaust HW filters in milliseconds. */
#define GET_FILTERS_LIMIT_TIMEOUT 120000

int
main(int argc, char *argv[])
{
    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    te_bool                 ef_no_fail;

    int limit;
    int loglevel;
    int iut_s_1;
    int iut_s_2;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(ef_no_fail);

    /* Make sure no Onload stacks stay alive. */
    sockts_kill_zombie_stacks(pco_iut);

    CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_NO_FAIL", ef_no_fail, TRUE,
                                 FALSE));
    CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_PREFAULT_PACKETS", FDTABLE_SIZE,
                                 TRUE, FALSE));
    CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_FDTABLE_SIZE", FDTABLE_SIZE,
                                 TRUE, FALSE));
    CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_MAX_ENDPOINTS", FDTABLE_SIZE,
                                 TRUE, FALSE));
    CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_TCP_BACKLOG_MAX", SOCKETS_MIN,
                                 TRUE, TRUE));

    sockts_inc_rlimit(pco_iut, RPC_RLIMIT_NOFILE, FDTABLE_SIZE);

    if (tapi_onload_lib_exists(pco_iut->ta))
    {
        TAPI_SYS_LOGLEVEL_DEBUG(pco_iut, &loglevel);

        /* In the loop create socket on IUT, bind() and listen(). Calculate
         * number of created and accelerated sockets. */
        pco_iut->timeout = GET_FILTERS_LIMIT_TIMEOUT;
        rc = rpc_out_of_hw_filters_do(pco_iut, TRUE, iut_addr, tst_addr,
                                      RPC_SOCK_STREAM, RPC_OOR_LISTEN,
                                      SOCKETS_MIN, &limit, NULL,
                                      &iut_s_1, &iut_s_2);
    }
    else
        limit = LINUX_FILTERS_NUM;

    RING("HW filters limit %d", limit);

    TEST_STEP("If obtained HW filters number is less then HW_FILTERS_MIN, there is "
              "high probability that something goes worng.");
    if (limit < HW_FILTERS_MIN)
        TEST_VERDICT("hardware filters number is less then expected "
                     "minimum");

    CHECK_RC(tapi_sh_env_set_int(pco_iut, TE_HW_FILTERS, limit, TRUE, TRUE));

    TEST_SUCCESS;

cleanup:
    CLEANUP_CHECK_RC(tapi_sh_env_unset(pco_iut, "EF_TCP_BACKLOG_MAX", TRUE,
                                       FALSE));
    CLEANUP_CHECK_RC(tapi_sh_env_unset(pco_iut, "EF_PREFAULT_PACKETS", TRUE,
                                       FALSE));

    if (tapi_onload_lib_exists(pco_iut->ta))
    {
        /* Force IUT sockets closing. */
        rcf_rpc_server_restart(pco_iut);
        TAPI_WAIT_NETWORK;

        TAPI_SYS_LOGLEVEL_CANCEL_DEBUG(pco_iut, loglevel);

        /* Make sure no Onload stacks stay alive. */
        sockts_kill_zombie_stacks(pco_iut);
    }

    TEST_END;
}
