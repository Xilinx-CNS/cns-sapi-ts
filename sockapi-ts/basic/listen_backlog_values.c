/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-listen_backlog_values Influence of backlog parameter
 *
 * @objective Investigate treatment of @b listen() function backlog parameter.
 *
 * @type conformance, robustness
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param backlog   Backlog value to use with listen():
 *                  - -1
 *                  - 0
 *                  - 1
 *                  - 10
 *                  - 150
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Edward Makarov <Edward.Makarov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/listen_backlog_values"

#include "sockapi-test.h"
#include "tapi_proc.h"
#include "onload.h"

/**
 * Measured backlog should be no more than
 * this value + expected backlog.
 */
#define MAX_BACKLOG_DIFF 1

/**
 * Value for EF_MAX_PACKETS.
 * We should provide enough packet buffers to test
 * how backlog limitation is handled, especially when
 * EF_ENDPOINT_PACKET_RESERVE is used.
 */
#define MAX_PACKETS 65536

/**
 * Value for EF_MAX_ENDPOINTS.
 * The test creates many sockets to establish many connections
 * with listener, so we need to provide enough buffers
 * to accelerate all these sockets.
 */
#define MAX_ENDPOINTS 32768

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL; /* IUT PCO */
    rcf_rpc_server        *pco_tst = NULL; /* Testing PCO */
    rcf_rpc_server        *pco_iut_modpar = NULL;
    const struct sockaddr *iut_addr;       /* IUT address */
    const struct sockaddr *tst_addr;       /* Testing address */

    int   backlog;
    int   exp_backlog;
    int   iut_s_listener = -1;
    int   measured_backlog = -1;
    int   old_somaxconn = -1;

    int init_max_packets;
    int init_max_endpoints;
    te_bool restore_max_packets;
    te_bool restore_max_endpoints;

    te_bool test_failed = FALSE;
    char *old_ci_tp_log_lvl = NULL;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(backlog);

    TEST_STEP("Set EF_MAX_PACKETS and EF_MAX_ENDPOINTS to big values.");
    CHECK_RC(tapi_sh_env_save_set_int(pco_iut,
                                      "EF_MAX_PACKETS",
                                      MAX_PACKETS, FALSE,
                                      &restore_max_packets,
                                      &init_max_packets));

    CHECK_RC(tapi_sh_env_save_set_int(pco_iut,
                                      "EF_MAX_ENDPOINTS",
                                      MAX_ENDPOINTS, TRUE,
                                      &restore_max_endpoints,
                                      &init_max_endpoints));

    TEST_STEP("Make sure that somaxconn is not less than backlog we are going to "
              "set. If @p backlog is negative, set @b exp_backlog to somaxconn "
              "value; otherwise set it to @p backlog.");

    CHECK_RC(tapi_cfg_sys_ns_get_int(pco_iut->ta, &old_somaxconn,
                                     "net/core/somaxconn"));

    if (backlog < 0)
        exp_backlog = old_somaxconn;
    else
        exp_backlog = backlog;

    if (old_somaxconn < exp_backlog)
    {
        CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, exp_backlog, NULL,
                                         "net/core/somaxconn"));
        rcf_rpc_server_restart(pco_iut);
    }
    else
    {
        old_somaxconn = -1;
    }

    TEST_STEP("Create TCP listener socket on IUT, passing @p backlog "
              "to listen().");
    iut_s_listener =
        rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                   RPC_PROTO_DEF, FALSE, FALSE, iut_addr);
    rpc_listen(pco_iut, iut_s_listener, backlog);

    TEST_STEP("Increase RLIMIT_NOFILE for tester to make possible creating "
              "enough sockets to establish many connections.");
    /*
     * sockts_tcp_measure_listen_backlog() tries to create @b exp_backlog * 3/2
     * connections.
     */
    sockts_inc_rlimit(pco_tst, RPC_RLIMIT_NOFILE, exp_backlog * 3 / 2 + 100);

    if (tapi_onload_run() && getenv("SFC_NDEBUG") == NULL)
    {
        char *ta = NULL;
        TEST_STEP("When testing a debug Onload build, limit the transport "
                  "logging to errors only (@c CI_TP_LOG_E).");
        CHECK_NOT_NULL((ta = getenv("TE_IUT_TA_NAME")));
        CHECK_RC(rcf_rpc_server_create(ta, "pco_iut_modpar", &pco_iut_modpar));
        tapi_onload_module_ci_tp_log_set(pco_iut_modpar, SOCKTS_CI_TP_LOG_E,
                                         &old_ci_tp_log_lvl);
    }

    TEST_STEP("Measure really used listen backlog by establishing many "
              "connections from Tester, closing them there, and then "
              "counting how many sockets accept() can return on IUT.");
    pco_iut->silent_pass = pco_iut->silent_pass_default = TRUE;
    pco_tst->silent_pass = pco_tst->silent_pass_default = TRUE;
    measured_backlog = sockts_tcp_measure_listen_backlog(
                                                pco_iut, iut_addr,
                                                iut_s_listener,
                                                pco_tst, tst_addr,
                                                exp_backlog,
                                                "Measuring backlog");
    pco_iut->silent_pass = pco_iut->silent_pass_default = FALSE;
    pco_tst->silent_pass = pco_tst->silent_pass_default = FALSE;

    if (old_ci_tp_log_lvl != NULL)
    {
        TEST_STEP("Restore Onload transport logging level (if this value was "
                  "changed before).");
        tapi_onload_module_ci_tp_log_restore(pco_iut_modpar, old_ci_tp_log_lvl);
        FREE_AND_CLEAN(old_ci_tp_log_lvl);
    }

    RING("Measured backlog is %d, expected is %d",
         measured_backlog, exp_backlog);

    TEST_STEP("Check that measured backlog is about the same as @b exp_backlog.");

    if (measured_backlog < exp_backlog)
    {
        ERROR_VERDICT("Measured backlog is less than expected");
        test_failed = TRUE;
    }
    else if (measured_backlog > exp_backlog + MAX_BACKLOG_DIFF)
    {
        ERROR_VERDICT("Measured backlog is more than expected");
        test_failed = TRUE;
    }
    else if (measured_backlog > exp_backlog)
    {
        ERROR_VERDICT("Measured backlog is a bit more than expected");
        test_failed = TRUE;
    }

    TEST_STEP("Check that closing TCP listener socket works fine.");

    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_close(pco_iut, iut_s_listener);
    iut_s_listener = -1;
    if (rc < 0)
        TEST_VERDICT("close() failed for listener socket with errno %r",
                     RPC_ERRNO(pco_iut));

    if (test_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:
    /*
     * The sockts_tcp_measure_listen_backlog() may return with a verdict
     * somewhere in the middle, before all operations are successfully
     * completed.
     */
    pco_iut->silent_pass = pco_iut->silent_pass_default = FALSE;
    pco_tst->silent_pass = pco_tst->silent_pass_default = FALSE;
    CLEANUP_RPC_RESTORE_CI_TP_LOG_LVL(pco_iut_modpar, old_ci_tp_log_lvl);
    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_modpar));
    FREE_AND_CLEAN(old_ci_tp_log_lvl);

    if (iut_s_listener >= 0)
        CLEANUP_RPC_CLOSE(pco_iut, iut_s_listener);

    CLEANUP_CHECK_RC(tapi_sh_env_rollback_int(pco_iut,
                                              "EF_MAX_PACKETS",
                                              restore_max_packets,
                                              init_max_packets, FALSE));

    CLEANUP_CHECK_RC(tapi_sh_env_rollback_int(pco_iut,
                                              "EF_MAX_ENDPOINTS",
                                              restore_max_endpoints,
                                              init_max_endpoints, TRUE));

    if (old_somaxconn >= 0)
        CLEANUP_CHECK_RC(
                    tapi_cfg_sys_ns_set_int(pco_iut->ta, old_somaxconn,
                                            NULL, "net/core/somaxconn"));

    TEST_END;
}
