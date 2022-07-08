/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-many_listen_connect_lo Connect() vs close() on peer listening socket race condition
 *
 * @objective Check that sequence of steps: socket(), connect() than
 *            close() on one process and socket(), bind(), listen() and
 *            close() on another process doesn't lead to crash.
 *
 * @type conformance, robustness
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer_lo
 *              - @ref arg_types_env_peer2peer_lo_ipv6
 * @param time2run  Amount of time for the sequences in seconds:
 *                  - 60
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/many_listen_connect_lo"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    rcf_rpc_server        *pco_iut_modpar = NULL;
    const struct sockaddr *iut_addr;
    uint32_t               time2run;
    rpc_socket_domain      domain;
    char                  *old_ci_tp_log_lvl = NULL;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_INT_PARAM(time2run);

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

    domain = rpc_socket_domain_by_addr(iut_addr);

    pco_iut->timeout = TE_SEC2MS(time2run + 10);
    pco_iut->op = RCF_RPC_CALL;
    rpc_socket_listen_close(pco_iut, domain, iut_addr, time2run);
    pco_tst->timeout = TE_SEC2MS(time2run + 2);
    pco_tst->op = RCF_RPC_CALL;
    rpc_socket_connect_close(pco_tst, domain, iut_addr, time2run);

    RPC_AWAIT_IUT_ERROR(pco_tst);
    pco_tst->op = RCF_RPC_WAIT;
    rc = rpc_socket_connect_close(pco_tst, domain, iut_addr, time2run);
    if (rc == -1)
        CHECK_RPC_ERRNO(pco_tst, RPC_ECONNRESET,
                        "socket_connect_close() returns -1, but");
    pco_iut->op = RCF_RPC_WAIT;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_socket_listen_close(pco_iut, domain, iut_addr, time2run);
    if (rc != 0)
    {
        TEST_VERDICT("socket_listen_close() unexpectedly fails with error %r",
                     RPC_ERRNO(pco_iut));
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_RESTORE_CI_TP_LOG_LVL(pco_iut_modpar, old_ci_tp_log_lvl);
    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_modpar));
    FREE_AND_CLEAN(old_ci_tp_log_lvl);

    TEST_END;
}
