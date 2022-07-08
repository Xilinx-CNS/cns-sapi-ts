/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Onload extensions
 *
 * $Id$
 */

/** @page extension-template_signal Call Onload template functions from signal handler
 *
 * @objective  Call Onload template functions from signal handler
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TST
 * @param iovcnt        IOVs array length
 * @param total         Total amount of data to be passed by template
 * 
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/extension/template_signal"

#include "sockapi-test.h"
#include "template.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    rcf_rpc_server        *pco_killer = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    int        iut_s  = -1;
    int        tst_s  = -1;
    char      *rcvbuf = NULL;
    int        iovcnt;
    int        total;
    te_bool    restore = FALSE;

    DEFINE_RPC_STRUCT_SIGACTION(oldsa);

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_killer);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(iovcnt);
    TEST_GET_INT_PARAM(total);

    sockts_kill_zombie_stacks(pco_iut);

    total -= total % iovcnt;

    TEST_STEP("Create TCP connection between IUT and tester.");
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Set socket and data amount on IUT agent to send template later.");
    rpc_set_var(pco_iut, "template_signal_socket",
                rpc_get_sizeof(pco_iut, "int"), iut_s);

    rpc_set_var(pco_iut, "template_signal_total",
                rpc_get_sizeof(pco_iut, "int"), total);

    rpc_set_var(pco_iut, "template_signal_iovcnt",
                rpc_get_sizeof(pco_iut, "int"), iovcnt);

    TEST_STEP("Set signal handler.");
    oldsa.mm_mask = rpc_sigset_new(pco_iut);
    rpc_sigaction(pco_iut, RPC_SIGUSR1, NULL, &oldsa);
    rpc_signal(pco_iut, RPC_SIGUSR1, "sighandler_template_send");
    restore = TRUE;

    /* Send signal to IUT. */
    rpc_kill(pco_killer, rpc_getpid(pco_iut), RPC_SIGUSR1);

    TEST_STEP("Receive packet on tester, check length.");
    rcvbuf = te_calloc_fill(1, total, 0);
    if (rpc_recv(pco_tst, tst_s, rcvbuf, total, 0) != total)
        TEST_VERDICT("Read wrong amount of data.");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (restore)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        if (rpc_sigaction(pco_iut, RPC_SIGUSR1, &oldsa, NULL) < 0)
            result = -1;
    }
    CLEANUP_RPC_FREE(pco_iut, oldsa.mm_mask);

    TEST_END;
}
