/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Siute
 * Reliability Socket API in Normal Use
 */

/** @page basic-kill_lock_stack Killing locked onload stack
 *
 * @objective Check that onload sends RST for TCP socket in locked stack
 *            after termination of the process by @b exit() or by a signal.
 *
 * @type use case
 *
 * @param env           Testing environment:
 *                      @ref arg_types_env_peer2peer
 *                      @ref arg_types_env_peer2peer_ipv6
 * @param term_func     How to terminate tested process:
                        - exit
                        - kill
 * @param sig           If @p term_func is @b kill(),
 *                      @p sig is number of signal to send:
 *                      - SIGKILL
 *                      - SIGUSR1
 * @param exit_status   If @p term_func is @b exit(), @p exit_status is status
 *                      value to be passed to @b exit():
 *                      - 11
 *
 * @par Test sequence:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/kill_lock_stack"

#include "sockapi-test.h"
#include "iomux.h"
#include "onload.h"
#include "extensions.h"

enum {
    EXIT_FUNC = 0,
    _EXIT_FUNC,
    KILL_FUNC
};

#define TERM_FUNCS \
    {"exit", EXIT_FUNC}, \
    {"_exit", _EXIT_FUNC}, \
    {"kill", KILL_FUNC}

int
main (int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    rcf_rpc_server         *pco_child = NULL;
    int                     iut_s = -1;
    int                     tst_s = -1;
    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    int                 term_func = 0;
    int                 exit_status = 0;
    rpc_signum          sig = 0;
    pid_t               child_pid;
    rpc_wait_status     status;
    tarpc_onload_stat   ostat;

    char                lockcmd[128];

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ENUM_PARAM(term_func, TERM_FUNCS);

    if (term_func == KILL_FUNC)
        TEST_GET_SIGNUM(sig);
    else
        TEST_GET_INT_PARAM(exit_status);

    TEST_STEP("Create @p pco_child process for the test purposes.");
    rcf_rpc_server_fork(pco_iut, "iut_child",
                        &pco_child);
    child_pid = rpc_getpid(pco_child);

    TEST_STEP("Create @c SOCK_STREAM connection between @p pco_child and "
              "@p pco_tst.");
    GEN_CONNECTION(pco_child, pco_tst, RPC_SOCK_STREAM,
                   RPC_PROTO_DEF, iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Lock stack using onload_stackdump command.");
    rpc_onload_fd_stat(pco_child, iut_s, &ostat);
    snprintf(lockcmd, sizeof(lockcmd), "te_onload_stdump %d lock",
             ostat.stack_id);
    RING("%s", lockcmd);
    rpc_system(pco_iut, lockcmd);
    TAPI_WAIT_NETWORK;

    TEST_STEP("According to @p term_func parameter call @b exit() or "
              "@b kill() function on @p pco_child.");
    switch (term_func)
    {
        case EXIT_FUNC:
            rpc_exit(pco_child, exit_status);
            break;

        case _EXIT_FUNC:
            rpc__exit(pco_child, exit_status);
            break;

        case KILL_FUNC:
            rpc_kill(pco_iut, child_pid, sig);
            break;
    }

    /*
     * Let configurator know that pco_child server
     * is completely terminated, so only associated data
     * structures should be released in TA
     */
    rcf_rpc_server_finished(pco_child);

    TEST_STEP("Call @b waitpid(PID of @p pco_child) and check "
              "returned status.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_waitpid(pco_iut, (tarpc_pid_t) child_pid, &status, 0);

    if (rc < 0)
    {
        TEST_VERDICT("waitpid() failed with errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }
    else
    {
        switch (status.flag)
        {
            case RPC_WAIT_STATUS_EXITED:
                RING_VERDICT("Child process exited with status %d",
                             status.value);
                break;

            case RPC_WAIT_STATUS_SIGNALED:
            case RPC_WAIT_STATUS_CORED:
                RING_VERDICT("Child process was %s by "
                             "the signal %s",
                             status.flag == RPC_WAIT_STATUS_SIGNALED ?
                                "terminated" : "cored",
                             signum_rpc2str(status.value));
                break;

            default:
                TEST_VERDICT("waitpid() returned unexpected status %s",
                             wait_status_flag_rpc2str(status.flag));
        }
    }

    TEST_STEP("Call @b poll() on @p tst_s socket and check that it "
              "returns @c POLLHUP event.");
    {
        struct rpc_pollfd   fds[1];
        int                 exp = RPC_POLLIN | RPC_POLLOUT | \
                                  RPC_POLLERR | RPC_POLLHUP;

        /* IUT should have been closed its socket by the time when
         * waitpid() returns.  Unfortunately Onload misbehaves here,
         * deferring the closing for a bit.
         * It is especially visible with older branches such as onload-7.1.
         * See ON-13096.
         */
        TAPI_WAIT_NETWORK;

        fds[0].fd = tst_s;
        fds[0].events = (RPC_POLLIN | RPC_POLLOUT);
        fds[0].revents = 0;

        if ((rc = rpc_poll(pco_tst, fds, 1, 1000)) != 1)
            TEST_VERDICT("poll() returned %d", rc);
        else if (fds[0].revents != exp)
            TEST_VERDICT("poll() returned %d and sets "
                         "events to %s", rc,
                         poll_event_rpc2str(fds[0].revents));
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    rcf_rpc_server_destroy(pco_child);

    TEST_END;
}
