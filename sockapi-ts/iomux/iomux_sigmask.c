/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * I/O Multiplexing
 * 
 * $Id$
 */

/**
 * @page iomux-iomux_sigmask Support of sigmask in pselect()/ ppoll()/ epoll_pwait()/ epoll_pwait2()
 *
 * @objective Check support of @a sigmask parameter in
 *            @b pselect()/ @b ppoll()/ @b epoll_pwait()/ @b epoll_pwait2()
 *            implementation.
 *
 * @type conformance
 *
 * @requirement REQ-1, REQ-2, REQ-3
 *
 * @reference @ref STEVENS section 6.9
 *
 * @param pco_iut       PCO with IUT
 * @param pco_killer    PCO on the same host as @p pco_iut
 * @param sig1          The first test signal
 * @param sig2          The second test signal
 * @param iomux         iomux function to use:
 *                      - @b pselect
 *                      - @b ppoll()
 *                      - @b epoll_pwait()
 *                      - @b epoll_pwait2()
 *
 * -# Set test signal handler which just registers the last delivered
 *    signal for @p sig1 and @p sig2;
 * -# Allocate four signal sets (@p save, @p empty, @p sig1 and @p sig2);
 * -# Clean up @p empty signal set using @b sigemptyset() function;
 * -# Get current signals mask in @p save, @p set1 and @p set2 set mask
 *    using @b sigprocmask() with @c SIG_BLOCK option and @p empty new
 *    set;
 * -# Unblock @p sig1 and block @p sig2 in set @p set1;
 * -# Unblock @p sig2 and block @p sig1 in set @p set2;
 * -# Set process signals mask to @p set1 using @b sigprocmask();
 * -# Send signal @p sig1 from @p pco_killer PCO to @p pco_iut using @b kill()
 *    function;
 * -# Check that the signal was delivered;
 * -# Send signal @p sig2 from @p pco_killer PCO to @p pco_iut using @b kill()
 *    function;
 * -# Check that the signal was not delivered. Note that the signal is
 *    pending;
 * -# Call @p iomux in blocking with zero timeout and @p set2
 *    signal set;
 * -# Check that @p iomux returns @c -1 and @c EINTR @b errno;
 *    Check that @p sig2 was delivered;
 * -# Send signal @p sig1 from @p pco_killer PCO to @p pco_iut using @b kill()
 *     function;
 * -# Check that the signal was delivered;
 * -# Call @p iomux with @c 10 seconds timeout and @p set2 signal set;
 * -# Send signal @p sig2 from @p pco_killer PCO to @p pco_iut using @b kill()
 *    function;
 * -# Check that @p iomux returns @c -1 and @c EINTR @b errno;
 *    Check that @p sig2 was delivered;
 * -# Call @p iomux with @c 10 seconds timeout and @p set2 signal set;
 * -# Send signal @p sig1 from @p pco_killer PCO to @p pco_iut using @b kill()
 *    function;
 * -# Check that the signal is not delivered before @p iomux
 *    timeout;
 * -# Restore original signal set using @p save signal set;
 * -# Restore original signal handlers for @p sig1 and @p sig2.
 * 
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME "iomux/iomux_sigmask"
#include "sockapi-test.h"
#include "iomux.h"

static rcf_rpc_server           *pco_iut = NULL;
static iomux_call_type           iomux;
static int                       iomux_rc = 0;
static iomux_evt_fd              event;
static struct tarpc_timeval      timeout;
static rpc_sigset_p              sig2_set = RPC_NULL;

void *
do_iomux_call(void *arg)
{
    UNUSED(arg);

    iomux_rc = iomux_call_signal(iomux, pco_iut, &event,
                                 1, &timeout, sig2_set);

    return NULL;
}

#define CHECK_MASK(s_) \
    do {                                                                \
        rpc_sigprocmask(pco_iut, RPC_SIG_SETMASK,                       \
                        RPC_NULL, current_set);                         \
        if (rpc_sigset_cmp(pco_iut, current_set, sig1_set) != 0)        \
            TEST_FAIL("Signal mask of process was changed after the "   \
                      s_ " iomux call");                                \
    } while (0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_killer = NULL;
    rcf_rpc_server     *pco_tst = NULL;
    rpc_sigset_p        save_set = RPC_NULL;
    rpc_sigset_p        empty_set = RPC_NULL;
    rpc_sigset_p        sig1_set = RPC_NULL;
    rpc_sigset_p        received_set = RPC_NULL;
    rpc_sigset_p        pending_set = RPC_NULL;
    rpc_sigset_p        current_set = RPC_NULL;
   
    DEFINE_RPC_STRUCT_SIGACTION(old_act1);
    DEFINE_RPC_STRUCT_SIGACTION(old_act2);
    const struct sockaddr  *iut_addr;
    
    tarpc_timeval       tv = {0, 0};
    rpc_signum          sig1;
    rpc_signum          sig2;
    pthread_t           thread;
    te_bool             thread_started = FALSE;

    te_bool save_set_restore = FALSE;
    te_bool restore_signal_handler = FALSE;
    int     iut_s = -1;
    int     tst_s = -1;
    
    pid_t pco_iut_pid;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_killer);
    TEST_GET_SIGNUM(sig1);
    TEST_GET_SIGNUM(sig2);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_ADDR(pco_iut, iut_addr);

    pco_iut_pid = rpc_getpid(pco_iut);

    iut_s = rpc_stream_server(pco_iut, RPC_PROTO_DEF, FALSE, iut_addr);
    event.fd = iut_s;
    event.events = EVT_RD;

    CHECK_RC(tapi_sigaction_simple(pco_iut, sig1,
                                   SIGNAL_REGISTRAR, &old_act1));
    CHECK_RC(tapi_sigaction_simple(pco_iut, sig2,
                                   SIGNAL_REGISTRAR, &old_act2));
    restore_signal_handler = TRUE;

    /* Scenario */
    save_set = rpc_sigset_new(pco_iut);
    empty_set = rpc_sigset_new(pco_iut);
    sig1_set = rpc_sigset_new(pco_iut);
    sig2_set = rpc_sigset_new(pco_iut);
    pending_set = rpc_sigset_new(pco_iut);
    current_set = rpc_sigset_new(pco_iut);

    received_set = rpc_sigreceived(pco_iut);

    rpc_sigemptyset(pco_iut, empty_set);

    rpc_sigprocmask(pco_iut, RPC_SIG_BLOCK, empty_set, save_set);

    save_set_restore = TRUE;

    rpc_sigprocmask(pco_iut, RPC_SIG_BLOCK, empty_set, sig1_set);
    rpc_sigprocmask(pco_iut, RPC_SIG_BLOCK, empty_set, sig2_set);

    rpc_sigdelset(pco_iut, sig1_set, sig1);
    rpc_sigaddset(pco_iut, sig1_set, sig2);

    rpc_sigdelset(pco_iut, sig2_set, sig2);
    rpc_sigaddset(pco_iut, sig2_set, sig1);

    rpc_sigprocmask(pco_iut, RPC_SIG_SETMASK, sig1_set, RPC_NULL);

    rpc_kill(pco_killer, pco_iut_pid, sig1);

    rc = rpc_sigismember(pco_iut, received_set, sig1);
    if (rc != TRUE)
    {
        TEST_FAIL("No sig1 signal has been recieved");
    }
    rpc_sigdelset(pco_iut, received_set, sig1);

    RING("Interrupt %s() by signal unblocked by sigmask",
         iomux_call_en2str(iomux));

    rpc_gettimeofday(pco_killer, &tv, NULL);
    pco_killer->start = (tv.tv_sec + 4) * 1000 + tv.tv_usec / 1000;
    pco_killer->op = RCF_RPC_CALL;
    rpc_kill(pco_killer, pco_iut_pid,  sig2);

    timeout.tv_sec  = 10;
    timeout.tv_usec = 0;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = iomux_call_signal(iomux, pco_iut, &event, 1, &timeout, sig2_set);

    pco_killer->op = RCF_RPC_WAIT;
    rpc_kill(pco_killer, pco_iut_pid,  sig2);

    if (rc != -1)
    {
        TEST_FAIL("RPC %s() on IUT returns unexpected value %d; "
                  "expected -1, since %s() should be interruped "
                  "by signal when unmasking", iomux_call_en2str(iomux),
                  rc, iomux_call_en2str(iomux));
    }
    CHECK_RPC_ERRNO(pco_iut, RPC_EINTR, "%s() interrupted by signal "
                                        "returns -1, but",
                                        iomux_call_en2str(iomux));
    CHECK_MASK("first");

    rc = rpc_sigismember(pco_iut, received_set, sig2);
    if (rc != TRUE)
    {
        TEST_FAIL("No sig2 signal has been recieved");
    }
    rpc_sigdelset(pco_iut, received_set, sig2);


    RING("Do not interrupt %s() by signal blocked by sigmask",
         iomux_call_en2str(iomux));

    rpc_gettimeofday(pco_killer, &tv, NULL);
    pco_killer->start = (tv.tv_sec + 4) * 1000 + tv.tv_usec / 1000;
    pco_killer->op = RCF_RPC_CALL;
    rpc_kill(pco_killer, pco_iut_pid,  sig1);

    timeout.tv_sec  = 10;
    timeout.tv_usec = 0;
    rc = iomux_call_signal(iomux, pco_iut, &event, 1, &timeout, sig2_set);

    pco_killer->op = RCF_RPC_WAIT;
    rpc_kill(pco_killer, pco_iut_pid,  sig1);

    if (rc != 0)
        TEST_FAIL("RPC %s() on IUT failed", iomux_call_en2str(iomux));
    CHECK_MASK("second");
    MSLEEP(100);

    /*
     * Signal should be delivered when pselect()/ ppoll()/ epoll_pwait()/
     * epoll_pwait2() restores original mask
    */
    rc = rpc_sigismember(pco_iut, received_set, sig1);
    if (rc != TRUE)
    {
        TEST_FAIL("No sig1 signal has been recieved");
    }
    rpc_sigdelset(pco_iut, received_set, sig1);

    RING("Interrupt %s() by previously-sent signal unblocked by sigmask",
         iomux_call_en2str(iomux));

    rpc_kill(pco_killer, pco_iut_pid,  sig2);

    rpc_sigpending(pco_iut, pending_set);

    rc = rpc_sigismember(pco_iut, pending_set, sig2);
    if (rc != TRUE)
    {
        TEST_FAIL("No sig2 signal has been pended");
    }

    timeout.tv_sec  = 0;
    timeout.tv_usec = 1000;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = iomux_call_signal(iomux, pco_iut, &event, 1, &timeout, sig2_set);
    if (rc != -1)
    {
        TEST_FAIL("RPC %s() on IUT returns unexpected value %d; "
                  "expected -1, since %s() should be interruped "
                  "by signal when unmasking", iomux_call_en2str(iomux),
                  rc, iomux_call_en2str(iomux));
    }
    CHECK_RPC_ERRNO(pco_iut, RPC_EINTR, "%s() returns -1, but",
                                        iomux_call_en2str(iomux));
    CHECK_MASK("third");

    rpc_sigpending(pco_iut, pending_set);

    rc = rpc_sigismember(pco_iut, pending_set, sig2);
    if (rc != FALSE)
    {
        TEST_FAIL("Unexpected appearance of sig2 in pending set");
    }
    rpc_sigdelset(pco_iut, pending_set, sig2);


    RING("Do not interrupt %s() by previously-sent blocked signal",
         iomux_call_en2str(iomux));

    rpc_kill(pco_killer, pco_iut_pid,  sig1);

    rc = rpc_sigismember(pco_iut, received_set, sig1);
    if (rc != TRUE)
    {
        TEST_FAIL("No sig1 signal has been recieved");
    }

    /* Now check that event fires the iomux */
    timeout.tv_sec  = 10;
    timeout.tv_usec = 0;
    pthread_create(&thread, NULL, do_iomux_call, NULL);
    thread_started = TRUE;

    TAPI_WAIT_NETWORK;
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_connect(pco_tst, tst_s, iut_addr);
    TAPI_WAIT_NETWORK;

    /* Iomux should already return */
    if (pthread_tryjoin_np(thread, NULL) != 0)
        TEST_FAIL("Event is not reported");
    thread_started = FALSE;
    CHECK_MASK("fourth");

    if (iomux_rc != 1 || event.revents != EVT_RD)
        TEST_FAIL("Unexpected events are reported");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (thread_started)
    {
        pthread_cancel(thread);
        pthread_join(thread, NULL);
        rcf_rpc_server_restart(pco_iut);
    }
    else
    {
        CLEANUP_RPC_CLOSE(pco_iut, iut_s);
        if (save_set_restore)
        {
            save_set_restore = FALSE;
            rpc_sigprocmask(pco_iut, RPC_SIG_SETMASK, save_set, RPC_NULL);
        }

        if (restore_signal_handler)
        {
            CLEANUP_RPC_SIGACTION(pco_iut, sig1, &old_act1,
                                  SIGNAL_REGISTRAR);
            CLEANUP_RPC_SIGACTION(pco_iut, sig2, &old_act2,
                                  SIGNAL_REGISTRAR);
        }

        if (save_set != RPC_NULL)
            rpc_sigset_delete(pco_iut, save_set);
        if (empty_set != RPC_NULL)
            rpc_sigset_delete(pco_iut, empty_set);
        if (sig1_set != RPC_NULL)
            rpc_sigset_delete(pco_iut, sig1_set);
        if (sig2_set != RPC_NULL)
            rpc_sigset_delete(pco_iut, sig2_set);
        if (pending_set != RPC_NULL)
            rpc_sigset_delete(pco_iut, pending_set);
        if (current_set != RPC_NULL)
            rpc_sigset_delete(pco_iut, current_set);
    }

    TEST_END;
}

