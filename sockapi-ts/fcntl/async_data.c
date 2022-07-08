/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * IOCTL Requests
 *
 * $Id$
 */

/** @page fcntl-async_data Usage of O_ASYNC request on connected sockets
 *
 * @objective Check that @c O_ASYNC request enables signal-driven I/O.
 *
 * @type conformance
 *
 * @param pco_iut             PCO on IUT
 * @param pco_tst             PCO on TESTER
 * @param sock_type           Type of socket to be used (@c SOCK_STREAM or
 *                            @c SOCK_DGRAM)
 * @param use_pipe            Use socket or pipe
 * @param read_avail          Read or write ability should be reported
 * @param use_fioasync_first  Use @c FIOASYNC or @c SET_FL at first
 * @param use_fioasync_second Use @c FIOASYNC or @c SET_FL at the end of
 *                            the test
 * @param use_siocspgrp       Use @c SIOCSPGRP or @c F_SETOWN
 * @param sig_to_set          Use the signal in @c F_SETSIG
 *
 * @par Test sequence:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#include "sockapi-test.h"

#define TE_TEST_NAME  "fcntl/async_data"



#include "sockapi-test.h"

#define GEN_SIGNAL(_clear_received_signals) \
do{                                                                    \
    if (read_avail)                                                    \
    {                                                                  \
        rpc_write(pco_tst, tst_fd, tx_buf, buf_len);                   \
        rc = rpc_read(pco_iut, iut_fd, rx_buf, buf_len);               \
        if (memcmp(tx_buf, rx_buf, buf_len) != 0)                      \
            TEST_FAIL("The content of 'tx_buf' and 'rx_buf' are "      \
                      "not the same");                                 \
        memset(rx_buf, 0, buf_len);                                    \
    }                                                                  \
    else                                                               \
    {                                                                  \
        if (use_pipe)                                                  \
            rpc_overfill_fd(pco_iut, iut_fd, &total_bytes);            \
        else                                                           \
            rpc_overfill_buffers(pco_iut, iut_fd, &total_bytes);       \
        if (_clear_received_signals)                                   \
        {                                                              \
            TAPI_WAIT_NETWORK;                                         \
            rpc_sigdelset(pco_iut, iut_sigmask, exp_sig_num);          \
        }                                                              \
        while (total_bytes)                                            \
            total_bytes -= rpc_read(pco_tst, tst_fd, rx_buf, buf_len); \
    }                                                                  \
} while(0);

int
main(int argc, char *argv[])
{
    rpc_socket_type    sock_type;
    rcf_rpc_server    *pco_iut = NULL;
    rcf_rpc_server    *pco_tst = NULL;
    int                iut_fd = -1;
    int                tst_fd = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    void                   *tx_buf = NULL;
    void                   *rx_buf = NULL;
    size_t                  buf_len;
    int                     old_flag = -1;
    int                     req_val;
    rpc_sigset_p            iut_sigmask = RPC_NULL;
    DEFINE_RPC_STRUCT_SIGACTION(old_act);
    te_bool                 restore_signal_handler = FALSE;

    te_bool                 use_pipe;
    te_bool                 read_avail = TRUE;
    int                     fds[2];

    te_bool                 use_fioasync_first = FALSE;
    te_bool                 use_fioasync_second = FALSE;
    te_bool                 use_siocspgrp = FALSE;
    te_bool                 active = FALSE;
    int                     sig_num_to_set = -1;

    const char             *sig_to_set = NULL;
    char                   *str_end;

    uint64_t                total_bytes;

    tarpc_siginfo_t         siginfo;
    rpc_signum              exp_sig_num = RPC_SIGUNKNOWN;

    struct param_map_entry signum_map[] = {
        SIGNUM_MAPPING_LIST,
        { NULL, 0}
    };

    /* Preambule */
    TEST_START;
    TEST_GET_BOOL_PARAM(use_pipe);
    TEST_GET_PCO(pco_iut);
    TEST_GET_BOOL_PARAM(read_avail);
    if (!use_pipe)
    {
        TEST_GET_ADDR(pco_iut, iut_addr);
        TEST_GET_SOCK_TYPE(sock_type);
        TEST_GET_BOOL_PARAM(active);
        TEST_GET_PCO(pco_tst);
        TEST_GET_ADDR(pco_tst, tst_addr);
    }
    TEST_GET_BOOL_PARAM(use_fioasync_first);
    TEST_GET_BOOL_PARAM(use_fioasync_second);
    TEST_GET_BOOL_PARAM(use_siocspgrp);
    TEST_GET_STRING_PARAM(sig_to_set);

    TEST_STEP("Create pipe or connected sockets according to @p use_pipe "
              "parameter");
    if (use_pipe)
    {
        pco_tst = pco_iut;
        rpc_pipe(pco_iut, fds);
        if (read_avail)
        {
            iut_fd = fds[0];
            tst_fd = fds[1];
        }
        else
        {
            iut_fd = fds[1];
            tst_fd = fds[0];
        }
    }
    else
    {
        if (active)
            GEN_CONNECTION(pco_tst, pco_iut, sock_type, RPC_PROTO_DEF,
                           tst_addr, iut_addr, &tst_fd, &iut_fd);
        else
            GEN_CONNECTION_WILD(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                                iut_addr, tst_addr, &iut_fd, &tst_fd, TRUE);
    }

    sig_num_to_set = strtol(sig_to_set, &str_end, 10);
    if (*str_end != '\0')
    {
        if (test_map_param_value("sig_to_set", signum_map, sig_to_set,
                                 &sig_num_to_set) != 0)
            TEST_STOP;
    }

    if (sig_num_to_set > 0)
        exp_sig_num = sig_num_to_set;
    else
        exp_sig_num = RPC_SIGIO;

    CHECK_NOT_NULL((tx_buf = sockts_make_buf_dgram(&buf_len)));
    rx_buf = te_make_buf_by_len(buf_len);

    TEST_STEP("Register 'pco_iut' on receiving the signal");
    CHECK_RC(tapi_sigaction_simple(pco_iut, exp_sig_num,
                                   SIGNAL_REGISTRAR_SIGINFO, &old_act));
    restore_signal_handler = TRUE;

    TEST_STEP("Set asynchronous mode on @p iut_fd using @c FIOASYNC or @c F_SETFL "
              "according to @p use_fioasync_first parameter");
    old_flag = rpc_fcntl(pco_iut, iut_fd, RPC_F_GETFL, 0);
    RING("Current flags set on the 'iut_fd' are %x", old_flag);
    if (use_fioasync_first)
    {
        req_val = 1;
        rpc_ioctl(pco_iut, iut_fd, RPC_FIOASYNC, &req_val);
    }
    else
    {
        rc = rpc_fcntl(pco_iut, iut_fd, RPC_F_SETFL, RPC_O_ASYNC);
    }

    TEST_STEP("Set @c F_SETSIG according to @p sig_num_to_set parameter");
    if (sig_num_to_set != -1)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_fcntl(pco_iut, iut_fd, RPC_F_SETSIG,
                       sig_num_to_set);
        if (rc != 0)
        {
            TEST_VERDICT("fcntl(F_SETSIG) failed with errno %s",
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
        }
    }

    TEST_STEP("Generate the signal");
    GEN_SIGNAL(FALSE);

    TEST_STEP("Check that the signal is not delivered to the process -  "
              "we haven't set an owner.");
    iut_sigmask = rpc_sigreceived(pco_iut);
    rc = rpc_sigismember(pco_iut, iut_sigmask, exp_sig_num);
    if (rc != FALSE)
    {
        TEST_VERDICT("Unexpected %s signal is delivered to the pco_iut, "
                     "while with O_ASYNC is enabled but we have NOT set "
                     "an owner for 'iut_fd' YET",
                     signum_rpc2str(exp_sig_num));
    }

    TEST_STEP("Set @c SIOCSPGRP or @c F_SETOWN accroding to @p use_siocspgrp "
              "parameter to id of @p pco_iut");
    req_val = rpc_getpid(pco_iut);
    if (use_siocspgrp)
        rpc_ioctl(pco_iut, iut_fd, RPC_SIOCSPGRP, &req_val);
    else
        rc = rpc_fcntl(pco_iut, iut_fd, RPC_F_SETOWN, req_val);

    TEST_STEP("Generate the signal");
    GEN_SIGNAL(TRUE);

    TEST_STEP("Check that the signal is delivered to the process -  "
              "it is the owner of 'iut_fd'.");
    iut_sigmask = rpc_sigreceived(pco_iut);
    rc = rpc_sigismember(pco_iut, iut_sigmask, exp_sig_num);
    if (rc != TRUE)
    {
        TEST_VERDICT("%s signal is not delivered to the pco_iut, "
                     "although O_ASYNC is enabled and there is an "
                     "owner of 'iut_fd'",
                     signum_rpc2str(exp_sig_num));
    }
    else
    {
        TEST_STEP("Check that 'si_signo', 'si_code' and 'si_fd' are set "
                  "correctly");
        rpc_siginfo_received(pco_iut, &siginfo);

        if (siginfo.sig_signo != (int)exp_sig_num)
            TEST_FAIL("Unexpected value %s of si_signo field of "
                      "siginfo_t structure",
                      signum_rpc2str(exp_sig_num));

        if (sig_num_to_set <= 0)
        {
            if (siginfo.sig_code != RPC_SI_KERNEL)
            {
                RING_VERDICT("si_code field of siginfo_t structure is "
                             "equal to %s instead of SI_KERNEL",
                             si_code_rpc2str(siginfo.sig_code));

                if (siginfo.sig_fd != 0)
                    RING_VERDICT("si_fd field of siginfo_t structure is "
                                 "not zero as expected and is%s socket fd",
                                 siginfo.sig_fd == iut_fd ?
                                            "" : " not");
            }
        }
        else
        {
            if (!((siginfo.sig_code == RPC_POLL_IN && read_avail) ||
                  (siginfo.sig_code == RPC_POLL_OUT && !read_avail)))
                RING_VERDICT("si_code field of siginfo_t structure is "
                             "equal to %s instead of %s",
                             si_code_rpc2str(siginfo.sig_code),
                             read_avail ? "POLL_IN" : "POLL_OUT");

            if (siginfo.sig_fd == 0)
                RING_VERDICT("si_fd field of siginfo_t structure is "
                             "zero unexpectedly");
            else if (siginfo.sig_fd != iut_fd)
            {
                RING_VERDICT("si_fd field of siginfo_t structure is "
                             "not equal to socket fd");
            }
        }
    }

    TEST_STEP("Clear the signal in mask of received signals");
    rpc_sigdelset(pco_iut, iut_sigmask, exp_sig_num);

    TEST_STEP("Unset asynchronous mode on @p iut_fd using @c FIOASYNC or @c F_SETFL "
              "according to @p use_fioasync_second parameter");
    if (use_fioasync_second)
    {
        req_val = 0;
        rpc_ioctl(pco_iut, iut_fd, RPC_FIOASYNC, &req_val);
    }
    else
    {
        /* Turn off O_ASYNC request on 'iut_fd' */
        rc = rpc_fcntl(pco_iut, iut_fd, RPC_F_SETFL, old_flag);
    }

    TEST_STEP("Generate the signal");
    GEN_SIGNAL(FALSE);

    TEST_STEP("Check that the signal is not delivered to the process");
    iut_sigmask = rpc_sigreceived(pco_iut);
    rc = rpc_sigismember(pco_iut, iut_sigmask, exp_sig_num);
    if (rc != FALSE)
    {
        TEST_VERDICT("Unexpected %d signal is delivered to the pco_iut, "
                     "although O_ASYNC is disabled on 'iut_fd'",
                     signum_rpc2str(exp_sig_num));
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_fd);
    CLEANUP_RPC_CLOSE(pco_tst, tst_fd);

    if (restore_signal_handler)
        CLEANUP_RPC_SIGACTION(pco_iut, exp_sig_num, &old_act,
                              SIGNAL_REGISTRAR_SIGINFO);

    free(tx_buf);
    free(rx_buf);

    TEST_END;
}
