/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Signal-related helpers
 *
 * Signal-related helpers
 *
 * @author Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 */

#ifndef SOCKAPI_TS_SIGNAL_H_
#define SOCKAPI_TS_SIGNAL_H_

#include "sockapi-test.h"

/* Check restart flag correctness:
 * If @p _has_timeout, assume that @p _restart is @c FALSE since nothing
 * should be restarted.
 *
 * @param _func          Tested function name.
 * @param _restart       If @c TRUE, function should be restartable.
 * @param _is_restarted  Whether the function really was restarted
 *                       after interrupting.
 * @param _has_timeout   Whether @c SO_RCVTIMEO or @c SO_SNDTIMEO was
 *                       used to set a timeout for @p _func.
 */
#define TAPI_CHECK_RESTART_CORRECTNESS(_func, _restart, _is_restarted,  \
                                       _has_timeout)                    \
    do {                                                                \
        if ((_restart & !_has_timeout) != _is_restarted)                \
        {                                                               \
            TEST_VERDICT("%s is %srestarted unexpectedly", #_func,      \
                         (_is_restarted ? "" : "not "));                \
        }                                                               \
    } while(0)

/**
 * Generate connection and set the server socket send buffer size
 * and the client socket receive buffer size to the required value.
 *
 * @param srvr_         PCO where server socket is created
 * @param clnt_         PCO where client socket is created
 * @param srvr_addr_    Server address for @b bind() on server side
 * @param clnt_addr_    Address to bind client to
 * @param srvr_s_       Descriptor of the socket residing on @p srvr
 *                      (accepted socket in the case of stream connection)
 *                      (OUT)
 * @param clnt_s_       Descriptor of the socket residing on @p clnt (OUT)
 * @param buf_size_     Buffer size to be set
 * @param sizes_sum_    Sum of real server send and client receive
 *                      socket buffer sizes (OUT)
 * @param snd_size_     How many bytes will remain to be processed
 *                      after socket buffers will be filled
 *
 * @note sizes_sum_ can be greater than 2 * buf_size because minimal
 *       allowed socket buffer size can be greated than buf_size_ and
 *       also Linux sets real buffer size to doubled requested
 *       one.
 */
#define SOCKBUF_SET_GEN_CONN(srvr_, clnt_, srvr_addr_, clnt_addr_, \
                             srvr_s_, clnt_s_, buf_size_, sizes_sum_, \
                             snd_size_) \
    do {                                                            \
        int srvrbuf_size_ = buf_size_;                              \
        int clntbuf_size_ = buf_size_;                              \
        int tmp_s_;                                                 \
        tmp_s_ = rpc_socket(srvr_,                                  \
                            rpc_socket_domain_by_addr(srvr_addr_),  \
                            RPC_SOCK_STREAM, RPC_PROTO_DEF);        \
        clnt_s_ = rpc_socket(clnt_,                                 \
                             rpc_socket_domain_by_addr(clnt_addr_), \
                             RPC_SOCK_STREAM, RPC_PROTO_DEF);       \
                                                                    \
        rpc_setsockopt(srvr_, tmp_s_, RPC_SO_SNDBUF,                \
                       &srvrbuf_size_);                             \
        rpc_getsockopt(srvr_, tmp_s_, RPC_SO_SNDBUF,                \
                       &srvrbuf_size_);                             \
        /*                                                          \
         * This is done to guarantee that writing function will     \
         * unblock even if it will be awaiked after a peer ends     \
         * to read data from overfilled buffer.                     \
         */                                                         \
        if (clntbuf_size_ * 2 < srvrbuf_size_ + snd_size_)          \
            clntbuf_size_ = (srvrbuf_size_ + snd_size_) / 2 + 1;    \
                                                                    \
        rpc_setsockopt(clnt_, clnt_s_, RPC_SO_RCVBUF,               \
                       &clntbuf_size_);                             \
                                                                    \
        rpc_bind(srvr_, tmp_s_, srvr_addr_);                        \
        rpc_listen(srvr_, tmp_s_, SOCKTS_BACKLOG_DEF);              \
        rpc_bind(clnt_, clnt_s_, clnt_addr_);                       \
        rpc_connect(clnt_, clnt_s_, srvr_addr_);                    \
        srvr_s_ = rpc_accept(srvr_, tmp_s_, NULL, NULL);            \
        rpc_close(srvr_, tmp_s_);                                   \
                                                                    \
        rpc_getsockopt(srvr_, srvr_s_, RPC_SO_SNDBUF,               \
                       &srvrbuf_size_);                             \
        rpc_getsockopt(clnt_, clnt_s_, RPC_SO_RCVBUF,               \
                       &clntbuf_size_);                             \
                                                                    \
        sizes_sum_ = srvrbuf_size_ + clntbuf_size_;                 \
    } while(0)

/**
 * Receive all the data sent to a socket.
 *
 * @param pco_      RPC server
 * @param s_        Socket fd
 * @param received_ Number of received bytes (OUT)
 * @param buf_      Buffer where to place received bytes
 * @param buf_size  Size of buffer
 */
#define RECV_ALL_DATA(pco_, s_, received_, buf_, buf_size_) \
    do {                                                                \
        te_bool readable_ = FALSE;                                      \
                                                                        \
        received_ = 0;                                                  \
        do {                                                            \
            RPC_GET_READABILITY(readable_, pco_, s_, 1000);             \
            if (!readable_)                                             \
                break;                                                  \
            rc = rpc_read(pco_, s_, buf_, buf_size_);                   \
            received_ += rc;                                            \
        } while (TRUE);                                                 \
    } while (0)

/**
 * Set handler for a signal.
 *
 * @param pco         RPC server
 * @param sig         Signal number
 * @param handler     Handler to set
 * @param how         How to set the handler (with help of which
 *                    function or functions)
 * @param restart     Whether interrupted system call should be
 *                    restartable
 * @param old_act     If not @c NULL, previous signal disposition
 *                    will be saved here
 */
extern void tapi_set_sighandler(rcf_rpc_server *pco, rpc_signum sig,
                                const char *handler, const char *how,
                                te_bool restart,
                                rpc_struct_sigaction *old_act);

/**
 * Set action for a signal and check that sigaction() returns the same
 * action for this signal after it.
 *
 * @param pco_                RPC server
 * @param sig_                signal
 * @param new_                signal action to be set
 * @param old_                here to save previous signal action
 * @param cur_                signal action returned by sigaction() after
 *                            setting @p new_ signal action
 * @param is_failed_          will be set to @c TRUE if test is failed
 * @param incorrect_flags_    will be set to @c TRUE if flags were incorrect
 * @param incorrect_mask_     will be set to @c TRUE if mask was incorrect
 * @param incorrect_handler_  will be set to @c TRUE if handler was
 *                            incorrect
 * @param restore_            will be set to @c TRUE if signal action was
 *                            changed and should be restored
 * @param func_sig_           @c "bsd_signal", @c "sysv_signal" or @c
 *                            "sigaction"
 * @param sock_after_         Open socket after sigaction() call
 * @param sock_               oscket descriptor
 */
#define SIGACT_SET_CHECK(pco_, sig_, new_, old_, cur_, is_failed_, \
                         incorrect_flags_, incorrect_mask_, \
                         incorrect_handler_, restore_, func_sig_, \
                         sock_after_, sock_) \
    do {                                                                \
    if (!sock_after_)                                                   \
        sock_ = rpc_socket(pco_, RPC_PF_INET, RPC_SOCK_STREAM,          \
                           RPC_PROTO_DEF);                              \
        if (strcmp(func_sig_, "sigaction") == 0)                        \
            rpc_sigaction(pco_, sig_, &new_, &old_);                    \
        else                                                            \
        {                                                               \
            rpc_sigaction(pco_, sig_, NULL, &old_);                     \
            if (strcmp(func_sig_, "sysv_signal") == 0)                  \
                rpc_sysv_signal(pco_iut, sig_, new_.mm_handler);        \
            else if (strcmp(func_sig_, "bsd_signal") == 0)              \
                rpc_bsd_signal(pco_iut, sig_, new_.mm_handler);         \
            else                                                        \
                TEST_FAIL("Incorred signal action setting function %s", \
                          func_sig_);                                   \
        }                                                               \
        restore_ = TRUE;                                                \
        rpc_sigaction(pco_, sig_, NULL, &cur_);                         \
                                                                        \
        incorrect_flags_ = (cur_.mm_flags != new_.mm_flags);            \
        incorrect_mask_ = (rpc_sigset_cmp(pco_, cur_.mm_mask,           \
                                          new_.mm_mask) != 0);          \
        incorrect_handler_ = (strncmp(cur_.mm_handler,                  \
                                      new_.mm_handler,                  \
                                      RCF_RPC_MAX_FUNC_NAME) != 0);     \
                                                                        \
        if (incorrect_flags_ || incorrect_mask_ || incorrect_handler_)  \
        {                                                               \
            if (incorrect_flags_)                                       \
                ERROR_VERDICT("Returned sigaction structure is "        \
                              "not the same as specified for previous " \
                              "sigaction() call: "                      \
                              "flags are %s instead of %s",             \
                              sigaction_flags_rpc2str(                  \
                                                cur_.mm_flags),         \
                              sigaction_flags_rpc2str(                  \
                                                new_.mm_flags));        \
            if (incorrect_mask_)                                        \
                ERROR_VERDICT("Returned sigaction structure is not "    \
                              "the same as specified for previous "     \
                              "sigaction() call: mask is different");   \
            if (incorrect_handler_)                                     \
                ERROR_VERDICT("Returned sigaction structure is not "    \
                              "the same as specified for previous "     \
                              "sigaction() call: handler is "           \
                              "different");                             \
            if (!(incorrect_flags_ && !incorrect_mask_ &&               \
                  !incorrect_handler_ &&                                \
                  (cur_.mm_flags ==                                     \
                                 (new_.mm_flags | RPC_SA_RESTORER)  ||  \
                   cur_.mm_flags ==                                     \
                                 (new_.mm_flags | RPC_SA_INTERRUPT) ||  \
                   cur_.mm_flags ==                                     \
                                 (new_.mm_flags | RPC_SA_INTERRUPT |    \
                                  RPC_SA_RESTORER))))                   \
                is_failed_ = TRUE;                                      \
        }                                                               \
    if (sock_after_)                                                    \
        sock_ = rpc_socket(pco_, RPC_PF_INET, RPC_SOCK_STREAM,          \
                           RPC_PROTO_DEF);                              \
    } while (0)

/**
 * Create child, destroy it and close socket to destroy Onload stack.
 * 
 * @param rpcs              RPCS server handler
 * @param sock              Socket pointer
 * @param sig_to_send       Signal number
 * @param new_sig_act       Set sigaction context
 * @param current_sig_act   Location to get current sigaction context
 * @param drop_stack        Leave the function without any actions if
 *                          @c FALSE
 */
static inline void
drop_onload_stack(rcf_rpc_server *rpcs, int *sock,
                  rpc_signum sig_to_send, rpc_struct_sigaction *new_sig_act,
                  rpc_struct_sigaction *current_sig_act, te_bool drop_stack)
{
    rcf_rpc_server *pco_iut_child = NULL;

    if (!drop_stack)
        return;

    rpc_sigaction_reinit(rpcs, new_sig_act);
    rpc_sigaction_reinit(rpcs, current_sig_act);

    rpc_sigaction(rpcs, sig_to_send, NULL, new_sig_act);

    rcf_rpc_server_create_process(rpcs, "pco_iut_child", 0,
                                  &pco_iut_child);
    rcf_rpc_server_destroy(pco_iut_child);
    RPC_CLOSE(rpcs, *sock);
    /* Delay is necessary for assurance in the stack destroying. */
    TAPI_WAIT_NETWORK;

    rpc_sigaction(rpcs, sig_to_send, NULL, current_sig_act);

    if (new_sig_act->mm_flags != current_sig_act->mm_flags)
        ERROR_VERDICT("Sigaction flags differs after Onload stack "
                      "destroying: %s instead of %s",
                      sigaction_flags_rpc2str(current_sig_act->mm_flags),
                      sigaction_flags_rpc2str(new_sig_act->mm_flags));
    if (rpc_sigset_cmp(rpcs, new_sig_act->mm_mask,
                       current_sig_act->mm_mask) != 0)
        ERROR_VERDICT("Sigaction mask is different after Onload stack "
                      "destroying");
    if (strcmp(new_sig_act->mm_handler, current_sig_act->mm_handler) != 0)
        ERROR_VERDICT("Sigaction handler is different after Onload "
                      "stack destroying");
}

/**
 * A state structure storing the disposition of @c SIGUSR1 and
 * @c SIGUSR2 to be restored in cleanup.
 */
typedef struct sockts_sig_state {
    rpc_struct_sigaction old_act1; /**< Previous state of @c SIGUSR1 */
    rpc_struct_sigaction old_act2; /**< Previous state of @c SIGUSR2 */
    te_bool restore1; /**< Whether the previous state of @c SIGUSR1
                           should be restored in cleanup */
    te_bool restore2; /**< Whether the previous state of @c SIGUSR2
                           should be restored in cleanup */
} sockts_sig_state;

/** Initializer for sockts_sig_state structure */
#define SOCKTS_SIG_STATE_INIT \
  { .old_act1 = __RPC_STRUCT_SIGACTION_INITIALIZER, \
    .old_act2 = __RPC_STRUCT_SIGACTION_INITIALIZER }

/**
 * A context structure storing common data for signal tests.
 */
typedef struct sockts_sig_ctx {
    /* Input parameters */
    struct {
        const char *func_sig; /**< Tested handler setting function */
        te_bool restart; /**< Whether a system call should be restarted
                              after interruption by a signal */
        te_bool second_signal; /**< If @c TRUE, @c SIGUSR2 is sent and its
                                    handler sends @c SIGUSR1 to the same
                                    process. Otherwise @c SIGUSR1 is sent
                                    directly. */
        te_bool multithread; /**< If @c TRUE, a signal is sent with
                                  pthread_kill() to a thread, otherwise -
                                  with kill() to a process. */
    };

    /* Internal fields */
    struct {
        tarpc_pid_t target_pid; /** PID of the target process */
        tarpc_pthread_t target_tid; /** TID of the target thread */
        tarpc_uid_t target_uid; /**< UID of the target process */

        tarpc_pid_t killer_pid; /** PID of the killer process */
        tarpc_uid_t killer_uid; /** UID of the killer process */

        const char *handler1; /**< Handler set for @c SIGUSR1 */
        const char *handler2; /**< Handler set for @c SIGUSR2 */
    };

    /* Output */
    struct {
        te_bool received; /**< @c TRUE if the signal was received */
        te_bool check_failed; /**< @c TRUE if some check failed and a
                                   verdict was printed */
    };
} sockts_sig_ctx;

/** Initializer for sockts_sig_ctx structure */
#define SOCKTS_SIG_CTX_INIT { .func_sig = NULL }

/**
 * Save current disposition of tested signals so that it can be
 * restored later.
 *
 * @param rpcs        RPC server
 * @param ctx         Pointer to context structure
 * @param state       Pointer to a structure where to save the current
 *                    disposition
 */
extern void sockts_sig_save_state(rcf_rpc_server *rpcs,
                                  sockts_sig_ctx *ctx,
                                  sockts_sig_state *state);

/**
 * Register handlers for @c SIGUSR1 and for @c SIGUSR2 (if two
 * signals are to be tested).
 *
 * @param rpcs      RPC server
 * @param ctx       Pointer to context structure
 * @param vpref     If not @c NULL, will be printed at the beginning of
 *                  verdicts
 */
extern void sockts_sig_register_handlers(rcf_rpc_server *rpcs,
                                         sockts_sig_ctx *ctx,
                                         const char *vpref);


/**
 * Set "SIG_IGN" handlers for @c SIGUSR1 and @c SIGUSR2 (if two signals
 * are checked).
 *
 * @param rpcs      RPC server
 * @param ctx       Pointer to context structure
 * @param vpref     If not @c NULL, will be printed at the beginning of
 *                  verdicts
 */
extern void sockts_sig_set_ignore(rcf_rpc_server *rpcs,
                                  sockts_sig_ctx *ctx,
                                  const char *vpref);

/**
 * Specify RPC server which is expected to receive the signal.
 *
 * @param rpcs        RPC server
 * @param ctx         Pointer to context structure
 */
extern void sockts_sig_set_target(rcf_rpc_server *rpcs,
                                  sockts_sig_ctx *ctx);

/**
 * Send tested signal (@c SIGUSR1 or @c SIGUSR2).
 * This function resets @b received field to @c FALSE in @b ctx.
 *
 * @param rpcs      RPC server on which to call rpc_kill()
 * @param ctx       Pointer to context structure telling which signal to
 *                  send and to which process/thread
 */
extern void sockts_sig_send(rcf_rpc_server *rpcs, sockts_sig_ctx *ctx);

/**
 * Call siginterrupt() for tested signal(s).
 *
 * @param rpcs      RPC server
 * @param ctx       Pointer to context structure
 * @param flag      Value for flag argument of siginterrupt()
 */
extern void sockts_sig_siginterrupt(rcf_rpc_server *rpcs,
                                    sockts_sig_ctx *ctx,
                                    int flag);

/**
 * Check that signal handlers did not change after invoking
 * (unless sysv_signal() was used to set them, in which case
 * they should be reset to default).
 *
 * @param rpcs      RPC server
 * @param ctx       Pointer to context structure
 * @param vpref     If not @c NULL, will be printed at the beginning of
 *                  verdicts
 */
extern void sockts_sig_check_handlers_after_invoke(rcf_rpc_server *rpcs,
                                                   sockts_sig_ctx *ctx,
                                                   const char *vpref);

/**
 * Check whether @c SIGUSR1 was received.
 * If it was received, @b received field in @p ctx is set to @c TRUE
 * and further calls of this function have no effect.
 *
 * @param rpcs      RPC server
 * @param ctx       Pointer to context structure
 */
extern void sockts_sig_check_received(rcf_rpc_server *rpcs,
                                      sockts_sig_ctx *ctx);

/**
 * Check @b sig_pid and @b sig_uid fields of siginfo_t structure
 * when a handler was set with @c SA_SIGINFO flag (using
 * "sigaction_siginfo" function). If it was not set this way,
 * this function has no effect.
 *
 * @param rpcs              RPC server where to get saved siginfo_t
 * @param ctx               Pointer to context structure
 */
extern void sockts_sig_check_siginfo(rcf_rpc_server *rpcs,
                                     sockts_sig_ctx *ctx);

/**
 * Call this function in cleanup to restore original signal handlers.
 *
 * @param rpcs      RPC server
 * @param state     Pointer to state structure storing original
 *                  dispositions for signals
 */
extern void sockts_sig_cleanup(rcf_rpc_server *rpcs, sockts_sig_state *state);

#endif
