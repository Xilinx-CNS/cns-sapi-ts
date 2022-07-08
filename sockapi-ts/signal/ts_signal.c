/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Signal-related helpers
 *
 * Implementation of signal-related helpers
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#include "ts_signal.h"

/**
 * Set handler for a signal.
 *
 * @param rpcs        RPC server
 * @param sig         Signal number
 * @param handler     Handler to set
 * @param func_sig    Function to use for setting the handler
 * @param restart     Whether interrupted system call should be
 *                    restartable
 * @param old_act     If not @c NULL, previous signal disposition
 *                    will be saved here
 * @param ctx         Pointer to sockts_sig_ctx structure; if not
 *                    @c NULL, error state may be set here if
 *                    a problem occurs
 * @param vpref       If not @c NULL, will be printed at the beginning
 *                    of verdicts
 */
static void
set_sighandler(rcf_rpc_server *rpcs, rpc_signum sig,
               const char *handler, const char *func_sig,
               te_bool restart, rpc_struct_sigaction *old_act,
               sockts_sig_ctx *ctx, const char *vpref)
{
    te_string prefix = TE_STRING_INIT;

    CHECK_RC(te_string_append(&prefix, ""));
    if (vpref != NULL)
        CHECK_RC(te_string_append(&prefix, "%s: ", vpref));

    if (old_act != NULL)
        rpc_sigaction_reinit(rpcs, old_act);

    if (strcmp(func_sig, "sigaction") == 0 ||
        strcmp(func_sig, "sigaction_siginfo") == 0)
    {
        DEFINE_RPC_STRUCT_SIGACTION(sig_act);

        if (old_act != NULL)
            sig_act = *old_act;
        else
            sig_act.mm_mask = rpc_sigset_new(rpcs);

        if (strcmp(func_sig, "sigaction_siginfo") == 0)
            sig_act.mm_flags |= RPC_SA_SIGINFO;

        strcpy(sig_act.mm_handler, handler);

        if (restart)
            sig_act.mm_flags |= RPC_SA_RESTART;
        else
            sig_act.mm_flags &= ~RPC_SA_RESTART;

        rpc_sigaction(rpcs, sig, &sig_act, old_act);

        if (old_act == NULL)
            rpc_sigaction_release(rpcs, &sig_act);
    }
    else
    {
        const char *exp_handler;
        char *old_handler;
        rpc_struct_sigaction *p_act = NULL;
        DEFINE_RPC_STRUCT_SIGACTION(act_aux);

        if (old_act != NULL)
            p_act = old_act;
        else
            p_act = &act_aux;

        rpc_sigaction(rpcs, sig, NULL, p_act);
        exp_handler = p_act->mm_handler;

        if (strcmp_start("bsd_signal", func_sig) == 0)
        {
            if (strcmp(func_sig, "bsd_signal_pre_siginterrupt") == 0)
                rpc_siginterrupt(rpcs, sig, !restart);

            old_handler = rpc_bsd_signal(rpcs, sig, handler);

            if (strcmp(func_sig, "bsd_signal_post_siginterrupt") == 0)
                rpc_siginterrupt(rpcs, sig, !restart);
        }
        else if (strcmp_start("signal", func_sig) == 0)
        {
            if (strcmp(func_sig, "signal_pre_siginterrupt") == 0)
                rpc_siginterrupt(rpcs, sig, !restart);

            old_handler = rpc_signal(rpcs, sig, handler);

            if (strcmp(func_sig, "signal_post_siginterrupt") == 0)
                rpc_siginterrupt(rpcs, sig, !restart);
        }
        else if (strcmp(func_sig, "sysv_signal") == 0)
        {
            old_handler = rpc_sysv_signal(rpcs, sig, handler);
        }
        else if (strcmp(func_sig, "__sysv_signal") == 0)
        {
            old_handler = rpc___sysv_signal(rpcs, sig, handler);
        }
        else
        {
            TEST_FAIL("Incorrect signal action setting function %s",
                      func_sig);
        }

        if (old_handler == NULL)
        {
            ERROR_VERDICT("%sNULL previous handler was reported when "
                          "setting a new one for %s", prefix.ptr,
                          signum_rpc2str(sig));

            if (ctx != NULL)
                ctx->check_failed = TRUE;
        }
        else if (strcmp(old_handler, exp_handler) != 0)
        {
            ERROR_VERDICT("%sUnexpected previous handler was reported when "
                          "setting a new one for %s", prefix.ptr,
                          signum_rpc2str(sig));

            if (ctx != NULL)
                ctx->check_failed = TRUE;
        }
        free(old_handler);
    }

    te_string_free(&prefix);
}

/* See description in ts_signal.h */
void
tapi_set_sighandler(rcf_rpc_server *pco, rpc_signum sig,
                    const char *handler, const char *how,
                    te_bool restart, rpc_struct_sigaction *old_act)
{
    set_sighandler(pco, sig, handler, how, restart, old_act,
                   NULL, NULL);
}

/* See description in ts_signal.h */
void
sockts_sig_save_state(rcf_rpc_server *rpcs,
                      sockts_sig_ctx *ctx,
                      sockts_sig_state *state)
{
    rpc_sigaction_reinit(rpcs, &state->old_act1);
    rpc_sigaction(rpcs, RPC_SIGUSR1, NULL, &state->old_act1);
    state->restore1 = TRUE;

    if (ctx->second_signal)
    {
        rpc_sigaction_reinit(rpcs, &state->old_act2);
        rpc_sigaction(rpcs, RPC_SIGUSR2, NULL, &state->old_act2);
        state->restore2 = TRUE;
    }
}

/* See description in ts_signal.h */
void
sockts_sig_register_handlers(rcf_rpc_server *rpcs,
                             sockts_sig_ctx *ctx,
                             const char *vpref)
{
    te_bool restart1 = ctx->restart;

    if (ctx->second_signal)
    {
        /*
         * Here a handler for SIGUSR2 is registered which will
         * send SIGUSR1 to the same process.
         *
         * We set restart behaviour in the opposite way for
         * SIGUSR1 to check that restart setting for SIGUSR2
         * has priority in such case.
         */

        restart1 = !ctx->restart;
        ctx->handler2 = "sighandler_sigusr";

        set_sighandler(
                    rpcs, RPC_SIGUSR2, ctx->handler2,
                    ctx->func_sig, ctx->restart, NULL,
                    ctx, vpref);
    }

    if (strcmp(ctx->func_sig, "sigaction_siginfo") == 0)
        ctx->handler1 = "sighandler_createfile_siginfo";
    else
        ctx->handler1 = "sighandler_createfile";

    rpc_sighandler_createfile_cleanup(rpcs, RPC_SIGUSR1);
    set_sighandler(rpcs, RPC_SIGUSR1, ctx->handler1,
                   ctx->func_sig, restart1, NULL, ctx, vpref);
}

/* See description in ts_signal.h */
void
sockts_sig_set_ignore(rcf_rpc_server *rpcs, sockts_sig_ctx *ctx,
                      const char *vpref)
{
    if (ctx->second_signal)
    {
        set_sighandler(rpcs, RPC_SIGUSR2, "SIG_IGN",
                       ctx->func_sig, FALSE, NULL, ctx, vpref);
    }

    set_sighandler(rpcs, RPC_SIGUSR1, "SIG_IGN",
                   ctx->func_sig, FALSE, NULL, ctx, vpref);
}

/* See description in ts_signal.h */
void
sockts_sig_set_target(rcf_rpc_server *rpcs, sockts_sig_ctx *ctx)
{
    ctx->target_pid = rpc_getpid(rpcs);
    ctx->target_tid = rpc_pthread_self(rpcs);
    ctx->target_uid = rpc_getuid(rpcs);
}

/* See description in ts_signal.h */
void
sockts_sig_send(rcf_rpc_server *rpcs, sockts_sig_ctx *ctx)
{
    int signal = (ctx->second_signal ? RPC_SIGUSR2 : RPC_SIGUSR1);

    ctx->killer_pid = rpc_getpid(rpcs);
    ctx->killer_uid = rpc_getuid(rpcs);
    ctx->received = FALSE;

    if (ctx->multithread)
        rpc_pthread_kill(rpcs, ctx->target_tid, signal);
    else
        rpc_kill(rpcs, ctx->target_pid, signal);
}

/* See description in ts_signal.h */
void
sockts_sig_siginterrupt(rcf_rpc_server *rpcs,
                        sockts_sig_ctx *ctx,
                        int flag)
{
    rpc_siginterrupt(rpcs, RPC_SIGUSR1, flag);
    if (ctx->second_signal)
        rpc_siginterrupt(rpcs, RPC_SIGUSR2, flag);
}

/**
 * Check that signal handler did not change after invoking
 * (unless sysv_signal() was used to set it, in which case
 * it should be reset to default).
 *
 * @param rpcs          RPC server
 * @param ctx           Pointer to context structure
 * @param sig           Signal number
 * @param set_handler   Signal handler which was set before
 * @param vpref         If not @c NULL, will be printed at the beginning of
 *                      verdicts
 */
static void
check_sig_handler_after_invoke(rcf_rpc_server *rpcs,
                               sockts_sig_ctx *ctx,
                               int sig,
                               const char *set_handler,
                               const char *vpref)
{
    const char *exp_handler;
    const char *problem;

    DEFINE_RPC_STRUCT_SIGACTION(cur_sig_act);

    if (set_handler == NULL)
        return;

    /**
     * Handler set with sysv_signal() is reset to default after
     * it is invoked.
     */
    if (strcmp(ctx->func_sig, "sysv_signal") == 0 ||
        strcmp(ctx->func_sig, "__sysv_signal") == 0)
        exp_handler = "SIG_DFL";
    else
        exp_handler = set_handler;

    rpc_sigaction(rpcs, sig, NULL, &cur_sig_act);
    if (strcmp(cur_sig_act.mm_handler, exp_handler) != 0)
    {
        if (strcmp(cur_sig_act.mm_handler, "SIG_DFL") == 0)
            problem = "reset to default";
        else if (strcmp(cur_sig_act.mm_handler, set_handler) == 0)
            problem = "not reset to default";
        else
            problem = "unknown";

        ERROR_VERDICT(
              "%s sigaction() unexpectedly reports %s handler for %s",
              vpref, problem, signum_rpc2str(sig));
        ctx->check_failed = TRUE;
    }
}

/* See description in ts_signal.h */
void
sockts_sig_check_handlers_after_invoke(rcf_rpc_server *rpcs,
                                       sockts_sig_ctx *ctx,
                                       const char *vpref)
{
    const char *prefix = (vpref == NULL ? "After processing a signal" :
                                          vpref);

    check_sig_handler_after_invoke(rpcs, ctx, RPC_SIGUSR1,
                                   ctx->handler1, prefix);
    if (ctx->second_signal)
    {
        check_sig_handler_after_invoke(rpcs, ctx, RPC_SIGUSR2,
                                       ctx->handler2, prefix);
    }
}

/* See description in ts_signal.h */
void
sockts_sig_check_received(rcf_rpc_server *rpcs,
                          sockts_sig_ctx *ctx)
{
    if (!ctx->received)
    {
        ctx->received = rpc_thrd_sighnd_crtfile_exists_unlink(
                                                      rpcs,
                                                      RPC_SIGUSR1,
                                                      ctx->target_pid,
                                                      ctx->target_tid);
    }
}

/* See description in ts_signal.h */
void
sockts_sig_check_siginfo(rcf_rpc_server *rpcs, sockts_sig_ctx *ctx)
{
    tarpc_pid_t pid;
    tarpc_uid_t uid;
    tarpc_siginfo_t siginfo;

    if (strcmp(ctx->func_sig, "sigaction_siginfo") == 0)
    {
        if (ctx->second_signal)
        {
            /*
             * SIGUSR1 signal is sent from signal handler of
             * SIGUSR2 signal, so PID and UID in siginfo_t structure
             * should match the process which receives SIGUSR2,
             * not the process which sends it.
             */
            pid = ctx->target_pid;
            uid = ctx->target_uid;
        }
        else
        {
            pid = ctx->killer_pid;
            uid = ctx->killer_uid;
        }

        rpc_siginfo_received(rpcs, &siginfo);
        if (siginfo.sig_pid != pid || siginfo.sig_uid != uid)
        {
            ERROR("Expected sig_pid=%d,sig_uid=%u, obtained sig_pid=%d,"
                  "sig_uid=%u", (int)pid, (unsigned int)uid,
                  (int)(siginfo.sig_pid), (unsigned int)(siginfo.sig_uid));
            ERROR_VERDICT("siginfo_t structure contains incorrect "
                          "sig_pid or sig_uid");
            ctx->check_failed = TRUE;
        }
    }
}

/**
 * Restore initial disposition of a signal.
 *
 * @param rpcs        RPC server
 * @param sig         Signal number
 * @param old_act     Signal disposition to restore
 */
static void
sig_handler_cleanup(rcf_rpc_server *rpcs, int sig,
                    rpc_struct_sigaction *old_act)
{
    /*
     * siginterrupt() is called here to ensure that state is indeed
     * reset to default after checking functions like
     * "bsd_signal_post_siginterrupt". If this is not done,
     * and we firstly run an iteration doing
     *
     * bsd_signal(SIGUSR1, ...);
     * siginterrupt(SIGUSR1, 1);
     *
     * and the next iteration checks calling only bsd_signal(),
     * it will see that default behaviour of bsd_signal() is overwritten
     * unexpectedly and interrupted system call is not restarted.
     */
    rpc_siginterrupt(rpcs, sig, 0);

    rpc_sigaction(rpcs, sig, old_act, NULL);
    rpc_sigaction_release(rpcs, old_act);
}

/* See description in ts_signal.h */
void
sockts_sig_cleanup(rcf_rpc_server *rpcs, sockts_sig_state *state)
{
    if (state->restore1)
        sig_handler_cleanup(rpcs, RPC_SIGUSR1, &state->old_act1);

    if (state->restore2)
        sig_handler_cleanup(rpcs, RPC_SIGUSR2, &state->old_act2);
}
