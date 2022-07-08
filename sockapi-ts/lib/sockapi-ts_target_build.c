/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief API to compile files on engine/agent
 *
 * API to compile files on engine/agent
 *
 * @author Vasilii Ivanov <swaotet@oktetlabs.ru>
 */

#include "sockapi-ts_target_build.h"

/**
 * Run command on test engine, wait while it finished
 * and print stdout/stderr from it
 *
 * @param cmd              Command line to execute
 *
 * @return                 Status code
 */
static te_errno
sockts_run_cmd(const char *cmd)
{
    pid_t           pid, rc_pid;
    int             fd_out = -1;
    int             fd_err = -1;
    char            buf_out[COMMON_CMD_BUF_SIZE] = {0};
    char            buf_err[COMMON_CMD_BUF_SIZE] = {0};
    int             status;
    ssize_t         bytes;
    te_errno        rc = 0;

    if ((pid = te_shell_cmd(cmd, -1, NULL, &fd_out, &fd_err)) < 0)
    {
        ERROR("%s() failed to run: %s", __FUNCTION__, cmd);
        return pid;
    }
    rc_pid = waitpid(pid, &status, 0);
    if (rc_pid != 0 && rc_pid != pid)
    {
        ERROR("%s() waitpid() returned unexpected result: %d",
              __FUNCTION__, rc_pid);
        return rc_pid;
    }
    if (!WIFEXITED(status))
    {
        ERROR("%s() program with pid %u was not exited normally",
              __FUNCTION__, pid);
        rc = -1;
        goto cleanup;
    }
    if (WEXITSTATUS(status) != 0)
    {
        ERROR("%s() program with pid %u returned unexpected exit code %d",
              __FUNCTION__, pid, WEXITSTATUS(status));
        rc = WEXITSTATUS(status);
        goto cleanup;
    }
    if ((bytes = read(fd_out, buf_out, sizeof(buf_out) - 1) < 0))
    {
        WARN("%s() read(stdout) returned unexpected errno %d",
             __FUNCTION__, errno);
    }
    else
    {
        if (WEXITSTATUS(status) == 0)
            RING("stdout: %s", buf_out);
        else
            WARN("stdout: %s", buf_out);
    }
    if ((bytes = read(fd_err, buf_err, sizeof(buf_err) - 1) < 0))
    {
        WARN("%s() read(stderr) returned unexpected errno %d",
             __FUNCTION__, errno);
    }
    else
    {
        if (WEXITSTATUS(status) == 0)
            RING("stderr: %s", buf_err);
        else
            WARN("stderr: %s", buf_err);
    }

cleanup:
    close(fd_out);
    close(fd_err);
    return rc;
}

/**
 * Run command on specified agent, wait while command will be finished
 * and print stdout/stderr from it
 *
 * @param rpcs             RPC server
 * @param cmd              Command line to execute
 * @param wait_timeout     How much to wait for the command to finish,
 *                         in milliseconds. Set 0 to use default RPC timeout.
 *
 * @return                 Status code
 */
static te_errno
sockts_run_rpcs_cmd(rcf_rpc_server *rpcs, const char *cmd,
                    uint32_t wait_timeout)
{
    tarpc_pid_t     pid;
    int             fd_out = -1;
    int             fd_err = -1;
    char            buf_out[COMMON_CMD_BUF_SIZE] = {0};
    char            buf_err[COMMON_CMD_BUF_SIZE] = {0};
    int             bytes;
    rpc_wait_status status;
    te_errno        rc = 0;

    if ((pid = rpc_te_shell_cmd(rpcs, cmd, -1, NULL, &fd_out, &fd_err)) < 0)
    {
        ERROR("%s() failed to run: %s", __FUNCTION__, cmd);
        return pid;
    }

    if (wait_timeout != 0)
        rpcs->timeout = wait_timeout;
    RPC_AWAIT_IUT_ERROR(rpcs);
    rc = rpc_waitpid(rpcs, pid, &status, 0);
    if (rc < 0)
    {
        ERROR("%s() waitpid() failed with errno %s",
              __FUNCTION__, errno_rpc2str(RPC_ERRNO(rpcs)));
        goto cleanup;
    }
    switch (status.flag)
    {
        case RPC_WAIT_STATUS_EXITED:
            rc = status.value;
            break;

        default:
            ERROR("%s() waitpid() returned unexpected status %s",
                  __FUNCTION__, wait_status_flag_rpc2str(status.flag));
            rc = TE_RC(TE_RPC, status.flag);
            goto cleanup;
    }

    if ((bytes = rpc_read(rpcs, fd_out, buf_out, sizeof(buf_out))) > 0)
    {
        if (status.value == 0)
            RING("stdout: %s", buf_out);
        else
            WARN("stdout: %s", buf_out);
    }

    if ((bytes = rpc_read(rpcs, fd_err, buf_err, sizeof(buf_err))) > 0)
    {
        if (status.value == 0)
            RING("stderr: %s", buf_err);
        else
            WARN("stderr: %s", buf_err);
    }


cleanup:
    rpc_close(rpcs, fd_out);
    rpc_close(rpcs, fd_err);
    return rc;
}

/* See description in sockapi-ts_target_build.h */
te_errno
sockts_build_dir(rcf_rpc_server *pco, const char *src_dir,
                 const char *dst_dir, te_bool build_on_engine)
{
    int             ret = 0;
    te_string       dst = TE_STRING_INIT;
    te_string       cmd = TE_STRING_INIT;
    te_string       src_full = TE_STRING_INIT;

    if (build_on_engine)
    {
        CHECK_ERRNO_RET((ret = te_string_append(&cmd, "make -C %s", src_dir)));
        CHECK_ERRNO_RET((ret = sockts_run_cmd(cmd.ptr)));

        te_string_reset(&cmd);
        CHECK_ERRNO_RET((ret = te_string_append(&cmd, "cd %s && tar -cvzf %s "
                                                "--exclude=%s *.o",
                                                src_dir, SOCKTS_TMP_TGZ_NAME,
                                                SOCKTS_TMP_TGZ_NAME)));
        CHECK_ERRNO_RET(sockts_run_cmd(cmd.ptr));
    }
    else
    {
        CHECK_ERRNO_RET((ret = te_string_append(&cmd, "cd %s && tar -cvzf %s "
                                                "--exclude=%s *",
                                                src_dir, SOCKTS_TMP_TGZ_NAME,
                                                SOCKTS_TMP_TGZ_NAME)));
        CHECK_ERRNO_RET((ret = sockts_run_cmd(cmd.ptr)));
    }

    CHECK_ERRNO_RET((ret = te_string_append(&src_full, "%s/%s", src_dir,
                                            SOCKTS_TMP_TGZ_NAME)));
    CHECK_ERRNO_RET((ret = te_string_append(&dst, "%s/%s", dst_dir,
                                            SOCKTS_TMP_TGZ_NAME)));
    CHECK_ERRNO_RET((ret = rcf_ta_put_file(pco->ta, 0, src_full.ptr, dst.ptr)));

    te_string_reset(&cmd);
    CHECK_ERRNO_RET((ret = te_string_append(&cmd, "tar -C %s -xvzf %s",
                                            dst_dir, dst.ptr)));
    CHECK_ERRNO_RET((ret = sockts_run_rpcs_cmd(pco, cmd.ptr, 0)));
    if (!build_on_engine)
    {
        te_string_reset(&cmd);
        CHECK_ERRNO_RET((ret = te_string_append(&cmd, "make -C %s", dst_dir)));
        CHECK_ERRNO_RET((ret = sockts_run_rpcs_cmd(pco,
                                                   cmd.ptr, TE_SEC2MS(300))));
    }

cleanup:
    te_string_free(&cmd);
    te_string_free(&dst);
    te_string_free(&src_full);
    return ret;
}

/* See description in sockapi-ts_target_build.h */
te_errno
sockts_cleanup_build(const char *src_dir, te_bool build_on_engine)
{
    int             ret = 0;
    te_string       cmd = TE_STRING_INIT;

    if (build_on_engine)
    {
        CHECK_ERRNO_RET((ret = te_string_append(&cmd, "cd %s && make clean",
                                                src_dir)));
        CHECK_ERRNO_RET((ret = sockts_run_cmd(cmd.ptr)));
        te_string_free(&cmd);
    }

    te_string_reset(&cmd);
    if (src_dir != NULL)
    {
        CHECK_ERRNO_RET((ret = te_string_append(&cmd,
                                                "test -f %s/%s && rm %s/%s",
                                                src_dir, SOCKTS_TMP_TGZ_NAME,
                                                src_dir, SOCKTS_TMP_TGZ_NAME)));
        CHECK_ERRNO_RET((ret = sockts_run_cmd(cmd.ptr)));
    }

cleanup:
    te_string_free(&cmd);
    return ret;
}
