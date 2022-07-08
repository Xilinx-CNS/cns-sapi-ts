/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * IOCTL Requests
 *
 * $Id$
 */

/** @page fcntl-fcntl_pipe_sz_many Usage of F_SETPIPE_SZ and F_GETPIPE_SZ requests on many pipes
 *
 * @objective Check that @c F_SETPIPE_SZ and @c F_GETPIPE_SZ requests
 *            correctly change and report pipe capacity for application
 *            with many pipes
 *
 * @type conformance
 *
 * @reference @ref WBS-PD, @ref STEVENS, @ref XNS5
 *
 * @par Scenario:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "fcntl/fcntl_pipe_sz_many"

#include "sockapi-test.h"

#define BUFF_SIZE 10240
#define MAX_PIPES 100

#define SET_CHECK_PIPE_OVERFILL(_pco, _pipe_fd, _size, _overfill_fd,  \
                                _bytes)                               \
do {                                                                  \
    int         got_size;                                             \
                                                                      \
    got_size = rpc_fcntl(_pco, _pipe_fd, RPC_F_GETPIPE_SZ);           \
    if (got_size != _size)                                            \
        TEST_VERDICT("Incorrect pipe size");                          \
    rpc_overfill_fd(_pco, _overfill_fd, &_bytes);                     \
    if ((int)_bytes != got_size)                                      \
    {                                                                 \
        if ((int)_bytes > got_size)                                   \
        {                                                             \
            if ((int)_bytes < 1.5 * got_size && !report_big)          \
            {                                                         \
                RING_VERDICT("Amount of data in the pipe is a "       \
                             "little bit bigger then pipe size");     \
                report_big = TRUE;                                    \
            }                                                         \
            if ((int)_bytes >= 1.5 * got_size)                        \
                TEST_VERDICT("Amount of data in the pipe is much "    \
                             "bigger then pipe size");                \
        }                                                             \
        else                                                          \
        {                                                             \
            if ((int)_bytes > 0.8 * got_size && !report_small)        \
            {                                                         \
                RING_VERDICT("Amount of data in the pipe is a "       \
                             "little bit smaller then pipe size");    \
                report_small = TRUE;                                  \
            }                                                         \
            if ((int)_bytes < 0.8 * got_size)                         \
                TEST_VERDICT("Amount of data in the pipe is much "    \
                             "smaller then pipe size");               \
        }                                                             \
    }                                                                 \
} while(0);

#define SET_CHECK_PIPE_SIZE(_pco, _pipe_fd, _size, _read_fd, _bytes)     \
do {                                                                     \
    int         got_size;                                                \
                                                                         \
    got_size = rpc_fcntl(_pco, _pipe_fd, RPC_F_GETPIPE_SZ);              \
    if (_size != got_size)                                               \
        TEST_VERDICT("Incorrect pipe size");                             \
    while (_bytes != 0)                                                  \
    {                                                                    \
        rc = rpc_read(_pco, _read_fd,                                    \
                      buffer,                                            \
                      (_bytes > BUFF_SIZE) ?                             \
                        BUFF_SIZE : _bytes);                             \
        _bytes -= rc;                                                    \
    }                                                                    \
    RPC_CHECK_READABILITY(_pco, _read_fd, FALSE);                        \
} while(0);

/**
 * Set F_SETPIPE_SZ for a pipe fd. If fcntl() reports
 * EINVAL, try to use values closer to initial one.
 *
 * @param rpcs        RPC server handle.
 * @param pipe_fd     Pipe descriptor.
 * @param init_size   Initial pipe capacity.
 * @param set_size    Pipe capacity to set.
 */
static void
set_pipe_size(rcf_rpc_server *rpcs, int pipe_fd,
              int init_size, int set_size)
{
    int rc;

    do {
        RPC_AWAIT_ERROR(rpcs);
        rc = rpc_fcntl(rpcs, pipe_fd, RPC_F_SETPIPE_SZ, set_size);
        if (rc < 0)
        {
            if (RPC_ERRNO(rpcs) == RPC_EINVAL)
            {
                if (set_size == init_size)
                {
                    TEST_VERDICT("Cannot set F_SETPIPE_SZ even to "
                                 "its initial value");
                }
                else
                {
                    int new_set_size;

                    new_set_size = set_size - (set_size - init_size) / 2;

                    if (new_set_size == set_size)
                        set_size = init_size;
                    else
                        set_size = new_set_size;
                }
            }
            else
            {
                TEST_VERDICT("fcntl(F_SETPIPE_SZ) failed with "
                             "unexpected errno %r", RPC_ERRNO(rpcs));
            }
        }
        else
        {
            break;
        }
    } while (1);
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    int             fds[MAX_PIPES][2];
    int             pipe_size[MAX_PIPES];
    int             pipe_bytes[MAX_PIPES];
    int             init_size = 0;

    te_bool         report_big = FALSE;
    te_bool         report_small = FALSE;

    char            buffer[BUFF_SIZE];

    const char     *new_ef_pipe_size = FALSE;
    char           *old_pipe_size = NULL;
    cfg_handle      ef_pipe_size_h = CFG_HANDLE_INVALID;
    int             pipe_num = 0;
    te_bool         diff_stacks = FALSE;
    uint64_t        bytes = 0;

    int i;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(new_ef_pipe_size);
    TEST_GET_INT_PARAM(pipe_num);
    TEST_GET_BOOL_PARAM(diff_stacks);

    if (strcmp(new_ef_pipe_size, "0") != 0)
        ef_pipe_size_h = sockts_set_env_gen(pco_iut, "EF_PIPE_SIZE",
                                            new_ef_pipe_size,
                                            &old_pipe_size, TRUE);

    for (i = 0; i < MAX_PIPES; i++)
        fds[i][0] = fds[i][1] = -1;

    for (i = 0; i < pipe_num / 2; i++)
        rpc_pipe(pco_iut, fds[i]);

    TEST_STEP("Change stack according to @p diff_stacks parameter");
    if (diff_stacks)
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, "test1");

    for (i = pipe_num / 2; i < pipe_num; i++)
        rpc_pipe(pco_iut, fds[i]);

    init_size = rpc_fcntl(pco_iut, fds[0][0], RPC_F_GETPIPE_SZ);

    for (i = 0; i < pipe_num; i++)
    {
        pipe_size[i] = rand_range(init_size / 4, 4 * init_size);
        set_pipe_size(pco_iut, fds[i][i % 2], init_size, pipe_size[i]);
        pipe_size[i] = rpc_fcntl(pco_iut, fds[i][i % 2],
                                 RPC_F_GETPIPE_SZ);
    }

    for (i = 0; i < pipe_num; i++)
    {
        SET_CHECK_PIPE_OVERFILL(pco_iut, fds[i][i % 2], pipe_size[i],
                                fds[i][1], bytes);
        pipe_bytes[i] = (int)bytes;
    }

    for (i = 0; i < pipe_num; i++)
        SET_CHECK_PIPE_SIZE(pco_iut, fds[i][(i + 1) % 2], pipe_size[i],
                            fds[i][0], pipe_bytes[i]);

    TEST_SUCCESS;

cleanup:
    for (i = 0; i < pipe_num; i++)
    {
        CLEANUP_RPC_CLOSE(pco_iut, fds[i][0]);
        CLEANUP_RPC_CLOSE(pco_iut, fds[i][1]);
    }
    CLEANUP_CHECK_RC(sockts_restore_env_gen(pco_iut, ef_pipe_size_h,
                                            old_pipe_size, TRUE));

    TEST_END;
}
