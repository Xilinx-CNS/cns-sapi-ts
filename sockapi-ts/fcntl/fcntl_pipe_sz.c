/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * IOCTL Requests
 *
 * $Id$
 */

/** @page fcntl-fcntl_pipe_sz Usage of F_SETPIPE_SZ and F_GETPIPE_SZ requests on pipes
 *
 * @objective Check that @c F_SETPIPE_SZ and @c F_GETPIPE_SZ requests
 *            correctly change and report pipe capacity
 *
 * @type conformance
 *
 * @reference @ref WBS-PD, @ref STEVENS, @ref XNS5
 *
 * @par Scenario:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "fcntl/fcntl_pipe_sz"

#include "sockapi-test.h"

#define BUFF_SIZE     1024
#define PKT_BUFF_SIZE 2000

#define SET_CHECK_PIPE_SIZE(_pco, _pipe_fd, _size, _overfill_fd,          \
                            _read_fd, _init_size)                         \
do {                                                                      \
    int         old_size;                                                 \
    int         size;                                                     \
    int         new_size = 0;                                             \
    uint64_t    bytes = 0;                                                \
                                                                          \
    old_size = rpc_fcntl(_pco, _pipe_fd, RPC_F_GETPIPE_SZ);               \
    new_size = old_size;                                                  \
    if (_init_size != 0 && old_size != _init_size)                        \
    {                                                                     \
        if (old_size > _init_size && old_size <                           \
            _init_size + PKT_BUFF_SIZE * 2)                               \
            RING_VERDICT("Pipe size is a little bit bigger then "         \
                         "EF_PIPE_SIZE value");                           \
        else                                                              \
            TEST_VERDICT("Incorrect pipe size");                          \
    }                                                                     \
    if (strcmp(_size, "unchanged") != 0)                                  \
    {                                                                     \
        if (strcmp(_size, "reduce") == 0)                                 \
            new_size = old_size / 2;                                      \
        else if (strcmp(_size, "increase") == 0)                          \
            new_size = old_size * 2;                                      \
        else                                                              \
            TEST_FAIL("Incorrect pipe size");                             \
        if (pipe_data_len > new_size)                                     \
            RPC_AWAIT_IUT_ERROR(pco_iut);                                 \
        rc = rpc_fcntl(_pco, _pipe_fd, RPC_F_SETPIPE_SZ, new_size);       \
        size = rpc_fcntl(_pco, _pipe_fd, RPC_F_GETPIPE_SZ);               \
        if (pipe_data_len > new_size)                                     \
        {                                                                 \
            if (rc != -1)                                                 \
                TEST_VERDICT("fcntl(F_SETPIPE_SZ) with size less than "   \
                             "amount of data in pipe returned %d", rc);   \
            CHECK_RPC_ERRNO(pco_iut, RPC_EBUSY,                           \
                            "fcntl(F_SETPIPE_SZ) returned -1");           \
            new_size = size;                                              \
        }                                                                 \
        if (size < new_size || new_size + 4096 < size)                    \
        {                                                                 \
            RING_VERDICT("Incorrect pipe size was set");                  \
        }                                                                 \
        new_size = size;                                                  \
    }                                                                     \
    if (_overfill_fd != -1)                                               \
    {                                                                     \
        rpc_overfill_fd(_pco, _overfill_fd, &bytes);                      \
        pipe_data_len += bytes;                                           \
        if (pipe_data_len != new_size)                                    \
        {                                                                 \
            if (pipe_data_len > new_size)                                 \
            {                                                             \
                if (pipe_data_len < PKT_BUFF_SIZE + new_size &&           \
                    !report_big)                                          \
                {                                                         \
                    RING_VERDICT("Amount of data in the pipe is a "       \
                                 "little bit bigger then pipe size");     \
                    report_big = TRUE;                                    \
                }                                                         \
                if (pipe_data_len >= PKT_BUFF_SIZE + new_size)            \
                    TEST_VERDICT("Amount of data in the pipe is much "    \
                                 "bigger then pipe size");                \
            }                                                             \
            else                                                          \
            {                                                             \
                if (pipe_data_len > 0.8 * new_size && !report_small)      \
                {                                                         \
                    RING_VERDICT("Amount of data in the pipe is a "       \
                                 "little bit smaller then pipe size");    \
                    report_small = TRUE;                                  \
                }                                                         \
                if (pipe_data_len < 0.8 * new_size)                       \
                    TEST_VERDICT("Amount of data in the pipe is much "    \
                                 "smaller then pipe size");               \
            }                                                             \
        }                                                                 \
    }                                                                     \
    if (_read_fd != -1)                                                   \
    {                                                                     \
        while (pipe_data_len != 0)                                        \
        {                                                                 \
            rc = rpc_read(_pco, _read_fd,                                 \
                          buffer,                                         \
                          (pipe_data_len > BUFF_SIZE) ?                   \
                            BUFF_SIZE : pipe_data_len);                   \
            pipe_data_len -= rc;                                          \
        }                                                                 \
        RPC_CHECK_READABILITY(_pco, _read_fd, FALSE);                     \
    }                                                                     \
} while(0);

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    int             fds[2] = { -1, -1};

    char            buffer[BUFF_SIZE];

    const char     *new_ef_pipe_size = FALSE;
    char           *old_pipe_size = NULL;
    cfg_handle      ef_pipe_size_h = CFG_HANDLE_INVALID;
    const char     *fcntl_size1 = 0;
    const char     *fcntl_size2 = 0;
    int             check_size = 0;
    te_bool         check_read_end1 = FALSE;
    te_bool         check_read_end2 = FALSE;
    te_bool         overfill_before = FALSE;
    te_bool         read_before = FALSE;
    te_bool         overfill_after = FALSE;
    te_bool         read_after = FALSE;

    int     pipe_data_len = 0;
    te_bool report_big = FALSE;
    te_bool report_small = FALSE;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(new_ef_pipe_size);
    TEST_GET_STRING_PARAM(fcntl_size1);
    TEST_GET_STRING_PARAM(fcntl_size2);
    TEST_GET_BOOL_PARAM(check_read_end1);
    TEST_GET_BOOL_PARAM(check_read_end2);
    TEST_GET_BOOL_PARAM(overfill_before);
    TEST_GET_BOOL_PARAM(read_before);
    TEST_GET_BOOL_PARAM(overfill_after);
    TEST_GET_BOOL_PARAM(read_after);

    if (strcmp(new_ef_pipe_size, "0") != 0)
    {
        ef_pipe_size_h = sockts_set_env_gen(pco_iut, "EF_PIPE_SIZE",
                                            new_ef_pipe_size,
                                            &old_pipe_size, TRUE);
        check_size = atoi(new_ef_pipe_size);
    }
    rpc_pipe(pco_iut, fds);

    SET_CHECK_PIPE_SIZE(pco_iut, fds[0], "unchanged",
                        overfill_before ? fds[1] : -1,
                        read_before ? fds[0] : -1, check_size);

    SET_CHECK_PIPE_SIZE(pco_iut,
                        check_read_end1 ? fds[0] : fds[1],
                        fcntl_size1,
                        overfill_after ? fds[1] : -1,
                        read_after ? fds[0] : -1, 0);

    SET_CHECK_PIPE_SIZE(pco_iut,
                        check_read_end2 ? fds[0] : fds[1],
                        fcntl_size2, fds[1], fds[0], 0);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, fds[0]);
    CLEANUP_RPC_CLOSE(pco_iut, fds[1]);
    CLEANUP_CHECK_RC(sockts_restore_env_gen(pco_iut, ef_pipe_size_h,
                                            old_pipe_size, TRUE));

    TEST_END;
}
