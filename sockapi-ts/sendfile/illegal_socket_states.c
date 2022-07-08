/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * sendfile() functionality
 *
 * $Id$
 */

/** @page sendfile-illegal_socket_states Socket descriptor in illegal state as sendfile() 'out_fd' parameter
 *
 * @objective Check @b sendfile() behavior in the case of passing an socket
 *            descriptor in illegal state as @b sendfile() @a out_fd parameter.
 *
 * @type conformance
 *
 * @reference  MAN 2 sendfile
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       Auxiliary PCO
 * @param iut_addr      The address of connection endpoint on @p pco_iut
 * @param tst_addr      The address of connection endpoint on @p pco_tst
 * @param state         Socket state which @b sendfile() behaviour should
 *                      be checked for.
 *
 * @par Test sequence:
 *
 * -# Create @p sendfile.pco_iut file on @p pco_iut.
 * -# Open @p sendfile.pco_iut for reading on @p pco_iut and retrieve @p src file
 *    descriptor.
 * -# Provide socket state according @p state test parameter.
 * -# Call @b sendfile() on @p pco_iut with @p src as @a in_fd parameter and
 *    socket descriptor as @a out_fd parameter.
 * -# Check that if socket is in:
 *      - clear(anew created socket), bound, listening or shutdown state
 *        @c SIGPIPE signal is generated and @b sendfile() returns @c -1 and
 *        @b errno is set to @c EPIPE or
 *        no @c SIGPIPE signal is generated and @b sendfile() returns
 *        @c -1 and @b errno is set to @c ENOTCONN;
 *      - closed state: @b sendfile() returns @c -1 and @b errno is set to 
 *        @c EBADF.
 * -# Close and remove file created and opened on @p pco_iut.
 * -# Close socket descriptors opened for test purposes.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendfile/illegal_socket_states"

#include "sendfile_common.h"


#define CHECK_SENDFILE_BEHAVIOUR(out_fd_, state_name_) \
    do {                                                                    \
        if (strcmp(state, #state_name_) == 0)                               \
        {                                                                   \
            int rc;                                                         \
            unsigned int err_code = 0;                                      \
                                                                            \
            INFO("sendfile() called with 'out_fd' in "#state_name_" state");\
            RPC_AWAIT_IUT_ERROR(pco_iut);                                   \
            rc = rpc_sendfile(pco_iut, out_fd_, src, &offset,               \
                              file_length, FALSE);                          \
            if (rc != -1)                                                   \
            {                                                               \
                TEST_FAIL("rpc_sendfile(): unexpected rc=%d", rc);          \
            }                                                               \
            if (!strcmp("closed", #state_name_))                            \
                CHECK_RPC_ERRNO(pco_iut, RPC_EBADF,                         \
                                "After calling sendfile() "                 \
                                "with 'out_fd' in "#state_name_" state it " \
                                "returns -1, but");                         \
            else if (RPC_ERRNO(pco_iut) == RPC_EPIPE ||                     \
                     RPC_ERRNO(pco_iut) == RPC_ENOTCONN)                    \
            {                                                               \
                RING_VERDICT("sendfile() to a socket in " #state_name_ " "  \
                             "state failed with errno %s",                  \
                             errno_rpc2str(RPC_ERRNO(pco_iut)));            \
            }                                                               \
            else                                                            \
            {                                                               \
                TEST_VERDICT("sendfile() to a socket in " #state_name_ " "  \
                             "state failed with unexpected errno %s",       \
                             errno_rpc2str(RPC_ERRNO(pco_iut)));            \
            }                                                               \
            if (err_code == RPC_EPIPE)                                      \
            {                                                               \
                iut_sigmask = rpc_sigreceived(pco_iut);                     \
                rc = rpc_sigismember(pco_iut, iut_sigmask, RPC_SIGPIPE);    \
                if (rc != TRUE)                                             \
                {                                                           \
                    TEST_FAIL("sendfile() is called with 'out_fd' in "      \
                              #state_name_" state, but the process does "   \
                              "not receive SIGPIPE signal");                \
                }                                                           \
            }                                                               \
            TEST_SUCCESS;                                                   \
        }                                                                   \
    } while (0)

#define TST_FILE_LENGTH    1024

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    int                     iut_s = -1;
    int                     accepted = -1;
    int                     tst_s = -1;
    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    const char             *file_iut = "sendfile.pco_iut";
    te_bool                 created_iut = FALSE;
    int                     src = -1;
    int                     file_length = TST_FILE_LENGTH;
    tarpc_off_t             offset = 0;
    DEFINE_RPC_STRUCT_SIGACTION(old_act);
    te_bool                 restore_signal_handler = FALSE;
    rpc_sigset_p            iut_sigmask = RPC_NULL;
    const char             *state;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(state);

    /* Register 'pco_iut' on receiving SIGPIPE signal */
    CHECK_RC(tapi_sigaction_simple(pco_iut, RPC_SIGPIPE,
                                   SIGNAL_REGISTRAR, &old_act));
    restore_signal_handler = TRUE;

    CREATE_REMOTE_FILE(pco_iut->ta, file_iut, 'F', file_length);
    created_iut = TRUE;

    RPC_FOPEN_D(src, pco_iut, file_iut, RPC_O_RDONLY, 0);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    CHECK_SENDFILE_BEHAVIOUR(iut_s, clear);

    rpc_bind(pco_iut, iut_s, iut_addr);
    CHECK_SENDFILE_BEHAVIOUR(iut_s, bound);

    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
    CHECK_SENDFILE_BEHAVIOUR(iut_s, listening);

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);
    rpc_connect(pco_tst, tst_s, iut_addr);
    accepted = rpc_accept(pco_iut, iut_s, NULL, NULL);

    rpc_shutdown(pco_iut, accepted, RPC_SHUT_WR);
    CHECK_SENDFILE_BEHAVIOUR(accepted, shutdown);

    RPC_CLOSE(pco_iut, iut_s);
    CHECK_SENDFILE_BEHAVIOUR(iut_s, closed);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, src);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, accepted);

    if (created_iut)
        REMOVE_REMOTE_FILE(pco_iut->ta, file_iut);

    if (restore_signal_handler)
        CLEANUP_RPC_SIGACTION(pco_iut, RPC_SIGPIPE, &old_act, 
                              SIGNAL_REGISTRAR);

    TEST_END;
}
