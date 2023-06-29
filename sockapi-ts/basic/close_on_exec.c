/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-close_on_exec Usage of fcntl, socket and accept4 functionality for handling close-on-exec
 *
 * @objective Check that @b fcntl(), @b socket() and @b accept4() can
 *            handle close-on-exec flag and @b exec() operates in
 *            accordance with this flag.
 *
 * @type conformance
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param sock_type Socket type:
 *                  - SOCK_STREAM
 *                  - SOCK_DGRAM
 * @param use_dup3  Use dup3() function to duplicate socket if @c TRUE,
 *                  else - fcntl(@c F_DUPFD_CLOEXEC or @c F_DUPFD).
 * @param use_fdup  Duplicated socket if @c TRUE.
 * @param func      Tested function:
 *                  - fcntl()
 *                  - socket()
 *                  - accept4()
 * @param close_on_exec Set @c SOCK_CLOEXEC or @c O_CLOEXEC flag if @c TRUE.
 *
 * @note
 *      - Parameters @p use_dup3 and @p use_fdup makes sense and iterated
 *      only for @p func = @c fcntl().
 *      - @p func = sock() is not iterated with @p close_on_exec = @c FALSE.
 *
 * @par Test sequence:
 * -# Create a connection of type @p sock_type between @p pco_iut and
 *    @p pco_tst. As the result we will have two sockets:
 *    @p iut_s and @p tst_s. If @p func is "socket" or
 *    "accept4" and @p close_on_exec is @c TRUE, obtain @p iut_s with
 *    @c RPC_SOCK_CLOEXEC flag set with help of function defined by @p
 *    func during this process.
 * -# If @p func is "fcntl", set close-on-exec flag by means of
 *    @b fcntl().
 * -# Change image of process @p pco_iut by @b execve() call.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# If @p close_on_exec is @c TRUE check that @p iut_s was closed
 *    while  @b execve() processing:
 *       - @c SOCK_STREAM case:
 *                  - call @b recv() on tst_s
 *                  - check that @b recv() returned @c 0 as reaction on @c
 *                    FIN segment sent.
 *                  - check that @p tst_s socket is in @c
 *                    RPC_TCP_CLOSE_WAIT state.
 *       - @c SOCK_DGRAM case:
 *                  - call @b send() on tst_s;
 *                  - check that @b send() returned no errors;
 *                  - call @b send() on tst_s;
 *                  - check that @b send() returned -1 and errno set to
 *                    @c ECONNREFUSED.
 *       - for both cases:
 *                  - call @b recv() on iut_s;
 *                  - check that it returned -1;
 *                  - check that errno is set to @c EBADF.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# If @p close_on_exec is @c FALSE check that @p iut_s is in opened
 *    state and can be used for sending/receiving purposes.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Delete all created buffers.
 * -# Close created sockets.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/close_on_exec"

#include "sockapi-test.h"
#include "tapi_sockets.h"
#include "check_sock_flags.h"

int
main(int argc, char *argv[])
{
    rpc_socket_type        sock_type;

    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;

    int                    iut_s = -1;
    int                    iut_s_aux = -1;
    int                    tst_s = -1;

    void                   *rd_buf = NULL;
    size_t                  rd_buflen;
    void                   *wr_buf = NULL;
    size_t                  wr_buflen;
    te_bool                 close_on_exec = FALSE;
    int                     arg = 0;

    int                     sent = 0;

    fdflag_set_func_type_t      func = UNKNOWN_SET_FDFLAG;
    te_bool                     accept4_found = FALSE;
    te_bool                     use_fdup = FALSE;
    te_bool                     use_dup3 = FALSE;

    /* Preambule */
    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(close_on_exec);
    TEST_GET_FDFLAG_SET_FUNC(func);
    if (func == FCNTL_SET_FDFLAG)
    {
        TEST_GET_BOOL_PARAM(use_fdup);
        TEST_GET_BOOL_PARAM(use_dup3);
    }

    if (rpc_find_func(pco_iut, "accept4") == 0)
        accept4_found = TRUE;

    if (func == ACCEPT4_SET_FDFLAG)
    {
        if (!accept4_found)
            TEST_VERDICT("Failed to find accept4 on pco_iut");

        if (sock_type != RPC_SOCK_STREAM)
            TEST_FAIL("accept4() can be used only with SOCK_STREAM socket");
    }

    wr_buf = sockts_make_buf_stream(&wr_buflen);
    rd_buf = te_make_buf_min(wr_buflen, &rd_buflen);

    /* Scenario */

    if (func == ACCEPT4_SET_FDFLAG)
        gen_conn_with_flags(pco_iut, pco_tst, iut_addr, tst_addr,
                            &iut_s, &tst_s, sock_type,
                            close_on_exec ? RPC_SOCK_CLOEXEC : 0,
                            FALSE, FALSE, TRUE);
    else
        gen_conn_with_flags(pco_tst, pco_iut, tst_addr, iut_addr,
                            &tst_s, &iut_s, sock_type,
                            close_on_exec ? RPC_SOCK_CLOEXEC : 0,
                            FALSE,
                            func == SOCKET_SET_FDFLAG ? TRUE : FALSE,
                            FALSE);

    if (func == FCNTL_SET_FDFLAG)
    {
        rc = rpc_fcntl(pco_iut, iut_s, RPC_F_GETFD, arg);
        RING("Default value of FD_CLOEXEC bit is %d", rc);

        if (!use_fdup)
            rpc_fcntl(pco_iut, iut_s, RPC_F_SETFD, close_on_exec);
        else
        {
            if (use_dup3)
            {
                iut_s_aux = rpc_socket(pco_iut,
                                       rpc_socket_domain_by_addr(iut_addr),
                                       sock_type, RPC_PROTO_DEF);
                rpc_dup3(pco_iut, iut_s, iut_s_aux,
                         close_on_exec ? RPC_O_CLOEXEC : 0);
            }
            else
            {
                RPC_AWAIT_IUT_ERROR(pco_iut);
                iut_s_aux = rpc_fcntl(pco_iut, iut_s,
                                      close_on_exec ? RPC_F_DUPFD_CLOEXEC :
                                                      RPC_F_DUPFD, 0);
                if (iut_s_aux < 0)
                    TEST_VERDICT("fcntl(%s) call failed",
                                 close_on_exec ?
                                 "F_DUPFD_CLOEXEC" :
                                 "F_DUPFD");
            }
            rpc_close(pco_iut, iut_s);
            iut_s = iut_s_aux;
        }

        rc = rpc_fcntl(pco_iut, iut_s, RPC_F_GETFD, arg);
        if (rc != close_on_exec)
            TEST_FAIL("Unable to set FD_CLOEXEC bit to %d", close_on_exec);
    }

    CHECK_RC(rcf_rpc_server_exec(pco_iut));
    SLEEP(2);

    if (close_on_exec == TRUE)
        check_sock_cloexec(pco_iut, pco_tst, iut_s, tst_s,
                           sock_type, FALSE, NULL, "");
    else
    {
        RPC_SEND(sent, pco_iut, iut_s, wr_buf, wr_buflen, 0);
        rc = rpc_recv(pco_tst, tst_s, rd_buf, rd_buflen, 0);
        if (rc != sent)
            TEST_FAIL("rpc_recv(): Expected to receive %d instead of %d",
                      sent, rc);
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    if (close_on_exec == FALSE)
        CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    sockts_kill_zombie_stacks_if_many(pco_iut);

    TEST_END;
}
