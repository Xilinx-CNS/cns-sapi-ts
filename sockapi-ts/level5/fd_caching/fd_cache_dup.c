/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * FD caching
 */

/** @page fd_caching-fd_cache_dup  Test sockets dup with caching
 *
 * @objective  Check thea sockets duplication disables caching.
 *
 * @type conformance
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_peer2peer_two_iut
 *                      - @ref arg_types_env_peer2peer_two_iut_ipv6
 * @param dup_way       How to duplicate socket
 *                      - @b dup()
 *                      - @b dup2()
 *                      - @b dup3()
 *                      - @b fcntl with F_DUPFD
 *                      - @b fcntl with F_DUPFD_CLOEXEC
 *                      - Copy with UNIX socket
 * @param state         Socket state when it should duplicated
 *                      - listener: Socket in the listen state
 *                      - established: Socket in the established state
 *                      - closed: Socket in the closed state
 * @param active        How to establish TCP connection.
 *                      - @c TRUE: active open way
 *                      - @c FALSE: passive open way
 *
 * @par Test sequence:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 * @author Denis Pryazhennikov <Denis.Pryazhennikov@oktetlabs.ru>
 */

#define TE_TEST_NAME    "level5/fd_caching/fd_cache_dup"

#include "sockapi-test.h"
#include "fd_cache.h"
#include "tapi_file.h"

/**
 * Socket duplication way
 */
typedef enum {
    DT_DUP,             /**< dup() */
    DT_DUP2,            /**< dup2() */
    DT_DUP3,            /**< dup3() */
    DT_FDUPFD,          /**< fcntl with F_DUPFD */
    DT_FDUPFD_CLOEXEC,  /**< fcntl with F_DUPFD_CLOEXEC */
    DT_UNIX,            /**< Copy with UNIX socket */
} duplication_way;

#define DUPLICATION_WAY \
    { "dup", DT_DUP },          \
    { "dup2", DT_DUP2 },        \
    { "dup3", DT_DUP3 },        \
    { "f_dupfd", DT_FDUPFD },   \
    { "f_dupfd_cloexec", DT_FDUPFD_CLOEXEC }, \
    { "unix", DT_UNIX }

/**
 * Socket state
 */
typedef enum {
    SS_LISTENER = 0,   /**< IUT socket in the listen state */
    SS_ESTABLISHED,    /**< IUT socket in the established state */
    SS_CLOSED,         /**< Closed (cached) IUT socket */
} socket_state;

#define SOCKET_STATE  \
    { "listener", SS_LISTENER },         \
    { "established", SS_ESTABLISHED },   \
    { "closed", SS_CLOSED }

/** Path to UNIX socket to be cleaned in the end */
static char *unix_rm_cmd = NULL;

/**
 * Duplicate a socket using UNIX socket.
 *
 * @param rpcs  RPC server
 * @param sock  Socket
 *
 * @return The socket duplicate
 */
int
dup_unix(rcf_rpc_server *rpcs, int sock)
{
    rpc_msghdr          msg;
    char                cmsg_buf[CMSG_SPACE(sizeof(int))];
    struct cmsghdr     *cmsg;
    int                 rpcs1_us = -1;
    int                 rpcs2_us = -1;
    struct sockaddr_un  us_addr;

    memset(&msg, 0, sizeof(msg));
    memset(&us_addr, 0, sizeof(us_addr));
    memset(&cmsg_buf, 0, sizeof(cmsg_buf));

    rpcs1_us = rpc_socket(rpcs, RPC_PF_UNIX, RPC_SOCK_DGRAM,
                         RPC_PROTO_DEF);
    rpcs2_us = rpc_socket(rpcs, RPC_PF_UNIX, RPC_SOCK_DGRAM,
                         RPC_PROTO_DEF);

    us_addr.sun_family = AF_UNIX;
    snprintf(us_addr.sun_path, sizeof(us_addr.sun_path),
             "/tmp/%s_share_usocket", tapi_file_generate_name());

    rpc_bind(rpcs, rpcs2_us, (struct sockaddr *)&us_addr);
    rpc_connect(rpcs, rpcs1_us, (struct sockaddr *)&us_addr);

    unix_rm_cmd = te_calloc_fill(sizeof(us_addr.sun_path) + 10,
                                 sizeof(*unix_rm_cmd), 0);
    snprintf(unix_rm_cmd, sizeof(us_addr.sun_path) + 10,
             "rm %s", us_addr.sun_path);

    msg.msg_control = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(sock));
    memcpy(CMSG_DATA(cmsg), &sock, sizeof(sock));
    msg.msg_cmsghdr_num = 1;

    rpc_sendmsg(rpcs, rpcs1_us, &msg, 0);

    memset(&cmsg_buf, 0, sizeof(cmsg_buf));
    memset(&msg, 0, sizeof(msg));
    msg.msg_control = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);

    rpc_recvmsg(rpcs, rpcs2_us, &msg, 0);

    RPC_CLOSE(rpcs, rpcs2_us);
    RPC_CLOSE(rpcs, rpcs1_us);

    if (cmsg->cmsg_type != SCM_RIGHTS)
        TEST_FAIL("Failed to pass file descriptor to the second process");

    return *((int*)CMSG_DATA(cmsg));
}

/**
 * Perform socket duplication with one of the ways.
 *
 * @param rpcs  RPC server handler
 * @param sock  Socket disecriptor
 * @param way   How to duplicate the socket
 *
 * @return New socket descriptor or -1 in case of failure
 */
static int
dup_socket(rcf_rpc_server *rpcs, int sock, rpc_socket_domain domain,
           duplication_way way)
{
    te_bool wait_err = !RPC_AWAITING_ERROR(rpcs);

    switch (way)
    {
        case DT_DUP:
            return rpc_dup(rpcs, sock);

        case DT_DUP2:
        case DT_DUP3:
        {
            int tmp_s;

            RPC_DONT_AWAIT_IUT_ERROR(rpcs);
            tmp_s = rpc_socket(rpcs, domain, RPC_SOCK_STREAM,
                               RPC_PROTO_DEF);

            rpcs->iut_err_jump = wait_err;
            if (way == DT_DUP2)
                return rpc_dup2(rpcs, sock, tmp_s);
            else
                return rpc_dup3(rpcs, sock, tmp_s, 0);
        }

        case DT_FDUPFD:
            return rpc_fcntl(rpcs, sock, RPC_F_DUPFD, 1);

        case DT_FDUPFD_CLOEXEC:
            return rpc_fcntl(rpcs, sock, RPC_F_DUPFD_CLOEXEC, 1);

        case DT_UNIX:
            return dup_unix(rpcs, sock);

        default:
            TEST_FAIL("Unknow value of argument dup_way");
    }

    return -1;
}

int
main(int argc, char *argv[])
{
    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    duplication_way dup_way;
    socket_state    state;
    te_bool         active;

    int iut_s   = -1;
    int iut_s2  = -1;
    int iut_dup = -1;
    int tst_s   = -1;
    int tst_s2  = -1;
    int aux_ls  = -1;

    te_bool iut_s_closed = FALSE;
    te_bool iut_s2_closed = FALSE;
    te_bool iut_dup_closed = FALSE;

    rpc_socket_domain domain;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ENUM_PARAM(dup_way, DUPLICATION_WAY);
    TEST_GET_ENUM_PARAM(state, SOCKET_STATE);
    TEST_GET_BOOL_PARAM(active);

    domain = rpc_socket_domain_by_addr(iut_addr);

    TEST_STEP("Open TCP sockets on IUT and tester.");
    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    TEST_STEP("Establish TCP connection according to @p active");
    if (active)
    {
        aux_ls = tst_s;
        rpc_bind(pco_tst, aux_ls, tst_addr);
        rpc_listen(pco_tst, aux_ls, -1);
        rpc_connect(pco_iut, iut_s, tst_addr);
        tst_s = rpc_accept(pco_tst, aux_ls, NULL, NULL);
    }
    else
    {
        aux_ls = iut_s;
        rpc_bind(pco_iut, aux_ls, iut_addr);
        rpc_listen(pco_iut, aux_ls, -1);

        TEST_SUBSTEP("Duplicate the listener socket if @p state is @a listener.");
        if (state == SS_LISTENER)
            iut_dup = dup_socket(pco_iut, aux_ls, domain, dup_way);

        rpc_connect(pco_tst, tst_s, iut_addr);
        iut_s = rpc_accept(pco_iut, iut_s, NULL, NULL);
    }

    TEST_STEP("Duplicate IUT socket if @p state is @c established.");
    if (state == SS_ESTABLISHED)
        iut_dup = dup_socket(pco_iut, iut_s, domain, dup_way);

    TEST_STEP("Close the IUT socket.");
    rpc_close(pco_iut, iut_s);
    iut_s_closed = TRUE;
    if (state == SS_ESTABLISHED)
    {
        rpc_close(pco_iut, iut_dup);
        iut_dup_closed = TRUE;
    }
    RPC_CLOSE(pco_tst, tst_s);

    TEST_STEP("If listener socket was duplicated establish the second TCP "
              "connection using the duplicated FD, close the second accepted "
              "socket as well. Check that both closed accepted sockets are "
              "cached in this case.");
    if (state == SS_LISTENER)
    {
        if (active)
            TEST_FAIL("Unsupported tcp state for active opening: SS_LISTENER");

        tst_s2 = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM,
                            RPC_PROTO_DEF);
        rpc_connect(pco_tst, tst_s2, iut_addr);
        iut_s2 = rpc_accept(pco_iut, iut_dup, NULL, NULL);
        rpc_close(pco_iut, iut_s2);
        iut_s2_closed = TRUE;
        RPC_CLOSE(pco_tst, tst_s2);

        if (!tapi_onload_socket_is_cached(pco_iut, iut_s2))
            TEST_VERDICT("The first accepted socket was not cached");

        if (!tapi_onload_socket_is_cached(pco_iut, iut_s))
            TEST_VERDICT("The accepted socket was not cached");
    }

    TEST_STEP("If @p state is @c established, both IUT and duplicated sockets should "
              "show that the FD is uncached.");
    if (state == SS_ESTABLISHED)
    {
        if (tapi_onload_socket_is_cached(pco_iut, iut_s))
            TEST_VERDICT("The original socket was cached");

        if (tapi_onload_socket_is_cached(pco_iut, iut_dup))
            TEST_VERDICT("The duplicated socket was cached");
    }

    TEST_STEP("If @p state is @c closed, try to duplicate the socket now, when it "
              "is closed and cached. Check that the duplication attempt fails with "
              "errno EBADF.");
    if (state == SS_CLOSED)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        if ((iut_dup = dup_socket(pco_iut, iut_s, domain, dup_way)) != -1 ||
            RPC_ERRNO(pco_iut) != RPC_EBADF)
            TEST_VERDICT("Duplication of the closed socket must fail with "
                         "EBADF");
    }

    TEST_SUCCESS;

cleanup:
    if (!iut_s_closed)
        CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    if (!iut_s2_closed)
        CLEANUP_RPC_CLOSE(pco_iut, iut_s2);
    if (!iut_dup_closed)
        CLEANUP_RPC_CLOSE(pco_iut, iut_dup);

    CLEANUP_RPC_CLOSE(pco_tst, tst_s2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(active ? pco_tst : pco_iut, aux_ls);

    if (unix_rm_cmd != NULL)
    {
        rpc_system(pco_iut, unix_rm_cmd);
        free(unix_rm_cmd);
    }

    TEST_END;
}
