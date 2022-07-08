/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-file_max_overflow Trying to create more FDs than file-max allows
 *
 * @objective Check what happens when it is attempted to create more
 *            FDs than /proc/sys/fs/file-max allows.
 *
 * @type conformance, robustness
 *
 * @param env             Testing environment:
 *                        - @ref arg_types_env_peer2peer
 *                        - @ref arg_types_env_peer2peer_ipv6
 * @param other_user      Whether to run IUT process under another
 *                        (non-root) user.
 * @param fd_type         Type of file descriptors to create:
 *                        - @c tcp (obtained from @b socket())
 *                        - @c tcp_passive (obtained from @b accept())
 *                        - @c udp
 *                        - @c pipe
 *                        - @c epoll
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "bnbvalue/file_max_overflow"

#include "sockapi-test.h"

/**
 * Maximum number of file descriptors this test tries to create.
 * Should not exceed number of FDs allowed to be opened in a single process.
*/
#define MAX_FDS 1000

/** Number of available FDs after decreasing file-max */
#define AVAILABLE_FDS 500

/** Tested FD types */
enum {
    FD_TYPE_TCP, /**< TCP socket obtained from socket() */
    FD_TYPE_TCP_PASSIVE, /**< TCP socket obtained from accept() */
    FD_TYPE_UDP, /**< UDP socket */
    FD_TYPE_PIPE, /**< Pipe */
    FD_TYPE_EPOLL, /**< Epoll set */
};

/** List of "fd_type" values for TEST_GET_ENUM_PARAM() */
#define FD_TYPES \
    { "tcp", FD_TYPE_TCP }, \
    { "tcp_passive", FD_TYPE_TCP_PASSIVE }, \
    { "udp", FD_TYPE_UDP }, \
    { "pipe", FD_TYPE_PIPE }, \
    { "epoll", FD_TYPE_EPOLL }

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    uint64_t cur_files;
    int iut_listener = -1;
    int tst_socks[MAX_FDS];
    int iut_fds[MAX_FDS];
    int iut_fds_aux[MAX_FDS];
    int pipefds[2];
    int max_fds;
    int i;

    rpc_socket_type sock_type;
    int fd_type;
    te_bool other_user;

    const char *func_name = NULL;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ENUM_PARAM(fd_type, FD_TYPES);
    TEST_GET_BOOL_PARAM(other_user);

    for (i = 0; i < MAX_FDS; i++)
    {
        iut_fds[i] = -1;
        iut_fds_aux[i] = -1;
        tst_socks[i] = -1;
    }

    TEST_STEP("Reduce /proc/sys/fs/file-max, so that it is not much "
              "larger than number of currently used FDs in the system "
              "(as reported in /proc/sys/fs/file-nr).");

    CHECK_RC(tapi_cfg_sys_ns_get_uint64(pco_iut->ta, &cur_files,
                                        "fs/file-nr:0"));

    CHECK_RC(tapi_cfg_sys_ns_set_uint64(
                pco_iut->ta,
                cur_files + AVAILABLE_FDS,
                NULL, "fs/file-max"));

    switch (fd_type)
    {
        case FD_TYPE_TCP_PASSIVE:
            iut_listener = rpc_socket(pco_iut,
                                      rpc_socket_domain_by_addr(iut_addr),
                                      RPC_SOCK_STREAM, RPC_PROTO_DEF);
            rpc_bind(pco_iut, iut_listener, iut_addr);
            rpc_listen(pco_iut, iut_listener, -1);

            sock_type = RPC_SOCK_STREAM;
            func_name = "accept";

            break;

        case FD_TYPE_TCP:
            sock_type = RPC_SOCK_STREAM;
            func_name = "socket";
            break;

        case FD_TYPE_UDP:
            sock_type = RPC_SOCK_DGRAM;
            func_name = "socket";
            break;

        case FD_TYPE_EPOLL:
            func_name = "epoll_create";
            break;

        case FD_TYPE_PIPE:
            func_name = "pipe";
            break;

        default:
            TEST_FAIL("Unknown fd_type parameter value");
    }

    if (other_user)
    {
        TEST_STEP("If @p other_user is @c TRUE, create a new user on IUT "
                  "and use @b setuid() on @p pco_iut to switch to it.");

        CHECK_RC(tapi_cfg_add_new_user(pco_iut->ta, SOCKTS_DEF_UID));
        rpc_setuid(pco_iut, SOCKTS_DEF_UID);
    }

    max_fds = MAX_FDS;
    if (fd_type == FD_TYPE_PIPE)
    {
        /* Single call of pipe() opens two FDs */
        max_fds = max_fds / 2;
    }

    TEST_STEP("In a loop try to create more FDs of type @p fd_type than "
              "/proc/sys/fs/file-max allows. Check that it fails with "
              "@c ENFILE eventually if @p other_user is @c TRUE, and "
              "succeeds otherwise.");

    for (i = 0; i < max_fds; i++)
    {
        RPC_AWAIT_ERROR(pco_iut);

        if (fd_type == FD_TYPE_EPOLL)
        {
            rc = iut_fds[i] = rpc_epoll_create(pco_iut, 1);
        }
        else if (fd_type == FD_TYPE_PIPE)
        {
            rc = rpc_pipe(pco_iut, pipefds);
            if (rc >= 0)
            {
                iut_fds[i] = pipefds[0];
                iut_fds_aux[i] = pipefds[1];
            }
        }
        else if (fd_type == FD_TYPE_TCP_PASSIVE)
        {
            tst_socks[i] = rpc_socket(pco_tst,
                                      rpc_socket_domain_by_addr(tst_addr),
                                      RPC_SOCK_STREAM, RPC_PROTO_DEF);
            rpc_connect(pco_tst, tst_socks[i], iut_addr);

            rc = iut_fds[i] = rpc_accept(pco_iut, iut_listener, NULL, NULL);
        }
        else
        {
            rc = iut_fds[i] = rpc_socket(
                                    pco_iut,
                                    rpc_socket_domain_by_addr(iut_addr),
                                    sock_type, RPC_PROTO_DEF);
        }

        if (rc < 0)
        {
            RING_VERDICT("%s() failed with error %r",
                         func_name, RPC_ERRNO(pco_iut));

            break;
        }
    }

    if (other_user && i == max_fds)
    {
        TEST_VERDICT("All the requested FDs were created despite "
                     "running with low file-max and non-root user");
    }

    TEST_SUCCESS;

cleanup:

    for (i = 0; i < MAX_FDS; i++)
    {
        CLEANUP_RPC_CLOSE(pco_iut, iut_fds[i]);
        CLEANUP_RPC_CLOSE(pco_iut, iut_fds_aux[i]);
        CLEANUP_RPC_CLOSE(pco_tst, tst_socks[i]);
    }

    CLEANUP_RPC_CLOSE(pco_iut, iut_listener);

    /* Timeout needed because Onload can close FD for too long.
     * See ON-2217
     */
    TAPI_WAIT_NETWORK;

    if (other_user)
    {
        /* Restart to rollback user ID. */
        CLEANUP_CHECK_RC(rcf_rpc_server_restart(pco_iut));
        CHECK_RC(tapi_cfg_del_user(pco_iut->ta, SOCKTS_DEF_UID));
    }

    /* Timeout needed because Onload can close FD for too long.
     * See ON-2217
     */
    TAPI_WAIT_NETWORK;

    TEST_END;
}
