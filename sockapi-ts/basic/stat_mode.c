/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/** @page basic-stat_mode Stat family calls on various objects
 *
 * @objective Correctness of stat function calls on various objects,
 *            currenly st_mode is tested to check 'type' of the resource.
 *
 * @type use case
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_iut_only
 * @param object    Object to check:
 *                  - TCP: TCP socket
 *                  - UDP: UDP socket
 *                  - pipe: pipe fd
 *                  - epoll: epoll fd
 * @param domain    Protocol domain to be used for socket creation:
 *                  - PF_INET (iterates with @c TCP and @c UDP)
 *                  - PF_INET6 (iterates with @c TCP and @c UDP)
 *                  - PF_UNKNOWN (iterates with @c pipe and @c epoll)
 * @param is64  Call fstat64() if @c TRUE, else fstat().
 *
 * @par Scenario:
 * -# Create object of type @p object
 * -# Call @p function on @p object and check that st_mode is correctly
 *    filled.
 *
 * @author Konstantin Ushakov <Konstantin.Ushakov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/stat_mode"

#include "sockapi-test.h"

typedef int (*rpc_stat_f)(rcf_rpc_server *pco_iut, int fd, rpc_stat *buf);

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    int             fds[2] = {-1, -1};
    int             s       = -1;
    int             sys_s = -1;
    int             sys_fds[2] = {-1, -1};
    const char     *object;
    uint64_t        mode;
    uint64_t        sys_mode;
    te_bool         is64;
    rpc_stat        buf;
    rpc_stat_f      rpc_stat_func;

    rpc_socket_domain   domain;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_BOOL_PARAM(is64);
    TEST_GET_STRING_PARAM(object);
    TEST_GET_DOMAIN(domain);

    if (!is64)
        rpc_stat_func = rpc_fstat;
    else
        rpc_stat_func = rpc_fstat64;

    if (strcmp(object, "TCP") == 0)
    {
        s = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
        pco_iut->use_libc_once = TRUE;
        sys_s = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    }
    else if (strcmp(object, "UDP") == 0)
    {
        s = rpc_socket(pco_iut, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
        pco_iut->use_libc_once = TRUE;
        sys_s = rpc_socket(pco_iut, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    }
    else if (strcmp(object, "pipe") == 0)
    {
        rpc_pipe(pco_iut, fds);
        pco_iut->use_libc_once = TRUE;
        rpc_pipe(pco_iut, sys_fds);
    }
    else if (strcmp(object, "epoll") == 0)
    {
        s = rpc_epoll_create(pco_iut, 1);
        pco_iut->use_libc_once = TRUE;
        sys_s = rpc_epoll_create(pco_iut, 1);
    }
    else
        TEST_FAIL("Invalid parameter %s", object);

    memset(&buf, 0, sizeof(buf));

    if (s != -1)
    {
        rpc_stat_func(pco_iut, s, &buf);
        mode = buf.st_mode;
        pco_iut->use_libc_once = TRUE;
        rpc_stat_func(pco_iut, sys_s, &buf);
        sys_mode = buf.st_mode;
    }
    else {
        uint64_t mode1;

        /* note, that we don't care about actual encoding of the
         * st_mode at this point - they MUST be the same */
        rpc_stat_func(pco_iut, fds[0], &buf);
        mode = buf.st_mode;
        memset(&buf, 0, sizeof(buf));
        rpc_stat_func(pco_iut, fds[1], &buf);
        mode1 = buf.st_mode;

        if (mode1 != mode)
            TEST_VERDICT("stat showed different st_mode for 2 ends "
                         "of the pipe: 0x%x != 0x%x",
                         mode, mode1);
        pco_iut->use_libc_once = TRUE;
        memset(&buf, 0, sizeof(buf));
        rpc_stat_func(pco_iut, sys_fds[0], &buf);
        sys_mode = buf.st_mode;
        pco_iut->use_libc_once = TRUE;
        memset(&buf, 0, sizeof(buf));
        rpc_stat_func(pco_iut, sys_fds[1], &buf);
        mode1 = buf.st_mode;
        if (mode1 != sys_mode)
            TEST_VERDICT("stat showed different st_mode for 2 ends of the "
                         "system pipe: 0x%x != 0x%x", mode, mode1);
    }

    RING("st_mode is 0x%x, system mode of the same object is 0x%x",
         mode, sys_mode);

    if ((strcmp(object, "TCP") == 0 || 
        strcmp(object, "UDP") == 0) &&
        (!buf.ifsock || buf.iflnk || buf.ifreg ||
         buf.ifblk || buf.ifdir || buf.ifchr || buf.ififo))
        TEST_VERDICT("Non-socket mode retuned for a socket: 0x%x", mode);

    if (strcmp(object, "pipe") == 0 &&
        (buf.ifsock || buf.iflnk || buf.ifreg ||
         buf.ifblk || buf.ifdir || buf.ifchr || !buf.ififo))
        TEST_VERDICT("Non-FIFO mode returned for a pipe end: 0x%x", mode);

    if (strcmp(object, "epoll") == 0 &&
        (buf.ifsock || buf.iflnk || buf.ifreg ||
         buf.ifblk || buf.ifdir || buf.ifchr || buf.ififo))
        TEST_VERDICT("Wrong mode returned for epoll fd: 0x%x", mode);

    if (mode != sys_mode)
        TEST_VERDICT("Mode for the same objects are not equal for "
                     "Onload and system");


    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, s);
    CLEANUP_RPC_CLOSE(pco_iut, sys_s);
    CLEANUP_RPC_CLOSE(pco_iut, fds[0]);
    CLEANUP_RPC_CLOSE(pco_iut, sys_fds[0]);
    CLEANUP_RPC_CLOSE(pco_iut, fds[1]);
    CLEANUP_RPC_CLOSE(pco_iut, sys_fds[1]);

    TEST_END;
}
