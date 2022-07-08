/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 * 
 * $Id$
 */

/** @page fd_caching-fd_cached_and_reused_diff_ifs 
 *
 * @objective Check that there is no FD 'leaking', i.e. establishing 
 *            and closing connection check that FD of accepted sockets
 *            don't increasing to infinity. Test is a modification of
 *            'fd_cached_and_reused' and uses different interfaces for
 *            connections, tries to close listening socket or rather quit the
 *            server and check that all related to listening socket 
 *            'cached' and accepted sockets truly closed.
 *
 * @type conformance
 *
 * @param pco_iut         RPC server on iut node
 * @param pco_tst         RPC server on tester node 
 * @param p_number        number of processes
 * @param num_of_cycles   number of cycles to close/establish
 *                        connections in different processes
 * @param if_number       Number of interfaces to connect to
 * @param quit_the_server TRUE or FALSE
 *
 * @par Test sequence:
 *
 * -# Create @p info_list containig @p if_number pairs 
 *    @p (@p tester, @p address_to_connect_to),
 *    where @p tester is rpc server on tester node, 
 *    @p address_to_connect_to is related unicast address on
 *    iut node to connect to.
 *    All these parameters are to be taken from environment as well
 *    as @p if_number - the size if the list.
 * -# Create @c SOCK_STREAM socket @p iut_s on @p pco_iut;
 * -# Bind @p iut_s to wildcard address;
 * -# Call @b listen() on @p iut_s with backlog big enough (256);
 * -# Create list of @p p_number processes @p p_list by
 *    forking @p pco_iut.
 * -# For each process @p p from @p p_list do:   
 *     -# For @p j = 0, @p j < @c MAX_CONNECTIONS_PER_PROCCESS do:   
 *         -# Relate with @p j for given @p p
 *            some item @p conn_s[@p j] from @p info_list.
 *         -# Create @c SOCK_STREAM @p conn_s[@p j] socket 
 *            on @p conn_s[@p j] tester;
 *         -# Call @b connect() on @p conn_s[@p j] socket
 *            towards @p conn_s[@p j] address;
 *         -# Call @b accept() on @p iut_s on @p p, let @p acc_s[@p j] be
 *            the result of the call;
 * -# Let @p max_fd be maximum of @p acc_s for all connnections created;          
 * -# While (@p num_of_cycles--) do:
 *     -# For each process @p p from @p p_list do:
 *         -# Generate state for that process - @c uint16_t type value;
 *         -# For @p j = 0, @p j < @c MAX_CONNECTIONS_PER_PROCCESS
 *             -# If (1 << j) & state then do:
 *                 -# Close @p conns_s[@p j] socket;
 *                 -# Create @c SOCK_STREAM socket @p conn_s[@p j] socket 
 *                    on @p conn_s[@p j] tester.
 *                 -# Call @b connect() on @p conn_s[@p j] socket towards
 *                    @p conn_s[@p j] address;
 *     -# For each process @p p from @p p_list do:               
 *         -# Call RPC procedure on @p p which do following:
 *             -# For @p j = 0, @p j < @c MAX_CONNECTIONS_PER_PROCCESS
 *                 -# If (1 << j) & state then do:
 *                     -# Close @p acc_s[@p j];
 *                     -# Call @b select() with @p iut_s in @p rfds;
 *                     -# Call @b accept() on @p iut_s, let @p acc_s[@p j] 
 *                        be the result of the call;
 *     -# For each process @p p from @p p_list do:
 *         -# For @p j = 0, @p j < @c MAX_CONNECTIONS_PER_PROCCESS:
 *             -# Check that @p acc_s[@p j] @p <= @p max_fd + @p 2*fd_cache_size.
 * -# If @p quit_the_server is @c TRUE than restart rpc server @p pco_iut,
 *    else close @p iut_s;
 * -# For each process @p p from @p p_list do:
 *     -# For @p j = 0, @p j < @c MAX_CONNECTIONS_PER_PROCCESS
 *         -# Close @p acc_s[@p j].
 *         -# Check that @p acc_s[@p j] is truly closed.
 *            Call @b dup() in @p acc_s[@p j] and
 *            check that it returns @c -1 and @p errno
 *            is set to @c EBADF.
 *            
 * @note RPC procedures should be called simultaneously 
 *       in non-blocking mode.
 * @note @p acc_s[@p j] and @p conn_s[@p j] may not belong to the same
 *       connection. It is true only for initial state. 
 *
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 */

#define TE_TEST_NAME    "level5/fd_caching/fd_cached_and_reused_diff_ifs"

#include <errno.h>
#include <pthread.h>
#include <sys/time.h>
#include <time.h>

#include "sockapi-test.h"
#include "rcf_api.h"
#include "tapi_cfg_base.h"
#include "rcf_rpc.h"
#include "tapi_rpc_unistd.h"
#include "tapi_rpc_misc.h"
#include "fd_cache.h"

#define PROCESSES_MAX_NUM               16
#define MAX_CONNECTIONS_PER_PROCCESS    10
#define MAX_NAME_LEN                    30 
#define MAX_BACKLOG                     256
#define START_DELAY                     8
#define WAIT_FOR_CACHE_EMPTIED          3

/**
 * Connection socket related information:
 */ 
typedef struct socket_info {
    rcf_rpc_server        *tester;  /**< RPC server on tester node */
    const struct sockaddr *to;      /**< Address to connect to */
} socket_info;    

/**
 * Connected socket with related information
 */ 
typedef struct conn_s_info {
    socket_info *related_info;      /**< Related information */
    int          conn_s;            /**< Connected socket */
} conn_s_info;    
 
/**
 * Process with related list of accepted sockets and
 * 'related' list of connected sockets on tester nodes with their
 * infos.
 * Actually, connected sockets don't correspond to accepted sockets,
 * they placed here for reasons of conviniences.
 */ 
typedef struct p_info_fd_cached_and_reused_diff_ifs {
    rcf_rpc_server  *p;       /**< RPC server on IUT node */
    int              acc_s[MAX_CONNECTIONS_PER_PROCCESS]; 
                              /**< List of accepted sockets 
                                   on iut_node */
    conn_s_info      conn_s[MAX_CONNECTIONS_PER_PROCCESS];
                              /**< List of connected sockets 
                                   on tester nodes
                                   and related stuff */
} p_info;    


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;

    socket_info    *info_list = NULL;    

    int             iut_s = -1;
    int             doubled = -1;

    p_info         *p_list = NULL;
    int             p_number;
    int             if_number;

    int             opt_val = 1;

    const struct sockaddr *wldc = NULL;

    p_info         *p_current;

    int             i;
    int             j;

    char            name[MAX_NAME_LEN + 1] = {0,};
    tarpc_timeval       current_time = { 0, 0 };
    uint64_t            start_time;

    int             num_of_cycles;
    te_bool         quit_the_server;
    
    int             fd_cache_size_val;
    const char     *default_fd_cache_size = NULL;
    const char     *fd_cache_size = NULL;    
    char           *old_fd_cache_size = NULL;

    int             max_fd = -1;
    te_bool         listening_socket_is_closed = FALSE;

    /* Preambule */
    TEST_START;
  
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, wldc);
    TEST_GET_INT_PARAM(p_number);
    TEST_GET_INT_PARAM(num_of_cycles);
    TEST_GET_INT_PARAM(if_number);
    TEST_GET_BOOL_PARAM(quit_the_server);
    
    if (p_number > PROCESSES_MAX_NUM)
        TEST_FAIL("Number of processes exceeds maximum = %d, exit",
                  PROCESSES_MAX_NUM);

    TEST_GET_STRING_PARAM(default_fd_cache_size);
    TEST_GET_STRING_PARAM(fd_cache_size);

    SET_ENV_VAR(pco_iut, EF_EPCACHE_MAX, 
                fd_cache_size, old_fd_cache_size);

    fd_cache_size_val = (uint16_t)strtoul(fd_cache_size, NULL, 0);

    p_list = (p_info *)calloc(p_number, sizeof(p_info));
    if (p_list == NULL)
        TEST_FAIL("Memory allocation failure");

    for (i = 0, p_current = p_list; i < p_number; i++, p_current++)
    {
        for (j = 0; j < MAX_CONNECTIONS_PER_PROCCESS; j++)
        {
            p_current->conn_s[j].conn_s = -1;
            p_current->acc_s[j] = -1;
        }
    }

    info_list = (socket_info *)calloc(if_number, sizeof(socket_info));
    if (info_list == NULL)
        TEST_FAIL("Memory allocation failure");

    for (i = 0; i < if_number; i++)
    {
        memset(name, 0, MAX_NAME_LEN);
        snprintf(name, MAX_NAME_LEN, "tester_%d", i + 1);
        info_list[i].tester = tapi_env_get_pco(&env, name);
        if (info_list[i].tester == NULL)
            TEST_FAIL("Cannot get tester for tst_list[%d]", i);

        memset(name, 0, MAX_NAME_LEN);
        snprintf(name, MAX_NAME_LEN, "to_%d", i + 1);
        info_list[i].to = tapi_env_get_addr(&env, name, NULL);
        if (info_list[i].to == NULL)
            TEST_FAIL("Cannot get address for tst_list[%d]");
        SIN(info_list[i].to)->sin_port = SIN(info_list[0].to)->sin_port;
    }

    iut_s = rpc_socket(pco_iut, RPC_AF_INET,
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_setsockopt(pco_iut, iut_s, RPC_SO_REUSEADDR, &opt_val);
    SIN(wldc)->sin_port = SIN(info_list[0].to)->sin_port;
    rpc_bind(pco_iut, iut_s, wldc);
    rpc_listen(pco_iut, iut_s, MAX_BACKLOG);

    memset(name, 0, MAX_NAME_LEN);

#define TESTER             p_current->conn_s[j].related_info->tester
#define CONN_SOCK          p_current->conn_s[j].conn_s    
#define ADDR_TO_CONNECT_TO p_current->conn_s[j].related_info->to
    
    /* Get initial state */
    for (i = 0, p_current = p_list; i < p_number; i++, p_current++)
    {
        snprintf(name, MAX_NAME_LEN, "child_process_%d", i);
        CHECK_RC(rcf_rpc_server_fork(pco_iut, name, &(p_current->p)));
        p_current->p->def_timeout *= 10;

        for (j = 0; j < MAX_CONNECTIONS_PER_PROCCESS; j++)
        {
            p_current->conn_s[j].related_info = 
                info_list + 
                    ((i * MAX_CONNECTIONS_PER_PROCCESS + j) % if_number);
            
            CONN_SOCK = 
                rpc_socket(TESTER, RPC_AF_INET,
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
            rpc_connect(TESTER, CONN_SOCK, ADDR_TO_CONNECT_TO);
            p_current->acc_s[j] = rpc_accept(p_current->p, iut_s, 
                                             NULL, NULL);
            max_fd = (p_current->acc_s[j] > max_fd) ? 
                p_current->acc_s[j] : max_fd;
        }
    }

    /* Let's shake it well */
    while (num_of_cycles--)
    {    
        for (i = 0, p_current = p_list; i < p_number; i++, p_current++)
        {
            for (j = 0; j < MAX_CONNECTIONS_PER_PROCCESS; j++)
            {
                rpc_close(TESTER, CONN_SOCK); 
                CONN_SOCK = 
                    rpc_socket(TESTER, RPC_AF_INET,
                               RPC_SOCK_STREAM, RPC_PROTO_DEF);
                rpc_connect(TESTER, CONN_SOCK, ADDR_TO_CONNECT_TO);
            }
        }
        rpc_gettimeofday(pco_iut, &current_time, NULL);
        start_time = (current_time.tv_sec + START_DELAY) * 1000;
        for (i = 0, p_current = p_list; i < p_number; i++, p_current++)
        {
            p_current->p->op = RCF_RPC_CALL;
            p_current->p->start = start_time;
            rpc_close_and_accept(p_current->p, iut_s,
                                 MAX_CONNECTIONS_PER_PROCCESS,
                                 p_current->acc_s, 
                                 0xffff);
        }

        for (i = 0, p_current = p_list; i < p_number; i++, p_current++)
        {
            rpc_close_and_accept(p_current->p, iut_s,
                                 MAX_CONNECTIONS_PER_PROCCESS,
                                 p_current->acc_s, 
                                 0xffff);
        }

        for (i = 0, p_current = p_list; i < p_number; i++, p_current++)
        {
            for (j = 0; j < MAX_CONNECTIONS_PER_PROCCESS; j++)
            {
                if (p_current->acc_s[j] > max_fd + 2 * fd_cache_size_val)
                    TEST_FAIL("FD leaking? "
                              "accepted socket %d, max_fd %d, "
                              "fd cache size %d", 
                              p_current->acc_s[j], max_fd, 
                              fd_cache_size_val);
            }
        }
    }
    /* Close the listening*/
    if (quit_the_server == TRUE)
    {
        if (rcf_rpc_server_restart(pco_iut) != 0)
            TEST_FAIL("Cannot restart rpc server");
    }    
    else
        rpc_close(pco_iut, iut_s);
    
    listening_socket_is_closed = TRUE;

    /* Check that the listening socket is closed */
    RPC_AWAIT_IUT_ERROR(pco_iut);
    doubled = rpc_dup(pco_iut, iut_s);
    if (doubled != -1)
        TEST_FAIL("Socket is not closed, exit");
    else
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_EBADF,
                        "dup returns -1, but");
    }

    SLEEP(WAIT_FOR_CACHE_EMPTIED);

    /* Check that accepted sockets closed truly, not cached */
    for (i = 0, p_current = p_list; i < p_number; i++, p_current++)
    {
        rpc_close(p_current->p, iut_s);
        for (j = 0; j < MAX_CONNECTIONS_PER_PROCCESS; j++)
        {
            rpc_close(p_current->p, p_current->acc_s[j]);
            RPC_AWAIT_IUT_ERROR(p_current->p);
            doubled = rpc_dup(p_current->p, p_current->acc_s[j]);
            if (doubled != -1)
                TEST_FAIL("This is the case, Socket is not closed, exit");
            else
            {
                CHECK_RPC_ERRNO(pco_iut, RPC_EBADF,
                                "dup returns -1, but");
            }
            p_current->acc_s[j] = -1;
        }
    }

    iut_s = -1;
    
    TEST_SUCCESS;

cleanup:
    if (p_list != NULL)
    {
        for (i = 0, p_current = p_list; i < p_number; i++, p_current++)
        {
            for (j = 0; j < MAX_CONNECTIONS_PER_PROCCESS; j++)
            {
                CLEANUP_RPC_CLOSE(p_current->p, p_current->acc_s[j]);
                if (p_current->conn_s[j].related_info != NULL)
                    CLEANUP_RPC_CLOSE(TESTER, CONN_SOCK);
            }
            if (p_current->p != NULL)
                CLEANUP_CHECK_RC(rcf_rpc_server_destroy(p_current->p));
        }
        free(p_list);
    }
    
    if (listening_socket_is_closed)
        iut_s = -1;
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    RESTORE_ENV_VAR(pco_iut, EF_EPCACHE_MAX, 
                    (old_fd_cache_size == NULL) ? 
                    default_fd_cache_size : old_fd_cache_size);
    TEST_END;
}
