/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 * 
 * $Id$
 */

/** @page fd_caching-set_linger_diff_ifs 
 *
 * @objective Test is a modification of 'set_linger' and uses different
 *            interfaces for connections, tries to close listening
 *            socket or rather quit the server and check that all
 *            related to listening socket 'cached' and accepted sockets
 *            truly closed.
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
 * @param linger_non_zero @c TRUE, if linger bit should be set to
 *                        non-zero value, @c FALSE otherwise
 * @param overfill_buffers
 *                        @c TRUE, if each connection client side socket
 *                        buffer should be overfilled, @c FALSE otherwise
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
 * -# If @p linger_non_zero is @c TRUE generate 
 *    any valid non_zero @p linger time, else let @p linger_time to be @c 0; 
 * -# While (@p num_of_cycles--) do:
 *     -# For each process @p p from @p p_list do:
 *         -# For @p j = 0, @p j < @c MAX_CONNECTIONS_PER_PROCCESS
 *             -# Call @b setsockopt() on @p @p acc_s[@p j] socket with 
 *                @c SO_LINGER option with 
 *                 - @a l_onoff  - @c 1;
 *                 - @a l_linger - @p linger_time;
 *             -# Close @p acc_s[@p j];    
 *             -# Close @p conns_s[@p j] socket;
 *             -# Create @c SOCK_STREAM socket @p conn_s[@p j] socket 
 *                on @p conn_s[@p j] tester;
 *             -# Call @b connect() on @p conn_s[@p j] socket towards
 *                @p conn_s[@p j] address;
 *             -# Call @b accept() on @p iut_s on @p p, 
 *                let @p acc_s[@p j] be the result of the call;  
 *     -# For each process @p p from @p p_list do:
 *         -# For @p j = 0, @p j < @c MAX_CONNECTIONS_PER_PROCCESS:
 *             -# Check that @p acc_s[@p j] @p <= 
 *                @p max_fd + @p fd_cache_size;
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
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 */

#define TE_TEST_NAME    "level5/fd_caching/set_linger_diff_ifs"

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
#define MAX_CONNECTIONS_PER_PROCCESS    16
#define MAX_NAME_LEN                    30 
#define MAX_BACKLOG                     256
#define START_DELAY                     8
#define WAIT_FOR_CACHE_EMPTIED          3

/**
 * Connection socket related information:
 */ 
typedef struct socket_info_set_linger_diff_ifs {
    rcf_rpc_server        *tester;  /**< RPC server on tester node */
    const struct sockaddr *to;      /**< Address to connect to */
} socket_info;    

/**
 * Connected socket with related information
 */ 
typedef struct conn_s_info_set_linger_diff_ifs {
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
typedef struct p_info_set_linger_diff_ifs {
    rcf_rpc_server  *p;       /**< RPC server on IUT node */
    uint16_t         state;   /**< Actually, 
                                   this is mask 
                                   to close connections */
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
    tarpc_linger    optval;

    te_bool         linger_non_zero;
    te_bool         overfill_buffers;

    const struct sockaddr *wldc = NULL;

    p_info         *p_current;

    int             i;
    int             j;

    char            name[MAX_NAME_LEN + 1] = {0,};

    int             num_of_cycles;
    te_bool         quit_the_server;
    
    const char     *default_fd_cache_size = NULL;
    const char     *fd_cache_size = NULL;    
    char           *old_fd_cache_size = NULL;
    int             fd_cache_size_val;

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
    
    TEST_GET_BOOL_PARAM(linger_non_zero);
    TEST_GET_BOOL_PARAM(overfill_buffers);

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

    /* Set linger time */
    optval.l_onoff = 1;
    if (linger_non_zero)
        optval.l_linger = rand_range(5, 10);
    else
        optval.l_linger = 0;

    while (num_of_cycles--)
    {    
        for (i = 0, p_current = p_list; i < p_number; i++, p_current++)
        {
            uint64_t total_filled;

            for (j = 0; j < MAX_CONNECTIONS_PER_PROCCESS; j++)
            {
                rpc_setsockopt(p_current->p, p_current->acc_s[j], 
                               RPC_SO_LINGER, &optval);
                if (overfill_buffers)
                {
                    total_filled = 0;
                    rpc_overfill_buffers(p_current->p, 
                                         p_current->acc_s[j], 
                                         &total_filled);
                }
                RPC_AWAIT_IUT_ERROR(p_current->p);
                rc = rpc_close(p_current->p, p_current->acc_s[j]);
                if (rc != 0)
                    CHECK_RPC_ERRNO(p_current->p, RPC_EAGAIN,
                                    "close() on 'iut_s' socket returns -1, but");
                rpc_close(TESTER, CONN_SOCK);

                CONN_SOCK = 
                    rpc_socket(TESTER, RPC_AF_INET,
                               RPC_SOCK_STREAM, RPC_PROTO_DEF);
                rpc_connect(TESTER, CONN_SOCK, ADDR_TO_CONNECT_TO);
                p_current->acc_s[j] = rpc_accept(p_current->p, iut_s, 
                                                 NULL, NULL);
            }
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

    /* Close listening sockets in all forked processes */
    for (i = 0, p_current = p_list; i < p_number; i++, p_current++)
    {
        rpc_close(p_current->p, iut_s);
    }

    /* Check that accepted sockets closed truly, not cached */
    for (i = 0, p_current = p_list; i < p_number; i++, p_current++)
    {
        for (j = 0; j < MAX_CONNECTIONS_PER_PROCCESS; j++)
        {
            rpc_close(p_current->p, p_current->acc_s[j]);
            RPC_AWAIT_IUT_ERROR(p_current->p);
            doubled = rpc_dup(p_current->p, p_current->acc_s[j]);
            if (doubled != -1)
            TEST_FAIL("Socket is not closed, exit");
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
