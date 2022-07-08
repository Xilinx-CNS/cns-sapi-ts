/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 * 
 * $Id$
 */

/** @page fd_caching-fd_cached_and_reused 
 *
 * @objective Check that there is no FD 'leaking', i.e. establishing 
 *            and closing connection check that FD of accepted sockets
 *            don't increasing to infinity.
 *
 * @type conformance
 *
 * @param pco_iut         RPC server on iut node
 * @param pco_tst         RPC server on tester node 
 * @param addr_to_connect address on iut node to connect to 
 *                        from tester node 
 * @param p_number        number of processes
 * @param num_of_cycles   number of cycles to close/establish
 *                        connections in different processes
 * @param fd_cache_size   FD cache size to be set
 * @param default_fd_cache_size
 *                        FD cache size to be restored 
 *                        after test running 
 *
 * @par Test sequence:
 *
 * -# Set FD cache size to @p fd_cache_size;
 * -# Create @c SOCK_STREAM socket @p iut_s on @p pco_iut;
 * -# Bind @p iut_s to wildcard address;
 * -# Call @b listen() on @p iut_s;
 * -# Create list of @p p_number processes @p p_list by
 *    forking @p pco_iut.
 * -# For each process @p p from @p p_list do:   
 *     -# For @p j = 0, @p j < @c MAX_CONNECTIONS_PER_PROCCESS do:   
 *         -# Create @c SOCK_STREAM socket @p conn_s[@p j] on @p pco_tst;
 *         -# Call @b connect() on @p conn_s[@p j] 
 *            towards @p addr_to_connect;
 *         -# Call @b accept() on @p iut_s on @p p, let @p acc_s[@p j] be
 *            the result of the call;
 * -# Let @p max_fd be maximum of @p acc_s for all connnections created;          
 * -# While (@p num_of_cycles--) do:
 *     -# For each process @p p from @p p_list do:
 *         -# For @p j = 0, @p j < @c MAX_CONNECTIONS_PER_PROCCESS
 *             -# Close @p conns_s[@p j];
 *             -# Create @c SOCK_STREAM socket @p conn_s[@p j] on @p
 *                pco_tst;
 *             -# Call @b connect() on @p conn_s[@p j] towards
 *                @p addr_to_connect;
 *     -# For each process @p p from @p p_list do:               
 *         -# Call RPC procedure on @p p which do following:
 *             -# For @p j = 0, @p j < @c MAX_CONNECTIONS_PER_PROCCESS
 *                 -# Close @p acc_s[@p j];
 *                 -# Call @b select() with @p iut_s in @p rfds;
 *                 -# Call @b accept() on @p iut_s, let @p acc_s[@p j] 
 *                    be the result of the call;
 *     -# For each process @p p from @p p_list do:
 *         -# For @p j = 0, @p j < @c MAX_CONNECTIONS_PER_PROCCESS:
 *             -# Check that @p acc_s[@p j] @p <= @p max_fd + @p 2*fd_cache_size.
 *                        
 * @note RPC procedures should be called simultaneously 
 *       in non-blocking mode.
 * @note @p acc_s[@p j] and @p conn_s[@p j] may not belong to the same
 *       connection. It is true only for initial state. 
 *
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 */

#define TE_TEST_NAME    "level5/fd_caching/fd_cached_and_reused"

#include "sockapi-test.h"
#include "tapi_cfg_base.h"
#include "tapi_rpc_unistd.h"
#include "tapi_rpc_misc.h"
#include "fd_cache.h"

#define PROCESSES_MAX_NUM               32
#define MAX_CONNECTIONS_PER_PROCCESS    10
#define PROCESS_MAX_NAME_LEN            24 
#define MAX_BACKLOG                     (PROCESSES_MAX_NUM * MAX_CONNECTIONS_PER_PROCCESS)
#define START_DELAY                     8

/** 
 * Process related information, process id, 
 * list of accepted sockets in that process,
 * and list of connected sockets on the only
 * process on tester node.
 */
typedef struct p_info {
    rcf_rpc_server *p;        /**< RPC server */
    int             acc_s[MAX_CONNECTIONS_PER_PROCCESS]; 
                              /**< List of accepted sockets
                                   belong
                                   on iut_node */
    int             conn_s[MAX_CONNECTIONS_PER_PROCCESS];
                              /**< List of connected sockets 
                                   on tester node */
} p_info;    
    

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    int             iut_s = -1;

    p_info         *p_list = NULL;
    int             p_number;

    int             opt_val = 1;

    const struct sockaddr *addr_to_connect = NULL;
    const struct sockaddr *wldc = NULL;

    p_info         *p_current;

    int             i;
    int             j;

    char            name[PROCESS_MAX_NAME_LEN] = {0,};
    tarpc_timeval       current_time = { 0, 0 };
    uint64_t            start_time;

    int             num_of_cycles;
    int             fd_cache_size;
    int             max_fd = -1;

    /* Preambule */
    TEST_START;
  
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    
    TEST_GET_ADDR(pco_iut, addr_to_connect);
    TEST_GET_ADDR_NO_PORT(wldc);
    SIN(wldc)->sin_port = SIN(addr_to_connect)->sin_port;

    TEST_GET_INT_PARAM(p_number);
    TEST_GET_INT_PARAM(num_of_cycles);
    TEST_GET_INT_PARAM(fd_cache_size);

    CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_SOCKET_CACHE_MAX",
                                 fd_cache_size, TRUE, TRUE));

    if (p_number > PROCESSES_MAX_NUM)
        TEST_FAIL("Number of processes exceeds maximum = %d, exit",
                  PROCESSES_MAX_NUM);

    p_list = (p_info *)calloc(p_number, sizeof(p_info));
    if (p_list == NULL)
        TEST_FAIL("Memory allocation failure");

    iut_s = rpc_socket(pco_iut, RPC_AF_INET,
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_setsockopt(pco_iut, iut_s, RPC_SO_REUSEADDR, &opt_val);
    rpc_bind(pco_iut, iut_s, wldc);
    rpc_listen(pco_iut, iut_s, MAX_BACKLOG);

    /* Get initial state */
    for (i = 0, p_current = p_list; i < p_number; i++, p_current++)
    {
        snprintf(name, PROCESS_MAX_NAME_LEN, "child_process_%d", i);
        //~ CHECK_RC(rcf_rpc_server_fork(pco_iut, name, &(p_current->p)));
        p_current->p = pco_iut;

        for (j = 0; j < MAX_CONNECTIONS_PER_PROCCESS; j++)
        {
            p_current->conn_s[j] = 
                rpc_socket(pco_tst, RPC_AF_INET,
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
            rpc_connect(pco_tst, p_current->conn_s[j], addr_to_connect);
            p_current->acc_s[j] = rpc_accept(p_current->p, iut_s, 
                                             NULL, NULL);
            max_fd = (p_current->acc_s[j] > max_fd) ? 
                p_current->acc_s[j] : max_fd;
        }
    }

    while (num_of_cycles--)
    {    
        for (i = 0, p_current = p_list; i < p_number; i++, p_current++)
        {
            for (j = 0; j < MAX_CONNECTIONS_PER_PROCCESS; j++)
            {
                rpc_close(pco_tst, p_current->conn_s[j]); 
                p_current->conn_s[j] = 
                    rpc_socket(pco_tst, RPC_AF_INET,
                               RPC_SOCK_STREAM, RPC_PROTO_DEF);
                rpc_connect(pco_tst, p_current->conn_s[j], addr_to_connect);
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
                if (p_current->acc_s[j] > max_fd + fd_cache_size)
                    TEST_FAIL("FD leaking? "
                              "accepted socket %d, max_fd %d, "
                              "fd cache size %d", 
                              p_current->acc_s[j], max_fd, 
                              fd_cache_size);
            }
        }
    }
    TEST_SUCCESS;

cleanup:
    for (i = 0, p_current = p_list; i < p_number; i++, p_current++)
    {
        if (p_current == NULL)
            break;
        for (j = 0; j < MAX_CONNECTIONS_PER_PROCCESS; j++)
        {
            CLEANUP_RPC_CLOSE(p_current->p, p_current->acc_s[j]);
            CLEANUP_RPC_CLOSE(pco_tst, p_current->conn_s[j]);
        }
        //~ CLEANUP_CHECK_RC(rcf_rpc_server_destroy(p_current->p));
    }
    if (p_list != NULL)
        free(p_list);
    
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    TEST_END;
}
