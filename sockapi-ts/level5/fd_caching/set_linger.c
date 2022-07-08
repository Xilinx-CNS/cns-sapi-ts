/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 * 
 * $Id$
 */

/** @page fd_caching-set_linger
 *
 * @objective Check that FD cache behaves friendly when the linger bit
 *            is set. Note that the test doesn't check TCP connection
 *            behavior (that the kernel linger while closing socket
 *            with the linger bit is switched on etc), it only tries
 *            to reuse many times sockets with @c SO_LINGER option set
 *            on them.
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
 * @param linger_non_zero @c TRUE, if linger bit should be set to
 *                        non-zero value, @c FALSE otherwise
 * @param overfill_buffers
 *                        @c TRUE, if each connection client side socket
 *                        buffer should be overfilled, @c FALSE otherwise
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
 *             -# Close @p conns_s[@p j];
 *             -# Create @c SOCK_STREAM socket @p conn_s[@p j] on @p
 *                pco_tst;
 *             -# Call @b connect() on @p conn_s[@p j] towards
 *                @p addr_to_connect;
 *             -# Call @b accept() on @p iut_s on @p p, 
 *                let @p acc_s[@p j] be the result of the call;  
 *     -# For each process @p p from @p p_list do:
 *         -# For @p j = 0, @p j < @c MAX_CONNECTIONS_PER_PROCCESS:
 *             -# Check that @p acc_s[@p j] @p <= 
 *                @p max_fd + @p fd_cache_size;
 *                        
 * @note
 *    When l_linger is set to non-zero value and the linger time
 *    expires before the remaining data is sent and acknowledged,
 *    @b close() returns @c EWOULDBLOCK. Current implementation
 *    doesn't support this feature, i.e. @b close() always returns 
 *    @c 0.
 *    
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 */

#define TE_TEST_NAME    "level5/fd_caching/set_linger"

#include "sockapi-test.h"
#include "tapi_cfg_base.h"
#include "tapi_rpc_unistd.h"
#include "tapi_rpc_misc.h"
#include "fd_cache.h"

#define PROCESSES_MAX_NUM               16
#define MAX_CONNECTIONS_PER_PROCCESS    1
#define PROCESS_MAX_NAME_LEN            24 
#define MAX_BACKLOG                     (PROCESSES_MAX_NUM * MAX_CONNECTIONS_PER_PROCCESS)
#define START_DELAY                     8

/** 
 * Process related information, process id, 
 * list of accepted sockets in that process,
 * and list of connected sockets on the only
 * process on tester node.
 */
typedef struct p_info_set_linger {
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

    tarpc_linger    optval;

    int             i;
    int             j;

    char            name[PROCESS_MAX_NAME_LEN] = {0,};

    int             num_of_cycles;
    int             fd_cache_size_val;
    int             max_fd = -1;
    
    const char     *default_fd_cache_size = NULL;
    const char     *fd_cache_size = NULL;    
    char           *old_fd_cache_size = NULL;

    te_bool         linger_non_zero;
    te_bool         overfill_buffers;

    /* Preambule */
    TEST_START;
  
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    
    TEST_GET_ADDR(pco_iut, addr_to_connect);
    TEST_GET_ADDR_NO_PORT(wldc);
    SIN(wldc)->sin_port = SIN(addr_to_connect)->sin_port;

    TEST_GET_INT_PARAM(p_number);
    TEST_GET_INT_PARAM(num_of_cycles);
    TEST_GET_STRING_PARAM(default_fd_cache_size);
    TEST_GET_STRING_PARAM(fd_cache_size);

    TEST_GET_BOOL_PARAM(linger_non_zero);
    TEST_GET_BOOL_PARAM(overfill_buffers);

    SET_ENV_VAR(pco_iut, EF_EPCACHE_MAX, 
                fd_cache_size, old_fd_cache_size);
    fd_cache_size_val = (uint16_t)strtoul(fd_cache_size, NULL, 0);

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
        CHECK_RC(rcf_rpc_server_fork(pco_iut, name, &(p_current->p)));

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
                rpc_close(pco_tst, p_current->conn_s[j]);

                p_current->conn_s[j] = 
                    rpc_socket(pco_tst, RPC_AF_INET,
                               RPC_SOCK_STREAM, RPC_PROTO_DEF);
                rpc_connect(pco_tst, p_current->conn_s[j], addr_to_connect);
                p_current->acc_s[j] = rpc_accept(p_current->p, iut_s, 
                                                 NULL, NULL);
            }    
        }

        for (i = 0, p_current = p_list; i < p_number; i++, p_current++)
        {
            for (j = 0; j < MAX_CONNECTIONS_PER_PROCCESS; j++)
            {
                if (p_current->acc_s[j] > max_fd + fd_cache_size_val)
                    TEST_FAIL("FD leaking? "
                              "accepted socket %d, max_fd %d, "
                              "fd cache size %d", 
                              p_current->acc_s[j], max_fd, 
                              fd_cache_size_val);
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
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(p_current->p));
    }
    if (p_list != NULL)
        free(p_list);
    
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    RESTORE_ENV_VAR(pco_iut, EF_EPCACHE_MAX, 
                    (old_fd_cache_size == NULL) ? 
                    default_fd_cache_size : old_fd_cache_size);
    TEST_END;
}
