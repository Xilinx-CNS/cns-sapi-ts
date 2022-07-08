/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 * 
 * $Id$
 */

/** @page fd_caching-fd_cache_filled 
 *
 * @objective The size of the cache is CI_TCP_EPCACHE_MAX and can be
 *            overwriten by EF_EPCACHE_MAX.
 *            Check that exactly that number of FDs could be cached and
 *            not more than that.
 *
 * @type conformance
 *
 * @param pco_iut         RPC server on iut node
 * @param pco_tst         RPC server on tester node 
 * @param addr_to_connect address on iut node to connect to 
 *                        from tester node 
 *                        CI_TCP_EPCACHE_MAX value
 * @param fd_cache_size   current FD cache size to be set                       
 *
 * @par Test sequence:
 *
 * -# Set @c EF_SOCKET_CACHE_MAX environment variable on @p pco_iut
 *    to @p fd_cache_size;
 * -# Create @c SOCK_STREAM socket @p iut_s on @p pco_iut;
 * -# Bind @p iut_s to wildcard address;
 * -# Call @b listen() on @p iut_s;
 * -# For @p i = 0, @p i < @p fd_cache_size + @p 1 do: 
 *     -# Create @c SOCK_STREAM socket @p tst_s[i] on @p pco_tst;
 *     -# Call @b connect() on @p tst_s[@p i] towards @p addr_to_connect;
 *     -# Call @b accept() on @p iut_s, let @p acc_s[@p i] be the result
 *        of the call;
 * -# For @p i = 0, @p i < @p fd_cache_size do: 
 *     -# Call @b close() on @p acc_s[@p i];
 *     -# Call @b close() on @p tst_s[@p i];
 *     -# Call @b dup() on @p acc_s, check that 
 *        new valid descriptor is returned (fd is cached);
 *     -# Close doubled of acc_s[i], obtained by the
 *        previous step;
 * -# Call @b close() on @p acc_s[@p fd_cache_size + @p 1];
 * -# Call @b close() on @p tst_s[@p fd_cache_size + @p 1]; 
 * -# Call @b dup() on @p acc_s[@p fd_cache_size + @p 1], check that
 *    the call returns @c -1 and errno on @p pco_iut is set to @c EBADF
 *    (fd is not cached but truly closed);
 *
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 */

#define TE_TEST_NAME    "level5/fd_caching/fd_cache_filled"

#include <errno.h>
#include <pthread.h>

#include "sockapi-test.h"
#include "rcf_api.h"
#include "tapi_cfg_base.h"
#include "rcf_rpc.h"
#include "tapi_rpc_unistd.h"
#include "tapi_rpc_stdio.h"
#include "fd_cache.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    int             iut_s = -1;  
    int            *acc_s = NULL;       
    int             doubled = -1;

    rcf_rpc_server *pco_tst = NULL;
    int            *tst_s = NULL;

    int             opt_val = 1;

    const struct sockaddr *addr_to_connect = NULL;
    const struct sockaddr *wldc = NULL;

    int fd_cache_size;           
    int           i;

    /* Preambule */
    TEST_START;
  
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    
    TEST_GET_ADDR(pco_iut, addr_to_connect);
    TEST_GET_ADDR_NO_PORT(wldc);
    SIN(wldc)->sin_port = SIN(addr_to_connect)->sin_port;
    TEST_GET_INT_PARAM(fd_cache_size);

    CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_SOCKET_CACHE_MAX",
                                 fd_cache_size, TRUE, TRUE));

    iut_s = rpc_socket(pco_iut, RPC_AF_INET,
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_setsockopt(pco_iut, iut_s, RPC_SO_REUSEADDR, &opt_val);
    rpc_bind(pco_iut, iut_s, wldc);
    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
    tst_s = (int *)calloc(fd_cache_size + 1, sizeof(int));
    acc_s = (int *)calloc(fd_cache_size + 1, sizeof(int));

    for (i = 0; i < fd_cache_size + 1; i++)
    {
        tst_s[i] = -1;
        acc_s[i] = -1;
    }
    
    /* Connect/accept */
    for (i = 0; i < fd_cache_size + 1; i++)
    {
        tst_s[i] = rpc_socket(pco_tst, RPC_AF_INET,
                              RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_connect(pco_tst, tst_s[i], addr_to_connect);
        acc_s[i] = rpc_accept(pco_iut, iut_s,  NULL, NULL);
    }

    for (i = 0; i < fd_cache_size; i++)
    {
        rpc_close(pco_iut, acc_s[i]);
        rpc_close(pco_tst, tst_s[i]);
        //~ pco_iut->use_libc_once = TRUE;
        doubled = rpc_dup(pco_iut, acc_s[i]);
        rpc_close(pco_iut, doubled);
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    //~ pco_iut->use_libc_once = TRUE;
    doubled = rpc_dup(pco_iut, acc_s[i]);
    if (doubled != -1)
        TEST_FAIL("This time dup must return -1");
    else
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_EBADF,
                        "This time dup returns -1, but");
    }
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    pco_iut->use_libc = TRUE;
    for (i = 0; i < fd_cache_size + 1; i++)
    {
        CLEANUP_RPC_CLOSE(pco_tst, tst_s[i]);
        CLEANUP_RPC_CLOSE(pco_iut, acc_s[i]);
    }
    if (tst_s != NULL)
        free(tst_s);
    if (acc_s != NULL)
        free(acc_s);
    
    TEST_END;
}
