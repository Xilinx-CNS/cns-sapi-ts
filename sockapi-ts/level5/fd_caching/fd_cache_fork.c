/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * FD caching
 * 
 * $Id$
 */

/** @page fd_caching-fd_cache_fork FD cachin with fork
 *
 * @objective  Check that Onload FD caching is completely disabled after
 *             calling fork().
 *
 * @type conformance
 *
 * @param pco_iut       RPC server on iut node
 * @param pco_tst       RPC server on tester node 
 * @param sockets_num   Accepted sockets number
 * @param position      Determine position where fork() is called
 *
 * @par Test sequence:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME    "level5/fd_caching/fd_cache_fork"

#include "sockapi-test.h"
#include "fd_cache.h"

/**
 * Positions where fork() can be called.
 */
typedef enum {
    FP_BEFORE_LISTEN = 0,   /**< Before listen() */
    FP_AFTER_LISTEN,        /**< Straight the after listen() */
    FP_OPENED,              /**< All sockets are accepted */
    FP_CLOSED               /**< All accepted sockets are closed */
} fork_position;

#define FORK_POSITION  \
    { "before_listen", FP_BEFORE_LISTEN },  \
    { "after_listen", FP_AFTER_LISTEN },    \
    { "opened", FP_OPENED },                \
    { "closed", FP_CLOSED }

#define CALL_FORK(_pos_c, _pos_o) \
do {                                                                        \
    if (pco_iut_aux == NULL && _pos_c == _pos_o)                            \
        CHECK_RC(rcf_rpc_server_fork(pco_iut, "iut_child", &pco_iut_aux));  \
} while (0)

int
main(int argc, char *argv[])
{
    const struct sockaddr     *iut_addr;
    const struct sockaddr     *tst_addr;

    /* FIXME: Remove pco_iut2 when debug is finished. */
    rcf_rpc_server *pco_iut2 = NULL;
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_iut_aux = NULL;
    rcf_rpc_server *rpcs = NULL;
    rcf_rpc_server *pco_tst = NULL;
    fork_position position;
    int sockets_num;

    int *iut_acc = NULL;
    int *tst_s = NULL;
    int iut_s = -1;
    int count = 0;
    int iter = 0;
    int iter_num = 1;
    int num = 0;
    int i;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(sockets_num);
    TEST_GET_ENUM_PARAM(position, FORK_POSITION);

    num = sockets_num * 2;
    iut_acc = te_calloc_fill(num, sizeof(*iut_acc), -1);
    tst_s = te_calloc_fill(num, sizeof(*tst_s), -1);
    num = sockets_num;

    TEST_STEP("Open TCP socket.");
    iut_s = rpc_socket(pco_iut, RPC_AF_INET, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    TEST_STEP("Bind the IUT socket.");
    rpc_bind(pco_iut, iut_s, iut_addr);

    TEST_STEP("Call fork here or later in dependence on parameter @p position.");
    CALL_FORK(position, FP_BEFORE_LISTEN);

    TEST_STEP("Call listen() on IUT socket.");
    rpc_listen(pco_iut, iut_s, -1);

    TEST_STEP("Call listen() for the cloned socket if fork() has already been "
              "called.");
    if (pco_iut_aux != NULL)
        rpc_listen(pco_iut_aux, iut_s, -1);

    CALL_FORK(position, FP_AFTER_LISTEN);

    TEST_STEP("Repeat the following actions twice if @p position is @c closed. it's "
              "to check that new accepted sockets won't use the cached before "
              "fds.");
    if (position == FP_CLOSED)
        iter_num = 2;

    if (pco_iut_aux != NULL)
        num = sockets_num * 2;

    for (iter = 0; iter < iter_num; iter++)
    {
        TEST_STEP("In the loop create socket on tester side and connect it to IUT, "
                  "accept the socket on IUT side. Iterations number is equal to "
                  "@p sockets_num multiplied to the current processes number.");
        for (i = 0; i < num; i++)
        {
            tst_s[i] = rpc_socket(pco_tst, RPC_AF_INET, RPC_SOCK_STREAM, RPC_PROTO_DEF);
            rpc_connect(pco_tst, tst_s[i], iut_addr);
            if (pco_iut_aux != NULL && i >= sockets_num)
                iut_acc[i] = rpc_accept(pco_iut_aux, iut_s, NULL, NULL);
            else
                iut_acc[i] = rpc_accept(pco_iut, iut_s, NULL, NULL);
        }

        CALL_FORK(position, FP_OPENED);

        TEST_STEP("Close the accepted sockets and calculate how many of them was "
                  "cached.");
        for (i = 0; i < num; i++)
        {
            if (i >= sockets_num)
                rpcs = pco_iut_aux;
            else
                rpcs = pco_iut;

            rpc_close(rpcs, iut_acc[i]);
            RPC_CLOSE(pco_tst, tst_s[i]);

            if (tapi_onload_socket_is_cached(rpcs, iut_acc[i]))
                count++;
        }

        TEST_STEP("Close the cloned accepted sockets if @p posiotion is "
                  "@c opened.");
        if (position == FP_OPENED)
        {
            for (i = 0; i < num; i++)
            {
                rpc_close(pco_iut_aux, iut_acc[i]);
                if (tapi_onload_socket_is_cached(pco_iut_aux, iut_acc[i]))
                    count++;
            }
            num = sockets_num * 2;
        }

        CALL_FORK(position, FP_CLOSED);

        if (position == FP_CLOSED)
        {
            TAPI_WAIT_NETWORK;
            count = 0;

            for (i = 0; i < num; i++)
            {
                if (tapi_onload_socket_is_cached(pco_iut, iut_acc[i]))
                    count++;
                if (tapi_onload_socket_is_cached(pco_iut_aux, iut_acc[i]))
                    count++;
            }
            num = sockets_num * 2;
        }

        RING("Cached sockets number %d, total accepted/cloned %d",
             count, num);

        /* FIXME: Remove logging when debug is finished. */
        rpc_system(pco_iut2, "te_onload_stdump lots | grep cache");
        usleep(20000);

        TEST_STEP("No sockets must be cached after the fork.");
        if (count > 0)
            RING_VERDICT("There are cached sockets after the fork");
    }

    TEST_SUCCESS;

cleanup:
    clean_sockets(pco_iut, iut_acc, num);
    clean_sockets(pco_iut, tst_s, num);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    rcf_rpc_server_destroy(pco_iut_aux);

    TEST_END;
}
