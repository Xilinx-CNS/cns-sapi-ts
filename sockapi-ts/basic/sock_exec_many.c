/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-sock_exec_many No resource leaks after multiple exec()
 *
 * @objective Check that in case of sequence socket-exec-socket-exec the
 *            number of new sockets is N+C, but not 2*N+C.
 *
 * @type conformance
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_peer2peer
 *                      - @ref arg_types_env_peer2peer_ipv6
 * @param iter_num      Number of "socket-exec" iterations:
 *                      - 80
 * @param read_socket   Read data on a socket:
 *                      - none: don't read
 *                      - first: read data on the first socket
 *                      - last: read data on the last socket
 *
 * @par Test sequence:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/sock_exec_many"

#include "sockapi-test.h"

#define BUF_LEN 1024

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst = NULL;
    const struct sockaddr     *iut_addr = NULL;
    struct sockaddr_storage    iut_addr_aux;
    int                        first_s = -1;
    int                        last_s = -1;
    int                        read_s = -1;
    int                        tst_s = -1;

    uint8_t                tx_buf[BUF_LEN];
    uint8_t                rx_buf[BUF_LEN];

    const char            *read_socket;
    int                    iter_num;
    int                    i;

    rpc_socket_domain      domain;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_INT_PARAM(iter_num);
    TEST_GET_STRING_PARAM(read_socket);

    te_fill_buf(tx_buf, BUF_LEN);

    domain = rpc_socket_domain_by_addr(iut_addr);

    tapi_sockaddr_clone_exact(iut_addr, &iut_addr_aux);

    if (strcmp(read_socket, "none") != 0)
    {
        TEST_STEP("If @p read_socket is not @c none, create an UDP socket "
                  "on Tester.");
        tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_DGRAM,
                           RPC_IPPROTO_UDP);
    }

    TEST_STEP("Create first UDP socket on IUT");
    first_s = rpc_socket(pco_iut, domain, RPC_SOCK_DGRAM,
                         RPC_IPPROTO_UDP);
    last_s = read_s = first_s;
    if (strcmp(read_socket, "none") != 0)
        rpc_bind(pco_iut, first_s, SA(&iut_addr_aux));

    TEST_STEP("Repeat following steps @p iter_num times:");
    for (i = 0; i < iter_num; i++)
    {
        TEST_SUBSTEP("Call @b execve() on @p pco_iut");
        CHECK_RC(rcf_rpc_server_exec(pco_iut));
        if (strcmp(read_socket, "none") != 0)
        {
            TEST_SUBSTEP("If @p read_socket is not @c none, send some data "
                      "from the Tester socket and receive it either on the "
                      "first IUT socket (if @p read_socket is @c first) or "
                      "on the IUT socket created the last time "
                      "(if @p read_socket is @c last).");
            rpc_sendto(pco_tst, tst_s, tx_buf, BUF_LEN, 0,
                       SA(&iut_addr_aux));
            rpc_read(pco_iut, read_s, rx_buf, BUF_LEN);
        }
        TEST_SUBSTEP("Create a new UDP socket on IUT. Bind it to @p iut_addr with "
                  "a newly chosen port if @p read_socket is @c last.");
        last_s = rpc_socket(pco_iut, domain, RPC_SOCK_DGRAM,
                            RPC_IPPROTO_UDP);
        if (strcmp(read_socket, "last") == 0)
        {
            TAPI_SET_NEW_PORT(pco_iut, SA(&iut_addr_aux));
            rpc_bind(pco_iut, last_s, SA(&iut_addr_aux));
            read_s = last_s;
        }
    }

    TEST_STEP("Check that FD of the IUT socket created the last time is not "
              "significantly more than FD of the first IUT socket + "
              "@p iter_num.");
    if (last_s - first_s - iter_num > 3)
        TEST_VERDICT("Too many open descriptors");
    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CHECK_RC(rcf_rpc_server_restart(pco_iut));

    TEST_END;
}
