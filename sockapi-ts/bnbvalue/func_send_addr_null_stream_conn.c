/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_send_addr_null_stream_conn Using NULL pointer as address in sendto()-like functions with connected SOCK_STREAM socket
 *
 * @objective Check that @b sendto()-like function ignores @p address
 *            and @p address_len parameters when it is called on
 *            connected @c SOCK_STREAM socket.
 *
 * @type conformance, robustness
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param addrlen   Pass zero address length if @c TRUE, else - non-zero.
 * @param func      Tested function:
 *                  - sendto
 *                  - sendmsg
 *                  - sendmmsg
 *                  - onload_zc_send
 *
 * @par Scenario:
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_send_addr_null_stream_conn"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_tst = NULL;
    te_bool             addrlen;
    rpc_sendto_f        func;

    struct sockaddr    *addr = NULL;
    tarpc_sa           *rpc_sa = NULL;

    const struct sockaddr  *tst_addr = NULL;
    const struct sockaddr  *iut_addr = NULL;

    int     iut_s = -1;
    int     tst_s = -1;

    void   *tx_buf = NULL;
    void   *rx_buf = NULL;
    size_t  tx_buflen;
    size_t  rx_buflen;

    ssize_t sent;
    ssize_t r;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_BOOL_PARAM(addrlen);
    TEST_GET_SENDTO_FUNC(func);

    CHECK_NOT_NULL(tx_buf = sockts_make_buf_stream(&tx_buflen));
    rx_buf = te_make_buf_min(tx_buflen, &rx_buflen);

    TEST_STEP("Create connection of @c SOCK_STREAM type between socket "
              "@b iut_s on @p pco_iut and @b tst_s on @p pco_tst by means of "
              "@p GEN_CONNECTION;");
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    CHECK_NOT_NULL(addr = sockaddr_to_te_af(NULL, &rpc_sa));
    if (addrlen)
        rpc_sa->len = rpc_get_sizeof(pco_iut,
            addr_family_sockaddr_str(addr_family_h2rpc(tst_addr->sa_family)));

    TEST_STEP("Call @p func on @p pco_iut socket passing @c NULL as the "
              "value of @a address parameter and zero or size of an "
              "appropriate sockaddr structure as the value of @a address_len "
              "parameter. Check that it returns number of sent bytes.");
    RPC_AWAIT_ERROR(pco_iut);
    sent = func(pco_iut, iut_s, tx_buf, tx_buflen, 0, addr);
    if (sent < 0)
    {
        TEST_VERDICT("%s() with NULL destination address and %s "
                     "address length called on connected SOCK_STREAM "
                     "sockets returned %d with " RPC_ERROR_FMT " errno "
                     "instead of number of sent bytes",
                     rpc_sendto_func_name(func),
                     addrlen ? "non-zero" : "0", sent,
                     RPC_ERROR_ARGS(pco_iut));
    }

    TEST_STEP("Receive data from @b tst_s socket and check that received data "
              "match the sent one.");
    r = rpc_recv(pco_tst, tst_s, rx_buf, rx_buflen, 0);
    if (r != sent || memcmp(tx_buf, rx_buf, sent) != 0)
    {
        TEST_FAIL("Incorrect amount or data itself are received");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(tx_buf);
    free(rx_buf);
    free(addr);

    TEST_END;
}
