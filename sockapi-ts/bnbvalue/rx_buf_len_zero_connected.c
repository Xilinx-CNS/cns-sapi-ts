/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-rx_buf_len_zero_connected Using zero length receive buffer on connected socket
 *
 * @objective Check that receive functions allow dummy receiving in zero
 *            length buffer on connected sockets.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param sock_type     Socket type that can be  @c SOCK_STREAM or
 *                      @c SOCK_DGRAM
 * @param func          Function used in the test:
 *                      - @ref arg_types_recv_func
 *                      - @b aio_read()
 * @param buffer        @c FALSE if @c NULL or @c TRUE in case of the
 *                      real buffer
 * @param env           Test environment
 *                       - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 *
 * @par Scenario:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/rx_buf_len_zero_connected"

#include "sockapi-test.h"

#define TST_TXBUF_LEN  300
#define TST_RXBUF_LEN  0

int
main(int argc, char *argv[])
{
    int                sent;
    rcf_rpc_server    *pco_iut = NULL;
    rcf_rpc_server    *pco_tst = NULL;
    int                iut_s = -1;
    int                tst_s = -1;
    rpc_socket_type    sock_type;
    rpc_recv_f         func;
    te_bool            buffer;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    void                   *tx_buf = NULL;
    size_t                  txbuf_len = TST_TXBUF_LEN;
    void                   *rx_buf = NULL;
    const size_t            rxbuf_len = TST_RXBUF_LEN;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(buffer);
    TEST_GET_RECV_FUNC(func);

    if (strcmp(rpc_recv_func_name(func), "onload_zc_recv") == 0)
        TEST_VERDICT("This test is not applicable for onload_zc_recv() "
                     "function");

    tx_buf = te_make_buf_by_len(TST_TXBUF_LEN);

    /* Prepare data to receive by means of: */
    /* read(), recv(), recvfrom() */
    if (buffer)
        rx_buf = te_make_buf_by_len(TST_TXBUF_LEN);
    else
        rx_buf = NULL;

    /* Scenario */
    TEST_STEP("Get connection for test purposes.");
    GEN_CONNECTION_WILD(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                        iut_addr, tst_addr, &iut_s, &tst_s, TRUE);

    TEST_STEP("Write() some data to @b tst_s socket.");
    RPC_WRITE(sent, pco_tst, tst_s, tx_buf, txbuf_len);

    /* Fixme: disable msg_flags auto check for datagrams. In case of
     * incomplete reading of a datagram flag MSG_TRUNC is set, what is
     * detected by the check. If msg_flags check is desired then explicit
     * call of recvmsg() like functions should be done with subsequent
     * flags check.
     *
     * This does not require any reversion, i.e. the check is disabled only
     * for the current test run. */
    if (sock_type == RPC_SOCK_DGRAM)
        tapi_rpc_msghdr_msg_flags_init_check(FALSE);

    TEST_STEP("Call @p func on @b iut_s socket with @c 0 as buffer length");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = func(pco_iut, iut_s, rx_buf, rxbuf_len, 0);

    TEST_STEP("Check that the function immediately returns @c 0.");
    if (rc > 0)
    {
        RING("Unexpected behaviour of %s(), returned code %d "
             "instead of 0", rpc_recv_func_name(func), rc);
        TEST_VERDICT("Receive function unexpectedly returned positive value");
    }
    else if (rc < 0)
    {
        RING("Unexpected behaviour of %s(), returned code %d "
             "instead of 0", rpc_recv_func_name(func), rc);
        TEST_VERDICT("Receive function unexpectedly failed with errno %r",
                     RPC_ERRNO(pco_iut));
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(tx_buf);
    free(rx_buf);

    TEST_END;
}
