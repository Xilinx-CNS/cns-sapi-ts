/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 */

/** @page sendrecv-peer_close Behaviour of send/receive functions when peer closes its socket
 *
 * @objective Check behaviour of send/receive functions when peer closes
 *            its socket.
 *
 * @type conformance
 *
 * @reference @ref STEVENS section 13.3
 *
 * @param env               Testing environment:
 *                          - @ref arg_types_env_peer2peer
 *                          - @ref arg_types_env_peer2peer_tst
 *                          - @ref arg_types_env_peer2peer_lo
 *                          - @ref arg_types_env_peer2peer_fake
 *                          - @ref arg_types_env_peer2peer_ipv6
 *                          - @ref arg_types_env_peer2peer_tst_ipv6
 *                          - @ref arg_types_env_peer2peer_lo_ipv6
 * @param first             The first I/O function to be called:
 *                          - @b send
 *                          - @b recv
 *                          - @b onload_zc_send
 *                          - @b onload_zc_send_user_buf
 *                          - @b template_send
 *                          - @b onload_zc_recv
 * @param second            The second I/O function to be called:
 *                          - @b send
 *                          - @b recv
 *                          - @b onload_zc_send
 *                          - @b onload_zc_send_user_buf
 *                          - @b template_send
 *                          - @b onload_zc_recv
 * @param overfill_buffers  Overfill IUT send buffer if @c TRUE
 * @param get_err_first     Get SO_ERROR before second I/O function call
 *                          if @c TRUE, else - after.
 *
 * -# Create stream connection between @p pco_iut and @p pco_tst (created
 *    sockets are referred below as @p iut_s and @p tst_s);
 * -# Write to @p iut_s socket while the socket is writable
 *    (i.e. fill in @p iut_s Tx and @p tst_s Rx buffers);
 * -# Close @p tst_s socket;
 * -# Call the @p first I/O function. It must return @c -1 with
 *    @c ECONNRESET errno;
 * -# Check SO_ERROR if @p get_err_first is @c TRUE;
 * -# Call the @p second I/O function. Tx function must return @c -1
 *    with @c EPIPE errno. Rx function must return @c 0;
 * -# Check SO_ERROR if @p get_err_first is @c FALSE;
 * -# Close opened sockets.
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/peer_close"

#include "sockapi-test.h"
#include "iomux.h"
#include "rpc_sendrecv.h"

/**
 * Check SO_ERROR value.
 *
 * @param rpcs              RPC server handler
 * @param sock              Socket descriptor
 * @param overfill_buffers  Overfil IUT send buffer
 * @param exp_error         Expected SO_ERROR value
 */
static void
check_so_error(rcf_rpc_server *rpcs, int sock, te_bool overfill_buffers,
               int exp_error)
{
    int err;

    rpc_getsockopt(rpcs, sock, RPC_SO_ERROR, &err);

    if (overfill_buffers)
    {
        if (err != 0)
            TEST_VERDICT("Non zero SO_ERROR value is returned: %r", err);
    }
    else if (err != exp_error)
        TEST_VERDICT("Unexpected code is returned for SO_ERROR, %r "
                     "instead of %r", err, exp_error);
}

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    void *first;
    void *second;

    te_bool first_send;
    te_bool second_send;
    te_bool overfill_buffers;
    te_bool get_err_first;

    /* Auxiliary variables */
    int     iut_s = -1;
    int     tst_s = -1;
    char    buf[1];
    ssize_t len;

    TEST_START;

    /* Prepare sockets */

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_FUNC(first, first_send);
    TEST_GET_FUNC(second, second_send);
    TEST_GET_BOOL_PARAM(overfill_buffers);
    TEST_GET_BOOL_PARAM(get_err_first);

    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                        tst_addr, iut_addr, &tst_s, &iut_s);

    /* Create conditions for blocking on write operation */
    if (overfill_buffers)
    {
        uint64_t total_filled = 0;

        rpc_overfill_buffers(pco_iut, iut_s, &total_filled);
        RING("To overfill the both send and received buffers "
             "%d bytes are written", (unsigned int)total_filled);
    }

    RPC_CLOSE(pco_tst, tst_s);

    /* Timeout is required to make sure FIN/RST packet is delivered. */
    TAPI_WAIT_NETWORK;

    if (overfill_buffers)
        RPC_AWAIT_IUT_ERROR(pco_iut);
    len = first_send ?
             ((rpc_send_f)first)(pco_iut, iut_s, buf, sizeof(buf), 0) :
             ((rpc_recv_f)first)(pco_iut, iut_s, buf, sizeof(buf), 0);

    if (overfill_buffers)
    {
        if (len != -1)
        {
            TEST_FAIL("Peer closed its socket with not empty Rx queue, "
                      "the first I/O function returned %d instead of -1",
                      (int)len);
        }
        CHECK_RPC_ERRNO(pco_iut, RPC_ECONNRESET,
                        "Peer closed its socket with not empty Rx queue, "
                        "the first I/O function returned -1, but");
    }

    /* Timeout is required after send operation to make sure a reply packet
     * is delivered. */
    if (first_send)
        TAPI_WAIT_NETWORK;

    if (get_err_first)
        check_so_error(pco_iut, iut_s, overfill_buffers,
                       first_send ? RPC_EPIPE : 0);

    if (second_send)
    {
        if (overfill_buffers || first_send)
            RPC_AWAIT_IUT_ERROR(pco_iut);

        len = ((rpc_send_f)second)(pco_iut, iut_s, buf, sizeof(buf), 0);

        if (overfill_buffers || first_send)
        {
            if (len != -1)
            {
                TEST_FAIL("Peer closed its socket, the second I/O function "
                          "returned %d instead of -1", (int)len);
            }
            CHECK_RPC_ERRNO(pco_iut, RPC_EPIPE,
                            "Peer closed its socket, the second I/O "
                            "function returned -1, but");
        }
        else if (len != sizeof(buf))
            TEST_VERDICT("The second I/O function call returned unexpected "
                         "value");
    }
    else
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        len = ((rpc_recv_f)second)(pco_iut, iut_s, buf, sizeof(buf), 0);

        if (len != 0)
        {
            TEST_VERDICT("Peer closed its socket, the second I/O function "
                         "returned %d instead of 0 and sets errno to %s",
                         len, errno_rpc2str(RPC_ERRNO(pco_iut)));
        }
    }

    TAPI_WAIT_NETWORK;
    if (!get_err_first)
    {
        /* OD send call requires delay for retransmit. */
        if (second == rpc_send_func_od_send)
            TAPI_WAIT_NETWORK;

        check_so_error(pco_iut, iut_s, overfill_buffers,
                       (second_send ^ first_send) ? RPC_EPIPE : 0);
    }

    TEST_SUCCESS;
cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CHECK_CLEAR_TRANSPARENT(iut_addr, pco_tst, tst_addr);

    TEST_END;
}
