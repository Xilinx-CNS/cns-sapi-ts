/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page sockopts-sndtimeo Usage of SO_SNDTIMEO socket option with stream sockets
 *
 * @objective Check that @c SO_SNDTIMEO option allows to place timeout
 *            on socket send operations.
 *
 * @type conformance
 *
 * @reference @ref STEVENS, section 7.5
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param func          Send function to be tested with the option:
 *                      - @b write
 *                      - @b sys_write
 *                      - @b writev
 *                      - @b sys_writev
 *                      - @b send
 *                      - @b sendto
 *                      - @b sendmsg
 *                      - @b sendmmsg
 *                      - @b onload_zc_send
 *                      - @b onload_zc_send_user_buf
 *                      - @b template_send
 * @param is_blocking   Whether we should test socket without or with
 *                      @c O_NONBLOCK flag set on it
 * @param onload_template_extension  Option determines iterations which are
 *                                   applicable only for Onload
 *                                   templates API.
 * @param flags_pio_retry            If it is @c TRUE set flag
 *                                   @c ONLOAD_TEMPLATE_FLAGS_PIO_RETRY
 *
 * @par Test sequence:
 *
 * -# Create @p pco_iut socket of type @c SOCK_STREAM on @p pco_iut.
 * -# Create @p pco_tst socket of type @c SOCK_STREAM on @p pco_tst.
 * -# Create a buffer @p tx_buf of an arbitrary number of bytes.
 * -# Call @b setsockopt() on @p pco_iut socket with @c SO_SNDTIMEO
 *    option specifying @p timeout as its value.
 * -# Bind @p pco_tst socket to a local address and port.
 * -# Call @b listen() on @p pco_tst socket.
 * -# @b Connect() @p pco_iut socket to @p pco_tst.
 * -# Call @b accept() on @p pco_tst socket to get a new connection
 *    @p accepted.
 * -# If !(@p is_blocking), set @c O_NONBLOCK flag on @p iut_s.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# If @p onload_template_extension is @c FALSE:
 *   -# Repeatedly call @p func function on @p pco_iut socket sending
 *      @p tx_buf buffer.
 *   -# If the function returns @c -1, go to the next step, otherwise
 *      repeat sending.
 *   -# Check that @b errno is set to @c EAGAIN.
 * -# else perform the following actions until send buffer is overfilled:
 *   -# Allocate template buffer, set flag
 *      @c ONLOAD_TEMPLATE_FLAGS_PIO_RETRY in dependence
 *      on @p flags_pio_retry. If the flag is set @b onload_msg_template_alloc
 *      will fail with errno @c EBUSY once the buffer is overfilled, else
 *      the allocation should fail with errno @c ENOME, once PIO buffer is
 *      filled.
 *   -# Call @b onload_msg_template_update() to send packet. Use flag
 *      @c ONLOAD_TEMPLATE_FLAGS_DONTWAIT if @p is_blocking is @c TRUE.
 * -# Check that the duration of the last call @p func function is
 *    @p timeout if @c O_NONBLOCK was not set or @c 0 otherwise;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Delete @p tx_buf buffer;
 * -# Close @p accepted, @p pco_tst and @p pco_iut sockets.
 * 
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/sndtimeo"

#include "sockapi-test.h"


#define TST_VEC        3

/* Timeout in seconds */
#define TST_SNDTIMEO   2

/*
 * Additional inaccuracy due to auxiliary steps
 * in RPC call implementation of onload_zc_send().
 */
#define ZC_SEND_INACCURACY (TST_TIME_INACCURACY / 5)

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;
    int             accepted = -1;
    rpc_send_f      func;
    int             ret;
    int             flags = 0;

    tarpc_timeval           optval;
    te_bool                 is_blocking;
    te_bool                 onload_template_extension;
    te_bool                 flags_pio_retry;
    te_bool                 check_errno = TRUE;
    const struct sockaddr  *tst_addr;
    void                   *tx_buf = NULL;
    size_t                  buf_len = 512;
    uint64_t                expected;

    rpc_onload_template_handle handle = 0;
    struct rpc_iovec           vector = {tx_buf, buf_len, buf_len};

    uint64_t add_inaccuracy = 0;

    TEST_START;
    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SEND_FUNC(func);
    TEST_GET_BOOL_PARAM(is_blocking);
    TEST_GET_BOOL_PARAM(onload_template_extension);
    if (onload_template_extension)
        TEST_GET_BOOL_PARAM(flags_pio_retry);

    if (func == rpc_send_func_template_send)
    {
        sockts_kill_zombie_stacks(pco_iut);
        flags = RPC_ONLOAD_TEMPLATE_FLAGS_PIO_RETRY;
    }

    if (func == rpc_send_func_onload_zc_send ||
        func == rpc_send_func_onload_zc_send_user_buf)
        add_inaccuracy = ZC_SEND_INACCURACY;

    /* Prepare data to transmit by means of: */
    /* write(), send(), sendto() */
    tx_buf = te_make_buf_by_len(buf_len);
    vector.iov_base = tx_buf;

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_bind(pco_tst, tst_s, tst_addr);
    rpc_listen(pco_tst, tst_s, 1);

    rpc_connect(pco_iut, iut_s, tst_addr);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    optval.tv_sec = TST_SNDTIMEO;
    optval.tv_usec = 0;
    ret = rpc_setsockopt(pco_iut, iut_s, RPC_SO_SNDTIMEO, &optval);
    if (ret != 0)
        TEST_VERDICT("setsockopt(SOL_SOCKET, SO_SNDTIMEO, {%d,%d}) "
                     "failed with errno %s", (int)optval.tv_sec,
                     (int)optval.tv_usec,
                     errno_rpc2str(RPC_ERRNO(pco_iut)));

    memset(&optval, 0, sizeof(optval));
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_SNDTIMEO, &optval);
    if ((optval.tv_sec != TST_SNDTIMEO) ||
        (optval.tv_usec != 0))
        TEST_FAIL("Unexpected optval returned by getsockopt()");

    if (is_blocking)
        expected = TST_SNDTIMEO * 1000000;
    else
        expected = 0;

    if (!onload_template_extension)
    {
        if (!is_blocking)
            rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, RPC_O_NONBLOCK);

        if (func == rpc_send_func_onload_zc_send_user_buf)
        {
            /*
             * RPC call for checking onload_zc_send() with user buffers
             * waits for completion of sent buffers before returning
             * (i.e. for arrival of ACK from the peer), so it cannot
             * be used to overfill socket buffers (it will fail due to
             * RPC call timeout).
             */

            RPC_AWAIT_ERROR(pco_iut);
            rc = rpc_overfill_buffers(pco_iut, iut_s, NULL);
            if (rc < 0)
            {
                TEST_VERDICT("rpc_overfill_buffers() failed with error %r",
                             RPC_ERRNO(pco_iut));
            }

            RPC_AWAIT_ERROR(pco_iut);
            rc = func(pco_iut, iut_s, tx_buf, buf_len, flags);
            if (rc >= 0)
            {
                TEST_VERDICT("The sending function succeeded after "
                             "overfilling socket buffers");
            }
        }
        else
        {
            do {
                RPC_AWAIT_IUT_ERROR(pco_iut);
            } while (func(pco_iut, iut_s, tx_buf, buf_len, flags) != -1);
        }
    }
    else
    {
        flags = RPC_ONLOAD_TEMPLATE_FLAGS_SEND_NOW;
        if (!is_blocking)
            flags |= RPC_ONLOAD_TEMPLATE_FLAGS_DONTWAIT;

        do {
            RPC_AWAIT_IUT_ERROR(pco_iut);
            rc = rpc_onload_msg_template_alloc(pco_iut, iut_s, &vector, 1,
                                               &handle, flags_pio_retry ?
                                   RPC_ONLOAD_TEMPLATE_FLAGS_PIO_RETRY : 0);
            if (rc != 0)
            {
                CHECK_RPC_ERRNO(pco_iut,
                                flags_pio_retry ? RPC_EBUSY : RPC_ENOMEM,
                                "Unexpected errno after "
                                "onload_msg_template_alloc()");
                check_errno = FALSE;
                expected = 0;
                break;
            }

            RPC_AWAIT_IUT_ERROR(pco_iut);
        } while (rpc_onload_msg_template_update(pco_iut, iut_s, handle,
                                                NULL, 0, flags) == 0);
    }

    if (check_errno)
        CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN, "Unexpected errno");

    CHECK_CALL_DURATION_INT_GEN(pco_iut->duration,
                                TST_TIME_INACCURACY + add_inaccuracy,
                                TST_TIME_INACCURACY_MULTIPLIER,
                                expected, expected, ERROR, TEST_VERDICT,
                                "%s() call took too much time",
                                rpc_send_func_name(func));

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, accepted);

    free(tx_buf);

    TEST_END;
}
