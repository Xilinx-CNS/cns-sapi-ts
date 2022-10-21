/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Onload extensions
 */

/**
 * @page extension-zc_send_user_buf_overfill Overfill send buffer with onload_zc_send() using registered buffers
 *
 * @objective Check that if send buffer is overfilled with
 *            @b onload_zc_send() using registered ZC buffers, after reading
 *            all data from peer socket all the queued ZC buffers eventually
 *            become completed and all the data in them is received by peer.
 *
 * @param env               Network environment configuration:
 *                          - @ref arg_types_env_peer2peer
 *                          - @ref arg_types_env_peer2peer_ipv6
 * @param sock_type         Socket type:
 *                          - @c tcp_active
 *                          - @c tcp_passive
 *                          - @c tcp_passive_close
 * @param msg_dontwait      If @c TRUE, pass @c MSG_DONTWAIT flag to
 *                          @b onload_zc_send() until @c EAGAIN is reported;
 *                          otherwise call onload_zc_send() until it hangs.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "level5/extension/zc_send_user_buf_overfill"

#include "sockapi-test.h"
#include "onload.h"

/** Maximum number of iovecs passed to onload_zc_send() */
#define MAX_IOVS 5
/** Maximum length of the single sent buffer */
#define MAX_BUF_LEN 2048
/** Minimum total size of registered buffer */
#define MIN_TOTAL_LEN 2000000

/**
 * A number by which total space in socket buffers will be
 * multiplied to get size of allocated and registered buffer
 */
#define BUFS_LEN_MULTIPLIER 10

/**
 * Check value returned by rpc_simple_zc_send_gen().
 *
 * @param pref        Prefix to print in verdicts.
 * @param pco_iut     RPC server on IUT.
 * @param rc          Return value.
 * @param mmsg_rc     Value from mmsg.rc.
 * @param exp_eagain  If TRUE, EAGAIN error is expected.
 * @param failed      Will be set to TRUE if some failure occurred.
 */
static void
check_zc_send_rc(const char *pref, rcf_rpc_server *pco_iut,
                 int rc, int mmsg_rc, te_bool exp_eagain,
                 te_bool *failed)
{
    if (rc < 0)
    {
        ERROR_VERDICT("%s: onload_zc_send() call failed with error "
                      RPC_ERROR_FMT, pref, RPC_ERROR_ARGS(pco_iut));
        *failed = TRUE;
    }
    else if (rc == 0)
    {
        ERROR_VERDICT("%s: no messages was sent", pref);
        *failed = TRUE;
    }
    else if (rc > 1)
    {
        ERROR_VERDICT("%s: too big number of sent messages was returned by "
                      "RPC call", pref);
        *failed = TRUE;
    }
    else if (mmsg_rc < 0)
    {
        if (exp_eagain && mmsg_rc == -RPC_EAGAIN)
        {
            return;
        }
        else
        {
            ERROR_VERDICT("%s: onload_zc_send() call returned unexpected "
                          "error %r in mmsg.rc", pref, -mmsg_rc);
            *failed = TRUE;
        }
    }
    else if (mmsg_rc == 0)
    {
        ERROR_VERDICT("%s: onload_zc_send() call returned zero in mmsg.rc",
                      pref);
        *failed = TRUE;
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    int64_t sys_page_size = 0;

    int iut_s = -1;
    int iut_l = -1;
    int tst_s = -1;
    int iut_sndbuf = 0;
    int tst_rcvbuf = 0;

    int64_t total_size = 0;
    int64_t alloc_size = 0;
    int64_t queued_size = 0;
    uint64_t sent_len = 0;
    uint64_t read_len = 0;

    rpc_ptr buf_ptr = RPC_NULL;
    rpc_onload_zc_handle buf_handle = RPC_NULL;
    rpc_ptr compl_queue = RPC_NULL;

    struct rpc_onload_zc_mmsg mmsg;
    rpc_iovec iovs[MAX_IOVS];
    char bufs[MAX_IOVS][MAX_BUF_LEN];
    struct tarpc_onload_zc_buf_spec buf_specs[MAX_IOVS];
    int iovs_num;
    int i;
    te_bool done = FALSE;
    te_bool failed = FALSE;

    te_bool msg_dontwait;
    sockts_socket_type sock_type;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(msg_dontwait);

    sys_page_size = rpc_sysconf(pco_iut, RPC_SC_PAGESIZE);

    TEST_STEP("Create a pair of connected sockets according to @p sock_type.");
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr, sock_type,
                      &iut_s, &tst_s, &iut_l);

    TEST_STEP("Obtain size of send buffer on the IUT socket and "
              "size of receive buffer on the Tester socket.");

    rpc_getsockopt(pco_iut, iut_s, RPC_SO_SNDBUF, &iut_sndbuf);
    rpc_getsockopt(pco_tst, tst_s, RPC_SO_RCVBUF, &tst_rcvbuf);

    total_size = MAX(MIN_TOTAL_LEN,
                     (iut_sndbuf + tst_rcvbuf) * BUFS_LEN_MULTIPLIER);
    alloc_size = sys_page_size * (total_size / sys_page_size + 1);

    TEST_STEP("Allocate with @b memalign() a page-aligned buffer on IUT "
              "of size which is multiple of system page size and is "
              "larger than available space in send socket buffer on IUT "
              "plus receive socket buffer on Tester.");
    rpc_posix_memalign(pco_iut, &buf_ptr, sys_page_size, alloc_size);

    TEST_STEP("Register the allocated buffer with "
              "@b onload_zc_register_buffers().");
    rpc_onload_zc_register_buffers(pco_iut, iut_s,
                                   SOCKTS_EF_ADDRSPACE_LOCAL,
                                   buf_ptr, 0, alloc_size, 0, &buf_handle);

    TEST_STEP("Allocate a queue on IUT to keep track of queued ZC buffers "
              "for which completion messages have not yet arrived.");
    compl_queue = rpc_sockts_alloc_zc_compl_queue(pco_iut);

    memset(iovs, 0, sizeof(iovs));
    memset(buf_specs, 0, sizeof(buf_specs));
    for (i = 0; i < MAX_IOVS; i++)
    {
        iovs[i].iov_base = bufs[i];
        buf_specs[i].type = TARPC_ONLOAD_ZC_BUF_EXIST_REG;
        buf_specs[i].buf_handle = buf_handle;
        buf_specs[i].existing_buf = buf_ptr;
    }

    memset(&mmsg, 0, sizeof(mmsg));
    mmsg.msg.msg_iov = iovs;
    mmsg.fd = iut_s;
    mmsg.buf_specs = buf_specs;

    TEST_STEP("Call @b onload_zc_send() in a loop, sending data from the "
              "registered buffer until all the data is sent, or until "
              "@c EAGAIN error is reported (if @p msg_dontwait is "
              "@c TRUE), or until the function blocks (if @p msg_dontwait "
              "is @c FALSE).");
    TEST_SUBSTEP("After each @b onload_zc_send() call read all the "
                 "available completion messages.");

    while (queued_size < alloc_size)
    {
        iovs_num = rand_range(1, MAX_IOVS);
        for (i = 0; i < iovs_num; i++)
        {
            iovs[i].iov_len = rand_range(1, MIN(MAX_BUF_LEN,
                                                alloc_size - queued_size));
            iovs[i].iov_rlen = iovs[i].iov_len;
            buf_specs[i].buf_offset = queued_size;
            queued_size += iovs[i].iov_len;
            if (queued_size >= alloc_size)
            {
                iovs_num = i + 1;
                break;
            }
        }

        mmsg.msg.msg_iovlen = mmsg.msg.msg_riovlen = iovs_num;

        if (!msg_dontwait)
        {
            pco_iut->op = RCF_RPC_CALL;
            rpc_simple_zc_send_gen(pco_iut, &mmsg, 1, 0,
                                   -1, FALSE, compl_queue, NULL);

            MSLEEP(10);
            CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));
            if (!done)
            {
                MSLEEP(TAPI_WAIT_NETWORK_DELAY);
                CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));
                if (!done)
                    break;
            }
        }

        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_simple_zc_send_gen(pco_iut, &mmsg, 1,
                                    (msg_dontwait ? RPC_MSG_DONTWAIT : 0),
                                    -1, FALSE, compl_queue, NULL);
        check_zc_send_rc("Not blocked call", pco_iut, rc, mmsg.rc,
                         msg_dontwait, &failed);
        if (rc != 1 || mmsg.rc <= 0)
            break;

        sent_len += mmsg.rc;
        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_sockts_proc_zc_compl_queue(pco_iut, compl_queue, 0);
        if (rc < 0)
        {
            TEST_VERDICT("Intermediary call of "
                         "rpc_sockts_proc_zc_compl_queue() failed with "
                         "error " RPC_ERROR_FMT, RPC_ERROR_ARGS(pco_iut));
        }
    }


    if (!msg_dontwait && done)
    {
        ERROR_VERDICT("onload_zc_send() has never blocked");
        failed = TRUE;
    }

    TEST_STEP("Read all the data from the Tester socket.");
    rpc_drain_fd_simple(pco_tst, tst_s, &read_len);

    if (!msg_dontwait && !done)
    {
        TEST_STEP("If @p msg_dontwait is @c FALSE and the last "
                  "@b onload_zc_send() call blocked, check that "
                  "now it unblocks and succeeds.");
        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_simple_zc_send_gen(pco_iut, &mmsg, 1, 0,
                                    -1, FALSE, compl_queue, NULL);
        check_zc_send_rc("Last blocked call", pco_iut, rc, mmsg.rc,
                         FALSE, &failed);

        if (rc == 1 && mmsg.rc > 0)
            sent_len += mmsg.rc;
    }

    TEST_STEP("Check that the number of bytes received on Tester matches "
              "the number of bytes sent from IUT.");

    RING("%" TE_PRINTF_64 "u bytes were sent, %" TE_PRINTF_64 "u bytes "
         "were received", sent_len, read_len);
    if (read_len < sent_len)
    {
        ERROR_VERDICT("Too little bytes were received on peer");
        failed = TRUE;
    }
    else if (read_len > sent_len)
    {
        ERROR_VERDICT("Too many bytes were received on peer");
        failed = TRUE;
    }

    TEST_STEP("Check that completion messages for all the queued ZC "
              "buffers eventually arrived.");
    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_sockts_proc_zc_compl_queue(pco_iut, compl_queue,
                                        TAPI_WAIT_NETWORK_DELAY);
    if (rc < 0)
    {
        TEST_VERDICT("The final rpc_sockts_proc_zc_compl_queue() call "
                     "failed with error " RPC_ERROR_FMT,
                     RPC_ERROR_ARGS(pco_iut));
    }
    else if (rc > 0)
    {
        TEST_VERDICT("Not all the sent ZC buffers are completed at "
                     "the end");
    }

    if (failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    if (buf_handle != RPC_NULL)
        rpc_onload_zc_unregister_buffers(pco_iut, iut_s, buf_handle, 0);

    if (buf_ptr != RPC_NULL)
        rpc_free(pco_iut, buf_ptr);

    if (compl_queue != RPC_NULL)
        rpc_sockts_free_zc_compl_queue(pco_iut, compl_queue);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_l);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
