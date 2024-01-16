/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Timestamps
 */

/** @page timestamps-ts_recvmsg_trunc Receiving truncated data with hardware timestamps
 *
 * @objective Check that @c MSG_TRUNC flag is returned if received data
 *            does not fit into space in msg_iov buffers while timestamps
 *            are also reported in control data. Also check that setting
 *            @c MSG_TRUNC before @b recvmsg() is called has no effect.
 *            Check the same for @c MSG_CTRUNC flag and truncated control
 *            data.
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on Tester
 * @param msg_trunc     If @c TRUE - set flag MSG_TRUNC before calling
 *                      @b recvmsg()
 * @param msg_ctrunc    If @c TRUE - set flag MSG_CTRUNC before calling
 *                      @b recvmsg()
 * @param sock_type     Socket type
 * @param onload_ext    If @c TRUE, enable Onload extension TCP timestamps
 * @param tx            If @c TRUE, check TX timestamps, otherwise - RX
 * @param msg_data      How much space should be available in msg_iov:
 *                      - @c zero_iovs: msg_iovlen is zero;
 *                      - @c small_space: not enough space for received
 *                                        data;
 *                      - @c ok: enough space for received data.
 * @param control_null  If @c TRUE, msg_control will be set to @c NULL.
 * @param control_len   Value of msg_controllen:
 *                      - @c zero;
 *                      - @c small (> 0 but too small for timestamps
 *                        message);
 *                      - @c ok (big enough to contain timestamps message).
 *
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "timestamps/ts_recvmsg_trunc"

#include "sockapi-test.h"
#include "timestamps.h"
#include "onload.h"

/** Possible values for msg_data parameter. */
enum {
    SOCKTS_MSG_DATA_ZERO_IOVS,  /**< Set msg_iovlen to 0 */
    SOCKTS_MSG_DATA_SMALL,      /**< Not enough space in iovec
                                     buffer */
    SOCKTS_MSG_DATA_OK,         /**< Enough space for data */
};

/**
 * List of values for msg_data parameter to use with
 * TEST_GET_ENUM_PARAM.
 */
#define SOCKTS_MSG_DATA_VARIANTS \
    { "zero_iovs",    SOCKTS_MSG_DATA_ZERO_IOVS },    \
    { "small_space",  SOCKTS_MSG_DATA_SMALL },        \
    { "ok",           SOCKTS_MSG_DATA_OK }

/** Possible values for control_len parameter. */
enum {
    SOCKTS_MSG_CONTROLLEN_ZERO,   /**< msg_controllen is @c 0 */
    SOCKTS_MSG_CONTROLLEN_SMALL,  /**< msg_controllen is too small */
    SOCKTS_MSG_CONTROLLEN_OK,     /**< msg_controllen is big enough
                                       for expected control message */
};

/**
 * List of values for control_len parameter to use with
 * TEST_GET_ENUM_PARAM.
 */
#define SOCKTS_MSG_CONTROLLEN_VARIANTS \
    { "zero",   SOCKTS_MSG_CONTROLLEN_ZERO },     \
    { "small",  SOCKTS_MSG_CONTROLLEN_SMALL },    \
    { "ok",     SOCKTS_MSG_CONTROLLEN_OK }

/**
 * Check whether truncated control message of expected type
 * was received.
 *
 * @param msg           Pointer to rpc_msghdr which was passed to
 *                      recvmsg().
 * @param ts_expected   If @c TRUE, control message with timestamp
 *                      is expected.
 * @param onload_ext    If @c TRUE, Onload TCP timestamps extension
 *                      was tested.
 * @param test_failed   Will be set to @c TRUE if test should fail.
 */
static void
check_truncated_cmsg(rpc_msghdr *msg,
                     te_bool ts_expected, te_bool onload_ext,
                     te_bool *test_failed)
{
    struct cmsghdr *cmsg = NULL;

    cmsg = rpc_cmsg_firsthdr(msg);
    if (ts_expected)
    {
        if (cmsg == NULL)
        {
            ERROR_VERDICT("Truncated control message was "
                          "not found");
            *test_failed = TRUE;
        }
        else
        {
            if (cmsg->cmsg_level != SOL_SOCKET)
            {
                ERROR_VERDICT("Control message has "
                              "unexpected level %s",
                              socklevel_rpc2str(
                                  socklevel_h2rpc(
                                        cmsg->cmsg_level)));
                *test_failed = TRUE;
            }
            else
            {
                int exp_type;

                if (onload_ext)
                    exp_type = ONLOAD_SCM_TIMESTAMPING_STREAM;
                else
                    exp_type = SO_TIMESTAMPING;

                if (cmsg->cmsg_type != exp_type)
                {
                    ERROR_VERDICT("Control message has "
                                  "unexpected type %s "
                                  "instead of %s",
                                  sockopt_rpc2str(
                                      cmsg_type_h2rpc(
                                            cmsg->cmsg_level,
                                            cmsg->cmsg_type)),
                                  sockopt_rpc2str(sockopt_h2rpc(SOL_SOCKET,
                                                                exp_type)));
                    *test_failed = TRUE;
                }
            }
        }
    }
    else
    {
        if (cmsg != NULL)
        {
            ERROR_VERDICT("Control message was unexpectedly "
                          "retrieved");
            *test_failed = TRUE;
        }
    }

    if (cmsg != NULL)
    {
        cmsg = rpc_cmsg_nxthdr(msg, cmsg);
        if (cmsg != NULL)
        {
            ERROR_VERDICT("More than one control message was "
                          "received");
            *test_failed = TRUE;
        }
    }
}

int
main(int argc, char *argv[])
{
    const struct if_nameindex *iut_if = NULL;
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst = NULL;
    const struct sockaddr     *iut_addr;
    const struct sockaddr     *tst_addr;
    rpc_socket_type            sock_type;
    te_bool                    msg_trunc;
    te_bool                    msg_ctrunc;
    te_bool                    onload_ext;
    te_bool                    tx;

    rpc_send_recv_flags exp_flags = 0;
    te_bool             ts_expected = FALSE;

    int         iut_s = -1;
    int         tst_s = -1;
    rpc_msghdr  msg = { NULL, };
    char       *sndbuf = NULL;
    size_t      length = 0;
    size_t      recv_len = 0;
    size_t      hlen = 0;
    int         msg_data;
    te_bool     control_null;
    int         control_len;
    te_bool     vlan = FALSE;
    te_bool     test_failed = FALSE;
    char       *disable_timestamps = getenv("DISABLE_TIMESTAMPS");

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(msg_trunc);
    TEST_GET_BOOL_PARAM(msg_ctrunc);
    TEST_GET_BOOL_PARAM(onload_ext);
    TEST_GET_BOOL_PARAM(tx);
    TEST_GET_IF(iut_if);
    TEST_GET_ENUM_PARAM(msg_data, SOCKTS_MSG_DATA_VARIANTS);
    TEST_GET_BOOL_PARAM(control_null);
    TEST_GET_ENUM_PARAM(control_len, SOCKTS_MSG_CONTROLLEN_VARIANTS);

    if (onload_ext && (sock_type != RPC_SOCK_STREAM || !tx))
    {
        TEST_FAIL("Checking ONLOAD_SOF_TIMESTAMPING_STREAM makes sense "
                  "only for TX timestamps on TCP socket");
    }

    ts_expected = (ts_any_event(tx, sock_type) || onload_ext);

    sndbuf = sockts_make_buf_stream(&length);
    vlan = ts_check_vlan(pco_iut, iut_if->if_name);

    TEST_STEP("Allocate/set msg.msg_iov/msg.msg_iovlen according to "
              "@p msg_data.");

    recv_len = length;
    hlen = 0;
    if (tx)
    {
        /* In case of @p tx, network protocol headers are reported too. */

        hlen = (sock_type == RPC_SOCK_DGRAM ? LINUX_DGRAM_HEADER_LEN :
                                              LINUX_TCP_HEADER_LEN);

        if (tx && vlan &&
            (sock_type == RPC_SOCK_STREAM || tapi_onload_run()))
        {
            hlen += 4;
        }

        /*
         * If timestamps are enabled, tcp header will be longer
         * by 12 bytes, because such header contains Options field.
         * Options field uses 10 bytes to store timestamps info and
         * 2 bytes are reserved for other options. If timestamps are
         * disabled, no options field will be present.
         */
        if (disable_timestamps != NULL &&
            strcmp(disable_timestamps, "yes") == 0 &&
            sock_type == RPC_SOCK_STREAM && tx)
        {
            hlen -= TCP_TIMESTAMPS_HSIZE;
        }
    }

    ts_init_msghdr(tx, &msg, recv_len + hlen);

    if (msg_data == SOCKTS_MSG_DATA_ZERO_IOVS)
    {
        msg.msg_iovlen = 0;
        recv_len = 0;
    }
    else if (msg_data == SOCKTS_MSG_DATA_SMALL)
    {
        int change;

        if (recv_len == 1)
            change = 1;
        else
            change = rand_range(1, recv_len - 1);

        msg.msg_iov->iov_len -= change;
        recv_len -= change;
    }

    TEST_STEP("Set msg_control/msg_controllen according to @p control_null, "
              "@p control_len.");

    msg.msg_cmsghdr_num = 0;
    msg.real_msg_controllen = msg.msg_controllen;

    if (control_null)
        msg.msg_control = NULL;

    if (control_len == SOCKTS_MSG_CONTROLLEN_ZERO)
    {
        msg.msg_controllen = 0;
    }
    else if (control_len == SOCKTS_MSG_CONTROLLEN_SMALL)
    {
        /*
         * Here a small number is added to size of struct cmsghdr so that
         * msg_controllen is big enough to include struct cmsghdr itself
         * but space for only part of timestamp remains after that.
         */
        msg.msg_controllen = rpc_get_sizeof(pco_iut, "struct cmsghdr") + 5;
    }

    TEST_STEP("Create a pair of connected sockets on IUT and Tester "
              "according to @p sock_type.");
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Enable hardware timestamping on IUT.");
    ts_enable_hw_ts(pco_iut, iut_s, sock_type, tx, onload_ext);

    TEST_STEP("If @p tx is @c TRUE, send data from IUT socket, otherwise "
              "send data from Tester socket.");

    if (tx)
        rpc_send(pco_iut, iut_s, sndbuf, length, 0);
    else
        rpc_send(pco_tst, tst_s, sndbuf, length, 0);

    TAPI_WAIT_NETWORK;

    if (ts_expected || !tx)
    {
        /*
         * In case of normal received TCP data retrieval there is
         * no datagrams so @c MSG_TRUNC is not expected.
         * Onload extension @c ONLOAD_SOF_TIMESTAMPING_STREAM does not
         * retrieve any data, so no @c MSG_TRUNC is expected for it.
         */
        if (msg_data != SOCKTS_MSG_DATA_OK &&
            !(sock_type == RPC_SOCK_STREAM && !tx) &&
            !onload_ext)
        {
            exp_flags |= RPC_MSG_TRUNC;
        }

        if (ts_expected &&
            (control_null || control_len != SOCKTS_MSG_CONTROLLEN_OK))
        {
            exp_flags |= RPC_MSG_CTRUNC;
        }

        if (ts_expected && tx)
            exp_flags |= RPC_MSG_ERRQUEUE;
    }

    /*
     * RPC_MSG_FLAGS_NO_SET means that flags will not be filled with
     * random data on calling recvmsg().
     * RPC_MSG_FLAGS_NO_CHECK means that verdict will not be printed
     * about flags being non-zero on return.
     */
    msg.msg_flags_mode = RPC_MSG_FLAGS_NO_SET | RPC_MSG_FLAGS_NO_CHECK;

    TEST_STEP("If @p msg_trunc is @c TRUE, set @c MSG_TRUNC flag in msg before "
              "calling @b recvmsg().");

    if (msg_trunc)
        msg.msg_flags |= RPC_MSG_TRUNC;

    TEST_STEP("If @p msg_ctrunc is @c TRUE, set @c MSG_CTRUNC flag in msg before "
              "calling @b recvmsg().");

    if (msg_ctrunc)
        msg.msg_flags |= RPC_MSG_CTRUNC;

    TEST_STEP("Call @b recvmsg() on IUT socket. Check that it succeeds if @p tx "
              "is @c FALSE or TX timestamps are expected to be returned. Check "
              "that both timestamps and data are retrieved in such case (unless "
              "we check @c ONLOAD_SOF_TIMESTAMPING_STREAM where data is not "
              "returned). "
              "Check that if recvmsg() should return some data but not enough "
              "space is provided, then @c MSG_TRUNC flag is reported; and if "
              "it should retrieve some control data but not enough space is "
              "provided in msg_control (or it is @c NULL), then @c MSG_CTRUNC "
              "flag is reported.");

    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_recvmsg(pco_iut, iut_s, &msg,
                     (tx ? RPC_MSG_ERRQUEUE : 0) | RPC_MSG_DONTWAIT);

    if (rc < 0)
    {
        if (ts_expected || !tx)
        {
            TEST_VERDICT("recvmsg() unexpectedly failed with errno %r",
                         RPC_ERRNO(pco_iut));
        }
        else
        {
            if (RPC_ERRNO(pco_iut) == RPC_EAGAIN)
            {
                TEST_SUCCESS;
            }
            else
            {
                TEST_VERDICT("recvmsg() failed with unexpected errno %r",
                             RPC_ERRNO(pco_iut));
            }
        }
    }
    else
    {
        if (!ts_expected && tx)
        {
            ERROR_VERDICT("recvmsg() unexpectedly succeeded");
            test_failed = TRUE;
        }

        if (msg.msg_flags != exp_flags)
        {
            ERROR_VERDICT("recvmsg() reported flags %s instead of %s",
                          send_recv_flags_rpc2str(msg.msg_flags),
                          send_recv_flags_rpc2str(exp_flags));
            test_failed = TRUE;
        }

        if (!control_null)
        {
            if (control_len == SOCKTS_MSG_CONTROLLEN_OK)
            {
                ts_check_cmsghdr_addr(&msg, rc, length, recv_len, sndbuf,
                                      tx, sock_type, onload_ext, vlan,
                                      FALSE, NULL, NULL, NULL);
            }
            else if (control_len == SOCKTS_MSG_CONTROLLEN_SMALL)
            {
                check_truncated_cmsg(&msg, ts_expected, onload_ext,
                                     &test_failed);
            }
        }

        if (recv_len == 0 || onload_ext)
        {
            if (rc != 0)
            {
                TEST_VERDICT("recvmsg() unexpectedly returned "
                             "nonzero");
            }
        }
        else
        {
            if (rc - hlen != recv_len)
                TEST_VERDICT("recvmsg() returned unexpected value");

            if (memcmp(sndbuf, msg.msg_iov->iov_base + hlen,
                       recv_len) != 0)
            {
                TEST_VERDICT("recvmsg() retrieved unexpected data");
            }
        }
    }

    if (test_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(sndbuf);
    sockts_release_msghdr(&msg);

    TEST_END;
}
