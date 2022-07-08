/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Onload extensions
 */

/** @page extension-onload_zc_recv_keep onload_zc_recv() with ONLOAD_ZC_KEEP
 *
 * @objective Check that Onload buffers can be kept and released or reused
 *            later if callback returns @c ONLOAD_ZC_KEEP flag.
 *
 * @type use case
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_peer2peer
 *                      - @ref arg_types_env_peer2peer_ipv6
 * @param sock_type     Socket type:
 *                      - @c SOCK_STREAM
 *                      - @c SOCK_DGRAM
 * @param pkts_num      Number of packets:
 *                      - @c 1
 *                      - @c 5
 * @param big_pkt       If @c TRUE, send big packets (so that
 *                      @b onload_zc_recv() will retrieve multiple iovecs
 *                      per message)
 * @param keep          Whether to keep Onload buffers by returning
 *                      @c ONLOAD_ZC_KEEP from @b onload_zc_recv()
 *                      callback:
 *                      - @c none - do not keep any buffers
 *                      - @c some - keep buffers for some of the received
 *                        messages
 *                      - @c all - keep buffers for all of the received
 *                        messages
 * @param action        What to do with kept Onload buffers:
 *                      - @c none - do nothing (to be used when no buffers
 *                        are kept)
 *                      - @c release - call @b onload_zc_release_buffers()
 *                      - @c reuse - pass messages with kept buffers to
 *                        @b onload_zc_send()
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "level5/extension/onload_zc_recv_keep"

#include "sockapi-test.h"
#include "onload.h"

/** Minimum size of a normal packet */
#define NORMAL_PKT_MIN 1
/** Maximum size of a normal packet */
#define NORMAL_PKT_MAX 1024

/** Minimum size of a large packet */
#define BIG_PKT_MIN 3000
/** Maximum size of a large packet */
#define BIG_PKT_MAX 5000

/** Maximum number of iovec buffers per message */
#define MAX_IOVS 5
/** Maximum length of a single iovec buffer */
#define MAX_IOV_SIZE 2000

/** Receive buffer size */
#define RX_BUF_SIZE  (BIG_PKT_MAX * 2)

/** Possible values of "keep" parameter */
enum {
    KEEP_NONE,  /**< "none" */
    KEEP_SOME,  /**< "some" */
    KEEP_ALL,   /**< "all" */
};

/** Possible values of "action" parameter */
enum {
    ACTION_NONE,    /**< "none" */
    ACTION_RELEASE, /**< "release" */
    ACTION_REUSE,   /**< "reuse" */
};

/** List of values of "keep" parameter for TEST_GET_ENUM_PARAM() */
#define KEEP_VARIANTS \
    { "none", KEEP_NONE }, \
    { "some", KEEP_SOME }, \
    { "all", KEEP_ALL }

/** List of values of "action" parameter for TEST_GET_ENUM_PARAM() */
#define ACTION_VARIANTS \
    { "none", ACTION_NONE }, \
    { "release", ACTION_RELEASE }, \
    { "reuse", ACTION_REUSE }

/** Structure describing packet data */
typedef struct pkt_data {
    struct rpc_iovec    iov[MAX_IOVS];          /**< Array of iovecs passed
                                                     to ZC RPC calls */
    char    tx_buf[BIG_PKT_MAX];                /**< Sent data */
    size_t  send_size;                          /**< Size of sent data */
    char    iov_bufs[MAX_IOVS][MAX_IOV_SIZE];   /**< Buffers for iovec
                                                     array */

    tarpc_onload_zc_buf_spec buf_spec[MAX_IOVS]; /**< ZC buffers allocation
                                                      specifications for
                                                      onload_zc_send() */
} pkt_data;

/**
 * Release all buffers kept by onload_zc_recv() call.
 *
 * @param rpcs            RPC server handle.
 * @param s               Socket FD.
 * @param mmsg            Pointer to array of Onload messages.
 * @param num             Number of elements in the array.
 *
 * @return 0 on success, -1 on failure.
 */
static int
release_kept_buffers(rcf_rpc_server *rpcs, int s,
                     struct rpc_onload_zc_mmsg *mmsg,
                     unsigned int num)
{
    te_bool release_failed = FALSE;
    unsigned int i;
    int rc;

    for (i = 0; i < num; i++)
    {
        if (mmsg[i].keep_recv_bufs)
        {
            RPC_AWAIT_ERROR(rpcs);
            rc = rpc_free_onload_zc_buffers(
                                      rpcs, s,
                                      mmsg[i].saved_recv_bufs, 1);
            if (rc < 0 && !release_failed)
            {
                release_failed = TRUE;
                ERROR_VERDICT("onload_zc_release_buffers() failed with "
                              "error " RPC_ERROR_FMT,
                              RPC_ERROR_ARGS(rpcs));
            }

            rpc_free(rpcs, mmsg[i].saved_recv_bufs);
        }
    }

    if (release_failed)
        return -1;

    return 0;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *tst_if = NULL;

    rpc_socket_type        sock_type;
    int                    pkts_num;
    te_bool                big_pkt;
    int                    keep;
    int                    action;

    int                    iut_s = -1;
    int                    tst_s = -1;
    int                    iut_s2 = -1;
    int                    tst_s2 = -1;

    int                    kept = 0;
    int                    received = 0;
    int                    reused = 0;
    int                    reused_sent = 0;
    int                    sent_fail_count = 0;
    int                    i;
    unsigned int           j;

    pkt_data                  *pkts = NULL;
    struct rpc_onload_zc_mmsg *mmsg = NULL;
    struct rpc_onload_zc_mmsg *mmsg_reuse = NULL;
    int                       *exp_sent_bytes = NULL;
    tarpc_onload_zc_buf_spec  *buf_spec = NULL;
    struct rpc_msghdr         *msg = NULL;

    char rx_buf[RX_BUF_SIZE];
    int rx_buf_pos;
    te_bool readable;
    uint8_t *cur_buf;
    size_t cur_buf_pos;
    int cmp_len;
    int bytes;
    te_bool test_failed = FALSE;
    te_bool release_failed = FALSE;

    te_saved_mtus iut_mtus = LIST_HEAD_INITIALIZER(iut_mtus);
    te_saved_mtus tst_mtus = LIST_HEAD_INITIALIZER(tst_mtus);
    int mtu_size;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_INT_PARAM(pkts_num);
    TEST_GET_BOOL_PARAM(big_pkt);
    TEST_GET_ENUM_PARAM(keep, KEEP_VARIANTS);
    TEST_GET_ENUM_PARAM(action, ACTION_VARIANTS);

    mmsg = tapi_calloc(pkts_num, sizeof(*mmsg));
    mmsg_reuse = tapi_calloc(pkts_num, sizeof(*mmsg_reuse));
    exp_sent_bytes = tapi_calloc(pkts_num, sizeof(*exp_sent_bytes));
    pkts = tapi_calloc(pkts_num, sizeof(*pkts));

    if (big_pkt)
    {
        TEST_STEP("If @p big_pkt is @c TRUE, increase MTU on IUT and "
                  "Tester interfaces to avoid packet fragmentation - "
                  "Onload considers fragmented UDP as system traffic.");
        /**
         * Set MTU greater than maximum payload size so that there
         * is a space for packet headers.
         */
        mtu_size = BIG_PKT_MAX + 200;

        CHECK_RC(tapi_set_if_mtu_smart2(pco_iut->ta, iut_if->if_name,
                                        mtu_size, &iut_mtus));
        CHECK_RC(tapi_set_if_mtu_smart2(pco_tst->ta, tst_if->if_name,
                                        mtu_size, &tst_mtus));
    }

    TEST_STEP("Create a pair of connected sockets of type @p sock_type: "
              "@b iut_s on IUT and @b tst_s on Tester.");
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    if (action == ACTION_REUSE)
    {
        TEST_STEP("If @p action is @c reuse, prepare a pair of sockets for "
                  "sending data back.");
        if (sock_type == RPC_SOCK_STREAM)
        {
            TEST_SUBSTEP("If @p sock_type is @c SOCK_STREAM, let "
                         "@b iut_s2 be the same as @b iut_s and "
                         "@b tst_s2 - the same as @b tst_s.");
            iut_s2 = iut_s;
            tst_s2 = tst_s;
        }
        else
        {
            TEST_SUBSTEP("If @p sock_type is @c SOCK_DGRAM, create an "
                         "additional pair of connected TCP sockets - "
                         "@b iut_s2 on IUT and @b tst_s2 on Tester - "
                         "@b onload_zc_send() cannot be used with "
                         "UDP sockets.");
            GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                           iut_addr, tst_addr, &iut_s2, &tst_s2);
        }
    }

    TEST_STEP("In case of TCP, enable @c TCP_NODELAY for @b tst_s "
              "so that packets will be sent immediately.");
    if (sock_type == RPC_SOCK_STREAM)
        rpc_setsockopt_int(pco_tst, tst_s, RPC_TCP_NODELAY, 1);

    TEST_STEP("Send @p pkts_num packets from @b tst_s, choosing their "
              "size according to @p big_pkt.");
    for (i = 0; i < pkts_num; i++)
    {
        if (big_pkt)
            pkts[i].send_size = rand_range(BIG_PKT_MIN, BIG_PKT_MAX);
        else
            pkts[i].send_size = rand_range(NORMAL_PKT_MIN, NORMAL_PKT_MAX);
        te_fill_buf(pkts[i].tx_buf, pkts[i].send_size);

        RPC_SEND(rc, pco_tst, tst_s, pkts[i].tx_buf, pkts[i].send_size, 0);

        mmsg[i].msg.msg_iov = pkts[i].iov;
        mmsg[i].msg.msg_iovlen = MAX_IOVS;
        mmsg[i].msg.msg_riovlen = MAX_IOVS;

        for (j = 0; j < MAX_IOVS; j++)
        {
            pkts[i].iov[j].iov_base = pkts[i].iov_bufs[j];
            pkts[i].iov[j].iov_len = MAX_IOV_SIZE;
            pkts[i].iov[j].iov_rlen = MAX_IOV_SIZE;
        }

        if (keep == KEEP_ALL ||
            (keep == KEEP_SOME && rand_range(1, 2) == 1))
        {
            mmsg[i].keep_recv_bufs = TRUE;
            kept++;
        }
    }

    if (keep == KEEP_SOME && kept == 0)
    {
        mmsg[rand_range(0, pkts_num - 1)].keep_recv_bufs = TRUE;
        kept++;
    }

    TAPI_WAIT_NETWORK;

    TEST_STEP("Receive all packets with the single @b onload_zc_recv() "
              "call on @b iut_s. Keep buffers for some or all of the "
              "received messages if @p keep is set to @c some or @c all.");
    RPC_AWAIT_ERROR(pco_iut);
    received = rpc_simple_zc_recv_gen(pco_iut, iut_s, mmsg, pkts_num,
                                      NULL, 0, NULL, FALSE);

    TEST_STEP("Check that @b onload_zc_recv() returned all the data "
              "sent from @b tst_s.");
    if (received < 0)
    {
        TEST_VERDICT("onload_zc_recv() failed with error " RPC_ERROR_FMT,
                     RPC_ERROR_ARGS(pco_iut));
    }
    else if (received != pkts_num)
    {
        ERROR_VERDICT("onload_zc_recv() retrieved unexpected number of "
                      "packets");
        test_failed = TRUE;
    }
    else
    {
        for (i = 0; i < pkts_num; i++)
        {
            if (mmsg[i].rc != (int)(pkts[i].send_size))
            {
                ERROR_VERDICT("onload_zc_recv() returned unexpected number "
                              "of bytes");
                test_failed = TRUE;
                break;
            }
            rc = sockts_compare_iovec_and_buffer(mmsg[i].msg.msg_iov,
                                                 mmsg[i].msg.msg_iovlen,
                                                 pkts[i].tx_buf,
                                                 pkts[i].send_size);
            if (rc != SOCKTS_BUF_EQUAL_IOVEC &&
                rc != SOCKTS_BUF_INCLUDED_IN_IOVEC)
            {
                ERROR_VERDICT("onload_zc_recv() returned unexpected data");
                test_failed = TRUE;
                break;
            }
        }
    }

    if (action == ACTION_RELEASE)
    {
        TEST_STEP("If @p action is @c release, call "
                  "@b onload_zc_release_buffers() for the first buffer "
                  "in every message where the buffers were kept.");
        if (release_kept_buffers(pco_iut, iut_s, mmsg, received) < 0)
            test_failed = TRUE;
    }
    else if (action == ACTION_REUSE)
    {
        TEST_STEP("If @p action is @c reuse, send kept buffers with "
                  "@b onload_zc_send() over @b iut_s2.");
        for (i = 0; i < received; i++)
        {
            if (mmsg[i].keep_recv_bufs)
            {
                memcpy(&mmsg_reuse[reused], &mmsg[i],
                       sizeof(mmsg[i]));
                buf_spec = pkts[i].buf_spec;
                mmsg_reuse[reused].buf_specs = buf_spec;
                bytes = 0;
                for (j = 0; j < MAX_IOVS && bytes < mmsg[i].rc; j++)
                {
                    buf_spec[j].type = TARPC_ONLOAD_ZC_BUF_EXIST_ALLOC;
                    buf_spec[j].existing_buf = mmsg[i].saved_recv_bufs;
                    buf_spec[j].buf_index = j;
                    bytes += mmsg[i].msg.msg_iov[j].iov_len;
                }

                if (bytes != mmsg[i].rc)
                {
                    release_kept_buffers(pco_iut, iut_s, mmsg, received);
                    TEST_VERDICT("Received message contains different "
                                 "number of bytes than the value of RC "
                                 "field");
                }

                mmsg_reuse[reused].msg.msg_iovlen = j;
                mmsg_reuse[reused].msg.msg_riovlen = j;
                mmsg_reuse[reused].fd = iut_s2;
                exp_sent_bytes[reused] = mmsg[i].rc;
                reused++;
            }
        }

        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_simple_zc_send_gen(pco_iut, mmsg_reuse, reused, 0, -1,
                                    FALSE, RPC_NULL, NULL);
        if (rc < 0)
        {
            ERROR_VERDICT("onload_zc_send() failed with error "
                          RPC_ERROR_FMT, RPC_ERROR_ARGS(pco_iut));
            test_failed = TRUE;
            reused_sent = 0;
        }
        else
        {
            reused_sent = rc;
            if (rc != reused)
            {
                ERROR("%d messages were sent instead of %d", rc, reused);
                ERROR_VERDICT("onload_zc_send() sent unexpected number of "
                              "messages");
                test_failed = TRUE;
            }
        }

        TEST_SUBSTEP("If some messages were not sent successfully, "
                     "release related Onload buffers explicitly and "
                     "fail the test.");

        for (i = 0; i < reused; i++)
        {
            if (mmsg_reuse[i].rc < 0 ||
                mmsg_reuse[i].rc != exp_sent_bytes[i])
            {
                if (sent_fail_count == 0)
                {
                    if (mmsg_reuse[i].rc < 0)
                    {
                        ERROR_VERDICT("onload_zc_send() failed to send a "
                                      "message; RC field was set to -%r",
                                      -mmsg_reuse[i].rc);
                    }
                    else
                    {
                        /*
                         * TODO: in this case we probably need to release
                         * explicitly part of buffers from the message
                         * which were not sent. However I'm not sure
                         * whether it is correct to do so given that
                         * normally we should release the first buffer
                         * from a message returned by onload_zc_recv(),
                         * and the remaining buffers "chained" to the first
                         * one whill be released automatically.
                         */
                        ERROR_VERDICT("onload_zc_send() sent unexpected "
                                      "number of bytes for a message");
                    }
                    test_failed = TRUE;
                }
                sent_fail_count++;
            }

            if (i >= reused_sent || mmsg_reuse[i].rc < 0)
            {
                RPC_AWAIT_ERROR(pco_iut);
                rc = rpc_free_onload_zc_buffers(
                                        pco_iut, iut_s,
                                        mmsg_reuse[i].saved_recv_bufs, 1);
                if (rc < 0 && !release_failed)
                {
                    release_failed = TRUE;
                    test_failed = TRUE;
                    ERROR_VERDICT("onload_zc_release_buffers() failed with "
                                  "error " RPC_ERROR_FMT,
                                  RPC_ERROR_ARGS(pco_iut));
                }
            }

            rpc_free(pco_iut, mmsg_reuse[i].saved_recv_bufs);
        }

        if (reused_sent == reused && sent_fail_count == 0)
        {
            TEST_SUBSTEP("If all messages were sent successfully, receive "
                         "and check data on @b tst_s2.");
            i = 0;
            j = 0;
            cur_buf_pos = 0;
            while (TRUE)
            {
                RPC_GET_READABILITY(readable, pco_tst, tst_s2,
                                    TAPI_WAIT_NETWORK_DELAY);
                if (!readable)
                {
                    TEST_VERDICT("Tester socket did not become "
                                 "readable but not all sent data "
                                 "is received");
                }

                bytes = rpc_recv(pco_tst, tst_s2, rx_buf, sizeof(rx_buf),
                                 0);

                rx_buf_pos = 0;
                while (TRUE)
                {
                    if (i == reused)
                        break;

                    msg = &(mmsg_reuse[i].msg);
                    cur_buf = msg->msg_iov[j].iov_base;
                    cmp_len =
                        MIN(bytes - rx_buf_pos,
                            msg->msg_iov[j].iov_len - cur_buf_pos);

                    if (memcmp(rx_buf + rx_buf_pos, cur_buf + cur_buf_pos,
                               cmp_len) != 0)
                    {
                        TEST_VERDICT("Data received on Tester does not "
                                     "match data sent from IUT");
                    }

                    rx_buf_pos += cmp_len;
                    cur_buf_pos += cmp_len;
                    if (cur_buf_pos == msg->msg_iov[j].iov_len)
                    {
                        j++;
                        cur_buf_pos = 0;
                        if (j == msg->msg_iovlen)
                        {
                            i++;
                            j = 0;
                        }
                    }
                    if (rx_buf_pos == bytes)
                        break;
                }

                if (rx_buf_pos < bytes)
                    TEST_VERDICT("Too much data was received on Tester");

                if (i >= reused)
                    break;
            }
        }
    }

    if (test_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    if (sock_type == RPC_SOCK_DGRAM)
    {
        CLEANUP_RPC_CLOSE(pco_iut, iut_s2);
        CLEANUP_RPC_CLOSE(pco_tst, tst_s2);
    }

    free(pkts);
    free(mmsg);
    free(mmsg_reuse);
    free(exp_sent_bytes);

    if (big_pkt)
    {
        CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&iut_mtus));
        CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&tst_mtus));
    }

    TEST_END;
}
