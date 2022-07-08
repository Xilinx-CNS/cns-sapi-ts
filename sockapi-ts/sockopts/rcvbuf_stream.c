/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page sockopts-rcvbuf_stream Influence SO_RCVBUF option on actual receive buffer size
 *
 * @objective Explore the possibility to change receive buffer size by means
 *            of setsockopt(SO_RCVBUF) and new value influence on actual
 *            buffer size.
 *
 * @type conformance, robustness
 *
 * @param pco_iut                   PCO on IUT
 * @param pco_tst                   PCO on TESTER
 * @param server                    IUT opens connection as
 *                                  TRUE/FALSE - server/client
 * @param force                     If @c TRUE, check SO_RCVBUFFORCE
 *
 * @par Test sequence:
 *
 * -# Repeat the following steps while RCVBUF value can be increased:
 * -#   - Create TCP sockets on IUT and Tester, set RCVBUF value
 *        for IUT socket and get its value (it should be multiplied
 *        by 2 by the system unless it is too big already), establish
 *        TCP connection.
 * -#   - Overfill IUT receive buffer.
 * -#   - Read data from IUT socket, check that amount of data
 *        read grows in approximately the same proportion as
 *        RCVBUF.
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/rcvbuf_stream"

#include "sockapi-test.h"
#include "iomux.h"
#include "tapi_mem.h"

/* Maximum number of general loop iterations */
#define MAX_ITER_NUM 20

typedef struct iteration_data_t {
    int rcvbuf;
    int filled;
} iteration_data_t;

static rcf_rpc_server *pco_iut = NULL;
static rcf_rpc_server *pco_tst = NULL;
static int             iut_s = -1;
static int             tst_s = -1;

/**
 * Overfill receive buffer of a TCP peer.
 *
 * @param rpcs      RPC server.
 * @param s         Socket from which to send data.
 * @param rcvbuf    Expected size of receive buffer on a peer.
 *
 * @return Number of bytes sent.
 */
static size_t
overfill_sock_buffer(rcf_rpc_server *rpcs, int s, size_t rcvbuf)
{
#define MAX_PKT_LEN 1024
#define WAIT_SENDQ  500

    char    *buf = NULL;
    te_bool  writable = FALSE;
    ssize_t  rc = 0;
    size_t   sent = 0;
    size_t   pkt_size = 0;
    int      send_queue = 0;
    int      i = 0;

    /*
     * Packet size should be a fraction of receive buffer,
     * otherwise our measurement may be rather inaccurate.
     */

    pkt_size = rcvbuf / 100;

    if (pkt_size == 0)
        pkt_size = 1;
    else if (pkt_size > MAX_PKT_LEN)
        pkt_size = MAX_PKT_LEN;

    buf = tapi_calloc(pkt_size, 1);

    rpc_setsockopt_int(rpcs, s, RPC_TCP_NODELAY, 1);

    while (TRUE)
    {
        rpcs->silent = TRUE;
        RPC_GET_WRITABILITY(writable, rpcs, s, 1000);
        if (!writable)
            break;

        rpcs->silent = TRUE;
        RPC_AWAIT_ERROR(rpcs);
        rc = rpc_send(rpcs, s, buf, pkt_size, RPC_MSG_DONTWAIT);

        if (rc < 0)
        {
            if (RPC_ERRNO(rpcs) != RPC_EAGAIN)
                TEST_FAIL("send() returned strange errno %r",
                          RPC_ERRNO(rpcs));
            else
                break;
        }

        sent += rc;

        /**
         * Wait until send buffer contains no more than 5% of
         * peer's receive buffer. If this does not happen within
         * @c WAIT_SENDQ ms, consider receive buffer as being
         * overfilled and stop sending.
         * This is done to prevent too much data being gathered in
         * send buffer, which may result in sending too big TCP packets,
         * leading to inaccurate measurement for small receive buffers.
         */

        for (i = 0; i < WAIT_SENDQ; i++)
        {
            rpcs->silent = TRUE;
            rpc_ioctl(rpcs, s, RPC_SIOCOUTQ, &send_queue);
            if (send_queue < 0.05 * rcvbuf)
                break;

            usleep(1000 * test_sleep_scale());
        }
        if (i >= WAIT_SENDQ)
            break;
    }

    free(buf);
    return sent;
}

/**
 * Make TCP connection between IUT and TESTER, set RCVBUF size for IUT
 * socket, overfill receive buffer by TESTER, get amount of data in IUT
 * receive bufer.
 *
 * @param iut_addr          IUT address
 * @param tst_addr          TESTER address
 * @param server            IUT opens connection as server/client
 * @param rcvbuf            Size of RCVBUF to be set, returns value which
 *                          is got after setting.
 * @param force             If @c TRUE, check SO_RCVBUFFORCE
 *
 * @return Data amount in IUT receive buffer after its overfilling
 */
static int
test_check_rcvbuf(const struct sockaddr *iut_addr,
                  const struct sockaddr *tst_addr, te_bool server,
                  int *rcvbuf, te_bool force)
{
    int         rcvbuf_filled;
    int         accept_s = -1;
    uint64_t    total;
    int         rcvbuf_set = *rcvbuf;
    struct sockaddr_storage iut_addr_unique = {0};
    struct sockaddr_storage tst_addr_unique = {0};

    /* Ensure that new connection will use free ports. */
    tapi_sockaddr_clone(pco_iut, iut_addr, &iut_addr_unique);
    tapi_sockaddr_clone(pco_tst, tst_addr, &tst_addr_unique);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, CONST_SA(&iut_addr_unique));
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, CONST_SA(&tst_addr_unique));

    /**
     * tcp(7) man page:
     * "On individual connections, the socket buffer size must be set
     * prior to the listen(2) or connect(2) calls in order to have it
     * take effect." The test results are sensitive to this sequence.
     */
    rpc_setsockopt(pco_iut, iut_s,
                   (force ? RPC_SO_RCVBUFFORCE : RPC_SO_RCVBUF), rcvbuf);
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_RCVBUF, rcvbuf);

    if (server)
    {
        rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);
        rpc_connect(pco_iut, iut_s, CONST_SA(&tst_addr_unique));
        accept_s = rpc_accept(pco_tst, tst_s, NULL, NULL);
        RPC_CLOSE(pco_tst, tst_s);
        tst_s = accept_s;
    }
    else
    {
        rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
        rpc_connect(pco_tst, tst_s, CONST_SA(&iut_addr_unique));
        accept_s = rpc_accept(pco_iut, iut_s, NULL, NULL);
        RPC_CLOSE(pco_iut, iut_s);
        iut_s = accept_s;
    }

    total = overfill_sock_buffer(pco_tst, tst_s, *rcvbuf);

    /* Get the actual number of bytes in 'iut_s' receive queue */
    rpc_ioctl(pco_iut, iut_s, RPC_FIONREAD, &rcvbuf_filled);
    if (rcvbuf_filled < 0)
        TEST_VERDICT("Read a negative value of option FIONREAD");
    else if (rcvbuf_filled == 0)
        TEST_VERDICT("Read zero value of option FIONREAD");

    RING("RCVBUF set %d, get %d, receive queue %d, sent to overfill %llu",
         rcvbuf_set, *rcvbuf, rcvbuf_filled, total);

    RPC_CLOSE(pco_iut, iut_s);
    RPC_CLOSE(pco_tst, tst_s);

    return rcvbuf_filled;
}

/**
 * Check that two values are approximately equal.
 *
 * @param d1          The first value.
 * @param d2          The second value.
 * @param precision   Comparison precision.
 *
 * @return @c TRUE if the values are approximately equal,
 *         @c FALSE otherwise.
 */
static te_bool
compare_approx(float d1, float d2, float precision)
{
    if (d1 < d2 * (1.0 - precision) ||
        d1 > d2 * (1.0 + precision))
        return FALSE;

    return TRUE;
}

int
main(int argc, char *argv[])
{
    const struct sockaddr       *iut_addr = NULL;
    const struct sockaddr       *tst_addr = NULL;
    const struct if_nameindex   *iut_if = NULL;

    te_bool server;
    te_bool force;

    iteration_data_t curr;
    iteration_data_t prev;
    int              rcvbuf_max;
    int              min_filled = -1;
    te_bool          verdict1 = FALSE;
    te_bool          verdict2 = FALSE;
    float            rcvbuf_ratio = 0;
    float            filled_ratio = 0;
    float            precision = 0.3;
    int              i;

    te_string        str = TE_STRING_INIT;
    te_bool          fail = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_BOOL_PARAM(server);
    TEST_GET_BOOL_PARAM(force);

    CHECK_RC(tapi_cfg_sys_ns_get_int(pco_iut->ta, &rcvbuf_max,
                                     "net/core/rmem_max"));

    memset(&prev, 0, sizeof(prev));
    memset(&curr, 0, sizeof(curr));
    curr.rcvbuf = 10;

    CHECK_RC(te_string_append(&str, "%20s %20s %20s %20s %10s\n",
                              "RCVBUF", "RATIO", "READ", "RATIO",
                              "RESULT"));

    for (i = 0; i < MAX_ITER_NUM; i++)
    {
        fail = FALSE;

        curr.filled = test_check_rcvbuf(iut_addr, tst_addr, server,
                                        &curr.rcvbuf, force);

        if (prev.rcvbuf == 0)
            rcvbuf_ratio = 0;
        else
            rcvbuf_ratio = (float)curr.rcvbuf / prev.rcvbuf;

        if (prev.filled == 0)
            filled_ratio = 0;
        else
            filled_ratio = (float)curr.filled / prev.filled;

        if (min_filled < 0)
            min_filled = curr.filled;

        if (curr.filled < min_filled * (1.0 - precision))
        {
            if (!verdict1)
                ERROR_VERDICT("Less than minumum was read");

            verdict1 = TRUE;
            fail = TRUE;
        }

        if (curr.filled > min_filled * (1.0 + precision) ||
            curr.rcvbuf > 2 * min_filled * (1.0 + precision))
        {
            /*
             * (rcvbuf_ratio - 1.0) * (filled_ratio - 1.0) < 0
             * when one of them > 1 and another one is < 1,
             * meaning that one of {rcvbuf, filled} is increasing
             * while another one is decreasing.
             *
             * It is OK for filled to grow faster than rcvbuf while it
             * is not significantly bigger than rcvbuf.
             */
            if ((rcvbuf_ratio - 1.0) * (filled_ratio - 1.0) < 0 ||
                ((filled_ratio < rcvbuf_ratio ||
                  curr.filled > curr.rcvbuf * (1.0 + precision)) &&
                 !compare_approx(filled_ratio, rcvbuf_ratio, precision)))
            {
                if (!verdict2)
                    ERROR_VERDICT("Amount of data read did not grow "
                                  "in accordance with receive "
                                  "buffer size");

                verdict2 = TRUE;
                fail = TRUE;
            }
        }

        CHECK_RC(te_string_append(&str, "%20d %20.3f %20d %20.3f %10s\n",
                                  curr.rcvbuf, rcvbuf_ratio,
                                  curr.filled, filled_ratio,
                                  (fail ? "FAIL" : "PASS")));

        if (prev.rcvbuf == curr.rcvbuf ||
            curr.rcvbuf >= rcvbuf_max * 2)
            break;

        memcpy(&prev, &curr, sizeof(prev));
    }

    RING("%s", str.ptr);

    if (verdict1 || verdict2)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    te_string_free(&str);

    TEST_END;
}
