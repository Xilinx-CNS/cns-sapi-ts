/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Timestamps
 *
 * $Id$
 */

/** @page timestamps-ts_flow Transmit data flow checking timestamps monotonic
 *
 * @objective  Transmit data flow with different parameters, check that
 *             timestastamps are monotonic.
 *
 * @param pco_iut    PCO on IUT
 * @param pco_tst    PCO on TST
 * @param tx         Determine is it TX or RX packet handling
 * @param sock_type  Socket type
 * @param total      Data amount to transmit
 * @param length_min Minimum packets length
 * @param length_max Minimum packets length
 * @param mtu        MTU value to set on IUT interface
 * @param enable_ts  Data amount to transmit before timestamps enabling
 * @param iomux      I/O multiplexing function type
 * @param onload_ext Onload extension TCP timestamps
 * 
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "timestamps/ts_flow"

#include "sockapi-test.h"
#include "timestamps.h"
#include "iomux.h"
#include "onload.h"

/** Maximum attempts number to try read TCP timestamp. */
#define MAX_ATTEMPTS_TCP 1000

/** Maximum attempts number to try read UDP timestamp. */
#define MAX_ATTEMPTS_UDP 50

/** UDP header length to calculate datagram payload length. */
#define UDP_HEADER_SIZE 28

/** Maximum amount of packet retransmissions. */
#define MAX_RETRANS_ALLOWED 3

/** IUT RPC server handler. */
static rcf_rpc_server *pco_iut = NULL;
/** Tester RPC server handler. */
static rcf_rpc_server *pco_tst = NULL;

/** IUT interface is VLAN. */
static te_bool vlan = FALSE;

/** Timestamp messages counter which were not received. */
static int count_miss = 0;

/**
 * Check whether timestamps are present as expected.
 *
 * @param msg       Message itself
 * @param enabled   Whether timestamps are expected to be
 *                  enabled
 */
static void
check_enabled(rpc_msghdr *msg, te_bool enabled)
{
    if (enabled)
    {
        if (msg->msg_controllen == 0)
            TEST_VERDICT("msg_controllen is zero, but tstamps are enabled");
    }
    else
    {
        if (msg->msg_controllen != 0)
        {
            TEST_VERDICT("msg_controllen is not zero, but tstamps "
                         "are disabled");
        }
    }
}

/**
 * Retrieve UDP or TCP TX timestamp and check it sanity.
 * 
 * @param msg       Buffer to receive message with timestamp
 * @param iut_s     IUT socket
 * @param sndbuf    Sent data buffer
 * @param len       Sent packet length
 * @param mtu       Current MTU
 * @param enabled   @c TRUE if timestamps are enabled
 * @param sock_type Socket type
 * @param ts_prev   Previous timestamp
 */
static void
retrieve_ts_tx(rpc_msghdr *msg, int iut_s, char *sndbuf, int len,
                   int mtu, te_bool enabled, rpc_socket_type sock_type,
                   struct timespec *ts_prev)
{
    struct timespec  ts_rx;
    int hsize;
    int rc;
    int i;
    struct timespec ts_aux;
    char           *disable_timestamps = getenv("DISABLE_TIMESTAMPS");

    te_bool zero_reported = FALSE;
    te_bool no_reported = FALSE;

    if (sock_type == RPC_SOCK_DGRAM)
        hsize = LINUX_DGRAM_HEADER_LEN;
    else
        hsize = LINUX_TCP_HEADER_LEN;
    mtu += LINUX_ETH_HEADER_LEN;

    /** UDP datagram is returned with VLAN addition with Onload, it
     * is thought to be correct, see bug 56367. */
    if (vlan && (sock_type == RPC_SOCK_STREAM || tapi_onload_run()))
    {
        hsize += 4;
        mtu += 4;
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
        sock_type == RPC_SOCK_STREAM)
    {
        hsize -= TCP_TIMESTAMPS_HSIZE;
    }

    memset(&ts_rx, 0, sizeof(ts_rx));

    for (i = 0; i < MAX_ATTEMPTS_UDP; i++)
    {
        memset(msg->msg_control, 0, SOCKTS_CMSG_LEN);
        msg->msg_controllen = SOCKTS_CMSG_LEN;

        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_recvmsg(pco_iut, iut_s, msg, RPC_MSG_ERRQUEUE);
        if (rc < 0 && RPC_ERRNO(pco_iut) != RPC_EAGAIN)
            TEST_FAIL("recvmsg failed with unexpected error %s",
                      errno_rpc2str(RPC_ERRNO(pco_iut)));

        if (rc < 0)
        {
            if (!enabled)
                return;

            usleep(10000);
        }
        else
        {
            if (!enabled && ts_any_event(TRUE, sock_type))
                TEST_VERDICT("recvmsg returned non-negative value "
                             "but timestamps are disabled");
            break;
        }
    }

    if (i == MAX_ATTEMPTS_UDP)
    {
        count_miss++;
        return;
    }

    check_enabled(msg, enabled);
    if (!enabled)
        return;

    if (sock_type == RPC_SOCK_DGRAM)
    {
        if (rc > mtu)
        {
            RING("rc %d, mtu %d", rc, mtu);
            TEST_VERDICT("recvmsg returned a number which is greater than MTU");
        }

        RING("len %d, mtu %d, rc %d, hsize %d", len, mtu, rc, hsize);
        if (len + hsize < mtu && rc != len + hsize)
            TEST_VERDICT("recvmsg returned a wrong value");

        if (len > mtu - hsize)
        {
            if (rc != mtu)
                TEST_VERDICT("recvmsg() function returned unexpected value");
            len = mtu - hsize;
        }
    }
    else
    {
        len = rc - hsize;
        sndbuf = NULL;
    }

    memcpy(&ts_aux, ts_prev, sizeof(ts_aux));
    ts_check_cmsghdr(msg, rc, len, sndbuf, TRUE, sock_type, FALSE, vlan,
                     &ts_rx, ts_prev);
    ts_check_second_cmsghdr(pco_iut, iut_s, NULL, &ts_aux, NULL, NULL,
                            FALSE, &zero_reported, &no_reported);
}

/**
 * Retrieve TCP TX timestamp and check it sanity.
 * 
 * @param msg       Buffer to receive message with timestamp
 * @param iut_s     IUT socket
 * @param len       Sent packet length
 * @param mtu       Current MTU
 * @param enabled   @c TRUE if timestamps are enabled
 * @param ts_prev   Previous timestamp
 */
static void
retrieve_ts_tx_tcp(rpc_msghdr *msg, int iut_s, int len, int mtu,
                   te_bool enabled, struct timespec *ts_prev)
{
    rpc_onload_scm_timestamping_stream *ts_tx;
    struct cmsghdr *cmsg = NULL;
    int count = 0;
    int rc;
    int i;
    int error_count = 0;

    for (i = 0; i < MAX_ATTEMPTS_TCP && count < len; i++)
    {
        memset(msg->msg_control, 0, SOCKTS_CMSG_LEN);
        msg->msg_controllen = SOCKTS_CMSG_LEN;

        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_recvmsg(pco_iut, iut_s, msg, RPC_MSG_ERRQUEUE);
        if (rc < 0 && RPC_ERRNO(pco_iut) != RPC_EAGAIN)
            TEST_FAIL("recvmsg failed with unexpected error %s",
                      errno_rpc2str(RPC_ERRNO(pco_iut)));
        if (rc < 0)
        {
            if (!enabled)
                return;

            continue;
        }
        else if (!enabled)
            TEST_VERDICT("recvmsg returned a number which is more than 0 "
                         "but timestamps are disabled");

        if (rc != 0)
            TEST_VERDICT("recvmsg returned more than 0 bytes for TX with "
                         "TCP");

        check_enabled(msg, enabled);
        if (!enabled)
            return;

        cmsg = sockts_msg_lookup_control_data(msg, SOL_SOCKET,
                         sockopt_rpc2h(RPC_ONLOAD_SCM_TIMESTAMPING_STREAM));

        ts_tx = (rpc_onload_scm_timestamping_stream *)CMSG_DATA(cmsg);

        ts_print_tcp_tx(ts_tx);

        if (!ts_timespec_is_zero(&ts_tx->last_sent))
            error_count += 1;

        if (error_count > MAX_RETRANS_ALLOWED)
            TEST_VERDICT("last_sent is not zero, probably the packet was "
                         "retransmitted");

        if ((int)ts_tx->len > mtu)
            TEST_VERDICT("TCP segment length retrived with ts is greater "
                         "than mtu %d", mtu);

        if (ts_cmp(ts_prev, &ts_tx->first_sent) >= 0)
            TEST_VERDICT("Timestamps are not monotonic");
        memcpy(ts_prev, &ts_tx->first_sent, sizeof(*ts_prev));

        count += ts_tx->len;
    }

    if (error_count)
        RING("Packet was retransmitted %d times.", error_count);

    if (count != len)
        TEST_VERDICT("It was extracted %d bytes with timestamps handler, "
                     "but %d bytes were sent", count, len);
}

/**
 * Send packet flow from IUT socket for testing TX tiemstamps.
 * 
 * @param iut_s      IUT socket
 * @param tst_s      Tester socket
 * @param sock_type  Socket type
 * @param length_min Maximum packet length
 * @param length_max Minimum packet length
 * @param total      Total data amount to send
 * @param mtu        Current MTU
 * @param enable_ts  Data amount to transmit before timestamps enabling
 * @param iomux      I/O multiplexing function type
 * @param onload_ext Onload extension TCP timestamps
 */
static void
transmit_flow_tx(int iut_s, int tst_s, rpc_socket_type sock_type,
                 int length_min, int length_max, int total, int mtu,
                 int enable_ts, iomux_call_type iomux, te_bool onload_ext)
{
    iomux_evt_fd    event;
    tarpc_timeval   timeout = {.tv_sec = 0, .tv_usec = 0};
    struct timespec ts = {0, 0};
    rpc_msghdr      msg;
    te_bool         enabled = FALSE;
    te_bool         en = FALSE;
    char *sndbuf;
    char *rcvbuf;
    int count = 0;
    int len;
    int offt;
    int received;
    int rc;
    int exp;

    exp = iomux_init_rd_error(&event, iut_s, iomux, FALSE, NULL);

    sndbuf = te_make_buf_by_len(length_max);
    rcvbuf = te_make_buf_by_len(length_max);

    ts_init_msghdr(TRUE, &msg, length_max + 300);

    while (count < total)
    {
        if (!enabled && count > enable_ts)
        {
            TEST_STEP("Enable timestamps setting @c SO_TIMESTAMPING socket option "
                      "with appropriate flags.");
             ts_enable_hw_ts(pco_iut, iut_s, sock_type, TRUE, onload_ext);
             enabled = TRUE;
             if (ts_any_event(TRUE, sock_type) || onload_ext)
                en = TRUE;
             timeout.tv_usec = 500000;
        }

        len = rand_range(length_min, length_max);
        offt = rand_range(0, length_max - len);

        if (rpc_send(pco_iut, iut_s, sndbuf + offt, len, 0) != len)
            TEST_FAIL("Failed to send full data");

        received = 0;
        do {
            rc = rpc_recv(pco_tst, tst_s, rcvbuf + received,
                          length_max - received, 0);
            if (rc == 0)
                break;
            received += rc;
        } while (received < len);

        if (received != len || memcmp(sndbuf + offt, rcvbuf, len) != 0)
            TEST_FAIL("Received packet differs from the sent one.");

        if (en)
            IOMUX_CHECK_EXP(1, exp, event,
                            iomux_call(iomux, pco_iut, &event, 1, &timeout));
        else
            IOMUX_CHECK_ZERO(iomux_call(iomux, pco_iut, &event, 1, &timeout));

        msg.msg_iov->iov_len = msg.msg_iov->iov_rlen = length_max + 300;
        if (sock_type == RPC_SOCK_STREAM && onload_ext)
            retrieve_ts_tx_tcp(&msg, iut_s, len, mtu, en, &ts);
        else
            retrieve_ts_tx(&msg, iut_s, sndbuf + offt, len, mtu, en,
                           sock_type, &ts);

        count += len;
    }

    IOMUX_CHECK_ZERO(iomux_call(iomux, pco_iut, &event, 1, &timeout));
    sockts_release_msghdr(&msg);
    free(sndbuf);
    free(rcvbuf);
}

/**
 * Receive packets on IUT with timestamps retrieving, check timestamps
 * sanity.
 * 
 * @param msg        Buffer to receive message with timestamp
 * @param iut_s      IUT socket
 * @param sock_type  Socket type
 * @param sndbuf     Sent packet payload
 * @param len        Sent packet length
 * @param length_max Maximum packet length
 * @param enabled    @c TRUE if timestamps are enabled
 * @param ts_prev    Previous timestamp
 * @param iomux      I/O multiplexing function type
 */
static void
check_ts_rx(rpc_msghdr *msg, int iut_s,rpc_socket_type sock_type,
            char *sndbuf, int len, int length_max,
            te_bool enabled, struct timespec *ts_prev, iomux_call_type iomux)
{
    struct timespec  ts_rx;
    tarpc_timeval    timeout = {.tv_sec = 0, .tv_usec = 500000};
    iomux_evt_fd     event;
    int count = 0;
    int rc;
    int limit = 0;
    int exp;

    te_dbuf rcv_dbuf = TE_DBUF_INIT(0);

    memset(&ts_rx, 0, sizeof(ts_rx));
    event.fd = iut_s;
    event.events = EVT_RD;
    exp = EVT_RD;

    do {
        memset(msg->msg_control, 0, SOCKTS_CMSG_LEN);
        msg->msg_controllen = SOCKTS_CMSG_LEN;
        msg->msg_iov->iov_len = msg->msg_iov->iov_rlen = length_max;

        IOMUX_CHECK_EXP(1, exp, event, iomux_call(iomux, pco_iut, &event, 1,
                                                  &timeout));
        rc = rpc_recvmsg(pco_iut, iut_s, msg, 0);
        if (sock_type == RPC_SOCK_DGRAM)
        {
            if (rc != len ||
                memcmp(sndbuf, msg->msg_iov->iov_base, len) != 0)
            {
                TEST_VERDICT("Received packet length or payload differs "
                             "from the sent one");
            }
        }
        else
        {
            /*
             * For TCP a single send call may correspond to multiple
             * receive calls.
             */
            CHECK_RC(te_dbuf_append(&rcv_dbuf, msg->msg_iov->iov_base, rc));
        }
        count += rc;

        if (!ts_any_event(FALSE, sock_type))
            enabled = FALSE;

        check_enabled(msg, enabled);
        if (enabled)
        {
            ts_check_cmsghdr(msg, rc, sock_type == RPC_SOCK_DGRAM ? len : 0,
                             sndbuf, FALSE, sock_type, FALSE, vlan,
                             &ts_rx, ts_prev);
        }

        limit++;
        if (limit > MAX_ATTEMPTS_TCP)
        {
            if (count < len)
                TEST_VERDICT("Received payload length is less than sent");
            break;
        }
    } while (sock_type != RPC_SOCK_DGRAM && count < len);

    if (sock_type == RPC_SOCK_STREAM)
    {
        if (rcv_dbuf.size != (size_t)len ||
            memcmp(rcv_dbuf.ptr, sndbuf, len) != 0)
        {
            TEST_VERDICT("Received packet length or payload differs "
                         "from the sent one");
        }
    }
    te_dbuf_free(&rcv_dbuf);

    memset(&timeout, 0, sizeof(timeout));
    IOMUX_CHECK_ZERO(iomux_call(iomux, pco_iut, &event, 1, &timeout));
}

/**
 * Send packet flow from tester socket and receive on IUT for testing RX
 * tiemstamps.
 * 
 * @param iut_s      IUT socket
 * @param tst_s      Tester socket
 * @param sock_type  Socket type
 * @param length_min Maximum packet length
 * @param length_max Minimum packet length
 * @param total      Total data amount to send
 * @param enable_ts  Data amount to transmit before timestamps enabling
 * @param iomux      I/O multiplexing function type
 */
static void
transmit_flow_rx(int iut_s, int tst_s, rpc_socket_type sock_type,
                 int length_min, int length_max, int total,
                 int enable_ts, iomux_call_type iomux)
{
    struct timespec ts = {0, 0};
    rpc_msghdr msg;
    te_bool enabled = FALSE;
    char *sndbuf;
    int count = 0;
    int len;
    int offt;

    sndbuf = te_make_buf_by_len(length_max);
    ts_init_msghdr(FALSE, &msg, length_max);

    while (count < total)
    {
        if (!enabled && count > enable_ts)
        {
            TEST_STEP("Enable timestamps setting @c SO_TIMESTAMPING socket option "
                      "with appropriate flags.");
             ts_enable_hw_ts(pco_iut, iut_s, sock_type, FALSE, FALSE);
             enabled = TRUE;
        }

        len = rand_range(length_min, length_max);
        offt = rand_range(0, length_max - len);

        if (rpc_send(pco_tst, tst_s, sndbuf + offt, len, 0) != len)
            TEST_FAIL("Failed to send full data");

        check_ts_rx(&msg, iut_s,  sock_type, sndbuf + offt, len, length_max,
                    enabled, &ts, iomux);

        count += len;
    }

    sockts_release_msghdr(&msg);
    free(sndbuf);
}

int
main(int argc, char *argv[])
{
    const struct sockaddr     *iut_addr = NULL;
    const struct sockaddr     *tst_addr = NULL;
    const struct if_nameindex *iut_if;
    const struct if_nameindex *tst_if;
    rpc_socket_type        sock_type;
    te_bool                tx;
    te_bool                onload_ext;
    int                    length_min;
    int                    length_max;
    int                    total;
    int                    mtu;
    int                    enable_ts = 0;
    iomux_call_type        iomux;

    int iut_s = -1;
    int tst_s = -1;

    te_saved_mtus   iut_mtus = LIST_HEAD_INITIALIZER(iut_mtus);
    te_saved_mtus   tst_mtus = LIST_HEAD_INITIALIZER(tst_mtus);
    
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(tx);
    TEST_GET_BOOL_PARAM(onload_ext);
    TEST_GET_INT_PARAM(mtu);
    TEST_GET_INT_PARAM(total);
    TEST_GET_INT_PARAM(length_min);
    TEST_GET_INT_PARAM(length_max);
    TEST_GET_INT_PARAM(enable_ts);
    TEST_GET_IOMUX_FUNC(iomux);

    vlan = ts_check_vlan(pco_iut, iut_if->if_name);

    if (length_min > length_max)
        TEST_FAIL("length_min must not be greater than length_max");
    if (length_min <= 0)
        TEST_FAIL("length_min must be greater than 0");

    TEST_STEP("Set MTU if it is required.");
    if (mtu != 0)
    {
        CHECK_RC(tapi_set_if_mtu_smart2(pco_iut->ta, iut_if->if_name,
                                        mtu, &iut_mtus));
        CHECK_RC(tapi_set_if_mtu_smart2(pco_tst->ta, tst_if->if_name,
                                        mtu, &tst_mtus));
        CFG_WAIT_CHANGES;
    }
    CHECK_RC(tapi_cfg_base_if_get_mtu_u(pco_iut->ta, iut_if->if_name, &mtu));

    TEST_STEP("Create connection between IUT and tester.");
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    if (tx)
    {
        TEST_STEP("If @p tx is @c TRUE, send data flow from IUT, "
                  "retrieve and check TX timestamps.");

        transmit_flow_tx(iut_s, tst_s, sock_type, length_min, length_max,
                         total, mtu, enable_ts, iomux, onload_ext);
    }
    else
    {
        TEST_STEP("Else (@p tx is @c FALSE) send data flow from tester, receive "
                  "packets with timestamps "
                  "on IUT, check timetamps sanity.");

        transmit_flow_rx(iut_s, tst_s, sock_type, length_min, length_max,
                         total, enable_ts, iomux);
    }

    RING("Missed datagrams number %d", count_miss);

    TEST_SUCCESS;
cleanup:
    /* Order matters: avoid TIME_WAIT on IUT side */
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&iut_mtus));
    CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&tst_mtus));

    TEST_END;
}
