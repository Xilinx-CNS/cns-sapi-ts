/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Helper functions for timetamps testing
 *
 * $Id$
 */

#include "sockapi-test.h"
#include "timestamps.h"
#include "onload.h"
#include "tapi_host_ns.h"

/** Deviation precision of timestamp, in usec (0.5 sec). */
#define DEVIATION_PRECISION 500000L

#define IOCTL_ATTEMPTS_MAX 20

typedef struct ioctl_set_ts_ctx {
    rpc_hwtstamp_config    *hw_cfg;
    sockts_rpcs_h           srpc_h;
} ioctl_set_ts_ctx;

/**
 * Call ioctl(SIOCSHWTSTAMP) to set new value and save previous if it is
 * necessary for particular interface.
 *
 * @param ta        Test agent name
 * @param if_name   Interface name
 * @param ctx       The context
 *
 * Status code.
 */
static te_errno
ioctl_set_ts_if(const char *ta, const char *if_name, ioctl_set_ts_ctx *ctx)
{
    rpc_hwtstamp_config *hw_cfg = ctx->hw_cfg;
    struct ifreq         ifreq_var;
    sockts_rpcs         *srpc;

    int rc;
    int i;

    rc = sockts_rpcs_get(ta, &ctx->srpc_h, &srpc);
    if (rc != 0)
        return rc;

    if (srpc->sock < 0)
    {
        RPC_AWAIT_IUT_ERROR(srpc->rpcs);
        srpc->sock = rpc_socket(srpc->rpcs, RPC_PF_INET, RPC_SOCK_DGRAM,
                                RPC_PROTO_DEF);
        if (srpc->sock < 0)
        {
            ERROR("Failed to open socket: %r", RPC_ERRNO(srpc->rpcs));
            return TE_RC(TE_TAPI, TE_EFAIL);
        }
    }

    memset(&ifreq_var, 0, sizeof(ifreq_var));
    strncpy(ifreq_var.ifr_name, if_name, sizeof(ifreq_var.ifr_name));
    ifreq_var.ifr_data = (char *)hw_cfg;

    for (i = 0; i < IOCTL_ATTEMPTS_MAX; i++)
    {
        RPC_AWAIT_IUT_ERROR(srpc->rpcs);
        rc = rpc_ioctl(srpc->rpcs, srpc->sock, RPC_SIOCSHWTSTAMP, &ifreq_var);
        if (rc < 0)
        {
            if (!(hw_cfg->tx_type == RPC_HWTSTAMP_TX_ONESTEP_SYNC &&
                  RPC_ERRNO(srpc->rpcs) == RPC_ERANGE) &&
                  RPC_ERRNO(srpc->rpcs) != RPC_EAGAIN)
                RING_VERDICT("ioctl(SIOCSHWTSTAMP) failed with %s",
                             errno_rpc2str(RPC_ERRNO(srpc->rpcs)));

            if (RPC_ERRNO(srpc->rpcs) != RPC_EAGAIN)
                break;
            else
                TAPI_WAIT_TS;
        }
        else if (hw_cfg->tx_type == RPC_HWTSTAMP_TX_ONESTEP_SYNC)
            RING_VERDICT("ioctl(SIOCSHWTSTAMP) had to fail with ERANGE");

        if (rc == 0)
            break;
    }

    if (i == IOCTL_ATTEMPTS_MAX)
        RING_VERDICT("ioctl(SIOCSHWTSTAMP) failed with EAGAIN %d times",
                     IOCTL_ATTEMPTS_MAX);

    return 0;
}

/**
 * Callback function to set a value using ioctl(SIOCSHWTSTAMP) on real network
 * interfaces.
 *
 * @param ta        Test agent name
 * @param ifname    Interface name
 * @param opaque    The context (@c ioctl_set_ts_ctx)
 *
 * @return Status code.
 */
static te_errno
ioctl_set_ts_cb(const char *ta, const char *ifname, void *opaque)
{
    te_interface_kind kind;
    te_errno          rc;

    rc = tapi_cfg_get_if_kind(ta, ifname, &kind);
    if (rc != 0)
        return rc;

    if (kind == TE_INTERFACE_KIND_NONE)
        return ioctl_set_ts_if(ta, ifname, (ioctl_set_ts_ctx *)opaque);

    return tapi_host_ns_if_parent_iter(ta, ifname, &ioctl_set_ts_cb, opaque);
}

/* See description in timestamps.h */
te_errno
ioctl_set_ts(const char *ta, const char *if_name, rpc_hwtstamp_config *hw_cfg)
{
    te_errno         rc;
    te_errno         rc2;
    ioctl_set_ts_ctx ctx = {.hw_cfg = hw_cfg};

    sockts_rpcs_init(&ctx.srpc_h);

    rc = ioctl_set_ts_cb(ta, if_name, (void *)&ctx);

    rc2 = sockts_rpcs_release(&ctx.srpc_h);
    if (rc == 0)
        rc = rc2;

    return rc;
}

/* See description in the timestamps.h */
void
cmp_ts_with_hosttime(struct timespec *ts, test_substep *test_cb,
                     const char *ts_type)
{
    struct timespec host_ts_l;
    struct timespec host_ts_h;

    TIMEVAL_TO_TIMESPEC(&test_cb->low_time, &host_ts_l);
    TIMEVAL_TO_TIMESPEC(&test_cb->high_time, &host_ts_h);

    if (ts_cmp(&host_ts_l, ts) < 0 && ts_cmp(&host_ts_h, ts) > 0)
        return;

    if (ts_check_deviation(&host_ts_l, ts, 0, DEVIATION_PRECISION) ||
        ts_check_deviation(&host_ts_h, ts, 0, DEVIATION_PRECISION))
        TEST_VERDICT("%s timestamp differ from the host time too much",
                     ts_type);
}

/* See description in the timestamps.h */
void
cmp_ts_with_prev(struct timespec *ts_prev, struct timespec *ts,
                 test_substep *test_cb_prev, test_substep *test_cb)
{
    long low;
    long high;

    if (ts_cmp(ts_prev, ts) >= 0)
        TEST_VERDICT("Previous timestamps is more or equal to the current "
                     "one");

    low = TIMEVAL_SUB(test_cb->low_time, test_cb_prev->low_time);
    high = TIMEVAL_SUB(test_cb->high_time, test_cb_prev->high_time);

    if (ts_check_deviation(ts_prev, ts, (low + high) / 2,
                           DEVIATION_PRECISION))
        TEST_VERDICT("Previous and current timestamps differ too much");
}

/* See description in the timestamps.h */
rpc_scm_timestamping *
ts_check_msg_control_data(rpc_msghdr *msghdr, te_bool tx,
                          struct sock_extended_err *err_in,
                          const struct sockaddr *addr)
{
    struct sock_extended_err *err = NULL;
    struct sock_extended_err  template = {.ee_errno = ENOMSG,
                                          .ee_origin =
                                              SO_EE_ORIGIN_TIMESTAMPING};
    static te_bool             ext_err_reported = FALSE;
    struct sockaddr            sa;
    struct msghdr              msg;
    struct cmsghdr            *cmsg = NULL;
    rpc_scm_timestamping      *ts = NULL;

    /* Bug 56027: don't use type cast rpc_msghdr -> 'struct msghdr'! */
    memset(&msg, 0, sizeof(msg));
    msg.msg_control = msghdr->msg_control;
    msg.msg_controllen = msghdr->msg_controllen;

    if (msghdr->msg_controllen == 0)
        TEST_VERDICT("Control data length is zero");

    for (cmsg = CMSG_FIRSTHDR(&msg);
         cmsg != NULL;
         cmsg = CMSG_NXTHDR(&msg, cmsg))
    {
        if (cmsg->cmsg_level == socklevel_rpc2h(RPC_SOL_IP) &&
            cmsg->cmsg_type == sockopt_rpc2h(RPC_IP_RECVERR))
        {
            err = (struct sock_extended_err *)CMSG_DATA(cmsg);
            sockts_print_sock_extended_err(err);
            if (err_in == NULL)
                err_in = &template;
            if (memcmp(err_in, err, sizeof(*err)) != 0 && !ext_err_reported)
            {
                RING_VERDICT("Bad IP_RECVERR message was retrieved");
                ext_err_reported = TRUE;
            }

            if (addr == NULL)
                memset(&sa, 0, sizeof(sa));
            else
            {
                memcpy(&sa, addr, sizeof(sa));
                te_sockaddr_set_port(&sa, 0);
            }

            if (memcmp(&sa, (struct sockaddr_in *)SO_EE_OFFENDER(err),
                       sizeof(sa)) != 0)
            {
                ERROR("sockaddr is %s instead of %s",
                      te_sockaddr2str(SO_EE_OFFENDER(err)),
                      te_sockaddr2str(&sa));
                RING_VERDICT("Unexpected sockadd value in IP_RECVERR "
                             "control message");
            }
        }
        else if (cmsg->cmsg_level == socklevel_rpc2h(RPC_SOL_SOCKET) &&
            cmsg->cmsg_type == sockopt_rpc2h(RPC_SO_TIMESTAMPING))
            ts = (rpc_scm_timestamping *)CMSG_DATA(cmsg);
        else
            TEST_VERDICT("Unknown cmsg: level %d, type %d: %s",
                         cmsg->cmsg_level, cmsg->cmsg_type,
                         sockopt_rpc2str(cmsg_type_h2rpc(cmsg->cmsg_level,
                                                         cmsg->cmsg_type)));
    }

    if (!tx)
    {
        if (err != NULL)
            TEST_VERDICT("cmsg IP_RECVERR was unexpectedly extracted");
    }
    else if (err == NULL)
        TEST_VERDICT("cmsg IP_RECVERR was not extracted");

    if (ts == NULL)
        TEST_VERDICT("Failed to extract timestamp control message");

    return ts;
}

/**
 * Log control data from msghdr structure.
 *
 * @param msghdr      Pointer to rpc_msghdr structure.
 */
static void
ts_print_msg_control_data(rpc_msghdr *msghdr)
{
    char                       buf[1024];
    struct cmsghdr            *cmsg = NULL;
    struct msghdr              msg;
    te_string                  str = TE_STRING_BUF_INIT(buf);

    CHECK_RC(te_string_append(&str, "Control data: "));

    if (msghdr->msg_controllen == 0)
    {
        CHECK_RC(te_string_append(&str, "none"));
        RING("%s", str.ptr);
        return;
    }

    memset(&msg, 0, sizeof(msg));
    msg.msg_control = msghdr->msg_control;
    msg.msg_controllen = msghdr->msg_controllen;

    for (cmsg = CMSG_FIRSTHDR(&msg);
         cmsg != NULL;
         cmsg = CMSG_NXTHDR(&msg, cmsg))
    {
        if (cmsg != CMSG_FIRSTHDR(&msg))
            CHECK_RC(te_string_append(&str, ", "));

        CHECK_RC(te_string_append(&str, "level=%d type=%d (%s)",
                                  cmsg->cmsg_level, cmsg->cmsg_type,
                                   sockopt_rpc2str(
                                        cmsg_type_h2rpc(cmsg->cmsg_level,
                                                        cmsg->cmsg_type))));
    }

    RING("%s", str.ptr);
}

/* See description in the timestamps.h */
void
ts_check_cmsghdr_addr(rpc_msghdr *msg, int rc, size_t sent_len,
                      size_t recv_len, char *sndbuf,
                      te_bool tx, rpc_socket_type sock_type,
                      te_bool onload_ext, te_bool vlan,
                      te_bool check_flags,
                      const struct sockaddr *addr, struct timespec *ts_o,
                      struct timespec *ts_prev)
{
    rpc_onload_scm_timestamping_stream *ts_tx;
    rpc_scm_timestamping *ts;
    struct cmsghdr *cmsg = NULL;
    int hsize = 0;

    ts_print_msg_control_data(msg);

    if (tx)
    {
        if (sock_type == RPC_SOCK_DGRAM)
            hsize = LINUX_DGRAM_HEADER_LEN;
        else
            hsize = LINUX_TCP_HEADER_LEN;
    }

    if (ts_any_event(tx, sock_type) || onload_ext)
    {
        if (msg->msg_controllen == 0)
            TEST_VERDICT("Failed to retrieve timestamps, controllen is "
                         "zero");
        if (tx && check_flags)
            sockts_check_msg_flags(msg, RPC_MSG_ERRQUEUE);
    }
    else
    {
        if (msg->msg_controllen != 0)
            TEST_VERDICT("The field msg_controllen is unexpectedly "
                         "non-zero");
        if (ts_o != NULL)
            memset(ts_o, 0, sizeof(*ts_o));
        return;
    }

    if (tx && sock_type == RPC_SOCK_STREAM && onload_ext)
    {
        cmsg = sockts_msg_lookup_control_data(msg, SOL_SOCKET,
                         sockopt_rpc2h(RPC_ONLOAD_SCM_TIMESTAMPING_STREAM));

        if (cmsg == NULL)
            TEST_VERDICT("Failed to find control message for "
                         "ONLOAD_SCM_TIMESTAMPING_STREAM");

        ts_tx = (rpc_onload_scm_timestamping_stream *)CMSG_DATA(cmsg);
        ts_print_tcp_tx(ts_tx);

        if (!ts_timespec_is_zero(&ts_tx->last_sent))
            TEST_VERDICT("last_sent is not zero, probably the packet was "
                         "retransmitted");

        if (sent_len != 0 && ts_tx->len != sent_len)
        {
            ERROR("Expected segment size %" TE_PRINTF_SIZE_T "u, "
                  "reported %" TE_PRINTF_SIZE_T "u",
                  sent_len, ts_tx->len);

            TEST_VERDICT("TX timestamp returned wrong segment size");
        }

        if (ts_o != NULL)
            memcpy(ts_o, &ts_tx->first_sent, sizeof(*ts_o));
    }
    else
    {
        /* Don't check payload if @p recv_len is @c 0. */
        if (recv_len != 0)
        {
            if (tx && vlan)
                hsize += 4;

            if (rc - hsize != (int)recv_len)
                TEST_VERDICT("recvmsg() function returned unexpected "
                             "value");

            if (sndbuf != NULL &&
                memcmp(sndbuf, msg->msg_iov->iov_base + hsize,
                       recv_len) != 0)
                TEST_VERDICT("Bad packet was extracted with timestamps");
        }

        ts = ts_check_msg_control_data(msg, tx, NULL, addr);
        ts_print_sys(ts);

        if (ts_is_supported(TS_SOFTWARE, tx, sock_type))
        {
            if(ts_timespec_is_zero(&ts->systime))
                TEST_VERDICT("Software timestamp is zero");
            if (ts_o != NULL)
                memcpy(ts_o, &ts->systime, sizeof(*ts_o));
        }

        if (ts_is_supported(TS_SYS_HARDWARE, tx, sock_type))
        {
            if(ts_timespec_is_zero(&ts->hwtimetrans))
                TEST_VERDICT("HW transformed timestamp is zero");
            if (ts_o != NULL)
                memcpy(ts_o, &ts->hwtimetrans, sizeof(*ts_o));
        }

        if (ts_is_supported(TS_RAW_HARDWARE, tx, sock_type))
        {
            if(ts_timespec_is_zero(&ts->hwtimeraw))
                TEST_VERDICT("Raw HW timestamp is zero");
            if (ts_o != NULL)
                memcpy(ts_o, &ts->hwtimeraw, sizeof(*ts_o));
        }
    }

    if (ts_prev != NULL)
    {
        if (ts_cmp(ts_prev, ts_o) >= 0)
            RING_VERDICT("Timestamps are not monotonic");
        memcpy(ts_prev, ts_o, sizeof(*ts_prev));
    }
}

/* See description in the timestamps.h */
te_bool
ts_is_supported(ts_type ts, te_bool tx, rpc_socket_type sock_type)
{
    static te_bool init_envs = TRUE;
    static te_bool ts_tx_tcp;
    static te_bool ts_tx_sw;
    static te_bool ts_tx_sw_udp;
    static te_bool ts_sys_zero;
    static te_bool ts_tx_hw;
    static te_bool ts_rx_tcp;

    if (init_envs)
    {
        ts_tx_tcp = tapi_getenv_bool("IUT_TS_TX_TCP");
        ts_tx_sw = tapi_getenv_bool("IUT_TS_TX_SW");
        ts_tx_sw_udp = tapi_getenv_bool("IUT_TS_TX_SW_UDP");
        ts_sys_zero = tapi_getenv_bool("IUT_TS_SYS_ZERO");
        ts_tx_hw = tapi_getenv_bool("IUT_TS_TX_HW");
        ts_rx_tcp = tapi_getenv_bool("IUT_TS_RX_TCP");

        init_envs = FALSE;
    }

    if (sock_type == RPC_SOCK_STREAM &&
        ((tx && !ts_tx_tcp) || (!tx && !ts_rx_tcp)))
        return FALSE;

    switch (ts)
    {
        case TS_SOFTWARE:
            if (tx && !ts_tx_sw)
                return FALSE;
            if (sock_type == RPC_SOCK_DGRAM && !ts_tx_sw_udp)
                return FALSE;
            break;

        case TS_SYS_HARDWARE:
            if (ts_sys_zero || (tx && !ts_tx_hw))
                return FALSE;
            break;

        case TS_RAW_HARDWARE:
            if (tx && !ts_tx_hw)
                return FALSE;
            break;

        default:
            TEST_FAIL("Unknown timestamp type %d", ts);
    }

    return TRUE;
}

/* See description in the timestamps.h */
rpc_scm_timestamping *
ts_get_tx_ack_ts(rpc_msghdr *msg, int rc, int length, char *sndbuf)
{
    rpc_scm_timestamping     *ts_tx;
    struct sock_extended_err  template = {.ee_errno = ENOMSG,
                                          .ee_info = RPC_SCM_TSTAMP_ACK,
                                          .ee_origin =
                                              SO_EE_ORIGIN_TIMESTAMPING};

    if (rc != length)
        TEST_VERDICT("Wrong packet length is returned");
    if (memcmp(msg->msg_iov->iov_base, sndbuf, length) != 0)
        TEST_VERDICT("Bad packet was got with timestamps");
    if (msg->msg_controllen == 0)
        TEST_VERDICT("Failed to retrieve timestamps, controllen is zero");

    ts_tx = ts_check_msg_control_data(msg, TRUE, &template, NULL);
    ts_print_sys(ts_tx);

    return ts_tx;
}

/**
 * FIXME: This function is called after ts_check_cmsghdr_addr(), which
 * checks SW timestamp without checking, that HW timestamp is not zero.
 * And this one checks only HW, without checking SW.
 * To improve both checks this function should be integrated to
 * ts_check_cmsghdr_addr(), and it should return all three timestamps: SW,
 * SYS HW and RAW HW for further checking in certain tests. Now
 * ts_check_cmsghdr_addr() returns only one timestamp.
 */
void
ts_check_second_cmsghdr(rcf_rpc_server *rpcs, int s,
                        rpc_msghdr *msg,
                        struct timespec *ts_check,
                        const struct sockaddr *addr,
                        struct sock_extended_err *err_in,
                        te_bool skip_check,
                        te_bool *zero_ts_reported,
                        te_bool *no_ts_reported)
{
/* Maximum deviation */
#define DEV_MS 10000

/* Lenght for packet with cmsg header */
#define PKT_LEN 2000

    struct timespec       ts_hw;
    rpc_scm_timestamping *ts;
    int                   rc;

    rpc_msghdr  msg_aux = {.msg_iov = NULL, .msg_control = NULL};
    rpc_msghdr *msg_ptr;

    RPC_AWAIT_IUT_ERROR(rpcs);
    /*
     * There are no SW timestamps in Onload and SOF_TIMESTAMPING_OPT_TX_SWHW
     * is not supported, so HW timestamp was returned in the first message
     * and there is no second one.
     */
    if (tapi_onload_run())
        return;

    if (msg == NULL)
    {
        ts_init_msghdr(TRUE, &msg_aux, PKT_LEN);
        rc = rpc_recvmsg(rpcs, s, &msg_aux,
                         RPC_MSG_ERRQUEUE | RPC_MSG_DONTWAIT);
        if (rc < 0)
        {
            if (no_ts_reported == NULL || !(*no_ts_reported))
            {
                *no_ts_reported = TRUE;
                ERROR_VERDICT("Second timestamp was not received.");
            }
            return;
        }
        msg_ptr = &msg_aux;
    }
    else
    {
        msg_ptr = msg;
    }

    ts_print_msg_control_data(msg_ptr);
    if (skip_check)
        return;
    ts = ts_check_msg_control_data(msg_ptr, TRUE, err_in, addr);
    ts_print_sys(ts);

    if(ts_timespec_is_zero(&ts->hwtimeraw))
    {
        if (zero_ts_reported == NULL || !(*zero_ts_reported))
        {
            if (zero_ts_reported != NULL)
                *zero_ts_reported = TRUE;
            ERROR_VERDICT("Raw HW timestamp in second packet is zero");
        }
        return;
    }
    if (ts_check != NULL)
    {
        memcpy(&ts_hw, &ts->hwtimeraw, sizeof(ts_hw));
        if (ts_cmp(ts_check, &ts_hw) >= 0)
            RING_VERDICT("Timestamps are not monotonic");
        ts_check_deviation(&ts_hw, ts_check, 0, DEV_MS);
    }
#undef DEV_MS
#undef PKT_LEN
}
