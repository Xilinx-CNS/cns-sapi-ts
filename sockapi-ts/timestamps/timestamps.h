/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Common macros and functions for timestamps API.
 *
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 *
 * $Id$
 */

#ifndef __SOCKAPI_TS_TIMESTAMPS_H__
#define __SOCKAPI_TS_TIMESTAMPS_H__

#include "parse_icmp.h"

/** Allowed difference between hwtimeraw and hwtimetrans when NIC clocks are
 * synced. */
#define HWTIMETRANS_PRECISION 1000

#define TAPI_WAIT_TS \
do {                                            \
    int _usec = 100000;                         \
    usleep(_usec);                              \
    RING("Sleep for %d microseconds", _usec);   \
} while (0)

/** Full datagram header length: MAC+IP+UDP.  */
#define LINUX_DGRAM_HEADER_LEN 42

/** Full TCP header length: MAC+IP+TCP.  */
#define LINUX_TCP_HEADER_LEN 66

/** MAC address length.  */
#define LINUX_ETH_HEADER_LEN 14

/**
 * Structure to keep delays between transmitted packets.
 */
typedef struct test_substep {
    unsigned int   delay;           /**< Delay to sleep between
                                         sending datagrams */
    struct tarpc_timeval low_time;  /**< Low boundary for timestamp 
                                         obtaind with ioctl() */
    struct tarpc_timeval high_time; /**< Upper boundary for timestamp
                                         obtaind with ioctl() */
} test_substep;

/**
 * Check whether @p ts is filled by zeroes.
 * 
 * @param ts    Timestamp
 * 
 * @return @c TRUE if @p ts is filled by zeroes.
 */
static inline te_bool ts_timespec_is_zero(struct timespec *ts)
{
    return ts->tv_sec == 0 && ts->tv_nsec == 0;
}

/**
 * Calculate difference in microseconds two timespec structures.
 * 
 * @param fist       First timestamp
 * @param second     Second timestamp
 * 
 * @return Difference in microseconds
 */
static inline int64_t ts_timespec_diff_us(struct timespec *first,
                                          struct timespec *second)
{
    return llabs((first->tv_sec - second->tv_sec) * (int64_t)1000000 +
                 (first->tv_nsec - second->tv_nsec) / (int64_t)1000);
}

/**
 * Check that difference between two timestamps is not more then
 * allowed @p deviation.
 * 
 * @param fist       First timestamp
 * @param second     Second timestamp
 * @param deviation  Expected difference in microseconds
 * @param precision  Allowed precision in microseconds
 * 
 * @return @c TRUE if the deviation does not satisfy allowed conditions
 */
static inline te_bool ts_check_deviation(struct timespec *first,
                                         struct timespec *second,
                                         int deviation,
                                         int precision)
{
    int64_t diff = ts_timespec_diff_us(first, second);

    return diff < deviation - precision || diff > deviation + precision;
}

/**
 * Compare two timespec structures values.
 * 
 * @param fist       First timestamp
 * @param second     Second timestamp
 * 
 * @return @c 1 if @p first is greater than @p second
 * @return @c -1 if @p first is less than @p second
 * @return @c 0 if @p first and @p second are equal
 */
static inline int ts_cmp(struct timespec *first, struct timespec *second)
{
    if (first->tv_sec > second->tv_sec)
        return 1;
    if (first->tv_sec < second->tv_sec)
        return -1;

    if (first->tv_nsec > second->tv_nsec)
        return 1;
    if (first->tv_nsec < second->tv_nsec)
        return -1;

    return 0;
}

/**
 * Print TCP TX timestamps.
 * 
 * @param ts    TCP TX timestamps structure
 */
static inline void ts_print_tcp_tx(rpc_onload_scm_timestamping_stream *ts)
{
    RING("TCP TX timestamp: first_sent %d.%ld, last_sent %d.%ld, len %d",
             (int)ts->first_sent.tv_sec, ts->first_sent.tv_nsec,
             (int)ts->last_sent.tv_sec, ts->last_sent.tv_nsec,
             (int)ts->len);
}

/**
 * Print timestamps.
 * 
 * @param ts    Timestamps location
 */
static inline void ts_print_sys(rpc_scm_timestamping *ts)
{
    RING("SW     : %d s %ld ns\n"
         "HW SYS : %d s %ld ns\n"
         "HW RAW : %d s %ld ns",
         (int)ts->systime.tv_sec, ts->systime.tv_nsec,
         (int)ts->hwtimetrans.tv_sec, ts->hwtimetrans.tv_nsec,
         (int)ts->hwtimeraw.tv_sec, ts->hwtimeraw.tv_nsec);
}

/**
 * Enable HW timestamps.
 * 
 * @param pco        RPC server handler
 * @param sock       Socket
 * @param sock_type  Socket type
 * @param tx         @c TRUE to enable TX timestamps, @c FALSE - RX.
 * @param onload_ext Onload extension TCP timestamps
 */
static inline void ts_enable_hw_ts(rcf_rpc_server *pco, int sock,
                                   rpc_socket_type sock_type, te_bool tx, 
                                   te_bool onload_ext)
{
    int flags = 0;

    flags = RPC_SOF_TIMESTAMPING_SYS_HARDWARE |
            RPC_SOF_TIMESTAMPING_RAW_HARDWARE |
            RPC_SOF_TIMESTAMPING_SOFTWARE;

    if (tx && sock_type == RPC_SOCK_STREAM && onload_ext)
        flags |= RPC_ONLOAD_SOF_TIMESTAMPING_STREAM;

    if (tx)
    {
        flags |= RPC_SOF_TIMESTAMPING_TX_HARDWARE |
                 RPC_SOF_TIMESTAMPING_TX_SOFTWARE;
        /* ST-2712: Onload returns EINVAL with such flag. */
        if (!tapi_onload_run())
            flags |= RPC_SOF_TIMESTAMPING_OPT_TX_SWHW;
    }
    else
    {
        flags |= RPC_SOF_TIMESTAMPING_RX_HARDWARE |
                 RPC_SOF_TIMESTAMPING_RX_SOFTWARE;
    }

    rpc_setsockopt_int(pco, sock, RPC_SO_TIMESTAMPING, flags);
    TAPI_WAIT_NETWORK;
}

/**
 * Call ioctl(SIOCSHWTSTAMP) to set new value.
 *
 * @note This function may change state for more than one interface
 *       in case of bonding.
 *
 * @param ta          Test agent
 * @param if_name     Interface name
 * @param hw_cfg      New value to be set
 *
 * @return Status code.
 */
extern te_errno ioctl_set_ts(const char *ta, const char *if_name,
                             rpc_hwtstamp_config *hw_cfg);

/**
 * Compare retrieved timestamp with the host time.
 * 
 * @param ts        Timestamp
 * @param test_cb   Iteration context
 * @param ts_type   Timestamp type string
 */
extern void cmp_ts_with_hosttime(struct timespec *ts,
                                 test_substep *test_cb,
                                 const char *ts_type);

/**
 * Compare retrieved timestamp with the previous one.
 * 
 * @param ts_prev       Previous timestamp
 * @param ts            Current timestamp
 * @param test_cb_prev  Previous iteration context
 * @param test_cb       Current iteration context
 * @param ts_type       Timestamp type
 * @param i             Iteration index
 */
extern void cmp_ts_with_prev(struct timespec *ts_prev, struct timespec *ts,
                             test_substep *test_cb_prev,
                             test_substep *test_cb);

/**
 * Check received cmsg sanity
 * 
 * @param msg             cmsg itself
 * @param rc              Returned bytes number of message payload
 * @param sent_len        Length of sent packet. Used only for checking
 *                        that Onload TCP TX timestamp returns correct
 *                        packet length. If zero, not checked.
 * @param recv_len        Length of data which is expected to be received
 *                        (may differ from @p sent_len if there is not
 *                        enough space in iovec buffers). If zero,
 *                        not checked.
 * @param sndbuf          Buffer with sent data
 * @param tx              Determine is it TX or RX packet handling
 * @param sock_type       Socket type
 * @param onload_ext      Onload extension TCP timestamps
 * @param vlan            Interface is VLAN
 * @param check_flags     if @c TRUE, check flags
 * @param addr            Event address or @c NULL
 * @param ts_o            Extracted timestamp
 * @param ts_prev         Extracted in the previous iteration timestamp
 */
extern void ts_check_cmsghdr_addr(rpc_msghdr *msg, int rc,
                                  size_t sent_len,
                                  size_t recv_len,
                                  char *sndbuf, te_bool tx,
                                  rpc_socket_type sock_type,
                                  te_bool onload_ext,
                                  te_bool vlan,
                                  te_bool check_flags,
                                  const struct sockaddr *addr,
                                  struct timespec *ts_o,
                                  struct timespec *ts_prev);

/**
 * Check received cmsg sanity
 * 
 * @param msg       cmsg itself
 * @param rc        Returned bytes number of message payload
 * @param length    Expected bytes number of message payload.
 *                  If zero, payload is not checked.
 * @param sndbuf    Buffer with sent data
 * @param tx        Determine is it TX or RX packet handling
 * @param sock_type Socket type
 * @param onload_ext Onload extension TCP timestamps
 * @param vlan      Interface is VLAN
 * @param ts_o      Extracted timestamp
 * @param ts_prev   Extracted in the  previous iteration timestamp
 */
static inline void
ts_check_cmsghdr(rpc_msghdr *msg, int rc, size_t length, char *sndbuf,
                 te_bool tx, rpc_socket_type sock_type, te_bool onload_ext,
                 te_bool vlan, struct timespec *ts_o,
                 struct timespec *ts_prev)
{
    ts_check_cmsghdr_addr(msg, rc, length, length, sndbuf, tx, sock_type,
                          onload_ext, vlan, TRUE, NULL, ts_o, ts_prev);
}

/**
 * Check second received TS cmsg sanity. Two timestamp messages are
 * received when both SW and HW timestamps are enabled and
 * @c SOF_TIMESTAMPING_OPT_TX_SWHW flag is set.
 *
 * @param rpcs             RPC server
 * @param s                Socket
 * @param msg              cmsg itself or @c NULL if it should be received
 *                         by this function
 * @param ts_check         Timestamp for comparison with obtained one or
 *                         @c NULL
 * @param addr             Address for comparison with obtained one or
 *                         @c NULL
 * @param err_in           Expected extended error value or @c NULL
 * @param skip_check       Receive message but do not check it
 * @param zero_ts_reported Whether already reported that HW timestamp is
 *                         zero or @c NULL
 * @param no_ts_reported   Whether already reported that there is no HW
 *                         timestamp in the message or @c NULL
 */
extern void ts_check_second_cmsghdr(rcf_rpc_server *rpcs, int s,
                                    rpc_msghdr *msg,
                                    struct timespec *ts_check,
                                    const struct sockaddr *addr,
                                    struct sock_extended_err *err_in,
                                    te_bool skip_check,
                                    te_bool *zero_ts_reported,
                                    te_bool *no_ts_reported);

/**
 * Timestamps types.
 */
typedef enum ts_type {
    TS_SOFTWARE = 0,    /**< Softare timestamp */
    TS_SYS_HARDWARE,    /**< Transmofrmed HW timestamps */
    TS_RAW_HARDWARE,    /**< RAW HW timestamps */
} ts_type;

/**
 * Check if timestamp @p ts is supported on IUT.
 * 
 * @param ts          Timestamp type
 * @param tx          Is it transmit or receive timestamps
 * @param sock_type   Socket type
 * 
 * @return @c TRUE if the timestamp is supported
 */
extern te_bool ts_is_supported(ts_type ts, te_bool tx,
                               rpc_socket_type sock_type);

/**
 * Check if any timestamp event can be expected on IUT.
 * 
 * @param tx          Is it transmit or receive timestamps
 * @param sock_type   Socket type
 * 
 * @return @c TRUE if the timestamp is supported
 */
static inline te_bool
ts_any_event(te_bool tx, rpc_socket_type sock_type)
{
    if (ts_is_supported(TS_SOFTWARE, tx, sock_type))
        return TRUE;
    if (ts_is_supported(TS_SYS_HARDWARE, tx, sock_type))
        return TRUE;
    if (ts_is_supported(TS_RAW_HARDWARE, tx, sock_type))
        return TRUE;

    return FALSE;
}

/**
 * Get TCP ACK timestamp and check the packet length and payload.
 * 
 * @param msg       cmsg itself
 * @param rc        Returned bytes number of message payload
 * @param length    Expeted bytes number of message payload
 * @param sndbuf    Buffer with sent data
 */
extern rpc_scm_timestamping * ts_get_tx_ack_ts(rpc_msghdr *msg, int rc,
                                               int length, char *sndbuf);

/**
 * Check control data messages which are received when timestamps are read.
 * 
 * @param msghdr    The message with the control data
 * @param tx        Data trsnsmission direction
 * @param err_in    Expected extended error value or @c NULL
 * @param addr      Event address or @c NULL
 * 
 * @return Pointer to timestamps structure.
 */
extern rpc_scm_timestamping * ts_check_msg_control_data(rpc_msghdr *msghdr,
                                           te_bool tx,
                                           struct sock_extended_err *err_in,
                                           const struct sockaddr *addr);

/**
 * Initialize msghdr structure with required buffers allocation,
 * @b msg_flags check will not be done in RPC if TX timestamp is expected.
 *
 * @param tx        Transmit timestamp is expected
 * @param msg       The structure location
 * @param length    Payload buffer length
 */
static inline void
ts_init_msghdr(te_bool tx, rpc_msghdr *msg, int length)
{
    sockts_init_msghdr(msg, length);
    if (tx)
        msg->msg_flags_mode = RPC_MSG_FLAGS_NO_CHECK;
}

/**
 * Initialize mmsghdr structure with required buffers allocation,
 * @b msg_flags check will not be done in RPC if TX timestamp is expected.
 *
 * @param tx        Transmit timestamp is expected
 * @param num       Messages number
 * @param length    Payload buffer length
 * @param mmsg      Messages array location
 */
static inline void
ts_init_mmsghdr(te_bool tx, int num, int length,
                struct rpc_mmsghdr **mmsg_o)
{
    init_mmsghdr(num, length, mmsg_o);

    if (tx)
    {
        int i;

        for (i = 0; i < num; i++)
            (*mmsg_o)[i].msg_hdr.msg_flags_mode = RPC_MSG_FLAGS_NO_CHECK;
    }
}

/**
 * Check if IUT interface or one of its parents is VLAN interface.
 *
 * @note The function jumps to @b cleanup in case of error.
 *
 * @param rpcs      RPC server
 * @param if_name   Interface name
 *
 * @return @c TRUE if there is VLAN in the interface relatives.
 */
static inline te_bool
ts_check_vlan(rcf_rpc_server *rpcs, const char *if_name)
{
    size_t num;

    CHECK_RC(tapi_interface_vlan_count(rpcs->ta, if_name, &num));

    if (num > 0)
        return TRUE;
    return FALSE;
}

#endif /* __SOCKAPI_TS_TIMESTAMPS_H__ */
