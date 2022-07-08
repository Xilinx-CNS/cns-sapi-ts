/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 * 
 * $Id$
 */

/** @page sockopts-ip_recvopts Usage of IP_OPTIONS and IP_RECVOPTS socket options with connectionless sockets
 *
 * @objective Check that @c IP_OPTIONS socket option can be used to set IP
 *            options to be sent with every packet originated from the
 *            socket, and that @c IP_RECVOPTS socket option can be used to
 *            force @b recvmsg() function return IP options of incoming 
 *            packets in ancillary data.
 *
 * @type conformance
 *
 * @reference MAN 7 ip
 *
 * @param pco_snd       PCO on sender (it can be IUT or TESTER)
 * @param pco_rcv       PCO on receiver (it can be IUT or TESTER)
 * @param use_sendmmsg  Whether to use @p sendmmsg() instead of
 *                      @b sendmsg()
 *
 * @note This test should be performed twice with the following values of
 * the parameters:
 * -#
 *     - @p pco_snd - PCO on IUT
 *     - @p pco_rcv - PCO on TESTER
 *     .
 * -#
 *     - @p pco_snd - PCO on TESTER
 *     - @p pco_rcv - PCO on IUT
 *     .
 *
 * @par Test sequence:
 * -# Create @p snd socket of type @c SOCK_DGRAM on @p pco_snd.
 * -# Create @p rcv socket of type @c SOCK_DGRAM on @p pco_rcv.
 * -# @b bind() @p rcv socket to a local address.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b getsockopt() on @p snd socket with @c IP_OPTIONS socket option
 *    passing buffer of size 44 bytes as @a option_value parameter.
 * -# Check that the value of @a option_len parameter is updated to zero -
 *    there is no IP options defined on the socket.
 * -# Call @b getsockopt() on @p rcv socket with @c IP_RECVOPTS socket option
 *    and log the initial value of this option @p recvopts_init.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Send some data from @p snd socket to @p rcv socket.
 * -# Call @b recvmsg() on @p rcv socket passing enough room to 
 *    @a msg_control field of @c msghdr structure.
 * -# Check that there is no @c cmsghdr structure with @a cmsg_level 
 *    equals to @c IPPROTO_IP and @a cmsg_type set to @c IP_OPTIONS or
 *    @c IP_RECVOPTS.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b setsockopt() on @p rcv socket enabling @c IP_RECVOPTS socket
 *    option.
 * -# Call @b getsockopt() on @p rcv socket with @c IP_RECVOPTS socket option
 *    and check that it is enabled.
 * -# Send some data from @p snd socket to @p rcv socket.
 * -# Call @b recvmsg() on @p rcv socket passing enough room to 
 *    @a msg_control field of @c msghdr structure.
 * -# Check that there is no @c cmsghdr structure with @a cmsg_level 
 *    equals to @c IPPROTO_IP and @a cmsg_type set to @c IP_OPTIONS or
 *    @c IP_RECVOPTS.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b setsockopt() on @p snd socket with @c IP_OPTIONS socket option
 *    setting some IP options @p new_opts for outgoing packets.
 * -# Call @b getsockopt() on @p snd socket with @c IP_OPTIONS socket option
 *    and check that its value the same as @p new_opts.
 * -# Send some data from @p snd socket to @p rcv socket.
 * -# Call @b recvmsg() on @p rcv socket passing enough room to 
 *    @a msg_control field of @c msghdr structure.
 * -# Check that there is @c cmsghdr structure with @a cmsg_level equals to 
 *    @c IPPROTO_IP and @a cmsg_type set to @c IP_OPTIONS or @c IP_RECVOPTS.
 * -# Check that the value obtained from @c cmsghdr structure is the same as
 *    @p new_opts.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b setsockopt() on @p rcv socket disabling @c IP_RECVOPTS socket
 *    option.
 * -# Call @b getsockopt() on @p rcv socket with @c IP_RECVOPTS socket option
 *    and check that it is disabled.
 * -# Send some data from @p snd socket to @p rcv socket.
 * -# Call @b recvmsg() on @p rcv socket passing enough room to 
 *    @a msg_control field of @c msghdr structure.
 * -# Check that there is no @c cmsghdr structure with @a cmsg_level equals 
 *    to @c IPPROTO_IP and @a cmsg_type set to @c IP_OPTIONS or 
 *    @c IP_RECVOPTS.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * * -# Call @b setsockopt() on @p snd socket with @c IP_OPTIONS socket option
 *    passing zero as the value of @a option_len parameter (remove all IP
 *    options on the socket).
 * -# Call @b getsockopt() on @p snd socket with @c IP_OPTIONS socket option
 *    and check that it updates @a option_len parameter to zero.
 * -# Send some data from @p snd socket to @p rcv socket.
 * -# Call @b recvmsg() on @p rcv socket passing enough room to 
 *    @a msg_control field of @c msghdr structure.
 * -# Check that there is no @c cmsghdr structure with @a cmsg_level equals to 
 *    @c IPPROTO_IP and @a cmsg_type set to @c IP_OPTIONS or @c IP_RECVOPTS.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * * -# Close @p rcv and @p snd sockets.
 * 
 * @note
 * -# @anchor sockopts_ip_recvopts_1
 *    Some implementations can use @c IP_RECVOPTIONS as the value 
 *    of @a cmsg_type field of @c cmsghdr structure, so that it is
 *    better to check @a cmsg_type field of each structure agains
 *    @c IP_OPTIONS and @c IP_RECVOPTS values and report actual value.
 * 
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/ip_recvopts"

#include "sockapi-test.h"
#include <netinet/ip.h>

 
#define TST_VEC          1
#define TST_CMSG_LEN     300
#define TST_OPTIONS_LEN  44

#define IP_TS_OPTS_LEN  12

#define TST_PASS_DATA(_send) \
    do {                                                        \
        memset(cmsg_buf, 0, TST_CMSG_LEN);                      \
        if (_send)                                              \
            RPC_WRITE(sent, pco_snd, snd, tx_buf, buf_len);     \
        rx_msghdr.msg_controllen = TST_CMSG_LEN;                \
        rx_msghdr.msg_cmsghdr_num = 1;                          \
        received = recv_f(pco_rcv, rcv, &rx_msghdr, 0);         \
        if (received != (int)buf_len)                                \
            TEST_VERDICT("data size mismatch");                 \
        cmsg = sockts_msg_lookup_control_data(&rx_msghdr, SOL_IP, \
                                              IP_RECVOPTS);      \
    } while (0)


int
main(int argc, char *argv[])
{
    int             i;
    int             sent = 0;
    int             received = 0;
    rcf_rpc_server *pco_snd = NULL;
    rcf_rpc_server *pco_rcv = NULL;
    int             snd = -1;
    int             rcv = -1;

    const struct sockaddr  *rcv_addr;
    void                   *tx_buf = NULL;
    void                   *rx_buf = NULL;
    struct rpc_iovec        rx_vector[TST_VEC];
    struct rpc_iovec        tx_vector[TST_VEC];
    uint8_t                 cmsg_buf[TST_CMSG_LEN];
    uint8_t                 tx_cmsg_buf[TST_CMSG_LEN];
    rpc_msghdr              rx_msghdr;
    rpc_msghdr              tx_msghdr;
    struct cmsghdr         *cmsg;
    size_t                  buf_len;

    int                     recv_init;
    uint8_t                 my_opts[IP_TS_OPTS_LEN] =
                                { IPOPT_TIMESTAMP, IP_TS_OPTS_LEN, 5, 0, };
    uint8_t                 opts_buf[TST_OPTIONS_LEN];
    socklen_t               opts_len;
    int                     int_opt;
    uint8_t                *optptr;
    te_bool                 test_fail = FALSE;
    te_bool                 use_retopts;
    te_bool                 use_sendmmsg = FALSE;

    rpc_msg_read_f recv_f;

    TEST_START;
    TEST_GET_PCO(pco_snd);
    TEST_GET_PCO(pco_rcv);
    TEST_GET_ADDR(pco_rcv, rcv_addr);
    TEST_GET_MSG_READ_FUNC(recv_f);
    TEST_GET_BOOL_PARAM(use_retopts);
    TEST_GET_BOOL_PARAM(use_sendmmsg);

    /* Prepare data to transmit */
    CHECK_NOT_NULL((tx_buf = sockts_make_buf_dgram(&buf_len)));
    rx_buf = te_make_buf_by_len(buf_len);


    for (i = 0; i < TST_VEC; i++)
    {
        rx_vector[i].iov_base = rx_buf;
        rx_vector[i].iov_len = rx_vector[i].iov_rlen = buf_len;
    }

    tx_vector[0].iov_base = tx_buf;
    tx_vector[0].iov_len = tx_vector[0].iov_rlen = buf_len;

    memset(&rx_msghdr, 0, sizeof(rx_msghdr));
    rx_msghdr.msg_iovlen = rx_msghdr.msg_riovlen = TST_VEC;
    rx_msghdr.msg_iov = rx_vector;
    rx_msghdr.msg_control = cmsg_buf;
    rx_msghdr.msg_controllen = TST_CMSG_LEN;
    rx_msghdr.msg_cmsghdr_num = 1;

    memset(&tx_msghdr, 0, sizeof(tx_msghdr));
    tx_msghdr.msg_iovlen = tx_msghdr.msg_riovlen = TST_VEC;
    tx_msghdr.msg_iov = tx_vector;
    tx_msghdr.msg_control = tx_cmsg_buf;
    tx_msghdr.msg_controllen = TST_CMSG_LEN;
    tx_msghdr.msg_cmsghdr_num = 1;

    snd = rpc_socket(pco_snd, rpc_socket_domain_by_addr(rcv_addr),
                     RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rcv = rpc_socket(pco_rcv, rpc_socket_domain_by_addr(rcv_addr),
                     RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    rpc_bind(pco_rcv, rcv, rcv_addr);

    memset(&opts_buf, 0, sizeof(opts_buf));
    opts_len = sizeof(opts_buf);
    rpc_getsockopt_raw(pco_snd, snd, RPC_IP_OPTIONS, opts_buf, &opts_len);
    if (opts_len != 0)
    {
        TEST_VERDICT("Default IP_OPTIONS option are not empty");
    }
    rpc_getsockopt(pco_rcv, rcv, RPC_IP_RECVOPTS, &recv_init);

    WARN("IP_RECVOPTS option default value is %d", recv_init);

    rpc_connect(pco_snd, snd, rcv_addr);

    TST_PASS_DATA(TRUE);

    if (cmsg != NULL)
    {
        TEST_VERDICT("No ancillary data are requested using socket "
                     "option, but some data have been returned");
    }

    int_opt = 1;
    rpc_setsockopt(pco_rcv, rcv, RPC_IP_RECVOPTS, &int_opt);
    rpc_getsockopt(pco_rcv, rcv, RPC_IP_RECVOPTS, &int_opt);
    if (int_opt == 0)
    {
        TEST_VERDICT("Cannot enable delivery of IP_OPTIONS in ancillary "
                     "data");
    }

    TST_PASS_DATA(TRUE);

    if (cmsg != NULL)
    {
        TEST_VERDICT("No IP options sent by peer, but some unexpected "
                     "data have been received as ancillary data");
    }

    if (!use_retopts)
    {
        rpc_setsockopt_raw(pco_snd, snd, RPC_IP_OPTIONS,
                           my_opts, sizeof(my_opts));

        memset(&opts_buf, 0, sizeof(opts_buf));
        opts_len = sizeof(opts_buf);
        rpc_getsockopt_raw(pco_snd, snd, RPC_IP_OPTIONS, opts_buf, &opts_len);

        if (opts_len != sizeof(my_opts))
        {
            if (opts_len == 0)
            {
                ERROR_VERDICT("Set IP_OPTIONS (IP timestamp) is not returned "
                              "on get request");
                test_fail = TRUE;
            }
            else
            {
                TEST_VERDICT("Unexpected IP_OPTIONS value length %u, "
                             "set and expected is %u", (unsigned)opts_len,
                             (unsigned)sizeof(my_opts));
            }
        }
        else if (memcmp(opts_buf, my_opts, sizeof(my_opts)) != 0)
        {
            TEST_VERDICT("IP timestamp option is not set");
        }
    }
    else
    {
        struct msghdr msg;

        int_opt = 1;
        rpc_setsockopt(pco_snd, snd, RPC_IP_RETOPTS, &int_opt);
        memset(tx_cmsg_buf, 0, TST_CMSG_LEN);
        tx_msghdr.msg_controllen = CMSG_SPACE(sizeof(my_opts));
        tx_msghdr.msg_cmsghdr_num = 1;

        /* Bug 56027: don't use type cast rpc_msghdr -> 'struct msghdr'! */
        memset(&msg, 0, sizeof(msg));
        msg.msg_control = tx_msghdr.msg_control;
        msg.msg_controllen = tx_msghdr.msg_controllen;
        cmsg = (struct cmsghdr *)CMSG_FIRSTHDR(&msg);

        /* Construct in_pktinfo */
        cmsg->cmsg_level = SOL_IP;
        cmsg->cmsg_type = IP_RETOPTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(my_opts));
        memcpy(CMSG_DATA(cmsg), my_opts, sizeof(my_opts));
        rc = (use_sendmmsg ?
                rpc_sendmmsg_as_sendmsg : rpc_sendmsg)
                                        (pco_snd, snd, &tx_msghdr, 0);
    }
    TST_PASS_DATA((!use_retopts));

    if (cmsg == NULL)
    {
        TEST_VERDICT("Delivery of IP options is enabled and IP options "
                     "sent by peer, but no ancillary data are received");
    }

    if (cmsg->cmsg_len != CMSG_LEN(sizeof(my_opts)) ||
        cmsg->cmsg_level != SOL_IP || cmsg->cmsg_type != IP_RECVOPTS)
    {
        TEST_VERDICT("Unexpected ancillary data are returned on receiver "
                     "socket: len=%u level=%s type=%s",
                     (unsigned)cmsg->cmsg_len,
                     socklevel_rpc2str(socklevel_h2rpc(cmsg->cmsg_level)),
                     sockopt_rpc2str(cmsg_type_h2rpc(cmsg->cmsg_level,
                                                     cmsg->cmsg_type)));
    }

    optptr = (uint8_t *)CMSG_DATA(cmsg);
    if (optptr[0] != my_opts[0] || optptr[1] != my_opts[1])
    {
        TEST_VERDICT("Invalid IP options are returned on receiver "
                     "socket as message ancillary data");
    }

    int_opt = 0;
    rpc_setsockopt(pco_rcv, rcv, RPC_IP_RECVOPTS, &int_opt);
    rpc_getsockopt(pco_rcv, rcv, RPC_IP_RECVOPTS, &int_opt);
    if (int_opt != 0)
    {
        TEST_VERDICT("Cannot disable delivery of IP_OPTIONS in ancillary "
                     "data");
    }
    TST_PASS_DATA(TRUE);

    if (cmsg != NULL)
    {
        TEST_VERDICT("No ancillary data are requested using socket "
                     "option, but some data have been returned");
    }

    /* Clear option that have been set above */
    rpc_setsockopt_raw(pco_snd, snd, RPC_IP_OPTIONS, NULL, 0);

    memset(&opts_buf, 0, sizeof(opts_buf));
    opts_len = sizeof(opts_buf);
    rpc_getsockopt_raw(pco_snd, snd, RPC_IP_OPTIONS, opts_buf, &opts_len);
    if (opts_len != 0)
    {
        TEST_VERDICT("Cannot clear IP_OPTIONS option value");
    }

    int_opt = 1;
    rpc_setsockopt(pco_rcv, rcv, RPC_IP_RECVOPTS, &int_opt);
    rpc_getsockopt(pco_rcv, rcv, RPC_IP_RECVOPTS, &int_opt);
    if (int_opt == 0)
    {
        TEST_VERDICT("Cannot re-enable delivery of IP_OPTIONS in "
                     "ancillary data");
    }

    TST_PASS_DATA(TRUE);

    if (cmsg != NULL)
    {
        TEST_VERDICT("No IP options sent by peer, but some unexpected "
                     "data have been received as ancillary data");
    }

    if (test_fail)
    {
        RING_VERDICT("IP options are sent and successfully received "
                     "and reported by peer");
        TEST_STOP;
    }
    else
        TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_snd, snd);
    CLEANUP_RPC_CLOSE(pco_rcv, rcv);

    free(tx_buf);
    free(rx_buf);

    TEST_END;
}
