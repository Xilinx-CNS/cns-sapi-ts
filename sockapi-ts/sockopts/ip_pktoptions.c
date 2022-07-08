/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-ip_pktoptions Usage of IP_PKTOPTIONS socket option
 *
 * @objective Check that @c IP_PKTOPTIONS socket option allows
 *            to obtain values of @c IP_PKTINFO and @c IP_TTL
 *            socket options via CMSG interface on @c SOCK_STREAM
 *            socket.
 *
 * @type conformance
 *
 * @reference Linux kernel sources
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst           PCO on TESTER
 * @param iut_if            Interface on @p pco_iut
 * @param iut_addr          Unicast address on @p pco_iut
 * @param tst_addr          Unicast address on @p pco_tst
 * @param garbage           Whether buffer to store value
 *                          of @c IP_PKTOPTIONS socket option
 *                          should be cleared or not before
 *                          @b getsockopt() call
 * @param active_connection Whether @p iut_s socket should
 *                          be connected to @p tst_s socket
 *                          actively or passively
 * @param traffic           Whether some data should be sent
 *                          (received) before calling @b
 *                          getsockopt() or not
 * @param set_pktinfo       Whether @c IP_PKTINFO socket option
 *                          should be set before getting value
 *                          of @c IP_PKTOPTIONS or not
 * @param set_pktinfo       Whether @c IP_RCVTTL socket option
 *                          should be set before getting value
 *                          of @c IP_PKTOPTIONS or not
 *
 * @par Test sequence:
 * -# Generate connection between @c SOCK_STREAM sockets @p iut_s
 *    on @p pco_iut and @p tst_s on @p pco_tst.
 * -# Enable @c IP_PKTINFO and @c IP_RECVTTL options on
 *    @p iut_s socket if required.
 * -# Obtain value of @c IP_PKTOPTIONS socket option on
 *    @p iut_s socket.
 * -# Get IP options from it via CMSG interface, check that
 *    only @c IP_TTL and @c IP_PKTINFO options are
 *    presented (and only if corresponding socket options were
 *    previously set) and that they have expected values.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */


#define TE_TEST_NAME  "sockopts/ip_pktoptions"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "multicast.h"

#define GARBAGE_STRING "BEEFBEEFBEEFBEEF"
#define NEW_TTL 33

int
main(int argc, char *argv[])
{
    int             i;
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;

    struct in_pktinfo          *pktinfo;
    const struct sockaddr      *tst_addr;
    const struct sockaddr      *iut_addr;
    const struct if_nameindex  *iut_if;

    uint8_t                     opt_val_buf[256];
    socklen_t                   opt_len;
    int                         opt_val;

    char                        tx_buf[1024];
    char                        rx_buf[1024];

    struct cmsghdr             *cmsg;

    char                        ip_str_buf1[INET_ADDRSTRLEN];
    char                        ip_str_buf2[INET_ADDRSTRLEN];

    int                         ttl_val;
    int                         multicast_ttl_val;

    te_bool                     garbage = FALSE;
    te_bool                     active_connection = FALSE;
    te_bool                     set_pktinfo = FALSE;
    te_bool                     set_recvttl = FALSE;
    te_bool                     traffic = FALSE;
    te_bool                     set_new_ttl = FALSE;

    te_bool                     is_failed = FALSE;
    int                         sock_option = 0;
    int                         sock_level = 0;

    TEST_START;
    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_BOOL_PARAM(garbage);
    TEST_GET_BOOL_PARAM(active_connection);
    TEST_GET_BOOL_PARAM(set_pktinfo);
    TEST_GET_BOOL_PARAM(set_recvttl);
    TEST_GET_BOOL_PARAM(traffic);
    TEST_GET_BOOL_PARAM(set_new_ttl);

    te_fill_buf(tx_buf, sizeof(tx_buf));
    memset(rx_buf, 0, sizeof(rx_buf));

    if (active_connection)
        GEN_CONNECTION(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                       tst_addr, iut_addr, &tst_s, &iut_s);
    else
        GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                       iut_addr, tst_addr, &iut_s, &tst_s);

    if (set_pktinfo)
    {
        opt_val = 1;
        rpc_setsockopt(pco_iut, iut_s, RPC_IP_PKTINFO, &opt_val);
    }

    if (set_recvttl)
    {
        opt_val = 1;
        rpc_setsockopt(pco_iut, iut_s, RPC_IP_RECVTTL, &opt_val);
        if (set_new_ttl)
        {
            ttl_val = NEW_TTL;
            rpc_setsockopt(pco_iut, iut_s, RPC_IP_TTL,
                           &ttl_val);
        }
    }

    if (garbage)
        snprintf((char *)opt_val_buf, sizeof(opt_val_buf), GARBAGE_STRING);
    else

        memset(opt_val_buf, 0, sizeof(opt_val_buf));

    if (traffic)
    {
        rpc_send(pco_iut, iut_s, tx_buf, sizeof(tx_buf), 0);
        rpc_recv(pco_tst, tst_s, rx_buf, sizeof(rx_buf), 0);
        rpc_send(pco_tst, tst_s, tx_buf, sizeof(tx_buf), 0);
        rpc_recv(pco_iut, iut_s, rx_buf, sizeof(rx_buf), 0);
    }

    opt_len = sizeof(opt_val_buf);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getsockopt_raw(pco_iut, iut_s, RPC_IP_PKTOPTIONS,
                            opt_val_buf, &opt_len);

    if (rc < 0)
    {
        if (RPC_ERRNO(pco_iut) == RPC_EILSEQ)
            TEST_VERDICT("Failed to process IP_PKTOPTIONS value");
        else
            TEST_VERDICT("getsockopt(IP_PKTOPTIONS) unexpectedly failed");
    }

    i = 0;
    cmsg = (struct cmsghdr *)opt_val_buf;

    while (CMSG_TOTAL_LEN(cmsg) <=
                CMSG_REMAINED_LEN(cmsg, opt_val_buf, opt_len))
    {
        i++;

        if (cmsg->cmsg_len == 0 ||
            (uint8_t *)cmsg == opt_val_buf + opt_len)
            break;

        if (cmsg->cmsg_level != SOL_IP)
        {
            sock_level = socklevel_h2rpc(cmsg->cmsg_level);
            sock_option = cmsg_type_h2rpc(cmsg->cmsg_level,
                                          cmsg->cmsg_type);

            RING("Unexpected socket option level encountered "
                 "in option %d: %u (%s); option is %u (%s)", i,
                 cmsg->cmsg_level,
                 socklevel_rpc2str(sock_level),
                 cmsg->cmsg_type,
                 sockopt_rpc2str(sock_option));

            RING_VERDICT("Unexpected socket option level encountered "
                         "in option %d: %s; option is %s", i,
                         socklevel_rpc2str(sock_level),
                         sockopt_rpc2str(sock_option));

            if (sock_level == RPC_SOL_UNKNOWN ||
                sock_option == RPC_SOCKOPT_UNKNOWN)
                is_failed = TRUE;
        }
        else
        {
            if (cmsg->cmsg_type == IP_TTL && set_recvttl)
            {
                RING("Value of IP_TTL option obtained via "
                     "IP_PKTOPTIONS is equal to %d",
                     *(int *)CMSG_DATA(cmsg));
                if (set_new_ttl)
                    ttl_val = NEW_TTL;
                else
                {
                    ttl_val = 0;
                    rpc_getsockopt(pco_iut, iut_s, RPC_IP_TTL,
                                   &ttl_val);
                }
                multicast_ttl_val = 0;
                RPC_AWAIT_IUT_ERROR(pco_iut);
                rc = rpc_getsockopt(pco_iut, iut_s,
                                    RPC_IP_MULTICAST_TTL,
                                    &multicast_ttl_val);

                if (rc < 0)
                    RING_VERDICT("Failed to obtain value of "
                                 "IP_MULTICAST_TTL socket option: %s",
                                 errno_rpc2str(RPC_ERRNO(pco_iut)));

                if (ttl_val == *(int *)CMSG_DATA(cmsg))
                    RING_VERDICT("Value of IP_TTL socket option "
                                 "obtained via IP_PKTOPTIONS "
                                 "is equal to value of IP_TTL "
                                 "socket option returned by "
                                 "getsockopt()");
                else
                {


                    if (rc >= 0 &&
                         multicast_ttl_val == *(int *)CMSG_DATA(cmsg))
                        RING_VERDICT("Value of IP_TTL socket option "
                                     "obtained via IP_PKTOPTIONS "
                                     "is equal to value of "
                                     "IP_MULTICAST_TTL "
                                     "socket option returned by "
                                     "getsockopt()");
                    else
                        RING_VERDICT("Value of IP_TTL socket option "
                                     "obtained via IP_PKTOPTIONS "
                                     "is not equal to value "
                                     "of IP_MULTICAST_TTL or IP_TTL "
                                     "socket options returned by "
                                     "getsockopt()");
                }
            }
            else if (cmsg->cmsg_type == IP_PKTINFO && set_pktinfo)
            {
                pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);

                RING("Returned in_pktinfo: ipi_ifindex: %d, "
                     "ipi_spec_dst: %s, ipi_addr: %s",
                     pktinfo->ipi_ifindex,
                     inet_ntop(AF_INET, &pktinfo->ipi_spec_dst,
                               ip_str_buf1, sizeof(ip_str_buf1)),
                     inet_ntop(AF_INET, &pktinfo->ipi_addr,
                               ip_str_buf2, sizeof(ip_str_buf2)));

                if (SIN(iut_addr)->sin_addr.s_addr !=
                                    pktinfo->ipi_spec_dst.s_addr)
                    RING_VERDICT("ipi_spec_dst member of in_pktinfo "
                                 "structure is not equal to address "
                                 "the socket is bound to");

                if (SIN(iut_addr)->sin_addr.s_addr !=
                                        pktinfo->ipi_addr.s_addr)
                    RING_VERDICT("ipi_addr member of in_pktinfo "
                                 "structure is not equal to address "
                                 "the socket is bound to");

                if (pktinfo->ipi_ifindex != (int)iut_if->if_index)
                {
                    if (pktinfo->ipi_ifindex == 0)
                        RING_VERDICT("ipi_ifindex member of in_pktinfo "
                                     "structure is equal to 0");
                    else
                        RING_VERDICT("ipi_ifindex member of in_pktinfo "
                                     "structure is not equal to index "
                                     "of interface obtained from "
                                     "environment");
                }
            }
            else
                RING_VERDICT("Unexpected socket option encountered "
                             " in option %d: %s", i,
                             sockopt_rpc2str(
                                    cmsg_type_h2rpc(cmsg->cmsg_level,
                                                    cmsg->cmsg_type)));
        }

        cmsg = CMSG_NEXT(cmsg);
    }

    if ((uint8_t *)cmsg != (uint8_t *)opt_val_buf + opt_len)
    {
        /*
         * If this occurs, it is due to incorrect parsing on the
         * test side in rpc_getsockopt() - it should report
         * error rather than return incorrect data quietly.
         */
        if (CMSG_TOTAL_LEN(cmsg) >
                    CMSG_REMAINED_LEN(cmsg, opt_val_buf, opt_len))
            TEST_FAIL("Parsing of IP_PKTOPTIONS option value "
                      "failed");
        else
            TEST_FAIL("Length of parsed cmsg structures does not "
                      "match length of data returned by getsockopt()");
    }

    if (is_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
