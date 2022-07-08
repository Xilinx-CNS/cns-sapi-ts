/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Multicasting in IP
 */

/** @page multicast-bindtodevice_vs_ip_multicast_if Interation between SO_BINDTODEVICE and IP_MULTICAST_IF
 *
 * @objective Chech that @c SO_BINDTODEVICE socket option has priority over
 *            @c IP_MULTICAST_IF option.
 *
 * @type Conformance.
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst1          PCO on Tester1
 * @param pco_tst2          PCO on Tester2
 * @param iut_if1           Interface on IUT connected to Tester1
 * @param tst1_if           Interface on Tester1
 * @param iut_if2           Interface on IUT connected to Tester2
 * @param tst2_if           Interface on Tester2
 * @param iut_addr1         Address on @p iut_if1
 * @param mcast_addr        Multicast address
 * @param method            Method used for joining to multicast group
 * @param packet_number     Number of datagrams to send for reliability.
 * @param sock_func         Socket creation function.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 * @author Denis Pryazhennikov <Denis.Pryazhennikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/bindtodevice_vs_ip_multicast_if"

#include "sockapi-test.h"
#include "mcast_lib.h"
#include "multicast.h"

int
main(int argc, char *argv[])
{
    rpc_socket_domain      domain;
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst1 = NULL;
    rcf_rpc_server        *pco_tst2 = NULL;
    const struct sockaddr *mcast_addr = NULL;
    const struct sockaddr *iut_addr1 = NULL;
    const struct sockaddr *iut_addr2 = NULL;
    const struct sockaddr *tst1_addr = NULL;
    const struct sockaddr *tst2_addr = NULL;
    int                    iut_s = -1;
    int                    tst1_s = -1;
    int                    tst2_s = -1;
    te_bool                detected = FALSE;
    te_bool                readable;
    struct tarpc_mreqn     mreq;

    const struct if_nameindex   *iut_if1;
    const struct if_nameindex   *tst1_if;
    const struct if_nameindex   *iut_if2;
    const struct if_nameindex   *tst2_if;

    mcast_listener_t listener = CSAP_INVALID_HANDLE;

    char                  *send_buf1 = NULL;
    char                  *send_buf2 = NULL;
    char                  *recv_buf = NULL;
    size_t                 send_buf2_len;
    size_t                 send_buf1_len;
    int                    recv_data_len;
    int                    packet_number;
    int                    i;

    const char           *field_to_use;
    sockts_socket_func    sock_func;
    tarpc_joining_method  method;

    te_bool first_joined = FALSE;
    te_bool second_joined = FALSE;

    char             opt_val[IFNAMSIZ];
    socklen_t        opt_len;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    TEST_GET_IF(iut_if1);
    TEST_GET_IF(iut_if2);
    TEST_GET_IF(tst1_if);
    TEST_GET_IF(tst2_if);
    TEST_GET_INT_PARAM(packet_number);
    TEST_GET_MCAST_METHOD(method);
    TEST_GET_STRING_PARAM(field_to_use);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    domain = rpc_socket_domain_by_addr(iut_addr1);

    send_buf1 = sockts_make_buf_dgram(&send_buf1_len);
    send_buf2 = sockts_make_buf_dgram(&send_buf2_len);
    recv_buf = te_make_buf_by_len(SOCKTS_MSG_DGRAM_MAX);

    TEST_STEP("Create datagram sockets: @p iut_s on @p pco_iut, @p tst1_s on @p pco_tst1, "
              "and @p tst2_s on @p pco_tst2.");
    iut_s = sockts_socket(sock_func, pco_iut, domain,
                          RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    tst1_s = rpc_socket(pco_tst1, domain, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    tst2_s = rpc_socket(pco_tst2, domain, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    TEST_STEP("Set outgoing interface with @p tst1_addr address for @p tst1_s and "
              "@p tst2_addr address for @p tst2_s using @c IP_MULTICAST_IF "
              "socket option.");
    memset(&mreq, 0, sizeof(mreq));
    mreq.type = OPT_IPADDR;
    mreq.address = SIN(tst1_addr)->sin_addr.s_addr;

    rpc_setsockopt(pco_tst1, tst1_s, RPC_IP_MULTICAST_IF, &mreq);

    mreq.address = SIN(tst2_addr)->sin_addr.s_addr;

    rpc_setsockopt(pco_tst2, tst2_s, RPC_IP_MULTICAST_IF, &mreq);

    TEST_STEP("Check multicast hash collision on @pco_iut for @p iut_if1 and "
              "@p iut_if2 with @p mcast_addr.");
    CHECK_MCAST_HASH_COLLISION(pco_iut, pco_tst1, iut_if1, tst1_s, mcast_addr);
    CHECK_MCAST_HASH_COLLISION(pco_iut, pco_tst2, iut_if2, tst2_s, mcast_addr);

    TEST_STEP("Check that it is impossible to bind @p iut_s to @p iut_if2 "
              "with IP_MULTICAST_IF when it is already bound to @p iut_if1 "
              "with SO_BINDTODEVICE");
    rpc_setsockopt_raw(pco_iut, iut_s, RPC_SO_BINDTODEVICE,
                       iut_if1->if_name, (strlen(iut_if1->if_name) + 1));
    TAPI_WAIT_NETWORK;

    memset(&mreq, 0, sizeof(mreq));
    memcpy(&mreq.multiaddr, te_sockaddr_get_netaddr(mcast_addr),
           sizeof(struct in_addr));
    mreq.type = OPT_MREQN;
    if (strcmp(field_to_use, "ifindex") != 0)
        memcpy(&mreq.address, te_sockaddr_get_netaddr(iut_addr2),
               sizeof(struct in_addr));
    if (strcmp(field_to_use, "address") != 0)
        mreq.ifindex = iut_if2->if_index;

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_setsockopt(pco_iut, iut_s, RPC_IP_MULTICAST_IF, &mreq);
    if (rc != -1)
        TEST_FAIL("rpc_setsockopt() unexpected behaviour, expected "
                  "return code -1");
    CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL,
                    "setsockopt(IP_MULTICAST_IF) after SO_BINDTODEVICE "
                    "returned -1, but");

    TEST_STEP("Unbind @p iut_s socket from @p iut_if1 interface.");
    memset(opt_val, '\0', sizeof(opt_val));
    opt_len = sizeof(opt_val);
    rpc_setsockopt_raw(pco_iut, iut_s, RPC_SO_BINDTODEVICE, opt_val, opt_len);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Bind @p iut_s to @p iut_if2 with IP_MULTICAST_IF and "
              "then bind it again to @p iut_if1 with @c SO_BINDTODEVICE.");
    rpc_setsockopt(pco_iut, iut_s, RPC_IP_MULTICAST_IF, &mreq);
    TAPI_WAIT_NETWORK;

    rpc_setsockopt_raw(pco_iut, iut_s, RPC_SO_BINDTODEVICE,
                       iut_if1->if_name, (strlen(iut_if1->if_name) + 1));
    TAPI_WAIT_NETWORK;

    TEST_STEP("Adjoin @p iut_s on @p iut1_if and @p iut2_if "
              "to @p mcast_addr multicast group.");
    rpc_mcast_join(pco_iut, iut_s, mcast_addr, iut_if1->if_index, method);
    first_joined = TRUE;

    rpc_mcast_join(pco_iut, iut_s, mcast_addr, iut_if2->if_index, method);
    second_joined = TRUE;

    rpc_bind(pco_iut, iut_s, mcast_addr);

    listener = mcast_listener_init(pco_iut, iut_if1, mcast_addr, NULL, 1);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Send multicast packets from @p tst1_s with @p send_buf1_len len and "
              "@p tst2_s with @p send_buf2_len len to @mcast_addr. "
              "Check that @iut_s received packet with @p send_buf1_len len only.");
    for (i = 0; i < packet_number; i++)
    {
        mcast_listen_start(pco_iut, listener);

        rpc_sendto(pco_tst1, tst1_s, send_buf1, send_buf1_len, 0, mcast_addr);
        rpc_sendto(pco_tst2, tst2_s, send_buf2, send_buf2_len, 0, mcast_addr);

        rc = mcast_listen_stop(pco_iut, listener, NULL);
        if (rc > 0 && !detected)
        {
            RING_VERDICT("Multicast packet was detected by system on "
                         "iut_if1");
            detected = TRUE;
        }

        RPC_GET_READABILITY(readable, pco_iut, iut_s, TAPI_WAIT_NETWORK_DELAY);
        if (readable)
        {
           recv_data_len = rpc_recv(pco_iut, iut_s, recv_buf,
                                    SOCKTS_MSG_DGRAM_MAX, 0);
           SOCKTS_CHECK_RECV(pco_iut, send_buf1, recv_buf, send_buf1_len,
                             recv_data_len);
        }
        else
        {
            TEST_VERDICT("Socket didn't receive multicast packet,"
                         " but it should");
        }
    }

    TEST_STEP("Check that @p iut_s socket is no longer received any packets.");
    RPC_CHECK_READABILITY(pco_iut, iut_s, FALSE);

    TEST_SUCCESS;

cleanup:
    if (first_joined)
        rpc_mcast_leave(pco_iut, iut_s, mcast_addr, iut_if1->if_index, method);
    if (second_joined)
        rpc_mcast_leave(pco_iut, iut_s, mcast_addr, iut_if2->if_index, method);

    mcast_listener_fini(pco_iut, listener);

    free(send_buf1);
    free(send_buf2);
    free(recv_buf);

    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
