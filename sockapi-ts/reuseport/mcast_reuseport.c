/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reuseport
 * 
 * $Id$
 */

/** @page reuseport-mcast_reuseport SO_REUSEPORT option with multicast addresses
 *
 * @objective  Test multicast address sharing with SO_REUSEPORT option.
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst           PCO on TST
 * @param reuseport_first   Set SO_REUSEPORT for the first socket
 * @param reuseport_second  Set SO_REUSEPORT for the second socket
 * 
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "reuseport/mcast_reuseport"

#include "sockapi-test.h"
#include "multicast.h"

#define PACKET_SIZE 500

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    const struct sockaddr *mcast_addr = NULL;
    const struct if_nameindex *tst_if = NULL;
    const struct if_nameindex *iut_if = NULL;
    tarpc_joining_method       method;

    te_bool reuseport_first;
    te_bool reuseport_second;
    char    recvbuf[PACKET_SIZE] = {0,};
    char   *sendbuf = NULL;

    int iut_s1 = -1;
    int iut_s2 = -1;
    int tst_s = -1;
    int exp;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(tst_if);
    TEST_GET_IF(iut_if);
    TEST_GET_BOOL_PARAM(reuseport_first);
    TEST_GET_BOOL_PARAM(reuseport_second);
    TEST_GET_MCAST_METHOD(method);

    sendbuf = te_make_buf_by_len(PACKET_SIZE);

    TEST_STEP("Creat UDP socket on tester for multicast packets transmission.");
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    TEST_STEP("Bind it and set IP_MULTCAST_IF option for it.");
    rpc_bind(pco_tst, tst_s, tst_addr);
    set_ip_multicast_if(pco_tst, tst_s, tst_addr);

    TEST_STEP("Open UDP socket on IUT.");
    iut_s1 = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                        RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    TEST_STEP("Set SO_REUSEPORT option in dependence on @p reuseport_first.");
    if (reuseport_first)
        rpc_setsockopt_int(pco_iut, iut_s1, RPC_SO_REUSEPORT, 1);

    TEST_STEP("Bind the socket to multicast address and joint to the multicast "
              "group.");
    rpc_bind(pco_iut, iut_s1, mcast_addr);
    rpc_mcast_join(pco_iut, iut_s1, mcast_addr, iut_if->if_index, method);

    TEST_STEP("Open IUT second socket on IUT.");
    iut_s2 = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                        RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    TEST_STEP("Set SO_REUSEPORT option in dependence on @p reuseport_second.");
    if (reuseport_second)
        rpc_setsockopt_int(pco_iut, iut_s2, RPC_SO_REUSEPORT, 1);

    TEST_STEP("Try to bind the second socket to the same multicast address. It is "
              "expected that bind has success only if SO_REUSEPORT option is set for "
              "both IUT sockets. Otherwise bind() should fail with EADDRINUSE.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    if ((rc = rpc_bind(pco_iut, iut_s2, mcast_addr)) != 0)
    {
        if (RPC_ERRNO(pco_iut) != RPC_EADDRINUSE)
            TEST_FAIL("IUT bind filed with unexpected errno %s",
                      errno_rpc2str(pco_iut->_errno));
    }

    if (reuseport_first && reuseport_second)
        exp = 0;
    else
        exp = -1;

    if (rc != exp)
    {
        if (rc != 0)
            TEST_VERDICT("Bind unexpectedly failed with EADDRINUSE");
        else
            TEST_VERDICT("Bind should fail with EADDRINUSE");
    }

    TEST_STEP("Leave if bind() is failed.");
    if (rc != 0)
        TEST_SUCCESS;

    TEST_STEP("Join second socket to the multicast group.");
    rpc_mcast_join(pco_iut, iut_s2, mcast_addr, iut_if->if_index, method);

    TEST_STEP("Send a multicast packet from tester.");
    if (rpc_sendto(pco_tst, tst_s, sendbuf, PACKET_SIZE, 0, mcast_addr) !=
                   PACKET_SIZE)
        TEST_FAIL("Only a part of packet has been transmitted");

#define RECV_CHECK(sock) \
do {                                                                       \
    if (rpc_recv(pco_iut, sock, recvbuf, PACKET_SIZE, 0) != PACKET_SIZE)   \
        TEST_FAIL("Only a part of packet has been received");              \
    if (memcmp(sendbuf, recvbuf, PACKET_SIZE) != 0)                        \
        TEST_FAIL("Received data differs from sent");                      \
} while (0)

    TEST_STEP("Receive and check packet on both IUT sockets.");
    RECV_CHECK(iut_s1);

    memset(recvbuf, 0, PACKET_SIZE);
    RECV_CHECK(iut_s2);

#undef RECV_CHECK

    TEST_SUCCESS;

cleanup:
    free(sendbuf);
    RPC_CLOSE(pco_iut, iut_s1);
    RPC_CLOSE(pco_iut, iut_s2);
    RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
