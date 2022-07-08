/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Multicasting in IP
 *
 * $Id$
 */

/** @page multicast-mcast_bind_send Unicast address for outgoing datagram.
 *
 * @objective Check that only unicast source adresses are used for outgoing
 *            datagrams, even if socket is bound to multicast address.
 *
 * @type Conformance.
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on Tester
 * @param mcast_addr    Multicast address
 * @param data_len      Size of datagram
 * @param connect_iut   Connect @p iut_s and use @b send() instead of
 *                      @b sendto()
 * @param packet_number Number of datagrams to send for reliability.
 * @param sock_func     Socket creation function.
 *
 * @par Scenario:
 *
 * -# Create a datagram socket @p iut_s on @p pco_iut.
 * -# Assign port numbers of @p mcast_addr and @p iut_addr to be equal.
 * -# Bind it to @p mcast_addr.
 * -# Create a datagram socket @p tst_s on @p pco_tst.
 * -# Repeat @p packet_number times:
 *     -# Send a datagram from @p iut_s to @p tst_s.
 *     -# Receive it using rpc_recvfrom(), saving source address.
 *     -# Check that the source address is a unicast one.
 *
 * @note We have to send 2 datagrams in order to create ARP record in cache,
 *       because in L5 stack the first datagram is always sent via kernel. 
 *  
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/mcast_bind_send"

#include <netinet/ip_icmp.h>
#include "sockapi-test.h"
#include "tapi_ip4.h"
#include "multicast.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    const struct sockaddr *mcast_addr = NULL;
    struct sockaddr_in     source_addr;
    unsigned int           source_addrlen = sizeof(source_addr);
    int                    iut_s = -1;
    int                    tst_s = -1;
    void                  *data = NULL;
    int                    data_len;
    int                    packet_number;
    int                    i;
    te_bool                connect_iut;
    sockts_socket_func     sock_func;
    const struct if_nameindex   *iut_if = NULL;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_INT_PARAM(data_len);
    TEST_GET_INT_PARAM(packet_number);
    TEST_GET_BOOL_PARAM(connect_iut);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    data = te_make_buf_by_len(data_len);

    iut_s = sockts_socket(sock_func, pco_iut, RPC_AF_INET,
                          RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    tst_s = rpc_socket(pco_tst, RPC_AF_INET, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    te_sockaddr_set_port(SA(mcast_addr), te_sockaddr_get_port(iut_addr));

    rpc_bind(pco_tst, tst_s, tst_addr);
    rpc_bind(pco_iut, iut_s, mcast_addr);

    if (connect_iut)
    {
        rpc_connect(pco_iut, iut_s, tst_addr);
    }

    for (i = 0; i < packet_number; i++)
    {
        te_bool sock_readable;
        
        if (connect_iut)
        {
            rpc_send(pco_iut, iut_s, data, sizeof(data), 0);
        }
        else
        {
            rpc_sendto(pco_iut, iut_s, data, sizeof(data), 0, tst_addr);
        }
        TAPI_WAIT_NETWORK;
        
        RPC_GET_READABILITY(sock_readable, pco_tst, tst_s, 1);
        if (!sock_readable)
        {
            if (i > 0 && !connect_iut)
            {
                TEST_VERDICT("Cannot receive 2nd datagram: "
                             "apparently a redirection occured");
            }
            else
            {
                TEST_FAIL("Cannot receive datagram");
            }
        }
        
        rpc_recvfrom(pco_tst, tst_s, data, sizeof(data), 0,
                     (struct sockaddr *)&source_addr, &source_addrlen);
        if (!(IN_CLASSA(source_addr.sin_addr.s_addr) ||
            IN_CLASSB(source_addr.sin_addr.s_addr) ||
            IN_CLASSC(source_addr.sin_addr.s_addr)))
        {
            TEST_FAIL("Non-unicast source address detected");
        }
    }

    /* Check that we are still bound */
    {
        struct sockaddr_storage ss;
        socklen_t               ss_len = sizeof(ss);

        rpc_getsockname(pco_iut, iut_s, SA(&ss), &ss_len);
        rc = te_sockaddrcmp(SA(&ss), ss_len,
                            mcast_addr, te_sockaddr_get_size(mcast_addr));
        if (rc != 0)
            TEST_FAIL("Socket has lost its bounding");
    }
    
    TEST_SUCCESS;

cleanup:    
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    free(data);
    TEST_END;
}
