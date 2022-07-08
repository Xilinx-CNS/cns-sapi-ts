/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/** @page usecases-sendmsg_recvmsg The sendmsg()/recvmsg() operations on the SOCK_DGRAM socket
 *
 * @objective Test on reliability of @b sendmsg()/recvmsg() operations
 *            on BSD compatible sockets.
 *
 * @type use case
 *
 * @param env   Testing environment:
 *                  - @ref arg_types_env_peer2peer
 *                  - @ref arg_types_env_p2p_ip6ip4mapped
 *                  - @ref arg_types_env_p2p_ip6
 *                  - @ref arg_types_env_peer2peer_tst
 *                  - @ref arg_types_env_peer2peer_lo
 *
 * @par Scenario:
 * -# Allocate on the both @p IUT side and @p TESTER side following resources:
 *    - @a msdhdr;
 *    - @a scatter/gather array;
 * -# Fill in an appropriate data to the msghdr: @a target @a address,
 *    @a scatter/gather array information, ancillary @a control information;
 * -# Create @p pco_iut socket of the @c SOCK_DGRAM type on the @p IUT side;
 * -# Create @p pco_tst socket of the @c SOCK_DGRAM type on the @p TESTER side;
 * -# @b bind() @p pco_iut socket to the local address/port;
 * -# @b bind() @p pco_tst socket to the local address/port;
 * -# Call blocking @b recvmsg() on the @p pco_iut socket;
 * -# @b sendmsg() data to the @p pco_tst socket;
 * -# Wait for @b recvmsg() completion on the @p pco_iut socket;
 * -# Call @b sendmsg() of the obtained data on the @p pco_iut socket;
 * -# Call @b recvmsg() on the @p pco_tst socket to obtain data from
 *    @p pco_iut socket;
 * -# Compare transmitted and received data.
 * -# Close created sockets;
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "usecases/sendmsg_recvmsg"

#include "sockapi-test.h"


#define TST_SENDRECV_FLAGS    0
#define TST_VEC               3
#define TST_FLAGS             0


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;
    rpc_msghdr      tx_msghdr;
    rpc_msghdr      rx_msghdr;
    rpc_msghdr      rrx_msghdr;
    size_t          sent, received;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;


    memset(&tx_msghdr, 0, sizeof(tx_msghdr));
    memset(&rx_msghdr, 0, sizeof(rx_msghdr));
    memset(&rrx_msghdr, 0, sizeof(rrx_msghdr));

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    /* Prepare tx/rx message headers */
    sockts_make_txrx_msghdr(&tx_msghdr, &rx_msghdr, &rrx_msghdr,
                            iut_addr, TST_VEC);

    GEN_DGRAM_CONN_WILD(pco_iut, pco_tst, RPC_SOCK_DGRAM, iut_addr,
                        tst_addr, &iut_s, &tst_s, FALSE, FALSE, TRUE);

    pco_iut->op = RCF_RPC_CALL;
    rpc_recvmsg(pco_iut, iut_s, &rx_msghdr, TST_FLAGS);
    sent = rc = rpc_sendmsg(pco_tst, tst_s, &tx_msghdr, TST_FLAGS);

    pco_iut->op = RCF_RPC_WAIT;
    received = rpc_recvmsg(pco_iut, iut_s, &rx_msghdr, TST_FLAGS);

    rc = sockts_compare_txrx_msgdata(&tx_msghdr, &rx_msghdr,
                                     tst_addr, sent, received);
    if (rc)
        TEST_STOP;

    sent = rpc_sendmsg(pco_iut, iut_s, &rx_msghdr, TST_FLAGS);

    received = rpc_recvmsg(pco_tst, tst_s, &rrx_msghdr, TST_FLAGS);

    rc = sockts_compare_txrx_msgdata(&rx_msghdr, &rrx_msghdr,
                                     iut_addr, sent, received);
    if (rc)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    sockts_clear_txrx_msghdr(&tx_msghdr, &rx_msghdr, &rrx_msghdr);

    TEST_END;
}
