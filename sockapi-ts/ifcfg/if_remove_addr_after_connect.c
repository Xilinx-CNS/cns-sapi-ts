/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Network interface related tests
 */

/** @page ifcfg-if_remove_addr_after_connect Remove IP address while there are connected sockets, try to send data
 *
 * @objective Check that send() call fails for a connected UDP socket and is
 *            successful for TCP socket (data is buffered) if local address is
 *            removed. But data is successfully sent when the address is back.
 *
 * @type conformance
 *
 * @param pco_iut   PCO on @p IUT
 * @param pco_tst   PCO on @p TESTER
 *
 * @par Test sequence:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ifcfg/if_remove_addr_after_connect"

#include "sockapi-test.h"
#include "tapi_cfg_base.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;

    rpc_socket_type         sock_type;

    const struct sockaddr *tst_addr = NULL;

    tapi_env_net          *net1;
    struct sockaddr       *iut_addr;
    cfg_handle             iut_addr_handle = CFG_HANDLE_INVALID;

    const struct if_nameindex *iut_if = NULL;

    int                    iut_s = -1;
    int                    tst_s = -1;

    void                  *tx_buf = NULL;
    void                  *rx_buf = NULL;
    size_t                 tx_buflen;

    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_SOCK_TYPE(sock_type);

    TEST_GET_NET(net1);

    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);

    rx_buf = te_make_buf_by_len(SOCKTS_MSG_STREAM_MAX);
    tx_buf = sockts_make_buf_stream(&tx_buflen);

    TEST_STEP("Add IP address on IUT interface.");
    CHECK_RC(tapi_env_allocate_addr(net1, AF_INET, &iut_addr, NULL));
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if->if_name,
                                           iut_addr, net1->ip4pfx, FALSE,
                                           &iut_addr_handle));
    CFG_WAIT_CHANGES;

    TEST_STEP("Establish TCP connection or bind, connect UDP socket.");
    GEN_CONNECTION(pco_tst, pco_iut, sock_type, RPC_PROTO_DEF,
                   tst_addr, iut_addr, &tst_s, &iut_s);

    TEST_STEP("Resolve ARP in case of UDP socket. ARP resolving should be done "
              "because in other case it is started when the first packet is sent "
              "and ends when the address is added back, so the first packet will "
              "be sent correctly and IUT will get it.");
    if (sock_type == RPC_SOCK_DGRAM)
    {
        rpc_send(pco_tst, tst_s, tx_buf, 1, 0);
        rc = rpc_read(pco_iut, iut_s, rx_buf, SOCKTS_MSG_STREAM_MAX);
        SOCKTS_CHECK_RECV(pco_iut, tx_buf, rx_buf, 1, rc);

    }

    TEST_STEP("Delete added address from IUT interface.");
    CHECK_RC(cfg_del_instance(iut_addr_handle, FALSE));
    iut_addr_handle = CFG_HANDLE_INVALID;
    CFG_WAIT_CHANGES;

    TEST_STEP("Try to send data: "
              "- TCP: send call is succeeded; "
              "- UDP: send call fails with errno @c EINVAL.");
    if (sock_type == RPC_SOCK_STREAM)
        rpc_send(pco_iut, iut_s, tx_buf, tx_buflen, 0);
    else
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_send(pco_iut, iut_s, tx_buf, tx_buflen, 0);
        if (rc >= 0)
            TEST_VERDICT("Send call is unexpectedly succeded");

        /* More about errno codes read in ST-1844. */
        if (RPC_ERRNO(pco_iut) != RPC_EINVAL &&
            RPC_ERRNO(pco_iut) != RPC_ENETUNREACH)
        {
            TEST_VERDICT("Send call failed with incorrect errno %r",
                         RPC_ERRNO(pco_iut));
        }
    }

    TEST_STEP("Send a packet from tester.");
    rpc_send(pco_tst, tst_s, tx_buf, tx_buflen, 0);
    TAPI_WAIT_NETWORK;

    TEST_STEP("No data should be received by tester and IUT.");
    RPC_CHECK_READABILITY(pco_iut, iut_s, FALSE);
    RPC_CHECK_READABILITY(pco_tst, tst_s, FALSE);

    TEST_STEP("Add the address back to IUT interface.");
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if->if_name,
                                           iut_addr, net1->ip4pfx, FALSE,
                                           &iut_addr_handle));
    CFG_WAIT_CHANGES;

    TEST_STEP("Read and check sent data for TCP.");
    if (sock_type == RPC_SOCK_STREAM)
    {
        rc = rpc_read(pco_iut, iut_s, rx_buf, SOCKTS_MSG_STREAM_MAX);
        SOCKTS_CHECK_RECV(pco_iut, tx_buf, rx_buf, tx_buflen, rc);
        rc = rpc_read(pco_tst, tst_s, rx_buf, SOCKTS_MSG_STREAM_MAX);
        SOCKTS_CHECK_RECV(pco_tst, tx_buf, rx_buf, tx_buflen, rc);
    }

    TEST_STEP("Check data transmission in both directions.");
    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);

    TEST_SUCCESS;
cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (iut_addr_handle != CFG_HANDLE_INVALID)
    {
        CLEANUP_CHECK_RC(cfg_del_instance(iut_addr_handle, FALSE));
        CFG_WAIT_CHANGES;
    }

    TEST_END;
}
