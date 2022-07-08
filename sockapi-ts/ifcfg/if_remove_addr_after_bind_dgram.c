/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Network interface related tests
 *
 */

/** @page ifcfg-if_remove_addr_after_bind_dgram Remove IP address after UDP socket binding, try to send a datagram
 *
 * @objective Check that sendto() on a bound UDP socket fails if local address
 *            is removed. But datagrams can be sent when the address is back.
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

#define TE_TEST_NAME  "ifcfg/if_remove_addr_after_bind_dgram"

#include "sockapi-test.h"
#include "tapi_cfg_base.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;

    const struct sockaddr *tst_addr = NULL;

    tapi_env_net          *net1;
    struct sockaddr       *iut_addr;
    cfg_handle             iut_addr_handle = CFG_HANDLE_INVALID;

    struct sockaddr_storage    myaddr;
    socklen_t                  myaddrlen;

    const struct if_nameindex *iut_if = NULL;

    int                    iut_s = -1;
    int                    tst_s = -1;

    void                  *tx_buf = NULL;
    size_t                 tx_buflen;
    void                  *rx_buf = NULL;
    size_t                 rx_buflen;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_NET(net1);

    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);

    tx_buf = sockts_make_buf_dgram(&tx_buflen);

    TEST_STEP("Add IP address on IUT interface.");
    CHECK_RC(tapi_env_allocate_addr(net1, AF_INET, &iut_addr, NULL));
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if->if_name,
                                           iut_addr, net1->ip4pfx, FALSE,
                                           &iut_addr_handle));
    CFG_WAIT_CHANGES;

    tapi_allocate_set_port(pco_iut, iut_addr);

    TEST_STEP("Create and bind UDP socket.");
    iut_s = rpc_socket(pco_iut, RPC_AF_INET, SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr);

    memset(&myaddr, 0, sizeof(myaddr));
    myaddrlen = sizeof(myaddr);
    rpc_getsockname(pco_iut, iut_s, SA(&myaddr), &myaddrlen);

    tst_s = rpc_socket(pco_tst, RPC_AF_INET, SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    TEST_STEP("Delete added address from IUT interface.");
    CHECK_RC(cfg_del_instance(iut_addr_handle, FALSE));
    iut_addr_handle = CFG_HANDLE_INVALID;
    CFG_WAIT_CHANGES;

    TEST_STEP("Try send a datagram from the socket - fail with @c EINVAL.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_sendto(pco_iut, iut_s, tx_buf, tx_buflen, 0, tst_addr);
    if (rc != -1)
    {
        struct sockaddr_storage from;
        socklen_t               fromlen = sizeof(from);
        ssize_t                 r;

        WARN("sendto() returned %d, but it is expected to return -1", rc);

        rx_buf = te_make_buf_min(tx_buflen, &rx_buflen);
        memset(&from, 0, sizeof(from));
        r = rpc_recvfrom(pco_tst, tst_s, rx_buf, rx_buflen, 0,
                         SA(&from), &fromlen);
        if (r != (ssize_t)tx_buflen)
            TEST_VERDICT("Unexpected number of bytes is received on peer");
        if (memcmp(tx_buf, rx_buf, tx_buflen) != 0)
            TEST_VERDICT("Invalid data are received on peer");
        if (te_sockaddrcmp(CONST_SA(&myaddr), myaddrlen,
                           CONST_SA(&from), fromlen) != 0)
            TEST_VERDICT("Data from unknown sender are received on peer");

        TEST_VERDICT("IP address has been deleted before sendto(), but "
                     "the address is used in sent and successfully "
                     "received packet");
    }
    /* More about errno codes read in ST-1844. */
    else if (RPC_ERRNO(pco_iut) != RPC_EINVAL &&
             RPC_ERRNO(pco_iut) != RPC_ENETUNREACH)
    {
        TEST_VERDICT("sendto() returns -1, but errno is set to %r instead "
                     "of %r or %r", RPC_ERRNO(pco_iut), RPC_EINVAL,
                     RPC_ENETUNREACH);
    }

    TEST_STEP("Add the address back to IUT interface.");
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if->if_name,
                                           iut_addr, net1->ip4pfx, FALSE,
                                           &iut_addr_handle));
    CFG_WAIT_CHANGES;

    TEST_STEP("Check that data transmission works in both directions.");
    sockts_test_udp_sendto_bidir(pco_iut, iut_s, iut_addr, pco_tst, tst_s,
                                 tst_addr);

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
