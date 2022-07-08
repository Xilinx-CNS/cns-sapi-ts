/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-socket_peer_rst Abort connection with RST sent from Tester
 *
 * @objective Check that @c RST packet sent by peer is handled correctly, call
 *            of function recv() should fail with errno @c ECONNRESET.
 *
 * @type conformance
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 *              - @ref arg_types_env_peer2peer_fake
 *
 * @par Test sequence:
 *
 * -# Create network connection of sockets of @c SOCK_STREAM type by means of
 *    @c GEN_CONNECTION with @p pco_iut and @p pco_tst as PCOs to interact,
 *    obtain sockets @p iut_s on @p pco_iut and @p tst_s on @p pco_tst.
 * -# @b send() some data through @p tst_s.
 * -# Call blocking @b recv() on @p tst_s.
 * -# @b close() @p iut_s (data has been sent on @p pco_tst is not read).
 * -# Check that @p iut_s send RST segment to the peer and blocking @b recv() 
 *    on @p tst_s returns -1 and @b errno set to the @c ECONNRESET.
 * -# Close all involved sockets.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/socket_peer_rst"

#include "sockapi-test.h"
#include "tapi_cfg.h"


#define TST_BUF_LEN   4096

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    int                    iut_s = -1;
    int                    tst_s = -1;

    const struct sockaddr *tst_addr;
    const struct sockaddr *iut_addr;
    unsigned char          tst_buf[TST_BUF_LEN];

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    /* Scenario */
    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                        tst_addr, iut_addr, &tst_s, &iut_s);

    RPC_SEND(rc, pco_iut, iut_s, tst_buf, 1, 0);
    TAPI_WAIT_NETWORK;

    /* Check that TCP server returns RST segment */
    pco_iut->op = RCF_RPC_CALL;
    rpc_recv(pco_iut, iut_s, tst_buf, TST_BUF_LEN, 0);

    RPC_CLOSE(pco_tst, tst_s);

    pco_iut->op = RCF_RPC_WAIT;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_recv(pco_iut, iut_s, tst_buf, TST_BUF_LEN, 0);
    if (rc != -1)
    {
        TEST_FAIL("Unexpected behavior, recv() should return -1 instead of %d",
                  rc);
    }

    CHECK_RPC_ERRNO(pco_iut, RPC_ECONNRESET, "recv() socket returns -1, but");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CHECK_CLEAR_TRANSPARENT(iut_addr, pco_tst, tst_addr);

    TEST_END;
}
