/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Network interface related tests
 */

/** @page ifcfg-if_down_nodelay Send data via a down interface setting TCP_NODELAY
 *
 * @objective Put interface down after establishing TCP connection, setting or
 *            not @c TCP_NODELAY. Try to send data and check that no data is
 *            sent. Data should be delivered when the interface is up.
 *
 * @type conformance
 *
 * @param pco_iut          PCO on @p IUT
 * @param pco_tst          PCO on @p TESTER
 * @param iut_if           Network interface name on @p IUT that
 *                         connected to @p TESTER
 * @param tcp_nodelay      On/Off
 * @param non_blocked      On/Off
 *
 * @par Test sequence:
 *
 * @author Igor Vasiliev <Igor.Vasilev@oktetlabs.ru>
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ifcfg/if_down_nodelay"

#include "sockapi-test.h"
#include "tapi_cfg_base.h"
#include "iomux.h"

#define TST_BUF_LEN     (32 * 1024)
#define TST_MTU_PART    4
#define SNDBUF_SIZE     (32 * 1024)

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut  = NULL;
    rcf_rpc_server        *pco_tst  = NULL;
    rcf_rpc_server        *pco_iut_thread = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    te_bool                non_blocked;
    te_bool                no_delay;

    const struct if_nameindex *iut_if = NULL;

    te_bool done      = FALSE;
    void   *tx_buf    = NULL;
    size_t  tx_buflen = TST_BUF_LEN;
    te_dbuf recv_dbuf = TE_DBUF_INIT(0);
    te_dbuf send_dbuf = TE_DBUF_INIT(0);

    int iut_s = -1;
    int tst_s = -1;
    int mtu;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(no_delay);
    TEST_GET_BOOL_PARAM(non_blocked);

    tx_buf = te_make_buf_by_len(tx_buflen);

    /*
     * The "pco_iut_thread" RPC server is used to wait for interface
     * to be upped, while "pco_iut" is executing another RPC call.
     */
    CHECK_RC(rcf_rpc_server_thread_create(pco_iut, "pco_iut_thread",
                                          &pco_iut_thread));

    TEST_STEP("Establish TCP connection.");
    GEN_CONNECTION(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   tst_addr, iut_addr, &tst_s, &iut_s);

    TEST_STEP("Set TCP_NODELAY in dependence on @p no_delay.");
    rpc_setsockopt_int(pco_iut, iut_s, RPC_TCP_NODELAY, no_delay);
    CHECK_RC(tapi_cfg_base_if_get_mtu_u(pco_iut->ta, iut_if->if_name, &mtu));

    TEST_STEP("Decrease IUT send buffer size to 32kb.");
    rpc_setsockopt_int(pco_iut, iut_s, RPC_SO_SNDBUF, SNDBUF_SIZE);

    TEST_STEP("Put IUT interface down.");
    CHECK_RC(tapi_cfg_base_if_down(pco_iut->ta, iut_if->if_name));
    CFG_WAIT_CHANGES;

    TEST_STEP("Send a small packet (less than MTU) from IUT.");
    tx_buflen = mtu/TST_MTU_PART;
    rpc_send(pco_iut, iut_s, tx_buf, tx_buflen, 0);
    te_dbuf_append(&send_dbuf, tx_buf, tx_buflen);

    TEST_STEP("Tester socket should stay unreadable.");
    RPC_CHECK_READABILITY(pco_tst, tst_s, FALSE);

    TEST_STEP("Send a bit larger packet (more than MTU) from IUT.");
    tx_buflen = mtu + (mtu/TST_MTU_PART);
    rpc_send(pco_iut, iut_s, tx_buf, tx_buflen, 0);
    te_dbuf_append(&send_dbuf, tx_buf, tx_buflen);

    tx_buflen = SNDBUF_SIZE;
    done = TRUE;
    do {
        TEST_STEP("Try to send a large packet (32kb) from IUT:");
        if (non_blocked)
        {
            TEST_SUBSTEP("If non-blocking - call send() until it fails with EAGAIN.");
            RPC_AWAIT_IUT_ERROR(pco_iut);
            rc = rpc_send(pco_iut, iut_s, tx_buf, tx_buflen, RPC_MSG_DONTWAIT);
            if (rc > 0)
                te_dbuf_append(&send_dbuf, tx_buf, rc);
            else if (rc == 0)
                TEST_VERDICT("Send call unexpectedly returned 0");
            else
                CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN, "Non-blocking send "
                                "failed with incorrect errno");
        }
        else
        {
            TEST_SUBSTEP("If blocking - call send() until it is blocked.");
            pco_iut->op = RCF_RPC_CALL;
            rpc_send(pco_iut, iut_s, tx_buf, tx_buflen, 0);
            TAPI_WAIT_NETWORK;
            rcf_rpc_server_is_op_done(pco_iut, &done);
            if (done)
            {
                rc = rpc_send(pco_iut, iut_s, tx_buf, tx_buflen, 0);
                if (rc != (int)tx_buflen)
                    TEST_VERDICT("Blocking send call returned unexpected "
                                 "value");
                te_dbuf_append(&send_dbuf, tx_buf, tx_buflen);
            }
        }
    } while (rc > 0 && done);

    TEST_STEP("Tester socket still should be unreadable.");
    RPC_CHECK_READABILITY(pco_tst, tst_s, FALSE);

    TEST_STEP("Up IUT interface.");
    CHECK_RC(tapi_cfg_base_if_up(pco_iut->ta, iut_if->if_name));
    CHECK_RC(sockts_wait_for_if_up(pco_iut_thread, iut_if->if_name));

    TEST_STEP("Finish data transmission for blocking mode or send some more data in "
              "non-blocking mode.");
    /*
     * Timeout value for pco_iut should be increased because switching the
     * interface to UP with team4 option can take a long time (see ST-2173).
     */
    pco_iut->timeout = TE_SEC2MS(60);
    rpc_send(pco_iut, iut_s, tx_buf, tx_buflen, 0);
    te_dbuf_append(&send_dbuf, tx_buf, tx_buflen);

    TEST_STEP("Read all data on tester and check it.");
    rpc_read_fd2te_dbuf(pco_tst, tst_s, TAPI_WAIT_NETWORK_DELAY, 0,
                        &recv_dbuf);
    SOCKTS_CHECK_RECV(pco_tst, send_dbuf.ptr, recv_dbuf.ptr,
                      send_dbuf.len, recv_dbuf.len);

    TEST_STEP("Check data transmission in both directions.");
    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_thread));

    free(tx_buf);
    TEST_END;
}
