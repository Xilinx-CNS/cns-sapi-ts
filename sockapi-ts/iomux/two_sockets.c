/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * I/O Multiplexing
 * 
 * $Id$
 */

/** @page iomux-two_sockets I/O multiplexing functions with two sockets
 *
 * @objective Check I/O multiplexing functions behaviour when it was called
 *            with two sockets in the sets.
 *
 * @param pco_iut   PCO on IUT
 * @param pco_tst1  Auxiliary PCO
 * @param pco_tst2  Auxiliary PCO
 * @param iomux     Type of I/O Multiplexing function
 *                  (@b select(), @b pselect(), @b poll())
 * @param how       @c EVT_RD, @c EVT_WR or @c EVT_RDWR
 * @param ready     If @c TRUE call iomux function with already ready
 *                  descriptor. If @c FALSE call iomux function with not
 *                  ready descriptors.
 * @param data_size Data portion size
 * 
 * @par Scenario:
 * -# Create @p sock_type connections between @p pco_iut and @p pco_tst1 and
 *    between @p pco_iut and @p pco_tst2. Created sockets are further named
 *    as @p iut_s1 and @p tst_s1, and @p iut_s2 and @p tst_s2 respectively;
 * -# Make @p iut_s1 socket not ready for @p how event. Make @p iut_s2
 *    socket not ready for @p how event if @p ready is @p FALSE. Make
 *    @p iut_s2 socket ready for @p how event if @p ready is @c TRUE.
 * -# Call iomux function with @p iut_s1 and @p iut_s2 sockets with @p how
 *    event and some non-zero timeout.
 * -# If @p ready is @c FALSE make iut_s2 socket ready for @p how event.
 * -# Check that iomux function returned @c 1.
 * -# Close sockets.
 * 
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME "iomux/two_sockets"
#include "sockapi-test.h"
#include "iomux.h"

int
main(int argc, char *argv[])
{
    iomux_call_type         iomux;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst1 = NULL;
    rcf_rpc_server         *pco_tst2 = NULL;

    const struct sockaddr  *iut_addr1 = NULL;
    const struct sockaddr  *tst_addr1 = NULL;

    const struct sockaddr  *iut_addr2 = NULL;
    const struct sockaddr  *tst_addr2 = NULL;

    int                     iut_s1 = -1;
    int                     tst_s1 = -1;
    int                     iut_s2 = -1;
    int                     tst_s2 = -1;

    rpc_socket_type         sock_type;
    int                     data_size;

    const char             *how;
    iomux_evt_fd            event[2];
    tarpc_timeval           tv = { 3, 0 };
    te_bool                 ready;
    te_bool                 iomux_done;
    te_bool                 use_wildcard;
    uint64_t                total_filled = 0;
    int                     ret_val;
    uint8_t                *data_buf = NULL;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_tst1, tst_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst2, tst_addr2);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_STRING_PARAM(how);
    TEST_GET_BOOL_PARAM(ready);
    TEST_GET_BOOL_PARAM(use_wildcard);
    TEST_GET_INT_PARAM(ret_val);
    TEST_GET_INT_PARAM(data_size);

    data_buf = te_make_buf_by_len(data_size);

    GEN_CONNECTION_WILD(pco_iut, pco_tst1, sock_type, RPC_PROTO_DEF,
                        iut_addr1, tst_addr1, &iut_s1, &tst_s1,
                        use_wildcard);

    GEN_CONNECTION_WILD(pco_iut, pco_tst2, sock_type, RPC_PROTO_DEF,
                        iut_addr2, tst_addr2, &iut_s2, &tst_s2,
                        use_wildcard);

    event[0].fd = iut_s1;
    event[1].fd = iut_s2;
    event[0].events = event[1].events = (strcmp(how, "rd") == 0) ? EVT_RD :
        ((strcmp(how, "wr") == 0) ? EVT_WR : EVT_RDWR);
    
    if (ready && (strcmp(how, "wr") != 0)) {
        RPC_SEND(rc, pco_tst2, tst_s2, data_buf, data_size, 0);
        TAPI_WAIT_NETWORK;
    }

    if (strcmp(how, "rd") != 0 && sock_type != RPC_SOCK_DGRAM)
        rpc_overfill_buffers_gen(pco_iut, iut_s1, &total_filled,
                                 iomux == IC_OO_EPOLL ? IC_EPOLL : iomux);

    if (!ready && strcmp(how, "rd") != 0)
        rpc_overfill_buffers_gen(pco_iut, iut_s2, &total_filled,
                                 iomux == IC_OO_EPOLL ? IC_EPOLL : iomux);
        
    pco_iut->op = RCF_RPC_CALL;
    rc = iomux_call(iomux, pco_iut, event, 2, &tv);
    TAPI_WAIT_NETWORK;

    if (!ready)
    {
        if (strcmp(how, "wr") != 0)
            RPC_SEND(rc, pco_tst2, tst_s2, data_buf, data_size, 0);
        else
            do {
                rc = rpc_recv(pco_tst2, tst_s2, data_buf, data_size, 0);
                total_filled -= rc;
            } while (total_filled != 0);
        TAPI_WAIT_NETWORK;
    }

    CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &iomux_done));
    if (!iomux_done)
        RING_VERDICT("iomux function does not return in time");

    pco_iut->op = RCF_RPC_WAIT;
    rc = iomux_call(iomux, pco_iut, event, 2, &tv);
    if (!((ready) &&
          (iomux != IC_SELECT && iomux != IC_PSELECT) &&
          (strcmp(how, "rdwr") == 0)))
    {
        if (rc != ret_val)
            TEST_FAIL("iomux function returned %d instead %d", rc, ret_val);
    }
    else
    {
        if (rc != (ret_val - 1))
            TEST_FAIL("iomux function returned %d instead %d", rc,
                      ret_val - 1);
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s1);
    CLEANUP_RPC_CLOSE(pco_tst1, tst_s1);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s2);
    CLEANUP_RPC_CLOSE(pco_tst2, tst_s2);

    free(data_buf);
    TEST_END;
}
