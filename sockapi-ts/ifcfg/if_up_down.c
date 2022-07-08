/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Network interface related tests
 */

/** @page ifcfg-if_up_down Interface down/up during data transmission
 *
 * @objective Put interface down during data transmission in both directions,
 *            check it can be continued when the interface is up.
 *
 * @type conformance
 *
 * @param pco_iut   PCO on @p IUT
 * @param pco_tst   PCO on @p TESTER
 * @param iut_if    Network interface name on @p IUT that connected to
 *                  @p TESTER
 * @param sock_type Socket type
 * @param incoming  Direction of the data flow relatively to IUT
 * @param rm_addr   Remove IP address if @c TRUE, else put interface down.
 *
 * @par Test sequence:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ifcfg/if_up_down"

#include "sockapi-test.h"
#include "tapi_cfg_base.h"

/* How long run sender in seconds. */
#define TIME_TO_RUN 60
/* How long run receiver in seconds. */
#define TIME_TO_RUN_RECV 62

/* Maximum delay between sends in microseconds. */
#define MAX_SEND_DELAY 10000

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_iut_thread = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    const struct sockaddr *iut_addr = NULL;
    struct sockaddr       *iut_addr2 = NULL;
    const struct sockaddr *tst_addr = NULL;
    tapi_env_net          *net;
    rpc_socket_type        sock_type;
    te_bool                incoming;
    te_bool                rm_addr;

    const struct if_nameindex *iut_if = NULL;

    struct timeval tv1;
    struct timeval tv2;

    cfg_handle  iut_addr_handle = CFG_HANDLE_INVALID;
    uint64_t    received = 0;
    uint64_t    sent = 0;
    te_bool     failed = FALSE;
    te_bool     done;

    int time_to_run_updated = TIME_TO_RUN;
    int iut_s = -1;
    int tst_s = -1;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_BOOL_PARAM(rm_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(incoming);
    TEST_GET_NET(net);

     CHECK_RC(rcf_rpc_server_thread_create(pco_iut, "pco_iut_thread",
                                           &pco_iut_thread));

    TEST_STEP("Add new IP address on IUT interface if @p rm_addr is @c TRUE.");
    if (rm_addr)
    {
        CHECK_RC(tapi_env_allocate_addr(net, AF_INET, &iut_addr2, NULL));
        CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if->if_name,
                                               iut_addr2, net->ip4pfx,
                                               FALSE, &iut_addr_handle));
        CFG_WAIT_CHANGES;
        tapi_allocate_set_port(pco_iut, iut_addr2);
    }

    TEST_STEP("Establish TCP connection or create, bind and connect UDP sockets.");
    GEN_CONNECTION(pco_tst, pco_iut, sock_type, RPC_PROTO_DEF, tst_addr,
                   rm_addr ? iut_addr2 : iut_addr, &tst_s, &iut_s);

    pco_iut->op = RCF_RPC_CALL;
    pco_tst->op = RCF_RPC_CALL;

    TEST_STEP("Repeatedly send or receive data for a time, stream direction depends "
              "on @p incoming.");
    if (incoming)
    {
        rpc_simple_sender(pco_tst, tst_s, 1, 10, 0, 0, MAX_SEND_DELAY, 1,
                          TIME_TO_RUN, &sent, 0);
        rpc_simple_receiver(pco_iut, iut_s, TIME_TO_RUN_RECV, &received);
    }
    else
    {
        rpc_simple_sender(pco_iut, iut_s, 1, 10, 0, 0, MAX_SEND_DELAY, 1,
                          TIME_TO_RUN, &sent, 0);
        rpc_simple_receiver(pco_tst, tst_s, TIME_TO_RUN_RECV, &received);
        gettimeofday(&tv1, NULL);
    }

    TAPI_WAIT_NETWORK;

    TEST_SUBSTEP("Put interface down or remove IP address if @p rm_addr is @c TRUE.");
    if (rm_addr)
    {
        CHECK_RC(cfg_del_instance(iut_addr_handle, FALSE));
        iut_addr_handle = CFG_HANDLE_INVALID;
    }
    else
        CHECK_RC(tapi_cfg_base_if_down(pco_iut->ta, iut_if->if_name));
    CFG_WAIT_CHANGES;

    if (rm_addr && sock_type == RPC_SOCK_DGRAM && !incoming)
    {
        TEST_SUBSTEP("For UDP only check that @b send() operation fails with "
                     "@c EINVAL or @c ENETUNREACH if the address is removed.");

        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_simple_sender(pco_iut, iut_s, 1, 10, 0, 0, MAX_SEND_DELAY, 1,
                               TIME_TO_RUN, &sent, 0);

        if (rc != -1)
            TEST_VERDICT("rpc_simple_sender() unexpectedly succeed");

        /* Read more about errno codes in ST-1844. */
        if (rc == -1 &&
            RPC_ERRNO(pco_iut) != RPC_EINVAL &&
            RPC_ERRNO(pco_iut) != RPC_ENETUNREACH)
        {
            TEST_VERDICT("rpc_simple_sender() returns -1, but errno is set "
                         "to %r instead of %r or %r", RPC_ERRNO(pco_iut),
                         RPC_EINVAL, RPC_ENETUNREACH);
        }

        gettimeofday(&tv2, NULL);
        time_to_run_updated = TIME_TO_RUN - TE_US2SEC(TIMEVAL_SUB(tv2, tv1));
        pco_iut->op = RCF_RPC_CALL;
        rpc_simple_sender(pco_iut, iut_s, 1, 10, 0, 0, MAX_SEND_DELAY, 1,
                          time_to_run_updated, &sent, TRUE);
    }
    else
    {
        TEST_SUBSTEP("In other cases neither @b send() nor @b recv() calls should fail.");

        CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));
        if (done)
        {
            ERROR_VERDICT("Data %s was unexpectedly stopped",
                          incoming ? "reception" : "sending");
            failed = TRUE;
        }
    }

    CHECK_RC(rcf_rpc_server_is_op_done(pco_tst, &done));
    if (done)
    {
        ERROR_VERDICT("Tester: data %s was unexpectedly stopped",
                      incoming ? "sending" : "reception");
        failed = TRUE;
    }

    TEST_SUBSTEP("Up interface or add IP address back if @p rm_addr is @c TRUE.");
    if (rm_addr)
    {
        CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if->if_name,
                                               iut_addr2, net->ip4pfx,
                                               FALSE, &iut_addr_handle));
        CFG_WAIT_CHANGES;
    }
    else
    {
        CHECK_RC(tapi_cfg_base_if_up(pco_iut->ta, iut_if->if_name));
        CHECK_RC(sockts_wait_for_if_up(pco_iut_thread, iut_if->if_name));
    }

    if (incoming)
    {
        RPC_AWAIT_IUT_ERROR(pco_tst);
        rc = rpc_simple_sender(pco_tst, tst_s, 1, 10, 0, 0, MAX_SEND_DELAY,
                               1, TIME_TO_RUN, &sent, 0);
        if (rc < 0)
            TEST_VERDICT("Send operation failed on tester with errno %r",
                         RPC_ERRNO(pco_tst));
        rpc_simple_receiver(pco_iut, iut_s, TIME_TO_RUN_RECV, &received);
    }
    else
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_simple_sender(pco_iut, iut_s, 1, 10, 0, 0, MAX_SEND_DELAY,
                               1, time_to_run_updated, &sent, 0);
        if (rc < 0)
            TEST_VERDICT("Send operation failed on IUT with errno %r",
                         RPC_ERRNO(pco_iut));

        rpc_simple_receiver(pco_tst, tst_s, TIME_TO_RUN_RECV, &received);
    }

    TEST_STEP("Check that sent and received data amount is equal for TCP.");
    if (sock_type == RPC_SOCK_STREAM && sent != received)
    {
        ERROR("Sent %"TE_PRINTF_64"u, received %"TE_PRINTF_64"u",
              sent, received);
        TEST_VERDICT("Different data amount was sent and received");
    }

    if (failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (iut_addr_handle != CFG_HANDLE_INVALID)
    {
        CLEANUP_CHECK_RC(cfg_del_instance(iut_addr_handle, FALSE));
        CFG_WAIT_CHANGES;
    }
    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_thread));


    TEST_END;
}
