/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Multicasting in IP
 */

/**
 * @page multicast-iomux_multicast iomux() reports events during multicast
 *
 * @objective Check that @b iomux() reports events during multicast
 *
 * @param env       Testing environment:
 *      - @ref arg_types_env_peer2peer_mcast
 *      - @ref arg_types_env_peer2peer_mcast_lo
 * @param iomux     IO multiplexing function to be tested
 * @param sock_func Socket creation function.
 * @param blocking  Should iomux() be blocking
 *
 * @par Scenario:
 *
 * @author Vasilij Ivanov <Vasilij.Ivanov@oktetlabs.ru>
 */

#define TE_TEST_NAME "multicast/iomux_multicast"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "iomux.h"
#include "multicast.h"
#include "mcast_lib.h"

#define DATA_BULK       200

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst = NULL;
    int                        iut_s = -1;
    int                        tst_s = -1;

    iomux_call_type            iomux;

    const struct sockaddr     *tst_addr = NULL;
    const struct if_nameindex *iut_if;
    const struct sockaddr     *mcast_addr = NULL;
    uint8_t                    sendbuf[DATA_BULK];
    uint8_t                    recvbuf[DATA_BULK];
    struct tarpc_mreqn         mreq;
    tarpc_joining_method       method;
    sockts_socket_func         sock_func;

    te_bool                    blocking = false;

    iomux_evt_fd               evt;
    te_bool                    done;
    int i;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_MCAST_METHOD(method);
    SOCKTS_GET_SOCK_FUNC(sock_func);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_BOOL_PARAM(blocking);

    te_fill_buf(sendbuf, DATA_BULK);

    rcf_tr_op_log(FALSE);

    if (strcmp(pco_iut->ta, pco_tst->ta) == 0)
    {
        CHECK_RC(tapi_sh_env_set(pco_tst, "EF_FORCE_SEND_MULTICAST", "0",
                                 TRUE, TRUE));
    }

    TEST_STEP("Create datagram sockets on IUT and Tester");
    tst_s = rpc_socket(pco_tst, RPC_PF_INET, RPC_SOCK_DGRAM,
                       RPC_IPPROTO_UDP);
    iut_s = sockts_socket(sock_func, pco_iut, RPC_PF_INET,
                          RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    TEST_STEP("Adjoin socket on IUT to multicasting group");
    if (SIN(mcast_addr)->sin_addr.s_addr != htonl(INADDR_ALLHOSTS_GROUP))
    {
        CHECK_MCAST_HASH_COLLISION_CREATE_SOCK(pco_iut, pco_tst, iut_if,
                                               tst_addr, mcast_addr);
    }

    if (rpc_common_mcast_join(pco_iut, iut_s, mcast_addr,
                              tst_addr, iut_if->if_index,
                              method) < 0)
    {
        TEST_VERDICT("Sockets on IUT cannot join multicast group");
    }

    TEST_STEP("Set @p IP_MULTICAST_IF on Tester socket");
    memset(&mreq, 0, sizeof(mreq));
    mreq.type = OPT_IPADDR;
    memcpy(&mreq.address, te_sockaddr_get_netaddr(tst_addr),
           sizeof(mreq.address));
    rpc_setsockopt(pco_tst, tst_s, RPC_IP_MULTICAST_IF, &mreq);

    TEST_STEP("Bind socket on IUT to multicast address");
    rpc_bind(pco_iut, iut_s, mcast_addr);

    evt.fd = iut_s;
    evt.events = EVT_RD;
    evt.revents = 0;
    if (blocking)
    {
        TEST_STEP("If @p blocking is @c TRUE:");

        TEST_SUBSTEP("Perform blocking @p iomux call");
        pco_iut->op = RCF_RPC_CALL;
        iomux_call(iomux, pco_iut, &evt, 1, NULL);

        TEST_SUBSTEP("Wait for a while");
        SLEEP(2);

        TEST_SUBSTEP("Check that @p iomux call hangs");
        CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));
        if (done)
        {
            TEST_VERDICT("iomux_call() is not hanging");
        }
    }

    TEST_STEP("Send and receive multicast datagram 3 times");
    for (i = 0; i < 3; i++)
    {
        TEST_SUBSTEP("Send datagram from Tester socket to multicast address");
        rpc_sendto(pco_tst, tst_s, sendbuf, DATA_BULK, 0, mcast_addr);
        TAPI_WAIT_NETWORK;

        TEST_SUBSTEP("Call @p iomux function if it was not already called. "
                  "Check that the call unblocks reporting "
                  "IUT socket as readable.");
        RPC_AWAIT_ERROR(pco_iut);
        rc = iomux_call(iomux, pco_iut, &evt, 1, NULL);

        if (rc == -1)
        {
            TEST_VERDICT("Error occured during iomux call, errno: %r",
                         RPC_ERRNO(pco_iut));
        }
        if (rc == 0)
            TEST_VERDICT("No events were reported");
        if (rc > 1)
            TEST_VERDICT("More than one event was reported");

        if (evt.revents != EVT_RD)
            TEST_VERDICT("Reported event was not read event");

        TEST_SUBSTEP("Receive datagram on IUT");
        rc = rpc_recv(pco_iut, iut_s, recvbuf, DATA_BULK, 0);

        if (rc != DATA_BULK)
            TEST_VERDICT("Incorrect size of data was receved");
        if (memcmp(sendbuf, recvbuf, DATA_BULK) != 0)
            TEST_VERDICT("Data verification failed");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
